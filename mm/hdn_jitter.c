// SPDX-License-Identifier: GPL-2.0-only
/* Closed typed envelopes. Every changed payload placement follows an RCU grace
 * period, including files whose former cache was SLAB_TYPESAFE_BY_RCU. */
#include <linux/cred.h>
#include <linux/cpu.h>
#include <linux/fs.h>
#include <linux/hardening.h>
#include <linux/kasan.h>
#include <linux/kfence.h>
#include <linux/kmemleak.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/shrinker.h>
#include <linux/siphash.h>
#include <linux/unaligned.h>
#include <linux/workqueue.h>
#include <linux/xarray.h>
#include "slab.h"
#include "hdn_jitter.h"
#ifdef CONFIG_KASAN_GENERIC
#include "kasan/kasan.h"
#endif

#define HDN_JITTER_SLOTS 8
#define HDN_JITTER_QUARANTINE 128

enum jitter_state { JITTER_LIVE, JITTER_RETIRED, JITTER_QUEUED, JITTER_RELEASING };
struct jitter_record {
	struct rcu_head rcu;
	void *backing;
	void *payload;
	struct kmem_cache *cache;
	siphash_key_t key;
	u64 generation;
	u32 offset;
	unsigned long expires;
	atomic_t state;
	bool strong;
#ifdef CONFIG_SECURITY_HARDENING_SLAB_JITTER_TEST
	bool test_hold;
#endif
};
struct jitter_class {
	struct kmem_cache *cache;
	unsigned int payload_size, align;
	raw_spinlock_t lock;
	struct jitter_record *queue[HDN_JITTER_QUARANTINE];
	unsigned int count;
	struct delayed_work drain;
	atomic64_t allocations, allocation_failures, retired, released, pressure;
};
static struct jitter_class classes[HDN_JITTER_CLASS_MAX];
static DEFINE_XARRAY(jitter_records);
static struct kmem_cache *record_cache __ro_after_init;
static atomic64_t generation;
static atomic64_t alloc_count, retire_count, release_count, pressure_count;
static atomic64_t alloc_failure_count, integrity_failure_count, early_live;
extern const struct cred *const __start___hdn_static_creds[];
extern const struct cred *const __stop___hdn_static_creds[];

static __noreturn void jitter_corruption(unsigned int id)
{
	atomic64_inc(&integrity_failure_count);
	/* Synchronous bounded diagnostic; no object address, key, or offset. */
	pr_emerg("HDN emergency: authority=%u transition=%u reason=%u action=%u class=%u\n",
		 HDN_AUTH_NONE, HDN_TRANS_KERNEL_ALLOC, HDN_REASON_KERNEL_OBJECT_CORRUPTION,
		 HDN_DECISION_DENY_AUDIT, id);
	panic("HDN critical object integrity violation");
}

static void jitter_allocation_failed(struct kmem_cache *cache)
{
	atomic64_inc(&alloc_failure_count);
	atomic64_inc(&classes[cache->hdn_jitter_class].allocation_failures);
}

void hdn_jitter_reject_generic(struct kmem_cache *cache)
{
	if (unlikely(cache->hdn_jitter_class))
		jitter_corruption(cache->hdn_jitter_class);
}

static struct jitter_record *lookup(const void *pointer)
{
	struct slab *slab;
	void *backing;

	if (!virt_addr_valid(pointer))
		return NULL;
	slab = virt_to_slab(pointer);
	if (!slab || !slab->slab_cache->hdn_jitter_class)
		return NULL;
	backing = is_kfence_address(pointer) ? kfence_object_start(pointer) :
		nearest_obj(slab->slab_cache, slab, (void *)pointer);
	return xa_load(&jitter_records, (unsigned long)backing >> 3);
}

static u64 canary(const struct jitter_record *record, unsigned int side)
{
	return siphash_4u64((unsigned long)record->backing, record->generation,
		((u64)record->cache->hdn_jitter_class << 32) | record->offset,
		side, &record->key);
}

static void check_record(const struct jitter_record *record)
{
	struct jitter_class *type = &classes[record->cache->hdn_jitter_class];
	u64 left, right;

	/* Only the guard words are read through KASAN's poisoned redzones. */
	kasan_disable_current();
	left = get_unaligned((u64 *)(record->payload - sizeof(u64)));
	right = get_unaligned((u64 *)(record->payload + type->payload_size));
	kasan_enable_current();
	if (unlikely(left != canary(record, 0) || right != canary(record, 1)))
		jitter_corruption(record->cache->hdn_jitter_class);
}

static void check_payload(const void *payload, unsigned int id, bool either_file)
{
	struct jitter_record *record;
	unsigned int actual;

	rcu_read_lock();
	record = lookup(payload);
	if (!record || record->payload != payload)
		jitter_corruption(id);
	actual = record->cache->hdn_jitter_class;
	if ((actual != id && !(either_file && actual == HDN_JITTER_BACKING_FILE)) ||
	    atomic_read(&record->state) != JITTER_LIVE)
		jitter_corruption(id);
	check_record(record);
	rcu_read_unlock();
}

void hdn_jitter_check_cred(const struct cred *cred)
{
	const struct cred *const *entry;
	bool dynamic;

	for (entry = __start___hdn_static_creds; entry < __stop___hdn_static_creds; entry++)
		if (*entry == cred)
			return;
	rcu_read_lock();
	dynamic = lookup(cred) != NULL;
	rcu_read_unlock();
	if (dynamic) {
		check_payload(cred, HDN_JITTER_CRED, false);
		return;
	}
#ifdef CONFIG_MODULES
	/* Module static identities were validated before executable finalization. */
	rcu_read_lock();
	{
		struct module *module = __module_address((unsigned long)cred);

		if (module)
			for (unsigned int i = 0; i < module->hdn_static_creds_count; i++)
				if (module->hdn_static_creds[i] == cred) {
					rcu_read_unlock();
					return;
				}
	}
	rcu_read_unlock();
#endif
	jitter_corruption(HDN_JITTER_CRED);
}
EXPORT_SYMBOL(hdn_jitter_check_cred);

void hdn_jitter_check_file(const struct file *file)
{
	check_payload(file, HDN_JITTER_FILE, true);
}
EXPORT_SYMBOL(hdn_jitter_check_file);

size_t hdn_jitter_usable_size(const void *payload)
{
	struct jitter_record *record;
	size_t size;

	rcu_read_lock();
	record = lookup(payload);
	if (!record || record->payload != payload || atomic_read(&record->state) != JITTER_LIVE)
		jitter_corruption(0);
	check_record(record);
	size = classes[record->cache->hdn_jitter_class].payload_size;
	rcu_read_unlock();
	return size;
}

bool hdn_jitter_release_allowed(struct kmem_cache *cache, void *backing)
{
	struct jitter_record *record;
	bool allowed = false;

	rcu_read_lock();
	record = xa_load(&jitter_records, (unsigned long)backing >> 3);
	if (!record || record->backing != backing || record->cache != cache ||
	    atomic_read(&record->state) != JITTER_RELEASING)
		goto out;
	allowed = xa_cmpxchg(&jitter_records, (unsigned long)backing >> 3, record, NULL,
			     GFP_NOWAIT) == record;
out:
	rcu_read_unlock();
	return allowed;
}

static void free_record_rcu(struct rcu_head *head)
{
	struct jitter_record *record = container_of(head, struct jitter_record, rcu);

	memzero_explicit(&record->key, sizeof(record->key));
	kmem_cache_free(record_cache, record);
}

static void release_record(struct jitter_record *record)
{
	check_record(record); /* Detect a stale write while the slot was held. */
	if (atomic_cmpxchg(&record->state, JITTER_QUEUED, JITTER_RELEASING) != JITTER_QUEUED)
		jitter_corruption(record->cache->hdn_jitter_class);
	kasan_unpoison_range(record->backing, record->cache->object_size);
	memzero_explicit(record->backing, record->cache->object_size);
	/* Keep the ownership record visible until the internal release authenticates
	 * it. The envelope can be recycled only after this allocator call. */
	hdn_jitter_release_backing(record->cache, record->backing);
	atomic64_inc(&release_count);
	atomic64_inc(&classes[record->cache->hdn_jitter_class].released);
	if (!record->strong)
		atomic64_dec(&early_live);
	call_rcu(&record->rcu, free_record_rcu);
}

static struct jitter_record *remove_slot(struct jitter_class *type, unsigned int index)
{
	struct jitter_record *record = type->queue[index];

	type->queue[index] = type->queue[--type->count];
	type->queue[type->count] = NULL;
	return record;
}

static void drain_work(struct work_struct *work)
{
	struct jitter_class *type = container_of(to_delayed_work(work), struct jitter_class, drain);
	struct jitter_record *record;
	unsigned long flags;
	unsigned int i;
	bool pending;

	for (;;) {
		record = NULL;
		raw_spin_lock_irqsave(&type->lock, flags);
		for (i = 0; i < type->count; i++)
			if (time_after_eq(jiffies, type->queue[i]->expires)) {
				record = remove_slot(type, i);
				break;
			}
		pending = type->count != 0;
		raw_spin_unlock_irqrestore(&type->lock, flags);
		if (!record)
			break;
		release_record(record);
	}
	if (pending)
		mod_delayed_work(system_unbound_wq, &type->drain, msecs_to_jiffies(250));
}

static void retire_rcu(struct rcu_head *head)
{
	struct jitter_record *record = container_of(head, struct jitter_record, rcu);
	struct jitter_class *type = &classes[record->cache->hdn_jitter_class];
	struct jitter_record *victim = NULL;
	unsigned long flags;
	u64 choice = canary(record, 2);

	check_record(record);
	record->expires = jiffies + msecs_to_jiffies(250 + choice % 1751);
#ifdef CONFIG_KASAN_GENERIC
	kasan_poison(record->payload, ALIGN(type->payload_size, KASAN_GRANULE_SIZE),
		     KASAN_SLAB_FREE, false);
#endif
	atomic_set(&record->state, JITTER_QUEUED);
#ifdef CONFIG_SECURITY_HARDENING_SLAB_JITTER_TEST
	if (record->test_hold)
		return;
#endif
	raw_spin_lock_irqsave(&type->lock, flags);
	if (type->count == HDN_JITTER_QUARANTINE)
		victim = remove_slot(type, choice % type->count);
	type->queue[type->count++] = record;
	raw_spin_unlock_irqrestore(&type->lock, flags);
	if (victim) {
		atomic64_inc(&pressure_count);
		atomic64_inc(&type->pressure);
		release_record(victim);
	}
	mod_delayed_work(system_unbound_wq, &type->drain, msecs_to_jiffies(250));
}

static void *jitter_alloc(struct kmem_cache *cache, gfp_t flags,
			 const siphash_key_t *test_key, unsigned int test_sequence)
{
	struct jitter_class *type = &classes[cache->hdn_jitter_class];
	struct jitter_record *record;
	unsigned int offset;
	int error;
#ifdef CONFIG_SECURITY_HARDENING_SLAB_JITTER_TEST
	unsigned int fail_stage = test_key && test_sequence >= U32_MAX - 2 ?
		test_sequence - (U32_MAX - 3) : 0;
#endif

	if (!cache->hdn_jitter_class || type->cache != cache)
		jitter_corruption(0);
#ifdef CONFIG_SECURITY_HARDENING_SLAB_JITTER_TEST
	if (fail_stage == 1) {
		jitter_allocation_failed(cache);
		return NULL;
	}
#endif
	record = kmem_cache_zalloc(record_cache, flags);
	if (!record) {
		jitter_allocation_failed(cache);
		return NULL;
	}
#ifdef CONFIG_SECURITY_HARDENING_SLAB_JITTER_TEST
	if (fail_stage == 2) {
		jitter_allocation_failed(cache);
		kmem_cache_free(record_cache, record);
		return NULL;
	}
#endif
	record->backing = kmem_cache_alloc(cache, flags);
	if (!record->backing) {
		jitter_allocation_failed(cache);
		kmem_cache_free(record_cache, record);
		return NULL;
	}
	record->cache = cache;
	record->generation = atomic64_inc_return(&generation);
	if (!record->generation)
		jitter_corruption(cache->hdn_jitter_class);
	record->strong = rng_is_initialized();
	get_random_bytes(&record->key, sizeof(record->key));
	offset = type->align * (1 + siphash_2u64(record->generation,
				(unsigned long)record->backing, &record->key) % HDN_JITTER_SLOTS);
#ifdef CONFIG_SECURITY_HARDENING_SLAB_JITTER_TEST
	if (test_key) {
		BUG_ON(cache->hdn_jitter_class != HDN_JITTER_TEST);
		record->key = *test_key;
		offset = type->align * (1 + siphash_1u64(test_sequence, test_key) % HDN_JITTER_SLOTS);
	}
#else
	BUG_ON(test_key);
#endif
	record->offset = offset;
	record->payload = record->backing + offset;
	atomic_set(&record->state, JITTER_LIVE);
	put_unaligned(canary(record, 0), (u64 *)(record->payload - sizeof(u64)));
	put_unaligned(canary(record, 1), (u64 *)(record->payload + type->payload_size));
#ifdef CONFIG_KASAN_GENERIC
	kasan_poison(record->backing, offset, KASAN_SLAB_REDZONE, false);
	kasan_poison(record->payload + ALIGN(type->payload_size, KASAN_GRANULE_SIZE),
		cache->object_size - offset - ALIGN(type->payload_size, KASAN_GRANULE_SIZE),
		KASAN_SLAB_REDZONE, false);
	kasan_poison_last_granule(record->payload, type->payload_size);
#endif
	error = 0;
#ifdef CONFIG_SECURITY_HARDENING_SLAB_JITTER_TEST
	if (fail_stage == 3)
		error = -ENOMEM;
	else
#endif
		error = xa_insert(&jitter_records, (unsigned long)record->backing >> 3, record, flags);
	if (error) {
		if (error != -ENOMEM)
			jitter_corruption(cache->hdn_jitter_class);
		/* No published payload exists. Authorize exactly this unpublished
		 * envelope's release through the ordinary allocator abort path. */
		kasan_unpoison_range(record->backing, cache->object_size);
		/* A separate primitive is needed before the registry owns the slot. */
		hdn_jitter_abort_backing(cache, record->backing);
		jitter_allocation_failed(cache);
		memzero_explicit(&record->key, sizeof(record->key));
		kmem_cache_free(record_cache, record);
		return NULL;
	}
	kmemleak_ignore(record);
	if (!record->strong)
		atomic64_inc(&early_live);
	atomic64_inc(&alloc_count);
	atomic64_inc(&type->allocations);
	return record->payload;
}

void *hdn_jitter_alloc(struct kmem_cache *cache, gfp_t flags)
{
	return jitter_alloc(cache, flags, NULL, 0);
}

void hdn_jitter_free(struct kmem_cache *cache, void *payload)
{
	struct jitter_record *record;

	if (!payload)
		return;
	rcu_read_lock();
	record = lookup(payload);
	if (!record || record->payload != payload || record->cache != cache)
		jitter_corruption(cache->hdn_jitter_class);
	check_record(record);
	if (atomic_cmpxchg(&record->state, JITTER_LIVE, JITTER_RETIRED) != JITTER_LIVE)
		jitter_corruption(cache->hdn_jitter_class);
	kmemleak_not_leak(record->backing);
	atomic64_inc(&retire_count);
	atomic64_inc(&classes[cache->hdn_jitter_class].retired);
	call_rcu(&record->rcu, retire_rcu);
	rcu_read_unlock();
}

struct kmem_cache * __init hdn_jitter_create(enum hdn_jitter_class id,
		const char *name, unsigned int size, unsigned int align,
		enum hdn_alloc_domain domain)
{
	struct jitter_class *type;
	unsigned int envelope;

	BUG_ON(id <= HDN_JITTER_NONE || id >= HDN_JITTER_CLASS_MAX || !size);
	type = &classes[id];
	BUG_ON(type->cache);
	if (!record_cache) {
		record_cache = kmem_cache_create("hdn-jitter-record", sizeof(struct jitter_record),
			0, SLAB_ACCOUNT | SLAB_PANIC | SLAB_NO_MERGE, NULL);
		hdn_cache_domain(record_cache, HDN_ALLOC_JITTER_META);
	}
	align = max_t(unsigned int, align, max_t(unsigned int, L1_CACHE_BYTES, 16));
	BUG_ON(!is_power_of_2(align));
	envelope = ALIGN(size + sizeof(u64), align) + align * HDN_JITTER_SLOTS;
	type->cache = kmem_cache_create(name, envelope, align,
		SLAB_ACCOUNT | SLAB_PANIC | SLAB_NO_MERGE, NULL);
	type->cache->hdn_jitter_class = id;
	hdn_cache_domain(type->cache, domain);
	type->payload_size = size;
	type->align = align;
	raw_spin_lock_init(&type->lock);
	INIT_DELAYED_WORK(&type->drain, drain_work);
	return type->cache;
}

void hdn_jitter_get_stats(struct hdn_jitter_stats *stats)
{
	*stats = (struct hdn_jitter_stats) {
		.allocations = atomic64_read(&alloc_count), .retired = atomic64_read(&retire_count),
		.released = atomic64_read(&release_count), .pressure = atomic64_read(&pressure_count),
		.allocation_failures = atomic64_read(&alloc_failure_count),
		.integrity_failures = atomic64_read(&integrity_failure_count),
		.early_live = atomic64_read(&early_live),
		.entropy_ready = rng_is_initialized(),
	};
	for (unsigned int id = 1; id < HDN_JITTER_CLASS_MAX; id++) {
		stats->classes[id].allocations = atomic64_read(&classes[id].allocations);
		stats->classes[id].allocation_failures =
			atomic64_read(&classes[id].allocation_failures);
		stats->classes[id].retired = atomic64_read(&classes[id].retired);
		stats->classes[id].released = atomic64_read(&classes[id].released);
		stats->classes[id].pressure = atomic64_read(&classes[id].pressure);
		stats->classes[id].quarantined = READ_ONCE(classes[id].count);
		stats->quarantined += stats->classes[id].quarantined;
	}
}

void hdn_jitter_dump(const void *pointer)
{
	struct jitter_record *record;

	/* Called by the existing privileged slab diagnostic path. No validation
	 * or canary read: the dump must survive a damaged payload. */
	rcu_read_lock();
	record = lookup(pointer);
	if (record)
		pr_cont(" hdn-class %u payload-offset %u payload-size %u generation %llu state %u",
			record->cache->hdn_jitter_class, record->offset,
			classes[record->cache->hdn_jitter_class].payload_size,
			record->generation, atomic_read(&record->state));
	rcu_read_unlock();
}

static unsigned long jitter_count(struct shrinker *shrinker, struct shrink_control *sc)
{
	struct hdn_jitter_stats stats;

	hdn_jitter_get_stats(&stats);
	return stats.quarantined ?: SHRINK_EMPTY;
}

static unsigned long jitter_scan(struct shrinker *shrinker, struct shrink_control *sc)
{
	unsigned long freed = 0, flags;
	unsigned int id;

	for (id = 1; id < HDN_JITTER_CLASS_MAX && freed < sc->nr_to_scan; id++) {
		struct jitter_class *type = &classes[id];
		struct jitter_record *record;

		if (!type->cache)
			continue;
		do {
			record = NULL;
			raw_spin_lock_irqsave(&type->lock, flags);
			if (type->count)
				record = remove_slot(type, get_random_u32_below(type->count));
			raw_spin_unlock_irqrestore(&type->lock, flags);
			if (record) {
				atomic64_inc(&pressure_count);
				atomic64_inc(&type->pressure);
				release_record(record);
				freed++;
			}
		} while (record && freed < sc->nr_to_scan);
	}
	return freed;
}

static int __init jitter_shrinker_init(void)
{
	struct shrinker *shrinker = shrinker_alloc(0, "hdn-critical-jitter");

#ifdef CONFIG_SECURITY_HARDENING_SLAB_JITTER_TEST
	hdn_jitter_create(HDN_JITTER_TEST, "hdn-jitter-fixture", 128, 64, HDN_ALLOC_JITTER_TEST);
#endif
	if (!shrinker)
		panic("HDN critical object reclaim registration failed");
	shrinker->count_objects = jitter_count;
	shrinker->scan_objects = jitter_scan;
	shrinker->seeks = DEFAULT_SEEKS;
	shrinker_register(shrinker);
	return 0;
}
subsys_initcall(jitter_shrinker_init);

#ifdef CONFIG_SECURITY_HARDENING_SLAB_JITTER_TEST
/* The only deterministic seed path is local to this disposable class. It never
 * changes placement or keys for real credentials or files. */
#define HDN_JITTER_TEST_REUSE 32
struct jitter_test_reuse {
	void *payloads[HDN_JITTER_TEST_REUSE];
	void *previous[HDN_JITTER_TEST_REUSE];
	siphash_key_t key;
	unsigned int class_id, sequence, matches;
	bool deterministic;
	bool compare;
};

static long jitter_test_reuse_cpu(void *argument)
{
	struct jitter_test_reuse *test = argument;
	struct jitter_class *type = &classes[test->class_id];
	unsigned int allocated = 0, i, j;
	long result = 0;

	for (i = 0; i < HDN_JITTER_TEST_REUSE; i++) {
		struct jitter_record *record;

		test->payloads[i] = jitter_alloc(type->cache, GFP_KERNEL,
						 test->deterministic ? &test->key : NULL,
						 test->sequence + i);
		if (!test->payloads[i]) {
			result = -ENOMEM;
			break;
		}
		allocated++;
		rcu_read_lock();
		record = lookup(test->payloads[i]);
		if (!record || record->payload != test->payloads[i])
			jitter_corruption(test->class_id);
		if (test->compare) {
			for (j = 0; j < HDN_JITTER_TEST_REUSE; j++)
				if (record->backing == test->previous[j])
					test->matches++;
		} else {
			test->previous[i] = record->backing;
		}
		rcu_read_unlock();
	}
	for (i = 0; i < allocated; i++)
		hdn_jitter_free(type->cache, test->payloads[i]);
	return result;
}

int hdn_jitter_test_run(unsigned int mode)
{
	const siphash_key_t seed = { { 0xc61f983b812d0a65ULL, 0x96a320cdd0517be4ULL } };
	struct jitter_class *type = &classes[HDN_JITTER_TEST];
	struct jitter_test_reuse reuse;
	struct jitter_record *record, *other_record;
	void *pointer, *other;
	unsigned long offsets = 0;
	unsigned int first_cpu, second_cpu, groom_success[HDN_JITTER_CLASS_MAX] = { }, i;
	long result;

	if (mode > 8)
		return -EINVAL;
	if (!mode) {
		first_cpu = cpumask_first(cpu_online_mask);
		second_cpu = cpumask_next(first_cpu, cpu_online_mask);
		if (second_cpu >= nr_cpu_ids)
			second_cpu = first_cpu;
		for (i = HDN_JITTER_CRED; i < HDN_JITTER_CLASS_MAX; i++) {
			reuse = (struct jitter_test_reuse) {
				.key = seed, .class_id = i, .deterministic = i == HDN_JITTER_TEST,
			};
			result = work_on_cpu(first_cpu, jitter_test_reuse_cpu, &reuse);
			if (result)
				return result;
			rcu_barrier();
			reuse.compare = true;
			reuse.sequence = HDN_JITTER_TEST_REUSE;
			result = work_on_cpu(second_cpu, jitter_test_reuse_cpu, &reuse);
			if (result)
				return result;
			rcu_barrier();
			groom_success[i] = reuse.matches;
			if (reuse.matches)
				return -EUCLEAN;
		}
		for (i = 0; i < 128; i++) {
			pointer = jitter_alloc(type->cache, GFP_KERNEL | __GFP_ZERO, &seed, i);
			if (!pointer)
				return -ENOMEM;
			rcu_read_lock();
			record = lookup(pointer);
			offsets |= BIT(record->offset / type->align - 1);
			check_payload(pointer, HDN_JITTER_TEST, false);
			if (!IS_ALIGNED((unsigned long)pointer, type->align) ||
			    memchr_inv(pointer, 0, type->payload_size))
				jitter_corruption(HDN_JITTER_TEST);
			memset(pointer, 0x5a, type->payload_size);
			hdn_jitter_free(type->cache, pointer);
			/* A pre-existing RCU observer must retain its original payload. */
			if (memchr_inv(pointer, 0x5a, type->payload_size))
				jitter_corruption(HDN_JITTER_TEST);
			rcu_read_unlock();
		}
		rcu_barrier();
		if (offsets != GENMASK(HDN_JITTER_SLOTS - 1, 0))
			return -EUCLEAN;
		pr_info("HDN_JITTER_FIXTURE_PASS offsets=%lx rcu=preserved cross_cpu_reuse=blocked cpus=%u,%u groom=cred:%u/%u,file:%u/%u,backing:%u/%u,test:%u/%u\n",
			offsets, first_cpu, second_cpu,
			groom_success[HDN_JITTER_CRED], HDN_JITTER_TEST_REUSE,
			groom_success[HDN_JITTER_FILE], HDN_JITTER_TEST_REUSE,
			groom_success[HDN_JITTER_BACKING_FILE], HDN_JITTER_TEST_REUSE,
			groom_success[HDN_JITTER_TEST], HDN_JITTER_TEST_REUSE);
		return 0;
	}
	pointer = jitter_alloc(type->cache, GFP_KERNEL | __GFP_ZERO, &seed, mode);
	if (!pointer)
		return -ENOMEM;
	rcu_read_lock();
	record = lookup(pointer);
	if (mode == 5)
		record->test_hold = true;
	rcu_read_unlock();
	pr_info("HDN_JITTER_FIXTURE_TRIGGER mode=%u\n", mode);
	switch (mode) {
	case 1:
	case 2:
		kasan_disable_current();
		if (mode == 1)
			((u8 *)pointer)[-1] ^= 1;
		else
			((u8 *)pointer)[type->payload_size] ^= 1;
		kasan_enable_current();
		check_payload(pointer, HDN_JITTER_TEST, false);
		break;
	case 3:
		kfree(pointer);
		break;
	case 4:
		hdn_jitter_free(classes[HDN_JITTER_CRED].cache, pointer);
		break;
	case 5:
		hdn_jitter_free(type->cache, pointer);
		rcu_barrier();
		kasan_disable_current();
		((u8 *)pointer)[-1] ^= 1;
		kasan_enable_current();
		release_record(record);
		break;
	case 6:
		other = jitter_alloc(type->cache, GFP_KERNEL, &seed, mode);
		if (!other) {
			hdn_jitter_free(type->cache, pointer);
			return -ENOMEM;
		}
		rcu_read_lock();
		other_record = lookup(other);
		kasan_disable_current();
		put_unaligned(canary(record, 0), (u64 *)(other_record->payload - sizeof(u64)));
		put_unaligned(canary(record, 1), (u64 *)(other_record->payload + type->payload_size));
		kasan_enable_current();
		check_payload(other, HDN_JITTER_TEST, false);
		rcu_read_unlock();
		break;
	case 7:
		pr_emerg("HDN_JITTER_VMCORE record=%px backing=%px payload=%px class=%u offset=%u generation=%llu\n",
			 record, record->backing, record->payload,
			 record->cache->hdn_jitter_class, record->offset, record->generation);
		panic("HDN critical object vmcore capture requested");
	case 8:
		hdn_jitter_free(type->cache, pointer);
		for (i = U32_MAX - 2; ; i++) {
			if (jitter_alloc(type->cache, GFP_KERNEL, &seed, i))
				return -EUCLEAN;
			if (i == U32_MAX)
				break;
		}
		other = jitter_alloc(type->cache, GFP_KERNEL, &seed, 9);
		if (!other)
			return -ENOMEM;
		hdn_jitter_free(type->cache, other);
		rcu_barrier();
		pr_info("HDN_JITTER_FAILURE_PASS stages=3 recovery=1\n");
		return 0;
	}
	pr_err("HDN_JITTER_FIXTURE_SURVIVED mode=%u\n", mode);
	return -EUCLEAN;
}
EXPORT_SYMBOL_GPL(hdn_jitter_test_run);
#endif
