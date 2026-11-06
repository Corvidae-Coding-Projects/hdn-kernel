// SPDX-License-Identifier: GPL-2.0-only
#include <linux/hardening.h>
#include <linux/hdn_execmem.h>
#include <linux/log2.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/nodemask.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include "seal.h"

enum hdn_seal_state {
	HDN_SEAL_BUILDING,
	HDN_SEAL_SEALED,
	HDN_SEAL_PUBLISHED,
	HDN_SEAL_RETIRED,
	HDN_SEAL_FAILED,
	HDN_SEAL_DISCARDED,
};

/* Mutable lifetime bookkeeping never shares a granule with the payload. */
struct hdn_seal {
	const struct hdn_seal_type *type;
	void *data;
	size_t size;
	struct task_struct *builder;
	struct mutex mutex;
	refcount_t refs;
	enum hdn_seal_state state;
	struct rcu_head rcu;
	struct work_struct destroy_work;
};

static atomic64_t hdn_seal_allocations;
static atomic64_t hdn_seal_live_objects;
static atomic64_t hdn_seal_live_pages;
static atomic64_t hdn_seal_live_payload_bytes;
static atomic64_t hdn_seal_live_granule_bytes;
static atomic64_t hdn_seal_operations;
static atomic64_t hdn_seal_publications;
static atomic64_t hdn_seal_replacements;
static atomic64_t hdn_seal_retirements;
static atomic64_t hdn_seal_discards;
static atomic64_t hdn_seal_rejections;
static atomic64_t hdn_seal_allocation_failures;
static atomic64_t hdn_seal_replacement_total_ns;
static atomic64_t hdn_seal_replacement_max_ns;

static bool hdn_seal_known_type(const struct hdn_seal_type *type)
{
#ifdef CONFIG_SECURITY_HARDENING_KERNSEAL_TEST
	if (type == &hdn_test_seal_type)
		return true;
#endif
	return type == &hdn_policy_seal_type || type == &hdn_mitigation_seal_type;
}

static bool hdn_seal_valid_type(const struct hdn_seal_type *type)
{
	if (!hdn_seal_known_type(type) || !type->id || !type->minimum_size ||
	    type->minimum_size > type->maximum_size || !type->alignment ||
	    !is_power_of_2(type->alignment) || !type->validate || !type->handle)
		return false;
	if (type->readers != HDN_SEAL_READER_IMMORTAL &&
	    type->readers != HDN_SEAL_READER_RCU_REFCOUNT)
		return false;
	return type->replacement == HDN_SEAL_REPLACE_NONE ||
	       (type->replacement == HDN_SEAL_REPLACE_COPY_RCU &&
		type->readers == HDN_SEAL_READER_RCU_REFCOUNT);
}

static int hdn_seal_error(const struct hdn_seal_type *type, int error)
{
	/* Closed class IDs, never payload contents or an address. */
	atomic64_inc(&hdn_seal_rejections);
	hdn_report_kernel_seal(hdn_seal_known_type(type) ? type->id : 0, error);
	return error;
}

static void hdn_seal_update_max(atomic64_t *maximum, u64 value)
{
	s64 old = atomic64_read(maximum);

	while (old < value && !atomic64_try_cmpxchg(maximum, &old, value))
		;
}

static void hdn_seal_destroy_work(struct work_struct *work)
{
	struct hdn_seal *object = container_of(work, struct hdn_seal, destroy_work);

	if (WARN_ON_ONCE(!hdn_execmem_free(object->data)))
		return; /* Never fall back to freeing storage with uncertain ownership. */
	atomic64_dec(&hdn_seal_live_objects);
	atomic64_sub(PFN_UP(object->size), &hdn_seal_live_pages);
	atomic64_sub(object->size, &hdn_seal_live_payload_bytes);
	atomic64_sub(PAGE_ALIGN(object->size), &hdn_seal_live_granule_bytes);
	kfree(object);
}

void hdn_seal_put(struct hdn_seal *object)
{
	if (!refcount_dec_and_test(&object->refs))
		return;
	if (WARN_ON_ONCE(READ_ONCE(object->state) != HDN_SEAL_RETIRED &&
			 READ_ONCE(object->state) != HDN_SEAL_DISCARDED))
		return; /* Misuse must not reclaim a still-published payload. */
	queue_work(system_unbound_wq, &object->destroy_work);
}

struct hdn_seal *hdn_seal_create(const struct hdn_seal_type *type, size_t size, int node)
{
	struct hdn_seal *object;
	int error;

	if (!hdn_seal_valid_type(type) || size < type->minimum_size ||
	    size > type->maximum_size || size > ((size_t)INT_MAX << PAGE_SHIFT))
		return ERR_PTR(hdn_seal_error(type, -EINVAL));
	if (node != NUMA_NO_NODE &&
	    (node < 0 || node >= MAX_NUMNODES || !node_online(node)))
		return ERR_PTR(hdn_seal_error(type, -EINVAL));
	object = kmalloc_node_typed(struct hdn_seal, sizeof(*object),
				    GFP_KERNEL | __GFP_ZERO, node);
	if (!object) {
		atomic64_inc(&hdn_seal_allocation_failures);
		return ERR_PTR(hdn_seal_error(type, -ENOMEM));
	}
	object->data = __vmalloc_node_range(PAGE_ALIGN(size), PAGE_SIZE,
					    VMALLOC_START, VMALLOC_END, GFP_KERNEL | __GFP_ZERO,
					    PAGE_KERNEL, VM_FLUSH_RESET_PERMS, node,
					    __builtin_return_address(0));
	if (!object->data) {
		kfree(object);
		atomic64_inc(&hdn_seal_allocation_failures);
		return ERR_PTR(hdn_seal_error(type, -ENOMEM));
	}
	if (WARN_ON_ONCE(!IS_ALIGNED((unsigned long)object->data, type->alignment))) {
		vfree(object->data);
		kfree(object);
		return ERR_PTR(hdn_seal_error(type, -EFAULT));
	}
	error = hdn_execmem_claim_data(object->data);
	if (error) {
		vfree(object->data);
		kfree(object);
		atomic64_inc(&hdn_seal_allocation_failures);
		return ERR_PTR(hdn_seal_error(type, error));
	}
	object->type = type;
	object->size = size;
	object->builder = current;
	get_task_struct(current);
	mutex_init(&object->mutex);
	refcount_set(&object->refs, 1);
	INIT_WORK(&object->destroy_work, hdn_seal_destroy_work);
	atomic64_inc(&hdn_seal_allocations);
	atomic64_inc(&hdn_seal_live_objects);
	atomic64_add(PFN_UP(size), &hdn_seal_live_pages);
	atomic64_add(size, &hdn_seal_live_payload_bytes);
	atomic64_add(PAGE_ALIGN(size), &hdn_seal_live_granule_bytes);
	return object;
}

void *hdn_seal_write(struct hdn_seal *object, const struct hdn_seal_type *type)
{
	void *data = NULL;

	if (!object) {
		hdn_seal_error(type, -EINVAL);
		return NULL;
	}
	mutex_lock(&object->mutex);
	if (object->type == type && object->state == HDN_SEAL_BUILDING &&
	    object->builder == current)
		data = object->data;
	mutex_unlock(&object->mutex);
	if (!data)
		hdn_seal_error(type, -EPERM);
	return data;
}

const void *hdn_seal_read(const struct hdn_seal *object, const struct hdn_seal_type *type)
{
	enum hdn_seal_state state;

	if (!object) {
		hdn_seal_error(type, -EINVAL);
		return NULL;
	}
	state = smp_load_acquire(&object->state);

	if (object->type != type || (state != HDN_SEAL_SEALED &&
	    state != HDN_SEAL_PUBLISHED && state != HDN_SEAL_RETIRED)) {
		hdn_seal_error(type, -EPERM);
		return NULL;
	}
	return object->data;
}

int hdn_seal_finish(struct hdn_seal *object, const struct hdn_seal_type *type)
{
	struct task_struct *builder = NULL;
	int error = -EPERM;

	if (!object)
		return hdn_seal_error(type, -EINVAL);
	mutex_lock(&object->mutex);
	if (object->type != type || object->state != HDN_SEAL_BUILDING ||
	    object->builder != current)
		goto out;
	error = type->validate(object->data, object->size);
	if (error)
		goto out;
	error = hdn_execmem_seal_data(object->data);
	/* A failed permission change cannot return the object to its builder. */
	smp_store_release(&object->state, error ? HDN_SEAL_FAILED : HDN_SEAL_SEALED);
	builder = object->builder;
	object->builder = NULL;
out:
	mutex_unlock(&object->mutex);
	if (builder)
		put_task_struct(builder);
	if (error)
		return hdn_seal_error(type, error);
	atomic64_inc(&hdn_seal_operations);
	hdn_report_kernel_seal(type->id, 0);
	return 0;
}

int hdn_seal_publish(struct hdn_seal *object, const struct hdn_seal_type *type)
{
	int error = -EPERM;

	if (!object)
		return hdn_seal_error(type, -EINVAL);
	mutex_lock(&object->mutex);
	if (object->type == type && object->state == HDN_SEAL_SEALED) {
		smp_store_release(&object->state, HDN_SEAL_PUBLISHED);
		error = 0;
	}
	mutex_unlock(&object->mutex);
	if (error)
		return hdn_seal_error(type, error);
	atomic64_inc(&hdn_seal_publications);
	return 0;
}

int hdn_seal_replace(struct hdn_seal *object, const struct hdn_seal_type *type,
		     hdn_seal_publish_fn publish, void *context)
{
	const void *old_data;
	struct hdn_seal *old;
	u64 started;
	u64 elapsed;
	int error;

	if (!object || !publish || !hdn_seal_valid_type(type) ||
	    type->replacement != HDN_SEAL_REPLACE_COPY_RCU)
		return hdn_seal_error(type, -EINVAL);

	started = ktime_get_mono_fast_ns();
	error = hdn_seal_publish(object, type);
	if (error)
		return error;

	/* The callback owns the consumer lock and returns only the instance that
	 * lost its final publication slot. The descriptor recovers its opaque
	 * handle without accepting an arbitrary address registration. */
	old_data = publish(context, object->data);
	if (old_data) {
		old = type->handle(old_data);
		if (!old || old == object || old->type != type || old->data != old_data) {
			/* Publication is irreversible. Keep every uncertain object live
			 * rather than reporting failure and letting the caller free @object. */
			hdn_seal_error(type, -EUCLEAN);
			goto published;
		}
		error = hdn_seal_retire(old, type);
		if (error)
			goto published; /* Same fail-safe leak after publication. */
		atomic64_inc(&hdn_seal_replacements);
	}

published:
	elapsed = ktime_get_mono_fast_ns() - started;
	atomic64_add(elapsed, &hdn_seal_replacement_total_ns);
	hdn_seal_update_max(&hdn_seal_replacement_max_ns, elapsed);
	return 0;
}

bool hdn_seal_get(struct hdn_seal *object, const struct hdn_seal_type *type)
{
	if (!object || object->type != type ||
	    type->readers != HDN_SEAL_READER_RCU_REFCOUNT) {
		hdn_seal_error(type, -EPERM);
		return false;
	}
	if (smp_load_acquire(&object->state) != HDN_SEAL_PUBLISHED)
		return false;
	return refcount_inc_not_zero(&object->refs);
}

static void hdn_seal_rcu_put(struct rcu_head *rcu)
{
	struct hdn_seal *object = container_of(rcu, struct hdn_seal, rcu);

	hdn_seal_put(object);
}

int hdn_seal_retire(struct hdn_seal *object, const struct hdn_seal_type *type)
{
	int error = -EPERM;

	if (!object)
		return hdn_seal_error(type, -EINVAL);
	mutex_lock(&object->mutex);
	if (object->type == type && object->state == HDN_SEAL_PUBLISHED &&
	    type->readers == HDN_SEAL_READER_RCU_REFCOUNT) {
		smp_store_release(&object->state, HDN_SEAL_RETIRED);
		error = 0;
	}
	mutex_unlock(&object->mutex);
	if (error)
		return hdn_seal_error(type, error);
	atomic64_inc(&hdn_seal_retirements);
	/* Publication was already removed under the consumer's serialization. */
	call_rcu(&object->rcu, hdn_seal_rcu_put);
	return 0;
}

int hdn_seal_destroy(struct hdn_seal *object, const struct hdn_seal_type *type)
{
	struct task_struct *builder;
	int error = 0;

	if (!object)
		return hdn_seal_error(type, -EINVAL);
	mutex_lock(&object->mutex);
	if (object->type != type || object->state == HDN_SEAL_PUBLISHED ||
	    object->state == HDN_SEAL_RETIRED ||
	    object->state == HDN_SEAL_DISCARDED ||
	    (object->builder && object->builder != current)) {
		error = -EPERM;
		goto out;
	}
	smp_store_release(&object->state, HDN_SEAL_DISCARDED);
	builder = object->builder;
	object->builder = NULL;
	mutex_unlock(&object->mutex);
	if (builder)
		put_task_struct(builder);
	atomic64_inc(&hdn_seal_discards);
	hdn_seal_put(object);
	return 0;
out:
	mutex_unlock(&object->mutex);
	return hdn_seal_error(type, error);
}

void hdn_seal_get_stats(struct hdn_seal_stats *stats)
{
	*stats = (struct hdn_seal_stats) {
		.allocations = atomic64_read(&hdn_seal_allocations),
		.live_objects = atomic64_read(&hdn_seal_live_objects),
		.live_pages = atomic64_read(&hdn_seal_live_pages),
		.live_payload_bytes = atomic64_read(&hdn_seal_live_payload_bytes),
		.live_granule_bytes = atomic64_read(&hdn_seal_live_granule_bytes),
		.seal_operations = atomic64_read(&hdn_seal_operations),
		.publications = atomic64_read(&hdn_seal_publications),
		.replacements = atomic64_read(&hdn_seal_replacements),
		.retirements = atomic64_read(&hdn_seal_retirements),
		.discards = atomic64_read(&hdn_seal_discards),
		.rejections = atomic64_read(&hdn_seal_rejections),
		.allocation_failures = atomic64_read(&hdn_seal_allocation_failures),
		.replacement_total_ns = atomic64_read(&hdn_seal_replacement_total_ns),
		.replacement_max_ns = atomic64_read(&hdn_seal_replacement_max_ns),
	};
}
