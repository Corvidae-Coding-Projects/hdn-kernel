// SPDX-License-Identifier: GPL-2.0
#include <kunit/test.h>
#include <kunit/test-bug.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/rcupdate.h>
#include <linux/delay.h>
#include <linux/hdn_slab.h>
#include <linux/lcm.h>
#include "../mm/slab.h"

static struct kunit_resource resource;
static int slab_errors;

/*
 * Wrapper function for kmem_cache_create(), which reduces 2 parameters:
 * 'align' and 'ctor', and sets SLAB_SKIP_KFENCE flag to avoid getting an
 * object from kfence pool, where the operation could be caught by both
 * our test and kfence sanity check.
 */
static struct kmem_cache *test_kmem_cache_create(const char *name,
				unsigned int size, slab_flags_t flags)
{
	struct kmem_cache *s = kmem_cache_create(name, size, 0,
					(flags | SLAB_NO_USER_FLAGS), NULL);
	s->flags |= SLAB_SKIP_KFENCE;
	return s;
}

static void test_clobber_zone(struct kunit *test)
{
	struct kmem_cache *s = test_kmem_cache_create("TestSlub_RZ_alloc", 64,
							SLAB_RED_ZONE);
	u8 *p = kmem_cache_alloc(s, GFP_KERNEL);

	kasan_disable_current();
	p[64] = 0x12;

	validate_slab_cache(s);
	KUNIT_EXPECT_EQ(test, 2, slab_errors);

	kasan_enable_current();
	kmem_cache_free(s, p);
	kmem_cache_destroy(s);
}

#ifndef CONFIG_KASAN
static void test_next_pointer(struct kunit *test)
{
	struct kmem_cache *s = test_kmem_cache_create("TestSlub_next_ptr_free",
							64, SLAB_POISON);
	u8 *p = kmem_cache_alloc(s, GFP_KERNEL);
	unsigned long tmp;
	unsigned long *ptr_addr;

	kmem_cache_free(s, p);

	ptr_addr = (unsigned long *)(p + s->offset);
	tmp = *ptr_addr;
	p[s->offset] = ~p[s->offset];

	/*
	 * Expecting three errors.
	 * One for the corrupted freechain and the other one for the wrong
	 * count of objects in use. The third error is fixing broken cache.
	 */
	validate_slab_cache(s);
	KUNIT_EXPECT_EQ(test, 3, slab_errors);

	/*
	 * Try to repair corrupted freepointer.
	 * Still expecting two errors. The first for the wrong count
	 * of objects in use.
	 * The second error is for fixing broken cache.
	 */
	*ptr_addr = tmp;
	slab_errors = 0;

	validate_slab_cache(s);
	KUNIT_EXPECT_EQ(test, 2, slab_errors);

	/*
	 * Previous validation repaired the count of objects in use.
	 * Now expecting no error.
	 */
	slab_errors = 0;
	validate_slab_cache(s);
	KUNIT_EXPECT_EQ(test, 0, slab_errors);

	kmem_cache_destroy(s);
}

static void test_first_word(struct kunit *test)
{
	struct kmem_cache *s = test_kmem_cache_create("TestSlub_1th_word_free",
							64, SLAB_POISON);
	u8 *p = kmem_cache_alloc(s, GFP_KERNEL);

	kmem_cache_free(s, p);
	*p = 0x78;

	validate_slab_cache(s);
	KUNIT_EXPECT_EQ(test, 2, slab_errors);

	kmem_cache_destroy(s);
}

static void test_clobber_50th_byte(struct kunit *test)
{
	struct kmem_cache *s = test_kmem_cache_create("TestSlub_50th_word_free",
							64, SLAB_POISON);
	u8 *p = kmem_cache_alloc(s, GFP_KERNEL);

	kmem_cache_free(s, p);
	p[50] = 0x9a;

	validate_slab_cache(s);
	KUNIT_EXPECT_EQ(test, 2, slab_errors);

	kmem_cache_destroy(s);
}
#endif

static void test_clobber_redzone_free(struct kunit *test)
{
	struct kmem_cache *s = test_kmem_cache_create("TestSlub_RZ_free", 64,
							SLAB_RED_ZONE);
	u8 *p = kmem_cache_alloc(s, GFP_KERNEL);

	kasan_disable_current();
	kmem_cache_free(s, p);
	p[64] = 0xab;

	validate_slab_cache(s);
	KUNIT_EXPECT_EQ(test, 2, slab_errors);

	kasan_enable_current();
	kmem_cache_destroy(s);
}

static void test_kmalloc_redzone_access(struct kunit *test)
{
	struct kmem_cache *s = test_kmem_cache_create("TestSlub_RZ_kmalloc", 32,
				SLAB_KMALLOC|SLAB_STORE_USER|SLAB_RED_ZONE);
	u8 *p = alloc_hooks(__kmalloc_cache_noprof(s, GFP_KERNEL, 18));

	kasan_disable_current();

	/* Suppress the -Warray-bounds warning */
	OPTIMIZER_HIDE_VAR(p);
	p[18] = 0xab;
	p[19] = 0xab;

	validate_slab_cache(s);
	KUNIT_EXPECT_EQ(test, 2, slab_errors);

	kasan_enable_current();
	kmem_cache_free(s, p);
	kmem_cache_destroy(s);
}

struct test_kfree_rcu_struct {
	struct rcu_head rcu;
};

static void test_kfree_rcu(struct kunit *test)
{
	struct kmem_cache *s;
	struct test_kfree_rcu_struct *p;

	if (IS_BUILTIN(CONFIG_SLUB_KUNIT_TEST))
		kunit_skip(test, "can't do kfree_rcu() when test is built-in");

	s = test_kmem_cache_create("TestSlub_kfree_rcu",
				   sizeof(struct test_kfree_rcu_struct),
				   SLAB_NO_MERGE);
	p = kmem_cache_alloc(s, GFP_KERNEL);

	kfree_rcu(p, rcu);
	kmem_cache_destroy(s);

	KUNIT_EXPECT_EQ(test, 0, slab_errors);
}

struct cache_destroy_work {
	struct work_struct work;
	struct kmem_cache *s;
};

static void cache_destroy_workfn(struct work_struct *w)
{
	struct cache_destroy_work *cdw;

	cdw = container_of(w, struct cache_destroy_work, work);
	kmem_cache_destroy(cdw->s);
}

#define KMEM_CACHE_DESTROY_NR 10

static void test_kfree_rcu_wq_destroy(struct kunit *test)
{
	struct test_kfree_rcu_struct *p;
	struct cache_destroy_work cdw;
	struct workqueue_struct *wq;
	struct kmem_cache *s;
	unsigned int delay;
	int i;

	if (IS_BUILTIN(CONFIG_SLUB_KUNIT_TEST))
		kunit_skip(test, "can't do kfree_rcu() when test is built-in");

	INIT_WORK_ONSTACK(&cdw.work, cache_destroy_workfn);
	wq = alloc_workqueue("test_kfree_rcu_destroy_wq",
			WQ_HIGHPRI | WQ_UNBOUND | WQ_MEM_RECLAIM, 0);

	if (!wq)
		kunit_skip(test, "failed to alloc wq");

	for (i = 0; i < KMEM_CACHE_DESTROY_NR; i++) {
		s = test_kmem_cache_create("TestSlub_kfree_rcu_wq_destroy",
				sizeof(struct test_kfree_rcu_struct),
				SLAB_NO_MERGE);

		if (!s)
			kunit_skip(test, "failed to create cache");

		delay = get_random_u8();
		p = kmem_cache_alloc(s, GFP_KERNEL);
		kfree_rcu(p, rcu);

		cdw.s = s;

		msleep(delay);
		queue_work(wq, &cdw.work);
		flush_work(&cdw.work);
	}

	destroy_workqueue(wq);
	KUNIT_EXPECT_EQ(test, 0, slab_errors);
}

static void test_leak_destroy(struct kunit *test)
{
	struct kmem_cache *s = test_kmem_cache_create("TestSlub_leak_destroy",
							64, SLAB_NO_MERGE);
	kmem_cache_alloc(s, GFP_KERNEL);

	kmem_cache_destroy(s);

	KUNIT_EXPECT_EQ(test, 2, slab_errors);
}

static void test_krealloc_redzone_zeroing(struct kunit *test)
{
	u8 *p;
	int i;
	struct kmem_cache *s = test_kmem_cache_create("TestSlub_krealloc", 64,
				SLAB_KMALLOC|SLAB_STORE_USER|SLAB_RED_ZONE);

	p = alloc_hooks(__kmalloc_cache_noprof(s, GFP_KERNEL, 48));
	memset(p, 0xff, 48);

	kasan_disable_current();
	OPTIMIZER_HIDE_VAR(p);

	/* Test shrink */
	p = krealloc(p, 40, GFP_KERNEL | __GFP_ZERO);
	for (i = 40; i < 64; i++)
		KUNIT_EXPECT_EQ(test, p[i], SLUB_RED_ACTIVE);

	/* Test grow within the same 64B kmalloc object */
	p = krealloc(p, 56, GFP_KERNEL | __GFP_ZERO);
	for (i = 40; i < 56; i++)
		KUNIT_EXPECT_EQ(test, p[i], 0);
	for (i = 56; i < 64; i++)
		KUNIT_EXPECT_EQ(test, p[i], SLUB_RED_ACTIVE);

	validate_slab_cache(s);
	KUNIT_EXPECT_EQ(test, 0, slab_errors);

	memset(p, 0xff, 56);
	/* Test grow with allocating a bigger 128B object */
	p = krealloc(p, 112, GFP_KERNEL | __GFP_ZERO);
	for (i = 0; i < 56; i++)
		KUNIT_EXPECT_EQ(test, p[i], 0xff);
	for (i = 56; i < 112; i++)
		KUNIT_EXPECT_EQ(test, p[i], 0);

	kfree(p);
	kasan_enable_current();
	kmem_cache_destroy(s);
}

#ifdef CONFIG_SECURITY_HARDENING_SLAB_LAYOUT
static void test_hdn_layout_bulk(struct kunit *test)
{
	struct kmem_cache *cache;
	struct slab *last = NULL;
	void **objects;
	unsigned int i, j, allocated, count = 8192;
	unsigned int observed_slabs = 0;
	unsigned long orders = 0, offsets = 0, expected, allowed;
	u64 sequence = 1469598103934665603ULL;

	objects = kunit_kcalloc(test, count, sizeof(*objects), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, objects);
	cache = kmem_cache_create("hdn_layout_bulk", 64, 16,
		SLAB_NO_MERGE | SLAB_NO_USER_FLAGS | SLAB_RED_ZONE | SLAB_POISON | SLAB_ACCOUNT,
		NULL);
	KUNIT_ASSERT_NOT_NULL(test, cache);
	cache->flags |= SLAB_SKIP_KFENCE;
	allocated = kmem_cache_alloc_bulk(cache, GFP_KERNEL, count, objects);
	if (allocated != count) {
		KUNIT_FAIL(test, "bulk allocation failed");
		if (allocated)
			kmem_cache_free_bulk(cache, allocated, objects);
		kmem_cache_destroy(cache);
		return;
	}
	for (i = 0; i < count; i++) {
		struct slab *slab = virt_to_slab(objects[i]);
		unsigned long base = (unsigned long)slab_address(slab);
		unsigned long pointer = (unsigned long)kasan_reset_tag(objects[i]);
		unsigned int offset = slab_object_offset(slab);
		unsigned long first = base + offset + cache->red_left_pad;

		KUNIT_EXPECT_TRUE(test, IS_ALIGNED(pointer, cache->align));
		KUNIT_EXPECT_GE(test, pointer, first);
		KUNIT_EXPECT_LE(test, pointer + 64, base + slab_size(slab));
		KUNIT_EXPECT_EQ(test, (pointer - first) % cache->size, 0UL);
		KUNIT_EXPECT_LE(test, offset + slab->objects * cache->size, slab_size(slab));
		KUNIT_EXPECT_LE(test, offset, 15U * HDN_SLAB_OFFSET_UNIT);
		KUNIT_EXPECT_EQ(test, offset % cache->align, 0U);
		KUNIT_EXPECT_EQ(test, offset % HDN_SLAB_OFFSET_UNIT, 0U);
		KUNIT_EXPECT_PTR_EQ(test, nearest_obj(cache, slab, objects[i]), objects[i]);
		orders |= BIT(slab_order(slab));
		offsets |= BIT(offset / HDN_SLAB_OFFSET_UNIT);
		if (slab != last) {
			sequence ^= ((u64)slab_order(slab) << 32) | offset;
			sequence *= 1099511628211ULL;
			observed_slabs++;
			last = slab;
		}
		memset(objects[i], (u8)i, 64);
	}
	/* Distinct live payloads must survive neighboring allocations and writes. */
	for (i = 0; i < count; i++)
		for (j = 0; j < 64; j++)
			KUNIT_EXPECT_EQ(test, ((u8 *)objects[i])[j], (u8)i);
	expected = GENMASK(oo_order(cache->oo), cache->hdn_min_order);
	allowed = GENMASK(oo_order(cache->oo), oo_order(cache->min));
	KUNIT_EXPECT_EQ(test, orders & expected, expected);
	KUNIT_EXPECT_EQ(test, orders & ~allowed, 0UL);
	KUNIT_EXPECT_GT(test, hweight_long(offsets), 1U);
	KUNIT_EXPECT_GE(test, observed_slabs, 32U);
	validate_slab_cache(cache);
	KUNIT_EXPECT_EQ(test, slab_errors, 0);
	kmem_cache_free_bulk(cache, count, objects);
	kmem_cache_shrink(cache);
	validate_slab_cache(cache);
	KUNIT_EXPECT_EQ(test, slab_errors, 0);
	kunit_info(test, "HDN_SLAB_LAYOUT_OBSERVATION slabs=%u orders=%lx offset_slots=%lx sequence=%016llx",
		   observed_slabs, orders, offsets, sequence);
	kmem_cache_destroy(cache);
}
#endif

#ifdef CONFIG_SECURITY_HARDENING_SLAB_LAYOUT_TEST
static void test_hdn_layout_fallback(struct kunit *test)
{
	struct hdn_slab_layout_stats before, after;
	struct kmem_cache *cache;
	struct slab *slab;
	unsigned int minimum, maximum, expected_offset;
	unsigned long fail_orders;
	u64 test_attempts, test_failures;
	void *object;
	int error;

	cache = kmem_cache_create("hdn_layout_fallback", 64, 16,
		SLAB_NO_MERGE | SLAB_NO_USER_FLAGS, NULL);
	KUNIT_ASSERT_NOT_NULL(test, cache);
	cache->flags |= SLAB_SKIP_KFENCE;
	minimum = oo_order(cache->min);
	maximum = oo_order(cache->oo);
	if (maximum <= minimum) {
		KUNIT_FAIL(test, "test cache has no higher order");
		kmem_cache_destroy(cache);
		return;
	}
	fail_orders = GENMASK(maximum, minimum + 1);
	hdn_slab_layout_stats(&before);
	error = hdn_slab_layout_test_configure(cache, 1, 1, fail_orders);
	if (error) {
		KUNIT_FAIL(test, "test control unavailable: %d", error);
		kmem_cache_destroy(cache);
		return;
	}
	object = kmem_cache_alloc(cache, GFP_KERNEL);
	hdn_slab_layout_test_clear(cache, &test_attempts, &test_failures);
	if (!object) {
		KUNIT_FAIL(test, "minimum-order fallback allocation failed");
		kmem_cache_destroy(cache);
		return;
	}
	slab = virt_to_slab(object);
	expected_offset = lcm(cache->align, HDN_SLAB_OFFSET_UNIT);
	KUNIT_EXPECT_EQ(test, slab_order(slab), minimum);
	KUNIT_EXPECT_EQ(test, slab_object_offset(slab), expected_offset);
	KUNIT_EXPECT_LE(test, slab_object_offset(slab) + slab->objects * cache->size,
			slab_size(slab));
	hdn_slab_layout_stats(&after);
	KUNIT_EXPECT_EQ(test, test_attempts, (u64)(maximum - minimum + 1));
	KUNIT_EXPECT_EQ(test, test_failures, (u64)(maximum - minimum));
	KUNIT_EXPECT_GE(test, after.allocation_attempts - before.allocation_attempts,
			(u64)(maximum - minimum + 1));
	KUNIT_EXPECT_GE(test, after.allocation_failures - before.allocation_failures,
			(u64)(maximum - minimum));
	KUNIT_EXPECT_GE(test, after.fallback - before.fallback, 1ULL);
	KUNIT_EXPECT_GE(test, after.slabs - before.slabs, 1ULL);
	kunit_info(test, "HDN_SLAB_LAYOUT_FALLBACK attempts=%llu failures=%llu order=%u offset=%u",
		   test_attempts, test_failures, slab_order(slab), slab_object_offset(slab));
	kmem_cache_free(cache, object);
	kmem_cache_shrink(cache);
	kmem_cache_destroy(cache);
}
#endif

static int test_init(struct kunit *test)
{
	slab_errors = 0;

	kunit_add_named_resource(test, NULL, NULL, &resource,
					"slab_errors", &slab_errors);
	return 0;
}

static struct kunit_case test_cases[] = {
#ifdef CONFIG_SECURITY_HARDENING_SLAB_LAYOUT
	KUNIT_CASE(test_hdn_layout_bulk),
#endif
#ifdef CONFIG_SECURITY_HARDENING_SLAB_LAYOUT_TEST
	KUNIT_CASE(test_hdn_layout_fallback),
#endif
	KUNIT_CASE(test_clobber_zone),

#ifndef CONFIG_KASAN
	KUNIT_CASE(test_next_pointer),
	KUNIT_CASE(test_first_word),
	KUNIT_CASE(test_clobber_50th_byte),
#endif

	KUNIT_CASE(test_clobber_redzone_free),
	KUNIT_CASE(test_kmalloc_redzone_access),
	KUNIT_CASE(test_kfree_rcu),
	KUNIT_CASE(test_kfree_rcu_wq_destroy),
	KUNIT_CASE(test_leak_destroy),
	KUNIT_CASE(test_krealloc_redzone_zeroing),
	{}
};

static struct kunit_suite test_suite = {
	.name = "slub_test",
	.init = test_init,
	.test_cases = test_cases,
};
kunit_test_suite(test_suite);

MODULE_DESCRIPTION("Kunit tests for slub allocator");
MODULE_LICENSE("GPL");
