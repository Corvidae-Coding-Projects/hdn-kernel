// SPDX-License-Identifier: GPL-2.0-only
/* Built in deliberately: a module may never request a built-in domain. */
#include <kunit/test.h>
#include <linux/completion.h>
#include <linux/hdn_alloc.h>
#include <linux/mmzone.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include "../../mm/slab.h"

#define HDN_TEST_ID_A 0x4155544f534c4142ULL
#define HDN_TEST_ID_B 0x534c414249534f4cULL
#define HDN_TEST_ID_FAIL 0x4641494c534c4142ULL

struct autoslab_rcu_object {
	struct rcu_head rcu;
	struct completion *done;
	struct kmem_cache *cache;
	u64 payload;
};

static unsigned int allocation_domain(const void *pointer)
{
	struct page *page;
	struct slab *slab;

	if (is_vmalloc_addr(pointer))
		return find_vm_area(pointer)->hdn_alloc_domain;
	page = virt_to_page(pointer);
	slab = page_slab(page);
	return slab ? slab->slab_cache->hdn_alloc_domain : page_private(page);
}

static void autoslab_rcu_free(struct rcu_head *head)
{
	struct autoslab_rcu_object *object =
		container_of(head, struct autoslab_rcu_object, rcu);
	struct completion *done = object->done;

	kmem_cache_free(object->cache, object);
	complete(done);
}

static void domains_and_resize(struct kunit *test)
{
	struct hdn_alloc_stats before, after;
	void *a, *b, *grown;
	unsigned int i;

	hdn_alloc_get_stats(&before);
	for (i = 0; i < 32; i++) {
		a = __hdn_alloc_typed(128, GFP_KERNEL_ACCOUNT | __GFP_ZERO,
				      NUMA_NO_NODE, 0, HDN_TEST_ID_A, HDN_ALLOC_IPC_QUEUE);
		b = __hdn_alloc_typed(128, GFP_KERNEL_ACCOUNT, NUMA_NO_NODE,
				      0, HDN_TEST_ID_B, HDN_ALLOC_SHM);
		if (!a || !b) {
			kfree(a);
			kfree(b);
			KUNIT_FAIL(test, "domain allocation failed");
			return;
		}
		KUNIT_EXPECT_EQ(test, allocation_domain(a), (unsigned int)HDN_ALLOC_IPC_QUEUE);
		KUNIT_EXPECT_EQ(test, allocation_domain(b), (unsigned int)HDN_ALLOC_SHM);
		KUNIT_EXPECT_TRUE(test, IS_ALIGNED((unsigned long)a, 128));
		KUNIT_EXPECT_PTR_NE(test, virt_to_slab(a)->slab_cache, virt_to_slab(b)->slab_cache);
		KUNIT_EXPECT_PTR_EQ(test, memchr_inv(a, 0, 128), NULL);
		memset(a, 0x5a, 128);
		grown = kvrealloc(a, 2 * KMALLOC_MAX_CACHE_SIZE, GFP_KERNEL_ACCOUNT);
		if (!grown) {
			kfree(a);
			kfree(b);
			KUNIT_FAIL(test, "domain growth failed");
			return;
		}
		KUNIT_EXPECT_EQ(test, allocation_domain(grown), (unsigned int)HDN_ALLOC_IPC_QUEUE);
		KUNIT_EXPECT_PTR_EQ(test, memchr_inv(grown, 0x5a, 128), NULL);
		kvfree(grown);
		kfree(b);
	}
	hdn_alloc_get_stats(&after);
	KUNIT_EXPECT_GE(test, after.typed - before.typed, 64ULL);
	KUNIT_EXPECT_GE(test, after.successful - before.successful, 64ULL);
	KUNIT_EXPECT_GE(test, after.mandatory - before.mandatory, 64ULL);
}

static void planes_nodes_and_failure(struct kunit *test)
{
	struct hdn_alloc_stats before, after;
	void *normal, *accounted, *reclaimable, *node_object;
	struct kmem_cache *normal_cache, *accounted_cache, *reclaim_cache;
	u64 test_attempts, test_failures;
	int node = first_memory_node;

	normal = __hdn_alloc_typed(256, GFP_KERNEL, NUMA_NO_NODE, 0,
				   HDN_TEST_ID_A, HDN_ALLOC_IPC_QUEUE);
	accounted = __hdn_alloc_typed(256, GFP_KERNEL_ACCOUNT, NUMA_NO_NODE, 0,
				      HDN_TEST_ID_A, HDN_ALLOC_IPC_QUEUE);
	reclaimable = __hdn_alloc_typed(256, GFP_KERNEL | __GFP_RECLAIMABLE,
					NUMA_NO_NODE, 0, HDN_TEST_ID_A,
					HDN_ALLOC_IPC_QUEUE);
	if (!normal || !accounted || !reclaimable) {
		kfree(normal);
		kfree(accounted);
		kfree(reclaimable);
		KUNIT_FAIL(test, "allocation-plane setup failed");
		return;
	}
	normal_cache = virt_to_slab(normal)->slab_cache;
	accounted_cache = virt_to_slab(accounted)->slab_cache;
	reclaim_cache = virt_to_slab(reclaimable)->slab_cache;
	KUNIT_EXPECT_EQ(test, normal_cache->hdn_alloc_domain,
			(unsigned int)HDN_ALLOC_IPC_QUEUE);
	KUNIT_EXPECT_TRUE(test, reclaim_cache->flags & SLAB_RECLAIM_ACCOUNT);
	if (IS_ENABLED(CONFIG_MEMCG)) {
		KUNIT_EXPECT_TRUE(test, accounted_cache->flags & SLAB_ACCOUNT);
		KUNIT_EXPECT_PTR_NE(test, normal_cache, accounted_cache);
	}
	KUNIT_EXPECT_PTR_NE(test, normal_cache, reclaim_cache);
	kfree(normal);
	kfree(accounted);
	kfree(reclaimable);

	node_object = __hdn_alloc_typed(256, GFP_KERNEL | __GFP_THISNODE, node, 0,
					HDN_TEST_ID_A, HDN_ALLOC_IPC_QUEUE);
	if (!node_object) {
		KUNIT_FAIL(test, "node-local allocation failed");
		return;
	}
	KUNIT_EXPECT_EQ(test, page_to_nid(virt_to_page(node_object)), node);
	kfree(node_object);

	hdn_alloc_get_stats(&before);
	KUNIT_ASSERT_EQ(test, hdn_alloc_test_fail(HDN_TEST_ID_FAIL), 0);
	normal = __hdn_alloc_typed(64, GFP_KERNEL | __GFP_NOWARN, NUMA_NO_NODE, 0,
				   HDN_TEST_ID_FAIL, HDN_ALLOC_IPC_QUEUE);
	hdn_alloc_test_clear(&test_attempts, &test_failures);
	KUNIT_EXPECT_PTR_EQ(test, normal, NULL);
	KUNIT_EXPECT_EQ(test, test_attempts, 1ULL);
	KUNIT_EXPECT_EQ(test, test_failures, 1ULL);
	hdn_alloc_get_stats(&after);
	KUNIT_EXPECT_GE(test, after.typed - before.typed, 1ULL);
	KUNIT_EXPECT_GE(test, after.failed - before.failed, 1ULL);
}

static void bulk_rcu_and_shrink(struct kunit *test)
{
	struct kmem_cache *first, *second;
	struct autoslab_rcu_object *delayed;
	struct completion *done;
	void **objects;
	unsigned int count;

	objects = kunit_kcalloc(test, 256, sizeof(*objects), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, objects);
	done = kunit_kzalloc(test, sizeof(*done), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, done);
	init_completion(done);

	first = kmem_cache_create("hdn-autoslab-bulk-a",
				  sizeof(struct autoslab_rcu_object), 0,
				  SLAB_ACCOUNT | SLAB_HDN_DOMAIN, NULL);
	if (!first) {
		KUNIT_FAIL(test, "first bulk cache creation failed");
		return;
	}
	second = kmem_cache_create("hdn-autoslab-bulk-b",
				   sizeof(struct autoslab_rcu_object), 0,
				   SLAB_ACCOUNT | SLAB_HDN_DOMAIN, NULL);
	if (!second) {
		kmem_cache_destroy(first);
		KUNIT_FAIL(test, "second bulk cache creation failed");
		return;
	}
	hdn_cache_domain(first, HDN_ALLOC_JITTER_META);
	hdn_cache_domain(second, HDN_ALLOC_JITTER_TEST);
	KUNIT_ASSERT_PTR_NE(test, first, second);

	count = kmem_cache_alloc_bulk(first, GFP_KERNEL_ACCOUNT,
				      256, objects);
	if (count != 256) {
		kmem_cache_free_bulk(first, count, objects);
		kmem_cache_destroy(first);
		kmem_cache_destroy(second);
		KUNIT_FAIL(test, "bulk allocation returned a partial batch");
		return;
	}
	for (unsigned int i = 0; i < count; i++) {
		KUNIT_EXPECT_PTR_EQ(test, virt_to_slab(objects[i])->slab_cache, first);
		KUNIT_EXPECT_EQ(test, allocation_domain(objects[i]),
				(unsigned int)HDN_ALLOC_JITTER_META);
	}
	delayed = objects[--count];
	delayed->done = done;
	delayed->cache = first;
	delayed->payload = HDN_TEST_ID_A;
	call_rcu(&delayed->rcu, autoslab_rcu_free);
	kmem_cache_free_bulk(first, count, objects);
	wait_for_completion(done);
	rcu_barrier();
	KUNIT_EXPECT_EQ(test, kmem_cache_shrink(first), 0);
	KUNIT_EXPECT_EQ(test, kmem_cache_shrink(second), 0);
	kmem_cache_destroy(first);
	kmem_cache_destroy(second);
}

static struct kunit_case autoslab_cases[] = {
	KUNIT_CASE(domains_and_resize),
	KUNIT_CASE(planes_nodes_and_failure),
	KUNIT_CASE(bulk_rcu_and_shrink),
	{}
};
static struct kunit_suite autoslab_suite = {
	.name = "hdn-autoslab", .test_cases = autoslab_cases,
};
kunit_test_suite(autoslab_suite);
MODULE_LICENSE("GPL");
