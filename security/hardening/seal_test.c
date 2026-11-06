// SPDX-License-Identifier: GPL-2.0-only
#include <kunit/test.h>
#include <linux/completion.h>
#include <linux/hdn_execmem.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/nodemask.h>
#include <linux/rcupdate.h>
#include <linux/sched/task.h>
#include <linux/set_memory.h>
#include <linux/timekeeping.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include "seal.h"

#define HDN_SEAL_TEST_MAGIC 0x51ea10b1ec7ULL

struct hdn_seal_test_payload {
	struct hdn_seal *seal;
	u64 magic;
	u64 values[];
};

static int hdn_test_seal_validate(const void *data, size_t size)
{
	const struct hdn_seal_test_payload *payload = data;

	return size == PAGE_SIZE && payload->seal &&
	       payload->magic == HDN_SEAL_TEST_MAGIC ? 0 : -EINVAL;
}

static struct hdn_seal *hdn_test_seal_handle(const void *data)
{
	return ((const struct hdn_seal_test_payload *)data)->seal;
}

const struct hdn_seal_type hdn_test_seal_type = {
	.id = 255,
	.minimum_size = PAGE_SIZE,
	.maximum_size = PAGE_SIZE,
	.alignment = __alignof__(struct hdn_seal_test_payload),
	.readers = HDN_SEAL_READER_RCU_REFCOUNT,
	.replacement = HDN_SEAL_REPLACE_COPY_RCU,
	.validate = hdn_test_seal_validate,
	.handle = hdn_test_seal_handle,
};

struct hdn_seal_test_resource {
	struct hdn_seal *object;
	bool published;
};

static void hdn_seal_test_cleanup(void *data)
{
	struct hdn_seal_test_resource *resource = data;

	if (!resource->object)
		return;
	if (resource->published)
		hdn_seal_retire(resource->object, &hdn_test_seal_type);
	else
		hdn_seal_destroy(resource->object, &hdn_test_seal_type);
}

static struct hdn_seal_test_resource *hdn_seal_test_create_node(struct kunit *test, int node)
{
	struct hdn_seal_test_resource *resource;

	resource = kunit_kzalloc(test, sizeof(*resource), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, resource);
	resource->object = hdn_seal_create(&hdn_test_seal_type, PAGE_SIZE, node);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, resource->object);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, hdn_seal_test_cleanup, resource), 0);
	return resource;
}

static struct hdn_seal_test_resource *hdn_seal_test_create(struct kunit *test)
{
	return hdn_seal_test_create_node(test, NUMA_NO_NODE);
}

static struct hdn_seal_test_payload *hdn_seal_test_write(
		struct hdn_seal_test_resource *resource)
{
	struct hdn_seal_test_payload *payload;

	payload = hdn_seal_write(resource->object, &hdn_test_seal_type);
	if (payload)
		payload->seal = resource->object;
	return payload;
}

static void hdn_seal_lifecycle_test(struct kunit *test)
{
	struct hdn_seal_test_resource *resource = hdn_seal_test_create(test);
	struct hdn_seal *object = resource->object;
	struct hdn_seal_test_payload *data = hdn_seal_test_write(resource);
	const struct hdn_seal_test_payload *read;

	KUNIT_ASSERT_NOT_NULL(test, data);
	KUNIT_EXPECT_EQ(test, hdn_seal_publish(object, &hdn_test_seal_type), -EPERM);
	KUNIT_EXPECT_EQ(test, hdn_seal_finish(object, &hdn_test_seal_type), -EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, hdn_seal_write(object, &hdn_policy_seal_type), NULL);
	data->magic = HDN_SEAL_TEST_MAGIC;
	KUNIT_ASSERT_EQ(test, hdn_seal_finish(object, &hdn_test_seal_type), 0);
	KUNIT_EXPECT_EQ(test, hdn_seal_finish(object, &hdn_test_seal_type), -EPERM);
	KUNIT_EXPECT_PTR_EQ(test, hdn_seal_write(object, &hdn_test_seal_type), NULL);
	KUNIT_EXPECT_PTR_EQ(test, hdn_seal_read(object, &hdn_policy_seal_type), NULL);
	read = hdn_seal_read(object, &hdn_test_seal_type);
	KUNIT_ASSERT_NOT_NULL(test, read);
	KUNIT_EXPECT_EQ(test, read->magic, HDN_SEAL_TEST_MAGIC);
	KUNIT_ASSERT_EQ(test, hdn_seal_publish(object, &hdn_test_seal_type), 0);
	resource->published = true;
	KUNIT_EXPECT_EQ(test, hdn_seal_destroy(object, &hdn_test_seal_type), -EPERM);
	KUNIT_EXPECT_EQ(test, hdn_seal_publish(object, &hdn_test_seal_type), -EPERM);
	KUNIT_ASSERT_TRUE(test, hdn_seal_get(object, &hdn_test_seal_type));
	read = hdn_seal_read(object, &hdn_test_seal_type);
	KUNIT_ASSERT_NOT_NULL(test, read);
	KUNIT_EXPECT_EQ(test, read->magic, HDN_SEAL_TEST_MAGIC);
	hdn_seal_put(object);
}

static void hdn_seal_alias_test(struct kunit *test)
{
	struct hdn_seal_test_resource *resource = hdn_seal_test_create(test);
	struct hdn_seal *object = resource->object;
	struct hdn_seal_test_payload *data = hdn_seal_test_write(resource);
	struct page *page;
	void *alias;
	u64 replacement = 0;
	u64 value;

	KUNIT_ASSERT_NOT_NULL(test, data);
	page = vmalloc_to_page(data);
	KUNIT_ASSERT_NOT_NULL(test, page);
	data->magic = HDN_SEAL_TEST_MAGIC;
	KUNIT_ASSERT_EQ(test, hdn_seal_finish(object, &hdn_test_seal_type), 0);
	KUNIT_EXPECT_LT(test, copy_to_kernel_nofault(&data->magic, &replacement,
						      sizeof(replacement)), 0);
	KUNIT_EXPECT_EQ(test, hdn_execmem_claim_data(data), -EBUSY);
	KUNIT_EXPECT_EQ(test, set_memory_rw((unsigned long)data, 1), -EPERM);
	KUNIT_EXPECT_EQ(test, set_memory_x((unsigned long)data, 1), -EPERM);
	KUNIT_EXPECT_EQ(test, set_memory_rox((unsigned long)data, 1), -EPERM);
	KUNIT_EXPECT_LT(test, copy_from_kernel_nofault(&value, page_address(page), sizeof(value)), 0);
	alias = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	KUNIT_EXPECT_PTR_EQ(test, alias, NULL);
	if (alias)
		vunmap(alias);
	alias = vmap(&page, 1, VM_MAP, PAGE_KERNEL_RO);
	KUNIT_EXPECT_PTR_EQ(test, alias, NULL);
	if (alias)
		vunmap(alias);
	KUNIT_EXPECT_FALSE(test, hdn_execmem_text_page(page));
	KUNIT_EXPECT_EQ(test, data->magic, HDN_SEAL_TEST_MAGIC);
}

struct hdn_seal_reader {
	const struct hdn_seal_test_payload __rcu *published;
	struct completion acquired;
	struct completion release;
	bool got_reference;
	bool intact;
};

static int hdn_seal_retained_reader(void *arg)
{
	struct hdn_seal_reader *reader = arg;
	struct hdn_seal *object;
	const struct hdn_seal_test_payload *published;
	const struct hdn_seal_test_payload *data;
	unsigned int i;

	rcu_read_lock();
	published = rcu_dereference(reader->published);
	object = published ? published->seal : NULL;
	reader->got_reference = object && hdn_seal_get(object, &hdn_test_seal_type);
	rcu_read_unlock();
	complete(&reader->acquired);
	wait_for_completion(&reader->release);
	if (!reader->got_reference)
		return 0;
	/* The writer has replaced publication and completed a full grace period.
	 * Only our explicit reference now keeps the old immutable payload alive. */
	data = hdn_seal_read(object, &hdn_test_seal_type);
	reader->intact = data && data->magic == HDN_SEAL_TEST_MAGIC;
	for (i = 0; reader->intact &&
	     i < (PAGE_SIZE - sizeof(*data)) / sizeof(data->values[0]); i++)
		reader->intact = data->values[i] == (0x123456789abcdef0ULL ^ i);
	hdn_seal_put(object);
	return 0;
}

static const void *hdn_seal_test_replace_publish(void *context, const void *next)
{
	struct hdn_seal_reader *reader = context;

	return rcu_replace_pointer(reader->published, next, true);
}

static void hdn_seal_replacement_test(struct kunit *test)
{
	struct hdn_seal_test_resource *old = hdn_seal_test_create(test);
	struct hdn_seal_test_resource *next = hdn_seal_test_create(test);
	struct hdn_seal_reader reader = {};
	struct task_struct *task;
	struct hdn_seal_test_payload *data;
	struct hdn_seal_test_payload *next_data;
	unsigned int i;
	int error;

	data = hdn_seal_test_write(old);
	KUNIT_ASSERT_NOT_NULL(test, data);
	data->magic = HDN_SEAL_TEST_MAGIC;
	for (i = 0; i < (PAGE_SIZE - sizeof(*data)) / sizeof(data->values[0]); i++)
		data->values[i] = 0x123456789abcdef0ULL ^ i;
	KUNIT_ASSERT_EQ(test, hdn_seal_finish(old->object, &hdn_test_seal_type), 0);
	KUNIT_ASSERT_EQ(test, hdn_seal_publish(old->object, &hdn_test_seal_type), 0);
	old->published = true;
	next_data = hdn_seal_test_write(next);
	KUNIT_ASSERT_NOT_NULL(test, next_data);
	next_data->magic = HDN_SEAL_TEST_MAGIC;
	for (i = 0; i < (PAGE_SIZE - sizeof(*next_data)) /
	     sizeof(next_data->values[0]); i++)
		next_data->values[i] = 0xfedcba9876543210ULL ^ i;
	KUNIT_ASSERT_EQ(test, hdn_seal_finish(next->object, &hdn_test_seal_type), 0);
	init_completion(&reader.acquired);
	init_completion(&reader.release);
	rcu_assign_pointer(reader.published, data);
	task = kthread_run(hdn_seal_retained_reader, &reader, "hdn-seal-reader");
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, task);
	get_task_struct(task);
	/* From this point every exit wakes and joins the reader before unwinding. */
	if (!wait_for_completion_timeout(&reader.acquired, 5 * HZ)) {
		KUNIT_FAIL(test, "retained reader did not start");
		goto join;
	}
	KUNIT_EXPECT_TRUE(test, reader.got_reference);
	error = hdn_seal_replace(next->object, &hdn_test_seal_type,
				 hdn_seal_test_replace_publish, &reader);
	KUNIT_EXPECT_EQ(test, error, 0);
	if (!error) {
		old->object = NULL; /* retirement owns the publication reference */
		old->published = false;
		next->published = true;
	}
	rcu_barrier();
	KUNIT_EXPECT_PTR_EQ(test, hdn_seal_write(next->object, &hdn_test_seal_type), NULL);
join:
	RCU_INIT_POINTER(reader.published, NULL);
	complete(&reader.release);
	kthread_stop(task);
	put_task_struct(task);
	KUNIT_EXPECT_TRUE(test, reader.intact);
}

static void hdn_seal_numa_test(struct kunit *test)
{
	int node;

	for_each_online_node(node) {
		struct hdn_seal_test_resource *resource = hdn_seal_test_create_node(test, node);
		struct hdn_seal_test_payload *data = hdn_seal_test_write(resource);
		const struct hdn_seal_test_payload *read;

		KUNIT_ASSERT_NOT_NULL(test, data);
		data->magic = HDN_SEAL_TEST_MAGIC;
		KUNIT_ASSERT_EQ(test, hdn_seal_finish(resource->object, &hdn_test_seal_type), 0);
		read = hdn_seal_read(resource->object, &hdn_test_seal_type);
		KUNIT_ASSERT_NOT_NULL(test, read);
		KUNIT_EXPECT_EQ(test, read->magic, HDN_SEAL_TEST_MAGIC);
		KUNIT_ASSERT_EQ(test, hdn_seal_destroy(resource->object, &hdn_test_seal_type), 0);
		resource->object = NULL;
	}
	KUNIT_EXPECT_EQ(test, PTR_ERR(hdn_seal_create(&hdn_test_seal_type, PAGE_SIZE, MAX_NUMNODES)), -EINVAL);
}

struct hdn_seal_builder_attack {
	struct hdn_seal *object;
	struct completion done;
	bool write_rejected;
	int finish_error;
	int destroy_error;
};

static int hdn_seal_wrong_builder(void *arg)
{
	struct hdn_seal_builder_attack *attack = arg;

	attack->write_rejected =
		!hdn_seal_write(attack->object, &hdn_test_seal_type);
	attack->finish_error = hdn_seal_finish(attack->object,
					       &hdn_test_seal_type);
	attack->destroy_error = hdn_seal_destroy(attack->object,
						 &hdn_test_seal_type);
	complete(&attack->done);
	return 0;
}

static void hdn_seal_builder_test(struct kunit *test)
{
	struct hdn_seal_test_resource *resource = hdn_seal_test_create(test);
	struct hdn_seal_builder_attack attack = {
		.object = resource->object,
	};
	struct hdn_seal_test_payload *payload;
	struct task_struct *task;

	init_completion(&attack.done);
	task = kthread_run(hdn_seal_wrong_builder, &attack,
			   "hdn-seal-wrong-builder");
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, task);
	get_task_struct(task);
	if (!wait_for_completion_timeout(&attack.done, 5 * HZ))
		KUNIT_FAIL(test, "wrong-builder probe did not finish");
	kthread_stop(task);
	put_task_struct(task);
	KUNIT_EXPECT_TRUE(test, attack.write_rejected);
	KUNIT_EXPECT_EQ(test, attack.finish_error, -EPERM);
	KUNIT_EXPECT_EQ(test, attack.destroy_error, -EPERM);

	payload = hdn_seal_test_write(resource);
	KUNIT_ASSERT_NOT_NULL(test, payload);
	payload->magic = HDN_SEAL_TEST_MAGIC;
	KUNIT_ASSERT_EQ(test, hdn_seal_finish(resource->object,
					      &hdn_test_seal_type), 0);
}

static void hdn_seal_validation_cleanup_test(struct kunit *test)
{
	struct hdn_seal_test_resource *resource = hdn_seal_test_create(test);
	struct hdn_seal_test_payload *payload = hdn_seal_test_write(resource);

	KUNIT_ASSERT_NOT_NULL(test, payload);
	KUNIT_EXPECT_EQ(test, hdn_seal_finish(resource->object,
					      &hdn_test_seal_type), -EINVAL);
	KUNIT_ASSERT_EQ(test, hdn_seal_destroy(resource->object,
					       &hdn_test_seal_type), 0);
	resource->object = NULL;
}

static void hdn_seal_metrics_test(struct kunit *test)
{
	struct hdn_seal_stats before;
	struct hdn_seal_stats after;
	struct hdn_seal_test_resource *resource;
	struct hdn_seal_test_payload *payload;
	const struct hdn_seal_test_payload *read;
	u64 seal_started;
	u64 seal_ns;
	u64 read_started;
	u64 read_ns;
	u64 sink = 0;
	unsigned int i;

	hdn_seal_get_stats(&before);
	resource = hdn_seal_test_create(test);
	payload = hdn_seal_test_write(resource);
	KUNIT_ASSERT_NOT_NULL(test, payload);
	payload->magic = HDN_SEAL_TEST_MAGIC;
	seal_started = ktime_get_mono_fast_ns();
	KUNIT_ASSERT_EQ(test, hdn_seal_finish(resource->object,
					      &hdn_test_seal_type), 0);
	seal_ns = ktime_get_mono_fast_ns() - seal_started;
	KUNIT_ASSERT_EQ(test, hdn_seal_publish(resource->object,
					       &hdn_test_seal_type), 0);
	resource->published = true;

	read_started = ktime_get_mono_fast_ns();
	for (i = 0; i < 10000; i++) {
		read = hdn_seal_read(resource->object, &hdn_test_seal_type);
		KUNIT_ASSERT_NOT_NULL(test, read);
		sink ^= READ_ONCE(read->magic);
		barrier();
	}
	read_ns = ktime_get_mono_fast_ns() - read_started;
	hdn_seal_get_stats(&after);

	KUNIT_EXPECT_EQ(test, sink, 0ULL);
	kunit_info(test,
		   "metrics class=test objects=%llu pages=%llu payload_bytes=%llu granule_bytes=%llu fragmentation_bytes=%llu seal_ns=%llu read_ops=10000 read_total_ns=%llu",
		   after.live_objects - before.live_objects,
		   after.live_pages - before.live_pages,
		   after.live_payload_bytes - before.live_payload_bytes,
		   after.live_granule_bytes - before.live_granule_bytes,
		   (after.live_granule_bytes - before.live_granule_bytes) -
		   (after.live_payload_bytes - before.live_payload_bytes),
		   seal_ns, read_ns);
}

static struct kunit_case hdn_seal_cases[] = {
	KUNIT_CASE(hdn_seal_lifecycle_test),
	KUNIT_CASE(hdn_seal_alias_test),
	KUNIT_CASE(hdn_seal_replacement_test),
	KUNIT_CASE(hdn_seal_numa_test),
	KUNIT_CASE(hdn_seal_builder_test),
	KUNIT_CASE(hdn_seal_validation_cleanup_test),
	KUNIT_CASE(hdn_seal_metrics_test),
	{}
};

struct kunit_suite hdn_seal_suite = {
	.name = "hdn-kernseal",
	.test_cases = hdn_seal_cases,
};
EXPORT_SYMBOL_GPL(hdn_seal_suite);
