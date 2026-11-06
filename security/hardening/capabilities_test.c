// SPDX-License-Identifier: GPL-2.0-only
#include <kunit/test.h>
#include <linux/errno.h>
#include <linux/hdn_capabilities.h>

static void hdn_capability_states_test(struct kunit *test)
{
	enum hdn_capability_state state;
	enum hdn_capability_backing backing;

	for (state = HDN_CAP_UNDECLARED; state <= HDN_CAP_NOT_APPLICABLE; state++) {
		for (backing = HDN_CAP_BACKING_NONE;
		     backing <= HDN_CAP_BACKING_HYBRID; backing++) {
			struct hdn_capability_record record =
				hdn_cap_record(HDN_CAP_KERNEL_WX, state, backing);

			KUNIT_EXPECT_TRUE(test, hdn_capability_record_valid(
				HDN_CAP_KERNEL_WX, &record));
		}
	}
}

static void hdn_capability_invalid_test(struct kunit *test)
{
	struct hdn_capability_record record = hdn_cap_record(
		HDN_CAP_KERNEL_WX, HDN_CAP_ENFORCED, HDN_CAP_BACKING_SOFTWARE);

	KUNIT_EXPECT_FALSE(test, hdn_capability_record_valid(HDN_CAP__MAX, &record));
	KUNIT_EXPECT_FALSE(test, hdn_capability_record_valid(HDN_CAP_KERNEL_WX, NULL));
	record.id = HDN_CAP_STATIC_ALIASES;
	KUNIT_EXPECT_FALSE(test, hdn_capability_record_valid(HDN_CAP_KERNEL_WX, &record));
	record.id = HDN_CAP_KERNEL_WX;
	record.state = HDN_CAP_NOT_APPLICABLE + 1;
	KUNIT_EXPECT_FALSE(test, hdn_capability_record_valid(HDN_CAP_KERNEL_WX, &record));
	record.state = HDN_CAP_ENFORCED;
	record.backing = HDN_CAP_BACKING_HYBRID + 1;
	KUNIT_EXPECT_FALSE(test, hdn_capability_record_valid(HDN_CAP_KERNEL_WX, &record));
}

static void hdn_capability_requirement_states_test(struct kunit *test)
{
	enum hdn_capability_state state;

	for (state = HDN_CAP_UNDECLARED; state <= HDN_CAP_NOT_APPLICABLE; state++)
		KUNIT_EXPECT_EQ(test,
			hdn_capability_state_satisfies_requirement(state),
			state == HDN_CAP_ENFORCED || state == HDN_CAP_NOT_APPLICABLE);
}

static void hdn_capability_inventory_test(struct kunit *test)
{
	enum hdn_capability_id id;

	for (id = 0; id < HDN_CAP__MAX; id++) {
		struct hdn_capability_record record = hdn_capability(id);

		KUNIT_EXPECT_TRUE(test, hdn_capability_record_valid(id, &record));
	}
	KUNIT_EXPECT_EQ(test, hdn_capabilities_require(~HDN_CAP_KNOWN_MASK), -EINVAL);
}

static struct kunit_case hdn_capability_cases[] = {
	KUNIT_CASE(hdn_capability_states_test),
	KUNIT_CASE(hdn_capability_invalid_test),
	KUNIT_CASE(hdn_capability_requirement_states_test),
	KUNIT_CASE(hdn_capability_inventory_test),
	{}
};

static struct kunit_suite hdn_capability_suite = {
	.name = "hdn-architecture-capabilities",
	.test_cases = hdn_capability_cases,
};

kunit_test_suite(hdn_capability_suite);
