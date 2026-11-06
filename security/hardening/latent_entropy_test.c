// SPDX-License-Identifier: GPL-2.0-only
#include <kunit/test.h>
#include <linux/hdn_latent_entropy.h>
#include <linux/module.h>

/* The compiler instruments this function only in the explicit test build. */
static noinline unsigned long hdn_latent_fixture(unsigned int rounds)
{
	unsigned long value = 1;
	unsigned int i;

	for (i = 0; i < rounds; i++) {
		if (i & 1)
			value ^= i;
		else
			value += i;
	}
	return value;
}

static void hdn_latent_deterministic(struct kunit *test)
{
	u64 first, second, changed;
	volatile unsigned long result;

	KUNIT_ASSERT_EQ(test, hdn_latent_test_begin(0x12345678), 0);
	result = hdn_latent_fixture(8);
	first = hdn_latent_test_end();
	KUNIT_ASSERT_EQ(test, hdn_latent_test_begin(0x12345678), 0);
	result = hdn_latent_fixture(8);
	second = hdn_latent_test_end();
	KUNIT_ASSERT_EQ(test, hdn_latent_test_begin(0x12345678), 0);
	result = hdn_latent_fixture(9);
	changed = hdn_latent_test_end();
	KUNIT_EXPECT_EQ(test, first, second);
	KUNIT_EXPECT_NE(test, first, changed);
	KUNIT_EXPECT_NE(test, first, (u64)0x12345678);
	(void)result;
}

static struct kunit_case hdn_latent_cases[] = {
	KUNIT_CASE(hdn_latent_deterministic),
	{}
};

static struct kunit_suite hdn_latent_suite = {
	.name = "hdn-latent-entropy",
	.test_cases = hdn_latent_cases,
};
kunit_test_suite(hdn_latent_suite);
MODULE_LICENSE("GPL");
