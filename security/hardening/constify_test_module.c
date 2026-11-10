// SPDX-License-Identifier: GPL-2.0-only
/* Load only after constify_target_module has reached MODULE_STATE_LIVE. */
#include <kunit/test.h>
#include <linux/module.h>

#include "constify_test.h"

static void hdn_constify_module_storage(struct kunit *test)
{
	const u64 *target = hdn_constify_module_probe_value();

	hdn_constify_module_storage_probe(test, target);
}

static struct kunit_case hdn_constify_module_cases[] = {
	KUNIT_CASE(hdn_constify_module_storage),
	{}
};

static struct kunit_suite hdn_constify_module_suite = {
	.name = "hdn-constify-module",
	.test_cases = hdn_constify_module_cases,
};
kunit_test_suite(hdn_constify_module_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("HDN post-init immutable module probes");
