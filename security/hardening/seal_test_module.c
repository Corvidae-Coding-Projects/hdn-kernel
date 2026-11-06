// SPDX-License-Identifier: GPL-2.0-only
#include <kunit/test.h>
#include <linux/module.h>

extern struct kunit_suite hdn_seal_suite;
kunit_test_suite(hdn_seal_suite);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("HDN typed immutable object probes");
