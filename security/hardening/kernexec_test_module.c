// SPDX-License-Identifier: GPL-2.0-only
/* Load after boot so the negative probes observe finalized kernel mappings. */
#include <kunit/test.h>
#include <linux/module.h>

extern struct kunit_suite hdn_cpa_suite;
kunit_test_suite(hdn_cpa_suite);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("HDN KERNEXEC CPA and built-in alias probes");
