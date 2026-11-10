/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_HARDENING_CONSTIFY_TEST_H
#define _SECURITY_HARDENING_CONSTIFY_TEST_H

#include <linux/types.h>

struct kunit;

const u64 *hdn_constify_module_probe_value(void);
void hdn_constify_module_storage_probe(struct kunit *test,
				       const u64 *target);

#endif /* _SECURITY_HARDENING_CONSTIFY_TEST_H */
