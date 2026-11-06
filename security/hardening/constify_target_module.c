// SPDX-License-Identifier: GPL-2.0-only
/* Load first; its post-init section is sealed before the probe module starts. */
#include <linux/cache.h>
#include <linux/init.h>
#include <linux/module.h>

#define HDN_CONSTIFY_MODULE_MAGIC 0xc0571f1ed5ea1edULL

static u64 hdn_constify_module_value __ro_after_init;

const u64 *hdn_constify_module_probe_value(void)
{
	return &hdn_constify_module_value;
}
EXPORT_SYMBOL_GPL(hdn_constify_module_probe_value);

static int __init hdn_constify_target_init(void)
{
	hdn_constify_module_value = HDN_CONSTIFY_MODULE_MAGIC;
	return 0;
}
module_init(hdn_constify_target_init);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("HDN post-init immutable module target");
