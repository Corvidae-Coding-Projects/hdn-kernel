// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>

static unsigned int mode;
module_param(mode, uint, 0400);
MODULE_PARM_DESC(mode, "0=alias probes, 1=VMCS write, 2=host-save write");
extern int hdn_kvm_state_test_run(unsigned int mode);

static int __init kvm_state_test_init(void)
{
	return hdn_kvm_state_test_run(mode);
}
static void __exit kvm_state_test_exit(void) { }
module_init(kvm_state_test_init);
module_exit(kvm_state_test_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("HDN virtualization state ownership probes");
