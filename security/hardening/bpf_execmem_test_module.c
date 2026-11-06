// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>

static unsigned int mode;
module_param(mode, uint, 0400);

extern int hdn_bpf_execmem_test_run(unsigned int mode);

static int __init hdn_bpf_execmem_test_init(void)
{
	int error = hdn_bpf_execmem_test_run(mode);

	if (!error)
		pr_info("HDN_BPF_EXECMEM_GUEST_READY mode=%u\n", mode);
	return error;
}

static void __exit hdn_bpf_execmem_test_exit(void)
{
}

module_init(hdn_bpf_execmem_test_init);
module_exit(hdn_bpf_execmem_test_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("HDN BPF executable-memory destructive fixture");
