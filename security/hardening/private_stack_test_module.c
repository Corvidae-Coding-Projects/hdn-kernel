// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>

#include "private_stack_test.h"

static unsigned int mode;
module_param(mode, uint, 0400);
MODULE_PARM_DESC(mode,
	"0=ownership/zero/alias checks, 1=lower guard write, 2=upper guard write, "
	"3=direct alias write, 4=construction alias write, 5=stack execute, "
	"6=inactive read, 7=inactive write, 8=crash/vmcore capture");
static int __init private_stack_test_init(void)
{
	return hdn_private_stack_test_run(mode);
}

static void __exit private_stack_test_exit(void) { }

module_init(private_stack_test_init);
module_exit(private_stack_test_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("HDN private kernel stack mapping probes");
