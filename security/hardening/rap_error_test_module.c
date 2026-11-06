// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>

static unsigned int mode;
module_param(mode, uint, 0400);
MODULE_PARM_DESC(mode, "0=lifecycle, 1=corrupt saved SP, 2=unmarked function");
extern int hdn_rap_error_test_run(unsigned int mode);

static int __init rap_error_init(void)
{
	return hdn_rap_error_test_run(mode);
}
static void __exit rap_error_exit(void) { }
module_init(rap_error_init);
module_exit(rap_error_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("HDN RAP error-injection return lifecycle probes");
