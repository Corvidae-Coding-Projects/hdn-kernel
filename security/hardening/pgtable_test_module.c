// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>
static unsigned int mode;
module_param(mode, uint, 0400);
MODULE_PARM_DESC(mode, "0=interfaces, 1=direct write, 2=wrong level, 3=unowned child, 4=writable alias");
extern int hdn_pgtable_test_run(unsigned int mode);
static int __init pgtable_test_init(void) { return hdn_pgtable_test_run(mode); }
static void __exit pgtable_test_exit(void) { }
module_init(pgtable_test_init);
module_exit(pgtable_test_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("HDN page-table ownership fault fixture");
