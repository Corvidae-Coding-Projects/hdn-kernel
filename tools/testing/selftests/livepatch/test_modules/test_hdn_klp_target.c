// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>

/* Deliberately unexported: the delayed resolver must use the object identity. */
unsigned long hdn_klp_secret = 0x123abcUL;

static int __init target_init(void) { return 0; }
static void __exit target_exit(void) { }
module_init(target_init);
module_exit(target_exit);
MODULE_LICENSE("GPL");
