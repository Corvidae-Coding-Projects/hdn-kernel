// SPDX-License-Identifier: GPL-2.0-only
/* Each destructive mode belongs in a fresh disposable test guest. */
#include <linux/module.h>
#include <linux/cred.h>
#include <linux/hdn_jitter.h>
static struct cred jitter_static_cred = { .usage = ATOMIC_INIT(1) };
HDN_STATIC_CRED(jitter_static_cred);
static unsigned int mode;
module_param(mode, uint, 0400);
MODULE_PARM_DESC(mode, "0=placement/RCU/reuse, 1=underflow, 2=overflow, 3=generic free, 4=wrong class, 5=stale write, 6=replay, 7=vmcore capture, 8=allocation failures");
static int __init jitter_test_init(void)
{
	return hdn_jitter_test_run(mode);
}
static void __exit jitter_test_exit(void) { }
module_init(jitter_test_init);
module_exit(jitter_test_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("HDN critical-object fault fixture");
