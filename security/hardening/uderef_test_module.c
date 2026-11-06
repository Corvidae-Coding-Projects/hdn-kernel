// SPDX-License-Identifier: GPL-2.0-only
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/user_namespace.h>

extern long hdn_uderef_test_run(unsigned int mode, unsigned long address);
static long uderef_ioctl(struct file *file, unsigned int mode, unsigned long address)
{
	if (!ns_capable(&init_user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	return hdn_uderef_test_run(mode, address);
}
static const struct file_operations uderef_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = uderef_ioctl,
};
static struct miscdevice uderef_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "hdn-uderef-test",
	.fops = &uderef_fops,
	.mode = 0600,
};
static int __init uderef_init(void) { return misc_register(&uderef_device); }
static void __exit uderef_exit(void) { misc_deregister(&uderef_device); }
module_init(uderef_init);
module_exit(uderef_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("HDN destructive user-access test interface");
