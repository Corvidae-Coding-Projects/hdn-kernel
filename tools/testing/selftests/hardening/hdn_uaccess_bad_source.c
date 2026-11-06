// SPDX-License-Identifier: GPL-2.0-only
/* Semantic-patch inputs only; never link into a running kernel. */
#include <linux/uaccess.h>
struct uaccess_fixture { int field; };
int hdn_uaccess_cast(int __user *p) { return *(int *)p; }
int hdn_uaccess_direct(int __user *p) { return *p; }
int hdn_uaccess_array(int __user *p, int n) { return p[n]; }
int hdn_uaccess_member(struct uaccess_fixture __user *p) { return p->field; }
int hdn_uaccess_good(int __user *p)
{
	int value;
	return get_user(value, p) ? -EFAULT : value;
}
