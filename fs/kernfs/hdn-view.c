// SPDX-License-Identifier: GPL-2.0-only
#include <linux/hdn_sysfs.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <linux/string.h>
#include "kernfs-internal.h"

/* Registration, before publication; no mutable pathname policy. */
void hdn_kernfs_classify(struct kernfs_node *kn, struct kernfs_node *parent,
			const char *name)
{
	if (!parent || !(kernfs_root(parent)->flags & KERNFS_ROOT_SYSFS))
		return;
	kn->hdn_disclosure = parent->hdn_disclosure;
	if (parent != kernfs_root(parent)->kn)
		return;
	if (!strcmp(name, "kernel"))
		kn->hdn_disclosure |= HDN_PROFILE_HIDE_SYSFS_KERNEL;
	else if (!strcmp(name, "firmware"))
		kn->hdn_disclosure |= HDN_PROFILE_HIDE_SYSFS_FIRMWARE;
	else if (!strcmp(name, "devices") || !strcmp(name, "class") ||
		 !strcmp(name, "bus") || !strcmp(name, "block"))
		kn->hdn_disclosure |= HDN_PROFILE_HIDE_SYSFS_DEVICES;
	else if (!strcmp(name, "module"))
		kn->hdn_disclosure |= HDN_PROFILE_HIDE_SYSFS_MODULES;
}

static u64 hdn_kernfs_disclosure(struct kernfs_node *kn)
{
	struct kernfs_root *root = kernfs_root(kn);
	struct kernfs_node *pos;
	u64 disclosure = 0;
	unsigned int links = 0;

	if (!(root->flags & KERNFS_ROOT_SYSFS))
		return 0;
	/* Serialize the whole ancestry snapshot against rename/reparent. */
	read_lock(&root->kernfs_rename_lock);
	rcu_read_lock();
	do {
		for (pos = kn; pos; pos = kernfs_parent(pos))
			disclosure |= pos->hdn_disclosure;
		if (kernfs_type(kn) != KERNFS_LINK)
			break;
		kn = kn->symlink.target_kn;
		/* Cycles and cross-root links cannot broaden a restricted view. */
		if (++links > 8 || kernfs_root(kn) != root) {
			disclosure = HDN_PROFILE_SYSFS_MASK;
			break;
		}
	} while (kn);
	rcu_read_unlock();
	read_unlock(&root->kernfs_rename_lock);
	return disclosure;
}

bool hdn_kernfs_hidden(struct kernfs_node *kn)
{
	return hdn_kernfs_disclosure(kn) & hdn_sysfs_hidden_classes();
}

u64 hdn_sysfs_inode_disclosure(const struct inode *inode)
{
	if (!inode || inode->i_sb->s_magic != SYSFS_MAGIC || !inode->i_private)
		return 0;
	return hdn_kernfs_disclosure(inode->i_private);
}

bool hdn_sysfs_file_hidden(const struct file *file)
{
	return file &&
		(hdn_sysfs_inode_disclosure(file_inode(file)) & hdn_sysfs_hidden_classes());
}
