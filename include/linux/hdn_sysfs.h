/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_HDN_SYSFS_H
#define _LINUX_HDN_SYSFS_H

#include <linux/types.h>
#include <uapi/linux/hardening.h>

struct file;
struct inode;

#ifdef CONFIG_SECURITY_HARDENING_SYSFS_VIEW
u64 hdn_sysfs_hidden_classes(void);
u64 hdn_sysfs_inode_disclosure(const struct inode *inode);
bool hdn_sysfs_file_hidden(const struct file *file);
#else
static inline u64 hdn_sysfs_hidden_classes(void) { return 0; }
static inline u64 hdn_sysfs_inode_disclosure(const struct inode *inode) { return 0; }
static inline bool hdn_sysfs_file_hidden(const struct file *file) { return false; }
#endif

#endif
