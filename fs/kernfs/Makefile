# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the kernfs pseudo filesystem
#

obj-y		:= mount.o inode.o dir.o file.o symlink.o
obj-$(CONFIG_SECURITY_HARDENING_SYSFS_VIEW) += hdn-view.o
