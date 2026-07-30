/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __LINUX_KMOD_H__
#define __LINUX_KMOD_H__

/*
 *	include/linux/kmod.h
 */

#include <linux/umh.h>
#include <linux/args.h>
#include <linux/gfp.h>
#include <linux/stddef.h>
#include <linux/errno.h>
#include <linux/compiler.h>
#include <linux/workqueue.h>
#include <linux/sysctl.h>

#ifdef CONFIG_MODULES
/* modprobe exit status on success, -ve on error.  Return value
 * usually useless though. */
extern __printf(2, 3)
int __request_module(bool wait, const char *name, ...);
int __request_module_name(bool wait, const char *name);

/*
 * One-argument request_module() calls are exact aliases/names. Calls with
 * extra arguments keep the printf-style formatting contract.
 */
#define __request_module_select(has_args) \
	CONCATENATE(__request_module_select_, has_args)
#define __request_module_select_(wait, name) \
	__request_module_name(wait, name)
#define __request_module_select_1(wait, fmt, ...) \
	__request_module(wait, fmt, __VA_ARGS__)

#define request_module(name, ...) \
	__request_module_select(__VA_OPT__(1))(true, name __VA_OPT__(,) \
					       __VA_ARGS__)
#define request_module_nowait(name, ...) \
	__request_module_select(__VA_OPT__(1))(false, name __VA_OPT__(,) \
					       __VA_ARGS__)
#define try_then_request_module(x, mod...) \
	((x) ?: (request_module(mod), (x)))
#else
static inline int request_module(const char *name, ...) { return -ENOSYS; }
static inline int request_module_nowait(const char *name, ...) { return -ENOSYS; }
#define try_then_request_module(x, mod...) (x)
#endif

#endif /* __LINUX_KMOD_H__ */
