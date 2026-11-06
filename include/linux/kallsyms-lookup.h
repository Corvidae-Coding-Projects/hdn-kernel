/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KALLSYMS_LOOKUP_H
#define _LINUX_KALLSYMS_LOOKUP_H

/*
 * Raw symbol lookup is an internal kernel mechanism. User-reachable callers
 * must authorize PROC_DISCLOSE before invoking any interface declared here.
 * Code that only formats symbols should include <linux/kallsyms.h>; those
 * formatters apply HDN disclosure policy themselves.
 */
#include <linux/errno.h>
#include <linux/stddef.h>

#ifdef CONFIG_KALLSYMS
unsigned long kallsyms_sym_address(int idx);
int kallsyms_on_each_symbol(int (*fn)(void *, const char *, unsigned long),
			    void *data);
int kallsyms_on_each_match_symbol(int (*fn)(void *, unsigned long),
				  const char *name, void *data);

unsigned long kallsyms_lookup_name(const char *name);
int kallsyms_lookup_size_offset(unsigned long addr,
				unsigned long *symbolsize,
				unsigned long *offset);
const char *kallsyms_lookup(unsigned long addr,
			    unsigned long *symbolsize,
			    unsigned long *offset,
			    char **modname, char *namebuf);
int lookup_symbol_name(unsigned long addr, char *symname);

#else /* !CONFIG_KALLSYMS */

static inline unsigned long kallsyms_sym_address(int idx)
{
	return 0;
}

static inline unsigned long kallsyms_lookup_name(const char *name)
{
	return 0;
}

static inline int kallsyms_lookup_size_offset(unsigned long addr,
					      unsigned long *symbolsize,
					      unsigned long *offset)
{
	return 0;
}

static inline const char *kallsyms_lookup(unsigned long addr,
					  unsigned long *symbolsize,
					  unsigned long *offset,
					  char **modname, char *namebuf)
{
	namebuf[0] = '\0';
	return NULL;
}

static inline int lookup_symbol_name(unsigned long addr, char *symname)
{
	symname[0] = '\0';
	return -ERANGE;
}

static inline int kallsyms_on_each_symbol(
	int (*fn)(void *, const char *, unsigned long), void *data)
{
	return -EOPNOTSUPP;
}

static inline int kallsyms_on_each_match_symbol(
	int (*fn)(void *, unsigned long), const char *name, void *data)
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_KALLSYMS */

#endif /* _LINUX_KALLSYMS_LOOKUP_H */
