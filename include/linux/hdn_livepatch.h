/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_HDN_LIVEPATCH_H
#define _LINUX_HDN_LIVEPATCH_H

#include <linux/elf.h>
#include <linux/errno.h>

struct module;
struct klp_modinfo;

#if defined(CONFIG_LIVEPATCH) && defined(CONFIG_SECURITY_HARDENING_PGTABLE)
int hdn_klp_prepare(struct module *mod, const struct klp_modinfo *info,
		    const char *strtab, size_t strtab_size);
int hdn_klp_relocate(struct module *mod, const char *object, bool apply);
void hdn_klp_release(struct module *mod);
int hdn_klp_symbols_prepare(struct module *mod, size_t strtab_size);
void hdn_klp_symbols_live(struct module *mod, bool live);
#else
static inline int hdn_klp_prepare(struct module *mod, const struct klp_modinfo *info,
				  const char *strtab, size_t strtab_size) { return 0; }
static inline int hdn_klp_relocate(struct module *mod, const char *object, bool apply)
{ return -EOPNOTSUPP; }
static inline void hdn_klp_release(struct module *mod) { }
static inline int hdn_klp_symbols_prepare(struct module *mod, size_t strtab_size)
{ return 0; }
static inline void hdn_klp_symbols_live(struct module *mod, bool live) { }
#endif
#endif
