/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_HDN_UACCESS_H
#define _LINUX_HDN_UACCESS_H
#include <linux/types.h>

#ifdef CONFIG_SECURITY_HARDENING_UDEREF
const char *hdn_uderef_state(void);
u64 hdn_uderef_repairs(void);
u64 hdn_uderef_site_id(unsigned long ip);
void hdn_uderef_report_fault(unsigned long ip);
#else
static inline const char *hdn_uderef_state(void) { return "disabled"; }
static inline u64 hdn_uderef_repairs(void) { return 0; }
static inline void hdn_uderef_report_fault(unsigned long ip) { }
#endif
#endif
