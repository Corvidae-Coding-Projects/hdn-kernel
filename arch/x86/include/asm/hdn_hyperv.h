/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_HDN_HYPERV_H
#define _ASM_X86_HDN_HYPERV_H

#ifndef __ASSEMBLY__
#include <linux/init.h>
#include <linux/types.h>

#ifdef CONFIG_SECURITY_HARDENING_RAP
u64 hdn_hv_hypercall(u64 control, u64 param1, u64 param2);
void __init hdn_hv_page_init(void *page);
void hdn_hv_publish(void *page);
void *hdn_hv_resume_page(void *saved);
int hdn_hv_vtl_init(u64 offset);
#else
static inline void hdn_hv_page_init(void *page) {}
static inline void hdn_hv_publish(void *page) {}
static inline void *hdn_hv_resume_page(void *saved) { return saved; }
static inline int hdn_hv_vtl_init(u64 offset) { return 0; }
#endif
#endif
#endif
