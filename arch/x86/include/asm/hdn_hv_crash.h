/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_HDN_HV_CRASH_H
#define _ASM_X86_HDN_HV_CRASH_H

#define HDN_HVC_SP 0
#define HDN_HVC_CR0 8
#define HDN_HVC_CR2 16
#define HDN_HVC_CR3 24
#define HDN_HVC_CR4 32
#define HDN_HVC_CR8 40
#define HDN_HVC_GSBASE 48
#define HDN_HVC_KERNELGS 56
#define HDN_HVC_FSBASE 64
#define HDN_HVC_EFER 72
#define HDN_HVC_PAT 80
#define HDN_HVC_SS 88
#define HDN_HVC_DS 90
#define HDN_HVC_ES 92
#define HDN_HVC_FS 94
#define HDN_HVC_GS 96
#define HDN_HVC_CS 98
#define HDN_HVC_GDT 104
#define HDN_HVC_IDT 114

#ifndef __ASSEMBLY__
#include <linux/init.h>
#include <asm/desc_defs.h>

struct hdn_hv_crash_cpu {
	unsigned long sp, cr0, cr2, cr3, cr4, cr8;
	unsigned long gsbase, kernelgs, fsbase, efer, pat;
	u16 ss, ds, es, fs, gs, cs;
	u32 padding;
	struct desc_ptr gdt, idt;
};

#ifdef CONFIG_SECURITY_HARDENING_RAP
extern struct hdn_hv_crash_cpu hdn_hv_crash_cpu;
void __noreturn hdn_hv_crash_enter(void);
void __noreturn hdn_hv_crash_return(void);
void hdn_hv_crash_capture(unsigned long sp);
void hdn_hv_crash_finish(void);
void __noreturn hv_crash_disable(void);
void __noreturn hv_crash_handle(void);
#endif
#if defined(CONFIG_MSHV_ROOT) && defined(CONFIG_CRASH_DUMP) && defined(CONFIG_SECURITY_HARDENING_PGTABLE)
void __init hdn_hv_crash_seal(void);
#else
static inline void hdn_hv_crash_seal(void) {}
#endif
#endif
#endif
