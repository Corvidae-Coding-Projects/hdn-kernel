/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_HDN_GDT_H
#define _ASM_X86_HDN_GDT_H

#include <linux/types.h>
#include <linux/string.h>
#include <asm/desc_defs.h>

struct desc_struct;
#if defined(CONFIG_SECURITY_HARDENING_RAP) && IS_ENABLED(CONFIG_KVM_INTEL)
unsigned long hdn_rap_vmx_vector(unsigned int vector);
#endif
#if defined(CONFIG_SECURITY_HARDENING_GDT) || defined(CONFIG_SECURITY_HARDENING_PGTABLE)
unsigned long hdn_entry_window_enter(void);
void hdn_entry_window_exit(unsigned long state);
#endif
#ifdef CONFIG_SECURITY_HARDENING_GDT
bool hdn_gdt_active(void);
bool hdn_gdt_sealed(void);
bool hdn_idt_sealed(void);
bool hdn_idt_protected_pfn(unsigned long first, unsigned long last);
const char *hdn_gdt_state(void);
void hdn_gdt_write(struct desc_struct *gdt, unsigned int entry,
		   const void *data, size_t size);
bool hdn_gdt_load_tr(void);
bool hdn_gdt_protected_pfn(unsigned long first, unsigned long last);
void hdn_gdt_xen_validate(const struct desc_struct *gdt, unsigned int entry, size_t size);
void hdn_gdt_xen_complete(void *unused);
void hdn_gdt_xen_bind(unsigned int cpu, unsigned long pfn, unsigned int size);
void hdn_gdt_xen_result(long result);
#else
static inline bool hdn_gdt_active(void) { return false; }
static inline bool hdn_gdt_sealed(void) { return false; }
static inline bool hdn_idt_sealed(void) { return false; }
static inline bool hdn_idt_protected_pfn(unsigned long first, unsigned long last)
{
	return false;
}
static inline const char *hdn_gdt_state(void) { return "disabled"; }
static inline void hdn_gdt_write(struct desc_struct *gdt, unsigned int entry,
				 const void *data, size_t size)
{
	memcpy(&gdt[entry], data, size);
}
static inline bool hdn_gdt_load_tr(void) { return false; }
static inline bool hdn_gdt_protected_pfn(unsigned long first, unsigned long last)
{
	return false;
}
static inline void hdn_gdt_xen_validate(const struct desc_struct *gdt,
				       unsigned int entry, size_t size) { }
static inline void hdn_gdt_xen_complete(void *unused) { }
static inline void hdn_gdt_xen_bind(unsigned int cpu, unsigned long pfn,
				   unsigned int size) { }
static inline void hdn_gdt_xen_result(long result) { }
#endif
#endif
