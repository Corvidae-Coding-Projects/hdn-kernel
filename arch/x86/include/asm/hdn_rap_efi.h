/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_HDN_RAP_EFI_H
#define _ASM_X86_HDN_RAP_EFI_H

#define HDN_EFI_PRM 0x10000
#define HDN_EFI_UV  0x10001

#define HDN_EFI_R15 64
#define HDN_EFI_R14 72
#define HDN_EFI_R13 80
#define HDN_EFI_R12 88
#define HDN_EFI_BP 96
#define HDN_EFI_BX 104
#define HDN_EFI_FLAGS 112
#define HDN_EFI_SP 120
#define HDN_EFI_TARGET 128
#define HDN_EFI_GS 136

#ifndef __ASSEMBLY__
#include <linux/init.h>
#include <linux/types.h>

/* Standard service identities are offsetof(efi_runtime_services_t, member).
 * PRM and UV have distinct ABIs and never share standard-service permission. */
#ifdef CONFIG_SECURITY_HARDENING_RAP
u64 __hdn_efi_call(unsigned long service, void *target, ...);
u64 __hdn_efi64_thunk(unsigned long service, unsigned long target, ...);
void __init hdn_efi_mixed_seal(void);
void __init hdn_rap_efi_context_init(unsigned long base, unsigned long size);
bool hdn_efi_stack_active(unsigned long address);
bool hdn_efi_stack_info(unsigned long address, unsigned long *begin,
		unsigned long *end, unsigned long *next);
int __init hdn_efi_register(unsigned long service, unsigned long target, bool physical);
int __init hdn_efi_register_runtime(bool physical);
struct pt_regs;
bool hdn_efi_fault_fixup(struct pt_regs *regs);
#else
static inline int hdn_efi_register(unsigned long service, unsigned long target, bool physical) { return 0; }
static inline int hdn_efi_register_runtime(bool physical) { return 0; }
static inline bool hdn_efi_stack_active(unsigned long address) { return false; }
static inline bool hdn_efi_stack_info(unsigned long address, unsigned long *begin,
		unsigned long *end, unsigned long *next) { return false; }
struct pt_regs;
static inline bool hdn_efi_fault_fixup(struct pt_regs *regs) { return false; }
#endif

/* Assembly captures these registers before calling instrumented code. */
struct hdn_efi_frame {
	unsigned long args[8];
	unsigned long r15, r14, r13, r12, bp, bx, flags, return_address;
};
struct hdn_efi_state {
	unsigned long args[8];
	unsigned long r15, r14, r13, r12, bp, bx, flags, sp;
	unsigned long target, gs, cr3, cr0, cr4, cpu, owner;
	unsigned long context, top, async_top, sequence, live, mixed;
};
const struct hdn_efi_state *hdn_efi_enter(unsigned long service,
		unsigned long target, const struct hdn_efi_frame *frame, bool mixed);
void hdn_efi_finish(void);
#endif
#endif
