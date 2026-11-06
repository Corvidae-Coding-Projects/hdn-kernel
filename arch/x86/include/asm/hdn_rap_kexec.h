/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_HDN_RAP_KEXEC_H
#define _ASM_X86_HDN_RAP_KEXEC_H

#ifndef __ASSEMBLY__
#include <asm/desc_defs.h>

struct kimage;
struct hdn_rap_kexec_launch {
	unsigned long head, control, entry, flags, code, table, swap;
};

/* The physical terminal domain consumes only CRs. The fixed virtual return
 * entry restores the remaining state before invoking any ordinary C. */
struct hdn_rap_kexec_state {
	unsigned long cr0, cr3, cr4, gsbase, sp, flags;
	unsigned long r15, r14, r13, r12, bp, bx;
	struct desc_ptr gdt, idt;
};

#ifdef CONFIG_SECURITY_HARDENING_RAP
extern struct hdn_rap_kexec_state hdn_rap_kexec_state;
int hdn_rap_kexec_publish(struct kimage *image,
		const struct hdn_rap_kexec_launch *launch);
void hdn_rap_kexec_release(struct kimage *image);
const struct hdn_rap_kexec_launch *hdn_rap_kexec_enter(struct kimage *image,
		unsigned long sp);
void hdn_rap_kexec_finish(unsigned long entry);
unsigned long hdn_rap_kexec(struct kimage *image);
void hdn_rap_kexec_return(void);
#endif
#endif
#endif
