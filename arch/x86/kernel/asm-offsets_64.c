// SPDX-License-Identifier: GPL-2.0
#ifndef __LINUX_KBUILD_H
# error "Please do not build this file directly, build asm-offsets.c instead"
#endif

#include <asm/ia32.h>
#include <asm/hdn_rap.h>
#ifdef CONFIG_SECURITY_HARDENING_RAP
#include <linux/hdn_rap.h>
#include <asm/hdn_rap_resume.h>
#include <asm/hdn_rap_kexec.h>
#include "hdn_rap_context_internal.h"
#endif

#if defined(CONFIG_KVM_GUEST)
#include <asm/kvm_para.h>
#endif

int main(void)
{
#ifdef CONFIG_SECURITY_HARDENING_PRIVATE_STACKS
	OFFSET(HDN_STACK_SWITCH_SP, hdn_stack_switch, sp);
	OFFSET(HDN_STACK_SWITCH_CR3, hdn_stack_switch, cr3);
	OFFSET(HDN_STACK_STARTUP_APICID, hdn_stack_startup, apicid);
	OFFSET(HDN_STACK_STARTUP_GSBASE, hdn_stack_startup, gsbase);
	OFFSET(HDN_STACK_STARTUP_SP, hdn_stack_startup, sp);
	OFFSET(HDN_STACK_STARTUP_CR3, hdn_stack_startup, cr3);
	DEFINE(HDN_STACK_STARTUP_SIZE, sizeof(struct hdn_stack_startup));
	BUILD_BUG_ON(offsetof(struct hdn_stack_startup, apicid) != 0);
	BUILD_BUG_ON(offsetof(struct hdn_stack_startup, gsbase) != 8);
	BUILD_BUG_ON(offsetof(struct hdn_stack_startup, sp) != 16);
	BUILD_BUG_ON(offsetof(struct hdn_stack_startup, cr3) != 24);
	BUILD_BUG_ON(sizeof(struct hdn_stack_startup) != 40);
#endif
#ifdef CONFIG_SECURITY_HARDENING_RAP
	OFFSET(HDN_KEXEC_HEAD, hdn_rap_kexec_launch, head);
	OFFSET(HDN_KEXEC_CONTROL, hdn_rap_kexec_launch, control);
	OFFSET(HDN_KEXEC_ENTRY, hdn_rap_kexec_launch, entry);
	OFFSET(HDN_KEXEC_FLAGS, hdn_rap_kexec_launch, flags);
	OFFSET(HDN_KEXEC_CODE, hdn_rap_kexec_launch, code);
	OFFSET(HDN_KEXEC_TABLE, hdn_rap_kexec_launch, table);
	OFFSET(HDN_KEXEC_CR0, hdn_rap_kexec_state, cr0);
	OFFSET(HDN_KEXEC_CR3, hdn_rap_kexec_state, cr3);
	OFFSET(HDN_KEXEC_CR4, hdn_rap_kexec_state, cr4);
	OFFSET(HDN_KEXEC_GS, hdn_rap_kexec_state, gsbase);
	OFFSET(HDN_KEXEC_SP, hdn_rap_kexec_state, sp);
	OFFSET(HDN_KEXEC_RFLAGS, hdn_rap_kexec_state, flags);
	OFFSET(HDN_KEXEC_R15, hdn_rap_kexec_state, r15);
	OFFSET(HDN_KEXEC_R14, hdn_rap_kexec_state, r14);
	OFFSET(HDN_KEXEC_R13, hdn_rap_kexec_state, r13);
	OFFSET(HDN_KEXEC_R12, hdn_rap_kexec_state, r12);
	OFFSET(HDN_KEXEC_BP, hdn_rap_kexec_state, bp);
	OFFSET(HDN_KEXEC_BX, hdn_rap_kexec_state, bx);
	OFFSET(HDN_KEXEC_GDT, hdn_rap_kexec_state, gdt);
	OFFSET(HDN_KEXEC_IDT, hdn_rap_kexec_state, idt);
	BUILD_BUG_ON(offsetof(struct hdn_rap_kexec_state, gdt) != 96);
	BUILD_BUG_ON(offsetof(struct hdn_rap_kexec_state, idt) != 106);
	/* Offsets are part of the closed image-handoff byte verifier. */
	BUILD_BUG_ON(offsetof(struct hdn_rap_hibernate_launch, entry) != 0);
	BUILD_BUG_ON(offsetof(struct hdn_rap_hibernate_launch, cr3) != 8);
	BUILD_BUG_ON(offsetof(struct hdn_rap_hibernate_launch, temporary_cr3) != 16);
	BUILD_BUG_ON(offsetof(struct hdn_rap_hibernate_launch, code) != 24);
	BUILD_BUG_ON(offsetof(struct hdn_rap_hibernate_launch, pages) != 32);
	BUILD_BUG_ON(offsetof(struct hdn_rap_hibernate_launch, cr4) != 40);
	BUILD_BUG_ON(offsetof(struct saved_context, kernelmode_gs_base) != 176);
	BUILD_BUG_ON(offsetof(struct saved_context, gdt_desc) != 266);
	BUILD_BUG_ON(offsetof(struct saved_context, idt) != 278);
	BUILD_BUG_ON(offsetof(struct saved_context, cr0) != 200);
	BUILD_BUG_ON(offsetof(struct saved_context, cr2) != 208);
	BUILD_BUG_ON(offsetof(struct saved_context, cr3) != 216);
	BUILD_BUG_ON(offsetof(struct saved_context, cr4) != 224);
	BUILD_BUG_ON(offsetof(struct pt_regs, sp) != 152);
	BUILD_BUG_ON(offsetof(struct pt_regs, flags) != 144);
	OFFSET(HDN_RAP_IMAGE_ENTRY, hdn_rap_hibernate_launch, entry);
	OFFSET(HDN_RAP_IMAGE_CR3, hdn_rap_hibernate_launch, cr3);
	OFFSET(HDN_RAP_IMAGE_TEMP_CR3, hdn_rap_hibernate_launch, temporary_cr3);
	OFFSET(HDN_RAP_IMAGE_CODE, hdn_rap_hibernate_launch, code);
	OFFSET(HDN_RAP_IMAGE_PAGES, hdn_rap_hibernate_launch, pages);
	OFFSET(HDN_RAP_IMAGE_CR4, hdn_rap_hibernate_launch, cr4);
	/* The terminal entry has an exact objtool byte/relocation verifier. */
	BUILD_BUG_ON(offsetof(struct hdn_rap_failure_cpu, gsbase) != 0);
	BUILD_BUG_ON(offsetof(struct hdn_rap_failure_cpu, sp) != 8);
	BUILD_BUG_ON(offsetof(struct hdn_rap_failure_cpu, cr3) != 16);
	BUILD_BUG_ON(offsetof(struct hdn_rap_failure_cpu, gdt) != 24);
	BUILD_BUG_ON(offsetof(struct hdn_rap_failure_cpu, busy) != 48);
	BUILD_BUG_ON(offsetof(struct hdn_rap_failure_cpu, begin) != 56);
	BUILD_BUG_ON(sizeof(struct hdn_rap_failure_cpu) != 64);
	OFFSET(HDN_RAP_FAILURE_GSBASE, hdn_rap_failure_cpu, gsbase);
	OFFSET(HDN_RAP_FAILURE_SP, hdn_rap_failure_cpu, sp);
	OFFSET(HDN_RAP_FAILURE_CR3, hdn_rap_failure_cpu, cr3);
	OFFSET(HDN_RAP_FAILURE_GDT, hdn_rap_failure_cpu, gdt);
	OFFSET(HDN_RAP_FAILURE_BUSY, hdn_rap_failure_cpu, busy);
	OFFSET(HDN_RAP_FAILURE_BEGIN, hdn_rap_failure_cpu, begin);
	DEFINE(HDN_RAP_FAILURE_SIZE, sizeof(struct hdn_rap_failure_cpu));
	DEFINE(HDN_RAP_FAIL_RETURN_CLASS, HDN_RAP_FAIL_RETURN);
	OFFSET(HDN_RAP_BPF_SP, rap_bpf_checkpoint, sp);
	OFFSET(HDN_RAP_BPF_BP, rap_bpf_checkpoint, bp);
	OFFSET(HDN_RAP_ENTRY_CR3, hdn_rap_entry_state, cr3);
	OFFSET(HDN_RAP_ENTRY_GS, hdn_rap_entry_state, gsbase);
	OFFSET(HDN_RAP_ENTRY_SPEC_CTRL, hdn_rap_entry_state, spec_ctrl);
	OFFSET(HDN_RAP_SWITCH_SP, hdn_rap_switch_frame, sp);
	OFFSET(HDN_RAP_SWITCH_CR3, hdn_rap_switch_frame, cr3);
	OFFSET(HDN_RAP_SWITCH_CANARY, hdn_rap_switch_frame, canary);
	BUILD_BUG_ON(offsetof(struct hdn_rap_switch_frame, frame) != 8);
	BUILD_BUG_ON(offsetof(struct hdn_rap_switch_frame, cr3) != 64);
	BUILD_BUG_ON(offsetof(struct hdn_rap_switch_frame, canary) != 72);
	BUILD_BUG_ON(offsetof(struct hdn_rap_entry_state, cr3) != 0);
	BUILD_BUG_ON(offsetof(struct hdn_rap_entry_state, gsbase) != 8);
	BUILD_BUG_ON(offsetof(struct hdn_rap_entry_state, spec_ctrl) != 16);
	BUILD_BUG_ON(offsetof(struct tlb_state, user_pcid_flush_mask) != 22);
	BUILD_BUG_ON(offsetof(struct tss_struct, x86_tss.sp0) != 4);
	BUILD_BUG_ON(offsetof(struct tss_struct, x86_tss.sp2) != 20);
	OFFSET(HDN_RAP_SWITCH_R15, hdn_rap_switch_frame, frame.r15);
	OFFSET(HDN_RAP_SWITCH_R14, hdn_rap_switch_frame, frame.r14);
	OFFSET(HDN_RAP_SWITCH_R13, hdn_rap_switch_frame, frame.r13);
	OFFSET(HDN_RAP_SWITCH_R12, hdn_rap_switch_frame, frame.r12);
	OFFSET(HDN_RAP_SWITCH_BX, hdn_rap_switch_frame, frame.bx);
	OFFSET(HDN_RAP_SWITCH_BP, hdn_rap_switch_frame, frame.bp);
	OFFSET(HDN_RAP_SWITCH_RET, hdn_rap_switch_frame, frame.ret_addr);
	DEFINE(HDN_RAP_SWITCH_SAVED_SIZE, offsetof(struct inactive_task_frame, ret_addr));
	BLANK();
#endif
#ifdef CONFIG_PARAVIRT
#ifdef CONFIG_PARAVIRT_XXL
#ifdef CONFIG_DEBUG_ENTRY
	OFFSET(PV_IRQ_save_fl, paravirt_patch_template, irq.save_fl);
#endif
#endif
	BLANK();
#endif

#if defined(CONFIG_KVM_GUEST)
	OFFSET(KVM_STEAL_TIME_preempted, kvm_steal_time, preempted);
	BLANK();
#endif

#define ENTRY(entry) OFFSET(pt_regs_ ## entry, pt_regs, entry)
	ENTRY(bx);
	ENTRY(cx);
	ENTRY(dx);
	ENTRY(sp);
	ENTRY(bp);
	ENTRY(si);
	ENTRY(di);
	ENTRY(r8);
	ENTRY(r9);
	ENTRY(r10);
	ENTRY(r11);
	ENTRY(r12);
	ENTRY(r13);
	ENTRY(r14);
	ENTRY(r15);
	ENTRY(flags);
	BLANK();
#undef ENTRY

#define ENTRY(entry) OFFSET(saved_context_ ## entry, saved_context, entry)
	ENTRY(cr0);
	ENTRY(cr2);
	ENTRY(cr3);
	ENTRY(cr4);
	ENTRY(gdt_desc);
	ENTRY(idt);
	ENTRY(kernelmode_gs_base);
	BLANK();
#undef ENTRY

	return 0;
}
