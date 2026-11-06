/* SPDX-License-Identifier: GPL-2.0-only */
.text
#include <linux/linkage.h>
#include <linux/cfi_types.h>
#include <linux/objtool.h>
#include <asm/segment.h>
#include <asm/pgtable_types.h>
#include <asm/page_types.h>
#include <asm/msr.h>
#include <asm/asm-offsets.h>
#include <asm/frame.h>
#include <asm/nospec-branch.h>
#include <asm/hdn_rap.h>
#include <asm/hdn_rap_resume.h>

# Copyright 2003 Pavel Machek <pavel@suse.cz

.code64
	/*
	 * Hooray, we are in Long 64-bit mode (but still running in low memory)
	 */
SYM_FUNC_START(wakeup_long64)
	HDN_KEXEC_FUNC wakeup_long64, 32
	ANNOTATE_NOENDBR
#ifdef CONFIG_SECURITY_HARDENING_RAP
	/* The startup root selected the sealed task stack and GS by APIC ID.
	 * Resume only at this fixed continuation, never through saved_rip. */
	jmp __hdn_s3_resume
#else
	movq	saved_magic(%rip), %rax
	movq	$0x123456789abcdef0, %rdx
	cmpq	%rdx, %rax
	je	2f

	/* stop here on a saved_magic mismatch */
	movq $0xbad6d61676963, %rcx
1:
	jmp 1b
2:
	movw	$__KERNEL_DS, %ax
	movw	%ax, %ss	
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %fs
	movw	%ax, %gs
	movq	saved_rsp(%rip), %rsp

	movq	saved_rbx(%rip), %rbx
	movq	saved_rdi(%rip), %rdi
	movq	saved_rsi(%rip), %rsi
	movq	saved_rbp(%rip), %rbp

	movq	saved_rip(%rip), %rax
	ANNOTATE_RETPOLINE_SAFE
	jmp	*%rax
#endif
SYM_FUNC_END(wakeup_long64)

SYM_TYPED_FUNC_START(do_suspend_lowlevel)
	HDN_TYPED_FUNC_ENTER do_suspend_lowlevel
	FRAME_BEGIN
	subq	$8, %rsp
	xorl	%eax, %eax
	HDN_C_CALL save_processor_state

	movq	$saved_context, %rax
	movq	%rsp, pt_regs_sp(%rax)
	movq	%rbp, pt_regs_bp(%rax)
	movq	%rsi, pt_regs_si(%rax)
	movq	%rdi, pt_regs_di(%rax)
	movq	%rbx, pt_regs_bx(%rax)
	movq	%rcx, pt_regs_cx(%rax)
	movq	%rdx, pt_regs_dx(%rax)
	movq	%r8, pt_regs_r8(%rax)
	movq	%r9, pt_regs_r9(%rax)
	movq	%r10, pt_regs_r10(%rax)
	movq	%r11, pt_regs_r11(%rax)
	movq	%r12, pt_regs_r12(%rax)
	movq	%r13, pt_regs_r13(%rax)
	movq	%r14, pt_regs_r14(%rax)
	movq	%r15, pt_regs_r15(%rax)
	pushfq
	popq	pt_regs_flags(%rax)

#ifdef CONFIG_SECURITY_HARDENING_RAP
	movq %rsp, %rsi
	movl $HDN_RAP_RESUME_S3, %edi
	HDN_C_CALL hdn_rap_resume_save
#else
	movq	$.Lresume_point, saved_rip(%rip)

	movq	%rsp, saved_rsp(%rip)
	movq	%rbp, saved_rbp(%rip)
	movq	%rbx, saved_rbx(%rip)
	movq	%rdi, saved_rdi(%rip)
	movq	%rsi, saved_rsi(%rip)
#endif

	addq	$8, %rsp
	movl	$3, %edi
	xorl	%eax, %eax
	HDN_C_CALL x86_acpi_enter_sleep_state
	/* in case something went wrong, restore the machine status and go on */
	jmp	.Lresume_point

	.align 4
.Lresume_point:
#ifdef CONFIG_SECURITY_HARDENING_RAP
SYM_INNER_LABEL(__hdn_s3_resume, SYM_L_GLOBAL)
#endif
	ANNOTATE_NOENDBR
	/* We don't restore %rax, it must be 0 anyway */
#ifdef CONFIG_SECURITY_HARDENING_RAP
	movq $hdn_rap_resume_state, %rax
	lgdt saved_context_gdt_desc(%rax)
	lidt saved_context_idt(%rax)
	movl $HDN_RAP_RESUME_S3, %edi
	HDN_C_CALL hdn_rap_resume_restore
#else
	movq	$saved_context, %rax
#endif
	movq	saved_context_cr4(%rax), %rbx
	movq	%rbx, %cr4
	movq	saved_context_cr3(%rax), %rbx
	movq	%rbx, %cr3
	movq	saved_context_cr2(%rax), %rbx
	movq	%rbx, %cr2
	movq	saved_context_cr0(%rax), %rbx
	movq	%rbx, %cr0
	pushq	pt_regs_flags(%rax)
	popfq
	movq	pt_regs_sp(%rax), %rsp
	movq	pt_regs_bp(%rax), %rbp
	movq	pt_regs_si(%rax), %rsi
	movq	pt_regs_di(%rax), %rdi
	movq	pt_regs_bx(%rax), %rbx
	movq	pt_regs_cx(%rax), %rcx
	movq	pt_regs_dx(%rax), %rdx
	movq	pt_regs_r8(%rax), %r8
	movq	pt_regs_r9(%rax), %r9
	movq	pt_regs_r10(%rax), %r10
	movq	pt_regs_r11(%rax), %r11
	movq	pt_regs_r12(%rax), %r12
	movq	pt_regs_r13(%rax), %r13
	movq	pt_regs_r14(%rax), %r14
	movq	pt_regs_r15(%rax), %r15

#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
	/*
	 * The suspend path may have poisoned some areas deeper in the stack,
	 * which we now need to unpoison.
	 */
	movq	%rsp, %rdi
	HDN_C_CALL kasan_unpoison_task_stack_below
#endif

	xorl	%eax, %eax
	addq	$8, %rsp
	FRAME_END
#ifdef CONFIG_SECURITY_HARDENING_RAP
	HDN_C_CALL restore_processor_state
	jmp __hdn_rap_return
#else
	jmp	restore_processor_state
#endif
SYM_FUNC_END(do_suspend_lowlevel)
STACK_FRAME_NON_STANDARD do_suspend_lowlevel
_ASM_NOKPROBE(do_suspend_lowlevel)
_ASM_NOKPROBE(wakeup_long64)

.data
#ifndef CONFIG_SECURITY_HARDENING_RAP
saved_rbp:		.quad	0
saved_rsi:		.quad	0
saved_rdi:		.quad	0
saved_rbx:		.quad	0

saved_rip:		.quad	0
saved_rsp:		.quad	0
#endif

SYM_DATA(saved_magic,	.quad	0)
