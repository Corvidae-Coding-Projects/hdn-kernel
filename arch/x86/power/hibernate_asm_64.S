/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Hibernation support for x86-64
 *
 * Copyright 2007 Rafael J. Wysocki <rjw@sisk.pl>
 * Copyright 2005 Andi Kleen <ak@suse.de>
 * Copyright 2004 Pavel Machek <pavel@suse.cz>
 *
 * swsusp_arch_resume must not use any stack or any nonlocal variables while
 * copying pages:
 *
 * Its rewriting one kernel image with another. What is stack in "old"
 * image could very well be data page in "new" image, and overwriting
 * your own stack under you is bad idea.
 */

	.text
#include <linux/linkage.h>
#include <linux/cfi_types.h>
#include <asm/segment.h>
#include <asm/page_types.h>
#include <asm/asm-offsets.h>
#include <asm/processor-flags.h>
#include <asm/frame.h>
#include <asm/nospec-branch.h>
#include <asm/msr.h>
#include <asm/hdn_rap.h>
#include <asm/hdn_rap_resume.h>
#include <asm/asm.h>
#include <asm/unwind_hints.h>

	 /* code below belongs to the image kernel */
	.align PAGE_SIZE
SYM_FUNC_START(restore_registers)
	HDN_RESUME_ENTRY restore_registers
	UNWIND_HINT_UNDEFINED
	ENDBR
	/* go back to the original page tables */
	movq    %r9, %cr3

	/* Flush TLB, including "global" things (vmalloc) */
	movq	mmu_cr4_features(%rip), %rax
	movq	%rax, %rdx
	andq	$~(X86_CR4_PGE), %rdx
	movq	%rdx, %cr4;  # turn off PGE
	movq	%cr3, %rcx;  # flush TLB
	movq	%rcx, %cr3
	movq	%rax, %cr4;  # turn PGE back on

	/* We don't restore %rax, it must be 0 anyway */
#ifdef CONFIG_SECURITY_HARDENING_RAP
	/* The restored image's sealed checkpoint owns this stack and GSBASE.
	 * Do not enter instrumented C with the boot kernel's per-CPU base. */
	movq $hdn_rap_resume_state, %rsi
	movq saved_context_kernelmode_gs_base(%rsi), %rax
	movq %rax, %rdx
	shrq $32, %rdx
	movl $MSR_GS_BASE, %ecx
	wrmsr
	movq pt_regs_sp(%rsi), %rsp
	UNWIND_HINT_FUNC
	lgdt saved_context_gdt_desc(%rsi)
	lidt saved_context_idt(%rsi)
	movl $HDN_RAP_RESUME_IMAGE, %edi
	HDN_C_CALL hdn_rap_resume_restore
#else
	movq	$saved_context, %rax
#endif
	movq	pt_regs_sp(%rax), %rsp
	UNWIND_HINT_FUNC
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
	pushq	pt_regs_flags(%rax)
	popfq

	/* Saved in save_processor_state. */
	lgdt	saved_context_gdt_desc(%rax)

	xorl	%eax, %eax

	/* tell the hibernation core that we've just restored the memory */
	movq	%rax, in_suspend(%rip)

	HDN_ENTRY_ROOT_RETURN
SYM_FUNC_END(restore_registers)
/* No incoming C frame exists across the image-copy boundary. The explicit
 * unwind hints and RAP's complete restoration verifier own this protocol. */
STACK_FRAME_NON_STANDARD restore_registers
_ASM_NOKPROBE(restore_registers)

SYM_TYPED_FUNC_START(swsusp_arch_suspend)
	HDN_TYPED_FUNC_ENTER swsusp_arch_suspend
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

	/* save cr3 */
	movq	%cr3, %rax
	movq	%rax, restore_cr3(%rip)

#ifdef CONFIG_SECURITY_HARDENING_RAP
	movq %rsp, %rsi
	movl $HDN_RAP_RESUME_IMAGE, %edi
	HDN_C_CALL hdn_rap_resume_save
#endif

	FRAME_BEGIN
	HDN_C_CALL swsusp_save
	FRAME_END
#ifdef CONFIG_SECURITY_HARDENING_RAP
	/* The original image also returns here after making the snapshot.
	 * Retire its checkpoint; the snapshot retains its own live copy. */
	pushq %rax
	movl $HDN_RAP_RESUME_IMAGE, %edi
	HDN_C_CALL hdn_rap_resume_restore
	popq %rax
#endif
	HDN_ENTRY_ROOT_RETURN
SYM_FUNC_END(swsusp_arch_suspend)

SYM_FUNC_START(restore_image)
	HDN_IMAGE_HANDOFF restore_image
#ifdef CONFIG_SECURITY_HARDENING_RAP
	FRAME_BEGIN
	HDN_C_CALL hdn_rap_hibernate_enter
	FRAME_END
	movq HDN_RAP_IMAGE_ENTRY(%rax), %r8
	movq HDN_RAP_IMAGE_CR3(%rax), %r9
	movq HDN_RAP_IMAGE_CR4(%rax), %rbx
	movq HDN_RAP_IMAGE_PAGES(%rax), %rdx
	movq HDN_RAP_IMAGE_CODE(%rax), %rcx
	movq HDN_RAP_IMAGE_TEMP_CR3(%rax), %rax
#else
	/* prepare to jump to the image kernel */
	movq	restore_jump_address(%rip), %r8
	movq	restore_cr3(%rip), %r9

	/* prepare to switch to temporary page tables */
	movq	temp_pgt(%rip), %rax
	movq	mmu_cr4_features(%rip), %rbx

	/* prepare to copy image data to their original locations */
	movq	restore_pblist(%rip), %rdx

	/* jump to relocated restore code */
	movq	relocated_restore_code(%rip), %rcx
#endif
	ANNOTATE_RETPOLINE_SAFE
	jmpq	*%rcx
SYM_FUNC_END(restore_image)
_ASM_NOKPROBE(restore_image)

	/* code below has been relocated to a safe page */
SYM_FUNC_START(core_restore_code)
	HDN_IMAGE_HANDOFF core_restore_code
	UNWIND_HINT_UNDEFINED
	ENDBR
	/* switch to temporary page tables */
	movq	%rax, %cr3
	/* flush TLB */
	movq	%rbx, %rcx
	andq	$~(X86_CR4_PGE), %rcx
	movq	%rcx, %cr4;  # turn off PGE
	movq	%cr3, %rcx;  # flush TLB
	movq	%rcx, %cr3;
	movq	%rbx, %cr4;  # turn PGE back on
.Lloop:
	testq	%rdx, %rdx
	jz	.Ldone

	/* get addresses from the pbe and copy the page */
	movq	pbe_address(%rdx), %rsi
	movq	pbe_orig_address(%rdx), %rdi
	movq	$(PAGE_SIZE >> 3), %rcx
	rep movsq

	/* progress to the next pbe */
	movq	pbe_next(%rdx), %rdx
	jmp	.Lloop

.Ldone:
	/* jump to the restore_registers address from the image header */
	ANNOTATE_RETPOLINE_SAFE
	jmpq	*%r8
SYM_FUNC_END(core_restore_code)
SYM_INNER_LABEL(core_restore_code_end, SYM_L_GLOBAL)
_ASM_NOKPROBE(core_restore_code)
