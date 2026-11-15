/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/linkage.h>
#include <asm/asm-offsets.h>
#include <asm/hdn_rap.h>
#include <asm/nospec-branch.h>
#include <asm/unwind_hints.h>

	.pushsection .init.text, "ax"
SYM_FUNC_START(__hdn_stack_bootstrap)
	ANNOTATE_NOENDBR
	HDN_STACK_BOOTSTRAP_FUNC __hdn_stack_bootstrap
	UNWIND_HINT_UNDEFINED
	movq HDN_STACK_SWITCH_CR3(%rdi), %r11
	movq HDN_STACK_SWITCH_SP(%rdi), %rdx
	movq %r11, %cr3
	movq %rdx, %rsp
	xorl %ebp, %ebp
	UNWIND_HINT_END_OF_STACK
	/* The bootstrap SP is 16-byte aligned before each C ABI call. It is
	 * also the canonical last-frame return slot immediately below
	 * task_pt_regs(). Seed that slot with each call's return site so the
	 * frame-pointer unwinder recognizes this one-way stack boundary. */
	leaq .Lhdn_stack_mm_finished(%rip), %rax
	movq %rax, (%rsp)
	HDN_C_CALL hdn_stack_mm_finish
.Lhdn_stack_mm_finished:
	leaq .Lhdn_stack_bootstrap_continued(%rip), %rax
	movq %rax, (%rsp)
	HDN_C_CALL hdn_stack_bootstrap_continue
.Lhdn_stack_bootstrap_continued:
	ud2
SYM_FUNC_END(__hdn_stack_bootstrap)
STACK_FRAME_NON_STANDARD __hdn_stack_bootstrap
_ASM_NOKPROBE(__hdn_stack_bootstrap)
	.popsection
