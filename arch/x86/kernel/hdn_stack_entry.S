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
	/* The bootstrap SP is 16-byte aligned before each C ABI call. */
	HDN_C_CALL hdn_stack_mm_finish
	HDN_C_CALL hdn_stack_bootstrap_continue
	ud2
SYM_FUNC_END(__hdn_stack_bootstrap)
STACK_FRAME_NON_STANDARD __hdn_stack_bootstrap
_ASM_NOKPROBE(__hdn_stack_bootstrap)
	.popsection
