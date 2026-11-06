/* SPDX-License-Identifier: GPL-2.0-only */
#include <asm/hdn_rap.h>

#ifdef HDN_RAP_REGS_TIMED
#define HDN_REG_HELPER arch_bpf_timed_may_goto
#else
#define HDN_REG_HELPER __poly1305_block
#endif

/* Isolated protocol fixture. Use real closed ABI names without linking these
 * synthetic bodies into a kernel or claiming to exercise Poly1305 itself. */
	.text
	.globl __fentry__
	.type __fentry__, @function
__fentry__:
	HDN_PRIVATE_FUNC_ENTER __fentry__
	pushq %rbp
	movq %rsp, %rbp
	movq $17, %r10
	movq $29, %r11
#ifdef HDN_RAP_REGS_BAD_CALL
	pushq %r11
	pushq %r11
	HDN_C_CALL HDN_REG_HELPER
	popq %r10
	popq %r11
#elif defined(HDN_RAP_REGS_BAD_RESULT)
	pushq %r11
	pushq %r10
	HDN_C_CALL HDN_REG_HELPER
	popq %r11
	popq %r10
#else
	HDN_REGS_CALL HDN_REG_HELPER
#endif
	popq %rbp
	HDN_ENTRY_ROOT_RETURN
	.size __fentry__, .-__fentry__

#if defined(HDN_RAP_REGS_TIMED) || defined(HDN_RAP_REGS_BAD_GLOBAL)
	.globl HDN_REG_HELPER
#else
	.local HDN_REG_HELPER
#endif
	.type HDN_REG_HELPER, @function
HDN_REG_HELPER:
#ifdef HDN_RAP_REGS_BAD_ENTRY
	HDN_ASM_PRIVATE HDN_REG_HELPER
	movq 16(%rsp), %r10
	movq 8(%rsp), %r11
#else
	HDN_REGS_FUNC HDN_REG_HELPER
#endif
	addq %r10, %r11
#ifdef HDN_RAP_REGS_BAD_RETURN
	movq %r10, 16(%rsp)
	movq %r11, 8(%rsp)
	HDN_ASM_RETURN
#else
	HDN_REGS_RETURN
#endif
	HDN_ASM_FUNCTION_END HDN_REG_HELPER
	.size HDN_REG_HELPER, .-HDN_REG_HELPER
	.section .note.GNU-stack, "", @progbits
