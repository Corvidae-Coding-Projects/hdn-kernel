/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_HDN_RAP_CALL_H
#define _ASM_X86_HDN_RAP_CALL_H

/* Extended-asm C ABI calls. Numeric local labels allow several invocations in
 * one asm block without reusing GCC's per-block %= value. R10 is a clobber. */
#if defined(CONFIG_SECURITY_HARDENING_RAP) && !defined(__DISABLE_EXPORTS) && !defined(BUILD_VDSO)
#define HDN_ASM_C_CALL(target) \
	"leaq 991f(%%rip), %%r10\n\t" \
	"994: call " target "\n\t" \
	"991:\n\t" \
	".pushsection .hdn.rap.sites,\"a\",@progbits\n\t" \
	".balign 8\n\t.quad 991b,0\n\t.popsection\n\t"
#define HDN_ASM_STACK_SAVE UNWIND_HINT_SAVE
#define HDN_ASM_STACK_ENTER \
	"movq %%rsp, %%rdi\n\tmovq $%c[__func], %%rsi\n\t" \
	HDN_ASM_C_CALL("hdn_rap_stack_enter")
#define HDN_ASM_STACK_LEAVE \
	"movq %%rsp, %%rdi\n\t" \
	HDN_ASM_C_CALL("hdn_rap_stack_exit") \
	"movq %%rax, %%rsp\n\t" \
	UNWIND_HINT_RESTORE
#else
#define HDN_ASM_C_CALL(target) "994: call " target "\n\t"
#define HDN_ASM_STACK_SAVE ""
#define HDN_ASM_STACK_ENTER ""
#define HDN_ASM_STACK_LEAVE "popq %%rsp\n\t"
#endif
#endif
