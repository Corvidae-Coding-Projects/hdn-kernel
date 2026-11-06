/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Function calling ABI conversion from Linux to EFI for x86_64
 *
 * Copyright (C) 2007 Intel Corp
 *	Bibo Mao <bibo.mao@intel.com>
 *	Huang Ying <ying.huang@intel.com>
 */

#include <linux/linkage.h>
#include <asm/nospec-branch.h>

#include <asm/hdn_rap.h>
#include <asm/hdn_rap_efi.h>
#include <asm/msr.h>
#include <linux/objtool.h>

#ifdef CONFIG_SECURITY_HARDENING_RAP
/* Eight padded argument slots make the capture independent of argument count.
 * Firmware can change caller-saved registers but cannot choose our saved stack
 * or the continuation used by the protected return adapter. */
SYM_FUNC_START(__hdn_efi_call)
	HDN_KEXEC_FUNC __hdn_efi_call, 14
	HDN_FUNC_ENTER
	pushfq
	cli
	pushq %rbx
	pushq %rbp
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15
	subq $64, %rsp
	movq %rdx, 0(%rsp)
	movq %rcx, 8(%rsp)
	movq %r8, 16(%rsp)
	movq %r9, 24(%rsp)
	movq 128(%rsp), %rax
	movq %rax, 32(%rsp)
	movq 136(%rsp), %rax
	movq %rax, 40(%rsp)
	movq 144(%rsp), %rax
	movq %rax, 48(%rsp)
	movq 152(%rsp), %rax
	movq %rax, 56(%rsp)
	movq %rsp, %rdx
	xorl %ecx, %ecx
	HDN_C_CALL hdn_efi_enter
	movq %rax, %r11
	andq $-16, %rsp
	subq $48, %rsp
	movq 32(%r11), %rax
	movq %rax, 32(%rsp)
	movq 40(%r11), %rax
	movq %rax, 40(%rsp)
	movq 0(%r11), %rcx
	movq 8(%r11), %rdx
	movq 16(%r11), %r8
	movq 24(%r11), %r9
	pushq HDN_EFI_FLAGS(%r11)
	popfq
	movq HDN_EFI_TARGET(%r11), %r11
	CALL_NOSPEC r11
	jmp __hdn_efi_return
SYM_FUNC_END(__hdn_efi_call)
STACK_FRAME_NON_STANDARD __hdn_efi_call
_ASM_NOKPROBE(__hdn_efi_call)

SYM_FUNC_START(__hdn_efi_fault_return)
	HDN_KEXEC_FUNC __hdn_efi_fault_return, 16
	movabsq $0x8000000000000015, %rax /* EFI_ABORTED */
	jmp __hdn_efi_return
SYM_FUNC_END(__hdn_efi_fault_return)
STACK_FRAME_NON_STANDARD __hdn_efi_fault_return
_ASM_NOKPROBE(__hdn_efi_fault_return)

SYM_FUNC_START(__hdn_efi_return)
	HDN_KEXEC_FUNC __hdn_efi_return, 15
	cli
	cld
	movq %rax, %r8
	leaq hdn_efi_state(%rip), %r11
	movq HDN_EFI_GS(%r11), %rax
	movq %rax, %rdx
	shrq $32, %rdx
	movl $MSR_GS_BASE, %ecx
	wrmsr
	movq HDN_EFI_SP(%r11), %rsp
	pushq %r8
	pushq HDN_EFI_FLAGS(%r11)
	movq HDN_EFI_R15(%r11), %r15
	movq HDN_EFI_R14(%r11), %r14
	movq HDN_EFI_R13(%r11), %r13
	movq HDN_EFI_R12(%r11), %r12
	movq HDN_EFI_BP(%r11), %rbp
	movq HDN_EFI_BX(%r11), %rbx
	/* No checkpoint fields may be read after finish releases ownership. */
	HDN_C_CALL hdn_efi_finish
	popfq
	popq %rax
	HDN_ENTRY_ROOT_RETURN
SYM_FUNC_END(__hdn_efi_return)
STACK_FRAME_NON_STANDARD __hdn_efi_return
_ASM_NOKPROBE(__hdn_efi_return)
#else
SYM_FUNC_START(__efi_call)
	/*
	 * The EFI code doesn't have any CFI, annotate away the CFI violation.
	 */
	ANNOTATE_NOCFI_SYM
	pushq %rbp
	movq %rsp, %rbp
	and $~0xf, %rsp
	mov 16(%rbp), %rax
	subq $48, %rsp
	mov %r9, 32(%rsp)
	mov %rax, 40(%rsp)
	mov %r8, %r9
	mov %rcx, %r8
	mov %rsi, %rcx
	CALL_NOSPEC rdi
	leave
	RET
SYM_FUNC_END(__efi_call)

#endif
