/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2014 Intel Corporation; author Matt Fleming
 *
 * Support for invoking 32-bit EFI runtime services from a 64-bit
 * kernel.
 *
 * The below thunking functions are only used after ExitBootServices()
 * has been called. This simplifies things considerably as compared with
 * the early EFI thunking because we can leave all the kernel state
 * intact (GDT, IDT, etc) and simply invoke the 32-bit EFI runtime
 * services from __KERNEL32_CS. This means we can continue to service
 * interrupts across an EFI mixed mode call.
 *
 * We do however, need to handle the fact that we're running in a full
 * 64-bit virtual address space. Things like the stack and instruction
 * addresses need to be accessible by the 32-bit firmware, so we rely on
 * using the identity mappings in the EFI page table to access the stack
 * and kernel text (see efi_setup_page_tables()).
 */

#include <linux/linkage.h>
#include <linux/objtool.h>
#include <asm/page_types.h>
#include <asm/segment.h>

#include <asm/hdn_rap.h>
#include <asm/hdn_rap_efi.h>

#ifdef CONFIG_SECURITY_HARDENING_RAP
	.text
	.code64
SYM_FUNC_START(__hdn_efi64_thunk)
	HDN_KEXEC_FUNC __hdn_efi64_thunk, 17
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
	movl $1, %ecx
	HDN_C_CALL hdn_efi_enter
	movq %rax, %r10
	movq efi_mixed_mode_stack_pa(%rip), %rsp
	subq $36, %rsp
	movq $__START_KERNEL_map, %rax
	subq phys_base(%rip), %rax
	leaq __efi64_thunk_ret_tramp(%rip), %rbp
	leaq __hdn_efi32_return(%rip), %rbx
	subq %rax, %rbp
	subq %rax, %rbx
	movl %ebx, 0(%rsp)
	movl 0(%r10), %edx
	movl %edx, 4(%rsp)
	movl 8(%r10), %edx
	movl %edx, 8(%rsp)
	movl 16(%r10), %edx
	movl %edx, 12(%rsp)
	movl 24(%r10), %edx
	movl %edx, 16(%rsp)
	movl 32(%r10), %edx
	movl %edx, 20(%rsp)
	movl 40(%r10), %edx
	movl %edx, 24(%rsp)
	movl 48(%r10), %edx
	movl %edx, 28(%rsp)
	movl 56(%r10), %edx
	movl %edx, 32(%rsp)
	pushq $__KERNEL32_CS
	pushq HDN_EFI_TARGET(%r10)
	lretq
SYM_FUNC_END(__hdn_efi64_thunk)
STACK_FRAME_NON_STANDARD __hdn_efi64_thunk
_ASM_NOKPROBE(__hdn_efi64_thunk)

/* One dedicated immutable page is executable only in the EFI identity map.
 * The 32-bit callee preserves EBP, containing the physical 64-bit entry. That
 * entry makes a fixed absolute jump; no saved stack pointer is trusted. */
	.section ".rodata", "a", @progbits
	.balign PAGE_SIZE
SYM_DATA_START(__efi64_thunk_ret_tramp)
	movabsq $__hdn_efi_return, %r11
	ANNOTATE_RETPOLINE_SAFE
	jmp *%r11
	.code32
SYM_INNER_LABEL(__hdn_efi32_return, SYM_L_GLOBAL)
	pushl $__KERNEL_CS
	pushl %ebp
	lret
SYM_DATA_END(__efi64_thunk_ret_tramp)
	.code64
#else
	.text
	.code64
SYM_FUNC_START(__efi64_thunk)
STACK_FRAME_NON_STANDARD __efi64_thunk
	push	%rbp
	push	%rbx

	/*
	 * Switch to 1:1 mapped 32-bit stack pointer.
	 */
	movq	%rsp, %rax
	movq	efi_mixed_mode_stack_pa(%rip), %rsp
	push	%rax

	/*
	 * Copy args passed via the stack
	 */
	subq	$0x24, %rsp
	movq	0x18(%rax), %rbp
	movq	0x20(%rax), %rbx
	movq	0x28(%rax), %rax
	movl	%ebp, 0x18(%rsp)
	movl	%ebx, 0x1c(%rsp)
	movl	%eax, 0x20(%rsp)

	/*
	 * Calculate the physical address of the kernel text.
	 */
	movq	$__START_KERNEL_map, %rax
	subq	phys_base(%rip), %rax

	leaq	1f(%rip), %rbp
	leaq	2f(%rip), %rbx
	subq	%rax, %rbp
	subq	%rax, %rbx

	movl	%ebx, 0x0(%rsp)		/* return address */
	movl	%esi, 0x4(%rsp)
	movl	%edx, 0x8(%rsp)
	movl	%ecx, 0xc(%rsp)
	movl	%r8d, 0x10(%rsp)
	movl	%r9d, 0x14(%rsp)

	/* Switch to 32-bit descriptor */
	pushq	$__KERNEL32_CS
	pushq	%rdi			/* EFI runtime service address */
	lretq

	// This return instruction is not needed for correctness, as it will
	// never be reached. It only exists to make objtool happy, which will
	// otherwise complain about unreachable instructions in the callers.
	RET
SYM_FUNC_END(__efi64_thunk)

	.section ".rodata", "a", @progbits
	.balign	16
SYM_DATA_START(__efi64_thunk_ret_tramp)
1:	movq	0x20(%rsp), %rsp
	pop	%rbx
	pop	%rbp
	ret
	int3

	.code32
2:	pushl	$__KERNEL_CS
	pushl	%ebp
	lret
SYM_DATA_END(__efi64_thunk_ret_tramp)

#endif
	.section ".data..ro_after_init", "aw"
	.balign 8
SYM_DATA(efi_mixed_mode_stack_pa, .quad 0)
