/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/linkage.h>
#include <asm/asm.h>
#include <asm/asm-offsets.h>
#include <asm/hdn_rap.h>
#include <asm/msr.h>
#include <asm/nospec-branch.h>
#include <asm/segment.h>
#include <asm/unwind_hints.h>

	.text
/* A compiler-bound direct call creates the checkpoint's protected record.
 * Once GS has been reset, there are no C calls until the fixed return entry. */
SYM_FUNC_START(hdn_rap_kexec)
	HDN_KEXEC_FUNC hdn_rap_kexec, 10
	HDN_FUNC_ENTER
	pushq %rbx
	pushq %rbp
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15
	movq %rsp, %rsi
	HDN_C_CALL hdn_rap_kexec_enter
	movq %rax, %r11
	movq HDN_KEXEC_HEAD(%r11), %rdi
	movq HDN_KEXEC_CONTROL(%r11), %rsi
	movq HDN_KEXEC_ENTRY(%r11), %rdx
	movq HDN_KEXEC_FLAGS(%r11), %rcx
	movq HDN_KEXEC_TABLE(%r11), %r8
	movq HDN_KEXEC_CODE(%r11), %r11
	movl $__KERNEL_DS, %eax
	movl %eax, %ds
	movl %eax, %es
	movl %eax, %ss
	movl %eax, %fs
	movl %eax, %gs
	ANNOTATE_RETPOLINE_SAFE
	jmp *%r11
SYM_FUNC_END(hdn_rap_kexec)
STACK_FRAME_NON_STANDARD hdn_rap_kexec
_ASM_NOKPROBE(hdn_rap_kexec)

/* The terminal copy code returns only here. It restored CRs from the physical
 * checkpoint; install the matching virtual stack and per-CPU base first. */
SYM_FUNC_START(hdn_rap_kexec_return)
	ENDBR
	HDN_KEXEC_FUNC hdn_rap_kexec_return, 12
	UNWIND_HINT_UNDEFINED
	movq $hdn_rap_kexec_state, %rsi
	movq HDN_KEXEC_GS(%rsi), %rax
	movq %rax, %rdx
	shrq $32, %rdx
	movl $MSR_GS_BASE, %ecx
	wrmsr
	movq HDN_KEXEC_SP(%rsi), %rsp
	lgdt HDN_KEXEC_GDT(%rsi)
	lidt HDN_KEXEC_IDT(%rsi)
	UNWIND_HINT_FUNC
	pushq %rbp
	movq %rbp, %rdi
	HDN_C_CALL hdn_rap_kexec_finish
	popq %rax
	movq $hdn_rap_kexec_state, %rdx
	movq HDN_KEXEC_R15(%rdx), %r15
	movq HDN_KEXEC_R14(%rdx), %r14
	movq HDN_KEXEC_R13(%rdx), %r13
	movq HDN_KEXEC_R12(%rdx), %r12
	movq HDN_KEXEC_BP(%rdx), %rbp
	movq HDN_KEXEC_BX(%rdx), %rbx
	pushq HDN_KEXEC_RFLAGS(%rdx)
	popfq
	HDN_ENTRY_ROOT_RETURN
SYM_FUNC_END(hdn_rap_kexec_return)
STACK_FRAME_NON_STANDARD hdn_rap_kexec_return
_ASM_NOKPROBE(hdn_rap_kexec_return)
