/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/linkage.h>
#include <linux/threads.h>
#include <asm/asm-offsets.h>
#include <asm/hdn_rap.h>
#include <asm/msr.h>
#include <asm/nospec-branch.h>
#include <asm/smap.h>
#include <asm/unwind_hints.h>

	.section .noinstr.text, "ax"
/* A violation never calls C or reads the rejected stack before installing
 * the hardware-identified CPU's permanent failure root and guarded stack. */
SYM_FUNC_START(__hdn_rap_fail)
	ANNOTATE_NOENDBR
	UNWIND_HINT_UNDEFINED
	cli
	ALTERNATIVE_2 "", "clac", X86_FEATURE_SMAP, "clac", X86_FEATURE_LASS
	cld
	movq %rdi, %r12
	movl $MSR_GS_BASE, %ecx
	rdmsr
	shlq $32, %rdx
	orq %rdx, %rax
	leaq hdn_rap_failure_cpus(%rip), %rbx
	movl $NR_CPUS, %ecx
.Lhdn_failure_cpu:
	cmpq HDN_RAP_FAILURE_GSBASE(%rbx), %rax
	jne .Lhdn_failure_next
	movq HDN_RAP_FAILURE_CR3(%rbx), %rdx
	testq %rdx, %rdx
	jz __hdn_rap_halt
	cmpq $0, HDN_RAP_FAILURE_BUSY(%rbx)
	jne __hdn_rap_halt
	/* A window failure while committing the protected busy flag must not
	 * reset this stack and retry forever. Check geometry without touching
	 * the rejected stack or relying on the yet-uncommitted flag. */
	movq HDN_RAP_FAILURE_SP(%rbx), %rax
	cmpq %rax, %rsp
	jae .Lhdn_failure_install
	cmpq HDN_RAP_FAILURE_BEGIN(%rbx), %rsp
	jae __hdn_rap_halt
.Lhdn_failure_install:
	lgdt HDN_RAP_FAILURE_GDT(%rbx)
	movq %rdx, %cr3
	movq HDN_RAP_FAILURE_SP(%rbx), %rsp
	xorl %ebp, %ebp
	UNWIND_HINT_END_OF_STACK
	HDN_C_CALL hdn_rap_failure_prepare
	movq %r12, %rdi
	ANNOTATE type=ANNOTYPE_INSTR_BEGIN
	HDN_C_CALL hdn_rap_failure_report
	UNWIND_HINT_END_OF_STACK
	jmp __hdn_rap_halt
.Lhdn_failure_next:
	addq $HDN_RAP_FAILURE_SIZE, %rbx
	decl %ecx
	jnz .Lhdn_failure_cpu
	jmp __hdn_rap_halt
SYM_FUNC_END(__hdn_rap_fail)
_ASM_NOKPROBE(__hdn_rap_fail)
STACK_FRAME_NON_STANDARD __hdn_rap_fail

/* Recursion or failure before domain initialization has no safe reporter. */
SYM_FUNC_START(__hdn_rap_halt)
	ANNOTATE_NOENDBR
	UNWIND_HINT_UNDEFINED
	cli
.Lhdn_failure_halt:
	hlt
	jmp .Lhdn_failure_halt
SYM_FUNC_END(__hdn_rap_halt)
_ASM_NOKPROBE(__hdn_rap_halt)

	.pushsection .discard.hdn_rap.functions, "", @progbits
	.balign 8
	.quad __hdn_rap_fail, 3, 0
	.quad __hdn_rap_halt, 2, 0
	.popsection
