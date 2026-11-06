/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/linkage.h>
#include <asm/asm.h>
#include <asm/hdn_rap.h>
#include <asm/hdn_hv_crash.h>
#include <asm/msr.h>
#include <asm/segment.h>
#include <asm/unwind_hints.h>

	.text
SYM_FUNC_START(hdn_hv_crash_enter)
	HDN_KEXEC_FUNC hdn_hv_crash_enter, 21
	HDN_FUNC_ENTER
	movq %rsp, %rdi
	subq $8, %rsp
	HDN_C_CALL hdn_hv_crash_capture
	HDN_C_CALL hv_crash_disable
	ud2
SYM_FUNC_END(hdn_hv_crash_enter)
STACK_FRAME_NON_STANDARD hdn_hv_crash_enter
_ASM_NOKPROBE(hdn_hv_crash_enter)

/* The low trampoline restored only init_mm. No stack or GS access is allowed
 * until the protected CPU state has restored the original private root. */
	.section .noinstr.text, "ax"
SYM_FUNC_START(hdn_hv_crash_return)
	HDN_KEXEC_FUNC hdn_hv_crash_return, 22
	UNWIND_HINT_UNDEFINED
	leaq hdn_hv_crash_cpu(%rip), %rsi
	lgdt HDN_HVC_GDT(%rsi)
	movw HDN_HVC_SS(%rsi), %ss
	movw HDN_HVC_DS(%rsi), %ds
	movw HDN_HVC_ES(%rsi), %es
	movw HDN_HVC_FS(%rsi), %fs
	movw HDN_HVC_GS(%rsi), %gs
.macro crash_msr offset:req msr:req
	movq \offset(%rsi), %rax
	movq %rax, %rdx
	shrq $32, %rdx
	movl $\msr, %ecx
	wrmsr
.endm
	crash_msr HDN_HVC_PAT, MSR_IA32_CR_PAT
	crash_msr HDN_HVC_GSBASE, MSR_GS_BASE
	crash_msr HDN_HVC_KERNELGS, MSR_KERNEL_GS_BASE
	crash_msr HDN_HVC_FSBASE, MSR_FS_BASE
	crash_msr HDN_HVC_EFER, MSR_EFER
	movq HDN_HVC_CR0(%rsi), %rax
	movq %rax, %cr0
	movq HDN_HVC_CR8(%rsi), %rax
	movq %rax, %cr8
	movq HDN_HVC_CR4(%rsi), %rax
	movq %rax, %cr4
	movq HDN_HVC_CR3(%rsi), %rax
	movq %rax, %cr3
	movq HDN_HVC_CR2(%rsi), %rax
	movq %rax, %cr2
	movq HDN_HVC_SP(%rsi), %rsp
	lidt HDN_HVC_IDT(%rsi)
	pushq $__KERNEL_CS
	leaq .Lcrash_cs(%rip), %rax
	pushq %rax
	lretq
.Lcrash_cs:
	UNWIND_HINT_FUNC
	subq $8, %rsp
	HDN_C_CALL hdn_hv_crash_finish
	/* Leave the recursion boundary before entering instrumented crash C. */
	jmp hdn_hv_crash_continue
SYM_FUNC_END(hdn_hv_crash_return)
STACK_FRAME_NON_STANDARD hdn_hv_crash_return
_ASM_NOKPROBE(hdn_hv_crash_return)

	.text
SYM_FUNC_START(hdn_hv_crash_continue)
	HDN_KEXEC_FUNC hdn_hv_crash_continue, 23
	UNWIND_HINT_UNDEFINED
	HDN_C_CALL hv_crash_handle
	ud2
SYM_FUNC_END(hdn_hv_crash_continue)
STACK_FRAME_NON_STANDARD hdn_hv_crash_continue
_ASM_NOKPROBE(hdn_hv_crash_continue)
