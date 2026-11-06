/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_HDN_RAP_H
#define _ASM_X86_HDN_RAP_H

#define HDN_RAP_FRAME_IDT 0
#define HDN_RAP_FRAME_PARANOID 1
#define HDN_RAP_FRAME_NMI 2
#define HDN_RAP_FRAME_FRED 3
#define HDN_RAP_FRAME_FRED_SYNTH 4

#if defined(CONFIG_SECURITY_HARDENING_RAP) && !defined(__DISABLE_EXPORTS) && !defined(BUILD_VDSO)
#define HDN_RAP_ASM_ACTIVE 1
#endif

#ifdef __ASSEMBLY__
.macro HDN_HARDWARE_EVENT_FUNC name:req
#ifdef HDN_RAP_ASM_ACTIVE
	.pushsection .discard.hdn_rap.functions, "", @progbits
	.balign 8
	.quad \name, 13, 0
	.popsection
#endif
.endm

.macro HDN_KEXEC_FUNC name:req kind:req
#ifdef HDN_RAP_ASM_ACTIVE
	.pushsection .discard.hdn_rap.functions, "", @progbits
	.balign 8
	.quad \name, \kind, 0
	.popsection
#endif
.endm

.macro HDN_RESUME_ENTRY name:req
#ifdef HDN_RAP_ASM_ACTIVE
	.pushsection .discard.hdn_rap.functions, "", @progbits
	.balign 8
	.quad \name, 9, 0
	.popsection
#endif
.endm

.macro HDN_IMAGE_HANDOFF name:req
#ifdef HDN_RAP_ASM_ACTIVE
	.pushsection .discard.hdn_rap.functions, "", @progbits
	.balign 8
	.quad \name, 8, 0
	.popsection
#endif
.endm

.macro HDN_BOOTSTRAP_FUNC name:req
#ifdef HDN_RAP_BOOTSTRAP
	.pushsection .discard.hdn_rap.functions, "", @progbits
	.balign 8
	.quad \name, 7, 0
	.popsection
#endif
.endm

/* C ABI calls only. Assembly-private conventions must not silently acquire a
 * clobbered R10. Each expansion carries its own exact post-call relocation. */
.macro HDN_C_CALL target:req
#ifdef HDN_RAP_ASM_ACTIVE
	leaq .Lhdn_c_return_\@(%rip), %r10
#endif
	call \target
#ifdef HDN_RAP_ASM_ACTIVE
.Lhdn_c_return_\@:
	.pushsection .hdn.rap.sites, "a", @progbits
	.balign 8
	.quad .Lhdn_c_return_\@, 0
	.popsection
#endif
.endm

/* C-callable assembly, with an incoming compiler-bound R10. */
.macro HDN_FUNC_ENTER
#ifdef HDN_RAP_ASM_ACTIVE
	leaq .Lhdn_func_resume_\@(%rip), %r11
	call __hdn_rap_enter
.Lhdn_func_resume_\@:
#endif
.endm

/* Compiler/tracing hooks preserve a private register ABI and have no ordinary
 * C function type. They still require every normal entry, call and return
 * check, and must never acquire indirect-call target permission. */
.macro HDN_PRIVATE_FUNC_ENTER name:req returns=1
	HDN_FUNC_ENTER
#ifdef HDN_RAP_ASM_ACTIVE
	.pushsection .discard.hdn_rap.functions, "", @progbits
	.balign 8
	.quad \name, 5, \returns
	.popsection
#endif
.endm

/* An actual C-callable assembly function. Its type anchor comes from a C
 * declaration, not a handwritten hash; entry/return coverage remains checked. */
.macro HDN_TYPED_FUNC_ENTER name:req returns=1 indirect=1
	HDN_BOOTSTRAP_FUNC \name
	HDN_FUNC_ENTER
#ifdef HDN_RAP_ASM_ACTIVE
.Lhdn_typed_body_\@:
	.pushsection .hdn.rap.entries, "a", @progbits
	.balign 8
	.quad \name, __hdn_rap_type_\name, .Lhdn_typed_body_\@, 0
	.popsection
	.if \indirect
	.pushsection .hdn.rap.targets, "a", @progbits
	.balign 8
	.quad \name, __hdn_rap_type_\name
	.popsection
	.endif
	.pushsection .discard.hdn_rap.functions, "", @progbits
	.balign 8
	.quad \name, 1, \returns
	.popsection
#endif
.endm

/* Direct-only assembly still has a canonical type for tracing and static
 * calls, but must not gain function-pointer permission or require ENDBR. */
.macro HDN_DIRECT_FUNC_ENTER name:req returns=1
	HDN_TYPED_FUNC_ENTER \name, \returns, 0
.endm

/* Macro-generated assembly can emit a different number of epilogues for each
 * instantiation. Count the emitted protected returns, then let objtool check
 * every actual return and the complete control-flow body independently. */
.set .Lhdn_asm_returns, 0
.macro HDN_ASM_FUNCTION name:req indirect=0
	.set .Lhdn_asm_start_\name, .Lhdn_asm_returns
	HDN_TYPED_FUNC_ENTER \name, .Lhdn_asm_count_\name, \indirect
.endm
.macro HDN_ASM_PRIVATE name:req
	.set .Lhdn_asm_start_\name, .Lhdn_asm_returns
	HDN_PRIVATE_FUNC_ENTER \name, .Lhdn_asm_count_\name
.endm
.macro HDN_ASM_FUNCTION_END name:req
	.set .Lhdn_asm_count_\name, .Lhdn_asm_returns - .Lhdn_asm_start_\name
.endm
.macro HDN_ASM_RETURN
	.set .Lhdn_asm_returns, .Lhdn_asm_returns + 1
	HDN_ENTRY_ROOT_RETURN
.endm

/* Assembly-only register ABI. Two caller-owned words transport R10/R11
 * through the RAP scratch registers in BOTH directions. The matching callee
 * must use HDN_REGS_FUNC/RETURN and have no arguments above its return slot.
 * The extra 16 bytes preserve call alignment; none of these moves change
 * flags. These words contain data, never an alternate return address. */
.macro HDN_REGS_CALL target:req
#ifdef HDN_RAP_ASM_ACTIVE
	pushq %r11
	pushq %r10
#endif
	HDN_C_CALL \target
#ifdef HDN_RAP_ASM_ACTIVE
	popq %r10
	popq %r11
#endif
.endm

.macro HDN_REGS_FUNC name:req
	HDN_ASM_PRIVATE \name
#ifdef HDN_RAP_ASM_ACTIVE
	movq 8(%rsp), %r10
	movq 16(%rsp), %r11
#endif
.endm

.macro HDN_REGS_RETURN
#ifdef HDN_RAP_ASM_ACTIVE
	movq %r10, 8(%rsp)
	movq %r11, 16(%rsp)
#endif
	HDN_ASM_RETURN
.endm

/* Entry assembly has saved the interrupted registers and established kernel
 * CR3/GS before this boundary. No C or other untrusted memory operation may
 * precede it on a path which subsequently calls C. The incoming assembly CALL
 * slot is captured once, before exposing that stack to a C handler. */
.macro HDN_ENTRY_ROOT
#ifdef HDN_RAP_ASM_ACTIVE
.Lhdn_entry_root_\@:
	movq (%rsp), %r10
	leaq .Lhdn_entry_resume_\@(%rip), %r11
	call __hdn_rap_enter
.Lhdn_entry_resume_\@:
	.pushsection .discard.hdn_rap.roots, "", @progbits
	.balign 8
	.quad .Lhdn_entry_root_\@, .Lhdn_entry_resume_\@
	.popsection
#endif
.endm

.macro HDN_ENTRY_ROOT_RETURN
#ifdef HDN_RAP_ASM_ACTIVE
	jmp __hdn_rap_return
#else
	RET
#endif
.endm

.macro HDN_FRAME_ENTER kind:req vector=256
#ifdef HDN_RAP_ASM_ACTIVE
	movq %rsp, %rdi
	movl $\kind, %esi
	.if \vector > 255
	movl $256, %r9d	/* common IRQ/unknown-vector entry is not a fixup domain */
	.else
	movl $\vector, %r9d
	.endif
	.if \kind == HDN_RAP_FRAME_PARANOID || \kind == HDN_RAP_FRAME_NMI
	movq %r14, %rdx
	movq %rbx, %rcx
	movq %r15, %r8
	.else
	xorl %edx, %edx
	xorl %ecx, %ecx
	xorl %r8d, %r8d
	.endif
	HDN_C_CALL hdn_rap_frame_enter
#elif defined(CONFIG_SECURITY_HARDENING_PGTABLE) || defined(CONFIG_SECURITY_HARDENING_GDT)
	/* R13 is free after the interrupted register set has been saved.
	 * All ordinary handlers preserve it as part of the C calling ABI. */
	call hdn_entry_window_enter
	movq %rax, %r13
#endif
.endm

.macro HDN_FRAME_EXIT kind:req
#ifdef HDN_RAP_ASM_ACTIVE
	movq %rsp, %rdi
	movl $\kind, %esi
	HDN_C_CALL hdn_rap_frame_exit
	.if \kind == HDN_RAP_FRAME_PARANOID || \kind == HDN_RAP_FRAME_NMI
	movq HDN_RAP_ENTRY_CR3(%rax), %r14
	movq HDN_RAP_ENTRY_GS(%rax), %rbx
	movq HDN_RAP_ENTRY_SPEC_CTRL(%rax), %r15
	.endif
#ifdef CONFIG_SECURITY_HARDENING_PRIVATE_STACKS
	.if \kind == HDN_RAP_FRAME_IDT || \kind == HDN_RAP_FRAME_FRED || \kind == HDN_RAP_FRAME_FRED_SYNTH
	movq HDN_RAP_ENTRY_CR3(%rax), %rdx
	movq %rdx, %cr3
	.endif
#endif
#elif defined(CONFIG_SECURITY_HARDENING_PGTABLE) || defined(CONFIG_SECURITY_HARDENING_GDT)
	movq %r13, %rdi
	call hdn_entry_window_exit
#endif
.endm
#else
#include <asm/switch_to.h>

/* Separate from the caller's mutable saved registers. Entry assembly loads
 * these values only from the immutable result of frame authentication. */
struct hdn_rap_entry_state {
	unsigned long cr3, gsbase, spec_ctrl, gdt_window;
};

struct hdn_rap_switch_frame {
	unsigned long sp;
	struct inactive_task_frame frame;
	unsigned long cr3;
	unsigned long canary;
};

void __noreturn rewind_stack_and_make_dead(int signr);

#ifdef CONFIG_SECURITY_HARDENING_RAP
unsigned long hdn_rap_fatal_rewind(unsigned long slot);
const struct hdn_rap_switch_frame *hdn_rap_switch(struct task_struct *prev,
		struct task_struct *next, struct inactive_task_frame *frame,
		unsigned long expected);
void hdn_rap_frame_enter(struct pt_regs *regs, unsigned long kind,
		unsigned long cr3, unsigned long gsbase, unsigned long spec_ctrl,
		unsigned long vector);
const struct hdn_rap_entry_state *hdn_rap_frame_exit(struct pt_regs *regs,
		unsigned long kind);
bool hdn_rap_espfix(struct pt_regs *regs);
#endif
#endif
#endif
