// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * x86 implementation of rethook. Mostly copied from arch/x86/kernel/kprobes/core.c.
 */
#include <linux/bug.h>
#include <linux/rethook.h>
#include <linux/kprobes.h>
#include <linux/objtool.h>
#include <linux/hdn_rap.h>

#include "kprobes/common.h"

__visible void arch_rethook_trampoline_callback(struct pt_regs *regs);

#ifndef ANNOTATE_NOENDBR
#define ANNOTATE_NOENDBR
#endif

/*
 * When a target function returns, this code saves registers and calls
 * arch_rethook_trampoline_callback(), which calls the rethook handler.
 */
asm(
	".text\n"
	".global arch_rethook_trampoline\n"
	".type arch_rethook_trampoline, @function\n"
	"arch_rethook_trampoline:\n"
#ifdef CONFIG_X86_64
	ANNOTATE_NOENDBR "\n"	/* This is only jumped from ret instruction */
	/* Push a fake return address to tell the unwinder it's a rethook. */
	"	pushq $arch_rethook_trampoline\n"
	UNWIND_HINT_FUNC
	"       pushq $" __stringify(__KERNEL_DS) "\n"
	/* Save the 'sp - 16', this will be fixed later. */
	"	pushq %rsp\n"
	"	pushfq\n"
	SAVE_REGS_STRING
	"	movq %rsp, %rdi\n"
#ifdef CONFIG_SECURITY_HARDENING_RAP
	"	leaq .Lhdn_rethook_callback_return(%rip), %r10\n"
#endif
	"	call arch_rethook_trampoline_callback\n"
#ifdef CONFIG_SECURITY_HARDENING_RAP
	".Lhdn_rethook_callback_return:\n"
	".pushsection .hdn.rap.sites, \"a\", @progbits\n"
	".balign 8\n"
	".quad .Lhdn_rethook_callback_return, 0\n"
	".popsection\n"
#endif
	RESTORE_REGS_STRING
	/* In the callback function, 'regs->flags' is copied to 'regs->ss'. */
	"	addq $16, %rsp\n"
	"	popfq\n"
#else
	/* Push a fake return address to tell the unwinder it's a rethook. */
	"	pushl $arch_rethook_trampoline\n"
	UNWIND_HINT_FUNC
	"	pushl %ss\n"
	/* Save the 'sp - 8', this will be fixed later. */
	"	pushl %esp\n"
	"	pushfl\n"
	SAVE_REGS_STRING
	"	movl %esp, %eax\n"
	"	call arch_rethook_trampoline_callback\n"
	RESTORE_REGS_STRING
	/* In the callback function, 'regs->flags' is copied to 'regs->ss'. */
	"	addl $8, %esp\n"
	"	popfl\n"
#endif
#ifdef CONFIG_SECURITY_HARDENING_RAP
	"	movq (%rsp), %r11\n"
	"	jmp __hdn_rap_rethook_return\n"
#else
	ASM_RET
#endif
	".size arch_rethook_trampoline, .-arch_rethook_trampoline\n"
#ifdef CONFIG_SECURITY_HARDENING_RAP
	".pushsection .discard.hdn_rap.functions, \"\", @progbits\n"
	".balign 8\n"
	".quad arch_rethook_trampoline, 4, 0\n"
	".popsection\n"
#endif
);
NOKPROBE_SYMBOL(arch_rethook_trampoline);

/*
 * Called from arch_rethook_trampoline
 */
__used __visible void arch_rethook_trampoline_callback(struct pt_regs *regs)
{
	unsigned long *frame_pointer;

	/* fixup registers */
	regs->cs = __KERNEL_CS;
#ifdef CONFIG_X86_32
	regs->gs = 0;
#endif
	regs->ip = (unsigned long)&arch_rethook_trampoline;
	regs->orig_ax = ~0UL;
	regs->sp += 2*sizeof(long);
	frame_pointer = (long *)(regs + 1);

	/*
	 * The return address at 'frame_pointer' is recovered by the
	 * arch_rethook_fixup_return() which called from this
	 * rethook_trampoline_handler().
	 */
	rethook_trampoline_handler(regs, (unsigned long)frame_pointer);

	/*
	 * Copy FLAGS to 'pt_regs::ss' so that arch_rethook_trapmoline()
	 * can do RET right after POPF.
	 */
	*(unsigned long *)&regs->ss = regs->flags;
}
NOKPROBE_SYMBOL(arch_rethook_trampoline_callback);

/*
 * arch_rethook_trampoline() skips updating frame pointer. The frame pointer
 * saved in arch_rethook_trampoline_callback() points to the real caller
 * function's frame pointer. Thus the arch_rethook_trampoline() doesn't have
 * a standard stack frame with CONFIG_FRAME_POINTER=y.
 * Let's mark it non-standard function. Anyway, FP unwinder can correctly
 * unwind without the hint.
 */
STACK_FRAME_NON_STANDARD_FP(arch_rethook_trampoline);

/* This is called from rethook_trampoline_handler(). */
void arch_rethook_fixup_return(struct pt_regs *regs,
			       unsigned long correct_ret_addr)
{
	unsigned long *frame_pointer = (void *)(regs + 1);

	/* Replace fake return address with real one. */
	*frame_pointer = correct_ret_addr;
}
NOKPROBE_SYMBOL(arch_rethook_fixup_return);

void arch_rethook_prepare(struct rethook_node *rh, struct pt_regs *regs, bool mcount)
{
	unsigned long *stack = (unsigned long *)regs->sp;

#ifdef CONFIG_SECURITY_HARDENING_RAP
	rh->ret_addr = hdn_rap_hook_arm((unsigned long)stack, HDN_RAP_HOOK_RETHOOK);
#else
	rh->ret_addr = stack[0];
#endif
	rh->frame = regs->sp;

	/* Replace the return addr with trampoline addr */
#ifndef CONFIG_SECURITY_HARDENING_RAP
	stack[0] = (unsigned long) arch_rethook_trampoline;
#endif
}
NOKPROBE_SYMBOL(arch_rethook_prepare);
