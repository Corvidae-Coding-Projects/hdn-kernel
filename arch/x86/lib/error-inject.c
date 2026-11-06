// SPDX-License-Identifier: GPL-2.0

#include <linux/linkage.h>
#include <linux/error-injection.h>
#include <linux/kprobes.h>
#include <linux/objtool.h>
#include <asm/hdn_rap_probe.h>

#ifndef CONFIG_SECURITY_HARDENING_RAP
asmlinkage void just_return_func(void);

asm(
	".text\n"
	".type just_return_func, @function\n"
	".globl just_return_func\n"
	ASM_FUNC_ALIGN
	"just_return_func:\n"
		ANNOTATE_NOENDBR "\n"
		ASM_RET
	".size just_return_func, .-just_return_func\n"
);
#endif

void override_function_with_return(struct pt_regs *regs)
{
#ifdef CONFIG_SECURITY_HARDENING_RAP
	hdn_rap_probe_override(regs);
#else
	regs->ip = (unsigned long)&just_return_func;
#endif
}
NOKPROBE_SYMBOL(override_function_with_return);
