/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_HDN_RAP_DEBUG_H
#define _ASM_X86_HDN_RAP_DEBUG_H
#include <asm/ptrace.h>

#ifdef CONFIG_SECURITY_HARDENING_RAP
int hdn_rap_debug_update(struct pt_regs *regs, unsigned long ip,
		unsigned long set_flags, unsigned long clear_flags);
#else
static inline int hdn_rap_debug_update(struct pt_regs *regs, unsigned long ip,
		unsigned long set_flags, unsigned long clear_flags)
{
	regs->ip = ip;
	regs->flags = (regs->flags & ~clear_flags) | set_flags;
	return 0;
}
#endif
#endif
