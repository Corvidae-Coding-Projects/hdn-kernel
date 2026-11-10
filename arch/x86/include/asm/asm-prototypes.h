/* SPDX-License-Identifier: GPL-2.0 */
#include <asm/ftrace.h>
#include <linux/uaccess.h>
#include <linux/pgtable.h>
#include <asm/string.h>
#include <asm/page.h>
#include <asm/checksum.h>
#include <asm/mce.h>

#include <asm-generic/asm-prototypes.h>

#include <asm/special_insns.h>
#include <asm/preempt.h>
#include <asm/asm.h>
#include <asm/fred.h>
#include <asm/gsseg.h>
#include <asm/nospec-branch.h>

#ifndef CONFIG_X86_CX8
extern void cmpxchg8b_emu(void);
#endif

#ifdef CONFIG_STACKPROTECTOR
extern unsigned long __ref_stack_chk_guard;
#endif

/* genksyms identities for the exported assembly protocol endpoints. These are
 * not C-callable ABIs; the declarations exist only for symbol versioning. */
extern void __hdn_rap_call(void);
extern void __hdn_rap_jump(void);
extern void __hdn_rap_enter(void);
extern void __hdn_rap_return(void);
extern void __hdn_rap_static_null(void);
