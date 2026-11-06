/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/linkage.h>
#include <asm/hdn_rap.h>
#include <asm/asm.h>
#include <asm/nospec-branch.h>
#include <asm/unwind_hints.h>

/* Entered only by the authenticated breakpoint override. The intercepted
 * function already owns the return record, so do not create a second one. */
SYM_CODE_START(just_return_func)
	HDN_KEXEC_FUNC just_return_func, 51
	UNWIND_HINT_FUNC
	ANNOTATE_NOENDBR
	jmp __hdn_rap_return
SYM_CODE_END(just_return_func)
_ASM_NOKPROBE(just_return_func)
