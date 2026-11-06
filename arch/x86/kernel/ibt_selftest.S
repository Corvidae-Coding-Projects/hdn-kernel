/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/linkage.h>
#include <linux/objtool.h>
#include <asm/nospec-branch.h>
#include <asm/hdn_rap.h>

#ifdef HDN_RAP_ASM_ACTIVE
/* Keep the intentional missing-ENDBR transfer inside one protected function.
 * Objtool checks this complete, fixed-target protocol before modeling the
 * raw indirect jump as its single local edge. */
SYM_FUNC_START(ibt_selftest)
	HDN_DIRECT_FUNC_ENTER ibt_selftest
	lea ibt_selftest_noendbr(%rip), %rax
	ANNOTATE_RETPOLINE_SAFE
	jmp *%rax
SYM_INNER_LABEL(ibt_selftest_noendbr, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	/* #CP handler sets %ax to 0 and authenticates that sole data edit. */
	HDN_ENTRY_ROOT_RETURN
SYM_FUNC_END(ibt_selftest)
_ASM_NOKPROBE(ibt_selftest)
#else
SYM_CODE_START(ibt_selftest_noendbr)
	ANNOTATE_NOENDBR
	UNWIND_HINT_FUNC
	/* #CP handler sets %ax to 0 */
	RET
SYM_CODE_END(ibt_selftest_noendbr)

SYM_FUNC_START(ibt_selftest)
	lea ibt_selftest_noendbr(%rip), %rax
	ANNOTATE_RETPOLINE_SAFE
	jmp *%rax
SYM_FUNC_END(ibt_selftest)
#endif
