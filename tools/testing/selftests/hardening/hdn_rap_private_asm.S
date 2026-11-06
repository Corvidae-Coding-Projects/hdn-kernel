/* SPDX-License-Identifier: GPL-2.0-only */
#include <asm/hdn_rap.h>

	.text
	.globl __fentry__
	.type __fentry__, @function
__fentry__:
	HDN_PRIVATE_FUNC_ENTER __fentry__
#ifdef HDN_RAP_PRIVATE_RAW_RETURN
	jmp __x86_return_thunk
#else
	HDN_ENTRY_ROOT_RETURN
#endif
	.size __fentry__, .-__fentry__

#ifdef HDN_RAP_PRIVATE_TARGET
/* A private ABI must be rejected even before examining its target type. */
	.pushsection .hdn.rap.targets, "a", @progbits
	.balign 8
	.quad __fentry__, 0
	.popsection
#endif
	.section .note.GNU-stack, "", @progbits
