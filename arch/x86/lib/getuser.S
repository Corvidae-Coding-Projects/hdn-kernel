/* SPDX-License-Identifier: GPL-2.0 */
/*
 * __get_user functions.
 *
 * (C) Copyright 1998 Linus Torvalds
 * (C) Copyright 2005 Andi Kleen
 * (C) Copyright 2008 Glauber Costa
 *
 * These functions have a non-standard call interface
 * to make them more efficient, especially as they
 * return an error value in addition to the "real"
 * return value.
 */

/*
 * __get_user_X
 *
 * Inputs:	%[r|e]ax contains the address.
 *
 * Outputs:	%[r|e]ax is error code (0 or -EFAULT)
 *		%[r|e]dx contains zero-extended value
 *		%ecx contains the high half for 32-bit __get_user_8
 *
 *
 * These functions should not modify any other registers,
 * as they get called from within inline assembly.
 */

#include <linux/export.h>
#include <linux/linkage.h>
#include <linux/objtool.h>
#include <asm/page_types.h>
#include <asm/errno.h>
#include <asm/asm-offsets.h>
#include <asm/thread_info.h>
#include <asm/asm.h>
#include <asm/smap.h>
#include <asm/hdn_rap.h>
#include <asm/runtime-const.h>

#define ASM_BARRIER_NOSPEC ALTERNATIVE "", "lfence", X86_FEATURE_LFENCE_RDTSC

.macro check_range size:req
.if IS_ENABLED(CONFIG_X86_64)
	RUNTIME_CONST_PTR USER_PTR_MAX, rdx
	cmp %rdx, %rax
	cmova %rdx, %rax
.else
	cmp $TASK_SIZE_MAX-\size+1, %eax
	jae .Lbad_get_user
	sbb %edx, %edx		/* array_index_mask_nospec() */
	and %edx, %eax
.endif
.endm

.macro UACCESS op src dst name
1:	\op \src,\dst
#ifdef CONFIG_SECURITY_HARDENING_RAP
	_ASM_EXTABLE_UA(1b, .Lhdn_bad_\name)
#else
	_ASM_EXTABLE_UA(1b, __get_user_handle_exception)
#endif
.endm

.macro HDN_GET_USER_EXIT name:req
	HDN_ENTRY_ROOT_RETURN
#ifdef CONFIG_SECURITY_HARDENING_RAP
.Lhdn_bad_\name:
	ASM_CLAC
	xor %edx,%edx
	mov $(-EFAULT),%_ASM_AX
	HDN_ENTRY_ROOT_RETURN
#endif
.endm


	.text
SYM_FUNC_START(__get_user_1)
	ANNOTATE_NOENDBR
	HDN_PRIVATE_FUNC_ENTER __get_user_1, 2
	check_range size=1
	ASM_STAC
	UACCESS movzbl (%_ASM_AX),%edx, __get_user_1
	xor %eax,%eax
	ASM_CLAC
	HDN_GET_USER_EXIT __get_user_1
SYM_FUNC_END(__get_user_1)
EXPORT_SYMBOL(__get_user_1)

SYM_FUNC_START(__get_user_2)
	ANNOTATE_NOENDBR
	HDN_PRIVATE_FUNC_ENTER __get_user_2, 2
	check_range size=2
	ASM_STAC
	UACCESS movzwl (%_ASM_AX),%edx, __get_user_2
	xor %eax,%eax
	ASM_CLAC
	HDN_GET_USER_EXIT __get_user_2
SYM_FUNC_END(__get_user_2)
EXPORT_SYMBOL(__get_user_2)

SYM_FUNC_START(__get_user_4)
	ANNOTATE_NOENDBR
	HDN_PRIVATE_FUNC_ENTER __get_user_4, 2
	check_range size=4
	ASM_STAC
	UACCESS movl (%_ASM_AX),%edx, __get_user_4
	xor %eax,%eax
	ASM_CLAC
	HDN_GET_USER_EXIT __get_user_4
SYM_FUNC_END(__get_user_4)
EXPORT_SYMBOL(__get_user_4)

SYM_FUNC_START(__get_user_8)
	ANNOTATE_NOENDBR
	HDN_PRIVATE_FUNC_ENTER __get_user_8, 2
#ifndef CONFIG_X86_64
	xor %ecx,%ecx
#endif
	check_range size=8
	ASM_STAC
#ifdef CONFIG_X86_64
	UACCESS movq (%_ASM_AX),%rdx, __get_user_8
#else
	UACCESS movl (%_ASM_AX),%edx, __get_user_8
	UACCESS movl 4(%_ASM_AX),%ecx, __get_user_8
#endif
	xor %eax,%eax
	ASM_CLAC
	HDN_GET_USER_EXIT __get_user_8
SYM_FUNC_END(__get_user_8)
EXPORT_SYMBOL(__get_user_8)

/* .. and the same for __get_user, just without the range checks */
SYM_FUNC_START(__get_user_nocheck_1)
	ANNOTATE_NOENDBR
	HDN_PRIVATE_FUNC_ENTER __get_user_nocheck_1, 2
	ASM_STAC
	ASM_BARRIER_NOSPEC
	UACCESS movzbl (%_ASM_AX),%edx, __get_user_nocheck_1
	xor %eax,%eax
	ASM_CLAC
	HDN_GET_USER_EXIT __get_user_nocheck_1
SYM_FUNC_END(__get_user_nocheck_1)
EXPORT_SYMBOL(__get_user_nocheck_1)

SYM_FUNC_START(__get_user_nocheck_2)
	ANNOTATE_NOENDBR
	HDN_PRIVATE_FUNC_ENTER __get_user_nocheck_2, 2
	ASM_STAC
	ASM_BARRIER_NOSPEC
	UACCESS movzwl (%_ASM_AX),%edx, __get_user_nocheck_2
	xor %eax,%eax
	ASM_CLAC
	HDN_GET_USER_EXIT __get_user_nocheck_2
SYM_FUNC_END(__get_user_nocheck_2)
EXPORT_SYMBOL(__get_user_nocheck_2)

SYM_FUNC_START(__get_user_nocheck_4)
	ANNOTATE_NOENDBR
	HDN_PRIVATE_FUNC_ENTER __get_user_nocheck_4, 2
	ASM_STAC
	ASM_BARRIER_NOSPEC
	UACCESS movl (%_ASM_AX),%edx, __get_user_nocheck_4
	xor %eax,%eax
	ASM_CLAC
	HDN_GET_USER_EXIT __get_user_nocheck_4
SYM_FUNC_END(__get_user_nocheck_4)
EXPORT_SYMBOL(__get_user_nocheck_4)

SYM_FUNC_START(__get_user_nocheck_8)
	ANNOTATE_NOENDBR
	HDN_PRIVATE_FUNC_ENTER __get_user_nocheck_8, 2
	ASM_STAC
	ASM_BARRIER_NOSPEC
#ifdef CONFIG_X86_64
	UACCESS movq (%_ASM_AX),%rdx, __get_user_nocheck_8
#else
	xor %ecx,%ecx
	UACCESS movl (%_ASM_AX),%edx, __get_user_nocheck_8
	UACCESS movl 4(%_ASM_AX),%ecx, __get_user_nocheck_8
#endif
	xor %eax,%eax
	ASM_CLAC
	HDN_GET_USER_EXIT __get_user_nocheck_8
SYM_FUNC_END(__get_user_nocheck_8)
EXPORT_SYMBOL(__get_user_nocheck_8)


#ifndef CONFIG_SECURITY_HARDENING_RAP
SYM_CODE_START_LOCAL(__get_user_handle_exception)
	ASM_CLAC
.Lbad_get_user:
	xor %edx,%edx
	mov $(-EFAULT),%_ASM_AX
	RET
SYM_CODE_END(__get_user_handle_exception)

#endif /* !CONFIG_SECURITY_HARDENING_RAP */
