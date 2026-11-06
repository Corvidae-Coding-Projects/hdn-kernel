/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2002 Andi Kleen, SuSE Labs */

#include <linux/export.h>
#include <linux/linkage.h>
#include <linux/cfi_types.h>
#include <asm/cpufeatures.h>
#include <asm/alternative.h>
#include <asm/hdn_rap.h>

.section .noinstr.text, "ax"

/*
 * ISO C memset - set a memory block to a byte value. This function uses fast
 * string to get better performance than the original function. The code is
 * simpler and shorter than the original function as well.
 *
 * rdi   destination
 * rsi   value (char)
 * rdx   count (bytes)
 *
 * rax   original destination
 *
 * The FSRS alternative should be done inline (avoiding the call and
 * the disgusting return handling), but that would require some help
 * from the compiler for better calling conventions.
 *
 * The 'rep stosb' itself is small enough to replace the call, but all
 * the register moves blow up the code. And two of them are "needed"
 * only for the return value that is the same as the source input,
 * which the compiler could/should do much better anyway.
 */
SYM_TYPED_FUNC_START(__memset)
	HDN_TYPED_FUNC_ENTER __memset, 2
	ALTERNATIVE "jmp memset_orig", "", X86_FEATURE_FSRS

	movq %rdi,%r9
	movb %sil,%al
	movq %rdx,%rcx
	rep stosb
	movq %r9,%rax
	HDN_ENTRY_ROOT_RETURN
#ifndef HDN_RAP_ASM_ACTIVE
SYM_FUNC_END(__memset)
#endif
EXPORT_SYMBOL(__memset)

SYM_FUNC_ALIAS_MEMFUNC(memset, __memset)
#ifndef CONFIG_SECURITY_HARDENING_RAP
SYM_PIC_ALIAS(memset)
#endif
EXPORT_SYMBOL(memset)

#ifdef HDN_RAP_ASM_ACTIVE
memset_orig:
#else
SYM_FUNC_START_LOCAL(memset_orig)
	HDN_BOOTSTRAP_FUNC memset_orig
#endif
	movq %rdi,%r10

	/* expand byte value  */
	movzbl %sil,%ecx
	movabs $0x0101010101010101,%rax
	imulq  %rcx,%rax

	/* align dst */
	movl  %edi,%r9d
	andl  $7,%r9d
	jnz  .Lbad_alignment
.Lafter_bad_alignment:

	movq  %rdx,%rcx
	shrq  $6,%rcx
	jz	 .Lhandle_tail

	.p2align 4
.Lloop_64:
	decq  %rcx
	movq  %rax,(%rdi)
	movq  %rax,8(%rdi)
	movq  %rax,16(%rdi)
	movq  %rax,24(%rdi)
	movq  %rax,32(%rdi)
	movq  %rax,40(%rdi)
	movq  %rax,48(%rdi)
	movq  %rax,56(%rdi)
	leaq  64(%rdi),%rdi
	jnz    .Lloop_64

	/* Handle tail in loops. The loops should be faster than hard
	   to predict jump tables. */
	.p2align 4
.Lhandle_tail:
	movl	%edx,%ecx
	andl    $63&(~7),%ecx
	jz 		.Lhandle_7
	shrl	$3,%ecx
	.p2align 4
.Lloop_8:
	decl   %ecx
	movq  %rax,(%rdi)
	leaq  8(%rdi),%rdi
	jnz    .Lloop_8

.Lhandle_7:
	andl	$7,%edx
	jz      .Lende
	.p2align 4
.Lloop_1:
	decl    %edx
	movb 	%al,(%rdi)
	leaq	1(%rdi),%rdi
	jnz     .Lloop_1

.Lende:
	movq	%r10,%rax
	HDN_ENTRY_ROOT_RETURN

.Lbad_alignment:
	cmpq $7,%rdx
	jbe	.Lhandle_7
	movq %rax,(%rdi)	/* unaligned store */
	movq $8,%r8
	subq %r9,%r8
	addq %r8,%rdi
	subq %r8,%rdx
	jmp .Lafter_bad_alignment
.Lfinal:
#ifdef HDN_RAP_ASM_ACTIVE
SYM_FUNC_END(__memset)
#else
SYM_FUNC_END(memset_orig)
#endif
