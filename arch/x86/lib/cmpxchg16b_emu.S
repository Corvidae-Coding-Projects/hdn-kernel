/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/linkage.h>
#include <asm/percpu.h>
#include <asm/processor-flags.h>
#include <asm/hdn_rap.h>

.text

/*
 * Emulate 'cmpxchg16b %gs:(%rsi)'
 *
 * Inputs:
 * %rsi : memory location to compare
 * %rax : low 64 bits of old value
 * %rdx : high 64 bits of old value
 * %rbx : low 64 bits of new value
 * %rcx : high 64 bits of new value
 *
 * Notably this is not LOCK prefixed and is not safe against NMIs
 */
SYM_FUNC_START(this_cpu_cmpxchg16b_emu)
	HDN_PRIVATE_FUNC_ENTER this_cpu_cmpxchg16b_emu, 2

	pushfq
	cli

	/* if (*ptr == old) */
	cmpq	__percpu (%rsi), %rax
	jne	.Lnot_same
	cmpq	__percpu 8(%rsi), %rdx
	jne	.Lnot_same

	/* *ptr = new */
	movq	%rbx, __percpu (%rsi)
	movq	%rcx, __percpu 8(%rsi)

	/* set ZF in EFLAGS to indicate success */
	orl	$X86_EFLAGS_ZF, (%rsp)

	popfq
	HDN_ENTRY_ROOT_RETURN

.Lnot_same:
	/* *ptr != old */

	/* old = *ptr */
	movq	__percpu (%rsi), %rax
	movq	__percpu 8(%rsi), %rdx

	/* clear ZF in EFLAGS to indicate failure */
	andl	$(~X86_EFLAGS_ZF), (%rsp)

	popfq
	HDN_ENTRY_ROOT_RETURN

SYM_FUNC_END(this_cpu_cmpxchg16b_emu)
