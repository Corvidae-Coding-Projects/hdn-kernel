/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/linkage.h>
#include <asm/nospec-branch.h>
#include <asm/page_types.h>
#include <asm/processor-flags.h>
#include <asm/hdn_rap.h>
#include <asm/unwind_hints.h>

	.text
	.align PAGE_SIZE

/*
 * asm_acpi_mp_play_dead() - Hand over control of the CPU to the BIOS
 *
 * rdi: Address of the ACPI MADT MPWK ResetVector
 * rsi: PGD of the identity mapping
 */
SYM_FUNC_START(asm_acpi_mp_play_dead)
	ANNOTATE_NOENDBR
#ifdef CONFIG_SECURITY_HARDENING_PGTABLE
	UNWIND_HINT_UNDEFINED
#ifdef HDN_RAP_ASM_ACTIVE
	.pushsection .discard.hdn_rap.functions, "", @progbits
	.balign 8
	.quad asm_acpi_mp_play_dead, 18, 0
	.popsection
#endif
	/* Ignore caller-supplied coordinates. No stack access or C call follows
	 * selection of the boot-frozen terminal address space. */
	leaq	hdn_madt_launch(%rip), %rax
	cmpq	$1, (%rax)
	jne	.Lmadt_unready
	movq	8(%rax), %rsi
	movq	16(%rax), %rdi
#endif
	/* Turn off global entries. Following CR3 write will flush them. */
	movq	%cr4, %rdx
	andq	$~(X86_CR4_PGE), %rdx
	movq	%rdx, %cr4

	/* Switch to identity mapping */
	movq	%rsi, %cr3

	/* Jump to reset vector */
	ANNOTATE_RETPOLINE_SAFE
	jmp	*%rdi
#ifdef CONFIG_SECURITY_HARDENING_PGTABLE
.Lmadt_unready:
	cli
.Lmadt_halt:
	hlt
	jmp .Lmadt_halt
#endif
SYM_FUNC_END(asm_acpi_mp_play_dead)
_ASM_NOKPROBE(asm_acpi_mp_play_dead)
