/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/linkage.h>
#include <linux/objtool.h>
#include <asm/hdn_rap.h>
#include <asm/nospec-branch.h>

	.section .noinstr.text, "ax"
/* The exact verifier binds this foreign call to the sealed boot endpoint.
 * It grants no C indirect-target permission to the generated page. */
SYM_FUNC_START(hdn_hv_hypercall)
	HDN_KEXEC_FUNC hdn_hv_hypercall, 19
	HDN_FUNC_ENTER
	pushq %rbp
	movq %rsp, %rbp
	movq %rdx, %r8
	movq %rdi, %rcx
	movq %rsi, %rdx
	movq hdn_hv_hypercall_target(%rip), %r11
	testq %r11, %r11
	jz .Lhv_unavailable
	CALL_NOSPEC r11
.Lhv_done:
	popq %rbp
	HDN_ENTRY_ROOT_RETURN
.Lhv_unavailable:
	movq $-1, %rax
	jmp .Lhv_done
SYM_FUNC_END(hdn_hv_hypercall)
_ASM_NOKPROBE(hdn_hv_hypercall)

#ifdef CONFIG_HYPERV_VTL_MODE
/* R10/R11 are guest data in this ABI. Pair their transport with the caller
 * before using RAX as the foreign target; all guest output registers survive. */
SYM_FUNC_START(hdn_hv_vtl_gate)
	HDN_KEXEC_FUNC hdn_hv_vtl_gate, 20
	HDN_FUNC_ENTER
	movq 8(%rsp), %r10
	movq 16(%rsp), %r11
	pushq %rax
	movq hdn_hv_vtl_target(%rip), %rax
	testq %rax, %rax
	jz .Lhv_vtl_unavailable
	CALL_NOSPEC rax
	addq $8, %rsp
	movq %r10, 8(%rsp)
	movq %r11, 16(%rsp)
	HDN_ENTRY_ROOT_RETURN
.Lhv_vtl_unavailable:
	ud2
SYM_FUNC_END(hdn_hv_vtl_gate)
_ASM_NOKPROBE(hdn_hv_vtl_gate)
#endif
	.section .note.GNU-stack, "", @progbits
