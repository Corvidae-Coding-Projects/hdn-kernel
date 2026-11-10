/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/export.h>
#include <linux/kvm_types.h>
#include <linux/linkage.h>
#include <asm/asm.h>
#include <asm/frame.h>
#include <asm/hdn_rap.h>

	.section .noinstr.text, "ax"
/* Preserve the five outer/five inner branch iterations and six nested calls
 * of clear_bhb_loop. Separate function entries let every nested CALL/return
 * carry a protected record; no writable stack return drives the recursion.
 * RAP's fixed transfer sequence also runs on the way out, before the final
 * fence. Only EAX/ECX and reserved R10/R11 are clobbered. */
SYM_FUNC_START(clear_bhb_loop)
	ANNOTATE_NOENDBR
	HDN_PRIVATE_FUNC_ENTER clear_bhb_loop
	pushq %rbp
	movq %rsp, %rbp
	movl $5, %ecx
	HDN_C_CALL __hdn_bhb_outer
	lfence
	popq %rbp
	HDN_ENTRY_ROOT_RETURN
SYM_FUNC_END(clear_bhb_loop)
EXPORT_SYMBOL_FOR_KVM(clear_bhb_loop)

SYM_FUNC_START_LOCAL(__hdn_bhb_outer)
	ANNOTATE_NOENDBR
	HDN_PRIVATE_FUNC_ENTER __hdn_bhb_outer
	FRAME_BEGIN
	HDN_C_CALL __hdn_bhb_inner
	FRAME_END
	HDN_ENTRY_ROOT_RETURN
SYM_FUNC_END(__hdn_bhb_outer)

SYM_FUNC_START_LOCAL(__hdn_bhb_inner)
	ANNOTATE_NOENDBR
	HDN_PRIVATE_FUNC_ENTER __hdn_bhb_inner
	FRAME_BEGIN
	movl $5, %eax
1:	jmp 2f
	nop
2:	subl $1, %eax
	jnz 1b
	subl $1, %ecx
	jz 3f
	HDN_C_CALL __hdn_bhb_inner
3:	FRAME_END
	HDN_ENTRY_ROOT_RETURN
SYM_FUNC_END(__hdn_bhb_inner)
