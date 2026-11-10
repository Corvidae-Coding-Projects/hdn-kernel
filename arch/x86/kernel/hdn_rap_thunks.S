/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/linkage.h>
#include <linux/export.h>
#include <asm/nospec-branch.h>
#include <asm/unwind_hints.h>
#include <asm/asm-offsets.h>
#include <asm/hdn_rap.h>
#include <asm/msr.h>
#include <asm/smap.h>
#include <linux/threads.h>

	.text
/* These adapters have private register/stack ABIs. Kind 4 requires objtool's
 * exact sequence verifier; it does not exempt arbitrary assembly from RAP. */
.macro RAP_ADAPTER name:req
	.pushsection .discard.hdn_rap.functions, "", @progbits
	.balign 8
	.quad \name, 4, 0
	.popsection
.endm
/* Save the call-clobbered state and one frame register. r10/r11 are reserved
 * by the compiler protocol. The original flags survive even for local jumps.
 * The runtime may not sleep, trace, allocate, or enable interrupts. */
.macro RAP_SAVE
	pushq %rbp
	movq %rsp, %rbp
	/* Save and clear AC before calling ordinary kernel C. Keeping PUSHF and
	 * POPF in alternatives also exposes the saved AC state to objtool. LASS
	 * alone needs the same protocol, including on CPUs without SMAP. */
	/* Without either feature AC has no access-control meaning. Analyze both
	 * feature-bearing alternatives, as smap_save()/smap_restore() do. */
	ANNOTATE_IGNORE_ALTERNATIVE
	ALTERNATIVE_2 "pushfq", "pushfq; clac", X86_FEATURE_SMAP, "pushfq; clac", X86_FEATURE_LASS
	cli
	pushq %rax
	pushq %rcx
	pushq %rdx
	pushq %rsi
	pushq %rdi
	pushq %r8
	pushq %r9
	pushq %r10
	pushq %r11
	andq $-16, %rsp
.endm

/* r11 is the validated transfer value returned by the runtime. Do not reload
 * the pre-validation candidate from a saved stack slot after its check. */
.macro RAP_RESTORE
	leaq -72(%rbp), %rsp
	popq %r10
	popq %r9
	popq %r8
	popq %rdi
	popq %rsi
	popq %rdx
	popq %rcx
	popq %rax
	ANNOTATE_IGNORE_ALTERNATIVE
	ALTERNATIVE_2 "popfq", "popfq", X86_FEATURE_SMAP, "popfq", X86_FEATURE_LASS
	popq %rbp
.endm

/* r11: candidate target; r10: compiler-bound return site. Metadata for that
 * exact site supplies the expected type. Preserve all integer arguments and
 * the caller's stack layout, including variadic and stack-passed arguments. */
SYM_FUNC_START(__hdn_rap_call)
	ANNOTATE_NOENDBR
	cmpq %r10, (%rsp)
	jne .Lhdn_rap_bad_call_site
	RAP_SAVE
	movq %r11, %rdi
	movq %r10, %rsi
	HDN_C_CALL hdn_rap_validate_call
	movq %rax, %r11
	RAP_RESTORE
	jmp __x86_indirect_thunk_r11
.Lhdn_rap_bad_call_site:
	movl $HDN_RAP_FAIL_RETURN_CLASS, %edi
	jmp __hdn_rap_fail
SYM_FUNC_END(__hdn_rap_call)
RAP_ADAPTER __hdn_rap_call
_ASM_NOKPROBE(__hdn_rap_call)
EXPORT_SYMBOL_GPL(__hdn_rap_call)

/* Intra-function jumps preserve every non-reserved register and flags. */
SYM_FUNC_START(__hdn_rap_jump)
	ANNOTATE_NOENDBR
	RAP_SAVE
	movq %r11, %rdi
	movq %r10, %rsi
	HDN_C_CALL hdn_rap_validate
	movq %rax, %r11
	RAP_RESTORE
	leaq 8(%rsp), %rsp
SYM_INNER_LABEL(__hdn_rap_jump_transfer, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	jmp __hdn_rap_transfer
SYM_INNER_LABEL(__hdn_rap_jump_transfer_end, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
SYM_FUNC_END(__hdn_rap_jump)
RAP_ADAPTER __hdn_rap_jump
_ASM_NOKPROBE(__hdn_rap_jump)
EXPORT_SYMBOL_GPL(__hdn_rap_jump)

/* Generated local/tail jumps carry an exact return-site identity instead of
 * a writable target-set pointer. The sealed image supplies the allowed set. */
SYM_FUNC_START(__hdn_rap_bpf_jump)
	ANNOTATE_NOENDBR
	cmpq %r10, (%rsp)
	jne .Lhdn_rap_bad_bpf_jump
	RAP_SAVE
	movq %r11, %rdi
	movq %r10, %rsi
	HDN_C_CALL hdn_rap_bpf_validate_jump
	movq %rax, %r11
	RAP_RESTORE
	leaq 8(%rsp), %rsp
	jmp __hdn_rap_transfer
.Lhdn_rap_bad_bpf_jump:
	movl $HDN_RAP_FAIL_RETURN_CLASS, %edi
	jmp __hdn_rap_fail
SYM_FUNC_END(__hdn_rap_bpf_jump)
RAP_ADAPTER __hdn_rap_bpf_jump
_ASM_NOKPROBE(__hdn_rap_bpf_jump)

/* Dispatcher entry is a transparent typed tail adapter. Preserve the incoming
 * R10 binding so the selected BPF function records the original caller slot. */
SYM_FUNC_START(__hdn_rap_bpf_dispatch)
	ANNOTATE_NOENDBR
	cmpq %r10, (%rsp)
	jne .Lhdn_rap_bad_bpf_dispatch
	RAP_SAVE
	movq %r11, %rdi
	HDN_C_CALL hdn_rap_bpf_dispatch_target
	movq %rax, %r11
	RAP_RESTORE
	jmp __x86_indirect_thunk_r11
.Lhdn_rap_bad_bpf_dispatch:
	movl $HDN_RAP_FAIL_RETURN_CLASS, %edi
	jmp __hdn_rap_fail
SYM_FUNC_END(__hdn_rap_bpf_dispatch)
RAP_ADAPTER __hdn_rap_bpf_dispatch
_ASM_NOKPROBE(__hdn_rap_bpf_dispatch)

/* Entered before the callee prologue. r10 names its caller's exact return
 * site; r11 names the compiler-generated continuation after this adapter.
 * The caller return slot is eight bytes above this adapter's own return. */
	.pushsection .noinstr.text, "ax"
.macro RAP_ENTER name:req caller_offset:req
SYM_FUNC_START(\name)
	ANNOTATE_NOENDBR
	cmpq %r11, (%rsp)
	jne .Lhdn_rap_bad_entry_\@
	RAP_SAVE
	leaq \caller_offset(%rbp), %rdi
	movq %r10, %rsi
	HDN_C_CALL hdn_rap_push
	/* This continuation was checked before the runtime call. Protecting its
	 * saved register, like every other assembly save, is part of the private
	 * stack and asynchronous frame protocol. */
	movq -80(%rbp), %r11
	RAP_RESTORE
	leaq 8(%rsp), %rsp
SYM_INNER_LABEL(\name\()_transfer, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	jmp __hdn_rap_transfer
SYM_INNER_LABEL(\name\()_transfer_end, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
.Lhdn_rap_bad_entry_\@:
	movl $HDN_RAP_FAIL_RETURN_CLASS, %edi
	jmp __hdn_rap_fail
SYM_FUNC_END(\name)
RAP_ADAPTER \name
_ASM_NOKPROBE(\name)
.endm

RAP_ENTER __hdn_rap_enter, 16
/* ftrace_regs_caller saves flags before its protected entry. Its own return
 * slot is therefore one word above the ordinary entry adapter's slot. */
RAP_ENTER __hdn_rap_enter_flags, 24
EXPORT_SYMBOL_GPL(__hdn_rap_enter)

SYM_FUNC_START(__hdn_rap_bpf_boundary)
	ANNOTATE_NOENDBR
	cmpq %r10, (%rsp)
	jne .Lhdn_rap_bad_bpf_boundary
	RAP_SAVE
	leaq 16(%rbp), %rdi
	movq (%rbp), %rsi
	movq %r10, %rdx
	HDN_C_CALL hdn_rap_bpf_boundary_save
	movq -72(%rbp), %r11
	RAP_RESTORE
	leaq 8(%rsp), %rsp
	jmp __hdn_rap_transfer
.Lhdn_rap_bad_bpf_boundary:
	movl $HDN_RAP_FAIL_RETURN_CLASS, %edi
	jmp __hdn_rap_fail
SYM_FUNC_END(__hdn_rap_bpf_boundary)
RAP_ADAPTER __hdn_rap_bpf_boundary
_ASM_NOKPROBE(__hdn_rap_bpf_boundary)

SYM_FUNC_START(__hdn_rap_bpf_exception)
	ANNOTATE_NOENDBR
	cmpq %r11, (%rsp)
	jne .Lhdn_rap_bad_bpf_exception
	RAP_SAVE
	movq %r11, %rdi
	leaq 16(%rbp), %rsi
	HDN_C_CALL hdn_rap_bpf_exception_restore
	/* Replace the two untrusted walker arguments with sealed coordinates.
	 * The subsequent fixed JIT prologue restores the sealed callee saves. */
	movq HDN_RAP_BPF_SP(%rax), %rdx
	movq %rdx, -40(%rbp)
	movq HDN_RAP_BPF_BP(%rax), %rdx
	movq %rdx, -32(%rbp)
	movq -80(%rbp), %r11
	RAP_RESTORE
	leaq 8(%rsp), %rsp
	jmp __hdn_rap_transfer
.Lhdn_rap_bad_bpf_exception:
	movl $HDN_RAP_FAIL_RETURN_CLASS, %edi
	jmp __hdn_rap_fail
SYM_FUNC_END(__hdn_rap_bpf_exception)
RAP_ADAPTER __hdn_rap_bpf_exception
_ASM_NOKPROBE(__hdn_rap_bpf_exception)

#ifdef CONFIG_DYNAMIC_FTRACE_WITH_JMP
SYM_FUNC_START(__hdn_rap_bpf_tramp_enter)
	ANNOTATE_NOENDBR
	cmpq %r11, (%rsp)
	jne .Lhdn_rap_bad_bpf_tramp_enter
	RAP_SAVE
	leaq 16(%rbp), %rdi
	movq %r11, %rsi
	movq %r10, %rdx
	HDN_C_CALL hdn_rap_bpf_tramp_enter
	movq -80(%rbp), %r11
	RAP_RESTORE
	leaq 8(%rsp), %rsp
	jmp __hdn_rap_transfer
.Lhdn_rap_bad_bpf_tramp_enter:
	movl $HDN_RAP_FAIL_RETURN_CLASS, %edi
	jmp __hdn_rap_fail
SYM_FUNC_END(__hdn_rap_bpf_tramp_enter)
RAP_ADAPTER __hdn_rap_bpf_tramp_enter
_ASM_NOKPROBE(__hdn_rap_bpf_tramp_enter)
#endif

SYM_FUNC_START(__hdn_rap_bpf_original)
	ANNOTATE_NOENDBR
	cmpq %r10, (%rsp)
	jne .Lhdn_rap_bad_bpf_original
	RAP_SAVE
	leaq 8(%rbp), %rdi
	movq %r10, %rsi
	movq (%rbp), %rdx
	HDN_C_CALL hdn_rap_bpf_original_enter
	movq %rax, %r11
	RAP_RESTORE
	/* Keep the CALL slot for the original body's authenticated epilogue. */
	jmp __hdn_rap_transfer
.Lhdn_rap_bad_bpf_original:
	movl $HDN_RAP_FAIL_RETURN_CLASS, %edi
	jmp __hdn_rap_fail
SYM_FUNC_END(__hdn_rap_bpf_original)
RAP_ADAPTER __hdn_rap_bpf_original
_ASM_NOKPROBE(__hdn_rap_bpf_original)

SYM_FUNC_START(__hdn_rap_bpf_skip)
	ANNOTATE_NOENDBR
	cmpq %r10, (%rsp)
	jne .Lhdn_rap_bad_bpf_skip
	RAP_SAVE
	leaq 16(%rbp), %rdi
	movq %r10, %rsi
	HDN_C_CALL hdn_rap_bpf_skip
	movq %rax, %r11
	RAP_RESTORE
	/* Consume this adapter CALL, fentry's slot, and the original return. */
	leaq 24(%rsp), %rsp
	jmp __hdn_rap_transfer
.Lhdn_rap_bad_bpf_skip:
	movl $HDN_RAP_FAIL_RETURN_CLASS, %edi
	jmp __hdn_rap_fail
SYM_FUNC_END(__hdn_rap_bpf_skip)
RAP_ADAPTER __hdn_rap_bpf_skip
_ASM_NOKPROBE(__hdn_rap_bpf_skip)

/* The epilogue jumps here with its original return slot at RSP. Transfer the
 * protected target returned in rax, preserving both scalar return registers.
 * The ordinary return slot is consumed without loading its value again. */
SYM_FUNC_START(__hdn_rap_return)
	ANNOTATE_NOENDBR
	RAP_SAVE
	leaq 8(%rbp), %rdi
	HDN_C_CALL hdn_rap_pop
	movq %rax, %r11
	RAP_RESTORE
	leaq 8(%rsp), %rsp
SYM_INNER_LABEL(__hdn_rap_return_transfer, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	jmp __hdn_rap_transfer
SYM_INNER_LABEL(__hdn_rap_return_transfer_end, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
SYM_FUNC_END(__hdn_rap_return)
RAP_ADAPTER __hdn_rap_return
_ASM_NOKPROBE(__hdn_rap_return)
EXPORT_SYMBOL_GPL(__hdn_rap_return)

/* A NULL static-call trampoline has not entered a callee and owns no return
 * record. Authenticate its still-register-bound caller continuation, consume
 * exactly that CALL slot, and retain the architecture return mitigation. */
SYM_FUNC_START(__hdn_rap_static_null)
	ANNOTATE_NOENDBR
	cmpq %r10, (%rsp)
	jne .Lhdn_rap_bad_static_null
	movq %r10, %r11
	leaq 8(%rsp), %rsp
	jmp __hdn_rap_transfer
.Lhdn_rap_bad_static_null:
	movl $HDN_RAP_FAIL_RETURN_CLASS, %edi
	jmp __hdn_rap_fail
SYM_FUNC_END(__hdn_rap_static_null)
RAP_ADAPTER __hdn_rap_static_null
_ASM_NOKPROBE(__hdn_rap_static_null)
EXPORT_SYMBOL_GPL(__hdn_rap_static_null)

/* A return hook retains the intercepted record until its final handler has
 * returned. R11 carries the handler's candidate; the root checks it against
 * the original protected target or the next fixed hook in the sealed chain. */
.macro RAP_HOOK_RETURN name:req kind:req
SYM_FUNC_START(\name)
	ANNOTATE_NOENDBR
	RAP_SAVE
	leaq 8(%rbp), %rdi
	movl $\kind, %esi
	movq -80(%rbp), %rdx
	HDN_C_CALL hdn_rap_hook_finish
	movq %rax, %r11
	RAP_RESTORE
	leaq 8(%rsp), %rsp
SYM_INNER_LABEL(\name\()_transfer, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	jmp __hdn_rap_transfer
SYM_INNER_LABEL(\name\()_transfer_end, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
SYM_FUNC_END(\name)
RAP_ADAPTER \name
_ASM_NOKPROBE(\name)
.endm

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
RAP_HOOK_RETURN __hdn_rap_graph_return, 1
#endif
#ifdef CONFIG_RETHOOK
RAP_HOOK_RETURN __hdn_rap_rethook_return, 2
#endif

/* Validated intra-function continuations are not IBT function entries. Keep
 * this fixed retpoline instead of entering an alternative which might emit
 * an IBT-tracked indirect jump. The final RET still uses the architecture's
 * return mitigation and return-site patching. Those preserve the authenticated
 * target installed below; replacing this entire capture with an indirect jump
 * would lose both its speculation trap and its interior-continuation ABI. */
SYM_FUNC_START(__hdn_rap_transfer)
	ANNOTATE_NOENDBR
	UNWIND_HINT_UNDEFINED
	ANNOTATE_INTRA_FUNCTION_CALL
	call .Lhdn_rap_transfer_capture
	int3
.Lhdn_rap_transfer_capture:
SYM_INNER_LABEL(__hdn_rap_transfer_capture, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	movq %r11, (%rsp)
SYM_INNER_LABEL(__hdn_rap_transfer_ready, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	UNWIND_HINT_FUNC
	RET
SYM_FUNC_END(__hdn_rap_transfer)
RAP_ADAPTER __hdn_rap_transfer
_ASM_NOKPROBE(__hdn_rap_transfer)
	.popsection
