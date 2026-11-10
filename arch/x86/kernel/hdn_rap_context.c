// SPDX-License-Identifier: GPL-2.0-only
/* Closed return/entry context operations; allocation and fixups live separately. */
#include <linux/hdn_rap.h>
#include <linux/bpf.h>
#include <linux/hdn_stack.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/sched/task_stack.h>
#include <asm/irqflags.h>
#include <asm/traps.h>
#include <asm/hdn_stack_mm.h>
#include <asm/hdn_rap_bpf.h>
#include <asm/hdn_rap_patch.h>
#include <asm/sections.h>
#include <asm/idtentry.h>
#include <asm/irq_vectors.h>
#include "hdn_rap_context_internal.h"
#include <asm/hdn_rap_efi.h>
#include "hdn_rap_internal.h"
#include "../mm/hdn_pgtable_internal.h"

/* IRQ exclusion is also the read-side lifetime guard. Unlink waits for an
 * RCU grace period before reclaiming either a link or its enclosing context. */
struct rap_context *noinstr hdn_rap_context_for(unsigned long slot)
{
	struct rap_link *link;

	if (slot >= hdn_rap_boot_context.begin && slot < hdn_rap_boot_context.end)
		return &hdn_rap_boot_context;
	link = READ_ONCE(hdn_rap_buckets[bucket_for(slot)]);
	for (; link; link = READ_ONCE(link->next)) {
		struct rap_context *context = READ_ONCE(link->context);

		if (slot >= context->begin && slot < context->end)
			return context;
	}
	return NULL;
}

void noinstr hdn_rap_context_store(struct rap_context *context, unsigned long *word, unsigned long value)
{
	unsigned long base = (unsigned long)context, address = (unsigned long)word;
	unsigned long pfn;

	if (!IS_ALIGNED(address, sizeof(*word)) || address < base ||
	    address - base > sizeof(*context) - sizeof(*word))
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	if (!READ_ONCE(hdn_rap_private_updates)) {
		WRITE_ONCE(*word, value);
		return;
	}
	pfn = context->pfns[(address - base) >> PAGE_SHIFT];
	hdn_pt_window_update(pfn, offset_in_page(address), value, 0, HDN_PT_STORE);
}

void noinstr hdn_rap_failure_prepare(void)
{
	unsigned int cpu = hdn_pt_cpu();
	struct hdn_rap_failure_cpu *failure = &hdn_rap_failure_cpus[cpu];
	struct rap_context *context = failure->context;
	unsigned long sp;

	asm volatile("movq %%rsp,%0" : "=r" (sp));
	if (!native_irqs_disabled_flags(native_save_fl()) || !context ||
	    __native_read_cr3() != failure->cr3 || context->cpu != cpu ||
	    context->domain != RAP_FAILURE || context->owner ||
	    context->begin != failure->begin || context->end != failure->sp ||
	    sp < context->begin || sp >= context->end || context->top ||
	    context->async_top || context->sequence || context->switch_ready ||
	    hdn_pt_window_update(__pa_symbol(&failure->busy) >> PAGE_SHIFT,
			offset_in_page(&failure->busy), 1, 0, HDN_PT_COMPARE_EXCHANGE))
		__hdn_rap_halt();
	/* This domain is single-use. Ordinary reporting begins only after the
	 * protected recursion guard is committed on its fresh guarded stack. */
}

bool noinstr hdn_rap_failure_stack(unsigned long address, unsigned long *begin, unsigned long *end)
{
	const struct hdn_rap_failure_cpu *failure = &hdn_rap_failure_cpus[hdn_pt_cpu()];
	const struct rap_context *context = failure->context;

	if (!failure->busy || !context || address < context->begin || address >= context->end)
		return false;
	*begin = context->begin;
	*end = context->end;
	return true;
}

void noinstr hdn_rap_stack_enter(unsigned long slot, unsigned long function)
{
	struct rap_context *context = hdn_rap_context_for(slot), *origin;
	struct rap_stack_link *bridge;
	unsigned long sp;
	u64 sequence;

	if (!native_irqs_disabled_flags(native_save_fl()) || !context || context->owner ||
	    context->cpu != hdn_pt_cpu() || slot != context->end - sizeof(long) ||
	    context->bridge.sequence || (context->domain != RAP_IRQ &&
	    !(context->domain == RAP_DF && function == (unsigned long)handle_stack_overflow)))
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	sp = READ_ONCE(*(unsigned long *)slot);
	origin = hdn_rap_context_for(sp);
	if (!origin || origin == context || !IS_ALIGNED(sp, sizeof(long)) ||
	    (origin->owner ?
#ifdef CONFIG_SECURITY_HARDENING_PRIVATE_STACKS
	     !hdn_stack_mm_active(origin->owner, sp) :
#else
	     origin->owner != current :
#endif
	     origin->cpu != context->cpu))
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	sequence = context->sequence + 1;
	if (!sequence)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	bridge = &context->bridge;
	hdn_rap_context_store(context, (unsigned long *)&bridge->origin, (unsigned long)origin);
	hdn_rap_context_store(context, &bridge->slot, slot);
	hdn_rap_context_store(context, &bridge->sp, sp);
	hdn_rap_context_store(context, &bridge->top, context->top);
	hdn_rap_context_store(context, &bridge->async_top, context->async_top);
	hdn_rap_context_store(context, &bridge->origin_top, origin->top);
	hdn_rap_context_store(context, &bridge->origin_async_top, origin->async_top);
	hdn_rap_context_store(context, &bridge->terminal, context->domain == RAP_DF);
	hdn_rap_context_store(context, (unsigned long *)&context->sequence, sequence);
	hdn_rap_context_store(context, (unsigned long *)&bridge->sequence, sequence);
}

unsigned long noinstr hdn_rap_stack_exit(unsigned long slot)
{
	struct rap_context *context = hdn_rap_context_for(slot);
	struct rap_stack_link *bridge;
	unsigned long sp;

	if (!native_irqs_disabled_flags(native_save_fl()) || !context || context->domain != RAP_IRQ ||
	    context->cpu != hdn_pt_cpu())
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	bridge = &context->bridge;
	if (!bridge->sequence || bridge->sequence > context->sequence || bridge->terminal ||
	    bridge->slot != slot || bridge->top != context->top ||
	    bridge->async_top != context->async_top ||
	    bridge->origin != hdn_rap_context_for(bridge->sp) ||
	    bridge->origin_top != bridge->origin->top ||
	    bridge->origin_async_top != bridge->origin->async_top ||
	    READ_ONCE(*(unsigned long *)slot) != bridge->sp)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	sp = bridge->sp;
	hdn_rap_context_store(context, (unsigned long *)&bridge->sequence, 0);
	hdn_rap_context_store(context, &bridge->sp, 0);
	return sp;
}

/* Do not derive the kind or privilege domain from a frame on exit: those
 * values could have been overwritten along with its saved instruction pointer.
 */
static bool noinstr live_stack(const struct rap_context *context, unsigned long slot);

/* Text pokes are an intentional exception to unchanged kernel register frames.
 * Only the frozen, currently published patch batch supplies a destination.
 * The ordinary writable batching array is never consulted at exception time. */
int noinstr hdn_rap_text_poke(struct pt_regs *regs)
{
	struct rap_context *context = hdn_rap_context_for((unsigned long)regs);
	struct rap_async_frame *frame = NULL;
	struct pt_regs expected;
	const struct smp_text_poke_loc *patch = NULL;
	unsigned long count = READ_ONCE(hdn_rap_text_patches.nr_entries);
	unsigned long address, next, target, slot;
	unsigned int i;
	u64 sequence;

	if (!native_irqs_disabled_flags(native_save_fl()) || count > TEXT_POKE_ARRAY_MAX)
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	if (context && context->async_top) {
		if (context->async_top > RAP_ASYNC_FRAMES)
			__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
		frame = &context->async[context->async_top - 1];
		if (frame->slot != (unsigned long)regs || frame->user ||
		    frame->vector != X86_TRAP_BP || !frame->sequence ||
		    frame->sequence > context->sequence)
			__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	} else if (READ_ONCE(hdn_rap_async_required)) {
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	}
	for (i = 0; i < RAP_REG_WORDS; i++) {
		unsigned long value = READ_ONCE(((unsigned long *)regs)[i]);

		if (frame && value != frame->words[i])
			__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
		((unsigned long *)&expected)[i] = value;
	}
	address = expected.ip - INT3_INSN_SIZE;
	for (i = 0; i < count; i++) {
		const struct smp_text_poke_loc *candidate = &hdn_rap_text_patches.vec[i];

		if ((unsigned long)_stext + candidate->rel_addr == address) {
			patch = candidate;
			break;
		}
	}
	if (!patch || patch->opcode == INT3_INSN_OPCODE)
		return 0;
	next = address + patch->len;
	target = next + patch->disp;
	switch (patch->opcode) {
	case CALL_INSN_OPCODE: {
		struct rap_context *stack;

		if (patch->len != CALL_INSN_SIZE || expected.r10 != next ||
		    !hdn_rap_return_site(next) || expected.sp < sizeof(long))
			__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
		slot = expected.sp - sizeof(long);
		stack = hdn_rap_context_for(slot);
		if (!live_stack(stack, slot) || !IS_ALIGNED(slot, sizeof(long)) ||
		    slot > stack->end - sizeof(long) ||
		    (slot >= (unsigned long)regs && slot < (unsigned long)(regs + 1)))
			__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
		WRITE_ONCE(*(unsigned long *)slot, next);
		expected.sp = slot;
		expected.ip = target;
		break;
	}
	case RET_INSN_OPCODE:
		/* Keep the return slot for the normal authenticated epilogue. */
		expected.ip = (unsigned long)__hdn_rap_return;
		break;
	case JMP32_INSN_OPCODE:
	case JMP8_INSN_OPCODE:
		expected.ip = target;
		break;
	case 0x70 ... 0x7f:
		expected.ip = __emulate_cc(expected.flags, patch->opcode & 0xf) ? target : next;
		break;
	default:
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	}
	WRITE_ONCE(regs->ip, expected.ip);
	WRITE_ONCE(regs->sp, expected.sp);
	if (frame) {
		sequence = context->sequence + 1;
		if (!sequence)
			__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
		hdn_rap_context_store(context, &frame->words[offsetof(struct pt_regs, ip) / sizeof(long)], expected.ip);
		hdn_rap_context_store(context, &frame->words[offsetof(struct pt_regs, sp) / sizeof(long)], expected.sp);
		hdn_rap_context_store(context, (unsigned long *)&frame->sequence, sequence);
		hdn_rap_context_store(context, (unsigned long *)&context->sequence, sequence);
	}
	return 1;
}

static noinstr unsigned int frame_words(unsigned long kind)
{
	if (kind > HDN_RAP_FRAME_FRED_SYNTH)
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	return RAP_REG_WORDS + (kind >= HDN_RAP_FRAME_FRED ? 2 : 0);
}

#ifdef CONFIG_X86_ESPFIX64
/* A failed user IRET on the read-only espfix alias becomes #DF. Its only
 * recoverable destination is a synthetic user #GP on this CPU's entry stack.
 * The entry-stack identity was frozen before runtime, independently of TSS.sp0. */
bool noinstr hdn_rap_espfix(struct pt_regs *regs)
{
	extern unsigned char native_irq_return_iret[];
	struct rap_context *context = hdn_rap_context_for((unsigned long)regs), *entry;
	struct rap_async_frame *frame;
	unsigned long user[5] __uninitialized;
	unsigned long *source, ip, sp, sequence, top;
	struct pt_regs *gpregs;
	unsigned int cpu = hdn_pt_cpu();

	if (!context || !context->async_top || context->async_top > RAP_ASYNC_FRAMES ||
	    !native_irqs_disabled_flags(native_save_fl()))
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	frame = &context->async[context->async_top - 1];
	if (frame->slot != (unsigned long)regs || frame->vector != X86_TRAP_DF ||
	    frame->user || !frame->sequence)
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	for (unsigned int i = 0; i < RAP_REG_WORDS; i++)
		if (READ_ONCE(((unsigned long *)regs)[i]) != frame->words[i])
			__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	ip = frame->words[offsetof(struct pt_regs, ip) / sizeof(long)];
	sp = frame->words[offsetof(struct pt_regs, sp) / sizeof(long)];
	if ((long)sp >> P4D_SHIFT != ESPFIX_PGD_ENTRY || regs->cs != __KERNEL_CS ||
	    ip != (unsigned long)native_irq_return_iret)
		return false;
	top = hdn_rap_entry_stack_top[cpu];
	gpregs = (struct pt_regs *)top - 1;
	entry = hdn_rap_context_for((unsigned long)gpregs);
	if (!top || !entry || entry->domain != RAP_ENTRY || entry->cpu != cpu ||
	    entry->end != top || entry->top || entry->async_top ||
	    (regs->flags & X86_EFLAGS_IF) || !IS_ALIGNED(sp, sizeof(long)) ||
	    offset_in_page(sp) > PAGE_SIZE - sizeof(user))
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	source = (unsigned long *)sp;
	for (unsigned int i = 0; i < ARRAY_SIZE(user); i++)
		user[i] = READ_ONCE(source[i]);
	if ((user[1] & 3) != 3 || (user[4] & 3) != 3)
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	gpregs->ip = user[0];
	gpregs->cs = user[1];
	gpregs->flags = user[2];
	gpregs->sp = user[3];
	gpregs->ss = user[4];
	gpregs->orig_ax = 0;
	ip = (unsigned long)asm_exc_general_protection;
	sp = (unsigned long)&gpregs->orig_ax;
	sequence = context->sequence + 1;
	if (!sequence)
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	WRITE_ONCE(regs->ip, ip);
	WRITE_ONCE(regs->sp, sp);
	hdn_rap_context_store(context, &frame->words[offsetof(struct pt_regs, ip) / sizeof(long)], ip);
	hdn_rap_context_store(context, &frame->words[offsetof(struct pt_regs, sp) / sizeof(long)], sp);
	hdn_rap_context_store(context, (unsigned long *)&frame->sequence, sequence);
	hdn_rap_context_store(context, (unsigned long *)&context->sequence, sequence);
	return true;
}
#endif

extern char __hdn_rap_repeat_nmi[];

static noinstr bool nmi_return_frame_ok(const struct rap_async_frame *frame)
{
	const unsigned long *iret = (void *)(frame->slot + sizeof(struct pt_regs));
	const unsigned long *original = &frame->words[offsetof(struct pt_regs, ip) / sizeof(long)];
	unsigned int i;
	unsigned long flags;

	for (i = 0; i < 5; i++)
		if (READ_ONCE(iret[i]) != original[i])
			break;
	if (i == 5)
		return true;
	/* Nested NMI assembly can request another iteration. It has one fixed
	 * target and one fixed stack position; it cannot install arbitrary RIP
	 * or RSP values. That update may occur even after this check returns. */
	flags = READ_ONCE(iret[2]);
	return READ_ONCE(iret[0]) == (unsigned long)__hdn_rap_repeat_nmi &&
		READ_ONCE(iret[1]) == __KERNEL_CS &&
		READ_ONCE(iret[3]) == frame->slot + offsetof(struct pt_regs, ip) &&
		READ_ONCE(iret[4]) == __KERNEL_DS && (flags & X86_EFLAGS_FIXED) &&
		!(flags & (X86_EFLAGS_IF | X86_EFLAGS_DF | X86_EFLAGS_AC | X86_EFLAGS_TF |
			   X86_EFLAGS_IOPL | X86_EFLAGS_NT | X86_EFLAGS_VM));
}

void noinstr hdn_rap_frame_enter(struct pt_regs *regs, unsigned long kind,
		unsigned long cr3, unsigned long gsbase, unsigned long spec_ctrl,
		unsigned long vector)
{
	unsigned long slot = (unsigned long)regs, flags;
	unsigned int count = frame_words(kind), i;
	unsigned int extent = count + (kind == HDN_RAP_FRAME_NMI ? 5 : 0);
	const unsigned long *words = (const unsigned long *)regs;
	struct rap_async_frame *frame;
	struct rap_context *context;
	u64 sequence;

	if (!native_irqs_disabled_flags(native_save_fl()) || vector > 256)
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	flags = native_local_irq_save();
	/* Normal IDT and FRED entry do not save CR3 in the paranoid-entry
	 * register. Capture before closing an interrupted update window. */
#ifdef CONFIG_SECURITY_HARDENING_PRIVATE_STACKS
	if (kind == HDN_RAP_FRAME_IDT || kind >= HDN_RAP_FRAME_FRED)
		cr3 = __native_read_cr3();
#endif
	if (kind >= HDN_RAP_FRAME_FRED)
		vector = (READ_ONCE(regs->ssx) >> 32) & 0xff;
	if (kind == HDN_RAP_FRAME_FRED_SYNTH && vector < 32 && vector != X86_TRAP_NMI)
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	context = hdn_rap_context_for(slot);
	if (!context ||
	    (context->domain == RAP_FIRMWARE && !hdn_efi_stack_active(slot)) ||
	    !IS_ALIGNED(slot, sizeof(unsigned long)) ||
	    slot > context->end - extent * sizeof(unsigned long) ||
	    context->async_top >= RAP_ASYNC_FRAMES ||
	    (context->async_top && context->async[context->async_top - 1].slot <= slot))
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	sequence = context->sequence + 1;
	if (!sequence)
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	frame = &context->async[context->async_top];
	hdn_rap_context_store(context, &frame->slot, slot);
	hdn_rap_context_store(context, &frame->kind, kind);
	hdn_rap_context_store(context, &frame->vector, vector);
	hdn_rap_context_store(context, &frame->debug_rewound, 0);
	hdn_rap_context_store(context, &frame->probe_override, 0);
	hdn_rap_context_store(context, &frame->user, !!(READ_ONCE(regs->cs) & 3));
	hdn_rap_context_store(context, &frame->return_top, context->top);
	hdn_rap_context_store(context, (unsigned long *)&frame->sequence, sequence);
	hdn_rap_context_store(context, &frame->entry.cr3, cr3);
	hdn_rap_context_store(context, &frame->entry.gsbase, gsbase);
	hdn_rap_context_store(context, &frame->entry.spec_ctrl, spec_ctrl);
	for (i = 0; i < count; i++)
		hdn_rap_context_store(context, &frame->words[i], READ_ONCE(words[i]));
	if (kind == HDN_RAP_FRAME_NMI && !nmi_return_frame_ok(frame))
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	hdn_rap_context_store(context, (unsigned long *)&context->sequence, sequence);
	hdn_rap_context_store(context, &context->async_top, context->async_top + 1);
#ifdef CONFIG_SECURITY_HARDENING_PRIVATE_STACKS
	/* The original root is now authenticated. Ordinary handlers must never
	 * inherit the interrupted page-update window's writable self mapping. */
	hdn_rap_context_store(context, &frame->entry.gdt_window, hdn_stack_mm_async_enter());
#endif
	native_local_irq_restore(flags);
}

const struct hdn_rap_entry_state *noinstr hdn_rap_frame_exit(struct pt_regs *regs,
		unsigned long kind)
{
	unsigned long slot = (unsigned long)regs, flags, top;
	unsigned int count = frame_words(kind), i;
	const unsigned long *words = (const unsigned long *)regs;
	struct rap_async_frame *frame;
	struct rap_context *context;

	if (!native_irqs_disabled_flags(native_save_fl()))
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	flags = native_local_irq_save();
	context = hdn_rap_context_for(slot);
	if (!context || !context->async_top || context->async_top > RAP_ASYNC_FRAMES)
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	top = context->async_top;
	frame = &context->async[top - 1];
	if (frame->slot != slot || frame->kind != kind || !frame->sequence ||
	    frame->sequence > context->sequence || frame->return_top != context->top)
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	if (frame->user) {
		/* Signal/ptrace/syscall results intentionally edit user state. The
		 * return must still be to ring 3, never an injected kernel frame. */
		if ((READ_ONCE(regs->cs) & 3) != 3)
			__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	} else {
		for (i = 0; i < count; i++)
			if (READ_ONCE(words[i]) != frame->words[i])
				__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	}
	if (kind == HDN_RAP_FRAME_NMI && !nmi_return_frame_ok(frame))
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	hdn_rap_context_store(context, &frame->slot, 0);
	hdn_rap_context_store(context, (unsigned long *)&frame->sequence, 0);
	hdn_rap_context_store(context, &context->async_top, top - 1);
#ifdef CONFIG_SECURITY_HARDENING_PRIVATE_STACKS
	{
		unsigned long entry_cr3 = frame->entry.cr3;
		unsigned long target = hdn_stack_mm_async_target(context->owner, slot,
							 entry_cr3, frame->entry.gdt_window);

		hdn_rap_context_store(context, &frame->entry.cr3, target);
		hdn_stack_mm_async_exit(entry_cr3, frame->entry.gdt_window);
	}
#endif
	native_local_irq_restore(flags);
	return &frame->entry;
}

static noinstr bool switch_frame_inside(struct rap_context *context,
		const struct task_struct *task, const struct inactive_task_frame *frame)
{
	unsigned long address = (unsigned long)frame;

	return context && context->owner == task &&
		IS_ALIGNED(address, sizeof(unsigned long)) && address >= context->begin &&
		address <= context->end - sizeof(*frame);
}

#ifdef CONFIG_SECURITY_HARDENING_PRIVATE_STACKS
/* Only the fixed assembly AP entry calls this, on a freshly installed idle
 * stack before its first C activation. Hotplug has abandoned the old chain;
 * none of its return or asynchronous records may be replayed on restart. */
void noinstr hdn_rap_cpu_restart(void)
{
	unsigned long sp;
	struct rap_context *context;

	asm volatile("movq %%rsp,%0" : "=r" (sp));
	context = hdn_rap_context_for(sp);
	if (!native_irqs_disabled_flags(native_save_fl()) || !context ||
	    context->domain != RAP_TASK || !context->owner || context->owner->pid ||
	    !hdn_stack_mm_active(context->owner, sp) || context->sequence == U64_MAX)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	hdn_rap_context_store(context, &context->top, 0);
	hdn_rap_context_store(context, &context->async_top, 0);
	hdn_rap_context_store(context, &context->switch_ready, 0);
	hdn_rap_context_store(context, &context->hook_used, 0);
	hdn_rap_context_store(context, &context->hook_free, 0);
	hdn_rap_context_store(context, &context->bpf_top, 0);
	hdn_rap_context_store(context, &context->probe_top, 0);
	hdn_rap_context_store(context, (unsigned long *)&context->bridge.sequence, 0);
	hdn_rap_context_store(context, (unsigned long *)&context->sequence, context->sequence + 1);
}
#endif

static noinstr void save_switch_frame(struct rap_context *context,
		const struct inactive_task_frame *frame, unsigned long sp)
{
	const unsigned long *from = (const unsigned long *)frame;
	unsigned long *to = (unsigned long *)&context->switch_frame.frame;
	unsigned int i;

	for (i = 0; i < sizeof(*frame) / sizeof(*from); i++)
		hdn_rap_context_store(context, &to[i], READ_ONCE(from[i]));
	hdn_rap_context_store(context, &context->switch_frame.sp, sp);
	hdn_rap_context_store(context, &context->switch_ready, 1);
}

static noinstr bool read_switch_frame(const struct task_struct *task,
		unsigned long address, struct inactive_task_frame *snapshot)
{
	unsigned long *out = (unsigned long *)snapshot;
	const unsigned long *in = (const unsigned long *)address;

#ifdef CONFIG_SECURITY_HARDENING_PRIVATE_STACKS
	if (hdn_stack_address(address))
		return !hdn_stack_read(task, address, snapshot, sizeof(*snapshot));
#endif
	for (unsigned int i = 0; i < sizeof(*snapshot) / sizeof(*out); i++)
		out[i] = READ_ONCE(in[i]);
	return true;
}

/* Only unpublished fork state can enter without a previous switch-out.
 * copy_thread() calls this after constructing its final register frame. */
int hdn_rap_task_seed(struct task_struct *task)
{
	struct inactive_task_frame *frame = (void *)task->thread.sp;
	struct inactive_task_frame snapshot;
	struct rap_context *context;
	unsigned long flags;
	int error = -EINVAL;

	flags = native_local_irq_save();
	context = hdn_rap_context_for((unsigned long)frame);
	if (switch_frame_inside(context, task, frame) && !context->top &&
	    !context->sequence && !context->switch_ready &&
	    read_switch_frame(task, (unsigned long)frame, &snapshot) &&
	    snapshot.ret_addr == (unsigned long)ret_from_fork_asm) {
		save_switch_frame(context, &snapshot, (unsigned long)frame);
		error = 0;
	}
	native_local_irq_restore(flags);
	return error;
}

/* The assembly adapter keeps IRQs disabled. The incoming stack identity and
 * all callee-saved values come from immutable storage, not thread.sp or a
 * second load of the validated ordinary stack. A consumed snapshot cannot be
 * replayed until that task really switches out again. */
const struct hdn_rap_switch_frame *noinstr hdn_rap_switch(struct task_struct *prev,
		struct task_struct *next, struct inactive_task_frame *frame,
		unsigned long expected)
{
	struct rap_context *out = hdn_rap_context_for((unsigned long)frame);
	struct rap_context *in = hdn_rap_context_for(READ_ONCE(next->thread.sp));
	const struct inactive_task_frame *incoming;
	struct inactive_task_frame snapshot;
	const unsigned long *saved, *ordinary;
	unsigned int i;

	if (!native_irqs_disabled_flags(native_save_fl()) || !switch_frame_inside(out, prev, frame) ||
	    out->switch_ready || READ_ONCE(frame->ret_addr) != expected ||
	    (out->top && out->records[out->top - 1].slot <= (unsigned long)&frame->ret_addr) ||
	    !in || in == out || in->owner != next || in->switch_ready != 1 ||
	    in->switch_frame.sp != READ_ONCE(next->thread.sp))
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	incoming = (void *)in->switch_frame.sp;
	if (!switch_frame_inside(in, next, incoming))
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	if (!read_switch_frame(next, (unsigned long)incoming, &snapshot))
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	saved = (const unsigned long *)&in->switch_frame.frame;
	ordinary = (const unsigned long *)&snapshot;
	for (i = 0; i < sizeof(*incoming) / sizeof(*ordinary); i++)
		if (READ_ONCE(ordinary[i]) != saved[i])
			__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	save_switch_frame(out, frame, (unsigned long)frame);
	WRITE_ONCE(prev->thread.sp, (unsigned long)frame);
#ifdef CONFIG_SECURITY_HARDENING_PRIVATE_STACKS
	{
		const struct hdn_stack_switch *transition = hdn_stack_mm_prepare(prev, next,
									in->switch_frame.sp);
		hdn_rap_context_store(in, &in->switch_frame.cr3, transition->cr3);
	}
#endif
	hdn_rap_context_store(in, &in->switch_ready, 0);
#ifdef CONFIG_STACKPROTECTOR
	hdn_rap_context_store(in, &in->switch_frame.canary, READ_ONCE(next->stack_canary));
#endif
	return &in->switch_frame;
}

static bool noinstr live_stack(const struct rap_context *context, unsigned long slot)
{
	if (!context)
		return false;
#ifdef CONFIG_EFI
	if (context->domain == RAP_FIRMWARE)
		return hdn_efi_stack_active(slot);
#endif
	if (!context->owner)
		return context->cpu == hdn_pt_cpu();
#ifdef CONFIG_SECURITY_HARDENING_PRIVATE_STACKS
	return hdn_stack_mm_active(context->owner, slot);
#else
	/* Before private CR3 integration, retain the exact stack-domain check.
	 * Scheduling updates current after the assembly stack switch. */
	return true;
#endif
}

static unsigned long noinstr hook_target(unsigned long kind)
{
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	extern void return_to_handler(void);

	if (kind == HDN_RAP_HOOK_GRAPH)
		return (unsigned long)return_to_handler;
#endif
#ifdef CONFIG_RETHOOK
	extern void arch_rethook_trampoline(void);

	if (kind == HDN_RAP_HOOK_RETHOOK)
		return (unsigned long)arch_rethook_trampoline;
#endif
	__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
}

static struct rap_return_hook *noinstr return_hook(const struct rap_context *context,
		const struct rap_record *record, unsigned long index)
{
	struct rap_return_hook *hook;

	if (!index || context->hook_used > RAP_HOOK_FRAMES || index > context->hook_used)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	hook = (struct rap_return_hook *)&context->hooks[index - 1];
	if (!record->sequence || hook->owner_sequence != record->sequence || hook->next == index ||
	    hook->next > context->hook_used)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	(void)hook_target(hook->kind);
	return hook;
}

unsigned long noinstr hdn_rap_record_target(const struct rap_context *context,
		const struct rap_record *record)
{
	unsigned long index = record->hooks & ~RAP_HOOK_ENTERED;

	return index ? hook_target(return_hook(context, record, index)->kind) : record->target;
}

static void noinstr clear_record(struct rap_context *context, struct rap_record *record)
{
	if (context->bpf_top) {
		struct rap_bpf_checkpoint *checkpoint;

		if (context->bpf_top > RAP_BPF_FRAMES)
			__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
		checkpoint = &context->bpf_frames[context->bpf_top - 1];
		if (checkpoint->slot == record->slot) {
			if (checkpoint->sequence != record->sequence)
				__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
			hdn_rap_context_store(context, &context->bpf_top, context->bpf_top - 1);
		}
	}
	hdn_rap_context_store(context, &record->slot, 0);
	hdn_rap_context_store(context, &record->target, 0);
	hdn_rap_context_store(context, (unsigned long *)&record->sequence, 0);
	hdn_rap_context_store(context, &record->hooks, 0);
}

static unsigned long noinstr release_hook(struct rap_context *context,
		struct rap_record *record, unsigned long index)
{
	struct rap_return_hook *hook = return_hook(context, record, index);
	unsigned long next = hook->next;

	if (next)
		(void)return_hook(context, record, next);
	hdn_rap_context_store(context, &hook->kind, 0);
	hdn_rap_context_store(context, (unsigned long *)&hook->owner_sequence, 0);
	hdn_rap_context_store(context, &hook->next, context->hook_free);
	hdn_rap_context_store(context, &context->hook_free, index);
	return next;
}

void noinstr hdn_rap_record_discard(struct rap_context *context, struct rap_record *record)
{
	unsigned long index, count = 0;

	if (!native_irqs_disabled_flags(native_save_fl()) || record < context->records ||
	    record >= context->records + RAP_FRAMES ||
	    ((unsigned long)record - (unsigned long)context->records) % sizeof(*record))
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	index = record->hooks & ~RAP_HOOK_ENTERED;

	while (index) {
		if (++count > RAP_HOOK_FRAMES)
			__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
		index = release_hook(context, record, index);
	}
	clear_record(context, record);
}

/* A fatal oops has no return continuation. Walk only immutable context and
 * captured exception links, never the damaged stack's frame-pointer chain.
 * IRQ/DF/NMI/firmware and active private update windows remain terminal: they
 * cannot safely be converted into an ordinary task exit. */
unsigned long noinstr hdn_rap_fatal_rewind(unsigned long slot)
{
	struct rap_context *chain[8], *context = hdn_rap_context_for(slot), *task;
	const struct rap_record *last;
	unsigned long live_sp, target;
	unsigned int cpu = hdn_pt_cpu(), depth = 0, i, j;

	asm volatile("movq %%rsp,%0" : "=r" (live_sp));
	if (!native_irqs_disabled_flags(native_save_fl()) || !live_stack(context, slot) ||
	    context != hdn_rap_context_for(live_sp) || live_sp >= slot ||
	    !IS_ALIGNED(slot, sizeof(long)) || slot > context->end - sizeof(long) ||
	    !context->top || context->top > RAP_FRAMES)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	last = &context->records[context->top - 1];
	if (last->slot != slot || !last->sequence || last->sequence > context->sequence ||
	    last->hooks || READ_ONCE(*(unsigned long *)slot) != last->target)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);

	for (;;) {
		if (!context || depth == ARRAY_SIZE(chain) || context->sequence == U64_MAX ||
		    context->top > RAP_FRAMES || context->async_top > RAP_ASYNC_FRAMES ||
		    context->bpf_top > RAP_BPF_FRAMES || context->probe_top > RAP_PROBE_STEPS ||
		    context->hook_used > RAP_HOOK_FRAMES || context->hook_free > context->hook_used ||
		    context->switch_ready || context->bridge.sequence ||
		    (context->domain != RAP_TASK && context->domain != RAP_EXCEPTION))
			__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
		for (i = 0; i < depth; i++)
			if (chain[i] == context)
				__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
		chain[depth++] = context;
		for (i = 0; i < context->async_top; i++) {
			const struct rap_async_frame *frame = &context->async[i];
			unsigned int words = frame_words(frame->kind);

			if (!frame->sequence || frame->sequence > context->sequence ||
			    frame->kind == HDN_RAP_FRAME_NMI || frame->kind == HDN_RAP_FRAME_FRED_SYNTH ||
			    (frame->vector >= 32 && !(frame->user && frame->kind == HDN_RAP_FRAME_IDT &&
						     frame->vector == IA32_SYSCALL_VECTOR)) ||
			    frame->vector == X86_TRAP_NMI || frame->vector == X86_TRAP_DF ||
			    frame->slot < context->begin || frame->slot > context->end - words * sizeof(long) ||
			    !IS_ALIGNED(frame->slot, sizeof(long)) || frame->return_top > context->top ||
			    (i && context->async[i - 1].slot <= frame->slot) || frame->entry.gdt_window)
				__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
#ifdef CONFIG_SECURITY_HARDENING_PRIVATE_STACKS
			/* Never abandon a suspended page-table write while its owner
			 * still holds the private window's busy token. */
			if ((frame->entry.cr3 & CR3_ADDR_MASK) != (__native_read_cr3() & CR3_ADDR_MASK))
				__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
#endif
		}
		if (context->domain == RAP_TASK)
			break;
		if (context->owner || context->cpu != cpu || !context->async_top || context->async[0].user)
			__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
		/* The oldest exception frame identifies the interrupted stack.
		 * Nested frames on this same IST never become alternate links. */
		target = context->async[0].words[offsetof(struct pt_regs, sp) / sizeof(long)];
		if (!IS_ALIGNED(target, sizeof(long)))
			__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
		context = hdn_rap_context_for(target);
	}
	task = context;
	target = task->end - sizeof(struct pt_regs);
	if (!task->owner || task->owner != current || !task->owner->pid ||
	    task->end - task->begin != THREAD_SIZE || !live_stack(task, target))
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);

	for (i = 0; i < depth; i++) {
		context = chain[i];
		while (context->top) {
			struct rap_record *record = &context->records[context->top - 1];
			if (!record->sequence || record->sequence > context->sequence ||
			    record->slot < context->begin || record->slot > context->end - sizeof(long))
				__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
			hdn_rap_record_discard(context, record);
			hdn_rap_context_store(context, &context->top, context->top - 1);
		}
		if (context->bpf_top)
			__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
		while (context->async_top) {
			struct rap_async_frame *frame = &context->async[context->async_top - 1];
			unsigned long *words = (unsigned long *)frame;
			for (j = 0; j < sizeof(*frame) / sizeof(long); j++)
				hdn_rap_context_store(context, &words[j], 0);
			hdn_rap_context_store(context, &context->async_top, context->async_top - 1);
		}
		while (context->probe_top) {
			struct rap_probe_step *step = &context->probe_steps[context->probe_top - 1];
			hdn_rap_context_store(context, (unsigned long *)&step->probe, 0);
			hdn_rap_context_store(context, (unsigned long *)&step->sequence, 0);
			hdn_rap_context_store(context, &step->flags, 0);
			hdn_rap_context_store(context, &step->async_top, 0);
			hdn_rap_context_store(context, &context->probe_top, context->probe_top - 1);
		}
		hdn_rap_context_store(context, &context->hook_used, 0);
		hdn_rap_context_store(context, &context->hook_free, 0);
		hdn_rap_context_store(context, (unsigned long *)&context->sequence, context->sequence + 1);
	}
	return target;
}

/* The argument selects a fixed adapter, never a replacement address. Keep the
 * original authenticated target and exact nesting order in protected storage.
 * The call can originate below the intercepted frame, so locate its record
 * by its exact slot rather than assuming it is the current C call. */
unsigned long noinstr hdn_rap_hook_arm(unsigned long slot, unsigned long kind)
{
	struct rap_context *context;
	struct rap_record *record = NULL;
	struct rap_return_hook *hook;
	unsigned long flags = native_local_irq_save(), target, old, index;

	target = hook_target(kind);
	context = hdn_rap_context_for(slot);
	if (!live_stack(context, slot) || !IS_ALIGNED(slot, sizeof(long)) ||
	    slot > context->end - sizeof(long) || !context->top || context->top > RAP_FRAMES)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	for (unsigned long i = context->top; i; i--)
		if (context->records[i - 1].slot == slot) {
			record = &context->records[i - 1];
			break;
		}
	if (!record || !record->sequence || record->sequence > context->sequence ||
	    (record->hooks & RAP_HOOK_ENTERED))
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	old = hdn_rap_record_target(context, record);
	if (READ_ONCE(*(unsigned long *)slot) != old)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	if (kind == HDN_RAP_HOOK_RETHOOK && record->hooks &&
	    return_hook(context, record, record->hooks)->kind == kind)
		goto out;
	if (context->hook_used > RAP_HOOK_FRAMES || context->hook_free > context->hook_used)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	if (context->hook_free) {
		index = context->hook_free;
		hook = &context->hooks[index - 1];
		if (hook->kind || hook->owner_sequence || hook->next > context->hook_used || hook->next == index)
			__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
		hdn_rap_context_store(context, &context->hook_free, hook->next);
	} else {
		if (context->hook_used == RAP_HOOK_FRAMES)
			__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
		index = context->hook_used + 1;
		hook = &context->hooks[index - 1];
		hdn_rap_context_store(context, &context->hook_used, index);
	}
	hdn_rap_context_store(context, &hook->next, record->hooks);
	hdn_rap_context_store(context, &hook->kind, kind);
	hdn_rap_context_store(context, (unsigned long *)&hook->owner_sequence, record->sequence);
	hdn_rap_context_store(context, &record->hooks, index);
	WRITE_ONCE(*(unsigned long *)slot, target);
out:
	native_local_irq_restore(flags);
	return old;
}

/* Called only after all handler C has returned and its protected records have
 * been popped. A handler's candidate is compared with protected state; the
 * assembly adapter transfers the returned value without reloading the stack. */
unsigned long noinstr hdn_rap_hook_finish(unsigned long slot, unsigned long kind,
		unsigned long candidate)
{
	struct rap_context *context;
	struct rap_record *record;
	struct rap_return_hook *hook;
	unsigned long flags = native_local_irq_save(), hooks, target, index;

	context = hdn_rap_context_for(slot);
	if (!live_stack(context, slot) || !IS_ALIGNED(slot, sizeof(long)) ||
	    slot > context->end - sizeof(long) || !context->top || context->top > RAP_FRAMES)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	record = &context->records[context->top - 1];
	if (record->slot != slot || !record->sequence || record->sequence > context->sequence ||
	    !(record->hooks & RAP_HOOK_ENTERED))
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	index = record->hooks & ~RAP_HOOK_ENTERED;
	hook = return_hook(context, record, index);
	if (hook->kind != kind)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	hooks = hook->next;
	target = hooks ? hook_target(return_hook(context, record, hooks)->kind) : record->target;
	if (candidate != target)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	release_hook(context, record, index);
	if (hooks) {
		hdn_rap_context_store(context, &record->hooks, hooks | RAP_HOOK_ENTERED);
	} else {
		clear_record(context, record);
		hdn_rap_context_store(context, &context->top, context->top - 1);
	}
	native_local_irq_restore(flags);
	return target;
}

void noinstr hdn_rap_push(unsigned long slot, unsigned long expected)
{
	struct rap_context *context;
	struct rap_record *record;
	unsigned long flags, top;
	u64 sequence;

	flags = native_local_irq_save();
	context = hdn_rap_context_for(slot);
	if (!live_stack(context, slot) || !IS_ALIGNED(slot, sizeof(unsigned long)) ||
	    slot > context->end - sizeof(unsigned long) || READ_ONCE(*(unsigned long *)slot) != expected)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	top = context->top;
	sequence = context->sequence + 1;
	if (top == RAP_FRAMES || !sequence ||
	    (top && context->records[top - 1].slot <= slot))
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	record = &context->records[top];
	hdn_rap_context_store(context, &record->slot, slot);
	hdn_rap_context_store(context, &record->target, expected);
	hdn_rap_context_store(context, &record->hooks, 0);
	hdn_rap_context_store(context, (unsigned long *)&record->sequence, sequence);
	hdn_rap_context_store(context, (unsigned long *)&context->sequence, sequence);
	hdn_rap_context_store(context, &context->top, top + 1);
	native_local_irq_restore(flags);
}

/* The JIT calls immediately after saving its original five callee registers.
 * No pointer into a writable aux structure or unwind walk is retained. A tail
 * transfer may replace the boundary for the same authenticated return slot. */
void noinstr hdn_rap_bpf_boundary_save(unsigned long sp, unsigned long bp, unsigned long site)
{
	unsigned long flags = native_local_irq_save(), top, i;
	const struct hdn_rap_bpf_image *image = hdn_rap_bpf_find(site);
	struct rap_context *context = hdn_rap_context_for(sp);
	struct rap_record *record;
	struct rap_bpf_checkpoint *checkpoint;

	if (!image || !image->boundary || image->boundary != site ||
	    !live_stack(context, sp) || !context->top || context->top > RAP_FRAMES ||
	    !IS_ALIGNED(sp, 8) || !IS_ALIGNED(bp, 8) || bp < sp ||
	    bp > context->end - 16 || bp - sp != image->frame_depth + 40)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	record = &context->records[context->top - 1];
	if (record->slot != bp + 8 || !record->sequence ||
	    record->sequence > context->sequence || (record->hooks & RAP_HOOK_ENTERED) ||
	    READ_ONCE(*(unsigned long *)record->slot) != hdn_rap_record_target(context, record))
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	top = context->bpf_top;
	if (top > RAP_BPF_FRAMES)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	if (top && context->bpf_frames[top - 1].slot == record->slot) {
		if (context->bpf_frames[top - 1].sequence != record->sequence ||
		    context->bpf_frames[top - 1].async_top != context->async_top)
			__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
		top--;
	}
	if (top == RAP_BPF_FRAMES)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	checkpoint = &context->bpf_frames[top];
	hdn_rap_context_store(context, &checkpoint->owner, image->owner);
	hdn_rap_context_store(context, &checkpoint->slot, record->slot);
	hdn_rap_context_store(context, &checkpoint->sp, sp);
	hdn_rap_context_store(context, &checkpoint->bp, bp);
	hdn_rap_context_store(context, &checkpoint->parent_bp, READ_ONCE(*(unsigned long *)bp));
	for (i = 0; i < ARRAY_SIZE(checkpoint->callee); i++)
		hdn_rap_context_store(context, &checkpoint->callee[i], READ_ONCE(((unsigned long *)sp)[i]));
	hdn_rap_context_store(context, &checkpoint->top, context->top);
	hdn_rap_context_store(context, &checkpoint->sequence, record->sequence);
	hdn_rap_context_store(context, &checkpoint->async_top, context->async_top);
	hdn_rap_context_store(context, &context->bpf_top, top + 1);
	native_local_irq_restore(flags);
}

/* bpf_throw is still the top instrumented call here. Resolve the exception
 * callback and cleanup coordinates before KASAN consumes them; writable aux
 * pointers and unwind results cannot authorize either operation. */
unsigned long noinstr hdn_rap_bpf_throw_info(unsigned long *sp, unsigned long *bp)
{
	unsigned long flags = native_local_irq_save(), live_sp, callback = 0, i;
	const struct hdn_rap_bpf_image *image, *source;
	struct rap_context *context;
	const struct rap_bpf_checkpoint *checkpoint;
	const struct rap_record *record;
	bool from_throw = false;

	asm volatile("movq %%rsp,%0" : "=r" (live_sp));
	context = hdn_rap_context_for(live_sp);
	if (!live_stack(context, live_sp) || !context->bpf_top ||
	    context->bpf_top > RAP_BPF_FRAMES || !context->top || context->top > RAP_FRAMES)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	checkpoint = &context->bpf_frames[context->bpf_top - 1];
	if (!checkpoint->owner || checkpoint->async_top != context->async_top ||
	    !checkpoint->top || checkpoint->top >= context->top ||
	    checkpoint->bp != checkpoint->slot - 8 || checkpoint->sp < context->begin ||
	    checkpoint->bp > context->end - 16 || live_sp >= checkpoint->sp)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	record = &context->records[context->top - 1];
	source = hdn_rap_bpf_find(record->target);
	if (source && source->owner == checkpoint->owner)
		for (i = 0; i < source->edge_count; i++)
			if (source->edges[i].kind == HDN_RAP_BPF_THROW &&
			    source->edges[i].site == record->target)
				from_throw = true;
	record = &context->records[checkpoint->top - 1];
	if (!from_throw || record->slot != checkpoint->slot ||
	    record->sequence != checkpoint->sequence || !record->sequence ||
	    record->sequence > context->sequence || (record->hooks & RAP_HOOK_ENTERED) ||
	    READ_ONCE(*(unsigned long *)record->slot) != hdn_rap_record_target(context, record))
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	for (image = READ_ONCE(hdn_rap_bpf_images); image; image = READ_ONCE(image->next))
		if (image->active && image->exception && image->owner == checkpoint->owner) {
			if (callback)
				__hdn_rap_fail(HDN_RAP_FAIL_TARGET);
			callback = image->address;
		}
	if (!callback)
		__hdn_rap_fail(HDN_RAP_FAIL_TARGET);
	*sp = checkpoint->sp;
	*bp = checkpoint->bp;
	native_local_irq_restore(flags);
	return callback;
}

/* The callback reuses the nearest BPF main return, discarding only the nested
 * records established after it. Neither SP/BP from the walker nor saved GPRs
 * from ordinary BPF frames authorize a restore. The generation never rewinds. */
const struct rap_bpf_checkpoint *noinstr
hdn_rap_bpf_exception_restore(unsigned long site, unsigned long live_sp)
{
	unsigned long flags = native_local_irq_save(), i;
	const struct hdn_rap_bpf_image *callback = hdn_rap_bpf_find(site), *source;
	struct rap_context *context = hdn_rap_context_for(live_sp);
	struct rap_bpf_checkpoint *checkpoint;
	struct rap_record *record, *throw_record;
	bool from_throw = false;

	if (!callback || !callback->exception || callback->function.body != site ||
	    !live_stack(context, live_sp) || !context->bpf_top ||
	    context->bpf_top > RAP_BPF_FRAMES || !context->top || context->top > RAP_FRAMES)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	checkpoint = &context->bpf_frames[context->bpf_top - 1];
	if (!checkpoint->owner || callback->owner != checkpoint->owner ||
	    checkpoint->async_top != context->async_top || !checkpoint->top ||
	    checkpoint->top >= context->top || checkpoint->bp != checkpoint->slot - 8 ||
	    checkpoint->sp < context->begin || checkpoint->bp > context->end - 16 ||
	    live_sp >= checkpoint->sp)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	throw_record = &context->records[context->top - 1];
	source = hdn_rap_bpf_find(throw_record->target);
	if (source && source->owner == checkpoint->owner)
		for (i = 0; i < source->edge_count; i++)
			if (source->edges[i].kind == HDN_RAP_BPF_THROW &&
			    source->edges[i].site == throw_record->target)
				from_throw = true;
	record = &context->records[checkpoint->top - 1];
	if (!from_throw || record->slot != checkpoint->slot ||
	    record->sequence != checkpoint->sequence || !record->sequence ||
	    record->sequence > context->sequence || (record->hooks & RAP_HOOK_ENTERED) ||
	    READ_ONCE(*(unsigned long *)record->slot) != hdn_rap_record_target(context, record))
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	/* Remove in reverse order so nested checkpoint/hook lifetimes unwind. */
	for (i = context->top; i > checkpoint->top; i--)
		hdn_rap_record_discard(context, &context->records[i - 1]);
	hdn_rap_context_store(context, &context->top, checkpoint->top);
	for (i = 0; i < ARRAY_SIZE(checkpoint->callee); i++)
		WRITE_ONCE(((unsigned long *)checkpoint->sp)[i], checkpoint->callee[i]);
	WRITE_ONCE(*(unsigned long *)checkpoint->bp, checkpoint->parent_bp);
	/* A callback cannot replay this boundary, even if it can call bpf_throw. */
	hdn_rap_context_store(context, &checkpoint->owner, 0);
	native_local_irq_restore(flags);
	return checkpoint;
}

void noinstr hdn_rap_bpf_tramp_enter(unsigned long slot, unsigned long site, unsigned long resume)
{
	unsigned long flags = native_local_irq_save();
	const struct hdn_rap_bpf_image *image = hdn_rap_bpf_find(site);
	struct rap_context *context = hdn_rap_context_for(slot);
	struct rap_record *record;

	if (!image || !image->trampoline || image->function.body != site ||
	    !bpf_trampoline_use_jmp(image->tramp_flags) || !resume ||
	    resume != image->reference.trace_return || !live_stack(context, slot) ||
	    !context->top || context->top > RAP_FRAMES)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	record = &context->records[context->top - 1];
	if (record->slot != slot || !record->sequence || record->sequence > context->sequence ||
	    (record->hooks & RAP_HOOK_ENTERED) ||
	    READ_ONCE(*(unsigned long *)slot) != hdn_rap_record_target(context, record))
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	native_local_irq_restore(flags);
}

unsigned long noinstr hdn_rap_bpf_original_enter(unsigned long slot, unsigned long site, unsigned long bp)
{
	unsigned long flags = native_local_irq_save(), resume = 0, target;
	const struct hdn_rap_bpf_image *image = hdn_rap_bpf_find(site);
	struct rap_context *context = hdn_rap_context_for(slot);
	struct rap_record *record;

	if (!image || !image->trampoline || image->original != site ||
	    !(image->tramp_flags & BPF_TRAMP_F_CALL_ORIG) || !live_stack(context, slot) ||
	    !context->top || context->top > RAP_FRAMES || !IS_ALIGNED(bp, 8) ||
	    bp < slot || bp > context->end - 16)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	record = &context->records[context->top - 1];
	if (record->slot != bp + 8 || !record->sequence || record->sequence > context->sequence ||
	    (record->hooks & RAP_HOOK_ENTERED) ||
	    READ_ONCE(*(unsigned long *)record->slot) != hdn_rap_record_target(context, record))
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	if (!bpf_trampoline_use_jmp(image->tramp_flags)) {
		resume = record->target;
		if (!(image->tramp_flags & BPF_TRAMP_F_ORIG_STACK) &&
		    resume != image->reference.trace_return)
			__hdn_rap_fail(HDN_RAP_FAIL_TARGET);
	}
	target = hdn_rap_bpf_original_target(site, resume);
	/* The original body skips its entry instrumentation. Establish exactly
	 * its new CALL record before transferring to that authenticated body. */
	hdn_rap_push(slot, site);
	native_local_irq_restore(flags);
	return target;
}

unsigned long noinstr hdn_rap_bpf_skip(unsigned long slot, unsigned long site)
{
	unsigned long flags = native_local_irq_save(), target;
	const struct hdn_rap_bpf_image *image = hdn_rap_bpf_find(site);
	struct rap_context *context = hdn_rap_context_for(slot);
	struct rap_record *record;

	if (!image || !image->trampoline || image->skip != site ||
	    !(image->tramp_flags & BPF_TRAMP_F_SKIP_FRAME) || !live_stack(context, slot) ||
	    context->top < 2 || context->top > RAP_FRAMES)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	record = &context->records[context->top - 1];
	if (record->slot != slot || record->hooks ||
	    context->records[context->top - 2].slot != slot + 8)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	(void)hdn_rap_bpf_original_target(image->original, record->target);
	(void)hdn_rap_pop(slot);
	target = hdn_rap_pop(slot + 8);
	native_local_irq_restore(flags);
	return target;
}

struct hdn_rap_bpf_handoff noinstr
hdn_rap_bpf_trace_handoff(unsigned long slot, unsigned long requested)
{
	unsigned long flags = native_local_irq_save();
	struct hdn_rap_bpf_handoff result = {};
	const struct hdn_rap_bpf_image *image;
	struct rap_context *context = hdn_rap_context_for(slot);
	struct rap_record *record;
	bool jump = requested & 1;

	if (!live_stack(context, slot) || context->top < 2 || context->top > RAP_FRAMES)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	record = &context->records[context->top - 1];
	if (record->slot != slot || !record->sequence || record->sequence > context->sequence ||
	    record->hooks || context->records[context->top - 2].slot != slot + 8 ||
	    READ_ONCE(*(unsigned long *)slot) != record->target)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
#ifdef CONFIG_DYNAMIC_FTRACE
	{
		extern void ftrace_stub_direct_tramp(void), __hdn_ftrace_stub_direct_body(void);

		if (requested == (unsigned long)ftrace_stub_direct_tramp) {
			result.target = (unsigned long)__hdn_ftrace_stub_direct_body;
			goto out;
		}
	}
#endif
	image = hdn_rap_bpf_find(requested & ~1UL);
	if (!image || !image->trampoline || image->address != (requested & ~1UL) ||
	    (image->tramp_flags & BPF_TRAMP_F_INDIRECT) ||
	    jump != bpf_trampoline_use_jmp(image->tramp_flags) ||
	    !hdn_rap_trace_compatible(record->target, image->reference.type))
		__hdn_rap_fail(HDN_RAP_FAIL_TARGET);
	if (jump) {
		if (record->target != image->reference.trace_return)
			__hdn_rap_fail(HDN_RAP_FAIL_TARGET);
		(void)hdn_rap_pop(slot);
		result.target = image->address;
		result.resume = image->reference.trace_return;
	} else {
		/* ftrace_regs_caller already established this return record. */
		result.target = image->function.body;
	}
#ifdef CONFIG_DYNAMIC_FTRACE
out:
#endif
	native_local_irq_restore(flags);
	return result;
}

unsigned long noinstr hdn_rap_trace_retarget(unsigned long slot, unsigned long requested)
{
	struct rap_context *context;
	struct rap_record *record;
	unsigned long flags = native_local_irq_save(), target;

	context = hdn_rap_context_for(slot);
	if (!live_stack(context, slot) || !IS_ALIGNED(slot, sizeof(long)) ||
	    slot > context->end - 2 * sizeof(long) || context->top < 2 || context->top > RAP_FRAMES)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	record = &context->records[context->top - 1];
	if (record->slot != slot || !record->sequence || record->sequence > context->sequence ||
	    record->hooks || READ_ONCE(*(unsigned long *)slot) != record->target ||
	    context->records[context->top - 2].slot != slot + sizeof(long))
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	target = hdn_rap_trace_redirect(record->target, requested);
	if (target != record->target)
		hdn_rap_context_store(context, &record->target, target);
	native_local_irq_restore(flags);
	return target;
}

unsigned long noinstr hdn_rap_pop(unsigned long slot)
{
	struct rap_context *context;
	struct rap_record *record;
	unsigned long flags, top, target;

	flags = native_local_irq_save();
	context = hdn_rap_context_for(slot);
	if (!live_stack(context, slot) || !IS_ALIGNED(slot, sizeof(unsigned long)) ||
	    slot > context->end - sizeof(unsigned long) || !context->top || context->top > RAP_FRAMES)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	top = context->top;
	record = &context->records[top - 1];
	if (record->slot != slot || !record->sequence || record->sequence > context->sequence ||
	    (record->hooks & RAP_HOOK_ENTERED) ||
	    READ_ONCE(*(unsigned long *)slot) != hdn_rap_record_target(context, record))
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	target = hdn_rap_record_target(context, record);
	if (record->hooks) {
		hdn_rap_context_store(context, &record->hooks, record->hooks | RAP_HOOK_ENTERED);
	} else {
		clear_record(context, record);
		hdn_rap_context_store(context, &context->top, top - 1);
	}
	native_local_irq_restore(flags);
	return target;
}
