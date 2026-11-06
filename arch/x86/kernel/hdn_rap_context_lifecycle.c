// SPDX-License-Identifier: GPL-2.0-only
/* Ordinary instrumented allocation, publication, fixup and retirement paths. */
#include <linux/hdn_execmem.h>
#include <linux/hdn_pgtable.h>
#include <linux/hdn_rap.h>
#include <linux/hardening.h>
#include <linux/bitfield.h>
#include <linux/extable.h>
#include <linux/error-injection.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/rcupdate.h>
#include <linux/sched/task_stack.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <linux/kprobes.h>
#include <asm/irqflags.h>
#include <asm/bug.h>
#include <asm/cpu_entry_area.h>
#include <asm/hdn_pgtable.h>
#include <asm/hdn_rap.h>
#include <asm/hdn_rap_efi.h>
#include <asm/hdn_rap_probe.h>
#include <asm/hdn_rap_debug.h>
#include <asm/hdn_stack_mm.h>
#include <asm/insn.h>
#include <asm/insn-eval.h>
#include <asm/sgx.h>
#include <asm/traps.h>
#include <asm/desc.h>
#include "../mm/hdn_pgtable_internal.h"

#include "hdn_rap_context_internal.h"
#include "hdn_rap_internal.h"
#include "hdn_stack_internal.h"

struct rap_context hdn_rap_boot_context __aligned(PAGE_SIZE) __ro_after_init = {
	.owner = &init_task,
	.domain = RAP_TASK,
	.cpu = NR_CPUS,
	.begin = (unsigned long)init_stack,
	.end = (unsigned long)init_stack + THREAD_SIZE,
};
/* The boot CPU installs IST before the slab/vmap allocators exist. Cover that
 * interval without allocating one oversized static array for every CPU. */
static struct {
	struct rap_context context;
} __aligned(PAGE_SIZE) boot_exception_contexts[5] __ro_after_init;
struct rap_link *hdn_rap_buckets[RAP_BUCKETS] __aligned(PAGE_SIZE) __ro_after_init;
bool hdn_rap_private_updates __ro_after_init;
bool hdn_rap_async_required __ro_after_init;
static bool hdn_rap_failure_ready __ro_after_init;
unsigned long hdn_rap_entry_stack_top[NR_CPUS] __ro_after_init;
struct hdn_rap_failure_cpu hdn_rap_failure_cpus[NR_CPUS] __ro_after_init;
static DEFINE_RAW_SPINLOCK(registry_lock);

static struct rap_async_frame *fixup_frame(struct rap_context *context,
		struct pt_regs *regs, int trapnr)
{
	struct rap_async_frame *frame;

	if (!context || !context->async_top) {
		/* Early IDT fixups predate installation of the full entry paths. */
		if (!READ_ONCE(hdn_rap_async_required))
			return NULL;
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	}
	if (context->async_top > RAP_ASYNC_FRAMES)
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	frame = &context->async[context->async_top - 1];
	if (frame->slot != (unsigned long)regs || frame->user ||
	    frame->kind == HDN_RAP_FRAME_FRED_SYNTH ||
	    frame->vector != trapnr || !frame->sequence)
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	return frame;
}
u64 hdn_rap_fixup_begin(struct pt_regs *regs, int trapnr)
{
	struct rap_async_frame *frame;
	unsigned long flags;
	unsigned int i;
	u64 sequence = 0;

	flags = native_local_irq_save();
	frame = fixup_frame(hdn_rap_context_for((unsigned long)regs), regs, trapnr);
	if (frame) {
		for (i = 0; i < RAP_REG_WORDS; i++)
			if (((unsigned long *)regs)[i] != frame->words[i])
				__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
		sequence = frame->sequence;
	}
	native_local_irq_restore(flags);
	return sequence;
}

/* Commit only an independently reconstructed result. In particular a handler
 * cannot turn an arbitrary saved-register edit into an authenticated frame. */
static void commit_fixup(struct rap_context *context, struct rap_async_frame *frame,
		struct pt_regs *regs, const struct pt_regs *expected)
{
	u64 sequence = context->sequence + 1;
	unsigned int i;

	if (!sequence)
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	for (i = 0; i < RAP_REG_WORDS; i++)
		if (READ_ONCE(((unsigned long *)regs)[i]) != ((const unsigned long *)expected)[i])
			__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	for (i = 0; i < RAP_REG_WORDS; i++)
		hdn_rap_context_store(context, &frame->words[i], ((const unsigned long *)expected)[i]);
	hdn_rap_context_store(context, (unsigned long *)&frame->sequence, sequence);
	hdn_rap_context_store(context, (unsigned long *)&context->sequence, sequence);
}

/* Debugger continue/step can replay the trapped instruction or toggle hardware
 * stepping. It cannot authorize an unrelated kernel PC, stack or register
 * image. Multiple commands in one stop are checked against the last committed
 * frame, so a series of one-byte rewinds cannot walk the instruction stream. */
int hdn_rap_debug_update(struct pt_regs *regs, unsigned long ip,
		unsigned long set_flags, unsigned long clear_flags)
{
	struct rap_context *context;
	struct rap_async_frame *frame;
	struct pt_regs expected;
	unsigned long flags = native_local_irq_save();
	int error = -EPERM;

	context = hdn_rap_context_for((unsigned long)regs);
	if (!context || !context->async_top || context->async_top > RAP_ASYNC_FRAMES)
		goto out;
	frame = &context->async[context->async_top - 1];
	if (frame->slot != (unsigned long)regs || frame->user || !frame->sequence ||
	    ((set_flags | clear_flags) & ~(X86_EFLAGS_TF | X86_EFLAGS_RF)))
		goto out;
	memcpy(&expected, frame->words, sizeof(expected));
	if (memcmp(regs, &expected, sizeof(expected)))
		goto out;
	if (ip != expected.ip) {
		if (frame->vector != X86_TRAP_BP || frame->debug_rewound ||
		    !expected.ip || ip != expected.ip - INT3_INSN_SIZE)
			goto out;
		hdn_rap_context_store(context, &frame->debug_rewound, 1);
	}
	expected.ip = ip;
	expected.flags = (expected.flags & ~clear_flags) | set_flags;
	/* NMI has a second IRET frame that nested NMI assembly can rewrite.
	 * Continue without edits remains valid; stepping that dual frame needs
	 * a separate protocol and must not leave only one copy changed. */
	if (frame->kind == HDN_RAP_FRAME_NMI &&
	    (ip != regs->ip || expected.flags != regs->flags))
		goto out;
	memcpy(regs, &expected, sizeof(expected));
	commit_fixup(context, frame, regs, &expected);
	error = 0;
out:
	native_local_irq_restore(flags);
	return error;
}
NOKPROBE_SYMBOL(hdn_rap_debug_update);

/* WARN resumes at the end of the original trap instruction. Decode it again
 * from the protected IP, never from the handler's candidate IP or length. */
void hdn_rap_bug_end(struct pt_regs *regs, u64 sequence, bool handled)
{
	struct rap_context *context;
	struct rap_async_frame *frame;
	struct pt_regs expected;
	unsigned long flags;
	s32 immediate;
	int type, length;

	if (!sequence)
		return;
	flags = native_local_irq_save();
	context = hdn_rap_context_for((unsigned long)regs);
	frame = fixup_frame(context, regs, X86_TRAP_UD);
	if (!frame || frame->sequence != sequence)
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	memcpy(&expected, frame->words, sizeof(expected));
	if (handled) {
		type = decode_bug(expected.ip, &immediate, &length);
		if ((type != BUG_UD2 && type != BUG_UD1_WARN &&
		     type != BUG_UDB && type != BUG_LOCK) || length <= 0 ||
		    length > MAX_INSN_SIZE || expected.ip > ULONG_MAX - length)
			__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
		expected.ip += length;
	}
	commit_fixup(context, frame, regs, &expected);
	native_local_irq_restore(flags);
}

static unsigned long *fixup_register(struct pt_regs *regs, int number)
{
	int offset = pt_regs_offset(regs, number);

	if (offset < 0 || offset > offsetof(struct pt_regs, di) ||
	    !IS_ALIGNED(offset, sizeof(unsigned long)))
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	return (void *)regs + offset;
}

/* The IBT probe may zero AX at its one fixed missing-ENDBR landing. Both
 * that probe and the existing warning policy clear only FRED's saved WFE bit;
 * neither authorizes a replacement instruction pointer or stack. */
void hdn_rap_cp_end(struct pt_regs *regs, u64 sequence, bool selftest)
{
	struct rap_context *context;
	struct rap_async_frame *frame;
	struct pt_regs expected;
	unsigned long flags;

	if (!sequence)
		return;
	flags = native_local_irq_save();
	context = hdn_rap_context_for((unsigned long)regs);
	frame = fixup_frame(context, regs, X86_TRAP_CP);
	if (!frame || frame->sequence != sequence)
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	memcpy(&expected, frame->words, sizeof(expected));
	if (selftest) {
#ifdef CONFIG_X86_KERNEL_IBT
		if (expected.ip != (unsigned long)&ibt_selftest_noendbr)
			__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
		expected.ax = 0;
#else
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
#endif
	}
	expected.fred_cs.wfe = 0;
	commit_fixup(context, frame, regs, &expected);
	native_local_irq_restore(flags);
}

/* Recompute control-state edits from the immutable exception-table entry and
 * the protected pre-fault frame. There is no general "accept new registers"
 * operation. Only zeropad's single decoded data-result register is variable.
 */
void hdn_rap_fixup_end(struct pt_regs *regs, u64 sequence, int trapnr, bool fixed)
{
	struct rap_context *context;
	struct rap_async_frame *frame;
	const struct exception_table_entry *entry;
	struct pt_regs expected;
	unsigned long flags;
	int type, reg, imm;

	if (!sequence)
		return;
	flags = native_local_irq_save();
	context = hdn_rap_context_for((unsigned long)regs);
	frame = fixup_frame(context, regs, trapnr);
	if (!frame || frame->sequence != sequence)
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	memcpy(&expected, frame->words, sizeof(expected));
	if (!fixed)
		goto compare;
	entry = search_exception_tables(expected.ip);
	if (!entry)
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	type = FIELD_GET(EX_DATA_TYPE_MASK, entry->data);
	reg = FIELD_GET(EX_DATA_REG_MASK, entry->data);
	imm = FIELD_GET(EX_DATA_IMM_MASK, entry->data);
	switch (type) {
	case EX_TYPE_DEFAULT:
	case EX_TYPE_DEFAULT_MCE_SAFE:
	case EX_TYPE_UACCESS:
	case EX_TYPE_CLEAR_FS:
	case EX_TYPE_FPU_RESTORE:
	case EX_TYPE_WRMSR:
		break;
	case EX_TYPE_FAULT:
	case EX_TYPE_FAULT_MCE_SAFE:
		expected.ax = trapnr;
		break;
	case EX_TYPE_FAULT_SGX:
		expected.ax = trapnr | SGX_ENCLS_FAULT_FLAG;
		break;
	case EX_TYPE_RDMSR:
	case EX_TYPE_RDMSR_SAFE:
		expected.ax = expected.dx = 0;
		if (type == EX_TYPE_RDMSR_SAFE)
			*fixup_register(&expected, reg) = -EIO;
		break;
	case EX_TYPE_WRMSR_SAFE:
		*fixup_register(&expected, reg) = -EIO;
		break;
	case EX_TYPE_POP_REG:
		if (expected.sp > ULONG_MAX - sizeof(long))
			__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
		expected.sp += sizeof(long);
		fallthrough;
	case EX_TYPE_IMM_REG:
		*fixup_register(&expected, reg) = (long)imm;
		break;
	case EX_TYPE_UCOPY_LEN:
		expected.cx = imm * expected.cx + *fixup_register(&expected, reg);
		break;
	case EX_TYPE_ZEROPAD: {
		struct insn insn;
		unsigned long next = (unsigned long)&entry->fixup + entry->fixup;
		unsigned long *result;
		unsigned long offset;

		if (next <= expected.ip || next - expected.ip > MAX_INSN_SIZE ||
		    insn_decode(&insn, (void *)expected.ip, next - expected.ip, INSN_MODE_KERN) ||
		    insn.length != next - expected.ip || insn.opcode.bytes[0] != 0x8b ||
		    insn.opnd_bytes != sizeof(long))
			__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
		result = insn_get_modrm_reg_ptr(&insn, &expected);
		offset = (unsigned long)result - (unsigned long)&expected;
		if (!result || offset > offsetof(struct pt_regs, di) ||
		    !IS_ALIGNED(offset, sizeof(long)) || offset == offsetof(struct pt_regs, r10) ||
		    offset == offsetof(struct pt_regs, r11))
			__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
		*result = READ_ONCE(*(unsigned long *)((void *)regs + offset));
		break;
	}
	case EX_TYPE_BPF: {
		unsigned int length = entry->fixup & 0xff;
		unsigned int offset = (entry->fixup >> 8) & 0xff;

		if (!length || length > MAX_INSN_SIZE || expected.ip + length < expected.ip)
			__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
		/* The BPF exception format encodes a pt_regs byte offset; 1
		 * explicitly means a store with no data-result register to clear. */
		if (offset != 1) {
			if (offset > offsetof(struct pt_regs, di) || !IS_ALIGNED(offset, sizeof(long)))
				__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
			*(unsigned long *)((void *)&expected + offset) = 0;
		}
		expected.ip += length;
		goto compare;
	}
	case EX_TYPE_ERETU:
		if (frame->kind != HDN_RAP_FRAME_FRED)
			__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
		expected.fred_ss.nmi = regs->fred_ss.nmi;
		break;
	default:
		/* MCE MSR failures never return; unknown fixups are not adapters. */
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	}
	if (entry->data & EX_FLAG_CLEAR_AX)
		expected.ax = 0;
	if (entry->data & EX_FLAG_CLEAR_DX)
		expected.dx = 0;
	expected.ip = (unsigned long)&entry->fixup + entry->fixup;
compare:
	commit_fixup(context, frame, regs, &expected);
	native_local_irq_restore(flags);
}

#ifdef CONFIG_KPROBES
/* Kprobe registration owns instruction decoding and executable slot creation.
 * Freeze that result before arming the breakpoint. The original address plus
 * executable slot is the identity, so aggregation can replace the kprobe
 * object without replacing instruction ownership. Writable kprobe fields never
 * supply a transfer destination. */
struct hdn_rap_probe {
	struct hdn_rap_probe *next;
	unsigned long pfn, address;
	enum hdn_rap_probe_op op;
	struct arch_specific_insn insn;
	bool error_entry;
};
static struct hdn_rap_probe *rap_probes __ro_after_init;
static DEFINE_RAW_SPINLOCK(rap_probes_lock);

static void probe_link_store(struct hdn_rap_probe *previous, struct hdn_rap_probe *next)
{
	unsigned long *word = previous ? (unsigned long *)&previous->next :
		(unsigned long *)&rap_probes;
	unsigned long pfn = previous ? previous->pfn : __pa_symbol(word) >> PAGE_SHIFT;

	hdn_pt_window_update(pfn, offset_in_page(word), (unsigned long)next, 0, HDN_PT_STORE);
}

int hdn_rap_probe_prepare(const struct kprobe *p, enum hdn_rap_probe_op op)
{
	struct hdn_rap_probe *probe, *other;
	unsigned long flags;
	int error;

	BUILD_BUG_ON(sizeof(*probe) > PAGE_SIZE);
	if (!hdn_pt_active() || !READ_ONCE(hdn_rap_async_required))
		return -EOPNOTSUPP;
	if (op > HDN_PROBE_LOOP || !p->ainsn.insn || !p->ainsn.size ||
	    p->ainsn.size >= MAX_INSN_SIZE || p->ainsn.boostable ||
	    p->ainsn.tp_len != p->ainsn.size + INT3_INSN_SIZE ||
	    READ_ONCE(p->ainsn.insn[p->ainsn.size]) != INT3_INSN_OPCODE)
		return -ENOEXEC;
	probe = __vmalloc_node_range(PAGE_SIZE, PAGE_SIZE, VMALLOC_START, VMALLOC_END,
		GFP_KERNEL | __GFP_ZERO, PAGE_KERNEL, VM_FLUSH_RESET_PERMS,
		NUMA_NO_NODE, __builtin_return_address(0));
	if (!probe)
		return -ENOMEM;
	error = hdn_execmem_claim_data(probe);
	if (error) {
		vfree(probe);
		return error;
	}
	probe->pfn = vmalloc_to_pfn(probe);
	probe->address = (unsigned long)p->addr;
	probe->op = op;
	probe->insn = p->ainsn;
	{
		unsigned long entry = hdn_rap_probe_entry(probe->address);

		/* This registration path may sleep. The exception path consumes
		 * only the sealed decision and never takes the whitelist mutex. */
		probe->error_entry = entry && within_error_injection_list(entry);
	}
	error = hdn_execmem_seal_data(probe);
	if (error)
		goto discard;
	raw_spin_lock_irqsave(&rap_probes_lock, flags);
	for (other = rap_probes; other; other = other->next)
		if (other->insn.insn == probe->insn.insn || other->address == probe->address) {
			error = -EEXIST;
			goto unlock;
		}
	probe_link_store(probe, rap_probes);
	smp_wmb();
	probe_link_store(NULL, probe);
unlock:
	raw_spin_unlock_irqrestore(&rap_probes_lock, flags);
	if (!error)
		return 0;
discard:
	if (!hdn_execmem_free(probe))
		panic("HDN RAP probe metadata retirement failed");
	return error;
}

void hdn_rap_probe_release(const struct kprobe *owner)
{
	struct hdn_rap_probe *probe, *previous = NULL;
	unsigned long flags;

	raw_spin_lock_irqsave(&rap_probes_lock, flags);
	for (probe = rap_probes; probe; previous = probe, probe = probe->next)
		if (probe->insn.insn == owner->ainsn.insn && probe->address == (unsigned long)owner->addr)
			break;
	if (probe)
		probe_link_store(previous, probe->next);
	raw_spin_unlock_irqrestore(&rap_probes_lock, flags);
	if (!probe)
		return;
	/* The owner has disarmed the breakpoint and drained its handlers. A
	 * copied instruction runs with IF clear until its second breakpoint;
	 * the CPU scheduling boundary also drains that in-flight interval. */
	hdn_rap_registry_synchronize();
	if (!hdn_execmem_free(probe))
		panic("HDN RAP probe metadata retirement failed");
}

static struct rap_async_frame *probe_frame(struct pt_regs *regs, int trapnr,
		struct rap_context **context, struct pt_regs *original)
{
	struct rap_async_frame *frame;

	if (!native_irqs_disabled_flags(native_save_fl()))
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	*context = hdn_rap_context_for((unsigned long)regs);
	frame = fixup_frame(*context, regs, trapnr);
	if (!frame)
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	memcpy(original, frame->words, sizeof(*original));
	if (memcmp(regs, original, sizeof(*original)))
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	return frame;
}

static unsigned long *probe_stack_word(struct pt_regs *regs, bool push)
{
	unsigned long address = push ? regs->sp - sizeof(long) : regs->sp;
	struct rap_context *stack = hdn_rap_context_for(address);

	if (!stack || !IS_ALIGNED(address, sizeof(long)) ||
	    address > stack->end - sizeof(long) || (push && address >= regs->sp) ||
	    (stack->owner ? !hdn_stack_mm_active(stack->owner, address) :
			   stack->cpu != hdn_pt_cpu()))
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	return (unsigned long *)address;
}

#ifdef CONFIG_FUNCTION_ERROR_INJECTION
void hdn_rap_probe_override(struct pt_regs *regs)
{
	extern void just_return_func(void);
	struct rap_context *context, *stack;
	struct rap_async_frame *frame;
	struct rap_record *record;
	const struct hdn_rap_probe *probe;
	struct pt_regs expected, observed;
	unsigned long top, flags = native_local_irq_save();

	context = hdn_rap_context_for((unsigned long)regs);
	frame = fixup_frame(context, regs, X86_TRAP_BP);
	if (!frame)
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	memcpy(&expected, frame->words, sizeof(expected));
	observed = *regs;
	/* The existing fault-injection APIs supply AX. All other registers
	 * must still match the protected hardware snapshot. */
	observed.ax = expected.ax;
	if (memcmp(&observed, &expected, sizeof(expected)))
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	if (frame->probe_override && expected.ip != (unsigned long)just_return_func)
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	for (probe = READ_ONCE(rap_probes); probe; probe = READ_ONCE(probe->next))
		if (probe->address + INT3_INSN_SIZE == (frame->probe_override ?: expected.ip))
			break;
	if (!probe || !probe->error_entry)
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	stack = hdn_rap_context_for(expected.sp);
	(void)probe_stack_word(&expected, false);
	top = stack == context ? frame->return_top : stack->top;
	if (!top || top > RAP_FRAMES || top > stack->top)
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	record = &stack->records[top - 1];
	if (record->slot != expected.sp || !record->sequence || record->sequence > stack->sequence ||
	    (record->hooks & RAP_HOOK_ENTERED) ||
	    READ_ONCE(*(unsigned long *)record->slot) != hdn_rap_record_target(stack, record))
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	/* Handler calls still sit above this record. Leave it in place until
	 * IRET; the fixed epilogue then consumes it, including registered hooks. */
	if (!frame->probe_override)
		hdn_rap_context_store(context, &frame->probe_override, expected.ip);
	expected.ax = regs->ax;
	expected.ip = (unsigned long)just_return_func;
	regs->ip = expected.ip;
	commit_fixup(context, frame, regs, &expected);
	native_local_irq_restore(flags);
}
NOKPROBE_SYMBOL(hdn_rap_probe_override);
#endif

bool hdn_rap_probe_start(struct pt_regs *regs, const struct kprobe *owner)
{
	struct rap_context *context;
	struct rap_async_frame *frame;
	const struct hdn_rap_probe *probe;
	struct pt_regs expected;
	unsigned long next, target, *word;
	bool matched;

	frame = probe_frame(regs, X86_TRAP_BP, &context, &expected);
	for (probe = READ_ONCE(rap_probes); probe; probe = READ_ONCE(probe->next))
		if (probe->address + INT3_INSN_SIZE == expected.ip)
			break;
	if (!probe || probe->insn.insn != owner->ainsn.insn ||
	    probe->address != (unsigned long)owner->addr)
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	next = probe->address + probe->insn.size;
	target = next + probe->insn.rel32;
	expected.ip = next;
	switch (probe->op) {
	case HDN_PROBE_STEP: {
		struct rap_probe_step *step;
		unsigned long sequence = context->sequence + 1;

		if (context->probe_top >= RAP_PROBE_STEPS || !sequence)
			__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
		step = &context->probe_steps[context->probe_top];
		hdn_rap_context_store(context, (unsigned long *)&step->probe, (unsigned long)probe);
		hdn_rap_context_store(context, &step->flags, expected.flags & X86_EFLAGS_IF);
		hdn_rap_context_store(context, &step->async_top, context->async_top - 1);
		hdn_rap_context_store(context, (unsigned long *)&step->sequence, sequence);
		hdn_rap_context_store(context, &context->probe_top, context->probe_top + 1);
		expected.flags &= ~X86_EFLAGS_IF;
		expected.ip = (unsigned long)probe->insn.insn;
		break;
	}
	case HDN_PROBE_CALL:
		/* Compiler/assembly call binding remains the original site even
		 * when the call instruction is emulated at its breakpoint. */
		if (expected.r10 != next || !hdn_rap_return_site(next))
			__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
		word = probe_stack_word(&expected, true);
		if ((unsigned long)word >= (unsigned long)regs &&
		    (unsigned long)word < (unsigned long)(regs + 1))
			__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
		WRITE_ONCE(*word, next);
		expected.sp = (unsigned long)word;
		fallthrough;
	case HDN_PROBE_JUMP:
		expected.ip = target;
		break;
	case HDN_PROBE_COND:
		if (__emulate_cc(expected.flags, probe->insn.jcc.type))
			expected.ip = target;
		break;
	case HDN_PROBE_LOOP:
		if (probe->insn.loop.asize != 32 && probe->insn.loop.asize != 64)
			__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
		if (probe->insn.loop.type == 3) {
			matched = probe->insn.loop.asize == 32 ? !(u32)expected.cx : !expected.cx;
		} else {
			if (probe->insn.loop.asize == 32)
				expected.cx = (u32)(expected.cx - 1);
			else
				expected.cx--;
			matched = expected.cx != 0;
			if (probe->insn.loop.type == 0)
				matched &= !(expected.flags & X86_EFLAGS_ZF);
			else if (probe->insn.loop.type == 1)
				matched &= !!(expected.flags & X86_EFLAGS_ZF);
		}
		if (matched)
			expected.ip = target;
		break;
	case HDN_PROBE_FLAGS:
		switch (probe->insn.opcode) {
		case 0xfa: expected.flags &= ~X86_EFLAGS_IF; break;
		case 0xfb: expected.flags |= X86_EFLAGS_IF; break;
		case 0x9c:
			word = probe_stack_word(&expected, true);
			WRITE_ONCE(*word, expected.flags & ~(X86_EFLAGS_RF | X86_EFLAGS_VM));
			expected.sp = (unsigned long)word;
			break;
		case 0x9d:
			word = probe_stack_word(&expected, false);
			expected.flags = READ_ONCE(*word);
			expected.sp += sizeof(long);
			break;
		default: __hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
		}
		break;
	default:
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	}
	memcpy(regs, &expected, sizeof(expected));
	commit_fixup(context, frame, regs, &expected);
	return probe->op != HDN_PROBE_STEP;
}

bool hdn_rap_probe_complete(struct pt_regs *regs, const struct kprobe *owner,
		bool fault, int trapnr)
{
	struct rap_context *context;
	struct rap_async_frame *frame;
	struct rap_probe_step *step;
	const struct hdn_rap_probe *probe;
	struct pt_regs expected;
	unsigned long ip;

	frame = probe_frame(regs, trapnr, &context, &expected);
	if (!context->probe_top)
		return false;
	if (context->probe_top > RAP_PROBE_STEPS)
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	step = &context->probe_steps[context->probe_top - 1];
	probe = step->probe;
	if (!probe || !step->sequence || step->sequence > context->sequence)
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	ip = (unsigned long)probe->insn.insn + (fault ? 0 : probe->insn.size + INT3_INSN_SIZE);
	if (expected.ip != ip)
		return false;
	if (!owner || probe->insn.insn != owner->ainsn.insn ||
	    probe->address != (unsigned long)owner->addr ||
	    step->async_top + 1 != context->async_top)
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	expected.ip = probe->address + (fault ? 0 : probe->insn.size);
	expected.flags = (expected.flags & ~X86_EFLAGS_IF) | step->flags;
	hdn_rap_context_store(context, (unsigned long *)&step->sequence, 0);
	hdn_rap_context_store(context, (unsigned long *)&step->probe, 0);
	hdn_rap_context_store(context, &context->probe_top, context->probe_top - 1);
	memcpy(regs, &expected, sizeof(expected));
	commit_fixup(context, frame, regs, &expected);
	return true;
}
NOKPROBE_SYMBOL(probe_frame);
NOKPROBE_SYMBOL(probe_stack_word);
NOKPROBE_SYMBOL(hdn_rap_probe_start);
NOKPROBE_SYMBOL(hdn_rap_probe_complete);
#endif /* CONFIG_KPROBES */

static void store_bucket(unsigned int bucket, struct rap_link *value)
{
	unsigned long address = (unsigned long)&hdn_rap_buckets[bucket];

	if (!READ_ONCE(hdn_rap_private_updates)) {
		WRITE_ONCE(hdn_rap_buckets[bucket], value);
		return;
	}
	hdn_pt_window_update(__pa_symbol(&hdn_rap_buckets[bucket]) >> PAGE_SHIFT,
		offset_in_page(address), (unsigned long)value, 0, HDN_PT_STORE);
}

static void retire_context(struct work_struct *work)
{
	struct rap_lifetime *life = container_of(to_rcu_work(work), struct rap_lifetime, retire);
	struct rap_context *context = life->context;

	if (context->lifetime != life || !hdn_execmem_free(context))
		panic("HDN RAP return context retirement mismatch");
	kfree(life);
}

/* The caller has a newly allocated, unpublished stack or an unused permanent
 * CPU stack. Its virtual range is the identity; live records never move when
 * a task migrates. Private-stack views retain that identity on every CPU. */
static int create_context(const struct task_struct *owner, unsigned long base,
		size_t size, int node, enum rap_domain domain, unsigned int cpu)
{
	struct rap_context *context;
	struct rap_lifetime *life;
	unsigned long flags;
	unsigned int i, pages = size >> PAGE_SHIFT;
	gfp_t allocation_flags = GFP_KERNEL | __GFP_ZERO | (owner ? __GFP_ACCOUNT : 0);
	int error;

	BUILD_BUG_ON(sizeof(*context) > RAP_STORAGE_PAGES * PAGE_SIZE);
	if (!IS_ALIGNED(base, PAGE_SIZE) || !IS_ALIGNED(size, PAGE_SIZE) ||
	    !size || size > THREAD_SIZE || base + size < base)
		return -EINVAL;
	life = kmalloc_typed(struct rap_lifetime, sizeof(*life), allocation_flags);
	if (!life)
		return -ENOMEM;
	context = __vmalloc_node_range(PAGE_ALIGN(sizeof(*context)), PAGE_SIZE,
		VMALLOC_START, VMALLOC_END, allocation_flags, PAGE_KERNEL,
		VM_FLUSH_RESET_PERMS, node, __builtin_return_address(0));
	if (!context) {
		kfree(life);
		return -ENOMEM;
	}
	error = hdn_execmem_claim_data(context);
	if (error) {
		vfree(context);
		kfree(life);
		return error;
	}
	context->owner = owner;
	context->domain = domain;
	context->cpu = cpu;
	context->begin = base;
	context->end = base + size;
	context->lifetime = life;
	life->context = context;
	INIT_RCU_WORK(&life->retire, retire_context);
	for (i = 0; i < DIV_ROUND_UP(sizeof(*context), PAGE_SIZE); i++)
		context->pfns[i] = vmalloc_to_pfn((void *)context + i * PAGE_SIZE);
	for (i = 0; i < pages; i++)
		context->links[i].context = context;
	if (hdn_rap_private_updates) {
		error = hdn_execmem_seal_data(context);
		if (error)
			goto discard;
	}
	raw_spin_lock_irqsave(&registry_lock, flags);
	for (i = 0; i < pages; i++)
		if (hdn_rap_context_for(base + i * PAGE_SIZE)) {
			error = -EEXIST;
			goto unlock;
		}
	for (i = 0; i < pages; i++) {
		unsigned int bucket = bucket_for(base + i * PAGE_SIZE);

		hdn_rap_context_store(context, (unsigned long *)&context->links[i].next,
			(unsigned long)hdn_rap_buckets[bucket]);
		/* All immutable geometry precedes publication to asynchronous readers. */
		smp_wmb();
		store_bucket(bucket, &context->links[i]);
	}
unlock:
	raw_spin_unlock_irqrestore(&registry_lock, flags);
	if (!error)
		return 0;
discard:
	if (!hdn_execmem_free(context))
		panic("HDN RAP unpublished context retirement failed");
	kfree(life);
	return error;
}

int hdn_rap_task_prepare(struct task_struct *task, int node)
{
	return create_context(task, (unsigned long)task->stack, THREAD_SIZE, node, RAP_TASK, NR_CPUS);
}

int __init hdn_rap_boot_stack_prepare(unsigned long base, int node)
{
	if (current != &init_task || num_online_cpus() != 1 || !hdn_rap_private_updates)
		return -EPERM;
	return create_context(&init_task, base, THREAD_SIZE, node, RAP_TASK, NR_CPUS);
}

void __init hdn_rap_failure_init(void)
{
#ifdef CONFIG_SECURITY_HARDENING_PRIVATE_STACKS
	unsigned int cpu;

	for_each_possible_cpu(cpu) {
		struct hdn_rap_failure_cpu *failure = &hdn_rap_failure_cpus[cpu];
		unsigned long begin, cr3;

		if (hdn_stack_failure_create(cpu, &begin, &cr3) ||
		    create_context(NULL, begin, THREAD_SIZE, cpu_to_node(cpu), RAP_FAILURE, cpu))
			panic("HDN could not allocate a protected failure domain");
		failure->context = hdn_rap_context_for(begin);
		failure->gsbase = cpu_kernelmode_gs_base(cpu);
		failure->sp = begin + THREAD_SIZE;
		failure->begin = begin;
		failure->gdt.address = (unsigned long)get_cpu_gdt_ro(cpu);
		failure->gdt.size = GDT_SIZE - 1;
		/* The no-stack assembly entry treats zero CR3 as unavailable. */
		smp_wmb();
		WRITE_ONCE(failure->cr3, cr3);
	}
	WRITE_ONCE(hdn_rap_failure_ready, true);
#endif
}

const char *hdn_rap_state(void)
{
	return hdn_pt_active() && READ_ONCE(hdn_rap_private_updates) &&
		READ_ONCE(hdn_rap_async_required) && READ_ONCE(hdn_rap_failure_ready) ?
		"active" : "initializing";
}

void __noreturn hdn_rap_failure_report(unsigned long kind)
{
	if (kind < HDN_RAP_FAIL_TARGET || kind > HDN_RAP_FAIL_WINDOW)
		kind = HDN_RAP_FAIL_WINDOW;
	hdn_report_control_flow_failure(kind);
	pr_emerg("HDN_RAP_DENIED class=%lu build=%s\n", kind,
		 hdn_rap_build_identity());
	panic("HDN control-flow violation (class %lu)", kind);
}

int hdn_rap_cpu_stack_prepare(unsigned long base, size_t size, int node, unsigned int cpu)
{
	return create_context(NULL, base, size, node, RAP_IRQ, cpu);
}

void __init hdn_rap_cpu_contexts_init(void)
{
	unsigned int cpu;

	for_each_possible_cpu(cpu) {
		struct cpu_entry_area *cea = get_cpu_entry_area(cpu);
		unsigned long starts[] = {
			CEA_ESTACK_BOT(&cea->estacks, DF), CEA_ESTACK_BOT(&cea->estacks, NMI),
			CEA_ESTACK_BOT(&cea->estacks, DB), CEA_ESTACK_BOT(&cea->estacks, MCE),
		};
		unsigned int i;

		hdn_rap_entry_stack_top[cpu] = (unsigned long)(&cea->entry_stack_page.stack + 1);
		if (cpu == 0) /* Registered before the boot CPU installs its TSS. */
			continue;

		if (create_context(NULL, (unsigned long)&cea->entry_stack_page.stack,
			   sizeof(cea->entry_stack_page.stack), cpu_to_node(cpu), RAP_ENTRY, cpu))
			panic("HDN RAP could not allocate an entry return context");
		for (i = 0; i < ARRAY_SIZE(starts); i++)
			if (create_context(NULL, starts[i], EXCEPTION_STKSZ, cpu_to_node(cpu),
					   i ? RAP_EXCEPTION : RAP_DF, cpu))
				panic("HDN RAP could not allocate an exception return context");
	}
	WRITE_ONCE(hdn_rap_async_required, true);
}

void __init hdn_rap_boot_contexts_init(void)
{
	struct cpu_entry_area *cea = get_cpu_entry_area(0);
	unsigned long starts[] = {
		(unsigned long)&cea->entry_stack_page.stack,
		CEA_ESTACK_BOT(&cea->estacks, DF), CEA_ESTACK_BOT(&cea->estacks, NMI),
		CEA_ESTACK_BOT(&cea->estacks, DB), CEA_ESTACK_BOT(&cea->estacks, MCE),
	};
	unsigned int i, page;

	BUILD_BUG_ON(ARRAY_SIZE(starts) != ARRAY_SIZE(boot_exception_contexts));
	hdn_rap_entry_stack_top[0] = (unsigned long)(&cea->entry_stack_page.stack + 1);
	for (i = 0; i < ARRAY_SIZE(starts); i++) {
		struct rap_context *context = &boot_exception_contexts[i].context;
		size_t size = i ? EXCEPTION_STKSZ : sizeof(cea->entry_stack_page.stack);

		if (context->begin || !IS_ALIGNED(starts[i], PAGE_SIZE) || size > THREAD_SIZE)
			panic("HDN RAP invalid boot exception context");
		context->begin = starts[i];
		context->end = starts[i] + size;
		context->domain = !i ? RAP_ENTRY : i == 1 ? RAP_DF : RAP_EXCEPTION;
		context->cpu = 0;
		for (page = 0; page < DIV_ROUND_UP(sizeof(*context), PAGE_SIZE); page++)
			context->pfns[page] = (__pa_symbol(context) >> PAGE_SHIFT) + page;
		for (page = 0; page < size / PAGE_SIZE; page++) {
			unsigned int bucket = bucket_for(starts[i] + page * PAGE_SIZE);

			context->links[page].context = context;
			context->links[page].next = hdn_rap_buckets[bucket];
			smp_wmb();
			WRITE_ONCE(hdn_rap_buckets[bucket], &context->links[page]);
		}
	}
}
void hdn_rap_task_release(struct task_struct *task)
{
	struct rap_context *context;
	struct rap_lifetime *life;
	unsigned long flags;
	unsigned int i, pages;

	raw_spin_lock_irqsave(&registry_lock, flags);
	context = hdn_rap_context_for((unsigned long)task->stack);
	/* Allocation failure may precede context construction. */
	if (!context) {
		raw_spin_unlock_irqrestore(&registry_lock, flags);
		return;
	}
	if (context == &hdn_rap_boot_context || context->owner != task || context->begin != (unsigned long)task->stack)
		panic("HDN RAP stack lifetime substitution");
	pages = (context->end - context->begin) >> PAGE_SHIFT;
	for (i = 0; i < pages; i++) {
		unsigned int bucket = bucket_for(context->begin + i * PAGE_SIZE);
		struct rap_link *link = hdn_rap_buckets[bucket], *previous = NULL;

		while (link && link != &context->links[i]) {
			previous = link;
			link = link->next;
		}
		if (!link)
			panic("HDN RAP missing stack lifetime link");
		if (previous)
			hdn_rap_context_store(previous->context, (unsigned long *)&previous->next, (unsigned long)link->next);
		else
			store_bucket(bucket, link->next);
	}
	life = context->lifetime;
	raw_spin_unlock_irqrestore(&registry_lock, flags);
	/* The existing task stack reference count has already excluded unwinding
	 * and other observers. RCU additionally protects a concurrent registry walk. */
	if (!queue_rcu_work(system_unbound_wq, &life->retire))
		panic("HDN RAP stack context retired twice");
}

#ifdef CONFIG_EFI
struct rap_context hdn_rap_efi_context __aligned(PAGE_SIZE) __ro_after_init;

void __init hdn_rap_efi_context_init(unsigned long base, unsigned long size)
{
	struct rap_context *context = &hdn_rap_efi_context;
	unsigned int page;

	if (context->begin || !IS_ALIGNED(base, PAGE_SIZE) || size != THREAD_SIZE ||
	    base >= (1UL << 32) || size > (1UL << 32) - base)
		panic("HDN invalid EFI stack registration");
	context->begin = base;
	context->end = base + size;
	context->domain = RAP_FIRMWARE;
	context->cpu = NR_CPUS; /* Bound dynamically by the protected EFI checkpoint. */
	for (page = 0; page < DIV_ROUND_UP(sizeof(*context), PAGE_SIZE); page++)
		context->pfns[page] = (__pa_symbol(context) >> PAGE_SHIFT) + page;
	for (page = 0; page < size / PAGE_SIZE; page++) {
		unsigned int bucket = bucket_for(base + page * PAGE_SIZE);

		if (hdn_rap_context_for(base + page * PAGE_SIZE))
			panic("HDN EFI stack identity overlaps another stack");
		context->links[page].context = context;
		context->links[page].next = hdn_rap_buckets[bucket];
		WRITE_ONCE(hdn_rap_buckets[bucket], &context->links[page]);
	}
}
#endif

void __init hdn_rap_context_seal(void)
{
	unsigned int i;

	if (!hdn_pt_active())
		panic("HDN RAP requires active private update windows");
#ifdef CONFIG_EFI
	hdn_efi_mixed_seal();
#endif
	for (i = 0; i < DIV_ROUND_UP(sizeof(hdn_rap_boot_context), PAGE_SIZE); i++)
		hdn_rap_boot_context.pfns[i] = (__pa_symbol(&hdn_rap_boot_context) >> PAGE_SHIFT) + i;
	/* Use private writes before sealing the first live context. An IRQ can
	 * interrupt the sealing walk, so there is no mixed writable/sealed mode. */
	WRITE_ONCE(hdn_rap_private_updates, true);
	for (i = 0; i < RAP_BUCKETS; i++) {
		struct rap_link *link;

		for (link = hdn_rap_buckets[i]; link; link = link->next)
			if (link->context->lifetime && link == &link->context->links[0] &&
			    hdn_execmem_seal_data(link->context))
				panic("HDN RAP could not seal a boot return context");
	}
}
