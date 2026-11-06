// SPDX-License-Identifier: GPL-2.0-only
/* Exact firmware entry admission and a protected native-call checkpoint.
 * Firmware executes at kernel privilege: its implementation is a trusted ABI
 * boundary. This protects the kernel's entry selection and continuation from
 * writable kernel metadata; it is not a sandbox for hostile firmware.
 */
#include <linux/efi.h>
#include <linux/hdn_rap.h>
#include <linux/sched.h>
#include <asm/efi.h>
#include <asm/hdn_rap_efi.h>
#include <asm/hdn_stack_mm.h>
#include <asm/irqflags.h>
#include <asm/special_insns.h>
#include <asm/traps.h>
#include "hdn_rap_context_internal.h"
#include "../mm/hdn_pgtable_internal.h"

static_assert(sizeof(struct hdn_efi_frame) == 128);
static_assert(offsetof(struct hdn_efi_frame, r15) == HDN_EFI_R15);
static_assert(offsetof(struct hdn_efi_frame, flags) == HDN_EFI_FLAGS);
static_assert(offsetof(struct hdn_efi_frame, return_address) == HDN_EFI_SP);
static_assert(offsetof(struct hdn_efi_state, gs) == HDN_EFI_GS);
static_assert(offsetof(struct hdn_efi_state, target) == HDN_EFI_TARGET);

#define EFI_ENDPOINTS 256
static struct {
	unsigned long service, address;
} endpoints[EFI_ENDPOINTS] __ro_after_init;
static unsigned int endpoint_count __ro_after_init;
static struct {
	unsigned long address, pages;
} code_ranges[EFI_ENDPOINTS] __ro_after_init;
static unsigned int code_range_count __ro_after_init;
struct hdn_efi_state hdn_efi_state __ro_after_init;

static bool __init firmware_code(unsigned long address, bool physical)
{
	efi_memory_desc_t *md;

	for_each_efi_memory_desc(md) {
		u64 start = physical ? md->phys_addr : md->virt_addr;
		u64 pages;

		if (!(md->attribute & EFI_MEMORY_RUNTIME) ||
		    md->type != EFI_RUNTIME_SERVICES_CODE || !start || address < start)
			continue;
		pages = (address - start) >> EFI_PAGE_SHIFT;
		if (pages < md->num_pages)
			return true;
	}
	return false;
}

int __init hdn_efi_register(unsigned long service, unsigned long target, bool physical)
{
	unsigned int i;

	if (!target || !firmware_code(target, physical))
		return -EINVAL;
	for (i = 0; i < endpoint_count; i++)
		if (endpoints[i].service == service && endpoints[i].address == target)
			return 0;
	if (endpoint_count == EFI_ENDPOINTS)
		return -ENOSPC;
	endpoints[endpoint_count].service = service;
	endpoints[endpoint_count++].address = target;
	return 0;
}

/* Caller has entered efi_mm: the runtime table is not necessarily visible in
 * the kernel's ordinary address space. SVAM permission is withdrawn before
 * the final virtual table is admitted. No post-init registration API exists. */
int __init hdn_efi_register_runtime(bool physical)
{
	int error = 0;
	unsigned int i, out = 0;
	efi_memory_desc_t *md;

	code_range_count = 0;
	for_each_efi_memory_desc(md) {
		unsigned long address = physical || efi_is_mixed() ? md->phys_addr : md->virt_addr;

		if (!address || !(md->attribute & EFI_MEMORY_RUNTIME) ||
		    md->type != EFI_RUNTIME_SERVICES_CODE || !md->num_pages)
			continue;
		if (code_range_count == ARRAY_SIZE(code_ranges))
			return -ENOSPC;
		code_ranges[code_range_count].address = address;
		code_ranges[code_range_count++].pages = md->num_pages;
	}
	if (!physical) {
		for (i = 0; i < endpoint_count; i++)
			if (endpoints[i].service != offsetof(efi_runtime_services_t, set_virtual_address_map))
				endpoints[out++] = endpoints[i];
		endpoint_count = out;
	}
#define ADMIT(member) do { \
	unsigned long target = efi_is_mixed() ? READ_ONCE(efi.runtime->mixed_mode.member) : \
		(unsigned long)READ_ONCE(efi.runtime->member); \
	if (target) { \
		error = hdn_efi_register(offsetof(efi_runtime_services_t, member), target, \
					 physical || efi_is_mixed()); \
		if (error) return error; \
	} \
} while (0)
	if (physical) {
		ADMIT(set_virtual_address_map);
		return 0;
	}
	ADMIT(get_time);
	ADMIT(set_time);
	ADMIT(get_wakeup_time);
	ADMIT(set_wakeup_time);
	ADMIT(get_variable);
	ADMIT(get_next_variable);
	ADMIT(set_variable);
	ADMIT(get_next_high_mono_count);
	ADMIT(reset_system);
	ADMIT(update_capsule);
	ADMIT(query_capsule_caps);
	ADMIT(query_variable_info);
#undef ADMIT
	return 0;
}

static void noinstr state_store(unsigned long *word, unsigned long value)
{
	unsigned long address = (unsigned long)word;

	if (address < (unsigned long)&hdn_efi_state ||
	    address - (unsigned long)&hdn_efi_state > sizeof(hdn_efi_state) - sizeof(long) ||
	    !IS_ALIGNED(address, sizeof(long)))
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	if (!hdn_rap_private_updates) {
		WRITE_ONCE(*word, value);
		return;
	}
	hdn_pt_window_update(__pa_symbol(word) >> PAGE_SHIFT, offset_in_page(word),
			    value, 0, HDN_PT_STORE);
}

const struct hdn_efi_state *noinstr hdn_efi_enter(unsigned long service,
		unsigned long target, const struct hdn_efi_frame *frame, bool mixed)
{
	unsigned long slot = (unsigned long)&frame->return_address;
	struct rap_context *context = hdn_rap_context_for(slot);
	const struct rap_record *record;
	unsigned int i;

	if (!native_irqs_disabled_flags(native_save_fl()) || hdn_efi_state.live ||
	    !context || (unsigned long)frame < context->begin ||
	    !context->top || context->top > RAP_FRAMES ||
	    (context->owner ?
#ifdef CONFIG_SECURITY_HARDENING_PRIVATE_STACKS
	     !hdn_stack_mm_active(context->owner, slot) :
#else
	     context->owner != current :
#endif
	     context->cpu != hdn_pt_cpu()))
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	record = &context->records[context->top - 1];
	if (record->slot != slot || !record->sequence || record->hooks ||
	    frame->return_address != hdn_rap_record_target(context, record))
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	for (i = 0; i < endpoint_count; i++)
		if (endpoints[i].service == service && endpoints[i].address == target)
			break;
	if (i == endpoint_count)
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	if (mixed && (target > U32_MAX || !hdn_rap_efi_context.begin ||
	    hdn_rap_efi_context.top || hdn_rap_efi_context.async_top))
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	/* Even corruption of the ordinary serialization lock cannot admit two
	 * CPUs to the protected checkpoint. 1 is construction, 2 is firmware,
	 * and 3 is an authenticated fault return in progress. */
	if (hdn_rap_private_updates ?
	    hdn_pt_window_update(__pa_symbol(&hdn_efi_state.live) >> PAGE_SHIFT,
				offset_in_page(&hdn_efi_state.live), 1, 0, HDN_PT_COMPARE_EXCHANGE) :
	    cmpxchg(&hdn_efi_state.live, 0, 1))
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	/* The frame prefix is deliberately identical, up to the return slot. */
	for (i = 0; i < offsetof(struct hdn_efi_frame, return_address) / sizeof(long); i++)
		state_store((unsigned long *)&hdn_efi_state + i, ((const unsigned long *)frame)[i]);
	state_store(&hdn_efi_state.sp, slot);
	state_store(&hdn_efi_state.target, target);
	state_store(&hdn_efi_state.gs, __rdmsr(MSR_GS_BASE));
	state_store(&hdn_efi_state.cr3, __native_read_cr3());
	state_store(&hdn_efi_state.cr0, native_read_cr0());
	state_store(&hdn_efi_state.cr4, native_read_cr4());
	state_store(&hdn_efi_state.cpu, hdn_pt_cpu());
	state_store(&hdn_efi_state.owner, (unsigned long)current);
	state_store(&hdn_efi_state.context, (unsigned long)context);
	state_store(&hdn_efi_state.top, context->top);
	state_store(&hdn_efi_state.async_top, context->async_top);
	state_store(&hdn_efi_state.sequence, record->sequence);
	state_store(&hdn_efi_state.mixed, mixed);
	state_store(&hdn_efi_state.live, 2);
	return &hdn_efi_state;
}

void noinstr hdn_efi_finish(void)
{
	struct rap_context *context = (void *)hdn_efi_state.context;
	const struct rap_record *record;

	if (!native_irqs_disabled_flags(native_save_fl()) ||
	    (hdn_efi_state.live != 2 && hdn_efi_state.live != 3) ||
	    hdn_efi_state.cpu != hdn_pt_cpu() || hdn_efi_state.owner != (unsigned long)current ||
	    hdn_efi_state.cr3 != __native_read_cr3() ||
	    hdn_efi_state.cr0 != native_read_cr0() || hdn_efi_state.cr4 != native_read_cr4() ||
	    !context || context->top != hdn_efi_state.top ||
	    context->async_top != hdn_efi_state.async_top)
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	if (hdn_efi_state.mixed && (hdn_rap_efi_context.top || hdn_rap_efi_context.async_top))
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	record = &context->records[context->top - 1];
	if (record->sequence != hdn_efi_state.sequence || record->slot != hdn_efi_state.sp ||
	    READ_ONCE(*(unsigned long *)record->slot) != hdn_rap_record_target(context, record))
		__hdn_rap_fail(HDN_RAP_FAIL_RETURN);
	state_store(&hdn_efi_state.live, 0);
}

/* Redirect only the authenticated #PF frame caused inside admitted firmware.
 * The normal exception exit unwinds all kernel bookkeeping before the fixed
 * return gate resumes on the original high stack. No handler frames are
 * discarded, and a mixed-mode fault never schedules on its temporary stack. */
bool noinstr hdn_efi_fault_fixup(struct pt_regs *regs)
{
	extern void __hdn_efi_fault_return(void);
	struct rap_context *context;
	struct rap_async_frame *frame;
	unsigned long flags = native_local_irq_save();
	unsigned int i;
	u64 sequence;
	bool fixed = false;

	if (hdn_efi_state.live != 2 || hdn_efi_state.cpu != hdn_pt_cpu() ||
	    hdn_efi_state.owner != (unsigned long)current)
		goto out;
	context = hdn_rap_context_for((unsigned long)regs);
	if (!context || !context->async_top || context->async_top > RAP_ASYNC_FRAMES)
		goto out;
	frame = &context->async[context->async_top - 1];
	if (frame->slot != (unsigned long)regs || frame->vector != X86_TRAP_PF || frame->user ||
	    frame->kind == HDN_RAP_FRAME_NMI || frame->kind == HDN_RAP_FRAME_FRED_SYNTH ||
	    !frame->sequence || regs->cs != (hdn_efi_state.mixed ? __KERNEL32_CS : __KERNEL_CS))
		goto out;
	for (i = 0; i < code_range_count; i++)
		if (regs->ip >= code_ranges[i].address &&
		    ((regs->ip - code_ranges[i].address) >> EFI_PAGE_SHIFT) < code_ranges[i].pages)
			break;
	if (i == code_range_count)
		goto out;
	for (i = 0; i < RAP_REG_WORDS; i++)
		if (READ_ONCE(((unsigned long *)regs)[i]) != frame->words[i])
			__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	sequence = context->sequence + 1;
	if (!sequence)
		__hdn_rap_fail(HDN_RAP_FAIL_ASYNC);
	regs->ip = (unsigned long)__hdn_efi_fault_return;
	regs->cs = __KERNEL_CS;
	regs->ss = __KERNEL_DS;
	regs->flags &= ~(X86_EFLAGS_IF | X86_EFLAGS_DF | X86_EFLAGS_TF | X86_EFLAGS_AC);
	if (frame->kind == HDN_RAP_FRAME_FRED) {
		regs->fred_ss.l = 1;
		regs->fred_ss.sti = 0;
		regs->fred_cs.wfe = 0;
	}
	for (i = 0; i < RAP_REG_WORDS; i++)
		hdn_rap_context_store(context, &frame->words[i], ((unsigned long *)regs)[i]);
	hdn_rap_context_store(context, (unsigned long *)&frame->sequence, sequence);
	hdn_rap_context_store(context, (unsigned long *)&context->sequence, sequence);
	state_store(&hdn_efi_state.live, 3);
	fixed = true;
out:
	native_local_irq_restore(flags);
	return fixed;
}

bool noinstr hdn_efi_stack_active(unsigned long address)
{
	return (hdn_efi_state.live == 2 || hdn_efi_state.live == 3) && hdn_efi_state.mixed &&
		hdn_efi_state.cpu == hdn_pt_cpu() && hdn_efi_state.owner == (unsigned long)current &&
		address >= hdn_rap_efi_context.begin && address < hdn_rap_efi_context.end;
}

bool noinstr hdn_efi_stack_info(unsigned long address, unsigned long *begin,
		unsigned long *end, unsigned long *next)
{
	if (!hdn_efi_stack_active(address))
		return false;
	*begin = hdn_rap_efi_context.begin;
	*end = hdn_rap_efi_context.end;
	*next = hdn_efi_state.sp;
	return true;
}
