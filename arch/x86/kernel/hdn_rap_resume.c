// SPDX-License-Identifier: GPL-2.0-only
/* Closed nonlocal suspend/hibernate transitions. No allocation or ordinary C. */
#include <linux/hdn_rap.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <asm/hdn_rap_resume.h>
#include <asm/hdn_stack_mm.h>
#include <asm/irqflags.h>
#include <asm/special_insns.h>
#include <asm/sections.h>
#include <asm/tlbflush.h>
#include "hdn_rap_context_internal.h"
#include "../mm/hdn_pgtable_internal.h"

extern struct saved_context saved_context;
u32 hdn_rap_pm_msr_ids[HDN_RAP_PM_MSRS] __ro_after_init;
unsigned long hdn_rap_pm_msr_count __ro_after_init;

/* The system sleep core serializes these operations with the other CPUs
 * offline. The active task and hardware CPU identity are checked separately;
 * this is not an arbitrary setjmp/longjmp API. */
struct {
	struct saved_context cpu __aligned(sizeof(unsigned long));
	struct saved_msr msrs[HDN_RAP_PM_MSRS] __aligned(sizeof(unsigned long));
	struct rap_context *context;
	unsigned long processor_live, cpu_id, kind, top;
	struct rap_record last;
#ifdef CONFIG_HIBERNATION
	struct hdn_rap_hibernate_launch launch;
	unsigned long image_physical, image_owner, image_live, copy_live, launch_live;
#endif
} hdn_rap_resume_state __ro_after_init;
static_assert(offsetof(typeof(hdn_rap_resume_state), cpu) == 0);

static void noinstr resume_store(unsigned long *word, unsigned long value)
{
	unsigned long address = (unsigned long)word;

	if (address < (unsigned long)&hdn_rap_resume_state ||
	    address - (unsigned long)&hdn_rap_resume_state > sizeof(hdn_rap_resume_state) - sizeof(*word) ||
	    !IS_ALIGNED(address, sizeof(*word)))
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	hdn_pt_window_update(__pa_symbol(word) >> PAGE_SHIFT,
			     offset_in_page(word), value, 0, HDN_PT_STORE);
}

/* Packed CPU state is copied exactly once. Zero the last word's padding and
 * avoid a compiler-generated memcpy call in this recursion-boundary unit. */
static void noinstr resume_copy(void *target, const void *source, unsigned long size)
{
	const volatile unsigned char *bytes = source;
	unsigned long *out = target;

	for (unsigned long offset = 0; offset < size; offset += sizeof(long)) {
		unsigned long word = 0;

		for (unsigned int byte = 0; byte < sizeof(long) && offset + byte < size; byte++)
			word |= (unsigned long)bytes[offset + byte] << (8 * byte);
		resume_store(out++, word);
	}
}

void noinstr hdn_rap_processor_save(const struct saved_context *source)
{
	struct saved_context copy __uninitialized;
	volatile unsigned char *out = (void *)&copy;
	const volatile unsigned char *in = (const void *)source;
	unsigned int cpu = hdn_pt_cpu();

	if (!native_irqs_disabled_flags(native_save_fl()) || source != &saved_context ||
	    hdn_rap_resume_state.processor_live || hdn_rap_resume_state.kind ||
	    hdn_rap_pm_msr_count > HDN_RAP_PM_MSRS)
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	for (unsigned int i = 0; i < sizeof(copy); i++)
		out[i] = in[i];
	/* Read the control state at the transition, independently of the
	 * writable compatibility copy consumed by feature-off kernels. */
	copy.cr0 = native_read_cr0();
	copy.cr2 = native_read_cr2();
	copy.cr3 = __native_read_cr3();
	copy.cr4 = native_read_cr4();
	copy.kernelmode_gs_base = __rdmsr(MSR_GS_BASE);
	copy.usermode_gs_base = __rdmsr(MSR_KERNEL_GS_BASE);
	copy.fs_base = __rdmsr(MSR_FS_BASE);
	copy.efer = __rdmsr(MSR_EFER);
	native_store_gdt(&copy.gdt_desc);
	store_idt(&copy.idt);
	copy.saved_msrs.num = hdn_rap_pm_msr_count;
	copy.saved_msrs.array = hdn_rap_resume_state.msrs;
	for (unsigned int i = 0; i < hdn_rap_pm_msr_count; i++) {
		struct saved_msr msr __uninitialized;
		volatile unsigned char *p = (void *)&msr;

		for (unsigned int j = 0; j < sizeof(msr); j++)
			p[j] = 0;
		msr.valid = true;
		msr.info.msr_no = hdn_rap_pm_msr_ids[i];
		msr.info.reg.q = __rdmsr(msr.info.msr_no);
		resume_copy(&hdn_rap_resume_state.msrs[i], &msr, sizeof(msr));
	}
	resume_copy(&hdn_rap_resume_state.cpu, &copy, sizeof(copy));
	resume_store(&hdn_rap_resume_state.cpu_id, cpu);
	resume_store(&hdn_rap_resume_state.processor_live, 1);
}

const struct saved_context *noinstr hdn_rap_processor_state(void)
{
	if (!native_irqs_disabled_flags(native_save_fl()) || !hdn_rap_resume_state.processor_live ||
	    hdn_rap_resume_state.cpu_id != hdn_pt_cpu() || hdn_rap_resume_state.kind)
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	return &hdn_rap_resume_state.cpu;
}

void noinstr hdn_rap_processor_finish(void)
{
	if (!native_irqs_disabled_flags(native_save_fl()) || !hdn_rap_resume_state.processor_live ||
	    hdn_rap_resume_state.kind || hdn_rap_resume_state.cpu_id != hdn_pt_cpu())
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	resume_store(&hdn_rap_resume_state.processor_live, 0);
}

void noinstr hdn_rap_resume_save(unsigned long kind, unsigned long sp)
{
	struct rap_context *context = hdn_rap_context_for(sp);
	const struct rap_record *last;
	unsigned long live_sp;

	asm volatile("movq %%rsp,%0" : "=r" (live_sp));
	if (!native_irqs_disabled_flags(native_save_fl()) || !hdn_rap_resume_state.processor_live ||
	    hdn_rap_resume_state.kind || hdn_rap_resume_state.cpu_id != hdn_pt_cpu() ||
	    (kind != HDN_RAP_RESUME_S3 && kind != HDN_RAP_RESUME_IMAGE) ||
	    !context || context->owner != current || context->domain != RAP_TASK ||
	    context->async_top || context->probe_top || !context->top || context->top > RAP_FRAMES ||
	    !hdn_stack_mm_active(current, sp) || live_sp > sp || sp - live_sp > 1024 ||
	    sp != READ_ONCE(saved_context.regs.sp))
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	last = &context->records[context->top - 1];
	if (!last->sequence || (last->hooks & RAP_HOOK_ENTERED) || last->slot < sp ||
	    last->slot - sp != (kind == HDN_RAP_RESUME_IMAGE ? 0 :
			       IS_ENABLED(CONFIG_FRAME_POINTER) ? 16 : 8) ||
	    (READ_ONCE(saved_context.regs.flags) & X86_EFLAGS_IF) ||
	    last->slot >= context->end ||
	    READ_ONCE(*(unsigned long *)last->slot) != hdn_rap_record_target(context, last))
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	resume_copy(&hdn_rap_resume_state.cpu.regs, &saved_context.regs, sizeof(struct pt_regs));
	resume_store((unsigned long *)&hdn_rap_resume_state.context, (unsigned long)context);
	resume_store(&hdn_rap_resume_state.top, context->top);
	resume_copy(&hdn_rap_resume_state.last, last, sizeof(*last));
	resume_store(&hdn_rap_resume_state.kind, kind);
	if (kind == HDN_RAP_RESUME_S3)
		hdn_stack_mm_resume_prepare(sp);
}

const struct saved_context *noinstr hdn_rap_resume_restore(unsigned long kind)
{
	struct rap_context *context = hdn_rap_resume_state.context;
	const struct rap_record *last;
	unsigned long live_sp;

	asm volatile("movq %%rsp,%0" : "=r" (live_sp));
	if (!native_irqs_disabled_flags(native_save_fl()) || !hdn_rap_resume_state.processor_live ||
	    !kind || hdn_rap_resume_state.kind != kind || hdn_rap_resume_state.cpu_id != hdn_pt_cpu() ||
	    !context || context != hdn_rap_context_for(live_sp) ||
	    context->owner != current || context->async_top || context->probe_top ||
	    !hdn_stack_mm_active(current, live_sp) ||
	    !hdn_rap_resume_state.top || hdn_rap_resume_state.top > context->top || context->top > RAP_FRAMES ||
	    (hdn_rap_resume_state.cpu.cr3 & CR3_ADDR_MASK) != (__native_read_cr3() & CR3_ADDR_MASK))
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	last = &context->records[hdn_rap_resume_state.top - 1];
	if (last->slot != hdn_rap_resume_state.last.slot || last->target != hdn_rap_resume_state.last.target ||
	    last->sequence != hdn_rap_resume_state.last.sequence ||
	    last->hooks != hdn_rap_resume_state.last.hooks ||
	    READ_ONCE(*(unsigned long *)last->slot) != hdn_rap_record_target(context, last))
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	/* Only frames created after this exact checkpoint may be abandoned.
	 * Never rewind the generation counter or accept replacement return data. */
	for (unsigned long i = hdn_rap_resume_state.top; i < context->top; i++)
		hdn_rap_record_discard(context, &context->records[i]);
	hdn_rap_context_store(context, &context->top, hdn_rap_resume_state.top);
	if (kind == HDN_RAP_RESUME_S3)
		hdn_stack_mm_resume_finish();
	resume_store(&hdn_rap_resume_state.kind, 0);
	return &hdn_rap_resume_state.cpu;
}

#ifdef CONFIG_HIBERNATION
/* The snapshot loader already owns image compatibility and authorization.
 * Capture its accepted header before device quiescence. This protects the
 * in-kernel handoff from later pointer replacement; it does not authenticate
 * an external hibernation image or extend RAP across the image-copy boundary. */
int noinstr hdn_rap_hibernate_header(unsigned long entry, unsigned long physical,
		unsigned long cr3)
{
	unsigned long flags = native_local_irq_save();
	int error = -EINVAL;

	if (hdn_rap_resume_state.image_live || hdn_rap_resume_state.launch_live)
		goto out;
	if (!PAGE_ALIGNED(entry) || entry < __START_KERNEL_map ||
	    entry - __START_KERNEL_map >= KERNEL_IMAGE_SIZE ||
	    !physical || !PAGE_ALIGNED(physical) || (physical & ~PTE_PFN_MASK) ||
	    !cr3 || (cr3 & ~CR3_ADDR_MASK))
		goto out;
	resume_store(&hdn_rap_resume_state.launch.entry, entry);
	resume_store(&hdn_rap_resume_state.launch.cr3, cr3);
	resume_store(&hdn_rap_resume_state.image_physical, physical);
	resume_store(&hdn_rap_resume_state.image_live, 1);
	error = 0;
out:
	native_local_irq_restore(flags);
	return error;
}

int noinstr hdn_rap_hibernate_prepare(unsigned long temporary_cr3, unsigned long code)
{
	unsigned long flags = native_local_irq_save();
	int error = -EINVAL;

	if (!hdn_rap_resume_state.image_live || !hdn_rap_resume_state.copy_live ||
	    hdn_rap_resume_state.launch_live ||
	    READ_ONCE(restore_jump_address) != hdn_rap_resume_state.launch.entry ||
	    READ_ONCE(jump_address_phys) != hdn_rap_resume_state.image_physical ||
	    READ_ONCE(restore_cr3) != hdn_rap_resume_state.launch.cr3 ||
	    !temporary_cr3 || (temporary_cr3 & ~CR3_ADDR_MASK) ||
	    !code || !PAGE_ALIGNED(code))
		goto out;
	resume_store(&hdn_rap_resume_state.launch.temporary_cr3, temporary_cr3);
	resume_store(&hdn_rap_resume_state.launch.code, code);
	resume_store(&hdn_rap_resume_state.launch.cr4, mmu_cr4_features);
	/* Loading through /dev/snapshot may precede a descriptor handoff.
	 * Bind the executing task only when the PM core commits preparation. */
	resume_store(&hdn_rap_resume_state.image_owner, (unsigned long)current);
	resume_store(&hdn_rap_resume_state.launch_live, 1);
	error = 0;
out:
	native_local_irq_restore(flags);
	return error;
}

int noinstr hdn_rap_hibernate_copy_publish(unsigned long pages)
{
	unsigned long flags = native_local_irq_save();
	int error = -EINVAL;

	if (!hdn_rap_resume_state.image_live || hdn_rap_resume_state.copy_live ||
	    hdn_rap_resume_state.launch_live ||
	    (pages && !IS_ALIGNED(pages, sizeof(unsigned long))))
		goto out;
	resume_store(&hdn_rap_resume_state.launch.pages, pages);
	resume_store(&hdn_rap_resume_state.copy_live, 1);
	error = 0;
out:
	native_local_irq_restore(flags);
	return error;
}

const struct hdn_rap_hibernate_launch *noinstr hdn_rap_hibernate_enter(void)
{
	unsigned long sp;
	struct rap_context *context;

	asm volatile("movq %%rsp,%0" : "=r" (sp));
	context = hdn_rap_context_for(sp);
	if (!native_irqs_disabled_flags(native_save_fl()) ||
	    !hdn_rap_resume_state.image_live || hdn_rap_resume_state.launch_live != 1 ||
	    hdn_rap_resume_state.image_owner != (unsigned long)current ||
	    !hdn_rap_resume_state.processor_live || hdn_rap_resume_state.kind ||
	    hdn_rap_resume_state.cpu_id != hdn_pt_cpu() ||
	    !context || context->owner != current || context->domain != RAP_TASK ||
	    context->async_top || context->probe_top || context->bpf_top ||
	    !hdn_stack_mm_active(current, sp))
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	/* Retain the descriptor until the irreversible image copy has consumed
	 * it. A second entry in this kernel cannot reuse the authorization. */
	resume_store(&hdn_rap_resume_state.launch_live, 2);
	return &hdn_rap_resume_state.launch;
}

void noinstr hdn_rap_hibernate_release(void)
{
	unsigned long flags = native_local_irq_save();

	if (hdn_rap_resume_state.launch_live == 2)
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	resume_store(&hdn_rap_resume_state.launch_live, 0);
	resume_store(&hdn_rap_resume_state.copy_live, 0);
	resume_store(&hdn_rap_resume_state.image_live, 0);
	resume_store(&hdn_rap_resume_state.image_owner, 0);
	native_local_irq_restore(flags);
}
#endif
