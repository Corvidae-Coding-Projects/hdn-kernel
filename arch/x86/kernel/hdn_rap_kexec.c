// SPDX-License-Identifier: GPL-2.0-only
/* Protected admission and one-shot return state for the kexec terminal ABI. */
#include <linux/hdn_rap.h>
#include <linux/kexec.h>
#include <linux/sched.h>
#include <asm/cacheflush.h>
#include <asm/hdn_rap_kexec.h>
#include <asm/hdn_stack_mm.h>
#include <asm/irqflags.h>
#include <asm/msr.h>
#include <asm/sections.h>
#include <asm/tlbflush.h>
#include "hdn_rap_context_internal.h"
#include "../mm/hdn_pgtable_internal.h"

/* kexec_lock serializes staging, replacement, teardown and both entry paths.
 * Two published images plus one staging image can coexist. Keep one spare
 * slot so a stale registration is rejected rather than replacing live data. */
struct rap_kexec_image {
	struct kimage *image;
	struct hdn_rap_kexec_launch launch;
};
static struct {
	struct rap_kexec_image images[4];
	struct hdn_rap_kexec_launch launch;
	struct rap_context *context;
	struct rap_record last;
	unsigned long slot, top, cpu, active;
} kexec_state __ro_after_init;

struct hdn_rap_kexec_state hdn_rap_kexec_state __ro_after_init;

static void noinstr kexec_store(unsigned long *word, unsigned long value)
{
	unsigned long address = (unsigned long)word;
	unsigned long private = (unsigned long)&kexec_state;
	unsigned long cpu = (unsigned long)&hdn_rap_kexec_state;

	if (!IS_ALIGNED(address, sizeof(*word)) ||
	    !((address >= private && address - private <= sizeof(kexec_state) - sizeof(*word)) ||
	      (address >= cpu && address - cpu <= sizeof(hdn_rap_kexec_state) - sizeof(*word))))
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	hdn_pt_window_update(__pa_symbol(word) >> PAGE_SHIFT,
			     offset_in_page(word), value, 0, HDN_PT_STORE);
}

static void noinstr kexec_copy(void *target, const void *source, unsigned long size)
{
	const volatile unsigned char *bytes = source;
	unsigned long *out = target;

	for (unsigned long offset = 0; offset < size; offset += sizeof(long)) {
		unsigned long word = 0;

		for (unsigned int i = 0; i < sizeof(long) && offset + i < size; i++)
			word |= (unsigned long)bytes[offset + i] << (i * 8);
		kexec_store(out++, word);
	}
}

int noinstr hdn_rap_kexec_publish(struct kimage *image,
		const struct hdn_rap_kexec_launch *launch)
{
	unsigned long flags = native_local_irq_save();
	unsigned int empty = ARRAY_SIZE(kexec_state.images);
	int error = -EINVAL;

	if (kexec_state.active || !image || !launch->control || !launch->table ||
	    !PAGE_ALIGNED(launch->control) || !PAGE_ALIGNED(launch->table) ||
	    (launch->head & ~PAGE_MASK) != IND_INDIRECTION ||
	    launch->code != (unsigned long)boot_phys_to_virt(launch->control) +
		(unsigned long)relocate_kernel - (unsigned long)__relocate_kernel_start ||
	    launch->entry > KEXEC_DESTINATION_MEMORY_LIMIT ||
	    (launch->flags & ~RELOC_KERNEL_PRESERVE_CONTEXT) ||
	    ((launch->flags & RELOC_KERNEL_PRESERVE_CONTEXT) && !launch->swap))
		goto out;
	for (unsigned int i = 0; i < ARRAY_SIZE(kexec_state.images); i++) {
		if (kexec_state.images[i].image == image)
			goto out;
		if (!kexec_state.images[i].image)
			empty = i;
	}
	if (empty == ARRAY_SIZE(kexec_state.images)) {
		error = -ENOSPC;
		goto out;
	}
	kexec_copy(&kexec_state.images[empty].launch, launch, sizeof(*launch));
	kexec_store((unsigned long *)&kexec_state.images[empty].image, (unsigned long)image);
	error = 0;
out:
	native_local_irq_restore(flags);
	return error;
}

void noinstr hdn_rap_kexec_release(struct kimage *image)
{
	unsigned long flags = native_local_irq_save();

	if (kexec_state.active)
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	for (unsigned int i = 0; i < ARRAY_SIZE(kexec_state.images); i++)
		if (kexec_state.images[i].image == image)
			kexec_store((unsigned long *)&kexec_state.images[i].image, 0);
	native_local_irq_restore(flags);
}

const struct hdn_rap_kexec_launch *noinstr hdn_rap_kexec_enter(struct kimage *image,
		unsigned long sp)
{
	struct rap_context *context = hdn_rap_context_for(sp);
	const struct rap_record *last;
	struct hdn_rap_kexec_state cpu __uninitialized;
	volatile unsigned char *bytes = (void *)&cpu;
	unsigned long live_sp, slot = sp + 6 * sizeof(long), index;

	asm volatile("movq %%rsp,%0" : "=r" (live_sp));
	if (!native_irqs_disabled_flags(native_save_fl()) || kexec_state.active ||
	    !context || !context->top || context->top > RAP_FRAMES ||
	    slot < sp || slot >= context->end || live_sp > sp || sp - live_sp > 1024)
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	for (index = 0; index < ARRAY_SIZE(kexec_state.images); index++)
		if (kexec_state.images[index].image == image)
			break;
	if (index == ARRAY_SIZE(kexec_state.images))
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	last = &context->records[context->top - 1];
	if (!last->sequence || last->slot != slot || last->hooks ||
	    READ_ONCE(*(unsigned long *)slot) != hdn_rap_record_target(context, last))
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	if ((kexec_state.images[index].launch.flags & RELOC_KERNEL_PRESERVE_CONTEXT) &&
	    (context->domain != RAP_TASK || context->owner != current || context->async_top ||
	     context->probe_top || context->bpf_top || !hdn_stack_mm_active(current, sp)))
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	for (unsigned int i = 0; i < sizeof(cpu); i++)
		bytes[i] = 0;
	cpu.cr0 = native_read_cr0();
	cpu.cr3 = __native_read_cr3();
	cpu.cr4 = native_read_cr4();
	cpu.gsbase = __rdmsr(MSR_GS_BASE);
	cpu.sp = slot;
	cpu.flags = native_save_fl();
	cpu.r15 = READ_ONCE(((unsigned long *)sp)[0]);
	cpu.r14 = READ_ONCE(((unsigned long *)sp)[1]);
	cpu.r13 = READ_ONCE(((unsigned long *)sp)[2]);
	cpu.r12 = READ_ONCE(((unsigned long *)sp)[3]);
	cpu.bp = READ_ONCE(((unsigned long *)sp)[4]);
	cpu.bx = READ_ONCE(((unsigned long *)sp)[5]);
	native_store_gdt(&cpu.gdt);
	store_idt(&cpu.idt);
	kexec_copy(&hdn_rap_kexec_state, &cpu, sizeof(cpu));
	kexec_copy(&kexec_state.launch, &kexec_state.images[index].launch,
		   sizeof(kexec_state.launch));
	if (this_cpu_read(cache_state_incoherent))
		kexec_store(&kexec_state.launch.flags,
			    kexec_state.launch.flags | RELOC_KERNEL_CACHE_INCOHERENT);
	kexec_store((unsigned long *)&kexec_state.context, (unsigned long)context);
	kexec_copy(&kexec_state.last, last, sizeof(*last));
	kexec_store(&kexec_state.top, context->top);
	kexec_store(&kexec_state.slot, index);
	kexec_store(&kexec_state.cpu, hdn_pt_cpu());
	kexec_store(&kexec_state.active, 1);
	return &kexec_state.launch;
}

void noinstr hdn_rap_kexec_finish(unsigned long entry)
{
	struct rap_context *context = kexec_state.context;
	const struct rap_record *last;
	unsigned long sp;

	asm volatile("movq %%rsp,%0" : "=r" (sp));
	if (!native_irqs_disabled_flags(native_save_fl()) || kexec_state.active != 1 ||
	    !(kexec_state.launch.flags & RELOC_KERNEL_PRESERVE_CONTEXT) ||
	    kexec_state.cpu != hdn_pt_cpu() || !context ||
	    context != hdn_rap_context_for(sp) || context->owner != current ||
	    context->domain != RAP_TASK || context->top != kexec_state.top ||
	    !context->top || context->top > RAP_FRAMES || context->async_top ||
	    context->probe_top || context->bpf_top || !hdn_stack_mm_active(current, sp) ||
	    (__native_read_cr3() & CR3_ADDR_MASK) != (hdn_rap_kexec_state.cr3 & CR3_ADDR_MASK) ||
	    kexec_state.slot >= ARRAY_SIZE(kexec_state.images) ||
	    entry > KEXEC_DESTINATION_MEMORY_LIMIT)
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	last = &context->records[context->top - 1];
	if (last->slot != kexec_state.last.slot || last->target != kexec_state.last.target ||
	    last->sequence != kexec_state.last.sequence || last->hooks != kexec_state.last.hooks ||
	    READ_ONCE(*(unsigned long *)last->slot) != hdn_rap_record_target(context, last))
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	/* The peer supplies its next entry as part of the established kexec-jump
 * ABI. Accept it only at this authenticated return from that peer. */
	kexec_store(&kexec_state.images[kexec_state.slot].launch.entry, entry);
	kexec_store(&kexec_state.active, 0);
}
