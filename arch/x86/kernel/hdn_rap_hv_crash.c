// SPDX-License-Identifier: GPL-2.0-only
/* A one-shot BSP crash checkpoint. The external hypervisor remains trusted. */
#include <linux/hdn_rap.h>
#include <linux/sched.h>
#include <asm/hdn_hv_crash.h>
#include <asm/irqflags.h>
#include <asm/msr.h>
#include <asm/sections.h>
#include <asm/segment.h>
#include <asm/tlbflush.h>
#include "hdn_rap_context_internal.h"
#include "../mm/hdn_pgtable_internal.h"

struct hdn_hv_crash_cpu hdn_hv_crash_cpu __ro_after_init;
static struct {
	struct rap_context *context;
	struct rap_record last;
	unsigned long top, async_top, probe_top, bpf_top, cpu, active;
} crash_checkpoint __ro_after_init;

#define CRASH_OFFSET(member, offset) static_assert(offsetof(struct hdn_hv_crash_cpu, member) == offset)
CRASH_OFFSET(sp, HDN_HVC_SP);
CRASH_OFFSET(cr0, HDN_HVC_CR0);
CRASH_OFFSET(cr2, HDN_HVC_CR2);
CRASH_OFFSET(cr3, HDN_HVC_CR3);
CRASH_OFFSET(cr4, HDN_HVC_CR4);
CRASH_OFFSET(cr8, HDN_HVC_CR8);
CRASH_OFFSET(gsbase, HDN_HVC_GSBASE);
CRASH_OFFSET(kernelgs, HDN_HVC_KERNELGS);
CRASH_OFFSET(fsbase, HDN_HVC_FSBASE);
CRASH_OFFSET(efer, HDN_HVC_EFER);
CRASH_OFFSET(pat, HDN_HVC_PAT);
CRASH_OFFSET(ss, HDN_HVC_SS);
CRASH_OFFSET(ds, HDN_HVC_DS);
CRASH_OFFSET(es, HDN_HVC_ES);
CRASH_OFFSET(fs, HDN_HVC_FS);
CRASH_OFFSET(gs, HDN_HVC_GS);
CRASH_OFFSET(cs, HDN_HVC_CS);
CRASH_OFFSET(gdt, HDN_HVC_GDT);
CRASH_OFFSET(idt, HDN_HVC_IDT);
static_assert(sizeof(struct hdn_hv_crash_cpu) == 128);

static void noinstr crash_store(unsigned long *word, unsigned long value)
{
	unsigned long p = (unsigned long)word;
	unsigned long state = (unsigned long)&crash_checkpoint;
	unsigned long cpu = (unsigned long)&hdn_hv_crash_cpu;

	if (!IS_ALIGNED(p, sizeof(*word)) ||
	    !((p >= state && p - state <= sizeof(crash_checkpoint) - sizeof(*word)) ||
	      (p >= cpu && p - cpu <= sizeof(hdn_hv_crash_cpu) - sizeof(*word))))
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	hdn_pt_window_update(__pa_symbol(word) >> PAGE_SHIFT,
			     offset_in_page(word), value, 0, HDN_PT_STORE);
}

static void noinstr crash_copy(void *target, const void *source, unsigned long size)
{
	const volatile unsigned char *bytes = source;
	unsigned long *out = target;

	for (unsigned long off = 0; off < size; off += sizeof(long)) {
		unsigned long word = 0;

		for (unsigned int i = 0; i < sizeof(long) && off + i < size; i++)
			word |= (unsigned long)bytes[off + i] << (8 * i);
		crash_store(out++, word);
	}
}

void noinstr hdn_hv_crash_capture(unsigned long sp)
{
	struct rap_context *context = hdn_rap_context_for(sp);
	struct hdn_hv_crash_cpu cpu __uninitialized;
	volatile unsigned char *bytes = (void *)&cpu;
	const struct rap_record *last;
	unsigned long live_sp;

	asm volatile("movq %%rsp,%0" : "=r" (live_sp));
	if (!native_irqs_disabled_flags(native_save_fl()) || crash_checkpoint.active ||
	    !context || !context->top || context->top > RAP_FRAMES ||
	    sp < context->begin || sp >= context->end || live_sp > sp || sp - live_sp > 1024 ||
	    raw_smp_processor_id() != 0)
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	last = &context->records[context->top - 1];
	if (!last->sequence || last->slot != sp || last->hooks ||
	    READ_ONCE(*(unsigned long *)sp) != hdn_rap_record_target(context, last))
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	for (unsigned int i = 0; i < sizeof(cpu); i++)
		bytes[i] = 0;
	cpu.sp = sp;
	cpu.cr0 = native_read_cr0();
	cpu.cr2 = native_read_cr2();
	cpu.cr3 = __native_read_cr3();
	cpu.cr4 = native_read_cr4();
	asm volatile("movq %%cr8,%0" : "=r" (cpu.cr8));
	asm volatile("movw %%ss,%0" : "=m" (cpu.ss));
	asm volatile("movw %%ds,%0" : "=m" (cpu.ds));
	asm volatile("movw %%es,%0" : "=m" (cpu.es));
	asm volatile("movw %%fs,%0" : "=m" (cpu.fs));
	asm volatile("movw %%gs,%0" : "=m" (cpu.gs));
	asm volatile("movw %%cs,%0" : "=m" (cpu.cs));
	cpu.gsbase = __rdmsr(MSR_GS_BASE);
	cpu.kernelgs = __rdmsr(MSR_KERNEL_GS_BASE);
	cpu.fsbase = __rdmsr(MSR_FS_BASE);
	cpu.efer = __rdmsr(MSR_EFER);
	cpu.pat = __rdmsr(MSR_IA32_CR_PAT);
	native_store_gdt(&cpu.gdt);
	store_idt(&cpu.idt);
	if (cpu.cs != __KERNEL_CS)
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	crash_copy(&hdn_hv_crash_cpu, &cpu, sizeof(cpu));
	crash_copy(&crash_checkpoint.last, last, sizeof(*last));
	crash_store((unsigned long *)&crash_checkpoint.context, (unsigned long)context);
	crash_store(&crash_checkpoint.top, context->top);
	crash_store(&crash_checkpoint.async_top, context->async_top);
	crash_store(&crash_checkpoint.probe_top, context->probe_top);
	crash_store(&crash_checkpoint.bpf_top, context->bpf_top);
	crash_store(&crash_checkpoint.cpu, hdn_pt_cpu());
	crash_store(&crash_checkpoint.active, 1);
}

void noinstr hdn_hv_crash_finish(void)
{
	struct rap_context *context = crash_checkpoint.context;
	const struct rap_record *last;
	unsigned long sp;

	asm volatile("movq %%rsp,%0" : "=r" (sp));
	if (!native_irqs_disabled_flags(native_save_fl()) || crash_checkpoint.active != 1 ||
	    crash_checkpoint.cpu != hdn_pt_cpu() || !context ||
	    hdn_rap_context_for(sp) != context || !crash_checkpoint.top ||
	    crash_checkpoint.top > context->top || context->top > RAP_FRAMES ||
	    context->async_top != crash_checkpoint.async_top ||
	    context->probe_top != crash_checkpoint.probe_top ||
	    context->bpf_top != crash_checkpoint.bpf_top ||
	    (__native_read_cr3() & CR3_ADDR_MASK) != (hdn_hv_crash_cpu.cr3 & CR3_ADDR_MASK))
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	last = &context->records[crash_checkpoint.top - 1];
	if (last->slot != crash_checkpoint.last.slot || last->target != crash_checkpoint.last.target ||
	    last->sequence != crash_checkpoint.last.sequence || last->hooks != crash_checkpoint.last.hooks ||
	    READ_ONCE(*(unsigned long *)last->slot) != hdn_rap_record_target(context, last))
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	/* Abandon only the calls made below this exact crash entry. Retain the
	 * async frame and generation; crash handling can itself take exceptions. */
	for (unsigned long i = crash_checkpoint.top; i < context->top; i++)
		hdn_rap_record_discard(context, &context->records[i]);
	hdn_rap_context_store(context, &context->top, crash_checkpoint.top);
	crash_store(&crash_checkpoint.active, 2);
}
