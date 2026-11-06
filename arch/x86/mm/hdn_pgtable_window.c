// SPDX-License-Identifier: GPL-2.0-only
/* Closed CPU-private page-table writes; allocation is in the init unit. */
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/hdn_rap.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/mmu_context.h>
#include <asm/smap.h>
#include <asm/special_insns.h>
#include <asm/hdn_stack_mm.h>
#include <asm/desc.h>
#include "hdn_pgtable_internal.h"

#include "hdn_pgtable_window_internal.h"

static __noreturn noinstr void hdn_window_fail(void)
{
#ifdef CONFIG_SECURITY_HARDENING_RAP
	__hdn_rap_fail(HDN_RAP_FAIL_WINDOW);
#else
	BUG();
#endif
}

unsigned int noinstr hdn_pt_cpu(void)
{
	unsigned long gsbase, unused_high;
	unsigned int low = 0, high = READ_ONCE(hdn_pt_cpu_count);

	/* Before construction only the boot CPU can execute these entry paths.
	 * After construction, no writable per-CPU integer selects a private CR3. */
	if (!high)
		return 0;
	asm volatile(ALTERNATIVE("rdmsr; shlq $32, %%rdx; orq %%rdx, %%rax",
				 "rdgsbase %%rax", X86_FEATURE_FSGSBASE)
		     : "=a" (gsbase), "=d" (unused_high) : "c" (MSR_GS_BASE) : "memory", "cc");
	while (low < high) {
		unsigned int middle = low + (high - low) / 2;
		const struct hdn_pt_cpu_identity *identity = &hdn_pt_cpu_identities[middle];

		if (gsbase < identity->gsbase)
			high = middle;
		else if (gsbase > identity->gsbase)
			low = middle + 1;
		else
			return identity->cpu;
	}
	hdn_window_fail();
}

#ifndef CONFIG_SECURITY_HARDENING_PRIVATE_STACKS
/* Without private stacks, init_mm contains every kernel stack. An asynchronous
 * handler must never inherit the update window's writable self mapping. The
 * interrupted window already has no user mappings; this kernel-only root keeps
 * that restriction while ordinary handler C runs. The original CR3 (including
 * its userspace mappings) is restored by window_operation after the handler. */
unsigned long noinstr hdn_pt_async_enter(void)
{
	unsigned long cr3 = __native_read_cr3(), state;
	const struct hdn_pt_windows *windows;
	struct desc_ptr gdt;

	if (!READ_ONCE(hdn_pt_writes_ready))
		return 0;
	windows = &hdn_pt_windows[hdn_pt_cpu()];
	if (cr3 != windows->views[0].normal.cr3 && cr3 != windows->views[0].emergency.cr3)
		return 0;
	state = cr3;
	native_store_gdt(&gdt);
	if (gdt.address == HDN_PT_TARGET) {
		gdt.address = windows->gdt_base;
		gdt.size = GDT_SIZE - 1;
		native_load_gdt(&gdt);
		/* Bit 63 is a write-only CR3 hint and never part of a saved CR3. */
		state |= BIT_ULL(63);
	}
	native_write_cr3(__sme_pa(init_mm.pgd));
	return state;
}

void noinstr hdn_pt_async_exit(unsigned long state)
{
	const struct hdn_pt_windows *windows;
	const struct hdn_pt_window *window;
	unsigned long cr3 = state & ~BIT_ULL(63), leaf;
	struct desc_ptr gdt = { .address = HDN_PT_TARGET, .size = GDT_SIZE - 1 };

	if (!READ_ONCE(hdn_pt_writes_ready) || !state)
		return;
	if (!native_irqs_disabled_flags(native_save_fl()))
		hdn_window_fail();
	windows = &hdn_pt_windows[hdn_pt_cpu()];
	if (cr3 == windows->views[0].normal.cr3)
		window = &windows->views[0].normal;
	else if (cr3 == windows->views[0].emergency.cr3)
		window = &windows->views[0].emergency;
	else
		hdn_window_fail();
	if (state & BIT_ULL(63)) {
		leaf = READ_ONCE(window->table[HDN_PT_SLOT].pte);
		if ((leaf & PTE_PFN_MASK) >> PAGE_SHIFT != windows->gdt_pfn ||
		    (leaf & (_PAGE_PRESENT | _PAGE_RW | _PAGE_USER)) != (_PAGE_PRESENT | _PAGE_RW))
			hdn_window_fail();
	}
	native_write_cr3(cr3);
	if (state & BIT_ULL(63))
		native_load_gdt(&gdt);
}
#endif

/* Once CR3 changes this routine must not call instrumented C, perform an
 * allocation, fault, touch userspace, or invoke a paravirtual callback.
 * Object instrumentation is disabled in the Makefile; objtool still checks it.
 * The caller validates ownership and lifetime before reaching this primitive.
 */
static noinstr unsigned long window_operation(unsigned long pfn, unsigned int offset,
		unsigned long value, unsigned long expected, enum hdn_pt_operation operation,
		bool clear, const unsigned long *source, unsigned int skip)
{
	unsigned long flags, saved_cr3, old = 0, mapping;
	const struct hdn_pt_window *window;
	const struct hdn_pt_window_pair *pair;
	unsigned long *slot = (unsigned long *)(HDN_PT_TARGET + offset);
	unsigned long *self = (unsigned long *)HDN_PT_SELF;
	unsigned int cpu;

	/* Validate the address geometry before the private context becomes live. */
	if (offset >= PAGE_SIZE || !IS_ALIGNED(offset, sizeof(unsigned long)) ||
	    operation > HDN_PT_LTR || (clear && operation != HDN_PT_STORE) ||
	    (operation == HDN_PT_COPY &&
	     (offset || skip > PTRS_PER_PTE || (source && !IS_ALIGNED((unsigned long)source, PAGE_SIZE)))))
		hdn_window_fail();
	flags = native_local_irq_save();
	cpu = hdn_pt_cpu();
	saved_cr3 = __native_read_cr3();
	pair = &hdn_pt_windows[cpu].views[hdn_stack_mm_view(cpu, saved_cr3)];
	/* Hardware CR3, rather than a writable busy flag, identifies nesting.
	 * A nested NMI gets the other private hierarchy; reentry into the
	 * emergency hierarchy cannot overwrite an interrupted update slot. */
	if ((saved_cr3 & CR3_ADDR_MASK) == pair->emergency.cr3)
		hdn_window_fail();
	if ((saved_cr3 & CR3_ADDR_MASK) == pair->normal.cr3 || in_nmi() ||
	    READ_ONCE(pair->normal.table[HDN_PT_SLOT].pte))
		window = &pair->emergency;
	else
		window = &pair->normal;
	if (READ_ONCE(window->table[HDN_PT_SLOT].pte))
		hdn_window_fail();
	mapping = (pfn << PAGE_SHIFT) | __sme_set(pgprot_val(PAGE_KERNEL) & ~_PAGE_GLOBAL);
	if (operation == HDN_PT_READ)
		mapping &= ~_PAGE_RW;
	native_write_cr3(window->cr3);
	/* LASS checks supervisor accesses to lower-half addresses. PTEs remain
	 * supervisor-only, so SMAP does not grant access to a userspace mapping. */
	lass_stac();
	WRITE_ONCE(self[HDN_PT_SLOT], mapping);
	asm volatile("invlpg (%0)" : : "r" (HDN_PT_TARGET) : "memory");
	if (clear) {
		unsigned long *target = (unsigned long *)HDN_PT_TARGET;
		for (unsigned int i = 0; i < PAGE_SIZE / sizeof(*target); i++)
			WRITE_ONCE(target[i], 0);
	} else {
		switch (operation) {
		case HDN_PT_LTR: {
			struct desc_ptr saved, writable = {
				.size = GDT_SIZE - 1, .address = HDN_PT_TARGET,
			};

			native_store_gdt(&saved);
			native_load_gdt(&writable);
			asm volatile("ltr %w0" : : "q" (GDT_ENTRY_TSS * 8) : "memory");
			native_load_gdt(&saved);
			break;
		}
		case HDN_PT_COPY:
			for (unsigned int i = 0; i < PTRS_PER_PTE; i++)
				if (i != skip)
					WRITE_ONCE(slot[i], source ? READ_ONCE(source[i]) : 0);
			break;
		case HDN_PT_READ:
			old = READ_ONCE(*slot);
			break;
		case HDN_PT_STORE:
			WRITE_ONCE(*slot, value);
			break;
		case HDN_PT_EXCHANGE:
			asm volatile("xchgq %0,%1" : "+r" (value), "+m" (*slot) : : "memory");
			old = value;
			break;
		case HDN_PT_COMPARE_EXCHANGE:
			asm volatile("lock cmpxchgq %2,%1" : "+a" (expected), "+m" (*slot)
				     : "r" (value) : "memory", "cc");
			old = expected;
			break;
		}
	}
	WRITE_ONCE(self[HDN_PT_SLOT], 0);
	asm volatile("invlpg (%0)" : : "r" (HDN_PT_TARGET) : "memory");
	lass_clac();
	native_write_cr3(saved_cr3);
	native_local_irq_restore(flags);
	return old;
}

unsigned long noinstr hdn_pt_window_update(unsigned long pfn, unsigned int offset,
		unsigned long value, unsigned long expected, enum hdn_pt_operation operation)
{
	if (operation > HDN_PT_COMPARE_EXCHANGE)
		hdn_window_fail();
	return window_operation(pfn, offset, value, expected, operation, false, NULL, PTRS_PER_PTE);
}

void noinstr hdn_pt_window_clear(unsigned long pfn)
{
	window_operation(pfn, 0, 0, 0, HDN_PT_STORE, true, NULL, PTRS_PER_PTE);
}

void noinstr hdn_pt_window_ltr(unsigned long pfn)
{
	window_operation(pfn, 0, 0, 0, HDN_PT_LTR, false, NULL, PTRS_PER_PTE);
}

/* Diagnostic consumers receive a value, never an address of the private
 * mapping. The temporary read mapping has no write permission. */
unsigned long noinstr hdn_pt_window_read(unsigned long pfn, unsigned int offset)
{
	return window_operation(pfn, offset, 0, 0, HDN_PT_READ, false, NULL, PTRS_PER_PTE);
}

/* A top-level clone must retain the currently executing private stack branch
 * throughout the copy. skip == PTRS_PER_PTE means copy every entry. A NULL
 * source clears all other entries without borrowing a writable alias. */
void noinstr hdn_pt_window_copy(unsigned long pfn, const unsigned long *source,
		unsigned int skip)
{
	window_operation(pfn, 0, 0, 0, HDN_PT_COPY, false, source, skip);
}
