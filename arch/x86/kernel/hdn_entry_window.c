// SPDX-License-Identifier: GPL-2.0-only
/* Close private writable aliases before ordinary asynchronous handler C. */
#include <linux/mm.h>
#include <asm/desc.h>
#include <asm/hdn_gdt.h>
#include <asm/hdn_pgtable.h>
#include <asm/mmu_context.h>
#include <asm/special_insns.h>
#include "hdn_gdt_internal.h"

/* RAP/private-stack entry performs this transition as part of authenticated
 * frame registration, retaining that CPU's active private stack view. */
#ifndef CONFIG_SECURITY_HARDENING_PRIVATE_STACKS

#ifdef CONFIG_SECURITY_HARDENING_GDT
static const struct hdn_gdt_config *noinstr gdt_config(void)
{
	unsigned long gsbase = __rdmsr(MSR_GS_BASE);
	unsigned int low = 0, high = READ_ONCE(hdn_gdt_cpu_count);

	while (low < high) {
		unsigned int middle = low + (high - low) / 2;
		const struct hdn_gdt_identity *identity = &hdn_gdt_identities[middle];

		if (gsbase < identity->gsbase)
			high = middle;
		else if (gsbase > identity->gsbase)
			low = middle + 1;
		else
			return &hdn_gdt_configs[identity->cpu];
	}
	BUG();
}
#endif

unsigned long noinstr hdn_entry_window_enter(void)
{
#ifdef CONFIG_SECURITY_HARDENING_PGTABLE
	if (READ_ONCE(hdn_pt_writes_ready))
		return hdn_pt_async_enter();
#endif
#ifdef CONFIG_SECURITY_HARDENING_GDT
	const struct hdn_gdt_config *config;
	unsigned long cr3;
	struct desc_ptr gdt;

	if (!READ_ONCE(hdn_gdt_ready))
		return 0;
	config = gdt_config();
	cr3 = __native_read_cr3();
	if (cr3 != config->normal.cr3 && cr3 != config->emergency.cr3)
		return 0;
	native_store_gdt(&gdt);
	if (gdt.address == HDN_GDT_ALIAS) {
		gdt.address = config->gdt_base;
		gdt.size = GDT_SIZE - 1;
		native_load_gdt(&gdt);
		cr3 |= BIT_ULL(63); /* Saved CR3 never contains the NOFLUSH hint. */
	}
	native_write_cr3(__sme_pa(init_mm.pgd));
	return cr3;
#else
	return 0;
#endif
}

void noinstr hdn_entry_window_exit(unsigned long state)
{
#ifdef CONFIG_SECURITY_HARDENING_PGTABLE
	if (READ_ONCE(hdn_pt_writes_ready)) {
		hdn_pt_async_exit(state);
		return;
	}
#endif
#ifdef CONFIG_SECURITY_HARDENING_GDT
	const struct hdn_gdt_config *config;
	const struct hdn_gdt_window *window;
	unsigned long cr3 = state & ~BIT_ULL(63), leaf;
	struct desc_ptr gdt = { .address = HDN_GDT_ALIAS, .size = GDT_SIZE - 1 };

	/* Xen callbacks can share error_return without entering this native
	 * protocol; native GDT windows are never activated on Xen PV. */
	if (!READ_ONCE(hdn_gdt_ready) || !state)
		return;
	if (!native_irqs_disabled_flags(native_save_fl()))
		BUG();
	config = gdt_config();
	if (cr3 == config->normal.cr3)
		window = &config->normal;
	else if (cr3 == config->emergency.cr3)
		window = &config->emergency;
	else
		BUG();
	leaf = READ_ONCE(window->pte->pte);
	/* The NMI may have arrived after the writer cleared its PTE but before
	 * restoring CR3. Only an aliased GDTR requires a still-present slot. */
	if ((leaf || (state & BIT_ULL(63))) &&
	    ((leaf & PTE_PFN_MASK) >> PAGE_SHIFT != config->pfn ||
	     (leaf & (_PAGE_PRESENT | _PAGE_RW | _PAGE_USER)) != (_PAGE_PRESENT | _PAGE_RW)))
		BUG();
	native_write_cr3(cr3);
	if (state & BIT_ULL(63))
		native_load_gdt(&gdt);
#endif
}
#endif
