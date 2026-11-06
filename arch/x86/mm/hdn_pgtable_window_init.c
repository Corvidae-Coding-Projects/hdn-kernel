// SPDX-License-Identifier: GPL-2.0-only
/* Ordinary instrumented construction and initial ownership discovery. */
#include <linux/init.h>
#include <linux/sort.h>
#include <linux/mm.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/mmu_context.h>
#include <asm/smap.h>
#include <asm/special_insns.h>
#include <asm/desc.h>
#include "hdn_pgtable_internal.h"

#include "hdn_pgtable_window_internal.h"

struct hdn_pt_windows hdn_pt_windows[NR_CPUS] __ro_after_init;
struct hdn_pt_cpu_identity hdn_pt_cpu_identities[NR_CPUS] __ro_after_init;
unsigned int hdn_pt_cpu_count __ro_after_init;

static int __init cpu_identity_compare(const void *left, const void *right)
{
	const struct hdn_pt_cpu_identity *a = left, *b = right;

	return (a->gsbase > b->gsbase) - (a->gsbase < b->gsbase);
}
static void __init create_window(struct hdn_pt_window *window)
{
	spinlock_t *lock;
	pte_t *pte;
	pgprot_t protection = __pgprot(pgprot_val(PAGE_KERNEL) & ~_PAGE_GLOBAL);

	window->mm = mm_alloc();
	if (!window->mm)
		panic("HDN could not allocate a page-table update context");
	set_notrack_mm(window->mm);
	pte = get_locked_pte(window->mm, HDN_PT_BASE, &lock);
	if (!pte)
		panic("HDN could not allocate a page-table update window");
	window->table = pte;
	window->table_pfn = __pa(pte) >> PAGE_SHIFT;
	/* This is the sole persistent writable view of the window's PTE page,
	 * and is unreachable through an ordinary CR3. Its own table hierarchy
	 * and direct-map backing are sealed by the lifecycle initialization. */
	WRITE_ONCE(pte[HDN_PT_SELF_SLOT].pte,
		pte_val(pfn_pte(window->table_pfn, protection)));
	pte_unmap_unlock(pte, lock);
	window->cr3 = __sme_pa(window->mm->pgd);
}

void __init hdn_pt_windows_init(void)
{
	unsigned int cpu, count = 0;

	BUILD_BUG_ON(HDN_PT_SELF_SLOT >= PTRS_PER_PTE);
	for_each_possible_cpu(cpu) {
		hdn_pt_windows[cpu].gdt_base = (unsigned long)get_cpu_gdt_ro(cpu);
		hdn_pt_windows[cpu].gdt_pfn = get_cpu_gdt_paddr(cpu) >> PAGE_SHIFT;
		for (unsigned int view = 0; view < HDN_PT_VIEWS; view++) {
			create_window(&hdn_pt_windows[cpu].views[view].normal);
			create_window(&hdn_pt_windows[cpu].views[view].emergency);
		}
		hdn_pt_cpu_identities[count++] = (struct hdn_pt_cpu_identity) {
			.gsbase = cpu_kernelmode_gs_base(cpu), .cpu = cpu,
		};
	}
	sort(hdn_pt_cpu_identities, count, sizeof(hdn_pt_cpu_identities[0]), cpu_identity_compare, NULL);
	for (cpu = 1; cpu < count; cpu++)
		if (hdn_pt_cpu_identities[cpu - 1].gsbase == hdn_pt_cpu_identities[cpu].gsbase)
			panic("HDN duplicate private CPU identity");
	WRITE_ONCE(hdn_pt_cpu_count, count);
}

void __init hdn_pt_windows_walk(void (*visit)(unsigned long *root, unsigned int order))
{
	unsigned int cpu;

	for_each_possible_cpu(cpu)
		for (unsigned int view = 0; view < HDN_PT_VIEWS; view++) {
			const struct hdn_pt_window_pair *pair = &hdn_pt_windows[cpu].views[view];
			visit((unsigned long *)pair->normal.mm->pgd, pgd_allocation_order());
			visit((unsigned long *)pair->emergency.mm->pgd, pgd_allocation_order());
		}
}

bool __init hdn_pt_window_private_alias(unsigned long *root,
		unsigned long address, unsigned long pfn)
{
	unsigned int cpu;

	if (address != HDN_PT_SELF)
		return false;
	for_each_possible_cpu(cpu)
		for (unsigned int view = 0; view < HDN_PT_VIEWS; view++) {
			const struct hdn_pt_window_pair *pair = &hdn_pt_windows[cpu].views[view];
			if ((root == (unsigned long *)pair->normal.mm->pgd && pfn == pair->normal.table_pfn) ||
			    (root == (unsigned long *)pair->emergency.mm->pgd && pfn == pair->emergency.table_pfn))
				return true;
		}
	return false;
}
