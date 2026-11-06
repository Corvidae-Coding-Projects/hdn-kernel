// SPDX-License-Identifier: GPL-2.0-only
/* Permanent per-CPU stack branches and adjacent PTI root pairs. */
#include <linux/mm.h>
#include <linux/percpu.h>
#include <asm/pgalloc.h>
#include <asm/mmu_context.h>
#include <asm/smp.h>
#include <asm/apic.h>
#include <asm/desc.h>
#include "hdn_stack_mm_internal.h"
#include "hdn_pgtable_window_internal.h"

struct hdn_stack_cpu hdn_stack_cpus[NR_CPUS] __ro_after_init;
bool hdn_stack_mm_ready __ro_after_init;
struct hdn_stack_startup hdn_stack_startup[NR_CPUS] __ro_after_init;

static unsigned long *__init allocate_table(unsigned int order, unsigned int cpu)
{
	struct page *page = alloc_pages_node(cpu_to_node(cpu), GFP_KERNEL | __GFP_ZERO, order);

	if (!page)
		panic("HDN could not allocate private stack page tables");
	return page_address(page);
}

static void __init install_branch(unsigned long *pgd, const struct hdn_stack_view *view)
{
	unsigned long child = (unsigned long)(pgtable_l5_enabled() ? view->kernel_p4d : view->pud);

	WRITE_ONCE(pgd[pgd_index(hdn_stack_region)], __pa(child) | _KERNPG_TABLE);
}

void __init hdn_stack_mm_init(void)
{
	unsigned int cpu;

	BUILD_BUG_ON(HDN_PT_VIEWS != HDN_STACK_VIEWS);
	if (!hdn_stack_region)
		panic("HDN private stack region was not reserved");
	for (cpu = 0; cpu < NR_CPUS; cpu++)
		hdn_stack_startup[cpu].apicid = BAD_APICID;
	for_each_possible_cpu(cpu) {
		hdn_stack_cpus[cpu].gdt_base = (unsigned long)get_cpu_gdt_ro(cpu);
		hdn_stack_cpus[cpu].gdt_pfn = get_cpu_gdt_paddr(cpu) >> PAGE_SHIFT;
		hdn_stack_startup[cpu].apicid = cpuid_to_apicid[cpu];
		hdn_stack_startup[cpu].gsbase = cpu_kernelmode_gs_base(cpu);
		for (unsigned int index = 0; index < HDN_STACK_VIEWS; index++) {
			struct hdn_stack_view *view = &hdn_stack_cpus[cpu].views[index];
			struct hdn_pt_window_pair *windows = &hdn_pt_windows[cpu].views[index];
			unsigned int pgd_slot = pgd_index(hdn_stack_region);
			unsigned int p4d_slot = (hdn_stack_region >> P4D_SHIFT) & (PTRS_PER_PTE - 1);

			view->pgd = allocate_table(pgd_allocation_order(), cpu);
			view->pud = allocate_table(0, cpu);
			view->pmd = allocate_table(0, cpu);
			view->pte = allocate_table(0, cpu);
			/* Connect empty leaves so boot ownership discovery covers every
			 * page, including leaves not yet assigned to any task. */
			view->pud[0] = __pa(view->pmd) | _KERNPG_TABLE;
			view->pmd[0] = __pa(view->pte) | _KERNPG_TABLE;
			memcpy(view->pgd, init_mm.pgd, PAGE_SIZE << pgd_allocation_order());
			if (pgtable_l5_enabled()) {
				unsigned long entry = view->pgd[pgd_slot];

				view->kernel_p4d = allocate_table(0, cpu);
				if (entry & _PAGE_PRESENT)
					memcpy(view->kernel_p4d, __va(entry & PTE_PFN_MASK), PAGE_SIZE);
				view->kernel_p4d[p4d_slot] = __pa(view->pud) | _KERNPG_TABLE;
			}
			install_branch(view->pgd, view);
			install_branch((unsigned long *)windows->normal.mm->pgd, view);
			install_branch((unsigned long *)windows->emergency.mm->pgd, view);
			view->cr3 = __pa(view->pgd);
		}
	}
}

void __init hdn_stack_mm_walk(void (*visit)(unsigned long *, unsigned int))
{
	unsigned int cpu;

	for_each_possible_cpu(cpu)
		for (unsigned int index = 0; index < HDN_STACK_VIEWS; index++)
			visit(hdn_stack_cpus[cpu].views[index].pgd, pgd_allocation_order());
}

void __init hdn_stack_mm_online(void)
{
	unsigned int cpu;

	/* CPA may have installed additional top-level branches during sealing.
	 * Refresh from the final canonical roots before enabling replication. */
	for_each_possible_cpu(cpu)
		for (unsigned int index = 0; index < HDN_STACK_VIEWS; index++)
			hdn_stack_mm_refresh(&hdn_stack_cpus[cpu].views[index], __pa(init_mm.pgd) >> PAGE_SHIFT, true);
	smp_store_release(&hdn_stack_mm_ready, true);
}
