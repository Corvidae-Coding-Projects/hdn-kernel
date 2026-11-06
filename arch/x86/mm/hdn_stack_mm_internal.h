/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _X86_HDN_STACK_MM_INTERNAL_H
#define _X86_HDN_STACK_MM_INTERNAL_H

#include <asm/hdn_stack_mm.h>
#include <asm/pgtable.h>
#include "../kernel/hdn_stack_internal.h"

#define HDN_STACK_TASK_VIEWS 2
#define HDN_STACK_FAILURE_VIEW 2
#define HDN_STACK_VIEWS 3
struct hdn_stack_view {
	unsigned long *pgd, *kernel_p4d, *pud, *pmd, *pte;
	unsigned long cr3;
	/* Mutable only through the private window while holding mirror_lock. */
	unsigned long canonical_pgd, canonical_p4d, canonical_pair;
	const struct hdn_stack_storage *stack;
	struct hdn_stack_switch transition;
};
struct hdn_stack_cpu {
	unsigned long gdt_base, gdt_pfn;
	struct hdn_stack_view views[HDN_STACK_VIEWS];
};

extern struct hdn_stack_cpu hdn_stack_cpus[NR_CPUS];
extern bool hdn_stack_mm_ready;
extern struct hdn_stack_startup hdn_stack_startup[NR_CPUS];
void hdn_stack_mm_refresh(struct hdn_stack_view *view, unsigned long canonical_pfn, bool paired);
unsigned long hdn_stack_mm_failure_install(unsigned int cpu,
		const struct hdn_stack_storage *storage);

#endif
