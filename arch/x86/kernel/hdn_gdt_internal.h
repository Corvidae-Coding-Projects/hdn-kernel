/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _X86_HDN_GDT_INTERNAL_H
#define _X86_HDN_GDT_INTERNAL_H

#include <linux/mm_types.h>
#include <linux/threads.h>
#include <asm/pgtable_types.h>

#define HDN_GDT_ALIAS __TASK_UNMAPPED_BASE(DEFAULT_MAP_WINDOW)

struct hdn_gdt_window {
	struct mm_struct *mm;
	pte_t *pte;
	unsigned long cr3;
};

struct hdn_gdt_config {
	unsigned long pfn, gsbase, gdt_base;
	struct hdn_gdt_window normal;
	struct hdn_gdt_window emergency;
};

struct hdn_gdt_identity {
	unsigned long gsbase;
	unsigned int cpu;
};

extern struct hdn_gdt_config hdn_gdt_configs[NR_CPUS];
extern struct hdn_gdt_identity hdn_gdt_identities[NR_CPUS];
extern unsigned int hdn_gdt_cpu_count;
extern bool hdn_gdt_ready;

#endif
