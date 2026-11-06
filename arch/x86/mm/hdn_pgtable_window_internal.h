/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _X86_HDN_PGTABLE_WINDOW_INTERNAL_H
#define _X86_HDN_PGTABLE_WINDOW_INTERNAL_H

/* A supervisor-only mapping in a private lower half cannot collide with any
 * ordinary kernel virtual address. It is non-global and never joins an mm's
 * user-visible page tables. Two guarded empty slots surround the target; the
 * separate self mapping is only used after switching to this private CR3. */
/* A permanent window must not move when current is a compat/ADDR32 task.
 * This hierarchy is private and supervisor-only; it does not use that task's
 * userspace allocation geometry. */
#define HDN_PT_BASE	(__TASK_UNMAPPED_BASE(DEFAULT_MAP_WINDOW) & PMD_MASK)
#define HDN_PT_TARGET	(HDN_PT_BASE + PAGE_SIZE)
#define HDN_PT_SELF	(HDN_PT_BASE + 3 * PAGE_SIZE)
#define HDN_PT_SLOT	1
#define HDN_PT_SELF_SLOT	3

struct hdn_pt_window {
	struct mm_struct *mm;
	unsigned long cr3;
	unsigned long table_pfn;
	pte_t *table;
};

struct hdn_pt_window_pair {
	struct hdn_pt_window normal;
	struct hdn_pt_window emergency;
};

#ifdef CONFIG_SECURITY_HARDENING_PRIVATE_STACKS
#define HDN_PT_VIEWS 3
#else
#define HDN_PT_VIEWS 1
#endif
struct hdn_pt_windows {
	struct hdn_pt_window_pair views[HDN_PT_VIEWS];
	unsigned long gdt_base, gdt_pfn;
};

extern struct hdn_pt_windows hdn_pt_windows[NR_CPUS];
struct hdn_pt_cpu_identity {
	unsigned long gsbase;
	unsigned int cpu;
};
extern struct hdn_pt_cpu_identity hdn_pt_cpu_identities[NR_CPUS];
extern unsigned int hdn_pt_cpu_count;

#endif
