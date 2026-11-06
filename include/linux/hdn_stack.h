/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_HDN_STACK_H
#define _LINUX_HDN_STACK_H

#include <linux/types.h>
#include <linux/init.h>

struct task_struct;
struct vm_struct;
struct pt_regs;

struct hdn_stack_stats {
	u64 allocation_attempts;
	u64 allocations;
	u64 allocation_failures;
	u64 live_stacks;
	u64 publications;
	u64 retirements;
	u64 diagnostic_reads;
	u64 diagnostic_read_failures;
	u64 construction_bytes;
	u64 task_switches;
	u64 async_root_entries;
};

/* Internal task lifecycle and bounded diagnostic interface. These symbols
 * are deliberately not exported and never return a writable backing alias. */
#ifdef CONFIG_SECURITY_HARDENING_PRIVATE_STACKS
void __init hdn_stack_reserve(void);
int hdn_stack_alloc(struct task_struct *task, int node);
void hdn_stack_free(struct task_struct *task);
int hdn_stack_read(const struct task_struct *task, unsigned long address,
		   void *destination, size_t size);
int hdn_stack_construct(struct task_struct *task, unsigned long address,
			const void *source, size_t size);
void hdn_stack_publish(struct task_struct *task);
bool hdn_stack_address(unsigned long address);
bool hdn_stack_overlaps(unsigned long address, size_t size);
bool hdn_stack_retired_pfns(unsigned long pfn, unsigned long nr);
unsigned long hdn_stack_task_reg(const struct task_struct *task, unsigned int offset);
void hdn_stack_regs_snapshot(struct task_struct *task, struct pt_regs *snapshot);
int hdn_stack_syscall_commit(struct task_struct *task, const struct pt_regs *before,
			     const struct pt_regs *after);
struct pt_regs *hdn_stack_bpf_regs(struct task_struct *task);
void __noreturn hdn_stack_bootstrap(void);
void hdn_stack_bootstrap_retire(void);
void __noreturn hdn_stack_bootstrap_continue(void);
void hdn_stack_vmcoreinfo(void);
const char *hdn_stack_state(void);
void hdn_stack_get_stats(struct hdn_stack_stats *stats);
#ifdef CONFIG_SECURITY_HARDENING_PRIVATE_STACKS_TEST
int hdn_stack_test_current(unsigned int mode);
#endif
#else
static inline void hdn_stack_reserve(void) { }
static inline bool hdn_stack_address(unsigned long address) { return false; }
static inline bool hdn_stack_overlaps(unsigned long address, size_t size) { return false; }
static inline bool hdn_stack_retired_pfns(unsigned long pfn, unsigned long nr) { return false; }
static inline void hdn_stack_vmcoreinfo(void) { }
static inline const char *hdn_stack_state(void) { return "disabled"; }
static inline void hdn_stack_get_stats(struct hdn_stack_stats *stats)
{
	*stats = (struct hdn_stack_stats) { };
}
#endif

#endif
