/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_HDN_STACK_MM_H
#define _ASM_X86_HDN_STACK_MM_H

#include <linux/types.h>
#include <linux/init.h>

struct task_struct;
struct mm_struct;
struct hdn_stack_switch {
	unsigned long sp, cr3;
};
struct hdn_stack_startup {
	unsigned long apicid, gsbase, sp, cr3, resume;
};

#ifdef CONFIG_SECURITY_HARDENING_PRIVATE_STACKS
void __init hdn_stack_mm_init(void);
void __init hdn_stack_mm_online(void);
void __init hdn_stack_mm_walk(void (*visit)(unsigned long *root, unsigned int order));
unsigned int hdn_stack_mm_view(unsigned int cpu, unsigned long cr3);
unsigned long hdn_stack_mm_route(unsigned long cr3);
unsigned long hdn_stack_mm_route_kernel(unsigned long cr3);
unsigned long hdn_stack_mm_expected(unsigned long canonical_cr3);
bool hdn_stack_mm_matches(unsigned long canonical_cr3, unsigned long actual_cr3);
bool hdn_stack_mm_sync_owned(const struct mm_struct *mm, unsigned long address);
bool hdn_stack_mm_update_begin(unsigned int level);
void hdn_stack_mm_update_end(unsigned long pfn, unsigned int offset,
		unsigned long value, unsigned int level);
void hdn_stack_mm_update_abort(void);
bool hdn_stack_mm_in_use(unsigned long begin);
const struct hdn_stack_switch *hdn_stack_mm_prepare(struct task_struct *prev,
		struct task_struct *next, unsigned long next_sp);
void hdn_stack_mm_finish(void);
bool hdn_stack_mm_active(const struct task_struct *owner, unsigned long address);
bool hdn_stack_mm_async_enter(void);
void hdn_stack_mm_async_exit(unsigned long cr3, bool gdt_window);
void hdn_stack_mm_cpu_prepare(unsigned int cpu, struct task_struct *idle);
unsigned long hdn_stack_mm_cpu_enter(void);
void hdn_stack_mm_resume_prepare(unsigned long sp);
void hdn_stack_mm_resume_finish(void);
#else
static inline void hdn_stack_mm_init(void) { }
static inline void hdn_stack_mm_online(void) { }
static inline void hdn_stack_mm_walk(void (*visit)(unsigned long *, unsigned int)) { }
static inline unsigned int hdn_stack_mm_view(unsigned int cpu, unsigned long cr3) { return 0; }
static inline unsigned long hdn_stack_mm_route(unsigned long cr3) { return cr3; }
static inline unsigned long hdn_stack_mm_route_kernel(unsigned long cr3) { return cr3; }
static inline unsigned long hdn_stack_mm_expected(unsigned long cr3) { return cr3; }
static inline bool hdn_stack_mm_matches(unsigned long canonical_cr3, unsigned long actual_cr3)
{
	return canonical_cr3 == actual_cr3;
}
static inline bool hdn_stack_mm_sync_owned(const struct mm_struct *mm, unsigned long address)
{
	return false;
}
static inline bool hdn_stack_mm_update_begin(unsigned int level) { return false; }
static inline void hdn_stack_mm_update_end(unsigned long pfn, unsigned int offset,
		unsigned long value, unsigned int level) { }
static inline void hdn_stack_mm_update_abort(void) { }
static inline bool hdn_stack_mm_in_use(unsigned long begin) { return false; }
#endif
#endif
