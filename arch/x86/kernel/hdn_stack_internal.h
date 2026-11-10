/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _X86_HDN_STACK_INTERNAL_H
#define _X86_HDN_STACK_INTERNAL_H

#include <linux/hdn_stack.h>
#include <linux/atomic.h>
#include <linux/workqueue.h>
#include <asm/page.h>

#define HDN_STACK_BUCKETS 1024
#define HDN_STACK_PAGES (THREAD_SIZE / PAGE_SIZE)
#define HDN_STACK_STRIDE (2 * THREAD_SIZE)

struct hdn_stack_storage;
struct hdn_stack_lifetime {
	struct rcu_work retire;
	struct hdn_stack_storage *storage;
};

/* Every field, including the registry link and publication bit, is read-only
 * in ordinary CR3s. Only the closed physical window updates these fields. */
struct hdn_stack_storage {
	const struct task_struct *owner, *builder;
	struct hdn_stack_storage *next;
	struct hdn_stack_lifetime *lifetime;
	struct vm_struct *backing;
	void *construction_address;
	unsigned long begin, generation, slot, published, header_pfn;
	unsigned long pfns[HDN_STACK_PAGES];
};

extern unsigned long hdn_stack_region;
extern unsigned long hdn_stack_boot_retired;
extern struct hdn_stack_storage *hdn_stack_buckets[HDN_STACK_BUCKETS];
extern atomic64_t stack_publications;
extern atomic64_t stack_diagnostic_reads;
extern atomic64_t stack_diagnostic_read_failures;
extern atomic64_t stack_construction_bytes;
extern atomic64_t stack_switches;
extern atomic64_t stack_async_root_entries;

static __always_inline unsigned int hdn_stack_bucket(unsigned long address)
{
	return (address / HDN_STACK_STRIDE) & (HDN_STACK_BUCKETS - 1);
}

/* Caller pins the task stack or keeps local IRQs disabled. Registry removal
 * waits for an RCU grace period before releasing the immutable descriptor. */
struct hdn_stack_storage *hdn_stack_lookup(unsigned long address);
void hdn_stack_store(struct hdn_stack_storage *storage,
		     unsigned long *word, unsigned long value);
void hdn_stack_publish_storage(struct hdn_stack_storage *storage);
int hdn_stack_failure_create(unsigned int cpu, unsigned long *begin, unsigned long *cr3);
static __always_inline void hdn_stack_account_switch(void)
{
	atomic64_inc(&stack_switches);
}

static __always_inline void hdn_stack_account_async_root(void)
{
	atomic64_inc(&stack_async_root_entries);
}

static __always_inline void hdn_stack_account_read(bool failed)
{
	atomic64_inc(&stack_diagnostic_reads);
	if (failed)
		atomic64_inc(&stack_diagnostic_read_failures);
}

static __always_inline void hdn_stack_account_construct(size_t bytes)
{
	atomic64_add(bytes, &stack_construction_bytes);
}

static __always_inline void hdn_stack_account_publication(void)
{
	atomic64_inc(&stack_publications);
}

#endif
