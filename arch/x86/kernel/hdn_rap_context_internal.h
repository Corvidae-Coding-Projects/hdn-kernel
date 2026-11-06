/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _X86_HDN_RAP_CONTEXT_INTERNAL_H
#define _X86_HDN_RAP_CONTEXT_INTERNAL_H

#include <linux/workqueue.h>
#include <asm/hdn_rap.h>
#include <asm/page.h>
#include <asm/desc_defs.h>

#define RAP_BUCKETS 1024
#define RAP_STACK_PAGES (THREAD_SIZE / PAGE_SIZE)
#define RAP_FRAMES (THREAD_SIZE / sizeof(unsigned long))
#define RAP_STORAGE_PAGES (15 * RAP_STACK_PAGES + 2)
#define RAP_BPF_FRAMES (THREAD_SIZE / 64)
#define RAP_HOOK_FRAMES (2 * RAP_FRAMES)
#define RAP_ASYNC_FRAMES (THREAD_SIZE / sizeof(struct pt_regs))
#define RAP_REG_WORDS (sizeof(struct pt_regs) / sizeof(unsigned long))
#define RAP_PROBE_STEPS 8

struct rap_context;
enum rap_domain { RAP_TASK, RAP_ENTRY, RAP_IRQ, RAP_DF, RAP_EXCEPTION, RAP_FAILURE, RAP_FIRMWARE };
struct rap_link {
	struct rap_context *context;
	struct rap_link *next;
};
struct rap_record {
	unsigned long slot;
	unsigned long target;
	u64 sequence;
	/* Index of a protected hook chain, with a return-in-progress bit.
	 * The original target never comes from a writable tracing database. */
	unsigned long hooks;
};
#define RAP_HOOK_ENTERED BIT(63)
struct rap_return_hook {
	unsigned long next, kind;
	u64 owner_sequence;
};
struct rap_lifetime {
	struct rcu_work retire;
	struct rap_context *context;
};
struct rap_async_frame {
	unsigned long slot, kind, return_top, user, vector;
	unsigned long debug_rewound;
	unsigned long probe_override;
	u64 sequence;
	struct hdn_rap_entry_state entry;
	/* FRED adds event data and reserved words after pt_regs. */
	unsigned long words[RAP_REG_WORDS + 2];
};
struct rap_stack_link {
	struct rap_context *origin;
	unsigned long slot, sp, top, async_top, origin_top, origin_async_top, terminal;
	u64 sequence;
};
struct rap_bpf_checkpoint {
	unsigned long owner, slot, sp, bp, parent_bp;
	unsigned long callee[5];
	unsigned long top, sequence, async_top;
};
struct hdn_rap_probe;
struct rap_probe_step {
	const struct hdn_rap_probe *probe;
	unsigned long flags, async_top;
	u64 sequence;
};
struct rap_context {
	const struct task_struct *owner;
	enum rap_domain domain;
	unsigned int cpu;
	unsigned long begin, end;
	struct rap_lifetime *lifetime;
	unsigned long pfns[RAP_STORAGE_PAGES];
	struct rap_link links[RAP_STACK_PAGES];
	unsigned long top;
	u64 sequence;
	unsigned long switch_ready;
	struct hdn_rap_switch_frame switch_frame;
	struct rap_stack_link bridge;
	unsigned long async_top;
	struct rap_async_frame async[RAP_ASYNC_FRAMES];
	struct rap_record records[RAP_FRAMES];
	/* A hook for every physical return plus graph entries for redirected
	 * functions which reuse that return slot. No allocation in the hook. */
	unsigned long hook_used, hook_free;
	struct rap_return_hook hooks[RAP_HOOK_FRAMES];
	unsigned long bpf_top;
	struct rap_bpf_checkpoint bpf_frames[RAP_BPF_FRAMES];
	unsigned long probe_top;
	struct rap_probe_step probe_steps[RAP_PROBE_STEPS];
};

static __always_inline unsigned int bucket_for(unsigned long address)
{
	return (address >> PAGE_SHIFT) & (RAP_BUCKETS - 1);
}

extern struct rap_context hdn_rap_boot_context;
extern struct rap_context hdn_rap_efi_context;
extern struct rap_link *hdn_rap_buckets[RAP_BUCKETS];
extern bool hdn_rap_private_updates, hdn_rap_async_required;
extern unsigned long hdn_rap_entry_stack_top[NR_CPUS];
struct hdn_rap_failure_cpu {
	unsigned long gsbase, sp, cr3;
	struct desc_ptr gdt;
	struct rap_context *context;
	unsigned long busy;
	unsigned long begin;
};
extern struct hdn_rap_failure_cpu hdn_rap_failure_cpus[NR_CPUS];
void hdn_rap_failure_prepare(void);
void __noreturn hdn_rap_failure_report(unsigned long kind);
struct rap_context *hdn_rap_context_for(unsigned long slot);
void hdn_rap_context_store(struct rap_context *context, unsigned long *word, unsigned long value);
unsigned long hdn_rap_record_target(const struct rap_context *context, const struct rap_record *record);
void hdn_rap_record_discard(struct rap_context *context, struct rap_record *record);
void hdn_rap_bpf_boundary_save(unsigned long sp, unsigned long bp, unsigned long site);
const struct rap_bpf_checkpoint *hdn_rap_bpf_exception_restore(unsigned long site,
		unsigned long live_sp);
void hdn_rap_bpf_tramp_enter(unsigned long slot, unsigned long site, unsigned long resume);
unsigned long hdn_rap_bpf_original_enter(unsigned long slot, unsigned long site, unsigned long bp);
unsigned long hdn_rap_bpf_skip(unsigned long slot, unsigned long site);
struct hdn_rap_bpf_handoff {
	unsigned long target, resume;
};
struct hdn_rap_bpf_handoff hdn_rap_bpf_trace_handoff(unsigned long slot, unsigned long requested);

#endif
