// SPDX-License-Identifier: GPL-2.0-only
#include <linux/hardening.h>
#include <linux/highmem.h>
#include <linux/hdn_execmem.h>
#include <linux/hdn_kernexec.h>
#include <linux/irq_work.h>
#include <linux/nmi.h>
#include <linux/pgtable.h>
#include <linux/overflow.h>
#include <linux/sched.h>
#include <linux/seqlock.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <asm/hdn_text.h>
#include <asm/set_memory.h>

enum hdn_text_state {
	HDN_TEXT_CLOSED,
	HDN_TEXT_PREPARED,
	HDN_TEXT_OPEN,
};

/*
 * The upstream poking mm has exactly one two-page write window. Its PTE lock
 * serializes users before they reach this table. Keep the separate raw lock
 * for status readers and lifecycle checking; never allocate here.
 */
static DEFINE_RAW_SPINLOCK(hdn_text_lock);
static seqcount_raw_spinlock_t hdn_text_seq =
	SEQCNT_RAW_SPINLOCK_ZERO(hdn_text_seq, &hdn_text_lock);
static struct {
	const struct hdn_text_token *token;
	struct task_struct *owner;
	pte_t *ptep;
	u64 generation;
	unsigned long start;
	size_t size;
	unsigned long pfns[2];
	unsigned int cpu;
	unsigned int nr_pages;
	enum hdn_text_kind kind;
	enum hdn_text_state state;
} hdn_window;
static struct hdn_text_window_stats hdn_text_stats;
static pte_t *hdn_text_expected_ptep __ro_after_init;
static atomic64_t hdn_text_audit_omitted = ATOMIC64_INIT(0);
static atomic64_t hdn_text_audit_deferred = ATOMIC64_INIT(0);

/*
 * Debugger/NMI producers cannot wait for a CPU holding an audit lock. A
 * bounded, preallocated mailbox defers emission until normal execution.
 * Slot states are EMPTY -> BUSY -> READY -> BUSY -> EMPTY. Neither an NMI
 * nor a stopped CPU can make another producer spin on an occupied slot.
 * No task pointer survives the transition; deferred events are explicitly
 * kernel events, with no attribution to the workqueue thread.
 */
enum { HDN_AUDIT_EMPTY, HDN_AUDIT_BUSY, HDN_AUDIT_READY };
static struct {
	unsigned int state;
	u64 generation;
	enum hdn_reason reason;
	enum hdn_transition transition;
} hdn_text_mailbox[64];
static bool hdn_text_audit_ready;

static void hdn_text_drain(struct work_struct *work)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(hdn_text_mailbox); i++) {
		if (cmpxchg_acquire(&hdn_text_mailbox[i].state,
				    HDN_AUDIT_READY, HDN_AUDIT_BUSY) != HDN_AUDIT_READY)
			continue;
		hdn_report_kernel_deferred(hdn_text_mailbox[i].transition,
					   hdn_text_mailbox[i].generation,
					   hdn_text_mailbox[i].reason);
		smp_store_release(&hdn_text_mailbox[i].state, HDN_AUDIT_EMPTY);
	}
}
static DECLARE_WORK(hdn_text_audit_work, hdn_text_drain);

static void hdn_text_wake(struct irq_work *work)
{
	schedule_work(&hdn_text_audit_work);
}
static struct irq_work hdn_text_audit_irq = IRQ_WORK_INIT(hdn_text_wake);

void hdn_x86_defer_transition(enum hdn_transition transition, u64 generation,
			       enum hdn_reason reason)
{
	unsigned int i;

	if (transition != HDN_TRANS_KERNEL_TEXT && transition != HDN_TRANS_KERNEL_DESCRIPTOR &&
	    transition != HDN_TRANS_KERNEL_UACCESS)
		panic("HDN invalid deferred kernel transition");
	for (i = 0; i < ARRAY_SIZE(hdn_text_mailbox); i++) {
		if (cmpxchg_acquire(&hdn_text_mailbox[i].state,
				    HDN_AUDIT_EMPTY, HDN_AUDIT_BUSY) != HDN_AUDIT_EMPTY)
			continue;
		hdn_text_mailbox[i].generation = generation;
		hdn_text_mailbox[i].reason = reason;
		hdn_text_mailbox[i].transition = transition;
		smp_store_release(&hdn_text_mailbox[i].state, HDN_AUDIT_READY);
		atomic64_inc(&hdn_text_audit_deferred);
		if (smp_load_acquire(&hdn_text_audit_ready))
			irq_work_queue(&hdn_text_audit_irq);
		return;
	}
	atomic64_inc(&hdn_text_audit_omitted);
}

static int __init hdn_text_audit_init(void)
{
	/* Boot producers can fill mailboxes before workqueues/irq_work exist. */
	smp_store_release(&hdn_text_audit_ready, true);
	schedule_work(&hdn_text_audit_work);
	return 0;
}
early_initcall(hdn_text_audit_init);

static __noreturn void hdn_text_reject(void)
{
	/* May be in a debugger with every other CPU stopped: take no audit locks. */
	panic("HDN kernel text transition invariant failed");
}

void __init hdn_text_bind_window(pte_t *ptep)
{
	if (!ptep || hdn_text_expected_ptep || !pte_none(ptep_get(ptep)) ||
	    !pte_none(ptep_get(ptep + 1)))
		hdn_text_reject();
	hdn_text_expected_ptep = ptep;
}

static bool hdn_text_owner(const struct hdn_text_token *token, pte_t *ptep,
			   enum hdn_text_state state)
{
	return hdn_window.token == token && hdn_window.generation == token->generation &&
	       hdn_window.owner == current && hdn_window.cpu == raw_smp_processor_id() &&
	       hdn_window.ptep == ptep && hdn_window.state == state;
}

static bool hdn_text_page_allowed(struct page *page)
{
	unsigned long pfn = page_to_pfn(page);

	if (!hdn_execmem_text_page(page))
		return false;
	/* Sealed static data and descriptors cannot borrow the text adapter. */
	if (hdn_kernel_sealed_data_page(pfn))
		return false;
	return true;
}

void hdn_text_prepare(struct hdn_text_token *token, void *address, size_t size,
		      struct page **pages, pte_t *ptep, enum hdn_text_kind kind)
{
	unsigned long start = (unsigned long)address, end, flags;
	bool invalid;
	unsigned int nr = size > PAGE_SIZE - offset_in_page(start) ? 2 : 1;

	lockdep_assert_irqs_disabled();
	raw_spin_lock_irqsave(&hdn_text_lock, flags);
	write_seqcount_begin(&hdn_text_seq);
	invalid = ptep != hdn_text_expected_ptep ||
		  hdn_window.state != HDN_TEXT_CLOSED || !size ||
		  size > 2 * PAGE_SIZE - offset_in_page(start) ||
		  check_add_overflow(start, size, &end) ||
		  (unsigned int)kind >= HDN_TEXT_KIND_COUNT ||
		  !pages[0] || (nr == 2 && !pages[1]) ||
		  (pages[0] && !hdn_text_page_allowed(pages[0])) ||
		  (nr == 2 && pages[1] && !hdn_text_page_allowed(pages[1])) ||
		  !pte_none(ptep_get(ptep)) || !pte_none(ptep_get(ptep + 1)) ||
		  hdn_text_stats.started == U64_MAX;
	if (invalid) {
		hdn_text_stats.rejected++;
	} else {
		token->generation = ++hdn_text_stats.started;
		hdn_window.token = token;
		hdn_window.owner = current;
		hdn_window.ptep = ptep;
		hdn_window.generation = token->generation;
		hdn_window.start = start;
		hdn_window.size = size;
		hdn_window.pfns[0] = page_to_pfn(pages[0]);
		hdn_window.pfns[1] = nr == 2 ? page_to_pfn(pages[1]) : 0;
		hdn_window.cpu = raw_smp_processor_id();
		hdn_window.nr_pages = nr;
		hdn_window.kind = kind;
		hdn_window.state = HDN_TEXT_PREPARED;
		hdn_text_stats.active = true;
	}
	write_seqcount_end(&hdn_text_seq);
	raw_spin_unlock_irqrestore(&hdn_text_lock, flags);
	if (invalid)
		hdn_text_reject();
}

void hdn_text_open(struct hdn_text_token *token, pte_t *ptep, void *address,
		   size_t size, enum hdn_text_kind kind)
{
	unsigned long flags;
	bool invalid;
	unsigned int i;

	lockdep_assert_irqs_disabled();
	raw_spin_lock_irqsave(&hdn_text_lock, flags);
	write_seqcount_begin(&hdn_text_seq);
	invalid = !hdn_text_owner(token, ptep, HDN_TEXT_PREPARED) ||
		  hdn_window.start != (unsigned long)address ||
		  hdn_window.size != size || hdn_window.kind != kind;
	for (i = 0; !invalid && i < hdn_window.nr_pages; i++) {
		pte_t pte = ptep_get(ptep + i);
		pteval_t val = pte_val(pte);

		invalid = !(val & _PAGE_PRESENT) || !(val & _PAGE_RW) ||
			  (val & (_PAGE_USER | _PAGE_GLOBAL)) ||
			  (kernel_wx_enforced() && !(val & _PAGE_NX)) ||
			  pte_pfn(pte) != hdn_window.pfns[i];
	}
	if (!invalid && hdn_window.nr_pages == 1)
		invalid = !pte_none(ptep_get(ptep + 1));
	if (invalid)
		hdn_text_stats.rejected++;
	else
		hdn_window.state = HDN_TEXT_OPEN;
	write_seqcount_end(&hdn_text_seq);
	raw_spin_unlock_irqrestore(&hdn_text_lock, flags);
	if (invalid)
		hdn_text_reject();
}

/* Page-table admission normally rejects every writable alias of sealed
 * execmem.  The text-poke mm is the sole exception, and only while the exact
 * prebound PTE slot is being opened by its current owner.  Binding the slot as
 * well as the PFN prevents this lifecycle token from authorizing an alias in
 * any other root or at any other virtual address. */
bool hdn_text_leaf_allowed(const unsigned long *slot, unsigned long pfn,
			   unsigned long nr, unsigned long flags)
{
	unsigned long irqflags;
	unsigned int index = ARRAY_SIZE(hdn_window.pfns);
	bool allowed;

	lockdep_assert_irqs_disabled();
	raw_spin_lock_irqsave(&hdn_text_lock, irqflags);
	if (hdn_window.ptep && slot == (const unsigned long *)hdn_window.ptep)
		index = 0;
	else if (hdn_window.ptep &&
		 slot == (const unsigned long *)(hdn_window.ptep + 1))
		index = 1;
	allowed = nr == 1 && index < hdn_window.nr_pages &&
		hdn_window.state == HDN_TEXT_PREPARED &&
		hdn_window.token &&
		hdn_window.generation == hdn_window.token->generation &&
		hdn_window.owner == current &&
		hdn_window.cpu == raw_smp_processor_id() &&
		hdn_window.pfns[index] == pfn &&
		(flags & (_PAGE_PRESENT | _PAGE_RW | _PAGE_NX)) ==
			 (_PAGE_PRESENT | _PAGE_RW | _PAGE_NX) &&
		!(flags & (_PAGE_USER | _PAGE_GLOBAL));
	raw_spin_unlock_irqrestore(&hdn_text_lock, irqflags);
	return allowed;
}

/* Called only after clearing both aliases, leaving the mm and flushing it. */
void hdn_text_close(struct hdn_text_token *token, pte_t *ptep)
{
	unsigned long flags;
	bool invalid;

	lockdep_assert_irqs_disabled();
	raw_spin_lock_irqsave(&hdn_text_lock, flags);
	write_seqcount_begin(&hdn_text_seq);
	invalid = !hdn_text_owner(token, ptep, HDN_TEXT_OPEN) ||
		  !pte_none(ptep_get(ptep)) || !pte_none(ptep_get(ptep + 1));
	if (invalid) {
		hdn_text_stats.rejected++;
	} else {
		hdn_text_stats.completed++;
		hdn_text_stats.active = false;
		memset(&hdn_window, 0, sizeof(hdn_window));
	}
	write_seqcount_end(&hdn_text_seq);
	raw_spin_unlock_irqrestore(&hdn_text_lock, flags);
	if (invalid)
		hdn_text_reject();
}

void hdn_text_report(const struct hdn_text_token *token, enum hdn_text_kind kind)
{
	static const enum hdn_reason reasons[HDN_TEXT_KIND_COUNT] = {
		[HDN_TEXT_LIVE_PATCH] = HDN_REASON_KERNEL_TEXT_PATCH,
		[HDN_TEXT_DEBUGGER] = HDN_REASON_KERNEL_TEXT_DEBUGGER,
		[HDN_TEXT_UNUSED_CODE] = HDN_REASON_KERNEL_TEXT_CONSTRUCT,
		[HDN_TEXT_TRAP_FILL] = HDN_REASON_KERNEL_TEXT_TRAP_FILL,
	};

	/* The existing bounded audit ring may throttle records; counters do not. */
	if ((unsigned int)kind >= HDN_TEXT_KIND_COUNT)
		hdn_text_reject();
	/* A debugger may stop an audit-ring owner. Never wait on that owner. */
	if (kind == HDN_TEXT_DEBUGGER || in_nmi()) {
		hdn_x86_defer_transition(HDN_TRANS_KERNEL_TEXT, token->generation, reasons[kind]);
		return;
	}
	hdn_report_kernel_text_transition(token->generation, reasons[kind], 0);
}

void hdn_text_get_stats(struct hdn_text_window_stats *stats)
{
	unsigned int seq;

	/* Readers must not strand a writer lock when KGDB stops another CPU. */
	do {
		seq = read_seqcount_begin(&hdn_text_seq);
		*stats = hdn_text_stats;
	} while (read_seqcount_retry(&hdn_text_seq, seq));
	stats->audit_omitted = atomic64_read(&hdn_text_audit_omitted);
	stats->audit_deferred = atomic64_read(&hdn_text_audit_deferred);
}
