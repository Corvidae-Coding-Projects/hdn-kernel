// SPDX-License-Identifier: GPL-2.0-only
/* Page-table ownership and deferred destruction; mutations use private CR3s. */
#include <linux/export.h>
#include <linux/efi.h>
#include <linux/cpuset.h>
#include <linux/cc_platform.h>
#include <xen/xen.h>
#include <linux/gfp.h>
#include <linux/hdn_pgtable.h>
#include <linux/hdn_execmem.h>
#include <linux/hdn_hibernate.h>
#include <linux/init.h>
#include <linux/kexec.h>
#include <linux/memcontrol.h>
#include <linux/mm.h>
#include <linux/overflow.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/set_memory.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/xarray.h>
#include <asm/hdn_pgtable.h>
#include <asm/acpi.h>
#include <asm/hdn_hv_crash.h>
#include <asm/pgalloc.h>
#include <asm/sections.h>
#include <asm/realmode.h>
#include <asm/text-patching.h>
#include <asm/x86_init.h>
#include <asm/set_memory.h>
#include <asm/suspend.h>
#include <asm/tlbflush.h>
#include "hdn_pgtable_internal.h"
#include <asm/hdn_stack_mm.h>

enum hdn_pt_state {
	HDN_PT_SEALING,
	HDN_PT_RESERVE,
	HDN_PT_LIVE,
	HDN_PT_RETIRING,
	HDN_PT_UNSEALING,
	HDN_PT_DEAD,
	HDN_PT_FROZEN,
};

struct hdn_pt_transition {
	struct list_head pages;
	const void *owner;
};

struct hdn_pt_record {
	struct rcu_head rcu;
	struct work_struct destroy;
	struct list_head reserve;
	struct page *page;
	struct task_struct *owner;
	unsigned int order;
	atomic_t state;
	atomic_t level[2];
	bool boot;
	bool code;
	struct hdn_pt_transition *transition;
};

static DEFINE_XARRAY(pt_pages);
static DEFINE_RAW_SPINLOCK(reserve_lock);
static LIST_HEAD(reserve_pages);
static unsigned int reserve_count[MAX_NUMNODES][2];
static atomic64_t reserved_pages;
bool hdn_pt_writes_ready __ro_after_init;
EXPORT_SYMBOL_GPL(hdn_pt_writes_ready);
static bool allocation_ready __ro_after_init;
static bool admission_ready __ro_after_init;
static const char *runtime_state __ro_after_init = "initializing";
static const char *firmware_wx_state __ro_after_init = "initializing";
static atomic64_t allocations, retirements, active_pages, allocation_failures;
static atomic64_t foreign_code_ranges, foreign_code_pages;

/* Atomic callers and CPA splits cannot recursively split a direct-map entry
 * while allocating the very page table needed for that split. Presealed pages
 * close that recursion. Normal allocations remain NUMA/memcg-aware; the reserve
 * is bounded and exhaustion fails the original allocation without an RW page.
 */
#define HDN_PT_RESERVE_0 128
#define HDN_PT_RESERVE_1 16
static void refill_reserve(struct work_struct *work);
static DECLARE_WORK(refill_work, refill_reserve);

bool hdn_pt_active(void)
{
	return smp_load_acquire(&allocation_ready);
}

bool hdn_pt_platform_supported(void)
{
	return !xen_pv_domain() && !cc_platform_has(CC_ATTR_MEM_ENCRYPT) &&
		kernel_wx_enforced();
}

const char *hdn_pt_state(void)
{
	return READ_ONCE(runtime_state);
}

const char *hdn_pt_firmware_state(void)
{
	return READ_ONCE(firmware_wx_state);
}

const char *hdn_pt_terminal_state(void)
{
	const char *state = READ_ONCE(runtime_state);

	/* Current-kernel terminal roots and code are owned and immutable. The
	 * peer kernel or firmware owns execution after the irreversible handoff. */
	return !strcmp(state, "active") ? "degraded-external-domain" : state;
}

void __init hdn_pt_efi_wx_result(bool runtime_present, bool active)
{
	if (!hdn_pt_platform_supported())
		WRITE_ONCE(firmware_wx_state, "unsupported-platform");
	else if (!runtime_present)
		WRITE_ONCE(firmware_wx_state, "not-present");
	else
		WRITE_ONCE(firmware_wx_state, active ? "active" : "runtime-disabled");
}

void hdn_pt_get_stats(struct hdn_pt_stats *stats)
{
	stats->allocated = atomic64_read(&allocations);
	stats->retired = atomic64_read(&retirements);
	stats->active_pages = atomic64_read(&active_pages);
	stats->reserve_pages = atomic64_read(&reserved_pages);
	stats->allocation_failures = atomic64_read(&allocation_failures);
	stats->foreign_code_ranges = atomic64_read(&foreign_code_ranges);
	stats->foreign_code_pages = atomic64_read(&foreign_code_pages);
}

bool hdn_pt_protected_pfn(unsigned long first, unsigned long last)
{
	bool protected;

	rcu_read_lock();
	protected = xa_find(&pt_pages, &first, last, XA_PRESENT) != NULL;
	rcu_read_unlock();
	return protected;
}

int hdn_pt_mapping(unsigned long address, unsigned long pfn,
		   unsigned long nr, unsigned long flags)
{
	struct hdn_pt_record *record;
	unsigned long last, index = pfn;
	int error = 0;

	if (!nr || nr - 1 > ULONG_MAX - pfn ||
	    nr - 1 > (ULONG_MAX - address) >> PAGE_SHIFT)
		return -EINVAL;
	last = pfn + nr - 1;
	rcu_read_lock();
	xa_for_each_range(&pt_pages, index, record, pfn, last) {
		unsigned long alias = address + ((index - pfn) << PAGE_SHIFT);
		int state = atomic_read_acquire(&record->state);
		bool teardown = state == HDN_PT_UNSEALING &&
			READ_ONCE(record->owner) == current && !in_interrupt();
		bool construction = state == HDN_PT_SEALING &&
			READ_ONCE(record->owner) == current && !in_interrupt();
		bool canonical = alias == (unsigned long)__va(index << PAGE_SHIFT);
		bool image = index >= PFN_DOWN(__pa_symbol(_text)) &&
			index < PFN_UP(__pa_symbol(_end)) &&
			alias == index * PAGE_SIZE + __START_KERNEL_map - phys_base;

		if (!(flags & _PAGE_PRESENT)) {
			/* Private storage keeps its canonical read view until retirement. */
			if (alias == (unsigned long)__va(index << PAGE_SHIFT) && !teardown)
				error = -EPERM;
		} else if (!(flags & _PAGE_NX) && (!record->code || (flags & _PAGE_RW))) {
			error = -EPERM;
		} else if ((flags & _PAGE_RW) &&
			   !(teardown && canonical) && !(construction && (canonical || image))) {
			error = -EPERM;
		}
		if (error)
			break;
	}
	rcu_read_unlock();
	return error;
}

static void destroy_record(struct work_struct *work)
{
	struct hdn_pt_record *record = container_of(work, struct hdn_pt_record, destroy);
	unsigned long pfn = page_to_pfn(record->page);
	unsigned int pages = 1U << record->order;

	if (atomic_read(&record->state) != HDN_PT_RETIRING || record->boot)
		panic("HDN page-table retirement ownership mismatch");
	for (unsigned int i = 0; i < pages; i++)
		hdn_pt_window_clear(pfn + i);
	WRITE_ONCE(record->owner, current);
	atomic_set_release(&record->state, HDN_PT_UNSEALING);
	/* Only this work item can restore the exact direct-map view. No new
	 * writable alias is admitted while the registry still owns the page. */
	if (set_memory_rw((unsigned long)page_address(record->page), pages))
		panic("HDN could not retire a page-table mapping");
	atomic_set_release(&record->state, HDN_PT_DEAD);
	for (unsigned int i = 0; i < pages; i++)
		if (xa_erase(&pt_pages, pfn + i) != record)
			panic("HDN page-table ownership was replaced during retirement");
	atomic64_sub(pages, &active_pages);
	atomic64_inc(&retirements);
	__free_pages(record->page, record->order);
	kfree_rcu(record, rcu);
}

bool hdn_pt_free(struct page *page, unsigned int order)
{
	struct hdn_pt_record *record;
	bool found;

	rcu_read_lock();
	record = xa_load(&pt_pages, page_to_pfn(page));
	found = record != NULL;
	if (record) {
		if (record->page != page || record->order != order || record->boot || record->transition ||
		    atomic_cmpxchg(&record->state, HDN_PT_LIVE, HDN_PT_RETIRING) != HDN_PT_LIVE)
			panic("HDN rejected an invalid page-table destruction");
		/* Generic MM has already completed its TLB/RCU ownership protocol.
		 * Actual unsealing/freeing always runs outside page-table locks. */
		if (!queue_work(system_unbound_wq, &record->destroy))
			panic("HDN page-table destruction queued twice");
	}
	rcu_read_unlock();
	return found;
}
EXPORT_SYMBOL_GPL(hdn_pt_free);

void hdn_pt_release_reserved(struct page *page)
{
	unsigned long pfn = page_to_pfn(page);
	struct hdn_pt_record *record = xa_load(&pt_pages, pfn);

	if (!record)
		return;
	/* Memory-hotremove calls this after unlinking the empty table and a
	 * global TLB flush. Keep its original bootmem accounting/free routine. */
	if (in_interrupt() || irqs_disabled() || !PageReserved(page) ||
	    record->page != page || record->order || record->transition ||
	    (pfn >= PFN_DOWN(__pa_symbol(_text)) && pfn < PFN_UP(__pa_symbol(_end))) ||
	    atomic_cmpxchg(&record->state, HDN_PT_LIVE, HDN_PT_RETIRING) != HDN_PT_LIVE)
		panic("HDN rejected a reserved page-table release");
	hdn_pt_window_clear(pfn);
	WRITE_ONCE(record->owner, current);
	atomic_set_release(&record->state, HDN_PT_UNSEALING);
	if (set_memory_rw((unsigned long)page_address(page), 1))
		panic("HDN could not retire a reserved page table");
	atomic_set_release(&record->state, HDN_PT_DEAD);
	if (xa_erase(&pt_pages, pfn) != record)
		panic("HDN reserved page-table ownership was replaced");
	atomic64_dec(&active_pages);
	atomic64_inc(&retirements);
	kfree_rcu(record, rcu);
}

static struct hdn_pt_record *claim_page(struct page *page, unsigned int order, bool boot, gfp_t gfp)
{
	struct hdn_pt_record *record;
	unsigned long pfn = page_to_pfn(page);
	unsigned int pages = 1U << order, inserted = 0;

	record = kzalloc(sizeof(*record), gfp & ~(__GFP_HIGHMEM | __GFP_COMP));
	if (!record)
		return NULL;
	record->page = page;
	record->order = order;
	record->boot = boot;
	record->owner = current;
	atomic_set(&record->state, HDN_PT_SEALING);
	INIT_LIST_HEAD(&record->reserve);
	INIT_WORK(&record->destroy, destroy_record);
	for (; inserted < pages; inserted++)
		if (xa_insert(&pt_pages, pfn + inserted, record, gfp))
			goto failed;
	atomic64_add(pages, &active_pages);
	atomic64_inc(&allocations);
	return record;
failed:
	while (inserted)
		xa_erase(&pt_pages, pfn + --inserted);
	kfree_rcu(record, rcu);
	return NULL;
}

static int seal_record(struct hdn_pt_record *record)
{
	unsigned long address = (unsigned long)page_address(record->page);
	unsigned long pfn = page_to_pfn(record->page);
	unsigned int pages = 1U << record->order;
	int error;

	/* Static tables also have an image alias. Make that exact data page NX
	 * before sealing; ordinary dynamic pages are already direct-map NX. */
	if (pfn >= PFN_DOWN(__pa_symbol(_text)) &&
	    pfn < PFN_UP(__pa_symbol(_end))) {
		unsigned long high = pfn * PAGE_SIZE + __START_KERNEL_map - phys_base;
		error = set_memory_nx(high, pages);
		if (error)
			return error;
	}
	error = set_memory_ro(address, pages);
	if (!error) {
		WRITE_ONCE(record->owner, NULL);
		atomic_set_release(&record->state, HDN_PT_LIVE);
	}
	return error;
}

static void add_reserve(struct hdn_pt_record *record)
{
	unsigned long flags;

	atomic_set_release(&record->state, HDN_PT_RESERVE);
	raw_spin_lock_irqsave(&reserve_lock, flags);
	list_add_tail(&record->reserve, &reserve_pages);
	reserve_count[page_to_nid(record->page)][record->order]++;
	atomic64_add(1U << record->order, &reserved_pages);
	raw_spin_unlock_irqrestore(&reserve_lock, flags);
}

static struct page *take_reserve(gfp_t gfp, unsigned int order)
{
	struct hdn_pt_record *record, *chosen;
	nodemask_t allowed, preferred, cpuset;
	unsigned long flags;
	enum zone_type zone = gfp_zone(gfp);
	unsigned int seq;
	int node, nid;

retry:
	seq = read_mems_allowed_begin();
	node = hdn_pt_policy_nodes(gfp, &allowed, &preferred);
	chosen = NULL;
	/* Evaluate cpusets outside our lock: the slow fallback can acquire the
	 * cpuset callback lock. First prefer the current set, then use precisely
	 * the allocator's permitted ancestor fallback, never an arbitrary node. */
	for (unsigned int pass = 0; pass < 2 && !chosen; pass++) {
		nodes_clear(cpuset);
		for_each_node_mask(nid, allowed)
			if (!cpusets_enabled() || cpuset_current_node_allowed(nid,
					gfp | (pass ? 0 : __GFP_HARDWALL)))
				node_set(nid, cpuset);
		raw_spin_lock_irqsave(&reserve_lock, flags);
		list_for_each_entry(record, &reserve_pages, reserve) {
			nid = page_to_nid(record->page);
			if (record->order != order || page_zonenum(record->page) > zone ||
			    !node_isset(nid, cpuset) ||
			    ((gfp & __GFP_THISNODE) && nid != node) ||
			    (!pass && !node_isset(nid, preferred)))
				continue;
			chosen = record;
			if (nid == node)
				break;
		}
		if (chosen) {
			list_del_init(&chosen->reserve);
			reserve_count[page_to_nid(chosen->page)][order]--;
			atomic64_sub(1U << order, &reserved_pages);
			if (atomic_cmpxchg(&chosen->state, HDN_PT_RESERVE, HDN_PT_LIVE) != HDN_PT_RESERVE)
				panic("HDN page-table reserve ownership mismatch");
		}
		raw_spin_unlock_irqrestore(&reserve_lock, flags);
	}
	if (!chosen && read_mems_allowed_retry(seq))
		goto retry;
	queue_work(system_unbound_wq, &refill_work);
	if (!chosen)
		return NULL;
	if ((gfp & __GFP_ACCOUNT) && memcg_kmem_charge_page(chosen->page,
			gfp & ~__GFP_DIRECT_RECLAIM, order)) {
		add_reserve(chosen);
		return NULL;
	}
	return chosen->page;
}

static struct page *allocate_owned(gfp_t gfp, unsigned int order, int nid)
{
	struct page *page;
	struct hdn_pt_record *record;

	if (nid == NUMA_NO_NODE)
		page = alloc_pages_noprof(gfp | __GFP_COMP | __GFP_ZERO, order);
	else
		page = alloc_pages_node_noprof(nid,
			gfp | __GFP_COMP | __GFP_ZERO | __GFP_THISNODE, order);
	if (!page)
		return NULL;
	record = claim_page(page, order, false, gfp);
	if (!record) {
		__free_pages(page, order);
		return NULL;
	}
	if (seal_record(record)) {
		/* CPA can partially protect a failed range. Retain ownership until
		 * checked deferred destruction removes every protected alias. */
		atomic_set(&record->state, HDN_PT_LIVE);
		hdn_pt_free(page, order);
		return NULL;
	}
	return page;
}

struct page *hdn_pt_alloc(gfp_t gfp, unsigned int order, bool reserve_only)
{
	struct page *page;

	if (!hdn_pt_active())
		return alloc_pages_noprof(gfp | __GFP_COMP, order);
	if (order > 1)
		goto failed;
	if (reserve_only || !gfpflags_allow_blocking(gfp) || in_atomic() || irqs_disabled()) {
		page = take_reserve(gfp, order);
		if (!page)
			goto failed;
		return page;
	}
	page = allocate_owned(gfp, order, NUMA_NO_NODE);
	if (!page)
		goto failed;
	return page;
failed:
	atomic64_inc(&allocation_failures);
	return NULL;
}
EXPORT_SYMBOL_GPL(hdn_pt_alloc);

unsigned long hdn_pt_alloc_address(gfp_t gfp, unsigned int order, bool reserve_only)
{
	struct page *page = hdn_pt_alloc(gfp, order, reserve_only);

	return page ? (unsigned long)page_address(page) : 0;
}

void hdn_pt_free_address(unsigned long address, unsigned int order)
{
	if (!address)
		return;
	if (!IS_ALIGNED(address, PAGE_SIZE))
		panic("HDN rejected a misaligned page-table release");
	if (!hdn_pt_free(virt_to_page((void *)address), order))
		free_pages(address, order);
}

static void refill_reserve(struct work_struct *work)
{
	int nid;

	for_each_node_state(nid, N_MEMORY) {
		for (unsigned int order = 0; order <= 1; order++) {
			unsigned int goal = order ? HDN_PT_RESERVE_1 : HDN_PT_RESERVE_0;
			/* Bound the pass even when other CPUs consume new reserves. */
			for (unsigned int n = READ_ONCE(reserve_count[nid][order]); n < goal; n++) {
				struct page *page = allocate_owned(GFP_KERNEL | __GFP_NOWARN, order, nid);
				struct hdn_pt_record *record;
				if (!page)
					break;
				record = xa_load(&pt_pages, page_to_pfn(page));
				if (!record)
					panic("HDN refill produced an unowned page table");
				add_reserve(record);
			}
		}
	}
}

static void check_level(struct hdn_pt_record *record, unsigned long pfn,
			unsigned int level)
{
	unsigned int part = pfn - page_to_pfn(record->page);
	int old;

	if (!level || level > (pgtable_l5_enabled() ? 5 : 4) || part >= (1U << record->order))
		panic("HDN rejected a page-table level");
	old = atomic_cmpxchg(&record->level[part], 0, level);
	if (old && old != level)
		panic("HDN rejected a page-table type substitution");
}

/* Called under RCU with local interrupts disabled. Non-leaf publication can
 * reference only owned, live tables of the immediately following level.
 * Leaf mappings cannot turn protected storage into executable/user/RW data.
 * CPA's construction/retirement owner is the only RW exception and its
 * address-aware admission check restricts it to the canonical aliases.
 */
static void validate_entry(unsigned long value, unsigned int level)
{
	struct hdn_pt_record *child;
	unsigned long pfn, nr, index;
	int state;

	if (!(value & _PAGE_PRESENT))
		return;
	pfn = (value & PTE_PFN_MASK) >> PAGE_SHIFT;
	if (level > 1 && !(level <= 3 && (value & _PAGE_PSE))) {
		child = xa_load(&pt_pages, pfn);
		if (!child)
			panic("HDN rejected an unowned child page table");
		state = atomic_read_acquire(&child->state);
		if (child->transition || child->code ||
		    (state != HDN_PT_LIVE && state != HDN_PT_SEALING))
			panic("HDN rejected an inactive child page table");
		check_level(child, pfn, level - 1);
		return;
	}
	nr = 1UL << ((level - 1) * (PAGE_SHIFT - 3));
	pfn &= ~(nr - 1);
	if (hdn_execmem_leaf(pfn, nr, value))
		panic("HDN rejected an alias of owned kernel storage");
	xa_for_each_range(&pt_pages, index, child, pfn, pfn + nr - 1) {
		state = atomic_read_acquire(&child->state);
		if ((value & _PAGE_USER) ||
		    (!(value & _PAGE_NX) && (!child->code || (value & _PAGE_RW))) ||
		    ((value & _PAGE_RW) && !((state == HDN_PT_SEALING ||
			state == HDN_PT_UNSEALING) && READ_ONCE(child->owner) == current &&
			!in_interrupt())))
			panic("HDN rejected an alias of protected page-table storage");
	}
}

unsigned long notrace hdn_pt_update(unsigned long *slot, unsigned long value,
				   unsigned long expected, enum hdn_pt_operation operation,
				   unsigned int level)
{
	struct hdn_pt_record *record = NULL;
	unsigned long flags, pfn = 0, old = 0;
	unsigned int offset = offset_in_page(slot);

	if (!IS_ALIGNED((unsigned long)slot, sizeof(*slot)) || operation > HDN_PT_COMPARE_EXCHANGE)
		panic("HDN rejected a malformed page-table update");
	local_irq_save(flags);
	rcu_read_lock();
	if (smp_load_acquire(&hdn_pt_writes_ready) && virt_addr_valid(slot)) {
		pfn = __pa(slot) >> PAGE_SHIFT;
		record = xa_load(&pt_pages, pfn);
	}
	if (record) {
		bool mirrored;
		int state = atomic_read_acquire(&record->state);
		if (state != HDN_PT_LIVE && state != HDN_PT_SEALING)
			panic("HDN rejected a retired or reserved page-table update");
		if (level)
			check_level(record, pfn, level);
		else
			level = atomic_read(&record->level[pfn - page_to_pfn(record->page)]);
		if (value && !level)
			panic("HDN rejected an untyped page-table publication");
		if (value && READ_ONCE(admission_ready))
			validate_entry(value, level);
		mirrored = hdn_stack_mm_update_begin(level);
		old = hdn_pt_window_update(pfn, offset, value, expected, operation);
		if (mirrored) {
			if (operation == HDN_PT_COMPARE_EXCHANGE && old != expected)
				hdn_stack_mm_update_abort();
			else
				hdn_stack_mm_update_end(pfn, offset, value, level);
		}
	} else {
		/* Early construction and local pte_t values are not live table pages.
		 * Publication/allocation adapters own the admission invariant. */
		switch (operation) {
		case HDN_PT_STORE: WRITE_ONCE(*slot, value); break;
		case HDN_PT_EXCHANGE: old = xchg(slot, value); break;
		case HDN_PT_COMPARE_EXCHANGE: old = cmpxchg(slot, expected, value); break;
		case HDN_PT_READ:
		case HDN_PT_COPY:
		case HDN_PT_LTR:
			BUG(); /* private-window-only operations were rejected above */
		}
	}
	rcu_read_unlock();
	local_irq_restore(flags);
	return old;
}
EXPORT_SYMBOL_GPL(hdn_pt_update);

void hdn_pt_copy(void *destination, const void *source, size_t size, unsigned int level)
{
	unsigned long *dst = destination;
	const unsigned long *src = source;

	if (!IS_ALIGNED((unsigned long)dst | (unsigned long)src | size, sizeof(*dst)))
		panic("HDN rejected a partial page-table entry copy");
	for (size_t i = 0; i < size / sizeof(*dst); i++)
		hdn_pt_store(dst + i, READ_ONCE(src[i]), level);
}
EXPORT_SYMBOL_GPL(hdn_pt_copy);

void hdn_pt_zero(void *destination, size_t size)
{
	unsigned long *dst = destination;

	if (!IS_ALIGNED((unsigned long)dst | size, sizeof(*dst)))
		panic("HDN rejected a partial page-table entry clear");
	for (size_t i = 0; i < size / sizeof(*dst); i++)
		hdn_pt_store(dst + i, 0, 0);
}
EXPORT_SYMBOL_GPL(hdn_pt_zero);

/* Terminal contexts never join pgd_list and are never used for scheduling or
 * ordinary execution. Seal their contents before publishing the kexec image
 * or quiescing for resume. Their identity mappings belong to the irreversible
 * handoff, not to a runtime relaxation of the current kernel's CR3. No setter
 * can mutate a finalized terminal table or attach it to an ordinary root.
 */
static int transition_collect(struct hdn_pt_transition *context,
			      unsigned long *table, unsigned int level)
{
	unsigned long pfn = __pa(table) >> PAGE_SHIFT;
	struct hdn_pt_record *record = xa_load(&pt_pages, pfn);
	int error;

	if (record)
		return record->transition == context && !record->code &&
			atomic_read(&record->level[0]) == level ? 0 : -EXDEV;
	record = claim_page(pfn_to_page(pfn), 0, false, GFP_KERNEL);
	if (!record)
		return -ENOMEM;
	record->transition = context;
	atomic_set(&record->level[0], level);
	list_add_tail(&record->reserve, &context->pages);
	if (level == 1)
		return 0;
	for (unsigned int i = 0; i < PTRS_PER_PTE; i++) {
		unsigned long entry = READ_ONCE(table[i]);
		if (!(entry & _PAGE_PRESENT) || (level <= 3 && (entry & _PAGE_PSE)))
			continue;
		error = transition_collect(context, __va(entry & PTE_PFN_MASK), level - 1);
		if (error)
			return error;
	}
	return 0;
}

static void transition_release(struct hdn_pt_transition *context, const void *owner)
{
	struct hdn_pt_record *record, *next;

	if (!context)
		return;
	if (context->owner != owner || in_interrupt() || irqs_disabled())
		panic("HDN rejected a terminal-context release");
	list_for_each_entry_safe(record, next, &context->pages, reserve) {
		unsigned long address = (unsigned long)page_address(record->page);
		unsigned long pfn = page_to_pfn(record->page);

		if (record->transition != context)
			panic("HDN terminal-context ownership mismatch");
		WRITE_ONCE(record->owner, current);
		atomic_set_release(&record->state, HDN_PT_UNSEALING);
		/* The image has been withdrawn or resume abandoned. Remove execute
		 * permission before clearing even its private construction view. */
		if (record->code && set_memory_nx(address, 1))
			panic("HDN could not retire terminal code");
		hdn_pt_window_clear(pfn);
		if (set_memory_rw(address, 1))
			panic("HDN could not retire a terminal-context page");
		atomic_set_release(&record->state, HDN_PT_DEAD);
		if (xa_erase(&pt_pages, pfn) != record)
			panic("HDN terminal-context ownership was replaced");
		list_del(&record->reserve);
		atomic64_dec(&active_pages);
		atomic64_inc(&retirements);
		kfree_rcu(record, rcu);
	}
	/* The original kimage/snapshot allocator owns the physical frees. */
	kfree(context);
}

static int transition_seal(unsigned long *root, unsigned long code,
			   const void *owner, struct hdn_pt_transition **result)
{
	struct hdn_pt_transition *context;
	struct hdn_pt_record *record;
	unsigned long code_pfn = __pa(code) >> PAGE_SHIFT;
	int error;

	if (!hdn_pt_active())
		return !strcmp(runtime_state, "initializing") ? -EAGAIN : 0;
	if (!PAGE_ALIGNED(root) || !PAGE_ALIGNED(code) || *result ||
	    in_interrupt() || irqs_disabled())
		return -EINVAL;
	context = kzalloc(sizeof(*context), GFP_KERNEL);
	if (!context)
		return -ENOMEM;
	INIT_LIST_HEAD(&context->pages);
	context->owner = owner;
	error = transition_collect(context, root, pgtable_l5_enabled() ? 5 : 4);
	if (error)
		goto failed;
	error = -EXDEV;
	if (xa_load(&pt_pages, code_pfn))
		goto failed;
	error = -ENOMEM;
	record = claim_page(pfn_to_page(code_pfn), 0, false, GFP_KERNEL);
	if (!record)
		goto failed;
	record->code = true;
	record->transition = context;
	list_add_tail(&record->reserve, &context->pages);
	list_for_each_entry(record, &context->pages, reserve) {
		if (record->code)
			error = set_memory_rox((unsigned long)page_address(record->page), 1);
		else
			error = seal_record(record);
		if (error)
			goto failed;
		WRITE_ONCE(record->owner, NULL);
		atomic_set_release(&record->state, HDN_PT_FROZEN);
	}
	*result = context;
	return 0;
failed:
	transition_release(context, owner);
	return error;
}

/* The real-mode blob remains reserved for the lifetime of the kernel.
 * Claim immutable code/header pages independently of its mutable firmware
 * scratch space and startup lock. No ordinary alias may rewrite a target. */
static void __init seal_realmode_page(unsigned long address, bool code)
{
	struct hdn_pt_record *record;

	record = claim_page(pfn_to_page(__pa(address) >> PAGE_SHIFT), 0, true, GFP_KERNEL);
	if (!record)
		panic("HDN could not own a real-mode immutable page");
	record->code = code;
	if (code ? set_memory_rox(address, 1) : seal_record(record))
		panic("HDN could not seal a real-mode immutable page");
	WRITE_ONCE(record->owner, NULL);
	atomic_set_release(&record->state, HDN_PT_FROZEN);
}

static void __init seal_realmode_blob(void)
{
	unsigned long base, text, end, header;

	if (!real_mode_is_initialized())
		return;
	base = (unsigned long)real_mode_header;
	text = (unsigned long)__va(real_mode_header->text_start);
	end = PAGE_ALIGN((unsigned long)__va(real_mode_header->ro_end));
	header = (unsigned long)__va(real_mode_header->trampoline_header);
	if (!PAGE_ALIGNED(base) || !PAGE_ALIGNED(text) || !PAGE_ALIGNED(header) ||
	    text < base || end <= text || header < end ||
	    header + PAGE_SIZE > base + PAGE_ALIGN(real_mode_blob_end - real_mode_blob))
		panic("HDN real-mode immutable ranges are malformed");
	for (unsigned long p = base; p < end; p += PAGE_SIZE)
		seal_realmode_page(p, p >= text);
	seal_realmode_page(header, false);
#ifdef CONFIG_ACPI_SLEEP
	header = (unsigned long)__va(real_mode_header->wakeup_header);
	if (!PAGE_ALIGNED(header) || header < end ||
	    header + PAGE_SIZE > base + PAGE_ALIGN(real_mode_blob_end - real_mode_blob))
		panic("HDN wakeup header page is malformed");
	seal_realmode_page(header, false);
#endif
}

/* The crash root is private until the BSP has stopped its peers. Only this
 * exact immutable low mapping may then join init_mm for the CR3 transition.
 * Ordinary setters deliberately continue rejecting all terminal children. */
static struct hdn_pt_transition *hyperv_context __ro_after_init;
static unsigned long *hyperv_slot __ro_after_init;
static unsigned long hyperv_entry __ro_after_init;

int __init hdn_pt_hyperv_seal(void *root, unsigned long code)
{
	unsigned long address = __pa(code);
	unsigned long *table = root;
	unsigned long *slot;
	int error;

	if (pgtable_l5_enabled() || address >= BIT_ULL(32) || !PAGE_ALIGNED(root) ||
	    !PAGE_ALIGNED(code) || !hdn_pt_active() || hyperv_context)
		return -EINVAL;
	slot = (unsigned long *)init_mm.pgd + pgd_index(address);
	if (READ_ONCE(*slot) || !(table[pgd_index(address)] & _PAGE_PRESENT))
		return -EEXIST;
	error = transition_seal(root, code, &hyperv_context, &hyperv_context);
	if (error)
		return error;
	hyperv_slot = slot;
	hyperv_entry = table[pgd_index(address)] | _PAGE_NOPTISHADOW;
	return 0;
}

void hdn_pt_hyperv_switch(bool install)
{
	unsigned long *slot = hyperv_slot;
	unsigned long old = install ? 0 : hyperv_entry;
	unsigned long value = install ? hyperv_entry : 0;
	unsigned long actual;

	if (!irqs_disabled() || !hyperv_context || !slot || raw_smp_processor_id() ||
	    READ_ONCE(*slot) != old)
		panic("HDN rejected the Hyper-V crash root transition");
	/* No allocator, locks, root-set walk or new target selection in NMI.
	 * The post-crash kernel never returns to normal scheduling. */
	actual = hdn_pt_window_update(__pa(slot) >> PAGE_SHIFT, offset_in_page(slot),
				      value, old, HDN_PT_COMPARE_EXCHANGE);
	if (actual != old)
		panic("HDN Hyper-V crash root changed during publication");
}

/* Boot-owned terminal tables outlive all CPUs and never join the ordinary
 * root set. Unlike kexec, their handoff code is already immutable kernel text.
 * No release API is provided: firmware CPU reset may use them at any time. */
int __init hdn_pt_boot_handoff_seal(unsigned long root, unsigned long launch)
{
	struct hdn_pt_transition *context;
	struct hdn_pt_record *record;
	int error;

	if (!hdn_pt_active() || !PAGE_ALIGNED(root) || !PAGE_ALIGNED(launch) ||
	    (root && !virt_addr_valid(__va(root))) ||
	    launch < (unsigned long)__start_ro_after_init ||
	    launch > (unsigned long)__end_ro_after_init - PAGE_SIZE)
		return -EINVAL;
	context = kzalloc(sizeof(*context), GFP_KERNEL);
	if (!context)
		return -ENOMEM;
	INIT_LIST_HEAD(&context->pages);
	context->owner = (void *)launch;
	if (root) {
		error = transition_collect(context, __va(root), pgtable_l5_enabled() ? 5 : 4);
		if (error)
			goto failed;
	}
	error = -ENOMEM;
	record = claim_page(pfn_to_page(__pa_symbol(launch) >> PAGE_SHIFT), 0, true, GFP_KERNEL);
	if (!record)
		goto failed;
	record->transition = context;
	list_add_tail(&record->reserve, &context->pages);
	list_for_each_entry(record, &context->pages, reserve) {
		error = seal_record(record);
		if (error)
			goto failed;
		atomic_set_release(&record->state, HDN_PT_FROZEN);
	}
	return 0;
failed:
	transition_release(context, (void *)launch);
	return error;
}

/* External firmware code used by a frozen terminal identity map must be RX in
 * that root and RO/NX through the kernel direct map. These firmware-owned pages
 * are never returned to the kernel allocator. */
static void __init terminal_code_rollback(struct hdn_pt_transition *context)
{
	struct hdn_pt_record *record, *next;

	list_for_each_entry_safe(record, next, &context->pages, reserve) {
		unsigned long pfn = page_to_pfn(record->page);

		if (record->transition != context || !record->code ||
		    (atomic_read(&record->state) != HDN_PT_SEALING &&
		     atomic_read(&record->state) != HDN_PT_FROZEN))
			panic("HDN terminal-code rollback ownership mismatch");
		WRITE_ONCE(record->owner, current);
		atomic_set_release(&record->state, HDN_PT_UNSEALING);
		if (set_memory_rw((unsigned long)page_address(record->page), 1))
			panic("HDN could not roll back terminal-code ownership");
		atomic_set_release(&record->state, HDN_PT_DEAD);
		if (xa_erase(&pt_pages, pfn) != record)
			panic("HDN terminal-code ownership was replaced");
		list_del(&record->reserve);
		atomic64_dec(&active_pages);
		kfree_rcu(record, rcu);
	}
	kfree(context);
}

int __init hdn_pt_foreign_code_seal(phys_addr_t start, size_t size,
		const void *owner)
{
	struct hdn_pt_transition *context;
	struct hdn_pt_record *record;
	phys_addr_t first, end;
	int error = -EINVAL;

	if (!hdn_pt_platform_supported() || !owner || !size ||
	    check_add_overflow(start, size, &end) ||
	    check_add_overflow(end, (phys_addr_t)PAGE_SIZE - 1, &end) ||
	    in_interrupt() || irqs_disabled())
		return -EINVAL;
	first = round_down(start, (phys_addr_t)PAGE_SIZE);
	end = round_down(end, (phys_addr_t)PAGE_SIZE);
	if (end <= first)
		return -EINVAL;
	context = kzalloc(sizeof(*context), GFP_KERNEL);
	if (!context)
		return -ENOMEM;
	INIT_LIST_HEAD(&context->pages);
	context->owner = owner;
	for (phys_addr_t address = first; address < end; address += PAGE_SIZE) {
		unsigned long pfn = PHYS_PFN(address);

		if (!pfn_valid(pfn) || !virt_addr_valid(__va(address)) || xa_load(&pt_pages, pfn))
			goto failed;
		record = claim_page(pfn_to_page(pfn), 0, true, GFP_KERNEL);
		if (!record) {
			error = -ENOMEM;
			goto failed;
		}
		record->code = true;
		record->transition = context;
		list_add_tail(&record->reserve, &context->pages);
	}
	list_for_each_entry(record, &context->pages, reserve) {
		unsigned long address = (unsigned long)page_address(record->page);

		error = set_memory_nx(address, 1);
		if (!error)
			error = set_memory_ro(address, 1);
		if (error)
			goto failed;
		WRITE_ONCE(record->owner, NULL);
		atomic_set_release(&record->state, HDN_PT_FROZEN);
	}
	atomic64_inc(&foreign_code_ranges);
	atomic64_add((end - first) >> PAGE_SHIFT, &foreign_code_pages);
	return 0;
failed:
	terminal_code_rollback(context);
	return error;
}

#ifdef CONFIG_KEXEC_CORE
int hdn_pt_kexec_seal(struct kimage *image)
{
	return transition_seal((unsigned long *)image->arch.pgd,
		(unsigned long)page_address(image->control_code_page), image, &image->arch.hdn_tables);
}

/* The loader retains allocation ownership. Register the private copy-program
 * pages before publication, and withdraw them with the terminal page tables. */
int hdn_pt_kexec_data_seal(struct kimage *image, struct page *page)
{
	struct hdn_pt_transition *context = image->arch.hdn_tables;
	struct hdn_pt_record *record;
	int error;

	if (!hdn_pt_active() || !context || context->owner != image ||
	    !page || in_interrupt() || irqs_disabled() ||
	    xa_load(&pt_pages, page_to_pfn(page)))
		return -EINVAL;
	record = claim_page(page, 0, false, GFP_KERNEL);
	if (!record)
		return -ENOMEM;
	record->transition = context;
	list_add_tail(&record->reserve, &context->pages);
	error = seal_record(record);
	if (error)
		return error; /* machine_kexec_cleanup owns partial construction */
	WRITE_ONCE(record->owner, NULL);
	atomic_set_release(&record->state, HDN_PT_FROZEN);
	return 0;
}

void hdn_pt_kexec_release(struct kimage *image)
{
	transition_release(image->arch.hdn_tables, image);
	image->arch.hdn_tables = NULL;
}
#endif

#ifdef CONFIG_HIBERNATION
static struct hdn_pt_transition *hibernate_context;
static struct hdn_pt_transition *hibernate_copy_context;

int hdn_pt_hibernate_copy_seal(struct hdn_hibernate_copy_page *pages,
		unsigned long count)
{
	struct hdn_pt_transition *context;
	struct hdn_hibernate_copy_page *page = pages;
	unsigned long remaining = count;
	int error = -EINVAL;

	if (!hdn_pt_active() || hibernate_copy_context || irqs_disabled() || in_interrupt())
		return -EINVAL;
	context = kzalloc(sizeof(*context), GFP_KERNEL);
	if (!context)
		return -ENOMEM;
	INIT_LIST_HEAD(&context->pages);
	context->owner = &hibernate_copy_context;
	while (page) {
		struct hdn_pt_record *record;
		struct hdn_hibernate_copy_page *next;
		unsigned long pfn;

		if (!PAGE_ALIGNED(page) || !virt_addr_valid(page) || !page->count ||
		    page->count > ARRAY_SIZE(page->entries) || page->count > remaining)
			goto failed;
		pfn = __pa(page) >> PAGE_SHIFT;
		if (xa_load(&pt_pages, pfn))
			goto failed;
		record = claim_page(pfn_to_page(pfn), 0, false, GFP_KERNEL);
		if (!record) {
			error = -ENOMEM;
			goto failed;
		}
		record->transition = context;
		list_add_tail(&record->reserve, &context->pages);
		next = page->next;
		for (unsigned int i = 0; i < page->count; i++) {
			struct pbe *expected = i + 1 < page->count ? &page->entries[i + 1] :
					      next ? &next->entries[0] : NULL;

			if (page->entries[i].next != expected)
				goto failed;
		}
		remaining -= page->count;
		error = seal_record(record);
		if (error)
			goto failed;
		WRITE_ONCE(record->owner, NULL);
		atomic_set_release(&record->state, HDN_PT_FROZEN);
		page = next;
		error = -EINVAL;
	}
	if (remaining)
		goto failed;
	hibernate_copy_context = context;
	return 0;
failed:
	transition_release(context, &hibernate_copy_context);
	return error;
}

int hdn_pt_hibernate_seal(void)
{
	return transition_seal(__va(temp_pgt), relocated_restore_code,
		&hibernate_context, &hibernate_context);
}

void hdn_pt_hibernate_release(void)
{
	transition_release(hibernate_context, &hibernate_context);
	hibernate_context = NULL;
	transition_release(hibernate_copy_context, &hibernate_copy_context);
	hibernate_copy_context = NULL;
}
#endif

static void __init discover_table(unsigned long *table, unsigned int level)
{
	unsigned long pfn = __pa(table) >> PAGE_SHIFT;
	struct hdn_pt_record *record;

	record = xa_load(&pt_pages, pfn);
	if (record && atomic_read(&record->level[pfn - page_to_pfn(record->page)])) {
		check_level(record, pfn, level);
		return;
	}
	if (!record)
		record = claim_page(pfn_to_page(pfn), 0,
		PageReserved(pfn_to_page(pfn)) ||
		(pfn >= PFN_DOWN(__pa_symbol(_text)) && pfn < PFN_UP(__pa_symbol(_end))), GFP_KERNEL);
	if (!record)
		panic("HDN could not record an initial page table");
	check_level(record, pfn, level);
	if (level == 1)
		return;
	for (unsigned int i = 0; i < PTRS_PER_PTE; i++) {
		unsigned long entry = READ_ONCE(table[i]);
		if (!(entry & _PAGE_PRESENT) || (level <= 3 && (entry & _PAGE_PSE)))
			continue;
		discover_table(__va(entry & PTE_PFN_MASK), level - 1);
	}
}

static void __init discover_root(unsigned long *root, unsigned int order)
{
	unsigned long pfn = __pa(root) >> PAGE_SHIFT;

	/* PTI roots are one order-1 allocation, not two independently freed
	 * pages. Preserve their original ownership and accounting granule. */
	if (!xa_load(&pt_pages, pfn) && !claim_page(pfn_to_page(pfn), order,
		PageReserved(pfn_to_page(pfn)) ||
		(pfn >= PFN_DOWN(__pa_symbol(_text)) && pfn < PFN_UP(__pa_symbol(_end))), GFP_KERNEL))
		panic("HDN could not record an initial page-table root");
	discover_table(root, pgtable_l5_enabled() ? 5 : 4);
	if (order)
		discover_table(root + PTRS_PER_PGD, pgtable_l5_enabled() ? 5 : 4);
}

static void __init sanitize_aliases(unsigned long *root, unsigned long *table,
				   unsigned int level, unsigned long base)
{
	for (unsigned int i = 0; i < PTRS_PER_PTE; i++) {
		unsigned long entry = READ_ONCE(table[i]);
		unsigned long address = base | ((unsigned long)i << (PAGE_SHIFT + 9 * (level - 1)));
		unsigned long pfn, count, index;
		struct hdn_pt_record *record;
		pgprot_t protection;

		if (!(entry & _PAGE_PRESENT))
			continue;
		address = sign_extend64(address, pgtable_l5_enabled() ? 56 : 47);
		if (level > 1 && !(level <= 3 && (entry & _PAGE_PSE))) {
			sanitize_aliases(root, __va(entry & PTE_PFN_MASK), level - 1, address);
			continue;
		}
		if ((entry & _PAGE_NX) && !(entry & (_PAGE_RW | _PAGE_USER)))
			continue;
		count = 1UL << (9 * (level - 1));
		pfn = ((entry & PTE_PFN_MASK) >> PAGE_SHIFT) & ~(count - 1);
		if (level == 3)
			protection = pgprot_large_2_4k(pud_pgprot(__pud(entry)));
		else if (level == 2)
			protection = pgprot_large_2_4k(pmd_pgprot(__pmd(entry)));
		else
			protection = pte_pgprot(__pte(entry));
		pgprot_val(protection) = (pgprot_val(protection) | _PAGE_NX) & ~_PAGE_RW;
		xa_for_each_range(&pt_pages, index, record, pfn, pfn + count - 1) {
			unsigned long alias = address + ((index - pfn) << PAGE_SHIFT);
			if (hdn_pt_window_private_alias(root, alias, index)) {
				if (level != 1 || !(entry & _PAGE_NX) ||
				    (entry & (_PAGE_USER | _PAGE_GLOBAL)))
					panic("HDN page-table window has invalid permissions");
				continue;
			}
			if (entry & _PAGE_USER)
				panic("HDN found a user mapping of initial page-table storage");
			/* CPA splits large mappings with presealed reserve pages. The
			 * entire hierarchy is already owned before this pass starts. */
			/* Preserve execution only for explicitly owned terminal code
			 * which was already executable in this root. Never retain W. */
			unsigned long flags = pgprot_val(protection);
			if (record->code && !(entry & _PAGE_NX))
				flags &= ~_PAGE_NX;
			if (kernel_map_pages_in_pgd((pgd_t *)root, index, alias, 1, flags))
				panic("HDN could not seal an initial page-table alias");
		}
	}
}

static void __init sanitize_root(unsigned long *root, unsigned int order)
{
	unsigned int level = pgtable_l5_enabled() ? 5 : 4;

	sanitize_aliases(root, root, level, 0);
	if (order)
		sanitize_aliases(root + PTRS_PER_PGD, root + PTRS_PER_PGD, level, 0);
}

static void __init visit_initial_roots(void (*visit)(unsigned long *, unsigned int))
{
	visit((unsigned long *)init_mm.pgd, pgd_allocation_order());
	if (text_poke_mm)
		visit((unsigned long *)text_poke_mm->pgd, pgd_allocation_order());
#ifdef CONFIG_EFI
	if (efi_mm.pgd)
		visit((unsigned long *)efi_mm.pgd, pgd_allocation_order());
#endif
	if (real_mode_is_initialized() && real_mode_header->trampoline_pgd)
		visit(__va(real_mode_header->trampoline_pgd), 0);
	hdn_pt_windows_walk(visit);
	hdn_stack_mm_walk(visit);
}

void __init hdn_pt_init(void)
{
	struct hdn_pt_record *record;
	unsigned long index;

	/* Native CR3 windows cannot replace a hypervisor's page-table ownership
	 * or confidential-computing exception protocol. Expose that boundary to
	 * signed required-capability policy; never silently advertise sealing. */
	if (xen_pv_domain()) {
		hdn_pt_efi_wx_result(efi_enabled(EFI_RUNTIME_SERVICES), false);
		runtime_state = "unsupported-xen-pv";
		return;
	}
	if (cc_platform_has(CC_ATTR_MEM_ENCRYPT)) {
		hdn_pt_efi_wx_result(efi_enabled(EFI_RUNTIME_SERVICES), false);
		runtime_state = "unsupported-confidential-memory";
		return;
	}
	/* Called before rest_init creates other tasks or brings up secondary CPUs.
	 * Build the contexts before changing the allocation or native-write path. */
	if (!kernel_wx_enforced() || num_online_cpus() != 1)
		panic("HDN page-table initialization requires the boot CPU and NX");
	/* The real-mode blob contains an embedded root. Its normal early
	 * initcall is after rest_init; finish construction now so discovery
	 * never reads an uninitialized header or seals a page later overwritten
	 * by the blob copy. Platforms that omit real mode keep their no-op hook. */
	x86_platform.realmode_init();
	hdn_pt_windows_init();
	hdn_stack_mm_init();
	smp_store_release(&hdn_pt_writes_ready, true);
	for (unsigned int order = 0; order <= 1; order++) {
		unsigned int goal = order ? HDN_PT_RESERVE_1 : HDN_PT_RESERVE_0;
		for (unsigned int n = 0; n < goal; n++) {
			struct page *page = alloc_pages(GFP_KERNEL | __GFP_COMP | __GFP_ZERO, order);
			if (!page || !(record = claim_page(page, order, false, GFP_KERNEL)) || seal_record(record))
				panic("HDN could not initialize the sealed page-table reserve");
			add_reserve(record);
		}
	}
	/* Subsequent CPA splits must consume presealed storage, not recurse into
	 * sealing a fresh page under the CPA lock. */
	smp_store_release(&allocation_ready, true);
	visit_initial_roots(discover_root);
	xa_for_each(&pt_pages, index, record)
		if (atomic_read(&record->state) == HDN_PT_SEALING && seal_record(record))
			panic("HDN could not seal an initial page table");
#ifdef CONFIG_ACPI_MADT_WAKEUP
	hdn_acpi_mp_seal();
#endif
	hdn_hv_crash_seal();
	seal_realmode_blob();
	if (!efi_enabled(EFI_RUNTIME_SERVICES))
		hdn_pt_efi_wx_result(false, false);
	else if (!strcmp(firmware_wx_state, "initializing"))
		panic("HDN EFI runtime W^X was not finalized before page-table sealing");
	visit_initial_roots(sanitize_root);
	smp_store_release(&admission_ready, true);
	hdn_stack_mm_online();
	refill_reserve(&refill_work);
	WRITE_ONCE(runtime_state, "active");
}
