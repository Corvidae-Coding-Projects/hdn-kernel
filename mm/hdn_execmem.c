// SPDX-License-Identifier: GPL-2.0-only
/* Fresh execmem pages: one construction mapping, then an irreversible seal. */
#include <linux/hardening.h>
#include <linux/hdn_execmem.h>
#include <linux/hdn_pgtable.h>
#include <linux/hdn_stack.h>
#include <linux/execmem.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/sched/task.h>
#include <linux/set_memory.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/xarray.h>
#include <linux/random.h>
#include <linux/workqueue.h>
#include <asm/set_memory.h>
#include <asm/tlbflush.h>
#ifdef CONFIG_SECURITY_HARDENING_PGTABLE
#include "../arch/x86/mm/hdn_pgtable_internal.h"
#endif

enum hdn_execmem_state {
	HDN_EXEC_BUILDING,
	HDN_EXEC_FINALIZING,
	HDN_EXEC_SEALED,
	HDN_EXEC_BROKEN,
	HDN_EXEC_RETIRING,
};

struct hdn_execmem_region;
struct hdn_execmem_page {
	struct hdn_execmem_region *region;
	unsigned int index;
	unsigned long pfn;
};

struct hdn_execmem_region {
	struct rcu_head rcu;
	struct delayed_work reuse_work;
	struct list_head quarantine_node;
	u64 generation;
	unsigned long address;
	unsigned int nr;
	bool executable;
	bool private_backing;
	size_t ldt_size;
	const struct module *rap_owner;
	size_t rap_size;
	bool bpf;
	bool quarantined;
	bool pressure_release;
	unsigned long quarantine_release_after;
#if IS_ENABLED(CONFIG_SECURITY_HARDENING_KERNEL_WX_TEST)
	bool test_hold;
#endif
	enum hdn_execmem_state state;
	struct task_struct *owner;
	struct hdn_execmem_page pages[] __counted_by(nr);
};

static DEFINE_XARRAY(hdn_execmem_pfns);
static DEFINE_MUTEX(hdn_execmem_mutex);
static u64 hdn_execmem_generation;
static atomic64_t hdn_execmem_allocations;
static atomic64_t hdn_execmem_live_pages;
static atomic64_t hdn_execmem_finalized;
static atomic64_t hdn_execmem_retired;
static atomic64_t hdn_execmem_failed_retirements;
static atomic64_t hdn_bpf_live_pages;
static atomic64_t hdn_bpf_quarantined_pages;
static atomic64_t hdn_bpf_failed_retirements;
static atomic64_t hdn_bpf_quarantine_pressure_releases;
static LIST_HEAD(hdn_bpf_quarantine);
static unsigned long hdn_bpf_quarantine_pages;
#define HDN_BPF_QUARANTINE_LIMIT_PAGES (SZ_16M >> PAGE_SHIFT)
static void hdn_execmem_reuse_work(struct work_struct *work);

#if IS_ENABLED(CONFIG_SECURITY_HARDENING_KERNEL_WX_TEST)
static bool hdn_execmem_test_held(const struct hdn_execmem_region *region)
{
	return region->test_hold;
}
#else
static bool hdn_execmem_test_held(const struct hdn_execmem_region *region)
{
	return false;
}
#endif

void hdn_execmem_get_stats(struct hdn_execmem_stats *stats)
{
	/* Independent monotonic/lifetime counters, not a transactional snapshot. */
	stats->allocations = atomic64_read(&hdn_execmem_allocations);
	stats->live_pages = atomic64_read(&hdn_execmem_live_pages);
	stats->finalized = atomic64_read(&hdn_execmem_finalized);
	stats->retired = atomic64_read(&hdn_execmem_retired);
	stats->failed_retirements = atomic64_read(&hdn_execmem_failed_retirements);
	stats->bpf_live_pages = atomic64_read(&hdn_bpf_live_pages);
	stats->bpf_quarantined_pages = atomic64_read(&hdn_bpf_quarantined_pages);
	stats->bpf_failed_retirements = atomic64_read(&hdn_bpf_failed_retirements);
	stats->bpf_quarantine_pressure_releases =
		atomic64_read(&hdn_bpf_quarantine_pressure_releases);
	stats->bpf_quarantine_limit_pages = HDN_BPF_QUARANTINE_LIMIT_PAGES;
}

/* Lookup under the lifecycle mutex; CPA uses the RCU lookup below instead. */
static struct hdn_execmem_region *hdn_execmem_find(unsigned long address)
{
	struct hdn_execmem_page *entry;
	struct page *page;
	struct vm_struct *vm;

	lockdep_assert_held(&hdn_execmem_mutex);
	if (!is_vmalloc_or_module_addr((void *)address))
		return NULL;
	vm = find_vm_area((void *)address);
	if (!vm || !(vm->flags & VM_HDN_EXECMEM) || !vm->pages ||
	    address < (unsigned long)vm->addr ||
	    ((address - (unsigned long)vm->addr) >> PAGE_SHIFT) >= vm->nr_pages)
		return NULL;
	/* Quarantined mappings are non-present, but their vm/PFN ownership persists. */
	page = vm->pages[(address - (unsigned long)vm->addr) >> PAGE_SHIFT];
	if (!page)
		return NULL;
	entry = xa_load(&hdn_execmem_pfns, page_to_pfn(page));
	return entry ? entry->region : NULL;
}

/* Native leaf setters have no virtual-address argument. Enforce physical
 * ownership here as well as CPA's stronger canonical-address admission.
 * RCU is already held by the page-table publisher; no mutex or allocation
 * may enter this path. A huge leaf must satisfy every owned PFN it spans. */
int hdn_execmem_leaf(unsigned long pfn, unsigned long nr, unsigned long flags)
{
	struct hdn_execmem_page *entry;
	unsigned long index;

	if (!nr || nr - 1 > ULONG_MAX - pfn)
		return -EINVAL;
	if (!(flags & _PAGE_PRESENT))
		return 0;
	if (hdn_stack_retired_pfns(pfn, nr))
		return -EPERM;
	xa_for_each_range(&hdn_execmem_pfns, index, entry, pfn, pfn + nr - 1) {
		const struct hdn_execmem_region *region = entry->region;
		enum hdn_execmem_state state = smp_load_acquire(&region->state);
		bool owner = READ_ONCE(region->owner) == current && !in_interrupt();

		if ((flags & _PAGE_USER) || state == HDN_EXEC_BROKEN ||
		    (region->private_backing && (state != HDN_EXEC_BUILDING || !owner)) ||
		    ((flags & _PAGE_RW) && (!owner ||
		     (state != HDN_EXEC_BUILDING && state != HDN_EXEC_RETIRING))) ||
		    (!(flags & _PAGE_NX) && (!region->executable || (flags & _PAGE_RW) ||
		     (state != HDN_EXEC_SEALED && !(state == HDN_EXEC_FINALIZING && owner)))))
			return -EPERM;
	}
	return 0;
}

bool hdn_execmem_snapshot_page(void *destination, struct page *page, bool *zeros_only)
{
#ifdef CONFIG_SECURITY_HARDENING_PGTABLE
	unsigned long pfn = page_to_pfn(page), bits = 0, *out = destination;
	bool owned;

	if (!hdn_pt_active())
		return false;
	rcu_read_lock();
	owned = xa_load(&hdn_execmem_pfns, pfn) || hdn_stack_retired_pfns(pfn, 1);
	if (owned) {
		/* Hibernation already froze task/CPU lifetimes. Unlike temporarily
		 * restoring the direct map, this never publishes a reusable alias. */
		for (unsigned int i = 0; i < PAGE_SIZE / sizeof(*out); i++) {
			unsigned long value = hdn_pt_window_read(pfn, i * sizeof(*out));

			WRITE_ONCE(out[i], value);
			bits |= value;
		}
		*zeros_only = !bits;
	}
	rcu_read_unlock();
	return owned;
#else
	return false;
#endif
}

/*
 * Admission only: no sleeping, allocation, audit or lifecycle lock beneath
 * CPA/page-table locks. All registered PFNs are private fresh allocations,
 * claimed before their first publication to an execmem consumer. This is
 * deliberately not a service for retroactively sealing arbitrary pages.
 */
int hdn_execmem_mapping(unsigned long address, unsigned long pfn,
			unsigned long nr, pgprot_t prot, bool new_alias)
{
	pgprotval_t flags = pgprot_val(prot);
	unsigned long i;
	int error = 0;

	if (!nr || nr - 1 > ULONG_MAX - pfn)
		return -EINVAL;
	if (nr - 1 > (ULONG_MAX - address) >> PAGE_SHIFT)
		return -EINVAL;
	if (nr > ULONG_MAX >> PAGE_SHIFT)
		return -EINVAL;
	if ((flags & _PAGE_PRESENT) && hdn_stack_overlaps(address, nr << PAGE_SHIFT))
		return -EPERM;
	if ((flags & _PAGE_PRESENT) && hdn_stack_retired_pfns(pfn, nr))
		return -EPERM;
	error = hdn_pt_mapping(address, pfn, nr, flags);
	if (error)
		return error;
	rcu_read_lock();
	for (i = 0; i < nr; i++) {
		struct hdn_execmem_page *entry = xa_load(&hdn_execmem_pfns, pfn + i);
		struct hdn_execmem_region *region;
		enum hdn_execmem_state state;
		bool owner;

		if (!entry)
			continue;
		region = entry->region;
		state = smp_load_acquire(&region->state);
		/* Direct-map invalidation is allowed; the canonical lifetime is owned. */
		if (!(flags & _PAGE_PRESENT)) {
			if (address + (i << PAGE_SHIFT) == region->address +
			    ((unsigned long)entry->index << PAGE_SHIFT) &&
			    state != HDN_EXEC_RETIRING &&
			    !(region->private_backing && state == HDN_EXEC_FINALIZING &&
			      READ_ONCE(region->owner) == current)) {
				error = -EPERM;
				break;
			}
			continue;
		}
		if (new_alias || address + (i << PAGE_SHIFT) !=
		    region->address + ((unsigned long)entry->index << PAGE_SHIFT)) {
			error = -EPERM;
			break;
		}
		owner = READ_ONCE(region->owner) == current;
		/* Private backing loses its construction mapping permanently. Only
		 * the architecture's closed CPU mapping primitive can expose it. */
		if (region->private_backing && state != HDN_EXEC_BUILDING) {
			error = -EPERM;
			break;
		}
		if ((flags & _PAGE_RW) &&
		    (!owner || (state != HDN_EXEC_BUILDING && state != HDN_EXEC_RETIRING)))
			error = -EPERM;
		if (!(flags & _PAGE_NX) && (!region->executable ||
		    (state != HDN_EXEC_SEALED && !(state == HDN_EXEC_FINALIZING && owner))))
			error = -EPERM;
		if (region->executable && state == HDN_EXEC_SEALED && (flags & _PAGE_NX))
			error = -EPERM;
		if (error)
			break;
	}
	rcu_read_unlock();
	return error;
}

static int hdn_execmem_claim_region(void *ptr, bool executable, bool bpf,
				   size_t ldt_size, bool private_backing)
{
	struct vm_struct *vm = find_vm_area(ptr);
	struct hdn_execmem_region *region;
	unsigned long first = ULONG_MAX, last = 0;
	unsigned int i, inserted = 0;
	int error = -EINVAL;

	if (!kernel_wx_enforced() || !vm || vm->addr != ptr || !vm->nr_pages ||
	    (!(vm->flags & VM_ALLOC) && !(private_backing && (vm->flags & VM_MAP_PUT_PAGES))) ||
	    !(vm->flags & VM_FLUSH_RESET_PERMS))
		return -EINVAL;
	if (ldt_size && (ldt_size % 8 || PAGE_ALIGN(ldt_size) >> PAGE_SHIFT != vm->nr_pages))
		return -EINVAL;
	region = kvzalloc(struct_size(region, pages, vm->nr_pages), GFP_KERNEL);
	if (!region)
		return -ENOMEM;
	region->nr = vm->nr_pages;
	region->address = (unsigned long)ptr;
	region->executable = executable;
	region->private_backing = private_backing;
	region->ldt_size = ldt_size;
	region->bpf = bpf;
	INIT_DELAYED_WORK(&region->reuse_work, hdn_execmem_reuse_work);
	INIT_LIST_HEAD(&region->quarantine_node);
	region->owner = current;
	get_task_struct(current);
	region->state = HDN_EXEC_BUILDING;
	mutex_lock(&hdn_execmem_mutex);
	if (hdn_execmem_generation == U64_MAX) {
		error = -EOVERFLOW;
		goto rollback;
	}
	region->generation = ++hdn_execmem_generation;
	for (i = 0; i < region->nr; i++) {
		region->pages[i].region = region;
		region->pages[i].index = i;
		region->pages[i].pfn = page_to_pfn(vm->pages[i]);
		error = xa_insert(&hdn_execmem_pfns, page_to_pfn(vm->pages[i]),
				  &region->pages[i], GFP_KERNEL);
		if (error)
			goto rollback;
		inserted++;
	}
	for (i = 0; i < region->nr; i++) {
		unsigned long address = (unsigned long)page_address(vm->pages[i]);

		error = set_direct_map_invalid_noflush(vm->pages[i]);
		if (error)
			goto rollback;
		first = min(first, address);
		last = max(last, address + PAGE_SIZE);
	}
	flush_tlb_kernel_range(first, last);
	vm->flags |= VM_HDN_EXECMEM;
	atomic64_inc(&hdn_execmem_allocations);
	atomic64_add(region->nr, &hdn_execmem_live_pages);
	if (region->bpf)
		atomic64_add(region->nr, &hdn_bpf_live_pages);
	mutex_unlock(&hdn_execmem_mutex);
	hdn_report_kernel_page_transition(region->generation, HDN_REASON_KERNEL_PAGE_CONSTRUCT, 0);
	return 0;

rollback:
	/* No executable or published mapping exists. vfree restores direct maps. */
	while (inserted)
		xa_erase(&hdn_execmem_pfns, page_to_pfn(vm->pages[--inserted]));
	mutex_unlock(&hdn_execmem_mutex);
	put_task_struct(region->owner);
	kvfree_rcu(region, rcu);
	return error;
}

int hdn_execmem_claim(void *ptr)
{
	return hdn_execmem_claim_region(ptr, true, false, 0, false);
}

int hdn_execmem_claim_type(void *ptr, unsigned int type)
{
	if (type >= EXECMEM_TYPE_MAX)
		return -EINVAL;
	return hdn_execmem_claim_region(ptr, true,
		IS_ENABLED(CONFIG_SECURITY_HARDENING_BPF_EXECMEM) && execmem_is_bpf(type), 0, false);
}

int hdn_execmem_claim_data(void *ptr)
{
	return hdn_execmem_claim_region(ptr, false, false, 0, false);
}

int hdn_execmem_claim_stack(void *ptr)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_PRIVATE_STACKS) || !hdn_pt_active())
		return -EOPNOTSUPP;
	return hdn_execmem_claim_region(ptr, false, false, 0, true);
}

int hdn_execmem_claim_ldt(void *ptr, size_t size)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_LDT) || !size || size > 65536)
		return -EINVAL;
	return hdn_execmem_claim_region(ptr, false, false, size, false);
}

/* Descriptor load runs with IRQs disabled; no lifecycle mutex or allocation. */
bool hdn_execmem_ldt_valid(const void *ptr, size_t size)
{
	struct hdn_execmem_page *entry;
	struct page *page;
	bool valid = false;

	if (!ptr || offset_in_page(ptr) || !is_vmalloc_addr(ptr))
		return false;
	page = vmalloc_to_page(ptr);
	if (!page)
		return false;
	rcu_read_lock();
	entry = xa_load(&hdn_execmem_pfns, page_to_pfn(page));
	if (entry && !entry->index) {
		struct hdn_execmem_region *region = entry->region;

		valid = smp_load_acquire(&region->state) == HDN_EXEC_SEALED &&
			!region->executable && region->ldt_size == size && size &&
			region->address == (unsigned long)ptr &&
			region->nr == PAGE_ALIGN(size) >> PAGE_SHIFT;
	}
	rcu_read_unlock();
	return valid;
}

int hdn_execmem_claim_rap(void *ptr, const struct module *owner, size_t size)
{
	struct hdn_execmem_region *region;
	int error;

	if (!owner || !size)
		return -EINVAL;
	error = hdn_execmem_claim_data(ptr);
	if (error)
		return error;
	mutex_lock(&hdn_execmem_mutex);
	region = hdn_execmem_find((unsigned long)ptr);
	/* Claiming a new allocation and assigning its class are one unpublished
	 * construction step. This API never reclassifies an existing object. */
	BUG_ON(!region || region->state != HDN_EXEC_BUILDING || region->owner != current ||
	       region->nr != PAGE_ALIGN(size) >> PAGE_SHIFT);
	region->rap_owner = owner;
	region->rap_size = size;
	mutex_unlock(&hdn_execmem_mutex);
	return 0;
}

bool hdn_execmem_rap_valid(const void *ptr, const struct module *owner)
{
	struct hdn_execmem_page *entry;
	struct page *page;
	bool valid = false;

	if (!ptr || offset_in_page(ptr) || !is_vmalloc_addr(ptr))
		return false;
	page = vmalloc_to_page(ptr);
	if (!page)
		return false;
	rcu_read_lock();
	entry = xa_load(&hdn_execmem_pfns, page_to_pfn(page));
	if (entry && !entry->index) {
		struct hdn_execmem_region *region = entry->region;

		valid = smp_load_acquire(&region->state) == HDN_EXEC_SEALED &&
			!region->executable && region->rap_size && region->rap_owner == owner &&
			region->address == (unsigned long)ptr;
	}
	rcu_read_unlock();
	return valid;
}

/* Initial generation uses the existing RW/NX canonical mapping, never text-poke. */
int hdn_execmem_bpf_copy(void *dst, const void *src, size_t size)
{
	struct hdn_execmem_region *region;
	unsigned long address = (unsigned long)dst, offset;
	int result = 0;

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_BPF_EXECMEM))
		return 0;
	mutex_lock(&hdn_execmem_mutex);
	region = hdn_execmem_find(address);
	if (!region || !region->bpf)
		goto out;
	if (region->state == HDN_EXEC_SEALED)
		goto out; /* Live patching still uses the separately audited text primitive. */
	result = -EPERM;
	offset = address - region->address;
	if (region->state != HDN_EXEC_BUILDING || region->owner != current ||
	    offset >= ((size_t)region->nr << PAGE_SHIFT) ||
	    size > ((size_t)region->nr << PAGE_SHIFT) - offset)
		goto out;
	memcpy(dst, src, size);
	result = 1;
out:
	mutex_unlock(&hdn_execmem_mutex);
	return result;
}

int hdn_execmem_bpf_finalize(void *ptr)
{
	struct hdn_execmem_region *region;
	unsigned int nr = 0;

	mutex_lock(&hdn_execmem_mutex);
	region = hdn_execmem_find((unsigned long)ptr);
	if (region && region->address == (unsigned long)ptr && region->bpf &&
	    region->state == HDN_EXEC_BUILDING && region->owner == current)
		nr = region->nr;
	mutex_unlock(&hdn_execmem_mutex);
	return nr ? set_memory_rox((unsigned long)ptr, nr) : -EPERM;
}

static int hdn_execmem_begin(unsigned long address, int nr, bool executable, bool private_backing)
{
	struct hdn_execmem_region *region;
	int result = 0;

	mutex_lock(&hdn_execmem_mutex);
	region = hdn_execmem_find(address);
	if (!region)
		goto out;
	result = -EPERM;
	if (nr <= 0 || region->address != address || region->nr != nr ||
	    region->owner != current || region->state != HDN_EXEC_BUILDING ||
	    region->executable != executable || region->private_backing != private_backing)
		goto out;
	smp_store_release(&region->state, HDN_EXEC_FINALIZING);
	result = 1;
out:
	mutex_unlock(&hdn_execmem_mutex);
	return result;
}

int hdn_execmem_seal_begin(unsigned long address, int nr)
{
	return hdn_execmem_begin(address, nr, true, false);
}

void hdn_execmem_seal_end(unsigned long address, int error)
{
	struct hdn_execmem_region *region;
	struct task_struct *owner;
	u64 generation;

	mutex_lock(&hdn_execmem_mutex);
	region = hdn_execmem_find(address);
	BUG_ON(!region || region->address != address || region->owner != current ||
	       region->state != HDN_EXEC_FINALIZING);
	owner = region->owner;
	generation = region->generation;
	WRITE_ONCE(region->owner, NULL);
	smp_store_release(&region->state, error ? HDN_EXEC_BROKEN : HDN_EXEC_SEALED);
	mutex_unlock(&hdn_execmem_mutex);
	put_task_struct(owner);
	if (!error)
		atomic64_inc(&hdn_execmem_finalized);
	hdn_report_kernel_page_transition(generation, HDN_REASON_KERNEL_PAGE_FINALIZE, error);
}

int hdn_execmem_seal_data(void *ptr)
{
	struct vm_struct *vm = find_vm_area(ptr);
	unsigned long address = (unsigned long)ptr;
	int error;

	if (!vm || vm->addr != ptr || !(vm->flags & VM_HDN_EXECMEM))
		return -EINVAL;
	error = hdn_execmem_begin(address, vm->nr_pages, false, false);
	if (error != 1)
		return error ?: -EINVAL;
	error = set_memory_ro(address, vm->nr_pages);
	hdn_execmem_seal_end(address, error);
	return error;
}

static int hdn_execmem_hide_private(void *ptr)
{
	struct vm_struct *vm = find_vm_area(ptr);
	unsigned long address = (unsigned long)ptr;
	int error;

	if (!vm || vm->addr != ptr || !(vm->flags & VM_HDN_EXECMEM))
		return -EINVAL;
	error = hdn_execmem_begin(address, vm->nr_pages, false, true);
	if (error != 1)
		return error ?: -EINVAL;
	/* CPA flushes the construction alias on every CPU before publication. */
	error = set_memory_np(address, vm->nr_pages);
	hdn_execmem_seal_end(address, error);
	return error;
}

int hdn_execmem_hide_stack(void *ptr)
{
	return hdn_execmem_hide_private(ptr);
}

/* Hardware host-save storage has the same alias-free lifetime as private
 * stack backing. Only its architecture adapter can update fixed fields. */
int hdn_execmem_claim_hardware(void *ptr)
{
	struct vm_struct *vm = find_vm_area(ptr);

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_PRIVATE_STACKS) ||
	    !hdn_pt_active() || !vm || vm->nr_pages != 1)
		return -EINVAL;
	return hdn_execmem_claim_region(ptr, false, false, 0, true);
}

int hdn_execmem_hide_hardware(void *ptr)
{
	return hdn_execmem_hide_private(ptr);
}

bool hdn_execmem_text_page(struct page *page)
{
	struct hdn_execmem_page *entry;
	bool allowed;

	rcu_read_lock();
	entry = xa_load(&hdn_execmem_pfns, page_to_pfn(page));
	allowed = !entry || entry->region->executable;
	rcu_read_unlock();
	return allowed;
}

bool hdn_execmem_sealed(unsigned long address, int nr)
{
	struct hdn_execmem_region *region;
	bool sealed;

	mutex_lock(&hdn_execmem_mutex);
	region = hdn_execmem_find(address);
	sealed = region && region->address == address && region->nr == nr &&
		 region->state == HDN_EXEC_SEALED;
	mutex_unlock(&hdn_execmem_mutex);
	return sealed;
}

/* JIT entries may start inside a page-private allocation. Check its complete
 * extent without rounding past the allocation or accepting another producer. */
bool hdn_execmem_sealed_bpf(unsigned long address, size_t size)
{
	struct hdn_execmem_region *region;
	bool sealed = false;

	mutex_lock(&hdn_execmem_mutex);
	region = hdn_execmem_find(address);
	if (region && region->state == HDN_EXEC_SEALED &&
	    region->bpf && region->executable && size &&
	    size <= (size_t)region->nr << PAGE_SHIFT &&
	    address - region->address <= ((size_t)region->nr << PAGE_SHIFT) - size)
		sealed = true;
	mutex_unlock(&hdn_execmem_mutex);
	return sealed;
}

static void hdn_execmem_reuse_work(struct work_struct *work)
{
	struct hdn_execmem_region *region = container_of(to_delayed_work(work),
						       struct hdn_execmem_region, reuse_work);
	unsigned long address = region->address;
	u64 generation = region->generation;

	mutex_lock(&hdn_execmem_mutex);
	BUG_ON(region->state != HDN_EXEC_RETIRING || region->owner || !region->quarantined);
	BUG_ON(list_empty(&region->quarantine_node) ||
	       hdn_bpf_quarantine_pages < region->nr);
	list_del_init(&region->quarantine_node);
	hdn_bpf_quarantine_pages -= region->nr;
	get_task_struct(current);
	WRITE_ONCE(region->owner, current);
	mutex_unlock(&hdn_execmem_mutex);
	vfree((void *)address);
	hdn_report_kernel_page_transition(generation, HDN_REASON_KERNEL_PAGE_RETIRE, 0);
}

bool hdn_execmem_free(void *ptr)
{
	struct hdn_execmem_region *region;
	struct task_struct *owner;
	unsigned long address = (unsigned long)ptr;
	unsigned int nr;
	u64 generation;
	int error;

	mutex_lock(&hdn_execmem_mutex);
	region = hdn_execmem_find(address);
	if (!region) {
		mutex_unlock(&hdn_execmem_mutex);
		return false;
	}
	if (region->address != address || region->state == HDN_EXEC_FINALIZING ||
	    region->state == HDN_EXEC_RETIRING) {
		mutex_unlock(&hdn_execmem_mutex);
		hdn_report_kernel_mapping_violation(-EPERM);
		return true;
	}
	nr = region->nr;
	generation = region->generation;
	owner = region->owner;
	get_task_struct(current);
	WRITE_ONCE(region->owner, current);
	smp_store_release(&region->state, HDN_EXEC_RETIRING);
	mutex_unlock(&hdn_execmem_mutex);
	if (owner)
		put_task_struct(owner);

	/* Caller has already removed all execution/lifetime references. */
#ifdef CONFIG_SECURITY_HARDENING_PRIVATE_STACKS
	if (region->private_backing) {
		/* Never make private backing generally accessible, even during
		 * teardown. Invalidate a possibly unfinished construction alias
		 * before scrubbing each owned PFN through the private window. */
		error = set_memory_np(address, nr);
		if (!error)
			for (unsigned int i = 0; i < nr; i++)
				hdn_pt_window_clear(region->pages[i].pfn);
	} else
#endif
	{
	error = set_memory_nx(address, nr);
	if (!error)
		error = set_memory_rw(address, nr);
	if (!error) {
		memzero_explicit(ptr, (size_t)nr << PAGE_SHIFT);
		if (region->bpf)
			error = set_memory_np(address, nr);
	}
	}
	if (error) {
		/* Retain inaccessible pages rather than recycle ambiguous mappings. */
		mutex_lock(&hdn_execmem_mutex);
		WRITE_ONCE(region->owner, NULL);
		smp_store_release(&region->state, HDN_EXEC_BROKEN);
		mutex_unlock(&hdn_execmem_mutex);
		put_task_struct(current);
		atomic64_inc(&hdn_execmem_failed_retirements);
		if (region->bpf)
			atomic64_inc(&hdn_bpf_failed_retirements);
		hdn_report_kernel_page_transition(generation, HDN_REASON_KERNEL_PAGE_RETIRE, error);
		return true;
	}
	if (region->bpf) {
		struct hdn_execmem_region *candidate = NULL, *walk;
		unsigned long reuse_delay = msecs_to_jiffies(
			get_random_u32_inclusive(250, 2000));
		bool held;

		/* Keep the VA reservation and inaccessible PFNs until randomized expiry.
		 * The fixed BPF domain bounds retention; exhaustion never falls back.
		 */
		mutex_lock(&hdn_execmem_mutex);
		region->quarantined = true;
		region->quarantine_release_after = jiffies + msecs_to_jiffies(250);
		WRITE_ONCE(region->owner, NULL);
		list_add_tail(&region->quarantine_node, &hdn_bpf_quarantine);
		hdn_bpf_quarantine_pages += nr;
		atomic64_add(nr, &hdn_bpf_quarantined_pages);
		held = hdn_execmem_test_held(region);
		if (hdn_bpf_quarantine_pages > HDN_BPF_QUARANTINE_LIMIT_PAGES) {
			list_for_each_entry(walk, &hdn_bpf_quarantine, quarantine_node) {
				if (!hdn_execmem_test_held(walk) && !walk->pressure_release) {
					candidate = walk;
					candidate->pressure_release = true;
					break;
				}
			}
		}
		if (candidate) {
			unsigned long delay = time_after(candidate->quarantine_release_after,
							jiffies) ?
				candidate->quarantine_release_after - jiffies : 0;

			atomic64_inc(&hdn_bpf_quarantine_pressure_releases);
			mod_delayed_work(system_unbound_wq, &candidate->reuse_work, delay);
		}
		mutex_unlock(&hdn_execmem_mutex);
		put_task_struct(current);
		if (!held)
			queue_delayed_work(system_unbound_wq, &region->reuse_work,
				reuse_delay);
		return true;
	}
	vfree(ptr);
	hdn_report_kernel_page_transition(generation, HDN_REASON_KERNEL_PAGE_RETIRE, 0);
	return true;
}

/* vfree has removed and flushed the canonical mapping, before restoring RW. */
void hdn_execmem_unmapped(struct vm_struct *vm)
{
	struct hdn_execmem_region *region;
	struct hdn_execmem_page *entry;
	struct task_struct *owner;
	unsigned int i;

	if (!(vm->flags & VM_HDN_EXECMEM))
		return;
	mutex_lock(&hdn_execmem_mutex);
	entry = xa_load(&hdn_execmem_pfns, page_to_pfn(vm->pages[0]));
	BUG_ON(!entry);
	region = entry->region;
	BUG_ON(region->address != (unsigned long)vm->addr || region->nr != vm->nr_pages ||
	       region->state != HDN_EXEC_RETIRING || region->owner != current);
	for (i = 0; i < region->nr; i++) {
		entry = xa_erase(&hdn_execmem_pfns, page_to_pfn(vm->pages[i]));
		BUG_ON(entry != &region->pages[i]);
	}
	owner = region->owner;
	atomic64_inc(&hdn_execmem_retired);
	atomic64_sub(region->nr, &hdn_execmem_live_pages);
	if (region->bpf)
		atomic64_sub(region->nr, &hdn_bpf_live_pages);
	if (region->quarantined)
		atomic64_sub(region->nr, &hdn_bpf_quarantined_pages);
	mutex_unlock(&hdn_execmem_mutex);
	put_task_struct(owner);
	kvfree_rcu(region, rcu);
}

#if IS_ENABLED(CONFIG_SECURITY_HARDENING_KERNEL_WX_TEST)
int hdn_execmem_test_quarantine(void *ptr, bool hold)
{
	struct hdn_execmem_region *region;
	int error = -EPERM;

	mutex_lock(&hdn_execmem_mutex);
	region = hdn_execmem_find((unsigned long)ptr);
	if (!region || region->address != (unsigned long)ptr || !region->bpf)
		goto out;
	if (hold) {
		if (region->state != HDN_EXEC_BUILDING || region->owner != current || region->test_hold)
			goto out;
		region->test_hold = true;
	} else {
		if (!region->test_hold)
			goto out;
		region->test_hold = false;
		if (region->quarantined && region->state == HDN_EXEC_RETIRING)
			queue_delayed_work(system_unbound_wq, &region->reuse_work, 0);
	}
	error = 0;
out:
	mutex_unlock(&hdn_execmem_mutex);
	return error;
}

int hdn_execmem_test_scrubbed(void *ptr)
{
#ifdef CONFIG_SECURITY_HARDENING_PGTABLE
	struct hdn_execmem_region *region;
	int error = -EPERM;

	if (!hdn_pt_active())
		return -EOPNOTSUPP;
	mutex_lock(&hdn_execmem_mutex);
	region = hdn_execmem_find((unsigned long)ptr);
	if (!region || region->address != (unsigned long)ptr || !region->test_hold ||
	    !region->quarantined || region->state != HDN_EXEC_RETIRING || region->owner)
		goto out;
	for (unsigned int page = 0; page < region->nr; page++)
		for (unsigned int offset = 0; offset < PAGE_SIZE; offset += sizeof(long))
			if (hdn_pt_window_read(region->pages[page].pfn, offset)) {
				error = -EIO;
				goto out;
			}
	error = 0;
out:
	mutex_unlock(&hdn_execmem_mutex);
	return error;
#else
	return -EOPNOTSUPP;
#endif
}
#endif
