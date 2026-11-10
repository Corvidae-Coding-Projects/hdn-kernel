// SPDX-License-Identifier: GPL-2.0-only
/* Stable private virtual identities and dedicated, alias-free stack backing. */
#include <linux/hdn_execmem.h>
#include <linux/hdn_pgtable.h>
#include <linux/hdn_rap.h>
#include <linux/atomic.h>
#include <linux/export.h>
#include <linux/kstack_erase.h>
#include <linux/idr.h>
#include <linux/kasan.h>
#include <linux/kmemleak.h>
#include <linux/memcontrol.h>
#include <linux/mm.h>
#include <linux/rcupdate.h>
#include <linux/sched/task_stack.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/vmcore_info.h>
#include <asm/pgtable.h>
#include <asm/hdn_stack_mm.h>
#include <asm/hdn_stack.h>
#include <asm/fred.h>
#include <asm/set_memory.h>
#include "../mm/hdn_pgtable_internal.h"
#include "../mm/hdn_stack_mm_internal.h"
#include "hdn_stack_internal.h"

unsigned long hdn_stack_region __ro_after_init;
unsigned long hdn_stack_boot_retired __ro_after_init;
struct hdn_stack_storage *hdn_stack_buckets[HDN_STACK_BUCKETS] __ro_after_init;
static struct vm_struct stack_reservation;
static DEFINE_IDA(stack_slots);
static DEFINE_RAW_SPINLOCK(stack_registry_lock);
static u64 stack_generation __ro_after_init;
static atomic64_t stack_allocation_attempts;
static atomic64_t stack_allocations;
static atomic64_t stack_allocation_failures;
static atomic64_t stack_live;
atomic64_t stack_publications;
static atomic64_t stack_retirements;
atomic64_t stack_diagnostic_reads;
atomic64_t stack_diagnostic_read_failures;
atomic64_t stack_construction_bytes;
atomic64_t stack_switches;
atomic64_t stack_async_root_entries;

const char *hdn_stack_state(void)
{
	if (!READ_ONCE(hdn_stack_region))
		return "initializing";
	return smp_load_acquire(&hdn_stack_mm_ready) ? "active" : "initializing";
}

void hdn_stack_get_stats(struct hdn_stack_stats *stats)
{
	*stats = (struct hdn_stack_stats) {
		.allocation_attempts = atomic64_read(&stack_allocation_attempts),
		.allocations = atomic64_read(&stack_allocations),
		.allocation_failures = atomic64_read(&stack_allocation_failures),
		.live_stacks = atomic64_read(&stack_live),
		.publications = atomic64_read(&stack_publications),
		.retirements = atomic64_read(&stack_retirements),
		.diagnostic_reads = atomic64_read(&stack_diagnostic_reads),
		.diagnostic_read_failures = atomic64_read(&stack_diagnostic_read_failures),
		.construction_bytes = atomic64_read(&stack_construction_bytes),
		.task_switches = atomic64_read(&stack_switches),
		.async_root_entries = atomic64_read(&stack_async_root_entries),
	};
}

/* Offline crash tooling reads physical backing from an owned descriptor;
 * the crashed kernel never remaps all tasks merely to make a dump readable. */
void hdn_stack_vmcoreinfo(void)
{
#ifdef CONFIG_VMCORE_INFO
	VMCOREINFO_SYMBOL(hdn_stack_region);
	VMCOREINFO_SYMBOL(hdn_stack_buckets);
	VMCOREINFO_NUMBER(HDN_STACK_BUCKETS);
	VMCOREINFO_NUMBER(HDN_STACK_PAGES);
	VMCOREINFO_NUMBER(HDN_STACK_STRIDE);
	VMCOREINFO_STRUCT_SIZE(hdn_stack_storage);
	VMCOREINFO_OFFSET(hdn_stack_storage, owner);
	VMCOREINFO_OFFSET(hdn_stack_storage, next);
	VMCOREINFO_OFFSET(hdn_stack_storage, begin);
	VMCOREINFO_OFFSET(hdn_stack_storage, generation);
	VMCOREINFO_OFFSET(hdn_stack_storage, published);
	VMCOREINFO_OFFSET(hdn_stack_storage, pfns);
#endif
}

void __init hdn_stack_reserve(void)
{
	/* Keep address classification and KASAN's vmalloc shadow geometry intact.
	 * KASLR may align vmalloc only to PUD_SIZE, so round the reservation down
	 * to an entire P4D branch contained within the original vmalloc range. */
	unsigned long base = round_down(VMALLOC_END + 1 - P4D_SIZE, P4D_SIZE);

	BUILD_BUG_ON(HDN_STACK_STRIDE > PMD_SIZE);
	BUILD_BUG_ON(sizeof(struct hdn_stack_storage) > PAGE_SIZE);
	if (base < VMALLOC_START)
		panic("HDN private stack virtual region does not fit");
	stack_reservation.addr = (void *)base;
	stack_reservation.size = P4D_SIZE;
	stack_reservation.flags = VM_IOREMAP | VM_NO_GUARD;
	/* This only reserves VA. Populating shadow for 512 GiB here would be
	 * wrong; individual stack lifetimes allocate their own small shadows. */
	vm_area_add_early(&stack_reservation);
	hdn_stack_region = base;
}

static void store_bucket(unsigned int bucket, struct hdn_stack_storage *storage)
{
	unsigned long address = (unsigned long)&hdn_stack_buckets[bucket];

	hdn_pt_window_update(__pa_symbol(&hdn_stack_buckets[bucket]) >> PAGE_SHIFT,
			offset_in_page(address), (unsigned long)storage, 0, HDN_PT_STORE);
}

static void release_shadow(unsigned long begin)
{
	kasan_poison_vmalloc((void *)begin, THREAD_SIZE);
	kasan_release_vmalloc(begin, begin + THREAD_SIZE,
			     begin, begin + THREAD_SIZE, KASAN_VMALLOC_TLB_FLUSH);
}

static void retire_storage(struct work_struct *work)
{
	struct hdn_stack_lifetime *life = container_of(to_rcu_work(work),
						    struct hdn_stack_lifetime, retire);
	struct hdn_stack_storage *storage = life->storage;
	unsigned long slot, begin;

	if (storage->lifetime != life || storage->backing->addr != storage->construction_address ||
	    storage->backing->nr_pages != HDN_STACK_PAGES)
		panic("HDN private stack retirement ownership mismatch");
	for (unsigned int i = 0; i < HDN_STACK_PAGES; i++)
		if (page_to_pfn(storage->backing->pages[i]) != storage->pfns[i])
			panic("HDN private stack backing identity mismatch");
	slot = storage->slot;
	begin = storage->begin;
	/* The task's last stack reference and the registry grace period have
	 * elapsed. The backing service invalidates, scrubs and flushes before
	 * restoring direct-map permissions for the page allocator. */
	if (!hdn_execmem_free(storage->construction_address))
		panic("HDN private stack backing retirement failed");
	release_shadow(begin);
	if (!hdn_execmem_free(storage))
		panic("HDN private stack descriptor retirement failed");
	ida_free(&stack_slots, slot);
	kfree(life);
	atomic64_inc(&stack_retirements);
}

static int allocate_stack(struct task_struct *task, int node,
			  struct hdn_stack_storage **result)
{
	struct hdn_stack_lifetime *life = NULL;
	struct hdn_stack_storage *storage = NULL;
	struct vm_struct *backing;
	void *bytes = NULL;
	unsigned long begin, flags;
	unsigned int bucket;
	bool claimed = false, descriptor_claimed = false, shadow = false;
	int slot, error = -ENOMEM;

	atomic64_inc(&stack_allocation_attempts);
	if (!hdn_stack_region || !hdn_pt_active()) {
		atomic64_inc(&stack_allocation_failures);
		return -EOPNOTSUPP;
	}
	slot = ida_alloc_range(&stack_slots, 0, P4D_SIZE / HDN_STACK_STRIDE - 2, GFP_KERNEL);
	if (slot < 0) {
		atomic64_inc(&stack_allocation_failures);
		return slot;
	}
	begin = hdn_stack_region + (unsigned long)slot * HDN_STACK_STRIDE + THREAD_SIZE;
	/* Backing pages retain the upstream fork.c memcg accounting protocol.
	 * Descriptor/lifetime storage is charged separately to the constructor. */
	bytes = __vmalloc_node_range(THREAD_SIZE, THREAD_ALIGN, VMALLOC_START, VMALLOC_END,
			GFP_KERNEL | __GFP_ZERO, PAGE_KERNEL, VM_FLUSH_RESET_PERMS,
			node, __builtin_return_address(0));
	if (!bytes)
		goto discard;
	backing = find_vm_area(bytes);
	if (!backing || backing->nr_pages != HDN_STACK_PAGES)
		panic("HDN private stack allocation geometry mismatch");
	life = kmalloc_typed(struct hdn_stack_lifetime, sizeof(*life), GFP_KERNEL | __GFP_ACCOUNT);
	if (!life)
		goto discard;
	storage = __vmalloc_node_range(PAGE_SIZE, PAGE_SIZE, VMALLOC_START, VMALLOC_END,
			GFP_KERNEL | __GFP_ZERO | __GFP_ACCOUNT, PAGE_KERNEL,
			VM_FLUSH_RESET_PERMS, node, __builtin_return_address(0));
	if (!storage)
		goto discard;
	error = kasan_populate_vmalloc(begin, THREAD_SIZE, GFP_KERNEL);
	if (error)
		goto discard;
	shadow = true;
	kasan_unpoison_vmalloc((void *)begin, THREAD_SIZE, KASAN_VMALLOC_PROT_NORMAL);
	storage->owner = task;
	storage->builder = current;
	storage->lifetime = life;
	storage->backing = backing;
	storage->construction_address = bytes;
	storage->begin = begin;
	storage->slot = slot;
	storage->header_pfn = vmalloc_to_pfn(storage);
	for (unsigned int i = 0; i < HDN_STACK_PAGES; i++)
		storage->pfns[i] = page_to_pfn(backing->pages[i]);
	life->storage = storage;
	INIT_RCU_WORK(&life->retire, retire_storage);
	error = hdn_execmem_claim_stack(bytes);
	if (error)
		goto discard;
	claimed = true;
	/* The generic scanner cannot dereference backing after publication.
	 * Stack-root scanning uses the bounded diagnostic adapter instead. */
	kmemleak_no_scan(bytes);
	error = hdn_execmem_hide_stack(bytes);
	if (error)
		goto discard;
	error = hdn_execmem_claim_data(storage);
	if (error)
		goto discard;
	descriptor_claimed = true;
	error = hdn_execmem_seal_data(storage);
	if (error)
		goto discard;
	bucket = hdn_stack_bucket(begin);
	raw_spin_lock_irqsave(&stack_registry_lock, flags);
	if (hdn_stack_lookup(begin)) {
		error = -EEXIST;
		goto unlock;
	}
	if (READ_ONCE(stack_generation) == U64_MAX) {
		error = -EOVERFLOW;
		goto unlock;
	}
	{
		unsigned long generation = READ_ONCE(stack_generation);
		unsigned long old = hdn_pt_window_update(
			__pa_symbol(&stack_generation) >> PAGE_SHIFT,
			offset_in_page(&stack_generation), generation + 1,
			generation, HDN_PT_COMPARE_EXCHANGE);

		if (old != generation)
			panic("HDN private stack generation serialization failed");
		hdn_stack_store(storage, &storage->generation, generation + 1);
	}
	hdn_stack_store(storage, (unsigned long *)&storage->next,
			(unsigned long)hdn_stack_buckets[bucket]);
	smp_wmb();
	store_bucket(bucket, storage);
	*result = storage;
unlock:
	raw_spin_unlock_irqrestore(&stack_registry_lock, flags);
	if (!error) {
		atomic64_inc(&stack_allocations);
		atomic64_inc(&stack_live);
		return 0;
	}
discard:
	if (storage) {
		if (descriptor_claimed)
			hdn_execmem_free(storage);
		else
			vfree(storage);
	}
	if (bytes) {
		if (claimed)
			hdn_execmem_free(bytes);
		else
			vfree(bytes);
	}
	if (shadow)
		release_shadow(begin);
	kfree(life);
	ida_free(&stack_slots, slot);
	atomic64_inc(&stack_allocation_failures);
	return error;
}

int hdn_stack_alloc(struct task_struct *task, int node)
{
	struct hdn_stack_storage *storage;
	int error = allocate_stack(task, node, &storage);

	if (!error) {
		task->stack_vm_area = storage->backing;
		task->stack = (void *)storage->begin;
	}
	return error;
}

int __init hdn_stack_failure_create(unsigned int cpu, unsigned long *begin, unsigned long *cr3)
{
	struct hdn_stack_storage *storage;
	unsigned long magic = STACK_END_MAGIC;
	int error;

	if (cpu >= NR_CPUS || !cpu_possible(cpu) || num_online_cpus() != 1)
		return -EINVAL;
	error = allocate_stack(NULL, cpu_to_node(cpu), &storage);
	if (error)
		return error;
	/* Permanent CPU failure stacks have no task owner and never enter the
	 * scheduler's stack lifecycle. Their guard and alias rules are identical. */
	if (hdn_stack_construct(NULL, storage->begin, &magic, sizeof(magic)))
		panic("HDN could not initialize a failure stack");
	hdn_stack_publish_storage(storage);
	*begin = storage->begin;
	*cr3 = hdn_stack_mm_failure_install(cpu, storage);
	return 0;
}

void hdn_stack_free(struct task_struct *task)
{
	struct hdn_stack_storage *storage, *previous = NULL;
	unsigned long begin = (unsigned long)task->stack, flags;
	unsigned int bucket = hdn_stack_bucket(begin);

	raw_spin_lock_irqsave(&stack_registry_lock, flags);
	for (storage = hdn_stack_buckets[bucket]; storage; storage = storage->next) {
		if (storage->begin == begin)
			break;
		previous = storage;
	}
	if (!storage || storage->owner != task || storage->backing != task->stack_vm_area)
		panic("HDN private stack release identity mismatch");
	if (hdn_stack_mm_in_use(begin))
		panic("HDN private stack release while mapped on a CPU");
	if (previous)
		hdn_stack_store(previous, (unsigned long *)&previous->next, (unsigned long)storage->next);
	else
		store_bucket(bucket, storage->next);
	task->stack = NULL;
	task->stack_vm_area = NULL;
	raw_spin_unlock_irqrestore(&stack_registry_lock, flags);
	atomic64_dec(&stack_live);
	/* This retirement control block is separate from unmapped stack storage. */
	if (!queue_rcu_work(system_unbound_wq, &storage->lifetime->retire))
		panic("HDN private stack retirement was already queued");
}

unsigned long hdn_stack_task_reg(const struct task_struct *task, unsigned int offset)
{
	return hdn_task_reg_read(task, offset);
}

void hdn_stack_regs_snapshot(struct task_struct *task, struct pt_regs *snapshot)
{
	hdn_task_regs_snapshot(task, snapshot);
}

int hdn_stack_syscall_commit(struct task_struct *task, const struct pt_regs *before,
		const struct pt_regs *after)
{
	const unsigned long *old = (const unsigned long *)before;
	const unsigned long *new = (const unsigned long *)after;

	/* Generic PTRACE_SET_SYSCALL_INFO may change only syscall number,
	 * result and argument registers for the native/compat x86 ABIs. Check
	 * the complete delta before the first write; no kernel return register
	 * or FRED metadata is part of this interface. */
	for (unsigned int i = 0; i < sizeof(*before) / sizeof(*old); i++) {
		if (old[i] == new[i])
			continue;
		switch (i * sizeof(*old)) {
		case offsetof(struct pt_regs, orig_ax):
		case offsetof(struct pt_regs, ax):
		case offsetof(struct pt_regs, di):
		case offsetof(struct pt_regs, si):
		case offsetof(struct pt_regs, dx):
		case offsetof(struct pt_regs, r10):
		case offsetof(struct pt_regs, r8):
		case offsetof(struct pt_regs, r9):
		case offsetof(struct pt_regs, bx):
		case offsetof(struct pt_regs, cx):
		case offsetof(struct pt_regs, bp):
			break;
		default:
			return -EPERM;
		}
		if (hdn_task_reg_read(task, i * sizeof(*old)) != old[i])
			return -EAGAIN;
	}
	for (unsigned int i = 0; i < sizeof(*before) / sizeof(*old); i++)
		if (old[i] != new[i]) {
			int error = hdn_task_reg_update(task, i * sizeof(*old), new[i], ~0UL);
			if (error)
				return error;
		}
	return 0;
}

struct pt_regs *hdn_stack_bpf_regs(struct task_struct *task)
{
	struct pt_regs snapshot = { };
	unsigned long *out = (unsigned long *)&task->thread.hdn_bpf_regs;
	const unsigned long *in = (const unsigned long *)&snapshot;

	/* Preserve current-task register identity for tracing consumers. Remote
	 * BTF reads use a task-lifetime diagnostic copy, not a transient per-CPU
	 * buffer and not a generally readable alias of an inactive stack. As
	 * with reading a running task's live registers, concurrent sampling is
	 * not a coherent register transaction. A task with no stack yields zero. */
	if (task == current)
		return task_pt_regs(task);
	if (try_get_task_stack(task)) {
		hdn_stack_regs_snapshot(task, &snapshot);
		put_task_stack(task);
	}
	for (unsigned int i = 0; i < sizeof(snapshot) / sizeof(*out); i++)
		WRITE_ONCE(out[i], in[i]);
	return &task->thread.hdn_bpf_regs;
}

extern void __noreturn __hdn_stack_bootstrap(const struct hdn_stack_switch *transition);

/* No task or secondary CPU exists yet. Abandoning the boot call chain at the
 * fixed rest_init continuation avoids relocating stack-contained pointers. */
void __init __noreturn hdn_stack_bootstrap(void)
{
	struct hdn_stack_storage *storage;
	const struct hdn_stack_switch *transition;
	unsigned long magic = STACK_END_MAGIC, sp;
	int node = numa_node_id();

	if (current != &init_task || num_online_cpus() != 1 || irqs_disabled() ||
	    allocate_stack(&init_task, node, &storage))
		panic("HDN could not construct the private boot stack");
	for (unsigned int i = 0; i < HDN_STACK_PAGES; i++) {
		struct page *page = storage->backing->pages[i];

		if (memcg_kmem_charge_page(page, GFP_KERNEL, 0))
			panic("HDN could not account the private boot stack");
		mod_lruvec_page_state(page, NR_KERNEL_STACK_KB, PAGE_SIZE / 1024);
	}
	if (hdn_stack_construct(&init_task, storage->begin, &magic, sizeof(magic)) ||
	    hdn_rap_boot_stack_prepare(storage->begin, node))
		panic("HDN could not initialize the private boot stack");
	sp = round_down(storage->begin + THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING -
			sizeof(struct pt_regs), 16);
	local_irq_disable();
	init_task.stack = (void *)storage->begin;
	init_task.stack_vm_area = storage->backing;
	init_task.thread.sp = sp;
	stackleak_task_init(&init_task);
	hdn_stack_publish(&init_task);
	transition = hdn_stack_mm_prepare(&init_task, &init_task, sp);
	__hdn_stack_bootstrap(transition);
}

void __init hdn_stack_bootstrap_retire(void)
{
	unsigned long first_pfn = __pa_symbol(init_stack) >> PAGE_SHIFT;

	if (current != &init_task || !irqs_disabled() ||
	    !hdn_stack_mm_active(&init_task, (unsigned long)__builtin_frame_address(0)))
		panic("HDN private boot stack transition mismatch");
	this_cpu_write(cpu_current_top_of_stack, task_top_of_stack(&init_task));
	if (cpu_feature_enabled(X86_FEATURE_FRED))
		fred_update_rsp0();
	/* CPA may sleep during alias splitting. IRQs are safe again after the
	 * current-task entry stack pointer and private CR3 agree. */
	local_irq_enable();
	if (set_memory_np((unsigned long)init_stack, HDN_STACK_PAGES) ||
	    set_memory_np((unsigned long)__va(first_pfn << PAGE_SHIFT), HDN_STACK_PAGES))
		panic("HDN could not withdraw boot stack aliases");
	/* These linker-owned pages never return to the page allocator. Deny
	 * their future publication through both CPA and native leaf setters. */
	hdn_pt_window_update(__pa_symbol(&hdn_stack_boot_retired) >> PAGE_SHIFT,
			offset_in_page(&hdn_stack_boot_retired), 1, 0, HDN_PT_STORE);
	for (unsigned int i = 0; i < HDN_STACK_PAGES; i++)
		hdn_pt_window_clear(first_pfn + i);
}

#ifdef CONFIG_SECURITY_HARDENING_PRIVATE_STACKS_TEST
static int hdn_stack_test_fresh_zero(void)
{
	struct hdn_stack_storage *storage, *entry, *previous = NULL;
	unsigned long flags, value;
	unsigned int bucket;
	int error;

	error = allocate_stack(NULL, numa_node_id(), &storage);
	if (error)
		return error;
	for (unsigned long offset = 0; offset < THREAD_SIZE; offset += sizeof(value)) {
		error = hdn_stack_read(NULL, storage->begin + offset,
				       &value, sizeof(value));
		if (error || value) {
			error = error ?: -EUCLEAN;
			break;
		}
	}

	/* The unpublished ownerless allocation was never installed in a CPU
	 * view. Withdraw it exactly like an ordinary task stack, then let the
	 * normal RCU retirement path scrub and release its physical backing. */
	bucket = hdn_stack_bucket(storage->begin);
	raw_spin_lock_irqsave(&stack_registry_lock, flags);
	for (entry = hdn_stack_buckets[bucket]; entry; entry = entry->next) {
		if (entry == storage)
			break;
		previous = entry;
	}
	if (!entry || entry->owner || entry->published ||
	    hdn_stack_mm_in_use(entry->begin))
		panic("HDN private stack fresh-zero probe ownership mismatch");
	if (previous)
		hdn_stack_store(previous, (unsigned long *)&previous->next,
				(unsigned long)entry->next);
	else
		store_bucket(bucket, entry->next);
	raw_spin_unlock_irqrestore(&stack_registry_lock, flags);
	atomic64_dec(&stack_live);
	if (!queue_rcu_work(system_unbound_wq, &storage->lifetime->retire))
		panic("HDN private stack fresh-zero retirement was already queued");
	return error;
}

int hdn_stack_test_current(unsigned int mode)
{
	struct hdn_stack_storage *storage;
	unsigned long begin, direct;
	unsigned long flags;
	void *construction;
	u64 value;
	int error = -EINVAL;

	if (mode == 0) {
		error = hdn_stack_test_fresh_zero();
		if (error)
			return error;
	}
	flags = native_local_irq_save();
	storage = hdn_stack_lookup((unsigned long)task_stack_page(current));
	if (!storage || storage->owner != current || !storage->published ||
	    storage->backing != current->stack_vm_area ||
	    !hdn_stack_mm_active(current, (unsigned long)__builtin_frame_address(0)))
		goto out;
	begin = storage->begin;
	direct = (unsigned long)__va(storage->pfns[0] << PAGE_SHIFT);
	construction = storage->construction_address;
	switch (mode) {
	case 0:
		if (hdn_stack_read(current, begin, &value, sizeof(value)) ||
		    !copy_from_kernel_nofault(&value, (void *)begin - sizeof(value), sizeof(value)) ||
		    !copy_from_kernel_nofault(&value, (void *)begin + THREAD_SIZE, sizeof(value)) ||
		    !copy_from_kernel_nofault(&value, (void *)direct, sizeof(value)) ||
		    !copy_from_kernel_nofault(&value, construction, sizeof(value)))
			goto out;
		error = 0;
		break;
	case 1:
		pr_info("HDN_PRIVATE_STACK_PROBE_READY mode=1 lower_guard=%px\n",
			(void *)begin - sizeof(value));
		WRITE_ONCE(*(u64 *)(begin - sizeof(value)), 0);
		break;
	case 2:
		pr_info("HDN_PRIVATE_STACK_PROBE_READY mode=2 upper_guard=%px\n",
			(void *)begin + THREAD_SIZE);
		WRITE_ONCE(*(u64 *)(begin + THREAD_SIZE), 0);
		break;
	case 3:
		pr_info("HDN_PRIVATE_STACK_PROBE_READY mode=3 direct_alias=%px\n",
			(void *)direct);
		WRITE_ONCE(*(u64 *)direct, 0);
		break;
	case 4:
		pr_info("HDN_PRIVATE_STACK_PROBE_READY mode=4 construction_alias=%px\n",
			construction);
		WRITE_ONCE(*(u64 *)construction, 0);
		break;
	case 5:
		pr_info("HDN_PRIVATE_STACK_PROBE_READY mode=5 nx_stack=%px\n",
			(void *)begin);
		((void (*)(void))begin)();
		break;
	default:
		goto out;
	}
	if (!mode)
		goto out;
	pr_err("HDN_PRIVATE_STACK_PROBE_UNEXPECTED_RETURN mode=%u\n", mode);
out:
	native_local_irq_restore(flags);
	return error;
}
EXPORT_SYMBOL_GPL(hdn_stack_test_current);
#endif
