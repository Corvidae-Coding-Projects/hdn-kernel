// SPDX-License-Identifier: GPL-2.0-only
/* Closed stack translation: callers receive bytes, never writable aliases. */
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/hdn_rap.h>
#include <linux/sched.h>
#include <asm/irqflags.h>
#include <asm/pgtable.h>
#include <asm/hdn_stack.h>
#include <asm/hdn_stack_mm.h>
#include "../mm/hdn_pgtable_internal.h"
#include "hdn_stack_internal.h"

bool noinstr hdn_stack_address(unsigned long address)
{
	unsigned long base = READ_ONCE(hdn_stack_region);

	return base && address >= base && address - base < P4D_SIZE;
}

bool noinstr hdn_stack_overlaps(unsigned long address, size_t size)
{
	unsigned long base = READ_ONCE(hdn_stack_region);

	if (!base || !size)
		return false;
	return address >= base ? address - base < P4D_SIZE : size > base - address;
}

bool noinstr hdn_stack_retired_pfns(unsigned long pfn, unsigned long nr)
{
	unsigned long first = __pa_symbol(init_stack) >> PAGE_SHIFT;

	if (!nr || !READ_ONCE(hdn_stack_boot_retired))
		return false;
	return pfn >= first ? pfn - first < HDN_STACK_PAGES : nr > first - pfn;
}

struct hdn_stack_storage *noinstr hdn_stack_lookup(unsigned long address)
{
	struct hdn_stack_storage *storage;

	if (!hdn_stack_address(address))
		return NULL;
	for (storage = READ_ONCE(hdn_stack_buckets[hdn_stack_bucket(address)]);
	     storage; storage = READ_ONCE(storage->next))
		if (address >= storage->begin && address - storage->begin < THREAD_SIZE)
			return storage;
	return NULL;
}

void noinstr hdn_stack_store(struct hdn_stack_storage *storage,
		unsigned long *word, unsigned long value)
{
	unsigned long offset = (unsigned long)word - (unsigned long)storage;

	if (offset > sizeof(*storage) - sizeof(*word) || !IS_ALIGNED(offset, sizeof(*word)))
		__hdn_rap_fail(HDN_RAP_FAIL_STACK);
	hdn_pt_window_update(storage->header_pfn, offset, value, 0, HDN_PT_STORE);
}

static bool noinstr range_valid(const struct hdn_stack_storage *storage,
		const struct task_struct *task, unsigned long address, size_t size)
{
	return storage && storage->owner == task && address >= storage->begin &&
		address - storage->begin <= THREAD_SIZE &&
		size <= THREAD_SIZE - (address - storage->begin);
}

int noinstr hdn_stack_read(const struct task_struct *task, unsigned long address,
		void *destination, size_t size)
{
	unsigned long flags = native_local_irq_save();
	struct hdn_stack_storage *storage = hdn_stack_lookup(address);
	unsigned char *out = destination;
	int error = -EFAULT;

	if (storage && !storage->owner && task == current && hdn_stack_mm_active(NULL, address))
		task = NULL; /* Diagnostic read of the executing CPU's failure domain. */
	if (!range_valid(storage, task, address, size))
		goto out;
	while (size) {
		unsigned long offset = address - storage->begin;
		unsigned int byte = offset % sizeof(unsigned long);
		unsigned int count = min_t(size_t, sizeof(unsigned long) - byte, size);
		unsigned long word = hdn_pt_window_read(storage->pfns[offset >> PAGE_SHIFT],
					 offset_in_page(offset) & ~(sizeof(word) - 1));

		for (unsigned int i = 0; i < count; i++)
			WRITE_ONCE(out[i], (word >> (8 * (byte + i))) & 0xff);
		address += count;
		out += count;
		size -= count;
	}
	error = 0;
out:
	hdn_stack_account_read(error != 0);
	native_local_irq_restore(flags);
	return error;
}

int noinstr hdn_stack_construct(struct task_struct *task, unsigned long address,
		const void *source, size_t size)
{
	unsigned long flags = native_local_irq_save();
	struct hdn_stack_storage *storage = hdn_stack_lookup(address);
	const unsigned char *in = source;
	size_t requested = size;
	int error = -EPERM;

	if (!range_valid(storage, task, address, size) ||
	    storage->builder != current || READ_ONCE(storage->published))
		goto out;
	while (size) {
		unsigned long offset = address - storage->begin;
		unsigned long pfn = storage->pfns[offset >> PAGE_SHIFT];
		unsigned int byte = offset % sizeof(unsigned long);
		unsigned int count = min_t(size_t, sizeof(unsigned long) - byte, size);
		unsigned int page_offset = offset_in_page(offset) & ~(sizeof(unsigned long) - 1);
		unsigned long old = hdn_pt_window_read(pfn, page_offset), word = old;

		for (unsigned int i = 0; i < count; i++) {
			unsigned int shift = 8 * (byte + i);
			word = (word & ~(0xffUL << shift)) | ((unsigned long)READ_ONCE(in[i]) << shift);
		}
		/* The unpublished owner is the sole writer; a mismatch is a
		 * lifecycle error, not permission to overwrite a racing update. */
		if (hdn_pt_window_update(pfn, page_offset, word, old, HDN_PT_COMPARE_EXCHANGE) != old)
			__hdn_rap_fail(HDN_RAP_FAIL_STACK);
		address += count;
		in += count;
		size -= count;
	}
	error = 0;
out:
	if (!error)
		hdn_stack_account_construct(requested);
	native_local_irq_restore(flags);
	return error;
}

void noinstr hdn_stack_publish_storage(struct hdn_stack_storage *storage)
{
	unsigned long flags = native_local_irq_save();

	if (!storage || storage->builder != current || storage->published)
		__hdn_rap_fail(HDN_RAP_FAIL_STACK);
	/* Construction writes and RAP seeding must precede runnable publication. */
	smp_wmb();
	hdn_stack_store(storage, &storage->published, 1);
	hdn_stack_account_publication();
	native_local_irq_restore(flags);
}

void noinstr hdn_stack_publish(struct task_struct *task)
{
	unsigned long flags = native_local_irq_save();
	struct hdn_stack_storage *storage = hdn_stack_lookup((unsigned long)task->stack);

	if (!storage || storage->owner != task)
		__hdn_rap_fail(HDN_RAP_FAIL_STACK);
	hdn_stack_publish_storage(storage);
	native_local_irq_restore(flags);
}

int noinstr hdn_stack_user_store(struct task_struct *task, unsigned int offset,
		unsigned long value, unsigned long mask)
{
	unsigned long flags = native_local_irq_save();
	struct hdn_stack_storage *storage = hdn_stack_lookup((unsigned long)task->stack);
	unsigned long base, address, pfn, old, updated, cs, allowed = ~0UL;
	unsigned int page_offset;
	int error = -EPERM;

	if (!storage || storage->owner != task || !storage->published ||
	    (task->flags & PF_KTHREAD) || offset > sizeof(struct pt_regs) - sizeof(value) ||
	    !IS_ALIGNED(offset, sizeof(value)))
		goto out;
	/* Remote writes require the stop protocol. A running task may only
	 * update its own user return frame; kernel frames are never writable
	 * through this diagnostic interface. */
	if (task != current) {
		if (!(READ_ONCE(task->__state) & (__TASK_TRACED | __TASK_STOPPED)))
			goto out;
#ifdef CONFIG_SMP
		if (READ_ONCE(task->on_cpu))
			goto out;
#endif
	}
	base = storage->begin + THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING - sizeof(struct pt_regs);
	if (hdn_stack_read(task, base + offsetof(struct pt_regs, cs), &cs, sizeof(cs)) ||
	    (cs & SEGMENT_RPL_MASK) != USER_RPL)
		goto out;
	if (offset == offsetof(struct pt_regs, cs) || offset == offsetof(struct pt_regs, ss)) {
		/* Preserve FRED's upper metadata bits. The ordinary ptrace
		 * selector validation remains in the caller. */
		allowed = 0xffff;
		if ((value & SEGMENT_RPL_MASK) != USER_RPL)
			goto out;
	} else if (offset == offsetof(struct pt_regs, flags)) {
		allowed = X86_EFLAGS_CF | X86_EFLAGS_PF | X86_EFLAGS_AF | X86_EFLAGS_ZF |
			X86_EFLAGS_SF | X86_EFLAGS_TF | X86_EFLAGS_DF | X86_EFLAGS_OF |
			X86_EFLAGS_RF | X86_EFLAGS_AC | X86_EFLAGS_NT;
	}
	if (mask & ~allowed)
		goto out;
	address = base + offset - storage->begin;
	pfn = storage->pfns[address >> PAGE_SHIFT];
	page_offset = offset_in_page(address);
	old = hdn_pt_window_read(pfn, page_offset);
	updated = (old & ~mask) | (value & mask);
	if (hdn_pt_window_update(pfn, page_offset, updated, old, HDN_PT_COMPARE_EXCHANGE) != old)
		goto out;
	error = 0;
out:
	native_local_irq_restore(flags);
	return error;
}
