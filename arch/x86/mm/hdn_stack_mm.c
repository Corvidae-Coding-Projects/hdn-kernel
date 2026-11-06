// SPDX-License-Identifier: GPL-2.0-only
/* Closed replication of canonical top-level mappings into CPU-private roots. */
#include <linux/mm.h>
#include <linux/hdn_rap.h>
#include <linux/cpu.h>
#include <linux/sched.h>
#include <asm/irqflags.h>
#include <asm/pgalloc.h>
#include <asm/mmu_context.h>
#include <asm/invpcid.h>
#include <asm/switch_to.h>
#include <asm/desc.h>
#include "hdn_stack_mm_internal.h"
#include "hdn_pgtable_internal.h"
#include "hdn_pgtable_window_internal.h"

/* The serialization word is protected too: an ordinary data write must not
 * turn concurrent root copies into an unsynchronized publication. */
static unsigned long mirror_lock __ro_after_init;

static __always_inline unsigned long table_pfn(const void *table)
{
	return __phys_addr_nodebug((unsigned long)table) >> PAGE_SHIFT;
}

static void noinstr mirror_acquire(void)
{
	if (!native_irqs_disabled_flags(native_save_fl()) || in_nmi())
		__hdn_rap_fail(HDN_RAP_FAIL_STACK);
	while (hdn_pt_window_update(__pa_symbol(&mirror_lock) >> PAGE_SHIFT,
			offset_in_page(&mirror_lock), 1, 0, HDN_PT_COMPARE_EXCHANGE))
		cpu_relax();
	smp_mb();
}

static void noinstr mirror_release(void)
{
	smp_mb();
	hdn_pt_window_update(__pa_symbol(&mirror_lock) >> PAGE_SHIFT,
			offset_in_page(&mirror_lock), 0, 0, HDN_PT_STORE);
}

static void noinstr view_store(struct hdn_stack_view *view, unsigned long *word,
		unsigned long value)
{
	unsigned long offset = (unsigned long)word - (unsigned long)view;

	if (offset > sizeof(*view) - sizeof(*word) || !IS_ALIGNED(offset, sizeof(*word)))
		__hdn_rap_fail(HDN_RAP_FAIL_STACK);
	hdn_pt_window_update(table_pfn(word),
			offset_in_page(word), value, 0, HDN_PT_STORE);
}

static void noinstr copy_kernel_p4d(struct hdn_stack_view *view, unsigned long entry)
{
	unsigned long pfn = (entry & _PAGE_PRESENT) ? (entry & PTE_PFN_MASK) >> PAGE_SHIFT : 0;
	unsigned int slot = (hdn_stack_region >> P4D_SHIFT) & (PTRS_PER_PTE - 1);

	hdn_pt_window_copy(table_pfn(view->kernel_p4d), pfn ? __va(pfn << PAGE_SHIFT) : NULL, slot);
	view_store(view, &view->canonical_p4d, pfn);
}

/* During bootstrap only the boot CPU is running. Otherwise mirror_lock
 * serializes this copy with every canonical PGD/P4D writer. Retaining the
 * private branch during each copy keeps the executing stack mapped. */
void noinstr hdn_stack_mm_refresh(struct hdn_stack_view *view, unsigned long canonical_pfn, bool paired)
{
	const unsigned long *canonical = __va(canonical_pfn << PAGE_SHIFT);
	unsigned int slot = pgd_index(hdn_stack_region);

	if (pgtable_l5_enabled())
		copy_kernel_p4d(view, READ_ONCE(canonical[slot]));
	if (pgd_allocation_order())
		hdn_pt_window_copy(table_pfn(view->pgd) + 1, paired ? canonical + PTRS_PER_PGD : NULL, PTRS_PER_PTE);
	hdn_pt_window_copy(table_pfn(view->pgd), canonical, slot);
	view_store(view, &view->canonical_pgd, canonical_pfn);
	view_store(view, &view->canonical_pair, paired);
}

unsigned int noinstr hdn_stack_mm_view(unsigned int cpu, unsigned long cr3)
{
	unsigned long address = cr3 & CR3_ADDR_MASK;

	if (!READ_ONCE(hdn_stack_mm_ready))
		return 0;
	if (cpu >= NR_CPUS)
		__hdn_rap_fail(HDN_RAP_FAIL_STACK);
	for (unsigned int i = 0; i < HDN_STACK_VIEWS; i++) {
		const struct hdn_stack_view *view = &hdn_stack_cpus[cpu].views[i];
		const struct hdn_pt_window_pair *windows = &hdn_pt_windows[cpu].views[i];

		if (address == view->cr3 ||
		    (pgd_allocation_order() && address == view->cr3 + PAGE_SIZE) ||
		    address == windows->normal.cr3 || address == windows->emergency.cr3)
			return i;
	}
	/* Early idle startup still uses the canonical root and static stack.
	 * Once a private task has been activated an unknown root is an error. */
	if (!READ_ONCE(hdn_stack_cpus[cpu].views[0].stack) &&
	    !READ_ONCE(hdn_stack_cpus[cpu].views[1].stack))
		return 0;
	__hdn_rap_fail(HDN_RAP_FAIL_STACK);
}

static unsigned long noinstr route_cr3(unsigned long cr3, bool paired)
{
	struct hdn_stack_view *view;
	unsigned int cpu, index;
	unsigned long pfn;

	if (!READ_ONCE(hdn_stack_mm_ready))
		return cr3;
	cpu = hdn_pt_cpu();
	index = hdn_stack_mm_view(cpu, __native_read_cr3());
	view = &hdn_stack_cpus[cpu].views[index];
	if ((cr3 & CR3_ADDR_MASK) == view->cr3)
		return cr3;
	pfn = (cr3 & CR3_ADDR_MASK) >> PAGE_SHIFT;
	mirror_acquire();
	hdn_stack_mm_refresh(view, pfn, paired);
	mirror_release();
	return (cr3 & ~CR3_ADDR_MASK) | view->cr3;
}

unsigned long noinstr hdn_stack_mm_route(unsigned long cr3)
{
	return route_cr3(cr3, true);
}

unsigned long noinstr hdn_stack_mm_route_kernel(unsigned long cr3)
{
	return route_cr3(cr3, false);
}

bool noinstr hdn_stack_mm_matches(unsigned long canonical_cr3, unsigned long actual_cr3)
{
	const struct hdn_stack_view *view;
	unsigned int cpu;

	if (canonical_cr3 == actual_cr3)
		return true;
	if (!READ_ONCE(hdn_stack_mm_ready) ||
	    (canonical_cr3 & ~CR3_ADDR_MASK) != (actual_cr3 & ~CR3_ADDR_MASK))
		return false;
	cpu = hdn_pt_cpu();
	view = &hdn_stack_cpus[cpu].views[hdn_stack_mm_view(cpu, actual_cr3)];
	return (actual_cr3 & CR3_ADDR_MASK) == view->cr3 &&
		(canonical_cr3 & CR3_ADDR_MASK) >> PAGE_SHIFT == READ_ONCE(view->canonical_pgd);
}

unsigned long noinstr hdn_stack_mm_expected(unsigned long canonical_cr3)
{
	const struct hdn_stack_view *view;
	unsigned int cpu;
	unsigned long actual;

	if (!READ_ONCE(hdn_stack_mm_ready))
		return canonical_cr3;
	cpu = hdn_pt_cpu();
	actual = __native_read_cr3();
	view = &hdn_stack_cpus[cpu].views[hdn_stack_mm_view(cpu, actual)];
	if (actual == canonical_cr3 && !READ_ONCE(view->stack))
		return canonical_cr3;
	if ((canonical_cr3 & CR3_ADDR_MASK) >> PAGE_SHIFT != READ_ONCE(view->canonical_pgd))
		__hdn_rap_fail(HDN_RAP_FAIL_STACK);
	return (canonical_cr3 & ~CR3_ADDR_MASK) | view->cr3;
}

bool noinstr hdn_stack_mm_sync_owned(const struct mm_struct *mm, unsigned long address)
{
	if (!hdn_stack_region || pgd_index(address) != pgd_index(hdn_stack_region))
		return false;
	for (unsigned int n = 0; n < READ_ONCE(hdn_pt_cpu_count); n++) {
		unsigned int cpu = hdn_pt_cpu_identities[n].cpu;

		for (unsigned int i = 0; i < HDN_STACK_VIEWS; i++) {
			const struct hdn_pt_window_pair *pair = &hdn_pt_windows[cpu].views[i];

			if (hdn_stack_cpus[cpu].views[i].pgd &&
			    (mm == pair->normal.mm || mm == pair->emergency.mm))
				return true;
		}
	}
	return false;
}

bool noinstr hdn_stack_mm_update_begin(unsigned int level)
{
	if (!READ_ONCE(hdn_stack_mm_ready) || level < 4)
		return false;
	mirror_acquire();
	return true;
}

void noinstr hdn_stack_mm_update_abort(void)
{
	mirror_release();
}

void noinstr hdn_stack_mm_update_end(unsigned long pfn, unsigned int offset,
		unsigned long value, unsigned int level)
{
	unsigned int slot = offset / sizeof(unsigned long);
	unsigned int private_pgd = pgd_index(hdn_stack_region);
	unsigned int private_p4d = (hdn_stack_region >> P4D_SHIFT) & (PTRS_PER_PTE - 1);
	unsigned int top = pgtable_l5_enabled() ? 5 : 4;
	bool global = level == top && pfn == table_pfn(init_mm.pgd) && slot >= KERNEL_PGD_BOUNDARY;
	bool global_user = level == top && pgd_allocation_order() &&
		pfn == table_pfn(init_mm.pgd) + 1 && slot >= KERNEL_PGD_BOUNDARY;

	if (offset >= PAGE_SIZE || !IS_ALIGNED(offset, sizeof(unsigned long)) || level < 4)
		__hdn_rap_fail(HDN_RAP_FAIL_STACK);
	for (unsigned int n = 0; n < READ_ONCE(hdn_pt_cpu_count); n++) {
		unsigned int cpu = hdn_pt_cpu_identities[n].cpu;

		for (unsigned int i = 0; i < HDN_STACK_VIEWS; i++) {
			struct hdn_stack_view *view = &hdn_stack_cpus[cpu].views[i];
			unsigned long canonical = READ_ONCE(view->canonical_pgd);

			if (!canonical)
				continue;
			if (level == top && (pfn == canonical || global)) {
				if (slot != private_pgd)
					hdn_pt_window_update(table_pfn(view->pgd), offset, value, 0, HDN_PT_STORE);
				else if (pgtable_l5_enabled())
					copy_kernel_p4d(view, value);
			} else if (level == top && pgd_allocation_order() && view->canonical_pair &&
				   (pfn == canonical + 1 || global_user)) {
				/* The user half is an exact canonical PTI clone. */
				hdn_pt_window_update(table_pfn(view->pgd) + 1, offset, value, 0, HDN_PT_STORE);
			} else if (pgtable_l5_enabled() && level == 4 &&
				   pfn == READ_ONCE(view->canonical_p4d) && slot != private_p4d) {
				hdn_pt_window_update(table_pfn(view->kernel_p4d), offset, value, 0, HDN_PT_STORE);
			}
		}
	}
	mirror_release();
}

bool noinstr hdn_stack_mm_in_use(unsigned long begin)
{
	for (unsigned int n = 0; n < READ_ONCE(hdn_pt_cpu_count); n++) {
		unsigned int cpu = hdn_pt_cpu_identities[n].cpu;

		for (unsigned int i = 0; i < HDN_STACK_VIEWS; i++) {
			const struct hdn_stack_storage *storage = READ_ONCE(hdn_stack_cpus[cpu].views[i].stack);
			if (storage && storage->begin == begin)
				return true;
		}
	}
	return false;
}

bool noinstr hdn_stack_mm_active(const struct task_struct *owner, unsigned long address)
{
	unsigned int cpu = hdn_pt_cpu();
	const struct hdn_stack_storage *storage;

	if (READ_ONCE(hdn_stack_mm_ready)) {
		unsigned int index = hdn_stack_mm_view(cpu, __native_read_cr3());

		storage = READ_ONCE(hdn_stack_cpus[cpu].views[index].stack);
		if (storage)
			return storage->owner == owner && address >= storage->begin &&
				address - storage->begin < THREAD_SIZE;
	}
	return cpu == 0 && owner == &init_task && address >= (unsigned long)init_stack &&
		address - (unsigned long)init_stack < THREAD_SIZE;
}

static void noinstr install_stack(struct hdn_stack_view *view,
		const struct hdn_stack_storage *storage)
{
	unsigned long leaf_flags = pgprot_val(PAGE_KERNEL) & ~_PAGE_GLOBAL;

	hdn_pt_window_copy(table_pfn(view->pud), NULL, PTRS_PER_PTE);
	hdn_pt_window_copy(table_pfn(view->pmd), NULL, PTRS_PER_PTE);
	hdn_pt_window_copy(table_pfn(view->pte), NULL, PTRS_PER_PTE);
	for (unsigned int page = 0; page < HDN_STACK_PAGES; page++) {
		unsigned int slot = pte_index(storage->begin) + page;

		if (slot >= PTRS_PER_PTE)
			__hdn_rap_fail(HDN_RAP_FAIL_STACK);
		hdn_pt_window_update(table_pfn(view->pte), slot * sizeof(unsigned long),
			(storage->pfns[page] << PAGE_SHIFT) | leaf_flags, 0, HDN_PT_STORE);
	}
	hdn_pt_window_update(table_pfn(view->pmd), pmd_index(storage->begin) * sizeof(unsigned long),
		(table_pfn(view->pte) << PAGE_SHIFT) | _KERNPG_TABLE, 0, HDN_PT_STORE);
	hdn_pt_window_update(table_pfn(view->pud), pud_index(storage->begin) * sizeof(unsigned long),
		(table_pfn(view->pmd) << PAGE_SHIFT) | _KERNPG_TABLE, 0, HDN_PT_STORE);
	view_store(view, (unsigned long *)&view->stack, (unsigned long)storage);
}

unsigned long noinstr hdn_stack_mm_failure_install(unsigned int cpu,
		const struct hdn_stack_storage *storage)
{
	unsigned long flags = native_local_irq_save();
	struct hdn_stack_view *view;

	if (cpu >= NR_CPUS || !storage || storage->owner || !storage->published)
		__hdn_rap_fail(HDN_RAP_FAIL_STACK);
	view = &hdn_stack_cpus[cpu].views[HDN_STACK_FAILURE_VIEW];
	mirror_acquire();
	if (view->stack)
		__hdn_rap_fail(HDN_RAP_FAIL_STACK);
	hdn_stack_mm_refresh(view, table_pfn(init_mm.pgd), true);
	install_stack(view, storage);
	mirror_release();
	native_local_irq_restore(flags);
	return view->cr3;
}

/* A handler may interrupt a closed update, including the CR3/RSP switch
 * boundary. Its authenticated frame retains the interrupted root for exit;
 * all ordinary C executes with the corresponding ordinary private root. */
bool noinstr hdn_stack_mm_async_enter(void)
{
	unsigned long cr3 = __native_read_cr3();
	unsigned int cpu, index;
	const struct hdn_pt_window_pair *windows;
	struct desc_ptr gdt;
	bool private_gdt = false;

	if (!READ_ONCE(hdn_stack_mm_ready))
		return false;
	hdn_stack_account_async_root();
	cpu = hdn_pt_cpu();
	index = hdn_stack_mm_view(cpu, cr3);
	windows = &hdn_pt_windows[cpu].views[index];
	if ((cr3 & CR3_ADDR_MASK) == windows->normal.cr3 ||
	    (cr3 & CR3_ADDR_MASK) == windows->emergency.cr3) {
		native_store_gdt(&gdt);
		if (gdt.address == HDN_PT_TARGET) {
			gdt.address = hdn_stack_cpus[cpu].gdt_base;
			gdt.size = GDT_SIZE - 1;
			native_load_gdt(&gdt);
			private_gdt = true;
		}
		native_write_cr3(hdn_stack_cpus[cpu].views[index].cr3);
	}
	return private_gdt;
}

void noinstr hdn_stack_mm_async_exit(unsigned long cr3, bool gdt_window)
{
	unsigned int cpu, index;
	const struct hdn_pt_window_pair *windows;
	const struct hdn_pt_window *window;
	unsigned long leaf;
	struct desc_ptr gdt = { .address = HDN_PT_TARGET, .size = GDT_SIZE - 1 };

	if (!gdt_window)
		return;
	cpu = hdn_pt_cpu();
	index = hdn_stack_mm_view(cpu, cr3);
	windows = &hdn_pt_windows[cpu].views[index];
	if ((cr3 & CR3_ADDR_MASK) == windows->normal.cr3)
		window = &windows->normal;
	else if ((cr3 & CR3_ADDR_MASK) == windows->emergency.cr3)
		window = &windows->emergency;
	else
		__hdn_rap_fail(HDN_RAP_FAIL_STACK);
	leaf = READ_ONCE(window->table[HDN_PT_SLOT].pte);
	if ((leaf & PTE_PFN_MASK) >> PAGE_SHIFT != hdn_stack_cpus[cpu].gdt_pfn ||
	    (leaf & (_PAGE_PRESENT | _PAGE_RW | _PAGE_USER)) != (_PAGE_PRESENT | _PAGE_RW))
		__hdn_rap_fail(HDN_RAP_FAIL_STACK);
	/* Only closed root/entry assembly follows this restoration. The
	 * interrupted LTR can now complete against its original descriptor. */
	native_write_cr3(cr3);
	native_load_gdt(&gdt);
}

/* The hotplug controller prepares an inactive view while the target is
 * quiescent. It leaves the parked CPU's old view intact until the AP itself
 * has installed this root and discarded its old call chain. */
void noinstr hdn_stack_mm_cpu_prepare(unsigned int cpu, struct task_struct *idle)
{
	struct hdn_stack_view *view;
	struct hdn_stack_startup *startup;
	struct hdn_stack_storage *storage;
	unsigned long flags = native_local_irq_save();
	unsigned long sp = round_down((unsigned long)task_pt_regs(idle), 16);
	unsigned int index;

	if (!READ_ONCE(hdn_stack_mm_ready) || cpu >= NR_CPUS || cpu == hdn_pt_cpu() ||
	    cpu_online(cpu) || idle->pid || !(idle->flags & PF_KTHREAD))
		__hdn_rap_fail(HDN_RAP_FAIL_STACK);
	storage = hdn_stack_lookup(sp);
	if (!storage || storage->owner != idle || !storage->published)
		__hdn_rap_fail(HDN_RAP_FAIL_STACK);
	startup = &hdn_stack_startup[cpu];
	if (startup->resume)
		__hdn_rap_fail(HDN_RAP_FAIL_STACK);
	/* A failed wakeup can be retried without replacing a launch which the
	 * AP might still consume. The hotplug core serializes these attempts. */
	if (READ_ONCE(startup->cr3)) {
		for (index = 0; index < HDN_STACK_TASK_VIEWS; index++) {
			view = &hdn_stack_cpus[cpu].views[index];
			if (startup->cr3 == view->cr3 && view->stack == storage && startup->sp == sp) {
				native_local_irq_restore(flags);
				return;
			}
		}
		__hdn_rap_fail(HDN_RAP_FAIL_STACK);
	}
	index = READ_ONCE(hdn_stack_cpus[cpu].views[0].stack) ? 1 : 0;
	view = &hdn_stack_cpus[cpu].views[index];
	startup = &hdn_stack_startup[cpu];
	mirror_acquire();
	if (view->stack)
		__hdn_rap_fail(HDN_RAP_FAIL_STACK);
	hdn_stack_mm_refresh(view, table_pfn(init_mm.pgd), true);
	install_stack(view, storage);
	hdn_pt_window_update(table_pfn(&startup->sp), offset_in_page(&startup->sp),
			     sp, 0, HDN_PT_STORE);
	/* The launch CR3 is published last; the AP checks its hardware APIC
	 * identity against this sealed row before loading either SP or GS. */
	smp_wmb();
	hdn_pt_window_update(table_pfn(&startup->cr3), offset_in_page(&startup->cr3),
			     view->cr3, 0, HDN_PT_STORE);
	mirror_release();
	native_local_irq_restore(flags);
}

unsigned long noinstr hdn_stack_mm_cpu_enter(void)
{
	unsigned int cpu = hdn_pt_cpu();
	unsigned long cr3 = __native_read_cr3(), sp;
	struct hdn_stack_startup *startup = &hdn_stack_startup[cpu];
	const struct hdn_stack_view *view = &hdn_stack_cpus[cpu].views[hdn_stack_mm_view(cpu, cr3)];

	asm volatile("movq %%rsp,%0" : "=r" (sp));
	if (!native_irqs_disabled_flags(native_save_fl()) || cr3 != startup->cr3 ||
	    !view->stack || sp > startup->sp || startup->sp - sp > 512)
		__hdn_rap_fail(HDN_RAP_FAIL_STACK);
	/* Re-establish current from the sealed owner before instrumented C can
	 * use it. The startup assembly already selected GS by hardware APIC ID. */
	this_cpu_write(current_task, (struct task_struct *)view->stack->owner);
	this_cpu_write(cpu_current_top_of_stack, view->stack->begin + THREAD_SIZE);
	/* S3 retains this task and its protected call-chain checkpoint. It
	 * must not take the hotplug path which discards an idle task's chain. */
	if (startup->resume) {
		if (startup->resume != 1)
			__hdn_rap_fail(HDN_RAP_FAIL_STACK);
		return 1;
	}
	hdn_stack_mm_finish();
	hdn_pt_window_update(table_pfn(&startup->cr3), offset_in_page(&startup->cr3),
			     0, 0, HDN_PT_STORE);
	return 0;
}

void noinstr hdn_stack_mm_resume_prepare(unsigned long sp)
{
	unsigned int cpu = hdn_pt_cpu();
	unsigned long cr3 = __native_read_cr3();
	unsigned int index = hdn_stack_mm_view(cpu, cr3);
	struct hdn_stack_startup *startup = &hdn_stack_startup[cpu];
	const struct hdn_stack_view *view = &hdn_stack_cpus[cpu].views[index];

	if (!native_irqs_disabled_flags(native_save_fl()) || index >= HDN_STACK_TASK_VIEWS ||
	    !view->stack || view->stack->owner != current || startup->cr3 || startup->resume ||
	    sp < view->stack->begin || sp >= view->stack->begin + THREAD_SIZE ||
	    (cr3 & CR3_ADDR_MASK) != view->cr3)
		__hdn_rap_fail(HDN_RAP_FAIL_STACK);
	hdn_pt_window_update(table_pfn(&startup->sp), offset_in_page(&startup->sp), sp, 0, HDN_PT_STORE);
	hdn_pt_window_update(table_pfn(&startup->resume), offset_in_page(&startup->resume), 1, 0, HDN_PT_STORE);
	/* Startup has PCIDE disabled. Use the same hierarchy with PCID zero;
	 * the sealed processor snapshot restores the original control state. */
	smp_wmb();
	hdn_pt_window_update(table_pfn(&startup->cr3), offset_in_page(&startup->cr3),
			     view->cr3, 0, HDN_PT_STORE);
}

void noinstr hdn_stack_mm_resume_finish(void)
{
	struct hdn_stack_startup *startup = &hdn_stack_startup[hdn_pt_cpu()];

	if (!native_irqs_disabled_flags(native_save_fl()) || startup->resume != 1 ||
	    !startup->cr3 || startup->cr3 != (__native_read_cr3() & CR3_ADDR_MASK))
		__hdn_rap_fail(HDN_RAP_FAIL_STACK);
	hdn_pt_window_update(table_pfn(&startup->cr3), offset_in_page(&startup->cr3), 0, 0, HDN_PT_STORE);
	hdn_pt_window_update(table_pfn(&startup->resume), offset_in_page(&startup->resume), 0, 0, HDN_PT_STORE);
}

const struct hdn_stack_switch *noinstr hdn_stack_mm_prepare(struct task_struct *prev,
		struct task_struct *next, unsigned long next_sp)
{
	unsigned long cr3 = __native_read_cr3();
	unsigned int cpu = hdn_pt_cpu(), index = hdn_stack_mm_view(cpu, cr3);
	struct hdn_stack_view *out, *in;
	struct hdn_stack_storage *storage = hdn_stack_lookup(next_sp);

	if (index >= HDN_STACK_TASK_VIEWS)
		__hdn_rap_fail(HDN_RAP_FAIL_STACK);
	out = &hdn_stack_cpus[cpu].views[index];
	in = &hdn_stack_cpus[cpu].views[index ^ 1];
	if (!READ_ONCE(hdn_stack_mm_ready) || !storage || storage->owner != next ||
	    !storage->published || !IS_ALIGNED(next_sp, sizeof(unsigned long)) ||
	    next_sp > storage->begin + THREAD_SIZE - sizeof(struct inactive_task_frame) ||
	    READ_ONCE(in->stack) ||
	    (out->stack ? (out->stack->owner != prev || (cr3 & CR3_ADDR_MASK) != out->cr3) :
	     (prev != &init_task || ((cr3 & CR3_ADDR_MASK) != out->cr3 &&
	      (cr3 & CR3_ADDR_MASK) >> PAGE_SHIFT != out->canonical_pgd))))
		__hdn_rap_fail(HDN_RAP_FAIL_STACK);
	mirror_acquire();
	hdn_stack_mm_refresh(in, READ_ONCE(out->canonical_pgd), READ_ONCE(out->canonical_pair));
	install_stack(in, storage);
	view_store(in, &in->transition.sp, next_sp);
	view_store(in, &in->transition.cr3, (cr3 & ~CR3_ADDR_MASK) | in->cr3);
	mirror_release();
	hdn_stack_account_switch();
	return &in->transition;
}

/* The assembly transition has installed the incoming CR3 and RSP. Do not
 * expose ordinary C until the old hierarchy and every cached PCID translation
 * have lost access to the outgoing stack. */
void noinstr hdn_stack_mm_finish(void)
{
	unsigned long cr3 = __native_read_cr3();
	unsigned int cpu = hdn_pt_cpu(), index = hdn_stack_mm_view(cpu, cr3);
	struct hdn_stack_view *in, *out;
	unsigned long sp;

	if (index >= HDN_STACK_TASK_VIEWS)
		__hdn_rap_fail(HDN_RAP_FAIL_STACK);
	in = &hdn_stack_cpus[cpu].views[index];
	out = &hdn_stack_cpus[cpu].views[index ^ 1];
	asm volatile("movq %%rsp,%0" : "=r" (sp));
	if (!in->stack || (cr3 & CR3_ADDR_MASK) != in->cr3 ||
	    sp < in->stack->begin || sp >= in->stack->begin + THREAD_SIZE)
		__hdn_rap_fail(HDN_RAP_FAIL_STACK);
	mirror_acquire();
	hdn_pt_window_copy(table_pfn(out->pud), NULL, PTRS_PER_PTE);
	hdn_pt_window_copy(table_pfn(out->pmd), NULL, PTRS_PER_PTE);
	hdn_pt_window_copy(table_pfn(out->pte), NULL, PTRS_PER_PTE);
	/* Withdraw canonical ownership before the scheduler releases old mm
	 * references. No stale PFN identity may match a later PGD allocation. */
	view_store(out, &out->canonical_pgd, 0);
	view_store(out, &out->canonical_pair, 0);
	view_store(out, &out->canonical_p4d, 0);
	view_store(out, (unsigned long *)&out->stack, 0);
	hdn_pt_window_copy(table_pfn(out->pgd), NULL, pgd_index(hdn_stack_region));
	if (pgd_allocation_order())
		hdn_pt_window_copy(table_pfn(out->pgd) + 1, NULL, PTRS_PER_PTE);
	if (static_cpu_has(X86_FEATURE_INVPCID)) {
		invpcid_flush_all_nonglobals();
	} else {
		unsigned long cr4 = native_read_cr4(), temporary = cr4 ^ X86_CR4_PGE;

		/* Change only PGE; preserve SMEP, SMAP, PCIDE and all other control
		 * bits. This is the native fallback when INVPCID is unavailable. */
		asm volatile("movq %0,%%cr4; movq %1,%%cr4"
			     : : "r" (temporary), "r" (cr4) : "memory");
	}
	mirror_release();
}
