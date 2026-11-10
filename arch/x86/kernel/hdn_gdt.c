// SPDX-License-Identifier: GPL-2.0-only
/* Native GDT updates through CPU-private, supervisor-only, transient aliases. */
#include <linux/cpu.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/hardening.h>
#include <linux/hdn_pgtable.h>
#include <linux/mm.h>
#include <linux/percpu.h>
#include <linux/set_memory.h>
#include <linux/smp.h>
#include <linux/sort.h>
#include <linux/string.h>
#include <asm/desc.h>
#include <asm/hdn_gdt.h>
#include <asm/hdn_text.h>
#include <asm/mem_encrypt.h>
#include <asm/mmu_context.h>
#include <asm/smap.h>
#include <asm/special_insns.h>
#include <asm/tlbflush.h>
#include <xen/xen.h>
#include "hdn_gdt_internal.h"
#ifdef CONFIG_SECURITY_HARDENING_PGTABLE
#include "../mm/hdn_pgtable_internal.h"
#endif

struct hdn_gdt_cpu {
	atomic64_t sequence;
	bool normal_busy;
	bool emergency_busy;
};

/* Mapping identities never share storage with mutable transition state. */
struct hdn_gdt_config hdn_gdt_configs[NR_CPUS] __ro_after_init;
struct hdn_gdt_identity hdn_gdt_identities[NR_CPUS] __ro_after_init;
unsigned int hdn_gdt_cpu_count __ro_after_init;
static DEFINE_PER_CPU(struct hdn_gdt_cpu, hdn_gdt_cpu);
bool hdn_gdt_ready __ro_after_init;
static bool hdn_gdt_xen_ready __ro_after_init;
static bool hdn_gdt_backing_ro __ro_after_init;

bool hdn_gdt_active(void)
{
	return smp_load_acquire(&hdn_gdt_ready);
}

bool hdn_gdt_sealed(void)
{
	return smp_load_acquire(&hdn_gdt_backing_ro);
}

const char *hdn_gdt_state(void)
{
	if (xen_pv_domain())
		return hdn_gdt_sealed() ? "xen-pv-active" : "initializing";
	if (hdn_gdt_sealed())
		return "active";
	return hdn_gdt_active() ? "sealing" : "initializing";
}

bool hdn_gdt_protected_pfn(unsigned long first, unsigned long last)
{
	unsigned int cpu;

	if (!hdn_gdt_active() && !smp_load_acquire(&hdn_gdt_xen_ready))
		return false;
	for_each_possible_cpu(cpu) {
		unsigned long pfn = hdn_gdt_configs[cpu].pfn;

		if (pfn >= first && pfn <= last)
			return true;
	}
	return false;
}

static unsigned int hdn_gdt_cpu_for(const struct desc_struct *gdt)
{
	unsigned int cpu;

	for_each_possible_cpu(cpu)
		if (gdt == get_cpu_gdt_rw(cpu))
			return cpu;
	panic("HDN rejected an unowned GDT update");
}

static void hdn_gdt_check_range(unsigned int entry, size_t size)
{
	if (entry >= GDT_ENTRIES || !size ||
	    size > (GDT_ENTRIES - entry) * sizeof(struct desc_struct) ||
	    size % sizeof(struct desc_struct))
		panic("HDN rejected an invalid GDT descriptor range");
	if (!((entry >= GDT_ENTRY_TLS_MIN && entry <= GDT_ENTRY_TLS_MAX &&
	       size <= (GDT_ENTRY_TLS_MAX - entry + 1) * sizeof(struct desc_struct)) ||
	      (entry == GDT_ENTRY_CPUNODE && size == sizeof(struct desc_struct)) ||
	      (entry == GDT_ENTRY_TSS && size == sizeof(tss_desc)) ||
	      (entry == GDT_ENTRY_LDT && size == sizeof(ldt_desc))))
		panic("HDN rejected an unapproved GDT descriptor class");
}

static void hdn_gdt_check_tss(unsigned int cpu, const tss_desc *tss)
{
	unsigned long base = tss->base0 | (unsigned long)tss->base1 << 16 |
		(unsigned long)tss->base2 << 24 | (unsigned long)tss->base3 << 32;
	unsigned int limit = tss->limit0 | tss->limit1 << 16;

	/* Reject a recoverable #GP before entering the temporary CR3 context. */
	if (tss->type != DESC_TSS || !tss->p || tss->dpl || tss->zero0 ||
	    tss->zero1 || tss->g || limit < sizeof(struct x86_hw_tss) - 1 ||
	    limit > __KERNEL_TSS_LIMIT ||
	    base != (unsigned long)&get_cpu_entry_area(cpu)->tss.x86_tss)
		panic("HDN rejected an invalid native TSS descriptor");
}

static void hdn_gdt_completed(bool load_tr)
{
	unsigned int cpu = raw_smp_processor_id();
	u64 sequence = atomic64_inc_return(&this_cpu_ptr(&hdn_gdt_cpu)->sequence);

	if (sequence >= BIT_ULL(48))
		panic("HDN GDT transition sequence exhausted");
	hdn_x86_defer_transition(HDN_TRANS_KERNEL_DESCRIPTOR, (u64)cpu << 48 | sequence,
				 load_tr ? HDN_REASON_KERNEL_GDT_LTR : HDN_REASON_KERNEL_GDT_UPDATE);
}

void hdn_gdt_xen_validate(const struct desc_struct *gdt, unsigned int entry, size_t size)
{
	if (!smp_load_acquire(&hdn_gdt_xen_ready))
		return;
	if (preemptible() || hdn_gdt_cpu_for(gdt) != raw_smp_processor_id())
		panic("HDN rejected an unowned Xen GDT update");
	hdn_gdt_check_range(entry, size);
}

void hdn_gdt_xen_bind(unsigned int cpu, unsigned long pfn, unsigned int size)
{
	if (!smp_load_acquire(&hdn_gdt_xen_ready))
		return;
	if (cpu >= nr_cpu_ids || !cpu_possible(cpu) ||
	    pfn != hdn_gdt_configs[cpu].pfn || size != GDT_SIZE)
		panic("HDN rejected an unowned Xen GDT binding");
}

void hdn_gdt_xen_result(long result)
{
	if (result < 0 && smp_load_acquire(&hdn_gdt_xen_ready))
		panic("HDN Xen descriptor transition failed");
}

/* The multicall adapter rejects descriptor failures before these callbacks. */
void hdn_gdt_xen_complete(void *unused)
{
	if (smp_load_acquire(&hdn_gdt_xen_ready))
		hdn_gdt_completed(false);
}

/*
 * Raw CR3 preservation is intentional: AP exception setup and resume run
 * before cpu_tlbstate can be used. These private mms never acquire users or
 * ASIDs. PCID zero is flushed on entry; the sole non-global alias is cleared
 * and invalidated before restoring the exact saved CR3 (with a flush).
 * Interrupts remain disabled and neither allocation nor a remote TLB flush
 * is needed. A separate emergency window supports terminal NMI crash paths
 * even when their interrupted CPU was using its normal window.
 */
static notrace void hdn_gdt_update(unsigned int target, unsigned int entry,
				   const void *data, size_t size, bool load_tr)
{
	struct hdn_gdt_cpu *cpu;
	const struct hdn_gdt_window *window;
	bool *busy;
	unsigned long irq_flags, saved_cr3, alias = HDN_GDT_ALIAS;
	struct desc_ptr saved_gdt, writable_gdt;
	pte_t mapping;
	unsigned int this_cpu;
	tss_desc tss;

	local_irq_save(irq_flags);
	if (irq_flags & X86_EFLAGS_AC)
		panic("HDN GDT update entered with UACCESS enabled");
	this_cpu = raw_smp_processor_id();
	if (target != this_cpu)
		panic("HDN rejected a remote live GDT update");
	if (load_tr) {
		memcpy(&tss, &get_cpu_gdt_rw(target)[GDT_ENTRY_TSS], sizeof(tss));
		hdn_gdt_check_tss(target, &tss);
	}
#ifdef CONFIG_SECURITY_HARDENING_PGTABLE
	if (hdn_pt_active()) {
		if (target != hdn_pt_cpu())
			panic("HDN GDT hardware CPU identity mismatch");
		if (load_tr)
			hdn_pt_window_ltr(hdn_gdt_configs[target].pfn);
		else
			for (unsigned int i = 0; i < size / sizeof(unsigned long); i++)
				hdn_pt_window_update(hdn_gdt_configs[target].pfn,
					entry * sizeof(struct desc_struct) + i * sizeof(unsigned long),
					((const unsigned long *)data)[i], 0, HDN_PT_STORE);
		hdn_gdt_completed(load_tr);
		local_irq_restore(irq_flags);
		return;
	}
#endif
	cpu = this_cpu_ptr(&hdn_gdt_cpu);
	window = in_nmi() ? &hdn_gdt_configs[this_cpu].emergency :
			   &hdn_gdt_configs[this_cpu].normal;
	busy = in_nmi() ? &cpu->emergency_busy : &cpu->normal_busy;
	if (READ_ONCE(*busy) || !pte_none(ptep_get(window->pte)))
		panic("HDN GDT window reused while open");
	WRITE_ONCE(*busy, true);
	mapping = pfn_pte(hdn_gdt_configs[target].pfn,
			  __pgprot(pgprot_val(PAGE_KERNEL) & ~_PAGE_GLOBAL));
	native_set_pte(window->pte, mapping);
	if (pte_val(ptep_get(window->pte)) != pte_val(mapping))
		panic("HDN GDT window mapping mismatch");
	saved_cr3 = __native_read_cr3();
	native_write_cr3(window->cr3);
	lass_stac();
	if (load_tr) {
		native_store_gdt(&saved_gdt);
		writable_gdt.address = alias;
		writable_gdt.size = GDT_SIZE - 1;
		native_load_gdt(&writable_gdt);
		asm volatile("ltr %w0" : : "q" (GDT_ENTRY_TSS * 8) : "memory");
		native_load_gdt(&saved_gdt);
	} else {
		__inline_memcpy((void *)(alias + entry * sizeof(struct desc_struct)), data, size);
	}
	/* Close the writable alias before any helper can enter the protected
	 * page-table update path. In particular, native_pte_clear() may call
	 * hdn_pt_update(), which must never execute with UACCESS enabled. */
	lass_clac();
	native_pte_clear(window->mm, alias, window->pte);
	asm volatile("invlpg (%0)" : : "r" (alias) : "memory");
	native_write_cr3(saved_cr3);
	if (!pte_none(ptep_get(window->pte)))
		panic("HDN GDT window remained mapped");
	WRITE_ONCE(*busy, false);
	hdn_gdt_completed(load_tr);
	local_irq_restore(irq_flags);
}

void notrace hdn_gdt_write(struct desc_struct *gdt, unsigned int entry,
			   const void *data, size_t size)
{
	unsigned int target;
	unsigned long flags;
	u8 copy[GDT_ENTRY_TLS_ENTRIES * sizeof(struct desc_struct)];

	local_irq_save(flags);
	if (smp_load_acquire(&hdn_gdt_xen_ready))
		panic("HDN native descriptor API used on Xen PV");
	if (!hdn_gdt_active()) {
		memcpy(&gdt[entry], data, size);
		local_irq_restore(flags);
		return;
	}
	hdn_gdt_check_range(entry, size);
	if (size > sizeof(copy))
		panic("HDN GDT update exceeds its construction buffer");
	target = hdn_gdt_cpu_for(gdt);
	/* The source and destination cannot be confused by the temporary alias. */
	memcpy(copy, data, size);
	if (entry == GDT_ENTRY_TSS)
		hdn_gdt_check_tss(target, (const tss_desc *)copy);
	hdn_gdt_update(target, entry, copy, size, false);
	memzero_explicit(copy, sizeof(copy));
	local_irq_restore(flags);
}
EXPORT_SYMBOL_GPL(hdn_gdt_write);

bool notrace hdn_gdt_load_tr(void)
{
	unsigned long flags;
	struct desc_ptr saved, direct;
	unsigned int cpu;

	local_irq_save(flags);
	if (smp_load_acquire(&hdn_gdt_xen_ready))
		panic("HDN native LTR API used on Xen PV");
	if (!hdn_gdt_active()) {
		cpu = raw_smp_processor_id();
		native_store_gdt(&saved);
		if (saved.address == (unsigned long)get_cpu_gdt_ro(cpu)) {
			direct.address = (unsigned long)get_cpu_gdt_rw(cpu);
			direct.size = GDT_SIZE - 1;
			native_load_gdt(&direct);
		}
		asm volatile("ltr %w0" : : "q" (GDT_ENTRY_TSS * 8) : "memory");
		native_load_gdt(&saved);
		local_irq_restore(flags);
		return true;
	}
	hdn_gdt_update(raw_smp_processor_id(), GDT_ENTRY_TSS, NULL, 0, true);
	local_irq_restore(flags);
	return true;
}
EXPORT_SYMBOL_GPL(hdn_gdt_load_tr);

static void __init hdn_gdt_window_init(struct hdn_gdt_window *window)
{
	spinlock_t *lock;

	window->mm = mm_alloc();
	if (!window->mm)
		panic("HDN could not allocate a private GDT context");
	set_notrack_mm(window->mm);
	window->pte = get_locked_pte(window->mm, HDN_GDT_ALIAS, &lock);
	if (!window->pte)
		panic("HDN could not allocate a GDT window PTE");
	pte_unmap_unlock(window->pte, lock);
	window->cr3 = __sme_pa(window->mm->pgd);
}

static void hdn_gdt_writer_barrier(void *unused)
{
	/* Completion follows every old writer's IRQ-disabled direct store. */
	smp_mb();
}

static int __init hdn_gdt_identity_compare(const void *left, const void *right)
{
	const struct hdn_gdt_identity *a = left, *b = right;

	return (a->gsbase > b->gsbase) - (a->gsbase < b->gsbase);
}

static int __init hdn_gdt_init(void)
{
	unsigned int cpu, count = 0;

	BUILD_BUG_ON(NR_CPUS > U16_MAX);
	if (!kernel_wx_enforced())
		panic("HDN GDT protection requires NX");
	cpus_read_lock();
	for_each_possible_cpu(cpu) {
		struct hdn_gdt_config *context = &hdn_gdt_configs[cpu];

		context->pfn = PFN_DOWN(get_cpu_gdt_paddr(cpu));
		context->gsbase = cpu_kernelmode_gs_base(cpu);
		context->gdt_base = (unsigned long)get_cpu_gdt_ro(cpu);
		hdn_gdt_identities[count++] = (struct hdn_gdt_identity) {
			.gsbase = context->gsbase, .cpu = cpu,
		};
		if (!xen_pv_domain() && !hdn_pt_active()) {
			hdn_gdt_window_init(&context->normal);
			hdn_gdt_window_init(&context->emergency);
		}
	}
	sort(hdn_gdt_identities, count, sizeof(hdn_gdt_identities[0]),
	     hdn_gdt_identity_compare, NULL);
	for (cpu = 1; cpu < count; cpu++)
		if (hdn_gdt_identities[cpu - 1].gsbase == hdn_gdt_identities[cpu].gsbase)
			panic("HDN duplicate GDT CPU identity");
	hdn_gdt_cpu_count = count;
	/* All writers switch to the private primitive before any backing is RO. */
	if (xen_pv_domain())
		smp_store_release(&hdn_gdt_xen_ready, true);
	else
		smp_store_release(&hdn_gdt_ready, true);
	on_each_cpu(hdn_gdt_writer_barrier, NULL, 1);
	for_each_possible_cpu(cpu)
		if (set_memory_ro((unsigned long)get_cpu_gdt_rw(cpu), 1))
			panic("HDN could not protect GDT backing storage");
	smp_store_release(&hdn_gdt_backing_ro, true);
	cpus_read_unlock();
	return 0;
}
late_initcall(hdn_gdt_init);
