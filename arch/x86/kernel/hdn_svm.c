// SPDX-License-Identifier: GPL-2.0-only
/* SVM hardware writes physical host-save storage directly. Software accesses
 * only the fixed fields below, through the private page window. There is no
 * generally mapped copy of the host's saved RSP, RIP, CR3 or GS base.
 */
#include <linux/hdn_execmem.h>
#include <linux/hdn_pgtable.h>
#include <linux/hdn_rap.h>
#include <linux/kvm_types.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <asm/hdn_svm.h>
#include <asm/msr.h>
#include <asm/mem_encrypt.h>
#include <asm/svm.h>
#include "../mm/hdn_pgtable_internal.h"

static struct hdn_svm_cpu {
	void *mapping;
	unsigned long pa, enabled;
} svm_host[NR_CPUS] __ro_after_init;
static DEFINE_MUTEX(svm_host_lock);

static void svm_store(unsigned long *slot, unsigned long value)
{
	hdn_pt_window_update(__pa_symbol(slot) >> PAGE_SHIFT,
			    offset_in_page(slot), value, 0, HDN_PT_STORE);
}

int hdn_svm_cpu_prepare(unsigned int cpu, struct page *page)
{
	struct page **pages;
	void *mapping;
	int error = -ENOMEM;

	if (!page)
		return -EINVAL;
	if (cpu >= nr_cpu_ids || !cpu_possible(cpu) || !hdn_pt_active()) {
		error = -EINVAL;
		goto free_page;
	}
	pages = kmalloc(sizeof(*pages), GFP_KERNEL);
	if (!pages)
		goto free_page;
	pages[0] = page;
	mapping = vmap(pages, 1, VM_MAP | VM_MAP_PUT_PAGES, PAGE_KERNEL);
	if (!mapping) {
		kfree(pages);
		goto free_page;
	}
	/* vmap now owns both the array and the page. */
	find_vm_area(mapping)->flags |= VM_FLUSH_RESET_PERMS;
	error = hdn_execmem_claim_hardware(mapping);
	if (error) {
		vfree(mapping);
		return error;
	}
	error = hdn_execmem_hide_hardware(mapping);
	if (error)
		goto free_owned;
	mutex_lock(&svm_host_lock);
	if (svm_host[cpu].mapping) {
		error = -EBUSY;
	} else {
		svm_store(&svm_host[cpu].pa, __sme_pa(page_address(page)));
		svm_store((unsigned long *)&svm_host[cpu].mapping, (unsigned long)mapping);
	}
	mutex_unlock(&svm_host_lock);
	if (!error)
		return 0;
free_owned:
	hdn_execmem_free(mapping);
	return error;
free_page:
	__free_page(page);
	return error;
}
EXPORT_SYMBOL_FOR_KVM(hdn_svm_cpu_prepare);

void hdn_svm_cpu_release(unsigned int cpu)
{
	void *mapping;

	if (cpu >= nr_cpu_ids)
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	mutex_lock(&svm_host_lock);
	if (svm_host[cpu].enabled)
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	mapping = svm_host[cpu].mapping;
	svm_store((unsigned long *)&svm_host[cpu].mapping, 0);
	svm_store(&svm_host[cpu].pa, 0);
	mutex_unlock(&svm_host_lock);
	if (mapping)
		hdn_execmem_free(mapping);
}
EXPORT_SYMBOL_FOR_KVM(hdn_svm_cpu_release);

static struct hdn_svm_cpu *noinstr svm_current(void)
{
	struct hdn_svm_cpu *host = &svm_host[hdn_pt_cpu()];

	if (preemptible() || !host->mapping || !host->pa)
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	return host;
}

void hdn_svm_enable(void)
{
	struct hdn_svm_cpu *host = svm_current();

	if (host->enabled)
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	svm_store(&host->enabled, 1);
	wrmsrq(MSR_VM_HSAVE_PA, host->pa);
}
EXPORT_SYMBOL_FOR_KVM(hdn_svm_enable);

void hdn_svm_disable(void)
{
	struct hdn_svm_cpu *host = &svm_host[hdn_pt_cpu()];

	/* Also used by emergency shutdown, which may precede full setup. */
	wrmsrq(MSR_VM_HSAVE_PA, 0);
	if (host->enabled)
		svm_store(&host->enabled, 0);
}
EXPORT_SYMBOL_FOR_KVM(hdn_svm_disable);

unsigned long noinstr hdn_svm_host_pa(void)
{
	struct hdn_svm_cpu *host = svm_current();

	if (!host->enabled || __rdmsr(MSR_VM_HSAVE_PA) != host->pa)
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	return host->pa;
}
EXPORT_SYMBOL_FOR_KVM(hdn_svm_host_pa);

static void noinstr svm_save_word(unsigned long pa, unsigned int offset, u64 value)
{
	hdn_pt_window_update(__sme_clr(pa) >> PAGE_SHIFT, offset,
			    value, 0, HDN_PT_STORE);
}

void noinstr hdn_svm_set_gprs(const struct hdn_svm_gprs *regs)
{
	struct hdn_svm_gprs copy = *regs;
	unsigned long pa = hdn_svm_host_pa();

#define SAVE_GPR(name) svm_save_word(pa, offsetof(struct vmcb, host_sev_es_save.name), copy.name)
	SAVE_GPR(rdi);
	SAVE_GPR(rsi);
	SAVE_GPR(rbx);
	SAVE_GPR(rbp);
	SAVE_GPR(r12);
	SAVE_GPR(r13);
	SAVE_GPR(r14);
	SAVE_GPR(r15);
#undef SAVE_GPR
}
EXPORT_SYMBOL_FOR_KVM(hdn_svm_set_gprs);

void hdn_svm_set_state(const struct hdn_svm_host_state *state)
{
	struct hdn_svm_host_state copy = *state;
	unsigned long pa = hdn_svm_host_pa(), packed, old;
	unsigned int offset = offsetof(struct vmcb, host_sev_es_save.pkru);

	BUILD_BUG_ON(offsetof(struct vmcb, host_sev_es_save.tsc_aux) !=
		     offsetof(struct vmcb, host_sev_es_save.pkru) + 4);
	BUILD_BUG_ON(offsetof(struct vmcb, host_sev_es_save.r15) + 8 > PAGE_SIZE);
	svm_save_word(pa, offsetof(struct vmcb, host_sev_es_save.xcr0), copy.xcr0);
	svm_save_word(pa, offsetof(struct vmcb, host_sev_es_save.xss), copy.xss);
	if (copy.debug_swap) {
		svm_save_word(pa, offsetof(struct vmcb, host_sev_es_save.dr0_addr_mask), copy.dr_mask[0]);
		svm_save_word(pa, offsetof(struct vmcb, host_sev_es_save.dr1_addr_mask), copy.dr_mask[1]);
		svm_save_word(pa, offsetof(struct vmcb, host_sev_es_save.dr2_addr_mask), copy.dr_mask[2]);
		svm_save_word(pa, offsetof(struct vmcb, host_sev_es_save.dr3_addr_mask), copy.dr_mask[3]);
	}
	/* PKRU and TSC_AUX share a word; retain the latter when not virtualized. */
	old = hdn_pt_window_read(__sme_clr(pa) >> PAGE_SHIFT, offset);
	packed = copy.pkru | ((u64)(copy.tsc_aux_valid ? copy.tsc_aux : old >> 32) << 32);
	svm_save_word(pa, offset, packed);
}
EXPORT_SYMBOL_FOR_KVM(hdn_svm_set_state);
