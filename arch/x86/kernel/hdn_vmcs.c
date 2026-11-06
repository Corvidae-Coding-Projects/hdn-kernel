// SPDX-License-Identifier: GPL-2.0-only
/* VMCS memory is hardware-owned after its revision header is initialized.
 * Native VMREAD/VMWRITE access remains available without a writable CPU alias.
 */
#include <linux/hdn_execmem.h>
#include <linux/hdn_pgtable.h>
#include <linux/hdn_rap.h>
#include <linux/kvm_types.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/vmalloc.h>
#include <asm/hdn_vmcs.h>
#include "../mm/hdn_pgtable_internal.h"

struct hdn_vmcs {
	struct hdn_vmcs *next;
	unsigned long address, pa;
};

static struct hdn_vmcs *vmcs_list __ro_after_init;
static DEFINE_MUTEX(vmcs_lock);

static void vmcs_store(struct hdn_vmcs **slot, struct hdn_vmcs *value)
{
	unsigned long pfn = is_vmalloc_addr(slot) ? vmalloc_to_pfn(slot) :
		__pa_symbol(slot) >> PAGE_SHIFT;

	hdn_pt_window_update(pfn, offset_in_page(slot), (unsigned long)value, 0, HDN_PT_STORE);
}

void *hdn_vmcs_alloc(int node, gfp_t flags, u32 revision, bool shadow)
{
	struct hdn_vmcs *record;
	void *vmcs;
	int error;

	if (!hdn_pt_active() || revision & BIT(31))
		return NULL;
	record = __vmalloc_node_range(2 * PAGE_SIZE, PAGE_SIZE, VMALLOC_START,
		VMALLOC_END, flags | __GFP_ZERO, PAGE_KERNEL, VM_FLUSH_RESET_PERMS,
		node, __builtin_return_address(0));
	if (!record)
		return NULL;
	error = hdn_execmem_claim_data(record);
	if (error) {
		vfree(record);
		return NULL;
	}
	vmcs = (char *)record + PAGE_SIZE;
	*(u32 *)vmcs = revision | (shadow ? BIT(31) : 0);
	record->address = (unsigned long)vmcs;
	record->pa = vmalloc_to_pfn(vmcs) << PAGE_SHIFT;
	mutex_lock(&vmcs_lock);
	record->next = vmcs_list;
	error = hdn_execmem_seal_data(record);
	if (!error)
		vmcs_store(&vmcs_list, record);
	mutex_unlock(&vmcs_lock);
	if (error) {
		hdn_execmem_free(record);
		return NULL;
	}
	return vmcs;
}
EXPORT_SYMBOL_FOR_KVM(hdn_vmcs_alloc);

unsigned long hdn_vmcs_pa(const void *vmcs)
{
	const struct hdn_vmcs *record;
	unsigned long pa = 0;

	rcu_read_lock();
	for (record = READ_ONCE(vmcs_list); record; record = READ_ONCE(record->next))
		if (record->address == (unsigned long)vmcs) {
			pa = record->pa;
			break;
		}
	rcu_read_unlock();
	if (!pa)
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	return pa;
}
EXPORT_SYMBOL_FOR_KVM(hdn_vmcs_pa);

void hdn_vmcs_free(void *vmcs)
{
	struct hdn_vmcs **link, *record;

	if (!vmcs)
		return;
	/* KVM has already VMCLEARed and removed every CPU reference. Unpublish
	 * the physical identity before the allocator can recycle either page. */
	mutex_lock(&vmcs_lock);
	for (link = &vmcs_list; (record = *link); link = &record->next)
		if (record->address == (unsigned long)vmcs)
			break;
	if (!record)
		__hdn_rap_fail(HDN_RAP_FAIL_SWITCH);
	vmcs_store(link, record->next);
	mutex_unlock(&vmcs_lock);
	synchronize_rcu();
	hdn_execmem_free(record);
}
EXPORT_SYMBOL_FOR_KVM(hdn_vmcs_free);
