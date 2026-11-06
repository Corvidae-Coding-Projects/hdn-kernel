// SPDX-License-Identifier: GPL-2.0-only
/* Hypervisor-supplied code is a foreign ABI, not a C function-pointer target.
 * Publish only the owned boot page and its independently queried VTL entry.
 * The hypervisor is trusted to supply and resume these instruction sequences.
 */
#include <linux/hdn_execmem.h>
#include <linux/spinlock.h>
#include <asm/hdn_hyperv.h>
#include <asm/mshyperv.h>
#include "../mm/hdn_pgtable_internal.h"

unsigned long hdn_hv_hypercall_target __ro_after_init;
unsigned long hdn_hv_vtl_target __ro_after_init;
static unsigned long hdn_hv_page __ro_after_init;
static unsigned long hdn_hv_vtl_entry __ro_after_init;
static DEFINE_RAW_SPINLOCK(hdn_hv_lock);

static void hdn_hv_store(unsigned long *word, unsigned long value)
{
	if (hdn_pt_active())
		hdn_pt_window_update(__pa_symbol(word) >> PAGE_SHIFT,
				offset_in_page(word), value, 0, HDN_PT_STORE);
	else
		WRITE_ONCE(*word, value);
}

void __init hdn_hv_page_init(void *page)
{
	if (!PAGE_ALIGNED(page) || hdn_hv_page ||
	    !hdn_execmem_sealed((unsigned long)page, 1))
		panic("HDN Hyper-V hypercall page is not privately sealed");
	hdn_hv_store(&hdn_hv_page, (unsigned long)page);
}

void *hdn_hv_resume_page(void *saved)
{
	/* Validate before issuing the MSR write which lets the hypervisor fill
	 * physical memory. Later publication is too late to reject a bad PFN. */
	if (!hdn_hv_page || (unsigned long)saved != hdn_hv_page)
		panic("HDN Hyper-V resume page identity changed");
	return (void *)hdn_hv_page;
}

/* Called under the existing boot/syscore/shutdown lifetime serialization.
 * No allocation or stop-machine update is needed on the panic path. The page
 * stays owned for the kernel lifetime, including while calls are disabled. */
void hdn_hv_publish(void *page)
{
	unsigned long flags, address = (unsigned long)page;

	/* Panic can interrupt a publisher holding the lock. Revocation cannot
	 * wait for another CPU, and it never frees the immutable code page. */
	if (!address) {
		hdn_hv_store(&hdn_hv_hypercall_target, 0);
		hdn_hv_store(&hdn_hv_vtl_target, 0);
		return;
	}
	raw_spin_lock_irqsave(&hdn_hv_lock, flags);
	if (address && address != hdn_hv_page)
		panic("HDN Hyper-V attempted to replace its sealed hypercall page");
	hdn_hv_store(&hdn_hv_vtl_target, address ? hdn_hv_vtl_entry : 0);
	hdn_hv_store(&hdn_hv_hypercall_target, address);
	raw_spin_unlock_irqrestore(&hdn_hv_lock, flags);
}

int hdn_hv_vtl_init(u64 requested)
{
#ifdef CONFIG_HYPERV_VTL_MODE
	struct hv_input_get_vp_registers *input;
	union hv_register_value *output;
	union hv_register_vsm_page_offsets offsets;
	unsigned long flags, target;
	u64 status;
	int error = 0;

	/* Do not trust a caller-supplied offset into executable memory. */
	local_irq_save(flags);
	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	output = *this_cpu_ptr(hyperv_pcpu_output_arg);
	memset(input, 0, sizeof(*input));
	input->partition_id = HV_PARTITION_ID_SELF;
	input->vp_index = HV_VP_INDEX_SELF;
	input->names[0] = HV_REGISTER_VSM_CODE_PAGE_OFFSETS;
	status = hv_do_rep_hypercall(HVCALL_GET_VP_REGISTERS, 1, 0, input, output);
	offsets.as_uint64 = hv_result_success(status) && hv_repcomp(status) == 1 ?
		output[0].reg64 : 0;
	local_irq_restore(flags);
	if (!hv_result_success(status) || hv_repcomp(status) != 1)
		return -EIO;
	if (offsets.reserved_mbz || !requested || requested >= HV_HYP_PAGE_SIZE ||
	    requested != offsets.vtl_return_offset)
		return -EINVAL;
	raw_spin_lock_irqsave(&hdn_hv_lock, flags);
	target = hdn_hv_page + requested;
	if (!hdn_hv_page || !hdn_hv_hypercall_target ||
	    (hdn_hv_vtl_entry && hdn_hv_vtl_entry != target)) {
		error = -EINVAL;
	} else {
		hdn_hv_store(&hdn_hv_vtl_entry, target);
		hdn_hv_store(&hdn_hv_vtl_target, target);
	}
	raw_spin_unlock_irqrestore(&hdn_hv_lock, flags);
	return error;
#else
	return -EOPNOTSUPP;
#endif
}
