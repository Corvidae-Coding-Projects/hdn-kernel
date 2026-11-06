// SPDX-License-Identifier: GPL-2.0-only
/* Real allocation/alias probes; guest entry is covered by KVM selftests. */
#include <linux/export.h>
#include <linux/hdn_execmem.h>
#include <linux/hdn_pgtable.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <asm/hdn_vmcs.h>
#include <asm/set_memory.h>

int hdn_kvm_state_test_run(unsigned int mode);

static int probe_aliases(void *address, struct page *page, bool hidden)
{
	struct page *pages[] = { page };
	u32 word;
	void *alias;

	if (!copy_from_kernel_nofault(&word, page_address(page), sizeof(word)))
		return -EINVAL;
	if (hidden && !copy_from_kernel_nofault(&word, address, sizeof(word)))
		return -EINVAL;
	if (!set_memory_rw((unsigned long)address, 1))
		return -EINVAL;
	alias = vmap(pages, 1, VM_MAP, PAGE_KERNEL);
	if (alias) {
		vunmap(alias);
		return -EINVAL;
	}
	return 0;
}

int hdn_kvm_state_test_run(unsigned int mode)
{
	struct page **pages, *page;
	void *mapping;
	int result;

	if (mode > 2 || !hdn_pt_active())
		return -ENODEV;
#if IS_ENABLED(CONFIG_KVM_INTEL)
	mapping = hdn_vmcs_alloc(NUMA_NO_NODE, GFP_KERNEL, 1, false);
	if (!mapping)
		return -ENOMEM;
	page = pfn_to_page(hdn_vmcs_pa(mapping) >> PAGE_SHIFT);
	result = probe_aliases(mapping, page, false);
	if (!result && READ_ONCE(*(u32 *)mapping) != 1)
		result = -EINVAL;
	if (!result && mode == 1) {
		pr_info("HDN_KVM_STATE_PROBE_READY mode=1\n");
		WRITE_ONCE(*(u32 *)mapping, 0);
		pr_err("HDN_KVM_STATE_PROBE_UNEXPECTED_RETURN mode=1\n");
		result = -EINVAL;
	}
	hdn_vmcs_free(mapping);
	if (result)
		return result;
#else
	if (mode == 1)
		return -EOPNOTSUPP;
#endif
	/* A synthetic hardware page exercises the exact SVM ownership path
	 * without stealing a live CPU's MSR_VM_HSAVE_PA or running VMRUN. */
	pages = kmalloc(sizeof(*pages), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;
	page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page) {
		kfree(pages);
		return -ENOMEM;
	}
	pages[0] = page;
	mapping = vmap(pages, 1, VM_MAP | VM_MAP_PUT_PAGES, PAGE_KERNEL);
	if (!mapping) {
		__free_page(page);
		kfree(pages);
		return -ENOMEM;
	}
	find_vm_area(mapping)->flags |= VM_FLUSH_RESET_PERMS;
	result = hdn_execmem_claim_hardware(mapping);
	if (result) {
		vfree(mapping);
		return result;
	}
	result = hdn_execmem_hide_hardware(mapping);
	if (!result)
		result = probe_aliases(mapping, page, true);
	if (!result && mode == 2) {
		pr_info("HDN_KVM_STATE_PROBE_READY mode=2\n");
		WRITE_ONCE(*(u32 *)mapping, 0);
		pr_err("HDN_KVM_STATE_PROBE_UNEXPECTED_RETURN mode=2\n");
		result = -EINVAL;
	}
	hdn_execmem_free(mapping);
	if (!result)
		pr_info("HDN_KVM_STATE_PROBE_PASS\n");
	return result;
}
EXPORT_SYMBOL_GPL(hdn_kvm_state_test_run);
