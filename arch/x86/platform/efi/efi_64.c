// SPDX-License-Identifier: GPL-2.0
/*
 * x86_64 specific EFI support functions
 * Based on Extensible Firmware Interface Specification version 1.0
 *
 * Copyright (C) 2005-2008 Intel Co.
 *	Fenghua Yu <fenghua.yu@intel.com>
 *	Bibo Mao <bibo.mao@intel.com>
 *	Chandramouli Narayanan <mouli@linux.intel.com>
 *	Huang Ying <ying.huang@intel.com>
 *
 * Code to convert EFI to E820 map has been implemented in elilo bootloader
 * based on a EFI patch by Edgar Hucek. Based on the E820 map, the page table
 * is setup appropriately for EFI runtime code.
 * - mouli 06/14/2007.
 *
 */

#define pr_fmt(fmt) "efi: " fmt

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/memblock.h>
#include <linux/ioport.h>
#include <linux/mc146818rtc.h>
#include <linux/efi.h>
#include <linux/export.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/reboot.h>
#include <linux/slab.h>
#include <linux/hdn_execmem.h>
#include <linux/hdn_pgtable.h>
#include <linux/kmemleak.h>
#include <linux/overflow.h>
#include <linux/vmalloc.h>
#include <linux/xarray.h>
#include <linux/ucs2_string.h>
#include <linux/cc_platform.h>
#include <linux/sched/task.h>

#include <asm/setup.h>
#include <asm/page.h>
#include <asm/e820/api.h>
#include <asm/tlbflush.h>
#include <asm/proto.h>
#include <asm/efi.h>
#include <asm/cacheflush.h>
#include <asm/fixmap.h>
#include <asm/realmode.h>
#include <asm/time.h>
#include <asm/pgalloc.h>
#include <asm/sev.h>

/*
 * We allocate runtime services regions top-down, starting from -4G, i.e.
 * 0xffff_ffff_0000_0000 and limit EFI VA mapping space to 64G.
 */
static u64 efi_va = EFI_VA_START;
static struct mm_struct *efi_prev_mm;

/*
 * We need our own copy of the higher levels of the page tables
 * because we want to avoid inserting EFI region mappings (EFI_VA_END
 * to EFI_VA_START) into the standard kernel page tables. Everything
 * else can be shared, see efi_sync_low_kernel_mappings().
 *
 * We don't want the pgd on the pgd_list and cannot use pgd_alloc() for the
 * allocation.
 */
int __init efi_alloc_page_tables(void)
{
	pgd_t *pgd, *efi_pgd;
	p4d_t *p4d;
	pud_t *pud;
	gfp_t gfp_mask;

	gfp_mask = GFP_KERNEL | __GFP_ZERO;
	efi_pgd = (pgd_t *)hdn_pt_alloc_address(gfp_mask, pgd_allocation_order(), false);
	if (!efi_pgd)
		goto fail;

	pgd = efi_pgd + pgd_index(EFI_VA_END);
	p4d = p4d_alloc(&init_mm, pgd, EFI_VA_END);
	if (!p4d)
		goto free_pgd;

	pud = pud_alloc(&init_mm, p4d, EFI_VA_END);
	if (!pud)
		goto free_p4d;

	efi_mm.pgd = efi_pgd;
	mm_init_cpumask(&efi_mm);
	init_new_context(NULL, &efi_mm);
	set_notrack_mm(&efi_mm);

	return 0;

free_p4d:
	if (pgtable_l5_enabled())
		hdn_pt_free_address((unsigned long)pgd_page_vaddr(*pgd), 0);
free_pgd:
	hdn_pt_free_address((unsigned long)efi_pgd, pgd_allocation_order());
fail:
	return -ENOMEM;
}

/*
 * Add low kernel mappings for passing arguments to EFI functions.
 */
void efi_sync_low_kernel_mappings(void)
{
	unsigned num_entries;
	pgd_t *pgd_k, *pgd_efi;
	p4d_t *p4d_k, *p4d_efi;
	pud_t *pud_k, *pud_efi;
	pgd_t *efi_pgd = efi_mm.pgd;

	pgd_efi = efi_pgd + pgd_index(PAGE_OFFSET);
	pgd_k = pgd_offset_k(PAGE_OFFSET);

	num_entries = pgd_index(EFI_VA_END) - pgd_index(PAGE_OFFSET);
	hdn_pt_copy(pgd_efi, pgd_k, sizeof(pgd_t) * num_entries, pgtable_l5_enabled() ? 5 : 4);

	pgd_efi = efi_pgd + pgd_index(EFI_VA_END);
	pgd_k = pgd_offset_k(EFI_VA_END);
	p4d_efi = p4d_offset(pgd_efi, 0);
	p4d_k = p4d_offset(pgd_k, 0);

	num_entries = p4d_index(EFI_VA_END);
	hdn_pt_copy(p4d_efi, p4d_k, sizeof(p4d_t) * num_entries, 4);

	/*
	 * We share all the PUD entries apart from those that map the
	 * EFI regions. Copy around them.
	 */
	BUILD_BUG_ON((EFI_VA_START & ~PUD_MASK) != 0);
	BUILD_BUG_ON((EFI_VA_END & ~PUD_MASK) != 0);

	p4d_efi = p4d_offset(pgd_efi, EFI_VA_END);
	p4d_k = p4d_offset(pgd_k, EFI_VA_END);
	pud_efi = pud_offset(p4d_efi, 0);
	pud_k = pud_offset(p4d_k, 0);

	num_entries = pud_index(EFI_VA_END);
	hdn_pt_copy(pud_efi, pud_k, sizeof(pud_t) * num_entries, 3);

	pud_efi = pud_offset(p4d_efi, EFI_VA_START);
	pud_k = pud_offset(p4d_k, EFI_VA_START);

	num_entries = PTRS_PER_PUD - pud_index(EFI_VA_START);
	hdn_pt_copy(pud_efi, pud_k, sizeof(pud_t) * num_entries, 3);
}

#ifdef CONFIG_SECURITY_HARDENING_RAP
/* Physically contiguous DMA32 backing preserves the firmware's identity
 * addressing assumption. vmap owns the split pages until permanent teardown.
 * Only the middle THREAD_SIZE is mapped in efi_mm; both ends have guards. */
static void *efi_mixed_backing __ro_after_init;
static unsigned long efi_mixed_backing_pa __ro_after_init;
#define EFI_MIXED_ORDER get_order(2 * THREAD_SIZE)

static int __init efi_mixed_stack_allocate(pgd_t *pgd)
{
	struct page *page, **pages;
	struct vm_struct *vm;
	unsigned int count = 1U << EFI_MIXED_ORDER, i;
	unsigned long physical;
	void *mapping;

	pages = kmalloc_array(count, sizeof(*pages), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;
	page = alloc_pages(GFP_KERNEL | __GFP_DMA32 | __GFP_ZERO, EFI_MIXED_ORDER);
	if (!page) {
		kfree(pages);
		return -ENOMEM;
	}
	split_page(page, EFI_MIXED_ORDER);
	for (i = 0; i < count; i++)
		pages[i] = page + i;
	physical = page_to_phys(page);
	mapping = vmap(pages, count, VM_MAP | VM_MAP_PUT_PAGES, PAGE_KERNEL);
	if (!mapping) {
		for (i = 0; i < count; i++)
			__free_page(pages[i]);
		kfree(pages);
		return -ENOMEM;
	}
	vm = find_vm_area(mapping);
	vm->flags |= VM_FLUSH_RESET_PERMS;
	if (kernel_unmap_pages_in_pgd(pgd, physical, count) ||
	    kernel_map_pages_in_pgd(pgd, (physical >> PAGE_SHIFT) + 1,
		physical + PAGE_SIZE, THREAD_SIZE >> PAGE_SHIFT, _PAGE_NX | _PAGE_RW | _PAGE_ENC)) {
		/* Do not recycle physical backing while any temporary alias survives. */
		if (kernel_unmap_pages_in_pgd(pgd, physical, count))
			panic("HDN cannot withdraw failed EFI stack mapping");
		vfree(mapping);
		return -ENOMEM;
	}
	efi_mixed_backing = mapping;
	efi_mixed_backing_pa = physical;
	efi_mixed_mode_stack_pa = physical + PAGE_SIZE + THREAD_SIZE;
	kmemleak_no_scan(mapping);
	return 0;
}

void __init hdn_efi_mixed_seal(void)
{
	if (!efi_mixed_backing)
		return;
	/* No EFI call is active before rest_init. The sole retained alias is
	 * the guarded, non-global EFI-only identity mapping created above. */
	if (hdn_execmem_claim_stack(efi_mixed_backing) || hdn_execmem_hide_stack(efi_mixed_backing))
		panic("HDN cannot isolate the EFI firmware stack");
}
#endif

int __init efi_setup_page_tables(unsigned long pa_memmap, unsigned num_pages)
{
	extern const u8 __efi64_thunk_ret_tramp[];
	unsigned long pfn, text, pf, rodata, tramp;
#ifndef CONFIG_SECURITY_HARDENING_RAP
	struct page *page;
#endif
	unsigned npages;
	pgd_t *pgd = efi_mm.pgd;

	/*
	 * It can happen that the physical address of new_memmap lands in memory
	 * which is not mapped in the EFI page table. Therefore we need to go
	 * and ident-map those pages containing the map before calling
	 * phys_efi_set_virtual_address_map().
	 */
	pfn = pa_memmap >> PAGE_SHIFT;
	pf = _PAGE_NX | _PAGE_RW | _PAGE_ENC;
	if (kernel_map_pages_in_pgd(pgd, pfn, pa_memmap, num_pages, pf)) {
		pr_err("Error ident-mapping new memmap (0x%lx)!\n", pa_memmap);
		return 1;
	}

	/*
	 * Certain firmware versions are way too sentimental and still believe
	 * they are exclusive and unquestionable owners of the first physical page,
	 * even though they explicitly mark it as EFI_CONVENTIONAL_MEMORY
	 * (but then write-access it later during SetVirtualAddressMap()).
	 *
	 * Create a 1:1 mapping for this page, to avoid triple faults during early
	 * boot with such firmware. We are free to hand this page to the BIOS,
	 * as trim_bios_range() will reserve the first page and isolate it away
	 * from memory allocators anyway.
	 */
	if (kernel_map_pages_in_pgd(pgd, 0x0, 0x0, 1, pf)) {
		pr_err("Failed to create 1:1 mapping for the first page!\n");
		return 1;
	}

	/*
	 * When SEV-ES is active, the GHCB as set by the kernel will be used
	 * by firmware. Create a 1:1 unencrypted mapping for each GHCB.
	 */
	if (sev_es_efi_map_ghcbs_cas(pgd)) {
		pr_err("Failed to create 1:1 mapping for the GHCBs and CAs!\n");
		return 1;
	}

	/*
	 * When making calls to the firmware everything needs to be 1:1
	 * mapped and addressable with 32-bit pointers. Map the kernel
	 * text and allocate a new stack because we can't rely on the
	 * stack pointer being < 4GB.
	 */
	if (!efi_is_mixed())
		return 0;

#ifdef CONFIG_SECURITY_HARDENING_RAP
	if (efi_mixed_stack_allocate(pgd))
		return 1;
#else
	page = alloc_page(GFP_KERNEL|__GFP_DMA32);
	if (!page) {
		pr_err("Unable to allocate EFI runtime stack < 4GB\n");
		return 1;
	}

	efi_mixed_mode_stack_pa = page_to_phys(page + 1); /* stack grows down */
#endif

	npages = (_etext - _text) >> PAGE_SHIFT;
	text = __pa(_text);

	if (kernel_unmap_pages_in_pgd(pgd, text, npages)) {
		pr_err("Failed to unmap kernel text 1:1 mapping\n");
		goto free_stack;
	}

	npages = (__end_rodata - __start_rodata) >> PAGE_SHIFT;
	rodata = __pa(__start_rodata);
	pfn = rodata >> PAGE_SHIFT;

	pf = _PAGE_NX | _PAGE_ENC;
	if (kernel_map_pages_in_pgd(pgd, pfn, rodata, npages, pf)) {
		pr_err("Failed to map kernel rodata 1:1\n");
		goto free_stack;
	}

	tramp = __pa(__efi64_thunk_ret_tramp);
	pfn = tramp >> PAGE_SHIFT;

	pf = _PAGE_ENC;
	if (kernel_map_pages_in_pgd(pgd, pfn, tramp, 1, pf)) {
		pr_err("Failed to map mixed mode return trampoline\n");
		goto free_stack;
	}

#ifdef CONFIG_SECURITY_HARDENING_RAP
	hdn_rap_efi_context_init(efi_mixed_mode_stack_pa - THREAD_SIZE, THREAD_SIZE);
#endif
	return 0;

free_stack:
#ifdef CONFIG_SECURITY_HARDENING_RAP
	if (kernel_unmap_pages_in_pgd(pgd, efi_mixed_backing_pa, 1U << EFI_MIXED_ORDER))
		panic("HDN cannot withdraw EFI stack after mapping failure");
	vfree(efi_mixed_backing);
	efi_mixed_backing = NULL;
#else
	__free_page(page);
#endif
	efi_mixed_mode_stack_pa = 0;
	return 1;
}

static void __init __map_region(efi_memory_desc_t *md, u64 va)
{
	unsigned long flags = _PAGE_RW;
	unsigned long pfn;
	pgd_t *pgd = efi_mm.pgd;

	/*
	 * EFI_RUNTIME_SERVICES_CODE regions typically cover PE/COFF
	 * executable images in memory that consist of both R-X and
	 * RW- sections, so we cannot apply read-only or non-exec
	 * permissions just yet. However, modern EFI systems provide
	 * a memory attributes table that describes those sections
	 * with the appropriate restricted permissions, which are
	 * applied in efi_runtime_update_mappings() below. All other
	 * regions can be mapped non-executable at this point, with
	 * the exception of boot services code regions, but those will
	 * be unmapped again entirely in efi_free_boot_services().
	 */
	if (md->type != EFI_BOOT_SERVICES_CODE &&
	    md->type != EFI_RUNTIME_SERVICES_CODE)
		flags |= _PAGE_NX;

	if (!(md->attribute & EFI_MEMORY_WB))
		flags |= _PAGE_PCD;

	if (cc_platform_has(CC_ATTR_GUEST_MEM_ENCRYPT) &&
	    md->type != EFI_MEMORY_MAPPED_IO)
		flags |= _PAGE_ENC;

	pfn = md->phys_addr >> PAGE_SHIFT;
	if (kernel_map_pages_in_pgd(pgd, pfn, va, md->num_pages, flags))
		pr_warn("Error mapping PA 0x%llx -> VA 0x%llx!\n",
			   md->phys_addr, va);
}

void __init efi_map_region(efi_memory_desc_t *md)
{
	unsigned long size = md->num_pages << PAGE_SHIFT;
	u64 pa = md->phys_addr;

	/*
	 * Make sure the 1:1 mappings are present as a catch-all for b0rked
	 * firmware which doesn't update all internal pointers after switching
	 * to virtual mode and would otherwise crap on us.
	 */
	__map_region(md, md->phys_addr);

	/*
	 * Enforce the 1:1 mapping as the default virtual address when
	 * booting in EFI mixed mode, because even though we may be
	 * running a 64-bit kernel, the firmware may only be 32-bit.
	 */
	if (efi_is_mixed()) {
		md->virt_addr = md->phys_addr;
		return;
	}

	efi_va -= size;

	/* Is PA 2M-aligned? */
	if (!(pa & (PMD_SIZE - 1))) {
		efi_va &= PMD_MASK;
	} else {
		u64 pa_offset = pa & (PMD_SIZE - 1);
		u64 prev_va = efi_va;

		/* get us the same offset within this 2M page */
		efi_va = (efi_va & PMD_MASK) + pa_offset;

		if (efi_va > prev_va)
			efi_va -= PMD_SIZE;
	}

	if (efi_va < EFI_VA_END) {
		pr_warn(FW_WARN "VA address range overflow!\n");
		return;
	}

	/* Do the VA map */
	__map_region(md, efi_va);
	md->virt_addr = efi_va;
}

/*
 * kexec kernel will use efi_map_region_fixed to map efi runtime memory ranges.
 * md->virt_addr is the original virtual address which had been mapped in kexec
 * 1st kernel.
 */
void __init efi_map_region_fixed(efi_memory_desc_t *md)
{
	__map_region(md, md->phys_addr);
	__map_region(md, md->virt_addr);
}

void __init parse_efi_setup(u64 phys_addr, u32 data_len)
{
	efi_setup = phys_addr + sizeof(struct setup_data);
}

static int __init efi_update_mappings(efi_memory_desc_t *md, unsigned long pf)
{
	unsigned long pfn;
	pgd_t *pgd = efi_mm.pgd;
	int err1, err2;

	/* Update the 1:1 mapping */
	pfn = md->phys_addr >> PAGE_SHIFT;
	err1 = kernel_map_pages_in_pgd(pgd, pfn, md->phys_addr, md->num_pages, pf);
	if (err1) {
		pr_err("Error while updating 1:1 mapping PA 0x%llx -> VA 0x%llx!\n",
			   md->phys_addr, md->virt_addr);
	}

	err2 = kernel_map_pages_in_pgd(pgd, pfn, md->virt_addr, md->num_pages, pf);
	if (err2) {
		pr_err("Error while updating VA mapping PA 0x%llx -> VA 0x%llx!\n",
			   md->phys_addr, md->virt_addr);
	}

	return err1 || err2;
}

bool efi_disable_ibt_for_runtime __ro_after_init = true;

#ifdef CONFIG_SECURITY_HARDENING_PGTABLE
/* Value 1 is an uncovered runtime-code page, 2 is NX and 3 is sealed RX. */
static DEFINE_XARRAY(efi_wx_pages);

static int __init hdn_efi_wx_begin(void)
{
	efi_memory_desc_t *md;
	int error;

	for_each_efi_memory_desc(md) {
		unsigned long pfn;

		if (!(md->attribute & EFI_MEMORY_RUNTIME) ||
		    md->type != EFI_RUNTIME_SERVICES_CODE)
			continue;
		pfn = md->phys_addr >> PAGE_SHIFT;
		if (!md->num_pages || md->num_pages > ULONG_MAX ||
		    md->num_pages - 1 > ULONG_MAX - pfn)
			return -EOVERFLOW;
		for (u64 page = 0; page < md->num_pages; page++) {
			error = xa_insert(&efi_wx_pages, pfn + page, xa_mk_value(1), GFP_KERNEL);
			if (error)
				return error;
		}
	}
	return xa_empty(&efi_wx_pages) ? -ENOENT : 0;
}

static int __init hdn_efi_wx_mark(efi_memory_desc_t *md, bool executable)
{
	unsigned long pfn = md->phys_addr >> PAGE_SHIFT;
	size_t size;

	if (md->type != EFI_RUNTIME_SERVICES_CODE)
		return 0;
	if (!md->num_pages || md->num_pages > ULONG_MAX ||
	    md->num_pages - 1 > ULONG_MAX - pfn ||
	    check_mul_overflow((size_t)md->num_pages, (size_t)PAGE_SIZE, &size))
		return -EOVERFLOW;
	for (u64 page = 0; page < md->num_pages; page++) {
		void *entry = xa_load(&efi_wx_pages, pfn + page);

		if (!xa_is_value(entry) || xa_to_value(entry) != 1)
			return -EINVAL;
	}
	if (executable && hdn_pt_foreign_code_seal(md->phys_addr, size, &efi_mm))
		return -EPERM;
	for (u64 page = 0; page < md->num_pages; page++)
		xa_store(&efi_wx_pages, pfn + page, xa_mk_value(executable ? 3 : 2),
			 GFP_KERNEL);
	return 0;
}

static bool __init hdn_efi_wx_complete(void)
{
	void *entry;
	unsigned long index;

	xa_for_each(&efi_wx_pages, index, entry)
		if (!xa_is_value(entry) || xa_to_value(entry) == 1)
			return false;
	return !xa_empty(&efi_wx_pages);
}

static int __init hdn_efi_disable_runtime_mappings(void)
{
	efi_memory_desc_t *md;
	int error = 0;

	for_each_efi_memory_desc(md) {
		unsigned long flags = _PAGE_NX;

		if (!(md->attribute & EFI_MEMORY_RUNTIME))
			continue;
		if (!(md->attribute & EFI_MEMORY_RO))
			flags |= _PAGE_RW;
		if (cc_platform_has(CC_ATTR_GUEST_MEM_ENCRYPT))
			flags |= _PAGE_ENC;
		error |= efi_update_mappings(md, flags);
	}
	clear_bit(EFI_RUNTIME_SERVICES, &efi.flags);
	return error ? -EIO : 0;
}
#endif

static int __init efi_update_mem_attr(struct mm_struct *mm, efi_memory_desc_t *md,
				      bool has_ibt)
{
	unsigned long pf = 0;
	bool executable;
#ifdef CONFIG_SECURITY_HARDENING_PGTABLE
	int error;
#endif

	efi_disable_ibt_for_runtime |= !has_ibt;

	executable = !(md->attribute & EFI_MEMORY_XP);
#ifdef CONFIG_SECURITY_HARDENING_PGTABLE
	if (hdn_pt_platform_supported())
		executable = md->type == EFI_RUNTIME_SERVICES_CODE && executable;
#endif
	if (!executable)
		pf |= _PAGE_NX;

	if (!(md->attribute & EFI_MEMORY_RO))
		pf |= _PAGE_RW;

#ifdef CONFIG_SECURITY_HARDENING_PGTABLE
	if (hdn_pt_platform_supported() && executable &&
	    !(md->attribute & EFI_MEMORY_RO))
		return -EPERM;
#endif

	if (cc_platform_has(CC_ATTR_GUEST_MEM_ENCRYPT))
		pf |= _PAGE_ENC;

#ifdef CONFIG_SECURITY_HARDENING_PGTABLE
	/* Revoke the writable kernel alias before publishing an executable EFI
	 * mapping. If publication then fails, runtime teardown keeps the already
	 * sealed firmware page RO/NX rather than reopening it. */
	if (hdn_pt_platform_supported()) {
		error = hdn_efi_wx_mark(md, executable);
		if (error)
			return error;
	}
#endif
	return efi_update_mappings(md, pf);
}

static void efi_enter_mm(void);
static void efi_leave_mm(void);

void __init efi_runtime_update_mappings(void)
{
#ifdef CONFIG_SECURITY_HARDENING_PGTABLE
	if (hdn_pt_platform_supported()) {
		int error = hdn_efi_wx_begin();

		if (!error && efi_enabled(EFI_MEM_ATTR)) {
			efi_disable_ibt_for_runtime = false;
			error = efi_memattr_apply_permissions(NULL, efi_update_mem_attr);
			if (!error && !hdn_efi_wx_complete())
				error = -ENODATA;
		} else if (!error) {
			error = -EOPNOTSUPP;
		}
		if (error) {
			if (hdn_efi_disable_runtime_mappings())
				panic("HDN could not remove executable EFI runtime mappings");
			pr_err("incomplete W^X attributes; runtime services disabled\n");
		}
		hdn_pt_efi_wx_result(true, !error);
		xa_destroy(&efi_wx_pages);
	} else if (efi_enabled(EFI_MEM_ATTR)) {
		efi_disable_ibt_for_runtime = false;
		efi_memattr_apply_permissions(NULL, efi_update_mem_attr);
		hdn_pt_efi_wx_result(true, false);
	} else {
		hdn_pt_efi_wx_result(true, false);
	}
#else
	if (efi_enabled(EFI_MEM_ATTR)) {
		efi_disable_ibt_for_runtime = false;
		efi_memattr_apply_permissions(NULL, efi_update_mem_attr);
	}
#endif
#ifdef CONFIG_SECURITY_HARDENING_RAP
	if (efi_enabled(EFI_RUNTIME_SERVICES)) {
		preempt_disable();
		efi_enter_mm();
		if (hdn_efi_register_runtime(false)) {
			clear_bit(EFI_RUNTIME_SERVICES, &efi.flags);
			pr_err("EFI runtime entry admission failed; services disabled\n");
		}
		efi_leave_mm();
		preempt_enable();
	}
#endif
}

void __init efi_dump_pagetable(void)
{
#ifdef CONFIG_EFI_PGT_DUMP
	ptdump_walk_pgd_level(NULL, &efi_mm);
#endif
}

/*
 * Makes the calling thread switch to/from efi_mm context. Can be used
 * in a kernel thread and user context. Preemption needs to remain disabled
 * while the EFI-mm is borrowed. mmgrab()/mmdrop() is not used because the mm
 * can not change under us.
 * It should be ensured that there are no concurrent calls to this function.
 */
static void efi_enter_mm(void)
{
	efi_prev_mm = use_temporary_mm(&efi_mm);
}

static void efi_leave_mm(void)
{
	unuse_temporary_mm(efi_prev_mm);
}

void arch_efi_call_virt_setup(void)
{
	efi_sync_low_kernel_mappings();
	efi_fpu_begin();
	firmware_restrict_branch_speculation_start();
	efi_enter_mm();
}

void arch_efi_call_virt_teardown(void)
{
	efi_leave_mm();
	firmware_restrict_branch_speculation_end();
	efi_fpu_end();
}

static DEFINE_SPINLOCK(efi_runtime_lock);

/*
 * DS and ES contain user values.  We need to save them.
 * The 32-bit EFI code needs a valid DS, ES, and SS.  There's no
 * need to save the old SS: __KERNEL_DS is always acceptable.
 */
#ifdef CONFIG_SECURITY_HARDENING_RAP
#define efi_runtime_thunk(func, ...) ({ \
	__efi_nargs_check(efi_runtime_thunk, 8, __VA_ARGS__); \
	__hdn_efi64_thunk(offsetof(efi_runtime_services_t, func), \
		READ_ONCE(efi.runtime->mixed_mode.func), __VA_ARGS__, \
		0UL, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL); \
})
#else
#define efi_runtime_thunk(func, ...) efi64_thunk(efi.runtime->mixed_mode.func, __VA_ARGS__)
#endif

#define __efi_thunk(func, ...)						\
({									\
	unsigned short __ds, __es;					\
	efi_status_t ____s;						\
									\
	savesegment(ds, __ds);						\
	savesegment(es, __es);						\
									\
	loadsegment(ss, __KERNEL_DS);					\
	loadsegment(ds, __KERNEL_DS);					\
	loadsegment(es, __KERNEL_DS);					\
									\
	____s = efi_runtime_thunk(func, __VA_ARGS__);	\
									\
	loadsegment(ds, __ds);						\
	loadsegment(es, __es);						\
									\
	____s ^= (____s & BIT(31)) | (____s & BIT_ULL(31)) << 32;	\
	____s;								\
})

/*
 * Switch to the EFI page tables early so that we can access the 1:1
 * runtime services mappings which are not mapped in any other page
 * tables.
 *
 * Also, disable interrupts because the IDT points to 64-bit handlers,
 * which aren't going to function correctly when we switch to 32-bit.
 */
#define efi_thunk(func...)						\
({									\
	efi_status_t __s;						\
									\
	arch_efi_call_virt_setup();					\
									\
	__s = __efi_thunk(func);					\
									\
	arch_efi_call_virt_teardown();					\
									\
	__s;								\
})

static efi_status_t __init __no_sanitize_address
efi_thunk_set_virtual_address_map(unsigned long memory_map_size,
				  unsigned long descriptor_size,
				  u32 descriptor_version,
				  efi_memory_desc_t *virtual_map)
{
	efi_status_t status;
	unsigned long flags;

	efi_sync_low_kernel_mappings();
	local_irq_save(flags);

	efi_enter_mm();

	if (hdn_efi_register_runtime(true)) {
		efi_leave_mm();
		local_irq_restore(flags);
		return EFI_SECURITY_VIOLATION;
	}

	status = __efi_thunk(set_virtual_address_map, memory_map_size,
			     descriptor_size, descriptor_version, virtual_map);

	efi_leave_mm();
	local_irq_restore(flags);

	return status;
}

static efi_status_t efi_thunk_get_time(efi_time_t *tm, efi_time_cap_t *tc)
{
	return EFI_UNSUPPORTED;
}

static efi_status_t efi_thunk_set_time(efi_time_t *tm)
{
	return EFI_UNSUPPORTED;
}

static efi_status_t
efi_thunk_get_wakeup_time(efi_bool_t *enabled, efi_bool_t *pending,
			  efi_time_t *tm)
{
	return EFI_UNSUPPORTED;
}

static efi_status_t
efi_thunk_set_wakeup_time(efi_bool_t enabled, efi_time_t *tm)
{
	return EFI_UNSUPPORTED;
}

/* Firmware cannot translate a private stack or a discontiguous vmalloc
 * buffer. All mixed-mode arguments, including UINTN results, therefore live
 * in a per-call DMA32 allocation. No caller's backing-page alias is exposed.
 * Allocation is outside efi_runtime_lock; nonblocking callers use GFP_ATOMIC.
 */
struct efi_mixed_args {
	efi_guid_t vendor __aligned(16);
	u32 size, attr;
	u64 storage, remaining, maximum;
	u8 payload[];
};

struct efi_mixed_buffer {
	struct efi_mixed_args *args;
	void *name, *data;
	unsigned int order;
};

static unsigned long efi_name_size(const efi_char16_t *name,
				   unsigned long capacity)
{
	unsigned long i;

	if (!name)
		return 0;
	for (i = 0; i < capacity / sizeof(*name); i++)
		if (!name[i])
			return (i + 1) * sizeof(*name);
	return 0;
}

static void efi_mixed_free(struct efi_mixed_buffer *buffer)
{
	if (!buffer->args)
		return;
	memzero_explicit(buffer->args, PAGE_SIZE << buffer->order);
	free_pages((unsigned long)buffer->args, buffer->order);
	buffer->args = NULL;
}

static efi_status_t efi_mixed_alloc(struct efi_mixed_buffer *buffer,
		unsigned long namesz, unsigned long datasz, gfp_t gfp)
{
	unsigned long bytes, name_aligned;
	phys_addr_t pa;

	*buffer = (struct efi_mixed_buffer) {};
	/* Each firmware UINTN is 32 bits. Check before alignment/addition. */
	if (namesz > U32_MAX || datasz > U32_MAX)
		return EFI_INVALID_PARAMETER;
	name_aligned = ALIGN(namesz, 8);
	bytes = sizeof(*buffer->args) + name_aligned + datasz;
	if (bytes > (PAGE_SIZE << MAX_PAGE_ORDER))
		return EFI_OUT_OF_RESOURCES;
	buffer->order = get_order(bytes);
	buffer->args = (void *)__get_free_pages(gfp | __GFP_ZERO | __GFP_DMA32,
					       buffer->order);
	if (!buffer->args)
		return EFI_OUT_OF_RESOURCES;
	pa = virt_to_phys(buffer->args);
	if (!pa || pa > U32_MAX || bytes - 1 > U32_MAX - pa) {
		efi_mixed_free(buffer);
		return EFI_OUT_OF_RESOURCES;
	}
	buffer->name = namesz ? buffer->args->payload : NULL;
	buffer->data = datasz ? buffer->args->payload + name_aligned : NULL;
	return EFI_SUCCESS;
}

static u32 efi_mixed_phys(const void *p)
{
	return p ? (u32)virt_to_phys((void *)p) : 0;
}

static efi_status_t
efi_thunk_get_variable(efi_char16_t *name, efi_guid_t *vendor,
		       u32 *attr, unsigned long *data_size, void *data)
{
	struct efi_mixed_buffer buffer;
	struct efi_mixed_args *args;
	unsigned long namesz, capacity, flags;
	efi_status_t status;

	if (!vendor || !data_size || (!data && *data_size))
		return EFI_INVALID_PARAMETER;
	namesz = efi_name_size(name, EFI_VAR_NAME_LEN);
	if (!namesz)
		return EFI_INVALID_PARAMETER;
	capacity = *data_size;
	status = efi_mixed_alloc(&buffer, namesz, capacity, GFP_KERNEL);
	if (status != EFI_SUCCESS)
		return status;
	args = buffer.args;
	args->vendor = *vendor;
	args->size = capacity;
	memcpy(buffer.name, name, namesz);

	spin_lock_irqsave(&efi_runtime_lock, flags);
	status = efi_thunk(get_variable, efi_mixed_phys(buffer.name),
			efi_mixed_phys(&args->vendor),
			attr ? efi_mixed_phys(&args->attr) : 0,
			efi_mixed_phys(&args->size), efi_mixed_phys(buffer.data));
	spin_unlock_irqrestore(&efi_runtime_lock, flags);
	if (status == EFI_SUCCESS && args->size > capacity)
		status = EFI_DEVICE_ERROR;
	if (status == EFI_SUCCESS || status == EFI_BUFFER_TOO_SMALL)
		*data_size = args->size;
	if (status == EFI_SUCCESS) {
		if (args->size)
			memcpy(data, buffer.data, args->size);
		if (attr)
			*attr = args->attr;
	}
	efi_mixed_free(&buffer);
	return status;
}

static efi_status_t
efi_mixed_set_variable(efi_char16_t *name, efi_guid_t *vendor, u32 attr,
		       unsigned long data_size, void *data, bool nonblocking)
{
	struct efi_mixed_buffer buffer;
	unsigned long namesz, flags;
	efi_status_t status;

	if (!vendor || (!data && data_size))
		return EFI_INVALID_PARAMETER;
	namesz = efi_name_size(name, EFI_VAR_NAME_LEN);
	if (!namesz)
		return EFI_INVALID_PARAMETER;
	status = efi_mixed_alloc(&buffer, namesz, data_size,
				nonblocking ? GFP_ATOMIC : GFP_KERNEL);
	if (status != EFI_SUCCESS)
		return status;
	buffer.args->vendor = *vendor;
	memcpy(buffer.name, name, namesz);
	if (data_size)
		memcpy(buffer.data, data, data_size);
	if (nonblocking) {
		if (!spin_trylock_irqsave(&efi_runtime_lock, flags)) {
			status = EFI_NOT_READY;
			goto out;
		}
	} else {
		spin_lock_irqsave(&efi_runtime_lock, flags);
	}
	status = efi_thunk(set_variable, efi_mixed_phys(buffer.name),
			efi_mixed_phys(&buffer.args->vendor), attr, data_size,
			efi_mixed_phys(buffer.data));
	spin_unlock_irqrestore(&efi_runtime_lock, flags);
out:
	efi_mixed_free(&buffer);
	return status;
}

static efi_status_t
efi_thunk_set_variable(efi_char16_t *name, efi_guid_t *vendor,
		       u32 attr, unsigned long data_size, void *data)
{
	return efi_mixed_set_variable(name, vendor, attr, data_size, data, false);
}

static efi_status_t
efi_thunk_set_variable_nonblocking(efi_char16_t *name, efi_guid_t *vendor,
				   u32 attr, unsigned long data_size, void *data)
{
	return efi_mixed_set_variable(name, vendor, attr, data_size, data, true);
}

static efi_status_t
efi_thunk_get_next_variable(unsigned long *name_size, efi_char16_t *name,
			    efi_guid_t *vendor)
{
	struct efi_mixed_buffer buffer;
	struct efi_mixed_args *args;
	unsigned long namesz, capacity, flags;
	efi_status_t status;

	if (!name_size || !vendor)
		return EFI_INVALID_PARAMETER;
	capacity = *name_size;
	namesz = efi_name_size(name, min_t(unsigned long, capacity, EFI_VAR_NAME_LEN));
	if (!namesz)
		return EFI_INVALID_PARAMETER;
	status = efi_mixed_alloc(&buffer, capacity, 0, GFP_KERNEL);
	if (status != EFI_SUCCESS)
		return status;
	args = buffer.args;
	args->vendor = *vendor;
	args->size = capacity;
	memcpy(buffer.name, name, namesz);
	spin_lock_irqsave(&efi_runtime_lock, flags);
	status = efi_thunk(get_next_variable, efi_mixed_phys(&args->size),
			efi_mixed_phys(buffer.name), efi_mixed_phys(&args->vendor));
	spin_unlock_irqrestore(&efi_runtime_lock, flags);
	if (status == EFI_SUCCESS &&
	    (args->size > capacity || !efi_name_size(buffer.name, args->size)))
		status = EFI_DEVICE_ERROR;
	if (status == EFI_SUCCESS || status == EFI_BUFFER_TOO_SMALL)
		*name_size = args->size;
	if (status == EFI_SUCCESS) {
		memcpy(name, buffer.name, args->size);
		*vendor = args->vendor;
	}
	efi_mixed_free(&buffer);
	return status;
}

static efi_status_t efi_thunk_get_next_high_mono_count(u32 *count)
{
	return EFI_UNSUPPORTED;
}

static void
efi_thunk_reset_system(int reset_type, efi_status_t status,
		       unsigned long data_size, efi_char16_t *data)
{
	struct efi_mixed_buffer buffer;
	unsigned long flags;
	efi_status_t error;

	/* Reset may be requested with interrupts disabled. */
	error = efi_mixed_alloc(&buffer, 0, data && data_size <= U32_MAX ? data_size : 0,
				GFP_ATOMIC);
	if (error == EFI_SUCCESS && buffer.data)
		memcpy(buffer.data, data, data_size);
	/* Optional reset text must never prevent the reset itself. */
	spin_lock_irqsave(&efi_runtime_lock, flags);
	efi_thunk(reset_system, reset_type, status,
		  error == EFI_SUCCESS && buffer.data ? data_size : 0,
		  error == EFI_SUCCESS ? efi_mixed_phys(buffer.data) : 0);
	spin_unlock_irqrestore(&efi_runtime_lock, flags);
	efi_mixed_free(&buffer);
}

static efi_status_t
efi_thunk_update_capsule(efi_capsule_header_t **capsules,
			 unsigned long count, unsigned long sg_list)
{
	/* The upstream mixed-mode ABI does not marshal capsule pointer lists. */
	return EFI_UNSUPPORTED;
}

static efi_status_t
efi_mixed_query_variable_info(u32 attr, u64 *storage_space,
			      u64 *remaining_space, u64 *max_variable_size,
			      bool nonblocking)
{
	struct efi_mixed_buffer buffer;
	struct efi_mixed_args *args;
	unsigned long flags;
	efi_status_t status;

	if (efi.runtime_version < EFI_2_00_SYSTEM_TABLE_REVISION)
		return EFI_UNSUPPORTED;
	if (!storage_space || !remaining_space || !max_variable_size)
		return EFI_INVALID_PARAMETER;
	status = efi_mixed_alloc(&buffer, 0, 0, nonblocking ? GFP_ATOMIC : GFP_KERNEL);
	if (status != EFI_SUCCESS)
		return status;
	args = buffer.args;
	if (nonblocking) {
		if (!spin_trylock_irqsave(&efi_runtime_lock, flags)) {
			status = EFI_NOT_READY;
			goto out;
		}
	} else {
		spin_lock_irqsave(&efi_runtime_lock, flags);
	}
	status = efi_thunk(query_variable_info, attr,
			efi_mixed_phys(&args->storage), efi_mixed_phys(&args->remaining),
			efi_mixed_phys(&args->maximum));
	spin_unlock_irqrestore(&efi_runtime_lock, flags);
	if (status == EFI_SUCCESS) {
		*storage_space = args->storage;
		*remaining_space = args->remaining;
		*max_variable_size = args->maximum;
	}
out:
	efi_mixed_free(&buffer);
	return status;
}

static efi_status_t
efi_thunk_query_variable_info(u32 attr, u64 *storage_space,
			      u64 *remaining_space, u64 *max_variable_size)
{
	return efi_mixed_query_variable_info(attr, storage_space, remaining_space,
					   max_variable_size, false);
}

static efi_status_t
efi_thunk_query_variable_info_nonblocking(u32 attr, u64 *storage_space,
					  u64 *remaining_space, u64 *max_variable_size)
{
	return efi_mixed_query_variable_info(attr, storage_space, remaining_space,
					   max_variable_size, true);
}

static efi_status_t
efi_thunk_query_capsule_caps(efi_capsule_header_t **capsules,
			     unsigned long count, u64 *max_size, int *reset_type)
{
	return EFI_UNSUPPORTED;
}

void __init efi_thunk_runtime_setup(void)
{
	if (!IS_ENABLED(CONFIG_EFI_MIXED))
		return;

	efi.get_time = efi_thunk_get_time;
	efi.set_time = efi_thunk_set_time;
	efi.get_wakeup_time = efi_thunk_get_wakeup_time;
	efi.set_wakeup_time = efi_thunk_set_wakeup_time;
	efi.get_variable = efi_thunk_get_variable;
	efi.get_next_variable = efi_thunk_get_next_variable;
	efi.set_variable = efi_thunk_set_variable;
	efi.set_variable_nonblocking = efi_thunk_set_variable_nonblocking;
	efi.get_next_high_mono_count = efi_thunk_get_next_high_mono_count;
	efi.reset_system = efi_thunk_reset_system;
	efi.query_variable_info = efi_thunk_query_variable_info;
	efi.query_variable_info_nonblocking = efi_thunk_query_variable_info_nonblocking;
	efi.update_capsule = efi_thunk_update_capsule;
	efi.query_capsule_caps = efi_thunk_query_capsule_caps;
}

efi_status_t __init __no_sanitize_address
efi_set_virtual_address_map(unsigned long memory_map_size,
			    unsigned long descriptor_size,
			    u32 descriptor_version,
			    efi_memory_desc_t *virtual_map,
			    unsigned long systab_phys)
{
	const efi_system_table_t *systab = (efi_system_table_t *)systab_phys;
	efi_status_t status;
	unsigned long flags;

	if (efi_is_mixed())
		return efi_thunk_set_virtual_address_map(memory_map_size,
							 descriptor_size,
							 descriptor_version,
							 virtual_map);
	efi_enter_mm();

	efi_fpu_begin();

	/* Disable interrupts around EFI calls: */
	local_irq_save(flags);
	if (hdn_efi_register_runtime(true)) {
		local_irq_restore(flags);
		efi_fpu_end();
		efi_leave_mm();
		return EFI_SECURITY_VIOLATION;
	}
	status = arch_efi_call_virt(efi.runtime, set_virtual_address_map,
				    memory_map_size, descriptor_size,
				    descriptor_version, virtual_map);
	local_irq_restore(flags);

	efi_fpu_end();

	/* grab the virtually remapped EFI runtime services table pointer */
	efi.runtime = READ_ONCE(systab->runtime);

	efi_leave_mm();

	return status;
}
