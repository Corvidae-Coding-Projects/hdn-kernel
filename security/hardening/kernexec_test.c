// SPDX-License-Identifier: GPL-2.0-only
#include <kunit/test.h>
#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/execmem.h>
#include <linux/hdn_execmem.h>
#include <linux/hdn_kernexec.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/uaccess.h>
#include <linux/set_memory.h>
#include <linux/vmalloc.h>
#include <asm/pgtable.h>
#include <asm/sections.h>
#include <asm/hdn_text.h>
#include <asm/hdn_gdt.h>
#include <asm/desc.h>
#include <asm/text-patching.h>

#define HDN_CONSTIFY_BUILTIN_MAGIC 0xc0571f1eb0171eULL

static u64 hdn_constify_builtin_value __ro_after_init = HDN_CONSTIFY_BUILTIN_MAGIC;

static bool hdn_cpa_ready(void)
{
	return kernel_wx_enforced() && READ_ONCE(kernel_set_to_readonly);
}

static void hdn_cpa_free(void *ptr)
{
	vfree(ptr);
}

static void hdn_cpa_expect_permissions(struct kunit *test, void *ptr,
				       bool writable, bool executable)
{
	unsigned int level;
	pte_t *pte = lookup_address((unsigned long)ptr, &level);

	KUNIT_ASSERT_NOT_NULL(test, pte);
	KUNIT_ASSERT_EQ(test, level, (unsigned int)PG_LEVEL_4K);
	KUNIT_EXPECT_TRUE(test, pte_present(*pte));
	KUNIT_EXPECT_EQ(test, !!(pte_val(*pte) & _PAGE_RW), writable);
	KUNIT_EXPECT_EQ(test, !(pte_val(*pte) & _PAGE_NX), executable);
}

static void hdn_cpa_transitions(struct kunit *test)
{
	void *ptr;
	unsigned long addr;

	if (!hdn_cpa_ready()) {
		kunit_skip(test, "load after boot with NX and static sealing active");
		return;
	}
	ptr = vmalloc(PAGE_SIZE);
	KUNIT_ASSERT_NOT_NULL(test, ptr);
	set_vm_flush_reset_perms(ptr);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, hdn_cpa_free, ptr), 0);
	addr = (unsigned long)ptr;

	hdn_cpa_expect_permissions(test, ptr, true, false);
	KUNIT_EXPECT_EQ(test, set_memory_x(addr, 1), -EACCES);
	hdn_cpa_expect_permissions(test, ptr, true, false);
	KUNIT_ASSERT_EQ(test, set_memory_rox(addr, 1), 0);
	hdn_cpa_expect_permissions(test, ptr, false, true);
	KUNIT_EXPECT_EQ(test, set_memory_rw(addr, 1), -EACCES);
	hdn_cpa_expect_permissions(test, ptr, false, true);
	KUNIT_ASSERT_EQ(test, set_memory_nx(addr, 1), 0);
	KUNIT_ASSERT_EQ(test, set_memory_rw(addr, 1), 0);
	hdn_cpa_expect_permissions(test, ptr, true, false);

	/* Non-present entries cannot smuggle W+X back through a PRESENT update. */
	KUNIT_ASSERT_EQ(test, set_memory_rox(addr, 1), 0);
	KUNIT_ASSERT_EQ(test, set_memory_np(addr, 1), 0);
	KUNIT_ASSERT_EQ(test, set_memory_rw(addr, 1), 0);
	KUNIT_EXPECT_EQ(test, set_memory_p(addr, 1), -EACCES);
	KUNIT_ASSERT_EQ(test, set_memory_nx(addr, 1), 0);
	KUNIT_ASSERT_EQ(test, set_memory_p(addr, 1), 0);
	hdn_cpa_expect_permissions(test, ptr, true, false);
}

static void hdn_cpa_static_alias(struct kunit *test, bool rodata)
{
	struct page *page = virt_to_page(rodata ? __start_rodata : _text);
	void *alias, *direct = page_address(page);
	int ret;

	/* No write is attempted, even if the admission check regresses. */
	alias = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	KUNIT_EXPECT_PTR_EQ(test, alias, NULL);
	if (alias)
		vunmap(alias);
	ret = set_memory_rw((unsigned long)direct, 1);
	KUNIT_EXPECT_EQ(test, ret, -EPERM);
	if (!ret)
		KUNIT_ASSERT_EQ(test, set_memory_ro((unsigned long)direct, 1), 0);

	/* Read-only aliases remain usable: immutable does not mean unmappable. */
	alias = vmap(&page, 1, VM_MAP, PAGE_KERNEL_RO);
	KUNIT_ASSERT_NOT_NULL(test, alias);
	vunmap(alias);
}

static void hdn_cpa_static_aliases(struct kunit *test)
{
	if (!hdn_cpa_ready()) {
		kunit_skip(test, "load after boot with NX and static sealing active");
		return;
	}
	hdn_cpa_static_alias(test, false);
	hdn_cpa_static_alias(test, true);
}

static void hdn_constify_builtin_storage(struct kunit *test)
{
	u64 value = READ_ONCE(hdn_constify_builtin_value);
	unsigned long address = (unsigned long)&hdn_constify_builtin_value;
	struct page *page = virt_to_page(&hdn_constify_builtin_value);
	unsigned int level;
	pte_t *pte;
	void *alias;
	int error;

	if (!hdn_cpa_ready()) {
		kunit_skip(test, "load after built-in post-init storage is sealed");
		return;
	}
	KUNIT_ASSERT_EQ(test, value, HDN_CONSTIFY_BUILTIN_MAGIC);
	pte = lookup_address(address, &level);
	KUNIT_ASSERT_NOT_NULL(test, pte);
	KUNIT_EXPECT_TRUE(test, pte_present(*pte));
	KUNIT_EXPECT_FALSE(test, pte_write(*pte));
	KUNIT_EXPECT_LT(test, copy_to_kernel_nofault((void *)address, &value,
						      sizeof(value)), 0);
	error = set_memory_rw(address & PAGE_MASK, 1);
	KUNIT_EXPECT_EQ(test, error, -EPERM);
	if (!error)
		KUNIT_ASSERT_EQ(test, set_memory_ro(address & PAGE_MASK, 1), 0);
	KUNIT_EXPECT_LT(test, copy_from_kernel_nofault(&value, page_address(page),
							sizeof(value)), 0);
	alias = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	KUNIT_EXPECT_PTR_EQ(test, alias, NULL);
	if (alias)
		vunmap(alias);
	KUNIT_EXPECT_EQ(test, READ_ONCE(hdn_constify_builtin_value),
			HDN_CONSTIFY_BUILTIN_MAGIC);
}

static void hdn_text_windows(struct kunit *test)
{
	static const u8 code[] = { 0x90, 0x90, 0x90, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc };
	struct hdn_text_window_stats before, after;
	void *ptr, *target;
	unsigned int i;
	const size_t offsets[] = { 0, PAGE_SIZE - 4 };

	if (!hdn_cpa_ready()) {
		kunit_skip(test, "load after boot with NX and static sealing active");
		return;
	}
	ptr = vmalloc(2 * PAGE_SIZE);
	KUNIT_ASSERT_NOT_NULL(test, ptr);
	set_vm_flush_reset_perms(ptr);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, hdn_cpa_free, ptr), 0);
	memset(ptr, 0xcc, 2 * PAGE_SIZE);
	KUNIT_ASSERT_EQ(test, set_memory_rox((unsigned long)ptr, 2), 0);

	for (i = 0; i < ARRAY_SIZE(offsets); i++) {
		target = ptr + offsets[i];
		hdn_text_get_stats(&before);
		KUNIT_ASSERT_PTR_EQ(test, text_poke_copy(target, code, sizeof(code)), target);
		hdn_text_get_stats(&after);
		KUNIT_EXPECT_MEMEQ(test, target, code, sizeof(code));
		/* Other patchers may run; this completed call adds at least one. */
		KUNIT_EXPECT_GT(test, after.completed, before.completed);
		KUNIT_EXPECT_GE(test, after.started, after.completed);
		hdn_cpa_expect_permissions(test, ptr, false, true);
		hdn_cpa_expect_permissions(test, ptr + PAGE_SIZE, false, true);
	}
}

struct hdn_wrong_owner_probe {
	struct completion done;
	void *ptr;
	int error;
};

static int hdn_wrong_owner_thread(void *data)
{
	struct hdn_wrong_owner_probe *probe = data;

	probe->error = set_memory_rox((unsigned long)probe->ptr, 2);
	complete(&probe->done);
	return 0;
}

static void hdn_execmem_cleanup(void *ptr)
{
	execmem_free(ptr);
}

static void hdn_execmem_owned_pages(struct kunit *test)
{
	struct hdn_wrong_owner_probe probe;
	struct task_struct *thread;
	struct page *page;
	void *ptr, *alias;
	u64 value;
	static const u8 code[] = { 0x90, 0x90, 0xc3, 0xcc };

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_EXECMEM) || !hdn_cpa_ready()) {
		kunit_skip(test, "requires private execmem after boot");
		return;
	}
	ptr = execmem_alloc_rw(EXECMEM_MODULE_TEXT, 2 * PAGE_SIZE);
	KUNIT_ASSERT_NOT_NULL(test, ptr);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, hdn_execmem_cleanup, ptr), 0);
	memset(ptr, 0xcc, 2 * PAGE_SIZE);
	page = vmalloc_to_page(ptr);
	KUNIT_ASSERT_NOT_NULL(test, page);
	KUNIT_EXPECT_LT(test, copy_from_kernel_nofault(&value, page_address(page), sizeof(value)), 0);
	alias = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	KUNIT_EXPECT_PTR_EQ(test, alias, NULL);
	if (alias)
		vunmap(alias);
	KUNIT_EXPECT_EQ(test, set_memory_rox((unsigned long)ptr, 1), -EPERM);
	KUNIT_EXPECT_EQ(test, set_memory_np((unsigned long)ptr, 1), -EPERM);
	hdn_cpa_expect_permissions(test, ptr, true, false);
	init_completion(&probe.done);
	probe.ptr = ptr;
	probe.error = 0;
	thread = kthread_run(hdn_wrong_owner_thread, &probe, "hdn-owner-probe");
	KUNIT_ASSERT_FALSE(test, IS_ERR(thread));
	/* The thread owns this stack argument until its completion. */
	wait_for_completion(&probe.done);
	KUNIT_EXPECT_EQ(test, probe.error, -EPERM);
	KUNIT_ASSERT_EQ(test, set_memory_rox((unsigned long)ptr, 2), 0);
	KUNIT_EXPECT_TRUE(test, hdn_execmem_sealed((unsigned long)ptr, 2));
	KUNIT_EXPECT_EQ(test, set_memory_rox((unsigned long)ptr, 2), -EPERM);
	KUNIT_EXPECT_EQ(test, set_memory_nx((unsigned long)ptr, 2), -EPERM);
	KUNIT_EXPECT_LT(test, set_memory_rw((unsigned long)ptr, 2), 0);
	KUNIT_EXPECT_EQ(test, set_memory_p((unsigned long)page_address(page), 1), -EPERM);
	KUNIT_ASSERT_PTR_EQ(test, text_poke_copy(ptr, code, sizeof(code)), ptr);
	KUNIT_EXPECT_MEMEQ(test, ptr, code, sizeof(code));
	hdn_cpa_expect_permissions(test, ptr, false, true);
	hdn_cpa_expect_permissions(test, ptr + PAGE_SIZE, false, true);
}

static void hdn_gdt_backing(struct kunit *test)
{
	struct desc_struct *gdt;
	struct desc_struct descriptor;
	struct page *page;
	unsigned int cpu;
	bool invalid;
	long error;
	void *alias;

	if (!hdn_gdt_active() || !hdn_gdt_sealed()) {
		kunit_skip(test, "requires native GDT sealing after boot");
		return;
	}
	/* Round-trip existing values; preserve the caller's lazy TSS marker. */
	cpu = get_cpu();
	gdt = get_cpu_gdt_rw(cpu);
	descriptor = gdt[GDT_ENTRY_CPUNODE];
	native_write_gdt_entry(gdt, GDT_ENTRY_CPUNODE, &descriptor, DESCTYPE_S);
	invalid = this_cpu_read(__tss_limit_invalid);
	force_reload_TR();
	this_cpu_write(__tss_limit_invalid, invalid);
	put_cpu();
	page = pfn_to_page(PFN_DOWN(get_cpu_gdt_paddr(cpu)));
	error = copy_to_kernel_nofault(&gdt[GDT_ENTRY_CPUNODE], &descriptor, sizeof(descriptor));
	KUNIT_EXPECT_LT(test, error, 0);
	KUNIT_EXPECT_MEMEQ(test, &gdt[GDT_ENTRY_CPUNODE], &descriptor, sizeof(descriptor));
	KUNIT_EXPECT_EQ(test, set_memory_rw((unsigned long)gdt, 1), -EPERM);
	KUNIT_EXPECT_EQ(test, set_memory_rw((unsigned long)page_address(page), 1), -EPERM);
	alias = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	KUNIT_EXPECT_PTR_EQ(test, alias, NULL);
	if (alias)
		vunmap(alias);
}

static void hdn_init_image_retired(struct kunit *test)
{
	unsigned long address;
	u8 value = 0;

	if (!hdn_init_aliases_retired()) {
		kunit_skip(test, "requires init reclamation and post-boot loader");
		return;
	}
	for (address = (unsigned long)__init_begin;
	     address < (unsigned long)__init_end; address += PAGE_SIZE) {
		unsigned int level;
		pte_t *pte = lookup_address(address, &level);

		KUNIT_EXPECT_TRUE(test, !pte || !pte_present(*pte));
		KUNIT_EXPECT_LT(test, copy_from_kernel_nofault(&value, (void *)address, 1), 0);
		KUNIT_EXPECT_LT(test, copy_to_kernel_nofault((void *)address, &value, 1), 0);
	}
}

static void hdn_bpf_quarantine_release(void *image)
{
	hdn_execmem_test_quarantine(image, false);
}

static void hdn_bpf_image_lifecycle(struct kunit *test)
{
	void *alias, *image, *module, *other;
	u8 byte = 0xcc, readback;
	unsigned int level;
	pte_t *pte;
	struct page *page;
	int scrubbed;

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_BPF_EXECMEM) || !hdn_cpa_ready()) {
		kunit_skip(test, "requires post-boot BPF executable isolation");
		return;
	}
	image = execmem_alloc_rw(EXECMEM_BPF, PAGE_SIZE);
	KUNIT_ASSERT_NOT_NULL(test, image);
	KUNIT_ASSERT_TRUE(test, execmem_bpf_contains(image, PAGE_SIZE));
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, hdn_execmem_cleanup, image), 0);
	KUNIT_ASSERT_EQ(test, hdn_execmem_test_quarantine(image, true), 0);
	/* LIFO cleanup first cancels the hold if an assertion fails before free. */
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, hdn_bpf_quarantine_release, image), 0);
	page = vmalloc_to_page(image);
	KUNIT_ASSERT_NOT_NULL(test, page);
	hdn_cpa_expect_permissions(test, image, true, false);
	alias = vmap(&page, 1, VM_MAP, PAGE_KERNEL_EXEC);
	KUNIT_EXPECT_PTR_EQ(test, alias, NULL);
	if (alias)
		vunmap(alias);
	KUNIT_EXPECT_EQ(test, hdn_execmem_bpf_copy(image, &byte, 1), 1);
	KUNIT_EXPECT_EQ(test, hdn_execmem_bpf_copy(image + PAGE_SIZE - 1, &byte, 2), -EPERM);
	KUNIT_ASSERT_EQ(test, hdn_execmem_bpf_finalize(image), 0);
	hdn_cpa_expect_permissions(test, image, false, true);
	alias = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	KUNIT_EXPECT_PTR_EQ(test, alias, NULL);
	if (alias)
		vunmap(alias);
	KUNIT_EXPECT_EQ(test, hdn_execmem_bpf_finalize(image), -EPERM);
	KUNIT_EXPECT_EQ(test, set_memory_rw((unsigned long)image, 1), -EACCES);
	kunit_release_action(test, hdn_execmem_cleanup, image);
	/* Address reservation survives while access and execution are revoked. */
	pte = lookup_address((unsigned long)image, &level);
	KUNIT_EXPECT_TRUE(test, !pte || !pte_present(*pte));
	KUNIT_EXPECT_LT(test, copy_from_kernel_nofault(&readback, image, 1), 0);
	KUNIT_EXPECT_LT(test, copy_to_kernel_nofault(image, &byte, 1), 0);
	alias = vmap(&page, 1, VM_MAP, PAGE_KERNEL_EXEC);
	KUNIT_EXPECT_PTR_EQ(test, alias, NULL);
	if (alias)
		vunmap(alias);
	scrubbed = hdn_execmem_test_scrubbed(image);
	if (scrubbed == -EOPNOTSUPP)
		kunit_info(test, "physical scrub observation requires the native PGTABLE test profile");
	else
		KUNIT_EXPECT_EQ(test, scrubbed, 0);
	other = execmem_alloc_rw(EXECMEM_BPF_DISPATCHER, PAGE_SIZE);
	KUNIT_EXPECT_NOT_NULL(test, other);
	KUNIT_EXPECT_TRUE(test, execmem_bpf_contains(other, PAGE_SIZE));
	KUNIT_EXPECT_PTR_NE(test, other, image);
	if (other)
		execmem_free(other);
	module = execmem_alloc_rw(EXECMEM_MODULE_TEXT, PAGE_SIZE);
	KUNIT_EXPECT_NOT_NULL(test, module);
	KUNIT_EXPECT_FALSE(test, execmem_bpf_contains(module, PAGE_SIZE));
	if (module)
		execmem_free(module);
}

static void hdn_idt_backing(struct kunit *test)
{
	struct desc_ptr idt;
	gate_desc first;
	struct page *page;
	pte_t *pte;
	unsigned int level;
	void *alias;

	if (!hdn_idt_sealed()) {
		kunit_skip(test, "requires finalized descriptor alias protection");
		return;
	}
	store_idt(&idt);
	KUNIT_ASSERT_EQ(test, idt.size, (unsigned short)(IDT_ENTRIES * sizeof(gate_desc) - 1));
	pte = lookup_address(idt.address, &level);
	KUNIT_ASSERT_NOT_NULL(test, pte);
	KUNIT_ASSERT_EQ(test, level, (unsigned int)PG_LEVEL_4K);
	page = pfn_to_page(pte_pfn(*pte));
	KUNIT_ASSERT_TRUE(test, hdn_idt_protected_pfn(page_to_pfn(page), page_to_pfn(page)));
	memcpy(&first, (void *)idt.address, sizeof(first));
	KUNIT_EXPECT_LT(test, copy_to_kernel_nofault((void *)idt.address, &first, sizeof(first)), 0);
	KUNIT_EXPECT_EQ(test, set_memory_rw((unsigned long)page_address(page), 1), -EPERM);
	alias = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	KUNIT_EXPECT_PTR_EQ(test, alias, NULL);
	if (alias)
		vunmap(alias);
}

static void hdn_ldt_storage(struct kunit *test)
{
	struct page *page;
	void *entries, *alias;
	u8 byte;

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_LDT)) {
		kunit_skip(test, "requires immutable LDT storage");
		return;
	}
	entries = __vmalloc_node_range(PAGE_SIZE, PAGE_SIZE, VMALLOC_START, VMALLOC_END,
		GFP_KERNEL | __GFP_ZERO, PAGE_KERNEL, VM_FLUSH_RESET_PERMS, NUMA_NO_NODE,
		__builtin_return_address(0));
	KUNIT_ASSERT_NOT_NULL(test, entries);
	if (hdn_execmem_claim_ldt(entries, 16 * LDT_ENTRY_SIZE)) {
		vfree(entries);
		KUNIT_FAIL(test, "could not claim LDT fixture");
		return;
	}
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test, hdn_execmem_cleanup, entries), 0);
	KUNIT_EXPECT_FALSE(test, hdn_execmem_ldt_valid(entries, 16 * LDT_ENTRY_SIZE));
	KUNIT_ASSERT_EQ(test, hdn_execmem_seal_data(entries), 0);
	KUNIT_EXPECT_TRUE(test, hdn_execmem_ldt_valid(entries, 16 * LDT_ENTRY_SIZE));
	KUNIT_EXPECT_FALSE(test, hdn_execmem_ldt_valid(entries, 15 * LDT_ENTRY_SIZE));
	KUNIT_EXPECT_FALSE(test, hdn_execmem_ldt_valid(entries + 8, 16 * LDT_ENTRY_SIZE));
	KUNIT_EXPECT_EQ(test, set_memory_rw((unsigned long)entries, 1), -EPERM);
	page = vmalloc_to_page(entries);
	KUNIT_EXPECT_LT(test, copy_from_kernel_nofault(&byte, page_address(page), 1), 0);
	alias = vmap(&page, 1, VM_MAP, PAGE_KERNEL_RO);
	KUNIT_EXPECT_PTR_EQ(test, alias, NULL);
	if (alias)
		vunmap(alias);
}

static struct kunit_case hdn_cpa_cases[] = {
	KUNIT_CASE(hdn_idt_backing),
	KUNIT_CASE(hdn_ldt_storage),
	KUNIT_CASE(hdn_cpa_transitions),
	KUNIT_CASE(hdn_cpa_static_aliases),
	KUNIT_CASE(hdn_constify_builtin_storage),
	KUNIT_CASE(hdn_text_windows),
	KUNIT_CASE(hdn_execmem_owned_pages),
	KUNIT_CASE(hdn_gdt_backing),
	KUNIT_CASE(hdn_init_image_retired),
	KUNIT_CASE(hdn_bpf_image_lifecycle),
	{}
};

struct kunit_suite hdn_cpa_suite = {
	.name = "hdn-kernexec-cpa",
	.test_cases = hdn_cpa_cases,
};
EXPORT_SYMBOL_GPL(hdn_cpa_suite);
MODULE_LICENSE("GPL");
