// SPDX-License-Identifier: GPL-2.0-only
/* Built in: the test module can invoke the suite, not arbitrary MM internals. */
#include <linux/export.h>
#include <linux/hdn_pgtable.h>
#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/set_memory.h>
#include <asm/hdn_pgtable.h>
#include <asm/pgalloc.h>
#include <asm/set_memory.h>

int hdn_pgtable_test_run(unsigned int mode);

int hdn_pgtable_test_run(unsigned int mode)
{
	pte_t *table;
	pmd_t *parent;
	struct page *foreign = NULL;
	unsigned long old, pfn;
	pte_t entry, *mapping;
	unsigned int level;
	int result = -EINVAL;

	if (mode > 4 || strcmp(hdn_pt_state(), "active"))
		return -ENODEV;
	table = pte_alloc_one_kernel(&init_mm);
	parent = pmd_alloc_one(&init_mm, 0);
	if (!table || !parent) {
		result = -ENOMEM;
		goto out;
	}
	pfn = __pa(table) >> PAGE_SHIFT;
	mapping = lookup_address((unsigned long)table, &level);
	if (!mapping || level != PG_LEVEL_4K || (pte_val(*mapping) & _PAGE_RW) ||
	    !(pte_val(*mapping) & _PAGE_NX) || !hdn_pt_protected_pfn(pfn, pfn))
		goto out;
	for (unsigned int i = 0; i < PTRS_PER_PTE; i++)
		if (pte_val(READ_ONCE(table[i])))
			goto out;
	/* Establish the table's leaf type even when all entries are absent. */
	set_pte(table, __pte(0));
	if (mode == 3) {
		foreign = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!foreign) {
			result = -ENOMEM;
			goto out;
		}
	}
	pr_info("HDN_PGTABLE_PROBE_READY mode=%u\n", mode);
	switch (mode) {
	case 1:
		/* Must fault through the ordinary direct map, before changing data. */
		WRITE_ONCE(table[0].pte, _PAGE_PRESENT);
		goto unexpected;
	case 2:
		hdn_pt_store(&table[0].pte, 0, 2);
		goto unexpected;
	case 3:
		set_pmd(parent, __pmd(page_to_phys(foreign) | _PAGE_TABLE));
		goto unexpected;
	case 4:
		set_pte(table, pfn_pte(pfn, PAGE_KERNEL));
		goto unexpected;
	}
	/* Use a real owned child, then exercise replacement and compare/exchange
	 * on its entries. The test root is unpublished, so no CPU can cache it. */
	pmd_populate_kernel(&init_mm, parent, table);
	entry = pfn_pte(page_to_pfn(ZERO_PAGE(0)), PAGE_KERNEL_RO);
	set_pte(table, entry);
	if (!pte_same(READ_ONCE(*table), entry))
		goto clear;
	old = pte_val(entry);
	if (!hdn_pt_try_cmpxchg(&table->pte, &old, 0, 1) || pte_val(*table))
		goto clear;
	set_pte(table, entry);
	if (!pte_same(native_ptep_get_and_clear(table), entry) || pte_val(*table))
		goto clear;
	if (!set_memory_rw((unsigned long)table, 1) ||
	    !set_memory_x((unsigned long)table, 1))
		goto clear;
	result = 0;
clear:
	pte_clear(&init_mm, 0, table);
	pmd_clear(parent);
	goto out;
unexpected:
	pr_err("HDN_PGTABLE_PROBE_UNEXPECTED_RETURN mode=%u\n", mode);
out:
	if (parent)
		pmd_free(&init_mm, parent);
	if (table)
		pte_free_kernel(&init_mm, table);
	if (foreign)
		__free_page(foreign);
	if (!result)
		pr_info("HDN_PGTABLE_PROBE_PASS\n");
	return result;
}
EXPORT_SYMBOL_GPL(hdn_pgtable_test_run);
