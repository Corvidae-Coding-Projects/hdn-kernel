// SPDX-License-Identifier: GPL-2.0-only
/* Load only after constify_target_module has reached MODULE_STATE_LIVE. */
#include <kunit/test.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/set_memory.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <asm/pgtable.h>

#define HDN_CONSTIFY_MODULE_MAGIC 0xc0571f1ed5ea1edULL

extern const u64 *hdn_constify_module_probe_value(void);

static void hdn_constify_module_storage(struct kunit *test)
{
	const u64 *target = hdn_constify_module_probe_value();
	struct page *page;
	unsigned int level;
	pte_t *pte;
	void *alias;
	u64 value;
	int error;

	KUNIT_ASSERT_NOT_NULL(test, target);
	KUNIT_ASSERT_EQ(test, READ_ONCE(*target), HDN_CONSTIFY_MODULE_MAGIC);
	pte = lookup_address((unsigned long)target, &level);
	KUNIT_ASSERT_NOT_NULL(test, pte);
	KUNIT_EXPECT_TRUE(test, pte_present(*pte));
	KUNIT_EXPECT_FALSE(test, pte_write(*pte));

	value = READ_ONCE(*target);
	KUNIT_EXPECT_LT(test, copy_to_kernel_nofault((void *)target, &value,
						      sizeof(value)), 0);
	error = set_memory_rw((unsigned long)target & PAGE_MASK, 1);
	KUNIT_EXPECT_EQ(test, error, -EPERM);
	if (!error)
		KUNIT_ASSERT_EQ(test,
			set_memory_ro((unsigned long)target & PAGE_MASK, 1), 0);

	page = vmalloc_to_page(target);
	KUNIT_ASSERT_NOT_NULL(test, page);
	KUNIT_EXPECT_LT(test, copy_from_kernel_nofault(&value, page_address(page),
							sizeof(value)), 0);
	alias = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	KUNIT_EXPECT_PTR_EQ(test, alias, NULL);
	if (alias)
		vunmap(alias);
	KUNIT_EXPECT_EQ(test, READ_ONCE(*target), HDN_CONSTIFY_MODULE_MAGIC);
}

static struct kunit_case hdn_constify_module_cases[] = {
	KUNIT_CASE(hdn_constify_module_storage),
	{}
};

static struct kunit_suite hdn_constify_module_suite = {
	.name = "hdn-constify-module",
	.test_cases = hdn_constify_module_cases,
};
kunit_test_suite(hdn_constify_module_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("HDN post-init immutable module probes");
