// SPDX-License-Identifier: GPL-2.0-only
/* Signed disposable-guest fixture for RESPECTRE module and semantic coverage. */
#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/module.h>

struct hdn_respectre_input {
	size_t length;
	const u8 *bytes;
};

static u8 hdn_respectre_table[64];
static volatile unsigned long hdn_respectre_index;
static volatile unsigned long hdn_respectre_slot;
static volatile unsigned long hdn_respectre_alias;

static noinline unsigned long hdn_respectre_bounded(unsigned long index)
{
	if (index < ARRAY_SIZE(hdn_respectre_table))
		return hdn_respectre_table[index];
	return 0;
}

static noinline unsigned long
hdn_respectre_pointer(const struct hdn_respectre_input *input,
		      unsigned long index)
{
	if (index < input->length)
		return input->bytes[index];
	return 0;
}

static noinline unsigned long hdn_respectre_identity(unsigned long value)
{
	return value;
}

static noinline unsigned long
hdn_respectre_indirect(unsigned long (*target)(unsigned long),
		       unsigned long value)
{
	return target(value);
}

static noinline unsigned long
hdn_respectre_store_load(volatile unsigned long *slot,
			 unsigned long value,
			 volatile unsigned long *alias)
{
	WRITE_ONCE(*slot, value);
	return READ_ONCE(*alias);
}

static int __init hdn_respectre_test_init(void)
{
	static const u8 bytes[] = { 11, 17, 23, 31 };
	const struct hdn_respectre_input input = {
		.length = ARRAY_SIZE(bytes),
		.bytes = bytes,
	};
	unsigned long index;

	for (index = 0; index < ARRAY_SIZE(hdn_respectre_table); index++)
		hdn_respectre_table[index] = index ^ 0x5a;

	WRITE_ONCE(hdn_respectre_index, 7);
	index = READ_ONCE(hdn_respectre_index);
	if (hdn_respectre_bounded(index) != (index ^ 0x5a) ||
	    hdn_respectre_bounded(ARRAY_SIZE(hdn_respectre_table)) != 0 ||
	    hdn_respectre_pointer(&input, 2) != 23 ||
	    hdn_respectre_pointer(&input, input.length) != 0 ||
	    hdn_respectre_indirect(hdn_respectre_identity, 0x1234) != 0x1234)
		return -EINVAL;

	WRITE_ONCE(hdn_respectre_alias, 0xa55a);
	if (hdn_respectre_store_load(&hdn_respectre_slot, 0x55aa,
				       &hdn_respectre_alias) != 0xa55a ||
	    READ_ONCE(hdn_respectre_slot) != 0x55aa)
		return -EINVAL;

	pr_info("HDN_RESPECTRE_PASS module-semantic-v1\n");
	return 0;
}

static void __exit hdn_respectre_test_exit(void)
{
}

module_init(hdn_respectre_test_init);
module_exit(hdn_respectre_test_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("HDN RESPECTRE signed semantic fixture");
