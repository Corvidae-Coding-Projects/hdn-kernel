// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>
#include <linux/livepatch.h>
#include <linux/unaligned.h>

/* Rewritten by make-hdn-relocs.py after modpost, before signing. Only data
 * relocations to this private stand-in are converted to SHN_LIVEPATCH. */
static unsigned long hdn_klp_binding __used = 0xdeadUL;
static unsigned long *const hdn_klp_ro_slot __used = &hdn_klp_binding;
extern unsigned char hdn_klp_cross_slot[];
asm(".pushsection .data.hdn_klp,\"aw\"\n"
    ".balign 4096\n"
    ".zero 4093\n"
    ".globl hdn_klp_cross_slot\n"
    "hdn_klp_cross_slot: .quad hdn_klp_binding\n"
    ".popsection\n");

static bool fail_after_binding;
module_param(fail_after_binding, bool, 0600);
static unsigned int binding_count;
module_param(binding_count, uint, 0400);

static int before_patch(struct klp_object *obj)
{
	unsigned long *cross = (void *)get_unaligned((unsigned long *)hdn_klp_cross_slot);
	unsigned long *ro = READ_ONCE(hdn_klp_ro_slot);

	if (!cross || cross != ro || READ_ONCE(*cross) != 0x123abcUL)
		return -EINVAL;
	binding_count++;
	return fail_after_binding ? -EAGAIN : 0;
}

static struct klp_func functions[] = { {} };
static struct klp_object objects[] = {
	{
		.name = "test_hdn_klp_target",
		.funcs = functions,
		.callbacks.pre_patch = before_patch,
	}, {}
};
static struct klp_patch patch = { .mod = THIS_MODULE, .objs = objects };
static int __init patch_init(void) { return klp_enable_patch(&patch); }
static void __exit patch_exit(void) { }
module_init(patch_init);
module_exit(patch_exit);
MODULE_LICENSE("GPL");
MODULE_INFO(livepatch, "Y");
