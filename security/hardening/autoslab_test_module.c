// SPDX-License-Identifier: GPL-2.0-only
#include <linux/hdn_alloc.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include "../../mm/slab.h"

#define HDN_AUTOSLAB_MODULE_ID 0x4d4f44554c45534cULL

struct autoslab_module_object {
	u64 marker;
	unsigned int length;
	u8 payload[];
};

static int __init autoslab_module_init(void)
{
	void *(*runtime_alloc)(size_t, gfp_t, int, unsigned int, u64,
			      unsigned int) = __hdn_alloc_typed;
	struct autoslab_module_object *typed;
	void *requested;
	unsigned int typed_domain, requested_domain;

	typed = kzalloc_flex(*typed, payload, 64);
	requested = runtime_alloc(struct_size(typed, payload, 64), GFP_KERNEL,
				  NUMA_NO_NODE, 0, HDN_AUTOSLAB_MODULE_ID,
				  HDN_ALLOC_CRED);
	if (!typed || !requested)
		goto fail;
	typed_domain = virt_to_slab(typed)->slab_cache->hdn_alloc_domain;
	requested_domain = virt_to_slab(requested)->slab_cache->hdn_alloc_domain;
	if (typed_domain != HDN_ALLOC_MODULE || requested_domain != HDN_ALLOC_MODULE ||
	    memchr_inv(typed, 0, struct_size(typed, payload, 64)))
		goto fail;
	pr_info("HDN_AUTOSLAB_MODULE_PASS typed_domain=%u requested_domain=%u\n",
		typed_domain, requested_domain);
	kfree(requested);
	kfree(typed);
	return 0;
fail:
	pr_err("HDN_AUTOSLAB_MODULE_FAIL\n");
	kfree(requested);
	kfree(typed);
	return -EINVAL;
}

static void __exit autoslab_module_exit(void)
{
	pr_info("HDN_AUTOSLAB_MODULE_UNLOAD\n");
}

module_init(autoslab_module_init);
module_exit(autoslab_module_exit);
MODULE_DESCRIPTION("HDN AUTOSLAB module-domain fixture");
MODULE_LICENSE("GPL");
