// SPDX-License-Identifier: GPL-2.0-only
/* Fresh-guest-only BPF executable-memory permission and stale-address probes. */
#include <linux/execmem.h>
#include <linux/hdn_execmem.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/set_memory.h>
#include <linux/vmalloc.h>

typedef int (*hdn_bpf_test_fn_t)(void);

int hdn_bpf_execmem_test_run(unsigned int mode);

static int hdn_bpf_execmem_placement(void)
{
	void *images[64] = {};
	u64 buckets = 0;
	unsigned int allocated = 0, count, n;
	int error = 0;

	for (n = 0; n < ARRAY_SIZE(images); n++) {
		int bucket;

		images[n] = execmem_alloc_rw(EXECMEM_BPF, PAGE_SIZE);
		if (!images[n] || !execmem_bpf_contains(images[n], PAGE_SIZE) ||
		    !IS_ALIGNED((unsigned long)images[n], PAGE_SIZE)) {
			error = -ENOMEM;
			break;
		}
		allocated++;
		bucket = execmem_bpf_test_bucket(images[n]);
		if (bucket < 0) {
			error = bucket;
			break;
		}
		buckets |= 1ULL << bucket;
	}
	count = hweight64(buckets);
	pr_info("HDN_BPF_PLACEMENT base=%016llx buckets=%016llx unique=%u\n",
		(unsigned long long)execmem_bpf_test_base_token(),
		(unsigned long long)buckets, count);
	while (allocated)
		execmem_free(images[--allocated]);
	if (error)
		return error;
	return count < 2 ? -ERANGE : 0;
}

int hdn_bpf_execmem_test_run(unsigned int mode)
{
	static const u8 return_zero[] = { 0x31, 0xc0, 0xc3 };
	hdn_bpf_test_fn_t function;
	struct page *page;
	void *alias, *image;
	int error;

	if (mode > 5)
		return -EINVAL;
	if (mode == 5) {
		pr_info("HDN_BPF_EXECMEM_PROBE_READY mode=%u\n", mode);
		return hdn_bpf_execmem_placement();
	}
	image = execmem_alloc_rw(EXECMEM_BPF, PAGE_SIZE);
	if (!image || !execmem_bpf_contains(image, PAGE_SIZE))
		return -ENOMEM;
	error = hdn_execmem_bpf_copy(image, return_zero, sizeof(return_zero));
	if (error != 1)
		goto fail;
	function = image;
	pr_info("HDN_BPF_EXECMEM_PROBE_READY mode=%u\n", mode);
	if (mode == 1)
		return function();
	error = hdn_execmem_bpf_finalize(image);
	if (error)
		goto fail;
	if (mode == 2) {
		WRITE_ONCE(*(u8 *)image, 0xcc);
		return -EUCLEAN;
	}
	if (mode == 3) {
		execmem_free(image);
		return function();
	}
	if (function()) {
		error = -EIO;
		goto fail;
	}
	page = vmalloc_to_page(image);
	if (!page) {
		error = -EFAULT;
		goto fail;
	}
	alias = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (alias) {
		vunmap(alias);
		error = -EACCES;
		goto fail;
	}
	if (mode == 4 && set_memory_rw((unsigned long)image, 1) != -EACCES) {
		error = -EACCES;
		goto fail;
	}
	execmem_free(image);
	return 0;
fail:
	execmem_free(image);
	return error;
}
EXPORT_SYMBOL_GPL(hdn_bpf_execmem_test_run);
