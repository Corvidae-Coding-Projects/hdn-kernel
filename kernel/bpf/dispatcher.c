// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2019 Intel Corporation. */

#include <linux/hash.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/static_call.h>
#include <linux/execmem.h>
#include <linux/hdn_execmem.h>

/* The BPF dispatcher is a multiway branch code generator. The
 * dispatcher is a mechanism to avoid the performance penalty of an
 * indirect call, which is expensive when retpolines are enabled. A
 * dispatch client registers a BPF program into the dispatcher, and if
 * there is available room in the dispatcher a direct call to the BPF
 * program will be generated. All calls to the BPF programs called via
 * the dispatcher will then be a direct call, instead of an
 * indirect. The dispatcher hijacks a trampoline function it via the
 * __fentry__ of the trampoline. The trampoline function has the
 * following signature:
 *
 * unsigned int trampoline(const void *ctx, const struct bpf_insn *insnsi,
 *                         unsigned int (*bpf_func)(const void *,
 *                                                  const struct bpf_insn *));
 */

static struct bpf_dispatcher_prog *bpf_dispatcher_find_prog(
	struct bpf_dispatcher *d, struct bpf_prog *prog)
{
	int i;

	for (i = 0; i < BPF_DISPATCHER_MAX; i++) {
		if (prog == d->progs[i].prog)
			return &d->progs[i];
	}
	return NULL;
}

static struct bpf_dispatcher_prog *bpf_dispatcher_find_free(
	struct bpf_dispatcher *d)
{
	return bpf_dispatcher_find_prog(d, NULL);
}

static bool bpf_dispatcher_add_prog(struct bpf_dispatcher *d,
				    struct bpf_prog *prog)
{
	struct bpf_dispatcher_prog *entry;

	if (!prog)
		return false;

	entry = bpf_dispatcher_find_prog(d, prog);
	if (entry) {
		refcount_inc(&entry->users);
		return false;
	}

	entry = bpf_dispatcher_find_free(d);
	if (!entry)
		return false;

	bpf_prog_inc(prog);
	entry->prog = prog;
	refcount_set(&entry->users, 1);
	d->num_progs++;
	return true;
}

static bool bpf_dispatcher_remove_prog(struct bpf_dispatcher *d,
				       struct bpf_prog *prog)
{
	struct bpf_dispatcher_prog *entry;

	if (!prog)
		return false;

	entry = bpf_dispatcher_find_prog(d, prog);
	if (!entry)
		return false;

	if (refcount_dec_and_test(&entry->users)) {
		entry->prog = NULL;
		bpf_prog_put(prog);
		d->num_progs--;
		return true;
	}
	return false;
}

int __weak arch_prepare_bpf_dispatcher(void *image, void *buf, s64 *funcs, int num_funcs)
{
	return -ENOTSUPP;
}

int __weak arch_register_bpf_dispatcher(void *image, s64 *funcs, int num_funcs)
{
	return 0;
}

void __weak arch_unregister_bpf_dispatcher(void *image)
{
}

static int bpf_dispatcher_prepare(struct bpf_dispatcher *d, void *image, void *buf)
{
	s64 ips[BPF_DISPATCHER_MAX] = {}, *ipsp = &ips[0];
	int i;

	for (i = 0; i < BPF_DISPATCHER_MAX; i++) {
		if (d->progs[i].prog)
			*ipsp++ = (s64)(uintptr_t)d->progs[i].prog->bpf_func;
	}
	return buf ? arch_prepare_bpf_dispatcher(image, buf, &ips[0], d->num_progs) :
		arch_register_bpf_dispatcher(image, &ips[0], d->num_progs);
}

#ifdef CONFIG_SECURITY_HARDENING_BPF_EXECMEM
struct hdn_bpf_dispatch_image {
	void *address;
	struct bpf_ksym ksym;
	struct bpf_prog *progs[BPF_DISPATCHER_MAX];
	unsigned int nr_progs;
	bool charged;
	bool registered;
};

static void hdn_bpf_dispatcher_put_progs(struct hdn_bpf_dispatch_image *image)
{
	while (image->nr_progs)
		bpf_prog_put(image->progs[--image->nr_progs]);
}

static void hdn_bpf_dispatcher_update(struct bpf_dispatcher *d)
{
	struct hdn_bpf_dispatch_image *old = d->hdn_image, *next = NULL;
	void *buffer = NULL;

	if (!d->num_progs)
		goto publish;
	next = kzalloc_obj(*next);
	buffer = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!next || !buffer)
		goto fallback;
	if (bpf_jit_charge_modmem(PAGE_SIZE))
		goto fallback;
	next->charged = true;
	next->address = bpf_prog_pack_alloc_type(PAGE_SIZE, bpf_jit_fill_hole_with_zero,
						EXECMEM_BPF_DISPATCHER);
	if (!next->address || bpf_dispatcher_prepare(d, next->address, buffer) ||
	    hdn_execmem_bpf_copy(next->address, buffer, PAGE_SIZE) != 1 ||
	    hdn_execmem_bpf_finalize(next->address) ||
	    bpf_dispatcher_prepare(d, next->address, NULL))
		goto fallback;
	next->registered = true;
	/* The dispatcher table owns only the current set. A replaced image can
	 * still branch to its prior set until static-call publication and the
	 * following RCU grace period complete, so snapshot independent refs. */
	for (int i = 0; i < BPF_DISPATCHER_MAX; i++) {
		if (!d->progs[i].prog)
			continue;
		bpf_prog_inc(d->progs[i].prog);
		next->progs[next->nr_progs++] = d->progs[i].prog;
	}
	INIT_LIST_HEAD_RCU(&next->ksym.lnode);
	strscpy(next->ksym.name, d->ksym.name, sizeof(next->ksym.name));
	bpf_image_ksym_init(next->address, PAGE_SIZE, &next->ksym);
	bpf_image_ksym_add(&next->ksym);
	goto publish;

fallback:
	/* Allocation failure keeps correct generic dispatch semantics. */
	if (next) {
		if (next->registered)
			arch_unregister_bpf_dispatcher(next->address);
		hdn_bpf_dispatcher_put_progs(next);
		if (next->address)
			bpf_prog_pack_free(next->address, PAGE_SIZE);
		if (next->charged)
			bpf_jit_uncharge_modmem(PAGE_SIZE);
		kfree(next);
		next = NULL;
	}
publish:
	kfree(buffer);
	__BPF_DISPATCHER_UPDATE(d, next ? next->address : (void *)&bpf_dispatcher_nop_func);
	d->hdn_image = next;
	d->image = next ? next->address : NULL;
	if (old) {
		bpf_image_ksym_del(&old->ksym);
		/* Retire both the executable entry and diagnostic publication. */
		synchronize_rcu();
		if (old->registered)
			arch_unregister_bpf_dispatcher(old->address);
		hdn_bpf_dispatcher_put_progs(old);
		bpf_prog_pack_free(old->address, PAGE_SIZE);
		bpf_jit_uncharge_modmem(PAGE_SIZE);
		kfree(old);
	}
}
#endif

static void bpf_dispatcher_update(struct bpf_dispatcher *d, int prev_num_progs)
{
	void *new, *tmp;
	u32 noff = 0;

#ifdef CONFIG_SECURITY_HARDENING_BPF_EXECMEM
	hdn_bpf_dispatcher_update(d);
	return;
#endif
	if (prev_num_progs)
		noff = d->image_off ^ (PAGE_SIZE / 2);

	new = d->num_progs ? d->image + noff : NULL;
	tmp = d->num_progs ? d->rw_image + noff : NULL;
	if (new) {
		/* Prepare the dispatcher in d->rw_image. Then use
		 * bpf_arch_text_copy to update d->image, which is RO+X.
		 */
		if (bpf_dispatcher_prepare(d, new, tmp))
			return;
		if (IS_ERR(bpf_arch_text_copy(new, tmp, PAGE_SIZE / 2)))
			return;
	}

	__BPF_DISPATCHER_UPDATE(d, new ?: (void *)&bpf_dispatcher_nop_func);

	/* Make sure all the callers executing the previous/old half of the
	 * image leave it, so following update call can modify it safely.
	 */
	synchronize_rcu();

	if (new)
		d->image_off = noff;
}

void bpf_dispatcher_change_prog(struct bpf_dispatcher *d, struct bpf_prog *from,
				struct bpf_prog *to)
{
	bool changed = false;
	int prev_num_progs;

	if (from == to)
		return;

	mutex_lock(&d->mutex);
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_BPF_EXECMEM) && !d->image) {
		d->image = bpf_prog_pack_alloc(PAGE_SIZE, bpf_jit_fill_hole_with_zero);
		if (!d->image)
			goto out;
		d->rw_image = bpf_jit_alloc_exec(PAGE_SIZE);
		if (!d->rw_image) {
			bpf_prog_pack_free(d->image, PAGE_SIZE);
			d->image = NULL;
			goto out;
		}
		bpf_image_ksym_init(d->image, PAGE_SIZE, &d->ksym);
		bpf_image_ksym_add(&d->ksym);
	}

	prev_num_progs = d->num_progs;
	changed |= bpf_dispatcher_remove_prog(d, from);
	changed |= bpf_dispatcher_add_prog(d, to);

	if (!changed)
		goto out;

	bpf_dispatcher_update(d, prev_num_progs);
out:
	mutex_unlock(&d->mutex);
}
