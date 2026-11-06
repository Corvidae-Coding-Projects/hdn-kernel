// SPDX-License-Identifier: GPL-2.0-only
/* Exact ftrace template admission and sealed return-site lifetimes. */
#include <linux/ftrace.h>
#include <linux/hdn_execmem.h>
#include <linux/hdn_pgtable.h>
#include <linux/mm.h>
#include <linux/memory.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <asm/text-patching.h>
#include <asm/nops.h>

#include "hdn_rap_internal.h"
#include "../mm/hdn_pgtable_internal.h"

struct hdn_rap_image *hdn_rap_images __ro_after_init;
static DEFINE_RAW_SPINLOCK(rap_images_lock);

static void notrace registry_quiescent(struct work_struct *work)
{
}

void hdn_rap_registry_synchronize(void)
{
	/* Closed transfer checks disable IRQs and may precede RCU watching at
	 * entry. A normal RCU grace period alone cannot drain those readers.
	 * Force a scheduling boundary on every online CPU as well. The generic
	 * rude-tasks API can be a no-op on ARCH_WANTS_NO_INSTR, while RAP's entry
	 * roots deliberately perform their own non-instrumented metadata reads.
	 * Code owners must already have drained their offline/startup users. */
	if (schedule_on_each_cpu(registry_quiescent))
		panic("HDN RAP registry quiescence failed");
	synchronize_rcu();
}

static void image_head_store(struct hdn_rap_image *image)
{
	hdn_pt_window_update(__pa_symbol(&hdn_rap_images) >> PAGE_SHIFT,
		offset_in_page(&hdn_rap_images), (unsigned long)image, 0, HDN_PT_STORE);
}

static void image_next_store(struct hdn_rap_image *image, struct hdn_rap_image *next)
{
	BUILD_BUG_ON(sizeof(*image) > PAGE_SIZE);
	hdn_pt_window_update(image->header_pfn, offset_in_page(&image->next),
		(unsigned long)next, 0, HDN_PT_STORE);
}

/* The ftrace owner has already drained executing trampolines before this call.
 * Our extra grace period drains transfer-time metadata readers after removal. */
void hdn_rap_ftrace_release(void *code)
{
	struct hdn_rap_image *image, *previous = NULL;
	unsigned long flags;

	raw_spin_lock_irqsave(&rap_images_lock, flags);
	for (image = hdn_rap_images; image; previous = image, image = image->next)
		if (image->address == (unsigned long)code)
			break;
	if (image) {
		if (previous)
			image_next_store(previous, image->next);
		else
			image_head_store(image->next);
	}
	raw_spin_unlock_irqrestore(&rap_images_lock, flags);
	if (image) {
		hdn_rap_registry_synchronize();
		if (!hdn_execmem_free(image))
			panic("HDN RAP trampoline metadata retirement failed");
	}
}

#if defined(CONFIG_DYNAMIC_FTRACE) && defined(CONFIG_X86_64)
extern void ftrace_caller_end(void), ftrace_regs_caller_end(void);
extern void ftrace_caller_op_ptr(void), ftrace_regs_caller_op_ptr(void);
extern void ftrace_regs_caller_jmp(void), __hdn_rap_return(void);

#define RAP_FTRACE_SITES 2

/* Reconstruct from the fixed built-in template, allowing exactly its ops
 * reference, callback CALL, disabled direct-call branch and protected return.
 * Compare the complete finalized image, including the appended ops pointer.
 * No caller can register an arbitrary list of addresses as valid returns. */
static int ftrace_image_check(void *image, size_t size, bool regs,
		const struct ftrace_ops *ops, unsigned long callback,
		unsigned long *source, size_t *code_size)
{
	unsigned long end, call, op, branch;
	u8 *expected;
	s32 displacement;
	int error = -ENOEXEC;

	if (regs) {
		*source = (unsigned long)ftrace_regs_caller;
		end = (unsigned long)ftrace_regs_caller_end;
		call = (unsigned long)ftrace_regs_call;
		op = (unsigned long)ftrace_regs_caller_op_ptr;
		branch = (unsigned long)ftrace_regs_caller_jmp;
	} else {
		*source = (unsigned long)ftrace_caller;
		end = (unsigned long)ftrace_caller_end;
		call = (unsigned long)ftrace_call;
		op = (unsigned long)ftrace_caller_op_ptr;
		branch = 0;
	}
	if (end <= *source || end - *source > PAGE_SIZE ||
	    size != end - *source + JMP32_INSN_SIZE + sizeof(ops) ||
	    call < *source || call > end - CALL_INSN_SIZE ||
	    op < *source || op > end - 7 ||
	    (regs && (branch < *source || branch > end - 2)) ||
	    !hdn_rap_target_matches(callback, (unsigned long)ftrace_stub) ||
	    !hdn_execmem_sealed((unsigned long)image, DIV_ROUND_UP(size, PAGE_SIZE)))
		return -ENOEXEC;
	*code_size = end - *source;
	expected = kmalloc(size, GFP_KERNEL);
	if (!expected)
		return -ENOMEM;
	mutex_lock(&text_mutex);
	memcpy(expected, (void *)*source, *code_size);
	if (regs) {
		if (expected[branch - *source] != 0x75)
			goto out;
		memcpy(expected + (branch - *source), x86_nops[2], 2);
	}
	text_poke_apply_relocation(expected, image, *code_size, (void *)*source, *code_size);
	if (memcmp(expected + (op - *source), "\x48\x8b\x15", 3))
		goto out;
	displacement = *code_size + JMP32_INSN_SIZE - (op - *source + 7);
	memcpy(expected + (op - *source) + 3, &displacement, sizeof(displacement));
	__text_gen_insn(expected + (call - *source), CALL_INSN_OPCODE,
		image + (call - *source), (void *)callback, CALL_INSN_SIZE);
	__text_gen_insn(expected + *code_size, JMP32_INSN_OPCODE,
		image + *code_size, __hdn_rap_return, JMP32_INSN_SIZE);
	memcpy(expected + *code_size + JMP32_INSN_SIZE, &ops, sizeof(ops));
	if (!memcmp(expected, image, size))
		error = 0;
out:
	mutex_unlock(&text_mutex);
	kfree(expected);
	return error;
}

int hdn_rap_ftrace_prepare(void *code, size_t size, bool regs,
		const struct ftrace_ops *ops, unsigned long callback)
{
	struct hdn_rap_image *image, *other;
	const struct hdn_rap_target *site;
	unsigned long source, flags;
	size_t code_size, count = 0;
	size_t allocation = struct_size(image, sites, RAP_FTRACE_SITES);
	int error;

	if (!hdn_pt_active())
		return -EOPNOTSUPP;
	error = ftrace_image_check(code, size, regs, ops, callback, &source, &code_size);
	if (error)
		return error;
	image = __vmalloc_node_range(PAGE_ALIGN(allocation), PAGE_SIZE, VMALLOC_START,
		VMALLOC_END, GFP_KERNEL | __GFP_ZERO, PAGE_KERNEL, VM_FLUSH_RESET_PERMS,
		NUMA_NO_NODE, __builtin_return_address(0));
	if (!image)
		return -ENOMEM;
	error = hdn_execmem_claim_data(image);
	if (error) {
		vfree(image);
		return error;
	}
	image->header_pfn = vmalloc_to_pfn(image);
	image->address = (unsigned long)code;
	image->callback_site = image->address + (regs ? (unsigned long)ftrace_regs_call :
		(unsigned long)ftrace_call) - source;
	image->size = code_size + JMP32_INSN_SIZE;
	for (site = __hdn_rap_sites_start; site < __hdn_rap_sites_end; site++) {
		unsigned long offset;

		if (site->address < source || site->address >= source + code_size)
			continue;
		offset = site->address - source;
		if (site->type || count == RAP_FTRACE_SITES || offset < 12 ||
		    memcmp(code + offset - 12, "\x4c\x8d\x15\x05\0\0\0\xe8", 8)) {
			error = -ENOEXEC;
			goto discard;
		}
		image->sites[count++].address = image->address + offset;
	}
	if (count != RAP_FTRACE_SITES || image->sites[0].address == image->sites[1].address) {
		error = -ENOEXEC;
		goto discard;
	}
	image->site_count = count;
	error = hdn_execmem_seal_data(image);
	if (error)
		goto discard;
	raw_spin_lock_irqsave(&rap_images_lock, flags);
	for (other = hdn_rap_images; other; other = other->next) {
		if (other->address == image->address) {
			error = -EEXIST;
			goto unlock;
		}
	}
	image_next_store(image, hdn_rap_images);
	smp_wmb();
	image_head_store(image);
unlock:
	raw_spin_unlock_irqrestore(&rap_images_lock, flags);
	if (!error)
		return 0;
discard:
	if (!hdn_execmem_free(image))
		panic("HDN RAP rejected trampoline metadata retirement failed");
	return error;
}
#else
int hdn_rap_ftrace_prepare(void *code, size_t size, bool regs,
		const struct ftrace_ops *ops, unsigned long callback)
{
	return -EOPNOTSUPP;
}
#endif
