// SPDX-License-Identifier: GPL-2.0-only
/* Admission for verified BPF programs. No arbitrary JIT registration API. */
#include <linux/bpf.h>
#include <linux/bitmap.h>
#include <linux/filter.h>
#include <linux/hdn_execmem.h>
#include <linux/memory.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/unaligned.h>
#include <asm/cfi.h>
#include <asm/hdn_rap_bpf.h>
#include <asm/nops.h>
#include <asm/insn.h>
#include <asm/nospec-branch.h>

#include "hdn_rap_internal.h"
#include "../mm/hdn_pgtable_internal.h"

struct hdn_rap_bpf_image *hdn_rap_bpf_images __ro_after_init;
static DEFINE_RAW_SPINLOCK(bpf_images_lock);
extern const struct hdn_rap_type __hdn_rap_type_provider_bpf_program;
extern const struct hdn_rap_type __hdn_rap_type_provider_bpf_callback;
extern const struct hdn_rap_type __hdn_rap_type_provider_bpf_dispatcher;
#ifdef CONFIG_BPF_SYSCALL
extern void bpf_throw(u64 cookie);
#endif

static bool throw_call(const u8 *code, unsigned int end)
{
#ifdef CONFIG_BPF_SYSCALL
	return end >= 5 && code[end - 5] == 0xe8 &&
		(unsigned long)(code + end) + (s32)get_unaligned_le32(code + end - 4) ==
		(unsigned long)bpf_throw;
#else
	return false;
#endif
}

static void bpf_head_store(struct hdn_rap_bpf_image *image)
{
	hdn_pt_window_update(__pa_symbol(&hdn_rap_bpf_images) >> PAGE_SHIFT,
		offset_in_page(&hdn_rap_bpf_images), (unsigned long)image, 0, HDN_PT_STORE);
}

static void bpf_next_store(struct hdn_rap_bpf_image *image,
		struct hdn_rap_bpf_image *next)
{
	BUILD_BUG_ON(sizeof(*image) > PAGE_SIZE);
	hdn_pt_window_update(image->header_pfn, offset_in_page(&image->next),
		(unsigned long)next, 0, HDN_PT_STORE);
}

static int bpf_image_publish(struct hdn_rap_bpf_image *image)
{
	struct hdn_rap_bpf_image *other;
	unsigned long flags;
	int error = hdn_execmem_seal_data(image);

	if (error)
		return error;
	raw_spin_lock_irqsave(&bpf_images_lock, flags);
	for (other = hdn_rap_bpf_images; other; other = other->next)
		if (image->address < other->address + other->size &&
		    other->address < image->address + image->size) {
			error = -EEXIST;
			goto unlock;
		}
	bpf_next_store(image, hdn_rap_bpf_images);
	smp_wmb();
	bpf_head_store(image);
unlock:
	raw_spin_unlock_irqrestore(&bpf_images_lock, flags);
	return error;
}

/* Rebuild the complete finite dispatcher from validated program entries. Its
 * direct leaves and checked fallback tail-transfer one bound caller slot;
 * this producer never acquires a normal-function tracing body or local labels. */
int hdn_rap_bpf_dispatcher_prepare(void *code, const s64 *funcs, unsigned int count)
{
#ifdef CONFIG_BPF_JIT
	struct hdn_rap_bpf_image *image;
	s64 targets[BPF_DISPATCHER_MAX];
	void *expected;
	unsigned int i;
	int error;

	if (!hdn_pt_active() || !count || count > ARRAY_SIZE(targets) ||
	    !hdn_execmem_sealed_bpf((unsigned long)code, PAGE_SIZE))
		return -ENOEXEC;
	for (i = 0; i < count; i++) {
		if (!hdn_rap_target_type_matches(funcs[i], &__hdn_rap_type_provider_bpf_program))
			return -ENOEXEC;
		targets[i] = funcs[i];
	}
	expected = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!expected)
		return -ENOMEM;
	error = arch_prepare_bpf_dispatcher(code, expected, targets, count);
	if (!error && memcmp(code, expected, PAGE_SIZE))
		error = -ENOEXEC;
	kfree(expected);
	if (error)
		return error;
	image = __vmalloc_node_range(PAGE_SIZE, PAGE_SIZE, VMALLOC_START,
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
	image->size = PAGE_SIZE;
	image->active = 1;
	image->target.address = image->address;
	image->target.type = &__hdn_rap_type_provider_bpf_dispatcher;
	error = bpf_image_publish(image);
	if (error && !hdn_execmem_free(image))
		panic("HDN RAP dispatcher metadata retirement failed");
	return error;
#else
	return -EOPNOTSUPP;
#endif
}

/* The program owner has drained execution before retiring its allocation.
 * Publication failure also comes here, but cannot have acquired any readers. */
void hdn_rap_bpf_release(void *code)
{
	struct hdn_rap_bpf_image *image, *prev = NULL;
	unsigned long flags;

	raw_spin_lock_irqsave(&bpf_images_lock, flags);
	for (image = hdn_rap_bpf_images; image; prev = image, image = image->next)
		if (image->address == (unsigned long)code)
			break;
	if (image) {
		if (prev)
			bpf_next_store(prev, image->next);
		else
			bpf_head_store(image->next);
	}
	raw_spin_unlock_irqrestore(&bpf_images_lock, flags);
	if (image) {
		hdn_rap_registry_synchronize();
		if (!hdn_execmem_free(image))
			panic("HDN RAP BPF metadata retirement failed");
	}
}

void hdn_rap_bpf_release_range(void *code, size_t size)
{
	struct hdn_rap_bpf_image *image;
	unsigned long address, flags;

	for (;;) {
		address = 0;
		raw_spin_lock_irqsave(&bpf_images_lock, flags);
		for (image = hdn_rap_bpf_images; image; image = image->next)
			if (image->address >= (unsigned long)code && image->size <= size &&
			    image->address - (unsigned long)code <= size - image->size) {
				address = image->address;
				break;
			}
		raw_spin_unlock_irqrestore(&bpf_images_lock, flags);
		if (!address)
			break;
		hdn_rap_bpf_release((void *)address);
	}
}

static bool bound_call(const u8 *code, unsigned int end, unsigned long target)
{
	if (end < 12 || memcmp(code + end - 12, "\x4c\x8d\x15\x05\0\0\0\xe8", 8))
		return false;
	return !target || (unsigned long)(code + end) +
		(s32)get_unaligned_le32(code + end - 4) == target;
}

/* Locate the architectural return slot, before any JIT register restoration.
 * The timed helper's R10 data transport is a closed private ABI: match both
 * ends and the fixed callee before giving this site a return permission. */
static bool bpf_call_end(const struct bpf_prog *prog, unsigned int index,
		const u8 *code, unsigned int start, unsigned int *end)
{
	unsigned int cursor = *end;
	unsigned long target = (unsigned long)__bpf_call_base + prog->insnsi[index].imm;
	bool timed = target == (unsigned long)arch_bpf_timed_may_goto;

	if (cursor < start)
		return false;
	if (prog->aux->priv_stack_ptr) {
		if (cursor - start < 2 || memcmp(code + cursor - 2, "\x41\x59", 2))
			return false;
		cursor -= 2;
	}
	if (timed) {
		if (cursor - start < 20 ||
		    memcmp(code + cursor - 4, "\x41\x5a\x41\x5b", 4) ||
		    memcmp(code + cursor - 20, "\x41\x53\x41\x52", 4) ||
		    !bound_call(code, cursor - 4, target))
			return false;
		cursor -= 4;
	} else if (cursor - start < 12 || !bound_call(code, cursor, 0) ||
		   bound_call(code, cursor, (unsigned long)arch_bpf_timed_may_goto)) {
		return false;
	}
	*end = cursor;
	return true;
}

static bool trampoline_call(unsigned long target, unsigned int end,
		const struct hdn_rap_bpf_tramp_layout *layout)
{
	if (target == (unsigned long)__hdn_rap_bpf_original)
		return end == layout->original;
	if (target == (unsigned long)__hdn_rap_bpf_skip)
		return end == layout->skip;
#if defined(CONFIG_BPF_SYSCALL) && defined(CONFIG_BPF_JIT)
	if (target == (unsigned long)__bpf_tramp_enter || target == (unsigned long)__bpf_tramp_exit)
		return true;
#endif
	return hdn_rap_target_type_matches(target, &__hdn_rap_type_provider_bpf_program) ||
		hdn_rap_target_type_matches(target, &__hdn_rap_type_provider_bpf_trampoline_enter) ||
		hdn_rap_target_type_matches(target, &__hdn_rap_type_provider_bpf_trampoline_exit);
}

/* Decode at instruction boundaries: immediates containing E8/RET bytes must
 * never be mistaken for control transfers or permission-bearing call sites. */
static int trampoline_sites(const void *code, const u8 *bytes, size_t size,
		const struct hdn_rap_bpf_tramp_layout *layout, struct hdn_rap_target *sites)
{
	DECLARE_BITMAP(boundaries, PAGE_SIZE);
	struct insn insn;
	unsigned int offset = 0, count = 0;

	if (!size || size > PAGE_SIZE)
		return -ENOEXEC;
	bitmap_zero(boundaries, size);
	/* A branch into an immediate or into the middle of an entry/call
	 * binding must not acquire permission from a simple range check. */
	while (offset < size) {
		if (insn_decode(&insn, bytes + offset, size - offset, INSN_MODE_64) ||
		    !insn.length || insn.length > size - offset)
			return -ENOEXEC;
		__set_bit(offset, boundaries);
		offset += insn.length;
	}
	offset = 0;
	while (offset < size) {
		unsigned int end;
		unsigned long target;
		u8 op;

		if (insn_decode(&insn, bytes + offset, size - offset, INSN_MODE_64) ||
		    !insn.length || insn.length > size - offset)
			return -ENOEXEC;
		end = offset + insn.length;
		op = insn.opcode.bytes[0];
		if (op == 0xe8) {
			if (insn.length != 5)
				return -ENOEXEC;
			if (offset != layout->entry + 7) {
				if (!bound_call(bytes, end, 0))
					return -ENOEXEC;
				target = (unsigned long)code + end +
					(s32)get_unaligned_le32(bytes + end - 4);
				if (!trampoline_call(target, end, layout))
					return -ENOEXEC;
				if (sites)
					sites[count].address = (unsigned long)code + end;
				count++;
			}
		} else if (op == 0xc3 || op == 0xc2 || op == 0xca || op == 0xcb || op == 0xcf ||
			   op == 0x9a || op == 0xea ||
			   (op == 0xff && X86_MODRM_REG(insn.modrm.value) >= 2 &&
			    X86_MODRM_REG(insn.modrm.value) <= 5) ||
			   (op == 0x0f && (insn.opcode.bytes[1] == 0x05 ||
			    insn.opcode.bytes[1] == 0x07 || insn.opcode.bytes[1] == 0x34 ||
			    insn.opcode.bytes[1] == 0x35))) {
			return -ENOEXEC;
		} else if (op == 0xe9 || op == 0xeb || (op >= 0x70 && op <= 0x7f) ||
			   (op >= 0xe0 && op <= 0xe3) ||
			   (op == 0x0f && insn.opcode.bytes[1] >= 0x80 && insn.opcode.bytes[1] <= 0x8f)) {
			target = (unsigned long)code + end + (insn.immediate.nbytes == 1 ?
				(s8)insn.immediate.value : (s32)insn.immediate.value);
			if (target >= (unsigned long)code && target - (unsigned long)code < size) {
				unsigned long off = target - (unsigned long)code;

				if (off < layout->entry + 12 || !test_bit(off, boundaries))
					return -ENOEXEC;
				/* Bound calls enter only through the full LEA/CALL pair. */
				if (bytes[off] == 0xe8)
					return -ENOEXEC;
			} else if (op != 0xe9 || target != (unsigned long)__hdn_rap_return || end != size) {
				return -ENOEXEC;
			}
		}
		offset = end;
	}
	return count;
}

/* A removal skips exactly one complete enter/program/exit group. No branch
 * outside that group may bypass its gate, and no branch inside may escape it.
 * Copy only the identity and validated endpoints into sealed metadata. */
static int trampoline_unlink_slots(const void *code, const u8 *bytes, size_t size,
		const struct hdn_rap_bpf_tramp_layout *layout, struct hdn_rap_bpf_unlink *slots)
{
#if defined(CONFIG_BPF_SYSCALL) && defined(CONFIG_BPF_JIT)
	unsigned long base = (unsigned long)code, previous = base;
	unsigned int i;

	if (layout->nr_unlink > BPF_MAX_TRAMP_LINKS ||
	    (layout->nr_unlink && !layout->unlink))
		return -ENOEXEC;
	for (i = 0; i < layout->nr_unlink; i++) {
		const struct bpf_tramp_unlink *slot = &layout->unlink[i];
		unsigned long targets[3];
		unsigned int off = 0, calls = 0;
		bool start_seen = false, end_seen = false;
		struct insn insn;

		if (!slot->link || !slot->prog || slot->start < previous ||
		    slot->start < base + layout->entry + 12 || slot->start >= base + size ||
		    slot->end <= slot->start || slot->end - slot->start <= 5 ||
		    slot->end >= base + size ||
		    memcmp(bytes + slot->start - base, x86_nops[5], 5))
			return -ENOEXEC;
		targets[0] = (unsigned long)bpf_trampoline_enter(slot->prog);
		targets[1] = (unsigned long)READ_ONCE(slot->prog->bpf_func);
		targets[2] = (unsigned long)bpf_trampoline_exit(slot->prog);
		while (off < size) {
			unsigned long address = base + off, end, target;
			u8 op;
			bool in = address >= slot->start && address < slot->end;

			if (insn_decode(&insn, bytes + off, size - off, INSN_MODE_64) ||
			    !insn.length || insn.length > size - off)
				return -ENOEXEC;
			end = address + insn.length;
			start_seen |= address == slot->start;
			end_seen |= address == slot->end;
			op = insn.opcode.bytes[0];
			if (in && op == 0xe8) {
				target = end + (s32)insn.immediate.value;
				if (calls >= ARRAY_SIZE(targets) || target != targets[calls++] ||
				    (calls == ARRAY_SIZE(targets) && end != slot->end))
					return -ENOEXEC;
			} else if (op == 0xe9 || op == 0xeb || (op >= 0x70 && op <= 0x7f) ||
				   (op >= 0xe0 && op <= 0xe3) || (op == 0x0f &&
				    insn.opcode.bytes[1] >= 0x80 && insn.opcode.bytes[1] <= 0x8f)) {
				target = end + (insn.immediate.nbytes == 1 ?
					(s8)insn.immediate.value : (s32)insn.immediate.value);
				if ((in && (target <= slot->start || target >= slot->end)) ||
				    (!in && target > slot->start && target < slot->end))
					return -ENOEXEC;
			}
			off += insn.length;
		}
		if (!start_seen || !end_seen || calls != ARRAY_SIZE(targets))
			return -ENOEXEC;
		if (slots)
			slots[i] = (struct hdn_rap_bpf_unlink) {
				.link = (unsigned long)slot->link,
				.start = slot->start, .end = slot->end,
			};
		previous = slot->end;
	}
	return 0;
#else
	return layout->nr_unlink ? -ENOEXEC : 0;
#endif
}

int hdn_rap_bpf_trampoline_stage(void *code, const void *bytes, size_t size,
		u32 flags, unsigned long reference, const struct hdn_rap_bpf_tramp_layout *layout)
{
	struct hdn_rap_bpf_image *image;
	struct hdn_rap_target *sites;
	struct hdn_rap_bpf_unlink *unlink;
	struct hdn_rap_type *type;
	size_t allocation, type_size = ALIGN(sizeof(*type) + HDN_RAP_TYPE_MAX + 1, 8);
	unsigned long entry_target;
	int count, copied, error;

	if (!hdn_pt_active() || !size || size > PAGE_SIZE || layout->size > size ||
	    layout->size < 12 || layout->entry > layout->size - 12 || cfi_get_offset() ||
	    flags & ~((BPF_TRAMP_F_INDIRECT << 1) - 1) ||
	    ((flags & BPF_TRAMP_F_INDIRECT) &&
	     (flags & ~(BPF_TRAMP_F_INDIRECT | BPF_TRAMP_F_RET_FENTRY_RET))) ||
	    ((flags & BPF_TRAMP_F_SKIP_FRAME) && !(flags & BPF_TRAMP_F_CALL_ORIG)) ||
	    memcmp(bytes + layout->entry, "\x4c\x8d\x1d\x05\0\0\0\xe8", 8))
		return -ENOEXEC;
	entry_target = (unsigned long)code + layout->entry + 12 +
		(s32)get_unaligned_le32(bytes + layout->entry + 8);
	if (entry_target != (unsigned long)(bpf_trampoline_use_jmp(flags) ?
		__hdn_rap_bpf_tramp_enter : __hdn_rap_enter))
		return -ENOEXEC;
	count = trampoline_sites(code, bytes, layout->size, layout, NULL);
	if (count < 0)
		return count;
	if (trampoline_unlink_slots(code, bytes, layout->size, layout, NULL))
		return -ENOEXEC;
	/* Every callable invocation in a direct trampoline has one gate.
	 * Account separately for the three original-call lifecycle helpers
	 * and the optional frame-skip adapter. struct_ops has its own owner. */
	if (!(flags & BPF_TRAMP_F_INDIRECT) &&
	    (!layout->nr_unlink || count != 3 * layout->nr_unlink +
		((flags & BPF_TRAMP_F_CALL_ORIG) ? 3 : 0) +
		((flags & BPF_TRAMP_F_SKIP_FRAME) ? 1 : 0)))
		return -ENOEXEC;
	allocation = sizeof(*image) + count * sizeof(*sites) +
		layout->nr_unlink * sizeof(*unlink) + type_size + size;
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
	image->size = size;
	image->trampoline = 1;
	image->tramp_flags = flags;
	image->site_count = count;
	sites = (void *)hdn_rap_bpf_sites(image);
	unlink = (void *)(sites + count);
	image->unlink = (struct hdn_rap_section) { unlink, layout->nr_unlink * sizeof(*unlink) };
	type = (void *)(unlink + layout->nr_unlink);
	copied = hdn_rap_function_copy(reference, &image->reference, type, type_size);
	if (copied < 0) {
		error = copied;
		goto discard;
	}
	image->types = (struct hdn_rap_section) { type, copied };
	image->template = (struct hdn_rap_section) { (void *)type + type_size, size };
	memcpy((void *)image->template.data, bytes, size);
	image->function.address = image->address;
	image->function.body = image->address + layout->entry + 12;
	image->function.type = type;
	if (flags & BPF_TRAMP_F_INDIRECT) {
		image->target.address = image->address;
		image->target.type = type;
	}
	image->original = layout->original ? image->address + layout->original : 0;
	image->skip = layout->skip ? image->address + layout->skip : 0;
	image->after_call = layout->after_call ? image->address + layout->after_call : 0;
	image->epilogue = layout->epilogue ? image->address + layout->epilogue : 0;
	error = -ENOEXEC;
	if ((!!image->original != !!(flags & BPF_TRAMP_F_CALL_ORIG)) ||
	    (!!image->skip != !!(flags & BPF_TRAMP_F_SKIP_FRAME)) ||
	    (image->original && (!image->reference.trace_return ||
	     layout->original > layout->size || !bound_call(bytes, layout->original, 0))) ||
	    (image->skip && (layout->skip + 1 != layout->size ||
	     !bound_call(bytes, layout->skip, 0))) ||
	    layout->after_call > layout->size || layout->epilogue > layout->size)
		goto discard;
	if (image->original &&
	    (image->original + (s32)get_unaligned_le32(bytes + layout->original - 4) !=
		(unsigned long)__hdn_rap_bpf_original ||
	     !image->after_call || !image->epilogue || layout->after_call < layout->original ||
	     layout->after_call + 5 > layout->epilogue ||
	     memcmp(bytes + layout->after_call, x86_nops[5], 5)))
		goto discard;
	if (image->skip &&
	    (image->skip + (s32)get_unaligned_le32(bytes + layout->skip - 4) !=
		(unsigned long)__hdn_rap_bpf_skip || ((u8 *)bytes)[layout->skip] != 0xcc))
		goto discard;
	if (!image->original && (image->after_call || image->epilogue))
		goto discard;
	for (size_t i = layout->size; i < size; i++)
		if (((const u8 *)bytes)[i] != 0xcc)
			goto discard;
	if (trampoline_sites(code, bytes, layout->size, layout, sites) != count)
		goto discard;
	if (trampoline_unlink_slots(code, bytes, layout->size, layout, unlink))
		goto discard;
	error = bpf_image_publish(image); /* active remains zero until RX finalization */
	if (!error)
		return 0;
discard:
	if (!hdn_execmem_free(image))
		panic("HDN RAP staged trampoline retirement failed");
	return error;
}

int hdn_rap_bpf_trampoline_publish(void *code, size_t size)
{
	struct hdn_rap_bpf_image *image;
	unsigned long flags;
	int error = 0;
	bool found = false;

	if (!hdn_execmem_sealed_bpf((unsigned long)code, size))
		return -ENOEXEC;
	raw_spin_lock_irqsave(&bpf_images_lock, flags);
	/* Validate the entire range first; a later member cannot expose an
	 * earlier member of a partially admitted struct_ops image page. */
	for (image = hdn_rap_bpf_images; image; image = image->next) {
		if (image->address < (unsigned long)code || image->size > size ||
		    image->address - (unsigned long)code > size - image->size)
			continue;
		if (!image->trampoline || image->active || image->template.size != image->size ||
		    memcmp((void *)image->address, image->template.data, image->size)) {
			error = -ENOEXEC;
			goto out;
		}
		found = true;
	}
	for (image = hdn_rap_bpf_images; image; image = image->next) {
		if (image->address < (unsigned long)code || image->size > size ||
		    image->address - (unsigned long)code > size - image->size)
			continue;
		smp_wmb();
		hdn_pt_window_update(image->header_pfn, offset_in_page(&image->active),
			1, 0, HDN_PT_STORE);
	}
out:
	raw_spin_unlock_irqrestore(&bpf_images_lock, flags);
	return error ?: (found ? 0 : -ENOEXEC);
}

/* Capture the verifier's frozen instruction-array label sets before mutable
 * ips[] is published. Interior bytes and non-label BPF instructions do not
 * become jump destinations simply because they belong to the same image. */
static int collect_labels(const struct bpf_prog *prog, unsigned long *labels)
{
	unsigned int i, j;

	for (i = 0; i < prog->aux->used_map_cnt; i++) {
		struct bpf_map *map = prog->aux->used_maps[i];

		if (map->map_type != BPF_MAP_TYPE_INSN_ARRAY)
			continue;
		if (!map->frozen)
			return -ENOEXEC;
		for (j = 0; j < map->max_entries; j++) {
			const struct bpf_insn_array_value *value;
			u32 off;

			value = map->ops->map_lookup_elem(map, &j);
			if (!value)
				return -ENOEXEC;
			off = value->xlated_off;
			if (off == U32_MAX || off < prog->aux->subprog_start)
				continue;
			off -= prog->aux->subprog_start;
			if (off >= prog->len)
				continue;
			if (off && prog->insnsi[off - 1].code == (BPF_LD | BPF_DW | BPF_IMM))
				return -ENOEXEC;
			__set_bit(off, labels);
		}
	}
	return 0;
}

int hdn_rap_bpf_prepare(const struct bpf_prog *prog, void *code, size_t size,
		const int *offsets, const struct hdn_rap_bpf_layout *layout)
{
	const struct bpf_prog_aux *owner = prog->aux->main_prog_aux ?: prog->aux;
	bool extension = prog->type == BPF_PROG_TYPE_EXT && !bpf_is_subprog(prog);
	struct hdn_rap_bpf_image *image = NULL;
	struct hdn_rap_target *sites;
	unsigned long *labels, *destinations;
	size_t edge_count = 0, site_count = 0, label_count, allocation;
	unsigned int i, entry = layout->entry;
	int error = -ENOEXEC;

	if (!hdn_pt_active() || !prog->len || size > INT_MAX ||
	    size < 12 || entry > size - 12 || offsets[0] < entry + 12 ||
	    offsets[prog->len] != size || cfi_get_offset() ||
	    !hdn_execmem_sealed_bpf((unsigned long)code, size) ||
	    memcmp(code + entry, "\x4c\x8d\x1d\x05\0\0\0\xe8", 8) ||
	    (unsigned long)code + entry + 12 + (s32)get_unaligned_le32(code + entry + 8) !=
		(unsigned long)(prog->aux->exception_cb ? __hdn_rap_bpf_exception : __hdn_rap_enter))
		return -ENOEXEC;
	labels = bitmap_zalloc(prog->len, GFP_KERNEL);
	if (!labels)
		return -ENOMEM;
	error = collect_labels(prog, labels);
	if (error)
		goto out;
	error = -ENOEXEC;
	for (i = 0; i < prog->len; i++) {
		u8 op = prog->insnsi[i].code;

		if (offsets[i] < 0 || offsets[i + 1] < offsets[i] || offsets[i + 1] > size)
			goto out;
		if (op == (BPF_JMP | BPF_JA | BPF_X) ||
		    (op == (BPF_JMP | BPF_TAIL_CALL) && !prog->insnsi[i].imm)) {
			unsigned int end = offsets[i + 1];

			if (end - offsets[i] < 13 || ((u8 *)code)[end - 1] != 0xcc ||
			    !bound_call(code, end - 1, (unsigned long)__hdn_rap_bpf_jump))
				goto out;
			edge_count++;
		}
		if (op == (BPF_JMP | BPF_CALL)) {
			unsigned int end = offsets[i + 1];

			if (!bpf_call_end(prog, i, code, offsets[i], &end))
				goto out;
			if (throw_call(code, end))
				edge_count++;
			site_count++;
		}
		if (op == (BPF_JMP | BPF_TAIL_CALL) && prog->insnsi[i].imm)
			edge_count += 2;
	}
	label_count = bitmap_weight(labels, prog->len);
	if (layout->bhb) {
		if (layout->bhb > size || !bpf_prog_was_classic(prog) ||
		    !bound_call(code, layout->bhb, (unsigned long)clear_bhb_loop))
			goto out;
		site_count++;
	}
	allocation = struct_size(image, edges, edge_count);
	allocation = size_add(allocation, size_mul(label_count, sizeof(unsigned long)));
	allocation = size_add(allocation, size_mul(site_count, sizeof(*sites)));
	if (extension)
		allocation = size_add(allocation, sizeof(struct hdn_rap_type) + HDN_RAP_TYPE_MAX + 1);
	if (allocation > HDN_RAP_METADATA_MAX) {
		error = -E2BIG;
		goto out;
	}
	image = __vmalloc_node_range(PAGE_ALIGN(allocation), PAGE_SIZE, VMALLOC_START,
		VMALLOC_END, GFP_KERNEL | __GFP_ZERO, PAGE_KERNEL, VM_FLUSH_RESET_PERMS,
		NUMA_NO_NODE, __builtin_return_address(0));
	if (!image) {
		error = -ENOMEM;
		goto out;
	}
	error = hdn_execmem_claim_data(image);
	if (error) {
		vfree(image);
		image = NULL;
		goto out;
	}
	image->header_pfn = vmalloc_to_pfn(image);
	image->address = (unsigned long)code;
	image->size = size;
	image->active = 1;
	image->owner = (unsigned long)owner;
	image->subprog = bpf_is_subprog(prog);
	image->exception = prog->aux->exception_cb;
	image->target.address = image->address;
	image->target.type = image->subprog ? &__hdn_rap_type_provider_bpf_callback :
		&__hdn_rap_type_provider_bpf_program;
	image->function.address = image->target.address;
	image->function.type = image->target.type;
	image->function.body = image->address + entry + 12;
	image->function.trace_return = image->function.body + 12;
	image->tail = layout->tail ? image->address + layout->tail : 0;
	image->boundary = layout->boundary ? image->address + layout->boundary : 0;
	image->frame_depth = prog->aux->priv_stack_ptr ? 0 : round_up(prog->aux->stack_depth, 8);
	if (prog->aux->tail_call_reachable)
		image->frame_depth += 16;
	image->edge_count = edge_count;
	image->label_count = label_count;
	image->site_count = site_count;
	destinations = (void *)hdn_rap_bpf_labels(image);
	sites = (void *)hdn_rap_bpf_sites(image);
	if (extension) {
		struct hdn_rap_type *type = (void *)(sites + site_count);
		int copied;

		if (!owner->dst_trampoline) {
			error = -ENOEXEC;
			goto out;
		}
		/* freplace inherits the intercepted function's exact calling type,
		 * including a subprogram's five-argument callback ABI. Copy it so
		 * no permission depends on writable aux or foreign metadata. */
		copied = hdn_rap_function_copy((unsigned long)owner->dst_trampoline->func.addr,
			&image->reference, type, sizeof(*type) + HDN_RAP_TYPE_MAX + 1);
		if (copied < 0) {
			error = copied;
			goto out;
		}
		image->types = (struct hdn_rap_section) { type, copied };
		image->target.type = type;
		image->function.type = type;
	}
	label_count = edge_count = site_count = 0;
	error = -ENOEXEC;
	for (i = 0; i < prog->len; i++) {
		u8 op = prog->insnsi[i].code;
		unsigned int end = offsets[i + 1];

		if (test_bit(i, labels))
			destinations[label_count++] = image->address + offsets[i];
		if (op == (BPF_JMP | BPF_JA | BPF_X) ||
		    (op == (BPF_JMP | BPF_TAIL_CALL) && !prog->insnsi[i].imm)) {
			image->edges[edge_count].site = image->address + end - 1;
			image->edges[edge_count++].kind = op == (BPF_JMP | BPF_JA | BPF_X) ?
				HDN_RAP_BPF_LOCAL : HDN_RAP_BPF_TAIL;
		}
		if (op == (BPF_JMP | BPF_CALL)) {
			if (!bpf_call_end(prog, i, code, offsets[i], &end))
				goto out;
			sites[site_count++].address = image->address + end;
			if (throw_call(code, end)) {
				image->edges[edge_count].site = image->address + end;
				image->edges[edge_count++].kind = HDN_RAP_BPF_THROW;
			}
		}
		if (op == (BPF_JMP | BPF_TAIL_CALL) && prog->insnsi[i].imm) {
			const struct bpf_jit_poke_descriptor *poke;
			unsigned long bypass, branch, exit;
			u32 index = prog->insnsi[i].imm - 1;

			if (index >= prog->aux->size_poke_tab || end - offsets[i] < 10)
				goto out;
			poke = &prog->aux->poke_tab[index];
			bypass = (unsigned long)poke->tailcall_bypass;
			branch = image->address + end - 5;
			exit = image->address + end;
			if (poke->reason != BPF_POKE_REASON_TAIL_CALL ||
			    (poke->aux && poke->aux != prog->aux) ||
			    poke->adj_off != entry + 31 ||
			    (unsigned long)poke->tailcall_target != branch ||
			    (unsigned long)poke->bypass_addr != exit ||
			    bypass < image->address + offsets[i] || bypass > branch - 5 ||
			    *(u8 *)bypass != 0xe9 ||
			    bypass + 5 + (s32)get_unaligned_le32((void *)bypass + 1) != exit ||
			    memcmp((void *)branch, x86_nops[5], 5))
				goto out;
			image->edges[edge_count++] = (struct hdn_rap_bpf_edge) {
				.site = branch, .kind = HDN_RAP_BPF_PATCH_TAIL,
			};
			image->edges[edge_count++] = (struct hdn_rap_bpf_edge) {
				.site = bypass, .kind = HDN_RAP_BPF_PATCH_BYPASS, .target = exit,
			};
		}
	}
	if (layout->bhb)
		sites[site_count++].address = image->address + layout->bhb;
	if ((image->tail && (layout->tail >= offsets[0] || image->subprog || image->exception)) ||
	    (image->boundary && (layout->boundary > offsets[0] ||
	     !prog->aux->exception_boundary ||
	     !bound_call(code, layout->boundary, (unsigned long)__hdn_rap_bpf_boundary))))
		goto out;
	error = bpf_image_publish(image);
out:
	bitmap_free(labels);
	if (error && image && !hdn_execmem_free(image))
		panic("HDN RAP rejected BPF metadata retirement failed");
	return error;
}
