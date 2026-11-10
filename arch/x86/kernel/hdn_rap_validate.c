// SPDX-License-Identifier: GPL-2.0-only
/* Transfer-time lookup: immutable ranges/copies, no allocator or module calls. */
#include <linux/init.h>
#include <linux/bpf.h>
#include <linux/export.h>
#include <linux/ftrace.h>
#include <linux/kernel.h>
#include <asm/irqflags.h>
#include <asm/hdn_rap_bpf.h>
#include <asm/hdn_rap_probe.h>
#include <asm/sections.h>
#include "hdn_rap_internal.h"

extern long __static_call_return0(void);

static __always_inline bool inside(unsigned long address, size_t size,
		unsigned long base, size_t extent)
{
	return address >= base && size <= extent && address - base <= extent - size;
}

static __always_inline bool in_section(const void *address, size_t size,
		struct hdn_rap_section section)
{
	return inside((unsigned long)address, size, (unsigned long)section.data, section.size);
}

static noinstr bool noinstr_address(unsigned long address)
{
	const struct hdn_rap_module *view;

	if (inside(address, 1, (unsigned long)__noinstr_text_start,
		   __noinstr_text_end - __noinstr_text_start))
		return true;
	for (view = READ_ONCE(hdn_rap_modules); view; view = READ_ONCE(view->next))
		if (inside(address, 1, view->noinstr_text, view->noinstr_size))
			return true;
	return false;
}

static noinstr bool valid_type(const struct hdn_rap_type *type, struct hdn_rap_section section)
{
	unsigned int i;

	if (!IS_ALIGNED((unsigned long)type, 8) || !in_section(type, sizeof(*type), section) ||
	    type->version != HDN_RAP_VERSION || !type->length || type->length > HDN_RAP_TYPE_MAX ||
	    !in_section(type, sizeof(*type) + type->length + 1, section))
		return false;
	/* Volatile byte reads prevent conversion into an instrumented libc call. */
	for (i = 0; i < type->length; i++)
		if (!READ_ONCE(type->canonical[i]))
			return false;
	return !READ_ONCE(type->canonical[i]);
}

static noinstr const struct hdn_rap_type *type_view(const struct hdn_rap_type *type)
{
	struct hdn_rap_section builtin = { __hdn_rap_types_start,
		__hdn_rap_types_end - __hdn_rap_types_start };
	const struct hdn_rap_module *view;
	const struct hdn_rap_bpf_image *image;

	if (in_section(type, sizeof(*type), builtin))
		return valid_type(type, builtin) ? type : NULL;
	for (view = READ_ONCE(hdn_rap_modules); view; view = READ_ONCE(view->next)) {
		const struct hdn_rap_type *copy = type;

		if (in_section(type, sizeof(*type), view->original_types))
			copy = view->types.data + ((const void *)type - view->original_types.data);
		else if (!in_section(type, sizeof(*type), view->types))
			continue;
		return valid_type(copy, view->types) ? copy : NULL;
	}
	for (image = READ_ONCE(hdn_rap_bpf_images); image; image = READ_ONCE(image->next))
		if (READ_ONCE(image->active) && in_section(type, sizeof(*type), image->types))
			return valid_type(type, image->types) ? type : NULL;
	return NULL;
}

static noinstr bool same_type(const struct hdn_rap_type *a, const struct hdn_rap_type *b)
{
	unsigned int i;

	if (a->length != b->length)
		return false;
	for (i = 0; i < sizeof(a->digest); i++)
		if (READ_ONCE(a->digest[i]) != READ_ONCE(b->digest[i]))
			return false;
	for (i = 0; i < a->length; i++)
		if (READ_ONCE(a->canonical[i]) != READ_ONCE(b->canonical[i]))
			return false;
	return true;
}

const struct hdn_rap_bpf_image *noinstr hdn_rap_bpf_find(unsigned long address)
{
	const struct hdn_rap_bpf_image *image;

	/* All callers hold IRQs disabled, including pre-RCU entry adapters. */
	if (!native_irqs_disabled_flags(native_save_fl()))
		__hdn_rap_fail(HDN_RAP_FAIL_TARGET);
	for (image = READ_ONCE(hdn_rap_bpf_images); image; image = READ_ONCE(image->next))
		if (READ_ONCE(image->active) && inside(address, 1, image->address, image->size))
			return image;
	return NULL;
}

unsigned long noinstr hdn_rap_bpf_validate_jump(unsigned long target, unsigned long site)
{
	unsigned long flags = native_local_irq_save(), result = 0;
	const struct hdn_rap_bpf_image *source = hdn_rap_bpf_find(site), *destination;
	size_t i, j;

	if (source) {
		for (i = 0; i < source->edge_count; i++) {
			if (source->edges[i].site != site)
				continue;
			if (source->edges[i].kind == HDN_RAP_BPF_LOCAL) {
				const unsigned long *labels = hdn_rap_bpf_labels(source);

				for (j = 0; j < source->label_count; j++)
					if (labels[j] == target) {
						result = labels[j];
						break;
					}
			} else if (source->edges[i].kind == HDN_RAP_BPF_TAIL) {
				destination = hdn_rap_bpf_find(target);
				if (destination && destination->tail && target == destination->tail)
					result = destination->tail;
			}
			break;
		}
	}
	native_local_irq_restore(flags);
	if (!result)
		__hdn_rap_fail(HDN_RAP_FAIL_TARGET);
	return result;
}

bool noinstr hdn_rap_bpf_tail_patch(unsigned long site, unsigned long target)
{
	unsigned long flags = native_local_irq_save();
	const struct hdn_rap_bpf_image *source = hdn_rap_bpf_find(site), *destination;
	bool valid = false;
	size_t i;

	if (source)
		for (i = 0; i < source->edge_count; i++) {
			const struct hdn_rap_bpf_edge *edge = &source->edges[i];

			if (edge->site != site)
				continue;
			if (edge->kind == HDN_RAP_BPF_PATCH_BYPASS)
				valid = !target || target == edge->target;
			else if (edge->kind == HDN_RAP_BPF_PATCH_TAIL) {
				destination = target ? hdn_rap_bpf_find(target) : NULL;
				valid = !target || (destination && destination->tail &&
						    destination->tail == target);
			}
			break;
		}
	native_local_irq_restore(flags);
	return valid;
}

static noinstr const struct hdn_rap_target *record(unsigned long address, bool call_site)
{
	const struct hdn_rap_target *entry, *end;
	const struct hdn_rap_module *view;
	size_t low, high;
	const struct hdn_rap_image *image;
	const struct hdn_rap_bpf_image *bpf;

	if (inside(address, 1, (unsigned long)_stext, _etext - _stext) ||
	    (READ_ONCE(hdn_rap_builtin_init_live) &&
	     inside(address, 1, (unsigned long)_sinittext, _einittext - _sinittext))) {
		entry = call_site ? __hdn_rap_sites_start : __hdn_rap_targets_start;
		end = call_site ? __hdn_rap_sites_end : __hdn_rap_targets_end;
		low = 0;
		high = end - entry;
		/*
		 * scripts/sorttable orders both built-in tables by address while
		 * preserving the link order of aliases.  Use a lower-bound search
		 * so duplicate target addresses retain the former first-match
		 * semantics.
		 */
		while (low < high) {
			size_t middle = low + (high - low) / 2;

			if (entry[middle].address < address)
				low = middle + 1;
			else
				high = middle;
		}
		if (low < end - entry && entry[low].address == address)
			return &entry[low];
		return NULL;
	}
	for (view = READ_ONCE(hdn_rap_modules); view; view = READ_ONCE(view->next)) {
		if (!inside(address, 1, view->text, view->text_size) &&
		    !(READ_ONCE(view->init_live) && inside(address, 1, view->init_text, view->init_size)))
			continue;
		low = call_site ? view->count : 0;
		high = call_site ? view->count + view->site_count : view->count;
		while (low < high) {
			size_t middle = low + (high - low) / 2;
			entry = &view->targets[middle];
			if (address < entry->address)
				high = middle;
			else if (address > entry->address)
				low = middle + 1;
			else
				return entry;
		}
		return NULL;
	}
	bpf = hdn_rap_bpf_find(address);
	if (bpf) {
		if (!call_site)
			return bpf->target.address == address ? &bpf->target : NULL;
		entry = hdn_rap_bpf_sites(bpf);
		for (low = 0; low < bpf->site_count; low++)
			if (entry[low].address == address)
				return &entry[low];
		return NULL;
	}
	if (!call_site)
		return NULL;
	for (image = READ_ONCE(hdn_rap_images); image; image = READ_ONCE(image->next)) {
		if (!inside(address, 1, image->address, image->size))
			continue;
		for (low = 0; low < image->site_count; low++)
			if (image->sites[low].address == address)
				return &image->sites[low];
		return NULL;
	}
	return NULL;
}

/* Text patching must admit the callback before changing a direct branch. Its
 * fixed reference supplies the compiler's complete type, not a caller-supplied
 * hash or a mutable ftrace_ops field. Module lifetime remains the caller's. */
bool noinstr hdn_rap_target_matches(unsigned long address, unsigned long reference)
{
	const struct hdn_rap_target *actual, *expected;
	const struct hdn_rap_type *a, *b;
	unsigned long flags = native_local_irq_save();
	bool valid = false;

	actual = record(address, false);
	expected = record(reference, false);
	if (actual && expected && (a = type_view(actual->type)) &&
	    (b = type_view(expected->type)))
		valid = same_type(a, b);
	native_local_irq_restore(flags);
	return valid;
}

bool noinstr hdn_rap_target_type_matches(unsigned long address, const struct hdn_rap_type *expected)
{
	const struct hdn_rap_target *actual;
	const struct hdn_rap_type *type;
	unsigned long flags = native_local_irq_save();
	bool valid = false;

	expected = type_view(expected);
	actual = record(address, false);
	if (expected && actual && (type = type_view(actual->type)))
		valid = same_type(expected, type);
	native_local_irq_restore(flags);
	return valid;
}

unsigned long noinstr hdn_rap_bpf_dispatch_target(unsigned long target)
{
	extern const struct hdn_rap_type __hdn_rap_type_provider_bpf_program;

	return hdn_rap_validate(target, &__hdn_rap_type_provider_bpf_program);
}

bool noinstr hdn_rap_return_site(unsigned long address)
{
	unsigned long flags = native_local_irq_save();
	bool valid = record(address, true) != NULL;

	native_local_irq_restore(flags);
	return valid;
}

static noinstr const struct hdn_rap_static_call *static_contract(unsigned long address)
{
	const struct hdn_rap_static_call *entry, *end;
	const struct hdn_rap_module *view;

	if (inside(address, 1, (unsigned long)_stext, _etext - _stext)) {
		for (entry = __hdn_rap_static_calls_start; entry < __hdn_rap_static_calls_end; entry++)
			if (entry->address == address)
				return entry;
		return NULL;
	}
	for (view = READ_ONCE(hdn_rap_modules); view; view = READ_ONCE(view->next)) {
		if (!inside(address, 8, view->text, view->text_size))
			continue;
		entry = view->static_calls.data;
		end = (const void *)entry + view->static_calls.size;
		for (; entry < end; entry++)
			if (entry->address == address)
				return entry;
		return NULL;
	}
	return NULL;
}

static noinstr unsigned long static_site_trampoline(unsigned long return_site)
{
	const struct hdn_rap_static_site *entry, *end;
	const struct hdn_rap_module *view;

	if (inside(return_site, 1, (unsigned long)_stext, _etext - _stext) ||
	    (READ_ONCE(hdn_rap_builtin_init_live) &&
	     inside(return_site, 1, (unsigned long)_sinittext, _einittext - _sinittext))) {
		for (entry = __hdn_rap_static_sites_start; entry < __hdn_rap_static_sites_end; entry++)
			if (entry->return_site == return_site)
				return entry->trampoline;
		return 0;
	}
	for (view = READ_ONCE(hdn_rap_modules); view; view = READ_ONCE(view->next)) {
		if (!inside(return_site, 1, view->text, view->text_size) &&
		    !(READ_ONCE(view->init_live) && inside(return_site, 1, view->init_text, view->init_size)))
			continue;
		entry = view->static_sites.data;
		end = (const void *)entry + view->static_sites.size;
		for (; entry < end; entry++)
			if (entry->return_site == return_site)
				return entry->trampoline;
		return 0;
	}
	return 0;
}

static const struct hdn_rap_function *noinstr function_record(unsigned long address,
		unsigned int which);

static noinstr bool static_target(const struct hdn_rap_static_call *contract,
		unsigned long address)
{
	const struct hdn_rap_target *actual;
	const struct hdn_rap_function *function;
	const struct hdn_rap_type *expected, *type;

	if (!contract || contract->flags > 1 || !(expected = type_view(contract->type)))
		return false;
	if (!address)
		return true;
	actual = record(address, false);
	if (actual)
		type = type_view(actual->type);
	else {
		/* A static call remains a direct branch after patching. Admit an
		 * exact protected function entry even when __noendbr deliberately
		 * excludes it from the general indirect-call target set. */
		function = function_record(address, 0);
		type = function ? type_view(function->type) : NULL;
	}
	if (!type)
		return false;
	if (address == (unsigned long)__static_call_return0)
		return contract->flags == 1;
	return same_type(expected, type);
}

/* Check the immutable key/trampoline association before publishing key->func.
 * Code owners retain their usual module/callback lifetime references. */
void noinstr hdn_rap_static_update(unsigned long key, unsigned long trampoline,
		unsigned long target)
{
	unsigned long flags = native_local_irq_save();
	const struct hdn_rap_static_call *contract = static_contract(trampoline);
	bool valid = key && contract && contract->key == key && static_target(contract, target);

	native_local_irq_restore(flags);
	if (!valid)
		__hdn_rap_fail(HDN_RAP_FAIL_TARGET);
}
EXPORT_SYMBOL_GPL(hdn_rap_static_update);

/* Site admission uses a separate immutable map, never the mutable upstream
 * key/site arrays. Ordinary RAP compilation eliminates sibling-call sites. */
void noinstr hdn_rap_static_transform(unsigned long site, unsigned long trampoline,
		unsigned long target, bool tail)
{
	unsigned long flags = native_local_irq_save(), owner = trampoline;
	bool valid;

	if (site) {
		owner = static_site_trampoline(site + 5);
		if (trampoline && owner != trampoline)
			owner = 0;
	}
	valid = !tail && owner && static_target(static_contract(owner), target);
	native_local_irq_restore(flags);
	if (!valid)
		__hdn_rap_fail(HDN_RAP_FAIL_TARGET);
}

static const struct hdn_rap_function *noinstr function_record(unsigned long address,
		unsigned int which)
{
	const struct hdn_rap_function *entry, *end;
	const struct hdn_rap_module *view;
	const struct hdn_rap_bpf_image *bpf;

	if (inside(address, 1, (unsigned long)_stext, _etext - _stext) ||
	    (READ_ONCE(hdn_rap_builtin_init_live) &&
	     inside(address, 1, (unsigned long)_sinittext, _einittext - _sinittext))) {
		entry = __hdn_rap_entries_start;
		end = __hdn_rap_entries_end;
		for (; entry < end; entry++)
			if ((which == 2 ? entry->body : which == 1 ? entry->trace_return : entry->address) == address)
				return entry;
		return NULL;
	}
	for (view = READ_ONCE(hdn_rap_modules); view; view = READ_ONCE(view->next)) {
		if (!inside(address, 1, view->text, view->text_size) &&
		    !(READ_ONCE(view->init_live) && inside(address, 1, view->init_text, view->init_size)))
			continue;
		entry = view->functions.data;
		end = (const void *)entry + view->functions.size;
		for (; entry < end; entry++)
			if ((which == 2 ? entry->body : which == 1 ? entry->trace_return : entry->address) == address)
				return entry;
		return NULL;
	}
	bpf = hdn_rap_bpf_find(address);
	if (bpf && !bpf->exception && (!bpf->trampoline || bpf->target.address) &&
	    (which == 2 ? bpf->function.body : which == 1 ? bpf->function.trace_return : bpf->function.address) == address)
		return &bpf->function;
	return NULL;
}

bool noinstr hdn_rap_function_entry(unsigned long address)
{
	unsigned long flags = native_local_irq_save();
	bool valid = function_record(address, 0) != NULL;

	native_local_irq_restore(flags);
	return valid;
}

/* Only the first body instruction, after the complete protected prologue,
 * is a function-entry probe. Interior instructions cannot acquire permission
 * to abandon locals and return merely by sharing an injectable symbol. */
unsigned long noinstr hdn_rap_probe_entry(unsigned long address)
{
	unsigned long flags = native_local_irq_save(), entry = 0;
	const struct hdn_rap_function *function = function_record(address, 2);

	if (function)
		entry = function->address;
	native_local_irq_restore(flags);
	return entry;
}

int noinstr hdn_rap_function_copy(unsigned long address, struct hdn_rap_function *function,
		struct hdn_rap_type *type, size_t capacity)
{
	const struct hdn_rap_function *entry;
	const struct hdn_rap_type *source;
	unsigned long flags = native_local_irq_save();
	size_t size, i;
	int result = -ENOEXEC;

	entry = function_record(address, 0);
	if (!entry || !(source = type_view(entry->type)))
		goto out;
	size = sizeof(*source) + source->length + 1;
	if (capacity < size || !IS_ALIGNED((unsigned long)type, 8))
		goto out;
	for (i = 0; i < size; i++)
		WRITE_ONCE(((u8 *)type)[i], READ_ONCE(((const u8 *)source)[i]));
	function->address = entry->address;
	function->body = entry->body;
	function->trace_return = entry->trace_return;
	function->type = type;
	result = size;
out:
	native_local_irq_restore(flags);
	return result;
}

bool noinstr hdn_rap_trace_compatible(unsigned long resume, const struct hdn_rap_type *expected)
{
	const struct hdn_rap_function *function = function_record(resume, 1);
	const struct hdn_rap_type *actual;

	if (!function)
		function = function_record(resume, 2);
	expected = type_view(expected);
	return resume && expected && function && (actual = type_view(function->type)) &&
		same_type(expected, actual);
}

bool noinstr hdn_rap_ftrace_patch(unsigned long site, unsigned long target)
{
	bool result = false;
#ifdef CONFIG_DYNAMIC_FTRACE
	unsigned long flags = native_local_irq_save();
	const struct hdn_rap_function *function = function_record(site + 5, 1);
	const struct hdn_rap_image *image;
	bool callback = site == (unsigned long)ftrace_call || site == (unsigned long)ftrace_regs_call;

	for (image = READ_ONCE(hdn_rap_images); image; image = READ_ONCE(image->next)) {
		if (site == image->callback_site)
			callback = true;
		if (function && target == image->address)
			result = true;
	}
	if (callback)
		result = !ftrace_is_jmp(target) &&
			hdn_rap_target_matches(target, (unsigned long)ftrace_stub);
	else if (function) {
		if (target == MCOUNT_ADDR || target == (unsigned long)ftrace_caller ||
		    target == (unsigned long)ftrace_regs_caller)
			result = true;
		else if (!result) {
			unsigned long address = ftrace_is_jmp(target) ? ftrace_jmp_get(target) : target;

			result = !hdn_rap_bpf_text_patch(site,
				ftrace_is_jmp(target) ? BPF_MOD_JUMP : BPF_MOD_CALL, &address) &&
				address == (target & ~1UL);
		}
	}
	native_local_irq_restore(flags);
#endif
	return result;
}

unsigned long noinstr hdn_rap_bpf_patch_address(unsigned long address)
{
	unsigned long flags = native_local_irq_save(), result = 0;
	const struct hdn_rap_function *function = function_record(address, 0);
	const struct hdn_rap_bpf_image *image;

	if (function && function->trace_return)
		result = function->trace_return - 5;
	else {
		image = hdn_rap_bpf_find(address);
		if (image && image->trampoline && image->after_call == address)
			result = address;
	}
	native_local_irq_restore(flags);
	return result;
}

bool noinstr hdn_rap_bpf_unlink_check(unsigned long address, unsigned long link,
		unsigned long start, unsigned long end)
{
	unsigned long flags = native_local_irq_save();
	const struct hdn_rap_bpf_image *image = hdn_rap_bpf_find(address);
	const struct hdn_rap_bpf_unlink *slots;
	bool found = false;
	size_t i;

	if (!image || !image->trampoline || image->address != address)
		goto out;
	slots = image->unlink.data;
	for (i = 0; i < image->unlink.size / sizeof(*slots); i++)
		if (slots[i].link == link && slots[i].start == start && slots[i].end == end) {
			found = true;
			break;
		}
out:
	native_local_irq_restore(flags);
	return found;
}

int noinstr hdn_rap_bpf_text_patch(unsigned long site, int kind, unsigned long *target)
{
	unsigned long flags = native_local_irq_save();
	const struct hdn_rap_function *function = function_record(site + 5, 1);
	const struct hdn_rap_bpf_image *image, *source;
	const struct hdn_rap_type *a, *b;
	int error = -EINVAL;

	if (kind != BPF_MOD_NOP && kind != BPF_MOD_CALL && kind != BPF_MOD_JUMP)
		goto out;
	if (kind == BPF_MOD_NOP && *target)
		goto out;
	if (function) {
		if (!*target) {
			error = 0;
			goto out;
		}
		image = hdn_rap_bpf_find(*target);
		if (!image || image->address != *target)
			goto out;
		if (image->trampoline) {
			if (image->reference.address == function->address &&
			    !(image->tramp_flags & BPF_TRAMP_F_INDIRECT) &&
			    ((kind == BPF_MOD_JUMP) == bpf_trampoline_use_jmp(image->tramp_flags)))
				error = 0;
		} else if (kind == BPF_MOD_JUMP && !image->exception) {
			source = hdn_rap_bpf_find(function->address);
			if (source && !source->trampoline &&
			    image->reference.address == function->address &&
			    (a = type_view(function->type)) && (b = type_view(image->function.type)) &&
			    same_type(a, b)) {
				/* freplace reuses the intercepted program's return record. */
				*target = image->function.body;
				error = 0;
			}
		}
	} else {
		image = hdn_rap_bpf_find(site);
		if (image && image->trampoline && image->after_call == site &&
		    ((!*target && kind == BPF_MOD_NOP) ||
		     (kind == BPF_MOD_JUMP && *target == image->epilogue)))
			error = 0;
	}
out:
	native_local_irq_restore(flags);
	return error;
}

unsigned long noinstr hdn_rap_bpf_original_target(unsigned long site, unsigned long resume)
{
	const struct hdn_rap_bpf_image *image = hdn_rap_bpf_find(site);

	if (!image || !image->trampoline || image->original != site)
		__hdn_rap_fail(HDN_RAP_FAIL_TARGET);
	if (!resume)
		resume = image->reference.trace_return;
	if (!hdn_rap_trace_compatible(resume, image->reference.type))
		__hdn_rap_fail(HDN_RAP_FAIL_TARGET);
	return resume;
}

/* The intercepted function already owns the protected caller record. A typed
 * replacement resumes after its own RAP entry so it reuses that record rather
 * than pushing a second record for the same slot. This permission is local to
 * tracing; direct-only functions are not added to the indirect-call set. */
bool noinstr hdn_rap_livepatch_match(unsigned long original, unsigned long replacement)
{
	const struct hdn_rap_function *source, *destination;
	const struct hdn_rap_type *a, *b;
	unsigned long flags = native_local_irq_save();
	bool valid = false;

	source = function_record(original, false);
	destination = function_record(replacement, false);
	if (source && source->trace_return && destination &&
	    (a = type_view(source->type)) && (b = type_view(destination->type)))
		valid = same_type(a, b);
	native_local_irq_restore(flags);
	return valid;
}

unsigned long noinstr hdn_rap_trace_redirect(unsigned long resume, unsigned long requested)
{
	const struct hdn_rap_function *source, *destination;
	const struct hdn_rap_type *old_type, *new_type;
	unsigned long flags, result = 0;

	if (resume == requested)
		return resume;
	flags = native_local_irq_save();
	source = function_record(resume, true);
	destination = function_record(requested, false);
	if (source && destination &&
	    (old_type = type_view(source->type)) && (new_type = type_view(destination->type)) &&
	    same_type(old_type, new_type))
		result = destination->body;
	native_local_irq_restore(flags);
	if (!result)
		__hdn_rap_fail(HDN_RAP_FAIL_TARGET);
	return result;
}

unsigned long noinstr hdn_rap_validate_call(unsigned long address, unsigned long expected_return)
{
	const struct hdn_rap_target *site, *actual;
	const struct hdn_rap_type *expected, *type;
	unsigned long flags = native_local_irq_save(), result = 0;

	/* Registry retirement drains IRQ-disabled checks, including entry before
	 * RCU watching. The caller still holds its code owner's normal lifetime
	 * reference across the subsequent transfer. */
	site = record(expected_return, true);
	if (site && site->type && (expected = type_view(site->type))) {
		actual = record(address, false);
		if (actual && (!noinstr_address(expected_return) ||
			       noinstr_address(actual->address)) &&
		    (type = type_view(actual->type)) && same_type(type, expected))
			result = actual->address;
	}
	native_local_irq_restore(flags);
	if (unlikely(!result))
		__hdn_rap_fail(HDN_RAP_FAIL_TARGET);
	return result;
}

unsigned long noinstr hdn_rap_validate(unsigned long address, const struct hdn_rap_type *expected)
{
	const struct hdn_rap_target *actual;
	const struct hdn_rap_type *type;
	unsigned long flags = native_local_irq_save(), result = 0;

	expected = type_view(expected);
	if (expected) {
		actual = record(address, false);
		if (actual && (type = type_view(actual->type)) && same_type(type, expected))
			result = actual->address;
	}
	native_local_irq_restore(flags);
	if (unlikely(!result))
		__hdn_rap_fail(HDN_RAP_FAIL_TARGET);
	return result;
}
