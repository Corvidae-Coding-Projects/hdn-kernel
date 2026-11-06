// SPDX-License-Identifier: GPL-2.0-only
/* Compiler identities are public, immutable evidence, never secret tokens. */
#include <crypto/sha2.h>
#include <linux/hdn_execmem.h>
#include <linux/hdn_rap.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/preempt.h>
#include <linux/sort.h>
#include <linux/static_call_types.h>
#include <linux/vmalloc.h>
#include <asm/sections.h>

#include <linux/hdn_pgtable.h>
#include <linux/rcupdate.h>
#include "hdn_rap_internal.h"
#include "../mm/hdn_pgtable_internal.h"

struct hdn_rap_module *hdn_rap_modules __ro_after_init;
unsigned long hdn_rap_builtin_init_live __ro_after_init = 1;
static DEFINE_RAW_SPINLOCK(rap_modules_lock);

static bool range_inside(const void *pointer, size_t size, struct hdn_rap_section section)
{
	unsigned long base = (unsigned long)section.data, start = (unsigned long)pointer;

	return start >= base && size <= section.size && start - base <= section.size - size;
}

static bool valid_type(const struct hdn_rap_type *type, struct hdn_rap_section types)
{
	if (!IS_ALIGNED((unsigned long)type, 8) || !range_inside(type, sizeof(*type), types) ||
	    type->version != HDN_RAP_VERSION || !type->length || type->length > HDN_RAP_TYPE_MAX ||
	    !range_inside(type, sizeof(*type) + type->length + 1, types))
		return false;
	return !type->canonical[type->length] &&
		strnlen(type->canonical, type->length) == type->length;
}

static bool valid_build(const struct hdn_rap_build *record)
{
	size_t length = strnlen(record->compiler, sizeof(record->compiler)), i;

	if (record->version != HDN_RAP_VERSION || record->abi != HDN_RAP_ABI ||
	    record->identity[64] || !length || length == sizeof(record->compiler))
		return false;
	for (i = 0; i < 64; i++)
		if (!((record->identity[i] >= '0' && record->identity[i] <= '9') ||
		      (record->identity[i] >= 'a' && record->identity[i] <= 'f')))
			return false;
	for (i = length + 1; i < sizeof(record->compiler); i++)
		if (record->compiler[i])
			return false;
	for (i = 0; i < sizeof(record->padding); i++)
		if (record->padding[i])
			return false;
	return true;
}

int hdn_rap_check_build(struct hdn_rap_section build)
{
	const struct hdn_rap_build *records = build.data;
	size_t i;

	BUILD_BUG_ON(sizeof(*records) != 208);
	if (!build.size || build.size % sizeof(*records) || build.size > HDN_RAP_METADATA_MAX ||
	    !IS_ALIGNED((unsigned long)records, 8) ||
	    &__hdn_rap_build_start[0] == &__hdn_rap_build_end[0] ||
	    !valid_build(__hdn_rap_build_start))
		return -ENOEXEC;
	for (i = 0; i < build.size / sizeof(*records); i++)
		if (memcmp(&records[i], __hdn_rap_build_start, sizeof(*records)))
			return -ENOEXEC;
	return 0;
}

const char *hdn_rap_build_identity(void)
{
	return __hdn_rap_build_start->identity;
}

static int validate_types(struct hdn_rap_section types)
{
	const char domain[] = "HDN-RAP-TYPE-v1;build=";
	const char suffix[] = ";type=";
	size_t offset = 0;

	if (!types.size || types.size > HDN_RAP_METADATA_MAX ||
	    !IS_ALIGNED((unsigned long)types.data, 8))
		return -ENOEXEC;
	while (offset < types.size) {
		const struct hdn_rap_type *type = types.data + offset;
		struct sha256_ctx ctx;
		u8 digest[32];
		size_t end, next;

		if (!valid_type(type, types))
			return -ENOEXEC;
		sha256_init(&ctx);
		sha256_update(&ctx, domain, sizeof(domain) - 1);
		sha256_update(&ctx, __hdn_rap_build_start->identity, 64);
		sha256_update(&ctx, suffix, sizeof(suffix) - 1);
		sha256_update(&ctx, type->canonical, type->length);
		sha256_final(&ctx, digest);
		if (memcmp(digest, type->digest, sizeof(digest)))
			return -ENOEXEC;
		end = offset + sizeof(*type) + type->length + 1;
		next = min(ALIGN(end, 8), types.size);
		for (; end < next; end++)
			if (((const u8 *)types.data)[end])
				return -ENOEXEC;
		offset = next;
	}
	return 0;
}

static int target_compare(const void *left, const void *right)
{
	const struct hdn_rap_target *a = left, *b = right;

	return (a->address > b->address) - (a->address < b->address);
}

static int function_compare(const void *left, const void *right)
{
	const struct hdn_rap_function *a = left, *b = right;

	return (a->address > b->address) - (a->address < b->address);
}

static int static_contract_compare(const void *left, const void *right)
{
	const struct hdn_rap_static_call *a = left, *b = right;

	return (a->address > b->address) - (a->address < b->address);
}

static int static_site_compare(const void *left, const void *right)
{
	const struct hdn_rap_static_site *a = left, *b = right;

	return (a->return_site > b->return_site) - (a->return_site < b->return_site);
}

static bool empty_function(const struct hdn_rap_function *entry)
{
	return !entry->address && !entry->type && !entry->body && !entry->trace_return;
}

static bool valid_function(const struct hdn_rap_function *entry,
		struct hdn_rap_section types)
{
	if (!valid_type(entry->type, types) || !entry->address || entry->body < entry->address ||
	    (entry->body - entry->address != 12 && entry->body - entry->address != 16))
		return false;
	return !entry->trace_return ||
		(entry->trace_return > entry->body && entry->trace_return - entry->body == 12);
}

static bool same_type(const struct hdn_rap_type *a, const struct hdn_rap_type *b)
{
	/* Full canonical comparison closes even a deliberately chosen hash collision. */
	return a->length == b->length && !memcmp(a->digest, b->digest, sizeof(a->digest)) &&
		!memcmp(a->canonical, b->canonical, a->length);
}

static void module_store(struct hdn_rap_module *view, unsigned long *slot, unsigned long value)
{
	unsigned long base = (unsigned long)view, address = (unsigned long)slot;

	BUILD_BUG_ON(sizeof(*view) > PAGE_SIZE);
	if (!IS_ALIGNED(address, sizeof(long)) || address < base ||
	    address - base > sizeof(*view) - sizeof(long))
		panic("HDN RAP invalid module registry update");
	hdn_pt_window_update(view->header_pfn, offset_in_page(address), value, 0, HDN_PT_STORE);
}

static void module_head_store(struct hdn_rap_module *view)
{
	hdn_pt_window_update(__pa_symbol(&hdn_rap_modules) >> PAGE_SHIFT,
		offset_in_page(&hdn_rap_modules), (unsigned long)view, 0, HDN_PT_STORE);
}

int hdn_rap_module_prepare(struct module *mod, struct hdn_rap_section targets,
		struct hdn_rap_section types, struct hdn_rap_section sites,
		struct hdn_rap_section functions, struct hdn_rap_section static_calls,
		struct hdn_rap_section static_sites)
{
	const struct hdn_rap_target *entries = targets.data;
	const struct hdn_rap_target *site_entries = sites.data;
	const struct hdn_rap_function *function_entries = functions.data;
	const struct hdn_rap_static_call *contracts = static_calls.data;
	const struct hdn_rap_static_site *patch_sites = static_sites.data;
	struct hdn_rap_static_call *contract_copies;
	struct hdn_rap_static_site *patch_site_copies;
	struct hdn_rap_function *function_copies;
	struct hdn_rap_module *view;
	size_t count, site_count, size, records_size, functions_offset, function_count, i;
	size_t contracts_offset, patch_sites_offset, contract_count, patch_site_count;
	unsigned long flags;
	int error;

	if (!hdn_pt_active())
		return -EOPNOTSUPP;
	if (!targets.size || targets.size % sizeof(*entries) ||
	    targets.size > HDN_RAP_METADATA_MAX || !IS_ALIGNED((unsigned long)entries, 8))
		return -ENOEXEC;
	if (!sites.size || sites.size % sizeof(*entries) ||
	    sites.size > HDN_RAP_METADATA_MAX || !IS_ALIGNED((unsigned long)sites.data, 8))
		return -ENOEXEC;
	if (!functions.size || functions.size % sizeof(*function_entries) ||
	    functions.size > HDN_RAP_METADATA_MAX || !IS_ALIGNED((unsigned long)functions.data, 8))
		return -ENOEXEC;
	if (!static_calls.size || static_calls.size % sizeof(*contracts) ||
	    static_calls.size > HDN_RAP_METADATA_MAX || !IS_ALIGNED((unsigned long)contracts, 8) ||
	    !static_sites.size || static_sites.size % sizeof(*patch_sites) ||
	    static_sites.size > HDN_RAP_METADATA_MAX || !IS_ALIGNED((unsigned long)patch_sites, 8))
		return -ENOEXEC;
	error = validate_types(types);
	if (error)
		return error;
	count = targets.size / sizeof(*entries);
	site_count = sites.size / sizeof(*entries);
	function_count = functions.size / sizeof(*function_entries);
	contract_count = static_calls.size / sizeof(*contracts);
	patch_site_count = static_sites.size / sizeof(*patch_sites);
	for (i = 0; i < contract_count; i++) {
		const struct hdn_rap_static_call *entry = &contracts[i];

		if (!entry->address && !entry->key && !entry->type && !entry->flags)
			continue;
		if (!valid_type(entry->type, types) || entry->flags > 1 ||
		    !within_module_mem_type(entry->address, mod, MOD_TEXT) ||
		    !within_module_mem_type(entry->address + 7, mod, MOD_TEXT) ||
		    !IS_ALIGNED(entry->key, sizeof(long)) ||
		    !within_module_mem_type(entry->key, mod, MOD_DATA) ||
		    !within_module_mem_type(entry->key + sizeof(struct static_call_key) - 1, mod, MOD_DATA))
			return -ENOEXEC;
	}
	for (i = 0; i < patch_site_count; i++) {
		const struct hdn_rap_static_site *entry = &patch_sites[i];

		if (!entry->return_site && !entry->trampoline)
			continue;
		if (!entry->trampoline || entry->return_site < 5 ||
		    !((within_module_mem_type(entry->return_site, mod, MOD_TEXT) &&
		       within_module_mem_type(entry->return_site - 5, mod, MOD_TEXT)) ||
		      (within_module_mem_type(entry->return_site, mod, MOD_INIT_TEXT) &&
		       within_module_mem_type(entry->return_site - 5, mod, MOD_INIT_TEXT))))
			return -ENOEXEC;
	}
	for (i = 0; i < count; i++) {
		if (!valid_type(entries[i].type, types) ||
		    (!within_module_mem_type(entries[i].address, mod, MOD_TEXT) &&
		     !within_module_mem_type(entries[i].address, mod, MOD_INIT_TEXT)))
			return -ENOEXEC;
	}
	for (i = 0; i < site_count; i++) {
		if (!site_entries[i].address && !site_entries[i].type)
			continue; /* Empty translation units still carry a section marker. */
		if ((site_entries[i].type && !valid_type(site_entries[i].type, types)) ||
		    (!within_module_mem_type(site_entries[i].address, mod, MOD_TEXT) &&
		     !within_module_mem_type(site_entries[i].address, mod, MOD_INIT_TEXT)))
			return -ENOEXEC;
	}
	for (i = 0; i < function_count; i++) {
		const struct hdn_rap_function *entry = &function_entries[i];
		unsigned long last = entry->trace_return ?: entry->body;

		if (empty_function(entry))
			continue;
		if (!valid_function(entry, types) ||
		    !((within_module_mem_type(entry->address, mod, MOD_TEXT) &&
		       within_module_mem_type(last, mod, MOD_TEXT)) ||
		      (within_module_mem_type(entry->address, mod, MOD_INIT_TEXT) &&
		       within_module_mem_type(last, mod, MOD_INIT_TEXT))))
			return -ENOEXEC;
	}
	records_size = struct_size(view, targets, count + site_count);
	if (check_add_overflow(records_size, types.size, &size) ||
	    check_add_overflow(size, (size_t)7, &functions_offset))
		return -EOVERFLOW;
	functions_offset &= ~7UL;
	if (check_add_overflow(functions_offset, functions.size, &contracts_offset) ||
	    check_add_overflow(contracts_offset, static_calls.size, &patch_sites_offset) ||
	    check_add_overflow(patch_sites_offset, static_sites.size, &size))
		return -EOVERFLOW;
	view = __vmalloc_node_range(PAGE_ALIGN(size), PAGE_SIZE, VMALLOC_START, VMALLOC_END,
		GFP_KERNEL | __GFP_ZERO, PAGE_KERNEL, VM_FLUSH_RESET_PERMS,
		NUMA_NO_NODE, __builtin_return_address(0));
	if (!view)
		return -ENOMEM;
	error = hdn_execmem_claim_rap(view, mod, size);
	if (error) {
		vfree(view);
		return error;
	}
	view->owner = mod;
	view->header_pfn = vmalloc_to_pfn(view);
	view->text = (unsigned long)mod->mem[MOD_TEXT].base;
	view->text_size = mod->mem[MOD_TEXT].size;
	view->init_text = (unsigned long)mod->mem[MOD_INIT_TEXT].base;
	view->init_size = mod->mem[MOD_INIT_TEXT].size;
	view->init_live = 1;
	view->original_types = types;
	view->types = (struct hdn_rap_section) { (void *)view + records_size, types.size };
	view->functions = (struct hdn_rap_section) { (void *)view + functions_offset, functions.size };
	view->static_calls = (struct hdn_rap_section) { (void *)view + contracts_offset, static_calls.size };
	view->static_sites = (struct hdn_rap_section) { (void *)view + patch_sites_offset, static_sites.size };
	view->count = count;
	view->site_count = site_count;
	memcpy((void *)view->types.data, types.data, types.size);
	memcpy(view->targets, entries, targets.size);
	memcpy(view->targets + count, site_entries, sites.size);
	function_copies = (void *)view->functions.data;
	memcpy(function_copies, function_entries, functions.size);
	contract_copies = (void *)view->static_calls.data;
	memcpy(contract_copies, contracts, static_calls.size);
	patch_site_copies = (void *)view->static_sites.data;
	memcpy(patch_site_copies, patch_sites, static_sites.size);
	for (i = 0; i < contract_count; i++)
		if (contract_copies[i].type)
			contract_copies[i].type = view->types.data +
				((const void *)contract_copies[i].type - types.data);
	sort(contract_copies, contract_count, sizeof(*contract_copies), static_contract_compare, NULL);
	sort(patch_site_copies, patch_site_count, sizeof(*patch_site_copies), static_site_compare, NULL);
	for (i = 1; i < contract_count; i++)
		if (contract_copies[i].address && contract_copies[i - 1].address == contract_copies[i].address) {
			error = -ENOEXEC;
			goto discard;
		}
	for (i = 1; i < patch_site_count; i++)
		if (patch_site_copies[i].return_site &&
		    patch_site_copies[i - 1].return_site == patch_site_copies[i].return_site) {
			error = -ENOEXEC;
			goto discard;
		}
	for (i = 0; i < function_count; i++)
		if (function_copies[i].type)
			function_copies[i].type = view->types.data +
				((const void *)function_copies[i].type - types.data);
	sort(function_copies, function_count, sizeof(*function_copies), function_compare, NULL);
	for (i = 1; i < function_count; i++)
		if (function_copies[i].address && function_copies[i - 1].address == function_copies[i].address &&
		    (function_copies[i - 1].body != function_copies[i].body ||
		     function_copies[i - 1].trace_return != function_copies[i].trace_return ||
		     !same_type(function_copies[i - 1].type, function_copies[i].type))) {
			error = -ENOEXEC;
			goto discard;
		}
	for (i = 0; i < count + site_count; i++)
		if (view->targets[i].type)
			view->targets[i].type = view->types.data +
				((const void *)view->targets[i].type - types.data);
	sort(view->targets, count, sizeof(*entries), target_compare, NULL);
	sort(view->targets + count, site_count, sizeof(*entries), target_compare, NULL);
	for (i = 1; i < count; i++)
		if (view->targets[i - 1].address == view->targets[i].address &&
		    !same_type(view->targets[i - 1].type, view->targets[i].type)) {
			error = -ENOEXEC;
			goto discard;
		}
	for (i = count + 1; i < count + site_count; i++)
		if (view->targets[i].address && view->targets[i - 1].address == view->targets[i].address) {
			error = -ENOEXEC;
			goto discard;
		}
	error = hdn_execmem_seal_data(view);
	if (error)
		goto discard;
	/* Publish only sealed copies. The fast path never follows the mutable
	 * module structure, allocation registry or ordinary module lookup code. */
	raw_spin_lock_irqsave(&rap_modules_lock, flags);
	module_store(view, (unsigned long *)&view->next, (unsigned long)hdn_rap_modules);
	smp_wmb();
	module_head_store(view);
	WRITE_ONCE(mod->hdn_rap, view);
	raw_spin_unlock_irqrestore(&rap_modules_lock, flags);
	return 0;
discard:
	if (!hdn_execmem_free(view))
		panic("HDN RAP metadata retirement failed");
	return error;
}

void hdn_rap_module_release(struct module *mod)
{
	struct hdn_rap_module *view, *previous = NULL;
	unsigned long flags;

	raw_spin_lock_irqsave(&rap_modules_lock, flags);
	for (view = hdn_rap_modules; view; previous = view, view = view->next)
		if (view->owner == mod)
			break;
	if (view != READ_ONCE(mod->hdn_rap))
		panic("HDN RAP metadata lifetime mismatch");
	if (view) {
		if (!hdn_execmem_rap_valid(view, mod))
			panic("HDN RAP invalid module registry owner");
		if (previous)
			module_store(previous, (unsigned long *)&previous->next, (unsigned long)view->next);
		else
			module_head_store(view->next);
		WRITE_ONCE(mod->hdn_rap, NULL);
	}
	raw_spin_unlock_irqrestore(&rap_modules_lock, flags);
	if (view) {
		/* Drain entry-time readers even before RCU watching is restored. */
		hdn_rap_registry_synchronize();
		if (!hdn_execmem_free(view))
			panic("HDN RAP module registry retirement failed");
	}
}

void hdn_rap_module_init_retire(struct module *mod)
{
	struct hdn_rap_module *view;
	unsigned long flags;

	raw_spin_lock_irqsave(&rap_modules_lock, flags);
	for (view = hdn_rap_modules; view && view->owner != mod; view = view->next)
		;
	if (!view || view != READ_ONCE(mod->hdn_rap) || !view->init_live)
		panic("HDN RAP invalid module init retirement");
	module_store(view, &view->init_live, 0);
	raw_spin_unlock_irqrestore(&rap_modules_lock, flags);
	/* The loader queues init storage behind its existing RCU grace period. */
}

void hdn_rap_builtin_init_retire(void)
{
	hdn_pt_window_update(__pa_symbol(&hdn_rap_builtin_init_live) >> PAGE_SHIFT,
		offset_in_page(&hdn_rap_builtin_init_live), 0, 0, HDN_PT_STORE);
}

static int __init hdn_rap_metadata_init(void)
{
	struct hdn_rap_section build = { __hdn_rap_build_start,
		(const char *)__hdn_rap_build_end - (const char *)__hdn_rap_build_start };
	struct hdn_rap_section types = { __hdn_rap_types_start,
		__hdn_rap_types_end - __hdn_rap_types_start };
	const struct hdn_rap_target *entry;
	const struct hdn_rap_function *function;

	if (hdn_rap_check_build(build) || validate_types(types))
		panic("HDN RAP built-in metadata mismatch");
	for (entry = __hdn_rap_targets_start; entry < __hdn_rap_targets_end; entry++)
		if (!valid_type(entry->type, types))
			panic("HDN RAP invalid built-in target metadata");
	for (function = __hdn_rap_entries_start; function < __hdn_rap_entries_end; function++)
		if (!empty_function(function) && !valid_function(function, types))
			panic("HDN RAP invalid built-in function metadata");
	return 0;
}
early_initcall(hdn_rap_metadata_init);
