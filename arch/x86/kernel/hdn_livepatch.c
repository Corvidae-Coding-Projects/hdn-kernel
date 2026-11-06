// SPDX-License-Identifier: GPL-2.0-only
/* Delayed relocations are a frozen program, not an arbitrary write interface. */
#include <linux/hdn_livepatch.h>
#ifdef CONFIG_LIVEPATCH
#include <linux/hdn_execmem.h>
#include <linux/hdn_pgtable.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/vmalloc.h>
#include <linux/kallsyms.h>
#include <asm/text-patching.h>
#include "../mm/hdn_pgtable_internal.h"

#define HDN_KLP_MAX (16U << 20)

struct hdn_klp_reloc {
	unsigned long address, position, type, size, text;
	long addend;
	/* Only this journal changes, through the private window under klp_lock. */
	unsigned long active, value;
	char object[MODULE_NAME_LEN], source[MODULE_NAME_LEN], name[KSYM_NAME_LEN];
};

struct hdn_klp_plan {
	struct hdn_klp_plan *next;
	const struct module *owner;
	size_t count;
	struct hdn_klp_reloc reloc[];
};

struct hdn_klp_symbols {
	struct hdn_klp_symbols *next;
	const struct module *owner;
	unsigned long live, count;
	char name[MODULE_NAME_LEN];
	const char *strings;
	Elf_Sym symbols[];
};

static struct hdn_klp_plan *klp_plans __ro_after_init;
static struct hdn_klp_symbols *klp_symbols __ro_after_init;
static DEFINE_MUTEX(klp_lock);

static void klp_store(unsigned long *slot, unsigned long value)
{
	unsigned long pfn = is_vmalloc_or_module_addr(slot) ?
		vmalloc_to_pfn(slot) : __pa_symbol(slot) >> PAGE_SHIFT;

	hdn_pt_window_update(pfn, offset_in_page(slot), value, 0, HDN_PT_STORE);
}

static void *klp_alloc(size_t size)
{
	void *p;

	if (!size || size > HDN_KLP_MAX)
		return NULL;
	p = __vmalloc_node_range(PAGE_ALIGN(size), PAGE_SIZE, VMALLOC_START,
		VMALLOC_END, GFP_KERNEL | __GFP_ZERO, PAGE_KERNEL,
		VM_FLUSH_RESET_PERMS, NUMA_NO_NODE, __builtin_return_address(0));
	if (p && hdn_execmem_claim_data(p)) {
		vfree(p);
		return NULL;
	}
	return p;
}

static int reloc_compare(const void *left, const void *right)
{
	const struct hdn_klp_reloc *a = left, *b = right;

	return (a->address > b->address) - (a->address < b->address);
}

static size_t reloc_size(unsigned long type)
{
	switch (type) {
	case R_X86_64_NONE: return 0;
	case R_X86_64_64: case R_X86_64_PC64: return 8;
	case R_X86_64_32: case R_X86_64_32S:
	case R_X86_64_PC32: case R_X86_64_PLT32: return 4;
	default: return SIZE_MAX;
	}
}

static bool section_family(const char *name, const char *family)
{
	size_t size = strlen(family);

	return !strncmp(name, family, size) && (!name[size] || name[size] == '.');
}

static const char *table_string(const char *table, size_t size, size_t offset)
{
	if (offset >= size || !memchr(table + offset, 0, size - offset))
		return NULL;
	return table + offset;
}

int hdn_klp_symbols_prepare(struct module *mod, size_t strtab_size)
{
	const struct mod_kallsyms *source = &mod->core_kallsyms;
	struct hdn_klp_symbols *view, *old;
	size_t header, size, used = 0, i;
	int error = -ENOEXEC;

	header = struct_size(view, symbols, source->num_symtab);
	if (!hdn_pt_active() || check_add_overflow(header, strtab_size, &size))
		return -ENOEXEC;
	view = klp_alloc(size);
	if (!view)
		return -ENOMEM;
	view->owner = mod;
	view->strings = (char *)view + header;
	strscpy(view->name, mod->name, sizeof(view->name));
	memcpy((char *)view->strings, source->strtab, strtab_size);
	for (i = 0; i < source->num_symtab; i++) {
		const Elf_Sym *symbol = &source->symtab[i];
		const char *name = table_string(view->strings, strtab_size, symbol->st_name);

		if (!name)
			goto fail;
		/* Delayed bindings cannot retain init storage or import another
		 * module's symbols under this owner's identity. */
		if (!*name || symbol->st_shndx == SHN_UNDEF ||
		    symbol->st_shndx >= SHN_LORESERVE ||
		    !within_module_core(symbol->st_value, mod))
			continue;
		view->symbols[used++] = *symbol;
	}
	view->count = used;
	mutex_lock(&klp_lock);
	for (old = klp_symbols; old; old = old->next)
		if (old->owner == mod || !strcmp(old->name, view->name)) {
			error = -EEXIST;
			goto unlock_symbols;
		}
	view->next = klp_symbols;
	error = hdn_execmem_seal_data(view);
	if (!error)
		klp_store((unsigned long *)&klp_symbols, (unsigned long)view);
unlock_symbols:
	mutex_unlock(&klp_lock);
	if (!error)
		return 0;
fail:
	hdn_execmem_free(view);
	return error;
}

void hdn_klp_symbols_live(struct module *mod, bool live)
{
	struct hdn_klp_symbols *view;

	mutex_lock(&klp_lock);
	for (view = klp_symbols; view; view = view->next)
		if (view->owner == mod) {
			klp_store(&view->live, live);
			break;
		}
	if (!view && live)
		panic("HDN missing module symbol ownership");
	mutex_unlock(&klp_lock);
}

static int symbol_value(const char *object, const char *name,
			unsigned long position, unsigned long *result)
{
	const struct hdn_klp_symbols *view;
	unsigned long count = 0, value = 0, i;

	lockdep_assert_held(&klp_lock);
	for (view = klp_symbols; view; view = view->next) {
		if (!view->live || strcmp(view->name, object))
			continue;
		for (i = 0; i < view->count; i++) {
			const Elf_Sym *symbol = &view->symbols[i];

			if (strcmp(view->strings + symbol->st_name, name))
				continue;
			count++;
			value = symbol->st_value;
			if (position && count == position)
				break;
		}
		break;
	}
	if (!value || (position ? count != position : count != 1))
		return -ENOENT;
	*result = value;
	return 0;
}

int hdn_klp_prepare(struct module *mod, const struct klp_modinfo *info,
		    const char *strtab, size_t strtab_size)
{
	const Elf_Shdr *sections = info->sechdrs, *symbols;
	struct hdn_klp_plan *plan, *old;
	size_t count = 0, used = 0, names_size, i, j;
	int error = -ENOEXEC;

	BUILD_BUG_ON(MODULE_NAME_LEN < 56 || KSYM_NAME_LEN != 512);
	if (!hdn_pt_active() || info->hdr.e_shstrndx >= info->hdr.e_shnum ||
	    info->symndx >= info->hdr.e_shnum)
		return -ENOEXEC;
	symbols = &sections[info->symndx];
	names_size = sections[info->hdr.e_shstrndx].sh_size;
	if (symbols->sh_size % sizeof(Elf_Sym))
		return -ENOEXEC;
	for (i = 1; i < info->hdr.e_shnum; i++) {
		const Elf_Shdr *sec = &sections[i];

		if (!(sec->sh_flags & SHF_RELA_LIVEPATCH))
			continue;
		if (sec->sh_type != SHT_RELA || sec->sh_size % sizeof(Elf_Rela) ||
		    check_add_overflow(count, sec->sh_size / sizeof(Elf_Rela), &count) ||
		    count > (HDN_KLP_MAX - sizeof(*plan)) / sizeof(plan->reloc[0]))
			return -ENOEXEC;
	}
	plan = klp_alloc(struct_size(plan, reloc, count));
	if (!plan)
		return -ENOMEM;
	plan->owner = mod;
	for (i = 1; i < info->hdr.e_shnum; i++) {
		const Elf_Shdr *sec = &sections[i], *target;
		const Elf_Rela *relas;
		const char *section_name, *target_name;
		char object[MODULE_NAME_LEN];
		int consumed = 0;

		if (!(sec->sh_flags & SHF_RELA_LIVEPATCH))
			continue;
		section_name = table_string(info->secstrings, names_size, sec->sh_name);
		if (!section_name ||
		    sscanf(section_name, ".klp.rela.%55[^.]%n", object, &consumed) != 1 ||
		    section_name[consumed] != '.')
			goto fail;
		/* Completed before metadata admission and module formation. */
		if (!strcmp(object, "vmlinux"))
			continue;
		if (!sec->sh_info || sec->sh_info >= info->hdr.e_shnum ||
		    sec->sh_link != info->symndx)
			goto fail;
		target = &sections[sec->sh_info];
		target_name = table_string(info->secstrings, names_size, target->sh_name);
		/* Derived metadata (RAP, alternatives, ORC, static calls, jump labels,
		 * ro_after_init) is consumed once. It cannot be relocated later.
		 * Ordinary patch text and data retain delayed binding support. */
		if (!target_name || strcmp(section_name + consumed + 1, target_name) ||
		    !(target->sh_flags & SHF_ALLOC) ||
		    (target->sh_flags & SHF_RO_AFTER_INIT) ||
		    !(section_family(target_name, ".text") ||
		      section_family(target_name, ".data") ||
		      section_family(target_name, ".rodata")))
			goto fail;
		relas = (const void *)sec->sh_addr;
		for (j = 0; j < sec->sh_size / sizeof(*relas); j++) {
			const Elf_Rela *rela = &relas[j];
			const Elf_Sym *symbol;
			const char *symbol_name;
			struct hdn_klp_reloc *r = &plan->reloc[used];
			unsigned long last;
			bool inside = false;

			r->type = ELF_R_TYPE(rela->r_info);
			r->size = reloc_size(r->type);
			if (!r->size)
				continue;
			if (r->size == SIZE_MAX || r->size > target->sh_size ||
			    rela->r_offset > target->sh_size - r->size ||
			    ELF_R_SYM(rela->r_info) >= symbols->sh_size / sizeof(*symbol) ||
			    check_add_overflow(target->sh_addr, rela->r_offset, &r->address) ||
			    check_add_overflow(r->address, r->size - 1, &last))
				goto fail;
			for_class_mod_mem_type(type, core) {
				if (type == MOD_RO_AFTER_INIT)
					continue;
				if (within_module_mem_type(r->address, mod, type) &&
				    within_module_mem_type(last, mod, type)) {
					r->text = mod_mem_type_is_text(type);
					inside = true;
					break;
				}
			}
			if (!inside || !!(target->sh_flags & SHF_EXECINSTR) != !!r->text)
				goto fail;
			symbol = (const Elf_Sym *)symbols->sh_addr + ELF_R_SYM(rela->r_info);
			symbol_name = table_string(strtab, strtab_size, symbol->st_name);
			consumed = 0;
			if (!symbol_name || symbol->st_shndx != SHN_LIVEPATCH ||
			    sscanf(symbol_name, ".klp.sym.%55[^.].%511[^,],%lu%n",
				   r->source, r->name, &r->position, &consumed) != 3 ||
			    symbol_name[consumed] || !strcmp(r->source, "vmlinux"))
				goto fail;
			strscpy(r->object, object, sizeof(r->object));
			r->addend = rela->r_addend;
			used++;
		}
	}
	plan->count = used;
	sort(plan->reloc, used, sizeof(plan->reloc[0]), reloc_compare, NULL);
	for (i = 1; i < used; i++)
		if (plan->reloc[i].address - plan->reloc[i - 1].address <
		    plan->reloc[i - 1].size)
			goto fail;
	mutex_lock(&klp_lock);
	for (old = klp_plans; old; old = old->next)
		if (old->owner == mod) {
			error = -EEXIST;
			goto unlock;
		}
	plan->next = klp_plans;
	error = hdn_execmem_seal_data(plan);
	if (!error)
		klp_store((unsigned long *)&klp_plans, (unsigned long)plan);
unlock:
	mutex_unlock(&klp_lock);
	if (!error)
		return 0;
fail:
	hdn_execmem_free(plan);
	return error;
}

static int reloc_value(const struct hdn_klp_reloc *r, unsigned long *value)
{
	unsigned long symbol, result;
	int error = symbol_value(r->source, r->name, r->position, &symbol);

	if (error)
		return error;
	result = symbol + r->addend;
	switch (r->type) {
	case R_X86_64_32:
		if (result != (u32)result)
			return -ENOEXEC;
		break;
	case R_X86_64_32S:
		if ((long)result != (s32)result)
			return -ENOEXEC;
		break;
	case R_X86_64_PC32: case R_X86_64_PLT32:
		result -= r->address;
		if ((long)result != (s32)result)
			return -ENOEXEC;
		break;
	case R_X86_64_PC64:
		result -= r->address;
		break;
	}
	*value = result;
	return 0;
}

/* Preserve adjacent live data even for unaligned or cross-page relocations.
 * This primitive has no exported caller and accepts only a sealed plan row. */
static void reloc_write(const struct hdn_klp_reloc *r, unsigned long value,
			unsigned long expected)
{
	unsigned long address = r->address;
	size_t remaining = r->size;

	if (r->text) {
		if (memcmp((void *)address, &expected, remaining))
			panic("HDN livepatch text changed during relocation");
		text_poke((void *)address, &value, remaining);
		return;
	}
	while (remaining) {
		unsigned long aligned = address & ~7UL;
		unsigned int shift = (address & 7) * 8;
		size_t size = min(remaining, 8 - (address & 7));
		unsigned long bits = size == 8 ? ~0UL : (1UL << (size * 8)) - 1;
		unsigned long mask = bits << shift, old, next, pfn = vmalloc_to_pfn((void *)aligned);

		do {
			old = hdn_pt_window_read(pfn, offset_in_page(aligned));
			if ((old & mask) != ((expected & bits) << shift))
				panic("HDN livepatch data changed during relocation");
			next = (old & ~mask) | ((value & bits) << shift);
		} while (hdn_pt_window_update(pfn, offset_in_page(aligned), next, old,
					      HDN_PT_COMPARE_EXCHANGE) != old);
		remaining -= size;
		address += size;
		if (remaining) {
			value >>= size * 8;
			expected >>= size * 8;
		}
	}
}

int hdn_klp_relocate(struct module *mod, const char *object, bool apply)
{
	struct hdn_klp_plan *plan;
	unsigned long *values = NULL;
	size_t i;
	int error = -ENOEXEC;

	if (!object)
		return -EINVAL;
	mutex_lock(&klp_lock);
	for (plan = klp_plans; plan; plan = plan->next)
		if (plan->owner == mod)
			break;
	if (!plan)
		goto out;
	if (!plan->count) {
		error = 0;
		goto out;
	}
	if (apply) {
		values = klp_alloc(array_size(plan->count, sizeof(*values)));
		if (!values) {
			error = -ENOMEM;
			goto out;
		}
	}
	/* Resolve and validate the complete object before changing any byte. */
	for (i = 0; i < plan->count; i++) {
		const struct hdn_klp_reloc *r = &plan->reloc[i];
		unsigned long expected = apply ? 0 : r->value;

		if (strcmp(r->object, object) || (!apply && !r->active))
			continue;
		if ((apply && r->active) || memcmp((void *)r->address, &expected, r->size)) {
			error = -ENOEXEC;
			goto free;
		}
		if (apply) {
			error = reloc_value(r, &values[i]);
			if (error)
				goto free;
		}
	}
	if (apply) {
		error = hdn_execmem_seal_data(values);
		if (error)
			goto free;
	}
	mutex_lock(&text_mutex);
	for (i = 0; i < plan->count; i++) {
		struct hdn_klp_reloc *r = &plan->reloc[i];

		if (strcmp(r->object, object) || (!apply && !r->active))
			continue;
		reloc_write(r, apply ? values[i] : 0, apply ? 0 : r->value);
		klp_store(&r->value, apply ? values[i] : 0);
		klp_store(&r->active, apply);
	}
	smp_text_poke_sync_each_cpu();
	mutex_unlock(&text_mutex);
	error = 0;
free:
	if (values)
		hdn_execmem_free(values);
out:
	mutex_unlock(&klp_lock);
	return error;
}

void hdn_klp_release(struct module *mod)
{
	struct hdn_klp_plan *plan, **link;
	struct hdn_klp_symbols *symbols, **symbol_link;

	mutex_lock(&klp_lock);
	for (link = &klp_plans; (plan = *link); link = &plan->next) {
		if (plan->owner != mod)
			continue;
		klp_store((unsigned long *)link, (unsigned long)plan->next);
		hdn_execmem_free(plan);
		break;
	}
	for (symbol_link = &klp_symbols; (symbols = *symbol_link);
	     symbol_link = &symbols->next) {
		if (symbols->owner != mod)
			continue;
		klp_store((unsigned long *)symbol_link, (unsigned long)symbols->next);
		hdn_execmem_free(symbols);
		break;
	}
	mutex_unlock(&klp_lock);
}
#endif
