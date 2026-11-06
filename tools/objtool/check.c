// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2015-2017 Josh Poimboeuf <jpoimboe@redhat.com>
 */

#define _GNU_SOURCE /* memmem() */
#include <fnmatch.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/mman.h>

#include <objtool/builtin.h>
#include <objtool/cfi.h>
#include <objtool/arch.h>
#include <objtool/disas.h>
#include <objtool/check.h>
#include <objtool/special.h>
#include <objtool/trace.h>
#include <objtool/warn.h>
#include <objtool/checksum.h>
#include <objtool/util.h>

#include <linux/objtool_types.h>
#include <linux/hashtable.h>
#include <linux/kernel.h>
#include <linux/static_call_types.h>
#include <linux/string.h>

static unsigned long nr_cfi, nr_cfi_reused, nr_cfi_cache;

static struct cfi_init_state initial_func_cfi;
static struct cfi_state init_cfi;
static struct cfi_state func_cfi;
static struct cfi_state force_undefined_cfi;

struct disas_context *objtool_disas_ctx;

size_t sym_name_max_len;

struct instruction *find_insn(struct objtool_file *file,
			      struct section *sec, unsigned long offset)
{
	struct instruction *insn;

	hash_for_each_possible(file->insn_hash, insn, hash, sec_offset_hash(sec, offset)) {
		if (insn->sec == sec && insn->offset == offset)
			return insn;
	}

	return NULL;
}

struct instruction *next_insn_same_sec(struct objtool_file *file,
				       struct instruction *insn)
{
	if (insn->idx == INSN_CHUNK_MAX)
		return find_insn(file, insn->sec, insn->offset + insn->len);

	insn++;
	if (!insn->len)
		return NULL;

	return insn;
}

static struct instruction *next_insn_same_func(struct objtool_file *file,
					       struct instruction *insn)
{
	struct instruction *next = next_insn_same_sec(file, insn);
	struct symbol *func = insn_func(insn);

	if (!func)
		return NULL;

	if (next && insn_func(next) == func)
		return next;

	/* Check if we're already in the subfunction: */
	if (func == func->cfunc)
		return NULL;

	/* Move to the subfunction: */
	return find_insn(file, func->cfunc->sec, func->cfunc->offset);
}

static struct instruction *prev_insn_same_sec(struct objtool_file *file,
					      struct instruction *insn)
{
	if (insn->idx == 0) {
		if (insn->prev_len)
			return find_insn(file, insn->sec, insn->offset - insn->prev_len);
		return NULL;
	}

	return insn - 1;
}

static struct instruction *prev_insn_same_sym(struct objtool_file *file,
					      struct instruction *insn)
{
	struct instruction *prev = prev_insn_same_sec(file, insn);

	if (prev && insn_func(prev) == insn_func(insn))
		return prev;

	return NULL;
}

#define for_each_insn(file, insn)					\
	for (struct section *__sec, *__fake = (struct section *)1;	\
	     __fake; __fake = NULL)					\
		for_each_sec(file->elf, __sec)				\
			sec_for_each_insn(file, __sec, insn)

#define func_for_each_insn(file, func, insn)				\
	for (insn = find_insn(file, func->sec, func->offset);		\
	     insn;							\
	     insn = next_insn_same_func(file, insn))

#define sym_for_each_insn(file, sym, insn)				\
	for (insn = find_insn(file, sym->sec, sym->offset);		\
	     insn && insn->offset < sym->offset + sym->len;		\
	     insn = next_insn_same_sec(file, insn))

#define sym_for_each_insn_continue_reverse(file, sym, insn)		\
	for (insn = prev_insn_same_sec(file, insn);			\
	     insn && insn->offset >= sym->offset;			\
	     insn = prev_insn_same_sec(file, insn))

#define sec_for_each_insn_from(file, insn)				\
	for (; insn; insn = next_insn_same_sec(file, insn))

#define sec_for_each_insn_continue(file, insn)				\
	for (insn = next_insn_same_sec(file, insn); insn;		\
	     insn = next_insn_same_sec(file, insn))

static inline struct reloc *insn_jump_table(struct instruction *insn)
{
	if (insn->type == INSN_JUMP_DYNAMIC ||
	    insn->type == INSN_CALL_DYNAMIC)
		return insn->_jump_table;

	return NULL;
}

static inline unsigned long insn_jump_table_size(struct instruction *insn)
{
	if (insn->type == INSN_JUMP_DYNAMIC ||
	    insn->type == INSN_CALL_DYNAMIC)
		return insn->_jump_table_size;

	return 0;
}

static bool is_jump_table_jump(struct instruction *insn)
{
	struct alt_group *alt_group = insn->alt_group;

	if (insn->rap_jump || insn_jump_table(insn))
		return true;

	/* Retpoline alternative for a jump table? */
	return alt_group && alt_group->orig_group &&
	       insn_jump_table(alt_group->orig_group->first_insn);
}

static bool is_sibling_call(struct instruction *insn)
{
	/*
	 * Assume only STT_FUNC calls have jump-tables.
	 */
	if (insn_func(insn)) {
		/* An indirect jump is either a sibling call or a jump to a table. */
		if (insn->type == INSN_JUMP_DYNAMIC)
			return !is_jump_table_jump(insn);
	}

	/* add_jump_destinations() sets insn_call_dest(insn) for sibling calls. */
	return (is_static_jump(insn) && insn_call_dest(insn));
}

/*
 * Checks if a function is a Rust "noreturn" one.
 */
static bool is_rust_noreturn(const struct symbol *func)
{
	/*
	 * If it does not start with "_R", then it is not a Rust symbol.
	 */
	if (strncmp(func->name, "_R", 2))
		return false;

	/*
	 * These are just heuristics -- we do not control the precise symbol
	 * name, due to the crate disambiguators (which depend on the compiler)
	 * as well as changes to the source code itself between versions (since
	 * these come from the Rust standard library).
	 */
	return str_ends_with(func->name, "_4core3num20from_str_radix_panic")				||
	       str_ends_with(func->name, "_4core3num22from_ascii_radix_panic")				||
	       str_ends_with(func->name, "_4core5sliceSp15copy_from_slice17len_mismatch_fail")		||
	       str_ends_with(func->name, "_4core6option13expect_failed")				||
	       str_ends_with(func->name, "_4core6option13unwrap_failed")				||
	       str_ends_with(func->name, "_4core6result13unwrap_failed")				||
	       str_ends_with(func->name, "_4core9panicking5panic")					||
	       str_ends_with(func->name, "_4core9panicking9panic_fmt")					||
	       str_ends_with(func->name, "_4core9panicking14panic_explicit")				||
	       str_ends_with(func->name, "_4core9panicking14panic_nounwind")				||
	       str_ends_with(func->name, "_4core9panicking18panic_bounds_check")			||
	       str_ends_with(func->name, "_4core9panicking18panic_nounwind_fmt")			||
	       str_ends_with(func->name, "_4core9panicking19assert_failed_inner")			||
	       str_ends_with(func->name, "_4core9panicking30panic_null_pointer_dereference")		||
	       str_ends_with(func->name, "_4core9panicking36panic_misaligned_pointer_dereference")	||
	       str_ends_with(func->name, "_7___rustc17rust_begin_unwind")				||
	       strstr(func->name, "_4core9panicking13assert_failed")					||
	       strstr(func->name, "_4core9panicking11panic_const24panic_const_")			||
	       (strstr(func->name, "_4core5slice5index") &&
		strstr(func->name, "slice_") &&
		str_ends_with(func->name, "_fail"));
}

/*
 * This checks to see if the given function is a "noreturn" function.
 *
 * For global functions which are outside the scope of this object file, we
 * have to keep a manual list of them.
 *
 * For local functions, we have to detect them manually by simply looking for
 * the lack of a return instruction.
 */
static bool __dead_end_function(struct objtool_file *file, struct symbol *func,
				int recursion)
{
	int i;
	struct instruction *insn;
	bool empty = true;

#define NORETURN(func) __stringify(func),
	static const char * const global_noreturns[] = {
#include "noreturns.h"
	};
#undef NORETURN

	if (!func)
		return false;

	if (!is_local_sym(func)) {
		if (is_rust_noreturn(func))
			return true;

		for (i = 0; i < ARRAY_SIZE(global_noreturns); i++)
			if (!strcmp(func->name, global_noreturns[i]))
				return true;
	}

	if (is_weak_sym(func))
		return false;

	if (!func->len)
		return false;

	insn = find_insn(file, func->sec, func->offset);
	if (!insn || !insn_func(insn))
		return false;

	func_for_each_insn(file, func, insn) {
		empty = false;

		if (insn->type == INSN_RETURN)
			return false;
	}

	if (empty)
		return false;

	/*
	 * A function can have a sibling call instead of a return.  In that
	 * case, the function's dead-end status depends on whether the target
	 * of the sibling call returns.
	 */
	func_for_each_insn(file, func, insn) {
		if (is_sibling_call(insn)) {
			struct instruction *dest = insn->jump_dest;

			if (!dest)
				/* sibling call to another file */
				return false;

			/* local sibling call */
			if (recursion == 5) {
				/*
				 * Infinite recursion: two functions have
				 * sibling calls to each other.  This is a very
				 * rare case.  It means they aren't dead ends.
				 */
				return false;
			}

			return __dead_end_function(file, insn_func(dest), recursion+1);
		}
	}

	return true;
}

static bool dead_end_function(struct objtool_file *file, struct symbol *func)
{
	return __dead_end_function(file, func, 0);
}

static void init_cfi_state(struct cfi_state *cfi)
{
	int i;

	for (i = 0; i < CFI_NUM_REGS; i++) {
		cfi->regs[i].base = CFI_UNDEFINED;
		cfi->vals[i].base = CFI_UNDEFINED;
	}
	cfi->cfa.base = CFI_UNDEFINED;
	cfi->drap_reg = CFI_UNDEFINED;
	cfi->drap_offset = -1;
}

static void init_insn_state(struct objtool_file *file, struct insn_state *state,
			    struct section *sec)
{
	memset(state, 0, sizeof(*state));
	init_cfi_state(&state->cfi);

	if (opts.noinstr && sec)
		state->noinstr = sec->noinstr;
}

static struct cfi_state *cfi_alloc(void)
{
	struct cfi_state *cfi = calloc(1, sizeof(struct cfi_state));
	if (!cfi) {
		ERROR_GLIBC("calloc");
		exit(1);
	}
	nr_cfi++;
	return cfi;
}

static int cfi_bits;
static struct hlist_head *cfi_hash;

static inline bool cficmp(struct cfi_state *cfi1, struct cfi_state *cfi2)
{
	return memcmp((void *)cfi1 + sizeof(cfi1->hash),
		      (void *)cfi2 + sizeof(cfi2->hash),
		      sizeof(struct cfi_state) - sizeof(struct hlist_node));
}

static inline u32 cfi_key(struct cfi_state *cfi)
{
	return jhash((void *)cfi + sizeof(cfi->hash),
		     sizeof(*cfi) - sizeof(cfi->hash), 0);
}

static struct cfi_state *cfi_hash_find_or_add(struct cfi_state *cfi)
{
	struct hlist_head *head = &cfi_hash[hash_min(cfi_key(cfi), cfi_bits)];
	struct cfi_state *obj;

	hlist_for_each_entry(obj, head, hash) {
		if (!cficmp(cfi, obj)) {
			nr_cfi_cache++;
			return obj;
		}
	}

	obj = cfi_alloc();
	*obj = *cfi;
	hlist_add_head(&obj->hash, head);

	return obj;
}

static void cfi_hash_add(struct cfi_state *cfi)
{
	struct hlist_head *head = &cfi_hash[hash_min(cfi_key(cfi), cfi_bits)];

	hlist_add_head(&cfi->hash, head);
}

static void *cfi_hash_alloc(unsigned long size)
{
	cfi_bits = max(10, ilog2(size));
	cfi_hash = mmap(NULL, sizeof(struct hlist_head) << cfi_bits,
			PROT_READ|PROT_WRITE,
			MAP_PRIVATE|MAP_ANON, -1, 0);
	if (cfi_hash == (void *)-1L) {
		ERROR_GLIBC("mmap fail cfi_hash");
		cfi_hash = NULL;
	}  else if (opts.stats) {
		printf("cfi_bits: %d\n", cfi_bits);
	}

	return cfi_hash;
}

static unsigned long nr_insns;
static unsigned long nr_insns_visited;

/*
 * Call the arch-specific instruction decoder for all the instructions and add
 * them to the global instruction list.
 */
static int decode_instructions(struct objtool_file *file)
{
	struct section *sec;
	struct symbol *func;
	unsigned long offset;
	struct instruction *insn;

	for_each_sec(file->elf, sec) {
		struct instruction *insns = NULL;
		u8 prev_len = 0;
		u8 idx = 0;

		if (!is_text_sec(sec))
			continue;

		if (strcmp(sec->name, ".altinstr_replacement") &&
		    strcmp(sec->name, ".altinstr_aux") &&
		    strncmp(sec->name, ".discard.", 9))
			sec->text = true;

		if (!strcmp(sec->name, ".noinstr.text") ||
		    !strcmp(sec->name, ".entry.text") ||
		    !strcmp(sec->name, ".cpuidle.text") ||
		    !strncmp(sec->name, ".text..__x86.", 13))
			sec->noinstr = true;

		/*
		 * .init.text code is ran before userspace and thus doesn't
		 * strictly need retpolines, except for modules which are
		 * loaded late, they very much do need retpoline in their
		 * .init.text
		 */
		if (!strcmp(sec->name, ".init.text") && !opts.module)
			sec->init = true;

		for (offset = 0; offset < sec_size(sec); offset += insn->len) {
			if (!insns || idx == INSN_CHUNK_MAX) {
				insns = calloc(INSN_CHUNK_SIZE, sizeof(*insn));
				if (!insns) {
					ERROR_GLIBC("calloc");
					return -1;
				}
				idx = 0;
			} else {
				idx++;
			}
			insn = &insns[idx];
			insn->idx = idx;

			INIT_LIST_HEAD(&insn->call_node);
			insn->sec = sec;
			insn->offset = offset;
			insn->prev_len = prev_len;

			if (arch_decode_instruction(file, sec, offset, sec_size(sec) - offset, insn))
				return -1;

			prev_len = insn->len;

			/*
			 * By default, "ud2" is a dead end unless otherwise
			 * annotated, because GCC 7 inserts it for certain
			 * divide-by-zero cases.
			 */
			if (insn->type == INSN_BUG)
				insn->dead_end = true;

			hash_add(file->insn_hash, &insn->hash, sec_offset_hash(sec, insn->offset));
			nr_insns++;
		}

		sec_for_each_sym(sec, func) {
			if (!is_notype_sym(func) && !is_func_sym(func))
				continue;

			if (func->offset == sec_size(sec)) {
				/* Heuristic: likely an "end" symbol */
				if (is_notype_sym(func))
					continue;
				ERROR("%s(): STT_FUNC at end of section", func->name);
				return -1;
			}

			if (func->embedded_insn || func->alias != func)
				continue;

			if (!find_insn(file, sec, func->offset)) {
				ERROR("%s(): can't find starting instruction", func->name);
				return -1;
			}

			sym_for_each_insn(file, func, insn) {
				insn->sym = func;
				if (is_func_sym(func) &&
				    insn->type == INSN_ENDBR &&
				    list_empty(&insn->call_node)) {
					if (insn->offset == func->offset) {
						list_add_tail(&insn->call_node, &file->endbr_list);
						file->nr_endbr++;
					} else {
						file->nr_endbr_int++;
					}
				}
			}
		}
	}

	if (opts.stats)
		printf("nr_insns: %lu\n", nr_insns);

	return 0;
}

/*
 * Known pv_ops*[] arrays.
 */
static struct {
	const char *name;
	int idx_off;
} pv_ops_tables[] = {
	{ .name = "pv_ops", },
	{ .name = "pv_ops_lock", },
	{ .name = NULL, .idx_off = -1 }
};

/*
 * Get index offset for a pv_ops* array.
 */
int pv_ops_idx_off(const char *symname)
{
	int idx;

	for (idx = 0; pv_ops_tables[idx].name; idx++) {
		if (!strcmp(symname, pv_ops_tables[idx].name))
			break;
	}

	return pv_ops_tables[idx].idx_off;
}

/*
 * Read a pv_ops*[] .data table to find the static initialized values.
 */
static int add_pv_ops(struct objtool_file *file, int pv_ops_idx)
{
	struct symbol *sym, *func;
	unsigned long off, end;
	struct reloc *reloc;
	int idx, idx_off;
	const char *symname;

	symname = pv_ops_tables[pv_ops_idx].name;
	sym = find_symbol_by_name(file->elf, symname);
	if (!sym) {
		ERROR("Unknown pv_ops array %s", symname);
		return -1;
	}

	off = sym->offset;
	end = off + sym->len;
	idx_off = pv_ops_tables[pv_ops_idx].idx_off;
	if (idx_off < 0) {
		ERROR("pv_ops array %s has unknown index offset", symname);
		return -1;
	}

	for (;;) {
		reloc = find_reloc_by_dest_range(file->elf, sym->sec, off, end - off);
		if (!reloc)
			break;

		idx = (reloc_offset(reloc) - sym->offset) / sizeof(unsigned long);

		func = reloc->sym;
		if (is_sec_sym(func))
			func = find_symbol_by_offset(reloc->sym->sec,
						     reloc_addend(reloc));
		if (!func) {
			ERROR_FUNC(reloc->sym->sec, reloc_addend(reloc),
				   "can't find func at %s[%d]", symname, idx);
			return -1;
		}

		if (objtool_pv_add(file, idx + idx_off, func))
			return -1;

		off = reloc_offset(reloc) + 1;
		if (off > end)
			break;
	}

	return 0;
}

/*
 * Allocate and initialize file->pv_ops[].
 */
static int init_pv_ops(struct objtool_file *file)
{
	struct symbol *sym;
	int idx, nr;

	if (!opts.noinstr)
		return 0;

	file->pv_ops = NULL;

	nr = 0;
	for (idx = 0; pv_ops_tables[idx].name; idx++) {
		sym = find_symbol_by_name(file->elf, pv_ops_tables[idx].name);
		if (!sym) {
			pv_ops_tables[idx].idx_off = -1;
			continue;
		}
		pv_ops_tables[idx].idx_off = nr;
		nr += sym->len / sizeof(unsigned long);
	}

	if (nr == 0)
		return 0;

	file->pv_ops = calloc(nr, sizeof(struct pv_state));
	if (!file->pv_ops) {
		ERROR_GLIBC("calloc");
		return -1;
	}

	for (idx = 0; idx < nr; idx++)
		INIT_LIST_HEAD(&file->pv_ops[idx].targets);

	for (idx = 0; pv_ops_tables[idx].name; idx++) {
		if (pv_ops_tables[idx].idx_off < 0)
			continue;
		if (add_pv_ops(file, idx))
			return -1;
	}

	return 0;
}

static bool is_livepatch_module(struct objtool_file *file)
{
	struct section *sec;

	if (!opts.module)
		return false;

	sec = find_section_by_name(file->elf, ".modinfo");
	if (!sec)
		return false;

	return memmem(sec->data->d_buf, sec_size(sec), "\0livepatch=Y", 12);
}

static int create_static_call_sections(struct objtool_file *file)
{
	struct static_call_site *site;
	struct section *sec;
	struct instruction *insn;
	struct symbol *key_sym;
	char *key_name, *tmp;
	int idx;

	sec = find_section_by_name(file->elf, ".static_call_sites");
	if (sec) {
		/*
		 * Livepatch modules may have already extracted the static call
		 * site entries to take advantage of vmlinux static call
		 * privileges.
		 */
		if (!file->klp)
			WARN("file already has .static_call_sites section, skipping");

		return 0;
	}

	if (list_empty(&file->static_call_list))
		return 0;

	idx = 0;
	list_for_each_entry(insn, &file->static_call_list, call_node)
		idx++;

	sec = elf_create_section_pair(file->elf, ".static_call_sites",
				      sizeof(*site), idx, idx * 2);
	if (!sec)
		return -1;

	/* Allow modules to modify the low bits of static_call_site::key */
	sec->sh.sh_flags |= SHF_WRITE;

	idx = 0;
	list_for_each_entry(insn, &file->static_call_list, call_node) {

		/* populate reloc for 'addr' */
		if (!elf_init_reloc_text_sym(file->elf, sec,
					     idx * sizeof(*site), idx * 2,
					     insn->sec, insn->offset))
			return -1;

		/* find key symbol */
		key_name = strdup(insn_call_dest(insn)->name);
		if (!key_name) {
			ERROR_GLIBC("strdup");
			return -1;
		}
		if (strncmp(key_name, STATIC_CALL_TRAMP_PREFIX_STR,
			    STATIC_CALL_TRAMP_PREFIX_LEN)) {
			ERROR("static_call: trampoline name malformed: %s", key_name);
			return -1;
		}
		tmp = key_name + STATIC_CALL_TRAMP_PREFIX_LEN - STATIC_CALL_KEY_PREFIX_LEN;
		memcpy(tmp, STATIC_CALL_KEY_PREFIX_STR, STATIC_CALL_KEY_PREFIX_LEN);

		key_sym = find_symbol_by_name(file->elf, tmp);
		if (!key_sym) {
			if (!opts.module) {
				ERROR("static_call: can't find static_call_key symbol: %s", tmp);
				return -1;
			}

			/*
			 * For modules(), the key might not be exported, which
			 * means the module can make static calls but isn't
			 * allowed to change them.
			 *
			 * In that case we temporarily set the key to be the
			 * trampoline address.  This is fixed up in
			 * static_call_add_module().
			 */
			key_sym = insn_call_dest(insn);
		}

		/* populate reloc for 'key' */
		if (!elf_init_reloc_data_sym(file->elf, sec,
					     idx * sizeof(*site) + 4,
					     (idx * 2) + 1, key_sym,
					     is_sibling_call(insn) * STATIC_CALL_SITE_TAIL))
			return -1;

		idx++;
	}

	return 0;
}

static int create_retpoline_sites_sections(struct objtool_file *file)
{
	struct instruction *insn;
	struct section *sec;
	int idx;

	sec = find_section_by_name(file->elf, ".retpoline_sites");
	if (sec) {
		WARN("file already has .retpoline_sites, skipping");
		return 0;
	}

	idx = 0;
	list_for_each_entry(insn, &file->retpoline_call_list, call_node)
		idx++;

	if (!idx)
		return 0;

	sec = elf_create_section_pair(file->elf, ".retpoline_sites",
				      sizeof(int), idx, idx);
	if (!sec)
		return -1;

	idx = 0;
	list_for_each_entry(insn, &file->retpoline_call_list, call_node) {

		if (!elf_init_reloc_text_sym(file->elf, sec,
					     idx * sizeof(int), idx,
					     insn->sec, insn->offset))
			return -1;

		idx++;
	}

	return 0;
}

static int create_return_sites_sections(struct objtool_file *file)
{
	struct instruction *insn;
	struct section *sec;
	int idx;

	sec = find_section_by_name(file->elf, ".return_sites");
	if (sec) {
		WARN("file already has .return_sites, skipping");
		return 0;
	}

	idx = 0;
	list_for_each_entry(insn, &file->return_thunk_list, call_node)
		idx++;

	if (!idx)
		return 0;

	sec = elf_create_section_pair(file->elf, ".return_sites",
				      sizeof(int), idx, idx);
	if (!sec)
		return -1;

	idx = 0;
	list_for_each_entry(insn, &file->return_thunk_list, call_node) {

		if (!elf_init_reloc_text_sym(file->elf, sec,
					     idx * sizeof(int), idx,
					     insn->sec, insn->offset))
			return -1;

		idx++;
	}

	return 0;
}

static int create_ibt_endbr_seal_sections(struct objtool_file *file)
{
	struct instruction *insn;
	struct section *sec;
	int idx;

	sec = find_section_by_name(file->elf, ".ibt_endbr_seal");
	if (sec) {
		WARN("file already has .ibt_endbr_seal, skipping");
		return 0;
	}

	idx = 0;
	list_for_each_entry(insn, &file->endbr_list, call_node)
		idx++;

	if (opts.stats) {
		printf("ibt: ENDBR at function start: %d\n", file->nr_endbr);
		printf("ibt: ENDBR inside functions:  %d\n", file->nr_endbr_int);
		printf("ibt: superfluous ENDBR:       %d\n", idx);
	}

	if (!idx)
		return 0;

	sec = elf_create_section_pair(file->elf, ".ibt_endbr_seal",
				      sizeof(int), idx, idx);
	if (!sec)
		return -1;

	idx = 0;
	list_for_each_entry(insn, &file->endbr_list, call_node) {

		int *site = (int *)sec->data->d_buf + idx;
		struct symbol *sym = insn->sym;
		*site = 0;

		if (opts.module && sym && is_func_sym(sym) &&
		    insn->offset == sym->offset &&
		    (!strcmp(sym->name, "init_module") ||
		     !strcmp(sym->name, "cleanup_module"))) {
			ERROR("%s(): Magic init_module() function name is deprecated, use module_init(fn) instead",
			      sym->name);
			return -1;
		}

		if (!elf_init_reloc_text_sym(file->elf, sec,
					     idx * sizeof(int), idx,
					     insn->sec, insn->offset))
			return -1;

		idx++;
	}

	return 0;
}

static int create_cfi_sections(struct objtool_file *file)
{
	struct section *sec;
	struct symbol *sym;
	int idx;

	sec = find_section_by_name(file->elf, ".cfi_sites");
	if (sec) {
		WARN("file already has .cfi_sites section, skipping");
		return 0;
	}

	idx = 0;
	for_each_sym(file->elf, sym) {
		if (!is_func_sym(sym))
			continue;

		if (strncmp(sym->name, "__cfi_", 6))
			continue;

		idx++;
	}

	sec = elf_create_section_pair(file->elf, ".cfi_sites",
				      sizeof(unsigned int), idx, idx);
	if (!sec)
		return -1;

	idx = 0;
	for_each_sym(file->elf, sym) {
		if (!is_func_sym(sym))
			continue;

		if (strncmp(sym->name, "__cfi_", 6))
			continue;

		if (!elf_init_reloc_text_sym(file->elf, sec,
					     idx * sizeof(unsigned int), idx,
					     sym->sec, sym->offset))
			return -1;

		idx++;
	}

	return 0;
}

static int create_mcount_loc_sections(struct objtool_file *file)
{
	size_t addr_size = elf_addr_size(file->elf);
	struct instruction *insn;
	struct section *sec;
	int idx;

	sec = find_section_by_name(file->elf, "__mcount_loc");
	if (sec) {
		/*
		 * Livepatch modules have already extracted their __mcount_loc
		 * entries to cover the !CONFIG_FTRACE_MCOUNT_USE_OBJTOOL case.
		 */
		if (!file->klp)
			WARN("file already has __mcount_loc section, skipping");

		return 0;
	}

	if (list_empty(&file->mcount_loc_list))
		return 0;

	idx = 0;
	list_for_each_entry(insn, &file->mcount_loc_list, call_node)
		idx++;

	sec = elf_create_section_pair(file->elf, "__mcount_loc", addr_size,
				      idx, idx);
	if (!sec)
		return -1;

	sec->sh.sh_addralign = addr_size;

	idx = 0;
	list_for_each_entry(insn, &file->mcount_loc_list, call_node) {

		struct reloc *reloc;

		reloc = elf_init_reloc_text_sym(file->elf, sec, idx * addr_size, idx,
					       insn->sec, insn->offset);
		if (!reloc)
			return -1;

		set_reloc_type(file->elf, reloc, addr_size == 8 ? R_ABS64 : R_ABS32);

		idx++;
	}

	return 0;
}

static int create_direct_call_sections(struct objtool_file *file)
{
	struct instruction *insn;
	struct section *sec;
	int idx;

	sec = find_section_by_name(file->elf, ".call_sites");
	if (sec) {
		WARN("file already has .call_sites section, skipping");
		return 0;
	}

	if (list_empty(&file->call_list))
		return 0;

	idx = 0;
	list_for_each_entry(insn, &file->call_list, call_node)
		idx++;

	sec = elf_create_section_pair(file->elf, ".call_sites",
				      sizeof(unsigned int), idx, idx);
	if (!sec)
		return -1;

	idx = 0;
	list_for_each_entry(insn, &file->call_list, call_node) {

		if (!elf_init_reloc_text_sym(file->elf, sec,
					     idx * sizeof(unsigned int), idx,
					     insn->sec, insn->offset))
			return -1;

		idx++;
	}

	return 0;
}

#ifdef BUILD_KLP
static int create_sym_checksum_section(struct objtool_file *file)
{
	struct section *sec;
	struct symbol *sym;
	unsigned int idx = 0;
	struct sym_checksum *checksum;
	size_t entsize = sizeof(struct sym_checksum);

	sec = find_section_by_name(file->elf, ".discard.sym_checksum");
	if (sec) {
		if (!opts.dryrun)
			WARN("file already has .discard.sym_checksum section, skipping");

		return 0;
	}

	for_each_sym(file->elf, sym)
		if (sym->csum.checksum)
			idx++;

	if (!idx)
		return 0;

	sec = elf_create_section_pair(file->elf, ".discard.sym_checksum", entsize,
				      idx, idx);
	if (!sec)
		return -1;

	idx = 0;
	for_each_sym(file->elf, sym) {
		if (!sym->csum.checksum)
			continue;

		if (!elf_init_reloc(file->elf, sec->rsec, idx, idx * entsize,
				    sym, 0, R_TEXT64))
			return -1;

		checksum = (struct sym_checksum *)sec->data->d_buf + idx;
		checksum->addr = 0; /* reloc */
		checksum->checksum = sym->csum.checksum;

		mark_sec_changed(file->elf, sec, true);

		idx++;
	}

	return 0;
}
#else
static int create_sym_checksum_section(struct objtool_file *file) { return -EINVAL; }
#endif

/*
 * Warnings shouldn't be reported for ignored functions.
 */
static int add_ignores(struct objtool_file *file)
{
	struct section *rsec;
	struct symbol *func;
	struct reloc *reloc;

	rsec = find_section_by_name(file->elf, ".rela.discard.func_stack_frame_non_standard");
	if (!rsec)
		return 0;

	for_each_reloc(rsec, reloc) {
		switch (reloc->sym->type) {
		case STT_FUNC:
			func = reloc->sym;
			break;

		case STT_SECTION:
			func = find_func_by_offset(reloc->sym->sec, reloc_addend(reloc));
			if (!func)
				continue;
			break;

		default:
			ERROR("unexpected relocation symbol type in %s: %d",
			      rsec->name, reloc->sym->type);
			return -1;
		}

		func->ignore = true;
		if (func->cfunc)
			func->cfunc->ignore = true;
	}

	return 0;
}

/*
 * This is a whitelist of functions that is allowed to be called with AC set.
 * The list is meant to be minimal and only contains compiler instrumentation
 * ABI and a few functions used to implement *_{to,from}_user() functions.
 *
 * These functions must not directly change AC, but may PUSHF/POPF.
 */
static const char *uaccess_safe_builtin[] = {
	/* RAP's compiler entry/return and local-jump adapters preserve AC.
	 * The indirect-call adapter deliberately is not safe: an opaque target
	 * is subject to the same UACCESS restriction as an ordinary indirect call.
	 */
	"__hdn_rap_enter",
	"__hdn_rap_enter_flags",
	"__hdn_rap_return",
	"__hdn_rap_jump",
	"__hdn_rap_graph_return",
	"__hdn_rap_rethook_return",
	"__hdn_rap_transfer",
	"__hdn_rap_static_null",
	"__hdn_rap_bpf_jump",
	"__hdn_rap_bpf_boundary",
	"__hdn_rap_bpf_exception",
	/* KASAN */
	"kasan_report",
	"kasan_check_range",
	/* KASAN out-of-line */
	"__asan_loadN_noabort",
	"__asan_load1_noabort",
	"__asan_load2_noabort",
	"__asan_load4_noabort",
	"__asan_load8_noabort",
	"__asan_load16_noabort",
	"__asan_storeN_noabort",
	"__asan_store1_noabort",
	"__asan_store2_noabort",
	"__asan_store4_noabort",
	"__asan_store8_noabort",
	"__asan_store16_noabort",
	"__kasan_check_read",
	"__kasan_check_write",
	/* KASAN in-line */
	"__asan_report_load_n_noabort",
	"__asan_report_load1_noabort",
	"__asan_report_load2_noabort",
	"__asan_report_load4_noabort",
	"__asan_report_load8_noabort",
	"__asan_report_load16_noabort",
	"__asan_report_store_n_noabort",
	"__asan_report_store1_noabort",
	"__asan_report_store2_noabort",
	"__asan_report_store4_noabort",
	"__asan_report_store8_noabort",
	"__asan_report_store16_noabort",
	/* KCSAN */
	"__kcsan_check_access",
	"__kcsan_mb",
	"__kcsan_wmb",
	"__kcsan_rmb",
	"__kcsan_release",
	"kcsan_found_watchpoint",
	"kcsan_setup_watchpoint",
	"kcsan_check_scoped_accesses",
	"kcsan_disable_current",
	"kcsan_enable_current_nowarn",
	/* KCSAN/TSAN */
	"__tsan_func_entry",
	"__tsan_func_exit",
	"__tsan_read_range",
	"__tsan_write_range",
	"__tsan_read1",
	"__tsan_read2",
	"__tsan_read4",
	"__tsan_read8",
	"__tsan_read16",
	"__tsan_write1",
	"__tsan_write2",
	"__tsan_write4",
	"__tsan_write8",
	"__tsan_write16",
	"__tsan_read_write1",
	"__tsan_read_write2",
	"__tsan_read_write4",
	"__tsan_read_write8",
	"__tsan_read_write16",
	"__tsan_volatile_read1",
	"__tsan_volatile_read2",
	"__tsan_volatile_read4",
	"__tsan_volatile_read8",
	"__tsan_volatile_read16",
	"__tsan_volatile_write1",
	"__tsan_volatile_write2",
	"__tsan_volatile_write4",
	"__tsan_volatile_write8",
	"__tsan_volatile_write16",
	"__tsan_atomic8_load",
	"__tsan_atomic16_load",
	"__tsan_atomic32_load",
	"__tsan_atomic64_load",
	"__tsan_atomic8_store",
	"__tsan_atomic16_store",
	"__tsan_atomic32_store",
	"__tsan_atomic64_store",
	"__tsan_atomic8_exchange",
	"__tsan_atomic16_exchange",
	"__tsan_atomic32_exchange",
	"__tsan_atomic64_exchange",
	"__tsan_atomic8_fetch_add",
	"__tsan_atomic16_fetch_add",
	"__tsan_atomic32_fetch_add",
	"__tsan_atomic64_fetch_add",
	"__tsan_atomic8_fetch_sub",
	"__tsan_atomic16_fetch_sub",
	"__tsan_atomic32_fetch_sub",
	"__tsan_atomic64_fetch_sub",
	"__tsan_atomic8_fetch_and",
	"__tsan_atomic16_fetch_and",
	"__tsan_atomic32_fetch_and",
	"__tsan_atomic64_fetch_and",
	"__tsan_atomic8_fetch_or",
	"__tsan_atomic16_fetch_or",
	"__tsan_atomic32_fetch_or",
	"__tsan_atomic64_fetch_or",
	"__tsan_atomic8_fetch_xor",
	"__tsan_atomic16_fetch_xor",
	"__tsan_atomic32_fetch_xor",
	"__tsan_atomic64_fetch_xor",
	"__tsan_atomic8_fetch_nand",
	"__tsan_atomic16_fetch_nand",
	"__tsan_atomic32_fetch_nand",
	"__tsan_atomic64_fetch_nand",
	"__tsan_atomic8_compare_exchange_strong",
	"__tsan_atomic16_compare_exchange_strong",
	"__tsan_atomic32_compare_exchange_strong",
	"__tsan_atomic64_compare_exchange_strong",
	"__tsan_atomic8_compare_exchange_weak",
	"__tsan_atomic16_compare_exchange_weak",
	"__tsan_atomic32_compare_exchange_weak",
	"__tsan_atomic64_compare_exchange_weak",
	"__tsan_atomic8_compare_exchange_val",
	"__tsan_atomic16_compare_exchange_val",
	"__tsan_atomic32_compare_exchange_val",
	"__tsan_atomic64_compare_exchange_val",
	"__tsan_atomic_thread_fence",
	"__tsan_atomic_signal_fence",
	"__tsan_unaligned_read16",
	"__tsan_unaligned_write16",
	/* KCOV */
	"write_comp_data",
	"check_kcov_mode",
	"__sanitizer_cov_trace_pc",
	"__sanitizer_cov_trace_const_cmp1",
	"__sanitizer_cov_trace_const_cmp2",
	"__sanitizer_cov_trace_const_cmp4",
	"__sanitizer_cov_trace_const_cmp8",
	"__sanitizer_cov_trace_cmp1",
	"__sanitizer_cov_trace_cmp2",
	"__sanitizer_cov_trace_cmp4",
	"__sanitizer_cov_trace_cmp8",
	"__sanitizer_cov_trace_switch",
	/* KMSAN */
	"kmsan_copy_to_user",
	"kmsan_disable_current",
	"kmsan_enable_current",
	"kmsan_report",
	"kmsan_unpoison_entry_regs",
	"kmsan_unpoison_memory",
	"__msan_chain_origin",
	"__msan_get_context_state",
	"__msan_instrument_asm_store",
	"__msan_metadata_ptr_for_load_1",
	"__msan_metadata_ptr_for_load_2",
	"__msan_metadata_ptr_for_load_4",
	"__msan_metadata_ptr_for_load_8",
	"__msan_metadata_ptr_for_load_n",
	"__msan_metadata_ptr_for_store_1",
	"__msan_metadata_ptr_for_store_2",
	"__msan_metadata_ptr_for_store_4",
	"__msan_metadata_ptr_for_store_8",
	"__msan_metadata_ptr_for_store_n",
	"__msan_poison_alloca",
	"__msan_warning",
	/* UBSAN */
	"__ubsan_handle_type_mismatch",
	"__ubsan_handle_type_mismatch_v1",
	"__ubsan_handle_shift_out_of_bounds",
	"__ubsan_handle_load_invalid_value",
	/* KSTACK_ERASE */
	"__sanitizer_cov_stack_depth",
	/* TRACE_BRANCH_PROFILING */
	"ftrace_likely_update",
	/* STACKPROTECTOR */
	"__stack_chk_fail",
	/* misc */
	"csum_partial_copy_generic",
	"copy_mc_fragile",
	"copy_mc_fragile_handle_tail",
	"copy_mc_enhanced_fast_string",
	"rep_stos_alternative",
	"rep_movs_alternative",
	"copy_to_nontemporal",
	NULL
};

static void add_uaccess_safe(struct objtool_file *file)
{
	struct symbol *func;
	const char **name;

	if (!opts.uaccess)
		return;

	for (name = uaccess_safe_builtin; *name; name++) {
		func = find_symbol_by_name(file->elf, *name);
		if (!func)
			continue;

		func->uaccess_safe = true;
	}
}

/*
 * Symbols that replace INSN_CALL_DYNAMIC, every (tail) call to such a symbol
 * will be added to the .retpoline_sites section.
 */
__weak bool arch_is_retpoline(struct symbol *sym)
{
	return false;
}

/*
 * Symbols that replace INSN_RETURN, every (tail) call to such a symbol
 * will be added to the .return_sites section.
 */
__weak bool arch_is_rethunk(struct symbol *sym)
{
	return false;
}

/*
 * Symbols that are embedded inside other instructions, because sometimes crazy
 * code exists. These are mostly ignored for validation purposes.
 */
__weak bool arch_is_embedded_insn(struct symbol *sym)
{
	return false;
}

static struct reloc *insn_reloc(struct objtool_file *file, struct instruction *insn)
{
	struct reloc *reloc;

	if (insn->no_reloc)
		return NULL;

	if (!file)
		return NULL;

	reloc = find_reloc_by_dest_range(file->elf, insn->sec,
					 insn->offset, insn->len);
	if (!reloc) {
		insn->no_reloc = 1;
		return NULL;
	}

	return reloc;
}

static void remove_insn_ops(struct instruction *insn)
{
	struct stack_op *op, *next;

	for (op = insn->stack_ops; op; op = next) {
		next = op->next;
		free(op);
	}
	insn->stack_ops = NULL;
}

static int annotate_call_site(struct objtool_file *file,
			       struct instruction *insn, bool sibling)
{
	struct reloc *reloc = insn_reloc(file, insn);
	struct symbol *sym = insn_call_dest(insn);

	if (!sym)
		sym = reloc->sym;

	if (sym->static_call_tramp) {
		list_add_tail(&insn->call_node, &file->static_call_list);
		return 0;
	}

	if (sym->retpoline_thunk) {
		list_add_tail(&insn->call_node, &file->retpoline_call_list);
		return 0;
	}

	/*
	 * Many compilers cannot disable KCOV or sanitizer calls with a function
	 * attribute so they need a little help, NOP out any such calls from
	 * noinstr text.
	 */
	if (opts.hack_noinstr && insn->sec->noinstr && sym->profiling_func) {
		if (reloc)
			set_reloc_type(file->elf, reloc, R_NONE);

		if (elf_write_insn(file->elf, insn->sec,
				   insn->offset, insn->len,
				   sibling ? arch_ret_insn(insn->len)
					   : arch_nop_insn(insn->len))) {
			return -1;
		}

		insn->type = sibling ? INSN_RETURN : INSN_NOP;

		if (sibling) {
			/*
			 * We've replaced the tail-call JMP insn by two new
			 * insn: RET; INT3, except we only have a single struct
			 * insn here. Mark it retpoline_safe to avoid the SLS
			 * warning, instead of adding another insn.
			 */
			insn->retpoline_safe = true;
		}

		return 0;
	}

	if (opts.mcount && sym->fentry) {
		if (sibling)
			WARN_INSN(insn, "tail call to __fentry__ !?!?");
		if (opts.mnop) {
			if (reloc)
				set_reloc_type(file->elf, reloc, R_NONE);

			if (elf_write_insn(file->elf, insn->sec,
					   insn->offset, insn->len,
					   arch_nop_insn(insn->len))) {
				return -1;
			}

			insn->type = INSN_NOP;
		}

		list_add_tail(&insn->call_node, &file->mcount_loc_list);
		return 0;
	}

	if (insn->type == INSN_CALL && !insn->sec->init &&
	    !insn->_call_dest->embedded_insn)
		list_add_tail(&insn->call_node, &file->call_list);

	if (!sibling && dead_end_function(file, sym))
		insn->dead_end = true;

	return 0;
}

static int add_call_dest(struct objtool_file *file, struct instruction *insn,
			  struct symbol *dest, bool sibling)
{
	insn->_call_dest = dest;
	if (!dest)
		return 0;

	/*
	 * Whatever stack impact regular CALLs have, should be undone
	 * by the RETURN of the called function.
	 *
	 * Annotated intra-function calls retain the stack_ops but
	 * are converted to JUMP, see read_intra_function_calls().
	 */
	remove_insn_ops(insn);

	return annotate_call_site(file, insn, sibling);
}

static int add_retpoline_call(struct objtool_file *file, struct instruction *insn)
{
	/*
	 * Retpoline calls/jumps are really dynamic calls/jumps in disguise,
	 * so convert them accordingly.
	 */
	switch (insn->type) {
	case INSN_CALL:
		insn->type = INSN_CALL_DYNAMIC;
		break;
	case INSN_JUMP_UNCONDITIONAL:
		insn->type = INSN_JUMP_DYNAMIC;
		break;
	case INSN_JUMP_CONDITIONAL:
		insn->type = INSN_JUMP_DYNAMIC_CONDITIONAL;
		break;
	default:
		return 0;
	}

	insn->retpoline_safe = true;

	/*
	 * Whatever stack impact regular CALLs have, should be undone
	 * by the RETURN of the called function.
	 *
	 * Annotated intra-function calls retain the stack_ops but
	 * are converted to JUMP, see read_intra_function_calls().
	 */
	remove_insn_ops(insn);

	return annotate_call_site(file, insn, false);
}

static void add_return_call(struct objtool_file *file, struct instruction *insn, bool add)
{
	/*
	 * Return thunk tail calls are really just returns in disguise,
	 * so convert them accordingly.
	 */
	insn->type = INSN_RETURN;
	insn->retpoline_safe = true;

	if (add)
		list_add_tail(&insn->call_node, &file->return_thunk_list);
}

static bool is_first_func_insn(struct objtool_file *file,
			       struct instruction *insn)
{
	struct symbol *func = insn_func(insn);

	if (!func)
		return false;

	if (insn->offset == func->offset)
		return true;

	/* Allow direct CALL/JMP past ENDBR */
	if (opts.ibt) {
		struct instruction *prev = prev_insn_same_sym(file, insn);

		if (prev && prev->type == INSN_ENDBR &&
		    insn->offset == func->offset + prev->len)
			return true;
	}

	return false;
}

/*
 * Find the destination instructions for all jumps.
 */
static int add_jump_destinations(struct objtool_file *file)
{
	struct instruction *insn;
	struct reloc *reloc;

	for_each_insn(file, insn) {
		struct symbol *func = insn_func(insn);
		struct instruction *dest_insn;
		struct section *dest_sec;
		struct symbol *dest_sym;
		unsigned long dest_off;

		if (!is_static_jump(insn))
			continue;

		if (insn->jump_dest) {
			/*
			 * handle_group_alt() may have previously set
			 * 'jump_dest' for some alternatives.
			 */
			continue;
		}

		reloc = insn_reloc(file, insn);
		if (!reloc) {
			dest_sec = insn->sec;
			dest_off = arch_jump_destination(insn);
			dest_sym = dest_sec->sym;
		} else {
			dest_sym = reloc->sym;
			if (is_undef_sym(dest_sym)) {
				if (!strcmp(dest_sym->name, "__hdn_rap_return")) {
					add_return_call(file, insn, false);
					insn->rap_return = true;
					continue;
				}
				if (dest_sym->retpoline_thunk) {
					if (add_retpoline_call(file, insn))
						return -1;
					continue;
				}

				if (dest_sym->return_thunk) {
					add_return_call(file, insn, true);
					continue;
				}

				/* External symbol */
				if (func) {
					/* External sibling call */
					if (add_call_dest(file, insn, dest_sym, true))
						return -1;
					continue;
				}

				/* Non-func asm code jumping to external symbol */
				continue;
			}

			dest_sec = dest_sym->sec;
			dest_off = dest_sym->offset + arch_insn_adjusted_addend(insn, reloc);
		}

		dest_insn = find_insn(file, dest_sec, dest_off);
		if (!dest_insn) {
			struct symbol *sym = find_symbol_by_offset(dest_sec, dest_off);

			/*
			 * retbleed_untrain_ret() jumps to
			 * __x86_return_thunk(), but objtool can't find
			 * the thunk's starting RET instruction,
			 * because the RET is also in the middle of
			 * another instruction.  Objtool only knows
			 * about the outer instruction.
			 */
			if (sym && sym->embedded_insn) {
				add_return_call(file, insn, false);
				continue;
			}

			/*
			 * GCOV/KCOV dead code can jump to the end of
			 * the function/section.
			 */
			if (file->ignore_unreachables && func &&
			    dest_sec == insn->sec &&
			    dest_off == func->offset + func->len)
				continue;

			ERROR_INSN(insn, "can't find jump dest instruction at %s",
				   offstr(dest_sec, dest_off));
			return -1;
		}

		if (!dest_sym || is_sec_sym(dest_sym)) {
			dest_sym = dest_insn->sym;
			if (!dest_sym)
				goto set_jump_dest;
		}

		if (dest_sym->retpoline_thunk && dest_insn->offset == dest_sym->offset) {
			if (add_retpoline_call(file, insn))
				return -1;
			continue;
		}

		if (dest_sym->return_thunk && dest_insn->offset == dest_sym->offset) {
			add_return_call(file, insn, true);
			continue;
		}
		if (!strcmp(dest_sym->name, "__hdn_rap_return") && dest_insn->offset == dest_sym->offset) {
			add_return_call(file, insn, false);
			insn->rap_return = true;
			continue;
		}

		if (!insn->sym || insn->sym->pfunc == dest_sym->pfunc)
			goto set_jump_dest;

		/*
		 * Internal cross-function jump.
		 */

		if (is_first_func_insn(file, dest_insn)) {
			/* Internal sibling call */
			if (add_call_dest(file, insn, dest_sym, true))
				return -1;
			continue;
		}

set_jump_dest:
		insn->jump_dest = dest_insn;
	}

	return 0;
}

static struct symbol *find_call_destination(struct section *sec, unsigned long offset)
{
	struct symbol *call_dest;

	call_dest = find_func_by_offset(sec, offset);
	if (!call_dest)
		call_dest = find_symbol_by_offset(sec, offset);

	return call_dest;
}

/*
 * Find the destination instructions for all calls.
 */
static int add_call_destinations(struct objtool_file *file)
{
	struct instruction *insn;
	unsigned long dest_off;
	struct symbol *dest;
	struct reloc *reloc;

	for_each_insn(file, insn) {
		struct symbol *func = insn_func(insn);
		if (insn->type != INSN_CALL)
			continue;

		reloc = insn_reloc(file, insn);
		if (!reloc) {
			dest_off = arch_jump_destination(insn);
			dest = find_call_destination(insn->sec, dest_off);

			if (add_call_dest(file, insn, dest, false))
				return -1;

			if (func && func->ignore)
				continue;

			if (!insn_call_dest(insn)) {
				ERROR_INSN(insn, "unannotated intra-function call");
				return -1;
			}

			if (func && !is_func_sym(insn_call_dest(insn))) {
				ERROR_INSN(insn, "unsupported call to non-function");
				return -1;
			}

		} else if (is_sec_sym(reloc->sym)) {
			dest_off = arch_insn_adjusted_addend(insn, reloc);
			dest = find_call_destination(reloc->sym->sec, dest_off);
			if (!dest) {
				ERROR_INSN(insn, "can't find call dest symbol at %s+0x%lx",
					   reloc->sym->sec->name, dest_off);
				return -1;
			}

			if (add_call_dest(file, insn, dest, false))
				return -1;

		} else if (reloc->sym->retpoline_thunk) {
			if (add_retpoline_call(file, insn))
				return -1;

		} else {
			if (add_call_dest(file, insn, reloc->sym, false))
				return -1;
		}
	}

	return 0;
}

/*
 * The .alternatives section requires some extra special care over and above
 * other special sections because alternatives are patched in place.
 */
static int handle_group_alt(struct objtool_file *file,
			    struct special_alt *special_alt,
			    struct instruction *orig_insn,
			    struct instruction **new_insn)
{
	struct instruction *last_new_insn = NULL, *insn, *nop = NULL;
	struct alt_group *orig_alt_group, *new_alt_group;
	unsigned long dest_off;

	orig_alt_group = orig_insn->alt_group;
	if (!orig_alt_group) {
		struct instruction *last_orig_insn = NULL;

		orig_alt_group = calloc(1, sizeof(*orig_alt_group));
		if (!orig_alt_group) {
			ERROR_GLIBC("calloc");
			return -1;
		}
		orig_alt_group->cfi = calloc(special_alt->orig_len,
					     sizeof(struct cfi_state *));
		if (!orig_alt_group->cfi) {
			ERROR_GLIBC("calloc");
			return -1;
		}

		insn = orig_insn;
		sec_for_each_insn_from(file, insn) {
			if (insn->offset >= special_alt->orig_off + special_alt->orig_len)
				break;

			insn->alt_group = orig_alt_group;
			last_orig_insn = insn;
		}
		orig_alt_group->orig_group = NULL;
		orig_alt_group->first_insn = orig_insn;
		orig_alt_group->last_insn = last_orig_insn;
		orig_alt_group->nop = NULL;
		orig_alt_group->ignore = orig_insn->ignore_alts;
		orig_alt_group->feature = 0;
	} else {
		if (orig_alt_group->last_insn->offset + orig_alt_group->last_insn->len -
		    orig_alt_group->first_insn->offset != special_alt->orig_len) {
			ERROR_INSN(orig_insn, "weirdly overlapping alternative! %ld != %d",
				   orig_alt_group->last_insn->offset +
				   orig_alt_group->last_insn->len -
				   orig_alt_group->first_insn->offset,
				   special_alt->orig_len);
			return -1;
		}
	}

	new_alt_group = calloc(1, sizeof(*new_alt_group));
	if (!new_alt_group) {
		ERROR_GLIBC("calloc");
		return -1;
	}

	if (special_alt->new_len < special_alt->orig_len) {
		/*
		 * Insert a fake nop at the end to make the replacement
		 * alt_group the same size as the original.  This is needed to
		 * allow propagate_alt_cfi() to do its magic.  When the last
		 * instruction affects the stack, the instruction after it (the
		 * nop) will propagate the new state to the shared CFI array.
		 */
		nop = calloc(1, sizeof(*nop));
		if (!nop) {
			ERROR_GLIBC("calloc");
			return -1;
		}
		memset(nop, 0, sizeof(*nop));

		nop->sec = special_alt->new_sec;
		nop->offset = special_alt->new_off + special_alt->new_len;
		nop->len = special_alt->orig_len - special_alt->new_len;
		nop->type = INSN_NOP;
		nop->sym = orig_insn->sym;
		nop->alt_group = new_alt_group;
		nop->fake = 1;
	}

	if (!special_alt->new_len) {
		*new_insn = nop;
		goto end;
	}

	insn = *new_insn;
	sec_for_each_insn_from(file, insn) {
		struct reloc *alt_reloc;

		if (insn->offset >= special_alt->new_off + special_alt->new_len)
			break;

		last_new_insn = insn;

		insn->sym = orig_insn->sym;
		insn->alt_group = new_alt_group;

		/*
		 * Since alternative replacement code is copy/pasted by the
		 * kernel after applying relocations, generally such code can't
		 * have relative-address relocation references to outside the
		 * .altinstr_replacement section, unless the arch's
		 * alternatives code can adjust the relative offsets
		 * accordingly.
		 */
		alt_reloc = insn_reloc(file, insn);
		if (alt_reloc && arch_pc_relative_reloc(alt_reloc) &&
		    !arch_support_alt_relocation(special_alt, insn, alt_reloc)) {

			ERROR_INSN(insn, "unsupported relocation in alternatives section");
			return -1;
		}

		if (!is_static_jump(insn))
			continue;

		if (!insn->immediate)
			continue;

		dest_off = arch_jump_destination(insn);
		if (dest_off == special_alt->new_off + special_alt->new_len) {
			insn->jump_dest = next_insn_same_sec(file, orig_alt_group->last_insn);
			if (!insn->jump_dest) {
				ERROR_INSN(insn, "can't find alternative jump destination");
				return -1;
			}
		}
	}

	if (!last_new_insn) {
		ERROR_FUNC(special_alt->new_sec, special_alt->new_off,
			   "can't find last new alternative instruction");
		return -1;
	}

end:
	new_alt_group->orig_group = orig_alt_group;
	new_alt_group->first_insn = *new_insn;
	new_alt_group->last_insn = last_new_insn;
	new_alt_group->nop = nop;
	new_alt_group->ignore = (*new_insn)->ignore_alts;
	new_alt_group->cfi = orig_alt_group->cfi;
	new_alt_group->feature = special_alt->feature;
	return 0;
}

/*
 * A jump table entry can either convert a nop to a jump or a jump to a nop.
 * If the original instruction is a jump, make the alt entry an effective nop
 * by just skipping the original instruction.
 */
static int handle_jump_alt(struct objtool_file *file,
			   struct special_alt *special_alt,
			   struct instruction *orig_insn,
			   struct instruction **new_insn)
{
	if (orig_insn->type != INSN_JUMP_UNCONDITIONAL &&
	    orig_insn->type != INSN_NOP) {

		ERROR_INSN(orig_insn, "unsupported instruction at jump label");
		return -1;
	}

	if (opts.hack_jump_label && special_alt->key_addend & 2) {
		struct reloc *reloc = insn_reloc(file, orig_insn);

		if (reloc)
			set_reloc_type(file->elf, reloc, R_NONE);

		if (elf_write_insn(file->elf, orig_insn->sec,
				   orig_insn->offset, orig_insn->len,
				   arch_nop_insn(orig_insn->len))) {
			return -1;
		}

		orig_insn->type = INSN_NOP;
	}

	if (orig_insn->type == INSN_NOP) {
		if (orig_insn->len == 2)
			file->jl_nop_short++;
		else
			file->jl_nop_long++;

		return 0;
	}

	if (orig_insn->len == 2)
		file->jl_short++;
	else
		file->jl_long++;

	*new_insn = next_insn_same_sec(file, orig_insn);
	return 0;
}

/*
 * Read all the special sections which have alternate instructions which can be
 * patched in or redirected to at runtime.  Each instruction having alternate
 * instruction(s) has them added to its insn->alts list, which will be
 * traversed in validate_branch().
 */
static int add_special_section_alts(struct objtool_file *file)
{
	struct list_head special_alts;
	struct instruction *orig_insn, *new_insn;
	struct special_alt *special_alt, *tmp;
	enum alternative_type alt_type;
	struct alternative *alt;
	struct alternative *a;

	if (special_get_alts(file->elf, &special_alts))
		return -1;

	list_for_each_entry_safe(special_alt, tmp, &special_alts, list) {

		orig_insn = find_insn(file, special_alt->orig_sec,
				      special_alt->orig_off);
		if (!orig_insn) {
			ERROR_FUNC(special_alt->orig_sec, special_alt->orig_off,
				   "special: can't find orig instruction");
			return -1;
		}

		new_insn = NULL;
		if (!special_alt->group || special_alt->new_len) {
			new_insn = find_insn(file, special_alt->new_sec,
					     special_alt->new_off);
			if (!new_insn) {
				ERROR_FUNC(special_alt->new_sec, special_alt->new_off,
					   "special: can't find new instruction");
				return -1;
			}
		}

		if (special_alt->group) {
			if (!special_alt->orig_len) {
				ERROR_INSN(orig_insn, "empty alternative entry");
				continue;
			}

			if (handle_group_alt(file, special_alt, orig_insn, &new_insn))
				return -1;

			alt_type = ALT_TYPE_INSTRUCTIONS;

		} else if (special_alt->jump_or_nop) {
			if (handle_jump_alt(file, special_alt, orig_insn, &new_insn))
				return -1;

			alt_type = ALT_TYPE_JUMP_TABLE;
		} else {
			alt_type = ALT_TYPE_EX_TABLE;
		}

		alt = calloc(1, sizeof(*alt));
		if (!alt) {
			ERROR_GLIBC("calloc");
			return -1;
		}

		alt->insn = new_insn;
		alt->type = alt_type;
		alt->next = NULL;

		/*
		 * Store alternatives in the same order they have been
		 * defined.
		 */
		if (!orig_insn->alts) {
			orig_insn->alts = alt;
		} else {
			for (a = orig_insn->alts; a->next; a = a->next)
				;
			a->next = alt;
		}

		list_del(&special_alt->list);
		free(special_alt);
	}

	if (opts.stats) {
		printf("jl\\\tNOP\tJMP\n");
		printf("short:\t%ld\t%ld\n", file->jl_nop_short, file->jl_short);
		printf("long:\t%ld\t%ld\n", file->jl_nop_long, file->jl_long);
	}

	return 0;
}

__weak unsigned long arch_jump_table_sym_offset(struct reloc *reloc, struct reloc *table)
{
	return reloc->sym->offset + reloc_addend(reloc);
}

static int add_jump_table(struct objtool_file *file, struct instruction *insn)
{
	unsigned long table_size = insn_jump_table_size(insn);
	struct symbol *pfunc = insn_func(insn)->pfunc;
	struct reloc *table = insn_jump_table(insn);
	struct instruction *dest_insn;
	unsigned int prev_offset = 0;
	struct reloc *reloc = table;
	struct alternative *alt;
	unsigned long sym_offset;

	/*
	 * Each @reloc is a switch table relocation which points to the target
	 * instruction.
	 */
	for_each_reloc_from(table->sec, reloc) {

		/* Check for the end of the table: */
		if (table_size && reloc_offset(reloc) - reloc_offset(table) >= table_size)
			break;
		if (reloc != table && is_jump_table(reloc))
			break;

		/* Make sure the table entries are consecutive: */
		if (prev_offset && reloc_offset(reloc) != prev_offset + arch_reloc_size(reloc))
			break;

		sym_offset = arch_jump_table_sym_offset(reloc, table);

		/* Detect function pointers from contiguous objects: */
		if (reloc->sym->sec == pfunc->sec && sym_offset == pfunc->offset)
			break;

		/*
		 * Clang sometimes leaves dangling unused jump table entries
		 * which point to the end of the function.  Ignore them.
		 */
		if (reloc->sym->sec == pfunc->sec &&
		    sym_offset == pfunc->offset + pfunc->len)
			goto next;

		dest_insn = find_insn(file, reloc->sym->sec, sym_offset);
		if (!dest_insn)
			break;

		/* Make sure the destination is in the same function: */
		if (!insn_func(dest_insn) || insn_func(dest_insn)->pfunc != pfunc)
			break;

		alt = calloc(1, sizeof(*alt));
		if (!alt) {
			ERROR_GLIBC("calloc");
			return -1;
		}

		alt->insn = dest_insn;
		alt->next = insn->alts;
		insn->alts = alt;
next:
		prev_offset = reloc_offset(reloc);
	}

	if (!prev_offset) {
		ERROR_INSN(insn, "can't find switch jump table");
		return -1;
	}

	return 0;
}

/*
 * find_jump_table() - Given a dynamic jump, find the switch jump table
 * associated with it.
 */
static void find_jump_table(struct objtool_file *file, struct symbol *func,
			    struct instruction *insn)
{
	struct reloc *table_reloc;
	struct instruction *dest_insn, *orig_insn = insn;
	unsigned long table_size;
	unsigned long sym_offset;

	/*
	 * Backward search using the @first_jump_src links, these help avoid
	 * much of the 'in between' code. Which avoids us getting confused by
	 * it.
	 */
	for (;
	     insn && insn_func(insn) && insn_func(insn)->pfunc == func;
	     insn = insn->first_jump_src ?: prev_insn_same_sym(file, insn)) {

		if (insn != orig_insn && insn->type == INSN_JUMP_DYNAMIC)
			break;

		/* allow small jumps within the range */
		if (insn->type == INSN_JUMP_UNCONDITIONAL &&
		    insn->jump_dest &&
		    (insn->jump_dest->offset <= insn->offset ||
		     insn->jump_dest->offset > orig_insn->offset))
			break;

		table_reloc = arch_find_switch_table(file, insn, &table_size);
		if (!table_reloc)
			continue;

		sym_offset = table_reloc->sym->offset + reloc_addend(table_reloc);

		dest_insn = find_insn(file, table_reloc->sym->sec, sym_offset);
		if (!dest_insn || !insn_func(dest_insn) || insn_func(dest_insn)->pfunc != func)
			continue;

		set_jump_table(table_reloc);
		orig_insn->_jump_table = table_reloc;
		orig_insn->_jump_table_size = table_size;

		break;
	}
}

/*
 * First pass: Mark the head of each jump table so that in the next pass,
 * we know when a given jump table ends and the next one starts.
 */
static void mark_func_jump_tables(struct objtool_file *file,
				    struct symbol *func)
{
	struct instruction *insn, *last = NULL;

	func_for_each_insn(file, func, insn) {
		if (!last)
			last = insn;

		/*
		 * Store back-pointers for forward jumps such
		 * that find_jump_table() can back-track using those and
		 * avoid some potentially confusing code.
		 */
		if (insn->jump_dest &&
		    insn->jump_dest->offset > insn->offset &&
		    !insn->jump_dest->first_jump_src) {

			insn->jump_dest->first_jump_src = insn;
			last = insn->jump_dest;
		}

		if (insn->type != INSN_JUMP_DYNAMIC)
			continue;

		find_jump_table(file, func, insn);
	}
}

static int add_func_jump_tables(struct objtool_file *file,
				  struct symbol *func)
{
	struct instruction *insn;

	func_for_each_insn(file, func, insn) {
		if (!insn_jump_table(insn))
			continue;

		if (add_jump_table(file, insn))
			return -1;
	}

	return 0;
}

/*
 * For some switch statements, gcc generates a jump table in the .rodata
 * section which contains a list of addresses within the function to jump to.
 * This finds these jump tables and adds them to the insn->alts lists.
 */
static int add_jump_table_alts(struct objtool_file *file)
{
	struct symbol *func;

	if (!file->rodata)
		return 0;

	for_each_sym(file->elf, func) {
		if (!is_func_sym(func) || func->alias != func)
			continue;

		mark_func_jump_tables(file, func);
		if (add_func_jump_tables(file, func))
			return -1;
	}

	return 0;
}

static void set_func_state(struct cfi_state *state)
{
	state->cfa = initial_func_cfi.cfa;
	memcpy(&state->regs, &initial_func_cfi.regs,
	       CFI_NUM_REGS * sizeof(struct cfi_reg));
	state->stack_size = initial_func_cfi.cfa.offset;
	state->type = UNWIND_HINT_TYPE_CALL;
}

static int read_unwind_hints(struct objtool_file *file)
{
	struct cfi_state cfi = init_cfi;
	struct section *sec;
	struct unwind_hint *hint;
	struct instruction *insn;
	struct reloc *reloc;
	unsigned long offset;
	int i;

	sec = find_section_by_name(file->elf, ".discard.unwind_hints");
	if (!sec)
		return 0;

	if (!sec->rsec) {
		ERROR("missing .rela.discard.unwind_hints section");
		return -1;
	}

	if (sec_size(sec) % sizeof(struct unwind_hint)) {
		ERROR("struct unwind_hint size mismatch");
		return -1;
	}

	file->hints = true;

	for (i = 0; i < sec_size(sec) / sizeof(struct unwind_hint); i++) {
		hint = (struct unwind_hint *)sec->data->d_buf + i;

		reloc = find_reloc_by_dest(file->elf, sec, i * sizeof(*hint));
		if (!reloc) {
			ERROR("can't find reloc for unwind_hints[%d]", i);
			return -1;
		}

		offset = reloc->sym->offset + reloc_addend(reloc);

		insn = find_insn(file, reloc->sym->sec, offset);
		if (!insn) {
			ERROR("can't find insn for unwind_hints[%d]", i);
			return -1;
		}

		insn->hint = true;

		if (hint->type == UNWIND_HINT_TYPE_UNDEFINED) {
			insn->cfi = &force_undefined_cfi;
			continue;
		}

		if (hint->type == UNWIND_HINT_TYPE_SAVE) {
			insn->hint = false;
			insn->save = true;
			continue;
		}

		if (hint->type == UNWIND_HINT_TYPE_RESTORE) {
			insn->restore = true;
			continue;
		}

		if (hint->type == UNWIND_HINT_TYPE_REGS_PARTIAL) {
			struct symbol *sym = find_symbol_by_offset(insn->sec, insn->offset);

			if (sym && is_global_sym(sym)) {
				if (opts.ibt && insn->type != INSN_ENDBR && !insn->noendbr) {
					ERROR_INSN(insn, "UNWIND_HINT_IRET_REGS without ENDBR");
					return -1;
				}
			}
		}

		if (hint->type == UNWIND_HINT_TYPE_FUNC) {
			insn->cfi = &func_cfi;
			continue;
		}

		if (insn->cfi)
			cfi = *(insn->cfi);

		if (arch_decode_hint_reg(hint->sp_reg, &cfi.cfa.base)) {
			ERROR_INSN(insn, "unsupported unwind_hint sp base reg %d", hint->sp_reg);
			return -1;
		}

		cfi.cfa.offset = bswap_if_needed(file->elf, hint->sp_offset);
		cfi.type = hint->type;
		cfi.signal = hint->signal;

		insn->cfi = cfi_hash_find_or_add(&cfi);
	}

	return 0;
}

static int read_annotate(struct objtool_file *file,
			 int (*func)(struct objtool_file *file, int type, struct instruction *insn))
{
	struct section *sec;
	struct instruction *insn;
	struct reloc *reloc;
	uint64_t offset;
	int type;

	sec = find_section_by_name(file->elf, ".discard.annotate_insn");
	if (!sec)
		return 0;

	if (!sec->rsec)
		return 0;

	if (sec->sh.sh_entsize != 8) {
		static bool warned = false;
		if (!warned && opts.verbose) {
			WARN("%s: dodgy linker, sh_entsize != 8", sec->name);
			warned = true;
		}
		sec->sh.sh_entsize = 8;
	}

	if (sec_num_entries(sec) != sec_num_entries(sec->rsec)) {
		ERROR("bad .discard.annotate_insn section: missing relocs");
		return -1;
	}

	for_each_reloc(sec->rsec, reloc) {
		type = annotype(file->elf, sec, reloc);
		offset = reloc->sym->offset + reloc_addend(reloc);
		insn = find_insn(file, reloc->sym->sec, offset);

		if (!insn) {
			ERROR("bad .discard.annotate_insn entry: %d of type %d", reloc_idx(reloc), type);
			return -1;
		}

		if (func(file, type, insn))
			return -1;
	}

	return 0;
}

static int __annotate_early(struct objtool_file *file, int type, struct instruction *insn)
{
	switch (type) {

	/* Must be before add_special_section_alts() */
	case ANNOTYPE_IGNORE_ALTS:
		insn->ignore_alts = true;
		break;

	/*
	 * Must be before read_unwind_hints() since that needs insn->noendbr.
	 */
	case ANNOTYPE_NOENDBR:
		insn->noendbr = 1;
		break;

	default:
		break;
	}

	return 0;
}

static int __annotate_ifc(struct objtool_file *file, int type, struct instruction *insn)
{
	unsigned long dest_off;

	if (type != ANNOTYPE_INTRA_FUNCTION_CALL)
		return 0;

	if (insn->type != INSN_CALL) {
		ERROR_INSN(insn, "intra_function_call not a direct call");
		return -1;
	}

	/*
	 * Treat intra-function CALLs as JMPs, but with a stack_op.
	 * See add_call_destinations(), which strips stack_ops from
	 * normal CALLs.
	 */
	insn->type = INSN_JUMP_UNCONDITIONAL;

	dest_off = arch_jump_destination(insn);
	insn->jump_dest = find_insn(file, insn->sec, dest_off);
	if (!insn->jump_dest) {
		ERROR_INSN(insn, "can't find call dest at %s+0x%lx",
			   insn->sec->name, dest_off);
		return -1;
	}

	return 0;
}

static int __annotate_late(struct objtool_file *file, int type, struct instruction *insn)
{
	struct symbol *sym;

	switch (type) {
	case ANNOTYPE_NOENDBR:
		/* early */
		break;

	case ANNOTYPE_RETPOLINE_SAFE:
		if (insn->type != INSN_JUMP_DYNAMIC &&
		    insn->type != INSN_CALL_DYNAMIC &&
		    insn->type != INSN_RETURN &&
		    insn->type != INSN_NOP) {
			ERROR_INSN(insn, "retpoline_safe hint not an indirect jump/call/ret/nop");
			return -1;
		}

		insn->retpoline_safe = true;
		break;

	case ANNOTYPE_INSTR_BEGIN:
		insn->instr++;
		break;

	case ANNOTYPE_INSTR_END:
		insn->instr--;
		break;

	case ANNOTYPE_UNRET_BEGIN:
		insn->unret = 1;
		break;

	case ANNOTYPE_IGNORE_ALTS:
		/* early */
		break;

	case ANNOTYPE_INTRA_FUNCTION_CALL:
		/* ifc */
		break;

	case ANNOTYPE_REACHABLE:
		insn->dead_end = false;
		break;

	case ANNOTYPE_NOCFI:
		sym = insn->sym;
		if (!sym) {
			ERROR_INSN(insn, "dodgy NOCFI annotation");
			return -1;
		}
		insn->sym->nocfi = 1;
		break;

	default:
		ERROR_INSN(insn, "Unknown annotation type: %d", type);
		return -1;
	}

	return 0;
}

/*
 * Return true if name matches an instrumentation function, where calls to that
 * function from noinstr code can safely be removed, but compilers won't do so.
 */
static bool is_profiling_func(const char *name)
{
	/*
	 * Many compilers cannot disable KCOV with a function attribute.
	 */
	if (!strncmp(name, "__sanitizer_cov_", 16))
		return true;

	return false;
}

static int classify_symbols(struct objtool_file *file)
{
	struct symbol *func;
	size_t len;

	for_each_sym(file->elf, func) {
		if (is_notype_sym(func) && strstarts(func->name, ".L"))
			func->local_label = true;

		if (!is_global_sym(func))
			continue;

		if (!strncmp(func->name, STATIC_CALL_TRAMP_PREFIX_STR,
			     strlen(STATIC_CALL_TRAMP_PREFIX_STR)))
			func->static_call_tramp = true;

		if (arch_is_retpoline(func))
			func->retpoline_thunk = true;

		if (arch_is_rethunk(func))
			func->return_thunk = true;

		if (arch_is_embedded_insn(func))
			func->embedded_insn = true;

		if (arch_ftrace_match(func->name))
			func->fentry = true;

		if (is_profiling_func(func->name))
			func->profiling_func = true;

		len = strlen(func->name);
		if (len > sym_name_max_len)
			sym_name_max_len = len;
	}

	return 0;
}

static void mark_rodata(struct objtool_file *file)
{
	struct section *sec;
	bool found = false;

	/*
	 * Search for the following rodata sections, each of which can
	 * potentially contain jump tables:
	 *
	 * - .rodata: can contain GCC switch tables
	 * - .rodata.<func>: same, if -fdata-sections is being used
	 * - .data.rel.ro.c_jump_table: contains C annotated jump tables
	 *
	 * .rodata.str1.* sections are ignored; they don't contain jump tables.
	 */
	for_each_sec(file->elf, sec) {
		if ((!strncmp(sec->name, ".rodata", 7) &&
		     !strstr(sec->name, ".str1.")) ||
		    !strncmp(sec->name, ".data.rel.ro", 12)) {
			sec->rodata = true;
			found = true;
		}
	}

	file->rodata = found;
}

static void mark_holes(struct objtool_file *file)
{
	struct instruction *insn;
	bool in_hole = false;

	if (!opts.link)
		return;

	/*
	 * Whole archive runs might encounter dead code from weak symbols.
	 * This is where the linker will have dropped the weak symbol in
	 * favour of a regular symbol, but leaves the code in place.
	 */
	for_each_insn(file, insn) {
		if (insn->sym || !find_symbol_hole_containing(insn->sec, insn->offset)) {
			in_hole = false;
			continue;
		}

		/* Skip function padding and pfx code */
		if (!in_hole && insn->type == INSN_NOP)
			continue;

		in_hole = true;
		insn->hole = 1;

		/*
		 * If this hole jumps to a .cold function, mark it ignore.
		 */
		if (insn->jump_dest) {
			struct symbol *dest_func = insn_func(insn->jump_dest);

			if (dest_func && dest_func->cold)
				dest_func->ignore = true;
		}
	}
}

static bool validate_branch_enabled(void)
{
	return opts.stackval ||
	       opts.rap ||
	       opts.orc ||
	       opts.uaccess ||
	       opts.checksum;
}

/* The RAP local-jump adapter consumes its CALL return slot before transferring
 * to a checked label in the same function. Model the net operation as a jump,
 * retaining every destination so ordinary stack/UACCESS validation follows it.
 * This section is compiler evidence, not a function-wide validation exemption.
 */
/* RAP covers explicitly sized special assembly entries as well as C
 * functions. Keep that interpretation separate from ORC's STT_FUNC rules. */
static struct symbol *rap_insn_owner(struct instruction *insn)
{
	struct symbol *sym = insn ? insn->sym : NULL;

	if (sym && sym->len && (is_func_sym(sym) || is_notype_sym(sym)))
		return sym;
	return NULL;
}

static struct instruction *rap_next_insn(struct objtool_file *file,
		struct symbol *func, struct instruction *insn)
{
	if (is_func_sym(func))
		return next_insn_same_func(file, insn);
	insn = next_insn_same_sec(file, insn);
	return insn && insn->sec == func->sec && insn->offset < func->offset + func->len ? insn : NULL;
}
#define rap_for_each_insn(file, func, insn) \
	for (insn = find_insn(file, func->sec, func->offset); insn; \
	     insn = rap_next_insn(file, func, insn))

static int read_rap_jumps(struct objtool_file *file)
{
	struct section *sec = find_section_by_name(file->elf, ".discard.hdn_rap_jumps");
	struct instruction *insn;
	unsigned long off;

	if (sec && (sec_size(sec) % 16 || !sec->rsec)) {
		ERROR("invalid RAP jump metadata");
		return -1;
	}
	for (off = 0; sec && off < sec_size(sec); off += 16) {
		struct reloc *from = find_reloc_by_dest(file->elf, sec, off);
		struct reloc *to = find_reloc_by_dest(file->elf, sec, off + 8);
		struct instruction *dest;
		struct alternative *alt;
		struct symbol *callee;

		if (!from || !to || arch_reloc_size(from) != 8 || arch_reloc_size(to) != 8) {
			ERROR("missing RAP jump relocation");
			return -1;
		}
		insn = find_insn(file, from->sym->sec, from->sym->offset + reloc_addend(from));
		dest = find_insn(file, to->sym->sec, to->sym->offset + reloc_addend(to));
		callee = insn && insn->type == INSN_CALL ? insn_call_dest(insn) : NULL;
		if (!callee || strcmp(callee->name, "__hdn_rap_jump") || !dest ||
		    !rap_insn_owner(insn) || !rap_insn_owner(dest) ||
		    rap_insn_owner(insn)->pfunc != rap_insn_owner(dest)->pfunc) {
			ERROR("RAP jump metadata does not describe a local checked transfer");
			return -1;
		}
		for (alt = insn->alts; alt; alt = alt->next)
			if (alt->insn == dest) {
				ERROR_INSN(insn, "duplicate RAP jump edge");
				return -1;
			}
		alt = calloc(1, sizeof(*alt));
		if (!alt) {
			ERROR_GLIBC("calloc");
			return -1;
		}
		alt->insn = dest;
		alt->type = ALT_TYPE_JUMP_TABLE;
		alt->next = insn->alts;
		insn->alts = alt;
	}
	for_each_insn(file, insn) {
		struct symbol *callee = insn->type == INSN_CALL ? insn_call_dest(insn) : NULL;
		struct instruction *after;

		if (!callee || strcmp(callee->name, "__hdn_rap_jump"))
			continue;
		if (!insn->alts) {
			ERROR_INSN(insn, "RAP jump has no destination metadata");
			return -1;
		}
		after = next_insn_same_sec(file, insn);
		if (!after || after->type != INSN_BUG) {
			ERROR_INSN(insn, "RAP local transfer lacks its nonreturn trap");
			return -1;
		}
		if (!insn->sec->init)
			list_del(&insn->call_node);
		insn->_call_dest = NULL;
		insn->type = INSN_JUMP_DYNAMIC;
		insn->retpoline_safe = true;
		insn->dead_end = true;
		insn->rap_jump = true;
	}
	return 0;
}

static bool rap_binding_matches(struct objtool_file *file, struct instruction *binding,
		struct instruction *call, bool entry)
{
	const unsigned char *bytes;
	struct reloc *reloc;
	unsigned long target;

	if (!binding || file->elf->ehdr.e_machine != EM_X86_64 ||
	    binding->sec != call->sec || binding->offset + binding->len != call->offset)
		return false;
	bytes = binding->sec->data->d_buf + binding->offset;
	/* Exact post-CALL constant in R10 (caller) or R11 (entry adapter). */
	if (!((binding->len == 7 && bytes[0] == 0x49 && bytes[1] == 0xc7 &&
	       bytes[2] == (entry ? 0xc3 : 0xc2)) ||
	      (binding->len == 10 && bytes[0] == 0x49 && bytes[1] == (entry ? 0xbb : 0xba)) ||
	      (binding->len == 7 && bytes[0] == 0x4c && bytes[1] == 0x8d &&
	       bytes[2] == (entry ? 0x1d : 0x15))))
		return false;
	reloc = insn_reloc(file, binding);
	if (reloc) {
		if (reloc->sym->sec != call->sec)
			return false;
		target = reloc->sym->offset + arch_insn_adjusted_addend(binding, reloc);
	} else if (binding->type == INSN_LEA_RIP) {
		target = arch_jump_destination(binding);
	} else {
		return false;
	}
	return target == call->offset + call->len;
}

static int read_rap_sites(struct objtool_file *file)
{
	struct section *sec = find_section_by_name(file->elf, ".hdn.rap.sites");
	unsigned long off;

	if (!sec)
		return 0;
	if (sec_size(sec) % 16) {
		ERROR("invalid RAP return-site metadata size");
		return -1;
	}
	for (off = 0; off < sec_size(sec); off += 16) {
		struct reloc *site = find_reloc_by_dest(file->elf, sec, off);
		struct reloc *type = find_reloc_by_dest(file->elf, sec, off + 8);
		struct instruction *call = NULL, *binding;
		struct symbol *callee;
		unsigned long address, length;

		/* Empty units carry a zero/zero sentinel, never a numeric address. */
		if (memcmp(sec->data->d_buf + off, (char[16]){}, 16) || (!site && type)) {
			ERROR("invalid RAP return-site data");
			return -1;
		}
		if (!site)
			continue;
		if (arch_reloc_size(site) != 8 || (type &&
		    (arch_reloc_size(type) != 8 || strcmp(type->sym->sec->name, ".hdn.rap.types")))) {
			ERROR("invalid RAP return-site relocation");
			return -1;
		}
		address = site->sym->offset + reloc_addend(site);
		for (length = 1; length <= 15 && length <= address; length++) {
			call = find_insn(file, site->sym->sec, address - length);
			if (call && call->len == length)
				break;
			call = NULL;
		}
		callee = call ? insn_call_dest(call) : NULL;
		if (call && call->type != INSN_CALL &&
		    !(opts.mnop && call->type == INSN_NOP && callee && callee->fentry))
			callee = NULL;
		if (!callee || call->rap_site ||
		    (!!type != !strcmp(callee->name, "__hdn_rap_call"))) {
			ERROR("RAP return site does not follow a unique matching call");
			return -1;
		}
		binding = prev_insn_same_sec(file, call);
		if (!rap_binding_matches(file, binding, call, false)) {
			ERROR_INSN(call, "RAP call lacks its exact R10 return-site binding");
			return -1;
		}
		call->rap_site = true;
		binding->rap_binding = true;
	}
	return 0;
}

static int read_rap_entries(struct objtool_file *file)
{
	struct instruction *insn;
	struct section *roots = find_section_by_name(file->elf, ".discard.hdn_rap.roots");
	unsigned long off;

	for_each_insn(file, insn) {
		struct symbol *callee = insn->type == INSN_CALL ? insn_call_dest(insn) : NULL;
		struct instruction *binding;

		if (!callee || (strcmp(callee->name, "__hdn_rap_enter") &&
			       strcmp(callee->name, "__hdn_rap_enter_flags")))
			continue;
		binding = prev_insn_same_sec(file, insn);
		if (!rap_binding_matches(file, binding, insn, true)) {
			ERROR_INSN(insn, "RAP entry lacks its exact R11 continuation binding");
			return -1;
		}
		/* The adapter transfers to that checked continuation via its fixed
		 * retpoline. Keep following the caller, even with its body linked in.
		 * Its own instructions still undergo the normal branch validation. */
		insn->dead_end = false;
		insn->rap_entry = true;
		binding->rap_binding = true;
	}
	for_each_insn(file, insn) {
		struct symbol *callee = insn->rap_site ? insn_call_dest(insn) : NULL;
		struct symbol *func = rap_insn_owner(insn);
		struct instruction *binding, *entry, *first;

		if (!callee || !callee->fentry)
			continue;
		binding = prev_insn_same_sec(file, insn);
		entry = binding ? prev_insn_same_sec(file, binding) : NULL;
		first = func ? find_insn(file, func->sec, func->offset) : NULL;
		if (first && first->type == INSN_ENDBR)
			first = next_insn_same_sec(file, first);
		if (!entry || !entry->rap_entry || !first ||
		    prev_insn_same_sec(file, entry) != first || binding->len != 7 ||
		    insn->offset != first->offset + 19) {
			ERROR_INSN(insn, "RAP fentry does not follow the protected prologue");
			return -1;
		}
	}
	if (roots && sec_size(roots) % 16) {
		ERROR("invalid RAP entry-root metadata size");
		return -1;
	}
	for (off = 0; roots && off < sec_size(roots); off += 16) {
		struct reloc *start = find_reloc_by_dest(file->elf, roots, off);
		struct reloc *end = find_reloc_by_dest(file->elf, roots, off + 8);
		struct instruction *capture, *binding, *call;
		struct symbol *owner;

		if (memcmp(roots->data->d_buf + off, (char[16]){}, 16) ||
		    !start || !end || arch_reloc_size(start) != 8 || arch_reloc_size(end) != 8) {
			ERROR("invalid RAP entry-root relocations");
			return -1;
		}
		capture = find_insn(file, start->sym->sec, start->sym->offset + reloc_addend(start));
		binding = capture ? next_insn_same_sec(file, capture) : NULL;
		call = binding ? next_insn_same_sec(file, binding) : NULL;
		owner = capture ? capture->sym : NULL;
		/* Only the reviewed IDT assembly root may capture an unbound CALL
		 * slot. Other assembly must carry the caller's immutable R10 binding. */
		if (!capture || !owner || strcmp(owner->name, "error_entry") ||
		    !capture->sec->noinstr || capture->len != 4 ||
		    memcmp(capture->sec->data->d_buf + capture->offset, "\x4c\x8b\x14\x24", 4) ||
		    !call || !call->rap_entry || call->rap_root ||
		    end->sym->sec != call->sec ||
		    end->sym->offset + reloc_addend(end) != call->offset + call->len) {
			ERROR("RAP entry root does not match the reviewed capture sequence");
			return -1;
		}
		call->rap_root = true;
	}
	return 0;
}

/* Kind 3 is one exact, terminal assembly protocol, not an instrumentation
 * exemption. Verify every byte, relocation, alternative and branch before
 * permitting a closed runtime to leave through it. The entry has no stack
 * access until LGDT/CR3/RSP select the sealed hardware-identity failure row. */
static int verify_rap_terminal(struct objtool_file *file, struct symbol *func)
{
	static const unsigned char body[] =
		"\xfa\x90\x90\x90\xfc\x49\x89\xfc\xb9\x01\x01\x00\xc0"
		"\x0f\x32\x48\xc1\xe2\x20\x48\x09\xd0\x48\x8d\x1d\0\0\0\0"
		"\xb9\0\0\0\0\x48\x3b\x03\x75\0\x48\x8b\x53\x10\x48\x85\xd2"
		"\x74\0\x48\x83\x7b\x30\0\x75\0"
		"\x48\x8b\x43\x08\x48\x39\xc4\x73\0\x48\x3b\x63\x38\x73\0"
		"\x0f\x01\x53\x18\x0f\x22\xda"
		"\x48\x8b\x63\x08\x31\xed\x4c\x8d\x15\x05\0\0\0\xe8\0\0\0\0"
		"\x4c\x89\xe7\x4c\x8d\x15\x05\0\0\0\xe8\0\0\0\0\xeb\0"
		"\x48\x83\xc3\x40\xff\xc9\x75\0\xeb\0";
	const unsigned char *bytes = func->sec->data->d_buf + func->offset;
	struct symbol *halt = find_symbol_by_name(file->elf, "__hdn_rap_halt");
	struct symbol *rows = find_symbol_by_name(file->elf, "hdn_rap_failure_cpus");
	struct instruction *insn;
	unsigned int i, alternatives = 0;
	uint32_t cpus;

	if (strcmp(func->name, "__hdn_rap_fail") || is_weak_sym(func) ||
	    !func->sec->noinstr || func->len != sizeof(body) - 1 || !halt ||
	    !halt->sec->noinstr || is_weak_sym(halt) || halt->rap_kind != 2 || halt->len != 4 ||
	    memcmp(halt->sec->data->d_buf + halt->offset, "\xfa\xf4\xeb\xfd", 4) ||
	    find_reloc_by_dest_range(file->elf, halt->sec, halt->offset, halt->len))
		goto bad;
	for (i = 0; i < sizeof(body) - 1; i++) {
		if ((i >= 25 && i < 29) || (i >= 30 && i < 34) ||
		    (i >= 91 && i < 95) || (i >= 106 && i < 110) ||
		    i == 38 || i == 47 || i == 54 || i == 63 || i == 69 ||
		    i == 111 || i == 119 || i == 121)
			continue;
		if (bytes[i] != body[i])
			goto bad;
	}
	memcpy(&cpus, bytes + 30, sizeof(cpus));
	if (!cpus || cpus > 1U << 20 || !rows || is_undef_sym(rows) ||
	    is_weak_sym(rows) || rows->len != (unsigned long)cpus * 64 ||
	    strcmp(rows->sec->name, ".data..ro_after_init"))
		goto bad;
	rap_for_each_insn(file, func, insn) {
		unsigned long offset = insn->offset - func->offset;
		struct reloc *reloc = insn_reloc(file, insn);
		struct alternative *alt;
		struct symbol *callee = insn_call_dest(insn);

		if (offset == 22) {
			if (!reloc || reloc->sym != rows ||
			    arch_reloc_size(reloc) != 4 || arch_insn_adjusted_addend(insn, reloc))
				goto bad;
		} else if (offset == 90 || offset == 105) {
			const char *name = offset == 90 ? "hdn_rap_failure_prepare" : "hdn_rap_failure_report";

			if (insn->type != INSN_CALL || !insn->rap_site || !callee || strcmp(callee->name, name))
				goto bad;
		} else if (reloc) {
			goto bad;
		}
		if (is_static_jump(insn)) {
			struct instruction *dest = insn->jump_dest;

			/* Objtool represents a branch to another function's entry
			 * as a sibling call, including conditional failure branches. */
			if (offset == 37 || offset == 62 || offset == 118) {
				unsigned long target = func->offset +
					(offset == 37 ? 112 : offset == 62 ? 70 : 34);

				if (!dest || dest->sec != func->sec || dest->offset != target)
					goto bad;
			} else if (callee != halt || dest) {
				goto bad;
			}
		}
		for (alt = insn->alts; alt; alt = alt->next) {
			struct alt_group *group = alt->insn->alt_group;
			const char *feature = group ? arch_cpu_feature_name(group->feature) : NULL;

			if (offset != 1 || alt->type != ALT_TYPE_INSTRUCTIONS ||
			    alt->insn->len != 3 || alt->insn->type != INSN_CLAC ||
			    !group || group->first_insn != alt->insn || group->last_insn != alt->insn ||
			    !group->orig_group || group->nop || !feature || alternatives >= 2 ||
			    strcmp(feature, alternatives ? "X86_FEATURE_LASS" : "X86_FEATURE_SMAP") ||
			    find_reloc_by_dest_range(file->elf, alt->insn->sec, alt->insn->offset, 3) ||
			    memcmp(alt->insn->sec->data->d_buf + alt->insn->offset, "\x0f\x01\xca", 3))
				goto bad;
			alternatives++;
		}
	}
	if (alternatives != 2)
		goto bad;
	func->rap_terminal = true;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset, "RAP terminal entry does not match its closed stack-switch protocol");
	return -1;
}

struct rap_sequence {
	struct objtool_file *file;
	struct symbol *func;
	unsigned long pos;
};

static bool rap_adapter_name(const char *name)
{
	static const char * const adapters[] = {
		"__hdn_rap_call", "__hdn_rap_jump", "__hdn_rap_enter",
		"__hdn_rap_enter_flags", "__hdn_rap_return", "__hdn_rap_graph_return",
		"__hdn_rap_rethook_return", "__hdn_rap_transfer",
		"__hdn_rap_static_null", "__hdn_rap_bpf_jump",
		"__hdn_rap_bpf_boundary", "__hdn_rap_bpf_exception",
		"__hdn_rap_bpf_dispatch",
		"__hdn_rap_bpf_tramp_enter", "__hdn_rap_bpf_original", "__hdn_rap_bpf_skip",
		"return_to_handler", "arch_rethook_trampoline",
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(adapters); i++)
		if (!strcmp(name, adapters[i]))
			return true;
	return false;
}

#include "hdn-crypto.h"

static bool rap_private_name(const char *name)
{
	static const char * const uaccess[] = {
		"__get_user_1", "__get_user_2", "__get_user_4", "__get_user_8",
		"__get_user_nocheck_1", "__get_user_nocheck_2", "__get_user_nocheck_4", "__get_user_nocheck_8",
		"__put_user_1", "__put_user_2", "__put_user_4", "__put_user_8",
		"__put_user_nocheck_1", "__put_user_nocheck_2", "__put_user_nocheck_4", "__put_user_nocheck_8",
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(uaccess); i++)
		if (!strcmp(name, uaccess[i]))
			return true;
	return rap_crypto_private_name(name) || !strcmp(name, "this_cpu_cmpxchg16b_emu") ||
		!strcmp(name, "check_events") ||
		!strcmp(name, "__fentry__") || !strcmp(name, "ftrace_caller") ||
		!strcmp(name, "ftrace_regs_caller") ||
		!strcmp(name, "clear_bhb_loop") || !strcmp(name, "__hdn_bhb_outer") ||
		!strcmp(name, "__hdn_bhb_inner") ||
		!strcmp(name, "__clear_pages_unrolled") ||
		!strcmp(name, "rep_movs_alternative") || !strcmp(name, "rep_stos_alternative") ||
		!strcmp(name, "__sw_hweight32") || !strcmp(name, "__sw_hweight64") ||
		!strcmp(name, "ftrace_stub_direct_tramp");
}

static bool rap_hook_name(const char *name)
{
	return !strcmp(name, "return_to_handler") || !strcmp(name, "arch_rethook_trampoline");
}

static bool rap_sequence_bytes(struct rap_sequence *s, const char *bytes, size_t len)
{
	struct symbol *func = s->func;

	if (s->pos > func->len || len > func->len - s->pos ||
	    memcmp(func->sec->data->d_buf + func->offset + s->pos, bytes, len) ||
	    find_reloc_by_dest_range(s->file->elf, func->sec, func->offset + s->pos, len))
		return false;
	s->pos += len;
	return true;
}

/* Match the actual PC-relative operand, including relocations to section
 * symbols. A matching name with a nonzero addend is not the same target. */
static bool rap_sequence_edge_match(struct rap_sequence *s, const char *name,
				    bool call, bool bound)
{
	struct symbol *func = s->func, *target = find_symbol_by_name(s->file->elf, name);
	unsigned long offset = func->offset + s->pos;
	struct instruction *insn = find_insn(s->file, func->sec, offset);
	struct reloc *reloc;
	const unsigned char *bytes = func->sec->data->d_buf + offset;

	if (!target || is_weak_sym(target) || !insn || s->pos >= func->len ||
	    insn->len > func->len - s->pos ||
	    !((insn->len == 5 && bytes[0] == (call ? 0xe8 : 0xe9)) ||
	      (!call && insn->len == 2 && bytes[0] == 0xeb)) ||
	    (call && (insn->type != INSN_CALL || (bound && !insn->rap_site))))
		return false;
	reloc = find_reloc_by_dest_range(s->file->elf, func->sec, offset, insn->len);
	if (reloc) {
		if (insn->len != 5 || reloc_offset(reloc) != offset + 1 ||
		    arch_reloc_size(reloc) != 4 || !arch_pc_relative_reloc(reloc) ||
		    reloc->sym->sec != target->sec ||
		    (is_undef_sym(target) && reloc->sym != target) ||
		    reloc->sym->offset + arch_insn_adjusted_addend(insn, reloc) != target->offset ||
		    find_reloc_by_dest_range(s->file->elf, func->sec, offset + 2, 3))
			return false;
	} else if (is_undef_sym(target) || func->sec != target->sec ||
		   arch_jump_destination(insn) != target->offset) {
		return false;
	}
	s->pos += insn->len;
	return true;
}

static bool rap_sequence_edge(struct rap_sequence *s, const char *name, bool call)
{
	return rap_sequence_edge_match(s, name, call, true);
}

/* Both original and replacement bytes matter even when objtool's ordinary
 * AC-state walker ignores the unpatched alternative. Only the two exact
 * PUSHF/CLAC and POPF sequences may surround a runtime call. */
static bool rap_sequence_flags(struct objtool_file *file, struct instruction *insn, bool save)
{
	struct alternative *alt;
	unsigned int count = 0;
	unsigned long len = save ? 4 : 1;

	if (!insn->alt_group || insn->alt_group->orig_group ||
	    insn->alt_group->first_insn != insn ||
	    insn->alt_group->last_insn->offset + insn->alt_group->last_insn->len != insn->offset + len)
		return false;
	for (alt = insn->alts; alt; alt = alt->next) {
		struct alt_group *group = alt->insn->alt_group;
		const char *feature = group ? arch_cpu_feature_name(group->feature) : NULL;

		if (count >= 2 || alt->type != ALT_TYPE_INSTRUCTIONS || !group ||
		    group->orig_group != insn->alt_group || group->first_insn != alt->insn ||
		    group->nop || !feature ||
		    strcmp(feature, count ? "X86_FEATURE_LASS" : "X86_FEATURE_SMAP") ||
		    group->last_insn->offset + group->last_insn->len != alt->insn->offset + len ||
		    memcmp(alt->insn->sec->data->d_buf + alt->insn->offset,
			   save ? "\x9c\x0f\x01\xca" : "\x9d", len) ||
		    find_reloc_by_dest_range(file->elf, alt->insn->sec, alt->insn->offset, len))
			return false;
		count++;
	}
	return count == 2;
}

/* Kind 4 covers only the finite private-ABI adapters below. Verify their whole
 * bodies, not just selected landmarks: save every non-reserved argument and
 * flags, disable interrupts/AC, bind the closed runtime call, retain its checked
 * result, and consume exactly the correct stack slot before the transfer. */
static int verify_rap_adapter(struct objtool_file *file, struct symbol *func)
{
	struct rap_sequence s = { .file = file, .func = func };
	struct instruction *insn, *reject = NULL;
	unsigned long save, restore;
	const char *root;
	bool call = !strcmp(func->name, "__hdn_rap_call");
	bool jump = !strcmp(func->name, "__hdn_rap_jump");
	bool bpf_jump = !strcmp(func->name, "__hdn_rap_bpf_jump");
	bool bpf_boundary = !strcmp(func->name, "__hdn_rap_bpf_boundary");
	bool bpf_exception = !strcmp(func->name, "__hdn_rap_bpf_exception");
	bool bpf_dispatch = !strcmp(func->name, "__hdn_rap_bpf_dispatch");
	bool bpf_enter = !strcmp(func->name, "__hdn_rap_bpf_tramp_enter");
	bool bpf_original = !strcmp(func->name, "__hdn_rap_bpf_original");
	bool bpf_skip = !strcmp(func->name, "__hdn_rap_bpf_skip");
	bool enter = !strcmp(func->name, "__hdn_rap_enter");
	bool flags = !strcmp(func->name, "__hdn_rap_enter_flags");
	bool ret = !strcmp(func->name, "__hdn_rap_return");
	bool graph = !strcmp(func->name, "__hdn_rap_graph_return");
	bool hook = !strcmp(func->name, "__hdn_rap_rethook_return");
	bool hook_handler = rap_hook_name(func->name);

#define RAP_BYTES(bytes) do { if (!rap_sequence_bytes(&s, bytes, sizeof(bytes) - 1)) goto bad; } while (0)
#define RAP_EDGE(name, call) do { if (!rap_sequence_edge(&s, name, call)) goto bad; } while (0)
	if (is_weak_sym(func) || !func->len ||
	    (!call && !jump && !bpf_jump && !bpf_dispatch && !hook_handler && !func->sec->noinstr))
		goto bad;
	if (!strcmp(func->name, "__hdn_rap_static_null")) {
		RAP_BYTES("\x4c\x39\x14\x24\x75\x0d\x4d\x89\xd3\x48\x8d\x64\x24\x08");
		RAP_EDGE("__hdn_rap_transfer", false);
		RAP_BYTES("\xbf\x02\0\0\0");
		RAP_EDGE("__hdn_rap_fail", false);
		rap_for_each_insn(file, func, insn)
			if (insn->alts)
				goto bad;
		goto complete;
	}
	if (hook_handler) {
		if (!strcmp(func->name, "return_to_handler")) {
			RAP_BYTES("\x48\x89\xe7\x48\x83\xec\x08\x48\x81\xec\xa8\0\0\0"
				  "\x48\x89\x44\x24\x50\x48\x89\x54\x24\x60\x48\x89\x6c\x24\x20"
				  "\x48\x89\xbc\x24\x98\0\0\0\x48\x89\xe7\x4c\x8d\x15\x05\0\0\0");
			RAP_EDGE("ftrace_return_to_handler", true);
			RAP_BYTES("\x49\x89\xc3\x48\x8b\x54\x24\x60\x48\x8b\x44\x24\x50"
				  "\x48\x81\xc4\xa8\0\0\0");
			RAP_EDGE("__hdn_rap_graph_return", false);
		} else {
			struct reloc *reloc = find_reloc_by_dest(file->elf, func->sec, func->offset + 1);

			/* The fake unwind slot is this exact trampoline's address. */
			if (func->len < 5 || memcmp(func->sec->data->d_buf + func->offset, "\x68\0\0\0\0", 5) ||
			    !reloc || reloc_type(reloc) != R_X86_64_32S || reloc->sym != func ||
			    reloc_addend(reloc) ||
			    find_reloc_by_dest_range(file->elf, func->sec, func->offset, 1) ||
			    find_reloc_by_dest_range(file->elf, func->sec, func->offset + 2, 3))
				goto bad;
			s.pos = 5;
			RAP_BYTES("\x6a\x18\x54\x9c\x48\x83\xec\x18\x57\x56\x52\x51\x50"
				  "\x41\x50\x41\x51\x41\x52\x41\x53\x53\x55\x41\x54\x41\x55\x41\x56\x41\x57");
			/* CONFIG_FRAME_POINTER encodes the saved pt_regs pointer. */
			if (s.pos + 5 <= func->len &&
			    !memcmp(func->sec->data->d_buf + func->offset + s.pos, "\x48\x8d\x6c\x24\x01", 5))
				RAP_BYTES("\x48\x8d\x6c\x24\x01");
			RAP_BYTES("\x48\x89\xe7\x4c\x8d\x15\x05\0\0\0");
			RAP_EDGE("arch_rethook_trampoline_callback", true);
			RAP_BYTES("\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x5d\x5b\x41\x5b\x41\x5a\x41\x59\x41\x58"
				  "\x58\x59\x5a\x5e\x5f\x48\x83\xc4\x18\x48\x83\xc4\x10\x9d\x4c\x8b\x1c\x24");
			RAP_EDGE("__hdn_rap_rethook_return", false);
		}
		rap_for_each_insn(file, func, insn)
			if (insn->alts)
				goto bad;
		goto complete;
	}
	if (!strcmp(func->name, "__hdn_rap_transfer")) {
		/* The local CALL must resolve inside this function before relocation,
		 * and its fall-through must trap. Keep the final architecture RET:
		 * return-site patching supplies the CPU's selected return mitigation. */
		RAP_BYTES("\xe8\x01\0\0\0\xcc\x4c\x89\x1c\x24");
		insn = find_insn(file, func->sec, func->offset);
		if (!insn || insn->type != INSN_JUMP_UNCONDITIONAL || !insn->jump_dest ||
		    insn->jump_dest->sec != func->sec || insn->jump_dest->offset != func->offset + 6)
			goto bad;
		if (s.pos < func->len && ((unsigned char *)func->sec->data->d_buf)[func->offset + s.pos] == 0xc3) {
			RAP_BYTES("\xc3");
			if (s.pos < func->len)
				RAP_BYTES("\xcc");
		} else {
			RAP_EDGE("__x86_return_thunk", false);
		}
		rap_for_each_insn(file, func, insn)
			if (insn->alts)
				goto bad;
		goto complete;
	}
	if (!call && !jump && !bpf_jump && !bpf_boundary && !bpf_exception && !bpf_dispatch &&
	    !bpf_enter && !bpf_original && !bpf_skip &&
	    !enter && !flags && !ret && !graph && !hook)
		goto bad;
	if (call || bpf_jump || bpf_boundary || bpf_exception || bpf_dispatch ||
	    bpf_enter || bpf_original || bpf_skip || enter || flags) {
		if (call || bpf_jump || bpf_boundary || bpf_dispatch || bpf_original || bpf_skip)
			RAP_BYTES("\x4c\x39\x14\x24");
		else
			RAP_BYTES("\x4c\x39\x1c\x24");
		reject = find_insn(file, func->sec, func->offset + s.pos);
		if (!reject || reject->type != INSN_JUMP_CONDITIONAL || reject->len != 2 ||
		    ((unsigned char *)func->sec->data->d_buf)[reject->offset] != 0x75 ||
		    find_reloc_by_dest_range(file->elf, func->sec, reject->offset, 2))
			goto bad;
		s.pos += 2;
	}
	save = s.pos + 4;
	RAP_BYTES("\x55\x48\x89\xe5\x9c\x90\x90\x90\xfa\x50\x51\x52\x56\x57"
		  "\x41\x50\x41\x51\x41\x52\x41\x53\x48\x83\xe4\xf0");
	if (call || jump || bpf_jump) {
		RAP_BYTES("\x4c\x89\xdf\x4c\x89\xd6");
		root = bpf_jump ? "hdn_rap_bpf_validate_jump" :
			call ? "hdn_rap_validate_call" : "hdn_rap_validate";
	} else if (bpf_dispatch) {
		RAP_BYTES("\x4c\x89\xdf");
		root = "hdn_rap_bpf_dispatch_target";
	} else if (bpf_boundary) {
		RAP_BYTES("\x48\x8d\x7d\x10\x48\x8b\x75\0\x4c\x89\xd2");
		root = "hdn_rap_bpf_boundary_save";
	} else if (bpf_exception) {
		RAP_BYTES("\x4c\x89\xdf\x48\x8d\x75\x10");
		root = "hdn_rap_bpf_exception_restore";
	} else if (bpf_enter) {
		RAP_BYTES("\x48\x8d\x7d\x10\x4c\x89\xde\x4c\x89\xd2");
		root = "hdn_rap_bpf_tramp_enter";
	} else if (bpf_original) {
		RAP_BYTES("\x48\x8d\x7d\x08\x4c\x89\xd6\x48\x8b\x55\0");
		root = "hdn_rap_bpf_original_enter";
	} else if (bpf_skip) {
		RAP_BYTES("\x48\x8d\x7d\x10\x4c\x89\xd6");
		root = "hdn_rap_bpf_skip";
	} else if (enter || flags) {
		if (enter)
			RAP_BYTES("\x48\x8d\x7d\x10");
		else
			RAP_BYTES("\x48\x8d\x7d\x18");
		RAP_BYTES("\x4c\x89\xd6");
		root = "hdn_rap_push";
	} else {
		RAP_BYTES("\x48\x8d\x7d\x08");
		root = "hdn_rap_pop";
		if (graph || hook) {
			if (graph)
				RAP_BYTES("\xbe\x01\0\0\0");
			else
				RAP_BYTES("\xbe\x02\0\0\0");
			RAP_BYTES("\x48\x8b\x55\xb0");
			root = "hdn_rap_hook_finish";
		}
	}
	RAP_BYTES("\x4c\x8d\x15\x05\0\0\0");
	RAP_EDGE(root, true);
	if (bpf_exception) {
		RAP_BYTES("\x48\x8b\x50\x10\x48\x89\x55\xd8"
			  "\x48\x8b\x50\x18\x48\x89\x55\xe0");
	}
	if (bpf_boundary)
		RAP_BYTES("\x4c\x8b\x5d\xb8");
	else if (enter || flags || bpf_exception || bpf_enter)
		RAP_BYTES("\x4c\x8b\x5d\xb0");
	else
		RAP_BYTES("\x49\x89\xc3");
	restore = s.pos + 15;
	RAP_BYTES("\x48\x8d\x65\xb8\x41\x5a\x41\x59\x41\x58\x5f\x5e\x5a\x59\x58\x9d\x5d");
	if (call || bpf_dispatch) {
		RAP_EDGE("__x86_indirect_thunk_r11", false);
	} else {
		if (bpf_skip)
			RAP_BYTES("\x48\x8d\x64\x24\x18");
		else if (!bpf_original)
			RAP_BYTES("\x48\x8d\x64\x24\x08");
		RAP_EDGE("__hdn_rap_transfer", false);
	}
	if (reject) {
		if (!reject->jump_dest || reject->jump_dest->sec != func->sec ||
		    reject->jump_dest->offset != func->offset + s.pos)
			goto bad;
		RAP_BYTES("\xbf\x02\0\0\0");
		RAP_EDGE("__hdn_rap_fail", false);
	}
	rap_for_each_insn(file, func, insn) {
		unsigned long off = insn->offset - func->offset;

		if (off == save || off == restore) {
			if (!rap_sequence_flags(file, insn, off == save))
				goto bad;
		} else if (insn->alts) {
			goto bad;
		}
	}
complete:
	if (s.pos != func->len)
		goto bad;
	func->rap_adapter = true;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s.pos, "RAP adapter does not match its closed transfer protocol");
	return -1;
#undef RAP_BYTES
#undef RAP_EDGE
}

/* The saved-register tracing path has two private transfers. Its closed root
 * chooses both the destination and whether one fentry slot is consumed. Check
 * the complete handoff so neither an ordinary saved register nor a branch into
 * the middle can bypass that decision. Other body code stays under the normal
 * protected-function coverage and stack checks. */
static int verify_rap_ftrace_handoff(struct objtool_file *file, struct symbol *func)
{
	struct rap_sequence s = { .file = file, .func = func };
	struct symbol *selector = find_symbol_by_name(file->elf, "ftrace_regs_caller_jmp");
	struct instruction *entry, *branch, *insn, *choice, *transfer[2];
	unsigned long start, call_path;
	unsigned int frame = 168, i;
	char coordinates[] = "\x48\x8d\xbc\x24\xb0\0\0\0";
	char release[] = "\x48\x81\xc4\xa8\0\0\0\x9d";
	const char restore[] = "\x48\x8b\x6c\x24\x20\x4c\x8b\x4c\x24\x40"
		"\x4c\x8b\x44\x24\x48\x48\x8b\x7c\x24\x70\x48\x8b\x74\x24\x68"
		"\x48\x8b\x54\x24\x60\x48\x8b\x4c\x24\x58\x48\x8b\x44\x24\x50";

#define RAP_BYTES(bytes) do { if (!rap_sequence_bytes(&s, bytes, sizeof(bytes) - 1)) goto bad; } while (0)
#define RAP_EDGE(name, call) do { if (!rap_sequence_edge(&s, name, call)) goto bad; } while (0)
	RAP_BYTES("\x9c\x4c\x8d\x1d\x05\0\0\0");
	entry = find_insn(file, func->sec, func->offset + s.pos);
	if (!entry || !entry->rap_entry || !insn_call_dest(entry) ||
	    strcmp(insn_call_dest(entry)->name, "__hdn_rap_enter_flags"))
		goto bad;
	s.pos += entry->len;
	if (s.pos < func->len && *((u8 *)func->sec->data->d_buf + func->offset + s.pos) == 0x55) {
		RAP_BYTES("\x55\xff\x74\x24\x18\x55\x48\x89\xe5"
			  "\xff\x74\x24\x20\x55\x48\x89\xe5");
		frame += 40;
	}
	RAP_BYTES("\x48\x81\xec\xa8\0\0\0");
	coordinates[4] = frame + 8;
	release[3] = frame;
	branch = selector ? find_insn(file, selector->sec, selector->offset) : NULL;
	if (!branch || rap_insn_owner(branch) != func || branch->len != 2 ||
	    *((u8 *)branch->sec->data->d_buf + branch->offset) != 0x75 ||
	    !branch->jump_dest || rap_insn_owner(branch->jump_dest) != func)
		goto bad;
	start = branch->jump_dest->offset;
	s.pos = start - func->offset;
	RAP_BYTES(coordinates);
	RAP_BYTES("\x48\x8b\x74\x24\x78\x4c\x8d\x15\x05\0\0\0");
	RAP_EDGE("hdn_rap_bpf_trace_handoff", true);
	RAP_BYTES("\x49\x89\xc3\x48\x85\xd2");
	choice = find_insn(file, func->sec, func->offset + s.pos);
	RAP_BYTES("\x74\x3d\x49\x89\xd2");
	for (i = 0; i < 2; i++) {
		RAP_BYTES(restore);
		RAP_BYTES(release);
		if (!i)
			RAP_BYTES("\x48\x8d\x64\x24\x08");
		transfer[i] = find_insn(file, func->sec, func->offset + s.pos);
		RAP_EDGE("__hdn_rap_transfer", false);
		if (!i)
			call_path = func->offset + s.pos;
	}
	if (s.pos != func->len || !choice || !choice->jump_dest ||
	    choice->jump_dest->sec != func->sec || choice->jump_dest->offset != call_path)
		goto bad;
	for_each_insn(file, insn) {
		if (insn->sec == func->sec && insn->offset >= start &&
		    insn->offset < func->offset + func->len && insn->alts)
			goto bad;
		if (insn->jump_dest && insn->jump_dest->sec == func->sec &&
		    insn->jump_dest->offset >= start && insn->jump_dest->offset < func->offset + func->len &&
		    insn != branch && insn != choice)
			goto bad;
	}
	transfer[0]->rap_handoff = true;
	transfer[1]->rap_handoff = true;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s.pos, "RAP tracing handoff does not match its protected transfer protocol");
	return -1;
#undef RAP_BYTES
#undef RAP_EDGE
}

/* Two finite bodies implement the outgoing image-copy boundary. The first
 * consumes only the sealed admission result; the relocated body cannot call
 * C, touch a stack, or reload an arbitrary transfer pointer. No ordinary
 * function can acquire this coverage kind or indirect-target permission. */
static int verify_rap_image_handoff(struct objtool_file *file, struct symbol *func)
{
	struct rap_sequence s = { .file = file, .func = func };
	struct instruction *insn, *first = find_insn(file, func->sec, func->offset);
	bool launch = !strcmp(func->name, "restore_image"), frame = false;
	unsigned long loop = 0, done = 0;

#define RAP_BYTES(bytes) do { if (!rap_sequence_bytes(&s, bytes, sizeof(bytes) - 1)) goto bad; } while (0)
	if (is_weak_sym(func) || (!launch && strcmp(func->name, "core_restore_code")))
		goto bad;
	if (first && first->type == INSN_ENDBR)
		RAP_BYTES("\xf3\x0f\x1e\xfa");
	if (launch) {
		if (s.pos < func->len &&
		    *((u8 *)func->sec->data->d_buf + func->offset + s.pos) == 0x55) {
			RAP_BYTES("\x55\x48\x89\xe5");
			frame = true;
		}
		RAP_BYTES("\x4c\x8d\x15\x05\0\0\0");
		if (!rap_sequence_edge(&s, "hdn_rap_hibernate_enter", true))
			goto bad;
		if (frame)
			RAP_BYTES("\x5d");
		RAP_BYTES("\x4c\x8b\x00\x4c\x8b\x48\x08\x48\x8b\x58\x28"
			  "\x48\x8b\x50\x20\x48\x8b\x48\x18\x48\x8b\x40\x10\xff\xe1");
	} else {
		RAP_BYTES("\x0f\x22\xd8\x48\x89\xd9\x48\x81\xe1\x7f\xff\xff\xff"
			  "\x0f\x22\xe1\x0f\x20\xd9\x0f\x22\xd9\x0f\x22\xe3");
		loop = func->offset + s.pos;
		RAP_BYTES("\x48\x85\xd2\x74\x17\x48\x8b\x32\x48\x8b\x7a\x08"
			  "\x48\xc7\xc1\x00\x02\x00\x00\xf3\x48\xa5\x48\x8b\x52\x10\xeb\xe4");
		done = func->offset + s.pos;
		RAP_BYTES("\x41\xff\xe0");
	}
	if (s.pos != func->len)
		goto bad;
	rap_for_each_insn(file, func, insn) {
		if (insn->alts)
			goto bad;
		if (is_static_jump(insn) && (!insn->jump_dest ||
		    insn->jump_dest->sec != func->sec ||
		    insn->jump_dest->offset !=
			(insn->type == INSN_JUMP_CONDITIONAL ? done : loop)))
			goto bad;
	}
	for_each_insn(file, insn) {
		if (rap_insn_owner(insn) != func && insn->jump_dest &&
		    insn->jump_dest->sec == func->sec &&
		    insn->jump_dest->offset > func->offset &&
		    insn->jump_dest->offset < func->offset + func->len)
			goto bad;
	}
	func->rap_image_handoff = true;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s.pos,
		   "RAP image handoff does not match its closed admission/copy protocol");
	return -1;
#undef RAP_BYTES
}

static bool rap_sequence_reference(struct rap_sequence *s, const char *opcode,
				   size_t size, const char *name, bool relative)
{
	struct symbol *target = find_symbol_by_name(s->file->elf, name);
	unsigned long offset = s->func->offset + s->pos;
	struct instruction *insn = find_insn(s->file, s->func->sec, offset);
	struct reloc *reloc;

	if (!target || is_weak_sym(target) || !insn || insn->len != size + 4 ||
	    s->pos > s->func->len || insn->len > s->func->len - s->pos ||
	    memcmp(s->func->sec->data->d_buf + offset, opcode, size))
		return false;
	reloc = find_reloc_by_dest(s->file->elf, s->func->sec, offset + size);
	if (!reloc) {
		int32_t displacement;

		/* GAS resolves same-section RIP references without a relocation. */
		memcpy(&displacement, s->func->sec->data->d_buf + offset + size, 4);
		if (!relative || is_undef_sym(target) || target->sec != s->func->sec ||
		    offset + insn->len + displacement != target->offset ||
		    find_reloc_by_dest_range(s->file->elf, s->func->sec, offset, insn->len))
			return false;
		s->pos += insn->len;
		return true;
	}
	if (arch_reloc_size(reloc) != 4 ||
	    (relative ? !arch_pc_relative_reloc(reloc) : reloc_type(reloc) != R_X86_64_32S) ||
	    reloc->sym->sec != target->sec ||
	    (is_undef_sym(target) && reloc->sym != target) ||
	    reloc->sym->offset + (relative ? arch_insn_adjusted_addend(insn, reloc) :
					     reloc_addend(reloc)) != target->offset ||
	    find_reloc_by_dest_range(s->file->elf, s->func->sec, offset, size) ||
	    find_reloc_by_dest_range(s->file->elf, s->func->sec, offset + size + 1, 3))
		return false;
	s->pos += insn->len;
	return true;
}

/* The image kernel starts with an externally restored CR3 and no usable
 * caller stack. Establish GS/SP and descriptors from its sealed checkpoint,
 * authenticate that checkpoint, restore registers, and use the ordinary RAP
 * return authenticator. This entry never obtains ordinary target permission. */
static int verify_rap_image_resume(struct objtool_file *file, struct symbol *func)
{
	struct rap_sequence s = { .file = file, .func = func };
	struct instruction *insn, *first = find_insn(file, func->sec, func->offset);

#define RAP_BYTES(bytes) do { if (!rap_sequence_bytes(&s, bytes, sizeof(bytes) - 1)) goto bad; } while (0)
#define RAP_REF(bytes, name, relative) do { \
	if (!rap_sequence_reference(&s, bytes, sizeof(bytes) - 1, name, relative)) goto bad; \
} while (0)
	if (strcmp(func->name, "restore_registers") || is_weak_sym(func))
		goto bad;
	if (first && first->type == INSN_ENDBR)
		RAP_BYTES("\xf3\x0f\x1e\xfa");
	RAP_BYTES("\x41\x0f\x22\xd9");
	RAP_REF("\x48\x8b\x05", "mmu_cr4_features", true);
	RAP_BYTES("\x48\x89\xc2\x48\x81\xe2\x7f\xff\xff\xff\x0f\x22\xe2"
		  "\x0f\x20\xd9\x0f\x22\xd9\x0f\x22\xe0");
	RAP_REF("\x48\xc7\xc6", "hdn_rap_resume_state", false);
	RAP_BYTES("\x48\x8b\x86\xb0\0\0\0\x48\x89\xc2\x48\xc1\xea\x20"
		  "\xb9\x01\x01\x00\xc0\x0f\x30\x48\x8b\xa6\x98\0\0\0"
		  "\x0f\x01\x96\x0a\x01\0\0\x0f\x01\x9e\x16\x01\0\0"
		  "\xbf\x02\0\0\0\x4c\x8d\x15\x05\0\0\0");
	if (!rap_sequence_edge(&s, "hdn_rap_resume_restore", true))
		goto bad;
	RAP_BYTES("\x48\x8b\xa0\x98\0\0\0\x48\x8b\x68\x20\x48\x8b\x70\x68"
		  "\x48\x8b\x78\x70\x48\x8b\x58\x28\x48\x8b\x48\x58\x48\x8b\x50\x60"
		  "\x4c\x8b\x40\x48\x4c\x8b\x48\x40\x4c\x8b\x50\x38\x4c\x8b\x58\x30"
		  "\x4c\x8b\x60\x18\x4c\x8b\x68\x10\x4c\x8b\x70\x08\x4c\x8b\x38"
		  "\xff\xb0\x90\0\0\0\x9d\x0f\x01\x90\x0a\x01\0\0\x31\xc0");
	RAP_REF("\x48\x89\x05", "in_suspend", true);
	if (!rap_sequence_edge(&s, "__hdn_rap_return", false) || s.pos != func->len)
		goto bad;
	rap_for_each_insn(file, func, insn)
		if (insn->alts)
			goto bad;
	for_each_insn(file, insn)
		if (rap_insn_owner(insn) != func && insn->jump_dest &&
		    insn->jump_dest->sec == func->sec &&
		    insn->jump_dest->offset > func->offset &&
		    insn->jump_dest->offset < func->offset + func->len)
			goto bad;
	func->rap_resume_entry = true;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s.pos,
		   "RAP image resume does not match its protected restoration protocol");
	return -1;
#undef RAP_REF
#undef RAP_BYTES
}

/* The C caller performs CMOS/NMI preparation, then this no-return bridge
 * consumes only the immutable real-mode launch descriptor. */
static int verify_rap_realmode_restart(struct objtool_file *file, struct symbol *func)
{
	struct rap_sequence s = { .file = file, .func = func };
	struct instruction *insn;

	if (strcmp(func->name, "hdn_realmode_restart") || is_weak_sym(func) ||
	    !rap_sequence_bytes(&s, "\x4c\x8d\x1d\x05\0\0\0", 7) ||
	    !rap_sequence_edge_match(&s, "__hdn_rap_enter", true, false) ||
	    !rap_sequence_bytes(&s, "\x0f\x20\xe0\x48\x25\x7f\xff\xfd\xff\x0f\x22\xe0", 12) ||
	    !rap_sequence_reference(&s, "\x48\x8b\x05", 3, "hdn_realmode_reboot", true) ||
	    !rap_sequence_bytes(&s, "\x0f\x22\xd8", 3))
		goto bad;
	/* The second operand is the six-byte far pointer at descriptor+8. */
	{
		struct reloc *reloc = find_reloc_by_dest(file->elf, func->sec, func->offset + s.pos + 2);
		struct symbol *state = find_symbol_by_name(file->elf, "hdn_realmode_reboot");
		const char *p = func->sec->data->d_buf + func->offset + s.pos;

		if (s.pos + 6 > func->len || memcmp(p, "\xff\x2d", 2) || !state || !reloc ||
		    arch_reloc_size(reloc) != 4 || !arch_pc_relative_reloc(reloc) ||
		    reloc->sym->sec != state->sec ||
		    (is_undef_sym(state) && reloc->sym != state) ||
		    reloc->sym->offset + reloc_addend(reloc) + 4 != state->offset + 8 ||
		    find_reloc_by_dest_range(file->elf, func->sec, func->offset + s.pos, 2) ||
		    find_reloc_by_dest_range(file->elf, func->sec, func->offset + s.pos + 3, 3))
			goto bad;
		s.pos += 6;
	}
	if (!rap_sequence_bytes(&s, "\x0f\x0b", 2) || s.pos != func->len)
		goto bad;
	rap_for_each_insn(file, func, insn)
		if (insn->alts)
			goto bad;
	for_each_insn(file, insn)
		if (rap_insn_owner(insn) != func && insn->jump_dest && insn->jump_dest->sec == func->sec &&
		    insn->jump_dest->offset > func->offset && insn->jump_dest->offset < func->offset + func->len)
			goto bad;
	func->rap_realmode_protocol = true;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s.pos, "RAP real-mode reboot has an invalid immutable launch protocol");
	return -1;
}

#include "hdn-kexec.h"
#include "hdn-efi.h"
#include "hdn-hyperv.h"
#include "hdn-hv-crash.h"
#include "hdn-thunks.h"
#include "hdn-entry.h"
#include "hdn-idt.h"
#include "hdn-entry-macros.h"
#include "hdn-entry-roots.h"
#include "hdn-entry-return.h"
#include "hdn-nmi.h"
#include "hdn-syscall.h"
#include "hdn-compat.h"
#include "hdn-rewind.h"
#include "hdn-head.h"
#include "hdn-pvh.h"

/* An injectable function has already executed its protected prologue. Only
 * the immutable breakpoint adapter may resume at this return-only gate; it
 * retains the original record until the ordinary authenticated epilogue. */
static int verify_rap_error_return(struct objtool_file *file, struct symbol *func)
{
	struct rap_sequence s = { .file = file, .func = func };
	struct symbol *root = find_symbol_by_name(file->elf, "__hdn_rap_return");
	struct instruction *insn;

	if (func->rap_kind != 51 || strcmp(func->name, "just_return_func") ||
	    is_weak_sym(func) || !rap_sequence_edge(&s, "__hdn_rap_return", false) ||
	    s.pos != func->len || !root || (opts.link && root->rap_kind != 4))
		goto bad;
	rap_for_each_insn(file, func, insn)
		if (insn->alts)
			goto bad;
	for_each_insn(file, insn) {
		struct section *sec;
		unsigned long offset;

		if (rap_thunk_edge_target(file, insn, &sec, &offset) &&
		    sec == func->sec && offset >= func->offset && offset < func->offset + func->len)
			goto bad;
	}
	func->rap_error_return_protocol = true;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset, "RAP error-injection epilogue lacks its closed return protocol");
	return -1;
}

/* These wrappers construct an architectural IRET frame. Their CALL is not an
 * ordinary C transfer and must not invent a return record for the hardware IP
 * slot. The entered IDT path owns the nested asynchronous record instead. */
static int verify_rap_hardware_event(struct objtool_file *file, struct symbol *func)
{
	struct rap_sequence s = { .file = file, .func = func };
	struct instruction *insn, *first = find_insn(file, func->sec, func->offset);
	bool nmi = !strcmp(func->name, "vmx_do_nmi_irqoff");

#define EVENT_BYTES(bytes) do { \
	if (!rap_sequence_bytes(&s, bytes, sizeof(bytes) - 1)) goto bad; \
} while (0)
	if (is_weak_sym(func) || (!nmi && strcmp(func->name, "vmx_do_interrupt_irqoff")))
		goto bad;
	if (first && first->type == INSN_ENDBR)
		EVENT_BYTES("\xf3\x0f\x1e\xfa");
	EVENT_BYTES("\x4c\x8d\x1d\x05\0\0\0");
	if (!rap_sequence_edge_match(&s, "__hdn_rap_enter", true, false))
		goto bad;
	if (!nmi) {
		EVENT_BYTES("\x4c\x8d\x15\x05\0\0\0");
		if (!rap_sequence_edge(&s, "hdn_rap_vmx_vector", true))
			goto bad;
		EVENT_BYTES("\x48\x89\xc7");
	}
	EVENT_BYTES("\x55\x48\x89\xe5\x48\x83\xe4\xf0\x6a\x18\x55\x9c\x6a\x10");
	if (nmi) {
		if (!rap_sequence_edge_match(&s, "asm_exc_nmi_kvm_vmx", true, false))
			goto bad;
	} else if (s.pos < func->len &&
		   *((unsigned char *)func->sec->data->d_buf + func->offset + s.pos) == 0xe8) {
		if (!rap_sequence_reference(&s, "\xe8", 1, "__x86_indirect_thunk_rdi", true))
			goto bad;
	} else {
		EVENT_BYTES("\xff\xd7");
	}
	EVENT_BYTES("\xc9");
	if (!rap_sequence_edge_match(&s, "__hdn_rap_return", false, false) || s.pos != func->len)
		goto bad;
	rap_for_each_insn(file, func, insn)
		if (insn->alts)
			goto bad;
	for_each_insn(file, insn)
		if (rap_insn_owner(insn) != func && insn->jump_dest && insn->jump_dest->sec == func->sec &&
		    insn->jump_dest->offset > func->offset && insn->jump_dest->offset < func->offset + func->len)
			goto bad;
	func->rap_hardware_event = true;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s.pos, "RAP hardware event does not match its checked synthetic-frame protocol");
	return -1;
#undef EVENT_BYTES
}

/* The IBT selftest deliberately branches to a missing-ENDBR landing. Only
 * its complete fixed-target sequence is exempt from dynamic target dispatch;
 * its ordinary entry and return still use the standard RAP protocol. */
static int verify_rap_ibt(struct objtool_file *file, struct symbol *func)
{
	struct rap_sequence s = { .file = file, .func = func };
	struct symbol *landing = find_symbol_by_name(file->elf, "ibt_selftest_noendbr");
	struct instruction *entry, *jump, *tail, *insn;

	if (func->rap_kind != 1 || is_weak_sym(func) || !landing ||
	    landing->sec != func->sec || is_weak_sym(landing))
		goto bad;
	if (!rap_sequence_bytes(&s, "\x4c\x8d\x1d\x05\0\0\0", 7))
		goto bad;
	entry = find_insn(file, func->sec, func->offset + s.pos);
	if (!entry || !entry->rap_entry ||
	    !rap_sequence_edge_match(&s, "__hdn_rap_enter", true, false) ||
	    !rap_sequence_reference(&s, "\x48\x8d\x05", 3, "ibt_selftest_noendbr", true))
		goto bad;
	jump = find_insn(file, func->sec, func->offset + s.pos);
	if (!rap_sequence_bytes(&s, "\xff\xe0", 2) ||
	    landing->offset != func->offset + s.pos)
		goto bad;
	tail = find_insn(file, func->sec, func->offset + s.pos);
	if (!jump || !tail || !tail->rap_return ||
	    !rap_sequence_edge(&s, "__hdn_rap_return", false) || s.pos != func->len)
		goto bad;
	rap_for_each_insn(file, func, insn)
		if (insn->alts)
			goto bad;
	for_each_insn(file, insn)
		if (rap_insn_owner(insn) != func && insn->jump_dest &&
		    insn->jump_dest->sec == func->sec &&
		    insn->jump_dest->offset > func->offset &&
		    insn->jump_dest->offset < func->offset + func->len)
			goto bad;
	/* Follow the independently verified local edge in the ordinary stack,
	 * return and IBT walkers. No arbitrary dynamic edge acquires permission. */
	jump->type = INSN_JUMP_UNCONDITIONAL;
	jump->jump_dest = tail;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s.pos, "RAP IBT selftest has an invalid fixed-target protocol");
	return -1;
}

/* Permanent boot-owned ACPI reset tables and launch state select the only
 * foreign destination. There are no stack accesses after leaving the private
 * kernel root, and no return into this kernel is accepted. */
static int verify_rap_madt(struct objtool_file *file, struct symbol *func)
{
	struct rap_kexec_sequence k = { .seq = { .file = file, .func = func } };
	struct rap_sequence *s = &k.seq;
	struct instruction *insn;
	unsigned int i;

	if (strcmp(func->name, "asm_acpi_mp_play_dead") || is_weak_sym(func) ||
	    !rap_sequence_reference(s, "\x48\x8d\x05", 3, "hdn_madt_launch", true) ||
	    !rap_sequence_bytes(s, "\x48\x83\x38\x01", 4) ||
	    !rap_kexec_branch(&k, 0x75, 0) ||
	    !rap_sequence_bytes(s, "\x48\x8b\x70\x08\x48\x8b\x78\x10"
		"\x0f\x20\xe2\x48\x81\xe2\x7f\xff\xff\xff\x0f\x22\xe2"
		"\x0f\x22\xde\xff\xe7", 26) ||
	    !rap_kexec_label(&k, 0) || !rap_sequence_bytes(s, "\xfa", 1) ||
	    !rap_kexec_label(&k, 1) || !rap_sequence_bytes(s, "\xf4", 1) ||
	    !rap_kexec_branch(&k, 0xeb, 1) || s->pos != func->len)
		goto bad;
	for (i = 0; i < k.count; i++)
		if (!k.branches[i].insn->jump_dest ||
		    k.branches[i].insn->jump_dest->sec != func->sec ||
		    k.branches[i].insn->jump_dest->offset != k.labels[k.branches[i].label])
			goto bad;
	rap_for_each_insn(file, func, insn)
		if (insn->alts)
			goto bad;
	for_each_insn(file, insn)
		if (rap_insn_owner(insn) != func && insn->jump_dest &&
		    insn->jump_dest->sec == func->sec &&
		    insn->jump_dest->offset > func->offset &&
		    insn->jump_dest->offset < func->offset + func->len)
			goto bad;
	func->rap_madt_protocol = true;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s->pos, "RAP ACPI CPU-reset handoff has an invalid frozen-launch protocol");
	return -1;
}

static int read_rap_functions(struct objtool_file *file)
{
	struct section *sec = find_section_by_name(file->elf, ".discard.hdn_rap.functions");
	unsigned long off;

	if (!sec)
		return 0;
	if (file->elf->ehdr.e_machine != EM_X86_64 || sec_size(sec) % 24) {
		ERROR("invalid RAP function coverage section");
		return -1;
	}
	for (off = 0; off < sec_size(sec); off += 24) {
		struct reloc *reloc = find_reloc_by_dest(file->elf, sec, off);
		struct instruction *first;
		struct symbol *func;
		uint64_t kind, returns;

		memcpy(&kind, sec->data->d_buf + off + 8, 8);
		memcpy(&returns, sec->data->d_buf + off + 16, 8);
		if (memcmp(sec->data->d_buf + off, (char[8]){}, 8) || !reloc ||
		    arch_reloc_size(reloc) != 8 || (kind < 1 || kind > 54) ||
		    (kind != 1 && kind != 5 && returns) ||
		    find_reloc_by_dest_range(file->elf, sec, off + 8, 16)) {
			ERROR("invalid RAP function coverage record");
			return -1;
		}
		first = find_insn(file, reloc->sym->sec, reloc->sym->offset + reloc_addend(reloc));
		func = first ? rap_insn_owner(first) : NULL;
		if (!func || (!is_func_sym(func) && !is_notype_sym(func)) ||
		    first->offset != func->offset || func->rap_kind || func->cold ||
		    returns > func->len + (func->cfunc ? func->cfunc->len : 0)) {
			ERROR("RAP coverage does not name a unique function start");
			return -1;
		}
		if ((rap_adapter_name(func->name) && kind != 4) ||
		    (((kind >= 52 && kind <= 54) || rap_pvh_kind(func->name)) &&
		     kind != rap_pvh_kind(func->name)) ||
		    ((kind == 51 || !strcmp(func->name, "just_return_func")) &&
		     (kind != 51 || strcmp(func->name, "just_return_func"))) ||
		    ((kind == 48 || !strcmp(func->name, "startup_64")) &&
		     (kind != 48 || strcmp(func->name, "startup_64"))) ||
		    ((kind == 49 || !strcmp(func->name, "secondary_startup_64")) &&
		     (kind != 49 || strcmp(func->name, "secondary_startup_64"))) ||
		    ((kind == 50 || !strcmp(func->name, "common_startup_64")) &&
		     (kind != 50 || strcmp(func->name, "common_startup_64"))) ||
		    ((kind == 46 || !strcmp(func->name, "early_idt_handler_array")) &&
		     (kind != 46 || strcmp(func->name, "early_idt_handler_array"))) ||
		    ((kind == 47 || !strcmp(func->name, "early_idt_handler_common")) &&
		     (kind != 47 || strcmp(func->name, "early_idt_handler_common"))) ||
		    ((kind == 44 || !strcmp(func->name, "entry_SYSENTER_compat")) &&
		     (kind != 44 || strcmp(func->name, "entry_SYSENTER_compat"))) ||
		    ((kind == 45 || !strcmp(func->name, "entry_SYSCALL_compat")) &&
		     (kind != 45 || strcmp(func->name, "entry_SYSCALL_compat"))) ||
		    ((kind == 40 || !strcmp(func->name, "common_interrupt_return")) &&
		     (kind != 40 || strcmp(func->name, "common_interrupt_return"))) ||
		    ((kind == 41 || !strcmp(func->name, "asm_exc_nmi")) &&
		     (kind != 41 || strcmp(func->name, "asm_exc_nmi"))) ||
		    ((kind == 42 || !strcmp(func->name, "entry_SYSCALL_64")) &&
		     (kind != 42 || strcmp(func->name, "entry_SYSCALL_64"))) ||
		    ((kind == 43 || !strcmp(func->name, "entry_SYSCALL32_ignore")) &&
		     (kind != 43 || strcmp(func->name, "entry_SYSCALL32_ignore"))) ||
		    (((kind >= 37 && kind <= 39) || rap_entry_root_kind(func->name)) &&
		     kind != rap_entry_root_kind(func->name)) ||
		    (((kind >= 33 && kind <= 36) || rap_idt_kind(func->name)) &&
		     kind != rap_idt_kind(func->name)) ||
		    ((kind == 32 || !strcmp(func->name, "wakeup_long64")) &&
		     (kind != 32 || strcmp(func->name, "wakeup_long64"))) ||
		    ((kind == 30 || !strcmp(func->name, "__switch_to_asm")) &&
		     (kind != 30 || strcmp(func->name, "__switch_to_asm"))) ||
		    ((kind == 31 || !strcmp(func->name, "ret_from_fork_asm")) &&
		     (kind != 31 || strcmp(func->name, "ret_from_fork_asm"))) ||
		    ((kind == 28 || rap_fred_name(func->name)) &&
		     (kind != 28 || !rap_fred_name(func->name))) ||
		    ((kind == 29 || !strcmp(func->name, "verify_cpu")) &&
		     (kind != 29 || strcmp(func->name, "verify_cpu"))) ||
		    ((kind == 27 || rap_thunk_name(func->name)) &&
		     (kind != 27 || !rap_thunk_name(func->name))) ||
		    (((kind >= 21 && kind <= 25) || rap_hv_crash_kind(func->name)) &&
		     kind != rap_hv_crash_kind(func->name)) ||
		    (kind == 26 && strcmp(func->name, "hdn_realmode_restart")) ||
		    (!strcmp(func->name, "hdn_realmode_restart") && kind != 26) ||
		    (kind == 19 && strcmp(func->name, "hdn_hv_hypercall")) ||
		    (kind == 20 && strcmp(func->name, "hdn_hv_vtl_gate")) ||
		    (!strcmp(func->name, "hdn_hv_hypercall") && kind != 19) ||
		    (!strcmp(func->name, "hdn_hv_vtl_gate") && kind != 20) ||
		    (kind == 18 && strcmp(func->name, "asm_acpi_mp_play_dead")) ||
		    (!strcmp(func->name, "asm_acpi_mp_play_dead") && kind != 18) ||
		    (kind == 6 && !func->static_call_tramp) ||
		    (func->static_call_tramp && kind != 6) ||
		    (kind == 5 && !rap_private_name(func->name)) ||
		    (rap_private_name(func->name) && kind != 5) ||
		    ((!strcmp(func->name, "restore_image") ||
		      !strcmp(func->name, "core_restore_code")) && kind != 8) ||
		    (!strcmp(func->name, "restore_registers") && kind != 9) ||
		    (!strcmp(func->name, "hdn_rap_kexec") && kind != 10) ||
		    (rap_kexec_terminal_name(func->name) && kind != 11) ||
		    (!strcmp(func->name, "hdn_rap_kexec_return") && kind != 12) ||
		    (!strcmp(func->name, "__hdn_efi_call") && kind != 14) ||
		    (!strcmp(func->name, "__hdn_efi_return") && kind != 15) ||
		    (!strcmp(func->name, "__hdn_efi_fault_return") && kind != 16) ||
		    (!strcmp(func->name, "__hdn_efi64_thunk") && kind != 17) ||
		    ((!strcmp(func->name, "vmx_do_nmi_irqoff") ||
		      !strcmp(func->name, "vmx_do_interrupt_irqoff")) && kind != 13) ||
		    (!strcmp(func->name, "__hdn_rap_fail") && kind != 3) ||
		    (!strcmp(func->name, "__hdn_rap_halt") && kind != 2)) {
			ERROR("RAP runtime protocol has the wrong coverage kind");
			return -1;
		}
		func->rap_kind = kind;
		func->rap_returns = returns;
		if (kind == 7 && opts.link && strncmp(func->name, "__pi_", 5)) {
			ERROR("RAP bootstrap coverage escaped the prefixed physical startup domain");
			return -1;
		}
	}
	{
		struct symbol *func;

		for_each_sym(file->elf, func)
			if (func->rap_kind == 27 && verify_rap_thunk(file, func))
				return -1;
		if (validate_rap_thunk_peers(file))
			return -1;
		if (read_rap_mitigation_calls(file))
			return -1;
		for_each_sym(file->elf, func)
			if (func->rap_kind >= 33 && func->rap_kind <= 36 && verify_rap_idt(file, func))
				return -1;
		if (validate_rap_idt_peers(file))
			return -1;
		for_each_sym(file->elf, func)
			if (func->rap_kind >= 37 && func->rap_kind <= 39 && verify_rap_entry_root(file, func))
				return -1;
		if (validate_rap_entry_root_peers(file))
			return -1;
		for_each_sym(file->elf, func) {
			if (((func->rap_kind >= 52 && func->rap_kind <= 54) && verify_rap_pvh(file, func)) ||
			    (func->rap_kind == 51 && verify_rap_error_return(file, func)) ||
			    (func->rap_kind == 40 && verify_rap_interrupt_return(file, func)) ||
			    (func->rap_kind == 41 && verify_rap_nmi(file, func)) ||
			    (func->rap_kind == 42 && verify_rap_syscall(file, func)) ||
			    (func->rap_kind == 43 && verify_rap_syscall32_ignore(file, func)) ||
			    ((func->rap_kind == 44 || func->rap_kind == 45) && verify_rap_compat(file, func)) ||
			    ((func->rap_kind == 46 || func->rap_kind == 47) && verify_rap_early_idt(file, func)) ||
			    ((func->rap_kind >= 48 && func->rap_kind <= 50) && verify_rap_startup(file, func)))
				return -1;
		}
		if (validate_rap_interrupt_return_peers(file) || validate_rap_syscall_peers(file) ||
		    validate_rap_compat_peers(file) || validate_rap_early_idt_peers(file))
			return -1;
		if (validate_rap_startup_peers(file))
			return -1;
		if (validate_rap_pvh_peers(file))
			return -1;
		for_each_sym(file->elf, func)
			if (!strcmp(func->name, "rewind_stack_and_make_dead") && !is_undef_sym(func) &&
			    verify_rap_rewind(file, func))
				return -1;
		for_each_sym(file->elf, func)
			if ((func->rap_kind == 32 || (!strcmp(func->name, "do_suspend_lowlevel") &&
			     !is_undef_sym(func))) && verify_rap_s3(file, func))
				return -1;
		for_each_sym(file->elf, func)
			if ((func->rap_kind == 30 || func->rap_kind == 31) && verify_rap_switch(file, func))
				return -1;
		for_each_sym(file->elf, func)
			if (func->rap_kind == 28 && verify_rap_fred(file, func))
				return -1;
		for_each_sym(file->elf, func)
			if (func->rap_kind == 29 && verify_rap_cpu(file, func))
				return -1;
		for_each_sym(file->elf, func)
			if (func->rap_kind == 26 && verify_rap_realmode_restart(file, func))
				return -1;
		for_each_sym(file->elf, func)
			if (func->rap_kind >= 21 && func->rap_kind <= 25 && verify_rap_hv_crash(file, func))
				return -1;
		for_each_sym(file->elf, func)
			if ((func->rap_kind == 19 || func->rap_kind == 20) &&
			    verify_rap_hyperv(file, func))
				return -1;
		for_each_sym(file->elf, func)
			if (func->rap_kind == 18 && verify_rap_madt(file, func))
				return -1;
		for_each_sym(file->elf, func)
			if (!strcmp(func->name, "ibt_selftest") && is_func_sym(func) &&
			    verify_rap_ibt(file, func))
				return -1;
		for_each_sym(file->elf, func)
			if (rap_regs_name(func->name) && is_func_sym(func) &&
			    verify_rap_regs(file, func))
				return -1;
		for_each_sym(file->elf, func)
			if (func->rap_kind == 3 && verify_rap_terminal(file, func))
				return -1;
		for_each_sym(file->elf, func)
			if (func->rap_kind == 4 && verify_rap_adapter(file, func))
				return -1;
		for_each_sym(file->elf, func)
			if (func->rap_kind == 8 && verify_rap_image_handoff(file, func))
				return -1;
		for_each_sym(file->elf, func)
			if (func->rap_kind == 9 && verify_rap_image_resume(file, func))
				return -1;
		for_each_sym(file->elf, func)
			if (func->rap_kind >= 10 && func->rap_kind <= 12 && verify_rap_kexec(file, func))
				return -1;
		for_each_sym(file->elf, func)
			if (func->rap_kind >= 14 && func->rap_kind <= 17 && verify_rap_efi(file, func))
				return -1;
		for_each_sym(file->elf, func)
			if (func->rap_kind == 13 && verify_rap_hardware_event(file, func))
				return -1;
		if (validate_rap_nmi_peers(file))
			return -1;
		for_each_sym(file->elf, func)
			if (func->rap_kind == 5 && !strcmp(func->name, "ftrace_regs_caller") &&
			    verify_rap_ftrace_handoff(file, func))
				return -1;
	}
	return 0;
}

/* Bind the runtime redirection table to actual compiler entry and fentry
 * instructions. A type-compatible address alone must not nominate an interior
 * label as the replacement function's protected-body continuation. */
static int read_rap_function_entries(struct objtool_file *file)
{
	struct section *sec = find_section_by_name(file->elf, ".hdn.rap.entries");
	unsigned long off;

	if (!sec)
		return 0;
	if (sec_size(sec) % 32) {
		ERROR("invalid RAP typed-entry metadata size");
		return -1;
	}
	for (off = 0; off < sec_size(sec); off += 32) {
		struct reloc *start = find_reloc_by_dest(file->elf, sec, off);
		struct reloc *type = find_reloc_by_dest(file->elf, sec, off + 8);
		struct reloc *body = find_reloc_by_dest(file->elf, sec, off + 16);
		struct reloc *trace = find_reloc_by_dest(file->elf, sec, off + 24);
		struct instruction *first, *entry, *trace_call;
		struct symbol *func, *callee;
		unsigned long body_offset;

		if (memcmp(sec->data->d_buf + off, (char[32]){}, 32))
			goto bad;
		if (!start && !type && !body && !trace)
			continue;
		if (!start || !type || !body || arch_reloc_size(start) != 8 ||
		    arch_reloc_size(type) != 8 || arch_reloc_size(body) != 8 ||
		    (strcmp(type->sym->sec->name, ".hdn.rap.types") &&
		     (opts.link || type->sym->sec->idx != SHN_UNDEF ||
		      strncmp(type->sym->name, "__hdn_rap_type_", 15))))
			goto bad;
		first = find_insn(file, start->sym->sec, start->sym->offset + reloc_addend(start));
		func = first ? rap_insn_owner(first) : NULL;
		if (!func || first->offset != func->offset ||
		    (func->rap_kind && func->rap_kind != 1) || func->rap_typed_entry)
			goto bad;
		if (first->type == INSN_ENDBR)
			first = next_insn_same_sec(file, first);
		entry = first ? next_insn_same_sec(file, first) : NULL;
		if (!entry || !entry->rap_entry || body->sym->sec != entry->sec)
			goto bad;
		body_offset = body->sym->offset + reloc_addend(body);
		if (body_offset != entry->offset + entry->len)
			goto bad;
		trace_call = find_insn(file, entry->sec, body_offset + 7);
		callee = trace_call ? insn_call_dest(trace_call) : NULL;
		if (trace) {
			if (arch_reloc_size(trace) != 8 || trace->sym->sec != entry->sec ||
			    trace->sym->offset + reloc_addend(trace) != body_offset + 12 ||
			    !trace_call || !trace_call->rap_site || !callee || !callee->fentry)
				goto bad;
		} else if (callee && callee->fentry) {
			goto bad;
		}
		func->rap_typed_entry = true;
	}
	return 0;
bad:
	ERROR("RAP typed-entry metadata does not match the protected function body");
	return -1;
}

/* Static-call contracts preserve the native eight-byte patch ABI. They are
 * direct-call identities, not function-entry or indirect-target permissions. */
static int read_rap_static_calls(struct objtool_file *file)
{
	struct section *contracts = find_section_by_name(file->elf, ".hdn.rap.static_calls");
	struct section *sites = find_section_by_name(file->elf, ".hdn.rap.static_sites");
	unsigned long off;

	if (contracts && sec_size(contracts) % 32)
		goto bad;
	if (sites && sec_size(sites) % 16)
		goto bad;
	for (off = 0; contracts && off < sec_size(contracts); off += 32) {
		struct reloc *start = find_reloc_by_dest(file->elf, contracts, off);
		struct reloc *key = find_reloc_by_dest(file->elf, contracts, off + 8);
		struct reloc *type = find_reloc_by_dest(file->elf, contracts, off + 16);
		struct reloc *zero = find_reloc_by_dest(file->elf, contracts, off + 24);
		struct instruction *first, *insn;
		struct symbol *func, *callee, *type_anchor, *zero_anchor;
		struct rap_sequence sequence;
		uint64_t flags;
		char *anchor_name;
		unsigned int field;

		memcpy(&flags, contracts->data->d_buf + off + 24, 8);
		if (!start && !key && !type && !zero &&
		    !memcmp(contracts->data->d_buf + off, (char[32]){}, 32) &&
		    !find_reloc_by_dest_range(file->elf, contracts, off, 32))
			continue;
		if (!start || !key || !type || arch_reloc_size(start) != 8 ||
		    arch_reloc_size(key) != 8 || arch_reloc_size(type) != 8 ||
		    memcmp(contracts->data->d_buf + off, (char[24]){}, 24))
			goto bad;
		for (field = 0; field < 32; field += 8)
			if (find_reloc_by_dest_range(file->elf, contracts, off + field + 1, 7))
				goto bad;
		first = find_insn(file, start->sym->sec, start->sym->offset + reloc_addend(start));
		func = first ? rap_insn_owner(first) : NULL;
		callee = first ? insn_call_dest(first) : NULL;
		if (!func || first->offset != func->offset || !func->static_call_tramp ||
		    func->rap_kind != 6 || func->rap_static_contract || func->len != 8 ||
		    strcmp(func->sec->name, ".static_call.text") || is_weak_sym(func) ||
		    !callee || first->len != 5 ||
		    strncmp(key->sym->name, STATIC_CALL_KEY_PREFIX_STR, STATIC_CALL_KEY_PREFIX_LEN) ||
		    strcmp(key->sym->name + STATIC_CALL_KEY_PREFIX_LEN,
			   func->name + STATIC_CALL_TRAMP_PREFIX_LEN) || reloc_addend(key) ||
		    (strcmp(type->sym->sec->name, ".hdn.rap.types") &&
		     (opts.link || !is_undef_sym(type->sym) ||
		      strncmp(type->sym->name, "__hdn_rap_type_", 15))))
			goto bad;
		if (asprintf(&anchor_name, "__hdn_rap_type_%s", func->name) < 0)
			goto bad;
		type_anchor = find_symbol_by_name(file->elf, anchor_name);
		free(anchor_name);
		if (!type_anchor || type->sym->sec != type_anchor->sec ||
		    type->sym->offset + reloc_addend(type) != type_anchor->offset ||
		    (is_undef_sym(type_anchor) && type->sym != type_anchor))
			goto bad;
		if (zero) {
			const char *prefix = "__hdn_rap_static_zero_";

			if (flags || arch_reloc_size(zero) != 8 || reloc_addend(zero))
				goto bad;
			/* ld -r folds a zero-valued weak absolute anchor into the ELF
			 * null symbol. This still resolves to exactly zero, not a
			 * missing external permission which could be rebound later. */
			if (zero->sym->idx && (zero->sym->sym.st_shndx != SHN_ABS ||
			    strncmp(zero->sym->name, prefix, strlen(prefix)) ||
			    strcmp(zero->sym->name + strlen(prefix), func->name)))
				goto bad;
			flags = zero->sym->offset;
		}
		if (asprintf(&anchor_name, "__hdn_rap_static_zero_%s", func->name) < 0)
			goto bad;
		zero_anchor = find_symbol_by_name(file->elf, anchor_name);
		free(anchor_name);
		if (!zero_anchor || zero_anchor->sym.st_shndx != SHN_ABS ||
		    zero_anchor->offset != flags || flags > 1 ||
		    (!strcmp(callee->name, "__static_call_return0") && !flags))
			goto bad;
		sequence = (struct rap_sequence) { .file = file, .func = func };
		if (!rap_sequence_edge(&sequence, callee->name, false) ||
		    !rap_sequence_bytes(&sequence, "\x0f\xb9\xcc", 3) || sequence.pos != func->len)
			goto bad;
		rap_for_each_insn(file, func, insn)
			if (insn->alts)
				goto bad;
		func->rap_static_contract = true;
	}
	for (off = 0; sites && off < sec_size(sites); off += 16) {
		struct reloc *site = find_reloc_by_dest(file->elf, sites, off);
		struct reloc *tramp = find_reloc_by_dest(file->elf, sites, off + 8);
		struct instruction *call;
		struct symbol *callee;
		unsigned long return_site;

		if (!site && !tramp && !memcmp(sites->data->d_buf + off, (char[16]){}, 16) &&
		    !find_reloc_by_dest_range(file->elf, sites, off, 16))
			continue;
		if (!site || !tramp || arch_reloc_size(site) != 8 || arch_reloc_size(tramp) != 8 ||
		    memcmp(sites->data->d_buf + off, (char[16]){}, 16) ||
		    find_reloc_by_dest_range(file->elf, sites, off + 1, 7) ||
		    find_reloc_by_dest_range(file->elf, sites, off + 9, 7))
			goto bad;
		return_site = site->sym->offset + reloc_addend(site);
		call = return_site >= 5 ? find_insn(file, site->sym->sec, return_site - 5) : NULL;
		callee = call ? insn_call_dest(call) : NULL;
		if (!call || call->len != 5 || call->type != INSN_CALL || !call->rap_site ||
		    call->rap_static_site || !callee || !callee->static_call_tramp ||
		    tramp->sym->sec != callee->sec ||
		    (is_undef_sym(callee) && tramp->sym != callee) ||
		    tramp->sym->offset + reloc_addend(tramp) != callee->offset)
			goto bad;
		call->rap_static_site = true;
	}
	return 0;
bad:
	ERROR("RAP static-call metadata does not match its exact patch contract");
	return -1;
}

/* A strict producer, separate from ordinary ORC/IBT validation. Assembly which
 * has not yet acquired its explicit ABI adapter fails this gate. Neither a
 * stack/unreachable annotation nor a compiler runtime record exempts a transfer
 * from the required binding checks. */
static int validate_rap(struct objtool_file *file)
{
	struct symbol *func;
	struct instruction *insn;
	struct section *targets = find_section_by_name(file->elf, ".hdn.rap.targets");
	int warnings = 0;

	if (file->elf->ehdr.e_machine != EM_X86_64) {
		ERROR("RAP coverage is defined only for x86-64");
		return 1;
	}
	for_each_sym(file->elf, func) {
		unsigned long returns = 0, entries = 0;
		struct instruction *first;
		bool protected = func->rap_kind == 1 || func->rap_kind == 5;

		if ((!is_func_sym(func) && !is_notype_sym(func)) || !func->sec->text ||
		    !func->len || func->cold || func->embedded_insn)
			continue;
		first = find_insn(file, func->sec, func->offset);
		/* Aliases share the exact same body and canonical coverage record. */
		if (first && rap_insn_owner(first) != func)
			continue;
		if (first && first->type == INSN_ENDBR)
			first = next_insn_same_sec(file, first);
		if (!func->rap_kind) {
			WARN_FUNC(func->sec, func->offset, "function lacks RAP coverage");
			warnings++;
			continue;
		}
		if (func->rap_kind == 1 && !func->rap_typed_entry) {
			WARN_FUNC(func->sec, func->offset, "function lacks RAP typed-entry metadata");
			warnings++;
		}
		if ((func->rap_kind == 5 || func->rap_kind == 6 || func->rap_kind == 7 ||
		     func->rap_kind == 8 || func->rap_kind == 9 || func->rap_kind >= 10) && targets) {
			unsigned long off;

			for (off = 0; off < sec_size(targets); off += 16) {
				struct reloc *reloc = find_reloc_by_dest(file->elf, targets, off);

				if (reloc && reloc->sym->sec == func->sec &&
				    reloc->sym->offset + reloc_addend(reloc) >= func->offset &&
				    reloc->sym->offset + reloc_addend(reloc) < func->offset + func->len) {
					WARN_FUNC(func->sec, func->offset, "private RAP ABI has an ordinary indirect target");
					warnings++;
				}
			}
		}
		if (func->rap_kind >= 52 && func->rap_kind <= 54) {
			if (!func->rap_pvh_protocol) {
				WARN_FUNC(func->sec, func->offset, "RAP PVH root lacks a checked boot protocol");
				warnings++;
			}
			continue;
		}
		if (func->rap_kind == 51) {
			if (!func->rap_error_return_protocol) {
				WARN_FUNC(func->sec, func->offset, "RAP error injection lacks a checked epilogue");
				warnings++;
			}
			continue;
		}
		if (func->rap_kind >= 40 && func->rap_kind <= 50) {
			bool complete = func->rap_kind == 41 ? func->rap_nmi_protocol :
				func->rap_kind == 42 ? func->rap_syscall_protocol :
				func->rap_kind >= 48 ? func->rap_startup_protocol :
				func->rap_kind >= 46 ? func->rap_early_idt_protocol :
				func->rap_kind >= 44 ? func->rap_compat_protocol : func->rap_interrupt_return_protocol;
			if (!complete) {
				WARN_FUNC(func->sec, func->offset, "RAP hardware root lacks a checked entry/exit protocol");
				warnings++;
			}
			continue;
		}
		if (func->rap_kind >= 37 && func->rap_kind <= 39) {
			if (!func->rap_entry_root_protocol) {
				WARN_FUNC(func->sec, func->offset, "RAP pre-C helper lacks a checked entry protocol");
				warnings++;
			}
			continue;
		}
		if (func->rap_kind >= 33 && func->rap_kind <= 36) {
			if (!func->rap_idt_protocol) {
				WARN_FUNC(func->sec, func->offset, "RAP IDT entry lacks a checked native frame protocol");
				warnings++;
			}
			continue;
		}
		if (func->rap_kind == 32 || !strcmp(func->name, "do_suspend_lowlevel")) {
			struct symbol *state = find_symbol_by_name(file->elf, "hdn_rap_resume_state");
			struct symbol *save = find_symbol_by_name(file->elf, "hdn_rap_resume_save");
			struct symbol *restore = find_symbol_by_name(file->elf, "hdn_rap_resume_restore");
			struct symbol *entry = find_symbol_by_name(file->elf, "wakeup_long64");
			struct symbol *body = find_symbol_by_name(file->elf, "do_suspend_lowlevel");

			if (!func->rap_s3_protocol || !entry || !entry->rap_s3_protocol ||
			    !body || !body->rap_s3_protocol || (opts.link &&
			    (!state || strcmp(state->sec->name, ".data..ro_after_init") ||
			     !save || save->rap_kind != 2 || !restore || restore->rap_kind != 2))) {
				WARN_FUNC(func->sec, func->offset, "RAP S3 lacks its sealed checkpoint and fixed continuation");
				warnings++;
			}
			if (func->rap_kind == 32)
				continue;
		}
		if (func->rap_kind == 30 || func->rap_kind == 31) {
			struct symbol *switcher = find_symbol_by_name(file->elf, "__switch_to");
			struct symbol *capture = find_symbol_by_name(file->elf, "hdn_rap_switch");
			struct symbol *fork = find_symbol_by_name(file->elf, "ret_from_fork");
			struct symbol *seed = find_symbol_by_name(file->elf, "hdn_rap_task_seed");

			if (!func->rap_switch_protocol || (opts.link &&
			    (!switcher || switcher->rap_kind != 1 || !capture || capture->rap_kind != 2 ||
			     !fork || fork->rap_kind != 1 || !seed || seed->rap_kind != 2))) {
				WARN_FUNC(func->sec, func->offset, "RAP switch/fork lacks its protected runtime and continuation");
				warnings++;
			}
			continue;
		}
		if (func->rap_kind == 28) {
			static const char * const roots[] = {
				"fred_entry_from_user", "fred_entry_from_kernel",
				"hdn_rap_frame_enter", "hdn_rap_frame_exit",
			};
			unsigned int n;

			if (!func->rap_fred_protocol) {
				WARN_FUNC(func->sec, func->offset, "RAP FRED root lacks a checked frame protocol");
				warnings++;
			}
			for (n = 0; opts.link && n < ARRAY_SIZE(roots); n++) {
				struct symbol *root = find_symbol_by_name(file->elf, roots[n]);
				if (!root || root->rap_kind != (n < 2 ? 1 : 2)) {
					WARN_FUNC(func->sec, func->offset, "RAP FRED handler/runtime coverage is incomplete");
					warnings++;
				}
			}
			continue;
		}
		if (func->rap_kind == 29) {
			if (!func->rap_cpu_protocol) {
				WARN_FUNC(func->sec, func->offset, "RAP CPU startup leaf lacks a checked instruction protocol");
				warnings++;
			}
			continue;
		}
		if (func->rap_kind == 27) {
			if (!func->rap_thunk_protocol) {
				WARN_FUNC(func->sec, func->offset, "RAP mitigation thunk lacks a checked instruction protocol");
				warnings++;
			}
			continue;
		}
		if (func->rap_kind == 26) {
			struct symbol *state = find_symbol_by_name(file->elf, "hdn_realmode_reboot");
			if (!func->rap_realmode_protocol || !state || (opts.link &&
			    (strcmp(state->sec->name, ".data..ro_after_init") || state->len != 16))) {
				WARN_FUNC(func->sec, func->offset, "RAP reboot lacks its immutable launch descriptor");
				warnings++;
			}
			continue;
		}
		if (func->rap_kind >= 21 && func->rap_kind <= 25) {
			struct symbol *cpu = find_symbol_by_name(file->elf, "hdn_hv_crash_cpu");
			struct symbol *capture = find_symbol_by_name(file->elf, "hdn_hv_crash_capture");
			struct symbol *finish = find_symbol_by_name(file->elf, "hdn_hv_crash_finish");
			struct symbol *handler = find_symbol_by_name(file->elf, "hv_crash_handle");
			unsigned int kind;

			if (!func->rap_hv_crash_protocol || (opts.link &&
			    (!cpu || cpu->len != 128 || strcmp(cpu->sec->name, ".data..ro_after_init") ||
			     !capture || capture->rap_kind != 2 || !finish || finish->rap_kind != 2 ||
			     !handler || handler->rap_kind != 1))) {
				WARN_FUNC(func->sec, func->offset, "RAP Hyper-V crash recovery lacks protected state and runtime roots");
				warnings++;
			}
			if (opts.link) {
				static const char * const names[] = { "hdn_hv_crash_enter", "hdn_hv_crash_return",
					"hdn_hv_crash_continue", "hv_crash_asm32", "hv_crash_asm64" };
				for (kind = 0; kind < ARRAY_SIZE(names); kind++) {
					struct symbol *peer = find_symbol_by_name(file->elf, names[kind]);
					if (!peer || peer->rap_kind != kind + 21 || !peer->rap_hv_crash_protocol) {
						WARN_FUNC(func->sec, func->offset, "RAP Hyper-V crash path is incomplete");
						warnings++;
					}
				}
			}
			continue;
		}
		if (func->rap_kind == 19 || func->rap_kind == 20) {
			struct symbol *state = find_symbol_by_name(file->elf,
				func->rap_kind == 19 ? "hdn_hv_hypercall_target" : "hdn_hv_vtl_target");
			struct symbol *ret = find_symbol_by_name(file->elf, "__hdn_rap_return");

			if (!func->rap_hyperv_protocol || !state || !ret ||
			    (opts.link && (strcmp(state->sec->name, ".data..ro_after_init") ||
				state->len != 8 || !ret->rap_adapter))) {
				WARN_FUNC(func->sec, func->offset, "RAP Hyper-V gateway lacks its sealed endpoint and return root");
				warnings++;
			}
			continue;
		}
		if (func->rap_kind == 18) {
			struct symbol *state = find_symbol_by_name(file->elf, "hdn_madt_launch");

			if (!func->rap_madt_protocol || !state ||
			    (opts.link && (strcmp(state->sec->name, ".data..ro_after_init") ||
				state->len != 4096 || (state->offset & 4095)))) {
				WARN_FUNC(func->sec, func->offset, "RAP ACPI reset lacks its dedicated frozen launch page");
				warnings++;
			}
			continue;
		}
		if (func->rap_kind >= 14 && func->rap_kind <= 17) {
			struct symbol *enter = find_symbol_by_name(file->elf, "hdn_efi_enter");
			struct symbol *finish = find_symbol_by_name(file->elf, "hdn_efi_finish");
			struct symbol *state = find_symbol_by_name(file->elf, "hdn_efi_state");
			struct symbol *ret = find_symbol_by_name(file->elf, "__hdn_rap_return");
			struct symbol *gate = find_symbol_by_name(file->elf, "__hdn_efi_return");
			struct symbol *fault = find_symbol_by_name(file->elf, "__hdn_efi_fault_return");

			if (!func->rap_efi_protocol || !enter || !finish || !state || !ret ||
			    (opts.link && (enter->rap_kind != 2 || finish->rap_kind != 2 ||
				!gate || gate->rap_kind != 15 || !gate->rap_efi_protocol ||
				!fault || fault->rap_kind != 16 || !fault->rap_efi_protocol ||
				!ret->rap_adapter || strcmp(state->sec->name, ".data..ro_after_init")))) {
				WARN_FUNC(func->sec, func->offset, "RAP EFI lacks its closed runtime and protected state");
				warnings++;
			}
			continue;
		}
		if (func->rap_kind == 13) {
			struct symbol *selector = find_symbol_by_name(file->elf, "hdn_rap_vmx_vector");
			if (!func->rap_hardware_event ||
			    (!strcmp(func->name, "vmx_do_interrupt_irqoff") &&
			     (!selector || (!is_undef_sym(selector) && selector->rap_kind != 1)))) {
				WARN_FUNC(func->sec, func->offset, "RAP synthetic interrupt lacks its protected selector");
				warnings++;
			}
			continue;
		}
		if (func->rap_kind >= 10 && func->rap_kind <= 12) {
			static const char * const roots[] = {
				"hdn_rap_kexec_enter", "hdn_rap_kexec_finish",
			};
			unsigned int i;

			if (!func->rap_kexec_protocol) {
				WARN_FUNC(func->sec, func->offset, "unverified RAP kexec protocol");
				warnings++;
			}
			if (opts.link) {
				struct symbol *state = find_symbol_by_name(file->elf, "hdn_rap_kexec_state");
				struct symbol *ret = find_symbol_by_name(file->elf, "hdn_rap_kexec_return");
				struct symbol *entry = find_symbol_by_name(file->elf, "hdn_rap_kexec");
				struct symbol *auth = find_symbol_by_name(file->elf, "__hdn_rap_return");

				if (!state || strcmp(state->sec->name, ".data..ro_after_init") ||
				    !ret || !ret->rap_kexec_protocol || ret->rap_kind != 12 ||
				    !entry || !entry->rap_kexec_protocol || entry->rap_kind != 10 ||
				    !auth || !auth->rap_adapter) {
					WARN_FUNC(func->sec, func->offset, "RAP kexec lacks its protected state and return adapter");
					warnings++;
				}
				for (i = 0; i < ARRAY_SIZE(roots); i++) {
					struct symbol *root = find_symbol_by_name(file->elf, roots[i]);
					if (!root || root->rap_kind != 2) {
						WARN_FUNC(func->sec, func->offset, "RAP kexec lacks its closed runtime root");
						warnings++;
					}
				}
			}
			continue;
		}
		if (func->rap_kind == 9) {
			struct symbol *restore = find_symbol_by_name(file->elf, "hdn_rap_resume_restore");
			struct symbol *ret = find_symbol_by_name(file->elf, "__hdn_rap_return");
			struct symbol *state = find_symbol_by_name(file->elf, "hdn_rap_resume_state");

			if (!func->rap_resume_entry || !restore || !ret || !state ||
			    (opts.link && (restore->rap_kind != 2 || !ret->rap_adapter ||
					  strcmp(state->sec->name, ".data..ro_after_init")))) {
				WARN_FUNC(func->sec, func->offset, "RAP image resume lacks its protected checkpoint/return roots");
				warnings++;
			}
			continue;
		}
		if (func->rap_kind == 8) {
			struct symbol *admit = find_symbol_by_name(file->elf, "hdn_rap_hibernate_enter");
			struct symbol *launch = find_symbol_by_name(file->elf, "restore_image");
			struct symbol *copy = find_symbol_by_name(file->elf, "core_restore_code");

			if (!func->rap_image_handoff || !launch || !copy ||
			    !launch->rap_image_handoff || !copy->rap_image_handoff ||
			    !admit || (admit->rap_kind != 2 &&
				       (opts.link || !is_undef_sym(admit)))) {
				WARN_FUNC(func->sec, func->offset, "RAP image handoff lacks its closed admission root");
				warnings++;
			}
			continue;
		}
		if (func->rap_kind == 7) {
			/* Physical startup has no runtime GS/stack identity. It is a
			 * closed direct-call domain, not an uninstrumented target set
			 * callable by ordinary kernel code. */
			rap_for_each_insn(file, func, insn) {
				struct symbol *callee = insn_call_dest(insn);

				if (insn->type == INSN_CALL_DYNAMIC || is_dynamic_jump(insn) ||
				    ((insn->type == INSN_CALL || is_sibling_call(insn)) &&
				     (!callee || (callee->rap_kind != 7 &&
				      (opts.link || !is_undef_sym(callee)))))) {
					WARN_INSN(insn, "RAP bootstrap leaves its closed direct-call domain");
					warnings++;
				}
			}
			continue;
		}
		if (func->rap_kind == 6) {
			struct symbol *callee = first ? insn_call_dest(first) : NULL;

			if (!func->rap_static_contract || !callee ||
			    (!is_undef_sym(callee) && callee->rap_kind != 1 &&
			     !(callee->rap_adapter && !strcmp(callee->name, "__hdn_rap_static_null")))) {
				WARN_FUNC(func->sec, func->offset, "static-call trampoline lacks protected destination coverage");
				warnings++;
			}
			continue;
		}
		if (func->rap_kind == 3) {
			struct symbol *prepare = find_symbol_by_name(file->elf, "hdn_rap_failure_prepare");
			struct symbol *report = find_symbol_by_name(file->elf, "hdn_rap_failure_report");

			if (!func->rap_terminal || !prepare || prepare->rap_kind != 2 ||
			    !report || report->rap_kind != 1) {
				WARN_FUNC(func->sec, func->offset, "RAP terminal domain lacks protected setup/report coverage");
				warnings++;
			}
			continue;
		}
		if (func->rap_kind == 4) {
			unsigned int call_kind = rap_hook_name(func->name) ? 1 : 2;

			/* Exact bytes alone do not establish that the runtime callees
			 * and assembly continuations belong to this same closed bundle. */
			if (!func->rap_adapter) {
				WARN_FUNC(func->sec, func->offset, "unverified RAP adapter");
				warnings++;
			}
			rap_for_each_insn(file, func, insn) {
				struct symbol *callee = insn_call_dest(insn);

				if ((insn->type == INSN_CALL && (!callee || callee->rap_kind != call_kind)) ||
				    (is_static_jump(insn) && is_sibling_call(insn) && (!callee ||
				     (!callee->rap_terminal && !callee->rap_adapter)))) {
					WARN_INSN(insn, "RAP adapter leaves its closed runtime boundary");
					warnings++;
				}
			}
			continue;
		}
		if (first && first->type == INSN_ENDBR)
			first = next_insn_same_sec(file, first);
		if (func->rap_kind == 5 && !strcmp(func->name, "ftrace_regs_caller")) {
			struct symbol *handoff = find_symbol_by_name(file->elf, "hdn_rap_bpf_trace_handoff");

			/* verify_rap_ftrace_handoff checked the exact leading PUSHF. */
			first = next_insn_same_sec(file, first);
			if (!handoff || handoff->rap_kind != 2) {
				WARN_FUNC(func->sec, func->offset, "RAP tracing handoff lacks its closed root");
				warnings++;
			}
		}
		rap_for_each_insn(file, func, insn) {
			struct symbol *callee = insn_call_dest(insn);

			if (insn->type == INSN_CALL && callee && callee->rap_kind == 7) {
				WARN_INSN(insn, "runtime RAP call enters the physical bootstrap domain");
				warnings++;
			}
			if (callee && ((callee->rap_kind >= 33 && callee->rap_kind <= 54) ||
				       callee->rap_kind == 28 || callee->rap_kind == 29 ||
				       callee->rap_kind == 31 || callee->rap_kind == 32 ||
				       callee->rap_kind == 11 || callee->rap_kind == 12 ||
				       callee->rap_kind == 15 || callee->rap_kind == 16 ||
				       (callee->rap_kind >= 22 && callee->rap_kind <= 25))) {
				WARN_INSN(insn, "ordinary RAP code enters a terminal handoff domain");
				warnings++;
			}
			if (insn->rap_entry) {
				entries++;
				if (!protected || prev_insn_same_sec(file, insn) != first) {
					WARN_INSN(insn, "RAP entry is not the first body operation");
					warnings++;
				}
			}
			if (insn->type == INSN_CALL && !insn->rap_entry && !insn->rap_site && !insn->rap_leaf_call) {
				WARN_INSN(insn, "call has no RAP return-site binding");
				warnings++;
			}
			if (insn->type == INSN_CALL && callee && callee->static_call_tramp &&
			    !insn->rap_static_site) {
				WARN_INSN(insn, "static call lacks immutable RAP patch-site identity");
				warnings++;
			}
			if (insn->type == INSN_CALL_DYNAMIC || (is_dynamic_jump(insn) && !insn->rap_jump)) {
				WARN_INSN(insn, "unprotected indirect RAP transfer");
				warnings++;
			}
			if (func->rap_kind == 2 && insn->type == INSN_CALL && !insn->rap_leaf_call &&
			    (!callee || (callee->rap_kind != 2 && !callee->rap_terminal))) {
				WARN_INSN(insn, "RAP runtime calls outside its closed recursion boundary");
				warnings++;
			}
			if (insn->type == INSN_RETURN) {
				returns += insn->rap_return;
				if (protected && !insn->rap_return) {
					WARN_INSN(insn, "return bypasses the RAP authenticator");
					warnings++;
				}
			}
			if (is_sibling_call(insn) && !insn->rap_handoff) {
				WARN_INSN(insn, "RAP sibling transfer lacks an explicit ABI adapter");
				warnings++;
			}
		}
		if (entries != protected || returns != func->rap_returns) {
			WARN_FUNC(func->sec, func->offset, "RAP entry/return counts disagree with compiler coverage");
			warnings++;
		}
	}
	/* Standalone assembly and padding cannot hide unowned transfer code. */
	for_each_insn(file, insn) {
		if (rap_insn_owner(insn) || insn->hole || insn->rap_thunk_safe || insn->rap_hw_safe)
			continue;
		if (insn->type == INSN_CALL || insn->type == INSN_CALL_DYNAMIC ||
		    insn->type == INSN_RETURN || is_jump(insn)) {
			WARN_INSN(insn, "assembly transfer lacks RAP function ownership");
			warnings++;
		}
	}
	return warnings;
}

static int decode_sections(struct objtool_file *file)
{
	file->klp = is_livepatch_module(file);

	mark_rodata(file);

	if (init_pv_ops(file))
		return -1;

	/*
	 * Must be before add_{jump_call}_destination.
	 */
	if (classify_symbols(file))
		return -1;

	if (decode_instructions(file))
		return -1;

	if (add_ignores(file))
		return -1;

	add_uaccess_safe(file);

	if (read_annotate(file, __annotate_early))
		return -1;

	/*
	 * Must be before add_jump_destinations(), which depends on 'func'
	 * being set for alternatives, to enable proper sibling call detection.
	 */
	if (validate_branch_enabled() || opts.noinstr || opts.hack_jump_label || opts.disas) {
		if (add_special_section_alts(file))
			return -1;
	}

	if (add_jump_destinations(file))
		return -1;

	/*
	 * Must be before add_call_destination(); it changes INSN_CALL to
	 * INSN_JUMP.
	 */
	if (read_annotate(file, __annotate_ifc))
		return -1;

	if (add_call_destinations(file))
		return -1;

	if (add_jump_table_alts(file))
		return -1;
	if (read_rap_jumps(file))
		return -1;
	if (read_rap_sites(file))
		return -1;
	if (read_rap_entries(file))
		return -1;
	if (read_rap_functions(file))
		return -1;
	if (read_rap_function_entries(file))
		return -1;
	if (read_rap_static_calls(file))
		return -1;

	if (read_unwind_hints(file))
		return -1;

	/* Must be after add_jump_destinations() */
	mark_holes(file);

	/*
	 * Must be after add_call_destinations() such that it can override
	 * dead_end_function() marks.
	 */
	if (read_annotate(file, __annotate_late))
		return -1;

	return 0;
}

static bool is_special_call(struct instruction *insn)
{
	if (insn->type == INSN_CALL) {
		struct symbol *dest = insn_call_dest(insn);

		if (!dest)
			return false;

		if (dest->fentry || dest->embedded_insn ||
		    !strcmp(dest->name, "__hdn_rap_enter") ||
		    !strcmp(dest->name, "__hdn_rap_enter_flags"))
			return true;
	}

	return false;
}

static bool has_modified_stack_frame(struct instruction *insn, struct insn_state *state)
{
	struct cfi_state *cfi = &state->cfi;
	int i;

	if (cfi->cfa.base != initial_func_cfi.cfa.base || cfi->drap)
		return true;

	if (cfi->cfa.offset != initial_func_cfi.cfa.offset)
		return true;

	if (cfi->stack_size != initial_func_cfi.cfa.offset)
		return true;

	for (i = 0; i < CFI_NUM_REGS; i++) {
		if (cfi->regs[i].base != initial_func_cfi.regs[i].base ||
		    cfi->regs[i].offset != initial_func_cfi.regs[i].offset)
			return true;
	}

	return false;
}

static bool check_reg_frame_pos(const struct cfi_reg *reg,
				int expected_offset)
{
	return reg->base == CFI_CFA &&
	       reg->offset == expected_offset;
}

static bool has_valid_stack_frame(struct insn_state *state)
{
	struct cfi_state *cfi = &state->cfi;

	if (cfi->cfa.base == CFI_BP &&
	    check_reg_frame_pos(&cfi->regs[CFI_BP], -cfi->cfa.offset) &&
	    check_reg_frame_pos(&cfi->regs[CFI_RA], -cfi->cfa.offset + 8))
		return true;

	if (cfi->drap && cfi->regs[CFI_BP].base == CFI_BP)
		return true;

	return false;
}

static int update_cfi_state_regs(struct instruction *insn,
				  struct cfi_state *cfi,
				  struct stack_op *op)
{
	struct cfi_reg *cfa = &cfi->cfa;

	if (cfa->base != CFI_SP && cfa->base != CFI_SP_INDIRECT)
		return 0;

	/* push */
	if (op->dest.type == OP_DEST_PUSH || op->dest.type == OP_DEST_PUSHF)
		cfa->offset += 8;

	/* pop */
	if (op->src.type == OP_SRC_POP || op->src.type == OP_SRC_POPF)
		cfa->offset -= 8;

	/* add immediate to sp */
	if (op->dest.type == OP_DEST_REG && op->src.type == OP_SRC_ADD &&
	    op->dest.reg == CFI_SP && op->src.reg == CFI_SP)
		cfa->offset -= op->src.offset;

	return 0;
}

static void save_reg(struct cfi_state *cfi, unsigned char reg, int base, int offset)
{
	if (arch_callee_saved_reg(reg) &&
	    cfi->regs[reg].base == CFI_UNDEFINED) {
		cfi->regs[reg].base = base;
		cfi->regs[reg].offset = offset;
	}
}

static void restore_reg(struct cfi_state *cfi, unsigned char reg)
{
	cfi->regs[reg].base = initial_func_cfi.regs[reg].base;
	cfi->regs[reg].offset = initial_func_cfi.regs[reg].offset;
}

/*
 * A note about DRAP stack alignment:
 *
 * GCC has the concept of a DRAP register, which is used to help keep track of
 * the stack pointer when aligning the stack.  r10 or r13 is used as the DRAP
 * register.  The typical DRAP pattern is:
 *
 *   4c 8d 54 24 08		lea    0x8(%rsp),%r10
 *   48 83 e4 c0		and    $0xffffffffffffffc0,%rsp
 *   41 ff 72 f8		pushq  -0x8(%r10)
 *   55				push   %rbp
 *   48 89 e5			mov    %rsp,%rbp
 *				(more pushes)
 *   41 52			push   %r10
 *				...
 *   41 5a			pop    %r10
 *				(more pops)
 *   5d				pop    %rbp
 *   49 8d 62 f8		lea    -0x8(%r10),%rsp
 *   c3				retq
 *
 * There are some variations in the epilogues, like:
 *
 *   5b				pop    %rbx
 *   41 5a			pop    %r10
 *   41 5c			pop    %r12
 *   41 5d			pop    %r13
 *   41 5e			pop    %r14
 *   c9				leaveq
 *   49 8d 62 f8		lea    -0x8(%r10),%rsp
 *   c3				retq
 *
 * and:
 *
 *   4c 8b 55 e8		mov    -0x18(%rbp),%r10
 *   48 8b 5d e0		mov    -0x20(%rbp),%rbx
 *   4c 8b 65 f0		mov    -0x10(%rbp),%r12
 *   4c 8b 6d f8		mov    -0x8(%rbp),%r13
 *   c9				leaveq
 *   49 8d 62 f8		lea    -0x8(%r10),%rsp
 *   c3				retq
 *
 * Sometimes r13 is used as the DRAP register, in which case it's saved and
 * restored beforehand:
 *
 *   41 55			push   %r13
 *   4c 8d 6c 24 10		lea    0x10(%rsp),%r13
 *   48 83 e4 f0		and    $0xfffffffffffffff0,%rsp
 *				...
 *   49 8d 65 f0		lea    -0x10(%r13),%rsp
 *   41 5d			pop    %r13
 *   c3				retq
 */
static int update_cfi_state(struct instruction *insn,
			    struct instruction *next_insn,
			    struct cfi_state *cfi, struct stack_op *op)
{
	struct cfi_reg *cfa = &cfi->cfa;
	struct cfi_reg *regs = cfi->regs;

	/* ignore UNWIND_HINT_UNDEFINED regions */
	if (cfi->force_undefined)
		return 0;
	/* The terminal protocol installs a fresh stack with no caller chain.
	 * Its exact body has already been checked, including every operation
	 * after the stack switch. Keep END_OF_STACK for the reporter's caller. */
	if (cfi->type == UNWIND_HINT_TYPE_END_OF_STACK && insn_func(insn) &&
	    insn_func(insn)->rap_terminal)
		return 0;

	/* stack operations don't make sense with an undefined CFA */
	if (cfa->base == CFI_UNDEFINED) {
		if (insn_func(insn)) {
			WARN_INSN(insn, "undefined stack state");
			return 1;
		}
		return 0;
	}

	if (cfi->type == UNWIND_HINT_TYPE_REGS ||
	    cfi->type == UNWIND_HINT_TYPE_REGS_PARTIAL)
		return update_cfi_state_regs(insn, cfi, op);

	switch (op->dest.type) {

	case OP_DEST_REG:
		switch (op->src.type) {

		case OP_SRC_REG:
			if (op->src.reg == CFI_SP && op->dest.reg == CFI_BP &&
			    cfa->base == CFI_SP &&
			    check_reg_frame_pos(&regs[CFI_BP], -cfa->offset)) {

				/* mov %rsp, %rbp */
				cfa->base = op->dest.reg;
				cfi->bp_scratch = false;
			}

			else if (op->src.reg == CFI_SP &&
				 op->dest.reg == CFI_BP && cfi->drap) {

				/* drap: mov %rsp, %rbp */
				regs[CFI_BP].base = CFI_BP;
				regs[CFI_BP].offset = -cfi->stack_size;
				cfi->bp_scratch = false;
			}

			else if (op->src.reg == CFI_SP && cfa->base == CFI_SP) {

				/*
				 * mov %rsp, %reg
				 *
				 * This is needed for the rare case where GCC
				 * does:
				 *
				 *   mov    %rsp, %rax
				 *   ...
				 *   mov    %rax, %rsp
				 */
				cfi->vals[op->dest.reg].base = CFI_CFA;
				cfi->vals[op->dest.reg].offset = -cfi->stack_size;
			}

			else if (op->src.reg == CFI_BP && op->dest.reg == CFI_SP &&
				 (cfa->base == CFI_BP || cfa->base == cfi->drap_reg)) {

				/*
				 * mov %rbp, %rsp
				 *
				 * Restore the original stack pointer (Clang).
				 */
				cfi->stack_size = -cfi->regs[CFI_BP].offset;
			}

			else if (op->dest.reg == cfa->base) {

				/* mov %reg, %rsp */
				if (cfa->base == CFI_SP &&
				    cfi->vals[op->src.reg].base == CFI_CFA) {

					/*
					 * This is needed for the rare case
					 * where GCC does something dumb like:
					 *
					 *   lea    0x8(%rsp), %rcx
					 *   ...
					 *   mov    %rcx, %rsp
					 */
					cfa->offset = -cfi->vals[op->src.reg].offset;
					cfi->stack_size = cfa->offset;

				} else if (cfa->base == CFI_SP &&
					   cfi->vals[op->src.reg].base == CFI_SP_INDIRECT &&
					   cfi->vals[op->src.reg].offset == cfa->offset) {

					/*
					 * Stack swizzle:
					 *
					 * 1: mov %rsp, (%[tos])
					 * 2: mov %[tos], %rsp
					 *    ...
					 * 3: pop %rsp
					 *
					 * Where:
					 *
					 * 1 - places a pointer to the previous
					 *     stack at the Top-of-Stack of the
					 *     new stack.
					 *
					 * 2 - switches to the new stack.
					 *
					 * 3 - pops the Top-of-Stack to restore
					 *     the original stack.
					 *
					 * Note: we set base to SP_INDIRECT
					 * here and preserve offset. Therefore
					 * when the unwinder reaches ToS it
					 * will dereference SP and then add the
					 * offset to find the next frame, IOW:
					 * (%rsp) + offset.
					 */
					cfa->base = CFI_SP_INDIRECT;

				} else {
					cfa->base = CFI_UNDEFINED;
					cfa->offset = 0;
				}
			}

			else if (op->dest.reg == CFI_SP &&
				 cfi->vals[op->src.reg].base == CFI_SP_INDIRECT &&
				 cfi->vals[op->src.reg].offset == cfa->offset) {

				/*
				 * The same stack swizzle case 2) as above. But
				 * because we can't change cfa->base, case 3)
				 * will become a regular POP. Pretend we're a
				 * PUSH so things don't go unbalanced.
				 */
				cfi->stack_size += 8;
			}

			else if (cfi->vals[op->src.reg].base == CFI_CFA) {
				/*
				 * Clang RSP musical chairs:
				 *
				 *   mov %rsp, %rdx [handled above]
				 *   ...
				 *   mov %rdx, %rbx [handled here]
				 *   ...
				 *   mov %rbx, %rsp [handled above]
				 */
				cfi->vals[op->dest.reg].base = CFI_CFA;
				cfi->vals[op->dest.reg].offset = cfi->vals[op->src.reg].offset;
			}


			break;

		case OP_SRC_ADD:
			if (op->dest.reg == CFI_SP && op->src.reg == CFI_SP) {

				/* add imm, %rsp */
				cfi->stack_size -= op->src.offset;
				if (cfa->base == CFI_SP)
					cfa->offset -= op->src.offset;
				break;
			}

			if (op->dest.reg == CFI_BP && op->src.reg == CFI_SP &&
			    insn->sym->frame_pointer) {
				/* addi.d fp,sp,imm on LoongArch */
				if (cfa->base == CFI_SP && cfa->offset == op->src.offset) {
					cfa->base = CFI_BP;
					cfa->offset = 0;
				}
				break;
			}

			if (op->dest.reg == CFI_SP && op->src.reg == CFI_BP) {
				/* addi.d sp,fp,imm on LoongArch */
				if (cfa->base == CFI_BP && cfa->offset == 0) {
					if (insn->sym->frame_pointer) {
						cfa->base = CFI_SP;
						cfa->offset = -op->src.offset;
					}
				} else {
					/* lea disp(%rbp), %rsp */
					cfi->stack_size = -(op->src.offset + regs[CFI_BP].offset);
				}
				break;
			}

			if (op->src.reg == CFI_SP && cfa->base == CFI_SP) {

				/* drap: lea disp(%rsp), %drap */
				cfi->drap_reg = op->dest.reg;

				/*
				 * lea disp(%rsp), %reg
				 *
				 * This is needed for the rare case where GCC
				 * does something dumb like:
				 *
				 *   lea    0x8(%rsp), %rcx
				 *   ...
				 *   mov    %rcx, %rsp
				 */
				cfi->vals[op->dest.reg].base = CFI_CFA;
				cfi->vals[op->dest.reg].offset = \
					-cfi->stack_size + op->src.offset;

				break;
			}

			if (cfi->drap && op->dest.reg == CFI_SP &&
			    op->src.reg == cfi->drap_reg) {

				 /* drap: lea disp(%drap), %rsp */
				cfa->base = CFI_SP;
				cfa->offset = cfi->stack_size = -op->src.offset;
				cfi->drap_reg = CFI_UNDEFINED;
				cfi->drap = false;
				break;
			}

			if (op->dest.reg == cfi->cfa.base && !(next_insn && next_insn->hint)) {
				WARN_INSN(insn, "unsupported stack register modification");
				return -1;
			}

			break;

		case OP_SRC_AND:
			if (op->dest.reg != CFI_SP ||
			    (cfi->drap_reg != CFI_UNDEFINED && cfa->base != CFI_SP) ||
			    (cfi->drap_reg == CFI_UNDEFINED && cfa->base != CFI_BP)) {
				WARN_INSN(insn, "unsupported stack pointer realignment");
				return -1;
			}

			if (cfi->drap_reg != CFI_UNDEFINED) {
				/* drap: and imm, %rsp */
				cfa->base = cfi->drap_reg;
				cfa->offset = cfi->stack_size = 0;
				cfi->drap = true;
			}

			/*
			 * Older versions of GCC (4.8ish) realign the stack
			 * without DRAP, with a frame pointer.
			 */

			break;

		case OP_SRC_POP:
		case OP_SRC_POPF:
			if (op->dest.reg == CFI_SP && cfa->base == CFI_SP_INDIRECT) {

				/* pop %rsp; # restore from a stack swizzle */
				cfa->base = CFI_SP;
				break;
			}

			if (!cfi->drap && op->dest.reg == cfa->base) {

				/* pop %rbp */
				cfa->base = CFI_SP;
			}

			if (cfi->drap && cfa->base == CFI_BP_INDIRECT &&
			    op->dest.reg == cfi->drap_reg &&
			    cfi->drap_offset == -cfi->stack_size) {

				/* drap: pop %drap */
				cfa->base = cfi->drap_reg;
				cfa->offset = 0;
				cfi->drap_offset = -1;

			} else if (cfi->stack_size == -regs[op->dest.reg].offset) {

				/* pop %reg */
				restore_reg(cfi, op->dest.reg);
			}

			cfi->stack_size -= 8;
			if (cfa->base == CFI_SP)
				cfa->offset -= 8;

			break;

		case OP_SRC_REG_INDIRECT:
			if (!cfi->drap && op->dest.reg == cfa->base &&
			    op->dest.reg == CFI_BP) {

				/* mov disp(%rsp), %rbp */
				cfa->base = CFI_SP;
				cfa->offset = cfi->stack_size;
			}

			if (cfi->drap && op->src.reg == CFI_BP &&
			    op->src.offset == cfi->drap_offset) {

				/* drap: mov disp(%rbp), %drap */
				cfa->base = cfi->drap_reg;
				cfa->offset = 0;
				cfi->drap_offset = -1;
			}

			if (cfi->drap && op->src.reg == CFI_BP &&
			    op->src.offset == regs[op->dest.reg].offset) {

				/* drap: mov disp(%rbp), %reg */
				restore_reg(cfi, op->dest.reg);

			} else if (op->src.reg == cfa->base &&
			    op->src.offset == regs[op->dest.reg].offset + cfa->offset) {

				/* mov disp(%rbp), %reg */
				/* mov disp(%rsp), %reg */
				restore_reg(cfi, op->dest.reg);

			} else if (op->src.reg == CFI_SP &&
				   op->src.offset == regs[op->dest.reg].offset + cfi->stack_size) {

				/* mov disp(%rsp), %reg */
				restore_reg(cfi, op->dest.reg);
			}

			break;

		default:
			WARN_INSN(insn, "unknown stack-related instruction");
			return -1;
		}

		break;

	case OP_DEST_PUSH:
	case OP_DEST_PUSHF:
		cfi->stack_size += 8;
		if (cfa->base == CFI_SP)
			cfa->offset += 8;

		if (op->src.type != OP_SRC_REG)
			break;

		if (cfi->drap) {
			if (op->src.reg == cfa->base && op->src.reg == cfi->drap_reg) {

				/* drap: push %drap */
				cfa->base = CFI_BP_INDIRECT;
				cfa->offset = -cfi->stack_size;

				/* save drap so we know when to restore it */
				cfi->drap_offset = -cfi->stack_size;

			} else if (op->src.reg == CFI_BP && cfa->base == cfi->drap_reg) {

				/* drap: push %rbp */
				cfi->stack_size = 0;

			} else {

				/* drap: push %reg */
				save_reg(cfi, op->src.reg, CFI_BP, -cfi->stack_size);
			}

		} else {

			/* push %reg */
			save_reg(cfi, op->src.reg, CFI_CFA, -cfi->stack_size);
		}

		/* detect when asm code uses rbp as a scratch register */
		if (opts.stackval && insn_func(insn) && op->src.reg == CFI_BP &&
		    cfa->base != CFI_BP)
			cfi->bp_scratch = true;
		break;

	case OP_DEST_REG_INDIRECT:

		if (cfi->drap) {
			if (op->src.reg == cfa->base && op->src.reg == cfi->drap_reg) {

				/* drap: mov %drap, disp(%rbp) */
				cfa->base = CFI_BP_INDIRECT;
				cfa->offset = op->dest.offset;

				/* save drap offset so we know when to restore it */
				cfi->drap_offset = op->dest.offset;
			} else {

				/* drap: mov reg, disp(%rbp) */
				save_reg(cfi, op->src.reg, CFI_BP, op->dest.offset);
			}

		} else if (op->dest.reg == cfa->base) {

			/* mov reg, disp(%rbp) */
			/* mov reg, disp(%rsp) */
			save_reg(cfi, op->src.reg, CFI_CFA,
				 op->dest.offset - cfi->cfa.offset);

		} else if (op->dest.reg == CFI_SP) {

			/* mov reg, disp(%rsp) */
			save_reg(cfi, op->src.reg, CFI_CFA,
				 op->dest.offset - cfi->stack_size);

		} else if (op->src.reg == CFI_SP && op->dest.offset == 0) {

			/* mov %rsp, (%reg); # setup a stack swizzle. */
			cfi->vals[op->dest.reg].base = CFI_SP_INDIRECT;
			cfi->vals[op->dest.reg].offset = cfa->offset;
		}

		break;

	case OP_DEST_MEM:
		if (op->src.type != OP_SRC_POP && op->src.type != OP_SRC_POPF) {
			WARN_INSN(insn, "unknown stack-related memory operation");
			return -1;
		}

		/* pop mem */
		cfi->stack_size -= 8;
		if (cfa->base == CFI_SP)
			cfa->offset -= 8;

		break;

	default:
		WARN_INSN(insn, "unknown stack-related instruction");
		return -1;
	}

	return 0;
}

/*
 * The stack layouts of alternatives instructions can sometimes diverge when
 * they have stack modifications.  That's fine as long as the potential stack
 * layouts don't conflict at any given potential instruction boundary.
 *
 * Flatten the CFIs of the different alternative code streams (both original
 * and replacement) into a single shared CFI array which can be used to detect
 * conflicts and nicely feed a linear array of ORC entries to the unwinder.
 */
static int propagate_alt_cfi(struct objtool_file *file, struct instruction *insn)
{
	struct cfi_state **alt_cfi;
	int group_off;

	if (!insn->alt_group)
		return 0;

	if (!insn->cfi) {
		WARN("CFI missing");
		return -1;
	}

	alt_cfi = insn->alt_group->cfi;
	group_off = insn->offset - insn->alt_group->first_insn->offset;

	if (!alt_cfi[group_off]) {
		alt_cfi[group_off] = insn->cfi;
	} else {
		if (cficmp(alt_cfi[group_off], insn->cfi)) {
			struct alt_group *orig_group = insn->alt_group->orig_group ?: insn->alt_group;
			struct instruction *orig = orig_group->first_insn;
			WARN_INSN(orig, "stack layout conflict in alternatives: %s",
				  offstr(insn->sec, insn->offset));
			return -1;
		}
	}

	return 0;
}

static int noinline handle_insn_ops(struct instruction *insn,
				    struct instruction *next_insn,
				    struct insn_state *state)
{
	struct insn_state prev_state __maybe_unused = *state;
	struct stack_op *op;
	int ret = 0;

	for (op = insn->stack_ops; op; op = op->next) {

		ret = update_cfi_state(insn, next_insn, &state->cfi, op);
		if (ret)
			goto done;

		if (!opts.uaccess || !insn->alt_group)
			continue;

		if (op->dest.type == OP_DEST_PUSHF) {
			if (!state->uaccess_stack) {
				state->uaccess_stack = 1;
			} else if (state->uaccess_stack >> 31) {
				WARN_INSN(insn, "PUSHF stack exhausted");
				ret = 1;
				goto done;
			}
			state->uaccess_stack <<= 1;
			state->uaccess_stack  |= state->uaccess;
		}

		if (op->src.type == OP_SRC_POPF) {
			if (state->uaccess_stack) {
				state->uaccess = state->uaccess_stack & 1;
				state->uaccess_stack >>= 1;
				if (state->uaccess_stack == 1)
					state->uaccess_stack = 0;
			}
		}
	}

done:
	TRACE_INSN_STATE(insn, &prev_state, state);

	return ret;
}

static bool insn_cfi_match(struct instruction *insn, struct cfi_state *cfi2)
{
	struct cfi_state *cfi1 = insn->cfi;
	int i;

	if (!cfi1) {
		WARN("CFI missing");
		return false;
	}

	if (memcmp(&cfi1->cfa, &cfi2->cfa, sizeof(cfi1->cfa))) {

		WARN_INSN(insn, "stack state mismatch: cfa1=%d%+d cfa2=%d%+d",
			  cfi1->cfa.base, cfi1->cfa.offset,
			  cfi2->cfa.base, cfi2->cfa.offset);
		return false;

	}

	if (memcmp(&cfi1->regs, &cfi2->regs, sizeof(cfi1->regs))) {
		for (i = 0; i < CFI_NUM_REGS; i++) {

			if (!memcmp(&cfi1->regs[i], &cfi2->regs[i], sizeof(struct cfi_reg)))
				continue;

			WARN_INSN(insn, "stack state mismatch: reg1[%d]=%d%+d reg2[%d]=%d%+d",
				  i, cfi1->regs[i].base, cfi1->regs[i].offset,
				  i, cfi2->regs[i].base, cfi2->regs[i].offset);
		}
		return false;
	}

	if (cfi1->type != cfi2->type) {

		WARN_INSN(insn, "stack state mismatch: type1=%d type2=%d",
			  cfi1->type, cfi2->type);
		return false;
	}

	if (cfi1->drap != cfi2->drap ||
		   (cfi1->drap && cfi1->drap_reg != cfi2->drap_reg) ||
		   (cfi1->drap && cfi1->drap_offset != cfi2->drap_offset)) {

		WARN_INSN(insn, "stack state mismatch: drap1=%d(%d,%d) drap2=%d(%d,%d)",
			  cfi1->drap, cfi1->drap_reg, cfi1->drap_offset,
			  cfi2->drap, cfi2->drap_reg, cfi2->drap_offset);
		return false;
	}

	return true;
}

static inline bool func_uaccess_safe(struct symbol *func)
{
	if (func)
		return func->uaccess_safe || func->rap_terminal;

	return false;
}

static inline const char *call_dest_name(struct instruction *insn)
{
	static char pvname[19];
	struct reloc *reloc;
	int idx;

	if (insn_call_dest(insn))
		return insn_call_dest(insn)->name;

	reloc = insn_reloc(NULL, insn);
	if (reloc && !strcmp(reloc->sym->name, "pv_ops")) {
		idx = (reloc_addend(reloc) / sizeof(void *));
		snprintf(pvname, sizeof(pvname), "pv_ops[%d]", idx);
		return pvname;
	}

	return "{dynamic}";
}

static bool pv_call_dest(struct objtool_file *file, struct instruction *insn)
{
	struct symbol *target;
	struct reloc *reloc;
	int idx;

	reloc = insn_reloc(file, insn);
	if (!reloc || strcmp(reloc->sym->name, "pv_ops"))
		return false;

	idx = arch_insn_adjusted_addend(insn, reloc) / sizeof(void *);

	if (file->pv_ops[idx].clean)
		return true;

	file->pv_ops[idx].clean = true;

	list_for_each_entry(target, &file->pv_ops[idx].targets, pv_target) {
		if (!target->sec->noinstr) {
			WARN("pv_ops[%d]: %s", idx, target->name);
			file->pv_ops[idx].clean = false;
		}
	}

	return file->pv_ops[idx].clean;
}

static inline bool noinstr_call_dest(struct objtool_file *file,
				     struct instruction *insn,
				     struct symbol *func)
{
	/*
	 * We can't deal with indirect function calls at present;
	 * assume they're instrumented.
	 */
	if (!func) {
		if (file->pv_ops)
			return pv_call_dest(file, insn);

		return false;
	}

	/*
	 * If the symbol is from a noinstr section; we good.
	 */
	if (func->sec->noinstr)
		return true;

	/*
	 * If the symbol is a static_call trampoline, we can't tell.
	 */
	if (func->static_call_tramp)
		return true;

	/*
	 * The __ubsan_handle_*() calls are like WARN(), they only happen when
	 * something 'BAD' happened. At the risk of taking the machine down,
	 * let them proceed to get the message out.
	 */
	if (!strncmp(func->name, "__ubsan_handle_", 15))
		return true;

	return false;
}

static int validate_call(struct objtool_file *file,
			 struct instruction *insn,
			 struct insn_state *state)
{
	if (state->noinstr && state->instr <= 0 &&
	    !noinstr_call_dest(file, insn, insn_call_dest(insn))) {
		WARN_INSN(insn, "call to %s() leaves .noinstr.text section", call_dest_name(insn));
		return 1;
	}

	if (state->uaccess && !func_uaccess_safe(insn_call_dest(insn))) {
		WARN_INSN(insn, "call to %s() with UACCESS enabled", call_dest_name(insn));
		return 1;
	}

	if (state->df) {
		WARN_INSN(insn, "call to %s() with DF set", call_dest_name(insn));
		return 1;
	}

	return 0;
}

static int validate_sibling_call(struct objtool_file *file,
				 struct instruction *insn,
				 struct insn_state *state)
{
	struct symbol *func = insn_func(insn), *dest = insn_call_dest(insn);
	/* This exact adapter has already consumed its return slot. The fixed
	 * capture restores a single authenticated slot before its architecture
	 * RET. Ordinary sibling calls must retain the usual stack geometry. */
	bool rap_transfer = func && (func->rap_adapter || insn->rap_handoff) && dest && dest->rap_adapter &&
			    (!strcmp(dest->name, "__hdn_rap_transfer") ||
			     (rap_hook_name(func->name) &&
			      (!strcmp(dest->name, "__hdn_rap_graph_return") ||
			       !strcmp(dest->name, "__hdn_rap_rethook_return"))));

	/* The byte-verified terminal protocol abandons its caller's stack and
	 * can only branch to its verified non-returning halt loop. */
	if (func && !func->rap_terminal && !rap_transfer &&
	    has_modified_stack_frame(insn, state)) {
		WARN_INSN(insn, "sibling call from callable instruction with modified stack frame");
		return 1;
	}

	return validate_call(file, insn, state);
}

static int validate_return(struct symbol *func, struct instruction *insn, struct insn_state *state)
{
	if (state->noinstr && state->instr > 0) {
		WARN_INSN(insn, "return with instrumentation enabled");
		return 1;
	}

	if (state->uaccess && !func_uaccess_safe(func)) {
		WARN_INSN(insn, "return with UACCESS enabled");
		return 1;
	}

	if (!state->uaccess && func_uaccess_safe(func)) {
		WARN_INSN(insn, "return with UACCESS disabled from a UACCESS-safe function");
		return 1;
	}

	if (state->df) {
		WARN_INSN(insn, "return with DF set");
		return 1;
	}

	if (func && has_modified_stack_frame(insn, state)) {
		WARN_INSN(insn, "return with modified stack frame");
		return 1;
	}

	if (state->cfi.bp_scratch) {
		WARN_INSN(insn, "BP used as a scratch register");
		return 1;
	}

	return 0;
}

static struct instruction *next_insn_to_validate(struct objtool_file *file,
						 struct instruction *insn)
{
	struct alt_group *alt_group = insn->alt_group;

	/*
	 * Simulate the fact that alternatives are patched in-place.  When the
	 * end of a replacement alt_group is reached, redirect objtool flow to
	 * the end of the original alt_group.
	 *
	 * insn->alts->insn -> alt_group->first_insn
	 *		       ...
	 *		       alt_group->last_insn
	 *		       [alt_group->nop]      -> next(orig_group->last_insn)
	 */
	if (alt_group) {
		if (alt_group->nop) {
			/* ->nop implies ->orig_group */
			if (insn == alt_group->last_insn)
				return alt_group->nop;
			if (insn == alt_group->nop)
				goto next_orig;
		}
		if (insn == alt_group->last_insn && alt_group->orig_group)
			goto next_orig;
	}

	return next_insn_same_sec(file, insn);

next_orig:
	return next_insn_same_sec(file, alt_group->orig_group->last_insn);
}

static bool skip_alt_group(struct instruction *insn)
{
	struct instruction *alt_insn = insn->alts ? insn->alts->insn : NULL;

	if (!insn->alt_group)
		return false;

	/* ANNOTATE_IGNORE_ALTERNATIVE */
	if (insn->alt_group->ignore) {
		TRACE_ALT(insn, "alt group ignored");
		return true;
	}

	/*
	 * For NOP patched with CLAC/STAC, only follow the latter to avoid
	 * impossible code paths combining patched CLAC with unpatched STAC
	 * or vice versa.
	 *
	 * ANNOTATE_IGNORE_ALTERNATIVE could have been used here, but Linus
	 * requested not to do that to avoid hurting .s file readability
	 * around CLAC/STAC alternative sites.
	 */

	if (!alt_insn)
		return false;

	/* Don't override ASM_{CLAC,STAC}_UNSAFE */
	if (alt_insn->alt_group && alt_insn->alt_group->ignore)
		return false;

	return alt_insn->type == INSN_CLAC || alt_insn->type == INSN_STAC;
}

static int checksum_debug_init(struct objtool_file *file)
{
	char *dup, *s;

	if (!opts.debug_checksum)
		return 0;

	dup = strdup(opts.debug_checksum);
	if (!dup) {
		ERROR_GLIBC("strdup");
		return -1;
	}

	s = dup;
	while (*s) {
		struct symbol *func;
		char *comma;

		comma = strchr(s, ',');
		if (comma)
			*comma = '\0';

		func = find_symbol_by_name(file->elf, s);
		if (!func || !is_func_sym(func))
			WARN("--debug-checksum: can't find '%s'", s);
		else
			func->debug_checksum = 1;

		if (!comma)
			break;

		s = comma + 1;
	}

	free(dup);
	return 0;
}

static void checksum_update_insn(struct objtool_file *file, struct symbol *func,
				 struct instruction *insn)
{
	struct reloc *reloc = insn_reloc(file, insn);
	unsigned long offset;
	struct symbol *sym;

	if (insn->fake)
		return;

	checksum_update(func, insn, insn->sec->data->d_buf + insn->offset, insn->len);

	if (!reloc) {
		struct symbol *call_dest = insn_call_dest(insn);

		if (call_dest)
			checksum_update(func, insn, call_dest->demangled_name,
					strlen(call_dest->demangled_name));
		return;
	}

	sym = reloc->sym;
	offset = arch_insn_adjusted_addend(insn, reloc);

	if (is_string_sec(sym->sec)) {
		char *str;

		str = sym->sec->data->d_buf + sym->offset + offset;
		checksum_update(func, insn, str, strlen(str));
		return;
	}

	if (is_sec_sym(sym)) {
		sym = find_symbol_containing(reloc->sym->sec, offset);
		if (!sym)
			return;

		offset -= sym->offset;
	}

	checksum_update(func, insn, sym->demangled_name, strlen(sym->demangled_name));
	checksum_update(func, insn, &offset, sizeof(offset));
}

static int validate_branch(struct objtool_file *file, struct symbol *func,
			   struct instruction *insn, struct insn_state state);
static int do_validate_branch(struct objtool_file *file, struct symbol *func,
			      struct instruction *insn, struct insn_state *state);

static int validate_insn(struct objtool_file *file, struct symbol *func,
			 struct instruction *insn, struct insn_state *statep,
			 struct instruction *prev_insn, struct instruction *next_insn,
			 bool *dead_end)
{
	char *alt_name __maybe_unused = NULL;
	struct alternative *alt;
	u8 visited;
	int ret;

	/*
	 * Any returns before the end of this function are effectively dead
	 * ends, i.e. validate_branch() has reached the end of the branch.
	 */
	*dead_end = true;

	visited = VISITED_BRANCH << statep->uaccess;
	if (insn->visited & VISITED_BRANCH_MASK) {
		if (!insn->hint && !insn_cfi_match(insn, &statep->cfi))
			return 1;

		if (insn->visited & visited) {
			TRACE_INSN(insn, "already visited");
			return 0;
		}
	} else {
		nr_insns_visited++;
	}

	if (statep->noinstr)
		statep->instr += insn->instr;

	if (insn->hint) {
		if (insn->restore) {
			struct instruction *save_insn, *i;

			i = insn;
			save_insn = NULL;

			sym_for_each_insn_continue_reverse(file, func, i) {
				if (i->save) {
					save_insn = i;
					break;
				}
			}

			if (!save_insn) {
				WARN_INSN(insn, "no corresponding CFI save for CFI restore");
				return 1;
			}

			if (!save_insn->visited) {
				/*
				 * If the restore hint insn is at the
				 * beginning of a basic block and was
				 * branched to from elsewhere, and the
				 * save insn hasn't been visited yet,
				 * defer following this branch for now.
				 * It will be seen later via the
				 * straight-line path.
				 */
				if (!prev_insn) {
					TRACE_INSN(insn, "defer restore");
					return 0;
				}

				WARN_INSN(insn, "objtool isn't smart enough to handle this CFI save/restore combo");
				return 1;
			}

			insn->cfi = save_insn->cfi;
			nr_cfi_reused++;
		}

		statep->cfi = *insn->cfi;
	} else {
		/* XXX track if we actually changed statep->cfi */

		if (prev_insn && !cficmp(prev_insn->cfi, &statep->cfi)) {
			insn->cfi = prev_insn->cfi;
			nr_cfi_reused++;
		} else {
			insn->cfi = cfi_hash_find_or_add(&statep->cfi);
		}
	}

	insn->visited |= visited;

	if (propagate_alt_cfi(file, insn))
		return 1;

	if (insn->alts) {
		for (alt = insn->alts; alt; alt = alt->next) {
			TRACE_ALT_BEGIN(insn, alt, alt_name);
			ret = validate_branch(file, func, alt->insn, *statep);
			TRACE_ALT_END(insn, alt, alt_name);
			if (ret) {
				BT_INSN(insn, "(alt)");
				return ret;
			}
		}
		TRACE_ALT_INFO_NOADDR(insn, "/ ", "DEFAULT");
	}

	if (skip_alt_group(insn))
		return 0;

	if (handle_insn_ops(insn, next_insn, statep))
		return 1;

	switch (insn->type) {

	case INSN_RETURN:
		TRACE_INSN(insn, "return");
		return validate_return(func, insn, statep);

	case INSN_CALL:
	case INSN_CALL_DYNAMIC:
		if (insn->type == INSN_CALL)
			TRACE_INSN(insn, "call");
		else
			TRACE_INSN(insn, "indirect call");

		ret = validate_call(file, insn, statep);
		if (ret)
			return ret;

		if (opts.stackval && func && !is_special_call(insn) &&
		    !has_valid_stack_frame(statep)) {
			WARN_INSN(insn, "call without frame pointer save/setup");
			return 1;
		}

		break;

	case INSN_JUMP_CONDITIONAL:
	case INSN_JUMP_UNCONDITIONAL:
		if (is_sibling_call(insn)) {
			TRACE_INSN(insn, "sibling call");
			ret = validate_sibling_call(file, insn, statep);
			if (ret)
				return ret;

		} else if (insn->jump_dest) {
			if (insn->type == INSN_JUMP_UNCONDITIONAL)
				TRACE_INSN(insn, "unconditional jump");
			else
				TRACE_INSN(insn, "jump taken");

			ret = validate_branch(file, func, insn->jump_dest, *statep);
			if (ret) {
				BT_INSN(insn, "(branch)");
				return ret;
			}
		}

		if (insn->type == INSN_JUMP_UNCONDITIONAL)
			return 0;

		TRACE_INSN(insn, "jump not taken");
		break;

	case INSN_JUMP_DYNAMIC:
	case INSN_JUMP_DYNAMIC_CONDITIONAL:
		TRACE_INSN(insn, "indirect jump");
		if (is_sibling_call(insn)) {
			ret = validate_sibling_call(file, insn, statep);
			if (ret)
				return ret;
		}

		if (insn->type == INSN_JUMP_DYNAMIC)
			return 0;

		break;

	case INSN_SYSCALL:
		TRACE_INSN(insn, "syscall");
		if (func && (!next_insn || !next_insn->hint)) {
			WARN_INSN(insn, "unsupported instruction in callable function");
			return 1;
		}

		break;

	case INSN_SYSRET:
		TRACE_INSN(insn, "sysret");
		if (func && (!next_insn || !next_insn->hint)) {
			WARN_INSN(insn, "unsupported instruction in callable function");
			return 1;
		}

		return 0;

	case INSN_STAC:
		TRACE_INSN(insn, "stac");
		if (!opts.uaccess)
			break;

		if (statep->uaccess) {
			WARN_INSN(insn, "recursive UACCESS enable");
			return 1;
		}

		statep->uaccess = true;
		break;

	case INSN_CLAC:
		TRACE_INSN(insn, "clac");
		if (!opts.uaccess)
			break;

		/* A PUSHF/CLAC/POPF adapter may start with AC clear. Its saved
		 * state is still checked at POPF and on every exit. */
		if (!statep->uaccess && func && !statep->uaccess_stack && !func->rap_terminal) {
			WARN_INSN(insn, "redundant UACCESS disable");
			return 1;
		}

		if (func_uaccess_safe(func) && !statep->uaccess_stack && !func->rap_terminal) {
			WARN_INSN(insn, "UACCESS-safe disables UACCESS");
			return 1;
		}

		statep->uaccess = false;
		break;

	case INSN_STD:
		TRACE_INSN(insn, "std");
		if (statep->df) {
			WARN_INSN(insn, "recursive STD");
			return 1;
		}

		statep->df = true;
		break;

	case INSN_CLD:
		TRACE_INSN(insn, "cld");
		if (!statep->df && func && !func->rap_terminal) {
			WARN_INSN(insn, "redundant CLD");
			return 1;
		}

		statep->df = false;
		break;

	default:
		break;
	}

	if (insn->dead_end)
		TRACE_INSN(insn, "dead end");

	*dead_end = insn->dead_end;
	return 0;
}

/*
 * Follow the branch starting at the given instruction, and recursively follow
 * any other branches (jumps).  Meanwhile, track the frame pointer state at
 * each instruction and validate all the rules described in
 * tools/objtool/Documentation/objtool.txt.
 */
static int do_validate_branch(struct objtool_file *file, struct symbol *func,
			      struct instruction *insn, struct insn_state *state)
{
	struct instruction *next_insn, *prev_insn = NULL;
	bool dead_end;
	int ret;

	if (func && func->ignore)
		return 0;

	do {
		insn->trace = 0;
		next_insn = next_insn_to_validate(file, insn);

		if (opts.checksum && func && insn->sec)
			checksum_update_insn(file, func, insn);

		if (func && insn_func(insn) && func != insn_func(insn)->pfunc) {
			/* Ignore KCFI type preambles, which always fall through */
			if (is_prefix_func(func))
				return 0;

			if (file->ignore_unreachables)
				return 0;

			WARN("%s() falls through to next function %s()",
			     func->name, insn_func(insn)->name);
			func->warned = 1;

			return 1;
		}

		ret = validate_insn(file, func, insn, state, prev_insn, next_insn,
				    &dead_end);

		if (!insn->trace) {
			if (ret)
				TRACE_INSN(insn, "warning (%d)", ret);
			else
				TRACE_INSN(insn, NULL);
		}

		if (!dead_end && !next_insn) {
			if (state->cfi.cfa.base == CFI_UNDEFINED)
				return 0;
			if (file->ignore_unreachables)
				return 0;

			WARN("%s%sunexpected end of section %s",
			     func ? func->name : "", func ? "(): " : "",
			     insn->sec->name);
			return 1;
		}

		prev_insn = insn;
		insn = next_insn;

	} while (!dead_end);

	return ret;
}

static int validate_branch(struct objtool_file *file, struct symbol *func,
			   struct instruction *insn, struct insn_state state)
{
	int ret;

	trace_depth_inc();
	ret = do_validate_branch(file, func, insn, &state);
	trace_depth_dec();

	return ret;
}

static int validate_unwind_hint(struct objtool_file *file,
				  struct instruction *insn,
				  struct insn_state *state)
{
	if (insn->hint && !insn->visited) {
		struct symbol *func = insn_func(insn);
		int ret;

		if (opts.checksum)
			checksum_init(func);

		ret = validate_branch(file, func, insn, *state);
		if (ret)
			BT_INSN(insn, "<=== (hint)");
		return ret;
	}

	return 0;
}

static int validate_unwind_hints(struct objtool_file *file, struct section *sec)
{
	struct instruction *insn;
	struct insn_state state;
	int warnings = 0;

	if (!file->hints)
		return 0;

	init_insn_state(file, &state, sec);

	if (sec) {
		sec_for_each_insn(file, sec, insn)
			warnings += validate_unwind_hint(file, insn, &state);
	} else {
		for_each_insn(file, insn)
			warnings += validate_unwind_hint(file, insn, &state);
	}

	return warnings;
}

/*
 * Validate rethunk entry constraint: must untrain RET before the first RET.
 *
 * Follow every branch (intra-function) and ensure VALIDATE_UNRET_END comes
 * before an actual RET instruction.
 */
static int validate_unret(struct objtool_file *file, struct instruction *insn)
{
	struct instruction *next, *dest;
	int ret;

	for (;;) {
		next = next_insn_to_validate(file, insn);

		if (insn->visited & VISITED_UNRET)
			return 0;

		insn->visited |= VISITED_UNRET;

		if (insn->alts) {
			struct alternative *alt;
			for (alt = insn->alts; alt; alt = alt->next) {
				ret = validate_unret(file, alt->insn);
				if (ret) {
					BT_INSN(insn, "(alt)");
					return ret;
				}
			}
		}

		switch (insn->type) {

		case INSN_CALL_DYNAMIC:
		case INSN_JUMP_DYNAMIC:
		case INSN_JUMP_DYNAMIC_CONDITIONAL:
			WARN_INSN(insn, "early indirect call");
			return 1;

		case INSN_JUMP_UNCONDITIONAL:
		case INSN_JUMP_CONDITIONAL:
			if (!is_sibling_call(insn)) {
				if (!insn->jump_dest) {
					WARN_INSN(insn, "unresolved jump target after linking?!?");
					return 1;
				}
				ret = validate_unret(file, insn->jump_dest);
				if (ret) {
					BT_INSN(insn, "(branch%s)",
						insn->type == INSN_JUMP_CONDITIONAL ? "-cond" : "");
					return ret;
				}

				if (insn->type == INSN_JUMP_UNCONDITIONAL)
					return 0;

				break;
			}

			/* fallthrough */
		case INSN_CALL:
			dest = find_insn(file, insn_call_dest(insn)->sec,
					 insn_call_dest(insn)->offset);
			if (!dest) {
				WARN("Unresolved function after linking!?: %s",
				     insn_call_dest(insn)->name);
				return 1;
			}

			ret = validate_unret(file, dest);
			if (ret) {
				BT_INSN(insn, "(call)");
				return ret;
			}
			/*
			 * If a call returns without error, it must have seen UNTRAIN_RET.
			 * Therefore any non-error return is a success.
			 */
			return 0;

		case INSN_RETURN:
			WARN_INSN(insn, "RET before UNTRAIN");
			return 1;

		case INSN_SYSCALL:
			break;

		case INSN_SYSRET:
			return 0;

		case INSN_NOP:
			if (insn->retpoline_safe)
				return 0;
			break;

		default:
			break;
		}

		if (insn->dead_end)
			return 0;

		if (!next) {
			WARN_INSN(insn, "teh end!");
			return 1;
		}
		insn = next;
	}

	return 0;
}

/*
 * Validate that all branches starting at VALIDATE_UNRET_BEGIN encounter
 * VALIDATE_UNRET_END before RET.
 */
static int validate_unrets(struct objtool_file *file)
{
	struct instruction *insn;
	int warnings = 0;

	for_each_insn(file, insn) {
		if (!insn->unret)
			continue;

		warnings += validate_unret(file, insn);
	}

	return warnings;
}

static int validate_retpoline(struct objtool_file *file)
{
	struct instruction *insn;
	int warnings = 0;

	for_each_insn(file, insn) {
		if (insn->type != INSN_JUMP_DYNAMIC &&
		    insn->type != INSN_CALL_DYNAMIC &&
		    insn->type != INSN_RETURN)
			continue;

		if (insn->retpoline_safe)
			continue;

		if (insn->sec->init)
			continue;

		if (insn->type == INSN_RETURN) {
			if (opts.rethunk) {
				WARN_INSN(insn, "'naked' return found in MITIGATION_RETHUNK build");
				warnings++;
			}
			continue;
		}

		WARN_INSN(insn, "indirect %s found in MITIGATION_RETPOLINE build",
			  insn->type == INSN_JUMP_DYNAMIC ? "jump" : "call");
		warnings++;
	}

	if (!opts.cfi)
		return warnings;

	/*
	 * kCFI call sites look like:
	 *
	 *     movl $(-0x12345678), %r10d
	 *     addl -4(%r11), %r10d
	 *     jz 1f
	 *     ud2
	 *  1: cs call __x86_indirect_thunk_r11
	 *
	 * Verify all indirect calls are kCFI adorned by checking for the
	 * UD2. Notably, doing __nocfi calls to regular (cfi) functions is
	 * broken.
	 */
	list_for_each_entry(insn, &file->retpoline_call_list, call_node) {
		struct symbol *sym = insn->sym;

		if (sym && (sym->type == STT_NOTYPE ||
			    sym->type == STT_FUNC) && !sym->nocfi) {
			struct instruction *prev =
				prev_insn_same_sym(file, insn);

			if (!prev || prev->type != INSN_BUG) {
				WARN_INSN(insn, "no-cfi indirect call!");
				warnings++;
			}
		}
	}

	return warnings;
}

static bool is_kasan_insn(struct instruction *insn)
{
	return (insn->type == INSN_CALL &&
		!strcmp(insn_call_dest(insn)->name, "__asan_handle_no_return"));
}

static bool is_ubsan_insn(struct instruction *insn)
{
	return (insn->type == INSN_CALL &&
		!strcmp(insn_call_dest(insn)->name,
			"__ubsan_handle_builtin_unreachable"));
}

static bool ignore_unreachable_insn(struct objtool_file *file, struct instruction *insn)
{
	struct symbol *func = insn_func(insn);
	struct instruction *prev_insn;
	int i;

	if (insn->type == INSN_NOP || insn->type == INSN_TRAP ||
	    insn->hole || (func && func->ignore))
		return true;

	/*
	 * Ignore alternative replacement instructions.  This can happen
	 * when a whitelisted function uses one of the ALTERNATIVE macros.
	 */
	if (!strcmp(insn->sec->name, ".altinstr_replacement") ||
	    !strcmp(insn->sec->name, ".altinstr_aux"))
		return true;

	if (!func)
		return false;

	if (func->static_call_tramp)
		return true;

	/*
	 * CONFIG_UBSAN_TRAP inserts a UD2 when it sees
	 * __builtin_unreachable().  The BUG() macro has an unreachable() after
	 * the UD2, which causes GCC's undefined trap logic to emit another UD2
	 * (or occasionally a JMP to UD2).
	 *
	 * It may also insert a UD2 after calling a __noreturn function.
	 */
	prev_insn = prev_insn_same_sec(file, insn);
	if (prev_insn && prev_insn->dead_end &&
	    (insn->type == INSN_BUG ||
	     (insn->type == INSN_JUMP_UNCONDITIONAL &&
	      insn->jump_dest && insn->jump_dest->type == INSN_BUG)))
		return true;

	/*
	 * Check if this (or a subsequent) instruction is related to
	 * CONFIG_UBSAN or CONFIG_KASAN.
	 *
	 * End the search at 5 instructions to avoid going into the weeds.
	 */
	for (i = 0; i < 5; i++) {

		if (is_kasan_insn(insn) || is_ubsan_insn(insn))
			return true;

		if (insn->type == INSN_JUMP_UNCONDITIONAL) {
			if (insn->jump_dest &&
			    insn_func(insn->jump_dest) == func) {
				insn = insn->jump_dest;
				continue;
			}

			break;
		}

		if (insn->offset + insn->len >= func->offset + func->len)
			break;

		insn = next_insn_same_sec(file, insn);
	}

	return false;
}

/*
 * For FineIBT or kCFI, a certain number of bytes preceding the function may be
 * NOPs.  Those NOPs may be rewritten at runtime and executed, so give them a
 * proper function name: __pfx_<func>.
 *
 * The NOPs may not exist for the following cases:
 *
 *   - compiler cloned functions (*.cold, *.part0, etc)
 *   - asm functions created with inline asm or without SYM_FUNC_START()
 *
 * Also, the function may already have a prefix from a previous objtool run
 * (livepatch extracted functions, or manually running objtool multiple times).
 *
 * So return 0 if the NOPs are missing or the function already has a prefix
 * symbol.
 */
static int create_prefix_symbol(struct objtool_file *file, struct symbol *func)
{
	struct instruction *insn, *prev;
	char name[SYM_NAME_LEN];
	struct cfi_state *cfi;

	if (!is_func_sym(func) || is_prefix_func(func) ||
	    func->cold || func->static_call_tramp)
		return 0;

	if ((strlen(func->name) + sizeof("__pfx_") > SYM_NAME_LEN)) {
		WARN("%s: symbol name too long, can't create __pfx_ symbol",
		      func->name);
		return 0;
	}

	if (snprintf_check(name, SYM_NAME_LEN, "__pfx_%s", func->name))
		return -1;

	if (file->klp) {
		struct symbol *pfx;

		pfx = find_symbol_by_offset(func->sec, func->offset - opts.prefix);
		if (pfx && is_prefix_func(pfx) && !strcmp(pfx->name, name))
			return 0;
	}

	insn = find_insn(file, func->sec, func->offset);
	if (!insn) {
		WARN("%s: can't find starting instruction", func->name);
		return -1;
	}

	for (prev = prev_insn_same_sec(file, insn);
	     prev;
	     prev = prev_insn_same_sec(file, prev)) {
		u64 offset;

		if (prev->type != INSN_NOP)
			return 0;

		offset = func->offset - prev->offset;

		if (offset > opts.prefix)
			return 0;

		if (offset < opts.prefix)
			continue;

		if (!elf_create_symbol(file->elf, name, func->sec,
				       GELF_ST_BIND(func->sym.st_info),
				       GELF_ST_TYPE(func->sym.st_info),
				       prev->offset, opts.prefix))
			return -1;

		break;
	}

	if (!prev)
		return 0;

	if (!insn->cfi) {
		/*
		 * This can happen if stack validation isn't enabled or the
		 * function is annotated with STACK_FRAME_NON_STANDARD.
		 */
		return 0;
	}

	/* Propagate insn->cfi to the prefix code */
	cfi = cfi_hash_find_or_add(insn->cfi);
	for (; prev != insn; prev = next_insn_same_sec(file, prev))
		prev->cfi = cfi;

	return 0;
}

static int create_prefix_symbols(struct objtool_file *file)
{
	struct section *sec;
	struct symbol *func;

	for_each_sec(file->elf, sec) {
		if (!is_text_sec(sec))
			continue;

		sec_for_each_sym(sec, func) {
			if (create_prefix_symbol(file, func))
				return -1;
		}
	}

	return 0;
}

static int validate_symbol(struct objtool_file *file, struct section *sec,
			   struct symbol *sym, struct insn_state *state)
{
	struct instruction *insn;
	struct symbol *func;
	int ret;

	if (!sym->len) {
		WARN("%s() is missing an ELF size annotation", sym->name);
		return 1;
	}

	if (sym->pfunc != sym || sym->alias != sym)
		return 0;

	insn = find_insn(file, sec, sym->offset);
	if (!insn || insn->visited)
		return 0;

	if (opts.uaccess)
		state->uaccess = sym->uaccess_safe;

	func = insn_func(insn);

	if (opts.checksum)
		checksum_init(func);

	if (opts.trace && !fnmatch(opts.trace, sym->name, 0)) {
		trace_enable();
		TRACE("%s: validation begin\n", sym->name);
	}

	ret = validate_branch(file, func, insn, *state);
	if (ret)
		BT_INSN(insn, "<=== (sym)");

	TRACE("%s: validation %s\n\n", sym->name, ret ? "failed" : "end");
	trace_disable();

	if (opts.checksum)
		checksum_finish(func);

	return ret;
}

static int validate_section(struct objtool_file *file, struct section *sec)
{
	struct insn_state state;
	struct symbol *func;
	int warnings = 0;

	sec_for_each_sym(sec, func) {
		if (!is_func_sym(func))
			continue;

		init_insn_state(file, &state, sec);
		set_func_state(&state.cfi);

		warnings += validate_symbol(file, sec, func, &state);
	}

	return warnings;
}

static int validate_noinstr_sections(struct objtool_file *file)
{
	struct section *sec;
	int warnings = 0;

	sec = find_section_by_name(file->elf, ".noinstr.text");
	if (sec) {
		warnings += validate_section(file, sec);
		warnings += validate_unwind_hints(file, sec);
	}

	sec = find_section_by_name(file->elf, ".entry.text");
	if (sec) {
		warnings += validate_section(file, sec);
		warnings += validate_unwind_hints(file, sec);
	}

	sec = find_section_by_name(file->elf, ".cpuidle.text");
	if (sec) {
		warnings += validate_section(file, sec);
		warnings += validate_unwind_hints(file, sec);
	}

	return warnings;
}

static int validate_functions(struct objtool_file *file)
{
	struct section *sec;
	int warnings = 0;

	for_each_sec(file->elf, sec) {
		if (!is_text_sec(sec))
			continue;

		warnings += validate_section(file, sec);
	}

	return warnings;
}

static void mark_endbr_used(struct instruction *insn)
{
	if (!list_empty(&insn->call_node))
		list_del_init(&insn->call_node);
}

static bool noendbr_range(struct objtool_file *file, struct instruction *insn)
{
	struct symbol *sym = find_symbol_containing(insn->sec, insn->offset-1);
	struct instruction *first;

	if (!sym)
		return false;

	first = find_insn(file, sym->sec, sym->offset);
	if (!first)
		return false;

	if (first->type != INSN_ENDBR && !first->noendbr)
		return false;

	return insn->offset == sym->offset + sym->len;
}

static int __validate_ibt_insn(struct objtool_file *file, struct instruction *insn,
			       struct instruction *dest)
{
	if (dest->type == INSN_ENDBR) {
		mark_endbr_used(dest);
		return 0;
	}

	if (insn_func(dest) && insn_func(insn) &&
	    insn_func(dest)->pfunc == insn_func(insn)->pfunc) {
		/*
		 * Anything from->to self is either _THIS_IP_ or
		 * IRET-to-self.
		 *
		 * There is no sane way to annotate _THIS_IP_ since the
		 * compiler treats the relocation as a constant and is
		 * happy to fold in offsets, skewing any annotation we
		 * do, leading to vast amounts of false-positives.
		 *
		 * There's also compiler generated _THIS_IP_ through
		 * KCOV and such which we have no hope of annotating.
		 *
		 * As such, blanket accept self-references without
		 * issue.
		 */
		return 0;
	}

	/*
	 * Accept anything ANNOTATE_NOENDBR.
	 */
	if (dest->noendbr)
		return 0;

	/*
	 * Accept if this is the instruction after a symbol
	 * that is (no)endbr -- typical code-range usage.
	 */
	if (noendbr_range(file, dest))
		return 0;

	WARN_INSN(insn, "relocation to !ENDBR: %s", offstr(dest->sec, dest->offset));
	return 1;
}

static int validate_ibt_insn(struct objtool_file *file, struct instruction *insn)
{
	struct instruction *dest;
	struct reloc *reloc;
	unsigned long off;
	int warnings = 0;

	/* Already proven to load R10 with the immediately following call's
	 * exact return address. A noreturn call may end at a symbol boundary. */
	if (insn->rap_binding)
		return 0;

	/*
	 * Looking for function pointer load relocations.  Ignore
	 * direct/indirect branches:
	 */
	switch (insn->type) {

	case INSN_CALL:
	case INSN_CALL_DYNAMIC:
	case INSN_JUMP_CONDITIONAL:
	case INSN_JUMP_UNCONDITIONAL:
	case INSN_JUMP_DYNAMIC:
	case INSN_JUMP_DYNAMIC_CONDITIONAL:
	case INSN_RETURN:
	case INSN_NOP:
		return 0;

	case INSN_LEA_RIP:
		if (!insn_reloc(file, insn)) {
			/* local function pointer reference without reloc */

			off = arch_jump_destination(insn);

			dest = find_insn(file, insn->sec, off);
			if (!dest) {
				WARN_INSN(insn, "corrupt function pointer reference");
				return 1;
			}

			return __validate_ibt_insn(file, insn, dest);
		}
		break;

	default:
		break;
	}

	for (reloc = insn_reloc(file, insn);
	     reloc;
	     reloc = find_reloc_by_dest_range(file->elf, insn->sec,
					      reloc_offset(reloc) + 1,
					      (insn->offset + insn->len) - (reloc_offset(reloc) + 1))) {

		off = reloc->sym->offset + arch_insn_adjusted_addend(insn, reloc);

		dest = find_insn(file, reloc->sym->sec, off);
		if (!dest)
			continue;

		warnings += __validate_ibt_insn(file, insn, dest);
	}

	return warnings;
}

static int validate_ibt_data_reloc(struct objtool_file *file,
				   struct reloc *reloc)
{
	struct instruction *dest;

	dest = find_insn(file, reloc->sym->sec,
			 reloc->sym->offset + reloc_addend(reloc));
	if (!dest)
		return 0;

	if (dest->type == INSN_ENDBR) {
		mark_endbr_used(dest);
		return 0;
	}

	if (dest->noendbr)
		return 0;

	WARN_FUNC(reloc->sec->base, reloc_offset(reloc),
		  "data relocation to !ENDBR: %s", offstr(dest->sec, dest->offset));

	return 1;
}

/*
 * Validate IBT rules and remove used ENDBR instructions from the seal list.
 * Unused ENDBR instructions will be annotated for sealing (i.e., replaced with
 * NOPs) later, in create_ibt_endbr_seal_sections().
 */
static int validate_ibt(struct objtool_file *file)
{
	struct section *sec;
	struct reloc *reloc;
	struct instruction *insn;
	int warnings = 0;

	for_each_insn(file, insn)
		warnings += validate_ibt_insn(file, insn);

	for_each_sec(file->elf, sec) {

		/* Already done by validate_ibt_insn() */
		if (is_text_sec(sec))
			continue;

		if (!sec->rsec)
			continue;

		/*
		 * These sections can reference text addresses, but not with
		 * the intent to indirect branch to them.
		 */
		if ((!strncmp(sec->name, ".discard", 8) &&
		     strcmp(sec->name, ".discard.ibt_endbr_noseal"))	||
		    !strncmp(sec->name, ".debug", 6)			||
		    !strcmp(sec->name, ".altinstructions")		||
		    !strcmp(sec->name, ".ibt_endbr_seal")		||
		    !strcmp(sec->name, ".kcfi_traps")			||
		    !strcmp(sec->name, ".orc_unwind_ip")		||
		    !strcmp(sec->name, ".retpoline_sites")		||
		    !strcmp(sec->name, ".smp_locks")			||
		    !strcmp(sec->name, ".static_call_sites")		||
		    !strcmp(sec->name, "_error_injection_whitelist")	||
		    !strcmp(sec->name, "_kprobe_blacklist")		||
		    !strcmp(sec->name, "__bug_table")			||
		    !strcmp(sec->name, "__ex_table")			||
		    !strcmp(sec->name, "__jump_table")			||
		    !strcmp(sec->name, ".init.klp_funcs")		||
		    !strcmp(sec->name, "__mcount_loc")			||
		    !strcmp(sec->name, ".llvm.call-graph-profile")	||
		    !strcmp(sec->name, ".llvm_bb_addr_map")		||
		    !strcmp(sec->name, "__tracepoints")			||
		    !strcmp(sec->name, ".return_sites")			||
		    /* Validated as exact post-CALL continuations above. */
		    !strcmp(sec->name, ".hdn.rap.sites")			||
		    /* Typed identities and checked entry/fentry continuations;
		     * these are not ordinary IBT indirect-call destinations. */
		    !strcmp(sec->name, ".hdn.rap.entries")			||
		    !strcmp(sec->name, ".hdn.rap.static_calls")		||
		    !strcmp(sec->name, ".hdn.rap.static_sites")		||
		    !strcmp(sec->name, ".call_sites")			||
		    !strcmp(sec->name, "__patchable_function_entries"))
			continue;

		for_each_reloc(sec->rsec, reloc)
			warnings += validate_ibt_data_reloc(file, reloc);
	}

	return warnings;
}

static int validate_sls(struct objtool_file *file)
{
	struct instruction *insn, *next_insn;
	int warnings = 0;

	for_each_insn(file, insn) {
		next_insn = next_insn_same_sec(file, insn);

		if (insn->retpoline_safe)
			continue;

		switch (insn->type) {
		case INSN_RETURN:
			if (!next_insn || next_insn->type != INSN_TRAP) {
				WARN_INSN(insn, "missing int3 after ret");
				warnings++;
			}

			break;
		case INSN_JUMP_DYNAMIC:
			if (!next_insn || next_insn->type != INSN_TRAP) {
				WARN_INSN(insn, "missing int3 after indirect jump");
				warnings++;
			}
			break;
		default:
			break;
		}
	}

	return warnings;
}

static int validate_reachable_instructions(struct objtool_file *file)
{
	struct instruction *insn, *prev_insn;
	struct symbol *call_dest;
	int warnings = 0;

	if (file->ignore_unreachables)
		return 0;

	for_each_insn(file, insn) {
		if (insn->visited || ignore_unreachable_insn(file, insn))
			continue;

		prev_insn = prev_insn_same_sec(file, insn);
		if (prev_insn && prev_insn->dead_end) {
			call_dest = insn_call_dest(prev_insn);
			if (call_dest) {
				WARN_INSN(insn, "%s() missing __noreturn in .c/.h or NORETURN() in noreturns.h",
					  call_dest->name);
				warnings++;
				continue;
			}
		}

		WARN_INSN(insn, "unreachable instruction");
		warnings++;
	}

	return warnings;
}

__weak bool arch_absolute_reloc(struct elf *elf, struct reloc *reloc)
{
	unsigned int type = reloc_type(reloc);
	size_t sz = elf_addr_size(elf);

	return (sz == 8) ? (type == R_ABS64) : (type == R_ABS32);
}

static int check_abs_references(struct objtool_file *file)
{
	struct section *sec;
	struct reloc *reloc;
	int ret = 0;

	for_each_sec(file->elf, sec) {
		/* absolute references in non-loadable sections are fine */
		if (!(sec->sh.sh_flags & SHF_ALLOC))
			continue;

		/* section must have an associated .rela section */
		if (!sec->rsec)
			continue;

		/*
		 * Special case for compiler generated metadata that is not
		 * consumed until after boot.
		 */
		if (!strcmp(sec->name, "__patchable_function_entries"))
			continue;

		for_each_reloc(sec->rsec, reloc) {
			if (arch_absolute_reloc(file->elf, reloc)) {
				WARN("section %s has absolute relocation at offset 0x%llx",
				     sec->name, (unsigned long long)reloc_offset(reloc));
				ret++;
			}
		}
	}
	return ret;
}

struct insn_chunk {
	void *addr;
	struct insn_chunk *next;
};

/*
 * Reduce peak RSS usage by freeing insns memory before writing the ELF file,
 * which can trigger more allocations for .debug_* sections whose data hasn't
 * been read yet.
 */
static void free_insns(struct objtool_file *file)
{
	struct instruction *insn;
	struct insn_chunk *chunks = NULL, *chunk;

	for_each_insn(file, insn) {
		if (!insn->idx) {
			chunk = malloc(sizeof(*chunk));
			chunk->addr = insn;
			chunk->next = chunks;
			chunks = chunk;
		}
	}

	for (chunk = chunks; chunk; chunk = chunk->next)
		free(chunk->addr);
}

const char *objtool_disas_insn(struct instruction *insn)
{
	struct disas_context *dctx = objtool_disas_ctx;

	if (!dctx)
		return "";

	disas_insn(dctx, insn);
	return disas_result(dctx);
}

int check(struct objtool_file *file)
{
	struct disas_context *disas_ctx = NULL;
	int ret = 0, warnings = 0;

	/*
	 * Create a disassembly context if we might disassemble any
	 * instruction or function.
	 */
	if (opts.verbose || opts.backtrace || opts.trace || opts.disas) {
		disas_ctx = disas_context_create(file);
		if (!disas_ctx) {
			opts.disas = false;
			opts.trace = false;
		}
		objtool_disas_ctx = disas_ctx;
	}

	arch_initial_func_cfi_state(&initial_func_cfi);
	init_cfi_state(&init_cfi);
	init_cfi_state(&func_cfi);
	set_func_state(&func_cfi);
	init_cfi_state(&force_undefined_cfi);
	force_undefined_cfi.force_undefined = true;

	if (!cfi_hash_alloc(1UL << (file->elf->symbol_bits - 3))) {
		ret = -1;
		goto out;
	}

	cfi_hash_add(&init_cfi);
	cfi_hash_add(&func_cfi);

	ret = checksum_debug_init(file);
	if (ret)
		goto out;

	ret = decode_sections(file);
	if (ret)
		goto out;

	if (!nr_insns)
		goto out;

	if (opts.retpoline)
		warnings += validate_retpoline(file);

	if (validate_branch_enabled()) {
		int w = 0;

		w += validate_functions(file);
		w += validate_unwind_hints(file, NULL);
		if (!w)
			w += validate_reachable_instructions(file);

		warnings += w;

	} else if (opts.noinstr) {
		warnings += validate_noinstr_sections(file);
	}

	if (opts.unret) {
		/*
		 * Must be after validate_branch() and friends, it plays
		 * further games with insn->visited.
		 */
		warnings += validate_unrets(file);
	}

	if (opts.ibt)
		warnings += validate_ibt(file);
	if (opts.rap)
		warnings += validate_rap(file);

	if (opts.sls)
		warnings += validate_sls(file);

	if (opts.static_call) {
		ret = create_static_call_sections(file);
		if (ret)
			goto out;
	}

	if (opts.retpoline) {
		ret = create_retpoline_sites_sections(file);
		if (ret)
			goto out;
	}

	if (opts.cfi) {
		ret = create_cfi_sections(file);
		if (ret)
			goto out;
	}

	if (opts.rethunk) {
		ret = create_return_sites_sections(file);
		if (ret)
			goto out;

		if (opts.hack_skylake) {
			ret = create_direct_call_sections(file);
			if (ret)
				goto out;
		}
	}

	if (opts.mcount) {
		ret = create_mcount_loc_sections(file);
		if (ret)
			goto out;
	}

	if (opts.prefix) {
		ret = create_prefix_symbols(file);
		if (ret)
			goto out;
	}

	if (opts.ibt) {
		ret = create_ibt_endbr_seal_sections(file);
		if (ret)
			goto out;
	}

	if (opts.noabs)
		warnings += check_abs_references(file);

	if (opts.checksum) {
		ret = create_sym_checksum_section(file);
		if (ret)
			goto out;
	}

	if (opts.orc && nr_insns) {
		ret = orc_create(file);
		if (ret)
			goto out;
	}

	if (opts.stats) {
		printf("nr_insns_visited: %ld\n", nr_insns_visited);
		printf("nr_cfi: %ld\n", nr_cfi);
		printf("nr_cfi_reused: %ld\n", nr_cfi_reused);
		printf("nr_cfi_cache: %ld\n", nr_cfi_cache);
	}

out:
	if (ret || warnings) {
		if (opts.werror && warnings)
			ret = 1;

		if (opts.verbose) {
			if (opts.werror && warnings)
				WARN("%d warning(s) upgraded to errors", warnings);
			disas_warned_funcs(disas_ctx);
		}
	}

	if (opts.disas)
		disas_funcs(disas_ctx);

	if (disas_ctx) {
		disas_context_destroy(disas_ctx);
		objtool_disas_ctx = NULL;
	}

	free_insns(file);

	if (!ret && !warnings)
		return 0;

	if (opts.backup && make_backup())
		return 1;

	return ret;
}
