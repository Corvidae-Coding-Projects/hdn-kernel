/* SPDX-License-Identifier: GPL-2.0-only */
/* PVH enters an ELF64 image in 32-bit mode. Only the exact named section is
 * decoded that way. The physical roots never call runtime C; the virtual root
 * establishes the statically registered boot stack before its bound C call. */
static unsigned int rap_pvh_kind(const char *name)
{
	if (!strcmp(name, "pvh_start_xen"))
		return 52;
	if (!strcmp(name, "hdn_pvh_physical64"))
		return 53;
	if (!strcmp(name, "hdn_pvh_virtual64"))
		return 54;
	return 0;
}

/* rva(symbol) is relative to the beginning of the 32-bit root, NOT to the
 * instruction end. ELF's PC32 addend includes the operand-to-root distance. */
static bool rap_pvh_rva(struct rap_sequence *s, const char *op, size_t size,
		const char *name)
{
	struct symbol *target = find_symbol_by_name(s->file->elf, name);
	unsigned long off = s->func->offset + s->pos;
	struct instruction *insn = find_insn(s->file, s->func->sec, off);
	struct reloc *reloc;
	const char *p = s->func->sec->data->d_buf + off;
	int32_t value;

	if (!target || is_weak_sym(target) || !insn || insn->len != size + 4 ||
	    s->pos > s->func->len || insn->len > s->func->len - s->pos ||
	    memcmp(p, op, size) ||
	    find_reloc_by_dest_range(s->file->elf, s->func->sec, off, size) ||
	    find_reloc_by_dest_range(s->file->elf, s->func->sec, off + size + 1, 3))
		return false;
	reloc = find_reloc_by_dest(s->file->elf, s->func->sec, off + size);
	if (reloc) {
		if (reloc_type(reloc) != R_X86_64_PC32 || reloc->sym->sec != target->sec ||
		    (is_undef_sym(target) && reloc->sym != target) ||
		    reloc->sym->offset + reloc_addend(reloc) != target->offset + s->pos + size)
			return false;
	} else {
		memcpy(&value, p + size, 4);
		if (is_undef_sym(target) || target->sec != s->func->sec ||
		    s->func->offset + value != target->offset)
			return false;
	}
	s->pos += insn->len;
	return true;
}

static int verify_rap_pvh(struct objtool_file *file, struct symbol *func)
{
	struct rap_kexec_sequence k = { .seq = { .file = file, .func = func } };
	struct rap_sequence *s = &k.seq;
	struct instruction *insn;

#define PVH_BYTES(b) do { if (!rap_sequence_bytes(s, b, sizeof(b) - 1)) goto bad; } while (0)
#define PVH_RVA(b, n) do { if (!rap_pvh_rva(s, b, sizeof(b) - 1, n)) goto bad; } while (0)
#define PVH_REF(b, n) do { if (!rap_sequence_reference(s, b, sizeof(b) - 1, n, true)) goto bad; } while (0)
#define PVH_LABEL(n) do { if (!rap_kexec_label(&k, n)) goto bad; } while (0)
#define PVH_BRANCH(op, n) do { if (!rap_kexec_branch(&k, op, n)) goto bad; } while (0)
	if (is_weak_sym(func) ||
	    (!func->sec->init && strcmp(func->sec->name, ".init.text.hdn_pvh32")) ||
	    func->rap_kind != rap_pvh_kind(func->name))
		goto bad;
	if (func->rap_kind == 52) {
		if (strcmp(func->sec->name, ".init.text.hdn_pvh32") || func->offset ||
		    func->len != sec_size(func->sec))
			goto bad;
		PVH_BYTES("\xfc\x8b\x03\x8d\x63\x04\xe8\0\0\0\0\x5d\x89\x03"
			  "\x83\xed\x0b\xbc\0\0\0\0");
		PVH_RVA("\x8d\x85", "pvh_gdt");
		PVH_BYTES("\x01\x40\x02\x0f\x01\x10\xb8\x10\0\0\0\x8e\xd8\x8e\xc0\x8e\xd0");
		PVH_RVA("\x8d\xbd", "pvh_start_info");
		PVH_BYTES("\x89\xde");
		PVH_RVA("\x8b\x8d", "pvh_start_info_sz");
		PVH_BYTES("\xc1\xe9\x02\xf3\xa5");
		PVH_RVA("\x8d\xa5", "pvh_early_stack_end");
		PVH_BYTES("\x0f\x20\xe0\x83\xc8\x20\x0f\x22\xe0"
			  "\xb9\x80\0\0\xc0\x0f\x32\x0f\xba\xe8\x08\x0f\x30\x89\xeb");
		PVH_RVA("\x2b\x9d", "xen_elfnote_phys32_entry");
		PVH_BRANCH(0x74, 0);
		PVH_RVA("\x89\x9d", "phys_base");
		PVH_RVA("\x8d\xbd", "pvh_init_top_pgt");
		PVH_BYTES("\xb9\0\x02\0\0");
		PVH_LABEL(1);
		PVH_BYTES("\xf7\x07\x01\0\0\0");
		PVH_BRANCH(0x74, 2);
		PVH_BYTES("\x01\x1f");
		PVH_LABEL(2);
		PVH_BYTES("\x83\xc7\x08\x49");
		PVH_BRANCH(0x75, 1);
		PVH_RVA("\x8d\xbd", "pvh_level3_ident_pgt");
		PVH_BYTES("\x01\x1f");
		PVH_RVA("\x8d\xbd", "pvh_level3_kernel_pgt");
		PVH_BYTES("\x01\x9f\xf0\x0f\0\0\x01\x9f\xf8\x0f\0\0");
		PVH_RVA("\x8d\xbd", "pvh_level2_kernel_pgt");
		PVH_BYTES("\xb9\0\x02\0\0");
		PVH_LABEL(3);
		PVH_BYTES("\xf7\x07\x01\0\0\0");
		PVH_BRANCH(0x74, 4);
		PVH_BYTES("\x01\x1f");
		PVH_LABEL(4);
		PVH_BYTES("\x83\xc7\x08\x49");
		PVH_BRANCH(0x75, 3);
		PVH_LABEL(0);
		PVH_RVA("\x8d\x85", "pvh_init_top_pgt");
		PVH_BYTES("\x0f\x22\xd8\xb8\x01\0\0\x80\x0f\x22\xc0\x6a\x08");
		PVH_RVA("\x8d\x85", "hdn_pvh_physical64");
		PVH_BYTES("\x50\xcb");
	} else if (func->rap_kind == 53) {
		PVH_REF("\x48\x8d\x05", "hdn_pvh_virtual64");
		PVH_REF("\x48\x2b\x05", "phys_base");
		PVH_BYTES("\x48\x05\0\0\0\x80\xff\xe0");
	} else {
		PVH_BYTES("\xb9\x01\x01\0\xc0\x31\xc0\x31\xd2\x0f\x30");
		PVH_REF("\x48\x8d\x25", "__top_init_kernel_stack");
		PVH_BYTES("\x31\xed");
		if (!rap_entry_call(s, "xen_prepare_pvh"))
			goto bad;
		PVH_REF("\x48\x8d\x35", "pvh_bootparams");
		PVH_BYTES("\x48\x81\xee\0\0\0\x80");
		PVH_REF("\x48\x03\x35", "phys_base");
		PVH_REF("\x48\x8d\x05", "startup_64");
		PVH_BYTES("\x48\x2d\0\0\0\x80");
		PVH_REF("\x48\x03\x05", "phys_base");
		PVH_BYTES("\xff\xe0");
	}
	if (s->pos != func->len || !rap_hw_local_edges(&k))
		goto bad;
	rap_for_each_insn(file, func, insn)
		if (insn->alts)
			goto bad;
	func->rap_pvh_protocol = true;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s->pos, "RAP PVH lacks its exact physical/virtual boot protocol");
	return -1;
#undef PVH_BYTES
#undef PVH_RVA
#undef PVH_REF
#undef PVH_LABEL
#undef PVH_BRANCH
}

static struct symbol *rap_pvh_data(struct objtool_file *file, const char *name, unsigned long size)
{
	struct symbol *sym = find_symbol_by_name(file->elf, name);

	if (!sym || is_undef_sym(sym) || is_weak_sym(sym) || sym->len != size ||
	    (!sym->sec->init && strcmp(sym->sec->name, ".init.data") &&
	     strcmp(sym->sec->name, ".init.rodata")) || is_text_sec(sym->sec) ||
	    sym->offset > sec_size(sym->sec) || size > sec_size(sym->sec) - sym->offset)
		return NULL;
	return sym;
}

static bool rap_pvh_word(struct objtool_file *file, struct symbol *sym,
		unsigned long index, uint64_t expected, struct symbol *target)
{
	unsigned long off = sym->offset + index * 8;
	struct reloc *reloc = find_reloc_by_dest(file->elf, sym->sec, off);
	uint64_t value;

	memcpy(&value, sym->sec->data->d_buf + off, 8);
	if (find_reloc_by_dest_range(file->elf, sym->sec, off + 1, 7))
		return false;
	if (!target)
		return !reloc && value == expected;
	return !value && reloc && reloc_type(reloc) == R_X86_64_64 &&
		reloc->sym->sec == target->sec &&
		reloc->sym->offset + reloc_addend(reloc) == target->offset + expected;
}

static bool rap_pvh_notes(struct objtool_file *file, unsigned int large_count)
{
	struct symbol *entry = find_symbol_by_name(file->elf, "xen_elfnote_phys32_entry");
	struct symbol *value = find_symbol_by_name(file->elf, "xen_elfnote_phys32_entry_value");
	struct symbol *note = find_symbol_by_name(file->elf, "pvh_reloc_note");
	struct reloc *reloc;
	uint32_t fields[3];

	if (!entry || is_undef_sym(entry) || is_weak_sym(entry) || !value ||
	    !note || note->len != 12 || is_undef_sym(note) || is_weak_sym(note) ||
	    strcmp(entry->sec->name, ".note.Xen") || note->sec != entry->sec ||
	    entry->offset < 16 || note->offset < 16 ||
	    entry->offset + 8 > sec_size(entry->sec) || note->offset + 12 > sec_size(note->sec) ||
	    memcmp(entry->sec->data->d_buf + entry->offset - 16,
		   "\x04\0\0\0\x08\0\0\0\x12\0\0\0Xen\0", 16) ||
	    memcmp(note->sec->data->d_buf + note->offset - 16,
		   "\x04\0\0\0\x0c\0\0\0\x13\0\0\0Xen\0", 16) ||
	    memcmp(entry->sec->data->d_buf + entry->offset, (char[8]){}, 8) ||
	    find_reloc_by_dest_range(file->elf, entry->sec, entry->offset - 16, 16) ||
	    find_reloc_by_dest_range(file->elf, entry->sec, entry->offset + 1, 7) ||
	    find_reloc_by_dest_range(file->elf, note->sec, note->offset - 16, 28))
		return false;
	reloc = find_reloc_by_dest(file->elf, entry->sec, entry->offset);
	if (!reloc || reloc_type(reloc) != R_X86_64_PC64 || reloc->sym != value || reloc_addend(reloc))
		return false;
	memcpy(fields, note->sec->data->d_buf + note->offset, sizeof(fields));
	return fields[0] >= 0x200000 && !(fields[0] & (fields[0] - 1)) &&
		!(fields[1] & (fields[0] - 1)) && fields[1] <= fields[2] &&
		fields[2] == ((uint64_t)large_count << 21) - 1;
}

static int validate_rap_pvh_peers(struct objtool_file *file)
{
	static const char * const names[] = { "pvh_start_xen", "hdn_pvh_physical64", "hdn_pvh_virtual64" };
	static const char * const tables[] = { "pvh_init_top_pgt", "pvh_level3_ident_pgt",
		"pvh_level2_ident_pgt", "pvh_level3_kernel_pgt", "pvh_level2_kernel_pgt" };
	struct symbol *roots[3], *page[5], *gdt, *desc, *stack, *stack_end, *info, *size;
	struct section *mode32 = find_section_by_name(file->elf, ".init.text.hdn_pvh32");
	struct instruction *insn;
	unsigned int i, j, large_count = 0;
	uint32_t info_size;

	if (!mode32)
		return 0;
	for (i = 0; i < ARRAY_SIZE(roots); i++) {
		roots[i] = find_symbol_by_name(file->elf, names[i]);
		if (!roots[i] || roots[i]->rap_kind != 52 + i || !roots[i]->rap_pvh_protocol)
			goto bad;
	}
	if (roots[0]->sec != mode32 || roots[1]->sec == mode32 || roots[2]->sec == mode32)
		goto bad;
	gdt = rap_pvh_data(file, "pvh_gdt", 8);
	desc = rap_pvh_data(file, "pvh_gdt_start", 24);
	stack = rap_pvh_data(file, "pvh_early_stack", 0x4000);
	stack_end = find_symbol_by_name(file->elf, "pvh_early_stack_end");
	if (!gdt || !desc || desc->sec != gdt->sec || desc->offset != gdt->offset + 8 ||
	    !rap_pvh_word(file, gdt, 0, 0x80017, NULL) ||
	    !rap_pvh_word(file, desc, 0, 0, NULL) ||
	    !rap_pvh_word(file, desc, 1, 0x00af9b000000ffffULL, NULL) ||
	    !rap_pvh_word(file, desc, 2, 0x00cf93000000ffffULL, NULL) ||
	    !stack || !stack_end || stack_end->sec != stack->sec ||
	    stack_end->offset != stack->offset + stack->len || stack->offset % 16)
		goto bad;
	for (i = 0; i < ARRAY_SIZE(page); i++) {
		page[i] = rap_pvh_data(file, tables[i], 4096);
		if (!page[i] || page[i]->offset % 4096)
			goto bad;
	}
	for (i = 0; i < 512; i++) {
		if (!rap_pvh_word(file, page[0], i, (i == 0 || i == 273) ? 0x80000063ULL :
				 i == 511 ? 0x80000067ULL : 0,
				 (i == 0 || i == 273) ? page[1] : i == 511 ? page[3] : NULL) ||
		    !rap_pvh_word(file, page[1], i, i == 0 ? 0x80000063ULL : 0, i == 0 ? page[2] : NULL) ||
		    !rap_pvh_word(file, page[2], i, ((uint64_t)i << 21) | 0x1e3, NULL) ||
		    !rap_pvh_word(file, page[3], i, i == 510 ? 0x80000063ULL : 0, i == 510 ? page[4] : NULL))
			goto bad;
		if (rap_pvh_word(file, page[4], i, ((uint64_t)i << 21) | 0x1e3, NULL)) {
			if (large_count != i)
				goto bad;
			large_count++;
		} else if (!rap_pvh_word(file, page[4], i, 0, NULL)) {
			goto bad;
		}
	}
	if ((large_count != 256 && large_count != 512) || !rap_pvh_notes(file, large_count))
		goto bad;
	if (opts.link) {
		struct symbol *prepare = find_symbol_by_name(file->elf, "xen_prepare_pvh");
		struct symbol *startup = find_symbol_by_name(file->elf, "startup_64");
		struct symbol *base = find_symbol_by_name(file->elf, "phys_base");
		info = find_symbol_by_name(file->elf, "pvh_start_info");
		size = rap_pvh_data(file, "pvh_start_info_sz", 4);
		if (!prepare || prepare->rap_kind != 1 || !prepare->sec->init ||
		    !startup || startup->rap_kind != 48 || !startup->rap_startup_protocol ||
		    !base || base->len != 8 || strcmp(base->sec->name, ".data..ro_after_init") ||
		    !info || !rap_pvh_data(file, "pvh_start_info", info->len) || !size ||
		    !rap_pvh_data(file, "pvh_bootparams", 4096) ||
		    find_reloc_by_dest_range(file->elf, size->sec, size->offset, 4))
			goto bad;
		memcpy(&info_size, size->sec->data->d_buf + size->offset, 4);
		if (!info_size || info_size % 4 || info_size != info->len)
			goto bad;
	}
	for_each_insn(file, insn) {
		struct symbol *owner = rap_entry_owner(insn);
		struct section *sec;
		unsigned long offset;
		if (!rap_thunk_edge_target(file, insn, &sec, &offset))
			continue;
		for (j = 0; j < ARRAY_SIZE(roots); j++)
			if (sec == roots[j]->sec && offset >= roots[j]->offset &&
			    offset < roots[j]->offset + roots[j]->len && owner != roots[j])
				goto bad;
	}
	return 0;
bad:
	ERROR("RAP PVH has invalid boot tables, stack, peer roots or an unauthorized incoming transfer");
	return -1;
}
