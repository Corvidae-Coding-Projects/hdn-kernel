/* SPDX-License-Identifier: GPL-2.0-only */
/* Included by check.c after the exact RAP instruction-sequence helpers.
 * These are independent protocol descriptions, not copied ELF templates.
 * Every byte, local edge, symbol operand and alternative is accounted for. */
static bool rap_kexec_terminal_name(const char *name)
{
	static const char * const names[] = {
		"relocate_kernel", "identity_mapped", "virtual_mapped", "swap_pages",
		"pr_char_8250", "pr_char_8250_mmio32", "pr_nybble", "pr_qword",
		"kexec_debug_exc_vectors", "exc_handler",
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(names); i++)
		if (!strcmp(name, names[i]))
			return true;
	return false;
}

struct rap_kexec_sequence {
	struct rap_sequence seq;
	unsigned long labels[16];
	bool defined[16];
	struct {
		struct instruction *insn;
		unsigned int label;
	} branches[32];
	unsigned int count;
	struct instruction *alternative;
};

static bool rap_kexec_label(struct rap_kexec_sequence *k, unsigned int label)
{
	if (label >= ARRAY_SIZE(k->labels) || k->defined[label])
		return false;
	k->defined[label] = true;
	k->labels[label] = k->seq.func->offset + k->seq.pos;
	return true;
}

/* Accept only short/near encodings of the specified condition, with no
 * relocation. The destination must equal a described instruction boundary. */
static bool rap_kexec_branch(struct rap_kexec_sequence *k, unsigned char op,
			     unsigned int label)
{
	struct rap_sequence *s = &k->seq;
	unsigned long offset = s->func->offset + s->pos;
	struct instruction *insn = find_insn(s->file, s->func->sec, offset);
	const unsigned char *p = s->func->sec->data->d_buf + offset;

	if (k->count == ARRAY_SIZE(k->branches) || label >= ARRAY_SIZE(k->labels) ||
	    !insn || s->pos >= s->func->len || insn->len > s->func->len - s->pos ||
	    !((insn->len == 2 && p[0] == op) ||
	      (op == 0xeb && insn->len == 5 && p[0] == 0xe9) ||
	      (op >= 0x70 && op <= 0x7f && insn->len == 6 &&
	       p[0] == 0x0f && p[1] == op + 0x10)) ||
	    find_reloc_by_dest_range(s->file->elf, s->func->sec, offset, insn->len))
		return false;
	k->branches[k->count].insn = insn;
	k->branches[k->count++].label = label;
	s->pos += insn->len;
	return true;
}

static bool rap_kexec_mce(struct rap_kexec_sequence *k)
{
	struct rap_sequence *s = &k->seq;
	struct instruction *insn = find_insn(s->file, s->func->sec, s->func->offset + s->pos);
	struct alternative *alt;
	struct alt_group *group;
	const char *feature;
	const char *original = s->func->sec->data->d_buf + s->func->offset + s->pos;

	if (!insn || !insn->alt_group || insn->alt_group->orig_group ||
	    insn->alt_group->first_insn != insn ||
	    insn->alt_group->last_insn->offset + insn->alt_group->last_insn->len != insn->offset + 4 ||
	    !(alt = insn->alts) || alt->next || alt->type != ALT_TYPE_INSTRUCTIONS ||
	    !(group = alt->insn->alt_group) || group->orig_group != insn->alt_group ||
	    group->first_insn != alt->insn || group->last_insn != alt->insn || group->nop ||
	    !(feature = arch_cpu_feature_name(group->feature)) || strcmp(feature, "X86_FEATURE_TDX_GUEST") ||
	    alt->insn->len != 4 ||
	    memcmp(alt->insn->sec->data->d_buf + alt->insn->offset, "\x41\x83\xcd\x40", 4) ||
	    find_reloc_by_dest_range(s->file->elf, alt->insn->sec, alt->insn->offset, 4) ||
	    (memcmp(original, "\x90\x90\x90\x90", 4) && memcmp(original, "\x0f\x1f\x40\x00", 4)) ||
	    !rap_sequence_bytes(s, original, 4))
		return false;
	k->alternative = insn;
	return true;
}

static int verify_rap_kexec(struct objtool_file *file, struct symbol *func)
{
	struct rap_kexec_sequence k = { .seq = { .file = file, .func = func } };
	struct rap_sequence *s = &k.seq;
	struct instruction *insn, *first = find_insn(file, func->sec, func->offset);
	unsigned int i;
	bool terminal = func->rap_kind == 11;

#define K_BYTES(bytes) do { if (!rap_sequence_bytes(s, bytes, sizeof(bytes) - 1)) goto bad; } while (0)
#define K_REF(bytes, name, relative) do { \
	if (!rap_sequence_reference(s, bytes, sizeof(bytes) - 1, name, relative)) goto bad; \
} while (0)
#define K_EDGE(name, call, bound) do { \
	if (!rap_sequence_edge_match(s, name, call, bound)) goto bad; \
} while (0)
#define K_LABEL(n) do { if (!rap_kexec_label(&k, n)) goto bad; } while (0)
#define K_BRANCH(op, n) do { if (!rap_kexec_branch(&k, op, n)) goto bad; } while (0)

	if (is_weak_sym(func) ||
	    (terminal ? !rap_kexec_terminal_name(func->name) :
	     strcmp(func->name, func->rap_kind == 10 ? "hdn_rap_kexec" : "hdn_rap_kexec_return")))
		goto bad;
	if (!terminal && first && first->type == INSN_ENDBR)
		K_BYTES("\xf3\x0f\x1e\xfa");
	if (func->rap_kind == 10) {
		K_BYTES("\x4c\x8d\x1d\x05\0\0\0");
		K_EDGE("__hdn_rap_enter", true, false);
		K_BYTES("\x53\x55\x41\x54\x41\x55\x41\x56\x41\x57\x48\x89\xe6"
			"\x4c\x8d\x15\x05\0\0\0");
		K_EDGE("hdn_rap_kexec_enter", true, true);
		K_BYTES("\x49\x89\xc3\x49\x8b\x3b\x49\x8b\x73\x08\x49\x8b\x53\x10"
			"\x49\x8b\x4b\x18\x4d\x8b\x43\x28\x4d\x8b\x5b\x20"
			"\xb8\x18\0\0\0\x8e\xd8\x8e\xc0\x8e\xd0\x8e\xe0\x8e\xe8\x41\xff\xe3");
	} else if (func->rap_kind == 12) {
		K_REF("\x48\xc7\xc6", "hdn_rap_kexec_state", false);
		K_BYTES("\x48\x8b\x46\x18\x48\x89\xc2\x48\xc1\xea\x20\xb9\x01\x01\x00\xc0"
			"\x0f\x30\x48\x8b\x66\x20\x0f\x01\x56\x60\x0f\x01\x5e\x6a"
			"\x55\x48\x89\xef\x4c\x8d\x15\x05\0\0\0");
		K_EDGE("hdn_rap_kexec_finish", true, true);
		K_BYTES("\x58");
		K_REF("\x48\xc7\xc2", "hdn_rap_kexec_state", false);
		K_BYTES("\x4c\x8b\x7a\x30\x4c\x8b\x72\x38\x4c\x8b\x6a\x40\x4c\x8b\x62\x48"
			"\x48\x8b\x6a\x50\x48\x8b\x5a\x58\xff\x72\x28\x9d");
		K_EDGE("__hdn_rap_return", false, false);
	} else if (!strcmp(func->name, "relocate_kernel")) {
		K_BYTES("\x53\x55\x41\x54\x41\x55\x41\x56\x41\x57\x9c\x6a\0\x6a\0"
			"\x0f\x01\x1c\x24\x0f\x01\x14\x24\x48\x83\xc4\x08\x9d"
			"\x0f\x20\xd8\x4d\x89\xc1\x41\x0f\x22\xd9\x41\x0f\x20\xe5"
			"\x4d\x89\xec\x49\x81\xe4\x7f\xff\xff\xf7\x41\x0f\x22\xe4");
		K_REF("\x4c\x89\x2d", "saved_cr4", true);
		K_REF("\x48\x89\x25", "saved_rsp", true);
		K_REF("\x48\x89\x05", "saved_cr3", true);
		K_BYTES("\x0f\x20\xc0");
		K_REF("\x48\x89\x05", "saved_cr0", true);
		K_REF("\x48\x89\x3d", "pa_backup_pages_map", true);
		K_BYTES("\x49\x89\xcb\x48\x8d\xa6\0\x10\0\0");
		K_REF("\x48\x8d\x05", "identity_mapped", true);
		K_REF("\x48\x2b\x05", "kexec_va_control_page", true);
		K_BYTES("\x48\x01\xc6\xff\xe6");
	} else if (!strcmp(func->name, "identity_mapped")) {
		K_BYTES("\x6a\0\x52");
		K_REF("\x48\x8d\x05", "kexec_debug_gdt", true);
		K_BYTES("\x50\x66\xff\x30\x0f\x01\x14\x24\x48\x83\xc4\x0a\x8c\xd8\x8e\xd8");
		K_REF("\x48\x8d\x35", "kexec_debug_idt", true);
		K_BYTES("\x56\x66\x68\xff\0\x0f\x01\x1c\x24\x48\x83\xc4\x0a"
			"\x0f\x20\xe0\x48\x25\xff\xff\x7f\xff\x0f\x22\xe0"
			"\x0f\x20\xc0\x48\x25\xf3\xff\xfa\xff\x0d\x01\0\0\x80\x0f\x22\xc0"
			"\x41\x81\xe5\x20\x10\0\0");
		if (!rap_kexec_mce(&k))
			goto bad;
		K_BYTES("\x41\x0f\x22\xe5\x41\x0f\x22\xd9\x41\xf6\xc3\x02");
		K_BRANCH(0x74, 0);
		K_BYTES("\x0f\x09");
		K_LABEL(0);
		K_EDGE("swap_pages", true, false);
		K_BYTES("\x0f\x20\xd8\x0f\x22\xd8\x41\xf6\xc3\x01");
		K_BRANCH(0x75, 1);
		K_BYTES("\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x31\xf6\x31\xff\x31\xed"
			"\x45\x31\xc0\x45\x31\xc9\x45\x31\xd2\x45\x31\xdb"
			"\x45\x31\xe4\x45\x31\xed\x45\x31\xf6\x45\x31\xff\xc3\xcc");
		K_LABEL(1);
		K_BYTES("\x5a");
		K_REF("\x4c\x8b\x15", "kexec_pa_swap_page", true);
		K_BYTES("\x49\x8d\xa2\0\x10\0\0\x52\xff\xd2\x5d");
		K_REF("\x4c\x8b\x15", "kexec_pa_swap_page", true);
		K_REF("\x48\x8b\x3d", "pa_backup_pages_map", true);
		K_REF("\x48\x8b\x05", "kexec_pa_table_page", true);
		K_BYTES("\x0f\x22\xd8\x4c\x8d\x05\0\0\0\0\x49\x81\xe0\0\xf0\xff\xff"
			"\x49\x8d\xa0\0\x10\0\0\x41\xbb\x01\0\0\0");
		K_EDGE("swap_pages", true, false);
		K_REF("\x48\x8d\x05", "virtual_mapped", true);
		K_BYTES("\x4c\x29\xc0");
		K_REF("\x48\x03\x05", "kexec_va_control_page", true);
		K_BYTES("\x50\xc3\xcc");
	} else if (!strcmp(func->name, "virtual_mapped")) {
		K_REF("\x48\x8b\x35", "kexec_pa_rap_state", true);
		K_BYTES("\x48\x8b\x46\x10\x0f\x22\xe0\x48\x8b\x46\x08\x4c\x8b\x06"
			"\x0f\x22\xd8\x41\x0f\x22\xc0");
		K_REF("\x48\xc7\xc0", "hdn_rap_kexec_return", false);
		K_BYTES("\xff\xe0");
	} else if (!strcmp(func->name, "swap_pages")) {
		K_BYTES("\x48\x89\xf9\x31\xff\x31\xf6");
		K_BRANCH(0xeb, 1);
		K_LABEL(0);
		K_BYTES("\x48\x8b\x0b\x48\x83\xc3\x08");
		K_LABEL(1);
		K_BYTES("\xf6\xc1\x01");
		K_BRANCH(0x74, 2);
		K_BYTES("\x48\x89\xcf\x48\x81\xe7\0\xf0\xff\xff");
		K_BRANCH(0xeb, 0);
		K_LABEL(2);
		K_BYTES("\xf6\xc1\x02");
		K_BRANCH(0x74, 3);
		K_BYTES("\x48\x89\xcb\x48\x81\xe3\0\xf0\xff\xff");
		K_BRANCH(0xeb, 0);
		K_LABEL(3);
		K_BYTES("\xf6\xc1\x04");
		K_BRANCH(0x74, 4);
		K_BRANCH(0xeb, 6);
		K_LABEL(4);
		K_BYTES("\xf6\xc1\x08");
		K_BRANCH(0x74, 0);
		K_BYTES("\x48\x89\xce\x48\x81\xe6\0\xf0\xff\xff\x48\x89\xfa\x48\x89\xf0"
			"\x41\xf6\xc3\x01");
		K_BRANCH(0x74, 5);
		K_REF("\x48\x8b\x3d", "kexec_pa_swap_page", true);
		K_BYTES("\xb9\0\x02\0\0\xf3\x48\xa5\x48\x89\xc7\x48\x89\xd6"
			"\xb9\0\x02\0\0\xf3\x48\xa5\x48\x89\xd7");
		K_REF("\x48\x8b\x35", "kexec_pa_swap_page", true);
		K_LABEL(5);
		K_BYTES("\xb9\0\x02\0\0\xf3\x48\xa5\x48\x8d\xb0\0\x10\0\0");
		K_BRANCH(0xeb, 0);
		K_LABEL(6);
		K_BYTES("\xc3\xcc");
	} else if (!strcmp(func->name, "pr_char_8250")) {
		K_BYTES("\x66\x83\xc2\x05\x86\xc4");
		K_LABEL(0);
		K_BYTES("\xec\xa8\x20");
		K_BRANCH(0x75, 1);
		K_BYTES("\xf3\x90");
		K_BRANCH(0xeb, 0);
		K_LABEL(1);
		K_BYTES("\x66\x83\xea\x05\x86\xc4\xee");
		{
			struct symbol *null = find_symbol_by_name(file->elf, "pr_char_null");
			if (!null || null->sec != func->sec || null->offset != func->offset + s->pos)
				goto bad;
		}
		K_BYTES("\xc3");
	} else if (!strcmp(func->name, "pr_char_8250_mmio32")) {
		K_LABEL(0);
		K_BYTES("\x8a\x62\x14\xf6\xc4\x20");
		K_BRANCH(0x75, 1);
		K_BYTES("\xf3\x90");
		K_BRANCH(0xeb, 0);
		K_LABEL(1);
		K_BYTES("\x88\x02\xc3");
	} else if (!strcmp(func->name, "pr_nybble")) {
		K_BYTES("\x88\xd8\x90\x24\x0f\x04\x30\x3c\x3a");
		K_BRANCH(0x72, 0);
		K_BYTES("\x04\x27");
		K_LABEL(0);
		K_BYTES("\xff\xe6");
	} else if (!strcmp(func->name, "pr_qword")) {
		K_BYTES("\x48\xc7\xc1\x10\0\0\0");
		K_LABEL(0);
		K_BYTES("\x48\xc1\xc3\x04");
		K_EDGE("pr_nybble", true, false);
		K_BRANCH(0xe2, 0);
		K_BYTES("\xb0\x0a\xff\xe6");
	} else if (!strcmp(func->name, "kexec_debug_exc_vectors")) {
		for (i = 0; i < 16; i++) {
			char number[] = { 0x6a, i };

			if (i == 8 || (i >= 10 && i <= 14))
				K_BYTES("\x90\x90");
			else
				K_BYTES("\x6a\0");
			if (!rap_sequence_bytes(s, number, sizeof(number)))
				goto bad;
			K_EDGE("exc_handler", false, false);
			if (s->pos != (i + 1) * 6)
				goto bad;
		}
	} else if (!strcmp(func->name, "exc_handler")) {
		/* Keep room for the terminator even though the matcher emits four bytes. */
		static const char names[][5] = {
			"Exc:", "Err:", "rip:", "rsp:", "rax:", "rbx:", "rcx:", "rdx:", "rsi:",
			"rdi:", "r8 :", "r9 :", "r10:", "r11:", "r12:", "r13:", "r14:", "r15:", "cr2:",
		};
		static const unsigned char slots[] = { 0x28, 0x30, 0x38, 0x50, 0x20, 0x18, 0x10, 0x08 };

		K_BYTES("\x50\x53\x51\x52\x56");
		K_REF("\x48\x8d\x35", "pr_char_8250", true);
		K_REF("\x66\x8b\x15", "kexec_debug_8250_port", true);
		K_BYTES("\x66\x85\xd2");
		K_BRANCH(0x75, 0);
		K_REF("\x48\x8d\x35", "pr_char_8250_mmio32", true);
		K_REF("\x48\x8b\x15", "kexec_debug_8250_mmio32", true);
		K_BYTES("\x48\x85\xd2");
		K_BRANCH(0x75, 0);
		K_REF("\x48\x8d\x35", "pr_char_null", true);
		K_LABEL(0);
		for (i = 0; i < ARRAY_SIZE(names); i++) {
			unsigned int j;
			for (j = 0; j < 4; j++) {
				char print[] = { 0xb0, names[i][j], 0xff, 0xd6 };
				if (!rap_sequence_bytes(s, print, sizeof(print)))
					goto bad;
			}
			if (i < ARRAY_SIZE(slots)) {
				char load[] = { 0x48, 0x8b, 0x5c, 0x24, slots[i] };
				if (!rap_sequence_bytes(s, load, sizeof(load)))
					goto bad;
			} else if (i == 8) {
				K_BYTES("\x48\x8b\x1c\x24");
			} else if (i == 9) {
				K_BYTES("\x48\x89\xfb");
			} else if (i < 18) {
				char move[] = { 0x4c, 0x89, 0xc3 + (i - 10) * 8 };
				if (!rap_sequence_bytes(s, move, sizeof(move)))
					goto bad;
			} else {
				K_BYTES("\x0f\x20\xd3");
			}
			K_EDGE("pr_qword", true, false);
		}
		K_BYTES("\x48\x83\x7c\x24\x28\x03");
		K_BRANCH(0x75, 1);
		K_BYTES("\x5e\x5a\x59\x5b\x58\x48\x83\xc4\x10\x48\xcf");
		K_LABEL(1);
		K_BYTES("\xf4");
		K_BRANCH(0xeb, 1);
	} else {
		goto bad;
	}
	if (s->pos != func->len)
		goto bad;
	for (i = 0; i < k.count; i++)
		if (!k.defined[k.branches[i].label] ||
		    arch_jump_destination(k.branches[i].insn) != k.labels[k.branches[i].label])
			goto bad;
	rap_for_each_insn(file, func, insn)
		if (insn->alts && insn != k.alternative)
			goto bad;
	/* None of these protocols admits an outside branch to an interior byte. */
	for_each_insn(file, insn)
		if (rap_insn_owner(insn) != func && insn->jump_dest &&
		    insn->jump_dest->sec == func->sec && insn->jump_dest->offset > func->offset &&
		    insn->jump_dest->offset < func->offset + func->len)
			goto bad;
	if (terminal && opts.link) {
		struct symbol *start = find_symbol_by_name(file->elf, "__relocate_kernel_start");
		struct symbol *end = find_symbol_by_name(file->elf, "__relocate_kernel_end");

		if (strcmp(func->sec->name, ".text..relocate_kernel") ||
		    sec_size(func->sec) > 2048 || func->offset > sec_size(func->sec) ||
		    func->len > sec_size(func->sec) - func->offset || !start || !end ||
		    is_weak_sym(start) || is_weak_sym(end) ||
		    (is_undef_sym(start) != is_undef_sym(end)))
			goto bad;
		if (!is_undef_sym(start) &&
		    (start->sec != func->sec || end->sec != func->sec ||
		     start->offset > func->offset || end->offset < func->offset + func->len ||
		     end->offset < start->offset || end->offset - start->offset > 2048))
			goto bad;
	} else if (terminal && strcmp(func->sec->name, ".text..relocate_kernel")) {
		goto bad;
	}
	func->rap_kexec_protocol = true;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s->pos, "RAP kexec does not match its closed handoff/return protocol");
	return -1;
#undef K_BRANCH
#undef K_LABEL
#undef K_EDGE
#undef K_REF
#undef K_BYTES
}
