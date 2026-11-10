/* SPDX-License-Identifier: GPL-2.0-only */
/* Exact native entry-macro descriptions, shared by the IRQ/NMI/syscall roots. */
static bool rap_hw_local_edges(struct rap_kexec_sequence *k)
{
	unsigned int i;

	for (i = 0; i < k->count; i++) {
		struct section *sec;
		unsigned long offset;
		if (!k->defined[k->branches[i].label] ||
		    !rap_thunk_edge_target(k->seq.file, k->branches[i].insn, &sec, &offset) ||
		    sec != k->seq.func->sec || offset != k->labels[k->branches[i].label])
			return false;
	}
	return true;
}

static bool rap_hw_alt_is(struct rap_sequence *s, const char *feature)
{
	struct instruction *first = find_insn(s->file, s->func->sec, s->func->offset + s->pos);
	struct alternative *alt;

	for (alt = first ? first->alts : NULL; alt; alt = alt->next) {
		struct alt_group *g = alt->insn->alt_group;
		const char *name = g ? arch_cpu_feature_name(g->feature & 0xffff) : NULL;

		if (name && !strcmp(name, feature))
			return true;
	}
	return false;
}

/* ALTERNATIVE "jmp local_label", "", feature. The empty replacement is
 * represented by objtool's synthetic NOP, not bytes in the input object. */
static bool rap_hw_skip(struct rap_kexec_sequence *k, const char *feature, unsigned int label)
{
	struct rap_sequence *s = &k->seq;
	struct instruction *first = find_insn(s->file, s->func->sec, s->func->offset + s->pos);
	struct alt_group *orig = first ? first->alt_group : NULL, *g;
	struct alternative *alt;
	unsigned long end;
	const char *name;

	if (!orig || orig->orig_group || orig->first_insn != first || !orig->last_insn ||
	    !(alt = first->alts) || alt->next || alt->type != ALT_TYPE_INSTRUCTIONS ||
	    !(g = alt->insn->alt_group) || g->orig_group != orig ||
	    g->first_insn != alt->insn || g->last_insn || g->nop != alt->insn || !g->nop->fake ||
	    g->feature >> 16 || !(name = arch_cpu_feature_name(g->feature)) || strcmp(name, feature))
		return false;
	end = orig->last_insn->offset + orig->last_insn->len - s->func->offset;
	if (end > s->func->len || end <= s->pos || g->nop->len != end - s->pos ||
	    !rap_kexec_branch(k, 0xeb, label) || !rap_thunk_padding(s, end, false))
		return false;
	first->rap_hw_alt = true;
	return true;
}

static bool rap_hw_untrain_alts(struct rap_sequence *s, bool leaves, bool from_call)
{
	struct instruction *first = find_insn(s->file, s->func->sec, s->func->offset + s->pos);
	struct alt_group *orig = first ? first->alt_group : NULL;
	struct alternative *alt;
	unsigned long end;
	unsigned int seen = 0;

	if (!orig || orig->orig_group || orig->first_insn != first || !orig->last_insn)
		return false;
	end = orig->last_insn->offset + orig->last_insn->len - s->func->offset;
	if (end > s->func->len || end <= s->pos)
		return false;
	for (alt = first->alts; alt; alt = alt->next) {
		struct alt_group *g = alt->insn->alt_group;
		struct symbol span = *s->func;
		struct rap_sequence body = { .file = s->file, .func = &span };
		const char *feature;
		unsigned int bit;

		if (alt->type != ALT_TYPE_INSTRUCTIONS || !g || g->orig_group != orig ||
		    g->first_insn != alt->insn || g->feature >> 16 ||
		    !(feature = arch_cpu_feature_name(g->feature)))
			return false;
		span.sec = alt->insn->sec;
		span.offset = alt->insn->offset;
		span.len = g->last_insn ? g->last_insn->offset + g->last_insn->len - span.offset : 0;
		if (span.len > end - s->pos || (!span.len && (g->nop != alt->insn || !g->nop->fake)))
			return false;
		if (leaves) {
			if (!strcmp(feature, "X86_FEATURE_UNRET")) {
				bit = 1;
				if (!rap_sequence_edge_match(&body, "entry_untrain_ret", true, false)) return false;
			} else if (!strcmp(feature, "X86_FEATURE_SRSO_ALIAS")) {
				bit = 2;
				if (!rap_sequence_edge_match(&body, "srso_alias_untrain_ret", true, false)) return false;
			} else return false;
		} else if (!strcmp(feature, "X86_FEATURE_ENTRY_IBPB")) {
			bit = 1;
			if (!rap_sequence_edge_match(&body, "write_ibpb", true, false)) return false;
		} else if (!strcmp(feature, "X86_FEATURE_CALL_DEPTH")) {
			bit = 2;
			if (find_symbol_by_name(s->file->elf, "__x86_call_depth")) {
				if (!rap_sequence_bytes(&body, from_call ? "\xb0\xfc\x48\xc1\xe0\x38" :
						"\x31\xc0\x48\x0f\xba\xe8\x3f", from_call ? 6 : 7) ||
				    !rap_thunk_percpu(&body, "\x48\x89\x05", 3, "", 0, "__x86_call_depth") ||
				    (from_call && !rap_thunk_debug(&body, "__x86_call_count")))
					return false;
			}
		} else return false;
		if ((seen & bit) || body.pos != span.len)
			return false;
		seen |= bit;
		rap_hw_mark(s->file, &span);
	}
	if (seen != 3 || !rap_thunk_padding(s, end, false))
		return false;
	first->rap_hw_alt = true;
	return true;
}

static bool rap_hw_untrain(struct rap_sequence *s, bool from_call)
{
	struct instruction *first = find_insn(s->file, s->func->sec, s->func->offset + s->pos);

	if (first && !first->alts)
		rap_sequence_bytes(s, "\x90", 1); /* VALIDATE_UNRET_END */
	if (rap_hw_alt_is(s, "X86_FEATURE_UNRET") && !rap_hw_untrain_alts(s, true, from_call))
		return false;
	if (rap_hw_alt_is(s, "X86_FEATURE_ENTRY_IBPB") && !rap_hw_untrain_alts(s, false, from_call))
		return false;
	return true;
}

static bool rap_hw_saferet_reference(struct rap_sequence *s, const char *name,
		unsigned long member)
{
	static const char opcode[] = "\x48\x81\xbc\x24\x88\0\0\0";
	struct symbol *target = find_symbol_by_name(s->file->elf, name);
	unsigned long offset = s->func->offset + s->pos;
	struct instruction *insn = find_insn(s->file, s->func->sec, offset);
	struct reloc *reloc;

	if (!target || is_weak_sym(target) || !insn || insn->len != 12 ||
	    s->pos > s->func->len || insn->len > s->func->len - s->pos ||
	    memcmp(s->func->sec->data->d_buf + offset, opcode, sizeof(opcode) - 1))
		return false;
	reloc = find_reloc_by_dest(s->file->elf, s->func->sec, offset + sizeof(opcode) - 1);
	if (!reloc || arch_reloc_size(reloc) != 4 || reloc_type(reloc) != R_X86_64_32S ||
	    reloc->sym->sec != target->sec ||
	    reloc->sym->offset + reloc_addend(reloc) != target->offset + member ||
	    find_reloc_by_dest_range(s->file->elf, s->func->sec, offset, sizeof(opcode) - 1) ||
	    find_reloc_by_dest_range(s->file->elf, s->func->sec, offset + sizeof(opcode), 3))
		return false;
	s->pos += insn->len;
	return true;
}

static bool rap_hw_saferet_branch(struct rap_sequence *s, unsigned char opcode)
{
	unsigned long offset = s->func->offset + s->pos;
	struct instruction *insn = find_insn(s->file, s->func->sec, offset);
	const char *bytes = s->func->sec->data->d_buf + offset;
	unsigned long delta;

	if (!insn)
		return false;
	if (insn->len != 2 || insn->type != INSN_JUMP_CONDITIONAL ||
	    (unsigned char)bytes[0] != opcode || s->pos + insn->len > s->func->len)
		return false;
	delta = s->func->len - s->pos - insn->len;
	if (delta > 0x7f || (unsigned char)bytes[1] != delta)
		return false;
	return rap_sequence_bytes(s, bytes, insn->len);
}

/* HANDLE_INTR_SAFERET is an empty original alternative with two complete SRSO
 * replacements. Match both speculative-safe return ranges, their common exit,
 * the fence and the sole reviewed handler call before accepting its padding. */
static bool rap_hw_saferet(struct rap_sequence *s)
{
	struct instruction *first = find_insn(s->file, s->func->sec,
			s->func->offset + s->pos);
	struct alt_group *orig = first ? first->alt_group : NULL;
	struct alternative *alt;
	unsigned long end;
	unsigned int seen = 0;

	if (!rap_hw_alt_is(s, "X86_FEATURE_SRSO") &&
	    !rap_hw_alt_is(s, "X86_FEATURE_SRSO_ALIAS"))
		return true;
	if (!orig || orig->orig_group || orig->first_insn != first || !orig->last_insn)
		return false;
	end = orig->last_insn->offset + orig->last_insn->len - s->func->offset;
	if (end <= s->pos || end > s->func->len)
		return false;
	for (alt = first->alts; alt; alt = alt->next) {
		struct alt_group *g = alt->insn->alt_group;
		struct symbol span = *s->func;
		struct rap_sequence body = { .file = s->file, .func = &span };
		const char *feature, *target;
		unsigned int bit;

		if (alt->type != ALT_TYPE_INSTRUCTIONS || !g || g->orig_group != orig ||
		    g->first_insn != alt->insn || !g->last_insn || g->feature >> 16 ||
		    !(feature = arch_cpu_feature_name(g->feature)))
			return false;
		if (!strcmp(feature, "X86_FEATURE_SRSO")) {
			bit = 1;
			target = "srso_safe_ret";
		} else if (!strcmp(feature, "X86_FEATURE_SRSO_ALIAS")) {
			bit = 2;
			target = "srso_alias_safe_ret";
		} else {
			return false;
		}
		span.sec = alt->insn->sec;
		span.offset = alt->insn->offset;
		span.len = g->last_insn->offset + g->last_insn->len - span.offset;
		if ((seen & bit) || span.len > end - s->pos)
			return false;
		if (!rap_hw_saferet_reference(&body, target, 0))
			return false;
		if (!rap_hw_saferet_branch(&body, 0x72))
			return false;
		if (!rap_hw_saferet_reference(&body, target, 5))
			return false;
		if (!rap_hw_saferet_branch(&body, 0x77))
			return false;
		if (!rap_sequence_bytes(&body, "\x0f\xae\xe8\x48\x8d\x7c\x24\x08", 8))
			return false;
		if (!rap_sequence_edge_match(&body, "handle_interrupted_saferet", true, false))
			return false;
		if (body.pos != span.len)
			return false;
		seen |= bit;
		rap_hw_mark(s->file, &span);
	}
	if (seen != 3 || !rap_thunk_padding(s, end, false))
		return false;
	first->rap_hw_alt = true;
	return true;
}

static bool rap_hw_ibrs(struct rap_sequence *s, bool enter, bool save)
{
	struct rap_kexec_sequence k = { .seq = *s };
	struct rap_sequence *p = &k.seq;

	if (!rap_hw_alt_is(s, "X86_FEATURE_KERNEL_IBRS"))
		return true;
	if (!rap_hw_skip(&k, "X86_FEATURE_KERNEL_IBRS", 0) ||
	    !rap_sequence_bytes(p, "\xb9\x48\0\0\0", 5))
		return false;
	if (enter && save) {
		if (!rap_sequence_bytes(p, "\x0f\x32\x48\xc1\xe2\x20\x48\x09\xd0\x49\x89\xc7"
					  "\xa9\x01\0\0\0", 17) ||
		    !rap_kexec_branch(&k, 0x74, 1) || !rap_sequence_bytes(p, "\x0f\xae\xe8", 3) ||
		    !rap_kexec_branch(&k, 0xeb, 0) || !rap_kexec_label(&k, 1))
			return false;
	}
	if (!enter && save) {
		if (!rap_sequence_bytes(p, "\x4c\x89\xfa", 3))
			return false;
	} else {
		if (!rap_thunk_percpu(p, "\x48\x8b\x15", 3, "", 0, "x86_spec_ctrl_current") ||
		    (!enter && !rap_sequence_bytes(p, "\x83\xe2\xfe", 3)))
			return false;
	}
	if (!rap_sequence_bytes(p, "\x89\xd0\x48\xc1\xea\x20\x0f\x30", 8) ||
	    !rap_kexec_label(&k, 0) || !rap_hw_local_edges(&k))
		return false;
	*s = *p;
	return true;
}

static bool rap_hw_save_regs(struct rap_sequence *s)
{
	/* PUSH_AND_CLEAR_REGS save_ret=1; the sole return slot remains on top. */
	return rap_sequence_bytes(s, "\x56\x48\x8b\x74\x24\x08\x48\x89\x7c\x24\x08"
		"\x52\x51\x50\x41\x50\x41\x51\x41\x52\x41\x53\x53\x55\x41\x54"
		"\x41\x55\x41\x56\x41\x57\x56", 33) &&
		rap_sequence_bytes(s,
		"\x31\xf6\x31\xd2\x31\xc9\x45\x31\xc0\x45\x31\xc9\x45\x31\xd2"
		"\x45\x31\xdb\x31\xdb\x31\xed\x45\x31\xe4\x45\x31\xed"
		"\x45\x31\xf6\x45\x31\xff", 34);
}

/* RAX-only form used by the IDT preamble, optionally preserving CR3 in R14. */
static bool rap_hw_kernel_cr3(struct rap_sequence *s, bool save)
{
	struct rap_kexec_sequence k = { .seq = *s };
	struct rap_sequence *p = &k.seq;

	if (save && !rap_sequence_bytes(p, "\x41\x0f\x20\xde", 4))
		return false;
	if (!rap_hw_alt_is(p, "X86_FEATURE_PTI")) {
		*s = *p;
		return true;
	}
	if (!rap_hw_skip(&k, "X86_FEATURE_PTI", 0) || !rap_sequence_bytes(p, "\x0f\x20\xd8", 3))
		return false;
	if (save && (!rap_sequence_bytes(p, "\x49\x89\xc6\x48\x0f\xba\xe0\x0c", 8) ||
		     !rap_kexec_branch(&k, 0x73, 0)))
		return false;
	if (!rap_hw_fixed_alt(p, "X86_FEATURE_PCID", "\x48\x0f\xba\xe8\x3f", 5) ||
	    !rap_sequence_bytes(p, "\x48\x25\xff\xe7\xff\xff\x0f\x22\xd8", 9) ||
	    !rap_kexec_label(&k, 0) || !rap_hw_local_edges(&k))
		return false;
	*s = *p;
	return true;
}

static bool rap_hw_depth(struct rap_sequence *s)
{
	return !rap_hw_alt_is(s, "X86_FEATURE_CALL_DEPTH") ||
		rap_thunk_alternative(s, RAP_ALT_DEPTH, 0);
}

static bool rap_hw_restore_cr3(struct rap_sequence *s, bool scratch_r15)
{
	struct rap_kexec_sequence k = { .seq = *s };
	struct rap_sequence *p = &k.seq;

	if (rap_sequence_bytes(p, "\x41\x0f\x22\xde", 4)) {
		if (opts.link && !find_symbol_by_name(s->file->elf, "hdn_stack_mm_ready"))
			return false;
		*s = *p;
		return true;
	}
	if (opts.link && find_symbol_by_name(s->file->elf, "hdn_stack_mm_ready"))
		return false;
	if (!rap_hw_alt_is(p, "X86_FEATURE_PTI"))
		return true;
	if (!rap_hw_skip(&k, "X86_FEATURE_PTI", 0) ||
	    !rap_sequence_bytes(p, "\x49\x0f\xba\xe6\x0c", 5) ||
	    !rap_kexec_branch(&k, 0x73, 0) || !rap_hw_skip(&k, "X86_FEATURE_PCID", 1) ||
	    !rap_sequence_bytes(p, scratch_r15 ? "\x4d\x89\xf7\x49\x81\xe7\xff\x07\0\0" :
					       "\x4c\x89\xf0\x48\x25\xff\x07\0\0", scratch_r15 ? 10 : 9) ||
	    !rap_thunk_percpu_offset(p, scratch_r15 ? "\x4c\x0f\xb3\x3d" : "\x48\x0f\xb3\x05",
				    4, "", 0, "cpu_tlbstate", 22) ||
	    !rap_kexec_branch(&k, 0x72, 1) || !rap_sequence_bytes(p, "\x49\x0f\xba\xee\x3f", 5) ||
	    !rap_kexec_label(&k, 1) || !rap_sequence_bytes(p, "\x41\x0f\x22\xde", 4) ||
	    !rap_kexec_label(&k, 0) || !rap_hw_local_edges(&k))
		return false;
	*s = *p;
	return true;
}

static bool rap_hw_single_alt(struct rap_sequence *s, const char *feature,
		struct symbol *span, unsigned long *end, struct instruction **original)
{
	struct instruction *first = find_insn(s->file, s->func->sec, s->func->offset + s->pos);
	struct alt_group *orig = first ? first->alt_group : NULL, *g;
	struct alternative *alt;
	const char *name;

	if (!orig || orig->orig_group || orig->first_insn != first || !orig->last_insn ||
	    !(alt = first->alts) || alt->next || alt->type != ALT_TYPE_INSTRUCTIONS ||
	    !(g = alt->insn->alt_group) || g->orig_group != orig ||
	    g->first_insn != alt->insn || !g->last_insn || g->feature >> 16 ||
	    !(name = arch_cpu_feature_name(g->feature)) || strcmp(name, feature))
		return false;
	*span = *s->func;
	span->sec = alt->insn->sec;
	span->offset = alt->insn->offset;
	span->len = g->last_insn->offset + g->last_insn->len - span->offset;
	*end = orig->last_insn->offset + orig->last_insn->len - s->func->offset;
	*original = first;
	return *end > s->pos && *end <= s->func->len && span->len <= *end - s->pos;
}

static bool rap_hw_take_alt(struct rap_kexec_sequence *k, const char *feature, unsigned int label)
{
	struct rap_sequence *s = &k->seq;
	struct instruction *first, *jump;
	struct symbol span;
	struct reloc *reloc;
	const unsigned char *p;
	unsigned long end;

	if (label >= ARRAY_SIZE(k->labels) || k->count == ARRAY_SIZE(k->branches) ||
	    !rap_hw_single_alt(s, feature, &span, &end, &first))
		return false;
	jump = first->alts->insn;
	p = span.sec->data->d_buf + span.offset;
	if (jump->len != span.len || !((span.len == 2 && *p == 0xeb) || (span.len == 5 && *p == 0xe9)))
		return false;
	reloc = find_reloc_by_dest_range(s->file->elf, span.sec, span.offset, span.len);
	if (reloc && (span.len != 5 || !arch_pc_relative_reloc(reloc) || arch_reloc_size(reloc) != 4 ||
		      reloc_offset(reloc) != span.offset + 1 ||
		      find_reloc_by_dest_range(s->file->elf, span.sec, span.offset + 2, 3)))
		return false;
	if (!rap_thunk_padding(s, end, false))
		return false;
	k->branches[k->count].insn = jump;
	k->branches[k->count++].label = label;
	first->rap_hw_alt = true;
	rap_hw_mark(s->file, &span);
	return true;
}

static bool rap_hw_clear_buffers(struct rap_sequence *s)
{
	struct symbol span;
	struct instruction *first;
	struct rap_sequence body = { .file = s->file, .func = &span };
	unsigned long end;

	if (!rap_hw_single_alt(s, "X86_FEATURE_CLEAR_CPU_BUF", &span, &end, &first) ||
	    !rap_sequence_reference(&body, "\x0f\x00\x2d", 3, "x86_verw_sel", true) ||
	    body.pos != span.len || !rap_thunk_padding(s, end, false))
		return false;
	first->rap_hw_alt = true;
	rap_hw_mark(s->file, &span);
	return true;
}

static bool rap_hw_switch_kernel_cr3(struct rap_sequence *s, unsigned int reg)
{
	struct rap_kexec_sequence k = { .seq = *s };
	struct rap_sequence *p = &k.seq;
	unsigned char read[] = { 0x0f, 0x20, 0xd8 + reg };
	unsigned char write[] = { 0x0f, 0x22, 0xd8 + reg };
	unsigned char bts[] = { 0x48, 0x0f, 0xba, 0xe8 + reg, 0x3f };
	unsigned char mask[] = { 0x48, 0x81, 0xe0 + reg, 0xff, 0xe7, 0xff, 0xff };

	if (reg != 0 && reg != 2 && reg != 4 && reg != 7)
		return false;
	if (!rap_hw_alt_is(p, "X86_FEATURE_PTI"))
		return true;
	if (!rap_hw_skip(&k, "X86_FEATURE_PTI", 0) ||
	    !rap_sequence_bytes(p, (const char *)read, sizeof(read)) ||
	    !rap_hw_fixed_alt(p, "X86_FEATURE_PCID", (const char *)bts, sizeof(bts)) ||
	    !(reg ? rap_sequence_bytes(p, (const char *)mask, sizeof(mask)) :
		    rap_sequence_bytes(p, "\x48\x25\xff\xe7\xff\xff", 6)) ||
	    !rap_sequence_bytes(p, (const char *)write, sizeof(write)) ||
	    !rap_kexec_label(&k, 0) || !rap_hw_local_edges(&k))
		return false;
	*s = *p;
	return true;
}

static bool rap_hw_user_cr3(struct rap_sequence *s)
{
	struct rap_kexec_sequence k = { .seq = *s };
	struct rap_sequence *p = &k.seq;

	if (!rap_sequence_bytes(p, "\x0f\x20\xdf", 3) || !rap_hw_skip(&k, "X86_FEATURE_PCID", 3) ||
	    !rap_sequence_bytes(p, "\x48\x89\xf8\x48\x81\xe7\xff\x07\0\0", 10) ||
	    !rap_thunk_percpu_offset(p, "\x48\x0f\xa3\x3d", 4, "", 0, "cpu_tlbstate", 22) ||
	    !rap_kexec_branch(&k, 0x73, 1) ||
	    !rap_thunk_percpu_offset(p, "\x48\x0f\xb3\x3d", 4, "", 0, "cpu_tlbstate", 22) ||
	    !rap_sequence_bytes(p, "\x48\x89\xc7", 3) || !rap_kexec_branch(&k, 0xeb, 2) ||
	    !rap_kexec_label(&k, 1) || !rap_sequence_bytes(p, "\x48\x89\xc7\x48\x0f\xba\xef\x3f", 8) ||
	    !rap_kexec_label(&k, 2) || !rap_sequence_bytes(p, "\x48\x81\xcf\0\x08\0\0", 7) ||
	    !rap_kexec_label(&k, 3) || !rap_sequence_bytes(p, "\x48\x81\xcf\0\x10\0\0\x0f\x22\xdf", 10) ||
	    !rap_hw_local_edges(&k))
		return false;
	*s = *p;
	return true;
}

static bool rap_hw_user_cr3_stack(struct rap_sequence *s)
{
	struct rap_kexec_sequence k = { .seq = *s };
	struct rap_sequence *p = &k.seq;

	if (!rap_hw_alt_is(s, "X86_FEATURE_PTI"))
		return true;
	if (!rap_hw_skip(&k, "X86_FEATURE_PTI", 0) || !rap_sequence_bytes(p, "\x50", 1) ||
	    !rap_hw_user_cr3(p) || !rap_sequence_bytes(p, "\x58", 1) ||
	    !rap_kexec_label(&k, 0) || !rap_hw_local_edges(&k))
		return false;
	*s = *p;
	return true;
}

static bool rap_hw_stack_erase(struct rap_sequence *s, bool save)
{
	bool enabled = !!find_symbol_by_name(s->file->elf, "stackleak_erase");

	if (!enabled)
		return true;
	return (!save || rap_entry_push_regs(s)) && rap_entry_call(s, "stackleak_erase") &&
		(!save || rap_entry_pop_regs(s));
}
