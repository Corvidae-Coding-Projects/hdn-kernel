/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * The mitigation thunks are not C functions. Their local CALL/RET pairs model
 * the predictor, and replacing them with RAP calls breaks that protocol. Admit
 * only these complete instruction sequences, their exact register slots and
 * alternatives. This does not grant an ordinary indirect-call target.
 */
static const char * const rap_thunk_names[] = {
	"__x86_indirect_thunk_array", "__x86_indirect_call_thunk_array",
	"__x86_indirect_jump_thunk_array", "__hdn_its_thunk_region",
	"srso_alias_untrain_ret", "srso_alias_return_thunk", "srso_untrain_ret",
	"srso_return_thunk", "retbleed_untrain_ret", "entry_untrain_ret",
	"call_depth_return_thunk", "its_return_thunk", "__x86_return_thunk",
	"write_ibpb",
};

static bool rap_thunk_name(const char *name)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(rap_thunk_names); i++)
		if (!strcmp(name, rap_thunk_names[i]))
			return true;
	return false;
}

static bool rap_thunk_symbol(struct objtool_file *file, const char *name,
		struct section *sec, unsigned long offset)
{
	struct symbol *sym = find_symbol_by_name(file->elf, name);

	return sym && !is_weak_sym(sym) && sym->sec == sec && sym->offset == offset;
}

/* The marker is set only after matching a complete closed instruction span.
 * It also covers embedded RET instructions which the regular decoder models
 * through the containing MOVABS/TEST rather than a separate function. */
static void rap_thunk_mark(struct objtool_file *file, struct symbol *span)
{
	struct instruction *insn;

	for_each_insn(file, insn)
		if (insn->sec == span->sec && insn->offset >= span->offset &&
		    insn->offset < span->offset + span->len)
			insn->rap_thunk_safe = true;
}

static bool rap_thunk_padding(struct rap_sequence *s, unsigned long end, bool traps)
{
	while (s->pos < end) {
		struct instruction *insn = find_insn(s->file, s->func->sec,
				s->func->offset + s->pos);
		const char *p = s->func->sec->data->d_buf + s->func->offset + s->pos;

		if (!insn || !insn->len || insn->len > end - s->pos ||
		    (traps ? (insn->len != 1 || *p != (char)0xcc) : insn->type != INSN_NOP) ||
		    !rap_sequence_bytes(s, p, insn->len))
			return false;
	}
	return s->pos == end;
}

/* RIP displacement is followed by an optional immediate. Matching the whole
 * instruction keeps a valid symbol with a changed shift count from passing. */
static bool rap_thunk_percpu_offset(struct rap_sequence *s, const char *op, size_t oplen,
		const char *imm, size_t immlen, const char *name, unsigned long member)
{
	struct symbol *target = find_symbol_by_name(s->file->elf, name);
	unsigned long off = s->func->offset + s->pos;
	struct instruction *insn = find_insn(s->file, s->func->sec, off);
	const char *p = s->func->sec->data->d_buf + off;
	struct reloc *reloc;
	size_t seg;

	if (!target || is_weak_sym(target) || !insn || s->pos >= s->func->len)
		return false;
	seg = (unsigned char)p[0] == 0x65;
	if (insn->len != seg + oplen + 4 + immlen || insn->len > s->func->len - s->pos ||
	    memcmp(p + seg, op, oplen) || memcmp(p + seg + oplen + 4, imm, immlen))
		return false;
	reloc = find_reloc_by_dest(s->file->elf, s->func->sec, off + seg + oplen);
	if (!reloc || !arch_pc_relative_reloc(reloc) || arch_reloc_size(reloc) != 4 ||
	    reloc->sym->sec != target->sec || (is_undef_sym(target) && reloc->sym != target) ||
	    reloc->sym->offset + arch_insn_adjusted_addend(insn, reloc) != target->offset + member ||
	    find_reloc_by_dest_range(s->file->elf, s->func->sec, off, seg + oplen) ||
	    find_reloc_by_dest_range(s->file->elf, s->func->sec, off + seg + oplen + 1,
				    3 + immlen))
		return false;
	/* At final link the addressing mode must agree with the selected per-CPU
	 * representation; no GS override is valid for a UP ordinary data symbol. */
	if (!is_undef_sym(target) && !!strstr(target->sec->name, "..percpu") != !!seg)
		return false;
	s->pos += insn->len;
	return true;
}

static bool rap_thunk_percpu(struct rap_sequence *s, const char *op, size_t oplen,
		const char *imm, size_t immlen, const char *name)
{
	return rap_thunk_percpu_offset(s, op, oplen, imm, immlen, name, 0);
}

static bool rap_thunk_debug(struct rap_sequence *s, const char *name)
{
	struct symbol *target = find_symbol_by_name(s->file->elf, name);

	if (!target)
		return true;
	return rap_thunk_percpu(s, "\x48\xff\x05", 3, "", 0, name);
}

static bool rap_thunk_poline(struct rap_sequence *s, unsigned int reg)
{
	unsigned char move[] = { reg < 8 ? 0x48 : 0x4c, 0x89, 0x04 | ((reg & 7) << 3), 0x24 };

	return rap_sequence_bytes(s, "\xe8\x01\0\0\0\xcc", 6) &&
		rap_sequence_bytes(s, (const char *)move, sizeof(move));
}

static bool rap_thunk_indirect(struct rap_sequence *s, unsigned int reg)
{
	unsigned char jump[] = { 0x41, 0xff, 0xe0 | (reg & 7) };

	return rap_sequence_bytes(s, (const char *)jump + (reg < 8), sizeof(jump) - (reg < 8));
}

static bool rap_thunk_ret(struct rap_sequence *s)
{
	const char *p = s->func->sec->data->d_buf + s->func->offset + s->pos;

	if (s->pos < s->func->len && (unsigned char)*p == 0xc3) {
		if (!rap_sequence_bytes(s, "\xc3", 1))
			return false;
		if (s->pos < s->func->len && (unsigned char)p[1] == 0xcc)
			return rap_sequence_bytes(s, "\xcc", 1);
		return true;
	}
	return rap_sequence_edge_match(s, "__x86_return_thunk", false, false);
}

static bool rap_thunk_fill_reg(struct rap_sequence *s, bool full, unsigned int reg)
{
	unsigned long loop;
	const unsigned char *p;

	if (!full)
		return rap_sequence_bytes(s, "\x90\x90\xe8\x01\0\0\0\xcc"
					 "\x48\x83\xc4\x08\x0f\xae\xe8", 15);
	if ((reg != 0 && reg != 12) || !rap_sequence_bytes(s, reg == 0 ?
		"\x48\xc7\xc0\x10\0\0\0" : "\x49\xc7\xc4\x10\0\0\0", 7))
		return false;
	loop = s->pos;
	if (!rap_sequence_bytes(s, "\xe8\x01\0\0\0\xcc\xe8\x01\0\0\0\xcc"
				  "\x48\x83\xc4\x10", 16) ||
	    !rap_sequence_bytes(s, reg == 0 ? "\x48\xff\xc8" : "\x49\xff\xcc", 3) ||
	    s->pos + 2 > s->func->len)
		return false;
	p = s->func->sec->data->d_buf + s->func->offset + s->pos;
	if (p[0] != 0x75 || s->pos + 2 + (signed char)p[1] != loop ||
	    !rap_sequence_bytes(s, (const char *)p, 2) ||
	    !rap_sequence_bytes(s, "\x0f\xae\xe8", 3))
		return false;
	if (find_symbol_by_name(s->file->elf, "__x86_call_depth") &&
	    !rap_thunk_percpu(s, "\x48\xc7\x05", 3, "\xff\xff\xff\xff", 4,
			      "__x86_call_depth"))
		return false;
	return rap_thunk_debug(s, "__x86_ctxsw_count");
}

static bool rap_thunk_fill(struct rap_sequence *s, bool full)
{
	return rap_thunk_fill_reg(s, full, 0);
}

enum rap_thunk_alt {
	RAP_ALT_INDIRECT, RAP_ALT_DEPTH, RAP_ALT_UNTRAIN, RAP_ALT_RETURN, RAP_ALT_IBPB,
	RAP_ALT_SWITCH_RSB
};

/* Validate the original span separately from all replacement spans. Padding
 * inserted by GAS is checked too; objtool's synthetic trailing NOP is not part
 * of the ELF and is deliberately excluded from the replacement extent. */
static bool rap_thunk_alternative(struct rap_sequence *s, enum rap_thunk_alt type,
		unsigned int reg)
{
	struct instruction *first = find_insn(s->file, s->func->sec, s->func->offset + s->pos);
	struct alt_group *orig = first ? first->alt_group : NULL;
	struct alternative *alt;
	struct symbol span;
	struct rap_sequence body;
	unsigned long end;
	unsigned int mask = 0;

	if (!orig || orig->orig_group || orig->first_insn != first)
		return false;
	end = orig->last_insn->offset + orig->last_insn->len - s->func->offset;
	if (end > s->func->len || end <= s->pos)
		return false;
	for (alt = first->alts; alt; alt = alt->next) {
		struct alt_group *g = alt->insn->alt_group;
		const char *feature;
		unsigned int bit;

		if (alt->type != ALT_TYPE_INSTRUCTIONS || !g || g->orig_group != orig ||
		    g->first_insn != alt->insn || !g->last_insn)
			return false;
		feature = arch_cpu_feature_name(g->feature & 0xffff);
		if (!feature)
			return false;
		span = *s->func;
		span.sec = alt->insn->sec;
		span.offset = alt->insn->offset;
		span.len = g->last_insn->offset + g->last_insn->len - span.offset;
		if (span.len > end - s->pos)
			return false;
		body = (struct rap_sequence){ .file = s->file, .func = &span };
		if (type == RAP_ALT_IBPB || type == RAP_ALT_SWITCH_RSB) {
			if (!strcmp(feature, type == RAP_ALT_IBPB ? "X86_BUG_IBPB_NO_RET" :
									 "X86_FEATURE_RSB_CTXSW") && !(g->feature >> 16)) {
				bit = 1;
				if (!rap_thunk_fill_reg(&body, true, type == RAP_ALT_IBPB ? 0 : 12)) return false;
			} else if (!strcmp(feature, "X86_FEATURE_ALWAYS") && (g->feature >> 16) == 1) {
				bit = 2;
				if (!rap_thunk_fill(&body, false)) return false;
			} else {
				return false;
			}
		} else if (type == RAP_ALT_INDIRECT) {
			if (!strcmp(feature, "X86_FEATURE_RETPOLINE_LFENCE") && !(g->feature >> 16)) {
				bit = 1;
				if (!rap_sequence_bytes(&body, "\x0f\xae\xe8", 3) ||
				    !rap_thunk_indirect(&body, reg) || !rap_sequence_bytes(&body, "\xcc", 1))
					return false;
			} else if (!strcmp(feature, "X86_FEATURE_RETPOLINE") && (g->feature >> 16) == 1) {
				bit = 2;
				if (!rap_thunk_indirect(&body, reg))
					return false;
			} else {
				return false;
			}
		} else {
			bit = 1;
			if (g->feature >> 16)
				return false;
			if (type == RAP_ALT_DEPTH) {
				if (strcmp(feature, "X86_FEATURE_CALL_DEPTH") ||
				    !rap_thunk_percpu(&body, "\x48\xc1\x3d", 3, "\x05", 1, "__x86_call_depth") ||
				    !rap_thunk_debug(&body, "__x86_call_count"))
					return false;
			} else if (type == RAP_ALT_UNTRAIN) {
				if (strcmp(feature, "X86_FEATURE_SRSO"))
					return false;
				if (find_symbol_by_name(s->file->elf, "srso_untrain_ret")) {
					if (!rap_sequence_edge_match(&body, "srso_untrain_ret", false, false))
						return false;
				} else if (!rap_sequence_bytes(&body, "\x0f\x0b", 2)) {
					return false;
				}
			} else if (strcmp(feature, "X86_FEATURE_ALWAYS") ||
				   !rap_sequence_bytes(&body, "\x0f\x0b", 2)) {
				return false;
			}
		}
		if ((mask & bit) || body.pos != span.len)
			return false;
		mask |= bit;
		rap_thunk_mark(s->file, &span);
	}
	if (mask != (type == RAP_ALT_INDIRECT || type == RAP_ALT_IBPB || type == RAP_ALT_SWITCH_RSB ? 3 : 1))
		return false;
	if (type == RAP_ALT_IBPB || type == RAP_ALT_SWITCH_RSB) {
		const char *p = first->sec->data->d_buf + first->offset;
		if (!((first->len == 2 && (unsigned char)*p == 0xeb) ||
		      (first->len == 5 && (unsigned char)*p == 0xe9)) ||
		    arch_jump_destination(first) != s->func->offset + end ||
		    !rap_sequence_bytes(s, p, first->len))
			return false;
	} else if (type == RAP_ALT_INDIRECT) {
		if (!rap_thunk_poline(s, reg) || !rap_thunk_ret(s))
			return false;
	} else if (type == RAP_ALT_UNTRAIN) {
		if (find_symbol_by_name(s->file->elf, "retbleed_untrain_ret")) {
			if (!rap_sequence_edge_match(s, "retbleed_untrain_ret", false, false))
				return false;
		} else if (!rap_sequence_bytes(s, "\x0f\x0b", 2)) {
			return false;
		}
	} else if (type == RAP_ALT_RETURN && !rap_sequence_bytes(s, "\xc3", 1)) {
		return false;
	}
	if (!rap_thunk_padding(s, end, false))
		return false;
	first->rap_thunk_alt = true;
	return true;
}

static bool rap_thunk_array(struct rap_sequence *s, unsigned int variant)
{
	static const char * const regs[] = {
		"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
		"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
	};
	static const char * const prefix[] = { "__x86_indirect_thunk_",
		"__x86_indirect_call_thunk_", "__x86_indirect_jump_thunk_",
		"__x86_indirect_its_thunk_" };
	unsigned int reg, stride = variant == 3 ? 64 : 32;
	char name[64];

	if (s->func->len != 16 * stride ||
	    (s->func->offset & (stride - 1)) != (variant == 3 ? 29 : 0))
		return false;
	for (reg = 0; reg < 16; reg++) {
		snprintf(name, sizeof(name), "%s%s", prefix[variant], regs[reg]);
		if (!rap_thunk_symbol(s->file, name, s->func->sec,
				s->func->offset + s->pos + (variant == 3 ? 3 : 0)))
			return false;
		if (variant == 3) {
			snprintf(name, sizeof(name), "__x86_indirect_paranoid_thunk_%s", regs[reg]);
			if (!rap_thunk_symbol(s->file, name, s->func->sec, s->func->offset + s->pos + 1) ||
			    !rap_sequence_bytes(s, "\xd6\x75\xfd", 3) ||
			    !rap_thunk_indirect(s, reg) || !rap_thunk_padding(s, (reg + 1) * stride, true))
				return false;
		} else {
			if (!variant) {
				if (!rap_thunk_alternative(s, RAP_ALT_INDIRECT, reg))
					return false;
			} else {
				if ((variant == 1 && !rap_thunk_alternative(s, RAP_ALT_DEPTH, reg)) ||
				    !rap_thunk_poline(s, reg) || !rap_sequence_bytes(s, "\xc3\xcc", 2))
					return false;
			}
			if (!rap_thunk_padding(s, (reg + 1) * stride, false))
				return false;
		}
	}
	return true;
}

static bool rap_thunk_alias_safe(struct objtool_file *file)
{
	struct symbol *safe = find_symbol_by_name(file->elf, "srso_alias_safe_ret");
	struct rap_sequence s = { .file = file, .func = safe };

	if (!safe || is_weak_sym(safe) || !safe->sec->text || safe->len != 7 ||
	    !rap_sequence_bytes(&s, "\x48\x8d\x64\x24\x08\xc3\xcc", 7))
		return false;
	rap_thunk_mark(file, safe);
	return true;
}

static bool rap_thunk_peer(struct objtool_file *file, const char *name)
{
	struct symbol *sym = find_symbol_by_name(file->elf, name);

	return sym && (is_undef_sym(sym) ? !opts.link :
			sym->rap_kind == 27 && sym->rap_thunk_protocol);
}

/* Direct edges have already been recategorized as synthetic returns or
 * indirect branches by objtool. Recover only their actual PC operand here;
 * a symbol name alone would miss a relocation redirected into padding. */
static bool rap_thunk_edge_target(struct objtool_file *file, struct instruction *insn,
		struct section **sec, unsigned long *offset)
{
	const unsigned char *p;
	unsigned int prefix, width;
	struct reloc *reloc;
	s32 displacement;

	if (insn->fake || !insn->len || insn->offset >= sec_size(insn->sec))
		return false;
	p = insn->sec->data->d_buf + insn->offset;
	prefix = p[0] == 0x2e;
	if (insn->len == prefix + 5 && (p[prefix] == 0xe8 || p[prefix] == 0xe9))
		width = 4;
	else if (insn->len == prefix + 2 && (p[prefix] == 0xeb ||
		 (p[prefix] >= 0x70 && p[prefix] <= 0x7f)))
		width = 1;
	else if (insn->len == prefix + 6 && p[prefix] == 0x0f &&
		 p[prefix + 1] >= 0x80 && p[prefix + 1] <= 0x8f)
		width = 4;
	else
		return false;
	reloc = find_reloc_by_dest_range(file->elf, insn->sec, insn->offset, insn->len);
	if (reloc) {
		if (is_undef_sym(reloc->sym))
			return false;
		*sec = reloc->sym->sec;
		*offset = reloc->sym->offset + arch_insn_adjusted_addend(insn, reloc);
	} else {
		if (width == 4)
			memcpy(&displacement, p + insn->len - 4, 4);
		else
			displacement = (signed char)p[insn->len - 1];
		*sec = insn->sec;
		*offset = insn->offset + insn->len + displacement;
	}
	return true;
}

static int validate_rap_thunk_peers(struct objtool_file *file)
{
	static const struct { const char *from, *to; } peers[] = {
		{ "srso_return_thunk", "srso_untrain_ret" },
		{ "srso_alias_return_thunk", "srso_alias_untrain_ret" },
		{ "__x86_indirect_call_thunk_array", "call_depth_return_thunk" },
		{ "__x86_indirect_jump_thunk_array", "call_depth_return_thunk" },
	};
	struct symbol *sym;
	struct symbol *safe = find_symbol_by_name(file->elf, "srso_alias_safe_ret");
	struct section *targets = find_section_by_name(file->elf, ".hdn.rap.targets");
	struct instruction *insn;
	unsigned int i;

	for_each_sym(file->elf, sym) {
		if (is_undef_sym(sym) || !rap_thunk_name(sym->name))
			continue;
		if (sym->rap_kind != 27 || !sym->rap_thunk_protocol) {
			ERROR_FUNC(sym->sec, sym->offset, "mitigation body lacks its unique RAP protocol record");
			return -1;
		}
	}
	for (i = 0; i < ARRAY_SIZE(peers); i++) {
		sym = find_symbol_by_name(file->elf, peers[i].from);
		if (sym && !is_undef_sym(sym) && !rap_thunk_peer(file, peers[i].to)) {
			ERROR_FUNC(sym->sec, sym->offset, "RAP mitigation thunk lacks its checked peer body");
			return -1;
		}
	}
	if (safe && !is_undef_sym(safe)) {
		unsigned long off;
		if (!rap_thunk_peer(file, "srso_alias_return_thunk") || !rap_thunk_alias_safe(file)) {
			ERROR_FUNC(safe->sec, safe->offset, "orphan RAP embedded mitigation return");
			return -1;
		}
		for (off = 0; targets && off < sec_size(targets); off += 16) {
			struct reloc *reloc = find_reloc_by_dest(file->elf, targets, off);
			if (reloc && reloc->sym->sec == safe->sec &&
			    reloc->sym->offset + reloc_addend(reloc) >= safe->offset &&
			    reloc->sym->offset + reloc_addend(reloc) < safe->offset + safe->len) {
				ERROR_FUNC(safe->sec, safe->offset, "embedded mitigation return has ordinary target permission");
				return -1;
			}
		}
	}
	for_each_insn(file, insn) {
		struct section *sec;
		unsigned long offset;

		if (insn->rap_thunk_safe && insn->alts && !insn->rap_thunk_alt) {
			ERROR_INSN(insn, "unexpected alternative in a RAP mitigation body");
			return -1;
		}
		if (!rap_thunk_edge_target(file, insn, &sec, &offset))
			continue;
		if (safe && !is_undef_sym(safe) && safe->sec == sec &&
		    offset >= safe->offset && offset < safe->offset + safe->len &&
		    !insn->rap_thunk_safe) {
			ERROR_INSN(insn, "ordinary code enters an embedded mitigation return");
			return -1;
		}
		for (i = 0; i < ARRAY_SIZE(rap_thunk_names); i++) {
			unsigned long delta;
			sym = find_symbol_by_name(file->elf, rap_thunk_names[i]);
			if (!sym || !sym->rap_thunk_protocol || sym->sec != sec ||
			    offset < sym->offset || offset >= sym->offset + sym->len)
				continue;
			/* Every outgoing edge in a checked mitigation body is exact. */
			if (insn->rap_thunk_safe)
				continue;
			delta = offset - sym->offset;
			if ((i < 3 && !(delta % 32)) ||
			    (i == 3 && (delta % 64 == 1 || delta % 64 == 3)) ||
			    (i > 3 && !delta))
				continue;
			ERROR_INSN(insn, "direct edge enters a RAP mitigation body at an unapproved offset");
			return -1;
		}
	}
	return 0;
}

/* These leaf services have no C callbacks, data-dependent stack access, or
 * writes through caller-supplied addresses. Their CALL creates a fresh return
 * slot and their full body is checked above, including unselected alternatives.
 * They can therefore run before the asynchronous RAP context is established.
 * No name-based exemption applies to an arbitrary function or return thunk. */
static int read_rap_mitigation_calls(struct objtool_file *file)
{
	struct instruction *insn;

	for_each_insn(file, insn) {
		struct symbol *callee = insn->type == INSN_CALL ? insn_call_dest(insn) : NULL;
		struct symbol span = { .sec = insn->sec, .offset = insn->offset, .len = insn->len };
		struct rap_sequence s = { .file = file, .func = &span };

		if (!callee || (strcmp(callee->name, "entry_untrain_ret") &&
		    strcmp(callee->name, "srso_alias_untrain_ret") && strcmp(callee->name, "write_ibpb")))
			continue;
		if (!rap_thunk_peer(file, callee->name) ||
		    !rap_sequence_edge_match(&s, callee->name, true, false) || s.pos != insn->len) {
			ERROR_INSN(insn, "mitigation call lacks a complete closed leaf protocol");
			return -1;
		}
		insn->rap_leaf_call = true;
	}
	return 0;
}

static int verify_rap_thunk(struct objtool_file *file, struct symbol *func)
{
	struct rap_sequence s = { .file = file, .func = func };
	struct instruction *insn;
	unsigned int i;
	const char *name = func->name;

#define MT_BYTES(b) do { if (!rap_sequence_bytes(&s, b, sizeof(b) - 1)) goto bad; } while (0)
#define MT_EDGE(n, c) do { if (!rap_sequence_edge_match(&s, n, c, false)) goto bad; } while (0)
	if (is_weak_sym(func) || !rap_thunk_name(name) || !func->sec->text)
		goto bad;
	if (!strcmp(name, "__x86_indirect_thunk_array")) {
		if (!rap_thunk_array(&s, 0)) goto bad;
	} else if (!strcmp(name, "__x86_indirect_call_thunk_array")) {
		if (!rap_thunk_array(&s, 1)) goto bad;
	} else if (!strcmp(name, "__x86_indirect_jump_thunk_array")) {
		if (!rap_thunk_array(&s, 2)) goto bad;
	} else if (!strcmp(name, "__hdn_its_thunk_region")) {
		if (!rap_thunk_array(&s, 3) ||
		    !rap_thunk_symbol(file, "__x86_indirect_its_thunk_array", func->sec, func->offset + 3))
			goto bad;
	} else if (!strcmp(name, "srso_alias_untrain_ret")) {
		if (func->len == 2) {
			MT_BYTES("\xc3\xcc");
		} else {
			MT_BYTES("\x66\x90\x0f\xae\xe8");
			MT_EDGE("srso_alias_return_thunk", false);
			if (!rap_thunk_alias_safe(file)) goto bad;
		}
	} else if (!strcmp(name, "srso_alias_return_thunk")) {
		MT_EDGE("srso_alias_safe_ret", true);
		MT_BYTES("\x0f\x0b");
		if (!rap_thunk_alias_safe(file)) goto bad;
	} else if (!strcmp(name, "srso_untrain_ret")) {
		if (!rap_thunk_symbol(file, "srso_safe_ret", func->sec, func->offset + 2) ||
		    ((func->offset + 2) & 63)) goto bad;
		MT_BYTES("\x48\xb8\x48\x8d\x64\x24\x08\xc3\xcc\xcc\x0f\xae\xe8");
		MT_EDGE("srso_safe_ret", true);
		MT_BYTES("\x0f\x0b");
	} else if (!strcmp(name, "srso_return_thunk")) {
		MT_EDGE("srso_safe_ret", true);
		MT_BYTES("\x0f\x0b");
	} else if (!strcmp(name, "retbleed_untrain_ret")) {
		if (!rap_thunk_symbol(file, "retbleed_return_thunk", func->sec, func->offset + 1) ||
		    ((func->offset + 1) & 63)) goto bad;
		MT_BYTES("\xf6\xc3\xcc\x0f\xae\xe8");
		MT_EDGE("retbleed_return_thunk", false);
		MT_BYTES("\xcc");
	} else if (!strcmp(name, "entry_untrain_ret")) {
		if (!rap_thunk_alternative(&s, RAP_ALT_UNTRAIN, 0)) goto bad;
	} else if (!strcmp(name, "call_depth_return_thunk")) {
		unsigned long target;
		const unsigned char *p;
		if (!rap_thunk_debug(&s, "__x86_ret_count") ||
		    !rap_thunk_percpu(&s, "\x48\xc1\x25", 3, "\x05", 1, "__x86_call_depth")) goto bad;
		p = func->sec->data->d_buf + func->offset + s.pos;
		if (s.pos + 2 > func->len || p[0] != 0x74) goto bad;
		target = s.pos + 2 + (signed char)p[1];
		if (!rap_sequence_bytes(&s, (const char *)p, 2)) goto bad;
		MT_BYTES("\xc3\xcc");
		if (target != s.pos || !rap_thunk_debug(&s, "__x86_stuffs_count")) goto bad;
		for (i = 0; i < 16; i++) MT_BYTES("\xe8\x01\0\0\0\xcc");
		MT_BYTES("\x48\x81\xc4\x80\0\0\0");
		if (!rap_thunk_percpu(&s, "\x48\xc7\x05", 3, "\xff\xff\xff\xff", 4,
				    "__x86_call_depth")) goto bad;
		MT_BYTES("\xc3\xcc");
	} else if (!strcmp(name, "its_return_thunk")) {
		if ((func->offset & 63) != 32) goto bad;
		MT_BYTES("\xc3\xcc");
	} else if (!strcmp(name, "write_ibpb")) {
		MT_BYTES("\xb9\x49\0\0\0");
		if (!rap_sequence_reference(&s, "\x8b\x05", 2, "x86_pred_cmd", true)) goto bad;
		MT_BYTES("\x31\xd2\x0f\x30");
		if (!rap_thunk_alternative(&s, RAP_ALT_IBPB, 0) || !rap_thunk_ret(&s)) goto bad;
	} else {
		insn = find_insn(file, func->sec, func->offset);
		if (insn && insn->alt_group) {
			if (!rap_thunk_alternative(&s, RAP_ALT_RETURN, 0)) goto bad;
		} else {
			MT_BYTES("\xc3");
		}
		MT_BYTES("\xcc");
	}
	if (s.pos != func->len)
		goto bad;
	/* Nothing may append an unreviewed alternative to a matched instruction. */
	rap_for_each_insn(file, func, insn)
		if (insn->alts && !insn->rap_thunk_alt)
			goto bad;
	rap_thunk_mark(file, func);
	func->rap_thunk_protocol = true;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s.pos, "RAP mitigation thunk differs from its closed instruction protocol");
	return -1;
#undef MT_BYTES
#undef MT_EDGE
}
