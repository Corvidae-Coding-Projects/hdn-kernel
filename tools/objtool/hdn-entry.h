/* SPDX-License-Identifier: GPL-2.0-only */
/* Hardware roots have no ordinary incoming C return slot. Describe their
 * whole instruction protocol instead of treating that fact as an exemption. */
static bool rap_fred_name(const char *name)
{
	return !strcmp(name, "asm_fred_entrypoint_user") ||
		!strcmp(name, "asm_fred_entrypoint_kernel");
}

static struct symbol *rap_entry_owner(struct instruction *insn)
{
	if (insn->alt_group && insn->alt_group->orig_group)
		insn = insn->alt_group->orig_group->first_insn;
	return rap_insn_owner(insn);
}

static bool rap_entry_push_regs(struct rap_sequence *s)
{
	return rap_sequence_bytes(s,
		"\x57\x56\x52\x51\x50\x41\x50\x41\x51\x41\x52\x41\x53"
		"\x53\x55\x41\x54\x41\x55\x41\x56\x41\x57", 23) &&
		rap_sequence_bytes(s,
		"\x31\xf6\x31\xd2\x31\xc9\x45\x31\xc0\x45\x31\xc9\x45\x31\xd2"
		"\x45\x31\xdb\x31\xdb\x31\xed\x45\x31\xe4\x45\x31\xed"
		"\x45\x31\xf6\x45\x31\xff", 34);
}

static bool rap_entry_pop_regs(struct rap_sequence *s)
{
	return rap_sequence_bytes(s,
		"\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x5d\x5b\x41\x5b\x41\x5a"
		"\x41\x59\x41\x58\x58\x59\x5a\x5e\x5f", 23);
}

static bool rap_entry_call(struct rap_sequence *s, const char *name)
{
	return rap_sequence_bytes(s, "\x4c\x8d\x15\x05\0\0\0", 7) &&
		rap_sequence_edge(s, name, true);
}

static bool rap_fred_eretu_fixup(struct objtool_file *file, struct symbol *func,
		struct instruction *insn)
{
	struct section *table = find_section_by_name(file->elf, "__ex_table");
	struct alternative *alt = insn->alts;
	unsigned long off;
	unsigned int matches = 0;

	if (!table || sec_size(table) % 12 || !alt || alt->next ||
	    alt->type != ALT_TYPE_EX_TABLE || !alt->insn ||
	    alt->insn->sec != func->sec || alt->insn->offset != func->offset)
		return false;
	for (off = 0; off < sec_size(table); off += 12) {
		struct reloc *from = find_reloc_by_dest(file->elf, table, off);
		struct reloc *to = find_reloc_by_dest(file->elf, table, off + 4);
		uint32_t type;

		if (!from || !to || reloc_type(from) != R_X86_64_PC32 ||
		    reloc_type(to) != R_X86_64_PC32 ||
		    from->sym->sec != insn->sec ||
		    from->sym->offset + reloc_addend(from) != insn->offset ||
		    to->sym->sec != func->sec ||
		    to->sym->offset + reloc_addend(to) != func->offset)
			continue;
		memcpy(&type, table->data->d_buf + off + 8, sizeof(type));
		if (type != 21 || memcmp(table->data->d_buf + off, (char[8]){}, 8) ||
		    find_reloc_by_dest_range(file->elf, table, off + 8, 4))
			return false;
		matches++;
	}
	return matches == 1;
}

static int verify_rap_fred(struct objtool_file *file, struct symbol *func)
{
	struct rap_sequence s = { .file = file, .func = func };
	struct instruction *insn;
	struct symbol *user = find_symbol_by_name(file->elf, "asm_fred_entrypoint_user");
	struct symbol *kernel = find_symbol_by_name(file->elf, "asm_fred_entrypoint_kernel");
	struct symbol *exit = find_symbol_by_name(file->elf, "asm_fred_exit_user");
	unsigned long exit_offset;
	bool from_user = !strcmp(func->name, "asm_fred_entrypoint_user");
	bool private_stack = false;

	if (!rap_fred_name(func->name) || is_weak_sym(func) || !func->sec->noinstr ||
	    !user || !kernel || user->sec != kernel->sec || (user->offset & 4095) ||
	    kernel->offset != user->offset + 256 || user->len > 256 ||
	    !rap_entry_push_regs(&s))
		goto bad;
	/* CONFIG_FRAME_POINTER only adds the exact pt_regs pointer encoding. */
	rap_sequence_bytes(&s, "\x48\x8d\x6c\x24\x01", 5);
	if (!rap_sequence_bytes(&s, "\x48\x89\xe7", 3))
		goto bad;
	if (from_user) {
		if (!rap_entry_call(&s, "fred_entry_from_user"))
			goto bad;
	} else {
		if (!rap_sequence_bytes(&s, "\x48\x89\xe7\xbe\x03\0\0\0\x41\xb9\0\x01\0\0"
					"\x31\xd2\x31\xc9\x45\x31\xc0", 21) ||
		    !rap_entry_call(&s, "hdn_rap_frame_enter") ||
		    !rap_sequence_bytes(&s, "\x48\x89\xe7", 3) ||
		    !rap_entry_call(&s, "fred_entry_from_kernel") ||
		    !rap_sequence_bytes(&s, "\x48\x89\xe7\xbe\x03\0\0\0", 8) ||
		    !rap_entry_call(&s, "hdn_rap_frame_exit"))
			goto bad;
		/* PRIVATE_STACKS consumes only the authenticated saved CR3. */
		private_stack = s.pos < func->len &&
			*(unsigned char *)(func->sec->data->d_buf + func->offset + s.pos) == 0x48;
		if (private_stack && !rap_sequence_bytes(&s, "\x48\x8b\x10\x0f\x22\xda", 6))
			goto bad;
		if (opts.link && !!find_symbol_by_name(file->elf, "hdn_stack_mm_ready") != private_stack)
			goto bad;
	}
	exit_offset = func->offset + s.pos;
	if (from_user && (!exit || exit->sec != func->sec || exit->offset != exit_offset))
		goto bad;
	if (!rap_entry_pop_regs(&s) ||
	    !rap_sequence_bytes(&s, from_user ? "\xf3\x0f\x01\xca" : "\xf2\x0f\x01\xca", 4) ||
	    s.pos != func->len)
		goto bad;
	rap_for_each_insn(file, func, insn)
		if (insn->alts && (!from_user || insn->offset + insn->len !=
		    func->offset + func->len || !rap_fred_eretu_fixup(file, func, insn)))
			goto bad;
	/* Only the fork return adapter may join the already-prepared user exit.
	 * There are no direct callers of either hardware entry point. */
	for_each_insn(file, insn) {
		struct symbol *owner = rap_entry_owner(insn);
		struct instruction *dest = insn->jump_dest;
		struct symbol *callee = insn->type == INSN_CALL ? insn_call_dest(insn) : NULL;

		if (callee == func)
			goto bad;
		if (!dest || dest->sec != func->sec || dest->offset < func->offset ||
		    dest->offset >= func->offset + func->len || owner == func)
			continue;
		if (!from_user || dest->offset != exit_offset ||
		    insn->type != INSN_JUMP_UNCONDITIONAL || !owner ||
		    strcmp(owner->name, "ret_from_fork_asm") || owner->rap_kind != 31)
			goto bad;
	}
	func->rap_fred_protocol = true;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s.pos, "RAP FRED root does not match its complete frame protocol");
	return -1;
}

/* CPU build requirements vary with the selected x86 baseline. Their values
 * cannot authorize memory access or a control transfer. Require the paired
 * AND/XOR masks to agree, and derive the SSE subset from that same mask. */
static bool rap_cpu_mask(struct rap_sequence *s, unsigned char modrm, uint32_t *value)
{
	unsigned long offset = s->func->offset + s->pos;
	struct instruction *insn = find_insn(s->file, s->func->sec, offset);
	const unsigned char *p = s->func->sec->data->d_buf + offset;

	if (!insn || s->pos >= s->func->len || insn->len > s->func->len - s->pos ||
	    !((insn->len == 6 && p[0] == 0x81) || (insn->len == 3 && p[0] == 0x83)) ||
	    p[1] != modrm || find_reloc_by_dest_range(s->file->elf, s->func->sec, offset, insn->len))
		return false;
	if (insn->len == 6)
		memcpy(value, p + 2, sizeof(*value));
	else
		*value = (int8_t)p[2];
	s->pos += insn->len;
	return true;
}

static int verify_rap_cpu(struct objtool_file *file, struct symbol *func)
{
	struct rap_kexec_sequence k = { .seq = { .file = file, .func = func } };
	struct rap_sequence *s = &k.seq;
	struct instruction *insn;
	uint32_t mask0, mask1, mask, sse;
	unsigned int i;

#define CPU_BYTES(bytes) do { if (!rap_sequence_bytes(s, bytes, sizeof(bytes) - 1)) goto bad; } while (0)
#define CPU_BRANCH(op, n) do { if (!rap_kexec_branch(&k, op, n)) goto bad; } while (0)
#define CPU_LABEL(n) do { if (!rap_kexec_label(&k, n)) goto bad; } while (0)
	if (strcmp(func->name, "verify_cpu") || is_weak_sym(func))
		goto bad;
	CPU_BYTES("\x9c\x6a\0\x9d\xb8\0\0\0\0\x0f\xa2\x83\xf8\x01");
	CPU_BRANCH(0x72, 5);
	CPU_BYTES("\x66\x31\xff\x81\xfb\x41\x75\x74\x68");
	CPU_BRANCH(0x75, 0);
	CPU_BYTES("\x81\xfa\x65\x6e\x74\x69");
	CPU_BRANCH(0x75, 0);
	CPU_BYTES("\x81\xf9\x63\x41\x4d\x44");
	CPU_BRANCH(0x75, 0);
	CPU_BYTES("\x66\xbf\x01\0");
	CPU_BRANCH(0xeb, 2);
	CPU_LABEL(0);
	CPU_BYTES("\x81\xfb\x47\x65\x6e\x75");
	CPU_BRANCH(0x75, 2);
	CPU_BYTES("\x81\xfa\x69\x6e\x65\x49");
	CPU_BRANCH(0x75, 2);
	CPU_BYTES("\x81\xf9\x6e\x74\x65\x6c");
	CPU_BRANCH(0x75, 2);
	CPU_BYTES("\xb8\x01\0\0\0\x0f\xa2\x89\xc1\x25\0\x0f\xf0\x0f\xc1\xe8\x08\x83\xf8\x06");
	CPU_BRANCH(0x77, 1);
	CPU_BRANCH(0x72, 2);
	CPU_BYTES("\x81\xe1\xf0\0\x0f\0\xc1\xe9\x04\x83\xf9\x0d");
	CPU_BRANCH(0x72, 2);
	CPU_LABEL(1);
	CPU_BYTES("\xb9\xa0\x01\0\0\x0f\x32\x0f\xba\xf2\x02");
	CPU_BRANCH(0x73, 2);
	CPU_BYTES("\x0f\x30");
	CPU_LABEL(2);
	CPU_BYTES("\xb8\x01\0\0\0\x0f\xa2");
	if (!rap_cpu_mask(s, 0xe2, &mask0) || !rap_cpu_mask(s, 0xf2, &mask) || mask != mask0)
		goto bad;
	CPU_BRANCH(0x75, 5);
	CPU_BYTES("\xb8\0\0\0\x80\x0f\xa2\x3d\x01\0\0\x80");
	CPU_BRANCH(0x72, 5);
	CPU_BYTES("\xb8\x01\0\0\x80\x0f\xa2");
	if (!rap_cpu_mask(s, 0xe2, &mask1) || !rap_cpu_mask(s, 0xf2, &mask) || mask != mask1)
		goto bad;
	CPU_BRANCH(0x75, 5);
	CPU_LABEL(3);
	CPU_BYTES("\xb8\x01\0\0\0\x0f\xa2");
	if (!rap_cpu_mask(s, 0xe2, &sse) || !rap_cpu_mask(s, 0xfa, &mask) ||
	    mask != sse || sse != (mask0 & 0x06000000U))
		goto bad;
	CPU_BRANCH(0x74, 6);
	CPU_BYTES("\x66\x85\xff");
	CPU_BRANCH(0x74, 5);
	CPU_BYTES("\xb9\x15\0\x01\xc0\x0f\x32\x0f\xba\xf0\x0f\x0f\x30\x66\x31\xff");
	CPU_BRANCH(0xeb, 3);
	CPU_LABEL(5);
	CPU_BYTES("\x9d\xb8\x01\0\0\0");
	if (!rap_thunk_ret(s))
		goto bad;
	CPU_LABEL(6);
	CPU_BYTES("\x9d\x31\xc0");
	if (!rap_thunk_ret(s) || s->pos != func->len)
		goto bad;
	for (i = 0; i < k.count; i++)
		if (!k.defined[k.branches[i].label] ||
		    arch_jump_destination(k.branches[i].insn) != k.labels[k.branches[i].label])
			goto bad;
	rap_for_each_insn(file, func, insn)
		if (insn->alts)
			goto bad;
	for_each_insn(file, insn) {
		struct instruction *dest = insn->jump_dest;
		struct symbol *owner = rap_entry_owner(insn);
		struct symbol *callee = insn->type == INSN_CALL ? insn_call_dest(insn) : NULL;

		if (owner == func)
			continue;
		if (callee == func) {
			if (!owner || (strcmp(owner->name, "startup_64") &&
				       strcmp(owner->name, "secondary_startup_64")))
				goto bad;
		} else if (dest && dest->sec == func->sec && dest->offset >= func->offset &&
			   dest->offset < func->offset + func->len) {
			goto bad;
		}
	}
	func->rap_cpu_protocol = true;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s->pos, "RAP CPU bootstrap leaf does not match its closed protocol");
	return -1;
#undef CPU_LABEL
#undef CPU_BRANCH
#undef CPU_BYTES
}

static bool rap_fork_exit(struct rap_sequence *s)
{
	struct instruction *first = find_insn(s->file, s->func->sec, s->func->offset + s->pos);
	struct alt_group *orig = first ? first->alt_group : NULL;
	struct alternative *alt;
	struct symbol span;
	struct rap_sequence replacement;
	unsigned long end;
	const char *feature;

	if (!orig)
		return rap_sequence_edge_match(s, "swapgs_restore_regs_and_return_to_usermode", false, false);
	if (orig->orig_group || orig->first_insn != first || !orig->last_insn ||
	    !(alt = first->alts) || alt->next || alt->type != ALT_TYPE_INSTRUCTIONS ||
	    !alt->insn->alt_group || alt->insn->alt_group->orig_group != orig ||
	    alt->insn->alt_group->first_insn != alt->insn || !alt->insn->alt_group->last_insn ||
	    !(feature = arch_cpu_feature_name(alt->insn->alt_group->feature)) ||
	    strcmp(feature, "X86_FEATURE_FRED"))
		return false;
	span = *s->func;
	span.sec = alt->insn->sec;
	span.offset = alt->insn->offset;
	span.len = alt->insn->alt_group->last_insn->offset +
		alt->insn->alt_group->last_insn->len - span.offset;
	replacement = (struct rap_sequence){ .file = s->file, .func = &span };
	if (!rap_sequence_edge_match(&replacement, "asm_fred_exit_user", false, false) ||
	    replacement.pos != span.len)
		return false;
	end = orig->last_insn->offset + orig->last_insn->len - s->func->offset;
	if (!rap_sequence_edge_match(s, "swapgs_restore_regs_and_return_to_usermode", false, false) ||
	    !rap_thunk_padding(s, end, false))
		return false;
	rap_thunk_mark(s->file, &span);
	first->rap_thunk_alt = true;
	return true;
}

static int verify_rap_switch(struct objtool_file *file, struct symbol *func)
{
	struct rap_sequence s = { .file = file, .func = func };
	struct instruction *insn;
	bool fork = func->rap_kind == 31;
	bool private_stack = false, canary = false;

#define SWITCH_BYTES(bytes) do { if (!rap_sequence_bytes(&s, bytes, sizeof(bytes) - 1)) goto bad; } while (0)
#define SWITCH_CALL(name) do { if (!rap_entry_call(&s, name)) goto bad; } while (0)
	if (is_weak_sym(func) || strcmp(func->name, fork ? "ret_from_fork_asm" : "__switch_to_asm"))
		goto bad;
	if (fork) {
		insn = find_insn(file, func->sec, func->offset);
		if (insn && insn->alts && !rap_thunk_alternative(&s, RAP_ALT_DEPTH, 0))
			goto bad;
		SWITCH_BYTES("\x48\x89\xc7\x48\x89\xe6\x48\x89\xda\x4c\x89\xe1");
		SWITCH_CALL("ret_from_fork");
		if (!rap_fork_exit(&s))
			goto bad;
	} else {
		SWITCH_BYTES("\x55\x53\x41\x54\x41\x55\x41\x56\x41\x57"
			     "\x49\x89\xfc\x49\x89\xf5\x48\x89\xe2\x4c\x89\xd1\x48\x83\xec\x08");
		SWITCH_CALL("hdn_rap_switch");
		SWITCH_BYTES("\x48\x83\xc4\x08\x4c\x89\xe7\x4c\x89\xee");
		insn = find_insn(file, func->sec, func->offset + s.pos);
		if (insn && insn->len == 3 && !memcmp(func->sec->data->d_buf + insn->offset,
						    "\x48\x8b\x20", 3)) {
			SWITCH_BYTES("\x48\x8b\x20");
		} else {
			private_stack = true;
			SWITCH_BYTES("\x4c\x8b\x58\x40\x48\x8b\x10");
			if (!rap_thunk_symbol(file, "__hdn_stack_switch_cr3", func->sec, func->offset + s.pos))
				goto bad;
			SWITCH_BYTES("\x41\x0f\x22\xdb\x48\x89\xd4");
			if (!rap_thunk_symbol(file, "__hdn_stack_switch_rsp", func->sec, func->offset + s.pos))
				goto bad;
			SWITCH_BYTES("\x49\x89\xc4\x49\x89\xfd\x49\x89\xf6\x48\x83\xec\x08");
			SWITCH_CALL("hdn_stack_mm_finish");
			SWITCH_BYTES("\x48\x83\xc4\x08\x4c\x89\xe0\x4c\x89\xef\x4c\x89\xf6");
		}
		insn = find_insn(file, func->sec, func->offset + s.pos);
		if (insn && insn->len == 4 && !memcmp(func->sec->data->d_buf + insn->offset,
						    "\x48\x8b\x58\x48", 4)) {
			canary = true;
			SWITCH_BYTES("\x48\x8b\x58\x48");
			if (!rap_thunk_percpu(&s, "\x48\x89\x1d", 3, "", 0, "__stack_chk_guard"))
				goto bad;
		}
		if (opts.link &&
		    (!!find_symbol_by_name(file->elf, "hdn_stack_mm_ready") != private_stack ||
		     !!find_symbol_by_name(file->elf, "__stack_chk_guard") != canary))
			goto bad;
		if (!rap_thunk_alternative(&s, RAP_ALT_SWITCH_RSB, 12))
			goto bad;
		SWITCH_BYTES("\x4c\x8b\x78\x08\x4c\x8b\x70\x10\x4c\x8b\x68\x18"
			     "\x4c\x8b\x60\x20\x48\x8b\x58\x28\x48\x8b\x68\x30"
			     "\x4c\x8b\x50\x38\x48\x83\xc4\x30");
		if (!rap_sequence_edge_match(&s, "__switch_to", false, false))
			goto bad;
	}
	if (s.pos != func->len)
		goto bad;
	rap_for_each_insn(file, func, insn)
		if (insn->alts && !insn->rap_thunk_alt)
			goto bad;
	for_each_insn(file, insn) {
		struct instruction *dest = insn->jump_dest;
		struct symbol *callee = insn->type == INSN_CALL ? insn_call_dest(insn) : NULL;

		if (rap_entry_owner(insn) == func)
			continue;
		if ((callee == func && (fork || !insn->rap_site)) ||
		    (dest && dest->sec == func->sec && dest->offset >= func->offset &&
		     dest->offset < func->offset + func->len))
			goto bad;
	}
	func->rap_switch_protocol = true;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s.pos, "RAP task switch/fork lacks its checked snapshot protocol");
	return -1;
#undef SWITCH_CALL
#undef SWITCH_BYTES
}

static int verify_rap_s3(struct objtool_file *file, struct symbol *func)
{
	struct rap_sequence s = { .file = file, .func = func };
	struct instruction *insn, *first = find_insn(file, func->sec, func->offset);
	struct symbol *resume = find_symbol_by_name(file->elf, "__hdn_s3_resume");
	struct symbol *suspend = find_symbol_by_name(file->elf, "do_suspend_lowlevel");
	struct symbol *wakeup = find_symbol_by_name(file->elf, "wakeup_long64");
	bool frame = false;

#define S3_BYTES(bytes) do { if (!rap_sequence_bytes(&s, bytes, sizeof(bytes) - 1)) goto bad; } while (0)
#define S3_CALL(name) do { if (!rap_entry_call(&s, name)) goto bad; } while (0)
#define S3_REF(bytes, name) do { if (!rap_sequence_reference(&s, bytes, sizeof(bytes) - 1, name, false)) goto bad; } while (0)
	if (is_weak_sym(func) || !resume || !suspend || !wakeup ||
	    suspend->rap_kind != 1 || wakeup->rap_kind != 32 ||
	    resume->sec != suspend->sec || resume->offset <= suspend->offset ||
	    resume->offset >= suspend->offset + suspend->len)
		goto bad;
	if (func == wakeup) {
		if (!rap_sequence_edge_match(&s, "__hdn_s3_resume", false, false))
			goto bad;
	} else if (func == suspend) {
		if (first && first->type == INSN_ENDBR)
			S3_BYTES("\xf3\x0f\x1e\xfa");
		S3_BYTES("\x4c\x8d\x1d\x05\0\0\0");
		if (!rap_sequence_edge_match(&s, "__hdn_rap_enter", true, false))
			goto bad;
		if (s.pos < func->len &&
		    *(unsigned char *)(func->sec->data->d_buf + func->offset + s.pos) == 0x55) {
			S3_BYTES("\x55\x48\x89\xe5");
			frame = true;
		}
		S3_BYTES("\x48\x83\xec\x08\x31\xc0");
		S3_CALL("save_processor_state");
		S3_REF("\x48\xc7\xc0", "saved_context");
		S3_BYTES("\x48\x89\xa0\x98\0\0\0\x48\x89\x68\x20\x48\x89\x70\x68"
			 "\x48\x89\x78\x70\x48\x89\x58\x28\x48\x89\x48\x58\x48\x89\x50\x60"
			 "\x4c\x89\x40\x48\x4c\x89\x48\x40\x4c\x89\x50\x38\x4c\x89\x58\x30"
			 "\x4c\x89\x60\x18\x4c\x89\x68\x10\x4c\x89\x70\x08\x4c\x89\x38"
			 "\x9c\x8f\x80\x90\0\0\0\x48\x89\xe6\xbf\x01\0\0\0");
		S3_CALL("hdn_rap_resume_save");
		S3_BYTES("\x48\x83\xc4\x08\xbf\x03\0\0\0\x31\xc0");
		S3_CALL("x86_acpi_enter_sleep_state");
		if (!rap_sequence_edge_match(&s, "__hdn_s3_resume", false, false) ||
		    (resume->offset & 3) || !rap_thunk_padding(&s, resume->offset - func->offset, false))
			goto bad;
		S3_REF("\x48\xc7\xc0", "hdn_rap_resume_state");
		S3_BYTES("\x0f\x01\x90\x0a\x01\0\0\x0f\x01\x98\x16\x01\0\0\xbf\x01\0\0\0");
		S3_CALL("hdn_rap_resume_restore");
		S3_BYTES("\x48\x8b\x98\xe0\0\0\0\x0f\x22\xe3"
			 "\x48\x8b\x98\xd8\0\0\0\x0f\x22\xdb"
			 "\x48\x8b\x98\xd0\0\0\0\x0f\x22\xd3"
			 "\x48\x8b\x98\xc8\0\0\0\x0f\x22\xc3"
			 "\xff\xb0\x90\0\0\0\x9d\x48\x8b\xa0\x98\0\0\0"
			 "\x48\x8b\x68\x20\x48\x8b\x70\x68\x48\x8b\x78\x70"
			 "\x48\x8b\x58\x28\x48\x8b\x48\x58\x48\x8b\x50\x60"
			 "\x4c\x8b\x40\x48\x4c\x8b\x48\x40\x4c\x8b\x50\x38\x4c\x8b\x58\x30"
			 "\x4c\x8b\x60\x18\x4c\x8b\x68\x10\x4c\x8b\x70\x08\x4c\x8b\x38");
		if (s.pos < func->len &&
		    *(unsigned char *)(func->sec->data->d_buf + func->offset + s.pos) == 0x48) {
			S3_BYTES("\x48\x89\xe7");
			S3_CALL("kasan_unpoison_task_stack_below");
		}
		S3_BYTES("\x31\xc0\x48\x83\xc4\x08");
		if (frame)
			S3_BYTES("\x5d");
		S3_CALL("restore_processor_state");
		if (!rap_sequence_edge_match(&s, "__hdn_rap_return", false, false))
			goto bad;
	} else {
		goto bad;
	}
	if (s.pos != func->len)
		goto bad;
	rap_for_each_insn(file, func, insn)
		if (insn->alts)
			goto bad;
	for_each_insn(file, insn) {
		struct instruction *dest = insn->jump_dest;
		struct symbol *owner = rap_entry_owner(insn);
		struct symbol *callee = insn->type == INSN_CALL ? insn_call_dest(insn) : NULL;

		if (func == wakeup && callee == func)
			goto bad;
		if (!dest || dest->sec != func->sec || dest->offset < func->offset ||
		    dest->offset >= func->offset + func->len || owner == func)
			continue;
		if (func == suspend) {
			if (owner != wakeup || dest->offset != resume->offset)
				goto bad;
		} else if (!owner || strcmp(owner->name, "common_startup_64") || owner->rap_kind != 50 ||
			   dest->offset != func->offset) {
			goto bad;
		}
	}
	func->rap_s3_protocol = true;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s.pos, "RAP S3 transition does not match its fixed checkpoint protocol");
	return -1;
#undef S3_REF
#undef S3_CALL
#undef S3_BYTES
}
