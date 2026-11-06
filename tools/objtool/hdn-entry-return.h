/* SPDX-License-Identifier: GPL-2.0-only */
static bool rap_hw_pop_except_rdi(struct rap_sequence *s)
{
	return rap_sequence_bytes(s, "\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x5d\x5b\x41\x5b\x41\x5a"
				    "\x41\x59\x41\x58\x58\x59\x5a\x5e", 22);
}

static bool rap_hw_espfix(struct rap_sequence *s)
{
	unsigned int i;
	const unsigned int words[] = { 1, 2, 3, 5, 4 };

	if (!rap_sequence_bytes(s, "\x57\x0f\x01\xf8", 4) || !rap_hw_switch_kernel_cr3(s, 7) ||
	    !rap_thunk_percpu(s, "\x48\x8b\x3d", 3, "", 0, "espfix_waddr") ||
	    !rap_sequence_bytes(s, "\x48\x89\x07", 3))
		return false;
	for (i = 0; i < ARRAY_SIZE(words); i++) {
		unsigned char read[] = { 0x48, 0x8b, 0x44, 0x24, words[i] * 8 };
		unsigned char write[] = { 0x48, 0x89, 0x47, words[i] * 8 };
		if (!rap_sequence_bytes(s, (const char *)read, sizeof(read)) ||
		    !rap_sequence_bytes(s, (const char *)write, sizeof(write)))
			return false;
	}
	return rap_sequence_bytes(s, "\x25\0\0\xff\xff", 5) &&
		rap_thunk_percpu(s, "\x48\x0b\x05", 3, "", 0, "espfix_stack") &&
		rap_hw_user_cr3_stack(s) && rap_sequence_bytes(s, "\x0f\x01\xf8\x5f\x48\x89\xc4\x58", 8) &&
		rap_hw_clear_buffers(s) && rap_sequence_edge_match(s, "native_irq_return_iret", false, false);
}

static int verify_rap_interrupt_return(struct objtool_file *file, struct symbol *func)
{
	struct rap_kexec_sequence k = { .seq = { .file = file, .func = func } };
	struct rap_sequence *s = &k.seq;
	struct instruction *insn;
	bool pti, espfix;

	if (is_weak_sym(func) || !func->sec->noinstr || strcmp(func->name, "common_interrupt_return") ||
	    !rap_thunk_symbol(file, "swapgs_restore_regs_and_return_to_usermode", func->sec, func->offset) ||
	    !rap_hw_ibrs(s, false, false))
		goto bad;
	pti = rap_hw_alt_is(s, "X86_FEATURE_PTI");
	if ((pti && !rap_hw_take_alt(&k, "X86_FEATURE_PTI", 1)) || !rap_hw_stack_erase(s, false) ||
	    !rap_entry_pop_regs(s) || !rap_sequence_bytes(s, "\x48\x83\xc4\x08", 4) ||
	    !rap_kexec_label(&k, 0) || !rap_sequence_bytes(s, "\x0f\x01\xf8", 3) ||
	    !rap_hw_clear_buffers(s) || !rap_sequence_bytes(s, "\xf6\x44\x24\x08\x03", 5) ||
	    !rap_kexec_branch(&k, 0x75, 3) || !rap_sequence_bytes(s, "\x0f\x0b", 2))
		goto bad;
	if (pti) {
		if (!rap_kexec_label(&k, 1) || !rap_hw_pop_except_rdi(s) ||
		    !rap_sequence_bytes(s, "\x48\x89\xe7", 3) ||
		    !rap_thunk_percpu_offset(s, "\x48\x8b\x25", 3, "", 0, "cpu_tss_rw", 4) ||
		    !rap_sequence_bytes(s, "\xff\x77\x30\xff\x77\x28\xff\x77\x20"
					  "\xff\x77\x18\xff\x77\x10\xff\x37", 17) ||
		    !rap_hw_stack_erase(s, true) || !rap_sequence_bytes(s, "\x50", 1) ||
		    !rap_hw_user_cr3(s) || !rap_sequence_bytes(s, "\x58\x5f", 2) ||
		    !rap_kexec_branch(&k, 0xeb, 0))
			goto bad;
	}
	if (!rap_thunk_symbol(file, "restore_regs_and_return_to_kernel", func->sec, func->offset + s->pos))
		goto bad;
	if (rap_sequence_bytes(s, "\xf6\x84\x24\x88\0\0\0\x03", 8)) {
		if (!rap_kexec_branch(&k, 0x74, 2) || !rap_sequence_bytes(s, "\x0f\x0b", 2) ||
		    !rap_kexec_label(&k, 2))
			goto bad;
	}
	if (!rap_entry_pop_regs(s) || !rap_sequence_bytes(s, "\x48\x83\xc4\x08", 4) ||
	    !rap_kexec_label(&k, 3))
		goto bad;
	espfix = rap_sequence_bytes(s, "\xf6\x44\x24\x20\x04", 5);
	if ((espfix && !rap_kexec_branch(&k, 0x75, 4)) ||
	    !rap_thunk_symbol(file, "native_irq_return_iret", func->sec, func->offset + s->pos) ||
	    !rap_sequence_bytes(s, "\x48\xcf", 2) ||
	    (espfix && (!rap_kexec_label(&k, 4) || !rap_hw_espfix(s))) ||
	    s->pos != func->len || !rap_hw_local_edges(&k))
		goto bad;
	rap_for_each_insn(file, func, insn)
		if (insn->alts && !insn->rap_hw_alt)
			goto bad;
	func->rap_interrupt_return_protocol = true;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s->pos, "RAP interrupt return differs from its complete native exit protocol");
	return -1;
}

static int verify_rap_syscall32_ignore(struct objtool_file *file, struct symbol *func)
{
	struct rap_sequence s = { .file = file, .func = func };
	struct instruction *insn;

	if (is_weak_sym(func) || !func->sec->noinstr || strcmp(func->name, "entry_SYSCALL32_ignore") ||
	    !rap_hw_endbr(&s) || !rap_sequence_bytes(&s, "\xb8\xda\xff\xff\xff", 5) ||
	    !rap_hw_clear_buffers(&s) || !rap_sequence_bytes(&s, "\x0f\x07", 2) || s.pos != func->len)
		goto bad;
	rap_for_each_insn(file, func, insn)
		if (insn->alts && !insn->rap_hw_alt)
			goto bad;
	func->rap_interrupt_return_protocol = true;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s.pos, "RAP ignored compat syscall has an invalid fixed exit");
	return -1;
}

static int validate_rap_interrupt_return_peers(struct objtool_file *file)
{
	struct symbol *func = find_symbol_by_name(file->elf, "common_interrupt_return");
	struct symbol *ignore = find_symbol_by_name(file->elf, "entry_SYSCALL32_ignore");
	struct symbol *kernel = find_symbol_by_name(file->elf, "restore_regs_and_return_to_kernel");
	struct instruction *insn;

	if ((!func || is_undef_sym(func)) && (!ignore || is_undef_sym(ignore)))
		return 0;
	if ((func && !is_undef_sym(func) && (func->rap_kind != 40 || !func->rap_interrupt_return_protocol)) ||
	    (ignore && !is_undef_sym(ignore) && (ignore->rap_kind != 43 || !ignore->rap_interrupt_return_protocol)))
		goto bad;
	if (opts.link) {
		struct symbol *erase = find_symbol_by_name(file->elf, "stackleak_erase");
		struct symbol *verw = find_symbol_by_name(file->elf, "x86_verw_sel");
		if ((erase && erase->rap_kind != 1) || !verw || !verw->sec->text || verw->len < 2 ||
		    memcmp(verw->sec->data->d_buf + verw->offset, "\x18\0", 2))
			goto bad;
	}
	for_each_insn(file, insn) {
		struct symbol *owner = rap_entry_owner(insn);
		struct section *sec;
		unsigned long offset;

		if (!rap_thunk_edge_target(file, insn, &sec, &offset))
			continue;
		if (ignore && !is_undef_sym(ignore) && sec == ignore->sec &&
		    offset >= ignore->offset && offset < ignore->offset + ignore->len)
			goto bad;
		if (!func || is_undef_sym(func) || sec != func->sec || offset < func->offset ||
		    offset >= func->offset + func->len || owner == func)
			continue;
		if (!owner || (insn->type != INSN_JUMP_UNCONDITIONAL && insn->type != INSN_JUMP_CONDITIONAL))
			goto bad;
		if (offset == func->offset && (owner->rap_kind == 31 || owner->rap_kind == 36 ||
		    owner->rap_kind == 41 || owner->rap_kind == 42 || owner->rap_kind == 45))
			continue;
		if (kernel && offset == kernel->offset &&
		    (owner->rap_kind == 36 || owner->rap_kind == 39 || owner->rap_kind == 47))
			continue;
		goto bad;
	}
	return 0;
bad:
	ERROR("RAP interrupt exit has an unverified caller or an unauthorized interior entry");
	return -1;
}
