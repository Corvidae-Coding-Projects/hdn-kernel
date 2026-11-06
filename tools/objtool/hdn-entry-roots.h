/* SPDX-License-Identifier: GPL-2.0-only */
/* Pre-C IDT helpers have a hardware frame and a fresh assembly CALL slot.
 * They are not general C functions. Only error_entry captures that slot,
 * exactly at the boundary before its first protected C call. */
static unsigned int rap_entry_root_kind(const char *name)
{
	if (!strcmp(name, "error_entry")) return 37;
	if (!strcmp(name, "paranoid_entry")) return 38;
	if (!strcmp(name, "paranoid_exit")) return 39;
	return 0;
}

static bool rap_hw_capture(struct rap_sequence *s)
{
	struct instruction *call;

	if (!rap_sequence_bytes(s, "\x4c\x8b\x14\x24\x4c\x8d\x1d\x05\0\0\0", 11))
		return false;
	call = find_insn(s->file, s->func->sec, s->func->offset + s->pos);
	return call && call->rap_root && call->rap_entry &&
		rap_sequence_edge_match(s, "__hdn_rap_enter", true, false);
}

static bool rap_hw_user_entry(struct rap_sequence *s)
{
	return rap_sequence_bytes(s, "\x0f\x01\xf8", 3) &&
		rap_hw_fixed_alt(s, "X86_FEATURE_FENCE_SWAPGS_USER", "\x0f\xae\xe8", 3) &&
		rap_hw_kernel_cr3(s, false) && rap_hw_ibrs(s, true, false) &&
		rap_hw_untrain(s, true) && rap_hw_capture(s) &&
		rap_sequence_bytes(s, "\x48\x8d\x7c\x24\x08", 5);
}

static bool rap_hw_error_entry(struct rap_sequence *s)
{
	struct rap_kexec_sequence k = { .seq = *s };
	struct rap_sequence *p = &k.seq;
	struct instruction *insn;

	if (!rap_hw_save_regs(p))
		return false;
	rap_sequence_bytes(p, "\x48\x8d\x6c\x24\x09", 5);
	if (!rap_sequence_bytes(p, "\xf6\x84\x24\x90\0\0\0\x03", 8) ||
	    !rap_kexec_branch(&k, 0x74, 0) || !rap_hw_user_entry(p) ||
	    !rap_entry_call(p, "sync_regs") || !rap_sequence_edge_match(p, "__hdn_rap_return", false, false) ||
	    !rap_kexec_label(&k, 0) ||
	    !rap_sequence_reference(p, "\x48\x8d\x0d", 3, "native_irq_return_iret", true) ||
	    !rap_sequence_bytes(p, "\x48\x39\x8c\x24\x88\0\0\0", 8) ||
	    !rap_kexec_branch(&k, 0x74, 2) || !rap_sequence_bytes(p, "\x89\xc8", 2) ||
	    !rap_sequence_bytes(p, "\x48\x39\x84\x24\x88\0\0\0", 8) ||
	    !rap_kexec_branch(&k, 0x74, 1) ||
	    !rap_sequence_reference(p, "\x48\x81\xbc\x24\x88\0\0\0", 8, "__hdn_rap_gs_change", false) ||
	    !rap_kexec_branch(&k, 0x75, 3) || !rap_sequence_bytes(p, "\x0f\x01\xf8", 3) ||
	    !rap_kexec_label(&k, 3) ||
	    !rap_hw_fixed_alt(p, "X86_FEATURE_FENCE_SWAPGS_KERNEL", "\x0f\xae\xe8", 3) ||
	    !rap_hw_depth(p) || !rap_sequence_bytes(p, "\x48\x8d\x44\x24\x08", 5))
		return false;
	insn = find_insn(p->file, p->func->sec, p->func->offset + p->pos);
	if (insn && !insn->alts)
		rap_sequence_bytes(p, "\x90", 1);
	if (!rap_thunk_ret(p) || !rap_kexec_label(&k, 1) ||
	    !rap_sequence_bytes(p, "\x48\x89\x8c\x24\x88\0\0\0", 8) ||
	    !rap_kexec_label(&k, 2) || !rap_hw_user_entry(p) ||
	    !rap_entry_call(p, "fixup_bad_iret") || !rap_sequence_bytes(p, "\x48\x89\xc7", 3) ||
	    !rap_entry_call(p, "sync_regs") || !rap_sequence_edge_match(p, "__hdn_rap_return", false, false) ||
	    !rap_hw_local_edges(&k))
		return false;
	*s = *p;
	return true;
}

static bool rap_hw_paranoid_entry(struct rap_sequence *s)
{
	struct rap_kexec_sequence k = { .seq = *s };
	struct rap_sequence *p = &k.seq;

	if (!rap_hw_save_regs(p))
		return false;
	rap_sequence_bytes(p, "\x48\x8d\x6c\x24\x09", 5);
	if (!rap_hw_kernel_cr3(p, true) || !rap_hw_skip(&k, "X86_FEATURE_FSGSBASE", 0) ||
	    !rap_sequence_bytes(p, "\xf3\x48\x0f\xae\xcb", 5))
		return false;
	if (rap_sequence_bytes(p, "\x48\xc7\xc0\x7b\0\0\0", 7)) {
		if (!rap_sequence_bytes(p, "\x48\x0f\x03\xc0\x48\x25\xff\x0f\0\0", 10) ||
		    !rap_sequence_reference(p, "\x48\x8b\x04\xc5", 4, "__per_cpu_offset", false))
			return false;
	} else if (!rap_sequence_reference(p, "\x48\x8b\x05", 3, "pcpu_unit_offsets", true)) {
		return false;
	}
	if (!rap_sequence_bytes(p, "\xf3\x48\x0f\xae\xd8", 5) ||
	    !rap_kexec_branch(&k, 0xeb, 1) || !rap_kexec_label(&k, 0) ||
	    !rap_sequence_bytes(p, "\xbb\x01\0\0\0\xb9\x01\x01\0\xc0\x0f\x32\x85\xd2", 14) ||
	    !rap_kexec_branch(&k, 0x78, 2) || !rap_sequence_bytes(p, "\x31\xdb\x0f\x01\xf8", 5) ||
	    !rap_kexec_label(&k, 2) ||
	    !rap_hw_fixed_alt(p, "X86_FEATURE_FENCE_SWAPGS_KERNEL", "\x0f\xae\xe8", 3) ||
	    !rap_kexec_label(&k, 1) || !rap_hw_ibrs(p, true, true) ||
	    !rap_hw_untrain(p, true) || !rap_thunk_ret(p) || !rap_hw_local_edges(&k))
		return false;
	*s = *p;
	return true;
}

static bool rap_hw_paranoid_exit(struct rap_sequence *s)
{
	struct rap_kexec_sequence k = { .seq = *s };
	struct rap_sequence *p = &k.seq;

	if (!rap_idt_frame_exit(p, 1) || !rap_hw_ibrs(p, false, true) ||
	    !rap_hw_restore_cr3(p, false) || !rap_hw_skip(&k, "X86_FEATURE_FSGSBASE", 0) ||
	    !rap_sequence_bytes(p, "\xf3\x48\x0f\xae\xdb", 5) ||
	    !rap_sequence_edge_match(p, "restore_regs_and_return_to_kernel", false, false) ||
	    !rap_kexec_label(&k, 0) || !rap_sequence_bytes(p, "\x85\xdb", 2) ||
	    !rap_hw_branch(p, "restore_regs_and_return_to_kernel", 0x75) ||
	    !rap_sequence_bytes(p, "\x0f\x01\xf8", 3) ||
	    !rap_sequence_edge_match(p, "restore_regs_and_return_to_kernel", false, false) ||
	    !rap_hw_local_edges(&k))
		return false;
	*s = *p;
	return true;
}

static int verify_rap_entry_root(struct objtool_file *file, struct symbol *func)
{
	struct rap_sequence s = { .file = file, .func = func };
	struct instruction *insn;

	if (is_weak_sym(func) || !func->sec->noinstr || func->rap_kind != rap_entry_root_kind(func->name))
		goto bad;
	if (func->rap_kind == 37 ? !rap_hw_error_entry(&s) :
	    func->rap_kind == 38 ? !rap_hw_paranoid_entry(&s) : !rap_hw_paranoid_exit(&s))
		goto bad;
	if (s.pos != func->len)
		goto bad;
	rap_for_each_insn(file, func, insn)
		if (insn->alts && !insn->rap_hw_alt && !insn->rap_thunk_alt)
			goto bad;
	func->rap_entry_root_protocol = true;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s.pos, "RAP pre-C entry/exit helper differs from its closed frame protocol");
	return -1;
}

static int validate_rap_entry_root_peers(struct objtool_file *file)
{
	struct instruction *insn;
	struct symbol *func;
	bool present = false;

	for_each_sym(file->elf, func) {
		if (!rap_entry_root_kind(func->name) || is_undef_sym(func))
			continue;
		present = true;
		if (func->rap_kind != rap_entry_root_kind(func->name) || !func->rap_entry_root_protocol)
			goto bad;
	}
	if (opts.link && present) {
		static const struct { const char *name; unsigned int kind; } peers[] = {
			{ "sync_regs", 1 }, { "fixup_bad_iret", 1 },
			{ "__hdn_rap_enter", 4 }, { "__hdn_rap_return", 4 },
			{ "hdn_rap_frame_exit", 2 }, { "asm_load_gs_index", 1 },
		};
		struct symbol *change = find_symbol_by_name(file->elf, "__hdn_rap_gs_change");
		struct symbol *load = find_symbol_by_name(file->elf, "asm_load_gs_index");
		unsigned int i;

		for (i = 0; i < ARRAY_SIZE(peers); i++) {
			struct symbol *peer = find_symbol_by_name(file->elf, peers[i].name);
			if (!peer || peer->rap_kind != peers[i].kind)
				goto bad;
		}
		if (!change || !load || change->sec != load->sec || change->offset < load->offset ||
		    change->offset - load->offset + 2 > load->len ||
		    memcmp(change->sec->data->d_buf + change->offset, "\x8e\xef", 2))
			goto bad;
	}
	for_each_insn(file, insn) {
		struct symbol *owner = rap_entry_owner(insn);
		struct instruction *dest;
		struct section *sec;
		unsigned long offset;

		if (!rap_thunk_edge_target(file, insn, &sec, &offset))
			continue;
		dest = find_insn(file, sec, offset);
		func = dest ? rap_insn_owner(dest) : NULL;
		if (!func || !func->rap_entry_root_protocol || owner == func)
			continue;
		if (offset != func->offset || !owner)
			goto bad;
		if (func->rap_kind == 37 && insn->type == INSN_CALL && owner->rap_idt_protocol &&
		    (owner->rap_kind == 33 || owner->rap_kind == 34))
			continue;
		if (func->rap_kind == 38 && insn->type == INSN_CALL &&
		    ((owner->rap_kind == 34 && owner->rap_idt_protocol) ||
		     (!strcmp(owner->name, "asm_exc_nmi") && owner->rap_kind == 41)))
			continue;
		if (func->rap_kind == 39 && insn->type == INSN_JUMP_UNCONDITIONAL &&
		    owner->rap_kind == 34 && owner->rap_idt_protocol)
			continue;
		goto bad;
	}
	return 0;
bad:
	ERROR("RAP pre-C entry helper has an unverified caller or an interior entry");
	return -1;
}
