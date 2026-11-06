/* SPDX-License-Identifier: GPL-2.0-only */
/* Compat hardware entries keep the IA32 ABI, including the shared SYSRETL
 * exit. Only SYSENTER may join that interior continuation. */
static bool rap_compat_user_cr3(struct rap_sequence *s)
{
	struct rap_kexec_sequence k = { .seq = *s };
	struct rap_sequence *p = &k.seq;

	if (!rap_hw_alt_is(p, "X86_FEATURE_PTI"))
		return true;
	if (!rap_hw_skip(&k, "X86_FEATURE_PTI", 0) ||
	    !rap_sequence_bytes(p, "\x41\x0f\x20\xd8", 4) ||
	    !rap_hw_skip(&k, "X86_FEATURE_PCID", 3) ||
	    !rap_sequence_bytes(p, "\x4d\x89\xc1\x49\x81\xe0\xff\x07\0\0", 10) ||
	    !rap_thunk_percpu_offset(p, "\x4c\x0f\xa3\x05", 4, "", 0, "cpu_tlbstate", 22) ||
	    !rap_kexec_branch(&k, 0x73, 1) ||
	    !rap_thunk_percpu_offset(p, "\x4c\x0f\xb3\x05", 4, "", 0, "cpu_tlbstate", 22) ||
	    !rap_sequence_bytes(p, "\x4d\x89\xc8", 3) || !rap_kexec_branch(&k, 0xeb, 2) ||
	    !rap_kexec_label(&k, 1) || !rap_sequence_bytes(p, "\x4d\x89\xc8\x49\x0f\xba\xe8\x3f", 8) ||
	    !rap_kexec_label(&k, 2) || !rap_sequence_bytes(p, "\x49\x81\xc8\0\x08\0\0", 7) ||
	    !rap_kexec_label(&k, 3) || !rap_sequence_bytes(p, "\x49\x81\xc8\0\x10\0\0\x41\x0f\x22\xd8", 11) ||
	    !rap_kexec_label(&k, 0) || !rap_hw_local_edges(&k))
		return false;
	*s = *p;
	return true;
}

static bool rap_compat_regs(struct rap_sequence *s)
{
	/* SYSCALL uses RBP for arg2; save it in pt_regs.cx. SYSENTER instead
	 * uses the ordinary register helper, which saves RCX in this slot. */
	return rap_sequence_bytes(s,
		"\x57\x56\x52\x55\x6a\xda\x41\x50\x41\x51\x41\x52\x41\x53"
		"\x53\x55\x41\x54\x41\x55\x41\x56\x41\x57"
		"\x31\xf6\x31\xd2\x31\xc9\x45\x31\xc0\x45\x31\xc9\x45\x31\xd2"
		"\x45\x31\xdb\x31\xdb\x31\xed\x45\x31\xe4\x45\x31\xed\x45\x31\xf6\x45\x31\xff", 58);
}

static int verify_rap_compat(struct objtool_file *file, struct symbol *func)
{
	struct rap_kexec_sequence k = { .seq = { .file = file, .func = func } };
	struct rap_sequence *s = &k.seq;
	struct instruction *insn;
	bool sysenter = func->rap_kind == 44;

#define COMPAT_BYTES(bytes) do { if (!rap_sequence_bytes(s, bytes, sizeof(bytes) - 1)) goto bad; } while (0)
#define COMPAT_LABEL(name) do { if (!rap_thunk_symbol(file, name, func->sec, func->offset + s->pos)) goto bad; } while (0)
	if (is_weak_sym(func) || !func->sec->noinstr ||
	    strcmp(func->name, sysenter ? "entry_SYSENTER_compat" : "entry_SYSCALL_compat") || !rap_hw_endbr(s))
		goto bad;
	COMPAT_BYTES("\x0f\x01\xf8");
	if (sysenter) {
		COMPAT_BYTES("\x50");
		if (!rap_hw_switch_kernel_cr3(s, 0))
			goto bad;
		COMPAT_BYTES("\x58");
	} else {
		COMPAT_BYTES("\x41\x89\xe0");
		if (!rap_hw_switch_kernel_cr3(s, 4))
			goto bad;
	}
	if (!rap_thunk_percpu(s, "\x48\x8b\x25", 3, "", 0, "cpu_current_top_of_stack"))
		goto bad;
	if (sysenter) {
		COMPAT_BYTES("\x6a\x2b\x6a\0\x9c\x6a\x23\x6a\0");
		COMPAT_LABEL("entry_SYSENTER_compat_after_hwframe");
	} else {
		COMPAT_LABEL("entry_SYSCALL_compat_safe_stack");
		COMPAT_BYTES("\x6a\x2b\x41\x50\x41\x53\x6a\x23\x51");
		COMPAT_LABEL("entry_SYSCALL_compat_after_hwframe");
	}
	COMPAT_BYTES("\x89\xc0\x50");
	if (!(sysenter ? rap_hw_syscall_regs(s) : rap_compat_regs(s)))
		goto bad;
	if (sysenter) {
		COMPAT_BYTES("\xfc\xf7\x84\x24\x90\0\0\0\0\x41\x04\0");
		if (!rap_kexec_branch(&k, 0x75, 0) || !rap_kexec_label(&k, 1))
			goto bad;
	}
	if (!rap_hw_ibrs(s, true, false) || !rap_hw_untrain(s, false) || !rap_hw_bhb(s))
		goto bad;
	COMPAT_BYTES("\x48\x89\xe7");
	if (!rap_entry_call(s, sysenter ? "do_SYSENTER_32" : "do_fast_syscall_32"))
		goto bad;
	if (sysenter) {
		if (!rap_sequence_edge_match(s, "__hdn_rap_sysret32", false, false) || !rap_kexec_label(&k, 0))
			goto bad;
		COMPAT_BYTES("\x6a\x02\x9d");
		if (!rap_kexec_branch(&k, 0xeb, 1) || !rap_hw_local_edges(&k))
			goto bad;
		COMPAT_LABEL("__end_entry_SYSENTER_compat");
	} else {
		COMPAT_LABEL("__hdn_rap_sysret32");
		COMPAT_BYTES("\x84\xc0");
		if (!rap_hw_branch(s, "swapgs_restore_regs_and_return_to_usermode", 0x74) ||
		    !rap_hw_stack_erase(s, false) || !rap_hw_ibrs(s, false, false))
			goto bad;
		COMPAT_BYTES("\x48\x8b\x5c\x24\x28\x48\x8b\x6c\x24\x20"
			"\x4c\x8b\x9c\x24\x90\0\0\0\x48\x8b\x8c\x24\x80\0\0\0"
			"\x48\x83\xc4\x50\x58\x5a\x5a\x5e\x5f\x48\x8b\x64\x24\x20");
		COMPAT_LABEL("entry_SYSRETL_compat_unsafe_stack");
		if (!rap_compat_user_cr3(s))
			goto bad;
		COMPAT_BYTES("\x45\x31\xc0\x45\x31\xc9\x45\x31\xd2\x0f\x01\xf8");
		if (!rap_hw_clear_buffers(s))
			goto bad;
		COMPAT_BYTES("\x0f\x07");
		COMPAT_LABEL("entry_SYSRETL_compat_end");
		COMPAT_BYTES("\xcc");
	}
	if (s->pos != func->len)
		goto bad;
	rap_for_each_insn(file, func, insn)
		if (insn->alts && !insn->rap_hw_alt && !insn->rap_thunk_alt)
			goto bad;
	func->rap_compat_protocol = true;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s->pos, "RAP compat syscall differs from its complete entry/exit protocol");
	return -1;
#undef COMPAT_LABEL
#undef COMPAT_BYTES
}

static int verify_rap_int80(struct objtool_file *file, struct symbol *func)
{
	struct rap_sequence s = { .file = file, .func = func };
	struct instruction *insn;

	if (is_weak_sym(func) || func->rap_kind != 1 || func->rap_returns != 1 ||
	    !func->sec->noinstr ||
	    !rap_sequence_bytes(&s, "\x4c\x8d\x1d\x05\0\0\0", 7) ||
	    !rap_sequence_edge_match(&s, "__hdn_rap_enter", true, false) ||
	    !rap_hw_bhb(&s) || !rap_entry_call(&s, "do_int80_emulation") ||
	    !rap_sequence_edge(&s, "__hdn_rap_return", false) || s.pos != func->len)
		goto bad;
	rap_for_each_insn(file, func, insn)
		if (insn->alts && !insn->rap_hw_alt)
			goto bad;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s.pos, "RAP int80 bridge lacks its typed entry and protected return");
	return -1;
}

static int validate_rap_compat_peers(struct objtool_file *file)
{
	struct symbol *enter = find_symbol_by_name(file->elf, "entry_SYSENTER_compat");
	struct symbol *call = find_symbol_by_name(file->elf, "entry_SYSCALL_compat");
	struct symbol *resume = find_symbol_by_name(file->elf, "__hdn_rap_sysret32");
	struct symbol *bridge = find_symbol_by_name(file->elf, "int80_emulation");
	struct instruction *insn;
	unsigned int i;
	static const char * const handlers[] = { "do_SYSENTER_32", "do_fast_syscall_32", "do_int80_emulation", "clear_bhb_loop" };

	if ((!enter || is_undef_sym(enter)) && (!call || is_undef_sym(call)))
		return 0;
	if (!enter || !call || is_undef_sym(enter) || is_undef_sym(call) ||
	    enter->rap_kind != 44 || call->rap_kind != 45 ||
	    !enter->rap_compat_protocol || !call->rap_compat_protocol ||
	    !resume || resume->sec != call->sec || !bridge || is_undef_sym(bridge) ||
	    verify_rap_int80(file, bridge))
		goto bad;
	if (opts.link)
		for (i = 0; i < ARRAY_SIZE(handlers); i++) {
			struct symbol *handler = find_symbol_by_name(file->elf, handlers[i]);
			if (!handler || handler->rap_kind != (i == 3 ? 5 : 1))
				goto bad;
		}
	for_each_insn(file, insn) {
		struct symbol *owner = rap_entry_owner(insn);
		struct section *sec;
		unsigned long offset;

		if (!rap_thunk_edge_target(file, insn, &sec, &offset))
			continue;
		if (owner != enter && sec == enter->sec && offset >= enter->offset &&
		    offset < enter->offset + enter->len)
			goto bad;
		if (owner != call && sec == call->sec && offset >= call->offset &&
		    offset < call->offset + call->len &&
		    !(owner == enter && offset == resume->offset && insn->type == INSN_JUMP_UNCONDITIONAL))
			goto bad;
		if (owner != bridge && sec == bridge->sec && offset >= bridge->offset &&
		    offset < bridge->offset + bridge->len &&
		    !(owner && owner->rap_kind == 33 && !strcmp(owner->name, "asm_int80_emulation") &&
		      offset == bridge->offset && insn->type == INSN_CALL && insn->rap_site))
			goto bad;
	}
	return 0;
bad:
	ERROR("RAP compat entry has an unverified handler or an unauthorized incoming transfer");
	return -1;
}
