/* SPDX-License-Identifier: GPL-2.0-only */
static bool rap_hw_bhb(struct rap_sequence *s)
{
	struct rap_kexec_sequence k = { .seq = *s };

	if (!rap_hw_skip(&k, "X86_FEATURE_CLEAR_BHB_LOOP", 0) ||
	    !rap_entry_call(&k.seq, "clear_bhb_loop") || !rap_kexec_label(&k, 0) ||
	    !rap_hw_local_edges(&k))
		return false;
	*s = k.seq;
	return true;
}

static bool rap_hw_syscall_regs(struct rap_sequence *s)
{
	/* PUSH_AND_CLEAR_REGS rax=$-ENOSYS. */
	return rap_sequence_bytes(s,
		"\x57\x56\x52\x51\x6a\xda\x41\x50\x41\x51\x41\x52\x41\x53"
		"\x53\x55\x41\x54\x41\x55\x41\x56\x41\x57"
		"\x31\xf6\x31\xd2\x31\xc9\x45\x31\xc0\x45\x31\xc9\x45\x31\xd2"
		"\x45\x31\xdb\x31\xdb\x31\xed\x45\x31\xe4\x45\x31\xed\x45\x31\xf6\x45\x31\xff", 58);
}

static int verify_rap_syscall(struct objtool_file *file, struct symbol *func)
{
	struct rap_sequence s = { .file = file, .func = func };
	struct instruction *insn;

#define SYSCALL_BYTES(bytes) do { if (!rap_sequence_bytes(&s, bytes, sizeof(bytes) - 1)) goto bad; } while (0)
#define SYSCALL_LABEL(name) do { if (!rap_thunk_symbol(file, name, func->sec, func->offset + s.pos)) goto bad; } while (0)
	if (is_weak_sym(func) || !func->sec->noinstr || strcmp(func->name, "entry_SYSCALL_64") || !rap_hw_endbr(&s))
		goto bad;
	SYSCALL_BYTES("\x0f\x01\xf8");
	if (!rap_thunk_percpu_offset(&s, "\x48\x89\x25", 3, "", 0, "cpu_tss_rw", 20) ||
	    !rap_hw_switch_kernel_cr3(&s, 4) ||
	    !rap_thunk_percpu(&s, "\x48\x8b\x25", 3, "", 0, "cpu_current_top_of_stack"))
		goto bad;
	SYSCALL_LABEL("entry_SYSCALL_64_safe_stack");
	SYSCALL_BYTES("\x6a\x2b");
	if (!rap_thunk_percpu_offset(&s, "\xff\x35", 2, "", 0, "cpu_tss_rw", 20))
		goto bad;
	SYSCALL_BYTES("\x41\x53\x6a\x33\x51");
	SYSCALL_LABEL("entry_SYSCALL_64_after_hwframe");
	SYSCALL_BYTES("\x50");
	if (!rap_hw_syscall_regs(&s))
		goto bad;
	SYSCALL_BYTES("\x48\x89\xe7\x48\x63\xf0");
	if (!rap_hw_ibrs(&s, true, false) || !rap_hw_untrain(&s, false) || !rap_hw_bhb(&s) ||
	    !rap_entry_call(&s, "do_syscall_64"))
		goto bad;
	SYSCALL_BYTES("\x84\xc0");
	if (!rap_hw_branch(&s, "swapgs_restore_regs_and_return_to_usermode", 0x74) ||
	    !rap_hw_ibrs(&s, false, false) || !rap_hw_pop_except_rdi(&s))
		goto bad;
	SYSCALL_BYTES("\x48\x89\xe7");
	if (!rap_thunk_percpu_offset(&s, "\x48\x8b\x25", 3, "", 0, "cpu_tss_rw", 4))
		goto bad;
	SYSCALL_BYTES("\xff\x77\x28\xff\x37");
	if (!rap_hw_stack_erase(&s, true) || !rap_hw_user_cr3_stack(&s))
		goto bad;
	SYSCALL_BYTES("\x5f\x5c");
	SYSCALL_LABEL("entry_SYSRETQ_unsafe_stack");
	SYSCALL_BYTES("\x0f\x01\xf8");
	if (!rap_hw_clear_buffers(&s))
		goto bad;
	SYSCALL_BYTES("\x48\x0f\x07");
	SYSCALL_LABEL("entry_SYSRETQ_end");
	SYSCALL_BYTES("\xcc");
	if (s.pos != func->len)
		goto bad;
	rap_for_each_insn(file, func, insn)
		if (insn->alts && !insn->rap_hw_alt && !insn->rap_thunk_alt)
			goto bad;
	func->rap_syscall_protocol = true;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s.pos, "RAP syscall root differs from its complete native entry/exit protocol");
	return -1;
#undef SYSCALL_LABEL
#undef SYSCALL_BYTES
}

static int validate_rap_syscall_peers(struct objtool_file *file)
{
	struct symbol *func = find_symbol_by_name(file->elf, "entry_SYSCALL_64");
	struct instruction *insn;

	if (!func || is_undef_sym(func))
		return 0;
	if (func->rap_kind != 42 || !func->rap_syscall_protocol)
		goto bad;
	if (opts.link) {
		struct symbol *call = find_symbol_by_name(file->elf, "do_syscall_64");
		struct symbol *bhb = find_symbol_by_name(file->elf, "clear_bhb_loop");
		if (!call || call->rap_kind != 1 || !bhb || bhb->rap_kind != 5)
			goto bad;
	}
	for_each_insn(file, insn) {
		struct section *sec;
		unsigned long offset;
		if (rap_entry_owner(insn) != func && rap_thunk_edge_target(file, insn, &sec, &offset) &&
		    sec == func->sec && offset >= func->offset && offset < func->offset + func->len)
			goto bad;
	}
	return 0;
bad:
	ERROR("RAP syscall root has an unverified handler or an incoming direct transfer");
	return -1;
}
