/* SPDX-License-Identifier: GPL-2.0-only */
/* The nested-NMI loop has two architectural frames. Both the assembly frame
 * construction and the runtime's single permitted repeat target are checked. */
static int verify_rap_nmi(struct objtool_file *file, struct symbol *func)
{
	struct rap_kexec_sequence k = { .seq = { .file = file, .func = func } };
	struct rap_sequence *s = &k.seq;
	struct instruction *insn;
	unsigned int i;

#define NMI_BYTES(bytes) do { if (!rap_sequence_bytes(s, bytes, sizeof(bytes) - 1)) goto bad; } while (0)
#define NMI_BRANCH(op, label) do { if (!rap_kexec_branch(&k, op, label)) goto bad; } while (0)
#define NMI_LABEL(label) do { if (!rap_kexec_label(&k, label)) goto bad; } while (0)
	if (strcmp(func->name, "asm_exc_nmi") || is_weak_sym(func) || !func->sec->noinstr ||
	    !rap_hw_endbr(s) || !rap_hw_fixed_alt(s, "X86_FEATURE_SMAP", "\x0f\x01\xca", 3))
		goto bad;
	NMI_BYTES("\xfc\x52\xf6\x44\x24\x10\x03");
	NMI_BRANCH(0x74, 0);
	NMI_BYTES("\x0f\x01\xf8");
	if (!rap_hw_fixed_alt(s, "X86_FEATURE_FENCE_SWAPGS_USER", "\x0f\xae\xe8", 3) ||
	    !rap_hw_switch_kernel_cr3(s, 2))
		goto bad;
	NMI_BYTES("\x48\x89\xe2");
	if (!rap_thunk_percpu(s, "\x48\x8b\x25", 3, "", 0, "cpu_current_top_of_stack"))
		goto bad;
	NMI_BYTES("\xff\x72\x28\xff\x72\x20\xff\x72\x18\xff\x72\x10\xff\x72\x08\x6a\xff");
	/* PUSH_AND_CLEAR_REGS rdx=(%rdx). */
	NMI_BYTES("\x57\x56\xff\x32\x51\x50\x41\x50\x41\x51\x41\x52\x41\x53"
		  "\x53\x55\x41\x54\x41\x55\x41\x56\x41\x57"
		  "\x31\xf6\x31\xd2\x31\xc9\x45\x31\xc0\x45\x31\xc9\x45\x31\xd2"
		  "\x45\x31\xdb\x31\xdb\x31\xed\x45\x31\xe4\x45\x31\xed\x45\x31\xf6\x45\x31\xff");
	rap_sequence_bytes(s, "\x48\x8d\x6c\x24\x01", 5);
	if (!rap_hw_ibrs(s, true, false) || !rap_hw_untrain(s, false))
		goto bad;
	NMI_BYTES("\x48\x89\xe7");
	if (!rap_entry_call(s, "exc_nmi") ||
	    !rap_sequence_edge_match(s, "swapgs_restore_regs_and_return_to_usermode", false, false))
		goto bad;
	NMI_LABEL(0);
	if (!rap_sequence_reference(s, "\x48\xc7\xc2", 3, "repeat_nmi", false))
		goto bad;
	NMI_BYTES("\x48\x3b\x54\x24\x08");
	NMI_BRANCH(0x77, 1);
	if (!rap_sequence_reference(s, "\x48\xc7\xc2", 3, "end_repeat_nmi", false))
		goto bad;
	NMI_BYTES("\x48\x3b\x54\x24\x08");
	NMI_BRANCH(0x77, 3);
	NMI_LABEL(1);
	NMI_BYTES("\x83\x7c\x24\xf8\x01");
	NMI_BRANCH(0x74, 2);
	NMI_BYTES("\x48\x8d\x54\x24\x30\x48\x39\x54\x24\x20");
	NMI_BRANCH(0x77, 4);
	if (!rap_sequence_bytes(s, "\x48\x81\xea\0\x20\0\0", 7) &&
	    !rap_sequence_bytes(s, "\x48\x81\xea\0\x40\0\0", 7))
		goto bad;
	NMI_BYTES("\x48\x39\x54\x24\x20");
	NMI_BRANCH(0x72, 4);
	NMI_BYTES("\xf6\x44\x24\x19\x04");
	NMI_BRANCH(0x74, 4);
	NMI_LABEL(2);
	NMI_BYTES("\x48\x83\xec\x08\x48\x8d\x54\x24\xb0\x6a\x18\x52\x9c\x6a\x10");
	if (!rap_sequence_reference(s, "\x68", 1, "repeat_nmi", false))
		goto bad;
	NMI_BYTES("\x48\x83\xc4\x30");
	NMI_LABEL(3);
	NMI_BYTES("\x5a\x48\xcf");
	NMI_LABEL(4);
	NMI_BYTES("\x48\x8b\x14\x24\x6a\0\x48\x83\xec\x28");
	for (i = 0; i < 5; i++)
		NMI_BYTES("\xff\x74\x24\x58");
	/* DEBUG_ENTRY unmasks NMI using a fixed, immediately following IRET. */
	if (rap_sequence_bytes(s, "\x6a\0", 2)) {
		NMI_BYTES("\x54\x48\x83\x04\x24\x08\x9c\x6a\x10");
		if (!rap_sequence_reference(s, "\x68", 1, "repeat_nmi", false))
			goto bad;
		NMI_BYTES("\x48\xcf");
	}
	if (!rap_thunk_symbol(file, "repeat_nmi", func->sec, func->offset + s->pos) ||
	    !rap_thunk_symbol(file, "__hdn_rap_repeat_nmi", func->sec, func->offset + s->pos))
		goto bad;
	NMI_BYTES("\x48\xc7\x44\x24\x50\x01\0\0\0\x48\x83\xc4\x50");
	for (i = 0; i < 5; i++)
		NMI_BYTES("\xff\x74\x24\xd0");
	NMI_BYTES("\x48\x83\xec\x28");
	if (!rap_thunk_symbol(file, "end_repeat_nmi", func->sec, func->offset + s->pos))
		goto bad;
	NMI_BYTES("\x6a\xff");
	if (!rap_sequence_edge_match(s, "paranoid_entry", true, false) ||
	    !rap_idt_frame_enter(s, 2, 2))
		goto bad;
	NMI_BYTES("\x48\x89\xe7");
	if (!rap_entry_call(s, "exc_nmi") || !rap_idt_frame_exit(s, 2) ||
	    !rap_hw_ibrs(s, false, true) || !rap_hw_restore_cr3(s, true) ||
	    !rap_hw_skip(&k, "X86_FEATURE_FSGSBASE", 5))
		goto bad;
	NMI_BYTES("\xf3\x48\x0f\xae\xdb");
	NMI_BRANCH(0xeb, 6);
	NMI_LABEL(5);
	NMI_BYTES("\x85\xdb");
	NMI_BRANCH(0x75, 6);
	NMI_BYTES("\x0f\x01\xf8");
	NMI_LABEL(6);
	if (!rap_entry_pop_regs(s))
		goto bad;
	NMI_BYTES("\x48\x83\xc4\x30\xfd\x48\xc7\x44\x24\x28\0\0\0\0\x48\xcf");
	if (s->pos != func->len || !rap_hw_local_edges(&k))
		goto bad;
	rap_for_each_insn(file, func, insn)
		if (insn->alts && !insn->rap_hw_alt && !insn->rap_thunk_alt)
			goto bad;
	func->rap_nmi_protocol = true;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s->pos, "RAP NMI entry differs from its nested-frame protocol");
	return -1;
#undef NMI_LABEL
#undef NMI_BRANCH
#undef NMI_BYTES
}

static int validate_rap_nmi_peers(struct objtool_file *file)
{
	struct symbol *nmi = find_symbol_by_name(file->elf, "asm_exc_nmi");
	struct instruction *insn;

	if (!nmi || is_undef_sym(nmi))
		return 0;
	if (!nmi->rap_nmi_protocol || nmi->rap_kind != 41)
		goto bad;
	if (opts.link) {
		static const char * const names[] = { "exc_nmi", "hdn_rap_frame_enter", "hdn_rap_frame_exit" };
		unsigned int i;
		for (i = 0; i < ARRAY_SIZE(names); i++) {
			struct symbol *target = find_symbol_by_name(file->elf, names[i]);
			if (!target || target->rap_kind != (i ? 2 : 1))
				goto bad;
		}
	}
	for_each_insn(file, insn) {
		struct symbol *owner = rap_entry_owner(insn);
		struct section *sec;
		unsigned long offset;

		if (!rap_thunk_edge_target(file, insn, &sec, &offset) || sec != nmi->sec ||
		    offset < nmi->offset || offset >= nmi->offset + nmi->len || owner == nmi)
			continue;
		if (offset == nmi->offset && insn->type == INSN_CALL && owner && owner->rap_kind == 13 &&
		    owner->rap_hardware_event && !strcmp(owner->name, "vmx_do_nmi_irqoff"))
			continue;
		goto bad;
	}
	return 0;
bad:
	ERROR("RAP NMI root has an unverified handler or incoming transfer");
	return -1;
}
