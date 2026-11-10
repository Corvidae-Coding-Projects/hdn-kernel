/* SPDX-License-Identifier: GPL-2.0-only */
/* These roots run after the virtual boot stack and GS have been installed.
 * They do not authorize calls back into the physical-address boot domain. */
static int verify_rap_early_idt(struct objtool_file *file, struct symbol *func)
{
	struct rap_sequence s = { .file = file, .func = func };
	struct instruction *insn;
	unsigned int vector, stride;
	bool ibt;

	if (is_weak_sym(func) || !func->sec->init)
		goto bad;
	if (func->rap_kind == 46) {
		insn = find_insn(file, func->sec, func->offset);
		ibt = insn && insn->type == INSN_ENDBR;
		stride = ibt ? 13 : 9;
		if (func->len != 32 * stride)
			goto bad;
		for (vector = 0; vector < 32; vector++) {
			unsigned char push[] = { 0x6a, vector };

			if ((ibt && !rap_sequence_bytes(&s, "\xf3\x0f\x1e\xfa", 4)) ||
			    (!(0x20027d00U & (1U << vector)) && !rap_sequence_bytes(&s, "\x6a\0", 2)) ||
			    !rap_sequence_bytes(&s, (const char *)push, sizeof(push)) ||
			    !rap_sequence_edge_match(&s, "early_idt_handler_common", false, false) ||
			    !rap_thunk_padding(&s, (vector + 1) * stride, true))
				goto bad;
		}
	} else {
		if (!rap_sequence_bytes(&s, "\xfc", 1) ||
		    !rap_sequence_reference(&s, "\xff\x05", 2, "early_recursion_flag", true) ||
		    !rap_sequence_bytes(&s,
			"\x56\x48\x8b\x74\x24\x08\x48\x89\x7c\x24\x08\x52\x51\x50"
			"\x41\x50\x41\x51\x41\x52\x41\x53\x53\x55\x41\x54\x41\x55\x41\x56\x41\x57"
			"\x49\x89\xf4\x49\x89\xf1\x48\x89\xe7\x31\xf6\x31\xd2\x31\xc9\x45\x31\xc0", 50) ||
		    !rap_entry_call(&s, "hdn_rap_frame_enter") ||
		    !rap_sequence_bytes(&s, "\x4c\x89\xe6\x48\x89\xe7", 6) ||
		    !rap_entry_call(&s, "do_early_exception") || !rap_idt_frame_exit(&s, 0) ||
		    !rap_sequence_reference(&s, "\xff\x0d", 2, "early_recursion_flag", true) ||
		    !rap_sequence_edge_match(&s, "restore_regs_and_return_to_kernel", false, false))
			goto bad;
	}
	if (s.pos != func->len)
		goto bad;
	rap_for_each_insn(file, func, insn)
		if (insn->alts)
			goto bad;
	func->rap_early_idt_protocol = true;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s.pos, "RAP early IDT root lacks its complete vector/frame protocol");
	return -1;
}

static int validate_rap_early_idt_peers(struct objtool_file *file)
{
	struct symbol *array = find_symbol_by_name(file->elf, "early_idt_handler_array");
	struct symbol *common = find_symbol_by_name(file->elf, "early_idt_handler_common");
	struct instruction *insn;

	if (!array || is_undef_sym(array))
		return 0;
	if (array->rap_kind != 46 || !array->rap_early_idt_protocol ||
	    !common || common->rap_kind != 47 || !common->rap_early_idt_protocol)
		goto bad;
	if (opts.link) {
		struct symbol *handler = find_symbol_by_name(file->elf, "do_early_exception");
		struct symbol *enter = find_symbol_by_name(file->elf, "hdn_rap_frame_enter");
		struct symbol *exit = find_symbol_by_name(file->elf, "hdn_rap_frame_exit");
		if (!handler || handler->rap_kind != 1 || !enter || enter->rap_kind != 2 ||
		    !exit || exit->rap_kind != 2)
			goto bad;
	}
	for_each_insn(file, insn) {
		struct symbol *owner = rap_entry_owner(insn);
		struct section *sec;
		unsigned long offset;

		if (!rap_thunk_edge_target(file, insn, &sec, &offset))
			continue;
		if (sec == array->sec && offset >= array->offset && offset < array->offset + array->len)
			goto bad;
		if (sec == common->sec && offset >= common->offset && offset < common->offset + common->len &&
		    (owner != array || offset != common->offset || insn->type != INSN_JUMP_UNCONDITIONAL))
			goto bad;
	}
	return 0;
bad:
	ERROR("RAP early IDT has an unverified handler or an unauthorized incoming transfer");
	return -1;
}

/* RIP-relative memory instruction with an immediate following its operand.
 * The relocation's adjusted addend must still identify the exact object. */
static bool rap_head_reference(struct rap_sequence *s, const char *op, size_t size,
		const char *name, const char *tail, size_t tail_size)
{
	struct symbol *target = find_symbol_by_name(s->file->elf, name);
	unsigned long offset = s->func->offset + s->pos;
	struct instruction *insn = find_insn(s->file, s->func->sec, offset);
	struct reloc *reloc;
	const unsigned char *p = s->func->sec->data->d_buf + offset;

	if (!target || is_weak_sym(target) || !insn || insn->len != size + 4 + tail_size ||
	    s->pos > s->func->len || insn->len > s->func->len - s->pos ||
	    memcmp(p, op, size) || memcmp(p + size + 4, tail, tail_size) ||
	    find_reloc_by_dest_range(s->file->elf, s->func->sec, offset, size) ||
	    find_reloc_by_dest_range(s->file->elf, s->func->sec, offset + size + 1, 3 + tail_size))
		return false;
	reloc = find_reloc_by_dest(s->file->elf, s->func->sec, offset + size);
	if (reloc) {
		if (arch_reloc_size(reloc) != 4 || !arch_pc_relative_reloc(reloc) ||
		    reloc->sym->sec != target->sec || (is_undef_sym(target) && reloc->sym != target) ||
		    reloc->sym->offset + arch_insn_adjusted_addend(insn, reloc) != target->offset)
			return false;
	} else {
		int32_t displacement;
		memcpy(&displacement, p + size, 4);
		if (is_undef_sym(target) || target->sec != s->func->sec ||
		    offset + insn->len + displacement != target->offset)
			return false;
	}
	s->pos += insn->len;
	return true;
}

static bool rap_head_ready(struct rap_sequence *s)
{
	return rap_head_reference(s, "\x80\x3d", 2, "hdn_stack_mm_ready", "\0", 1);
}

static bool rap_head_cpu_count(struct rap_sequence *s)
{
	unsigned long offset = s->func->offset + s->pos;
	struct instruction *insn = find_insn(s->file, s->func->sec, offset);
	struct symbol *rows = find_symbol_by_name(s->file->elf, "hdn_stack_startup");
	uint32_t count;
	const unsigned char *p = s->func->sec->data->d_buf + offset;

	if (!insn || insn->len != 5 || *p != 0xb9 || s->pos > s->func->len ||
	    5 > s->func->len - s->pos || find_reloc_by_dest_range(s->file->elf, s->func->sec, offset, 5))
		return false;
	memcpy(&count, p + 1, 4);
	if (!count || count > 65536 || (opts.link && (!rows || rows->len != count * 40)))
		return false;
	s->pos += 5;
	return true;
}

static int verify_rap_startup(struct objtool_file *file, struct symbol *func)
{
	struct rap_kexec_sequence k = { .seq = { .file = file, .func = func } };
	struct rap_sequence *s = &k.seq;
	struct instruction *insn;
	bool s3 = false;

#define HEAD_BYTES(bytes) do { if (!rap_sequence_bytes(s, bytes, sizeof(bytes) - 1)) goto bad; } while (0)
#define HEAD_REF(bytes, name) do { if (!rap_sequence_reference(s, bytes, sizeof(bytes) - 1, name, true)) goto bad; } while (0)
#define HEAD_CALL(name) do { if (!rap_entry_call(s, name)) goto bad; } while (0)
#define HEAD_LABEL(n) do { if (!rap_kexec_label(&k, n)) goto bad; } while (0)
#define HEAD_BRANCH(op, n) do { if (!rap_kexec_branch(&k, op, n)) goto bad; } while (0)
	if (is_weak_sym(func))
		goto bad;
	if (func->rap_kind == 48) {
		HEAD_BYTES("\x49\x89\xf7");
		HEAD_REF("\x48\x8d\x25", "__top_init_kernel_stack");
		HEAD_BYTES("\xb9\x01\x01\0\xc0\x31\xc0\x31\xd2\x0f\x30");
		if (!rap_sequence_edge_match(s, "__pi_startup_64_setup_gdt_idt", true, false))
			goto bad;
		HEAD_BYTES("\x6a\x10\x48\x8d\x05\x03\0\0\0\x50\x48\xcb");
		if (!rap_sequence_edge_match(s, "verify_cpu", true, false))
			goto bad;
		HEAD_REF("\x48\x8d\x3d", "common_startup_64");
		HEAD_REF("\x48\x2b\x3d", "hdn_common_startup_64_ptr");
		HEAD_BYTES("\x4c\x89\xfe");
		if (!rap_sequence_edge_match(s, "__pi___startup_64", true, false))
			goto bad;
		HEAD_REF("\x48\x8d\x0d", "early_top_pgt");
		HEAD_BYTES("\x48\x01\xc8\x0f\x22\xd8");
		HEAD_REF("\xff\x25", "hdn_common_startup_64_ptr");
	} else if (func->rap_kind == 49) {
		if (!rap_sequence_edge_match(s, "verify_cpu", true, false) ||
		    !rap_thunk_symbol(file, "secondary_startup_64_no_verify", func->sec, func->offset + s->pos))
			goto bad;
		HEAD_BYTES("\x45\x31\xff");
		HEAD_REF("\x48\x8b\x05", "phys_base");
		HEAD_REF("\x48\x8d\x0d", "init_top_pgt");
		HEAD_BYTES("\x48\xba\0\0\0\x80\xff\xff\xff\xff\x48\x29\xd1\x48\x01\xc8\x0f\x22\xd8");
		if (!rap_thunk_symbol(file, "common_startup_64", func->sec, func->offset + s->pos))
			goto bad;
	} else {
		HEAD_BYTES("\xba\x20\x10\0\0");
		rap_sequence_bytes(s, "\x83\xca\x40", 3); /* CONFIG_X86_MCE */
		HEAD_BYTES("\x0f\x20\xe1\x21\xd1\x0f\xba\xe9\x04\x0f\x22\xe1\x0f\xba\xe9\x07");
		if (!rap_hw_fixed_alt(s, "X86_FEATURE_FSGSBASE", "\x0f\xba\xe9\x10", 4))
			goto bad;
		HEAD_BYTES("\x0f\x22\xe1");
		if (!rap_head_ready(s))
			goto bad;
		HEAD_BRANCH(0x75, 0);
		HEAD_BYTES("\x31\xd2");
		HEAD_REF("\x48\x8d\x25", "__top_init_kernel_stack");
		HEAD_BRANCH(0xeb, 4);
		HEAD_LABEL(0);
		HEAD_BYTES("\xb9\x1b\0\0\0\x0f\x32\xa9\0\x04\0\0");
		HEAD_BRANCH(0x75, 1);
		if (rap_head_reference(s, "\x83\x3d", 2, "x2apic_mode", "\0", 1)) {
			HEAD_BRANCH(0x74, 2);
			HEAD_BYTES("\x0d\0\x04\0\0\x0f\x30");
			HEAD_BRANCH(0xeb, 1);
		}
		HEAD_LABEL(2);
		HEAD_REF("\x48\x8b\x0d", "apic_mmio_base");
		HEAD_BYTES("\x48\x83\xc1\x20\x8b\x01\xc1\xe8\x18");
		HEAD_BRANCH(0xeb, 3);
		HEAD_LABEL(1);
		HEAD_BYTES("\xb9\x02\x08\0\0\x0f\x32");
		HEAD_BRANCH(0xeb, 3);
		HEAD_LABEL(3);
		HEAD_REF("\x48\x8d\x1d", "hdn_stack_startup");
		if (!rap_head_cpu_count(s))
			goto bad;
		HEAD_LABEL(6);
		HEAD_BYTES("\x48\x3b\x03");
		HEAD_BRANCH(0x75, 5);
		HEAD_BYTES("\x48\x83\x7b\x18\0");
		HEAD_BRANCH(0x74, 5);
		HEAD_BYTES("\x48\x8b\x53\x08\x48\x8b\x43\x18\x0f\x22\xd8\x48\x8b\x63\x10");
		HEAD_BRANCH(0xeb, 4);
		HEAD_LABEL(5);
		HEAD_BYTES("\x48\x83\xc3\x28\xff\xc9");
		HEAD_BRANCH(0x75, 6);
		HEAD_BYTES("\x0f\x0b");
		HEAD_LABEL(4);
		HEAD_REF("\x48\x8b\x05", "trampoline_lock");
		HEAD_BYTES("\x48\x85\xc0");
		HEAD_BRANCH(0x74, 7);
		HEAD_BYTES("\xc7\x00\0\0\0\0");
		HEAD_LABEL(7);
		HEAD_BYTES("\x48\x83\xec\x10\x66\xc7\x04\x24\x7f\0");
		if (!rap_sequence_reference(s, "\x48\x8d\x82", 3, "gdt_page", false))
			goto bad;
		HEAD_BYTES("\x48\x89\x44\x24\x02\x0f\x01\x14\x24\x48\x83\xc4\x10"
			   "\x31\xc0\x8e\xd8\x8e\xd0\x8e\xc0\x8e\xe0\x8e\xe8"
			   "\xb9\x01\x01\0\xc0\x89\xd0\x48\xc1\xea\x20\x0f\x30");
		if (!rap_head_ready(s))
			goto bad;
		HEAD_BRANCH(0x74, 8);
		HEAD_CALL("hdn_stack_mm_cpu_enter");
		HEAD_BYTES("\x49\x89\xc4");
		s3 = rap_sequence_bytes(s, "\x4d\x85\xe4", 3);
		if (s3)
			HEAD_BRANCH(0x75, 9);
		HEAD_CALL("hdn_rap_cpu_restart");
		HEAD_CALL("early_setup_idt");
		HEAD_BRANCH(0xeb, 9);
		HEAD_LABEL(8);
		HEAD_CALL("early_setup_idt");
		HEAD_LABEL(9);
		HEAD_BYTES("\xb8\x01\0\0\x80\x0f\xa2\x89\xd7\xb9\x80\0\0\xc0\x0f\x32"
			   "\x89\xc2\x0f\xba\xe8\0\x0f\xba\xe7\x14");
		HEAD_BRANCH(0x73, 10);
		HEAD_BYTES("\x0f\xba\xe8\x0b");
		if (!rap_head_reference(s, "\x48\x0f\xba\x2d", 4, "early_pmd_flags", "\x3f", 1))
			goto bad;
		HEAD_LABEL(10);
		HEAD_BYTES("\x39\xd0");
		HEAD_BRANCH(0x74, 11);
		HEAD_BYTES("\x31\xd2\x0f\x30");
		HEAD_LABEL(11);
		HEAD_BYTES("\xb8\x33\0\x05\x80\x0f\x22\xc0\x6a\0\x9d\x4c\x89\xff\x31\xed");
		if (!rap_head_ready(s))
			goto bad;
		HEAD_BRANCH(0x74, 12);
		if (s3) {
			HEAD_BYTES("\x4d\x85\xe4");
			if (!rap_hw_branch(s, "wakeup_long64", 0x75))
				goto bad;
		}
		if (opts.link && s3 != !!find_symbol_by_name(file->elf, "wakeup_long64"))
			goto bad;
		HEAD_CALL("start_secondary");
		HEAD_BYTES("\x0f\x0b");
		HEAD_LABEL(12);
		HEAD_CALL("hdn_x86_64_start_kernel");
		HEAD_BYTES("\x0f\x0b");
	}
	if (s->pos != func->len || !rap_hw_local_edges(&k))
		goto bad;
	rap_for_each_insn(file, func, insn)
		if (insn->alts && !insn->rap_hw_alt)
			goto bad;
	func->rap_startup_protocol = true;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s->pos, "RAP startup differs from its native sealed-launch protocol");
	return -1;
#undef HEAD_BYTES
#undef HEAD_REF
#undef HEAD_CALL
#undef HEAD_LABEL
#undef HEAD_BRANCH
}

static int validate_rap_startup_peers(struct objtool_file *file)
{
	struct symbol *boot = find_symbol_by_name(file->elf, "startup_64");
	struct symbol *ap = find_symbol_by_name(file->elf, "secondary_startup_64");
	struct symbol *common = find_symbol_by_name(file->elf, "common_startup_64");
	struct symbol *pointer = find_symbol_by_name(file->elf, "hdn_common_startup_64_ptr");
	struct reloc *reloc;
	struct instruction *insn;
	unsigned int i;
	static const struct { const char *name; unsigned int kind; } calls[] = {
		{ "__pi_startup_64_setup_gdt_idt", 7 }, { "__pi___startup_64", 7 },
		{ "verify_cpu", 29 }, { "hdn_stack_mm_cpu_enter", 2 },
		{ "hdn_rap_cpu_restart", 2 }, { "early_setup_idt", 1 },
		{ "start_secondary", 1 }, { "hdn_x86_64_start_kernel", 1 },
	};
	static const char * const data[] = {
		"hdn_stack_mm_ready", "hdn_stack_startup", "phys_base", "apic_mmio_base", "trampoline_lock",
	};

	if ((!boot || is_undef_sym(boot)) && (!ap || is_undef_sym(ap)) && (!common || is_undef_sym(common)))
		return 0;
	if (!boot || !ap || !common || boot->rap_kind != 48 || ap->rap_kind != 49 || common->rap_kind != 50 ||
	    !boot->rap_startup_protocol || !ap->rap_startup_protocol || !common->rap_startup_protocol ||
	    !boot->sec->init || ap->sec != common->sec || ap->offset + ap->len != common->offset ||
	    !pointer || pointer->len != 8 || strcmp(pointer->sec->name, ".init.rodata"))
		goto bad;
	reloc = find_reloc_by_dest(file->elf, pointer->sec, pointer->offset);
	if (!reloc || reloc_type(reloc) != R_X86_64_64 || reloc->sym->sec != common->sec ||
	    reloc->sym->offset + reloc_addend(reloc) != common->offset ||
	    memcmp(pointer->sec->data->d_buf + pointer->offset, (char[8]){}, 8) ||
	    find_reloc_by_dest_range(file->elf, pointer->sec, pointer->offset + 1, 7))
		goto bad;
	if (opts.link) {
		for (i = 0; i < ARRAY_SIZE(calls); i++) {
			struct symbol *callee = find_symbol_by_name(file->elf, calls[i].name);
			if (!callee || callee->rap_kind != calls[i].kind)
				goto bad;
		}
		for (i = 0; i < ARRAY_SIZE(data); i++) {
			struct symbol *object = find_symbol_by_name(file->elf, data[i]);
			if (!object || strcmp(object->sec->name, ".data..ro_after_init"))
				goto bad;
		}
	}
	for_each_insn(file, insn) {
		struct symbol *owner = rap_entry_owner(insn);
		struct section *sec;
		unsigned long offset;

		if (!rap_thunk_edge_target(file, insn, &sec, &offset))
			continue;
		if (sec == boot->sec && offset >= boot->offset && offset < boot->offset + boot->len)
			goto bad;
		if (sec == ap->sec && offset >= ap->offset && offset < ap->offset + ap->len)
			goto bad;
		if (owner != common && sec == common->sec && offset >= common->offset && offset < common->offset + common->len)
			goto bad;
	}
	return 0;
bad:
	ERROR("RAP startup has an unverified runtime/physical boundary, mutable launch identity or unauthorized direct entry");
	return -1;
}
