/* SPDX-License-Identifier: GPL-2.0-only */
/* Independent native IDT shapes. Neither a coverage record nor a handler
 * relocation is authority to change the architectural vector or frame ABI. */
struct rap_idt_shape {
	const char *handler;
	unsigned int vector;
	bool error, paranoid;
};

#define RAP_IDT(_handler, _vector) \
	{ .handler = (_handler), .vector = (_vector) }
#define RAP_IDT_ERROR(_handler, _vector) \
	{ .handler = (_handler), .vector = (_vector), .error = true }
#define RAP_IDT_PARANOID(_handler, _vector) \
	{ .handler = (_handler), .vector = (_vector), .paranoid = true }
#define RAP_IDT_ERROR_PARANOID(_handler, _vector) \
	{ .handler = (_handler), .vector = (_vector), .error = true, .paranoid = true }

static const struct rap_idt_shape rap_idt_shapes[] = {
	RAP_IDT("exc_divide_error", 0),
	RAP_IDT_PARANOID("exc_debug", 1),
	RAP_IDT("exc_nmi_kvm_vmx", 2),
	RAP_IDT("exc_int3", 3),
	RAP_IDT("exc_overflow", 4),
	RAP_IDT("exc_bounds", 5),
	RAP_IDT("exc_invalid_op", 6),
	RAP_IDT("exc_device_not_available", 7),
	RAP_IDT_ERROR_PARANOID("exc_double_fault", 8),
	RAP_IDT("exc_coproc_segment_overrun", 9),
	RAP_IDT_ERROR("exc_invalid_tss", 10),
	RAP_IDT_ERROR("exc_segment_not_present", 11),
	RAP_IDT_ERROR("exc_stack_segment", 12),
	RAP_IDT_ERROR("exc_general_protection", 13),
	RAP_IDT_ERROR("exc_page_fault", 14),
	RAP_IDT("exc_spurious_interrupt_bug", 15),
	RAP_IDT("exc_coprocessor_error", 16),
	RAP_IDT_ERROR("exc_alignment_check", 17),
	RAP_IDT_PARANOID("exc_machine_check", 18),
	RAP_IDT("exc_simd_coprocessor_error", 19),
	RAP_IDT("exc_virtualization_exception", 20),
	RAP_IDT_ERROR("exc_control_protection", 21),
	RAP_IDT("int80_emulation", 128),
	RAP_IDT_ERROR("common_interrupt", 256),
	RAP_IDT_ERROR("spurious_interrupt", 256),
	RAP_IDT("sysvec_posted_msi_notification", 0xeb),
	RAP_IDT("sysvec_apic_timer_interrupt", 0xec),
	RAP_IDT("sysvec_hyperv_stimer0", 0xed),
	RAP_IDT("sysvec_hyperv_reenlightenment", 0xee),
	RAP_IDT("sysvec_kvm_posted_intr_nested_ipi", 0xf0),
	RAP_IDT("sysvec_kvm_posted_intr_wakeup_ipi", 0xf1),
	RAP_IDT("sysvec_kvm_posted_intr_ipi", 0xf2),
	RAP_IDT("sysvec_hyperv_callback", 0xf3),
	RAP_IDT("sysvec_acrn_hv_callback", 0xf3),
	RAP_IDT("sysvec_xen_hvm_callback", 0xf3),
	RAP_IDT("sysvec_kvm_asyncpf_interrupt", 0xf3),
	RAP_IDT("sysvec_deferred_error", 0xf4),
	RAP_IDT("sysvec_perf_guest_mediated_pmi_handler", 0xf5),
	RAP_IDT("sysvec_irq_work", 0xf6),
	RAP_IDT("sysvec_x86_platform_ipi", 0xf7),
	RAP_IDT("sysvec_reboot", 0xf8),
	RAP_IDT("sysvec_threshold", 0xf9),
	RAP_IDT("sysvec_thermal", 0xfa),
	RAP_IDT("sysvec_call_function_single", 0xfb),
	RAP_IDT("sysvec_call_function", 0xfc),
	RAP_IDT("sysvec_reschedule_ipi", 0xfd),
	RAP_IDT("sysvec_error_interrupt", 0xfe),
	RAP_IDT("sysvec_spurious_apic_interrupt", 0xff),
};

#undef RAP_IDT_ERROR_PARANOID
#undef RAP_IDT_PARANOID
#undef RAP_IDT_ERROR
#undef RAP_IDT

static const struct rap_idt_shape *rap_idt_shape(const char *name)
{
	unsigned int i;

	if (strncmp(name, "asm_", 4))
		return NULL;
	for (i = 0; i < ARRAY_SIZE(rap_idt_shapes); i++)
		if (!strcmp(name + 4, rap_idt_shapes[i].handler))
			return &rap_idt_shapes[i];
	return NULL;
}

static unsigned int rap_idt_kind(const char *name)
{
	const struct rap_idt_shape *shape = rap_idt_shape(name);

	if (shape)
		return shape->paranoid ? 34 : 33;
	if (!strcmp(name, "irq_entries_start") || !strcmp(name, "spurious_entries_start"))
		return 35;
	if (!strcmp(name, "error_return"))
		return 36;
	return 0;
}

static void rap_hw_mark(struct objtool_file *file, struct symbol *span)
{
	struct instruction *insn;

	for_each_insn(file, insn)
		if (insn->sec == span->sec && insn->offset >= span->offset &&
		    insn->offset < span->offset + span->len)
			insn->rap_hw_safe = true;
}

/* A single NOP -> fixed instruction alternative. All feature/flag bits,
 * original padding and replacement bytes are part of the protocol. */
static bool rap_hw_fixed_alt(struct rap_sequence *s, const char *feature,
		const char *bytes, unsigned long size)
{
	struct instruction *first = find_insn(s->file, s->func->sec, s->func->offset + s->pos);
	struct alt_group *orig = first ? first->alt_group : NULL, *g;
	struct alternative *alt;
	struct symbol span;
	struct rap_sequence body;
	const char *actual;
	unsigned long end;

	if (!orig || orig->orig_group || orig->first_insn != first || !orig->last_insn ||
	    !(alt = first->alts) || alt->next || alt->type != ALT_TYPE_INSTRUCTIONS ||
	    !(g = alt->insn->alt_group) || g->orig_group != orig ||
	    g->first_insn != alt->insn || !g->last_insn || g->feature >> 16 ||
	    !(actual = arch_cpu_feature_name(g->feature)) || strcmp(actual, feature))
		return false;
	end = orig->last_insn->offset + orig->last_insn->len - s->func->offset;
	if (end > s->func->len || end < s->pos || end - s->pos != size)
		return false;
	span = *s->func;
	span.sec = alt->insn->sec;
	span.offset = alt->insn->offset;
	span.len = g->last_insn->offset + g->last_insn->len - span.offset;
	body = (struct rap_sequence){ .file = s->file, .func = &span };
	if (span.len != size || !rap_sequence_bytes(&body, bytes, size) ||
	    !rap_thunk_padding(s, end, false))
		return false;
	first->rap_hw_alt = true;
	rap_hw_mark(s->file, &span);
	return true;
}

static bool rap_hw_endbr(struct rap_sequence *s)
{
	struct instruction *insn = find_insn(s->file, s->func->sec, s->func->offset + s->pos);

	return insn && (insn->type != INSN_ENDBR ||
		       rap_sequence_bytes(s, "\xf3\x0f\x1e\xfa", 4));
}

static bool rap_hw_branch(struct rap_sequence *s, const char *name, unsigned char condition)
{
	struct symbol *target = find_symbol_by_name(s->file->elf, name);
	unsigned long offset = s->func->offset + s->pos;
	struct instruction *insn = find_insn(s->file, s->func->sec, offset);
	const unsigned char *p = s->func->sec->data->d_buf + offset;
	struct reloc *reloc;

	if (!target || is_weak_sym(target) || !insn || s->pos >= s->func->len ||
	    insn->len > s->func->len - s->pos || condition < 0x70 || condition > 0x7f ||
	    !((insn->len == 2 && p[0] == condition) ||
	      (insn->len == 6 && p[0] == 0x0f && p[1] == condition + 0x10)))
		return false;
	reloc = find_reloc_by_dest_range(s->file->elf, s->func->sec, offset, insn->len);
	if (reloc) {
		if (insn->len != 6 || reloc_offset(reloc) != offset + 2 ||
		    arch_reloc_size(reloc) != 4 || !arch_pc_relative_reloc(reloc) ||
		    reloc->sym->sec != target->sec ||
		    (is_undef_sym(target) && reloc->sym != target) ||
		    reloc->sym->offset + arch_insn_adjusted_addend(insn, reloc) != target->offset ||
		    find_reloc_by_dest_range(s->file->elf, s->func->sec, offset + 3, 3))
			return false;
	} else if (is_undef_sym(target) || target->sec != s->func->sec ||
		   arch_jump_destination(insn) != target->offset) {
		return false;
	}
	s->pos += insn->len;
	return true;
}

static bool rap_idt_frame_enter(struct rap_sequence *s, unsigned int kind, unsigned int vector)
{
	unsigned char args[] = { 0x48, 0x89, 0xe7, 0xbe, kind, 0, 0, 0,
				0x41, 0xb9, vector & 255, vector >> 8, 0, 0 };

	return rap_sequence_bytes(s, (const char *)args, sizeof(args)) &&
		rap_sequence_bytes(s, kind ? "\x4c\x89\xf2\x48\x89\xd9\x4d\x89\xf8" :
					    "\x31\xd2\x31\xc9\x45\x31\xc0", kind ? 9 : 7) &&
		rap_entry_call(s, "hdn_rap_frame_enter");
}

static bool rap_idt_frame_exit(struct rap_sequence *s, unsigned int kind)
{
	unsigned char args[] = { 0x48, 0x89, 0xe7, 0xbe, kind, 0, 0, 0 };
	bool restore;

	if (!rap_sequence_bytes(s, (const char *)args, sizeof(args)) ||
	    !rap_entry_call(s, "hdn_rap_frame_exit"))
		return false;
	if (kind)
		return rap_sequence_bytes(s, "\x4c\x8b\x30\x48\x8b\x58\x08\x4c\x8b\x78\x10", 11);
	restore = rap_sequence_bytes(s, "\x48\x8b\x10\x0f\x22\xda", 6);
	return !opts.link || restore == !!find_symbol_by_name(s->file->elf, "hdn_stack_mm_ready");
}

static bool rap_idt_save_error(struct rap_sequence *s)
{
	return rap_sequence_bytes(s, "\x4c\x8b\x64\x24\x78"
				    "\x48\xc7\x44\x24\x78\xff\xff\xff\xff", 14);
}

static bool rap_idt_handler(struct rap_sequence *s, const char *name, bool error)
{
	return rap_sequence_bytes(s, "\x48\x89\xe7", 3) &&
		(!error || rap_sequence_bytes(s, "\x4c\x89\xe6", 3)) && rap_entry_call(s, name);
}

static bool rap_idt_normal_body(struct rap_sequence *s, const char *handler,
		unsigned int vector, bool error)
{
	if (!rap_sequence_edge_match(s, "error_entry", true, false) ||
	    !rap_sequence_bytes(s, "\x48\x89\xc4", 3))
		return false;
	/* Frame pointers are a diagnostic option, not an alternative frame ABI. */
	rap_sequence_bytes(s, "\x48\x8d\x6c\x24\x01", 5);
	return (!error || rap_idt_save_error(s)) && rap_idt_frame_enter(s, 0, vector) &&
		rap_idt_handler(s, handler, error) &&
		rap_sequence_edge_match(s, "error_return", false, false);
}

static bool rap_idt_array(struct rap_sequence *s)
{
	bool spurious = !strcmp(s->func->name, "spurious_entries_start");
	struct symbol *other = find_symbol_by_name(s->file->elf, "spurious_entries_start");
	struct instruction *first = find_insn(s->file, s->func->sec, s->func->offset);
	bool ibt = first && first->type == INSN_ENDBR;
	unsigned int stride = ibt ? 16 : 8, vector = spurious ? 0xeb : 0x20;
	unsigned int end = spurious || !other || is_undef_sym(other) ? 256 : 0xeb;
	unsigned int n;

	if (s->func->offset % stride || s->func->len != (end - vector) * stride)
		return false;
	for (n = 0; vector < end; vector++, n++) {
		unsigned char push[] = { 0x6a, vector };

		if ((ibt && !rap_sequence_bytes(s, "\xf3\x0f\x1e\xfa", 4)) ||
		    !rap_sequence_bytes(s, (const char *)push, sizeof(push)) ||
		    !rap_sequence_edge_match(s, spurious ? "asm_spurious_interrupt" :
							  "asm_common_interrupt", false, false) ||
		    !rap_thunk_padding(s, (n + 1) * stride, true))
			return false;
	}
	return true;
}

static int verify_rap_idt(struct objtool_file *file, struct symbol *func)
{
	const struct rap_idt_shape *shape = rap_idt_shape(func->name);
	struct rap_kexec_sequence k = { .seq = { .file = file, .func = func } };
	struct rap_sequence *s = &k.seq;
	struct instruction *insn;
	unsigned int i;
	char noist[96];

	if (is_weak_sym(func) || !func->sec->noinstr || func->rap_kind != rap_idt_kind(func->name))
		goto bad;
	if (func->rap_kind == 35) {
		if (!rap_idt_array(s))
			goto bad;
	} else if (func->rap_kind == 36) {
		/* Native DEBUG_ENTRY uses PUSHF/POP, never an indirect PV call. */
		if (rap_sequence_bytes(s, "\x50", 1)) {
			if (!rap_sequence_bytes(s, "\x9c\x58\xa9\0\x02\0\0", 7) ||
			    !rap_kexec_branch(&k, 0x74, 0) ||
			    !rap_sequence_bytes(s, "\x0f\x0b", 2) || !rap_kexec_label(&k, 0) ||
			    !rap_sequence_bytes(s, "\x58", 1))
				goto bad;
		}
		if (!rap_idt_frame_exit(s, 0) ||
		    !rap_sequence_bytes(s, "\xf6\x84\x24\x88\0\0\0\x03", 8) ||
		    !rap_hw_branch(s, "restore_regs_and_return_to_kernel", 0x74) ||
		    !rap_sequence_edge_match(s, "swapgs_restore_regs_and_return_to_usermode", false, false))
			goto bad;
	} else {
		if (!shape || !rap_hw_endbr(s) ||
		    !rap_hw_fixed_alt(s, "X86_FEATURE_SMAP", "\x0f\x01\xca", 3) ||
		    !rap_sequence_bytes(s, "\xfc", 1) ||
		    (!shape->error && !rap_sequence_bytes(s, "\x6a\xff", 2)))
			goto bad;
		if (shape->paranoid) {
			if ((!shape->error &&
			     (!rap_sequence_bytes(s, "\xf6\x44\x24\x10\x03", 5) ||
			      !rap_kexec_branch(&k, 0x75, 0))) ||
			    !rap_sequence_edge_match(s, "paranoid_entry", true, false) ||
			    (shape->error && !rap_idt_save_error(s)) ||
			    !rap_idt_frame_enter(s, 1, shape->vector) ||
			    !rap_idt_handler(s, shape->handler, shape->error) ||
			    !rap_sequence_edge_match(s, "paranoid_exit", false, false))
				goto bad;
			if (!shape->error) {
				snprintf(noist, sizeof(noist), "noist_%s", shape->handler);
				if (!rap_kexec_label(&k, 0) ||
				    !rap_idt_normal_body(s, noist, shape->vector, false))
					goto bad;
			}
		} else {
			if (shape->vector == 3) {
				if (!rap_sequence_bytes(s, "\xf6\x44\x24\x10\x03", 5) ||
				    !rap_kexec_branch(&k, 0x75, 0))
					goto bad;
				for (i = 0; i < 6; i++)
					if (!rap_sequence_bytes(s, "\xff\x74\x24\x28", 4))
						goto bad;
				if (!rap_kexec_label(&k, 0))
					goto bad;
			}
			if (!rap_idt_normal_body(s, shape->handler, shape->vector, shape->error))
				goto bad;
		}
	}
	if (s->pos != func->len)
		goto bad;
	for (i = 0; i < k.count; i++)
		if (!k.defined[k.branches[i].label] ||
		    arch_jump_destination(k.branches[i].insn) != k.labels[k.branches[i].label])
			goto bad;
	rap_for_each_insn(file, func, insn)
		if (insn->alts && !insn->rap_hw_alt)
			goto bad;
	func->rap_idt_protocol = true;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s->pos, "RAP IDT entry differs from its native vector/frame protocol");
	return -1;
}

/* Check callers after all bodies are parsed. Hardware and IDT-vector entry
 * points are not ordinary function-pointer targets or callable C functions. */
static int validate_rap_idt_peers(struct objtool_file *file)
{
	struct instruction *insn = NULL;
	struct symbol *func;

	for_each_sym(file->elf, func) {
		unsigned int expected = rap_idt_kind(func->name);
		const struct rap_idt_shape *shape;

		if (!expected || is_undef_sym(func))
			continue;
		if (func->rap_kind != expected || !func->rap_idt_protocol)
			goto bad;
		shape = rap_idt_shape(func->name);
		if (opts.link && shape) {
			struct symbol *handler = find_symbol_by_name(file->elf, shape->handler);
			struct symbol *enter = find_symbol_by_name(file->elf, "hdn_rap_frame_enter");
			struct symbol *leave = find_symbol_by_name(file->elf, "hdn_rap_frame_exit");

			if (!handler || handler->rap_kind != 1 || !enter || enter->rap_kind != 2 ||
			    !leave || leave->rap_kind != 2)
				goto bad;
			if (shape->paranoid && !shape->error) {
				char name[96];
				snprintf(name, sizeof(name), "noist_%s", shape->handler);
				handler = find_symbol_by_name(file->elf, name);
				if (!handler || handler->rap_kind != 1)
					goto bad;
			}
		}
	}
	func = NULL;
	for_each_insn(file, insn) {
		struct symbol *owner = rap_entry_owner(insn);
		struct instruction *dest;
		struct section *sec;
		unsigned long offset;

		if (insn->rap_hw_safe && insn->alts && !insn->rap_hw_alt)
			goto bad;
		if (!rap_thunk_edge_target(file, insn, &sec, &offset))
			continue;
		dest = find_insn(file, sec, offset);
		func = dest ? rap_insn_owner(dest) : NULL;
		if (!func || !func->rap_idt_protocol || owner == func)
			continue;
		/* KVM VMX NMI injection constructs an architectural frame in a
		 * separately closed kind-13 wrapper, then CALLs the one dedicated
		 * IDT entry.  Admit only that exact reviewed pairing. */
		if (offset == func->offset && insn->type == INSN_CALL && owner &&
		    owner->rap_kind == 13 && owner->rap_hardware_event &&
		    !strcmp(owner->name, "idt_do_nmi_irqoff") &&
		    !strcmp(func->name, "asm_exc_nmi_kvm_vmx"))
			continue;
		if (offset != func->offset || insn->type != INSN_JUMP_UNCONDITIONAL || !owner)
			goto bad;
		if (func->rap_kind == 36 && owner->rap_idt_protocol &&
		    (owner->rap_kind == 33 || owner->rap_kind == 34))
			continue;
		if (func->rap_kind == 33 && owner->rap_idt_protocol && owner->rap_kind == 35 &&
		    ((!strcmp(owner->name, "irq_entries_start") && !strcmp(func->name, "asm_common_interrupt")) ||
		     (!strcmp(owner->name, "spurious_entries_start") && !strcmp(func->name, "asm_spurious_interrupt"))))
			continue;
		goto bad;
	}
	return 0;
bad:
	if (insn) {
		struct symbol *owner = rap_entry_owner(insn);

		ERROR_INSN(insn,
			   "RAP native IDT entry has an unauthorized incoming edge from %s (kind %u, protocol %u, type %u)%s%s",
			   owner ? owner->name : "<none>", owner ? owner->rap_kind : 0,
			   owner ? owner->rap_hardware_event : 0, insn->type,
			   func ? " to " : "", func ? func->name : "");
	}
	else if (func)
		ERROR_FUNC(func->sec, func->offset,
			   "RAP native IDT entry has an unverified handler or runtime peer");
	else
		ERROR("RAP native IDT validation failed without a resolved peer or edge");
	return -1;
}
