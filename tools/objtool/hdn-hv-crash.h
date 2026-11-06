/* SPDX-License-Identifier: GPL-2.0-only */
/* Closed Hyper-V devirtualization path, including its mixed-mode copy. */
static unsigned int rap_hv_crash_kind(const char *name)
{
	if (!strcmp(name, "hdn_hv_crash_enter")) return 21;
	if (!strcmp(name, "hdn_hv_crash_return")) return 22;
	if (!strcmp(name, "hdn_hv_crash_continue")) return 23;
	if (!strcmp(name, "hv_crash_asm32")) return 24;
	if (!strcmp(name, "hv_crash_asm64")) return 25;
	return 0;
}

static bool rap_hv_crash_msr(struct rap_sequence *s, unsigned char offset, u32 msr)
{
	unsigned char prefix[] = { 0x48, 0x8b, 0x46, offset, 0x48, 0x89, 0xc2,
		0x48, 0xc1, 0xea, 0x20, 0xb9 };
	unsigned char suffix[] = { msr, msr >> 8, msr >> 16, msr >> 24, 0x0f, 0x30 };
	unsigned char bytes[sizeof(prefix) + sizeof(suffix)];

	memcpy(bytes, prefix, sizeof(prefix));
	memcpy(bytes + sizeof(prefix), suffix, sizeof(suffix));
	return rap_sequence_bytes(s, (char *)bytes, sizeof(bytes));
}

static int verify_rap_hv_crash(struct objtool_file *file, struct symbol *func)
{
	struct rap_sequence s = { .file = file, .func = func };
	struct instruction *insn, *first = find_insn(file, func->sec, func->offset);
	unsigned long far_target = 0;
	unsigned int kind = rap_hv_crash_kind(func->name);
	const char *p;
	s32 displacement;

#define HC_BYTES(bytes) do { if (!rap_sequence_bytes(&s, bytes, sizeof(bytes) - 1)) goto bad; } while (0)
#define HC_REF(bytes, name) do { \
	if (!rap_sequence_reference(&s, bytes, sizeof(bytes) - 1, name, true)) goto bad; \
} while (0)
#define HC_EDGE(name, call, bound) do { \
	if (!rap_sequence_edge_match(&s, name, call, bound)) goto bad; \
} while (0)
#define HC_MSR(off, msr) do { if (!rap_hv_crash_msr(&s, off, msr)) goto bad; } while (0)
	if (!kind || func->rap_kind != kind || is_weak_sym(func) ||
	    (kind == 22 && !func->sec->noinstr))
		goto bad;
	if (first && first->type == INSN_ENDBR)
		HC_BYTES("\xf3\x0f\x1e\xfa");
	if (kind == 21) {
		HC_BYTES("\x4c\x8d\x1d\x05\0\0\0");
		HC_EDGE("__hdn_rap_enter", true, false);
		HC_BYTES("\x48\x89\xe7\x48\x83\xec\x08\x4c\x8d\x15\x05\0\0\0");
		HC_EDGE("hdn_hv_crash_capture", true, true);
		HC_BYTES("\x4c\x8d\x15\x05\0\0\0");
		HC_EDGE("hv_crash_disable", true, true);
		HC_BYTES("\x0f\x0b");
	} else if (kind == 22) {
		HC_REF("\x48\x8d\x35", "hdn_hv_crash_cpu");
		HC_BYTES("\x0f\x01\x56\x68\x8e\x56\x58\x8e\x5e\x5a"
			 "\x8e\x46\x5c\x8e\x66\x5e\x8e\x6e\x60");
		HC_MSR(80, 0x277);
		HC_MSR(48, 0xc0000101);
		HC_MSR(56, 0xc0000102);
		HC_MSR(64, 0xc0000100);
		HC_MSR(72, 0xc0000080);
		HC_BYTES("\x48\x8b\x46\x08\x0f\x22\xc0"
			 "\x48\x8b\x46\x28\x44\x0f\x22\xc0"
			 "\x48\x8b\x46\x20\x0f\x22\xe0"
			 "\x48\x8b\x46\x18\x0f\x22\xd8"
			 "\x48\x8b\x46\x10\x0f\x22\xd0"
			 "\x48\x8b\x26\x0f\x01\x5e\x72\x6a\x10");
		/* The far return restores only the fixed kernel CS and this exact
		 * following landing. No writable return slot selects its target. */
		if (s.pos + 7 > func->len || find_reloc_by_dest_range(file->elf, func->sec,
			func->offset + s.pos, 7))
			goto bad;
		p = func->sec->data->d_buf + func->offset + s.pos;
		if (memcmp(p, "\x48\x8d\x05", 3))
			goto bad;
		memcpy(&displacement, p + 3, 4);
		far_target = func->offset + s.pos + 7 + displacement;
		if (!rap_sequence_bytes(&s, p, 7))
			goto bad;
		HC_BYTES("\x50\x48\xcb");
		if (far_target != func->offset + s.pos)
			goto bad;
		HC_BYTES("\x48\x83\xec\x08\x4c\x8d\x15\x05\0\0\0");
		HC_EDGE("hdn_hv_crash_finish", true, true);
		HC_EDGE("hdn_hv_crash_continue", false, false);
	} else if (kind == 23) {
		HC_BYTES("\x4c\x8d\x15\x05\0\0\0");
		HC_EDGE("hv_crash_handle", true, true);
		HC_BYTES("\x0f\x0b");
	} else if (kind == 24) {
		HC_BYTES("\xb9\x20\0\0\0\x0f\x22\xe1\x89\xfb\x83\xc3\0"
			 "\x2e\x8b\x03\x0f\x22\xd8\xb9\x80\0\0\xc0\x0f\x32"
			 "\x0f\xba\xe8\x08\x0f\x30\x0f\x20\xc0\x0d\0\0\0\x80"
			 "\x0f\x22\xc0\x89\xf8\x83\xc0\x12\x2e\x0f\x01\x10"
			 "\x89\xf8\x83\xc0\x28\x2e\xff\x28");
	} else {
		HC_BYTES("\x89\xf8\x83\xc0\x08\x2e\x67\x48\x8b\x18\x0f\x22\xdb"
			 "\x89\xf8\x83\xc0\x30\x2e\x67\x48\x8b\x18\xff\xe3\xcc");
	}
	if (s.pos != func->len)
		goto bad;
	rap_for_each_insn(file, func, insn)
		if (insn->alts)
			goto bad;
	for_each_insn(file, insn) {
		struct symbol *source = rap_insn_owner(insn);

		if (!insn->jump_dest || insn->jump_dest->sec != func->sec ||
		    insn->jump_dest->offset < func->offset ||
		    insn->jump_dest->offset >= func->offset + func->len || source == func)
			continue;
		if (insn->jump_dest->offset != func->offset ||
		    (kind != 21 && !(kind == 23 && source && source->rap_kind == 22)))
			goto bad;
	}
	func->rap_hv_crash_protocol = true;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s.pos, "RAP Hyper-V crash recovery has an invalid checkpoint protocol");
	return -1;
#undef HC_BYTES
#undef HC_REF
#undef HC_EDGE
#undef HC_MSR
}
