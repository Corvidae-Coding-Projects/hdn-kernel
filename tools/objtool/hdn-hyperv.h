/* SPDX-License-Identifier: GPL-2.0-only */
/* Hypervisor-page calls are a closed foreign ABI. Ordinary C, static calls,
 * and BPF never receive permission to target these generated instructions. */
static int verify_rap_hyperv(struct objtool_file *file, struct symbol *func)
{
	struct rap_kexec_sequence k = { .seq = { .file = file, .func = func } };
	struct rap_sequence *s = &k.seq;
	struct instruction *insn;
	bool vtl = func->rap_kind == 20;
	unsigned int i;
	const char *target = vtl ? "hdn_hv_vtl_target" : "hdn_hv_hypercall_target";
	const char *thunk = vtl ? "__x86_indirect_thunk_rax" : "__x86_indirect_thunk_r11";

#define HV_BYTES(bytes) do { \
	if (!rap_sequence_bytes(s, bytes, sizeof(bytes) - 1)) goto bad; \
} while (0)
	if (is_weak_sym(func) || !func->sec->noinstr ||
	    strcmp(func->name, vtl ? "hdn_hv_vtl_gate" : "hdn_hv_hypercall"))
		goto bad;
	HV_BYTES("\x4c\x8d\x1d\x05\0\0\0");
	if (!rap_sequence_edge_match(s, "__hdn_rap_enter", true, false))
		goto bad;
	if (vtl) {
		HV_BYTES("\x4c\x8b\x54\x24\x08\x4c\x8b\x5c\x24\x10\x50");
		if (!rap_sequence_reference(s, "\x48\x8b\x05", 3, target, true))
			goto bad;
		HV_BYTES("\x48\x85\xc0");
	} else {
		HV_BYTES("\x55\x48\x89\xe5\x49\x89\xd0\x48\x89\xf9\x48\x89\xf2");
		if (!rap_sequence_reference(s, "\x4c\x8b\x1d", 3, target, true))
			goto bad;
		HV_BYTES("\x4d\x85\xdb");
	}
	if (!rap_kexec_branch(&k, 0x74, 0))
		goto bad;
	/* CALL_NOSPEC retains the selected architecture return-stack mitigation. */
	if (s->pos < func->len &&
	    *((u8 *)func->sec->data->d_buf + func->offset + s->pos) == 0x2e) {
		if (vtl || !rap_sequence_reference(s, "\x2e\xe8", 2, thunk, true))
			goto bad;
	} else if (s->pos < func->len &&
		   *((u8 *)func->sec->data->d_buf + func->offset + s->pos) == 0xe8) {
		if (!vtl || !rap_sequence_reference(s, "\xe8", 1, thunk, true))
			goto bad;
	} else if (vtl) {
		HV_BYTES("\xff\xd0");
	} else {
		HV_BYTES("\x41\xff\xd3");
	}
	if (vtl) {
		HV_BYTES("\x48\x83\xc4\x08\x4c\x89\x54\x24\x08\x4c\x89\x5c\x24\x10");
	} else {
		if (!rap_kexec_label(&k, 1))
			goto bad;
		HV_BYTES("\x5d");
	}
	if (!rap_sequence_edge_match(s, "__hdn_rap_return", false, false) ||
	    !rap_kexec_label(&k, 0))
		goto bad;
	if (vtl) {
		HV_BYTES("\x0f\x0b");
	} else {
		HV_BYTES("\x48\xc7\xc0\xff\xff\xff\xff");
		if (!rap_kexec_branch(&k, 0xeb, 1))
			goto bad;
	}
	if (s->pos != func->len)
		goto bad;
	for (i = 0; i < k.count; i++)
		if (!k.branches[i].insn->jump_dest ||
		    k.branches[i].insn->jump_dest->sec != func->sec ||
		    k.branches[i].insn->jump_dest->offset != k.labels[k.branches[i].label])
			goto bad;
	rap_for_each_insn(file, func, insn)
		if (insn->alts)
			goto bad;
	for_each_insn(file, insn)
		if (rap_insn_owner(insn) != func && insn->jump_dest &&
		    insn->jump_dest->sec == func->sec &&
		    insn->jump_dest->offset > func->offset &&
		    insn->jump_dest->offset < func->offset + func->len)
			goto bad;
	func->rap_hyperv_protocol = true;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s->pos, "RAP Hyper-V gateway has an invalid sealed-endpoint protocol");
	return -1;
#undef HV_BYTES
}
