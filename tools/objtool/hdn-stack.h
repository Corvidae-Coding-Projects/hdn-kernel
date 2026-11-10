/* SPDX-License-Identifier: GPL-2.0-only */
/* The private boot-stack handoff abandons the incoming CR3 and stack. Match
 * its entire fixed protocol instead of exempting a generic stack switch. */
static int verify_rap_stack_bootstrap(struct objtool_file *file, struct symbol *func)
{
	struct rap_sequence s = { .file = file, .func = func };
	struct symbol *finish = find_symbol_by_name(file->elf, "hdn_stack_mm_finish");
	struct symbol *continuation = find_symbol_by_name(file->elf, "hdn_stack_bootstrap_continue");
	struct instruction *insn;
	unsigned int callers = 0;

	if (func->rap_kind != 55 || strcmp(func->name, "__hdn_stack_bootstrap") ||
	    is_weak_sym(func) || strcmp(func->sec->name, ".init.text") ||
	    !rap_sequence_bytes(&s, "\x4c\x8b\x5f\x08\x48\x8b\x17\x41\x0f\x22\xdb"
				   "\x48\x89\xd4\x31\xed", 16) ||
	    !rap_entry_call(&s, "hdn_stack_mm_finish") ||
	    !rap_entry_call(&s, "hdn_stack_bootstrap_continue") ||
	    !rap_sequence_bytes(&s, "\x0f\x0b", 2) || s.pos != func->len)
		goto bad;
	rap_for_each_insn(file, func, insn)
		if (insn->alts)
			goto bad;
	if (opts.link) {
		if (!finish || finish->rap_kind != 2 || !continuation ||
		    continuation->rap_kind != 1)
			goto bad;
		for_each_insn(file, insn) {
			struct section *sec;
			struct symbol *owner;
			unsigned long offset;

			if (!rap_thunk_edge_target(file, insn, &sec, &offset) ||
			    sec != func->sec || offset != func->offset)
				continue;
			owner = rap_insn_owner(insn);
			if (insn->type != INSN_CALL || !owner || owner->rap_kind != 1 ||
			    strcmp(owner->name, "hdn_stack_bootstrap"))
				goto bad;
			callers++;
		}
		if (callers != 1)
			goto bad;
	}
	func->rap_stack_bootstrap_protocol = true;
	func->rap_terminal = true;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s.pos,
		   "RAP private-stack bootstrap differs from its closed handoff protocol");
	return -1;
}
