/* SPDX-License-Identifier: GPL-2.0-only */
/* Oops recovery is a one-way stack abandonment, not an exception to the
 * normal protected return ABI. Its new SP comes only from the closed root. */
static int verify_rap_rewind(struct objtool_file *file, struct symbol *func)
{
	struct rap_sequence s = { .file = file, .func = func };
	struct symbol *root = find_symbol_by_name(file->elf, "hdn_rap_fatal_rewind");
	struct symbol *exit = find_symbol_by_name(file->elf, "make_task_dead");
	struct instruction *insn;

	if (func->rap_kind != 1 || func->rap_returns || is_weak_sym(func) ||
	    !rap_sequence_bytes(&s, "\x4c\x8d\x1d\x05\0\0\0", 7) ||
	    !rap_sequence_edge_match(&s, "__hdn_rap_enter", true, false) ||
	    !rap_sequence_bytes(&s, "\xfa\x41\x89\xfc\x48\x89\xe7\x48\x83\xec\x08", 11) ||
	    !rap_entry_call(&s, "hdn_rap_fatal_rewind") ||
	    !rap_sequence_bytes(&s, "\x31\xed\x48\x89\xc4\x44\x89\xe7", 8) ||
	    !rap_entry_call(&s, "make_task_dead") || s.pos != func->len ||
	    !root || !exit || (opts.link && (root->rap_kind != 2 || exit->rap_kind != 1)))
		goto bad;
	rap_for_each_insn(file, func, insn)
		if (insn->alts)
			goto bad;
	for_each_insn(file, insn) {
		struct symbol *owner = rap_entry_owner(insn);
		struct section *sec;
		unsigned long offset;

		if (!rap_thunk_edge_target(file, insn, &sec, &offset))
			continue;
		if (sec == func->sec && offset >= func->offset && offset < func->offset + func->len) {
			if (owner && owner->pfunc)
				owner = owner->pfunc;
			if (offset != func->offset || insn->type != INSN_CALL || !insn->rap_site ||
			    !owner || strcmp(owner->name, "oops_end") || owner->rap_kind != 1)
				goto bad;
		}
		if (!is_undef_sym(root) && owner != root && (!owner || owner->pfunc != root) &&
		    sec == root->sec && offset >= root->offset && offset < root->offset + root->len &&
		    (owner != func || offset != root->offset || insn->type != INSN_CALL || !insn->rap_site))
			goto bad;
	}
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s.pos, "RAP fatal stack rewind lacks its closed abandonment protocol");
	return -1;
}
