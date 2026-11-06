/* SPDX-License-Identifier: GPL-2.0-only */
/* Native EFI is a closed foreign ABI: match every instruction and relocation,
 * including the only unchecked (firmware) CALL and the protected return path. */
/* The return stub is deliberately data, mapped executable only in efi_mm.
 * Validate its complete mixed 64/32-bit encoding without decoding 32-bit
 * instructions with objtool's ordinary 64-bit text decoder. */
static bool rap_efi_trampoline(struct objtool_file *file)
{
	struct symbol *blob = find_symbol_by_name(file->elf, "__efi64_thunk_ret_tramp");
	struct symbol *compat = find_symbol_by_name(file->elf, "__hdn_efi32_return");
	struct symbol *target = find_symbol_by_name(file->elf, "__hdn_efi_return");
	struct reloc *reloc;
	const char *bytes;

	if (!blob || !compat || !target || is_weak_sym(blob) || is_weak_sym(compat) ||
	    is_weak_sym(target) || blob->len != 17 || blob->offset % 4096 ||
	    blob->offset + blob->len > sec_size(blob->sec) ||
	    !(blob->sec->sh.sh_flags & SHF_ALLOC) || (blob->sec->sh.sh_flags & SHF_WRITE) ||
	    compat->sec != blob->sec || compat->offset != blob->offset + 13)
		return false;
	bytes = blob->sec->data->d_buf + blob->offset;
	if (memcmp(bytes, "\x49\xbb", 2) ||
	    memcmp(bytes + 10, "\x41\xff\xe3\x6a\x10\x55\xcb", 7))
		return false;
	reloc = find_reloc_by_dest(file->elf, blob->sec, blob->offset + 2);
	return reloc && reloc_type(reloc) == R_X86_64_64 && arch_reloc_size(reloc) == 8 &&
		reloc->sym->sec == target->sec &&
		(!is_undef_sym(target) || reloc->sym == target) &&
		reloc->sym->offset + reloc_addend(reloc) == target->offset &&
		!find_reloc_by_dest_range(file->elf, blob->sec, blob->offset, 2) &&
		!find_reloc_by_dest_range(file->elf, blob->sec, blob->offset + 3, 14);
}

static int verify_rap_efi(struct objtool_file *file, struct symbol *func)
{
	struct rap_sequence s = { .file = file, .func = func };
	struct instruction *insn, *first = find_insn(file, func->sec, func->offset);

#define EFI_BYTES(bytes) do { \
	if (!rap_sequence_bytes(&s, bytes, sizeof(bytes) - 1)) goto bad; \
} while (0)
#define EFI_REF(bytes, name) do { \
	if (!rap_sequence_reference(&s, bytes, sizeof(bytes) - 1, name, true)) goto bad; \
} while (0)
#define EFI_EDGE(name, call, bound) do { \
	if (!rap_sequence_edge_match(&s, name, call, bound)) goto bad; \
} while (0)
	if (is_weak_sym(func) || strcmp(func->name,
		func->rap_kind == 14 ? "__hdn_efi_call" :
		func->rap_kind == 15 ? "__hdn_efi_return" :
		func->rap_kind == 16 ? "__hdn_efi_fault_return" : "__hdn_efi64_thunk"))
		goto bad;
	if (first && first->type == INSN_ENDBR)
		EFI_BYTES("\xf3\x0f\x1e\xfa");
	if (func->rap_kind == 16) {
		EFI_BYTES("\x48\xb8\x15\0\0\0\0\0\0\x80");
		EFI_EDGE("__hdn_efi_return", false, false);
	} else if (func->rap_kind == 14 || func->rap_kind == 17) {
	EFI_BYTES("\x4c\x8d\x1d\x05\0\0\0");
	EFI_EDGE("__hdn_rap_enter", true, false);
	EFI_BYTES("\x9c\xfa\x53\x55\x41\x54\x41\x55\x41\x56\x41\x57"
		  "\x48\x83\xec\x40\x48\x89\x14\x24\x48\x89\x4c\x24\x08"
		  "\x4c\x89\x44\x24\x10\x4c\x89\x4c\x24\x18"
		  "\x48\x8b\x84\x24\x80\0\0\0\x48\x89\x44\x24\x20"
		  "\x48\x8b\x84\x24\x88\0\0\0\x48\x89\x44\x24\x28"
		  "\x48\x8b\x84\x24\x90\0\0\0\x48\x89\x44\x24\x30"
		  "\x48\x8b\x84\x24\x98\0\0\0\x48\x89\x44\x24\x38"
		  "\x48\x89\xe2");
	if (func->rap_kind == 17)
		EFI_BYTES("\xb9\x01\0\0\0");
	else
		EFI_BYTES("\x31\xc9");
	EFI_BYTES("\x4c\x8d\x15\x05\0\0\0");
	EFI_EDGE("hdn_efi_enter", true, true);
	if (func->rap_kind == 17) {
		EFI_BYTES("\x49\x89\xc2");
		EFI_REF("\x48\x8b\x25", "efi_mixed_mode_stack_pa");
		EFI_BYTES("\x48\x83\xec\x24\x48\xc7\xc0\0\0\0\x80");
		EFI_REF("\x48\x2b\x05", "phys_base");
		EFI_REF("\x48\x8d\x2d", "__efi64_thunk_ret_tramp");
		EFI_REF("\x48\x8d\x1d", "__hdn_efi32_return");
		EFI_BYTES("\x48\x29\xc5\x48\x29\xc3\x89\x1c\x24"
			  "\x41\x8b\x12\x89\x54\x24\x04"
			  "\x41\x8b\x52\x08\x89\x54\x24\x08"
			  "\x41\x8b\x52\x10\x89\x54\x24\x0c"
			  "\x41\x8b\x52\x18\x89\x54\x24\x10"
			  "\x41\x8b\x52\x20\x89\x54\x24\x14"
			  "\x41\x8b\x52\x28\x89\x54\x24\x18"
			  "\x41\x8b\x52\x30\x89\x54\x24\x1c"
			  "\x41\x8b\x52\x38\x89\x54\x24\x20"
			  "\x6a\x08\x41\xff\xb2\x80\0\0\0\x48\xcb");
		if (!rap_efi_trampoline(file))
			goto bad;
	} else {
	EFI_BYTES("\x49\x89\xc3\x48\x83\xe4\xf0\x48\x83\xec\x30"
		  "\x49\x8b\x43\x20\x48\x89\x44\x24\x20"
		  "\x49\x8b\x43\x28\x48\x89\x44\x24\x28"
		  "\x49\x8b\x0b\x49\x8b\x53\x08\x4d\x8b\x43\x10\x4d\x8b\x4b\x18"
		  "\x41\xff\x73\x70\x9d\x4d\x8b\x9b\x80\0\0\0");
	if (s.pos < func->len &&
	    *((unsigned char *)func->sec->data->d_buf + func->offset + s.pos) == 0x2e)
		EFI_REF("\x2e\xe8", "__x86_indirect_thunk_r11");
	else
		EFI_BYTES("\x41\xff\xd3");
	EFI_EDGE("__hdn_efi_return", false, false);
	}
	} else {
	EFI_BYTES("\xfa\xfc\x49\x89\xc0");
	EFI_REF("\x4c\x8d\x1d", "hdn_efi_state");
	EFI_BYTES("\x49\x8b\x83\x88\0\0\0\x48\x89\xc2\x48\xc1\xea\x20"
		  "\xb9\x01\x01\0\xc0\x0f\x30\x49\x8b\x63\x78\x41\x50"
		  "\x41\xff\x73\x70\x4d\x8b\x7b\x40\x4d\x8b\x73\x48"
		  "\x4d\x8b\x6b\x50\x4d\x8b\x63\x58\x49\x8b\x6b\x60\x49\x8b\x5b\x68"
		  "\x4c\x8d\x15\x05\0\0\0");
	EFI_EDGE("hdn_efi_finish", true, true);
	EFI_BYTES("\x9d\x58");
	EFI_EDGE("__hdn_rap_return", false, false);
	}
	if (s.pos != func->len)
		goto bad;
	rap_for_each_insn(file, func, insn)
		if (insn->alts)
			goto bad;
	for_each_insn(file, insn)
		if (rap_insn_owner(insn) != func && insn->jump_dest && insn->jump_dest->sec == func->sec &&
		    insn->jump_dest->offset > func->offset && insn->jump_dest->offset < func->offset + func->len)
			goto bad;
	func->rap_efi_protocol = true;
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset + s.pos, "RAP EFI call does not match its protected foreign-ABI protocol");
	return -1;
#undef EFI_BYTES
#undef EFI_REF
#undef EFI_EDGE
}
