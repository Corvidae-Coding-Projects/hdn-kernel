/* SPDX-License-Identifier: GPL-2.0-only */
/* Closed assembly-only crypto ABIs. The normal RAP verifier still checks
 * every transfer; these lists never exempt a body from that verification. */
static bool rap_regs_name(const char *name)
{
	static const char * const names[] = {
		"__aria_aesni_avx2_crypt_32way",
		"__aria_aesni_avx2_ctr_gen_keystream_32way",
		"__aria_aesni_avx2_gfni_crypt_32way",
		"__aria_aesni_avx_crypt_16way",
		"__aria_aesni_avx_ctr_gen_keystream_16way",
		"__aria_aesni_avx_gfni_crypt_16way",
		"__aria_gfni_avx512_crypt_64way",
		"__aria_gfni_avx512_ctr_gen_keystream_64way",
		"__camellia_dec_blk16",
		"__camellia_dec_blk32",
		"__camellia_enc_blk16",
		"__camellia_enc_blk32",
		"__cast5_dec_blk16",
		"__cast5_enc_blk16",
		"__cast6_dec_blk8",
		"__cast6_enc_blk8",
		"__poly1305_block",
		"__poly1305_init_avx",
		"__serpent_dec_blk16",
		"__serpent_dec_blk8_avx",
		"__serpent_enc_blk16",
		"__serpent_enc_blk8_avx",
		"__sm4_crypt_blk16",
		"__sm4_crypt_blk8",
		"__twofish_dec_blk8",
		"__twofish_enc_blk8",
		"arch_bpf_timed_may_goto",
		"hdn_hv_vtl_gate",
		"chacha_permute",
		"roundsm16_x0_x1_x2_x3_x4_x5_x6_x7_y0_y1_y2_y3_y4_y5_y6_y7_cd",
		"roundsm16_x4_x5_x6_x7_x0_x1_x2_x3_y4_y5_y6_y7_y0_y1_y2_y3_ab",
		"roundsm32_x0_x1_x2_x3_x4_x5_x6_x7_y0_y1_y2_y3_y4_y5_y6_y7_cd",
		"roundsm32_x4_x5_x6_x7_x0_x1_x2_x3_y4_y5_y6_y7_y0_y1_y2_y3_ab",
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(names); i++)
		if (!strcmp(name, names[i]))
			return true;
	return false;
}

static bool rap_crypto_private_name(const char *name)
{
	static const char * const names[] = {
		"__clmul_gf128mul_ble",
		"_aesni_dec1",
		"_aesni_dec4",
		"_aesni_enc1",
		"_aesni_enc4",
		"_aesni_inc",
		"_aesni_inc_init",
		"_key_expansion_192a",
		"_key_expansion_192b",
		"_key_expansion_256a",
		"_key_expansion_256b",
	};
	unsigned int i;

	if (rap_regs_name(name) && strcmp(name, "hdn_hv_vtl_gate"))
		return true;
	for (i = 0; i < ARRAY_SIZE(names); i++)
		if (!strcmp(name, names[i]))
			return true;
	return false;
}

static bool rap_regs_insn(struct objtool_file *file, struct instruction *insn,
			  struct symbol *owner, const char *bytes, size_t len)
{
	return insn && rap_insn_owner(insn) == owner && !insn->alts &&
		insn->len == len &&
		!find_reloc_by_dest_range(file->elf, insn->sec, insn->offset, len) &&
		!memcmp(insn->sec->data->d_buf + insn->offset, bytes, len);
}

/* Match both ends of HDN_REGS_CALL and the callee's data transports. The two
 * words above the authenticated return slot must never become C arguments or
 * a different private convention. The sole global helper is also called by
 * the BPF JIT, whose sealed-image admission checks the same paired bytes. */
static int verify_rap_regs(struct objtool_file *file, struct symbol *func)
{
	struct instruction *insn, *a, *b, *binding;
	bool vtl = !strcmp(func->name, "hdn_hv_vtl_gate");

	if ((func->bind != STB_LOCAL && strcmp(func->name, "arch_bpf_timed_may_goto") && !vtl) ||
	    func->rap_kind != (vtl ? 20 : 5))
		goto bad;
	rap_for_each_insn(file, func, insn) {
		if (insn->rap_entry) {
			a = next_insn_same_sec(file, insn);
			b = a ? next_insn_same_sec(file, a) : NULL;
			if (!rap_regs_insn(file, a, func, "\x4c\x8b\x54\x24\x08", 5) ||
			    !rap_regs_insn(file, b, func, "\x4c\x8b\x5c\x24\x10", 5) ||
			    a->offset != insn->offset + insn->len || b->offset != a->offset + a->len)
				goto bad;
		}
		if (insn->rap_return) {
			b = prev_insn_same_sec(file, insn);
			a = b ? prev_insn_same_sec(file, b) : NULL;
			if (!rap_regs_insn(file, a, func, "\x4c\x89\x54\x24\x08", 5) ||
			    !rap_regs_insn(file, b, func, "\x4c\x89\x5c\x24\x10", 5) ||
			    b->offset != a->offset + a->len || insn->offset != b->offset + b->len)
				goto bad;
		}
	}
	for_each_insn(file, insn) {
		struct symbol *caller = rap_insn_owner(insn);

		if (insn->jump_dest && rap_insn_owner(insn->jump_dest) == func && caller != func)
			goto bad;
		if (insn->type != INSN_CALL || insn_call_dest(insn) != func)
			continue;
		binding = prev_insn_same_sec(file, insn);
		b = binding ? prev_insn_same_sec(file, binding) : NULL;
		a = b ? prev_insn_same_sec(file, b) : NULL;
		if (!caller || !insn->rap_site || insn->alts || !binding ||
		    !binding->rap_binding || binding->alts ||
		    !rap_regs_insn(file, a, caller, "\x41\x53", 2) ||
		    !rap_regs_insn(file, b, caller, "\x41\x52", 2) ||
		    b->offset != a->offset + a->len || binding->offset != b->offset + b->len)
			goto bad;
		a = next_insn_same_sec(file, insn);
		b = a ? next_insn_same_sec(file, a) : NULL;
		if (!rap_regs_insn(file, a, caller, "\x41\x5a", 2) ||
		    !rap_regs_insn(file, b, caller, "\x41\x5b", 2) ||
		    a->offset != insn->offset + insn->len || b->offset != a->offset + a->len)
			goto bad;
	}
	return 0;
bad:
	ERROR_FUNC(func->sec, func->offset, "RAP assembly register ABI has an unpaired argument/result transport");
	return -1;
}
