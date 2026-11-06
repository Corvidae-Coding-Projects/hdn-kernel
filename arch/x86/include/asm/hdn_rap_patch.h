/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_HDN_RAP_PATCH_H
#define _ASM_X86_HDN_RAP_PATCH_H

#include <linux/types.h>
#include <asm/page_types.h>
#include <asm/text-patching.h>

/* Shared by the text-poke producer and the closed asynchronous-frame adapter.
 * A six-byte Jcc retains the producer's compact, prefix-free text encoding. */
struct smp_text_poke_loc {
	s32 rel_addr;
	s32 disp;
	u8 len;
	u8 opcode;
	const u8 text[TEXT_POKE_MAX_OPCODE_SIZE];
	u8 old;
};

#define TEXT_POKE_ARRAY_MAX (PAGE_SIZE / sizeof(struct smp_text_poke_loc))
struct smp_text_poke_array {
	struct smp_text_poke_loc vec[TEXT_POKE_ARRAY_MAX];
	unsigned long nr_entries;
};

#ifdef CONFIG_SECURITY_HARDENING_RAP
extern struct smp_text_poke_array hdn_rap_text_patches;
int hdn_rap_text_poke(struct pt_regs *regs);
#endif

#endif
