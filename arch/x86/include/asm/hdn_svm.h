/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_HDN_SVM_H
#define _ASM_X86_HDN_SVM_H

#ifndef __ASSEMBLER__
#include <linux/types.h>

struct page;
/* Matches the pushes in the SEV-ES entry adapter. */
struct hdn_svm_gprs {
	unsigned long rdi, rsi, rbx, rbp, r12, r13, r14, r15;
};

struct hdn_svm_host_state {
	u64 xcr0, xss, dr_mask[4];
	u32 pkru, tsc_aux;
	bool debug_swap, tsc_aux_valid;
};

#ifdef CONFIG_SECURITY_HARDENING_PRIVATE_STACKS
/* Consumes the fresh, SNP-safe page on both success and failure. */
int hdn_svm_cpu_prepare(unsigned int cpu, struct page *page);
void hdn_svm_cpu_release(unsigned int cpu);
void hdn_svm_enable(void);
void hdn_svm_disable(void);
unsigned long hdn_svm_host_pa(void);
void hdn_svm_set_gprs(const struct hdn_svm_gprs *regs);
void hdn_svm_set_state(const struct hdn_svm_host_state *state);
#endif
#endif
#endif
