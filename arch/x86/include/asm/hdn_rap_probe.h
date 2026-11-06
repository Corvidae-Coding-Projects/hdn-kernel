/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_HDN_RAP_PROBE_H
#define _ASM_X86_HDN_RAP_PROBE_H

#include <linux/types.h>

struct kprobe;
struct pt_regs;
enum hdn_rap_probe_op {
	HDN_PROBE_STEP, HDN_PROBE_FLAGS, HDN_PROBE_CALL,
	HDN_PROBE_JUMP, HDN_PROBE_COND, HDN_PROBE_LOOP,
};
#ifdef CONFIG_SECURITY_HARDENING_RAP
int hdn_rap_probe_prepare(const struct kprobe *probe, enum hdn_rap_probe_op op);
void hdn_rap_probe_release(const struct kprobe *probe);
bool hdn_rap_probe_start(struct pt_regs *regs, const struct kprobe *probe);
bool hdn_rap_probe_complete(struct pt_regs *regs, const struct kprobe *probe,
		bool fault, int trapnr);
unsigned long hdn_rap_probe_entry(unsigned long address);
void hdn_rap_probe_override(struct pt_regs *regs);
#else
static inline int hdn_rap_probe_prepare(const struct kprobe *probe,
		enum hdn_rap_probe_op op) { return 0; }
static inline void hdn_rap_probe_release(const struct kprobe *probe) { }
#endif
#endif
