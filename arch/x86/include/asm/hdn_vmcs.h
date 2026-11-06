/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_HDN_VMCS_H
#define _ASM_X86_HDN_VMCS_H

#include <linux/types.h>
#include <linux/gfp_types.h>

#ifdef CONFIG_SECURITY_HARDENING_PRIVATE_STACKS
void *hdn_vmcs_alloc(int node, gfp_t flags, u32 revision, bool shadow);
void hdn_vmcs_free(void *vmcs);
unsigned long hdn_vmcs_pa(const void *vmcs);
#endif
#endif
