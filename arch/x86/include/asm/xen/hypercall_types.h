/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_XEN_HYPERCALL_TYPES_H
#define _ASM_X86_XEN_HYPERCALL_TYPES_H

#ifdef CONFIG_SECURITY_HARDENING_RAP
/* A real C ABI keeps hypercall payloads out of the RAP scratch registers.
 * Only the terminal assembly wrappers marshal the hypervisor register ABI. */
long xen_hypercall_func(unsigned int call, unsigned long a1, unsigned long a2,
		unsigned long a3, unsigned long a4, unsigned long a5);
#else
void xen_hypercall_func(void);
#endif

extern typeof(xen_hypercall_func) xen_hypercall_hvm;
extern typeof(xen_hypercall_func) xen_hypercall_amd;
extern typeof(xen_hypercall_func) xen_hypercall_intel;
#ifdef CONFIG_XEN_PV
extern typeof(xen_hypercall_func) xen_hypercall_pv;
#endif

#endif
