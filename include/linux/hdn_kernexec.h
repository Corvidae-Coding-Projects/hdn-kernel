/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_HDN_KERNEXEC_H
#define _LINUX_HDN_KERNEXEC_H

#include <linux/mm_types.h>

#ifdef CONFIG_SECURITY_HARDENING_INITIFY
bool hdn_init_aliases_retired(void);
unsigned long hdn_init_reclaimed_bytes(void);
#else
static inline bool hdn_init_aliases_retired(void) { return false; }
static inline unsigned long hdn_init_reclaimed_bytes(void) { return 0; }
#endif

/*
 * Admission for CPA and vmalloc mappings. This covers same-mapping W+X and
 * writable aliases of finalized built-in text/rodata. Dynamic image ownership
 * and page-table-page sealing are separate contracts, not inferred here.
 * No allocation, locks, or event emission: callers can hold page-table locks.
 */
#ifdef CONFIG_SECURITY_HARDENING_KERNEL_WX
bool hdn_kernel_sealed_data_page(unsigned long pfn);
int hdn_kernel_mapping_check(unsigned long pfn, unsigned long nr_pages,
			     pgprot_t prot);
#else
static inline bool hdn_kernel_sealed_data_page(unsigned long pfn) { return false; }
static inline int hdn_kernel_mapping_check(unsigned long pfn,
					   unsigned long nr_pages, pgprot_t prot)
{
	return 0;
}
#endif

#endif
