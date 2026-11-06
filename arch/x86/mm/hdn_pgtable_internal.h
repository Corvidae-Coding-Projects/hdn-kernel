/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _X86_HDN_PGTABLE_INTERNAL_H
#define _X86_HDN_PGTABLE_INTERNAL_H

#include <asm/hdn_pgtable.h>

/* Internal lifecycle-to-window interface. No symbols in this interface are
 * exported to modules, and no caller obtains an address of a writable alias. */
void hdn_pt_windows_init(void);
unsigned int hdn_pt_cpu(void);
void hdn_pt_windows_walk(void (*visit)(unsigned long *root, unsigned int order));
unsigned long hdn_pt_window_update(unsigned long pfn, unsigned int offset,
		unsigned long value, unsigned long expected, enum hdn_pt_operation operation);
void hdn_pt_window_clear(unsigned long pfn);
void hdn_pt_window_ltr(unsigned long pfn);
unsigned long hdn_pt_window_read(unsigned long pfn, unsigned int offset);
void hdn_pt_window_copy(unsigned long pfn, const unsigned long *source,
			unsigned int skip);
bool hdn_pt_window_private_alias(unsigned long *root, unsigned long address, unsigned long pfn);

#endif
