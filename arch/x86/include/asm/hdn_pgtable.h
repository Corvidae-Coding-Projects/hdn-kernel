/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_HDN_PGTABLE_H
#define _ASM_X86_HDN_PGTABLE_H

#include <linux/types.h>
#include <linux/compiler.h>
#include <asm/cmpxchg.h>
#include <linux/bitops.h>

/* This header must not include pgtable.h: native setters include it. */
enum hdn_pt_operation {
	HDN_PT_STORE,
	HDN_PT_EXCHANGE,
	HDN_PT_COMPARE_EXCHANGE,
	HDN_PT_READ,
	HDN_PT_COPY,
	HDN_PT_LTR,
};

#if defined(CONFIG_SECURITY_HARDENING_PGTABLE) && !defined(HDN_PGTABLE_BOOTSTRAP)
extern bool hdn_pt_writes_ready;
unsigned long hdn_pt_update(unsigned long *slot, unsigned long value,
			    unsigned long expected, enum hdn_pt_operation operation,
			    unsigned int level);
bool hdn_pt_protected_pfn(unsigned long first, unsigned long last);
bool hdn_pt_active(void);
unsigned long hdn_pt_async_enter(void);
void hdn_pt_async_exit(unsigned long state);
void hdn_pt_copy(void *destination, const void *source, size_t size, unsigned int level);
void hdn_pt_zero(void *destination, size_t size);
#else
static inline bool hdn_pt_protected_pfn(unsigned long first, unsigned long last) { return false; }
static inline bool hdn_pt_active(void) { return false; }
#define hdn_pt_copy(dst, src, size, level) memcpy(dst, src, size)
#define hdn_pt_zero(dst, size) memset(dst, 0, size)
#endif

static __always_inline void hdn_pt_store(unsigned long *slot, unsigned long value, unsigned int level)
{
#if defined(CONFIG_SECURITY_HARDENING_PGTABLE) && !defined(HDN_PGTABLE_BOOTSTRAP)
	if (READ_ONCE(hdn_pt_writes_ready)) {
		hdn_pt_update(slot, value, 0, HDN_PT_STORE, level);
		return;
	}
#endif
	WRITE_ONCE(*slot, value);
}

static __always_inline unsigned long hdn_pt_exchange(unsigned long *slot, unsigned long value, unsigned int level)
{
#if defined(CONFIG_SECURITY_HARDENING_PGTABLE) && !defined(HDN_PGTABLE_BOOTSTRAP)
	if (READ_ONCE(hdn_pt_writes_ready))
		return hdn_pt_update(slot, value, 0, HDN_PT_EXCHANGE, level);
#endif
	return xchg(slot, value);
}

static __always_inline bool hdn_pt_try_cmpxchg(unsigned long *slot,
					     unsigned long *old, unsigned long value, unsigned int level)
{
#if defined(CONFIG_SECURITY_HARDENING_PGTABLE) && !defined(HDN_PGTABLE_BOOTSTRAP)
	if (READ_ONCE(hdn_pt_writes_ready)) {
		unsigned long seen = hdn_pt_update(slot, value, *old, HDN_PT_COMPARE_EXCHANGE, level);
		bool changed = seen == *old;
		if (!changed)
			*old = seen;
		return changed;
	}
#endif
	return try_cmpxchg(slot, old, value);
}

static __always_inline bool hdn_pt_test_clear_bit(unsigned int bit, unsigned long *slot, unsigned int level)
{
#if defined(CONFIG_SECURITY_HARDENING_PGTABLE) && !defined(HDN_PGTABLE_BOOTSTRAP)
	unsigned long old = READ_ONCE(*slot), mask = 1UL << bit;

	do {
		if (!(old & mask))
			return false;
	} while (!hdn_pt_try_cmpxchg(slot, &old, old & ~mask, level));
	return true;
#else
	return test_and_clear_bit(bit, slot);
#endif
}
#endif
