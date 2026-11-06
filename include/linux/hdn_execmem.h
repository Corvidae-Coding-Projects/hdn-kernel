/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_HDN_EXECMEM_H
#define _LINUX_HDN_EXECMEM_H

#include <linux/types.h>
#include <linux/errno.h>
#include <asm/pgtable.h>

struct vm_struct;
struct page;
struct module;

struct hdn_execmem_stats {
	u64 allocations;
	u64 live_pages;
	u64 finalized;
	u64 retired;
	u64 failed_retirements;
	u64 bpf_live_pages;
	u64 bpf_quarantined_pages;
	u64 bpf_failed_retirements;
	u64 bpf_quarantine_pressure_releases;
	u64 bpf_quarantine_limit_pages;
};

/* Internal execmem lifecycle, never exported as an address registration API. */
#ifdef CONFIG_SECURITY_HARDENING_EXECMEM
int hdn_execmem_claim_type(void *ptr, unsigned int type);
int hdn_execmem_bpf_copy(void *dst, const void *src, size_t size);
int hdn_execmem_bpf_finalize(void *ptr);
int hdn_execmem_claim(void *ptr);
int hdn_execmem_claim_data(void *ptr);
int hdn_execmem_claim_stack(void *ptr);
int hdn_execmem_claim_hardware(void *ptr);
int hdn_execmem_hide_hardware(void *ptr);
int hdn_execmem_hide_stack(void *ptr);
int hdn_execmem_claim_rap(void *ptr, const struct module *owner, size_t size);
bool hdn_execmem_rap_valid(const void *ptr, const struct module *owner);
int hdn_execmem_claim_ldt(void *ptr, size_t size);
bool hdn_execmem_ldt_valid(const void *ptr, size_t size);
int hdn_execmem_seal_data(void *ptr);
bool hdn_execmem_text_page(struct page *page);
bool hdn_execmem_free(void *ptr);
void hdn_execmem_unmapped(struct vm_struct *vm);
int hdn_execmem_mapping(unsigned long address, unsigned long pfn,
			unsigned long nr, pgprot_t prot, bool new_alias);
int hdn_execmem_leaf(unsigned long pfn, unsigned long nr, unsigned long flags);
bool hdn_execmem_snapshot_page(void *destination, struct page *page, bool *zeros_only);
int hdn_execmem_seal_begin(unsigned long address, int nr);
void hdn_execmem_seal_end(unsigned long address, int error);
bool hdn_execmem_sealed(unsigned long address, int nr);
bool hdn_execmem_sealed_bpf(unsigned long address, size_t size);
void hdn_execmem_get_stats(struct hdn_execmem_stats *stats);
#if IS_ENABLED(CONFIG_SECURITY_HARDENING_KERNEL_WX_TEST)
/* Disposable-guest fixtures only; never exported to modules or user space. */
int hdn_execmem_test_quarantine(void *ptr, bool hold);
int hdn_execmem_test_scrubbed(void *ptr);
#endif
#else
static inline int hdn_execmem_claim_type(void *ptr, unsigned int type) { return 0; }
static inline int hdn_execmem_bpf_copy(void *dst, const void *src, size_t size) { return 0; }
static inline int hdn_execmem_bpf_finalize(void *ptr) { return -EOPNOTSUPP; }
static inline int hdn_execmem_claim(void *ptr) { return 0; }
static inline int hdn_execmem_claim_data(void *ptr) { return -EOPNOTSUPP; }
static inline int hdn_execmem_claim_hardware(void *ptr) { return -EOPNOTSUPP; }
static inline int hdn_execmem_hide_hardware(void *ptr) { return -EOPNOTSUPP; }
static inline int hdn_execmem_claim_stack(void *ptr) { return -EOPNOTSUPP; }
static inline int hdn_execmem_hide_stack(void *ptr) { return -EOPNOTSUPP; }
static inline int hdn_execmem_claim_ldt(void *ptr, size_t size) { return -EOPNOTSUPP; }
static inline bool hdn_execmem_ldt_valid(const void *ptr, size_t size) { return false; }
static inline int hdn_execmem_seal_data(void *ptr) { return -EOPNOTSUPP; }
static inline bool hdn_execmem_text_page(struct page *page) { return true; }
static inline bool hdn_execmem_free(void *ptr) { return false; }
static inline void hdn_execmem_unmapped(struct vm_struct *vm) { }
static inline int hdn_execmem_mapping(unsigned long address, unsigned long pfn,
		unsigned long nr, pgprot_t prot, bool new_alias) { return 0; }
static inline int hdn_execmem_leaf(unsigned long pfn, unsigned long nr,
		unsigned long flags) { return 0; }
static inline bool hdn_execmem_snapshot_page(void *destination, struct page *page,
		bool *zeros_only) { return false; }
static inline int hdn_execmem_seal_begin(unsigned long address, int nr) { return 0; }
static inline void hdn_execmem_seal_end(unsigned long address, int error) { }
static inline bool hdn_execmem_sealed(unsigned long address, int nr) { return false; }
static inline bool hdn_execmem_sealed_bpf(unsigned long address, size_t size) { return false; }
#if IS_ENABLED(CONFIG_SECURITY_HARDENING_KERNEL_WX_TEST)
static inline int hdn_execmem_test_quarantine(void *ptr, bool hold) { return -EOPNOTSUPP; }
static inline int hdn_execmem_test_scrubbed(void *ptr) { return -EOPNOTSUPP; }
#endif
#endif
#endif
