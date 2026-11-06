/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_HDN_PGTABLE_H
#define _LINUX_HDN_PGTABLE_H

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/gfp_types.h>
#include <linux/nodemask.h>

struct page;
struct kimage;
struct hdn_hibernate_copy_page;
struct hdn_pt_stats {
	u64 allocated;
	u64 retired;
	u64 active_pages;
	u64 reserve_pages;
	u64 allocation_failures;
	u64 foreign_code_ranges;
	u64 foreign_code_pages;
};

#if defined(CONFIG_SECURITY_HARDENING_PGTABLE) && !defined(HDN_PGTABLE_BOOTSTRAP)
bool hdn_pt_active(void);
bool hdn_pt_platform_supported(void);
const char *hdn_pt_state(void);
const char *hdn_pt_firmware_state(void);
const char *hdn_pt_terminal_state(void);
void hdn_pt_efi_wx_result(bool runtime_present, bool active);
void hdn_pt_release_reserved(struct page *page);
int hdn_pt_kexec_seal(struct kimage *image);
int hdn_pt_kexec_data_seal(struct kimage *image, struct page *page);
void hdn_pt_kexec_release(struct kimage *image);
int hdn_pt_hibernate_seal(void);
int hdn_pt_hibernate_copy_seal(struct hdn_hibernate_copy_page *pages,
		unsigned long count);
void hdn_pt_hibernate_release(void);
struct page *hdn_pt_alloc(gfp_t gfp, unsigned int order, bool reserve_only);
unsigned long hdn_pt_alloc_address(gfp_t gfp, unsigned int order, bool reserve_only);
void hdn_pt_free_address(unsigned long address, unsigned int order);
bool hdn_pt_free(struct page *page, unsigned int order);
int hdn_pt_mapping(unsigned long address, unsigned long pfn,
		   unsigned long nr, unsigned long flags);
void hdn_pt_init(void);
int hdn_pt_hyperv_seal(void *root, unsigned long code);
void hdn_pt_hyperv_switch(bool install);
int hdn_pt_boot_handoff_seal(unsigned long root, unsigned long launch);
int hdn_pt_foreign_code_seal(phys_addr_t start, size_t size, const void *owner);
void hdn_pt_get_stats(struct hdn_pt_stats *stats);
#ifdef CONFIG_NUMA
int hdn_pt_policy_nodes(gfp_t gfp, nodemask_t *allowed, nodemask_t *preferred);
#else
static inline int hdn_pt_policy_nodes(gfp_t gfp, nodemask_t *allowed,
                                      nodemask_t *preferred)
{
	*allowed = node_states[N_MEMORY];
	*preferred = *allowed;
	return 0;
}
#endif
#else
static inline const char *hdn_pt_state(void) { return "disabled"; }
static inline const char *hdn_pt_firmware_state(void) { return "disabled"; }
static inline const char *hdn_pt_terminal_state(void) { return "disabled"; }
static inline void hdn_pt_efi_wx_result(bool runtime_present, bool active) { }
static inline bool hdn_pt_platform_supported(void) { return false; }
static inline void hdn_pt_init(void) { }
static inline void hdn_pt_release_reserved(struct page *page) { }
static inline int hdn_pt_kexec_seal(struct kimage *image) { return 0; }
static inline int hdn_pt_kexec_data_seal(struct kimage *image, struct page *page)
{ return -EOPNOTSUPP; }
static inline void hdn_pt_kexec_release(struct kimage *image) { }
static inline int hdn_pt_hibernate_seal(void) { return 0; }
static inline int hdn_pt_hibernate_copy_seal(struct hdn_hibernate_copy_page *pages,
		unsigned long count) { return -EOPNOTSUPP; }
static inline void hdn_pt_hibernate_release(void) { }
#define hdn_pt_alloc(gfp, order, reserve_only) alloc_pages((gfp) | __GFP_COMP, order)
#define hdn_pt_alloc_address(gfp, order, reserve_only) __get_free_pages(gfp, order)
#define hdn_pt_free_address(address, order) free_pages(address, order)
static inline bool hdn_pt_free(struct page *page, unsigned int order) { return false; }
static inline int hdn_pt_mapping(unsigned long address, unsigned long pfn,
		unsigned long nr, unsigned long flags) { return 0; }
static inline int hdn_pt_foreign_code_seal(phys_addr_t start, size_t size,
		const void *owner) { return 0; }
#endif
#endif
