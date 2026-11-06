/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_HDN_TEXT_H
#define _ASM_X86_HDN_TEXT_H

#include <linux/types.h>
#include <linux/init.h>
#include <asm/pgtable_types.h>

struct page;
enum hdn_transition;
enum hdn_reason;

enum hdn_text_kind {
	HDN_TEXT_LIVE_PATCH,
	HDN_TEXT_DEBUGGER,
	HDN_TEXT_UNUSED_CODE,
	HDN_TEXT_TRAP_FILL,
	HDN_TEXT_KIND_COUNT,
};

/* Private stack capability. No constructor or token API is exported to modules. */
struct hdn_text_token {
	u64 generation;
};

struct hdn_text_window_stats {
	u64 started;
	u64 completed;
	u64 rejected;
	/* Shared text/descriptor deferred mailbox counters. */
	u64 audit_omitted;
	u64 audit_deferred;
	bool active;
};

#ifdef CONFIG_SECURITY_HARDENING_KERNEL_WX
void __init hdn_text_bind_window(pte_t *ptep);
void hdn_x86_defer_transition(enum hdn_transition transition, u64 generation,
			       enum hdn_reason reason);
void hdn_text_prepare(struct hdn_text_token *token, void *address, size_t size,
		      struct page **pages, pte_t *ptep, enum hdn_text_kind kind);
void hdn_text_open(struct hdn_text_token *token, pte_t *ptep, void *address,
		   size_t size, enum hdn_text_kind kind);
void hdn_text_close(struct hdn_text_token *token, pte_t *ptep);
void hdn_text_report(const struct hdn_text_token *token, enum hdn_text_kind kind);
void hdn_text_get_stats(struct hdn_text_window_stats *stats);
#else
static inline void hdn_text_bind_window(pte_t *ptep) { }
static inline void hdn_text_prepare(struct hdn_text_token *token, void *address,
		 size_t size, struct page **pages, pte_t *ptep, enum hdn_text_kind kind) { }
static inline void hdn_text_open(struct hdn_text_token *token, pte_t *ptep,
		void *address, size_t size, enum hdn_text_kind kind) { }
static inline void hdn_text_close(struct hdn_text_token *token, pte_t *ptep) { }
static inline void hdn_text_report(const struct hdn_text_token *token,
				   enum hdn_text_kind kind) { }
#endif
#endif
