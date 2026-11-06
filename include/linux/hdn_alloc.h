/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_HDN_ALLOC_H
#define _LINUX_HDN_ALLOC_H
#include <linux/types.h>
#include <linux/hdn_alloc_domains.h>

struct kmem_cache;

struct hdn_alloc_stats {
	u64 typed;
	u64 successful;
	u64 failed;
	u64 mandatory;
	u64 early;
	u64 rejected;
	u32 caches;
	bool ready;
};

#ifdef CONFIG_SECURITY_HARDENING_AUTOSLAB
void hdn_alloc_get_stats(struct hdn_alloc_stats *stats);
void hdn_cache_domain(struct kmem_cache *cache, enum hdn_alloc_domain domain);
#define SLAB_HDN_DOMAIN SLAB_NO_MERGE
/* Only the compiler emits calls to this entry point. No registration API. */
void *__hdn_alloc_typed(size_t size, gfp_t flags, int node, unsigned int virtual,
			u64 identity, unsigned int domain);
#ifdef CONFIG_SECURITY_HARDENING_AUTOSLAB_TEST
int hdn_alloc_test_fail(u64 identity);
void hdn_alloc_test_clear(u64 *attempts, u64 *failures);
#endif
#else
#define SLAB_HDN_DOMAIN 0
static inline void hdn_cache_domain(struct kmem_cache *cache,
				    enum hdn_alloc_domain domain) { }
#endif
#endif
