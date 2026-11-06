/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_HDN_SLAB_H
#define _LINUX_HDN_SLAB_H
#include <linux/types.h>

struct hdn_slab_layout_stats {
	u64 allocation_attempts;
	u64 allocation_failures;
	u64 slabs;
	u64 fallback;
	u64 no_offset_room;
	u64 offset_slabs;
	u64 offset_bytes;
	u64 original_objects;
	u64 placed_objects;
	u64 displaced_objects;
	bool active;
};

#ifdef CONFIG_SECURITY_HARDENING_SLAB_LAYOUT
void hdn_slab_layout_stats(struct hdn_slab_layout_stats *stats);
#endif

#ifdef CONFIG_SECURITY_HARDENING_SLAB_LAYOUT_TEST
struct kmem_cache;
int hdn_slab_layout_test_configure(struct kmem_cache *cache,
		u64 order_choice, u64 offset_choice, unsigned long fail_orders);
void hdn_slab_layout_test_clear(struct kmem_cache *cache,
		u64 *allocation_attempts, u64 *allocation_failures);
#endif
#endif
