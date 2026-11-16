/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_WAIT_TYPES_H
#define _LINUX_WAIT_TYPES_H

#include <linux/list.h>
#include <linux/spinlock_types.h>

struct folio;
struct wait_queue_entry;
typedef int (*wait_queue_func_t)(struct wait_queue_entry *wq_entry,
		unsigned int mode, int flags, void *key);

struct wait_queue_entry {
	unsigned int		flags;
	void			*private;
	wait_queue_func_t	func;
	struct list_head	entry;
};

struct wait_queue_head {
	spinlock_t		lock;
	struct list_head	head;
};

struct wait_bit_key {
	unsigned long		*flags;
	int			bit_nr;
	unsigned long		timeout;
};

struct wait_bit_queue_entry {
	struct wait_bit_key	key;
	struct wait_queue_entry	wq_entry;
};

struct wait_page_queue {
	struct folio		*folio;
	int			bit_nr;
	struct wait_queue_entry	wait;
};

#ifdef CONFIG_SECURITY_HARDENING_PRIVATE_STACKS
/*
 * Manual wait-queue users can nest (for example, poll plus a driver wait).
 * Keep a small task-owned pool so no queued descriptor is left on a private
 * stack while that stack is unmapped.
 */
#define HDN_WAIT_SLOTS	8
#define HDN_WAIT_OBJECT_SLOTS	4
#define HDN_WAIT_OBJECT_SIZE	256

union hdn_wait_object {
	u8 data[HDN_WAIT_OBJECT_SIZE];
	u64 align;
} __aligned(16);
#endif

#endif /* _LINUX_WAIT_TYPES_H */
