/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_WAIT_TYPES_H
#define _LINUX_WAIT_TYPES_H

#include <linux/list.h>
#include <linux/spinlock_types.h>

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

#endif /* _LINUX_WAIT_TYPES_H */
