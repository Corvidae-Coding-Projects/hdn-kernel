/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_LOCK_WAITER_TYPES_H
#define _LINUX_LOCK_WAITER_TYPES_H

#include <linux/rbtree_types.h>
#include <linux/types.h>

struct rt_mutex_base;
struct task_struct;
struct ww_acquire_ctx;

struct mutex_waiter {
	struct list_head		list;
	struct task_struct	*task;
	struct ww_acquire_ctx	*ww_ctx;
#ifdef CONFIG_DEBUG_MUTEXES
	void			*magic;
#endif
};

enum rwsem_waiter_type {
	RWSEM_WAITING_FOR_WRITE,
	RWSEM_WAITING_FOR_READ
};

struct rwsem_waiter {
	struct list_head		list;
	struct task_struct	*task;
	enum rwsem_waiter_type	type;
	unsigned long		timeout;
	bool			handoff_set;
};

struct semaphore_waiter {
	struct list_head		list;
	struct task_struct	*task;
	bool			up;
};

struct rt_waiter_node {
	struct rb_node	entry;
	int		prio;
	u64		deadline;
};

struct rt_mutex_waiter {
	struct rt_waiter_node	tree;
	struct rt_waiter_node	pi_tree;
	struct task_struct	*task;
	struct rt_mutex_base	*lock;
	unsigned int		wake_state;
	struct ww_acquire_ctx	*ww_ctx;
};

enum hdn_lock_waiter_type {
	HDN_LOCK_WAITER_NONE,
	HDN_LOCK_WAITER_MUTEX,
	HDN_LOCK_WAITER_RWSEM,
	HDN_LOCK_WAITER_SEMAPHORE,
	HDN_LOCK_WAITER_RT_MUTEX,
};

union hdn_lock_waiter {
	struct mutex_waiter	mutex;
	struct rwsem_waiter	rwsem;
	struct semaphore_waiter semaphore;
	struct rt_mutex_waiter	rt_mutex;
};

#endif /* _LINUX_LOCK_WAITER_TYPES_H */
