/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_HDN_STACK_H
#define _ASM_X86_HDN_STACK_H

#include <linux/hdn_stack.h>
#include <linux/errno.h>
#include <linux/sched/task_stack.h>
#include <asm/processor.h>
#include <asm/ptrace.h>

#ifdef CONFIG_SECURITY_HARDENING_PRIVATE_STACKS
int hdn_stack_user_store(struct task_struct *task, unsigned int offset,
			 unsigned long value, unsigned long mask);
#endif

/* ptrace/regset callers already hold the target's stopped-task lifetime.
 * The offset describes a pt_regs field, never an arbitrary stack address. */
static inline unsigned long hdn_task_reg_read(const struct task_struct *task, unsigned int offset)
{
	unsigned long address = (unsigned long)task_pt_regs(task) + offset;
	unsigned long value;

	if (offset > sizeof(struct pt_regs) - sizeof(value) || !IS_ALIGNED(offset, sizeof(value)))
		BUG();
#ifdef CONFIG_SECURITY_HARDENING_PRIVATE_STACKS
	if (hdn_stack_address(address)) {
		if (hdn_stack_read(task, address, &value, sizeof(value)))
			BUG();
		return value;
	}
#endif
	return READ_ONCE(*(unsigned long *)address);
}

static inline int hdn_task_reg_update(struct task_struct *task, unsigned int offset,
				      unsigned long value, unsigned long mask)
{
	unsigned long *address = (void *)task_pt_regs(task) + offset;

	if (offset > sizeof(struct pt_regs) - sizeof(value) || !IS_ALIGNED(offset, sizeof(value)))
		return -EINVAL;
#ifdef CONFIG_SECURITY_HARDENING_PRIVATE_STACKS
	if (hdn_stack_address((unsigned long)address))
		return hdn_stack_user_store(task, offset, value, mask);
#endif
	WRITE_ONCE(*address, (READ_ONCE(*address) & ~mask) | (value & mask));
	return 0;
}

#define hdn_task_reg(task, field) \
	((typeof(((struct pt_regs *)0)->field))hdn_task_reg_read(task, offsetof(struct pt_regs, field)))
#define hdn_task_reg_set(task, field, value) \
	hdn_task_reg_update(task, offsetof(struct pt_regs, field), value, \
			   (unsigned long)(typeof(((struct pt_regs *)0)->field))~0ULL)

static inline bool hdn_task_user_64bit_mode(struct task_struct *task)
{
	struct pt_regs regs = { .cs = hdn_task_reg(task, cs) };

	return user_64bit_mode(&regs);
}

static inline void hdn_task_regs_snapshot(struct task_struct *task, struct pt_regs *snapshot)
{
	struct pt_regs *regs = task_pt_regs(task);

#ifdef CONFIG_SECURITY_HARDENING_PRIVATE_STACKS
	if (hdn_stack_address((unsigned long)regs)) {
		if (hdn_stack_read(task, (unsigned long)regs, snapshot, sizeof(*snapshot)))
			BUG();
		return;
	}
#endif
	*snapshot = *regs;
}

#endif
