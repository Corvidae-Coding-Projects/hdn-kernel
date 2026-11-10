// SPDX-License-Identifier: GPL-2.0-only
/* Test-only real task lifetimes for private-stack mapping probes. */
#include <linux/export.h>
#include <linux/hdn_stack.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/sched/task_stack.h>
#include <linux/uaccess.h>

#include "private_stack_test.h"

struct hdn_private_stack_sleeper {
	struct completion ready;
	struct completion release;
};

static int hdn_private_stack_idle(void *unused)
{
	return 0;
}

static int hdn_private_stack_sleep(void *opaque)
{
	struct hdn_private_stack_sleeper *state = opaque;

	complete(&state->ready);
	wait_for_completion(&state->release);
	return 0;
}

static int hdn_private_stack_inactive(unsigned int mode)
{
	struct task_struct *task;
	unsigned long *stack;
	unsigned long value = 0;
	int error = -EINVAL;

	task = kthread_create(hdn_private_stack_idle, NULL, "hdn-stack-probe");
	if (IS_ERR(task))
		return PTR_ERR(task);
	stack = try_get_task_stack(task);
	if (!stack) {
		error = -ESRCH;
		goto stop;
	}
	if (mode == 0) {
		/* A never-run task is published but has never been installed in a
		 * CPU view. Its stable identity must be inaccessible normally while
		 * the bounded reader can still inspect its dedicated backing. */
		if (!copy_from_kernel_nofault(&value, stack, sizeof(value)))
			goto put;
		if (hdn_stack_read(task, (unsigned long)stack, &value, sizeof(value)))
			goto put;
		for (unsigned long offset = PAGE_SIZE;
		     offset < min_t(unsigned long, THREAD_SIZE / 2, 2 * PAGE_SIZE);
		     offset += sizeof(value)) {
			if (hdn_stack_read(task, (unsigned long)stack + offset,
					   &value, sizeof(value)) || value)
				goto put;
		}
		error = 0;
		goto put;
	}
	pr_info("HDN_PRIVATE_STACK_PROBE_READY mode=%u inactive=%px\n", mode, stack);
	if (mode == 6)
		value = READ_ONCE(*stack);
	else if (mode == 7)
		WRITE_ONCE(*stack, 0);
	else
		goto put;
	barrier_data(value);
	pr_err("HDN_PRIVATE_STACK_PROBE_UNEXPECTED_RETURN mode=%u\n", mode);
put:
	put_task_stack(task);
stop:
	kthread_stop(task);
	return error;
}

static int hdn_private_stack_capture(void)
{
	struct hdn_private_stack_sleeper state;
	struct task_struct *never, *sleeping;

	init_completion(&state.ready);
	init_completion(&state.release);
	never = kthread_create(hdn_private_stack_idle, NULL, "hdn-stack-captured");
	if (IS_ERR(never))
		return PTR_ERR(never);
	sleeping = kthread_run(hdn_private_stack_sleep, &state, "hdn-stack-sleeping");
	if (IS_ERR(sleeping)) {
		kthread_stop(never);
		return PTR_ERR(sleeping);
	}
	wait_for_completion(&state.ready);
	if (!wait_task_inactive(sleeping, TASK_UNINTERRUPTIBLE)) {
		complete(&state.release);
		kthread_stop(sleeping);
		kthread_stop(never);
		return -EBUSY;
	}
	pr_emerg("HDN_PRIVATE_STACK_CAPTURE role=current task=%px address=%px length=256\n",
		 current, task_stack_page(current) + PAGE_SIZE);
	pr_emerg("HDN_PRIVATE_STACK_CAPTURE role=sleeping task=%px address=%px length=256\n",
		 sleeping, task_stack_page(sleeping) + PAGE_SIZE);
	pr_emerg("HDN_PRIVATE_STACK_CAPTURE role=kthread task=%px address=%px length=256\n",
		 never, task_stack_page(never) + PAGE_SIZE);
	panic("HDN private-stack crash capture requested");
}

int hdn_private_stack_test_run(unsigned int mode)
{
	int error;

	if (mode <= 5)
		error = hdn_stack_test_current(mode);
	else if (mode <= 7)
		error = hdn_private_stack_inactive(mode);
	else if (mode == 8)
		error = hdn_private_stack_capture();
	else
		error = -EINVAL;
	if (!error)
		pr_info("HDN_PRIVATE_STACK_PROBE_PASS\n");
	return error;
}
EXPORT_SYMBOL_GPL(hdn_private_stack_test_run);
