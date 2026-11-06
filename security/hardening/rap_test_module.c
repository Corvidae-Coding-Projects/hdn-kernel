// SPDX-License-Identifier: GPL-2.0-only
/* Signed, post-boot RAP probes. Destructive modes require fresh guests. */
#include <linux/completion.h>
#include <linux/hrtimer.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/nmi.h>
#include <linux/sched.h>
#include <asm/apic.h>
#include <asm/irq_vectors.h>

struct rap_test_payload { unsigned long value; };
typedef long (*rap_long_fn)(long value);
typedef long (*rap_payload_fn)(struct rap_test_payload *payload);

static unsigned int mode;
module_param(mode, uint, 0400);
MODULE_PARM_DESC(mode, "0=positive callback, 1=wrong indirect type, 2=overwrite return, 3=copy return, 4=IRQ/NMI/switch positive");

static struct completion timer_done, thread_done;
static struct hrtimer timer;
static unsigned long captured_return;
static long timer_value, nmi_value, thread_value;
static bool nmi_pending;

static noinline long rap_good(long value)
{
	return value + 17;
}

static noinline long rap_wrong(struct rap_test_payload *payload)
{
	(void)payload;
	pr_emerg("HDN_RAP_UNEXPECTED_WRONG_TARGET\n");
	return 0;
}

static noinline long rap_invoke(rap_long_fn function, long value)
{
	return function(value);
}

static noinline void rap_capture_return(void)
{
	captured_return = (unsigned long)__builtin_return_address(0);
}

static noinline void rap_overwrite_return(void)
{
	unsigned long *slot = (unsigned long *)__builtin_frame_address(0) + 1;

	WRITE_ONCE(*slot, 0);
	barrier();
}

static noinline void rap_copy_return(void)
{
	unsigned long *slot = (unsigned long *)__builtin_frame_address(0) + 1;

	WRITE_ONCE(*slot, READ_ONCE(captured_return));
	barrier();
}

static enum hrtimer_restart rap_timer(struct hrtimer *unused)
{
	rap_long_fn function = rap_good;

	timer_value = rap_invoke(function, 10);
	complete(&timer_done);
	return HRTIMER_NORESTART;
}

static unsigned int rap_nmi(unsigned int type, struct pt_regs *regs)
{
	rap_long_fn function = rap_good;

	if (!READ_ONCE(nmi_pending))
		return NMI_DONE;
	nmi_value = rap_invoke(function, 20);
	WRITE_ONCE(nmi_pending, false);
	return NMI_HANDLED;
}

static int rap_thread(void *unused)
{
	rap_long_fn function = rap_good;

	schedule_timeout_uninterruptible(1);
	thread_value = rap_invoke(function, 30);
	complete(&thread_done);
	return 0;
}

static int rap_positive_async(void)
{
	struct task_struct *task;
	unsigned long count;
	int error;

	init_completion(&timer_done);
	init_completion(&thread_done);
	hrtimer_setup(&timer, rap_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	hrtimer_start(&timer, ns_to_ktime(100000), HRTIMER_MODE_REL);
	if (!wait_for_completion_timeout(&timer_done, HZ))
		return -ETIMEDOUT;
	task = kthread_run(rap_thread, NULL, "hdn-rap-probe");
	if (IS_ERR(task))
		return PTR_ERR(task);
	if (!wait_for_completion_timeout(&thread_done, HZ))
		return -ETIMEDOUT;
	error = register_nmi_handler(NMI_LOCAL, rap_nmi, NMI_FLAG_FIRST, "hdn-rap-probe");
	if (error)
		return error;
	WRITE_ONCE(nmi_pending, true);
	__apic_send_IPI_self(NMI_VECTOR);
	for (count = 0; READ_ONCE(nmi_pending) && count < 10000000; count++)
		cpu_relax();
	unregister_nmi_handler(NMI_LOCAL, "hdn-rap-probe");
	if (READ_ONCE(nmi_pending))
		return -ETIMEDOUT;
	return timer_value == 27 && nmi_value == 37 && thread_value == 47 ? 0 : -EUCLEAN;
}

static int __init rap_test_init(void)
{
	rap_long_fn function;
	long value;

	if (mode > 4)
		return -EINVAL;
	pr_info("HDN_RAP_GUEST_READY mode=%u\n", mode);
	switch (mode) {
	case 0:
		function = rap_good;
		value = rap_invoke(function, 5);
		if (value != 22)
			return -EUCLEAN;
		break;
	case 1:
		function = (rap_long_fn)(unsigned long)(rap_payload_fn)rap_wrong;
		barrier_data(function);
		(void)rap_invoke(function, 5);
		return -EUCLEAN;
	case 2:
		rap_overwrite_return();
		return -EUCLEAN;
	case 3:
		rap_capture_return();
		rap_copy_return();
		return -EUCLEAN;
	case 4:
		if (rap_positive_async())
			return -EUCLEAN;
		break;
	}
	pr_info("HDN_RAP_GUEST_PASS mode=%u\n", mode);
	return 0;
}

static void __exit rap_test_exit(void)
{
	if (mode == 4)
		hrtimer_cancel(&timer);
}

module_init(rap_test_init);
module_exit(rap_test_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("HDN RAP typed-transfer, return and asynchronous-entry probes");
