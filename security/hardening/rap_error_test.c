// SPDX-License-Identifier: GPL-2.0-only
/* Post-boot probes use the real kprobe and protected exception interfaces. */
#include <linux/error-injection.h>
#include <linux/export.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/ptrace.h>

int hdn_rap_error_test_run(unsigned int mode);
static DEFINE_MUTEX(test_lock);
static unsigned long body_calls, return_calls, mode;
static long normal_result = 37;
static bool wrong_return;

static noinline long hdn_rap_error_target(void)
{
	body_calls++;
	return READ_ONCE(normal_result);
}
ALLOW_ERROR_INJECTION(hdn_rap_error_target, ERRNO);

static noinline long hdn_rap_unmarked_target(void)
{
	body_calls++;
	return READ_ONCE(normal_result);
}

static int inject(struct kprobe *probe, struct pt_regs *regs)
{
	if (mode == 1)
		regs->sp += sizeof(long);
	regs_set_return_value(regs, -EIO);
	override_function_with_return(regs);
	/* Aggregated BPF handlers may update the same permitted result twice. */
	regs_set_return_value(regs, -EAGAIN);
	override_function_with_return(regs);
	return 1;
}
NOKPROBE_SYMBOL(inject);

static int returned(struct kretprobe_instance *instance, struct pt_regs *regs)
{
	return_calls++;
	if ((long)regs_return_value(regs) != -EAGAIN)
		wrong_return = true;
	return 0;
}
NOKPROBE_SYMBOL(returned);

int hdn_rap_error_test_run(unsigned int requested)
{
	struct kprobe probe = { .pre_handler = inject };
	struct kretprobe retprobe = { .handler = returned, .maxactive = 4 };
	long (*target)(void) = requested == 2 ? hdn_rap_unmarked_target : hdn_rap_error_target;
	unsigned long before;
	bool have_return = false, have_probe = false;
	int error;

	if (requested > 2)
		return -EINVAL;
	mutex_lock(&test_lock);
	mode = requested;
	body_calls = return_calls = 0;
	wrong_return = false;
	error = -EUCLEAN;
	if (target() != 37 || body_calls != 1)
		goto out;
	probe.addr = (kprobe_opcode_t *)target;
	if (!requested) {
		retprobe.kp.addr = (kprobe_opcode_t *)target;
		error = register_kretprobe(&retprobe);
		if (error)
			goto out;
		have_return = true;
	}
	error = register_kprobe(&probe);
	if (error)
		goto out;
	have_probe = true;
	before = body_calls;
	if (requested)
		pr_info("HDN_RAP_ERROR_PROBE_READY mode=%u\n", requested);
	error = -EUCLEAN;
	if (target() != -EAGAIN || body_calls != before || requested ||
	    return_calls != 1 || wrong_return || retprobe.nmissed)
		goto out;
	unregister_kprobe(&probe);
	have_probe = false;
	unregister_kretprobe(&retprobe);
	have_return = false;
	if (target() != 37 || body_calls != before + 1)
		goto out;
	pr_info("HDN_RAP_ERROR_PROBE_PASS entry override repeated return-hook unregister\n");
	error = 0;
out:
	if (have_probe)
		unregister_kprobe(&probe);
	if (have_return)
		unregister_kretprobe(&retprobe);
	mutex_unlock(&test_lock);
	return error;
}
EXPORT_SYMBOL_GPL(hdn_rap_error_test_run);
