// SPDX-License-Identifier: GPL-2.0-only
/* Test-only real user mappings. Modes 1 and 2 intentionally oops. */
#include <linux/hdn_uaccess.h>
#include <linux/hrtimer.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <asm/apic.h>
#include <asm/irq_regs.h>
#include <asm/nmi.h>
#include <asm/special_insns.h>

#define HDN_UDEREF_WORD 0x9182736455aacc33ULL
static DEFINE_MUTEX(uderef_probe_lock);
static struct hrtimer uderef_timer;
static int uderef_cpu = -1;
static bool irq_seen, irq_clean, nmi_seen, nmi_clean, nmi_pending;

static int uderef_nmi(unsigned int type, struct pt_regs *regs)
{
	if (raw_smp_processor_id() != READ_ONCE(uderef_cpu) || !READ_ONCE(nmi_pending))
		return NMI_DONE;
	WRITE_ONCE(nmi_clean, !(native_save_fl() & X86_EFLAGS_AC));
	WRITE_ONCE(nmi_seen, true);
	WRITE_ONCE(nmi_pending, false);
	return NMI_HANDLED;
}

static enum hrtimer_restart uderef_interrupt(struct hrtimer *timer)
{
	struct pt_regs *regs = get_irq_regs();

	/* Only count an interrupt that actually interrupted the open window. */
	if (regs && (regs->flags & X86_EFLAGS_AC)) {
		WRITE_ONCE(irq_clean, !(native_save_fl() & X86_EFLAGS_AC));
		WRITE_ONCE(irq_seen, true);
		WRITE_ONCE(nmi_pending, true);
		__apic_send_IPI_self(NMI_VECTOR);
		return HRTIMER_NORESTART;
	}
	hrtimer_forward_now(timer, ns_to_ktime(100000));
	return HRTIMER_RESTART;
}

static int uderef_interrupt_window(u64 __user *user)
{
	u64 value = 0;
	unsigned long after = 0, iterations = 10000000;
	int error;

	if (irqs_disabled())
		return -EOPNOTSUPP;
	irq_seen = irq_clean = nmi_seen = nmi_clean = nmi_pending = false;
	error = register_nmi_handler(NMI_LOCAL, uderef_nmi, NMI_FLAG_FIRST, "hdn-uderef");
	if (error)
		return error;
	hrtimer_setup(&uderef_timer, uderef_interrupt, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED_HARD);
	migrate_disable();
	preempt_disable();
	WRITE_ONCE(uderef_cpu, smp_processor_id());
	hrtimer_start(&uderef_timer, ns_to_ktime(100000), HRTIMER_MODE_REL_PINNED_HARD);
	error = -EFAULT;
	if (!user_access_begin(user, sizeof(*user)))
		goto out;
	unsafe_get_user(value, user, fault);
	/* No function call is allowed in this window. IRQ and NMI entry must
	 * close AC and restore it on return without corrupting the data. */
	asm volatile("1: pause; dec %[count]; jnz 1b; pushfq; popq %[flags]"
		     : [count] "+r" (iterations), [flags] "=r" (after)
		     : : "cc", "memory");
	unsafe_get_user(value, user, fault);
	user_access_end();
	error = value == HDN_UDEREF_WORD && (after & X86_EFLAGS_AC) &&
		!(native_save_fl() & X86_EFLAGS_AC) ? 0 : -EIO;
	goto out;
fault:
	user_access_end();
out:
	preempt_enable();
	hrtimer_cancel(&uderef_timer);
	/* Do not unregister while an already-sent self-NMI is still in flight. */
	for (iterations = 0; READ_ONCE(nmi_pending) && iterations < 10000000; iterations++)
		cpu_relax();
	if (READ_ONCE(nmi_pending))
		panic("HDN UDEREF probe self-NMI did not complete");
	WRITE_ONCE(uderef_cpu, -1);
	migrate_enable();
	unregister_nmi_handler(NMI_LOCAL, "hdn-uderef");
	if (!error && (!irq_seen || !nmi_seen))
		error = -ENODATA;
	if (!error && (!irq_clean || !nmi_clean))
		error = -EIO;
	return error;
}

static noinline u64 hdn_uderef_raw_read(u64 __user *user)
{
	return *(volatile u64 __force *)user;
}

static noinline void hdn_uderef_raw_write(u64 __user *user)
{
	*(volatile u64 __force *)user = 0;
}

long hdn_uderef_test_run(unsigned int mode, unsigned long address);
long hdn_uderef_test_run(unsigned int mode, unsigned long address)
{
	u64 __user *user = (u64 __user *)address;
	u64 value = 0, before;
	unsigned long flags, cr4;
	int error = 0;

	if (mode > 5)
		return -EINVAL;
	if (strcmp(hdn_uderef_state(), "hardware"))
		return -EOPNOTSUPP;
	if (mutex_lock_interruptible(&uderef_probe_lock))
		return -EINTR;
	if (native_save_fl() & X86_EFLAGS_AC) {
		error = -EIO;
		goto out;
	}
	if (mode == 4) {
		/* User supplies a PROT_NONE page. Exercise the actual access fixup,
		 * including CLAC on the unsafe_get_user error edge. */
		if (copy_from_user(&value, user, sizeof(value)) != sizeof(value) ||
		    get_user(value, user) != -EFAULT ||
		    copy_from_user_nofault(&value, user, sizeof(value)) != -EFAULT) {
			error = -EIO;
			goto out;
		}
		if (!user_access_begin(user, sizeof(*user))) {
			error = -ERANGE;
			goto out;
		}
		unsafe_get_user(value, user, fixed_fault);
		user_access_end();
		error = -EIO;
		goto out;
fixed_fault:
		user_access_end();
		error = native_save_fl() & X86_EFLAGS_AC ? -EIO : 0;
		goto out;
	}
	/* Demonstrate that the same address is readable through an approved
	 * window before the ordinary dereference. Invalid addresses cannot
	 * produce a false positive for the SMAP fault modes. */
	if (copy_from_user(&value, user, sizeof(value)) || value != HDN_UDEREF_WORD) {
		error = -EFAULT;
		goto out;
	}
	pr_info("HDN_UDEREF_PROBE_READY mode=%u\n", mode);
	switch (mode) {
	case 0:
		if (copy_from_user_nofault(&value, user, sizeof(value)) ||
		    value != HDN_UDEREF_WORD) {
			error = -EIO;
			break;
		}
		if (get_user(value, user) || value != HDN_UDEREF_WORD) {
			error = -EIO;
			break;
		}
		if (put_user(~value, user) || get_user(value, user) ||
		    value != ~HDN_UDEREF_WORD) {
			error = -EIO;
			break;
		}
		value = HDN_UDEREF_WORD;
		if (copy_to_user(user, &value, sizeof(value)))
			error = -EIO;
		break;
	case 1:
		value = hdn_uderef_raw_read(user);
		pr_err("HDN_UDEREF_UNEXPECTED_READ\n");
		error = -EIO;
		break;
	case 2:
		hdn_uderef_raw_write(user);
		pr_err("HDN_UDEREF_UNEXPECTED_WRITE\n");
		error = -EIO;
		break;
	case 3:
		before = hdn_uderef_repairs();
		local_irq_save(flags);
		cr4 = __read_cr4();
		native_write_cr4(cr4 & ~X86_CR4_SMAP);
		if (__read_cr4() != cr4)
			error = -EIO;
		local_irq_restore(flags);
		if (hdn_uderef_repairs() <= before)
			error = -EIO;
		break;
	case 5:
		error = uderef_interrupt_window(user);
		break;
	}
	if (native_save_fl() & X86_EFLAGS_AC)
		error = -EIO;
out:
	mutex_unlock(&uderef_probe_lock);
	return error;
}
EXPORT_SYMBOL_GPL(hdn_uderef_test_run);
