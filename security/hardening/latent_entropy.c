// SPDX-License-Identifier: GPL-2.0-only
/* Supplemental state diversity. This code makes no entropy/readiness claim. */
#include <linux/bitops.h>
#include <linux/errno.h>
#include <linux/hdn_latent_entropy.h>
#include <linux/interrupt.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/random.h>
#include <linux/string.h>
#include <linux/timex.h>

struct hdn_latent_cpu {
	u64 trace;
	unsigned long domain;
	u32 events[HDN_LATENT_NR_SITES];
#ifdef CONFIG_SECURITY_HARDENING_LATENT_ENTROPY_TEST
	struct {
		u64 trace;
		unsigned long irq_flags;
		bool active;
	} test;
#endif
};

static DEFINE_PER_CPU(struct hdn_latent_cpu, hdn_latent_state);
static unsigned long hdn_latent_domain __read_mostly;

/* Defined unsigned arithmetic, independent of padding and stack contents. */
static u64 hdn_latent_step(u64 state, u64 input)
{
	return rol64(state ^ input, 17) + 0x9e3779b97f4a7c15ULL;
}

void hdn_latent_mix(unsigned long trace, unsigned int site)
{
	struct hdn_latent_cpu *state;
	unsigned long flags, domain;
	u64 contribution[3] = {};
	bool contribute = false;

	/* The collector never nests in NMI or retains pointers into callers. */
	if (in_nmi())
		return;
	preempt_disable();
	local_irq_save(flags);
	state = this_cpu_ptr(&hdn_latent_state);
#ifdef CONFIG_SECURITY_HARDENING_LATENT_ENTROPY_TEST
	if (site == HDN_LATENT_NR_SITES) {
		if (state->test.active)
			state->test.trace = hdn_latent_step(state->test.trace, trace);
		goto unlock;
	}
#endif
	if (site >= HDN_LATENT_NR_SITES)
		goto unlock;
	domain = READ_ONCE(hdn_latent_domain);
	if (state->domain != domain) {
		state->domain = domain;
		state->trace = hdn_latent_step(state->trace, domain);
	}
	state->trace = hdn_latent_step(state->trace,
				     (u64)trace ^ ((u64)site << 56));
	state->events[site]++;
	/* At most one pool mix per boot, 64 forks, or 1024 interrupt samples. */
	contribute = (site == HDN_LATENT_BOOT && state->events[site] == 1) ||
		(site == HDN_LATENT_FORK && !(state->events[site] & 63)) ||
		(site == HDN_LATENT_INTERRUPT && !(state->events[site] & 1023));
	if (contribute) {
		contribution[0] = state->trace;
		contribution[1] = random_get_entropy();
		contribution[2] = ((u64)state->events[site] << 32) | site;
		state->trace = 0;
	}
unlock:
	local_irq_restore(flags);
	preempt_enable();
	if (contribute)
		hdn_random_mix_nocredit(contribution, sizeof(contribution));
	memzero_explicit(contribution, sizeof(contribution));
}

void hdn_latent_reseed(void)
{
	unsigned long domain;

	/* Existing pool state may separate clones; it is never new entropy. */
	domain = rng_is_initialized() ? get_random_long() : random_get_entropy();
	WRITE_ONCE(hdn_latent_domain, domain);
}

#ifdef CONFIG_SECURITY_HARDENING_LATENT_ENTROPY_TEST
int hdn_latent_test_begin(u64 seed)
{
	struct hdn_latent_cpu *state;
	unsigned long flags;

	/* The fixture is bounded arithmetic and cannot sleep in this window. */
	preempt_disable();
	local_irq_save(flags);
	state = this_cpu_ptr(&hdn_latent_state);
	if (state->test.active) {
		local_irq_restore(flags);
		preempt_enable();
		return -EBUSY;
	}
	state->test.trace = seed;
	state->test.irq_flags = flags;
	state->test.active = true;
	return 0;
}

u64 hdn_latent_test_end(void)
{
	struct hdn_latent_cpu *state = this_cpu_ptr(&hdn_latent_state);
	unsigned long flags = state->test.irq_flags;
	u64 trace = state->test.trace;

	memzero_explicit(&state->test, sizeof(state->test));
	local_irq_restore(flags);
	preempt_enable();
	return trace;
}
#endif
