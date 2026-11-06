// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "hdn_bpf_detach.lskel.h"

static bool run_detach_target(struct hdn_bpf_detach_lskel *skel,
			      __u64 a, __u64 b, __u64 exit)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);

	skel->bss->entries_a = skel->bss->entries_b = skel->bss->exits = 0;
	skel->bss->bad_args = 0;
	return ASSERT_OK(bpf_prog_test_run_opts(skel->progs.entry_a.prog_fd, &opts),
			 "run_target") && ASSERT_OK(opts.retval, "target_result") &&
		ASSERT_EQ(skel->bss->entries_a, a, "entry_a_count") &&
		ASSERT_EQ(skel->bss->entries_b, b, "entry_b_count") &&
		ASSERT_EQ(skel->bss->exits, exit, "exit_count") &&
		ASSERT_EQ(skel->bss->bad_args, 0, "arguments_and_return");
}

/* Arm only this thread. Clear the injection before assertions, logging, or
 * another BPF syscall; those operations must not consume the intended fault. */
static bool close_with_fault(int fault_fd, int *link_fd, bool allocation_free)
{
	int ret, saved_errno;
	ssize_t armed, observed, cleared;
	char remaining[32] = {};

	armed = pwrite(fault_fd, "1", 1, 0);
	if (armed != 1) {
		pwrite(fault_fd, "0", 1, 0);
		return ASSERT_EQ(armed, 1, "arm_next_allocation");
	}
	ret = close(*link_fd);
	saved_errno = errno;
	*link_fd = -1;
	observed = pread(fault_fd, remaining, sizeof(remaining) - 1, 0);
	cleared = pwrite(fault_fd, "0", 1, 0);
	errno = saved_errno;
	return ASSERT_OK(ret, "close_link_under_fault") &&
		ASSERT_EQ(cleared, 1, "clear_fault") &&
		ASSERT_GT(observed, 0, "read_pending_fault") &&
		(!allocation_free || ASSERT_EQ(strtoul(remaining, NULL, 10), 1,
					       "partial_detach_did_not_allocate"));
}

/* Serialized because failslab's GFP filter is global. The actual fault is
 * thread-local, and both controls are restored on every exit. Run in the
 * disposable HDN guest with the signed-selftest key enrolled. */
void serial_test_hdn_bpf_detach(void)
{
	struct hdn_bpf_detach_lskel *skel = NULL;
	int links[3] = { -1, -1, -1 }, fault_fd = -1, filter_fd = -1;
	char previous = 0;
	bool filter_changed = false;

	skel = hdn_bpf_detach_lskel__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		goto out;
	skel->keyring_id = KEY_SPEC_SESSION_KEYRING;
	if (!ASSERT_OK(hdn_bpf_detach_lskel__load(skel), "load_signed_programs"))
		goto out;
	links[0] = bpf_link_create(skel->progs.entry_a.prog_fd, 0, BPF_TRACE_FENTRY, NULL);
	links[1] = bpf_link_create(skel->progs.entry_b.prog_fd, 0, BPF_TRACE_FENTRY, NULL);
	links[2] = bpf_link_create(skel->progs.exit_a.prog_fd, 0, BPF_TRACE_FEXIT, NULL);
	for (int i = 0; i < 3; i++)
		if (!ASSERT_GE(links[i], 0, "attach"))
			goto out;
	if (!run_detach_target(skel, 1, 1, 1))
		goto out;
	if (!skel->bss->isolated) {
		test__skip();
		goto out;
	}
	fault_fd = open("/proc/thread-self/fail-nth", O_RDWR);
	filter_fd = open("/sys/kernel/debug/failslab/ignore-gfp-wait", O_RDWR);
	if (!ASSERT_GE(fault_fd, 0, "fault_injection_config") ||
	    !ASSERT_GE(filter_fd, 0, "failslab_config") ||
	    !ASSERT_EQ(pread(filter_fd, &previous, 1, 0), 1, "read_filter"))
		goto out;
	if (!ASSERT_EQ(pwrite(filter_fd, "N", 1, 0), 1, "include_sleepable_allocations"))
		goto out;
	filter_changed = true;
	if (!close_with_fault(fault_fd, &links[0], true) || !run_detach_target(skel, 0, 1, 1))
		goto out;
	/* A subsequent attach rebuilds the image without resurrecting removed
	 * invocations, then a second removal exercises the newly generated gate. */
	links[0] = bpf_link_create(skel->progs.entry_a.prog_fd, 0, BPF_TRACE_FENTRY, NULL);
	if (!ASSERT_GE(links[0], 0, "reattach") || !run_detach_target(skel, 1, 1, 1) ||
	    !close_with_fault(fault_fd, &links[0], true) || !run_detach_target(skel, 0, 1, 1) ||
	    !close_with_fault(fault_fd, &links[2], true) || !run_detach_target(skel, 0, 1, 0) ||
	    !close_with_fault(fault_fd, &links[1], false) || !run_detach_target(skel, 0, 0, 0))
		goto out;
out:
	if (fault_fd >= 0) {
		ASSERT_EQ(pwrite(fault_fd, "0", 1, 0), 1, "clear_fault_cleanup");
		close(fault_fd);
	}
	if (filter_changed)
		ASSERT_EQ(pwrite(filter_fd, &previous, 1, 0), 1, "restore_filter");
	if (filter_fd >= 0)
		close(filter_fd);
	for (int i = 0; i < 3; i++)
		if (links[i] >= 0)
			close(links[i]);
	hdn_bpf_detach_lskel__destroy(skel);
}
