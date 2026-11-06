// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

extern bool CONFIG_SECURITY_HARDENING_BPF_EXECMEM __kconfig __weak;
__u64 entries_a, entries_b, exits, bad_args;
bool isolated;

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(entry_a, int a)
{
	isolated = CONFIG_SECURITY_HARDENING_BPF_EXECMEM;
	entries_a++;
	bad_args += a != 1;
	return 0;
}

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(entry_b, int a)
{
	entries_b++;
	bad_args += a != 1;
	return 0;
}

SEC("fexit/bpf_fentry_test1")
int BPF_PROG(exit_a, int a, int ret)
{
	exits++;
	bad_args += a != 1 || ret != 2;
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
