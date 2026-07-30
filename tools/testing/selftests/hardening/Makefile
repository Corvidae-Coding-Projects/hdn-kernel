# SPDX-License-Identifier: GPL-2.0

TEST_GEN_PROGS := hdn_smoke
TEST_GEN_PROGS_EXTENDED := hdn_elfnote_jit
TEST_FILES := capability.policy chroot-mount.policy cred-deny.policy jit.policy kallsyms-api.sh kill.policy mount-policy.policy mount-ro-policy.policy namespace-only.policy namespace-proc-task.policy object-audit.policy privexec-deny.policy proc-disclose.policy proc-task.policy relro.policy restricted.policy socket-policy.policy trace-symbol.policy userns-depth.policy run-qemu-smoke.sh vm_init.c
CFLAGS += -pthread
LDLIBS += -pthread

include ../lib.mk
