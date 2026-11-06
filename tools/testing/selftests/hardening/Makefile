# SPDX-License-Identifier: GPL-2.0

TEST_GEN_PROGS := hdn_smoke
TEST_GEN_PROGS_EXTENDED := hdn_elfnote_jit hdn_sysfs_view hdn_sysfs_notify hdn_compat_target
TEST_FILES := capability.policy chroot-mount.policy cred-deny.policy hdn_null_runtime_vm.c jit.policy kallsyms-api.sh kill.policy mount-policy.policy mount-ro-policy.policy namespace-only.policy namespace-proc-task.policy object-audit.policy privexec-deny.policy proc-disclose.policy proc-task.policy relro.policy restricted.policy run-null-runtime-qemu.sh socket-policy.policy trace-symbol.policy userns-depth.policy run-qemu-smoke.sh vm_init.c
CFLAGS += -pthread
TEST_FILES += hdn_compat_corpus.py hdn_pgtable_vm.c
TEST_FILES += hdn_capability_corpus.py
TEST_FILES += hdn_status_capability.py
TEST_FILES += hdn_stack_compat32.S
TEST_FILES += hdn_respectre_fixture.c hdn_respectre_bad_asm.c hdn_respectre_native.c hdn_respectre_vm.c
TEST_FILES += hdn_bpf_execmem_vm.c
TEST_FILES += hdn_private_stacks_vm.c
TEST_FILES += hdn_private_stacks_stress.c
TEST_FILES += hdn_kvm_state_vm.c
TEST_FILES += hdn_slab_layout_stress.c
TEST_FILES += hdn_autoslab_vm.c hdn_alloc_fixture.h hdn_alloc_fixture_a.c hdn_alloc_fixture_b.c
TEST_FILES += hdn_jitter_vm.c
LDLIBS += -pthread

include ../lib.mk
