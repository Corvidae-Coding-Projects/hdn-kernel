// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE

#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/aio_abi.h>
#include <linux/capability.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/fanotify.h>
#include <linux/fs.h>
#include <linux/io_uring.h>
#include <linux/ip.h>
#include <linux/loop.h>
#include <linux/mount.h>
#include <linux/perf_event.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/userfaultfd.h>
#include <linux/xattr.h>
#include <limits.h>
#include <mqueue.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/file.h>
#include <sys/ipc.h>
#include <sys/ioctl.h>
#include <sys/msg.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <termios.h>
#include <net/if.h>
#include <netinet/in.h>
#include <time.h>
#include <unistd.h>

#include "../kselftest.h"

#ifndef F_SETOWN_EX
#define F_SETOWN_EX 15
#endif

#ifndef F_OWNER_PID
#define F_OWNER_PID 1
#endif

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

#ifndef PR_GET_SPECULATION_CTRL
#define PR_GET_SPECULATION_CTRL 52
#endif
#ifndef PR_SET_SPECULATION_CTRL
#define PR_SET_SPECULATION_CTRL 53
#endif
#ifndef PR_SPEC_STORE_BYPASS
#define PR_SPEC_STORE_BYPASS 0
#endif
#ifndef PR_SPEC_INDIRECT_BRANCH
#define PR_SPEC_INDIRECT_BRANCH 1
#endif
#ifndef PR_SPEC_PRCTL
#define PR_SPEC_PRCTL (1UL << 0)
#endif
#ifndef PR_SPEC_ENABLE
#define PR_SPEC_ENABLE (1UL << 1)
#endif
#ifndef PR_SPEC_FORCE_DISABLE
#define PR_SPEC_FORCE_DISABLE (1UL << 3)
#endif
#ifndef PR_SPEC_NOT_AFFECTED
#define PR_SPEC_NOT_AFFECTED (1UL << 4)
#endif
#ifndef MFD_NOEXEC_SEAL
#define MFD_NOEXEC_SEAL 0x0008U
#endif
#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
#endif
#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif
#ifndef __NR_copy_file_range
#define __NR_copy_file_range 326
#endif
#ifndef __NR_fanotify_init
#ifdef SYS_fanotify_init
#define __NR_fanotify_init SYS_fanotify_init
#endif
#endif
#ifndef __NR_fanotify_mark
#ifdef SYS_fanotify_mark
#define __NR_fanotify_mark SYS_fanotify_mark
#endif
#endif
#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd 438
#endif
#ifndef __NR_process_madvise
#define __NR_process_madvise 440
#endif
#ifndef __NR_process_mrelease
#define __NR_process_mrelease 448
#endif
#ifndef PIDFD_INFO_SUPPORTED_MASK
#define PIDFD_INFO_SUPPORTED_MASK (1ULL << 5)
#endif
#ifndef PIDFS_IOCTL_MAGIC
#define PIDFS_IOCTL_MAGIC 0xff
#endif
#ifndef PIDFD_GET_INFO
struct hdn_pidfd_info {
	uint64_t mask;
	uint64_t cgroupid;
	uint32_t pid;
	uint32_t tgid;
	uint32_t ppid;
	uint32_t ruid;
	uint32_t rgid;
	uint32_t euid;
	uint32_t egid;
	uint32_t suid;
	uint32_t sgid;
	uint32_t fsuid;
	uint32_t fsgid;
	int32_t exit_code;
	uint32_t coredump_mask;
	uint32_t coredump_signal;
	uint64_t supported_mask;
};
#define PIDFD_GET_INFO _IOWR(PIDFS_IOCTL_MAGIC, 11, struct hdn_pidfd_info)
#endif
#ifndef PIDFD_GET_UTS_NAMESPACE
#define PIDFD_GET_UTS_NAMESPACE _IO(PIDFS_IOCTL_MAGIC, 10)
#endif
#ifndef __NR_migrate_pages
#define __NR_migrate_pages 256
#endif
#ifndef __NR_move_pages
#define __NR_move_pages 279
#endif
#ifndef __NR_userfaultfd
#ifdef SYS_userfaultfd
#define __NR_userfaultfd SYS_userfaultfd
#endif
#endif
#ifndef MADV_COLD
#define MADV_COLD 20
#endif

#define HDN_SOCKET_TYPE_MASK 0xf
#define HDN_THREADSTACK_MAP_COUNT 64
#define HDN_THREADSTACK_MAP_SIZE (64UL * 1024UL)
#define HDN_MMAP_MIN_ADDR_FLOOR (64UL * 1024UL)
#define HDN_PROCESS_MEMORY_SENTINEL "hdn-process-memory"

#define HDN_STATUS "/sys/kernel/security/hardening/status"
#define HDN_EVENTS "/sys/kernel/security/hardening/events"
#define HDN_PROFILES "/sys/kernel/security/hardening/profiles"
#define HDN_SEALED_WRITE_PROBE \
	"/sys/kernel/security/hardening/sealed_write_probe"
#define HDN_KERNEL_LOCKOUT_PROBE \
	"/sys/kernel/security/hardening/kernel_lockout_probe"
#define HDN_PHASE "/sys/kernel/security/hardening/phase"
#define HDN_POLICY "/sys/kernel/security/hardening/policy"
#define HDN_REFRESH "/sys/kernel/security/hardening/refresh"
#define HDN_COMMIT "/sys/kernel/security/hardening/commit"
#define HDN_ROLLBACK "/sys/kernel/security/hardening/rollback"
#define HDN_AUDIT_FLOOD_BURST_CTL \
	"/sys/kernel/security/hardening/audit_flood_burst"
#define HDN_AUDIT_FLOOD_WINDOW_MS_CTL \
	"/sys/kernel/security/hardening/audit_flood_window_ms"
#define HDN_UNPRIV_BPF_DISABLED \
	"/proc/sys/kernel/unprivileged_bpf_disabled"
#define HDN_BPF_JIT_HARDEN "/proc/sys/net/core/bpf_jit_harden"
#define HDN_BPF_JIT_KALLSYMS "/proc/sys/net/core/bpf_jit_kallsyms"
#define HDN_PERF_EVENT_PARANOID "/proc/sys/kernel/perf_event_paranoid"
#define HDN_YAMA_PTRACE_SCOPE "/proc/sys/kernel/yama/ptrace_scope"
#define HDN_DMESG_RESTRICT "/proc/sys/kernel/dmesg_restrict"
#define HDN_DEV_KMSG "/dev/kmsg"
#define HDN_IO_URING_DISABLED "/proc/sys/kernel/io_uring_disabled"
#define HDN_KPTR_RESTRICT "/proc/sys/kernel/kptr_restrict"
#define HDN_MEMFD_NOEXEC "/proc/sys/vm/memfd_noexec"
#define HDN_MMAP_MIN_ADDR "/proc/sys/vm/mmap_min_addr"
#define HDN_UNPRIV_USERFAULTFD "/proc/sys/vm/unprivileged_userfaultfd"
#define HDN_LEGACY_TIOCSTI "/proc/sys/dev/tty/legacy_tiocsti"
#define HDN_LDISC_AUTOLOAD "/proc/sys/dev/tty/ldisc_autoload"
#define HDN_MODPROBE_PATH "/proc/sys/kernel/modprobe"
#define HDN_KEXEC_LOAD_DISABLED "/proc/sys/kernel/kexec_load_disabled"
#define HDN_MODULES_DISABLED "/proc/sys/kernel/modules_disabled"
#define HDN_MODPROBE_CONTEXT_CAPTURE "/hdn-modprobe-context"
#define HDN_MODPROBE_UNSAFE_DIR "/hdn-modprobe-unsafe"
#define HDN_MODPROBE_UNSAFE_PATH HDN_MODPROBE_UNSAFE_DIR "/modprobe"
#define HDN_SIGNED_POLICY "/default.hdn"
#define HDN_UNSIGNED_POLICY "/default.hdn.unsigned"
#define HDN_BROKER_SIGNED_POLICY "/hdn-policies/default.hdn"
#define HDN_RESTRICTED_POLICY "/restricted.hdn"
#define HDN_PROC_DISCLOSE_POLICY "/proc-disclose.hdn"
#define HDN_PROC_READER_EXEC "/hdn-proc-reader"
#define HDN_TRACE_SYMBOL_POLICY "/trace-symbol.hdn"
#define HDN_CHROOT_MOUNT_POLICY "/chroot-mount.hdn"
#define HDN_JIT_POLICY "/jit.hdn"
#define HDN_EXECSTACK_POLICY "/execstack.hdn"
#define HDN_TEXTREL_POLICY "/textrel.hdn"
#define HDN_RELRO_POLICY "/relro.hdn"
#define HDN_KILL_POLICY "/kill.hdn"
#define HDN_CRED_DENY_POLICY "/cred-deny.hdn"
#define HDN_PRIVEXEC_DENY_POLICY "/privexec-deny.hdn"
#define HDN_IDENTITY_POLICY "/identity.hdn"
#define HDN_MODULE_PATH_POLICY "/module-path.hdn"
#define HDN_FIRMWARE_POLICY "/firmware.hdn"
#define HDN_MOUNT_POLICY "/mount-policy.hdn"
#define HDN_MOUNT_RO_POLICY "/mount-ro-policy.hdn"
#define HDN_PROC_TASK_POLICY "/proc-task.hdn"
#define HDN_NAMESPACE_ONLY_POLICY "/namespace-only.hdn"
#define HDN_NAMESPACE_PROC_TASK_POLICY "/namespace-proc-task.hdn"
#define HDN_SUBJECT_POLICY "/subject.hdn"
#define HDN_USERNS_DEPTH_POLICY "/userns-depth.hdn"
#define HDN_ROLE_POLICY "/role.hdn"
#define HDN_CAPABILITY_POLICY "/capability.hdn"
#define HDN_OBJECT_AUDIT_POLICY "/object-audit.hdn"
#define HDN_PROCESS_ACCOUNT_POLICY "/process-account.hdn"
#define HDN_OBJECT_WRITE_POLICY "/object-write.hdn"
#define HDN_SOCKET_POLICY "/socket-policy.hdn"
#define HDN_BLOCK_ADMIN_POLICY "/block-admin.hdn"
#define HDN_REFRESH_TARGET "/hdn-refresh-target"
#define HDN_REFRESH_TARGET_NEW "/hdn-refresh-target.new"
#define HDN_USB_HOTPLUG_TRIGGER "/hdn-usb-hotplug-test"
#define HDN_DEBUGFS_KPROBES "/sys/kernel/debug/kprobes/list"
#define HDN_DEBUGFS_KPROBES_BLACKLIST "/sys/kernel/debug/kprobes/blacklist"
#define HDN_TRACE_SYMBOL_KPROBE_EVENT "hdn_direct_symbol_redact"
#define HDN_TRACEFS_TRACING_ON "/sys/kernel/tracing/tracing_on"
#define HDN_TEST_FIRMWARE_DIR "/sys/devices/virtual/misc/test_firmware"
#define HDN_TEST_FIRMWARE_TRIGGER HDN_TEST_FIRMWARE_DIR "/trigger_request"
#define HDN_SYSFS_RCU_EXPEDITED "/sys/kernel/rcu_expedited"
#define HDN_SYSFS_VMCOREINFO "/sys/kernel/vmcoreinfo"
#define HDN_SYSFS_BOOT_PARAMS_DATA "/sys/kernel/boot_params/data"
#define HDN_SYSFS_MEMMAP_START "/sys/firmware/memmap/0/start"
#define HDN_SYSFS_MEMMAP_TYPE "/sys/firmware/memmap/0/type"
#define HDN_SYSFS_SLAB_DIR "/sys/kernel/slab"
#define HDN_DEV_PORT "/dev/port"
#define HDN_DEV_USBMON0 "/dev/usbmon0"
#define HDN_DEV_CPU_DIR "/dev/cpu"
#define HDN_DEV_CPU0_DIR "/dev/cpu/0"
#define HDN_DEV_CPU_MSR "/dev/cpu/0/msr"
#define HDN_DEV_CPU_CPUID "/dev/cpu/0/cpuid"
#define HDN_MSR_MAJOR 202
#define HDN_CPUID_MAJOR 203
#define HDN_BLOCK_DEVICE_TEST "/hdn-block-device-test"
#define HDN_CAPABILITY_DENY_TARGET "/hdn-capability-deny-target"
#define HDN_CAPABILITY_AUDIT_TARGET "/hdn-capability-audit-target"
#define HDN_OBJECT_AUDIT_READ_TARGET "/hdn-object-audit-read"
#define HDN_OBJECT_AUDIT_APPEND_TARGET "/hdn-object-audit-append"
#define HDN_OBJECT_AUDIT_WRITE_TARGET "/hdn-object-audit-write"
#define HDN_OBJECT_AUDIT_FIND_TARGET "/hdn-object-audit-find"
#define HDN_OBJECT_AUDIT_CREATE_DIR "/hdn-object-audit-create-dir"
#define HDN_OBJECT_AUDIT_CREATE_TARGET \
	HDN_OBJECT_AUDIT_CREATE_DIR "/created"
#define HDN_OBJECT_AUDIT_DELETE_TARGET "/hdn-object-audit-delete"
#define HDN_OBJECT_AUDIT_LINK_TARGET "/hdn-object-audit-link"
#define HDN_OBJECT_AUDIT_LINK_DEST "/hdn-object-audit-link-dest"
#define HDN_OBJECT_AUDIT_SETID_TARGET "/hdn-object-audit-setid"
#define HDN_OBJECT_AUDIT_DENY_TARGET "/hdn-object-audit-deny"
#define HDN_PROC_KALLSYMS "/proc/kallsyms"
#define HDN_PROC_IOPORTS "/proc/ioports"
#define HDN_PROC_IOMEM "/proc/iomem"
#define HDN_PROC_KPAGECOUNT "/proc/kpagecount"
#define HDN_PROC_KPAGEFLAGS "/proc/kpageflags"
#define HDN_PROC_KPAGECGROUP "/proc/kpagecgroup"
#define HDN_PROC_VMALLOCINFO "/proc/vmallocinfo"
#define HDN_PROC_NET_PTYPE "/proc/net/ptype"
#define HDN_PROC_TIMER_LIST "/proc/timer_list"
#define HDN_PROC_SENSITIVE_ARG "hdn-proc-sensitive-arg"
#define HDN_PROC_SENSITIVE_ENV "HDN_PROC_SENSITIVE_ENV=hdn-proc-sensitive-env"
#define HDN_SIGNAL_CRASH_EXEC "/hdn-signal-crash"
#define HDN_MOUNT_TEST_DIR "/hdn-mount-test"
#define HDN_PROC_GID_MOUNT "/hdn-proc-gid"
#define HDN_TRACEFS_KPROBE_EVENTS "/sys/kernel/tracing/kprobe_events"
#define HDN_TRACEFS_AVAILABLE_FILTER_FUNCTIONS \
	"/sys/kernel/tracing/available_filter_functions"
#define HDN_FSIZE_PRESSURE_FILE "/hdn-fsize-pressure"
#define HDN_CORE_PATTERN "/proc/sys/kernel/core_pattern"
#define HDN_SUID_DUMPABLE "/proc/sys/fs/suid_dumpable"
#define HDN_PRIVDESC_EXEC "/hdn-privdesc-exec"
#define HDN_PRIVDESC_CORE_DIR "/hdn-privdesc-core"
#define HDN_PRIVDESC_CORE_FILE HDN_PRIVDESC_CORE_DIR "/core"
#define HDN_FLOCK_PRESSURE_FILE "/hdn-flock-pressure"
#define HDN_POSIX_LOCK_PRESSURE_FILE "/hdn-posix-lock-pressure"
#define HDN_UNTRUSTED_EXEC "/hdn-untrusted-exec"
#define HDN_SETUID_EXEC "/hdn-setuid-exec"
#define HDN_FILECAP_EXEC "/hdn-filecap-exec"
#define HDN_PRIVEXEC_ARG_ENV_LIMIT (512UL * 1024UL)
#define HDN_PRIVEXEC_STACK_LIMIT (8UL * 1024UL * 1024UL)
#define HDN_IDENTITY_TRUSTED_EXEC "/hdn-identity-trusted"
#define HDN_IDENTITY_COPY_EXEC "/hdn-identity-copy"
#define HDN_IDENTITY_BACKUP_EXEC "/hdn-identity-trusted.old"
#define HDN_IDENTITY_SCRIPT "/hdn-identity-script"
#define HDN_IDENTITY_INHERIT_EXEC "/hdn-identity-inherit"
#define HDN_IDENTITY_PARENT_INHERIT_EXEC "/hdn-identity-parent-inherit"
#define HDN_SUBJECT_UMASK_ROOT "/hdn-subject-umask"
#define HDN_SUBJECT_UMASK_FILE HDN_SUBJECT_UMASK_ROOT "/file"
#define HDN_SUBJECT_UMASK_DIR HDN_SUBJECT_UMASK_ROOT "/dir"
#define HDN_OBJECT_WRITE_PROTECTED "/hdn-object-write-protected"
#define HDN_OBJECT_WRITE_UNPROTECTED "/hdn-object-write-unprotected"
#define HDN_OBJECT_WRITE_UNMATCHED_TRUNCATE \
	"/hdn-object-write-unmatched-truncate"
#define HDN_OBJECT_WRITE_UNMATCHED_FTRUNCATE \
	"/hdn-object-write-unmatched-ftruncate"
#define HDN_OBJECT_WRITE_FIFO_PROTECTED "/hdn-object-write-fifo-protected"
#define HDN_OBJECT_WRITE_FIFO_UNPROTECTED "/hdn-object-write-fifo-unprotected"
#define HDN_OBJECT_WRITE_CHRDEV_PROTECTED "/hdn-object-write-chrdev-protected"
#define HDN_OBJECT_WRITE_CHRDEV_UNPROTECTED \
	"/hdn-object-write-chrdev-unprotected"
#define HDN_OBJECT_WRITE_BLKDEV_PROTECTED "/hdn-object-write-blkdev-protected"
#define HDN_OBJECT_WRITE_BLKDEV_UNPROTECTED \
	"/hdn-object-write-blkdev-unprotected"
#define HDN_OBJECT_READ_PROTECTED "/hdn-object-read-protected"
#define HDN_OBJECT_READ_UNPROTECTED "/hdn-object-read-unprotected"
#define HDN_OBJECT_READ_FIFO_PROTECTED "/hdn-object-read-fifo-protected"
#define HDN_OBJECT_READ_FIFO_UNPROTECTED "/hdn-object-read-fifo-unprotected"
#define HDN_OBJECT_READ_CHRDEV_PROTECTED "/hdn-object-read-chrdev-protected"
#define HDN_OBJECT_READ_CHRDEV_UNPROTECTED \
	"/hdn-object-read-chrdev-unprotected"
#define HDN_OBJECT_READ_BLKDEV_PROTECTED "/hdn-object-read-blkdev-protected"
#define HDN_OBJECT_READ_BLKDEV_UNPROTECTED \
	"/hdn-object-read-blkdev-unprotected"
#define HDN_OBJECT_BLKDEV_SETUP "/hdn-object-blkdev-setup"
#define HDN_OBJECT_BLKDEV_BACKING "/hdn-object-blkdev-backing"
#define HDN_OBJECT_READLINK_PROTECTED "/hdn-object-readlink-protected"
#define HDN_OBJECT_READLINK_UNPROTECTED "/hdn-object-readlink-unprotected"
#define HDN_OBJECT_DELETE_PROTECTED "/hdn-object-delete-protected"
#define HDN_OBJECT_DELETE_UNPROTECTED "/hdn-object-delete-unprotected"
#define HDN_OBJECT_DELETE_RENAME_TARGET "/hdn-object-delete-protected.renamed"
#define HDN_OBJECT_DELETE_REPLACE_SOURCE "/hdn-object-delete-replace-source"
#define HDN_OBJECT_DELETE_PROTECTED_DIR "/hdn-object-delete-protected-dir"
#define HDN_OBJECT_DELETE_PROTECTED_DIR_TARGET \
	"/hdn-object-delete-protected-dir.renamed"
#define HDN_OBJECT_DELETE_UNPROTECTED_DIR \
	"/hdn-object-delete-unprotected-dir"
#define HDN_OBJECT_CREATE_PROTECTED_DIR "/hdn-object-create-protected"
#define HDN_OBJECT_CREATE_UNPROTECTED_DIR "/hdn-object-create-unprotected"
#define HDN_OBJECT_CREATE_PROTECTED_FILE \
	HDN_OBJECT_CREATE_PROTECTED_DIR "/new-file"
#define HDN_OBJECT_CREATE_PROTECTED_DIR_CHILD \
	HDN_OBJECT_CREATE_PROTECTED_DIR "/new-dir"
#define HDN_OBJECT_CREATE_PROTECTED_SYMLINK \
	HDN_OBJECT_CREATE_PROTECTED_DIR "/new-symlink"
#define HDN_OBJECT_CREATE_PROTECTED_FIFO \
	HDN_OBJECT_CREATE_PROTECTED_DIR "/new-fifo"
#define HDN_OBJECT_CREATE_PROTECTED_CHRDEV \
	HDN_OBJECT_CREATE_PROTECTED_DIR "/new-chrdev"
#define HDN_OBJECT_CREATE_PROTECTED_BLKDEV \
	HDN_OBJECT_CREATE_PROTECTED_DIR "/new-blkdev"
#define HDN_OBJECT_CREATE_PROTECTED_LINK \
	HDN_OBJECT_CREATE_PROTECTED_DIR "/new-link"
#define HDN_OBJECT_CREATE_PROTECTED_RENAME \
	HDN_OBJECT_CREATE_PROTECTED_DIR "/renamed-in"
#define HDN_OBJECT_CREATE_UNPROTECTED_FILE \
	HDN_OBJECT_CREATE_UNPROTECTED_DIR "/new-file"
#define HDN_OBJECT_CREATE_UNPROTECTED_FIFO \
	HDN_OBJECT_CREATE_UNPROTECTED_DIR "/new-fifo"
#define HDN_OBJECT_CREATE_UNPROTECTED_CHRDEV \
	HDN_OBJECT_CREATE_UNPROTECTED_DIR "/new-chrdev"
#define HDN_OBJECT_CREATE_UNPROTECTED_BLKDEV \
	HDN_OBJECT_CREATE_UNPROTECTED_DIR "/new-blkdev"
#define HDN_OBJECT_CREATE_UNPROTECTED_LINK_SOURCE \
	HDN_OBJECT_CREATE_UNPROTECTED_DIR "/link-source"
#define HDN_OBJECT_CREATE_UNPROTECTED_RENAME_SOURCE \
	HDN_OBJECT_CREATE_UNPROTECTED_DIR "/rename-source"
#define HDN_OBJECT_CREAT_PROTECTED_DIR "/hdn-object-creat-protected"
#define HDN_OBJECT_CREAT_PROTECTED_FILE \
	HDN_OBJECT_CREAT_PROTECTED_DIR "/new-file"
#define HDN_OBJECT_MKDIR_PROTECTED_DIR "/hdn-object-mkdir-protected"
#define HDN_OBJECT_MKDIR_PROTECTED_CHILD \
	HDN_OBJECT_MKDIR_PROTECTED_DIR "/new-dir"
#define HDN_OBJECT_MKNOD_PROTECTED_DIR "/hdn-object-mknod-protected"
#define HDN_OBJECT_MKNOD_PROTECTED_FIFO \
	HDN_OBJECT_MKNOD_PROTECTED_DIR "/new-fifo"
#define HDN_OBJECT_SYMLINK_PROTECTED_DIR "/hdn-object-symlink-protected"
#define HDN_OBJECT_SYMLINK_PROTECTED_LINK \
	HDN_OBJECT_SYMLINK_PROTECTED_DIR "/new-symlink"
#define HDN_OBJECT_UNLINK_PROTECTED "/hdn-object-unlink-protected"
#define HDN_OBJECT_RMDIR_PROTECTED_DIR "/hdn-object-rmdir-protected"
#define HDN_OBJECT_SPLIT_CREATE_UNPROTECTED_DIR \
	"/hdn-object-split-create-unprotected"
#define HDN_OBJECT_SPLIT_CREAT_UNPROTECTED_FILE \
	HDN_OBJECT_SPLIT_CREATE_UNPROTECTED_DIR "/new-file"
#define HDN_OBJECT_SPLIT_MKDIR_UNPROTECTED_CHILD \
	HDN_OBJECT_SPLIT_CREATE_UNPROTECTED_DIR "/new-dir"
#define HDN_OBJECT_SPLIT_MKNOD_UNPROTECTED_FIFO \
	HDN_OBJECT_SPLIT_CREATE_UNPROTECTED_DIR "/new-fifo"
#define HDN_OBJECT_SPLIT_SYMLINK_UNPROTECTED_LINK \
	HDN_OBJECT_SPLIT_CREATE_UNPROTECTED_DIR "/new-symlink"
#define HDN_OBJECT_SPLIT_UNLINK_UNPROTECTED \
	"/hdn-object-split-unlink-unprotected"
#define HDN_OBJECT_SPLIT_RMDIR_UNPROTECTED_DIR \
	"/hdn-object-split-rmdir-unprotected"
#define HDN_OBJECT_EXEC_PROTECTED "/hdn-object-exec-protected"
#define HDN_OBJECT_EXEC_UNPROTECTED "/hdn-object-exec-unprotected"
#define HDN_OBJECT_APPEND_PROTECTED "/hdn-object-append-protected"
#define HDN_OBJECT_LINK_PROTECTED "/hdn-object-link-protected"
#define HDN_OBJECT_LINK_UNPROTECTED "/hdn-object-link-unprotected"
#define HDN_OBJECT_ATTR_PROTECTED "/hdn-object-attr-protected"
#define HDN_OBJECT_ATTR_UNPROTECTED "/hdn-object-attr-unprotected"
#define HDN_OBJECT_FILEATTR_DIR "/hdn-object-fileattr-tmpfs"
#define HDN_OBJECT_FILEATTR_PROTECTED HDN_OBJECT_FILEATTR_DIR "/protected"
#define HDN_OBJECT_FILEATTR_UNPROTECTED HDN_OBJECT_FILEATTR_DIR "/unprotected"
#define HDN_OBJECT_FILEGETATTR_PROTECTED \
	HDN_OBJECT_FILEATTR_DIR "/stat-protected"
#define HDN_OBJECT_FILEGETATTR_UNPROTECTED \
	HDN_OBJECT_FILEATTR_DIR "/stat-unprotected"
#define HDN_OBJECT_CHMOD_PROTECTED "/hdn-object-chmod-protected"
#define HDN_OBJECT_SETID_PROTECTED "/hdn-object-setid-protected"
#define HDN_OBJECT_SETID_UNPROTECTED "/hdn-object-setid-unprotected"
#define HDN_OBJECT_SETID_CREATE_PROTECTED_DIR \
	"/hdn-object-setid-create-protected"
#define HDN_OBJECT_SETID_CREATE_PROTECTED_PATH \
	HDN_OBJECT_SETID_CREATE_PROTECTED_DIR "/setuid-file"
#define HDN_OBJECT_SETID_CREATE_ORDINARY_PATH \
	HDN_OBJECT_SETID_CREATE_PROTECTED_DIR "/ordinary-file"
#define HDN_OBJECT_SETID_MKNOD_PROTECTED_FIFO \
	HDN_OBJECT_SETID_CREATE_PROTECTED_DIR "/setgid-fifo"
#define HDN_OBJECT_SETID_MKNOD_ORDINARY_FIFO \
	HDN_OBJECT_SETID_CREATE_PROTECTED_DIR "/ordinary-fifo"
#define HDN_OBJECT_SETID_CREATE_UNPROTECTED_DIR \
	"/hdn-object-setid-create-unprotected"
#define HDN_OBJECT_SETID_CREATE_UNPROTECTED_PATH \
	HDN_OBJECT_SETID_CREATE_UNPROTECTED_DIR "/setuid-file"
#define HDN_OBJECT_PTRACE_TARGET_EXEC "/hdn-ptrace-object-target"
#define HDN_OBJECT_CHOWN_PROTECTED "/hdn-object-chown-protected"
#define HDN_OBJECT_UTIME_PROTECTED "/hdn-object-utime-protected"
#define HDN_OBJECT_SETXATTR_PROTECTED "/hdn-object-setxattr-protected"
#define HDN_OBJECT_REMOVEXATTR_PROTECTED \
	"/hdn-object-removexattr-protected"
#define HDN_OBJECT_SPLIT_ATTR_UNPROTECTED \
	"/hdn-object-split-attr-unprotected"
#define HDN_OBJECT_ACCESS_PROTECTED "/hdn-object-access-protected"
#define HDN_OBJECT_ACCESS_UNPROTECTED "/hdn-object-access-unprotected"
#define HDN_OBJECT_STAT_PROTECTED "/hdn-object-stat-protected"
#define HDN_OBJECT_STAT_UNPROTECTED "/hdn-object-stat-unprotected"
#define HDN_OBJECT_LIST_PROTECTED_DIR "/hdn-object-list-protected"
#define HDN_OBJECT_LIST_UNPROTECTED_DIR "/hdn-object-list-unprotected"
#define HDN_OBJECT_FIND_PROTECTED "/hdn-object-find-protected"
#define HDN_OBJECT_FIND_UNPROTECTED "/hdn-object-find-unprotected"
#define HDN_OBJECT_IOCTL_PROTECTED "/hdn-object-ioctl-protected"
#define HDN_OBJECT_IOCTL_UNPROTECTED "/hdn-object-ioctl-unprotected"
#define HDN_OBJECT_LOCK_PROTECTED "/hdn-object-lock-protected"
#define HDN_OBJECT_LOCK_UNPROTECTED "/hdn-object-lock-unprotected"
#define HDN_OBJECT_WATCH_PROTECTED "/hdn-object-watch-protected"
#define HDN_OBJECT_WATCH_UNPROTECTED "/hdn-object-watch-unprotected"
#define HDN_OBJECT_WATCH_DIR_PROTECTED "/hdn-object-watch-dir-protected"
#define HDN_OBJECT_WATCH_DIR_UNPROTECTED "/hdn-object-watch-dir-unprotected"
#define HDN_OBJECT_XATTR_PROTECTED "/hdn-object-xattr-protected"
#define HDN_OBJECT_XATTR_UNPROTECTED "/hdn-object-xattr-unprotected"
#define HDN_OBJECT_RECEIVE_PROTECTED "/hdn-object-receive-protected"
#define HDN_OBJECT_RECEIVE_UNPROTECTED "/hdn-object-receive-unprotected"
#define HDN_OBJECT_FCNTL_PROTECTED "/hdn-object-fcntl-protected"
#define HDN_OBJECT_FCNTL_UNPROTECTED "/hdn-object-fcntl-unprotected"
#define HDN_OBJECT_CHDIR_PROTECTED_DIR "/hdn-object-chdir-protected"
#define HDN_OBJECT_CHDIR_UNPROTECTED_DIR "/hdn-object-chdir-unprotected"
#define HDN_OBJECT_MOUNT_PROTECTED_DIR "/hdn-object-mount-protected"
#define HDN_OBJECT_MOUNT_UNPROTECTED_DIR "/hdn-object-mount-unprotected"
#define HDN_OBJECT_UMOUNT_PROTECTED_DIR "/hdn-object-umount-protected"
#define HDN_OBJECT_UMOUNT_UNPROTECTED_DIR "/hdn-object-umount-unprotected"
#define HDN_OBJECT_TRUNCATE_PROTECTED "/hdn-object-truncate-protected"
#define HDN_OBJECT_TRUNCATE_UNPROTECTED "/hdn-object-truncate-unprotected"
#define HDN_OBJECT_RENAME_PROTECTED "/hdn-object-rename-protected"
#define HDN_OBJECT_RENAME_TARGET "/hdn-object-rename-protected.renamed"
#define HDN_OBJECT_RENAME_UNPROTECTED "/hdn-object-rename-unprotected"
#define HDN_OBJECT_RENAME_UNPROTECTED_TARGET \
	"/hdn-object-rename-unprotected.renamed"
#define HDN_OBJECT_RENAME_TARGET_PROTECTED_DIR \
	"/hdn-object-rename-target-protected"
#define HDN_OBJECT_RENAME_TARGET_SOURCE \
	HDN_OBJECT_CREATE_UNPROTECTED_DIR "/rename-target-source"
#define HDN_OBJECT_RENAME_TARGET_PROTECTED_PATH \
	HDN_OBJECT_RENAME_TARGET_PROTECTED_DIR "/renamed-in"
#define HDN_OBJECT_RENAME_TARGET_CREATE_PATH \
	HDN_OBJECT_RENAME_TARGET_PROTECTED_DIR "/ordinary-create"
#define HDN_OBJECT_UNIX_CONNECT_PROTECTED \
	"/hdn-object-unix-connect-protected"
#define HDN_OBJECT_UNIX_CONNECT_UNPROTECTED \
	"/hdn-object-unix-connect-unprotected"
#define HDN_OBJECT_UNIX_BIND_PROTECTED_DIR \
	"/hdn-object-unix-bind-protected"
#define HDN_OBJECT_UNIX_BIND_PROTECTED \
	HDN_OBJECT_UNIX_BIND_PROTECTED_DIR "/sock"
#define HDN_OBJECT_UNIX_BIND_UNPROTECTED_DIR \
	"/hdn-object-unix-bind-unprotected"
#define HDN_OBJECT_UNIX_BIND_UNPROTECTED \
	HDN_OBJECT_UNIX_BIND_UNPROTECTED_DIR "/sock"
#define HDN_OBJECT_UNIX_LISTEN_PROTECTED \
	"/hdn-object-unix-listen-protected"
#define HDN_OBJECT_UNIX_LISTEN_UNPROTECTED \
	"/hdn-object-unix-listen-unprotected"
#define HDN_OBJECT_UNIX_ACCEPT_PROTECTED \
	"/hdn-object-unix-accept-protected"
#define HDN_OBJECT_UNIX_ACCEPT_UNPROTECTED \
	"/hdn-object-unix-accept-unprotected"
#define HDN_OBJECT_UNIX_SEND_PROTECTED \
	"/hdn-object-unix-send-protected"
#define HDN_OBJECT_UNIX_SEND_UNPROTECTED \
	"/hdn-object-unix-send-unprotected"
#define HDN_OBJECT_UNIX_RECV_PROTECTED \
	"/hdn-object-unix-recv-protected"
#define HDN_OBJECT_UNIX_RECV_UNPROTECTED \
	"/hdn-object-unix-recv-unprotected"
#define HDN_OBJECT_UNIX_ABSTRACT_CONNECT_PROTECTED \
	"hdn-object-abstract-connect-protected"
#define HDN_OBJECT_UNIX_ABSTRACT_CONNECT_UNPROTECTED \
	"hdn-object-abstract-connect-unprotected"
#define HDN_OBJECT_UNIX_ABSTRACT_BIND_PROTECTED \
	"hdn-object-abstract-bind-protected"
#define HDN_OBJECT_UNIX_ABSTRACT_BIND_UNPROTECTED \
	"hdn-object-abstract-bind-unprotected"
#define HDN_OBJECT_UNIX_ABSTRACT_LISTEN_PROTECTED \
	"hdn-object-abstract-listen-protected"
#define HDN_OBJECT_UNIX_ABSTRACT_LISTEN_UNPROTECTED \
	"hdn-object-abstract-listen-unprotected"
#define HDN_OBJECT_UNIX_ABSTRACT_ACCEPT_PROTECTED \
	"hdn-object-abstract-accept-protected"
#define HDN_OBJECT_UNIX_ABSTRACT_ACCEPT_UNPROTECTED \
	"hdn-object-abstract-accept-unprotected"
#define HDN_OBJECT_UNIX_ABSTRACT_SEND_PROTECTED \
	"hdn-object-abstract-send-protected"
#define HDN_OBJECT_UNIX_ABSTRACT_SEND_UNPROTECTED \
	"hdn-object-abstract-send-unprotected"
#define HDN_OBJECT_UNIX_ABSTRACT_RECV_PROTECTED \
	"hdn-object-abstract-recv-protected"
#define HDN_OBJECT_UNIX_ABSTRACT_RECV_UNPROTECTED \
	"hdn-object-abstract-recv-unprotected"
#define HDN_OBJECT_MOVE_MOUNT_SOURCE_DENIED \
	"/hdn-object-move-mount-source-denied"
#define HDN_OBJECT_MOVE_MOUNT_SOURCE_ALLOWED \
	"/hdn-object-move-mount-source-allowed"
#define HDN_OBJECT_MOUNT_SOURCE_PROTECTED \
	"/hdn-object-mount-source-protected"
#define HDN_OBJECT_MOUNT_SOURCE_UNPROTECTED \
	"/hdn-object-mount-source-unprotected"
#define HDN_OBJECT_MOVE_MOUNT_SOURCE_TARGET_DENIED \
	"/hdn-object-move-mount-source-target-denied"
#define HDN_OBJECT_MOVE_MOUNT_SOURCE_TARGET_ALLOWED \
	"/hdn-object-move-mount-source-target-allowed"
#define HDN_OBJECT_FIND_DIR "/hdn-object-find-dir"
#define HDN_OBJECT_FIND_DIR_HIDDEN HDN_OBJECT_FIND_DIR "/hidden"
#define HDN_OBJECT_FIND_TREE_DIR "/hdn-object-find-tree"
#define HDN_OBJECT_LINK_PROTECTED_TARGET \
	HDN_OBJECT_CREATE_UNPROTECTED_DIR "/link-source-denied"
#define HDN_OBJECT_LINK_UNPROTECTED_TARGET \
	HDN_OBJECT_CREATE_UNPROTECTED_DIR "/link-source-allowed"
#define HDN_OBJECT_LINK_TARGET_PROTECTED_DIR \
	"/hdn-object-link-target-protected"
#define HDN_OBJECT_LINK_TARGET_PROTECTED_PATH \
	HDN_OBJECT_LINK_TARGET_PROTECTED_DIR "/linked-in"
#define HDN_OBJECT_LINK_TARGET_CREATE_PATH \
	HDN_OBJECT_LINK_TARGET_PROTECTED_DIR "/ordinary-create"
#define HDN_OBJECT_TREE_PROTECTED_DIR "/hdn-object-tree-protected"
#define HDN_OBJECT_TREE_UNPROTECTED_DIR "/hdn-object-tree-unprotected"
#define HDN_OBJECT_TREE_PROTECTED_READ \
	HDN_OBJECT_TREE_PROTECTED_DIR "/nested/read-target"
#define HDN_OBJECT_TREE_PROTECTED_WRITE \
	HDN_OBJECT_TREE_PROTECTED_DIR "/nested/write-target"
#define HDN_OBJECT_TREE_PROTECTED_DELETE \
	HDN_OBJECT_TREE_PROTECTED_DIR "/nested/delete-target"
#define HDN_OBJECT_TREE_PROTECTED_DELETE_DIR \
	HDN_OBJECT_TREE_PROTECTED_DIR "/nested/delete-dir"
#define HDN_OBJECT_TREE_PROTECTED_CREATE \
	HDN_OBJECT_TREE_PROTECTED_DIR "/nested/new-file"
#define HDN_OBJECT_TREE_PROTECTED_ATTR \
	HDN_OBJECT_TREE_PROTECTED_DIR "/nested/attr-target"
#define HDN_OBJECT_TREE_PROTECTED_LIST \
	HDN_OBJECT_TREE_PROTECTED_DIR "/nested/list-target"
#define HDN_OBJECT_TREE_PROTECTED_FIND \
	HDN_OBJECT_TREE_PROTECTED_DIR "/nested/find-target"
#define HDN_OBJECT_TREE_OPS_DIR "/hdn-object-tree-ops"
#define HDN_OBJECT_TREE_OPS_NESTED HDN_OBJECT_TREE_OPS_DIR "/nested"
#define HDN_OBJECT_TREE_OPS_EXEC \
	HDN_OBJECT_TREE_OPS_NESTED "/exec-target"
#define HDN_OBJECT_TREE_OPS_LINK_SOURCE \
	HDN_OBJECT_TREE_OPS_NESTED "/link-source"
#define HDN_OBJECT_TREE_OPS_LINK_TARGET \
	HDN_OBJECT_CREATE_UNPROTECTED_DIR "/tree-link-source-denied"
#define HDN_OBJECT_TREE_OPS_LINK_TARGET_PATH \
	HDN_OBJECT_TREE_OPS_NESTED "/link-target-in"
#define HDN_OBJECT_TREE_OPS_LINK_TARGET_CREATE \
	HDN_OBJECT_TREE_OPS_NESTED "/link-target-create"
#define HDN_OBJECT_TREE_OPS_IOCTL \
	HDN_OBJECT_TREE_OPS_NESTED "/ioctl-target"
#define HDN_OBJECT_TREE_OPS_LOCK \
	HDN_OBJECT_TREE_OPS_NESTED "/lock-target"
#define HDN_OBJECT_TREE_OPS_WATCH \
	HDN_OBJECT_TREE_OPS_NESTED "/watch-target"
#define HDN_OBJECT_TREE_OPS_FCNTL \
	HDN_OBJECT_TREE_OPS_NESTED "/fcntl-target"
#define HDN_OBJECT_TREE_OPS_CHDIR \
	HDN_OBJECT_TREE_OPS_NESTED "/chdir-target"
#define HDN_OBJECT_TREE_OPS_TRUNCATE \
	HDN_OBJECT_TREE_OPS_NESTED "/truncate-target"
#define HDN_OBJECT_TREE_OPS_RENAME \
	HDN_OBJECT_TREE_OPS_NESTED "/rename-target"
#define HDN_OBJECT_TREE_OPS_RENAME_TARGET \
	HDN_OBJECT_CREATE_UNPROTECTED_DIR "/tree-rename-source-denied"
#define HDN_OBJECT_TREE_OPS_RENAME_TARGET_SOURCE \
	HDN_OBJECT_CREATE_UNPROTECTED_DIR "/tree-rename-target-source-denied"
#define HDN_OBJECT_TREE_OPS_RENAME_TARGET_PATH \
	HDN_OBJECT_TREE_OPS_NESTED "/rename-target-in"
#define HDN_OBJECT_TREE_OPS_RENAME_TARGET_CREATE \
	HDN_OBJECT_TREE_OPS_NESTED "/rename-target-create"
#define HDN_OBJECT_TREE_OPS_UNIX_CONNECT \
	HDN_OBJECT_TREE_OPS_NESTED "/unix-connect-sock"
#define HDN_OBJECT_TREE_OPS_EXEC_UNMATCHED \
	HDN_OBJECT_TREE_UNPROTECTED_DIR "/nested/exec-target"
#define HDN_OBJECT_TREE_OPS_LINK_SOURCE_UNMATCHED \
	HDN_OBJECT_TREE_UNPROTECTED_DIR "/nested/link-source"
#define HDN_OBJECT_TREE_OPS_LINK_TARGET_UNMATCHED \
	HDN_OBJECT_CREATE_UNPROTECTED_DIR "/tree-link-source-unmatched"
#define HDN_OBJECT_TREE_OPS_LINK_TARGET_UNMATCHED_PATH \
	HDN_OBJECT_TREE_UNPROTECTED_DIR "/nested/link-target-in"
#define HDN_OBJECT_TREE_OPS_IOCTL_UNMATCHED \
	HDN_OBJECT_TREE_UNPROTECTED_DIR "/nested/ioctl-target"
#define HDN_OBJECT_TREE_OPS_LOCK_UNMATCHED \
	HDN_OBJECT_TREE_UNPROTECTED_DIR "/nested/lock-target"
#define HDN_OBJECT_TREE_OPS_WATCH_UNMATCHED \
	HDN_OBJECT_TREE_UNPROTECTED_DIR "/nested/watch-target"
#define HDN_OBJECT_TREE_OPS_FCNTL_UNMATCHED \
	HDN_OBJECT_TREE_UNPROTECTED_DIR "/nested/fcntl-target"
#define HDN_OBJECT_TREE_OPS_CHDIR_UNMATCHED \
	HDN_OBJECT_TREE_UNPROTECTED_DIR "/nested/chdir-target"
#define HDN_OBJECT_TREE_OPS_TRUNCATE_UNMATCHED \
	HDN_OBJECT_TREE_UNPROTECTED_DIR "/nested/truncate-target"
#define HDN_OBJECT_TREE_OPS_RENAME_UNMATCHED \
	HDN_OBJECT_TREE_UNPROTECTED_DIR "/nested/rename-target"
#define HDN_OBJECT_TREE_OPS_RENAME_TARGET_UNMATCHED \
	HDN_OBJECT_CREATE_UNPROTECTED_DIR "/tree-rename-source-unmatched"
#define HDN_OBJECT_TREE_OPS_RENAME_TARGET_UNMATCHED_SOURCE \
	HDN_OBJECT_CREATE_UNPROTECTED_DIR "/tree-rename-target-source-unmatched"
#define HDN_OBJECT_TREE_OPS_RENAME_TARGET_UNMATCHED_PATH \
	HDN_OBJECT_TREE_UNPROTECTED_DIR "/nested/rename-target-in"
#define HDN_OBJECT_TREE_OPS_UNIX_CONNECT_UNMATCHED \
	HDN_OBJECT_TREE_UNPROTECTED_DIR "/nested/unix-connect-sock"
#define HDN_OBJECT_TREE_RECEIVE \
	"/hdn-object-tree-receive/nested/receive-target"
#define HDN_OBJECT_TREE_RECEIVE_UNMATCHED \
	HDN_OBJECT_TREE_UNPROTECTED_DIR "/nested/receive-target"
#define HDN_OBJECT_TREE_MOUNT_TARGET \
	"/hdn-object-tree-mount/nested/mount-target"
#define HDN_OBJECT_TREE_MOVE_MOUNT_TARGET \
	"/hdn-object-tree-mount/nested/move-target"
#define HDN_OBJECT_TREE_MOVE_MOUNT_SOURCE \
	"/hdn-object-tree-move-mount-source"
#define HDN_OBJECT_TREE_MOUNT_UNMATCHED \
	HDN_OBJECT_TREE_UNPROTECTED_DIR "/nested/mount-target"
#define HDN_OBJECT_TREE_MOVE_MOUNT_UNMATCHED \
	HDN_OBJECT_TREE_UNPROTECTED_DIR "/nested/move-target"
#define HDN_OBJECT_TREE_MOVE_MOUNT_SOURCE_UNMATCHED \
	"/hdn-object-tree-move-mount-source-unmatched"
#define HDN_OBJECT_TREE_UMOUNT_TARGET \
	"/hdn-object-tree-umount/nested/umount-target"
#define HDN_OBJECT_TREE_UMOUNT_UNMATCHED \
	HDN_OBJECT_TREE_UNPROTECTED_DIR "/nested/umount-target"
#define HDN_OBJECT_TREE_META_DIR "/hdn-object-tree-meta"
#define HDN_OBJECT_TREE_META_NESTED HDN_OBJECT_TREE_META_DIR "/nested"
#define HDN_OBJECT_TREE_META_CHMOD \
	HDN_OBJECT_TREE_META_NESTED "/chmod-target"
#define HDN_OBJECT_TREE_META_CHOWN \
	HDN_OBJECT_TREE_META_NESTED "/chown-target"
#define HDN_OBJECT_TREE_META_UTIME \
	HDN_OBJECT_TREE_META_NESTED "/utime-target"
#define HDN_OBJECT_TREE_META_SETXATTR \
	HDN_OBJECT_TREE_META_NESTED "/setxattr-target"
#define HDN_OBJECT_TREE_META_REMOVEXATTR \
	HDN_OBJECT_TREE_META_NESTED "/removexattr-target"
#define HDN_OBJECT_TREE_META_XATTR \
	HDN_OBJECT_TREE_META_NESTED "/xattr-target"
#define HDN_OBJECT_TREE_IPC_BIND \
	"/hdn-object-tree-ipc-bind/nested/bind-dir/sock"
#define HDN_OBJECT_TREE_IPC_LISTEN \
	"/hdn-object-tree-ipc-listen/nested/listen-sock"
#define HDN_OBJECT_TREE_IPC_ACCEPT \
	"/hdn-object-tree-ipc-accept/nested/accept-sock"
#define HDN_OBJECT_TREE_IPC_SEND \
	"/hdn-object-tree-ipc-send/nested/send-sock"
#define HDN_OBJECT_TREE_IPC_RECV \
	"/hdn-object-tree-ipc-recv/nested/recv-sock"
#define HDN_OBJECT_TREE_UNPROTECTED_WRITE \
	HDN_OBJECT_TREE_UNPROTECTED_DIR "/nested/write-target"
#define HDN_OBJECT_TREE_SPLIT_DIR "/hdn-object-tree-split"
#define HDN_OBJECT_TREE_SPLIT_NESTED HDN_OBJECT_TREE_SPLIT_DIR "/nested"
#define HDN_OBJECT_TREE_SPLIT_CREAT \
	HDN_OBJECT_TREE_SPLIT_NESTED "/creat-target"
#define HDN_OBJECT_TREE_SPLIT_MKDIR \
	HDN_OBJECT_TREE_SPLIT_NESTED "/mkdir-target"
#define HDN_OBJECT_TREE_SPLIT_MKNOD \
	HDN_OBJECT_TREE_SPLIT_NESTED "/mknod-target"
#define HDN_OBJECT_TREE_SPLIT_SYMLINK \
	HDN_OBJECT_TREE_SPLIT_NESTED "/symlink-target"
#define HDN_OBJECT_TREE_SPLIT_UNLINK \
	HDN_OBJECT_TREE_SPLIT_NESTED "/unlink-target"
#define HDN_OBJECT_TREE_SPLIT_RMDIR \
	HDN_OBJECT_TREE_SPLIT_NESTED "/rmdir-target"
#define HDN_OBJECT_TREE_APPEND_FILE \
	"/hdn-object-tree-append/nested/append-target"
#define HDN_ROFS_UPDATER_EXEC "/hdn-rofs-updater"
#define HDN_ROFS_APPLY_EXEC "/hdn-rofs-apply"
#define HDN_ROFS_BIND_APPLY_EXEC "/hdn-rofs-bind-apply"
#define HDN_ROFS_TRANSACTION_EXEC "/hdn-rofs-transaction"
#define HDN_ADMIN_BROKER_EXEC "/hdn-admin-broker"
#define HDN_ADMIN_BROKER_MISSING_EXEC "/hdn-admin-broker-missing"
#define HDN_ADMIN_BROKER_UNSAFE_EXEC "/hdn-admin-broker-unsafe"
#define HDN_ADMIN_BROKER_TOKEN_EXEC "/hdn-admin-broker-token"
#define HDN_APPROVAL_TOKEN_ISSUER_EXEC "/hdn-approval-token"
#define HDN_SYSTEM_TRANSACTION_EXEC "/hdn-system-transaction"
#define HDN_RECOVERY_ACTION_EXEC "/hdn-recovery-action"
#define HDN_RECOVERY_DESCRIBE_EXEC "/hdn-recovery-describe"
#define HDN_RECOVERY_SESSION_EXEC "/hdn-recovery-session"
#define HDN_RECOVERY_PORTAL_EXEC "/hdn-recovery-portal"
#define HDN_RECOVERY_PANEL_EXEC "/hdn-recovery-panel"
#define HDN_RECOVERY_UI_EXEC "/hdn-recovery-ui"
#define HDN_RECOVERY_PROMPT_EXEC "/hdn-recovery-prompt"
#define HDN_PROMPT_DISPATCH_EXEC "/hdn-prompt-dispatch"
#define HDN_PROMPT_DESCRIBE_EXEC "/hdn-prompt-describe"
#define HDN_PROMPT_SESSION_EXEC "/hdn-prompt-session"
#define HDN_PROMPT_PORTAL_EXEC "/hdn-prompt-portal"
#define HDN_DESKTOP_ACTION_EXEC "/hdn-desktop-action"
#define HDN_DESKTOP_DAEMON_EXEC "/hdn-desktop-daemon"
#define HDN_CONTROL_CENTER_EXEC "/hdn-control-center"
#define HDN_SETTINGS_PANEL_EXEC "/hdn-settings-panel"
#define HDN_SETTINGS_UI_EXEC "/hdn-settings-ui"
#define HDN_AUTH_PROMPT_EXEC "/hdn-auth-prompt"
#define HDN_IMAGE_SEAL_EXEC "/hdn-image-seal"
#define HDN_PACKAGE_HOOK_EXEC "/hdn-package-hook"
#define HDN_EVENT_DECODE_EXEC "/hdn-event-decode"
#define HDN_EVENT_DECODE_DETAILS_INPUT "/hdn-event-decode-details.events"
#define HDN_STATUS_HELPER_EXEC "/hdn-status"
#define HDN_STATUS_HELPER_FIXTURE "/hdn-status-fixture.status"
#define HDN_SUPPORT_BUNDLE_EXEC "/hdn-support-bundle"
#define HDN_SUPPORT_BUNDLE_UNSAFE_CONFIG "/hdn-support-bundle-unsafe.conf"
#define HDN_SUPPORT_BUNDLE_EVENTS "/hdn-support-bundle.events"
#define HDN_POLICY_LEARN_EXEC "/hdn-policy-learn"
#define HDN_POLICY_LEARN_EVENTS "/hdn-policy-learn-events"
#define HDN_POLICY_LEARN_OUTPUT "/hdn-policy-learn.out"
#define HDN_POLICY_MERGE_EXEC "/hdn-policy-merge"
#define HDN_POLICY_COMPILER_EXEC "/hdn-policy"
#define HDN_POLICY_MERGE_BASE "/hdn-policy-merge-base.policy"
#define HDN_POLICY_MERGE_LEARN "/hdn-policy-merge-learn.frag"
#define HDN_POLICY_MERGE_OUTPUT "/hdn-policy-merge-output.policy"
#define HDN_POLICY_MERGE_BINARY "/hdn-policy-merge-output.hdn"
#define HDN_POLICY_WORKFLOW_EXEC "/hdn-policy-workflow"
#define HDN_POLICY_WORKFLOW_UNSAFE_CONFIG \
	"/hdn-policy-workflows-unsafe.conf"
#define HDN_POLICY_WORKFLOW_NOSIGNED_CONFIG \
	"/hdn-policy-workflows-nosigned.conf"
#define HDN_POLICY_DAEMON_EXEC "/hdn-policy-daemon"
#define HDN_POLICY_DAEMON_UNSAFE_CONFIG "/hdn-policy-daemon-unsafe.conf"
#define HDN_POLICY_WORKFLOW_BASE "/hdn-policy-workflow-base.policy"
#define HDN_POLICY_WORKFLOW_EVENTS "/hdn-policy-workflow-events"
#define HDN_POLICY_WORKFLOW_LEARN "/hdn-policy-workflow-learn.frag"
#define HDN_POLICY_WORKFLOW_OUTPUT "/hdn-policy-workflow-output.policy"
#define HDN_POLICY_WORKFLOW_BINARY "/hdn-policy-workflow-output.unsigned.hdn"
#define HDN_APPROVAL_TOKEN_DIR "/hdn-approvals"
#define HDN_APPROVAL_TOKEN_OK "/hdn-approvals/ok.token"
#define HDN_APPROVAL_TOKEN_UNSAFE "/hdn-approvals/unsafe.token"
#define HDN_APPROVAL_TOKEN_WRONG "/hdn-approvals/wrong.token"
#define HDN_APPROVAL_TOKEN_EXPIRED "/hdn-approvals/expired.token"
#define HDN_APPROVAL_TOKEN_ISSUED "/hdn-approvals/issued.token"
#define HDN_APPROVAL_TOKEN_ISSUER_BAD "/hdn-approvals/bad-issuer.token"
#define HDN_PRODUCT_ROFS_DIR "/hdn-product-rofs"
#define HDN_PRODUCT_ROFS_SENTINEL "/hdn-product-rofs/sentinel"
#define HDN_PRODUCT_ROFS_CANCEL_PID "/hdn-rofs-cancel-worker.pid"
#define HDN_PRODUCT_ROFS_ORPHAN_PID "/hdn-rofs-orphan-worker.pid"
#define HDN_PRODUCT_ROFS_BROKER_DIR "/hdn-product-rofs-broker"
#define HDN_PRODUCT_ROFS_BROKER_SENTINEL \
	"/hdn-product-rofs-broker/sentinel"
#define HDN_IMAGE_SEAL_DIR "/hdn-image-seal-rofs"
#define HDN_IMAGE_SEAL_SENTINEL "/hdn-image-seal-rofs/sentinel"
#define HDN_ROFS_APPLY_LIST "/hdn-rofs-apply-list.conf"
#define HDN_ROFS_APPLY_UNSAFE_LIST "/hdn-rofs-apply-unsafe-list.conf"
#define HDN_ROFS_APPLY_DENIED_LIST "/hdn-rofs-apply-denied.conf"
#define HDN_ROFS_APPLY_OPTIONAL_LIST "/hdn-rofs-apply-optional.conf"
#define HDN_ROFS_APPLY_OPTIONAL_DIR "/hdn-rofs-apply-optional"
#define HDN_ROFS_APPLY_OPTIONAL_SENTINEL \
	"/hdn-rofs-apply-optional/sentinel"
#define HDN_ROFS_APPLY_OPTIONAL_MISSING "/hdn-rofs-optional-missing"
#define HDN_ROFS_APPLY_OPTIONAL_NONMOUNT "/hdn-rofs-optional-nonmount"
#define HDN_ROFS_APPLY_BIND_LIST "/hdn-rofs-apply-bind.conf"
#define HDN_ROFS_APPLY_BIND_DIR "/hdn-rofs-apply-bind"
#define HDN_ROFS_APPLY_BIND_SENTINEL "/hdn-rofs-apply-bind/sentinel"
#define HDN_ROFS_APPLY_BIND_ROOT_SENTINEL "/hdn-rofs-bind-root-writable"
#define HDN_SYSTEM_TRANSACTION_UNSAFE_CONFIG \
	"/hdn-system-transactions-unsafe.conf"
#define HDN_PACKAGE_HOOK_UNSAFE_CONFIG \
	"/hdn-package-hooks-unsafe.conf"
#define HDN_APT_PACKAGE_HOOK_CONFIG "/hdn-package-manager-hooks/apt.conf"
#define HDN_PACMAN_PACKAGE_HOOK_CONFIG \
	"/hdn-package-manager-hooks/pacman.hook"
#define HDN_DNF_PACKAGE_HOOK_CONFIG \
	"/hdn-package-manager-hooks/dnf.action"
#define HDN_DNF5_PACKAGE_HOOK_CONFIG \
	"/hdn-package-manager-hooks/dnf5.actions"
#define HDN_IMAGE_SEAL_SERVICE_UNIT \
	"/hdn-package-manager-hooks/hdn-image-seal.service"
#define HDN_RECOVERY_ACTION_UNSAFE_CONFIG \
	"/hdn-recovery-actions-unsafe.conf"
#define HDN_RECOVERY_DESCRIBE_UNSAFE_CONFIG \
	"/hdn-recovery-metadata-unsafe.conf"
#define HDN_RECOVERY_DESCRIBE_OUTPUT "/hdn-recovery-description.out"
#define HDN_RECOVERY_SESSION_CONFIRM_DENY_CONFIG \
	"/hdn-recovery-session-deny.conf"
#define HDN_RECOVERY_SESSION_NO_DISPLAY_CONFIG \
	"/hdn-recovery-session-nodisplay.conf"
#define HDN_RECOVERY_SESSION_UNSAFE_CONFIG \
	"/hdn-recovery-session-unsafe.conf"
#define HDN_RECOVERY_PORTAL_UNSAFE_CONFIG \
	"/hdn-recovery-portal-unsafe.conf"
#define HDN_RECOVERY_PANEL_UNSAFE_CONFIG \
	"/hdn-recovery-panel-unsafe.conf"
#define HDN_RECOVERY_UI_UNSAFE_CONFIG \
	"/hdn-recovery-ui-unsafe.conf"
#define HDN_PROMPT_DISPATCH_UNSAFE_CONFIG \
	"/hdn-prompt-actions-unsafe.conf"
#define HDN_PROMPT_DESCRIBE_UNSAFE_CONFIG \
	"/hdn-prompt-metadata-unsafe.conf"
#define HDN_PROMPT_DESCRIBE_OUTPUT "/hdn-prompt-description.out"
#define HDN_PROMPT_SESSION_AUTH_DENY_CONFIG \
	"/hdn-prompt-session-deny.conf"
#define HDN_PROMPT_SESSION_NO_DISPLAY_CONFIG \
	"/hdn-prompt-session-nodisplay.conf"
#define HDN_PROMPT_SESSION_UNSAFE_CONFIG \
	"/hdn-prompt-session-unsafe.conf"
#define HDN_PROMPT_PORTAL_UNSAFE_CONFIG \
	"/hdn-prompt-portal-unsafe.conf"
#define HDN_DESKTOP_ACTION_UNSAFE_CONFIG \
	"/hdn-desktop-actions-unsafe.conf"
#define HDN_DESKTOP_DAEMON_UNSAFE_CONFIG \
	"/hdn-desktop-daemon-unsafe.conf"
#define HDN_SETTINGS_PANEL_UNSAFE_CONFIG \
	"/hdn-settings-panel-unsafe.conf"
#define HDN_SETTINGS_UI_UNSAFE_CONFIG \
	"/hdn-settings-ui-unsafe.conf"
#define HDN_IMAGE_SEAL_UNSAFE_CONFIG \
	"/hdn-image-seals-unsafe.conf"
#define HDN_KNOWN_MODULE "/hdn-known-module"
#define HDN_KNOWN_MODULE_BACKUP "/hdn-known-module.old"
#define HDN_SYMBOL_TEST_MODULE "/hdn-symbol-test-module.ko"
#define HDN_SYMBOL_TEST_MODULE_NAME "efivarfs"
#define HDN_ALLOWED_FIRMWARE "hdn-allowed-fw.bin"
#define HDN_DENIED_FIRMWARE "hdn-denied-fw.bin"
#define HDN_TPE_PARENT_DIR "/hdn-tpe-parent"
#define HDN_TPE_MOUNT_DIR "/hdn-tpe-parent/mnt"
#define HDN_TPE_MOUNT_EXEC "/hdn-tpe-parent/mnt/hdn_smoke"
#define HDN_TPE_USER_DIR "/hdn-tpe-user"
#define HDN_TPE_USER_EXEC "/hdn-tpe-user/hdn_smoke"
#define HDN_CHROOT_TEST_DIR "/hdn-chroot-test"
#define HDN_CHROOT_INNER_DIR "/hdn-chroot-test/inner"
#define HDN_CHROOT_CHMOD_FILE "/hdn-chroot-test/inner/chmod-target"
#define HDN_CHROOT_DEVICE_NODE "/hdn-chroot-test/inner/hdn-null"
#define HDN_CHROOT_RENAME_TARGET "/hdn-chroot-rename-target"
#define HDN_CHROOT_EXEC "/hdn-chroot-test/hdn_smoke"
#define HDN_PROTECTED_SYMLINKS "/proc/sys/fs/protected_symlinks"
#define HDN_PROTECTED_HARDLINKS "/proc/sys/fs/protected_hardlinks"
#define HDN_PROTECTED_FIFOS "/proc/sys/fs/protected_fifos"
#define HDN_PROTECTED_REGULAR "/proc/sys/fs/protected_regular"
#define HDN_FS_PROTECT_DIR "/hdn-fs-protect"
#define HDN_FS_PROTECT_TARGET "/hdn-fs-protect/target"
#define HDN_FS_PROTECT_SYMLINK "/hdn-fs-protect/link"
#define HDN_FS_PROTECT_FIFO "/hdn-fs-protect/fifo"
#define HDN_FS_PROTECT_REGULAR "/hdn-fs-protect/regular"
#define HDN_FS_PROTECT_HARDLINK_SOURCE "/hdn-hardlink-source"
#define HDN_FS_PROTECT_HARDLINK_DEST "/hdn-fs-protect/hardlink"
#define HDN_SYMLINK_OWNER_DIR "/hdn-symlink-owner"
#define HDN_SYMLINK_OWNER_TARGET "/hdn-symlink-owner/target"
#define HDN_SYMLINK_OWNER_LINK "/hdn-symlink-owner/link"
#define HDN_EXEC_STACK_ELF "/hdn-exec-stack-elf"
#define HDN_TEXTREL_ELF "/hdn-textrel-elf"
#define HDN_RELRO_ELF "/hdn-relro-elf"
#define HDN_ELFNOTE_JIT_EXEC "/hdn-elfnote-jit"
#define HDN_PROC_SELF_IPADDR "/proc/self/ipaddr"
#define HDN_TUN_DEV "/dev/net/tun"
#define HDN_BLACKHOLE_TUN "hdntun0"
#define HDN_BLACKHOLE_LOCAL_ADDR 0xc6336401U
#define HDN_BLACKHOLE_REMOTE_ADDR 0xc6336402U

#ifndef TUNSETIFF
#define TUNSETIFF _IOW('T', 202, int)
#endif
#ifndef IFF_TUN
#define IFF_TUN 0x0001
#endif
#ifndef IFF_NO_PI
#define IFF_NO_PI 0x1000
#endif
#ifndef ICMP_DEST_UNREACH
#define ICMP_DEST_UNREACH 3
#endif
#ifndef ICMP_PORT_UNREACH
#define ICMP_PORT_UNREACH 3
#endif

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#ifndef SYS_getdents64
#ifdef __NR_getdents64
#define SYS_getdents64 __NR_getdents64
#endif
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#endif

#define HDN_SYSLOG_ACTION_READ_ALL 3
#define HDN_TEST_NOBODY 65534
#define HDN_PROC_TASK_GID 65533
#define HDN_LOCKOUT_TEST_UID 60000
#define HDN_BRUTE_TEST_CRASHES 3
#define HDN_BRUTE_DAEMON_DELAY_MIN_MS 25000ULL
#define HDN_RLIMIT_STACK_LOW (64UL * 1024UL)
#define HDN_RLIMIT_STACK_CONSUME (8UL * 1024UL * 1024UL)
#define HDN_RESOURCE_NOFILE_SOFT_CAP 64
#define HDN_RESOURCE_NOFILE_HARD_CAP 128
#define HDN_AUDIT_FLOOD_TEST_ATTEMPTS 64
#define HDN_POSIX_MQ_NAME "/hdn-posix-mqueue"

static char hdn_owner_only_sysfs_path[PATH_MAX];
static bool hdn_owner_only_sysfs_path_ready;
static bool hdn_symbol_test_module_loaded;
static bool hdn_trace_symbol_kprobe_installed;

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#ifndef OPEN_TREE_NAMESPACE
#define OPEN_TREE_NAMESPACE (1U << 1)
#endif

#ifndef OPEN_TREE_CLOEXEC
#define OPEN_TREE_CLOEXEC O_CLOEXEC
#endif

#ifndef TIOCL_GETFGCONSOLE
#define TIOCL_GETFGCONSOLE 12
#endif

static bool file_readable(const char *path)
{
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return false;

	close(fd);
	return true;
}

static bool errno_is_denial(int err)
{
	return err == EACCES || err == EPERM;
}

static bool errno_is_policy_rejection(int err)
{
	return errno_is_denial(err) || err == EINVAL || err == ENODATA ||
	       err == EBADMSG || err == ENOKEY || err == EKEYREJECTED ||
	       err == ENOPKG;
}

static int run_as_unprivileged(int (*fn)(void), const char *description)
{
	int status;
	pid_t child;

	if (geteuid() != 0) {
		ksft_test_result(!fn(), "%s\n", description);
		return 0;
	}

	child = fork();
	if (child < 0) {
		ksft_test_result_fail("%s fork failed: %s\n", description,
				      strerror(errno));
		return -1;
	}

	if (!child) {
		if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
			_exit(3);
		_exit(fn());
	}

	if (waitpid(child, &status, 0) < 0) {
		ksft_test_result_fail("%s waitpid failed: %s\n", description,
				      strerror(errno));
		return -1;
	}

	if (WIFEXITED(status) && WEXITSTATUS(status) == KSFT_SKIP)
		ksft_test_result_skip("%s\n", description);
	else
		ksft_test_result(WIFEXITED(status) && WEXITSTATUS(status) == 0,
				 "%s\n", description);
	return 0;
}

static int mapping_has_exec(void *addr, bool *executable)
{
	unsigned long target = (unsigned long)addr;
	unsigned long start;
	unsigned long end;
	char perms[5];
	char line[512];
	FILE *maps;

	maps = fopen("/proc/self/maps", "r");
	if (!maps)
		return -errno;

	while (fgets(line, sizeof(line), maps)) {
		if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3)
			continue;
		if (target < start || target >= end)
			continue;

		*executable = !!strchr(perms, 'x');
		fclose(maps);
		return 0;
	}

	fclose(maps);
	return -ENOENT;
}

static void test_securityfs_status(void)
{
	ksft_test_result(file_readable(HDN_STATUS),
			 "hardening status is readable\n");
}

static void test_securityfs_status_contains(const char *needle,
					    const char *description)
{
	char buf[8192] = {};
	int fd;
	ssize_t len;

	fd = open(HDN_STATUS, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		ksft_test_result_fail("hardening status open failed: %s\n",
				      strerror(errno));
		return;
	}

	len = read(fd, buf, sizeof(buf) - 1);
	close(fd);

	ksft_test_result(len > 0 && strstr(buf, needle), "%s\n",
			 description);
}

static int read_long_file(const char *path, long *value)
{
	char buf[64] = {};
	char *end;
	int fd;
	ssize_t len;
	int ret = 0;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	len = read(fd, buf, sizeof(buf) - 1);
	if (len <= 0)
		ret = -EIO;
	close(fd);
	if (ret)
		return ret;

	errno = 0;
	*value = strtol(buf, &end, 0);
	if (errno || end == buf)
		return -EINVAL;

	return 0;
}

static void test_int_file_equals(const char *path, long expected,
				 const char *description)
{
	long value;
	int ret;

	ret = read_long_file(path, &value);
	if (ret) {
		errno = -ret;
		if (errno == ENOENT)
			ksft_test_result_skip("%s\n", description);
		else
			ksft_test_result_fail("%s read failed: %s\n",
					      description, strerror(errno));
		return;
	}

	ksft_test_result(value == expected, "%s\n", description);
}

static bool securityfs_status_has_line(const char *expected)
{
	char buf[8192] = {};
	char *line;
	char *save;
	int fd;
	ssize_t len;

	fd = open(HDN_STATUS, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return false;

	len = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (len <= 0)
		return false;

	for (line = strtok_r(buf, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		if (!strcmp(line, expected))
			return true;
	}

	return false;
}

static bool securityfs_status_u64(const char *key, unsigned long long *value)
{
	char buf[8192] = {};
	size_t key_len = strlen(key);
	char *line;
	char *save;
	int fd;
	ssize_t len;

	fd = open(HDN_STATUS, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return false;

	len = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (len <= 0)
		return false;

	for (line = strtok_r(buf, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		char *end;

		if (strncmp(line, key, key_len))
			continue;
		line += key_len;
		while (*line == ' ' || *line == '\t')
			line++;
		errno = 0;
		*value = strtoull(line, &end, 0);
		return !errno && end != line;
	}

	return false;
}

static void test_securityfs_events(void)
{
	ksft_test_result(file_readable(HDN_EVENTS),
			 "hardening events are readable\n");
}

static bool securityfs_events_contains(const char *needle);
static char *securityfs_events_read_all(void);
static unsigned int securityfs_events_count(const char *needle);
static unsigned int securityfs_events_line_count(const char *needle_a,
						 const char *needle_b);
static unsigned int securityfs_resource_pressure_count(unsigned int resource);
static unsigned int product_rofs_sentinel_update_count(void);
static int child_exit_result(pid_t child);
static void report_child_result(int result, const char *description);
static int resource_nproc_pressure_child(void);
static int userns_depth_policy_enforced(void);
static int copy_file(const char *src, const char *dst, mode_t mode);
static int write_blob_file(const char *path, const unsigned char *buf,
			   size_t size);
static int write_text_file(const char *path, const char *text);
static int write_created_text_file(const char *path, const char *text);
static int exec_stack_elf_compat_allowed(void);
static int textrel_mprotect_compat_allowed(void);
static int relro_write_restore_compat_allowed(void);

struct consistent_setxid_state {
	atomic_int ready;
	atomic_int go;
	atomic_int seen_uid;
	atomic_int seen_gid;
};

static void *consistent_setxid_thread(void *arg)
{
	struct consistent_setxid_state *state = arg;
	int i;

	atomic_store(&state->ready, 1);
	while (!atomic_load(&state->go))
		sched_yield();

	for (i = 0; i < 100000; i++) {
		uid_t uid = geteuid();
		gid_t gid = getegid();

		atomic_store(&state->seen_uid, uid);
		atomic_store(&state->seen_gid, gid);
		if (uid == HDN_TEST_NOBODY && gid == HDN_TEST_NOBODY)
			return NULL;
		sched_yield();
	}

	return NULL;
}

static int consistent_setxid_child(void)
{
	struct consistent_setxid_state state;
	pthread_t thread;
	int i;

	atomic_init(&state.ready, 0);
	atomic_init(&state.go, 0);
	atomic_init(&state.seen_uid, -1);
	atomic_init(&state.seen_gid, -1);

	if (pthread_create(&thread, NULL, consistent_setxid_thread, &state))
		return 2;

	for (i = 0; i < 100000 && !atomic_load(&state.ready); i++)
		sched_yield();
	if (!atomic_load(&state.ready))
		return 2;

	if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
		return 2;
	atomic_store(&state.go, 1);

	if (pthread_join(thread, NULL))
		return 2;

	return atomic_load(&state.seen_uid) == HDN_TEST_NOBODY &&
	       atomic_load(&state.seen_gid) == HDN_TEST_NOBODY ? 0 : 1;
}

static void test_consistent_setxid(void)
{
	pid_t child;

	child = fork();
	if (child < 0) {
		ksft_test_result_fail(
			"multithreaded setuid drop test fork failed: %s\n",
			strerror(errno));
		return;
	}

	if (!child)
		_exit(consistent_setxid_child());

	report_child_result(child_exit_result(child),
			    "multithreaded setuid drop propagates to sibling thread");
}

static int signal_crash_sentinel(void)
{
	long page_size;
	void *mapping;
	volatile char value;

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0)
		return 2;

	mapping = mmap(NULL, page_size, PROT_NONE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mapping == MAP_FAILED)
		return 2;

	value = *(volatile char *)mapping;
	(void)value;
	return 2;
}

static void test_exec_event_logged(void)
{
	int status;
	pid_t child;

	child = fork();
	if (child < 0) {
		ksft_test_result_fail("exec audit child failed: %s\n",
				      strerror(errno));
		return;
	}

	if (!child) {
		execl("/proc/self/exe", "hdn_smoke", "--exec-sentinel", NULL);
		_exit(127);
	}

	if (waitpid(child, &status, 0) < 0) {
		ksft_test_result_fail("exec audit wait failed: %s\n",
				      strerror(errno));
		return;
	}

	ksft_test_result(WIFEXITED(status) && WEXITSTATUS(status) == 42 &&
			 securityfs_events_contains("authority=1 transition=1 action=3"),
			 "hardening events report exec audit\n");
}

static void test_exec_args_event_logged(void)
{
	const char *event_needle =
		"authority=1 transition=88 action=3 reason=0 error=0";
	char object_needle[64];
	char *const argv[] = {
		"hdn_smoke",
		"--exec-args-sentinel",
		"alpha",
		"beta",
		NULL,
	};
	char *const envp[] = {
		"HDN_EXEC_ARG_TEST=1",
		"HDN_EXEC_ARG_TEST2=2",
		NULL,
	};
	unsigned int before;
	unsigned long long object;
	int status;
	pid_t child;

	object = ((unsigned long long)4 << 32) | 2;
	snprintf(object_needle, sizeof(object_needle), "object=%llu", object);
	before = securityfs_events_line_count(event_needle, object_needle);

	child = fork();
	if (child < 0) {
		ksft_test_result_fail("exec args audit child failed: %s\n",
				      strerror(errno));
		return;
	}

	if (!child) {
		execve("/proc/self/exe", argv, envp);
		_exit(127);
	}

	if (waitpid(child, &status, 0) < 0) {
		ksft_test_result_fail("exec args audit wait failed: %s\n",
				      strerror(errno));
		return;
	}

	ksft_test_result(WIFEXITED(status) && WEXITSTATUS(status) == 42 &&
			 securityfs_events_line_count(event_needle,
						      object_needle) > before,
			 "hardening events report exec arg counts\n");
}

static void test_fork_event_logged(void)
{
	int status;
	pid_t child;

	child = fork();
	if (child < 0) {
		ksft_test_result_fail("fork audit child failed: %s\n",
				      strerror(errno));
		return;
	}

	if (!child)
		_exit(0);

	if (waitpid(child, &status, 0) < 0) {
		ksft_test_result_fail("fork audit wait failed: %s\n",
				      strerror(errno));
		return;
	}

	ksft_test_result(WIFEXITED(status) && !WEXITSTATUS(status) &&
			 securityfs_events_contains("transition=40"),
			 "hardening events report fork audit\n");
}

static void test_fork_failure_event_logged(void)
{
	const char *needle = "reason=42";
	unsigned int before;
	pid_t child;
	int result;

	before = securityfs_events_count(needle);

	child = fork();
	if (child < 0) {
		ksft_test_result_fail(
			"failed fork audit child failed: %s\n",
			strerror(errno));
		return;
	}
	if (!child)
		_exit(resource_nproc_pressure_child());

	result = child_exit_result(child);
	if (result == KSFT_SKIP) {
		ksft_test_result_skip(
			"hardening events report failed fork audit\n");
		return;
	}

	ksft_test_result(result == 0 && securityfs_events_count(needle) > before,
			 "hardening events report failed fork audit\n");
}

static int process_account_event_recorded(void)
{
	const char *event_needle =
		"authority=0 transition=86 action=3 reason=0 error=0";
	const char *object_needle = "object=10752";
	unsigned int before;
	pid_t child;
	int status;

	before = securityfs_events_line_count(event_needle, object_needle);
	child = fork();
	if (child < 0)
		return 2;

	if (!child)
		_exit(42);

	if (waitpid(child, &status, 0) < 0)
		return 2;
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 42)
		return 2;

	return securityfs_events_line_count(event_needle, object_needle) > before ?
	       0 : 2;
}

static void cleanup_fs_protection_audit_paths(void)
{
	unlink(HDN_FS_PROTECT_HARDLINK_DEST);
	unlink(HDN_FS_PROTECT_HARDLINK_SOURCE);
	unlink(HDN_FS_PROTECT_SYMLINK);
	unlink(HDN_FS_PROTECT_FIFO);
	unlink(HDN_FS_PROTECT_REGULAR);
	unlink(HDN_FS_PROTECT_TARGET);
	rmdir(HDN_FS_PROTECT_DIR);
	unlink(HDN_SYMLINK_OWNER_LINK);
	unlink(HDN_SYMLINK_OWNER_TARGET);
	rmdir(HDN_SYMLINK_OWNER_DIR);
}

static int setup_fs_protection_audit_paths(void)
{
	int fd;

	cleanup_fs_protection_audit_paths();

	if (mkdir(HDN_FS_PROTECT_DIR, 01777) && errno != EEXIST)
		return -errno;
	if (chmod(HDN_FS_PROTECT_DIR, 01777))
		return -errno;

	fd = open(HDN_FS_PROTECT_TARGET,
		  O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0)
		return -errno;
	close(fd);

	if (symlink(HDN_FS_PROTECT_TARGET, HDN_FS_PROTECT_SYMLINK))
		return -errno;
	if (lchown(HDN_FS_PROTECT_SYMLINK, HDN_TEST_NOBODY,
		   HDN_TEST_NOBODY))
		return -errno;

	fd = open(HDN_FS_PROTECT_HARDLINK_SOURCE,
		  O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return -errno;
	close(fd);

	if (mkfifo(HDN_FS_PROTECT_FIFO, 0600))
		return -errno;
	if (chown(HDN_FS_PROTECT_FIFO, HDN_TEST_NOBODY, HDN_TEST_NOBODY))
		return -errno;

	fd = open(HDN_FS_PROTECT_REGULAR,
		  O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return -errno;
	close(fd);
	if (chown(HDN_FS_PROTECT_REGULAR, HDN_TEST_NOBODY,
		  HDN_TEST_NOBODY))
		return -errno;

	if (mkdir(HDN_SYMLINK_OWNER_DIR, 0755) && errno != EEXIST)
		return -errno;
	if (chmod(HDN_SYMLINK_OWNER_DIR, 0755))
		return -errno;

	fd = open(HDN_SYMLINK_OWNER_TARGET,
		  O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0)
		return -errno;
	close(fd);
	if (chown(HDN_SYMLINK_OWNER_TARGET, 0, 0))
		return -errno;

	if (symlink(HDN_SYMLINK_OWNER_TARGET, HDN_SYMLINK_OWNER_LINK))
		return -errno;
	if (lchown(HDN_SYMLINK_OWNER_LINK, HDN_TEST_NOBODY,
		   HDN_TEST_NOBODY))
		return -errno;

	return 0;
}

static int protected_hardlink_child(void)
{
	int saved_errno = 0;
	int ret;

	if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
		return 2;

	errno = 0;
	ret = link(HDN_FS_PROTECT_HARDLINK_SOURCE,
		   HDN_FS_PROTECT_HARDLINK_DEST);
	if (ret)
		saved_errno = errno;

	return ret && errno_is_denial(saved_errno) ? 0 : 1;
}

static int symlink_owner_self_follow_child(void)
{
	int fd;

	if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
		return 2;

	fd = open(HDN_SYMLINK_OWNER_LINK, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 1;
	close(fd);

	return 0;
}

static bool event_count_increased(const char *needle, unsigned int before)
{
	return securityfs_events_count(needle) > before;
}

static void test_fs_protection_events_logged(void)
{
	unsigned int before;
	int saved_errno = 0;
	pid_t child;
	int result;
	int ret;
	int fd;

	if (geteuid() != 0) {
		ksft_test_result_skip(
			"hardening events report protected symlink denial\n");
		ksft_test_result_skip(
			"hardening events report protected hardlink denial\n");
		ksft_test_result_skip(
			"hardening events report protected FIFO denial\n");
		ksft_test_result_skip(
			"hardening events report protected regular-file denial\n");
		ksft_test_result_skip(
			"hardening events report symlink owner mismatch denial\n");
		ksft_test_result_skip(
			"symlink owner may follow own link to permitted target\n");
		return;
	}

	ret = setup_fs_protection_audit_paths();
	if (ret) {
		ksft_test_result_fail(
			"protected filesystem setup failed: %s\n",
			strerror(-ret));
		ksft_test_result_skip(
			"hardening events report protected hardlink denial\n");
		ksft_test_result_skip(
			"hardening events report protected FIFO denial\n");
		ksft_test_result_skip(
			"hardening events report protected regular-file denial\n");
		ksft_test_result_skip(
			"hardening events report symlink owner mismatch denial\n");
		ksft_test_result_skip(
			"symlink owner may follow own link to permitted target\n");
		cleanup_fs_protection_audit_paths();
		return;
	}

	before = securityfs_events_count("reason=43");
	errno = 0;
	fd = open(HDN_FS_PROTECT_SYMLINK, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		saved_errno = errno;
	else
		close(fd);
	ksft_test_result(fd < 0 && errno_is_denial(saved_errno) &&
			 event_count_increased("reason=43", before),
			 "hardening events report protected symlink denial\n");

	before = securityfs_events_count("reason=48");
	errno = 0;
	fd = open(HDN_SYMLINK_OWNER_LINK, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		saved_errno = errno;
	else
		close(fd);
	ksft_test_result(fd < 0 && errno_is_denial(saved_errno) &&
			 event_count_increased("reason=48", before),
			 "hardening events report symlink owner mismatch denial\n");

	child = fork();
	if (child < 0) {
		ksft_test_result_fail(
			"symlink owner self-follow child failed: %s\n",
			strerror(errno));
	} else if (!child) {
		_exit(symlink_owner_self_follow_child());
	} else {
		report_child_result(child_exit_result(child),
				    "symlink owner may follow own link to permitted target");
	}

	before = securityfs_events_count("reason=44");
	child = fork();
	if (child < 0) {
		ksft_test_result_fail(
			"protected hardlink child failed: %s\n",
			strerror(errno));
	} else if (!child) {
		_exit(protected_hardlink_child());
	} else {
		result = child_exit_result(child);
		ksft_test_result(result == 0 &&
				 event_count_increased("reason=44", before),
				 "hardening events report protected hardlink denial\n");
	}

	before = securityfs_events_count("reason=45");
	errno = 0;
	fd = open(HDN_FS_PROTECT_FIFO,
		  O_RDONLY | O_NONBLOCK | O_CREAT | O_CLOEXEC, 0600);
	if (fd < 0)
		saved_errno = errno;
	else
		close(fd);
	ksft_test_result(fd < 0 && errno_is_denial(saved_errno) &&
			 event_count_increased("reason=45", before),
			 "hardening events report protected FIFO denial\n");

	before = securityfs_events_count("reason=46");
	errno = 0;
	fd = open(HDN_FS_PROTECT_REGULAR,
		  O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
	if (fd < 0)
		saved_errno = errno;
	else
		close(fd);
	ksft_test_result(fd < 0 && errno_is_denial(saved_errno) &&
			 event_count_increased("reason=46", before),
			 "hardening events report protected regular-file denial\n");

	cleanup_fs_protection_audit_paths();
}

static void test_signal_event_logged(void)
{
	const char *needle = "transition=46";
	unsigned int before;
	int status;
	pid_t child;

	if (copy_file("/proc/self/exe", HDN_SIGNAL_CRASH_EXEC, 0755)) {
		ksft_test_result_fail("signal audit copy failed: %s\n",
				      strerror(errno));
		return;
	}

	before = securityfs_events_count(needle);
	child = fork();
	if (child < 0) {
		unlink(HDN_SIGNAL_CRASH_EXEC);
		ksft_test_result_fail("signal audit child failed: %s\n",
				      strerror(errno));
		return;
	}

	if (!child) {
		execl(HDN_SIGNAL_CRASH_EXEC, "hdn-signal-crash",
		      "--signal-crash-sentinel", NULL);
		_exit(2);
	}

	if (waitpid(child, &status, 0) < 0) {
		unlink(HDN_SIGNAL_CRASH_EXEC);
		ksft_test_result_fail("signal audit wait failed: %s\n",
				      strerror(errno));
		return;
	}
	unlink(HDN_SIGNAL_CRASH_EXEC);

	ksft_test_result(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV &&
			 securityfs_events_count(needle) > before,
			 "hardening events report severe signal audit\n");
}

static void test_chdir_event_logged(void)
{
	int ret;

	ret = chdir("/");
	ksft_test_result(!ret &&
			 securityfs_events_contains("authority=0 transition=26 action=3"),
				 "hardening events report chdir audit\n");
}

static void test_mount_event_logged(void)
{
	const char *needle = "authority=17 transition=11 action=3";
	unsigned int before;
	bool found;
	int saved_errno = 0;
	int ret;

	if (mkdir(HDN_MOUNT_TEST_DIR, 0700) && errno != EEXIST) {
		ksft_test_result_fail("mount audit mkdir failed: %s\n",
				      strerror(errno));
		return;
	}

	before = securityfs_events_count(needle);
	errno = 0;
	ret = mount("none", HDN_MOUNT_TEST_DIR, "tmpfs", 0, "size=4k");
	if (ret)
		saved_errno = errno;

	found = !ret && securityfs_events_count(needle) > before;

	if (!ret)
		umount(HDN_MOUNT_TEST_DIR);
	rmdir(HDN_MOUNT_TEST_DIR);

	if (ret) {
		ksft_test_result_fail("mount audit setup failed: %s\n",
				      strerror(saved_errno));
		return;
	}

	ksft_test_result(found, "hardening events report mount audit\n");
}

static void test_resource_limit_event_logged(void)
{
	const char *needle = "authority=33 transition=38 action=3";
	struct rlimit lower;
	struct rlimit orig;
	unsigned int before;
	bool found;

	if (getrlimit(RLIMIT_NOFILE, &orig)) {
		ksft_test_result_fail("resource audit getrlimit failed: %s\n",
				      strerror(errno));
		return;
	}

	lower = orig;
	if (lower.rlim_cur == RLIM_INFINITY || lower.rlim_cur > 64)
		lower.rlim_cur = 64;
	else if (lower.rlim_cur > 1)
		lower.rlim_cur--;
	else {
		ksft_test_result_skip(
			"hardening events report resource-limit audit\n");
		return;
	}

	before = securityfs_events_count(needle);
	if (setrlimit(RLIMIT_NOFILE, &lower)) {
		ksft_test_result_fail("resource audit setrlimit failed: %s\n",
				      strerror(errno));
		return;
	}

	found = securityfs_events_count(needle) > before;
	if (setrlimit(RLIMIT_NOFILE, &orig)) {
		ksft_test_result_fail("resource audit restore failed: %s\n",
				      strerror(errno));
		return;
	}

	ksft_test_result(found,
			 "hardening events report resource-limit audit\n");
}

static unsigned int securityfs_resource_limit_count(unsigned int resource)
{
	const char *needle = "authority=33 transition=38 action=3";
	unsigned int count = 0;
	char *object_field;
	char *cursor;
	char *line;
	char *buf;

	buf = securityfs_events_read_all();
	if (!buf)
		return 0;

	cursor = buf;
	while ((line = strsep(&cursor, "\n"))) {
		unsigned long long object;
		char *end;

		if (!strstr(line, needle))
			continue;

		object_field = strstr(line, "object=");
		if (!object_field)
			continue;

		errno = 0;
		object = strtoull(object_field + strlen("object="), &end, 10);
		if (errno || end == object_field + strlen("object="))
			continue;

		if (object == resource)
			count++;
	}

	free(buf);
	return count;
}

static void test_resource_rss_limit_event_logged(void)
{
	struct rlimit next;
	struct rlimit orig;
	unsigned int before;
	bool found;

	if (getrlimit(RLIMIT_RSS, &orig)) {
		ksft_test_result_fail("resource RSS audit getrlimit failed: %s\n",
				      strerror(errno));
		return;
	}

	next = orig;
	if (next.rlim_max == RLIM_INFINITY || next.rlim_max > 4096)
		next.rlim_cur = 4096;
	else
		next.rlim_cur = next.rlim_max;

	before = securityfs_resource_limit_count(RLIMIT_RSS);
	if (setrlimit(RLIMIT_RSS, &next)) {
		ksft_test_result_fail("resource RSS audit setrlimit failed: %s\n",
				      strerror(errno));
		return;
	}

	found = securityfs_resource_limit_count(RLIMIT_RSS) > before;
	if (setrlimit(RLIMIT_RSS, &orig)) {
		ksft_test_result_fail("resource RSS audit restore failed: %s\n",
				      strerror(errno));
		return;
	}

	ksft_test_result(found,
			 "hardening events report RSS resource-limit audit\n");
}

static unsigned long long hdn_resource_pressure_object(unsigned int resource,
						       unsigned long wanted)
{
	const unsigned long long wanted_mask = (1ULL << 56) - 1;
	unsigned long long capped = wanted;

	if (capped > wanted_mask)
		capped = wanted_mask;

	return ((unsigned long long)(resource & 0xff) << 56) | capped;
}

static void test_resource_pressure_event_logged(void)
{
	struct rlimit lower;
	struct rlimit orig;
	char needle[128];
	int fds[128];
	unsigned int before;
	size_t i = 0;
	int saved_errno = 0;
	int fd = -1;
	bool found;

	if (getrlimit(RLIMIT_NOFILE, &orig)) {
		ksft_test_result_fail(
			"resource pressure getrlimit failed: %s\n",
			strerror(errno));
		return;
	}

	lower = orig;
	if (lower.rlim_cur == RLIM_INFINITY || lower.rlim_cur > 32)
		lower.rlim_cur = 32;
	else if (lower.rlim_cur > 4)
		lower.rlim_cur--;
	else {
		ksft_test_result_skip(
			"hardening events report resource pressure\n");
		return;
	}

	snprintf(needle, sizeof(needle), "object=%llu",
		 hdn_resource_pressure_object(RLIMIT_NOFILE,
					      lower.rlim_cur));
	before = securityfs_events_count(needle);
	if (setrlimit(RLIMIT_NOFILE, &lower)) {
		ksft_test_result_fail(
			"resource pressure setrlimit failed: %s\n",
			strerror(errno));
		return;
	}

	while (i < ARRAY_SIZE(fds)) {
		fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			saved_errno = errno;
			break;
		}
		fds[i++] = fd;
	}

	while (i > 0)
		close(fds[--i]);

	if (setrlimit(RLIMIT_NOFILE, &orig)) {
		ksft_test_result_fail(
			"resource pressure restore failed: %s\n",
			strerror(errno));
		return;
	}

	found = fd < 0 && saved_errno == EMFILE &&
		securityfs_events_count(needle) > before;
	ksft_test_result(found,
			 "hardening events report resource pressure\n");
}

static void test_resource_fsize_pressure_event_logged(void)
{
	struct sigaction ignore = {};
	struct sigaction old;
	struct rlimit lower;
	struct rlimit orig;
	unsigned int before;
	char needle[128];
	char byte = 'x';
	int saved_errno = 0;
	ssize_t ret = -1;
	bool limit_set = false;
	bool reported = false;
	bool found;
	int fd = -1;

	ignore.sa_handler = SIG_IGN;
	sigemptyset(&ignore.sa_mask);
	if (sigaction(SIGXFSZ, &ignore, &old)) {
		ksft_test_result_fail(
			"resource fsize pressure signal setup failed: %s\n",
			strerror(errno));
		return;
	}

	if (getrlimit(RLIMIT_FSIZE, &orig)) {
		ksft_test_result_fail(
			"resource fsize pressure getrlimit failed: %s\n",
			strerror(errno));
		goto out_signal;
	}

	if (orig.rlim_max != RLIM_INFINITY && orig.rlim_max < 1) {
		ksft_test_result_skip(
			"hardening events report file-size resource pressure\n");
		goto out_signal;
	}

	snprintf(needle, sizeof(needle), "object=%llu",
		 hdn_resource_pressure_object(RLIMIT_FSIZE, 1));
	before = securityfs_events_count(needle);

	unlink(HDN_FSIZE_PRESSURE_FILE);
	fd = open(HDN_FSIZE_PRESSURE_FILE,
		  O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
	if (fd < 0) {
		ksft_test_result_fail(
			"resource fsize pressure open failed: %s\n",
			strerror(errno));
		goto out_file;
	}

	lower = orig;
	lower.rlim_cur = 1;
	if (setrlimit(RLIMIT_FSIZE, &lower)) {
		ksft_test_result_fail(
			"resource fsize pressure setrlimit failed: %s\n",
			strerror(errno));
		goto out_file;
	}
	limit_set = true;

	if (write(fd, &byte, sizeof(byte)) != sizeof(byte)) {
		ksft_test_result_fail(
			"resource fsize pressure first write failed: %s\n",
			strerror(errno));
		reported = true;
		goto out_limit;
	}

	ret = write(fd, &byte, sizeof(byte));
	if (ret < 0)
		saved_errno = errno;

out_limit:
	if (limit_set && setrlimit(RLIMIT_FSIZE, &orig)) {
		ksft_test_result_fail(
			"resource fsize pressure restore failed: %s\n",
			strerror(errno));
		reported = true;
		goto out_file;
	}

	if (!reported) {
		if (ret >= 0 || saved_errno != EFBIG)
			found = false;
		else
			found = securityfs_events_count(needle) > before;
		ksft_test_result(found,
				 "hardening events report file-size resource pressure\n");
	}

out_file:
	if (fd >= 0)
		close(fd);
	unlink(HDN_FSIZE_PRESSURE_FILE);
out_signal:
	sigaction(SIGXFSZ, &old, NULL);
}

static int resource_core_pressure_child(void)
{
	struct rlimit limit = {};

	signal(SIGSEGV, SIG_DFL);
	if (setrlimit(RLIMIT_CORE, &limit))
		return 2;

	raise(SIGSEGV);
	return 2;
}

static void test_resource_core_pressure_event_logged(void)
{
	char old_pattern[256];
	unsigned int before;
	unsigned int after;
	ssize_t old_len;
	bool crashed;
	pid_t child;
	int status;
	int ret;
	int fd;

	fd = open(HDN_CORE_PATTERN, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		ksft_test_result_fail("core pattern open failed: %s\n",
				      strerror(errno));
		return;
	}
	old_len = read(fd, old_pattern, sizeof(old_pattern));
	close(fd);
	if (old_len <= 0 || old_len == sizeof(old_pattern)) {
		ksft_test_result_fail("core pattern read failed\n");
		return;
	}

	ret = write_text_file(HDN_CORE_PATTERN, "core\n");
	if (ret) {
		ksft_test_result_fail("core pattern setup failed: %s\n",
				      strerror(-ret));
		return;
	}

	before = securityfs_resource_pressure_count(RLIMIT_CORE);
	child = fork();
	if (child < 0) {
		ksft_test_result_fail("core pressure fork failed: %s\n",
				      strerror(errno));
		goto out_restore;
	}
	if (!child)
		_exit(resource_core_pressure_child());

	if (waitpid(child, &status, 0) < 0) {
		ksft_test_result_fail("core pressure wait failed: %s\n",
				      strerror(errno));
		goto out_restore;
	}

	after = securityfs_resource_pressure_count(RLIMIT_CORE);
	crashed = WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV;

	ret = write_blob_file(HDN_CORE_PATTERN, (unsigned char *)old_pattern,
			      old_len);
	if (ret) {
		ksft_test_result_fail("core pattern restore failed: %s\n",
				      strerror(-ret));
		return;
	}

	ksft_test_result(crashed && after > before,
			 "hardening events report core-size resource pressure\n");
	return;

out_restore:
	write_blob_file(HDN_CORE_PATTERN, (unsigned char *)old_pattern,
			old_len);
}

static int resource_as_pressure_child(void)
{
	struct rlimit limit = {};
	void *addr;

	if (setrlimit(RLIMIT_AS, &limit))
		return 2;

	errno = 0;
	addr = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED)
		return errno == ENOMEM ? 0 : 2;

	munmap(addr, 4096);
	return 1;
}

static void test_resource_as_pressure_event_logged(void)
{
	unsigned int before;
	pid_t child;
	int result;

	before = securityfs_resource_pressure_count(RLIMIT_AS);

	child = fork();
	if (child < 0) {
		ksft_test_result_fail("as pressure fork failed: %s\n",
				      strerror(errno));
		return;
	}
	if (!child)
		_exit(resource_as_pressure_child());

	result = child_exit_result(child);
	ksft_test_result(result == 0 &&
			 securityfs_resource_pressure_count(RLIMIT_AS) >
			 before,
			 "hardening events report address-space resource pressure\n");
}

static int resource_data_pressure_child(void)
{
	struct rlimit limit = {
		.rlim_cur = 1,
		.rlim_max = 1,
	};
	void *addr;

	if (setrlimit(RLIMIT_DATA, &limit))
		return 2;

	errno = 0;
	addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED)
		return errno == ENOMEM ? 0 : 2;

	munmap(addr, 4096);
	return 1;
}

static void test_resource_data_pressure_event_logged(void)
{
	unsigned int before;
	pid_t child;
	int result;

	before = securityfs_resource_pressure_count(RLIMIT_DATA);

	child = fork();
	if (child < 0) {
		ksft_test_result_fail("data pressure fork failed: %s\n",
				      strerror(errno));
		return;
	}
	if (!child)
		_exit(resource_data_pressure_child());

	result = child_exit_result(child);
	ksft_test_result(result == 0 &&
			 securityfs_resource_pressure_count(RLIMIT_DATA) >
			 before,
			 "hardening events report data-segment resource pressure\n");
}

static volatile unsigned char hdn_stack_pressure_sink;

static __attribute__((noinline)) void consume_stack_for_rlimit(size_t left)
{
	volatile unsigned char buf[8192];

	memset((void *)buf, 0xa5, sizeof(buf));
	hdn_stack_pressure_sink ^= buf[0];
	if (left > sizeof(buf))
		consume_stack_for_rlimit(left - sizeof(buf));
	hdn_stack_pressure_sink ^= buf[sizeof(buf) - 1];
}

static int resource_stack_pressure_child(void)
{
	struct rlimit limit = {
		.rlim_cur = HDN_RLIMIT_STACK_LOW,
		.rlim_max = HDN_RLIMIT_STACK_LOW,
	};

	signal(SIGSEGV, SIG_DFL);
	if (setrlimit(RLIMIT_STACK, &limit))
		return 2;

	consume_stack_for_rlimit(HDN_RLIMIT_STACK_CONSUME);
	return 1;
}

static void test_resource_stack_pressure_event_logged(void)
{
	unsigned int before;
	unsigned int after;
	pid_t child;
	int status;

	before = securityfs_resource_pressure_count(RLIMIT_STACK);

	child = fork();
	if (child < 0) {
		ksft_test_result_fail("stack pressure fork failed: %s\n",
				      strerror(errno));
		return;
	}
	if (!child)
		_exit(resource_stack_pressure_child());

	if (waitpid(child, &status, 0) < 0) {
		ksft_test_result_fail("stack pressure wait failed: %s\n",
				      strerror(errno));
		return;
	}

	after = securityfs_resource_pressure_count(RLIMIT_STACK);
	ksft_test_result(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV &&
			 after > before,
			 "hardening events report stack resource pressure\n");
}

static int resource_nproc_pressure_child(void)
{
	struct rlimit limit;
	pid_t child;

	if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
		return 2;

	if (getrlimit(RLIMIT_NPROC, &limit))
		return 2;
	if (limit.rlim_max != RLIM_INFINITY && limit.rlim_max < 1)
		return KSFT_SKIP;

	limit.rlim_cur = 1;
	if (setrlimit(RLIMIT_NPROC, &limit))
		return 2;

	errno = 0;
	child = fork();
	if (child < 0)
		return errno == EAGAIN ? 0 : 2;
	if (!child)
		_exit(0);

	waitpid(child, NULL, 0);
	return 1;
}

static void test_resource_nproc_pressure_event_logged(void)
{
	char needle[128];
	unsigned int before;
	pid_t child;
	int result;

	snprintf(needle, sizeof(needle), "object=%llu",
		 hdn_resource_pressure_object(RLIMIT_NPROC, 2));
	before = securityfs_events_count(needle);

	child = fork();
	if (child < 0) {
		ksft_test_result_fail(
			"resource nproc pressure fork failed: %s\n",
			strerror(errno));
		return;
	}
	if (!child)
		_exit(resource_nproc_pressure_child());

	result = child_exit_result(child);
	if (result == KSFT_SKIP) {
		ksft_test_result_skip(
			"hardening events report nproc resource pressure\n");
		return;
	}

	ksft_test_result(result == 0 && securityfs_events_count(needle) > before,
			 "hardening events report nproc resource pressure\n");
}

static int resource_memlock_pressure_child(void)
{
	long page_size = sysconf(_SC_PAGESIZE);
	struct rlimit limit;
	size_t len;
	void *addr;
	int saved_errno = 0;
	int ret;

	if (page_size <= 0)
		return 2;
	len = (size_t)page_size * 2;

	if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
		return 2;

	if (getrlimit(RLIMIT_MEMLOCK, &limit))
		return 2;
	if (limit.rlim_max != RLIM_INFINITY &&
	    limit.rlim_max < (rlim_t)page_size)
		return KSFT_SKIP;

	limit.rlim_cur = page_size;
	if (setrlimit(RLIMIT_MEMLOCK, &limit))
		return 2;

	addr = mmap(NULL, len, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED)
		return 2;

	ret = mlock(addr, len);
	if (ret < 0)
		saved_errno = errno;
	munmap(addr, len);

	return ret < 0 && saved_errno == ENOMEM ? 0 : 1;
}

static void test_resource_memlock_pressure_event_logged(void)
{
	long page_size = sysconf(_SC_PAGESIZE);
	char needle[128];
	unsigned int before;
	pid_t child;
	int result;

	if (page_size <= 0) {
		ksft_test_result_fail(
			"resource memlock pressure page-size query failed\n");
		return;
	}

	snprintf(needle, sizeof(needle), "object=%llu",
		 hdn_resource_pressure_object(RLIMIT_MEMLOCK,
					      (unsigned long)page_size * 2));
	before = securityfs_events_count(needle);

	child = fork();
	if (child < 0) {
		ksft_test_result_fail(
			"resource memlock pressure fork failed: %s\n",
			strerror(errno));
		return;
	}
	if (!child)
		_exit(resource_memlock_pressure_child());

	result = child_exit_result(child);
	if (result == KSFT_SKIP) {
		ksft_test_result_skip(
			"hardening events report memlock resource pressure\n");
		return;
	}

	ksft_test_result(result == 0 && securityfs_events_count(needle) > before,
			 "hardening events report memlock resource pressure\n");
}

static void test_resource_msgqueue_pressure_event_logged(void)
{
	struct mq_attr attr = {
		.mq_maxmsg = 8,
		.mq_msgsize = 256,
	};
	struct rlimit lower;
	struct rlimit orig;
	unsigned int before;
	int saved_errno = 0;
	mqd_t mqd;

	if (getrlimit(RLIMIT_MSGQUEUE, &orig)) {
		ksft_test_result_fail("msgqueue getrlimit failed: %s\n",
				      strerror(errno));
		return;
	}
	if (orig.rlim_max != RLIM_INFINITY && orig.rlim_max < 1) {
		ksft_test_result_skip("msgqueue limit unavailable\n");
		return;
	}

	mq_unlink(HDN_POSIX_MQ_NAME);
	before = securityfs_resource_pressure_count(RLIMIT_MSGQUEUE);

	lower = orig;
	lower.rlim_cur = 1;
	if (setrlimit(RLIMIT_MSGQUEUE, &lower)) {
		ksft_test_result_fail("msgqueue setrlimit failed: %s\n",
				      strerror(errno));
		return;
	}

	mqd = mq_open(HDN_POSIX_MQ_NAME,
		      O_CREAT | O_EXCL | O_RDWR | O_NONBLOCK, 0600, &attr);
	if (mqd == (mqd_t)-1)
		saved_errno = errno;
	else
		mq_close(mqd);
	mq_unlink(HDN_POSIX_MQ_NAME);

	if (setrlimit(RLIMIT_MSGQUEUE, &orig)) {
		ksft_test_result_fail("msgqueue restore failed: %s\n",
				      strerror(errno));
		return;
	}

	ksft_test_result(mqd == (mqd_t)-1 && saved_errno == EMFILE &&
			 securityfs_resource_pressure_count(RLIMIT_MSGQUEUE) >
			 before,
			 "hardening events report msgqueue resource pressure\n");
}

static void test_resource_sigpending_pressure_event_logged(void)
{
	struct timespec timeout = {};
	union sigval value = {};
	struct rlimit lower;
	struct rlimit orig;
	unsigned int before;
	int saved_errno = 0;
	sigset_t oldset;
	sigset_t set;
	int ret;

	if (getrlimit(RLIMIT_SIGPENDING, &orig)) {
		ksft_test_result_fail("sigpending getrlimit failed: %s\n",
				      strerror(errno));
		return;
	}

	sigemptyset(&set);
	sigaddset(&set, SIGRTMIN);
	if (sigprocmask(SIG_BLOCK, &set, &oldset)) {
		ksft_test_result_fail("sigpending block failed: %s\n",
				      strerror(errno));
		return;
	}

	before = securityfs_resource_pressure_count(RLIMIT_SIGPENDING);

	lower = orig;
	lower.rlim_cur = 0;
	if (setrlimit(RLIMIT_SIGPENDING, &lower)) {
		ksft_test_result_fail("sigpending setrlimit failed: %s\n",
				      strerror(errno));
		goto out_signal;
	}

	ret = sigqueue(getpid(), SIGRTMIN, value);
	if (ret < 0)
		saved_errno = errno;
	else
		sigtimedwait(&set, NULL, &timeout);

	if (setrlimit(RLIMIT_SIGPENDING, &orig)) {
		ksft_test_result_fail("sigpending restore failed: %s\n",
				      strerror(errno));
		goto out_signal;
	}

	ksft_test_result(ret < 0 && saved_errno == EAGAIN &&
			 securityfs_resource_pressure_count(RLIMIT_SIGPENDING) >
			 before,
			 "hardening events report sigpending resource pressure\n");

out_signal:
	sigprocmask(SIG_SETMASK, &oldset, NULL);
}

static void resource_cpu_pressure_signal(int signum)
{
	_exit(signum == SIGXCPU ? 0 : 2);
}

static int resource_cpu_pressure_child(void)
{
	struct sigaction action = {
		.sa_handler = resource_cpu_pressure_signal,
	};
	struct rlimit limit = {
		.rlim_cur = 1,
		.rlim_max = 3,
	};

	sigemptyset(&action.sa_mask);
	if (sigaction(SIGXCPU, &action, NULL) ||
	    sigaction(SIGALRM, &action, NULL))
		return 2;

	if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
		return 2;

	if (setrlimit(RLIMIT_CPU, &limit))
		return 2;

	alarm(8);
	for (;;)
		getpid();
}

static void test_resource_cpu_pressure_event_logged(void)
{
	unsigned int before;
	pid_t child;
	int result;

	before = securityfs_resource_pressure_count(RLIMIT_CPU);

	child = fork();
	if (child < 0) {
		ksft_test_result_fail("cpu pressure fork failed: %s\n",
				      strerror(errno));
		return;
	}
	if (!child)
		_exit(resource_cpu_pressure_child());

	result = child_exit_result(child);
	ksft_test_result(result == 0 &&
			 securityfs_resource_pressure_count(RLIMIT_CPU) >
			 before,
			 "hardening events report cpu-time resource pressure\n");
}

static int resource_rttime_pressure_child(void)
{
	struct sigaction action = {
		.sa_handler = resource_cpu_pressure_signal,
	};
	struct sched_param param = {
		.sched_priority = 1,
	};
	struct rlimit limit = {
		.rlim_cur = 100000,
		.rlim_max = 1000000,
	};

	sigemptyset(&action.sa_mask);
	if (sigaction(SIGXCPU, &action, NULL) ||
	    sigaction(SIGALRM, &action, NULL))
		return 2;

	if (setrlimit(RLIMIT_RTTIME, &limit))
		return 2;

	errno = 0;
	if (sched_setscheduler(0, SCHED_FIFO, &param))
		return errno == EPERM ? KSFT_SKIP : 2;

	alarm(8);
	for (;;)
		getpid();
}

static void test_resource_rttime_pressure_event_logged(void)
{
	unsigned int before;
	pid_t child;
	int result;

	before = securityfs_resource_pressure_count(RLIMIT_RTTIME);

	child = fork();
	if (child < 0) {
		ksft_test_result_fail("rttime pressure fork failed: %s\n",
				      strerror(errno));
		return;
	}
	if (!child)
		_exit(resource_rttime_pressure_child());

	result = child_exit_result(child);
	if (result == KSFT_SKIP) {
		ksft_test_result_skip("rttime resource pressure unavailable\n");
		return;
	}

	ksft_test_result(result == 0 &&
			 securityfs_resource_pressure_count(RLIMIT_RTTIME) >
			 before,
			 "hardening events report rttime resource pressure\n");
}

static int resource_nice_pressure_child(void)
{
	struct rlimit limit = {};
	int ret;

	if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
		return 2;

	if (setrlimit(RLIMIT_NICE, &limit))
		return 2;

	errno = 0;
	ret = setpriority(PRIO_PROCESS, 0, -1);
	if (!ret) {
		setpriority(PRIO_PROCESS, 0, 0);
		return 1;
	}

	return errno == EACCES ? 0 : 2;
}

static void test_resource_nice_pressure_event_logged(void)
{
	unsigned int before;
	pid_t child;
	int result;

	before = securityfs_resource_pressure_count(RLIMIT_NICE);

	child = fork();
	if (child < 0) {
		ksft_test_result_fail("nice pressure fork failed: %s\n",
				      strerror(errno));
		return;
	}
	if (!child)
		_exit(resource_nice_pressure_child());

	result = child_exit_result(child);
	ksft_test_result(result == 0 &&
			 securityfs_resource_pressure_count(RLIMIT_NICE) >
			 before,
			 "hardening events report nice resource pressure\n");
}

static int resource_rtprio_pressure_child(void)
{
	struct sched_param param = {
		.sched_priority = 1,
	};
	struct rlimit limit = {};
	int ret;

	if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
		return 2;

	if (setrlimit(RLIMIT_RTPRIO, &limit))
		return 2;

	errno = 0;
	ret = sched_setscheduler(0, SCHED_FIFO, &param);
	if (!ret) {
		sched_setscheduler(0, SCHED_OTHER, &(struct sched_param){});
		return 1;
	}

	return errno == EPERM ? 0 : 2;
}

static void test_resource_rtprio_pressure_event_logged(void)
{
	unsigned int before;
	pid_t child;
	int result;

	before = securityfs_resource_pressure_count(RLIMIT_RTPRIO);

	child = fork();
	if (child < 0) {
		ksft_test_result_fail("rtprio pressure fork failed: %s\n",
				      strerror(errno));
		return;
	}
	if (!child)
		_exit(resource_rtprio_pressure_child());

	result = child_exit_result(child);
	ksft_test_result(result == 0 &&
			 securityfs_resource_pressure_count(RLIMIT_RTPRIO) >
			 before,
			 "hardening events report rtprio resource pressure\n");
}

static int file_lock_pressure_child(const char *path, int inherited_fd,
				    bool posix_lock)
{
	int saved_errno = 0;
	int fd;
	int ret;

	close(inherited_fd);
	fd = open(path, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return 2;

	if (posix_lock) {
		struct flock lock = {
			.l_type = F_WRLCK,
			.l_whence = SEEK_SET,
			.l_start = 0,
			.l_len = 1,
		};

		ret = fcntl(fd, F_SETLK, &lock);
	} else {
		ret = flock(fd, LOCK_EX | LOCK_NB);
	}
	if (ret < 0)
		saved_errno = errno;
	close(fd);

	return ret < 0 && (saved_errno == EACCES ||
			   saved_errno == EAGAIN ||
			   saved_errno == EWOULDBLOCK) ? 0 : 1;
}

static int run_conflicting_file_lock(const char *path, bool posix_lock)
{
	int result = 2;
	pid_t child;
	int fd;

	unlink(path);
	fd = open(path, O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
	if (fd < 0)
		return 2;

	if (posix_lock) {
		struct flock lock = {
			.l_type = F_WRLCK,
			.l_whence = SEEK_SET,
			.l_start = 0,
			.l_len = 1,
		};

		if (fcntl(fd, F_SETLK, &lock))
			goto out;
	} else if (flock(fd, LOCK_EX)) {
		goto out;
	}

	child = fork();
	if (child < 0)
		goto out;
	if (!child)
		_exit(file_lock_pressure_child(path, fd, posix_lock));

	result = child_exit_result(child);

out:
	if (posix_lock) {
		struct flock unlock = {
			.l_type = F_UNLCK,
			.l_whence = SEEK_SET,
			.l_start = 0,
			.l_len = 1,
		};

		fcntl(fd, F_SETLK, &unlock);
	} else {
		flock(fd, LOCK_UN);
	}
	close(fd);
	unlink(path);
	return result;
}

static void test_resource_locks_pressure_event_logged(void)
{
	unsigned int before;
	unsigned int after;
	int flock_result;
	int posix_result;

	before = securityfs_resource_pressure_count(RLIMIT_LOCKS);
	flock_result = run_conflicting_file_lock(HDN_FLOCK_PRESSURE_FILE,
						 false);
	posix_result = run_conflicting_file_lock(HDN_POSIX_LOCK_PRESSURE_FILE,
						 true);
	after = securityfs_resource_pressure_count(RLIMIT_LOCKS);

	ksft_test_result(flock_result == 0 && posix_result == 0 &&
			 after >= before + 2,
			 "hardening events report file-lock resource pressure\n");
}

static void test_time_change_event_logged(void)
{
	const char *needle = "authority=32 transition=37 action=3";
	struct timespec ts;
	unsigned int before;

	if (clock_gettime(CLOCK_REALTIME, &ts)) {
		ksft_test_result_fail("time audit clock_gettime failed: %s\n",
				      strerror(errno));
		return;
	}

	before = securityfs_events_count(needle);
	if (clock_settime(CLOCK_REALTIME, &ts)) {
		ksft_test_result_fail("time audit clock_settime failed: %s\n",
				      strerror(errno));
		return;
	}

	ksft_test_result(securityfs_events_count(needle) > before,
			 "hardening events report time-change audit\n");
}

#define HDN_EVENTS_READ_MAX (1024 * 1024)

static char *securityfs_events_read_all(void)
{
	char *buf;
	size_t cap = 65536;
	size_t used = 0;
	int fd;

	fd = open(HDN_EVENTS, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;

	buf = malloc(cap);
	if (!buf) {
		close(fd);
		return NULL;
	}

	for (;;) {
		ssize_t len;

		if (used == cap - 1) {
			char *new_buf;

			if (cap >= HDN_EVENTS_READ_MAX)
				break;
			cap *= 2;
			if (cap > HDN_EVENTS_READ_MAX)
				cap = HDN_EVENTS_READ_MAX;
			new_buf = realloc(buf, cap);
			if (!new_buf) {
				free(buf);
				close(fd);
				return NULL;
			}
			buf = new_buf;
		}

		len = read(fd, buf + used, cap - used - 1);
		if (len < 0) {
			free(buf);
			close(fd);
			return NULL;
		}
		if (len == 0)
			break;
		used += len;
	}

	close(fd);
	buf[used] = '\0';

	return buf;
}

static bool securityfs_events_contains(const char *needle)
{
	char *buf;
	bool found = false;

	buf = securityfs_events_read_all();
	if (!buf)
		return false;

	found = strstr(buf, needle);

	free(buf);
	return found;
}

static bool securityfs_events_line_contains(const char *needle_a,
					    const char *needle_b)
{
	char *cursor;
	char *line;
	char *buf;
	bool found = false;

	buf = securityfs_events_read_all();
	if (!buf)
		return false;

	cursor = buf;
	while ((line = strsep(&cursor, "\n"))) {
		if (strstr(line, needle_a) && strstr(line, needle_b)) {
			found = true;
			break;
		}
	}

	free(buf);
	return found;
}

static unsigned int securityfs_events_line_count(const char *needle_a,
						 const char *needle_b)
{
	char *cursor;
	char *line;
	char *buf;
	unsigned int count = 0;

	buf = securityfs_events_read_all();
	if (!buf)
		return 0;

	cursor = buf;
	while ((line = strsep(&cursor, "\n"))) {
		if (strstr(line, needle_a) && strstr(line, needle_b))
			count++;
	}

	free(buf);
	return count;
}

static unsigned int securityfs_resource_pressure_count(unsigned int resource)
{
	const char *needle = "authority=33 transition=38 action=3";
	const unsigned long long resource_shift = 56;
	unsigned int count = 0;
	char *object_field;
	char *cursor;
	char *line;
	char *buf;

	buf = securityfs_events_read_all();
	if (!buf)
		return 0;

	cursor = buf;
	while ((line = strsep(&cursor, "\n"))) {
		unsigned long long object;
		char *end;

		if (!strstr(line, needle))
			continue;

		object_field = strstr(line, "object=");
		if (!object_field)
			continue;

		errno = 0;
		object = strtoull(object_field + strlen("object="), &end, 10);
		if (errno || end == object_field + strlen("object="))
			continue;

		if ((object >> resource_shift) == (resource & 0xff))
			count++;
	}

	free(buf);
	return count;
}

static unsigned int securityfs_events_count(const char *needle)
{
	const char *cursor;
	char *buf;
	unsigned int count = 0;

	buf = securityfs_events_read_all();
	if (!buf)
		return 0;

	cursor = buf;
	while ((cursor = strstr(cursor, needle))) {
		count++;
		cursor += strlen(needle);
	}

	free(buf);
	return count;
}

static int event_decoder_finds_wx_denial(void)
{
	pid_t child;

	if (access(HDN_EVENT_DECODE_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_EVENT_DECODE_EXEC, "hdn-event-decode", "--quiet",
		      "--expect", "reason=USER_WX_MAPPING",
		      "--expect", "action=DENY_AUDIT", NULL);
		fprintf(stderr, "event decoder exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int event_decoder_finds_rwxmap_denial(void)
{
	pid_t child;

	if (access(HDN_EVENT_DECODE_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_EVENT_DECODE_EXEC, "hdn-event-decode", "--quiet",
		      "--expect", "reason=RWXMAP_DENIED",
		      "--expect", "action=DENY_AUDIT", NULL);
		fprintf(stderr, "event decoder exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int event_decoder_finds_exec_stack_elf_audit(void)
{
	pid_t child;

	if (access(HDN_EVENT_DECODE_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_EVENT_DECODE_EXEC, "hdn-event-decode", "--quiet",
		      "--expect", "reason=EXEC_STACK_ELF",
		      "--expect", "action=DENY_AUDIT", NULL);
		fprintf(stderr, "event decoder exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int event_decoder_finds_textrel_mprotect_audit(void)
{
	pid_t child;

	if (access(HDN_EVENT_DECODE_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_EVENT_DECODE_EXEC, "hdn-event-decode", "--quiet",
		      "--expect", "reason=TEXTREL_MPROTECT",
		      "--expect", "action=DENY_AUDIT", NULL);
		fprintf(stderr, "event decoder exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int event_decoder_finds_relro_write_audit(void)
{
	pid_t child;

	if (access(HDN_EVENT_DECODE_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_EVENT_DECODE_EXEC, "hdn-event-decode", "--quiet",
		      "--expect", "reason=RELRO_WRITE",
		      "--expect", "action=DENY_AUDIT", NULL);
		fprintf(stderr, "event decoder exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int event_decoder_finds_userns_depth_denial(void)
{
	pid_t child;

	if (access(HDN_EVENT_DECODE_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_EVENT_DECODE_EXEC, "hdn-event-decode", "--quiet",
		      "--expect", "authority=USERNS_CREATE",
		      "--expect", "reason=USERNS_DEPTH", NULL);
		fprintf(stderr, "event decoder exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int event_decoder_finds_chroot_mount_denial(void)
{
	pid_t child;

	if (access(HDN_EVENT_DECODE_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_EVENT_DECODE_EXEC, "hdn-event-decode", "--quiet",
		      "--expect", "authority=CHROOT_ADMIN",
		      "--expect", "transition=MOUNT",
		      "--expect", "reason=CHROOT_MOUNT", NULL);
		fprintf(stderr, "event decoder exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int event_decoder_finds_chroot_file_handle_denial(void)
{
	pid_t child;

	if (access(HDN_EVENT_DECODE_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_EVENT_DECODE_EXEC, "hdn-event-decode", "--quiet",
		      "--expect", "authority=CHROOT_ADMIN",
		      "--expect", "transition=CHROOT",
		      "--expect", "reason=CHROOT_FILE_HANDLE", NULL);
		fprintf(stderr, "event decoder exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int event_decoder_finds_chroot_sysctl_denial(void)
{
	pid_t child;

	if (access(HDN_EVENT_DECODE_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_EVENT_DECODE_EXEC, "hdn-event-decode", "--quiet",
		      "--expect", "authority=CHROOT_ADMIN",
		      "--expect", "transition=CHROOT",
		      "--expect", "reason=CHROOT_SYSCTL", NULL);
		fprintf(stderr, "event decoder exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int event_decoder_finds_signal_audit(void)
{
	pid_t child;

	if (access(HDN_EVENT_DECODE_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_EVENT_DECODE_EXEC, "hdn-event-decode", "--quiet",
		      "--expect", "transition=SIGNAL",
		      "--expect", "action=ALLOW_AUDIT", NULL);
		fprintf(stderr, "event decoder exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int event_decoder_finds_ptrace_audit(void)
{
	pid_t child;

	if (access(HDN_EVENT_DECODE_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_EVENT_DECODE_EXEC, "hdn-event-decode", "--quiet",
		      "--expect", "authority=PTRACE",
		      "--expect", "transition=PTRACE",
		      "--expect", "action=ALLOW_AUDIT", NULL);
		fprintf(stderr, "event decoder exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int event_decoder_finds_fork_failure_audit(void)
{
	pid_t child;

	if (access(HDN_EVENT_DECODE_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_EVENT_DECODE_EXEC, "hdn-event-decode", "--quiet",
		      "--expect", "transition=FORK",
		      "--expect", "reason=FORK_FAILED",
		      "--expect", "action=DENY_AUDIT", NULL);
		fprintf(stderr, "event decoder exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int event_decoder_finds_fs_protection_audit(void)
{
	pid_t child;

	if (access(HDN_EVENT_DECODE_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_EVENT_DECODE_EXEC, "hdn-event-decode", "--quiet",
		      "--expect", "transition=FS_PROTECTION",
		      "--expect", "reason=PROTECTED_SYMLINK",
		      "--expect", "action=DENY_AUDIT", NULL);
		fprintf(stderr, "event decoder exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int event_decoder_finds_symlink_owner_audit(void)
{
	pid_t child;

	if (access(HDN_EVENT_DECODE_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_EVENT_DECODE_EXEC, "hdn-event-decode", "--quiet",
		      "--expect", "transition=FS_PROTECTION",
		      "--expect", "reason=SYMLINK_OWNER_MISMATCH",
		      "--expect", "action=DENY_AUDIT", NULL);
		fprintf(stderr, "event decoder exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int event_decoder_finds_kernel_log_write_denial(void)
{
	pid_t child;

	if (access(HDN_EVENT_DECODE_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_EVENT_DECODE_EXEC, "hdn-event-decode", "--quiet",
		      "--expect", "authority=KERNEL_LOG_WRITE",
		      "--expect", "transition=KERNEL_LOG_WRITE",
		      "--expect", "action=DENY_AUDIT", NULL);
		fprintf(stderr, "event decoder exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int event_decoder_finds_object_rename_target_denial(void)
{
	pid_t child;

	if (access(HDN_EVENT_DECODE_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_EVENT_DECODE_EXEC, "hdn-event-decode", "--quiet",
		      "--expect", "authority=OBJECT_RENAME_TARGET",
		      "--expect", "transition=OBJECT_RENAME_TARGET",
		      "--expect", "action=DENY_AUDIT", NULL);
		fprintf(stderr, "event decoder exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int event_decoder_finds_object_link_target_denial(void)
{
	pid_t child;

	if (access(HDN_EVENT_DECODE_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_EVENT_DECODE_EXEC, "hdn-event-decode", "--quiet",
		      "--expect", "authority=OBJECT_LINK_TARGET",
		      "--expect", "transition=OBJECT_LINK_TARGET",
		      "--expect", "action=DENY_AUDIT", NULL);
		fprintf(stderr, "event decoder exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int event_decoder_finds_object_mount_source_denial(void)
{
	pid_t child;

	if (access(HDN_EVENT_DECODE_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_EVENT_DECODE_EXEC, "hdn-event-decode", "--quiet",
		      "--expect", "authority=OBJECT_MOUNT_SOURCE",
		      "--expect", "transition=OBJECT_MOUNT_SOURCE",
		      "--expect", "action=DENY_AUDIT", NULL);
		fprintf(stderr, "event decoder exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int event_decoder_finds_object_setid_denial(void)
{
	pid_t child;

	if (access(HDN_EVENT_DECODE_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_EVENT_DECODE_EXEC, "hdn-event-decode", "--quiet",
		      "--expect", "authority=OBJECT_SETID",
		      "--expect", "transition=OBJECT_SETID",
		      "--expect", "action=DENY_AUDIT", NULL);
		fprintf(stderr, "event decoder exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int event_decoder_finds_object_ptrace_denial(void)
{
	pid_t child;

	if (access(HDN_EVENT_DECODE_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_EVENT_DECODE_EXEC, "hdn-event-decode", "--quiet",
		      "--expect", "authority=OBJECT_PTRACE",
		      "--expect", "transition=OBJECT_PTRACE",
		      "--expect", "action=DENY_AUDIT", NULL);
		fprintf(stderr, "event decoder exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int event_decoder_finds_protected_shm_denial(void)
{
	pid_t child;

	if (access(HDN_EVENT_DECODE_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_EVENT_DECODE_EXEC, "hdn-event-decode", "--quiet",
		      "--expect", "authority=IPC_ADMIN",
		      "--expect", "transition=SYSVIPC_ACCESS",
		      "--expect", "reason=PROTECTED_SHM",
		      "--expect", "action=DENY_AUDIT", NULL);
		fprintf(stderr, "event decoder exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int event_decoder_finds_tty_access_denial(void)
{
	pid_t child;

	if (access(HDN_EVENT_DECODE_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_EVENT_DECODE_EXEC, "hdn-event-decode", "--quiet",
		      "--expect", "authority=TTY_ACCESS",
		      "--expect", "transition=TTY_ACCESS",
		      "--expect", "reason=TTY_ACCESS",
		      "--expect", "action=DENY_AUDIT", NULL);
		fprintf(stderr, "event decoder exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int event_decoder_finds_capability_denial(void)
{
	pid_t child;

	if (access(HDN_EVENT_DECODE_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_EVENT_DECODE_EXEC, "hdn-event-decode", "--quiet",
		      "--expect", "authority=NONE",
		      "--expect", "transition=CAPABILITY",
		      "--expect", "reason=CAPABILITY_PROFILE",
		      "--expect", "action=DENY_AUDIT", NULL);
		fprintf(stderr, "event decoder exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int event_decoder_finds_object_read_audit(void)
{
	pid_t child;

	if (access(HDN_EVENT_DECODE_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_EVENT_DECODE_EXEC, "hdn-event-decode", "--quiet",
		      "--expect", "transition=OBJECT_READ",
		      "--expect", "reason=NONE",
		      "--expect", "action=ALLOW_AUDIT", NULL);
		fprintf(stderr, "event decoder exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int event_decoder_finds_exec_inherit_audit(void)
{
	pid_t child;

	if (access(HDN_EVENT_DECODE_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_EVENT_DECODE_EXEC, "hdn-event-decode", "--quiet",
		      "--expect", "authority=EXEC",
		      "--expect", "transition=EXEC_INHERIT",
		      "--expect", "reason=NONE",
		      "--expect", "action=ALLOW_AUDIT", NULL);
		fprintf(stderr, "event decoder exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int event_decoder_read_output(int fd, char *buf, size_t size)
{
	size_t offset = 0;

	if (!size)
		return -EINVAL;

	for (;;) {
		ssize_t len;

		if (offset == size - 1)
			return -ENOSPC;
		len = read(fd, buf + offset, size - 1 - offset);
		if (len < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (!len)
			break;
		offset += len;
	}

	buf[offset] = '\0';
	return 0;
}

static int event_decoder_run_capture(const char *input, char *buf, size_t size)
{
	int pipefd[2];
	int status;
	pid_t child;
	int ret;

	if (pipe(pipefd))
		return -errno;

	child = fork();
	if (child < 0) {
		ret = -errno;
		close(pipefd[0]);
		close(pipefd[1]);
		return ret;
	}

	if (!child) {
		close(pipefd[0]);
		if (dup2(pipefd[1], STDOUT_FILENO) < 0)
			_exit(2);
		close(pipefd[1]);
		execl(HDN_EVENT_DECODE_EXEC, "hdn-event-decode",
		      "--input", input, NULL);
		fprintf(stderr, "event decoder exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	close(pipefd[1]);
	ret = event_decoder_read_output(pipefd[0], buf, size);
	close(pipefd[0]);

	if (waitpid(child, &status, 0) < 0)
		return -errno;
	if (ret)
		return ret;
	if (!WIFEXITED(status))
		return 2;
	return WEXITSTATUS(status);
}

static int event_decoder_names_object_details(void)
{
	static const char * const needles[] = {
		"object_detail=exec_args argc=3 envc=4",
		"object_detail=signal signal_id=11 signal=SIGSEGV",
		"fault_addr_low=0x1234",
		"object_detail=resource resource_id=",
		"resource=NOFILE",
		"resource=FSIZE resource_wanted=123",
		"time_operation=SET_WALL",
		"usb_bus=5 usb_port=7",
		"socket_family=AF_INET socket_type_id=1 socket_type=SOCK_STREAM socket_protocol=6",
		"socket_port=443 socket_address=127.0.0.1",
		"object_detail=signal signal_id=25 signal=SIGXFSZ",
		"object_detail=capability capability_id=0 capability=CAP_CHOWN",
	};
	char fixture[4096];
	char output[8192];
	unsigned long long exec_args_object = (3ULL << 32) | 4ULL;
	unsigned long long signal_object =
		((unsigned long long)SIGSEGV << 56) | 0x1234ULL;
	unsigned long long resource_pressure_object =
		((unsigned long long)RLIMIT_FSIZE << 56) | 123ULL;
	unsigned long long usb_object = (5ULL << 32) | 7ULL;
	unsigned long long socket_create_object =
		((unsigned long long)AF_INET << 32) |
		((unsigned long long)SOCK_STREAM << 16) |
		(unsigned long long)IPPROTO_TCP;
	unsigned long long socket_endpoint_object =
		((unsigned long long)AF_INET << 56) |
		((unsigned long long)SOCK_STREAM << 48) |
		(443ULL << 32) | 0x7f000001ULL;
	size_t i;
	int ret;

	if (access(HDN_EVENT_DECODE_EXEC, X_OK))
		return KSFT_SKIP;

	ret = snprintf(fixture, sizeof(fixture),
		       "sequence=1 timestamp_ns=1 event_id=88 pid=1 uid=0 profile=1 authority=1 transition=88 action=3 reason=0 error=0 subject=1 object=%llu flags=0x0\n"
		       "sequence=2 timestamp_ns=1 event_id=46 pid=1 uid=0 profile=1 authority=0 transition=46 action=3 reason=0 error=0 subject=1 object=%llu flags=0x0\n"
		       "sequence=3 timestamp_ns=1 event_id=38 pid=1 uid=0 profile=1 authority=33 transition=38 action=3 reason=0 error=0 subject=1 object=%u flags=0x0\n"
		       "sequence=4 timestamp_ns=1 event_id=38 pid=1 uid=0 profile=1 authority=33 transition=38 action=3 reason=0 error=0 subject=1 object=%llu flags=0x0\n"
		       "sequence=5 timestamp_ns=1 event_id=37 pid=1 uid=0 profile=1 authority=32 transition=37 action=3 reason=0 error=0 subject=1 object=1 flags=0x0\n"
		       "sequence=6 timestamp_ns=1 event_id=32 pid=1 uid=0 profile=1 authority=27 transition=32 action=4 reason=7 error=-1 subject=1 object=%llu flags=0x0\n"
		       "sequence=7 timestamp_ns=1 event_id=33 pid=1 uid=0 profile=1 authority=28 transition=33 action=4 reason=7 error=-1 subject=1 object=%llu flags=0x0\n"
		       "sequence=8 timestamp_ns=1 event_id=34 pid=1 uid=0 profile=1 authority=29 transition=34 action=4 reason=7 error=-1 subject=1 object=%llu flags=0x0\n"
		       "sequence=9 timestamp_ns=1 event_id=87 pid=1 uid=0 profile=1 authority=0 transition=87 action=4 reason=53 error=-1 subject=1 object=%u flags=0x0\n"
		       "sequence=10 timestamp_ns=1 event_id=103 pid=1 uid=0 profile=1 authority=0 transition=103 action=4 reason=59 error=-1 subject=1 object=%u flags=0x0\n",
		       exec_args_object, signal_object, RLIMIT_NOFILE,
		       resource_pressure_object, usb_object,
		       socket_create_object, socket_endpoint_object, SIGXFSZ,
		       CAP_CHOWN);
	if (ret < 0 || (size_t)ret >= sizeof(fixture))
		return 2;

	ret = write_created_text_file(HDN_EVENT_DECODE_DETAILS_INPUT,
				      fixture);
	if (ret)
		return 2;

	ret = event_decoder_run_capture(HDN_EVENT_DECODE_DETAILS_INPUT,
					output, sizeof(output));
	unlink(HDN_EVENT_DECODE_DETAILS_INPUT);
	if (ret)
		return ret;

	for (i = 0; i < ARRAY_SIZE(needles); i++) {
		if (!strstr(output, needles[i])) {
			fprintf(stderr, "event decoder output missing %s\n",
				needles[i]);
			fprintf(stderr, "%s\n", output);
			return 1;
		}
	}

	return 0;
}

static int status_helper_reports_live_state(void)
{
	pid_t child;

	if (access(HDN_STATUS_HELPER_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_STATUS_HELPER_EXEC, "hdn-status", "--quiet",
		      "--expect", "available=1",
		      "--expect", "mitigations_sealed=1",
		      "--expect", "mitigation_audit_flood_control=1", NULL);
		fprintf(stderr, "status helper exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int status_helper_reports_live_compat_state(void)
{
	pid_t child;

	if (access(HDN_STATUS_HELPER_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_STATUS_HELPER_EXEC, "hdn-status", "--compat",
		      "--quiet",
		      "--expect", "compat_status_v1=1",
		      "--expect", "compat_hidesym=1",
		      "--expect", "compat_proc=1",
		      "--expect", "compat_proc_memmap=1",
		      "--expect", "compat_sysfs=1",
		      "--expect", "compat_bpf=1",
		      "--expect", "compat_memory_init=1",
		      "--expect", "compat_allocator=1",
		      "--expect", "compat_compiler=1",
		      "--expect", "compat_stack=1",
		      "--expect", "compat_kernel_wx=1",
		      "--expect", "compat_perf=1",
		      "--expect", "compat_module=1",
		      "--expect", "compat_rofs=1",
		      "--expect", "compat_usb=1",
		      "--expect", "compat_socket=1",
		      "--expect", "compat_net_blackhole=1",
		      "--expect", "compat_ipc=1",
		      "--expect", "compat_tty=1",
		      "--expect", "compat_resource=1",
		      "--expect", "compat_block_device=1",
		      "--expect", "compat_audit=1", NULL);
		fprintf(stderr, "status helper compat exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int status_helper_reports_compat_fixture(void)
{
	static const char fixture[] =
		"phase: runtime\n"
		"policy_loaded: 1\n"
		"policy_sealed: 1\n"
		"mitigations_sealed: 1\n"
		"mitigation_dmesg_restrict: 1\n"
		"mitigation_kernel_symbol_lookup_gate: 1\n"
		"mitigation_kptr_restrict: 0\n"
		"mitigation_proc_hide: 1\n"
		"mitigation_proc_mem_restrict: 0\n"
		"mitigation_proc_memmap_redact: 1\n"
		"mitigation_sysfs_restrict: 1\n"
		"mitigation_unpriv_bpf_lockdown: 1\n"
		"mitigation_bpf_jit_harden: 1\n"
		"mitigation_init_on_alloc: 1\n"
		"mitigation_init_on_free: 1\n"
		"mitigation_init_stack_zero: 0\n"
		"mitigation_kstack_erase: 1\n"
		"mitigation_zero_call_used_regs: 1\n"
		"mitigation_slab_freelist_random: 1\n"
		"mitigation_slab_freelist_hardened: 1\n"
		"mitigation_random_kmalloc_caches: 1\n"
		"mitigation_slab_buckets: 1\n"
		"mitigation_slab_merge_disabled: 1\n"
		"mitigation_hardened_usercopy: 1\n"
		"mitigation_fortify_source: 1\n"
		"mitigation_randstruct: 0\n"
		"mitigation_list_hardened: 1\n"
		"mitigation_stackprotector_strong: 1\n"
		"mitigation_vmap_stack: 1\n"
		"mitigation_thread_info_in_task: 1\n"
		"mitigation_randomize_kstack: 1\n"
		"mitigation_rand_threadstack: 1\n"
		"mitigation_strict_kernel_rwx: 1\n"
		"mitigation_strict_module_rwx: 1\n"
		"mitigation_page_table_check: 0\n"
		"mitigation_net_blackhole: 1\n"
		"mitigation_tcp_no_simult_connect: 0\n"
			"mitigation_usb_restrict: 1\n"
			"mitigation_usb_monitor_restrict: 1\n"
			"mitigation_tty_injection_harden: 1\n"
			"mitigation_tty_access_harden: 1\n"
			"mitigation_resource_admin: 1\n"
			"mitigation_resource_audit: 0\n";
	pid_t child;
	int ret;

	if (access(HDN_STATUS_HELPER_EXEC, X_OK))
		return KSFT_SKIP;

	ret = write_created_text_file(HDN_STATUS_HELPER_FIXTURE, fixture);
	if (ret)
		return 2;

	child = fork();
	if (child < 0) {
		unlink(HDN_STATUS_HELPER_FIXTURE);
		return 2;
	}

	if (!child) {
		execl(HDN_STATUS_HELPER_EXEC, "hdn-status",
		      "--status-path", HDN_STATUS_HELPER_FIXTURE, "--compat",
		      "--quiet",
		      "--expect", "compat_status_v1=1",
		      "--expect", "compat_dmesg=1",
		      "--expect", "compat_hidesym=0",
		      "--expect", "compat_proc=1",
		      "--expect", "compat_proc_memmap=0",
		      "--expect", "compat_sysfs=1",
		      "--expect", "compat_bpf=1",
		      "--expect", "compat_memory_init=0",
		      "--expect", "compat_allocator=1",
		      "--expect", "compat_compiler=0",
		      "--expect", "compat_stack=1",
		      "--expect", "compat_kernel_wx=0",
			      "--expect", "compat_net_blackhole=0",
			      "--expect", "compat_usb=1",
			      "--expect", "compat_tty=1",
			      "--expect", "compat_resource=0", NULL);
		fprintf(stderr, "status helper compat fixture exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	ret = child_exit_result(child);
	unlink(HDN_STATUS_HELPER_FIXTURE);
	return ret;
}

static int status_helper_decodes_audit_flood_fixture(void)
{
	static const char fixture[] =
				"abi_version: 99\n"
		"phase: runtime\n"
		"phase_id: 3\n"
		"policy_loaded: 1\n"
		"policy_staged: 0\n"
		"policy_sealed: 1\n"
		"rollback_available: 1\n"
		"generation: 4\n"
		"expected_generation: 3\n"
		"profile_count: 7\n"
		"subject_rule_count: 2\n"
		"object_rule_count: 3\n"
		"exec_rule_count: 5\n"
		"module_rule_count: 7\n"
		"firmware_rule_count: 11\n"
		"resource_rule_count: 13\n"
		"current_profile: 2\n"
		"current_mntns_profile: 2\n"
		"current_exec_memory_flags: 0x0\n"
		"mitigations_sealed: 1\n"
		"capability_version: 1\n"
		"capability_architecture: x86-64\n"
		"capability_required_mask: 0x0\n"
		"capability_requirements: unconstrained\n"
		"mitigation_kernel_lockout: 1\n"
		"mitigation_proc_hide: 0\n"
		"mitigation_audit_flood_control: 1\n"
		"audit_flood_suppressed_total: 9\n"
		"audit_flood_last_action: 4\n"
		"audit_flood_last_authority: 78\n"
		"audit_flood_last_transition: 90\n"
		"audit_flood_last_reason: 56\n";
	pid_t child;
	int ret;

	if (access(HDN_STATUS_HELPER_EXEC, X_OK))
		return KSFT_SKIP;

	ret = write_created_text_file(HDN_STATUS_HELPER_FIXTURE, fixture);
	if (ret)
		return 2;

	child = fork();
	if (child < 0) {
		unlink(HDN_STATUS_HELPER_FIXTURE);
		return 2;
	}

	if (!child) {
		execl(HDN_STATUS_HELPER_EXEC, "hdn-status",
		      "--status-path", HDN_STATUS_HELPER_FIXTURE, "--quiet",
		      "--expect", "state=active",
		      "--expect", "attention=0",
		      "--expect", "rule_count=41",
		      "--expect", "mitigation_known=3",
		      "--expect", "mitigation_enabled=2",
		      "--expect", "audit_flood_active=1",
		      "--expect", "audit_flood_last_action=DENY_AUDIT",
		      "--expect", "audit_flood_last_authority=USB_MONITOR",
		      "--expect", "audit_flood_last_transition=USB_MONITOR",
		      "--expect", "audit_flood_last_reason=RESOURCE_PROFILE_LIMIT",
		      NULL);
		fprintf(stderr, "status helper exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	ret = child_exit_result(child);
	unlink(HDN_STATUS_HELPER_FIXTURE);
	return ret;
}

static int support_bundle_write_event_fixture(void)
{
	char fixture[512];
	int ret;

	ret = snprintf(fixture, sizeof(fixture),
		       "sequence=1 timestamp_ns=1 event_id=3 pid=1 uid=0 profile=1 authority=2 transition=3 action=4 reason=1 error=-1 subject=1 object=0 flags=0x0\n");
	if (ret < 0 || (size_t)ret >= sizeof(fixture))
		return 2;

	return write_created_text_file(HDN_SUPPORT_BUNDLE_EVENTS, fixture);
}

static int support_bundle_run(bool dry_run, const char *config_path)
{
	pid_t child;

	if (access(HDN_SUPPORT_BUNDLE_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		if (config_path && dry_run)
			execl(HDN_SUPPORT_BUNDLE_EXEC, "hdn-support-bundle",
			      "--config", config_path, "--dry-run", NULL);
		else if (config_path)
			execl(HDN_SUPPORT_BUNDLE_EXEC, "hdn-support-bundle",
			      "--config", config_path, NULL);
		else if (dry_run)
			execl(HDN_SUPPORT_BUNDLE_EXEC, "hdn-support-bundle",
			      "--dry-run", NULL);
		else
			execl(HDN_SUPPORT_BUNDLE_EXEC, "hdn-support-bundle",
			      NULL);
		fprintf(stderr, "support bundle exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int support_bundle_unsafe_config_denied(void)
{
	int ret;

	ret = support_bundle_run(true, HDN_SUPPORT_BUNDLE_UNSAFE_CONFIG);
	if (ret == KSFT_SKIP)
		return ret;
	if (!ret) {
		fprintf(stderr, "support bundle accepted unsafe config\n");
		return 1;
	}

	return ret == 1 ? 0 : ret;
}

static int support_bundle_dry_run_passes(void)
{
	int ret;

	if (access(HDN_SUPPORT_BUNDLE_EXEC, X_OK))
		return KSFT_SKIP;

	ret = support_bundle_write_event_fixture();
	if (ret)
		return ret;

	ret = support_bundle_run(true, NULL);
	unlink(HDN_SUPPORT_BUNDLE_EVENTS);
	return ret;
}

static int support_bundle_run_capture(char *buf, size_t size)
{
	int pipefd[2];
	pid_t child;
	int status;
	int ret;

	if (access(HDN_SUPPORT_BUNDLE_EXEC, X_OK))
		return KSFT_SKIP;

	if (pipe(pipefd))
		return 2;

	child = fork();
	if (child < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return 2;
	}

	if (!child) {
		close(pipefd[0]);
		if (dup2(pipefd[1], STDOUT_FILENO) < 0)
			_exit(2);
		close(pipefd[1]);
		execl(HDN_SUPPORT_BUNDLE_EXEC, "hdn-support-bundle", NULL);
		fprintf(stderr, "support bundle exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	close(pipefd[1]);
	ret = event_decoder_read_output(pipefd[0], buf, size);
	close(pipefd[0]);

	if (waitpid(child, &status, 0) < 0)
		return 2;
	if (ret)
		return 2;
	if (!WIFEXITED(status))
		return 2;
	return WEXITSTATUS(status);
}

static int support_bundle_reports_status_and_events(void)
{
	static const char * const needles[] = {
		"HDN_SUPPORT_BUNDLE_V1",
		"section=status",
		"available=1",
		"section=compat",
		"compat_status_v1=1",
		"section=events",
		"reason=USER_WX_MAPPING",
		"action=DENY_AUDIT",
	};
	char output[131072];
	size_t i;
	int ret;

	if (access(HDN_SUPPORT_BUNDLE_EXEC, X_OK))
		return KSFT_SKIP;

	ret = support_bundle_write_event_fixture();
	if (ret)
		return ret;

	ret = support_bundle_run_capture(output, sizeof(output));
	unlink(HDN_SUPPORT_BUNDLE_EVENTS);
	if (ret)
		return ret;

	for (i = 0; i < ARRAY_SIZE(needles); i++) {
		if (!strstr(output, needles[i])) {
			fprintf(stderr, "support bundle output missing %s\n",
				needles[i]);
			fprintf(stderr, "%s\n", output);
			return 1;
		}
	}

	return 0;
}

static int control_center_status_fixture_passes(void)
{
	static const char fixture[] =
		"phase: runtime\n"
		"policy_loaded: 1\n"
		"policy_sealed: 1\n"
		"mitigations_sealed: 1\n"
		"capability_version: 1\n"
		"capability_architecture: x86-64\n"
		"capability_required_mask: 0x0\n"
		"capability_requirements: unconstrained\n"
		"mitigation_kernel_lockout: 1\n";
	pid_t child;
	int ret;

	if (access(HDN_CONTROL_CENTER_EXEC, X_OK))
		return KSFT_SKIP;

	ret = write_created_text_file(HDN_STATUS_HELPER_FIXTURE, fixture);
	if (ret)
		return 2;

	child = fork();
	if (child < 0) {
		unlink(HDN_STATUS_HELPER_FIXTURE);
		return 2;
	}

	if (!child) {
		execl(HDN_CONTROL_CENTER_EXEC, "hdn-control-center",
		      "status", "--status-path", HDN_STATUS_HELPER_FIXTURE,
		      "--quiet", "--expect", "state=active",
		      "--expect", "mitigation_known=1",
		      "--expect", "mitigation_enabled=1", NULL);
		fprintf(stderr, "control center status exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	ret = child_exit_result(child);
	unlink(HDN_STATUS_HELPER_FIXTURE);
	return ret;
}

static int control_center_stdio_run(const char *request)
{
	int pipefd[2];
	int child_ret;
	pid_t child;
	int ret;

	if (access(HDN_CONTROL_CENTER_EXEC, X_OK))
		return KSFT_SKIP;
	if (pipe(pipefd))
		return 2;

	child = fork();
	if (child < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return 2;
	}

	if (!child) {
		close(pipefd[1]);
		if (dup2(pipefd[0], STDIN_FILENO) < 0)
			_exit(2);
		close(pipefd[0]);
		execl(HDN_CONTROL_CENTER_EXEC, "hdn-control-center",
		      "--stdio", NULL);
		fprintf(stderr, "control center stdio exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	close(pipefd[0]);
	ret = dprintf(pipefd[1], "%s\n", request);
	close(pipefd[1]);
	if (ret < 0) {
		child_ret = child_exit_result(child);
		return child_ret ? child_ret : 2;
	}

	return child_exit_result(child);
}

static int control_center_stdio_status_passes(void)
{
	return control_center_stdio_run("status");
}

static void test_securityfs_events_contains(const char *needle,
					    const char *description)
{
	if (!file_readable(HDN_EVENTS)) {
		ksft_test_result_fail("hardening events open failed: %s\n",
				      strerror(errno));
		return;
	}

	ksft_test_result(securityfs_events_contains(needle),
			 "%s\n", description);
}

static void test_securityfs_events_line_contains(const char *needle_a,
						 const char *needle_b,
						 const char *description)
{
	if (!file_readable(HDN_EVENTS)) {
		ksft_test_result_fail("hardening events open failed: %s\n",
				      strerror(errno));
		return;
	}

	ksft_test_result(securityfs_events_line_contains(needle_a, needle_b),
			 "%s\n", description);
}

static void test_sealed_write_probe_event_logged(void)
{
	const char *event_needle = "authority=0 transition=44 action=4";
	const char *reason_needle = "reason=39 error=-14";
	unsigned int before;
	int ret;

	if (!file_readable(HDN_EVENTS)) {
		ksft_test_result_fail("hardening events open failed: %s\n",
				      strerror(errno));
		return;
	}

	before = securityfs_events_count(event_needle);
	ret = write_text_file(HDN_SEALED_WRITE_PROBE, "1\n");
	if (ret) {
		ksft_test_result_fail("sealed write probe failed: %s\n",
				      strerror(-ret));
		return;
	}

	ksft_test_result(securityfs_events_count(event_needle) > before &&
			 securityfs_events_line_contains(event_needle,
							 reason_needle),
			 "hardening events report sealed data write fault\n");
}

static int kernel_lockout_probe_blocks_uid(void)
{
	const char *lockout_event =
		"authority=0 transition=89 action=3 reason=55";
	const char *deny_event =
		"authority=0 transition=2 action=4 reason=55";
	char uid_buf[32];
	unsigned int before_lockouts;
	unsigned int before_denials;
	int pipefd[2];
	int status;
	pid_t child;
	char ready;
	int ret;

	if (pipe(pipefd))
		return 2;

	before_lockouts = securityfs_events_line_count(lockout_event,
						      "error=0");
	before_denials = securityfs_events_line_count(deny_event, "error=-1");

	child = fork();
	if (child < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return 2;
	}

	if (!child) {
		close(pipefd[0]);
		if (setgid(HDN_LOCKOUT_TEST_UID) ||
		    setuid(HDN_LOCKOUT_TEST_UID))
			_exit(2);
		if (write(pipefd[1], "x", 1) != 1)
			_exit(2);
		close(pipefd[1]);
		for (;;)
			pause();
	}

	close(pipefd[1]);
	ret = read(pipefd[0], &ready, sizeof(ready));
	close(pipefd[0]);
	if (ret != 1) {
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		return 2;
	}

	snprintf(uid_buf, sizeof(uid_buf), "%u\n", HDN_LOCKOUT_TEST_UID);
	ret = write_text_file(HDN_KERNEL_LOCKOUT_PROBE, uid_buf);
	if (ret) {
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		return 2;
	}

	if (waitpid(child, &status, 0) < 0)
		return 2;
	if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL)
		return 1;

	if (securityfs_events_line_count(lockout_event, "error=0") <=
	    before_lockouts)
		return 1;
	if (!securityfs_status_has_line("kernel_lockout_banned_uids: 1"))
		return 1;

	child = fork();
	if (child < 0)
		return 2;
	if (!child) {
		if (setgid(HDN_LOCKOUT_TEST_UID))
			_exit(2);
		errno = 0;
		if (setuid(HDN_LOCKOUT_TEST_UID) < 0 && errno == EPERM)
			_exit(0);
		_exit(1);
	}

	if (waitpid(child, &status, 0) < 0)
		return 2;
	if (!((WIFEXITED(status) && WEXITSTATUS(status) == 0) ||
	      (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)))
		return 1;

	return securityfs_events_line_count(deny_event, "error=-1") >
	       before_denials ? 0 : 1;
}

static bool securityfs_events_contains_timeout(const char *needle,
					       unsigned int timeout_ms)
{
	unsigned int waited_ms = 0;

	do {
		if (securityfs_events_contains(needle))
			return true;
		usleep(100000);
		waited_ms += 100;
	} while (waited_ms < timeout_ms);

	return securityfs_events_contains(needle);
}

static bool securityfs_events_line_contains_timeout(const char *needle_a,
						    const char *needle_b,
						    unsigned int timeout_ms)
{
	unsigned int waited_ms = 0;

	do {
		if (securityfs_events_line_contains(needle_a, needle_b))
			return true;
		usleep(100000);
		waited_ms += 100;
	} while (waited_ms < timeout_ms);

	return securityfs_events_line_contains(needle_a, needle_b);
}

static void test_securityfs_phase(void)
{
	ksft_test_result(file_readable(HDN_PHASE),
			 "hardening phase is readable\n");
}

static void test_securityfs_commit(void)
{
	ksft_test_result(!access(HDN_COMMIT, F_OK),
			 "hardening policy commit endpoint exists\n");
}

static void test_securityfs_refresh(void)
{
	ksft_test_result(!access(HDN_REFRESH, F_OK),
			 "hardening policy refresh endpoint exists\n");
}

static int read_whole_file(const char *path, unsigned char **buf,
			   size_t *size)
{
	const size_t max_size = 2 * 1024 * 1024;
	struct stat st;
	unsigned char *data;
	bool stream;
	size_t capacity;
	size_t offset = 0;
	int fd;
	int ret = 0;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st)) {
		ret = -errno;
		goto out_close;
	}
	if (st.st_size > (off_t)max_size) {
		ret = -EINVAL;
		goto out_close;
	}

	stream = st.st_size == 0;
	capacity = st.st_size > 0 ? (size_t)st.st_size : 4096;
	data = malloc(capacity);
	if (!data) {
		ret = -ENOMEM;
		goto out_close;
	}

	for (;;) {
		ssize_t len;

		if (offset == capacity) {
			unsigned char *grown;
			size_t new_capacity;

			if (capacity == max_size) {
				ret = -EFBIG;
				goto out_free;
			}
			new_capacity = capacity > max_size / 2 ? max_size :
							       capacity * 2;
			grown = realloc(data, new_capacity);
			if (!grown) {
				ret = -ENOMEM;
				goto out_free;
			}
			data = grown;
			capacity = new_capacity;
		}

		len = read(fd, data + offset, capacity - offset);
		if (len < 0) {
			ret = -errno;
			goto out_free;
		}
		if (!len && !stream && offset != (size_t)st.st_size) {
			ret = -EIO;
			goto out_free;
		}
		if (!len)
			break;
		offset += len;
		if (!stream && offset == (size_t)st.st_size)
			break;
	}
	if (!offset) {
		ret = -EINVAL;
		goto out_free;
	}

	*buf = data;
	*size = offset;
	goto out_close;

out_free:
	free(data);
out_close:
	close(fd);
	return ret;
}

static int write_blob_file(const char *path, const unsigned char *buf,
			   size_t size)
{
	int fd;
	ssize_t len;
	int ret = 0;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	len = write(fd, buf, size);
	if (len < 0)
		ret = -errno;
	else if ((size_t)len != size)
		ret = -EIO;

	close(fd);
	return ret;
}

static int write_text_file(const char *path, const char *text)
{
	return write_blob_file(path, (const unsigned char *)text, strlen(text));
}

static int read_text_file_small(const char *path, char *buf, size_t size)
{
	int fd;
	ssize_t len;

	if (!size)
		return -EINVAL;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	len = read(fd, buf, size - 1);
	close(fd);
	if (len < 0)
		return -errno;
	if (!len)
		return -EIO;

	buf[len] = '\0';
	return 0;
}

static bool hdn_is_modprobe_invocation(int argc, char **argv)
{
	const char *name;

	if (argc < 4 || !argv[0] || !argv[1] || !argv[2] || !argv[3])
		return false;

	name = strrchr(argv[0], '/');
	name = name ? name + 1 : argv[0];

	return !strcmp(name, "modprobe") &&
	       !strcmp(argv[1], "-q") &&
	       !strcmp(argv[2], "--");
}

static int hdn_modprobe_capture_main(int argc, char **argv)
{
	const char *request = getenv("HDN_MODULE_REQUEST");
	const char *uid = getenv("HDN_MODULE_UID");
	const char *euid = getenv("HDN_MODULE_EUID");
	const char *profile = getenv("HDN_MODULE_PROFILE");
	int fd;

	fd = open(HDN_MODPROBE_CONTEXT_CAPTURE,
		  O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return 125;

	dprintf(fd, "argc=%d\n", argc);
	dprintf(fd, "argv1=%s\n", argv[1]);
	dprintf(fd, "argv2=%s\n", argv[2]);
	dprintf(fd, "argv3=%s\n", argv[3]);
	dprintf(fd, "HDN_MODULE_REQUEST=%s\n", request ? request : "");
	dprintf(fd, "HDN_MODULE_UID=%s\n", uid ? uid : "");
	dprintf(fd, "HDN_MODULE_EUID=%s\n", euid ? euid : "");
	dprintf(fd, "HDN_MODULE_PROFILE=%s\n", profile ? profile : "");
	close(fd);

	return 1;
}

static int directory_entry_count(const char *path, unsigned int *count)
{
	struct dirent *de;
	DIR *dir;

	dir = opendir(path);
	if (!dir)
		return -errno;

	*count = 0;
	while ((de = readdir(dir))) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		(*count)++;
	}

	closedir(dir);
	return 0;
}

static int read_fd_once(int fd)
{
	char buf[64];
	ssize_t len;

	len = read(fd, buf, sizeof(buf));
	if (len < 0)
		return -errno;
	return len > 0 ? 0 : -EIO;
}

static int read_text_file_once(const char *path)
{
	int fd;
	int ret;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	ret = read_fd_once(fd);
	close(fd);
	return ret;
}

static int object_protected_write_denied(void)
{
	int ret = write_text_file(HDN_OBJECT_WRITE_PROTECTED, "denied\n");

	if (!ret)
		return 1;
	if (errno_is_denial(-ret))
		return 0;
	return 2;
}

static int object_unprotected_write_allowed(void)
{
	return write_text_file(HDN_OBJECT_WRITE_UNPROTECTED, "allowed\n") ? 2 : 0;
}

static int object_create_text_file(const char *path)
{
	int fd;
	ssize_t len;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return -errno;

	len = write(fd, "truncate fixture\n", strlen("truncate fixture\n"));
	close(fd);
	if (len < 0)
		return -errno;
	return len == (ssize_t)strlen("truncate fixture\n") ? 0 : -EIO;
}

static int object_protected_truncate_denied(void)
{
	int saved_errno;

	errno = 0;
	if (!truncate(HDN_OBJECT_WRITE_PROTECTED, 0))
		return 1;
	saved_errno = errno;

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_unmatched_truncate_allowed(void)
{
	int ret;

	ret = object_create_text_file(HDN_OBJECT_WRITE_UNMATCHED_TRUNCATE);
	if (ret)
		return 2;
	ret = truncate(HDN_OBJECT_WRITE_UNMATCHED_TRUNCATE, 0);
	unlink(HDN_OBJECT_WRITE_UNMATCHED_TRUNCATE);
	return ret ? 2 : 0;
}

static int object_preopened_ftruncate_denied(int fd)
{
	int saved_errno;

	if (fd < 0)
		return 2;

	errno = 0;
	if (!ftruncate(fd, 0))
		return 1;
	saved_errno = errno;

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_unmatched_ftruncate_allowed(void)
{
	int fd;
	int ret;

	ret = object_create_text_file(HDN_OBJECT_WRITE_UNMATCHED_FTRUNCATE);
	if (ret)
		return 2;
	fd = open(HDN_OBJECT_WRITE_UNMATCHED_FTRUNCATE,
		  O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		unlink(HDN_OBJECT_WRITE_UNMATCHED_FTRUNCATE);
		return 2;
	}

	ret = ftruncate(fd, 0);
	close(fd);
	unlink(HDN_OBJECT_WRITE_UNMATCHED_FTRUNCATE);
	return ret ? 2 : 0;
}

static int object_preopened_fallocate_write_denied(int fd)
{
	int saved_errno;
	int ret;

	if (fd < 0)
		return 2;

	errno = 0;
	ret = fallocate(fd, 0, 0, 4096);
	saved_errno = errno;
	if (!ret)
		return 1;

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_truncate_write_allowed(void)
{
	return write_text_file(HDN_OBJECT_TRUNCATE_PROTECTED,
			       "truncate policy allows writes\n") ? 2 : 0;
}

static int object_truncate_path_denied(void)
{
	int saved_errno;

	errno = 0;
	if (!truncate(HDN_OBJECT_TRUNCATE_PROTECTED, 0))
		return 1;
	saved_errno = errno;

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_truncate_unmatched_allowed(void)
{
	if (write_text_file(HDN_OBJECT_TRUNCATE_UNPROTECTED,
			    "unmatched truncate policy target\n"))
		return 2;
	return truncate(HDN_OBJECT_TRUNCATE_UNPROTECTED, 0) ? 2 : 0;
}

static int object_rename_denied(void)
{
	int saved_errno;

	unlink(HDN_OBJECT_RENAME_TARGET);
	errno = 0;
	if (!rename(HDN_OBJECT_RENAME_PROTECTED, HDN_OBJECT_RENAME_TARGET)) {
		rename(HDN_OBJECT_RENAME_TARGET, HDN_OBJECT_RENAME_PROTECTED);
		return 1;
	}
	saved_errno = errno;

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_rename_unmatched_allowed(void)
{
	unlink(HDN_OBJECT_RENAME_UNPROTECTED_TARGET);
	if (write_text_file(HDN_OBJECT_RENAME_UNPROTECTED,
			    "unmatched rename policy target\n"))
		return 2;
	if (rename(HDN_OBJECT_RENAME_UNPROTECTED,
		   HDN_OBJECT_RENAME_UNPROTECTED_TARGET))
		return 2;
	if (rename(HDN_OBJECT_RENAME_UNPROTECTED_TARGET,
		   HDN_OBJECT_RENAME_UNPROTECTED))
		return 2;

	return 0;
}

static int object_rename_target_denied(void)
{
	int ret;

	unlink(HDN_OBJECT_RENAME_TARGET_SOURCE);
	unlink(HDN_OBJECT_RENAME_TARGET_PROTECTED_PATH);
	ret = write_created_text_file(HDN_OBJECT_RENAME_TARGET_SOURCE,
				      "rename target source\n");
	if (ret) {
		ksft_print_msg("rename-target source create failed: %d\n",
			       ret);
		return 2;
	}

	errno = 0;
	if (!rename(HDN_OBJECT_RENAME_TARGET_SOURCE,
		    HDN_OBJECT_RENAME_TARGET_PROTECTED_PATH)) {
		unlink(HDN_OBJECT_RENAME_TARGET_PROTECTED_PATH);
		ksft_print_msg("rename-target policy unexpectedly allowed rename\n");
		return 1;
	}

	ret = errno_is_denial(errno) ? 0 : 2;
	if (ret)
		ksft_print_msg("rename-target denial errno was %d\n", errno);
	unlink(HDN_OBJECT_RENAME_TARGET_SOURCE);
	return ret;
}

static int object_rename_target_create_allowed(void)
{
	int ret;

	unlink(HDN_OBJECT_RENAME_TARGET_CREATE_PATH);
	ret = write_created_text_file(HDN_OBJECT_RENAME_TARGET_CREATE_PATH,
				      "ordinary create under rename-target policy\n");
	if (ret) {
		ksft_print_msg("rename-target ordinary create failed: %d\n",
			       ret);
		return 2;
	}
	if (unlink(HDN_OBJECT_RENAME_TARGET_CREATE_PATH))
		return 2;

	return 0;
}

static int unix_sockaddr_path(const char *path, struct sockaddr_un *addr,
			      socklen_t *addrlen)
{
	size_t len = strlen(path);

	if (len >= sizeof(addr->sun_path))
		return -ENAMETOOLONG;

	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	memcpy(addr->sun_path, path, len + 1);
	*addrlen = offsetof(struct sockaddr_un, sun_path) + len + 1;
	return 0;
}

static int unix_sockaddr_abstract(const char *name, struct sockaddr_un *addr,
				  socklen_t *addrlen)
{
	size_t len = strlen(name);

	if (!len || len + 1 > sizeof(addr->sun_path))
		return -ENAMETOOLONG;

	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	memcpy(addr->sun_path + 1, name, len);
	*addrlen = offsetof(struct sockaddr_un, sun_path) + 1 + len;
	return 0;
}

static int setup_object_unix_abstract_socket(const char *name, int type,
					     int *server_fd,
					     bool start_listening)
{
	struct sockaddr_un addr;
	socklen_t addrlen;
	int fd;
	int ret;

	*server_fd = -1;
	ret = unix_sockaddr_abstract(name, &addr, &addrlen);
	if (ret)
		return ret;

	fd = socket(AF_UNIX, type | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	if (bind(fd, (struct sockaddr *)&addr, addrlen)) {
		ret = -errno;
		close(fd);
		return ret;
	}
	if (start_listening && listen(fd, 4)) {
		ret = -errno;
		close(fd);
		return ret;
	}

	*server_fd = fd;
	return 0;
}

static int setup_object_unix_socket(const char *path, int *server_fd,
				    bool start_listening)
{
	struct sockaddr_un addr;
	socklen_t addrlen;
	int fd;
	int ret;

	*server_fd = -1;
	ret = unix_sockaddr_path(path, &addr, &addrlen);
	if (ret)
		return ret;

	unlink(path);
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	if (bind(fd, (struct sockaddr *)&addr, addrlen)) {
		ret = -errno;
		close(fd);
		unlink(path);
		return ret;
	}
	if (start_listening && listen(fd, 4)) {
		ret = -errno;
		close(fd);
		unlink(path);
		return ret;
	}

	*server_fd = fd;
	return 0;
}

static int setup_object_unix_connect_socket(const char *path, int *server_fd)
{
	return setup_object_unix_socket(path, server_fd, true);
}

static int setup_object_unix_connect_fixtures(int *protected_fd,
					      int *unprotected_fd)
{
	int ret;

	ret = setup_object_unix_connect_socket(
		HDN_OBJECT_UNIX_CONNECT_PROTECTED, protected_fd);
	if (ret)
		return ret;

	ret = setup_object_unix_connect_socket(
		HDN_OBJECT_UNIX_CONNECT_UNPROTECTED, unprotected_fd);
	if (ret) {
		close(*protected_fd);
		*protected_fd = -1;
		unlink(HDN_OBJECT_UNIX_CONNECT_PROTECTED);
		return ret;
	}

	return 0;
}

static int setup_object_unix_listen_fixtures(int *protected_fd,
					     int *unprotected_fd)
{
	int ret;

	ret = setup_object_unix_socket(HDN_OBJECT_UNIX_LISTEN_PROTECTED,
				       protected_fd, false);
	if (ret)
		return ret;

	ret = setup_object_unix_socket(HDN_OBJECT_UNIX_LISTEN_UNPROTECTED,
				       unprotected_fd, false);
	if (ret) {
		close(*protected_fd);
		*protected_fd = -1;
		unlink(HDN_OBJECT_UNIX_LISTEN_PROTECTED);
		return ret;
	}

	return 0;
}

static int setup_object_unix_accept_fixtures(int *protected_fd,
					     int *unprotected_fd)
{
	int ret;

	ret = setup_object_unix_socket(HDN_OBJECT_UNIX_ACCEPT_PROTECTED,
				       protected_fd, true);
	if (ret)
		return ret;

	ret = setup_object_unix_socket(HDN_OBJECT_UNIX_ACCEPT_UNPROTECTED,
				       unprotected_fd, true);
	if (ret) {
		close(*protected_fd);
		*protected_fd = -1;
		unlink(HDN_OBJECT_UNIX_ACCEPT_PROTECTED);
		return ret;
	}

	return 0;
}

static int setup_object_unix_dgram_socket(const char *path, int *server_fd)
{
	struct sockaddr_un addr;
	socklen_t addrlen;
	int fd;
	int ret;

	*server_fd = -1;
	ret = unix_sockaddr_path(path, &addr, &addrlen);
	if (ret)
		return ret;

	unlink(path);
	fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	if (bind(fd, (struct sockaddr *)&addr, addrlen)) {
		ret = -errno;
		close(fd);
		unlink(path);
		return ret;
	}

	*server_fd = fd;
	return 0;
}

static int setup_object_unix_send_fixtures(int *protected_fd,
					   int *unprotected_fd)
{
	int ret;

	ret = setup_object_unix_dgram_socket(HDN_OBJECT_UNIX_SEND_PROTECTED,
					     protected_fd);
	if (ret)
		return ret;

	ret = setup_object_unix_dgram_socket(HDN_OBJECT_UNIX_SEND_UNPROTECTED,
					     unprotected_fd);
	if (ret) {
		close(*protected_fd);
		*protected_fd = -1;
		unlink(HDN_OBJECT_UNIX_SEND_PROTECTED);
		return ret;
	}

	return 0;
}

static int setup_object_unix_dgram_client(const char *path, int *client_fd)
{
	struct sockaddr_un addr;
	socklen_t addrlen;
	int fd;
	int ret;

	*client_fd = -1;
	ret = unix_sockaddr_path(path, &addr, &addrlen);
	if (ret)
		return ret;

	fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	if (connect(fd, (struct sockaddr *)&addr, addrlen)) {
		ret = -errno;
		close(fd);
		return ret;
	}

	*client_fd = fd;
	return 0;
}

static int setup_object_unix_connected_send_fixtures(int *protected_fd,
						     int *unprotected_fd)
{
	int ret;

	ret = setup_object_unix_dgram_client(HDN_OBJECT_UNIX_SEND_PROTECTED,
					     protected_fd);
	if (ret)
		return ret;

	ret = setup_object_unix_dgram_client(HDN_OBJECT_UNIX_SEND_UNPROTECTED,
					     unprotected_fd);
	if (ret) {
		close(*protected_fd);
		*protected_fd = -1;
		return ret;
	}

	return 0;
}

static int setup_object_unix_recv_fixtures(int *protected_fd,
					   int *unprotected_fd)
{
	int ret;

	ret = setup_object_unix_dgram_socket(HDN_OBJECT_UNIX_RECV_PROTECTED,
					     protected_fd);
	if (ret)
		return ret;

	ret = setup_object_unix_dgram_socket(HDN_OBJECT_UNIX_RECV_UNPROTECTED,
					     unprotected_fd);
	if (ret) {
		close(*protected_fd);
		*protected_fd = -1;
		unlink(HDN_OBJECT_UNIX_RECV_PROTECTED);
		return ret;
	}

	return 0;
}

static int setup_object_unix_abstract_pair(const char *protected_name,
					   const char *unprotected_name,
					   int type, bool start_listening,
					   int *protected_fd,
					   int *unprotected_fd)
{
	int ret;

	ret = setup_object_unix_abstract_socket(protected_name, type,
						protected_fd,
						start_listening);
	if (ret)
		return ret;

	ret = setup_object_unix_abstract_socket(unprotected_name, type,
						unprotected_fd,
						start_listening);
	if (ret) {
		close(*protected_fd);
		*protected_fd = -1;
		return ret;
	}

	return 0;
}

static int setup_object_unix_abstract_connect_fixtures(int *protected_fd,
						       int *unprotected_fd)
{
	return setup_object_unix_abstract_pair(
		HDN_OBJECT_UNIX_ABSTRACT_CONNECT_PROTECTED,
		HDN_OBJECT_UNIX_ABSTRACT_CONNECT_UNPROTECTED, SOCK_STREAM,
		true, protected_fd, unprotected_fd);
}

static int setup_object_unix_abstract_listen_fixtures(int *protected_fd,
						      int *unprotected_fd)
{
	return setup_object_unix_abstract_pair(
		HDN_OBJECT_UNIX_ABSTRACT_LISTEN_PROTECTED,
		HDN_OBJECT_UNIX_ABSTRACT_LISTEN_UNPROTECTED, SOCK_STREAM,
		false, protected_fd, unprotected_fd);
}

static int setup_object_unix_abstract_accept_fixtures(int *protected_fd,
						      int *unprotected_fd)
{
	return setup_object_unix_abstract_pair(
		HDN_OBJECT_UNIX_ABSTRACT_ACCEPT_PROTECTED,
		HDN_OBJECT_UNIX_ABSTRACT_ACCEPT_UNPROTECTED, SOCK_STREAM,
		true, protected_fd, unprotected_fd);
}

static int setup_object_unix_abstract_send_fixtures(int *protected_fd,
						    int *unprotected_fd)
{
	return setup_object_unix_abstract_pair(
		HDN_OBJECT_UNIX_ABSTRACT_SEND_PROTECTED,
		HDN_OBJECT_UNIX_ABSTRACT_SEND_UNPROTECTED, SOCK_DGRAM,
		false, protected_fd, unprotected_fd);
}

static int setup_object_unix_abstract_recv_fixtures(int *protected_fd,
						    int *unprotected_fd)
{
	return setup_object_unix_abstract_pair(
		HDN_OBJECT_UNIX_ABSTRACT_RECV_PROTECTED,
		HDN_OBJECT_UNIX_ABSTRACT_RECV_UNPROTECTED, SOCK_DGRAM,
		false, protected_fd, unprotected_fd);
}

static int setup_object_unix_abstract_dgram_client(const char *name,
						   int *client_fd)
{
	struct sockaddr_un addr;
	socklen_t addrlen;
	int fd;
	int ret;

	*client_fd = -1;
	ret = unix_sockaddr_abstract(name, &addr, &addrlen);
	if (ret)
		return ret;

	fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	if (connect(fd, (struct sockaddr *)&addr, addrlen)) {
		ret = -errno;
		close(fd);
		return ret;
	}

	*client_fd = fd;
	return 0;
}

static int setup_object_unix_abstract_connected_send_fixtures(
	int *protected_fd, int *unprotected_fd)
{
	int ret;

	ret = setup_object_unix_abstract_dgram_client(
		HDN_OBJECT_UNIX_ABSTRACT_SEND_PROTECTED, protected_fd);
	if (ret)
		return ret;

	ret = setup_object_unix_abstract_dgram_client(
		HDN_OBJECT_UNIX_ABSTRACT_SEND_UNPROTECTED, unprotected_fd);
	if (ret) {
		close(*protected_fd);
		*protected_fd = -1;
		return ret;
	}

	return 0;
}

static int setup_object_unix_bind_fixtures(void)
{
	unlink(HDN_OBJECT_UNIX_BIND_PROTECTED);
	unlink(HDN_OBJECT_UNIX_BIND_UNPROTECTED);

	if (mkdir(HDN_OBJECT_UNIX_BIND_PROTECTED_DIR, 0777) && errno != EEXIST)
		return -errno;
	if (mkdir(HDN_OBJECT_UNIX_BIND_UNPROTECTED_DIR, 0777) && errno != EEXIST)
		return -errno;

	return 0;
}

static int object_unix_connect_result(const char *path, bool expect_allowed)
{
	struct sockaddr_un addr;
	socklen_t addrlen;
	int saved_errno;
	int fd;
	int ret;

	ret = unix_sockaddr_path(path, &addr, &addrlen);
	if (ret)
		return 2;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return 2;

	errno = 0;
	ret = connect(fd, (struct sockaddr *)&addr, addrlen);
	saved_errno = errno;
	close(fd);

	if (expect_allowed)
		return ret ? 2 : 0;
	if (!ret)
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_unix_connect_denied(void)
{
	return object_unix_connect_result(HDN_OBJECT_UNIX_CONNECT_PROTECTED,
					  false);
}

static int object_unix_connect_unmatched_allowed(void)
{
	return object_unix_connect_result(HDN_OBJECT_UNIX_CONNECT_UNPROTECTED,
					  true);
}

static int object_unix_bind_result(const char *path, bool expect_allowed)
{
	struct sockaddr_un addr;
	socklen_t addrlen;
	int saved_errno;
	int fd;
	int ret;

	ret = unix_sockaddr_path(path, &addr, &addrlen);
	if (ret)
		return 2;

	unlink(path);
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return 2;

	errno = 0;
	ret = bind(fd, (struct sockaddr *)&addr, addrlen);
	saved_errno = errno;
	close(fd);

	if (expect_allowed) {
		if (ret) {
			unlink(path);
			return 2;
		}
		unlink(path);
		return 0;
	}
	if (!ret) {
		unlink(path);
		return 1;
	}
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_unix_bind_denied(void)
{
	return object_unix_bind_result(HDN_OBJECT_UNIX_BIND_PROTECTED, false);
}

static int object_unix_bind_unmatched_allowed(void)
{
	return object_unix_bind_result(HDN_OBJECT_UNIX_BIND_UNPROTECTED, true);
}

static int object_unix_listen_result(int fd, bool expect_allowed)
{
	int saved_errno;
	int ret;

	if (fd < 0)
		return 2;

	errno = 0;
	ret = listen(fd, 4);
	saved_errno = errno;

	if (expect_allowed)
		return ret ? 2 : 0;
	if (!ret)
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_unix_listen_denied(int fd)
{
	return object_unix_listen_result(fd, false);
}

static int object_unix_listen_unmatched_allowed(int fd)
{
	return object_unix_listen_result(fd, true);
}

static int object_unix_accept_result(int server_fd, const char *path,
				     bool expect_allowed)
{
	struct sockaddr_un addr;
	socklen_t addrlen;
	int accepted_fd;
	int client_fd = -1;
	int saved_errno;
	int ret;

	if (server_fd < 0)
		return 2;

	if (!expect_allowed) {
		errno = 0;
		accepted_fd = accept4(server_fd, NULL, NULL,
				      SOCK_CLOEXEC | SOCK_NONBLOCK);
		saved_errno = errno;
		if (accepted_fd >= 0) {
			close(accepted_fd);
			return 1;
		}
		return errno_is_denial(saved_errno) ? 0 : 2;
	}

	ret = unix_sockaddr_path(path, &addr, &addrlen);
	if (ret)
		return 2;

	client_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (client_fd < 0)
		return 2;
	if (connect(client_fd, (struct sockaddr *)&addr, addrlen)) {
		close(client_fd);
		return 2;
	}

	accepted_fd = accept4(server_fd, NULL, NULL,
			      SOCK_CLOEXEC | SOCK_NONBLOCK);
	saved_errno = errno;
	close(client_fd);
	if (accepted_fd >= 0) {
		close(accepted_fd);
		return 0;
	}
	return saved_errno ? 2 : 1;
}

static int object_unix_accept_denied(int fd)
{
	return object_unix_accept_result(fd, HDN_OBJECT_UNIX_ACCEPT_PROTECTED,
					 false);
}

static int object_unix_accept_unmatched_allowed(int fd)
{
	return object_unix_accept_result(fd, HDN_OBJECT_UNIX_ACCEPT_UNPROTECTED,
					 true);
}

static int object_unix_send_result(const char *path, bool expect_allowed)
{
	struct sockaddr_un addr;
	socklen_t addrlen;
	int saved_errno;
	char byte = 'x';
	int fd;
	int ret;

	ret = unix_sockaddr_path(path, &addr, &addrlen);
	if (ret)
		return 2;

	fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return 2;

	errno = 0;
	ret = sendto(fd, &byte, sizeof(byte), 0, (struct sockaddr *)&addr,
		     addrlen);
	saved_errno = errno;
	close(fd);

	if (expect_allowed)
		return ret == (int)sizeof(byte) ? 0 : 2;
	if (ret == (int)sizeof(byte))
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_unix_send_denied(void)
{
	return object_unix_send_result(HDN_OBJECT_UNIX_SEND_PROTECTED, false);
}

static int object_unix_send_unmatched_allowed(void)
{
	return object_unix_send_result(HDN_OBJECT_UNIX_SEND_UNPROTECTED, true);
}

static int object_unix_connected_send_result(int fd, bool expect_allowed)
{
	int saved_errno;
	char byte = 'c';
	int ret;

	if (fd < 0)
		return 2;

	errno = 0;
	ret = send(fd, &byte, sizeof(byte), MSG_DONTWAIT);
	saved_errno = errno;

	if (expect_allowed)
		return ret == (int)sizeof(byte) ? 0 : 2;
	if (ret == (int)sizeof(byte))
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_unix_connected_send_denied(int fd)
{
	return object_unix_connected_send_result(fd, false);
}

static int object_unix_connected_send_unmatched_allowed(int fd)
{
	return object_unix_connected_send_result(fd, true);
}

static int object_unix_recv_result(int server_fd, const char *path,
				   bool expect_allowed)
{
	struct sockaddr_un addr;
	socklen_t addrlen;
	int client_fd;
	int saved_errno;
	char send_byte = 'r';
	char recv_byte = '\0';
	int ret;

	if (server_fd < 0)
		return 2;

	ret = unix_sockaddr_path(path, &addr, &addrlen);
	if (ret)
		return 2;

	client_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (client_fd < 0)
		return 2;

	ret = sendto(client_fd, &send_byte, sizeof(send_byte), 0,
		     (struct sockaddr *)&addr, addrlen);
	close(client_fd);
	if (ret != (int)sizeof(send_byte))
		return 2;

	errno = 0;
	ret = recv(server_fd, &recv_byte, sizeof(recv_byte), MSG_DONTWAIT);
	saved_errno = errno;

	if (expect_allowed)
		return ret == (int)sizeof(recv_byte) &&
			       recv_byte == send_byte ? 0 : 2;
	if (ret == (int)sizeof(recv_byte))
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_unix_recv_denied(int fd)
{
	return object_unix_recv_result(fd, HDN_OBJECT_UNIX_RECV_PROTECTED,
				       false);
}

static int object_unix_recv_unmatched_allowed(int fd)
{
	return object_unix_recv_result(fd, HDN_OBJECT_UNIX_RECV_UNPROTECTED,
				       true);
}

static int object_unix_abstract_connect_result(const char *name,
					       bool expect_allowed)
{
	struct sockaddr_un addr;
	socklen_t addrlen;
	int saved_errno;
	int fd;
	int ret;

	ret = unix_sockaddr_abstract(name, &addr, &addrlen);
	if (ret)
		return 2;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return 2;

	errno = 0;
	ret = connect(fd, (struct sockaddr *)&addr, addrlen);
	saved_errno = errno;
	close(fd);

	if (expect_allowed)
		return ret ? 2 : 0;
	if (!ret)
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_unix_abstract_connect_denied(void)
{
	return object_unix_abstract_connect_result(
		HDN_OBJECT_UNIX_ABSTRACT_CONNECT_PROTECTED, false);
}

static int object_unix_abstract_connect_unmatched_allowed(void)
{
	return object_unix_abstract_connect_result(
		HDN_OBJECT_UNIX_ABSTRACT_CONNECT_UNPROTECTED, true);
}

static int object_unix_abstract_bind_result(const char *name,
					    bool expect_allowed)
{
	struct sockaddr_un addr;
	socklen_t addrlen;
	int saved_errno;
	int fd;
	int ret;

	ret = unix_sockaddr_abstract(name, &addr, &addrlen);
	if (ret)
		return 2;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return 2;

	errno = 0;
	ret = bind(fd, (struct sockaddr *)&addr, addrlen);
	saved_errno = errno;
	close(fd);

	if (expect_allowed)
		return ret ? 2 : 0;
	if (!ret)
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_unix_abstract_bind_denied(void)
{
	return object_unix_abstract_bind_result(
		HDN_OBJECT_UNIX_ABSTRACT_BIND_PROTECTED, false);
}

static int object_unix_abstract_bind_unmatched_allowed(void)
{
	return object_unix_abstract_bind_result(
		HDN_OBJECT_UNIX_ABSTRACT_BIND_UNPROTECTED, true);
}

static int object_unix_abstract_accept_result(int server_fd, const char *name,
					      bool expect_allowed)
{
	struct sockaddr_un addr;
	socklen_t addrlen;
	int accepted_fd;
	int client_fd = -1;
	int saved_errno;
	int ret;

	if (server_fd < 0)
		return 2;

	if (!expect_allowed) {
		errno = 0;
		accepted_fd = accept4(server_fd, NULL, NULL,
				      SOCK_CLOEXEC | SOCK_NONBLOCK);
		saved_errno = errno;
		if (accepted_fd >= 0) {
			close(accepted_fd);
			return 1;
		}
		return errno_is_denial(saved_errno) ? 0 : 2;
	}

	ret = unix_sockaddr_abstract(name, &addr, &addrlen);
	if (ret)
		return 2;

	client_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (client_fd < 0)
		return 2;
	if (connect(client_fd, (struct sockaddr *)&addr, addrlen)) {
		close(client_fd);
		return 2;
	}

	accepted_fd = accept4(server_fd, NULL, NULL,
			      SOCK_CLOEXEC | SOCK_NONBLOCK);
	saved_errno = errno;
	close(client_fd);
	if (accepted_fd >= 0) {
		close(accepted_fd);
		return 0;
	}
	return saved_errno ? 2 : 1;
}

static int object_unix_abstract_accept_denied(int fd)
{
	return object_unix_abstract_accept_result(
		fd, HDN_OBJECT_UNIX_ABSTRACT_ACCEPT_PROTECTED, false);
}

static int object_unix_abstract_accept_unmatched_allowed(int fd)
{
	return object_unix_abstract_accept_result(
		fd, HDN_OBJECT_UNIX_ABSTRACT_ACCEPT_UNPROTECTED, true);
}

static int object_unix_abstract_send_result(const char *name,
					    bool expect_allowed)
{
	struct sockaddr_un addr;
	socklen_t addrlen;
	int saved_errno;
	char byte = 'a';
	int fd;
	int ret;

	ret = unix_sockaddr_abstract(name, &addr, &addrlen);
	if (ret)
		return 2;

	fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return 2;

	errno = 0;
	ret = sendto(fd, &byte, sizeof(byte), 0, (struct sockaddr *)&addr,
		     addrlen);
	saved_errno = errno;
	close(fd);

	if (expect_allowed)
		return ret == (int)sizeof(byte) ? 0 : 2;
	if (ret == (int)sizeof(byte))
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_unix_abstract_send_denied(void)
{
	return object_unix_abstract_send_result(
		HDN_OBJECT_UNIX_ABSTRACT_SEND_PROTECTED, false);
}

static int object_unix_abstract_send_unmatched_allowed(void)
{
	return object_unix_abstract_send_result(
		HDN_OBJECT_UNIX_ABSTRACT_SEND_UNPROTECTED, true);
}

static int object_unix_abstract_recv_result(int server_fd, const char *name,
					    bool expect_allowed)
{
	struct sockaddr_un addr;
	socklen_t addrlen;
	int client_fd;
	int saved_errno;
	char send_byte = 'b';
	char recv_byte = '\0';
	int ret;

	if (server_fd < 0)
		return 2;

	ret = unix_sockaddr_abstract(name, &addr, &addrlen);
	if (ret)
		return 2;

	client_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (client_fd < 0)
		return 2;

	ret = sendto(client_fd, &send_byte, sizeof(send_byte), 0,
		     (struct sockaddr *)&addr, addrlen);
	close(client_fd);
	if (ret != (int)sizeof(send_byte))
		return 2;

	errno = 0;
	ret = recv(server_fd, &recv_byte, sizeof(recv_byte), MSG_DONTWAIT);
	saved_errno = errno;

	if (expect_allowed)
		return ret == (int)sizeof(recv_byte) &&
			       recv_byte == send_byte ? 0 : 2;
	if (ret == (int)sizeof(recv_byte))
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_unix_abstract_recv_denied(int fd)
{
	return object_unix_abstract_recv_result(
		fd, HDN_OBJECT_UNIX_ABSTRACT_RECV_PROTECTED, false);
}

static int object_unix_abstract_recv_unmatched_allowed(int fd)
{
	return object_unix_abstract_recv_result(
		fd, HDN_OBJECT_UNIX_ABSTRACT_RECV_UNPROTECTED, true);
}

static int object_truncate_ftruncate_denied(int fd)
{
	int saved_errno;

	if (fd < 0)
		return 2;

	errno = 0;
	if (!ftruncate(fd, 0))
		return 1;
	saved_errno = errno;

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_truncate_fallocate_denied(int fd)
{
	int saved_errno;
	int ret;

	if (fd < 0)
		return 2;

	errno = 0;
	ret = fallocate(fd, 0, 0, 4096);
	saved_errno = errno;
	if (!ret)
		return 1;

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_stream_open_path(const char *path, int flags,
				   bool expect_denied)
{
	int saved_errno;
	int fd;

	errno = 0;
	fd = open(path, flags | O_NONBLOCK | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		close(fd);
		return expect_denied ? 1 : 0;
	}

	if (expect_denied)
		return errno_is_denial(saved_errno) ? 0 : 2;
	return 2;
}

static int object_prepare_chrdev(const char *path)
{
	struct stat st;

	if (!lstat(path, &st)) {
		return S_ISCHR(st.st_mode) ? 0 : 2;
	}
	if (errno != ENOENT)
		return 2;

	if (mknod(path, S_IFCHR | 0666, makedev(1, 3)))
		return 2;

	return chmod(path, 0666) ? 2 : 0;
}

static int object_prepare_chrdev_fixtures(void)
{
	if (object_prepare_chrdev(HDN_OBJECT_WRITE_CHRDEV_PROTECTED))
		return 2;
	if (object_prepare_chrdev(HDN_OBJECT_WRITE_CHRDEV_UNPROTECTED))
		return 2;
	if (object_prepare_chrdev(HDN_OBJECT_READ_CHRDEV_PROTECTED))
		return 2;
	if (object_prepare_chrdev(HDN_OBJECT_READ_CHRDEV_UNPROTECTED))
		return 2;

	return 0;
}

static int object_prepare_blkdev_node(const char *path, dev_t dev)
{
	struct stat st;

	if (!lstat(path, &st)) {
		if (S_ISBLK(st.st_mode) && st.st_rdev == dev)
			return chmod(path, 0666) ? 2 : 0;
		if (unlink(path))
			return 2;
	} else if (errno != ENOENT) {
		return 2;
	}

	if (mknod(path, S_IFBLK | 0666, dev))
		return 2;

	return chmod(path, 0666) ? 2 : 0;
}

static int object_configure_loop_blkdev(dev_t *dev)
{
	int backing_fd;
	int loop_fd;
	int minor;

	backing_fd = open(HDN_OBJECT_BLKDEV_BACKING,
			  O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (backing_fd < 0)
		return 2;
	if (ftruncate(backing_fd, 1024 * 1024)) {
		close(backing_fd);
		return 2;
	}

	for (minor = 0; minor < 8; minor++) {
		dev_t candidate = makedev(7, minor);

		if (object_prepare_blkdev_node(HDN_OBJECT_BLKDEV_SETUP,
					       candidate))
			continue;

		loop_fd = open(HDN_OBJECT_BLKDEV_SETUP, O_RDWR | O_CLOEXEC);
		if (loop_fd < 0)
			continue;

		if (!ioctl(loop_fd, LOOP_SET_FD, backing_fd)) {
			close(loop_fd);
			close(backing_fd);
			*dev = candidate;
			return 0;
		}

		close(loop_fd);
	}

	close(backing_fd);
	return 2;
}

static int object_prepare_blkdev_fixtures(void)
{
	dev_t dev;

	if (object_configure_loop_blkdev(&dev))
		return 2;

	if (object_prepare_blkdev_node(HDN_OBJECT_WRITE_BLKDEV_PROTECTED, dev))
		return 2;
	if (object_prepare_blkdev_node(HDN_OBJECT_WRITE_BLKDEV_UNPROTECTED,
				       dev))
		return 2;
	if (object_prepare_blkdev_node(HDN_OBJECT_READ_BLKDEV_PROTECTED, dev))
		return 2;
	if (object_prepare_blkdev_node(HDN_OBJECT_READ_BLKDEV_UNPROTECTED,
				       dev))
		return 2;

	return 0;
}

static int object_write_fifo_denied(void)
{
	return object_stream_open_path(HDN_OBJECT_WRITE_FIFO_PROTECTED, O_RDWR,
				       true);
}

static int object_write_fifo_unmatched_allowed(void)
{
	return object_stream_open_path(HDN_OBJECT_WRITE_FIFO_UNPROTECTED, O_RDWR,
				       false);
}

static int object_write_chrdev_denied(void)
{
	return object_stream_open_path(HDN_OBJECT_WRITE_CHRDEV_PROTECTED,
				       O_WRONLY, true);
}

static int object_write_chrdev_unmatched_allowed(void)
{
	return object_stream_open_path(HDN_OBJECT_WRITE_CHRDEV_UNPROTECTED,
				       O_WRONLY, false);
}

static int object_write_blkdev_denied(void)
{
	return object_stream_open_path(HDN_OBJECT_WRITE_BLKDEV_PROTECTED,
				       O_WRONLY, true);
}

static int object_write_blkdev_unmatched_allowed(void)
{
	return object_stream_open_path(HDN_OBJECT_WRITE_BLKDEV_UNPROTECTED,
				       O_WRONLY, false);
}

static int object_preopened_shared_mmap_write_denied(int fd)
{
	long page_size;
	void *mapping;
	int saved_errno;

	if (fd < 0)
		return 2;

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0)
		return 2;

	errno = 0;
	mapping = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED,
		       fd, 0);
	saved_errno = errno;
	if (mapping != MAP_FAILED) {
		munmap(mapping, page_size);
		return 1;
	}

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_preopened_shared_mprotect_write_denied(int fd)
{
	long page_size;
	void *mapping;
	int saved_errno;
	int ret;

	if (fd < 0)
		return 2;

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0)
		return 2;

	mapping = mmap(NULL, page_size, PROT_READ, MAP_SHARED, fd, 0);
	if (mapping == MAP_FAILED)
		return 2;

	errno = 0;
	ret = mprotect(mapping, page_size, PROT_READ | PROT_WRITE);
	saved_errno = errno;
	munmap(mapping, page_size);
	if (!ret)
		return 1;

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_preopened_splice_write_denied(int fd)
{
	const char text[] = "denied splice\n";
	int pipefd[2];
	int saved_errno;
	ssize_t len;

	if (fd < 0)
		return 2;
	if (pipe2(pipefd, O_CLOEXEC))
		return 2;
	if (write(pipefd[1], text, sizeof(text) - 1) !=
	    (ssize_t)(sizeof(text) - 1)) {
		close(pipefd[0]);
		close(pipefd[1]);
		return 2;
	}
	if (lseek(fd, 0, SEEK_SET) < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return 2;
	}

	errno = 0;
	len = splice(pipefd[0], NULL, fd, NULL, sizeof(text) - 1, 0);
	saved_errno = errno;
	close(pipefd[0]);
	close(pipefd[1]);
	if (len >= 0)
		return 1;

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_preopened_copy_file_range_write_denied(int fd)
{
	int64_t off_in = 0;
	int64_t off_out = 0;
	int saved_errno;
	ssize_t len;
	int src;

	if (fd < 0)
		return 2;

	src = open(HDN_OBJECT_WRITE_UNPROTECTED, O_RDONLY | O_CLOEXEC);
	if (src < 0)
		return 2;
	if (lseek(fd, 0, SEEK_SET) < 0) {
		close(src);
		return 2;
	}

	errno = 0;
	len = syscall(__NR_copy_file_range, src, &off_in, fd, &off_out,
		      (size_t)8, 0);
	saved_errno = errno;
	close(src);
	if (len >= 0)
		return 1;

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_preopened_copy_file_range_source_read_denied(int fd)
{
	int64_t off_in = 0;
	int64_t off_out = 0;
	int saved_errno;
	ssize_t len;
	int dst;

	if (fd < 0)
		return 2;

	dst = open(HDN_OBJECT_WRITE_UNPROTECTED, O_WRONLY | O_CLOEXEC);
	if (dst < 0)
		return 2;

	errno = 0;
	len = syscall(__NR_copy_file_range, fd, &off_in, dst, &off_out,
		      (size_t)8, 0);
	saved_errno = errno;
	close(dst);
	if (len >= 0)
		return 1;

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_copy_file_range_unmatched_source_read_allowed(void)
{
	int64_t off_in = 0;
	int64_t off_out = 0;
	ssize_t len;
	int src;
	int dst;

	src = open(HDN_OBJECT_READ_UNPROTECTED, O_RDONLY | O_CLOEXEC);
	if (src < 0)
		return 2;
	dst = open(HDN_OBJECT_WRITE_UNPROTECTED, O_WRONLY | O_CLOEXEC);
	if (dst < 0) {
		close(src);
		return 2;
	}

	len = syscall(__NR_copy_file_range, src, &off_in, dst, &off_out,
		      (size_t)8, 0);
	close(src);
	close(dst);
	return len > 0 ? 0 : 2;
}

static int object_preopened_splice_source_read_denied(int fd)
{
	int pipefd[2];
	int saved_errno;
	ssize_t len;

	if (fd < 0)
		return 2;
	if (pipe2(pipefd, O_CLOEXEC))
		return 2;

	errno = 0;
	len = splice(fd, NULL, pipefd[1], NULL, (size_t)8, 0);
	saved_errno = errno;
	close(pipefd[0]);
	close(pipefd[1]);
	if (len >= 0)
		return 1;

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_splice_unmatched_source_read_allowed(void)
{
	char buf[16];
	int pipefd[2];
	ssize_t len;
	int src;

	src = open(HDN_OBJECT_READ_UNPROTECTED, O_RDONLY | O_CLOEXEC);
	if (src < 0)
		return 2;
	if (pipe2(pipefd, O_CLOEXEC)) {
		close(src);
		return 2;
	}

	len = splice(src, NULL, pipefd[1], NULL, (size_t)8, 0);
	close(src);
	if (len <= 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return 2;
	}

	if (read(pipefd[0], buf, sizeof(buf)) != len) {
		close(pipefd[0]);
		close(pipefd[1]);
		return 2;
	}
	close(pipefd[0]);
	close(pipefd[1]);
	return 0;
}

static int object_preopened_sendfile_source_read_denied(int fd)
{
	off_t off = 0;
	int saved_errno;
	ssize_t len;
	int dst;

	if (fd < 0)
		return 2;

	dst = open(HDN_OBJECT_WRITE_UNPROTECTED, O_WRONLY | O_CLOEXEC);
	if (dst < 0)
		return 2;

	errno = 0;
	len = syscall(__NR_sendfile, dst, fd, &off, (size_t)8);
	saved_errno = errno;
	close(dst);
	if (len >= 0)
		return 1;

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_sendfile_unmatched_source_read_allowed(void)
{
	off_t off = 0;
	ssize_t len;
	int src;
	int dst;

	src = open(HDN_OBJECT_READ_UNPROTECTED, O_RDONLY | O_CLOEXEC);
	if (src < 0)
		return 2;
	dst = open(HDN_OBJECT_WRITE_UNPROTECTED, O_WRONLY | O_CLOEXEC);
	if (dst < 0) {
		close(src);
		return 2;
	}

	len = syscall(__NR_sendfile, dst, src, &off, (size_t)8);
	close(src);
	close(dst);
	return len > 0 ? 0 : 2;
}

static int object_preopened_sendfile_dest_write_denied(int fd)
{
	off_t off = 0;
	int saved_errno;
	ssize_t len;
	int src;

	if (fd < 0)
		return 2;

	src = open(HDN_OBJECT_WRITE_UNPROTECTED, O_RDONLY | O_CLOEXEC);
	if (src < 0)
		return 2;
	if (lseek(fd, 0, SEEK_SET) < 0) {
		close(src);
		return 2;
	}

	errno = 0;
	len = syscall(__NR_sendfile, fd, src, &off, (size_t)8);
	saved_errno = errno;
	close(src);
	if (len >= 0)
		return 1;

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_sendfile_unmatched_dest_write_allowed(void)
{
	off_t off = 0;
	ssize_t len;
	int src;
	int dst;

	src = open(HDN_OBJECT_READ_UNPROTECTED, O_RDONLY | O_CLOEXEC);
	if (src < 0)
		return 2;
	dst = open(HDN_OBJECT_WRITE_UNPROTECTED, O_WRONLY | O_CLOEXEC);
	if (dst < 0) {
		close(src);
		return 2;
	}

	len = syscall(__NR_sendfile, dst, src, &off, (size_t)8);
	close(src);
	close(dst);
	return len > 0 ? 0 : 2;
}

#if defined(__NR_io_setup) && defined(__NR_io_submit) && \
	defined(__NR_io_getevents) && defined(__NR_io_destroy)
static int hdn_legacy_aio_once(int fd, bool write_op, unsigned int rw_flags)
{
	aio_context_t ctx = 0;
	struct io_event event;
	struct iocb iocb;
	struct iocb *iocbs[1] = { &iocb };
	char buf[16] = "legacy aio\n";
	long ret;
	int result;

	ret = syscall(__NR_io_setup, 2, &ctx);
	if (ret < 0)
		return -errno;

	memset(&iocb, 0, sizeof(iocb));
	iocb.aio_data = 1;
	iocb.aio_lio_opcode = write_op ? IOCB_CMD_PWRITE : IOCB_CMD_PREAD;
	iocb.aio_fildes = fd;
	iocb.aio_buf = (uintptr_t)buf;
	iocb.aio_nbytes = write_op ? strlen(buf) : sizeof(buf);
	iocb.aio_offset = 0;
	iocb.aio_rw_flags = rw_flags;

	do {
		ret = syscall(__NR_io_submit, ctx, 1, iocbs);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		result = -errno;
		goto out_destroy;
	}
	if (ret != 1) {
		result = -EIO;
		goto out_destroy;
	}

	memset(&event, 0, sizeof(event));
	do {
		ret = syscall(__NR_io_getevents, ctx, 1, 1, &event, NULL);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0)
		result = -errno;
	else if (ret != 1)
		result = -EIO;
	else
		result = event.res;

out_destroy:
	syscall(__NR_io_destroy, ctx);
	return result;
}

static int object_preopened_legacy_aio_write_denied(int fd)
{
	int ret;

	if (fd < 0)
		return 2;

	ret = hdn_legacy_aio_once(fd, true, 0);
	if (ret >= 0)
		return 1;
	return errno_is_denial(-ret) ? 0 : 2;
}

static int object_legacy_aio_unmatched_write_allowed(void)
{
	int fd;
	int ret;

	fd = open(HDN_OBJECT_WRITE_UNPROTECTED, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return 2;

	ret = hdn_legacy_aio_once(fd, true, 0);
	close(fd);
	return ret > 0 ? 0 : 2;
}

static int object_preopened_legacy_aio_read_denied(int fd)
{
	int ret;

	if (fd < 0)
		return 2;

	ret = hdn_legacy_aio_once(fd, false, 0);
	if (ret >= 0)
		return 1;
	return errno_is_denial(-ret) ? 0 : 2;
}

static int object_legacy_aio_unmatched_read_allowed(void)
{
	int fd;
	int ret;

	fd = open(HDN_OBJECT_READ_UNPROTECTED, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 2;

	ret = hdn_legacy_aio_once(fd, false, 0);
	close(fd);
	return ret > 0 ? 0 : 2;
}

static int object_append_only_legacy_aio_write_denied(int fd)
{
	int ret;

	if (fd < 0)
		return 2;

	ret = hdn_legacy_aio_once(fd, true, 0);
	if (ret >= 0)
		return 1;
	return errno_is_denial(-ret) ? 0 : 2;
}

static int object_append_only_legacy_aio_append_allowed(int fd)
{
	int ret;

	if (fd < 0)
		return 2;

	ret = hdn_legacy_aio_once(fd, true, RWF_APPEND);
	return ret > 0 ? 0 : 2;
}
#else
static int object_preopened_legacy_aio_write_denied(int fd)
{
	(void)fd;
	return 2;
}

static int object_legacy_aio_unmatched_write_allowed(void)
{
	return 2;
}

static int object_preopened_legacy_aio_read_denied(int fd)
{
	(void)fd;
	return 2;
}

static int object_legacy_aio_unmatched_read_allowed(void)
{
	return 2;
}

static int object_append_only_legacy_aio_write_denied(int fd)
{
	(void)fd;
	return 2;
}

static int object_append_only_legacy_aio_append_allowed(int fd)
{
	(void)fd;
	return 2;
}
#endif

#if defined(__NR_io_uring_setup) && defined(__NR_io_uring_enter)
struct hdn_io_uring_ring {
	int fd;
	void *sq_ring;
	void *cq_ring;
	void *sqes;
	size_t sq_ring_size;
	size_t cq_ring_size;
	size_t sqes_size;
	unsigned int *sq_head;
	unsigned int *sq_tail;
	unsigned int *sq_ring_mask;
	unsigned int *sq_array;
	unsigned int *cq_head;
	unsigned int *cq_tail;
	unsigned int *cq_ring_mask;
	struct io_uring_cqe *cqes;
};

static void hdn_io_uring_close(struct hdn_io_uring_ring *ring)
{
	if (ring->sqes)
		munmap(ring->sqes, ring->sqes_size);
	if (ring->cq_ring && ring->cq_ring != ring->sq_ring)
		munmap(ring->cq_ring, ring->cq_ring_size);
	if (ring->sq_ring)
		munmap(ring->sq_ring, ring->sq_ring_size);
	if (ring->fd >= 0)
		close(ring->fd);
}

static int hdn_io_uring_open(struct hdn_io_uring_ring *ring)
{
	struct io_uring_params params = {};
	void *sq_ptr;
	void *cq_ptr;

	memset(ring, 0, sizeof(*ring));
	ring->fd = -1;

	ring->fd = syscall(__NR_io_uring_setup, 2, &params);
	if (ring->fd < 0)
		return -errno;

	ring->sq_ring_size = params.sq_off.array +
		params.sq_entries * sizeof(unsigned int);
	ring->cq_ring_size = params.cq_off.cqes +
		params.cq_entries * sizeof(struct io_uring_cqe);
	if (params.features & IORING_FEAT_SINGLE_MMAP) {
		if (ring->cq_ring_size > ring->sq_ring_size)
			ring->sq_ring_size = ring->cq_ring_size;
		ring->cq_ring_size = ring->sq_ring_size;
	}

	sq_ptr = mmap(NULL, ring->sq_ring_size, PROT_READ | PROT_WRITE,
		      MAP_SHARED | MAP_POPULATE, ring->fd, IORING_OFF_SQ_RING);
	if (sq_ptr == MAP_FAILED)
		goto out_errno;
	ring->sq_ring = sq_ptr;

	if (params.features & IORING_FEAT_SINGLE_MMAP) {
		cq_ptr = sq_ptr;
	} else {
		cq_ptr = mmap(NULL, ring->cq_ring_size, PROT_READ | PROT_WRITE,
			      MAP_SHARED | MAP_POPULATE, ring->fd,
			      IORING_OFF_CQ_RING);
		if (cq_ptr == MAP_FAILED)
			goto out_errno;
		ring->cq_ring = cq_ptr;
	}
	if (!ring->cq_ring)
		ring->cq_ring = cq_ptr;

	ring->sqes_size = params.sq_entries * sizeof(struct io_uring_sqe);
	ring->sqes = mmap(NULL, ring->sqes_size, PROT_READ | PROT_WRITE,
			  MAP_SHARED | MAP_POPULATE, ring->fd, IORING_OFF_SQES);
	if (ring->sqes == MAP_FAILED) {
		ring->sqes = NULL;
		goto out_errno;
	}

	ring->sq_head = sq_ptr + params.sq_off.head;
	ring->sq_tail = sq_ptr + params.sq_off.tail;
	ring->sq_ring_mask = sq_ptr + params.sq_off.ring_mask;
	ring->sq_array = sq_ptr + params.sq_off.array;
	ring->cq_head = cq_ptr + params.cq_off.head;
	ring->cq_tail = cq_ptr + params.cq_off.tail;
	ring->cq_ring_mask = cq_ptr + params.cq_off.ring_mask;
	ring->cqes = cq_ptr + params.cq_off.cqes;
	return 0;

out_errno:
	{
		int ret = -errno;

		hdn_io_uring_close(ring);
		return ret;
	}
}

static int hdn_io_uring_cqe_result(struct hdn_io_uring_ring *ring)
{
	unsigned int head;
	unsigned int tail;
	struct io_uring_cqe *cqe;
	int res;

	head = __atomic_load_n(ring->cq_head, __ATOMIC_ACQUIRE);
	tail = __atomic_load_n(ring->cq_tail, __ATOMIC_ACQUIRE);
	if (head == tail)
		return -EIO;

	cqe = &ring->cqes[head & *ring->cq_ring_mask];
	res = cqe->res;
	__atomic_store_n(ring->cq_head, head + 1, __ATOMIC_RELEASE);
	return res;
}

static int hdn_io_uring_rw_once(int fd, bool write_op, unsigned int rw_flags)
{
	struct hdn_io_uring_ring ring;
	struct io_uring_sqe *sqe;
	char buf[16] = "io_uring rw\n";
	unsigned int tail;
	unsigned int index;
	int ret;

	ret = hdn_io_uring_open(&ring);
	if (ret)
		return ret;

	if (!write_op)
		memset(buf, 0, sizeof(buf));
	tail = __atomic_load_n(ring.sq_tail, __ATOMIC_RELAXED);
	index = tail & *ring.sq_ring_mask;
	sqe = &((struct io_uring_sqe *)ring.sqes)[index];
	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = write_op ? IORING_OP_WRITE : IORING_OP_READ;
	sqe->fd = fd;
	sqe->addr = (uintptr_t)buf;
	sqe->len = write_op ? strlen(buf) : sizeof(buf);
	sqe->off = 0;
	sqe->rw_flags = rw_flags;
	sqe->user_data = 1;
	ring.sq_array[index] = index;
	__atomic_store_n(ring.sq_tail, tail + 1, __ATOMIC_RELEASE);

	do {
		ret = syscall(__NR_io_uring_enter, ring.fd, 1, 1,
			      IORING_ENTER_GETEVENTS, NULL, 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		ret = -errno;
		hdn_io_uring_close(&ring);
		return ret;
	}

	ret = hdn_io_uring_cqe_result(&ring);
	hdn_io_uring_close(&ring);
	return ret;
}

static int hdn_io_uring_read_once(int fd)
{
	return hdn_io_uring_rw_once(fd, false, 0);
}

static int hdn_io_uring_write_once(int fd, unsigned int rw_flags)
{
	return hdn_io_uring_rw_once(fd, true, rw_flags);
}

static int object_preopened_io_uring_write_denied(int fd)
{
	int ret;

	if (fd < 0)
		return 2;

	ret = hdn_io_uring_write_once(fd, 0);
	if (ret >= 0)
		return 1;
	return errno_is_denial(-ret) ? 0 : 2;
}

static int object_io_uring_unmatched_write_allowed(void)
{
	int fd;
	int ret;

	fd = open(HDN_OBJECT_WRITE_UNPROTECTED, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return 2;

	ret = hdn_io_uring_write_once(fd, 0);
	close(fd);
	return ret > 0 ? 0 : 2;
}

static int object_preopened_io_uring_read_denied(int fd)
{
	int ret;

	if (fd < 0)
		return 2;

	ret = hdn_io_uring_read_once(fd);
	if (ret >= 0)
		return 1;
	return errno_is_denial(-ret) ? 0 : 2;
}

static int object_io_uring_unmatched_read_allowed(void)
{
	int fd;
	int ret;

	fd = open(HDN_OBJECT_READ_UNPROTECTED, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 2;

	ret = hdn_io_uring_read_once(fd);
	close(fd);
	return ret > 0 ? 0 : 2;
}

static int object_append_only_io_uring_write_denied(int fd)
{
	int ret;

	if (fd < 0)
		return 2;

	ret = hdn_io_uring_write_once(fd, 0);
	if (ret >= 0)
		return 1;
	return errno_is_denial(-ret) ? 0 : 2;
}

static int object_append_only_io_uring_append_allowed(int fd)
{
	int ret;

	if (fd < 0)
		return 2;

	ret = hdn_io_uring_write_once(fd, RWF_APPEND);
	return ret > 0 ? 0 : 2;
}
#else
static int object_preopened_io_uring_write_denied(int fd)
{
	(void)fd;
	return 2;
}

static int object_io_uring_unmatched_write_allowed(void)
{
	return 2;
}

static int object_preopened_io_uring_read_denied(int fd)
{
	(void)fd;
	return 2;
}

static int object_io_uring_unmatched_read_allowed(void)
{
	return 2;
}

static int object_append_only_io_uring_write_denied(int fd)
{
	(void)fd;
	return 2;
}

static int object_append_only_io_uring_append_allowed(int fd)
{
	(void)fd;
	return 2;
}
#endif

static int object_preopened_clone_dest_write_denied(int fd)
{
	int saved_errno;
	int src;
	int ret;

	if (fd < 0)
		return 2;

	src = open(HDN_OBJECT_WRITE_UNPROTECTED, O_RDONLY | O_CLOEXEC);
	if (src < 0)
		return 2;

	errno = 0;
	ret = ioctl(fd, FICLONE, src);
	saved_errno = errno;
	close(src);
	if (!ret)
		return 1;

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_clone_range_once(int dst, int src)
{
	struct file_clone_range range = {
		.src_fd = src,
		.src_offset = 0,
		.src_length = 8,
		.dest_offset = 0,
	};

	return ioctl(dst, FICLONERANGE, &range);
}

static int object_preopened_clone_range_dest_write_denied(int fd)
{
	int saved_errno;
	int src;
	int ret;

	if (fd < 0)
		return 2;

	src = open(HDN_OBJECT_WRITE_UNPROTECTED, O_RDONLY | O_CLOEXEC);
	if (src < 0)
		return 2;

	errno = 0;
	ret = object_clone_range_once(fd, src);
	saved_errno = errno;
	close(src);
	if (!ret)
		return 1;

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_preopened_clone_source_read_denied(int fd)
{
	int saved_errno;
	int dst;
	int ret;

	if (fd < 0)
		return 2;

	dst = open(HDN_OBJECT_WRITE_UNPROTECTED, O_RDWR | O_CLOEXEC);
	if (dst < 0)
		return 2;

	errno = 0;
	ret = ioctl(dst, FICLONE, fd);
	saved_errno = errno;
	close(dst);
	if (!ret)
		return 1;

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_preopened_clone_range_source_read_denied(int fd)
{
	int saved_errno;
	int dst;
	int ret;

	if (fd < 0)
		return 2;

	dst = open(HDN_OBJECT_WRITE_UNPROTECTED, O_RDWR | O_CLOEXEC);
	if (dst < 0)
		return 2;

	errno = 0;
	ret = object_clone_range_once(dst, fd);
	saved_errno = errno;
	close(dst);
	if (!ret)
		return 1;

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_unprotected_shared_mmap_write_allowed(void)
{
	long page_size;
	char *mapping;
	int fd;

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0)
		return 2;

	fd = open(HDN_OBJECT_WRITE_UNPROTECTED, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return 2;

	mapping = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED,
		       fd, 0);
	close(fd);
	if (mapping == MAP_FAILED)
		return 2;

	mapping[0] = 'A';
	munmap(mapping, page_size);
	return 0;
}

static int object_append_only_append_allowed_path(const char *path)
{
	const char text[] = "allowed append\n";
	ssize_t len;
	int fd;

	fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC);
	if (fd < 0)
		return 2;

	len = write(fd, text, sizeof(text) - 1);
	close(fd);
	return len == (ssize_t)(sizeof(text) - 1) ? 0 : 2;
}

static int object_append_only_append_allowed(void)
{
	return object_append_only_append_allowed_path(HDN_OBJECT_APPEND_PROTECTED);
}

static int object_tree_append_only_append_allowed(void)
{
	return object_append_only_append_allowed_path(HDN_OBJECT_TREE_APPEND_FILE);
}

static int object_tree_append_only_rewrite_open_denied(void)
{
	int fd;

	errno = 0;
	fd = open(HDN_OBJECT_TREE_APPEND_FILE, O_RDWR | O_CLOEXEC);
	if (fd >= 0) {
		close(fd);
		return 1;
	}

	return errno_is_denial(errno) ? 0 : 2;
}

static int object_append_only_preopened_write_denied(int fd)
{
	const char text[] = "denied rewrite\n";
	ssize_t len;

	if (fd < 0)
		return 2;
	if (lseek(fd, 0, SEEK_SET) < 0)
		return 2;

	len = write(fd, text, sizeof(text) - 1);
	if (len >= 0)
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_append_only_truncate_denied(void)
{
	if (!truncate(HDN_OBJECT_APPEND_PROTECTED, 0))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_append_only_fallocate_denied(void)
{
	int fd;
	int ret;

	fd = open(HDN_OBJECT_APPEND_PROTECTED,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	if (fd < 0)
		return 2;

	ret = fallocate(fd, 0, 0, 4096);
	if (!ret) {
		close(fd);
		return 1;
	}

	ret = errno_is_denial(errno) ? 0 : 2;
	close(fd);
	return ret;
}

static int object_protected_read_open_denied(void)
{
	int fd;

	fd = open(HDN_OBJECT_READ_PROTECTED, O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		close(fd);
		return 1;
	}
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_preopened_read_denied(int fd)
{
	int ret;

	if (fd < 0)
		return 2;
	if (lseek(fd, 0, SEEK_SET) < 0)
		return 2;

	ret = read_fd_once(fd);
	if (!ret)
		return 1;
	if (errno_is_denial(-ret))
		return 0;
	return 2;
}

static int object_preopened_read_mmap_denied(int fd)
{
	long page_size;
	void *mapping;
	int saved_errno;

	if (fd < 0)
		return 2;

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0)
		return 2;

	errno = 0;
	mapping = mmap(NULL, page_size, PROT_READ, MAP_PRIVATE, fd, 0);
	saved_errno = errno;
	if (mapping != MAP_FAILED) {
		munmap(mapping, page_size);
		return 1;
	}

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_preopened_read_mprotect_denied(int fd)
{
	long page_size;
	void *mapping;
	int saved_errno;
	int ret;

	if (fd < 0)
		return 2;

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0)
		return 2;

	mapping = mmap(NULL, page_size, PROT_NONE, MAP_PRIVATE, fd, 0);
	if (mapping == MAP_FAILED)
		return 2;

	errno = 0;
	ret = mprotect(mapping, page_size, PROT_READ);
	saved_errno = errno;
	munmap(mapping, page_size);
	if (!ret)
		return 1;

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_unprotected_read_allowed(void)
{
	return read_text_file_once(HDN_OBJECT_READ_UNPROTECTED) ? 2 : 0;
}

static int object_read_fifo_denied(void)
{
	return object_stream_open_path(HDN_OBJECT_READ_FIFO_PROTECTED, O_RDONLY,
				       true);
}

static int object_read_fifo_unmatched_allowed(void)
{
	return object_stream_open_path(HDN_OBJECT_READ_FIFO_UNPROTECTED,
				       O_RDONLY, false);
}

static int object_read_chrdev_denied(void)
{
	return object_stream_open_path(HDN_OBJECT_READ_CHRDEV_PROTECTED,
				       O_RDONLY, true);
}

static int object_read_chrdev_unmatched_allowed(void)
{
	return object_stream_open_path(HDN_OBJECT_READ_CHRDEV_UNPROTECTED,
				       O_RDONLY, false);
}

static int object_read_blkdev_denied(void)
{
	return object_stream_open_path(HDN_OBJECT_READ_BLKDEV_PROTECTED,
				       O_RDONLY, true);
}

static int object_read_blkdev_unmatched_allowed(void)
{
	return object_stream_open_path(HDN_OBJECT_READ_BLKDEV_UNPROTECTED,
				       O_RDONLY, false);
}

static int object_unprotected_read_mmap_allowed(void)
{
	volatile char first;
	long page_size;
	char *mapping;
	int fd;

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0)
		return 2;

	fd = open(HDN_OBJECT_READ_UNPROTECTED, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 2;

	mapping = mmap(NULL, page_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (mapping == MAP_FAILED)
		return 2;

	first = mapping[0];
	(void)first;
	munmap(mapping, page_size);
	return 0;
}

static int object_unprotected_read_mprotect_allowed(void)
{
	volatile char first;
	long page_size;
	char *mapping;
	int fd;
	int ret;

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0)
		return 2;

	fd = open(HDN_OBJECT_READ_UNPROTECTED, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 2;

	mapping = mmap(NULL, page_size, PROT_NONE, MAP_PRIVATE, fd, 0);
	close(fd);
	if (mapping == MAP_FAILED)
		return 2;

	ret = mprotect(mapping, page_size, PROT_READ);
	if (ret) {
		munmap(mapping, page_size);
		return 2;
	}

	first = mapping[0];
	(void)first;
	munmap(mapping, page_size);
	return 0;
}

static int object_protected_readlink_denied(void)
{
	char buf[PATH_MAX];
	ssize_t len;

	errno = 0;
	len = readlink(HDN_OBJECT_READLINK_PROTECTED, buf, sizeof(buf));
	if (len >= 0)
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_unprotected_readlink_allowed(void)
{
	char buf[PATH_MAX];
	ssize_t len;

	errno = 0;
	len = readlink(HDN_OBJECT_READLINK_UNPROTECTED, buf, sizeof(buf));
	if (len < 0)
		return 2;
	return len > 0 ? 0 : 2;
}

static int object_protected_delete_denied(void)
{
	if (!unlink(HDN_OBJECT_DELETE_PROTECTED))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_protected_rename_denied(void)
{
	if (!rename(HDN_OBJECT_DELETE_PROTECTED,
		    HDN_OBJECT_DELETE_RENAME_TARGET))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_protected_replace_denied(void)
{
	if (!rename(HDN_OBJECT_DELETE_REPLACE_SOURCE,
		    HDN_OBJECT_DELETE_PROTECTED))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_protected_rmdir_denied(void)
{
	if (!rmdir(HDN_OBJECT_DELETE_PROTECTED_DIR))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_protected_dir_rename_denied(void)
{
	if (!rename(HDN_OBJECT_DELETE_PROTECTED_DIR,
		    HDN_OBJECT_DELETE_PROTECTED_DIR_TARGET)) {
		rename(HDN_OBJECT_DELETE_PROTECTED_DIR_TARGET,
		       HDN_OBJECT_DELETE_PROTECTED_DIR);
		return 1;
	}
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_unprotected_delete_allowed(void)
{
	return unlink(HDN_OBJECT_DELETE_UNPROTECTED) ? 2 : 0;
}

static int object_unprotected_rmdir_allowed(void)
{
	return rmdir(HDN_OBJECT_DELETE_UNPROTECTED_DIR) ? 2 : 0;
}

static int create_file_exclusive(const char *path)
{
	int fd;

	fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd < 0)
		return -errno;

	close(fd);
	return 0;
}

static int object_protected_create_file_denied(void)
{
	int ret;

	unlink(HDN_OBJECT_CREATE_PROTECTED_FILE);
	ret = create_file_exclusive(HDN_OBJECT_CREATE_PROTECTED_FILE);
	if (!ret) {
		unlink(HDN_OBJECT_CREATE_PROTECTED_FILE);
		return 1;
	}

	return errno_is_denial(-ret) || ret == -EINVAL ? 0 : 2;
}

static int object_unprotected_create_file_allowed(void)
{
	int ret;

	unlink(HDN_OBJECT_CREATE_UNPROTECTED_FILE);
	ret = create_file_exclusive(HDN_OBJECT_CREATE_UNPROTECTED_FILE);
	if (ret)
		return 2;

	return unlink(HDN_OBJECT_CREATE_UNPROTECTED_FILE) ? 2 : 0;
}

static int object_protected_tmpfile_denied(void)
{
	int fd;

	fd = open(HDN_OBJECT_CREATE_PROTECTED_DIR,
		  O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
	if (fd >= 0) {
		close(fd);
		return 1;
	}

	return errno_is_denial(errno) ? 0 : 2;
}

static int object_unprotected_tmpfile_allowed(void)
{
	int fd;

	fd = open(HDN_OBJECT_CREATE_UNPROTECTED_DIR,
		  O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
	if (fd < 0)
		return 2;

	close(fd);
	return 0;
}

static int object_protected_mkdir_denied(void)
{
	rmdir(HDN_OBJECT_CREATE_PROTECTED_DIR_CHILD);
	if (!mkdir(HDN_OBJECT_CREATE_PROTECTED_DIR_CHILD, 0700)) {
		rmdir(HDN_OBJECT_CREATE_PROTECTED_DIR_CHILD);
		return 1;
	}

	return errno_is_denial(errno) ? 0 : 2;
}

static int object_protected_symlink_denied(void)
{
	unlink(HDN_OBJECT_CREATE_PROTECTED_SYMLINK);
	if (!symlink(HDN_OBJECT_READ_UNPROTECTED,
		     HDN_OBJECT_CREATE_PROTECTED_SYMLINK)) {
		unlink(HDN_OBJECT_CREATE_PROTECTED_SYMLINK);
		return 1;
	}

	return errno_is_denial(errno) ? 0 : 2;
}

static int object_protected_fifo_denied(void)
{
	unlink(HDN_OBJECT_CREATE_PROTECTED_FIFO);
	if (!mkfifo(HDN_OBJECT_CREATE_PROTECTED_FIFO, 0600)) {
		unlink(HDN_OBJECT_CREATE_PROTECTED_FIFO);
		return 1;
	}

	return errno_is_denial(errno) ? 0 : 2;
}

static int object_unprotected_fifo_allowed(void)
{
	unlink(HDN_OBJECT_CREATE_UNPROTECTED_FIFO);
	if (mkfifo(HDN_OBJECT_CREATE_UNPROTECTED_FIFO, 0600))
		return 2;

	return unlink(HDN_OBJECT_CREATE_UNPROTECTED_FIFO) ? 2 : 0;
}

static int object_protected_chrdev_denied(void)
{
	unlink(HDN_OBJECT_CREATE_PROTECTED_CHRDEV);
	if (!mknod(HDN_OBJECT_CREATE_PROTECTED_CHRDEV, S_IFCHR | 0600,
		   makedev(1, 3))) {
		unlink(HDN_OBJECT_CREATE_PROTECTED_CHRDEV);
		return 1;
	}

	return errno_is_denial(errno) ? 0 : 2;
}

static int object_unprotected_chrdev_allowed(void)
{
	unlink(HDN_OBJECT_CREATE_UNPROTECTED_CHRDEV);
	if (mknod(HDN_OBJECT_CREATE_UNPROTECTED_CHRDEV, S_IFCHR | 0600,
		  makedev(1, 3)))
		return 2;

	return unlink(HDN_OBJECT_CREATE_UNPROTECTED_CHRDEV) ? 2 : 0;
}

static int object_protected_blkdev_denied(void)
{
	unlink(HDN_OBJECT_CREATE_PROTECTED_BLKDEV);
	if (!mknod(HDN_OBJECT_CREATE_PROTECTED_BLKDEV, S_IFBLK | 0600,
		   makedev(7, 255))) {
		unlink(HDN_OBJECT_CREATE_PROTECTED_BLKDEV);
		return 1;
	}

	return errno_is_denial(errno) ? 0 : 2;
}

static int object_unprotected_blkdev_allowed(void)
{
	unlink(HDN_OBJECT_CREATE_UNPROTECTED_BLKDEV);
	if (mknod(HDN_OBJECT_CREATE_UNPROTECTED_BLKDEV, S_IFBLK | 0600,
		  makedev(7, 255)))
		return 2;

	return unlink(HDN_OBJECT_CREATE_UNPROTECTED_BLKDEV) ? 2 : 0;
}

static int object_protected_link_denied(void)
{
	int ret;

	unlink(HDN_OBJECT_CREATE_UNPROTECTED_LINK_SOURCE);
	unlink(HDN_OBJECT_CREATE_PROTECTED_LINK);
	ret = create_file_exclusive(HDN_OBJECT_CREATE_UNPROTECTED_LINK_SOURCE);
	if (ret)
		return 2;

	if (!link(HDN_OBJECT_CREATE_UNPROTECTED_LINK_SOURCE,
		  HDN_OBJECT_CREATE_PROTECTED_LINK)) {
		unlink(HDN_OBJECT_CREATE_PROTECTED_LINK);
		unlink(HDN_OBJECT_CREATE_UNPROTECTED_LINK_SOURCE);
		return 1;
	}

	ret = errno_is_denial(errno) ? 0 : 2;
	unlink(HDN_OBJECT_CREATE_UNPROTECTED_LINK_SOURCE);
	return ret;
}

static int object_protected_link_source_denied(void)
{
	unlink(HDN_OBJECT_LINK_PROTECTED_TARGET);
	if (!link(HDN_OBJECT_LINK_PROTECTED,
		  HDN_OBJECT_LINK_PROTECTED_TARGET)) {
		unlink(HDN_OBJECT_LINK_PROTECTED_TARGET);
		return 1;
	}

	return errno_is_denial(errno) ? 0 : 2;
}

static int object_unprotected_link_source_allowed(void)
{
	int ret;

	unlink(HDN_OBJECT_LINK_UNPROTECTED_TARGET);
	ret = link(HDN_OBJECT_LINK_UNPROTECTED,
		   HDN_OBJECT_LINK_UNPROTECTED_TARGET);
	if (ret)
		return 2;

	return unlink(HDN_OBJECT_LINK_UNPROTECTED_TARGET) ? 2 : 0;
}

static int object_link_target_denied(void)
{
	int ret;

	unlink(HDN_OBJECT_LINK_TARGET_PROTECTED_PATH);
	ret = link(HDN_OBJECT_LINK_UNPROTECTED,
		   HDN_OBJECT_LINK_TARGET_PROTECTED_PATH);
	if (!ret) {
		unlink(HDN_OBJECT_LINK_TARGET_PROTECTED_PATH);
		return 1;
	}

	return errno_is_denial(errno) ? 0 : 2;
}

static int object_link_target_create_allowed(void)
{
	int ret;

	unlink(HDN_OBJECT_LINK_TARGET_CREATE_PATH);
	ret = write_created_text_file(HDN_OBJECT_LINK_TARGET_CREATE_PATH,
				      "ordinary create under link-target policy\n");
	if (ret)
		return 2;
	if (unlink(HDN_OBJECT_LINK_TARGET_CREATE_PATH))
		return 2;

	return 0;
}

static int object_creat_denied(void)
{
	int ret;

	unlink(HDN_OBJECT_CREAT_PROTECTED_FILE);
	ret = create_file_exclusive(HDN_OBJECT_CREAT_PROTECTED_FILE);
	if (!ret) {
		unlink(HDN_OBJECT_CREAT_PROTECTED_FILE);
		return 1;
	}

	return errno_is_denial(-ret) ? 0 : 2;
}

static int object_mkdir_denied(void)
{
	rmdir(HDN_OBJECT_MKDIR_PROTECTED_CHILD);
	if (!mkdir(HDN_OBJECT_MKDIR_PROTECTED_CHILD, 0700)) {
		rmdir(HDN_OBJECT_MKDIR_PROTECTED_CHILD);
		return 1;
	}

	return errno_is_denial(errno) ? 0 : 2;
}

static int object_mknod_denied(void)
{
	unlink(HDN_OBJECT_MKNOD_PROTECTED_FIFO);
	if (!mkfifo(HDN_OBJECT_MKNOD_PROTECTED_FIFO, 0600)) {
		unlink(HDN_OBJECT_MKNOD_PROTECTED_FIFO);
		return 1;
	}

	return errno_is_denial(errno) ? 0 : 2;
}

static int object_symlink_denied(void)
{
	unlink(HDN_OBJECT_SYMLINK_PROTECTED_LINK);
	if (!symlink(HDN_OBJECT_READ_UNPROTECTED,
		     HDN_OBJECT_SYMLINK_PROTECTED_LINK)) {
		unlink(HDN_OBJECT_SYMLINK_PROTECTED_LINK);
		return 1;
	}

	return errno_is_denial(errno) ? 0 : 2;
}

static int object_unlink_denied(void)
{
	if (!unlink(HDN_OBJECT_UNLINK_PROTECTED))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_rmdir_denied(void)
{
	if (!rmdir(HDN_OBJECT_RMDIR_PROTECTED_DIR))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_split_create_unmatched_allowed(void)
{
	int ret;

	unlink(HDN_OBJECT_SPLIT_CREAT_UNPROTECTED_FILE);
	rmdir(HDN_OBJECT_SPLIT_MKDIR_UNPROTECTED_CHILD);
	unlink(HDN_OBJECT_SPLIT_MKNOD_UNPROTECTED_FIFO);
	unlink(HDN_OBJECT_SPLIT_SYMLINK_UNPROTECTED_LINK);

	ret = create_file_exclusive(HDN_OBJECT_SPLIT_CREAT_UNPROTECTED_FILE);
	if (ret)
		return 2;
	if (mkdir(HDN_OBJECT_SPLIT_MKDIR_UNPROTECTED_CHILD, 0700))
		return 2;
	if (mkfifo(HDN_OBJECT_SPLIT_MKNOD_UNPROTECTED_FIFO, 0600))
		return 2;
	if (symlink(HDN_OBJECT_READ_UNPROTECTED,
		    HDN_OBJECT_SPLIT_SYMLINK_UNPROTECTED_LINK))
		return 2;

	if (unlink(HDN_OBJECT_SPLIT_CREAT_UNPROTECTED_FILE))
		return 2;
	if (rmdir(HDN_OBJECT_SPLIT_MKDIR_UNPROTECTED_CHILD))
		return 2;
	if (unlink(HDN_OBJECT_SPLIT_MKNOD_UNPROTECTED_FIFO))
		return 2;
	if (unlink(HDN_OBJECT_SPLIT_SYMLINK_UNPROTECTED_LINK))
		return 2;

	return 0;
}

static int object_split_delete_unmatched_allowed(void)
{
	if (unlink(HDN_OBJECT_SPLIT_UNLINK_UNPROTECTED))
		return 2;
	if (rmdir(HDN_OBJECT_SPLIT_RMDIR_UNPROTECTED_DIR))
		return 2;

	return 0;
}

static int object_attr_chmod_denied(void)
{
	if (!chmod(HDN_OBJECT_ATTR_PROTECTED, 0600))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_attr_chown_denied(void)
{
	if (!chown(HDN_OBJECT_ATTR_PROTECTED, 65534, 65534))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_attr_timestamp_denied(void)
{
	struct timespec times[2] = {
		{ .tv_sec = 1700000000, .tv_nsec = 0 },
		{ .tv_sec = 1700000000, .tv_nsec = 0 },
	};

	if (!utimensat(AT_FDCWD, HDN_OBJECT_ATTR_PROTECTED, times, 0))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static void init_test_file_caps(struct vfs_cap_data *caps)
{
	memset(caps, 0, sizeof(*caps));
	caps->magic_etc = VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE;
	caps->data[0].permitted = 1U << CAP_CHOWN;
}

static int setup_object_attr_xattr(void)
{
	struct vfs_cap_data caps;

	init_test_file_caps(&caps);
	if (setxattr(HDN_OBJECT_ATTR_PROTECTED, XATTR_NAME_CAPS, &caps,
		     XATTR_CAPS_SZ_2, 0))
		return -errno;

	return 0;
}

static int setup_object_xattr_file(const char *path)
{
	struct vfs_cap_data caps;

	init_test_file_caps(&caps);
	if (setxattr(path, XATTR_NAME_CAPS, &caps, XATTR_CAPS_SZ_2, 0))
		return -errno;

	return 0;
}

static int setup_object_xattr(void)
{
	int ret;

	ret = setup_object_xattr_file(HDN_OBJECT_XATTR_PROTECTED);
	if (ret)
		return ret;

	return setup_object_xattr_file(HDN_OBJECT_XATTR_UNPROTECTED);
}

static int setup_object_tree_xattr(void)
{
	int ret;

	ret = setup_object_xattr_file(HDN_OBJECT_TREE_META_REMOVEXATTR);
	if (ret)
		return ret;

	return setup_object_xattr_file(HDN_OBJECT_TREE_META_XATTR);
}

static int object_attr_setxattr_denied(void)
{
	struct vfs_cap_data caps;

	init_test_file_caps(&caps);
	if (!setxattr(HDN_OBJECT_ATTR_PROTECTED, XATTR_NAME_CAPS, &caps,
		      XATTR_CAPS_SZ_2, 0))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_attr_removexattr_denied(void)
{
	if (!removexattr(HDN_OBJECT_ATTR_PROTECTED, XATTR_NAME_CAPS))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static void cleanup_object_fileattr_fs(void)
{
	unlink(HDN_OBJECT_FILEATTR_PROTECTED);
	unlink(HDN_OBJECT_FILEATTR_UNPROTECTED);
	unlink(HDN_OBJECT_FILEGETATTR_PROTECTED);
	unlink(HDN_OBJECT_FILEGETATTR_UNPROTECTED);
	umount(HDN_OBJECT_FILEATTR_DIR);
	rmdir(HDN_OBJECT_FILEATTR_DIR);
}

static int setup_object_fileattr_fs(void)
{
	int ret;

	cleanup_object_fileattr_fs();

	if (mkdir(HDN_OBJECT_FILEATTR_DIR, 0700) && errno != EEXIST)
		return -errno;
	if (mount("none", HDN_OBJECT_FILEATTR_DIR, "tmpfs", 0, "size=16k")) {
		ret = -errno;
		rmdir(HDN_OBJECT_FILEATTR_DIR);
		return ret;
	}

	ret = create_file_exclusive(HDN_OBJECT_FILEATTR_PROTECTED);
	if (ret)
		goto out_cleanup;
	ret = create_file_exclusive(HDN_OBJECT_FILEATTR_UNPROTECTED);
	if (ret)
		goto out_cleanup;
	ret = create_file_exclusive(HDN_OBJECT_FILEGETATTR_PROTECTED);
	if (ret)
		goto out_cleanup;
	ret = create_file_exclusive(HDN_OBJECT_FILEGETATTR_UNPROTECTED);
	if (ret)
		goto out_cleanup;

	return 0;

out_cleanup:
	cleanup_object_fileattr_fs();
	return ret;
}

static int object_fileattr_setflags_result(const char *path, bool denied)
{
	unsigned int flags;
	int saved_errno;
	int result;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 2;

	if (ioctl(fd, FS_IOC_GETFLAGS, &flags)) {
		result = 2;
		goto out;
	}

	errno = 0;
	if (!ioctl(fd, FS_IOC_SETFLAGS, &flags)) {
		result = denied ? 1 : 0;
		goto out;
	}

	saved_errno = errno;
	result = denied && errno_is_denial(saved_errno) ? 0 : 2;

out:
	close(fd);
	return result;
}

static int object_attr_fileattr_denied(void)
{
	return object_fileattr_setflags_result(HDN_OBJECT_FILEATTR_PROTECTED,
					       true);
}

static int object_attr_fileattr_unmatched_allowed(void)
{
	return object_fileattr_setflags_result(HDN_OBJECT_FILEATTR_UNPROTECTED,
					       false);
}

static int object_filegetattr_result(const char *path, bool denied)
{
	unsigned int flags;
	int saved_errno;
	int result;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 2;

	errno = 0;
	if (!ioctl(fd, FS_IOC_GETFLAGS, &flags)) {
		result = denied ? 1 : 0;
		goto out;
	}

	saved_errno = errno;
	result = denied && errno_is_denial(saved_errno) ? 0 : 2;

out:
	close(fd);
	return result;
}

static int object_stat_filegetattr_denied(void)
{
	return object_filegetattr_result(HDN_OBJECT_FILEGETATTR_PROTECTED,
					 true);
}

static int object_stat_filegetattr_unmatched_allowed(void)
{
	return object_filegetattr_result(HDN_OBJECT_FILEGETATTR_UNPROTECTED,
					 false);
}

static int object_attr_unmatched_chmod_allowed(void)
{
	if (chmod(HDN_OBJECT_ATTR_UNPROTECTED, 0600))
		return 2;
	return chmod(HDN_OBJECT_ATTR_UNPROTECTED, 0644) ? 2 : 0;
}

static int object_attr_unmatched_xattr_allowed(void)
{
	struct vfs_cap_data caps;

	init_test_file_caps(&caps);
	if (setxattr(HDN_OBJECT_ATTR_UNPROTECTED, XATTR_NAME_CAPS, &caps,
		     XATTR_CAPS_SZ_2, 0))
		return 2;
	if (removexattr(HDN_OBJECT_ATTR_UNPROTECTED, XATTR_NAME_CAPS))
		return 2;

	return 0;
}

static int setup_object_split_xattr(void)
{
	return setup_object_xattr_file(HDN_OBJECT_REMOVEXATTR_PROTECTED);
}

static int object_chmod_denied(void)
{
	if (!chmod(HDN_OBJECT_CHMOD_PROTECTED, 0600))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_setid_chmod_denied(void)
{
	if (!chmod(HDN_OBJECT_SETID_PROTECTED, 04755))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_setid_chmod_ordinary_allowed(void)
{
	if (chmod(HDN_OBJECT_SETID_PROTECTED, 0600))
		return 2;
	return chmod(HDN_OBJECT_SETID_PROTECTED, 0644) ? 2 : 0;
}

static int object_setid_chmod_unmatched_allowed(void)
{
	if (chmod(HDN_OBJECT_SETID_UNPROTECTED, 04755))
		return 2;
	return chmod(HDN_OBJECT_SETID_UNPROTECTED, 0644) ? 2 : 0;
}

static int object_setid_create_path(const char *path, mode_t mode,
				    bool expect_denied)
{
	int saved_errno;
	int fd;

	unlink(path);
	fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, mode);
	saved_errno = errno;
	if (fd >= 0) {
		close(fd);
		unlink(path);
		return expect_denied ? 1 : 0;
	}

	return expect_denied && errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_setid_create_denied(void)
{
	return object_setid_create_path(HDN_OBJECT_SETID_CREATE_PROTECTED_PATH,
					04755, true);
}

static int object_setid_create_ordinary_allowed(void)
{
	return object_setid_create_path(HDN_OBJECT_SETID_CREATE_ORDINARY_PATH,
					0644, false);
}

static int object_setid_create_unmatched_allowed(void)
{
	return object_setid_create_path(HDN_OBJECT_SETID_CREATE_UNPROTECTED_PATH,
					04755, false);
}

static int object_setid_mknod_fifo(const char *path, mode_t mode,
				   bool expect_denied)
{
	int saved_errno;

	unlink(path);
	errno = 0;
	if (!mkfifo(path, mode)) {
		unlink(path);
		return expect_denied ? 1 : 0;
	}

	saved_errno = errno;
	return expect_denied && errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_setid_mknod_denied(void)
{
	return object_setid_mknod_fifo(HDN_OBJECT_SETID_MKNOD_PROTECTED_FIFO,
				       02750, true);
}

static int object_setid_mknod_ordinary_allowed(void)
{
	return object_setid_mknod_fifo(HDN_OBJECT_SETID_MKNOD_ORDINARY_FIFO,
				       0600, false);
}

static int object_chown_denied(void)
{
	if (!chown(HDN_OBJECT_CHOWN_PROTECTED, 65534, 65534))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_utime_denied(void)
{
	struct timespec times[2] = {
		{ .tv_sec = 1700000100, .tv_nsec = 0 },
		{ .tv_sec = 1700000100, .tv_nsec = 0 },
	};

	if (!utimensat(AT_FDCWD, HDN_OBJECT_UTIME_PROTECTED, times, 0))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_setxattr_denied(void)
{
	struct vfs_cap_data caps;

	init_test_file_caps(&caps);
	if (!setxattr(HDN_OBJECT_SETXATTR_PROTECTED, XATTR_NAME_CAPS, &caps,
		      XATTR_CAPS_SZ_2, 0))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_removexattr_denied(void)
{
	if (!removexattr(HDN_OBJECT_REMOVEXATTR_PROTECTED, XATTR_NAME_CAPS))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_split_attr_unmatched_allowed(void)
{
	struct timespec times[2] = {
		{ .tv_sec = 1700000100, .tv_nsec = 0 },
		{ .tv_sec = 1700000100, .tv_nsec = 0 },
	};
	struct vfs_cap_data caps;

	init_test_file_caps(&caps);
	if (chmod(HDN_OBJECT_SPLIT_ATTR_UNPROTECTED, 0600))
		return 2;
	if (utimensat(AT_FDCWD, HDN_OBJECT_SPLIT_ATTR_UNPROTECTED,
		      times, 0))
		return 2;
	if (setxattr(HDN_OBJECT_SPLIT_ATTR_UNPROTECTED, XATTR_NAME_CAPS,
		     &caps, XATTR_CAPS_SZ_2, 0))
		return 2;
	if (removexattr(HDN_OBJECT_SPLIT_ATTR_UNPROTECTED, XATTR_NAME_CAPS))
		return 2;
	if (chown(HDN_OBJECT_SPLIT_ATTR_UNPROTECTED, 65534, 65534))
		return 2;
	if (chown(HDN_OBJECT_SPLIT_ATTR_UNPROTECTED, 0, 0))
		return 2;

	return chmod(HDN_OBJECT_SPLIT_ATTR_UNPROTECTED, 0644) ? 2 : 0;
}

static int object_xattr_get_path(const char *path, bool expect_denied)
{
	char buf[XATTR_CAPS_SZ_2];
	ssize_t ret;
	int saved_errno;

	errno = 0;
	ret = getxattr(path, XATTR_NAME_CAPS, buf, sizeof(buf));
	saved_errno = errno;
	if (ret >= 0)
		return expect_denied ? 1 : 0;

	if (expect_denied)
		return errno_is_denial(saved_errno) ? 0 : 2;

	return 2;
}

static int object_xattr_list_path(const char *path, bool expect_denied)
{
	char buf[256];
	ssize_t ret;
	int saved_errno;

	errno = 0;
	ret = listxattr(path, buf, sizeof(buf));
	saved_errno = errno;
	if (ret >= 0)
		return expect_denied ? 1 : 0;

	if (expect_denied)
		return errno_is_denial(saved_errno) ? 0 : 2;

	return 2;
}

static int object_xattr_acl_get_denied(void)
{
	ssize_t ret;
	int saved_errno;

	errno = 0;
	ret = getxattr(HDN_OBJECT_XATTR_PROTECTED,
		       "system.posix_acl_access", NULL, 0);
	saved_errno = errno;
	if (ret >= 0)
		return 1;

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_xattr_get_denied(void)
{
	return object_xattr_get_path(HDN_OBJECT_XATTR_PROTECTED, true);
}

static int object_xattr_list_denied(void)
{
	return object_xattr_list_path(HDN_OBJECT_XATTR_PROTECTED, true);
}

static int object_xattr_unmatched_get_allowed(void)
{
	return object_xattr_get_path(HDN_OBJECT_XATTR_UNPROTECTED, false);
}

static int object_xattr_unmatched_list_allowed(void)
{
	return object_xattr_list_path(HDN_OBJECT_XATTR_UNPROTECTED, false);
}

static int object_access_denied(const char *path, int mode)
{
	if (!access(path, mode))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_access_allowed(const char *path, int mode)
{
	return access(path, mode) ? 2 : 0;
}

static int object_access_explicit_denied(void)
{
	return object_access_denied(HDN_OBJECT_ACCESS_PROTECTED, F_OK);
}

static int object_access_unmatched_allowed(void)
{
	return object_access_allowed(HDN_OBJECT_ACCESS_UNPROTECTED, F_OK);
}

static int object_access_read_probe_denied(void)
{
	return object_access_denied(HDN_OBJECT_READ_PROTECTED, R_OK);
}

static int object_access_write_probe_denied(void)
{
	return object_access_denied(HDN_OBJECT_WRITE_PROTECTED, W_OK);
}

static int object_access_exec_probe_denied(void)
{
	return object_access_denied(HDN_OBJECT_EXEC_PROTECTED, X_OK);
}

static int object_tree_access_denied(void)
{
	return object_access_denied(HDN_OBJECT_TREE_PROTECTED_READ, F_OK);
}

static int object_stat_denied(const char *path)
{
	struct stat st;

	if (!stat(path, &st))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_stat_allowed(const char *path)
{
	struct stat st;

	return stat(path, &st) ? 2 : 0;
}

static int object_stat_path_denied(void)
{
	return object_stat_denied(HDN_OBJECT_STAT_PROTECTED);
}

static int object_stat_preopened_denied(int fd)
{
	struct stat st;

	if (fd < 0)
		return 2;
	if (!fstat(fd, &st))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_stat_unmatched_allowed(void)
{
	return object_stat_allowed(HDN_OBJECT_STAT_UNPROTECTED);
}

static int object_tree_stat_denied(void)
{
	return object_stat_denied(HDN_OBJECT_TREE_PROTECTED_READ);
}

static int list_dir_fd_once(int fd)
{
#ifdef SYS_getdents64
	char buf[1024];
	long ret;

	ret = syscall(SYS_getdents64, fd, buf, sizeof(buf));
	if (ret < 0)
		return -errno;

	return 0;
#else
	return -ENOSYS;
#endif
}

struct hdn_linux_dirent64 {
	uint64_t d_ino;
	int64_t d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[];
};

static int dir_path_contains_name(const char *path, const char *needle,
				  bool *found)
{
#ifdef SYS_getdents64
	char buf[4096];
	int fd;
	int err = 0;

	*found = false;
	fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	for (;;) {
		long nread;
		long bpos;

		nread = syscall(SYS_getdents64, fd, buf, sizeof(buf));
		if (nread < 0) {
			err = -errno;
			break;
		}
		if (!nread)
			break;

		for (bpos = 0; bpos < nread;) {
			struct hdn_linux_dirent64 *d;

			d = (struct hdn_linux_dirent64 *)(buf + bpos);
			if (d->d_reclen < offsetof(struct hdn_linux_dirent64,
						   d_name) + 1 ||
			    bpos + d->d_reclen > nread) {
				err = -EIO;
				break;
			}
			if (!strcmp(d->d_name, needle)) {
				*found = true;
				break;
			}
			bpos += d->d_reclen;
		}
		if (err || *found)
			break;
	}

	close(fd);
	return err;
#else
	return -ENOSYS;
#endif
}

static int object_list_fd_denied(int fd)
{
	int ret;

	if (fd < 0)
		return 2;

	ret = list_dir_fd_once(fd);
	if (!ret)
		return 1;
	return errno_is_denial(-ret) ? 0 : 2;
}

static int object_list_path_denied(const char *path)
{
	int fd;
	int ret;

	fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		return 2;

	ret = object_list_fd_denied(fd);
	close(fd);
	return ret;
}

static int object_list_path_allowed(const char *path)
{
	int fd;
	int ret;

	fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		return 2;

	ret = list_dir_fd_once(fd);
	close(fd);
	return ret ? 2 : 0;
}

static int object_list_path_denied_test(void)
{
	return object_list_path_denied(HDN_OBJECT_LIST_PROTECTED_DIR);
}

static int object_list_preopened_denied(int fd)
{
	return object_list_fd_denied(fd);
}

static int object_list_unmatched_allowed(void)
{
	return object_list_path_allowed(HDN_OBJECT_LIST_UNPROTECTED_DIR);
}

static int object_tree_list_denied(void)
{
	return object_list_path_denied(HDN_OBJECT_TREE_PROTECTED_LIST);
}

static int object_find_opath_denied(const char *path)
{
	int fd;
	int saved_errno;

	errno = 0;
	fd = open(path, O_PATH | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		close(fd);
		return 1;
	}

	return saved_errno == ENOENT ? 0 : 2;
}

static int object_find_opath_allowed(void)
{
	int fd;

	fd = open(HDN_OBJECT_FIND_UNPROTECTED, O_PATH | O_CLOEXEC);
	if (fd < 0)
		return 2;

	close(fd);
	return 0;
}

static int object_find_path_denied(void)
{
	return object_find_opath_denied(HDN_OBJECT_FIND_PROTECTED);
}

static int object_find_regular_open_denied(void)
{
	int saved_errno;
	int fd;

	errno = 0;
	fd = open(HDN_OBJECT_FIND_PROTECTED, O_RDONLY | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		close(fd);
		return 1;
	}

	return saved_errno == ENOENT ? 0 : 2;
}

static int object_find_regular_open_allowed(void)
{
	int fd;

	fd = open(HDN_OBJECT_FIND_UNPROTECTED, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 2;

	close(fd);
	return 0;
}

static int object_ioctl_path(const char *path, bool expect_denied)
{
	int saved_errno;
	int available = 0;
	int ret;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 2;

	errno = 0;
	ret = ioctl(fd, FIONREAD, &available);
	saved_errno = errno;
	close(fd);

	if (expect_denied) {
		if (!ret)
			return 1;
		return errno_is_denial(saved_errno) ? 0 : 2;
	}

	if (!ret)
		return 0;
	return errno_is_denial(saved_errno) ? 2 : 0;
}

static int object_ioctl_denied(void)
{
	return object_ioctl_path(HDN_OBJECT_IOCTL_PROTECTED, true);
}

static int object_ioctl_unmatched_allowed(void)
{
	return object_ioctl_path(HDN_OBJECT_IOCTL_UNPROTECTED, false);
}

static int object_lock_path(const char *path, bool posix_lock,
			    bool expect_denied)
{
	int saved_errno;
	int ret;
	int fd;

	fd = open(path, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return 2;

	errno = 0;
	if (posix_lock) {
		struct flock lock = {
			.l_type = F_WRLCK,
			.l_whence = SEEK_SET,
			.l_start = 0,
			.l_len = 1,
		};

		ret = fcntl(fd, F_SETLK, &lock);
	} else {
		ret = flock(fd, LOCK_EX | LOCK_NB);
	}
	saved_errno = errno;

	if (expect_denied) {
		close(fd);
		if (!ret)
			return 1;
		return errno_is_denial(saved_errno) ? 0 : 2;
	}

	if (ret) {
		close(fd);
		return 2;
	}

	if (posix_lock) {
		struct flock unlock = {
			.l_type = F_UNLCK,
			.l_whence = SEEK_SET,
			.l_start = 0,
			.l_len = 1,
		};

		ret = fcntl(fd, F_SETLK, &unlock);
	} else {
		ret = flock(fd, LOCK_UN);
	}
	close(fd);
	return ret ? 2 : 0;
}

static int object_flock_denied(void)
{
	return object_lock_path(HDN_OBJECT_LOCK_PROTECTED, false, true);
}

static int object_posix_lock_denied(void)
{
	return object_lock_path(HDN_OBJECT_LOCK_PROTECTED, true, true);
}

static int object_flock_unmatched_allowed(void)
{
	return object_lock_path(HDN_OBJECT_LOCK_UNPROTECTED, false, false);
}

static int object_posix_lock_unmatched_allowed(void)
{
	return object_lock_path(HDN_OBJECT_LOCK_UNPROTECTED, true, false);
}

static int object_ofd_lock_path(const char *path, bool expect_denied)
{
	struct flock lock = {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 1,
	};
	int saved_errno;
	int ret;
	int fd;

	fd = open(path, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return 2;

	errno = 0;
	ret = fcntl(fd, F_OFD_SETLK, &lock);
	saved_errno = errno;

	if (expect_denied) {
		close(fd);
		if (!ret)
			return 1;
		return errno_is_denial(saved_errno) ? 0 : 2;
	}

	if (ret) {
		close(fd);
		return 2;
	}

	lock.l_type = F_UNLCK;
	ret = fcntl(fd, F_OFD_SETLK, &lock);
	close(fd);
	return ret ? 2 : 0;
}

static int object_ofd_lock_denied(void)
{
	return object_ofd_lock_path(HDN_OBJECT_LOCK_PROTECTED, true);
}

static int object_ofd_lock_unmatched_allowed(void)
{
	return object_ofd_lock_path(HDN_OBJECT_LOCK_UNPROTECTED, false);
}

static int object_lease_path(const char *path, bool expect_denied)
{
	int saved_errno;
	int ret;
	int fd;

	fd = open(path, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return 2;

	errno = 0;
	ret = fcntl(fd, F_SETLEASE, F_WRLCK);
	saved_errno = errno;

	if (expect_denied) {
		close(fd);
		if (!ret)
			return 1;
		return errno_is_denial(saved_errno) ? 0 : 2;
	}

	if (ret) {
		close(fd);
		return 2;
	}

	ret = fcntl(fd, F_SETLEASE, F_UNLCK);
	close(fd);
	return ret ? 2 : 0;
}

static int object_lease_denied(void)
{
	return object_lease_path(HDN_OBJECT_LOCK_PROTECTED, true);
}

static int object_lease_unmatched_allowed(void)
{
	return object_lease_path(HDN_OBJECT_LOCK_UNPROTECTED, false);
}

static int object_watch_path(const char *path, bool expect_denied)
{
	int saved_errno;
	int wd;
	int fd;

	fd = inotify_init1(IN_CLOEXEC);
	if (fd < 0)
		return 2;

	errno = 0;
	wd = inotify_add_watch(fd, path, IN_ALL_EVENTS);
	saved_errno = errno;

	if (wd >= 0) {
		inotify_rm_watch(fd, wd);
		close(fd);
		return expect_denied ? 1 : 0;
	}

	close(fd);
	if (expect_denied)
		return errno_is_denial(saved_errno) ? 0 : 2;
	return 2;
}

static int object_watch_denied(void)
{
	return object_watch_path(HDN_OBJECT_WATCH_PROTECTED, true);
}

static int object_watch_unmatched_allowed(void)
{
	return object_watch_path(HDN_OBJECT_WATCH_UNPROTECTED, false);
}

static int object_dnotify_watch_path(const char *path, bool expect_denied)
{
	int saved_errno;
	int ret;
	int fd;

#if !defined(F_NOTIFY) || !defined(DN_MODIFY) || !defined(DN_CREATE) || \
	!defined(DN_MULTISHOT)
	return 2;
#else
	fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		return 2;

	errno = 0;
	ret = fcntl(fd, F_NOTIFY, DN_MODIFY | DN_CREATE | DN_MULTISHOT);
	saved_errno = errno;

	if (!ret) {
		fcntl(fd, F_NOTIFY, 0);
		close(fd);
		return expect_denied ? 1 : 0;
	}

	close(fd);
	if (expect_denied)
		return errno_is_denial(saved_errno) ? 0 : 2;
	return 2;
#endif
}

static int object_dnotify_watch_denied(void)
{
	return object_dnotify_watch_path(HDN_OBJECT_WATCH_DIR_PROTECTED, true);
}

static int object_dnotify_watch_unmatched_allowed(void)
{
	return object_dnotify_watch_path(HDN_OBJECT_WATCH_DIR_UNPROTECTED, false);
}

static int object_fanotify_watch_path(const char *path, bool expect_denied)
{
	int saved_errno;
	int ret;
	int fd;

#if !defined(__NR_fanotify_init) || !defined(__NR_fanotify_mark) || \
	!defined(FAN_CLOEXEC) || !defined(FAN_CLASS_NOTIF) || \
	!defined(FAN_MARK_ADD) || !defined(FAN_MARK_REMOVE) || \
	!defined(FAN_MARK_ONLYDIR) || !defined(FAN_MODIFY)
	return KSFT_SKIP;
#else
	uint64_t mask = FAN_MODIFY;

	fd = syscall(__NR_fanotify_init, FAN_CLOEXEC | FAN_CLASS_NOTIF,
		     O_RDONLY);
	if (fd < 0)
		return errno == ENOSYS ? KSFT_SKIP : 2;

	errno = 0;
	ret = syscall(__NR_fanotify_mark, fd,
		      FAN_MARK_ADD | FAN_MARK_ONLYDIR, mask, AT_FDCWD, path);
	saved_errno = errno;

	if (!ret) {
		syscall(__NR_fanotify_mark, fd,
			FAN_MARK_REMOVE | FAN_MARK_ONLYDIR, mask, AT_FDCWD,
			path);
		close(fd);
		return expect_denied ? 1 : 0;
	}

	close(fd);
	if (expect_denied)
		return errno_is_denial(saved_errno) ? 0 : 2;
	return 2;
#endif
}

static int object_fanotify_watch_denied(void)
{
	return object_fanotify_watch_path(HDN_OBJECT_WATCH_DIR_PROTECTED, true);
}

static int object_fanotify_watch_unmatched_allowed(void)
{
	return object_fanotify_watch_path(HDN_OBJECT_WATCH_DIR_UNPROTECTED,
					  false);
}

static int object_find_readdir_entry_hidden(void)
{
	bool found_hidden;
	bool found_visible;
	int ret;

	ret = dir_path_contains_name(HDN_OBJECT_FIND_DIR, "hidden",
				     &found_hidden);
	if (ret == -ENOSYS)
		return KSFT_SKIP;
	if (ret)
		return 2;

	ret = dir_path_contains_name(HDN_OBJECT_FIND_DIR, "visible",
				     &found_visible);
	if (ret == -ENOSYS)
		return KSFT_SKIP;
	if (ret)
		return 2;

	return !found_hidden && found_visible ? 0 : 1;
}

static int object_find_tree_readdir_entry_hidden(void)
{
	bool found_child;
	int ret;

	ret = dir_path_contains_name(HDN_OBJECT_FIND_TREE_DIR, "child",
				     &found_child);
	if (ret == -ENOSYS)
		return KSFT_SKIP;
	if (ret)
		return 2;

	return found_child ? 1 : 0;
}

static int object_tree_find_denied(void)
{
	return object_find_opath_denied(HDN_OBJECT_TREE_PROTECTED_FIND);
}

static int object_find_handle_denied(void)
{
#ifdef __NR_name_to_handle_at
	struct {
		struct file_handle handle;
		unsigned char bytes[128];
	} fh = {};
	int saved_errno;
	int mnt_id = 0;
	long ret;

	fh.handle.handle_bytes = sizeof(fh.bytes);
	errno = 0;
	ret = syscall(__NR_name_to_handle_at, AT_FDCWD,
		      HDN_OBJECT_FIND_PROTECTED, &fh.handle, &mnt_id, 0);
	saved_errno = errno;
	if (!ret)
		return 1;

	return saved_errno == ENOENT ? 0 : 2;
#else
	return KSFT_SKIP;
#endif
}

static int object_tree_attr_denied(void)
{
	if (!chmod(HDN_OBJECT_TREE_PROTECTED_ATTR, 0600))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_tree_xattr_denied(void)
{
	struct vfs_cap_data caps;

	init_test_file_caps(&caps);
	if (!setxattr(HDN_OBJECT_TREE_PROTECTED_ATTR, XATTR_NAME_CAPS, &caps,
		      XATTR_CAPS_SZ_2, 0))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_tree_read_denied(void)
{
	int ret = read_text_file_once(HDN_OBJECT_TREE_PROTECTED_READ);

	if (!ret)
		return 1;
	if (errno_is_denial(-ret))
		return 0;
	return 2;
}

static int object_tree_write_denied(void)
{
	int ret = write_text_file(HDN_OBJECT_TREE_PROTECTED_WRITE,
				  "denied tree write\n");

	if (!ret)
		return 1;
	if (errno_is_denial(-ret))
		return 0;
	return 2;
}

static int object_tree_delete_denied(void)
{
	if (!unlink(HDN_OBJECT_TREE_PROTECTED_DELETE))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_tree_rmdir_denied(void)
{
	if (!rmdir(HDN_OBJECT_TREE_PROTECTED_DELETE_DIR))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_tree_create_denied(void)
{
	int ret;

	unlink(HDN_OBJECT_TREE_PROTECTED_CREATE);
	ret = create_file_exclusive(HDN_OBJECT_TREE_PROTECTED_CREATE);
	if (!ret) {
		unlink(HDN_OBJECT_TREE_PROTECTED_CREATE);
		return 1;
	}

	return errno_is_denial(-ret) ? 0 : 2;
}

static int object_tree_creat_denied(void)
{
	int ret;

	unlink(HDN_OBJECT_TREE_SPLIT_CREAT);
	ret = create_file_exclusive(HDN_OBJECT_TREE_SPLIT_CREAT);
	if (!ret) {
		unlink(HDN_OBJECT_TREE_SPLIT_CREAT);
		return 1;
	}

	return errno_is_denial(-ret) ? 0 : 2;
}

static int object_tree_mkdir_denied(void)
{
	rmdir(HDN_OBJECT_TREE_SPLIT_MKDIR);
	if (!mkdir(HDN_OBJECT_TREE_SPLIT_MKDIR, 0700)) {
		rmdir(HDN_OBJECT_TREE_SPLIT_MKDIR);
		return 1;
	}

	return errno_is_denial(errno) ? 0 : 2;
}

static int object_tree_mknod_denied(void)
{
	unlink(HDN_OBJECT_TREE_SPLIT_MKNOD);
	if (!mkfifo(HDN_OBJECT_TREE_SPLIT_MKNOD, 0600)) {
		unlink(HDN_OBJECT_TREE_SPLIT_MKNOD);
		return 1;
	}

	return errno_is_denial(errno) ? 0 : 2;
}

static int object_tree_symlink_denied(void)
{
	unlink(HDN_OBJECT_TREE_SPLIT_SYMLINK);
	if (!symlink(HDN_OBJECT_READ_UNPROTECTED,
		     HDN_OBJECT_TREE_SPLIT_SYMLINK)) {
		unlink(HDN_OBJECT_TREE_SPLIT_SYMLINK);
		return 1;
	}

	return errno_is_denial(errno) ? 0 : 2;
}

static int object_tree_unlink_denied(void)
{
	if (!unlink(HDN_OBJECT_TREE_SPLIT_UNLINK))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_tree_split_rmdir_denied(void)
{
	if (!rmdir(HDN_OBJECT_TREE_SPLIT_RMDIR))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_tree_unmatched_write_allowed(void)
{
	return write_text_file(HDN_OBJECT_TREE_UNPROTECTED_WRITE,
			       "allowed tree write\n") ? 2 : 0;
}

static int object_protected_rename_into_denied(void)
{
	int ret;

	unlink(HDN_OBJECT_CREATE_UNPROTECTED_RENAME_SOURCE);
	unlink(HDN_OBJECT_CREATE_PROTECTED_RENAME);
	ret = create_file_exclusive(HDN_OBJECT_CREATE_UNPROTECTED_RENAME_SOURCE);
	if (ret)
		return 2;

	if (!rename(HDN_OBJECT_CREATE_UNPROTECTED_RENAME_SOURCE,
		    HDN_OBJECT_CREATE_PROTECTED_RENAME)) {
		unlink(HDN_OBJECT_CREATE_PROTECTED_RENAME);
		return 1;
	}

	ret = errno_is_denial(errno) ? 0 : 2;
	unlink(HDN_OBJECT_CREATE_UNPROTECTED_RENAME_SOURCE);
	return ret;
}

static int object_exec_path(const char *path, bool expect_denied)
{
	int status;
	pid_t child;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(path, path, "--exec-sentinel", NULL);
		_exit(errno_is_denial(errno) ? 0 : 2);
	}

	if (waitpid(child, &status, 0) < 0)
		return 2;
	if (!WIFEXITED(status))
		return 2;

	if (expect_denied)
		return WEXITSTATUS(status) == 0 ? 0 :
		       WEXITSTATUS(status) == 42 ? 1 : 2;

	return WEXITSTATUS(status) == 42 ? 0 :
	       WEXITSTATUS(status) == 0 ? 1 : 2;
}

static int object_protected_exec_denied(void)
{
	return object_exec_path(HDN_OBJECT_EXEC_PROTECTED, true);
}

static int object_unprotected_exec_allowed(void)
{
	return object_exec_path(HDN_OBJECT_EXEC_UNPROTECTED, false);
}

static int object_protected_exec_mmap_denied(void)
{
	long page_size;
	void *mapping;
	int fd;
	int ret;

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0)
		return 2;

	fd = open(HDN_OBJECT_EXEC_PROTECTED, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 2;

	mapping = mmap(NULL, page_size, PROT_READ | PROT_EXEC,
		       MAP_PRIVATE, fd, 0);
	if (mapping != MAP_FAILED) {
		munmap(mapping, page_size);
		close(fd);
		return 1;
	}

	ret = errno_is_denial(errno) ? 0 : 2;
	close(fd);
	return ret;
}

static int object_protected_exec_mprotect_denied(void)
{
	long page_size;
	void *mapping;
	int fd;
	int ret;

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0)
		return 2;

	fd = open(HDN_OBJECT_EXEC_PROTECTED, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 2;

	mapping = mmap(NULL, page_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mapping == MAP_FAILED) {
		close(fd);
		return 2;
	}

	if (!mprotect(mapping, page_size, PROT_READ | PROT_EXEC))
		ret = 1;
	else
		ret = errno_is_denial(errno) ? 0 : 2;

	munmap(mapping, page_size);
	close(fd);
	return ret;
}

static int write_all_fd(int fd, const void *buf, size_t size)
{
	const unsigned char *pos = buf;

	while (size) {
		ssize_t len = write(fd, pos, size);

		if (len < 0)
			return -errno;
		if (!len)
			return -EIO;

		pos += len;
		size -= len;
	}

	return 0;
}

static void reset_audit_flood_buckets_for_test(void)
{
	unsigned long long burst;
	char text[32];

	if (!securityfs_status_u64("audit_flood_burst:", &burst))
		return;
	if (snprintf(text, sizeof(text), "%llu\n", burst) >=
	    (int)sizeof(text))
		return;

	(void)write_text_file(HDN_AUDIT_FLOOD_BURST_CTL, text);
}

static int write_policy_path_to(const char *endpoint, const char *policy_path)
{
	unsigned char *blob = NULL;
	size_t size = 0;
	int ret;

	ret = read_whole_file(policy_path, &blob, &size);
	if (ret)
		return ret;

	ret = write_blob_file(endpoint, blob, size);
	free(blob);
	return ret;
}

static int write_signed_policy_path(const char *policy_path)
{
	return write_policy_path_to(HDN_POLICY, policy_path);
}

static int write_signed_policy(void)
{
	return write_signed_policy_path(HDN_SIGNED_POLICY);
}

static int run_refresh_target(void)
{
	pid_t child = fork();

	if (child < 0)
		return 2;
	if (!child) {
		execl(HDN_REFRESH_TARGET, HDN_REFRESH_TARGET, NULL);
		_exit(2);
	}

	return child_exit_result(child);
}

static int replace_refresh_target(void)
{
	int ret;

	unlink(HDN_REFRESH_TARGET_NEW);
	ret = copy_file(HDN_REFRESH_TARGET, HDN_REFRESH_TARGET_NEW, 0755);
	if (ret)
		return ret;
	if (rename(HDN_REFRESH_TARGET_NEW, HDN_REFRESH_TARGET)) {
		ret = -errno;
		unlink(HDN_REFRESH_TARGET_NEW);
		return ret;
	}

	return 0;
}

static int refresh_target_denied(void)
{
	return run_refresh_target() == 1 ? 0 : 1;
}

static int broker_policy_commit_default(void)
{
	pid_t child;
	int ret;

	if (access(HDN_ADMIN_BROKER_EXEC, X_OK) ||
	    access(HDN_BROKER_SIGNED_POLICY, R_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_ADMIN_BROKER_EXEC, "hdn-admin-broker",
		      "policy-commit", HDN_BROKER_SIGNED_POLICY, NULL);
		fprintf(stderr, "policy broker commit exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	ret = child_exit_result(child);
	if (ret)
		return ret;

	return securityfs_status_has_line("policy_loaded: 1") &&
	       securityfs_status_has_line("generation: 1") ? 0 : 1;
}

static int broker_policy_rollback_to_generation0(void)
{
	pid_t child;
	int ret;

	if (access(HDN_ADMIN_BROKER_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_ADMIN_BROKER_EXEC, "hdn-admin-broker",
		      "policy-rollback", NULL);
		fprintf(stderr, "policy broker rollback exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	ret = child_exit_result(child);
	if (ret)
		return ret;

	return securityfs_status_has_line("generation: 0") ? 0 : 1;
}

static int broker_policy_unapproved_commit_denied(void)
{
	pid_t child;
	int ret;

	if (access(HDN_ADMIN_BROKER_EXEC, X_OK) ||
	    access(HDN_SIGNED_POLICY, R_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_ADMIN_BROKER_EXEC, "hdn-admin-broker",
		      "policy-commit", HDN_SIGNED_POLICY, NULL);
		fprintf(stderr, "policy broker denied-path exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	ret = child_exit_result(child);
	if (!ret)
		return 1;

	return securityfs_status_has_line("generation: 0") &&
	       securityfs_status_has_line("policy_staged: 0") ? 0 : 1;
}

static int recovery_action_run(const char *action, const char *config_path,
			       bool dry_run)
{
	pid_t child;

	if (access(HDN_RECOVERY_ACTION_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		if (config_path && dry_run)
			execl(HDN_RECOVERY_ACTION_EXEC, "hdn-recovery-action",
			      "--dry-run", "--config", config_path, action,
			      NULL);
		else if (config_path)
			execl(HDN_RECOVERY_ACTION_EXEC, "hdn-recovery-action",
			      "--config", config_path, action, NULL);
		else if (dry_run)
			execl(HDN_RECOVERY_ACTION_EXEC, "hdn-recovery-action",
			      "--dry-run", action, NULL);
		else
			execl(HDN_RECOVERY_ACTION_EXEC, "hdn-recovery-action",
			      action, NULL);
		fprintf(stderr, "recovery action exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int recovery_action_unknown_denied(void)
{
	int ret = recovery_action_run("unknown-action", NULL, false);

	if (ret == KSFT_SKIP)
		return ret;
	if (ret != 1)
		return ret ? ret : 1;

	return securityfs_status_has_line("generation: 0") &&
	       securityfs_status_has_line("policy_staged: 0") ? 0 : 1;
}

static int recovery_action_unsafe_config_denied(void)
{
	int ret = recovery_action_run("policy-rollback",
				      HDN_RECOVERY_ACTION_UNSAFE_CONFIG,
				      false);

	if (ret == KSFT_SKIP)
		return ret;
	if (ret != 1)
		return ret ? ret : 1;

	return securityfs_status_has_line("generation: 0") &&
	       securityfs_status_has_line("policy_staged: 0") ? 0 : 1;
}

static int recovery_action_policy_rollback_to_generation0(void)
{
	int ret;

	ret = broker_policy_commit_default();
	if (ret)
		return ret;

	ret = recovery_action_run("policy-rollback", NULL, true);
	if (ret) {
		(void)write_text_file(HDN_ROLLBACK, "1\n");
		return ret;
	}
	if (!securityfs_status_has_line("generation: 1")) {
		(void)write_text_file(HDN_ROLLBACK, "1\n");
		return 1;
	}

	ret = recovery_action_run("policy-rollback", NULL, false);
	if (ret) {
		(void)write_text_file(HDN_ROLLBACK, "1\n");
		return ret;
	}

	if (securityfs_status_has_line("generation: 0"))
		return 0;

	(void)write_text_file(HDN_ROLLBACK, "1\n");
	return 1;
}

static int recovery_describe_run(const char *action, const char *config_path)
{
	pid_t child;

	if (access(HDN_RECOVERY_DESCRIBE_EXEC, X_OK)) {
		fprintf(stderr,
			"recovery describe helper is not executable: %s\n",
			strerror(errno));
		return KSFT_SKIP;
	}

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		int fd;

		fd = open(HDN_RECOVERY_DESCRIBE_OUTPUT,
			  O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0600);
		if (fd < 0)
			_exit(2);
		if (dup2(fd, STDOUT_FILENO) < 0)
			_exit(2);
		close(fd);

		if (config_path)
			execl(HDN_RECOVERY_DESCRIBE_EXEC,
			      "hdn-recovery-describe", "--config",
			      config_path, action, NULL);
		else
			execl(HDN_RECOVERY_DESCRIBE_EXEC,
			      "hdn-recovery-describe", action, NULL);
		fprintf(stderr, "recovery describe exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int recovery_describe_denied(const char *action, const char *config_path,
				    const char *failure)
{
	int ret;

	unlink(HDN_RECOVERY_DESCRIBE_OUTPUT);
	ret = recovery_describe_run(action, config_path);
	if (ret == KSFT_SKIP)
		return ret;
	if (!ret) {
		fprintf(stderr, "recovery describe allowed %s\n", failure);
		return 1;
	}

	return ret == 1 ? 0 : ret;
}

static int recovery_describe_unknown_denied(void)
{
	return recovery_describe_denied("unknown-action", NULL,
					"unknown action");
}

static int recovery_describe_unsafe_config_denied(void)
{
	return recovery_describe_denied("policy-rollback",
					HDN_RECOVERY_DESCRIBE_UNSAFE_CONFIG,
					"unsafe config");
}

static bool recovery_description_has_line(const char *text, const char *line)
{
	const char *match = text;
	size_t len = strlen(line);

	while ((match = strstr(match, line))) {
		if ((match == text || match[-1] == '\n') &&
		    match[len] == '\n')
			return true;
		match += len;
	}

	return false;
}

static int recovery_describe_policy_rollback(void)
{
	unsigned char *blob = NULL;
	char *text = NULL;
	size_t size = 0;
	bool valid;
	int ret;

	unlink(HDN_RECOVERY_DESCRIBE_OUTPUT);
	ret = recovery_describe_run("policy-rollback", NULL);
	if (ret == KSFT_SKIP)
		return ret;
	if (ret) {
		fprintf(stderr, "recovery describe exited with %d\n", ret);
		return ret;
	}

	ret = read_whole_file(HDN_RECOVERY_DESCRIBE_OUTPUT, &blob, &size);
	if (ret) {
		fprintf(stderr, "recovery describe output missing: %s\n",
			strerror(-ret));
		return 1;
	}

	text = malloc(size + 1);
	if (!text) {
		free(blob);
		return 2;
	}
	memcpy(text, blob, size);
	text[size] = '\0';

	valid = recovery_description_has_line(text,
					      "HDN_RECOVERY_METADATA_V1") &&
		recovery_description_has_line(text,
					      "action=policy-rollback") &&
		recovery_description_has_line(text,
					      "title=Roll back security policy") &&
		recovery_description_has_line(text, "risk=recovery") &&
		strstr(text, "message=") &&
		strstr(text, "consequence=");

	free(text);
	free(blob);
	if (!valid) {
		fprintf(stderr,
			"recovery describe output did not contain expected metadata\n");
		return 1;
	}

	return 0;
}

static const char hdn_recovery_policy_rollback_metadata[] =
	"HDN_RECOVERY_METADATA_V1\n"
	"action=policy-rollback\n"
	"title=Roll back security policy\n"
	"message=Restore the previous signed hardening policy.\n"
	"consequence=The current policy generation is replaced by the rollback slot.\n"
	"risk=recovery\n";

static int recovery_prompt_run(const char *action, const char *mode,
			       bool clear_display)
{
	int pipefd[2];
	pid_t child;
	int status;
	int ret;

	if (access(HDN_RECOVERY_PROMPT_EXEC, X_OK)) {
		fprintf(stderr,
			"recovery prompt helper is not executable: %s\n",
			strerror(errno));
		return KSFT_SKIP;
	}

	if (pipe(pipefd))
		return 2;

	child = fork();
	if (child < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return 2;
	}

	if (!child) {
		close(pipefd[1]);
		if (dup2(pipefd[0], STDIN_FILENO) < 0)
			_exit(2);
		close(pipefd[0]);
		if (clear_display) {
			unsetenv("DISPLAY");
			unsetenv("WAYLAND_DISPLAY");
		}
		if (mode)
			execl(HDN_RECOVERY_PROMPT_EXEC, "hdn-recovery-prompt",
			      mode, action, NULL);
		else
			execl(HDN_RECOVERY_PROMPT_EXEC, "hdn-recovery-prompt",
			      action, NULL);
		fprintf(stderr, "recovery prompt exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	close(pipefd[0]);
	ret = write(pipefd[1], hdn_recovery_policy_rollback_metadata,
		    sizeof(hdn_recovery_policy_rollback_metadata) - 1);
	close(pipefd[1]);

	status = child_exit_result(child);
	if (ret != (int)sizeof(hdn_recovery_policy_rollback_metadata) - 1 &&
	    !status)
		return 2;

	return status;
}

static int recovery_prompt_test_approve(void)
{
	return recovery_prompt_run("policy-rollback", "--test-approve", false);
}

static int recovery_prompt_test_deny(void)
{
	int ret = recovery_prompt_run("policy-rollback", "--test-deny", false);

	if (ret == KSFT_SKIP)
		return ret;
	return ret == 1 ? 0 : ret ? ret : 1;
}

static int recovery_prompt_no_display_denied(void)
{
	int ret = recovery_prompt_run("policy-rollback", NULL, true);

	if (ret == KSFT_SKIP)
		return ret;
	return ret == 1 ? 0 : ret ? ret : 1;
}

static int recovery_confirm_sentinel(const char *action, bool approve)
{
	char expected[256];
	char buf[8193];
	size_t done = 0;

	for (;;) {
		ssize_t len;

		len = read(STDIN_FILENO, buf + done, sizeof(buf) - done - 1);
		if (len < 0) {
			if (errno == EINTR)
				continue;
			return 2;
		}
		if (!len)
			break;
		done += (size_t)len;
		if (done >= sizeof(buf) - 1)
			return 2;
	}
	buf[done] = '\0';

	if (!recovery_description_has_line(buf, "HDN_RECOVERY_METADATA_V1"))
		return 2;
	if (snprintf(expected, sizeof(expected), "action=%s", action) >=
	    (int)sizeof(expected))
		return 2;
	if (!recovery_description_has_line(buf, expected))
		return 2;

	return approve ? 0 : 1;
}

static int recovery_session_run(const char *action, const char *config_path,
				bool dry_run)
{
	pid_t child;

	if (access(HDN_RECOVERY_SESSION_EXEC, X_OK)) {
		fprintf(stderr,
			"recovery session helper is not executable: %s\n",
			strerror(errno));
		return KSFT_SKIP;
	}

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		if (config_path && dry_run)
			execl(HDN_RECOVERY_SESSION_EXEC,
			      "hdn-recovery-session", "--dry-run", "--config",
			      config_path, action, NULL);
		else if (config_path)
			execl(HDN_RECOVERY_SESSION_EXEC,
			      "hdn-recovery-session", "--config",
			      config_path, action, NULL);
		else if (dry_run)
			execl(HDN_RECOVERY_SESSION_EXEC,
			      "hdn-recovery-session", "--dry-run", action,
			      NULL);
		else
			execl(HDN_RECOVERY_SESSION_EXEC,
			      "hdn-recovery-session", action, NULL);
		fprintf(stderr, "recovery session exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int recovery_session_denied(const char *action, const char *config_path,
				   const char *failure)
{
	int ret = recovery_session_run(action, config_path, false);

	if (ret == KSFT_SKIP)
		return ret;
	if (!ret) {
		fprintf(stderr, "recovery session allowed %s\n", failure);
		return 1;
	}
	if (ret != 1)
		return ret;

	return securityfs_status_has_line("generation: 0") &&
	       securityfs_status_has_line("policy_staged: 0") ? 0 : 1;
}

static int recovery_session_unknown_denied(void)
{
	return recovery_session_denied("unknown-action", NULL,
				       "unknown action");
}

static int recovery_session_unsafe_config_denied(void)
{
	return recovery_session_denied("policy-rollback",
				       HDN_RECOVERY_SESSION_UNSAFE_CONFIG,
				       "unsafe config");
}

static int recovery_session_confirm_denied(void)
{
	return recovery_session_denied("policy-rollback",
				       HDN_RECOVERY_SESSION_CONFIRM_DENY_CONFIG,
				       "confirmation denial");
}

static int recovery_session_no_display_denied(void)
{
	return recovery_session_denied("policy-rollback",
				       HDN_RECOVERY_SESSION_NO_DISPLAY_CONFIG,
				       "missing graphical session");
}

static int recovery_session_policy_rollback_to_generation0(void)
{
	int ret;

	ret = broker_policy_commit_default();
	if (ret)
		return ret;

	ret = recovery_session_run("policy-rollback", NULL, true);
	if (ret) {
		(void)write_text_file(HDN_ROLLBACK, "1\n");
		return ret;
	}
	if (!securityfs_status_has_line("generation: 1")) {
		(void)write_text_file(HDN_ROLLBACK, "1\n");
		return 1;
	}

	ret = recovery_session_run("policy-rollback", NULL, false);
	if (ret) {
		(void)write_text_file(HDN_ROLLBACK, "1\n");
		return ret;
	}

	if (securityfs_status_has_line("generation: 0"))
		return 0;

	(void)write_text_file(HDN_ROLLBACK, "1\n");
	return 1;
}

static int recovery_portal_run(const char *action, const char *config_path,
			       bool dry_run)
{
	pid_t child;

	if (access(HDN_RECOVERY_PORTAL_EXEC, X_OK)) {
		fprintf(stderr,
			"recovery portal helper is not executable: %s\n",
			strerror(errno));
		return KSFT_SKIP;
	}

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		if (config_path && dry_run)
			execl(HDN_RECOVERY_PORTAL_EXEC,
			      "hdn-recovery-portal", "--dry-run", "--config",
			      config_path, action, NULL);
		else if (config_path)
			execl(HDN_RECOVERY_PORTAL_EXEC,
			      "hdn-recovery-portal", "--config",
			      config_path, action, NULL);
		else if (dry_run)
			execl(HDN_RECOVERY_PORTAL_EXEC,
			      "hdn-recovery-portal", "--dry-run", action,
			      NULL);
		else
			execl(HDN_RECOVERY_PORTAL_EXEC,
			      "hdn-recovery-portal", action, NULL);
		fprintf(stderr, "recovery portal exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int recovery_portal_denied(const char *action, const char *config_path,
				  const char *failure)
{
	int ret = recovery_portal_run(action, config_path, false);

	if (ret == KSFT_SKIP)
		return ret;
	if (!ret) {
		fprintf(stderr, "recovery portal allowed %s\n", failure);
		return 1;
	}
	if (ret != 1)
		return ret;

	return securityfs_status_has_line("generation: 0") &&
	       securityfs_status_has_line("policy_staged: 0") ? 0 : 1;
}

static int recovery_portal_unknown_denied(void)
{
	return recovery_portal_denied("unknown-recovery", NULL,
				      "unknown action");
}

static int recovery_portal_unsafe_config_denied(void)
{
	return recovery_portal_denied("rollback-policy",
				      HDN_RECOVERY_PORTAL_UNSAFE_CONFIG,
				      "unsafe config");
}

static int recovery_portal_policy_rollback_to_generation0(void)
{
	int ret;

	ret = broker_policy_commit_default();
	if (ret)
		return ret;

	ret = recovery_portal_run("rollback-policy", NULL, true);
	if (ret) {
		(void)write_text_file(HDN_ROLLBACK, "1\n");
		return ret;
	}
	if (!securityfs_status_has_line("generation: 1")) {
		(void)write_text_file(HDN_ROLLBACK, "1\n");
		return 1;
	}

	ret = recovery_portal_run("rollback-policy", NULL, false);
	if (ret) {
		(void)write_text_file(HDN_ROLLBACK, "1\n");
		return ret;
	}

	if (securityfs_status_has_line("generation: 0"))
		return 0;

	(void)write_text_file(HDN_ROLLBACK, "1\n");
	return 1;
}

static int recovery_panel_run(const char *command, const char *action,
			      const char *config_path, bool dry_run,
			      bool capture_output)
{
	pid_t child;

	if (access(HDN_RECOVERY_PANEL_EXEC, X_OK)) {
		fprintf(stderr,
			"recovery panel helper is not executable: %s\n",
			strerror(errno));
		return KSFT_SKIP;
	}

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		if (capture_output) {
			int fd;

			fd = open(HDN_RECOVERY_DESCRIBE_OUTPUT,
				  O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC,
				  0600);
			if (fd < 0)
				_exit(2);
			if (dup2(fd, STDOUT_FILENO) < 0)
				_exit(2);
			close(fd);
		}

		if (config_path && dry_run)
			execl(HDN_RECOVERY_PANEL_EXEC, "hdn-recovery-panel",
			      "--config", config_path, "--dry-run", command,
			      action, NULL);
		else if (config_path)
			execl(HDN_RECOVERY_PANEL_EXEC, "hdn-recovery-panel",
			      "--config", config_path, command, action, NULL);
		else if (dry_run)
			execl(HDN_RECOVERY_PANEL_EXEC, "hdn-recovery-panel",
			      "--dry-run", command, action, NULL);
		else
			execl(HDN_RECOVERY_PANEL_EXEC, "hdn-recovery-panel",
			      command, action, NULL);
		fprintf(stderr, "recovery panel exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int recovery_panel_shortcut_run(const char *command,
				       const char *config_path, bool dry_run)
{
	pid_t child;

	if (access(HDN_RECOVERY_PANEL_EXEC, X_OK)) {
		fprintf(stderr,
			"recovery panel helper is not executable: %s\n",
			strerror(errno));
		return KSFT_SKIP;
	}

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		if (config_path && dry_run)
			execl(HDN_RECOVERY_PANEL_EXEC, "hdn-recovery-panel",
			      "--config", config_path, "--dry-run", command,
			      NULL);
		else if (config_path)
			execl(HDN_RECOVERY_PANEL_EXEC, "hdn-recovery-panel",
			      "--config", config_path, command, NULL);
		else if (dry_run)
			execl(HDN_RECOVERY_PANEL_EXEC, "hdn-recovery-panel",
			      "--dry-run", command, NULL);
		else
			execl(HDN_RECOVERY_PANEL_EXEC, "hdn-recovery-panel",
			      command, NULL);
		fprintf(stderr, "recovery panel exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int recovery_panel_denied(const char *action, const char *config_path,
				 const char *failure)
{
	int ret = recovery_panel_run("action", action, config_path, false,
				     false);

	if (ret == KSFT_SKIP)
		return ret;
	if (!ret) {
		fprintf(stderr, "recovery panel allowed %s\n", failure);
		return 1;
	}
	if (ret != 1)
		return ret;

	return securityfs_status_has_line("generation: 0") &&
	       securityfs_status_has_line("policy_staged: 0") ? 0 : 1;
}

static int recovery_panel_unknown_denied(void)
{
	return recovery_panel_denied("unknown-recovery", NULL,
				     "unknown action");
}

static int recovery_panel_unsafe_config_denied(void)
{
	return recovery_panel_denied("rollback-policy",
				     HDN_RECOVERY_PANEL_UNSAFE_CONFIG,
				     "unsafe config");
}

static int recovery_panel_repair_describe_reports_metadata(void)
{
	unsigned char *blob = NULL;
	char *text = NULL;
	size_t size = 0;
	bool valid;
	int ret;

	unlink(HDN_RECOVERY_DESCRIBE_OUTPUT);
	ret = recovery_panel_run("describe", "repair-system", NULL, false,
				 true);
	if (ret == KSFT_SKIP)
		return ret;
	if (ret) {
		fprintf(stderr, "recovery panel describe exited with %d\n",
			ret);
		return ret;
	}

	ret = read_whole_file(HDN_RECOVERY_DESCRIBE_OUTPUT, &blob, &size);
	if (ret) {
		fprintf(stderr, "recovery panel describe output missing: %s\n",
			strerror(-ret));
		return 1;
	}

	text = malloc(size + 1);
	if (!text) {
		free(blob);
		return 2;
	}
	memcpy(text, blob, size);
	text[size] = '\0';

	valid = recovery_description_has_line(text,
					      "HDN_RECOVERY_METADATA_V1") &&
		recovery_description_has_line(text, "action=package-repair") &&
		recovery_description_has_line(text,
					      "title=Repair protected system files") &&
		recovery_description_has_line(text, "risk=repair") &&
		strstr(text, "message=") &&
		strstr(text, "consequence=");

	free(text);
	free(blob);
	if (!valid) {
		fprintf(stderr,
			"recovery panel describe output did not contain expected metadata\n");
		return 1;
	}

	return 0;
}

static int recovery_panel_policy_rollback_to_generation0(void)
{
	int ret;

	ret = broker_policy_commit_default();
	if (ret)
		return ret;

	ret = recovery_panel_shortcut_run("rollback", NULL, true);
	if (ret) {
		(void)write_text_file(HDN_ROLLBACK, "1\n");
		return ret;
	}
	if (!securityfs_status_has_line("generation: 1")) {
		(void)write_text_file(HDN_ROLLBACK, "1\n");
		return 1;
	}

	ret = recovery_panel_shortcut_run("rollback", NULL, false);
	if (ret) {
		(void)write_text_file(HDN_ROLLBACK, "1\n");
		return ret;
	}

	if (securityfs_status_has_line("generation: 0"))
		return 0;

	(void)write_text_file(HDN_ROLLBACK, "1\n");
	return 1;
}

static int recovery_ui_run(const char *choice, const char *config_path,
			   bool dry_run, bool test_cancel)
{
	char *argv[8];
	unsigned int argc = 0;
	pid_t child;

	if (access(HDN_RECOVERY_UI_EXEC, X_OK)) {
		fprintf(stderr,
			"recovery UI helper is not executable: %s\n",
			strerror(errno));
		return KSFT_SKIP;
	}

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		argv[argc++] = "hdn-recovery-ui";
		if (config_path) {
			argv[argc++] = "--config";
			argv[argc++] = (char *)config_path;
		}
		if (dry_run)
			argv[argc++] = "--dry-run";
		if (test_cancel) {
			argv[argc++] = "--test-cancel";
		} else if (choice) {
			argv[argc++] = "--test-choice";
			argv[argc++] = (char *)choice;
		}
		argv[argc] = NULL;
		execv(HDN_RECOVERY_UI_EXEC, argv);
		fprintf(stderr, "recovery UI exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int recovery_ui_denied(const char *choice, const char *config_path,
			      bool test_cancel, const char *failure)
{
	int ret = recovery_ui_run(choice, config_path, false, test_cancel);

	if (ret == KSFT_SKIP)
		return ret;
	if (!ret) {
		fprintf(stderr, "recovery UI allowed %s\n", failure);
		return 1;
	}
	if (ret != 1)
		return ret;

	return securityfs_status_has_line("generation: 0") &&
	       securityfs_status_has_line("policy_staged: 0") ? 0 : 1;
}

static int recovery_ui_unknown_denied(void)
{
	return recovery_ui_denied("unknown-recovery", NULL, false,
				  "unknown action");
}

static int recovery_ui_unsafe_config_denied(void)
{
	return recovery_ui_denied("rollback-policy",
				  HDN_RECOVERY_UI_UNSAFE_CONFIG, false,
				  "unsafe config");
}

static int recovery_ui_cancel_denied(void)
{
	return recovery_ui_denied(NULL, NULL, true, "canceled selection");
}

static int recovery_ui_no_display_denied(void)
{
	return recovery_ui_denied(NULL, NULL, false, "no-display UI");
}

static int recovery_ui_policy_rollback_to_generation0(void)
{
	int ret;

	ret = broker_policy_commit_default();
	if (ret)
		return ret;

	ret = recovery_ui_run("rollback-policy", NULL, true, false);
	if (ret) {
		(void)write_text_file(HDN_ROLLBACK, "1\n");
		return ret;
	}
	if (!securityfs_status_has_line("generation: 1")) {
		(void)write_text_file(HDN_ROLLBACK, "1\n");
		return 1;
	}

	ret = recovery_ui_run("rollback-policy", NULL, false, false);
	if (ret) {
		(void)write_text_file(HDN_ROLLBACK, "1\n");
		return ret;
	}

	if (securityfs_status_has_line("generation: 0"))
		return 0;

	(void)write_text_file(HDN_ROLLBACK, "1\n");
	return 1;
}

static int write_approval_token(const char *path, const char *intent,
				mode_t mode, long long lifetime_ms)
{
	unsigned long long expires_ms;
	unsigned long long now_ms;
	struct timespec ts;
	char text[256];
	ssize_t len;
	int fd;

	if (mkdir(HDN_APPROVAL_TOKEN_DIR, 0700) && errno != EEXIST)
		return -errno;
	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return -errno;
	if (ts.tv_sec < 0)
		return -EINVAL;
	if ((unsigned long long)ts.tv_sec >
	    (ULLONG_MAX - (unsigned long long)(ts.tv_nsec / 1000000)) / 1000)
		return -EOVERFLOW;
	now_ms = (unsigned long long)ts.tv_sec * 1000 +
		 (unsigned long long)(ts.tv_nsec / 1000000);
	if (lifetime_ms >= 0) {
		if (now_ms > ULLONG_MAX - (unsigned long long)lifetime_ms)
			return -EOVERFLOW;
		expires_ms = now_ms + (unsigned long long)lifetime_ms;
	} else if (now_ms > (unsigned long long)(-lifetime_ms)) {
		expires_ms = now_ms - (unsigned long long)(-lifetime_ms);
	} else {
		expires_ms = 0;
	}

	if (snprintf(text, sizeof(text),
		     "HDN_APPROVAL_V1\nintent=%s\nexpires-monotonic-ms=%llu\n",
		     intent, expires_ms) >= (int)sizeof(text))
		return -E2BIG;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
	if (fd < 0)
		return -errno;
	if (fchmod(fd, mode)) {
		int ret = -errno;

		close(fd);
		return ret;
	}

	len = write(fd, text, strlen(text));
	if (len < 0) {
		int ret = -errno;

		close(fd);
		return ret;
	}
	close(fd);
	return len == (ssize_t)strlen(text) ? 0 : -EIO;
}

static int broker_approval_rofs_transaction(const char *token, bool dry_run)
{
	pid_t child;

	if (access(HDN_ADMIN_BROKER_TOKEN_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		if (dry_run && token)
			execl(HDN_ADMIN_BROKER_TOKEN_EXEC,
			      "hdn-admin-broker-token", "--dry-run",
			      "--approval-token", token, "rofs-transaction",
			      HDN_PRODUCT_ROFS_DIR, "--", "/hdn_smoke",
			      "--product-rofs-write-sentinel", NULL);
		else if (dry_run)
			execl(HDN_ADMIN_BROKER_TOKEN_EXEC,
			      "hdn-admin-broker-token", "--dry-run",
			      "rofs-transaction", HDN_PRODUCT_ROFS_DIR, "--",
			      "/hdn_smoke", "--product-rofs-write-sentinel",
			      NULL);
		else if (token)
			execl(HDN_ADMIN_BROKER_TOKEN_EXEC,
			      "hdn-admin-broker-token", "--approval-token",
			      token, "rofs-transaction", HDN_PRODUCT_ROFS_DIR,
			      "--", "/hdn_smoke",
			      "--product-rofs-write-sentinel", NULL);
		else
			execl(HDN_ADMIN_BROKER_TOKEN_EXEC,
			      "hdn-admin-broker-token", "rofs-transaction",
			      HDN_PRODUCT_ROFS_DIR, "--", "/hdn_smoke",
			      "--product-rofs-write-sentinel", NULL);
		fprintf(stderr, "approval broker exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int broker_approval_missing_token_denied(void)
{
	int ret = broker_approval_rofs_transaction(NULL, true);

	if (ret == KSFT_SKIP)
		return ret;
	return ret ? 0 : 1;
}

static int broker_approval_unsafe_token_denied(void)
{
	int ret;

	unlink(HDN_APPROVAL_TOKEN_UNSAFE);
	ret = write_approval_token(HDN_APPROVAL_TOKEN_UNSAFE,
				   "rofs-transaction", 0644, 60000);
	if (ret)
		return 2;

	ret = broker_approval_rofs_transaction(HDN_APPROVAL_TOKEN_UNSAFE, true);
	unlink(HDN_APPROVAL_TOKEN_UNSAFE);
	return ret ? 0 : 1;
}

static int broker_approval_wrong_intent_denied(void)
{
	int ret;

	unlink(HDN_APPROVAL_TOKEN_WRONG);
	ret = write_approval_token(HDN_APPROVAL_TOKEN_WRONG, "policy-commit",
				   0600, 60000);
	if (ret)
		return 2;

	ret = broker_approval_rofs_transaction(HDN_APPROVAL_TOKEN_WRONG, true);
	unlink(HDN_APPROVAL_TOKEN_WRONG);
	return ret ? 0 : 1;
}

static int broker_approval_valid_token_allows_dry_run(void)
{
	int ret;

	unlink(HDN_APPROVAL_TOKEN_OK);
	ret = write_approval_token(HDN_APPROVAL_TOKEN_OK, "rofs-transaction",
				   0600, 60000);
	if (ret)
		return 2;

	ret = broker_approval_rofs_transaction(HDN_APPROVAL_TOKEN_OK, true);
	unlink(HDN_APPROVAL_TOKEN_OK);
	return ret;
}

static int broker_approval_expired_token_denied(void)
{
	int ret;

	unlink(HDN_APPROVAL_TOKEN_EXPIRED);
	ret = write_approval_token(HDN_APPROVAL_TOKEN_EXPIRED,
				   "rofs-transaction", 0600, -1000);
	if (ret)
		return 2;

	ret = broker_approval_rofs_transaction(HDN_APPROVAL_TOKEN_EXPIRED,
					       true);
	unlink(HDN_APPROVAL_TOKEN_EXPIRED);
	return ret ? 0 : 1;
}

static int approval_token_issuer_run(const char *intent, const char *name)
{
	pid_t child;

	if (access(HDN_APPROVAL_TOKEN_ISSUER_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_APPROVAL_TOKEN_ISSUER_EXEC, "hdn-approval-token",
		      "--dir", HDN_APPROVAL_TOKEN_DIR, "--intent", intent,
		      "--ttl-ms", "60000", "--name", name, NULL);
		fprintf(stderr, "approval token issuer exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int approval_token_issuer_unknown_intent_denied(void)
{
	int ret;

	unlink(HDN_APPROVAL_TOKEN_ISSUER_BAD);
	ret = approval_token_issuer_run("shell", "bad-issuer.token");
	if (ret == KSFT_SKIP)
		return ret;
	if (!ret) {
		unlink(HDN_APPROVAL_TOKEN_ISSUER_BAD);
		return 1;
	}
	if (ret != 1)
		return ret;
	if (!access(HDN_APPROVAL_TOKEN_ISSUER_BAD, F_OK)) {
		unlink(HDN_APPROVAL_TOKEN_ISSUER_BAD);
		return 1;
	}

	return 0;
}

static int approval_token_issuer_creates_valid_token(void)
{
	int ret;

	unlink(HDN_APPROVAL_TOKEN_ISSUED);
	ret = approval_token_issuer_run("rofs-transaction", "issued.token");
	if (ret)
		return ret;

	ret = broker_approval_rofs_transaction(HDN_APPROVAL_TOKEN_ISSUED, true);
	unlink(HDN_APPROVAL_TOKEN_ISSUED);
	return ret;
}

static int broker_approval_token_consumed_and_replay_denied(unsigned int updates)
{
	unsigned int count_before;
	unsigned int count_after;
	int saved_errno;
	int replay_ret;
	int ret;
	int fd;

	if (access(HDN_ADMIN_BROKER_TOKEN_EXEC, X_OK))
		return KSFT_SKIP;

	unlink(HDN_APPROVAL_TOKEN_OK);
	ret = write_approval_token(HDN_APPROVAL_TOKEN_OK, "rofs-transaction",
				   0600, 60000);
	if (ret)
		return 2;

	ret = broker_approval_rofs_transaction(HDN_APPROVAL_TOKEN_OK, false);
	if (ret) {
		unlink(HDN_APPROVAL_TOKEN_OK);
		return ret;
	}
	if (!access(HDN_APPROVAL_TOKEN_OK, F_OK)) {
		fprintf(stderr, "approval token was not consumed\n");
		unlink(HDN_APPROVAL_TOKEN_OK);
		return 1;
	}

	count_before = product_rofs_sentinel_update_count();
	if (count_before < updates) {
		fprintf(stderr, "approval transaction left %u updates, expected at least %u\n",
			count_before, updates);
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"approval transaction left product mount writable\n");
		close(fd);
		return 1;
	}
	if (saved_errno != EROFS) {
		fprintf(stderr,
			"approval transaction write-open failed with %s\n",
			strerror(saved_errno));
		return 2;
	}

	replay_ret = broker_approval_rofs_transaction(HDN_APPROVAL_TOKEN_OK,
						      false);
	if (!replay_ret) {
		fprintf(stderr, "approval token replay succeeded\n");
		return 1;
	}

	count_after = product_rofs_sentinel_update_count();
	if (count_after != count_before) {
		fprintf(stderr, "approval replay changed update count from %u to %u\n",
			count_before, count_after);
		return 1;
	}

	return 0;
}

static int kexec_load_denied(void)
{
#ifdef __NR_kexec_load
	int ret;

	errno = 0;
	ret = syscall(__NR_kexec_load, 0UL, 0UL, NULL, 0UL);
	if (!ret)
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
#else
	return KSFT_SKIP;
#endif
}

static int bpf_map_create_without_authority_denied(void)
{
#ifdef __NR_bpf
	union bpf_attr attr = {};
	int fd;

	attr.map_type = BPF_MAP_TYPE_ARRAY;
	attr.key_size = sizeof(uint32_t);
	attr.value_size = sizeof(uint32_t);
	attr.max_entries = 1;

	errno = 0;
	fd = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
	if (fd >= 0) {
		close(fd);
		return 1;
	}

	return errno_is_denial(errno) ? 0 : 2;
#else
	return KSFT_SKIP;
#endif
}

static int bpf_metadata_without_authority_denied(void)
{
#ifdef __NR_bpf
	static const int cmds[] = {
		BPF_PROG_GET_NEXT_ID,
		BPF_MAP_GET_NEXT_ID,
		BPF_BTF_GET_NEXT_ID,
		BPF_LINK_GET_NEXT_ID,
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(cmds); i++) {
		union bpf_attr attr = {};
		int ret;

		attr.start_id = 0;
		errno = 0;
		ret = syscall(__NR_bpf, cmds[i], &attr, sizeof(attr));
		if (!ret)
			return 1;
		if (!errno_is_denial(errno))
			return 2;
	}

	return 0;
#else
	return KSFT_SKIP;
#endif
}

static int sysfs_mutation_denied(void)
{
	int fd;
	int ret;

	errno = 0;
	fd = open(HDN_SYSFS_RCU_EXPEDITED, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return errno == ENOENT ? KSFT_SKIP : 2;

	errno = 0;
	ret = write(fd, "0\n", 2);
	close(fd);
	if (ret >= 0)
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int build_child_path(char *dst, size_t size, const char *dir,
			    const char *name)
{
	size_t remaining;
	size_t dir_len = strlen(dir);
	size_t name_len = strlen(name);

	if (dir_len + 1 >= size)
		return -ENAMETOOLONG;

	remaining = size - dir_len - 1;
	if (name_len >= remaining)
		return -ENAMETOOLONG;

	memcpy(dst, dir, dir_len);
	dst[dir_len] = '/';
	memcpy(dst + dir_len + 1, name, name_len + 1);
	return 0;
}

static int find_owner_only_sysfs_file(char *path, size_t size)
{
	struct dirent *cache;
	DIR *slabs;
	int ret = -ENOENT;

	slabs = opendir(HDN_SYSFS_SLAB_DIR);
	if (!slabs)
		return -errno;

	while ((cache = readdir(slabs))) {
		struct dirent *attr;
		char dir_path[PATH_MAX];
		DIR *dir;

		if (!strcmp(cache->d_name, ".") ||
		    !strcmp(cache->d_name, ".."))
			continue;

		if (build_child_path(dir_path, sizeof(dir_path),
				     HDN_SYSFS_SLAB_DIR, cache->d_name))
			continue;

		dir = opendir(dir_path);
		if (!dir)
			continue;

		while ((attr = readdir(dir))) {
			struct stat st;

				if (!strcmp(attr->d_name, ".") ||
				    !strcmp(attr->d_name, ".."))
					continue;

				if (build_child_path(path, size, dir_path,
						     attr->d_name))
					continue;
				if (stat(path, &st))
					continue;
			if (!S_ISREG(st.st_mode))
				continue;
			if ((st.st_mode & 0400) &&
			    !(st.st_mode & 0044)) {
				ret = 0;
				break;
			}
		}

		closedir(dir);
		if (!ret)
			break;
	}

	closedir(slabs);
	return ret;
}

static int get_owner_only_sysfs_file(char *path, size_t size)
{
	int ret;

	if (hdn_owner_only_sysfs_path_ready) {
		ret = snprintf(path, size, "%s", hdn_owner_only_sysfs_path);
		return ret < 0 || (size_t)ret >= size ? -ENAMETOOLONG : 0;
	}

	return find_owner_only_sysfs_file(path, size);
}

static int sysfs_owner_only_read_denied(void)
{
	char path[PATH_MAX];
	char buf[1];
	int saved_errno = 0;
	int fd;
	int ret;

	ret = get_owner_only_sysfs_file(path, sizeof(path));
	if (ret)
		return ret == -ENOENT || ret == -ENOTDIR ? KSFT_SKIP : 2;

	errno = 0;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return errno_is_denial(errno) ? 0 : 2;

	errno = 0;
	ret = read(fd, buf, sizeof(buf));
	if (ret < 0)
		saved_errno = errno;
	close(fd);

	if (ret >= 0)
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int sysfs_readdir_path_hidden(const char *path)
{
	char dir[PATH_MAX];
	char name[NAME_MAX + 1];
	const char *slash;
	struct stat st;
	struct dirent *entry;
	size_t dir_len;
	size_t name_len;
	DIR *stream;

	if (stat(path, &st))
		return errno == ENOENT || errno == ENOTDIR ? KSFT_SKIP : 2;
	slash = strrchr(path, '/');
	if (!slash || slash == path || !slash[1])
		return 2;

	dir_len = slash - path;
	name_len = strlen(slash + 1);
	if (dir_len >= sizeof(dir) || name_len >= sizeof(name))
		return 2;

	memcpy(dir, path, dir_len);
	dir[dir_len] = '\0';
	memcpy(name, slash + 1, name_len + 1);

	stream = opendir(dir);
	if (!stream)
		return errno == ENOENT || errno == ENOTDIR ? KSFT_SKIP : 2;

	while ((entry = readdir(stream))) {
		if (!strcmp(entry->d_name, name)) {
			closedir(stream);
			return 1;
		}
	}

	closedir(stream);
	return 0;
}

static int sysfs_owner_only_readdir_hidden(void)
{
	char path[PATH_MAX];
	int ret;

	ret = get_owner_only_sysfs_file(path, sizeof(path));
	if (ret)
		return ret == -ENOENT || ret == -ENOTDIR ? KSFT_SKIP : 2;

	return sysfs_readdir_path_hidden(path);
}

static int sysfs_path_read_denied(const char *path)
{
	char buf[1];
	int saved_errno = 0;
	int fd;
	int ret;

	errno = 0;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return errno == ENOENT || errno == ENOTDIR ? KSFT_SKIP :
		       errno_is_denial(errno) ? 0 : 2;

	errno = 0;
	ret = read(fd, buf, sizeof(buf));
	if (ret < 0)
		saved_errno = errno;
	close(fd);

	if (ret >= 0)
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int sysfs_sensitive_read_denied(void)
{
	return sysfs_path_read_denied(HDN_SYSFS_VMCOREINFO);
}

static int sysfs_sensitive_readdir_hidden(void)
{
	return sysfs_readdir_path_hidden(HDN_SYSFS_VMCOREINFO);
}

static int sysfs_boot_params_read_denied(void)
{
	return sysfs_path_read_denied(HDN_SYSFS_BOOT_PARAMS_DATA);
}

static int sysfs_boot_params_readdir_hidden(void)
{
	return sysfs_readdir_path_hidden(HDN_SYSFS_BOOT_PARAMS_DATA);
}

static int sysfs_memmap_address_read_denied(void)
{
	return sysfs_path_read_denied(HDN_SYSFS_MEMMAP_START);
}

static int sysfs_memmap_address_readdir_hidden(void)
{
	return sysfs_readdir_path_hidden(HDN_SYSFS_MEMMAP_START);
}

static int sysfs_memmap_type_read_allowed(void)
{
	char buf[64];
	int fd;
	int ret;

	fd = open(HDN_SYSFS_MEMMAP_TYPE, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return errno == ENOENT || errno == ENOTDIR ? KSFT_SKIP : 2;
	ret = read(fd, buf, sizeof(buf));
	close(fd);

	return ret > 0 ? 0 : 1;
}

static int sysfs_memmap_type_readdir_visible(void)
{
	int ret = sysfs_readdir_path_hidden(HDN_SYSFS_MEMMAP_TYPE);

	if (ret == KSFT_SKIP || ret == 2)
		return ret;
	return ret ? 0 : 1;
}

static bool module_address_hidden_token(const char *token)
{
	const char *digits;

	if (!strcmp(token, "0x(null)") || !strcmp(token, "(null)"))
		return true;
	if (strncmp(token, "0x", 2))
		return false;

	for (digits = token + 2; *digits; digits++) {
		if (*digits != '0')
			return false;
	}

	return true;
}

static int proc_modules_symbol_address_hidden(void)
{
	char line[512];
	FILE *stream;

	if (!hdn_symbol_test_module_loaded)
		return 2;

	stream = fopen("/proc/modules", "r");
	if (!stream)
		return errno == ENOENT ? KSFT_SKIP : 2;

	while (fgets(line, sizeof(line), stream)) {
		char name[64];
		char refcount[64];
		char deps[256];
		char state[64];
		char address[64];
		unsigned int size;

		if (sscanf(line, "%63s %u %63s %255s %63s %63s",
			   name, &size, refcount, deps, state, address) != 6)
			continue;
		if (strcmp(name, HDN_SYMBOL_TEST_MODULE_NAME))
			continue;

		fclose(stream);
		return module_address_hidden_token(address) ? 0 : 1;
	}

	fclose(stream);
	return 2;
}

static void test_symbol_test_module_load(void)
{
#ifdef __NR_finit_module
	int saved_errno = 0;
	int fd;
	int ret;

	fd = open(HDN_SYMBOL_TEST_MODULE, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT)
			ksft_test_result_skip("signed module fixture loads\n");
		else
			ksft_test_result_fail("signed module fixture open failed: %s\n",
					      strerror(errno));
		return;
	}

	errno = 0;
	ret = syscall(__NR_finit_module, fd, "", 0);
	if (ret)
		saved_errno = errno;
	close(fd);

	hdn_symbol_test_module_loaded = !ret || saved_errno == EEXIST;
	ksft_test_result(hdn_symbol_test_module_loaded,
			 "signed module fixture loads\n");
#else
	ksft_test_result_skip("signed module fixture loads\n");
#endif
}

static int proc_kcore_denied(void)
{
	int fd;

	errno = 0;
	fd = open("/proc/kcore", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		close(fd);
		return 1;
	}

	return errno_is_denial(errno) ? 0 : 2;
}

static int proc_kallsyms_symbols_hidden(void)
{
	char buf[256];
	ssize_t len;
	int fd;

	errno = 0;
	fd = open(HDN_PROC_KALLSYMS, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return errno == ENOENT ? KSFT_SKIP :
		       errno_is_denial(errno) ? 0 : 2;

	errno = 0;
	len = read(fd, buf, sizeof(buf));
	close(fd);
	if (len < 0)
		return errno_is_denial(errno) ? 0 : 2;
	return len == 0 ? 0 : 1;
}

static int bpf_kallsyms_lookup_without_disclosure_denied(void);
static int bpf_pseudo_btf_id_without_disclosure_denied(void);

static int proc_sensitive_target_main(void)
{
	char ready = 'R';

	if (write(3, &ready, sizeof(ready)) != sizeof(ready))
		return 2;
	close(3);

	for (;;)
		pause();
}

static pid_t spawn_proc_sensitive_target(void)
{
	char *const argv[] = {
		"hdn_smoke",
		"--proc-sensitive-target",
		(char *)HDN_PROC_SENSITIVE_ARG,
		NULL,
	};
	char *const envp[] = {
		(char *)HDN_PROC_SENSITIVE_ENV,
		NULL,
	};
	int sync_pipe[2];
	char ready;
	pid_t child;

	if (pipe(sync_pipe))
		return -1;

	child = fork();
	if (child < 0) {
		close(sync_pipe[0]);
		close(sync_pipe[1]);
		return -1;
	}

	if (!child) {
		close(sync_pipe[0]);
		if (dup2(sync_pipe[1], 3) < 0)
			_exit(2);
		if (sync_pipe[1] != 3)
			close(sync_pipe[1]);
		execve("/proc/self/exe", argv, envp);
		_exit(2);
	}

	close(sync_pipe[1]);
	if (read(sync_pipe[0], &ready, sizeof(ready)) != sizeof(ready)) {
		close(sync_pipe[0]);
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		return -1;
	}
	close(sync_pipe[0]);

	return child;
}

static int read_proc_sensitive_file(pid_t pid, const char *name,
				    const char *needle, bool expect_denied)
{
	char path[64];
	char buf[512];
	int saved_errno = 0;
	ssize_t len;
	int fd;

	snprintf(path, sizeof(path), "/proc/%d/%s", pid, name);
	errno = 0;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		saved_errno = errno;
		if (expect_denied)
			return errno_is_denial(saved_errno) ? 0 : 2;
		return saved_errno == ENOENT ? KSFT_SKIP : 2;
	}

	errno = 0;
	len = read(fd, buf, sizeof(buf));
	if (len < 0)
		saved_errno = errno;
	close(fd);

	if (expect_denied) {
		if (len >= 0)
			return 1;
		return errno_is_denial(saved_errno) ? 0 : 2;
	}

	if (len <= 0)
		return 1;
	if (needle && !memmem(buf, len, needle, strlen(needle)))
		return 1;
	return 0;
}

static int proc_sensitive_file_visibility(const char *name, const char *needle,
					  bool expect_disclosed)
{
	bool expect_denied = !expect_disclosed;
	pid_t child;
	int ret;

	child = spawn_proc_sensitive_target();
	if (child < 0)
		return 2;

	ret = read_proc_sensitive_file(child, name, needle, expect_denied);

	kill(child, SIGKILL);
	waitpid(child, NULL, 0);
	return ret;
}

static int write_proc_sensitive_file(pid_t pid, const char *name,
				     const char *text, bool expect_denied)
{
	char path[64];
	int saved_errno = 0;
	ssize_t len;
	int fd;

	snprintf(path, sizeof(path), "/proc/%d/%s", pid, name);
	errno = 0;
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		saved_errno = errno;
		if (saved_errno == ENOENT)
			return KSFT_SKIP;
		if (expect_denied)
			return errno_is_denial(saved_errno) ? 0 : 2;
		return 2;
	}

	errno = 0;
	len = write(fd, text, strlen(text));
	if (len < 0)
		saved_errno = errno;
	close(fd);

	if (expect_denied) {
		if (len >= 0)
			return 1;
		return errno_is_denial(saved_errno) ? 0 : 2;
	}

	return len == (ssize_t)strlen(text) ? 0 : 1;
}

static int proc_sensitive_file_write_visibility(const char *name,
						const char *text,
						bool expect_disclosed)
{
	bool expect_denied = !expect_disclosed;
	pid_t child;
	int ret;

	child = spawn_proc_sensitive_target();
	if (child < 0)
		return 2;

	ret = write_proc_sensitive_file(child, name, text, expect_denied);

	kill(child, SIGKILL);
	waitpid(child, NULL, 0);
	return ret;
}

static int proc_cmdline_disclosed_by_policy(void)
{
	return proc_sensitive_file_visibility("cmdline", HDN_PROC_SENSITIVE_ARG,
					      true);
}

static int proc_environ_disclosed_by_policy(void)
{
	return proc_sensitive_file_visibility("environ", HDN_PROC_SENSITIVE_ENV,
					      true);
}

static int proc_auxv_disclosed_by_policy(void)
{
	return proc_sensitive_file_visibility("auxv", NULL, true);
}

static int proc_syscall_disclosed_by_policy(void)
{
	return proc_sensitive_file_visibility("syscall", NULL, true);
}

static int proc_io_disclosed_by_policy(void)
{
	return proc_sensitive_file_visibility("io", "rchar:", true);
}

static int proc_personality_disclosed_by_policy(void)
{
	return proc_sensitive_file_visibility("personality", NULL, true);
}

static int proc_coredump_filter_disclosed_by_policy(void)
{
	return proc_sensitive_file_visibility("coredump_filter", NULL, true);
}

static int proc_coredump_filter_write_allowed_by_policy(void)
{
	return proc_sensitive_file_write_visibility("coredump_filter", "0x33\n",
						    true);
}

static int proc_limits_disclosed_by_policy(void)
{
	return proc_sensitive_file_visibility("limits", "Limit", true);
}

static int proc_statm_disclosed_by_policy(void)
{
	return proc_sensitive_file_visibility("statm", NULL, true);
}

static int proc_sched_disclosed_by_policy(void)
{
	return proc_sensitive_file_visibility("sched", "se.exec_start", true);
}

static int proc_schedstat_disclosed_by_policy(void)
{
	return proc_sensitive_file_visibility("schedstat", NULL, true);
}

static int proc_cmdline_denied_without_disclosure(void)
{
	return proc_sensitive_file_visibility("cmdline", HDN_PROC_SENSITIVE_ARG,
					      false);
}

static int proc_environ_denied_without_disclosure(void)
{
	return proc_sensitive_file_visibility("environ", HDN_PROC_SENSITIVE_ENV,
					      false);
}

static int proc_auxv_denied_without_disclosure(void)
{
	return proc_sensitive_file_visibility("auxv", NULL, false);
}

static int proc_syscall_denied_without_disclosure(void)
{
	return proc_sensitive_file_visibility("syscall", NULL, false);
}

static int proc_io_denied_without_disclosure(void)
{
	return proc_sensitive_file_visibility("io", "rchar:", false);
}

static int proc_personality_denied_without_disclosure(void)
{
	return proc_sensitive_file_visibility("personality", NULL, false);
}

static int proc_coredump_filter_denied_without_disclosure(void)
{
	return proc_sensitive_file_visibility("coredump_filter", NULL, false);
}

static int proc_coredump_filter_write_denied_without_disclosure(void)
{
	return proc_sensitive_file_write_visibility("coredump_filter", "0x33\n",
						    false);
}

static int proc_limits_denied_without_disclosure(void)
{
	return proc_sensitive_file_visibility("limits", "Limit", false);
}

static int proc_statm_denied_without_disclosure(void)
{
	return proc_sensitive_file_visibility("statm", NULL, false);
}

static int proc_sched_denied_without_disclosure(void)
{
	return proc_sensitive_file_visibility("sched", "se.exec_start", false);
}

static int proc_schedstat_denied_without_disclosure(void)
{
	return proc_sensitive_file_visibility("schedstat", NULL, false);
}

static pid_t spawn_proc_memmap_target(void)
{
	int sync_pipe[2];
	char ready = 'R';
	pid_t child;

	if (pipe(sync_pipe))
		return -1;

	child = fork();
	if (child < 0) {
		close(sync_pipe[0]);
		close(sync_pipe[1]);
		return -1;
	}

	if (!child) {
		close(sync_pipe[0]);
		if (write(sync_pipe[1], &ready, sizeof(ready)) != sizeof(ready))
			_exit(2);
		close(sync_pipe[1]);
		for (;;)
			pause();
	}

	close(sync_pipe[1]);
	if (read(sync_pipe[0], &ready, sizeof(ready)) != sizeof(ready)) {
		close(sync_pipe[0]);
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		return -1;
	}
	close(sync_pipe[0]);

	return child;
}

static int read_proc_maps_range(pid_t pid, unsigned long *start,
				unsigned long *end)
{
	char path[64];
	char perms[8];
	char line[512];
	FILE *stream;

	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	stream = fopen(path, "r");
	if (!stream)
		return errno == ENOENT ? KSFT_SKIP : 2;
	if (!fgets(line, sizeof(line), stream)) {
		fclose(stream);
		return 2;
	}
	fclose(stream);

	if (sscanf(line, "%lx-%lx %7s", start, end, perms) != 3)
		return 2;

	return 0;
}

static int read_proc_stat_memmap_fields(pid_t pid, unsigned long long *start_code,
					 unsigned long long *end_code,
					 unsigned long long *start_stack)
{
	char path[64];
	char buf[2048];
	char *cursor;
	char *save = NULL;
	char *token;
	FILE *stream;
	int field = 3;

	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	stream = fopen(path, "r");
	if (!stream)
		return errno == ENOENT ? KSFT_SKIP : 2;
	if (!fgets(buf, sizeof(buf), stream)) {
		fclose(stream);
		return 2;
	}
	fclose(stream);

	cursor = strrchr(buf, ')');
	if (!cursor || cursor[1] != ' ')
		return 2;
	cursor += 2;

	*start_code = 0;
	*end_code = 0;
	*start_stack = 0;
	for (token = strtok_r(cursor, " \n", &save); token;
	     token = strtok_r(NULL, " \n", &save), field++) {
		char *endp;
		unsigned long long value;

		if (field < 26 || field > 28)
			continue;
		errno = 0;
		value = strtoull(token, &endp, 10);
		if (errno || endp == token)
			return 2;
		if (field == 26)
			*start_code = value;
		else if (field == 27)
			*end_code = value;
		else
			*start_stack = value;
	}

	return field > 28 ? 0 : 2;
}

static int proc_memmap_visibility(bool expect_disclosed)
{
	unsigned long map_start = 0, map_end = 0;
	unsigned long long stat_start = 0, stat_end = 0, stat_stack = 0;
	pid_t child;
	int ret;

	child = spawn_proc_memmap_target();
	if (child < 0)
		return 2;

	ret = read_proc_maps_range(child, &map_start, &map_end);
	if (!ret)
		ret = read_proc_stat_memmap_fields(child, &stat_start,
						   &stat_end, &stat_stack);

	kill(child, SIGKILL);
	waitpid(child, NULL, 0);
	if (ret)
		return ret;

	if (expect_disclosed) {
		if (!map_start || map_end <= map_start)
			return 1;
		if (stat_start <= 1 || stat_end <= stat_start || !stat_stack)
			return 1;
		return 0;
	}

	if (map_start || map_end)
		return 1;
	if (stat_start != 1 || stat_end != 1 || stat_stack)
		return 1;
	return 0;
}

static int proc_memmap_disclosed_by_policy(void)
{
	return proc_memmap_visibility(true);
}

static int proc_memmap_redacted_without_disclosure(void)
{
	return proc_memmap_visibility(false);
}

static int proc_resource_map_visibility(const char *path, bool expect_disclosed)
{
	char line[512];
	bool saw_entry = false;
	bool saw_nonzero = false;
	FILE *stream;

	stream = fopen(path, "r");
	if (!stream)
		return errno == ENOENT ? KSFT_SKIP : 2;

	while (fgets(line, sizeof(line), stream)) {
		unsigned long long start;
		unsigned long long end;

		if (sscanf(line, " %llx-%llx :", &start, &end) != 2)
			continue;

		saw_entry = true;
		if (start || end)
			saw_nonzero = true;
		if (!expect_disclosed && (start || end)) {
			fclose(stream);
			return 1;
		}
	}

	fclose(stream);
	if (!saw_entry)
		return 2;
	if (expect_disclosed && !saw_nonzero)
		return 1;
	return 0;
}

static int proc_resource_maps_visibility(bool expect_disclosed)
{
	int ret;

	ret = proc_resource_map_visibility(HDN_PROC_IOPORTS, expect_disclosed);
	if (ret)
		return ret;
	return proc_resource_map_visibility(HDN_PROC_IOMEM, expect_disclosed);
}

static int proc_resource_maps_disclosed_by_policy(void)
{
	return proc_resource_maps_visibility(true);
}

static int proc_resource_maps_redacted_without_disclosure(void)
{
	return proc_resource_maps_visibility(false);
}

static off_t self_pagemap_offset(void)
{
	long page_size = sysconf(_SC_PAGESIZE);
	uintptr_t addr = (uintptr_t)&page_size;

	if (page_size <= 0)
		page_size = 4096;

	return (off_t)((addr / (uintptr_t)page_size) * sizeof(uint64_t));
}

static int read_pagemap_entry(const char *path, off_t offset,
			      bool expect_denial)
{
	uint64_t entry;
	ssize_t len;
	int fd;

	errno = 0;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return errno == ENOENT ? KSFT_SKIP : 2;

	errno = 0;
	len = pread(fd, &entry, sizeof(entry), offset);
	close(fd);
	if (expect_denial) {
		if (len >= 0)
			return 1;
		return errno_is_denial(errno) ? 0 : 2;
	}

	return len == sizeof(entry) ? 0 : 1;
}

static int proc_self_pagemap_allowed_without_disclosure(void)
{
	return read_pagemap_entry("/proc/self/pagemap", self_pagemap_offset(),
				  false);
}

static int proc_pagemap_denied_without_disclosure(void)
{
	char path[64];
	pid_t child;
	int ret;

	child = spawn_proc_memmap_target();
	if (child < 0)
		return 2;

	snprintf(path, sizeof(path), "/proc/%d/pagemap", child);
	ret = read_pagemap_entry(path, 0, true);

	kill(child, SIGKILL);
	waitpid(child, NULL, 0);
	return ret;
}

static int proc_kpage_file_denied_without_disclosure(const char *path)
{
	uint64_t entry;
	ssize_t len;
	int fd;

	errno = 0;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return errno == ENOENT ? KSFT_SKIP : 2;

	errno = 0;
	len = read(fd, &entry, sizeof(entry));
	close(fd);
	if (len >= 0)
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int proc_kpage_metadata_denied_without_disclosure(void)
{
	static const char * const paths[] = {
		HDN_PROC_KPAGECOUNT,
		HDN_PROC_KPAGEFLAGS,
		HDN_PROC_KPAGECGROUP,
	};
	bool saw_file = false;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(paths); i++) {
		int ret = proc_kpage_file_denied_without_disclosure(paths[i]);

		if (ret == KSFT_SKIP)
			continue;
		saw_file = true;
		if (ret)
			return ret;
	}

	return saw_file ? 0 : KSFT_SKIP;
}

static int proc_vmallocinfo_symbols_hidden(void)
{
	char line[1024];
	bool saw_line = false;
	bool saw_hidden = false;
	FILE *stream;

	stream = fopen(HDN_PROC_VMALLOCINFO, "r");
	if (!stream)
		return errno == ENOENT ? KSFT_SKIP : 2;

	while (fgets(line, sizeof(line), stream)) {
		saw_line = true;
		if (strstr(line, "[hidden]")) {
			saw_hidden = true;
			break;
		}
	}

	fclose(stream);
	if (!saw_line)
		return 2;
	return saw_hidden ? 0 : 1;
}

static int proc_net_ptype_symbols_hidden(void)
{
	char line[512];
	bool saw_entry = false;
	FILE *stream;

	stream = fopen(HDN_PROC_NET_PTYPE, "r");
	if (!stream)
		return errno == ENOENT || errno == ENOTDIR ? KSFT_SKIP : 2;

	while (fgets(line, sizeof(line), stream)) {
		if (!strncmp(line, "Type ", 5) || line[0] == '\n')
			continue;

		saw_entry = true;
		if (!strstr(line, "[hidden]")) {
			fclose(stream);
			return 1;
		}
	}

	fclose(stream);
	return saw_entry ? 0 : KSFT_SKIP;
}

static bool proc_timer_list_symbol_line(const char *line)
{
	static const char * const prefixes[] = {
		" set_next_event:",
		" shutdown:",
		" periodic:",
		" oneshot:",
		" oneshot stopped:",
		" resume:",
		" event_handler:",
	};
	size_t i;

	if (line[0] == ' ' && line[1] == '#' &&
	    line[2] >= '0' && line[2] <= '9')
		return true;

	for (i = 0; i < ARRAY_SIZE(prefixes); i++) {
		if (!strncmp(line, prefixes[i], strlen(prefixes[i])))
			return true;
	}

	return false;
}

static int proc_timer_list_symbols_hidden(void)
{
	char line[512];
	bool saw_symbol_line = false;
	FILE *stream;

	stream = fopen(HDN_PROC_TIMER_LIST, "r");
	if (!stream)
		return errno == ENOENT || errno == ENOTDIR ? KSFT_SKIP : 2;

	while (fgets(line, sizeof(line), stream)) {
		if (!proc_timer_list_symbol_line(line))
			continue;

		saw_symbol_line = true;
		if (!strstr(line, "[hidden]")) {
			fclose(stream);
			return 1;
		}
	}

	fclose(stream);
	return saw_symbol_line ? 0 : KSFT_SKIP;
}

static int module_helper_path_write_current_value(void)
{
	char path[256];
	int ret;

	ret = read_text_file_small(HDN_MODPROBE_PATH, path, sizeof(path));
	if (ret)
		return ret == -ENOENT ? KSFT_SKIP : 2;

	return write_text_file(HDN_MODPROBE_PATH, path);
}

static int module_helper_path_write_allowed_by_policy(void)
{
	return module_helper_path_write_current_value() ? 2 : 0;
}

static int module_helper_unsafe_path_denied_by_policy(void)
{
	char current[256];
	char restore[300];
	int ret;

	ret = read_text_file_small(HDN_MODPROBE_PATH, current, sizeof(current));
	if (ret)
		return ret == -ENOENT ? KSFT_SKIP : 2;

	(void)unlink(HDN_MODPROBE_UNSAFE_PATH);
	(void)rmdir(HDN_MODPROBE_UNSAFE_DIR);
	if (mkdir(HDN_MODPROBE_UNSAFE_DIR, 0777) && errno != EEXIST)
		return 2;
	if (chmod(HDN_MODPROBE_UNSAFE_DIR, 0777))
		return 2;
	ret = copy_file("/hdn_smoke", HDN_MODPROBE_UNSAFE_PATH, 0755);
	if (ret)
		return 2;
	if (chmod(HDN_MODPROBE_UNSAFE_PATH, 0755))
		return 2;

	ret = write_text_file(HDN_MODPROBE_PATH,
			      HDN_MODPROBE_UNSAFE_PATH "\n");
	if (!ret) {
		snprintf(restore, sizeof(restore), "%s\n", current);
		(void)write_text_file(HDN_MODPROBE_PATH, restore);
		(void)unlink(HDN_MODPROBE_UNSAFE_PATH);
		(void)rmdir(HDN_MODPROBE_UNSAFE_DIR);
		return 1;
	}

	(void)unlink(HDN_MODPROBE_UNSAFE_PATH);
	(void)rmdir(HDN_MODPROBE_UNSAFE_DIR);
	if (ret == -ENOENT)
		return KSFT_SKIP;

	return ret == -EINVAL ? 0 : 2;
}

static int module_helper_path_write_without_authority_denied(void)
{
	unsigned int before;
	int ret;

	before = securityfs_events_count("authority=37 transition=43");
	ret = module_helper_path_write_current_value();
	if (!ret)
		return 1;
	if (ret == KSFT_SKIP)
		return KSFT_SKIP;
	if (!errno_is_denial(-ret))
		return 2;
	return securityfs_events_count("authority=37 transition=43") > before ?
	       0 : 2;
}

static int kernel_log_write_without_authority_denied(void)
{
	static const char msg[] = "hdn restricted kernel log write probe\n";
	unsigned int before;
	int saved_errno;
	ssize_t written;
	int fd;

	before = securityfs_events_count("authority=84 transition=96");

	fd = open(HDN_DEV_KMSG, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT || errno == ENODEV)
			return KSFT_SKIP;
		return 2;
	}

	errno = 0;
	written = write(fd, msg, sizeof(msg) - 1);
	saved_errno = errno;
	close(fd);

	if (written >= 0)
		return 1;
	if (!errno_is_denial(saved_errno))
		return 2;

	return securityfs_events_count("authority=84 transition=96") > before ?
	       0 : 2;
}

static int module_autoload_context_reported(void)
{
	char buf[1024];
	int saved_errno;
	int fd;
	int ret;

	(void)unlink(HDN_MODPROBE_CONTEXT_CAPTURE);

	errno = 0;
	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_SCTP);
	saved_errno = errno;
	if (fd >= 0) {
		close(fd);
		return 1;
	}
	if (saved_errno != EPROTONOSUPPORT &&
	    saved_errno != ESOCKTNOSUPPORT &&
	    saved_errno != EAFNOSUPPORT)
		return 2;

	ret = read_text_file_small(HDN_MODPROBE_CONTEXT_CAPTURE, buf,
				   sizeof(buf));
	(void)unlink(HDN_MODPROBE_CONTEXT_CAPTURE);
	if (ret)
		return 2;

	return strstr(buf, "argv1=-q\n") &&
	       strstr(buf, "argv2=--\n") &&
	       strstr(buf, "argv3=net-pf-2-proto-132") &&
	       strstr(buf, "HDN_MODULE_REQUEST=net-pf-2-proto-132") &&
	       strstr(buf, "HDN_MODULE_UID=0\n") &&
	       strstr(buf, "HDN_MODULE_EUID=0\n") &&
	       strstr(buf, "HDN_MODULE_PROFILE=2\n") ? 0 : 1;
}

static int debugfs_access_denied(void)
{
	char buf[1];
	int fd;
	int ret;

	errno = 0;
	fd = open(HDN_DEBUGFS_KPROBES, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT || errno == ENOTDIR)
			return KSFT_SKIP;
		return errno_is_denial(errno) ? 0 : 2;
	}

	errno = 0;
	ret = read(fd, buf, sizeof(buf));
	close(fd);
	if (ret >= 0)
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int tracefs_access_denied(void)
{
	char buf[1];
	int fd;
	int ret;

	errno = 0;
	fd = open(HDN_TRACEFS_TRACING_ON, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT || errno == ENOTDIR)
			return KSFT_SKIP;
		return errno_is_denial(errno) ? 0 : 2;
	}

	errno = 0;
	ret = read(fd, buf, sizeof(buf));
	close(fd);
	if (ret >= 0)
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int tracefs_basic_access_allowed(void)
{
	int fd;

	errno = 0;
	fd = open(HDN_TRACEFS_TRACING_ON, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return errno == ENOENT || errno == ENOTDIR ? KSFT_SKIP : 2;

	close(fd);
	return 0;
}

static int tracefs_available_symbols_denied(void)
{
	char buf[1];
	int saved_errno;
	int fd;
	int ret;

	ret = tracefs_basic_access_allowed();
	if (ret)
		return ret;

	errno = 0;
	fd = open(HDN_TRACEFS_AVAILABLE_FILTER_FUNCTIONS,
		  O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT || errno == ENOTDIR)
			return 0;
		return errno_is_denial(errno) ? 0 : 2;
	}

	errno = 0;
	ret = read(fd, buf, sizeof(buf));
	saved_errno = errno;
	close(fd);
	if (ret >= 0)
		return 1;

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int tracefs_kprobe_symbol_lookup_denied(void)
{
	static const char probe[] =
		"p:hdn_symbol_lookup_gate hdn_missing_symbol_for_gate\n";
	static const char cleanup[] = "-:hdn_symbol_lookup_gate\n";
	int saved_errno;
	int fd;
	int ret;

	ret = tracefs_basic_access_allowed();
	if (ret)
		return ret;

	errno = 0;
	fd = open(HDN_TRACEFS_KPROBE_EVENTS, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT || errno == ENOTDIR)
			return KSFT_SKIP;
		return 2;
	}

	errno = 0;
	ret = write(fd, probe, sizeof(probe) - 1);
	saved_errno = errno;
	if (ret >= 0)
		(void)write(fd, cleanup, sizeof(cleanup) - 1);
	close(fd);
	if (ret >= 0)
		return 1;

	return errno_is_denial(saved_errno) ? 0 : 1;
}

static int install_kprobe_fixture(void)
{
	static const char cleanup[] = "-:" HDN_TRACE_SYMBOL_KPROBE_EVENT "\n";
	static const char * const candidates[] = {
		"vfs_read",
		"ksys_read",
		"__x64_sys_getpid",
		"security_file_open",
	};
	char probe[128];
	size_t i;
	int fd;

	errno = 0;
	fd = open(HDN_TRACEFS_KPROBE_EVENTS, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT || errno == ENOTDIR)
			return KSFT_SKIP;
		return 2;
	}

	(void)write(fd, cleanup, sizeof(cleanup) - 1);
	for (i = 0; i < ARRAY_SIZE(candidates); i++) {
		int len;

		len = snprintf(probe, sizeof(probe), "p:%s %s\n",
			       HDN_TRACE_SYMBOL_KPROBE_EVENT, candidates[i]);
		if (len <= 0 || (size_t)len >= sizeof(probe)) {
			close(fd);
			return 2;
		}
		if (write(fd, probe, len) == len) {
			close(fd);
			hdn_trace_symbol_kprobe_installed = true;
			return 0;
		}
	}

	close(fd);
	return 1;
}

static void cleanup_numeric_kprobe_fixture(void)
{
	static const char cleanup[] = "-:" HDN_TRACE_SYMBOL_KPROBE_EVENT "\n";
	int fd;

	if (!hdn_trace_symbol_kprobe_installed)
		return;

	fd = open(HDN_TRACEFS_KPROBE_EVENTS, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return;
	(void)write(fd, cleanup, sizeof(cleanup) - 1);
	close(fd);
	hdn_trace_symbol_kprobe_installed = false;
}

static int kprobe_list_symbols_hidden(void)
{
	char buf[2048] = {};
	int fd;
	ssize_t len;

	if (!hdn_trace_symbol_kprobe_installed)
		return KSFT_SKIP;

	errno = 0;
	fd = open(HDN_DEBUGFS_KPROBES, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT || errno == ENOTDIR)
			return KSFT_SKIP;
		return 2;
	}

	errno = 0;
	len = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (len < 0)
		return 2;
	if (!len)
		return 1;

	if (!strstr(buf, "[hidden]"))
		return 1;
	if (strstr(buf, "__x64_sys") || strstr(buf, "ksys_") ||
	    strstr(buf, "vfs_") || strstr(buf, "security_"))
		return 1;

	return 0;
}

static int kprobe_blacklist_symbols_hidden(void)
{
	char buf[1024] = {};
	int fd;
	ssize_t len;

	errno = 0;
	fd = open(HDN_DEBUGFS_KPROBES_BLACKLIST, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT || errno == ENOTDIR)
			return KSFT_SKIP;
		return 2;
	}

	errno = 0;
	len = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (len < 0)
		return 2;
	if (!len)
		return KSFT_SKIP;

	if (!strstr(buf, "[hidden]"))
		return 1;
	if (strstr(buf, "entry") || strstr(buf, "text") || strstr(buf, "do_"))
		return 1;

	return 0;
}

static void report_child_result(int result, const char *description)
{
	if (result == KSFT_SKIP)
		ksft_test_result_skip("%s\n", description);
	else
		ksft_test_result(!result, "%s\n", description);
}

static int forked_child_result(int (*fn)(void))
{
	int status;
	pid_t child;

	child = fork();
	if (child < 0)
		return 2;

	if (!child)
		_exit(fn());

	if (waitpid(child, &status, 0) < 0)
		return 2;
	if (!WIFEXITED(status))
		return 2;

	return WEXITSTATUS(status);
}

static void report_forked_child_result(int (*fn)(void),
				       const char *description)
{
	int status;
	pid_t child;

	child = fork();
	if (child < 0) {
		ksft_test_result_fail("%s fork failed: %s\n", description,
				      strerror(errno));
		return;
	}

	if (!child)
		_exit(fn());

	if (waitpid(child, &status, 0) < 0) {
		ksft_test_result_fail("%s waitpid failed: %s\n", description,
				      strerror(errno));
		return;
	}

	if (!WIFEXITED(status)) {
		ksft_test_result_fail("%s child terminated unexpectedly\n",
				      description);
		return;
	}

	report_child_result(WEXITSTATUS(status), description);
}

static void report_killed_child_result(int (*fn)(void),
				       const char *description)
{
	int status;
	pid_t child;

	child = fork();
	if (child < 0) {
		ksft_test_result_fail("%s fork failed: %s\n", description,
				      strerror(errno));
		return;
	}

	if (!child)
		_exit(fn());

	if (waitpid(child, &status, 0) < 0) {
		ksft_test_result_fail("%s waitpid failed: %s\n", description,
				      strerror(errno));
		return;
	}

	ksft_test_result(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
			 "%s\n", description);
}

static pid_t spawn_ptrace_target_exec(const char *path, bool drop_creds)
{
	int sync_pipe[2];
	char ready;
	pid_t child;

	if (pipe(sync_pipe))
		return -1;

	child = fork();
	if (child < 0) {
		close(sync_pipe[0]);
		close(sync_pipe[1]);
		return -1;
	}

	if (!child) {
		close(sync_pipe[0]);
		if (drop_creds &&
		    (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY)))
			_exit(2);
		if (dup2(sync_pipe[1], 3) < 0)
			_exit(2);
		if (sync_pipe[1] != 3)
			close(sync_pipe[1]);
		execl(path, "hdn_smoke", "--ptrace-target", NULL);
		_exit(2);
	}

	close(sync_pipe[1]);
	if (read(sync_pipe[0], &ready, sizeof(ready)) != sizeof(ready)) {
		close(sync_pipe[0]);
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		return -1;
	}
	close(sync_pipe[0]);

	return child;
}

static pid_t spawn_nobody_ptrace_target_exec(const char *path)
{
	return spawn_ptrace_target_exec(path, true);
}

static pid_t spawn_nobody_ptrace_target(void)
{
	return spawn_nobody_ptrace_target_exec("/hdn_smoke");
}

static pid_t spawn_same_uid_ptrace_target(void)
{
	return spawn_ptrace_target_exec("/hdn_smoke", false);
}

static int ptrace_attach_result(bool same_uid)
{
	int saved_errno = 0;
	int status;
	pid_t child;
	long ret;

	child = same_uid ? spawn_same_uid_ptrace_target() :
			   spawn_nobody_ptrace_target();
	if (child < 0)
		return 2;

	errno = 0;
	ret = ptrace(PTRACE_ATTACH, child, NULL, NULL);
	if (ret)
		saved_errno = errno;

	if (!ret) {
		waitpid(child, &status, WUNTRACED);
		ptrace(PTRACE_DETACH, child, NULL, NULL);
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		return 1;
	}

	kill(child, SIGKILL);
	waitpid(child, NULL, 0);
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int ptrace_attach_denied(void)
{
	return ptrace_attach_result(false);
}

static int ptrace_attach_same_uid_denied(void)
{
	return ptrace_attach_result(true);
}

static int proc_root_disclosed_without_ptrace(void)
{
	char path[64];
	pid_t child;
	int fd;

	child = spawn_same_uid_ptrace_target();
	if (child < 0)
		return 2;

	snprintf(path, sizeof(path), "/proc/%d/root", child);
	fd = open(path, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (fd >= 0)
		close(fd);

	kill(child, SIGKILL);
	waitpid(child, NULL, 0);
	return fd >= 0 ? 0 : 1;
}

static int run_proc_reader(const char *operation)
{
	int status;
	pid_t child;

	child = fork();
	if (child < 0)
		return 2;
	if (!child) {
		execl(HDN_PROC_READER_EXEC, HDN_PROC_READER_EXEC, operation, NULL);
		_exit(2);
	}

	if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status))
		return 2;
	return WEXITSTATUS(status);
}

static int object_ptrace_denied(void)
{
	int saved_errno = 0;
	int status;
	pid_t child;
	long ret;

	child = spawn_nobody_ptrace_target_exec(HDN_OBJECT_PTRACE_TARGET_EXEC);
	if (child < 0)
		return 2;

	errno = 0;
	ret = ptrace(PTRACE_ATTACH, child, NULL, NULL);
	if (ret)
		saved_errno = errno;

	if (!ret) {
		waitpid(child, &status, WUNTRACED);
		ptrace(PTRACE_DETACH, child, NULL, NULL);
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		return 1;
	}

	kill(child, SIGKILL);
	waitpid(child, NULL, 0);
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static void test_ptrace_audit_event_logged(void)
{
	const char *needle = "authority=8 transition=9 action=3";
	unsigned int before;
	int status;
	pid_t child;
	long ret;

	child = spawn_nobody_ptrace_target();
	if (child < 0) {
		ksft_test_result_fail("ptrace audit target failed\n");
		return;
	}

	before = securityfs_events_count(needle);
	errno = 0;
	ret = ptrace(PTRACE_ATTACH, child, NULL, NULL);
	if (!ret)
		waitpid(child, &status, WUNTRACED);

	ksft_test_result(!ret && securityfs_events_count(needle) > before,
			 "hardening events report ptrace attach audit\n");

	if (!ret)
		ptrace(PTRACE_DETACH, child, NULL, NULL);
	kill(child, SIGKILL);
	waitpid(child, NULL, 0);
}

static pid_t spawn_nobody_signal_target(void)
{
	int sync_pipe[2];
	char ready = 'R';
	pid_t child;

	if (pipe(sync_pipe))
		return -1;

	child = fork();
	if (child < 0) {
		close(sync_pipe[0]);
		close(sync_pipe[1]);
		return -1;
	}

	if (!child) {
		close(sync_pipe[0]);
		if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
			_exit(2);
		if (write(sync_pipe[1], &ready, sizeof(ready)) !=
		    sizeof(ready))
			_exit(2);
		close(sync_pipe[1]);
		for (;;)
			pause();
	}

	close(sync_pipe[1]);
	if (read(sync_pipe[0], &ready, sizeof(ready)) != sizeof(ready)) {
		close(sync_pipe[0]);
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		return -1;
	}
	close(sync_pipe[0]);

	return child;
}

static int signal_cross_profile_denied(void)
{
	int saved_errno = 0;
	int status;
	int ret;
	pid_t killer;
	pid_t target;

	target = spawn_nobody_signal_target();
	if (target < 0)
		return 2;

	killer = fork();
	if (killer < 0) {
		kill(target, SIGKILL);
		waitpid(target, NULL, 0);
		return 2;
	}

	if (!killer) {
		errno = 0;
		ret = kill(target, SIGTERM);
		if (ret)
			saved_errno = errno;
		_exit(ret && errno_is_denial(saved_errno) ? 0 :
		      !ret ? 1 : 2);
	}

	if (waitpid(killer, &status, 0) < 0) {
		kill(target, SIGKILL);
		waitpid(target, NULL, 0);
		return 2;
	}

	kill(target, SIGKILL);
	waitpid(target, NULL, 0);

	if (!WIFEXITED(status))
		return 2;
	return WEXITSTATUS(status);
}

static int signal_direct_child_allowed(void)
{
	int saved_errno = 0;
	int status;
	pid_t target;

	target = spawn_nobody_signal_target();
	if (target < 0)
		return 2;

	errno = 0;
	if (kill(target, SIGTERM)) {
		saved_errno = errno;
		kill(target, SIGKILL);
		waitpid(target, NULL, 0);
		return errno_is_denial(saved_errno) ? 1 : 2;
	}

	if (waitpid(target, &status, 0) < 0)
		return 2;

	return WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM ? 0 : 1;
}

static int pidfd_open_sibling_result(bool expect_allowed)
{
	int saved_errno = 0;
	int status;
	pid_t opener;
	pid_t target;

	target = spawn_nobody_ptrace_target();
	if (target < 0)
		return 2;

	opener = fork();
	if (opener < 0) {
		kill(target, SIGKILL);
		waitpid(target, NULL, 0);
		return 2;
	}

	if (!opener) {
		int fd;

		errno = 0;
		fd = syscall(__NR_pidfd_open, target, 0);
		if (fd < 0)
			saved_errno = errno;
		else
			close(fd);

		if (expect_allowed)
			_exit(fd >= 0 ? 0 :
			      saved_errno == ENOSYS ? KSFT_SKIP : 1);
		_exit(fd >= 0 ? 1 :
		      saved_errno == ENOSYS ? KSFT_SKIP :
		      errno_is_denial(saved_errno) ? 0 : 2);
	}

	if (waitpid(opener, &status, 0) < 0) {
		kill(target, SIGKILL);
		waitpid(target, NULL, 0);
		return 2;
	}

	kill(target, SIGKILL);
	waitpid(target, NULL, 0);

	if (!WIFEXITED(status))
		return 2;
	return WEXITSTATUS(status);
}

static int pidfd_open_cross_profile_denied(void)
{
	return pidfd_open_sibling_result(false);
}

static int pidfd_open_proc_task_allowed(void)
{
	return pidfd_open_sibling_result(true);
}

static int join_proc_task_group(void)
{
	gid_t groups[] = { HDN_PROC_TASK_GID };

	return setgroups(ARRAY_SIZE(groups), groups) ? 2 : 0;
}

static int pidfd_open_proc_task_gid_allowed(void)
{
	int ret;

	ret = join_proc_task_group();
	if (ret)
		return ret;

	return pidfd_open_proc_task_allowed();
}

static int send_fd_over_socket(int sock, int fd)
{
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(fd))];
	} cmsg = {};
	char byte = 'F';
	struct iovec iov = {
		.iov_base = &byte,
		.iov_len = sizeof(byte),
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cmsg.buf,
		.msg_controllen = sizeof(cmsg.buf),
	};
	struct cmsghdr *hdr;

	hdr = CMSG_FIRSTHDR(&msg);
	hdr->cmsg_level = SOL_SOCKET;
	hdr->cmsg_type = SCM_RIGHTS;
	hdr->cmsg_len = CMSG_LEN(sizeof(fd));
	memcpy(CMSG_DATA(hdr), &fd, sizeof(fd));

	return sendmsg(sock, &msg, 0) == sizeof(byte) ? 0 : -1;
}

static int recv_fd_with_flags_over_socket(int sock, int *msg_flags)
{
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(int))];
	} cmsg = {};
	char byte;
	struct iovec iov = {
		.iov_base = &byte,
		.iov_len = sizeof(byte),
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cmsg.buf,
		.msg_controllen = sizeof(cmsg.buf),
	};
	struct cmsghdr *hdr;
	int fd = -1;

	if (recvmsg(sock, &msg, 0) != sizeof(byte))
		return -1;
	if (msg_flags)
		*msg_flags = msg.msg_flags;

	hdr = CMSG_FIRSTHDR(&msg);
	if (!hdr || hdr->cmsg_level != SOL_SOCKET ||
	    hdr->cmsg_type != SCM_RIGHTS ||
	    hdr->cmsg_len < CMSG_LEN(sizeof(fd)))
		return -1;

	memcpy(&fd, CMSG_DATA(hdr), sizeof(fd));
	return fd;
}

static int recv_fd_over_socket(int sock)
{
	return recv_fd_with_flags_over_socket(sock, NULL);
}

static int object_receive_fd_result(const char *path, bool expect_allowed)
{
	int saved_errno = 0;
	int msg_flags = 0;
	int status;
	int sv[2];
	int fd;
	int ret;
	pid_t child;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv))
		return 2;

	child = fork();
	if (child < 0) {
		close(sv[0]);
		close(sv[1]);
		return 2;
	}

	if (!child) {
		int got;

		close(sv[0]);
		errno = 0;
		got = recv_fd_with_flags_over_socket(sv[1], &msg_flags);
		saved_errno = errno;
		close(sv[1]);

		if (got >= 0) {
			ret = read_fd_once(got);
			close(got);
			if (!expect_allowed)
				_exit(1);
			_exit(ret ? 2 : 0);
		}

		if (expect_allowed)
			_exit(1);
		if (errno_is_denial(saved_errno))
			_exit(0);
		_exit(!saved_errno && (msg_flags & MSG_CTRUNC) ? 0 : 2);
	}

	close(sv[1]);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		close(sv[0]);
		waitpid(child, NULL, 0);
		return 2;
	}

	ret = send_fd_over_socket(sv[0], fd);
	close(fd);
	close(sv[0]);
	if (ret) {
		waitpid(child, NULL, 0);
		return 2;
	}

	if (waitpid(child, &status, 0) < 0)
		return 2;
	if (!WIFEXITED(status))
		return 2;
	return WEXITSTATUS(status);
}

static int object_receive_denied(void)
{
	return object_receive_fd_result(HDN_OBJECT_RECEIVE_PROTECTED, false);
}

static int object_receive_unmatched_allowed(void)
{
	return object_receive_fd_result(HDN_OBJECT_RECEIVE_UNPROTECTED, true);
}

static int object_tree_receive_denied(void)
{
	return object_receive_fd_result(HDN_OBJECT_TREE_RECEIVE, false);
}

static int object_tree_receive_unmatched_allowed(void)
{
	return object_receive_fd_result(HDN_OBJECT_TREE_RECEIVE_UNMATCHED,
					true);
}

static int object_fcntl_dup_result(const char *path, bool expect_allowed)
{
	int saved_errno = 0;
	int dup;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 2;

	errno = 0;
	dup = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	saved_errno = errno;
	close(fd);

	if (dup >= 0) {
		close(dup);
		return expect_allowed ? 0 : 1;
	}

	if (expect_allowed)
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_fcntl_dup_denied(void)
{
	return object_fcntl_dup_result(HDN_OBJECT_FCNTL_PROTECTED, false);
}

static int object_fcntl_unmatched_dup_allowed(void)
{
	return object_fcntl_dup_result(HDN_OBJECT_FCNTL_UNPROTECTED, true);
}

static int object_fcntl_ioctl_flag_result(const char *path, bool expect_allowed)
{
	int saved_errno = 0;
	int fd;
	int ret;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return 2;

	errno = 0;
	ret = ioctl(fd, FIOCLEX);
	saved_errno = errno;
	close(fd);

	if (!ret)
		return expect_allowed ? 0 : 1;

	if (expect_allowed)
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_fcntl_ioctl_flag_denied(void)
{
	return object_fcntl_ioctl_flag_result(HDN_OBJECT_FCNTL_PROTECTED,
					      false);
}

static int object_fcntl_ioctl_flag_unmatched_allowed(void)
{
	return object_fcntl_ioctl_flag_result(HDN_OBJECT_FCNTL_UNPROTECTED,
					      true);
}

static int object_fcntl_setfl_result(const char *path, bool expect_allowed)
{
	int saved_errno = 0;
	int flags;
	int fd;
	int ret;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 2;

	flags = fcntl(fd, F_GETFL);
	if (flags < 0) {
		close(fd);
		return 2;
	}

	errno = 0;
	ret = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	saved_errno = errno;
	close(fd);

	if (!ret)
		return expect_allowed ? 0 : 1;

	if (expect_allowed)
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_fcntl_setfl_denied(void)
{
	return object_fcntl_setfl_result(HDN_OBJECT_FCNTL_PROTECTED, false);
}

static int object_fcntl_setfl_unmatched_allowed(void)
{
	return object_fcntl_setfl_result(HDN_OBJECT_FCNTL_UNPROTECTED, true);
}

static int object_fcntl_setfd_result(const char *path, bool expect_allowed)
{
	int saved_errno = 0;
	int fd;
	int ret;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 2;

	errno = 0;
	ret = fcntl(fd, F_SETFD, FD_CLOEXEC);
	saved_errno = errno;
	close(fd);

	if (!ret)
		return expect_allowed ? 0 : 1;

	if (expect_allowed)
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_fcntl_setfd_denied(void)
{
	return object_fcntl_setfd_result(HDN_OBJECT_FCNTL_PROTECTED, false);
}

static int object_fcntl_setfd_unmatched_allowed(void)
{
	return object_fcntl_setfd_result(HDN_OBJECT_FCNTL_UNPROTECTED, true);
}

static int object_fcntl_setown_result(const char *path, bool expect_allowed)
{
#if !defined(F_SETOWN)
	return KSFT_SKIP;
#else
	int saved_errno = 0;
	int fd;
	int ret;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 2;

	errno = 0;
	ret = fcntl(fd, F_SETOWN, getpid());
	saved_errno = errno;
	close(fd);

	if (!ret)
		return expect_allowed ? 0 : 1;

	if (expect_allowed)
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 2;
#endif
}

static int object_fcntl_setown_denied(void)
{
	return object_fcntl_setown_result(HDN_OBJECT_FCNTL_PROTECTED, false);
}

static int object_fcntl_setown_unmatched_allowed(void)
{
	return object_fcntl_setown_result(HDN_OBJECT_FCNTL_UNPROTECTED, true);
}

static int object_fcntl_setown_ex_result(const char *path, bool expect_allowed)
{
	struct hdn_f_owner_ex {
		int type;
		pid_t pid;
	} owner = {
		.type = F_OWNER_PID,
		.pid = getpid(),
	};
	int saved_errno = 0;
	int fd;
	int ret;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 2;

	errno = 0;
	ret = fcntl(fd, F_SETOWN_EX, &owner);
	saved_errno = errno;
	close(fd);

	if (!ret)
		return expect_allowed ? 0 : 1;

	if (expect_allowed)
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_fcntl_setown_ex_denied(void)
{
	return object_fcntl_setown_ex_result(HDN_OBJECT_FCNTL_PROTECTED, false);
}

static int object_fcntl_setown_ex_unmatched_allowed(void)
{
	return object_fcntl_setown_ex_result(HDN_OBJECT_FCNTL_UNPROTECTED, true);
}

static int object_fcntl_setsig_result(const char *path, bool expect_allowed)
{
#if !defined(F_SETSIG)
	return KSFT_SKIP;
#else
	int saved_errno = 0;
	int fd;
	int ret;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 2;

	errno = 0;
	ret = fcntl(fd, F_SETSIG, SIGUSR1);
	saved_errno = errno;
	close(fd);

	if (!ret)
		return expect_allowed ? 0 : 1;

	if (expect_allowed)
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 2;
#endif
}

static int object_fcntl_setsig_denied(void)
{
	return object_fcntl_setsig_result(HDN_OBJECT_FCNTL_PROTECTED, false);
}

static int object_fcntl_setsig_unmatched_allowed(void)
{
	return object_fcntl_setsig_result(HDN_OBJECT_FCNTL_UNPROTECTED, true);
}

static int object_fcntl_query_allowed(void)
{
	int fd;
	int ret;

	fd = open(HDN_OBJECT_FCNTL_PROTECTED, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 2;

	ret = fcntl(fd, F_GETFL);
	close(fd);
	return ret >= 0 ? 0 : 2;
}

static int object_chdir_path(const char *path, bool expect_denied)
{
	int rootfd;
	int saved_errno;
	int ret;

	rootfd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (rootfd < 0)
		return 2;

	errno = 0;
	ret = chdir(path);
	saved_errno = errno;
	if (!ret) {
		ret = fchdir(rootfd);
		close(rootfd);
		if (ret)
			return 2;
		return expect_denied ? 1 : 0;
	}

	close(rootfd);
	if (expect_denied)
		return errno_is_denial(saved_errno) ? 0 : 2;
	return 2;
}

static int object_chdir_denied(void)
{
	return object_chdir_path(HDN_OBJECT_CHDIR_PROTECTED_DIR, true);
}

static int object_chdir_unmatched_allowed(void)
{
	return object_chdir_path(HDN_OBJECT_CHDIR_UNPROTECTED_DIR, false);
}

static int object_preopened_fchdir_denied(int fd)
{
	int saved_errno;

	if (fd < 0)
		return 2;

	errno = 0;
	if (!fchdir(fd))
		return 1;
	saved_errno = errno;

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_tree_exec_denied(void)
{
	return object_exec_path(HDN_OBJECT_TREE_OPS_EXEC, true);
}

static int object_tree_exec_unmatched_allowed(void)
{
	return object_exec_path(HDN_OBJECT_TREE_OPS_EXEC_UNMATCHED, false);
}

static int object_tree_link_source_denied(void)
{
	unlink(HDN_OBJECT_TREE_OPS_LINK_TARGET);
	if (!link(HDN_OBJECT_TREE_OPS_LINK_SOURCE,
		  HDN_OBJECT_TREE_OPS_LINK_TARGET)) {
		unlink(HDN_OBJECT_TREE_OPS_LINK_TARGET);
		return 1;
	}

	return errno_is_denial(errno) ? 0 : 2;
}

static int object_tree_link_source_unmatched_allowed(void)
{
	unlink(HDN_OBJECT_TREE_OPS_LINK_TARGET_UNMATCHED);
	if (link(HDN_OBJECT_TREE_OPS_LINK_SOURCE_UNMATCHED,
		 HDN_OBJECT_TREE_OPS_LINK_TARGET_UNMATCHED))
		return 2;

	unlink(HDN_OBJECT_TREE_OPS_LINK_TARGET_UNMATCHED);
	return 0;
}

static int object_tree_link_target_denied(void)
{
	int saved_errno;

	unlink(HDN_OBJECT_TREE_OPS_LINK_TARGET_PATH);
	errno = 0;
	if (!link(HDN_OBJECT_LINK_UNPROTECTED,
		  HDN_OBJECT_TREE_OPS_LINK_TARGET_PATH)) {
		unlink(HDN_OBJECT_TREE_OPS_LINK_TARGET_PATH);
		return 1;
	}
	saved_errno = errno;

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_tree_link_target_create_allowed(void)
{
	int ret;

	unlink(HDN_OBJECT_TREE_OPS_LINK_TARGET_CREATE);
	ret = write_created_text_file(HDN_OBJECT_TREE_OPS_LINK_TARGET_CREATE,
				      "ordinary create under link-target tree policy\n");
	if (ret)
		return 2;
	return unlink(HDN_OBJECT_TREE_OPS_LINK_TARGET_CREATE) ? 2 : 0;
}

static int object_tree_link_target_unmatched_allowed(void)
{
	unlink(HDN_OBJECT_TREE_OPS_LINK_TARGET_UNMATCHED_PATH);
	if (link(HDN_OBJECT_LINK_UNPROTECTED,
		 HDN_OBJECT_TREE_OPS_LINK_TARGET_UNMATCHED_PATH))
		return 2;

	return unlink(HDN_OBJECT_TREE_OPS_LINK_TARGET_UNMATCHED_PATH) ? 2 : 0;
}

static int object_tree_ioctl_denied(void)
{
	return object_ioctl_path(HDN_OBJECT_TREE_OPS_IOCTL, true);
}

static int object_tree_ioctl_unmatched_allowed(void)
{
	return object_ioctl_path(HDN_OBJECT_TREE_OPS_IOCTL_UNMATCHED, false);
}

static int object_tree_lock_denied(void)
{
	return object_lock_path(HDN_OBJECT_TREE_OPS_LOCK, false, true);
}

static int object_tree_lock_unmatched_allowed(void)
{
	return object_lock_path(HDN_OBJECT_TREE_OPS_LOCK_UNMATCHED, false,
				false);
}

static int object_tree_watch_denied(void)
{
	return object_watch_path(HDN_OBJECT_TREE_OPS_WATCH, true);
}

static int object_tree_watch_unmatched_allowed(void)
{
	return object_watch_path(HDN_OBJECT_TREE_OPS_WATCH_UNMATCHED, false);
}

static int object_tree_fcntl_dup_denied(void)
{
	return object_fcntl_dup_result(HDN_OBJECT_TREE_OPS_FCNTL, false);
}

static int object_tree_fcntl_dup_unmatched_allowed(void)
{
	return object_fcntl_dup_result(HDN_OBJECT_TREE_OPS_FCNTL_UNMATCHED,
				       true);
}

static int object_tree_chdir_denied(void)
{
	return object_chdir_path(HDN_OBJECT_TREE_OPS_CHDIR, true);
}

static int object_tree_chdir_unmatched_allowed(void)
{
	return object_chdir_path(HDN_OBJECT_TREE_OPS_CHDIR_UNMATCHED, false);
}

static int object_tree_preopened_fchdir_denied(int fd)
{
	return object_preopened_fchdir_denied(fd);
}

static int object_tree_preopened_fchdir_unmatched_allowed(int fd)
{
	int rootfd;
	int ret;

	if (fd < 0)
		return 2;

	rootfd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (rootfd < 0)
		return 2;

	ret = fchdir(fd);
	if (ret) {
		close(rootfd);
		return 2;
	}

	ret = fchdir(rootfd);
	close(rootfd);
	return ret ? 2 : 0;
}

static int object_tree_truncate_denied(void)
{
	int saved_errno;

	errno = 0;
	if (!truncate(HDN_OBJECT_TREE_OPS_TRUNCATE, 0))
		return 1;
	saved_errno = errno;

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_tree_truncate_unmatched_allowed(void)
{
	if (write_text_file(HDN_OBJECT_TREE_OPS_TRUNCATE_UNMATCHED,
			    "unmatched tree truncate target\n"))
		return 2;
	return truncate(HDN_OBJECT_TREE_OPS_TRUNCATE_UNMATCHED, 0) ? 2 : 0;
}

static int object_tree_preopened_ftruncate_denied(int fd)
{
	return object_truncate_ftruncate_denied(fd);
}

static int object_tree_preopened_ftruncate_unmatched_allowed(int fd)
{
	if (fd < 0)
		return 2;

	return ftruncate(fd, 0) ? 2 : 0;
}

static int object_tree_rename_denied(void)
{
	int saved_errno;

	unlink(HDN_OBJECT_TREE_OPS_RENAME_TARGET);
	errno = 0;
	if (!rename(HDN_OBJECT_TREE_OPS_RENAME,
		    HDN_OBJECT_TREE_OPS_RENAME_TARGET)) {
		rename(HDN_OBJECT_TREE_OPS_RENAME_TARGET,
		       HDN_OBJECT_TREE_OPS_RENAME);
		return 1;
	}
	saved_errno = errno;

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_tree_rename_unmatched_allowed(void)
{
	unlink(HDN_OBJECT_TREE_OPS_RENAME_TARGET_UNMATCHED);
	if (write_text_file(HDN_OBJECT_TREE_OPS_RENAME_UNMATCHED,
			    "unmatched tree rename target\n"))
		return 2;
	if (rename(HDN_OBJECT_TREE_OPS_RENAME_UNMATCHED,
		   HDN_OBJECT_TREE_OPS_RENAME_TARGET_UNMATCHED))
		return 2;
	if (rename(HDN_OBJECT_TREE_OPS_RENAME_TARGET_UNMATCHED,
		   HDN_OBJECT_TREE_OPS_RENAME_UNMATCHED))
		return 2;

	return 0;
}

static int object_tree_rename_target_denied(void)
{
	int saved_errno;
	int ret;

	unlink(HDN_OBJECT_TREE_OPS_RENAME_TARGET_SOURCE);
	unlink(HDN_OBJECT_TREE_OPS_RENAME_TARGET_PATH);
	ret = write_created_text_file(
		HDN_OBJECT_TREE_OPS_RENAME_TARGET_SOURCE,
		"rename target tree source\n");
	if (ret)
		return 2;

	errno = 0;
	if (!rename(HDN_OBJECT_TREE_OPS_RENAME_TARGET_SOURCE,
		    HDN_OBJECT_TREE_OPS_RENAME_TARGET_PATH)) {
		unlink(HDN_OBJECT_TREE_OPS_RENAME_TARGET_PATH);
		return 1;
	}
	saved_errno = errno;
	unlink(HDN_OBJECT_TREE_OPS_RENAME_TARGET_SOURCE);

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int object_tree_rename_target_create_allowed(void)
{
	int ret;

	unlink(HDN_OBJECT_TREE_OPS_RENAME_TARGET_CREATE);
	ret = write_created_text_file(
		HDN_OBJECT_TREE_OPS_RENAME_TARGET_CREATE,
		"ordinary create under rename-target tree policy\n");
	if (ret)
		return 2;
	return unlink(HDN_OBJECT_TREE_OPS_RENAME_TARGET_CREATE) ? 2 : 0;
}

static int object_tree_rename_target_unmatched_allowed(void)
{
	int ret;

	unlink(HDN_OBJECT_TREE_OPS_RENAME_TARGET_UNMATCHED_SOURCE);
	unlink(HDN_OBJECT_TREE_OPS_RENAME_TARGET_UNMATCHED_PATH);
	ret = write_created_text_file(
		HDN_OBJECT_TREE_OPS_RENAME_TARGET_UNMATCHED_SOURCE,
		"unmatched rename target tree source\n");
	if (ret)
		return 2;
	if (rename(HDN_OBJECT_TREE_OPS_RENAME_TARGET_UNMATCHED_SOURCE,
		   HDN_OBJECT_TREE_OPS_RENAME_TARGET_UNMATCHED_PATH))
		return 2;
	if (rename(HDN_OBJECT_TREE_OPS_RENAME_TARGET_UNMATCHED_PATH,
		   HDN_OBJECT_TREE_OPS_RENAME_TARGET_UNMATCHED_SOURCE))
		return 2;

	return unlink(HDN_OBJECT_TREE_OPS_RENAME_TARGET_UNMATCHED_SOURCE) ? 2 : 0;
}

static int object_tree_unix_connect_denied(void)
{
	return object_unix_connect_result(HDN_OBJECT_TREE_OPS_UNIX_CONNECT,
					  false);
}

static int object_tree_unix_connect_unmatched_allowed(void)
{
	return object_unix_connect_result(
		HDN_OBJECT_TREE_OPS_UNIX_CONNECT_UNMATCHED, true);
}

static int object_tree_chmod_denied(void)
{
	if (!chmod(HDN_OBJECT_TREE_META_CHMOD, 0600))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_tree_chown_denied(void)
{
	if (!chown(HDN_OBJECT_TREE_META_CHOWN, 65534, 65534))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_tree_utime_denied(void)
{
	struct timespec times[2] = {
		{ .tv_sec = 1700000100, .tv_nsec = 0 },
		{ .tv_sec = 1700000100, .tv_nsec = 0 },
	};

	if (!utimensat(AT_FDCWD, HDN_OBJECT_TREE_META_UTIME, times, 0))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_tree_setxattr_denied(void)
{
	struct vfs_cap_data caps;

	init_test_file_caps(&caps);
	if (!setxattr(HDN_OBJECT_TREE_META_SETXATTR, XATTR_NAME_CAPS, &caps,
		      XATTR_CAPS_SZ_2, 0))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_tree_removexattr_denied(void)
{
	if (!removexattr(HDN_OBJECT_TREE_META_REMOVEXATTR, XATTR_NAME_CAPS))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int object_tree_xattr_get_denied(void)
{
	return object_xattr_get_path(HDN_OBJECT_TREE_META_XATTR, true);
}

static int object_tree_xattr_list_denied(void)
{
	return object_xattr_list_path(HDN_OBJECT_TREE_META_XATTR, true);
}

static int object_tree_unix_bind_denied(void)
{
	return object_unix_bind_result(HDN_OBJECT_TREE_IPC_BIND, false);
}

static int object_tree_unix_listen_denied(int fd)
{
	return object_unix_listen_result(fd, false);
}

static int object_tree_unix_accept_denied(int fd)
{
	return object_unix_accept_result(fd, HDN_OBJECT_TREE_IPC_ACCEPT, false);
}

static int object_tree_unix_send_denied(void)
{
	return object_unix_send_result(HDN_OBJECT_TREE_IPC_SEND, false);
}

static int object_tree_unix_connected_send_denied(int fd)
{
	return object_unix_connected_send_result(fd, false);
}

static int object_tree_unix_recv_denied(int fd)
{
	return object_unix_recv_result(fd, HDN_OBJECT_TREE_IPC_RECV, false);
}

static int object_fchdir_unmatched_allowed(void)
{
	int rootfd;
	int fd;
	int ret;

	rootfd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (rootfd < 0)
		return 2;
	fd = open(HDN_OBJECT_CHDIR_UNPROTECTED_DIR,
		  O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0) {
		close(rootfd);
		return 2;
	}

	ret = fchdir(fd);
	close(fd);
	if (ret) {
		close(rootfd);
		return 2;
	}

	ret = fchdir(rootfd);
	close(rootfd);
	return ret ? 2 : 0;
}

static int object_mount_path(const char *path, bool expect_denied)
{
	int saved_errno;
	int ret;

	errno = 0;
	ret = mount("none", path, "tmpfs", 0, "size=4k");
	saved_errno = errno;
	if (!ret) {
		ret = umount(path);
		if (ret)
			return 2;
		return expect_denied ? 1 : 0;
	}

	if (expect_denied)
		return errno_is_denial(saved_errno) ? 0 : 2;
	return 2;
}

static int object_mount_denied(void)
{
	return object_mount_path(HDN_OBJECT_MOUNT_PROTECTED_DIR, true);
}

static int object_mount_unmatched_allowed(void)
{
	return object_mount_path(HDN_OBJECT_MOUNT_UNPROTECTED_DIR, false);
}

static int object_move_mount_path(const char *source, const char *target,
				  bool expect_denied)
{
#ifdef __NR_move_mount
	int saved_errno;
	int ret;

	umount(source);
	umount(target);

	if (mount("none", source, "tmpfs", 0, "size=4k"))
		return 2;

	errno = 0;
	ret = syscall(__NR_move_mount, AT_FDCWD, source, AT_FDCWD, target, 0);
	saved_errno = errno;
	if (!ret) {
		ret = umount(target);
		if (ret)
			return 2;
		return expect_denied ? 1 : 0;
	}

	ret = umount(source);
	if (ret)
		return 2;
	if (expect_denied)
		return errno_is_denial(saved_errno) ? 0 : 2;
	return 2;
#else
	return KSFT_SKIP;
#endif
}

static int object_move_mount_denied(void)
{
	return object_move_mount_path(HDN_OBJECT_MOVE_MOUNT_SOURCE_DENIED,
				      HDN_OBJECT_MOUNT_PROTECTED_DIR, true);
}

static int object_move_mount_unmatched_allowed(void)
{
	return object_move_mount_path(HDN_OBJECT_MOVE_MOUNT_SOURCE_ALLOWED,
				      HDN_OBJECT_MOUNT_UNPROTECTED_DIR,
				      false);
}

static void cleanup_object_mount_source_fixtures(void)
{
	umount(HDN_OBJECT_MOVE_MOUNT_SOURCE_DENIED);
	umount(HDN_OBJECT_MOVE_MOUNT_SOURCE_ALLOWED);
	umount(HDN_OBJECT_MOUNT_SOURCE_PROTECTED);
	umount(HDN_OBJECT_MOUNT_SOURCE_UNPROTECTED);
	umount(HDN_OBJECT_MOVE_MOUNT_SOURCE_TARGET_DENIED);
	umount(HDN_OBJECT_MOVE_MOUNT_SOURCE_TARGET_ALLOWED);
}

static int setup_object_mount_source_fixtures(void)
{
	cleanup_object_mount_source_fixtures();

	if (mount("none", HDN_OBJECT_MOUNT_SOURCE_PROTECTED, "tmpfs", 0,
		  "size=4k"))
		return -errno;
	if (mount("none", HDN_OBJECT_MOUNT_SOURCE_UNPROTECTED, "tmpfs", 0,
		  "size=4k")) {
		int saved_errno = errno;

		umount(HDN_OBJECT_MOUNT_SOURCE_PROTECTED);
		return -saved_errno;
	}

	return 0;
}

static int object_prepared_move_mount_path(const char *source,
					   const char *target,
					   bool expect_denied)
{
#ifdef __NR_move_mount
	int saved_errno;
	int ret;

	umount(target);

	errno = 0;
	ret = syscall(__NR_move_mount, AT_FDCWD, source, AT_FDCWD, target, 0);
	saved_errno = errno;
	if (!ret) {
		ret = umount(target);
		if (ret)
			return 2;
		return expect_denied ? 1 : 0;
	}

	if (expect_denied)
		return errno_is_denial(saved_errno) ? 0 : 2;
	return 2;
#else
	return KSFT_SKIP;
#endif
}

static int object_mount_source_denied(void)
{
	return object_prepared_move_mount_path(
		HDN_OBJECT_MOUNT_SOURCE_PROTECTED,
		HDN_OBJECT_MOVE_MOUNT_SOURCE_TARGET_DENIED, true);
}

static int object_mount_source_unmatched_allowed(void)
{
	return object_prepared_move_mount_path(
		HDN_OBJECT_MOUNT_SOURCE_UNPROTECTED,
		HDN_OBJECT_MOVE_MOUNT_SOURCE_TARGET_ALLOWED, false);
}

static void cleanup_object_umount_fixtures(void)
{
	umount(HDN_OBJECT_UMOUNT_PROTECTED_DIR);
	umount(HDN_OBJECT_UMOUNT_UNPROTECTED_DIR);
}

static int setup_object_umount_fixtures(void)
{
	cleanup_object_umount_fixtures();

	if (mount("none", HDN_OBJECT_UMOUNT_PROTECTED_DIR, "tmpfs", 0,
		  "size=4k"))
		return -errno;
	if (mount("none", HDN_OBJECT_UMOUNT_UNPROTECTED_DIR, "tmpfs", 0,
		  "size=4k")) {
		int saved_errno = errno;

		umount(HDN_OBJECT_UMOUNT_PROTECTED_DIR);
		return -saved_errno;
	}

	return 0;
}

static void cleanup_object_tree_umount_fixture(void)
{
	umount(HDN_OBJECT_TREE_UMOUNT_TARGET);
	umount(HDN_OBJECT_TREE_UMOUNT_UNMATCHED);
}

static int setup_object_tree_umount_fixture(void)
{
	cleanup_object_tree_umount_fixture();

	if (mount("none", HDN_OBJECT_TREE_UMOUNT_TARGET, "tmpfs", 0,
		  "size=4k"))
		return -errno;
	if (mount("none", HDN_OBJECT_TREE_UMOUNT_UNMATCHED, "tmpfs", 0,
		  "size=4k")) {
		int saved_errno = errno;

		umount(HDN_OBJECT_TREE_UMOUNT_TARGET);
		return -saved_errno;
	}

	return 0;
}

static int object_umount_path(const char *path, bool expect_denied)
{
	int saved_errno;
	int ret;

	errno = 0;
	ret = umount(path);
	saved_errno = errno;
	if (!ret)
		return expect_denied ? 1 : 0;

	if (expect_denied)
		return errno_is_denial(saved_errno) ? 0 : 2;
	return 2;
}

static int object_umount_denied(void)
{
	return object_umount_path(HDN_OBJECT_UMOUNT_PROTECTED_DIR, true);
}

static int object_umount_unmatched_allowed(void)
{
	return object_umount_path(HDN_OBJECT_UMOUNT_UNPROTECTED_DIR, false);
}

static int object_tree_mount_denied(void)
{
	return object_mount_path(HDN_OBJECT_TREE_MOUNT_TARGET, true);
}

static int object_tree_mount_unmatched_allowed(void)
{
	return object_mount_path(HDN_OBJECT_TREE_MOUNT_UNMATCHED, false);
}

static int object_tree_move_mount_denied(void)
{
	return object_move_mount_path(HDN_OBJECT_TREE_MOVE_MOUNT_SOURCE,
				      HDN_OBJECT_TREE_MOVE_MOUNT_TARGET, true);
}

static int object_tree_move_mount_unmatched_allowed(void)
{
	return object_move_mount_path(HDN_OBJECT_TREE_MOVE_MOUNT_SOURCE_UNMATCHED,
				      HDN_OBJECT_TREE_MOVE_MOUNT_UNMATCHED,
				      false);
}

static int object_tree_umount_denied(void)
{
	return object_umount_path(HDN_OBJECT_TREE_UMOUNT_TARGET, true);
}

static int object_tree_umount_unmatched_allowed(void)
{
	return object_umount_path(HDN_OBJECT_TREE_UMOUNT_UNMATCHED, false);
}

static int pidfd_info_received_result(bool expect_allowed)
{
	int saved_errno = 0;
	int sv[2];
	int status;
	int pidfd;
	pid_t reader;
	pid_t target;

	target = spawn_nobody_ptrace_target();
	if (target < 0)
		return 2;

	pidfd = syscall(__NR_pidfd_open, target, 0);
	if (pidfd < 0) {
		saved_errno = errno;
		kill(target, SIGKILL);
		waitpid(target, NULL, 0);
		return saved_errno == ENOSYS ? KSFT_SKIP : 2;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv)) {
		close(pidfd);
		kill(target, SIGKILL);
		waitpid(target, NULL, 0);
		return 2;
	}

	reader = fork();
	if (reader < 0) {
		close(sv[0]);
		close(sv[1]);
		close(pidfd);
		kill(target, SIGKILL);
		waitpid(target, NULL, 0);
		return 2;
	}

	if (!reader) {
		struct hdn_pidfd_info info = {
			.mask = PIDFD_INFO_SUPPORTED_MASK,
		};
		int fd;
		int ret;

		close(sv[0]);
		close(pidfd);
		fd = recv_fd_over_socket(sv[1]);
		close(sv[1]);
		if (fd < 0)
			_exit(2);

		errno = 0;
		ret = ioctl(fd, PIDFD_GET_INFO, &info);
		if (ret)
			saved_errno = errno;
		close(fd);

		if (expect_allowed)
			_exit(!ret ? 0 :
			      saved_errno == ENOTTY ? KSFT_SKIP : 1);
		_exit(!ret ? 1 :
		      saved_errno == ENOTTY ? KSFT_SKIP :
		      errno_is_denial(saved_errno) ? 0 : 2);
	}

	close(sv[1]);
	if (send_fd_over_socket(sv[0], pidfd)) {
		close(sv[0]);
		close(pidfd);
		kill(reader, SIGKILL);
		waitpid(reader, NULL, 0);
		kill(target, SIGKILL);
		waitpid(target, NULL, 0);
		return 2;
	}
	close(sv[0]);
	close(pidfd);

	if (waitpid(reader, &status, 0) < 0) {
		kill(target, SIGKILL);
		waitpid(target, NULL, 0);
		return 2;
	}

	kill(target, SIGKILL);
	waitpid(target, NULL, 0);

	if (!WIFEXITED(status))
		return 2;
	return WEXITSTATUS(status);
}

static int pidfd_info_cross_profile_denied(void)
{
	return pidfd_info_received_result(false);
}

static int pidfd_info_proc_task_allowed(void)
{
	return pidfd_info_received_result(true);
}

static int read_pidfd_fdinfo(int fd, char *buf, size_t size)
{
	char path[64];
	ssize_t len;
	int infofd;
	int saved_errno;

	if (!size)
		return -EINVAL;

	snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
	infofd = open(path, O_RDONLY | O_CLOEXEC);
	if (infofd < 0)
		return -errno;

	len = read(infofd, buf, size - 1);
	saved_errno = errno;
	close(infofd);
	if (len < 0)
		return -saved_errno;

	buf[len] = '\0';
	return 0;
}

static int pidfd_fdinfo_received_result(bool expect_allowed)
{
	int saved_errno = 0;
	int sv[2];
	int status;
	int pidfd;
	pid_t reader;
	pid_t target;

	target = spawn_nobody_ptrace_target();
	if (target < 0)
		return 2;

	pidfd = syscall(__NR_pidfd_open, target, 0);
	if (pidfd < 0) {
		saved_errno = errno;
		kill(target, SIGKILL);
		waitpid(target, NULL, 0);
		return saved_errno == ENOSYS ? KSFT_SKIP : 2;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv)) {
		close(pidfd);
		kill(target, SIGKILL);
		waitpid(target, NULL, 0);
		return 2;
	}

	reader = fork();
	if (reader < 0) {
		close(sv[0]);
		close(sv[1]);
		close(pidfd);
		kill(target, SIGKILL);
		waitpid(target, NULL, 0);
		return 2;
	}

	if (!reader) {
		char fdinfo[1024];
		char nspid_line[64];
		char pid_line[64];
		int fd;
		int ret;

		close(sv[0]);
		close(pidfd);
		fd = recv_fd_over_socket(sv[1]);
		close(sv[1]);
		if (fd < 0)
			_exit(2);

		ret = read_pidfd_fdinfo(fd, fdinfo, sizeof(fdinfo));
		close(fd);
		if (ret) {
			if (ret == -ENOENT || ret == -ENOTDIR)
				_exit(KSFT_SKIP);
			_exit(2);
		}

		snprintf(pid_line, sizeof(pid_line), "Pid:\t%d\n", target);
		snprintf(nspid_line, sizeof(nspid_line), "NSpid:\t%d", target);

		if (expect_allowed)
			_exit(strstr(fdinfo, pid_line) &&
			      strstr(fdinfo, nspid_line) ? 0 : 1);

		if (strstr(fdinfo, pid_line) || strstr(fdinfo, nspid_line))
			_exit(1);

		_exit(strstr(fdinfo, "Pid:\t0\n") &&
		      strstr(fdinfo, "NSpid:\t0") ? 0 : 1);
	}

	close(sv[1]);
	if (send_fd_over_socket(sv[0], pidfd)) {
		close(sv[0]);
		close(pidfd);
		kill(reader, SIGKILL);
		waitpid(reader, NULL, 0);
		kill(target, SIGKILL);
		waitpid(target, NULL, 0);
		return 2;
	}
	close(sv[0]);
	close(pidfd);

	if (waitpid(reader, &status, 0) < 0) {
		kill(target, SIGKILL);
		waitpid(target, NULL, 0);
		return 2;
	}

	kill(target, SIGKILL);
	waitpid(target, NULL, 0);

	if (!WIFEXITED(status))
		return 2;
	return WEXITSTATUS(status);
}

static int pidfd_fdinfo_cross_profile_redacted(void)
{
	return pidfd_fdinfo_received_result(false);
}

static int pidfd_fdinfo_proc_task_visible(void)
{
	return pidfd_fdinfo_received_result(true);
}

static int pidfd_setns_received_result(bool expect_allowed)
{
	int saved_errno = 0;
	int sv[2];
	int status;
	int pidfd;
	pid_t reader;
	pid_t target;

	target = spawn_nobody_ptrace_target();
	if (target < 0)
		return 2;

	pidfd = syscall(__NR_pidfd_open, target, 0);
	if (pidfd < 0) {
		saved_errno = errno;
		kill(target, SIGKILL);
		waitpid(target, NULL, 0);
		return saved_errno == ENOSYS ? KSFT_SKIP : 2;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv)) {
		close(pidfd);
		kill(target, SIGKILL);
		waitpid(target, NULL, 0);
		return 2;
	}

	reader = fork();
	if (reader < 0) {
		close(sv[0]);
		close(sv[1]);
		close(pidfd);
		kill(target, SIGKILL);
		waitpid(target, NULL, 0);
		return 2;
	}

	if (!reader) {
		int fd;
		int ret;

		close(sv[0]);
		close(pidfd);
		fd = recv_fd_over_socket(sv[1]);
		close(sv[1]);
		if (fd < 0)
			_exit(2);

		errno = 0;
		ret = setns(fd, CLONE_NEWUTS | CLONE_NEWIPC);
		if (ret)
			saved_errno = errno;
		close(fd);

		if (expect_allowed)
			_exit(!ret ? 0 :
			      saved_errno == EINVAL ? KSFT_SKIP : 1);
		_exit(!ret ? 1 : errno_is_denial(saved_errno) ? 0 : 2);
	}

	close(sv[1]);
	if (send_fd_over_socket(sv[0], pidfd)) {
		close(sv[0]);
		close(pidfd);
		kill(reader, SIGKILL);
		waitpid(reader, NULL, 0);
		kill(target, SIGKILL);
		waitpid(target, NULL, 0);
		return 2;
	}
	close(sv[0]);
	close(pidfd);

	if (waitpid(reader, &status, 0) < 0) {
		kill(target, SIGKILL);
		waitpid(target, NULL, 0);
		return 2;
	}

	kill(target, SIGKILL);
	waitpid(target, NULL, 0);

	if (!WIFEXITED(status))
		return 2;
	return WEXITSTATUS(status);
}

static int pidfd_setns_without_proc_task_denied(void)
{
	return pidfd_setns_received_result(false);
}

static int pidfd_setns_with_proc_task_allowed(void)
{
	return pidfd_setns_received_result(true);
}

static int pidfd_namespace_received_result(bool expect_allowed)
{
	int saved_errno = 0;
	int sv[2];
	int status;
	int pidfd;
	pid_t reader;
	pid_t target;

	target = spawn_nobody_ptrace_target();
	if (target < 0)
		return 2;

	pidfd = syscall(__NR_pidfd_open, target, 0);
	if (pidfd < 0) {
		saved_errno = errno;
		kill(target, SIGKILL);
		waitpid(target, NULL, 0);
		return saved_errno == ENOSYS ? KSFT_SKIP : 2;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv)) {
		close(pidfd);
		kill(target, SIGKILL);
		waitpid(target, NULL, 0);
		return 2;
	}

	reader = fork();
	if (reader < 0) {
		close(sv[0]);
		close(sv[1]);
		close(pidfd);
		kill(target, SIGKILL);
		waitpid(target, NULL, 0);
		return 2;
	}

	if (!reader) {
		int nsfd;
		int fd;

		close(sv[0]);
		close(pidfd);
		fd = recv_fd_over_socket(sv[1]);
		close(sv[1]);
		if (fd < 0)
			_exit(2);

		errno = 0;
		nsfd = ioctl(fd, PIDFD_GET_UTS_NAMESPACE, 0);
		if (nsfd < 0) {
			saved_errno = errno;
		} else {
			close(nsfd);
		}
		close(fd);

		if (expect_allowed)
			_exit(nsfd >= 0 ? 0 :
			      saved_errno == ENOTTY ||
			      saved_errno == EINVAL ||
			      saved_errno == EOPNOTSUPP ? KSFT_SKIP : 1);
		_exit(nsfd >= 0 ? 1 :
		      saved_errno == ENOTTY ||
		      saved_errno == EINVAL ||
		      saved_errno == EOPNOTSUPP ? KSFT_SKIP :
		      errno_is_denial(saved_errno) ? 0 : 2);
	}

	close(sv[1]);
	if (send_fd_over_socket(sv[0], pidfd)) {
		close(sv[0]);
		close(pidfd);
		kill(reader, SIGKILL);
		waitpid(reader, NULL, 0);
		kill(target, SIGKILL);
		waitpid(target, NULL, 0);
		return 2;
	}
	close(sv[0]);
	close(pidfd);

	if (waitpid(reader, &status, 0) < 0) {
		kill(target, SIGKILL);
		waitpid(target, NULL, 0);
		return 2;
	}

	kill(target, SIGKILL);
	waitpid(target, NULL, 0);

	if (!WIFEXITED(status))
		return 2;
	return WEXITSTATUS(status);
}

static int pidfd_namespace_without_proc_task_denied(void)
{
	return pidfd_namespace_received_result(false);
}

static int pidfd_namespace_with_proc_task_allowed(void)
{
	return pidfd_namespace_received_result(true);
}

static int proc_mem_profile_denied(void)
{
	int saved_errno = 0;
	char path[64];
	pid_t child;
	int fd;

	child = spawn_nobody_ptrace_target();
	if (child < 0)
		return 2;

	snprintf(path, sizeof(path), "/proc/%d/mem", child);
	errno = 0;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		close(fd);
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		return 1;
	}
	saved_errno = errno;

	kill(child, SIGKILL);
	waitpid(child, NULL, 0);
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int process_memory_target_child(int sync_fd)
{
	unsigned long addr;
	long page_size;
	void *mapping;

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0)
		return 2;

	mapping = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mapping == MAP_FAILED)
		return 2;

	memcpy(mapping, HDN_PROCESS_MEMORY_SENTINEL,
	       sizeof(HDN_PROCESS_MEMORY_SENTINEL));
	addr = (unsigned long)mapping;
	if (write(sync_fd, &addr, sizeof(addr)) != sizeof(addr))
		return 2;
	close(sync_fd);

	for (;;)
		pause();
}

static pid_t spawn_process_memory_target(bool nobody, unsigned long *addr)
{
	int sync_pipe[2];
	pid_t child;

	if (pipe(sync_pipe))
		return -1;

	child = fork();
	if (child < 0) {
		close(sync_pipe[0]);
		close(sync_pipe[1]);
		return -1;
	}

	if (!child) {
		close(sync_pipe[0]);
		if (nobody &&
		    (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY)))
			_exit(2);
		_exit(process_memory_target_child(sync_pipe[1]));
	}

	close(sync_pipe[1]);
	if (read(sync_pipe[0], addr, sizeof(*addr)) != sizeof(*addr)) {
		close(sync_pipe[0]);
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		return -1;
	}
	close(sync_pipe[0]);

	return child;
}

static ssize_t hdn_process_vm_read(pid_t pid, unsigned long addr,
				   void *buf, size_t len)
{
	struct iovec local = {
		.iov_base = buf,
		.iov_len = len,
	};
	struct iovec remote = {
		.iov_base = (void *)addr,
		.iov_len = len,
	};

	return syscall(__NR_process_vm_readv, pid, &local, 1, &remote, 1, 0);
}

static ssize_t hdn_process_vm_write(pid_t pid, unsigned long addr,
				    const void *buf, size_t len)
{
	struct iovec local = {
		.iov_base = (void *)buf,
		.iov_len = len,
	};
	struct iovec remote = {
		.iov_base = (void *)addr,
		.iov_len = len,
	};

	return syscall(__NR_process_vm_writev, pid, &local, 1, &remote, 1, 0);
}

static int process_vm_read_cross_profile_denied(void)
{
	int saved_errno = 0;
	unsigned long addr;
	char buf[sizeof(HDN_PROCESS_MEMORY_SENTINEL)];
	ssize_t ret;
	pid_t child;

	child = spawn_process_memory_target(true, &addr);
	if (child < 0)
		return 2;

	errno = 0;
	ret = hdn_process_vm_read(child, addr, buf, sizeof(buf));
	if (ret < 0)
		saved_errno = errno;

	kill(child, SIGKILL);
	waitpid(child, NULL, 0);

	if (ret >= 0)
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int process_vm_write_cross_profile_denied(void)
{
	static const char value[] = "hdn-process-memory-write";
	int saved_errno = 0;
	unsigned long addr;
	ssize_t ret;
	pid_t child;

	child = spawn_process_memory_target(true, &addr);
	if (child < 0)
		return 2;

	errno = 0;
	ret = hdn_process_vm_write(child, addr, value, sizeof(value));
	if (ret < 0)
		saved_errno = errno;

	kill(child, SIGKILL);
	waitpid(child, NULL, 0);

	if (ret >= 0)
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int process_vm_read_same_profile_allowed(void)
{
	unsigned long addr;
	char buf[sizeof(HDN_PROCESS_MEMORY_SENTINEL)] = {};
	ssize_t ret;
	pid_t child;

	child = spawn_process_memory_target(false, &addr);
	if (child < 0)
		return 2;

	ret = hdn_process_vm_read(child, addr, buf, sizeof(buf));
	kill(child, SIGKILL);
	waitpid(child, NULL, 0);

	if (ret != sizeof(buf))
		return 1;
	return memcmp(buf, HDN_PROCESS_MEMORY_SENTINEL, sizeof(buf)) ? 1 : 0;
}

static int process_madvise_cross_profile_denied(void)
{
	int saved_errno = 0;
	unsigned long addr;
	long page_size;
	struct iovec remote;
	long ret;
	int pidfd;
	pid_t child;

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0)
		return 2;

	child = spawn_process_memory_target(true, &addr);
	if (child < 0)
		return 2;

	pidfd = syscall(__NR_pidfd_open, child, 0);
	if (pidfd < 0) {
		saved_errno = errno;
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		return saved_errno == ENOSYS ? KSFT_SKIP : 2;
	}

	remote.iov_base = (void *)addr;
	remote.iov_len = page_size;

	errno = 0;
	ret = syscall(__NR_process_madvise, pidfd, &remote, 1, MADV_COLD, 0);
	if (ret < 0)
		saved_errno = errno;
	close(pidfd);

	kill(child, SIGKILL);
	waitpid(child, NULL, 0);

	if (ret >= 0)
		return 1;
	if (saved_errno == ENOSYS)
		return KSFT_SKIP;
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int process_mrelease_cross_profile_denied(void)
{
	int saved_errno = 0;
	unsigned long addr;
	long ret;
	int pidfd;
	pid_t child;

	child = spawn_process_memory_target(true, &addr);
	if (child < 0)
		return 2;

	pidfd = syscall(__NR_pidfd_open, child, 0);
	if (pidfd < 0) {
		saved_errno = errno;
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		return saved_errno == ENOSYS ? KSFT_SKIP : 2;
	}

	errno = 0;
	ret = syscall(__NR_process_mrelease, pidfd, 0);
	if (ret < 0)
		saved_errno = errno;
	close(pidfd);

	kill(child, SIGKILL);
	waitpid(child, NULL, 0);

	if (ret >= 0)
		return 1;
	if (saved_errno == ENOSYS)
		return KSFT_SKIP;
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int move_pages_cross_profile_denied(void)
{
	const void *page;
	int saved_errno = 0;
	unsigned long addr;
	int status = 0;
	long ret;
	pid_t child;

	child = spawn_process_memory_target(true, &addr);
	if (child < 0)
		return 2;

	page = (void *)addr;
	errno = 0;
	ret = syscall(__NR_move_pages, child, 1UL, &page, NULL, &status, 0);
	if (ret < 0)
		saved_errno = errno;

	kill(child, SIGKILL);
	waitpid(child, NULL, 0);

	if (ret >= 0)
		return 1;
	if (saved_errno == ENOSYS)
		return KSFT_SKIP;
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int move_pages_same_profile_allowed(void)
{
	const void *page;
	int saved_errno = 0;
	unsigned long addr;
	int status = 0;
	long ret;
	pid_t child;

	child = spawn_process_memory_target(false, &addr);
	if (child < 0)
		return 2;

	page = (void *)addr;
	errno = 0;
	ret = syscall(__NR_move_pages, child, 1UL, &page, NULL, &status, 0);
	if (ret < 0)
		saved_errno = errno;

	kill(child, SIGKILL);
	waitpid(child, NULL, 0);

	if (!ret)
		return 0;
	return saved_errno == ENOSYS ? KSFT_SKIP : 1;
}

static int migrate_pages_cross_profile_denied(void)
{
	int saved_errno = 0;
	unsigned long old_nodes = 1;
	unsigned long new_nodes = 1;
	unsigned long maxnode = sizeof(unsigned long) * CHAR_BIT;
	unsigned long addr;
	long ret;
	pid_t child;

	child = spawn_process_memory_target(true, &addr);
	if (child < 0)
		return 2;

	errno = 0;
	ret = syscall(__NR_migrate_pages, child, maxnode, &old_nodes,
		      &new_nodes);
	if (ret < 0)
		saved_errno = errno;

	kill(child, SIGKILL);
	waitpid(child, NULL, 0);

	if (ret >= 0)
		return 1;
	if (saved_errno == ENOSYS)
		return KSFT_SKIP;
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int process_fd_target_child(int sync_fd)
{
	int fd;

	fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 2;

	if (write(sync_fd, &fd, sizeof(fd)) != sizeof(fd))
		return 2;
	close(sync_fd);

	for (;;)
		pause();
}

static pid_t spawn_process_fd_target(bool nobody, int *remote_fd)
{
	int sync_pipe[2];
	pid_t child;

	if (pipe(sync_pipe))
		return -1;

	child = fork();
	if (child < 0) {
		close(sync_pipe[0]);
		close(sync_pipe[1]);
		return -1;
	}

	if (!child) {
		close(sync_pipe[0]);
		if (nobody &&
		    (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY)))
			_exit(2);
		_exit(process_fd_target_child(sync_pipe[1]));
	}

	close(sync_pipe[1]);
	if (read(sync_pipe[0], remote_fd, sizeof(*remote_fd)) !=
	    sizeof(*remote_fd)) {
		close(sync_pipe[0]);
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		return -1;
	}
	close(sync_pipe[0]);

	return child;
}

static int pidfd_getfd_cross_profile_denied(void)
{
	int saved_errno = 0;
	int remote_fd;
	int pidfd;
	int fd;
	pid_t child;

	child = spawn_process_fd_target(true, &remote_fd);
	if (child < 0)
		return 2;

	pidfd = syscall(__NR_pidfd_open, child, 0);
	if (pidfd < 0) {
		saved_errno = errno;
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		return saved_errno == ENOSYS ? KSFT_SKIP : 2;
	}

	errno = 0;
	fd = syscall(__NR_pidfd_getfd, pidfd, remote_fd, 0);
	if (fd < 0)
		saved_errno = errno;
	close(pidfd);

	kill(child, SIGKILL);
	waitpid(child, NULL, 0);

	if (fd >= 0) {
		close(fd);
		return 1;
	}
	if (saved_errno == ENOSYS)
		return KSFT_SKIP;
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int pidfd_getfd_same_profile_allowed(void)
{
	int saved_errno = 0;
	int remote_fd;
	int pidfd;
	int fd;
	pid_t child;

	child = spawn_process_fd_target(false, &remote_fd);
	if (child < 0)
		return 2;

	pidfd = syscall(__NR_pidfd_open, child, 0);
	if (pidfd < 0) {
		saved_errno = errno;
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		return saved_errno == ENOSYS ? KSFT_SKIP : 2;
	}

	errno = 0;
	fd = syscall(__NR_pidfd_getfd, pidfd, remote_fd, 0);
	if (fd < 0)
		saved_errno = errno;
	close(pidfd);

	kill(child, SIGKILL);
	waitpid(child, NULL, 0);

	if (fd >= 0) {
		close(fd);
		return 0;
	}
	return saved_errno == ENOSYS ? KSFT_SKIP : 1;
}

static int execute_only_target_main(void)
{
	unsigned long addr;
	size_t page_size = sysconf(_SC_PAGESIZE);
	void *mapping;
	int fd;

	fd = open("/hdn_smoke", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 2;

	mapping = mmap(NULL, page_size, PROT_EXEC, MAP_PRIVATE, fd, 0);
	close(fd);
	if (mapping == MAP_FAILED)
		return 2;

	addr = (unsigned long)mapping;
	if (write(3, &addr, sizeof(addr)) != sizeof(addr))
		return 2;
	close(3);

	for (;;)
		pause();
}

static pid_t spawn_execute_only_target(unsigned long *addr)
{
	int sync_pipe[2];
	pid_t child;

	if (pipe(sync_pipe))
		return -1;

	child = fork();
	if (child < 0) {
		close(sync_pipe[0]);
		close(sync_pipe[1]);
		return -1;
	}

	if (!child) {
		close(sync_pipe[0]);
		if (dup2(sync_pipe[1], 3) < 0)
			_exit(2);
		if (sync_pipe[1] != 3)
			close(sync_pipe[1]);
		execl("/hdn_smoke", "hdn_smoke", "--exec-only-target", NULL);
		_exit(2);
	}

	close(sync_pipe[1]);
	if (read(sync_pipe[0], addr, sizeof(*addr)) != sizeof(*addr)) {
		close(sync_pipe[0]);
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		return -1;
	}
	close(sync_pipe[0]);

	return child;
}

static int attach_execute_only_target(pid_t child)
{
	int status;

	if (ptrace(PTRACE_ATTACH, child, NULL, NULL))
		return -errno;
	if (waitpid(child, &status, WUNTRACED) < 0)
		return -errno;
	if (!WIFSTOPPED(status))
		return -ESRCH;

	return 0;
}

static void cleanup_execute_only_target(pid_t child, bool attached)
{
	if (attached)
		ptrace(PTRACE_DETACH, child, NULL, NULL);
	kill(child, SIGKILL);
	waitpid(child, NULL, 0);
}

static int ptrace_execute_only_read_denied(void)
{
	unsigned long addr = 0;
	bool attached = false;
	int saved_errno = 0;
	pid_t child;
	long ret;

	child = spawn_execute_only_target(&addr);
	if (child < 0)
		return 2;

	ret = attach_execute_only_target(child);
	if (ret) {
		cleanup_execute_only_target(child, false);
		return 2;
	}
	attached = true;

	errno = 0;
	ret = ptrace(PTRACE_PEEKDATA, child, (void *)addr, NULL);
	if (ret < 0)
		saved_errno = errno;

	cleanup_execute_only_target(child, attached);
	if (ret >= 0)
		return 1;
	return errno_is_denial(saved_errno) || saved_errno == EIO ? 0 : 2;
}

static int proc_mem_execute_only_read_denied(void)
{
	unsigned long addr = 0;
	char path[64];
	bool attached = false;
	int saved_errno = 0;
	pid_t child;
	ssize_t ret;
	char word[sizeof(long)];
	int fd;

	child = spawn_execute_only_target(&addr);
	if (child < 0)
		return 2;

	ret = attach_execute_only_target(child);
	if (ret) {
		cleanup_execute_only_target(child, false);
		return 2;
	}
	attached = true;

	snprintf(path, sizeof(path), "/proc/%d/mem", child);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		cleanup_execute_only_target(child, attached);
		return 2;
	}

	errno = 0;
	ret = pread(fd, word, sizeof(word), (off_t)addr);
	if (ret < 0)
		saved_errno = errno;
	close(fd);

	cleanup_execute_only_target(child, attached);
	if (ret >= 0)
		return 1;
	return errno_is_denial(saved_errno) || saved_errno == EIO ? 0 : 2;
}

static int proc_pid_visibility_denied(void)
{
	char path[64];
	char pid_name[32];
	struct dirent *de;
	bool found = false;
	int saved_errno = 0;
	pid_t child;
	DIR *dir;
	int fd;

	child = spawn_nobody_ptrace_target();
	if (child < 0)
		return 2;

	snprintf(path, sizeof(path), "/proc/%d/status", child);
	snprintf(pid_name, sizeof(pid_name), "%d", child);
	errno = 0;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		close(fd);
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		return 1;
	}
	saved_errno = errno;
	if (saved_errno != ENOENT && !errno_is_denial(saved_errno)) {
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		return 2;
	}

	errno = 0;
	dir = opendir("/proc");
	if (!dir) {
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		return 2;
	}
	while ((de = readdir(dir))) {
		if (!strcmp(de->d_name, pid_name)) {
			found = true;
			break;
		}
	}
	saved_errno = errno;
	closedir(dir);

	kill(child, SIGKILL);
	waitpid(child, NULL, 0);
	if (saved_errno)
		return 2;

	return found ? 1 : 0;
}

static void cleanup_proc_gid_mount_test(void)
{
	umount(HDN_PROC_GID_MOUNT);
	rmdir(HDN_PROC_GID_MOUNT);
}

static int setup_proc_gid_mount_test(void)
{
	int ret;

	cleanup_proc_gid_mount_test();
	if (mkdir(HDN_PROC_GID_MOUNT, 0700) && errno != EEXIST)
		return -errno;

	errno = 0;
	if (mount("proc", HDN_PROC_GID_MOUNT, "proc", 0,
		  "hidepid=2,gid=0")) {
		ret = -errno;
		cleanup_proc_gid_mount_test();
		return ret == -ENODEV ? KSFT_SKIP : ret;
	}

	return 0;
}

static int proc_pid_gid_mount_visible(void)
{
	char path[PATH_MAX];
	char pid_name[32];
	struct dirent *de;
	bool found = false;
	int saved_errno = 0;
	pid_t child;
	DIR *dir;
	int fd;

	if (access(HDN_PROC_GID_MOUNT, R_OK))
		return KSFT_SKIP;

	child = spawn_nobody_ptrace_target();
	if (child < 0)
		return 2;

	snprintf(path, sizeof(path), "%s/%d/status", HDN_PROC_GID_MOUNT,
		 child);
	snprintf(pid_name, sizeof(pid_name), "%d", child);
	errno = 0;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		saved_errno = errno;
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		return saved_errno == ENOENT || errno_is_denial(saved_errno) ?
		       1 : 2;
	}
	close(fd);

	dir = opendir(HDN_PROC_GID_MOUNT);
	if (!dir) {
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		return 2;
	}

	errno = 0;
	while ((de = readdir(dir))) {
		if (!strcmp(de->d_name, pid_name)) {
			found = true;
			break;
		}
	}
	saved_errno = errno;
	closedir(dir);

	kill(child, SIGKILL);
	waitpid(child, NULL, 0);
	if (saved_errno)
		return 2;

	return found ? 0 : 1;
}

static int proc_pid_visibility_allowed(void)
{
	char path[64];
	char pid_name[32];
	struct dirent *de;
	bool found = false;
	pid_t child;
	DIR *dir;
	int fd;

	child = spawn_nobody_ptrace_target();
	if (child < 0)
		return 2;

	snprintf(path, sizeof(path), "/proc/%d/status", child);
	snprintf(pid_name, sizeof(pid_name), "%d", child);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		return 1;
	}
	close(fd);

	dir = opendir("/proc");
	if (!dir) {
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		return 2;
	}
	errno = 0;
	while ((de = readdir(dir))) {
		if (!strcmp(de->d_name, pid_name)) {
			found = true;
			break;
		}
	}
	closedir(dir);

	kill(child, SIGKILL);
	waitpid(child, NULL, 0);
	return found ? 0 : 1;
}

static int proc_pid_visibility_gid_allowed(void)
{
	int ret;

	ret = join_proc_task_group();
	if (ret)
		return ret;

	return proc_pid_visibility_allowed();
}

static bool proc_task_dir_metadata_matches(const struct stat *st)
{
	return S_ISDIR(st->st_mode) &&
	       (st->st_mode & 0777) ==
		       (S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP) &&
	       st->st_gid == HDN_PROC_TASK_GID;
}

static int proc_task_dir_metadata_check(const char *path)
{
	struct stat st;

	if (stat(path, &st)) {
		ksft_print_msg("proc task metadata stat failed: path=%s errno=%d\n",
			       path, errno);
		return 2;
	}
	if (!proc_task_dir_metadata_matches(&st)) {
		ksft_print_msg("proc task metadata mismatch: path=%s mode=%03o gid=%u\n",
			       path, (unsigned int)(st.st_mode & 0777),
			       (unsigned int)st.st_gid);
		return 1;
	}

	return 0;
}

static int proc_task_directory_modes_restricted(void)
{
	char path[64];
	pid_t child;
	int ret = 0;

	child = fork();
	if (child < 0)
		return 2;
	if (!child) {
		for (;;)
			pause();
		_exit(0);
	}

	snprintf(path, sizeof(path), "/proc/%d", child);
	ret = proc_task_dir_metadata_check(path);
	if (ret)
		goto out;

	snprintf(path, sizeof(path), "/proc/%d/task", child);
	ret = proc_task_dir_metadata_check(path);
	if (ret)
		goto out;

	snprintf(path, sizeof(path), "/proc/%d/task/%d", child, child);
	ret = proc_task_dir_metadata_check(path);

out:
	kill(child, SIGKILL);
	waitpid(child, NULL, 0);
	return ret;
}

static int mount_admin_denied(void)
{
	int saved_errno = 0;
	int ret;

	if (mkdir(HDN_MOUNT_TEST_DIR, 0700) && errno != EEXIST)
		return 2;

	errno = 0;
	ret = mount("none", HDN_MOUNT_TEST_DIR, "tmpfs", 0, "size=4k");
	if (ret)
		saved_errno = errno;

	if (!ret) {
		umount(HDN_MOUNT_TEST_DIR);
		rmdir(HDN_MOUNT_TEST_DIR);
		return 1;
	}

	rmdir(HDN_MOUNT_TEST_DIR);
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int mount_admin_allowed(void)
{
	int saved_errno = 0;
	int ret;

	if (mkdir(HDN_MOUNT_TEST_DIR, 0700) && errno != EEXIST)
		return 2;

	errno = 0;
	ret = mount("none", HDN_MOUNT_TEST_DIR, "tmpfs", 0, "size=4k");
	if (ret)
		saved_errno = errno;

	if (!ret)
		umount(HDN_MOUNT_TEST_DIR);
	rmdir(HDN_MOUNT_TEST_DIR);

	if (ret)
		return saved_errno == ENODEV ? KSFT_SKIP : 2;
	return 0;
}

static void cleanup_mount_policy_test(void)
{
	umount(HDN_MOUNT_TEST_DIR);
	rmdir(HDN_MOUNT_TEST_DIR);
}

static int mount_readonly_tmpfs(void)
{
	if (mkdir(HDN_MOUNT_TEST_DIR, 0700) && errno != EEXIST)
		return 2;

	errno = 0;
	if (mount("none", HDN_MOUNT_TEST_DIR, "tmpfs", MS_RDONLY,
		  "size=4k")) {
		int saved_errno = errno;

		cleanup_mount_policy_test();
		return saved_errno == ENODEV ? KSFT_SKIP : 2;
	}

	return 0;
}

static int mount_bind_readonly_tmpfs(void)
{
	if (mkdir(HDN_MOUNT_TEST_DIR, 0700) && errno != EEXIST)
		return 2;

	errno = 0;
	if (mount("none", HDN_MOUNT_TEST_DIR, "tmpfs", 0, "size=4k")) {
		int saved_errno = errno;

		cleanup_mount_policy_test();
		return saved_errno == ENODEV ? KSFT_SKIP : 2;
	}

	errno = 0;
	if (mount(NULL, HDN_MOUNT_TEST_DIR, NULL,
		  MS_REMOUNT | MS_BIND | MS_RDONLY, NULL)) {
		cleanup_mount_policy_test();
		return 2;
	}

	return 0;
}

static int fuse_mount_without_authority_denied(void)
{
#ifdef __NR_fsopen
	int fd;

	errno = 0;
	fd = syscall(__NR_fsopen, "fuse", 0);
	if (fd >= 0) {
		close(fd);
		return 1;
	}
	if (errno == ENODEV)
		return KSFT_SKIP;
	return errno_is_denial(errno) ? 0 : 2;
#else
	return KSFT_SKIP;
#endif
}

static int rofs_remount_without_authority_denied(void)
{
	int saved_errno;
	int ret;

	ret = mount_readonly_tmpfs();
	if (ret)
		return ret;

	errno = 0;
	ret = mount("none", HDN_MOUNT_TEST_DIR, "tmpfs", MS_REMOUNT,
		    "size=4k");
	saved_errno = errno;
	cleanup_mount_policy_test();

	if (!ret)
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int rofs_mount_setattr_without_authority_denied(void)
{
#ifdef __NR_mount_setattr
	struct mount_attr attr = {
		.attr_clr = MOUNT_ATTR_RDONLY,
	};
	int saved_errno;
	int ret;

	ret = mount_bind_readonly_tmpfs();
	if (ret)
		return ret;

	errno = 0;
	ret = syscall(__NR_mount_setattr, AT_FDCWD, HDN_MOUNT_TEST_DIR, 0,
		      &attr, sizeof(attr));
	saved_errno = errno;
	cleanup_mount_policy_test();

	if (!ret)
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 2;
#else
	return KSFT_SKIP;
#endif
}

static int writable_mount_without_rofs_relax_denied(void)
{
	int saved_errno;
	int ret;

	if (mkdir(HDN_MOUNT_TEST_DIR, 0700) && errno != EEXIST)
		return 2;

	errno = 0;
	ret = mount("none", HDN_MOUNT_TEST_DIR, "tmpfs", 0, "size=4k");
	saved_errno = errno;

	if (!ret) {
		cleanup_mount_policy_test();
		return 1;
	}

	rmdir(HDN_MOUNT_TEST_DIR);
	if (saved_errno == ENODEV)
		return KSFT_SKIP;
	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int readonly_mount_with_enforcement_allowed(void)
{
	int ret;

	ret = mount_readonly_tmpfs();
	if (ret)
		return ret;

	cleanup_mount_policy_test();
	return 0;
}

static int rofs_updater_writable_mount_sentinel(void)
{
	int saved_errno;
	int ret;

	if (!securityfs_status_has_line("current_profile: 3"))
		return 1;

	if (mkdir(HDN_MOUNT_TEST_DIR, 0700) && errno != EEXIST)
		return 2;

	errno = 0;
	ret = mount("none", HDN_MOUNT_TEST_DIR, "tmpfs", 0, "size=4k");
	saved_errno = errno;

	if (!ret) {
		cleanup_mount_policy_test();
		return 0;
	}

	rmdir(HDN_MOUNT_TEST_DIR);
	if (saved_errno == ENODEV)
		return KSFT_SKIP;
	return 2;
}

static int rofs_updater_writable_mount_allowed(void)
{
	pid_t child;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_ROFS_UPDATER_EXEC, "hdn-rofs-updater",
		      "--rofs-updater-writable-mount-sentinel", NULL);
		_exit(errno_is_denial(errno) ? 1 : 2);
	}

	return child_exit_result(child);
}

static void cleanup_product_rofs_mount(const char *dir)
{
	umount(dir);
	rmdir(dir);
}

static void cleanup_product_rofs_test(void)
{
	cleanup_product_rofs_mount(HDN_PRODUCT_ROFS_DIR);
}

static int prepare_product_rofs_mount_path(const char *dir,
					   const char *sentinel)
{
	int saved_errno;
	int fd;

	if (mkdir(dir, 0700) && errno != EEXIST)
		return 2;

	errno = 0;
	if (mount("none", dir, "tmpfs", 0, "size=4k")) {
		saved_errno = errno;
		rmdir(dir);
		return saved_errno == ENODEV ? KSFT_SKIP : 2;
	}

	fd = open(sentinel, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0) {
		cleanup_product_rofs_mount(dir);
		return 2;
	}
	if (write(fd, "mutable\n", strlen("mutable\n")) !=
	    (ssize_t)strlen("mutable\n")) {
		close(fd);
		cleanup_product_rofs_mount(dir);
		return 2;
	}
	close(fd);

	return 0;
}

static int prepare_product_rofs_mount(void)
{
	return prepare_product_rofs_mount_path(HDN_PRODUCT_ROFS_DIR,
					       HDN_PRODUCT_ROFS_SENTINEL);
}

static int product_rofs_apply_seals_mount_readonly(void)
{
	int saved_errno;
	pid_t child;
	int ret;
	int fd;

	if (access(HDN_ROFS_APPLY_EXEC, X_OK)) {
		fprintf(stderr, "product ROFS helper is not executable: %s\n",
			strerror(errno));
		cleanup_product_rofs_test();
		return KSFT_SKIP;
	}

	child = fork();
	if (child < 0) {
		cleanup_product_rofs_test();
		return 2;
	}

	if (!child) {
		execl(HDN_ROFS_APPLY_EXEC, "hdn-rofs-apply",
		      HDN_PRODUCT_ROFS_DIR, NULL);
		fprintf(stderr, "product ROFS helper exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	ret = child_exit_result(child);
	if (ret) {
		fprintf(stderr, "product ROFS helper exited with %d\n", ret);
		cleanup_product_rofs_test();
		return ret;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr, "product ROFS sentinel remained writable\n");
		close(fd);
		cleanup_product_rofs_test();
		return 1;
	}

	if (saved_errno != EROFS) {
		fprintf(stderr,
			"product ROFS sentinel write-open failed with %s\n",
			strerror(saved_errno));
		cleanup_product_rofs_test();
		return 2;
	}

	return 0;
}

static void cleanup_rofs_apply_optional_test(void)
{
	unlink(HDN_ROFS_APPLY_OPTIONAL_LIST);
	rmdir(HDN_ROFS_APPLY_OPTIONAL_NONMOUNT);
	cleanup_product_rofs_mount(HDN_ROFS_APPLY_OPTIONAL_DIR);
}

static int product_rofs_apply_optional_list_seals_required_mount(void)
{
	static const char config[] =
		"optional " HDN_ROFS_APPLY_OPTIONAL_MISSING "\n"
		"optional " HDN_ROFS_APPLY_OPTIONAL_NONMOUNT "\n"
		"required " HDN_ROFS_APPLY_OPTIONAL_DIR "\n";
	int saved_errno;
	pid_t child;
	int ret;
	int fd;

	if (access(HDN_ROFS_APPLY_EXEC, X_OK)) {
		fprintf(stderr, "product ROFS helper is not executable: %s\n",
			strerror(errno));
		cleanup_rofs_apply_optional_test();
		return KSFT_SKIP;
	}

	if (mkdir(HDN_ROFS_APPLY_OPTIONAL_NONMOUNT, 0700) &&
	    errno != EEXIST) {
		cleanup_rofs_apply_optional_test();
		return 2;
	}

	ret = write_created_text_file(HDN_ROFS_APPLY_OPTIONAL_LIST, config);
	if (ret) {
		cleanup_rofs_apply_optional_test();
		return 2;
	}

	child = fork();
	if (child < 0) {
		cleanup_rofs_apply_optional_test();
		return 2;
	}

	if (!child) {
		execl(HDN_ROFS_APPLY_EXEC, "hdn-rofs-apply", "-f",
		      HDN_ROFS_APPLY_OPTIONAL_LIST, NULL);
		_exit(2);
	}

	ret = child_exit_result(child);
	if (ret) {
		fprintf(stderr, "product ROFS optional-list helper exited with %d\n",
			ret);
		cleanup_rofs_apply_optional_test();
		return ret;
	}

	errno = 0;
	fd = open(HDN_ROFS_APPLY_OPTIONAL_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"product ROFS optional-list sentinel remained writable\n");
		close(fd);
		cleanup_rofs_apply_optional_test();
		return 1;
	}

	cleanup_rofs_apply_optional_test();
	if (saved_errno != EROFS)
		fprintf(stderr,
			"product ROFS optional-list write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static void cleanup_rofs_apply_bind_test(void)
{
	umount(HDN_ROFS_APPLY_BIND_DIR);
	unlink(HDN_ROFS_APPLY_BIND_SENTINEL);
	rmdir(HDN_ROFS_APPLY_BIND_DIR);
	unlink(HDN_ROFS_APPLY_BIND_LIST);
	unlink(HDN_ROFS_APPLY_BIND_ROOT_SENTINEL);
}

static int product_rofs_apply_bind_seals_unified_path(void)
{
	static const char config[] = "bind " HDN_ROFS_APPLY_BIND_DIR "\n";
	int saved_errno;
	pid_t child;
	int ret;
	int fd;

	if (access(HDN_ROFS_BIND_APPLY_EXEC, X_OK))
		return KSFT_SKIP;
	if (mkdir(HDN_ROFS_APPLY_BIND_DIR, 0700) && errno != EEXIST)
		return 2;
	ret = write_created_text_file(HDN_ROFS_APPLY_BIND_SENTINEL,
				      "mutable\n");
	if (!ret)
		ret = write_created_text_file(HDN_ROFS_APPLY_BIND_LIST, config);
	if (ret) {
		cleanup_rofs_apply_bind_test();
		return 2;
	}

	child = fork();
	if (child < 0) {
		cleanup_rofs_apply_bind_test();
		return 2;
	}
	if (!child) {
		execl(HDN_ROFS_BIND_APPLY_EXEC, "hdn-rofs-bind-apply", "-f",
		      HDN_ROFS_APPLY_BIND_LIST, NULL);
		_exit(2);
	}

	ret = child_exit_result(child);
	if (ret) {
		fprintf(stderr,
			"product ROFS bind-list helper exited with %d\n", ret);
		cleanup_rofs_apply_bind_test();
		return ret;
	}

	errno = 0;
	fd = open(HDN_ROFS_APPLY_BIND_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"product ROFS bind-list sentinel remained writable\n");
		close(fd);
		cleanup_rofs_apply_bind_test();
		return 1;
	}
	if (saved_errno != EROFS) {
		fprintf(stderr,
			"product ROFS bind-list write-open failed with %s\n",
			strerror(saved_errno));
		cleanup_rofs_apply_bind_test();
		return 2;
	}

	ret = write_created_text_file(HDN_ROFS_APPLY_BIND_ROOT_SENTINEL,
				      "root-writable\n");
	if (ret)
		fprintf(stderr,
			"product ROFS bind-list backing root became unwritable: %s\n",
			strerror(-ret));
	cleanup_rofs_apply_bind_test();
	return ret ? 1 : 0;
}

static int product_rofs_write_sentinel(void)
{
	int fd;

	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	if (fd < 0)
		return 2;
	if (write(fd, "updated\n", strlen("updated\n")) !=
	    (ssize_t)strlen("updated\n")) {
		close(fd);
		return 2;
	}
	close(fd);
	return 0;
}

static int product_rofs_cancel_worker(const char *pid_path)
{
	int fd;

	fd = open(pid_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return 2;
	if (dprintf(fd, "%ld\n", (long)getpid()) < 0 || fsync(fd)) {
		close(fd);
		return 2;
	}
	close(fd);

	for (;;)
		pause();
}

static int product_rofs_orphan_worker(const char *pid_path)
{
	char pid_text[64];
	int i;
	pid_t child;

	child = fork();
	if (child < 0)
		return 2;
	if (!child) {
		pid_t grandchild = fork();

		if (grandchild < 0)
			return 2;
		if (!grandchild)
			return product_rofs_cancel_worker(pid_path);
		for (;;)
			pause();
	}

	for (i = 0; i < 100; i++) {
		if (!read_text_file_small(pid_path, pid_text, sizeof(pid_text)))
			return 0;
		usleep(50000);
	}

	kill(child, SIGKILL);
	(void)waitpid(child, NULL, 0);
	return 2;
}

static bool process_is_gone_or_zombie(pid_t pid)
{
	char path[64];
	char stat_line[512];
	char *name_end;
	FILE *stream;

	snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
	stream = fopen(path, "r");
	if (!stream)
		return errno == ENOENT;
	if (!fgets(stat_line, sizeof(stat_line), stream)) {
		fclose(stream);
		return false;
	}
	fclose(stream);

	name_end = strrchr(stat_line, ')');
	return name_end && name_end[1] == ' ' &&
	       (name_end[2] == 'Z' || name_end[2] == 'X');
}

static unsigned int product_rofs_sentinel_update_count(void)
{
	unsigned char *buf = NULL;
	size_t size = 0;
	const char marker[] = "updated\n";
	const size_t marker_len = strlen(marker);
	unsigned int count = 0;
	size_t offset = 0;

	if (read_whole_file(HDN_PRODUCT_ROFS_SENTINEL, &buf, &size))
		return 0;

	while (offset < size) {
		unsigned char *match;

		match = memmem(buf + offset, size - offset, marker,
			       marker_len);
		if (!match)
			break;
		count++;
		offset = (size_t)(match - buf) + marker_len;
	}
	free(buf);
	return count;
}

static int product_rofs_transaction_updates_and_reseals(bool via_broker,
						       unsigned int min_updates,
						       bool cleanup_mount)
{
	const char *exec_path = via_broker ? HDN_ADMIN_BROKER_EXEC :
					     HDN_ROFS_TRANSACTION_EXEC;
	const char *exec_name = via_broker ? "hdn-admin-broker" :
					     "hdn-rofs-transaction";
	unsigned int update_count;
	int saved_errno;
	pid_t child;
	int ret;
	int fd;

	if (access(exec_path, X_OK)) {
		fprintf(stderr,
			"product ROFS transaction helper is not executable: %s\n",
			strerror(errno));
		if (cleanup_mount)
			cleanup_product_rofs_test();
		return KSFT_SKIP;
	}

	child = fork();
	if (child < 0) {
		if (cleanup_mount)
			cleanup_product_rofs_test();
		return 2;
	}

	if (!child) {
		if (via_broker)
			execl(exec_path, exec_name, "rofs-transaction",
			      HDN_PRODUCT_ROFS_DIR, "--", "/hdn_smoke",
			      "--product-rofs-write-sentinel", NULL);
		else
			execl(exec_path, exec_name, HDN_PRODUCT_ROFS_DIR, "--",
			      "/hdn_smoke", "--product-rofs-write-sentinel",
			      NULL);
		fprintf(stderr, "product ROFS transaction exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	ret = child_exit_result(child);
	if (ret) {
		fprintf(stderr, "product ROFS transaction exited with %d\n",
			ret);
		if (cleanup_mount)
			cleanup_product_rofs_test();
		return ret;
	}

	update_count = product_rofs_sentinel_update_count();
	if (update_count < min_updates) {
		fprintf(stderr,
			"product ROFS transaction only wrote %u sentinel updates\n",
			update_count);
		if (cleanup_mount)
			cleanup_product_rofs_test();
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"product ROFS sentinel remained writable after transaction\n");
		close(fd);
		if (cleanup_mount)
			cleanup_product_rofs_test();
		return 1;
	}

	if (cleanup_mount)
		cleanup_product_rofs_test();
	if (saved_errno != EROFS)
		fprintf(stderr,
			"post-transaction write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static int product_rofs_transaction_cancel_reseals(void)
{
	char pid_text[64];
	char *end;
	long parsed_pid = -1;
	bool worker_dead;
	int saved_errno;
	pid_t guardian;
	pid_t worker;
	int result;
	int fd;
	int i;

	unlink(HDN_PRODUCT_ROFS_CANCEL_PID);
	guardian = fork();
	if (guardian < 0)
		return 2;
	if (!guardian) {
		execl(HDN_ROFS_TRANSACTION_EXEC, "hdn-rofs-transaction",
		      HDN_PRODUCT_ROFS_DIR, "--", "/hdn_smoke",
		      "--product-rofs-cancel-worker",
		      HDN_PRODUCT_ROFS_CANCEL_PID, NULL);
		_exit(2);
	}

	for (i = 0; i < 100; i++) {
		if (!read_text_file_small(HDN_PRODUCT_ROFS_CANCEL_PID, pid_text,
					  sizeof(pid_text))) {
			errno = 0;
			parsed_pid = strtol(pid_text, &end, 10);
			if (!errno && end != pid_text && parsed_pid > 1 &&
			    parsed_pid <= INT_MAX)
				break;
		}
		usleep(50000);
	}
	if (i == 100) {
		kill(guardian, SIGKILL);
		(void)child_exit_result(guardian);
		unlink(HDN_PRODUCT_ROFS_CANCEL_PID);
		return 2;
	}
	worker = (pid_t)parsed_pid;

	if (kill(guardian, SIGTERM)) {
		kill(guardian, SIGKILL);
		(void)child_exit_result(guardian);
		kill(worker, SIGKILL);
		unlink(HDN_PRODUCT_ROFS_CANCEL_PID);
		return 2;
	}
	result = child_exit_result(guardian);

	errno = 0;
	worker_dead = kill(worker, 0) && errno == ESRCH;
	if (!worker_dead)
		kill(worker, SIGKILL);

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0)
		close(fd);
	unlink(HDN_PRODUCT_ROFS_CANCEL_PID);

	if (result == 128 + SIGTERM && worker_dead && fd < 0 &&
	    saved_errno == EROFS)
		return 0;

	fprintf(stderr,
		"canceled ROFS transaction status=%d worker_dead=%d write_errno=%s\n",
		result, worker_dead, fd < 0 ? strerror(saved_errno) : "none");
	if (fd >= 0)
		(void)product_rofs_apply_seals_mount_readonly();
	return 1;
}

static int product_rofs_transaction_stops_background_worker(void)
{
	char pid_text[64];
	char *end;
	long parsed_pid = -1;
	bool worker_stopped = false;
	int saved_errno;
	pid_t guardian;
	pid_t worker;
	int result;
	int fd;
	int i;

	unlink(HDN_PRODUCT_ROFS_ORPHAN_PID);
	guardian = fork();
	if (guardian < 0)
		return 2;
	if (!guardian) {
		execl(HDN_ROFS_TRANSACTION_EXEC, "hdn-rofs-transaction",
		      HDN_PRODUCT_ROFS_DIR, "--", "/hdn_smoke",
		      "--product-rofs-orphan-worker",
		      HDN_PRODUCT_ROFS_ORPHAN_PID, NULL);
		_exit(2);
	}

	result = child_exit_result(guardian);
	if (!read_text_file_small(HDN_PRODUCT_ROFS_ORPHAN_PID, pid_text,
				  sizeof(pid_text))) {
		errno = 0;
		parsed_pid = strtol(pid_text, &end, 10);
		if (errno || end == pid_text || parsed_pid <= 1 ||
		    parsed_pid > INT_MAX)
			parsed_pid = -1;
	}
	worker = (pid_t)parsed_pid;
	if (parsed_pid > 1) {
		for (i = 0; i < 100; i++) {
			if (process_is_gone_or_zombie(worker)) {
				worker_stopped = true;
				break;
			}
			usleep(50000);
		}
		if (!worker_stopped)
			kill(worker, SIGKILL);
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0)
		close(fd);
	unlink(HDN_PRODUCT_ROFS_ORPHAN_PID);

	if (!result && worker_stopped && fd < 0 && saved_errno == EROFS)
		return 0;

	fprintf(stderr,
		"completed ROFS transaction status=%d worker_stopped=%d write_errno=%s\n",
		result, worker_stopped, fd < 0 ? strerror(saved_errno) : "none");
	if (fd >= 0)
		(void)product_rofs_apply_seals_mount_readonly();
	return 1;
}

static int product_rofs_transaction_preserves_mount_restrictions(void)
{
	const unsigned long restrictions = MS_NOSUID | MS_NODEV | MS_NOEXEC;
	struct statvfs state;
	int ret;

	/* Force the helper through its legacy superblock remount fallback. */
	if (mount(NULL, HDN_PRODUCT_ROFS_DIR, NULL,
		  MS_REMOUNT | MS_RDONLY | restrictions, NULL)) {
		fprintf(stderr, "restricted ROFS remount failed: %s\n",
			strerror(errno));
		return 2;
	}

	ret = product_rofs_transaction_updates_and_reseals(false, 1, false);
	if (ret)
		return ret;
	if (statvfs(HDN_PRODUCT_ROFS_DIR, &state))
		return 2;
	if (!(state.f_flag & ST_RDONLY) || !(state.f_flag & ST_NOSUID) ||
	    !(state.f_flag & ST_NODEV) || !(state.f_flag & ST_NOEXEC)) {
		fprintf(stderr,
			"ROFS transaction dropped mount restrictions: flags=%#lx\n",
			(unsigned long)state.f_flag);
		return 1;
	}

	return 0;
}

static int product_rofs_broker_denied(const char *broker_path,
				      const char *broker_name,
				      const char *worker_path,
				      const char *allowed_failure,
				      unsigned int updates)
{
	int saved_errno;
	unsigned int count;
	pid_t child;
	int ret;
	int fd;

	if (access(broker_path, X_OK)) {
		fprintf(stderr,
			"product ROFS broker is not executable: %s\n",
			strerror(errno));
		return KSFT_SKIP;
	}

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(broker_path, broker_name, "rofs-transaction",
		      HDN_PRODUCT_ROFS_DIR, "--", worker_path,
		      "--product-rofs-write-sentinel", NULL);
		fprintf(stderr, "product ROFS broker exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	ret = child_exit_result(child);
	if (!ret) {
		fprintf(stderr, "product ROFS broker allowed %s\n",
			allowed_failure);
		return 1;
	}

	count = product_rofs_sentinel_update_count();
	if (count != updates) {
		fprintf(stderr,
			"product ROFS broker denial left %u sentinel updates, expected %u\n",
			count, updates);
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"product ROFS sentinel became writable after broker denial\n");
		close(fd);
		return 1;
	}

	if (saved_errno != EROFS)
		fprintf(stderr,
			"post-denial write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static int product_rofs_broker_unapproved_worker_denied(unsigned int updates)
{
	return product_rofs_broker_denied(HDN_ADMIN_BROKER_EXEC,
					  "hdn-admin-broker",
					  HDN_IDENTITY_COPY_EXEC,
					  "unapproved worker", updates);
}

static int product_rofs_broker_config_failure_denied(const char *broker_path,
						     const char *broker_name,
						     const char *failure,
						     unsigned int updates)
{
	return product_rofs_broker_denied(broker_path, broker_name, "/hdn_smoke",
					  failure, updates);
}

static int product_rofs_system_transaction_run(const char *operation,
					       const char *config_path,
					       bool dry_run)
{
	pid_t child;

	if (access(HDN_SYSTEM_TRANSACTION_EXEC, X_OK)) {
		fprintf(stderr,
			"system transaction helper is not executable: %s\n",
			strerror(errno));
		return KSFT_SKIP;
	}

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		if (config_path && dry_run)
			execl(HDN_SYSTEM_TRANSACTION_EXEC,
			      "hdn-system-transaction", "--dry-run",
			      "--config", config_path, operation, NULL);
		else if (config_path)
			execl(HDN_SYSTEM_TRANSACTION_EXEC,
			      "hdn-system-transaction", "--config", config_path,
			      operation, NULL);
		else if (dry_run)
			execl(HDN_SYSTEM_TRANSACTION_EXEC,
			      "hdn-system-transaction", "--dry-run",
			      operation, NULL);
		else
			execl(HDN_SYSTEM_TRANSACTION_EXEC,
			      "hdn-system-transaction", operation, NULL);
		fprintf(stderr, "system transaction exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int product_rofs_system_transaction_denied(const char *operation,
						  const char *config_path,
						  const char *failure,
						  unsigned int updates)
{
	int saved_errno;
	unsigned int count;
	int ret;
	int fd;

	ret = product_rofs_system_transaction_run(operation, config_path, false);
	if (ret == KSFT_SKIP)
		return ret;
	if (!ret) {
		fprintf(stderr, "system transaction allowed %s\n", failure);
		return 1;
	}
	if (ret != 1)
		return ret;

	count = product_rofs_sentinel_update_count();
	if (count != updates) {
		fprintf(stderr,
			"system transaction denial left %u sentinel updates, expected %u\n",
			count, updates);
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"system transaction denial left product mount writable\n");
		close(fd);
		return 1;
	}

	if (saved_errno != EROFS)
		fprintf(stderr,
			"post-system-transaction-denial write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static int product_rofs_system_transaction_unknown_denied(unsigned int updates)
{
	return product_rofs_system_transaction_denied("unknown-update", NULL,
						     "unknown operation",
						     updates);
}

static int product_rofs_system_transaction_unsafe_config_denied(unsigned int updates)
{
	return product_rofs_system_transaction_denied("package-update",
						     HDN_SYSTEM_TRANSACTION_UNSAFE_CONFIG,
						     "unsafe config", updates);
}

static int product_rofs_system_transaction_updates_and_reseals(unsigned int min_updates)
{
	int saved_errno;
	unsigned int count;
	int ret;
	int fd;

	count = product_rofs_sentinel_update_count();
	ret = product_rofs_system_transaction_run("package-update", NULL, true);
	if (ret == KSFT_SKIP)
		return ret;
	if (ret) {
		fprintf(stderr, "system transaction dry-run exited with %d\n",
			ret);
		return ret;
	}
	if (product_rofs_sentinel_update_count() != count) {
		fprintf(stderr, "system transaction dry-run changed sentinel\n");
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"system transaction dry-run left product mount writable\n");
		close(fd);
		return 1;
	}
	if (saved_errno != EROFS) {
		fprintf(stderr,
			"post-system-transaction-dry-run write-open failed with %s\n",
			strerror(saved_errno));
		return 2;
	}

	ret = product_rofs_system_transaction_run("package-update", NULL, false);
	if (ret) {
		fprintf(stderr, "system transaction exited with %d\n", ret);
		return ret;
	}

	count = product_rofs_sentinel_update_count();
	if (count < min_updates) {
		fprintf(stderr,
			"system transaction only wrote %u sentinel updates\n",
			count);
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"system transaction left product mount writable\n");
		close(fd);
		return 1;
	}

	if (saved_errno != EROFS)
		fprintf(stderr,
			"post-system-transaction write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static int product_rofs_package_hook_run(const char *hook,
					 const char *config_path,
					 bool dry_run)
{
	pid_t child;

	if (access(HDN_PACKAGE_HOOK_EXEC, X_OK)) {
		fprintf(stderr,
			"package hook helper is not executable: %s\n",
			strerror(errno));
		return KSFT_SKIP;
	}

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		if (config_path && dry_run)
			execl(HDN_PACKAGE_HOOK_EXEC, "hdn-package-hook",
			      "--dry-run", "--config", config_path, hook,
			      NULL);
		else if (config_path)
			execl(HDN_PACKAGE_HOOK_EXEC, "hdn-package-hook",
			      "--config", config_path, hook, NULL);
		else if (dry_run)
			execl(HDN_PACKAGE_HOOK_EXEC, "hdn-package-hook",
			      "--dry-run", hook, NULL);
		else
			execl(HDN_PACKAGE_HOOK_EXEC, "hdn-package-hook",
			      hook, NULL);
		fprintf(stderr, "package hook exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int product_rofs_package_hook_denied(const char *hook,
					    const char *config_path,
					    const char *failure,
					    unsigned int updates)
{
	int saved_errno;
	unsigned int count;
	int ret;
	int fd;

	ret = product_rofs_package_hook_run(hook, config_path, false);
	if (ret == KSFT_SKIP)
		return ret;
	if (!ret) {
		fprintf(stderr, "package hook allowed %s\n", failure);
		return 1;
	}
	if (ret != 1)
		return ret;

	count = product_rofs_sentinel_update_count();
	if (count != updates) {
		fprintf(stderr,
			"package hook denial left %u sentinel updates, expected %u\n",
			count, updates);
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"package hook denial left product mount writable\n");
		close(fd);
		return 1;
	}

	if (saved_errno != EROFS)
		fprintf(stderr,
			"post-package-hook-denial write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static int product_rofs_package_hook_unknown_denied(unsigned int updates)
{
	return product_rofs_package_hook_denied("unknown-update", NULL,
						"unknown hook", updates);
}

static int product_rofs_package_hook_unsafe_config_denied(unsigned int updates)
{
	return product_rofs_package_hook_denied("package-update",
						HDN_PACKAGE_HOOK_UNSAFE_CONFIG,
						"unsafe config", updates);
}

static int product_rofs_package_hook_updates_and_reseals(unsigned int min_updates)
{
	int saved_errno;
	unsigned int count;
	int ret;
	int fd;

	count = product_rofs_sentinel_update_count();
	ret = product_rofs_package_hook_run("package-update", NULL, true);
	if (ret == KSFT_SKIP)
		return ret;
	if (ret) {
		fprintf(stderr, "package hook dry-run exited with %d\n", ret);
		return ret;
	}
	if (product_rofs_sentinel_update_count() != count) {
		fprintf(stderr, "package hook dry-run changed sentinel\n");
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"package hook dry-run left product mount writable\n");
		close(fd);
		return 1;
	}
	if (saved_errno != EROFS) {
		fprintf(stderr,
			"post-package-hook-dry-run write-open failed with %s\n",
			strerror(saved_errno));
		return 2;
	}

	ret = product_rofs_package_hook_run("package-update", NULL, false);
	if (ret) {
		fprintf(stderr, "package hook exited with %d\n", ret);
		return ret;
	}

	count = product_rofs_sentinel_update_count();
	if (count < min_updates) {
		fprintf(stderr,
			"package hook only wrote %u sentinel updates\n",
			count);
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"package hook left product mount writable\n");
		close(fd);
		return 1;
	}

	if (saved_errno != EROFS)
		fprintf(stderr,
			"post-package-hook write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static int text_file_contains_all(const char *path, const char *needle_a,
				  const char *needle_b, const char *needle_c)
{
	unsigned char *blob = NULL;
	char *text = NULL;
	size_t size = 0;
	bool found;
	int ret;

	ret = read_whole_file(path, &blob, &size);
	if (ret) {
		fprintf(stderr, "hook snippet %s is unreadable: %s\n",
			path, strerror(-ret));
		return 1;
	}

	text = malloc(size + 1);
	if (!text) {
		free(blob);
		return 2;
	}
	memcpy(text, blob, size);
	text[size] = '\0';

	found = strstr(text, needle_a) && strstr(text, needle_b) &&
		(!needle_c || strstr(text, needle_c));
	if (!found)
		fprintf(stderr,
			"hook snippet %s is missing expected command; contents:\n%s\n",
			path, text);

	free(text);
	free(blob);
	return found ? 0 : 1;
}

static int text_file_lacks(const char *path, const char *needle)
{
	unsigned char *blob = NULL;
	char *text = NULL;
	size_t size = 0;
	bool found;
	int ret;

	ret = read_whole_file(path, &blob, &size);
	if (ret) {
		fprintf(stderr, "%s is unreadable: %s\n", path,
			strerror(-ret));
		return 1;
	}

	text = malloc(size + 1);
	if (!text) {
		free(blob);
		return 2;
	}
	memcpy(text, blob, size);
	text[size] = '\0';

	found = strstr(text, needle);
	if (found)
		fprintf(stderr, "%s unexpectedly contains %s\n", path, needle);

	free(text);
	free(blob);
	return found ? 1 : 0;
}

static int write_created_text_file(const char *path, const char *text)
{
	int fd;
	int ret;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return -errno;
	ret = write_all_fd(fd, text, strlen(text));
	close(fd);
	return ret;
}

static int policy_learner_run_fixture(const char *fixture)
{
	int status;
	int fd;
	pid_t child;
	int ret;

	if (access(HDN_POLICY_LEARN_EXEC, X_OK))
		return KSFT_SKIP;

	ret = write_created_text_file(HDN_POLICY_LEARN_EVENTS, fixture);
	if (ret)
		return 2;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		fd = open(HDN_POLICY_LEARN_OUTPUT,
			  O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
		if (fd < 0)
			_exit(2);
		if (dup2(fd, STDOUT_FILENO) < 0)
			_exit(2);
		close(fd);
		execl(HDN_POLICY_LEARN_EXEC, "hdn-policy-learn",
		      "--input", HDN_POLICY_LEARN_EVENTS, NULL);
		_exit(2);
	}

	if (waitpid(child, &status, 0) < 0)
		return 2;

	if (!WIFEXITED(status))
		return 2;
	return WEXITSTATUS(status);
}

static int policy_learner_suggests_authorities(void)
{
	const char *fixture =
		"sequence=1 profile=7 authority=4 transition=7 action=1 reason=3 error=-1 subject=0 object=0\n"
		"sequence=2 profile=7 authority=4 transition=7 action=4 reason=3 error=-1 subject=0 object=0\n"
		"sequence=3 profile=7 authority=8 transition=9 action=1 reason=7 error=-13 subject=0 object=0\n";
	int ret;

	ret = policy_learner_run_fixture(fixture);
	if (ret)
		return ret;

	return text_file_contains_all(HDN_POLICY_LEARN_OUTPUT,
				      "# HDN_LEARN_V1",
				      "allow 7 BPF_LOAD PTRACE",
				      NULL);
}

static int policy_learner_suggests_memory_flags(void)
{
	const char *fixture =
		"sequence=1 profile=7 authority=3 transition=4 action=1 reason=2 error=-13 subject=0 object=0\n"
		"sequence=2 profile=7 authority=2 transition=3 action=1 reason=12 error=-13 subject=0 object=0\n"
		"sequence=3 profile=7 authority=2 transition=3 action=1 reason=50 error=-13 subject=0 object=0\n"
		"sequence=4 profile=7 authority=3 transition=4 action=1 reason=51 error=-13 subject=0 object=0\n"
		"sequence=5 profile=7 authority=3 transition=4 action=1 reason=60 error=-13 subject=0 object=0\n";
	int ret;

	ret = policy_learner_run_fixture(fixture);
	if (ret)
		return ret;

	return text_file_contains_all(HDN_POLICY_LEARN_OUTPUT,
				      "# HDN_LEARN_V1",
				      "mem 7 ALLOW_EXEC_AFTER_WRITE ALLOW_FIXED_ANON_EXEC ALLOW_EXEC_STACK_ELF ALLOW_TEXTREL_MPROTECT ALLOW_RELRO_WRITE",
				      NULL);
}

static int policy_learner_reviews_wx_invariants(void)
{
	const char *fixture =
		"sequence=1 profile=7 authority=2 transition=3 action=4 reason=1 error=-13 subject=0 object=123\n";
	int ret;

	ret = policy_learner_run_fixture(fixture);
	if (ret)
		return ret;

	ret = text_file_contains_all(HDN_POLICY_LEARN_OUTPUT,
				     "# No automatic allow/mem suggestions.",
				     "reason=USER_WX_MAPPING",
				     "authority=MMAP");
	if (ret)
		return ret;

	return text_file_lacks(HDN_POLICY_LEARN_OUTPUT, "ALLOW_WX");
}

static int policy_merge_run_fixture(const char *base, const char *learn)
{
	int status;
	pid_t child;
	int ret;

	if (access(HDN_POLICY_MERGE_EXEC, X_OK))
		return KSFT_SKIP;

	unlink(HDN_POLICY_MERGE_OUTPUT);
	unlink(HDN_POLICY_MERGE_BINARY);
	ret = write_created_text_file(HDN_POLICY_MERGE_BASE, base);
	if (ret)
		return 2;
	ret = write_created_text_file(HDN_POLICY_MERGE_LEARN, learn);
	if (ret)
		return 2;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_POLICY_MERGE_EXEC, "hdn-policy-merge",
		      HDN_POLICY_MERGE_BASE, HDN_POLICY_MERGE_LEARN,
		      HDN_POLICY_MERGE_OUTPUT, NULL);
		_exit(2);
	}

	if (waitpid(child, &status, 0) < 0)
		return 2;
	if (!WIFEXITED(status))
		return 2;
	return WEXITSTATUS(status);
}

static int policy_merge_suggests_only_new_grants(void)
{
	const char *base =
		"generation 1\n"
		"base 0\n"
			"default 1\n"
			"privileged 2\n"
			"profile 1 default\n"
			"profile 2 privileged\n"
			"allow 2 TTY_ACCESS\n"
			"allow 2 BPF_LOAD\n"
			"mem 2 ALLOW_EXEC_AFTER_WRITE\n";
	const char *learn =
		"# HDN_LEARN_V1\n"
		"allow 2 BPF_LOAD PTRACE KEXEC_LOAD\n"
		"mem 2 ALLOW_EXEC_AFTER_WRITE ALLOW_FIXED_ANON_EXEC ALLOW_EXEC_STACK_ELF ALLOW_TEXTREL_MPROTECT ALLOW_RELRO_WRITE\n"
		"# review profile=2 authority=MMAP reason=USER_WX_MAPPING\n";
	int ret;

	ret = policy_merge_run_fixture(base, learn);
	if (ret)
		return ret;

	ret = text_file_contains_all(HDN_POLICY_MERGE_OUTPUT,
				     "# HDN_POLICY_MERGE_V1",
				     "allow 2 PTRACE KEXEC_LOAD",
				     "mem 2 ALLOW_FIXED_ANON_EXEC ALLOW_EXEC_STACK_ELF ALLOW_TEXTREL_MPROTECT ALLOW_RELRO_WRITE");
	if (ret)
		return ret;
	return text_file_lacks(HDN_POLICY_MERGE_OUTPUT,
			       "mem 2 ALLOW_EXEC_AFTER_WRITE ALLOW_FIXED_ANON_EXEC ALLOW_EXEC_STACK_ELF ALLOW_TEXTREL_MPROTECT ALLOW_RELRO_WRITE");
}

static int policy_output_compiles(const char *policy_path, const char *binary_path)
{
	int status;
	pid_t child;

	if (access(HDN_POLICY_COMPILER_EXEC, X_OK))
		return KSFT_SKIP;
	if (access(policy_path, R_OK))
		return 2;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_POLICY_COMPILER_EXEC, "hdn-policy",
		      policy_path, binary_path, NULL);
		_exit(2);
	}

	if (waitpid(child, &status, 0) < 0)
		return 2;
	if (!WIFEXITED(status))
		return 2;
	return WEXITSTATUS(status);
}

static int policy_merge_output_compiles(void)
{
	return policy_output_compiles(HDN_POLICY_MERGE_OUTPUT,
				      HDN_POLICY_MERGE_BINARY);
}

static int policy_merge_rejects_unknown_profiles(void)
{
	const char *base =
		"generation 1\n"
		"base 0\n"
		"default 1\n"
		"privileged 2\n"
		"profile 1 default\n"
		"profile 2 privileged\n"
		"allow 2 TTY_ACCESS\n";
	const char *learn =
		"# HDN_LEARN_V1\n"
		"allow 99 PTRACE\n";
	int ret;

	ret = policy_merge_run_fixture(base, learn);
	if (ret == KSFT_SKIP)
		return ret;
	return ret ? 0 : 1;
}

static int policy_workflow_run_opts(const char *command, const char *workflow,
				    const char *config_path, bool dry_run)
{
	pid_t child;

	if (access(HDN_POLICY_WORKFLOW_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		if (dry_run && config_path)
			execl(HDN_POLICY_WORKFLOW_EXEC, "hdn-policy-workflow",
			      "--dry-run", "--config", config_path, command,
			      workflow, NULL);
		else if (dry_run)
			execl(HDN_POLICY_WORKFLOW_EXEC, "hdn-policy-workflow",
			      "--dry-run", command, workflow, NULL);
		else if (config_path)
			execl(HDN_POLICY_WORKFLOW_EXEC, "hdn-policy-workflow",
			      "--config", config_path, command, workflow, NULL);
		else
			execl(HDN_POLICY_WORKFLOW_EXEC, "hdn-policy-workflow",
			      command, workflow, NULL);
		_exit(2);
	}

	return child_exit_result(child);
}

static int policy_workflow_run(const char *command, const char *workflow,
			       const char *config_path)
{
	return policy_workflow_run_opts(command, workflow, config_path, false);
}

static int policy_workflow_run_dry(const char *command, const char *workflow,
				   const char *config_path)
{
	return policy_workflow_run_opts(command, workflow, config_path, true);
}

static int policy_workflow_rejects_unknown(void)
{
	int ret = policy_workflow_run("learn", "unknown", NULL);

	if (ret == KSFT_SKIP)
		return ret;
	return ret ? 0 : 1;
}

static int policy_workflow_rejects_unsafe_config(void)
{
	int ret = policy_workflow_run("learn", "default",
				      HDN_POLICY_WORKFLOW_UNSAFE_CONFIG);

	if (ret == KSFT_SKIP)
		return ret;
	return ret ? 0 : 1;
}

static int policy_workflow_rejects_commit_without_signed_policy(void)
{
	int ret = policy_workflow_run_dry("commit", "default",
					  HDN_POLICY_WORKFLOW_NOSIGNED_CONFIG);

	if (ret == KSFT_SKIP)
		return ret;
	return ret ? 0 : 1;
}

static int policy_workflow_prepare_fixture(void)
{
	const char *base =
		"generation 1\n"
		"base 0\n"
		"default 1\n"
		"privileged 2\n"
		"profile 1 default\n"
		"profile 2 privileged\n";
	const char *events =
		"sequence=1 profile=2 authority=8 transition=9 action=1 reason=7 error=-13 subject=0 object=0\n"
		"sequence=2 profile=2 authority=12 transition=12 action=1 reason=7 error=-1 subject=0 object=0\n";
	int ret;

	unlink(HDN_POLICY_WORKFLOW_LEARN);
	unlink(HDN_POLICY_WORKFLOW_OUTPUT);
	unlink(HDN_POLICY_WORKFLOW_BINARY);

	ret = write_created_text_file(HDN_POLICY_WORKFLOW_BASE, base);
	if (ret)
		return 2;
	ret = write_created_text_file(HDN_POLICY_WORKFLOW_EVENTS, events);
	if (ret)
		return 2;

	return 0;
}

static int policy_workflow_generates_candidate(void)
{
	int ret;

	ret = policy_workflow_prepare_fixture();
	if (ret)
		return ret;

	ret = policy_workflow_run("learn", "default", NULL);
	if (ret)
		return ret;
	ret = text_file_contains_all(HDN_POLICY_WORKFLOW_LEARN,
				     "# HDN_LEARN_V1",
				     "allow 2 PTRACE KEXEC_LOAD",
				     NULL);
	if (ret)
		return ret;

	ret = policy_workflow_run("candidate", "default", NULL);
	if (ret)
		return ret;
	ret = text_file_contains_all(HDN_POLICY_WORKFLOW_OUTPUT,
				     "# HDN_POLICY_MERGE_V1",
				     "allow 2 PTRACE KEXEC_LOAD",
				     NULL);
	if (ret)
		return ret;

	ret = policy_workflow_run("compile", "default", NULL);
	if (ret)
		return ret;

	if (access(HDN_POLICY_WORKFLOW_BINARY, R_OK) ||
	    access(HDN_BROKER_SIGNED_POLICY, R_OK))
		return 2;

	return policy_workflow_run_dry("commit", "default", NULL);
}

static int policy_daemon_run_opts(const char *command, const char *workflow,
				  const char *config_path, bool dry_run)
{
	pid_t child;

	if (access(HDN_POLICY_DAEMON_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		if (dry_run && config_path)
			execl(HDN_POLICY_DAEMON_EXEC, "hdn-policy-daemon",
			      "--dry-run", "--config", config_path, command,
			      workflow, NULL);
		else if (dry_run)
			execl(HDN_POLICY_DAEMON_EXEC, "hdn-policy-daemon",
			      "--dry-run", command, workflow, NULL);
		else if (config_path)
			execl(HDN_POLICY_DAEMON_EXEC, "hdn-policy-daemon",
			      "--config", config_path, command, workflow, NULL);
		else
			execl(HDN_POLICY_DAEMON_EXEC, "hdn-policy-daemon",
			      command, workflow, NULL);
		_exit(2);
	}

	return child_exit_result(child);
}

static int policy_daemon_run(const char *command, const char *workflow,
			     const char *config_path)
{
	return policy_daemon_run_opts(command, workflow, config_path, false);
}

static int policy_daemon_run_dry(const char *command, const char *workflow,
				 const char *config_path)
{
	return policy_daemon_run_opts(command, workflow, config_path, true);
}

static int policy_daemon_stdio_run(const char *request)
{
	int pipefd[2];
	int child_ret;
	pid_t child;
	int ret;

	if (access(HDN_POLICY_DAEMON_EXEC, X_OK))
		return KSFT_SKIP;
	if (pipe(pipefd))
		return 2;

	child = fork();
	if (child < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return 2;
	}

	if (!child) {
		close(pipefd[1]);
		if (dup2(pipefd[0], STDIN_FILENO) < 0)
			_exit(2);
		close(pipefd[0]);
		execl(HDN_POLICY_DAEMON_EXEC, "hdn-policy-daemon",
		      "--stdio", NULL);
		_exit(2);
	}

	close(pipefd[0]);
	ret = dprintf(pipefd[1], "%s\n", request);
	close(pipefd[1]);
	if (ret < 0) {
		child_ret = child_exit_result(child);
		return child_ret ? child_ret : 2;
	}

	return child_exit_result(child);
}

static int policy_daemon_rejects_unknown(void)
{
	int ret = policy_daemon_run("learn", "unknown", NULL);

	if (ret == KSFT_SKIP)
		return ret;
	return ret ? 0 : 1;
}

static int policy_daemon_rejects_unsafe_config(void)
{
	int ret = policy_daemon_run("learn", "default",
				    HDN_POLICY_DAEMON_UNSAFE_CONFIG);

	if (ret == KSFT_SKIP)
		return ret;
	return ret ? 0 : 1;
}

static int policy_daemon_stdio_rejects_noncommit_dry_run(void)
{
	int ret = policy_daemon_stdio_run("dry-run compile default");

	if (ret == KSFT_SKIP)
		return ret;
	return ret ? 0 : 1;
}

static int policy_daemon_generates_candidate(void)
{
	int ret;

	ret = policy_workflow_prepare_fixture();
	if (ret)
		return ret;

	ret = policy_daemon_run("learn", "default", NULL);
	if (ret)
		return ret;
	ret = text_file_contains_all(HDN_POLICY_WORKFLOW_LEARN,
				     "# HDN_LEARN_V1",
				     "allow 2 PTRACE KEXEC_LOAD",
				     NULL);
	if (ret)
		return ret;

	ret = policy_daemon_run("candidate", "default", NULL);
	if (ret)
		return ret;
	ret = text_file_contains_all(HDN_POLICY_WORKFLOW_OUTPUT,
				     "# HDN_POLICY_MERGE_V1",
				     "allow 2 PTRACE KEXEC_LOAD",
				     NULL);
	if (ret)
		return ret;

	ret = policy_daemon_run("compile", "default", NULL);
	if (ret)
		return ret;

	if (access(HDN_POLICY_WORKFLOW_BINARY, R_OK) ||
	    access(HDN_BROKER_SIGNED_POLICY, R_OK))
		return 2;

	ret = policy_daemon_run_dry("commit", "default", NULL);
	if (ret)
		return ret;

	return policy_daemon_stdio_run("dry-run commit default");
}

static int control_center_policy_run_opts(const char *command,
					  const char *workflow, bool dry_run)
{
	pid_t child;

	if (access(HDN_CONTROL_CENTER_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		if (dry_run)
			execl(HDN_CONTROL_CENTER_EXEC, "hdn-control-center",
			      "--dry-run", "policy", command, workflow, NULL);
		else
			execl(HDN_CONTROL_CENTER_EXEC, "hdn-control-center",
			      "policy", command, workflow, NULL);
		_exit(2);
	}

	return child_exit_result(child);
}

static int control_center_policy_run(const char *command, const char *workflow)
{
	return control_center_policy_run_opts(command, workflow, false);
}

static int control_center_policy_run_dry(const char *command,
					 const char *workflow)
{
	return control_center_policy_run_opts(command, workflow, true);
}

static int control_center_stdio_rejects_noncommit_policy_dry_run(void)
{
	int ret = control_center_stdio_run("dry-run policy compile default");

	if (ret == KSFT_SKIP)
		return ret;
	return ret ? 0 : 1;
}

static int control_center_policy_generates_candidate(void)
{
	int ret;

	ret = policy_workflow_prepare_fixture();
	if (ret)
		return ret;

	ret = control_center_policy_run("learn", "default");
	if (ret)
		return ret;
	ret = text_file_contains_all(HDN_POLICY_WORKFLOW_LEARN,
				     "# HDN_LEARN_V1",
				     "allow 2 PTRACE KEXEC_LOAD",
				     NULL);
	if (ret)
		return ret;

	ret = control_center_policy_run("candidate", "default");
	if (ret)
		return ret;
	ret = text_file_contains_all(HDN_POLICY_WORKFLOW_OUTPUT,
				     "# HDN_POLICY_MERGE_V1",
				     "allow 2 PTRACE KEXEC_LOAD",
				     NULL);
	if (ret)
		return ret;

	ret = control_center_policy_run("compile", "default");
	if (ret)
		return ret;

	if (access(HDN_POLICY_WORKFLOW_BINARY, R_OK) ||
	    access(HDN_BROKER_SIGNED_POLICY, R_OK))
		return 2;

	ret = control_center_policy_run_dry("commit", "default");
	if (ret)
		return ret;

	return control_center_stdio_run("dry-run policy commit default");
}

static int apt_package_hook_invokes_hdn_hook(void)
{
	return text_file_contains_all(
		HDN_APT_PACKAGE_HOOK_CONFIG, "DPkg::Post-Invoke",
		"/usr/libexec/hdn-package-hook image-seal-default", NULL);
}

static int pacman_package_hook_invokes_hdn_hook(void)
{
	return text_file_contains_all(
		HDN_PACMAN_PACKAGE_HOOK_CONFIG, "When = PostTransaction",
		"Exec = /usr/libexec/hdn-package-hook image-seal-default",
		"AbortOnFail");
}

static int dnf_package_hook_invokes_hdn_hook(void)
{
	return text_file_contains_all(
		HDN_DNF_PACKAGE_HOOK_CONFIG, "*:any:",
		"/usr/libexec/hdn-package-hook image-seal-default", NULL);
}

static int dnf5_package_hook_invokes_hdn_hook(void)
{
	return text_file_contains_all(
		HDN_DNF5_PACKAGE_HOOK_CONFIG, "post_transaction:::",
		"enabled=host-only raise_error=1",
		"/usr/libexec/hdn-package-hook image-seal-default");
}

static int image_seal_unit_invokes_hdn_hook(void)
{
	return text_file_contains_all(
		HDN_IMAGE_SEAL_SERVICE_UNIT, "Type=oneshot",
		"ExecStart=/usr/libexec/hdn-package-hook image-seal-default",
		"ConditionPathExists=/etc/hdn/package-hooks.conf");
}

static int product_rofs_recovery_repair_updates_and_reseals(unsigned int min_updates)
{
	int saved_errno;
	unsigned int count;
	pid_t child;
	int ret;
	int fd;

	if (access(HDN_RECOVERY_ACTION_EXEC, X_OK)) {
		fprintf(stderr,
			"recovery action helper is not executable: %s\n",
			strerror(errno));
		return KSFT_SKIP;
	}

	count = product_rofs_sentinel_update_count();
	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_RECOVERY_ACTION_EXEC, "hdn-recovery-action",
		      "--dry-run", "package-repair", NULL);
		fprintf(stderr, "recovery repair dry-run exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	ret = child_exit_result(child);
	if (ret) {
		fprintf(stderr, "recovery repair dry-run exited with %d\n",
			ret);
		return ret;
	}
	if (product_rofs_sentinel_update_count() != count) {
		fprintf(stderr, "recovery repair dry-run changed sentinel\n");
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"recovery repair dry-run left product mount writable\n");
		close(fd);
		return 1;
	}
	if (saved_errno != EROFS) {
		fprintf(stderr,
			"post-recovery-repair-dry-run write-open failed with %s\n",
			strerror(saved_errno));
		return 2;
	}

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_RECOVERY_ACTION_EXEC, "hdn-recovery-action",
		      "package-repair", NULL);
		fprintf(stderr, "recovery repair exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	ret = child_exit_result(child);
	if (ret) {
		fprintf(stderr, "recovery repair exited with %d\n", ret);
		return ret;
	}

	count = product_rofs_sentinel_update_count();
	if (count < min_updates) {
		fprintf(stderr,
			"recovery repair only wrote %u sentinel updates\n",
			count);
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"recovery repair left product mount writable\n");
		close(fd);
		return 1;
	}

	if (saved_errno != EROFS)
		fprintf(stderr,
			"post-recovery-repair write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static int product_rofs_recovery_session_repair_updates_and_reseals(unsigned int min_updates)
{
	int saved_errno;
	unsigned int count;
	pid_t child;
	int ret;
	int fd;

	if (access(HDN_RECOVERY_SESSION_EXEC, X_OK)) {
		fprintf(stderr,
			"recovery session helper is not executable: %s\n",
			strerror(errno));
		return KSFT_SKIP;
	}

	count = product_rofs_sentinel_update_count();
	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_RECOVERY_SESSION_EXEC, "hdn-recovery-session",
		      "--dry-run", "package-repair", NULL);
		fprintf(stderr,
			"recovery session repair dry-run exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	ret = child_exit_result(child);
	if (ret) {
		fprintf(stderr,
			"recovery session repair dry-run exited with %d\n",
			ret);
		return ret;
	}
	if (product_rofs_sentinel_update_count() != count) {
		fprintf(stderr,
			"recovery session repair dry-run changed sentinel\n");
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"recovery session repair dry-run left product mount writable\n");
		close(fd);
		return 1;
	}
	if (saved_errno != EROFS) {
		fprintf(stderr,
			"post-recovery-session-repair-dry-run write-open failed with %s\n",
			strerror(saved_errno));
		return 2;
	}

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_RECOVERY_SESSION_EXEC, "hdn-recovery-session",
		      "package-repair", NULL);
		fprintf(stderr, "recovery session repair exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	ret = child_exit_result(child);
	if (ret) {
		fprintf(stderr, "recovery session repair exited with %d\n", ret);
		return ret;
	}

	count = product_rofs_sentinel_update_count();
	if (count < min_updates) {
		fprintf(stderr,
			"recovery session repair only wrote %u sentinel updates\n",
			count);
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"recovery session repair left product mount writable\n");
		close(fd);
		return 1;
	}

	if (saved_errno != EROFS)
		fprintf(stderr,
			"post-recovery-session-repair write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static int product_rofs_recovery_portal_repair_updates_and_reseals(unsigned int min_updates)
{
	int saved_errno;
	unsigned int count;
	pid_t child;
	int ret;
	int fd;

	if (access(HDN_RECOVERY_PORTAL_EXEC, X_OK)) {
		fprintf(stderr,
			"recovery portal helper is not executable: %s\n",
			strerror(errno));
		return KSFT_SKIP;
	}

	count = product_rofs_sentinel_update_count();
	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_RECOVERY_PORTAL_EXEC, "hdn-recovery-portal",
		      "--dry-run", "repair-system", NULL);
		fprintf(stderr,
			"recovery portal repair dry-run exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	ret = child_exit_result(child);
	if (ret) {
		fprintf(stderr,
			"recovery portal repair dry-run exited with %d\n",
			ret);
		return ret;
	}
	if (product_rofs_sentinel_update_count() != count) {
		fprintf(stderr,
			"recovery portal repair dry-run changed sentinel\n");
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"recovery portal repair dry-run left product mount writable\n");
		close(fd);
		return 1;
	}
	if (saved_errno != EROFS) {
		fprintf(stderr,
			"post-recovery-portal-repair-dry-run write-open failed with %s\n",
			strerror(saved_errno));
		return 2;
	}

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_RECOVERY_PORTAL_EXEC, "hdn-recovery-portal",
		      "repair-system", NULL);
		fprintf(stderr, "recovery portal repair exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	ret = child_exit_result(child);
	if (ret) {
		fprintf(stderr, "recovery portal repair exited with %d\n", ret);
		return ret;
	}

	count = product_rofs_sentinel_update_count();
	if (count < min_updates) {
		fprintf(stderr,
			"recovery portal repair only wrote %u sentinel updates\n",
			count);
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"recovery portal repair left product mount writable\n");
		close(fd);
		return 1;
	}

	if (saved_errno != EROFS)
		fprintf(stderr,
			"post-recovery-portal-repair write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static int prompt_describe_run(const char *action, const char *config_path)
{
	pid_t child;

	if (access(HDN_PROMPT_DESCRIBE_EXEC, X_OK)) {
		fprintf(stderr,
			"prompt describe helper is not executable: %s\n",
			strerror(errno));
		return KSFT_SKIP;
	}

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		int fd;

		fd = open(HDN_PROMPT_DESCRIBE_OUTPUT,
			  O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0600);
		if (fd < 0)
			_exit(2);
		if (dup2(fd, STDOUT_FILENO) < 0)
			_exit(2);
		close(fd);

		if (config_path)
			execl(HDN_PROMPT_DESCRIBE_EXEC, "hdn-prompt-describe",
			      "--config", config_path, action, NULL);
		else
			execl(HDN_PROMPT_DESCRIBE_EXEC, "hdn-prompt-describe",
			      action, NULL);
		fprintf(stderr, "prompt describe exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int prompt_describe_denied(const char *action, const char *config_path,
				  const char *failure)
{
	int ret;

	unlink(HDN_PROMPT_DESCRIBE_OUTPUT);
	ret = prompt_describe_run(action, config_path);
	if (ret == KSFT_SKIP)
		return ret;
	if (!ret) {
		fprintf(stderr, "prompt describe allowed %s\n", failure);
		return 1;
	}

	return ret == 1 ? 0 : ret;
}

static int prompt_describe_unknown_denied(void)
{
	return prompt_describe_denied("unknown-update", NULL,
				      "unknown action");
}

static int prompt_describe_unsafe_config_denied(void)
{
	return prompt_describe_denied("package-update",
				      HDN_PROMPT_DESCRIBE_UNSAFE_CONFIG,
				      "unsafe config");
}

static bool prompt_description_has_line(const char *text, const char *line)
{
	const char *match = text;
	size_t len = strlen(line);

	while ((match = strstr(match, line))) {
		if ((match == text || match[-1] == '\n') &&
		    match[len] == '\n')
			return true;
		match += len;
	}

	return false;
}

static int prompt_describe_package_update(void)
{
	unsigned char *blob = NULL;
	char *text = NULL;
	size_t size = 0;
	bool valid;
	int ret;

	unlink(HDN_PROMPT_DESCRIBE_OUTPUT);
	ret = prompt_describe_run("package-update", NULL);
	if (ret == KSFT_SKIP)
		return ret;
	if (ret) {
		fprintf(stderr, "prompt describe exited with %d\n", ret);
		return ret;
	}

	ret = read_whole_file(HDN_PROMPT_DESCRIBE_OUTPUT, &blob, &size);
	if (ret) {
		fprintf(stderr, "prompt describe output missing: %s\n",
			strerror(-ret));
		return 1;
	}

	text = malloc(size + 1);
	if (!text) {
		free(blob);
		return 2;
	}
	memcpy(text, blob, size);
	text[size] = '\0';

	valid = prompt_description_has_line(text, "HDN_PROMPT_METADATA_V1") &&
		prompt_description_has_line(text, "action=package-update") &&
		prompt_description_has_line(text,
					    "title=Install system updates") &&
		prompt_description_has_line(text, "risk=system") &&
		strstr(text, "message=") &&
		strstr(text, "consequence=");

	free(text);
	free(blob);
	if (!valid) {
		fprintf(stderr,
			"prompt describe output did not contain expected metadata\n");
		return 1;
	}

	return 0;
}

static const char hdn_prompt_package_update_metadata[] =
	"HDN_PROMPT_METADATA_V1\n"
	"action=package-update\n"
	"title=Install system updates\n"
	"message=The operating system will update protected system files.\n"
	"consequence=The system image is temporarily writable and then resealed.\n"
	"risk=system\n";

static int auth_prompt_run(const char *action, const char *mode,
			   bool clear_display)
{
	int pipefd[2];
	pid_t child;
	int status;
	int ret;

	if (access(HDN_AUTH_PROMPT_EXEC, X_OK)) {
		fprintf(stderr,
			"auth prompt helper is not executable: %s\n",
			strerror(errno));
		return KSFT_SKIP;
	}

	if (pipe(pipefd))
		return 2;

	child = fork();
	if (child < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return 2;
	}

	if (!child) {
		close(pipefd[1]);
		if (dup2(pipefd[0], STDIN_FILENO) < 0)
			_exit(2);
		close(pipefd[0]);
		if (clear_display) {
			unsetenv("DISPLAY");
			unsetenv("WAYLAND_DISPLAY");
		}
		if (mode)
			execl(HDN_AUTH_PROMPT_EXEC, "hdn-auth-prompt",
			      mode, action, NULL);
		else
			execl(HDN_AUTH_PROMPT_EXEC, "hdn-auth-prompt",
			      action, NULL);
		fprintf(stderr, "auth prompt exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	close(pipefd[0]);
	ret = write(pipefd[1], hdn_prompt_package_update_metadata,
		    sizeof(hdn_prompt_package_update_metadata) - 1);
	close(pipefd[1]);

	status = child_exit_result(child);
	if (ret != (int)sizeof(hdn_prompt_package_update_metadata) - 1 &&
	    !status)
		return 2;

	return status;
}

static int auth_prompt_test_approve(void)
{
	return auth_prompt_run("package-update", "--test-approve", false);
}

static int auth_prompt_test_deny(void)
{
	int ret = auth_prompt_run("package-update", "--test-deny", false);

	if (ret == KSFT_SKIP)
		return ret;
	return ret == 1 ? 0 : ret ? ret : 1;
}

static int auth_prompt_no_display_denied(void)
{
	int ret = auth_prompt_run("package-update", NULL, true);

	if (ret == KSFT_SKIP)
		return ret;
	return ret == 1 ? 0 : ret ? ret : 1;
}

static int prompt_auth_sentinel(const char *action, bool approve)
{
	char expected[256];
	char buf[8193];
	size_t done = 0;

	for (;;) {
		ssize_t len;

		len = read(STDIN_FILENO, buf + done, sizeof(buf) - done - 1);
		if (len < 0) {
			if (errno == EINTR)
				continue;
			return 2;
		}
		if (!len)
			break;
		done += (size_t)len;
		if (done >= sizeof(buf) - 1)
			return 2;
	}
	buf[done] = '\0';

	if (!prompt_description_has_line(buf, "HDN_PROMPT_METADATA_V1"))
		return 2;
	if (snprintf(expected, sizeof(expected), "action=%s", action) >=
	    (int)sizeof(expected))
		return 2;
	if (!prompt_description_has_line(buf, expected))
		return 2;

	return approve ? 0 : 1;
}

static int product_rofs_prompt_session_run(const char *action,
					   const char *config_path)
{
	pid_t child;

	if (access(HDN_PROMPT_SESSION_EXEC, X_OK)) {
		fprintf(stderr,
			"prompt session helper is not executable: %s\n",
			strerror(errno));
		return KSFT_SKIP;
	}

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		if (config_path)
			execl(HDN_PROMPT_SESSION_EXEC, "hdn-prompt-session",
			      "--config", config_path, action, NULL);
		else
			execl(HDN_PROMPT_SESSION_EXEC, "hdn-prompt-session",
			      action, NULL);
		fprintf(stderr, "prompt session exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int prompt_session_unprivileged_authorized_denied(void)
{
	pid_t child;
	int ret;

	if (access(HDN_PROMPT_SESSION_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;
	if (!child) {
		if (setgroups(0, NULL) || setresgid(65534, 65534, 65534) ||
		    setresuid(65534, 65534, 65534))
			_exit(2);
		execl(HDN_PROMPT_SESSION_EXEC, "hdn-prompt-session",
		      "--authorized", "package-update", NULL);
		_exit(2);
	}

	ret = child_exit_result(child);
	return ret == 1 ? 0 : ret ? ret : 1;
}

static int product_rofs_prompt_session_denied(const char *action,
					      const char *config_path,
					      const char *failure,
					      unsigned int updates)
{
	int saved_errno;
	unsigned int count;
	int ret;
	int fd;

	ret = product_rofs_prompt_session_run(action, config_path);
	if (ret == KSFT_SKIP)
		return ret;
	if (!ret) {
		fprintf(stderr, "prompt session allowed %s\n", failure);
		return 1;
	}
	if (ret != 1)
		return ret;

	count = product_rofs_sentinel_update_count();
	if (count != updates) {
		fprintf(stderr,
			"prompt session denial left %u sentinel updates, expected %u\n",
			count, updates);
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"prompt session denial left product mount writable\n");
		close(fd);
		return 1;
	}

	if (saved_errno != EROFS)
		fprintf(stderr,
			"post-prompt-session-denial write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static int product_rofs_prompt_session_unknown_denied(unsigned int updates)
{
	return product_rofs_prompt_session_denied("unknown-update", NULL,
						 "unknown action", updates);
}

static int product_rofs_prompt_session_unsafe_config_denied(unsigned int updates)
{
	return product_rofs_prompt_session_denied(
		"package-update", HDN_PROMPT_SESSION_UNSAFE_CONFIG,
		"unsafe config", updates);
}

static int product_rofs_prompt_session_auth_denied(unsigned int updates)
{
	return product_rofs_prompt_session_denied(
		"package-update", HDN_PROMPT_SESSION_AUTH_DENY_CONFIG,
		"auth denial", updates);
}

static int product_rofs_prompt_session_no_display_denied(unsigned int updates)
{
	return product_rofs_prompt_session_denied(
		"package-update", HDN_PROMPT_SESSION_NO_DISPLAY_CONFIG,
		"missing graphical session", updates);
}

static int product_rofs_prompt_session_updates_and_reseals(unsigned int min_updates)
{
	int saved_errno;
	unsigned int count;
	int ret;
	int fd;

	ret = product_rofs_prompt_session_run("package-update", NULL);
	if (ret == KSFT_SKIP)
		return ret;
	if (ret) {
		fprintf(stderr, "prompt session exited with %d\n", ret);
		return ret;
	}

	count = product_rofs_sentinel_update_count();
	if (count < min_updates) {
		fprintf(stderr,
			"prompt session only wrote %u sentinel updates\n",
			count);
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"prompt session left product mount writable\n");
		close(fd);
		return 1;
	}

	if (saved_errno != EROFS)
		fprintf(stderr,
			"post-prompt-session write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static int product_rofs_prompt_portal_run(const char *action,
					  const char *config_path)
{
	pid_t child;

	if (access(HDN_PROMPT_PORTAL_EXEC, X_OK)) {
		fprintf(stderr,
			"prompt portal helper is not executable: %s\n",
			strerror(errno));
		return KSFT_SKIP;
	}

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		if (config_path)
			execl(HDN_PROMPT_PORTAL_EXEC, "hdn-prompt-portal",
			      "--config", config_path, action, NULL);
		else
			execl(HDN_PROMPT_PORTAL_EXEC, "hdn-prompt-portal",
			      action, NULL);
		fprintf(stderr, "prompt portal exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int product_rofs_prompt_portal_denied(const char *action,
					     const char *config_path,
					     const char *failure,
					     unsigned int updates)
{
	int saved_errno;
	unsigned int count;
	int ret;
	int fd;

	ret = product_rofs_prompt_portal_run(action, config_path);
	if (ret == KSFT_SKIP)
		return ret;
	if (!ret) {
		fprintf(stderr, "prompt portal allowed %s\n", failure);
		return 1;
	}
	if (ret != 1)
		return ret;

	count = product_rofs_sentinel_update_count();
	if (count != updates) {
		fprintf(stderr,
			"prompt portal denial left %u sentinel updates, expected %u\n",
			count, updates);
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"prompt portal denial left product mount writable\n");
		close(fd);
		return 1;
	}

	if (saved_errno != EROFS)
		fprintf(stderr,
			"post-prompt-portal-denial write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static int product_rofs_prompt_portal_unknown_denied(unsigned int updates)
{
	return product_rofs_prompt_portal_denied("unknown-update", NULL,
						"unknown action", updates);
}

static int product_rofs_prompt_portal_unsafe_config_denied(unsigned int updates)
{
	return product_rofs_prompt_portal_denied(
		"desktop-package-update", HDN_PROMPT_PORTAL_UNSAFE_CONFIG,
		"unsafe config", updates);
}

static int product_rofs_prompt_portal_updates_and_reseals(unsigned int min_updates)
{
	int saved_errno;
	unsigned int count;
	int ret;
	int fd;

	ret = product_rofs_prompt_portal_run("desktop-package-update", NULL);
	if (ret == KSFT_SKIP)
		return ret;
	if (ret) {
		fprintf(stderr, "prompt portal exited with %d\n", ret);
		return ret;
	}

	count = product_rofs_sentinel_update_count();
	if (count < min_updates) {
		fprintf(stderr,
			"prompt portal only wrote %u sentinel updates\n",
			count);
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"prompt portal left product mount writable\n");
		close(fd);
		return 1;
	}

	if (saved_errno != EROFS)
		fprintf(stderr,
			"post-prompt-portal write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static int product_rofs_desktop_action_run(const char *action,
					   const char *config_path)
{
	pid_t child;

	if (access(HDN_DESKTOP_ACTION_EXEC, X_OK)) {
		fprintf(stderr,
			"desktop action helper is not executable: %s\n",
			strerror(errno));
		return KSFT_SKIP;
	}

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		if (config_path)
			execl(HDN_DESKTOP_ACTION_EXEC, "hdn-desktop-action",
			      "--config", config_path, action, NULL);
		else
			execl(HDN_DESKTOP_ACTION_EXEC, "hdn-desktop-action",
			      action, NULL);
		fprintf(stderr, "desktop action exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int product_rofs_desktop_action_denied(const char *action,
					      const char *config_path,
					      const char *failure,
					      unsigned int updates)
{
	int saved_errno;
	unsigned int count;
	int ret;
	int fd;

	ret = product_rofs_desktop_action_run(action, config_path);
	if (ret == KSFT_SKIP)
		return ret;
	if (!ret) {
		fprintf(stderr, "desktop action allowed %s\n", failure);
		return 1;
	}
	if (ret != 1)
		return ret;

	count = product_rofs_sentinel_update_count();
	if (count != updates) {
		fprintf(stderr,
			"desktop action denial left %u sentinel updates, expected %u\n",
			count, updates);
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"desktop action denial left product mount writable\n");
		close(fd);
		return 1;
	}

	if (saved_errno != EROFS)
		fprintf(stderr,
			"post-desktop-action-denial write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static int product_rofs_desktop_action_unknown_denied(unsigned int updates)
{
	return product_rofs_desktop_action_denied("updates.remove", NULL,
						 "unknown action", updates);
}

static int product_rofs_desktop_action_unsafe_config_denied(unsigned int updates)
{
	return product_rofs_desktop_action_denied(
		"updates.install", HDN_DESKTOP_ACTION_UNSAFE_CONFIG,
		"unsafe config", updates);
}

static int product_rofs_desktop_action_updates_and_reseals(unsigned int min_updates)
{
	int saved_errno;
	unsigned int count;
	int ret;
	int fd;

	ret = product_rofs_desktop_action_run("updates.install", NULL);
	if (ret == KSFT_SKIP)
		return ret;
	if (ret) {
		fprintf(stderr, "desktop action exited with %d\n", ret);
		return ret;
	}

	count = product_rofs_sentinel_update_count();
	if (count < min_updates) {
		fprintf(stderr,
			"desktop action only wrote %u sentinel updates\n",
			count);
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"desktop action left product mount writable\n");
		close(fd);
		return 1;
	}

	if (saved_errno != EROFS)
		fprintf(stderr,
			"post-desktop-action write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static int product_rofs_desktop_daemon_run(const char *action,
					   const char *config_path)
{
	pid_t child;

	if (access(HDN_DESKTOP_DAEMON_EXEC, X_OK)) {
		fprintf(stderr,
			"desktop daemon helper is not executable: %s\n",
			strerror(errno));
		return KSFT_SKIP;
	}

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		if (config_path)
			execl(HDN_DESKTOP_DAEMON_EXEC, "hdn-desktop-daemon",
			      "--config", config_path, action, NULL);
		else
			execl(HDN_DESKTOP_DAEMON_EXEC, "hdn-desktop-daemon",
			      action, NULL);
		fprintf(stderr, "desktop daemon exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int product_rofs_desktop_daemon_stdio_run(const char *action)
{
	int pipefd[2];
	int child_ret;
	pid_t child;
	int ret;

	if (access(HDN_DESKTOP_DAEMON_EXEC, X_OK)) {
		fprintf(stderr,
			"desktop daemon helper is not executable: %s\n",
			strerror(errno));
		return KSFT_SKIP;
	}
	if (pipe(pipefd))
		return 2;

	child = fork();
	if (child < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return 2;
	}

	if (!child) {
		close(pipefd[1]);
		if (dup2(pipefd[0], STDIN_FILENO) < 0)
			_exit(2);
		close(pipefd[0]);
		execl(HDN_DESKTOP_DAEMON_EXEC, "hdn-desktop-daemon",
		      "--stdio", NULL);
		fprintf(stderr, "desktop daemon stdio exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	close(pipefd[0]);
	ret = dprintf(pipefd[1], "%s\n", action);
	close(pipefd[1]);
	if (ret < 0) {
		child_ret = child_exit_result(child);
		return child_ret ? child_ret : 2;
	}

	return child_exit_result(child);
}

static int product_rofs_desktop_daemon_denied(const char *action,
					      const char *config_path,
					      const char *failure,
					      unsigned int updates)
{
	int saved_errno;
	unsigned int count;
	int ret;
	int fd;

	ret = product_rofs_desktop_daemon_run(action, config_path);
	if (ret == KSFT_SKIP)
		return ret;
	if (!ret) {
		fprintf(stderr, "desktop daemon allowed %s\n", failure);
		return 1;
	}
	if (ret != 1)
		return ret;

	count = product_rofs_sentinel_update_count();
	if (count != updates) {
		fprintf(stderr,
			"desktop daemon denial left %u sentinel updates, expected %u\n",
			count, updates);
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"desktop daemon denial left product mount writable\n");
		close(fd);
		return 1;
	}

	if (saved_errno != EROFS)
		fprintf(stderr,
			"post-desktop-daemon-denial write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static int product_rofs_desktop_daemon_unknown_denied(unsigned int updates)
{
	return product_rofs_desktop_daemon_denied("updates.remove", NULL,
						 "unknown action", updates);
}

static int product_rofs_desktop_daemon_unsafe_config_denied(unsigned int updates)
{
	return product_rofs_desktop_daemon_denied(
		"updates.install", HDN_DESKTOP_DAEMON_UNSAFE_CONFIG,
		"unsafe config", updates);
}

static int product_rofs_desktop_daemon_updates_and_reseals(unsigned int min_updates)
{
	int saved_errno;
	unsigned int count;
	int ret;
	int fd;

	count = product_rofs_sentinel_update_count();
	ret = product_rofs_desktop_daemon_stdio_run("dry-run updates.install");
	if (ret == KSFT_SKIP)
		return ret;
	if (ret) {
		fprintf(stderr, "desktop daemon dry-run exited with %d\n", ret);
		return ret;
	}
	if (product_rofs_sentinel_update_count() != count) {
		fprintf(stderr, "desktop daemon dry-run changed sentinel\n");
		return 1;
	}
	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"desktop daemon dry-run left product mount writable\n");
		close(fd);
		return 1;
	}
	if (saved_errno != EROFS) {
		fprintf(stderr,
			"post-desktop-daemon-dry-run write-open failed with %s\n",
			strerror(saved_errno));
		return 2;
	}

	ret = product_rofs_desktop_daemon_stdio_run("updates.install");
	if (ret == KSFT_SKIP)
		return ret;
	if (ret) {
		fprintf(stderr, "desktop daemon exited with %d\n", ret);
		return ret;
	}

	count = product_rofs_sentinel_update_count();
	if (count < min_updates) {
		fprintf(stderr,
			"desktop daemon only wrote %u sentinel updates\n",
			count);
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"desktop daemon left product mount writable\n");
		close(fd);
		return 1;
	}

	if (saved_errno != EROFS)
		fprintf(stderr,
			"post-desktop-daemon write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static int product_rofs_control_center_run(const char *action, bool dry_run)
{
	pid_t child;

	if (access(HDN_CONTROL_CENTER_EXEC, X_OK)) {
		fprintf(stderr,
			"control center helper is not executable: %s\n",
			strerror(errno));
		return KSFT_SKIP;
	}

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		if (dry_run)
			execl(HDN_CONTROL_CENTER_EXEC, "hdn-control-center",
			      "--dry-run", "action", action, NULL);
		else
			execl(HDN_CONTROL_CENTER_EXEC, "hdn-control-center",
			      "action", action, NULL);
		fprintf(stderr, "control center exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int product_rofs_control_center_denied(const char *action,
					      const char *failure,
					      unsigned int updates)
{
	int saved_errno;
	unsigned int count;
	int ret;
	int fd;

	ret = product_rofs_control_center_run(action, false);
	if (ret == KSFT_SKIP)
		return ret;
	if (!ret) {
		fprintf(stderr, "control center allowed %s\n", failure);
		return 1;
	}
	if (ret != 1)
		return ret;

	count = product_rofs_sentinel_update_count();
	if (count != updates) {
		fprintf(stderr,
			"control center denial left %u sentinel updates, expected %u\n",
			count, updates);
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"control center denial left product mount writable\n");
		close(fd);
		return 1;
	}

	if (saved_errno != EROFS)
		fprintf(stderr,
			"post-control-center-denial write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static int product_rofs_control_center_unknown_denied(unsigned int updates)
{
	return product_rofs_control_center_denied("updates.remove",
						 "unknown action", updates);
}

static int product_rofs_control_center_stdio_denied(const char *request,
						    const char *failure,
						    unsigned int updates)
{
	int saved_errno;
	unsigned int count;
	int ret;
	int fd;

	ret = control_center_stdio_run(request);
	if (ret == KSFT_SKIP)
		return ret;
	if (!ret) {
		fprintf(stderr, "control center stdio allowed %s\n", failure);
		return 1;
	}
	if (ret != 1)
		return ret;

	count = product_rofs_sentinel_update_count();
	if (count != updates) {
		fprintf(stderr,
			"control center stdio denial left %u sentinel updates, expected %u\n",
			count, updates);
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"control center stdio denial left product mount writable\n");
		close(fd);
		return 1;
	}

	if (saved_errno != EROFS)
		fprintf(stderr,
			"post-control-center-stdio-denial write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static int product_rofs_control_center_stdio_unknown_denied(unsigned int updates)
{
	return product_rofs_control_center_stdio_denied("action updates.remove",
						       "unknown action",
						       updates);
}

static int product_rofs_control_center_updates_and_reseals(unsigned int min_updates)
{
	int saved_errno;
	unsigned int count;
	int ret;
	int fd;

	count = product_rofs_sentinel_update_count();
	ret = product_rofs_control_center_run("updates.install", true);
	if (ret == KSFT_SKIP)
		return ret;
	if (ret) {
		fprintf(stderr, "control center dry-run exited with %d\n",
			ret);
		return ret;
	}
	if (product_rofs_sentinel_update_count() != count) {
		fprintf(stderr, "control center dry-run changed sentinel\n");
		return 1;
	}
	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"control center dry-run left product mount writable\n");
		close(fd);
		return 1;
	}
	if (saved_errno != EROFS) {
		fprintf(stderr,
			"post-control-center-dry-run write-open failed with %s\n",
			strerror(saved_errno));
		return 2;
	}

	ret = product_rofs_control_center_run("updates.install", false);
	if (ret == KSFT_SKIP)
		return ret;
	if (ret) {
		fprintf(stderr, "control center exited with %d\n", ret);
		return ret;
	}

	count = product_rofs_sentinel_update_count();
	if (count < min_updates) {
		fprintf(stderr,
			"control center only wrote %u sentinel updates\n",
			count);
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"control center left product mount writable\n");
		close(fd);
		return 1;
	}

	if (saved_errno != EROFS)
		fprintf(stderr,
			"post-control-center write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static int product_rofs_control_center_stdio_updates_and_reseals(unsigned int min_updates)
{
	int saved_errno;
	unsigned int count;
	int ret;
	int fd;

	count = product_rofs_sentinel_update_count();
	ret = control_center_stdio_run("dry-run action updates.install");
	if (ret == KSFT_SKIP)
		return ret;
	if (ret) {
		fprintf(stderr, "control center stdio dry-run exited with %d\n",
			ret);
		return ret;
	}
	if (product_rofs_sentinel_update_count() != count) {
		fprintf(stderr, "control center stdio dry-run changed sentinel\n");
		return 1;
	}
	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"control center stdio dry-run left product mount writable\n");
		close(fd);
		return 1;
	}
	if (saved_errno != EROFS) {
		fprintf(stderr,
			"post-control-center-stdio-dry-run write-open failed with %s\n",
			strerror(saved_errno));
		return 2;
	}

	ret = control_center_stdio_run("action updates.install");
	if (ret == KSFT_SKIP)
		return ret;
	if (ret) {
		fprintf(stderr, "control center stdio exited with %d\n", ret);
		return ret;
	}

	count = product_rofs_sentinel_update_count();
	if (count < min_updates) {
		fprintf(stderr,
			"control center stdio only wrote %u sentinel updates\n",
			count);
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"control center stdio left product mount writable\n");
		close(fd);
		return 1;
	}

	if (saved_errno != EROFS)
		fprintf(stderr,
			"post-control-center-stdio write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static int product_rofs_settings_panel_run(const char *action,
					   const char *config_path,
					   bool dry_run)
{
	pid_t child;

	if (access(HDN_SETTINGS_PANEL_EXEC, X_OK)) {
		fprintf(stderr,
			"settings panel helper is not executable: %s\n",
			strerror(errno));
		return KSFT_SKIP;
	}

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		if (config_path && dry_run)
			execl(HDN_SETTINGS_PANEL_EXEC, "hdn-settings-panel",
			      "--config", config_path, "--dry-run", "action",
			      action, NULL);
		else if (config_path)
			execl(HDN_SETTINGS_PANEL_EXEC, "hdn-settings-panel",
			      "--config", config_path, "action", action,
			      NULL);
		else if (dry_run)
			execl(HDN_SETTINGS_PANEL_EXEC, "hdn-settings-panel",
			      "--dry-run", "action", action, NULL);
		else
			execl(HDN_SETTINGS_PANEL_EXEC, "hdn-settings-panel",
			      "action", action, NULL);
		fprintf(stderr, "settings panel exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int product_rofs_settings_panel_denied(const char *action,
					      const char *config_path,
					      const char *failure,
					      unsigned int updates)
{
	int saved_errno;
	unsigned int count;
	int ret;
	int fd;

	ret = product_rofs_settings_panel_run(action, config_path, false);
	if (ret == KSFT_SKIP)
		return ret;
	if (!ret) {
		fprintf(stderr, "settings panel allowed %s\n", failure);
		return 1;
	}
	if (ret != 1)
		return ret;

	count = product_rofs_sentinel_update_count();
	if (count != updates) {
		fprintf(stderr,
			"settings panel denial left %u sentinel updates, expected %u\n",
			count, updates);
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"settings panel denial left product mount writable\n");
		close(fd);
		return 1;
	}

	if (saved_errno != EROFS)
		fprintf(stderr,
			"post-settings-panel-denial write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static int product_rofs_settings_panel_unknown_denied(unsigned int updates)
{
	return product_rofs_settings_panel_denied("updates.remove", NULL,
						 "unknown action", updates);
}

static int product_rofs_settings_panel_unsafe_config_denied(unsigned int updates)
{
	return product_rofs_settings_panel_denied(
		"updates.install", HDN_SETTINGS_PANEL_UNSAFE_CONFIG,
		"unsafe config", updates);
}

static int product_rofs_settings_panel_updates_and_reseals(unsigned int min_updates)
{
	int saved_errno;
	unsigned int count;
	int ret;
	int fd;

	count = product_rofs_sentinel_update_count();
	ret = product_rofs_settings_panel_run("updates.install", NULL, true);
	if (ret == KSFT_SKIP)
		return ret;
	if (ret) {
		fprintf(stderr, "settings panel dry-run exited with %d\n",
			ret);
		return ret;
	}
	if (product_rofs_sentinel_update_count() != count) {
		fprintf(stderr, "settings panel dry-run changed sentinel\n");
		return 1;
	}
	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"settings panel dry-run left product mount writable\n");
		close(fd);
		return 1;
	}
	if (saved_errno != EROFS) {
		fprintf(stderr,
			"post-settings-panel-dry-run write-open failed with %s\n",
			strerror(saved_errno));
		return 2;
	}

	ret = product_rofs_settings_panel_run("updates.install", NULL, false);
	if (ret == KSFT_SKIP)
		return ret;
	if (ret) {
		fprintf(stderr, "settings panel exited with %d\n", ret);
		return ret;
	}

	count = product_rofs_sentinel_update_count();
	if (count < min_updates) {
		fprintf(stderr,
			"settings panel only wrote %u sentinel updates\n",
			count);
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"settings panel left product mount writable\n");
		close(fd);
		return 1;
	}

	if (saved_errno != EROFS)
		fprintf(stderr,
			"post-settings-panel write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static int product_rofs_settings_ui_run(const char *choice,
					const char *config_path,
					bool dry_run, bool test_cancel)
{
	char *argv[8];
	unsigned int argc = 0;
	pid_t child;

	if (access(HDN_SETTINGS_UI_EXEC, X_OK)) {
		fprintf(stderr,
			"settings UI helper is not executable: %s\n",
			strerror(errno));
		return KSFT_SKIP;
	}

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		argv[argc++] = "hdn-settings-ui";
		if (config_path) {
			argv[argc++] = "--config";
			argv[argc++] = (char *)config_path;
		}
		if (dry_run)
			argv[argc++] = "--dry-run";
		if (test_cancel) {
			argv[argc++] = "--test-cancel";
		} else if (choice) {
			argv[argc++] = "--test-choice";
			argv[argc++] = (char *)choice;
		}
		argv[argc] = NULL;

		execv(HDN_SETTINGS_UI_EXEC, argv);
		fprintf(stderr, "settings UI exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int product_rofs_settings_ui_denied(const char *choice,
					   const char *config_path,
					   bool test_cancel,
					   const char *failure,
					   unsigned int updates)
{
	int saved_errno;
	unsigned int count;
	int ret;
	int fd;

	ret = product_rofs_settings_ui_run(choice, config_path, false,
					   test_cancel);
	if (ret == KSFT_SKIP)
		return ret;
	if (!ret) {
		fprintf(stderr, "settings UI allowed %s\n", failure);
		return 1;
	}
	if (ret != 1)
		return ret;

	count = product_rofs_sentinel_update_count();
	if (count != updates) {
		fprintf(stderr,
			"settings UI denial left %u sentinel updates, expected %u\n",
			count, updates);
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"settings UI denial left product mount writable\n");
		close(fd);
		return 1;
	}

	if (saved_errno != EROFS)
		fprintf(stderr,
			"post-settings-UI-denial write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static int product_rofs_settings_ui_unknown_denied(unsigned int updates)
{
	return product_rofs_settings_ui_denied("updates.remove", NULL, false,
					       "unknown action", updates);
}

static int product_rofs_settings_ui_unsafe_config_denied(unsigned int updates)
{
	return product_rofs_settings_ui_denied(
		"updates.install", HDN_SETTINGS_UI_UNSAFE_CONFIG, false,
		"unsafe config", updates);
}

static int product_rofs_settings_ui_cancel_denied(unsigned int updates)
{
	return product_rofs_settings_ui_denied(NULL, NULL, true,
					       "canceled selection", updates);
}

static int product_rofs_settings_ui_no_display_denied(unsigned int updates)
{
	return product_rofs_settings_ui_denied(NULL, NULL, false,
					       "no-display UI", updates);
}

static int product_rofs_settings_ui_updates_and_reseals(unsigned int min_updates)
{
	int saved_errno;
	unsigned int count;
	int ret;
	int fd;

	count = product_rofs_sentinel_update_count();
	ret = product_rofs_settings_ui_run("updates.install", NULL, true,
					   false);
	if (ret == KSFT_SKIP)
		return ret;
	if (ret) {
		fprintf(stderr, "settings UI dry-run exited with %d\n",
			ret);
		return ret;
	}
	if (product_rofs_sentinel_update_count() != count) {
		fprintf(stderr, "settings UI dry-run changed sentinel\n");
		return 1;
	}
	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"settings UI dry-run left product mount writable\n");
		close(fd);
		return 1;
	}
	if (saved_errno != EROFS) {
		fprintf(stderr,
			"post-settings-UI-dry-run write-open failed with %s\n",
			strerror(saved_errno));
		return 2;
	}

	ret = product_rofs_settings_ui_run("updates.install", NULL, false,
					   false);
	if (ret == KSFT_SKIP)
		return ret;
	if (ret) {
		fprintf(stderr, "settings UI exited with %d\n", ret);
		return ret;
	}

	count = product_rofs_sentinel_update_count();
	if (count < min_updates) {
		fprintf(stderr,
			"settings UI only wrote %u sentinel updates\n",
			count);
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"settings UI left product mount writable\n");
		close(fd);
		return 1;
	}

	if (saved_errno != EROFS)
		fprintf(stderr,
			"post-settings-UI write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static int product_rofs_prompt_dispatch_run(const char *action,
					    const char *config_path)
{
	pid_t child;

	if (access(HDN_PROMPT_DISPATCH_EXEC, X_OK)) {
		fprintf(stderr,
			"prompt dispatch helper is not executable: %s\n",
			strerror(errno));
		return KSFT_SKIP;
	}

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		if (config_path)
			execl(HDN_PROMPT_DISPATCH_EXEC, "hdn-prompt-dispatch",
			      "--config", config_path, action, NULL);
		else
			execl(HDN_PROMPT_DISPATCH_EXEC, "hdn-prompt-dispatch",
			      action, NULL);
		fprintf(stderr, "prompt dispatch exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int product_rofs_prompt_dispatch_denied(const char *action,
					       const char *config_path,
					       const char *failure,
					       unsigned int updates)
{
	int saved_errno;
	unsigned int count;
	int ret;
	int fd;

	ret = product_rofs_prompt_dispatch_run(action, config_path);
	if (ret == KSFT_SKIP)
		return ret;
	if (!ret) {
		fprintf(stderr, "prompt dispatch allowed %s\n", failure);
		return 1;
	}
	if (ret != 1)
		return ret;

	count = product_rofs_sentinel_update_count();
	if (count != updates) {
		fprintf(stderr,
			"prompt dispatch denial left %u sentinel updates, expected %u\n",
			count, updates);
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"prompt dispatch denial left product mount writable\n");
		close(fd);
		return 1;
	}

	if (saved_errno != EROFS)
		fprintf(stderr,
			"post-prompt-dispatch-denial write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static int product_rofs_prompt_dispatch_unknown_denied(unsigned int updates)
{
	return product_rofs_prompt_dispatch_denied("unknown-update", NULL,
						  "unknown action", updates);
}

static int product_rofs_prompt_dispatch_unsafe_config_denied(unsigned int updates)
{
	return product_rofs_prompt_dispatch_denied(
		"package-update", HDN_PROMPT_DISPATCH_UNSAFE_CONFIG,
		"unsafe config", updates);
}

static int product_rofs_prompt_dispatch_updates_and_reseals(unsigned int min_updates)
{
	int saved_errno;
	unsigned int count;
	int ret;
	int fd;

	ret = product_rofs_prompt_dispatch_run("package-update", NULL);
	if (ret == KSFT_SKIP)
		return ret;
	if (ret) {
		fprintf(stderr, "prompt dispatch exited with %d\n", ret);
		return ret;
	}

	count = product_rofs_sentinel_update_count();
	if (count < min_updates) {
		fprintf(stderr,
			"prompt dispatch only wrote %u sentinel updates\n",
			count);
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"prompt dispatch left product mount writable\n");
		close(fd);
		return 1;
	}

	if (saved_errno != EROFS)
		fprintf(stderr,
			"post-prompt-dispatch write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static void cleanup_image_seal_test(void)
{
	cleanup_product_rofs_mount(HDN_IMAGE_SEAL_DIR);
}

static int image_seal_run(const char *seal, const char *config_path,
			  bool dry_run)
{
	pid_t child;

	if (access(HDN_IMAGE_SEAL_EXEC, X_OK)) {
		fprintf(stderr, "image seal helper is not executable: %s\n",
			strerror(errno));
		return KSFT_SKIP;
	}

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		if (config_path && dry_run)
			execl(HDN_IMAGE_SEAL_EXEC, "hdn-image-seal",
			      "--dry-run", "--config", config_path, seal,
			      NULL);
		else if (config_path)
			execl(HDN_IMAGE_SEAL_EXEC, "hdn-image-seal",
			      "--config", config_path, seal, NULL);
		else if (dry_run)
			execl(HDN_IMAGE_SEAL_EXEC, "hdn-image-seal",
			      "--dry-run", seal, NULL);
		else
			execl(HDN_IMAGE_SEAL_EXEC, "hdn-image-seal", seal,
			      NULL);
		fprintf(stderr, "image seal exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

static int image_seal_mount_is_writable(void)
{
	int fd;

	errno = 0;
	fd = open(HDN_IMAGE_SEAL_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr,
			"image seal sentinel write-open failed with %s\n",
			strerror(errno));
		return errno == EROFS ? 1 : 2;
	}
	close(fd);
	return 0;
}

static int image_seal_denied(const char *seal, const char *config_path,
			     const char *failure)
{
	int ret;

	ret = image_seal_run(seal, config_path, false);
	if (ret == KSFT_SKIP)
		return ret;
	if (!ret) {
		fprintf(stderr, "image seal allowed %s\n", failure);
		return 1;
	}
	if (ret != 1)
		return ret;

	return image_seal_mount_is_writable();
}

static int image_seal_unknown_denied(void)
{
	return image_seal_denied("unknown-seal", NULL, "unknown seal");
}

static int image_seal_unsafe_config_denied(void)
{
	return image_seal_denied("default", HDN_IMAGE_SEAL_UNSAFE_CONFIG,
				 "unsafe config");
}

static int image_seal_applies_rofs(void)
{
	int saved_errno;
	int ret;
	int fd;

	ret = image_seal_run("default", NULL, true);
	if (ret) {
		cleanup_image_seal_test();
		return ret;
	}
	ret = image_seal_mount_is_writable();
	if (ret) {
		fprintf(stderr, "image seal dry-run changed mount state\n");
		cleanup_image_seal_test();
		return ret;
	}

	ret = image_seal_run("default", NULL, false);
	if (ret) {
		cleanup_image_seal_test();
		return ret;
	}

	errno = 0;
	fd = open(HDN_IMAGE_SEAL_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr, "image seal left product mount writable\n");
		close(fd);
		cleanup_image_seal_test();
		return 1;
	}

	cleanup_image_seal_test();
	if (saved_errno != EROFS)
		fprintf(stderr,
			"post-image-seal write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static int product_rofs_broker_apply_list_denied(const char *list_path,
						 const char *failure)
{
	int saved_errno;
	pid_t child;
	int ret;
	int fd;

	if (access(HDN_ADMIN_BROKER_EXEC, X_OK)) {
		fprintf(stderr,
			"product ROFS broker is not executable: %s\n",
			strerror(errno));
		return KSFT_SKIP;
	}

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_ADMIN_BROKER_EXEC, "hdn-admin-broker",
		      "rofs-apply", "-f", list_path, NULL);
		fprintf(stderr, "product ROFS broker apply exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	ret = child_exit_result(child);
	if (!ret) {
		fprintf(stderr,
			"product ROFS broker allowed %s apply list\n",
			failure);
		return 1;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_BROKER_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd < 0) {
		fprintf(stderr,
			"broker apply denial left product mount unwritable: %s\n",
			strerror(saved_errno));
		return 1;
	}
	if (write(fd, "denied-list\n", strlen("denied-list\n")) !=
	    (ssize_t)strlen("denied-list\n")) {
		close(fd);
		return 2;
	}
	close(fd);
	return 0;
}

static int product_rofs_broker_apply_denied_list(void)
{
	return product_rofs_broker_apply_list_denied(HDN_ROFS_APPLY_DENIED_LIST,
						    "unapproved");
}

static int product_rofs_broker_apply_unsafe_list(void)
{
	return product_rofs_broker_apply_list_denied(HDN_ROFS_APPLY_UNSAFE_LIST,
						    "unsafe");
}

static int product_rofs_broker_apply_list_seals_mount(void)
{
	int saved_errno;
	pid_t child;
	int ret;
	int fd;

	if (access(HDN_ADMIN_BROKER_EXEC, X_OK)) {
		fprintf(stderr,
			"product ROFS broker is not executable: %s\n",
			strerror(errno));
		cleanup_product_rofs_mount(HDN_PRODUCT_ROFS_BROKER_DIR);
		return KSFT_SKIP;
	}

	child = fork();
	if (child < 0) {
		cleanup_product_rofs_mount(HDN_PRODUCT_ROFS_BROKER_DIR);
		return 2;
	}

	if (!child) {
		execl(HDN_ADMIN_BROKER_EXEC, "hdn-admin-broker",
		      "rofs-apply", "-f", HDN_ROFS_APPLY_LIST, NULL);
		fprintf(stderr, "product ROFS broker apply exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	ret = child_exit_result(child);
	if (ret) {
		fprintf(stderr, "product ROFS broker apply exited with %d\n",
			ret);
		cleanup_product_rofs_mount(HDN_PRODUCT_ROFS_BROKER_DIR);
		return ret;
	}

	errno = 0;
	fd = open(HDN_PRODUCT_ROFS_BROKER_SENTINEL,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		fprintf(stderr,
			"broker ROFS apply left product mount writable\n");
		close(fd);
		cleanup_product_rofs_mount(HDN_PRODUCT_ROFS_BROKER_DIR);
		return 1;
	}

	cleanup_product_rofs_mount(HDN_PRODUCT_ROFS_BROKER_DIR);
	if (saved_errno != EROFS)
		fprintf(stderr, "broker ROFS apply write-open failed with %s\n",
			strerror(saved_errno));
	return saved_errno == EROFS ? 0 : 2;
}

static int raw_io_device_denied(void)
{
	int saved_errno = 0;
	int fd;

	errno = 0;
	fd = open(HDN_DEV_PORT, O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		close(fd);
		return 1;
	}
	saved_errno = errno;

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int ensure_cpu_char_device(const char *path, unsigned int major)
{
	struct stat st;

	if (mkdir(HDN_DEV_CPU_DIR, 0755) && errno != EEXIST)
		return 2;
	if (mkdir(HDN_DEV_CPU0_DIR, 0755) && errno != EEXIST)
		return 2;

	if (!lstat(path, &st)) {
		if (S_ISCHR(st.st_mode) && major(st.st_rdev) == major &&
		    minor(st.st_rdev) == 0)
			return 0;
		return 2;
	}
	if (errno != ENOENT)
		return 2;

	if (mknod(path, S_IFCHR | 0600, makedev(major, 0)) &&
	    errno != EEXIST)
		return 2;

	return 0;
}

static int raw_cpu_device_denied(const char *path, unsigned int major)
{
	int saved_errno = 0;
	int ret;
	int fd;

	ret = ensure_cpu_char_device(path, major);
	if (ret)
		return ret;

	errno = 0;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		close(fd);
		return 1;
	}
	saved_errno = errno;

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int raw_cpu_msr_device_denied(void)
{
	return raw_cpu_device_denied(HDN_DEV_CPU_MSR, HDN_MSR_MAJOR);
}

static int raw_cpu_cpuid_device_denied(void)
{
	return raw_cpu_device_denied(HDN_DEV_CPU_CPUID, HDN_CPUID_MAJOR);
}

static int first_block_device(dev_t *dev)
{
	DIR *dir;
	struct dirent *entry;
	char path[512];
	char buf[64];
	unsigned int major;
	unsigned int minor;
	int fd;
	ssize_t len;
	int ret = -ENOENT;

	dir = opendir("/sys/class/block");
	if (!dir)
		return -errno;

	while ((entry = readdir(dir))) {
		if (!strcmp(entry->d_name, ".") ||
		    !strcmp(entry->d_name, ".."))
			continue;

		snprintf(path, sizeof(path), "/sys/class/block/%s/dev",
			 entry->d_name);
		fd = open(path, O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			continue;

		len = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (len <= 0)
			continue;

		buf[len] = '\0';
		if (sscanf(buf, "%u:%u", &major, &minor) != 2)
			continue;

		*dev = makedev(major, minor);
		ret = 0;
		break;
	}

	closedir(dir);
	return ret;
}

static int create_block_device_test_node(void)
{
	dev_t dev;

	if (first_block_device(&dev))
		return KSFT_SKIP;

	unlink(HDN_BLOCK_DEVICE_TEST);
	if (mknod(HDN_BLOCK_DEVICE_TEST, S_IFBLK | 0600, dev))
		return 2;

	return 0;
}

static int block_device_open_without_authority_denied(void)
{
	int saved_errno = 0;
	int ret;
	int fd;

	ret = create_block_device_test_node();
	if (ret)
		return ret;

	errno = 0;
	fd = open(HDN_BLOCK_DEVICE_TEST, O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		close(fd);
		unlink(HDN_BLOCK_DEVICE_TEST);
		return 1;
	}
	saved_errno = errno;
	unlink(HDN_BLOCK_DEVICE_TEST);

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int block_device_query_with_access_allowed(void)
{
	unsigned long long bytes = 0;
	int saved_errno = 0;
	int ret;
	int fd;

	ret = create_block_device_test_node();
	if (ret)
		return ret;

	errno = 0;
	fd = open(HDN_BLOCK_DEVICE_TEST, O_RDONLY | O_CLOEXEC);
	saved_errno = errno;
	if (fd < 0) {
		fprintf(stderr, "block-device query open failed with %s\n",
			strerror(saved_errno));
		unlink(HDN_BLOCK_DEVICE_TEST);
		return errno_is_denial(saved_errno) ? 1 : 2;
	}

	errno = 0;
	ret = ioctl(fd, BLKGETSIZE64, &bytes);
	saved_errno = errno;
	close(fd);
	unlink(HDN_BLOCK_DEVICE_TEST);

	if (ret) {
		fprintf(stderr, "block-device query ioctl failed with %s\n",
			strerror(saved_errno));
		return 2;
	}

	return 0;
}

static int block_device_admin_without_authority_denied(void)
{
	int saved_errno = 0;
	int ret;
	int fd;

	ret = create_block_device_test_node();
	if (ret)
		return ret;

	errno = 0;
	fd = open(HDN_BLOCK_DEVICE_TEST, O_RDONLY | O_CLOEXEC);
	saved_errno = errno;
	if (fd < 0) {
		fprintf(stderr, "block-device admin open failed with %s\n",
			strerror(saved_errno));
		unlink(HDN_BLOCK_DEVICE_TEST);
		return errno_is_denial(saved_errno) ? 1 : 2;
	}

	errno = 0;
	ret = ioctl(fd, BLKRRPART, 0);
	saved_errno = errno;
	close(fd);
	unlink(HDN_BLOCK_DEVICE_TEST);

	if (!ret) {
		fprintf(stderr, "block-device admin ioctl was allowed\n");
		return 1;
	}

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int child_exit_result(pid_t child)
{
	int status;

	if (waitpid(child, &status, 0) < 0)
		return 2;
	if (!WIFEXITED(status))
		return 2;

	return WEXITSTATUS(status);
}

struct hdn_msgbuf {
	long mtype;
	char mtext[];
};

static int sysvipc_msg_overpermissive_denied(void)
{
	struct hdn_msgbuf *msg;
	pid_t child;
	int msqid;
	int ret;

	msqid = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
	if (msqid < 0)
		return 2;

	msg = calloc(1, sizeof(*msg) + 1);
	if (!msg) {
		msgctl(msqid, IPC_RMID, NULL);
		return 2;
	}
	msg->mtype = 1;
	msg->mtext[0] = 'x';

	child = fork();
	if (child < 0) {
		msgctl(msqid, IPC_RMID, NULL);
		free(msg);
		return 2;
	}

	if (!child) {
		if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
			_exit(2);
		errno = 0;
		ret = msgsnd(msqid, msg, 1, IPC_NOWAIT);
		if (!ret)
			_exit(1);
		_exit(errno_is_denial(errno) ? 0 : 2);
	}

	ret = child_exit_result(child);
	msgctl(msqid, IPC_RMID, NULL);
	free(msg);
	return ret;
}

static int sysvipc_sem_overpermissive_denied(void)
{
	struct sembuf op = {
		.sem_num = 0,
		.sem_op = 0,
		.sem_flg = IPC_NOWAIT,
	};
	pid_t child;
	int semid;
	int ret;

	semid = semget(IPC_PRIVATE, 1, IPC_CREAT | 0666);
	if (semid < 0)
		return 2;

	child = fork();
	if (child < 0) {
		semctl(semid, 0, IPC_RMID);
		return 2;
	}

	if (!child) {
		if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
			_exit(2);
		errno = 0;
		ret = semop(semid, &op, 1);
		if (!ret)
			_exit(1);
		_exit(errno_is_denial(errno) ? 0 : 2);
	}

	ret = child_exit_result(child);
	semctl(semid, 0, IPC_RMID);
	return ret;
}

static int sysvipc_shm_overpermissive_denied(void)
{
	pid_t child;
	int shmid;
	int ret;

	shmid = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0666);
	if (shmid < 0)
		return 2;

	child = fork();
	if (child < 0) {
		shmctl(shmid, IPC_RMID, NULL);
		return 2;
	}

	if (!child) {
		void *addr;

		if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
			_exit(2);
		errno = 0;
		addr = shmat(shmid, NULL, 0);
		if (addr != (void *)-1) {
			shmdt(addr);
			_exit(1);
		}
		_exit(errno_is_denial(errno) ? 0 : 2);
	}

	ret = child_exit_result(child);
	shmctl(shmid, IPC_RMID, NULL);
	return ret;
}

static int protected_shm_same_profile_allowed(void)
{
	void *addr;
	int shmid;

	shmid = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
	if (shmid < 0)
		return 2;

	addr = shmat(shmid, NULL, 0);
	if (addr == (void *)-1) {
		shmctl(shmid, IPC_RMID, NULL);
		return 2;
	}

	shmdt(addr);
	shmctl(shmid, IPC_RMID, NULL);
	return 0;
}

static int protected_shm_cross_profile_denied(void)
{
	pid_t child;
	int shmid;
	int ret;

	shmid = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0666);
	if (shmid < 0)
		return 2;

	child = fork();
	if (child < 0) {
		shmctl(shmid, IPC_RMID, NULL);
		return 2;
	}

	if (!child) {
		void *addr;

		if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
			_exit(2);
		errno = 0;
		addr = shmat(shmid, NULL, 0);
		if (addr != (void *)-1) {
			shmdt(addr);
			_exit(1);
		}
		_exit(errno_is_denial(errno) ? 0 : 2);
	}

	ret = child_exit_result(child);
	shmctl(shmid, IPC_RMID, NULL);
	return ret;
}

static int setup_posix_mqueue_test(mqd_t *mqd)
{
	struct mq_attr attr = {
		.mq_maxmsg = 4,
		.mq_msgsize = 8,
	};

	mq_unlink(HDN_POSIX_MQ_NAME);
	*mqd = mq_open(HDN_POSIX_MQ_NAME,
		       O_CREAT | O_EXCL | O_RDWR | O_NONBLOCK, 0666, &attr);
	if (*mqd == (mqd_t)-1)
		return 2;

	return 0;
}

static int posix_mqueue_send_overpermissive_denied(void)
{
	static const char msg[] = "x";
	pid_t child;
	mqd_t mqd;
	int ret;

	ret = setup_posix_mqueue_test(&mqd);
	if (ret)
		return ret;

	child = fork();
	if (child < 0) {
		mq_close(mqd);
		mq_unlink(HDN_POSIX_MQ_NAME);
		return 2;
	}

	if (!child) {
		mqd_t child_mqd;

		if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
			_exit(2);
		errno = 0;
		child_mqd = mq_open(HDN_POSIX_MQ_NAME, O_WRONLY | O_NONBLOCK);
		if (child_mqd == (mqd_t)-1)
			_exit(errno_is_denial(errno) ? 0 : 2);
		errno = 0;
		ret = mq_send(child_mqd, msg, sizeof(msg), 0);
		mq_close(child_mqd);
		if (!ret)
			_exit(1);
		_exit(errno_is_denial(errno) ? 0 : 2);
	}

	ret = child_exit_result(child);
	mq_close(mqd);
	mq_unlink(HDN_POSIX_MQ_NAME);
	return ret;
}

static int posix_mqueue_receive_overpermissive_denied(void)
{
	char buf[8];
	pid_t child;
	mqd_t mqd;
	int ret;

	ret = setup_posix_mqueue_test(&mqd);
	if (ret)
		return ret;
	if (mq_send(mqd, "x", 2, 0)) {
		mq_close(mqd);
		mq_unlink(HDN_POSIX_MQ_NAME);
		return 2;
	}

	child = fork();
	if (child < 0) {
		mq_close(mqd);
		mq_unlink(HDN_POSIX_MQ_NAME);
		return 2;
	}

	if (!child) {
		mqd_t child_mqd;
		ssize_t len;

		if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
			_exit(2);
		errno = 0;
		child_mqd = mq_open(HDN_POSIX_MQ_NAME, O_RDONLY | O_NONBLOCK);
		if (child_mqd == (mqd_t)-1)
			_exit(errno_is_denial(errno) ? 0 : 2);
		errno = 0;
		len = mq_receive(child_mqd, buf, sizeof(buf), NULL);
		mq_close(child_mqd);
		if (len >= 0)
			_exit(1);
		_exit(errno_is_denial(errno) ? 0 : 2);
	}

	ret = child_exit_result(child);
	mq_close(mqd);
	mq_unlink(HDN_POSIX_MQ_NAME);
	return ret;
}

static int tty_controlling_fd(void)
{
	int fd;

	if (setsid() < 0 && errno != EPERM)
		return -1;

	fd = open("/dev/ttyS0", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		fd = open("/dev/console", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return -1;
	if (!isatty(fd)) {
		close(fd);
		errno = ENOTTY;
		return -1;
	}
	ioctl(fd, TIOCSCTTY, 0);

	return fd;
}

static int tty_tiocsti_denied(void)
{
	pid_t child;
	int ret;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		char ch = 'x';
		int fd;

		fd = tty_controlling_fd();
		if (fd < 0)
			_exit(errno == ENOTTY || errno == ENOENT ?
			      KSFT_SKIP : 2);
		if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
			_exit(2);
		errno = 0;
		ret = ioctl(fd, TIOCSTI, &ch);
		close(fd);
		if (!ret)
			_exit(1);
		_exit(errno_is_denial(errno) || errno == EIO ? 0 : 2);
	}

	return child_exit_result(child);
}

static int tty_tioclinux_denied(void)
{
	pid_t child;
	int ret;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		char arg[2] = { TIOCL_GETFGCONSOLE, 0 };
		int fd;

		fd = tty_controlling_fd();
		if (fd < 0)
			_exit(errno == ENOTTY || errno == ENOENT ?
			      KSFT_SKIP : 2);
		if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
			_exit(2);
		errno = 0;
		ret = ioctl(fd, TIOCLINUX, arg);
		close(fd);
		if (!ret)
			_exit(1);
		_exit(errno_is_denial(errno) || errno == ENOTTY ? 0 : 2);
	}

	return child_exit_result(child);
}

enum hdn_tty_access_test_operation {
	HDN_TTY_ACCESS_TEST_READ = 1,
	HDN_TTY_ACCESS_TEST_WRITE = 2,
	HDN_TTY_ACCESS_TEST_IOCTL = 3,
};

static int tty_noncontrolling_fd(void)
{
	int fd;

	fd = open("/dev/ttyS0", O_RDWR | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
	if (fd < 0)
		fd = open("/dev/console",
			  O_RDWR | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	if (!isatty(fd)) {
		close(fd);
		errno = ENOTTY;
		return -1;
	}

	return fd;
}

static void tty_access_child(enum hdn_tty_access_test_operation operation)
{
	struct winsize winsz;
	char ch;
	int fd;
	int ret;

	fd = tty_noncontrolling_fd();
	if (fd < 0)
		_exit(errno == ENOTTY || errno == ENOENT ? KSFT_SKIP : 2);
	if (setsid() < 0 && errno != EPERM) {
		close(fd);
		_exit(2);
	}
	if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY)) {
		close(fd);
		_exit(2);
	}

	errno = 0;
	switch (operation) {
	case HDN_TTY_ACCESS_TEST_READ:
		ret = read(fd, &ch, 1);
		break;
	case HDN_TTY_ACCESS_TEST_WRITE:
		ch = 'x';
		ret = write(fd, &ch, 1);
		break;
	case HDN_TTY_ACCESS_TEST_IOCTL:
		memset(&winsz, 0, sizeof(winsz));
		ret = ioctl(fd, TIOCGWINSZ, &winsz);
		break;
	default:
		close(fd);
		_exit(2);
	}

	close(fd);
	if (ret >= 0)
		_exit(1);
	_exit(errno_is_denial(errno) ? 0 : 2);
}

static int tty_access_denied(enum hdn_tty_access_test_operation operation)
{
	pid_t child;

	child = fork();
	if (child < 0)
		return 2;
	if (!child) {
		tty_access_child(operation);
		_exit(2);
	}

	return child_exit_result(child);
}

static int tty_access_read_denied(void)
{
	return tty_access_denied(HDN_TTY_ACCESS_TEST_READ);
}

static int tty_access_write_denied(void)
{
	return tty_access_denied(HDN_TTY_ACCESS_TEST_WRITE);
}

static int tty_access_ioctl_denied(void)
{
	return tty_access_denied(HDN_TTY_ACCESS_TEST_IOCTL);
}

static int tty_controlling_pty_broker_child(void)
{
	struct termios termios;
	char path[128];
	pid_t broker;
	pid_t child;
	int sockets[2];
	int master;
	int slave;
	int ret;

	master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
	if (master < 0) {
		fprintf(stderr, "TTY PTY allocation failed: %s\n",
			strerror(errno));
		return 2;
	}
	if (grantpt(master) || unlockpt(master) ||
	    ptsname_r(master, path, sizeof(path))) {
		close(master);
		return 2;
	}

	slave = open(path, O_RDWR | O_NOCTTY | O_CLOEXEC);
	if (slave < 0) {
		close(master);
		return 2;
	}
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets)) {
		close(slave);
		close(master);
		return 2;
	}

	broker = fork();
	if (broker < 0) {
		close(sockets[0]);
		close(sockets[1]);
		close(slave);
		close(master);
		return 2;
	}
	if (!broker) {
		int received;

		close(sockets[0]);
		close(master);

		/* Fork inheritance alone must not confer PTY broker authority. */
		errno = 0;
		if (!tcgetattr(slave, &termios))
			_exit(1);
		if (!errno_is_denial(errno))
			_exit(2);
		close(slave);

		received = recv_fd_over_socket(sockets[1]);
		close(sockets[1]);
		if (received < 0)
			_exit(2);
		if (tcgetattr(received, &termios)) {
			close(received);
			_exit(1);
		}

		child = fork();
		if (child < 0) {
			close(received);
			_exit(2);
		}
		if (!child) {
			if (setsid() < 0)
				_exit(2);
			errno = 0;
			ret = ioctl(received, TIOCSCTTY, 0);
			close(received);
			_exit(ret ? (errno_is_denial(errno) ? 1 : 2) : 0);
		}

		ret = child_exit_result(child);
		if (!ret && tcgetattr(received, &termios))
			ret = 1;
		close(received);
		_exit(ret);
	}

	close(sockets[1]);
	if (send_fd_over_socket(sockets[0], slave)) {
		kill(broker, SIGKILL);
		ret = 2;
	} else {
		ret = child_exit_result(broker);
		broker = -1;
	}
	if (broker > 0)
		(void)child_exit_result(broker);
	close(sockets[0]);
	close(slave);
	close(master);
	return ret;
}

static int tty_controlling_pty_acquisition_allowed(void)
{
	pid_t child;

	child = fork();
	if (child < 0)
		return 2;
	if (!child) {
		if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
			_exit(2);
		_exit(tty_controlling_pty_broker_child());
	}

	return child_exit_result(child);
}

static int anonymous_rwx_mapping_child(void)
{
	size_t page_size = sysconf(_SC_PAGESIZE);
	void *addr;

	addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE | PROT_EXEC,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr != MAP_FAILED) {
		munmap(addr, page_size);
		return 1;
	}

	return errno_is_denial(errno) ? 0 : 2;
}

static int jit_exec_after_write_allowed(void)
{
	size_t page_size = sysconf(_SC_PAGESIZE);
	bool executable = false;
	void *addr;
	int ret;

	addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED)
		return 2;
	if (mprotect(addr, page_size, PROT_READ)) {
		munmap(addr, page_size);
		return 2;
	}

	errno = 0;
	ret = mprotect(addr, page_size, PROT_READ | PROT_EXEC);
	if (!ret)
		ret = mapping_has_exec(addr, &executable);
	munmap(addr, page_size);

	return ret == 0 && executable ? 0 : 1;
}

static int jit_file_backed_exec_after_write_denied(void)
{
#ifdef __NR_memfd_create
	size_t page_size = sysconf(_SC_PAGESIZE);
	int saved_errno = 0;
	void *addr;
	int fd;
	int ret;

	fd = syscall(__NR_memfd_create, "hdn-jit-file", MFD_CLOEXEC);
	if (fd < 0)
		return 2;
	if (ftruncate(fd, page_size)) {
		close(fd);
		return 2;
	}

	addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE,
		    fd, 0);
	close(fd);
	if (addr == MAP_FAILED)
		return 2;

	errno = 0;
	ret = mprotect(addr, page_size, PROT_READ | PROT_EXEC);
	if (ret)
		saved_errno = errno;
	munmap(addr, page_size);

	if (!ret)
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 2;
#else
	return KSFT_SKIP;
#endif
}

static int elf_note_memory_mode_allowed(const char *mode)
{
	pid_t child;

	if (access(HDN_ELFNOTE_JIT_EXEC, X_OK))
		return KSFT_SKIP;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		if (mode)
			execl(HDN_ELFNOTE_JIT_EXEC, "hdn-elfnote-jit",
			      mode, NULL);
		else
			execl(HDN_ELFNOTE_JIT_EXEC, "hdn-elfnote-jit", NULL);
		_exit(2);
	}

	return child_exit_result(child);
}

static int elf_note_jit_exec_after_write_allowed(void)
{
	return elf_note_memory_mode_allowed(NULL);
}

static int elf_note_exec_stack_elf_allowed(void)
{
	return elf_note_memory_mode_allowed("exec-stack");
}

static int elf_note_textrel_mprotect_allowed(void)
{
	return elf_note_memory_mode_allowed("textrel");
}

static int copy_file(const char *src, const char *dst, mode_t mode)
{
	char buf[4096];
	int in;
	int out;
	int ret = 0;

	in = open(src, O_RDONLY | O_CLOEXEC);
	if (in < 0)
		return -errno;

	out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
	if (out < 0) {
		ret = -errno;
		goto out_close_in;
	}

	for (;;) {
		ssize_t rd = read(in, buf, sizeof(buf));

		if (rd < 0) {
			ret = -errno;
			break;
		}
		if (!rd)
			break;
		if (write(out, buf, rd) != rd) {
			ret = -errno;
			break;
		}
	}

	if (fchmod(out, mode) && !ret)
		ret = -errno;
	close(out);
out_close_in:
	close(in);
	return ret;
}

static int untrusted_exec_denied(void)
{
	int status;
	pid_t child;
	int ret;

	unlink(HDN_UNTRUSTED_EXEC);
	ret = copy_file("/hdn_smoke", HDN_UNTRUSTED_EXEC, 0777);
	if (ret)
		return 2;

	child = fork();
	if (child < 0) {
		unlink(HDN_UNTRUSTED_EXEC);
		return 2;
	}

	if (!child) {
		execl(HDN_UNTRUSTED_EXEC, "hdn-untrusted-exec",
		      "--exec-sentinel", NULL);
		_exit(errno_is_denial(errno) ? 0 : 2);
	}

	if (waitpid(child, &status, 0) < 0) {
		unlink(HDN_UNTRUSTED_EXEC);
		return 2;
	}

	unlink(HDN_UNTRUSTED_EXEC);
	if (!WIFEXITED(status))
		return 2;
	return WEXITSTATUS(status) == 0 ? 0 : 1;
}

static int setuid_exec_sentinel(void)
{
	if (geteuid() != 0)
		return 1;
	if (!securityfs_status_has_line("current_profile: 2"))
		return 1;

	return 0;
}

static bool effective_capability_raised(unsigned int capability)
{
#ifdef __NR_capget
	struct __user_cap_header_struct header = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};
	struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3] = {};
	unsigned int index = capability / 32;
	unsigned int bit = capability % 32;

	if (index >= ARRAY_SIZE(data))
		return false;
	if (syscall(__NR_capget, &header, data))
		return false;

	return data[index].effective & (1U << bit);
#else
	return false;
#endif
}

static int filecap_exec_sentinel(void)
{
	if (geteuid() != HDN_TEST_NOBODY)
		return 1;
	if (!effective_capability_raised(CAP_DAC_READ_SEARCH))
		return 1;
	if (!securityfs_status_has_line("current_profile: 2"))
		return 1;

	return 0;
}

static bool spec_ctrl_forced_or_unaffected(unsigned long which)
{
	int ret;

	errno = 0;
	ret = prctl(PR_GET_SPECULATION_CTRL, which, 0, 0, 0);
	if (ret < 0)
		return errno == ENODEV || errno == ENXIO || errno == EINVAL;
	if (ret & PR_SPEC_NOT_AFFECTED)
		return true;
	if (!(ret & PR_SPEC_PRCTL))
		return true;

	return ret & PR_SPEC_FORCE_DISABLE;
}

static void spec_ctrl_try_enable(unsigned long which)
{
	prctl(PR_SET_SPECULATION_CTRL, which, PR_SPEC_ENABLE, 0, 0);
}

static int suid_spectre_sentinel(void)
{
	if (geteuid() != 0)
		return 1;
	if (!securityfs_status_has_line("current_profile: 2"))
		return 1;
	if (!spec_ctrl_forced_or_unaffected(PR_SPEC_STORE_BYPASS))
		return 1;
	if (!spec_ctrl_forced_or_unaffected(PR_SPEC_INDIRECT_BRANCH))
		return 1;

	return 0;
}

static int privexec_stack_limit_sentinel(void)
{
	struct rlimit limit;

	if (geteuid() != 0)
		return 1;
	if (getrlimit(RLIMIT_STACK, &limit))
		return 2;
	if (limit.rlim_cur > HDN_PRIVEXEC_STACK_LIMIT ||
	    limit.rlim_max > HDN_PRIVEXEC_STACK_LIMIT)
		return 1;

	return 0;
}

static int profile_sentinel(unsigned long profile_id)
{
	char expected[64];

	snprintf(expected, sizeof(expected), "current_profile: %lu",
		 profile_id);
	if (!securityfs_status_has_line(expected))
		return 1;

	return 0;
}

static int exec_as_nobody(const char *path, const char *arg)
{
	int status;
	pid_t child;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
			_exit(2);
		execl(path, path, arg, NULL);
		_exit(errno_is_denial(errno) ? 1 : 2);
	}

	if (waitpid(child, &status, 0) < 0)
		return 2;
	if (!WIFEXITED(status))
		return 2;

	return WEXITSTATUS(status) == 0 ? 0 : 1;
}

static int identity_binary_profile_selected(void)
{
	return exec_as_nobody(HDN_IDENTITY_TRUSTED_EXEC,
			      "--identity-binary-sentinel");
}

static int identity_binary_profile_survives_credential_drop(void)
{
	pid_t child;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_IDENTITY_TRUSTED_EXEC, "hdn-identity-trusted",
		      "--identity-drop-sentinel", NULL);
		_exit(2);
	}

	return child_exit_result(child);
}

static int identity_unmatched_copy_defaults(void)
{
	return exec_as_nobody(HDN_IDENTITY_COPY_EXEC,
			      "--identity-default-sentinel");
}

static int identity_script_profile_selected(void)
{
	return exec_as_nobody(HDN_IDENTITY_SCRIPT,
			      "--identity-script-sentinel");
}

static int identity_inherit_profile_selected(void)
{
	return exec_as_nobody(HDN_IDENTITY_TRUSTED_EXEC,
			      "--identity-launch-inherit-sentinel");
}

static int identity_unmatched_exec_inherits_profile(void)
{
	return exec_as_nobody(HDN_IDENTITY_TRUSTED_EXEC,
			      "--identity-launch-unmatched-inherit-sentinel");
}

static int identity_parent_inherit_profile_selected(void)
{
	return exec_as_nobody(HDN_IDENTITY_TRUSTED_EXEC,
			      "--identity-launch-parent-inherit-sentinel");
}

static int identity_parent_inherit_unmatched_defaults(void)
{
	return exec_as_nobody(HDN_IDENTITY_PARENT_INHERIT_EXEC,
			      "--identity-default-sentinel");
}

static int identity_replaced_path_defaults(void)
{
	int ret = 0;
	int fd;

	unlink(HDN_IDENTITY_BACKUP_EXEC);
	if (rename(HDN_IDENTITY_TRUSTED_EXEC, HDN_IDENTITY_BACKUP_EXEC))
		return 2;

	ret = copy_file(HDN_IDENTITY_COPY_EXEC, HDN_IDENTITY_TRUSTED_EXEC,
			0755);
	if (!ret) {
		fd = open(HDN_IDENTITY_TRUSTED_EXEC,
			  O_WRONLY | O_APPEND | O_CLOEXEC);
		if (fd < 0) {
			ret = -errno;
		} else {
			if (write(fd, "\0", 1) != 1)
				ret = -errno;
			close(fd);
		}
	}
	if (!ret)
		ret = exec_as_nobody(HDN_IDENTITY_TRUSTED_EXEC,
				     "--identity-default-sentinel");

	unlink(HDN_IDENTITY_TRUSTED_EXEC);
	if (rename(HDN_IDENTITY_BACKUP_EXEC, HDN_IDENTITY_TRUSTED_EXEC) &&
	    !ret)
		ret = 2;

	return ret < 0 ? 2 : ret;
}

static int exec_with_ids_expect_profile(uid_t uid, gid_t gid, const char *arg)
{
	pid_t child;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		if (setgid(gid) || setuid(uid))
			_exit(2);
		execl("/hdn_smoke", "hdn_smoke", arg, NULL);
		_exit(2);
	}

	return child_exit_result(child);
}

static int subject_uid_profile_selected(void)
{
	return exec_with_ids_expect_profile(HDN_TEST_NOBODY, HDN_TEST_NOBODY,
					    "--subject-uid-sentinel");
}

static int subject_gid_profile_selected(void)
{
	return exec_with_ids_expect_profile(65533, HDN_TEST_NOBODY,
					    "--subject-gid-sentinel");
}

static void cleanup_subject_umask_test(void)
{
	unlink(HDN_SUBJECT_UMASK_FILE);
	rmdir(HDN_SUBJECT_UMASK_DIR);
	rmdir(HDN_SUBJECT_UMASK_ROOT);
}

static int setup_subject_umask_test(void)
{
	cleanup_subject_umask_test();
	if (mkdir(HDN_SUBJECT_UMASK_ROOT, 0777) && errno != EEXIST)
		return -errno;
	if (chmod(HDN_SUBJECT_UMASK_ROOT, 0777))
		return -errno;
	return 0;
}

static int subject_umask_file_sentinel(void)
{
	struct stat st;
	mode_t old;
	int fd;

	old = umask(0000);
	unlink(HDN_SUBJECT_UMASK_FILE);
	fd = open(HDN_SUBJECT_UMASK_FILE,
		  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0666);
	umask(old);
	if (fd < 0)
		return 2;
	close(fd);

	if (stat(HDN_SUBJECT_UMASK_FILE, &st))
		return 2;

	return (st.st_mode & 0777) == 0600 ? 0 : 1;
}

static int subject_umask_dir_sentinel(void)
{
	struct stat st;
	mode_t old;
	int ret;

	old = umask(0000);
	rmdir(HDN_SUBJECT_UMASK_DIR);
	ret = mkdir(HDN_SUBJECT_UMASK_DIR, 0777);
	umask(old);
	if (ret)
		return 2;

	if (stat(HDN_SUBJECT_UMASK_DIR, &st))
		return 2;

	return S_ISDIR(st.st_mode) && (st.st_mode & 0777) == 0700 ? 0 : 1;
}

static int subject_umask_file_private(void)
{
	int ret;

	ret = setup_subject_umask_test();
	if (ret)
		return 2;
	ret = exec_with_ids_expect_profile(HDN_TEST_NOBODY, HDN_TEST_NOBODY,
					   "--subject-umask-file-sentinel");
	cleanup_subject_umask_test();
	return ret;
}

static int subject_umask_dir_private(void)
{
	int ret;

	ret = setup_subject_umask_test();
	if (ret)
		return 2;
	ret = exec_with_ids_expect_profile(HDN_TEST_NOBODY, HDN_TEST_NOBODY,
					   "--subject-umask-dir-sentinel");
	cleanup_subject_umask_test();
	return ret;
}

static void cleanup_setuid_exec_test(void)
{
	unlink(HDN_SETUID_EXEC);
}

static void cleanup_filecap_exec_test(void)
{
	unlink(HDN_FILECAP_EXEC);
}

static int setup_setuid_exec_test(void)
{
	int ret;

	cleanup_setuid_exec_test();
	ret = copy_file("/hdn_smoke", HDN_SETUID_EXEC, 0755);
	if (ret)
		return ret;
	if (chown(HDN_SETUID_EXEC, 0, 0)) {
		ret = -errno;
		goto out_cleanup;
	}
	if (chmod(HDN_SETUID_EXEC, 04755)) {
		ret = -errno;
		goto out_cleanup;
	}

	return 0;

out_cleanup:
	cleanup_setuid_exec_test();
	return ret;
}

static int setup_filecap_exec_test(void)
{
	struct vfs_cap_data caps = {
		.magic_etc = VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE,
	};
	int ret;

	caps.data[0].permitted = 1U << CAP_DAC_READ_SEARCH;

	cleanup_filecap_exec_test();
	ret = copy_file("/hdn_smoke", HDN_FILECAP_EXEC, 0755);
	if (ret)
		return ret;
	if (chown(HDN_FILECAP_EXEC, 0, 0)) {
		ret = -errno;
		goto out_cleanup;
	}
	if (chmod(HDN_FILECAP_EXEC, 0755)) {
		ret = -errno;
		goto out_cleanup;
	}
	if (setxattr(HDN_FILECAP_EXEC, XATTR_NAME_CAPS, &caps,
		     XATTR_CAPS_SZ_2, 0)) {
		ret = -errno;
		goto out_cleanup;
	}

	return 0;

out_cleanup:
	cleanup_filecap_exec_test();
	return ret;
}

static int setuid_exec_privileged_profile(void)
{
	int status;
	pid_t child;
	int ret;

	ret = setup_setuid_exec_test();
	if (ret)
		return 2;

	child = fork();
	if (child < 0) {
		cleanup_setuid_exec_test();
		return 2;
	}

	if (!child) {
		if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
			_exit(2);
		execl(HDN_SETUID_EXEC, "hdn-setuid-exec",
		      "--setuid-sentinel", NULL);
		_exit(errno_is_denial(errno) ? 1 : 2);
	}

	if (waitpid(child, &status, 0) < 0) {
		cleanup_setuid_exec_test();
		return 2;
	}

	cleanup_setuid_exec_test();
	if (!WIFEXITED(status))
		return 2;
	return WEXITSTATUS(status) == 0 ? 0 : 1;
}

static int filecap_exec_privileged_profile(void)
{
	int status;
	pid_t child;
	int ret;

	ret = setup_filecap_exec_test();
	if (ret)
		return 2;

	child = fork();
	if (child < 0) {
		cleanup_filecap_exec_test();
		return 2;
	}

	if (!child) {
		if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
			_exit(2);
		execl(HDN_FILECAP_EXEC, "hdn-filecap-exec",
		      "--filecap-sentinel", NULL);
		_exit(errno_is_denial(errno) ? 1 : 2);
	}

	if (waitpid(child, &status, 0) < 0) {
		cleanup_filecap_exec_test();
		return 2;
	}

	cleanup_filecap_exec_test();
	if (!WIFEXITED(status))
		return 2;
	return WEXITSTATUS(status) == 0 ? 0 : 1;
}

static int setuid_exec_forces_spectre_mitigations(void)
{
	int status;
	pid_t child;
	int ret;

	ret = setup_setuid_exec_test();
	if (ret)
		return 2;

	child = fork();
	if (child < 0) {
		cleanup_setuid_exec_test();
		return 2;
	}

	if (!child) {
		if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
			_exit(2);
		spec_ctrl_try_enable(PR_SPEC_STORE_BYPASS);
		spec_ctrl_try_enable(PR_SPEC_INDIRECT_BRANCH);
		execl(HDN_SETUID_EXEC, "hdn-setuid-exec",
		      "--suid-spectre-sentinel", NULL);
		_exit(2);
	}

	if (waitpid(child, &status, 0) < 0) {
		cleanup_setuid_exec_test();
		return 2;
	}

	cleanup_setuid_exec_test();
	if (!WIFEXITED(status))
		return 2;
	return WEXITSTATUS(status) == 0 ? 0 : 1;
}

static void free_oversize_privexec_env(char **envp)
{
	unsigned int i;

	if (!envp)
		return;
	for (i = 0; envp[i]; i++)
		free(envp[i]);
	free(envp);
}

static char **alloc_oversize_privexec_env(void)
{
	const unsigned int entries = 8;
	const size_t entry_len = 96UL * 1024UL;
	char **envp;
	unsigned int i;

	envp = calloc(entries + 1, sizeof(*envp));
	if (!envp)
		return NULL;

	for (i = 0; i < entries; i++) {
		int prefix;

		envp[i] = malloc(entry_len + 1);
		if (!envp[i])
			goto out_free;
		prefix = snprintf(envp[i], entry_len + 1, "HDN_BIG_ENV_%u=", i);
		if (prefix < 0 || (size_t)prefix >= entry_len)
			goto out_free;
		memset(envp[i] + prefix, 'A' + (i % 26), entry_len - prefix);
		envp[i][entry_len] = '\0';
	}

	return envp;

out_free:
	free_oversize_privexec_env(envp);
	return NULL;
}

static int setuid_exec_oversize_env_denied(void)
{
	char *const args[] = {
		"hdn-setuid-exec",
		"--privexec-arglimit-sentinel",
		NULL,
	};
	char **envp;
	int status;
	pid_t child;
	int ret;

	ret = setup_setuid_exec_test();
	if (ret)
		return 2;
	envp = alloc_oversize_privexec_env();
	if (!envp) {
		cleanup_setuid_exec_test();
		return 2;
	}

	child = fork();
	if (child < 0) {
		free_oversize_privexec_env(envp);
		cleanup_setuid_exec_test();
		return 2;
	}

	if (!child) {
		if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
			_exit(2);
		execve(HDN_SETUID_EXEC, args, envp);
		_exit(errno == E2BIG ? 0 : 1);
	}

	if (waitpid(child, &status, 0) < 0) {
		free_oversize_privexec_env(envp);
		cleanup_setuid_exec_test();
		return 2;
	}

	free_oversize_privexec_env(envp);
	cleanup_setuid_exec_test();
	if (!WIFEXITED(status))
		return 2;
	return WEXITSTATUS(status) == 0 ? 0 : 1;
}

static int setuid_exec_stack_limit_capped(void)
{
	struct rlimit old_limit;
	struct rlimit wide_limit;
	int status;
	pid_t child;
	int ret;

	ret = setup_setuid_exec_test();
	if (ret)
		return 2;
	if (getrlimit(RLIMIT_STACK, &old_limit)) {
		cleanup_setuid_exec_test();
		return 2;
	}
	wide_limit = old_limit;
	if (old_limit.rlim_max == RLIM_INFINITY ||
	    old_limit.rlim_max > HDN_PRIVEXEC_STACK_LIMIT * 4)
		wide_limit.rlim_cur = HDN_PRIVEXEC_STACK_LIMIT * 4;
	else {
		wide_limit.rlim_cur = HDN_PRIVEXEC_STACK_LIMIT * 4;
		wide_limit.rlim_max = wide_limit.rlim_cur;
	}
	if (setrlimit(RLIMIT_STACK, &wide_limit)) {
		cleanup_setuid_exec_test();
		return 2;
	}

	child = fork();
	if (child < 0) {
		setrlimit(RLIMIT_STACK, &old_limit);
		cleanup_setuid_exec_test();
		return 2;
	}

	if (!child) {
		if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
			_exit(2);
		execl(HDN_SETUID_EXEC, "hdn-setuid-exec",
		      "--privexec-stack-sentinel", NULL);
		_exit(errno_is_denial(errno) ? 1 : 2);
	}

	if (waitpid(child, &status, 0) < 0) {
		setrlimit(RLIMIT_STACK, &old_limit);
		cleanup_setuid_exec_test();
		return 2;
	}

	setrlimit(RLIMIT_STACK, &old_limit);
	cleanup_setuid_exec_test();
	if (!WIFEXITED(status))
		return 2;
	return WEXITSTATUS(status) == 0 ? 0 : 1;
}

static int setuid_exec_cred_change_denied(void)
{
	int status;
	pid_t child;
	int ret;

	ret = setup_setuid_exec_test();
	if (ret)
		return 2;

	child = fork();
	if (child < 0) {
		cleanup_setuid_exec_test();
		return 2;
	}

	if (!child) {
		if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
			_exit(2);
		execl(HDN_SETUID_EXEC, "hdn-setuid-exec",
		      "--exec-sentinel", NULL);
		_exit(errno_is_denial(errno) ? 0 : 1);
	}

	if (waitpid(child, &status, 0) < 0) {
		cleanup_setuid_exec_test();
		return 2;
	}

	cleanup_setuid_exec_test();
	if (!WIFEXITED(status))
		return 2;
	return WEXITSTATUS(status) == 0 ? 0 : 1;
}

static int filecap_exec_cred_change_denied(void)
{
	int status;
	pid_t child;
	int ret;

	ret = setup_filecap_exec_test();
	if (ret)
		return 2;

	child = fork();
	if (child < 0) {
		cleanup_filecap_exec_test();
		return 2;
	}

	if (!child) {
		if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
			_exit(2);
		execl(HDN_FILECAP_EXEC, "hdn-filecap-exec",
		      "--exec-sentinel", NULL);
		_exit(errno_is_denial(errno) ? 0 : 1);
	}

	if (waitpid(child, &status, 0) < 0) {
		cleanup_filecap_exec_test();
		return 2;
	}

	cleanup_filecap_exec_test();
	if (!WIFEXITED(status))
		return 2;
	return WEXITSTATUS(status) == 0 ? 0 : 1;
}

static int run_crashing_setuid_exec(void)
{
	int status;
	pid_t child;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
			_exit(2);
		execl(HDN_SETUID_EXEC, "hdn-setuid-exec",
		      "--crash-sentinel", NULL);
		_exit(2);
	}

	if (waitpid(child, &status, 0) < 0)
		return 2;

	return WIFSIGNALED(status) ? 0 : 1;
}

static int setuid_exec_throttled_after_crashes(void)
{
	int status;
	pid_t child;
	int ret;
	int i;

	ret = setup_setuid_exec_test();
	if (ret)
		return 2;

	for (i = 0; i < HDN_BRUTE_TEST_CRASHES; i++) {
		ret = run_crashing_setuid_exec();
		if (ret)
			goto out_cleanup;
	}

	child = fork();
	if (child < 0) {
		ret = 2;
		goto out_cleanup;
	}

	if (!child) {
		if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
			_exit(2);
		execl(HDN_SETUID_EXEC, "hdn-setuid-exec",
		      "--setuid-sentinel", NULL);
		_exit(errno == EAGAIN || errno_is_denial(errno) ? 0 : 1);
	}

	if (waitpid(child, &status, 0) < 0) {
		ret = 2;
		goto out_cleanup;
	}

	if (!WIFEXITED(status))
		ret = 2;
	else
		ret = WEXITSTATUS(status) == 0 ? 0 : 1;

out_cleanup:
	cleanup_setuid_exec_test();
	return ret;
}

static int monotonic_ms(unsigned long long *value)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return -1;

	*value = (unsigned long long)ts.tv_sec * 1000ULL +
		 (unsigned long long)ts.tv_nsec / 1000000ULL;
	return 0;
}

static int daemon_brute_fork_delayed_child(void)
{
	unsigned long long before_ms;
	unsigned long long after_ms;
	int status;
	pid_t child;

	child = fork();
	if (child < 0)
		return 2;
	if (!child) {
		raise(SIGSEGV);
		_exit(2);
	}
	if (waitpid(child, &status, 0) < 0)
		return 2;
	if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGSEGV)
		return 1;

	if (monotonic_ms(&before_ms))
		return 2;
	child = fork();
	if (child < 0)
		return 2;
	if (!child)
		_exit(0);
	if (monotonic_ms(&after_ms))
		return 2;
	if (waitpid(child, &status, 0) < 0)
		return 2;
	if (!WIFEXITED(status) || WEXITSTATUS(status))
		return 2;

	return after_ms - before_ms >= HDN_BRUTE_DAEMON_DELAY_MIN_MS ? 0 : 1;
}

static int daemon_brute_fork_delayed(void)
{
	const char *event_needle =
		"authority=0 transition=40 action=3 reason=54";
	unsigned int before_events;
	unsigned int after_events;
	pid_t child;
	int ret;

	before_events = securityfs_events_line_count(event_needle, "error=0");

	child = fork();
	if (child < 0)
		return 2;
	if (!child) {
		if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
			_exit(2);
		execl("/hdn_smoke", "hdn_smoke", "--daemon-brute-sentinel",
		      NULL);
		_exit(2);
	}

	ret = child_exit_result(child);
	if (ret)
		return ret;

	after_events = securityfs_events_line_count(event_needle, "error=0");
	return after_events > before_events ? 0 : 1;
}

static int privileged_descendant_coredump_trigger(void)
{
	struct rlimit limit = {
		.rlim_cur = 8 * 1024 * 1024,
		.rlim_max = 8 * 1024 * 1024,
	};

	if (getuid() != HDN_TEST_NOBODY || geteuid() != HDN_TEST_NOBODY)
		return 2;
	if (setrlimit(RLIMIT_CORE, &limit))
		return 2;
	if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0))
		return 2;

	signal(SIGXFSZ, SIG_DFL);
	raise(SIGXFSZ);
	return 2;
}

static int privileged_descendant_coredump_dropper(void)
{
	struct rlimit limit = {
		.rlim_cur = 8 * 1024 * 1024,
		.rlim_max = 8 * 1024 * 1024,
	};

	if (geteuid() != 0)
		return 2;
	if (setrlimit(RLIMIT_CORE, &limit))
		return 2;
	if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
		return 2;

	execl(HDN_PRIVDESC_EXEC, "hdn-privdesc-exec",
	      "--privdesc-coredump-trigger", NULL);
	return 2;
}

static void cleanup_privileged_descendant_coredump_test(void)
{
	struct dirent *de;
	DIR *dir;

	dir = opendir(HDN_PRIVDESC_CORE_DIR);
	if (dir) {
		int dfd = dirfd(dir);

		while ((de = readdir(dir))) {
			if (!strcmp(de->d_name, ".") ||
			    !strcmp(de->d_name, ".."))
				continue;
			unlinkat(dfd, de->d_name, 0);
		}
		closedir(dir);
	}

	rmdir(HDN_PRIVDESC_CORE_DIR);
	unlink(HDN_PRIVDESC_CORE_DIR);
	unlink(HDN_PRIVDESC_EXEC);
	cleanup_setuid_exec_test();
}

static int setup_privileged_descendant_coredump_test(void)
{
	int ret;

	cleanup_privileged_descendant_coredump_test();

	if (mkdir(HDN_PRIVDESC_CORE_DIR, 0777)) {
		ret = -errno;
		goto out_cleanup;
	}
	if (chmod(HDN_PRIVDESC_CORE_DIR, 0777)) {
		ret = -errno;
		goto out_cleanup;
	}

	ret = copy_file("/hdn_smoke", HDN_PRIVDESC_EXEC, 0755);
	if (ret)
		goto out_cleanup;
	ret = setup_setuid_exec_test();
	if (ret)
		goto out_cleanup;

	return 0;

out_cleanup:
	cleanup_privileged_descendant_coredump_test();
	return ret;
}

static int privileged_descendant_coredump_blocked(void)
{
	const char *event_needle = "authority=0 transition=87 action=4";
	const char *reason_needle = "reason=53 error=-1";
	char old_core_pattern[256];
	char old_suid_dumpable[32];
	unsigned int before;
	unsigned int entries;
	bool core_pattern_set = false;
	bool suid_dumpable_set = false;
	int status;
	int ret;
	pid_t child;

	if (geteuid() != 0)
		return KSFT_SKIP;

	ret = read_text_file_small(HDN_CORE_PATTERN, old_core_pattern,
				   sizeof(old_core_pattern));
	if (ret)
		return 2;
	ret = read_text_file_small(HDN_SUID_DUMPABLE, old_suid_dumpable,
				   sizeof(old_suid_dumpable));
	if (ret)
		return 2;

	ret = setup_privileged_descendant_coredump_test();
	if (ret)
		return 2;

	ret = directory_entry_count(HDN_PRIVDESC_CORE_DIR, &entries);
	if (ret || entries) {
		ret = 2;
		goto out_cleanup;
	}

	ret = write_text_file(HDN_CORE_PATTERN, HDN_PRIVDESC_CORE_FILE "\n");
	if (ret)
		goto out_cleanup;
	core_pattern_set = true;

	ret = write_text_file(HDN_SUID_DUMPABLE, "0\n");
	if (ret)
		goto out_restore;
	suid_dumpable_set = true;

	before = securityfs_events_line_count(event_needle, reason_needle);

	child = fork();
	if (child < 0) {
		ret = 2;
		goto out_restore;
	}

	if (!child) {
		if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
			_exit(2);
		execl(HDN_SETUID_EXEC, "hdn-setuid-exec",
		      "--privdesc-coredump-dropper", NULL);
		_exit(2);
	}

	if (waitpid(child, &status, 0) < 0) {
		ret = 2;
		goto out_restore;
	}

	ret = directory_entry_count(HDN_PRIVDESC_CORE_DIR, &entries);
	if (ret)
		goto out_restore;

	ret = WIFSIGNALED(status) && WTERMSIG(status) == SIGXFSZ &&
	      !entries &&
	      securityfs_events_line_count(event_needle, reason_needle) >
	      before ? 0 : 1;

out_restore:
	if (suid_dumpable_set &&
	    write_text_file(HDN_SUID_DUMPABLE, old_suid_dumpable))
		ret = 2;
	if (core_pattern_set &&
	    write_text_file(HDN_CORE_PATTERN, old_core_pattern))
		ret = 2;
out_cleanup:
	cleanup_privileged_descendant_coredump_test();
	return ret;
}

static void cleanup_tpe_mount_test(void)
{
	unlink(HDN_TPE_MOUNT_EXEC);
	umount(HDN_TPE_MOUNT_DIR);
	rmdir(HDN_TPE_MOUNT_DIR);
	rmdir(HDN_TPE_PARENT_DIR);
}

static int setup_tpe_mount_test(void)
{
	int ret;

	cleanup_tpe_mount_test();
	if (mkdir(HDN_TPE_PARENT_DIR, 0777) && errno != EEXIST)
		return -errno;
	if (chmod(HDN_TPE_PARENT_DIR, 0777))
		return -errno;
	if (mkdir(HDN_TPE_MOUNT_DIR, 0777) && errno != EEXIST)
		return -errno;
	if (chmod(HDN_TPE_MOUNT_DIR, 0755))
		return -errno;

	if (mount("none", HDN_TPE_MOUNT_DIR, "tmpfs", 0,
		  "size=4m,mode=755"))
		return -errno;

	ret = copy_file("/hdn_smoke", HDN_TPE_MOUNT_EXEC, 0755);
	if (ret)
		cleanup_tpe_mount_test();
	return ret;
}

static int untrusted_mountpoint_exec_denied(void)
{
	int status;
	pid_t child;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		execl(HDN_TPE_MOUNT_EXEC, "hdn-tpe-mount-exec",
		      "--exec-sentinel", NULL);
		_exit(errno_is_denial(errno) ? 0 : 2);
	}

	if (waitpid(child, &status, 0) < 0)
		return 2;
	if (!WIFEXITED(status))
		return 2;
	return WEXITSTATUS(status) == 0 ? 0 : 1;
}

static void cleanup_tpe_user_test(void)
{
	unlink(HDN_TPE_USER_EXEC);
	rmdir(HDN_TPE_USER_DIR);
}

static int setup_tpe_user_test(void)
{
	int ret;

	cleanup_tpe_user_test();
	if (mkdir(HDN_TPE_USER_DIR, 0755) && errno != EEXIST)
		return -errno;
	if (chown(HDN_TPE_USER_DIR, HDN_TEST_NOBODY, HDN_TEST_NOBODY))
		return -errno;
	if (chmod(HDN_TPE_USER_DIR, 0755))
		return -errno;

	ret = copy_file("/hdn_smoke", HDN_TPE_USER_EXEC, 0755);
	if (ret)
		cleanup_tpe_user_test();
	return ret;
}

static int untrusted_user_exec_denied(void)
{
	int status;
	pid_t child;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
			_exit(2);
		execl(HDN_TPE_USER_EXEC, "hdn-tpe-user-exec",
		      "--exec-sentinel", NULL);
		_exit(errno_is_denial(errno) ? 0 : 2);
	}

	if (waitpid(child, &status, 0) < 0)
		return 2;
	if (!WIFEXITED(status))
		return 2;
	return WEXITSTATUS(status) == 0 ? 0 : 1;
}

static int untrusted_user_exec_mmap_denied(void)
{
	size_t page_size = sysconf(_SC_PAGESIZE);
	int status;
	pid_t child;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		int saved_errno = 0;
		void *addr;
		int fd;

		if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
			_exit(2);
		fd = open(HDN_TPE_USER_EXEC, O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			_exit(2);

		errno = 0;
		addr = mmap(NULL, page_size, PROT_READ | PROT_EXEC,
			    MAP_PRIVATE, fd, 0);
		saved_errno = errno;
		close(fd);
		if (addr != MAP_FAILED) {
			munmap(addr, page_size);
			_exit(1);
		}
		_exit(errno_is_denial(saved_errno) ? 0 : 2);
	}

	if (waitpid(child, &status, 0) < 0)
		return 2;
	if (!WIFEXITED(status))
		return 2;
	return WEXITSTATUS(status) == 0 ? 0 : 1;
}

static int untrusted_user_exec_mprotect_denied(void)
{
	size_t page_size = sysconf(_SC_PAGESIZE);
	int status;
	pid_t child;

	child = fork();
	if (child < 0)
		return 2;

	if (!child) {
		int saved_errno = 0;
		void *addr;
		int ret;
		int fd;

		if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
			_exit(2);
		fd = open(HDN_TPE_USER_EXEC, O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			_exit(2);

		addr = mmap(NULL, page_size, PROT_READ, MAP_PRIVATE, fd, 0);
		close(fd);
		if (addr == MAP_FAILED)
			_exit(2);

		errno = 0;
		ret = mprotect(addr, page_size, PROT_READ | PROT_EXEC);
		saved_errno = errno;
		munmap(addr, page_size);
		if (!ret)
			_exit(1);
		_exit(errno_is_denial(saved_errno) ? 0 : 2);
	}

	if (waitpid(child, &status, 0) < 0)
		return 2;
	if (!WIFEXITED(status))
		return 2;
	return WEXITSTATUS(status) == 0 ? 0 : 1;
}

static int setup_chroot_test_dirs(void)
{
	if (mkdir(HDN_CHROOT_TEST_DIR, 0755) && errno != EEXIST)
		return -errno;
	if (mkdir(HDN_CHROOT_INNER_DIR, 0755) && errno != EEXIST)
		return -errno;
	return 0;
}

static void cleanup_chroot_test_dirs(void)
{
	unlink(HDN_CHROOT_DEVICE_NODE);
	unlink(HDN_CHROOT_CHMOD_FILE);
	unlink(HDN_CHROOT_EXEC);
	rmdir(HDN_CHROOT_RENAME_TARGET);
	rmdir(HDN_CHROOT_INNER_DIR);
	rmdir(HDN_CHROOT_TEST_DIR);
}

static int chroot_exec_audit_flagged(void)
{
	int status;
	pid_t child;
	int ret;

	ret = setup_chroot_test_dirs();
	if (ret)
		return 2;

	ret = copy_file("/hdn_smoke", HDN_CHROOT_EXEC, 0755);
	if (ret)
		return 2;

	if (chroot(HDN_CHROOT_TEST_DIR))
		return 2;

	child = fork();
	if (child < 0)
		return 2;
	if (!child) {
		execl("/hdn_smoke", "hdn_smoke", "--exec-sentinel", NULL);
		_exit(127);
	}

	if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status))
		return 2;
	return WEXITSTATUS(status) == 42 ? 0 : 1;
}

static int chroot_fchdir_escape_denied(void)
{
	int rootfd;
	int ret;

	if (setup_chroot_test_dirs())
		return 2;

	rootfd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (rootfd < 0)
		return 2;

	if (chroot(HDN_CHROOT_TEST_DIR)) {
		close(rootfd);
		return 2;
	}

	errno = 0;
	ret = fchdir(rootfd);
	close(rootfd);
	if (!ret)
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int chroot_reentry_denied(void)
{
	if (setup_chroot_test_dirs())
		return 2;
	if (chroot(HDN_CHROOT_TEST_DIR))
		return 2;

	errno = 0;
	if (!chroot("/"))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int chroot_chmod_denied(void)
{
	int fd;

	if (setup_chroot_test_dirs())
		return 2;
	fd = open(HDN_CHROOT_CHMOD_FILE, O_CREAT | O_TRUNC | O_WRONLY |
		  O_CLOEXEC, 0644);
	if (fd < 0)
		return 2;
	close(fd);
	if (chroot(HDN_CHROOT_TEST_DIR))
		return 2;

	errno = 0;
	if (!chmod("/inner/chmod-target", 0600))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int chroot_mknod_denied(void)
{
	if (setup_chroot_test_dirs())
		return 2;
	if (chroot(HDN_CHROOT_TEST_DIR))
		return 2;

	errno = 0;
	if (!mknod("/inner/hdn-null", S_IFCHR | 0600, makedev(1, 3)))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int chroot_mount_denied(void)
{
	int saved_errno;
	int ret;

	if (setup_chroot_test_dirs())
		return 2;
	if (chroot(HDN_CHROOT_TEST_DIR))
		return 2;
	if (chdir("/"))
		return 2;

	errno = 0;
	ret = mount("none", "/inner", "tmpfs", 0, "size=4k");
	saved_errno = errno;
	if (!ret) {
		umount("/inner");
		return 1;
	}

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int chroot_file_handle_denied(void)
{
#ifdef __NR_open_by_handle_at
	struct {
		struct file_handle handle;
		unsigned char bytes[8];
	} fh = {};
	int saved_errno;
	int fd;

	if (setup_chroot_test_dirs())
		return 2;
	if (chroot(HDN_CHROOT_TEST_DIR))
		return 2;
	if (chdir("/"))
		return 2;

	fh.handle.handle_bytes = sizeof(fh.bytes);
	fh.handle.handle_type = 1;

	errno = 0;
	fd = syscall(__NR_open_by_handle_at, AT_FDCWD, &fh.handle, O_RDONLY);
	saved_errno = errno;
	if (fd >= 0) {
		close(fd);
		return 1;
	}

	return errno_is_denial(saved_errno) ? 0 : 2;
#else
	return KSFT_SKIP;
#endif
}

static int chroot_sysctl_denied(void)
{
	char old_pattern[256];
	ssize_t old_len;
	ssize_t written;
	int saved_errno;
	int fd;

	if (setup_chroot_test_dirs())
		return 2;

	fd = open(HDN_CORE_PATTERN, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 2;
	old_len = read(fd, old_pattern, sizeof(old_pattern));
	close(fd);
	if (old_len <= 0 || old_len == sizeof(old_pattern))
		return 2;

	fd = open(HDN_CORE_PATTERN, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return 2;
	if (chroot(HDN_CHROOT_TEST_DIR) || chdir("/")) {
		close(fd);
		return 2;
	}

	errno = 0;
	written = write(fd, old_pattern, old_len);
	saved_errno = errno;
	close(fd);
	if (written >= 0)
		return 1;

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int chroot_shmat_denied(void)
{
	int saved_errno;
	int shmid;
	void *addr;

	if (setup_chroot_test_dirs())
		return 2;
	shmid = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
	if (shmid < 0)
		return 2;
	if (chroot(HDN_CHROOT_TEST_DIR)) {
		shmctl(shmid, IPC_RMID, NULL);
		return 2;
	}

	errno = 0;
	addr = shmat(shmid, NULL, 0);
	saved_errno = errno;
	if (addr != (void *)-1) {
		shmdt(addr);
		shmctl(shmid, IPC_RMID, NULL);
		return 1;
	}
	shmctl(shmid, IPC_RMID, NULL);

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int chroot_nice_denied(void)
{
	if (setup_chroot_test_dirs())
		return 2;
	if (chroot(HDN_CHROOT_TEST_DIR))
		return 2;

	errno = 0;
	if (!setpriority(PRIO_PROCESS, 0, -1))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int chroot_bad_rename_denied(void)
{
	int rootfd;
	int saved_errno;

	if (setup_chroot_test_dirs())
		return 2;

	rootfd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (rootfd < 0)
		return 2;
	if (chroot(HDN_CHROOT_TEST_DIR)) {
		close(rootfd);
		return 2;
	}

	errno = 0;
	if (!renameat(AT_FDCWD, "/inner", rootfd,
		      "hdn-chroot-rename-target")) {
		renameat(rootfd, "hdn-chroot-rename-target", AT_FDCWD,
			 "/inner");
		close(rootfd);
		return 1;
	}
	saved_errno = errno;
	close(rootfd);

	return saved_errno == EXDEV || errno_is_denial(saved_errno) ? 0 : 2;
}

static int chroot_abstract_unix_denied(void)
{
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
	};
	socklen_t addrlen;
	int client;
	int server;
	int saved_errno;

	if (setup_chroot_test_dirs())
		return 2;

	snprintf(addr.sun_path + 1, sizeof(addr.sun_path) - 1,
		 "hdn-chroot-unix-%ld", (long)getpid());
	addrlen = offsetof(struct sockaddr_un, sun_path) + 1 +
		  strlen(addr.sun_path + 1);

	server = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (server < 0)
		return 2;
	if (bind(server, (struct sockaddr *)&addr, addrlen)) {
		close(server);
		return 2;
	}
	if (listen(server, 1)) {
		close(server);
		return 2;
	}
	if (chroot(HDN_CHROOT_TEST_DIR)) {
		close(server);
		return 2;
	}

	client = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (client < 0) {
		close(server);
		return 2;
	}

	errno = 0;
	if (!connect(client, (struct sockaddr *)&addr, addrlen)) {
		close(client);
		close(server);
		return 1;
	}
	saved_errno = errno;
	close(client);
	close(server);

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int chroot_capability_denied(void)
{
	struct timespec ts;

	if (setup_chroot_test_dirs())
		return 2;
	if (clock_gettime(CLOCK_REALTIME, &ts))
		return 2;
	if (chroot(HDN_CHROOT_TEST_DIR))
		return 2;

	errno = 0;
	if (!clock_settime(CLOCK_REALTIME, &ts))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int time_change_without_authority_denied(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_REALTIME, &ts))
		return 2;

	errno = 0;
	if (!clock_settime(CLOCK_REALTIME, &ts))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int resource_limit_without_authority_denied(void)
{
	struct rlimit orig;
	struct rlimit lower;
	rlim_t lowered_max;

	if (getrlimit(RLIMIT_NOFILE, &orig))
		return 2;
	if (orig.rlim_max != RLIM_INFINITY && orig.rlim_max < 2)
		return KSFT_SKIP;

	lowered_max = orig.rlim_max == RLIM_INFINITY ? 64 : orig.rlim_max - 1;
	if (lowered_max > 64)
		lowered_max = 64;
	if (!lowered_max)
		return KSFT_SKIP;

	lower = orig;
	lower.rlim_max = lowered_max;
	if (lower.rlim_cur > lower.rlim_max)
		lower.rlim_cur = lower.rlim_max;
	if (setrlimit(RLIMIT_NOFILE, &lower))
		return 2;

	errno = 0;
	if (!setrlimit(RLIMIT_NOFILE, &orig))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int resource_profile_soft_cap_denied(void)
{
	struct rlimit orig;
	struct rlimit capped = {
		.rlim_cur = HDN_RESOURCE_NOFILE_SOFT_CAP,
		.rlim_max = HDN_RESOURCE_NOFILE_HARD_CAP,
	};
	struct rlimit raised = capped;

	if (getrlimit(RLIMIT_NOFILE, &orig))
		return 2;
	if (orig.rlim_max != RLIM_INFINITY &&
	    orig.rlim_max < HDN_RESOURCE_NOFILE_HARD_CAP)
		return KSFT_SKIP;

	if (setrlimit(RLIMIT_NOFILE, &capped))
		return 2;

	raised.rlim_cur = HDN_RESOURCE_NOFILE_SOFT_CAP + 1;
	errno = 0;
	if (!setrlimit(RLIMIT_NOFILE, &raised))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int resource_profile_hard_cap_denied(void)
{
	struct rlimit orig;
	struct rlimit capped = {
		.rlim_cur = HDN_RESOURCE_NOFILE_SOFT_CAP,
		.rlim_max = HDN_RESOURCE_NOFILE_HARD_CAP,
	};
	struct rlimit raised = capped;

	if (getrlimit(RLIMIT_NOFILE, &orig))
		return 2;
	if (orig.rlim_max != RLIM_INFINITY &&
	    orig.rlim_max < HDN_RESOURCE_NOFILE_HARD_CAP)
		return KSFT_SKIP;

	if (setrlimit(RLIMIT_NOFILE, &capped))
		return 2;

	raised.rlim_max = HDN_RESOURCE_NOFILE_HARD_CAP + 1;
	errno = 0;
	if (!setrlimit(RLIMIT_NOFILE, &raised))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static void cleanup_capability_policy_test(void)
{
	unlink(HDN_CAPABILITY_DENY_TARGET);
	unlink(HDN_CAPABILITY_AUDIT_TARGET);
}

static int setup_capability_policy_test(void)
{
	int fd;

	cleanup_capability_policy_test();
	fd = open(HDN_CAPABILITY_DENY_TARGET,
		  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd < 0)
		return 2;
	close(fd);

	fd = open(HDN_CAPABILITY_AUDIT_TARGET,
		  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd < 0) {
		cleanup_capability_policy_test();
		return 2;
	}
	close(fd);
	if (chown(HDN_CAPABILITY_AUDIT_TARGET, HDN_TEST_NOBODY,
		  HDN_TEST_NOBODY)) {
		cleanup_capability_policy_test();
		return 2;
	}

	return 0;
}

static int capability_profile_masks_reported(void)
{
	return text_file_contains_all(HDN_PROFILES,
				      "id=2 name=capability-restricted-root",
				      "capability_deny=0x1",
				      "capability_audit=0x8");
}

static int capability_profile_denies_chown(void)
{
	if (!effective_capability_raised(CAP_CHOWN))
		return KSFT_SKIP;

	errno = 0;
	if (!chown(HDN_CAPABILITY_DENY_TARGET, HDN_TEST_NOBODY,
		   HDN_TEST_NOBODY))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static int capability_profile_audits_fowner(void)
{
	const char *event = "authority=0 transition=103 action=3 reason=0";
	const char *object = "object=3";
	unsigned int before;

	if (!effective_capability_raised(CAP_FOWNER))
		return KSFT_SKIP;

	before = securityfs_events_line_count(event, object);
	if (chmod(HDN_CAPABILITY_AUDIT_TARGET, 0640))
		return 2;

	return securityfs_events_line_count(event, object) > before ? 0 : 1;
}

static int capability_profile_chown_restored(void)
{
	if (!effective_capability_raised(CAP_CHOWN))
		return KSFT_SKIP;

	return chown(HDN_CAPABILITY_DENY_TARGET, HDN_TEST_NOBODY,
		     HDN_TEST_NOBODY) ? 1 : 0;
}

static void cleanup_object_audit_policy_test(void)
{
	unlink(HDN_OBJECT_AUDIT_CREATE_TARGET);
	unlink(HDN_OBJECT_AUDIT_LINK_DEST);
	unlink(HDN_OBJECT_AUDIT_READ_TARGET);
	unlink(HDN_OBJECT_AUDIT_APPEND_TARGET);
	unlink(HDN_OBJECT_AUDIT_WRITE_TARGET);
	unlink(HDN_OBJECT_AUDIT_FIND_TARGET);
	unlink(HDN_OBJECT_AUDIT_DELETE_TARGET);
	unlink(HDN_OBJECT_AUDIT_LINK_TARGET);
	unlink(HDN_OBJECT_AUDIT_SETID_TARGET);
	unlink(HDN_OBJECT_AUDIT_DENY_TARGET);
	rmdir(HDN_OBJECT_AUDIT_CREATE_DIR);
}

static int setup_object_audit_policy_test(void)
{
	static const char * const paths[] = {
		HDN_OBJECT_AUDIT_READ_TARGET,
		HDN_OBJECT_AUDIT_APPEND_TARGET,
		HDN_OBJECT_AUDIT_WRITE_TARGET,
		HDN_OBJECT_AUDIT_FIND_TARGET,
		HDN_OBJECT_AUDIT_DELETE_TARGET,
		HDN_OBJECT_AUDIT_LINK_TARGET,
		HDN_OBJECT_AUDIT_SETID_TARGET,
		HDN_OBJECT_AUDIT_DENY_TARGET,
	};
	size_t i;

	cleanup_object_audit_policy_test();
	for (i = 0; i < ARRAY_SIZE(paths); i++) {
		if (write_created_text_file(paths[i], "fixture\n"))
			goto fail;
	}
	if (mkdir(HDN_OBJECT_AUDIT_CREATE_DIR, 0700))
		goto fail;

	return 0;

fail:
	cleanup_object_audit_policy_test();
	return 2;
}

static int object_audit_read_recorded(void)
{
	const char *event = "transition=49 action=3 reason=0 error=0";
	unsigned int before;
	char byte;
	int fd;

	before = securityfs_events_count(event);
	fd = open(HDN_OBJECT_AUDIT_READ_TARGET, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 2;
	if (read(fd, &byte, 1) != 1) {
		close(fd);
		return 2;
	}
	close(fd);

	return securityfs_events_count(event) > before ? 0 : 1;
}

static int object_audit_write_recorded(void)
{
	const char *event = "transition=48 action=3 reason=0 error=0";
	unsigned int before;
	int fd;

	before = securityfs_events_count(event);
	fd = open(HDN_OBJECT_AUDIT_WRITE_TARGET,
		  O_WRONLY | O_TRUNC | O_CLOEXEC);
	if (fd < 0)
		return 2;
	if (write(fd, "x", 1) != 1) {
		close(fd);
		return 2;
	}
	close(fd);

	return securityfs_events_count(event) > before ? 0 : 1;
}

static int object_audit_append_recorded(void)
{
	const char *event = "transition=53 action=3 reason=0 error=0";
	unsigned int before;
	int fd;

	before = securityfs_events_count(event);
	fd = open(HDN_OBJECT_AUDIT_APPEND_TARGET,
		  O_WRONLY | O_APPEND | O_CLOEXEC);
	if (fd < 0)
		return 2;
	if (write(fd, "x", 1) != 1) {
		close(fd);
		return 2;
	}
	close(fd);

	return securityfs_events_count(event) > before ? 0 : 1;
}

static int object_audit_exec_recorded(void)
{
	const char *event = "transition=52 action=3 reason=0 error=0";
	unsigned int before;
	pid_t child;
	int ret;

	before = securityfs_events_count(event);
	child = fork();
	if (child < 0)
		return 2;
	if (!child) {
		execl(HDN_ELFNOTE_JIT_EXEC, "hdn-elfnote-jit", NULL);
		_exit(2);
	}

	ret = child_exit_result(child);
	if (ret)
		return ret;
	return securityfs_events_count(event) > before ? 0 : 1;
}

static int object_audit_find_recorded(void)
{
	const char *event = "transition=59 action=3 reason=0 error=0";
	unsigned int before;
	int fd;

	before = securityfs_events_count(event);
	fd = open(HDN_OBJECT_AUDIT_FIND_TARGET, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 2;
	close(fd);

	return securityfs_events_count(event) > before ? 0 : 1;
}

static int object_audit_inherit_recorded(void)
{
	const char *event = "transition=104 action=3 reason=0 error=0";
	unsigned int before;
	pid_t child;
	int ret;

	before = securityfs_events_count(event);
	child = fork();
	if (child < 0)
		return 2;
	if (!child) {
		execl(HDN_ELFNOTE_JIT_EXEC, "hdn-elfnote-jit", NULL);
		_exit(2);
	}

	ret = child_exit_result(child);
	if (ret)
		return ret;
	return securityfs_events_count(event) > before ? 0 : 1;
}

static int object_audit_create_recorded(void)
{
	const char *event = "transition=51 action=3 reason=0 error=0";
	unsigned int before;
	int fd;

	unlink(HDN_OBJECT_AUDIT_CREATE_TARGET);
	before = securityfs_events_count(event);
	fd = open(HDN_OBJECT_AUDIT_CREATE_TARGET,
		  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd < 0)
		return 2;
	close(fd);

	return securityfs_events_count(event) > before ? 0 : 1;
}

static int object_audit_delete_recorded(void)
{
	const char *event = "transition=50 action=3 reason=0 error=0";
	unsigned int before;

	before = securityfs_events_count(event);
	if (unlink(HDN_OBJECT_AUDIT_DELETE_TARGET))
		return 2;

	return securityfs_events_count(event) > before ? 0 : 1;
}

static int object_audit_link_recorded(void)
{
	const char *event = "transition=54 action=3 reason=0 error=0";
	unsigned int before;

	unlink(HDN_OBJECT_AUDIT_LINK_DEST);
	before = securityfs_events_count(event);
	if (link(HDN_OBJECT_AUDIT_LINK_TARGET, HDN_OBJECT_AUDIT_LINK_DEST))
		return 2;

	return securityfs_events_count(event) > before ? 0 : 1;
}

static int object_audit_setid_recorded(void)
{
	const char *event = "transition=100 action=3 reason=0 error=0";
	unsigned int before;

	before = securityfs_events_count(event);
	if (chmod(HDN_OBJECT_AUDIT_SETID_TARGET, 04755))
		return 2;

	return securityfs_events_count(event) > before ? 0 : 1;
}

static int object_audit_deny_precedes_audit(void)
{
	const char *allow_event = "action=3 reason=0 error=0";
	const char *deny_event = "action=4 reason=52";
	unsigned int allow_before;
	unsigned int deny_before;
	int saved_errno;
	int fd;

	allow_before = securityfs_events_count(allow_event);
	deny_before = securityfs_events_count(deny_event);
	errno = 0;
	fd = open(HDN_OBJECT_AUDIT_DENY_TARGET, O_RDONLY | O_CLOEXEC);
	saved_errno = errno;
	if (fd >= 0) {
		close(fd);
		return 1;
	}
	if (!errno_is_denial(saved_errno))
		return 2;

	return securityfs_events_count(allow_event) == allow_before &&
	       securityfs_events_count(deny_event) > deny_before ? 0 : 1;
}

static int object_audit_stops_after_rollback(void)
{
	const char *event = "transition=49 action=3 reason=0 error=0";
	unsigned int before;
	char byte;
	int fd;

	before = securityfs_events_count(event);
	fd = open(HDN_OBJECT_AUDIT_READ_TARGET, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 2;
	if (read(fd, &byte, 1) != 1) {
		close(fd);
		return 2;
	}
	close(fd);

	return securityfs_events_count(event) == before ? 0 : 1;
}

static int exec_inherit_audit_stops_after_rollback(void)
{
	const char *event = "transition=104 action=3 reason=0 error=0";
	unsigned int before;
	pid_t child;
	int ret;

	before = securityfs_events_count(event);
	child = fork();
	if (child < 0)
		return 2;
	if (!child) {
		execl(HDN_ELFNOTE_JIT_EXEC, "hdn-elfnote-jit", NULL);
		_exit(2);
	}

	ret = child_exit_result(child);
	if (ret)
		return ret;
	return securityfs_events_count(event) == before ? 0 : 1;
}

static pid_t spawn_chroot_outside_target(int *release_fd)
{
	int pipefd[2];
	pid_t child;

	if (pipe(pipefd))
		return -1;

	child = fork();
	if (child < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return -1;
	}

	if (!child) {
		char byte;

		close(pipefd[1]);
		while (read(pipefd[0], &byte, 1) > 0)
			;
		close(pipefd[0]);
		_exit(0);
	}

	close(pipefd[0]);
	*release_fd = pipefd[1];
	return child;
}

static int release_chroot_outside_target(pid_t child, int release_fd)
{
	int status;
	pid_t waited;

	if (release_fd >= 0)
		close(release_fd);

	do {
		waited = waitpid(child, &status, 0);
	} while (waited < 0 && errno == EINTR);

	if (waited != child)
		return 2;
	if (!WIFEXITED(status) || WEXITSTATUS(status))
		return 2;

	return 0;
}

static int chroot_findtask_proc_hidden(void)
{
	char proc_path[64];
	struct stat st;
	int release_fd = -1;
	int saved_errno;
	int rootfd;
	pid_t child;
	int ret;

	if (setup_chroot_test_dirs())
		return 2;

	rootfd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (rootfd < 0)
		return 2;

	child = spawn_chroot_outside_target(&release_fd);
	if (child < 0) {
		close(rootfd);
		return 2;
	}

	if (chroot(HDN_CHROOT_TEST_DIR)) {
		close(rootfd);
		release_chroot_outside_target(child, release_fd);
		return 2;
	}

	snprintf(proc_path, sizeof(proc_path), "proc/%ld", (long)child);
	errno = 0;
	ret = fstatat(rootfd, proc_path, &st, AT_SYMLINK_NOFOLLOW);
	saved_errno = errno;
	close(rootfd);
	if (release_chroot_outside_target(child, release_fd))
		return 2;
	if (!ret)
		return 1;

	return saved_errno == ENOENT || errno_is_denial(saved_errno) ? 0 : 2;
}

static int chroot_findtask_signal_denied(void)
{
	int release_fd = -1;
	int saved_errno;
	pid_t child;

	if (setup_chroot_test_dirs())
		return 2;

	child = spawn_chroot_outside_target(&release_fd);
	if (child < 0)
		return 2;

	if (chroot(HDN_CHROOT_TEST_DIR)) {
		release_chroot_outside_target(child, release_fd);
		return 2;
	}

	errno = 0;
	if (!kill(child, 0)) {
		release_chroot_outside_target(child, release_fd);
		return 1;
	}
	saved_errno = errno;
	if (release_chroot_outside_target(child, release_fd))
		return 2;

	return errno_is_denial(saved_errno) ? 0 : 2;
}

static int namespace_admin_denied(void)
{
	errno = 0;
	if (!unshare(CLONE_NEWNS))
		return 1;

	return errno_is_denial(errno) ? 0 : 2;
}

static int open_tree_namespace_denied(void)
{
#ifdef __NR_open_tree
	int fd;

	errno = 0;
	fd = syscall(__NR_open_tree, AT_FDCWD, "/",
		     OPEN_TREE_NAMESPACE | OPEN_TREE_CLOEXEC);
	if (fd >= 0) {
		close(fd);
		return 1;
	}

	return errno_is_denial(errno) ? 0 : 2;
#else
	return 2;
#endif
}

#ifdef __NR_finit_module
static int unsigned_finit_module_rejected(void)
{
	char image[16] = {};
	int saved_errno = 0;
	int fd;
	int ret;

	fd = syscall(__NR_memfd_create, "hdn-unknown-module", MFD_CLOEXEC);
	if (fd < 0)
		return 2;
	if (write(fd, image, sizeof(image)) != sizeof(image)) {
		close(fd);
		return 2;
	}
	lseek(fd, 0, SEEK_SET);

	errno = 0;
	ret = syscall(__NR_finit_module, fd, "", 0);
	if (ret)
		saved_errno = errno;
	close(fd);

	if (!ret)
		return 1;
	return saved_errno == EKEYREJECTED ? 0 : 2;
}

static int finit_module_errno(const char *path, int *module_errno)
{
	int saved_errno = 0;
	int fd;
	int ret;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 2;

	errno = 0;
	ret = syscall(__NR_finit_module, fd, "", 0);
	if (ret)
		saved_errno = errno;
	close(fd);

	if (!ret)
		return 1;

	*module_errno = saved_errno;
	return 0;
}

static int known_module_path_reaches_loader(void)
{
	int module_errno = 0;
	int ret;

	ret = finit_module_errno(HDN_KNOWN_MODULE, &module_errno);
	if (ret)
		return ret;

	return errno_is_denial(module_errno) ? 1 : 0;
}

static int signed_module_delegation_reaches_loader(void)
{
	int module_errno = 0;
	int ret;

	ret = finit_module_errno(HDN_SYMBOL_TEST_MODULE, &module_errno);
	if (ret == 1)
		return 0;
	if (ret)
		return ret;

	/* The disclosure tests load this module before policy activation. */
	return errno_is_denial(module_errno) ? 1 : 0;
}

static int write_known_module_file(const char *path)
{
	static const char image[] = "not the trusted module\n";
	int fd;
	int ret = 0;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0)
		return -errno;
	if (write(fd, image, sizeof(image)) != sizeof(image))
		ret = -errno;
	if (fchmod(fd, 0644) && !ret)
		ret = -errno;
	close(fd);

	return ret;
}

static int replaced_module_path_denied(void)
{
	int module_errno = 0;
	int ret = 0;

	unlink(HDN_KNOWN_MODULE_BACKUP);
	if (rename(HDN_KNOWN_MODULE, HDN_KNOWN_MODULE_BACKUP))
		return 2;

	ret = write_known_module_file(HDN_KNOWN_MODULE);
	if (!ret)
		ret = finit_module_errno(HDN_KNOWN_MODULE, &module_errno);

	unlink(HDN_KNOWN_MODULE);
	if (rename(HDN_KNOWN_MODULE_BACKUP, HDN_KNOWN_MODULE) && !ret)
		ret = 2;

	if (ret)
		return ret < 0 ? 2 : ret;

	return errno_is_denial(module_errno) ? 0 : 1;
}
#endif

static int firmware_request_errno(const char *name, int *request_errno)
{
	size_t size = strlen(name);
	int saved_errno = 0;
	ssize_t len;
	int fd;

	fd = open(HDN_TEST_FIRMWARE_TRIGGER, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT || errno == ENOTDIR)
			return KSFT_SKIP;
		return 2;
	}

	errno = 0;
	len = write(fd, name, size);
	if (len < 0)
		saved_errno = errno;
	close(fd);

	if (len == (ssize_t)size) {
		*request_errno = 0;
		return 0;
	}
	if (len >= 0)
		return 2;

	*request_errno = saved_errno;
	return 0;
}

static int trusted_firmware_name_loads(void)
{
	int request_errno = 0;
	int ret;

	ret = firmware_request_errno(HDN_ALLOWED_FIRMWARE, &request_errno);
	if (ret)
		return ret;
	if (request_errno)
		ksft_print_msg("trusted firmware request failed: %s\n",
			       strerror(request_errno));

	return request_errno ? 1 : 0;
}

static int untrusted_firmware_name_denied(void)
{
	int request_errno = 0;
	int ret;

	ret = firmware_request_errno(HDN_DENIED_FIRMWARE, &request_errno);
	if (ret)
		return ret;
	if (!errno_is_denial(request_errno))
		ksft_print_msg("untrusted firmware request returned: %s\n",
			       request_errno ? strerror(request_errno) :
					       "success");

	return errno_is_denial(request_errno) ? 0 : 1;
}

static int product_firmware_delegation_loads(void)
{
	int request_errno = 0;
	int ret;

	ret = firmware_request_errno(HDN_DENIED_FIRMWARE, &request_errno);
	if (ret)
		return ret;

	return request_errno ? 1 : 0;
}

static int socket_create_nonlocal_denied(void)
{
	int fd;

	errno = 0;
	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd >= 0) {
		close(fd);
		return 1;
	}

	return errno_is_denial(errno) ? 0 : 2;
}

static int socket_create_local_allowed(void)
{
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd >= 0) {
		close(fd);
		return 0;
	}

	return errno_is_denial(errno) ? 1 : 2;
}

static int proc_self_ipaddr_equals(const char *expected)
{
	char buf[64] = {};
	int fd;
	ssize_t len;

	fd = open(HDN_PROC_SELF_IPADDR, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		ksft_print_msg("%s open failed: %s\n", HDN_PROC_SELF_IPADDR,
			       strerror(errno));
		return errno == ENOENT ? KSFT_SKIP : 2;
	}

	len = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (len <= 0) {
		ksft_print_msg("%s read failed\n", HDN_PROC_SELF_IPADDR);
		return 2;
	}

	if (strcmp(buf, expected)) {
		ksft_print_msg("%s expected %s got %s", HDN_PROC_SELF_IPADDR,
			       expected, buf);
		return 1;
	}

	return 0;
}

static int loopback_up(void)
{
	struct ifreq ifr = {};
	int fd;
	int ret;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		ksft_print_msg("loopback control socket failed: %s\n",
			       strerror(errno));
		return 2;
	}

	strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
	ret = ioctl(fd, SIOCGIFFLAGS, &ifr);
	if (ret) {
		ksft_print_msg("loopback flag read failed: %s\n",
			       strerror(errno));
		close(fd);
		return 2;
	}
	if (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;
		ret = ioctl(fd, SIOCSIFFLAGS, &ifr);
		if (ret) {
			ksft_print_msg("loopback flag update failed: %s\n",
				       strerror(errno));
			close(fd);
			return 2;
		}
	}

	close(fd);
	return 0;
}

static int proc_ipaddr_accept_handoff(void)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	socklen_t addrlen = sizeof(addr);
	int server = -1;
	int client = -1;
	int accepted = -1;
	int status;
	pid_t child;
	int ret;

	ret = loopback_up();
	if (ret)
		return ret;

	server = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (server < 0) {
		ksft_print_msg("proc ipaddr server socket failed: %s\n",
			       strerror(errno));
		return 2;
	}
	if (bind(server, (struct sockaddr *)&addr, sizeof(addr))) {
		ksft_print_msg("proc ipaddr bind failed: %s\n",
			       strerror(errno));
		goto err;
	}
	if (listen(server, 1)) {
		ksft_print_msg("proc ipaddr listen failed: %s\n",
			       strerror(errno));
		goto err;
	}
	if (getsockname(server, (struct sockaddr *)&addr, &addrlen)) {
		ksft_print_msg("proc ipaddr getsockname failed: %s\n",
			       strerror(errno));
		goto err;
	}

	client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (client < 0) {
		ksft_print_msg("proc ipaddr client socket failed: %s\n",
			       strerror(errno));
		goto err;
	}
	if (connect(client, (struct sockaddr *)&addr, sizeof(addr))) {
		ksft_print_msg("proc ipaddr connect failed: %s\n",
			       strerror(errno));
		goto err;
	}

	accepted = accept4(server, NULL, NULL, SOCK_CLOEXEC);
	if (accepted < 0) {
		ksft_print_msg("proc ipaddr accept failed: %s\n",
			       strerror(errno));
		goto err;
	}

	ret = proc_self_ipaddr_equals("127.0.0.1\n");
	if (ret)
		goto out;

	child = fork();
	if (child < 0) {
		ret = 2;
		goto out;
	}
	if (!child)
		_exit(proc_self_ipaddr_equals("127.0.0.1\n"));

	if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status)) {
		ret = 2;
		goto out;
	}
	ret = WEXITSTATUS(status);
	if (ret)
		goto out;

	ret = proc_self_ipaddr_equals("0.0.0.0\n");
out:
	if (accepted >= 0)
		close(accepted);
	if (client >= 0)
		close(client);
	if (server >= 0)
		close(server);
	return ret;

err:
	ret = 2;
	goto out;
}

static int proc_ipaddr_local_tcp_carry(void)
{
	struct sockaddr_in frontend = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct sockaddr_in backend = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct sockaddr_in remote_bind = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(0x7f000002),
	};
	socklen_t frontend_len = sizeof(frontend);
	socklen_t backend_len = sizeof(backend);
	int frontend_server = -1;
	int frontend_client = -1;
	int frontend_accepted = -1;
	int backend_server = -1;
	int backend_client = -1;
	int backend_accepted = -1;
	int status;
	pid_t child;
	int ret;

	ret = loopback_up();
	if (ret)
		return ret;

	frontend_server = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (frontend_server < 0) {
		ksft_print_msg("proc ipaddr frontend socket failed: %s\n",
			       strerror(errno));
		return 2;
	}
	if (bind(frontend_server, (struct sockaddr *)&frontend,
		 sizeof(frontend))) {
		ksft_print_msg("proc ipaddr frontend bind failed: %s\n",
			       strerror(errno));
		goto err;
	}
	if (listen(frontend_server, 1)) {
		ksft_print_msg("proc ipaddr frontend listen failed: %s\n",
			       strerror(errno));
		goto err;
	}
	if (getsockname(frontend_server, (struct sockaddr *)&frontend,
			&frontend_len)) {
		ksft_print_msg("proc ipaddr frontend getsockname failed: %s\n",
			       strerror(errno));
		goto err;
	}

	frontend_client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (frontend_client < 0) {
		ksft_print_msg("proc ipaddr frontend client socket failed: %s\n",
			       strerror(errno));
		goto err;
	}
	if (bind(frontend_client, (struct sockaddr *)&remote_bind,
		 sizeof(remote_bind))) {
		ksft_print_msg("proc ipaddr remote bind failed: %s\n",
			       strerror(errno));
		goto err;
	}
	if (connect(frontend_client, (struct sockaddr *)&frontend,
		    sizeof(frontend))) {
		ksft_print_msg("proc ipaddr frontend connect failed: %s\n",
			       strerror(errno));
		goto err;
	}
	frontend_accepted = accept4(frontend_server, NULL, NULL, SOCK_CLOEXEC);
	if (frontend_accepted < 0) {
		ksft_print_msg("proc ipaddr frontend accept failed: %s\n",
			       strerror(errno));
		goto err;
	}

	ret = proc_self_ipaddr_equals("127.0.0.2\n");
	if (ret)
		goto out;

	backend_server = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (backend_server < 0) {
		ksft_print_msg("proc ipaddr backend socket failed: %s\n",
			       strerror(errno));
		goto err;
	}
	if (bind(backend_server, (struct sockaddr *)&backend,
		 sizeof(backend))) {
		ksft_print_msg("proc ipaddr backend bind failed: %s\n",
			       strerror(errno));
		goto err;
	}
	if (listen(backend_server, 1)) {
		ksft_print_msg("proc ipaddr backend listen failed: %s\n",
			       strerror(errno));
		goto err;
	}
	if (getsockname(backend_server, (struct sockaddr *)&backend,
			&backend_len)) {
		ksft_print_msg("proc ipaddr backend getsockname failed: %s\n",
			       strerror(errno));
		goto err;
	}

	backend_client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (backend_client < 0) {
		ksft_print_msg("proc ipaddr backend client socket failed: %s\n",
			       strerror(errno));
		goto err;
	}
	if (connect(backend_client, (struct sockaddr *)&backend,
		    sizeof(backend))) {
		ksft_print_msg("proc ipaddr backend connect failed: %s\n",
			       strerror(errno));
		goto err;
	}
	backend_accepted = accept4(backend_server, NULL, NULL, SOCK_CLOEXEC);
	if (backend_accepted < 0) {
		ksft_print_msg("proc ipaddr backend accept failed: %s\n",
			       strerror(errno));
		goto err;
	}

	ret = proc_self_ipaddr_equals("127.0.0.2\n");
	if (ret)
		goto out;

	child = fork();
	if (child < 0) {
		ret = 2;
		goto out;
	}
	if (!child)
		_exit(proc_self_ipaddr_equals("127.0.0.2\n"));

	if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status)) {
		ret = 2;
		goto out;
	}
	ret = WEXITSTATUS(status);
	if (ret)
		goto out;

	ret = proc_self_ipaddr_equals("0.0.0.0\n");
out:
	if (backend_accepted >= 0)
		close(backend_accepted);
	if (backend_client >= 0)
		close(backend_client);
	if (backend_server >= 0)
		close(backend_server);
	if (frontend_accepted >= 0)
		close(frontend_accepted);
	if (frontend_client >= 0)
		close(frontend_client);
	if (frontend_server >= 0)
		close(frontend_server);
	return ret;

err:
	ret = 2;
	goto out;
}

static int proc_ipaddr_seed_remote_alias(int *server, int *client,
					 int *accepted)
{
	struct sockaddr_in frontend = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct sockaddr_in remote_bind = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(0x7f000002),
	};
	socklen_t frontend_len = sizeof(frontend);
	int ret;

	ret = loopback_up();
	if (ret)
		return ret;

	*server = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (*server < 0) {
		ksft_print_msg("proc ipaddr seed server socket failed: %s\n",
			       strerror(errno));
		return 2;
	}
	if (bind(*server, (struct sockaddr *)&frontend, sizeof(frontend))) {
		ksft_print_msg("proc ipaddr seed bind failed: %s\n",
			       strerror(errno));
		goto err;
	}
	if (listen(*server, 1)) {
		ksft_print_msg("proc ipaddr seed listen failed: %s\n",
			       strerror(errno));
		goto err;
	}
	if (getsockname(*server, (struct sockaddr *)&frontend,
			&frontend_len)) {
		ksft_print_msg("proc ipaddr seed getsockname failed: %s\n",
			       strerror(errno));
		goto err;
	}

	*client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (*client < 0) {
		ksft_print_msg("proc ipaddr seed client socket failed: %s\n",
			       strerror(errno));
		goto err;
	}
	if (bind(*client, (struct sockaddr *)&remote_bind,
		 sizeof(remote_bind))) {
		ksft_print_msg("proc ipaddr seed remote bind failed: %s\n",
			       strerror(errno));
		goto err;
	}
	if (connect(*client, (struct sockaddr *)&frontend, sizeof(frontend))) {
		ksft_print_msg("proc ipaddr seed connect failed: %s\n",
			       strerror(errno));
		goto err;
	}

	*accepted = accept4(*server, NULL, NULL, SOCK_CLOEXEC);
	if (*accepted < 0) {
		ksft_print_msg("proc ipaddr seed accept failed: %s\n",
			       strerror(errno));
		goto err;
	}

	return proc_self_ipaddr_equals("127.0.0.2\n");

err:
	if (*accepted >= 0) {
		close(*accepted);
		*accepted = -1;
	}
	if (*client >= 0) {
		close(*client);
		*client = -1;
	}
	if (*server >= 0) {
		close(*server);
		*server = -1;
	}
	return 2;
}

static int proc_ipaddr_unix_stream_carry(void)
{
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
	};
	socklen_t addrlen;
	int frontend_server = -1;
	int frontend_client = -1;
	int frontend_accepted = -1;
	int unix_server = -1;
	int unix_client = -1;
	int unix_accepted = -1;
	int status;
	pid_t child;
	int ret;

	ret = proc_ipaddr_seed_remote_alias(&frontend_server, &frontend_client,
					    &frontend_accepted);
	if (ret)
		return ret;

	snprintf(addr.sun_path + 1, sizeof(addr.sun_path) - 1,
		 "hdn-proc-ip-unix-%ld", (long)getpid());
	addrlen = offsetof(struct sockaddr_un, sun_path) + 1 +
		  strlen(addr.sun_path + 1);

	unix_server = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (unix_server < 0) {
		ksft_print_msg("proc ipaddr unix server socket failed: %s\n",
			       strerror(errno));
		ret = 2;
		goto out;
	}
	if (bind(unix_server, (struct sockaddr *)&addr, addrlen)) {
		ksft_print_msg("proc ipaddr unix bind failed: %s\n",
			       strerror(errno));
		ret = 2;
		goto out;
	}
	if (listen(unix_server, 1)) {
		ksft_print_msg("proc ipaddr unix listen failed: %s\n",
			       strerror(errno));
		ret = 2;
		goto out;
	}

	unix_client = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (unix_client < 0) {
		ksft_print_msg("proc ipaddr unix client socket failed: %s\n",
			       strerror(errno));
		ret = 2;
		goto out;
	}
	if (connect(unix_client, (struct sockaddr *)&addr, addrlen)) {
		ksft_print_msg("proc ipaddr unix connect failed: %s\n",
			       strerror(errno));
		ret = 2;
		goto out;
	}

	unix_accepted = accept4(unix_server, NULL, NULL, SOCK_CLOEXEC);
	if (unix_accepted < 0) {
		ksft_print_msg("proc ipaddr unix accept failed: %s\n",
			       strerror(errno));
		ret = 2;
		goto out;
	}

	ret = proc_self_ipaddr_equals("127.0.0.2\n");
	if (ret)
		goto out;

	child = fork();
	if (child < 0) {
		ret = 2;
		goto out;
	}
	if (!child)
		_exit(proc_self_ipaddr_equals("127.0.0.2\n"));

	if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status)) {
		ret = 2;
		goto out;
	}
	ret = WEXITSTATUS(status);
	if (ret)
		goto out;

	ret = proc_self_ipaddr_equals("0.0.0.0\n");
out:
	if (unix_accepted >= 0)
		close(unix_accepted);
	if (unix_client >= 0)
		close(unix_client);
	if (unix_server >= 0)
		close(unix_server);
	if (frontend_accepted >= 0)
		close(frontend_accepted);
	if (frontend_client >= 0)
		close(frontend_client);
	if (frontend_server >= 0)
		close(frontend_server);
	return ret;
}

static unsigned long long hdn_ipv4_socket_event_object(int type,
						       unsigned int port,
						       unsigned int addr)
{
	return ((unsigned long long)AF_INET << 56) |
	       ((unsigned long long)(type & HDN_SOCKET_TYPE_MASK) << 48) |
	       ((unsigned long long)(port & 0xffff) << 32) | addr;
}

static unsigned long long hdn_bytes_event_hash(const void *data, size_t len)
{
	const unsigned char *bytes = data;
	unsigned long long hash = 14695981039346656037ULL;

	while (len--) {
		hash ^= *bytes++;
		hash *= 1099511628211ULL;
	}

	return hash;
}

static unsigned long long hdn_ipv6_socket_event_object(int type,
						       unsigned int port,
						       const struct in6_addr *addr)
{
	unsigned long long hash = hdn_bytes_event_hash(addr, sizeof(*addr));

	return ((unsigned long long)AF_INET6 << 56) |
	       ((unsigned long long)(type & HDN_SOCKET_TYPE_MASK) << 48) |
	       ((unsigned long long)(port & 0xffff) << 32) |
	       (hash & 0xffffffffULL);
}

static uint16_t hdn_ip_checksum(const void *data, size_t len)
{
	const uint16_t *words = data;
	uint32_t sum = 0;

	while (len > 1) {
		sum += *words++;
		len -= 2;
	}
	if (len)
		sum += *(const uint8_t *)words;

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return (uint16_t)~sum;
}

struct hdn_icmphdr {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint32_t rest;
};

static uint16_t hdn_tcp_checksum(const struct iphdr *iph,
				 const struct tcphdr *tcp, size_t tcp_len)
{
	struct {
		uint32_t saddr;
		uint32_t daddr;
		uint8_t zero;
		uint8_t protocol;
		uint16_t len;
	} pseudo = {
		.saddr = iph->saddr,
		.daddr = iph->daddr,
		.zero = 0,
		.protocol = IPPROTO_TCP,
		.len = htons(tcp_len),
	};
	uint8_t packet[sizeof(pseudo) + sizeof(*tcp)];

	memcpy(packet, &pseudo, sizeof(pseudo));
	memcpy(packet + sizeof(pseudo), tcp, sizeof(*tcp));

	return hdn_ip_checksum(packet, sizeof(packet));
}

static void hdn_build_ipv4_header(struct iphdr *iph, uint16_t total_len,
				  uint8_t protocol)
{
	memset(iph, 0, sizeof(*iph));
	iph->version = 4;
	iph->ihl = 5;
	iph->tot_len = htons(total_len);
	iph->id = htons(0x4844);
	iph->ttl = 64;
	iph->protocol = protocol;
	iph->saddr = htonl(HDN_BLACKHOLE_REMOTE_ADDR);
	iph->daddr = htonl(HDN_BLACKHOLE_LOCAL_ADDR);
	iph->check = hdn_ip_checksum(iph, sizeof(*iph));
}

static size_t hdn_build_blackhole_udp_packet(uint8_t *packet, uint16_t dport)
{
	static const char payload[] = "h";
	const size_t payload_len = sizeof(payload) - 1;
	const size_t total_len = sizeof(struct iphdr) +
				 sizeof(struct udphdr) + payload_len;
	struct iphdr *iph = (struct iphdr *)packet;
	struct udphdr *udp = (struct udphdr *)(packet + sizeof(*iph));

	hdn_build_ipv4_header(iph, total_len, IPPROTO_UDP);
	memset(udp, 0, sizeof(*udp));
	udp->source = htons(40100);
	udp->dest = htons(dport);
	udp->len = htons(sizeof(*udp) + payload_len);
	memcpy(packet + sizeof(*iph) + sizeof(*udp), payload, payload_len);

	return total_len;
}

static size_t hdn_build_blackhole_tcp_packet(uint8_t *packet, uint16_t dport)
{
	const size_t total_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
	struct iphdr *iph = (struct iphdr *)packet;
	struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(*iph));

	hdn_build_ipv4_header(iph, total_len, IPPROTO_TCP);
	memset(tcp, 0, sizeof(*tcp));
	tcp->source = htons(40101);
	tcp->dest = htons(dport);
	tcp->seq = htonl(1);
	tcp->doff = sizeof(*tcp) / 4;
	tcp->syn = 1;
	tcp->window = htons(4096);
	tcp->check = hdn_tcp_checksum(iph, tcp, sizeof(*tcp));

	return total_len;
}

static int hdn_tun_set_ipv4(const char *ifname)
{
	struct ifreq ifr = {};
	struct sockaddr_in *sin;
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
	sin = (struct sockaddr_in *)&ifr.ifr_addr;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(HDN_BLACKHOLE_LOCAL_ADDR);
	if (ioctl(fd, SIOCSIFADDR, &ifr)) {
		close(fd);
		return -errno;
	}

	memset(&ifr.ifr_addr, 0, sizeof(ifr.ifr_addr));
	sin = (struct sockaddr_in *)&ifr.ifr_netmask;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(0xffffff00U);
	if (ioctl(fd, SIOCSIFNETMASK, &ifr)) {
		close(fd);
		return -errno;
	}

	if (ioctl(fd, SIOCGIFFLAGS, &ifr)) {
		close(fd);
		return -errno;
	}
	ifr.ifr_flags |= IFF_UP;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr)) {
		close(fd);
		return -errno;
	}

	close(fd);
	return 0;
}

static int hdn_open_blackhole_tun(void)
{
	struct ifreq ifr = {};
	int fd;
	int ret;

	if (mkdir("/dev/net", 0755) && errno != EEXIST)
		return -errno;
	if (mknod(HDN_TUN_DEV, S_IFCHR | 0600, makedev(10, 200)) &&
	    errno != EEXIST)
		return -errno;

	fd = open(HDN_TUN_DEV, O_RDWR | O_CLOEXEC | O_NONBLOCK);
	if (fd < 0)
		return -errno;

	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", HDN_BLACKHOLE_TUN);
	if (ioctl(fd, TUNSETIFF, &ifr)) {
		ret = -errno;
		close(fd);
		return ret;
	}

	ret = hdn_tun_set_ipv4(ifr.ifr_name);
	if (ret) {
		close(fd);
		return ret;
	}

	return fd;
}

static bool hdn_packet_is_blackhole_tcp_reset(const uint8_t *packet,
					      size_t len, uint16_t port)
{
	const struct iphdr *iph = (const struct iphdr *)packet;
	const struct tcphdr *tcp;
	size_t ihl;

	if (len < sizeof(*iph) || iph->version != 4 || iph->protocol != IPPROTO_TCP)
		return false;
	ihl = iph->ihl * 4;
	if (ihl < sizeof(*iph) || len < ihl + sizeof(*tcp))
		return false;
	if (iph->saddr != htonl(HDN_BLACKHOLE_LOCAL_ADDR) ||
	    iph->daddr != htonl(HDN_BLACKHOLE_REMOTE_ADDR))
		return false;

	tcp = (const struct tcphdr *)(packet + ihl);
	return tcp->rst && ntohs(tcp->source) == port &&
	       ntohs(tcp->dest) == 40101;
}

static bool hdn_packet_is_blackhole_udp_error(const uint8_t *packet,
					      size_t len)
{
	const struct iphdr *iph = (const struct iphdr *)packet;
	const struct hdn_icmphdr *icmp;
	size_t ihl;

	if (len < sizeof(*iph) || iph->version != 4 ||
	    iph->protocol != IPPROTO_ICMP)
		return false;
	ihl = iph->ihl * 4;
	if (ihl < sizeof(*iph) || len < ihl + sizeof(*icmp))
		return false;
	if (iph->saddr != htonl(HDN_BLACKHOLE_LOCAL_ADDR) ||
	    iph->daddr != htonl(HDN_BLACKHOLE_REMOTE_ADDR))
		return false;

	icmp = (const struct hdn_icmphdr *)(packet + ihl);
	return icmp->type == ICMP_DEST_UNREACH &&
	       icmp->code == ICMP_PORT_UNREACH;
}

static bool hdn_tun_observed_blackhole_response(int fd, uint8_t protocol,
						uint16_t port)
{
	uint8_t packet[256];
	struct pollfd pfd = {
		.fd = fd,
		.events = POLLIN,
	};
	int i;

	for (i = 0; i < 10; i++) {
		ssize_t len;
		int ret;

		pfd.revents = 0;
		ret = poll(&pfd, 1, 100);
		if (ret <= 0)
			continue;

		len = read(fd, packet, sizeof(packet));
		if (len <= 0)
			continue;
		if (protocol == IPPROTO_TCP &&
		    hdn_packet_is_blackhole_tcp_reset(packet, len, port))
			return true;
		if (protocol == IPPROTO_UDP &&
		    hdn_packet_is_blackhole_udp_error(packet, len))
			return true;
	}

	return false;
}

static void test_blackhole_remote_tcp_suppressed(void)
{
	const uint16_t port = 65003;
	uint8_t packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
	bool observed;
	size_t len;
	int fd;

	fd = hdn_open_blackhole_tun();
	if (fd < 0) {
		ksft_test_result_skip("non-loopback TCP blackhole unavailable: %s\n",
				      strerror(-fd));
		return;
	}

	len = hdn_build_blackhole_tcp_packet(packet, port);
	if (write(fd, packet, len) != (ssize_t)len) {
		ksft_test_result_fail("non-loopback TCP packet inject failed: %s\n",
				      strerror(errno));
		close(fd);
		return;
	}

	observed = hdn_tun_observed_blackhole_response(fd, IPPROTO_TCP, port);
	ksft_test_result(!observed,
			 "network blackhole suppresses remote TCP resets\n");
	close(fd);
}

static void test_blackhole_remote_udp_suppressed(void)
{
	const uint16_t port = 65004;
	uint8_t packet[sizeof(struct iphdr) + sizeof(struct udphdr) + 1];
	bool observed;
	size_t len;
	int fd;

	fd = hdn_open_blackhole_tun();
	if (fd < 0) {
		ksft_test_result_skip("non-loopback UDP blackhole unavailable: %s\n",
				      strerror(-fd));
		return;
	}

	len = hdn_build_blackhole_udp_packet(packet, port);
	if (write(fd, packet, len) != (ssize_t)len) {
		ksft_test_result_fail("non-loopback UDP packet inject failed: %s\n",
				      strerror(errno));
		close(fd);
		return;
	}

	observed = hdn_tun_observed_blackhole_response(fd, IPPROTO_UDP, port);
	ksft_test_result(!observed,
			 "network blackhole suppresses remote UDP ICMP errors\n");
	close(fd);
}

static void test_blackhole_loopback_tcp_exempt(void)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(65001),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct pollfd pfd;
	int error = 0;
	socklen_t len = sizeof(error);
	int flags;
	int ret;
	int fd;

	ret = loopback_up();
	if (ret) {
		ksft_test_result(ret == KSFT_SKIP,
				 "network blackhole preserves loopback TCP resets\n");
		return;
	}

	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		ksft_test_result_fail("loopback TCP socket failed: %s\n",
				      strerror(errno));
		return;
	}

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		ksft_test_result_fail("loopback TCP nonblock failed: %s\n",
				      strerror(errno));
		close(fd);
		return;
	}

	errno = 0;
	ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0 && errno == ECONNREFUSED) {
		close(fd);
		ksft_test_result_pass(
			"network blackhole preserves loopback TCP resets\n");
		return;
	}
	if (ret < 0 && errno != EINPROGRESS) {
		ksft_test_result_fail("loopback TCP connect failed: %s\n",
				      strerror(errno));
		close(fd);
		return;
	}

	pfd.fd = fd;
	pfd.events = POLLOUT | POLLERR;
	pfd.revents = 0;
	ret = poll(&pfd, 1, 1000);
	if (ret > 0)
		getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
	close(fd);

	ksft_test_result(ret > 0 && error == ECONNREFUSED,
			 "network blackhole preserves loopback TCP resets\n");
}

static void test_blackhole_loopback_udp_exempt(void)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(65002),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct pollfd pfd;
	char byte = 'x';
	int error = 0;
	socklen_t len = sizeof(error);
	int ret;
	int fd;

	ret = loopback_up();
	if (ret) {
		ksft_test_result(ret == KSFT_SKIP,
				 "network blackhole preserves loopback UDP ICMP errors\n");
		return;
	}

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		ksft_test_result_fail("loopback UDP socket failed: %s\n",
				      strerror(errno));
		return;
	}
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr))) {
		ksft_test_result_fail("loopback UDP connect failed: %s\n",
				      strerror(errno));
		close(fd);
		return;
	}
	if (send(fd, &byte, sizeof(byte), 0) != sizeof(byte)) {
		ksft_test_result_fail("loopback UDP send failed: %s\n",
				      strerror(errno));
		close(fd);
		return;
	}

	pfd.fd = fd;
	pfd.events = POLLIN | POLLERR;
	pfd.revents = 0;
	ret = poll(&pfd, 1, 1000);
	if (ret > 0)
		getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
	close(fd);

	ksft_test_result(ret > 0 && error == ECONNREFUSED,
			 "network blackhole preserves loopback UDP ICMP errors\n");
}

static int socket_connect_without_authority_denied(void)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(9),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	int saved_errno;
	int fd;
	int ret;

	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return 2;

	errno = 0;
	ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	saved_errno = errno;
	close(fd);

	if (!ret)
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 1;
}

static int socket_connect6_without_authority_denied(void)
{
	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(9),
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
	};
	int saved_errno;
	int fd;
	int ret;

	fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return 2;

	errno = 0;
	ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	saved_errno = errno;
	close(fd);

	if (!ret)
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 1;
}

static int socket_udp_connect_without_authority_denied(void)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(9),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	int saved_errno;
	int fd;
	int ret;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return 2;

	errno = 0;
	ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	saved_errno = errno;
	close(fd);

	if (!ret)
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 1;
}

static int socket_udp_connect6_without_authority_denied(void)
{
	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(9),
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
	};
	int saved_errno;
	int fd;
	int ret;

	fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return 2;

	errno = 0;
	ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	saved_errno = errno;
	close(fd);

	if (!ret)
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 1;
}

static int socket_server_without_authority_denied(void)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = 0,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	int saved_errno;
	int fd;
	int ret;

	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return 2;

	errno = 0;
	ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	saved_errno = errno;
	close(fd);

	if (!ret)
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 1;
}

static int socket_server6_without_authority_denied(void)
{
	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_port = 0,
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
	};
	int saved_errno;
	int fd;
	int ret;

	fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return 2;

	errno = 0;
	ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	saved_errno = errno;
	close(fd);

	if (!ret)
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 1;
}

static int socket_udp_server_without_authority_denied(void)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = 0,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	int saved_errno;
	int fd;
	int ret;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return 2;

	errno = 0;
	ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	saved_errno = errno;
	close(fd);

	if (!ret)
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 1;
}

static int socket_udp_server6_without_authority_denied(void)
{
	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_port = 0,
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
	};
	int saved_errno;
	int fd;
	int ret;

	fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return 2;

	errno = 0;
	ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	saved_errno = errno;
	close(fd);

	if (!ret)
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 1;
}

static int module_autoload_without_authority_denied(void)
{
	int fd;

	errno = 0;
	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_SCTP);
	if (fd >= 0) {
		close(fd);
		return 1;
	}

	return errno == EPROTONOSUPPORT || errno_is_denial(errno) ? 0 : 2;
}

static int usb_hotplug_without_authority_denied(void)
{
	if (access(HDN_USB_HOTPLUG_TRIGGER, R_OK))
		return KSFT_SKIP;

	printf("HDN_USB_HOTPLUG_READY\n");
	fflush(stdout);

	return securityfs_events_contains_timeout("authority=27", 5000) ?
	       0 : 1;
}

static int usb_monitor_without_authority_denied(void)
{
	int fd;

	errno = 0;
	fd = open(HDN_DEV_USBMON0, O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		close(fd);
		return 1;
	}

	return errno_is_denial(errno) ? 0 : 2;
}

static void test_signed_policy_transaction(void)
{
	bool staged = false;
	bool committed = false;
	int broker_commit_result = 2;
	int broker_rollback_result = 2;
	int broker_denied_result = 2;
	int recovery_unknown_result = 2;
	int recovery_unsafe_config_result = 2;
	int recovery_rollback_result = 2;
	int recovery_describe_unknown_result = 2;
	int recovery_describe_unsafe_config_result = 2;
	int recovery_describe_result = 2;
	int recovery_prompt_approve_result = 2;
	int recovery_prompt_deny_result = 2;
	int recovery_prompt_no_display_result = 2;
	int recovery_session_unknown_result = 2;
	int recovery_session_unsafe_config_result = 2;
	int recovery_session_confirm_denied_result = 2;
	int recovery_session_no_display_result = 2;
	int recovery_session_rollback_result = 2;
	int recovery_portal_unknown_result = 2;
	int recovery_portal_unsafe_config_result = 2;
	int recovery_portal_rollback_result = 2;
	int recovery_panel_unknown_result = 2;
	int recovery_panel_unsafe_config_result = 2;
	int recovery_panel_describe_result = 2;
	int recovery_panel_rollback_result = 2;
	int recovery_ui_unknown_result = 2;
	int recovery_ui_unsafe_config_result = 2;
	int recovery_ui_cancel_result = 2;
	int recovery_ui_no_display_result = 2;
	int recovery_ui_rollback_result = 2;
	bool restricted_staged = false;
	bool restricted_committed = false;
	bool restricted_rolled_back = false;
	bool proc_disclose_staged = false;
	bool proc_disclose_committed = false;
	bool proc_disclose_rolled_back = false;
	bool trace_symbol_staged = false;
	bool trace_symbol_committed = false;
	bool trace_symbol_rolled_back = false;
	int owner_only_sysfs_setup = -ENOENT;
	bool chroot_mount_staged = false;
	bool chroot_mount_committed = false;
	bool chroot_mount_rolled_back = false;
	bool jit_staged = false;
	bool jit_committed = false;
	bool jit_rolled_back = false;
	bool execstack_staged = false;
	bool execstack_committed = false;
	bool execstack_rolled_back = false;
	bool textrel_staged = false;
	bool textrel_committed = false;
	bool textrel_rolled_back = false;
	bool relro_staged = false;
	bool relro_committed = false;
	bool relro_rolled_back = false;
	bool kill_staged = false;
	bool kill_committed = false;
	bool kill_rolled_back = false;
	bool cred_staged = false;
	bool cred_committed = false;
	bool cred_rolled_back = false;
	bool privexec_staged = false;
	bool privexec_committed = false;
	bool privexec_rolled_back = false;
	bool identity_staged = false;
	bool identity_committed = false;
	bool identity_rolled_back = false;
	bool module_path_staged = false;
	bool module_path_committed = false;
	bool module_path_rolled_back = false;
	bool firmware_staged = false;
	bool firmware_committed = false;
	bool firmware_rolled_back = false;
	bool mount_policy_staged = false;
	bool mount_policy_committed = false;
	bool mount_policy_rolled_back = false;
	bool mount_ro_policy_staged = false;
	bool mount_ro_policy_committed = false;
	bool mount_ro_policy_rolled_back = false;
	int product_rofs_mount_setup = 2;
	int product_rofs_broker_apply_mount_setup = 2;
	int product_rofs_optional_mount_setup = 2;
	int product_rofs_apply_result = 2;
	int product_rofs_apply_optional_result = 2;
	int product_rofs_apply_bind_result = 2;
	int product_rofs_broker_apply_denied_result = 2;
	int product_rofs_broker_apply_unsafe_result = 2;
	int product_rofs_broker_apply_result = 2;
	int product_rofs_image_seal_mount_setup = 2;
	int image_seal_unknown_result = 2;
	int image_seal_unsafe_config_result = 2;
	int image_seal_result = 2;
	int product_rofs_transaction_result = 2;
	int product_rofs_transaction_cancel_result = 2;
	int product_rofs_transaction_orphan_result = 2;
	int product_rofs_transaction_restrictions_result = 2;
	int product_rofs_broker_missing_config_result = 2;
	int product_rofs_broker_unsafe_config_result = 2;
	int product_rofs_broker_denial_result = 2;
	int product_rofs_broker_token_result = 2;
	int product_rofs_system_unknown_result = 2;
	int product_rofs_system_unsafe_config_result = 2;
	int product_rofs_system_transaction_result = 2;
	int product_rofs_package_hook_unknown_result = 2;
	int product_rofs_package_hook_unsafe_config_result = 2;
	int product_rofs_package_hook_result = 2;
	int product_rofs_recovery_repair_result = 2;
	int product_rofs_recovery_session_repair_result = 2;
	int product_rofs_recovery_portal_repair_result = 2;
	int prompt_describe_unknown_result = 2;
	int prompt_describe_unsafe_config_result = 2;
	int prompt_describe_result = 2;
	int auth_prompt_approve_result = 2;
	int auth_prompt_deny_result = 2;
	int auth_prompt_no_display_result = 2;
	int product_rofs_prompt_unknown_result = 2;
	int product_rofs_prompt_unsafe_config_result = 2;
	int product_rofs_prompt_dispatch_result = 2;
	int product_rofs_prompt_session_unknown_result = 2;
	int product_rofs_prompt_session_unsafe_config_result = 2;
	int product_rofs_prompt_session_auth_denied_result = 2;
	int product_rofs_prompt_session_no_display_result = 2;
	int product_rofs_prompt_session_result = 2;
	int product_rofs_prompt_portal_unknown_result = 2;
	int product_rofs_prompt_portal_unsafe_config_result = 2;
	int product_rofs_prompt_portal_result = 2;
	int product_rofs_desktop_action_unknown_result = 2;
	int product_rofs_desktop_action_unsafe_config_result = 2;
	int product_rofs_desktop_action_result = 2;
	int product_rofs_desktop_daemon_unknown_result = 2;
	int product_rofs_desktop_daemon_unsafe_config_result = 2;
	int product_rofs_desktop_daemon_result = 2;
	int product_rofs_control_center_stdio_unknown_result = 2;
	int product_rofs_control_center_unknown_result = 2;
	int product_rofs_control_center_result = 2;
	int product_rofs_control_center_stdio_result = 2;
	int product_rofs_settings_panel_unknown_result = 2;
	int product_rofs_settings_panel_unsafe_config_result = 2;
	int product_rofs_settings_panel_result = 2;
	int product_rofs_settings_ui_unknown_result = 2;
	int product_rofs_settings_ui_unsafe_config_result = 2;
	int product_rofs_settings_ui_cancel_result = 2;
	int product_rofs_settings_ui_no_display_result = 2;
	int product_rofs_settings_ui_result = 2;
	int product_rofs_settings_ui_prereq = 2;
	int block_admin_query_result = 2;
	int block_admin_denial_result = 2;
	bool proc_task_policy_staged = false;
	bool proc_task_policy_committed = false;
	bool proc_task_policy_rolled_back = false;
	bool namespace_only_policy_staged = false;
	bool namespace_only_policy_committed = false;
	bool namespace_only_policy_rolled_back = false;
	bool namespace_proc_task_policy_staged = false;
	bool namespace_proc_task_policy_committed = false;
	bool namespace_proc_task_policy_rolled_back = false;
	bool subject_policy_staged = false;
	bool subject_policy_committed = false;
	bool subject_policy_rolled_back = false;
	bool userns_depth_policy_staged = false;
	bool userns_depth_policy_committed = false;
	bool userns_depth_policy_rolled_back = false;
	bool role_policy_staged = false;
	bool role_policy_committed = false;
	bool role_policy_rolled_back = false;
	bool capability_policy_staged = false;
	bool capability_policy_committed = false;
	bool capability_policy_rolled_back = false;
	int capability_test_setup = 2;
	bool object_audit_policy_staged = false;
	bool object_audit_policy_committed = false;
	bool object_audit_policy_rolled_back = false;
	int object_audit_test_setup = 2;
	bool process_account_policy_staged = false;
	bool process_account_policy_committed = false;
	bool process_account_policy_rolled_back = false;
	bool object_policy_staged = false;
	bool object_policy_committed = false;
	bool object_policy_rolled_back = false;
	bool object_attr_xattr_prepared = false;
	bool object_fileattr_prepared = false;
	bool object_xattr_prepared = false;
	bool object_split_xattr_prepared = false;
	bool object_tree_xattr_prepared = false;
	int object_preopen_fd = -1;
	int object_write_preopen_fd = -1;
	int object_append_preopen_fd = -1;
	int object_truncate_preopen_fd = -1;
	int object_tree_truncate_preopen_fd = -1;
	int object_tree_truncate_unmatched_preopen_fd = -1;
	int object_stat_preopen_fd = -1;
	int object_list_preopen_fd = -1;
	int object_chdir_preopen_fd = -1;
	int object_tree_chdir_preopen_fd = -1;
	int object_tree_chdir_unmatched_preopen_fd = -1;
	int object_unix_connect_protected_fd = -1;
	int object_unix_connect_unprotected_fd = -1;
	int object_tree_unix_connect_fd = -1;
	int object_tree_unix_connect_unmatched_fd = -1;
	int object_tree_unix_listen_fd = -1;
	int object_tree_unix_accept_fd = -1;
	int object_tree_unix_send_fd = -1;
	int object_tree_unix_connected_send_fd = -1;
	int object_tree_unix_recv_fd = -1;
	int object_unix_listen_protected_fd = -1;
	int object_unix_listen_unprotected_fd = -1;
	int object_unix_accept_protected_fd = -1;
	int object_unix_accept_unprotected_fd = -1;
	int object_unix_send_protected_fd = -1;
	int object_unix_send_unprotected_fd = -1;
	int object_unix_connected_send_protected_fd = -1;
	int object_unix_connected_send_unprotected_fd = -1;
	int object_unix_recv_protected_fd = -1;
	int object_unix_recv_unprotected_fd = -1;
	int object_unix_abs_connect_protected_fd = -1;
	int object_unix_abs_connect_unprotected_fd = -1;
	int object_unix_abs_listen_protected_fd = -1;
	int object_unix_abs_listen_unprotected_fd = -1;
	int object_unix_abs_accept_protected_fd = -1;
	int object_unix_abs_accept_unprotected_fd = -1;
	int object_unix_abs_send_protected_fd = -1;
	int object_unix_abs_send_unprotected_fd = -1;
	int object_unix_abs_connected_send_protected_fd = -1;
	int object_unix_abs_connected_send_unprotected_fd = -1;
	int object_unix_abs_recv_protected_fd = -1;
	int object_unix_abs_recv_unprotected_fd = -1;
	bool socket_policy_staged = false;
	bool socket_policy_committed = false;
	bool socket_policy_rolled_back = false;
	bool block_admin_policy_staged = false;
	bool block_admin_policy_committed = false;
	bool block_admin_policy_rolled_back = false;
	bool recovery_staged = false;
	bool recovery_committed = false;
	bool recovery = false;
	bool recovery_rolled_back = false;
	bool resealed = false;
	bool rolled_back = false;
	bool proc_gid_mount_ready = false;
	bool tpe_mount_ready = false;
	bool tpe_user_ready = false;
	bool runtime = false;
	char socket_connect_object[64];
	char socket_connect6_object[64];
	char socket_udp_connect_object[64];
	char socket_udp_connect6_object[64];
	char socket_server_object[64];
	char socket_server6_object[64];
	char socket_udp_server_object[64];
	char socket_udp_server6_object[64];
	int proc_gid_mount_setup = 2;
	int ret;

	if (geteuid() != 0 ||
	    access(HDN_SIGNED_POLICY, R_OK) ||
	    access(HDN_BROKER_SIGNED_POLICY, R_OK) ||
	    access(HDN_RESTRICTED_POLICY, R_OK) ||
	    access(HDN_PROC_DISCLOSE_POLICY, R_OK) ||
	    access(HDN_TRACE_SYMBOL_POLICY, R_OK) ||
	    access(HDN_CHROOT_MOUNT_POLICY, R_OK) ||
	    access(HDN_JIT_POLICY, R_OK) ||
	    access(HDN_EXECSTACK_POLICY, R_OK) ||
	    access(HDN_TEXTREL_POLICY, R_OK) ||
	    access(HDN_RELRO_POLICY, R_OK) ||
	    access(HDN_KILL_POLICY, R_OK) ||
	    access(HDN_CRED_DENY_POLICY, R_OK) ||
	    access(HDN_PRIVEXEC_DENY_POLICY, R_OK) ||
	    access(HDN_IDENTITY_POLICY, R_OK) ||
	    access(HDN_MODULE_PATH_POLICY, R_OK) ||
	    access(HDN_FIRMWARE_POLICY, R_OK) ||
	    access(HDN_MOUNT_POLICY, R_OK) ||
	    access(HDN_MOUNT_RO_POLICY, R_OK) ||
	    access(HDN_PROC_TASK_POLICY, R_OK) ||
	    access(HDN_NAMESPACE_ONLY_POLICY, R_OK) ||
	    access(HDN_NAMESPACE_PROC_TASK_POLICY, R_OK) ||
	    access(HDN_SUBJECT_POLICY, R_OK) ||
	    access(HDN_USERNS_DEPTH_POLICY, R_OK) ||
	    access(HDN_ROLE_POLICY, R_OK) ||
	    access(HDN_CAPABILITY_POLICY, R_OK) ||
	    access(HDN_OBJECT_AUDIT_POLICY, R_OK) ||
	    access(HDN_PROCESS_ACCOUNT_POLICY, R_OK) ||
	    access(HDN_OBJECT_WRITE_POLICY, R_OK) ||
	    access(HDN_SOCKET_POLICY, R_OK) ||
	    access(HDN_BLOCK_ADMIN_POLICY, R_OK)) {
		ksft_test_result_skip("admin broker policy commit succeeds\n");
		ksft_test_result_skip("admin broker policy rollback succeeds\n");
		ksft_test_result_skip("admin broker denies unapproved policy path\n");
		ksft_test_result_skip("recovery action denies unknown action\n");
		ksft_test_result_skip("recovery action denies unsafe config\n");
		ksft_test_result_skip("recovery action policy rollback succeeds\n");
		ksft_test_result_skip("recovery describe denies unknown action\n");
		ksft_test_result_skip("recovery describe denies unsafe config\n");
		ksft_test_result_skip("recovery describe reports approved action metadata\n");
		ksft_test_result_skip("recovery prompt approves valid metadata in test mode\n");
		ksft_test_result_skip("recovery prompt denies valid metadata in test mode\n");
		ksft_test_result_skip("recovery prompt fails closed without graphical session\n");
		ksft_test_result_skip("recovery session denies unknown action\n");
		ksft_test_result_skip("recovery session denies unsafe config\n");
		ksft_test_result_skip("recovery session denies failed confirmation\n");
		ksft_test_result_skip("recovery session fails closed without graphical session\n");
		ksft_test_result_skip("recovery session policy rollback succeeds\n");
		ksft_test_result_skip("recovery portal denies unknown recovery UI action\n");
		ksft_test_result_skip("recovery portal denies unsafe config\n");
		ksft_test_result_skip("recovery portal policy rollback succeeds\n");
		ksft_test_result_skip("recovery panel denies unknown recovery action\n");
		ksft_test_result_skip("recovery panel denies unsafe config\n");
		ksft_test_result_skip("recovery panel describes mapped repair action\n");
		ksft_test_result_skip("recovery panel policy rollback succeeds\n");
		ksft_test_result_skip("recovery UI denies unknown recovery action\n");
		ksft_test_result_skip("recovery UI denies unsafe config\n");
		ksft_test_result_skip("recovery UI denies canceled selection\n");
		ksft_test_result_skip("recovery UI fails closed without graphical session\n");
		ksft_test_result_skip("recovery UI policy rollback succeeds\n");
		ksft_test_result_skip("APT package hook invokes hdn package hook\n");
		ksft_test_result_skip("pacman package hook invokes hdn package hook\n");
		ksft_test_result_skip("DNF package hook invokes hdn package hook\n");
		ksft_test_result_skip("DNF5 package hook invokes hdn package hook\n");
		ksft_test_result_skip("image seal unit invokes hdn package hook\n");
		ksft_test_result_skip("admin broker approval token is required when configured\n");
		ksft_test_result_skip("admin broker rejects unsafe approval token\n");
		ksft_test_result_skip("admin broker rejects approval token for wrong intent\n");
		ksft_test_result_skip("admin broker rejects expired approval token\n");
		ksft_test_result_skip("approval token issuer rejects unknown intent\n");
		ksft_test_result_skip("approval token issuer creates broker-valid token\n");
		ksft_test_result_skip("admin broker accepts valid approval token for typed intent\n");
		ksft_test_result_skip("signed hardening policy stages\n");
		ksft_test_result_skip("signed hardening policy is staged sealed\n");
		ksft_test_result_skip("signed hardening policy commits\n");
		ksft_test_result_skip("committed hardening policy generation is active\n");
		ksft_test_result_skip("committed hardening policy is sealed\n");
		ksft_test_result_skip("proc ipaddr records accepted TCP peer and child handoff\n");
				ksft_test_result_skip("proc ipaddr carries peer across local TCP\n");
				ksft_test_result_skip("proc ipaddr carries peer across AF_UNIX stream\n");
				ksft_test_result_skip("proc memmap disclosure policy exposes target addresses\n");
				ksft_test_result_skip("proc disclosure policy exposes target cmdline\n");
				ksft_test_result_skip("proc disclosure policy exposes target environ\n");
				ksft_test_result_skip("proc disclosure policy exposes target auxv\n");
					ksft_test_result_skip("proc disclosure policy exposes target syscall metadata\n");
					ksft_test_result_skip("proc disclosure policy exposes target io accounting\n");
						ksft_test_result_skip("proc disclosure policy exposes target personality flags\n");
						ksft_test_result_skip("proc disclosure policy exposes target coredump filter\n");
						ksft_test_result_skip("proc disclosure policy allows target coredump filter writes\n");
						ksft_test_result_skip("proc disclosure policy exposes target resource limits\n");
						ksft_test_result_skip("proc disclosure policy exposes target statm accounting\n");
						ksft_test_result_skip("proc disclosure policy exposes target scheduler state\n");
						ksft_test_result_skip("proc disclosure policy exposes target scheduler statistics\n");
						ksft_test_result_skip("proc resource-map disclosure policy exposes address ranges\n");
			ksft_test_result_skip("module-autoload profile can write modprobe helper path\n");
			ksft_test_result_skip("module-autoload profile denies unsafe modprobe helper path\n");
			ksft_test_result_skip("setuid exec caps inherited stack resource limit\n");
		ksft_test_result_skip("normal loader rejects unsigned module file\n");
		ksft_test_result_skip("signed policy denies ptrace execute-only read\n");
		ksft_test_result_skip("signed policy denies proc mem execute-only read\n");
		ksft_test_result_skip("hardening events report ptrace execute-only read denial\n");
		ksft_test_result_skip("hardening events report sealed data write fault\n");
		ksft_test_result_skip("kernel lockout probe bans uid and blocks reentry\n");
		ksft_test_result_skip("hardening policy rollback succeeds\n");
		ksft_test_result_skip("rollback restores previous active generation\n");
		ksft_test_result_skip("proc-disclose hardening policy stages\n");
		ksft_test_result_skip("proc-disclose hardening policy commits\n");
		ksft_test_result_skip("proc disclosure permits read-only proc root access\n");
		ksft_test_result_skip("proc disclosure does not permit ptrace attach\n");
		ksft_test_result_skip("proc-disclose hardening policy rollback succeeds\n");
		ksft_test_result_skip("restricted hardening policy stages\n");
		ksft_test_result_skip("restricted hardening policy commits\n");
		ksft_test_result_skip("restricted profile denies ptrace attach\n");
		ksft_test_result_skip("restricted profile denies proc mem access\n");
		ksft_test_result_skip("restricted profile denies cross-profile signal\n");
		ksft_test_result_skip("restricted profile allows direct-child signal\n");
		ksft_test_result_skip("restricted profile allows protected shared memory inside profile\n");
		ksft_test_result_skip("restricted profile denies protected shared memory across profiles\n");
		ksft_test_result_skip("restricted profile denies process_vm_readv across profiles\n");
		ksft_test_result_skip("restricted profile denies process_vm_writev across profiles\n");
		ksft_test_result_skip("restricted profile allows process_vm_readv inside profile\n");
		ksft_test_result_skip("restricted profile denies process_madvise across profiles\n");
		ksft_test_result_skip("restricted profile denies process_mrelease across profiles\n");
		ksft_test_result_skip("restricted profile denies move_pages across profiles\n");
		ksft_test_result_skip("restricted profile allows move_pages inside profile\n");
		ksft_test_result_skip("restricted profile denies migrate_pages across profiles\n");
		ksft_test_result_skip("restricted profile denies pidfd_open across profiles\n");
		ksft_test_result_skip("restricted profile denies received pidfd info across profiles\n");
		ksft_test_result_skip("restricted profile redacts received pidfd fdinfo across profiles\n");
		ksft_test_result_skip("restricted profile denies pidfd_getfd across profiles\n");
		ksft_test_result_skip("restricted profile allows pidfd_getfd inside profile\n");
		ksft_test_result_skip("restricted profile hides other-user proc entries\n");
		ksft_test_result_skip("restricted profile allows proc gid mount group access\n");
		ksft_test_result_skip("restricted profile allows proc task-view group access\n");
		ksft_test_result_skip("restricted profile allows pidfd_open for task-view group\n");
		ksft_test_result_skip("restricted profile denies kexec load\n");
		ksft_test_result_skip("restricted profile denies mount administration\n");
		ksft_test_result_skip("restricted profile denies raw I/O device access\n");
		ksft_test_result_skip("restricted profile denies raw CPU MSR device access\n");
		ksft_test_result_skip("restricted profile denies raw CPU CPUID device access\n");
		ksft_test_result_skip("restricted profile denies namespace administration\n");
		ksft_test_result_skip("restricted profile denies open_tree namespace\n");
		ksft_test_result_skip("restricted profile denies sysfs mutation\n");
		ksft_test_result_skip("restricted profile denies owner-only sysfs read\n");
		ksft_test_result_skip("restricted profile hides owner-only sysfs entries\n");
		ksft_test_result_skip("restricted profile denies sensitive sysfs read\n");
		ksft_test_result_skip("restricted profile hides sensitive sysfs entries\n");
		ksft_test_result_skip("restricted profile denies boot params sysfs read\n");
		ksft_test_result_skip("restricted profile hides boot params sysfs entry\n");
		ksft_test_result_skip("restricted profile denies firmware memmap address read\n");
		ksft_test_result_skip("restricted profile hides firmware memmap address entry\n");
		ksft_test_result_skip("restricted profile allows firmware memmap type read\n");
		ksft_test_result_skip("restricted profile lists firmware memmap type entry\n");
			ksft_test_result_skip("restricted profile denies proc disclosure\n");
			ksft_test_result_skip("restricted profile redacts proc memmap addresses\n");
			ksft_test_result_skip("restricted profile preserves self pagemap reads\n");
			ksft_test_result_skip("restricted profile denies cross-process pagemap reads\n");
				ksft_test_result_skip("restricted profile denies global kpage metadata\n");
					ksft_test_result_skip("restricted profile denies cross-process cmdline reads\n");
					ksft_test_result_skip("restricted profile denies cross-process environ reads\n");
					ksft_test_result_skip("restricted profile denies cross-process auxv reads\n");
						ksft_test_result_skip("restricted profile denies cross-process syscall reads\n");
						ksft_test_result_skip("restricted profile denies cross-process io accounting reads\n");
						ksft_test_result_skip("restricted profile denies cross-process personality reads\n");
						ksft_test_result_skip("restricted profile denies cross-process coredump filter reads\n");
						ksft_test_result_skip("restricted profile denies cross-process coredump filter writes\n");
						ksft_test_result_skip("restricted profile denies cross-process resource-limit reads\n");
						ksft_test_result_skip("restricted profile denies cross-process statm reads\n");
						ksft_test_result_skip("restricted profile denies cross-process scheduler-state reads\n");
						ksft_test_result_skip("restricted profile denies cross-process scheduler-statistic reads\n");
						ksft_test_result_skip("restricted profile redacts proc resource-map addresses\n");
				ksft_test_result_skip("restricted profile redacts vmalloc caller symbols\n");
				ksft_test_result_skip("restricted profile denies modprobe helper path write\n");
				ksft_test_result_skip("restricted profile denies kernel log write\n");
				ksft_test_result_skip("restricted profile hides kallsyms symbols\n");
		ksft_test_result_skip("restricted profile hides module base addresses\n");
		ksft_test_result_skip("restricted profile denies debugfs access\n");
		ksft_test_result_skip("restricted profile denies tracefs access\n");
		ksft_test_result_skip("restricted profile denies BPF map creation\n");
		ksft_test_result_skip("restricted profile denies BPF metadata enumeration\n");
		ksft_test_result_skip("restricted profile denies untrusted executable path\n");
		ksft_test_result_skip("restricted TPE denies untrusted mountpoint\n");
		ksft_test_result_skip("restricted profile TPE denies non-root-owned exec directory\n");
		ksft_test_result_skip("restricted profile TPE denies executable mmap from non-root-owned directory\n");
		ksft_test_result_skip("restricted profile TPE denies executable mprotect from non-root-owned directory\n");
		ksft_test_result_skip("restricted setuid exec enters privileged profile\n");
		ksft_test_result_skip("restricted filecap exec enters privileged profile\n");
		ksft_test_result_skip("setuid exec force-disables user-controllable speculation controls\n");
		ksft_test_result_skip("setuid exec rejects oversized argv/env stack\n");
		ksft_test_result_skip("restricted chroot denies fchdir escape\n");
		ksft_test_result_skip("restricted chroot denies repeated chroot\n");
		ksft_test_result_skip("restricted chroot denies chmod\n");
		ksft_test_result_skip("restricted chroot denies device mknod\n");
		ksft_test_result_skip("restricted chroot denies shared memory attach\n");
		ksft_test_result_skip("restricted chroot denies priority increase\n");
		ksft_test_result_skip("restricted chroot denies bad directory rename\n");
		ksft_test_result_skip("restricted chroot denies abstract UNIX socket escape\n");
		ksft_test_result_skip("restricted chroot denies privileged capability use\n");
		ksft_test_result_skip("restricted chroot hides outside proc task\n");
			ksft_test_result_skip("restricted chroot denies outside task signal\n");
			ksft_test_result_skip("restricted chroot denies file-handle open\n");
			ksft_test_result_skip("restricted chroot denies sysctl write\n");
			ksft_test_result_skip("restricted chroot exec audit is flagged\n");
		ksft_test_result_skip("restricted profile denies non-local socket creation\n");
		ksft_test_result_skip("restricted profile allows local socket creation\n");
		ksft_test_result_skip("restricted profile denies runtime USB hotplug\n");
		ksft_test_result_skip("restricted profile denies USB monitor capture\n");
		ksft_test_result_skip("restricted profile denies system time change\n");
		ksft_test_result_skip("restricted resource-limit hard raise denied\n");
		ksft_test_result_skip("restricted profile resource soft ceiling denied\n");
		ksft_test_result_skip("restricted profile resource hard ceiling denied\n");
		ksft_test_result_skip("restricted raw block-device access denied\n");
		ksft_test_result_skip("restricted hardening policy rollback succeeds\n");
		ksft_test_result_skip("restricted rollback restores previous active generation\n");
		ksft_test_result_skip("trace-symbol kprobe fixture installs\n");
		ksft_test_result_skip("trace-symbol hardening policy stages\n");
		ksft_test_result_skip("trace-symbol hardening policy commits\n");
		ksft_test_result_skip("trace-symbol policy denies ftrace symbol listing\n");
		ksft_test_result_skip("trace-symbol policy denies kprobe symbol lookup\n");
		ksft_test_result_skip("trace-symbol policy redacts kprobe list symbols\n");
		ksft_test_result_skip("trace-symbol policy redacts symbolic pointer formatting\n");
		ksft_test_result_skip("trace-symbol policy denies BPF kallsyms helper lookup\n");
		ksft_test_result_skip("trace-symbol hardening policy rollback succeeds\n");
		ksft_test_result_skip("chroot-mount hardening policy stages\n");
		ksft_test_result_skip("chroot-mount hardening policy commits\n");
		ksft_test_result_skip("chroot-mount profile allows mount outside chroot\n");
		ksft_test_result_skip("contained chroot denies mount despite mount authority\n");
		ksft_test_result_skip("chroot-mount hardening policy rollback succeeds\n");
		ksft_test_result_skip("hardening events report chroot mount denial\n");
			ksft_test_result_skip("event decoder names chroot mount denial reason\n");
			ksft_test_result_skip("event decoder names chroot file-handle denial reason\n");
			ksft_test_result_skip("event decoder names chroot sysctl denial reason\n");
		ksft_test_result_skip("credential-deny hardening policy stages\n");
		ksft_test_result_skip("credential-deny hardening policy commits\n");
		ksft_test_result_skip("target profile without CRED_CHANGE denies setuid exec\n");
		ksft_test_result_skip("target profile without CRED_CHANGE denies filecap exec\n");
		ksft_test_result_skip("credential-deny hardening policy rollback succeeds\n");
		ksft_test_result_skip("hardening events report credential transition denial\n");
		ksft_test_result_skip("privexec-deny hardening policy stages\n");
		ksft_test_result_skip("privexec-deny hardening policy commits\n");
		ksft_test_result_skip("unprivileged setuid exec is denied even with CRED_CHANGE\n");
		ksft_test_result_skip("privexec-deny blocks unprivileged filecap exec\n");
		ksft_test_result_skip("hardening events report privexec denial\n");
		ksft_test_result_skip("privexec-deny hardening policy rollback succeeds\n");
		ksft_test_result_skip("privileged exec crash throttle denies retry\n");
		ksft_test_result_skip("privileged-descendant SIGXFSZ coredump is blocked\n");
		ksft_test_result_skip("identity hardening policy stages\n");
		ksft_test_result_skip("identity hardening policy commits\n");
		ksft_test_result_skip("identity binary exec enters matched profile\n");
		ksft_test_result_skip("identity exec profile survives credential drop\n");
		ksft_test_result_skip("identity unmatched copy enters default profile\n");
		ksft_test_result_skip("identity script enters interpreter-chain profile\n");
		ksft_test_result_skip("identity inherit exec preserves caller profile\n");
		ksft_test_result_skip("identity profile retains unmatched child exec\n");
		ksft_test_result_skip("identity parent inherit exec preserves matched caller profile\n");
		ksft_test_result_skip("identity parent inherit rule ignores unmatched caller profile\n");
		ksft_test_result_skip("identity replaced trusted path enters default profile\n");
		ksft_test_result_skip("identity hardening policy rollback succeeds\n");
		ksft_test_result_skip("module-path hardening policy stages\n");
		ksft_test_result_skip("module-path hardening policy commits\n");
		ksft_test_result_skip("trusted module path reaches loader\n");
		ksft_test_result_skip("replaced trusted module path is denied\n");
		ksft_test_result_skip("module-path hardening policy rollback succeeds\n");
		ksft_test_result_skip("firmware hardening policy stages\n");
		ksft_test_result_skip("firmware hardening policy commits\n");
		ksft_test_result_skip("trusted firmware name loads\n");
		ksft_test_result_skip("untrusted firmware name is denied\n");
		ksft_test_result_skip("firmware hardening policy rollback succeeds\n");
		ksft_test_result_skip("mount hardening policy stages\n");
		ksft_test_result_skip("mount hardening policy commits\n");
		ksft_test_result_skip("mount policy denies FUSE mount without authority\n");
		ksft_test_result_skip("mount policy denies read-only remount relaxation\n");
		ksft_test_result_skip("mount policy denies read-only mount_setattr relaxation\n");
		ksft_test_result_skip("hardening events report FUSE mount denial\n");
		ksft_test_result_skip("hardening events report ROFS relaxation denial\n");
		ksft_test_result_skip("mount hardening policy rollback succeeds\n");
		ksft_test_result_skip("read-only mount hardening policy stages\n");
		ksft_test_result_skip("read-only mount hardening policy commits\n");
		ksft_test_result_skip("read-only mount policy denies writable mount\n");
		ksft_test_result_skip("read-only mount policy allows read-only mount\n");
		ksft_test_result_skip("read-only mount policy allows updater writable mount\n");
		ksft_test_result_skip("product ROFS apply tool seals mounted path read-only\n");
		ksft_test_result_skip("product ROFS apply optional list skips absent paths and seals required mount\n");
		ksft_test_result_skip("admin broker denies unapproved ROFS apply list\n");
		ksft_test_result_skip("admin broker rejects unsafe ROFS apply list\n");
		ksft_test_result_skip("admin broker ROFS apply list seals mounted path read-only\n");
		ksft_test_result_skip("image seal denies unknown seal\n");
		ksft_test_result_skip("image seal denies unsafe config\n");
		ksft_test_result_skip("image seal applies read-only mount list\n");
		ksft_test_result_skip("product ROFS transaction updates and reseals mount\n");
		ksft_test_result_skip("canceled ROFS transaction stops worker and reseals mount\n");
		ksft_test_result_skip("ROFS transaction stops background worker before reseal\n");
		ksft_test_result_skip("admin broker denies missing allowlist\n");
		ksft_test_result_skip("admin broker denies writable allowlist\n");
		ksft_test_result_skip("admin broker denies unapproved ROFS worker\n");
		ksft_test_result_skip("admin broker approval token is consumed and cannot replay\n");
		ksft_test_result_skip("system transaction denies unknown operation\n");
		ksft_test_result_skip("system transaction denies unsafe config\n");
		ksft_test_result_skip("system transaction updates and reseals mount\n");
		ksft_test_result_skip("package hook denies unknown hook\n");
		ksft_test_result_skip("package hook denies unsafe config\n");
		ksft_test_result_skip("package hook updates and reseals mount\n");
		ksft_test_result_skip("recovery action package repair updates and reseals mount\n");
		ksft_test_result_skip("recovery session package repair updates and reseals mount\n");
		ksft_test_result_skip("recovery portal package repair updates and reseals mount\n");
		ksft_test_result_skip("prompt describe denies unknown action\n");
		ksft_test_result_skip("prompt describe denies unsafe config\n");
		ksft_test_result_skip("prompt describe reports approved action metadata\n");
		ksft_test_result_skip("auth prompt approves valid metadata in test mode\n");
		ksft_test_result_skip("auth prompt denies valid metadata in test mode\n");
		ksft_test_result_skip("auth prompt fails closed without graphical session\n");
		ksft_test_result_skip("prompt dispatch denies unknown action\n");
		ksft_test_result_skip("prompt dispatch denies unsafe config\n");
		ksft_test_result_skip("prompt dispatch updates and reseals mount\n");
		ksft_test_result_skip("prompt session denies unknown action\n");
		ksft_test_result_skip("prompt session denies unsafe config\n");
		ksft_test_result_skip("prompt session denies failed authentication\n");
		ksft_test_result_skip("prompt session fails closed without graphical session\n");
		ksft_test_result_skip("prompt session authenticates updates and reseals mount\n");
		ksft_test_result_skip("prompt portal denies unknown desktop action\n");
		ksft_test_result_skip("prompt portal denies unsafe config\n");
		ksft_test_result_skip("prompt portal authenticates updates and reseals mount\n");
		ksft_test_result_skip("desktop action denies unknown UI action\n");
		ksft_test_result_skip("desktop action denies unsafe config\n");
		ksft_test_result_skip("desktop action authenticates updates and reseals mount\n");
		ksft_test_result_skip("desktop daemon denies unknown UI action\n");
		ksft_test_result_skip("desktop daemon denies unsafe config\n");
		ksft_test_result_skip("desktop daemon stdio authenticates updates and reseals mount\n");
		ksft_test_result_skip("control center denies unknown UI action\n");
		ksft_test_result_skip("control center authenticates updates and reseals mount\n");
		ksft_test_result_skip("admin broker ROFS transaction updates and reseals mount\n");
		ksft_test_result_skip("hardening events report writable mount denial\n");
		ksft_test_result_skip("read-only mount hardening policy rollback succeeds\n");
		ksft_test_result_skip("proc-task hardening policy stages\n");
		ksft_test_result_skip("proc-task hardening policy commits\n");
		ksft_test_result_skip("proc-task policy allows other-user proc entries\n");
		ksft_test_result_skip("proc-task policy allows pidfd_open for other-user task\n");
		ksft_test_result_skip("proc-task policy allows received pidfd info for other-user task\n");
		ksft_test_result_skip("proc-task policy allows received pidfd fdinfo for other-user task\n");
		ksft_test_result_skip("proc-task policy keeps kernel symbols hidden\n");
		ksft_test_result_skip("proc-task hardening policy rollback succeeds\n");
		ksft_test_result_skip("namespace-only hardening policy stages\n");
		ksft_test_result_skip("namespace-only hardening policy commits\n");
		ksft_test_result_skip("namespace-only policy denies received pidfd setns without proc-task view\n");
		ksft_test_result_skip("namespace-only policy denies received pidfd namespace fd without proc-task view\n");
		ksft_test_result_skip("namespace-only hardening policy rollback succeeds\n");
		ksft_test_result_skip("namespace proc-task hardening policy stages\n");
		ksft_test_result_skip("namespace proc-task hardening policy commits\n");
		ksft_test_result_skip("namespace proc-task policy allows received pidfd setns\n");
		ksft_test_result_skip("namespace proc-task policy allows received pidfd namespace fd\n");
		ksft_test_result_skip("namespace proc-task hardening policy rollback succeeds\n");
		ksft_test_result_skip("subject hardening policy stages\n");
		ksft_test_result_skip("subject hardening policy commits\n");
		ksft_test_result_skip("subject policy reports subject rule count\n");
		ksft_test_result_skip("subject uid rule assigns user profile\n");
		ksft_test_result_skip("subject gid rule assigns user profile\n");
		ksft_test_result_skip("subject profile umask makes files private\n");
		ksft_test_result_skip("subject profile umask makes directories private\n");
		ksft_test_result_skip("subject hardening policy rollback succeeds\n");
		ksft_test_result_skip("userns-depth hardening policy stages\n");
		ksft_test_result_skip("userns-depth hardening policy commits\n");
		ksft_test_result_skip("userns-depth policy permits two levels and denies the third\n");
		ksft_test_result_skip("hardening events report requested userns level\n");
		ksft_test_result_skip("event decoder names userns-depth denial\n");
		ksft_test_result_skip("userns-depth hardening policy rollback succeeds\n");
		ksft_test_result_skip("role hardening policy stages\n");
		ksft_test_result_skip("role hardening policy commits\n");
		ksft_test_result_skip("nested role-expanded policy authority permits rollback\n");
		ksft_test_result_skip("capability policy fixture setup succeeds\n");
		ksft_test_result_skip("capability hardening policy stages\n");
		ksft_test_result_skip("capability hardening policy commits\n");
		ksft_test_result_skip("capability policy reports role-expanded masks\n");
		ksft_test_result_skip("capability profile denies CAP_CHOWN\n");
		ksft_test_result_skip("hardening events report capability profile denial\n");
		ksft_test_result_skip("capability profile audits allowed CAP_FOWNER\n");
		ksft_test_result_skip("event decoder names capability profile denial\n");
		ksft_test_result_skip("capability hardening policy rollback succeeds\n");
		ksft_test_result_skip("capability rollback restores CAP_CHOWN\n");
		ksft_test_result_skip("object audit policy fixture setup succeeds\n");
		ksft_test_result_skip("object audit hardening policy stages\n");
		ksft_test_result_skip("object audit hardening policy commits\n");
		ksft_test_result_skip("object audit policy records allowed read\n");
		ksft_test_result_skip("object audit policy records allowed append\n");
		ksft_test_result_skip("object audit policy records allowed write\n");
		ksft_test_result_skip("object audit policy records allowed exec\n");
		ksft_test_result_skip("object audit policy records inherited exec\n");
		ksft_test_result_skip("object audit policy records allowed find\n");
		ksft_test_result_skip("object audit policy records allowed create\n");
		ksft_test_result_skip("object audit policy records allowed delete\n");
		ksft_test_result_skip("object audit policy records allowed link\n");
		ksft_test_result_skip("object audit policy records allowed setid\n");
		ksft_test_result_skip("object deny takes precedence over audit\n");
		ksft_test_result_skip("event decoder names object allow audit\n");
		ksft_test_result_skip("event decoder names inherited exec audit\n");
		ksft_test_result_skip("object audit hardening policy rollback succeeds\n");
		ksft_test_result_skip("object audit rollback stops object audit events\n");
		ksft_test_result_skip("object audit rollback stops inherited exec events\n");
		ksft_test_result_skip("process-account hardening policy stages\n");
			ksft_test_result_skip("process-account hardening policy commits\n");
			ksft_test_result_skip("process-account policy records child exit event\n");
			ksft_test_result_skip("process-account hardening policy rollback succeeds\n");
			ksft_test_result_skip("object-write hardening policy stages\n");
			ksft_test_result_skip("object-write hardening policy commits\n");
			ksft_test_result_skip("object-write policy reports object rule count\n");
			ksft_test_result_skip("object-write policy denies protected file write\n");
			ksft_test_result_skip("object-write policy allows unmatched file write\n");
			ksft_test_result_skip("object-write policy denies protected truncate\n");
			ksft_test_result_skip("object-write policy allows unmatched truncate\n");
			ksft_test_result_skip("object-write policy denies preopened ftruncate\n");
			ksft_test_result_skip("object-write policy allows unmatched ftruncate\n");
			ksft_test_result_skip("object-write policy denies preopened fallocate\n");
			ksft_test_result_skip("object truncate policy allows ordinary write\n");
			ksft_test_result_skip("object truncate policy denies path truncate\n");
			ksft_test_result_skip("object truncate policy allows unmatched truncate\n");
			ksft_test_result_skip("object truncate policy denies preopened ftruncate\n");
			ksft_test_result_skip("object truncate policy denies preopened fallocate\n");
				ksft_test_result_skip("object rename policy denies protected rename\n");
				ksft_test_result_skip("object rename policy allows unmatched rename\n");
				ksft_test_result_skip("object rename-target policy denies protected target\n");
				ksft_test_result_skip("object rename-target policy allows ordinary create\n");
				ksft_test_result_skip("object tree target policy denies nested rename target\n");
				ksft_test_result_skip("object tree target policy allows nested ordinary create after rename-target rule\n");
				ksft_test_result_skip("object tree target policy allows unmatched nested rename target\n");
				ksft_test_result_skip("object unix-connect policy denies protected socket connect\n");
				ksft_test_result_skip("object unix-connect policy allows unmatched socket connect\n");
				ksft_test_result_skip("object unix-bind policy denies protected socket bind\n");
				ksft_test_result_skip("object unix-bind policy allows unmatched socket bind\n");
				ksft_test_result_skip("object unix-listen policy denies protected socket listen\n");
				ksft_test_result_skip("object unix-listen policy allows unmatched socket listen\n");
				ksft_test_result_skip("object unix-accept policy denies protected socket accept\n");
				ksft_test_result_skip("object unix-accept policy allows unmatched socket accept\n");
				ksft_test_result_skip("object unix-send policy denies protected datagram send\n");
				ksft_test_result_skip("object unix-send policy allows unmatched datagram send\n");
				ksft_test_result_skip("object unix-send policy denies preconnected datagram send\n");
				ksft_test_result_skip("object unix-send policy allows unmatched preconnected datagram send\n");
				ksft_test_result_skip("object unix-recv policy denies protected datagram receive\n");
				ksft_test_result_skip("object unix-recv policy allows unmatched datagram receive\n");
				ksft_test_result_skip("object abstract unix-connect policy denies protected socket connect\n");
				ksft_test_result_skip("object abstract unix-connect policy allows unmatched socket connect\n");
				ksft_test_result_skip("object abstract unix-bind policy denies protected socket bind\n");
				ksft_test_result_skip("object abstract unix-bind policy allows unmatched socket bind\n");
				ksft_test_result_skip("object abstract unix-listen policy denies protected socket listen\n");
				ksft_test_result_skip("object abstract unix-listen policy allows unmatched socket listen\n");
				ksft_test_result_skip("object abstract unix-accept policy denies protected socket accept\n");
				ksft_test_result_skip("object abstract unix-accept policy allows unmatched socket accept\n");
				ksft_test_result_skip("object abstract unix-send policy denies protected datagram send\n");
				ksft_test_result_skip("object abstract unix-send policy allows unmatched datagram send\n");
				ksft_test_result_skip("object abstract unix-send policy denies preconnected datagram send\n");
				ksft_test_result_skip("object abstract unix-send policy allows unmatched preconnected datagram send\n");
				ksft_test_result_skip("object abstract unix-recv policy denies protected datagram receive\n");
				ksft_test_result_skip("object abstract unix-recv policy allows unmatched datagram receive\n");
				ksft_test_result_skip("object-write policy denies protected FIFO write open\n");
			ksft_test_result_skip("object-write policy allows unmatched FIFO write open\n");
			ksft_test_result_skip("object-write policy denies protected character device write open\n");
			ksft_test_result_skip("object-write policy allows unmatched character device write open\n");
			ksft_test_result_skip("object-write policy denies protected block device write open\n");
			ksft_test_result_skip("object-write policy allows unmatched block device write open\n");
				ksft_test_result_skip("object-write policy denies preopened splice write\n");
				ksft_test_result_skip("object-write policy denies preopened copy_file_range write\n");
				ksft_test_result_skip("object-write policy denies preopened sendfile write\n");
				ksft_test_result_skip("object-write policy allows unmatched sendfile write\n");
					ksft_test_result_skip("object-write policy denies preopened clone write\n");
					ksft_test_result_skip("object-write policy denies preopened clone-range write\n");
					ksft_test_result_skip("object-write policy denies preopened io_uring write\n");
					ksft_test_result_skip("object-write policy allows unmatched io_uring write\n");
					ksft_test_result_skip("object-write policy denies preopened legacy AIO write\n");
					ksft_test_result_skip("object-write policy allows unmatched legacy AIO write\n");
				ksft_test_result_skip("object-write policy denies preopened shared writable mmap\n");
			ksft_test_result_skip("object-write policy denies preopened shared writable mprotect\n");
			ksft_test_result_skip("object-write policy allows unmatched shared writable mmap\n");
					ksft_test_result_skip("object-read policy denies protected file open\n");
					ksft_test_result_skip("object-read policy denies preopened file read\n");
					ksft_test_result_skip("object-read policy denies preopened clone source read\n");
					ksft_test_result_skip("object-read policy denies preopened clone-range source read\n");
					ksft_test_result_skip("object-read policy denies preopened copy_file_range source read\n");
					ksft_test_result_skip("object-read policy allows unmatched copy_file_range source read\n");
					ksft_test_result_skip("object-read policy denies preopened splice source read\n");
					ksft_test_result_skip("object-read policy allows unmatched splice source read\n");
					ksft_test_result_skip("object-read policy denies preopened sendfile source read\n");
					ksft_test_result_skip("object-read policy allows unmatched sendfile source read\n");
						ksft_test_result_skip("object-read policy denies preopened io_uring read\n");
						ksft_test_result_skip("object-read policy allows unmatched io_uring read\n");
						ksft_test_result_skip("object-read policy denies preopened legacy AIO read\n");
						ksft_test_result_skip("object-read policy allows unmatched legacy AIO read\n");
						ksft_test_result_skip("object-read policy allows unmatched file read\n");
					ksft_test_result_skip("object-read policy denies protected FIFO read open\n");
					ksft_test_result_skip("object-read policy allows unmatched FIFO read open\n");
					ksft_test_result_skip("object-read policy denies protected character device read open\n");
					ksft_test_result_skip("object-read policy allows unmatched character device read open\n");
					ksft_test_result_skip("object-read policy denies protected block device read open\n");
					ksft_test_result_skip("object-read policy allows unmatched block device read open\n");
					ksft_test_result_skip("object-read policy denies preopened readable mmap\n");
					ksft_test_result_skip("object-read policy allows unmatched readable mmap\n");
					ksft_test_result_skip("object-read policy denies preopened readable mprotect\n");
					ksft_test_result_skip("object-read policy allows unmatched readable mprotect\n");
					ksft_test_result_skip("object-read policy denies protected symlink readlink\n");
					ksft_test_result_skip("object-read policy allows unmatched symlink readlink\n");
				ksft_test_result_skip("object-delete policy denies protected file unlink\n");
			ksft_test_result_skip("object-delete policy denies protected file rename\n");
			ksft_test_result_skip("object-delete policy denies replacing protected file\n");
			ksft_test_result_skip("object-delete policy allows unmatched file unlink\n");
			ksft_test_result_skip("object-delete policy denies protected directory rmdir\n");
			ksft_test_result_skip("object-delete policy denies protected directory rename\n");
			ksft_test_result_skip("object-delete policy allows unmatched directory rmdir\n");
			ksft_test_result_skip("object-create policy denies protected file create\n");
			ksft_test_result_skip("object-create policy allows unmatched file create\n");
			ksft_test_result_skip("object-create policy denies protected tmpfile\n");
			ksft_test_result_skip("object-create policy allows unmatched tmpfile\n");
			ksft_test_result_skip("object-create policy denies protected mkdir\n");
			ksft_test_result_skip("object-create policy denies protected symlink\n");
			ksft_test_result_skip("object-create policy denies protected FIFO\n");
			ksft_test_result_skip("object-create policy allows unmatched FIFO\n");
			ksft_test_result_skip("object-create policy denies protected character device\n");
			ksft_test_result_skip("object-create policy allows unmatched character device\n");
			ksft_test_result_skip("object-create policy denies protected block device\n");
			ksft_test_result_skip("object-create policy allows unmatched block device\n");
			ksft_test_result_skip("object-create policy denies protected hardlink\n");
			ksft_test_result_skip("object-create policy denies protected rename target\n");
			ksft_test_result_skip("object creat policy denies protected file create\n");
			ksft_test_result_skip("object mkdir policy denies protected directory create\n");
			ksft_test_result_skip("object mknod policy denies protected node create\n");
			ksft_test_result_skip("object symlink policy denies protected symlink create\n");
			ksft_test_result_skip("object unlink policy denies protected file unlink\n");
			ksft_test_result_skip("object rmdir policy denies protected directory rmdir\n");
			ksft_test_result_skip("object split create policy allows unmatched create operations\n");
			ksft_test_result_skip("object split delete policy allows unmatched delete operations\n");
			ksft_test_result_skip("object-exec policy denies protected exec\n");
			ksft_test_result_skip("object-exec policy allows unmatched exec\n");
			ksft_test_result_skip("object-exec policy denies protected executable mmap\n");
			ksft_test_result_skip("object-exec policy denies protected executable mprotect\n");
				ksft_test_result_skip("object append-only policy allows append write\n");
					ksft_test_result_skip("object append-only policy denies preopened rewrite\n");
					ksft_test_result_skip("object append-only policy denies preopened io_uring rewrite\n");
					ksft_test_result_skip("object append-only policy allows io_uring append\n");
					ksft_test_result_skip("object append-only policy denies preopened legacy AIO rewrite\n");
					ksft_test_result_skip("object append-only policy allows legacy AIO append\n");
				ksft_test_result_skip("object append-only policy denies preopened splice write\n");
			ksft_test_result_skip("object append-only policy denies preopened copy_file_range write\n");
			ksft_test_result_skip("object append-only policy denies preopened sendfile write\n");
			ksft_test_result_skip("object append-only policy denies preopened clone write\n");
			ksft_test_result_skip("object append-only policy denies preopened clone-range write\n");
			ksft_test_result_skip("object append-only policy denies preopened shared writable mmap\n");
			ksft_test_result_skip("object append-only policy denies preopened shared writable mprotect\n");
			ksft_test_result_skip("object append-only policy denies truncate\n");
			ksft_test_result_skip("object append-only policy denies preopened ftruncate\n");
			ksft_test_result_skip("object append-only policy denies fallocate\n");
				ksft_test_result_skip("object link policy denies protected source hardlink\n");
				ksft_test_result_skip("object link policy allows unmatched source hardlink\n");
				ksft_test_result_skip("object link-target policy denies protected target\n");
				ksft_test_result_skip("object link-target policy allows ordinary create\n");
				ksft_test_result_skip("object tree target policy denies nested hardlink target\n");
				ksft_test_result_skip("object tree target policy allows nested ordinary create after link-target rule\n");
				ksft_test_result_skip("object tree target policy allows unmatched nested hardlink target\n");
				ksft_test_result_skip("object attr policy denies protected chmod\n");
			ksft_test_result_skip("object attr policy denies protected chown\n");
			ksft_test_result_skip("object attr policy denies protected timestamps\n");
			ksft_test_result_skip("object attr policy denies protected setxattr\n");
			ksft_test_result_skip("object attr policy denies protected removexattr\n");
			ksft_test_result_skip("object attr policy denies protected fileattr ioctl\n");
			ksft_test_result_skip("object attr policy allows unmatched fileattr ioctl\n");
			ksft_test_result_skip("object attr policy allows unmatched chmod\n");
			ksft_test_result_skip("object attr policy allows unmatched xattr mutation\n");
			ksft_test_result_skip("object chmod policy denies protected chmod\n");
			ksft_test_result_skip("object chown policy denies protected chown\n");
			ksft_test_result_skip("object utime policy denies protected timestamp change\n");
			ksft_test_result_skip("object setxattr policy denies protected setxattr\n");
			ksft_test_result_skip("object removexattr policy denies protected removexattr\n");
			ksft_test_result_skip("object split metadata policy allows unmatched metadata/xattr changes\n");
			ksft_test_result_skip("object xattr policy denies protected getxattr\n");
			ksft_test_result_skip("object setid policy denies protected setuid chmod\n");
			ksft_test_result_skip("object setid policy allows ordinary chmod\n");
			ksft_test_result_skip("object setid policy allows unmatched setuid chmod\n");
			ksft_test_result_skip("object setid policy denies protected setuid create\n");
			ksft_test_result_skip("object setid policy allows ordinary create\n");
			ksft_test_result_skip("object setid policy allows unmatched setuid create\n");
			ksft_test_result_skip("object setid policy denies protected setgid mknod\n");
			ksft_test_result_skip("object setid policy allows ordinary mknod\n");
			ksft_test_result_skip("object ptrace policy denies protected executable target\n");
				ksft_test_result_skip("object xattr policy denies protected listxattr\n");
				ksft_test_result_skip("object xattr policy denies protected POSIX ACL getxattr\n");
				ksft_test_result_skip("object xattr policy allows unmatched getxattr\n");
				ksft_test_result_skip("object xattr policy allows unmatched listxattr\n");
				ksft_test_result_skip("object access policy denies protected access probe\n");
				ksft_test_result_skip("object access policy allows unmatched access probe\n");
				ksft_test_result_skip("object access policy denies read access probe\n");
				ksft_test_result_skip("object access policy denies write access probe\n");
				ksft_test_result_skip("object access policy denies exec access probe\n");
				ksft_test_result_skip("object stat policy denies protected stat\n");
				ksft_test_result_skip("object stat policy denies preopened fstat\n");
				ksft_test_result_skip("object stat policy denies protected fileattr ioctl\n");
				ksft_test_result_skip("object stat policy allows unmatched fileattr ioctl\n");
				ksft_test_result_skip("object stat policy allows unmatched stat\n");
				ksft_test_result_skip("object list policy denies protected readdir\n");
				ksft_test_result_skip("object list policy denies preopened readdir\n");
				ksft_test_result_skip("object list policy allows unmatched readdir\n");
				ksft_test_result_skip("object find policy denies protected O_PATH lookup\n");
				ksft_test_result_skip("object find policy allows unmatched O_PATH lookup\n");
				ksft_test_result_skip("object find policy denies protected regular open\n");
				ksft_test_result_skip("object find policy allows unmatched regular open\n");
				ksft_test_result_skip("object find policy denies protected file handle export\n");
				ksft_test_result_skip("object ioctl policy denies protected ioctl\n");
				ksft_test_result_skip("object ioctl policy allows unmatched ioctl\n");
				ksft_test_result_skip("object lock policy denies protected flock\n");
				ksft_test_result_skip("object lock policy denies protected POSIX lock\n");
				ksft_test_result_skip("object lock policy allows unmatched flock\n");
				ksft_test_result_skip("object lock policy allows unmatched POSIX lock\n");
				ksft_test_result_skip("object lock policy denies protected OFD lock\n");
				ksft_test_result_skip("object lock policy allows unmatched OFD lock\n");
				ksft_test_result_skip("object lock policy denies protected file lease\n");
				ksft_test_result_skip("object lock policy allows unmatched file lease\n");
				ksft_test_result_skip("object watch policy denies protected inotify watch\n");
				ksft_test_result_skip("object watch policy allows unmatched inotify watch\n");
				ksft_test_result_skip("object watch policy denies protected dnotify watch\n");
				ksft_test_result_skip("object watch policy allows unmatched dnotify watch\n");
				ksft_test_result_skip("object watch policy denies protected fanotify watch\n");
				ksft_test_result_skip("object watch policy allows unmatched fanotify watch\n");
				ksft_test_result_skip("object receive policy denies protected fd receive\n");
				ksft_test_result_skip("object receive policy allows unmatched fd receive\n");
				ksft_test_result_skip("object fcntl policy denies protected fd duplication\n");
					ksft_test_result_skip("object fcntl policy allows unmatched fd duplication\n");
					ksft_test_result_skip("object fcntl policy denies protected ioctl flag alias\n");
						ksft_test_result_skip("object fcntl policy allows unmatched ioctl flag alias\n");
						ksft_test_result_skip("object fcntl policy denies protected direct flag change\n");
						ksft_test_result_skip("object fcntl policy allows unmatched direct flag change\n");
						ksft_test_result_skip("object fcntl policy denies protected descriptor flag change\n");
						ksft_test_result_skip("object fcntl policy allows unmatched descriptor flag change\n");
						ksft_test_result_skip("object fcntl policy denies protected owner change\n");
						ksft_test_result_skip("object fcntl policy allows unmatched owner change\n");
						ksft_test_result_skip("object fcntl policy denies protected extended owner change\n");
						ksft_test_result_skip("object fcntl policy allows unmatched extended owner change\n");
						ksft_test_result_skip("object fcntl policy denies protected signal change\n");
						ksft_test_result_skip("object fcntl policy allows unmatched signal change\n");
						ksft_test_result_skip("object fcntl policy allows protected status query\n");
					ksft_test_result_skip("object chdir policy denies protected chdir\n");
					ksft_test_result_skip("object chdir policy allows unmatched chdir\n");
					ksft_test_result_skip("object chdir policy denies preopened fchdir\n");
					ksft_test_result_skip("object chdir policy allows unmatched fchdir\n");
					ksft_test_result_skip("object mount policy denies protected mount target\n");
					ksft_test_result_skip("object mount policy allows unmatched mount target\n");
					ksft_test_result_skip("object mount policy denies protected move_mount target\n");
					ksft_test_result_skip("object mount policy allows unmatched move_mount target\n");
					ksft_test_result_skip("object mount-source policy denies protected move_mount source\n");
					ksft_test_result_skip("object mount-source policy allows unmatched move_mount source\n");
					ksft_test_result_skip("object umount policy denies protected mount\n");
					ksft_test_result_skip("object umount policy allows unmatched mount\n");
				ksft_test_result_skip("object find policy hides protected readdir entry\n");
				ksft_test_result_skip("object find tree policy hides nested readdir entry\n");
					ksft_test_result_skip("object tree policy denies nested read\n");
					ksft_test_result_skip("object tree policy denies nested write\n");
					ksft_test_result_skip("object tree policy denies nested delete\n");
					ksft_test_result_skip("object tree policy denies nested rmdir\n");
					ksft_test_result_skip("object tree policy denies nested create\n");
					ksft_test_result_skip("object tree policy denies nested attr\n");
				ksft_test_result_skip("object tree policy denies nested xattr\n");
				ksft_test_result_skip("object tree policy denies nested access probe\n");
				ksft_test_result_skip("object tree policy denies nested stat\n");
				ksft_test_result_skip("object tree policy denies nested readdir\n");
				ksft_test_result_skip("object tree policy denies nested O_PATH lookup\n");
				ksft_test_result_skip("object tree ops policy denies nested exec\n");
				ksft_test_result_skip("object tree ops policy denies nested hardlink source\n");
				ksft_test_result_skip("object tree ops policy denies nested ioctl\n");
				ksft_test_result_skip("object tree ops policy denies nested lock\n");
				ksft_test_result_skip("object tree ops policy denies nested inotify watch\n");
				ksft_test_result_skip("object tree ops policy denies nested fd duplication\n");
				ksft_test_result_skip("object tree ops policy denies nested chdir\n");
					ksft_test_result_skip("object tree ops policy denies preopened nested fchdir\n");
					ksft_test_result_skip("object tree ops policy denies nested truncate\n");
					ksft_test_result_skip("object tree ops policy denies preopened nested ftruncate\n");
					ksft_test_result_skip("object tree ops policy denies nested source rename\n");
					ksft_test_result_skip("object tree ops policy denies nested socket connect\n");
					ksft_test_result_skip("object tree ops policy allows unmatched exec\n");
					ksft_test_result_skip("object tree ops policy allows unmatched hardlink source\n");
					ksft_test_result_skip("object tree ops policy allows unmatched ioctl\n");
					ksft_test_result_skip("object tree ops policy allows unmatched lock\n");
					ksft_test_result_skip("object tree ops policy allows unmatched inotify watch\n");
					ksft_test_result_skip("object tree ops policy allows unmatched fd duplication\n");
					ksft_test_result_skip("object tree ops policy allows unmatched chdir\n");
					ksft_test_result_skip("object tree ops policy allows preopened unmatched fchdir\n");
					ksft_test_result_skip("object tree ops policy allows unmatched truncate\n");
					ksft_test_result_skip("object tree ops policy allows preopened unmatched ftruncate\n");
					ksft_test_result_skip("object tree ops policy allows unmatched source rename\n");
					ksft_test_result_skip("object tree ops policy allows unmatched socket connect\n");
				ksft_test_result_skip("object tree receive policy denies nested fd receive\n");
				ksft_test_result_skip("object tree mount policy denies nested mount target\n");
				ksft_test_result_skip("object tree mount policy denies nested move_mount target\n");
				ksft_test_result_skip("object tree umount policy denies mounted tree root\n");
				ksft_test_result_skip("object tree receive policy allows unmatched fd receive\n");
				ksft_test_result_skip("object tree mount policy allows unmatched mount target\n");
				ksft_test_result_skip("object tree mount policy allows unmatched move_mount target\n");
				ksft_test_result_skip("object tree umount policy allows unmatched mounted target\n");
				ksft_test_result_skip("object tree metadata policy denies nested chmod\n");
				ksft_test_result_skip("object tree metadata policy denies nested chown\n");
				ksft_test_result_skip("object tree metadata policy denies nested timestamp change\n");
				ksft_test_result_skip("object tree metadata policy denies nested setxattr\n");
				ksft_test_result_skip("object tree metadata policy denies nested removexattr\n");
				ksft_test_result_skip("object tree metadata policy denies nested getxattr\n");
				ksft_test_result_skip("object tree metadata policy denies nested listxattr\n");
				ksft_test_result_skip("object tree IPC policy denies nested socket bind\n");
				ksft_test_result_skip("object tree IPC policy denies nested socket listen\n");
				ksft_test_result_skip("object tree IPC policy denies nested socket accept\n");
				ksft_test_result_skip("object tree IPC policy denies nested datagram send\n");
				ksft_test_result_skip("object tree IPC policy denies preconnected nested datagram send\n");
				ksft_test_result_skip("object tree IPC policy denies nested datagram receive\n");
				ksft_test_result_skip("object tree split policy denies nested file create\n");
				ksft_test_result_skip("object tree split policy denies nested directory create\n");
				ksft_test_result_skip("object tree split policy denies nested FIFO create\n");
				ksft_test_result_skip("object tree split policy denies nested symlink create\n");
				ksft_test_result_skip("object tree split policy denies nested file unlink\n");
				ksft_test_result_skip("object tree split policy denies nested directory rmdir\n");
				ksft_test_result_skip("object tree append-only policy allows nested append write\n");
				ksft_test_result_skip("object tree append-only policy denies nested rewrite open\n");
				ksft_test_result_skip("object tree policy allows unmatched nested write\n");
				ksft_test_result_skip("hardening events report object find denial\n");
				ksft_test_result_skip("hardening events report object ioctl denial\n");
				ksft_test_result_skip("hardening events report object lock denial\n");
					ksft_test_result_skip("hardening events report object watch denial\n");
					ksft_test_result_skip("hardening events report object xattr denial\n");
					ksft_test_result_skip("hardening events report object receive denial\n");
					ksft_test_result_skip("hardening events report object fcntl denial\n");
					ksft_test_result_skip("hardening events report object chdir denial\n");
					ksft_test_result_skip("hardening events report object mount denial\n");
					ksft_test_result_skip("hardening events report object mount-source denial\n");
					ksft_test_result_skip("event decoder names object mount-source denial\n");
			ksft_test_result_skip("hardening events report object umount denial\n");
				ksft_test_result_skip("hardening events report object truncate denial\n");
				ksft_test_result_skip("hardening events report object rename denial\n");
				ksft_test_result_skip("hardening events report object rename-target denial\n");
				ksft_test_result_skip("event decoder names object rename-target denial\n");
				ksft_test_result_skip("hardening events report object link-target denial\n");
				ksft_test_result_skip("event decoder names object link-target denial\n");
				ksft_test_result_skip("hardening events report object unix-connect denial\n");
				ksft_test_result_skip("hardening events report object unix-bind denial\n");
				ksft_test_result_skip("hardening events report object unix-listen denial\n");
				ksft_test_result_skip("hardening events report object unix-accept denial\n");
				ksft_test_result_skip("hardening events report object unix-send denial\n");
				ksft_test_result_skip("hardening events report object unix-recv denial\n");
				ksft_test_result_skip("hardening events report object chmod denial\n");
			ksft_test_result_skip("hardening events report object chown denial\n");
			ksft_test_result_skip("hardening events report object utime denial\n");
			ksft_test_result_skip("hardening events report object setid denial\n");
			ksft_test_result_skip("event decoder names object setid denial\n");
			ksft_test_result_skip("hardening events report object setxattr denial\n");
			ksft_test_result_skip("hardening events report object removexattr denial\n");
			ksft_test_result_skip("hardening events report object creat denial\n");
			ksft_test_result_skip("hardening events report object mkdir denial\n");
			ksft_test_result_skip("hardening events report object mknod denial\n");
			ksft_test_result_skip("hardening events report object symlink denial\n");
			ksft_test_result_skip("hardening events report object unlink denial\n");
			ksft_test_result_skip("hardening events report object rmdir denial\n");
			ksft_test_result_skip("object-write hardening policy rollback succeeds\n");
			ksft_test_result_skip("socket hardening policy stages\n");
		ksft_test_result_skip("socket hardening policy commits\n");
		ksft_test_result_skip("socket policy denies outbound connect without authority\n");
		ksft_test_result_skip("socket policy denies IPv6 outbound connect without authority\n");
		ksft_test_result_skip("socket policy denies UDP outbound connect without authority\n");
		ksft_test_result_skip("socket policy denies IPv6 UDP outbound connect without authority\n");
		ksft_test_result_skip("socket policy denies server bind without authority\n");
		ksft_test_result_skip("socket policy denies IPv6 server bind without authority\n");
		ksft_test_result_skip("socket policy denies UDP server bind without authority\n");
		ksft_test_result_skip("socket policy denies IPv6 UDP server bind without authority\n");
		ksft_test_result_skip("socket policy denies module autoload without authority\n");
		ksft_test_result_skip("hardening events report socket create denial\n");
		ksft_test_result_skip("hardening events report socket connect denial\n");
		ksft_test_result_skip("hardening events report socket connect endpoint object\n");
		ksft_test_result_skip("hardening events report IPv6 socket connect endpoint object\n");
		ksft_test_result_skip("hardening events report UDP socket connect endpoint object\n");
		ksft_test_result_skip("hardening events report IPv6 UDP socket connect endpoint object\n");
		ksft_test_result_skip("hardening events report socket server denial\n");
		ksft_test_result_skip("hardening events report socket server endpoint object\n");
		ksft_test_result_skip("hardening events report IPv6 socket server endpoint object\n");
		ksft_test_result_skip("hardening events report UDP socket server endpoint object\n");
		ksft_test_result_skip("hardening events report IPv6 UDP socket server endpoint object\n");
		ksft_test_result_skip("hardening events report module autoload denial\n");
		ksft_test_result_skip("socket hardening policy rollback succeeds\n");
		ksft_test_result_skip("block-device admin hardening policy stages\n");
		ksft_test_result_skip("block-device admin hardening policy commits\n");
		ksft_test_result_skip("block-device profile allows raw block-device query\n");
		ksft_test_result_skip("block-device profile denies admin ioctl without authority\n");
		ksft_test_result_skip("hardening events report block-device admin denial\n");
		ksft_test_result_skip("block-device admin hardening policy rollback succeeds\n");
		ksft_test_result_skip("JIT hardening policy stages\n");
		ksft_test_result_skip("JIT hardening policy commits\n");
		ksft_test_result_skip("JIT profile allows private anonymous exec-after-write\n");
		ksft_test_result_skip("JIT profile denies file-backed exec-after-write\n");
		ksft_test_result_skip("JIT hardening policy rollback succeeds\n");
		ksft_test_result_skip("exec-stack compatibility policy stages\n");
		ksft_test_result_skip("exec-stack compatibility policy commits\n");
		ksft_test_result_skip("exec-stack compatibility allows executable-stack ELF\n");
		ksft_test_result_skip("exec-stack compatibility policy rollback succeeds\n");
		ksft_test_result_skip("textrel compatibility policy stages\n");
		ksft_test_result_skip("textrel compatibility policy commits\n");
		ksft_test_result_skip("textrel compatibility allows text relocation mprotect\n");
		ksft_test_result_skip("textrel compatibility policy rollback succeeds\n");
		ksft_test_result_skip("RELRO compatibility policy stages\n");
		ksft_test_result_skip("RELRO compatibility policy commits\n");
		ksft_test_result_skip("RELRO compatibility allows write restoration\n");
		ksft_test_result_skip("RELRO compatibility policy rollback succeeds\n");
		ksft_test_result_skip("KILL_MEMORY hardening policy stages\n");
		ksft_test_result_skip("KILL_MEMORY hardening policy commits\n");
		ksft_test_result_skip("KILL_MEMORY response kills denied W+X task\n");
		ksft_test_result_skip("KILL_MEMORY hardening policy rollback succeeds\n");
		ksft_test_result_skip("hardening events report kill response flag\n");
		ksft_test_result_skip("hardening events report untrusted module denial\n");
		ksft_test_result_skip("hardening events report restricted ptrace denial\n");
		ksft_test_result_skip("hardening events report restricted kexec denial\n");
		ksft_test_result_skip("hardening events report restricted BPF denial\n");
			ksft_test_result_skip("hardening events report restricted mount denial\n");
			ksft_test_result_skip("hardening events report restricted raw I/O denial\n");
			ksft_test_result_skip("hardening events report restricted kernel log write denial\n");
			ksft_test_result_skip("hardening events report restricted namespace denial\n");
		ksft_test_result_skip("hardening events report restricted sysfs denial\n");
		ksft_test_result_skip("hardening events report restricted sysfs read denial\n");
		ksft_test_result_skip("hardening events report restricted proc denial\n");
		ksft_test_result_skip("hardening events report restricted signal denial\n");
		ksft_test_result_skip("events report restricted debugfs denial\n");
		ksft_test_result_skip("events report restricted time-change denial\n");
		ksft_test_result_skip("events report restricted resource denial\n");
		ksft_test_result_skip("events report restricted block-device denial\n");
		ksft_test_result_skip("hardening events report untrusted exec denial\n");
		ksft_test_result_skip("hardening events report untrusted executable mmap denial\n");
		ksft_test_result_skip("hardening events report untrusted executable mprotect denial\n");
		ksft_test_result_skip("hardening events report untrusted firmware denial\n");
		ksft_test_result_skip("hardening events report chroot fchdir denial\n");
		ksft_test_result_skip("hardening events report chroot reentry denial\n");
		ksft_test_result_skip("hardening events report chroot chmod denial\n");
		ksft_test_result_skip("hardening events report chroot mknod denial\n");
		ksft_test_result_skip("hardening events report chroot shmat denial\n");
		ksft_test_result_skip("hardening events report chroot nice denial\n");
		ksft_test_result_skip("hardening events report chroot rename denial\n");
		ksft_test_result_skip("hardening events report chroot abstract UNIX denial\n");
		ksft_test_result_skip("hardening events report chroot capability denial\n");
			ksft_test_result_skip("hardening events report chroot outside-task denial\n");
			ksft_test_result_skip("hardening events report chroot file-handle denial\n");
			ksft_test_result_skip("hardening events report chroot sysctl denial\n");
			ksft_test_result_skip("hardening events report chroot exec audit flag\n");
			ksft_test_result_skip("event decoder names kernel log write denial\n");
			ksft_test_result_skip("hardening events report brute throttle denial\n");
		ksft_test_result_skip("recovery test hardening policy stages\n");
		ksft_test_result_skip("recovery test hardening policy commits\n");
		ksft_test_result_skip("runtime hardening phase can be set\n");
		ksft_test_result_skip("runtime policy binds the refresh test executable\n");
		ksft_test_result_skip("refresh test executable is atomically replaced\n");
		ksft_test_result_skip("stale executable identity loses JIT compatibility\n");
		ksft_test_result_skip("runtime accepts an identical signed policy refresh\n");
		ksft_test_result_skip("policy refresh preserves generation and runtime phase\n");
		ksft_test_result_skip("policy refresh binds the replacement executable\n");
		ksft_test_result_skip("hardening events report allowed policy refresh\n");
		ksft_test_result_skip("runtime rejects a different signed policy refresh\n");
		ksft_test_result_skip("hardening events report policy identity mismatch\n");
		ksft_test_result_skip("runtime rejects an unsigned policy refresh\n");
		ksft_test_result_skip("rejected refresh leaves active executable binding intact\n");
		ksft_test_result_skip("runtime phase rejects signed policy mutation\n");
		ksft_test_result_skip("hardening events report sealed runtime denial\n");
		ksft_test_result_skip("recovery hardening phase can be set\n");
		ksft_test_result_skip("recovery rollback restores previous active generation\n");
		ksft_test_result_skip("hardening events survive recovery transition\n");
		ksft_test_result_skip("recovery phase can reseal runtime\n");
		return;
	}

	broker_commit_result = broker_policy_commit_default();
	report_child_result(broker_commit_result,
			    "admin broker policy commit succeeds");
	broker_rollback_result = broker_commit_result ?
				 broker_commit_result :
				 broker_policy_rollback_to_generation0();
	report_child_result(broker_rollback_result,
			    "admin broker policy rollback succeeds");
	if (!broker_commit_result && broker_rollback_result)
		(void)write_text_file(HDN_ROLLBACK, "1\n");
	broker_denied_result = broker_rollback_result ?
			       broker_rollback_result :
			       broker_policy_unapproved_commit_denied();
	report_child_result(broker_denied_result,
			    "admin broker denies unapproved policy path");
	recovery_unknown_result = broker_denied_result ? broker_denied_result :
				  recovery_action_unknown_denied();
	report_child_result(recovery_unknown_result,
			    "recovery action denies unknown action");
	recovery_unsafe_config_result = recovery_unknown_result ?
					recovery_unknown_result :
					recovery_action_unsafe_config_denied();
	report_child_result(recovery_unsafe_config_result,
			    "recovery action denies unsafe config");
	recovery_rollback_result = recovery_unsafe_config_result ?
				   recovery_unsafe_config_result :
				   recovery_action_policy_rollback_to_generation0();
	report_child_result(recovery_rollback_result,
			    "recovery action policy rollback succeeds");
	recovery_describe_unknown_result = recovery_describe_unknown_denied();
	report_child_result(recovery_describe_unknown_result,
			    "recovery describe denies unknown action");
	recovery_describe_unsafe_config_result = recovery_describe_unknown_result ?
						recovery_describe_unknown_result :
						recovery_describe_unsafe_config_denied();
	report_child_result(recovery_describe_unsafe_config_result,
			    "recovery describe denies unsafe config");
	recovery_describe_result = (recovery_describe_unknown_result ||
				    recovery_describe_unsafe_config_result) ?
				   KSFT_SKIP : recovery_describe_policy_rollback();
	report_child_result(recovery_describe_result,
			    "recovery describe reports approved action metadata");
	recovery_prompt_approve_result = recovery_prompt_test_approve();
	report_child_result(recovery_prompt_approve_result,
			    "recovery prompt approves valid metadata in test mode");
	recovery_prompt_deny_result = recovery_prompt_test_deny();
	report_child_result(recovery_prompt_deny_result,
			    "recovery prompt denies valid metadata in test mode");
	recovery_prompt_no_display_result = recovery_prompt_no_display_denied();
	report_child_result(recovery_prompt_no_display_result,
			    "recovery prompt fails closed without graphical session");
	recovery_session_unknown_result = recovery_describe_result ?
					  recovery_describe_result :
					  recovery_session_unknown_denied();
	report_child_result(recovery_session_unknown_result,
			    "recovery session denies unknown action");
	recovery_session_unsafe_config_result =
		recovery_session_unknown_result ?
		recovery_session_unknown_result :
		recovery_session_unsafe_config_denied();
	report_child_result(recovery_session_unsafe_config_result,
			    "recovery session denies unsafe config");
	recovery_session_confirm_denied_result =
		recovery_session_unsafe_config_result ?
		recovery_session_unsafe_config_result :
		recovery_session_confirm_denied();
	report_child_result(recovery_session_confirm_denied_result,
			    "recovery session denies failed confirmation");
	recovery_session_no_display_result =
		recovery_session_confirm_denied_result ?
		recovery_session_confirm_denied_result :
		recovery_session_no_display_denied();
	report_child_result(recovery_session_no_display_result,
			    "recovery session fails closed without graphical session");
	recovery_session_rollback_result =
		recovery_session_no_display_result ?
		recovery_session_no_display_result :
		recovery_session_policy_rollback_to_generation0();
	report_child_result(recovery_session_rollback_result,
			    "recovery session policy rollback succeeds");
	recovery_portal_unknown_result =
		recovery_session_rollback_result ?
		recovery_session_rollback_result :
		recovery_portal_unknown_denied();
	report_child_result(recovery_portal_unknown_result,
			    "recovery portal denies unknown recovery UI action");
	recovery_portal_unsafe_config_result =
		recovery_portal_unknown_result ?
		recovery_portal_unknown_result :
		recovery_portal_unsafe_config_denied();
	report_child_result(recovery_portal_unsafe_config_result,
			    "recovery portal denies unsafe config");
	recovery_portal_rollback_result =
		recovery_portal_unsafe_config_result ?
		recovery_portal_unsafe_config_result :
		recovery_portal_policy_rollback_to_generation0();
	report_child_result(recovery_portal_rollback_result,
			    "recovery portal policy rollback succeeds");
	recovery_panel_unknown_result =
		recovery_portal_rollback_result ?
		recovery_portal_rollback_result :
		recovery_panel_unknown_denied();
	report_child_result(recovery_panel_unknown_result,
			    "recovery panel denies unknown recovery action");
	recovery_panel_unsafe_config_result =
		recovery_panel_unknown_result ?
		recovery_panel_unknown_result :
		recovery_panel_unsafe_config_denied();
	report_child_result(recovery_panel_unsafe_config_result,
			    "recovery panel denies unsafe config");
	recovery_panel_describe_result =
		recovery_panel_unsafe_config_result ?
		recovery_panel_unsafe_config_result :
		recovery_panel_repair_describe_reports_metadata();
	report_child_result(recovery_panel_describe_result,
			    "recovery panel describes mapped repair action");
	recovery_panel_rollback_result =
		recovery_panel_describe_result ?
		recovery_panel_describe_result :
		recovery_panel_policy_rollback_to_generation0();
	report_child_result(recovery_panel_rollback_result,
			    "recovery panel policy rollback succeeds");
	recovery_ui_unknown_result =
		recovery_panel_rollback_result ?
		recovery_panel_rollback_result :
		recovery_ui_unknown_denied();
	report_child_result(recovery_ui_unknown_result,
			    "recovery UI denies unknown recovery action");
	recovery_ui_unsafe_config_result =
		recovery_ui_unknown_result ?
		recovery_ui_unknown_result :
		recovery_ui_unsafe_config_denied();
	report_child_result(recovery_ui_unsafe_config_result,
			    "recovery UI denies unsafe config");
	recovery_ui_cancel_result =
		recovery_ui_unsafe_config_result ?
		recovery_ui_unsafe_config_result :
		recovery_ui_cancel_denied();
	report_child_result(recovery_ui_cancel_result,
			    "recovery UI denies canceled selection");
	recovery_ui_no_display_result =
		recovery_ui_cancel_result ?
		recovery_ui_cancel_result :
		recovery_ui_no_display_denied();
	report_child_result(recovery_ui_no_display_result,
			    "recovery UI fails closed without graphical session");
	recovery_ui_rollback_result =
		recovery_ui_no_display_result ?
		recovery_ui_no_display_result :
		recovery_ui_policy_rollback_to_generation0();
	report_child_result(recovery_ui_rollback_result,
			    "recovery UI policy rollback succeeds");
	report_child_result(apt_package_hook_invokes_hdn_hook(),
			    "APT package hook invokes hdn package hook");
	report_child_result(pacman_package_hook_invokes_hdn_hook(),
			    "pacman package hook invokes hdn package hook");
	report_child_result(dnf_package_hook_invokes_hdn_hook(),
			    "DNF package hook invokes hdn package hook");
	report_child_result(dnf5_package_hook_invokes_hdn_hook(),
			    "DNF5 package hook invokes hdn package hook");
	report_child_result(image_seal_unit_invokes_hdn_hook(),
			    "image seal unit invokes hdn package hook");
	report_child_result(broker_approval_missing_token_denied(),
			    "admin broker approval token is required when configured");
	report_child_result(broker_approval_unsafe_token_denied(),
			    "admin broker rejects unsafe approval token");
	report_child_result(broker_approval_wrong_intent_denied(),
			    "admin broker rejects approval token for wrong intent");
	report_child_result(broker_approval_expired_token_denied(),
			    "admin broker rejects expired approval token");
	report_child_result(approval_token_issuer_unknown_intent_denied(),
			    "approval token issuer rejects unknown intent");
	report_child_result(approval_token_issuer_creates_valid_token(),
			    "approval token issuer creates broker-valid token");
	report_child_result(broker_approval_valid_token_allows_dry_run(),
			    "admin broker accepts valid approval token for typed intent");
	prompt_describe_unknown_result = prompt_describe_unknown_denied();
	report_child_result(prompt_describe_unknown_result,
			    "prompt describe denies unknown action");
	prompt_describe_unsafe_config_result = prompt_describe_unknown_result ?
					       prompt_describe_unknown_result :
					       prompt_describe_unsafe_config_denied();
	report_child_result(prompt_describe_unsafe_config_result,
			    "prompt describe denies unsafe config");
	prompt_describe_result = (prompt_describe_unknown_result ||
				  prompt_describe_unsafe_config_result) ?
				 KSFT_SKIP : prompt_describe_package_update();
	report_child_result(prompt_describe_result,
			    "prompt describe reports approved action metadata");
	auth_prompt_approve_result = auth_prompt_test_approve();
	report_child_result(auth_prompt_approve_result,
			    "auth prompt approves valid metadata in test mode");
	auth_prompt_deny_result = auth_prompt_test_deny();
	report_child_result(auth_prompt_deny_result,
			    "auth prompt denies valid metadata in test mode");
	auth_prompt_no_display_result = auth_prompt_no_display_denied();
	report_child_result(auth_prompt_no_display_result,
			    "auth prompt fails closed without graphical session");

	ret = write_signed_policy();
	staged = !ret;
	ksft_test_result(staged, "signed hardening policy stages\n");
	ksft_test_result(staged &&
			 securityfs_status_has_line("staged_generation: 1") &&
			 securityfs_status_has_line("staged_policy_sealed: 1"),
			 "signed hardening policy is staged sealed\n");

	ret = staged ? write_text_file(HDN_COMMIT, "1\n") : -EINVAL;
	committed = !ret;
	ksft_test_result(committed, "signed hardening policy commits\n");
	ksft_test_result(committed &&
			 securityfs_status_has_line("policy_loaded: 1") &&
			 securityfs_status_has_line("generation: 1"),
			 "committed hardening policy generation is active\n");
	ksft_test_result(committed &&
			 securityfs_status_has_line("policy_sealed: 1"),
			 "committed hardening policy is sealed\n");
#ifdef __NR_finit_module
	report_child_result(committed ?
			    signed_module_delegation_reaches_loader() : 2,
			    "signed module delegation reaches the normal loader");
#else
	ksft_test_result_skip("signed module delegation reaches the normal loader\n");
#endif
	report_child_result(committed ? product_firmware_delegation_loads() : 2,
			    "product firmware delegation loads packaged firmware");
	report_child_result(committed ? proc_ipaddr_accept_handoff() : 2,
			    "proc ipaddr records accepted TCP peer and child handoff");
	report_child_result(committed ? proc_ipaddr_local_tcp_carry() : 2,
			    "proc ipaddr carries peer across local TCP");
	report_child_result(committed ? proc_ipaddr_unix_stream_carry() : 2,
			    "proc ipaddr carries peer across AF_UNIX stream");
		report_child_result(committed ? proc_memmap_disclosed_by_policy() : 2,
				    "proc memmap disclosure policy exposes target addresses");
		report_child_result(committed ? proc_cmdline_disclosed_by_policy() : 2,
				    "proc disclosure policy exposes target cmdline");
		report_child_result(committed ? proc_environ_disclosed_by_policy() : 2,
				    "proc disclosure policy exposes target environ");
		report_child_result(committed ? proc_auxv_disclosed_by_policy() : 2,
				    "proc disclosure policy exposes target auxv");
		report_child_result(committed ? proc_syscall_disclosed_by_policy() : 2,
				    "proc disclosure policy exposes target syscall metadata");
		report_child_result(committed ? proc_io_disclosed_by_policy() : 2,
				    "proc disclosure policy exposes target io accounting");
			report_child_result(committed ? proc_personality_disclosed_by_policy() : 2,
					    "proc disclosure policy exposes target personality flags");
			report_child_result(committed ?
					    proc_coredump_filter_disclosed_by_policy() : 2,
					    "proc disclosure policy exposes target coredump filter");
				report_child_result(committed ?
						    proc_coredump_filter_write_allowed_by_policy() : 2,
						    "proc disclosure policy allows target coredump filter writes");
				report_child_result(committed ? proc_limits_disclosed_by_policy() : 2,
						    "proc disclosure policy exposes target resource limits");
				report_child_result(committed ? proc_statm_disclosed_by_policy() : 2,
						    "proc disclosure policy exposes target statm accounting");
				report_child_result(committed ? proc_sched_disclosed_by_policy() : 2,
						    "proc disclosure policy exposes target scheduler state");
				report_child_result(committed ? proc_schedstat_disclosed_by_policy() : 2,
						    "proc disclosure policy exposes target scheduler statistics");
				report_child_result(committed ?
						    proc_resource_maps_disclosed_by_policy() : 2,
						    "proc resource-map disclosure policy exposes address ranges");
	report_child_result(committed ?
			    module_helper_path_write_allowed_by_policy() : 2,
			    "module-autoload profile can write modprobe helper path");
	report_child_result(committed ?
			    module_helper_unsafe_path_denied_by_policy() : 2,
			    "module-autoload profile denies unsafe modprobe helper path");
	report_child_result(committed ?
			    setuid_exec_stack_limit_capped() : 2,
			    "setuid exec caps inherited stack resource limit");

#ifdef __NR_finit_module
	report_child_result(committed ? unsigned_finit_module_rejected() : 2,
			    "normal loader rejects unsigned module file");
#else
	ksft_test_result_skip("finit_module syscall number unavailable\n");
#endif

	report_child_result(committed ? ptrace_execute_only_read_denied() : 2,
			    "signed policy denies ptrace execute-only read");
	report_child_result(committed ? proc_mem_execute_only_read_denied() : 2,
			    "signed policy denies proc mem execute-only read");
	ksft_test_result(securityfs_events_contains("reason=29"),
			 "hardening events report ptrace execute-only read denial\n");
	if (committed)
		test_sealed_write_probe_event_logged();
	else
		ksft_test_result_skip(
			"hardening events report sealed data write fault\n");
	report_child_result(committed ? kernel_lockout_probe_blocks_uid() : 2,
			    "kernel lockout probe bans uid and blocks reentry");

	ret = committed ? write_text_file(HDN_ROLLBACK, "1\n") : -EINVAL;
	rolled_back = !ret;
	ksft_test_result(rolled_back,
			 "hardening policy rollback succeeds\n");
	ksft_test_result(rolled_back &&
			 securityfs_status_has_line("generation: 0"),
			 "rollback restores previous active generation\n");

	ret = rolled_back ? write_signed_policy_path(HDN_PROC_DISCLOSE_POLICY) :
			   -EINVAL;
	proc_disclose_staged = !ret;
	ksft_test_result(proc_disclose_staged,
			 "proc-disclose hardening policy stages\n");
	ret = proc_disclose_staged ? write_text_file(HDN_COMMIT, "1\n") :
					     -EINVAL;
	proc_disclose_committed = !ret;
	ksft_test_result(proc_disclose_committed,
			 "proc-disclose hardening policy commits\n");
	report_child_result(proc_disclose_committed ?
			    run_proc_reader("--proc-root-reader") : 2,
			    "proc disclosure permits read-only proc root access");
	report_child_result(proc_disclose_committed ?
			    run_proc_reader("--proc-ptrace-reader") : 2,
			    "proc disclosure does not permit ptrace attach");
	ret = proc_disclose_committed ? write_text_file(HDN_ROLLBACK, "1\n") :
					      -EINVAL;
	proc_disclose_rolled_back = !ret;
	ksft_test_result(proc_disclose_rolled_back,
			 "proc-disclose hardening policy rollback succeeds\n");

	ret = proc_disclose_rolled_back ?
		write_signed_policy_path(HDN_RESTRICTED_POLICY) : -EINVAL;
	restricted_staged = !ret;
	ksft_test_result(restricted_staged,
			 "restricted hardening policy stages\n");
	if (restricted_staged) {
		owner_only_sysfs_setup =
			find_owner_only_sysfs_file(hdn_owner_only_sysfs_path,
						   sizeof(hdn_owner_only_sysfs_path));
		hdn_owner_only_sysfs_path_ready = !owner_only_sysfs_setup;
		if (owner_only_sysfs_setup &&
		    owner_only_sysfs_setup != -ENOENT &&
		    owner_only_sysfs_setup != -ENOTDIR)
			ksft_print_msg("owner-only sysfs discovery failed: %d\n",
				       owner_only_sysfs_setup);

		proc_gid_mount_setup = setup_proc_gid_mount_test();
		if (proc_gid_mount_setup &&
		    proc_gid_mount_setup != KSFT_SKIP)
			ksft_print_msg("proc gid mount setup failed: %d\n",
				       proc_gid_mount_setup);
		proc_gid_mount_ready = !proc_gid_mount_setup;

		ret = setup_tpe_mount_test();
		if (ret)
			ksft_print_msg("TPE mount test setup failed: %d\n", ret);
		tpe_mount_ready = !ret;

		ret = setup_tpe_user_test();
		if (ret)
			ksft_print_msg("TPE user test setup failed: %d\n", ret);
		tpe_user_ready = !ret;
	}

	ret = restricted_staged ? write_text_file(HDN_COMMIT, "1\n") :
				  -EINVAL;
	restricted_committed = !ret;
	ksft_test_result(restricted_committed,
			 "restricted hardening policy commits\n");

	report_child_result(restricted_committed ? ptrace_attach_denied() : 2,
			    "restricted profile denies ptrace attach");
	report_child_result(restricted_committed ? proc_mem_profile_denied() :
			    2,
			    "restricted profile denies proc mem access");
	report_child_result(restricted_committed ?
			    forked_child_result(signal_cross_profile_denied) : 2,
			    "restricted profile denies cross-profile signal");
	report_child_result(restricted_committed ?
			    forked_child_result(signal_direct_child_allowed) : 2,
			    "restricted profile allows direct-child signal");
	report_child_result(restricted_committed ?
			    protected_shm_same_profile_allowed() : 2,
			    "restricted profile allows protected shared memory inside profile");
	report_child_result(restricted_committed ?
			    protected_shm_cross_profile_denied() : 2,
			    "restricted profile denies protected shared memory across profiles");
	report_child_result(restricted_committed ?
			    process_vm_read_cross_profile_denied() : 2,
			    "restricted profile denies process_vm_readv across profiles");
	report_child_result(restricted_committed ?
			    process_vm_write_cross_profile_denied() : 2,
			    "restricted profile denies process_vm_writev across profiles");
	report_child_result(restricted_committed ?
			    process_vm_read_same_profile_allowed() : 2,
			    "restricted profile allows process_vm_readv inside profile");
	report_child_result(restricted_committed ?
			    process_madvise_cross_profile_denied() : 2,
			    "restricted profile denies process_madvise across profiles");
	report_child_result(restricted_committed ?
			    process_mrelease_cross_profile_denied() : 2,
			    "restricted profile denies process_mrelease across profiles");
	report_child_result(restricted_committed ?
			    move_pages_cross_profile_denied() : 2,
			    "restricted profile denies move_pages across profiles");
	report_child_result(restricted_committed ?
			    move_pages_same_profile_allowed() : 2,
			    "restricted profile allows move_pages inside profile");
	report_child_result(restricted_committed ?
			    migrate_pages_cross_profile_denied() : 2,
			    "restricted profile denies migrate_pages across profiles");
	report_child_result(restricted_committed ?
			    pidfd_open_cross_profile_denied() : 2,
			    "restricted profile denies pidfd_open across profiles");
	report_child_result(restricted_committed ?
			    pidfd_info_cross_profile_denied() : 2,
			    "restricted profile denies received pidfd info across profiles");
	report_child_result(restricted_committed ?
			    pidfd_fdinfo_cross_profile_redacted() : 2,
			    "restricted profile redacts received pidfd fdinfo across profiles");
	report_child_result(restricted_committed ?
			    pidfd_getfd_cross_profile_denied() : 2,
			    "restricted profile denies pidfd_getfd across profiles");
	report_child_result(restricted_committed ?
			    pidfd_getfd_same_profile_allowed() : 2,
			    "restricted profile allows pidfd_getfd inside profile");
	report_child_result(restricted_committed ? proc_pid_visibility_denied() :
			    2,
			    "restricted profile hides other-user proc entries");
	report_child_result(restricted_committed ?
			    (proc_gid_mount_ready ?
			     proc_pid_gid_mount_visible() :
			     proc_gid_mount_setup == KSFT_SKIP ? KSFT_SKIP :
			     2) : 2,
			    "restricted profile allows proc gid mount group access");
	if (restricted_committed) {
		report_forked_child_result(proc_pid_visibility_gid_allowed,
					   "restricted profile allows proc task-view group access");
		report_forked_child_result(pidfd_open_proc_task_gid_allowed,
					   "restricted profile allows pidfd_open for task-view group");
		report_child_result(proc_task_directory_modes_restricted(),
				    "proc task directories use task-view group modes");
	} else {
		report_child_result(2,
				    "restricted profile allows proc task-view group access");
		report_child_result(2,
				    "restricted profile allows pidfd_open for task-view group");
		report_child_result(2,
				    "proc task directories use task-view group modes");
	}
	report_child_result(restricted_committed ? kexec_load_denied() : 2,
			    "restricted profile denies kexec load");
	report_child_result(restricted_committed ?
			    bpf_map_create_without_authority_denied() : 2,
			    "restricted profile denies BPF map creation");
	report_child_result(restricted_committed ?
			    bpf_metadata_without_authority_denied() : 2,
			    "restricted profile denies BPF metadata enumeration");
	report_child_result(restricted_committed ? mount_admin_denied() : 2,
			    "restricted profile denies mount administration");
	report_child_result(restricted_committed ? raw_io_device_denied() : 2,
			    "restricted profile denies raw I/O device access");
	report_child_result(restricted_committed ? raw_cpu_msr_device_denied() : 2,
			    "restricted profile denies raw CPU MSR device access");
	report_child_result(restricted_committed ? raw_cpu_cpuid_device_denied() : 2,
			    "restricted profile denies raw CPU CPUID device access");
	if (restricted_committed)
		report_forked_child_result(namespace_admin_denied,
					   "restricted profile denies namespace administration");
	else
		report_child_result(2,
				    "restricted profile denies namespace administration");
	report_child_result(restricted_committed ? open_tree_namespace_denied() :
			    2,
			    "restricted profile denies open_tree namespace");
	report_child_result(restricted_committed ? sysfs_mutation_denied() : 2,
			    "restricted profile denies sysfs mutation");
	report_child_result(restricted_committed ?
			    sysfs_owner_only_read_denied() : 2,
			    "restricted profile denies owner-only sysfs read");
	report_child_result(restricted_committed ?
			    sysfs_owner_only_readdir_hidden() : 2,
			    "restricted profile hides owner-only sysfs entries");
	report_child_result(restricted_committed ? sysfs_sensitive_read_denied() :
			    2,
			    "restricted profile denies sensitive sysfs read");
	report_child_result(restricted_committed ?
			    sysfs_sensitive_readdir_hidden() : 2,
			    "restricted profile hides sensitive sysfs entries");
	report_child_result(restricted_committed ?
			    sysfs_boot_params_read_denied() : 2,
			    "restricted profile denies boot params sysfs read");
	report_child_result(restricted_committed ?
			    sysfs_boot_params_readdir_hidden() : 2,
			    "restricted profile hides boot params sysfs entry");
	report_child_result(restricted_committed ?
			    sysfs_memmap_address_read_denied() : 2,
			    "restricted profile denies firmware memmap address read");
	report_child_result(restricted_committed ?
			    sysfs_memmap_address_readdir_hidden() : 2,
			    "restricted profile hides firmware memmap address entry");
	report_child_result(restricted_committed ?
			    sysfs_memmap_type_read_allowed() : 2,
			    "restricted profile allows firmware memmap type read");
	report_child_result(restricted_committed ?
			    sysfs_memmap_type_readdir_visible() : 2,
			    "restricted profile lists firmware memmap type entry");
	report_child_result(restricted_committed ? proc_kcore_denied() : 2,
			    "restricted profile denies proc disclosure");
	report_child_result(restricted_committed ?
			    proc_memmap_redacted_without_disclosure() : 2,
			    "restricted profile redacts proc memmap addresses");
	report_child_result(restricted_committed ?
			    proc_self_pagemap_allowed_without_disclosure() : 2,
			    "restricted profile preserves self pagemap reads");
	report_child_result(restricted_committed ?
			    proc_pagemap_denied_without_disclosure() : 2,
			    "restricted profile denies cross-process pagemap reads");
		report_child_result(restricted_committed ?
				    proc_kpage_metadata_denied_without_disclosure() : 2,
				    "restricted profile denies global kpage metadata");
		report_child_result(restricted_committed ?
				    proc_cmdline_denied_without_disclosure() : 2,
				    "restricted profile denies cross-process cmdline reads");
		report_child_result(restricted_committed ?
				    proc_environ_denied_without_disclosure() : 2,
				    "restricted profile denies cross-process environ reads");
		report_child_result(restricted_committed ?
				    proc_auxv_denied_without_disclosure() : 2,
				    "restricted profile denies cross-process auxv reads");
		report_child_result(restricted_committed ?
				    proc_syscall_denied_without_disclosure() : 2,
				    "restricted profile denies cross-process syscall reads");
		report_child_result(restricted_committed ?
				    proc_io_denied_without_disclosure() : 2,
				    "restricted profile denies cross-process io accounting reads");
			report_child_result(restricted_committed ?
					    proc_personality_denied_without_disclosure() : 2,
					    "restricted profile denies cross-process personality reads");
			report_child_result(restricted_committed ?
					    proc_coredump_filter_denied_without_disclosure() : 2,
					    "restricted profile denies cross-process coredump filter reads");
				report_child_result(restricted_committed ?
						    proc_coredump_filter_write_denied_without_disclosure() : 2,
						    "restricted profile denies cross-process coredump filter writes");
				report_child_result(restricted_committed ?
						    proc_limits_denied_without_disclosure() : 2,
						    "restricted profile denies cross-process resource-limit reads");
				report_child_result(restricted_committed ?
						    proc_statm_denied_without_disclosure() : 2,
						    "restricted profile denies cross-process statm reads");
				report_child_result(restricted_committed ?
						    proc_sched_denied_without_disclosure() : 2,
						    "restricted profile denies cross-process scheduler-state reads");
				report_child_result(restricted_committed ?
						    proc_schedstat_denied_without_disclosure() : 2,
						    "restricted profile denies cross-process scheduler-statistic reads");
				report_child_result(restricted_committed ?
						    proc_resource_maps_redacted_without_disclosure() : 2,
						    "restricted profile redacts proc resource-map addresses");
	report_child_result(restricted_committed ?
			    proc_vmallocinfo_symbols_hidden() : 2,
			    "restricted profile redacts vmalloc caller symbols");
		report_child_result(restricted_committed ?
				    module_helper_path_write_without_authority_denied() : 2,
				    "restricted profile denies modprobe helper path write");
		report_child_result(restricted_committed ?
				    kernel_log_write_without_authority_denied() : 2,
				    "restricted profile denies kernel log write");
		report_child_result(restricted_committed ?
				    proc_kallsyms_symbols_hidden() : 2,
				    "restricted profile hides kallsyms symbols");
	report_child_result(restricted_committed ?
			    proc_modules_symbol_address_hidden() : 2,
			    "restricted profile hides module base addresses");
	report_child_result(restricted_committed ? debugfs_access_denied() : 2,
			    "restricted profile denies debugfs access");
	report_child_result(restricted_committed ? tracefs_access_denied() : 2,
			    "restricted profile denies tracefs access");
	report_child_result(restricted_committed ? untrusted_exec_denied() : 2,
			    "restricted profile denies untrusted executable path");
	report_child_result(restricted_committed && tpe_mount_ready ?
			    untrusted_mountpoint_exec_denied() : 2,
				    "restricted TPE denies untrusted mountpoint");
	report_child_result(restricted_committed && tpe_user_ready ?
			    untrusted_user_exec_denied() : 2,
			    "restricted profile TPE denies non-root-owned exec directory");
	report_child_result(restricted_committed && tpe_user_ready ?
			    untrusted_user_exec_mmap_denied() : 2,
			    "restricted profile TPE denies executable mmap from non-root-owned directory");
	report_child_result(restricted_committed && tpe_user_ready ?
			    untrusted_user_exec_mprotect_denied() : 2,
			    "restricted profile TPE denies executable mprotect from non-root-owned directory");
	report_child_result(restricted_committed ?
			    setuid_exec_privileged_profile() : 2,
			    "restricted setuid exec enters privileged profile");
	report_child_result(restricted_committed ?
			    filecap_exec_privileged_profile() : 2,
			    "restricted filecap exec enters privileged profile");
	report_child_result(restricted_committed ?
			    setuid_exec_forces_spectre_mitigations() : 2,
			    "setuid exec force-disables user-controllable speculation controls");
	report_child_result(restricted_committed ?
			    setuid_exec_oversize_env_denied() : 2,
			    "setuid exec rejects oversized argv/env stack");
	if (restricted_committed) {
		report_forked_child_result(chroot_fchdir_escape_denied,
					   "restricted chroot denies fchdir escape");
		cleanup_chroot_test_dirs();
		report_forked_child_result(chroot_reentry_denied,
					   "restricted chroot denies repeated chroot");
		cleanup_chroot_test_dirs();
		report_forked_child_result(chroot_chmod_denied,
					   "restricted chroot denies chmod");
		cleanup_chroot_test_dirs();
		report_forked_child_result(chroot_mknod_denied,
					   "restricted chroot denies device mknod");
		cleanup_chroot_test_dirs();
		report_forked_child_result(chroot_shmat_denied,
					   "restricted chroot denies shared memory attach");
		cleanup_chroot_test_dirs();
		report_forked_child_result(chroot_nice_denied,
					   "restricted chroot denies priority increase");
		cleanup_chroot_test_dirs();
		report_forked_child_result(chroot_bad_rename_denied,
					   "restricted chroot denies bad directory rename");
		cleanup_chroot_test_dirs();
		report_forked_child_result(chroot_abstract_unix_denied,
					   "restricted chroot denies abstract UNIX socket escape");
		cleanup_chroot_test_dirs();
		report_forked_child_result(chroot_capability_denied,
					   "restricted chroot denies privileged capability use");
		cleanup_chroot_test_dirs();
		report_forked_child_result(chroot_findtask_proc_hidden,
					   "restricted chroot hides outside proc task");
		cleanup_chroot_test_dirs();
		report_forked_child_result(chroot_findtask_signal_denied,
					   "restricted chroot denies outside task signal");
		cleanup_chroot_test_dirs();
		report_forked_child_result(chroot_file_handle_denied,
					   "restricted chroot denies file-handle open");
		cleanup_chroot_test_dirs();
		report_forked_child_result(chroot_sysctl_denied,
					   "restricted chroot denies sysctl write");
		cleanup_chroot_test_dirs();
		reset_audit_flood_buckets_for_test();
		report_forked_child_result(chroot_exec_audit_flagged,
					   "restricted chroot exec audit is flagged");
		ksft_test_result(securityfs_events_line_contains_timeout(
					 "authority=1 transition=1 action=3",
					 "flags=0x2", 5000),
				 "hardening events report chroot exec audit flag\n");
		cleanup_chroot_test_dirs();
		report_child_result(socket_create_nonlocal_denied(),
				    "restricted profile denies non-local socket creation");
		report_child_result(socket_create_local_allowed(),
				    "restricted profile allows local socket creation");
		report_child_result(usb_hotplug_without_authority_denied(),
				    "restricted profile denies runtime USB hotplug");
		report_child_result(usb_monitor_without_authority_denied(),
				    "restricted profile denies USB monitor capture");
		test_securityfs_events_contains("authority=78",
						"hardening events report USB monitor denial");
		report_child_result(time_change_without_authority_denied(),
				    "restricted profile denies system time change");
		report_forked_child_result(resource_limit_without_authority_denied,
					   "restricted resource-limit hard raise denied");
		report_forked_child_result(resource_profile_soft_cap_denied,
					   "restricted profile resource soft ceiling denied");
		report_forked_child_result(resource_profile_hard_cap_denied,
					   "restricted profile resource hard ceiling denied");
		report_forked_child_result(block_device_open_without_authority_denied,
					   "restricted raw block-device access denied");
		} else {
			report_child_result(2,
					    "restricted chroot denies fchdir escape");
			report_child_result(2,
					    "restricted chroot denies repeated chroot");
			report_child_result(2,
					    "restricted chroot denies chmod");
			report_child_result(2,
					    "restricted chroot denies device mknod");
			report_child_result(2,
					    "restricted chroot denies shared memory attach");
			report_child_result(2,
					    "restricted chroot denies priority increase");
			report_child_result(2,
					    "restricted chroot denies bad directory rename");
			report_child_result(2,
					    "restricted chroot denies abstract UNIX socket escape");
			report_child_result(2,
					    "restricted chroot denies privileged capability use");
			report_child_result(2,
					    "restricted chroot hides outside proc task");
			report_child_result(2,
					    "restricted chroot denies outside task signal");
			report_child_result(2,
					    "restricted chroot denies file-handle open");
			report_child_result(2,
					    "restricted chroot denies sysctl write");
			report_child_result(2,
					    "restricted profile denies non-local socket creation");
			report_child_result(2,
					    "restricted profile allows local socket creation");
			report_child_result(2,
					    "restricted profile denies runtime USB hotplug");
			report_child_result(2,
					    "restricted profile denies USB monitor capture");
			report_child_result(2,
					    "restricted profile denies system time change");
			report_child_result(2,
					    "restricted profile denies resource-limit hard raise");
			report_child_result(2,
					    "restricted profile resource soft ceiling denied");
			report_child_result(2,
					    "restricted profile resource hard ceiling denied");
			report_child_result(2,
					    "restricted profile denies raw block-device access");
		}

	ret = restricted_committed ? write_text_file(HDN_ROLLBACK, "1\n") :
				    -EINVAL;
	restricted_rolled_back = !ret;
	ksft_test_result(restricted_rolled_back,
			 "restricted hardening policy rollback succeeds\n");
	ksft_test_result(restricted_rolled_back &&
			 securityfs_status_has_line("generation: 0"),
			 "restricted rollback restores previous active generation\n");
	if (tpe_mount_ready)
		cleanup_tpe_mount_test();
	if (tpe_user_ready)
		cleanup_tpe_user_test();
	if (proc_gid_mount_ready)
		cleanup_proc_gid_mount_test();

	ret = install_kprobe_fixture();
	ksft_test_result(ret == 0 || ret == KSFT_SKIP,
			 "trace-symbol kprobe fixture installs\n");
	if (ret == KSFT_SKIP)
		hdn_trace_symbol_kprobe_installed = false;

	ret = write_signed_policy_path(HDN_TRACE_SYMBOL_POLICY);
	trace_symbol_staged = !ret;
	ksft_test_result(trace_symbol_staged,
			 "trace-symbol hardening policy stages\n");

	ret = trace_symbol_staged ? write_text_file(HDN_COMMIT, "1\n") :
				    -EINVAL;
	trace_symbol_committed = !ret;
	ksft_test_result(trace_symbol_committed,
			 "trace-symbol hardening policy commits\n");

	report_child_result(trace_symbol_committed ?
			    tracefs_available_symbols_denied() : 2,
			    "trace-symbol policy denies ftrace symbol listing");
	report_child_result(trace_symbol_committed ?
			    tracefs_kprobe_symbol_lookup_denied() : 2,
			    "trace-symbol policy denies kprobe symbol lookup");
	report_child_result(trace_symbol_committed ?
			    kprobe_list_symbols_hidden() : 2,
			    "trace-symbol policy redacts kprobe list symbols");
	report_child_result(trace_symbol_committed ?
			    kprobe_blacklist_symbols_hidden() : 2,
			    "trace-symbol policy redacts symbolic pointer formatting");
	report_child_result(trace_symbol_committed ?
			    proc_net_ptype_symbols_hidden() : 2,
			    "trace-symbol policy redacts proc net packet handler symbols");
	report_child_result(trace_symbol_committed ?
			    proc_timer_list_symbols_hidden() : 2,
			    "trace-symbol policy redacts proc timer callback symbols");
	report_child_result(trace_symbol_committed ?
			    bpf_kallsyms_lookup_without_disclosure_denied() : 2,
			    "trace-symbol policy denies BPF kallsyms helper lookup");
	report_child_result(trace_symbol_committed ?
			    bpf_pseudo_btf_id_without_disclosure_denied() : 2,
			    "trace-symbol policy denies BPF pseudo-BTF symbol lookup");

	ret = trace_symbol_committed ? write_text_file(HDN_ROLLBACK, "1\n") :
				       -EINVAL;
	trace_symbol_rolled_back = !ret;
	ksft_test_result(trace_symbol_rolled_back,
			 "trace-symbol hardening policy rollback succeeds\n");
	if (trace_symbol_rolled_back)
		cleanup_numeric_kprobe_fixture();

	ret = write_signed_policy_path(HDN_CHROOT_MOUNT_POLICY);
	chroot_mount_staged = !ret;
	ksft_test_result(chroot_mount_staged,
			 "chroot-mount hardening policy stages\n");

	ret = chroot_mount_staged ? write_text_file(HDN_COMMIT, "1\n") :
				    -EINVAL;
	chroot_mount_committed = !ret;
	ksft_test_result(chroot_mount_committed,
			 "chroot-mount hardening policy commits\n");

	report_child_result(chroot_mount_committed ? mount_admin_allowed() : 2,
			    "chroot-mount profile allows mount outside chroot");
	if (chroot_mount_committed) {
		report_forked_child_result(chroot_mount_denied,
					   "contained chroot denies mount despite mount authority");
		cleanup_chroot_test_dirs();
	} else {
		report_child_result(2,
				    "contained chroot denies mount despite mount authority");
	}

	ret = chroot_mount_committed ? write_text_file(HDN_ROLLBACK, "1\n") :
				       -EINVAL;
	chroot_mount_rolled_back = !ret;
	ksft_test_result(chroot_mount_rolled_back,
			 "chroot-mount hardening policy rollback succeeds\n");
	test_securityfs_events_line_contains("authority=21 transition=11",
					     "reason=40",
					     "hardening events report chroot mount denial");
	report_child_result(event_decoder_finds_chroot_mount_denial(),
			    "event decoder names chroot mount denial reason");

	ret = write_signed_policy_path(HDN_CRED_DENY_POLICY);
	cred_staged = !ret;
	ksft_test_result(cred_staged,
			 "credential-deny hardening policy stages\n");

	ret = cred_staged ? write_text_file(HDN_COMMIT, "1\n") : -EINVAL;
	cred_committed = !ret;
	ksft_test_result(cred_committed,
			 "credential-deny hardening policy commits\n");

	report_child_result(cred_committed ?
			    setuid_exec_cred_change_denied() : 2,
			    "target profile without CRED_CHANGE denies setuid exec");
	report_child_result(cred_committed ?
			    filecap_exec_cred_change_denied() : 2,
			    "target profile without CRED_CHANGE denies filecap exec");

	ret = cred_committed ? write_text_file(HDN_ROLLBACK, "1\n") :
			       -EINVAL;
	cred_rolled_back = !ret;
	ksft_test_result(cred_rolled_back,
			 "credential-deny hardening policy rollback succeeds\n");

	ret = write_signed_policy_path(HDN_PRIVEXEC_DENY_POLICY);
	privexec_staged = !ret;
	ksft_test_result(privexec_staged,
			 "privexec-deny hardening policy stages\n");

	ret = privexec_staged ? write_text_file(HDN_COMMIT, "1\n") :
				-EINVAL;
	privexec_committed = !ret;
	ksft_test_result(privexec_committed,
			 "privexec-deny hardening policy commits\n");

	report_child_result(privexec_committed ?
			    setuid_exec_cred_change_denied() : 2,
			    "unprivileged setuid exec is denied even with CRED_CHANGE");
	report_child_result(privexec_committed ?
			    filecap_exec_cred_change_denied() : 2,
			    "unprivileged filecap exec is denied even with CRED_CHANGE");
	test_securityfs_events_contains("reason=28",
					"events report unprivileged privexec denial");

	ret = privexec_committed ? write_text_file(HDN_ROLLBACK, "1\n") :
				   -EINVAL;
	privexec_rolled_back = !ret;
	ksft_test_result(privexec_rolled_back,
			 "privexec-deny hardening policy rollback succeeds\n");

	report_child_result(privexec_rolled_back ?
			    setuid_exec_throttled_after_crashes() : 2,
			    "privileged exec crash throttle denies retry");
	report_child_result(privexec_rolled_back ?
			    daemon_brute_fork_delayed() : 2,
			    "daemon brute throttle delays fork and audits");
	report_child_result(privexec_rolled_back ?
			    privileged_descendant_coredump_blocked() : 2,
			    "privileged-descendant SIGXFSZ coredump is blocked");

	ret = write_signed_policy_path(HDN_IDENTITY_POLICY);
	identity_staged = !ret;
	ksft_test_result(identity_staged,
			 "identity hardening policy stages\n");

	ret = identity_staged ? write_text_file(HDN_COMMIT, "1\n") :
				-EINVAL;
	identity_committed = !ret;
	ksft_test_result(identity_committed,
			 "identity hardening policy commits\n");

	report_child_result(identity_committed ?
			    identity_binary_profile_selected() : 2,
			    "identity binary exec enters matched profile");
	report_child_result(identity_committed ?
			    identity_binary_profile_survives_credential_drop() : 2,
			    "identity exec profile survives credential drop");
	report_child_result(identity_committed ?
			    identity_unmatched_copy_defaults() : 2,
			    "identity unmatched copy enters default profile");
	report_child_result(identity_committed ?
			    identity_script_profile_selected() : 2,
			    "identity script enters interpreter-chain profile");
	report_child_result(identity_committed ?
			    identity_inherit_profile_selected() : 2,
			    "identity inherit exec preserves caller profile");
	report_child_result(identity_committed ?
			    identity_unmatched_exec_inherits_profile() : 2,
			    "identity profile retains unmatched child exec");
	report_child_result(identity_committed ?
			    identity_parent_inherit_profile_selected() : 2,
			    "identity parent inherit exec preserves matched caller profile");
	report_child_result(identity_committed ?
			    identity_parent_inherit_unmatched_defaults() : 2,
			    "identity parent inherit rule ignores unmatched caller profile");
	report_child_result(identity_committed ?
			    identity_replaced_path_defaults() : 2,
			    "identity replaced trusted path enters default profile");

	ret = identity_committed ? write_text_file(HDN_ROLLBACK, "1\n") :
				   -EINVAL;
	identity_rolled_back = !ret;
	ksft_test_result(identity_rolled_back,
			 "identity hardening policy rollback succeeds\n");

	ret = write_signed_policy_path(HDN_MODULE_PATH_POLICY);
	module_path_staged = !ret;
	ksft_test_result(module_path_staged,
			 "module-path hardening policy stages\n");

	ret = module_path_staged ? write_text_file(HDN_COMMIT, "1\n") :
				   -EINVAL;
	module_path_committed = !ret;
	ksft_test_result(module_path_committed,
			 "module-path hardening policy commits\n");

#ifdef __NR_finit_module
	report_child_result(module_path_committed ?
			    known_module_path_reaches_loader() : 2,
			    "trusted module path reaches loader");
	report_child_result(module_path_committed ?
			    replaced_module_path_denied() : 2,
			    "replaced trusted module path is denied");
#else
	ksft_test_result_skip("trusted module path reaches loader\n");
	ksft_test_result_skip("replaced trusted module path is denied\n");
#endif

	ret = module_path_committed ? write_text_file(HDN_ROLLBACK, "1\n") :
				      -EINVAL;
	module_path_rolled_back = !ret;
	ksft_test_result(module_path_rolled_back,
			 "module-path hardening policy rollback succeeds\n");

	ret = write_signed_policy_path(HDN_FIRMWARE_POLICY);
	firmware_staged = !ret;
	ksft_test_result(firmware_staged,
			 "firmware hardening policy stages\n");

	ret = firmware_staged ? write_text_file(HDN_COMMIT, "1\n") :
				-EINVAL;
	firmware_committed = !ret;
	ksft_test_result(firmware_committed,
			 "firmware hardening policy commits\n");

	report_child_result(firmware_committed ?
			    trusted_firmware_name_loads() : 2,
			    "trusted firmware name loads");
	report_child_result(firmware_committed ?
			    untrusted_firmware_name_denied() : 2,
			    "untrusted firmware name is denied");

	ret = firmware_committed ? write_text_file(HDN_ROLLBACK, "1\n") :
				   -EINVAL;
	firmware_rolled_back = !ret;
	ksft_test_result(firmware_rolled_back,
			 "firmware hardening policy rollback succeeds\n");

	ret = write_signed_policy_path(HDN_MOUNT_POLICY);
	mount_policy_staged = !ret;
	ksft_test_result(mount_policy_staged,
			 "mount hardening policy stages\n");

	ret = mount_policy_staged ? write_text_file(HDN_COMMIT, "1\n") :
				    -EINVAL;
	mount_policy_committed = !ret;
	ksft_test_result(mount_policy_committed,
			 "mount hardening policy commits\n");

	report_child_result(mount_policy_committed ?
			    fuse_mount_without_authority_denied() : 2,
			    "mount policy denies FUSE mount without authority");
	report_child_result(mount_policy_committed ?
			    rofs_remount_without_authority_denied() : 2,
			    "mount policy denies read-only remount relaxation");
	report_child_result(mount_policy_committed ?
			    rofs_mount_setattr_without_authority_denied() : 2,
			    "mount policy denies read-only mount_setattr relaxation");
	test_securityfs_events_contains("authority=25",
					"hardening events report FUSE mount denial");
	test_securityfs_events_contains("authority=26",
					"hardening events report ROFS relaxation denial");

	ret = mount_policy_committed ? write_text_file(HDN_ROLLBACK, "1\n") :
				       -EINVAL;
	mount_policy_rolled_back = !ret;
	ksft_test_result(mount_policy_rolled_back,
			 "mount hardening policy rollback succeeds\n");

	product_rofs_mount_setup = mount_policy_rolled_back ?
				   prepare_product_rofs_mount() : 2;
	product_rofs_broker_apply_mount_setup = !product_rofs_mount_setup ?
		prepare_product_rofs_mount_path(HDN_PRODUCT_ROFS_BROKER_DIR,
						HDN_PRODUCT_ROFS_BROKER_SENTINEL) :
		product_rofs_mount_setup;
	product_rofs_image_seal_mount_setup = !product_rofs_mount_setup ?
		prepare_product_rofs_mount_path(HDN_IMAGE_SEAL_DIR,
						HDN_IMAGE_SEAL_SENTINEL) :
		product_rofs_mount_setup;
	product_rofs_optional_mount_setup = !product_rofs_mount_setup ?
		prepare_product_rofs_mount_path(HDN_ROFS_APPLY_OPTIONAL_DIR,
						HDN_ROFS_APPLY_OPTIONAL_SENTINEL) :
		product_rofs_mount_setup;

	ret = write_signed_policy_path(HDN_MOUNT_RO_POLICY);
	mount_ro_policy_staged = !ret;
	ksft_test_result(mount_ro_policy_staged,
			 "read-only mount hardening policy stages\n");

	ret = mount_ro_policy_staged ? write_text_file(HDN_COMMIT, "1\n") :
				       -EINVAL;
	mount_ro_policy_committed = !ret;
	ksft_test_result(mount_ro_policy_committed,
			 "read-only mount hardening policy commits\n");

	report_child_result(mount_ro_policy_committed ?
			    writable_mount_without_rofs_relax_denied() : 2,
			    "read-only mount policy denies writable mount");
	report_child_result(mount_ro_policy_committed ?
			    readonly_mount_with_enforcement_allowed() : 2,
			    "read-only mount policy allows read-only mount");
	report_child_result(mount_ro_policy_committed ?
			    rofs_updater_writable_mount_allowed() : 2,
			    "read-only mount policy allows updater writable mount");
	if (mount_ro_policy_committed)
		product_rofs_apply_result = product_rofs_mount_setup ?
					    product_rofs_mount_setup :
					    product_rofs_apply_seals_mount_readonly();
	report_child_result(mount_ro_policy_committed ?
			    product_rofs_apply_result : 2,
			    "product ROFS apply tool seals mounted path read-only");
	if (mount_ro_policy_committed && !product_rofs_optional_mount_setup)
		product_rofs_apply_optional_result =
			product_rofs_apply_optional_list_seals_required_mount();
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_optional_mount_setup ?
			     product_rofs_optional_mount_setup :
			     product_rofs_apply_optional_result) : 2,
			    "product ROFS apply optional list skips absent paths and seals required mount");
	if (mount_ro_policy_committed)
		product_rofs_apply_bind_result =
			product_rofs_apply_bind_seals_unified_path();
	report_child_result(mount_ro_policy_committed ?
			    product_rofs_apply_bind_result : 2,
			    "product ROFS apply bind list seals unified-root path without sealing root");
	if (mount_ro_policy_committed && !product_rofs_broker_apply_mount_setup)
		product_rofs_broker_apply_denied_result =
			product_rofs_broker_apply_denied_list();
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_broker_apply_mount_setup ?
			     product_rofs_broker_apply_mount_setup :
			     product_rofs_broker_apply_denied_result) : 2,
			    "admin broker denies unapproved ROFS apply list");
	if (mount_ro_policy_committed && !product_rofs_broker_apply_mount_setup &&
	    !product_rofs_broker_apply_denied_result)
		product_rofs_broker_apply_unsafe_result =
			product_rofs_broker_apply_unsafe_list();
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_broker_apply_mount_setup ?
			     product_rofs_broker_apply_mount_setup :
			     (product_rofs_broker_apply_denied_result ?
			      KSFT_SKIP :
			      product_rofs_broker_apply_unsafe_result)) : 2,
			    "admin broker rejects unsafe ROFS apply list");
	if (mount_ro_policy_committed && !product_rofs_broker_apply_mount_setup &&
	    !product_rofs_broker_apply_denied_result &&
	    !product_rofs_broker_apply_unsafe_result)
		product_rofs_broker_apply_result =
			product_rofs_broker_apply_list_seals_mount();
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_broker_apply_mount_setup ?
			     product_rofs_broker_apply_mount_setup :
			     ((product_rofs_broker_apply_denied_result ||
			       product_rofs_broker_apply_unsafe_result) ?
			      KSFT_SKIP : product_rofs_broker_apply_result)) : 2,
			    "admin broker ROFS apply list seals mounted path read-only");
	if (mount_ro_policy_committed && !product_rofs_broker_apply_mount_setup &&
	    (product_rofs_broker_apply_denied_result ||
	     product_rofs_broker_apply_unsafe_result ||
	     product_rofs_broker_apply_result))
		cleanup_product_rofs_mount(HDN_PRODUCT_ROFS_BROKER_DIR);
	if (mount_ro_policy_committed && !product_rofs_image_seal_mount_setup)
		image_seal_unknown_result = image_seal_unknown_denied();
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_image_seal_mount_setup ?
			     product_rofs_image_seal_mount_setup :
			     image_seal_unknown_result) : 2,
			    "image seal denies unknown seal");
	if (mount_ro_policy_committed && !product_rofs_image_seal_mount_setup &&
	    !image_seal_unknown_result)
		image_seal_unsafe_config_result =
			image_seal_unsafe_config_denied();
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_image_seal_mount_setup ?
			     product_rofs_image_seal_mount_setup :
			     (image_seal_unknown_result ? KSFT_SKIP :
			      image_seal_unsafe_config_result)) : 2,
			    "image seal denies unsafe config");
	if (mount_ro_policy_committed && !product_rofs_image_seal_mount_setup &&
	    !image_seal_unknown_result &&
	    !image_seal_unsafe_config_result)
		image_seal_result = image_seal_applies_rofs();
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_image_seal_mount_setup ?
			     product_rofs_image_seal_mount_setup :
			     ((image_seal_unknown_result ||
			       image_seal_unsafe_config_result) ? KSFT_SKIP :
			      image_seal_result)) : 2,
			    "image seal applies read-only mount list");
	if (mount_ro_policy_committed && !product_rofs_image_seal_mount_setup &&
	    (image_seal_unknown_result || image_seal_unsafe_config_result ||
	     image_seal_result))
		cleanup_image_seal_test();
	if (mount_ro_policy_committed && !product_rofs_apply_result)
		product_rofs_transaction_result =
			product_rofs_transaction_updates_and_reseals(false, 1,
								    false);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     product_rofs_transaction_result) : 2,
			    "product ROFS transaction updates and reseals mount");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result)
		product_rofs_transaction_cancel_result =
			product_rofs_transaction_cancel_reseals();
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     (product_rofs_transaction_result ? KSFT_SKIP :
			      product_rofs_transaction_cancel_result)) : 2,
			    "canceled ROFS transaction stops worker and reseals mount");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result)
		product_rofs_transaction_orphan_result =
			product_rofs_transaction_stops_background_worker();
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     (product_rofs_transaction_result ? KSFT_SKIP :
			      product_rofs_transaction_orphan_result)) : 2,
			    "ROFS transaction stops background worker before reseal");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_transaction_orphan_result)
		product_rofs_transaction_restrictions_result =
			product_rofs_transaction_preserves_mount_restrictions();
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_transaction_orphan_result) ? KSFT_SKIP :
			      product_rofs_transaction_restrictions_result)) : 2,
			    "ROFS transaction preserves mount restrictions");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result)
		product_rofs_broker_missing_config_result =
			product_rofs_broker_config_failure_denied(
				HDN_ADMIN_BROKER_MISSING_EXEC,
				"hdn-admin-broker-missing",
				"missing allowlist", 1);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     (product_rofs_transaction_result ? KSFT_SKIP :
			      product_rofs_broker_missing_config_result)) : 2,
			    "admin broker denies missing allowlist");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result)
		product_rofs_broker_unsafe_config_result =
			product_rofs_broker_config_failure_denied(
				HDN_ADMIN_BROKER_UNSAFE_EXEC,
				"hdn-admin-broker-unsafe",
				"writable allowlist", 1);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result) ?
			      KSFT_SKIP :
			      product_rofs_broker_unsafe_config_result)) : 2,
			    "admin broker denies writable allowlist");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result)
		product_rofs_broker_denial_result =
			product_rofs_broker_unapproved_worker_denied(1);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result) ?
			      KSFT_SKIP :
			      product_rofs_broker_denial_result)) : 2,
			    "admin broker denies unapproved ROFS worker");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result)
		product_rofs_broker_token_result =
			broker_approval_token_consumed_and_replay_denied(2);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result) ?
			      KSFT_SKIP : product_rofs_broker_token_result)) : 2,
			    "admin broker approval token is consumed and cannot replay");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result)
		product_rofs_system_unknown_result =
			product_rofs_system_transaction_unknown_denied(2);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result) ?
			      KSFT_SKIP : product_rofs_system_unknown_result)) : 2,
			    "system transaction denies unknown operation");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result)
		product_rofs_system_unsafe_config_result =
			product_rofs_system_transaction_unsafe_config_denied(2);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result) ?
			      KSFT_SKIP :
			      product_rofs_system_unsafe_config_result)) : 2,
			    "system transaction denies unsafe config");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result)
		product_rofs_system_transaction_result =
			product_rofs_system_transaction_updates_and_reseals(3);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result) ?
			      KSFT_SKIP :
			      product_rofs_system_transaction_result)) : 2,
			    "system transaction updates and reseals mount");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result)
		product_rofs_package_hook_unknown_result =
			product_rofs_package_hook_unknown_denied(3);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result) ?
			      KSFT_SKIP :
			      product_rofs_package_hook_unknown_result)) : 2,
			    "package hook denies unknown hook");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result &&
	    !product_rofs_package_hook_unknown_result)
		product_rofs_package_hook_unsafe_config_result =
			product_rofs_package_hook_unsafe_config_denied(3);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result) ?
			      KSFT_SKIP :
			      product_rofs_package_hook_unsafe_config_result)) : 2,
			    "package hook denies unsafe config");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result &&
	    !product_rofs_package_hook_unknown_result &&
	    !product_rofs_package_hook_unsafe_config_result)
		product_rofs_package_hook_result =
			product_rofs_package_hook_updates_and_reseals(4);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result ||
			       product_rofs_package_hook_unsafe_config_result) ?
			      KSFT_SKIP :
			      product_rofs_package_hook_result)) : 2,
			    "package hook updates and reseals mount");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result &&
	    !product_rofs_package_hook_unknown_result &&
	    !product_rofs_package_hook_unsafe_config_result &&
	    !product_rofs_package_hook_result)
		product_rofs_recovery_repair_result =
			product_rofs_recovery_repair_updates_and_reseals(5);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result ||
			       product_rofs_package_hook_unsafe_config_result ||
			       product_rofs_package_hook_result) ?
			      KSFT_SKIP :
			      product_rofs_recovery_repair_result)) : 2,
			    "recovery action package repair updates and reseals mount");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result &&
	    !product_rofs_package_hook_unknown_result &&
	    !product_rofs_package_hook_unsafe_config_result &&
	    !product_rofs_package_hook_result &&
	    !product_rofs_recovery_repair_result)
		product_rofs_recovery_session_repair_result =
			product_rofs_recovery_session_repair_updates_and_reseals(6);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result ||
			       product_rofs_package_hook_unsafe_config_result ||
			       product_rofs_package_hook_result ||
			       product_rofs_recovery_repair_result) ?
			      KSFT_SKIP :
			      product_rofs_recovery_session_repair_result)) : 2,
			    "recovery session package repair updates and reseals mount");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result &&
	    !product_rofs_package_hook_unknown_result &&
	    !product_rofs_package_hook_unsafe_config_result &&
	    !product_rofs_package_hook_result &&
	    !product_rofs_recovery_repair_result &&
	    !product_rofs_recovery_session_repair_result)
		product_rofs_recovery_portal_repair_result =
			product_rofs_recovery_portal_repair_updates_and_reseals(7);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result ||
			       product_rofs_package_hook_unsafe_config_result ||
			       product_rofs_package_hook_result ||
			       product_rofs_recovery_repair_result ||
			       product_rofs_recovery_session_repair_result) ?
			      KSFT_SKIP :
			      product_rofs_recovery_portal_repair_result)) : 2,
			    "recovery portal package repair updates and reseals mount");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result &&
	    !product_rofs_package_hook_unknown_result &&
	    !product_rofs_package_hook_unsafe_config_result &&
	    !product_rofs_package_hook_result &&
	    !product_rofs_recovery_repair_result &&
	    !product_rofs_recovery_session_repair_result &&
	    !product_rofs_recovery_portal_repair_result)
		product_rofs_prompt_unknown_result =
			product_rofs_prompt_dispatch_unknown_denied(7);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result ||
			       product_rofs_package_hook_unsafe_config_result ||
			       product_rofs_package_hook_result ||
			       product_rofs_recovery_repair_result ||
			       product_rofs_recovery_session_repair_result ||
			       product_rofs_recovery_portal_repair_result) ?
			      KSFT_SKIP : product_rofs_prompt_unknown_result)) : 2,
			    "prompt dispatch denies unknown action");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result &&
	    !product_rofs_package_hook_unknown_result &&
	    !product_rofs_package_hook_unsafe_config_result &&
	    !product_rofs_package_hook_result &&
	    !product_rofs_recovery_repair_result &&
	    !product_rofs_recovery_session_repair_result &&
	    !product_rofs_recovery_portal_repair_result &&
	    !product_rofs_prompt_unknown_result)
		product_rofs_prompt_unsafe_config_result =
			product_rofs_prompt_dispatch_unsafe_config_denied(7);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result ||
			       product_rofs_package_hook_unsafe_config_result ||
			       product_rofs_package_hook_result ||
			       product_rofs_recovery_repair_result ||
			       product_rofs_recovery_session_repair_result ||
			       product_rofs_recovery_portal_repair_result ||
			       product_rofs_prompt_unknown_result) ?
			      KSFT_SKIP :
			      product_rofs_prompt_unsafe_config_result)) : 2,
			    "prompt dispatch denies unsafe config");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result &&
	    !product_rofs_package_hook_unknown_result &&
	    !product_rofs_package_hook_unsafe_config_result &&
	    !product_rofs_package_hook_result &&
	    !product_rofs_recovery_repair_result &&
	    !product_rofs_recovery_session_repair_result &&
	    !product_rofs_recovery_portal_repair_result &&
	    !product_rofs_prompt_unknown_result &&
	    !product_rofs_prompt_unsafe_config_result)
		product_rofs_prompt_dispatch_result =
			product_rofs_prompt_dispatch_updates_and_reseals(8);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result ||
			       product_rofs_package_hook_unsafe_config_result ||
			       product_rofs_package_hook_result ||
			       product_rofs_recovery_repair_result ||
			       product_rofs_recovery_session_repair_result ||
			       product_rofs_recovery_portal_repair_result ||
			       product_rofs_prompt_unknown_result ||
			       product_rofs_prompt_unsafe_config_result) ?
			      KSFT_SKIP :
			      product_rofs_prompt_dispatch_result)) : 2,
			    "prompt dispatch updates and reseals mount");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result &&
	    !product_rofs_package_hook_unknown_result &&
	    !product_rofs_package_hook_unsafe_config_result &&
	    !product_rofs_package_hook_result &&
	    !product_rofs_recovery_repair_result &&
	    !product_rofs_recovery_session_repair_result &&
	    !product_rofs_recovery_portal_repair_result &&
	    !product_rofs_prompt_unknown_result &&
	    !product_rofs_prompt_unsafe_config_result &&
	    !product_rofs_prompt_dispatch_result)
		product_rofs_prompt_session_unknown_result =
			product_rofs_prompt_session_unknown_denied(8);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result ||
			       product_rofs_package_hook_unsafe_config_result ||
			       product_rofs_package_hook_result ||
			       product_rofs_recovery_repair_result ||
			       product_rofs_recovery_session_repair_result ||
			       product_rofs_recovery_portal_repair_result ||
			       product_rofs_prompt_unknown_result ||
			       product_rofs_prompt_unsafe_config_result ||
			       product_rofs_prompt_dispatch_result) ?
			      KSFT_SKIP :
			      product_rofs_prompt_session_unknown_result)) : 2,
			    "prompt session denies unknown action");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result &&
	    !product_rofs_package_hook_unknown_result &&
	    !product_rofs_package_hook_unsafe_config_result &&
	    !product_rofs_package_hook_result &&
	    !product_rofs_recovery_repair_result &&
	    !product_rofs_recovery_session_repair_result &&
	    !product_rofs_recovery_portal_repair_result &&
	    !product_rofs_prompt_unknown_result &&
	    !product_rofs_prompt_unsafe_config_result &&
	    !product_rofs_prompt_dispatch_result &&
	    !product_rofs_prompt_session_unknown_result)
		product_rofs_prompt_session_unsafe_config_result =
			product_rofs_prompt_session_unsafe_config_denied(8);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result ||
			       product_rofs_package_hook_unsafe_config_result ||
			       product_rofs_package_hook_result ||
			       product_rofs_recovery_repair_result ||
			       product_rofs_recovery_session_repair_result ||
			       product_rofs_recovery_portal_repair_result ||
			       product_rofs_prompt_unknown_result ||
			       product_rofs_prompt_unsafe_config_result ||
			       product_rofs_prompt_dispatch_result ||
			       product_rofs_prompt_session_unknown_result) ?
			      KSFT_SKIP :
			      product_rofs_prompt_session_unsafe_config_result)) : 2,
			    "prompt session denies unsafe config");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result &&
	    !product_rofs_package_hook_unknown_result &&
	    !product_rofs_package_hook_unsafe_config_result &&
	    !product_rofs_package_hook_result &&
	    !product_rofs_recovery_repair_result &&
	    !product_rofs_recovery_session_repair_result &&
	    !product_rofs_recovery_portal_repair_result &&
	    !product_rofs_prompt_unknown_result &&
	    !product_rofs_prompt_unsafe_config_result &&
	    !product_rofs_prompt_dispatch_result &&
	    !product_rofs_prompt_session_unknown_result &&
	    !product_rofs_prompt_session_unsafe_config_result)
		product_rofs_prompt_session_auth_denied_result =
			product_rofs_prompt_session_auth_denied(8);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result ||
			       product_rofs_package_hook_unsafe_config_result ||
			       product_rofs_package_hook_result ||
			       product_rofs_recovery_repair_result ||
			       product_rofs_recovery_session_repair_result ||
			       product_rofs_recovery_portal_repair_result ||
			       product_rofs_prompt_unknown_result ||
			       product_rofs_prompt_unsafe_config_result ||
			       product_rofs_prompt_dispatch_result ||
			       product_rofs_prompt_session_unknown_result ||
			       product_rofs_prompt_session_unsafe_config_result) ?
			      KSFT_SKIP :
			      product_rofs_prompt_session_auth_denied_result)) : 2,
			    "prompt session denies failed authentication");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result &&
	    !product_rofs_package_hook_unknown_result &&
	    !product_rofs_package_hook_unsafe_config_result &&
	    !product_rofs_package_hook_result &&
	    !product_rofs_recovery_repair_result &&
	    !product_rofs_recovery_session_repair_result &&
	    !product_rofs_recovery_portal_repair_result &&
	    !product_rofs_prompt_unknown_result &&
	    !product_rofs_prompt_unsafe_config_result &&
	    !product_rofs_prompt_dispatch_result &&
	    !product_rofs_prompt_session_unknown_result &&
	    !product_rofs_prompt_session_unsafe_config_result &&
	    !product_rofs_prompt_session_auth_denied_result)
		product_rofs_prompt_session_no_display_result =
			product_rofs_prompt_session_no_display_denied(8);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result ||
			       product_rofs_package_hook_unsafe_config_result ||
			       product_rofs_package_hook_result ||
			       product_rofs_recovery_repair_result ||
			       product_rofs_recovery_session_repair_result ||
			       product_rofs_recovery_portal_repair_result ||
			       product_rofs_prompt_unknown_result ||
			       product_rofs_prompt_unsafe_config_result ||
			       product_rofs_prompt_dispatch_result ||
			       product_rofs_prompt_session_unknown_result ||
			       product_rofs_prompt_session_unsafe_config_result ||
			       product_rofs_prompt_session_auth_denied_result) ?
			      KSFT_SKIP :
			      product_rofs_prompt_session_no_display_result)) : 2,
			    "prompt session fails closed without graphical session");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result &&
	    !product_rofs_package_hook_unknown_result &&
	    !product_rofs_package_hook_unsafe_config_result &&
	    !product_rofs_package_hook_result &&
	    !product_rofs_recovery_repair_result &&
	    !product_rofs_recovery_session_repair_result &&
	    !product_rofs_recovery_portal_repair_result &&
	    !product_rofs_prompt_unknown_result &&
	    !product_rofs_prompt_unsafe_config_result &&
	    !product_rofs_prompt_dispatch_result &&
	    !product_rofs_prompt_session_unknown_result &&
	    !product_rofs_prompt_session_unsafe_config_result &&
	    !product_rofs_prompt_session_auth_denied_result &&
	    !product_rofs_prompt_session_no_display_result)
		product_rofs_prompt_session_result =
			product_rofs_prompt_session_updates_and_reseals(9);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result ||
			       product_rofs_package_hook_unsafe_config_result ||
			       product_rofs_package_hook_result ||
			       product_rofs_recovery_repair_result ||
			       product_rofs_recovery_session_repair_result ||
			       product_rofs_recovery_portal_repair_result ||
			       product_rofs_prompt_unknown_result ||
			       product_rofs_prompt_unsafe_config_result ||
			       product_rofs_prompt_dispatch_result ||
			       product_rofs_prompt_session_unknown_result ||
			       product_rofs_prompt_session_unsafe_config_result ||
			       product_rofs_prompt_session_auth_denied_result ||
			       product_rofs_prompt_session_no_display_result) ?
			      KSFT_SKIP :
			      product_rofs_prompt_session_result)) : 2,
			    "prompt session authenticates updates and reseals mount");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result &&
	    !product_rofs_package_hook_unknown_result &&
	    !product_rofs_package_hook_unsafe_config_result &&
	    !product_rofs_package_hook_result &&
	    !product_rofs_recovery_repair_result &&
	    !product_rofs_recovery_session_repair_result &&
	    !product_rofs_recovery_portal_repair_result &&
	    !product_rofs_prompt_unknown_result &&
	    !product_rofs_prompt_unsafe_config_result &&
	    !product_rofs_prompt_dispatch_result &&
	    !product_rofs_prompt_session_unknown_result &&
	    !product_rofs_prompt_session_unsafe_config_result &&
	    !product_rofs_prompt_session_auth_denied_result &&
	    !product_rofs_prompt_session_no_display_result &&
	    !product_rofs_prompt_session_result)
		product_rofs_prompt_portal_unknown_result =
			product_rofs_prompt_portal_unknown_denied(9);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result ||
			       product_rofs_package_hook_unsafe_config_result ||
			       product_rofs_package_hook_result ||
			       product_rofs_recovery_repair_result ||
			       product_rofs_recovery_session_repair_result ||
			       product_rofs_recovery_portal_repair_result ||
			       product_rofs_prompt_unknown_result ||
			       product_rofs_prompt_unsafe_config_result ||
			       product_rofs_prompt_dispatch_result ||
			       product_rofs_prompt_session_unknown_result ||
			       product_rofs_prompt_session_unsafe_config_result ||
			       product_rofs_prompt_session_auth_denied_result ||
			       product_rofs_prompt_session_no_display_result ||
			       product_rofs_prompt_session_result) ?
			      KSFT_SKIP :
			      product_rofs_prompt_portal_unknown_result)) : 2,
			    "prompt portal denies unknown desktop action");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result &&
	    !product_rofs_package_hook_unknown_result &&
	    !product_rofs_package_hook_unsafe_config_result &&
	    !product_rofs_package_hook_result &&
	    !product_rofs_recovery_repair_result &&
	    !product_rofs_recovery_session_repair_result &&
	    !product_rofs_recovery_portal_repair_result &&
	    !product_rofs_prompt_unknown_result &&
	    !product_rofs_prompt_unsafe_config_result &&
	    !product_rofs_prompt_dispatch_result &&
	    !product_rofs_prompt_session_unknown_result &&
	    !product_rofs_prompt_session_unsafe_config_result &&
	    !product_rofs_prompt_session_auth_denied_result &&
	    !product_rofs_prompt_session_no_display_result &&
	    !product_rofs_prompt_session_result &&
	    !product_rofs_prompt_portal_unknown_result)
		product_rofs_prompt_portal_unsafe_config_result =
			product_rofs_prompt_portal_unsafe_config_denied(9);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result ||
			       product_rofs_package_hook_unsafe_config_result ||
			       product_rofs_package_hook_result ||
			       product_rofs_recovery_repair_result ||
			       product_rofs_recovery_session_repair_result ||
			       product_rofs_recovery_portal_repair_result ||
			       product_rofs_prompt_unknown_result ||
			       product_rofs_prompt_unsafe_config_result ||
			       product_rofs_prompt_dispatch_result ||
			       product_rofs_prompt_session_unknown_result ||
			       product_rofs_prompt_session_unsafe_config_result ||
			       product_rofs_prompt_session_auth_denied_result ||
			       product_rofs_prompt_session_no_display_result ||
			       product_rofs_prompt_session_result ||
			       product_rofs_prompt_portal_unknown_result) ?
			      KSFT_SKIP :
			      product_rofs_prompt_portal_unsafe_config_result)) : 2,
			    "prompt portal denies unsafe config");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result &&
	    !product_rofs_package_hook_unknown_result &&
	    !product_rofs_package_hook_unsafe_config_result &&
	    !product_rofs_package_hook_result &&
	    !product_rofs_recovery_repair_result &&
	    !product_rofs_recovery_session_repair_result &&
	    !product_rofs_recovery_portal_repair_result &&
	    !product_rofs_prompt_unknown_result &&
	    !product_rofs_prompt_unsafe_config_result &&
	    !product_rofs_prompt_dispatch_result &&
	    !product_rofs_prompt_session_unknown_result &&
	    !product_rofs_prompt_session_unsafe_config_result &&
	    !product_rofs_prompt_session_auth_denied_result &&
	    !product_rofs_prompt_session_no_display_result &&
	    !product_rofs_prompt_session_result &&
	    !product_rofs_prompt_portal_unknown_result &&
	    !product_rofs_prompt_portal_unsafe_config_result)
		product_rofs_prompt_portal_result =
			product_rofs_prompt_portal_updates_and_reseals(10);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result ||
			       product_rofs_package_hook_unsafe_config_result ||
			       product_rofs_package_hook_result ||
			       product_rofs_recovery_repair_result ||
			       product_rofs_recovery_session_repair_result ||
			       product_rofs_recovery_portal_repair_result ||
			       product_rofs_prompt_unknown_result ||
			       product_rofs_prompt_unsafe_config_result ||
			       product_rofs_prompt_dispatch_result ||
			       product_rofs_prompt_session_unknown_result ||
			       product_rofs_prompt_session_unsafe_config_result ||
			       product_rofs_prompt_session_auth_denied_result ||
			       product_rofs_prompt_session_no_display_result ||
			       product_rofs_prompt_session_result ||
			       product_rofs_prompt_portal_unknown_result ||
			       product_rofs_prompt_portal_unsafe_config_result) ?
			      KSFT_SKIP :
			      product_rofs_prompt_portal_result)) : 2,
			    "prompt portal authenticates updates and reseals mount");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result &&
	    !product_rofs_package_hook_unknown_result &&
	    !product_rofs_package_hook_unsafe_config_result &&
	    !product_rofs_package_hook_result &&
	    !product_rofs_recovery_repair_result &&
	    !product_rofs_recovery_session_repair_result &&
	    !product_rofs_recovery_portal_repair_result &&
	    !product_rofs_prompt_unknown_result &&
	    !product_rofs_prompt_unsafe_config_result &&
	    !product_rofs_prompt_dispatch_result &&
	    !product_rofs_prompt_session_unknown_result &&
	    !product_rofs_prompt_session_unsafe_config_result &&
	    !product_rofs_prompt_session_auth_denied_result &&
	    !product_rofs_prompt_session_no_display_result &&
	    !product_rofs_prompt_session_result &&
	    !product_rofs_prompt_portal_unknown_result &&
	    !product_rofs_prompt_portal_unsafe_config_result &&
	    !product_rofs_prompt_portal_result)
		product_rofs_desktop_action_unknown_result =
			product_rofs_desktop_action_unknown_denied(10);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result ||
			       product_rofs_package_hook_unsafe_config_result ||
			       product_rofs_package_hook_result ||
			       product_rofs_recovery_repair_result ||
			       product_rofs_recovery_session_repair_result ||
			       product_rofs_recovery_portal_repair_result ||
			       product_rofs_prompt_unknown_result ||
			       product_rofs_prompt_unsafe_config_result ||
			       product_rofs_prompt_dispatch_result ||
			       product_rofs_prompt_session_unknown_result ||
			       product_rofs_prompt_session_unsafe_config_result ||
			       product_rofs_prompt_session_auth_denied_result ||
			       product_rofs_prompt_session_no_display_result ||
			       product_rofs_prompt_session_result ||
			       product_rofs_prompt_portal_unknown_result ||
			       product_rofs_prompt_portal_unsafe_config_result ||
			       product_rofs_prompt_portal_result) ?
			      KSFT_SKIP :
			      product_rofs_desktop_action_unknown_result)) : 2,
			    "desktop action denies unknown UI action");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result &&
	    !product_rofs_package_hook_unknown_result &&
	    !product_rofs_package_hook_unsafe_config_result &&
	    !product_rofs_package_hook_result &&
	    !product_rofs_recovery_repair_result &&
	    !product_rofs_recovery_session_repair_result &&
	    !product_rofs_recovery_portal_repair_result &&
	    !product_rofs_prompt_unknown_result &&
	    !product_rofs_prompt_unsafe_config_result &&
	    !product_rofs_prompt_dispatch_result &&
	    !product_rofs_prompt_session_unknown_result &&
	    !product_rofs_prompt_session_unsafe_config_result &&
	    !product_rofs_prompt_session_auth_denied_result &&
	    !product_rofs_prompt_session_no_display_result &&
	    !product_rofs_prompt_session_result &&
	    !product_rofs_prompt_portal_unknown_result &&
	    !product_rofs_prompt_portal_unsafe_config_result &&
	    !product_rofs_prompt_portal_result &&
	    !product_rofs_desktop_action_unknown_result)
		product_rofs_desktop_action_unsafe_config_result =
			product_rofs_desktop_action_unsafe_config_denied(10);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result ||
			       product_rofs_package_hook_unsafe_config_result ||
			       product_rofs_package_hook_result ||
			       product_rofs_recovery_repair_result ||
			       product_rofs_recovery_session_repair_result ||
			       product_rofs_recovery_portal_repair_result ||
			       product_rofs_prompt_unknown_result ||
			       product_rofs_prompt_unsafe_config_result ||
			       product_rofs_prompt_dispatch_result ||
			       product_rofs_prompt_session_unknown_result ||
			       product_rofs_prompt_session_unsafe_config_result ||
			       product_rofs_prompt_session_auth_denied_result ||
			       product_rofs_prompt_session_no_display_result ||
			       product_rofs_prompt_session_result ||
			       product_rofs_prompt_portal_unknown_result ||
			       product_rofs_prompt_portal_unsafe_config_result ||
			       product_rofs_prompt_portal_result ||
			       product_rofs_desktop_action_unknown_result) ?
			      KSFT_SKIP :
			      product_rofs_desktop_action_unsafe_config_result)) : 2,
			    "desktop action denies unsafe config");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result &&
	    !product_rofs_package_hook_unknown_result &&
	    !product_rofs_package_hook_unsafe_config_result &&
	    !product_rofs_package_hook_result &&
	    !product_rofs_recovery_repair_result &&
	    !product_rofs_recovery_session_repair_result &&
	    !product_rofs_recovery_portal_repair_result &&
	    !product_rofs_prompt_unknown_result &&
	    !product_rofs_prompt_unsafe_config_result &&
	    !product_rofs_prompt_dispatch_result &&
	    !product_rofs_prompt_session_unknown_result &&
	    !product_rofs_prompt_session_unsafe_config_result &&
	    !product_rofs_prompt_session_auth_denied_result &&
	    !product_rofs_prompt_session_no_display_result &&
	    !product_rofs_prompt_session_result &&
	    !product_rofs_prompt_portal_unknown_result &&
	    !product_rofs_prompt_portal_unsafe_config_result &&
	    !product_rofs_prompt_portal_result &&
	    !product_rofs_desktop_action_unknown_result &&
	    !product_rofs_desktop_action_unsafe_config_result)
		product_rofs_desktop_action_result =
			product_rofs_desktop_action_updates_and_reseals(11);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result ||
			       product_rofs_package_hook_unsafe_config_result ||
			       product_rofs_package_hook_result ||
			       product_rofs_recovery_repair_result ||
			       product_rofs_recovery_session_repair_result ||
			       product_rofs_recovery_portal_repair_result ||
			       product_rofs_prompt_unknown_result ||
			       product_rofs_prompt_unsafe_config_result ||
			       product_rofs_prompt_dispatch_result ||
			       product_rofs_prompt_session_unknown_result ||
			       product_rofs_prompt_session_unsafe_config_result ||
			       product_rofs_prompt_session_auth_denied_result ||
			       product_rofs_prompt_session_no_display_result ||
			       product_rofs_prompt_session_result ||
			       product_rofs_prompt_portal_unknown_result ||
			       product_rofs_prompt_portal_unsafe_config_result ||
			       product_rofs_prompt_portal_result ||
			       product_rofs_desktop_action_unknown_result ||
			       product_rofs_desktop_action_unsafe_config_result) ?
			      KSFT_SKIP :
			      product_rofs_desktop_action_result)) : 2,
			    "desktop action authenticates updates and reseals mount");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result &&
	    !product_rofs_package_hook_unknown_result &&
	    !product_rofs_package_hook_unsafe_config_result &&
	    !product_rofs_package_hook_result &&
	    !product_rofs_recovery_repair_result &&
	    !product_rofs_recovery_session_repair_result &&
	    !product_rofs_recovery_portal_repair_result &&
	    !product_rofs_prompt_unknown_result &&
	    !product_rofs_prompt_unsafe_config_result &&
	    !product_rofs_prompt_dispatch_result &&
	    !product_rofs_prompt_session_unknown_result &&
	    !product_rofs_prompt_session_unsafe_config_result &&
	    !product_rofs_prompt_session_auth_denied_result &&
	    !product_rofs_prompt_session_no_display_result &&
	    !product_rofs_prompt_session_result &&
	    !product_rofs_prompt_portal_unknown_result &&
	    !product_rofs_prompt_portal_unsafe_config_result &&
	    !product_rofs_prompt_portal_result &&
	    !product_rofs_desktop_action_unknown_result &&
	    !product_rofs_desktop_action_unsafe_config_result &&
	    !product_rofs_desktop_action_result)
		product_rofs_desktop_daemon_unknown_result =
			product_rofs_desktop_daemon_unknown_denied(11);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result ||
			       product_rofs_package_hook_unsafe_config_result ||
			       product_rofs_package_hook_result ||
			       product_rofs_recovery_repair_result ||
			       product_rofs_recovery_session_repair_result ||
			       product_rofs_recovery_portal_repair_result ||
			       product_rofs_prompt_unknown_result ||
			       product_rofs_prompt_unsafe_config_result ||
			       product_rofs_prompt_dispatch_result ||
			       product_rofs_prompt_session_unknown_result ||
			       product_rofs_prompt_session_unsafe_config_result ||
			       product_rofs_prompt_session_auth_denied_result ||
			       product_rofs_prompt_session_no_display_result ||
			       product_rofs_prompt_session_result ||
			       product_rofs_prompt_portal_unknown_result ||
			       product_rofs_prompt_portal_unsafe_config_result ||
			       product_rofs_prompt_portal_result ||
			       product_rofs_desktop_action_unknown_result ||
			       product_rofs_desktop_action_unsafe_config_result ||
			       product_rofs_desktop_action_result) ?
			      KSFT_SKIP :
			      product_rofs_desktop_daemon_unknown_result)) : 2,
			    "desktop daemon denies unknown UI action");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result &&
	    !product_rofs_package_hook_unknown_result &&
	    !product_rofs_package_hook_unsafe_config_result &&
	    !product_rofs_package_hook_result &&
	    !product_rofs_recovery_repair_result &&
	    !product_rofs_recovery_session_repair_result &&
	    !product_rofs_recovery_portal_repair_result &&
	    !product_rofs_prompt_unknown_result &&
	    !product_rofs_prompt_unsafe_config_result &&
	    !product_rofs_prompt_dispatch_result &&
	    !product_rofs_prompt_session_unknown_result &&
	    !product_rofs_prompt_session_unsafe_config_result &&
	    !product_rofs_prompt_session_auth_denied_result &&
	    !product_rofs_prompt_session_no_display_result &&
	    !product_rofs_prompt_session_result &&
	    !product_rofs_prompt_portal_unknown_result &&
	    !product_rofs_prompt_portal_unsafe_config_result &&
	    !product_rofs_prompt_portal_result &&
	    !product_rofs_desktop_action_unknown_result &&
	    !product_rofs_desktop_action_unsafe_config_result &&
	    !product_rofs_desktop_action_result &&
	    !product_rofs_desktop_daemon_unknown_result)
		product_rofs_desktop_daemon_unsafe_config_result =
			product_rofs_desktop_daemon_unsafe_config_denied(11);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result ||
			       product_rofs_package_hook_unsafe_config_result ||
			       product_rofs_package_hook_result ||
			       product_rofs_recovery_repair_result ||
			       product_rofs_recovery_session_repair_result ||
			       product_rofs_recovery_portal_repair_result ||
			       product_rofs_prompt_unknown_result ||
			       product_rofs_prompt_unsafe_config_result ||
			       product_rofs_prompt_dispatch_result ||
			       product_rofs_prompt_session_unknown_result ||
			       product_rofs_prompt_session_unsafe_config_result ||
			       product_rofs_prompt_session_auth_denied_result ||
			       product_rofs_prompt_session_no_display_result ||
			       product_rofs_prompt_session_result ||
			       product_rofs_prompt_portal_unknown_result ||
			       product_rofs_prompt_portal_unsafe_config_result ||
			       product_rofs_prompt_portal_result ||
			       product_rofs_desktop_action_unknown_result ||
			       product_rofs_desktop_action_unsafe_config_result ||
			       product_rofs_desktop_action_result ||
			       product_rofs_desktop_daemon_unknown_result) ?
			      KSFT_SKIP :
			      product_rofs_desktop_daemon_unsafe_config_result)) : 2,
			    "desktop daemon denies unsafe config");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result &&
	    !product_rofs_package_hook_unknown_result &&
	    !product_rofs_package_hook_unsafe_config_result &&
	    !product_rofs_package_hook_result &&
	    !product_rofs_recovery_repair_result &&
	    !product_rofs_recovery_session_repair_result &&
	    !product_rofs_recovery_portal_repair_result &&
	    !product_rofs_prompt_unknown_result &&
	    !product_rofs_prompt_unsafe_config_result &&
	    !product_rofs_prompt_dispatch_result &&
	    !product_rofs_prompt_session_unknown_result &&
	    !product_rofs_prompt_session_unsafe_config_result &&
	    !product_rofs_prompt_session_auth_denied_result &&
	    !product_rofs_prompt_session_no_display_result &&
	    !product_rofs_prompt_session_result &&
	    !product_rofs_prompt_portal_unknown_result &&
	    !product_rofs_prompt_portal_unsafe_config_result &&
	    !product_rofs_prompt_portal_result &&
	    !product_rofs_desktop_action_unknown_result &&
	    !product_rofs_desktop_action_unsafe_config_result &&
	    !product_rofs_desktop_action_result &&
	    !product_rofs_desktop_daemon_unknown_result &&
	    !product_rofs_desktop_daemon_unsafe_config_result)
		product_rofs_desktop_daemon_result =
			product_rofs_desktop_daemon_updates_and_reseals(12);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result ||
			       product_rofs_package_hook_unsafe_config_result ||
			       product_rofs_package_hook_result ||
			       product_rofs_recovery_repair_result ||
			       product_rofs_recovery_session_repair_result ||
			       product_rofs_recovery_portal_repair_result ||
			       product_rofs_prompt_unknown_result ||
			       product_rofs_prompt_unsafe_config_result ||
			       product_rofs_prompt_dispatch_result ||
			       product_rofs_prompt_session_unknown_result ||
			       product_rofs_prompt_session_unsafe_config_result ||
			       product_rofs_prompt_session_auth_denied_result ||
			       product_rofs_prompt_session_no_display_result ||
			       product_rofs_prompt_session_result ||
			       product_rofs_prompt_portal_unknown_result ||
			       product_rofs_prompt_portal_unsafe_config_result ||
			       product_rofs_prompt_portal_result ||
			       product_rofs_desktop_action_unknown_result ||
			       product_rofs_desktop_action_unsafe_config_result ||
			       product_rofs_desktop_action_result ||
			       product_rofs_desktop_daemon_unknown_result ||
			       product_rofs_desktop_daemon_unsafe_config_result) ?
			      KSFT_SKIP :
			      product_rofs_desktop_daemon_result)) : 2,
			    "desktop daemon stdio authenticates updates and reseals mount");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result &&
	    !product_rofs_package_hook_unknown_result &&
	    !product_rofs_package_hook_unsafe_config_result &&
	    !product_rofs_package_hook_result &&
	    !product_rofs_recovery_repair_result &&
	    !product_rofs_recovery_session_repair_result &&
	    !product_rofs_recovery_portal_repair_result &&
	    !product_rofs_prompt_unknown_result &&
	    !product_rofs_prompt_unsafe_config_result &&
	    !product_rofs_prompt_dispatch_result &&
	    !product_rofs_prompt_session_unknown_result &&
	    !product_rofs_prompt_session_unsafe_config_result &&
	    !product_rofs_prompt_session_auth_denied_result &&
	    !product_rofs_prompt_session_no_display_result &&
	    !product_rofs_prompt_session_result &&
	    !product_rofs_prompt_portal_unknown_result &&
	    !product_rofs_prompt_portal_unsafe_config_result &&
	    !product_rofs_prompt_portal_result &&
	    !product_rofs_desktop_action_unknown_result &&
	    !product_rofs_desktop_action_unsafe_config_result &&
	    !product_rofs_desktop_action_result &&
	    !product_rofs_desktop_daemon_unknown_result &&
	    !product_rofs_desktop_daemon_unsafe_config_result &&
	    !product_rofs_desktop_daemon_result)
		product_rofs_control_center_stdio_unknown_result =
			product_rofs_control_center_stdio_unknown_denied(12);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result ||
			       product_rofs_package_hook_unsafe_config_result ||
			       product_rofs_package_hook_result ||
			       product_rofs_recovery_repair_result ||
			       product_rofs_recovery_session_repair_result ||
			       product_rofs_recovery_portal_repair_result ||
			       product_rofs_prompt_unknown_result ||
			       product_rofs_prompt_unsafe_config_result ||
			       product_rofs_prompt_dispatch_result ||
			       product_rofs_prompt_session_unknown_result ||
			       product_rofs_prompt_session_unsafe_config_result ||
			       product_rofs_prompt_session_auth_denied_result ||
			       product_rofs_prompt_session_no_display_result ||
			       product_rofs_prompt_session_result ||
			       product_rofs_prompt_portal_unknown_result ||
			       product_rofs_prompt_portal_unsafe_config_result ||
			       product_rofs_prompt_portal_result ||
			       product_rofs_desktop_action_unknown_result ||
			       product_rofs_desktop_action_unsafe_config_result ||
			       product_rofs_desktop_action_result ||
			       product_rofs_desktop_daemon_unknown_result ||
			       product_rofs_desktop_daemon_unsafe_config_result ||
			       product_rofs_desktop_daemon_result) ?
			      KSFT_SKIP :
			      product_rofs_control_center_stdio_unknown_result)) : 2,
			    "control center stdio denies unknown UI action");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result &&
	    !product_rofs_package_hook_unknown_result &&
	    !product_rofs_package_hook_unsafe_config_result &&
	    !product_rofs_package_hook_result &&
	    !product_rofs_recovery_repair_result &&
	    !product_rofs_recovery_session_repair_result &&
	    !product_rofs_recovery_portal_repair_result &&
	    !product_rofs_prompt_unknown_result &&
	    !product_rofs_prompt_unsafe_config_result &&
	    !product_rofs_prompt_dispatch_result &&
	    !product_rofs_prompt_session_unknown_result &&
	    !product_rofs_prompt_session_unsafe_config_result &&
	    !product_rofs_prompt_session_auth_denied_result &&
	    !product_rofs_prompt_session_no_display_result &&
	    !product_rofs_prompt_session_result &&
	    !product_rofs_prompt_portal_unknown_result &&
	    !product_rofs_prompt_portal_unsafe_config_result &&
	    !product_rofs_prompt_portal_result &&
	    !product_rofs_desktop_action_unknown_result &&
	    !product_rofs_desktop_action_unsafe_config_result &&
	    !product_rofs_desktop_action_result &&
	    !product_rofs_desktop_daemon_unknown_result &&
	    !product_rofs_desktop_daemon_unsafe_config_result &&
	    !product_rofs_desktop_daemon_result &&
	    !product_rofs_control_center_stdio_unknown_result)
		product_rofs_control_center_unknown_result =
			product_rofs_control_center_unknown_denied(12);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result ||
			       product_rofs_package_hook_unsafe_config_result ||
			       product_rofs_package_hook_result ||
			       product_rofs_recovery_repair_result ||
			       product_rofs_recovery_session_repair_result ||
			       product_rofs_recovery_portal_repair_result ||
			       product_rofs_prompt_unknown_result ||
			       product_rofs_prompt_unsafe_config_result ||
			       product_rofs_prompt_dispatch_result ||
			       product_rofs_prompt_session_unknown_result ||
			       product_rofs_prompt_session_unsafe_config_result ||
			       product_rofs_prompt_session_auth_denied_result ||
			       product_rofs_prompt_session_no_display_result ||
			       product_rofs_prompt_session_result ||
			       product_rofs_prompt_portal_unknown_result ||
			       product_rofs_prompt_portal_unsafe_config_result ||
			       product_rofs_prompt_portal_result ||
			       product_rofs_desktop_action_unknown_result ||
			       product_rofs_desktop_action_unsafe_config_result ||
			       product_rofs_desktop_action_result ||
			       product_rofs_desktop_daemon_unknown_result ||
			       product_rofs_desktop_daemon_unsafe_config_result ||
			       product_rofs_desktop_daemon_result ||
			       product_rofs_control_center_stdio_unknown_result) ?
			      KSFT_SKIP :
			      product_rofs_control_center_unknown_result)) : 2,
			    "control center denies unknown UI action");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result &&
	    !product_rofs_package_hook_unknown_result &&
	    !product_rofs_package_hook_unsafe_config_result &&
	    !product_rofs_package_hook_result &&
	    !product_rofs_recovery_repair_result &&
	    !product_rofs_recovery_session_repair_result &&
	    !product_rofs_recovery_portal_repair_result &&
	    !product_rofs_prompt_unknown_result &&
	    !product_rofs_prompt_unsafe_config_result &&
	    !product_rofs_prompt_dispatch_result &&
	    !product_rofs_prompt_session_unknown_result &&
	    !product_rofs_prompt_session_unsafe_config_result &&
	    !product_rofs_prompt_session_auth_denied_result &&
	    !product_rofs_prompt_session_no_display_result &&
	    !product_rofs_prompt_session_result &&
	    !product_rofs_prompt_portal_unknown_result &&
	    !product_rofs_prompt_portal_unsafe_config_result &&
	    !product_rofs_prompt_portal_result &&
	    !product_rofs_desktop_action_unknown_result &&
	    !product_rofs_desktop_action_unsafe_config_result &&
	    !product_rofs_desktop_action_result &&
	    !product_rofs_desktop_daemon_unknown_result &&
	    !product_rofs_desktop_daemon_unsafe_config_result &&
	    !product_rofs_desktop_daemon_result &&
	    !product_rofs_control_center_stdio_unknown_result &&
	    !product_rofs_control_center_unknown_result)
		product_rofs_control_center_result =
			product_rofs_control_center_updates_and_reseals(13);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result ||
			       product_rofs_package_hook_unsafe_config_result ||
			       product_rofs_package_hook_result ||
			       product_rofs_recovery_repair_result ||
			       product_rofs_recovery_session_repair_result ||
			       product_rofs_recovery_portal_repair_result ||
			       product_rofs_prompt_unknown_result ||
			       product_rofs_prompt_unsafe_config_result ||
			       product_rofs_prompt_dispatch_result ||
			       product_rofs_prompt_session_unknown_result ||
			       product_rofs_prompt_session_unsafe_config_result ||
			       product_rofs_prompt_session_auth_denied_result ||
			       product_rofs_prompt_session_no_display_result ||
			       product_rofs_prompt_session_result ||
			       product_rofs_prompt_portal_unknown_result ||
			       product_rofs_prompt_portal_unsafe_config_result ||
			       product_rofs_prompt_portal_result ||
			       product_rofs_desktop_action_unknown_result ||
			       product_rofs_desktop_action_unsafe_config_result ||
			       product_rofs_desktop_action_result ||
			       product_rofs_desktop_daemon_unknown_result ||
			       product_rofs_desktop_daemon_unsafe_config_result ||
			       product_rofs_desktop_daemon_result ||
			       product_rofs_control_center_stdio_unknown_result ||
			       product_rofs_control_center_unknown_result) ?
			      KSFT_SKIP :
			      product_rofs_control_center_result)) : 2,
			    "control center authenticates updates and reseals mount");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result &&
	    !product_rofs_package_hook_unknown_result &&
	    !product_rofs_package_hook_unsafe_config_result &&
	    !product_rofs_package_hook_result &&
	    !product_rofs_recovery_repair_result &&
	    !product_rofs_recovery_session_repair_result &&
	    !product_rofs_recovery_portal_repair_result &&
	    !product_rofs_prompt_unknown_result &&
	    !product_rofs_prompt_unsafe_config_result &&
	    !product_rofs_prompt_dispatch_result &&
	    !product_rofs_prompt_session_unknown_result &&
	    !product_rofs_prompt_session_unsafe_config_result &&
	    !product_rofs_prompt_session_auth_denied_result &&
	    !product_rofs_prompt_session_no_display_result &&
	    !product_rofs_prompt_session_result &&
	    !product_rofs_prompt_portal_unknown_result &&
	    !product_rofs_prompt_portal_unsafe_config_result &&
	    !product_rofs_prompt_portal_result &&
	    !product_rofs_desktop_action_unknown_result &&
	    !product_rofs_desktop_action_unsafe_config_result &&
	    !product_rofs_desktop_action_result &&
	    !product_rofs_desktop_daemon_unknown_result &&
	    !product_rofs_desktop_daemon_unsafe_config_result &&
	    !product_rofs_desktop_daemon_result &&
	    !product_rofs_control_center_stdio_unknown_result &&
	    !product_rofs_control_center_unknown_result &&
	    !product_rofs_control_center_result)
		product_rofs_control_center_stdio_result =
			product_rofs_control_center_stdio_updates_and_reseals(14);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result ||
			       product_rofs_package_hook_unsafe_config_result ||
			       product_rofs_package_hook_result ||
			       product_rofs_recovery_repair_result ||
			       product_rofs_recovery_session_repair_result ||
			       product_rofs_recovery_portal_repair_result ||
			       product_rofs_prompt_unknown_result ||
			       product_rofs_prompt_unsafe_config_result ||
			       product_rofs_prompt_dispatch_result ||
			       product_rofs_prompt_session_unknown_result ||
			       product_rofs_prompt_session_unsafe_config_result ||
			       product_rofs_prompt_session_auth_denied_result ||
			       product_rofs_prompt_session_no_display_result ||
			       product_rofs_prompt_session_result ||
			       product_rofs_prompt_portal_unknown_result ||
			       product_rofs_prompt_portal_unsafe_config_result ||
			       product_rofs_prompt_portal_result ||
			       product_rofs_desktop_action_unknown_result ||
			       product_rofs_desktop_action_unsafe_config_result ||
			       product_rofs_desktop_action_result ||
			       product_rofs_desktop_daemon_unknown_result ||
			       product_rofs_desktop_daemon_unsafe_config_result ||
			       product_rofs_desktop_daemon_result ||
			       product_rofs_control_center_stdio_unknown_result ||
			       product_rofs_control_center_unknown_result ||
			       product_rofs_control_center_result) ?
			      KSFT_SKIP :
			      product_rofs_control_center_stdio_result)) : 2,
			    "control center stdio authenticates updates and reseals mount");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result &&
	    !product_rofs_package_hook_unknown_result &&
	    !product_rofs_package_hook_unsafe_config_result &&
	    !product_rofs_package_hook_result &&
	    !product_rofs_recovery_repair_result &&
	    !product_rofs_recovery_session_repair_result &&
	    !product_rofs_recovery_portal_repair_result &&
	    !product_rofs_prompt_unknown_result &&
	    !product_rofs_prompt_unsafe_config_result &&
	    !product_rofs_prompt_dispatch_result &&
	    !product_rofs_prompt_session_unknown_result &&
	    !product_rofs_prompt_session_unsafe_config_result &&
	    !product_rofs_prompt_session_auth_denied_result &&
	    !product_rofs_prompt_session_no_display_result &&
	    !product_rofs_prompt_session_result &&
	    !product_rofs_prompt_portal_unknown_result &&
	    !product_rofs_prompt_portal_unsafe_config_result &&
	    !product_rofs_prompt_portal_result &&
	    !product_rofs_desktop_action_unknown_result &&
	    !product_rofs_desktop_action_unsafe_config_result &&
	    !product_rofs_desktop_action_result &&
	    !product_rofs_desktop_daemon_unknown_result &&
	    !product_rofs_desktop_daemon_unsafe_config_result &&
	    !product_rofs_desktop_daemon_result &&
	    !product_rofs_control_center_stdio_unknown_result &&
	    !product_rofs_control_center_unknown_result &&
	    !product_rofs_control_center_result &&
	    !product_rofs_control_center_stdio_result)
		product_rofs_settings_panel_unknown_result =
			product_rofs_settings_panel_unknown_denied(14);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result ||
			       product_rofs_package_hook_unsafe_config_result ||
			       product_rofs_package_hook_result ||
			       product_rofs_recovery_repair_result ||
			       product_rofs_recovery_session_repair_result ||
			       product_rofs_recovery_portal_repair_result ||
			       product_rofs_prompt_unknown_result ||
			       product_rofs_prompt_unsafe_config_result ||
			       product_rofs_prompt_dispatch_result ||
			       product_rofs_prompt_session_unknown_result ||
			       product_rofs_prompt_session_unsafe_config_result ||
			       product_rofs_prompt_session_auth_denied_result ||
			       product_rofs_prompt_session_no_display_result ||
			       product_rofs_prompt_session_result ||
			       product_rofs_prompt_portal_unknown_result ||
			       product_rofs_prompt_portal_unsafe_config_result ||
			       product_rofs_prompt_portal_result ||
			       product_rofs_desktop_action_unknown_result ||
			       product_rofs_desktop_action_unsafe_config_result ||
			       product_rofs_desktop_action_result ||
			       product_rofs_desktop_daemon_unknown_result ||
			       product_rofs_desktop_daemon_unsafe_config_result ||
			       product_rofs_desktop_daemon_result ||
			       product_rofs_control_center_stdio_unknown_result ||
			       product_rofs_control_center_unknown_result ||
			       product_rofs_control_center_result ||
			       product_rofs_control_center_stdio_result) ?
			      KSFT_SKIP :
			      product_rofs_settings_panel_unknown_result)) : 2,
			    "settings panel denies unknown UI action");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result &&
	    !product_rofs_package_hook_unknown_result &&
	    !product_rofs_package_hook_unsafe_config_result &&
	    !product_rofs_package_hook_result &&
	    !product_rofs_recovery_repair_result &&
	    !product_rofs_recovery_session_repair_result &&
	    !product_rofs_recovery_portal_repair_result &&
	    !product_rofs_prompt_unknown_result &&
	    !product_rofs_prompt_unsafe_config_result &&
	    !product_rofs_prompt_dispatch_result &&
	    !product_rofs_prompt_session_unknown_result &&
	    !product_rofs_prompt_session_unsafe_config_result &&
	    !product_rofs_prompt_session_auth_denied_result &&
	    !product_rofs_prompt_session_no_display_result &&
	    !product_rofs_prompt_session_result &&
	    !product_rofs_prompt_portal_unknown_result &&
	    !product_rofs_prompt_portal_unsafe_config_result &&
	    !product_rofs_prompt_portal_result &&
	    !product_rofs_desktop_action_unknown_result &&
	    !product_rofs_desktop_action_unsafe_config_result &&
	    !product_rofs_desktop_action_result &&
	    !product_rofs_desktop_daemon_unknown_result &&
	    !product_rofs_desktop_daemon_unsafe_config_result &&
	    !product_rofs_desktop_daemon_result &&
	    !product_rofs_control_center_stdio_unknown_result &&
	    !product_rofs_control_center_unknown_result &&
	    !product_rofs_control_center_result &&
	    !product_rofs_control_center_stdio_result &&
	    !product_rofs_settings_panel_unknown_result)
		product_rofs_settings_panel_unsafe_config_result =
			product_rofs_settings_panel_unsafe_config_denied(14);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result ||
			       product_rofs_package_hook_unsafe_config_result ||
			       product_rofs_package_hook_result ||
			       product_rofs_recovery_repair_result ||
			       product_rofs_recovery_session_repair_result ||
			       product_rofs_recovery_portal_repair_result ||
			       product_rofs_prompt_unknown_result ||
			       product_rofs_prompt_unsafe_config_result ||
			       product_rofs_prompt_dispatch_result ||
			       product_rofs_prompt_session_unknown_result ||
			       product_rofs_prompt_session_unsafe_config_result ||
			       product_rofs_prompt_session_auth_denied_result ||
			       product_rofs_prompt_session_no_display_result ||
			       product_rofs_prompt_session_result ||
			       product_rofs_prompt_portal_unknown_result ||
			       product_rofs_prompt_portal_unsafe_config_result ||
			       product_rofs_prompt_portal_result ||
			       product_rofs_desktop_action_unknown_result ||
			       product_rofs_desktop_action_unsafe_config_result ||
			       product_rofs_desktop_action_result ||
			       product_rofs_desktop_daemon_unknown_result ||
			       product_rofs_desktop_daemon_unsafe_config_result ||
			       product_rofs_desktop_daemon_result ||
			       product_rofs_control_center_stdio_unknown_result ||
			       product_rofs_control_center_unknown_result ||
			       product_rofs_control_center_result ||
			       product_rofs_control_center_stdio_result ||
			       product_rofs_settings_panel_unknown_result) ?
			      KSFT_SKIP :
			      product_rofs_settings_panel_unsafe_config_result)) : 2,
			    "settings panel denies unsafe config");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_transaction_result &&
	    !product_rofs_broker_missing_config_result &&
	    !product_rofs_broker_unsafe_config_result &&
	    !product_rofs_broker_denial_result &&
	    !product_rofs_broker_token_result &&
	    !product_rofs_system_unknown_result &&
	    !product_rofs_system_unsafe_config_result &&
	    !product_rofs_system_transaction_result &&
	    !product_rofs_package_hook_unknown_result &&
	    !product_rofs_package_hook_unsafe_config_result &&
	    !product_rofs_package_hook_result &&
	    !product_rofs_recovery_repair_result &&
	    !product_rofs_recovery_session_repair_result &&
	    !product_rofs_recovery_portal_repair_result &&
	    !product_rofs_prompt_unknown_result &&
	    !product_rofs_prompt_unsafe_config_result &&
	    !product_rofs_prompt_dispatch_result &&
	    !product_rofs_prompt_session_unknown_result &&
	    !product_rofs_prompt_session_unsafe_config_result &&
	    !product_rofs_prompt_session_auth_denied_result &&
	    !product_rofs_prompt_session_no_display_result &&
	    !product_rofs_prompt_session_result &&
	    !product_rofs_prompt_portal_unknown_result &&
	    !product_rofs_prompt_portal_unsafe_config_result &&
	    !product_rofs_prompt_portal_result &&
	    !product_rofs_desktop_action_unknown_result &&
	    !product_rofs_desktop_action_unsafe_config_result &&
	    !product_rofs_desktop_action_result &&
	    !product_rofs_desktop_daemon_unknown_result &&
	    !product_rofs_desktop_daemon_unsafe_config_result &&
	    !product_rofs_desktop_daemon_result &&
	    !product_rofs_control_center_stdio_unknown_result &&
	    !product_rofs_control_center_unknown_result &&
	    !product_rofs_control_center_result &&
	    !product_rofs_control_center_stdio_result &&
	    !product_rofs_settings_panel_unknown_result &&
	    !product_rofs_settings_panel_unsafe_config_result)
		product_rofs_settings_panel_result =
			product_rofs_settings_panel_updates_and_reseals(15);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result ||
			       product_rofs_package_hook_unsafe_config_result ||
			       product_rofs_package_hook_result ||
			       product_rofs_recovery_repair_result ||
			       product_rofs_recovery_session_repair_result ||
			       product_rofs_recovery_portal_repair_result ||
			       product_rofs_prompt_unknown_result ||
			       product_rofs_prompt_unsafe_config_result ||
			       product_rofs_prompt_dispatch_result ||
			       product_rofs_prompt_session_unknown_result ||
			       product_rofs_prompt_session_unsafe_config_result ||
			       product_rofs_prompt_session_auth_denied_result ||
			       product_rofs_prompt_session_no_display_result ||
			       product_rofs_prompt_session_result ||
			       product_rofs_prompt_portal_unknown_result ||
			       product_rofs_prompt_portal_unsafe_config_result ||
			       product_rofs_prompt_portal_result ||
			       product_rofs_desktop_action_unknown_result ||
			       product_rofs_desktop_action_unsafe_config_result ||
			       product_rofs_desktop_action_result ||
			       product_rofs_desktop_daemon_unknown_result ||
			       product_rofs_desktop_daemon_unsafe_config_result ||
			       product_rofs_desktop_daemon_result ||
			       product_rofs_control_center_stdio_unknown_result ||
			       product_rofs_control_center_unknown_result ||
			       product_rofs_control_center_result ||
			       product_rofs_control_center_stdio_result ||
			       product_rofs_settings_panel_unknown_result ||
			       product_rofs_settings_panel_unsafe_config_result) ?
			      KSFT_SKIP :
			      product_rofs_settings_panel_result)) : 2,
			    "settings panel authenticates updates and reseals mount");

	product_rofs_settings_ui_prereq =
		product_rofs_transaction_result ||
		product_rofs_broker_missing_config_result ||
		product_rofs_broker_unsafe_config_result ||
		product_rofs_broker_denial_result ||
		product_rofs_broker_token_result ||
		product_rofs_system_unknown_result ||
		product_rofs_system_unsafe_config_result ||
		product_rofs_system_transaction_result ||
		product_rofs_package_hook_unknown_result ||
		product_rofs_package_hook_unsafe_config_result ||
		product_rofs_package_hook_result ||
		product_rofs_recovery_repair_result ||
		product_rofs_recovery_session_repair_result ||
		product_rofs_recovery_portal_repair_result ||
		product_rofs_prompt_unknown_result ||
		product_rofs_prompt_unsafe_config_result ||
		product_rofs_prompt_dispatch_result ||
		product_rofs_prompt_session_unknown_result ||
		product_rofs_prompt_session_unsafe_config_result ||
		product_rofs_prompt_session_auth_denied_result ||
		product_rofs_prompt_session_no_display_result ||
		product_rofs_prompt_session_result ||
		product_rofs_prompt_portal_unknown_result ||
		product_rofs_prompt_portal_unsafe_config_result ||
		product_rofs_prompt_portal_result ||
		product_rofs_desktop_action_unknown_result ||
		product_rofs_desktop_action_unsafe_config_result ||
		product_rofs_desktop_action_result ||
		product_rofs_desktop_daemon_unknown_result ||
		product_rofs_desktop_daemon_unsafe_config_result ||
		product_rofs_desktop_daemon_result ||
		product_rofs_control_center_stdio_unknown_result ||
		product_rofs_control_center_unknown_result ||
		product_rofs_control_center_result ||
		product_rofs_control_center_stdio_result ||
		product_rofs_settings_panel_unknown_result ||
		product_rofs_settings_panel_unsafe_config_result ||
		product_rofs_settings_panel_result;
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_settings_ui_prereq)
		product_rofs_settings_ui_unknown_result =
			product_rofs_settings_ui_unknown_denied(15);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     (product_rofs_settings_ui_prereq ? KSFT_SKIP :
			      product_rofs_settings_ui_unknown_result)) : 2,
			    "settings UI denies unknown UI action");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_settings_ui_prereq &&
	    !product_rofs_settings_ui_unknown_result)
		product_rofs_settings_ui_unsafe_config_result =
			product_rofs_settings_ui_unsafe_config_denied(15);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_settings_ui_prereq ||
			       product_rofs_settings_ui_unknown_result) ?
			      KSFT_SKIP :
			      product_rofs_settings_ui_unsafe_config_result)) : 2,
			    "settings UI denies unsafe config");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_settings_ui_prereq &&
	    !product_rofs_settings_ui_unknown_result &&
	    !product_rofs_settings_ui_unsafe_config_result)
		product_rofs_settings_ui_cancel_result =
			product_rofs_settings_ui_cancel_denied(15);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_settings_ui_prereq ||
			       product_rofs_settings_ui_unknown_result ||
			       product_rofs_settings_ui_unsafe_config_result) ?
			      KSFT_SKIP :
			      product_rofs_settings_ui_cancel_result)) : 2,
			    "settings UI denies canceled selection");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_settings_ui_prereq &&
	    !product_rofs_settings_ui_unknown_result &&
	    !product_rofs_settings_ui_unsafe_config_result &&
	    !product_rofs_settings_ui_cancel_result)
		product_rofs_settings_ui_no_display_result =
			product_rofs_settings_ui_no_display_denied(15);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_settings_ui_prereq ||
			       product_rofs_settings_ui_unknown_result ||
			       product_rofs_settings_ui_unsafe_config_result ||
			       product_rofs_settings_ui_cancel_result) ?
			      KSFT_SKIP :
			      product_rofs_settings_ui_no_display_result)) : 2,
			    "settings UI fails closed without graphical session");
	if (mount_ro_policy_committed && !product_rofs_apply_result &&
	    !product_rofs_settings_ui_prereq &&
	    !product_rofs_settings_ui_unknown_result &&
	    !product_rofs_settings_ui_unsafe_config_result &&
	    !product_rofs_settings_ui_cancel_result &&
	    !product_rofs_settings_ui_no_display_result)
		product_rofs_settings_ui_result =
			product_rofs_settings_ui_updates_and_reseals(16);
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_settings_ui_prereq ||
			       product_rofs_settings_ui_unknown_result ||
			       product_rofs_settings_ui_unsafe_config_result ||
			       product_rofs_settings_ui_cancel_result ||
			       product_rofs_settings_ui_no_display_result) ?
			      KSFT_SKIP :
			      product_rofs_settings_ui_result)) : 2,
			    "settings UI authenticates updates and reseals mount");
	report_child_result(mount_ro_policy_committed ?
			    (product_rofs_apply_result ?
			     product_rofs_apply_result :
			     ((product_rofs_transaction_result ||
			       product_rofs_broker_missing_config_result ||
			       product_rofs_broker_unsafe_config_result ||
			       product_rofs_broker_denial_result ||
			       product_rofs_broker_token_result ||
			       product_rofs_system_unknown_result ||
			       product_rofs_system_unsafe_config_result ||
			       product_rofs_system_transaction_result ||
			       product_rofs_package_hook_unknown_result ||
			       product_rofs_package_hook_unsafe_config_result ||
			       product_rofs_package_hook_result ||
			       product_rofs_recovery_repair_result ||
			       product_rofs_recovery_session_repair_result ||
			       product_rofs_recovery_portal_repair_result ||
			       product_rofs_prompt_unknown_result ||
			       product_rofs_prompt_unsafe_config_result ||
			       product_rofs_prompt_dispatch_result ||
			       product_rofs_prompt_session_unknown_result ||
			       product_rofs_prompt_session_unsafe_config_result ||
			       product_rofs_prompt_session_auth_denied_result ||
			       product_rofs_prompt_session_no_display_result ||
			       product_rofs_prompt_session_result ||
			       product_rofs_prompt_portal_unknown_result ||
			       product_rofs_prompt_portal_unsafe_config_result ||
			       product_rofs_prompt_portal_result ||
			       product_rofs_desktop_action_unknown_result ||
			       product_rofs_desktop_action_unsafe_config_result ||
			       product_rofs_desktop_action_result ||
			       product_rofs_desktop_daemon_unknown_result ||
			       product_rofs_desktop_daemon_unsafe_config_result ||
			       product_rofs_desktop_daemon_result ||
			       product_rofs_control_center_stdio_unknown_result ||
			       product_rofs_control_center_unknown_result ||
			       product_rofs_control_center_result ||
			       product_rofs_control_center_stdio_result ||
			       product_rofs_settings_panel_unknown_result ||
			       product_rofs_settings_panel_unsafe_config_result ||
			       product_rofs_settings_panel_result ||
			       product_rofs_settings_ui_unknown_result ||
			       product_rofs_settings_ui_unsafe_config_result ||
			       product_rofs_settings_ui_cancel_result ||
			       product_rofs_settings_ui_no_display_result ||
			       product_rofs_settings_ui_result) ? KSFT_SKIP :
			      product_rofs_transaction_updates_and_reseals(true,
									  17,
									  true))) : 2,
			    "admin broker ROFS transaction updates and reseals mount");
	if ((!mount_ro_policy_committed && !product_rofs_mount_setup) ||
	    (mount_ro_policy_committed && !product_rofs_mount_setup &&
	     !product_rofs_apply_result &&
	     (product_rofs_transaction_result ||
	      product_rofs_broker_missing_config_result ||
	      product_rofs_broker_unsafe_config_result ||
	      product_rofs_broker_denial_result ||
	      product_rofs_broker_token_result ||
	      product_rofs_system_unknown_result ||
	      product_rofs_system_unsafe_config_result ||
	      product_rofs_system_transaction_result ||
	      product_rofs_package_hook_unknown_result ||
	      product_rofs_package_hook_unsafe_config_result ||
	      product_rofs_package_hook_result ||
	      product_rofs_recovery_repair_result ||
	      product_rofs_recovery_session_repair_result ||
	      product_rofs_recovery_portal_repair_result ||
	      product_rofs_prompt_unknown_result ||
	      product_rofs_prompt_unsafe_config_result ||
	      product_rofs_prompt_dispatch_result ||
	      product_rofs_prompt_session_unknown_result ||
	      product_rofs_prompt_session_unsafe_config_result ||
	      product_rofs_prompt_session_auth_denied_result ||
	      product_rofs_prompt_session_no_display_result ||
	      product_rofs_prompt_session_result ||
	      product_rofs_prompt_portal_unknown_result ||
	      product_rofs_prompt_portal_unsafe_config_result ||
	      product_rofs_prompt_portal_result ||
	      product_rofs_desktop_action_unknown_result ||
	      product_rofs_desktop_action_unsafe_config_result ||
	      product_rofs_desktop_action_result ||
	      product_rofs_desktop_daemon_unknown_result ||
	      product_rofs_desktop_daemon_unsafe_config_result ||
	      product_rofs_desktop_daemon_result ||
	      product_rofs_control_center_stdio_unknown_result ||
	      product_rofs_control_center_unknown_result ||
	      product_rofs_control_center_result ||
	      product_rofs_control_center_stdio_result ||
	      product_rofs_settings_panel_unknown_result ||
	      product_rofs_settings_panel_unsafe_config_result ||
	      product_rofs_settings_panel_result ||
	      product_rofs_settings_ui_unknown_result ||
	      product_rofs_settings_ui_unsafe_config_result ||
	      product_rofs_settings_ui_cancel_result ||
	      product_rofs_settings_ui_no_display_result ||
	      product_rofs_settings_ui_result)))
		cleanup_product_rofs_test();
	test_securityfs_events_line_contains("authority=26 transition=11",
					     "reason=27",
					     "hardening events report writable mount denial");

	ret = mount_ro_policy_committed ? write_text_file(HDN_ROLLBACK, "1\n") :
					  -EINVAL;
	mount_ro_policy_rolled_back = !ret;
	ksft_test_result(mount_ro_policy_rolled_back,
			 "read-only mount hardening policy rollback succeeds\n");

	ret = write_signed_policy_path(HDN_PROC_TASK_POLICY);
	proc_task_policy_staged = !ret;
	ksft_test_result(proc_task_policy_staged,
			 "proc-task hardening policy stages\n");

	ret = proc_task_policy_staged ? write_text_file(HDN_COMMIT, "1\n") :
					-EINVAL;
	proc_task_policy_committed = !ret;
	ksft_test_result(proc_task_policy_committed,
			 "proc-task hardening policy commits\n");
	report_child_result(proc_task_policy_committed ?
			    proc_pid_visibility_allowed() : 2,
			    "proc-task policy allows other-user proc entries");
	report_child_result(proc_task_policy_committed ?
			    pidfd_open_proc_task_allowed() : 2,
			    "proc-task policy allows pidfd_open for other-user task");
	report_child_result(proc_task_policy_committed ?
			    pidfd_info_proc_task_allowed() : 2,
			    "proc-task policy allows received pidfd info for other-user task");
	report_child_result(proc_task_policy_committed ?
			    pidfd_fdinfo_proc_task_visible() : 2,
			    "proc-task policy allows received pidfd fdinfo for other-user task");
	report_child_result(proc_task_policy_committed ?
			    proc_kallsyms_symbols_hidden() : 2,
			    "proc-task policy keeps kernel symbols hidden");

	ret = proc_task_policy_committed ? write_text_file(HDN_ROLLBACK, "1\n") :
					   -EINVAL;
	proc_task_policy_rolled_back = !ret;
	ksft_test_result(proc_task_policy_rolled_back,
			 "proc-task hardening policy rollback succeeds\n");

	ret = write_signed_policy_path(HDN_NAMESPACE_ONLY_POLICY);
	namespace_only_policy_staged = !ret;
	ksft_test_result(namespace_only_policy_staged,
			 "namespace-only hardening policy stages\n");

	ret = namespace_only_policy_staged ? write_text_file(HDN_COMMIT, "1\n") :
					     -EINVAL;
	namespace_only_policy_committed = !ret;
	ksft_test_result(namespace_only_policy_committed,
			 "namespace-only hardening policy commits\n");
		report_child_result(namespace_only_policy_committed ?
				    pidfd_setns_without_proc_task_denied() : 2,
				    "namespace-only policy denies received pidfd setns without proc-task view");
		report_child_result(namespace_only_policy_committed ?
				    pidfd_namespace_without_proc_task_denied() : 2,
				    "namespace-only policy denies received pidfd namespace fd without proc-task view");

		ret = namespace_only_policy_committed ?
		      write_text_file(HDN_ROLLBACK, "1\n") : -EINVAL;
	namespace_only_policy_rolled_back = !ret;
	ksft_test_result(namespace_only_policy_rolled_back,
			 "namespace-only hardening policy rollback succeeds\n");

	ret = write_signed_policy_path(HDN_NAMESPACE_PROC_TASK_POLICY);
	namespace_proc_task_policy_staged = !ret;
	ksft_test_result(namespace_proc_task_policy_staged,
			 "namespace proc-task hardening policy stages\n");

	ret = namespace_proc_task_policy_staged ?
	      write_text_file(HDN_COMMIT, "1\n") : -EINVAL;
	namespace_proc_task_policy_committed = !ret;
	ksft_test_result(namespace_proc_task_policy_committed,
			 "namespace proc-task hardening policy commits\n");
		report_child_result(namespace_proc_task_policy_committed ?
				    pidfd_setns_with_proc_task_allowed() : 2,
				    "namespace proc-task policy allows received pidfd setns");
		report_child_result(namespace_proc_task_policy_committed ?
				    pidfd_namespace_with_proc_task_allowed() : 2,
				    "namespace proc-task policy allows received pidfd namespace fd");

		ret = namespace_proc_task_policy_committed ?
		      write_text_file(HDN_ROLLBACK, "1\n") : -EINVAL;
	namespace_proc_task_policy_rolled_back = !ret;
	ksft_test_result(namespace_proc_task_policy_rolled_back,
			 "namespace proc-task hardening policy rollback succeeds\n");

	ret = write_signed_policy_path(HDN_SUBJECT_POLICY);
	subject_policy_staged = !ret;
	ksft_test_result(subject_policy_staged,
			 "subject hardening policy stages\n");

	ret = subject_policy_staged ? write_text_file(HDN_COMMIT, "1\n") :
				      -EINVAL;
	subject_policy_committed = !ret;
	ksft_test_result(subject_policy_committed,
			 "subject hardening policy commits\n");
	ksft_test_result(subject_policy_committed &&
			 securityfs_status_has_line("subject_rule_count: 2"),
			 "subject policy reports subject rule count\n");
	report_child_result(subject_policy_committed ?
			    subject_uid_profile_selected() : 2,
			    "subject uid rule assigns user profile");
	report_child_result(subject_policy_committed ?
			    subject_gid_profile_selected() : 2,
			    "subject gid rule assigns user profile");
	report_child_result(subject_policy_committed ?
			    subject_umask_file_private() : 2,
			    "subject profile umask makes files private");
	report_child_result(subject_policy_committed ?
			    subject_umask_dir_private() : 2,
			    "subject profile umask makes directories private");

	ret = subject_policy_committed ? write_text_file(HDN_ROLLBACK, "1\n") :
					 -EINVAL;
	subject_policy_rolled_back = !ret;
	ksft_test_result(subject_policy_rolled_back,
			 "subject hardening policy rollback succeeds\n");

	ret = write_signed_policy_path(HDN_USERNS_DEPTH_POLICY);
	userns_depth_policy_staged = !ret;
	ksft_test_result(userns_depth_policy_staged,
			 "userns-depth hardening policy stages\n");

	ret = userns_depth_policy_staged ?
	      write_text_file(HDN_COMMIT, "1\n") : -EINVAL;
	userns_depth_policy_committed = !ret;
	ksft_test_result(userns_depth_policy_committed,
			 "userns-depth hardening policy commits\n");
	report_child_result(userns_depth_policy_committed ?
			    userns_depth_policy_enforced() : 2,
			    "userns-depth policy permits two levels and denies the third");
	ksft_test_result(userns_depth_policy_committed &&
			 securityfs_events_line_contains("reason=61", "object=3"),
			 "hardening events report requested userns level\n");
	report_child_result(userns_depth_policy_committed ?
			    event_decoder_finds_userns_depth_denial() : 2,
			    "event decoder names userns-depth denial");

	ret = userns_depth_policy_committed ?
	      write_text_file(HDN_ROLLBACK, "1\n") : -EINVAL;
	userns_depth_policy_rolled_back = !ret;
	ksft_test_result(userns_depth_policy_rolled_back,
			 "userns-depth hardening policy rollback succeeds\n");

	ret = write_signed_policy_path(HDN_ROLE_POLICY);
	role_policy_staged = !ret;
	ksft_test_result(role_policy_staged,
			 "role hardening policy stages\n");

	ret = role_policy_staged ? write_text_file(HDN_COMMIT, "1\n") :
				   -EINVAL;
	role_policy_committed = !ret;
	ksft_test_result(role_policy_committed,
			 "role hardening policy commits\n");

	ret = role_policy_committed ? write_text_file(HDN_ROLLBACK, "1\n") :
				      -EINVAL;
	role_policy_rolled_back = !ret;
	ksft_test_result(role_policy_rolled_back,
			 "nested role-expanded policy authority permits rollback\n");

	capability_test_setup = setup_capability_policy_test();
	report_child_result(capability_test_setup,
			    "capability policy fixture setup succeeds");

	ret = write_signed_policy_path(HDN_CAPABILITY_POLICY);
	capability_policy_staged = !ret;
	ksft_test_result(capability_policy_staged,
			 "capability hardening policy stages\n");

	ret = capability_policy_staged ? write_text_file(HDN_COMMIT, "1\n") :
						 -EINVAL;
	capability_policy_committed = !ret;
	ksft_test_result(capability_policy_committed,
			 "capability hardening policy commits\n");
	report_child_result(capability_policy_committed ?
			    capability_profile_masks_reported() : 2,
			    "capability policy reports role-expanded masks");
	report_child_result(capability_policy_committed && !capability_test_setup ?
			    capability_profile_denies_chown() : 2,
			    "capability profile denies CAP_CHOWN");
	ksft_test_result(capability_policy_committed &&
			 securityfs_events_contains(
				 "authority=0 transition=103 action=4 reason=59"),
			 "hardening events report capability profile denial\n");
	report_child_result(capability_policy_committed && !capability_test_setup ?
			    capability_profile_audits_fowner() : 2,
			    "capability profile audits allowed CAP_FOWNER");
	report_child_result(capability_policy_committed ?
			    event_decoder_finds_capability_denial() : 2,
			    "event decoder names capability profile denial");

	ret = capability_policy_committed ? write_text_file(HDN_ROLLBACK, "1\n") :
						    -EINVAL;
	capability_policy_rolled_back = !ret;
	ksft_test_result(capability_policy_rolled_back,
			 "capability hardening policy rollback succeeds\n");
	report_child_result(capability_policy_rolled_back && !capability_test_setup ?
			    capability_profile_chown_restored() : 2,
			    "capability rollback restores CAP_CHOWN");
	cleanup_capability_policy_test();

	object_audit_test_setup = setup_object_audit_policy_test();
	report_child_result(object_audit_test_setup,
			    "object audit policy fixture setup succeeds");

	ret = write_signed_policy_path(HDN_OBJECT_AUDIT_POLICY);
	object_audit_policy_staged = !ret;
	ksft_test_result(object_audit_policy_staged,
			 "object audit hardening policy stages\n");

	ret = object_audit_policy_staged ? write_text_file(HDN_COMMIT, "1\n") :
						     -EINVAL;
	object_audit_policy_committed = !ret;
	ksft_test_result(object_audit_policy_committed,
			 "object audit hardening policy commits\n");
	report_child_result(object_audit_policy_committed &&
			    !object_audit_test_setup ?
			    object_audit_read_recorded() : 2,
			    "object audit policy records allowed read");
	report_child_result(object_audit_policy_committed &&
			    !object_audit_test_setup ?
			    object_audit_append_recorded() : 2,
			    "object audit policy records allowed append");
	report_child_result(object_audit_policy_committed &&
			    !object_audit_test_setup ?
			    object_audit_write_recorded() : 2,
			    "object audit policy records allowed write");
	report_child_result(object_audit_policy_committed &&
			    !object_audit_test_setup ?
			    object_audit_exec_recorded() : 2,
			    "object audit policy records allowed exec");
	report_child_result(object_audit_policy_committed &&
			    !object_audit_test_setup ?
			    object_audit_inherit_recorded() : 2,
			    "object audit policy records inherited exec");
	report_child_result(object_audit_policy_committed &&
			    !object_audit_test_setup ?
			    object_audit_find_recorded() : 2,
			    "object audit policy records allowed find");
	report_child_result(object_audit_policy_committed &&
			    !object_audit_test_setup ?
			    object_audit_create_recorded() : 2,
			    "object audit policy records allowed create");
	report_child_result(object_audit_policy_committed &&
			    !object_audit_test_setup ?
			    object_audit_delete_recorded() : 2,
			    "object audit policy records allowed delete");
	report_child_result(object_audit_policy_committed &&
			    !object_audit_test_setup ?
			    object_audit_link_recorded() : 2,
			    "object audit policy records allowed link");
	report_child_result(object_audit_policy_committed &&
			    !object_audit_test_setup ?
			    object_audit_setid_recorded() : 2,
			    "object audit policy records allowed setid");
	report_child_result(object_audit_policy_committed &&
			    !object_audit_test_setup ?
			    object_audit_deny_precedes_audit() : 2,
			    "object deny takes precedence over audit");
	report_child_result(object_audit_policy_committed ?
			    event_decoder_finds_object_read_audit() : 2,
			    "event decoder names object allow audit");
	report_child_result(object_audit_policy_committed ?
			    event_decoder_finds_exec_inherit_audit() : 2,
			    "event decoder names inherited exec audit");

	ret = object_audit_policy_committed ?
		      write_text_file(HDN_ROLLBACK, "1\n") : -EINVAL;
	object_audit_policy_rolled_back = !ret;
	ksft_test_result(object_audit_policy_rolled_back,
			 "object audit hardening policy rollback succeeds\n");
	report_child_result(object_audit_policy_rolled_back &&
			    !object_audit_test_setup ?
			    object_audit_stops_after_rollback() : 2,
			    "object audit rollback stops object audit events");
	report_child_result(object_audit_policy_rolled_back &&
			    !object_audit_test_setup ?
			    exec_inherit_audit_stops_after_rollback() : 2,
			    "object audit rollback stops inherited exec events");
	cleanup_object_audit_policy_test();

	ret = write_signed_policy_path(HDN_PROCESS_ACCOUNT_POLICY);
	process_account_policy_staged = !ret;
	ksft_test_result(process_account_policy_staged,
			 "process-account hardening policy stages\n");

	ret = process_account_policy_staged ? write_text_file(HDN_COMMIT,
							      "1\n") :
					      -EINVAL;
	process_account_policy_committed = !ret;
	ksft_test_result(process_account_policy_committed,
			 "process-account hardening policy commits\n");

	report_child_result(process_account_policy_committed ?
			    process_account_event_recorded() : 2,
			    "process-account policy records child exit event");

	ret = process_account_policy_committed ?
		      write_text_file(HDN_ROLLBACK, "1\n") : -EINVAL;
	process_account_policy_rolled_back = !ret;
	ksft_test_result(process_account_policy_rolled_back,
			 "process-account hardening policy rollback succeeds\n");

	ret = object_prepare_chrdev_fixtures();
	if (!ret)
		ret = object_prepare_blkdev_fixtures();
	if (!ret)
		ret = setup_object_umount_fixtures();
	if (!ret)
		ret = setup_object_tree_umount_fixture();
	if (!ret)
		ret = setup_object_unix_connect_fixtures(
			&object_unix_connect_protected_fd,
			&object_unix_connect_unprotected_fd);
	if (!ret)
		ret = setup_object_unix_connect_socket(
			HDN_OBJECT_TREE_OPS_UNIX_CONNECT,
			&object_tree_unix_connect_fd);
	if (!ret)
		ret = setup_object_unix_connect_socket(
			HDN_OBJECT_TREE_OPS_UNIX_CONNECT_UNMATCHED,
			&object_tree_unix_connect_unmatched_fd);
	if (!ret)
		ret = setup_object_unix_socket(HDN_OBJECT_TREE_IPC_LISTEN,
					       &object_tree_unix_listen_fd,
					       false);
	if (!ret)
		ret = setup_object_unix_socket(HDN_OBJECT_TREE_IPC_ACCEPT,
					       &object_tree_unix_accept_fd,
					       true);
	if (!ret)
		ret = setup_object_unix_dgram_socket(
			HDN_OBJECT_TREE_IPC_SEND, &object_tree_unix_send_fd);
	if (!ret)
		ret = setup_object_unix_dgram_client(
			HDN_OBJECT_TREE_IPC_SEND,
			&object_tree_unix_connected_send_fd);
	if (!ret)
		ret = setup_object_unix_dgram_socket(
			HDN_OBJECT_TREE_IPC_RECV, &object_tree_unix_recv_fd);
	if (!ret)
		ret = setup_object_unix_bind_fixtures();
	if (!ret)
		ret = setup_object_unix_listen_fixtures(
			&object_unix_listen_protected_fd,
			&object_unix_listen_unprotected_fd);
	if (!ret)
		ret = setup_object_unix_accept_fixtures(
			&object_unix_accept_protected_fd,
			&object_unix_accept_unprotected_fd);
	if (!ret)
		ret = setup_object_unix_send_fixtures(
			&object_unix_send_protected_fd,
			&object_unix_send_unprotected_fd);
	if (!ret)
		ret = setup_object_unix_connected_send_fixtures(
			&object_unix_connected_send_protected_fd,
			&object_unix_connected_send_unprotected_fd);
	if (!ret)
		ret = setup_object_unix_recv_fixtures(
			&object_unix_recv_protected_fd,
			&object_unix_recv_unprotected_fd);
	if (!ret)
		ret = setup_object_unix_abstract_connect_fixtures(
			&object_unix_abs_connect_protected_fd,
			&object_unix_abs_connect_unprotected_fd);
	if (!ret)
		ret = setup_object_unix_abstract_listen_fixtures(
			&object_unix_abs_listen_protected_fd,
			&object_unix_abs_listen_unprotected_fd);
	if (!ret)
		ret = setup_object_unix_abstract_accept_fixtures(
			&object_unix_abs_accept_protected_fd,
			&object_unix_abs_accept_unprotected_fd);
	if (!ret)
		ret = setup_object_unix_abstract_send_fixtures(
			&object_unix_abs_send_protected_fd,
			&object_unix_abs_send_unprotected_fd);
	if (!ret)
		ret = setup_object_unix_abstract_connected_send_fixtures(
			&object_unix_abs_connected_send_protected_fd,
			&object_unix_abs_connected_send_unprotected_fd);
	if (!ret)
		ret = setup_object_unix_abstract_recv_fixtures(
			&object_unix_abs_recv_protected_fd,
			&object_unix_abs_recv_unprotected_fd);
	if (!ret)
		ret = setup_object_mount_source_fixtures();
	if (!ret)
		ret = setup_object_fileattr_fs();
	object_fileattr_prepared = !ret;
	if (!ret)
		ret = write_signed_policy_path(HDN_OBJECT_WRITE_POLICY);
	object_policy_staged = !ret;
	ksft_test_result(object_policy_staged,
			 "object-write hardening policy stages\n");
	if (object_policy_staged)
		object_preopen_fd = open(HDN_OBJECT_READ_PROTECTED,
					 O_RDONLY | O_CLOEXEC);
	if (object_policy_staged)
		object_write_preopen_fd = open(HDN_OBJECT_WRITE_PROTECTED,
					       O_RDWR | O_CLOEXEC);
	if (object_policy_staged)
		object_append_preopen_fd = open(HDN_OBJECT_APPEND_PROTECTED,
						O_RDWR | O_CLOEXEC);
	if (object_policy_staged)
		object_truncate_preopen_fd = open(HDN_OBJECT_TRUNCATE_PROTECTED,
						  O_RDWR | O_CLOEXEC);
	if (object_policy_staged)
		object_tree_truncate_preopen_fd = open(
			HDN_OBJECT_TREE_OPS_TRUNCATE, O_RDWR | O_CLOEXEC);
	if (object_policy_staged)
		object_tree_truncate_unmatched_preopen_fd = open(
			HDN_OBJECT_TREE_OPS_TRUNCATE_UNMATCHED, O_RDWR | O_CLOEXEC);
	if (object_policy_staged)
		object_stat_preopen_fd = open(HDN_OBJECT_STAT_PROTECTED,
					      O_RDONLY | O_CLOEXEC);
	if (object_policy_staged)
		object_list_preopen_fd = open(HDN_OBJECT_LIST_PROTECTED_DIR,
					      O_RDONLY | O_DIRECTORY |
					      O_CLOEXEC);
	if (object_policy_staged)
		object_chdir_preopen_fd = open(HDN_OBJECT_CHDIR_PROTECTED_DIR,
					       O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (object_policy_staged)
		object_tree_chdir_preopen_fd = open(HDN_OBJECT_TREE_OPS_CHDIR,
						    O_RDONLY | O_DIRECTORY |
						    O_CLOEXEC);
	if (object_policy_staged)
		object_tree_chdir_unmatched_preopen_fd = open(
			HDN_OBJECT_TREE_OPS_CHDIR_UNMATCHED,
			O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (object_policy_staged)
		object_attr_xattr_prepared = !setup_object_attr_xattr();
	if (object_policy_staged)
		object_xattr_prepared = !setup_object_xattr();
	if (object_policy_staged)
		object_split_xattr_prepared = !setup_object_split_xattr();
	if (object_policy_staged)
		object_tree_xattr_prepared = !setup_object_tree_xattr();

	ret = object_policy_staged ? write_text_file(HDN_COMMIT, "1\n") :
				     -EINVAL;
		object_policy_committed = !ret;
	ksft_test_result(object_policy_committed,
			 "object-write hardening policy commits\n");
	ksft_test_result(object_policy_committed &&
							 securityfs_status_has_line("object_rule_count: 107"),
						 "object-write policy reports object rule count\n");
	report_child_result(object_policy_committed ?
			    object_protected_write_denied() : 2,
			    "object-write policy denies protected file write");
	report_child_result(object_policy_committed ?
			    object_unprotected_write_allowed() : 2,
			    "object-write policy allows unmatched file write");
	report_child_result(object_policy_committed ?
			    object_protected_truncate_denied() : 2,
			    "object-write policy denies protected truncate");
	report_child_result(object_policy_committed ?
			    object_unmatched_truncate_allowed() : 2,
			    "object-write policy allows unmatched truncate");
	report_child_result(object_policy_committed ?
			    object_preopened_ftruncate_denied(
				    object_write_preopen_fd) : 2,
			    "object-write policy denies preopened ftruncate");
	report_child_result(object_policy_committed ?
			    object_unmatched_ftruncate_allowed() : 2,
			    "object-write policy allows unmatched ftruncate");
	report_child_result(object_policy_committed ?
			    object_preopened_fallocate_write_denied(
				    object_write_preopen_fd) : 2,
			    "object-write policy denies preopened fallocate");
	report_child_result(object_policy_committed ?
			    object_truncate_write_allowed() : 2,
			    "object truncate policy allows ordinary write");
	report_child_result(object_policy_committed ?
			    object_truncate_path_denied() : 2,
			    "object truncate policy denies path truncate");
	report_child_result(object_policy_committed ?
			    object_truncate_unmatched_allowed() : 2,
			    "object truncate policy allows unmatched truncate");
	report_child_result(object_policy_committed ?
			    object_truncate_ftruncate_denied(
				    object_truncate_preopen_fd) : 2,
			    "object truncate policy denies preopened ftruncate");
	report_child_result(object_policy_committed ?
			    object_truncate_fallocate_denied(
				    object_truncate_preopen_fd) : 2,
			    "object truncate policy denies preopened fallocate");
	report_child_result(object_policy_committed ?
			    object_rename_denied() : 2,
			    "object rename policy denies protected rename");
	report_child_result(object_policy_committed ?
			    object_rename_unmatched_allowed() : 2,
			    "object rename policy allows unmatched rename");
	report_child_result(object_policy_committed ?
			    object_rename_target_denied() : 2,
			    "object rename-target policy denies protected target");
	report_child_result(object_policy_committed ?
			    object_rename_target_create_allowed() : 2,
			    "object rename-target policy allows ordinary create");
	report_child_result(object_policy_committed ?
			    object_link_target_denied() : 2,
			    "object link-target policy denies protected target");
	report_child_result(object_policy_committed ?
			    object_link_target_create_allowed() : 2,
			    "object link-target policy allows ordinary create");
	report_child_result(object_policy_committed ?
			    object_unix_connect_denied() : 2,
			    "object unix-connect policy denies protected socket connect");
		report_child_result(object_policy_committed ?
				    object_unix_connect_unmatched_allowed() : 2,
				    "object unix-connect policy allows unmatched socket connect");
		report_child_result(object_policy_committed ?
				    object_unix_bind_denied() : 2,
				    "object unix-bind policy denies protected socket bind");
		report_child_result(object_policy_committed ?
				    object_unix_bind_unmatched_allowed() : 2,
				    "object unix-bind policy allows unmatched socket bind");
		report_child_result(object_policy_committed ?
				    object_unix_listen_denied(
					    object_unix_listen_protected_fd) : 2,
				    "object unix-listen policy denies protected socket listen");
		report_child_result(object_policy_committed ?
				    object_unix_listen_unmatched_allowed(
					    object_unix_listen_unprotected_fd) : 2,
				    "object unix-listen policy allows unmatched socket listen");
		report_child_result(object_policy_committed ?
				    object_unix_accept_denied(
					    object_unix_accept_protected_fd) : 2,
				    "object unix-accept policy denies protected socket accept");
		report_child_result(object_policy_committed ?
				    object_unix_accept_unmatched_allowed(
					    object_unix_accept_unprotected_fd) : 2,
				    "object unix-accept policy allows unmatched socket accept");
		report_child_result(object_policy_committed ?
				    object_unix_send_denied() : 2,
				    "object unix-send policy denies protected datagram send");
		report_child_result(object_policy_committed ?
				    object_unix_send_unmatched_allowed() : 2,
				    "object unix-send policy allows unmatched datagram send");
		report_child_result(object_policy_committed ?
				    object_unix_connected_send_denied(
					    object_unix_connected_send_protected_fd) : 2,
				    "object unix-send policy denies preconnected datagram send");
		report_child_result(object_policy_committed ?
				    object_unix_connected_send_unmatched_allowed(
					    object_unix_connected_send_unprotected_fd) : 2,
				    "object unix-send policy allows unmatched preconnected datagram send");
		report_child_result(object_policy_committed ?
				    object_unix_recv_denied(
					    object_unix_recv_protected_fd) : 2,
				    "object unix-recv policy denies protected datagram receive");
		report_child_result(object_policy_committed ?
				    object_unix_recv_unmatched_allowed(
					    object_unix_recv_unprotected_fd) : 2,
				    "object unix-recv policy allows unmatched datagram receive");
		report_child_result(object_policy_committed ?
				    object_unix_abstract_connect_denied() : 2,
				    "object abstract unix-connect policy denies protected socket connect");
		report_child_result(object_policy_committed ?
				    object_unix_abstract_connect_unmatched_allowed() : 2,
				    "object abstract unix-connect policy allows unmatched socket connect");
		report_child_result(object_policy_committed ?
				    object_unix_abstract_bind_denied() : 2,
				    "object abstract unix-bind policy denies protected socket bind");
		report_child_result(object_policy_committed ?
				    object_unix_abstract_bind_unmatched_allowed() : 2,
				    "object abstract unix-bind policy allows unmatched socket bind");
		report_child_result(object_policy_committed ?
				    object_unix_listen_result(
					    object_unix_abs_listen_protected_fd,
					    false) : 2,
				    "object abstract unix-listen policy denies protected socket listen");
		report_child_result(object_policy_committed ?
				    object_unix_listen_result(
					    object_unix_abs_listen_unprotected_fd,
					    true) : 2,
				    "object abstract unix-listen policy allows unmatched socket listen");
		report_child_result(object_policy_committed ?
				    object_unix_abstract_accept_denied(
					    object_unix_abs_accept_protected_fd) : 2,
				    "object abstract unix-accept policy denies protected socket accept");
		report_child_result(object_policy_committed ?
				    object_unix_abstract_accept_unmatched_allowed(
					    object_unix_abs_accept_unprotected_fd) : 2,
				    "object abstract unix-accept policy allows unmatched socket accept");
		report_child_result(object_policy_committed ?
				    object_unix_abstract_send_denied() : 2,
				    "object abstract unix-send policy denies protected datagram send");
		report_child_result(object_policy_committed ?
				    object_unix_abstract_send_unmatched_allowed() : 2,
				    "object abstract unix-send policy allows unmatched datagram send");
		report_child_result(object_policy_committed ?
				    object_unix_connected_send_result(
					    object_unix_abs_connected_send_protected_fd,
					    false) : 2,
				    "object abstract unix-send policy denies preconnected datagram send");
		report_child_result(object_policy_committed ?
				    object_unix_connected_send_result(
					    object_unix_abs_connected_send_unprotected_fd,
					    true) : 2,
				    "object abstract unix-send policy allows unmatched preconnected datagram send");
		report_child_result(object_policy_committed ?
				    object_unix_abstract_recv_denied(
					    object_unix_abs_recv_protected_fd) : 2,
				    "object abstract unix-recv policy denies protected datagram receive");
		report_child_result(object_policy_committed ?
				    object_unix_abstract_recv_unmatched_allowed(
					    object_unix_abs_recv_unprotected_fd) : 2,
				    "object abstract unix-recv policy allows unmatched datagram receive");
		report_child_result(object_policy_committed ?
				    object_write_fifo_denied() : 2,
			    "object-write policy denies protected FIFO write open");
	report_child_result(object_policy_committed ?
			    object_write_fifo_unmatched_allowed() : 2,
			    "object-write policy allows unmatched FIFO write open");
	report_child_result(object_policy_committed ?
			    object_write_chrdev_denied() : 2,
			    "object-write policy denies protected character device write open");
	report_child_result(object_policy_committed ?
			    object_write_chrdev_unmatched_allowed() : 2,
			    "object-write policy allows unmatched character device write open");
	report_child_result(object_policy_committed ?
			    object_write_blkdev_denied() : 2,
			    "object-write policy denies protected block device write open");
	report_child_result(object_policy_committed ?
			    object_write_blkdev_unmatched_allowed() : 2,
			    "object-write policy allows unmatched block device write open");
	report_child_result(object_policy_committed ?
			    object_preopened_splice_write_denied(
				    object_write_preopen_fd) : 2,
			    "object-write policy denies preopened splice write");
	report_child_result(object_policy_committed ?
			    object_preopened_copy_file_range_write_denied(
				    object_write_preopen_fd) : 2,
			    "object-write policy denies preopened copy_file_range write");
	report_child_result(object_policy_committed ?
			    object_preopened_sendfile_dest_write_denied(
				    object_write_preopen_fd) : 2,
			    "object-write policy denies preopened sendfile write");
	report_child_result(object_policy_committed ?
			    object_sendfile_unmatched_dest_write_allowed() : 2,
			    "object-write policy allows unmatched sendfile write");
			report_child_result(object_policy_committed ?
					    object_preopened_clone_dest_write_denied(
						    object_write_preopen_fd) : 2,
					    "object-write policy denies preopened clone write");
			report_child_result(object_policy_committed ?
					    object_preopened_clone_range_dest_write_denied(
						    object_write_preopen_fd) : 2,
					    "object-write policy denies preopened clone-range write");
			report_child_result(object_policy_committed ?
					    object_preopened_io_uring_write_denied(
						    object_write_preopen_fd) : 2,
					    "object-write policy denies preopened io_uring write");
			report_child_result(object_policy_committed ?
					    object_io_uring_unmatched_write_allowed() : 2,
					    "object-write policy allows unmatched io_uring write");
			report_child_result(object_policy_committed ?
					    object_preopened_legacy_aio_write_denied(
						    object_write_preopen_fd) : 2,
				    "object-write policy denies preopened legacy AIO write");
		report_child_result(object_policy_committed ?
				    object_legacy_aio_unmatched_write_allowed() : 2,
				    "object-write policy allows unmatched legacy AIO write");
		report_child_result(object_policy_committed ?
				    object_preopened_shared_mmap_write_denied(
					    object_write_preopen_fd) : 2,
				    "object-write policy denies preopened shared writable mmap");
	report_child_result(object_policy_committed ?
			    object_preopened_shared_mprotect_write_denied(
				    object_write_preopen_fd) : 2,
			    "object-write policy denies preopened shared writable mprotect");
	report_child_result(object_policy_committed ?
			    object_unprotected_shared_mmap_write_allowed() : 2,
			    "object-write policy allows unmatched shared writable mmap");
	report_child_result(object_policy_committed ?
			    object_protected_read_open_denied() : 2,
			    "object-read policy denies protected file open");
		report_child_result(object_policy_committed ?
				    object_preopened_read_denied(object_preopen_fd) : 2,
				    "object-read policy denies preopened file read");
			report_child_result(object_policy_committed ?
					    object_preopened_clone_source_read_denied(
						    object_preopen_fd) : 2,
					    "object-read policy denies preopened clone source read");
			report_child_result(object_policy_committed ?
					    object_preopened_clone_range_source_read_denied(
						    object_preopen_fd) : 2,
					    "object-read policy denies preopened clone-range source read");
			report_child_result(object_policy_committed ?
					    object_preopened_copy_file_range_source_read_denied(
						    object_preopen_fd) : 2,
					    "object-read policy denies preopened copy_file_range source read");
			report_child_result(object_policy_committed ?
					    object_copy_file_range_unmatched_source_read_allowed() : 2,
					    "object-read policy allows unmatched copy_file_range source read");
			report_child_result(object_policy_committed ?
					    object_preopened_splice_source_read_denied(
						    object_preopen_fd) : 2,
					    "object-read policy denies preopened splice source read");
			report_child_result(object_policy_committed ?
					    object_splice_unmatched_source_read_allowed() : 2,
					    "object-read policy allows unmatched splice source read");
			report_child_result(object_policy_committed ?
					    object_preopened_sendfile_source_read_denied(
						    object_preopen_fd) : 2,
					    "object-read policy denies preopened sendfile source read");
				report_child_result(object_policy_committed ?
						    object_sendfile_unmatched_source_read_allowed() : 2,
						    "object-read policy allows unmatched sendfile source read");
				report_child_result(object_policy_committed ?
						    object_preopened_io_uring_read_denied(
							    object_preopen_fd) : 2,
						    "object-read policy denies preopened io_uring read");
					report_child_result(object_policy_committed ?
							    object_io_uring_unmatched_read_allowed() : 2,
							    "object-read policy allows unmatched io_uring read");
					report_child_result(object_policy_committed ?
							    object_preopened_legacy_aio_read_denied(
								    object_preopen_fd) : 2,
							    "object-read policy denies preopened legacy AIO read");
					report_child_result(object_policy_committed ?
							    object_legacy_aio_unmatched_read_allowed() : 2,
							    "object-read policy allows unmatched legacy AIO read");
					report_child_result(object_policy_committed ?
							    object_unprotected_read_allowed() : 2,
							    "object-read policy allows unmatched file read");
			report_child_result(object_policy_committed ?
					    object_read_fifo_denied() : 2,
					    "object-read policy denies protected FIFO read open");
			report_child_result(object_policy_committed ?
					    object_read_fifo_unmatched_allowed() : 2,
					    "object-read policy allows unmatched FIFO read open");
			report_child_result(object_policy_committed ?
					    object_read_chrdev_denied() : 2,
					    "object-read policy denies protected character device read open");
			report_child_result(object_policy_committed ?
					    object_read_chrdev_unmatched_allowed() : 2,
					    "object-read policy allows unmatched character device read open");
			report_child_result(object_policy_committed ?
					    object_read_blkdev_denied() : 2,
					    "object-read policy denies protected block device read open");
			report_child_result(object_policy_committed ?
					    object_read_blkdev_unmatched_allowed() : 2,
					    "object-read policy allows unmatched block device read open");
			report_child_result(object_policy_committed ?
					    object_preopened_read_mmap_denied(
						    object_preopen_fd) : 2,
					    "object-read policy denies preopened readable mmap");
				report_child_result(object_policy_committed ?
						    object_unprotected_read_mmap_allowed() : 2,
						    "object-read policy allows unmatched readable mmap");
				report_child_result(object_policy_committed ?
						    object_preopened_read_mprotect_denied(
							    object_preopen_fd) : 2,
						    "object-read policy denies preopened readable mprotect");
				report_child_result(object_policy_committed ?
						    object_unprotected_read_mprotect_allowed() : 2,
						    "object-read policy allows unmatched readable mprotect");
				report_child_result(object_policy_committed ?
						    object_protected_readlink_denied() : 2,
						    "object-read policy denies protected symlink readlink");
		report_child_result(object_policy_committed ?
				    object_unprotected_readlink_allowed() : 2,
				    "object-read policy allows unmatched symlink readlink");
		report_child_result(object_policy_committed ?
				    object_protected_delete_denied() : 2,
				    "object-delete policy denies protected file unlink");
	report_child_result(object_policy_committed ?
			    object_protected_rename_denied() : 2,
			    "object-delete policy denies protected file rename");
	report_child_result(object_policy_committed ?
			    object_protected_replace_denied() : 2,
			    "object-delete policy denies replacing protected file");
	report_child_result(object_policy_committed ?
			    object_unprotected_delete_allowed() : 2,
			    "object-delete policy allows unmatched file unlink");
	report_child_result(object_policy_committed ?
			    object_protected_rmdir_denied() : 2,
			    "object-delete policy denies protected directory rmdir");
	report_child_result(object_policy_committed ?
			    object_protected_dir_rename_denied() : 2,
			    "object-delete policy denies protected directory rename");
	report_child_result(object_policy_committed ?
			    object_unprotected_rmdir_allowed() : 2,
			    "object-delete policy allows unmatched directory rmdir");
	report_child_result(object_policy_committed ?
			    object_protected_create_file_denied() : 2,
			    "object-create policy denies protected file create");
		report_child_result(object_policy_committed ?
				    object_unprotected_create_file_allowed() : 2,
				    "object-create policy allows unmatched file create");
		report_child_result(object_policy_committed ?
				    object_protected_tmpfile_denied() : 2,
				    "object-create policy denies protected tmpfile");
		report_child_result(object_policy_committed ?
				    object_unprotected_tmpfile_allowed() : 2,
				    "object-create policy allows unmatched tmpfile");
		report_child_result(object_policy_committed ?
				    object_protected_mkdir_denied() : 2,
				    "object-create policy denies protected mkdir");
		report_child_result(object_policy_committed ?
				    object_protected_symlink_denied() : 2,
				    "object-create policy denies protected symlink");
		report_child_result(object_policy_committed ?
				    object_protected_fifo_denied() : 2,
				    "object-create policy denies protected FIFO");
		report_child_result(object_policy_committed ?
				    object_unprotected_fifo_allowed() : 2,
				    "object-create policy allows unmatched FIFO");
		report_child_result(object_policy_committed ?
				    object_protected_chrdev_denied() : 2,
				    "object-create policy denies protected character device");
		report_child_result(object_policy_committed ?
				    object_unprotected_chrdev_allowed() : 2,
				    "object-create policy allows unmatched character device");
		report_child_result(object_policy_committed ?
				    object_protected_blkdev_denied() : 2,
				    "object-create policy denies protected block device");
		report_child_result(object_policy_committed ?
				    object_unprotected_blkdev_allowed() : 2,
				    "object-create policy allows unmatched block device");
		report_child_result(object_policy_committed ?
				    object_protected_link_denied() : 2,
				    "object-create policy denies protected hardlink");
	report_child_result(object_policy_committed ?
			    object_protected_rename_into_denied() : 2,
			    "object-create policy denies protected rename target");
	report_child_result(object_policy_committed ?
			    object_creat_denied() : 2,
			    "object creat policy denies protected file create");
	report_child_result(object_policy_committed ?
			    object_mkdir_denied() : 2,
			    "object mkdir policy denies protected directory create");
	report_child_result(object_policy_committed ?
			    object_mknod_denied() : 2,
			    "object mknod policy denies protected node create");
	report_child_result(object_policy_committed ?
			    object_symlink_denied() : 2,
			    "object symlink policy denies protected symlink create");
	report_child_result(object_policy_committed ?
			    object_unlink_denied() : 2,
			    "object unlink policy denies protected file unlink");
	report_child_result(object_policy_committed ?
			    object_rmdir_denied() : 2,
			    "object rmdir policy denies protected directory rmdir");
	report_child_result(object_policy_committed ?
			    object_split_create_unmatched_allowed() : 2,
			    "object split create policy allows unmatched create operations");
	report_child_result(object_policy_committed ?
			    object_split_delete_unmatched_allowed() : 2,
			    "object split delete policy allows unmatched delete operations");
	report_child_result(object_policy_committed ?
			    object_protected_exec_denied() : 2,
			    "object-exec policy denies protected exec");
	report_child_result(object_policy_committed ?
			    object_unprotected_exec_allowed() : 2,
			    "object-exec policy allows unmatched exec");
	report_child_result(object_policy_committed ?
			    object_protected_exec_mmap_denied() : 2,
			    "object-exec policy denies protected executable mmap");
	report_child_result(object_policy_committed ?
			    object_protected_exec_mprotect_denied() : 2,
			    "object-exec policy denies protected executable mprotect");
	report_child_result(object_policy_committed ?
			    object_append_only_append_allowed() : 2,
			    "object append-only policy allows append write");
			report_child_result(object_policy_committed ?
					    object_append_only_preopened_write_denied(
						    object_append_preopen_fd) : 2,
					    "object append-only policy denies preopened rewrite");
			report_child_result(object_policy_committed ?
					    object_append_only_io_uring_write_denied(
						    object_append_preopen_fd) : 2,
					    "object append-only policy denies preopened io_uring rewrite");
			report_child_result(object_policy_committed ?
					    object_append_only_io_uring_append_allowed(
						    object_append_preopen_fd) : 2,
					    "object append-only policy allows io_uring append");
			report_child_result(object_policy_committed ?
					    object_append_only_legacy_aio_write_denied(
						    object_append_preopen_fd) : 2,
				    "object append-only policy denies preopened legacy AIO rewrite");
		report_child_result(object_policy_committed ?
				    object_append_only_legacy_aio_append_allowed(
					    object_append_preopen_fd) : 2,
				    "object append-only policy allows legacy AIO append");
		report_child_result(object_policy_committed ?
				    object_preopened_splice_write_denied(
					    object_append_preopen_fd) : 2,
			    "object append-only policy denies preopened splice write");
	report_child_result(object_policy_committed ?
			    object_preopened_copy_file_range_write_denied(
				    object_append_preopen_fd) : 2,
			    "object append-only policy denies preopened copy_file_range write");
	report_child_result(object_policy_committed ?
			    object_preopened_sendfile_dest_write_denied(
				    object_append_preopen_fd) : 2,
			    "object append-only policy denies preopened sendfile write");
	report_child_result(object_policy_committed ?
			    object_preopened_clone_dest_write_denied(
				    object_append_preopen_fd) : 2,
			    "object append-only policy denies preopened clone write");
	report_child_result(object_policy_committed ?
			    object_preopened_clone_range_dest_write_denied(
				    object_append_preopen_fd) : 2,
			    "object append-only policy denies preopened clone-range write");
	report_child_result(object_policy_committed ?
			    object_preopened_shared_mmap_write_denied(
				    object_append_preopen_fd) : 2,
			    "object append-only policy denies preopened shared writable mmap");
	report_child_result(object_policy_committed ?
			    object_preopened_shared_mprotect_write_denied(
				    object_append_preopen_fd) : 2,
			    "object append-only policy denies preopened shared writable mprotect");
	report_child_result(object_policy_committed ?
			    object_append_only_truncate_denied() : 2,
			    "object append-only policy denies truncate");
	report_child_result(object_policy_committed ?
			    object_preopened_ftruncate_denied(
				    object_append_preopen_fd) : 2,
			    "object append-only policy denies preopened ftruncate");
	report_child_result(object_policy_committed ?
			    object_append_only_fallocate_denied() : 2,
			    "object append-only policy denies fallocate");
	report_child_result(object_policy_committed ?
			    object_protected_link_source_denied() : 2,
			    "object link policy denies protected source hardlink");
	report_child_result(object_policy_committed ?
			    object_unprotected_link_source_allowed() : 2,
			    "object link policy allows unmatched source hardlink");
	report_child_result(object_policy_committed ?
			    object_attr_chmod_denied() : 2,
			    "object attr policy denies protected chmod");
	report_child_result(object_policy_committed ?
			    object_attr_chown_denied() : 2,
			    "object attr policy denies protected chown");
	report_child_result(object_policy_committed ?
			    object_attr_timestamp_denied() : 2,
			    "object attr policy denies protected timestamps");
	report_child_result(object_policy_committed && object_attr_xattr_prepared ?
			    object_attr_setxattr_denied() : 2,
			    "object attr policy denies protected setxattr");
	report_child_result(object_policy_committed && object_attr_xattr_prepared ?
			    object_attr_removexattr_denied() : 2,
			    "object attr policy denies protected removexattr");
	report_child_result(object_policy_committed && object_fileattr_prepared ?
			    object_attr_fileattr_denied() : 2,
			    "object attr policy denies protected fileattr ioctl");
	report_child_result(object_policy_committed && object_fileattr_prepared ?
			    object_attr_fileattr_unmatched_allowed() : 2,
			    "object attr policy allows unmatched fileattr ioctl");
	report_child_result(object_policy_committed ?
			    object_attr_unmatched_chmod_allowed() : 2,
			    "object attr policy allows unmatched chmod");
	report_child_result(object_policy_committed ?
			    object_attr_unmatched_xattr_allowed() : 2,
			    "object attr policy allows unmatched xattr mutation");
	report_child_result(object_policy_committed ?
			    object_chmod_denied() : 2,
			    "object chmod policy denies protected chmod");
	report_child_result(object_policy_committed ?
			    object_setid_chmod_denied() : 2,
			    "object setid policy denies protected setuid chmod");
	report_child_result(object_policy_committed ?
			    object_setid_chmod_ordinary_allowed() : 2,
			    "object setid policy allows ordinary chmod");
	report_child_result(object_policy_committed ?
			    object_setid_chmod_unmatched_allowed() : 2,
			    "object setid policy allows unmatched setuid chmod");
	report_child_result(object_policy_committed ?
			    object_setid_create_denied() : 2,
			    "object setid policy denies protected setuid create");
	report_child_result(object_policy_committed ?
			    object_setid_create_ordinary_allowed() : 2,
			    "object setid policy allows ordinary create");
	report_child_result(object_policy_committed ?
			    object_setid_create_unmatched_allowed() : 2,
			    "object setid policy allows unmatched setuid create");
	report_child_result(object_policy_committed ?
			    object_setid_mknod_denied() : 2,
			    "object setid policy denies protected setgid mknod");
	report_child_result(object_policy_committed ?
			    object_setid_mknod_ordinary_allowed() : 2,
			    "object setid policy allows ordinary mknod");
	report_child_result(object_policy_committed ?
			    object_ptrace_denied() : 2,
			    "object ptrace policy denies protected executable target");
	report_child_result(object_policy_committed ?
			    object_chown_denied() : 2,
			    "object chown policy denies protected chown");
	report_child_result(object_policy_committed ?
			    object_utime_denied() : 2,
			    "object utime policy denies protected timestamp change");
	report_child_result(object_policy_committed ?
			    object_setxattr_denied() : 2,
			    "object setxattr policy denies protected setxattr");
	report_child_result(object_policy_committed && object_split_xattr_prepared ?
			    object_removexattr_denied() : 2,
			    "object removexattr policy denies protected removexattr");
	report_child_result(object_policy_committed ?
			    object_split_attr_unmatched_allowed() : 2,
			    "object split metadata policy allows unmatched metadata/xattr changes");
	report_child_result(object_policy_committed && object_xattr_prepared ?
			    object_xattr_get_denied() : 2,
			    "object xattr policy denies protected getxattr");
	report_child_result(object_policy_committed && object_xattr_prepared ?
			    object_xattr_list_denied() : 2,
			    "object xattr policy denies protected listxattr");
	report_child_result(object_policy_committed ?
			    object_xattr_acl_get_denied() : 2,
			    "object xattr policy denies protected POSIX ACL getxattr");
	report_child_result(object_policy_committed && object_xattr_prepared ?
			    object_xattr_unmatched_get_allowed() : 2,
			    "object xattr policy allows unmatched getxattr");
	report_child_result(object_policy_committed && object_xattr_prepared ?
			    object_xattr_unmatched_list_allowed() : 2,
			    "object xattr policy allows unmatched listxattr");
	report_child_result(object_policy_committed ?
			    object_access_explicit_denied() : 2,
			    "object access policy denies protected access probe");
	report_child_result(object_policy_committed ?
			    object_access_unmatched_allowed() : 2,
			    "object access policy allows unmatched access probe");
	report_child_result(object_policy_committed ?
			    object_access_read_probe_denied() : 2,
			    "object access policy denies read access probe");
	report_child_result(object_policy_committed ?
			    object_access_write_probe_denied() : 2,
			    "object access policy denies write access probe");
	report_child_result(object_policy_committed ?
			    object_access_exec_probe_denied() : 2,
			    "object access policy denies exec access probe");
	report_child_result(object_policy_committed ?
			    object_stat_path_denied() : 2,
			    "object stat policy denies protected stat");
	report_child_result(object_policy_committed ?
			    object_stat_preopened_denied(object_stat_preopen_fd) : 2,
			    "object stat policy denies preopened fstat");
	report_child_result(object_policy_committed && object_fileattr_prepared ?
			    object_stat_filegetattr_denied() : 2,
			    "object stat policy denies protected fileattr ioctl");
	report_child_result(object_policy_committed && object_fileattr_prepared ?
			    object_stat_filegetattr_unmatched_allowed() : 2,
			    "object stat policy allows unmatched fileattr ioctl");
	report_child_result(object_policy_committed ?
			    object_stat_unmatched_allowed() : 2,
			    "object stat policy allows unmatched stat");
	report_child_result(object_policy_committed ?
			    object_list_path_denied_test() : 2,
			    "object list policy denies protected readdir");
	report_child_result(object_policy_committed ?
			    object_list_preopened_denied(
				    object_list_preopen_fd) : 2,
			    "object list policy denies preopened readdir");
	report_child_result(object_policy_committed ?
			    object_list_unmatched_allowed() : 2,
			    "object list policy allows unmatched readdir");
	report_child_result(object_policy_committed ?
			    object_find_path_denied() : 2,
			    "object find policy denies protected O_PATH lookup");
	report_child_result(object_policy_committed ?
			    object_find_opath_allowed() : 2,
			    "object find policy allows unmatched O_PATH lookup");
	report_child_result(object_policy_committed ?
			    object_find_regular_open_denied() : 2,
			    "object find policy denies protected regular open");
	report_child_result(object_policy_committed ?
			    object_find_regular_open_allowed() : 2,
			    "object find policy allows unmatched regular open");
	report_child_result(object_policy_committed ?
			    object_find_handle_denied() : 2,
			    "object find policy denies protected file handle export");
	report_child_result(object_policy_committed ?
			    object_ioctl_denied() : 2,
			    "object ioctl policy denies protected ioctl");
	report_child_result(object_policy_committed ?
			    object_ioctl_unmatched_allowed() : 2,
			    "object ioctl policy allows unmatched ioctl");
	report_child_result(object_policy_committed ?
			    object_flock_denied() : 2,
			    "object lock policy denies protected flock");
	report_child_result(object_policy_committed ?
			    object_posix_lock_denied() : 2,
			    "object lock policy denies protected POSIX lock");
	report_child_result(object_policy_committed ?
			    object_flock_unmatched_allowed() : 2,
			    "object lock policy allows unmatched flock");
	report_child_result(object_policy_committed ?
			    object_posix_lock_unmatched_allowed() : 2,
			    "object lock policy allows unmatched POSIX lock");
	report_child_result(object_policy_committed ?
			    object_ofd_lock_denied() : 2,
			    "object lock policy denies protected OFD lock");
	report_child_result(object_policy_committed ?
			    object_ofd_lock_unmatched_allowed() : 2,
			    "object lock policy allows unmatched OFD lock");
	report_child_result(object_policy_committed ?
			    object_lease_denied() : 2,
			    "object lock policy denies protected file lease");
	report_child_result(object_policy_committed ?
			    object_lease_unmatched_allowed() : 2,
			    "object lock policy allows unmatched file lease");
	report_child_result(object_policy_committed ?
			    object_watch_denied() : 2,
			    "object watch policy denies protected inotify watch");
		report_child_result(object_policy_committed ?
				    object_watch_unmatched_allowed() : 2,
				    "object watch policy allows unmatched inotify watch");
		report_child_result(object_policy_committed ?
				    object_dnotify_watch_denied() : 2,
				    "object watch policy denies protected dnotify watch");
		report_child_result(object_policy_committed ?
				    object_dnotify_watch_unmatched_allowed() : 2,
				    "object watch policy allows unmatched dnotify watch");
		report_child_result(object_policy_committed ?
				    object_fanotify_watch_denied() : 2,
				    "object watch policy denies protected fanotify watch");
		report_child_result(object_policy_committed ?
				    object_fanotify_watch_unmatched_allowed() : 2,
				    "object watch policy allows unmatched fanotify watch");
		report_child_result(object_policy_committed ?
				    object_receive_denied() : 2,
				    "object receive policy denies protected fd receive");
			report_child_result(object_policy_committed ?
					    object_receive_unmatched_allowed() : 2,
					    "object receive policy allows unmatched fd receive");
			report_child_result(object_policy_committed ?
					    object_fcntl_dup_denied() : 2,
					    "object fcntl policy denies protected fd duplication");
			report_child_result(object_policy_committed ?
					    object_fcntl_unmatched_dup_allowed() : 2,
					    "object fcntl policy allows unmatched fd duplication");
			report_child_result(object_policy_committed ?
					    object_fcntl_ioctl_flag_denied() : 2,
					    "object fcntl policy denies protected ioctl flag alias");
				report_child_result(object_policy_committed ?
						    object_fcntl_ioctl_flag_unmatched_allowed() : 2,
						    "object fcntl policy allows unmatched ioctl flag alias");
				report_child_result(object_policy_committed ?
						    object_fcntl_setfl_denied() : 2,
						    "object fcntl policy denies protected direct flag change");
					report_child_result(object_policy_committed ?
							    object_fcntl_setfl_unmatched_allowed() : 2,
							    "object fcntl policy allows unmatched direct flag change");
					report_child_result(object_policy_committed ?
							    object_fcntl_setfd_denied() : 2,
							    "object fcntl policy denies protected descriptor flag change");
					report_child_result(object_policy_committed ?
							    object_fcntl_setfd_unmatched_allowed() : 2,
							    "object fcntl policy allows unmatched descriptor flag change");
					report_child_result(object_policy_committed ?
							    object_fcntl_setown_denied() : 2,
							    "object fcntl policy denies protected owner change");
					report_child_result(object_policy_committed ?
							    object_fcntl_setown_unmatched_allowed() : 2,
							    "object fcntl policy allows unmatched owner change");
					report_child_result(object_policy_committed ?
							    object_fcntl_setown_ex_denied() : 2,
							    "object fcntl policy denies protected extended owner change");
					report_child_result(object_policy_committed ?
							    object_fcntl_setown_ex_unmatched_allowed() : 2,
							    "object fcntl policy allows unmatched extended owner change");
					report_child_result(object_policy_committed ?
							    object_fcntl_setsig_denied() : 2,
							    "object fcntl policy denies protected signal change");
					report_child_result(object_policy_committed ?
							    object_fcntl_setsig_unmatched_allowed() : 2,
							    "object fcntl policy allows unmatched signal change");
					report_child_result(object_policy_committed ?
							    object_fcntl_query_allowed() : 2,
							    "object fcntl policy allows protected status query");
			report_child_result(object_policy_committed ?
					    object_chdir_denied() : 2,
					    "object chdir policy denies protected chdir");
			report_child_result(object_policy_committed ?
					    object_chdir_unmatched_allowed() : 2,
					    "object chdir policy allows unmatched chdir");
			report_child_result(object_policy_committed ?
					    object_preopened_fchdir_denied(
						    object_chdir_preopen_fd) : 2,
					    "object chdir policy denies preopened fchdir");
			report_child_result(object_policy_committed ?
					    object_fchdir_unmatched_allowed() : 2,
					    "object chdir policy allows unmatched fchdir");
			report_child_result(object_policy_committed ?
					    object_mount_denied() : 2,
					    "object mount policy denies protected mount target");
			report_child_result(object_policy_committed ?
					    object_mount_unmatched_allowed() : 2,
					    "object mount policy allows unmatched mount target");
			report_child_result(object_policy_committed ?
					    object_move_mount_denied() : 2,
					    "object mount policy denies protected move_mount target");
			report_child_result(object_policy_committed ?
					    object_move_mount_unmatched_allowed() : 2,
					    "object mount policy allows unmatched move_mount target");
			report_child_result(object_policy_committed ?
					    object_mount_source_denied() : 2,
					    "object mount-source policy denies protected move_mount source");
			report_child_result(object_policy_committed ?
					    object_mount_source_unmatched_allowed() : 2,
					    "object mount-source policy allows unmatched move_mount source");
			report_child_result(object_policy_committed ?
					    object_umount_denied() : 2,
					    "object umount policy denies protected mount");
			report_child_result(object_policy_committed ?
					    object_umount_unmatched_allowed() : 2,
					    "object umount policy allows unmatched mount");
		report_child_result(object_policy_committed ?
				    object_find_readdir_entry_hidden() : 2,
			    "object find policy hides protected readdir entry");
	report_child_result(object_policy_committed ?
			    object_find_tree_readdir_entry_hidden() : 2,
			    "object find tree policy hides nested readdir entry");
	report_child_result(object_policy_committed ?
			    object_tree_read_denied() : 2,
			    "object tree policy denies nested read");
		report_child_result(object_policy_committed ?
				    object_tree_write_denied() : 2,
				    "object tree policy denies nested write");
		report_child_result(object_policy_committed ?
				    object_tree_delete_denied() : 2,
				    "object tree policy denies nested delete");
		report_child_result(object_policy_committed ?
				    object_tree_rmdir_denied() : 2,
				    "object tree policy denies nested rmdir");
		report_child_result(object_policy_committed ?
				    object_tree_create_denied() : 2,
				    "object tree policy denies nested create");
	report_child_result(object_policy_committed ?
			    object_tree_attr_denied() : 2,
			    "object tree policy denies nested attr");
	report_child_result(object_policy_committed ?
			    object_tree_xattr_denied() : 2,
			    "object tree policy denies nested xattr");
	report_child_result(object_policy_committed ?
			    object_tree_access_denied() : 2,
			    "object tree policy denies nested access probe");
	report_child_result(object_policy_committed ?
			    object_tree_stat_denied() : 2,
			    "object tree policy denies nested stat");
	report_child_result(object_policy_committed ?
			    object_tree_list_denied() : 2,
			    "object tree policy denies nested readdir");
	report_child_result(object_policy_committed ?
			    object_tree_find_denied() : 2,
			    "object tree policy denies nested O_PATH lookup");
	report_child_result(object_policy_committed ?
			    object_tree_exec_denied() : 2,
			    "object tree ops policy denies nested exec");
	report_child_result(object_policy_committed ?
			    object_tree_link_source_denied() : 2,
			    "object tree ops policy denies nested hardlink source");
	report_child_result(object_policy_committed ?
			    object_tree_link_target_denied() : 2,
			    "object tree target policy denies nested hardlink target");
	report_child_result(object_policy_committed ?
			    object_tree_ioctl_denied() : 2,
			    "object tree ops policy denies nested ioctl");
	report_child_result(object_policy_committed ?
			    object_tree_lock_denied() : 2,
			    "object tree ops policy denies nested lock");
	report_child_result(object_policy_committed ?
			    object_tree_watch_denied() : 2,
			    "object tree ops policy denies nested inotify watch");
	report_child_result(object_policy_committed ?
			    object_tree_fcntl_dup_denied() : 2,
			    "object tree ops policy denies nested fd duplication");
	report_child_result(object_policy_committed ?
			    object_tree_chdir_denied() : 2,
			    "object tree ops policy denies nested chdir");
	report_child_result(object_policy_committed ?
			    object_tree_preopened_fchdir_denied(
				    object_tree_chdir_preopen_fd) : 2,
			    "object tree ops policy denies preopened nested fchdir");
	report_child_result(object_policy_committed ?
			    object_tree_truncate_denied() : 2,
			    "object tree ops policy denies nested truncate");
	report_child_result(object_policy_committed ?
			    object_tree_preopened_ftruncate_denied(
				    object_tree_truncate_preopen_fd) : 2,
			    "object tree ops policy denies preopened nested ftruncate");
	report_child_result(object_policy_committed ?
			    object_tree_rename_denied() : 2,
			    "object tree ops policy denies nested source rename");
	report_child_result(object_policy_committed ?
			    object_tree_rename_target_denied() : 2,
			    "object tree target policy denies nested rename target");
	report_child_result(object_policy_committed ?
			    object_tree_unix_connect_denied() : 2,
			    "object tree ops policy denies nested socket connect");
	report_child_result(object_policy_committed ?
			    object_tree_exec_unmatched_allowed() : 2,
			    "object tree ops policy allows unmatched exec");
	report_child_result(object_policy_committed ?
			    object_tree_link_source_unmatched_allowed() : 2,
			    "object tree ops policy allows unmatched hardlink source");
	report_child_result(object_policy_committed ?
			    object_tree_link_target_create_allowed() : 2,
			    "object tree target policy allows nested ordinary create after link-target rule");
	report_child_result(object_policy_committed ?
			    object_tree_link_target_unmatched_allowed() : 2,
			    "object tree target policy allows unmatched nested hardlink target");
	report_child_result(object_policy_committed ?
			    object_tree_ioctl_unmatched_allowed() : 2,
			    "object tree ops policy allows unmatched ioctl");
	report_child_result(object_policy_committed ?
			    object_tree_lock_unmatched_allowed() : 2,
			    "object tree ops policy allows unmatched lock");
	report_child_result(object_policy_committed ?
			    object_tree_watch_unmatched_allowed() : 2,
			    "object tree ops policy allows unmatched inotify watch");
	report_child_result(object_policy_committed ?
			    object_tree_fcntl_dup_unmatched_allowed() : 2,
			    "object tree ops policy allows unmatched fd duplication");
		report_child_result(object_policy_committed ?
				    object_tree_chdir_unmatched_allowed() : 2,
				    "object tree ops policy allows unmatched chdir");
		report_child_result(object_policy_committed ?
				    object_tree_preopened_fchdir_unmatched_allowed(
					    object_tree_chdir_unmatched_preopen_fd) : 2,
				    "object tree ops policy allows preopened unmatched fchdir");
		report_child_result(object_policy_committed ?
				    object_tree_truncate_unmatched_allowed() : 2,
				    "object tree ops policy allows unmatched truncate");
		report_child_result(object_policy_committed ?
				    object_tree_preopened_ftruncate_unmatched_allowed(
					    object_tree_truncate_unmatched_preopen_fd) : 2,
				    "object tree ops policy allows preopened unmatched ftruncate");
	report_child_result(object_policy_committed ?
			    object_tree_rename_unmatched_allowed() : 2,
			    "object tree ops policy allows unmatched source rename");
	report_child_result(object_policy_committed ?
			    object_tree_rename_target_create_allowed() : 2,
			    "object tree target policy allows nested ordinary create after rename-target rule");
	report_child_result(object_policy_committed ?
			    object_tree_rename_target_unmatched_allowed() : 2,
			    "object tree target policy allows unmatched nested rename target");
	report_child_result(object_policy_committed ?
			    object_tree_unix_connect_unmatched_allowed() : 2,
			    "object tree ops policy allows unmatched socket connect");
	report_child_result(object_policy_committed ?
			    object_tree_receive_denied() : 2,
			    "object tree receive policy denies nested fd receive");
	report_child_result(object_policy_committed ?
			    object_tree_mount_denied() : 2,
			    "object tree mount policy denies nested mount target");
	report_child_result(object_policy_committed ?
			    object_tree_move_mount_denied() : 2,
			    "object tree mount policy denies nested move_mount target");
	report_child_result(object_policy_committed ?
			    object_tree_umount_denied() : 2,
			    "object tree umount policy denies mounted tree root");
	report_child_result(object_policy_committed ?
			    object_tree_receive_unmatched_allowed() : 2,
			    "object tree receive policy allows unmatched fd receive");
	report_child_result(object_policy_committed ?
			    object_tree_mount_unmatched_allowed() : 2,
			    "object tree mount policy allows unmatched mount target");
	report_child_result(object_policy_committed ?
			    object_tree_move_mount_unmatched_allowed() : 2,
			    "object tree mount policy allows unmatched move_mount target");
	report_child_result(object_policy_committed ?
			    object_tree_umount_unmatched_allowed() : 2,
			    "object tree umount policy allows unmatched mounted target");
	report_child_result(object_policy_committed ?
			    object_tree_chmod_denied() : 2,
			    "object tree metadata policy denies nested chmod");
	report_child_result(object_policy_committed ?
			    object_tree_chown_denied() : 2,
			    "object tree metadata policy denies nested chown");
	report_child_result(object_policy_committed ?
			    object_tree_utime_denied() : 2,
			    "object tree metadata policy denies nested timestamp change");
	report_child_result(object_policy_committed ?
			    object_tree_setxattr_denied() : 2,
			    "object tree metadata policy denies nested setxattr");
	report_child_result(object_policy_committed && object_tree_xattr_prepared ?
			    object_tree_removexattr_denied() : 2,
			    "object tree metadata policy denies nested removexattr");
	report_child_result(object_policy_committed && object_tree_xattr_prepared ?
			    object_tree_xattr_get_denied() : 2,
			    "object tree metadata policy denies nested getxattr");
	report_child_result(object_policy_committed && object_tree_xattr_prepared ?
			    object_tree_xattr_list_denied() : 2,
			    "object tree metadata policy denies nested listxattr");
	report_child_result(object_policy_committed ?
			    object_tree_unix_bind_denied() : 2,
			    "object tree IPC policy denies nested socket bind");
	report_child_result(object_policy_committed ?
			    object_tree_unix_listen_denied(
				    object_tree_unix_listen_fd) : 2,
			    "object tree IPC policy denies nested socket listen");
	report_child_result(object_policy_committed ?
			    object_tree_unix_accept_denied(
				    object_tree_unix_accept_fd) : 2,
			    "object tree IPC policy denies nested socket accept");
	report_child_result(object_policy_committed ?
			    object_tree_unix_send_denied() : 2,
			    "object tree IPC policy denies nested datagram send");
	report_child_result(object_policy_committed ?
			    object_tree_unix_connected_send_denied(
				    object_tree_unix_connected_send_fd) : 2,
			    "object tree IPC policy denies preconnected nested datagram send");
	report_child_result(object_policy_committed ?
			    object_tree_unix_recv_denied(
				    object_tree_unix_recv_fd) : 2,
			    "object tree IPC policy denies nested datagram receive");
	report_child_result(object_policy_committed ?
			    object_tree_creat_denied() : 2,
			    "object tree split policy denies nested file create");
	report_child_result(object_policy_committed ?
			    object_tree_mkdir_denied() : 2,
			    "object tree split policy denies nested directory create");
	report_child_result(object_policy_committed ?
			    object_tree_mknod_denied() : 2,
			    "object tree split policy denies nested FIFO create");
	report_child_result(object_policy_committed ?
			    object_tree_symlink_denied() : 2,
			    "object tree split policy denies nested symlink create");
	report_child_result(object_policy_committed ?
			    object_tree_unlink_denied() : 2,
			    "object tree split policy denies nested file unlink");
	report_child_result(object_policy_committed ?
			    object_tree_split_rmdir_denied() : 2,
			    "object tree split policy denies nested directory rmdir");
	report_child_result(object_policy_committed ?
			    object_tree_append_only_append_allowed() : 2,
			    "object tree append-only policy allows nested append write");
	report_child_result(object_policy_committed ?
			    object_tree_append_only_rewrite_open_denied() : 2,
			    "object tree append-only policy denies nested rewrite open");
		report_child_result(object_policy_committed ?
				    object_tree_unmatched_write_allowed() : 2,
				    "object tree policy allows unmatched nested write");
		test_securityfs_events_contains("authority=40",
						"hardening events report object read denial");
		test_securityfs_events_contains("authority=50",
						"hardening events report object find denial");
	test_securityfs_events_contains("authority=51",
					"hardening events report object ioctl denial");
	test_securityfs_events_contains("authority=52",
					"hardening events report object lock denial");
	test_securityfs_events_contains("authority=53",
					"hardening events report object watch denial");
		test_securityfs_events_contains("authority=54",
						"hardening events report object xattr denial");
		test_securityfs_events_contains("authority=59",
						"hardening events report object receive denial");
		test_securityfs_events_contains("authority=60",
						"hardening events report object fcntl denial");
		test_securityfs_events_contains("authority=61",
						"hardening events report object chdir denial");
		test_securityfs_events_contains("authority=62",
						"hardening events report object mount denial");
		test_securityfs_events_line_contains("authority=87 transition=99",
						     "reason=52",
						     "hardening events report object mount-source denial");
		report_child_result(event_decoder_finds_object_mount_source_denial(),
				    "event decoder names object mount-source denial");
		test_securityfs_events_contains("authority=63",
						"hardening events report object umount denial");
		test_securityfs_events_contains("authority=64",
						"hardening events report object truncate denial");
		test_securityfs_events_contains("authority=65",
						"hardening events report object rename denial");
			test_securityfs_events_line_contains("authority=85 transition=97",
							     "reason=52",
							     "hardening events report object rename-target denial");
			report_child_result(event_decoder_finds_object_rename_target_denial(),
					    "event decoder names object rename-target denial");
			test_securityfs_events_line_contains("authority=86 transition=98",
							     "reason=52",
							     "hardening events report object link-target denial");
			report_child_result(event_decoder_finds_object_link_target_denial(),
					    "event decoder names object link-target denial");
				test_securityfs_events_contains("authority=66",
								"hardening events report object unix-connect denial");
			test_securityfs_events_contains("authority=79",
							"hardening events report object unix-bind denial");
			test_securityfs_events_contains("authority=80",
							"hardening events report object unix-listen denial");
			test_securityfs_events_contains("authority=81",
							"hardening events report object unix-accept denial");
			test_securityfs_events_contains("authority=82",
							"hardening events report object unix-send denial");
			test_securityfs_events_contains("authority=83",
							"hardening events report object unix-recv denial");
			test_securityfs_events_contains("authority=67",
							"hardening events report object chmod denial");
		test_securityfs_events_contains("authority=68",
						"hardening events report object chown denial");
		test_securityfs_events_contains("authority=69",
						"hardening events report object utime denial");
		test_securityfs_events_line_contains("authority=88 transition=100",
						     "reason=52",
						     "hardening events report object setid denial");
		report_child_result(event_decoder_finds_object_setid_denial(),
				    "event decoder names object setid denial");
		test_securityfs_events_line_contains("authority=89 transition=101",
						     "reason=52",
						     "hardening events report object ptrace denial");
		report_child_result(event_decoder_finds_object_ptrace_denial(),
				    "event decoder names object ptrace denial");
		test_securityfs_events_contains("authority=70",
						"hardening events report object setxattr denial");
		test_securityfs_events_contains("authority=71",
						"hardening events report object removexattr denial");
		test_securityfs_events_contains("authority=72",
						"hardening events report object creat denial");
		test_securityfs_events_contains("authority=73",
						"hardening events report object mkdir denial");
		test_securityfs_events_contains("authority=74",
						"hardening events report object mknod denial");
		test_securityfs_events_contains("authority=75",
						"hardening events report object symlink denial");
		test_securityfs_events_contains("authority=76",
						"hardening events report object unlink denial");
		test_securityfs_events_contains("authority=77",
						"hardening events report object rmdir denial");
	if (object_preopen_fd >= 0) {
		close(object_preopen_fd);
		object_preopen_fd = -1;
	}
	if (object_write_preopen_fd >= 0) {
		close(object_write_preopen_fd);
		object_write_preopen_fd = -1;
	}
	if (object_append_preopen_fd >= 0) {
		close(object_append_preopen_fd);
		object_append_preopen_fd = -1;
	}
	if (object_truncate_preopen_fd >= 0) {
		close(object_truncate_preopen_fd);
		object_truncate_preopen_fd = -1;
	}
		if (object_tree_truncate_preopen_fd >= 0) {
			close(object_tree_truncate_preopen_fd);
			object_tree_truncate_preopen_fd = -1;
		}
		if (object_tree_truncate_unmatched_preopen_fd >= 0) {
			close(object_tree_truncate_unmatched_preopen_fd);
			object_tree_truncate_unmatched_preopen_fd = -1;
		}
	if (object_stat_preopen_fd >= 0) {
		close(object_stat_preopen_fd);
		object_stat_preopen_fd = -1;
	}
	if (object_list_preopen_fd >= 0) {
		close(object_list_preopen_fd);
		object_list_preopen_fd = -1;
	}
	if (object_chdir_preopen_fd >= 0) {
		close(object_chdir_preopen_fd);
		object_chdir_preopen_fd = -1;
	}
		if (object_tree_chdir_preopen_fd >= 0) {
			close(object_tree_chdir_preopen_fd);
			object_tree_chdir_preopen_fd = -1;
		}
		if (object_tree_chdir_unmatched_preopen_fd >= 0) {
			close(object_tree_chdir_unmatched_preopen_fd);
			object_tree_chdir_unmatched_preopen_fd = -1;
		}
	if (object_unix_connect_protected_fd >= 0) {
		close(object_unix_connect_protected_fd);
		object_unix_connect_protected_fd = -1;
	}
	if (object_unix_connect_unprotected_fd >= 0) {
		close(object_unix_connect_unprotected_fd);
		object_unix_connect_unprotected_fd = -1;
	}
	if (object_tree_unix_connect_fd >= 0) {
		close(object_tree_unix_connect_fd);
		object_tree_unix_connect_fd = -1;
	}
	if (object_tree_unix_connect_unmatched_fd >= 0) {
		close(object_tree_unix_connect_unmatched_fd);
		object_tree_unix_connect_unmatched_fd = -1;
	}
	if (object_tree_unix_listen_fd >= 0) {
		close(object_tree_unix_listen_fd);
		object_tree_unix_listen_fd = -1;
	}
	if (object_tree_unix_accept_fd >= 0) {
		close(object_tree_unix_accept_fd);
		object_tree_unix_accept_fd = -1;
	}
	if (object_tree_unix_send_fd >= 0) {
		close(object_tree_unix_send_fd);
		object_tree_unix_send_fd = -1;
	}
	if (object_tree_unix_connected_send_fd >= 0) {
		close(object_tree_unix_connected_send_fd);
		object_tree_unix_connected_send_fd = -1;
	}
	if (object_tree_unix_recv_fd >= 0) {
		close(object_tree_unix_recv_fd);
		object_tree_unix_recv_fd = -1;
	}
	if (object_unix_listen_protected_fd >= 0) {
		close(object_unix_listen_protected_fd);
		object_unix_listen_protected_fd = -1;
	}
	if (object_unix_listen_unprotected_fd >= 0) {
		close(object_unix_listen_unprotected_fd);
		object_unix_listen_unprotected_fd = -1;
	}
	if (object_unix_accept_protected_fd >= 0) {
		close(object_unix_accept_protected_fd);
		object_unix_accept_protected_fd = -1;
	}
	if (object_unix_accept_unprotected_fd >= 0) {
		close(object_unix_accept_unprotected_fd);
		object_unix_accept_unprotected_fd = -1;
	}
	if (object_unix_send_protected_fd >= 0) {
		close(object_unix_send_protected_fd);
		object_unix_send_protected_fd = -1;
	}
	if (object_unix_send_unprotected_fd >= 0) {
		close(object_unix_send_unprotected_fd);
		object_unix_send_unprotected_fd = -1;
	}
	if (object_unix_connected_send_protected_fd >= 0) {
		close(object_unix_connected_send_protected_fd);
		object_unix_connected_send_protected_fd = -1;
	}
	if (object_unix_connected_send_unprotected_fd >= 0) {
		close(object_unix_connected_send_unprotected_fd);
		object_unix_connected_send_unprotected_fd = -1;
	}
	if (object_unix_recv_protected_fd >= 0) {
		close(object_unix_recv_protected_fd);
		object_unix_recv_protected_fd = -1;
	}
	if (object_unix_recv_unprotected_fd >= 0) {
		close(object_unix_recv_unprotected_fd);
		object_unix_recv_unprotected_fd = -1;
	}
	if (object_unix_abs_connect_protected_fd >= 0) {
		close(object_unix_abs_connect_protected_fd);
		object_unix_abs_connect_protected_fd = -1;
	}
	if (object_unix_abs_connect_unprotected_fd >= 0) {
		close(object_unix_abs_connect_unprotected_fd);
		object_unix_abs_connect_unprotected_fd = -1;
	}
	if (object_unix_abs_listen_protected_fd >= 0) {
		close(object_unix_abs_listen_protected_fd);
		object_unix_abs_listen_protected_fd = -1;
	}
	if (object_unix_abs_listen_unprotected_fd >= 0) {
		close(object_unix_abs_listen_unprotected_fd);
		object_unix_abs_listen_unprotected_fd = -1;
	}
	if (object_unix_abs_accept_protected_fd >= 0) {
		close(object_unix_abs_accept_protected_fd);
		object_unix_abs_accept_protected_fd = -1;
	}
	if (object_unix_abs_accept_unprotected_fd >= 0) {
		close(object_unix_abs_accept_unprotected_fd);
		object_unix_abs_accept_unprotected_fd = -1;
	}
	if (object_unix_abs_send_protected_fd >= 0) {
		close(object_unix_abs_send_protected_fd);
		object_unix_abs_send_protected_fd = -1;
	}
	if (object_unix_abs_send_unprotected_fd >= 0) {
		close(object_unix_abs_send_unprotected_fd);
		object_unix_abs_send_unprotected_fd = -1;
	}
	if (object_unix_abs_connected_send_protected_fd >= 0) {
		close(object_unix_abs_connected_send_protected_fd);
		object_unix_abs_connected_send_protected_fd = -1;
	}
	if (object_unix_abs_connected_send_unprotected_fd >= 0) {
		close(object_unix_abs_connected_send_unprotected_fd);
		object_unix_abs_connected_send_unprotected_fd = -1;
	}
	if (object_unix_abs_recv_protected_fd >= 0) {
		close(object_unix_abs_recv_protected_fd);
		object_unix_abs_recv_protected_fd = -1;
	}
	if (object_unix_abs_recv_unprotected_fd >= 0) {
		close(object_unix_abs_recv_unprotected_fd);
		object_unix_abs_recv_unprotected_fd = -1;
	}
		unlink(HDN_OBJECT_UNIX_CONNECT_PROTECTED);
		unlink(HDN_OBJECT_UNIX_CONNECT_UNPROTECTED);
		unlink(HDN_OBJECT_TREE_OPS_UNIX_CONNECT);
		unlink(HDN_OBJECT_TREE_OPS_UNIX_CONNECT_UNMATCHED);
		unlink(HDN_OBJECT_UNIX_BIND_PROTECTED);
		unlink(HDN_OBJECT_UNIX_BIND_UNPROTECTED);
		unlink(HDN_OBJECT_UNIX_LISTEN_PROTECTED);
		unlink(HDN_OBJECT_UNIX_LISTEN_UNPROTECTED);
		unlink(HDN_OBJECT_UNIX_ACCEPT_PROTECTED);
		unlink(HDN_OBJECT_UNIX_ACCEPT_UNPROTECTED);
		unlink(HDN_OBJECT_UNIX_SEND_PROTECTED);
		unlink(HDN_OBJECT_UNIX_SEND_UNPROTECTED);
		unlink(HDN_OBJECT_UNIX_RECV_PROTECTED);
		unlink(HDN_OBJECT_UNIX_RECV_UNPROTECTED);
		unlink(HDN_OBJECT_CHMOD_PROTECTED);
	unlink(HDN_OBJECT_CHOWN_PROTECTED);
	unlink(HDN_OBJECT_UTIME_PROTECTED);
	unlink(HDN_OBJECT_SETXATTR_PROTECTED);
	unlink(HDN_OBJECT_REMOVEXATTR_PROTECTED);
	unlink(HDN_OBJECT_SPLIT_ATTR_UNPROTECTED);

	ret = object_policy_committed ? write_text_file(HDN_ROLLBACK, "1\n") :
					-EINVAL;
	object_policy_rolled_back = !ret;
	ksft_test_result(object_policy_rolled_back,
			 "object-write hardening policy rollback succeeds\n");
	if (object_policy_rolled_back) {
		unlink(HDN_OBJECT_CREAT_PROTECTED_FILE);
		rmdir(HDN_OBJECT_MKDIR_PROTECTED_CHILD);
		unlink(HDN_OBJECT_MKNOD_PROTECTED_FIFO);
		unlink(HDN_OBJECT_SYMLINK_PROTECTED_LINK);
		unlink(HDN_OBJECT_UNLINK_PROTECTED);
		rmdir(HDN_OBJECT_RMDIR_PROTECTED_DIR);
		unlink(HDN_OBJECT_SPLIT_CREAT_UNPROTECTED_FILE);
		rmdir(HDN_OBJECT_SPLIT_MKDIR_UNPROTECTED_CHILD);
		unlink(HDN_OBJECT_SPLIT_MKNOD_UNPROTECTED_FIFO);
		unlink(HDN_OBJECT_SPLIT_SYMLINK_UNPROTECTED_LINK);
			unlink(HDN_OBJECT_SPLIT_UNLINK_UNPROTECTED);
			rmdir(HDN_OBJECT_SPLIT_RMDIR_UNPROTECTED_DIR);
		}
		rmdir(HDN_OBJECT_UNIX_BIND_PROTECTED_DIR);
		rmdir(HDN_OBJECT_UNIX_BIND_UNPROTECTED_DIR);
		cleanup_object_umount_fixtures();
		cleanup_object_mount_source_fixtures();
		cleanup_object_tree_umount_fixture();
		cleanup_object_fileattr_fs();

	ret = write_signed_policy_path(HDN_SOCKET_POLICY);
	socket_policy_staged = !ret;
	ksft_test_result(socket_policy_staged,
			 "socket hardening policy stages\n");

	ret = socket_policy_staged ? write_text_file(HDN_COMMIT, "1\n") :
				     -EINVAL;
	socket_policy_committed = !ret;
	ksft_test_result(socket_policy_committed,
			 "socket hardening policy commits\n");

	report_child_result(socket_policy_committed ?
			    socket_connect_without_authority_denied() : 2,
			    "socket policy denies outbound connect without authority");
	report_child_result(socket_policy_committed ?
			    socket_connect6_without_authority_denied() : 2,
			    "socket policy denies IPv6 outbound connect without authority");
	report_child_result(socket_policy_committed ?
			    socket_udp_connect_without_authority_denied() : 2,
			    "socket policy denies UDP outbound connect without authority");
	report_child_result(socket_policy_committed ?
			    socket_udp_connect6_without_authority_denied() : 2,
			    "socket policy denies IPv6 UDP outbound connect without authority");
	report_child_result(socket_policy_committed ?
			    socket_server_without_authority_denied() : 2,
			    "socket policy denies server bind without authority");
	report_child_result(socket_policy_committed ?
			    socket_server6_without_authority_denied() : 2,
			    "socket policy denies IPv6 server bind without authority");
	report_child_result(socket_policy_committed ?
			    socket_udp_server_without_authority_denied() : 2,
			    "socket policy denies UDP server bind without authority");
	report_child_result(socket_policy_committed ?
			    socket_udp_server6_without_authority_denied() : 2,
			    "socket policy denies IPv6 UDP server bind without authority");
	report_child_result(socket_policy_committed ?
			    module_autoload_without_authority_denied() : 2,
			    "socket policy denies module autoload without authority");
	test_securityfs_events_contains("authority=28",
					"hardening events report socket create denial");
	test_securityfs_events_contains("authority=29",
					"hardening events report socket connect denial");
	snprintf(socket_connect_object, sizeof(socket_connect_object),
		 "object=%llu",
		 hdn_ipv4_socket_event_object(SOCK_STREAM, 9,
					      INADDR_LOOPBACK));
	test_securityfs_events_line_contains("authority=29 transition=34",
					     socket_connect_object,
					     "hardening events report socket connect endpoint object");
	snprintf(socket_connect6_object, sizeof(socket_connect6_object),
		 "object=%llu",
		 hdn_ipv6_socket_event_object(SOCK_STREAM, 9,
					      &in6addr_loopback));
	test_securityfs_events_line_contains("authority=29 transition=34",
					     socket_connect6_object,
					     "hardening events report IPv6 socket connect endpoint object");
	snprintf(socket_udp_connect_object, sizeof(socket_udp_connect_object),
		 "object=%llu",
		 hdn_ipv4_socket_event_object(SOCK_DGRAM, 9,
					      INADDR_LOOPBACK));
	test_securityfs_events_line_contains("authority=29 transition=34",
					     socket_udp_connect_object,
					     "hardening events report UDP socket connect endpoint object");
	snprintf(socket_udp_connect6_object, sizeof(socket_udp_connect6_object),
		 "object=%llu",
		 hdn_ipv6_socket_event_object(SOCK_DGRAM, 9,
					      &in6addr_loopback));
	test_securityfs_events_line_contains("authority=29 transition=34",
					     socket_udp_connect6_object,
					     "hardening events report IPv6 UDP socket connect endpoint object");
	test_securityfs_events_contains("authority=30",
					"hardening events report socket server denial");
	snprintf(socket_server_object, sizeof(socket_server_object),
		 "object=%llu",
		 hdn_ipv4_socket_event_object(SOCK_STREAM, 0,
					      INADDR_LOOPBACK));
	test_securityfs_events_line_contains("authority=30 transition=35",
					     socket_server_object,
					     "hardening events report socket server endpoint object");
	snprintf(socket_server6_object, sizeof(socket_server6_object),
		 "object=%llu",
		 hdn_ipv6_socket_event_object(SOCK_STREAM, 0,
					      &in6addr_loopback));
	test_securityfs_events_line_contains("authority=30 transition=35",
					     socket_server6_object,
					     "hardening events report IPv6 socket server endpoint object");
	snprintf(socket_udp_server_object, sizeof(socket_udp_server_object),
		 "object=%llu",
		 hdn_ipv4_socket_event_object(SOCK_DGRAM, 0,
					      INADDR_LOOPBACK));
	test_securityfs_events_line_contains("authority=30 transition=35",
					     socket_udp_server_object,
					     "hardening events report UDP socket server endpoint object");
	snprintf(socket_udp_server6_object, sizeof(socket_udp_server6_object),
		 "object=%llu",
		 hdn_ipv6_socket_event_object(SOCK_DGRAM, 0,
					      &in6addr_loopback));
	test_securityfs_events_line_contains("authority=30 transition=35",
					     socket_udp_server6_object,
					     "hardening events report IPv6 UDP socket server endpoint object");
	test_securityfs_events_contains("authority=37",
					"hardening events report module autoload denial");

	ret = socket_policy_committed ? write_text_file(HDN_ROLLBACK, "1\n") :
					-EINVAL;
	socket_policy_rolled_back = !ret;
	ksft_test_result(socket_policy_rolled_back,
			 "socket hardening policy rollback succeeds\n");

	ret = write_signed_policy_path(HDN_BLOCK_ADMIN_POLICY);
	block_admin_policy_staged = !ret;
	ksft_test_result(block_admin_policy_staged,
			 "block-device admin hardening policy stages\n");

	ret = block_admin_policy_staged ? write_text_file(HDN_COMMIT, "1\n") :
					  -EINVAL;
	block_admin_policy_committed = !ret;
	ksft_test_result(block_admin_policy_committed,
			 "block-device admin hardening policy commits\n");
	if (block_admin_policy_committed)
		block_admin_query_result =
			forked_child_result(block_device_query_with_access_allowed);
	report_child_result(block_admin_policy_committed ?
			    block_admin_query_result : 2,
			    "block-device profile allows raw block-device query");
	if (block_admin_policy_committed && !block_admin_query_result)
		block_admin_denial_result =
			forked_child_result(
				block_device_admin_without_authority_denied);
	report_child_result(block_admin_policy_committed ?
			    (block_admin_query_result ? KSFT_SKIP :
			     block_admin_denial_result) : 2,
			    "block-device profile denies admin ioctl without authority");
	if (block_admin_policy_committed && !block_admin_query_result &&
	    !block_admin_denial_result)
		test_securityfs_events_line_contains("authority=38 transition=45",
						     "reason=7",
						     "hardening events report block-device admin denial");
	else
		ksft_test_result_skip(
			"hardening events report block-device admin denial\n");

	ret = block_admin_policy_committed ? write_text_file(HDN_ROLLBACK, "1\n") :
					     -EINVAL;
	block_admin_policy_rolled_back = !ret;
	ksft_test_result(block_admin_policy_rolled_back,
			 "block-device admin hardening policy rollback succeeds\n");

	ret = write_signed_policy_path(HDN_JIT_POLICY);
	jit_staged = !ret;
	ksft_test_result(jit_staged,
			 "JIT hardening policy stages\n");

	ret = jit_staged ? write_text_file(HDN_COMMIT, "1\n") : -EINVAL;
	jit_committed = !ret;
	ksft_test_result(jit_committed,
			 "JIT hardening policy commits\n");

	report_child_result(jit_committed ? jit_exec_after_write_allowed() : 2,
			    "JIT profile allows private anonymous exec-after-write");
	report_child_result(jit_committed ?
			    jit_file_backed_exec_after_write_denied() : 2,
			    "JIT profile denies file-backed exec-after-write");

	ret = jit_committed ? write_text_file(HDN_ROLLBACK, "1\n") : -EINVAL;
	jit_rolled_back = !ret;
	ksft_test_result(jit_rolled_back,
			 "JIT hardening policy rollback succeeds\n");

	ret = write_signed_policy_path(HDN_EXECSTACK_POLICY);
	execstack_staged = !ret;
	ksft_test_result(execstack_staged,
			 "exec-stack compatibility policy stages\n");

	ret = execstack_staged ? write_text_file(HDN_COMMIT, "1\n") :
				 -EINVAL;
	execstack_committed = !ret;
	ksft_test_result(execstack_committed,
			 "exec-stack compatibility policy commits\n");

	report_child_result(execstack_committed ?
			    exec_stack_elf_compat_allowed() : 2,
			    "exec-stack compatibility allows executable-stack ELF");

	ret = execstack_committed ? write_text_file(HDN_ROLLBACK, "1\n") :
				    -EINVAL;
	execstack_rolled_back = !ret;
	ksft_test_result(execstack_rolled_back,
			 "exec-stack compatibility policy rollback succeeds\n");

	ret = write_signed_policy_path(HDN_TEXTREL_POLICY);
	textrel_staged = !ret;
	ksft_test_result(textrel_staged,
			 "textrel compatibility policy stages\n");

	ret = textrel_staged ? write_text_file(HDN_COMMIT, "1\n") :
			       -EINVAL;
	textrel_committed = !ret;
	ksft_test_result(textrel_committed,
			 "textrel compatibility policy commits\n");

	report_child_result(textrel_committed ?
			    textrel_mprotect_compat_allowed() : 2,
			    "textrel compatibility allows text relocation mprotect");

	ret = textrel_committed ? write_text_file(HDN_ROLLBACK, "1\n") :
				  -EINVAL;
	textrel_rolled_back = !ret;
	ksft_test_result(textrel_rolled_back,
			 "textrel compatibility policy rollback succeeds\n");

	ret = write_signed_policy_path(HDN_RELRO_POLICY);
	relro_staged = !ret;
	ksft_test_result(relro_staged,
			 "RELRO compatibility policy stages\n");

	ret = relro_staged ? write_text_file(HDN_COMMIT, "1\n") : -EINVAL;
	relro_committed = !ret;
	ksft_test_result(relro_committed,
			 "RELRO compatibility policy commits\n");

	report_child_result(relro_committed ?
			    relro_write_restore_compat_allowed() : 2,
			    "RELRO compatibility allows write restoration");

	ret = relro_committed ? write_text_file(HDN_ROLLBACK, "1\n") :
				 -EINVAL;
	relro_rolled_back = !ret;
	ksft_test_result(relro_rolled_back,
			 "RELRO compatibility policy rollback succeeds\n");

	ret = write_signed_policy_path(HDN_KILL_POLICY);
	kill_staged = !ret;
	ksft_test_result(kill_staged,
			 "KILL_MEMORY hardening policy stages\n");

	ret = kill_staged ? write_text_file(HDN_COMMIT, "1\n") : -EINVAL;
	kill_committed = !ret;
	ksft_test_result(kill_committed,
			 "KILL_MEMORY hardening policy commits\n");

	if (kill_committed)
		report_killed_child_result(anonymous_rwx_mapping_child,
					   "KILL_MEMORY response kills denied W+X task");
	else
		report_child_result(2,
				    "KILL_MEMORY response kills denied W+X task");

	ret = kill_committed ? write_text_file(HDN_ROLLBACK, "1\n") :
			       -EINVAL;
	kill_rolled_back = !ret;
	ksft_test_result(kill_rolled_back,
			 "KILL_MEMORY hardening policy rollback succeeds\n");

	ksft_test_result(securityfs_events_contains("flags=0x1"),
			 "hardening events report kill response flag\n");
	ksft_test_result(securityfs_events_contains("reason=16"),
			 "hardening events report untrusted module denial\n");
	ksft_test_result(securityfs_events_contains("authority=8"),
			 "hardening events report restricted ptrace denial\n");
	ksft_test_result(securityfs_events_contains("authority=12"),
			 "hardening events report restricted kexec denial\n");
	ksft_test_result(securityfs_events_contains("authority=4"),
			 "hardening events report restricted BPF denial\n");
	ksft_test_result(securityfs_events_contains("authority=17"),
			 "hardening events report restricted mount denial\n");
		ksft_test_result(securityfs_events_contains("authority=16"),
				 "hardening events report restricted raw I/O denial\n");
		ksft_test_result(securityfs_events_contains("authority=84 transition=96"),
				 "hardening events report restricted kernel log write denial\n");
		ksft_test_result(securityfs_events_contains("authority=19"),
				 "hardening events report restricted namespace denial\n");
	ksft_test_result(securityfs_events_contains("authority=11"),
			 "hardening events report restricted sysfs denial\n");
	ksft_test_result(securityfs_events_contains("authority=35"),
			 "hardening events report restricted sysfs read denial\n");
	ksft_test_result(securityfs_events_contains("authority=9"),
			 "hardening events report restricted proc denial\n");
	ksft_test_result(securityfs_events_contains("authority=31"),
			 "hardening events report restricted proc-task denial\n");
	ksft_test_result(securityfs_events_contains("authority=55"),
			 "hardening events report restricted signal denial\n");
	ksft_test_result(securityfs_events_contains("authority=56"),
			 "hardening events report restricted process-memory denial\n");
	ksft_test_result(securityfs_events_contains("authority=57"),
			 "hardening events report restricted memory-migrate denial\n");
	ksft_test_result(securityfs_events_contains("authority=58"),
			 "hardening events report restricted process-fd denial\n");
	ksft_test_result(securityfs_events_contains("authority=10"),
			 "hardening events report restricted debugfs denial\n");
	ksft_test_result(securityfs_events_contains("authority=32"),
			 "hardening events report restricted time-change denial\n");
	ksft_test_result(securityfs_events_contains("authority=33"),
			 "hardening events report restricted resource-limit denial\n");
	ksft_test_result(securityfs_events_contains("reason=56"),
			 "hardening events report resource profile ceiling denial\n");
	ksft_test_result(securityfs_events_contains("authority=34"),
			 "hardening events report restricted block-device denial\n");
	ksft_test_result(securityfs_events_contains("reason=19"),
			 "hardening events report untrusted exec denial\n");
	test_securityfs_events_line_contains("authority=22 transition=3",
					     "reason=19",
					     "hardening events report untrusted executable mmap denial");
	test_securityfs_events_line_contains("authority=22 transition=4",
					     "reason=19",
					     "hardening events report untrusted executable mprotect denial");
	ksft_test_result(securityfs_events_contains("reason=17"),
			 "hardening events report untrusted firmware denial\n");
	ksft_test_result(securityfs_events_contains("reason=21"),
			 "hardening events report chroot fchdir denial\n");
	ksft_test_result(securityfs_events_contains("reason=20"),
			 "hardening events report chroot reentry denial\n");
	test_securityfs_events_line_contains("authority=21 transition=25",
					     "reason=31",
					     "hardening events report chroot chmod denial");
	test_securityfs_events_line_contains("authority=21 transition=25",
					     "reason=32",
					     "hardening events report chroot mknod denial");
	test_securityfs_events_line_contains("authority=21 transition=25",
					     "reason=33",
					     "hardening events report chroot shmat denial");
	test_securityfs_events_line_contains("authority=21 transition=25",
					     "reason=34",
					     "hardening events report chroot nice denial");
	test_securityfs_events_line_contains("authority=21 transition=25",
					     "reason=35",
					     "hardening events report chroot rename denial");
	test_securityfs_events_line_contains("authority=21 transition=25",
					     "reason=36",
					     "hardening events report chroot abstract UNIX denial");
	test_securityfs_events_line_contains("authority=21 transition=25",
					     "reason=37",
					     "hardening events report chroot capability denial");
		test_securityfs_events_line_contains("authority=21 transition=25",
						     "reason=38",
						     "hardening events report chroot outside-task denial");
		test_securityfs_events_line_contains("authority=21 transition=25",
						     "reason=41",
						     "hardening events report chroot file-handle denial");
		test_securityfs_events_line_contains("authority=21 transition=25",
						     "reason=47",
						     "hardening events report chroot sysctl denial");
		report_child_result(event_decoder_finds_chroot_file_handle_denial(),
				    "event decoder names chroot file-handle denial reason");
			report_child_result(event_decoder_finds_chroot_sysctl_denial(),
					    "event decoder names chroot sysctl denial reason");
		report_child_result(event_decoder_finds_kernel_log_write_denial(),
				    "event decoder names kernel log write denial");
		ksft_test_result(securityfs_events_contains("authority=20"),
				 "hardening events report credential transition denial\n");
	ksft_test_result(securityfs_events_contains("reason=23"),
			 "hardening events report brute throttle denial\n");

	ret = write_signed_policy();
	recovery_staged = !ret;
	ksft_test_result(recovery_staged,
			 "recovery test hardening policy stages\n");

	ret = recovery_staged ? write_text_file(HDN_COMMIT, "1\n") :
				-EINVAL;
	recovery_committed = !ret;
	ksft_test_result(recovery_committed &&
			 securityfs_status_has_line("generation: 1"),
			 "recovery test hardening policy commits\n");

	ret = recovery_committed ? write_text_file(HDN_PHASE, "runtime\n") :
				   -EINVAL;
	runtime = !ret;
	ksft_test_result(runtime &&
			 securityfs_status_has_line("phase: runtime"),
			 "runtime hardening phase can be set\n");

	report_child_result(runtime ? run_refresh_target() : 2,
			    "runtime policy binds the refresh test executable");
	ret = runtime ? replace_refresh_target() : -EINVAL;
	ksft_test_result(!ret,
			 "refresh test executable is atomically replaced\n");
	report_child_result(!ret ? refresh_target_denied() : 2,
			    "stale executable identity loses JIT compatibility");

	ret = runtime ? write_policy_path_to(HDN_REFRESH,
					     HDN_SIGNED_POLICY) : -EINVAL;
	ksft_test_result(!ret,
			 "runtime accepts an identical signed policy refresh\n");
	ksft_test_result(!ret &&
			 securityfs_status_has_line("generation: 1") &&
			 securityfs_status_has_line("phase: runtime"),
			 "policy refresh preserves generation and runtime phase\n");
	report_child_result(!ret ? run_refresh_target() : 2,
			    "policy refresh binds the replacement executable");
	ksft_test_result(!ret &&
			 securityfs_events_line_contains("transition=105",
						 "reason=0"),
			 "hardening events report allowed policy refresh\n");

	ret = runtime ? write_policy_path_to(HDN_REFRESH,
					     HDN_RESTRICTED_POLICY) : -EINVAL;
	ksft_test_result(ret == -ESTALE,
			 "runtime rejects a different signed policy refresh\n");
	ksft_test_result(ret == -ESTALE &&
			 securityfs_events_line_contains("transition=105",
						 "reason=62"),
			 "hardening events report policy identity mismatch\n");
	ret = runtime ? write_policy_path_to(HDN_REFRESH,
					     HDN_UNSIGNED_POLICY) : -EINVAL;
	ksft_test_result(ret < 0 &&
			 securityfs_events_line_contains("transition=105",
						 "reason=11"),
			 "runtime rejects an unsigned policy refresh\n");
	report_child_result(runtime ? run_refresh_target() : 2,
			    "rejected refresh leaves active executable binding intact");

	ret = runtime ? write_signed_policy() : -EINVAL;
	ksft_test_result(ret < 0 && errno_is_denial(-ret),
			 "runtime phase rejects signed policy mutation\n");
	ksft_test_result(securityfs_events_contains("reason=8"),
			 "hardening events report sealed runtime denial\n");

	ret = runtime ? write_text_file(HDN_PHASE, "recovery\n") : -EINVAL;
	recovery = !ret;
	ksft_test_result(recovery &&
			 securityfs_status_has_line("phase: recovery"),
			 "recovery hardening phase can be set\n");

	ret = recovery ? write_text_file(HDN_ROLLBACK, "1\n") : -EINVAL;
	recovery_rolled_back = !ret;
	ksft_test_result(recovery_rolled_back &&
			 securityfs_status_has_line("generation: 0"),
			 "recovery rollback restores previous active generation\n");
	ksft_test_result(securityfs_events_contains("reason=16"),
			 "hardening events survive recovery transition\n");

	ret = recovery_rolled_back ? write_text_file(HDN_PHASE, "runtime\n") :
				     -EINVAL;
	resealed = !ret;
	ksft_test_result(resealed &&
			 securityfs_status_has_line("phase: runtime"),
			 "recovery phase can reseal runtime\n");
}

static void test_anonymous_rwx_denied(void)
{
	unsigned int before;
	size_t page_size = sysconf(_SC_PAGESIZE);
	void *addr;
	int saved_errno = 0;

	before = securityfs_events_count("reason=49");
	errno = 0;
	addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE | PROT_EXEC,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED)
		saved_errno = errno;
	else
		munmap(addr, page_size);

	ksft_test_result(addr == MAP_FAILED && errno_is_denial(saved_errno),
			 "anonymous RWX mmap is denied\n");
	ksft_test_result(addr == MAP_FAILED && errno_is_denial(saved_errno) &&
			 event_count_increased("reason=49", before),
			 "hardening events report denied RWX mmap audit\n");
}

static void test_audit_flood_runtime_knobs(void)
{
	unsigned long long orig_window_ms;
	unsigned long long orig_burst;
	unsigned long long window_ms;
	unsigned long long burst;
	char restore_window[32];
	char restore_burst[32];
	bool restored = false;
	bool updated = false;
	int restore_window_ret = 0;
	int restore_burst_ret = 0;
	int window_ret;
	int burst_ret;

	if (!securityfs_status_u64("audit_flood_burst:", &orig_burst) ||
	    !securityfs_status_u64("audit_flood_window_ms:",
				   &orig_window_ms)) {
		ksft_test_result_fail("audit flood runtime knobs are readable\n");
		return;
	}

	burst_ret = write_text_file(HDN_AUDIT_FLOOD_BURST_CTL, "7\n");
	window_ret = write_text_file(HDN_AUDIT_FLOOD_WINDOW_MS_CTL, "250\n");

	updated = !burst_ret && !window_ret &&
		  securityfs_status_u64("audit_flood_burst:", &burst) &&
		  burst == 7 &&
		  securityfs_status_u64("audit_flood_window_ms:", &window_ms) &&
		  window_ms == 250 &&
		  securityfs_status_has_line(
			  "audit_flood_window_ns: 250000000");

	snprintf(restore_burst, sizeof(restore_burst), "%llu\n", orig_burst);
	snprintf(restore_window, sizeof(restore_window), "%llu\n",
		 orig_window_ms);
	if (!burst_ret)
		restore_burst_ret =
			write_text_file(HDN_AUDIT_FLOOD_BURST_CTL,
					restore_burst);
	if (!window_ret)
		restore_window_ret =
			write_text_file(HDN_AUDIT_FLOOD_WINDOW_MS_CTL,
					restore_window);

	restored = !restore_burst_ret && !restore_window_ret &&
		   securityfs_status_u64("audit_flood_burst:", &burst) &&
		   burst == orig_burst &&
		   securityfs_status_u64("audit_flood_window_ms:",
					 &window_ms) &&
		   window_ms == orig_window_ms;

	ksft_test_result(!burst_ret && !window_ret && updated && restored,
			 "audit flood runtime knobs can be tuned\n");
}

static void test_audit_flood_control(void)
{
	unsigned long long before;
	unsigned long long after;
	int i;

	if (!securityfs_status_u64("audit_flood_suppressed_total:",
				   &before)) {
		ksft_test_result_fail("audit flood counter is readable\n");
		return;
	}

	for (i = 0; i < HDN_AUDIT_FLOOD_TEST_ATTEMPTS; i++) {
		int ret = anonymous_rwx_mapping_child();

		if (ret) {
			ksft_test_result_fail("audit flood denial trigger works\n");
			return;
		}
	}

	if (!securityfs_status_u64("audit_flood_suppressed_total:", &after)) {
		ksft_test_result_fail("audit flood counter is readable\n");
		return;
	}

	ksft_test_result(after > before,
			 "audit flood control suppresses repeated denials\n");
}

static void test_file_backed_rwx_denied(void)
{
#ifdef __NR_memfd_create
	size_t page_size = sysconf(_SC_PAGESIZE);
	int saved_errno = 0;
	void *addr;
	int fd;

	errno = 0;
	fd = syscall(__NR_memfd_create, "hdn-rwx", MFD_CLOEXEC);
	if (fd < 0) {
		ksft_test_result_fail("memfd_create failed: %s\n",
				      strerror(errno));
		return;
	}

	if (ftruncate(fd, page_size)) {
		ksft_test_result_fail("memfd ftruncate failed: %s\n",
				      strerror(errno));
		close(fd);
		return;
	}

	errno = 0;
	addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE | PROT_EXEC,
		    MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED)
		saved_errno = errno;
	else
		munmap(addr, page_size);
	close(fd);

	ksft_test_result(addr == MAP_FAILED && errno_is_denial(saved_errno),
			 "file-backed RWX mmap is denied\n");
#else
	ksft_test_result_skip("memfd_create syscall number unavailable\n");
#endif
}

static void test_exec_after_write_denied(void)
{
	size_t page_size = sysconf(_SC_PAGESIZE);
	void *addr;
	int ret;
	int saved_errno = 0;

	addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		ksft_test_result_fail("RW mmap setup failed: %s\n",
				      strerror(errno));
		return;
	}

	errno = 0;
	ret = mprotect(addr, page_size, PROT_READ | PROT_EXEC);
	if (ret)
		saved_errno = errno;

	munmap(addr, page_size);
	ksft_test_result(ret && errno_is_denial(saved_errno),
			 "mprotect exec-after-write is denied\n");
}

static void test_exec_after_write_history_denied(void)
{
	size_t page_size = sysconf(_SC_PAGESIZE);
	void *addr;
	int ret;
	int saved_errno = 0;

	addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED || mprotect(addr, page_size, PROT_READ)) {
		ksft_test_result_fail("write-history mmap setup failed: %s\n",
				      strerror(errno));
		if (addr != MAP_FAILED)
			munmap(addr, page_size);
		return;
	}

	errno = 0;
	ret = mprotect(addr, page_size, PROT_READ | PROT_EXEC);
	if (ret)
		saved_errno = errno;

	munmap(addr, page_size);
	ksft_test_result(ret && errno_is_denial(saved_errno),
			 "mprotect preserves exec-after-write history\n");
}

static void test_exec_after_write_split_history_denied(void)
{
	size_t page_size = sysconf(_SC_PAGESIZE);
	void *middle;
	void *addr;
	int ret;
	int saved_errno = 0;

	addr = mmap(NULL, page_size * 3, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		ksft_test_result_fail("write-history split mmap failed: %s\n",
				      strerror(errno));
		return;
	}
	middle = (char *)addr + page_size;
	if (mprotect(middle, page_size, PROT_READ)) {
		ksft_test_result_fail("write-history VMA split failed: %s\n",
				      strerror(errno));
		munmap(addr, page_size * 3);
		return;
	}

	errno = 0;
	ret = mprotect(middle, page_size, PROT_READ | PROT_EXEC);
	if (ret)
		saved_errno = errno;

	munmap(addr, page_size * 3);
	ksft_test_result(ret && errno_is_denial(saved_errno),
			 "VMA splits preserve exec-after-write history\n");
}

static void test_exec_after_write_merge_history_denied(void)
{
	size_t page_size = sysconf(_SC_PAGESIZE);
	void *middle;
	void *addr;
	int ret;
	int saved_errno = 0;

	addr = mmap(NULL, page_size * 3, PROT_READ,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		ksft_test_result_fail("write-history merge mmap failed: %s\n",
				      strerror(errno));
		return;
	}
	middle = (char *)addr + page_size;
	if (mprotect(middle, page_size, PROT_READ | PROT_WRITE) ||
	    mprotect(addr, page_size * 3, PROT_READ)) {
		ksft_test_result_fail("write-history VMA merge setup failed: %s\n",
				      strerror(errno));
		munmap(addr, page_size * 3);
		return;
	}

	errno = 0;
	ret = mprotect(addr, page_size, PROT_READ | PROT_EXEC);
	if (ret)
		saved_errno = errno;

	munmap(addr, page_size * 3);
	ksft_test_result(ret && errno_is_denial(saved_errno),
			 "VMA merges preserve exec-after-write history\n");
}

static void test_exec_after_write_fork_history_denied(void)
{
	size_t page_size = sysconf(_SC_PAGESIZE);
	void *addr;
	pid_t child;
	int ret;

	addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED || mprotect(addr, page_size, PROT_READ)) {
		ksft_test_result_fail("write-history fork mmap setup failed: %s\n",
				      strerror(errno));
		if (addr != MAP_FAILED)
			munmap(addr, page_size);
		return;
	}

	child = fork();
	if (child < 0) {
		ksft_test_result_fail("write-history fork failed: %s\n",
				      strerror(errno));
		munmap(addr, page_size);
		return;
	}
	if (!child) {
		errno = 0;
		ret = mprotect(addr, page_size, PROT_READ | PROT_EXEC);
		_exit(ret && errno_is_denial(errno) ? 0 : 1);
	}

	ret = child_exit_result(child);
	munmap(addr, page_size);
	ksft_test_result(!ret, "fork preserves exec-after-write history\n");
}

static void test_rwx_mprotect_audit_logged(void)
{
	unsigned int before;
	size_t page_size = sysconf(_SC_PAGESIZE);
	void *addr;
	int ret;
	int saved_errno = 0;

	addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		ksft_test_result_fail("RW mmap setup for RWX mprotect failed: %s\n",
				      strerror(errno));
		return;
	}

	before = securityfs_events_count("reason=49");
	errno = 0;
	ret = mprotect(addr, page_size,
		       PROT_READ | PROT_WRITE | PROT_EXEC);
	if (ret)
		saved_errno = errno;

	munmap(addr, page_size);
	ksft_test_result(ret && errno_is_denial(saved_errno) &&
			 event_count_increased("reason=49", before),
			 "hardening events report denied RWX mprotect audit\n");
}

static int write_exec_stack_elf_fixture(const char *path)
{
	Elf64_Ehdr ehdr = {};
	Elf64_Phdr phdr = {};
	int fd;
	int ret;

	memcpy(ehdr.e_ident, ELFMAG, SELFMAG);
	ehdr.e_ident[EI_CLASS] = ELFCLASS64;
	ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr.e_ident[EI_VERSION] = EV_CURRENT;
	ehdr.e_ident[EI_OSABI] = ELFOSABI_SYSV;
	ehdr.e_type = ET_DYN;
	ehdr.e_machine = EM_X86_64;
	ehdr.e_version = EV_CURRENT;
	ehdr.e_ehsize = sizeof(ehdr);
	ehdr.e_phoff = sizeof(ehdr);
	ehdr.e_phentsize = sizeof(phdr);
	ehdr.e_phnum = 1;

	phdr.p_type = PT_GNU_STACK;
	phdr.p_flags = PF_R | PF_W | PF_X;
	phdr.p_align = 16;

	fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
	if (fd < 0)
		return -errno;

	ret = write_all_fd(fd, &ehdr, sizeof(ehdr));
	if (!ret)
		ret = write_all_fd(fd, &phdr, sizeof(phdr));
	if (!ret && ftruncate(fd, 4096))
		ret = -errno;

	close(fd);
	if (ret)
		unlink(path);
	return ret;
}

static int exec_stack_elf_mapping_result(bool expect_allow, bool require_event)
{
	unsigned int before;
	size_t page_size = sysconf(_SC_PAGESIZE);
	void *addr;
	int fd;
	int saved_errno = 0;
	int ret;

	ret = write_exec_stack_elf_fixture(HDN_EXEC_STACK_ELF);
	if (ret)
		return 2;

	fd = open(HDN_EXEC_STACK_ELF, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		unlink(HDN_EXEC_STACK_ELF);
		return 2;
	}

	before = securityfs_events_count("reason=50");
	errno = 0;
	addr = mmap(NULL, page_size, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED)
		saved_errno = errno;
	else
		munmap(addr, page_size);
	close(fd);
	unlink(HDN_EXEC_STACK_ELF);

	if (expect_allow) {
		if (addr == MAP_FAILED)
			return errno_is_denial(saved_errno) ? 1 : 2;
		return !require_event ||
		       event_count_increased("reason=50", before) ? 0 : 1;
	}

	if (addr != MAP_FAILED)
		return 1;
	if (!errno_is_denial(saved_errno))
		return 2;
	return !require_event || event_count_increased("reason=50", before) ?
	       0 : 1;
}

static void test_exec_stack_elf_denied(void)
{
	int ret;

	ret = exec_stack_elf_mapping_result(false, true);
	ksft_test_result(!ret, "executable-stack ELF mmap is denied\n");
	if (ret == 2)
		ksft_print_msg("executable-stack ELF denial test setup failed\n");
}

static int exec_stack_elf_compat_allowed(void)
{
	return exec_stack_elf_mapping_result(true, true);
}

static int write_textrel_elf_fixture(const char *path)
{
	Elf64_Ehdr ehdr = {};
	Elf64_Phdr phdrs[2] = {};
	Elf64_Dyn dyns[2] = {};
	int fd;
	int ret;

	memcpy(ehdr.e_ident, ELFMAG, SELFMAG);
	ehdr.e_ident[EI_CLASS] = ELFCLASS64;
	ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr.e_ident[EI_VERSION] = EV_CURRENT;
	ehdr.e_ident[EI_OSABI] = ELFOSABI_SYSV;
	ehdr.e_type = ET_DYN;
	ehdr.e_machine = EM_X86_64;
	ehdr.e_version = EV_CURRENT;
	ehdr.e_ehsize = sizeof(ehdr);
	ehdr.e_phoff = sizeof(ehdr);
	ehdr.e_phentsize = sizeof(phdrs[0]);
	ehdr.e_phnum = ARRAY_SIZE(phdrs);

	phdrs[0].p_type = PT_LOAD;
	phdrs[0].p_offset = 0;
	phdrs[0].p_vaddr = 0;
	phdrs[0].p_paddr = 0;
	phdrs[0].p_filesz = 4096;
	phdrs[0].p_memsz = 4096;
	phdrs[0].p_flags = PF_R | PF_X;
	phdrs[0].p_align = 4096;

	phdrs[1].p_type = PT_DYNAMIC;
	phdrs[1].p_offset = 0x200;
	phdrs[1].p_vaddr = 0x200;
	phdrs[1].p_paddr = 0x200;
	phdrs[1].p_filesz = sizeof(dyns);
	phdrs[1].p_memsz = sizeof(dyns);
	phdrs[1].p_flags = PF_R;
	phdrs[1].p_align = 8;

	dyns[0].d_tag = DT_TEXTREL;
	dyns[1].d_tag = DT_NULL;

	fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
	if (fd < 0)
		return -errno;

	ret = write_all_fd(fd, &ehdr, sizeof(ehdr));
	if (!ret)
		ret = write_all_fd(fd, phdrs, sizeof(phdrs));
	if (!ret && lseek(fd, phdrs[1].p_offset, SEEK_SET) < 0)
		ret = -errno;
	if (!ret)
		ret = write_all_fd(fd, dyns, sizeof(dyns));
	if (!ret && ftruncate(fd, 4096))
		ret = -errno;

	close(fd);
	if (ret)
		unlink(path);
	return ret;
}

static int textrel_mprotect_result(bool expect_allow, bool require_event)
{
	unsigned int before;
	size_t page_size = sysconf(_SC_PAGESIZE);
	int saved_errno = 0;
	void *addr;
	int fd;
	int ret;
	int ret_exec = 0;
	int saved_exec_errno = 0;

	ret = write_textrel_elf_fixture(HDN_TEXTREL_ELF);
	if (ret)
		return 2;

	fd = open(HDN_TEXTREL_ELF, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		unlink(HDN_TEXTREL_ELF);
		return 2;
	}

	addr = mmap(NULL, page_size, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED) {
		close(fd);
		unlink(HDN_TEXTREL_ELF);
		return 2;
	}

	before = securityfs_events_count("reason=51");
	errno = 0;
	ret = mprotect(addr, page_size, PROT_READ | PROT_WRITE);
	if (ret)
		saved_errno = errno;
	if (!ret && expect_allow) {
		errno = 0;
		ret_exec = mprotect(addr, page_size, PROT_READ | PROT_EXEC);
		if (ret_exec)
			saved_exec_errno = errno;
	}

	munmap(addr, page_size);
	close(fd);
	unlink(HDN_TEXTREL_ELF);

	if (expect_allow) {
		if (ret)
			return errno_is_denial(saved_errno) ? 1 : 2;
		if (ret_exec)
			return errno_is_denial(saved_exec_errno) ? 1 : 2;
		return !require_event ||
		       event_count_increased("reason=51", before) ? 0 : 1;
	}

	if (!ret)
		return 1;
	if (!errno_is_denial(saved_errno))
		return 2;
	return !require_event || event_count_increased("reason=51", before) ?
	       0 : 1;
}

static void test_textrel_mprotect_denied(void)
{
	int ret;

	ret = textrel_mprotect_result(false, true);
	ksft_test_result(!ret, "textrel mprotect is denied\n");
	if (ret == 2)
		ksft_print_msg("textrel mprotect denial test setup failed\n");
}

static int textrel_mprotect_compat_allowed(void)
{
	return textrel_mprotect_result(true, true);
}

static int write_relro_elf_fixture(const char *path)
{
	Elf64_Ehdr ehdr = {};
	Elf64_Phdr phdrs[2] = {};
	int fd;
	int ret;

	memcpy(ehdr.e_ident, ELFMAG, SELFMAG);
	ehdr.e_ident[EI_CLASS] = ELFCLASS64;
	ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr.e_ident[EI_VERSION] = EV_CURRENT;
	ehdr.e_ident[EI_OSABI] = ELFOSABI_SYSV;
	ehdr.e_type = ET_DYN;
	ehdr.e_machine = EM_X86_64;
	ehdr.e_version = EV_CURRENT;
	ehdr.e_ehsize = sizeof(ehdr);
	ehdr.e_phoff = sizeof(ehdr);
	ehdr.e_phentsize = sizeof(phdrs[0]);
	ehdr.e_phnum = ARRAY_SIZE(phdrs);

	phdrs[0].p_type = PT_LOAD;
	phdrs[0].p_filesz = 8192;
	phdrs[0].p_memsz = 8192;
	phdrs[0].p_flags = PF_R | PF_W;
	phdrs[0].p_align = 4096;

	phdrs[1].p_type = PT_GNU_RELRO;
	phdrs[1].p_offset = 0x1800;
	phdrs[1].p_vaddr = 0x2800;
	phdrs[1].p_filesz = 0x200;
	phdrs[1].p_memsz = 0x200;
	phdrs[1].p_flags = PF_R;
	phdrs[1].p_align = 4096;

	fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
	if (fd < 0)
		return -errno;

	ret = write_all_fd(fd, &ehdr, sizeof(ehdr));
	if (!ret)
		ret = write_all_fd(fd, phdrs, sizeof(phdrs));
	if (!ret && ftruncate(fd, 8192))
		ret = -errno;

	close(fd);
	if (ret)
		unlink(path);
	return ret;
}

static int relro_write_restore_result(bool expect_allow, bool require_event)
{
	unsigned int before;
	size_t page_size = sysconf(_SC_PAGESIZE);
	int saved_errno = 0;
	void *addr;
	int fd;
	int ret;

	ret = write_relro_elf_fixture(HDN_RELRO_ELF);
	if (ret)
		return 2;

	fd = open(HDN_RELRO_ELF, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		unlink(HDN_RELRO_ELF);
		return 2;
	}

	addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE, fd, page_size);
	if (addr == MAP_FAILED) {
		close(fd);
		unlink(HDN_RELRO_ELF);
		return 2;
	}
	if (mprotect(addr, page_size, PROT_READ)) {
		munmap(addr, page_size);
		close(fd);
		unlink(HDN_RELRO_ELF);
		return 2;
	}

	before = securityfs_events_count("reason=60");
	errno = 0;
	ret = mprotect(addr, page_size, PROT_READ | PROT_WRITE);
	if (ret)
		saved_errno = errno;

	munmap(addr, page_size);
	close(fd);
	unlink(HDN_RELRO_ELF);

	if (expect_allow) {
		if (ret)
			return errno_is_denial(saved_errno) ? 1 : 2;
		return !require_event ||
		       event_count_increased("reason=60", before) ? 0 : 1;
	}

	if (!ret)
		return 1;
	if (!errno_is_denial(saved_errno))
		return 2;
	return !require_event || event_count_increased("reason=60", before) ?
	       0 : 1;
}

static void test_relro_write_restore_denied(void)
{
	int ret = relro_write_restore_result(false, true);

	ksft_test_result(!ret, "sealed ELF RELRO cannot become writable again\n");
	if (ret == 2)
		ksft_print_msg("ELF RELRO write-restoration test setup failed\n");
}

static int relro_write_restore_compat_allowed(void)
{
	return relro_write_restore_result(true, true);
}

static void test_fixed_anonymous_exec_denied(void)
{
	size_t page_size = sysconf(_SC_PAGESIZE);
	void *reserved;
	void *addr;
	int saved_errno = 0;

	reserved = mmap(NULL, page_size, PROT_NONE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (reserved == MAP_FAILED) {
		ksft_test_result_fail("fixed RX mmap setup failed: %s\n",
				      strerror(errno));
		return;
	}

	if (munmap(reserved, page_size)) {
		ksft_test_result_fail("fixed RX mmap slot release failed: %s\n",
				      strerror(errno));
		return;
	}

	errno = 0;
	addr = mmap(reserved, page_size, PROT_READ | PROT_EXEC,
		    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	if (addr == MAP_FAILED)
		saved_errno = errno;
	else
		munmap(addr, page_size);

	ksft_test_result(addr == MAP_FAILED && errno_is_denial(saved_errno),
			 "fixed anonymous executable mmap is denied\n");
}

static void test_read_implies_exec_rewritten(void)
{
	size_t page_size = sysconf(_SC_PAGESIZE);
	bool executable = true;
	long original;
	void *addr;
	int saved_errno = 0;
	int ret;

	errno = 0;
	original = personality(0xffffffffUL);
	if (original < 0) {
		ksft_test_result_fail("personality read failed: %s\n",
				      strerror(errno));
		return;
	}

	if (personality((unsigned long)original | READ_IMPLIES_EXEC) < 0) {
		ksft_test_result_fail("personality setup failed: %s\n",
				      strerror(errno));
		return;
	}

	addr = mmap(NULL, page_size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS,
		    -1, 0);
	if (addr == MAP_FAILED)
		saved_errno = errno;
	ret = personality((unsigned long)original);
	if (ret < 0)
		ksft_print_msg("personality restore failed: %s\n",
			       strerror(errno));
	if (addr == MAP_FAILED) {
		ksft_test_result_fail("READ_IMPLIES_EXEC mmap failed: %s\n",
				      strerror(saved_errno));
		return;
	}

	ret = mapping_has_exec(addr, &executable);
	munmap(addr, page_size);
	if (ret) {
		ksft_test_result_fail("READ_IMPLIES_EXEC VMA lookup failed\n");
		return;
	}

	ksft_test_result(!executable,
			 "READ_IMPLIES_EXEC mmap is rewritten without execute\n");
}

static int unprivileged_userns_denied(void)
{
	if (!unshare(CLONE_NEWUSER))
		return 1;
	return errno_is_denial(errno) ? 0 : 2;
}

static void test_unprivileged_userns_denied(void)
{
	run_as_unprivileged(unprivileged_userns_denied,
			    "unprivileged user namespace creation is denied");
}

static int map_current_userns(uid_t outer_uid, gid_t outer_gid)
{
	char mapping[64];
	int ret;

	ret = write_created_text_file("/proc/self/setgroups", "deny\n");
	if (ret && ret != -ENOENT)
		return ret;

	if (snprintf(mapping, sizeof(mapping), "0 %u 1\n", outer_uid) >=
	    (int)sizeof(mapping))
		return -EOVERFLOW;
	ret = write_created_text_file("/proc/self/uid_map", mapping);
	if (ret)
		return ret;

	if (snprintf(mapping, sizeof(mapping), "0 %u 1\n", outer_gid) >=
	    (int)sizeof(mapping))
		return -EOVERFLOW;
	return write_created_text_file("/proc/self/gid_map", mapping);
}

static int userns_depth_sentinel(void)
{
	unsigned int level;
	int ret;

	if (!securityfs_status_has_line("current_profile: 2")) {
		fprintf(stderr, "userns-depth sentinel did not enter profile 2\n");
		return 2;
	}

	for (level = 1; level <= 2; level++) {
		uid_t outer_uid = geteuid();
		gid_t outer_gid = getegid();

		if (unshare(CLONE_NEWUSER)) {
			fprintf(stderr,
				"userns-depth unshare level %u failed: %s\n",
				level, strerror(errno));
			return 2;
		}
		ret = map_current_userns(outer_uid, outer_gid);
		if (ret) {
			fprintf(stderr,
				"userns-depth map level %u failed: %s\n",
				level, strerror(-ret));
			return 2;
		}
	}

	errno = 0;
	if (!unshare(CLONE_NEWUSER))
		return 1;

	if (errno_is_denial(errno))
		return 0;

	fprintf(stderr, "userns-depth level 3 failed unexpectedly: %s\n",
		strerror(errno));
	return 2;
}

static int userns_depth_policy_enforced(void)
{
	pid_t child;

	child = fork();
	if (child < 0)
		return 2;
	if (!child) {
		execl("/hdn_smoke", "hdn_smoke", "--userns-depth-sentinel",
		      NULL);
		fprintf(stderr, "userns-depth sentinel exec failed: %s\n",
			strerror(errno));
		_exit(2);
	}

	return child_exit_result(child);
}

#ifdef __NR_bpf
#define HDN_BPF_INSN(_code, _dst, _src, _off, _imm)	\
	((struct bpf_insn) {				\
		.code = (_code),			\
		.dst_reg = (_dst),			\
		.src_reg = (_src),			\
		.off = (_off),				\
		.imm = (_imm),				\
	})
#define HDN_BPF_MOV64_IMM(_dst, _imm) \
	HDN_BPF_INSN(BPF_ALU64 | BPF_MOV | BPF_K, _dst, 0, 0, _imm)
#define HDN_BPF_MOV64_REG(_dst, _src) \
	HDN_BPF_INSN(BPF_ALU64 | BPF_MOV | BPF_X, _dst, _src, 0, 0)
#define HDN_BPF_ALU64_IMM(_op, _dst, _imm) \
	HDN_BPF_INSN(BPF_ALU64 | BPF_OP(_op) | BPF_K, _dst, 0, 0, _imm)
#define HDN_BPF_ST_MEM(_size, _dst, _off, _imm) \
	HDN_BPF_INSN(BPF_ST | BPF_SIZE(_size) | BPF_MEM, _dst, 0, _off, _imm)
#define HDN_BPF_CALL(_func) \
	HDN_BPF_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, _func)
#define HDN_BPF_EXIT_INSN() \
	HDN_BPF_INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
#define HDN_BTF_INFO_ENC(_kind, _kind_flag, _vlen) \
	((!!(_kind_flag) << 31) | ((_kind) << 24) | ((_vlen) & BTF_MAX_VLEN))
#define HDN_BTF_TYPE_ENC(_name, _info, _size_or_type) \
	(_name), (_info), (_size_or_type)
#define HDN_BTF_FUNC_PROTO_ENC(_ret_type, _nargs) \
	HDN_BTF_TYPE_ENC(0, HDN_BTF_INFO_ENC(BTF_KIND_FUNC_PROTO, 0, _nargs), \
			 _ret_type)
#define HDN_BTF_FUNC_ENC(_name, _func_proto) \
	HDN_BTF_TYPE_ENC(_name, HDN_BTF_INFO_ENC(BTF_KIND_FUNC, 0, 0), \
			 _func_proto)

static int unprivileged_bpf_load_denied(void)
{
	struct bpf_insn insns[] = {
		{
			.code = BPF_ALU64 | BPF_MOV | BPF_K,
			.dst_reg = BPF_REG_0,
			.imm = 0,
		},
		{
			.code = BPF_JMP | BPF_EXIT,
		},
	};
	static const char license[] = "GPL";
	union bpf_attr attr = {};
	int fd;

	attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
	attr.insn_cnt = ARRAY_SIZE(insns);
	attr.insns = (uintptr_t)insns;
	attr.license = (uintptr_t)license;

	errno = 0;
	fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	if (fd >= 0) {
		close(fd);
		return 1;
	}

	return errno_is_denial(errno) ? 0 : 2;
}

static int bpf_kallsyms_lookup_without_disclosure_denied(void)
{
	struct bpf_insn insns[] = {
		HDN_BPF_ST_MEM(BPF_B, BPF_REG_10, -8, '_'),
		HDN_BPF_ST_MEM(BPF_B, BPF_REG_10, -7, 's'),
		HDN_BPF_ST_MEM(BPF_B, BPF_REG_10, -6, 't'),
		HDN_BPF_ST_MEM(BPF_B, BPF_REG_10, -5, 'e'),
		HDN_BPF_ST_MEM(BPF_B, BPF_REG_10, -4, 'x'),
		HDN_BPF_ST_MEM(BPF_B, BPF_REG_10, -3, 't'),
		HDN_BPF_ST_MEM(BPF_B, BPF_REG_10, -2, '\0'),
		HDN_BPF_ST_MEM(BPF_DW, BPF_REG_10, -16, 0),
		HDN_BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
		HDN_BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -8),
		HDN_BPF_MOV64_IMM(BPF_REG_2, 7),
		HDN_BPF_MOV64_IMM(BPF_REG_3, 0),
		HDN_BPF_MOV64_REG(BPF_REG_4, BPF_REG_10),
		HDN_BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, -16),
		HDN_BPF_CALL(BPF_FUNC_kallsyms_lookup_name),
		HDN_BPF_EXIT_INSN(),
	};
	static const char license[] = "GPL";
	union bpf_attr attr = {};
	union bpf_attr run = {};
	unsigned int before;
	unsigned int after;
	int saved_errno = 0;
	int fd;
	int ret;

	before = securityfs_events_count("authority=9 transition=18");

	attr.prog_type = BPF_PROG_TYPE_SYSCALL;
	attr.prog_flags = BPF_F_SLEEPABLE;
	attr.insn_cnt = ARRAY_SIZE(insns);
	attr.insns = (uintptr_t)insns;
	attr.license = (uintptr_t)license;

	errno = 0;
	fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	if (fd < 0) {
		ksft_print_msg("BPF kallsyms helper load failed: errno=%d\n",
			       errno);
		return errno == EOPNOTSUPP || errno == ENOTSUP ? KSFT_SKIP : 2;
	}

	run.test.prog_fd = fd;
	errno = 0;
	ret = syscall(__NR_bpf, BPF_PROG_TEST_RUN, &run, sizeof(run));
	if (ret)
		saved_errno = errno;
	close(fd);
	if (ret) {
		ksft_print_msg("BPF kallsyms helper run failed: errno=%d\n",
			       saved_errno);
		return saved_errno == EOPNOTSUPP || saved_errno == ENOTSUP ?
		       KSFT_SKIP : 2;
	}
	if (run.test.retval != (uint32_t)-EPERM) {
		ksft_print_msg("BPF kallsyms helper returned %u, expected %u\n",
			       run.test.retval, (uint32_t)-EPERM);
		return 1;
	}

	after = securityfs_events_count("authority=9 transition=18");
	if (after <= before) {
		ksft_print_msg("BPF kallsyms helper event count did not increase: before=%u after=%u\n",
			       before, after);
		return 1;
	}

	return 0;
}

static int bpf_load_minimal_stext_btf(void)
{
	struct hdn_btf_blob {
		struct btf_header header;
		uint32_t types[6];
		char strings[8];
	} raw_btf = {
		.header = {
			.magic = BTF_MAGIC,
			.version = BTF_VERSION,
			.hdr_len = sizeof(struct btf_header),
			.type_len = sizeof(raw_btf.types),
			.str_off = sizeof(raw_btf.types),
			.str_len = sizeof(raw_btf.strings),
		},
		.types = {
			HDN_BTF_FUNC_PROTO_ENC(0, 0),	/* [1] void (*)(void) */
			HDN_BTF_FUNC_ENC(1, 1),		/* [2] _stext */
		},
		.strings = "\0_stext",
	};
	union bpf_attr attr = {};
	int fd;

	attr.btf = (uintptr_t)&raw_btf;
	attr.btf_size = sizeof(raw_btf);

	errno = 0;
	fd = syscall(__NR_bpf, BPF_BTF_LOAD, &attr, sizeof(attr));
	if (fd < 0)
		return -errno;
	return fd;
}

static int bpf_pseudo_btf_id_without_disclosure_denied(void)
{
#ifdef BPF_PSEUDO_BTF_ID
	struct bpf_insn insns[] = {
		HDN_BPF_INSN(BPF_LD | BPF_DW | BPF_IMM, BPF_REG_1,
			     BPF_PSEUDO_BTF_ID, 0, 2),
		HDN_BPF_INSN(0, 0, 0, 0, 0),
		HDN_BPF_MOV64_IMM(BPF_REG_0, 0),
		HDN_BPF_EXIT_INSN(),
	};
	static const char license[] = "GPL";
	union bpf_attr attr = {};
	unsigned int before;
	unsigned int after;
	int saved_errno;
	int btf_fd;
	int fd;

	btf_fd = bpf_load_minimal_stext_btf();
	if (btf_fd < 0) {
		saved_errno = -btf_fd;
		ksft_print_msg("BPF BTF load failed: errno=%d\n", saved_errno);
		return saved_errno == EOPNOTSUPP || saved_errno == ENOTSUP ?
		       KSFT_SKIP : 2;
	}

	insns[1].imm = btf_fd;
	before = securityfs_events_count("authority=9 transition=18");

	attr.prog_type = BPF_PROG_TYPE_SYSCALL;
	attr.prog_flags = BPF_F_SLEEPABLE;
	attr.insn_cnt = ARRAY_SIZE(insns);
	attr.insns = (uintptr_t)insns;
	attr.license = (uintptr_t)license;

	errno = 0;
	fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	saved_errno = errno;
	close(btf_fd);
	if (fd >= 0) {
		close(fd);
		return 1;
	}
	if (!errno_is_denial(saved_errno)) {
		ksft_print_msg("BPF pseudo-BTF symbol load failed unexpectedly: errno=%d\n",
			       saved_errno);
		return saved_errno == EOPNOTSUPP || saved_errno == ENOTSUP ?
		       KSFT_SKIP : 2;
	}

	after = securityfs_events_count("authority=9 transition=18");
	if (after <= before) {
		ksft_print_msg("BPF pseudo-BTF symbol event count did not increase: before=%u after=%u\n",
			       before, after);
		return 1;
	}

	return 0;
#else
	return KSFT_SKIP;
#endif
}
#else
static int bpf_kallsyms_lookup_without_disclosure_denied(void)
{
	return KSFT_SKIP;
}

static int bpf_pseudo_btf_id_without_disclosure_denied(void)
{
	return KSFT_SKIP;
}
#endif

static void test_unprivileged_bpf_load_denied(void)
{
#ifdef __NR_bpf
	run_as_unprivileged(unprivileged_bpf_load_denied,
			    "unprivileged BPF program load is denied");
#else
	ksft_test_result_skip("BPF syscall number unavailable\n");
#endif
}

static int unprivileged_userfaultfd_kernel_denied(void)
{
#ifdef __NR_userfaultfd
	int fd;

	errno = 0;
	fd = syscall(__NR_userfaultfd, 0);
	if (fd >= 0) {
		close(fd);
		return 1;
	}
	if (errno == ENOSYS)
		return 0;

	return errno_is_denial(errno) ? 0 : 2;
#else
	return 0;
#endif
}

static int unprivileged_userfaultfd_user_mode_allowed_or_unavailable(void)
{
#ifdef __NR_userfaultfd
	int fd;

	fd = syscall(__NR_userfaultfd, UFFD_USER_MODE_ONLY | O_CLOEXEC);
	if (fd < 0)
		return errno == ENOSYS ? 0 : 1;

	close(fd);
	return 0;
#else
	return 0;
#endif
}

static void test_unprivileged_userfaultfd_restricted(void)
{
#ifdef __NR_userfaultfd
	run_as_unprivileged(unprivileged_userfaultfd_kernel_denied,
			    "unprivileged kernel-fault userfaultfd is denied or unavailable");
	run_as_unprivileged(unprivileged_userfaultfd_user_mode_allowed_or_unavailable,
			    "unprivileged user-mode-only userfaultfd is allowed or unavailable");
#else
	ksft_test_result_pass("userfaultfd syscall number unavailable\n");
	ksft_test_result_pass("userfaultfd syscall number unavailable\n");
#endif
}

static int unprivileged_bpf_sysctl_locked(void)
{
	int ret;

	ret = write_text_file(HDN_UNPRIV_BPF_DISABLED, "0\n");
	if (!ret) {
		(void)write_text_file(HDN_UNPRIV_BPF_DISABLED, "1\n");
		return 1;
	}
	if (ret == -ENOENT)
		return KSFT_SKIP;

	return 0;
}

static int bpf_jit_harden_locked_or_unavailable(void)
{
	long value;
	int ret;

	ret = read_long_file(HDN_BPF_JIT_HARDEN, &value);
	if (ret == -ENOENT)
		return 0;
	if (ret || value != 2)
		return 1;

	ret = write_text_file(HDN_BPF_JIT_HARDEN, "1\n");
	if (!ret) {
		(void)write_text_file(HDN_BPF_JIT_HARDEN, "2\n");
		return 1;
	}

	return 0;
}

static int bpf_jit_kallsyms_locked_or_unavailable(void)
{
	long value;
	int ret;

	ret = read_long_file(HDN_BPF_JIT_KALLSYMS, &value);
	if (ret == -ENOENT)
		return 0;
	if (ret || value != 0)
		return 1;

	ret = write_text_file(HDN_BPF_JIT_KALLSYMS, "1\n");
	if (!ret) {
		(void)write_text_file(HDN_BPF_JIT_KALLSYMS, "0\n");
		return 1;
	}

	return 0;
}

static int perf_event_paranoid_sysctl_locked(void)
{
	int ret;

	ret = write_text_file(HDN_PERF_EVENT_PARANOID, "2\n");
	if (!ret) {
		(void)write_text_file(HDN_PERF_EVENT_PARANOID, "3\n");
		return 1;
	}
	if (ret == -ENOENT)
		return KSFT_SKIP;

	return 0;
}

static int yama_ptrace_scope_sysctl_locked(void)
{
	int ret;

	ret = write_text_file(HDN_YAMA_PTRACE_SCOPE, "0\n");
	if (!ret) {
		(void)write_text_file(HDN_YAMA_PTRACE_SCOPE, "1\n");
		return 1;
	}
	if (ret == -ENOENT)
		return KSFT_SKIP;

	return 0;
}

static int suid_dumpable_sysctl_locked(void)
{
	int ret;

	ret = write_text_file(HDN_SUID_DUMPABLE, "2\n");
	if (!ret) {
		(void)write_text_file(HDN_SUID_DUMPABLE, "0\n");
		return 1;
	}
	if (ret == -ENOENT)
		return KSFT_SKIP;

	return ret == -EINVAL || errno_is_denial(-ret) ? 0 : 2;
}

static int unprivileged_userfaultfd_sysctl_locked(void)
{
	int ret;

	ret = write_text_file(HDN_UNPRIV_USERFAULTFD, "1\n");
	if (!ret) {
		(void)write_text_file(HDN_UNPRIV_USERFAULTFD, "0\n");
		return 1;
	}
	if (ret == -ENOENT)
		return 0;

	return ret == -EINVAL || errno_is_denial(-ret) ? 0 : 2;
}

static int unprivileged_userfaultfd_disabled_or_unavailable(void)
{
	long value;
	int ret;

	ret = read_long_file(HDN_UNPRIV_USERFAULTFD, &value);
	if (ret == -ENOENT)
		return 0;
	if (ret)
		return 2;

	return value == 0 ? 0 : 1;
}

static int io_uring_disabled_sysctl_monotonic(void)
{
	long value;
	int ret;

	ret = read_long_file(HDN_IO_URING_DISABLED, &value);
	if (ret == -ENOENT)
		return KSFT_SKIP;
	if (ret || value < 0 || value > 2)
		return 2;

	if (value == 0) {
		ret = write_text_file(HDN_IO_URING_DISABLED, "1\n");
		if (ret)
			return 2;
		value = 1;
	}

	ret = write_text_file(HDN_IO_URING_DISABLED,
			      value == 2 ? "1\n" : "0\n");
	if (!ret)
		return 1;
	if (ret == -ENOENT)
		return KSFT_SKIP;

	ret = read_long_file(HDN_IO_URING_DISABLED, &value);
	if (ret)
		return 2;
	return value >= 1 ? 0 : 1;
}

static int one_way_disable_sysctl_locked(const char *path)
{
	long value;
	int ret;

	ret = read_long_file(path, &value);
	if (ret == -ENOENT)
		return KSFT_SKIP;
	if (ret || value < 0 || value > 1)
		return 2;

	if (value == 0) {
		ret = write_text_file(path, "1\n");
		if (ret)
			return ret == -ENOENT ? KSFT_SKIP : 2;
	}

	ret = write_text_file(path, "0\n");
	if (!ret)
		return 1;
	if (ret == -ENOENT)
		return KSFT_SKIP;

	ret = read_long_file(path, &value);
	if (ret)
		return 2;
	return value == 1 ? 0 : 1;
}

static int kptr_restrict_sysctl_locked(void)
{
	int ret;

	ret = write_text_file(HDN_KPTR_RESTRICT, "1\n");
	if (!ret) {
		(void)write_text_file(HDN_KPTR_RESTRICT, "2\n");
		return 1;
	}
	if (ret == -ENOENT)
		return KSFT_SKIP;

	return 0;
}

static int dmesg_restrict_sysctl_locked(void)
{
	int ret;

	ret = write_text_file(HDN_DMESG_RESTRICT, "0\n");
	if (!ret) {
		(void)write_text_file(HDN_DMESG_RESTRICT, "1\n");
		return 1;
	}
	if (ret == -ENOENT)
		return KSFT_SKIP;

	return 0;
}

static int legacy_tiocsti_sysctl_locked(void)
{
	int ret;

	ret = write_text_file(HDN_LEGACY_TIOCSTI, "1\n");
	if (!ret) {
		(void)write_text_file(HDN_LEGACY_TIOCSTI, "0\n");
		return 1;
	}
	if (ret == -ENOENT)
		return KSFT_SKIP;

	return 0;
}

static int ldisc_autoload_sysctl_locked(void)
{
	int ret;

	ret = write_text_file(HDN_LDISC_AUTOLOAD, "1\n");
	if (!ret) {
		(void)write_text_file(HDN_LDISC_AUTOLOAD, "0\n");
		return 1;
	}
	if (ret == -ENOENT)
		return KSFT_SKIP;

	return 0;
}

static int memfd_noexec_sysctl_locked(void)
{
	int ret;

	ret = write_text_file(HDN_MEMFD_NOEXEC, "1\n");
	if (!ret) {
		(void)write_text_file(HDN_MEMFD_NOEXEC, "2\n");
		return 1;
	}
	if (ret == -ENOENT)
		return KSFT_SKIP;

	return ret == -EINVAL || errno_is_denial(-ret) ? 0 : 2;
}

static int mmap_min_addr_sysctl_locked(void)
{
	char restore[32];
	long value;
	int ret;

	ret = read_long_file(HDN_MMAP_MIN_ADDR, &value);
	if (ret == -ENOENT)
		return KSFT_SKIP;
	if (ret)
		return 2;
	if (value < (long)HDN_MMAP_MIN_ADDR_FLOOR)
		return 1;

	snprintf(restore, sizeof(restore), "%ld\n", value);
	ret = write_text_file(HDN_MMAP_MIN_ADDR, "0\n");
	if (!ret) {
		(void)write_text_file(HDN_MMAP_MIN_ADDR, restore);
		return 1;
	}
	if (ret == -ENOENT)
		return KSFT_SKIP;

	return ret == -EINVAL || errno_is_denial(-ret) ? 0 : 2;
}

static int low_fixed_mmap_denied(void)
{
	long page_size;
	void *addr;

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0 || (unsigned long)page_size >= HDN_MMAP_MIN_ADDR_FLOOR)
		return KSFT_SKIP;

	errno = 0;
	addr = mmap((void *)page_size, (size_t)page_size, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	if (addr != MAP_FAILED) {
		munmap(addr, (size_t)page_size);
		return 1;
	}

	return errno_is_denial(errno) || errno == EINVAL ? 0 : 2;
}

static int protected_path_sysctl_locked(const char *path, const char *lower,
					const char *restore)
{
	int ret;

	ret = write_text_file(path, lower);
	if (!ret) {
		(void)write_text_file(path, restore);
		return 1;
	}
	if (ret == -ENOENT)
		return KSFT_SKIP;
	return ret == -EINVAL || errno_is_denial(-ret) ? 0 : 2;
}

static int memfd_exec_flag_denied(void)
{
#ifdef __NR_memfd_create
	int fd;

	errno = 0;
	fd = syscall(__NR_memfd_create, "hdn-exec-memfd",
		     MFD_CLOEXEC | MFD_EXEC);
	if (fd >= 0) {
		close(fd);
		return 1;
	}

	return errno_is_denial(errno) ? 0 : 2;
#else
	return KSFT_SKIP;
#endif
}

#ifdef __NR_perf_event_open
static int unprivileged_perf_kernel_denied(void)
{
	struct perf_event_attr attr = {};
	int fd;

	attr.type = PERF_TYPE_SOFTWARE;
	attr.size = sizeof(attr);
	attr.config = PERF_COUNT_SW_CPU_CLOCK;
	attr.disabled = 1;
	attr.exclude_kernel = 0;
	attr.exclude_hv = 1;

	errno = 0;
	fd = syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
	if (fd >= 0) {
		close(fd);
		return 1;
	}

	return errno_is_denial(errno) ? 0 : 2;
}
#endif

static void test_unprivileged_perf_kernel_denied(void)
{
#ifdef __NR_perf_event_open
	run_as_unprivileged(unprivileged_perf_kernel_denied,
			    "unprivileged kernel perf visibility is denied");
#else
	ksft_test_result_skip("perf_event_open syscall number unavailable\n");
#endif
}

#ifdef __NR_syslog
static int unprivileged_kernel_log_denied(void)
{
	char buf[1];
	int ret;

	errno = 0;
	ret = syscall(__NR_syslog, HDN_SYSLOG_ACTION_READ_ALL, buf,
		      sizeof(buf));
	if (!ret)
		return 1;

	return errno_is_denial(errno) ? 0 : 2;
}
#endif

static void test_unprivileged_kernel_log_denied(void)
{
#ifdef __NR_syslog
	run_as_unprivileged(unprivileged_kernel_log_denied,
			    "unprivileged kernel log read is denied");
#else
	ksft_test_result_skip("syslog syscall number unavailable\n");
#endif
}

#ifdef __NR_ioperm
static int unprivileged_raw_io_denied(void)
{
	int ret;

	errno = 0;
	ret = syscall(__NR_ioperm, 0, 1, 1);
	if (!ret)
		return 1;

	return errno_is_denial(errno) ? 0 : 2;
}
#endif

static void test_unprivileged_raw_io_denied(void)
{
#ifdef __NR_ioperm
	run_as_unprivileged(unprivileged_raw_io_denied,
			    "unprivileged raw I/O permission is denied");
#else
	ksft_test_result_skip("ioperm syscall number unavailable\n");
#endif
}

#ifdef __NR_io_uring_setup
static int unprivileged_io_uring_sqpoll_denied(void)
{
	struct io_uring_params params = {};
	int fd;

	params.flags = IORING_SETUP_SQPOLL;

	errno = 0;
	fd = syscall(__NR_io_uring_setup, 2, &params);
	if (fd >= 0) {
		close(fd);
		return 1;
	}

	return errno_is_denial(errno) ? 0 : 2;
}

static int unprivileged_io_uring_restricted_denied(void)
{
	struct io_uring_params params = {};
	unsigned int workers[2] = { 1, 1 };
	int saved_errno = 0;
	int fd;
	int ret;

	errno = 0;
	fd = syscall(__NR_io_uring_setup, 2, &params);
	if (fd < 0) {
		if (errno_is_denial(errno))
			return KSFT_SKIP;
		return 2;
	}

	errno = 0;
	ret = syscall(__NR_io_uring_register, fd,
		      IORING_REGISTER_IOWQ_MAX_WORKERS, workers,
		      ARRAY_SIZE(workers));
	if (ret)
		saved_errno = errno;
	close(fd);

	if (!ret)
		return 1;
	return errno_is_denial(saved_errno) ? 0 : 2;
}
#endif

static void test_unprivileged_io_uring_sqpoll_denied(void)
{
#ifdef __NR_io_uring_setup
	unsigned int before;

	before = securityfs_events_count("authority=14 transition=13");
	run_as_unprivileged(unprivileged_io_uring_sqpoll_denied,
			    "unprivileged io_uring SQPOLL setup is denied");
	ksft_test_result(securityfs_events_count("authority=14 transition=13") >
			 before,
			 "hardening events report io_uring SQPOLL denial\n");
#else
	ksft_test_result_skip("io_uring syscall numbers unavailable\n");
	ksft_test_result_skip("io_uring syscall numbers unavailable\n");
#endif
}

static void test_unprivileged_io_uring_restricted_denied(void)
{
#ifdef __NR_io_uring_setup
	run_as_unprivileged(unprivileged_io_uring_restricted_denied,
			    "unprivileged restricted io_uring registration is denied");
#else
	ksft_test_result_skip("io_uring syscall numbers unavailable\n");
#endif
}

static int compare_ulong(const void *a, const void *b)
{
	unsigned long va = *(const unsigned long *)a;
	unsigned long vb = *(const unsigned long *)b;

	if (va < vb)
		return -1;
	if (va > vb)
		return 1;
	return 0;
}

static void test_rand_threadstack_gap_flags(unsigned long stack_flags,
					    const char *label)
{
	void *maps[HDN_THREADSTACK_MAP_COUNT] = {};
	unsigned long starts[HDN_THREADSTACK_MAP_COUNT];
	unsigned long first_gap = 0;
	unsigned long page_size;
	bool page_aligned = true;
	bool have_gap = false;
	bool varied = false;
	long sys_page_size;
	int i;

	sys_page_size = sysconf(_SC_PAGESIZE);
	if (sys_page_size <= 0) {
		ksft_test_result_skip("page size unavailable\n");
		return;
	}
	page_size = (unsigned long)sys_page_size;

	for (i = 0; i < HDN_THREADSTACK_MAP_COUNT; i++) {
		maps[i] = mmap(NULL, HDN_THREADSTACK_MAP_SIZE,
			       PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS | stack_flags, -1, 0);
		if (maps[i] == MAP_FAILED) {
			ksft_test_result_fail("%s mmap failed: %s\n",
					      label, strerror(errno));
			goto out;
		}
		starts[i] = (unsigned long)maps[i];
	}

	qsort(starts, HDN_THREADSTACK_MAP_COUNT, sizeof(starts[0]),
	      compare_ulong);
	for (i = 1; i < HDN_THREADSTACK_MAP_COUNT; i++) {
		unsigned long prev_end;
		unsigned long gap;

		if (starts[i - 1] > ULONG_MAX - HDN_THREADSTACK_MAP_SIZE)
			continue;
		prev_end = starts[i - 1] + HDN_THREADSTACK_MAP_SIZE;
		if (starts[i] <= prev_end)
			continue;

		gap = starts[i] - prev_end;
		if (gap % page_size)
			page_aligned = false;
		if (!have_gap) {
			first_gap = gap;
			have_gap = true;
		} else if (gap != first_gap) {
			varied = true;
		}
	}

	if (!have_gap || !varied || !page_aligned)
		ksft_print_msg("%s gaps have=%d varied=%d aligned=%d first=%lu\n",
			       label, have_gap, varied, page_aligned, first_gap);
	ksft_test_result(have_gap && varied && page_aligned,
			 "%s mappings receive random inter-stack gaps\n",
			 label);

out:
	for (i = 0; i < HDN_THREADSTACK_MAP_COUNT; i++) {
		if (maps[i] && maps[i] != MAP_FAILED)
			munmap(maps[i], HDN_THREADSTACK_MAP_SIZE);
	}
}

static void test_rand_threadstack_gap(void)
{
#ifdef MAP_STACK
	test_rand_threadstack_gap_flags(MAP_STACK, "anonymous MAP_STACK");
#else
	ksft_test_result_skip("MAP_STACK unavailable\n");
#endif
#ifdef MAP_GROWSDOWN
	test_rand_threadstack_gap_flags(MAP_GROWSDOWN, "anonymous MAP_GROWSDOWN");
#else
	ksft_test_result_skip("MAP_GROWSDOWN unavailable\n");
#endif
}

#ifdef __NR_init_module
static void test_raw_init_module_denied(void)
{
	char image[16] = {};
	int saved_errno = 0;
	int ret;

	if (geteuid() != 0) {
		ksft_test_result_skip("raw init_module denial needs root\n");
		return;
	}

	errno = 0;
	ret = syscall(__NR_init_module, image, sizeof(image), "");
	if (ret)
		saved_errno = errno;

	ksft_test_result(ret && errno_is_denial(saved_errno),
			 "raw init_module image is denied\n");
}
#endif

static void test_init_module_denied(void)
{
#ifdef __NR_init_module
	test_raw_init_module_denied();
#else
	ksft_test_result_skip("init_module syscall number unavailable\n");
#endif
}

static void test_unsigned_policy_denied(void)
{
	char blob[128] = {};
	int saved_errno = 0;
	ssize_t len;
	int fd;

	if (geteuid() != 0) {
		ksft_test_result_skip("policy load denial needs root\n");
		return;
	}

	fd = open(HDN_POLICY, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		ksft_test_result_skip("hardening policy is not writable: %s\n",
				      strerror(errno));
		return;
	}

	errno = 0;
	len = write(fd, blob, sizeof(blob));
	if (len < 0)
		saved_errno = errno;
	close(fd);

	ksft_test_result(len < 0 && errno_is_policy_rejection(saved_errno),
			 "unsigned hardening policy is denied\n");
}

static int ptrace_target_main(void)
{
	char ready = 1;

	if (write(3, &ready, sizeof(ready)) != sizeof(ready))
		return 2;
	close(3);

	for (;;)
		pause();
}

int main(int argc, char **argv)
{
	if (hdn_is_modprobe_invocation(argc, argv))
		return hdn_modprobe_capture_main(argc, argv);
	if (argc == 2 && !strcmp(argv[1], "--exec-sentinel"))
		return 42;
	if (argc >= 2 && !strcmp(argv[1], "--exec-args-sentinel"))
		return 42;
	if (argc == 2 && !strcmp(argv[1], "--setuid-sentinel"))
		return setuid_exec_sentinel();
	if (argc == 2 && !strcmp(argv[1], "--filecap-sentinel"))
		return filecap_exec_sentinel();
	if (argc == 2 && !strcmp(argv[1], "--suid-spectre-sentinel"))
		return suid_spectre_sentinel();
	if (argc == 2 && !strcmp(argv[1], "--privexec-stack-sentinel"))
		return privexec_stack_limit_sentinel();
	if (argc == 2 && !strcmp(argv[1], "--privexec-arglimit-sentinel"))
		return 73;
	if (argc == 2 && !strcmp(argv[1], "--crash-sentinel")) {
		raise(SIGSEGV);
		return 2;
	}
	if (argc == 2 && !strcmp(argv[1], "--daemon-brute-sentinel"))
		return daemon_brute_fork_delayed_child();
	if (argc == 2 && !strcmp(argv[1], "--privdesc-coredump-dropper"))
		return privileged_descendant_coredump_dropper();
	if (argc == 2 && !strcmp(argv[1], "--privdesc-coredump-trigger"))
		return privileged_descendant_coredump_trigger();
	if (argc >= 2 && !strcmp(argv[1], "--identity-binary-sentinel"))
		return profile_sentinel(3);
	if (argc >= 2 && !strcmp(argv[1], "--identity-drop-sentinel")) {
		if (setgid(HDN_TEST_NOBODY) || setuid(HDN_TEST_NOBODY))
			return 2;
		return profile_sentinel(3);
	}
	if (argc >= 2 && !strcmp(argv[1], "--identity-default-sentinel"))
		return profile_sentinel(1);
	if (argc >= 2 && !strcmp(argv[1], "--identity-script-sentinel"))
		return profile_sentinel(4);
	if (argc >= 2 && !strcmp(argv[1], "--identity-launch-inherit-sentinel")) {
		execl(HDN_IDENTITY_INHERIT_EXEC, HDN_IDENTITY_INHERIT_EXEC,
		      "--identity-binary-sentinel", NULL);
		return 2;
	}
	if (argc >= 2 &&
	    !strcmp(argv[1], "--identity-launch-unmatched-inherit-sentinel")) {
		execl(HDN_IDENTITY_COPY_EXEC, HDN_IDENTITY_COPY_EXEC,
		      "--identity-binary-sentinel", NULL);
		return 2;
	}
	if (argc >= 2 &&
	    !strcmp(argv[1], "--identity-launch-parent-inherit-sentinel")) {
		execl(HDN_IDENTITY_PARENT_INHERIT_EXEC,
		      HDN_IDENTITY_PARENT_INHERIT_EXEC,
		      "--identity-binary-sentinel", NULL);
		return 2;
	}
	if (argc >= 2 && !strcmp(argv[1], "--subject-uid-sentinel"))
		return profile_sentinel(7);
	if (argc >= 2 && !strcmp(argv[1], "--subject-gid-sentinel"))
		return profile_sentinel(8);
	if (argc >= 2 && !strcmp(argv[1], "--subject-umask-file-sentinel"))
		return subject_umask_file_sentinel();
	if (argc >= 2 && !strcmp(argv[1], "--subject-umask-dir-sentinel"))
		return subject_umask_dir_sentinel();
	if (argc >= 2 && !strcmp(argv[1], "--userns-depth-sentinel"))
		return userns_depth_sentinel();
	if (argc == 2 &&
	    !strcmp(argv[1], "--rofs-updater-writable-mount-sentinel"))
		return rofs_updater_writable_mount_sentinel();
	if (argc == 2 && !strcmp(argv[1], "--product-rofs-write-sentinel"))
		return product_rofs_write_sentinel();
	if (argc == 3 && !strcmp(argv[1], "--product-rofs-cancel-worker"))
		return product_rofs_cancel_worker(argv[2]);
	if (argc == 3 && !strcmp(argv[1], "--product-rofs-orphan-worker"))
		return product_rofs_orphan_worker(argv[2]);
	if (argc == 3 && !strcmp(argv[1], "--recovery-confirm-allow"))
		return recovery_confirm_sentinel(argv[2], true);
	if (argc == 3 && !strcmp(argv[1], "--recovery-confirm-deny"))
		return recovery_confirm_sentinel(argv[2], false);
	if (argc == 3 && !strcmp(argv[1], "--prompt-auth-allow"))
		return prompt_auth_sentinel(argv[2], true);
	if (argc == 3 && !strcmp(argv[1], "--prompt-auth-deny"))
		return prompt_auth_sentinel(argv[2], false);
	if (argc == 2 && !strcmp(argv[1], "--ptrace-target"))
		return ptrace_target_main();
	if (argc == 2 && !strcmp(argv[1], "--proc-root-reader"))
		return proc_root_disclosed_without_ptrace();
	if (argc == 2 && !strcmp(argv[1], "--proc-ptrace-reader"))
		return ptrace_attach_same_uid_denied();
	if (argc == 2 && !strcmp(argv[1], "--exec-only-target"))
		return execute_only_target_main();
	if (argc == 2 && !strcmp(argv[1], "--signal-crash-sentinel"))
		return signal_crash_sentinel();
	if (argc >= 2 && !strcmp(argv[1], "--proc-sensitive-target"))
		return proc_sensitive_target_main();

	ksft_print_header();

	if (access(HDN_STATUS, R_OK))
		ksft_exit_skip("hardening securityfs status not present\n");

	ksft_set_plan(1118);
	report_child_result(prompt_session_unprivileged_authorized_denied(),
			    "prompt session rejects unprivileged authorized bypass");
	test_securityfs_status();
	test_symbol_test_module_load();
	test_securityfs_status_contains("abi_version: 99",
					"hardening status reports policy ABI 99");
	test_securityfs_status_contains("phase:",
					"hardening status reports sealing phase");
	test_securityfs_status_contains("policy_staged:",
					"hardening status reports staged policy state");
	test_securityfs_status_contains("policy_sealed:",
					"hardening status reports active policy sealing");
	test_securityfs_status_contains("staged_policy_sealed:",
					"hardening status reports staged policy sealing");
	test_securityfs_status_contains("expected_generation:",
					"hardening status reports active policy base");
	test_securityfs_status_contains("staged_expected_generation:",
					"hardening status reports staged policy base");
	test_securityfs_status_contains("current_mntns_profile:",
					"hardening status reports mount namespace profile");
	test_securityfs_status_contains("module_rule_count:",
					"hardening status reports module trust rule count");
	test_securityfs_status_contains("firmware_rule_count:",
					"hardening status reports firmware trust rule count");
	test_securityfs_status_contains("resource_rule_count:",
					"hardening status reports resource limit rule count");
	test_securityfs_status_contains("mitigations_sealed: 1",
					"hardening status reports sealed mitigation state");
	test_securityfs_status_contains("mitigation_hardened_usercopy: 1",
					"hardening status reports hardened usercopy");
	test_securityfs_status_contains("mitigation_init_on_alloc: 1",
					"hardening status reports init-on-alloc");
	test_securityfs_status_contains("mitigation_init_on_free: 1",
					"hardening status reports init-on-free");
	test_securityfs_status_contains("mitigation_init_stack_zero: 1",
					"hardening status reports stack zero initialization");
	test_securityfs_status_contains("mitigation_kstack_erase: 1",
					"hardening status reports kernel stack erasure");
	test_securityfs_status_contains("mitigation_zero_call_used_regs: 1",
					"hardening status reports zeroed call-used registers");
	test_securityfs_status_contains("mitigation_fortify_source: 1",
					"hardening status reports fortify source");
	test_securityfs_status_contains("mitigation_randstruct: 1",
					"hardening status reports randomized kernel structures");
	test_securityfs_status_contains("mitigation_slab_freelist_random: 1",
					"hardening status reports slab freelist randomization");
	test_securityfs_status_contains("mitigation_slab_freelist_hardened: 1",
					"hardening status reports slab freelist hardening");
	test_securityfs_status_contains("mitigation_random_kmalloc_caches: 1",
					"hardening status reports random kmalloc caches");
	test_securityfs_status_contains("mitigation_slab_buckets: 1",
					"hardening status reports isolated slab buckets");
	test_securityfs_status_contains("mitigation_slab_merge_disabled: 1",
					"hardening status reports disabled slab merging");
	test_securityfs_status_contains("mitigation_randomize_kstack: 1",
					"hardening status reports syscall kernel-stack offset randomization");
	test_securityfs_status_contains("mitigation_dmesg_restrict: 1",
					"hardening status reports dmesg restriction");
	test_int_file_equals(HDN_DMESG_RESTRICT, 1,
			     "dmesg sysctl is locked restricted");
	report_child_result(dmesg_restrict_sysctl_locked(),
			    "dmesg sysctl cannot be lowered");
	test_securityfs_status_contains("mitigation_proc_mem_restrict: 1",
					"hardening status reports proc mem restriction");
	test_securityfs_status_contains("mitigation_proc_memmap_redact: 1",
					"hardening status reports proc memmap redaction");
	test_securityfs_status_contains("mitigation_userfaultfd_restrict: 1",
					"hardening status reports userfaultfd restriction");
	test_securityfs_status_contains("mitigation_page_table_check: 1",
					"hardening status reports page table checking");
	test_securityfs_status_contains("mitigation_mmap_min_addr: 1",
					"hardening status reports low mmap floor");
	report_child_result(mmap_min_addr_sysctl_locked(),
			    "mmap_min_addr sysctl cannot be lowered below floor");
	run_as_unprivileged(low_fixed_mmap_denied,
			    "unprivileged low fixed mmap below mmap_min_addr is denied");
	test_securityfs_status_contains("mitigation_io_uring_sysctl_lock: 1",
					"hardening status reports monotonic io_uring sysctl");
	test_securityfs_status_contains("mitigation_module_autoload_path: 1",
					"hardening status reports validated modprobe helper paths");
	test_securityfs_status_contains("mitigation_kexec_load_disable: 1",
					"hardening status reports one-way kexec disable sysctl");
	test_securityfs_status_contains("mitigation_module_load_disable: 1",
					"hardening status reports one-way module disable sysctl");
	test_securityfs_status_contains("mitigation_module_request_name: 1",
					"hardening status reports exact module request names");
	test_securityfs_status_contains("mitigation_module_autoload_context: 1",
					"hardening status reports module autoload context");
	report_child_result(module_autoload_context_reported(),
			    "modprobe helper receives bounded autoload context");
	test_securityfs_status_contains("mitigation_privexec_arg_stack_limits: 1",
					"hardening status reports privileged exec argument and stack limits");
	test_int_file_equals(HDN_SUID_DUMPABLE, 0,
			     "setuid coredump sysctl is locked disabled");
	report_child_result(suid_dumpable_sysctl_locked(),
			    "setuid coredump sysctl cannot be enabled");
	test_securityfs_status_contains("mitigation_memfd_noexec: 1",
					"hardening status reports enforced memfd noexec");
	test_securityfs_status_contains("mitigation_kernel_symbol_lookup_gate: 1",
					"hardening status reports kernel symbol lookup gating");
	test_securityfs_status_contains("mitigation_kptr_restrict: 1",
					"hardening status reports pointer restriction");
	test_int_file_equals(HDN_KPTR_RESTRICT, 2,
			     "kernel pointer sysctl is locked at no-disclose level");
	report_child_result(kptr_restrict_sysctl_locked(),
			    "kernel pointer sysctl cannot be lowered");
	test_int_file_equals(HDN_MEMFD_NOEXEC, 2,
			     "memfd noexec sysctl is locked at enforce level");
	report_child_result(memfd_noexec_sysctl_locked(),
			    "memfd noexec sysctl cannot be lowered");
	report_child_result(memfd_exec_flag_denied(),
			    "explicit executable memfd creation is denied");
	test_securityfs_status_contains("mitigation_rand_threadstack: 1",
					"hardening status reports thread-stack gap randomization");
	test_securityfs_status_contains("mitigation_vmap_stack: 1",
					"hardening status reports vmalloc kernel stacks");
	test_securityfs_status_contains("mitigation_thread_info_in_task: 1",
					"hardening status reports separated thread info");
	test_securityfs_status_contains("mitigation_stackprotector_strong: 1",
					"hardening status reports strong stack protector");
	test_securityfs_status_contains("mitigation_list_hardened: 1",
					"hardening status reports list hardening");
	test_securityfs_status_contains("mitigation_strict_kernel_rwx: 1",
					"hardening status reports strict kernel RWX");
	test_securityfs_status_contains("mitigation_strict_module_rwx: 1",
					"hardening status reports strict module RWX");
	test_securityfs_status_contains("mitigation_brute_throttle: 1",
					"hardening status reports brute-force throttle");
	test_securityfs_status_contains("mitigation_kernel_lockout: 1",
					"hardening status reports kernel lockout");
	test_securityfs_status_contains("kernel_lockout_banned_uids: 0",
					"hardening status reports kernel lockout state");
	test_securityfs_status_contains("mitigation_sysvipc_harden: 1",
					"hardening status reports System V IPC hardening");
	test_securityfs_status_contains("mitigation_posix_mqueue_harden: 1",
					"hardening status reports POSIX mqueue hardening");
	test_securityfs_status_contains("mitigation_tty_injection_harden: 1",
					"hardening status reports TTY injection hardening");
	test_securityfs_status_contains("mitigation_tty_access_harden: 1",
					"hardening status reports TTY access hardening");
	test_int_file_equals(HDN_LEGACY_TIOCSTI, 0,
			     "legacy TIOCSTI sysctl is locked disabled");
	report_child_result(legacy_tiocsti_sysctl_locked(),
			    "legacy TIOCSTI sysctl cannot be enabled");
	test_int_file_equals(HDN_LDISC_AUTOLOAD, 0,
			     "TTY line-discipline autoload sysctl is locked disabled");
	report_child_result(ldisc_autoload_sysctl_locked(),
			    "TTY line-discipline autoload sysctl cannot be enabled");
	test_securityfs_status_contains("mitigation_unpriv_bpf_lockdown: 1",
					"hardening status reports locked unprivileged BPF");
	test_securityfs_status_contains("mitigation_unpriv_perf_lockdown: 1",
					"hardening status reports locked unprivileged perf");
	test_securityfs_status_contains("mitigation_bpf_jit_harden: 1",
					"hardening status reports BPF JIT hardening");
	test_securityfs_status_contains("mitigation_fuse_restrict: 1",
					"hardening status reports FUSE restriction");
	test_securityfs_status_contains("mitigation_rofs_harden: 1",
					"hardening status reports read-only filesystem hardening");
	test_securityfs_status_contains("mitigation_sysfs_restrict: 1",
					"hardening status reports sysfs restriction");
	test_securityfs_status_contains("mitigation_proc_hide: 1",
					"hardening status reports proc task hiding");
	test_securityfs_status_contains("proc_task_gid: 65533",
					"hardening status reports proc task-view group");
	test_securityfs_status_contains("proc_task_modes: 1",
					"hardening status reports proc task directory mode restriction");
	test_securityfs_status_contains("mitigation_usb_restrict: 1",
					"hardening status reports USB attach restriction");
	test_securityfs_status_contains("mitigation_usb_monitor_restrict: 1",
					"hardening status reports USB monitor restriction");
	test_securityfs_status_contains("mitigation_socket_restrict: 1",
					"hardening status reports socket restriction");
	test_securityfs_status_contains("mitigation_net_blackhole: 1",
					"hardening status reports network blackhole");
	test_securityfs_status_contains("mitigation_tcp_no_simult_connect: 1",
					"hardening status reports TCP simultaneous-connect hardening");
	test_securityfs_status_contains("mitigation_sealed_data_report: 1",
					"hardening status reports sealed data write-fault reporting");
	test_securityfs_status_contains("mitigation_audit_flood_control: 1",
					"hardening status reports audit flood control");
	test_securityfs_status_contains("mitigation_exec_audit: 1",
					"hardening status reports exec audit");
	test_securityfs_status_contains("mitigation_chdir_audit: 1",
					"hardening status reports chdir audit");
	test_securityfs_status_contains("mitigation_mount_audit: 1",
					"hardening status reports mount audit");
	test_securityfs_status_contains("mitigation_time_admin: 1",
					"hardening status reports time administration hardening");
	test_securityfs_status_contains("mitigation_time_audit: 1",
					"hardening status reports time audit");
	test_securityfs_status_contains("mitigation_resource_admin: 1",
					"hardening status reports resource hardening");
	test_securityfs_status_contains("mitigation_resource_audit: 1",
					"hardening status reports resource audit");
	test_securityfs_status_contains("mitigation_block_device_restrict: 1",
					"hardening status reports block-device restriction");
	test_securityfs_status_contains("mitigation_fork_audit: 1",
					"hardening status reports fork audit");
	test_securityfs_status_contains("mitigation_forkfail_audit: 1",
					"hardening status reports failed fork audit");
	test_securityfs_status_contains("mitigation_fs_protection_audit: 1",
					"hardening status reports filesystem protection audit");
	test_securityfs_status_contains("mitigation_ptrace_audit: 1",
					"hardening status reports ptrace attach audit");
	test_securityfs_status_contains("mitigation_ptrace_readexec: 1",
					"hardening status reports ptrace execute-only read restriction");
	test_int_file_equals(HDN_YAMA_PTRACE_SCOPE, 1,
			     "Yama ptrace scope is locked relational");
	report_child_result(yama_ptrace_scope_sysctl_locked(),
			    "Yama ptrace scope cannot be disabled");
	test_securityfs_status_contains("mitigation_consistent_setxid: 1",
					"hardening status reports consistent setxid");
	test_securityfs_status_contains("mitigation_module_autoload: 1",
					"hardening status reports module autoload restriction");
	test_securityfs_status_contains("mitigation_proc_ipaddr: 1",
					"hardening status reports proc ipaddr attribution");
	test_securityfs_status_contains("mitigation_signal_audit: 1",
					"hardening status reports severe signal audit");
	test_securityfs_status_contains("mitigation_symlink_owner: 1",
					"hardening status reports symlink owner hardening");
	test_securityfs_status_contains("mitigation_rwxmap_audit: 1",
					"hardening status reports denied RWX map audit");
	test_securityfs_status_contains("mitigation_suid_spectre: 1",
					"hardening status reports suid Spectre hardening");
	test_int_file_equals(HDN_PROTECTED_SYMLINKS, 1,
			     "protected symlink default is hardened");
	report_child_result(protected_path_sysctl_locked(HDN_PROTECTED_SYMLINKS,
							"0\n", "1\n"),
			    "protected symlink sysctl cannot be lowered");
	test_int_file_equals(HDN_PROTECTED_HARDLINKS, 1,
			     "protected hardlink default is hardened");
	report_child_result(protected_path_sysctl_locked(HDN_PROTECTED_HARDLINKS,
							"0\n", "1\n"),
			    "protected hardlink sysctl cannot be lowered");
	test_int_file_equals(HDN_PROTECTED_FIFOS, 2,
			     "protected FIFO default is hardened");
	report_child_result(protected_path_sysctl_locked(HDN_PROTECTED_FIFOS,
							"1\n", "2\n"),
			    "protected FIFO sysctl cannot be lowered");
	test_int_file_equals(HDN_PROTECTED_REGULAR, 2,
			     "protected regular-file default is hardened");
	report_child_result(protected_path_sysctl_locked(HDN_PROTECTED_REGULAR,
							"1\n", "2\n"),
			    "protected regular-file sysctl cannot be lowered");
	test_securityfs_events();
	test_rand_threadstack_gap();
	test_exec_event_logged();
	test_exec_args_event_logged();
	test_fork_event_logged();
	test_fork_failure_event_logged();
	report_child_result(event_decoder_finds_fork_failure_audit(),
			    "event decoder names failed fork audit reason");
	test_fs_protection_events_logged();
	report_child_result(event_decoder_finds_fs_protection_audit(),
			    "event decoder names filesystem protection audit");
	report_child_result(event_decoder_finds_symlink_owner_audit(),
			    "event decoder names symlink owner mismatch audit");
	test_ptrace_audit_event_logged();
	report_child_result(event_decoder_finds_ptrace_audit(),
			    "event decoder names ptrace audit");
	test_consistent_setxid();
	test_signal_event_logged();
	report_child_result(event_decoder_finds_signal_audit(),
			    "event decoder names severe signal audit transition");
	report_child_result(event_decoder_names_object_details(),
			    "event decoder names packed event object details");
	report_child_result(status_helper_reports_live_state(),
			    "status helper reports live hardening state");
	report_child_result(status_helper_reports_live_compat_state(),
			    "status helper reports compatibility status families");
	report_child_result(status_helper_reports_compat_fixture(),
			    "status helper composes compatibility status families");
	report_child_result(status_helper_decodes_audit_flood_fixture(),
			    "status helper decodes audit flood status names");
	report_child_result(support_bundle_unsafe_config_denied(),
			    "support bundle denies unsafe config");
	report_child_result(support_bundle_dry_run_passes(),
			    "support bundle dry-run validates configured helpers");
	report_child_result(support_bundle_reports_status_and_events(),
			    "support bundle reports status compat and decoded events");
	report_child_result(control_center_status_fixture_passes(),
			    "control center reports product status");
	report_child_result(control_center_stdio_status_passes(),
			    "control center stdio reports product status");
	report_child_result(policy_learner_suggests_authorities(),
			    "policy learner suggests denied profile authorities");
	report_child_result(policy_learner_suggests_memory_flags(),
			    "policy learner suggests memory compatibility flags");
	report_child_result(policy_learner_reviews_wx_invariants(),
			    "policy learner keeps W+X invariant denials review-only");
	report_child_result(policy_merge_suggests_only_new_grants(),
			    "policy merge emits only new reviewed grants");
	report_child_result(policy_merge_output_compiles(),
			    "policy merge output compiles");
	report_child_result(policy_merge_rejects_unknown_profiles(),
			    "policy merge rejects unknown profile suggestions");
	report_child_result(policy_workflow_rejects_unknown(),
			    "policy workflow rejects unknown workflow");
	report_child_result(policy_workflow_rejects_unsafe_config(),
			    "policy workflow rejects unsafe config");
	report_child_result(policy_workflow_rejects_commit_without_signed_policy(),
			    "policy workflow rejects commit without signed policy");
	report_child_result(policy_workflow_generates_candidate(),
			    "policy workflow learns, merges, compiles, and dry-runs commit");
	report_child_result(policy_daemon_rejects_unknown(),
			    "policy daemon rejects unknown workflow");
	report_child_result(policy_daemon_rejects_unsafe_config(),
			    "policy daemon rejects unsafe config");
	report_child_result(policy_daemon_stdio_rejects_noncommit_dry_run(),
			    "policy daemon stdio rejects non-commit dry-run");
	report_child_result(policy_daemon_generates_candidate(),
			    "policy daemon learns, merges, compiles, and preflights commit");
	report_child_result(control_center_stdio_rejects_noncommit_policy_dry_run(),
			    "control center stdio rejects non-commit policy dry-run");
	report_child_result(control_center_policy_generates_candidate(),
			    "control center runs compiled policy workflow and one-shot/stdio commit preflight");
	test_chdir_event_logged();
	test_mount_event_logged();
	test_resource_limit_event_logged();
	test_resource_rss_limit_event_logged();
	test_resource_pressure_event_logged();
	test_resource_fsize_pressure_event_logged();
	test_resource_core_pressure_event_logged();
	test_resource_as_pressure_event_logged();
	test_resource_data_pressure_event_logged();
	test_resource_stack_pressure_event_logged();
	test_resource_nproc_pressure_event_logged();
	test_resource_memlock_pressure_event_logged();
	test_resource_msgqueue_pressure_event_logged();
	test_resource_sigpending_pressure_event_logged();
	test_resource_cpu_pressure_event_logged();
	test_resource_rttime_pressure_event_logged();
	test_resource_nice_pressure_event_logged();
	test_resource_rtprio_pressure_event_logged();
	test_resource_locks_pressure_event_logged();
	test_blackhole_loopback_tcp_exempt();
	test_blackhole_loopback_udp_exempt();
	test_blackhole_remote_tcp_suppressed();
	test_blackhole_remote_udp_suppressed();
	test_time_change_event_logged();
	test_securityfs_phase();
	test_securityfs_commit();
	test_securityfs_refresh();
	test_audit_flood_runtime_knobs();
	test_signed_policy_transaction();
	test_anonymous_rwx_denied();
	test_rwx_mprotect_audit_logged();
	test_exec_stack_elf_denied();
	report_child_result(event_decoder_finds_exec_stack_elf_audit(),
			    "event decoder names executable-stack ELF denial reason");
	test_textrel_mprotect_denied();
	report_child_result(event_decoder_finds_textrel_mprotect_audit(),
			    "event decoder names textrel mprotect denial reason");
	test_relro_write_restore_denied();
	report_child_result(event_decoder_finds_relro_write_audit(),
			    "event decoder names RELRO write denial reason");
	test_audit_flood_control();
	test_file_backed_rwx_denied();
	test_exec_after_write_denied();
	test_exec_after_write_history_denied();
	test_exec_after_write_split_history_denied();
	test_exec_after_write_merge_history_denied();
	test_exec_after_write_fork_history_denied();
	report_child_result(elf_note_jit_exec_after_write_allowed(),
			    "ELF memory note allows private anonymous exec-after-write");
	report_child_result(elf_note_exec_stack_elf_allowed(),
			    "ELF memory note allows executable-stack ELF mmap");
	report_child_result(elf_note_textrel_mprotect_allowed(),
			    "ELF memory note allows textrel mprotect");
	test_fixed_anonymous_exec_denied();
	test_read_implies_exec_rewritten();
	test_unprivileged_userns_denied();
	report_child_result(unprivileged_userfaultfd_disabled_or_unavailable(),
			    "unprivileged userfaultfd sysctl is disabled or unavailable");
	report_child_result(unprivileged_userfaultfd_sysctl_locked(),
			    "unprivileged userfaultfd sysctl cannot be enabled or is unavailable");
	test_unprivileged_userfaultfd_restricted();
	test_int_file_equals(HDN_UNPRIV_BPF_DISABLED, 1,
			     "unprivileged BPF sysctl is locked disabled");
	report_child_result(unprivileged_bpf_sysctl_locked(),
			    "unprivileged BPF sysctl cannot be re-enabled");
	report_child_result(bpf_jit_harden_locked_or_unavailable(),
			    "BPF JIT hardening is locked or JIT is unavailable");
	report_child_result(bpf_jit_kallsyms_locked_or_unavailable(),
			    "BPF JIT kallsyms are hidden or JIT is unavailable");
	test_unprivileged_bpf_load_denied();
	test_int_file_equals(HDN_PERF_EVENT_PARANOID, 3,
			     "perf sysctl is locked at unprivileged-deny level");
	report_child_result(perf_event_paranoid_sysctl_locked(),
			    "perf sysctl cannot be lowered");
	test_unprivileged_perf_kernel_denied();
	test_unprivileged_kernel_log_denied();
	test_unprivileged_raw_io_denied();
	test_unprivileged_io_uring_sqpoll_denied();
	report_child_result(sysvipc_msg_overpermissive_denied(),
			    "over-permissive message queue denies cross-uid access");
	report_child_result(sysvipc_sem_overpermissive_denied(),
			    "over-permissive semaphore denies cross-uid access");
	report_child_result(sysvipc_shm_overpermissive_denied(),
			    "over-permissive shared memory denies cross-uid access");
	report_child_result(posix_mqueue_send_overpermissive_denied(),
			    "over-permissive POSIX mqueue denies cross-uid send");
	report_child_result(posix_mqueue_receive_overpermissive_denied(),
			    "over-permissive POSIX mqueue denies cross-uid receive");
	test_securityfs_events_contains("transition=36",
					"hardening events report POSIX mqueue denial");
	report_child_result(tty_tiocsti_denied(),
			    "TTY TIOCSTI injection requires authority");
	report_child_result(tty_tioclinux_denied(),
			    "TTY TIOCLINUX injection requires authority");
	report_child_result(tty_access_read_denied(),
			    "TTY non-controlling inherited read requires authority");
	report_child_result(tty_access_write_denied(),
			    "TTY non-controlling inherited write requires authority");
	report_child_result(tty_access_ioctl_denied(),
			    "TTY non-controlling inherited ioctl requires authority");
	report_child_result(tty_controlling_pty_acquisition_allowed(),
			    "TTY PTY SCM broker configures and cleans up a controlling session");
	test_unprivileged_io_uring_restricted_denied();
	report_child_result(io_uring_disabled_sysctl_monotonic(),
			    "io_uring disabled sysctl cannot be lowered after restriction");
	test_init_module_denied();
	test_unsigned_policy_denied();
	test_securityfs_events_contains("event_id=",
					"hardening events report stable event IDs");
	test_securityfs_events_contains("authority=14",
					"hardening events report io_uring denial");
	test_securityfs_events_contains("authority=7",
					"hardening events report raw module denial");
	test_securityfs_events_contains("authority=23",
					"hardening events report System V IPC denial");
	test_securityfs_events_line_contains("authority=23 transition=28",
					     "reason=57",
					     "hardening events report protected shared memory denial");
	report_child_result(event_decoder_finds_protected_shm_denial(),
			    "event decoder names protected shared memory denial");
	test_securityfs_events_contains("authority=24",
					"hardening events report TTY injection denial");
	test_securityfs_events_line_contains("authority=90 transition=102",
					     "reason=58",
					     "hardening events report TTY access denial");
	report_child_result(event_decoder_finds_tty_access_denial(),
			    "event decoder names TTY access denial");
	test_securityfs_events_contains("reason=1",
					"hardening events report W+X denial reason");
	report_child_result(event_decoder_finds_wx_denial(),
			    "event decoder names W+X denial reason");
	report_child_result(event_decoder_finds_rwxmap_denial(),
			    "event decoder names denied RWX map audit reason");
	report_child_result(one_way_disable_sysctl_locked(HDN_KEXEC_LOAD_DISABLED),
			    "kexec load disable sysctl cannot be lowered after restriction");
	report_child_result(one_way_disable_sysctl_locked(HDN_MODULES_DISABLED),
			    "module load disable sysctl cannot be lowered after restriction");

	ksft_finished();
}
