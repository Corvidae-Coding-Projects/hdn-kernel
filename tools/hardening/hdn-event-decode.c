// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE

#include <errno.h>
#include <arpa/inet.h>
#ifndef __user
#define __user
#endif
#include <linux/capability.h>
#include <linux/hardening.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>

#ifndef HDN_EVENTS_PATH
#define HDN_EVENTS_PATH "/sys/kernel/security/hardening/events"
#endif

#define HDN_MAX_EXPECTATIONS 16
#define HDN_FOLLOW_POLL_NS 250000000L

static volatile sig_atomic_t follow_stop;

static void stop_follow(int signal_number)
{
	(void)signal_number;
	follow_stop = 1;
}

enum hdn_decode_field {
	HDN_FIELD_EVENT,
	HDN_FIELD_ACTION,
	HDN_FIELD_AUTHORITY,
	HDN_FIELD_TRANSITION,
	HDN_FIELD_REASON,
};

struct hdn_name {
	unsigned int value;
	const char *name;
};

struct hdn_decoded_event {
	unsigned long long sequence;
	unsigned long long timestamp_ns;
	unsigned long long profile;
	unsigned long long subject;
	unsigned long long object;
	unsigned long long flags;
	unsigned int event_id;
	unsigned int pid;
	unsigned int uid;
	unsigned int authority;
	unsigned int transition;
	unsigned int action;
	unsigned int reason;
	int error;
};

struct hdn_expectation {
	enum hdn_decode_field field;
	unsigned int value;
};

static const struct hdn_name authority_names[] = {
	{ HDN_AUTH_NONE, "NONE" },
	{ HDN_AUTH_EXEC, "EXEC" },
	{ HDN_AUTH_MMAP, "MMAP" },
	{ HDN_AUTH_MPROTECT, "MPROTECT" },
	{ HDN_AUTH_BPF_LOAD, "BPF_LOAD" },
	{ HDN_AUTH_PERF_OPEN, "PERF_OPEN" },
	{ HDN_AUTH_USERNS_CREATE, "USERNS_CREATE" },
	{ HDN_AUTH_MODULE_LOAD, "MODULE_LOAD" },
	{ HDN_AUTH_PTRACE, "PTRACE" },
	{ HDN_AUTH_PROC_DISCLOSE, "PROC_DISCLOSE" },
	{ HDN_AUTH_DEBUGFS, "DEBUGFS" },
	{ HDN_AUTH_SYSFS_MUTATE, "SYSFS_MUTATE" },
	{ HDN_AUTH_KEXEC_LOAD, "KEXEC_LOAD" },
	{ HDN_AUTH_FIRMWARE_LOAD, "FIRMWARE_LOAD" },
	{ HDN_AUTH_IO_URING_RESTRICTED_OP, "IO_URING_RESTRICTED_OP" },
	{ HDN_AUTH_KERNEL_LOG_READ, "KERNEL_LOG_READ" },
	{ HDN_AUTH_KERNEL_LOG_WRITE, "KERNEL_LOG_WRITE" },
	{ HDN_AUTH_RAW_IO, "RAW_IO" },
	{ HDN_AUTH_MOUNT_ADMIN, "MOUNT_ADMIN" },
	{ HDN_AUTH_POLICY_ADMIN, "POLICY_ADMIN" },
	{ HDN_AUTH_NAMESPACE_ADMIN, "NAMESPACE_ADMIN" },
	{ HDN_AUTH_CRED_CHANGE, "CRED_CHANGE" },
	{ HDN_AUTH_CHROOT_ADMIN, "CHROOT_ADMIN" },
	{ HDN_AUTH_TRUSTED_EXEC_BYPASS, "TRUSTED_EXEC_BYPASS" },
	{ HDN_AUTH_IPC_ADMIN, "IPC_ADMIN" },
	{ HDN_AUTH_TTY_INJECT, "TTY_INJECT" },
	{ HDN_AUTH_TTY_ACCESS, "TTY_ACCESS" },
	{ HDN_AUTH_FUSE_MOUNT, "FUSE_MOUNT" },
	{ HDN_AUTH_ROFS_RELAX, "ROFS_RELAX" },
	{ HDN_AUTH_USB_ATTACH, "USB_ATTACH" },
	{ HDN_AUTH_USB_MONITOR, "USB_MONITOR" },
	{ HDN_AUTH_SOCKET_CREATE, "SOCKET_CREATE" },
	{ HDN_AUTH_SOCKET_CONNECT, "SOCKET_CONNECT" },
	{ HDN_AUTH_SOCKET_SERVER, "SOCKET_SERVER" },
	{ HDN_AUTH_PROC_TASK_VIEW, "PROC_TASK_VIEW" },
	{ HDN_AUTH_TIME_ADMIN, "TIME_ADMIN" },
	{ HDN_AUTH_RESOURCE_ADMIN, "RESOURCE_ADMIN" },
	{ HDN_AUTH_BLOCK_DEVICE_ACCESS, "BLOCK_DEVICE_ACCESS" },
	{ HDN_AUTH_SYSFS_READ, "SYSFS_READ" },
	{ HDN_AUTH_PTRACE_EXEC_READ, "PTRACE_EXEC_READ" },
	{ HDN_AUTH_MODULE_AUTOLOAD, "MODULE_AUTOLOAD" },
	{ HDN_AUTH_BLOCK_DEVICE_ADMIN, "BLOCK_DEVICE_ADMIN" },
	{ HDN_AUTH_OBJECT_WRITE, "OBJECT_WRITE" },
	{ HDN_AUTH_OBJECT_READ, "OBJECT_READ" },
	{ HDN_AUTH_OBJECT_DELETE, "OBJECT_DELETE" },
	{ HDN_AUTH_OBJECT_CREATE, "OBJECT_CREATE" },
	{ HDN_AUTH_OBJECT_EXEC, "OBJECT_EXEC" },
	{ HDN_AUTH_OBJECT_APPEND, "OBJECT_APPEND" },
	{ HDN_AUTH_OBJECT_LINK, "OBJECT_LINK" },
	{ HDN_AUTH_OBJECT_ATTR, "OBJECT_ATTR" },
	{ HDN_AUTH_OBJECT_ACCESS, "OBJECT_ACCESS" },
	{ HDN_AUTH_OBJECT_STAT, "OBJECT_STAT" },
	{ HDN_AUTH_OBJECT_LIST, "OBJECT_LIST" },
	{ HDN_AUTH_OBJECT_FIND, "OBJECT_FIND" },
	{ HDN_AUTH_OBJECT_IOCTL, "OBJECT_IOCTL" },
	{ HDN_AUTH_OBJECT_LOCK, "OBJECT_LOCK" },
	{ HDN_AUTH_OBJECT_WATCH, "OBJECT_WATCH" },
	{ HDN_AUTH_OBJECT_XATTR, "OBJECT_XATTR" },
	{ HDN_AUTH_SIGNAL, "SIGNAL" },
	{ HDN_AUTH_PROCESS_MEMORY, "PROCESS_MEMORY" },
	{ HDN_AUTH_MEMORY_MIGRATE, "MEMORY_MIGRATE" },
	{ HDN_AUTH_PROCESS_FD, "PROCESS_FD" },
	{ HDN_AUTH_OBJECT_RECEIVE, "OBJECT_RECEIVE" },
	{ HDN_AUTH_OBJECT_FCNTL, "OBJECT_FCNTL" },
	{ HDN_AUTH_OBJECT_CHDIR, "OBJECT_CHDIR" },
	{ HDN_AUTH_OBJECT_MOUNT, "OBJECT_MOUNT" },
	{ HDN_AUTH_OBJECT_MOUNT_SOURCE, "OBJECT_MOUNT_SOURCE" },
	{ HDN_AUTH_OBJECT_UMOUNT, "OBJECT_UMOUNT" },
	{ HDN_AUTH_OBJECT_TRUNCATE, "OBJECT_TRUNCATE" },
	{ HDN_AUTH_OBJECT_RENAME, "OBJECT_RENAME" },
	{ HDN_AUTH_OBJECT_RENAME_TARGET, "OBJECT_RENAME_TARGET" },
	{ HDN_AUTH_OBJECT_LINK_TARGET, "OBJECT_LINK_TARGET" },
	{ HDN_AUTH_OBJECT_UNIX_CONNECT, "OBJECT_UNIX_CONNECT" },
	{ HDN_AUTH_OBJECT_CHMOD, "OBJECT_CHMOD" },
	{ HDN_AUTH_OBJECT_CHOWN, "OBJECT_CHOWN" },
	{ HDN_AUTH_OBJECT_UTIME, "OBJECT_UTIME" },
	{ HDN_AUTH_OBJECT_SETID, "OBJECT_SETID" },
	{ HDN_AUTH_OBJECT_PTRACE, "OBJECT_PTRACE" },
	{ HDN_AUTH_OBJECT_SETXATTR, "OBJECT_SETXATTR" },
	{ HDN_AUTH_OBJECT_REMOVEXATTR, "OBJECT_REMOVEXATTR" },
	{ HDN_AUTH_OBJECT_CREAT, "OBJECT_CREAT" },
	{ HDN_AUTH_OBJECT_MKDIR, "OBJECT_MKDIR" },
	{ HDN_AUTH_OBJECT_MKNOD, "OBJECT_MKNOD" },
	{ HDN_AUTH_OBJECT_SYMLINK, "OBJECT_SYMLINK" },
	{ HDN_AUTH_OBJECT_UNLINK, "OBJECT_UNLINK" },
	{ HDN_AUTH_OBJECT_RMDIR, "OBJECT_RMDIR" },
	{ HDN_AUTH_OBJECT_UNIX_BIND, "OBJECT_UNIX_BIND" },
	{ HDN_AUTH_OBJECT_UNIX_LISTEN, "OBJECT_UNIX_LISTEN" },
	{ HDN_AUTH_OBJECT_UNIX_ACCEPT, "OBJECT_UNIX_ACCEPT" },
	{ HDN_AUTH_OBJECT_UNIX_SEND, "OBJECT_UNIX_SEND" },
	{ HDN_AUTH_OBJECT_UNIX_RECV, "OBJECT_UNIX_RECV" },
};

static const struct hdn_name transition_names[] = {
	{ HDN_TRANS_NONE, "NONE" },
	{ HDN_TRANS_EXEC, "EXEC" },
	{ HDN_TRANS_CRED_CHANGE, "CRED_CHANGE" },
	{ HDN_TRANS_MMAP, "MMAP" },
	{ HDN_TRANS_MPROTECT, "MPROTECT" },
	{ HDN_TRANS_MODULE_LOAD, "MODULE_LOAD" },
	{ HDN_TRANS_FIRMWARE_LOAD, "FIRMWARE_LOAD" },
	{ HDN_TRANS_BPF_LOAD, "BPF_LOAD" },
	{ HDN_TRANS_PERF_OPEN, "PERF_OPEN" },
	{ HDN_TRANS_PTRACE, "PTRACE" },
	{ HDN_TRANS_USERNS_CREATE, "USERNS_CREATE" },
	{ HDN_TRANS_MOUNT, "MOUNT" },
	{ HDN_TRANS_KEXEC_LOAD, "KEXEC_LOAD" },
	{ HDN_TRANS_IO_URING_OP, "IO_URING_OP" },
	{ HDN_TRANS_PROCFS_READ, "PROCFS_READ" },
	{ HDN_TRANS_SYSFS_WRITE, "SYSFS_WRITE" },
	{ HDN_TRANS_KERNEL_LOG_READ, "KERNEL_LOG_READ" },
	{ HDN_TRANS_KERNEL_LOG_WRITE, "KERNEL_LOG_WRITE" },
	{ HDN_TRANS_RAW_IO, "RAW_IO" },
	{ HDN_TRANS_DEBUGFS_ACCESS, "DEBUGFS_ACCESS" },
	{ HDN_TRANS_POLICY_LOAD, "POLICY_LOAD" },
	{ HDN_TRANS_POLICY_ROLLBACK, "POLICY_ROLLBACK" },
	{ HDN_TRANS_PHASE_CHANGE, "PHASE_CHANGE" },
	{ HDN_TRANS_NAMESPACE_CREATE, "NAMESPACE_CREATE" },
	{ HDN_TRANS_NAMESPACE_JOIN, "NAMESPACE_JOIN" },
	{ HDN_TRANS_POLICY_COMMIT, "POLICY_COMMIT" },
	{ HDN_TRANS_CHROOT, "CHROOT" },
	{ HDN_TRANS_CHDIR, "CHDIR" },
	{ HDN_TRANS_PIVOT_ROOT, "PIVOT_ROOT" },
	{ HDN_TRANS_SYSVIPC_ACCESS, "SYSVIPC_ACCESS" },
	{ HDN_TRANS_TTY_INJECT, "TTY_INJECT" },
	{ HDN_TRANS_TTY_ACCESS, "TTY_ACCESS" },
	{ HDN_TRANS_FUSE_MOUNT, "FUSE_MOUNT" },
	{ HDN_TRANS_ROFS_RELAX, "ROFS_RELAX" },
	{ HDN_TRANS_USB_ATTACH, "USB_ATTACH" },
	{ HDN_TRANS_USB_MONITOR, "USB_MONITOR" },
	{ HDN_TRANS_SOCKET_CREATE, "SOCKET_CREATE" },
	{ HDN_TRANS_SOCKET_CONNECT, "SOCKET_CONNECT" },
	{ HDN_TRANS_SOCKET_SERVER, "SOCKET_SERVER" },
	{ HDN_TRANS_POSIX_MQUEUE_ACCESS, "POSIX_MQUEUE_ACCESS" },
	{ HDN_TRANS_TIME_CHANGE, "TIME_CHANGE" },
	{ HDN_TRANS_RESOURCE_LIMIT, "RESOURCE_LIMIT" },
	{ HDN_TRANS_BLOCK_DEVICE_ACCESS, "BLOCK_DEVICE_ACCESS" },
	{ HDN_TRANS_FORK, "FORK" },
	{ HDN_TRANS_SYSFS_READ, "SYSFS_READ" },
	{ HDN_TRANS_PTRACE_EXEC_READ, "PTRACE_EXEC_READ" },
	{ HDN_TRANS_MODULE_AUTOLOAD, "MODULE_AUTOLOAD" },
	{ HDN_TRANS_SEALED_DATA, "SEALED_DATA" },
	{ HDN_TRANS_BLOCK_DEVICE_ADMIN, "BLOCK_DEVICE_ADMIN" },
	{ HDN_TRANS_SIGNAL, "SIGNAL" },
	{ HDN_TRANS_FS_PROTECTION, "FS_PROTECTION" },
	{ HDN_TRANS_OBJECT_WRITE, "OBJECT_WRITE" },
	{ HDN_TRANS_OBJECT_READ, "OBJECT_READ" },
	{ HDN_TRANS_OBJECT_DELETE, "OBJECT_DELETE" },
	{ HDN_TRANS_OBJECT_CREATE, "OBJECT_CREATE" },
	{ HDN_TRANS_OBJECT_EXEC, "OBJECT_EXEC" },
	{ HDN_TRANS_OBJECT_APPEND, "OBJECT_APPEND" },
	{ HDN_TRANS_OBJECT_LINK, "OBJECT_LINK" },
	{ HDN_TRANS_OBJECT_ATTR, "OBJECT_ATTR" },
	{ HDN_TRANS_OBJECT_ACCESS, "OBJECT_ACCESS" },
	{ HDN_TRANS_OBJECT_STAT, "OBJECT_STAT" },
	{ HDN_TRANS_OBJECT_LIST, "OBJECT_LIST" },
	{ HDN_TRANS_OBJECT_FIND, "OBJECT_FIND" },
	{ HDN_TRANS_OBJECT_IOCTL, "OBJECT_IOCTL" },
	{ HDN_TRANS_OBJECT_LOCK, "OBJECT_LOCK" },
	{ HDN_TRANS_OBJECT_WATCH, "OBJECT_WATCH" },
	{ HDN_TRANS_OBJECT_XATTR, "OBJECT_XATTR" },
	{ HDN_TRANS_PROCESS_MEMORY, "PROCESS_MEMORY" },
	{ HDN_TRANS_MEMORY_MIGRATE, "MEMORY_MIGRATE" },
	{ HDN_TRANS_PROCESS_FD, "PROCESS_FD" },
	{ HDN_TRANS_OBJECT_RECEIVE, "OBJECT_RECEIVE" },
	{ HDN_TRANS_OBJECT_FCNTL, "OBJECT_FCNTL" },
	{ HDN_TRANS_OBJECT_CHDIR, "OBJECT_CHDIR" },
	{ HDN_TRANS_OBJECT_MOUNT, "OBJECT_MOUNT" },
	{ HDN_TRANS_OBJECT_MOUNT_SOURCE, "OBJECT_MOUNT_SOURCE" },
	{ HDN_TRANS_OBJECT_UMOUNT, "OBJECT_UMOUNT" },
	{ HDN_TRANS_OBJECT_TRUNCATE, "OBJECT_TRUNCATE" },
	{ HDN_TRANS_OBJECT_RENAME, "OBJECT_RENAME" },
	{ HDN_TRANS_OBJECT_RENAME_TARGET, "OBJECT_RENAME_TARGET" },
	{ HDN_TRANS_OBJECT_LINK_TARGET, "OBJECT_LINK_TARGET" },
	{ HDN_TRANS_OBJECT_UNIX_CONNECT, "OBJECT_UNIX_CONNECT" },
	{ HDN_TRANS_OBJECT_CHMOD, "OBJECT_CHMOD" },
	{ HDN_TRANS_OBJECT_CHOWN, "OBJECT_CHOWN" },
	{ HDN_TRANS_OBJECT_UTIME, "OBJECT_UTIME" },
	{ HDN_TRANS_OBJECT_SETID, "OBJECT_SETID" },
	{ HDN_TRANS_OBJECT_PTRACE, "OBJECT_PTRACE" },
	{ HDN_TRANS_OBJECT_SETXATTR, "OBJECT_SETXATTR" },
	{ HDN_TRANS_OBJECT_REMOVEXATTR, "OBJECT_REMOVEXATTR" },
	{ HDN_TRANS_OBJECT_CREAT, "OBJECT_CREAT" },
	{ HDN_TRANS_OBJECT_MKDIR, "OBJECT_MKDIR" },
	{ HDN_TRANS_OBJECT_MKNOD, "OBJECT_MKNOD" },
	{ HDN_TRANS_OBJECT_SYMLINK, "OBJECT_SYMLINK" },
	{ HDN_TRANS_OBJECT_UNLINK, "OBJECT_UNLINK" },
	{ HDN_TRANS_OBJECT_RMDIR, "OBJECT_RMDIR" },
	{ HDN_TRANS_EXEC_INHERIT, "EXEC_INHERIT" },
	{ HDN_TRANS_PROCESS_ACCOUNT, "PROCESS_ACCOUNT" },
	{ HDN_TRANS_COREDUMP, "COREDUMP" },
	{ HDN_TRANS_EXEC_ARGS, "EXEC_ARGS" },
	{ HDN_TRANS_KERNEL_LOCKOUT, "KERNEL_LOCKOUT" },
	{ HDN_TRANS_OBJECT_UNIX_BIND, "OBJECT_UNIX_BIND" },
	{ HDN_TRANS_OBJECT_UNIX_LISTEN, "OBJECT_UNIX_LISTEN" },
	{ HDN_TRANS_OBJECT_UNIX_ACCEPT, "OBJECT_UNIX_ACCEPT" },
	{ HDN_TRANS_OBJECT_UNIX_SEND, "OBJECT_UNIX_SEND" },
	{ HDN_TRANS_OBJECT_UNIX_RECV, "OBJECT_UNIX_RECV" },
	{ HDN_TRANS_CAPABILITY, "CAPABILITY" },
	{ HDN_TRANS_POLICY_REFRESH, "POLICY_REFRESH" },
};

static const struct hdn_name action_names[] = {
	{ HDN_DECISION_ALLOW, "ALLOW" },
	{ HDN_DECISION_DENY, "DENY" },
	{ HDN_DECISION_REWRITE, "REWRITE" },
	{ HDN_DECISION_ALLOW_AUDIT, "ALLOW_AUDIT" },
	{ HDN_DECISION_DENY_AUDIT, "DENY_AUDIT" },
};

static const struct hdn_name reason_names[] = {
	{ HDN_REASON_NONE, "NONE" },
	{ HDN_REASON_USER_WX_MAPPING, "USER_WX_MAPPING" },
	{ HDN_REASON_EXEC_AFTER_WRITE, "EXEC_AFTER_WRITE" },
	{ HDN_REASON_UNPRIVILEGED_BPF, "UNPRIVILEGED_BPF" },
	{ HDN_REASON_UNPRIVILEGED_PERF_KERNEL, "UNPRIVILEGED_PERF_KERNEL" },
	{ HDN_REASON_UNPRIVILEGED_USERNS, "UNPRIVILEGED_USERNS" },
	{ HDN_REASON_RAW_MODULE_IMAGE, "RAW_MODULE_IMAGE" },
	{ HDN_REASON_PROFILE_DENIED, "PROFILE_DENIED" },
	{ HDN_REASON_SEALED_RUNTIME, "SEALED_RUNTIME" },
	{ HDN_REASON_INVALID_PHASE, "INVALID_PHASE" },
	{ HDN_REASON_POLICY_DOWNGRADE, "POLICY_DOWNGRADE" },
	{ HDN_REASON_INVALID_POLICY, "INVALID_POLICY" },
	{ HDN_REASON_FIXED_ANON_EXEC_MAPPING, "FIXED_ANON_EXEC_MAPPING" },
	{ HDN_REASON_READ_IMPLIES_EXEC, "READ_IMPLIES_EXEC" },
	{ HDN_REASON_NAMESPACE_PROFILE_WIDEN, "NAMESPACE_PROFILE_WIDEN" },
	{ HDN_REASON_NO_STAGED_POLICY, "NO_STAGED_POLICY" },
	{ HDN_REASON_UNTRUSTED_MODULE, "UNTRUSTED_MODULE" },
	{ HDN_REASON_UNTRUSTED_FIRMWARE, "UNTRUSTED_FIRMWARE" },
	{ HDN_REASON_POLICY_BASE_MISMATCH, "POLICY_BASE_MISMATCH" },
	{ HDN_REASON_UNTRUSTED_EXEC_PATH, "UNTRUSTED_EXEC_PATH" },
	{ HDN_REASON_CHROOT_REENTRY, "CHROOT_REENTRY" },
	{ HDN_REASON_CHROOT_ESCAPE, "CHROOT_ESCAPE" },
	{ HDN_REASON_PIVOT_ROOT_IN_CHROOT, "PIVOT_ROOT_IN_CHROOT" },
	{ HDN_REASON_BRUTE_THROTTLED, "BRUTE_THROTTLED" },
	{ HDN_REASON_OVERPERMISSIVE_IPC, "OVERPERMISSIVE_IPC" },
	{ HDN_REASON_TTY_INJECTION, "TTY_INJECTION" },
	{ HDN_REASON_TTY_ACCESS, "TTY_ACCESS" },
	{ HDN_REASON_FUSE_RESTRICTED, "FUSE_RESTRICTED" },
	{ HDN_REASON_ROFS_RELAX, "ROFS_RELAX" },
	{ HDN_REASON_UNPRIVILEGED_PRIVEXEC, "UNPRIVILEGED_PRIVEXEC" },
	{ HDN_REASON_PTRACE_EXEC_READ, "PTRACE_EXEC_READ" },
	{ HDN_REASON_MODULE_AUTOLOAD, "MODULE_AUTOLOAD" },
	{ HDN_REASON_CHROOT_CHMOD, "CHROOT_CHMOD" },
	{ HDN_REASON_CHROOT_MKNOD, "CHROOT_MKNOD" },
	{ HDN_REASON_CHROOT_SHMAT, "CHROOT_SHMAT" },
	{ HDN_REASON_CHROOT_NICE, "CHROOT_NICE" },
	{ HDN_REASON_CHROOT_RENAME, "CHROOT_RENAME" },
	{ HDN_REASON_CHROOT_ABSTRACT_UNIX, "CHROOT_ABSTRACT_UNIX" },
	{ HDN_REASON_CHROOT_CAPABILITY, "CHROOT_CAPABILITY" },
	{ HDN_REASON_CHROOT_OUTSIDE_TASK, "CHROOT_OUTSIDE_TASK" },
	{ HDN_REASON_SEALED_DATA_WRITE, "SEALED_DATA_WRITE" },
	{ HDN_REASON_CHROOT_MOUNT, "CHROOT_MOUNT" },
	{ HDN_REASON_CHROOT_FILE_HANDLE, "CHROOT_FILE_HANDLE" },
	{ HDN_REASON_FORK_FAILED, "FORK_FAILED" },
	{ HDN_REASON_PROTECTED_SYMLINK, "PROTECTED_SYMLINK" },
	{ HDN_REASON_PROTECTED_HARDLINK, "PROTECTED_HARDLINK" },
	{ HDN_REASON_PROTECTED_FIFO, "PROTECTED_FIFO" },
	{ HDN_REASON_PROTECTED_REGULAR, "PROTECTED_REGULAR" },
	{ HDN_REASON_CHROOT_SYSCTL, "CHROOT_SYSCTL" },
	{ HDN_REASON_SYMLINK_OWNER_MISMATCH, "SYMLINK_OWNER_MISMATCH" },
	{ HDN_REASON_RWXMAP_DENIED, "RWXMAP_DENIED" },
	{ HDN_REASON_EXEC_STACK_ELF, "EXEC_STACK_ELF" },
	{ HDN_REASON_TEXTREL_MPROTECT, "TEXTREL_MPROTECT" },
	{ HDN_REASON_RELRO_WRITE, "RELRO_WRITE" },
	{ HDN_REASON_OBJECT_POLICY, "OBJECT_POLICY" },
	{ HDN_REASON_PRIVILEGED_DESCENDANT_COREDUMP,
	  "PRIVILEGED_DESCENDANT_COREDUMP" },
	{ HDN_REASON_BRUTE_DAEMON_THROTTLED,
	  "BRUTE_DAEMON_THROTTLED" },
	{ HDN_REASON_KERNEL_LOCKOUT, "KERNEL_LOCKOUT" },
	{ HDN_REASON_RESOURCE_PROFILE_LIMIT, "RESOURCE_PROFILE_LIMIT" },
	{ HDN_REASON_PROTECTED_SHM, "PROTECTED_SHM" },
	{ HDN_REASON_CAPABILITY_PROFILE, "CAPABILITY_PROFILE" },
	{ HDN_REASON_USERNS_DEPTH, "USERNS_DEPTH" },
	{ HDN_REASON_POLICY_IDENTITY_MISMATCH,
	  "POLICY_IDENTITY_MISMATCH" },
};

static const struct hdn_name capability_names[] = {
	{ CAP_CHOWN, "CAP_CHOWN" },
	{ CAP_DAC_OVERRIDE, "CAP_DAC_OVERRIDE" },
	{ CAP_DAC_READ_SEARCH, "CAP_DAC_READ_SEARCH" },
	{ CAP_FOWNER, "CAP_FOWNER" },
	{ CAP_FSETID, "CAP_FSETID" },
	{ CAP_KILL, "CAP_KILL" },
	{ CAP_SETGID, "CAP_SETGID" },
	{ CAP_SETUID, "CAP_SETUID" },
	{ CAP_SETPCAP, "CAP_SETPCAP" },
	{ CAP_LINUX_IMMUTABLE, "CAP_LINUX_IMMUTABLE" },
	{ CAP_NET_BIND_SERVICE, "CAP_NET_BIND_SERVICE" },
	{ CAP_NET_BROADCAST, "CAP_NET_BROADCAST" },
	{ CAP_NET_ADMIN, "CAP_NET_ADMIN" },
	{ CAP_NET_RAW, "CAP_NET_RAW" },
	{ CAP_IPC_LOCK, "CAP_IPC_LOCK" },
	{ CAP_IPC_OWNER, "CAP_IPC_OWNER" },
	{ CAP_SYS_MODULE, "CAP_SYS_MODULE" },
	{ CAP_SYS_RAWIO, "CAP_SYS_RAWIO" },
	{ CAP_SYS_CHROOT, "CAP_SYS_CHROOT" },
	{ CAP_SYS_PTRACE, "CAP_SYS_PTRACE" },
	{ CAP_SYS_PACCT, "CAP_SYS_PACCT" },
	{ CAP_SYS_ADMIN, "CAP_SYS_ADMIN" },
	{ CAP_SYS_BOOT, "CAP_SYS_BOOT" },
	{ CAP_SYS_NICE, "CAP_SYS_NICE" },
	{ CAP_SYS_RESOURCE, "CAP_SYS_RESOURCE" },
	{ CAP_SYS_TIME, "CAP_SYS_TIME" },
	{ CAP_SYS_TTY_CONFIG, "CAP_SYS_TTY_CONFIG" },
	{ CAP_MKNOD, "CAP_MKNOD" },
	{ CAP_LEASE, "CAP_LEASE" },
	{ CAP_AUDIT_WRITE, "CAP_AUDIT_WRITE" },
	{ CAP_AUDIT_CONTROL, "CAP_AUDIT_CONTROL" },
	{ CAP_SETFCAP, "CAP_SETFCAP" },
	{ CAP_MAC_OVERRIDE, "CAP_MAC_OVERRIDE" },
	{ CAP_MAC_ADMIN, "CAP_MAC_ADMIN" },
	{ CAP_SYSLOG, "CAP_SYSLOG" },
	{ CAP_WAKE_ALARM, "CAP_WAKE_ALARM" },
	{ CAP_BLOCK_SUSPEND, "CAP_BLOCK_SUSPEND" },
	{ CAP_AUDIT_READ, "CAP_AUDIT_READ" },
	{ CAP_PERFMON, "CAP_PERFMON" },
	{ CAP_BPF, "CAP_BPF" },
	{ CAP_CHECKPOINT_RESTORE, "CAP_CHECKPOINT_RESTORE" },
};

static const struct hdn_name resource_names[] = {
	{ RLIMIT_CPU, "CPU" },
	{ RLIMIT_FSIZE, "FSIZE" },
	{ RLIMIT_DATA, "DATA" },
	{ RLIMIT_STACK, "STACK" },
	{ RLIMIT_CORE, "CORE" },
	{ RLIMIT_RSS, "RSS" },
	{ RLIMIT_NPROC, "NPROC" },
	{ RLIMIT_NOFILE, "NOFILE" },
	{ RLIMIT_MEMLOCK, "MEMLOCK" },
	{ RLIMIT_AS, "AS" },
	{ RLIMIT_LOCKS, "LOCKS" },
	{ RLIMIT_SIGPENDING, "SIGPENDING" },
	{ RLIMIT_MSGQUEUE, "MSGQUEUE" },
	{ RLIMIT_NICE, "NICE" },
	{ RLIMIT_RTPRIO, "RTPRIO" },
	{ RLIMIT_RTTIME, "RTTIME" },
};

static const struct hdn_name signal_names[] = {
	{ SIGABRT, "SIGABRT" },
	{ SIGBUS, "SIGBUS" },
	{ SIGFPE, "SIGFPE" },
	{ SIGILL, "SIGILL" },
	{ SIGSEGV, "SIGSEGV" },
	{ SIGSYS, "SIGSYS" },
	{ SIGTRAP, "SIGTRAP" },
	{ SIGXCPU, "SIGXCPU" },
	{ SIGXFSZ, "SIGXFSZ" },
};

static const struct hdn_name time_operation_names[] = {
	{ HDN_TIME_SET_WALL, "SET_WALL" },
	{ HDN_TIME_SET_TIMEZONE, "SET_TIMEZONE" },
	{ HDN_TIME_ADJTIMEX, "ADJTIMEX" },
};

static const struct hdn_name socket_family_names[] = {
	{ AF_UNSPEC, "AF_UNSPEC" },
	{ AF_UNIX, "AF_UNIX" },
	{ AF_INET, "AF_INET" },
	{ AF_INET6, "AF_INET6" },
	{ AF_NETLINK, "AF_NETLINK" },
	{ AF_PACKET, "AF_PACKET" },
};

static const struct hdn_name socket_type_names[] = {
	{ SOCK_STREAM, "SOCK_STREAM" },
	{ SOCK_DGRAM, "SOCK_DGRAM" },
	{ SOCK_RAW, "SOCK_RAW" },
	{ SOCK_RDM, "SOCK_RDM" },
	{ SOCK_SEQPACKET, "SOCK_SEQPACKET" },
};

static const char *lookup_name(const struct hdn_name *names, size_t count,
			       unsigned int value)
{
	size_t i;

	for (i = 0; i < count; i++) {
		if (names[i].value == value)
			return names[i].name;
	}

	return "UNKNOWN";
}

static int lookup_value(const struct hdn_name *names, size_t count,
			const char *name, unsigned int *value)
{
	size_t i;

	for (i = 0; i < count; i++) {
		if (!strcasecmp(names[i].name, name)) {
			*value = names[i].value;
			return 0;
		}
	}

	return -ENOENT;
}

static int parse_u64(const char *text, unsigned long long *value)
{
	char *end;

	errno = 0;
	*value = strtoull(text, &end, 0);
	if (errno || end == text || *end)
		return -EINVAL;
	return 0;
}

static int parse_s32(const char *text, int *value)
{
	char *end;
	long parsed;

	errno = 0;
	parsed = strtol(text, &end, 0);
	if (errno || end == text || *end)
		return -EINVAL;
	*value = (int)parsed;
	return 0;
}

static int parse_event_line(char *line, struct hdn_decoded_event *event)
{
	char *save = NULL;
	char *word;

	memset(event, 0, sizeof(*event));

	for (word = strtok_r(line, " \t\r\n", &save); word;
	     word = strtok_r(NULL, " \t\r\n", &save)) {
		char *value = strchr(word, '=');
		unsigned long long parsed;
		int parsed_s32;

		if (!value)
			continue;
		*value++ = '\0';

		if (!strcmp(word, "sequence")) {
			if (parse_u64(value, &event->sequence))
				return -EINVAL;
		} else if (!strcmp(word, "timestamp_ns")) {
			if (parse_u64(value, &event->timestamp_ns))
				return -EINVAL;
		} else if (!strcmp(word, "event_id")) {
			if (parse_u64(value, &parsed))
				return -EINVAL;
			event->event_id = (unsigned int)parsed;
		} else if (!strcmp(word, "pid")) {
			if (parse_u64(value, &parsed))
				return -EINVAL;
			event->pid = (unsigned int)parsed;
		} else if (!strcmp(word, "uid")) {
			if (parse_u64(value, &parsed))
				return -EINVAL;
			event->uid = (unsigned int)parsed;
		} else if (!strcmp(word, "profile")) {
			if (parse_u64(value, &event->profile))
				return -EINVAL;
		} else if (!strcmp(word, "authority")) {
			if (parse_u64(value, &parsed))
				return -EINVAL;
			event->authority = (unsigned int)parsed;
		} else if (!strcmp(word, "transition")) {
			if (parse_u64(value, &parsed))
				return -EINVAL;
			event->transition = (unsigned int)parsed;
		} else if (!strcmp(word, "action")) {
			if (parse_u64(value, &parsed))
				return -EINVAL;
			event->action = (unsigned int)parsed;
		} else if (!strcmp(word, "reason")) {
			if (parse_u64(value, &parsed))
				return -EINVAL;
			event->reason = (unsigned int)parsed;
		} else if (!strcmp(word, "error")) {
			if (parse_s32(value, &parsed_s32))
				return -EINVAL;
			event->error = parsed_s32;
		} else if (!strcmp(word, "subject")) {
			if (parse_u64(value, &event->subject))
				return -EINVAL;
		} else if (!strcmp(word, "object")) {
			if (parse_u64(value, &event->object))
				return -EINVAL;
		} else if (!strcmp(word, "flags")) {
			if (parse_u64(value, &event->flags))
				return -EINVAL;
		}
	}

	return 0;
}

static unsigned int event_field(const struct hdn_decoded_event *event,
				enum hdn_decode_field field)
{
	switch (field) {
	case HDN_FIELD_EVENT:
		return event->event_id;
	case HDN_FIELD_ACTION:
		return event->action;
	case HDN_FIELD_AUTHORITY:
		return event->authority;
	case HDN_FIELD_TRANSITION:
		return event->transition;
	case HDN_FIELD_REASON:
		return event->reason;
	}

	return 0;
}

static int parse_field(const char *name, enum hdn_decode_field *field)
{
	if (!strcasecmp(name, "event") || !strcasecmp(name, "event_id")) {
		*field = HDN_FIELD_EVENT;
		return 0;
	}
	if (!strcasecmp(name, "action")) {
		*field = HDN_FIELD_ACTION;
		return 0;
	}
	if (!strcasecmp(name, "authority")) {
		*field = HDN_FIELD_AUTHORITY;
		return 0;
	}
	if (!strcasecmp(name, "transition")) {
		*field = HDN_FIELD_TRANSITION;
		return 0;
	}
	if (!strcasecmp(name, "reason")) {
		*field = HDN_FIELD_REASON;
		return 0;
	}

	return -EINVAL;
}

static const struct hdn_name *map_for_field(enum hdn_decode_field field,
					    size_t *count)
{
	switch (field) {
	case HDN_FIELD_EVENT:
	case HDN_FIELD_TRANSITION:
		*count = sizeof(transition_names) / sizeof(transition_names[0]);
		return transition_names;
	case HDN_FIELD_ACTION:
		*count = sizeof(action_names) / sizeof(action_names[0]);
		return action_names;
	case HDN_FIELD_AUTHORITY:
		*count = sizeof(authority_names) / sizeof(authority_names[0]);
		return authority_names;
	case HDN_FIELD_REASON:
		*count = sizeof(reason_names) / sizeof(reason_names[0]);
		return reason_names;
	}

	*count = 0;
	return NULL;
}

static int parse_expectation(const char *text, struct hdn_expectation *expect)
{
	char *copy;
	char *value;
	size_t count;
	const struct hdn_name *names;
	unsigned long long parsed;
	int ret;

	copy = strdup(text);
	if (!copy)
		return -ENOMEM;

	value = strchr(copy, '=');
	if (!value) {
		free(copy);
		return -EINVAL;
	}
	*value++ = '\0';

	ret = parse_field(copy, &expect->field);
	if (ret) {
		free(copy);
		return ret;
	}

	if (!parse_u64(value, &parsed)) {
		expect->value = (unsigned int)parsed;
		free(copy);
		return 0;
	}

	names = map_for_field(expect->field, &count);
	ret = lookup_value(names, count, value, &expect->value);
	free(copy);
	return ret;
}

static bool event_matches(const struct hdn_decoded_event *event,
			  const struct hdn_expectation *expectations,
			  unsigned int expectation_count)
{
	unsigned int i;

	for (i = 0; i < expectation_count; i++) {
		if (event_field(event, expectations[i].field) !=
		    expectations[i].value)
			return false;
	}

	return true;
}

static void print_flag_names(unsigned long long flags)
{
	bool first = true;

	if (flags & HDN_EVENT_RESPONSE_KILL_TASK) {
		printf("%sRESPONSE_KILL_TASK", first ? "" : ",");
		first = false;
	}
	if (flags & HDN_EVENT_CHROOTED) {
		printf("%sCHROOTED", first ? "" : ",");
		first = false;
	}
	if (first)
		printf("none");
}

static void print_resource_detail(unsigned long long object)
{
	unsigned int resource = object >> 56;
	unsigned long long wanted =
		object & ((1ULL << 56) - 1);
	bool packed_pressure = resource != 0;

	if (!packed_pressure)
		resource = (unsigned int)object;

	printf(" object_detail=resource resource_id=%u resource=%s",
	       resource,
	       lookup_name(resource_names,
			   sizeof(resource_names) / sizeof(resource_names[0]),
			   resource));
	if (packed_pressure)
		printf(" resource_wanted=%llu", wanted);
}

static void print_signal_detail(unsigned long long object)
{
	unsigned int sig = object >> 56;
	unsigned long long addr = object & ((1ULL << 56) - 1);

	printf(" object_detail=signal signal_id=%u signal=%s fault_addr_low=0x%llx",
	       sig,
	       lookup_name(signal_names,
			   sizeof(signal_names) / sizeof(signal_names[0]),
			   sig),
	       addr);
}

static void print_signal_number_detail(unsigned int sig)
{
	printf(" object_detail=signal signal_id=%u signal=%s",
	       sig,
	       lookup_name(signal_names,
			   sizeof(signal_names) / sizeof(signal_names[0]),
			   sig));
}

static void print_socket_create_detail(unsigned long long object)
{
	unsigned int family = object >> 32;
	unsigned int type = (object >> 16) & 0xffff;
	unsigned int protocol = object & 0xffff;

	printf(" object_detail=socket socket_family_id=%u socket_family=%s socket_type_id=%u socket_type=%s socket_protocol=%u",
	       family,
	       lookup_name(socket_family_names,
			   sizeof(socket_family_names) /
			   sizeof(socket_family_names[0]), family),
	       type,
	       lookup_name(socket_type_names,
			   sizeof(socket_type_names) /
			   sizeof(socket_type_names[0]), type),
	       protocol);
}

static void print_ipv4_endpoint(unsigned long long object)
{
	unsigned int type = (object >> 48) & 0xff;
	unsigned int port = (object >> 32) & 0xffff;
	unsigned int addr = object & 0xffffffff;
	unsigned char octets[4];

	octets[0] = (addr >> 24) & 0xff;
	octets[1] = (addr >> 16) & 0xff;
	octets[2] = (addr >> 8) & 0xff;
	octets[3] = addr & 0xff;

	printf(" object_detail=socket socket_family_id=%u socket_family=AF_INET socket_type_id=%u socket_type=%s socket_port=%u socket_address=%u.%u.%u.%u",
	       AF_INET, type,
	       lookup_name(socket_type_names,
			   sizeof(socket_type_names) /
			   sizeof(socket_type_names[0]), type),
	       port, octets[0], octets[1], octets[2], octets[3]);
}

static void print_ipv6_endpoint(unsigned long long object)
{
	unsigned int type = (object >> 48) & 0xff;
	unsigned int port = (object >> 32) & 0xffff;
	unsigned int hash = object & 0xffffffff;

	printf(" object_detail=socket socket_family_id=%u socket_family=AF_INET6 socket_type_id=%u socket_type=%s socket_port=%u socket_addr_hash=0x%x",
	       AF_INET6, type,
	       lookup_name(socket_type_names,
			   sizeof(socket_type_names) /
			   sizeof(socket_type_names[0]), type),
	       port, hash);
}

static void print_socket_endpoint_detail(unsigned long long object)
{
	unsigned int family = object >> 56;

	if (family == AF_INET) {
		print_ipv4_endpoint(object);
		return;
	}
	if (family == AF_INET6) {
		print_ipv6_endpoint(object);
		return;
	}

	print_socket_create_detail(object);
}

static void print_object_detail(const struct hdn_decoded_event *event)
{
	switch (event->transition) {
	case HDN_TRANS_EXEC_ARGS:
		printf(" object_detail=exec_args argc=%u envc=%u",
		       (unsigned int)(event->object >> 32),
		       (unsigned int)(event->object & 0xffffffff));
		break;
	case HDN_TRANS_FORK:
		if (event->object)
			printf(" object_detail=process related_pid=%llu",
			       event->object);
		break;
	case HDN_TRANS_PROCESS_ACCOUNT:
		printf(" object_detail=process exit_code=%u",
		       (unsigned int)event->object);
		break;
	case HDN_TRANS_SIGNAL:
		print_signal_detail(event->object);
		break;
	case HDN_TRANS_COREDUMP:
		print_signal_number_detail((unsigned int)event->object);
		break;
	case HDN_TRANS_TIME_CHANGE:
		printf(" object_detail=time time_operation_id=%u time_operation=%s",
		       (unsigned int)event->object,
		       lookup_name(time_operation_names,
				   sizeof(time_operation_names) /
				   sizeof(time_operation_names[0]),
				   (unsigned int)event->object));
		break;
	case HDN_TRANS_RESOURCE_LIMIT:
		print_resource_detail(event->object);
		break;
	case HDN_TRANS_USB_ATTACH:
		printf(" object_detail=usb usb_bus=%u usb_port=%u",
		       (unsigned int)(event->object >> 32),
		       (unsigned int)(event->object & 0xffffffff));
		break;
	case HDN_TRANS_USB_MONITOR:
		printf(" object_detail=usb usb_bus=%llu", event->object);
		break;
	case HDN_TRANS_SOCKET_CREATE:
		print_socket_create_detail(event->object);
		break;
	case HDN_TRANS_SOCKET_CONNECT:
	case HDN_TRANS_SOCKET_SERVER:
		print_socket_endpoint_detail(event->object);
		break;
	case HDN_TRANS_CAPABILITY:
		printf(" object_detail=capability capability_id=%u capability=%s",
		       (unsigned int)event->object,
		       lookup_name(capability_names,
				   sizeof(capability_names) /
				   sizeof(capability_names[0]),
				   (unsigned int)event->object));
		break;
	default:
		break;
	}
}

static void print_event(const struct hdn_decoded_event *event)
{
	printf("sequence=%llu timestamp_ns=%llu pid=%u uid=%u profile=%llu ",
	       event->sequence, event->timestamp_ns, event->pid, event->uid,
	       event->profile);
	printf("event_id=%u event=%s authority_id=%u authority=%s ",
	       event->event_id,
	       lookup_name(transition_names,
			   sizeof(transition_names) / sizeof(transition_names[0]),
			   event->event_id),
	       event->authority,
	       lookup_name(authority_names,
			   sizeof(authority_names) / sizeof(authority_names[0]),
			   event->authority));
	printf("transition_id=%u transition=%s action_id=%u action=%s ",
	       event->transition,
	       lookup_name(transition_names,
			   sizeof(transition_names) / sizeof(transition_names[0]),
			   event->transition),
	       event->action,
	       lookup_name(action_names,
			   sizeof(action_names) / sizeof(action_names[0]),
			   event->action));
	printf("reason_id=%u reason=%s error=%d subject=%llu object=%llu flags=0x%llx flag_names=",
	       event->reason,
	       lookup_name(reason_names,
			   sizeof(reason_names) / sizeof(reason_names[0]),
			   event->reason),
	       event->error, event->subject, event->object, event->flags);
	print_flag_names(event->flags);
	print_object_detail(event);
	printf("\n");
	fflush(stdout);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--input PATH] [--follow] [--quiet] "
		"[--expect FIELD=VALUE]...\n"
		"\n"
		"Decodes securityfs hardening event records to stable UAPI names.\n"
		"--follow polls the bounded event ring and prints each sequence once.\n"
		"Fields for --expect: event, action, authority, transition, reason.\n",
		prog);
}

int main(int argc, char **argv)
{
	const char *input = HDN_EVENTS_PATH;
	struct hdn_expectation expectations[HDN_MAX_EXPECTATIONS];
	unsigned int expectation_count = 0;
	unsigned long long last_sequence = 0;
	bool have_sequence = false;
	bool follow = false;
	bool quiet = false;
	bool found = false;
	char *line = NULL;
	size_t size = 0;
	ssize_t len;
	FILE *file;
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--help")) {
			usage(argv[0]);
			return 0;
		}
		if (!strcmp(argv[i], "--input")) {
			if (++i >= argc)
				goto bad_args;
			input = argv[i];
			continue;
		}
		if (!strcmp(argv[i], "--quiet")) {
			quiet = true;
			continue;
		}
		if (!strcmp(argv[i], "--follow")) {
			follow = true;
			continue;
		}
		if (!strcmp(argv[i], "--expect")) {
			if (++i >= argc ||
			    expectation_count >= HDN_MAX_EXPECTATIONS)
				goto bad_args;
			if (parse_expectation(argv[i],
					      &expectations[expectation_count]))
				goto bad_args;
			expectation_count++;
			continue;
		}
		goto bad_args;
	}

	if (follow && expectation_count)
		goto bad_args;
	if (follow) {
		if (signal(SIGTERM, stop_follow) == SIG_ERR ||
		    signal(SIGINT, stop_follow) == SIG_ERR) {
			fprintf(stderr,
				"hdn-event-decode: cannot install signal handler\n");
			return 2;
		}
	}

	do {
		struct timespec delay = {
			.tv_sec = 0,
			.tv_nsec = HDN_FOLLOW_POLL_NS,
		};

		file = fopen(input, "r");
		if (!file) {
			fprintf(stderr, "hdn-event-decode: cannot open %s: %s\n",
				input, strerror(errno));
			free(line);
			return 2;
		}

		while ((len = getline(&line, &size, file)) >= 0) {
			struct hdn_decoded_event event;

			(void)len;
			if (parse_event_line(line, &event)) {
				free(line);
				fclose(file);
				fprintf(stderr,
					"hdn-event-decode: malformed event line\n");
				return 2;
			}
			if (follow && have_sequence &&
			    event.sequence <= last_sequence)
				continue;
			if (follow) {
				last_sequence = event.sequence;
				have_sequence = true;
			}
			if (expectation_count &&
			    event_matches(&event, expectations,
					  expectation_count))
				found = true;
			if (!quiet)
				print_event(&event);
		}

		if (ferror(file)) {
			free(line);
			fclose(file);
			return 2;
		}
		fclose(file);
		if (follow && !follow_stop) {
			while (nanosleep(&delay, &delay) && errno == EINTR &&
			       !follow_stop)
				;
		}
	} while (follow && !follow_stop);

	free(line);

	if (expectation_count)
		return found ? 0 : 1;
	return 0;

bad_args:
	usage(argv[0]);
	return 2;
}
