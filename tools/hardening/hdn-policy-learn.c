// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE

#include <errno.h>
#include <linux/hardening.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#ifndef HDN_EVENTS_PATH
#define HDN_EVENTS_PATH "/sys/kernel/security/hardening/events"
#endif

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define HDN_MAX_LEARN_PROFILES 256
#define HDN_MAX_REVIEW_ITEMS 512

struct hdn_name {
	unsigned int value;
	const char *name;
};

struct hdn_learn_event {
	unsigned long long sequence;
	unsigned long long profile;
	unsigned long long subject;
	unsigned long long object;
	unsigned int event_id;
	unsigned int authority;
	unsigned int transition;
	unsigned int action;
	unsigned int reason;
	int error;
};

struct hdn_profile_suggestion {
	bool used;
	unsigned long long profile;
	uint64_t authority_mask;
	uint64_t authority_mask_hi;
	uint64_t mem_flags;
};

struct hdn_review_item {
	bool used;
	unsigned long long profile;
	unsigned long long subject;
	unsigned long long object;
	unsigned int authority;
	unsigned int transition;
	unsigned int reason;
	unsigned int action;
	int error;
	unsigned int count;
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
	{ HDN_TRANS_PROCESS_ACCOUNT, "PROCESS_ACCOUNT" },
	{ HDN_TRANS_COREDUMP, "COREDUMP" },
	{ HDN_TRANS_EXEC_ARGS, "EXEC_ARGS" },
	{ HDN_TRANS_KERNEL_LOCKOUT, "KERNEL_LOCKOUT" },
	{ HDN_TRANS_OBJECT_UNIX_BIND, "OBJECT_UNIX_BIND" },
	{ HDN_TRANS_OBJECT_UNIX_LISTEN, "OBJECT_UNIX_LISTEN" },
	{ HDN_TRANS_OBJECT_UNIX_ACCEPT, "OBJECT_UNIX_ACCEPT" },
	{ HDN_TRANS_OBJECT_UNIX_SEND, "OBJECT_UNIX_SEND" },
	{ HDN_TRANS_OBJECT_UNIX_RECV, "OBJECT_UNIX_RECV" },
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
	{ HDN_REASON_USERNS_DEPTH, "USERNS_DEPTH" },
	{ HDN_REASON_POLICY_IDENTITY_MISMATCH,
	  "POLICY_IDENTITY_MISMATCH" },
};

struct hdn_mem_name {
	uint64_t value;
	const char *name;
};

static const struct hdn_mem_name mem_flag_names[] = {
	{ HDN_MEM_ALLOW_WX, "ALLOW_WX" },
	{ HDN_MEM_ALLOW_EXEC_AFTER_WRITE, "ALLOW_EXEC_AFTER_WRITE" },
	{ HDN_MEM_ALLOW_FIXED_ANON_EXEC, "ALLOW_FIXED_ANON_EXEC" },
	{ HDN_MEM_ALLOW_READ_IMPLIES_EXEC, "ALLOW_READ_IMPLIES_EXEC" },
	{ HDN_MEM_ALLOW_JIT_EXEC_AFTER_WRITE, "ALLOW_JIT_EXEC_AFTER_WRITE" },
	{ HDN_MEM_ALLOW_EXEC_STACK_ELF, "ALLOW_EXEC_STACK_ELF" },
	{ HDN_MEM_ALLOW_TEXTREL_MPROTECT, "ALLOW_TEXTREL_MPROTECT" },
	{ HDN_MEM_ALLOW_RELRO_WRITE, "ALLOW_RELRO_WRITE" },
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

static int parse_named_u32(const char *text, const struct hdn_name *names,
			   size_t count, unsigned int *value)
{
	unsigned long long parsed;

	if (!parse_u64(text, &parsed)) {
		*value = (unsigned int)parsed;
		return 0;
	}

	return lookup_value(names, count, text, value);
}

static int parse_event_line(char *line, struct hdn_learn_event *event)
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
		} else if (!strcmp(word, "event_id") ||
			   !strcmp(word, "event")) {
			if (parse_named_u32(value, transition_names,
					    ARRAY_SIZE(transition_names),
					    &event->event_id))
				return -EINVAL;
		} else if (!strcmp(word, "profile")) {
			if (parse_u64(value, &event->profile))
				return -EINVAL;
		} else if (!strcmp(word, "authority") ||
			   !strcmp(word, "authority_id")) {
			if (parse_named_u32(value, authority_names,
					    ARRAY_SIZE(authority_names),
					    &event->authority))
				return -EINVAL;
		} else if (!strcmp(word, "transition") ||
			   !strcmp(word, "transition_id")) {
			if (parse_named_u32(value, transition_names,
					    ARRAY_SIZE(transition_names),
					    &event->transition))
				return -EINVAL;
		} else if (!strcmp(word, "action") ||
			   !strcmp(word, "action_id")) {
			if (parse_named_u32(value, action_names,
					    ARRAY_SIZE(action_names),
					    &event->action))
				return -EINVAL;
		} else if (!strcmp(word, "reason") ||
			   !strcmp(word, "reason_id")) {
			if (parse_named_u32(value, reason_names,
					    ARRAY_SIZE(reason_names),
					    &event->reason))
				return -EINVAL;
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
		} else if (!strcmp(word, "pid") ||
			   !strcmp(word, "uid") ||
			   !strcmp(word, "timestamp_ns") ||
			   !strcmp(word, "flags")) {
			if (parse_u64(value, &parsed))
				return -EINVAL;
		}
	}

	return 0;
}

static struct hdn_profile_suggestion *
find_profile_suggestion(struct hdn_profile_suggestion *profiles,
			unsigned long long profile)
{
	size_t i;

	for (i = 0; i < HDN_MAX_LEARN_PROFILES; i++) {
		if (profiles[i].used && profiles[i].profile == profile)
			return &profiles[i];
	}

	for (i = 0; i < HDN_MAX_LEARN_PROFILES; i++) {
		if (!profiles[i].used) {
			profiles[i].used = true;
			profiles[i].profile = profile;
			return &profiles[i];
		}
	}

	return NULL;
}

static bool is_deny_action(unsigned int action)
{
	return action == HDN_DECISION_DENY ||
	       action == HDN_DECISION_DENY_AUDIT;
}

static int add_authority_mask(unsigned int authority, uint64_t *mask,
			      uint64_t *mask_hi)
{
	if (!authority || authority >= HDN_AUTH__MAX ||
	    authority >= HDN_AUTHORITY_MAX_BITS)
		return -EINVAL;

	if (HDN_AUTHORITY_WORD(authority) == 0)
		*mask |= HDN_AUTHORITY_MASK(authority);
	else if (HDN_AUTHORITY_WORD(authority) == 1)
		*mask_hi |= HDN_AUTHORITY_MASK(authority);
	else
		return -EINVAL;

	return 0;
}

static bool authority_mask_contains(uint64_t mask, uint64_t mask_hi,
				    unsigned int authority)
{
	if (authority >= HDN_AUTH__MAX || authority >= HDN_AUTHORITY_MAX_BITS)
		return false;
	if (HDN_AUTHORITY_WORD(authority) == 0)
		return mask & HDN_AUTHORITY_MASK(authority);
	if (HDN_AUTHORITY_WORD(authority) == 1)
		return mask_hi & HDN_AUTHORITY_MASK(authority);
	return false;
}

static bool is_memory_authority(unsigned int authority)
{
	return authority == HDN_AUTH_MMAP || authority == HDN_AUTH_MPROTECT;
}

static bool memory_flag_for_reason(unsigned int reason, uint64_t *flag)
{
	switch (reason) {
	case HDN_REASON_EXEC_AFTER_WRITE:
		*flag = HDN_MEM_ALLOW_EXEC_AFTER_WRITE;
		return true;
	case HDN_REASON_FIXED_ANON_EXEC_MAPPING:
		*flag = HDN_MEM_ALLOW_FIXED_ANON_EXEC;
		return true;
	case HDN_REASON_READ_IMPLIES_EXEC:
		*flag = HDN_MEM_ALLOW_READ_IMPLIES_EXEC;
		return true;
	case HDN_REASON_EXEC_STACK_ELF:
		*flag = HDN_MEM_ALLOW_EXEC_STACK_ELF;
		return true;
	case HDN_REASON_TEXTREL_MPROTECT:
		*flag = HDN_MEM_ALLOW_TEXTREL_MPROTECT;
		return true;
	case HDN_REASON_RELRO_WRITE:
		*flag = HDN_MEM_ALLOW_RELRO_WRITE;
		return true;
	default:
		return false;
	}
}

static bool authority_is_review_only(unsigned int authority)
{
	switch (authority) {
	case HDN_AUTH_NONE:
	case HDN_AUTH_EXEC:
	case HDN_AUTH_MMAP:
	case HDN_AUTH_MPROTECT:
	case HDN_AUTH_MODULE_LOAD:
	case HDN_AUTH_MODULE_AUTOLOAD:
	case HDN_AUTH_FIRMWARE_LOAD:
	case HDN_AUTH_POLICY_ADMIN:
	case HDN_AUTH_CRED_CHANGE:
	case HDN_AUTH_TRUSTED_EXEC_BYPASS:
	case HDN_AUTH_OBJECT_WRITE:
	case HDN_AUTH_OBJECT_READ:
	case HDN_AUTH_OBJECT_DELETE:
	case HDN_AUTH_OBJECT_CREATE:
	case HDN_AUTH_OBJECT_EXEC:
	case HDN_AUTH_OBJECT_APPEND:
	case HDN_AUTH_OBJECT_LINK:
	case HDN_AUTH_OBJECT_ATTR:
	case HDN_AUTH_OBJECT_ACCESS:
	case HDN_AUTH_OBJECT_STAT:
	case HDN_AUTH_OBJECT_LIST:
	case HDN_AUTH_OBJECT_FIND:
	case HDN_AUTH_OBJECT_IOCTL:
	case HDN_AUTH_OBJECT_LOCK:
	case HDN_AUTH_OBJECT_WATCH:
	case HDN_AUTH_OBJECT_XATTR:
	case HDN_AUTH_OBJECT_RECEIVE:
	case HDN_AUTH_OBJECT_FCNTL:
	case HDN_AUTH_OBJECT_CHDIR:
	case HDN_AUTH_OBJECT_MOUNT:
	case HDN_AUTH_OBJECT_MOUNT_SOURCE:
	case HDN_AUTH_OBJECT_UMOUNT:
	case HDN_AUTH_OBJECT_TRUNCATE:
	case HDN_AUTH_OBJECT_RENAME:
	case HDN_AUTH_OBJECT_RENAME_TARGET:
	case HDN_AUTH_OBJECT_LINK_TARGET:
	case HDN_AUTH_OBJECT_UNIX_CONNECT:
	case HDN_AUTH_OBJECT_CHMOD:
	case HDN_AUTH_OBJECT_CHOWN:
	case HDN_AUTH_OBJECT_UTIME:
	case HDN_AUTH_OBJECT_SETID:
	case HDN_AUTH_OBJECT_PTRACE:
	case HDN_AUTH_OBJECT_SETXATTR:
	case HDN_AUTH_OBJECT_REMOVEXATTR:
	case HDN_AUTH_OBJECT_CREAT:
	case HDN_AUTH_OBJECT_MKDIR:
	case HDN_AUTH_OBJECT_MKNOD:
	case HDN_AUTH_OBJECT_SYMLINK:
	case HDN_AUTH_OBJECT_UNLINK:
	case HDN_AUTH_OBJECT_RMDIR:
	case HDN_AUTH_OBJECT_UNIX_BIND:
	case HDN_AUTH_OBJECT_UNIX_LISTEN:
	case HDN_AUTH_OBJECT_UNIX_ACCEPT:
	case HDN_AUTH_OBJECT_UNIX_SEND:
	case HDN_AUTH_OBJECT_UNIX_RECV:
		return true;
	default:
		return false;
	}
}

static int add_review(struct hdn_review_item *reviews,
		      const struct hdn_learn_event *event)
{
	size_t i;

	for (i = 0; i < HDN_MAX_REVIEW_ITEMS; i++) {
		if (!reviews[i].used)
			continue;
		if (reviews[i].profile == event->profile &&
		    reviews[i].authority == event->authority &&
		    reviews[i].transition == event->transition &&
		    reviews[i].reason == event->reason &&
		    reviews[i].action == event->action &&
		    reviews[i].error == event->error &&
		    reviews[i].subject == event->subject &&
		    reviews[i].object == event->object) {
			reviews[i].count++;
			return 0;
		}
	}

	for (i = 0; i < HDN_MAX_REVIEW_ITEMS; i++) {
		if (!reviews[i].used) {
			reviews[i].used = true;
			reviews[i].profile = event->profile;
			reviews[i].authority = event->authority;
			reviews[i].transition = event->transition;
			reviews[i].reason = event->reason;
			reviews[i].action = event->action;
			reviews[i].error = event->error;
			reviews[i].subject = event->subject;
			reviews[i].object = event->object;
			reviews[i].count = 1;
			return 0;
		}
	}

	return -ENOSPC;
}

static int learn_event(struct hdn_profile_suggestion *profiles,
		       struct hdn_review_item *reviews,
		       const struct hdn_learn_event *event,
		       unsigned long long profile_filter)
{
	struct hdn_profile_suggestion *profile;
	uint64_t mem_flag;

	if (!is_deny_action(event->action))
		return 0;
	if (profile_filter && event->profile != profile_filter)
		return 0;

	profile = find_profile_suggestion(profiles, event->profile);
	if (!profile)
		return -ENOSPC;

	if (is_memory_authority(event->authority) &&
	    memory_flag_for_reason(event->reason, &mem_flag)) {
		profile->mem_flags |= mem_flag;
		return 0;
	}

	if (event->reason == HDN_REASON_RESOURCE_PROFILE_LIMIT)
		return add_review(reviews, event);
	if (event->reason == HDN_REASON_PROTECTED_SHM)
		return add_review(reviews, event);

	if (event->authority < HDN_AUTH__MAX &&
	    !authority_is_review_only(event->authority)) {
		if (add_authority_mask(event->authority,
				       &profile->authority_mask,
				       &profile->authority_mask_hi))
			return add_review(reviews, event);
		return 0;
	}

	return add_review(reviews, event);
}

static bool profile_has_output(const struct hdn_profile_suggestion *profile)
{
	return profile->authority_mask || profile->authority_mask_hi ||
	       profile->mem_flags;
}

static void print_authority_line(const struct hdn_profile_suggestion *profile)
{
	unsigned int authority;

	if (!profile->authority_mask && !profile->authority_mask_hi)
		return;

	printf("allow %llu", profile->profile);
	for (authority = 1; authority < HDN_AUTH__MAX; authority++) {
		if (authority_mask_contains(profile->authority_mask,
					    profile->authority_mask_hi,
					    authority))
			printf(" %s", lookup_name(authority_names,
						  ARRAY_SIZE(authority_names),
						  authority));
	}
	printf("\n");
}

static void print_mem_line(const struct hdn_profile_suggestion *profile)
{
	size_t i;

	if (!profile->mem_flags)
		return;

	printf("mem %llu", profile->profile);
	for (i = 0; i < ARRAY_SIZE(mem_flag_names); i++) {
		if (profile->mem_flags & mem_flag_names[i].value)
			printf(" %s", mem_flag_names[i].name);
	}
	printf("\n");
}

static void print_review_item(const struct hdn_review_item *review)
{
	printf("# review profile=%llu count=%u authority=%s transition=%s ",
	       review->profile, review->count,
	       lookup_name(authority_names, ARRAY_SIZE(authority_names),
			   review->authority),
	       lookup_name(transition_names, ARRAY_SIZE(transition_names),
			   review->transition));
	printf("action=%s reason=%s error=%d subject=%llu object=%llu\n",
	       lookup_name(action_names, ARRAY_SIZE(action_names),
			   review->action),
	       lookup_name(reason_names, ARRAY_SIZE(reason_names),
			   review->reason),
	       review->error, review->subject, review->object);
}

static void print_suggestions(const struct hdn_profile_suggestion *profiles,
			      const struct hdn_review_item *reviews,
			      const char *input)
{
	bool emitted = false;
	size_t i;

	printf("# HDN_LEARN_V1\n");
	printf("# source %s\n", input);
	printf("# Review before compiling, signing, and committing.\n");

	for (i = 0; i < HDN_MAX_LEARN_PROFILES; i++) {
		if (!profiles[i].used || !profile_has_output(&profiles[i]))
			continue;
		print_authority_line(&profiles[i]);
		print_mem_line(&profiles[i]);
		emitted = true;
	}

	for (i = 0; i < HDN_MAX_REVIEW_ITEMS; i++) {
		if (!reviews[i].used)
			continue;
		if (!emitted) {
			printf("# No automatic allow/mem suggestions.\n");
			emitted = true;
		}
		print_review_item(&reviews[i]);
	}

	if (!emitted)
		printf("# No denied HDN events found.\n");
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--input PATH] [--profile ID]\n"
		"\n"
		"Reads HDN event records and emits a reviewable policy fragment.\n"
		"Only denied events become suggestions. High-risk identity and\n"
		"invariant failures are emitted as review comments.\n",
		prog);
}

int main(int argc, char **argv)
{
	struct hdn_profile_suggestion profiles[HDN_MAX_LEARN_PROFILES] = {};
	struct hdn_review_item reviews[HDN_MAX_REVIEW_ITEMS] = {};
	unsigned long long profile_filter = 0;
	const char *input = HDN_EVENTS_PATH;
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
		if (!strcmp(argv[i], "--profile")) {
			if (++i >= argc || parse_u64(argv[i], &profile_filter))
				goto bad_args;
			continue;
		}
		goto bad_args;
	}

	file = fopen(input, "r");
	if (!file) {
		fprintf(stderr, "hdn-policy-learn: cannot open %s: %s\n",
			input, strerror(errno));
		return 2;
	}

	while ((len = getline(&line, &size, file)) >= 0) {
		struct hdn_learn_event event;

		(void)len;
		if (parse_event_line(line, &event)) {
			free(line);
			fclose(file);
			fprintf(stderr,
				"hdn-policy-learn: malformed event line\n");
			return 2;
		}
		if (learn_event(profiles, reviews, &event, profile_filter)) {
			free(line);
			fclose(file);
			fprintf(stderr,
				"hdn-policy-learn: too many suggestions\n");
			return 2;
		}
	}

	free(line);
	if (ferror(file)) {
		fclose(file);
		return 2;
	}
	fclose(file);

	print_suggestions(profiles, reviews, input);
	return 0;

bad_args:
	usage(argv[0]);
	return 2;
}
