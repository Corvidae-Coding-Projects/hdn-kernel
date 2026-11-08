// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <linux/hardening.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef HDN_STATUS_PATH
#define HDN_STATUS_PATH "/sys/kernel/security/hardening/status"
#endif

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define HDN_STATUS_MAX_ENTRIES 512
#define HDN_STATUS_MAX_OUTPUTS 512
#define HDN_STATUS_MAX_EXPECTATIONS 32

struct hdn_name {
	unsigned int value;
	const char *name;
};

struct hdn_status_entry {
	char *key;
	char *value;
};

struct hdn_status {
	struct hdn_status_entry entries[HDN_STATUS_MAX_ENTRIES];
	unsigned int count;
};

struct hdn_output {
	char key[64];
	char value[256];
};

struct hdn_outputs {
	struct hdn_output values[HDN_STATUS_MAX_OUTPUTS];
	unsigned int count;
};

struct hdn_expectation {
	char *key;
	char *value;
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
	{ HDN_AUTH_USB_MONITOR, "USB_MONITOR" },
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
	{ HDN_TRANS_USB_MONITOR, "USB_MONITOR" },
	{ HDN_TRANS_OBJECT_UNIX_BIND, "OBJECT_UNIX_BIND" },
	{ HDN_TRANS_OBJECT_UNIX_LISTEN, "OBJECT_UNIX_LISTEN" },
	{ HDN_TRANS_OBJECT_UNIX_ACCEPT, "OBJECT_UNIX_ACCEPT" },
	{ HDN_TRANS_OBJECT_UNIX_SEND, "OBJECT_UNIX_SEND" },
	{ HDN_TRANS_OBJECT_UNIX_RECV, "OBJECT_UNIX_RECV" },
	{ HDN_TRANS_POLICY_REFRESH, "POLICY_REFRESH" },
	{ HDN_TRANS_KERNEL_MAPPING, "KERNEL_MAPPING" },
	{ HDN_TRANS_KERNEL_TEXT, "KERNEL_TEXT" },
	{ HDN_TRANS_KERNEL_SEAL, "KERNEL_SEAL" },
	{ HDN_TRANS_KERNEL_DESCRIPTOR, "KERNEL_DESCRIPTOR" },
	{ HDN_TRANS_KERNEL_UACCESS, "KERNEL_UACCESS" },
	{ HDN_TRANS_KERNEL_ALLOC, "KERNEL_ALLOC" },
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
	{ HDN_REASON_BRUTE_DAEMON_THROTTLED, "BRUTE_DAEMON_THROTTLED" },
	{ HDN_REASON_KERNEL_LOCKOUT, "KERNEL_LOCKOUT" },
	{ HDN_REASON_RESOURCE_PROFILE_LIMIT, "RESOURCE_PROFILE_LIMIT" },
	{ HDN_REASON_PROTECTED_SHM, "PROTECTED_SHM" },
	{ HDN_REASON_USERNS_DEPTH, "USERNS_DEPTH" },
	{ HDN_REASON_POLICY_IDENTITY_MISMATCH,
	  "POLICY_IDENTITY_MISMATCH" },
	{ HDN_REASON_KERNEL_WX_MAPPING, "KERNEL_WX_MAPPING" },
	{ HDN_REASON_KERNEL_TEXT_PATCH, "KERNEL_TEXT_PATCH" },
	{ HDN_REASON_KERNEL_TEXT_DEBUGGER, "KERNEL_TEXT_DEBUGGER" },
	{ HDN_REASON_KERNEL_TEXT_CONSTRUCT, "KERNEL_TEXT_CONSTRUCT" },
	{ HDN_REASON_KERNEL_TEXT_TRAP_FILL, "KERNEL_TEXT_TRAP_FILL" },
	{ HDN_REASON_KERNEL_TEXT_STATE, "KERNEL_TEXT_STATE" },
	{ HDN_REASON_KERNEL_SEAL_STATE, "KERNEL_SEAL_STATE" },
	{ HDN_REASON_KERNEL_PAGE_CONSTRUCT, "KERNEL_PAGE_CONSTRUCT" },
	{ HDN_REASON_KERNEL_PAGE_FINALIZE, "KERNEL_PAGE_FINALIZE" },
	{ HDN_REASON_KERNEL_PAGE_RETIRE, "KERNEL_PAGE_RETIRE" },
	{ HDN_REASON_KERNEL_GDT_UPDATE, "KERNEL_GDT_UPDATE" },
	{ HDN_REASON_KERNEL_GDT_LTR, "KERNEL_GDT_LTR" },
	{ HDN_REASON_KERNEL_SMAP_RESTORED, "KERNEL_SMAP_RESTORED" },
	{ HDN_REASON_KERNEL_OBJECT_CORRUPTION, "KERNEL_OBJECT_CORRUPTION" },
	{ HDN_REASON_CONTROL_FLOW_VIOLATION, "CONTROL_FLOW_VIOLATION" },
	{ HDN_REASON_KERNEL_USER_ACCESS_DENIED, "KERNEL_USER_ACCESS_DENIED" },
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--status-path PATH] [--raw] [--compat] [--quiet] [--expect KEY=VALUE]...\n"
		"\n"
		"Prints stable product-facing key=value status from hardening securityfs.\n",
		prog);
}

static char *trim(char *line)
{
	char *end;

	while (*line == ' ' || *line == '\t' || *line == '\r' ||
	       *line == '\n')
		line++;

	end = line + strlen(line);
	while (end > line &&
	       (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' ||
		end[-1] == '\n'))
		*--end = '\0';

	return line;
}

static bool valid_key(const char *key)
{
	bool capability_key;
	const char *p;

	if (!key || !key[0])
		return false;
	capability_key = !strncmp(key, "capability.", 11) && key[11];

	for (p = key; *p; p++) {
		if (isalnum((unsigned char)*p) || *p == '_')
			continue;
		if (*p == '.' && capability_key && p == key + 10)
			continue;
		return false;
	}

	return true;
}

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

static int read_status_line(struct hdn_status *status, char *line,
			    unsigned int lineno)
{
	struct hdn_status_entry *entry;
	char *colon;
	char *key;
	char *value;
	unsigned int i;

	line = trim(line);
	if (!line[0])
		return 0;

	colon = strchr(line, ':');
	if (!colon) {
		fprintf(stderr, "hdn-status: malformed status line %u\n", lineno);
		return -EINVAL;
	}

	*colon = '\0';
	key = trim(line);
	value = trim(colon + 1);
	if (!valid_key(key)) {
		fprintf(stderr, "hdn-status: invalid status key at line %u\n",
			lineno);
		return -EINVAL;
	}
	if (status->count >= HDN_STATUS_MAX_ENTRIES) {
		fprintf(stderr, "hdn-status: too many status entries\n");
		return -E2BIG;
	}

	entry = &status->entries[status->count];
	for (i = 0; i < status->count; i++) {
		if (!strcmp(status->entries[i].key, key)) {
			fprintf(stderr, "hdn-status: duplicate status key at line %u\n",
				lineno);
			return -EINVAL;
		}
	}
	entry->key = strdup(key);
	entry->value = strdup(value);
	if (!entry->key || !entry->value)
		return -ENOMEM;
	status->count++;
	return 0;
}

static int read_status_file(const char *path, struct hdn_status *status)
{
	char *line = NULL;
	unsigned int lineno = 0;
	size_t size = 0;
	ssize_t len;
	FILE *file;
	int ret = 0;

	memset(status, 0, sizeof(*status));

	file = fopen(path, "r");
	if (!file) {
		fprintf(stderr, "hdn-status: cannot open %s: %s\n", path,
			strerror(errno));
		return -errno;
	}

	while ((len = getline(&line, &size, file)) >= 0) {
		(void)len;
		lineno++;
		ret = read_status_line(status, line, lineno);
		if (ret)
			break;
	}
	if (ferror(file) && !ret)
		ret = -EIO;

	free(line);
	fclose(file);
	return ret;
}

static void free_status(struct hdn_status *status)
{
	unsigned int i;

	for (i = 0; i < status->count; i++) {
		free(status->entries[i].key);
		free(status->entries[i].value);
	}
}

static const char *status_value(const struct hdn_status *status,
				const char *key)
{
	unsigned int i;

	for (i = 0; i < status->count; i++) {
		if (!strcmp(status->entries[i].key, key))
			return status->entries[i].value;
	}

	return NULL;
}

static bool status_u64(const struct hdn_status *status, const char *key,
		       unsigned long long *value)
{
	const char *text = status_value(status, key);
	char *end;

	if (!text)
		return false;

	errno = 0;
	*value = strtoull(text, &end, 0);
	return !errno && end != text && !*end;
}

static unsigned long long status_u64_default(const struct hdn_status *status,
					     const char *key,
					     unsigned long long fallback)
{
	unsigned long long value;

	return status_u64(status, key, &value) ? value : fallback;
}

static bool status_bool(const struct hdn_status *status, const char *key)
{
	return status_u64_default(status, key, 0) != 0;
}

static bool starts_with(const char *text, const char *prefix)
{
	return !strncmp(text, prefix, strlen(prefix));
}

static bool mitigation_counter_key(const char *key)
{
	if (!starts_with(key, "mitigation_"))
		return false;
	if (!strcmp(key, "mitigation_pages") ||
	    !strcmp(key, "mitigation_flags") ||
	    !strcmp(key, "mitigation_flags2"))
		return false;
	return true;
}

static void count_mitigations(const struct hdn_status *status,
			      unsigned int *known, unsigned int *enabled)
{
	unsigned int i;

	*known = 0;
	*enabled = 0;

	for (i = 0; i < status->count; i++) {
		unsigned long long value;

		if (!mitigation_counter_key(status->entries[i].key))
			continue;
		if (!status_u64(status, status->entries[i].key, &value))
			continue;
		if (value > 1)
			continue;
		(*known)++;
		if (value)
			(*enabled)++;
	}
}

static const char *const capability_status_names[] = {
#define HDN_CAP_STATUS_NAME(symbol, name) [HDN_CAP_##symbol] = "capability." #name,
	HDN_CAPABILITY_LIST(HDN_CAP_STATUS_NAME)
#undef HDN_CAP_STATUS_NAME
};

_Static_assert(ARRAY_SIZE(capability_status_names) == HDN_CAP__MAX,
	       "capability status inventory mismatch");

static bool capability_record_satisfies(const char *record)
{
	const char *backing;
	size_t state_length;

	if (!record)
		return false;
	backing = strchr(record, ',');
	if (!backing || strchr(backing + 1, ','))
		return false;
	state_length = (size_t)(backing - record);
	backing++;
	if (strcmp(backing, "none") && strcmp(backing, "hardware") &&
	    strcmp(backing, "software") && strcmp(backing, "hybrid"))
		return false;

	return (state_length == strlen("enforced") &&
		!strncmp(record, "enforced", state_length)) ||
	       (state_length == strlen("not-applicable") &&
		!strncmp(record, "not-applicable", state_length));
}

static bool capability_requirements_satisfied(const struct hdn_status *status)
{
	const char *architecture = status_value(status, "capability_architecture");
	const char *requirements = status_value(status, "capability_requirements");
	const char *version = status_value(status, "capability_version");
	unsigned long long required;
	unsigned int id;

	if (!version || strcmp(version, "1") || !architecture || !architecture[0] ||
	    !requirements || !status_u64(status, "capability_required_mask", &required) ||
	    (required & ~(unsigned long long)HDN_CAP_KNOWN_MASK))
		return false;
	if (!strcmp(requirements, "unconstrained"))
		return required == 0;
	if (strcmp(requirements, "satisfied") || required == 0)
		return false;

	for (id = 0; id < HDN_CAP__MAX; id++) {
		if ((required & HDN_CAP_REQUIRED(id)) &&
		    !capability_record_satisfies(status_value(
			status, capability_status_names[id])))
			return false;
	}
	return true;
}

static const char *attention_reason(const struct hdn_status *status)
{
	if (!status_bool(status, "mitigations_sealed"))
		return "mitigations_unsealed";
	if (!status_bool(status, "policy_loaded"))
		return "policy_not_loaded";
	if (!status_bool(status, "policy_sealed"))
		return "policy_unsealed";
	if (!capability_requirements_satisfied(status))
		return "capability_requirements_unsatisfied";
	return "none";
}

static const char *state_name(const struct hdn_status *status,
			      const char *attention)
{
	const char *phase = status_value(status, "phase");

	if (strcmp(attention, "none") &&
	    strcmp(attention, "policy_not_loaded"))
		return "degraded";
	if (phase && !strcmp(phase, "recovery"))
		return "recovery";
	if (!status_bool(status, "policy_loaded"))
		return status_bool(status, "policy_staged") ? "staged" :
							       "setup";
	if (phase && !strcmp(phase, "policy-load"))
		return "loading";
	return "active";
}

static int output_add(struct hdn_outputs *outputs, const char *key,
		      const char *format, ...)
{
	struct hdn_output *output;
	va_list ap;
	int ret;

	if (!valid_key(key)) {
		fprintf(stderr, "hdn-status: internal invalid output key: %s\n",
			key);
		return -EINVAL;
	}
	if (outputs->count >= HDN_STATUS_MAX_OUTPUTS) {
		fprintf(stderr, "hdn-status: too many output entries\n");
		return -E2BIG;
	}

	output = &outputs->values[outputs->count];
	snprintf(output->key, sizeof(output->key), "%s", key);
	va_start(ap, format);
	ret = vsnprintf(output->value, sizeof(output->value), format, ap);
	va_end(ap);
	if (ret < 0 || (size_t)ret >= sizeof(output->value)) {
		fprintf(stderr, "hdn-status: output value too long for %s\n",
			key);
		return -E2BIG;
	}

	outputs->count++;
	return 0;
}

static int output_status_value(struct hdn_outputs *outputs,
			       const struct hdn_status *status, const char *key,
			       const char *fallback)
{
	const char *value = status_value(status, key);

	return output_add(outputs, key, "%s", value ? value : fallback);
}

static bool status_all_enabled(const struct hdn_status *status,
			       const char * const *keys, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		if (!status_bool(status, keys[i]))
			return false;
	}

	return true;
}

static int output_compat_bool(struct hdn_outputs *outputs,
			      const char *key, bool enabled)
{
	return output_add(outputs, key, "%u", enabled ? 1 : 0);
}

static int output_compat_all(struct hdn_outputs *outputs,
			     const struct hdn_status *status, const char *key,
			     const char * const *required, size_t count)
{
	return output_compat_bool(outputs, key,
				  status_all_enabled(status, required, count));
}

static int build_compat_outputs(const struct hdn_status *status,
				struct hdn_outputs *outputs)
{
	static const char * const hidesym[] = {
		"mitigation_kernel_symbol_lookup_gate",
		"mitigation_kptr_restrict",
	};
	static const char * const proc_memmap[] = {
		"mitigation_proc_mem_restrict",
		"mitigation_proc_memmap_redact",
	};
	static const char * const bpf[] = {
		"mitigation_unpriv_bpf_lockdown",
		"mitigation_bpf_jit_harden",
	};
	static const char * const memory_init[] = {
		"mitigation_init_on_alloc",
		"mitigation_init_on_free",
		"mitigation_init_stack_zero",
		"mitigation_kstack_erase",
		"mitigation_zero_call_used_regs",
	};
	static const char * const allocator[] = {
		"mitigation_slab_freelist_random",
		"mitigation_slab_freelist_hardened",
		"mitigation_random_kmalloc_caches",
		"mitigation_slab_buckets",
		"mitigation_slab_merge_disabled",
	};
	static const char * const compiler[] = {
		"mitigation_hardened_usercopy",
		"mitigation_fortify_source",
		"mitigation_randstruct",
		"mitigation_list_hardened",
		"mitigation_stackprotector_strong",
	};
	static const char * const stack[] = {
		"mitigation_vmap_stack",
		"mitigation_thread_info_in_task",
		"mitigation_randomize_kstack",
		"mitigation_rand_threadstack",
	};
	static const char * const kernel_wx[] = {
		"mitigation_strict_kernel_rwx",
		"mitigation_strict_module_rwx",
		"mitigation_page_table_check",
	};
	static const char * const module[] = {
		"mitigation_module_load_disable",
		"mitigation_module_autoload",
		"mitigation_module_autoload_path",
		"mitigation_module_request_name",
		"mitigation_module_autoload_context",
	};
	static const char * const usb[] = {
		"mitigation_usb_restrict",
		"mitigation_usb_monitor_restrict",
	};
	static const char * const net_blackhole[] = {
		"mitigation_net_blackhole",
		"mitigation_tcp_no_simult_connect",
	};
	static const char * const ipc[] = {
		"mitigation_sysvipc_harden",
		"mitigation_posix_mqueue_harden",
	};
	static const char * const tty[] = {
		"mitigation_tty_injection_harden",
		"mitigation_tty_access_harden",
	};
	static const char * const resource[] = {
		"mitigation_resource_admin",
		"mitigation_resource_audit",
	};
	static const char * const audit[] = {
		"mitigation_audit_flood_control",
		"mitigation_exec_audit",
		"mitigation_chdir_audit",
		"mitigation_mount_audit",
		"mitigation_time_audit",
		"mitigation_resource_audit",
		"mitigation_fork_audit",
		"mitigation_forkfail_audit",
		"mitigation_fs_protection_audit",
		"mitigation_ptrace_audit",
		"mitigation_signal_audit",
		"mitigation_rwxmap_audit",
	};
	int ret;

	ret = output_add(outputs, "compat_status_v1", "1");
	if (ret)
		return ret;
	ret = output_compat_bool(outputs, "compat_dmesg",
				 status_bool(status,
					     "mitigation_dmesg_restrict"));
	if (ret)
		return ret;
	ret = output_compat_all(outputs, status, "compat_hidesym",
				hidesym, ARRAY_SIZE(hidesym));
	if (ret)
		return ret;
	ret = output_compat_bool(outputs, "compat_proc",
				 status_bool(status, "mitigation_proc_hide"));
	if (ret)
		return ret;
	ret = output_compat_all(outputs, status, "compat_proc_memmap",
				proc_memmap, ARRAY_SIZE(proc_memmap));
	if (ret)
		return ret;
	ret = output_compat_bool(outputs, "compat_sysfs",
				 status_bool(status,
					     "mitigation_sysfs_restrict"));
	if (ret)
		return ret;
	ret = output_compat_all(outputs, status, "compat_bpf",
				bpf, ARRAY_SIZE(bpf));
	if (ret)
		return ret;
	ret = output_compat_all(outputs, status, "compat_memory_init",
				memory_init, ARRAY_SIZE(memory_init));
	if (ret)
		return ret;
	ret = output_compat_all(outputs, status, "compat_allocator",
				allocator, ARRAY_SIZE(allocator));
	if (ret)
		return ret;
	ret = output_compat_all(outputs, status, "compat_compiler",
				compiler, ARRAY_SIZE(compiler));
	if (ret)
		return ret;
	ret = output_compat_all(outputs, status, "compat_stack",
				stack, ARRAY_SIZE(stack));
	if (ret)
		return ret;
	ret = output_compat_all(outputs, status, "compat_kernel_wx",
				kernel_wx, ARRAY_SIZE(kernel_wx));
	if (ret)
		return ret;
	ret = output_compat_bool(outputs, "compat_perf",
				 status_bool(status,
					     "mitigation_unpriv_perf_lockdown"));
	if (ret)
		return ret;
	ret = output_compat_bool(outputs, "compat_memfd_noexec",
				 status_bool(status,
					     "mitigation_memfd_noexec"));
	if (ret)
		return ret;
	ret = output_compat_bool(outputs, "compat_threadstack",
				 status_bool(status,
					     "mitigation_rand_threadstack"));
	if (ret)
		return ret;
	ret = output_compat_all(outputs, status, "compat_module",
				module, ARRAY_SIZE(module));
	if (ret)
		return ret;
	ret = output_compat_bool(outputs, "compat_rofs",
				 status_bool(status, "mitigation_rofs_harden"));
	if (ret)
		return ret;
	ret = output_compat_bool(outputs, "compat_fuse",
				 status_bool(status,
					     "mitigation_fuse_restrict"));
	if (ret)
		return ret;
	ret = output_compat_all(outputs, status, "compat_usb",
				usb, ARRAY_SIZE(usb));
	if (ret)
		return ret;
	ret = output_compat_bool(outputs, "compat_socket",
				 status_bool(status,
					     "mitigation_socket_restrict"));
	if (ret)
		return ret;
	ret = output_compat_all(outputs, status, "compat_net_blackhole",
				net_blackhole, ARRAY_SIZE(net_blackhole));
	if (ret)
		return ret;
	ret = output_compat_all(outputs, status, "compat_ipc",
				ipc, ARRAY_SIZE(ipc));
	if (ret)
		return ret;
	ret = output_compat_all(outputs, status, "compat_tty",
				tty, ARRAY_SIZE(tty));
	if (ret)
		return ret;
	ret = output_compat_all(outputs, status, "compat_resource",
				resource, ARRAY_SIZE(resource));
	if (ret)
		return ret;
	ret = output_compat_bool(outputs, "compat_block_device",
				 status_bool(status,
					     "mitigation_block_device_restrict"));
	if (ret)
		return ret;
	return output_compat_all(outputs, status, "compat_audit",
				 audit, ARRAY_SIZE(audit));
}

static int build_outputs(const struct hdn_status *status, const char *source,
			 bool raw, bool compat, struct hdn_outputs *outputs)
{
	unsigned long long audit_last_action;
	unsigned long long audit_last_authority;
	unsigned long long audit_last_transition;
	unsigned long long audit_last_reason;
	unsigned long long audit_suppressed;
	unsigned long long rule_count;
	unsigned int mitigation_known;
	unsigned int mitigation_enabled;
	const char *attention;
	unsigned int i;
	int ret;

	memset(outputs, 0, sizeof(*outputs));
	count_mitigations(status, &mitigation_known, &mitigation_enabled);

	audit_suppressed = status_u64_default(status,
					      "audit_flood_suppressed_total",
					      0);
	audit_last_action = status_u64_default(status,
					       "audit_flood_last_action", 0);
	audit_last_authority = status_u64_default(status,
						  "audit_flood_last_authority",
						  0);
	audit_last_transition = status_u64_default(status,
						   "audit_flood_last_transition",
						   0);
	audit_last_reason = status_u64_default(status,
					       "audit_flood_last_reason", 0);
	rule_count = status_u64_default(status, "subject_rule_count", 0) +
		     status_u64_default(status, "object_rule_count", 0) +
		     status_u64_default(status, "exec_rule_count", 0) +
		     status_u64_default(status, "module_rule_count", 0) +
		     status_u64_default(status, "firmware_rule_count", 0) +
		     status_u64_default(status, "resource_rule_count", 0);
	attention = attention_reason(status);

	ret = output_add(outputs, "HDN_STATUS_V1", "1");
	if (ret)
		return ret;
	ret = output_add(outputs, "source", "%s", source);
	if (ret)
		return ret;
	ret = output_add(outputs, "available", "1");
	if (ret)
		return ret;
	ret = output_add(outputs, "state", "%s", state_name(status, attention));
	if (ret)
		return ret;
	ret = output_add(outputs, "attention", "%u",
			 strcmp(attention, "none") ? 1 : 0);
	if (ret)
		return ret;
	ret = output_add(outputs, "attention_reason", "%s", attention);
	if (ret)
		return ret;

	ret = output_status_value(outputs, status, "phase", "unknown");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "phase_id", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "policy_loaded", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "policy_staged", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "policy_sealed", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "rollback_available", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "generation", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "expected_generation", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "profile_count", "0");
	if (ret)
		return ret;
	ret = output_add(outputs, "rule_count", "%llu", rule_count);
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "current_profile", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "current_mntns_profile", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status,
				  "current_exec_memory_flags", "0x0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "mitigations_sealed", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernexec_cpa_state", "unknown");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernexec_cpa_wx", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernexec_static_alias_guard", "unknown");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernexec_text_windows", "unknown");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernexec_text_started", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernexec_text_completed", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernexec_text_rejected", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernexec_text_active", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernexec_deferred_kernel_overflow", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernexec_deferred_kernel_events", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernexec_gdt", "unknown");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "latent_entropy_mixing", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernexec_private_allocations", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernexec_allocations", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernexec_owned_pages", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernexec_finalized", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernexec_retired", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernexec_failed_retirements", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernseal_typed_objects", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernseal_state", "disabled");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernseal_allocations", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernseal_live_objects", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernseal_live_pages", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernseal_live_payload_bytes", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernseal_live_granule_bytes", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernseal_fragmentation_bytes", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernseal_seal_operations", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernseal_publications", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernseal_replacements", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernseal_retirements", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernseal_discards", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernseal_rejections", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernseal_allocation_failures", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernseal_replacement_total_ns", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kernseal_replacement_max_ns", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "autoslab_state", "disabled");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "autoslab_metadata_version", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "autoslab_cache_budget", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "autoslab_caches", "0");
	if (ret)
		return ret;
	{
		static const char *const fields[] = {
			"autoslab_typed", "autoslab_successful", "autoslab_failed",
			"autoslab_mandatory", "autoslab_early", "autoslab_rejected",
		};

		for (size_t i = 0; i < ARRAY_SIZE(fields); i++) {
			ret = output_status_value(outputs, status, fields[i], "unavailable");
			if (ret)
				return ret;
		}
	}
	ret = output_status_value(outputs, status, "initify_image_aliases", "unknown");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "initify_reclaimed_bytes", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "static_lifetime_analysis", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "constify_state", "unknown");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "constify_test_interface", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "rap_state", "unknown");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "rap_metadata_version", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "rap_transfer_abi", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "rap_failure_classes", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "rap_build_identity", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "rap_xor_state", "disabled");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "private_stacks_state", "unknown");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "private_stacks_test_interface", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "kvm_state_test_interface", "0");
	if (ret)
		return ret;
	{
		static const char *const fields[] = {
			"private_stacks_allocation_attempts",
			"private_stacks_allocations",
			"private_stacks_allocation_failures",
			"private_stacks_live",
			"private_stacks_publications",
			"private_stacks_retirements",
			"private_stacks_diagnostic_reads",
			"private_stacks_diagnostic_read_failures",
			"private_stacks_construction_bytes",
			"private_stacks_task_switches",
			"private_stacks_async_root_entries",
		};

		for (size_t i = 0; i < ARRAY_SIZE(fields); i++) {
			ret = output_status_value(outputs, status, fields[i], "unavailable");
			if (ret)
				return ret;
		}
	}
	ret = output_status_value(outputs, status, "rap_error_test_interface", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "rap_test_interface", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "respectre_state", "unknown");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "respectre_coverage", "unknown");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "respectre_report_schema", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "respectre_analyzer_version", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "respectre_compiler_abi", "none");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "respectre_store_bypass", "disabled");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "respectre_test_interface", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "capability_version", "unknown");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "capability_architecture", "unknown");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "capability_required_mask", "0x0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "capability_requirements", "unknown");
	if (ret)
		return ret;
#define HDN_CAP_STATUS(symbol, name) \
	ret = output_status_value(outputs, status, "capability." #name, "undeclared,none"); \
	if (ret) \
		return ret;
	HDN_CAPABILITY_LIST(HDN_CAP_STATUS)
#undef HDN_CAP_STATUS
	ret = output_status_value(outputs, status, "sysfs_visibility_version", "unknown");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "sysfs_discovery_view", "unknown");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "uderef_state", "unknown");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "uderef_build_id", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "uderef_site_scheme", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "uderef_smap_repairs", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "bpf_execmem_state", "disabled");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "bpf_execmem_test_interface", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "bpf_execmem_capacity_bytes", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "bpf_execmem_live_pages", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "bpf_execmem_quarantined_pages", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "bpf_execmem_failed_retirements", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "bpf_execmem_quarantine_limit_pages", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "bpf_execmem_quarantine_pressure_releases", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "bpf_execmem_allocation_attempts", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "bpf_execmem_allocation_successes", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "bpf_execmem_allocation_failures", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "bpf_execmem_requested_bytes", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "bpf_execmem_reserved_bytes", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "bpf_execmem_internal_slack_bytes", "unavailable");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "slab_layout_state", "unknown");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "slab_layout_test_interface", "0");
	if (ret)
		return ret;
	{
		static const char *const fields[] = {
			"kernexec_idt", "kernexec_ldt", "kernexec_page_tables",
			"kernexec_firmware_wx", "kernexec_terminal_handoff",
			"kernexec_page_table_allocations", "kernexec_page_table_retirements",
			"kernexec_page_table_owned_pages", "kernexec_page_table_reserve_pages",
			"kernexec_page_table_allocation_failures",
			"kernexec_foreign_code_ranges", "kernexec_foreign_code_pages",
			"compatibility_intent_version", "compatibility_binding_version",
			"application_compatibility", "application_remediation", "legacy_emulation",
			"autoslab_state", "autoslab_metadata_version", "autoslab_cache_budget",
			"autoslab_caches", "autoslab_typed", "autoslab_successful",
			"autoslab_failed", "autoslab_mandatory",
			"autoslab_early", "autoslab_rejected",
			"critical_jitter_state", "critical_jitter_metadata_version",
			"critical_jitter_classes", "critical_jitter_placement_slots",
			"critical_jitter_queue_limit_per_class", "critical_jitter_allocations",
			"critical_jitter_allocation_failures",
			"critical_jitter_retired", "critical_jitter_released",
			"critical_jitter_quarantined", "critical_jitter_pressure",
			"critical_jitter_early_live", "critical_jitter_failures",
			"critical_jitter_cred_allocations", "critical_jitter_cred_retired",
			"critical_jitter_cred_allocation_failures",
			"critical_jitter_cred_released", "critical_jitter_cred_quarantined",
			"critical_jitter_cred_pressure", "critical_jitter_file_allocations",
			"critical_jitter_file_allocation_failures",
			"critical_jitter_file_retired", "critical_jitter_file_released",
			"critical_jitter_file_quarantined", "critical_jitter_file_pressure",
			"critical_jitter_backing_file_allocations",
			"critical_jitter_backing_file_allocation_failures",
			"critical_jitter_backing_file_retired",
			"critical_jitter_backing_file_released",
			"critical_jitter_backing_file_quarantined",
			"critical_jitter_backing_file_pressure",
		};
		for (size_t i = 0; i < ARRAY_SIZE(fields); i++) {
			ret = output_status_value(outputs, status, fields[i], "unavailable");
			if (ret)
				return ret;
		}
	}
	if (ret)
		return ret;
	{
		static const char *const fields[] = {
			"slab_layout_allocation_attempts",
			"slab_layout_allocation_failures",
			"slab_layout_slabs", "slab_layout_fallbacks",
			"slab_layout_no_offset_room", "slab_layout_offset_slabs",
			"slab_layout_offset_bytes", "slab_layout_original_objects",
			"slab_layout_placed_objects", "slab_layout_displaced_objects",
		};

		for (size_t i = 0; i < ARRAY_SIZE(fields); i++) {
			ret = output_status_value(outputs, status, fields[i], "unavailable");
			if (ret)
				return ret;
		}
	}
	ret = output_status_value(outputs, status, "latent_entropy_credited_bits", "0");
	if (ret)
		return ret;
	ret = output_status_value(outputs, status, "latent_entropy_test_interface", "0");
	if (ret)
		return ret;
	ret = output_add(outputs, "mitigation_known", "%u", mitigation_known);
	if (ret)
		return ret;
	ret = output_add(outputs, "mitigation_enabled", "%u",
			 mitigation_enabled);
	if (ret)
		return ret;
	ret = output_status_value(outputs, status,
				  "mitigation_audit_flood_control", "0");
	if (ret)
		return ret;

	ret = output_add(outputs, "audit_flood_suppressed_total", "%llu",
			 audit_suppressed);
	if (ret)
		return ret;
	ret = output_add(outputs, "audit_flood_active", "%u",
			 audit_suppressed ? 1 : 0);
	if (ret)
		return ret;
	ret = output_add(outputs, "audit_flood_last_action_id", "%llu",
			 audit_last_action);
	if (ret)
		return ret;
	ret = output_add(outputs, "audit_flood_last_action", "%s",
			 lookup_name(action_names, ARRAY_SIZE(action_names),
				     audit_last_action));
	if (ret)
		return ret;
	ret = output_add(outputs, "audit_flood_last_authority_id", "%llu",
			 audit_last_authority);
	if (ret)
		return ret;
	ret = output_add(outputs, "audit_flood_last_authority", "%s",
			 lookup_name(authority_names,
				     ARRAY_SIZE(authority_names),
				     audit_last_authority));
	if (ret)
		return ret;
	ret = output_add(outputs, "audit_flood_last_transition_id", "%llu",
			 audit_last_transition);
	if (ret)
		return ret;
	ret = output_add(outputs, "audit_flood_last_transition", "%s",
			 lookup_name(transition_names,
				     ARRAY_SIZE(transition_names),
				     audit_last_transition));
	if (ret)
		return ret;
	ret = output_add(outputs, "audit_flood_last_reason_id", "%llu",
			 audit_last_reason);
	if (ret)
		return ret;
	ret = output_add(outputs, "audit_flood_last_reason", "%s",
			 lookup_name(reason_names, ARRAY_SIZE(reason_names),
				     audit_last_reason));
	if (ret)
		return ret;

	if (compat) {
		ret = build_compat_outputs(status, outputs);
		if (ret)
			return ret;
	}

	if (!raw)
		return 0;

	for (i = 0; i < status->count; i++) {
		char raw_key[80];

		ret = snprintf(raw_key, sizeof(raw_key), "raw_%s",
			       status->entries[i].key);
		if (ret < 0 || (size_t)ret >= sizeof(raw_key))
			return -E2BIG;
		ret = output_add(outputs, raw_key, "%s",
				 status->entries[i].value);
		if (ret)
			return ret;
	}

	return 0;
}

static const char *output_value(const struct hdn_outputs *outputs,
				const char *key)
{
	unsigned int i;

	for (i = 0; i < outputs->count; i++) {
		if (!strcmp(outputs->values[i].key, key))
			return outputs->values[i].value;
	}

	return NULL;
}

static int parse_expectation(const char *text, struct hdn_expectation *expect)
{
	char *copy;
	char *equals;

	copy = strdup(text);
	if (!copy)
		return -ENOMEM;

	equals = strchr(copy, '=');
	if (!equals) {
		free(copy);
		return -EINVAL;
	}
	*equals = '\0';
	if (!valid_key(copy) || !equals[1]) {
		free(copy);
		return -EINVAL;
	}

	expect->key = copy;
	expect->value = equals + 1;
	return 0;
}

static void free_expectations(struct hdn_expectation *expectations,
			      unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count; i++)
		free(expectations[i].key);
}

static bool expectations_match(const struct hdn_outputs *outputs,
			       const struct hdn_expectation *expectations,
			       unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count; i++) {
		const char *actual = output_value(outputs, expectations[i].key);

		if (actual && !strcmp(actual, expectations[i].value))
			continue;

		fprintf(stderr,
			"hdn-status: expectation failed: %s=%s",
			expectations[i].key, expectations[i].value);
		if (actual)
			fprintf(stderr, " (actual %s)\n", actual);
		else
			fprintf(stderr, " (missing)\n");
		return false;
	}

	return true;
}

static void print_outputs(const struct hdn_outputs *outputs)
{
	unsigned int i;

	for (i = 0; i < outputs->count; i++)
		printf("%s=%s\n", outputs->values[i].key,
		       outputs->values[i].value);
}

int main(int argc, char **argv)
{
	struct hdn_expectation expectations[HDN_STATUS_MAX_EXPECTATIONS];
	unsigned int expectation_count = 0;
	struct hdn_outputs outputs;
	struct hdn_status status;
	const char *status_path = HDN_STATUS_PATH;
	bool quiet = false;
	bool compat = false;
	bool raw = false;
	int ret;
	int i;

	memset(expectations, 0, sizeof(expectations));

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--help")) {
			usage(argv[0]);
			return 0;
		}
		if (!strcmp(argv[i], "--status-path")) {
			if (++i >= argc)
				goto bad_args;
			status_path = argv[i];
			continue;
		}
		if (!strcmp(argv[i], "--raw")) {
			raw = true;
			continue;
		}
		if (!strcmp(argv[i], "--compat")) {
			compat = true;
			continue;
		}
		if (!strcmp(argv[i], "--quiet")) {
			quiet = true;
			continue;
		}
		if (!strcmp(argv[i], "--expect")) {
			if (++i >= argc ||
			    expectation_count >= HDN_STATUS_MAX_EXPECTATIONS)
				goto bad_args;
			if (parse_expectation(argv[i],
					      &expectations[expectation_count]))
				goto bad_args;
			expectation_count++;
			continue;
		}
		goto bad_args;
	}

	ret = read_status_file(status_path, &status);
	if (ret) {
		free_expectations(expectations, expectation_count);
		return 2;
	}

	ret = build_outputs(&status, status_path, raw, compat, &outputs);
	if (ret) {
		free_status(&status);
		free_expectations(expectations, expectation_count);
		return 2;
	}

	if (!quiet)
		print_outputs(&outputs);

	ret = 0;
	if (expectation_count &&
	    !expectations_match(&outputs, expectations, expectation_count))
		ret = 1;

	free_status(&status);
	free_expectations(expectations, expectation_count);
	return ret;

bad_args:
	usage(argv[0]);
	free_expectations(expectations, expectation_count);
	return 2;
}
