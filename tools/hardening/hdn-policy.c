// SPDX-License-Identifier: GPL-2.0-only

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#ifndef __user
#define __user
#endif
#include <linux/capability.h>
#include <linux/fsverity.h>
#include <linux/hardening.h>

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define HDN_VERITY_DIGEST_MAX \
	sizeof(((struct hdn_exec_rule_record *)0)->verity_digest)
#define HDN_ROLE_NAME_LEN 64
#define HDN_MAX_ROLES 128
#define HDN_MAX_ROLE_USES 512
#define HDN_MAX_ROLE_INCLUDES 512

struct hdn_profile_builder {
	struct hdn_profile_record record;
	bool present;
};

struct hdn_role_builder {
	uint64_t authority_allow;
	uint64_t authority_allow_hi;
	uint64_t authority_audit;
	uint64_t authority_audit_hi;
	uint64_t memory_flags;
	uint64_t flags;
	uint64_t capability_deny;
	uint64_t capability_audit;
	char name[HDN_ROLE_NAME_LEN];
	bool present;
	unsigned int visit_state;
};

struct hdn_role_use {
	uint64_t profile_id;
	unsigned int line;
	char role_name[HDN_ROLE_NAME_LEN];
};

struct hdn_role_include {
	unsigned int line;
	char role_name[HDN_ROLE_NAME_LEN];
	char parent_name[HDN_ROLE_NAME_LEN];
};

struct hdn_policy_builder {
	struct hdn_profile_builder profiles[HDN_MAX_PROFILES];
	struct hdn_role_builder roles[HDN_MAX_ROLES];
	struct hdn_role_use role_uses[HDN_MAX_ROLE_USES];
	struct hdn_role_include role_includes[HDN_MAX_ROLE_INCLUDES];
	struct hdn_subject_rule_record subject_rules[HDN_MAX_SUBJECT_RULES];
	struct hdn_object_rule_record object_rules[HDN_MAX_OBJECT_RULES];
	struct hdn_exec_rule_record exec_rules[HDN_MAX_EXEC_RULES];
	struct hdn_module_rule_record module_rules[HDN_MAX_MODULE_RULES];
	struct hdn_firmware_rule_record firmware_rules[HDN_MAX_FIRMWARE_RULES];
	struct hdn_resource_rule_record resource_rules[HDN_MAX_RESOURCE_RULES];
	uint32_t role_use_count;
	uint32_t role_include_count;
	uint32_t subject_rule_count;
	uint32_t object_rule_count;
	uint32_t exec_rule_count;
	uint32_t module_rule_count;
	uint32_t firmware_rule_count;
	uint32_t resource_rule_count;
};

struct name_value {
	const char *name;
	uint64_t value;
};

static const struct name_value authority_names[] = {
	{ "EXEC", HDN_AUTH_EXEC },
	{ "MMAP", HDN_AUTH_MMAP },
	{ "MPROTECT", HDN_AUTH_MPROTECT },
	{ "BPF_LOAD", HDN_AUTH_BPF_LOAD },
	{ "PERF_OPEN", HDN_AUTH_PERF_OPEN },
	{ "USERNS_CREATE", HDN_AUTH_USERNS_CREATE },
	{ "MODULE_LOAD", HDN_AUTH_MODULE_LOAD },
	{ "MODULE_AUTOLOAD", HDN_AUTH_MODULE_AUTOLOAD },
	{ "PTRACE", HDN_AUTH_PTRACE },
	{ "PTRACE_EXEC_READ", HDN_AUTH_PTRACE_EXEC_READ },
	{ "PROC_DISCLOSE", HDN_AUTH_PROC_DISCLOSE },
	{ "DEBUGFS", HDN_AUTH_DEBUGFS },
	{ "SYSFS_MUTATE", HDN_AUTH_SYSFS_MUTATE },
	{ "SYSFS_READ", HDN_AUTH_SYSFS_READ },
	{ "KEXEC_LOAD", HDN_AUTH_KEXEC_LOAD },
	{ "FIRMWARE_LOAD", HDN_AUTH_FIRMWARE_LOAD },
	{ "IO_URING_RESTRICTED_OP", HDN_AUTH_IO_URING_RESTRICTED_OP },
	{ "KERNEL_LOG_READ", HDN_AUTH_KERNEL_LOG_READ },
	{ "KERNEL_LOG_WRITE", HDN_AUTH_KERNEL_LOG_WRITE },
	{ "RAW_IO", HDN_AUTH_RAW_IO },
	{ "MOUNT_ADMIN", HDN_AUTH_MOUNT_ADMIN },
	{ "POLICY_ADMIN", HDN_AUTH_POLICY_ADMIN },
	{ "NAMESPACE_ADMIN", HDN_AUTH_NAMESPACE_ADMIN },
	{ "CRED_CHANGE", HDN_AUTH_CRED_CHANGE },
	{ "CHROOT_ADMIN", HDN_AUTH_CHROOT_ADMIN },
	{ "TRUSTED_EXEC_BYPASS", HDN_AUTH_TRUSTED_EXEC_BYPASS },
	{ "IPC_ADMIN", HDN_AUTH_IPC_ADMIN },
	{ "TTY_INJECT", HDN_AUTH_TTY_INJECT },
	{ "TTY_ACCESS", HDN_AUTH_TTY_ACCESS },
	{ "FUSE_MOUNT", HDN_AUTH_FUSE_MOUNT },
	{ "ROFS_RELAX", HDN_AUTH_ROFS_RELAX },
	{ "USB_ATTACH", HDN_AUTH_USB_ATTACH },
	{ "USB_MONITOR", HDN_AUTH_USB_MONITOR },
	{ "SOCKET_CREATE", HDN_AUTH_SOCKET_CREATE },
	{ "SOCKET_CONNECT", HDN_AUTH_SOCKET_CONNECT },
	{ "SOCKET_SERVER", HDN_AUTH_SOCKET_SERVER },
	{ "PROC_TASK_VIEW", HDN_AUTH_PROC_TASK_VIEW },
	{ "TIME_ADMIN", HDN_AUTH_TIME_ADMIN },
	{ "RESOURCE_ADMIN", HDN_AUTH_RESOURCE_ADMIN },
	{ "BLOCK_DEVICE_ACCESS", HDN_AUTH_BLOCK_DEVICE_ACCESS },
	{ "BLOCK_DEVICE_ADMIN", HDN_AUTH_BLOCK_DEVICE_ADMIN },
	{ "SIGNAL", HDN_AUTH_SIGNAL },
	{ "PROCESS_MEMORY", HDN_AUTH_PROCESS_MEMORY },
	{ "MEMORY_MIGRATE", HDN_AUTH_MEMORY_MIGRATE },
	{ "PROCESS_FD", HDN_AUTH_PROCESS_FD },
};

static const struct name_value capability_names[] = {
	{ "CAP_CHOWN", CAP_CHOWN },
	{ "CAP_DAC_OVERRIDE", CAP_DAC_OVERRIDE },
	{ "CAP_DAC_READ_SEARCH", CAP_DAC_READ_SEARCH },
	{ "CAP_FOWNER", CAP_FOWNER },
	{ "CAP_FSETID", CAP_FSETID },
	{ "CAP_KILL", CAP_KILL },
	{ "CAP_SETGID", CAP_SETGID },
	{ "CAP_SETUID", CAP_SETUID },
	{ "CAP_SETPCAP", CAP_SETPCAP },
	{ "CAP_LINUX_IMMUTABLE", CAP_LINUX_IMMUTABLE },
	{ "CAP_NET_BIND_SERVICE", CAP_NET_BIND_SERVICE },
	{ "CAP_NET_BROADCAST", CAP_NET_BROADCAST },
	{ "CAP_NET_ADMIN", CAP_NET_ADMIN },
	{ "CAP_NET_RAW", CAP_NET_RAW },
	{ "CAP_IPC_LOCK", CAP_IPC_LOCK },
	{ "CAP_IPC_OWNER", CAP_IPC_OWNER },
	{ "CAP_SYS_MODULE", CAP_SYS_MODULE },
	{ "CAP_SYS_RAWIO", CAP_SYS_RAWIO },
	{ "CAP_SYS_CHROOT", CAP_SYS_CHROOT },
	{ "CAP_SYS_PTRACE", CAP_SYS_PTRACE },
	{ "CAP_SYS_PACCT", CAP_SYS_PACCT },
	{ "CAP_SYS_ADMIN", CAP_SYS_ADMIN },
	{ "CAP_SYS_BOOT", CAP_SYS_BOOT },
	{ "CAP_SYS_NICE", CAP_SYS_NICE },
	{ "CAP_SYS_RESOURCE", CAP_SYS_RESOURCE },
	{ "CAP_SYS_TIME", CAP_SYS_TIME },
	{ "CAP_SYS_TTY_CONFIG", CAP_SYS_TTY_CONFIG },
	{ "CAP_MKNOD", CAP_MKNOD },
	{ "CAP_LEASE", CAP_LEASE },
	{ "CAP_AUDIT_WRITE", CAP_AUDIT_WRITE },
	{ "CAP_AUDIT_CONTROL", CAP_AUDIT_CONTROL },
	{ "CAP_SETFCAP", CAP_SETFCAP },
	{ "CAP_MAC_OVERRIDE", CAP_MAC_OVERRIDE },
	{ "CAP_MAC_ADMIN", CAP_MAC_ADMIN },
	{ "CAP_SYSLOG", CAP_SYSLOG },
	{ "CAP_WAKE_ALARM", CAP_WAKE_ALARM },
	{ "CAP_BLOCK_SUSPEND", CAP_BLOCK_SUSPEND },
	{ "CAP_AUDIT_READ", CAP_AUDIT_READ },
	{ "CAP_PERFMON", CAP_PERFMON },
	{ "CAP_BPF", CAP_BPF },
	{ "CAP_CHECKPOINT_RESTORE", CAP_CHECKPOINT_RESTORE },
};

static const struct name_value memory_flag_names[] = {
	{ "ALLOW_WX", HDN_MEM_ALLOW_WX },
	{ "ALLOW_EXEC_AFTER_WRITE", HDN_MEM_ALLOW_EXEC_AFTER_WRITE },
	{ "ALLOW_FIXED_ANON_EXEC", HDN_MEM_ALLOW_FIXED_ANON_EXEC },
	{ "ALLOW_READ_IMPLIES_EXEC", HDN_MEM_ALLOW_READ_IMPLIES_EXEC },
	{ "ALLOW_JIT_EXEC_AFTER_WRITE", HDN_MEM_ALLOW_JIT_EXEC_AFTER_WRITE },
	{ "ALLOW_EXEC_STACK_ELF", HDN_MEM_ALLOW_EXEC_STACK_ELF },
	{ "ALLOW_TEXTREL_MPROTECT", HDN_MEM_ALLOW_TEXTREL_MPROTECT },
	{ "ALLOW_RELRO_WRITE", HDN_MEM_ALLOW_RELRO_WRITE },
};

static const struct name_value profile_flag_names[] = {
	{ "KILL_DENY", HDN_PROFILE_RESPONSE_KILL_DENY },
	{ "KILL_MEMORY", HDN_PROFILE_RESPONSE_KILL_MEMORY },
	{ "KILL_KERNEL_SURFACE", HDN_PROFILE_RESPONSE_KILL_KERNEL_SURFACE },
	{ "ENFORCE_TRUSTED_EXEC", HDN_PROFILE_ENFORCE_TRUSTED_EXEC },
	{ "CHROOT_CONTAINED", HDN_PROFILE_CHROOT_CONTAINED },
	{ "DENY_UNPRIVILEGED_PRIVEXEC",
	  HDN_PROFILE_DENY_UNPRIVILEGED_PRIVEXEC },
	{ "ENFORCE_READONLY_MOUNTS",
	  HDN_PROFILE_ENFORCE_READONLY_MOUNTS },
	{ "DENY_UNTRUSTED_USER_EXEC",
	  HDN_PROFILE_DENY_UNTRUSTED_USER_EXEC },
	{ "AUDIT_PROCESS_ACCOUNT",
	  HDN_PROFILE_AUDIT_PROCESS_ACCOUNT },
	{ "PROTECT_SHM", HDN_PROFILE_PROTECT_SHM },
	{ "INHERIT_UNMATCHED_EXEC", HDN_PROFILE_INHERIT_UNMATCHED_EXEC },
};

static const struct name_value resource_names[] = {
	{ "CPU", RLIMIT_CPU },
	{ "FSIZE", RLIMIT_FSIZE },
	{ "DATA", RLIMIT_DATA },
	{ "STACK", RLIMIT_STACK },
	{ "CORE", RLIMIT_CORE },
	{ "RSS", RLIMIT_RSS },
	{ "NPROC", RLIMIT_NPROC },
	{ "NOFILE", RLIMIT_NOFILE },
	{ "MEMLOCK", RLIMIT_MEMLOCK },
	{ "AS", RLIMIT_AS },
	{ "LOCKS", RLIMIT_LOCKS },
	{ "SIGPENDING", RLIMIT_SIGPENDING },
	{ "MSGQUEUE", RLIMIT_MSGQUEUE },
	{ "NICE", RLIMIT_NICE },
	{ "RTPRIO", RLIMIT_RTPRIO },
	{ "RTTIME", RLIMIT_RTTIME },
};

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s INPUT.policy OUTPUT.hdn\n", prog);
}

static void normalize_token(const char *input, char *output, size_t size)
{
	size_t i;

	for (i = 0; i + 1 < size && input[i]; i++) {
		unsigned char c = input[i];

		if (c == '-')
			output[i] = '_';
		else
			output[i] = (char)toupper(c);
	}

	output[i] = '\0';

	if (!strncmp(output, "HDN_AUTH_", 9))
		memmove(output, output + 9, strlen(output + 9) + 1);
	else if (!strncmp(output, "AUTH_", 5))
		memmove(output, output + 5, strlen(output + 5) + 1);
	else if (!strncmp(output, "HDN_MEM_", 8))
		memmove(output, output + 8, strlen(output + 8) + 1);
	else if (!strncmp(output, "MEM_", 4))
		memmove(output, output + 4, strlen(output + 4) + 1);
	else if (!strncmp(output, "HDN_PROFILE_", 12))
		memmove(output, output + 12, strlen(output + 12) + 1);
	else if (!strncmp(output, "PROFILE_", 8))
		memmove(output, output + 8, strlen(output + 8) + 1);

	if (!strncmp(output, "RESPONSE_", 9))
		memmove(output, output + 9, strlen(output + 9) + 1);
}

static int parse_u64(const char *text, uint64_t *value)
{
	char *end;
	unsigned long long parsed;

	errno = 0;
	parsed = strtoull(text, &end, 0);
	if (errno || *end)
		return -EINVAL;

	*value = parsed;
	return 0;
}

static int lookup_name(const struct name_value *names, size_t count,
		       const char *text, uint64_t *value)
{
	char normalized[64];
	size_t i;

	normalize_token(text, normalized, sizeof(normalized));
	for (i = 0; i < count; i++) {
		if (!strcmp(normalized, names[i].name)) {
			*value = names[i].value;
			return 0;
		}
	}

	return -ENOENT;
}

static struct hdn_profile_builder *
find_profile(struct hdn_profile_builder *profiles, uint64_t id)
{
	size_t i;

	for (i = 0; i < HDN_MAX_PROFILES; i++) {
		if (profiles[i].present && profiles[i].record.profile_id == id)
			return &profiles[i];
	}

	return NULL;
}

static struct hdn_role_builder *
find_role(struct hdn_role_builder *roles, const char *name)
{
	size_t i;

	for (i = 0; i < HDN_MAX_ROLES; i++) {
		if (roles[i].present && !strcmp(roles[i].name, name))
			return &roles[i];
	}

	return NULL;
}

static int find_role_index(struct hdn_role_builder *roles, const char *name)
{
	size_t i;

	for (i = 0; i < HDN_MAX_ROLES; i++) {
		if (roles[i].present && !strcmp(roles[i].name, name))
			return (int)i;
	}

	return -ENOENT;
}

static struct hdn_role_builder *
get_role(struct hdn_role_builder *roles, const char *name)
{
	struct hdn_role_builder *role;
	size_t i;

	if (!name || strlen(name) >= HDN_ROLE_NAME_LEN)
		return NULL;

	role = find_role(roles, name);
	if (role)
		return role;

	for (i = 0; i < HDN_MAX_ROLES; i++) {
		if (!roles[i].present) {
			role = &roles[i];
			memset(role, 0, sizeof(*role));
			snprintf(role->name, sizeof(role->name), "%s", name);
			role->present = true;
			return role;
		}
	}

	return NULL;
}

static int add_profile(struct hdn_profile_builder *profiles, uint64_t id,
		       const char *name)
{
	struct hdn_profile_builder *profile;
	size_t i;

	if (!id)
		return -EINVAL;
	if (strlen(name) >= HDN_PROFILE_NAME_LEN)
		return -ENAMETOOLONG;
	if (find_profile(profiles, id))
		return -EEXIST;

	for (i = 0; i < HDN_MAX_PROFILES; i++) {
		if (!profiles[i].present) {
			profile = &profiles[i];
			memset(profile, 0, sizeof(*profile));
			profile->record.profile_id = id;
			snprintf(profile->record.name,
				 sizeof(profile->record.name), "%s", name);
			profile->present = true;
			return 0;
		}
	}

	return -ENOSPC;
}

static int parse_profile_command(struct hdn_profile_builder *profiles,
				 char *save, unsigned int line)
{
	char *id_text;
	char *name;
	uint64_t id;
	int ret;

	id_text = strtok_r(NULL, " \t\r\n", &save);
	name = strtok_r(NULL, " \t\r\n", &save);
	if (!id_text || !name) {
		fprintf(stderr, "%u: profile needs ID and name\n", line);
		return -EINVAL;
	}

	ret = parse_u64(id_text, &id);
	if (ret) {
		fprintf(stderr, "%u: invalid profile ID '%s'\n", line,
			id_text);
		return ret;
	}

	ret = add_profile(profiles, id, name);
	if (ret) {
		fprintf(stderr, "%u: could not add profile '%s': %s\n", line,
			name, strerror(-ret));
		return ret;
	}

	return 0;
}

static int add_authority_mask(uint64_t authority, uint64_t *mask,
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

static int parse_authority_tokens(uint64_t *mask, uint64_t *mask_hi,
				  char *name, char **save,
				  unsigned int line, const char *command)
{
	if (!name) {
		fprintf(stderr, "%u: %s needs at least one authority\n", line,
			command);
		return -EINVAL;
	}

	while (name) {
		uint64_t authority;
		int ret;

		ret = lookup_name(authority_names, ARRAY_SIZE(authority_names),
				  name, &authority);
		if (ret) {
			fprintf(stderr, "%u: unknown authority '%s'\n", line,
				name);
			return ret;
		}

		ret = add_authority_mask(authority, mask, mask_hi);
		if (ret) {
			fprintf(stderr, "%u: invalid authority '%s'\n", line,
				name);
			return ret;
		}
		name = strtok_r(NULL, " \t\r\n", save);
	}

	return 0;
}

static int parse_memory_tokens(uint64_t *mask, char *name, char **save,
			       unsigned int line, const char *command)
{
	if (!name) {
		fprintf(stderr, "%u: %s needs at least one flag\n", line,
			command);
		return -EINVAL;
	}

	while (name) {
		uint64_t flag;
		int ret;

		ret = lookup_name(memory_flag_names,
				  ARRAY_SIZE(memory_flag_names), name, &flag);
		if (ret) {
			fprintf(stderr, "%u: unknown memory flag '%s'\n", line,
				name);
			return ret;
		}

		*mask |= flag;
		name = strtok_r(NULL, " \t\r\n", save);
	}

	return 0;
}

static int parse_profile_flag_tokens(uint64_t *mask, char *name, char **save,
				     unsigned int line, const char *command)
{
	if (!name) {
		fprintf(stderr, "%u: %s needs at least one flag\n", line,
			command);
		return -EINVAL;
	}

	while (name) {
		uint64_t flag;
		int ret;

		ret = lookup_name(profile_flag_names,
				  ARRAY_SIZE(profile_flag_names), name, &flag);
		if (ret) {
			fprintf(stderr, "%u: unknown profile flag '%s'\n",
				line, name);
			return ret;
		}

		*mask |= flag;
		name = strtok_r(NULL, " \t\r\n", save);
	}

	return 0;
}

static int parse_capability_tokens(uint64_t *mask, char *name, char **save,
				   unsigned int line, const char *command)
{
	if (!name) {
		fprintf(stderr, "%u: %s needs at least one capability\n", line,
			command);
		return -EINVAL;
	}

	while (name) {
		uint64_t capability;
		int ret;

		ret = lookup_name(capability_names, ARRAY_SIZE(capability_names),
				  name, &capability);
		if (ret)
			ret = parse_u64(name, &capability);
		if (ret || capability > CAP_LAST_CAP) {
			fprintf(stderr, "%u: unknown capability '%s'\n", line, name);
			return ret ? ret : -EINVAL;
		}

		*mask |= 1ULL << capability;
		name = strtok_r(NULL, " \t\r\n", save);
	}

	return 0;
}

static int parse_capability_command(struct hdn_profile_builder *profiles,
				    char *save, unsigned int line, bool audit)
{
	struct hdn_profile_builder *profile;
	char *id_text;
	char *name;
	uint64_t mask = 0;
	uint64_t id;
	int ret;

	id_text = strtok_r(NULL, " \t\r\n", &save);
	if (!id_text) {
		fprintf(stderr, "%u: capability command needs profile ID\n", line);
		return -EINVAL;
	}

	ret = parse_u64(id_text, &id);
	if (ret) {
		fprintf(stderr, "%u: invalid capability profile ID '%s'\n", line,
			id_text);
		return ret;
	}

	profile = find_profile(profiles, id);
	if (!profile) {
		fprintf(stderr, "%u: unknown capability profile %llu\n", line,
			(unsigned long long)id);
		return -ENOENT;
	}

	name = strtok_r(NULL, " \t\r\n", &save);
	ret = parse_capability_tokens(&mask, name, &save, line,
				      audit ? "capability-audit" :
				      "capability-deny");
	if (ret)
		return ret;

	if (audit)
		profile->record.capability_audit |= mask;
	else
		profile->record.capability_deny |= mask;

	return 0;
}

static int parse_mask_command(struct hdn_profile_builder *profiles, char *save,
			      unsigned int line, bool audit)
{
	struct hdn_profile_builder *profile;
	char *id_text;
	char *name;
	uint64_t mask = 0;
	uint64_t mask_hi = 0;
	uint64_t id;
	int ret;

	id_text = strtok_r(NULL, " \t\r\n", &save);
	if (!id_text) {
		fprintf(stderr, "%u: allow/audit needs profile ID\n", line);
		return -EINVAL;
	}

	ret = parse_u64(id_text, &id);
	if (ret) {
		fprintf(stderr, "%u: invalid profile ID '%s'\n", line,
			id_text);
		return ret;
	}

	profile = find_profile(profiles, id);
	if (!profile) {
		fprintf(stderr, "%u: unknown profile ID %llu\n", line,
			(unsigned long long)id);
		return -ENOENT;
	}

	name = strtok_r(NULL, " \t\r\n", &save);
	ret = parse_authority_tokens(&mask, &mask_hi, name, &save, line,
				     audit ? "audit" : "allow");
	if (ret)
		return ret;

	if (audit) {
		profile->record.authority_audit |= mask;
		profile->record.authority_audit_hi |= mask_hi;
	} else {
		profile->record.authority_allow |= mask;
		profile->record.authority_allow_hi |= mask_hi;
	}

	return 0;
}

static int parse_mem_command(struct hdn_profile_builder *profiles, char *save,
			     unsigned int line)
{
	struct hdn_profile_builder *profile;
	char *id_text;
	char *name;
	uint64_t mask = 0;
	uint64_t id;
	int ret;

	id_text = strtok_r(NULL, " \t\r\n", &save);
	if (!id_text) {
		fprintf(stderr, "%u: mem needs profile ID\n", line);
		return -EINVAL;
	}

	ret = parse_u64(id_text, &id);
	if (ret) {
		fprintf(stderr, "%u: invalid profile ID '%s'\n", line,
			id_text);
		return ret;
	}

	profile = find_profile(profiles, id);
	if (!profile) {
		fprintf(stderr, "%u: unknown profile ID %llu\n", line,
			(unsigned long long)id);
		return -ENOENT;
	}

	name = strtok_r(NULL, " \t\r\n", &save);
	ret = parse_memory_tokens(&mask, name, &save, line, "mem");
	if (ret)
		return ret;

	profile->record.memory_flags |= mask;
	return 0;
}

static int parse_profile_flag_command(struct hdn_profile_builder *profiles,
				      char *save, unsigned int line,
				      const char *command)
{
	struct hdn_profile_builder *profile;
	char *id_text;
	char *name;
	uint64_t mask = 0;
	uint64_t id;
	int ret;

	id_text = strtok_r(NULL, " \t\r\n", &save);
	if (!id_text) {
		fprintf(stderr, "%u: %s needs profile ID\n", line, command);
		return -EINVAL;
	}

	ret = parse_u64(id_text, &id);
	if (ret) {
		fprintf(stderr, "%u: invalid profile ID '%s'\n", line,
			id_text);
		return ret;
	}

	profile = find_profile(profiles, id);
	if (!profile) {
		fprintf(stderr, "%u: unknown profile ID %llu\n", line,
			(unsigned long long)id);
		return -ENOENT;
	}

	name = strtok_r(NULL, " \t\r\n", &save);
	ret = parse_profile_flag_tokens(&mask, name, &save, line, command);
	if (ret)
		return ret;

	profile->record.flags |= mask;
	return 0;
}

static int parse_umask_command(struct hdn_profile_builder *profiles,
			       char *save, unsigned int line)
{
	struct hdn_profile_builder *profile;
	char *id_text;
	char *mask_text;
	uint64_t mask;
	uint64_t id;
	int ret;

	id_text = strtok_r(NULL, " \t\r\n", &save);
	mask_text = strtok_r(NULL, " \t\r\n", &save);
	if (!id_text || !mask_text || strtok_r(NULL, " \t\r\n", &save)) {
		fprintf(stderr, "%u: umask needs PROFILE MASK\n", line);
		return -EINVAL;
	}

	ret = parse_u64(id_text, &id);
	if (ret) {
		fprintf(stderr, "%u: invalid umask profile ID '%s'\n", line,
			id_text);
		return ret;
	}

	ret = parse_u64(mask_text, &mask);
	if (ret || (mask & ~0777ULL)) {
		fprintf(stderr, "%u: invalid umask '%s'\n", line, mask_text);
		return ret ? ret : -EINVAL;
	}

	profile = find_profile(profiles, id);
	if (!profile) {
		fprintf(stderr, "%u: unknown umask profile %llu\n", line,
			(unsigned long long)id);
		return -ENOENT;
	}

	profile->record.umask = (uint16_t)mask;
	return 0;
}

static int parse_userns_max_command(struct hdn_profile_builder *profiles,
				    char *save, unsigned int line)
{
	struct hdn_profile_builder *profile;
	char *id_text;
	char *level_text;
	uint64_t level;
	uint64_t id;
	int ret;

	id_text = strtok_r(NULL, " \t\r\n", &save);
	level_text = strtok_r(NULL, " \t\r\n", &save);
	if (!id_text || !level_text || strtok_r(NULL, " \t\r\n", &save)) {
		fprintf(stderr, "%u: userns-max needs PROFILE LEVEL\n", line);
		return -EINVAL;
	}

	ret = parse_u64(id_text, &id);
	if (ret) {
		fprintf(stderr, "%u: invalid userns-max profile ID '%s'\n",
			line, id_text);
		return ret;
	}

	ret = parse_u64(level_text, &level);
	if (ret || level > 32) {
		fprintf(stderr, "%u: invalid userns-max level '%s'\n", line,
			level_text);
		return ret ? ret : -EINVAL;
	}

	profile = find_profile(profiles, id);
	if (!profile) {
		fprintf(stderr, "%u: unknown userns-max profile %llu\n", line,
			(unsigned long long)id);
		return -ENOENT;
	}

	profile->record.max_userns_level = (uint16_t)level;
	return 0;
}

static int parse_resource_id(const char *text, uint32_t *resource)
{
	uint64_t value;
	int ret;

	ret = lookup_name(resource_names, ARRAY_SIZE(resource_names), text,
			  &value);
	if (ret)
		ret = parse_u64(text, &value);
	if (ret)
		return ret;
	if (value >= RLIM_NLIMITS)
		return -EINVAL;

	*resource = (uint32_t)value;
	return 0;
}

static int parse_resource_limit(const char *text, uint64_t *limit)
{
	char normalized[64];

	normalize_token(text, normalized, sizeof(normalized));
	if (!strcmp(normalized, "INFINITY") ||
	    !strcmp(normalized, "UNLIMITED") ||
	    !strcmp(normalized, "RLIM_INFINITY")) {
		*limit = HDN_RESOURCE_LIMIT_INFINITY;
		return 0;
	}

	return parse_u64(text, limit);
}

static int parse_resource_command(struct hdn_policy_builder *builder,
				  char *save, unsigned int line)
{
	struct hdn_resource_rule_record *rule;
	char *profile_text;
	char *resource_text;
	char *soft_text;
	char *hard_text;
	uint64_t profile_id;
	uint64_t soft_limit;
	uint64_t hard_limit;
	uint32_t resource;
	int ret;

	if (builder->resource_rule_count >= HDN_MAX_RESOURCE_RULES)
		return -ENOSPC;

	profile_text = strtok_r(NULL, " \t\r\n", &save);
	resource_text = strtok_r(NULL, " \t\r\n", &save);
	soft_text = strtok_r(NULL, " \t\r\n", &save);
	hard_text = strtok_r(NULL, " \t\r\n", &save);
	if (!profile_text || !resource_text || !soft_text || !hard_text ||
	    strtok_r(NULL, " \t\r\n", &save)) {
		fprintf(stderr,
			"%u: resource needs PROFILE RLIMIT SOFT HARD\n",
			line);
		return -EINVAL;
	}

	ret = parse_u64(profile_text, &profile_id);
	if (ret) {
		fprintf(stderr, "%u: invalid resource profile '%s'\n", line,
			profile_text);
		return ret;
	}
	if (!find_profile(builder->profiles, profile_id)) {
		fprintf(stderr, "%u: unknown resource profile %llu\n", line,
			(unsigned long long)profile_id);
		return -ENOENT;
	}

	ret = parse_resource_id(resource_text, &resource);
	if (ret) {
		fprintf(stderr, "%u: invalid resource '%s'\n", line,
			resource_text);
		return ret;
	}

	ret = parse_resource_limit(soft_text, &soft_limit);
	if (ret) {
		fprintf(stderr, "%u: invalid resource soft limit '%s'\n",
			line, soft_text);
		return ret;
	}
	ret = parse_resource_limit(hard_text, &hard_limit);
	if (ret) {
		fprintf(stderr, "%u: invalid resource hard limit '%s'\n",
			line, hard_text);
		return ret;
	}
	if (soft_limit > hard_limit) {
		fprintf(stderr,
			"%u: resource soft limit may not exceed hard limit\n",
			line);
		return -EINVAL;
	}

	rule = &builder->resource_rules[builder->resource_rule_count];
	memset(rule, 0, sizeof(*rule));
	rule->profile_id = profile_id;
	rule->resource = resource;
	rule->soft_limit = soft_limit;
	rule->hard_limit = hard_limit;
	builder->resource_rule_count++;
	return 0;
}

static int add_role_include(struct hdn_policy_builder *builder,
			    const char *role_name, const char *parent_name,
			    unsigned int line)
{
	struct hdn_role_include *include;

	if (builder->role_include_count >= HDN_MAX_ROLE_INCLUDES) {
		fprintf(stderr, "%u: too many role includes\n", line);
		return -E2BIG;
	}
	if (!parent_name || strlen(parent_name) >= HDN_ROLE_NAME_LEN) {
		fprintf(stderr, "%u: invalid included role '%s'\n", line,
			parent_name ? parent_name : "");
		return -EINVAL;
	}

	include = &builder->role_includes[builder->role_include_count++];
	memset(include, 0, sizeof(*include));
	include->line = line;
	snprintf(include->role_name, sizeof(include->role_name), "%s",
		 role_name);
	snprintf(include->parent_name, sizeof(include->parent_name), "%s",
		 parent_name);
	return 0;
}

static int parse_role_include_tokens(struct hdn_policy_builder *builder,
				     const char *role_name, char *name,
				     char **save, unsigned int line)
{
	int ret;

	if (!name) {
		fprintf(stderr, "%u: role include needs at least one parent\n",
			line);
		return -EINVAL;
	}

	while (name) {
		ret = add_role_include(builder, role_name, name, line);
		if (ret)
			return ret;
		name = strtok_r(NULL, " \t\r\n", save);
	}

	return 0;
}

static int parse_role_command(struct hdn_policy_builder *builder,
			      char *save, unsigned int line)
{
	struct hdn_role_builder *role;
	char *role_name;
	char *operation;
	char *name;

	role_name = strtok_r(NULL, " \t\r\n", &save);
	operation = strtok_r(NULL, " \t\r\n", &save);
	if (!role_name) {
		fprintf(stderr, "%u: role needs name\n", line);
		return -EINVAL;
	}

	role = get_role(builder->roles, role_name);
	if (!role) {
		fprintf(stderr, "%u: invalid or excessive role '%s'\n", line,
			role_name);
		return -EINVAL;
	}

	if (!operation)
		return 0;

	name = strtok_r(NULL, " \t\r\n", &save);
	if (!strcmp(operation, "include") || !strcmp(operation, "inherit") ||
	    !strcmp(operation, "extends"))
		return parse_role_include_tokens(builder, role_name, name, &save,
						 line);
	if (!strcmp(operation, "allow"))
		return parse_authority_tokens(&role->authority_allow,
					      &role->authority_allow_hi,
					      name, &save, line,
					      "role allow");
	if (!strcmp(operation, "audit"))
		return parse_authority_tokens(&role->authority_audit,
					      &role->authority_audit_hi,
					      name, &save, line,
					      "role audit");
	if (!strcmp(operation, "mem"))
		return parse_memory_tokens(&role->memory_flags, name, &save,
					   line, "role mem");
	if (!strcmp(operation, "capability-deny") ||
	    !strcmp(operation, "cap-deny"))
		return parse_capability_tokens(&role->capability_deny, name, &save,
					       line, "role capability-deny");
	if (!strcmp(operation, "capability-audit") ||
	    !strcmp(operation, "cap-audit"))
		return parse_capability_tokens(&role->capability_audit, name,
					       &save, line,
					       "role capability-audit");
	if (!strcmp(operation, "response") || !strcmp(operation, "feature"))
		return parse_profile_flag_tokens(&role->flags, name, &save,
						 line, "role flag");

	fprintf(stderr, "%u: unknown role operation '%s'\n", line, operation);
	return -EINVAL;
}

static int parse_role_use_command(struct hdn_policy_builder *builder,
				  char *save, unsigned int line)
{
	struct hdn_role_use *role_use;
	char *profile_text;
	char *role_name;
	uint64_t profile_id;
	int ret;

	if (builder->role_use_count >= HDN_MAX_ROLE_USES) {
		fprintf(stderr, "%u: too many role uses\n", line);
		return -E2BIG;
	}

	profile_text = strtok_r(NULL, " \t\r\n", &save);
	role_name = strtok_r(NULL, " \t\r\n", &save);
	if (!profile_text || !role_name || strtok_r(NULL, " \t\r\n", &save)) {
		fprintf(stderr, "%u: use-role needs PROFILE ROLE\n", line);
		return -EINVAL;
	}

	ret = parse_u64(profile_text, &profile_id);
	if (ret || !profile_id) {
		fprintf(stderr, "%u: invalid use-role profile '%s'\n", line,
			profile_text);
		return -EINVAL;
	}
	if (strlen(role_name) >= HDN_ROLE_NAME_LEN) {
		fprintf(stderr, "%u: role name is too long\n", line);
		return -ENAMETOOLONG;
	}

	role_use = &builder->role_uses[builder->role_use_count++];
	memset(role_use, 0, sizeof(*role_use));
	role_use->profile_id = profile_id;
	role_use->line = line;
	snprintf(role_use->role_name, sizeof(role_use->role_name), "%s",
		 role_name);
	return 0;
}

static int set_object_identity(struct hdn_object_rule_record *rule,
			       uint64_t dev_major, uint64_t dev_minor,
			       uint64_t ino)
{
	if (!ino)
		return -EINVAL;

	rule->file_dev_major = dev_major;
	rule->file_dev_minor = dev_minor;
	rule->file_ino = ino;
	rule->flags |= HDN_OBJECT_MATCH_FILE_ID;
	return 0;
}

static int set_object_path(struct hdn_object_rule_record *rule,
			   const char *path)
{
	size_t len;

	if (path[0] != '/')
		return -EINVAL;

	len = strlen(path);
	if (!len || len >= HDN_POLICY_PATH_LEN)
		return -ENAMETOOLONG;

	snprintf(rule->file_path, sizeof(rule->file_path), "%s", path);
	rule->flags |= HDN_OBJECT_RESOLVE_FILE_PATH;
	return 0;
}

static int set_object_unix_abstract(struct hdn_object_rule_record *rule,
				    const char *name)
{
	size_t len;

	len = strlen(name);
	if (!len || len >= HDN_POLICY_PATH_LEN)
		return -ENAMETOOLONG;

	snprintf(rule->file_path, sizeof(rule->file_path), "%s", name);
	rule->flags |= HDN_OBJECT_MATCH_UNIX_ABSTRACT;
	return 0;
}

static int parse_object_identity_tokens(struct hdn_object_rule_record *rule,
					char **save, unsigned int line)
{
	char *major_text = strtok_r(NULL, " \t\r\n", save);
	char *minor_text = strtok_r(NULL, " \t\r\n", save);
	char *ino_text = strtok_r(NULL, " \t\r\n", save);
	uint64_t dev_major;
	uint64_t dev_minor;
	uint64_t ino;
	int ret;

	if (!major_text || !minor_text || !ino_text) {
		fprintf(stderr, "%u: object inode needs major minor ino\n",
			line);
		return -EINVAL;
	}

	ret = parse_u64(major_text, &dev_major);
	if (ret)
		return ret;
	ret = parse_u64(minor_text, &dev_minor);
	if (ret)
		return ret;
	ret = parse_u64(ino_text, &ino);
	if (ret)
		return ret;

	return set_object_identity(rule, dev_major, dev_minor, ino);
}

static int parse_object_command(struct hdn_policy_builder *builder, char *save,
				unsigned int line)
{
	struct hdn_object_rule_record *rule;
	char action_name[64];
	char *profile_text;
	char *action;
	char *mode;
	char *name;
	uint64_t profile_id;
	int ret;

	if (builder->object_rule_count >= HDN_MAX_OBJECT_RULES)
		return -ENOSPC;

	profile_text = strtok_r(NULL, " \t\r\n", &save);
	action = strtok_r(NULL, " \t\r\n", &save);
	mode = strtok_r(NULL, " \t\r\n", &save);
	if (!profile_text || !action || !mode) {
		fprintf(stderr,
			"%u: object needs PROFILE deny-*|append-only|audit-read|audit-append|audit-write|audit-exec|audit-find|audit-create|audit-delete|audit-link|audit-setid path|nofollow-path|tree|inode|abstract\n",
			line);
		return -EINVAL;
	}

	ret = parse_u64(profile_text, &profile_id);
	if (ret)
		return ret;
	if (!find_profile(builder->profiles, profile_id)) {
		fprintf(stderr, "%u: unknown object profile %llu\n", line,
			(unsigned long long)profile_id);
		return -ENOENT;
	}

	normalize_token(action, action_name, sizeof(action_name));
	if (strcmp(action_name, "DENY_WRITE") &&
	    strcmp(action_name, "DENY_READ") &&
	    strcmp(action_name, "DENY_DELETE") &&
	    strcmp(action_name, "DENY_CREATE") &&
	    strcmp(action_name, "DENY_CREAT") &&
	    strcmp(action_name, "DENY_MKDIR") &&
	    strcmp(action_name, "DENY_MKNOD") &&
	    strcmp(action_name, "DENY_SYMLINK") &&
	    strcmp(action_name, "DENY_UNLINK") &&
	    strcmp(action_name, "DENY_RMDIR") &&
	    strcmp(action_name, "DENY_EXEC") &&
	    strcmp(action_name, "APPEND_ONLY") &&
	    strcmp(action_name, "DENY_LINK") &&
	    strcmp(action_name, "DENY_LINK_TARGET") &&
	    strcmp(action_name, "DENY_ATTR") &&
	    strcmp(action_name, "DENY_CHMOD") &&
	    strcmp(action_name, "DENY_CHOWN") &&
	    strcmp(action_name, "DENY_UTIME") &&
	    strcmp(action_name, "DENY_SETID") &&
	    strcmp(action_name, "DENY_PTRACE") &&
	    strcmp(action_name, "DENY_ACCESS") &&
	    strcmp(action_name, "DENY_STAT") &&
	    strcmp(action_name, "DENY_LIST") &&
	    strcmp(action_name, "DENY_FIND") &&
		    strcmp(action_name, "DENY_IOCTL") &&
		    strcmp(action_name, "DENY_LOCK") &&
	    strcmp(action_name, "DENY_WATCH") &&
	    strcmp(action_name, "DENY_XATTR") &&
	    strcmp(action_name, "DENY_SETXATTR") &&
	    strcmp(action_name, "DENY_REMOVEXATTR") &&
	    strcmp(action_name, "DENY_RECEIVE") &&
	    strcmp(action_name, "DENY_FCNTL") &&
	    strcmp(action_name, "DENY_CHDIR") &&
	    strcmp(action_name, "DENY_MOUNT") &&
	    strcmp(action_name, "DENY_MOUNT_SOURCE") &&
	    strcmp(action_name, "DENY_UMOUNT") &&
		    strcmp(action_name, "DENY_TRUNCATE") &&
	    strcmp(action_name, "DENY_RENAME") &&
	    strcmp(action_name, "DENY_RENAME_TARGET") &&
	    strcmp(action_name, "DENY_UNIX_CONNECT") &&
	    strcmp(action_name, "DENY_UNIX_BIND") &&
	    strcmp(action_name, "DENY_UNIX_LISTEN") &&
	    strcmp(action_name, "DENY_UNIX_ACCEPT") &&
	    strcmp(action_name, "DENY_UNIX_SEND") &&
	    strcmp(action_name, "DENY_UNIX_RECV") &&
	    strcmp(action_name, "AUDIT_READ") &&
	    strcmp(action_name, "AUDIT_APPEND") &&
	    strcmp(action_name, "AUDIT_WRITE") &&
	    strcmp(action_name, "AUDIT_EXEC") &&
	    strcmp(action_name, "AUDIT_FIND") &&
	    strcmp(action_name, "AUDIT_CREATE") &&
	    strcmp(action_name, "AUDIT_DELETE") &&
	    strcmp(action_name, "AUDIT_LINK") &&
	    strcmp(action_name, "AUDIT_SETID")) {
		fprintf(stderr, "%u: unknown object action '%s'\n", line,
			action);
		return -EINVAL;
	}

	rule = &builder->object_rules[builder->object_rule_count];
	memset(rule, 0, sizeof(*rule));
	rule->profile_id = profile_id;
	if (!strcmp(action_name, "AUDIT_READ"))
		rule->audit_flags = HDN_OBJECT_DENY_READ;
	else if (!strcmp(action_name, "AUDIT_APPEND"))
		rule->audit_flags = HDN_OBJECT_APPEND_ONLY;
	else if (!strcmp(action_name, "AUDIT_WRITE"))
		rule->audit_flags = HDN_OBJECT_DENY_WRITE;
	else if (!strcmp(action_name, "AUDIT_EXEC"))
		rule->audit_flags = HDN_OBJECT_DENY_EXEC;
	else if (!strcmp(action_name, "AUDIT_FIND"))
		rule->audit_flags = HDN_OBJECT_DENY_FIND;
	else if (!strcmp(action_name, "AUDIT_CREATE"))
		rule->audit_flags = HDN_OBJECT_DENY_CREATE;
	else if (!strcmp(action_name, "AUDIT_DELETE"))
		rule->audit_flags = HDN_OBJECT_DENY_DELETE;
	else if (!strcmp(action_name, "AUDIT_LINK"))
		rule->audit_flags = HDN_OBJECT_DENY_LINK;
	else if (!strcmp(action_name, "AUDIT_SETID"))
		rule->audit_flags = HDN_OBJECT_DENY_SETID;
	else if (!strcmp(action_name, "DENY_WRITE"))
		rule->flags = HDN_OBJECT_DENY_WRITE;
	else if (!strcmp(action_name, "DENY_READ"))
		rule->flags = HDN_OBJECT_DENY_READ;
	else if (!strcmp(action_name, "DENY_DELETE"))
		rule->flags = HDN_OBJECT_DENY_DELETE;
	else if (!strcmp(action_name, "DENY_CREATE"))
		rule->flags = HDN_OBJECT_DENY_CREATE;
	else if (!strcmp(action_name, "DENY_CREAT"))
		rule->flags = HDN_OBJECT_DENY_CREAT;
	else if (!strcmp(action_name, "DENY_MKDIR"))
		rule->flags = HDN_OBJECT_DENY_MKDIR;
	else if (!strcmp(action_name, "DENY_MKNOD"))
		rule->flags = HDN_OBJECT_DENY_MKNOD;
	else if (!strcmp(action_name, "DENY_SYMLINK"))
		rule->flags = HDN_OBJECT_DENY_SYMLINK;
	else if (!strcmp(action_name, "DENY_UNLINK"))
		rule->flags = HDN_OBJECT_DENY_UNLINK;
	else if (!strcmp(action_name, "DENY_RMDIR"))
		rule->flags = HDN_OBJECT_DENY_RMDIR;
	else if (!strcmp(action_name, "DENY_EXEC"))
		rule->flags = HDN_OBJECT_DENY_EXEC;
	else if (!strcmp(action_name, "APPEND_ONLY"))
		rule->flags = HDN_OBJECT_APPEND_ONLY;
	else if (!strcmp(action_name, "DENY_LINK"))
		rule->flags = HDN_OBJECT_DENY_LINK;
	else if (!strcmp(action_name, "DENY_LINK_TARGET"))
		rule->flags = HDN_OBJECT_DENY_LINK_TARGET;
	else if (!strcmp(action_name, "DENY_ATTR"))
		rule->flags = HDN_OBJECT_DENY_ATTR;
	else if (!strcmp(action_name, "DENY_CHMOD"))
		rule->flags = HDN_OBJECT_DENY_CHMOD;
	else if (!strcmp(action_name, "DENY_CHOWN"))
		rule->flags = HDN_OBJECT_DENY_CHOWN;
	else if (!strcmp(action_name, "DENY_UTIME"))
		rule->flags = HDN_OBJECT_DENY_UTIME;
	else if (!strcmp(action_name, "DENY_SETID"))
		rule->flags = HDN_OBJECT_DENY_SETID;
	else if (!strcmp(action_name, "DENY_PTRACE"))
		rule->flags = HDN_OBJECT_DENY_PTRACE;
	else if (!strcmp(action_name, "DENY_ACCESS"))
		rule->flags = HDN_OBJECT_DENY_ACCESS;
	else if (!strcmp(action_name, "DENY_STAT"))
		rule->flags = HDN_OBJECT_DENY_STAT;
	else if (!strcmp(action_name, "DENY_LIST"))
		rule->flags = HDN_OBJECT_DENY_LIST;
	else if (!strcmp(action_name, "DENY_FIND"))
		rule->flags = HDN_OBJECT_DENY_FIND;
	else if (!strcmp(action_name, "DENY_IOCTL"))
		rule->flags = HDN_OBJECT_DENY_IOCTL;
	else if (!strcmp(action_name, "DENY_LOCK"))
		rule->flags = HDN_OBJECT_DENY_LOCK;
	else if (!strcmp(action_name, "DENY_WATCH"))
		rule->flags = HDN_OBJECT_DENY_WATCH;
	else if (!strcmp(action_name, "DENY_XATTR"))
		rule->flags = HDN_OBJECT_DENY_XATTR;
	else if (!strcmp(action_name, "DENY_SETXATTR"))
		rule->flags = HDN_OBJECT_DENY_SETXATTR;
	else if (!strcmp(action_name, "DENY_REMOVEXATTR"))
		rule->flags = HDN_OBJECT_DENY_REMOVEXATTR;
	else if (!strcmp(action_name, "DENY_RECEIVE"))
		rule->flags = HDN_OBJECT_DENY_RECEIVE;
	else if (!strcmp(action_name, "DENY_FCNTL"))
		rule->flags = HDN_OBJECT_DENY_FCNTL;
	else if (!strcmp(action_name, "DENY_CHDIR"))
		rule->flags = HDN_OBJECT_DENY_CHDIR;
	else if (!strcmp(action_name, "DENY_MOUNT"))
		rule->flags = HDN_OBJECT_DENY_MOUNT;
	else if (!strcmp(action_name, "DENY_MOUNT_SOURCE"))
		rule->flags = HDN_OBJECT_DENY_MOUNT_SOURCE;
	else if (!strcmp(action_name, "DENY_UMOUNT"))
		rule->flags = HDN_OBJECT_DENY_UMOUNT;
	else if (!strcmp(action_name, "DENY_TRUNCATE"))
		rule->flags = HDN_OBJECT_DENY_TRUNCATE;
	else if (!strcmp(action_name, "DENY_RENAME"))
		rule->flags = HDN_OBJECT_DENY_RENAME;
	else if (!strcmp(action_name, "DENY_RENAME_TARGET"))
		rule->flags = HDN_OBJECT_DENY_RENAME_TARGET;
	else if (!strcmp(action_name, "DENY_UNIX_CONNECT"))
		rule->flags = HDN_OBJECT_DENY_UNIX_CONNECT;
	else if (!strcmp(action_name, "DENY_UNIX_BIND"))
		rule->flags = HDN_OBJECT_DENY_UNIX_BIND;
	else if (!strcmp(action_name, "DENY_UNIX_LISTEN"))
		rule->flags = HDN_OBJECT_DENY_UNIX_LISTEN;
	else if (!strcmp(action_name, "DENY_UNIX_ACCEPT"))
		rule->flags = HDN_OBJECT_DENY_UNIX_ACCEPT;
	else if (!strcmp(action_name, "DENY_UNIX_SEND"))
		rule->flags = HDN_OBJECT_DENY_UNIX_SEND;
	else
		rule->flags = HDN_OBJECT_DENY_UNIX_RECV;

	if (!strcmp(mode, "path")) {
		name = strtok_r(NULL, " \t\r\n", &save);
		if (!name)
			return -EINVAL;
		ret = set_object_path(rule, name);
		if (ret) {
			fprintf(stderr, "%u: invalid object path '%s': %s\n",
				line, name, strerror(-ret));
			return ret;
		}
	} else if (!strcmp(mode, "nofollow-path")) {
		name = strtok_r(NULL, " \t\r\n", &save);
		if (!name)
			return -EINVAL;
		ret = set_object_path(rule, name);
		if (ret) {
			fprintf(stderr,
				"%u: invalid object nofollow path '%s': %s\n",
				line, name, strerror(-ret));
			return ret;
		}
		rule->flags |= HDN_OBJECT_RESOLVE_NOFOLLOW_PATH;
	} else if (!strcmp(mode, "tree")) {
		name = strtok_r(NULL, " \t\r\n", &save);
		if (!name)
			return -EINVAL;
		ret = set_object_path(rule, name);
		if (ret) {
			fprintf(stderr, "%u: invalid object tree '%s': %s\n",
				line, name, strerror(-ret));
			return ret;
		}
		rule->flags |= HDN_OBJECT_MATCH_SUBTREE;
	} else if (!strcmp(mode, "inode")) {
		ret = parse_object_identity_tokens(rule, &save, line);
		if (ret)
			return ret;
	} else if (!strcmp(mode, "abstract")) {
		name = strtok_r(NULL, " \t\r\n", &save);
		if (!name)
			return -EINVAL;
		ret = set_object_unix_abstract(rule, name);
		if (ret) {
			fprintf(stderr,
				"%u: invalid object abstract name '%s': %s\n",
				line, name, strerror(-ret));
			return ret;
		}
	} else {
		fprintf(stderr, "%u: unknown object match mode '%s'\n",
			line, mode);
		return -EINVAL;
	}

	if (strtok_r(NULL, " \t\r\n", &save)) {
		fprintf(stderr, "%u: object rule has trailing tokens\n", line);
		return -EINVAL;
	}

	builder->object_rule_count++;
	return 0;
}

static int set_exec_identity(struct hdn_exec_rule_record *rule,
			     bool original, uint64_t dev_major,
			     uint64_t dev_minor, uint64_t ino)
{
	if (!ino)
		return -EINVAL;

	if (original) {
		rule->original_dev_major = dev_major;
		rule->original_dev_minor = dev_minor;
		rule->original_ino = ino;
		rule->flags |= HDN_EXEC_MATCH_ORIGINAL_ID;
	} else {
		rule->file_dev_major = dev_major;
		rule->file_dev_minor = dev_minor;
		rule->file_ino = ino;
		rule->flags |= HDN_EXEC_MATCH_FILE_ID;
	}

	return 0;
}

static int set_exec_path(struct hdn_exec_rule_record *rule, bool original,
			 const char *path)
{
	size_t len;

	if (path[0] != '/')
		return -EINVAL;

	len = strlen(path);
	if (!len || len >= HDN_POLICY_PATH_LEN)
		return -ENAMETOOLONG;

	if (original) {
		snprintf(rule->original_path, sizeof(rule->original_path),
			 "%s", path);
		rule->flags |= HDN_EXEC_RESOLVE_ORIGINAL_PATH;
	} else {
		snprintf(rule->file_path, sizeof(rule->file_path), "%s",
			 path);
		rule->flags |= HDN_EXEC_RESOLVE_FILE_PATH;
	}

	return 0;
}

static int parse_hex_digit(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;

	return -EINVAL;
}

static int parse_hex_digest(const char *text, uint8_t *digest,
			    uint32_t *digest_size)
{
	size_t len = strlen(text);
	size_t i;

	if (!len || len % 2 || len / 2 > HDN_VERITY_DIGEST_MAX)
		return -EINVAL;

	for (i = 0; i < len / 2; i++) {
		int hi = parse_hex_digit(text[i * 2]);
		int lo = parse_hex_digit(text[i * 2 + 1]);

		if (hi < 0 || lo < 0)
			return -EINVAL;
		digest[i] = (uint8_t)((hi << 4) | lo);
	}

	*digest_size = len / 2;
	return 0;
}

static int parse_verity_algorithm(const char *text, uint32_t *algorithm)
{
	char normalized[64];
	uint64_t value;
	int ret;

	normalize_token(text, normalized, sizeof(normalized));
	if (!strcmp(normalized, "SHA256") ||
	    !strcmp(normalized, "SHA_256") ||
	    !strcmp(normalized, "FS_VERITY_HASH_ALG_SHA256")) {
		*algorithm = FS_VERITY_HASH_ALG_SHA256;
		return 0;
	}
	if (!strcmp(normalized, "SHA512") ||
	    !strcmp(normalized, "SHA_512") ||
	    !strcmp(normalized, "FS_VERITY_HASH_ALG_SHA512")) {
		*algorithm = FS_VERITY_HASH_ALG_SHA512;
		return 0;
	}

	ret = parse_u64(text, &value);
	if (ret)
		return ret;
	if (value > UINT32_MAX)
		return -ERANGE;

	*algorithm = value;
	return 0;
}

static int set_exec_verity(struct hdn_exec_rule_record *rule,
			   const char *algorithm_text, const char *digest_text)
{
	uint32_t algorithm;
	uint32_t digest_size;
	int ret;

	if (rule->flags & HDN_EXEC_MATCH_VERITY_DIGEST)
		return -EEXIST;

	ret = parse_verity_algorithm(algorithm_text, &algorithm);
	if (ret)
		return ret;
	ret = parse_hex_digest(digest_text, rule->verity_digest, &digest_size);
	if (ret)
		return ret;

	rule->verity_digest_algorithm = algorithm;
	rule->verity_digest_size = digest_size;
	rule->flags |= HDN_EXEC_MATCH_VERITY_DIGEST;
	return 0;
}

static int parse_exec_identity_tokens(struct hdn_exec_rule_record *rule,
				      char **save, unsigned int line,
				      bool original)
{
	char *major_text = strtok_r(NULL, " \t\r\n", save);
	char *minor_text = strtok_r(NULL, " \t\r\n", save);
	char *ino_text = strtok_r(NULL, " \t\r\n", save);
	uint64_t dev_major;
	uint64_t dev_minor;
	uint64_t ino;
	int ret;

	if (!major_text || !minor_text || !ino_text) {
		fprintf(stderr, "%u: exec inode needs major minor ino\n",
			line);
		return -EINVAL;
	}

	ret = parse_u64(major_text, &dev_major);
	if (ret)
		return ret;
	ret = parse_u64(minor_text, &dev_minor);
	if (ret)
		return ret;
	ret = parse_u64(ino_text, &ino);
	if (ret)
		return ret;

	return set_exec_identity(rule, original, dev_major, dev_minor, ino);
}

static int parse_exec_options(struct hdn_exec_rule_record *rule,
			      struct hdn_profile_builder *profiles, char *name,
			      char **save, unsigned int line)
{
	uint64_t parent;
	int ret;

	while (name) {
		if (!strcmp(name, "parent")) {
			name = strtok_r(NULL, " \t\r\n", save);
			if (!name) {
				fprintf(stderr,
					"%u: exec parent needs profile ID\n",
					line);
				return -EINVAL;
			}

			ret = parse_u64(name, &parent);
			if (ret)
				return ret;
			if (!find_profile(profiles, parent)) {
				fprintf(stderr, "%u: unknown parent profile %llu\n",
					line, (unsigned long long)parent);
				return -ENOENT;
			}
			if (rule->parent_profile_id)
				return -EEXIST;
			rule->parent_profile_id = parent;
		} else if (!strcmp(name, "audit-inherit")) {
			if (!(rule->flags & HDN_EXEC_INHERIT_PROFILE)) {
				fprintf(stderr,
					"%u: audit-inherit requires exec inherit\n",
					line);
				return -EINVAL;
			}
			if (rule->flags & HDN_EXEC_AUDIT_INHERIT)
				return -EEXIST;
			rule->flags |= HDN_EXEC_AUDIT_INHERIT;
		} else if (!strcmp(name, "verity")) {
			char *algorithm = strtok_r(NULL, " \t\r\n", save);
			char *digest = strtok_r(NULL, " \t\r\n", save);

			if (!algorithm || !digest) {
				fprintf(stderr,
					"%u: exec verity needs algorithm and hex digest\n",
					line);
				return -EINVAL;
			}
			ret = set_exec_verity(rule, algorithm, digest);
			if (ret) {
				fprintf(stderr,
					"%u: invalid exec verity digest\n",
					line);
				return ret;
			}
		} else {
			fprintf(stderr, "%u: unknown exec option '%s'\n",
				line, name);
			return -EINVAL;
		}

		name = strtok_r(NULL, " \t\r\n", save);
	}

	return 0;
}

static int parse_exec_command(struct hdn_policy_builder *builder, char *save,
			      unsigned int line)
{
	struct hdn_exec_rule_record *rule;
	char *profile_text;
	char *mode;
	char *name;
	uint64_t target;
	bool inherit = false;
	int ret;

	if (builder->exec_rule_count >= HDN_MAX_EXEC_RULES)
		return -ENOSPC;

	profile_text = strtok_r(NULL, " \t\r\n", &save);
	mode = strtok_r(NULL, " \t\r\n", &save);
	if (!profile_text || !mode) {
		fprintf(stderr, "%u: exec needs profile ID and match mode\n",
			line);
		return -EINVAL;
	}

	if (!strcmp(profile_text, "inherit")) {
		inherit = true;
		target = 0;
	} else {
		ret = parse_u64(profile_text, &target);
		if (ret)
			return ret;
		if (!find_profile(builder->profiles, target)) {
			fprintf(stderr, "%u: unknown exec target profile %llu\n",
				line, (unsigned long long)target);
			return -ENOENT;
		}
	}

	rule = &builder->exec_rules[builder->exec_rule_count];
	memset(rule, 0, sizeof(*rule));
	rule->target_profile_id = target;
	if (inherit)
		rule->flags |= HDN_EXEC_INHERIT_PROFILE;

	if (!strcmp(mode, "path")) {
		name = strtok_r(NULL, " \t\r\n", &save);
		if (!name)
			return -EINVAL;
		ret = set_exec_path(rule, false, name);
		if (ret) {
			fprintf(stderr, "%u: invalid exec path '%s': %s\n",
				line, name, strerror(-ret));
			return ret;
		}
		name = strtok_r(NULL, " \t\r\n", &save);
	} else if (!strcmp(mode, "inode")) {
		ret = parse_exec_identity_tokens(rule, &save, line, false);
		if (ret)
			return ret;
		name = strtok_r(NULL, " \t\r\n", &save);
	} else if (!strcmp(mode, "interpreter-path")) {
		char *interpreter = strtok_r(NULL, " \t\r\n", &save);
		char *original_mode = strtok_r(NULL, " \t\r\n", &save);
		char *original = strtok_r(NULL, " \t\r\n", &save);

		if (!interpreter || !original_mode || !original ||
		    strcmp(original_mode, "original-path"))
			return -EINVAL;
		ret = set_exec_path(rule, false, interpreter);
		if (ret)
			return ret;
		ret = set_exec_path(rule, true, original);
		if (ret)
			return ret;
		name = strtok_r(NULL, " \t\r\n", &save);
	} else if (!strcmp(mode, "interpreter")) {
		char *original_mode;

		ret = parse_exec_identity_tokens(rule, &save, line, false);
		if (ret)
			return ret;
		original_mode = strtok_r(NULL, " \t\r\n", &save);
		if (!original_mode || strcmp(original_mode, "original"))
			return -EINVAL;
		ret = parse_exec_identity_tokens(rule, &save, line, true);
		if (ret)
			return ret;
		name = strtok_r(NULL, " \t\r\n", &save);
	} else if (!strcmp(mode, "verity")) {
		char *algorithm = strtok_r(NULL, " \t\r\n", &save);
		char *digest = strtok_r(NULL, " \t\r\n", &save);

		if (!algorithm || !digest) {
			fprintf(stderr,
				"%u: exec verity needs algorithm and hex digest\n",
				line);
			return -EINVAL;
		}
		ret = set_exec_verity(rule, algorithm, digest);
		if (ret) {
			fprintf(stderr, "%u: invalid exec verity digest\n", line);
			return ret;
		}
		name = strtok_r(NULL, " \t\r\n", &save);
	} else {
		fprintf(stderr, "%u: unknown exec match mode '%s'\n",
			line, mode);
		return -EINVAL;
	}

	ret = parse_exec_options(rule, builder->profiles, name, &save, line);
	if (ret)
		return ret;

	builder->exec_rule_count++;
	return 0;
}

static int set_module_identity(struct hdn_module_rule_record *rule,
			       uint64_t dev_major, uint64_t dev_minor,
			       uint64_t ino)
{
	if (!ino)
		return -EINVAL;

	rule->file_dev_major = dev_major;
	rule->file_dev_minor = dev_minor;
	rule->file_ino = ino;
	rule->flags |= HDN_MODULE_MATCH_FILE_ID;
	return 0;
}

static int set_module_path(struct hdn_module_rule_record *rule,
			   const char *path)
{
	size_t len;

	if (path[0] != '/')
		return -EINVAL;

	len = strlen(path);
	if (!len || len >= HDN_POLICY_PATH_LEN)
		return -ENAMETOOLONG;

	snprintf(rule->file_path, sizeof(rule->file_path), "%s", path);
	rule->flags |= HDN_MODULE_RESOLVE_FILE_PATH;
	return 0;
}

static int set_module_verity(struct hdn_module_rule_record *rule,
			     const char *algorithm_text,
			     const char *digest_text)
{
	uint32_t algorithm;
	uint32_t digest_size;
	int ret;

	if (rule->flags & HDN_MODULE_MATCH_VERITY_DIGEST)
		return -EEXIST;

	ret = parse_verity_algorithm(algorithm_text, &algorithm);
	if (ret)
		return ret;
	ret = parse_hex_digest(digest_text, rule->verity_digest, &digest_size);
	if (ret)
		return ret;

	rule->verity_digest_algorithm = algorithm;
	rule->verity_digest_size = digest_size;
	rule->flags |= HDN_MODULE_MATCH_VERITY_DIGEST;
	return 0;
}

static int parse_module_identity_tokens(struct hdn_module_rule_record *rule,
					char **save, unsigned int line)
{
	char *major_text = strtok_r(NULL, " \t\r\n", save);
	char *minor_text = strtok_r(NULL, " \t\r\n", save);
	char *ino_text = strtok_r(NULL, " \t\r\n", save);
	uint64_t dev_major;
	uint64_t dev_minor;
	uint64_t ino;
	int ret;

	if (!major_text || !minor_text || !ino_text) {
		fprintf(stderr, "%u: module inode needs major minor ino\n",
			line);
		return -EINVAL;
	}

	ret = parse_u64(major_text, &dev_major);
	if (ret)
		return ret;
	ret = parse_u64(minor_text, &dev_minor);
	if (ret)
		return ret;
	ret = parse_u64(ino_text, &ino);
	if (ret)
		return ret;

	return set_module_identity(rule, dev_major, dev_minor, ino);
}

static int parse_module_options(struct hdn_module_rule_record *rule,
				char *name, char **save, unsigned int line)
{
	int ret;

	while (name) {
		if (!strcmp(name, "signed")) {
			if (rule->flags & HDN_MODULE_MATCH_TRUSTED_SIGNATURE) {
				fprintf(stderr,
					"%u: duplicate module signed option\n", line);
				return -EEXIST;
			}
			rule->flags |= HDN_MODULE_MATCH_TRUSTED_SIGNATURE;
		} else if (!strcmp(name, "verity")) {
			char *algorithm = strtok_r(NULL, " \t\r\n", save);
			char *digest = strtok_r(NULL, " \t\r\n", save);

			if (!algorithm || !digest) {
				fprintf(stderr,
					"%u: module verity needs algorithm and hex digest\n",
					line);
				return -EINVAL;
			}
			ret = set_module_verity(rule, algorithm, digest);
			if (ret) {
				fprintf(stderr,
					"%u: invalid module verity digest\n",
					line);
				return ret;
			}
		} else {
			fprintf(stderr, "%u: unknown module option '%s'\n",
				line, name);
			return -EINVAL;
		}

		name = strtok_r(NULL, " \t\r\n", save);
	}

	return 0;
}

static int parse_module_command(struct hdn_policy_builder *builder, char *save,
				unsigned int line)
{
	struct hdn_module_rule_record *rule;
	char *profile_text;
	char *mode;
	char *name;
	uint64_t profile_id;
	int ret;

	if (builder->module_rule_count >= HDN_MAX_MODULE_RULES)
		return -ENOSPC;

	profile_text = strtok_r(NULL, " \t\r\n", &save);
	mode = strtok_r(NULL, " \t\r\n", &save);
	if (!profile_text || !mode) {
		fprintf(stderr, "%u: module needs profile ID and match mode\n",
			line);
		return -EINVAL;
	}

	ret = parse_u64(profile_text, &profile_id);
	if (ret)
		return ret;
	if (!find_profile(builder->profiles, profile_id)) {
		fprintf(stderr, "%u: unknown module profile %llu\n",
			line, (unsigned long long)profile_id);
		return -ENOENT;
	}

	rule = &builder->module_rules[builder->module_rule_count];
	memset(rule, 0, sizeof(*rule));
	rule->profile_id = profile_id;

	if (!strcmp(mode, "path")) {
		name = strtok_r(NULL, " \t\r\n", &save);
		if (!name)
			return -EINVAL;
		ret = set_module_path(rule, name);
		if (ret) {
			fprintf(stderr, "%u: invalid module path '%s': %s\n",
				line, name, strerror(-ret));
			return ret;
		}
		name = strtok_r(NULL, " \t\r\n", &save);
	} else if (!strcmp(mode, "inode")) {
		ret = parse_module_identity_tokens(rule, &save, line);
		if (ret)
			return ret;
		name = strtok_r(NULL, " \t\r\n", &save);
	} else if (!strcmp(mode, "verity")) {
		char *algorithm = strtok_r(NULL, " \t\r\n", &save);
		char *digest = strtok_r(NULL, " \t\r\n", &save);

		if (!algorithm || !digest) {
			fprintf(stderr,
				"%u: module verity needs algorithm and hex digest\n",
				line);
			return -EINVAL;
		}
		ret = set_module_verity(rule, algorithm, digest);
		if (ret) {
			fprintf(stderr, "%u: invalid module verity digest\n",
				line);
			return ret;
		}
		name = strtok_r(NULL, " \t\r\n", &save);
	} else if (!strcmp(mode, "signed")) {
		rule->flags |= HDN_MODULE_MATCH_TRUSTED_SIGNATURE;
		name = strtok_r(NULL, " \t\r\n", &save);
	} else {
		fprintf(stderr, "%u: unknown module match mode '%s'\n",
			line, mode);
		return -EINVAL;
	}

	ret = parse_module_options(rule, name, &save, line);
	if (ret)
		return ret;

	builder->module_rule_count++;
	return 0;
}

static int parse_firmware_command(struct hdn_policy_builder *builder,
				  char *save, unsigned int line)
{
	struct hdn_firmware_rule_record *rule;
	char *profile_text;
	char *mode;
	char *name;
	uint64_t profile_id;
	int ret;

	if (builder->firmware_rule_count >= HDN_MAX_FIRMWARE_RULES)
		return -ENOSPC;

	profile_text = strtok_r(NULL, " \t\r\n", &save);
	mode = strtok_r(NULL, " \t\r\n", &save);
	name = strtok_r(NULL, " \t\r\n", &save);
	if (!profile_text || !mode ||
	    (strcmp(mode, "name") && strcmp(mode, "any")) ||
	    (!strcmp(mode, "name") && !name) ||
	    (!strcmp(mode, "any") && name)) {
		fprintf(stderr,
			"%u: firmware needs profile ID and name <firmware> or any\n",
			line);
		return -EINVAL;
	}
	if (name && strtok_r(NULL, " \t\r\n", &save)) {
		fprintf(stderr, "%u: firmware name may not contain spaces\n",
			line);
		return -EINVAL;
	}
	if (name && strlen(name) >= HDN_FIRMWARE_NAME_LEN) {
		fprintf(stderr, "%u: firmware name is too long\n", line);
		return -ENAMETOOLONG;
	}

	ret = parse_u64(profile_text, &profile_id);
	if (ret)
		return ret;
	if (!find_profile(builder->profiles, profile_id)) {
		fprintf(stderr, "%u: unknown firmware profile %llu\n",
			line, (unsigned long long)profile_id);
		return -ENOENT;
	}

	rule = &builder->firmware_rules[builder->firmware_rule_count];
	memset(rule, 0, sizeof(*rule));
	rule->profile_id = profile_id;
	if (!strcmp(mode, "any"))
		rule->flags = HDN_FIRMWARE_MATCH_ANY;
	else
		snprintf(rule->name, sizeof(rule->name), "%s", name);
	builder->firmware_rule_count++;
	return 0;
}

static int parse_id_command(uint64_t *value, char *save, unsigned int line,
			    const char *command)
{
	char *id_text = strtok_r(NULL, " \t\r\n", &save);
	int ret;

	if (!id_text) {
		fprintf(stderr, "%u: %s needs profile ID\n", line, command);
		return -EINVAL;
	}

	ret = parse_u64(id_text, value);
	if (ret)
		fprintf(stderr, "%u: invalid %s ID '%s'\n", line, command,
			id_text);

	return ret;
}

static int parse_subject_command(struct hdn_policy_builder *builder,
				 char *save, unsigned int line)
{
	struct hdn_subject_rule_record *rule;
	char *kind;
	char *id_text;
	char *profile_text;
	uint64_t id;
	uint64_t profile_id;
	int ret;

	if (builder->subject_rule_count >= HDN_MAX_SUBJECT_RULES) {
		fprintf(stderr, "%u: too many subject rules\n", line);
		return -E2BIG;
	}

	kind = strtok_r(NULL, " \t\r\n", &save);
	id_text = strtok_r(NULL, " \t\r\n", &save);
	profile_text = strtok_r(NULL, " \t\r\n", &save);
	if (!kind || !id_text || !profile_text ||
	    strtok_r(NULL, " \t\r\n", &save)) {
		fprintf(stderr,
			"%u: subject needs uid|gid ID PROFILE\n", line);
		return -EINVAL;
	}

	ret = parse_u64(id_text, &id);
	if (ret || id > UINT32_MAX) {
		fprintf(stderr, "%u: invalid subject ID '%s'\n", line,
			id_text);
		return -EINVAL;
	}

	ret = parse_u64(profile_text, &profile_id);
	if (ret) {
		fprintf(stderr, "%u: invalid subject profile '%s'\n", line,
			profile_text);
		return -EINVAL;
	}
	if (!find_profile(builder->profiles, profile_id)) {
		fprintf(stderr, "%u: unknown subject profile %llu\n", line,
			(unsigned long long)profile_id);
		return -EINVAL;
	}

	rule = &builder->subject_rules[builder->subject_rule_count];
	memset(rule, 0, sizeof(*rule));
	rule->profile_id = profile_id;
	rule->id = (uint32_t)id;
	if (!strcmp(kind, "uid"))
		rule->flags = HDN_SUBJECT_MATCH_UID;
	else if (!strcmp(kind, "gid"))
		rule->flags = HDN_SUBJECT_MATCH_GID;
	else {
		fprintf(stderr, "%u: unknown subject kind '%s'\n", line,
			kind);
		return -EINVAL;
	}

	builder->subject_rule_count++;
	return 0;
}

static int parse_line(struct hdn_policy_builder *builder,
		      uint64_t *generation, uint64_t *default_profile,
		      uint64_t *privileged_profile,
		      uint64_t *expected_generation, char *line,
		      unsigned int line_number)
{
	char *comment;
	char *command;
	char *save = NULL;

	comment = strchr(line, '#');
	if (comment)
		*comment = '\0';

	command = strtok_r(line, " \t\r\n", &save);
	if (!command)
		return 0;

	if (!strcmp(command, "generation"))
		return parse_id_command(generation, save, line_number,
					command);
	if (!strcmp(command, "base"))
		return parse_id_command(expected_generation, save, line_number,
					command);
	if (!strcmp(command, "default"))
		return parse_id_command(default_profile, save, line_number,
					command);
	if (!strcmp(command, "privileged"))
		return parse_id_command(privileged_profile, save, line_number,
					command);
	if (!strcmp(command, "profile"))
		return parse_profile_command(builder->profiles, save,
					     line_number);
	if (!strcmp(command, "role"))
		return parse_role_command(builder, save, line_number);
	if (!strcmp(command, "use-role") || !strcmp(command, "profile-role"))
		return parse_role_use_command(builder, save, line_number);
	if (!strcmp(command, "allow"))
		return parse_mask_command(builder->profiles, save, line_number,
					  false);
	if (!strcmp(command, "audit"))
		return parse_mask_command(builder->profiles, save, line_number,
					  true);
	if (!strcmp(command, "capability-deny") ||
	    !strcmp(command, "cap-deny"))
		return parse_capability_command(builder->profiles, save, line_number,
						false);
	if (!strcmp(command, "capability-audit") ||
	    !strcmp(command, "cap-audit"))
		return parse_capability_command(builder->profiles, save, line_number,
						true);
	if (!strcmp(command, "mem"))
		return parse_mem_command(builder->profiles, save, line_number);
	if (!strcmp(command, "response"))
		return parse_profile_flag_command(builder->profiles, save,
						  line_number, command);
	if (!strcmp(command, "feature"))
		return parse_profile_flag_command(builder->profiles, save,
						  line_number, command);
	if (!strcmp(command, "umask") || !strcmp(command, "profile-umask"))
		return parse_umask_command(builder->profiles, save,
					   line_number);
	if (!strcmp(command, "userns-max"))
		return parse_userns_max_command(builder->profiles, save,
						line_number);
	if (!strcmp(command, "resource") || !strcmp(command, "rlimit"))
		return parse_resource_command(builder, save, line_number);
	if (!strcmp(command, "subject"))
		return parse_subject_command(builder, save, line_number);
	if (!strcmp(command, "object"))
		return parse_object_command(builder, save, line_number);
	if (!strcmp(command, "exec"))
		return parse_exec_command(builder, save, line_number);
	if (!strcmp(command, "module"))
		return parse_module_command(builder, save, line_number);
	if (!strcmp(command, "firmware"))
		return parse_firmware_command(builder, save, line_number);

	fprintf(stderr, "%u: unknown command '%s'\n", line_number, command);
	return -EINVAL;
}

static int read_policy(const char *path, struct hdn_policy_builder *builder,
		       uint64_t *generation, uint64_t *default_profile,
		       uint64_t *privileged_profile,
		       uint64_t *expected_generation)
{
	char line[4096];
	unsigned int line_number = 0;
	FILE *file;
	int ret = 0;

	file = fopen(path, "r");
	if (!file) {
		perror(path);
		return -errno;
	}

	while (fgets(line, sizeof(line), file)) {
		line_number++;
		ret = parse_line(builder, generation, default_profile,
				 privileged_profile, expected_generation, line,
				 line_number);
		if (ret)
			break;
	}

	if (ferror(file) && !ret) {
		perror(path);
		ret = -EIO;
	}

	fclose(file);
	return ret;
}

static void merge_role(struct hdn_role_builder *role,
		       const struct hdn_role_builder *parent)
{
	role->authority_allow |= parent->authority_allow;
	role->authority_allow_hi |= parent->authority_allow_hi;
	role->authority_audit |= parent->authority_audit;
	role->authority_audit_hi |= parent->authority_audit_hi;
	role->memory_flags |= parent->memory_flags;
	role->flags |= parent->flags;
	role->capability_deny |= parent->capability_deny;
	role->capability_audit |= parent->capability_audit;
}

static int expand_role(struct hdn_policy_builder *builder, size_t index)
{
	struct hdn_role_builder *role = &builder->roles[index];
	uint32_t i;
	int ret;
	int parent_index;

	if (role->visit_state == 2)
		return 0;
	if (role->visit_state == 1) {
		fprintf(stderr, "role include cycle involving '%s'\n",
			role->name);
		return -EINVAL;
	}

	role->visit_state = 1;
	for (i = 0; i < builder->role_include_count; i++) {
		const struct hdn_role_include *include =
			&builder->role_includes[i];

		if (strcmp(include->role_name, role->name))
			continue;

		parent_index = find_role_index(builder->roles,
					       include->parent_name);
		if (parent_index < 0) {
			fprintf(stderr, "%u: unknown included role '%s'\n",
				include->line, include->parent_name);
			return -ENOENT;
		}

		ret = expand_role(builder, (size_t)parent_index);
		if (ret)
			return ret;
		merge_role(role, &builder->roles[parent_index]);
	}
	role->visit_state = 2;

	return 0;
}

static int expand_roles(struct hdn_policy_builder *builder)
{
	size_t i;
	int ret;

	for (i = 0; i < HDN_MAX_ROLES; i++)
		builder->roles[i].visit_state = 0;

	for (i = 0; i < HDN_MAX_ROLES; i++) {
		if (!builder->roles[i].present)
			continue;
		ret = expand_role(builder, i);
		if (ret)
			return ret;
	}

	return 0;
}

static int apply_role_uses(struct hdn_policy_builder *builder)
{
	uint32_t i;

	for (i = 0; i < builder->role_use_count; i++) {
		const struct hdn_role_use *role_use = &builder->role_uses[i];
		struct hdn_profile_builder *profile;
		struct hdn_role_builder *role;

		profile = find_profile(builder->profiles, role_use->profile_id);
		if (!profile) {
			fprintf(stderr, "%u: unknown use-role profile %llu\n",
				role_use->line,
				(unsigned long long)role_use->profile_id);
			return -ENOENT;
		}

		role = find_role(builder->roles, role_use->role_name);
		if (!role) {
			fprintf(stderr, "%u: unknown role '%s'\n",
				role_use->line, role_use->role_name);
			return -ENOENT;
		}

		profile->record.authority_allow |= role->authority_allow;
		profile->record.authority_allow_hi |= role->authority_allow_hi;
		profile->record.authority_audit |= role->authority_audit;
		profile->record.authority_audit_hi |= role->authority_audit_hi;
		profile->record.memory_flags |= role->memory_flags;
		profile->record.flags |= role->flags;
		profile->record.capability_deny |= role->capability_deny;
		profile->record.capability_audit |= role->capability_audit;
	}

	return 0;
}

static int build_records(const struct hdn_profile_builder *profiles,
			 struct hdn_profile_record *records, uint32_t *count)
{
	size_t i;

	*count = 0;
	for (i = 0; i < HDN_MAX_PROFILES; i++) {
		if (!profiles[i].present)
			continue;
		records[*count] = profiles[i].record;
		(*count)++;
	}

	return *count ? 0 : -EINVAL;
}

static int write_policy(const char *path,
			const struct hdn_profile_record *records,
			uint32_t count,
			const struct hdn_subject_rule_record *subject_rules,
			uint32_t subject_rule_count,
			const struct hdn_object_rule_record *object_rules,
			uint32_t object_rule_count,
			const struct hdn_exec_rule_record *exec_rules,
			uint32_t exec_rule_count,
			const struct hdn_module_rule_record *module_rules,
			uint32_t module_rule_count,
			const struct hdn_firmware_rule_record *firmware_rules,
			uint32_t firmware_rule_count,
			const struct hdn_resource_rule_record *resource_rules,
			uint32_t resource_rule_count, uint64_t generation,
			uint64_t expected_generation,
			uint64_t default_profile, uint64_t privileged_profile)
{
	struct hdn_policy_header header = {
		.magic = HDN_POLICY_MAGIC,
		.abi_version = HDN_POLICY_ABI_VERSION,
		.header_size = sizeof(header),
		.profile_size = sizeof(records[0]),
		.profile_count = count,
		.subject_rule_size = sizeof(subject_rules[0]),
		.subject_rule_count = subject_rule_count,
		.object_rule_size = sizeof(object_rules[0]),
		.object_rule_count = object_rule_count,
		.exec_rule_size = sizeof(exec_rules[0]),
		.exec_rule_count = exec_rule_count,
		.module_rule_size = sizeof(module_rules[0]),
		.module_rule_count = module_rule_count,
		.firmware_rule_size = sizeof(firmware_rules[0]),
		.firmware_rule_count = firmware_rule_count,
		.resource_rule_size = sizeof(resource_rules[0]),
		.resource_rule_count = resource_rule_count,
		.generation = generation,
		.expected_generation = expected_generation,
		.default_profile_id = default_profile,
		.privileged_profile_id = privileged_profile,
	};
	FILE *file;

	file = fopen(path, "wb");
	if (!file) {
		perror(path);
		return -errno;
	}

	if (fwrite(&header, sizeof(header), 1, file) != 1 ||
	    fwrite(records, sizeof(records[0]), count, file) != count ||
	    fwrite(subject_rules, sizeof(subject_rules[0]),
		   subject_rule_count, file) != subject_rule_count ||
	    fwrite(object_rules, sizeof(object_rules[0]),
		   object_rule_count, file) != object_rule_count ||
	    fwrite(exec_rules, sizeof(exec_rules[0]), exec_rule_count, file) !=
	    exec_rule_count ||
	    fwrite(module_rules, sizeof(module_rules[0]), module_rule_count,
		   file) != module_rule_count ||
	    fwrite(firmware_rules, sizeof(firmware_rules[0]),
		   firmware_rule_count, file) != firmware_rule_count ||
	    fwrite(resource_rules, sizeof(resource_rules[0]),
		   resource_rule_count, file) != resource_rule_count) {
		perror(path);
		fclose(file);
		return -EIO;
	}

	if (fclose(file)) {
		perror(path);
		return -EIO;
	}

	return 0;
}

static bool profile_id_present(const struct hdn_profile_record *records,
			       uint32_t count, uint64_t id)
{
	uint32_t i;

	for (i = 0; i < count; i++) {
		if (records[i].profile_id == id)
			return true;
	}

	return false;
}

static int validate_policy(const struct hdn_profile_record *records,
			   uint32_t count,
			   const struct hdn_subject_rule_record *subject_rules,
			   uint32_t subject_rule_count,
			   const struct hdn_object_rule_record *object_rules,
			   uint32_t object_rule_count,
			   const struct hdn_resource_rule_record *resource_rules,
			   uint32_t resource_rule_count,
			   uint64_t default_profile, uint64_t privileged_profile)
{
	uint32_t i;

	if (!profile_id_present(records, count, default_profile)) {
		fprintf(stderr, "default profile %llu is missing\n",
			(unsigned long long)default_profile);
		return -EINVAL;
	}

	if (!profile_id_present(records, count, privileged_profile)) {
		fprintf(stderr, "privileged profile %llu is missing\n",
			(unsigned long long)privileged_profile);
		return -EINVAL;
	}

	for (i = 0; i < subject_rule_count; i++) {
		if (!profile_id_present(records, count,
					subject_rules[i].profile_id)) {
			fprintf(stderr,
				"subject rule %u target profile %llu is missing\n",
				i,
				(unsigned long long)subject_rules[i].profile_id);
			return -EINVAL;
		}
	}

	for (i = 0; i < object_rule_count; i++) {
		if (!profile_id_present(records, count,
					object_rules[i].profile_id)) {
			fprintf(stderr,
				"object rule %u profile %llu is missing\n",
				i,
				(unsigned long long)object_rules[i].profile_id);
			return -EINVAL;
		}
	}

	for (i = 0; i < resource_rule_count; i++) {
		if (!profile_id_present(records, count,
					resource_rules[i].profile_id)) {
			fprintf(stderr,
				"resource rule %u profile %llu is missing\n",
				i,
				(unsigned long long)resource_rules[i].profile_id);
			return -EINVAL;
		}
		if (resource_rules[i].resource >= RLIM_NLIMITS) {
			fprintf(stderr, "resource rule %u has invalid resource\n",
				i);
			return -EINVAL;
		}
		if (resource_rules[i].soft_limit >
		    resource_rules[i].hard_limit) {
			fprintf(stderr,
				"resource rule %u soft limit exceeds hard limit\n",
				i);
			return -EINVAL;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct hdn_policy_builder builder = {};
	struct hdn_profile_record records[HDN_MAX_PROFILES] = {};
	uint64_t generation = 1;
	uint64_t expected_generation = HDN_POLICY_EXPECT_ANY;
	uint64_t default_profile = HDN_PROFILE_DEFAULT;
	uint64_t privileged_profile = HDN_PROFILE_PRIVILEGED;
	uint32_t count;
	int ret;

	if (argc != 3) {
		usage(argv[0]);
		return 2;
	}

	ret = read_policy(argv[1], &builder, &generation, &default_profile,
			  &privileged_profile, &expected_generation);
	if (ret)
		return 1;

	ret = expand_roles(&builder);
	if (ret)
		return 1;

	ret = apply_role_uses(&builder);
	if (ret)
		return 1;

	ret = build_records(builder.profiles, records, &count);
	if (ret) {
		fprintf(stderr, "policy contains no profiles\n");
		return 1;
	}

	ret = validate_policy(records, count, builder.subject_rules,
			      builder.subject_rule_count, builder.object_rules,
			      builder.object_rule_count, builder.resource_rules,
			      builder.resource_rule_count, default_profile,
			      privileged_profile);
	if (ret)
		return 1;

	ret = write_policy(argv[2], records, count, builder.subject_rules,
			   builder.subject_rule_count, builder.object_rules,
			   builder.object_rule_count, builder.exec_rules,
			   builder.exec_rule_count, builder.module_rules,
			   builder.module_rule_count, builder.firmware_rules,
			   builder.firmware_rule_count, builder.resource_rules,
			   builder.resource_rule_count, generation,
			   expected_generation,
			   default_profile, privileged_profile);
	if (ret)
		return 1;

	return 0;
}
