// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <linux/hardening.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

struct name_value {
	const char *name;
	uint64_t value;
};

struct hdn_merge_profile {
	bool present;
	uint64_t id;
	uint64_t authority_allow;
	uint64_t authority_allow_hi;
	uint64_t memory_flags;
	uint64_t suggested_authority_allow;
	uint64_t suggested_authority_allow_hi;
	uint64_t suggested_memory_flags;
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

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s BASE.policy LEARN.frag OUTPUT.policy\n"
		"\n"
		"Appends reviewed hdn-policy-learn allow/mem suggestions to a\n"
		"candidate policy file without rewriting the base policy.\n",
		prog);
}

static void normalize_token(const char *input, char *output, size_t size)
{
	size_t i;

	for (i = 0; i + 1 < size && input[i]; i++) {
		unsigned char c = input[i];

		output[i] = c == '-' ? '_' : (char)toupper(c);
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
}

static int parse_u64(const char *text, uint64_t *value)
{
	char *end;
	unsigned long long parsed;

	errno = 0;
	parsed = strtoull(text, &end, 0);
	if (errno || end == text || *end)
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

static const char *value_name(const struct name_value *names, size_t count,
			      uint64_t value)
{
	size_t i;

	for (i = 0; i < count; i++) {
		if (names[i].value == value)
			return names[i].name;
	}

	return "UNKNOWN";
}

static struct hdn_merge_profile *
find_profile(struct hdn_merge_profile *profiles, uint64_t id)
{
	size_t i;

	for (i = 0; i < HDN_MAX_PROFILES; i++) {
		if (profiles[i].present && profiles[i].id == id)
			return &profiles[i];
	}

	return NULL;
}

static int add_profile(struct hdn_merge_profile *profiles, uint64_t id)
{
	size_t i;

	if (!id)
		return -EINVAL;
	if (find_profile(profiles, id))
		return 0;

	for (i = 0; i < HDN_MAX_PROFILES; i++) {
		if (!profiles[i].present) {
			profiles[i].present = true;
			profiles[i].id = id;
			return 0;
		}
	}

	return -ENOSPC;
}

static int parse_profile_line(struct hdn_merge_profile *profiles, char *save,
			      unsigned int line_number)
{
	char *id_text;
	uint64_t id;
	int ret;

	id_text = strtok_r(NULL, " \t\r\n", &save);
	if (!id_text) {
		fprintf(stderr, "%u: profile needs an ID\n", line_number);
		return -EINVAL;
	}

	ret = parse_u64(id_text, &id);
	if (ret) {
		fprintf(stderr, "%u: invalid profile ID '%s'\n",
			line_number, id_text);
		return ret;
	}

	ret = add_profile(profiles, id);
	if (ret)
		fprintf(stderr, "%u: could not add profile %llu: %s\n",
			line_number, (unsigned long long)id, strerror(-ret));
	return ret;
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

static bool authority_mask_contains(uint64_t mask, uint64_t mask_hi,
				    uint64_t authority)
{
	if (authority >= HDN_AUTH__MAX || authority >= HDN_AUTHORITY_MAX_BITS)
		return false;
	if (HDN_AUTHORITY_WORD(authority) == 0)
		return mask & HDN_AUTHORITY_MASK(authority);
	if (HDN_AUTHORITY_WORD(authority) == 1)
		return mask_hi & HDN_AUTHORITY_MASK(authority);
	return false;
}

static int parse_mask_tokens(const struct name_value *names, size_t name_count,
			     char *save, uint64_t *id, uint64_t *mask,
			     uint64_t *mask_hi, unsigned int line_number)
{
	char *id_text;
	char *name;
	int ret;

	*mask = 0;
	if (mask_hi)
		*mask_hi = 0;
	id_text = strtok_r(NULL, " \t\r\n", &save);
	if (!id_text) {
		fprintf(stderr, "%u: suggestion needs profile ID\n",
			line_number);
		return -EINVAL;
	}

	ret = parse_u64(id_text, id);
	if (ret) {
		fprintf(stderr, "%u: invalid profile ID '%s'\n",
			line_number, id_text);
		return ret;
	}

	name = strtok_r(NULL, " \t\r\n", &save);
	if (!name) {
		fprintf(stderr, "%u: suggestion needs at least one token\n",
			line_number);
		return -EINVAL;
	}

	while (name) {
		uint64_t value;

		ret = lookup_name(names, name_count, name, &value);
		if (ret) {
			fprintf(stderr, "%u: unknown token '%s'\n",
				line_number, name);
			return ret;
		}
		if (names == authority_names) {
			ret = add_authority_mask(value, mask, mask_hi);
			if (ret)
				return ret;
		} else {
			*mask |= value;
		}
		name = strtok_r(NULL, " \t\r\n", &save);
	}

	return 0;
}

static int parse_base_line(struct hdn_merge_profile *profiles, char *line,
			   unsigned int line_number)
{
	struct hdn_merge_profile *profile;
	char *comment;
	char *command;
	char *save = NULL;
	uint64_t id;
	uint64_t mask;
	uint64_t mask_hi = 0;
	int ret;

	comment = strchr(line, '#');
	if (comment)
		*comment = '\0';

	command = strtok_r(line, " \t\r\n", &save);
	if (!command)
		return 0;

	if (!strcmp(command, "profile"))
		return parse_profile_line(profiles, save, line_number);
	if (strcmp(command, "allow") && strcmp(command, "mem"))
		return 0;

	if (!strcmp(command, "allow"))
		ret = parse_mask_tokens(authority_names,
					ARRAY_SIZE(authority_names), save, &id,
					&mask, &mask_hi, line_number);
	else
		ret = parse_mask_tokens(memory_flag_names,
					ARRAY_SIZE(memory_flag_names), save, &id,
					&mask, NULL, line_number);
	if (ret)
		return ret;

	profile = find_profile(profiles, id);
	if (!profile) {
		fprintf(stderr, "%u: unknown profile %llu\n", line_number,
			(unsigned long long)id);
		return -ENOENT;
	}

	if (!strcmp(command, "allow")) {
		profile->authority_allow |= mask;
		profile->authority_allow_hi |= mask_hi;
	} else {
		profile->memory_flags |= mask;
	}
	return 0;
}

static int parse_base_policy(const char *path,
			     struct hdn_merge_profile *profiles)
{
	char line[4096];
	unsigned int line_number = 0;
	FILE *file;
	int ret = 0;

	file = fopen(path, "r");
	if (!file) {
		fprintf(stderr, "hdn-policy-merge: cannot open %s: %s\n",
			path, strerror(errno));
		return -errno;
	}

	while (fgets(line, sizeof(line), file)) {
		line_number++;
		ret = parse_base_line(profiles, line, line_number);
		if (ret)
			break;
	}

	if (ferror(file) && !ret)
		ret = -EIO;
	fclose(file);
	return ret;
}

static int parse_suggestion_line(struct hdn_merge_profile *profiles, char *line,
				 unsigned int line_number)
{
	struct hdn_merge_profile *profile;
	char *comment;
	char *command;
	char *save = NULL;
	uint64_t id;
	uint64_t mask;
	uint64_t mask_hi = 0;
	int ret;

	comment = strchr(line, '#');
	if (comment)
		*comment = '\0';

	command = strtok_r(line, " \t\r\n", &save);
	if (!command)
		return 0;

	if (strcmp(command, "allow") && strcmp(command, "mem")) {
		fprintf(stderr, "%u: unsupported merge command '%s'\n",
			line_number, command);
		return -EINVAL;
	}

	if (!strcmp(command, "allow"))
		ret = parse_mask_tokens(authority_names,
					ARRAY_SIZE(authority_names), save, &id,
					&mask, &mask_hi, line_number);
	else
		ret = parse_mask_tokens(memory_flag_names,
					ARRAY_SIZE(memory_flag_names), save, &id,
					&mask, NULL, line_number);
	if (ret)
		return ret;

	profile = find_profile(profiles, id);
	if (!profile) {
		fprintf(stderr, "%u: suggestion references unknown profile %llu\n",
			line_number, (unsigned long long)id);
		return -ENOENT;
	}

	if (!strcmp(command, "allow")) {
		mask &= ~profile->authority_allow;
		mask_hi &= ~profile->authority_allow_hi;
		profile->suggested_authority_allow |= mask;
		profile->suggested_authority_allow_hi |= mask_hi;
		profile->authority_allow |= mask;
		profile->authority_allow_hi |= mask_hi;
	} else {
		mask &= ~profile->memory_flags;
		profile->suggested_memory_flags |= mask;
		profile->memory_flags |= mask;
	}

	return 0;
}

static int parse_suggestions(const char *path,
			     struct hdn_merge_profile *profiles)
{
	char line[4096];
	unsigned int line_number = 0;
	FILE *file;
	int ret = 0;

	file = fopen(path, "r");
	if (!file) {
		fprintf(stderr, "hdn-policy-merge: cannot open %s: %s\n",
			path, strerror(errno));
		return -errno;
	}

	while (fgets(line, sizeof(line), file)) {
		line_number++;
		ret = parse_suggestion_line(profiles, line, line_number);
		if (ret)
			break;
	}

	if (ferror(file) && !ret)
		ret = -EIO;
	fclose(file);
	return ret;
}

static bool profile_has_suggestions(const struct hdn_merge_profile *profile)
{
	return profile->suggested_authority_allow ||
	       profile->suggested_authority_allow_hi ||
	       profile->suggested_memory_flags;
}

static unsigned int write_authority_line(FILE *out,
					 const struct hdn_merge_profile *profile)
{
	unsigned int authority;
	unsigned int count = 0;

	if (!profile->suggested_authority_allow &&
	    !profile->suggested_authority_allow_hi)
		return 0;

	fprintf(out, "allow %llu", (unsigned long long)profile->id);
	for (authority = 1; authority < HDN_AUTH__MAX; authority++) {
		if (authority_mask_contains(
			    profile->suggested_authority_allow,
			    profile->suggested_authority_allow_hi,
			    authority)) {
			fprintf(out, " %s",
				value_name(authority_names,
					   ARRAY_SIZE(authority_names),
					   authority));
			count++;
		}
	}
	fprintf(out, "\n");
	return count;
}

static unsigned int write_memory_line(FILE *out,
				      const struct hdn_merge_profile *profile)
{
	unsigned int count = 0;
	size_t i;

	if (!profile->suggested_memory_flags)
		return 0;

	fprintf(out, "mem %llu", (unsigned long long)profile->id);
	for (i = 0; i < ARRAY_SIZE(memory_flag_names); i++) {
		if (profile->suggested_memory_flags & memory_flag_names[i].value) {
			fprintf(out, " %s", memory_flag_names[i].name);
			count++;
		}
	}
	fprintf(out, "\n");
	return count;
}

static int copy_base_policy(FILE *out, const char *path)
{
	char buf[4096];
	size_t len;
	int last = '\n';
	FILE *in;

	in = fopen(path, "r");
	if (!in) {
		fprintf(stderr, "hdn-policy-merge: cannot open %s: %s\n",
			path, strerror(errno));
		return -errno;
	}

	while ((len = fread(buf, 1, sizeof(buf), in)) > 0) {
		if (fwrite(buf, 1, len, out) != len) {
			fclose(in);
			return -EIO;
		}
		last = (unsigned char)buf[len - 1];
	}

	if (ferror(in)) {
		fclose(in);
		return -EIO;
	}
	fclose(in);

	if (last != '\n')
		fputc('\n', out);
	return 0;
}

static int write_merged_policy(const char *base, const char *learn,
			       const char *output,
			       const struct hdn_merge_profile *profiles)
{
	unsigned int count = 0;
	FILE *out;
	size_t i;
	int ret;

	out = fopen(output, "w");
	if (!out) {
		fprintf(stderr, "hdn-policy-merge: cannot open %s: %s\n",
			output, strerror(errno));
		return -errno;
	}

	ret = copy_base_policy(out, base);
	if (ret)
		goto out_close;

	fprintf(out, "\n# HDN_POLICY_MERGE_V1\n");
	fprintf(out, "# source %s\n", learn);
	fprintf(out, "# Review, compile, sign, and commit this candidate policy.\n");

	for (i = 0; i < HDN_MAX_PROFILES; i++) {
		if (!profiles[i].present || !profile_has_suggestions(&profiles[i]))
			continue;
		count += write_authority_line(out, &profiles[i]);
		count += write_memory_line(out, &profiles[i]);
	}
	if (!count)
		fprintf(out, "# no new allow/mem suggestions\n");

out_close:
	if (fclose(out) && !ret)
		ret = -EIO;
	return ret;
}

int main(int argc, char **argv)
{
	struct hdn_merge_profile profiles[HDN_MAX_PROFILES] = {};
	const char *base;
	const char *learn;
	const char *output;
	int ret;

	if (argc != 4 || !strcmp(argv[1], "--help")) {
		usage(argv[0]);
		return argc == 2 && !strcmp(argv[1], "--help") ? 0 : 2;
	}

	base = argv[1];
	learn = argv[2];
	output = argv[3];
	if (!strcmp(base, output) || !strcmp(learn, output)) {
		fprintf(stderr,
			"hdn-policy-merge: output must not replace input files\n");
		return 2;
	}

	ret = parse_base_policy(base, profiles);
	if (ret)
		return 2;
	ret = parse_suggestions(learn, profiles);
	if (ret)
		return 2;
	ret = write_merged_policy(base, learn, output, profiles);
	if (ret)
		return 2;

	return 0;
}
