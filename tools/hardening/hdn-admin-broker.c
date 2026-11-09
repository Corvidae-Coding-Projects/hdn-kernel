// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/hardening.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef HDN_ROFS_APPLY_PATH
#define HDN_ROFS_APPLY_PATH "/usr/libexec/hdn-rofs-apply"
#endif

#ifndef HDN_ROFS_TRANSACTION_PATH
#define HDN_ROFS_TRANSACTION_PATH "/usr/libexec/hdn-rofs-transaction"
#endif

#ifndef HDN_SECURITYFS_DIR
#define HDN_SECURITYFS_DIR "/sys/kernel/security/hardening"
#endif

#ifndef HDN_ADMIN_BROKER_CONFIG
#define HDN_ADMIN_BROKER_CONFIG "/etc/hdn/admin-broker.conf"
#endif

#define HDN_POLICY_PATH HDN_SECURITYFS_DIR "/policy"
#define HDN_COMMIT_PATH HDN_SECURITYFS_DIR "/commit"
#define HDN_ROLLBACK_PATH HDN_SECURITYFS_DIR "/rollback"
#define HDN_MAX_SIGNED_POLICY_SIZE (HDN_MAX_POLICY_SIZE + 131072)
#define HDN_APPROVAL_TOKEN_MAX_SIZE 4096
#define HDN_APPROVAL_TOKEN_MAGIC "HDN_APPROVAL_V1\n"
#define HDN_BROKER_MAX_RULES 128

struct hdn_broker_policy {
	char *rofs_mounts[HDN_BROKER_MAX_RULES];
	char *rofs_workers[HDN_BROKER_MAX_RULES];
	char *rofs_apply_lists[HDN_BROKER_MAX_RULES];
	char *policy_dirs[HDN_BROKER_MAX_RULES];
	char *approval_token_dirs[HDN_BROKER_MAX_RULES];
	unsigned int rofs_mount_count;
	unsigned int rofs_worker_count;
	unsigned int rofs_apply_list_count;
	unsigned int policy_dir_count;
	unsigned int approval_token_dir_count;
	bool allow_policy_rollback;
	bool require_approval_token;
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s [--dry-run] seal-readonly [-r|--recursive] [-f PATHS.conf] [MOUNTPOINT...]\n"
		"  %s [--dry-run] [--approval-token TOKEN] rofs-apply [-r|--recursive] [-f PATHS.conf] [MOUNTPOINT...]\n"
		"  %s [--dry-run] [--approval-token TOKEN] rofs-transaction MOUNTPOINT -- WORKER [ARG...]\n"
		"  %s [--dry-run] [--approval-token TOKEN] policy-commit SIGNED_POLICY\n"
		"  %s [--dry-run] [--approval-token TOKEN] policy-rollback\n"
		"\n"
		"Product allowlist: %s\n",
		prog, prog, prog, prog, prog, HDN_ADMIN_BROKER_CONFIG);
}

static int require_absolute(const char *what, const char *path)
{
	if (path && path[0] == '/')
		return 0;

	fprintf(stderr, "hdn-admin-broker: %s must be an absolute path: %s\n",
		what, path ? path : "(null)");
	return -EINVAL;
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

static bool path_has_dot_component(const char *path)
{
	const char *part = path;

	while (*part) {
		size_t len;
		const char *slash;

		while (*part == '/')
			part++;
		if (!*part)
			break;

		slash = strchr(part, '/');
		len = slash ? (size_t)(slash - part) : strlen(part);
		if ((len == 1 && part[0] == '.') ||
		    (len == 2 && part[0] == '.' && part[1] == '.'))
			return true;
		part += len;
	}

	return false;
}

static int require_safe_absolute(const char *what, const char *path)
{
	int ret;

	ret = require_absolute(what, path);
	if (ret)
		return ret;

	if (path_has_dot_component(path)) {
		fprintf(stderr,
			"hdn-admin-broker: %s must not contain . or .. path components: %s\n",
			what, path);
		return -EINVAL;
	}

	return 0;
}

static int add_path_rule(char **rules, unsigned int *count, const char *kind,
			 const char *path)
{
	char *copy;
	int ret;

	ret = require_safe_absolute(kind, path);
	if (ret)
		return ret;

	if (*count >= HDN_BROKER_MAX_RULES) {
		fprintf(stderr, "hdn-admin-broker: too many %s rules\n", kind);
		return -E2BIG;
	}

	copy = strdup(path);
	if (!copy) {
		fprintf(stderr, "hdn-admin-broker: allocation failed\n");
		return -ENOMEM;
	}

	rules[(*count)++] = copy;
	return 0;
}

static bool path_allowed_exact(char *const rules[], unsigned int count,
			       const char *path)
{
	unsigned int i;

	for (i = 0; i < count; i++) {
		if (!strcmp(rules[i], path))
			return true;
	}

	return false;
}

static bool path_allowed_under_dir(char *const rules[], unsigned int count,
				   const char *path)
{
	unsigned int i;

	for (i = 0; i < count; i++) {
		const char *dir = rules[i];
		size_t len = strlen(dir);

		if (len == 1 && dir[0] == '/')
			continue;
		if (dir[len - 1] == '/') {
			if (!strncmp(path, dir, len) && path[len])
				return true;
		} else if (!strncmp(path, dir, len) && path[len] == '/') {
			return true;
		}
	}

	return false;
}

static int deny_unlisted(const char *what, const char *path)
{
	fprintf(stderr, "hdn-admin-broker: %s is not product-approved: %s\n",
		what, path);
	return 1;
}

static int parse_policy_line(struct hdn_broker_policy *policy, char *line,
			     unsigned int lineno)
{
	char *value;
	char *key;

	key = trim(line);
	if (!key[0] || key[0] == '#')
		return 0;

	value = strpbrk(key, " \t");
	if (value) {
		*value++ = '\0';
		value = trim(value);
	}

	if (!strcmp(key, "rofs-mount")) {
		if (!value || !value[0])
			goto missing_value;
		return add_path_rule(policy->rofs_mounts,
				     &policy->rofs_mount_count, key, value);
	}
	if (!strcmp(key, "rofs-worker")) {
		if (!value || !value[0])
			goto missing_value;
		return add_path_rule(policy->rofs_workers,
				     &policy->rofs_worker_count, key, value);
	}
	if (!strcmp(key, "rofs-apply-list")) {
		if (!value || !value[0])
			goto missing_value;
		return add_path_rule(policy->rofs_apply_lists,
				     &policy->rofs_apply_list_count, key,
				     value);
	}
	if (!strcmp(key, "policy-dir")) {
		if (!value || !value[0])
			goto missing_value;
		if (!strcmp(value, "/")) {
			fprintf(stderr,
				"hdn-admin-broker: policy-dir / is too broad at line %u\n",
				lineno);
			return -EINVAL;
		}
		return add_path_rule(policy->policy_dirs,
				     &policy->policy_dir_count, key, value);
	}
	if (!strcmp(key, "approval-token-dir")) {
		if (!value || !value[0])
			goto missing_value;
		if (!strcmp(value, "/")) {
			fprintf(stderr,
				"hdn-admin-broker: approval-token-dir / is too broad at line %u\n",
				lineno);
			return -EINVAL;
		}
		return add_path_rule(policy->approval_token_dirs,
				     &policy->approval_token_dir_count, key,
				     value);
	}
	if (!strcmp(key, "allow-policy-rollback")) {
		if (value && value[0])
			goto unexpected_value;
		policy->allow_policy_rollback = true;
		return 0;
	}
	if (!strcmp(key, "require-approval-token")) {
		if (value && value[0])
			goto unexpected_value;
		policy->require_approval_token = true;
		return 0;
	}

	fprintf(stderr, "hdn-admin-broker: unknown allowlist key at line %u: %s\n",
		lineno, key);
	return -EINVAL;

missing_value:
	fprintf(stderr, "hdn-admin-broker: missing value for %s at line %u\n",
		key, lineno);
	return -EINVAL;
unexpected_value:
	fprintf(stderr,
		"hdn-admin-broker: unexpected value for %s at line %u\n",
		key, lineno);
	return -EINVAL;
}

static int open_policy_config(void)
{
	struct stat st;
	int flags = O_RDONLY | O_CLOEXEC;
	int fd;

#ifdef O_NOFOLLOW
	flags |= O_NOFOLLOW;
#endif

	fd = open(HDN_ADMIN_BROKER_CONFIG, flags);
	if (fd < 0) {
		fprintf(stderr, "hdn-admin-broker: cannot open %s: %s\n",
			HDN_ADMIN_BROKER_CONFIG, strerror(errno));
		return -errno;
	}

	if (fstat(fd, &st)) {
		int ret = -errno;

		fprintf(stderr, "hdn-admin-broker: cannot stat %s: %s\n",
			HDN_ADMIN_BROKER_CONFIG, strerror(errno));
		close(fd);
		return ret;
	}

	if (!S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 022)) {
		fprintf(stderr,
			"hdn-admin-broker: refusing unsafe allowlist file %s\n",
			HDN_ADMIN_BROKER_CONFIG);
		close(fd);
		return -EACCES;
	}

	return fd;
}

static int load_broker_policy(struct hdn_broker_policy *policy)
{
	char *line = NULL;
	size_t size = 0;
	unsigned int lineno = 0;
	ssize_t len;
	FILE *file;
	int ret = 0;
	int fd;

	memset(policy, 0, sizeof(*policy));

	fd = open_policy_config();
	if (fd < 0)
		return fd;

	file = fdopen(fd, "r");
	if (!file) {
		ret = -errno;
		fprintf(stderr, "hdn-admin-broker: fdopen %s failed: %s\n",
			HDN_ADMIN_BROKER_CONFIG, strerror(errno));
		close(fd);
		return ret;
	}

	while ((len = getline(&line, &size, file)) >= 0) {
		(void)len;
		lineno++;
		ret = parse_policy_line(policy, line, lineno);
		if (ret)
			break;
	}

	if (ferror(file) && !ret)
		ret = -EIO;

	free(line);
	fclose(file);
	return ret;
}

static void free_broker_policy(struct hdn_broker_policy *policy)
{
	unsigned int i;

	for (i = 0; i < policy->rofs_mount_count; i++)
		free(policy->rofs_mounts[i]);
	for (i = 0; i < policy->rofs_worker_count; i++)
		free(policy->rofs_workers[i]);
	for (i = 0; i < policy->rofs_apply_list_count; i++)
		free(policy->rofs_apply_lists[i]);
	for (i = 0; i < policy->policy_dir_count; i++)
		free(policy->policy_dirs[i]);
	for (i = 0; i < policy->approval_token_dir_count; i++)
		free(policy->approval_token_dirs[i]);
}

static bool token_has_line(const char *token, const char *line)
{
	const char *match = token;
	size_t line_len = strlen(line);

	while ((match = strstr(match, line))) {
		if ((match == token || match[-1] == '\n') &&
		    match[line_len] == '\n')
			return true;
		match += line_len;
	}

	return false;
}

static bool token_read_u64_line(const char *token, const char *key,
				unsigned long long *value)
{
	const char *line = token;
	size_t key_len = strlen(key);

	while ((line = strstr(line, key))) {
		char *end;

		if (line != token && line[-1] != '\n') {
			line += key_len;
			continue;
		}

		errno = 0;
		*value = strtoull(line + key_len, &end, 10);
		return !errno && end != line + key_len && *end == '\n';
	}

	return false;
}

static int monotonic_milliseconds(unsigned long long *now_ms)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return -errno;
	if (ts.tv_sec < 0)
		return -EINVAL;
	if ((unsigned long long)ts.tv_sec >
	    (ULLONG_MAX - (unsigned long long)(ts.tv_nsec / 1000000)) / 1000)
		return -EOVERFLOW;

	*now_ms = (unsigned long long)ts.tv_sec * 1000 +
		  (unsigned long long)(ts.tv_nsec / 1000000);
	return 0;
}

static int validate_approval_token(const struct hdn_broker_policy *policy,
				   const char *intent, const char *path,
				   bool dry_run)
{
	char expected[128];
	char buf[HDN_APPROVAL_TOKEN_MAX_SIZE + 1];
	unsigned long long expires_ms = 0;
	unsigned long long now_ms = 0;
	struct stat st;
	ssize_t len;
	size_t done = 0;
	int flags = O_RDONLY | O_CLOEXEC;
	int fd;
	int ret = 0;

	if (!policy->require_approval_token && !path)
		return 0;

	if (!path) {
		fprintf(stderr,
			"hdn-admin-broker: approval token required for %s\n",
			intent);
		return 1;
	}

	if (require_safe_absolute("approval token", path))
		return 1;
	if (!path_allowed_under_dir(policy->approval_token_dirs,
				    policy->approval_token_dir_count, path))
		return deny_unlisted("approval token", path);

#ifdef O_NOFOLLOW
	flags |= O_NOFOLLOW;
#endif

	fd = open(path, flags);
	if (fd < 0) {
		fprintf(stderr, "hdn-admin-broker: cannot open approval token %s: %s\n",
			path, strerror(errno));
		return 1;
	}

	if (fstat(fd, &st)) {
		fprintf(stderr, "hdn-admin-broker: cannot stat approval token %s: %s\n",
			path, strerror(errno));
		ret = 1;
		goto out_close;
	}

	if (!S_ISREG(st.st_mode) || st.st_uid != 0 || st.st_nlink != 1 ||
	    (st.st_mode & 077) || st.st_size <= 0 ||
	    st.st_size > HDN_APPROVAL_TOKEN_MAX_SIZE) {
		fprintf(stderr,
			"hdn-admin-broker: refusing unsafe approval token %s\n",
			path);
		ret = 1;
		goto out_close;
	}

	while (done < (size_t)st.st_size) {
		len = read(fd, buf + done, (size_t)st.st_size - done);
		if (len < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr,
				"hdn-admin-broker: read approval token %s failed: %s\n",
				path, strerror(errno));
			ret = 1;
			goto out_close;
		}
		if (!len) {
			fprintf(stderr,
				"hdn-admin-broker: short read from approval token %s\n",
				path);
			ret = 1;
			goto out_close;
		}
		done += (size_t)len;
	}
	buf[done] = '\0';

	if (strncmp(buf, HDN_APPROVAL_TOKEN_MAGIC,
		    strlen(HDN_APPROVAL_TOKEN_MAGIC))) {
		fprintf(stderr,
			"hdn-admin-broker: invalid approval token magic in %s\n",
			path);
		ret = 1;
		goto out_close;
	}

	if (snprintf(expected, sizeof(expected), "intent=%s", intent) >=
	    (int)sizeof(expected) || !token_has_line(buf, expected)) {
		fprintf(stderr,
			"hdn-admin-broker: approval token %s does not authorize %s\n",
			path, intent);
		ret = 1;
		goto out_close;
	}

	if (!token_read_u64_line(buf, "expires-monotonic-ms=", &expires_ms)) {
		fprintf(stderr,
			"hdn-admin-broker: approval token %s has no valid expiry\n",
			path);
		ret = 1;
		goto out_close;
	}
	if (monotonic_milliseconds(&now_ms)) {
		fprintf(stderr,
			"hdn-admin-broker: cannot read monotonic clock for approval token\n");
		ret = 1;
		goto out_close;
	}
	if (expires_ms <= now_ms) {
		fprintf(stderr,
			"hdn-admin-broker: approval token %s is expired\n", path);
		ret = 1;
		goto out_close;
	}

	if (!dry_run && unlink(path)) {
		fprintf(stderr,
			"hdn-admin-broker: cannot consume approval token %s: %s\n",
			path, strerror(errno));
		ret = 1;
	}

out_close:
	close(fd);
	return ret;
}

static char **alloc_argv(int argc)
{
	char **argv;

	argv = calloc((size_t)argc + 1, sizeof(*argv));
	if (!argv)
		fprintf(stderr, "hdn-admin-broker: allocation failed\n");
	return argv;
}

static void print_argv(char *const argv[])
{
	int i;

	for (i = 0; argv[i]; i++)
		printf(" %s", argv[i]);
	printf("\n");
}

static int exec_intent(const char *intent, char *const argv[], bool dry_run)
{
	int exec_errno;

	if (dry_run) {
		printf("hdn-admin-broker: intent=%s\n", intent);
		printf("hdn-admin-broker: exec");
		print_argv(argv);
		return 0;
	}

	execv(argv[0], argv);
	exec_errno = errno;
	fprintf(stderr, "hdn-admin-broker: exec %s failed: %s\n", argv[0],
		strerror(exec_errno));
	return exec_errno == ENOENT ? 127 : 126;
}

static int run_rofs_apply(const char *intent, int argc, char **argv,
			  bool dry_run,
			  const struct hdn_broker_policy *policy)
{
	bool saw_path = false;
	bool saw_config = false;
	char **child_argv;
	int child_argc;
	int ret = 0;
	int i;

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "-r") || !strcmp(argv[i], "--recursive"))
			continue;
		if (!strcmp(argv[i], "-f") || !strcmp(argv[i], "--file")) {
			if (++i >= argc) {
				usage("hdn-admin-broker");
				return 2;
			}
			ret = require_absolute("readonly mount list", argv[i]);
			if (ret)
				return 2;
			if (!path_allowed_exact(policy->rofs_apply_lists,
						policy->rofs_apply_list_count,
						argv[i]))
				return deny_unlisted("readonly mount list",
						     argv[i]);
			saw_config = true;
			continue;
		}
		if (argv[i][0] == '-') {
			usage("hdn-admin-broker");
			return 2;
		}

		ret = require_absolute("mountpoint", argv[i]);
		if (ret)
			return 2;
		if (!path_allowed_exact(policy->rofs_mounts,
					policy->rofs_mount_count, argv[i]))
			return deny_unlisted("mountpoint", argv[i]);
		saw_path = true;
	}

	if (!saw_config && !saw_path) {
		usage("hdn-admin-broker");
		return 2;
	}

	child_argc = argc + 1;
	child_argv = alloc_argv(child_argc);
	if (!child_argv)
		return 1;

	child_argv[0] = (char *)HDN_ROFS_APPLY_PATH;
	for (i = 0; i < argc; i++)
		child_argv[i + 1] = argv[i];

	ret = exec_intent(intent, child_argv, dry_run);
	free(child_argv);
	return ret;
}

static int run_rofs_transaction(int argc, char **argv, bool dry_run,
				const struct hdn_broker_policy *policy)
{
	char **child_argv;
	int ret;
	int i;

	if (argc < 3 || strcmp(argv[1], "--")) {
		usage("hdn-admin-broker");
		return 2;
	}

	ret = require_absolute("mountpoint", argv[0]);
	if (ret)
		return 2;
	ret = require_absolute("worker", argv[2]);
	if (ret)
		return 2;
	if (!path_allowed_exact(policy->rofs_mounts, policy->rofs_mount_count,
				argv[0]))
		return deny_unlisted("mountpoint", argv[0]);
	if (!path_allowed_exact(policy->rofs_workers,
				policy->rofs_worker_count, argv[2]))
		return deny_unlisted("worker", argv[2]);

	child_argv = alloc_argv(argc + 1);
	if (!child_argv)
		return 1;

	child_argv[0] = (char *)HDN_ROFS_TRANSACTION_PATH;
	for (i = 0; i < argc; i++)
		child_argv[i + 1] = argv[i];

	ret = exec_intent("rofs-transaction", child_argv, dry_run);
	free(child_argv);
	return ret;
}

static int read_whole_file(const char *path, unsigned char **data, size_t *size)
{
	unsigned char *buf;
	struct stat st;
	ssize_t len;
	size_t done = 0;
	int flags = O_RDONLY | O_CLOEXEC;
	int fd;
	int ret = 0;

#ifdef O_NOFOLLOW
	flags |= O_NOFOLLOW;
#endif

	fd = open(path, flags);
	if (fd < 0) {
		fprintf(stderr, "hdn-admin-broker: cannot open %s: %s\n", path,
			strerror(errno));
		return -errno;
	}

	if (fstat(fd, &st)) {
		ret = -errno;
		fprintf(stderr, "hdn-admin-broker: cannot stat %s: %s\n", path,
			strerror(errno));
		goto out_close;
	}
	if (!S_ISREG(st.st_mode) || st.st_size <= 0 ||
	    st.st_size > HDN_MAX_SIGNED_POLICY_SIZE) {
		fprintf(stderr, "hdn-admin-broker: invalid policy blob: %s\n",
			path);
		ret = -EINVAL;
		goto out_close;
	}

	buf = malloc((size_t)st.st_size);
	if (!buf) {
		ret = -ENOMEM;
		fprintf(stderr, "hdn-admin-broker: allocation failed\n");
		goto out_close;
	}

	while (done < (size_t)st.st_size) {
		len = read(fd, buf + done, (size_t)st.st_size - done);
		if (len < 0) {
			if (errno == EINTR)
				continue;
			ret = -errno;
			fprintf(stderr, "hdn-admin-broker: read %s failed: %s\n",
				path, strerror(errno));
			goto out_free;
		}
		if (!len) {
			ret = -EIO;
			fprintf(stderr, "hdn-admin-broker: short read from %s\n",
				path);
			goto out_free;
		}
		done += (size_t)len;
	}

	*data = buf;
	*size = done;
	goto out_close;

out_free:
	free(buf);
out_close:
	close(fd);
	return ret;
}

static int write_blob_once(const char *path, const void *buf, size_t size)
{
	ssize_t len;
	int fd;
	int ret = 0;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "hdn-admin-broker: cannot open %s: %s\n", path,
			strerror(errno));
		return -errno;
	}

	do {
		len = write(fd, buf, size);
	} while (len < 0 && errno == EINTR);

	if (len < 0) {
		ret = -errno;
		fprintf(stderr, "hdn-admin-broker: write %s failed: %s\n",
			path, strerror(errno));
	} else if ((size_t)len != size) {
		ret = -EIO;
		fprintf(stderr, "hdn-admin-broker: short write to %s\n", path);
	}

	close(fd);
	return ret;
}

static int write_text_once(const char *path, const char *text)
{
	return write_blob_once(path, text, strlen(text));
}

static int run_policy_commit(int argc, char **argv, bool dry_run,
			     const struct hdn_broker_policy *policy)
{
	unsigned char *blob = NULL;
	size_t size = 0;
	int ret;

	if (argc != 1) {
		usage("hdn-admin-broker");
		return 2;
	}

	ret = require_absolute("signed policy", argv[0]);
	if (ret)
		return 2;
	if (path_has_dot_component(argv[0]))
		return deny_unlisted("signed policy", argv[0]);
	if (!path_allowed_under_dir(policy->policy_dirs,
				    policy->policy_dir_count, argv[0]))
		return deny_unlisted("signed policy", argv[0]);

	if (dry_run) {
		printf("hdn-admin-broker: intent=policy-commit\n");
		printf("hdn-admin-broker: write %s -> %s\n", argv[0],
		       HDN_POLICY_PATH);
		printf("hdn-admin-broker: write 1 -> %s\n", HDN_COMMIT_PATH);
		return 0;
	}

	ret = read_whole_file(argv[0], &blob, &size);
	if (ret)
		return 1;

	ret = write_blob_once(HDN_POLICY_PATH, blob, size);
	free(blob);
	if (ret)
		return 1;

	return write_text_once(HDN_COMMIT_PATH, "1\n") ? 1 : 0;
}

static int run_policy_rollback(int argc, bool dry_run,
			       const struct hdn_broker_policy *policy)
{
	if (argc) {
		usage("hdn-admin-broker");
		return 2;
	}

	if (!policy->allow_policy_rollback) {
		fprintf(stderr,
			"hdn-admin-broker: policy rollback is not product-approved\n");
		return 1;
	}

	if (dry_run) {
		printf("hdn-admin-broker: intent=policy-rollback\n");
		printf("hdn-admin-broker: write 1 -> %s\n", HDN_ROLLBACK_PATH);
		return 0;
	}

	return write_text_once(HDN_ROLLBACK_PATH, "1\n") ? 1 : 0;
}

int main(int argc, char **argv)
{
	struct hdn_broker_policy policy;
	const char *approval_token = NULL;
	bool dry_run = false;
	const char *prog = argv[0];
	const char *intent;
	int ret;

	if (argc < 2) {
		usage(prog);
		return 2;
	}

	while (argc >= 2 && argv[1][0] == '-') {
		if (!strcmp(argv[1], "--dry-run")) {
			dry_run = true;
			argv++;
			argc--;
			continue;
		}
		if (!strcmp(argv[1], "--approval-token")) {
			if (argc < 3) {
				usage(prog);
				return 2;
			}
			approval_token = argv[2];
			argv += 2;
			argc -= 2;
			continue;
		}
		if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
			usage(prog);
			return 0;
		}
		usage(prog);
		return 2;
	}

	if (argc < 2) {
		usage(prog);
		return 2;
	}
	intent = argv[1];
	argv += 2;
	argc -= 2;

	ret = load_broker_policy(&policy);
	if (ret)
		return 1;

	/*
	 * seal-readonly is deliberately monotonic: it can only apply an
	 * allowlisted read-only mount list. It is used during boot before any
	 * interactive authorization service exists. Every operation that can
	 * open a writable window or change policy remains token-gated.
	 */
	if (strcmp(intent, "seal-readonly")) {
		ret = validate_approval_token(&policy, intent, approval_token,
					      dry_run);
		if (ret)
			goto out_free;
	} else if (approval_token) {
		fprintf(stderr,
			"hdn-admin-broker: seal-readonly does not accept approval tokens\n");
		ret = 2;
		goto out_free;
	}

	if (!strcmp(intent, "seal-readonly") || !strcmp(intent, "rofs-apply"))
		ret = run_rofs_apply(intent, argc, argv, dry_run, &policy);
	else if (!strcmp(intent, "rofs-transaction"))
		ret = run_rofs_transaction(argc, argv, dry_run, &policy);
	else if (!strcmp(intent, "policy-commit"))
		ret = run_policy_commit(argc, argv, dry_run, &policy);
	else if (!strcmp(intent, "policy-rollback"))
		ret = run_policy_rollback(argc, dry_run, &policy);
	else {
		usage("hdn-admin-broker");
		ret = 2;
	}

out_free:
	free_broker_policy(&policy);
	return ret;
}
