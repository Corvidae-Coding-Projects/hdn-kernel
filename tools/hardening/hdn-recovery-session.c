// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef HDN_RECOVERY_SESSION_CONFIG
#define HDN_RECOVERY_SESSION_CONFIG "/etc/hdn/recovery-session.conf"
#endif

#ifndef HDN_RECOVERY_DESCRIBE_PATH
#define HDN_RECOVERY_DESCRIBE_PATH "/usr/libexec/hdn-recovery-describe"
#endif

#ifndef HDN_RECOVERY_ACTION_PATH
#define HDN_RECOVERY_ACTION_PATH "/usr/libexec/hdn-recovery-action"
#endif

#ifndef HDN_RECOVERY_CONFIRM_PATH
#define HDN_RECOVERY_CONFIRM_PATH "/usr/libexec/hdn-recovery-confirm"
#endif

#define HDN_RECOVERY_SESSION_MAX_ARGS 16
#define HDN_RECOVERY_SESSION_MAX_METADATA 8192

struct hdn_recovery_session_config {
	char *describe_helper;
	char *action_helper;
	char *confirm_argv[HDN_RECOVERY_SESSION_MAX_ARGS + 1];
	unsigned int confirm_argc;
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--config FILE] [--dry-run] [--authorized] ACTION\n"
		"\n"
		"Runs a named recovery session: describe, confirm, then act.\n"
		"Config lines:\n"
		"  describe-helper PATH\n"
		"  confirm-helper PATH [ARG...]\n"
		"  action-helper PATH\n",
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

static bool safe_name(const char *name)
{
	const char *p;

	if (!name || !name[0] || !strcmp(name, ".") || !strcmp(name, ".."))
		return false;

	for (p = name; *p; p++) {
		if ((*p >= 'A' && *p <= 'Z') ||
		    (*p >= 'a' && *p <= 'z') ||
		    (*p >= '0' && *p <= '9') ||
		    *p == '.' || *p == '_' || *p == '-')
			continue;
		return false;
	}

	return true;
}

static bool path_has_dot_component(const char *path)
{
	const char *part = path;

	while (*part) {
		const char *slash;
		size_t len;

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
	if (!path || path[0] != '/') {
		fprintf(stderr,
			"hdn-recovery-session: %s must be absolute: %s\n",
			what, path ? path : "(null)");
		return -EINVAL;
	}
	if (!strcmp(path, "/")) {
		fprintf(stderr,
			"hdn-recovery-session: %s / is too broad\n", what);
		return -EINVAL;
	}
	if (path_has_dot_component(path)) {
		fprintf(stderr,
			"hdn-recovery-session: %s must not contain . or .. path components: %s\n",
			what, path);
		return -EINVAL;
	}

	return 0;
}

static int require_safe_arg(const char *arg, unsigned int lineno)
{
	const unsigned char *p;

	if (!arg || !arg[0]) {
		fprintf(stderr,
			"hdn-recovery-session: empty helper argument at line %u\n",
			lineno);
		return -EINVAL;
	}

	for (p = (const unsigned char *)arg; *p; p++) {
		if (*p >= 0x21 && *p <= 0x7e)
			continue;
		fprintf(stderr,
			"hdn-recovery-session: unsafe helper argument at line %u\n",
			lineno);
		return -EINVAL;
	}

	return 0;
}

static int replace_string(char **slot, const char *value)
{
	char *copy = strdup(value);

	if (!copy)
		return -ENOMEM;
	free(*slot);
	*slot = copy;
	return 0;
}

static int set_helper_path(char **slot, const char *kind, char **tokens,
			   unsigned int count, unsigned int lineno)
{
	if (count != 2) {
		fprintf(stderr,
			"hdn-recovery-session: %s line %u needs exactly one path\n",
			kind, lineno);
		return -EINVAL;
	}
	if (require_safe_absolute(kind, tokens[1]))
		return -EINVAL;
	return replace_string(slot, tokens[1]);
}

static int set_confirm_helper(struct hdn_recovery_session_config *config,
			      char **tokens, unsigned int count,
			      unsigned int lineno)
{
	unsigned int i;

	if (count < 2) {
		fprintf(stderr,
			"hdn-recovery-session: confirm-helper line %u needs PATH [ARG...]\n",
			lineno);
		return -EINVAL;
	}
	if (count > HDN_RECOVERY_SESSION_MAX_ARGS) {
		fprintf(stderr,
			"hdn-recovery-session: too many confirm-helper arguments at line %u\n",
			lineno);
		return -E2BIG;
	}
	if (require_safe_absolute("confirm-helper", tokens[1]))
		return -EINVAL;

	for (i = 2; i < count; i++) {
		if (require_safe_arg(tokens[i], lineno))
			return -EINVAL;
	}

	for (i = 0; i < config->confirm_argc; i++)
		free(config->confirm_argv[i]);
	config->confirm_argc = 0;

	for (i = 1; i < count; i++) {
		config->confirm_argv[config->confirm_argc] =
			strdup(tokens[i]);
		if (!config->confirm_argv[config->confirm_argc])
			return -ENOMEM;
		config->confirm_argc++;
	}
	config->confirm_argv[config->confirm_argc] = NULL;
	return 0;
}

static int parse_config_line(struct hdn_recovery_session_config *config,
			     char *line, unsigned int lineno)
{
	char *tokens[HDN_RECOVERY_SESSION_MAX_ARGS + 1];
	unsigned int count = 0;
	char *save = NULL;
	char *word;

	line = trim(line);
	if (!line[0] || line[0] == '#')
		return 0;

	for (word = strtok_r(line, " \t", &save); word;
	     word = strtok_r(NULL, " \t", &save)) {
		if (count >= sizeof(tokens) / sizeof(tokens[0])) {
			fprintf(stderr,
				"hdn-recovery-session: too many fields at line %u\n",
				lineno);
			return -E2BIG;
		}
		tokens[count++] = word;
	}

	if (!count)
		return 0;
	if (!strcmp(tokens[0], "describe-helper"))
		return set_helper_path(&config->describe_helper,
				       "describe-helper", tokens, count,
				       lineno);
	if (!strcmp(tokens[0], "action-helper"))
		return set_helper_path(&config->action_helper,
				       "action-helper", tokens, count,
				       lineno);
	if (!strcmp(tokens[0], "confirm-helper"))
		return set_confirm_helper(config, tokens, count, lineno);

	fprintf(stderr,
		"hdn-recovery-session: unknown config key at line %u: %s\n",
		lineno, tokens[0]);
	return -EINVAL;
}

static int open_config(const char *path)
{
	struct stat st;
	int flags = O_RDONLY | O_CLOEXEC;
	int fd;

#ifdef O_NOFOLLOW
	flags |= O_NOFOLLOW;
#endif

	fd = open(path, flags);
	if (fd < 0) {
		fprintf(stderr, "hdn-recovery-session: cannot open %s: %s\n",
			path, strerror(errno));
		return -errno;
	}

	if (fstat(fd, &st)) {
		int ret = -errno;

		fprintf(stderr, "hdn-recovery-session: cannot stat %s: %s\n",
			path, strerror(errno));
		close(fd);
		return ret;
	}

	if (!S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 022)) {
		fprintf(stderr,
			"hdn-recovery-session: refusing unsafe config %s\n",
			path);
		close(fd);
		return -EACCES;
	}

	return fd;
}

static int load_config(const char *path,
		       struct hdn_recovery_session_config *config)
{
	char *line = NULL;
	size_t size = 0;
	unsigned int lineno = 0;
	ssize_t len;
	FILE *file;
	int ret = 0;
	int fd;

	memset(config, 0, sizeof(*config));

	ret = replace_string(&config->describe_helper,
			     HDN_RECOVERY_DESCRIBE_PATH);
	if (ret)
		return ret;
	ret = replace_string(&config->action_helper, HDN_RECOVERY_ACTION_PATH);
	if (ret)
		return ret;
	config->confirm_argv[0] = strdup(HDN_RECOVERY_CONFIRM_PATH);
	if (!config->confirm_argv[0])
		return -ENOMEM;
	config->confirm_argc = 1;

	fd = open_config(path);
	if (fd < 0)
		return fd;

	file = fdopen(fd, "r");
	if (!file) {
		ret = -errno;
		close(fd);
		return ret;
	}

	while ((len = getline(&line, &size, file)) >= 0) {
		(void)len;
		lineno++;
		ret = parse_config_line(config, line, lineno);
		if (ret)
			break;
	}
	if (ferror(file) && !ret)
		ret = -EIO;

	free(line);
	fclose(file);
	return ret;
}

static void free_config(struct hdn_recovery_session_config *config)
{
	unsigned int i;

	free(config->describe_helper);
	free(config->action_helper);
	for (i = 0; i < config->confirm_argc; i++)
		free(config->confirm_argv[i]);
}

static int child_status_result(pid_t child)
{
	int status;

	if (waitpid(child, &status, 0) < 0)
		return 1;
	if (!WIFEXITED(status))
		return 1;
	return WEXITSTATUS(status);
}

static int read_metadata_from_describe(const char *helper, const char *action,
				       char **metadata)
{
	char buf[HDN_RECOVERY_SESSION_MAX_METADATA + 1];
	size_t done = 0;
	int pipefd[2];
	pid_t child;
	int status;

	if (pipe(pipefd)) {
		fprintf(stderr, "hdn-recovery-session: pipe failed: %s\n",
			strerror(errno));
		return 1;
	}

	child = fork();
	if (child < 0) {
		fprintf(stderr, "hdn-recovery-session: fork failed: %s\n",
			strerror(errno));
		close(pipefd[0]);
		close(pipefd[1]);
		return 1;
	}

	if (!child) {
		close(pipefd[0]);
		if (dup2(pipefd[1], STDOUT_FILENO) < 0)
			_exit(126);
		close(pipefd[1]);
		execl(helper, "hdn-recovery-describe", action, NULL);
		fprintf(stderr, "hdn-recovery-session: exec %s failed: %s\n",
			helper, strerror(errno));
		_exit(errno == ENOENT ? 127 : 126);
	}

	close(pipefd[1]);
	for (;;) {
		ssize_t len;

		len = read(pipefd[0], buf + done,
			   HDN_RECOVERY_SESSION_MAX_METADATA - done);
		if (len < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr,
				"hdn-recovery-session: read recovery metadata failed: %s\n",
				strerror(errno));
			close(pipefd[0]);
			(void)child_status_result(child);
			return 1;
		}
		if (!len)
			break;
		done += (size_t)len;
		if (done == HDN_RECOVERY_SESSION_MAX_METADATA) {
			fprintf(stderr,
				"hdn-recovery-session: recovery metadata too large\n");
			close(pipefd[0]);
			(void)child_status_result(child);
			return 1;
		}
	}
	close(pipefd[0]);

	status = child_status_result(child);
	if (status)
		return status;
	if (!done) {
		fprintf(stderr, "hdn-recovery-session: empty recovery metadata\n");
		return 1;
	}

	buf[done] = '\0';
	*metadata = strdup(buf);
	if (!*metadata)
		return 1;
	return 0;
}

static bool metadata_has_line(const char *metadata, const char *line)
{
	const char *match = metadata;
	size_t line_len = strlen(line);

	while ((match = strstr(match, line))) {
		if ((match == metadata || match[-1] == '\n') &&
		    match[line_len] == '\n')
			return true;
		match += line_len;
	}

	return false;
}

static int validate_metadata(const char *metadata, const char *action)
{
	char expected[256];

	if (!metadata_has_line(metadata, "HDN_RECOVERY_METADATA_V1")) {
		fprintf(stderr,
			"hdn-recovery-session: recovery metadata missing magic\n");
		return 1;
	}
	if (snprintf(expected, sizeof(expected), "action=%s", action) >=
	    (int)sizeof(expected)) {
		fprintf(stderr, "hdn-recovery-session: action name too long\n");
		return 1;
	}
	if (!metadata_has_line(metadata, expected)) {
		fprintf(stderr,
			"hdn-recovery-session: recovery metadata action mismatch\n");
		return 1;
	}

	return 0;
}

static int write_all(int fd, const char *buf, size_t size)
{
	size_t done = 0;

	while (done < size) {
		ssize_t ret = write(fd, buf + done, size - done);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (!ret)
			return -EIO;
		done += (size_t)ret;
	}

	return 0;
}

static int run_confirm_helper(const struct hdn_recovery_session_config *config,
			      const char *action, const char *metadata)
{
	char *argv[HDN_RECOVERY_SESSION_MAX_ARGS + 2];
	int pipefd[2];
	unsigned int i;
	pid_t child;
	int write_ret;
	int status;

	if (pipe(pipefd)) {
		fprintf(stderr, "hdn-recovery-session: pipe failed: %s\n",
			strerror(errno));
		return 1;
	}

	child = fork();
	if (child < 0) {
		fprintf(stderr, "hdn-recovery-session: fork failed: %s\n",
			strerror(errno));
		close(pipefd[0]);
		close(pipefd[1]);
		return 1;
	}

	if (!child) {
		close(pipefd[1]);
		if (dup2(pipefd[0], STDIN_FILENO) < 0)
			_exit(126);
		close(pipefd[0]);
		for (i = 0; i < config->confirm_argc; i++)
			argv[i] = config->confirm_argv[i];
		argv[config->confirm_argc] = (char *)action;
		argv[config->confirm_argc + 1] = NULL;
		execv(config->confirm_argv[0], argv);
		fprintf(stderr, "hdn-recovery-session: exec %s failed: %s\n",
			config->confirm_argv[0], strerror(errno));
		_exit(errno == ENOENT ? 127 : 126);
	}

	close(pipefd[0]);
	write_ret = write_all(pipefd[1], metadata, strlen(metadata));
	close(pipefd[1]);
	status = child_status_result(child);
	if (write_ret && !status) {
		fprintf(stderr,
			"hdn-recovery-session: confirm helper input failed: %s\n",
			strerror(-write_ret));
		return 1;
	}
	return status ? 1 : 0;
}

static int run_action_helper(const char *helper, const char *action,
			     bool dry_run)
{
	pid_t child;

	child = fork();
	if (child < 0) {
		fprintf(stderr, "hdn-recovery-session: fork failed: %s\n",
			strerror(errno));
		return 1;
	}

	if (!child) {
		if (dry_run)
			execl(helper, "hdn-recovery-action", "--dry-run",
			      action, NULL);
		else
			execl(helper, "hdn-recovery-action", action, NULL);
		fprintf(stderr, "hdn-recovery-session: exec %s failed: %s\n",
			helper, strerror(errno));
		_exit(errno == ENOENT ? 127 : 126);
	}

	return child_status_result(child);
}

int main(int argc, char **argv)
{
	struct hdn_recovery_session_config config;
	const char *config_path = HDN_RECOVERY_SESSION_CONFIG;
	const char *action = NULL;
	char *metadata = NULL;
	bool authorized = false;
	bool dry_run = false;
	int ret;
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--config")) {
			if (++i >= argc) {
				usage(argv[0]);
				return 2;
			}
			config_path = argv[i];
		} else if (!strcmp(argv[i], "-h") ||
			   !strcmp(argv[i], "--help")) {
			usage(argv[0]);
			return 0;
		} else if (!strcmp(argv[i], "--dry-run")) {
			dry_run = true;
		} else if (!strcmp(argv[i], "--authorized")) {
			authorized = true;
		} else if (!action) {
			action = argv[i];
		} else {
			usage(argv[0]);
			return 2;
		}
	}

	if (!action || !safe_name(action)) {
		usage(argv[0]);
		return 2;
	}
	if (authorized && geteuid() != 0) {
		fprintf(stderr,
			"hdn-recovery-session: --authorized requires root\n");
		return 1;
	}

	ret = load_config(config_path, &config);
	if (ret)
		return 1;

	ret = read_metadata_from_describe(config.describe_helper, action,
					  &metadata);
	if (ret)
		goto out;

	ret = validate_metadata(metadata, action);
	if (ret)
		goto out;

	if (!dry_run && !authorized) {
		ret = run_confirm_helper(&config, action, metadata);
		if (ret) {
			fprintf(stderr,
				"hdn-recovery-session: recovery confirmation denied: %s\n",
				action);
			goto out;
		}
	}

	ret = run_action_helper(config.action_helper, action, true);
	if (!ret && !dry_run)
		ret = run_action_helper(config.action_helper, action, false);
	if (ret)
		fprintf(stderr,
			"hdn-recovery-session: recovery action failed for %s\n",
			action);

out:
	free(metadata);
	free_config(&config);
	return ret ? 1 : 0;
}
