// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef HDN_SYSTEM_TRANSACTION_CONFIG
#define HDN_SYSTEM_TRANSACTION_CONFIG "/etc/hdn/system-transactions.conf"
#endif

#ifndef HDN_ADMIN_BROKER_PATH
#define HDN_ADMIN_BROKER_PATH "/usr/libexec/hdn-admin-broker"
#endif

#define HDN_TRANSACTION_MAX_RULES 64
#define HDN_TRANSACTION_MAX_ARGS 32

struct hdn_transaction_rule {
	char *name;
	char *mountpoint;
	char *worker_argv[HDN_TRANSACTION_MAX_ARGS + 1];
	unsigned int worker_argc;
};

struct hdn_transaction_config {
	struct hdn_transaction_rule rules[HDN_TRANSACTION_MAX_RULES];
	unsigned int count;
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--config FILE] [--broker PATH] [--approval-token TOKEN] [--dry-run] OPERATION\n"
		"\n"
		"Runs a named product transaction through hdn-admin-broker.\n"
		"Config lines: transaction NAME MOUNTPOINT WORKER [ARG...]\n",
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
			"hdn-system-transaction: %s must be absolute: %s\n",
			what, path ? path : "(null)");
		return -EINVAL;
	}
	if (path_has_dot_component(path)) {
		fprintf(stderr,
			"hdn-system-transaction: %s must not contain . or .. path components: %s\n",
			what, path);
		return -EINVAL;
	}

	return 0;
}

static bool safe_operation_name(const char *name)
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

static int add_rule(struct hdn_transaction_config *config, char **tokens,
		    unsigned int count, unsigned int lineno)
{
	struct hdn_transaction_rule *rule;
	unsigned int i;

	if (count < 4) {
		fprintf(stderr,
			"hdn-system-transaction: transaction line %u needs NAME MOUNTPOINT WORKER\n",
			lineno);
		return -EINVAL;
	}
	if (config->count >= HDN_TRANSACTION_MAX_RULES) {
		fprintf(stderr,
			"hdn-system-transaction: too many transaction rules\n");
		return -E2BIG;
	}
	if (!safe_operation_name(tokens[1])) {
		fprintf(stderr,
			"hdn-system-transaction: unsafe operation name at line %u: %s\n",
			lineno, tokens[1]);
		return -EINVAL;
	}
	if (require_safe_absolute("mountpoint", tokens[2]) ||
	    require_safe_absolute("worker", tokens[3]))
		return -EINVAL;
	if (count - 3 > HDN_TRANSACTION_MAX_ARGS) {
		fprintf(stderr,
			"hdn-system-transaction: too many worker arguments at line %u\n",
			lineno);
		return -E2BIG;
	}

	rule = &config->rules[config->count];
	rule->name = strdup(tokens[1]);
	rule->mountpoint = strdup(tokens[2]);
	if (!rule->name || !rule->mountpoint)
		return -ENOMEM;

	for (i = 3; i < count; i++) {
		rule->worker_argv[rule->worker_argc] = strdup(tokens[i]);
		if (!rule->worker_argv[rule->worker_argc])
			return -ENOMEM;
		rule->worker_argc++;
	}
	rule->worker_argv[rule->worker_argc] = NULL;
	config->count++;
	return 0;
}

static int parse_config_line(struct hdn_transaction_config *config, char *line,
			     unsigned int lineno)
{
	char *tokens[HDN_TRANSACTION_MAX_ARGS + 4];
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
				"hdn-system-transaction: too many fields at line %u\n",
				lineno);
			return -E2BIG;
		}
		tokens[count++] = word;
	}

	if (!count)
		return 0;
	if (strcmp(tokens[0], "transaction")) {
		fprintf(stderr,
			"hdn-system-transaction: unknown config key at line %u: %s\n",
			lineno, tokens[0]);
		return -EINVAL;
	}

	return add_rule(config, tokens, count, lineno);
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
		fprintf(stderr, "hdn-system-transaction: cannot open %s: %s\n",
			path, strerror(errno));
		return -errno;
	}

	if (fstat(fd, &st)) {
		int ret = -errno;

		fprintf(stderr, "hdn-system-transaction: cannot stat %s: %s\n",
			path, strerror(errno));
		close(fd);
		return ret;
	}

	if (!S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 022)) {
		fprintf(stderr,
			"hdn-system-transaction: refusing unsafe config %s\n",
			path);
		close(fd);
		return -EACCES;
	}

	return fd;
}

static int load_config(const char *path, struct hdn_transaction_config *config)
{
	char *line = NULL;
	size_t size = 0;
	unsigned int lineno = 0;
	ssize_t len;
	FILE *file;
	int ret = 0;
	int fd;

	memset(config, 0, sizeof(*config));

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

static void free_config(struct hdn_transaction_config *config)
{
	unsigned int i;
	unsigned int j;

	for (i = 0; i < config->count; i++) {
		free(config->rules[i].name);
		free(config->rules[i].mountpoint);
		for (j = 0; j < config->rules[i].worker_argc; j++)
			free(config->rules[i].worker_argv[j]);
	}
}

static const struct hdn_transaction_rule *
find_rule(const struct hdn_transaction_config *config, const char *operation)
{
	unsigned int i;

	for (i = 0; i < config->count; i++) {
		if (!strcmp(config->rules[i].name, operation))
			return &config->rules[i];
	}

	return NULL;
}

static int run_rule(const char *broker, const char *approval_token,
		    bool dry_run,
		    const struct hdn_transaction_rule *rule)
{
	char **argv;
	unsigned int argc = 0;
	unsigned int i;

	argv = calloc((size_t)rule->worker_argc + 8, sizeof(*argv));
	if (!argv) {
		fprintf(stderr, "hdn-system-transaction: allocation failed\n");
		return 1;
	}

	argv[argc++] = (char *)broker;
	if (dry_run)
		argv[argc++] = "--dry-run";
	if (approval_token) {
		argv[argc++] = "--approval-token";
		argv[argc++] = (char *)approval_token;
	}
	argv[argc++] = "rofs-transaction";
	argv[argc++] = rule->mountpoint;
	argv[argc++] = "--";
	for (i = 0; i < rule->worker_argc; i++)
		argv[argc++] = rule->worker_argv[i];
	argv[argc] = NULL;

	execv(broker, argv);
	fprintf(stderr, "hdn-system-transaction: exec %s failed: %s\n",
		broker, strerror(errno));
	free(argv);
	return errno == ENOENT ? 127 : 126;
}

int main(int argc, char **argv)
{
	const char *config_path = HDN_SYSTEM_TRANSACTION_CONFIG;
	const char *broker_path = HDN_ADMIN_BROKER_PATH;
	const char *approval_token = NULL;
	const char *operation = NULL;
	const struct hdn_transaction_rule *rule;
	struct hdn_transaction_config config;
	bool dry_run = false;
	int ret = 0;
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--help")) {
			usage(argv[0]);
			return 0;
		}
		if (!strcmp(argv[i], "--config")) {
			if (++i >= argc)
				goto bad_args;
			config_path = argv[i];
			continue;
		}
		if (!strcmp(argv[i], "--broker")) {
			if (++i >= argc)
				goto bad_args;
			broker_path = argv[i];
			continue;
		}
		if (!strcmp(argv[i], "--approval-token")) {
			if (++i >= argc)
				goto bad_args;
			approval_token = argv[i];
			continue;
		}
		if (!strcmp(argv[i], "--dry-run")) {
			dry_run = true;
			continue;
		}
		if (argv[i][0] == '-')
			goto bad_args;
		if (operation)
			goto bad_args;
		operation = argv[i];
	}

	if (!operation || !safe_operation_name(operation))
		goto bad_args;
	if (require_safe_absolute("config", config_path) ||
	    require_safe_absolute("broker", broker_path) ||
	    (approval_token &&
	     require_safe_absolute("approval token", approval_token)))
		return 1;

	ret = load_config(config_path, &config);
	if (ret)
		return 1;

	rule = find_rule(&config, operation);
	if (!rule) {
		fprintf(stderr,
			"hdn-system-transaction: operation is not product-approved: %s\n",
			operation);
		free_config(&config);
		return 1;
	}

	ret = run_rule(broker_path, approval_token, dry_run, rule);
	free_config(&config);
	return ret;

bad_args:
	usage(argv[0]);
	return 2;
}
