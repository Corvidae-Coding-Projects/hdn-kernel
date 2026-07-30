// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef HDN_RECOVERY_ACTION_CONFIG
#define HDN_RECOVERY_ACTION_CONFIG "/etc/hdn/recovery-actions.conf"
#endif

#ifndef HDN_ADMIN_BROKER_PATH
#define HDN_ADMIN_BROKER_PATH "/usr/libexec/hdn-admin-broker"
#endif

#ifndef HDN_SYSTEM_TRANSACTION_PATH
#define HDN_SYSTEM_TRANSACTION_PATH "/usr/libexec/hdn-system-transaction"
#endif

#define HDN_RECOVERY_MAX_RULES 64

enum hdn_recovery_backend {
	HDN_RECOVERY_POLICY_ROLLBACK,
	HDN_RECOVERY_SYSTEM_TRANSACTION,
};

struct hdn_recovery_rule {
	char *name;
	enum hdn_recovery_backend backend;
	char *argument;
};

struct hdn_recovery_config {
	struct hdn_recovery_rule rules[HDN_RECOVERY_MAX_RULES];
	unsigned int count;
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--config FILE] [--broker PATH] [--system-transaction PATH] [--dry-run] ACTION\n"
		"\n"
		"Runs a product-approved recovery action.\n"
		"Config lines:\n"
		"  action NAME policy-rollback\n"
		"  action NAME system-transaction TRANSACTION\n",
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
			"hdn-recovery-action: %s must be absolute: %s\n",
			what, path ? path : "(null)");
		return -EINVAL;
	}
	if (path_has_dot_component(path)) {
		fprintf(stderr,
			"hdn-recovery-action: %s must not contain . or .. path components: %s\n",
			what, path);
		return -EINVAL;
	}

	return 0;
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

static int add_rule(struct hdn_recovery_config *config, char **tokens,
		    unsigned int count, unsigned int lineno)
{
	struct hdn_recovery_rule *rule;

	if (count < 3) {
		fprintf(stderr,
			"hdn-recovery-action: action line %u needs NAME BACKEND\n",
			lineno);
		return -EINVAL;
	}
	if (config->count >= HDN_RECOVERY_MAX_RULES) {
		fprintf(stderr,
			"hdn-recovery-action: too many recovery actions\n");
		return -E2BIG;
	}
	if (!safe_name(tokens[1])) {
		fprintf(stderr,
			"hdn-recovery-action: unsafe action name at line %u: %s\n",
			lineno, tokens[1]);
		return -EINVAL;
	}

	rule = &config->rules[config->count];
	rule->name = strdup(tokens[1]);
	if (!rule->name)
		return -ENOMEM;

	if (!strcmp(tokens[2], "policy-rollback")) {
		if (count != 3) {
			fprintf(stderr,
				"hdn-recovery-action: policy-rollback takes no argument at line %u\n",
				lineno);
			return -EINVAL;
		}
		rule->backend = HDN_RECOVERY_POLICY_ROLLBACK;
	} else if (!strcmp(tokens[2], "system-transaction")) {
		if (count != 4 || !safe_name(tokens[3])) {
			fprintf(stderr,
				"hdn-recovery-action: invalid system transaction at line %u\n",
				lineno);
			return -EINVAL;
		}
		rule->backend = HDN_RECOVERY_SYSTEM_TRANSACTION;
		rule->argument = strdup(tokens[3]);
		if (!rule->argument)
			return -ENOMEM;
	} else {
		fprintf(stderr,
			"hdn-recovery-action: unknown backend at line %u: %s\n",
			lineno, tokens[2]);
		return -EINVAL;
	}

	config->count++;
	return 0;
}

static int parse_config_line(struct hdn_recovery_config *config, char *line,
			     unsigned int lineno)
{
	char *tokens[5];
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
				"hdn-recovery-action: too many fields at line %u\n",
				lineno);
			return -E2BIG;
		}
		tokens[count++] = word;
	}

	if (!count)
		return 0;
	if (strcmp(tokens[0], "action")) {
		fprintf(stderr,
			"hdn-recovery-action: unknown config key at line %u: %s\n",
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
		fprintf(stderr, "hdn-recovery-action: cannot open %s: %s\n",
			path, strerror(errno));
		return -errno;
	}

	if (fstat(fd, &st)) {
		int ret = -errno;

		fprintf(stderr, "hdn-recovery-action: cannot stat %s: %s\n",
			path, strerror(errno));
		close(fd);
		return ret;
	}

	if (!S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 022)) {
		fprintf(stderr,
			"hdn-recovery-action: refusing unsafe config %s\n",
			path);
		close(fd);
		return -EACCES;
	}

	return fd;
}

static int load_config(const char *path, struct hdn_recovery_config *config)
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

static void free_config(struct hdn_recovery_config *config)
{
	unsigned int i;

	for (i = 0; i < config->count; i++) {
		free(config->rules[i].name);
		free(config->rules[i].argument);
	}
}

static const struct hdn_recovery_rule *
find_rule(const struct hdn_recovery_config *config, const char *action)
{
	unsigned int i;

	for (i = 0; i < config->count; i++) {
		if (!strcmp(config->rules[i].name, action))
			return &config->rules[i];
	}

	return NULL;
}

static int run_rule(const char *broker, const char *system_transaction,
		    const struct hdn_recovery_rule *rule, bool dry_run)
{
	if (rule->backend == HDN_RECOVERY_POLICY_ROLLBACK) {
		char *const dry_argv[] = {
			(char *)broker,
			"--dry-run",
			"policy-rollback",
			NULL,
		};
		char *const real_argv[] = {
			(char *)broker,
			"policy-rollback",
			NULL,
		};

		execv(broker, dry_run ? dry_argv : real_argv);
		fprintf(stderr, "hdn-recovery-action: exec %s failed: %s\n",
			broker, strerror(errno));
		return errno == ENOENT ? 127 : 126;
	}

	if (rule->backend == HDN_RECOVERY_SYSTEM_TRANSACTION) {
		char *const dry_argv[] = {
			(char *)system_transaction,
			"--dry-run",
			rule->argument,
			NULL,
		};
		char *const real_argv[] = {
			(char *)system_transaction,
			rule->argument,
			NULL,
		};

		execv(system_transaction, dry_run ? dry_argv : real_argv);
		fprintf(stderr, "hdn-recovery-action: exec %s failed: %s\n",
			system_transaction, strerror(errno));
		return errno == ENOENT ? 127 : 126;
	}

	return 1;
}

int main(int argc, char **argv)
{
	const char *config_path = HDN_RECOVERY_ACTION_CONFIG;
	const char *broker_path = HDN_ADMIN_BROKER_PATH;
	const char *system_transaction_path = HDN_SYSTEM_TRANSACTION_PATH;
	const char *action = NULL;
	const struct hdn_recovery_rule *rule;
	struct hdn_recovery_config config;
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
		if (!strcmp(argv[i], "--system-transaction")) {
			if (++i >= argc)
				goto bad_args;
			system_transaction_path = argv[i];
			continue;
		}
		if (!strcmp(argv[i], "--dry-run")) {
			dry_run = true;
			continue;
		}
		if (argv[i][0] == '-')
			goto bad_args;
		if (action)
			goto bad_args;
		action = argv[i];
	}

	if (!action || !safe_name(action))
		goto bad_args;
	if (require_safe_absolute("config", config_path) ||
	    require_safe_absolute("broker", broker_path) ||
	    require_safe_absolute("system transaction", system_transaction_path))
		return 1;

	ret = load_config(config_path, &config);
	if (ret)
		return 1;

	rule = find_rule(&config, action);
	if (!rule) {
		fprintf(stderr,
			"hdn-recovery-action: action is not product-approved: %s\n",
			action);
		free_config(&config);
		return 1;
	}

	ret = run_rule(broker_path, system_transaction_path, rule, dry_run);
	free_config(&config);
	return ret;

bad_args:
	usage(argv[0]);
	return 2;
}
