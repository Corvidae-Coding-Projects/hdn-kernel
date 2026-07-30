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

#ifndef HDN_PACKAGE_HOOK_CONFIG
#define HDN_PACKAGE_HOOK_CONFIG "/etc/hdn/package-hooks.conf"
#endif

#ifndef HDN_SYSTEM_TRANSACTION_PATH
#define HDN_SYSTEM_TRANSACTION_PATH "/usr/libexec/hdn-system-transaction"
#endif

#ifndef HDN_IMAGE_SEAL_PATH
#define HDN_IMAGE_SEAL_PATH "/usr/libexec/hdn-image-seal"
#endif

#define HDN_PACKAGE_HOOK_MAX_RULES 64

enum hdn_package_hook_backend {
	HDN_PACKAGE_HOOK_SYSTEM_TRANSACTION,
	HDN_PACKAGE_HOOK_IMAGE_SEAL,
};

struct hdn_package_hook_rule {
	char *name;
	enum hdn_package_hook_backend backend;
	char *argument;
};

struct hdn_package_hook_config {
	struct hdn_package_hook_rule rules[HDN_PACKAGE_HOOK_MAX_RULES];
	unsigned int count;
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--config FILE] [--system-transaction PATH] [--image-seal PATH] [--dry-run] HOOK\n"
		"\n"
		"Runs a product-approved package-manager hook.\n"
		"Config lines:\n"
		"  hook NAME system-transaction TRANSACTION\n"
		"  hook NAME image-seal SEAL\n",
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
		fprintf(stderr, "hdn-package-hook: %s must be absolute: %s\n",
			what, path ? path : "(null)");
		return -EINVAL;
	}
	if (path_has_dot_component(path)) {
		fprintf(stderr,
			"hdn-package-hook: %s must not contain . or .. path components: %s\n",
			what, path);
		return -EINVAL;
	}

	return 0;
}

static int add_rule(struct hdn_package_hook_config *config, char **tokens,
		    unsigned int count, unsigned int lineno)
{
	struct hdn_package_hook_rule *rule;
	enum hdn_package_hook_backend backend;

	if (count != 4) {
		fprintf(stderr,
			"hdn-package-hook: hook line %u needs NAME BACKEND ARGUMENT\n",
			lineno);
		return -EINVAL;
	}
	if (config->count >= HDN_PACKAGE_HOOK_MAX_RULES) {
		fprintf(stderr, "hdn-package-hook: too many hook rules\n");
		return -E2BIG;
	}
	if (!safe_name(tokens[1])) {
		fprintf(stderr,
			"hdn-package-hook: unsafe hook name at line %u: %s\n",
			lineno, tokens[1]);
		return -EINVAL;
	}
	if (!safe_name(tokens[3])) {
		fprintf(stderr,
			"hdn-package-hook: unsafe backend argument at line %u: %s\n",
			lineno, tokens[3]);
		return -EINVAL;
	}

	if (!strcmp(tokens[2], "system-transaction"))
		backend = HDN_PACKAGE_HOOK_SYSTEM_TRANSACTION;
	else if (!strcmp(tokens[2], "image-seal"))
		backend = HDN_PACKAGE_HOOK_IMAGE_SEAL;
	else {
		fprintf(stderr,
			"hdn-package-hook: unknown hook backend at line %u: %s\n",
			lineno, tokens[2]);
		return -EINVAL;
	}

	rule = &config->rules[config->count];
	rule->name = strdup(tokens[1]);
	rule->argument = strdup(tokens[3]);
	if (!rule->name || !rule->argument)
		return -ENOMEM;
	rule->backend = backend;
	config->count++;
	return 0;
}

static int parse_config_line(struct hdn_package_hook_config *config,
			     char *line, unsigned int lineno)
{
	char *tokens[4];
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
				"hdn-package-hook: too many fields at line %u\n",
				lineno);
			return -E2BIG;
		}
		tokens[count++] = word;
	}

	if (!count)
		return 0;
	if (strcmp(tokens[0], "hook")) {
		fprintf(stderr,
			"hdn-package-hook: unknown config key at line %u: %s\n",
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
		fprintf(stderr, "hdn-package-hook: cannot open %s: %s\n",
			path, strerror(errno));
		return -errno;
	}

	if (fstat(fd, &st)) {
		int ret = -errno;

		fprintf(stderr, "hdn-package-hook: cannot stat %s: %s\n",
			path, strerror(errno));
		close(fd);
		return ret;
	}

	if (!S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 022)) {
		fprintf(stderr,
			"hdn-package-hook: refusing unsafe config %s\n",
			path);
		close(fd);
		return -EACCES;
	}

	return fd;
}

static int load_config(const char *path, struct hdn_package_hook_config *config)
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

static void free_config(struct hdn_package_hook_config *config)
{
	unsigned int i;

	for (i = 0; i < config->count; i++) {
		free(config->rules[i].name);
		free(config->rules[i].argument);
	}
}

static const struct hdn_package_hook_rule *
find_rule(const struct hdn_package_hook_config *config, const char *hook)
{
	unsigned int i;

	for (i = 0; i < config->count; i++) {
		if (!strcmp(config->rules[i].name, hook))
			return &config->rules[i];
	}

	return NULL;
}

static int run_hook(const struct hdn_package_hook_rule *rule,
		    const char *system_transaction, const char *image_seal,
		    bool dry_run)
{
	const char *path;
	const char *argv0;
	pid_t child;
	int status;

	if (rule->backend == HDN_PACKAGE_HOOK_SYSTEM_TRANSACTION) {
		path = system_transaction;
		argv0 = "hdn-system-transaction";
	} else {
		path = image_seal;
		argv0 = "hdn-image-seal";
	}

	child = fork();
	if (child < 0) {
		fprintf(stderr, "hdn-package-hook: fork failed: %s\n",
			strerror(errno));
		return 1;
	}

	if (!child) {
		if (dry_run)
			execl(path, argv0, "--dry-run", rule->argument, NULL);
		else
			execl(path, argv0, rule->argument, NULL);
		fprintf(stderr, "hdn-package-hook: exec %s failed: %s\n",
			path, strerror(errno));
		_exit(errno == ENOENT ? 127 : 126);
	}

	if (waitpid(child, &status, 0) < 0)
		return 1;
	if (!WIFEXITED(status))
		return 1;
	return WEXITSTATUS(status);
}

int main(int argc, char **argv)
{
	struct hdn_package_hook_config config;
	const struct hdn_package_hook_rule *rule;
	const char *config_path = HDN_PACKAGE_HOOK_CONFIG;
	const char *system_transaction = HDN_SYSTEM_TRANSACTION_PATH;
	const char *image_seal = HDN_IMAGE_SEAL_PATH;
	const char *transaction;
	const char *hook = NULL;
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
		} else if (!strcmp(argv[i], "--system-transaction")) {
			if (++i >= argc ||
			    require_safe_absolute("system transaction helper",
						  argv[i])) {
				usage(argv[0]);
				return 2;
			}
			system_transaction = argv[i];
		} else if (!strcmp(argv[i], "--image-seal")) {
			if (++i >= argc ||
			    require_safe_absolute("image seal helper", argv[i])) {
				usage(argv[0]);
				return 2;
			}
			image_seal = argv[i];
		} else if (!strcmp(argv[i], "--dry-run")) {
			dry_run = true;
		} else if (!strcmp(argv[i], "-h") ||
			   !strcmp(argv[i], "--help")) {
			usage(argv[0]);
			return 0;
		} else if (!hook) {
			hook = argv[i];
		} else {
			usage(argv[0]);
			return 2;
		}
	}

	if (!hook || !safe_name(hook)) {
		usage(argv[0]);
		return 2;
	}
	transaction = getenv("HDN_PACKAGE_TRANSACTION");
	if (!strcmp(hook, "image-seal-default") && transaction &&
	    !strcmp(transaction, "1"))
		return 0;

	ret = load_config(config_path, &config);
	if (ret)
		return 1;

	rule = find_rule(&config, hook);
	if (!rule) {
		fprintf(stderr,
			"hdn-package-hook: hook is not product-approved: %s\n",
			hook);
		free_config(&config);
		return 1;
	}

	ret = run_hook(rule, system_transaction, image_seal, dry_run);
	free_config(&config);
	return ret ? 1 : 0;
}
