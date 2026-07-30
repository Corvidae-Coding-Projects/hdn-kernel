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

#ifndef HDN_DESKTOP_ACTION_CONFIG
#define HDN_DESKTOP_ACTION_CONFIG "/etc/hdn/desktop-actions.conf"
#endif

#ifndef HDN_PROMPT_PORTAL_PATH
#define HDN_PROMPT_PORTAL_PATH "/usr/libexec/hdn-prompt-portal"
#endif

#define HDN_DESKTOP_ACTION_MAX_RULES 128

struct hdn_desktop_action_rule {
	char *name;
	char *portal_action;
};

struct hdn_desktop_action_config {
	char *portal_helper;
	struct hdn_desktop_action_rule rules[HDN_DESKTOP_ACTION_MAX_RULES];
	unsigned int count;
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--config FILE] [--dry-run] ACTION\n"
		"\n"
		"Runs a product-approved desktop action through the prompt portal.\n"
		"Config lines:\n"
		"  portal-helper PATH\n"
		"  action DESKTOP_ACTION PROMPT_PORTAL_ACTION\n",
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
			"hdn-desktop-action: %s must be absolute: %s\n",
			what, path ? path : "(null)");
		return -EINVAL;
	}
	if (!strcmp(path, "/")) {
		fprintf(stderr,
			"hdn-desktop-action: %s / is too broad\n", what);
		return -EINVAL;
	}
	if (path_has_dot_component(path)) {
		fprintf(stderr,
			"hdn-desktop-action: %s must not contain . or .. path components: %s\n",
			what, path);
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

static int set_portal_helper(struct hdn_desktop_action_config *config,
			     char **tokens, unsigned int count,
			     unsigned int lineno)
{
	if (count != 2) {
		fprintf(stderr,
			"hdn-desktop-action: portal-helper line %u needs exactly one path\n",
			lineno);
		return -EINVAL;
	}
	if (require_safe_absolute("portal-helper", tokens[1]))
		return -EINVAL;
	return replace_string(&config->portal_helper, tokens[1]);
}

static int add_action(struct hdn_desktop_action_config *config, char **tokens,
		      unsigned int count, unsigned int lineno)
{
	struct hdn_desktop_action_rule *rule;

	if (count != 3) {
		fprintf(stderr,
			"hdn-desktop-action: action line %u needs DESKTOP_ACTION PROMPT_PORTAL_ACTION\n",
			lineno);
		return -EINVAL;
	}
	if (config->count >= HDN_DESKTOP_ACTION_MAX_RULES) {
		fprintf(stderr, "hdn-desktop-action: too many action rules\n");
		return -E2BIG;
	}
	if (!safe_name(tokens[1]) || !safe_name(tokens[2])) {
		fprintf(stderr,
			"hdn-desktop-action: unsafe action name at line %u\n",
			lineno);
		return -EINVAL;
	}

	rule = &config->rules[config->count];
	rule->name = strdup(tokens[1]);
	rule->portal_action = strdup(tokens[2]);
	if (!rule->name || !rule->portal_action)
		return -ENOMEM;
	config->count++;
	return 0;
}

static int parse_config_line(struct hdn_desktop_action_config *config,
			     char *line, unsigned int lineno)
{
	char *tokens[3];
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
				"hdn-desktop-action: too many fields at line %u\n",
				lineno);
			return -E2BIG;
		}
		tokens[count++] = word;
	}

	if (!count)
		return 0;
	if (!strcmp(tokens[0], "portal-helper"))
		return set_portal_helper(config, tokens, count, lineno);
	if (!strcmp(tokens[0], "action"))
		return add_action(config, tokens, count, lineno);

	fprintf(stderr,
		"hdn-desktop-action: unknown config key at line %u: %s\n",
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
		fprintf(stderr, "hdn-desktop-action: cannot open %s: %s\n",
			path, strerror(errno));
		return -errno;
	}

	if (fstat(fd, &st)) {
		int ret = -errno;

		fprintf(stderr, "hdn-desktop-action: cannot stat %s: %s\n",
			path, strerror(errno));
		close(fd);
		return ret;
	}

	if (!S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 022)) {
		fprintf(stderr,
			"hdn-desktop-action: refusing unsafe config %s\n",
			path);
		close(fd);
		return -EACCES;
	}

	return fd;
}

static int load_config(const char *path,
		       struct hdn_desktop_action_config *config)
{
	char *line = NULL;
	size_t size = 0;
	unsigned int lineno = 0;
	ssize_t len;
	FILE *file;
	int ret;
	int fd;

	memset(config, 0, sizeof(*config));

	ret = replace_string(&config->portal_helper, HDN_PROMPT_PORTAL_PATH);
	if (ret)
		return ret;

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

static void free_config(struct hdn_desktop_action_config *config)
{
	unsigned int i;

	free(config->portal_helper);
	for (i = 0; i < config->count; i++) {
		free(config->rules[i].name);
		free(config->rules[i].portal_action);
	}
}

static const struct hdn_desktop_action_rule *
find_action(const struct hdn_desktop_action_config *config, const char *action)
{
	unsigned int i;

	for (i = 0; i < config->count; i++) {
		if (!strcmp(config->rules[i].name, action))
			return &config->rules[i];
	}

	return NULL;
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

static int run_prompt_portal(const char *helper, const char *action,
			     bool dry_run)
{
	pid_t child;

	child = fork();
	if (child < 0) {
		fprintf(stderr, "hdn-desktop-action: fork failed: %s\n",
			strerror(errno));
		return 1;
	}

	if (!child) {
		if (dry_run)
			execl(helper, "hdn-prompt-portal", "--dry-run",
			      action, NULL);
		else
			execl(helper, "hdn-prompt-portal", action, NULL);
		fprintf(stderr, "hdn-desktop-action: exec %s failed: %s\n",
			helper, strerror(errno));
		_exit(errno == ENOENT ? 127 : 126);
	}

	return child_status_result(child);
}

int main(int argc, char **argv)
{
	struct hdn_desktop_action_config config;
	const struct hdn_desktop_action_rule *rule;
	const char *config_path = HDN_DESKTOP_ACTION_CONFIG;
	const char *action = NULL;
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
		} else if (!strcmp(argv[i], "--dry-run")) {
			dry_run = true;
		} else if (!strcmp(argv[i], "-h") ||
			   !strcmp(argv[i], "--help")) {
			usage(argv[0]);
			return 0;
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

	ret = load_config(config_path, &config);
	if (ret)
		return 1;

	rule = find_action(&config, action);
	if (!rule) {
		fprintf(stderr,
			"hdn-desktop-action: action is not product-approved: %s\n",
			action);
		free_config(&config);
		return 1;
	}

	ret = run_prompt_portal(config.portal_helper, rule->portal_action,
				dry_run);
	free_config(&config);
	return ret ? 1 : 0;
}
