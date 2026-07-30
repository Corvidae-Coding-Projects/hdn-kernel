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

#ifndef HDN_SETTINGS_PANEL_CONFIG
#define HDN_SETTINGS_PANEL_CONFIG "/etc/hdn/settings-panel.conf"
#endif

#ifndef HDN_CONTROL_CENTER_PATH
#define HDN_CONTROL_CENTER_PATH "/usr/libexec/hdn-control-center"
#endif

#define HDN_SETTINGS_PANEL_MAX_RULES 128

struct hdn_settings_panel_rule {
	char *name;
	char *control_action;
};

struct hdn_settings_panel_config {
	char *control_center;
	struct hdn_settings_panel_rule rules[HDN_SETTINGS_PANEL_MAX_RULES];
	unsigned int count;
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--config FILE] status [HDN_STATUS_ARGS...]\n"
		"       %s [--config FILE] [--dry-run] action SETTINGS_ACTION\n"
		"       %s [--config FILE] [--dry-run] update\n"
		"\n"
		"Stable product-facing entry point for graphical settings panels.\n"
		"Config lines:\n"
		"  control-center-helper PATH\n"
		"  action SETTINGS_ACTION CONTROL_CENTER_ACTION\n",
		prog, prog, prog);
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
			"hdn-settings-panel: %s must be absolute: %s\n",
			what, path ? path : "(null)");
		return -EINVAL;
	}
	if (!strcmp(path, "/")) {
		fprintf(stderr,
			"hdn-settings-panel: %s / is too broad\n", what);
		return -EINVAL;
	}
	if (path_has_dot_component(path)) {
		fprintf(stderr,
			"hdn-settings-panel: %s must not contain . or .. path components: %s\n",
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

static int set_control_center(struct hdn_settings_panel_config *config,
			      char **tokens, unsigned int count,
			      unsigned int lineno)
{
	if (count != 2) {
		fprintf(stderr,
			"hdn-settings-panel: control-center-helper line %u needs exactly one path\n",
			lineno);
		return -EINVAL;
	}
	if (require_safe_absolute("control-center-helper", tokens[1]))
		return -EINVAL;
	return replace_string(&config->control_center, tokens[1]);
}

static int add_action(struct hdn_settings_panel_config *config, char **tokens,
		      unsigned int count, unsigned int lineno)
{
	struct hdn_settings_panel_rule *rule;

	if (count != 3) {
		fprintf(stderr,
			"hdn-settings-panel: action line %u needs SETTINGS_ACTION CONTROL_CENTER_ACTION\n",
			lineno);
		return -EINVAL;
	}
	if (config->count >= HDN_SETTINGS_PANEL_MAX_RULES) {
		fprintf(stderr, "hdn-settings-panel: too many action rules\n");
		return -E2BIG;
	}
	if (!safe_name(tokens[1]) || !safe_name(tokens[2])) {
		fprintf(stderr,
			"hdn-settings-panel: unsafe action name at line %u\n",
			lineno);
		return -EINVAL;
	}

	rule = &config->rules[config->count];
	rule->name = strdup(tokens[1]);
	rule->control_action = strdup(tokens[2]);
	if (!rule->name || !rule->control_action)
		return -ENOMEM;
	config->count++;
	return 0;
}

static int parse_config_line(struct hdn_settings_panel_config *config,
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
				"hdn-settings-panel: too many fields at line %u\n",
				lineno);
			return -E2BIG;
		}
		tokens[count++] = word;
	}

	if (!count)
		return 0;
	if (!strcmp(tokens[0], "control-center-helper"))
		return set_control_center(config, tokens, count, lineno);
	if (!strcmp(tokens[0], "action"))
		return add_action(config, tokens, count, lineno);

	fprintf(stderr,
		"hdn-settings-panel: unknown config key at line %u: %s\n",
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
		fprintf(stderr, "hdn-settings-panel: cannot open %s: %s\n",
			path, strerror(errno));
		return -errno;
	}

	if (fstat(fd, &st)) {
		int ret = -errno;

		fprintf(stderr, "hdn-settings-panel: cannot stat %s: %s\n",
			path, strerror(errno));
		close(fd);
		return ret;
	}

	if (!S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 022)) {
		fprintf(stderr,
			"hdn-settings-panel: refusing unsafe config %s\n",
			path);
		close(fd);
		return -EACCES;
	}

	return fd;
}

static int load_config(const char *path,
		       struct hdn_settings_panel_config *config)
{
	char *line = NULL;
	size_t size = 0;
	unsigned int lineno = 0;
	ssize_t len;
	FILE *file;
	int ret;
	int fd;

	memset(config, 0, sizeof(*config));

	ret = replace_string(&config->control_center, HDN_CONTROL_CENTER_PATH);
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

static void free_config(struct hdn_settings_panel_config *config)
{
	unsigned int i;

	free(config->control_center);
	for (i = 0; i < config->count; i++) {
		free(config->rules[i].name);
		free(config->rules[i].control_action);
	}
}

static const struct hdn_settings_panel_rule *
find_action(const struct hdn_settings_panel_config *config, const char *action)
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

static int run_status(const char *control_center, int argc, char **argv)
{
	char **status_argv;
	int err;
	int i;

	status_argv = calloc((size_t)argc + 3, sizeof(*status_argv));
	if (!status_argv)
		return 1;

	status_argv[0] = "hdn-control-center";
	status_argv[1] = "status";
	for (i = 0; i < argc; i++)
		status_argv[i + 2] = argv[i];
	status_argv[argc + 2] = NULL;

	execv(control_center, status_argv);
	err = errno;
	fprintf(stderr, "hdn-settings-panel: exec %s failed: %s\n",
		control_center, strerror(err));
	free(status_argv);
	return err == ENOENT ? 127 : 126;
}

static int run_control_action_child(const char *control_center,
				    const char *action, bool dry_run)
{
	pid_t child;

	child = fork();
	if (child < 0) {
		fprintf(stderr, "hdn-settings-panel: fork failed: %s\n",
			strerror(errno));
		return 1;
	}

	if (!child) {
		if (dry_run)
			execl(control_center, "hdn-control-center",
			      "--dry-run", "action", action, NULL);
		else
			execl(control_center, "hdn-control-center",
			      "action", action, NULL);
		fprintf(stderr, "hdn-settings-panel: exec %s failed: %s\n",
			control_center, strerror(errno));
		_exit(errno == ENOENT ? 127 : 126);
	}

	return child_status_result(child);
}

static int run_settings_action(const char *control_center, const char *action,
			       bool dry_run)
{
	return run_control_action_child(control_center, action, dry_run);
}

int main(int argc, char **argv)
{
	struct hdn_settings_panel_config config;
	const struct hdn_settings_panel_rule *rule;
	const char *config_path = HDN_SETTINGS_PANEL_CONFIG;
	const char *command = NULL;
	int command_index = 0;
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
		} else {
			command = argv[i];
			command_index = i + 1;
			break;
		}
	}

	if (!command) {
		usage(argv[0]);
		return 2;
	}

	ret = load_config(config_path, &config);
	if (ret)
		return 1;

	if (!strcmp(command, "status")) {
		if (dry_run) {
			free_config(&config);
			usage(argv[0]);
			return 2;
		}
		ret = run_status(config.control_center, argc - command_index,
				 &argv[command_index]);
		free_config(&config);
		return ret;
	}

	if (!strcmp(command, "update")) {
		if (command_index != argc) {
			free_config(&config);
			usage(argv[0]);
			return 2;
		}
		rule = find_action(&config, "updates.install");
	} else if (!strcmp(command, "action")) {
		if (command_index + 1 != argc ||
		    !safe_name(argv[command_index])) {
			free_config(&config);
			usage(argv[0]);
			return 2;
		}
		rule = find_action(&config, argv[command_index]);
	} else {
		free_config(&config);
		usage(argv[0]);
		return 2;
	}

	if (!rule) {
		fprintf(stderr,
			"hdn-settings-panel: action is not product-approved\n");
		free_config(&config);
		return 1;
	}

	ret = run_settings_action(config.control_center, rule->control_action,
				  dry_run);
	free_config(&config);
	return ret ? 1 : 0;
}
