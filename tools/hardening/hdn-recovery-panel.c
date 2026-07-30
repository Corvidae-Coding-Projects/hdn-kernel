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

#ifndef HDN_RECOVERY_PANEL_CONFIG
#define HDN_RECOVERY_PANEL_CONFIG "/etc/hdn/recovery-panel.conf"
#endif

#ifndef HDN_RECOVERY_DESCRIBE_PATH
#define HDN_RECOVERY_DESCRIBE_PATH "/usr/libexec/hdn-recovery-describe"
#endif

#ifndef HDN_RECOVERY_PORTAL_PATH
#define HDN_RECOVERY_PORTAL_PATH "/usr/libexec/hdn-recovery-portal"
#endif

#define HDN_RECOVERY_PANEL_MAX_RULES 64

struct hdn_recovery_panel_rule {
	char *name;
	char *describe_action;
	char *portal_action;
};

struct hdn_recovery_panel_config {
	char *describe_helper;
	char *portal_helper;
	struct hdn_recovery_panel_rule rules[HDN_RECOVERY_PANEL_MAX_RULES];
	unsigned int count;
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--config FILE] describe RECOVERY_ACTION\n"
		"       %s [--config FILE] [--dry-run] [--authorized] action RECOVERY_ACTION\n"
		"       %s [--config FILE] [--dry-run] [--authorized] repair\n"
		"       %s [--config FILE] [--dry-run] [--authorized] rollback\n"
		"\n"
		"Stable product-facing entry point for recovery panels.\n"
		"Config lines:\n"
		"  describe-helper PATH\n"
		"  portal-helper PATH\n"
		"  action RECOVERY_ACTION DESCRIBE_ACTION PORTAL_ACTION\n",
		prog, prog, prog, prog);
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
			"hdn-recovery-panel: %s must be absolute: %s\n",
			what, path ? path : "(null)");
		return -EINVAL;
	}
	if (!strcmp(path, "/")) {
		fprintf(stderr,
			"hdn-recovery-panel: %s / is too broad\n", what);
		return -EINVAL;
	}
	if (path_has_dot_component(path)) {
		fprintf(stderr,
			"hdn-recovery-panel: %s must not contain . or .. path components: %s\n",
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

static int set_helper(char **slot, const char *kind, char **tokens,
		      unsigned int count, unsigned int lineno)
{
	if (count != 2) {
		fprintf(stderr,
			"hdn-recovery-panel: %s line %u needs exactly one path\n",
			kind, lineno);
		return -EINVAL;
	}
	if (require_safe_absolute(kind, tokens[1]))
		return -EINVAL;
	return replace_string(slot, tokens[1]);
}

static int add_action(struct hdn_recovery_panel_config *config, char **tokens,
		      unsigned int count, unsigned int lineno)
{
	struct hdn_recovery_panel_rule *rule;

	if (count != 4) {
		fprintf(stderr,
			"hdn-recovery-panel: action line %u needs RECOVERY_ACTION DESCRIBE_ACTION PORTAL_ACTION\n",
			lineno);
		return -EINVAL;
	}
	if (config->count >= HDN_RECOVERY_PANEL_MAX_RULES) {
		fprintf(stderr, "hdn-recovery-panel: too many action rules\n");
		return -E2BIG;
	}
	if (!safe_name(tokens[1]) || !safe_name(tokens[2]) ||
	    !safe_name(tokens[3])) {
		fprintf(stderr,
			"hdn-recovery-panel: unsafe action name at line %u\n",
			lineno);
		return -EINVAL;
	}

	rule = &config->rules[config->count];
	rule->name = strdup(tokens[1]);
	rule->describe_action = strdup(tokens[2]);
	rule->portal_action = strdup(tokens[3]);
	if (!rule->name || !rule->describe_action || !rule->portal_action)
		return -ENOMEM;
	config->count++;
	return 0;
}

static int parse_config_line(struct hdn_recovery_panel_config *config,
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
				"hdn-recovery-panel: too many fields at line %u\n",
				lineno);
			return -E2BIG;
		}
		tokens[count++] = word;
	}

	if (!count)
		return 0;
	if (!strcmp(tokens[0], "describe-helper"))
		return set_helper(&config->describe_helper, "describe-helper",
				  tokens, count, lineno);
	if (!strcmp(tokens[0], "portal-helper"))
		return set_helper(&config->portal_helper, "portal-helper",
				  tokens, count, lineno);
	if (!strcmp(tokens[0], "action"))
		return add_action(config, tokens, count, lineno);

	fprintf(stderr,
		"hdn-recovery-panel: unknown config key at line %u: %s\n",
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
		fprintf(stderr, "hdn-recovery-panel: cannot open %s: %s\n",
			path, strerror(errno));
		return -errno;
	}

	if (fstat(fd, &st)) {
		int ret = -errno;

		fprintf(stderr, "hdn-recovery-panel: cannot stat %s: %s\n",
			path, strerror(errno));
		close(fd);
		return ret;
	}

	if (!S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 022)) {
		fprintf(stderr,
			"hdn-recovery-panel: refusing unsafe config %s\n",
			path);
		close(fd);
		return -EACCES;
	}

	return fd;
}

static int load_config(const char *path,
		       struct hdn_recovery_panel_config *config)
{
	char *line = NULL;
	size_t size = 0;
	unsigned int lineno = 0;
	ssize_t len;
	FILE *file;
	int ret;
	int fd;

	memset(config, 0, sizeof(*config));

	ret = replace_string(&config->describe_helper,
			     HDN_RECOVERY_DESCRIBE_PATH);
	if (ret)
		return ret;
	ret = replace_string(&config->portal_helper, HDN_RECOVERY_PORTAL_PATH);
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

static void free_config(struct hdn_recovery_panel_config *config)
{
	unsigned int i;

	free(config->describe_helper);
	free(config->portal_helper);
	for (i = 0; i < config->count; i++) {
		free(config->rules[i].name);
		free(config->rules[i].describe_action);
		free(config->rules[i].portal_action);
	}
}

static const struct hdn_recovery_panel_rule *
find_action(const struct hdn_recovery_panel_config *config, const char *action)
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

static int run_describe(const char *helper, const char *action)
{
	int err;

	execl(helper, "hdn-recovery-describe", action, NULL);
	err = errno;
	fprintf(stderr, "hdn-recovery-panel: exec %s failed: %s\n",
		helper, strerror(err));
	return err == ENOENT ? 127 : 126;
}

static int run_portal_child(const char *helper, const char *action,
			    bool dry_run, bool authorized)
{
	pid_t child;

	child = fork();
	if (child < 0) {
		fprintf(stderr, "hdn-recovery-panel: fork failed: %s\n",
			strerror(errno));
		return 1;
	}

	if (!child) {
		if (dry_run && authorized)
			execl(helper, "hdn-recovery-portal", "--dry-run",
			      "--authorized", action, NULL);
		else if (dry_run)
			execl(helper, "hdn-recovery-portal", "--dry-run",
			      action, NULL);
		else if (authorized)
			execl(helper, "hdn-recovery-portal", "--authorized",
			      action, NULL);
		else
			execl(helper, "hdn-recovery-portal", action, NULL);
		fprintf(stderr, "hdn-recovery-panel: exec %s failed: %s\n",
			helper, strerror(errno));
		_exit(errno == ENOENT ? 127 : 126);
	}

	return child_status_result(child);
}

static int run_panel_action(const char *portal_helper, const char *action,
			    bool dry_run, bool authorized)
{
	return run_portal_child(portal_helper, action, dry_run, authorized);
}

int main(int argc, char **argv)
{
	struct hdn_recovery_panel_config config;
	const struct hdn_recovery_panel_rule *rule;
	const char *config_path = HDN_RECOVERY_PANEL_CONFIG;
	const char *command = NULL;
	const char *action = NULL;
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
		} else if (!strcmp(argv[i], "--dry-run")) {
			dry_run = true;
		} else if (!strcmp(argv[i], "--authorized")) {
			authorized = true;
		} else if (!strcmp(argv[i], "-h") ||
			   !strcmp(argv[i], "--help")) {
			usage(argv[0]);
			return 0;
		} else {
			command = argv[i++];
			break;
		}
	}

	if (!command) {
		usage(argv[0]);
		return 2;
	}
	if (authorized && geteuid() != 0) {
		fprintf(stderr,
			"hdn-recovery-panel: --authorized requires root\n");
		return 1;
	}

	if (!strcmp(command, "repair")) {
		action = "repair-system";
		if (i != argc) {
			usage(argv[0]);
			return 2;
		}
	} else if (!strcmp(command, "rollback")) {
		action = "rollback-policy";
		if (i != argc) {
			usage(argv[0]);
			return 2;
		}
	} else if (!strcmp(command, "describe") ||
		   !strcmp(command, "action")) {
		if (i + 1 != argc || !safe_name(argv[i])) {
			usage(argv[0]);
			return 2;
		}
		action = argv[i];
	} else {
		usage(argv[0]);
		return 2;
	}

	if (dry_run && !strcmp(command, "describe")) {
		usage(argv[0]);
		return 2;
	}

	ret = load_config(config_path, &config);
	if (ret)
		return 1;

	rule = find_action(&config, action);
	if (!rule) {
		fprintf(stderr,
			"hdn-recovery-panel: action is not product-approved: %s\n",
			action);
		free_config(&config);
		return 1;
	}

	if (!strcmp(command, "describe"))
		ret = run_describe(config.describe_helper,
				   rule->describe_action);
	else
		ret = run_panel_action(config.portal_helper,
				       rule->portal_action, dry_run,
				       authorized);

	free_config(&config);
	return ret ? 1 : 0;
}
