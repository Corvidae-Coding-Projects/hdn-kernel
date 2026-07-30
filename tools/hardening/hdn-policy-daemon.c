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

#ifndef HDN_POLICY_DAEMON_CONFIG
#define HDN_POLICY_DAEMON_CONFIG "/etc/hdn/policy-daemon.conf"
#endif

#ifndef HDN_POLICY_WORKFLOW_PATH
#define HDN_POLICY_WORKFLOW_PATH "/usr/libexec/hdn-policy-workflow"
#endif

#define HDN_POLICY_DAEMON_MAX_WORKFLOWS 128

struct hdn_policy_daemon_config {
	char *workflow_helper;
	char *workflows[HDN_POLICY_DAEMON_MAX_WORKFLOWS];
	unsigned int count;
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--config FILE] [--dry-run] COMMAND WORKFLOW\n"
		"       %s [--config FILE] --stdio\n"
		"\n"
		"Runs product-approved policy workflows through hdn-policy-workflow.\n"
		"Commands: learn, candidate, compile, commit\n"
		"Stdio requests: COMMAND WORKFLOW, or dry-run commit WORKFLOW\n"
		"Config lines:\n"
		"  workflow-helper PATH\n"
		"  allow-workflow WORKFLOW\n",
		prog, prog);
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

static bool safe_command(const char *command)
{
	return command &&
	       (!strcmp(command, "learn") || !strcmp(command, "candidate") ||
		!strcmp(command, "compile") || !strcmp(command, "commit"));
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
			"hdn-policy-daemon: %s must be absolute: %s\n",
			what, path ? path : "(null)");
		return -EINVAL;
	}
	if (!strcmp(path, "/")) {
		fprintf(stderr,
			"hdn-policy-daemon: %s / is too broad\n", what);
		return -EINVAL;
	}
	if (path_has_dot_component(path)) {
		fprintf(stderr,
			"hdn-policy-daemon: %s must not contain . or .. path components: %s\n",
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

static int set_workflow_helper(struct hdn_policy_daemon_config *config,
			       char **tokens, unsigned int count,
			       unsigned int lineno)
{
	if (count != 2) {
		fprintf(stderr,
			"hdn-policy-daemon: workflow-helper line %u needs exactly one path\n",
			lineno);
		return -EINVAL;
	}
	if (require_safe_absolute("workflow-helper", tokens[1]))
		return -EINVAL;
	return replace_string(&config->workflow_helper, tokens[1]);
}

static int add_allowed_workflow(struct hdn_policy_daemon_config *config,
				char **tokens, unsigned int count,
				unsigned int lineno)
{
	if (count != 2) {
		fprintf(stderr,
			"hdn-policy-daemon: allow-workflow line %u needs exactly one workflow\n",
			lineno);
		return -EINVAL;
	}
	if (config->count >= HDN_POLICY_DAEMON_MAX_WORKFLOWS) {
		fprintf(stderr, "hdn-policy-daemon: too many workflows\n");
		return -E2BIG;
	}
	if (!safe_name(tokens[1])) {
		fprintf(stderr,
			"hdn-policy-daemon: unsafe workflow name at line %u\n",
			lineno);
		return -EINVAL;
	}

	config->workflows[config->count] = strdup(tokens[1]);
	if (!config->workflows[config->count])
		return -ENOMEM;
	config->count++;
	return 0;
}

static int parse_config_line(struct hdn_policy_daemon_config *config,
			     char *line, unsigned int lineno)
{
	char *tokens[2];
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
				"hdn-policy-daemon: too many fields at line %u\n",
				lineno);
			return -E2BIG;
		}
		tokens[count++] = word;
	}

	if (!count)
		return 0;
	if (!strcmp(tokens[0], "workflow-helper"))
		return set_workflow_helper(config, tokens, count, lineno);
	if (!strcmp(tokens[0], "allow-workflow"))
		return add_allowed_workflow(config, tokens, count, lineno);

	fprintf(stderr,
		"hdn-policy-daemon: unknown config key at line %u: %s\n",
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
		fprintf(stderr, "hdn-policy-daemon: cannot open %s: %s\n",
			path, strerror(errno));
		return -errno;
	}

	if (fstat(fd, &st)) {
		int ret = -errno;

		fprintf(stderr, "hdn-policy-daemon: cannot stat %s: %s\n",
			path, strerror(errno));
		close(fd);
		return ret;
	}

	if (!S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 022)) {
		fprintf(stderr,
			"hdn-policy-daemon: refusing unsafe config %s\n",
			path);
		close(fd);
		return -EACCES;
	}

	return fd;
}

static int load_config(const char *path,
		       struct hdn_policy_daemon_config *config)
{
	char *line = NULL;
	size_t size = 0;
	unsigned int lineno = 0;
	ssize_t len;
	FILE *file;
	int ret;
	int fd;

	memset(config, 0, sizeof(*config));

	ret = replace_string(&config->workflow_helper,
			     HDN_POLICY_WORKFLOW_PATH);
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

static void free_config(struct hdn_policy_daemon_config *config)
{
	unsigned int i;

	free(config->workflow_helper);
	for (i = 0; i < config->count; i++)
		free(config->workflows[i]);
}

static bool workflow_allowed(const struct hdn_policy_daemon_config *config,
			     const char *workflow)
{
	unsigned int i;

	for (i = 0; i < config->count; i++) {
		if (!strcmp(config->workflows[i], workflow))
			return true;
	}

	return false;
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

static int run_policy_workflow(const char *helper, const char *command,
			       const char *workflow, bool dry_run)
{
	pid_t child;

	child = fork();
	if (child < 0) {
		fprintf(stderr, "hdn-policy-daemon: fork failed: %s\n",
			strerror(errno));
		return 1;
	}

	if (!child) {
		if (dry_run)
			execl(helper, "hdn-policy-workflow", "--dry-run",
			      command, workflow, NULL);
		else
			execl(helper, "hdn-policy-workflow", command,
			      workflow, NULL);
		fprintf(stderr, "hdn-policy-daemon: exec %s failed: %s\n",
			helper, strerror(errno));
		_exit(errno == ENOENT ? 127 : 126);
	}

	return child_status_result(child);
}

static int dispatch_workflow(const struct hdn_policy_daemon_config *config,
			     const char *command, const char *workflow,
			     bool dry_run)
{
	if (!safe_command(command)) {
		fprintf(stderr,
			"hdn-policy-daemon: unsafe policy command: %s\n",
			command ? command : "(null)");
		return 1;
	}
	if (dry_run && strcmp(command, "commit")) {
		fprintf(stderr,
			"hdn-policy-daemon: --dry-run is only valid with commit\n");
		return 1;
	}
	if (!safe_name(workflow)) {
		fprintf(stderr,
			"hdn-policy-daemon: unsafe workflow name: %s\n",
			workflow ? workflow : "(null)");
		return 1;
	}
	if (!workflow_allowed(config, workflow)) {
		fprintf(stderr,
			"hdn-policy-daemon: workflow is not product-approved: %s\n",
			workflow);
		return 1;
	}

	return run_policy_workflow(config->workflow_helper, command, workflow,
				   dry_run) ? 1 : 0;
}

static int run_stdio(const struct hdn_policy_daemon_config *config)
{
	char *line = NULL;
	size_t size = 0;
	bool failed = false;
	ssize_t len;

	puts("HDN_POLICY_DAEMON_READY");
	fflush(stdout);

	while ((len = getline(&line, &size, stdin)) >= 0) {
		char *tokens[4];
		unsigned int count = 0;
		char *save = NULL;
		char *word;
		char *request = trim(line);
		const char *command = NULL;
		const char *workflow = NULL;
		bool dry_run = false;
		int ret;

		(void)len;
		if (!request[0])
			continue;

		for (word = strtok_r(request, " \t", &save); word;
		     word = strtok_r(NULL, " \t", &save)) {
			if (count < sizeof(tokens) / sizeof(tokens[0]))
				tokens[count] = word;
			count++;
		}

		if (count == 2) {
			command = tokens[0];
			workflow = tokens[1];
		} else if (count == 3 && !strcmp(tokens[0], "dry-run")) {
			dry_run = true;
			command = tokens[1];
			workflow = tokens[2];
		}

		if (!command || !workflow || !safe_command(command) ||
		    !safe_name(workflow)) {
			printf("HDN_POLICY_DAEMON_RESULT command=(invalid) workflow=(invalid) status=invalid exit=1\n");
			fflush(stdout);
			failed = true;
			continue;
		}

		ret = dispatch_workflow(config, command, workflow, dry_run);
		printf("HDN_POLICY_DAEMON_RESULT command=%s workflow=%s status=%s exit=%d\n",
		       command, workflow, ret ? "failed" : "ok", ret ? 1 : 0);
		fflush(stdout);
		if (ret)
			failed = true;
	}

	free(line);
	return ferror(stdin) || failed ? 1 : 0;
}

int main(int argc, char **argv)
{
	struct hdn_policy_daemon_config config;
	const char *config_path = HDN_POLICY_DAEMON_CONFIG;
	const char *command = NULL;
	const char *workflow = NULL;
	bool stdio_mode = false;
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
		} else if (!strcmp(argv[i], "--stdio")) {
			stdio_mode = true;
		} else if (!strcmp(argv[i], "--dry-run")) {
			dry_run = true;
		} else if (!strcmp(argv[i], "-h") ||
			   !strcmp(argv[i], "--help")) {
			usage(argv[0]);
			return 0;
		} else if (!command) {
			command = argv[i];
		} else if (!workflow) {
			workflow = argv[i];
		} else {
			usage(argv[0]);
			return 2;
		}
	}

	if (stdio_mode && (command || workflow || dry_run)) {
		usage(argv[0]);
		return 2;
	}
	if (!stdio_mode && (!command || !workflow)) {
		usage(argv[0]);
		return 2;
	}
	if (require_safe_absolute("config", config_path))
		return 1;

	ret = load_config(config_path, &config);
	if (ret)
		return 1;

	if (stdio_mode)
		ret = run_stdio(&config);
	else
		ret = dispatch_workflow(&config, command, workflow, dry_run);

	free_config(&config);
	return ret ? 1 : 0;
}
