// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef HDN_STATUS_HELPER_PATH
#define HDN_STATUS_HELPER_PATH "/usr/libexec/hdn-status"
#endif

#ifndef HDN_DESKTOP_DAEMON_PATH
#define HDN_DESKTOP_DAEMON_PATH "/usr/libexec/hdn-desktop-daemon"
#endif

#ifndef HDN_POLICY_DAEMON_PATH
#define HDN_POLICY_DAEMON_PATH "/usr/libexec/hdn-policy-daemon"
#endif

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--status-helper PATH] [--desktop-daemon PATH] [--policy-daemon PATH] status [HDN_STATUS_ARGS...]\n"
		"       %s [--desktop-daemon PATH] [--dry-run] action DESKTOP_ACTION\n"
		"       %s [--policy-daemon PATH] [--dry-run] policy COMMAND WORKFLOW\n"
		"       %s [--status-helper PATH] [--desktop-daemon PATH] [--policy-daemon PATH] --stdio\n"
		"\n"
		"Policy commands: learn, candidate, compile, commit (--dry-run only for commit)\n"
		"Stdio requests: status, action DESKTOP_ACTION, dry-run action DESKTOP_ACTION, policy COMMAND WORKFLOW, or dry-run policy commit WORKFLOW\n"
		"Stable product-facing entry point for desktop shells and settings panels.\n",
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
			"hdn-control-center: %s must be absolute: %s\n",
			what, path ? path : "(null)");
		return -EINVAL;
	}
	if (!strcmp(path, "/")) {
		fprintf(stderr,
			"hdn-control-center: %s / is too broad\n", what);
		return -EINVAL;
	}
	if (path_has_dot_component(path)) {
		fprintf(stderr,
			"hdn-control-center: %s must not contain . or .. path components: %s\n",
			what, path);
		return -EINVAL;
	}

	return 0;
}

static int run_status(const char *status_helper, int argc, char **argv)
{
	char **status_argv;
	int err;
	int i;

	status_argv = calloc((size_t)argc + 2, sizeof(*status_argv));
	if (!status_argv)
		return 1;

	status_argv[0] = "hdn-status";
	for (i = 0; i < argc; i++)
		status_argv[i + 1] = argv[i];
	status_argv[argc + 1] = NULL;

	execv(status_helper, status_argv);
	err = errno;
	fprintf(stderr, "hdn-control-center: exec %s failed: %s\n",
		status_helper, strerror(err));
	free(status_argv);
	return err == ENOENT ? 127 : 126;
}

static int run_action(const char *desktop_daemon, const char *action,
		      bool dry_run)
{
	int err;

	if (!safe_name(action)) {
		fprintf(stderr,
			"hdn-control-center: unsafe desktop action: %s\n",
			action ? action : "(null)");
		return 1;
	}

	if (dry_run)
		execl(desktop_daemon, "hdn-desktop-daemon", "--dry-run",
		      action, NULL);
	else
		execl(desktop_daemon, "hdn-desktop-daemon", action, NULL);
	err = errno;
	fprintf(stderr, "hdn-control-center: exec %s failed: %s\n",
		desktop_daemon, strerror(err));
	return err == ENOENT ? 127 : 126;
}

static bool safe_policy_command(const char *command)
{
	return command &&
	       (!strcmp(command, "learn") || !strcmp(command, "candidate") ||
		!strcmp(command, "compile") || !strcmp(command, "commit"));
}

static int run_policy(const char *policy_daemon, const char *command,
		      const char *workflow, bool dry_run)
{
	int err;

	if (!safe_policy_command(command)) {
		fprintf(stderr,
			"hdn-control-center: unsafe policy command: %s\n",
			command ? command : "(null)");
		return 1;
	}
	if (dry_run && strcmp(command, "commit")) {
		fprintf(stderr,
			"hdn-control-center: --dry-run is only valid with policy commit\n");
		return 1;
	}
	if (!safe_name(workflow)) {
		fprintf(stderr,
			"hdn-control-center: unsafe workflow name: %s\n",
			workflow ? workflow : "(null)");
		return 1;
	}

	if (dry_run)
		execl(policy_daemon, "hdn-policy-daemon", "--dry-run",
		      command, workflow, NULL);
	else
		execl(policy_daemon, "hdn-policy-daemon", command, workflow,
		      NULL);
	err = errno;
	fprintf(stderr, "hdn-control-center: exec %s failed: %s\n",
		policy_daemon, strerror(err));
	return err == ENOENT ? 127 : 126;
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

static int run_status_child(const char *status_helper)
{
	pid_t child;

	child = fork();
	if (child < 0) {
		fprintf(stderr, "hdn-control-center: fork failed: %s\n",
			strerror(errno));
		return 1;
	}

	if (!child)
		_exit(run_status(status_helper, 0, NULL));

	return child_status_result(child);
}

static int run_action_child(const char *desktop_daemon, const char *action,
			    bool dry_run)
{
	pid_t child;

	child = fork();
	if (child < 0) {
		fprintf(stderr, "hdn-control-center: fork failed: %s\n",
			strerror(errno));
		return 1;
	}

	if (!child)
		_exit(run_action(desktop_daemon, action, dry_run));

	return child_status_result(child);
}

static int run_policy_child(const char *policy_daemon, const char *command,
			    const char *workflow, bool dry_run)
{
	pid_t child;

	child = fork();
	if (child < 0) {
		fprintf(stderr, "hdn-control-center: fork failed: %s\n",
			strerror(errno));
		return 1;
	}

	if (!child)
		_exit(run_policy(policy_daemon, command, workflow, dry_run));

	return child_status_result(child);
}

static int run_stdio(const char *status_helper, const char *desktop_daemon,
		     const char *policy_daemon)
{
	char *line = NULL;
	size_t size = 0;
	bool failed = false;
	ssize_t len;

	puts("HDN_CONTROL_CENTER_READY");
	fflush(stdout);

	while ((len = getline(&line, &size, stdin)) >= 0) {
		char *tokens[5];
		unsigned int count = 0;
		char *save = NULL;
		char *word;
		char *request = trim(line);
		const char *kind = NULL;
		const char *action = NULL;
		const char *command = NULL;
		const char *workflow = NULL;
		bool dry_run = false;
		int ret = 1;

		(void)len;
		if (!request[0])
			continue;

		for (word = strtok_r(request, " \t", &save); word;
		     word = strtok_r(NULL, " \t", &save)) {
			if (count < sizeof(tokens) / sizeof(tokens[0]))
				tokens[count] = word;
			count++;
		}

		if (count == 1 && !strcmp(tokens[0], "status")) {
			kind = "status";
			ret = run_status_child(status_helper);
		} else if (count == 2 && !strcmp(tokens[0], "action")) {
			kind = "action";
			action = tokens[1];
			ret = run_action_child(desktop_daemon, action, false);
		} else if (count == 3 && !strcmp(tokens[0], "dry-run") &&
			   !strcmp(tokens[1], "action")) {
			kind = "action";
			dry_run = true;
			action = tokens[2];
			ret = run_action_child(desktop_daemon, action, true);
		} else if (count == 3 && !strcmp(tokens[0], "policy")) {
			kind = "policy";
			command = tokens[1];
			workflow = tokens[2];
			ret = run_policy_child(policy_daemon, command, workflow,
					       false);
		} else if (count == 4 && !strcmp(tokens[0], "dry-run") &&
			   !strcmp(tokens[1], "policy")) {
			kind = "policy";
			dry_run = true;
			command = tokens[2];
			workflow = tokens[3];
			ret = run_policy_child(policy_daemon, command, workflow,
					       true);
		}

		if (!kind) {
			printf("HDN_CONTROL_CENTER_RESULT request=(invalid) status=invalid exit=1\n");
			fflush(stdout);
			failed = true;
			continue;
		}

		if (!strcmp(kind, "action"))
			printf("HDN_CONTROL_CENTER_RESULT request=action action=%s dry_run=%u status=%s exit=%d\n",
			       safe_name(action) ? action : "(invalid)",
			       dry_run ? 1 : 0, ret ? "failed" : "ok",
			       ret ? 1 : 0);
		else if (!strcmp(kind, "policy"))
			printf("HDN_CONTROL_CENTER_RESULT request=policy command=%s workflow=%s dry_run=%u status=%s exit=%d\n",
			       safe_policy_command(command) ? command : "(invalid)",
			       safe_name(workflow) ? workflow : "(invalid)",
			       dry_run ? 1 : 0, ret ? "failed" : "ok",
			       ret ? 1 : 0);
		else
			printf("HDN_CONTROL_CENTER_RESULT request=status status=%s exit=%d\n",
			       ret ? "failed" : "ok", ret ? 1 : 0);
		fflush(stdout);
		if (ret)
			failed = true;
	}

	free(line);
	return ferror(stdin) || failed ? 1 : 0;
}

int main(int argc, char **argv)
{
	const char *status_helper = HDN_STATUS_HELPER_PATH;
	const char *desktop_daemon = HDN_DESKTOP_DAEMON_PATH;
	const char *policy_daemon = HDN_POLICY_DAEMON_PATH;
	const char *command = NULL;
	int command_index = 0;
	bool dry_run = false;
	bool stdio_mode = false;
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--status-helper")) {
			if (++i >= argc) {
				usage(argv[0]);
				return 2;
			}
			status_helper = argv[i];
		} else if (!strcmp(argv[i], "--desktop-daemon")) {
			if (++i >= argc) {
				usage(argv[0]);
				return 2;
			}
			desktop_daemon = argv[i];
		} else if (!strcmp(argv[i], "--policy-daemon")) {
			if (++i >= argc) {
				usage(argv[0]);
				return 2;
			}
			policy_daemon = argv[i];
		} else if (!strcmp(argv[i], "--dry-run")) {
			dry_run = true;
		} else if (!strcmp(argv[i], "--stdio")) {
			stdio_mode = true;
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

	if (stdio_mode && (command || dry_run)) {
		usage(argv[0]);
		return 2;
	}
	if (!stdio_mode && !command) {
		usage(argv[0]);
		return 2;
	}
	if (require_safe_absolute("status-helper", status_helper) ||
	    require_safe_absolute("desktop-daemon", desktop_daemon) ||
	    require_safe_absolute("policy-daemon", policy_daemon))
		return 1;

	if (stdio_mode)
		return run_stdio(status_helper, desktop_daemon, policy_daemon);

	if (!strcmp(command, "status")) {
		if (dry_run) {
			usage(argv[0]);
			return 2;
		}
		return run_status(status_helper, argc - command_index,
				  &argv[command_index]);
	}

	if (!strcmp(command, "action")) {
		if (command_index + 1 != argc) {
			usage(argv[0]);
			return 2;
		}
		return run_action(desktop_daemon, argv[command_index],
				  dry_run);
	}

	if (!strcmp(command, "policy")) {
		if (command_index + 2 != argc) {
			usage(argv[0]);
			return 2;
		}
		return run_policy(policy_daemon, argv[command_index],
				  argv[command_index + 1], dry_run);
	}

	usage(argv[0]);
	return 2;
}
