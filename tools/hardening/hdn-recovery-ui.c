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

#ifndef HDN_RECOVERY_UI_CONFIG
#define HDN_RECOVERY_UI_CONFIG "/etc/hdn/recovery-ui.conf"
#endif

#ifndef HDN_RECOVERY_PANEL_PATH
#define HDN_RECOVERY_PANEL_PATH "/usr/libexec/hdn-recovery-panel"
#endif

#define HDN_RECOVERY_UI_MAX_ACTIONS 16
#define HDN_RECOVERY_UI_MAX_METADATA 8192
#define HDN_RECOVERY_UI_MAX_TEXT 512

struct hdn_recovery_ui_action {
	char *name;
	char *title;
};

struct hdn_recovery_ui_config {
	char *panel_helper;
	char *title;
	char *message;
	struct hdn_recovery_ui_action actions[HDN_RECOVERY_UI_MAX_ACTIONS];
	unsigned int count;
};

struct hdn_recovery_ui_metadata {
	char *action;
	char *title;
	char *message;
	char *consequence;
	char *risk;
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--config FILE] [--dry-run]\n"
		"       %s [--config FILE] [--dry-run] --test-choice RECOVERY_ACTION\n"
		"       %s [--config FILE] --test-cancel\n"
		"\n"
		"Graphical recovery UI entry point above hdn-recovery-panel.\n"
		"Config lines:\n"
		"  panel-helper PATH\n"
		"  title TEXT\n"
		"  message TEXT\n"
		"  action RECOVERY_ACTION\n",
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

static bool safe_text(const char *text)
{
	const unsigned char *p;
	size_t len;

	if (!text || !text[0])
		return false;

	len = strlen(text);
	if (len > HDN_RECOVERY_UI_MAX_TEXT)
		return false;

	for (p = (const unsigned char *)text; *p; p++) {
		if (*p >= 0x20 && *p <= 0x7e)
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
			"hdn-recovery-ui: %s must be absolute: %s\n",
			what, path ? path : "(null)");
		return -EINVAL;
	}
	if (!strcmp(path, "/")) {
		fprintf(stderr, "hdn-recovery-ui: %s / is too broad\n",
			what);
		return -EINVAL;
	}
	if (path_has_dot_component(path)) {
		fprintf(stderr,
			"hdn-recovery-ui: %s must not contain . or .. path components: %s\n",
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

static int parse_panel_helper(struct hdn_recovery_ui_config *config,
			      char *rest, unsigned int lineno)
{
	char *path = trim(rest);

	if (!path[0] || strchr(path, ' ') || strchr(path, '\t')) {
		fprintf(stderr,
			"hdn-recovery-ui: panel-helper line %u needs exactly one path\n",
			lineno);
		return -EINVAL;
	}
	if (require_safe_absolute("panel-helper", path))
		return -EINVAL;
	return replace_string(&config->panel_helper, path);
}

static int parse_text_field(char **slot, const char *key, char *rest,
			    unsigned int lineno)
{
	char *value = trim(rest);

	if (!safe_text(value)) {
		fprintf(stderr,
			"hdn-recovery-ui: unsafe %s text at line %u\n",
			key, lineno);
		return -EINVAL;
	}
	return replace_string(slot, value);
}

static int add_action(struct hdn_recovery_ui_config *config, char *rest,
		      unsigned int lineno)
{
	struct hdn_recovery_ui_action *action;
	char *name = trim(rest);

	if (!safe_name(name) || strchr(name, ' ') || strchr(name, '\t')) {
		fprintf(stderr,
			"hdn-recovery-ui: unsafe action name at line %u\n",
			lineno);
		return -EINVAL;
	}
	if (config->count >= HDN_RECOVERY_UI_MAX_ACTIONS) {
		fprintf(stderr, "hdn-recovery-ui: too many actions\n");
		return -E2BIG;
	}

	action = &config->actions[config->count];
	action->name = strdup(name);
	if (!action->name)
		return -ENOMEM;
	config->count++;
	return 0;
}

static int parse_config_line(struct hdn_recovery_ui_config *config,
			     char *line, unsigned int lineno)
{
	line = trim(line);
	if (!line[0] || line[0] == '#')
		return 0;

	if (!strncmp(line, "panel-helper", 12) &&
	    (line[12] == ' ' || line[12] == '\t'))
		return parse_panel_helper(config, line + 12, lineno);
	if (!strncmp(line, "title", 5) &&
	    (line[5] == ' ' || line[5] == '\t'))
		return parse_text_field(&config->title, "title",
					line + 5, lineno);
	if (!strncmp(line, "message", 7) &&
	    (line[7] == ' ' || line[7] == '\t'))
		return parse_text_field(&config->message, "message",
					line + 7, lineno);
	if (!strncmp(line, "action", 6) &&
	    (line[6] == ' ' || line[6] == '\t'))
		return add_action(config, line + 6, lineno);

	fprintf(stderr,
		"hdn-recovery-ui: unknown config key at line %u\n",
		lineno);
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
		fprintf(stderr, "hdn-recovery-ui: cannot open %s: %s\n",
			path, strerror(errno));
		return -errno;
	}

	if (fstat(fd, &st)) {
		int ret = -errno;

		fprintf(stderr, "hdn-recovery-ui: cannot stat %s: %s\n",
			path, strerror(errno));
		close(fd);
		return ret;
	}

	if (!S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 022)) {
		fprintf(stderr,
			"hdn-recovery-ui: refusing unsafe config %s\n",
			path);
		close(fd);
		return -EACCES;
	}

	return fd;
}

static int load_config(const char *path, struct hdn_recovery_ui_config *config)
{
	char *line = NULL;
	size_t size = 0;
	unsigned int lineno = 0;
	ssize_t len;
	FILE *file;
	int ret;
	int fd;

	memset(config, 0, sizeof(*config));

	ret = replace_string(&config->panel_helper, HDN_RECOVERY_PANEL_PATH);
	if (ret)
		return ret;
	ret = replace_string(&config->title, "System Recovery");
	if (ret)
		return ret;
	ret = replace_string(&config->message, "Choose a recovery action.");
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

	if (!ret && !config->count) {
		fprintf(stderr, "hdn-recovery-ui: no approved actions\n");
		ret = -EINVAL;
	}

	return ret;
}

static void free_config(struct hdn_recovery_ui_config *config)
{
	unsigned int i;

	free(config->panel_helper);
	free(config->title);
	free(config->message);
	for (i = 0; i < config->count; i++) {
		free(config->actions[i].name);
		free(config->actions[i].title);
	}
}

static struct hdn_recovery_ui_action *
find_action(struct hdn_recovery_ui_config *config, const char *name)
{
	unsigned int i;

	for (i = 0; i < config->count; i++) {
		if (!strcmp(config->actions[i].name, name))
			return &config->actions[i];
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

static int read_pipe_limited(int fd, char **out)
{
	char *buf;
	size_t done = 0;

	buf = calloc(HDN_RECOVERY_UI_MAX_METADATA + 1, 1);
	if (!buf)
		return -ENOMEM;

	for (;;) {
		ssize_t len;

		len = read(fd, buf + done, HDN_RECOVERY_UI_MAX_METADATA - done);
		if (len < 0) {
			if (errno == EINTR)
				continue;
			free(buf);
			return -errno;
		}
		if (!len)
			break;
		done += (size_t)len;
		if (done == HDN_RECOVERY_UI_MAX_METADATA) {
			free(buf);
			return -E2BIG;
		}
	}

	buf[done] = '\0';
	*out = buf;
	return 0;
}

static int run_capture(char *const argv[], char **out)
{
	int pipefd[2];
	pid_t child;
	int ret;

	if (pipe2(pipefd, O_CLOEXEC)) {
		fprintf(stderr, "hdn-recovery-ui: pipe failed: %s\n",
			strerror(errno));
		return 1;
	}

	child = fork();
	if (child < 0) {
		fprintf(stderr, "hdn-recovery-ui: fork failed: %s\n",
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
		execv(argv[0], argv);
		_exit(errno == ENOENT ? 127 : 126);
	}

	close(pipefd[1]);
	ret = read_pipe_limited(pipefd[0], out);
	close(pipefd[0]);
	if (ret) {
		(void)child_status_result(child);
		return 1;
	}

	ret = child_status_result(child);
	return ret ? 1 : 0;
}

static int set_field(char **slot, char *value, bool action)
{
	if (*slot)
		return -EINVAL;
	if (action) {
		if (!safe_name(value))
			return -EINVAL;
	} else if (!safe_text(value)) {
		return -EINVAL;
	}

	*slot = value;
	return 0;
}

static int parse_metadata(char *blob,
			  struct hdn_recovery_ui_metadata *metadata)
{
	char *save = NULL;
	char *line;
	bool magic = false;

	memset(metadata, 0, sizeof(*metadata));

	for (line = strtok_r(blob, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		size_t len = strlen(line);

		if (len && line[len - 1] == '\r')
			line[--len] = '\0';
		if (!len)
			continue;
		if (!strcmp(line, "HDN_RECOVERY_METADATA_V1")) {
			magic = true;
			continue;
		}
		if (!strncmp(line, "action=", 7)) {
			if (set_field(&metadata->action, line + 7, true))
				return -EINVAL;
			continue;
		}
		if (!strncmp(line, "title=", 6)) {
			if (set_field(&metadata->title, line + 6, false))
				return -EINVAL;
			continue;
		}
		if (!strncmp(line, "message=", 8)) {
			if (set_field(&metadata->message, line + 8, false))
				return -EINVAL;
			continue;
		}
		if (!strncmp(line, "consequence=", 12)) {
			if (set_field(&metadata->consequence, line + 12, false))
				return -EINVAL;
			continue;
		}
		if (!strncmp(line, "risk=", 5)) {
			if (set_field(&metadata->risk, line + 5, false))
				return -EINVAL;
			continue;
		}

		return -EINVAL;
	}

	if (!magic || !metadata->action || !metadata->title ||
	    !metadata->message || !metadata->consequence)
		return -EINVAL;

	return 0;
}

static int describe_action(const char *helper, const char *action, char **title)
{
	struct hdn_recovery_ui_metadata metadata;
	char *argv[] = {
		(char *)helper, "describe", (char *)action, NULL
	};
	char *blob = NULL;
	int ret;

	ret = run_capture(argv, &blob);
	if (ret) {
		free(blob);
		return ret;
	}

	ret = parse_metadata(blob, &metadata);
	if (ret) {
		fprintf(stderr,
			"hdn-recovery-ui: rejected recovery metadata for %s\n",
			action);
		free(blob);
		return 1;
	}

	ret = replace_string(title, metadata.title);
	free(blob);
	return ret ? 1 : 0;
}

static int describe_config_actions(struct hdn_recovery_ui_config *config)
{
	unsigned int i;

	for (i = 0; i < config->count; i++) {
		int ret;

		ret = describe_action(config->panel_helper,
				      config->actions[i].name,
				      &config->actions[i].title);
		if (ret)
			return ret;
	}

	return 0;
}

static bool desktop_session_available(void)
{
	const char *display = getenv("DISPLAY");
	const char *wayland = getenv("WAYLAND_DISPLAY");

	return (display && display[0]) || (wayland && wayland[0]);
}

static int capture_selection(char *const argv[], char **selection)
{
	char *out = NULL;
	char *chosen;
	int ret;

	ret = run_capture(argv, &out);
	if (ret) {
		free(out);
		return ret;
	}

	chosen = trim(out);
	if (!safe_name(chosen)) {
		fprintf(stderr,
			"hdn-recovery-ui: graphical selection was invalid\n");
		free(out);
		return 1;
	}

	ret = replace_string(selection, chosen);
	free(out);
	return ret ? 1 : 0;
}

static int choose_with_zenity(const struct hdn_recovery_ui_config *config,
			      char **selection)
{
	char **argv;
	unsigned int argc = 0;
	unsigned int i;
	int ret;

	argv = calloc(14 + config->count * 2, sizeof(*argv));
	if (!argv)
		return 1;

	argv[argc++] = "/usr/bin/zenity";
	argv[argc++] = "--list";
	argv[argc++] = "--title";
	argv[argc++] = config->title;
	argv[argc++] = "--width";
	argv[argc++] = "640";
	argv[argc++] = "--height";
	argv[argc++] = "360";
	argv[argc++] = "--column";
	argv[argc++] = "Action";
	argv[argc++] = "--column";
	argv[argc++] = "Description";
	argv[argc++] = "--print-column=1";
	for (i = 0; i < config->count; i++) {
		argv[argc++] = config->actions[i].name;
		argv[argc++] = config->actions[i].title;
	}
	argv[argc] = NULL;

	ret = capture_selection(argv, selection);
	free(argv);
	return ret;
}

static int choose_with_kdialog(const struct hdn_recovery_ui_config *config,
			       char **selection)
{
	char **argv;
	unsigned int argc = 0;
	unsigned int i;
	int ret;

	argv = calloc(7 + config->count * 2, sizeof(*argv));
	if (!argv)
		return 1;

	argv[argc++] = "/usr/bin/kdialog";
	argv[argc++] = "--title";
	argv[argc++] = config->title;
	argv[argc++] = "--menu";
	argv[argc++] = config->message;
	for (i = 0; i < config->count; i++) {
		argv[argc++] = config->actions[i].name;
		argv[argc++] = config->actions[i].title;
	}
	argv[argc] = NULL;

	ret = capture_selection(argv, selection);
	free(argv);
	return ret;
}

static int choose_graphical_action(struct hdn_recovery_ui_config *config,
				   char **selection)
{
	int ret;

	if (!desktop_session_available()) {
		fprintf(stderr,
			"hdn-recovery-ui: no graphical session available; denying request\n");
		return 1;
	}

	ret = describe_config_actions(config);
	if (ret)
		return ret;

	if (!access("/usr/bin/zenity", X_OK))
		return choose_with_zenity(config, selection);
	if (!access("/usr/bin/kdialog", X_OK))
		return choose_with_kdialog(config, selection);

	fprintf(stderr,
		"hdn-recovery-ui: no supported graphical selection helper found\n");
	return 1;
}

static int run_panel_child(const char *helper, const char *action, bool dry_run)
{
	pid_t child;

	child = fork();
	if (child < 0) {
		fprintf(stderr, "hdn-recovery-ui: fork failed: %s\n",
			strerror(errno));
		return 1;
	}

	if (!child) {
		if (dry_run)
			execl(helper, "hdn-recovery-panel", "--dry-run",
			      "action", action, NULL);
		else
			execl(helper, "hdn-recovery-panel", "action",
			      action, NULL);
		fprintf(stderr, "hdn-recovery-ui: exec %s failed: %s\n",
			helper, strerror(errno));
		_exit(errno == ENOENT ? 127 : 126);
	}

	return child_status_result(child);
}

static int run_selected_action(const struct hdn_recovery_ui_config *config,
			       const char *action, bool dry_run)
{
	char *title = NULL;
	int ret;

	ret = describe_action(config->panel_helper, action, &title);
	free(title);
	if (ret)
		return ret;

	return run_panel_child(config->panel_helper, action, dry_run);
}

int main(int argc, char **argv)
{
	struct hdn_recovery_ui_config config;
	const char *config_path = HDN_RECOVERY_UI_CONFIG;
	const char *test_choice = NULL;
	char *selection = NULL;
	bool test_cancel = false;
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
			continue;
		}
		if (!strcmp(argv[i], "--dry-run")) {
			dry_run = true;
			continue;
		}
		if (!strcmp(argv[i], "--test-choice")) {
			if (++i >= argc || !safe_name(argv[i])) {
				usage(argv[0]);
				return 2;
			}
			test_choice = argv[i];
			continue;
		}
		if (!strcmp(argv[i], "--test-cancel")) {
			test_cancel = true;
			continue;
		}
		if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
			usage(argv[0]);
			return 0;
		}
		usage(argv[0]);
		return 2;
	}

	if ((test_choice && test_cancel) || (test_cancel && dry_run)) {
		usage(argv[0]);
		return 2;
	}

	ret = load_config(config_path, &config);
	if (ret)
		return 1;

	if (test_cancel) {
		free_config(&config);
		return 1;
	}

	if (test_choice) {
		if (!find_action(&config, test_choice)) {
			fprintf(stderr,
				"hdn-recovery-ui: action is not product-approved: %s\n",
				test_choice);
			free_config(&config);
			return 1;
		}
		ret = run_selected_action(&config, test_choice, dry_run);
		free_config(&config);
		return ret ? 1 : 0;
	}

	ret = choose_graphical_action(&config, &selection);
	if (ret) {
		free_config(&config);
		return 1;
	}

	if (!find_action(&config, selection)) {
		fprintf(stderr,
			"hdn-recovery-ui: selected action is not approved: %s\n",
			selection);
		free(selection);
		free_config(&config);
		return 1;
	}

	ret = run_selected_action(&config, selection, dry_run);
	free(selection);
	free_config(&config);
	return ret ? 1 : 0;
}
