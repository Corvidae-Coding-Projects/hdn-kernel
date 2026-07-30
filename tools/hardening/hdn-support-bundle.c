// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef HDN_SUPPORT_BUNDLE_CONFIG
#define HDN_SUPPORT_BUNDLE_CONFIG "/etc/hdn/support-bundle.conf"
#endif

#ifndef HDN_STATUS_HELPER_PATH
#define HDN_STATUS_HELPER_PATH "/usr/libexec/hdn-status"
#endif

#ifndef HDN_EVENT_DECODE_PATH
#define HDN_EVENT_DECODE_PATH "/usr/libexec/hdn-event-decode"
#endif

#ifndef HDN_EVENTS_PATH
#define HDN_EVENTS_PATH "/sys/kernel/security/hardening/events"
#endif

#define HDN_SUPPORT_MIN_SECTION_BYTES 512UL
#define HDN_SUPPORT_MAX_SECTION_BYTES 262144UL
#define HDN_SUPPORT_DEFAULT_SECTION_BYTES 65536UL

struct hdn_support_config {
	char *status_helper;
	char *event_decode_helper;
	char *event_input;
	bool include_compat;
	bool include_events;
	size_t max_section_bytes;
};

struct hdn_capture {
	char *data;
	size_t len;
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--config FILE] [--dry-run] [--no-events]\n"
		"\n"
		"Prints a bounded product-facing support bundle from HDN helpers.\n"
		"Config lines: status-helper PATH, event-decode-helper PATH,\n"
		"              event-input PATH, include-compat 0|1,\n"
		"              include-events 0|1, max-section-bytes BYTES\n",
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
			"hdn-support-bundle: %s must be absolute: %s\n",
			what, path ? path : "(null)");
		return -EINVAL;
	}
	if (!strcmp(path, "/")) {
		fprintf(stderr,
			"hdn-support-bundle: %s / is too broad\n", what);
		return -EINVAL;
	}
	if (path_has_dot_component(path)) {
		fprintf(stderr,
			"hdn-support-bundle: %s must not contain . or .. path components: %s\n",
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

static int parse_bool(const char *text, bool *value)
{
	if (!strcmp(text, "1") || !strcmp(text, "yes") ||
	    !strcmp(text, "true") || !strcmp(text, "on")) {
		*value = true;
		return 0;
	}
	if (!strcmp(text, "0") || !strcmp(text, "no") ||
	    !strcmp(text, "false") || !strcmp(text, "off")) {
		*value = false;
		return 0;
	}

	return -EINVAL;
}

static int parse_size(const char *text, size_t *value)
{
	unsigned long parsed;
	char *end;

	errno = 0;
	parsed = strtoul(text, &end, 10);
	if (errno || !text[0] || *end)
		return -EINVAL;
	if (parsed < HDN_SUPPORT_MIN_SECTION_BYTES ||
	    parsed > HDN_SUPPORT_MAX_SECTION_BYTES)
		return -ERANGE;

	*value = parsed;
	return 0;
}

static int parse_single_path(char *rest, const char *what, char **slot,
			     unsigned int lineno)
{
	char *path = trim(rest);
	int ret;

	if (!path[0] || strchr(path, ' ') || strchr(path, '\t')) {
		fprintf(stderr,
			"hdn-support-bundle: %s line %u needs exactly one path\n",
			what, lineno);
		return -EINVAL;
	}

	ret = require_safe_absolute(what, path);
	if (ret)
		return ret;
	return replace_string(slot, path);
}

static int parse_bool_line(char *rest, const char *what, bool *slot,
			   unsigned int lineno)
{
	char *text = trim(rest);

	if (!text[0] || strchr(text, ' ') || strchr(text, '\t') ||
	    parse_bool(text, slot)) {
		fprintf(stderr,
			"hdn-support-bundle: %s line %u needs 0 or 1\n",
			what, lineno);
		return -EINVAL;
	}

	return 0;
}

static int parse_size_line(char *rest, const char *what, size_t *slot,
			   unsigned int lineno)
{
	char *text = trim(rest);

	if (!text[0] || strchr(text, ' ') || strchr(text, '\t') ||
	    parse_size(text, slot)) {
		fprintf(stderr,
			"hdn-support-bundle: %s line %u needs %lu-%lu bytes\n",
			what, lineno, HDN_SUPPORT_MIN_SECTION_BYTES,
			HDN_SUPPORT_MAX_SECTION_BYTES);
		return -EINVAL;
	}

	return 0;
}

static int parse_config_line(struct hdn_support_config *config, char *line,
			     unsigned int lineno)
{
	line = trim(line);
	if (!line[0] || line[0] == '#')
		return 0;

	if (!strncmp(line, "status-helper", 13) &&
	    (line[13] == ' ' || line[13] == '\t'))
		return parse_single_path(line + 13, "status-helper",
					 &config->status_helper, lineno);
	if (!strncmp(line, "event-decode-helper", 19) &&
	    (line[19] == ' ' || line[19] == '\t'))
		return parse_single_path(line + 19, "event-decode-helper",
					 &config->event_decode_helper, lineno);
	if (!strncmp(line, "event-input", 11) &&
	    (line[11] == ' ' || line[11] == '\t'))
		return parse_single_path(line + 11, "event-input",
					 &config->event_input, lineno);
	if (!strncmp(line, "include-compat", 14) &&
	    (line[14] == ' ' || line[14] == '\t'))
		return parse_bool_line(line + 14, "include-compat",
				       &config->include_compat, lineno);
	if (!strncmp(line, "include-events", 14) &&
	    (line[14] == ' ' || line[14] == '\t'))
		return parse_bool_line(line + 14, "include-events",
				       &config->include_events, lineno);
	if (!strncmp(line, "max-section-bytes", 17) &&
	    (line[17] == ' ' || line[17] == '\t'))
		return parse_size_line(line + 17, "max-section-bytes",
				       &config->max_section_bytes, lineno);

	fprintf(stderr,
		"hdn-support-bundle: unknown config key at line %u\n",
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
		fprintf(stderr, "hdn-support-bundle: cannot open %s: %s\n",
			path, strerror(errno));
		return -errno;
	}

	if (fstat(fd, &st)) {
		int ret = -errno;

		fprintf(stderr, "hdn-support-bundle: cannot stat %s: %s\n",
			path, strerror(errno));
		close(fd);
		return ret;
	}

	if (!S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 022)) {
		fprintf(stderr,
			"hdn-support-bundle: refusing unsafe config %s\n",
			path);
		close(fd);
		return -EACCES;
	}

	return fd;
}

static void free_config(struct hdn_support_config *config)
{
	free(config->status_helper);
	free(config->event_decode_helper);
	free(config->event_input);
}

static int load_config(const char *path, struct hdn_support_config *config)
{
	char *line = NULL;
	size_t size = 0;
	unsigned int lineno = 0;
	ssize_t len;
	FILE *file;
	int ret;
	int fd;

	memset(config, 0, sizeof(*config));
	config->include_compat = true;
	config->include_events = false;
	config->max_section_bytes = HDN_SUPPORT_DEFAULT_SECTION_BYTES;

	ret = replace_string(&config->status_helper, HDN_STATUS_HELPER_PATH);
	if (ret)
		return ret;
	ret = replace_string(&config->event_decode_helper,
			     HDN_EVENT_DECODE_PATH);
	if (ret)
		return ret;
	ret = replace_string(&config->event_input, HDN_EVENTS_PATH);
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

	free(line);
	if (!ret && ferror(file))
		ret = -EIO;
	fclose(file);
	if (ret)
		return ret;

	if (require_safe_absolute("status-helper", config->status_helper) ||
	    require_safe_absolute("event-decode-helper",
				  config->event_decode_helper) ||
	    require_safe_absolute("event-input", config->event_input))
		return -EINVAL;

	return 0;
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

static int run_child(char *const argv[])
{
	pid_t child;

	child = fork();
	if (child < 0) {
		fprintf(stderr, "hdn-support-bundle: fork failed: %s\n",
			strerror(errno));
		return 1;
	}

	if (!child) {
		execv(argv[0], argv);
		fprintf(stderr, "hdn-support-bundle: exec %s failed: %s\n",
			argv[0], strerror(errno));
		_exit(errno == ENOENT ? 127 : 126);
	}

	return child_status_result(child);
}

static int capture_read(int fd, struct hdn_capture *capture, size_t max)
{
	size_t done = 0;
	ssize_t len;

	capture->data = calloc(max + 1, 1);
	if (!capture->data)
		return 1;

	for (;;) {
		if (done == max)
			return 1;

		len = read(fd, capture->data + done, max - done);
		if (len < 0) {
			if (errno == EINTR)
				continue;
			return 1;
		}
		if (!len)
			break;
		done += len;
	}

	capture->data[done] = '\0';
	capture->len = done;
	return 0;
}

static int run_capture(char *const argv[], size_t max,
		       struct hdn_capture *capture)
{
	int pipefd[2];
	pid_t child;
	int ret;

	memset(capture, 0, sizeof(*capture));

	if (pipe(pipefd)) {
		fprintf(stderr, "hdn-support-bundle: pipe failed: %s\n",
			strerror(errno));
		return 1;
	}

	child = fork();
	if (child < 0) {
		fprintf(stderr, "hdn-support-bundle: fork failed: %s\n",
			strerror(errno));
		close(pipefd[0]);
		close(pipefd[1]);
		return 1;
	}

	if (!child) {
		close(pipefd[0]);
		if (dup2(pipefd[1], STDOUT_FILENO) < 0)
			_exit(2);
		close(pipefd[1]);
		execv(argv[0], argv);
		fprintf(stderr, "hdn-support-bundle: exec %s failed: %s\n",
			argv[0], strerror(errno));
		_exit(errno == ENOENT ? 127 : 126);
	}

	close(pipefd[1]);
	ret = capture_read(pipefd[0], capture, max);
	close(pipefd[0]);
	if (ret)
		kill(child, SIGKILL);

	ret = child_status_result(child) || ret;
	if (ret) {
		free(capture->data);
		memset(capture, 0, sizeof(*capture));
	}

	return ret ? 1 : 0;
}

static void free_capture(struct hdn_capture *capture)
{
	free(capture->data);
	memset(capture, 0, sizeof(*capture));
}

static int run_status_dry_run(const struct hdn_support_config *config)
{
	char *const argv[] = {
		config->status_helper, "--quiet",
		"--expect", "available=1", NULL
	};

	return run_child(argv);
}

static int run_compat_dry_run(const struct hdn_support_config *config)
{
	char *const argv[] = {
		config->status_helper, "--compat", "--quiet",
		"--expect", "compat_status_v1=1", NULL
	};

	return run_child(argv);
}

static int run_events_dry_run(const struct hdn_support_config *config)
{
	char *const argv[] = {
		config->event_decode_helper, "--input",
		config->event_input, "--quiet", NULL
	};

	return run_child(argv);
}

static int collect_status(const struct hdn_support_config *config,
			  struct hdn_capture *capture)
{
	char *const argv[] = {
		config->status_helper, NULL
	};

	return run_capture(argv, config->max_section_bytes, capture);
}

static int collect_compat(const struct hdn_support_config *config,
			  struct hdn_capture *capture)
{
	char *const argv[] = {
		config->status_helper, "--compat", NULL
	};

	return run_capture(argv, config->max_section_bytes, capture);
}

static int collect_events(const struct hdn_support_config *config,
			  struct hdn_capture *capture)
{
	char *const argv[] = {
		config->event_decode_helper, "--input",
		config->event_input, NULL
	};

	return run_capture(argv, config->max_section_bytes, capture);
}

static void print_section(const char *name, const struct hdn_capture *capture)
{
	printf("section=%s\n", name);
	printf("begin\n");
	if (capture->len)
		fwrite(capture->data, 1, capture->len, stdout);
	if (!capture->len || capture->data[capture->len - 1] != '\n')
		printf("\n");
	printf("end\n");
}

static int dry_run_bundle(const struct hdn_support_config *config)
{
	int ret;

	ret = run_status_dry_run(config);
	if (ret)
		return ret;
	if (config->include_compat) {
		ret = run_compat_dry_run(config);
		if (ret)
			return ret;
	}
	if (config->include_events) {
		ret = run_events_dry_run(config);
		if (ret)
			return ret;
	}

	printf("HDN_SUPPORT_BUNDLE_DRY_RUN=1\n");
	return 0;
}

static int print_bundle(const struct hdn_support_config *config)
{
	struct hdn_capture status;
	struct hdn_capture compat;
	struct hdn_capture events;
	int ret;

	ret = collect_status(config, &status);
	if (ret)
		return ret;

	memset(&compat, 0, sizeof(compat));
	if (config->include_compat) {
		ret = collect_compat(config, &compat);
		if (ret) {
			free_capture(&status);
			return ret;
		}
	}

	memset(&events, 0, sizeof(events));
	if (config->include_events) {
		ret = collect_events(config, &events);
		if (ret) {
			free_capture(&compat);
			free_capture(&status);
			return ret;
		}
	}

	printf("HDN_SUPPORT_BUNDLE_V1\n");
	print_section("status", &status);
	if (config->include_compat)
		print_section("compat", &compat);
	if (config->include_events)
		print_section("events", &events);

	free_capture(&events);
	free_capture(&compat);
	free_capture(&status);
	return ferror(stdout) ? 1 : 0;
}

int main(int argc, char **argv)
{
	struct hdn_support_config config;
	const char *config_path = HDN_SUPPORT_BUNDLE_CONFIG;
	bool no_events = false;
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
		if (!strcmp(argv[i], "--no-events")) {
			no_events = true;
			continue;
		}
		if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
			usage(argv[0]);
			return 0;
		}
		usage(argv[0]);
		return 2;
	}

	ret = load_config(config_path, &config);
	if (ret)
		return 1;

	if (no_events)
		config.include_events = false;

	ret = dry_run ? dry_run_bundle(&config) : print_bundle(&config);
	free_config(&config);
	return ret ? 1 : 0;
}
