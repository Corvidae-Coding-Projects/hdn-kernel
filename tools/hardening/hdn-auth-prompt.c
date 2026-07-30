// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define HDN_AUTH_PROMPT_MAX_METADATA 8192
#define HDN_AUTH_PROMPT_MAX_TEXT 512

struct hdn_prompt_metadata {
	char *action;
	char *title;
	char *message;
	char *consequence;
	char *risk;
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--test-approve|--test-deny] ACTION\n"
		"\n"
		"Reads HDN prompt metadata on stdin, shows a desktop approval prompt,\n"
		"and exits 0 only when the user approves.\n",
		prog);
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
	if (len > HDN_AUTH_PROMPT_MAX_TEXT)
		return false;

	for (p = (const unsigned char *)text; *p; p++) {
		if (*p >= 0x20 && *p <= 0x7e)
			continue;
		return false;
	}

	return true;
}

static int read_metadata(char **metadata)
{
	char *buf;
	size_t done = 0;

	buf = calloc(HDN_AUTH_PROMPT_MAX_METADATA + 1, 1);
	if (!buf)
		return -ENOMEM;

	for (;;) {
		ssize_t len;

		len = read(STDIN_FILENO, buf + done,
			   HDN_AUTH_PROMPT_MAX_METADATA - done);
		if (len < 0) {
			if (errno == EINTR)
				continue;
			free(buf);
			return -errno;
		}
		if (!len)
			break;
		done += (size_t)len;
		if (done == HDN_AUTH_PROMPT_MAX_METADATA) {
			free(buf);
			return -E2BIG;
		}
	}

	if (!done) {
		free(buf);
		return -EINVAL;
	}

	buf[done] = '\0';
	*metadata = buf;
	return 0;
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

static int parse_metadata(char *blob, struct hdn_prompt_metadata *metadata)
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
		if (!strcmp(line, "HDN_PROMPT_METADATA_V1")) {
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

static int child_status_result(pid_t child)
{
	int status;

	if (waitpid(child, &status, 0) < 0)
		return 1;
	if (!WIFEXITED(status))
		return 1;
	return WEXITSTATUS(status);
}

static int run_prompt_tool(const char *path, char *const argv[])
{
	pid_t child;

	child = fork();
	if (child < 0) {
		fprintf(stderr, "hdn-auth-prompt: fork failed: %s\n",
			strerror(errno));
		return 1;
	}

	if (!child) {
		execv(path, argv);
		_exit(errno == ENOENT ? 127 : 126);
	}

	return child_status_result(child) ? 1 : 0;
}

static bool desktop_session_available(void)
{
	const char *display = getenv("DISPLAY");
	const char *wayland = getenv("WAYLAND_DISPLAY");

	return (display && display[0]) || (wayland && wayland[0]);
}

static int show_graphical_prompt(const struct hdn_prompt_metadata *metadata)
{
	char body[2048];

	if (!desktop_session_available()) {
		fprintf(stderr,
			"hdn-auth-prompt: no graphical session available; denying request\n");
		return 1;
	}

	if (metadata->risk) {
		snprintf(body, sizeof(body), "%s\n\n%s\n\nRisk: %s",
			 metadata->message, metadata->consequence,
			 metadata->risk);
	} else {
		snprintf(body, sizeof(body), "%s\n\n%s",
			 metadata->message, metadata->consequence);
	}

	if (!access("/usr/bin/zenity", X_OK)) {
		char *const argv[] = {
			"zenity", "--question", "--title", metadata->title,
			"--width", "480", "--ok-label", "Allow",
			"--cancel-label", "Cancel", "--text", body, NULL
		};

		return run_prompt_tool("/usr/bin/zenity", argv);
	}

	if (!access("/usr/bin/kdialog", X_OK)) {
		char *const argv[] = {
			"kdialog", "--title", metadata->title,
			"--yes-label", "Allow", "--no-label", "Cancel",
			"--yesno", body, NULL
		};

		return run_prompt_tool("/usr/bin/kdialog", argv);
	}

	if (!access("/usr/bin/xmessage", X_OK)) {
		char *const argv[] = {
			"xmessage", "-center", "-title", metadata->title,
			"-buttons", "Allow:0,Cancel:1", body, NULL
		};

		return run_prompt_tool("/usr/bin/xmessage", argv);
	}

	fprintf(stderr,
		"hdn-auth-prompt: no supported graphical prompt helper found\n");
	return 1;
}

int main(int argc, char **argv)
{
	struct hdn_prompt_metadata metadata;
	const char *action = NULL;
	bool test_approve = false;
	bool test_deny = false;
	char *blob = NULL;
	int ret;
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
			usage(argv[0]);
			return 0;
		}
		if (!strcmp(argv[i], "--test-approve")) {
			test_approve = true;
			continue;
		}
		if (!strcmp(argv[i], "--test-deny")) {
			test_deny = true;
			continue;
		}
		if (!action) {
			action = argv[i];
			continue;
		}
		usage(argv[0]);
		return 2;
	}

	if (!action || !safe_name(action) || (test_approve && test_deny)) {
		usage(argv[0]);
		return 2;
	}

	ret = read_metadata(&blob);
	if (ret) {
		fprintf(stderr, "hdn-auth-prompt: invalid prompt metadata\n");
		return 1;
	}

	ret = parse_metadata(blob, &metadata);
	if (ret || strcmp(metadata.action, action)) {
		fprintf(stderr, "hdn-auth-prompt: rejected prompt metadata\n");
		free(blob);
		return 1;
	}

	if (test_approve) {
		free(blob);
		return 0;
	}
	if (test_deny) {
		free(blob);
		return 1;
	}

	ret = show_graphical_prompt(&metadata);
	free(blob);
	return ret;
}
