// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef HDN_DNF5_PATH
#define HDN_DNF5_PATH "/usr/bin/dnf5"
#endif

#ifndef HDN_ROFS_TRANSACTION_PATH
#define HDN_ROFS_TRANSACTION_PATH "/usr/libexec/hdn-rofs-transaction"
#endif

#ifndef HDN_PACKAGE_WORKER_PATH
#define HDN_PACKAGE_WORKER_PATH "/usr/libexec/hdn-package-worker"
#endif

#ifndef HDN_POLICY_LOAD_PATH
#define HDN_POLICY_LOAD_PATH "/usr/libexec/hdn-policy-load"
#endif

#ifndef HDN_SYSTEMCTL_PATH
#define HDN_SYSTEMCTL_PATH "/usr/bin/systemctl"
#endif

#ifndef HDN_MOUNTINFO_PATH
#define HDN_MOUNTINFO_PATH "/proc/self/mountinfo"
#endif

static const char *const boot_mounts[] = {
	"/boot",
	"/boot/efi",
};

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [update|repair]\n", prog);
}

static bool mount_option_present(const char *options, const char *wanted)
{
	const char *option = options;
	size_t wanted_len = strlen(wanted);

	while (option && *option) {
		const char *comma = strchr(option, ',');
		size_t len = comma ? (size_t)(comma - option) : strlen(option);

		if (len == wanted_len && !memcmp(option, wanted, len))
			return true;
		option = comma ? comma + 1 : NULL;
	}

	return false;
}

static int decode_mountinfo_path(const char *src, char *dst, size_t dst_size)
{
	size_t di = 0;

	while (*src) {
		unsigned char ch;

		if (di + 1 >= dst_size)
			return -ENAMETOOLONG;
		if (src[0] == '\\' && src[1] >= '0' && src[1] <= '7' &&
		    src[2] >= '0' && src[2] <= '7' &&
		    src[3] >= '0' && src[3] <= '7') {
			ch = ((src[1] - '0') << 6) |
			     ((src[2] - '0') << 3) |
			     (src[3] - '0');
			src += 4;
		} else {
			ch = *src++;
		}
		dst[di++] = ch;
	}

	dst[di] = '\0';
	return 0;
}

static int mount_is_readonly(const char *path, bool *mounted, bool *readonly)
{
	char *line = NULL;
	size_t size = 0;
	FILE *file;
	int ret = 0;

	*mounted = false;
	*readonly = false;
	file = fopen(HDN_MOUNTINFO_PATH, "r");
	if (!file) {
		fprintf(stderr, "hdn-package-worker: cannot open %s: %s\n",
			HDN_MOUNTINFO_PATH, strerror(errno));
		return -errno;
	}

	while (getline(&line, &size, file) >= 0) {
		char decoded[PATH_MAX];
		char *fields = line;
		char *mountpoint = NULL;
		char *options = NULL;
		int i;

		for (i = 0; i < 6; i++) {
			char *field = strsep(&fields, " ");

			if (!field)
				break;
			if (i == 4)
				mountpoint = field;
			else if (i == 5)
				options = field;
		}
		if (!mountpoint || !options ||
		    decode_mountinfo_path(mountpoint, decoded, sizeof(decoded)) ||
		    strcmp(decoded, path))
			continue;

		/* Retain the final match, which is the visible mount in a stack. */
		*mounted = true;
		*readonly = mount_option_present(options, "ro");
	}

	if (ferror(file)) {
		fprintf(stderr, "hdn-package-worker: cannot read %s: %s\n",
			HDN_MOUNTINFO_PATH, strerror(errno));
		ret = -EIO;
	}
	free(line);
	fclose(file);
	return ret;
}

static int open_next_boot_mount(unsigned int stage, const char *operation)
{
	for (; stage < sizeof(boot_mounts) / sizeof(boot_mounts[0]); stage++) {
		char next_stage[16];
		bool mounted;
		bool readonly;
		char *const transaction_argv[] = {
			"hdn-rofs-transaction",
			(char *)boot_mounts[stage],
			"--",
			(char *)HDN_PACKAGE_WORKER_PATH,
			"--continue",
			next_stage,
			(char *)operation,
			NULL,
		};

		if (mount_is_readonly(boot_mounts[stage], &mounted, &readonly))
			return 1;
		if (!mounted || !readonly)
			continue;

		snprintf(next_stage, sizeof(next_stage), "%u", stage + 1);
		execv(HDN_ROFS_TRANSACTION_PATH, transaction_argv);
		fprintf(stderr, "hdn-package-worker: exec %s failed: %s\n",
			HDN_ROFS_TRANSACTION_PATH, strerror(errno));
		return errno == ENOENT ? 127 : 126;
	}

	return -1;
}

static int run_command(const char *path, char *const argv[])
{
	pid_t child;
	int status;

	child = fork();
	if (child < 0) {
		fprintf(stderr, "hdn-package-worker: fork failed: %s\n",
			strerror(errno));
		return 1;
	}
	if (!child) {
		execv(path, argv);
		fprintf(stderr, "hdn-package-worker: exec %s failed: %s\n",
			path, strerror(errno));
		_exit(errno == ENOENT ? 127 : 126);
	}
	if (waitpid(child, &status, 0) < 0) {
		fprintf(stderr, "hdn-package-worker: wait failed: %s\n",
			strerror(errno));
		return 1;
	}
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	if (WIFSIGNALED(status))
		return 128 + WTERMSIG(status);
	return 1;
}

static int quiesce_package_services(void)
{
	char *const argv[] = {
		"systemctl",
		"stop",
		"packagekit.service",
		"dnf5daemon-server.service",
		NULL,
	};
	int ret;

	ret = run_command(HDN_SYSTEMCTL_PATH, argv);
	if (ret)
		fprintf(stderr,
			"hdn-package-worker: cannot quiesce package services\n");
	return ret;
}

int main(int argc, char **argv)
{
	char *const update_argv[] = {
		"dnf5",
		"upgrade",
		"--refresh",
		"--assumeyes",
		NULL,
	};
	char *const repair_argv[] = {
		"dnf5",
		"distro-sync",
		"--refresh",
		"--assumeyes",
		NULL,
	};
	char *const refresh_argv[] = {
		"hdn-policy-load",
		"--refresh",
		NULL,
	};
	char *const *dnf_argv;
	const char *operation;
	unsigned int stage = 0;
	int ret;

	if (argc == 1 || (argc == 2 && !strcmp(argv[1], "update"))) {
		dnf_argv = update_argv;
		operation = "update";
	} else if (argc == 2 && !strcmp(argv[1], "repair")) {
		dnf_argv = repair_argv;
		operation = "repair";
	} else if (argc == 4 && !strcmp(argv[1], "--continue") &&
		   (!strcmp(argv[2], "1") || !strcmp(argv[2], "2")) &&
		   (!strcmp(argv[3], "update") || !strcmp(argv[3], "repair"))) {
		stage = (unsigned int)(argv[2][0] - '0');
		operation = argv[3];
		dnf_argv = !strcmp(operation, "repair") ? repair_argv : update_argv;
	} else {
		usage(argv[0]);
		return 2;
	}
	if (geteuid() != 0) {
		fprintf(stderr, "hdn-package-worker: must run as root\n");
		return 1;
	}

	if (clearenv() || setenv("PATH", "/usr/sbin:/usr/bin", 1) ||
	    setenv("HOME", "/root", 1) || setenv("LANG", "C.UTF-8", 1) ||
	    setenv("HDN_PACKAGE_TRANSACTION", "1", 1)) {
		fprintf(stderr, "hdn-package-worker: environment setup failed: %s\n",
			strerror(errno));
		return 1;
	}

	ret = open_next_boot_mount(stage, operation);
	if (ret >= 0)
		return ret;

	ret = quiesce_package_services();
	if (ret)
		return ret;

	ret = run_command(HDN_DNF5_PATH, (char *const *)dnf_argv);
	if (!ret)
		ret = run_command(HDN_POLICY_LOAD_PATH, refresh_argv);
	if (ret)
		fprintf(stderr,
			"hdn-package-worker: package transaction or policy refresh failed\n");
	if (quiesce_package_services())
		return 1;
	return ret;
}
