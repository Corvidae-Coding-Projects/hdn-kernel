// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/mount.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define HDN_SEAL_RETRIES 20
#define HDN_SEAL_RETRY_NS 250000000L

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s MOUNTPOINT -- COMMAND [ARG...]\n", prog);
}

static int remount_state_once(const char *path, bool readonly)
{
	unsigned long flags = MS_REMOUNT;

#ifdef __NR_mount_setattr
	struct mount_attr attr = {
		.attr_set = readonly ? MOUNT_ATTR_RDONLY : 0,
		.attr_clr = readonly ? 0 : MOUNT_ATTR_RDONLY,
	};

	if (!syscall(__NR_mount_setattr, AT_FDCWD, path, 0, &attr,
		     sizeof(attr))) {
		struct statvfs state;

		if (readonly || statvfs(path, &state) ||
		    !(state.f_flag & ST_RDONLY))
			return 0;
		/* A legacy remount may also have set the superblock read-only. */
	} else if (errno != ENOSYS && errno != EINVAL &&
		   errno != EOPNOTSUPP) {
		return -errno;
	}
#endif

	if (readonly)
		flags |= MS_RDONLY;

	if (!mount(NULL, path, NULL, flags, NULL))
		return 0;

	return -errno;
}

static int remount_state(const char *path, bool readonly)
{
	struct timespec delay = {
		.tv_nsec = HDN_SEAL_RETRY_NS,
	};
	unsigned int attempts = readonly ? HDN_SEAL_RETRIES : 1;
	unsigned int attempt;
	int ret = -EIO;

	for (attempt = 0; attempt < attempts; attempt++) {
		ret = remount_state_once(path, readonly);
		if (!ret)
			return 0;
		if (ret != -EBUSY || attempt + 1 == attempts)
			break;
		sync();
		while (nanosleep(&delay, &delay) && errno == EINTR)
			;
		delay.tv_sec = 0;
		delay.tv_nsec = HDN_SEAL_RETRY_NS;
	}

	fprintf(stderr, "hdn-rofs-transaction: remount %s %s failed: %s\n",
		path, readonly ? "read-only" : "writable", strerror(-ret));
	return ret;
}

static int run_command(char **argv)
{
	int status;
	pid_t child;

	child = fork();
	if (child < 0) {
		fprintf(stderr, "hdn-rofs-transaction: fork failed: %s\n",
			strerror(errno));
		return 1;
	}

	if (!child) {
		execv(argv[0], argv);
		fprintf(stderr, "hdn-rofs-transaction: exec %s failed: %s\n",
			argv[0], strerror(errno));
		_exit(127);
	}

	if (waitpid(child, &status, 0) < 0) {
		fprintf(stderr, "hdn-rofs-transaction: wait failed: %s\n",
			strerror(errno));
		return 1;
	}

	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	if (WIFSIGNALED(status))
		return 128 + WTERMSIG(status);

	return 1;
}

int main(int argc, char **argv)
{
	const char *mountpoint;
	int command_arg = 2;
	int command_status;
	int seal_ret;

	if (argc < 4) {
		usage(argv[0]);
		return 2;
	}

	mountpoint = argv[1];
	if (mountpoint[0] != '/') {
		fprintf(stderr,
			"hdn-rofs-transaction: mountpoint must be absolute: %s\n",
			mountpoint);
		return 2;
	}

	if (!strcmp(argv[command_arg], "--")) {
		command_arg++;
		if (command_arg >= argc) {
			usage(argv[0]);
			return 2;
		}
	}

	if (remount_state(mountpoint, false))
		return 1;

	command_status = run_command(&argv[command_arg]);
	seal_ret = remount_state(mountpoint, true);
	if (seal_ret)
		return 1;

	return command_status;
}
