// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/reboot.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static void mkdir_if_needed(const char *path, mode_t mode)
{
	if (mkdir(path, mode) && errno != EEXIST)
		printf("HDN_INIT mkdir %s failed: %s\n", path, strerror(errno));
}

static void mount_if_needed(const char *src, const char *target,
			    const char *type)
{
	if (mount(src, target, type, 0, "") && errno != EBUSY)
		printf("HDN_INIT mount %s on %s failed: %s\n", type, target,
		       strerror(errno));
}

static int run_smoke(void)
{
	int status;
	pid_t child;

	child = fork();
	if (child < 0) {
		printf("HDN_INIT fork failed: %s\n", strerror(errno));
		return 127;
	}

	if (!child) {
		char *const argv[] = { "/hdn_smoke", NULL };
		char *const envp[] = { "PATH=/", NULL };

		execve(argv[0], argv, envp);
		printf("HDN_INIT exec /hdn_smoke failed: %s\n",
		       strerror(errno));
		_exit(127);
	}

	if (waitpid(child, &status, 0) < 0) {
		printf("HDN_INIT waitpid failed: %s\n", strerror(errno));
		return 127;
	}

	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	if (WIFSIGNALED(status))
		return 128 + WTERMSIG(status);
	return 127;
}

int main(void)
{
	int console;
	int ret;

	mkdir_if_needed("/dev", 0755);
	mount_if_needed("devtmpfs", "/dev", "devtmpfs");
	mkdir_if_needed("/dev/pts", 0755);
	if (mount("devpts", "/dev/pts", "devpts", MS_NOSUID | MS_NOEXEC,
		  "newinstance,ptmxmode=0666,mode=0620") && errno != EBUSY)
		printf("HDN_INIT mount devpts on /dev/pts failed: %s\n",
		       strerror(errno));
	if (symlink("pts/ptmx", "/dev/ptmx") && errno != EEXIST)
		printf("HDN_INIT symlink /dev/ptmx failed: %s\n",
		       strerror(errno));
	console = open("/dev/console", O_RDWR);
	if (console >= 0) {
		dup2(console, STDIN_FILENO);
		dup2(console, STDOUT_FILENO);
		dup2(console, STDERR_FILENO);
		if (console > STDERR_FILENO)
			close(console);
	}

	printf("HDN_INIT booted\n");
	mkdir_if_needed("/proc", 0555);
	mkdir_if_needed("/sys", 0555);
	mount_if_needed("proc", "/proc", "proc");
	mount_if_needed("sysfs", "/sys", "sysfs");
	mkdir_if_needed("/sys/kernel/security", 0555);
	mount_if_needed("securityfs", "/sys/kernel/security", "securityfs");
	mkdir_if_needed("/sys/kernel/debug", 0555);
	mount_if_needed("debugfs", "/sys/kernel/debug", "debugfs");
	mkdir_if_needed("/sys/kernel/tracing", 0555);
	mount_if_needed("tracefs", "/sys/kernel/tracing", "tracefs");

	ret = run_smoke();
	printf("HDN_SMOKE_EXIT=%d\n", ret);
	sync();
	reboot(LINUX_REBOOT_CMD_POWER_OFF);
	reboot(LINUX_REBOOT_CMD_RESTART);
	return ret;
}
