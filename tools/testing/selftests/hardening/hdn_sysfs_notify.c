// SPDX-License-Identifier: GPL-2.0-only
/*
 * Real-interface notification transfer probe. An unrestricted launcher queues
 * inotify and fanotify events for a classified sysfs node, primes each proc
 * fdinfo seq_file, and execs a separately signed restricted receiver. The
 * receiver proves that event data and watched-inode metadata do not survive
 * the profile boundary. The qualification driver runs this as root so it can
 * create the fanotify group; the receiver receives no setup privilege.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/fanotify.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int parse_fd(const char *text)
{
	char *end;
	long value = strtol(text, &end, 10);

	if (*end || value < 0 || value > 0x7fffffff)
		return -1;
	return value;
}

static int open_fdinfo(int fd)
{
	char path[64];

	snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
	return open(path, O_RDONLY);
}

static int read_fdinfo_without_mark(int fd, const char *needle)
{
	char buffer[16384];
	ssize_t length;

	length = read(fd, buffer, sizeof(buffer) - 1);
	if (length < 0)
		return -1;
	buffer[length] = '\0';
	return strstr(buffer, needle) ? -1 : 0;
}

static int require_empty_notification(int fd)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	char buffer[4096];
	int bytes = -1;

	if (poll(&pfd, 1, 0) != 0)
		return -1;
	if (ioctl(fd, FIONREAD, &bytes) || bytes != 0)
		return -1;
	errno = 0;
	if (read(fd, buffer, sizeof(buffer)) != -1 || errno != EAGAIN)
		return -1;
	return 0;
}

static int trigger_sysfs(const char *path)
{
	char byte;
	int fd = open(path, O_RDONLY);
	int error = 0;

	if (fd < 0)
		return -1;
	if (read(fd, &byte, 1) < 0)
		error = -1;
	close(fd);
	return error;
}

int main(int argc, char **argv)
{
	char ifdarg[32], ffdarg[32], pfdarg[32], ifinfoarg[32], ffinfoarg[32];
	char helperarg[32];
	char byte;
	int ifd, ffd, pfd, ifinfo, ffinfo;
	pid_t helper;

	if (argc == 4 && !strcmp(argv[1], "transfer")) {
		char *parent = strdup(argv[3]);
		char *slash;
		int bytes;

		if (!parent)
			return 1;
		slash = strrchr(parent, '/');
		if (!slash || slash == parent)
			return 2;
		*slash = '\0';
		ifd = inotify_init1(IN_NONBLOCK);
		if (ifd < 0 || inotify_add_watch(ifd, parent,
				IN_OPEN | IN_ACCESS | IN_ATTRIB) < 0) {
			perror("inotify setup");
			return 1;
		}
		ffd = syscall(SYS_fanotify_init, FAN_CLASS_NOTIF | FAN_NONBLOCK,
			      O_RDONLY | O_LARGEFILE);
		if (ffd < 0 || syscall(SYS_fanotify_mark, ffd,
				      FAN_MARK_ADD | FAN_MARK_ONLYDIR,
				      FAN_OPEN | FAN_ACCESS | FAN_EVENT_ON_CHILD,
				      AT_FDCWD, parent)) {
			perror("fanotify setup");
			return 1;
		}
		if (trigger_sysfs(argv[3])) {
			perror("sysfs trigger");
			return 1;
		}
		if (ioctl(ifd, FIONREAD, &bytes) || bytes <= 0 ||
		    ioctl(ffd, FIONREAD, &bytes) || bytes <= 0)
			return 1;
		ifinfo = open_fdinfo(ifd);
		ffinfo = open_fdinfo(ffd);
		if (ifinfo < 0 || ffinfo < 0 || read(ifinfo, &byte, 1) != 1 ||
		    read(ffinfo, &byte, 1) != 1)
			return 1;
		pfd = syscall(SYS_fanotify_init, FAN_CLASS_CONTENT | FAN_NONBLOCK,
			      O_RDONLY | O_LARGEFILE);
		if (pfd < 0 || syscall(SYS_fanotify_mark, pfd,
				      FAN_MARK_ADD | FAN_MARK_ONLYDIR,
				      FAN_OPEN_PERM | FAN_EVENT_ON_CHILD,
				      AT_FDCWD, parent)) {
			perror("fanotify permission setup");
			return 1;
		}
		free(parent);
		helper = fork();
		if (helper < 0)
			return 1;
		if (!helper)
			_exit(trigger_sysfs(argv[3]) ? 1 : 0);
		{
			struct pollfd pfd_poll = { .fd = pfd, .events = POLLIN };

			if (poll(&pfd_poll, 1, 10000) != 1)
				return 1;
		}
		snprintf(ifdarg, sizeof(ifdarg), "%d", ifd);
		snprintf(ffdarg, sizeof(ffdarg), "%d", ffd);
		snprintf(pfdarg, sizeof(pfdarg), "%d", pfd);
		snprintf(ifinfoarg, sizeof(ifinfoarg), "%d", ifinfo);
		snprintf(ffinfoarg, sizeof(ffinfoarg), "%d", ffinfo);
		snprintf(helperarg, sizeof(helperarg), "%d", helper);
		execl(argv[2], argv[2], "receive", ifdarg, ffdarg, pfdarg,
		      ifinfoarg, ffinfoarg, helperarg, NULL);
		perror("exec receiver");
		return 1;
	}

	if (argc != 8 || strcmp(argv[1], "receive")) {
		fprintf(stderr, "usage: %s transfer RECEIVER SYSFS_FILE\n", argv[0]);
		return 2;
	}
	ifd = parse_fd(argv[2]);
	ffd = parse_fd(argv[3]);
	pfd = parse_fd(argv[4]);
	ifinfo = parse_fd(argv[5]);
	ffinfo = parse_fd(argv[6]);
	helper = parse_fd(argv[7]);
	if (ifd < 0 || ffd < 0 || pfd < 0 || ifinfo < 0 || ffinfo < 0 ||
	    helper < 0)
		return 2;
	if (require_empty_notification(ifd) || require_empty_notification(ffd) ||
	    require_empty_notification(pfd))
		return 1;
	{
		int status;

		if (waitpid(helper, &status, 0) != helper || !WIFEXITED(status) ||
		    WEXITSTATUS(status))
			return 1;
	}
	if (read_fdinfo_without_mark(ifinfo, "inotify wd:") ||
	    read_fdinfo_without_mark(ffinfo, "fanotify ino:"))
		return 1;
	close(ifinfo);
	close(ffinfo);
	ifinfo = open_fdinfo(ifd);
	ffinfo = open_fdinfo(ffd);
	if (ifinfo < 0 || ffinfo < 0 ||
	    read_fdinfo_without_mark(ifinfo, "inotify wd:") ||
	    read_fdinfo_without_mark(ffinfo, "fanotify ino:"))
		return 1;
	close(ifd);
	close(ffd);
	close(pfd);
	close(ifinfo);
	close(ffinfo);
	puts("sysfs notification view: pass");
	return 0;
}
