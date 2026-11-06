// SPDX-License-Identifier: GPL-2.0-only
/*
 * Real-interface probe. The qualification driver assigns the receiving copy
 * of this executable a signed HIDE_SYSFS_* profile. The unrestricted launcher
 * calls: hdn_sysfs_view transfer /receiver /sys/classified/attribute
 * File, O_PATH, parent-directory and fdinfo descriptors cross exec, including
 * a byte already buffered by seq_file. No policy mutation or privileged setup
 * is performed by this probe.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>

static void require_hidden(long result, const char *operation)
{
	if (result != -1 || errno != ENOENT) {
		fprintf(stderr, "%s: expected ENOENT, result=%ld errno=%d\n",
			operation, result, errno);
		exit(1);
	}
}

int main(int argc, char **argv)
{
	char buffer[4096], fdarg[32], opatharg[32], dirarg[32], fdinfoarg[32];
	char fdpath[64], fdinfopath[64];
	struct stat st;
	struct statx stx;
	struct pollfd pollfd;
	int fd, opath, dirfd, fdinfo;
	void *mapping;

	if (argc == 4 && !strcmp(argv[1], "transfer")) {
		char *parent = strdup(argv[3]);
		char *slash;

		if (!parent)
			return 1;
		slash = strrchr(parent, '/');
		if (!slash)
			return 2;
		if (slash == parent)
			slash[1] = '\0';
		else
			*slash = '\0';
		fd = open(argv[3], O_RDONLY);
		opath = open(argv[3], O_PATH);
		dirfd = open(parent, O_RDONLY | O_DIRECTORY);
		free(parent);
		if (fd < 0 || opath < 0 || dirfd < 0 || read(fd, buffer, 1) != 1) {
			perror("open/prefill");
			return 1;
		}
		snprintf(fdinfopath, sizeof(fdinfopath), "/proc/self/fdinfo/%d", fd);
		fdinfo = open(fdinfopath, O_RDONLY);
		if (fdinfo < 0)
			return 1;
		snprintf(fdarg, sizeof(fdarg), "%d", fd);
		snprintf(opatharg, sizeof(opatharg), "%d", opath);
		snprintf(dirarg, sizeof(dirarg), "%d", dirfd);
		snprintf(fdinfoarg, sizeof(fdinfoarg), "%d", fdinfo);
		execl(argv[2], argv[2], "receive", fdarg, opatharg, dirarg,
		      fdinfoarg, argv[3], NULL);
		perror("exec receiver");
		return 1;
	}
	if (argc != 7 || strcmp(argv[1], "receive")) {
		fprintf(stderr, "usage: %s transfer RECEIVER SYSFS_FILE\n", argv[0]);
		return 2;
	}
	for (int index = 2; index <= 5; index++) {
		char *end;
		long value = strtol(argv[index], &end, 10);

		if (*end || value < 0 || value > 0x7fffffff)
			return 2;
		if (index == 2)
			fd = value;
		else if (index == 3)
			opath = value;
		else if (index == 4)
			dirfd = value;
		else
			fdinfo = value;
	}
	require_hidden(open(argv[6], O_RDONLY), "lookup/open");
	require_hidden(read(fd, buffer, sizeof(buffer)), "buffered read");
	require_hidden(pread(fd, buffer, sizeof(buffer), 0), "pread");
	require_hidden(fstat(fd, &st), "fstat");
	require_hidden(fstat(opath, &st), "O_PATH fstat");
	require_hidden(statx(opath, "", AT_EMPTY_PATH, STATX_BASIC_STATS, &stx),
		       "O_PATH statx");
	require_hidden(fstat(dirfd, &st), "directory fstat");
	require_hidden(flistxattr(fd, buffer, sizeof(buffer)), "listxattr");
	require_hidden(fgetxattr(fd, "user.hdn", buffer, sizeof(buffer)), "getxattr");
	require_hidden(fsetxattr(fd, "user.hdn", "x", 1, 0), "setxattr");
	require_hidden(lseek(fd, 0, SEEK_SET), "seek");
	require_hidden(lseek(dirfd, 0, SEEK_SET), "directory seek");
	require_hidden(fsync(fd), "fsync");
	require_hidden(syscall(SYS_getdents64, dirfd, buffer, sizeof(buffer)), "readdir");
	const char *base = strrchr(argv[6], '/');
	if (!base || !base[1])
		return 2;
	require_hidden(openat(dirfd, base + 1, O_RDONLY), "directory-relative lookup");
	snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", fd);
	require_hidden(readlink(fdpath, buffer, sizeof(buffer)), "proc fd readlink");
	snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", opath);
	require_hidden(readlink(fdpath, buffer, sizeof(buffer)), "proc O_PATH readlink");
	snprintf(fdinfopath, sizeof(fdinfopath), "/proc/self/fdinfo/%d", fd);
	require_hidden(open(fdinfopath, O_RDONLY), "proc fdinfo open");
	require_hidden(read(fdinfo, buffer, sizeof(buffer)), "transferred fdinfo read");
	pollfd = (struct pollfd){ .fd = fd, .events = POLLIN };
	if (poll(&pollfd, 1, 0) != 1 || pollfd.revents != POLLERR)
		return 1;
	mapping = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mapping != MAP_FAILED || errno != ENOENT)
		return 1;
	close(fd);
	close(opath);
	close(dirfd);
	close(fdinfo);
	puts("sysfs descriptor view: pass");
	return 0;
}
