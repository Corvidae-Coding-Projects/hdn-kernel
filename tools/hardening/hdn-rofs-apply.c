// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/mount.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000
#endif

enum hdn_rofs_requirement {
	HDN_ROFS_REQUIRED,
	HDN_ROFS_OPTIONAL,
	HDN_ROFS_BIND,
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-r|--recursive] [-f PATHS.conf] [MOUNTPOINT...]\n"
		"PATHS.conf entries: PATH, required PATH, optional PATH, or bind PATH\n",
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

static int decode_mountinfo_path(const char *src, char *dst, size_t dst_size)
{
	size_t di = 0;

	while (*src) {
		unsigned char ch;

		if (di + 1 >= dst_size)
			return -ENAMETOOLONG;

		if (src[0] == '\\' &&
		    src[1] >= '0' && src[1] <= '7' &&
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

static int fallback_path_is_mountpoint(const char *path)
{
	char parent[PATH_MAX];
	struct stat st;
	struct stat parent_st;
	size_t len;

	if (!strcmp(path, "/"))
		return 1;

	len = strlen(path);
	if (len + 4 > sizeof(parent))
		return -ENAMETOOLONG;

	memcpy(parent, path, len);
	if (len > 1 && parent[len - 1] == '/')
		memcpy(parent + len, "..", 3);
	else
		memcpy(parent + len, "/..", 4);

	if (stat(path, &st))
		return -errno;
	if (stat(parent, &parent_st))
		return -errno;

	return st.st_dev != parent_st.st_dev ||
	       (st.st_dev == parent_st.st_dev && st.st_ino == parent_st.st_ino);
}

static int path_is_mountpoint(const char *path)
{
	char *line = NULL;
	size_t size = 0;
	FILE *file;
	int ret = 0;

	file = fopen("/proc/self/mountinfo", "r");
	if (!file)
		return fallback_path_is_mountpoint(path);

	while (getline(&line, &size, file) >= 0) {
		char decoded[PATH_MAX];
		char *fields = line;
		char *mountpoint = NULL;
		int i;

		for (i = 0; i < 5; i++) {
			mountpoint = strsep(&fields, " ");
			if (!mountpoint)
				break;
		}
		if (!mountpoint)
			continue;

		if (decode_mountinfo_path(mountpoint, decoded,
					  sizeof(decoded)))
			continue;
		if (!strcmp(decoded, path)) {
			ret = 1;
			break;
		}
	}

	free(line);
	fclose(file);
	return ret;
}

static int parse_config_entry(char *entry, const char **path,
			      enum hdn_rofs_requirement *requirement)
{
	char *first = entry;
	char *rest;

	*requirement = HDN_ROFS_REQUIRED;
	*path = entry;

	if (entry[0] == '/')
		return 0;

	rest = first;
	while (*rest && !isspace((unsigned char)*rest))
		rest++;
	if (*rest) {
		*rest++ = '\0';
		rest = trim(rest);
	}

	if (!strcmp(first, "required")) {
		*requirement = HDN_ROFS_REQUIRED;
		*path = rest;
	} else if (!strcmp(first, "optional")) {
		*requirement = HDN_ROFS_OPTIONAL;
		*path = rest;
	} else if (!strcmp(first, "bind")) {
		*requirement = HDN_ROFS_BIND;
		*path = rest;
	} else {
		fprintf(stderr,
			"hdn-rofs-apply: unknown path-list directive: %s\n",
			first);
		return -EINVAL;
	}

	if (!*path || !(*path)[0]) {
		fprintf(stderr,
			"hdn-rofs-apply: missing path for %s entry\n", first);
		return -EINVAL;
	}

	return 0;
}

static int apply_mount_readonly(const char *path, bool recursive,
				 bool bind_remount)
{
#ifdef __NR_mount_setattr
	struct mount_attr attr = {
		.attr_set = MOUNT_ATTR_RDONLY,
	};
	int flags = recursive ? AT_RECURSIVE : 0;

	if (!syscall(__NR_mount_setattr, AT_FDCWD, path, flags, &attr,
		     sizeof(attr)))
		return 0;
	if (errno != ENOSYS && errno != EINVAL && errno != EOPNOTSUPP)
		return -errno;
#endif

	if (!recursive) {
		unsigned long flags = MS_REMOUNT | MS_RDONLY;

		if (bind_remount)
			flags |= MS_BIND;
		if (!mount(NULL, path, NULL, flags, NULL))
			return 0;
		return -errno;
	}

	return -EOPNOTSUPP;
}

static int ensure_bind_mount(const char *path, bool *created)
{
	int ret;

	*created = false;
	ret = path_is_mountpoint(path);
	if (ret < 0)
		return ret;
	if (ret)
		return 0;

	if (mount(path, path, NULL, MS_BIND, NULL))
		return -errno;
	*created = true;
	return 0;
}

static int apply_path(const char *path, bool recursive,
		      enum hdn_rofs_requirement requirement)
{
	bool created_bind = false;
	int ret;

	if (!path[0] || path[0] != '/') {
		fprintf(stderr, "hdn-rofs-apply: path must be absolute: %s\n",
			path);
		return -EINVAL;
	}

	if (requirement == HDN_ROFS_OPTIONAL) {
		ret = path_is_mountpoint(path);
		if (ret < 0) {
			if (ret == -ENOENT) {
				fprintf(stderr,
					"hdn-rofs-apply: skipping absent optional path %s\n",
					path);
				return 0;
			}
			fprintf(stderr,
				"hdn-rofs-apply: cannot inspect optional path %s: %s\n",
				path, strerror(-ret));
			return ret;
		}
		if (!ret) {
			fprintf(stderr,
				"hdn-rofs-apply: skipping optional non-mountpoint %s\n",
				path);
			return 0;
		}
	}

	if (requirement == HDN_ROFS_BIND) {
		ret = ensure_bind_mount(path, &created_bind);
		if (ret) {
			fprintf(stderr,
				"hdn-rofs-apply: failed to establish bind mount at %s: %s\n",
				path, strerror(-ret));
			return ret;
		}
	}

	ret = apply_mount_readonly(path, recursive, created_bind);
	if (ret) {
		fprintf(stderr,
			"hdn-rofs-apply: failed to make %s read-only: %s\n",
			path, strerror(-ret));
		if (created_bind && umount2(path, MNT_DETACH))
			fprintf(stderr,
				"hdn-rofs-apply: failed to remove unsealed bind mount at %s: %s\n",
				path, strerror(errno));
	}

	return ret;
}

static int apply_file(const char *path, bool recursive)
{
	char *line = NULL;
	size_t size = 0;
	ssize_t len;
	FILE *file;
	struct stat st;
	int flags = O_RDONLY | O_CLOEXEC;
	int fd;
	int ret = 0;

#ifdef O_NOFOLLOW
	flags |= O_NOFOLLOW;
#endif

	fd = open(path, flags);
	if (fd < 0) {
		fprintf(stderr, "hdn-rofs-apply: cannot open %s: %s\n", path,
			strerror(errno));
		return -errno;
	}

	if (fstat(fd, &st)) {
		ret = -errno;
		fprintf(stderr, "hdn-rofs-apply: cannot stat %s: %s\n", path,
			strerror(errno));
		close(fd);
		return ret;
	}

	if (!S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 022)) {
		fprintf(stderr,
			"hdn-rofs-apply: refusing unsafe path list %s\n",
			path);
		close(fd);
		return -EACCES;
	}

	file = fdopen(fd, "r");
	if (!file) {
		ret = -errno;
		fprintf(stderr, "hdn-rofs-apply: fdopen %s failed: %s\n",
			path, strerror(errno));
		close(fd);
		return ret;
	}

	while ((len = getline(&line, &size, file)) >= 0) {
		char *entry = trim(line);
		enum hdn_rofs_requirement requirement;
		const char *entry_path;
		int path_ret;

		(void)len;
		if (!entry[0] || entry[0] == '#')
			continue;

		path_ret = parse_config_entry(entry, &entry_path,
					      &requirement);
		if (!path_ret)
			path_ret = apply_path(entry_path, recursive,
					      requirement);
		if (path_ret && !ret)
			ret = path_ret;
	}

	if (ferror(file) && !ret)
		ret = -EIO;

	free(line);
	fclose(file);
	return ret;
}

int main(int argc, char **argv)
{
	bool recursive = false;
	const char *config = NULL;
	bool saw_path = false;
	int ret = 0;
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-r") || !strcmp(argv[i], "--recursive")) {
			recursive = true;
			continue;
		} else if (!strcmp(argv[i], "-f") ||
			   !strcmp(argv[i], "--file")) {
			if (++i >= argc) {
				usage(argv[0]);
				return 2;
			}
			config = argv[i];
			continue;
		} else if (!strcmp(argv[i], "-h") ||
			   !strcmp(argv[i], "--help")) {
			usage(argv[0]);
			return 0;
		} else if (!strcmp(argv[i], "--")) {
			i++;
			break;
		} else if (argv[i][0] != '-') {
			break;
		}

		usage(argv[0]);
		return 2;
	}

	if (config) {
		ret = apply_file(config, recursive);
		if (ret)
			return 1;
	}

	for (; i < argc; i++) {
		int path_ret = apply_path(argv[i], recursive,
					  HDN_ROFS_REQUIRED);

		saw_path = true;
		if (path_ret && !ret)
			ret = path_ret;
	}

	if (!config && !saw_path) {
		usage(argv[0]);
		return 2;
	}

	return ret ? 1 : 0;
}
