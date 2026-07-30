// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef HDN_APPROVAL_TOKEN_DIR
#define HDN_APPROVAL_TOKEN_DIR "/run/hdn/approvals"
#endif

#define HDN_APPROVAL_TOKEN_DEFAULT_TTL_MS 30000ULL
#define HDN_APPROVAL_TOKEN_MAX_TTL_MS 300000ULL
#define HDN_APPROVAL_TOKEN_MAGIC "HDN_APPROVAL_V1"

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s --intent INTENT [--dir DIR] [--ttl-ms MS] [--name NAME]\n"
		"\n"
		"Creates a root-owned 0600 approval token for hdn-admin-broker.\n"
		"Known intents: rofs-apply, rofs-transaction, policy-commit, policy-rollback\n",
		prog);
}

static bool known_intent(const char *intent)
{
	return !strcmp(intent, "rofs-apply") ||
	       !strcmp(intent, "rofs-transaction") ||
	       !strcmp(intent, "policy-commit") ||
	       !strcmp(intent, "policy-rollback");
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

static int require_safe_dir_path(const char *path)
{
	if (!path || path[0] != '/') {
		fprintf(stderr,
			"hdn-approval-token: token directory must be absolute\n");
		return -EINVAL;
	}
	if (!strcmp(path, "/") || path_has_dot_component(path)) {
		fprintf(stderr,
			"hdn-approval-token: unsafe token directory: %s\n",
			path);
		return -EINVAL;
	}

	return 0;
}

static bool safe_token_name(const char *name)
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

static int parse_u64(const char *text, unsigned long long *value)
{
	char *end;

	errno = 0;
	*value = strtoull(text, &end, 10);
	if (errno || end == text || *end)
		return -EINVAL;
	return 0;
}

static int open_token_dir(const char *dir)
{
	struct stat st;
	int flags = O_RDONLY | O_CLOEXEC | O_DIRECTORY;
	int fd;

#ifdef O_NOFOLLOW
	flags |= O_NOFOLLOW;
#endif

	fd = open(dir, flags);
	if (fd < 0) {
		fprintf(stderr, "hdn-approval-token: cannot open %s: %s\n",
			dir, strerror(errno));
		return -errno;
	}

	if (fstat(fd, &st)) {
		int ret = -errno;

		fprintf(stderr, "hdn-approval-token: cannot stat %s: %s\n",
			dir, strerror(errno));
		close(fd);
		return ret;
	}

	if (!S_ISDIR(st.st_mode) || st.st_uid != 0 || (st.st_mode & 077)) {
		fprintf(stderr,
			"hdn-approval-token: refusing unsafe token directory %s\n",
			dir);
		close(fd);
		return -EACCES;
	}

	return fd;
}

static int monotonic_milliseconds(unsigned long long *now_ms)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return -errno;
	if (ts.tv_sec < 0)
		return -EINVAL;
	if ((unsigned long long)ts.tv_sec >
	    (ULLONG_MAX - (unsigned long long)(ts.tv_nsec / 1000000)) / 1000)
		return -EOVERFLOW;

	*now_ms = (unsigned long long)ts.tv_sec * 1000 +
		  (unsigned long long)(ts.tv_nsec / 1000000);
	return 0;
}

static int fill_random(void *buf, size_t len)
{
	size_t done = 0;
	int fd;

	fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	while (done < len) {
		ssize_t ret = read(fd, (char *)buf + done, len - done);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			ret = -errno;
			close(fd);
			return (int)ret;
		}
		if (!ret) {
			close(fd);
			return -EIO;
		}
		done += (size_t)ret;
	}

	close(fd);
	return 0;
}

static int random_token_name(char *name, size_t size)
{
	unsigned char random[8];
	int ret;

	ret = fill_random(random, sizeof(random));
	if (ret)
		return ret;

	if (snprintf(name, size,
		     "hdn-approval-%02x%02x%02x%02x%02x%02x%02x%02x.token",
		     random[0], random[1], random[2], random[3],
		     random[4], random[5], random[6], random[7]) >=
	    (int)size)
		return -ENAMETOOLONG;

	return 0;
}

static int join_path(char *path, size_t size, const char *dir,
		     const char *name)
{
	size_t len = strlen(dir);

	if (snprintf(path, size, "%s%s%s", dir, len && dir[len - 1] == '/' ?
		     "" : "/", name) >= (int)size)
		return -ENAMETOOLONG;
	return 0;
}

static int create_token_file(int dirfd, const char *name)
{
	int flags = O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC;

#ifdef O_NOFOLLOW
	flags |= O_NOFOLLOW;
#endif

	return openat(dirfd, name, flags, 0600);
}

static int write_all(int fd, const char *buf, size_t len)
{
	size_t done = 0;

	while (done < len) {
		ssize_t ret = write(fd, buf + done, len - done);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (!ret)
			return -EIO;
		done += (size_t)ret;
	}

	return 0;
}

static int issue_token(const char *dir, const char *intent,
		       unsigned long long ttl_ms, const char *requested_name)
{
	char name[96];
	char path[PATH_MAX];
	char text[256];
	unsigned int attempts;
	unsigned long long now_ms = 0;
	unsigned long long expires_ms = 0;
	struct stat st;
	int dirfd;
	int fd = -1;
	int ret;

	if (geteuid() != 0) {
		fprintf(stderr, "hdn-approval-token: must run as root\n");
		return 1;
	}
	if (!known_intent(intent)) {
		fprintf(stderr, "hdn-approval-token: unknown intent: %s\n",
			intent);
		return 1;
	}
	if (!ttl_ms || ttl_ms > HDN_APPROVAL_TOKEN_MAX_TTL_MS) {
		fprintf(stderr,
			"hdn-approval-token: ttl-ms must be between 1 and %llu\n",
			HDN_APPROVAL_TOKEN_MAX_TTL_MS);
		return 1;
	}

	ret = require_safe_dir_path(dir);
	if (ret)
		return 1;

	dirfd = open_token_dir(dir);
	if (dirfd < 0)
		return 1;

	if (monotonic_milliseconds(&now_ms)) {
		fprintf(stderr,
			"hdn-approval-token: cannot read monotonic clock\n");
		ret = 1;
		goto out_dir;
	}
	if (now_ms > ULLONG_MAX - ttl_ms) {
		ret = 1;
		goto out_dir;
	}
	expires_ms = now_ms + ttl_ms;

	if (requested_name) {
		if (!safe_token_name(requested_name)) {
			fprintf(stderr,
				"hdn-approval-token: unsafe token name: %s\n",
				requested_name);
			ret = 1;
			goto out_dir;
		}
		if (snprintf(name, sizeof(name), "%s", requested_name) >=
		    (int)sizeof(name)) {
			ret = 1;
			goto out_dir;
		}
		fd = create_token_file(dirfd, name);
		if (fd < 0) {
			fprintf(stderr,
				"hdn-approval-token: cannot create token %s/%s: %s\n",
				dir, name, strerror(errno));
			ret = 1;
			goto out_dir;
		}
	} else {
		for (attempts = 0; attempts < 16; attempts++) {
			ret = random_token_name(name, sizeof(name));
			if (ret) {
				fprintf(stderr,
					"hdn-approval-token: cannot generate token name\n");
				ret = 1;
				goto out_dir;
			}
			fd = create_token_file(dirfd, name);
			if (fd >= 0)
				break;
			if (errno != EEXIST) {
				fprintf(stderr,
					"hdn-approval-token: cannot create token under %s: %s\n",
					dir, strerror(errno));
				ret = 1;
				goto out_dir;
			}
		}
		if (fd < 0) {
			fprintf(stderr,
				"hdn-approval-token: could not allocate token name\n");
			ret = 1;
			goto out_dir;
		}
	}

	if (fchown(fd, 0, 0) || fchmod(fd, 0600)) {
		fprintf(stderr,
			"hdn-approval-token: cannot set token ownership/mode: %s\n",
			strerror(errno));
		ret = 1;
		goto out_unlink;
	}
	if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
	    st.st_nlink != 1 || (st.st_mode & 077)) {
		fprintf(stderr,
			"hdn-approval-token: created token failed safety checks\n");
		ret = 1;
		goto out_unlink;
	}

	if (snprintf(text, sizeof(text),
		     "%s\nintent=%s\nexpires-monotonic-ms=%llu\n",
		     HDN_APPROVAL_TOKEN_MAGIC, intent, expires_ms) >=
	    (int)sizeof(text)) {
		ret = 1;
		goto out_unlink;
	}

	ret = write_all(fd, text, strlen(text));
	if (ret || fsync(fd)) {
		fprintf(stderr, "hdn-approval-token: token write failed: %s\n",
			strerror(ret ? -ret : errno));
		ret = 1;
		goto out_unlink;
	}
	if (join_path(path, sizeof(path), dir, name)) {
		ret = 1;
		goto out_unlink;
	}

	if (close(fd)) {
		fd = -1;
		ret = 1;
		goto out_unlink_name;
	}
	fd = -1;

	printf("%s\n", path);
	ret = 0;
	goto out_dir;

out_unlink:
	if (fd >= 0)
		close(fd);
	fd = -1;
out_unlink_name:
	unlinkat(dirfd, name, 0);
out_dir:
	close(dirfd);
	return ret;
}

int main(int argc, char **argv)
{
	const char *dir = HDN_APPROVAL_TOKEN_DIR;
	const char *intent = NULL;
	const char *name = NULL;
	unsigned long long ttl_ms = HDN_APPROVAL_TOKEN_DEFAULT_TTL_MS;
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--help")) {
			usage(argv[0]);
			return 0;
		}
		if (!strcmp(argv[i], "--intent")) {
			if (++i >= argc)
				goto bad_args;
			intent = argv[i];
			continue;
		}
		if (!strcmp(argv[i], "--dir")) {
			if (++i >= argc)
				goto bad_args;
			dir = argv[i];
			continue;
		}
		if (!strcmp(argv[i], "--ttl-ms")) {
			if (++i >= argc || parse_u64(argv[i], &ttl_ms))
				goto bad_args;
			continue;
		}
		if (!strcmp(argv[i], "--name")) {
			if (++i >= argc)
				goto bad_args;
			name = argv[i];
			continue;
		}
		goto bad_args;
	}

	if (!intent)
		goto bad_args;

	return issue_token(dir, intent, ttl_ms, name);

bad_args:
	usage(argv[0]);
	return 2;
}
