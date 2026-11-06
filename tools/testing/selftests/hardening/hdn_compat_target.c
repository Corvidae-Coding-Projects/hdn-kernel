// SPDX-License-Identifier: GPL-2.0-only
/* Real W^X transition and fork probe, controlled through stdin/stdout pipes. */
#include <errno.h>
#include <fcntl.h>
#include <linux/fsverity.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static int transition(int writable)
{
#if defined(__x86_64__)
	static const unsigned char code[] = { 0xb8, 42, 0, 0, 0, 0xc3 };
#elif defined(__aarch64__)
	static const unsigned int code[] = { 0x52800540, 0xd65f03c0 };
#elif defined(__riscv) && __riscv_xlen == 64
	static const unsigned int code[] = { 0x02a00513, 0x00008067 };
#else
#error Unsupported compatibility fixture architecture
#endif
	size_t size = (size_t)sysconf(_SC_PAGESIZE);
	void *page;
	int result;

	page = mmap(NULL, size, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (page == MAP_FAILED)
		return errno;
	memcpy(page, code, sizeof(code));
	__builtin___clear_cache(page, (char *)page + sizeof(code));
	if (mprotect(page, size, PROT_READ | PROT_EXEC | (writable ? PROT_WRITE : 0)))
		result = errno;
	else
		result = ((int (*)(void))page)() == 42 ? 0 : EILSEQ;
	munmap(page, size);
	return result;
}

static int verity(const char *path, int enable)
{
	struct fsverity_enable_arg arg = { .version = 1, .hash_algorithm = 1, .block_size = 4096 };
	unsigned char buffer[sizeof(struct fsverity_digest) + 64] = { 0 };
	struct fsverity_digest *digest = (void *)buffer;
	int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW), result = 1;
	unsigned int i;

	if (fd < 0)
		return 1;
	if (enable && ioctl(fd, FS_IOC_ENABLE_VERITY, &arg))
		goto out;
	digest->digest_size = 64;
	if (ioctl(fd, FS_IOC_MEASURE_VERITY, digest) || digest->digest_algorithm != 1 ||
	    digest->digest_size != 32)
		goto out;
	for (i = 0; i < digest->digest_size; i++)
		printf("%02x", digest->digest[i]);
	puts("");
	result = 0;
out:
	if (result)
		perror("verity fixture");
	close(fd);
	return result;
}

int main(int argc, char **argv)
{
	char command;
	int result, status;
	pid_t child;

	if (argc == 3 && (!strcmp(argv[1], "--enable-verity") || !strcmp(argv[1], "--measure-verity")))
		return verity(argv[2], !strcmp(argv[1], "--enable-verity"));
	if (argc == 2 && !strcmp(argv[1], "--transition"))
		return transition(0);
	if (argc != 1)
		return 2;
	setvbuf(stdout, NULL, _IONBF, 0);
	puts("READY");
	while (read(STDIN_FILENO, &command, 1) == 1) {
		if (command == 'q')
			return 0;
		if (command == '\n')
			continue;
		if (command == 'f') {
			child = fork();
			if (child < 0)
				result = errno;
			else if (!child)
				_exit(transition(0));
			else if (waitpid(child, &status, 0) != child || !WIFEXITED(status))
				result = ECHILD;
			else
				result = WEXITSTATUS(status);
		} else if (command == 'a' || command == 'w') {
			result = transition(command == 'w');
		} else {
			result = EINVAL;
		}
		printf("%c %d\n", command, result);
	}
	return 0;
}
