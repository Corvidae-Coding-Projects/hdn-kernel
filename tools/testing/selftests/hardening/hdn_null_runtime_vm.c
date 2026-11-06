// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/reboot.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#define HDN_MMAP_MIN_ADDR_FLOOR 65536UL
#define LKDTM_DIRECT "/sys/kernel/debug/provoke-crash/DIRECT"

static void mkdir_if_needed(const char *path, mode_t mode)
{
	if (mkdir(path, mode) && errno != EEXIST) {
		printf("HDN_NULL_RUNTIME_FAIL mkdir=%s errno=%d\n", path,
		       errno);
		exit(EXIT_FAILURE);
	}
}

static void mount_required(const char *source, const char *target,
			   const char *type)
{
	if (mount(source, target, type, 0, "") && errno != EBUSY) {
		printf("HDN_NULL_RUNTIME_FAIL mount=%s target=%s errno=%d\n",
		       type, target, errno);
		exit(EXIT_FAILURE);
	}
}

static int denied_errno(int error)
{
	return error == EACCES || error == EPERM;
}

static int low_mapping_denied(void *address, size_t page_size, int *error_out)
{
	void *mapped;
	int error;

	errno = 0;
	mapped = mmap(address, page_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
		      -1, 0);
	error = errno;
	*error_out = error;
	if (mapped != MAP_FAILED) {
		munmap(mapped, page_size);
		return 1;
	}
	if (!denied_errno(error))
		return 1;
	return 0;
}

struct mapping_result {
	int status;
	int zero_error;
	int page_error;
};

static int run_unprivileged_mapping_test(struct mapping_result *result)
{
	long page_size;

	if (setgroups(0, NULL) || setgid(65534) || setuid(65534)) {
		result->status = 1;
		return 1;
	}
	if (geteuid() != 65534 || getegid() != 65534) {
		result->status = 2;
		return 1;
	}

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0 || (unsigned long)page_size >=
				    HDN_MMAP_MIN_ADDR_FLOOR) {
		result->status = 3;
		return 1;
	}
	if (low_mapping_denied(NULL, (size_t)page_size,
			       &result->zero_error)) {
		result->status = 4;
		return 1;
	}
	if (low_mapping_denied((void *)(unsigned long)page_size,
			       (size_t)page_size, &result->page_error)) {
		result->status = 5;
		return 1;
	}
	result->status = 0;
	return 0;
}

static int check_mapping_policy(void)
{
	FILE *sysctl;
	unsigned long floor;
	struct mapping_result result = { };
	int result_pipe[2];
	pid_t child;
	int status;
	ssize_t received;

	sysctl = fopen("/proc/sys/vm/mmap_min_addr", "re");
	if (!sysctl) {
		printf("HDN_NULL_RUNTIME_FAIL mmap-min-open errno=%d\n", errno);
		return 1;
	}
	if (fscanf(sysctl, "%lu", &floor) != 1) {
		printf("HDN_NULL_RUNTIME_FAIL mmap-min-read\n");
		fclose(sysctl);
		return 1;
	}
	fclose(sysctl);
	if (floor < HDN_MMAP_MIN_ADDR_FLOOR) {
		printf("HDN_NULL_RUNTIME_FAIL mmap-min=%lu expected-at-least=%lu\n",
		       floor, HDN_MMAP_MIN_ADDR_FLOOR);
		return 1;
	}
	printf("HDN_NULL_RUNTIME_MMAP_MIN floor=%lu\n", floor);

	if (pipe(result_pipe)) {
		printf("HDN_NULL_RUNTIME_FAIL pipe errno=%d\n", errno);
		return 1;
	}
	child = fork();
	if (child < 0) {
		printf("HDN_NULL_RUNTIME_FAIL fork errno=%d\n", errno);
		close(result_pipe[0]);
		close(result_pipe[1]);
		return 1;
	}
	if (!child) {
		int child_status;

		close(result_pipe[0]);
		child_status = run_unprivileged_mapping_test(&result);
		if (write(result_pipe[1], &result, sizeof(result)) !=
		    (ssize_t)sizeof(result))
			child_status = 1;
		close(result_pipe[1]);
		_exit(child_status);
	}
	close(result_pipe[1]);
	received = read(result_pipe[0], &result, sizeof(result));
	close(result_pipe[0]);
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status) || received != (ssize_t)sizeof(result)) {
		printf("HDN_NULL_RUNTIME_FAIL mapping-child status=%d result=%d received=%zd\n",
		       status, result.status, received);
		return 1;
	}
	printf("HDN_NULL_RUNTIME_LOW_MAP_DENIED address=(nil) errno=%d nonexec=1\n",
	       result.zero_error);
	printf("HDN_NULL_RUNTIME_LOW_MAP_DENIED address=0x1000 errno=%d nonexec=1\n",
	       result.page_error);
	return 0;
}

static void halt_failed_guest(void)
{
	sync();
	reboot(LINUX_REBOOT_CMD_POWER_OFF);
	reboot(LINUX_REBOOT_CMD_RESTART);
	for (;;)
		pause();
}

int main(void)
{
	static const char trigger[] = "ACCESS_NULL\n";
	int console;
	int fd;
	ssize_t written;

	setvbuf(stdout, NULL, _IONBF, 0);
	mkdir_if_needed("/dev", 0755);
	mount_required("devtmpfs", "/dev", "devtmpfs");
	console = open("/dev/console", O_RDWR | O_CLOEXEC);
	if (console >= 0) {
		dup2(console, STDIN_FILENO);
		dup2(console, STDOUT_FILENO);
		dup2(console, STDERR_FILENO);
		if (console > STDERR_FILENO)
			close(console);
	}

	printf("HDN_NULL_RUNTIME_BOOTED\n");
	mkdir_if_needed("/proc", 0555);
	mkdir_if_needed("/sys", 0555);
	mount_required("proc", "/proc", "proc");
	mount_required("sysfs", "/sys", "sysfs");
	mkdir_if_needed("/sys/kernel/debug", 0555);
	mount_required("debugfs", "/sys/kernel/debug", "debugfs");

	if (check_mapping_policy())
		halt_failed_guest();

	fd = open(LKDTM_DIRECT, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		printf("HDN_NULL_RUNTIME_FAIL lkdtm-open errno=%d\n", errno);
		halt_failed_guest();
	}
	printf("HDN_NULL_RUNTIME_LKDTM_TRIGGER ACCESS_NULL\n");
	written = write(fd, trigger, sizeof(trigger) - 1);
	if (written != (ssize_t)(sizeof(trigger) - 1)) {
		printf("HDN_NULL_RUNTIME_FAIL lkdtm-write result=%zd errno=%d\n",
		       written, errno);
		halt_failed_guest();
	}

	printf("HDN_NULL_RUNTIME_SURVIVED\n");
	halt_failed_guest();
}
