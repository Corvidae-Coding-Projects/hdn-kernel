// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define STATUS "/sys/kernel/security/hardening/status"

static const char *const privileged[] = {
	"private_stacks_allocation_attempts: ",
	"private_stacks_allocations: ",
	"private_stacks_allocation_failures: ",
	"private_stacks_live: ",
	"private_stacks_publications: ",
	"private_stacks_retirements: ",
	"private_stacks_diagnostic_reads: ",
	"private_stacks_diagnostic_read_failures: ",
	"private_stacks_construction_bytes: ",
	"private_stacks_task_switches: ",
	"private_stacks_async_root_entries: ",
};

static int status_view(int privileged_view)
{
	FILE *file = fopen(STATUS, "re");
	char *line = NULL;
	size_t capacity = 0;
	unsigned int seen = 0, privileged_seen = 0;

	if (!file)
		return 0;
	while (getline(&line, &capacity, file) >= 0) {
		if (!strcmp(line, "private_stacks_state: active\n"))
			seen |= 1U << 0;
		else if (!strcmp(line, "private_stacks_test_interface: 1\n"))
			seen |= 1U << 1;
		else if (!strcmp(line, "capability.private_stack_aliases: enforced,software\n"))
			seen |= 1U << 2;
		for (size_t i = 0; i < sizeof(privileged) / sizeof(privileged[0]); i++) {
			if (strncmp(line, privileged[i], strlen(privileged[i])))
				continue;
			if (!privileged_view) {
				free(line);
				fclose(file);
				return 0;
			}
			privileged_seen++;
		}
	}
	free(line);
	fclose(file);
	return privileged_view ? seen == 0x7 &&
		privileged_seen == sizeof(privileged) / sizeof(privileged[0]) :
		seen == 0x7;
}

static int unprivileged_status_ok(void)
{
	int status;
	pid_t child = fork();

	if (child < 0)
		return 0;
	if (!child) {
		if (setgid(65534) || setuid(65534))
			_exit(2);
		_exit(status_view(0) ? 0 : 1);
	}
	return waitpid(child, &status, 0) == child && WIFEXITED(status) &&
		WEXITSTATUS(status) == 0;
}

int main(void)
{
	char mode[2] = { 0 }, parameters[16];
	FILE *file;
	int fd;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (mount("proc", "/proc", "proc", 0, NULL) ||
	    mount("sysfs", "/sys", "sysfs", 0, NULL) ||
	    mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) ||
	    mount("securityfs", "/sys/kernel/security", "securityfs", 0, NULL) ||
	    !status_view(1) || !unprivileged_status_ok())
		goto fail;
	file = fopen("/mode", "re");
	if (!file || fread(mode, 1, 1, file) != 1 || mode[0] < '0' || mode[0] > '8')
		goto fail;
	fclose(file);
	fd = open("/private-stacks.ko", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		goto fail;
	snprintf(parameters, sizeof(parameters), "mode=%c", mode[0]);
	printf("HDN_PRIVATE_STACK_INIT_READY mode=%c\n", mode[0]);
	if (syscall(SYS_finit_module, fd, parameters, 0))
		goto fail;
	close(fd);
	if (mode[0] != '0')
		goto fail;
	if (syscall(SYS_delete_module, "private_stack_test_module", O_NONBLOCK))
		goto fail;
	printf("HDN_PRIVATE_STACK_GUEST_PASS mode=%c\n", mode[0]);
	reboot(RB_POWER_OFF);
	return 0;
fail:
	printf("HDN_PRIVATE_STACK_GUEST_FAIL errno=%d\n", errno);
	reboot(RB_POWER_OFF);
	return 1;
}
