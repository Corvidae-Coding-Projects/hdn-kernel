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
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

static int status_ok(void)
{
	FILE *file = fopen(STATUS, "re");
	char *line = NULL;
	size_t capacity = 0;
	unsigned int seen = 0;

	if (!file)
		return 0;
	while (getline(&line, &capacity, file) >= 0) {
		line[strcspn(line, "\n")] = 0;
		if (!strcmp(line, "bpf_execmem_state: active")) seen |= 1U << 0;
		else if (!strcmp(line, "bpf_execmem_test_interface: 1")) seen |= 1U << 1;
		else if (!strcmp(line, "capability.bpf_domain: enforced,software")) seen |= 1U << 2;
		else if (!strcmp(line, "capability.bpf_retirement: enforced,software")) seen |= 1U << 3;
		else if (!strncmp(line, "bpf_execmem_capacity_bytes: ", 28) &&
			 strtoull(line + 28, NULL, 10)) seen |= 1U << 4;
		else if (!strncmp(line, "bpf_execmem_quarantine_limit_pages: ", 36) &&
			 strtoull(line + 36, NULL, 10)) seen |= 1U << 5;
	}
	free(line);
	fclose(file);
	return seen == 0x3f;
}

static int unprivileged_status_view_ok(void)
{
	static const char *const privileged[] = {
		"bpf_execmem_capacity_bytes: ",
		"bpf_execmem_live_pages: ",
		"bpf_execmem_quarantined_pages: ",
		"bpf_execmem_failed_retirements: ",
		"bpf_execmem_quarantine_limit_pages: ",
		"bpf_execmem_quarantine_pressure_releases: ",
		"bpf_execmem_allocation_attempts: ",
		"bpf_execmem_allocation_successes: ",
		"bpf_execmem_allocation_failures: ",
		"bpf_execmem_requested_bytes: ",
		"bpf_execmem_reserved_bytes: ",
		"bpf_execmem_internal_slack_bytes: ",
	};
	FILE *file = fopen(STATUS, "re");
	char *line = NULL;
	size_t capacity = 0;
	int state = 0;

	if (!file)
		return 0;
	while (getline(&line, &capacity, file) >= 0) {
		if (!strncmp(line, "bpf_execmem_state: ", 19))
			state = 1;
		for (size_t i = 0; i < ARRAY_SIZE(privileged); i++)
			if (!strncmp(line, privileged[i], strlen(privileged[i]))) {
				free(line);
				fclose(file);
				return 0;
			}
	}
	free(line);
	fclose(file);
	return state;
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
		_exit(unprivileged_status_view_ok() ? 0 : 1);
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
	    !status_ok() || !unprivileged_status_ok())
		goto fail;
	file = fopen("/mode", "re");
	if (!file || fread(mode, 1, 1, file) != 1 || mode[0] < '0' || mode[0] > '5')
		goto fail;
	fclose(file);
	fd = open("/bpf-execmem.ko", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		goto fail;
	snprintf(parameters, sizeof(parameters), "mode=%c", mode[0]);
	printf("HDN_BPF_EXECMEM_INIT_READY mode=%c\n", mode[0]);
	if (syscall(SYS_finit_module, fd, parameters, 0))
		goto fail;
	close(fd);
	if (mode[0] >= '1' && mode[0] <= '3')
		goto fail;
	if (syscall(SYS_delete_module, "bpf_execmem_test_module", O_NONBLOCK))
		goto fail;
	printf("HDN_BPF_EXECMEM_GUEST_PASS mode=%c\n", mode[0]);
	reboot(RB_POWER_OFF);
	return 0;
fail:
	printf("HDN_BPF_EXECMEM_GUEST_FAIL errno=%d\n", errno);
	reboot(RB_POWER_OFF);
	return 1;
}
