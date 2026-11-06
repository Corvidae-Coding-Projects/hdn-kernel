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
#include <unistd.h>

#define STATUS "/sys/kernel/security/hardening/status"

static int status_ok(void)
{
	FILE *file = fopen(STATUS, "re");
	char *line = NULL;
	size_t capacity = 0;
	unsigned int seen = 0;

	if (!file)
		return 0;
	while (getline(&line, &capacity, file) >= 0) {
		if (!strcmp(line, "private_stacks_state: active\n"))
			seen |= 1U << 0;
		else if (!strcmp(line, "kvm_state_test_interface: 1\n"))
			seen |= 1U << 1;
	}
	free(line);
	fclose(file);
	return seen == 3;
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
	    !status_ok())
		goto fail;
	file = fopen("/mode", "re");
	if (!file || fread(mode, 1, 1, file) != 1 || mode[0] < '0' || mode[0] > '2')
		goto fail;
	fclose(file);
	fd = open("/kvm-state.ko", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		goto fail;
	snprintf(parameters, sizeof(parameters), "mode=%c", mode[0]);
	printf("HDN_KVM_STATE_INIT_READY mode=%c\n", mode[0]);
	if (syscall(SYS_finit_module, fd, parameters, 0))
		goto fail;
	close(fd);
	if (mode[0] != '0')
		goto fail;
	if (syscall(SYS_delete_module, "kvm_state_test_module", O_NONBLOCK))
		goto fail;
	printf("HDN_KVM_STATE_GUEST_PASS mode=0\n");
	reboot(RB_POWER_OFF);
	return 0;
fail:
	printf("HDN_KVM_STATE_GUEST_FAIL errno=%d\n", errno);
	reboot(RB_POWER_OFF);
	return 1;
}
