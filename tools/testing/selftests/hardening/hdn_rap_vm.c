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

static int status_ok(const char *identity)
{
	FILE *file = fopen(STATUS, "re");
	char *line = NULL;
	size_t capacity = 0;
	unsigned int seen = 0;

	if (!file)
		return 0;
	while (getline(&line, &capacity, file) >= 0) {
		line[strcspn(line, "\n")] = 0;
		if (!strcmp(line, "rap_state: active")) seen |= 1U << 0;
		else if (!strcmp(line, "rap_metadata_version: 1")) seen |= 1U << 1;
		else if (!strcmp(line, "rap_transfer_abi: 4")) seen |= 1U << 2;
		else if (!strcmp(line, "rap_failure_classes: 6")) seen |= 1U << 3;
		else if (!strcmp(line, "rap_xor_state: base-only")) seen |= 1U << 4;
		else if (!strcmp(line, "private_stacks_state: active")) seen |= 1U << 5;
		else if (!strcmp(line, "rap_error_test_interface: 1")) seen |= 1U << 6;
		else if (!strcmp(line, "rap_test_interface: 1")) seen |= 1U << 7;
		else if (!strncmp(line, "rap_build_identity: ", 20) &&
			 !strcmp(line + 20, identity)) seen |= 1U << 8;
	}
	free(line);
	fclose(file);
	return seen == 0x1ff;
}

int main(void)
{
	char identity[65], parameters[32];
	unsigned int mode;
	FILE *file;
	int fd;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (mount("proc", "/proc", "proc", 0, NULL) ||
	    mount("sysfs", "/sys", "sysfs", 0, NULL) ||
	    mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) ||
	    mount("securityfs", "/sys/kernel/security", "securityfs", 0, NULL))
		goto fail;
	file = fopen("/mode", "re");
	if (!file || fscanf(file, "%u", &mode) != 1 || mode > 4)
		goto fail;
	fclose(file);
	file = fopen("/build-id", "re");
	if (!file || fscanf(file, "%64[0-9a-f]", identity) != 1 || strlen(identity) != 64)
		goto fail;
	fclose(file);
	if (!status_ok(identity))
		goto fail;
	fd = open("/rap.ko", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		goto fail;
	snprintf(parameters, sizeof(parameters), "mode=%u", mode);
	printf("HDN_RAP_INIT_READY mode=%u\n", mode);
	errno = 0;
	if (syscall(SYS_finit_module, fd, parameters, 0))
		goto fail;
	close(fd);
	if (mode >= 1 && mode <= 3)
		goto fail;
	if (syscall(SYS_delete_module, "rap_test_module", O_NONBLOCK))
		goto fail;
	printf("HDN_RAP_GUEST_PASS mode=%u\n", mode);
	reboot(RB_POWER_OFF);
	return 0;
fail:
	printf("HDN_RAP_GUEST_FAIL errno=%d\n", errno);
	reboot(RB_POWER_OFF);
	return 1;
}
