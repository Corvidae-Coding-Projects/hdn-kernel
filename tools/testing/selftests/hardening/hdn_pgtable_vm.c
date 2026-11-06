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

int main(void)
{
	char mode[2] = { 0 }, parameters[16];
	int fd, ret;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (mount("proc", "/proc", "proc", 0, NULL) ||
	    mount("sysfs", "/sys", "sysfs", 0, NULL))
		goto fail;
	fd = open("/mode", O_RDONLY | O_CLOEXEC);
	if (fd < 0 || read(fd, mode, 1) != 1 || mode[0] < '0' || mode[0] > '4')
		goto fail;
	close(fd);
	snprintf(parameters, sizeof(parameters), "mode=%c", mode[0]);
	fd = open("/pgtable.ko", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		goto fail;
	printf("HDN_PGTABLE_GUEST_READY mode=%c\n", mode[0]);
	ret = syscall(SYS_finit_module, fd, parameters, 0);
	close(fd);
	if (ret || mode[0] != '0')
		goto fail;
	puts("HDN_PGTABLE_GUEST_PASS");
	reboot(RB_POWER_OFF);
	return 0;
fail:
	printf("HDN_PGTABLE_GUEST_FAIL errno=%d\n", errno);
	reboot(RB_POWER_OFF);
	return 1;
}
