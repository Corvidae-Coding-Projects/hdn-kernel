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
	static const char *const expected[] = {
		"respectre_state: compiler-instrumented",
		"respectre_coverage: selected-c-dataflow",
		"respectre_report_schema: 1",
		"respectre_analyzer_version: 1",
		"respectre_compiler_abi: gcc-16",
		"respectre_store_bypass: software-serialization",
		"respectre_test_interface: 1",
		"capability.transient_dataflow: degraded,software",
	};
	FILE *file = fopen(STATUS, "re");
	char *line = NULL;
	size_t capacity = 0;
	unsigned int seen = 0;

	if (!file)
		return 0;
	while (getline(&line, &capacity, file) >= 0) {
		line[strcspn(line, "\n")] = 0;
		for (unsigned int n = 0; n < sizeof(expected) / sizeof(expected[0]); n++)
			if (!strcmp(line, expected[n]))
				seen |= 1U << n;
	}
	free(line);
	fclose(file);
	return seen == (1U << (sizeof(expected) / sizeof(expected[0]))) - 1;
}

int main(void)
{
	int fd;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (mount("proc", "/proc", "proc", 0, NULL) ||
	    mount("sysfs", "/sys", "sysfs", 0, NULL) ||
	    mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) ||
	    mount("securityfs", "/sys/kernel/security", "securityfs", 0, NULL) ||
	    !status_ok())
		goto fail;
	fd = open("/respectre.ko", O_RDONLY | O_CLOEXEC);
	if (fd < 0 || syscall(SYS_finit_module, fd, "", 0))
		goto fail;
	close(fd);
	if (syscall(SYS_delete_module, "respectre_test_module", O_NONBLOCK))
		goto fail;
	puts("HDN_RESPECTRE_GUEST_PASS semantic-module-v1");
	reboot(RB_POWER_OFF);
	return 0;
fail:
	printf("HDN_RESPECTRE_GUEST_FAIL errno=%d\n", errno);
	reboot(RB_POWER_OFF);
	return 1;
}
