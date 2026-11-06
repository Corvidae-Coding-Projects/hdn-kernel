// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "../../../../include/uapi/linux/hardening.h"

#define WORD UINT64_C(0x9182736455aacc33)
#define STATUS "/sys/kernel/security/hardening/status"
#define EVENTS "/sys/kernel/security/hardening/events"

static int state_is(const char *expected)
{
	FILE *file = fopen(STATUS, "re");
	char *line = NULL, *value;
	size_t capacity = 0;
	int state = 0, build_id = 0, scheme = 0;

	if (!file)
		return 0;
	while (getline(&line, &capacity, file) >= 0) {
		if (!strncmp(line, "uderef_", 7))
			fputs(line, stdout);
		if (!strncmp(line, "uderef_state: ", 14)) {
			line[strcspn(line, "\n")] = 0;
			state = !strcmp(line + 14, expected);
		} else if (!strncmp(line, "uderef_build_id: ", 18)) {
			line[strcspn(line, "\n")] = 0;
			value = line + 18;
			build_id = strlen(value) == 40 &&
				strspn(value, "0123456789abcdef") == 40 &&
				strspn(value, "0") != 40;
		} else if (!strcmp(line, "uderef_site_scheme: buildid-fnv1a64-v1\n")) {
			scheme = 1;
		}
	}
	free(line);
	fclose(file);
	return state && build_id && scheme;
}

static int repair_event(void)
{
	FILE *file = fopen(EVENTS, "re");
	char *line = NULL, *object;
	size_t capacity = 0;
	int found = 0;

	if (!file)
		return 0;
	while (getline(&line, &capacity, file) >= 0) {
		unsigned int transition, reason;
		char *t = strstr(line, " transition="), *r = strstr(line, " reason=");

		object = strstr(line, " object=");
		if (t && r && object && sscanf(t, " transition=%u", &transition) == 1 &&
		    sscanf(r, " reason=%u", &reason) == 1 &&
		    transition == HDN_TRANS_KERNEL_UACCESS && reason == HDN_REASON_KERNEL_SMAP_RESTORED &&
		    strtoull(object + 8, NULL, 10) && strstr(line, " error=0 ")) {
			fputs(line, stdout);
			found = 1;
		}
	}
	free(line);
	fclose(file);
	return found;
}

int main(void)
{
	FILE *file;
	unsigned int mode, hardware, i;
	long pagesize = sysconf(_SC_PAGESIZE);
	uint64_t *page;
	int fd, result;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (pagesize < 4096 || mount("proc", "/proc", "proc", 0, NULL) ||
	    mount("sysfs", "/sys", "sysfs", 0, NULL) ||
	    mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) ||
	    mount("securityfs", "/sys/kernel/security", "securityfs", 0, NULL))
		goto fail;
	file = fopen("/mode", "re");
	if (!file || fscanf(file, "%u %u", &mode, &hardware) != 2 || mode > 5 || hardware > 1)
		goto fail;
	fclose(file);
	if (!state_is(hardware ? "hardware" : "unsupported"))
		goto fail;
	fd = open("/uderef.ko", O_RDONLY | O_CLOEXEC);
	if (fd < 0 || syscall(SYS_finit_module, fd, "", 0))
		goto fail;
	close(fd);
	fd = open("/dev/hdn-uderef-test", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		goto fail;
	page = mmap(NULL, pagesize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (page == MAP_FAILED)
		goto fail;
	*page = WORD;
	if (mode == 4 && mprotect(page, pagesize, PROT_NONE))
		goto fail;
	/* A fresh guest must not contain an old matching repair event. */
	if (mode == 3 && repair_event())
		goto fail;
	printf("HDN_UDEREF_GUEST_READY mode=%u hardware=%u\n", mode, hardware);
	errno = 0;
	result = ioctl(fd, mode, page);
	if (!hardware) {
		if (result != -1 || errno != EOPNOTSUPP)
			goto fail;
		puts("HDN_UDEREF_UNSUPPORTED_PASS");
		goto done;
	}
	if (result || mode == 1 || mode == 2)
		goto fail;
	if (mode == 3) {
		for (i = 0; i < 100 && !repair_event(); i++)
			usleep(10000);
		if (i == 100)
			goto fail;
	}
	if (mode != 4 && *page != WORD)
		goto fail;
	puts("HDN_UDEREF_GUEST_PASS");
done:
	close(fd);
	reboot(RB_POWER_OFF);
	return 0;
fail:
	printf("HDN_UDEREF_GUEST_FAIL errno=%d\n", errno);
	reboot(RB_POWER_OFF);
	return 1;
}
