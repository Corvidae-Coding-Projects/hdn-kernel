// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define STATUS "/sys/kernel/security/hardening/status"
#define ITERATIONS 192

enum jitter_class { JITTER_CRED, JITTER_FILE, JITTER_BACKING, JITTER_CLASSES };

struct class_status {
	unsigned long long allocations, allocation_failures, retired, released, pressure;
	unsigned int quarantined;
};

struct jitter_status {
	struct class_status classes[JITTER_CLASSES];
	unsigned long long allocations, allocation_failures, retired, released, pressure;
	unsigned long long failures, early_live;
	unsigned int quarantined;
};

struct worker {
	unsigned int cpu;
	int failed;
};

static int finit(const char *path, const char *parameters)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	int result;

	if (fd < 0)
		return -1;
	result = syscall(SYS_finit_module, fd, parameters, 0);
	close(fd);
	return result;
}

static int module_mutations(void)
{
	static const char *const names[] = {
		"unallocated", "writable", "executable", "misaligned", "truncated",
		"bad-target",
	};
	char path[128];

	for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		snprintf(path, sizeof(path), "/mutations/jitter-%s.ko", names[i]);
		errno = 0;
		if (!finit(path, "mode=0") || errno != ENOEXEC)
			return -1;
	}
	return 0;
}

static int write_text(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	ssize_t length = strlen(text);
	int result;

	if (fd < 0)
		return -1;
	result = write(fd, text, length) == length ? 0 : -1;
	close(fd);
	return result;
}

static int read_status(struct jitter_status *status, int privileged)
{
	static const char *const aggregate_names[] = {
		"critical_jitter_allocations: ", "critical_jitter_allocation_failures: ",
		"critical_jitter_retired: ",
		"critical_jitter_released: ", "critical_jitter_pressure: ",
		"critical_jitter_failures: ", "critical_jitter_early_live: ",
	};
	static const char *const class_names[JITTER_CLASSES] = {
		"critical_jitter_cred_", "critical_jitter_file_",
		"critical_jitter_backing_file_",
	};
	unsigned long long *aggregate_values[] = {
		&status->allocations, &status->allocation_failures, &status->retired,
		&status->released,
		&status->pressure, &status->failures, &status->early_live,
	};
	FILE *file = fopen(STATUS, "re");
	char *line = NULL;
	size_t capacity = 0;
	unsigned int stable = 0, private = 0;

	if (!file)
		return -1;
	while (getline(&line, &capacity, file) >= 0) {
		unsigned int value;

		if (!strcmp(line, "critical_jitter_state: active\n") ||
		    !strcmp(line, "critical_jitter_state: degraded-entropy\n"))
			stable |= 1U;
		else if (!strcmp(line, "critical_jitter_metadata_version: 1\n"))
			stable |= 2U;
		else if (!strcmp(line, "critical_jitter_classes: credentials,files,backing-files\n"))
			stable |= 4U;
		else if (sscanf(line, "critical_jitter_placement_slots: %u", &value) == 1 &&
			 value == 8)
			stable |= 8U;
		else if (sscanf(line, "critical_jitter_queue_limit_per_class: %u", &value) == 1 &&
			 value == 128)
			stable |= 16U;
		else if (sscanf(line, "critical_jitter_quarantined: %u", &status->quarantined) == 1)
			private |= 1U << 7;
		for (size_t i = 0; i < sizeof(aggregate_names) / sizeof(aggregate_names[0]); i++) {
			size_t length = strlen(aggregate_names[i]);

			if (!strncmp(line, aggregate_names[i], length)) {
				*aggregate_values[i] = strtoull(line + length, NULL, 10);
				private |= 1U << i;
			}
		}
		for (size_t id = 0; id < JITTER_CLASSES; id++) {
			char name[96];
			size_t length;

			snprintf(name, sizeof(name), "%sallocations: ", class_names[id]);
			length = strlen(name);
			if (!strncmp(line, name, length)) {
				status->classes[id].allocations = strtoull(line + length, NULL, 10);
				private |= 1U << (8 + id * 6);
			}
			snprintf(name, sizeof(name), "%sallocation_failures: ", class_names[id]);
			length = strlen(name);
			if (!strncmp(line, name, length)) {
				status->classes[id].allocation_failures = strtoull(line + length, NULL, 10);
				private |= 1U << (9 + id * 6);
			}
			snprintf(name, sizeof(name), "%sretired: ", class_names[id]);
			length = strlen(name);
			if (!strncmp(line, name, length)) {
				status->classes[id].retired = strtoull(line + length, NULL, 10);
				private |= 1U << (10 + id * 6);
			}
			snprintf(name, sizeof(name), "%sreleased: ", class_names[id]);
			length = strlen(name);
			if (!strncmp(line, name, length)) {
				status->classes[id].released = strtoull(line + length, NULL, 10);
				private |= 1U << (11 + id * 6);
			}
			snprintf(name, sizeof(name), "%squarantined: ", class_names[id]);
			length = strlen(name);
			if (!strncmp(line, name, length)) {
				status->classes[id].quarantined = strtoul(line + length, NULL, 10);
				private |= 1U << (12 + id * 6);
			}
			snprintf(name, sizeof(name), "%spressure: ", class_names[id]);
			length = strlen(name);
			if (!strncmp(line, name, length)) {
				status->classes[id].pressure = strtoull(line + length, NULL, 10);
				private |= 1U << (13 + id * 6);
			}
		}
	}
	free(line);
	fclose(file);
	if (stable != 31U)
		return -1;
	return privileged ? (private == (1U << 26) - 1 ? 0 : -1) : (private ? -1 : 0);
}

static int check_unprivileged_status(void)
{
	struct jitter_status status = { };
	pid_t child = fork();
	int result;

	if (child < 0)
		return -1;
	if (!child) {
		if (setgid(65534) || setuid(65534))
			_exit(2);
		_exit(read_status(&status, 0) ? 1 : 0);
	}
	return waitpid(child, &result, 0) == child && WIFEXITED(result) &&
		!WEXITSTATUS(result) ? 0 : -1;
}

static int pin_cpu(unsigned int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return sched_setaffinity(0, sizeof(set), &set);
}

static void *file_worker(void *opaque)
{
	struct worker *worker = opaque;
	char byte;

	if (pin_cpu(worker->cpu)) {
		worker->failed = 1;
		return NULL;
	}
	for (unsigned int i = 0; i < ITERATIONS; i++) {
		int plain = open("/mode", O_RDONLY | O_CLOEXEC);
		int overlay = open("/overlay/merged/source", O_RDONLY | O_CLOEXEC);

		if (plain < 0 || overlay < 0 || read(plain, &byte, 1) != 1 ||
		    read(overlay, &byte, 1) != 1 || fcntl(overlay, F_GETFL) < 0) {
			if (plain >= 0)
				close(plain);
			if (overlay >= 0)
				close(overlay);
			worker->failed = 1;
			break;
		}
		close(plain);
		close(overlay);
		if (!(i & 15U))
			sched_yield();
	}
	return NULL;
}

static int credential_churn(void)
{
	for (unsigned int i = 0; i < ITERATIONS; i++) {
		pid_t child = fork();
		int status;

		if (child < 0)
			return -1;
		if (!child)
			_exit(setgroups(0, NULL) ||
			      setresgid(65534, 65534, 65534) ||
			      setresuid(65534, 65534, 65534));
		if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
		    WEXITSTATUS(status))
			return -1;
	}
	return 0;
}

static int setup_overlay(void)
{
	int fd;

	if (mount("tmpfs", "/overlay", "tmpfs", 0, "size=32m") ||
	    mkdir("/overlay/lower", 0755) || mkdir("/overlay/upper", 0755) ||
	    mkdir("/overlay/work", 0755) || mkdir("/overlay/merged", 0755))
		return -1;
	fd = open("/overlay/lower/source", O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
	if (fd < 0 || write(fd, "j", 1) != 1) {
		if (fd >= 0)
			close(fd);
		return -1;
	}
	close(fd);
	return mount("overlay", "/overlay/merged", "overlay", 0,
		     "lowerdir=/overlay/lower,upperdir=/overlay/upper,workdir=/overlay/work");
}

static int memcg_pressure(void)
{
	int start[2], status;
	pid_t child;
	char pid[32], release = 1;

	if (write_text("/cgroup/cgroup.subtree_control", "+memory\n") ||
	    mkdir("/cgroup/jitter", 0755) ||
	    write_text("/cgroup/jitter/memory.high", "16777216\n") ||
	    write_text("/cgroup/jitter/memory.max", "134217728\n") || pipe2(start, O_CLOEXEC))
		return -1;
	child = fork();
	if (child < 0)
		return -1;
	if (!child) {
		unsigned char *memory;

		close(start[1]);
		if (read(start[0], &release, 1) != 1)
			_exit(2);
		close(start[0]);
		memory = malloc(64U * 1024U * 1024U);
		if (!memory)
			_exit(3);
		for (size_t offset = 0; offset < 64U * 1024U * 1024U; offset += 4096)
			memory[offset] = (unsigned char)offset;
		for (unsigned int i = 0; i < ITERATIONS; i++) {
			int fd = open("/overlay/merged/source", O_RDONLY | O_CLOEXEC);

			if (fd < 0)
				_exit(4);
			close(fd);
		}
		free(memory);
		_exit(0);
	}
	close(start[0]);
	snprintf(pid, sizeof(pid), "%d\n", child);
	if (write_text("/cgroup/jitter/cgroup.procs", pid) ||
	    write(start[1], &release, 1) != 1) {
		close(start[1]);
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		return -1;
	}
	close(start[1]);
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
		return -1;
	return rmdir("/cgroup/jitter");
}

static int run_production_workload(void)
{
	long online_value = sysconf(_SC_NPROCESSORS_ONLN);
	struct jitter_status before = { }, after = { };
	pthread_t *threads = NULL;
	struct worker *workers = NULL;
	unsigned int online;
	int failed = 0;

	if (online_value < 2 || online_value > CPU_SETSIZE || setup_overlay() ||
	    read_status(&before, 1) || check_unprivileged_status())
		return -1;
	online = (unsigned int)online_value;
	threads = calloc(online, sizeof(*threads));
	workers = calloc(online, sizeof(*workers));
	if (!threads || !workers)
		goto fail;
	for (unsigned int cpu = 0; cpu < online; cpu++) {
		workers[cpu].cpu = cpu;
		if (pthread_create(&threads[cpu], NULL, file_worker, &workers[cpu])) {
			failed = 1;
			online = cpu;
			break;
		}
	}
	if (credential_churn() || memcg_pressure())
		failed = 1;
	for (unsigned int cpu = 0; cpu < online; cpu++) {
		pthread_join(threads[cpu], NULL);
		failed |= workers[cpu].failed;
	}
	sleep(3);
	if (failed || read_status(&after, 1) || check_unprivileged_status() ||
	    after.failures != before.failures || after.pressure <= before.pressure)
		goto fail;
	for (unsigned int id = 0; id < JITTER_CLASSES; id++) {
		if (after.classes[id].allocations <= before.classes[id].allocations ||
		    after.classes[id].retired <= before.classes[id].retired ||
		    after.classes[id].released <= before.classes[id].released ||
		    after.classes[id].quarantined > 128)
			goto fail;
	}
	printf("HDN_JITTER_RUNTIME_PASS workers=%u memcg_pressure=1 cred=%llu file=%llu backing=%llu\n",
	       online,
	       after.classes[JITTER_CRED].allocations - before.classes[JITTER_CRED].allocations,
	       after.classes[JITTER_FILE].allocations - before.classes[JITTER_FILE].allocations,
	       after.classes[JITTER_BACKING].allocations - before.classes[JITTER_BACKING].allocations);
	free(threads);
	free(workers);
	return 0;
fail:
	free(threads);
	free(workers);
	return -1;
}

int main(void)
{
	char mode[2] = { 0 }, parameters[16];
	int fd, ret;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (mount("proc", "/proc", "proc", 0, NULL) ||
	    mount("sysfs", "/sys", "sysfs", 0, NULL) ||
	    mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) ||
	    mount("securityfs", "/sys/kernel/security", "securityfs", 0, NULL) ||
	    mount("cgroup2", "/cgroup", "cgroup2", 0, NULL))
		goto fail;
	fd = open("/mode", O_RDONLY | O_CLOEXEC);
	if (fd < 0 || read(fd, mode, 1) != 1 || mode[0] < '0' || mode[0] > '8')
		goto fail;
	close(fd);
	snprintf(parameters, sizeof(parameters), "mode=%c", mode[0]);
	printf("HDN_JITTER_GUEST_READY mode=%c\n", mode[0]);
	if (mode[0] == '0' && module_mutations())
		goto fail;
	ret = finit("/jitter.ko", parameters);
	if (ret || (mode[0] == '0' && run_production_workload()) ||
	    (mode[0] != '0' && mode[0] != '8'))
		goto fail;
	puts("HDN_JITTER_GUEST_PASS");
	reboot(RB_POWER_OFF);
	return 0;
fail:
	printf("HDN_JITTER_GUEST_FAIL errno=%d\n", errno);
	reboot(RB_POWER_OFF);
	return 1;
}
