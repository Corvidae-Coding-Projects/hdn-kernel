// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define STATUS "/sys/kernel/security/hardening/status"
#define DEFAULT_ITERATIONS 4096U

struct worker {
	unsigned int cpu;
	unsigned int iterations;
	int error;
};

static volatile sig_atomic_t signals_seen;

static void signal_handler(int signal)
{
	if (signal == SIGALRM || signal == SIGUSR1)
		signals_seen++;
}

static int read_counter(const char *name, unsigned long long *value)
{
	FILE *file = fopen(STATUS, "re");
	char *line = NULL;
	size_t capacity = 0, length = strlen(name);
	int found = 0;

	if (!file)
		return -1;
	while (getline(&line, &capacity, file) >= 0) {
		if (strncmp(line, name, length) || line[length] != ':' || line[length + 1] != ' ')
			continue;
		*value = strtoull(line + length + 2, NULL, 10);
		found = 1;
		break;
	}
	free(line);
	fclose(file);
	return found ? 0 : -1;
}

static void *worker_main(void *opaque)
{
	struct worker *worker = opaque;
	cpu_set_t set;
	struct timespec pause = { .tv_nsec = 1000 };

	CPU_ZERO(&set);
	CPU_SET(worker->cpu, &set);
	if (pthread_setaffinity_np(pthread_self(), sizeof(set), &set)) {
		worker->error = 1;
		return NULL;
	}
	for (unsigned int i = 0; i < worker->iterations; i++) {
		(void)syscall(SYS_gettid);
		(void)syscall(SYS_getpid);
		if (!(i & 7))
			sched_yield();
		if (!(i & 31))
			pthread_kill(pthread_self(), SIGUSR1);
		if (!(i & 127))
			nanosleep(&pause, NULL);
	}
	return NULL;
}

static int fork_teardown(unsigned int iterations)
{
	for (unsigned int i = 0; i < iterations; i++) {
		pid_t child = fork();
		int status;

		if (child < 0)
			return -1;
		if (!child)
			_exit((int)(syscall(SYS_gettid) < 0));
		if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
			return -1;
	}
	return 0;
}

static int ptrace_register_roundtrip(void)
{
	pid_t child = fork();
	struct user_regs_struct before, after;
	int status;

	if (child < 0)
		return -1;
	if (!child) {
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL))
			_exit(2);
		raise(SIGSTOP);
		_exit(0);
	}
	if (waitpid(child, &status, 0) != child || !WIFSTOPPED(status) ||
	    ptrace(PTRACE_GETREGS, child, NULL, &before) ||
	    ptrace(PTRACE_SETREGS, child, NULL, &before) ||
	    ptrace(PTRACE_GETREGS, child, NULL, &after) ||
	    memcmp(&before, &after, sizeof(before)) ||
	    ptrace(PTRACE_CONT, child, NULL, NULL)) {
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		return -1;
	}
	return waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status)
		? 0 : -1;
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

static unsigned int hotplug_roundtrip(unsigned int cpus)
{
	char path[128];
	unsigned int completed = 0;

	for (unsigned int cpu = 1; cpu < cpus; cpu++) {
		snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%u/online", cpu);
		if (!write_text(path, "0\n") && !write_text(path, "1\n"))
			completed++;
	}
	return completed;
}

static int mount_interfaces(void)
{
	if (getpid() != 1)
		return 0;
	return mount("proc", "/proc", "proc", 0, NULL) ||
		mount("sysfs", "/sys", "sysfs", 0, NULL) ||
		mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) ||
		mount("securityfs", "/sys/kernel/security", "securityfs", 0, NULL);
}

int main(int argc, char **argv)
{
	unsigned int iterations = argc > 1 ? strtoul(argv[1], NULL, 10) : DEFAULT_ITERATIONS;
	long configured = sysconf(_SC_NPROCESSORS_CONF);
	long available = sysconf(_SC_NPROCESSORS_ONLN);
	unsigned int cpus, online;
	unsigned int hotplugged;
	unsigned long long switches_before, switches_after, async_before, async_after;
	struct sigaction action = { .sa_handler = signal_handler };
	struct itimerval timer = { .it_interval = { .tv_usec = 1000 },
				   .it_value = { .tv_usec = 1000 } };
	pthread_t *threads;
	struct worker *workers;
	int failed = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (configured < 1 || available < 1 || available > configured ||
	    configured > CPU_SETSIZE)
		goto fail;
	cpus = configured;
	online = available;
	if (!iterations || mount_interfaces() ||
	    read_counter("private_stacks_task_switches", &switches_before) ||
	    read_counter("private_stacks_async_root_entries", &async_before))
		goto fail;
	if (sigaction(SIGALRM, &action, NULL) || sigaction(SIGUSR1, &action, NULL) ||
	    setitimer(ITIMER_REAL, &timer, NULL))
		goto fail;
	threads = calloc(online, sizeof(*threads));
	workers = calloc(online, sizeof(*workers));
	if (!threads || !workers)
		goto fail;
	for (unsigned int cpu = 0; cpu < online; cpu++) {
		workers[cpu] = (struct worker) { .cpu = cpu, .iterations = iterations };
		if (pthread_create(&threads[cpu], NULL, worker_main, &workers[cpu])) {
			failed = 1;
			online = cpu;
			break;
		}
	}
	for (unsigned int cpu = 0; cpu < online; cpu++) {
		pthread_join(threads[cpu], NULL);
		failed |= workers[cpu].error;
	}
	free(workers);
	free(threads);
	if (failed || fork_teardown(iterations / 32 + 1) || ptrace_register_roundtrip())
		goto fail;
	/* SysRq-l uses the architecture backtrace/NMI path; SysRq-t walks and
	 * attributes sleeping task stacks through the privileged unwinder. */
	if (write_text("/proc/sysrq-trigger", "l\n") || write_text("/proc/sysrq-trigger", "t\n"))
		goto fail;
	hotplugged = hotplug_roundtrip(cpus);
	if (cpus > 1 && !hotplugged)
		goto fail;
	if (read_counter("private_stacks_task_switches", &switches_after) ||
	    read_counter("private_stacks_async_root_entries", &async_after) ||
	    switches_after <= switches_before || async_after <= async_before || !signals_seen)
		goto fail;
	printf("HDN_PRIVATE_STACK_STRESS_PASS switches=%llu async=%llu signals=%d hotplug=%u\n",
	       switches_after - switches_before, async_after - async_before,
	       signals_seen, hotplugged);
	if (getpid() == 1)
		reboot(RB_POWER_OFF);
	return 0;
fail:
	printf("HDN_PRIVATE_STACK_STRESS_FAIL errno=%d\n", errno);
	if (getpid() == 1)
		reboot(RB_POWER_OFF);
	return 1;
}
