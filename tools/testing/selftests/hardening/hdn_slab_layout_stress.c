// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define STATUS "/sys/kernel/security/hardening/status"
#define LIVE_FDS 64

static const char *const aggregate_fields[] = {
	"slab_layout_allocation_attempts: ", "slab_layout_allocation_failures: ",
	"slab_layout_slabs: ", "slab_layout_fallbacks: ",
	"slab_layout_no_offset_room: ", "slab_layout_offset_slabs: ",
	"slab_layout_offset_bytes: ", "slab_layout_original_objects: ",
	"slab_layout_placed_objects: ", "slab_layout_displaced_objects: ",
};

struct counters {
	unsigned long long attempts, failures, slabs, fallback, no_room;
	unsigned long long offset_slabs, offset_bytes, original, placed, displaced;
};

struct worker {
	unsigned int cpu, iterations;
	int failed;
};

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

static int read_status(struct counters *values, int privileged)
{
	FILE *file = fopen(STATUS, "re");
	char *line = NULL;
	size_t capacity = 0;
	unsigned int state = 0, fields = 0;
	unsigned long long *destinations[] = {
		&values->attempts, &values->failures, &values->slabs, &values->fallback,
		&values->no_room, &values->offset_slabs, &values->offset_bytes,
		&values->original, &values->placed, &values->displaced,
	};

	if (!file)
		return -1;
	while (getline(&line, &capacity, file) >= 0) {
		if (!strcmp(line, "slab_layout_state: active\n"))
			state |= 1U;
		else if (!strcmp(line, "slab_layout_test_interface: 1\n"))
			state |= 2U;
		for (size_t i = 0; i < sizeof(aggregate_fields) / sizeof(aggregate_fields[0]); i++) {
			size_t length = strlen(aggregate_fields[i]);

			if (strncmp(line, aggregate_fields[i], length))
				continue;
			if (!privileged) {
				free(line);
				fclose(file);
				return -1;
			}
			*destinations[i] = strtoull(line + length, NULL, 10);
			fields |= 1U << i;
		}
	}
	free(line);
	fclose(file);
	return state == 3U && (!privileged || fields == (1U << 10) - 1) ? 0 : -1;
}

static int unprivileged_status(void)
{
	struct counters values = { };
	pid_t child = fork();
	int status;

	if (child < 0)
		return -1;
	if (!child) {
		if (setgid(65534) || setuid(65534))
			_exit(2);
		_exit(read_status(&values, 0) ? 1 : 0);
	}
	return waitpid(child, &status, 0) == child && WIFEXITED(status) &&
		!WEXITSTATUS(status) ? 0 : -1;
}

static void close_pair(int pair[2])
{
	if (pair[0] >= 0)
		close(pair[0]);
	if (pair[1] >= 0)
		close(pair[1]);
}

static void *worker_main(void *opaque)
{
	struct worker *worker = opaque;
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(worker->cpu, &set);
	if (pthread_setaffinity_np(pthread_self(), sizeof(set), &set)) {
		worker->failed = 1;
		return NULL;
	}
	for (unsigned int round = 0; round < worker->iterations; round++) {
		int sockets[LIVE_FDS][2], pipes[LIVE_FDS][2];
		int epolls[LIVE_FDS], events[LIVE_FDS], watches[LIVE_FDS];

		for (unsigned int i = 0; i < LIVE_FDS; i++) {
			sockets[i][0] = sockets[i][1] = pipes[i][0] = pipes[i][1] = -1;
			epolls[i] = events[i] = watches[i] = -1;
			if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets[i]) ||
			    pipe2(pipes[i], O_CLOEXEC) ||
			    (epolls[i] = epoll_create1(EPOLL_CLOEXEC)) < 0 ||
			    (events[i] = eventfd(0, EFD_CLOEXEC)) < 0 ||
			    (watches[i] = inotify_init1(IN_CLOEXEC)) < 0) {
				worker->failed = 1;
				for (unsigned int j = 0; j <= i; j++) {
					close_pair(sockets[j]);
					close_pair(pipes[j]);
					if (epolls[j] >= 0)
						close(epolls[j]);
					if (events[j] >= 0)
						close(events[j]);
					if (watches[j] >= 0)
						close(watches[j]);
				}
				return NULL;
			}
		}
		for (unsigned int i = 0; i < LIVE_FDS; i++) {
			close_pair(sockets[i]);
			close_pair(pipes[i]);
			close(epolls[i]);
			close(events[i]);
			close(watches[i]);
		}
		if (!(round & 7))
			sched_yield();
	}
	return NULL;
}

static unsigned int validate_caches(void)
{
	DIR *directory = opendir("/sys/kernel/slab");
	struct dirent *entry;
	unsigned int validated = 0;

	if (!directory)
		return 0;
	while ((entry = readdir(directory))) {
		char path[512];

		if (entry->d_name[0] == '.')
			continue;
		if (snprintf(path, sizeof(path), "/sys/kernel/slab/%s/validate",
			     entry->d_name) >= (int)sizeof(path))
			continue;
		if (!write_text(path, "1\n"))
			validated++;
	}
	closedir(directory);
	return validated;
}

static unsigned int hotplug(const char *kind, const char *leaf, int cpu_mode)
{
	char root[128], path[512], value[32];
	DIR *directory;
	struct dirent *entry;
	unsigned int completed = 0;

	snprintf(root, sizeof(root), "/sys/devices/system/%s", kind);
	directory = opendir(root);
	if (!directory)
		return 0;
	while ((entry = readdir(directory))) {
		unsigned int id;

		if (sscanf(entry->d_name, cpu_mode ? "cpu%u" : "memory%u", &id) != 1 ||
		    (cpu_mode && id == 0))
			continue;
		if (!cpu_mode) {
			FILE *file;

			snprintf(path, sizeof(path), "%s/%s/removable", root, entry->d_name);
			file = fopen(path, "re");
			if (!file || !fgets(value, sizeof(value), file) || value[0] != '1') {
				if (file)
					fclose(file);
				continue;
			}
			fclose(file);
		}
		snprintf(path, sizeof(path), "%s/%s/%s", root, entry->d_name, leaf);
		if (!write_text(path, cpu_mode ? "0\n" : "offline\n") &&
		    !write_text(path, cpu_mode ? "1\n" : "online\n"))
			completed++;
	}
	closedir(directory);
	return completed;
}

static unsigned int node_count(void)
{
	DIR *directory = opendir("/sys/devices/system/node");
	struct dirent *entry;
	unsigned int count = 0, id;

	if (!directory)
		return 0;
	while ((entry = readdir(directory)))
		if (sscanf(entry->d_name, "node%u", &id) == 1)
			count++;
	closedir(directory);
	return count;
}

static int memcg_churn(unsigned int iterations)
{
	char pid[32];
	char release = 1;
	pid_t child;
	int start[2];
	int status;

	if (write_text("/cgroup/cgroup.subtree_control", "+memory\n") ||
	    (mkdir("/cgroup/layout", 0755) && errno != EEXIST) ||
	    access("/cgroup/layout/memory.current", R_OK))
		return -1;
	if (pipe2(start, O_CLOEXEC))
		return -1;
	child = fork();
	if (child < 0) {
		close_pair(start);
		return -1;
	}
	if (!child) {
		struct worker worker = { .cpu = 0, .iterations = iterations };

		close(start[1]);
		if (read(start[0], &release, 1) != 1)
			_exit(2);
		close(start[0]);
		worker_main(&worker);
		_exit(worker.failed);
	}
	close(start[0]);
	snprintf(pid, sizeof(pid), "%d\n", child);
	if (write_text("/cgroup/layout/cgroup.procs", pid) ||
	    write(start[1], &release, 1) != 1) {
		close(start[1]);
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		return -1;
	}
	close(start[1]);
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
		return -1;
	(void)write_text("/cgroup/cgroup.procs", "1\n");
	rmdir("/cgroup/layout");
	return 0;
}

int main(int argc, char **argv)
{
	long online_value = sysconf(_SC_NPROCESSORS_ONLN);
	unsigned int iterations = argc > 1 ? strtoul(argv[1], NULL, 10) : 64;
	unsigned int online, nodes, cpu_hotplug, memory_hotplug, validated;
	struct counters before = { }, after = { };
	struct worker *workers;
	pthread_t *threads;
	int failed = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (getpid() != 1 || online_value < 2 || online_value > CPU_SETSIZE || !iterations ||
	    mount("proc", "/proc", "proc", 0, NULL) ||
	    mount("sysfs", "/sys", "sysfs", 0, NULL) ||
	    mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) ||
	    mount("securityfs", "/sys/kernel/security", "securityfs", 0, NULL) ||
	    mount("tmpfs", "/work", "tmpfs", 0, "size=64m") ||
	    mount("cgroup2", "/cgroup", "cgroup2", 0, NULL) ||
	    read_status(&before, 1) || unprivileged_status())
		goto fail;
	online = online_value;
	nodes = node_count();
	if (nodes < 2)
		goto fail;
	workers = calloc(online, sizeof(*workers));
	threads = calloc(online, sizeof(*threads));
	if (!workers || !threads)
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
		failed |= workers[cpu].failed;
	}
	free(threads);
	free(workers);
	if (failed || memcg_churn(iterations / 2 + 1) ||
	    write_text("/proc/sys/vm/compact_memory", "1\n"))
		goto fail;
	validated = validate_caches();
	cpu_hotplug = hotplug("cpu", "online", 1);
	memory_hotplug = hotplug("memory", "state", 0);
	if (!validated || !cpu_hotplug || !memory_hotplug || read_status(&after, 1) ||
	    after.attempts <= before.attempts || after.slabs <= before.slabs ||
	    after.offset_slabs <= before.offset_slabs || after.failures > after.attempts ||
	    after.placed > after.original || after.displaced > after.original)
		goto fail;
	printf("HDN_SLAB_LAYOUT_STRESS_PASS attempts=%llu slabs=%llu offsets=%llu validate=%u nodes=%u cpu_hotplug=%u memory_hotplug=%u\n",
	       after.attempts - before.attempts, after.slabs - before.slabs,
	       after.offset_slabs - before.offset_slabs, validated, nodes,
	       cpu_hotplug, memory_hotplug);
	reboot(RB_POWER_OFF);
	return 0;
fail:
	printf("HDN_SLAB_LAYOUT_STRESS_FAIL errno=%d\n", errno);
	reboot(RB_POWER_OFF);
	return 1;
}
