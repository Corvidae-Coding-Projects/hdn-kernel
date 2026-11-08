// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mount.h>
#include <sys/msg.h>
#include <sys/reboot.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define STATUS "/sys/kernel/security/hardening/status"
#define MODULE_DIRECTORY "/modules"
#define KEY_SPEC_PROCESS_KEYRING -2
#define KEYCTL_UNLINK 9
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

struct autoslab_status {
	unsigned long long typed, successful, failed, mandatory, early, rejected;
	unsigned int caches, budget;
};

struct worker {
	unsigned int cpu, iterations;
	int failed;
};

struct message {
	long type;
	char payload[128];
};

union semun {
	int val;
	struct semid_ds *buf;
	unsigned short *array;
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

static int read_status(struct autoslab_status *status, int privileged)
{
	static const char *const names[] = {
		"autoslab_typed: ", "autoslab_successful: ", "autoslab_failed: ",
		"autoslab_mandatory: ", "autoslab_early: ", "autoslab_rejected: ",
	};
	unsigned long long *values[] = {
		&status->typed, &status->successful, &status->failed,
		&status->mandatory, &status->early, &status->rejected,
	};
	FILE *file = fopen(STATUS, "re");
	char *line = NULL;
	size_t capacity = 0;
	unsigned int stable = 0, private = 0;

	if (!file)
		return -1;
	while (getline(&line, &capacity, file) >= 0) {
		if (!strcmp(line, "autoslab_state: active\n"))
			stable |= 1U;
		else if (!strcmp(line, "autoslab_metadata_version: 1\n"))
			stable |= 2U;
		else if (sscanf(line, "autoslab_cache_budget: %u", &status->budget) == 1)
			stable |= 4U;
		else if (sscanf(line, "autoslab_caches: %u", &status->caches) == 1)
			stable |= 8U;
		for (size_t i = 0; i < ARRAY_SIZE(names); i++) {
			size_t length = strlen(names[i]);

			if (!strncmp(line, names[i], length)) {
				*values[i] = strtoull(line + length, NULL, 10);
				private |= 1U << i;
			}
		}
	}
	free(line);
	fclose(file);
	if (stable != 15U || status->budget != 2048 || !status->caches ||
	    status->caches > status->budget)
		return -1;
	return privileged ? (private == 63U ? 0 : -1) : (private ? -1 : 0);
}

static int check_unprivileged_status(void)
{
	struct autoslab_status status = { };
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

static int churn_files(void)
{
	int files[64];

	for (size_t i = 0; i < ARRAY_SIZE(files); i++) {
		files[i] = open("/dev/null", O_RDWR | O_CLOEXEC);
		if (files[i] < 0) {
			while (i)
				close(files[--i]);
			return -1;
		}
	}
	for (size_t i = 0; i < ARRAY_SIZE(files); i++)
		close(files[i]);
	return 0;
}

static int churn_sysv(unsigned int seed)
{
	struct message message = { .type = 1 };
	struct sembuf operation = { .sem_num = 0, .sem_op = 1, .sem_flg = SEM_UNDO };
	union semun argument = { .val = 0 };
	int queue = -1, memory = -1, semaphore = -1;
	void *mapping = (void *)-1;
	int result = -1;

	memset(message.payload, (int)seed, sizeof(message.payload));
	queue = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
	memory = shmget(IPC_PRIVATE, 4096 + (seed & 4095U), IPC_CREAT | 0600);
	semaphore = semget(IPC_PRIVATE, 1, IPC_CREAT | 0600);
	if (queue < 0 || memory < 0 || semaphore < 0)
		goto out;
	mapping = shmat(memory, NULL, 0);
	if (mapping == (void *)-1 || semctl(semaphore, 0, SETVAL, argument) < 0 ||
	    semop(semaphore, &operation, 1) ||
	    msgsnd(queue, &message, sizeof(message.payload), 0) ||
	    msgrcv(queue, &message, sizeof(message.payload), 1, 0) < 0)
		goto out;
	memset(mapping, (int)(seed ^ 0x5a), 4096);
	result = 0;
out:
	if (mapping != (void *)-1)
		shmdt(mapping);
	if (queue >= 0)
		msgctl(queue, IPC_RMID, NULL);
	if (memory >= 0)
		shmctl(memory, IPC_RMID, NULL);
	if (semaphore >= 0)
		semctl(semaphore, 0, IPC_RMID, argument);
	return result;
}

static int churn_mqueue(unsigned int cpu, unsigned int round)
{
	struct mq_attr attributes = { .mq_maxmsg = 4, .mq_msgsize = 128 };
	char name[64], payload[128];
	mqd_t queue;
	int result = -1;

	snprintf(name, sizeof(name), "/hdn-autoslab-%d-%u-%u", getpid(), cpu, round);
	queue = mq_open(name, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600, &attributes);
	if (queue == (mqd_t)-1)
		return -1;
	memset(payload, (int)round, sizeof(payload));
	if (!mq_send(queue, payload, sizeof(payload), 0) &&
	    mq_receive(queue, payload, sizeof(payload), NULL) == (ssize_t)sizeof(payload))
		result = 0;
	mq_close(queue);
	mq_unlink(name);
	return result;
}

static int churn_key(unsigned int cpu, unsigned int round)
{
#if defined(SYS_add_key) && defined(SYS_keyctl)
	char description[64], payload[96];
	long key;

	snprintf(description, sizeof(description), "hdn-autoslab-%u-%u", cpu, round);
	memset(payload, (int)(cpu + round), sizeof(payload));
	key = syscall(SYS_add_key, "user", description, payload, sizeof(payload),
		      KEY_SPEC_PROCESS_KEYRING);
	if (key < 0)
		return -1;
	return syscall(SYS_keyctl, KEYCTL_UNLINK, key, KEY_SPEC_PROCESS_KEYRING) < 0 ? -1 : 0;
#else
	errno = ENOSYS;
	return -1;
#endif
}

static int pin_cpu(unsigned int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return sched_setaffinity(0, sizeof(set), &set);
}

static void *worker_main(void *opaque)
{
	struct worker *worker = opaque;

	if (pin_cpu(worker->cpu)) {
		worker->failed = 1;
		return NULL;
	}
	for (unsigned int round = 0; round < worker->iterations; round++) {
		if (churn_files() || churn_sysv(round ^ worker->cpu) ||
		    churn_mqueue(worker->cpu, round) || churn_key(worker->cpu, round)) {
			worker->failed = 1;
			break;
		}
		if (!(round & 3U))
			sched_yield();
	}
	return NULL;
}

static int namespace_churn(void)
{
	pid_t child;
	int status;

	child = fork();
	if (child < 0)
		return -1;
	if (!child) {
		pid_t nested;

		if (unshare(CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWNS | CLONE_NEWPID |
			    CLONE_NEWNET) || sethostname("hdn-autoslab", 12) ||
		    mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) ||
		    mount("tmpfs", "/work", "tmpfs", 0, "size=8m"))
			_exit(2);
		nested = fork();
		if (nested < 0)
			_exit(3);
		if (!nested)
			_exit(churn_files() || churn_sysv(1));
		if (waitpid(nested, &status, 0) != nested || !WIFEXITED(status) ||
		    WEXITSTATUS(status))
			_exit(4);
		umount2("/work", MNT_DETACH);
		_exit(0);
	}
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
		return -1;
	child = fork();
	if (child < 0)
		return -1;
	if (!child)
		_exit(unshare(CLONE_NEWUSER) ? 1 : 0);
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
		return -1;
#ifdef CLONE_NEWTIME
	child = fork();
	if (child < 0)
		return -1;
	if (!child)
		_exit(unshare(CLONE_NEWTIME) ? 1 : 0);
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
		return -1;
#endif
	return 0;
}

static int credential_churn(void)
{
	for (unsigned int i = 0; i < 32; i++) {
		pid_t child = fork();
		int status;

		if (child < 0)
			return -1;
		if (!child)
			_exit(setgid(65534) || setuid(65534));
		if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
		    WEXITSTATUS(status))
			return -1;
	}
	return 0;
}

static unsigned int cpu_drain(void)
{
	DIR *directory = opendir("/sys/devices/system/cpu");
	struct dirent *entry;
	unsigned int completed = 0, cpu;

	if (!directory)
		return 0;
	while ((entry = readdir(directory))) {
		char path[256];

		if (sscanf(entry->d_name, "cpu%u", &cpu) != 1 || cpu == 0)
			continue;
		snprintf(path, sizeof(path), "/sys/devices/system/cpu/%s/online",
			 entry->d_name);
		if (!write_text(path, "0\n") && !write_text(path, "1\n")) {
			completed++;
			break;
		}
	}
	closedir(directory);
	return completed;
}

static int memcg_churn(unsigned int iterations)
{
	char pid[32], release = 1;
	int start[2], status;
	pid_t child;

	if (write_text("/cgroup/cgroup.subtree_control", "+memory\n") ||
	    mkdir("/cgroup/autoslab", 0755) ||
	    write_text("/cgroup/autoslab/memory.high", "16777216\n") ||
	    write_text("/cgroup/autoslab/memory.max", "134217728\n") ||
	    access("/cgroup/autoslab/memory.current", R_OK) || pipe2(start, O_CLOEXEC))
		return -1;
	child = fork();
	if (child < 0)
		return -1;
	if (!child) {
		struct worker worker = { .cpu = 0, .iterations = iterations };
		unsigned char *pressure;

		close(start[1]);
		if (read(start[0], &release, 1) != 1)
			_exit(2);
		close(start[0]);
		pressure = malloc(48U * 1024U * 1024U);
		if (!pressure)
			_exit(3);
		for (size_t offset = 0; offset < 48U * 1024U * 1024U; offset += 4096)
			pressure[offset] = (unsigned char)offset;
		worker_main(&worker);
		free(pressure);
		_exit(worker.failed);
	}
	close(start[0]);
	snprintf(pid, sizeof(pid), "%d\n", child);
	if (write_text("/cgroup/autoslab/cgroup.procs", pid) ||
	    write(start[1], &release, 1) != 1) {
		close(start[1]);
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		return -1;
	}
	close(start[1]);
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
		return -1;
	return rmdir("/cgroup/autoslab");
}

static int finit(const char *path)
{
#ifdef SYS_finit_module
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	int result;

	if (fd < 0)
		return -1;
	result = syscall(SYS_finit_module, fd, "", 0);
	close(fd);
	return result;
#else
	errno = ENOSYS;
	return -1;
#endif
}

static int module_checks(void)
{
	static const char *const rejected[] = {
		MODULE_DIRECTORY "/autoslab-missing-section.ko",
		MODULE_DIRECTORY "/autoslab-wrong-domain.ko",
		MODULE_DIRECTORY "/autoslab-wrong-version.ko",
		MODULE_DIRECTORY "/autoslab-missing-sentinel.ko",
		MODULE_DIRECTORY "/autoslab-truncated.ko",
		MODULE_DIRECTORY "/autoslab-writable.ko",
		MODULE_DIRECTORY "/autoslab-executable.ko",
	};

	if (finit(MODULE_DIRECTORY "/autoslab-valid.ko"))
		return -1;
#ifdef SYS_delete_module
	if (syscall(SYS_delete_module, "autoslab_test_module", O_NONBLOCK))
		return -1;
#else
	return -1;
#endif
	for (size_t i = 0; i < ARRAY_SIZE(rejected); i++) {
		errno = 0;
		if (!finit(rejected[i]) || errno != ENOEXEC)
			return -1;
	}
	return 0;
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

int main(int argc, char **argv)
{
	unsigned int iterations = argc > 1 ? strtoul(argv[1], NULL, 10) : 32;
	long online_value = sysconf(_SC_NPROCESSORS_ONLN);
	struct autoslab_status before = { }, after = { };
	struct worker *workers = NULL;
	pthread_t *threads = NULL;
	unsigned int online, nodes, drained;
	int failed = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (getpid() != 1 || online_value < 2 || online_value > CPU_SETSIZE || iterations < 16 ||
	    mount("proc", "/proc", "proc", 0, NULL) ||
	    mount("sysfs", "/sys", "sysfs", 0, NULL) ||
	    mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) ||
	    (mkdir("/dev/mqueue", 0755) && errno != EEXIST) ||
	    mount("securityfs", "/sys/kernel/security", "securityfs", 0, NULL) ||
	    mount("cgroup2", "/cgroup", "cgroup2", 0, NULL) ||
	    mount("mqueue", "/dev/mqueue", "mqueue", 0, NULL) ||
	    read_status(&before, 1) || check_unprivileged_status())
		goto fail;
	nodes = node_count();
	if (nodes < 2 || namespace_churn() || credential_churn() || module_checks())
		goto fail;
	online = (unsigned int)online_value;
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
	threads = NULL;
	workers = NULL;
	drained = cpu_drain();
	if (failed || !drained || memcg_churn(iterations / 2) ||
	    churn_sysv(0x55) || churn_mqueue(0, iterations + 1) ||
	    read_status(&after, 1) ||
	    after.typed <= before.typed || after.successful <= before.successful ||
	    after.mandatory <= before.mandatory || after.failed > after.typed ||
	    after.caches != before.caches)
		goto fail;
	printf("HDN_AUTOSLAB_RUNTIME_PASS typed=%llu successful=%llu mandatory=%llu failed=%llu caches=%u workers=%u nodes=%u cpu_hotplug=%u memcg_pressure=1 mutations=7\n",
	       after.typed - before.typed, after.successful - before.successful,
	       after.mandatory - before.mandatory, after.failed - before.failed,
	       after.caches, online, nodes, drained);
	reboot(RB_POWER_OFF);
	return 0;
fail:
	free(threads);
	free(workers);
	printf("HDN_AUTOSLAB_RUNTIME_FAIL errno=%d\n", errno);
	reboot(RB_POWER_OFF);
	return 1;
}
