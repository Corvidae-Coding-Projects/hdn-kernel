// SPDX-License-Identifier: GPL-2.0-only
/* Closed, unprivileged front end to the system's existing hardware brokers. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static long long monotonic_ms(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return -1;
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static bool property(bool power, char *buffer, size_t capacity)
{
	char *argv[] = { "/usr/bin/busctl", "--system", "--no-pager",
		"--timeout=2", "get-property",
		power ? "org.freedesktop.UPower" : "org.freedesktop.NetworkManager",
		power ? "/org/freedesktop/UPower" : "/org/freedesktop/NetworkManager",
		power ? "org.freedesktop.UPower" : "org.freedesktop.NetworkManager",
		power ? "OnBattery" : "Connectivity", NULL };
	/* Do not accept a caller-selected bus, executable, address or path. */
	char *env[] = { "LC_ALL=C", "PATH=/usr/bin", NULL };
	posix_spawn_file_actions_t actions;
	struct pollfd pfd;
	int pipes[2], status, ret;
	size_t used = 0;
	pid_t child;
	long long start = monotonic_ms(), remaining;
	bool ok = false;

	if (start < 0 || pipe2(pipes, O_CLOEXEC))
		return false;
	if (posix_spawn_file_actions_init(&actions))
		goto close_pipes;
	ret = posix_spawn_file_actions_adddup2(&actions, pipes[1], STDOUT_FILENO);
	ret |= posix_spawn_file_actions_addopen(&actions, STDIN_FILENO,
					       "/dev/null", O_RDONLY, 0);
	ret |= posix_spawn_file_actions_addopen(&actions, STDERR_FILENO,
					       "/dev/null", O_WRONLY, 0);
	ret |= posix_spawn_file_actions_addclosefrom_np(&actions, 3);
	if (!ret)
		ret = posix_spawn(&child, argv[0], &actions, NULL, argv, env);
	posix_spawn_file_actions_destroy(&actions);
	if (ret)
		goto close_pipes;
	close(pipes[1]);
	pfd = (struct pollfd){ .fd = pipes[0], .events = POLLIN };
	for (;;) {
		long long now = monotonic_ms();
		ssize_t n;

		remaining = now < 0 ? 0 : 3000 - (now - start);
		if (remaining <= 0)
			break;
		ret = poll(&pfd, 1, remaining);
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret <= 0 || used == capacity - 1)
			break;
		n = read(pipes[0], buffer + used, capacity - 1 - used);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0)
			break;
		if (!n) {
			ok = true;
			break;
		}
		used += n;
	}
	close(pipes[0]);
	if (!ok)
		kill(child, SIGKILL);
	for (;;) {
		long long now;

		ret = waitpid(child, &status, WNOHANG);
		if (ret == child || (ret < 0 && errno != EINTR))
			break;
		now = monotonic_ms();
		if (now < 0 || now - start >= 3000) {
			kill(child, SIGKILL);
			ok = false;
			while ((ret = waitpid(child, &status, 0)) < 0 && errno == EINTR)
				;
			break;
		}
		poll(NULL, 0, 10);
	}
	buffer[used] = '\0';
	return ok && ret == child && WIFEXITED(status) && !WEXITSTATUS(status);
close_pipes:
	close(pipes[0]);
	close(pipes[1]);
	return false;
}

int main(int argc, char **argv)
{
	char buffer[64];
	const char *value = "unknown";
	bool power;

	if (argc != 2 || (strcmp(argv[1], "power-source") &&
			  strcmp(argv[1], "network-state"))) {
		fprintf(stderr, "usage: %s power-source|network-state\n", argv[0]);
		return 2;
	}
	/* This adapter never gains a service identity on behalf of its caller. */
	if (getuid() != geteuid() || getgid() != getegid() ||
	    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
		return 1;
	power = !strcmp(argv[1], "power-source");
	if (property(power, buffer, sizeof(buffer))) {
		if (power) {
			if (!strcmp(buffer, "b true\n"))
				value = "battery";
			else if (!strcmp(buffer, "b false\n"))
				value = "external";
		} else {
			const char *states[] = { "unknown", "none", "portal", "limited", "full" };
			for (unsigned int i = 0; i < sizeof(states) / sizeof(states[0]); i++) {
				char expected[8];
				snprintf(expected, sizeof(expected), "u %u\n", i);
				if (!strcmp(buffer, expected))
					value = states[i];
			}
		}
	}
	printf("{\"version\":1,\"fact\":\"%s\",\"value\":\"%s\"}\n", argv[1], value);
	return 0;
}
