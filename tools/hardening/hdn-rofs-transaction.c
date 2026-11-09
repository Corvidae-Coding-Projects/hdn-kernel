// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/mount.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define HDN_SEAL_RETRIES 20
#define HDN_SEAL_RETRY_NS 250000000L
#define HDN_CANCEL_POLL_NS 50000000L
#define HDN_CANCEL_GRACE_POLLS 40

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s MOUNTPOINT -- COMMAND [ARG...]\n", prog);
}

static int remount_state_once(const char *path, bool readonly)
{
	unsigned long flags = MS_REMOUNT;

#ifdef __NR_mount_setattr
	struct mount_attr attr = {
		.attr_set = readonly ? MOUNT_ATTR_RDONLY : 0,
		.attr_clr = readonly ? 0 : MOUNT_ATTR_RDONLY,
	};

	if (!syscall(__NR_mount_setattr, AT_FDCWD, path, 0, &attr,
		     sizeof(attr))) {
		struct statvfs state;

		if (readonly || statvfs(path, &state) ||
		    !(state.f_flag & ST_RDONLY))
			return 0;
		/* A legacy remount may also have set the superblock read-only. */
	} else if (errno != ENOSYS && errno != EINVAL &&
		   errno != EOPNOTSUPP) {
		return -errno;
	}
#endif

	if (readonly)
		flags |= MS_RDONLY;

	if (!mount(NULL, path, NULL, flags, NULL))
		return 0;

	return -errno;
}

static int remount_state(const char *path, bool readonly)
{
	struct timespec delay = {
		.tv_nsec = HDN_SEAL_RETRY_NS,
	};
	unsigned int attempts = readonly ? HDN_SEAL_RETRIES : 1;
	unsigned int attempt;
	int ret = -EIO;

	for (attempt = 0; attempt < attempts; attempt++) {
		ret = remount_state_once(path, readonly);
		if (!ret)
			return 0;
		if (ret != -EBUSY || attempt + 1 == attempts)
			break;
		sync();
		while (nanosleep(&delay, &delay) && errno == EINTR)
			;
		delay.tv_sec = 0;
		delay.tv_nsec = HDN_SEAL_RETRY_NS;
	}

	fprintf(stderr, "hdn-rofs-transaction: remount %s %s failed: %s\n",
		path, readonly ? "read-only" : "writable", strerror(-ret));
	return ret;
}

static int status_code(int status)
{
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	if (WIFSIGNALED(status))
		return 128 + WTERMSIG(status);

	return 1;
}

static int next_cancel_signal(const sigset_t *cancel_set,
			      const struct timespec *timeout)
{
	int signal;

	for (;;) {
		signal = sigtimedwait(cancel_set, NULL, timeout);
		if (signal >= 0)
			return signal;
		if (errno == EAGAIN)
			return 0;
		if (errno != EINTR) {
			fprintf(stderr,
				"hdn-rofs-transaction: signal wait failed: %s\n",
				strerror(errno));
			return -errno;
		}
	}
}

static void signal_worker(pid_t child, bool worker_group, int signal)
{
	pid_t target = worker_group ? -child : child;

	if (kill(target, signal) && errno != ESRCH)
		fprintf(stderr,
			"hdn-rofs-transaction: signal worker failed: %s\n",
			strerror(errno));
}

static void cancel_worker(pid_t child, bool worker_group, int signal,
			  int *status)
{
	const struct timespec delay = {
		.tv_nsec = HDN_CANCEL_POLL_NS,
	};
	bool child_exited = false;
	bool child_waitable = true;
	unsigned int attempt;

	signal_worker(child, worker_group, signal);
	for (attempt = 0; attempt < HDN_CANCEL_GRACE_POLLS; attempt++) {
		siginfo_t info = {};
		int ret;

		ret = waitid(P_PID, child, &info, WEXITED | WNOHANG | WNOWAIT);
		if (!ret && info.si_pid == child) {
			child_exited = true;
			break;
		}
		if (ret && errno != EINTR) {
			if (errno == ECHILD)
				child_waitable = false;
			else
				fprintf(stderr,
					"hdn-rofs-transaction: wait failed: %s\n",
					strerror(errno));
			break;
		}
		nanosleep(&delay, NULL);
	}

	/*
	 * Stop descendants in the worker's process group before reaping the
	 * direct child. Keeping the child waitable pins its PID and prevents a
	 * reused process-group ID from being signaled here.
	 */
	if (worker_group && child_waitable)
		signal_worker(child, true, SIGKILL);
	else if (!child_exited && child_waitable)
		signal_worker(child, false, SIGKILL);

	while (child_waitable) {
		pid_t ret = waitpid(child, status, 0);

		if (ret == child || (ret < 0 && errno == ECHILD))
			return;
		if (ret < 0 && errno != EINTR) {
			fprintf(stderr,
				"hdn-rofs-transaction: wait failed: %s\n",
				strerror(errno));
			return;
		}
	}
}

static int run_command(char **argv, const sigset_t *cancel_set,
		       const sigset_t *old_mask, int *cancel_signal)
{
	const struct timespec no_wait = {};
	const struct timespec poll_delay = {
		.tv_nsec = HDN_CANCEL_POLL_NS,
	};
	bool worker_group = false;
	int status = 0;
	pid_t child;

	child = fork();
	if (child < 0) {
		fprintf(stderr, "hdn-rofs-transaction: fork failed: %s\n",
			strerror(errno));
		return 1;
	}

	if (!child) {
		if (setpgid(0, 0))
			fprintf(stderr,
				"hdn-rofs-transaction: worker process group failed: %s\n",
				strerror(errno));
		if (sigprocmask(SIG_SETMASK, old_mask, NULL)) {
			fprintf(stderr,
				"hdn-rofs-transaction: worker signal restore failed: %s\n",
				strerror(errno));
			_exit(126);
		}
		execv(argv[0], argv);
		fprintf(stderr, "hdn-rofs-transaction: exec %s failed: %s\n",
			argv[0], strerror(errno));
		_exit(127);
	}

	if (!setpgid(child, child) || getpgid(child) == child)
		worker_group = true;

	for (;;) {
		pid_t waited;
		int signal;

		signal = next_cancel_signal(cancel_set, &no_wait);
		if (signal < 0) {
			cancel_worker(child, worker_group, SIGTERM, &status);
			return 1;
		}
		if (signal > 0) {
			*cancel_signal = signal;
			cancel_worker(child, worker_group, signal, &status);
			return 128 + signal;
		}

		waited = waitpid(child, &status, WNOHANG);
		if (waited == child)
			return status_code(status);
		if (waited < 0 && errno != EINTR) {
			fprintf(stderr, "hdn-rofs-transaction: wait failed: %s\n",
				strerror(errno));
			cancel_worker(child, worker_group, SIGTERM, &status);
			return 1;
		}

		signal = next_cancel_signal(cancel_set, &poll_delay);
		if (signal < 0) {
			cancel_worker(child, worker_group, SIGTERM, &status);
			return 1;
		}
		if (signal > 0) {
			*cancel_signal = signal;
			cancel_worker(child, worker_group, signal, &status);
			return 128 + signal;
		}
	}
}

int main(int argc, char **argv)
{
	const char *mountpoint;
	const struct timespec no_wait = {};
	sigset_t cancel_set;
	sigset_t old_mask;
	int command_arg = 2;
	int command_status;
	int cancel_signal = 0;
	int seal_ret;
	int signal;

	if (argc < 4) {
		usage(argv[0]);
		return 2;
	}

	mountpoint = argv[1];
	if (mountpoint[0] != '/') {
		fprintf(stderr,
			"hdn-rofs-transaction: mountpoint must be absolute: %s\n",
			mountpoint);
		return 2;
	}

	if (!strcmp(argv[command_arg], "--")) {
		command_arg++;
		if (command_arg >= argc) {
			usage(argv[0]);
			return 2;
		}
	}

	sigemptyset(&cancel_set);
	sigaddset(&cancel_set, SIGHUP);
	sigaddset(&cancel_set, SIGINT);
	sigaddset(&cancel_set, SIGQUIT);
	sigaddset(&cancel_set, SIGTERM);
	if (sigprocmask(SIG_BLOCK, &cancel_set, &old_mask)) {
		fprintf(stderr,
			"hdn-rofs-transaction: signal setup failed: %s\n",
			strerror(errno));
		return 1;
	}

	signal = next_cancel_signal(&cancel_set, &no_wait);
	if (signal) {
		sigprocmask(SIG_SETMASK, &old_mask, NULL);
		return signal > 0 ? 128 + signal : 1;
	}

	if (remount_state(mountpoint, false)) {
		sigprocmask(SIG_SETMASK, &old_mask, NULL);
		return 1;
	}

	signal = next_cancel_signal(&cancel_set, &no_wait);
	if (signal > 0) {
		cancel_signal = signal;
		command_status = 128 + signal;
	} else if (signal < 0) {
		command_status = 1;
	} else {
		command_status = run_command(&argv[command_arg], &cancel_set,
					     &old_mask, &cancel_signal);
	}

	seal_ret = remount_state(mountpoint, true);
	for (;;) {
		signal = next_cancel_signal(&cancel_set, &no_wait);
		if (signal <= 0)
			break;
		if (!cancel_signal)
			cancel_signal = signal;
	}
	if (sigprocmask(SIG_SETMASK, &old_mask, NULL)) {
		fprintf(stderr,
			"hdn-rofs-transaction: signal restore failed: %s\n",
			strerror(errno));
		return 1;
	}
	if (seal_ret)
		return 1;
	if (cancel_signal)
		return 128 + cancel_signal;

	return command_status;
}
