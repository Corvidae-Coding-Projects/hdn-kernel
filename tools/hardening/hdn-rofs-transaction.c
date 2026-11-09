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

static unsigned long legacy_remount_flags(const struct statvfs *state,
					  bool readonly)
{
	unsigned long flags = MS_REMOUNT;

	if (readonly)
		flags |= MS_RDONLY;
#ifdef ST_NOSUID
	if (state->f_flag & ST_NOSUID)
		flags |= MS_NOSUID;
#endif
#ifdef ST_NODEV
	if (state->f_flag & ST_NODEV)
		flags |= MS_NODEV;
#endif
#ifdef ST_NOEXEC
	if (state->f_flag & ST_NOEXEC)
		flags |= MS_NOEXEC;
#endif
#ifdef ST_SYNCHRONOUS
	if (state->f_flag & ST_SYNCHRONOUS)
		flags |= MS_SYNCHRONOUS;
#endif
#ifdef ST_MANDLOCK
	if (state->f_flag & ST_MANDLOCK)
		flags |= MS_MANDLOCK;
#endif
#ifdef ST_NOATIME
	if (state->f_flag & ST_NOATIME)
		flags |= MS_NOATIME;
#endif
#ifdef ST_NODIRATIME
	if (state->f_flag & ST_NODIRATIME)
		flags |= MS_NODIRATIME;
#endif
#ifdef ST_RELATIME
	if (state->f_flag & ST_RELATIME)
		flags |= MS_RELATIME;
#endif
#ifdef ST_NOSYMFOLLOW
	if (state->f_flag & ST_NOSYMFOLLOW)
		flags |= MS_NOSYMFOLLOW;
#endif

	return flags;
}

static int read_mount_state(const char *path, struct statvfs *state)
{
	if (!statvfs(path, state))
		return 0;

	return -errno;
}

static bool mount_state_matches(const struct statvfs *state, bool readonly)
{
	return !!(state->f_flag & ST_RDONLY) == readonly;
}

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s MOUNTPOINT -- COMMAND [ARG...]\n", prog);
}

static int remount_state_once(const char *path, bool readonly)
{
	struct statvfs state;
	unsigned long flags;
	int ret;

#ifdef __NR_mount_setattr
	struct mount_attr attr = {
		.attr_set = readonly ? MOUNT_ATTR_RDONLY : 0,
		.attr_clr = readonly ? 0 : MOUNT_ATTR_RDONLY,
	};

	if (!syscall(__NR_mount_setattr, AT_FDCWD, path, 0, &attr,
		     sizeof(attr))) {
		ret = read_mount_state(path, &state);
		if (ret)
			return ret;
		if (mount_state_matches(&state, readonly))
			return 0;
		/* The superblock can remain read-only after clearing the mount bit. */
	} else if (errno != ENOSYS && errno != EINVAL &&
		   errno != EOPNOTSUPP) {
		return -errno;
	} else {
		ret = read_mount_state(path, &state);
		if (ret)
			return ret;
	}
#else
	ret = read_mount_state(path, &state);
	if (ret)
		return ret;
#endif

	flags = legacy_remount_flags(&state, readonly);
	if (mount(NULL, path, NULL, flags, NULL))
		return -errno;
	ret = read_mount_state(path, &state);
	if (ret)
		return ret;
	if (!mount_state_matches(&state, readonly))
		return readonly ? -EIO : -EROFS;

	return 0;
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

static int finish_worker(pid_t child, bool worker_group, int *status)
{
	/*
	 * A successful direct worker must not be able to leave a background
	 * writer behind. The waitid(WNOWAIT) caller keeps the direct child (and
	 * therefore its process-group ID) pinned until the complete group has
	 * been stopped and the child can be reaped safely.
	 */
	if (worker_group)
		signal_worker(child, true, SIGKILL);

	for (;;) {
		pid_t ret = waitpid(child, status, 0);

		if (ret == child)
			return status_code(*status);
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0)
			fprintf(stderr,
				"hdn-rofs-transaction: wait failed: %s\n",
				strerror(errno));
		return 1;
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
		if (setpgid(0, 0)) {
			fprintf(stderr,
				"hdn-rofs-transaction: worker process group failed: %s\n",
				strerror(errno));
			_exit(126);
		}
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
		siginfo_t info = {};
		int signal;
		int ret;

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

		ret = waitid(P_PID, child, &info, WEXITED | WNOHANG | WNOWAIT);
		if (!ret && info.si_pid == child)
			return finish_worker(child, worker_group, &status);
		if (ret && errno != EINTR) {
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
