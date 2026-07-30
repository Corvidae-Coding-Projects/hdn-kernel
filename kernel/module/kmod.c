// SPDX-License-Identifier: GPL-2.0
/*
 * kmod - the kernel module loader
 *
 * Copyright (C) 2023 Luis Chamberlain <mcgrof@kernel.org>
 */

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/binfmts.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/kmod.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <linux/cred.h>
#include <linux/file.h>
#include <linux/workqueue.h>
#include <linux/security.h>
#include <linux/hardening.h>
#include <linux/mount.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/resource.h>
#include <linux/notifier.h>
#include <linux/suspend.h>
#include <linux/rwsem.h>
#include <linux/ptrace.h>
#include <linux/async.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/user_namespace.h>

#include <trace/events/module.h>
#include "internal.h"

/*
 * Assuming:
 *
 * threads = div64_u64((u64) totalram_pages * (u64) PAGE_SIZE,
 *		       (u64) THREAD_SIZE * 8UL);
 *
 * If you need less than 50 threads would mean we're dealing with systems
 * smaller than 3200 pages. This assumes you are capable of having ~13M memory,
 * and this would only be an upper limit, after which the OOM killer would take
 * effect. Systems like these are very unlikely if modules are enabled.
 */
#define MAX_KMOD_CONCURRENT 50
static DEFINE_SEMAPHORE(kmod_concurrent_max, MAX_KMOD_CONCURRENT);

/*
 * This is a restriction on having *all* MAX_KMOD_CONCURRENT threads
 * running at the same time without returning. When this happens we
 * believe you've somehow ended up with a recursive module dependency
 * creating a loop.
 *
 * We have no option but to fail.
 *
 * Userspace should proactively try to detect and prevent these.
 */
#define MAX_KMOD_ALL_BUSY_TIMEOUT 5

/*
	modprobe_path is set via /proc/sys.
*/
char modprobe_path[KMOD_PATH_LEN] = CONFIG_MODPROBE_PATH;

enum {
	MODPROBE_ENV_HOME,
	MODPROBE_ENV_TERM,
	MODPROBE_ENV_PATH,
	MODPROBE_ENV_HDN_REQUEST,
	MODPROBE_ENV_HDN_UID,
	MODPROBE_ENV_HDN_EUID,
	MODPROBE_ENV_HDN_PROFILE,
	MODPROBE_ENV_COUNT,
};

static void free_modprobe_envp(char **envp)
{
	if (!envp)
		return;

	kfree(envp[MODPROBE_ENV_HDN_REQUEST]);
	kfree(envp[MODPROBE_ENV_HDN_UID]);
	kfree(envp[MODPROBE_ENV_HDN_EUID]);
	kfree(envp[MODPROBE_ENV_HDN_PROFILE]);
	kfree(envp);
}

static char **build_modprobe_envp(const char *module_name)
{
	uid_t uid = from_kuid_munged(&init_user_ns, current_uid());
	uid_t euid = from_kuid_munged(&init_user_ns, current_euid());
	char **envp;

	envp = kcalloc(MODPROBE_ENV_COUNT, sizeof(*envp), GFP_KERNEL);
	if (!envp)
		return NULL;

	envp[MODPROBE_ENV_HOME] = "HOME=/";
	envp[MODPROBE_ENV_TERM] = "TERM=linux";
	envp[MODPROBE_ENV_PATH] = "PATH=/sbin:/usr/sbin:/bin:/usr/bin";
	envp[MODPROBE_ENV_HDN_REQUEST] =
		kasprintf(GFP_KERNEL, "HDN_MODULE_REQUEST=%s", module_name);
	envp[MODPROBE_ENV_HDN_UID] =
		kasprintf(GFP_KERNEL, "HDN_MODULE_UID=%u", uid);
	envp[MODPROBE_ENV_HDN_EUID] =
		kasprintf(GFP_KERNEL, "HDN_MODULE_EUID=%u", euid);
	envp[MODPROBE_ENV_HDN_PROFILE] =
		kasprintf(GFP_KERNEL, "HDN_MODULE_PROFILE=%llu",
			  (unsigned long long)hdn_current_profile_id());

	if (!envp[MODPROBE_ENV_HDN_REQUEST] ||
	    !envp[MODPROBE_ENV_HDN_UID] ||
	    !envp[MODPROBE_ENV_HDN_EUID] ||
	    !envp[MODPROBE_ENV_HDN_PROFILE]) {
		free_modprobe_envp(envp);
		return NULL;
	}

	return envp;
}

static void free_modprobe_argv(struct subprocess_info *info)
{
	kfree(info->argv[3]); /* check call_modprobe() */
	kfree(info->argv);
	free_modprobe_envp(info->envp);
}

static int call_modprobe(char *orig_module_name, int wait)
{
	struct subprocess_info *info;
	char **envp;
	char *module_name;
	int ret;

	char **argv = kmalloc(sizeof(char *[5]), GFP_KERNEL);
	if (!argv)
		goto out;

	module_name = kstrdup(orig_module_name, GFP_KERNEL);
	if (!module_name)
		goto free_argv;

	envp = build_modprobe_envp(module_name);
	if (!envp)
		goto free_module_name;

	argv[0] = modprobe_path;
	argv[1] = "-q";
	argv[2] = "--";
	argv[3] = module_name;	/* check free_modprobe_argv() */
	argv[4] = NULL;

	info = call_usermodehelper_setup(modprobe_path, argv, envp, GFP_KERNEL,
					 NULL, free_modprobe_argv, NULL);
	if (!info)
		goto free_envp;

	ret = call_usermodehelper_exec(info, wait | UMH_KILLABLE);
	kmod_dup_request_announce(orig_module_name, ret);
	return ret;

free_envp:
	free_modprobe_envp(envp);
free_module_name:
	kfree(module_name);
free_argv:
	kfree(argv);
out:
	kmod_dup_request_announce(orig_module_name, -ENOMEM);
	return -ENOMEM;
}

static int request_module_preflight(bool wait)
{
	/*
	 * We don't allow synchronous module loading from async.  Module
	 * init may invoke async_synchronize_full() which will end up
	 * waiting for this task which already is waiting for the module
	 * loading to complete, leading to a deadlock.
	 */
	WARN_ON_ONCE(wait && current_is_async());

	if (!modprobe_path[0])
		return -ENOENT;

	return 0;
}

static int request_module_run(bool wait, char *module_name)
{
	int ret, dup_ret;

	if (!module_name[0])
		return -EINVAL;

	ret = security_kernel_module_request(module_name);
	if (ret)
		return ret;

	ret = hdn_authorize_module_autoload(module_name);
	if (ret)
		return ret;

	ret = down_timeout(&kmod_concurrent_max, MAX_KMOD_ALL_BUSY_TIMEOUT * HZ);
	if (ret) {
		pr_warn_ratelimited("request_module: modprobe %s cannot be processed, kmod busy with %d threads for more than %d seconds now",
				    module_name, MAX_KMOD_CONCURRENT, MAX_KMOD_ALL_BUSY_TIMEOUT);
		return ret;
	}

	trace_module_request(module_name, wait, _RET_IP_);

	if (kmod_dup_request_exists_wait(module_name, wait, &dup_ret)) {
		ret = dup_ret;
		goto out;
	}

	ret = call_modprobe(module_name, wait ? UMH_WAIT_PROC : UMH_WAIT_EXEC);

out:
	up(&kmod_concurrent_max);

	return ret;
}

/**
 * __request_module_name - try to load an exact kernel module name
 * @wait: wait (or not) for the operation to complete
 * @name: literal module alias/name, not a printf format string
 *
 * Load a module using the user mode module loader. The function returns
 * zero on success or a negative errno code or positive exit code from
 * "modprobe" on failure.
 */
int __request_module_name(bool wait, const char *name)
{
	char module_name[MODULE_NAME_LEN];
	int ret;

	ret = request_module_preflight(wait);
	if (ret)
		return ret;
	if (!name)
		return -EINVAL;

	ret = strscpy(module_name, name, sizeof(module_name));
	if (ret < 0)
		return -ENAMETOOLONG;

	return request_module_run(wait, module_name);
}
EXPORT_SYMBOL(__request_module_name);

/**
 * __request_module - try to load a formatted kernel module name
 * @wait: wait (or not) for the operation to complete
 * @fmt: printf style format string for the name of the module
 * @...: arguments as specified in the format string
 *
 * Load a module using the user mode module loader. The function returns
 * zero on success or a negative errno code or positive exit code from
 * "modprobe" on failure. Note that a successful module load does not mean
 * the module did not then unload and exit on an error of its own. Callers
 * must check that the service they requested is now available not blindly
 * invoke it.
 *
 * If module auto-loading support is disabled then this function
 * simply returns -ENOENT.
 */
int __request_module(bool wait, const char *fmt, ...)
{
	va_list args;
	char module_name[MODULE_NAME_LEN];
	int ret;

	ret = request_module_preflight(wait);
	if (ret)
		return ret;
	if (!fmt)
		return -EINVAL;

	va_start(args, fmt);
	ret = vsnprintf(module_name, MODULE_NAME_LEN, fmt, args);
	va_end(args);
	if (ret < 0)
		return ret;
	if (ret >= MODULE_NAME_LEN)
		return -ENAMETOOLONG;

	return request_module_run(wait, module_name);
}
EXPORT_SYMBOL(__request_module);
