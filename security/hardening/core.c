// SPDX-License-Identifier: GPL-2.0-only

#include <linux/binfmts.h>
#include <linux/buildid.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/delay.h>
#include <linux/elf.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/fsverity.h>
#include <linux/hardirq.h>
#include <linux/hardening.h>
#include <linux/hdn_execmem.h>
#include <linux/hdn_pgtable.h>
#include <linux/hdn_kernexec.h>
#include <linux/hdn_rap.h>
#include <linux/hdn_stack.h>
#include <linux/hdn_uaccess.h>
#include <linux/execmem.h>
#include <linux/hdn_slab.h>
#include <linux/hdn_alloc.h>
#include <linux/hdn_jitter.h>
#include <linux/hdn_sysfs.h>
#include <linux/hdn_capabilities.h>
#include <linux/hash.h>
#include <linux/init.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ipc.h>
#include <linux/ipc_namespace.h>
#include <linux/kdev_t.h>
#include <linux/kernel.h>
#include <linux/kstrtox.h>
#include <linux/ktime.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/module_signature.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/namei.h>
#include <linux/nospec.h>
#include <linux/overflow.h>
#include <linux/pid.h>
#include <linux/poll.h>
#include <linux/ptrace.h>
#include <linux/rcupdate.h>
#include <linux/resource.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/set_memory.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <linux/uaccess.h>
#include <linux/un.h>
#include <linux/user_namespace.h>
#include <linux/verification.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <net/inet_sock.h>
#include <net/sock.h>
#include <asm/byteorder.h>
#include <asm/ioctls.h>
#include <crypto/sha2.h>
#include <uapi/linux/prctl.h>
#include "seal.h"
#ifdef CONFIG_SECURITY_HARDENING_KERNEL_WX
#include <asm/hdn_gdt.h>
#include <asm/hdn_text.h>
#endif

#define HDN_EVENT_RING_SIZE 1024
#define HDN_AUDIT_FLOOD_BUCKET_COUNT 64
#define HDN_AUDIT_FLOOD_BURST 32
#define HDN_AUDIT_FLOOD_WINDOW_NS (10ULL * NSEC_PER_SEC)
#define HDN_AUDIT_FLOOD_MIN_BURST 1
#define HDN_AUDIT_FLOOD_MAX_BURST 1024
#define HDN_AUDIT_FLOOD_MIN_WINDOW_MS 1
#define HDN_AUDIT_FLOOD_MAX_WINDOW_MS 600000
#define HDN_POLICY_SIG_STRING MODULE_SIG_STRING
#define HDN_MAX_SIGNED_POLICY_SIZE (HDN_MAX_POLICY_SIZE + 131072)
#define HDN_BRUTE_RECORD_COUNT 64
#define HDN_BRUTE_CRASH_LIMIT 3
#define HDN_BRUTE_WINDOW_NS (60ULL * NSEC_PER_SEC)
#define HDN_BRUTE_PENALTY_NS (60ULL * NSEC_PER_SEC)
#define HDN_BRUTE_DAEMON_WINDOW_NS (30ULL * 60ULL * NSEC_PER_SEC)
#define HDN_BRUTE_DAEMON_FORK_DELAY_MS (30U * 1000U)
#define HDN_KERNEL_LOCKOUT_UID_COUNT 16
#define HDN_PRIVEXEC_ARG_LIMIT (512UL * 1024UL)
#define HDN_PRIVEXEC_STACK_LIMIT (8UL * 1024UL * 1024UL)

#ifndef CONFIG_SECURITY_HARDENING_PROC_TASK_GID
#define CONFIG_SECURITY_HARDENING_PROC_TASK_GID (-1)
#endif

#define HDN_MITIGATION_HARDENED_USERCOPY	(1ULL << 0)
#define HDN_MITIGATION_INIT_ON_ALLOC		(1ULL << 1)
#define HDN_MITIGATION_INIT_ON_FREE		(1ULL << 2)
#define HDN_MITIGATION_INIT_STACK_ZERO		(1ULL << 3)
#define HDN_MITIGATION_KSTACK_ERASE		(1ULL << 4)
#define HDN_MITIGATION_ZERO_CALL_USED_REGS	(1ULL << 5)
#define HDN_MITIGATION_FORTIFY_SOURCE		(1ULL << 6)
#define HDN_MITIGATION_RANDSTRUCT		(1ULL << 7)
#define HDN_MITIGATION_SLAB_FREELIST_RANDOM	(1ULL << 8)
#define HDN_MITIGATION_SLAB_FREELIST_HARDENED	(1ULL << 9)
#define HDN_MITIGATION_RANDOM_KMALLOC_CACHES	(1ULL << 10)
#define HDN_MITIGATION_SLAB_BUCKETS		(1ULL << 11)
#define HDN_MITIGATION_SLAB_MERGE_DISABLED	(1ULL << 12)
#define HDN_MITIGATION_RANDOMIZE_KSTACK		(1ULL << 13)
#define HDN_MITIGATION_CFI			(1ULL << 14)
#define HDN_MITIGATION_FINEIBT			(1ULL << 15)
#define HDN_MITIGATION_LIST_HARDENED		(1ULL << 16)
#define HDN_MITIGATION_STRICT_KERNEL_RWX	(1ULL << 17)
#define HDN_MITIGATION_STRICT_MODULE_RWX	(1ULL << 18)
#define HDN_MITIGATION_DMESG_RESTRICT		(1ULL << 19)
#define HDN_MITIGATION_PROC_MEM_RESTRICT	(1ULL << 20)
#define HDN_MITIGATION_KPTR_RESTRICT		(1ULL << 21)
#define HDN_MITIGATION_BRUTE_THROTTLE		(1ULL << 22)
#define HDN_MITIGATION_SYSVIPC_HARDEN		(1ULL << 23)
#define HDN_MITIGATION_TTY_INJECTION_HARDEN	(1ULL << 24)
#define HDN_MITIGATION_FUSE_RESTRICT		(1ULL << 25)
#define HDN_MITIGATION_ROFS_HARDEN		(1ULL << 26)
#define HDN_MITIGATION_PROC_HIDE		(1ULL << 27)
#define HDN_MITIGATION_USB_RESTRICT		(1ULL << 28)
#define HDN_MITIGATION_SOCKET_RESTRICT		(1ULL << 29)
#define HDN_MITIGATION_AUDIT_FLOOD		(1ULL << 30)
#define HDN_MITIGATION_POSIX_MQUEUE_HARDEN	(1ULL << 31)
#define HDN_MITIGATION_TIME_ADMIN		(1ULL << 32)
#define HDN_MITIGATION_RESOURCE_ADMIN		(1ULL << 33)
#define HDN_MITIGATION_BLOCK_DEVICE_RESTRICT	(1ULL << 34)
#define HDN_MITIGATION_FORK_AUDIT		(1ULL << 35)
#define HDN_MITIGATION_EXEC_AUDIT		(1ULL << 36)
#define HDN_MITIGATION_CHDIR_AUDIT		(1ULL << 37)
#define HDN_MITIGATION_MOUNT_AUDIT		(1ULL << 38)
#define HDN_MITIGATION_RESOURCE_AUDIT		(1ULL << 39)
#define HDN_MITIGATION_TIME_AUDIT		(1ULL << 40)
#define HDN_MITIGATION_PTRACE_READEXEC		(1ULL << 41)
#define HDN_MITIGATION_MODULE_AUTOLOAD		(1ULL << 42)
#define HDN_MITIGATION_PROC_IPADDR		(1ULL << 43)
#define HDN_MITIGATION_NET_BLACKHOLE		(1ULL << 44)
#define HDN_MITIGATION_TCP_NO_SIMULT_CONNECT	(1ULL << 45)
#define HDN_MITIGATION_SEALED_DATA_REPORT	(1ULL << 46)
#define HDN_MITIGATION_RAND_THREADSTACK		(1ULL << 47)
#define HDN_MITIGATION_VMAP_STACK		(1ULL << 48)
#define HDN_MITIGATION_THREAD_INFO_IN_TASK	(1ULL << 49)
#define HDN_MITIGATION_STACKPROTECTOR_STRONG	(1ULL << 50)
#define HDN_MITIGATION_SIGNAL_AUDIT		(1ULL << 51)
#define HDN_MITIGATION_FORKFAIL_AUDIT		(1ULL << 52)
#define HDN_MITIGATION_FS_PROTECTION_AUDIT	(1ULL << 53)
#define HDN_MITIGATION_PTRACE_AUDIT		(1ULL << 54)
#define HDN_MITIGATION_CONSISTENT_SETXID	(1ULL << 55)
#define HDN_MITIGATION_SYMLINK_OWNER		(1ULL << 56)
#define HDN_MITIGATION_RWXMAP_AUDIT		(1ULL << 57)
#define HDN_MITIGATION_SUID_SPECTRE		(1ULL << 58)
#define HDN_MITIGATION_UNPRIV_BPF_LOCKDOWN	(1ULL << 59)
#define HDN_MITIGATION_UNPRIV_PERF_LOCKDOWN	(1ULL << 60)
#define HDN_MITIGATION_BPF_JIT_HARDEN		(1ULL << 61)
#define HDN_MITIGATION_KERNEL_LOCKOUT		(1ULL << 62)
#define HDN_MITIGATION_PROC_MEMMAP_REDACT	(1ULL << 63)

#define HDN_MITIGATION2_USERFAULTFD_RESTRICT	(1ULL << 0)
#define HDN_MITIGATION2_PAGE_TABLE_CHECK	(1ULL << 1)
#define HDN_MITIGATION2_MMAP_MIN_ADDR		(1ULL << 2)
#define HDN_MITIGATION2_IO_URING_SYSCTL_LOCK	(1ULL << 3)
#define HDN_MITIGATION2_MODULE_AUTOLOAD_PATH	(1ULL << 4)
#define HDN_MITIGATION2_KEXEC_LOAD_DISABLE	(1ULL << 5)
#define HDN_MITIGATION2_MODULE_LOAD_DISABLE	(1ULL << 6)
#define HDN_MITIGATION2_MODULE_REQUEST_NAME	(1ULL << 7)
#define HDN_MITIGATION2_MODULE_AUTOLOAD_CONTEXT	(1ULL << 8)
#define HDN_MITIGATION2_TTY_ACCESS_HARDEN	(1ULL << 9)

struct hdn_mitigation_state {
	struct hdn_seal *seal;
	u32 abi_version;
	u32 sealed_pages;
	u64 flags;
	u64 flags2;
	bool sealed;
};

struct hdn_policy {
	struct hdn_seal *seal;
	u32 required_capabilities;
	u32 profile_count;
	u32 subject_rule_count;
	u32 object_rule_count;
	u32 exec_rule_count;
	u32 module_rule_count;
	u32 firmware_rule_count;
	u32 resource_rule_count;
	u64 generation;
	u64 expected_generation;
	u64 default_profile_id;
	u64 privileged_profile_id;
	u8 source_digest[SHA256_DIGEST_SIZE];
	size_t alloc_size;
	bool sealed;
	struct hdn_subject_rule_record *subject_rules;
	struct hdn_object_rule_record *object_rules;
	struct hdn_exec_rule_record *exec_rules;
	struct hdn_module_rule_record *module_rules;
	struct hdn_firmware_rule_record *firmware_rules;
	struct hdn_resource_rule_record *resource_rules;
	struct hdn_profile_record profiles[] __counted_by(profile_count);
};

struct hdn_policy_free_work {
	struct rcu_head rcu;
	struct work_struct work;
	struct hdn_policy *policy;
};

struct hdn_file_identity {
	u64 dev_major;
	u64 dev_minor;
	u64 ino;
	u32 verity_digest_size;
	u32 verity_digest_algorithm;
	u8 verity_digest[64];
};

struct hdn_brute_record {
	bool used;
	uid_t uid;
	u64 dev_major;
	u64 dev_minor;
	u64 ino;
	u64 profile_id;
	u64 first_crash_ns;
	u64 last_crash_ns;
	u64 penalty_until_ns;
	u32 crash_count;
};

struct hdn_kernel_lockout_record {
	bool used;
	kuid_t uid;
};

struct hdn_audit_flood_key {
	u64 profile_id;
	u32 action;
	u32 authority;
	u32 transition;
	u32 reason;
	s32 error;
};

struct hdn_audit_flood_bucket {
	bool used;
	struct hdn_audit_flood_key key;
	u64 window_start_ns;
	u64 last_seen_ns;
	u32 count;
	u32 suppressed;
};

static const struct hdn_profile_record hdn_builtin_profiles[] = {
	{
		.profile_id = HDN_PROFILE_DEFAULT,
		.name = "default",
	},
	{
		.profile_id = HDN_PROFILE_PRIVILEGED,
		.authority_allow =
			HDN_AUTHORITY_MASK(HDN_AUTH_BPF_LOAD) |
			HDN_AUTHORITY_MASK(HDN_AUTH_PERF_OPEN) |
			HDN_AUTHORITY_MASK(HDN_AUTH_USERNS_CREATE) |
			HDN_AUTHORITY_MASK(HDN_AUTH_MODULE_LOAD) |
			HDN_AUTHORITY_MASK(HDN_AUTH_MODULE_AUTOLOAD) |
			HDN_AUTHORITY_MASK(HDN_AUTH_PTRACE) |
			HDN_AUTHORITY_MASK(HDN_AUTH_PROC_DISCLOSE) |
			HDN_AUTHORITY_MASK(HDN_AUTH_DEBUGFS) |
			HDN_AUTHORITY_MASK(HDN_AUTH_SYSFS_MUTATE) |
			HDN_AUTHORITY_MASK(HDN_AUTH_KEXEC_LOAD) |
			HDN_AUTHORITY_MASK(HDN_AUTH_FIRMWARE_LOAD) |
			HDN_AUTHORITY_MASK(HDN_AUTH_IO_URING_RESTRICTED_OP) |
			HDN_AUTHORITY_MASK(HDN_AUTH_KERNEL_LOG_READ) |
			HDN_AUTHORITY_MASK(HDN_AUTH_RAW_IO) |
			HDN_AUTHORITY_MASK(HDN_AUTH_MOUNT_ADMIN) |
			HDN_AUTHORITY_MASK(HDN_AUTH_POLICY_ADMIN) |
			HDN_AUTHORITY_MASK(HDN_AUTH_NAMESPACE_ADMIN) |
			HDN_AUTHORITY_MASK(HDN_AUTH_CRED_CHANGE) |
			HDN_AUTHORITY_MASK(HDN_AUTH_CHROOT_ADMIN) |
			HDN_AUTHORITY_MASK(HDN_AUTH_TRUSTED_EXEC_BYPASS) |
			HDN_AUTHORITY_MASK(HDN_AUTH_IPC_ADMIN) |
			HDN_AUTHORITY_MASK(HDN_AUTH_TTY_INJECT) |
			HDN_AUTHORITY_MASK(HDN_AUTH_FUSE_MOUNT) |
			HDN_AUTHORITY_MASK(HDN_AUTH_ROFS_RELAX) |
			HDN_AUTHORITY_MASK(HDN_AUTH_USB_ATTACH) |
			HDN_AUTHORITY_MASK(HDN_AUTH_SOCKET_CREATE) |
			HDN_AUTHORITY_MASK(HDN_AUTH_SOCKET_CONNECT) |
			HDN_AUTHORITY_MASK(HDN_AUTH_SOCKET_SERVER) |
			HDN_AUTHORITY_MASK(HDN_AUTH_PROC_TASK_VIEW) |
			HDN_AUTHORITY_MASK(HDN_AUTH_TIME_ADMIN) |
			HDN_AUTHORITY_MASK(HDN_AUTH_RESOURCE_ADMIN) |
			HDN_AUTHORITY_MASK(HDN_AUTH_BLOCK_DEVICE_ACCESS) |
			HDN_AUTHORITY_MASK(HDN_AUTH_BLOCK_DEVICE_ADMIN) |
			HDN_AUTHORITY_MASK(HDN_AUTH_SYSFS_READ) |
			HDN_AUTHORITY_MASK(HDN_AUTH_PTRACE_EXEC_READ) |
			HDN_AUTHORITY_MASK(HDN_AUTH_SIGNAL) |
			HDN_AUTHORITY_MASK(HDN_AUTH_PROCESS_MEMORY) |
			HDN_AUTHORITY_MASK(HDN_AUTH_MEMORY_MIGRATE) |
			HDN_AUTHORITY_MASK(HDN_AUTH_PROCESS_FD),
			.authority_allow_hi =
				HDN_AUTHORITY_MASK(HDN_AUTH_USB_MONITOR) |
				HDN_AUTHORITY_MASK(HDN_AUTH_KERNEL_LOG_WRITE) |
				HDN_AUTHORITY_MASK(HDN_AUTH_TTY_ACCESS),
		.name = "privileged",
	},
};

static const char * const hdn_phase_names[] = {
	[HDN_PHASE_BOOT] = "boot",
	[HDN_PHASE_INIT] = "init",
	[HDN_PHASE_POLICY_LOAD] = "policy_load",
	[HDN_PHASE_RUNTIME] = "runtime",
	[HDN_PHASE_RECOVERY] = "recovery",
};

static DEFINE_MUTEX(hdn_policy_mutex);
static DEFINE_SEQLOCK(hdn_policy_publication_lock);
static atomic64_t hdn_policy_epoch = ATOMIC64_INIT(1);
/* A rollback can restore base policy, never old compatibility approvals. */
static u64 hdn_compat_generation_highwater;
static bool hdn_compat_after_rollback;
static bool hdn_compat_policy_enabled;
static struct hdn_policy __rcu *hdn_active_policy;
static struct hdn_policy __rcu *hdn_previous_policy;
static struct hdn_policy *hdn_staged_policy;
static enum hdn_phase hdn_phase = HDN_PHASE_POLICY_LOAD;
static DEFINE_SPINLOCK(hdn_event_lock);
static DEFINE_SPINLOCK(hdn_brute_lock);
static DEFINE_SPINLOCK(hdn_kernel_lockout_lock);
static DECLARE_WAIT_QUEUE_HEAD(hdn_event_wait);
static struct hdn_event hdn_events[HDN_EVENT_RING_SIZE];
static struct hdn_brute_record hdn_brute_records[HDN_BRUTE_RECORD_COUNT];
static struct hdn_kernel_lockout_record
	hdn_kernel_lockout_records[HDN_KERNEL_LOCKOUT_UID_COUNT];
static struct hdn_audit_flood_bucket
	hdn_audit_flood_buckets[HDN_AUDIT_FLOOD_BUCKET_COUNT];
static u32 hdn_audit_flood_burst = HDN_AUDIT_FLOOD_BURST;
static u64 hdn_audit_flood_window_ns = HDN_AUDIT_FLOOD_WINDOW_NS;
static u64 hdn_event_sequence;
static u64 hdn_audit_flood_suppressed_total;
static u32 hdn_audit_flood_last_action;
static u32 hdn_audit_flood_last_authority;
static u32 hdn_audit_flood_last_transition;
static u32 hdn_audit_flood_last_reason;
static int hdn_proc_task_gid __ro_after_init =
	CONFIG_SECURITY_HARDENING_PROC_TASK_GID;

static int __init hdn_proc_task_gid_setup(char *str)
{
	int gid;

	if (!str || kstrtoint(str, 0, &gid))
		return 0;
	if (gid < -1)
		return 0;

	WRITE_ONCE(hdn_proc_task_gid, gid);
	return 1;
}
__setup("hdn.proc_task_gid=", hdn_proc_task_gid_setup);
static const struct hdn_mitigation_state *hdn_mitigations __ro_after_init;

static const struct hdn_profile_record *hdn_profile_by_id(u64 profile_id);

static u64 hdn_build_mitigation_flags(void)
{
	u64 flags = 0;

	if (IS_ENABLED(CONFIG_HARDENED_USERCOPY))
		flags |= HDN_MITIGATION_HARDENED_USERCOPY;
	if (IS_ENABLED(CONFIG_INIT_ON_ALLOC_DEFAULT_ON))
		flags |= HDN_MITIGATION_INIT_ON_ALLOC;
	if (IS_ENABLED(CONFIG_INIT_ON_FREE_DEFAULT_ON))
		flags |= HDN_MITIGATION_INIT_ON_FREE;
	if (IS_ENABLED(CONFIG_INIT_STACK_ALL_ZERO))
		flags |= HDN_MITIGATION_INIT_STACK_ZERO;
	if (IS_ENABLED(CONFIG_KSTACK_ERASE))
		flags |= HDN_MITIGATION_KSTACK_ERASE;
	if (IS_ENABLED(CONFIG_ZERO_CALL_USED_REGS))
		flags |= HDN_MITIGATION_ZERO_CALL_USED_REGS;
	if (IS_ENABLED(CONFIG_FORTIFY_SOURCE))
		flags |= HDN_MITIGATION_FORTIFY_SOURCE;
	if (IS_ENABLED(CONFIG_RANDSTRUCT))
		flags |= HDN_MITIGATION_RANDSTRUCT;
	if (IS_ENABLED(CONFIG_SLAB_FREELIST_RANDOM))
		flags |= HDN_MITIGATION_SLAB_FREELIST_RANDOM;
	if (IS_ENABLED(CONFIG_SLAB_FREELIST_HARDENED))
		flags |= HDN_MITIGATION_SLAB_FREELIST_HARDENED;
	if (IS_ENABLED(CONFIG_RANDOM_KMALLOC_CACHES))
		flags |= HDN_MITIGATION_RANDOM_KMALLOC_CACHES;
	if (IS_ENABLED(CONFIG_SLAB_BUCKETS))
		flags |= HDN_MITIGATION_SLAB_BUCKETS;
	if (!IS_ENABLED(CONFIG_SLAB_MERGE_DEFAULT))
		flags |= HDN_MITIGATION_SLAB_MERGE_DISABLED;
	if (IS_ENABLED(CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT))
		flags |= HDN_MITIGATION_RANDOMIZE_KSTACK;
	if (IS_ENABLED(CONFIG_CFI))
		flags |= HDN_MITIGATION_CFI;
	if (IS_ENABLED(CONFIG_FINEIBT))
		flags |= HDN_MITIGATION_FINEIBT;
	if (IS_ENABLED(CONFIG_LIST_HARDENED))
		flags |= HDN_MITIGATION_LIST_HARDENED;
	if (IS_ENABLED(CONFIG_STRICT_KERNEL_RWX))
		flags |= HDN_MITIGATION_STRICT_KERNEL_RWX;
	if (IS_ENABLED(CONFIG_STRICT_MODULE_RWX))
		flags |= HDN_MITIGATION_STRICT_MODULE_RWX;
	if (IS_ENABLED(CONFIG_SECURITY_DMESG_RESTRICT))
		flags |= HDN_MITIGATION_DMESG_RESTRICT;
	if (IS_ENABLED(CONFIG_PROC_MEM_FORCE_PTRACE) ||
	    IS_ENABLED(CONFIG_PROC_MEM_NO_FORCE))
		flags |= HDN_MITIGATION_PROC_MEM_RESTRICT;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_EXPLOIT_MITIGATIONS))
		flags |= HDN_MITIGATION_KPTR_RESTRICT;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_BRUTE))
		flags |= HDN_MITIGATION_BRUTE_THROTTLE;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_KERNEL_LOCKOUT))
		flags |= HDN_MITIGATION_KERNEL_LOCKOUT;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_PROC_MEMMAP))
		flags |= HDN_MITIGATION_PROC_MEMMAP_REDACT;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_SYSVIPC))
		flags |= HDN_MITIGATION_SYSVIPC_HARDEN;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_POSIX_MQUEUE))
		flags |= HDN_MITIGATION_POSIX_MQUEUE_HARDEN;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_TTY_INJECTION))
		flags |= HDN_MITIGATION_TTY_INJECTION_HARDEN;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_FUSE_RESTRICT))
		flags |= HDN_MITIGATION_FUSE_RESTRICT;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_ROFS))
		flags |= HDN_MITIGATION_ROFS_HARDEN;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_PROC_HIDE))
		flags |= HDN_MITIGATION_PROC_HIDE;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_USB_RESTRICT))
		flags |= HDN_MITIGATION_USB_RESTRICT;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_SOCKET_RESTRICT))
		flags |= HDN_MITIGATION_SOCKET_RESTRICT;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_AUDIT_FLOOD))
		flags |= HDN_MITIGATION_AUDIT_FLOOD;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_EXEC_AUDIT))
		flags |= HDN_MITIGATION_EXEC_AUDIT;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_CHDIR_AUDIT))
		flags |= HDN_MITIGATION_CHDIR_AUDIT;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_MOUNT_AUDIT))
		flags |= HDN_MITIGATION_MOUNT_AUDIT;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_TIME_ADMIN))
		flags |= HDN_MITIGATION_TIME_ADMIN;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_TIME_AUDIT))
		flags |= HDN_MITIGATION_TIME_AUDIT;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_RESOURCE_ADMIN))
		flags |= HDN_MITIGATION_RESOURCE_ADMIN;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_RESOURCE_AUDIT))
		flags |= HDN_MITIGATION_RESOURCE_AUDIT;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_BLOCK_DEVICE_RESTRICT))
		flags |= HDN_MITIGATION_BLOCK_DEVICE_RESTRICT;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_FORK_AUDIT))
		flags |= HDN_MITIGATION_FORK_AUDIT;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_PTRACE_READEXEC))
		flags |= HDN_MITIGATION_PTRACE_READEXEC;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_PTRACE_AUDIT))
		flags |= HDN_MITIGATION_PTRACE_AUDIT;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_SETXID))
		flags |= HDN_MITIGATION_CONSISTENT_SETXID;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_MODULE_AUTOLOAD))
		flags |= HDN_MITIGATION_MODULE_AUTOLOAD;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_PROC_IPADDR))
		flags |= HDN_MITIGATION_PROC_IPADDR;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_NET_BLACKHOLE))
		flags |= HDN_MITIGATION_NET_BLACKHOLE;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_TCP_NO_SIMULT_CONNECT))
		flags |= HDN_MITIGATION_TCP_NO_SIMULT_CONNECT;
	flags |= HDN_MITIGATION_SEALED_DATA_REPORT;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_RAND_THREADSTACK))
		flags |= HDN_MITIGATION_RAND_THREADSTACK;
	if (IS_ENABLED(CONFIG_VMAP_STACK))
		flags |= HDN_MITIGATION_VMAP_STACK;
	if (IS_ENABLED(CONFIG_THREAD_INFO_IN_TASK))
		flags |= HDN_MITIGATION_THREAD_INFO_IN_TASK;
	if (IS_ENABLED(CONFIG_STACKPROTECTOR_STRONG))
		flags |= HDN_MITIGATION_STACKPROTECTOR_STRONG;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_SIGNAL_AUDIT))
		flags |= HDN_MITIGATION_SIGNAL_AUDIT;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_FORKFAIL_AUDIT))
		flags |= HDN_MITIGATION_FORKFAIL_AUDIT;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_FS_PROTECTION_AUDIT))
		flags |= HDN_MITIGATION_FS_PROTECTION_AUDIT;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_SYMLINK_OWNER))
		flags |= HDN_MITIGATION_SYMLINK_OWNER;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_RWXMAP_AUDIT))
		flags |= HDN_MITIGATION_RWXMAP_AUDIT;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_SUID_SPECTRE))
		flags |= HDN_MITIGATION_SUID_SPECTRE;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_UNPRIV_BPF))
		flags |= HDN_MITIGATION_UNPRIV_BPF_LOCKDOWN;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_UNPRIV_PERF_KERNEL))
		flags |= HDN_MITIGATION_UNPRIV_PERF_LOCKDOWN;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_UNPRIV_BPF) &&
	    IS_ENABLED(CONFIG_BPF_JIT) && IS_ENABLED(CONFIG_HAVE_EBPF_JIT))
		flags |= HDN_MITIGATION_BPF_JIT_HARDEN;

	return flags;
}

static u64 hdn_build_mitigation_flags2(void)
{
	u64 flags = 0;

	if (!IS_ENABLED(CONFIG_USERFAULTFD) ||
	    IS_ENABLED(CONFIG_SECURITY_HARDENING_USERFAULTFD_RESTRICT))
		flags |= HDN_MITIGATION2_USERFAULTFD_RESTRICT;
	if (IS_ENABLED(CONFIG_PAGE_TABLE_CHECK_ENFORCED))
		flags |= HDN_MITIGATION2_PAGE_TABLE_CHECK;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_MMAP_MIN_ADDR))
		flags |= HDN_MITIGATION2_MMAP_MIN_ADDR;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_IO_URING_SYSCTL_LOCK))
		flags |= HDN_MITIGATION2_IO_URING_SYSCTL_LOCK;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_MODULE_AUTOLOAD_PATH))
		flags |= HDN_MITIGATION2_MODULE_AUTOLOAD_PATH;
	if (IS_ENABLED(CONFIG_KEXEC_CORE) && IS_ENABLED(CONFIG_SYSCTL))
		flags |= HDN_MITIGATION2_KEXEC_LOAD_DISABLE;
	if (IS_ENABLED(CONFIG_MODULES) && IS_ENABLED(CONFIG_SYSCTL))
		flags |= HDN_MITIGATION2_MODULE_LOAD_DISABLE;
	if (IS_ENABLED(CONFIG_MODULES))
		flags |= HDN_MITIGATION2_MODULE_REQUEST_NAME;
	if (IS_ENABLED(CONFIG_MODULES))
		flags |= HDN_MITIGATION2_MODULE_AUTOLOAD_CONTEXT;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_TTY_ACCESS))
		flags |= HDN_MITIGATION2_TTY_ACCESS_HARDEN;

	return flags;
}

static bool hdn_mitigation_enabled(u64 flag)
{
	return hdn_mitigations && (hdn_mitigations->flags & flag);
}

static bool hdn_mitigation2_enabled(u64 flag)
{
	return hdn_mitigations && (hdn_mitigations->flags2 & flag);
}

static int __init hdn_mitigations_init(void)
{
	struct hdn_mitigation_state *state;
	struct hdn_seal *seal = NULL;
	int ret;

	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_KERNSEAL)) {
		seal = hdn_seal_create(&hdn_mitigation_seal_type, PAGE_SIZE, NUMA_NO_NODE);
		if (IS_ERR(seal))
			return PTR_ERR(seal);
		state = hdn_seal_write(seal, &hdn_mitigation_seal_type);
	} else {
		state = vzalloc(PAGE_SIZE);
	}
	if (!state) {
		if (seal)
			hdn_seal_destroy(seal, &hdn_mitigation_seal_type);
		return -ENOMEM;
	}

	state->seal = seal;
	state->abi_version = HDN_POLICY_ABI_VERSION;
	state->sealed_pages = 1;
	state->flags = hdn_build_mitigation_flags();
	state->flags2 = hdn_build_mitigation_flags2();
	state->sealed = true;

	if (seal) {
		ret = hdn_seal_finish(seal, &hdn_mitigation_seal_type);
		if (!ret)
			ret = hdn_seal_publish(seal, &hdn_mitigation_seal_type);
		if (ret) {
			hdn_seal_destroy(seal, &hdn_mitigation_seal_type);
			return ret;
		}
		hdn_mitigations = state;
		return 0;
	}

	set_vm_flush_reset_perms(state);
	ret = set_memory_ro((unsigned long)state, state->sealed_pages);
	if (ret) {
		if (!set_memory_rw((unsigned long)state, state->sealed_pages))
			state->sealed = false;
		vfree(state);
		return ret;
	}

	hdn_mitigations = state;
	return 0;
}

static u32 hdn_event_id_for_transition(enum hdn_transition transition)
{
	if (transition > HDN_TRANS_NONE && transition < HDN_TRANS__MAX)
		return transition;

	return HDN_EVENT_ID_NONE;
}

static void hdn_audit(enum hdn_authority authority,
		      enum hdn_transition transition,
		      enum hdn_reason reason,
		      enum hdn_decision_action action, int error)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_AUDIT))
		return;

	pr_notice_ratelimited("hardening: action=%u authority=%u transition=%u reason=%u error=%d profile=%llu pid=%d comm=%s\n",
			      action, authority, transition, reason, error,
			      (unsigned long long)hdn_mm_profile_id(current->mm),
			      task_pid_nr(current), current->comm);
}

static u64 hdn_file_object_id(const struct file *file)
{
	const struct inode *inode;

	if (!file)
		return 0;

	inode = file_inode(file);
	return inode ? inode->i_ino : 0;
}

static u64 hdn_inode_object_id(const struct inode *inode)
{
	return inode ? inode->i_ino : 0;
}

static u64 hdn_path_object_id(const struct path *path)
{
	const struct inode *inode;

	if (!path || !path->dentry)
		return 0;

	inode = d_inode(path->dentry);
	return inode ? inode->i_ino : 0;
}

static u64 hdn_vfsmount_object_id(const struct vfsmount *mnt)
{
	const struct inode *inode;

	if (!mnt || !mnt->mnt_root)
		return 0;

	inode = d_inode(mnt->mnt_root);
	return inode ? inode->i_ino : 0;
}

static u64 hdn_super_object_id(const struct super_block *sb)
{
	const struct inode *inode;

	if (!sb || !sb->s_root)
		return 0;

	inode = d_inode(sb->s_root);
	return inode ? inode->i_ino : 0;
}

static u64 hdn_string_object_id(const char *text)
{
	u64 hash = 14695981039346656037ULL;

	if (!text)
		return 0;

	while (*text) {
		hash ^= (u8)*text++;
		hash *= 1099511628211ULL;
	}

	return hash;
}

static u64 hdn_bytes_object_id(const void *data, size_t len)
{
	const u8 *bytes = data;
	u64 hash = 14695981039346656037ULL;

	while (len--) {
		hash ^= *bytes++;
		hash *= 1099511628211ULL;
	}

	return hash;
}

static u64 hdn_vma_object_id(const struct vm_area_struct *vma)
{
	if (!vma)
		return 0;
	if (vma->vm_file)
		return hdn_file_object_id(vma->vm_file);

	return vma->vm_start;
}

static bool hdn_audit_flood_key_matches(const struct hdn_audit_flood_key *key,
					const struct hdn_event *event)
{
	return key->profile_id == event->profile_id &&
	       key->action == event->action &&
	       key->authority == event->authority &&
	       key->transition == event->transition &&
	       key->reason == event->reason &&
	       key->error == event->error;
}

static void hdn_audit_flood_set_key(struct hdn_audit_flood_key *key,
				    const struct hdn_event *event)
{
	key->profile_id = event->profile_id;
	key->action = event->action;
	key->authority = event->authority;
	key->transition = event->transition;
	key->reason = event->reason;
	key->error = event->error;
}

static void hdn_audit_flood_reset_bucket(struct hdn_audit_flood_bucket *bucket,
					 const struct hdn_event *event,
					 u64 now_ns)
{
	bucket->used = true;
	hdn_audit_flood_set_key(&bucket->key, event);
	bucket->window_start_ns = now_ns;
	bucket->last_seen_ns = now_ns;
	bucket->count = 1;
	bucket->suppressed = 0;
}

static u64 hdn_current_chroot_event_flags(void)
{
	if (!current->fs || !current->nsproxy || !current->nsproxy->mnt_ns)
		return 0;
	if (!current_chrooted())
		return 0;

	return HDN_EVENT_CHROOTED;
}

static bool hdn_audit_flood_allowed_locked(const struct hdn_event *event,
					   u64 now_ns)
{
	struct hdn_audit_flood_bucket *candidate = NULL;
	struct hdn_audit_flood_bucket *oldest = &hdn_audit_flood_buckets[0];
	u64 window_ns;
	u32 burst;
	u32 i;

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_AUDIT_FLOOD))
		return true;

	window_ns = READ_ONCE(hdn_audit_flood_window_ns);
	burst = READ_ONCE(hdn_audit_flood_burst);

	for (i = 0; i < HDN_AUDIT_FLOOD_BUCKET_COUNT; i++) {
		struct hdn_audit_flood_bucket *bucket =
			&hdn_audit_flood_buckets[i];

		if (!bucket->used) {
			if (!candidate)
				candidate = bucket;
			continue;
		}

		if (hdn_audit_flood_key_matches(&bucket->key, event)) {
			if (now_ns < bucket->window_start_ns ||
			    now_ns - bucket->window_start_ns >=
			    window_ns) {
				hdn_audit_flood_reset_bucket(bucket, event,
							     now_ns);
				return true;
			}

			bucket->last_seen_ns = now_ns;
			if (bucket->count < burst) {
				bucket->count++;
				return true;
			}

			bucket->suppressed++;
			hdn_audit_flood_suppressed_total++;
			hdn_audit_flood_last_action = event->action;
			hdn_audit_flood_last_authority = event->authority;
			hdn_audit_flood_last_transition = event->transition;
			hdn_audit_flood_last_reason = event->reason;
			return false;
		}

		if (!candidate && bucket->last_seen_ns < oldest->last_seen_ns)
			oldest = bucket;
	}

	if (!candidate)
		candidate = oldest;
	hdn_audit_flood_reset_bucket(candidate, event, now_ns);
	return true;
}

static bool hdn_record_event_object_flags(enum hdn_authority authority,
					  enum hdn_transition transition,
					  enum hdn_reason reason,
					  enum hdn_decision_action action,
					  int error, u64 object_id,
					  u64 event_flags)
{
	struct hdn_event event = {
		.abi_version = HDN_POLICY_ABI_VERSION,
		.event_id = hdn_event_id_for_transition(transition),
		.action = action,
		.authority = authority,
		.transition = transition,
		.reason = reason,
		.error = error,
		.pid = task_pid_nr(current),
		.uid = from_kuid_munged(&init_user_ns, current_uid()),
		.timestamp_ns = ktime_get_real_ns(),
		.profile_id = hdn_mm_profile_id(current->mm),
		.subject_id = task_pid_nr(current),
		.object_id = object_id,
		.flags = event_flags,
	};
	unsigned long flags;
	u64 now_ns = ktime_get_ns();
	u64 sequence;
	bool recorded = true;

	if (event_flags & HDN_EVENT_DEFERRED_KERNEL) {
		event.pid = 0;
		event.uid = 0;
		event.profile_id = 0;
		event.subject_id = 0;
	}

	spin_lock_irqsave(&hdn_event_lock, flags);
	if (!hdn_audit_flood_allowed_locked(&event, now_ns)) {
		recorded = false;
		goto out_unlock;
	}

	sequence = hdn_event_sequence++;
	event.sequence = sequence;
	hdn_events[sequence % HDN_EVENT_RING_SIZE] = event;
out_unlock:
	spin_unlock_irqrestore(&hdn_event_lock, flags);
	if (recorded)
		wake_up_interruptible(&hdn_event_wait);

	return recorded;
}

static bool hdn_record_event_flags(enum hdn_authority authority,
				   enum hdn_transition transition,
				   enum hdn_reason reason,
				   enum hdn_decision_action action, int error,
				   u64 event_flags)
{
	return hdn_record_event_object_flags(authority, transition, reason,
					     action, error, 0, event_flags);
}

static bool hdn_record_event(enum hdn_authority authority,
			     enum hdn_transition transition,
			     enum hdn_reason reason,
			     enum hdn_decision_action action, int error)
{
	return hdn_record_event_flags(authority, transition, reason, action,
				      error, 0);
}

static bool hdn_reason_is_memory(enum hdn_reason reason)
{
	return reason == HDN_REASON_USER_WX_MAPPING ||
	       reason == HDN_REASON_EXEC_AFTER_WRITE ||
	       reason == HDN_REASON_FIXED_ANON_EXEC_MAPPING ||
	       reason == HDN_REASON_READ_IMPLIES_EXEC ||
	       reason == HDN_REASON_EXEC_STACK_ELF ||
	       reason == HDN_REASON_TEXTREL_MPROTECT ||
	       reason == HDN_REASON_RELRO_WRITE;
}

static bool hdn_authority_is_kernel_surface(enum hdn_authority authority)
{
	switch (authority) {
	case HDN_AUTH_BPF_LOAD:
	case HDN_AUTH_PERF_OPEN:
	case HDN_AUTH_USERNS_CREATE:
	case HDN_AUTH_MODULE_LOAD:
	case HDN_AUTH_MODULE_AUTOLOAD:
	case HDN_AUTH_PTRACE:
	case HDN_AUTH_PTRACE_EXEC_READ:
	case HDN_AUTH_PROCESS_MEMORY:
	case HDN_AUTH_MEMORY_MIGRATE:
	case HDN_AUTH_PROCESS_FD:
	case HDN_AUTH_PROC_DISCLOSE:
	case HDN_AUTH_DEBUGFS:
	case HDN_AUTH_SYSFS_MUTATE:
	case HDN_AUTH_SYSFS_READ:
	case HDN_AUTH_KEXEC_LOAD:
	case HDN_AUTH_FIRMWARE_LOAD:
	case HDN_AUTH_IO_URING_RESTRICTED_OP:
	case HDN_AUTH_KERNEL_LOG_READ:
	case HDN_AUTH_KERNEL_LOG_WRITE:
	case HDN_AUTH_RAW_IO:
	case HDN_AUTH_MOUNT_ADMIN:
	case HDN_AUTH_NAMESPACE_ADMIN:
	case HDN_AUTH_CHROOT_ADMIN:
	case HDN_AUTH_IPC_ADMIN:
	case HDN_AUTH_TTY_INJECT:
	case HDN_AUTH_TTY_ACCESS:
	case HDN_AUTH_FUSE_MOUNT:
	case HDN_AUTH_ROFS_RELAX:
	case HDN_AUTH_USB_ATTACH:
	case HDN_AUTH_USB_MONITOR:
	case HDN_AUTH_SOCKET_CREATE:
	case HDN_AUTH_SOCKET_CONNECT:
	case HDN_AUTH_SOCKET_SERVER:
	case HDN_AUTH_TIME_ADMIN:
	case HDN_AUTH_RESOURCE_ADMIN:
	case HDN_AUTH_BLOCK_DEVICE_ACCESS:
	case HDN_AUTH_BLOCK_DEVICE_ADMIN:
		return true;
	default:
		return false;
	}
}

static u64 hdn_profile_flags(u64 profile_id)
{
	const struct hdn_profile_record *profile;
	u64 flags;

	rcu_read_lock();
	profile = hdn_profile_by_id(profile_id);
	flags = profile->flags;
	rcu_read_unlock();

	return flags;
}

static u64 hdn_current_profile_flags(void)
{
	return hdn_profile_flags(hdn_current_profile_id());
}

static u16 hdn_profile_max_userns_level(u64 profile_id)
{
	const struct hdn_profile_record *profile;
	u16 level;

	rcu_read_lock();
	profile = hdn_profile_by_id(profile_id);
	level = profile->max_userns_level;
	rcu_read_unlock();

	return level;
}

static bool hdn_deny_should_kill(enum hdn_authority authority,
				 enum hdn_reason reason)
{
	u64 flags = hdn_current_profile_flags();

	if (flags & HDN_PROFILE_RESPONSE_KILL_DENY)
		return true;
	if ((flags & HDN_PROFILE_RESPONSE_KILL_MEMORY) &&
	    hdn_reason_is_memory(reason))
		return true;
	if ((flags & HDN_PROFILE_RESPONSE_KILL_KERNEL_SURFACE) &&
	    hdn_authority_is_kernel_surface(authority))
		return true;

	return false;
}

static void hdn_apply_response(bool kill)
{
	if (!kill || !current->mm || (current->flags & PF_KTHREAD))
		return;

	send_sig(SIGKILL, current, 0);
}

static int hdn_deny_object(enum hdn_authority authority,
			   enum hdn_transition transition,
			   enum hdn_reason reason, int error, u64 object_id)
{
	bool kill = hdn_deny_should_kill(authority, reason);
	u64 flags = kill ? HDN_EVENT_RESPONSE_KILL_TASK : 0;

	if (current->mm && READ_ONCE(current->mm->hardening_compat_revoked))
		reason = HDN_REASON_APPLICATION_RESTART_REQUIRED;
	if (hdn_record_event_object_flags(authority, transition, reason,
					  HDN_DECISION_DENY_AUDIT, error,
					  object_id, flags))
		hdn_audit(authority, transition, reason,
			  HDN_DECISION_DENY_AUDIT, error);
	hdn_apply_response(kill);
	return error;
}

static int hdn_deny(enum hdn_authority authority,
		    enum hdn_transition transition,
		    enum hdn_reason reason, int error)
{
	return hdn_deny_object(authority, transition, reason, error, 0);
}

static u64 hdn_uid_object_id(kuid_t uid)
{
	return from_kuid_munged(&init_user_ns, uid);
}

static bool hdn_kernel_lockout_uid_banned(kuid_t uid)
{
	unsigned long flags;
	bool banned = false;
	int i;

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_KERNEL_LOCKOUT))
		return false;
	if (!uid_valid(uid))
		return false;

	spin_lock_irqsave(&hdn_kernel_lockout_lock, flags);
	for (i = 0; i < ARRAY_SIZE(hdn_kernel_lockout_records); i++) {
		if (hdn_kernel_lockout_records[i].used &&
		    uid_eq(hdn_kernel_lockout_records[i].uid, uid)) {
			banned = true;
			break;
		}
	}
	spin_unlock_irqrestore(&hdn_kernel_lockout_lock, flags);

	return banned;
}

static unsigned int hdn_kernel_lockout_count(void)
{
	unsigned long flags;
	unsigned int count = 0;
	int i;

	spin_lock_irqsave(&hdn_kernel_lockout_lock, flags);
	for (i = 0; i < ARRAY_SIZE(hdn_kernel_lockout_records); i++) {
		if (hdn_kernel_lockout_records[i].used)
			count++;
	}
	spin_unlock_irqrestore(&hdn_kernel_lockout_lock, flags);

	return count;
}

static int hdn_kernel_lockout_add_uid(kuid_t uid)
{
	unsigned long flags;
	int empty = -1;
	int i;

	if (!uid_valid(uid))
		return -EINVAL;

	spin_lock_irqsave(&hdn_kernel_lockout_lock, flags);
	for (i = 0; i < ARRAY_SIZE(hdn_kernel_lockout_records); i++) {
		if (hdn_kernel_lockout_records[i].used) {
			if (uid_eq(hdn_kernel_lockout_records[i].uid, uid)) {
				spin_unlock_irqrestore(&hdn_kernel_lockout_lock,
						       flags);
				return 0;
			}
			continue;
		}
		if (empty < 0)
			empty = i;
	}

	if (empty >= 0) {
		hdn_kernel_lockout_records[empty].used = true;
		hdn_kernel_lockout_records[empty].uid = uid;
	}
	spin_unlock_irqrestore(&hdn_kernel_lockout_lock, flags);

	return empty >= 0 ? 0 : -ENOSPC;
}

static void hdn_kernel_lockout_kill_uid(kuid_t uid)
{
	struct task_struct *g;
	struct task_struct *t;

	read_lock(&tasklist_lock);
	for_each_process_thread(g, t) {
		if (uid_eq(task_uid(t), uid))
			send_sig(SIGKILL, t, 0);
	}
	read_unlock(&tasklist_lock);
}

static int hdn_kernel_lockout_ban_uid(kuid_t uid)
{
	int ret;

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_KERNEL_LOCKOUT))
		return 0;
	if (!uid_valid(uid))
		return -EINVAL;
	if (uid_eq(uid, GLOBAL_ROOT_UID))
		return -EPERM;

	ret = hdn_kernel_lockout_add_uid(uid);
	if (ret)
		return ret;

	hdn_record_event_object_flags(HDN_AUTH_NONE, HDN_TRANS_KERNEL_LOCKOUT,
				      HDN_REASON_KERNEL_LOCKOUT,
				      HDN_DECISION_ALLOW_AUDIT, 0,
				      hdn_uid_object_id(uid), 0);
	hdn_kernel_lockout_kill_uid(uid);
	return 0;
}

static kuid_t hdn_kernel_lockout_cred_uid(const struct cred *cred)
{
	if (hdn_kernel_lockout_uid_banned(cred->uid))
		return cred->uid;
	if (hdn_kernel_lockout_uid_banned(cred->euid))
		return cred->euid;
	if (hdn_kernel_lockout_uid_banned(cred->suid))
		return cred->suid;
	if (hdn_kernel_lockout_uid_banned(cred->fsuid))
		return cred->fsuid;

	return INVALID_UID;
}

static int hdn_kernel_lockout_deny(enum hdn_transition transition, kuid_t uid)
{
	return hdn_deny_object(HDN_AUTH_NONE, transition,
			       HDN_REASON_KERNEL_LOCKOUT, -EPERM,
			       hdn_uid_object_id(uid));
}

int hdn_kernel_lockout_check_fork(void)
{
	kuid_t uid = current_uid();

	if (!hdn_kernel_lockout_uid_banned(uid))
		return 0;

	return hdn_kernel_lockout_deny(HDN_TRANS_FORK, uid);
}

void hdn_report_kernel_lockout(void)
{
	kuid_t uid;

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_KERNEL_LOCKOUT))
		return;

	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_KERNEL_LOCKOUT_PANIC)) {
		if (in_interrupt())
			panic("HDN: kernel-surface fault in interrupt context");
		if (uid_eq(current_uid(), GLOBAL_ROOT_UID))
			panic("HDN: kernel-surface fault from root-owned task");
	}

	/*
	 * Faults from interrupt context or root-owned tasks cannot be pinned to
	 * a bannable unprivileged uid. Without the opt-in panic above, let the
	 * normal oops path handle them (the faulting task is already being torn
	 * down) instead of taking the whole machine down.
	 */
	if (in_interrupt())
		return;

	uid = current_uid();
	if (uid_eq(uid, GLOBAL_ROOT_UID))
		return;

	hdn_kernel_lockout_ban_uid(uid);
}

static void hdn_rewrite_object(enum hdn_authority authority,
			       enum hdn_transition transition,
			       enum hdn_reason reason, u64 object_id)
{
	if (hdn_record_event_object_flags(authority, transition, reason,
					  HDN_DECISION_REWRITE, 0,
					  object_id, 0))
		hdn_audit(authority, transition, reason,
			  HDN_DECISION_REWRITE, 0);
}

static void hdn_record_rwxmap_denial(enum hdn_authority authority,
				     enum hdn_transition transition,
				     u64 object_id)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_RWXMAP_AUDIT))
		return;

	hdn_record_event_object_flags(authority, transition,
				      HDN_REASON_RWXMAP_DENIED,
				      HDN_DECISION_DENY_AUDIT, -EACCES,
				      object_id, 0);
}

#ifndef DT_FLAGS
#define DT_FLAGS 30
#endif

#ifndef DF_TEXTREL
#define DF_TEXTREL 0x00000004
#endif

#if ELF_CLASS == ELFCLASS32
typedef Elf32_Dyn hdn_elf_dyn;
#else
typedef Elf64_Dyn hdn_elf_dyn;
#endif

#define HDN_ELF_NOTE_MAX_SCAN 65536
#define HDN_ELF_NOTE_VALID_MEMORY_FLAGS \
	(HDN_MEM_ALLOW_JIT_EXEC_AFTER_WRITE | \
	 HDN_MEM_ALLOW_EXEC_STACK_ELF | \
	 HDN_MEM_ALLOW_TEXTREL_MPROTECT)

static bool hdn_file_read_exact(struct file *file, u64 offset,
				void *buf, size_t size)
{
	loff_t pos;

	if (offset > LLONG_MAX)
		return false;

	pos = offset;
	return kernel_read(file, buf, size, &pos) == size;
}

static bool hdn_note_add_aligned(u64 base, u32 size, u64 *out)
{
	u64 aligned;

	if (check_add_overflow((u64)size, 3ULL, &aligned))
		return false;
	aligned &= ~3ULL;

	return !check_add_overflow(base, aligned, out);
}

static bool hdn_file_trusted_for_elf_memory_note(struct file *file)
{
	const struct inode *inode;

	if (!file)
		return false;

	inode = file_inode(file);
	if (!inode || !S_ISREG(inode->i_mode))
		return false;
	if (!uid_eq(inode->i_uid, GLOBAL_ROOT_UID))
		return false;
	if (inode->i_mode & 0022)
		return false;

	return true;
}

static u64 hdn_elf_memory_flags_from_note_segment(struct file *file,
						 const struct elf_phdr *phdr)
{
	u64 flags = 0;
	u64 offset = 0;
	u64 next;
	u64 name_offset;
	u64 desc_offset;

	if (!phdr->p_filesz || phdr->p_filesz > HDN_ELF_NOTE_MAX_SCAN)
		return 0;

	while (offset + sizeof(struct elf_note) <= phdr->p_filesz) {
		struct hdn_elf_memory_note note;
		struct elf_note nhdr;
		char name[HDN_ELF_NOTE_NAME_SIZE];

		if (check_add_overflow((u64)phdr->p_offset, offset,
				       &name_offset))
			break;
		if (!hdn_file_read_exact(file, name_offset, &nhdr,
					 sizeof(nhdr)))
			break;

		if (check_add_overflow(offset, (u64)sizeof(nhdr), &next))
			break;
		name_offset = next;
		if (!hdn_note_add_aligned(next, nhdr.n_namesz, &desc_offset))
			break;
		if (!hdn_note_add_aligned(desc_offset, nhdr.n_descsz, &next))
			break;
		if (next > phdr->p_filesz || next <= offset)
			break;

		if (nhdr.n_type == HDN_ELF_NOTE_MEMORY_TYPE &&
		    nhdr.n_namesz == HDN_ELF_NOTE_NAME_SIZE &&
		    nhdr.n_descsz >= sizeof(note)) {
			if (check_add_overflow((u64)phdr->p_offset,
					       name_offset, &name_offset))
				break;
			if (check_add_overflow((u64)phdr->p_offset,
					       desc_offset, &desc_offset))
				break;
			if (!hdn_file_read_exact(file, name_offset, name,
						 sizeof(name)))
				break;
			if (!memcmp(name, HDN_ELF_NOTE_NAME,
				    HDN_ELF_NOTE_NAME_SIZE) &&
			    hdn_file_read_exact(file, desc_offset, &note,
						sizeof(note)) &&
			    note.abi_version == HDN_ELF_NOTE_MEMORY_ABI_VERSION &&
			    !note.reserved)
				flags |= note.memory_flags &
					 HDN_ELF_NOTE_VALID_MEMORY_FLAGS;
		}

		offset = next;
	}

	return flags;
}

static bool hdn_file_has_executable_gnu_stack(struct file *file)
{
	struct elf_phdr phdr;
	struct elfhdr ehdr;
	const struct inode *inode;
	unsigned long i;
	loff_t pos;

	if (!file)
		return false;

	inode = file_inode(file);
	if (!inode || !S_ISREG(inode->i_mode))
		return false;

	pos = 0;
	if (kernel_read(file, &ehdr, sizeof(ehdr), &pos) != sizeof(ehdr))
		return false;
	if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG))
		return false;
	if (ehdr.e_type != ET_DYN && ehdr.e_type != ET_EXEC)
		return false;
	if (!elf_check_arch(&ehdr))
		return false;
	if (ehdr.e_phentsize != sizeof(struct elf_phdr))
		return false;
	if (!ehdr.e_phnum ||
	    ehdr.e_phnum > 65536UL / sizeof(struct elf_phdr))
		return false;

	for (i = 0; i < ehdr.e_phnum; i++) {
		pos = ehdr.e_phoff + i * sizeof(phdr);
		if (kernel_read(file, &phdr, sizeof(phdr), &pos) !=
		    sizeof(phdr))
			return false;
		if (phdr.p_type == PT_GNU_STACK && (phdr.p_flags & PF_X))
			return true;
	}

	return false;
}

static u64 hdn_file_elf_memory_flags(struct file *file)
{
	struct elf_phdr phdr;
	struct elfhdr ehdr;
	unsigned long i;
	loff_t pos;
	u64 flags = 0;

	if (!hdn_file_trusted_for_elf_memory_note(file))
		return 0;

	pos = 0;
	if (kernel_read(file, &ehdr, sizeof(ehdr), &pos) != sizeof(ehdr))
		return 0;
	if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG))
		return 0;
	if (ehdr.e_type != ET_DYN && ehdr.e_type != ET_EXEC)
		return 0;
	if (!elf_check_arch(&ehdr))
		return 0;
	if (ehdr.e_phentsize != sizeof(struct elf_phdr))
		return 0;
	if (!ehdr.e_phnum ||
	    ehdr.e_phnum > 65536UL / sizeof(struct elf_phdr))
		return 0;

	for (i = 0; i < ehdr.e_phnum; i++) {
		pos = ehdr.e_phoff + i * sizeof(phdr);
		if (kernel_read(file, &phdr, sizeof(phdr), &pos) !=
		    sizeof(phdr))
			return flags;
		if (phdr.p_type == PT_NOTE)
			flags |= hdn_elf_memory_flags_from_note_segment(file,
								       &phdr);
	}

	return flags;
}

static bool hdn_dynamic_section_has_textrel(struct file *file,
					    const struct elf_phdr *phdr)
{
	hdn_elf_dyn dyn;
	unsigned long i;
	unsigned long entries;
	u64 dyn_pos;
	loff_t pos;

	if (!phdr->p_filesz || phdr->p_filesz > 65536 ||
	    phdr->p_filesz < sizeof(dyn))
		return false;

	entries = phdr->p_filesz / sizeof(dyn);
	for (i = 0; i < entries; i++) {
		if (check_mul_overflow((u64)i, (u64)sizeof(dyn), &dyn_pos))
			return false;
		if (check_add_overflow((u64)phdr->p_offset, dyn_pos,
				       &dyn_pos))
			return false;
		if (dyn_pos > LLONG_MAX)
			return false;

		pos = dyn_pos;
		if (kernel_read(file, &dyn, sizeof(dyn), &pos) != sizeof(dyn))
			return false;
		if (dyn.d_tag == DT_NULL)
			return false;
		if (dyn.d_tag == DT_TEXTREL)
			return true;
		if (dyn.d_tag == DT_FLAGS && (dyn.d_un.d_val & DF_TEXTREL))
			return true;
	}

	return false;
}

static bool hdn_file_has_textrel_dynamic(struct file *file)
{
	struct elf_phdr phdr;
	struct elfhdr ehdr;
	const struct inode *inode;
	unsigned long i;
	loff_t pos;

	if (!file)
		return false;

	inode = file_inode(file);
	if (!inode || !S_ISREG(inode->i_mode))
		return false;

	pos = 0;
	if (kernel_read(file, &ehdr, sizeof(ehdr), &pos) != sizeof(ehdr))
		return false;
	if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG))
		return false;
	if (ehdr.e_type != ET_DYN)
		return false;
	if (!elf_check_arch(&ehdr))
		return false;
	if (ehdr.e_phentsize != sizeof(struct elf_phdr))
		return false;
	if (!ehdr.e_phnum ||
	    ehdr.e_phnum > 65536UL / sizeof(struct elf_phdr))
		return false;

	for (i = 0; i < ehdr.e_phnum; i++) {
		pos = ehdr.e_phoff + i * sizeof(phdr);
		if (kernel_read(file, &phdr, sizeof(phdr), &pos) !=
		    sizeof(phdr))
			return false;
		if (phdr.p_type == PT_DYNAMIC &&
		    hdn_dynamic_section_has_textrel(file, &phdr))
			return true;
	}

	return false;
}

static bool hdn_mprotect_is_textrel(const struct hdn_mprotect_request *req)
{
	bool adds_write;
	bool adds_exec;

	if (!req->vma || !req->vma->vm_file)
		return false;

	adds_write = !(req->oldflags & VM_WRITE) && (req->newflags & VM_WRITE);
	adds_exec = !(req->oldflags & VM_EXEC) && (req->newflags & VM_EXEC);
	if ((!adds_write || !(req->oldflags & VM_EXEC)) &&
	    (!adds_exec || !(req->oldflags & VM_WRITE)))
		return false;

	return hdn_file_has_textrel_dynamic(req->vma->vm_file);
}

static bool hdn_relro_segment_range(const struct elf_phdr *phdr,
				    u64 *file_offset, u64 *length)
{
	u64 aligned_end;
	u64 segment_end;
	u64 segment_start;
	u64 page_mask = ~((u64)PAGE_SIZE - 1);

	if (!phdr->p_memsz ||
	    (phdr->p_offset & ~page_mask) != (phdr->p_vaddr & ~page_mask))
		return false;
	if (check_add_overflow((u64)phdr->p_vaddr, (u64)phdr->p_memsz,
			       &segment_end) ||
	    check_add_overflow(segment_end, (u64)PAGE_SIZE - 1,
			       &aligned_end))
		return false;

	segment_start = (u64)phdr->p_vaddr & page_mask;
	segment_end = aligned_end & page_mask;
	if (segment_end <= segment_start)
		return false;

	*file_offset = (u64)phdr->p_offset & page_mask;
	*length = segment_end - segment_start;
	return true;
}

static bool hdn_mprotect_targets_relro(const struct hdn_mprotect_request *req)
{
	struct elf_phdr phdr;
	struct elfhdr ehdr;
	const struct inode *inode;
	struct file *file;
	u64 request_offset;
	u64 request_length;
	u64 vma_offset;
	unsigned long i;
	loff_t pos;

	if (!req->vma || !req->vma->vm_file || req->start >= req->end ||
	    req->start < req->vma->vm_start || req->end > req->vma->vm_end ||
	    (req->oldflags & VM_SHARED))
		return false;

	file = req->vma->vm_file;
	inode = file_inode(file);
	if (!inode || !S_ISREG(inode->i_mode))
		return false;
	if (check_mul_overflow((u64)req->vma->vm_pgoff, (u64)PAGE_SIZE,
			       &vma_offset) ||
	    check_add_overflow(vma_offset,
			       (u64)(req->start - req->vma->vm_start),
			       &request_offset))
		return false;
	request_length = req->end - req->start;

	pos = 0;
	if (kernel_read(file, &ehdr, sizeof(ehdr), &pos) != sizeof(ehdr) ||
	    memcmp(ehdr.e_ident, ELFMAG, SELFMAG) ||
	    (ehdr.e_type != ET_DYN && ehdr.e_type != ET_EXEC) ||
	    !elf_check_arch(&ehdr) ||
	    ehdr.e_phentsize != sizeof(struct elf_phdr) ||
	    !ehdr.e_phnum ||
	    ehdr.e_phnum > 65536UL / sizeof(struct elf_phdr))
		return false;

	for (i = 0; i < ehdr.e_phnum; i++) {
		u64 relro_length;
		u64 relro_offset;

		pos = ehdr.e_phoff + i * sizeof(phdr);
		if (kernel_read(file, &phdr, sizeof(phdr), &pos) !=
		    sizeof(phdr))
			return false;
		if (phdr.p_type != PT_GNU_RELRO ||
		    !hdn_relro_segment_range(&phdr, &relro_offset,
					     &relro_length))
			continue;
		if (request_offset == relro_offset &&
		    request_length == relro_length)
			return true;
	}

	return false;
}

static void hdn_record_textrel_mprotect(const struct hdn_mprotect_request *req,
					enum hdn_decision_action action,
					int error)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_RWXMAP_AUDIT))
		return;
	if (!hdn_mprotect_is_textrel(req))
		return;

	hdn_record_event_object_flags(HDN_AUTH_MPROTECT, HDN_TRANS_MPROTECT,
				      HDN_REASON_TEXTREL_MPROTECT,
				      action, error,
				      hdn_vma_object_id(req->vma), 0);
}

static void hdn_allow_audit(enum hdn_authority authority,
			    enum hdn_transition transition)
{
	if (hdn_record_event(authority, transition, HDN_REASON_NONE,
			     HDN_DECISION_ALLOW_AUDIT, 0))
		hdn_audit(authority, transition, HDN_REASON_NONE,
			  HDN_DECISION_ALLOW_AUDIT, 0);
}

static const char *hdn_phase_name(enum hdn_phase phase)
{
	if (phase < HDN_PHASE__MAX && hdn_phase_names[phase])
		return hdn_phase_names[phase];

	return "unknown";
}

static bool hdn_policy_mutable_phase(enum hdn_phase phase)
{
	return phase == HDN_PHASE_POLICY_LOAD || phase == HDN_PHASE_RECOVERY;
}

static bool hdn_phase_can_transition(enum hdn_phase old, enum hdn_phase new)
{
	if (old == new)
		return true;

	switch (old) {
	case HDN_PHASE_BOOT:
		return new == HDN_PHASE_INIT ||
		       new == HDN_PHASE_POLICY_LOAD ||
		       new == HDN_PHASE_RECOVERY;
	case HDN_PHASE_INIT:
		return new == HDN_PHASE_POLICY_LOAD ||
		       new == HDN_PHASE_RECOVERY;
	case HDN_PHASE_POLICY_LOAD:
		return new == HDN_PHASE_RUNTIME ||
		       new == HDN_PHASE_RECOVERY;
	case HDN_PHASE_RUNTIME:
		return new == HDN_PHASE_RECOVERY;
	case HDN_PHASE_RECOVERY:
		return new == HDN_PHASE_RUNTIME;
	default:
		return false;
	}
}

static int hdn_parse_phase(char *buf, enum hdn_phase *phase)
{
	unsigned int value;
	char *name;
	int ret;
	int i;

	name = strim(buf);
	for (i = 0; i < HDN_PHASE__MAX; i++) {
		if (hdn_phase_names[i] && sysfs_streq(name, hdn_phase_names[i])) {
			*phase = i;
			return 0;
		}
	}

	ret = kstrtouint(name, 0, &value);
	if (ret)
		return ret;
	if (value >= HDN_PHASE__MAX)
		return -EINVAL;

	*phase = value;
	return 0;
}

static const struct hdn_profile_record *hdn_builtin_profile(u64 profile_id)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(hdn_builtin_profiles); i++) {
		if (hdn_builtin_profiles[i].profile_id == profile_id)
			return &hdn_builtin_profiles[i];
	}

	return &hdn_builtin_profiles[0];
}

static const struct hdn_profile_record hdn_revoked_profile = {
	.profile_id = HDN_PROFILE_REVOKED,
	.name = "application-restart-required",
	.capability_deny = ~0ULL,
	.umask = 0777,
	.flags = HDN_PROFILE_SYSFS_MASK | HDN_PROFILE_ENFORCE_TRUSTED_EXEC |
		 HDN_PROFILE_DENY_UNPRIVILEGED_PRIVEXEC |
		 HDN_PROFILE_DENY_UNTRUSTED_USER_EXEC | HDN_PROFILE_CHROOT_CONTAINED |
		 HDN_PROFILE_ENFORCE_READONLY_MOUNTS | HDN_PROFILE_PROTECT_SHM,
};

/* No allocation or name lookup: usable inside the policy's RCU read section. */
static bool hdn_compat_path_matches(struct file *file, const char *expected)
{
	char buffer[HDN_POLICY_PATH_LEN];
	char *path;

	if (!file || d_unlinked(file->f_path.dentry))
		return false;
	path = d_absolute_path(&file->f_path, buffer, sizeof(buffer));
	return !IS_ERR(path) && !strcmp(path, expected);
}

static bool hdn_mm_compat_valid(const struct mm_struct *mm)
{
	struct file *file;
	struct inode *inode;
	u64 epoch;
	bool valid;

	if (!mm)
		return true;
	epoch = smp_load_acquire(&mm->hardening_compat_epoch);
	if (!epoch)
		return true;
	/* Interrupt diagnostics cannot walk a path whose writer they interrupted. */
	if (in_interrupt())
		return false;
	if (READ_ONCE(mm->hardening_compat_revoked))
		return false;
	if (epoch != atomic64_read(&hdn_policy_epoch))
		goto revoke;
	file = get_mm_exe_file((struct mm_struct *)mm);
	if (!file)
		goto revoke;
	inode = file_inode(file);
	valid = IS_VERITY(inode) &&
		inode->i_ino == READ_ONCE(mm->hardening_exec_ino) &&
		MAJOR(inode->i_sb->s_dev) == READ_ONCE(mm->hardening_exec_dev_major) &&
		MINOR(inode->i_sb->s_dev) == READ_ONCE(mm->hardening_exec_dev_minor) &&
		hdn_compat_path_matches(file, mm->hardening_compat_path);
	fput(file);
	if (valid && epoch == atomic64_read(&hdn_policy_epoch))
		return true;
revoke:
	/* Never revive a binding after rollback or a later matching rename. */
	WRITE_ONCE(((struct mm_struct *)mm)->hardening_compat_revoked, true);
	return false;
}

static const struct hdn_profile_record *
hdn_policy_find_profile(const struct hdn_policy *policy, u64 profile_id)
{
	u32 i;

	if (profile_id == HDN_PROFILE_REVOKED ||
	    (current->mm &&
	     profile_id == READ_ONCE(current->mm->hardening_profile_id) &&
	     !hdn_mm_compat_valid(current->mm)))
		return &hdn_revoked_profile;

	if (!policy)
		return hdn_builtin_profile(profile_id);

	for (i = 0; i < policy->profile_count; i++) {
		if (policy->profiles[i].profile_id == profile_id)
			return &policy->profiles[i];
	}

	return hdn_builtin_profile(HDN_PROFILE_DEFAULT);
}

u64 hdn_current_profile_id(void)
{
	struct mm_struct *mm = current->mm;

	if (!mm)
		return HDN_PROFILE_PRIVILEGED;

	return hdn_mm_profile_id(mm);
}

static const struct hdn_profile_record *hdn_profile_by_id(u64 profile_id)
{
	struct hdn_policy *policy;

	policy = rcu_dereference(hdn_active_policy);
	return hdn_policy_find_profile(policy, profile_id);
}

#ifdef CONFIG_SECURITY_HARDENING_SYSFS_VIEW
static u64 hdn_sysfs_profile_mask(const struct hdn_policy *policy, u64 id)
{
	const struct hdn_profile_record *profile = hdn_policy_find_profile(policy, id);

	/* Removing a profile must not turn its surviving tasks into base services. */
	if (id && profile->profile_id != id)
		return HDN_PROFILE_SYSFS_MASK;
	return profile->flags & HDN_PROFILE_SYSFS_MASK;
}

u64 hdn_sysfs_hidden_classes(void)
{
	const struct hdn_policy *policy;
	u64 mask;

	if (!current->mm)
		return 0;
	/* One policy generation, no dentry, opener-credential or path cache. */
	rcu_read_lock();
	policy = rcu_dereference(hdn_active_policy);
	mask = hdn_sysfs_profile_mask(policy, hdn_current_profile_id());
	mask |= hdn_sysfs_profile_mask(policy, hdn_current_mntns_profile_id());
	mask |= hdn_sysfs_profile_mask(policy,
				       hdn_userns_profile_id(current_user_ns()));
	rcu_read_unlock();
	return mask;
}
#endif

int hdn_current_umask(void)
{
	const struct hdn_profile_record *profile;
	int mask;

	rcu_read_lock();
	profile = hdn_profile_by_id(hdn_current_profile_id());
	mask = profile->umask & 0777;
	rcu_read_unlock();

	return mask;
}
EXPORT_SYMBOL_GPL(hdn_current_umask);

static bool hdn_authority_valid(enum hdn_authority authority)
{
	return authority < HDN_AUTH__MAX &&
	       authority < HDN_AUTHORITY_MAX_BITS;
}

static bool hdn_authority_word_contains(u64 low, u64 high,
					enum hdn_authority authority)
{
	if (!hdn_authority_valid(authority))
		return false;
	if (HDN_AUTHORITY_WORD(authority) == 0)
		return low & HDN_AUTHORITY_MASK(authority);
	if (HDN_AUTHORITY_WORD(authority) == 1)
		return high & HDN_AUTHORITY_MASK(authority);
	return false;
}

static u64 hdn_valid_authority_low_mask(void)
{
	if (HDN_AUTH__MAX >= HDN_AUTHORITY_WORD_BITS)
		return ~0ULL;
	return HDN_AUTHORITY_MASK(HDN_AUTH__MAX) - 1;
}

static u64 hdn_valid_authority_high_mask(void)
{
	unsigned int high_bits;

	if (HDN_AUTH__MAX <= HDN_AUTHORITY_WORD_BITS)
		return 0;

	high_bits = HDN_AUTH__MAX - HDN_AUTHORITY_WORD_BITS;
	if (high_bits >= HDN_AUTHORITY_WORD_BITS)
		return ~0ULL;

	return (1ULL << high_bits) - 1;
}

static bool hdn_profile_id_authorizes(u64 profile_id,
				      enum hdn_authority authority,
				      bool *audit)
{
	const struct hdn_profile_record *profile;
	bool allowed;

	rcu_read_lock();
	profile = hdn_profile_by_id(profile_id);
	allowed = hdn_authority_word_contains(profile->authority_allow,
					       profile->authority_allow_hi,
					       authority);
	if (audit)
		*audit = hdn_authority_word_contains(
			profile->authority_audit, profile->authority_audit_hi,
			authority);
	rcu_read_unlock();

	return allowed;
}

static bool hdn_profile_id_allows(u64 profile_id, enum hdn_authority authority,
				  enum hdn_transition transition)
{
	bool audit = false;

	if (!hdn_profile_id_authorizes(profile_id, authority, &audit))
		return false;
	if (audit)
		hdn_allow_audit(authority, transition);

	return true;
}

static bool hdn_profile_allows(enum hdn_authority authority,
			       enum hdn_transition transition)
{
	return hdn_profile_id_allows(hdn_current_profile_id(), authority,
				     transition);
}

static int hdn_require_policy_admin(enum hdn_transition transition)
{
	/* Avoid a false denial audit when CAP_SYS_ADMIN satisfies the fallback. */
	if (!ns_capable_noaudit(&init_user_ns, CAP_MAC_ADMIN) &&
	    !capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (!hdn_profile_allows(HDN_AUTH_POLICY_ADMIN, transition))
		return hdn_deny(HDN_AUTH_POLICY_ADMIN, transition,
				HDN_REASON_PROFILE_DENIED, -EPERM);

	return 0;
}

static bool hdn_memory_allows(u64 flag)
{
	const struct hdn_profile_record *profile;
	bool allowed;

	rcu_read_lock();
	profile = hdn_profile_by_id(hdn_current_profile_id());
	allowed = profile->memory_flags & flag;
	rcu_read_unlock();

	return allowed;
}

static u64 hdn_current_exec_memory_flags(void)
{
	struct mm_struct *mm = current->mm;

	if (!mm || !hdn_mm_compat_valid(mm))
		return 0;

	return READ_ONCE(mm->hardening_exec_memory_flags);
}

static bool hdn_exec_memory_allows(u64 flag)
{
	return hdn_current_exec_memory_flags() & flag;
}

static bool hdn_profile_flag_enabled(u64 flag)
{
	return hdn_current_profile_flags() & flag;
}

static bool hdn_profile_id_flag_enabled(u64 profile_id, u64 flag)
{
	return hdn_profile_flags(profile_id) & flag;
}

static bool hdn_jit_mprotect_allows(const struct hdn_mprotect_request *req)
{
	if (!hdn_memory_allows(HDN_MEM_ALLOW_JIT_EXEC_AFTER_WRITE) &&
	    !hdn_exec_memory_allows(HDN_MEM_ALLOW_JIT_EXEC_AFTER_WRITE))
		return false;
	if (!req->vma || req->vma->vm_file)
		return false;
	if (req->newflags & VM_WRITE)
		return false;
	if ((req->oldflags | req->newflags) & VM_SHARED)
		return false;

	return true;
}

int hdn_authorize(enum hdn_authority authority,
		  enum hdn_transition transition,
		  enum hdn_reason reason, int error)
{
	if (hdn_profile_allows(authority, transition))
		return 0;

	return hdn_deny(authority, transition, reason, error);
}

int hdn_authorize_profile(enum hdn_authority authority,
			  enum hdn_transition transition,
			  enum hdn_reason reason, int error, u64 profile_id)
{
	u64 current_profile = hdn_current_profile_id();

	if (!hdn_profile_id_allows(current_profile, authority, transition))
		return hdn_deny_object(authority, transition, reason, error,
				       profile_id);
	if (profile_id && profile_id != current_profile &&
	    !hdn_profile_id_allows(profile_id, authority, transition))
		return hdn_deny_object(authority, transition, reason, error,
				       profile_id);

	return 0;
}

void hdn_mm_set_profile(struct mm_struct *mm, u64 profile_id)
{
	if (!mm)
		return;

	WRITE_ONCE(mm->hardening_profile_id, profile_id);
}

u64 hdn_mm_profile_id(const struct mm_struct *mm)
{
	u64 profile_id;

	if (!mm)
		return HDN_PROFILE_PRIVILEGED;
	if (!hdn_mm_compat_valid(mm))
		return HDN_PROFILE_REVOKED;

	profile_id = READ_ONCE(mm->hardening_profile_id);
	if (!profile_id)
		return HDN_PROFILE_DEFAULT;

	return profile_id;
}

void hdn_userns_init_profile(struct user_namespace *ns)
{
	if (!ns)
		return;

	WRITE_ONCE(ns->hardening_profile_id, hdn_current_profile_id());
}

u64 hdn_userns_profile_id(const struct user_namespace *ns)
{
	u64 profile_id;

	if (!ns)
		return HDN_PROFILE_DEFAULT;

	profile_id = READ_ONCE(ns->hardening_profile_id);
	if (!profile_id)
		return HDN_PROFILE_DEFAULT;

	return profile_id;
}

static void hdn_file_identity_from_inode(struct inode *inode,
					 struct hdn_file_identity *id)
{
	enum hash_algo hash_algo;
	u8 verity_alg;
	int digest_size;

	memset(id, 0, sizeof(*id));
	if (!inode)
		return;

	id->dev_major = MAJOR(inode->i_sb->s_dev);
	id->dev_minor = MINOR(inode->i_sb->s_dev);
	id->ino = inode->i_ino;

	digest_size = fsverity_get_digest(inode, id->verity_digest,
					  &verity_alg, &hash_algo);
	if (digest_size <= 0 || digest_size > sizeof(id->verity_digest))
		return;

	id->verity_digest_size = digest_size;
	id->verity_digest_algorithm = verity_alg;
}

static void hdn_file_identity_from_file(struct file *file,
					struct hdn_file_identity *id)
{
	hdn_file_identity_from_inode(file ? file_inode(file) : NULL, id);
}

static int hdn_file_identity_from_path(const char *name,
				       struct hdn_file_identity *id)
{
	struct path path;
	int ret;

	if (!name || name[0] != '/')
		return -EINVAL;

	ret = kern_path(name, LOOKUP_FOLLOW, &path);
	if (ret)
		return ret;

	hdn_file_identity_from_inode(d_inode(path.dentry), id);
	path_put(&path);

	return id->ino ? 0 : -ENOENT;
}

void hdn_bprm_record_original(struct linux_binprm *bprm, struct file *file)
{
	struct hdn_file_identity id;

	hdn_file_identity_from_file(file, &id);
	bprm->hardening_original_dev_major = id.dev_major;
	bprm->hardening_original_dev_minor = id.dev_minor;
	bprm->hardening_original_ino = id.ino;
}

void hdn_bprm_note_interpreter(struct linux_binprm *bprm)
{
	bprm->hardening_interpreted = true;
}

static bool hdn_bprm_privileged(const struct linux_binprm *bprm)
{
	const struct cred *old = current_cred();
	const struct cred *new = bprm->cred;

	if (bprm->secureexec)
		return true;
	if (uid_eq(new->euid, GLOBAL_ROOT_UID))
		return true;
	if (!uid_eq(new->euid, old->euid) || !uid_eq(new->uid, old->uid))
		return true;
	if (!gid_eq(new->egid, old->egid) || !gid_eq(new->gid, old->gid))
		return true;
	if (!cap_issubset(new->cap_permitted, old->cap_permitted))
		return true;
	if (!cap_issubset(new->cap_effective, old->cap_effective))
		return true;

	return false;
}

static int hdn_apply_privexec_limits(struct linux_binprm *bprm)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_PROC_MEMMAP))
		return 0;
	if (!bprm->hardening_privileged_exec)
		return 0;

#ifdef CONFIG_MMU
	if (bprm->vma &&
	    bprm->vma->vm_end - bprm->vma->vm_start > HDN_PRIVEXEC_ARG_LIMIT)
		return -E2BIG;
#endif

	if (bprm->rlim_stack.rlim_max > HDN_PRIVEXEC_STACK_LIMIT)
		bprm->rlim_stack.rlim_max = HDN_PRIVEXEC_STACK_LIMIT;
	if (bprm->rlim_stack.rlim_cur > HDN_PRIVEXEC_STACK_LIMIT)
		bprm->rlim_stack.rlim_cur = HDN_PRIVEXEC_STACK_LIMIT;

	return 0;
}

static void hdn_apply_suid_spectre(const struct linux_binprm *bprm)
{
	const struct cred *cred = current_cred();

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_SUID_SPECTRE))
		return;
	if (!bprm->hardening_privileged_exec)
		return;
	if (uid_eq(cred->uid, GLOBAL_ROOT_UID))
		return;

	arch_prctl_spec_ctrl_set(current, PR_SPEC_STORE_BYPASS,
				 PR_SPEC_FORCE_DISABLE);
	arch_prctl_spec_ctrl_set(current, PR_SPEC_INDIRECT_BRANCH,
				 PR_SPEC_FORCE_DISABLE);
}

static bool hdn_current_privexec_admin(void)
{
	const struct cred *cred = current_cred();

	if (uid_eq(cred->uid, GLOBAL_ROOT_UID) ||
	    uid_eq(cred->euid, GLOBAL_ROOT_UID))
		return true;
	if (capable(CAP_SETUID) || capable(CAP_SETPCAP))
		return true;

	return false;
}

static bool hdn_identity_matches(const struct hdn_file_identity *id,
				 u64 dev_major, u64 dev_minor, u64 ino)
{
	return id->dev_major == dev_major &&
	       id->dev_minor == dev_minor &&
	       id->ino == ino;
}

static void hdn_mm_exec_identity(const struct mm_struct *mm,
				 struct hdn_file_identity *id)
{
	id->dev_major = READ_ONCE(mm->hardening_exec_dev_major);
	id->dev_minor = READ_ONCE(mm->hardening_exec_dev_minor);
	id->ino = READ_ONCE(mm->hardening_exec_ino);
}

static bool hdn_brute_record_matches(const struct hdn_brute_record *record,
				     const struct hdn_file_identity *id,
				     u64 profile_id, uid_t uid)
{
	return record->used &&
	       record->dev_major == id->dev_major &&
	       record->dev_minor == id->dev_minor &&
	       record->ino == id->ino &&
	       record->profile_id == profile_id &&
	       record->uid == uid;
}

static void hdn_brute_record_set_key(struct hdn_brute_record *record,
				     const struct hdn_file_identity *id,
				     u64 profile_id, uid_t uid)
{
	memset(record, 0, sizeof(*record));
	record->used = true;
	record->dev_major = id->dev_major;
	record->dev_minor = id->dev_minor;
	record->ino = id->ino;
	record->profile_id = profile_id;
	record->uid = uid;
}

static struct hdn_brute_record *
hdn_brute_find_record(const struct hdn_file_identity *id, u64 profile_id,
		      uid_t uid)
{
	int i;

	for (i = 0; i < HDN_BRUTE_RECORD_COUNT; i++) {
		if (hdn_brute_record_matches(&hdn_brute_records[i], id,
					     profile_id, uid))
			return &hdn_brute_records[i];
	}

	return NULL;
}

static struct hdn_brute_record *
hdn_brute_find_or_reuse_record(const struct hdn_file_identity *id,
			       u64 profile_id, uid_t uid)
{
	struct hdn_brute_record *oldest = &hdn_brute_records[0];
	int i;

	for (i = 0; i < HDN_BRUTE_RECORD_COUNT; i++) {
		if (hdn_brute_record_matches(&hdn_brute_records[i], id,
					     profile_id, uid))
			return &hdn_brute_records[i];
		if (!hdn_brute_records[i].used) {
			hdn_brute_record_set_key(&hdn_brute_records[i], id,
						 profile_id, uid);
			return &hdn_brute_records[i];
		}
		if (hdn_brute_records[i].last_crash_ns < oldest->last_crash_ns)
			oldest = &hdn_brute_records[i];
	}

	hdn_brute_record_set_key(oldest, id, profile_id, uid);
	return oldest;
}

static bool hdn_brute_signal(int sig)
{
	switch (sig) {
	case SIGABRT:
	case SIGBUS:
	case SIGFPE:
	case SIGILL:
	case SIGSEGV:
	case SIGTRAP:
		return true;
	default:
		return false;
	}
}

static void hdn_brute_mark_daemon_parent(const struct mm_struct *mm, int sig)
{
	struct hdn_file_identity child_id = {};
	struct hdn_file_identity parent_id = {};
	struct task_struct *parent;
	struct mm_struct *parent_mm;
	u64 until;

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_BRUTE))
		return;
	if (!mm || !hdn_brute_signal(sig))
		return;
	if (READ_ONCE(mm->hardening_exec_privileged))
		return;

	hdn_mm_exec_identity(mm, &child_id);
	if (!child_id.ino)
		return;

	rcu_read_lock();
	parent = rcu_dereference(current->real_parent);
	if (!parent || parent == current) {
		rcu_read_unlock();
		return;
	}
	get_task_struct(parent);
	rcu_read_unlock();

	parent_mm = get_task_mm(parent);
	if (!parent_mm)
		goto out_put_parent;
	hdn_mm_exec_identity(parent_mm, &parent_id);
	mmput(parent_mm);

	if (!hdn_identity_matches(&parent_id, child_id.dev_major,
				  child_id.dev_minor, child_id.ino))
		goto out_put_parent;

	until = ktime_get_ns() + HDN_BRUTE_DAEMON_WINDOW_NS;
	WRITE_ONCE(parent->hardening_brute_fork_delay_until_ns, until);
	hdn_record_event_object_flags(HDN_AUTH_NONE, HDN_TRANS_FORK,
				      HDN_REASON_BRUTE_DAEMON_THROTTLED,
				      HDN_DECISION_ALLOW_AUDIT, 0,
				      task_pid_nr(parent), 0);

out_put_parent:
	put_task_struct(parent);
}

void hdn_brute_check_fork(void)
{
	u64 until;

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_BRUTE))
		return;

	until = READ_ONCE(current->hardening_brute_fork_delay_until_ns);
	if (!until)
		return;
	if (ktime_get_ns() >= until) {
		WRITE_ONCE(current->hardening_brute_fork_delay_until_ns, 0);
		return;
	}

	hdn_record_event_object_flags(HDN_AUTH_NONE, HDN_TRANS_FORK,
				      HDN_REASON_BRUTE_DAEMON_THROTTLED,
				      HDN_DECISION_ALLOW_AUDIT, 0,
				      task_pid_nr(current), 0);
	msleep(HDN_BRUTE_DAEMON_FORK_DELAY_MS);
}

static int hdn_brute_authorize_exec(struct linux_binprm *bprm,
				    u64 profile_id)
{
	struct hdn_file_identity id;
	struct hdn_brute_record *record;
	unsigned long flags;
	bool throttled = false;
	uid_t uid;
	u64 now;

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_BRUTE))
		return 0;
	if (!bprm->hardening_privileged_exec)
		return 0;

	hdn_file_identity_from_file(bprm->file, &id);
	uid = from_kuid_munged(&init_user_ns, current_uid());
	now = ktime_get_ns();

	spin_lock_irqsave(&hdn_brute_lock, flags);
	record = hdn_brute_find_record(&id, profile_id, uid);
	if (record && record->penalty_until_ns > now)
		throttled = true;
	spin_unlock_irqrestore(&hdn_brute_lock, flags);

	if (!throttled)
		return 0;

	return hdn_deny_object(HDN_AUTH_EXEC, HDN_TRANS_EXEC,
			       HDN_REASON_BRUTE_THROTTLED, -EAGAIN,
			       hdn_file_object_id(bprm->file));
}

static void hdn_brute_record_crash(const struct mm_struct *mm, int sig)
{
	struct hdn_file_identity id = {};
	struct hdn_brute_record *record;
	unsigned long flags;
	uid_t uid;
	u64 now;

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_BRUTE))
		return;
	if (!mm || !hdn_brute_signal(sig))
		return;
	if (!READ_ONCE(mm->hardening_exec_privileged))
		return;

	id.dev_major = READ_ONCE(mm->hardening_exec_dev_major);
	id.dev_minor = READ_ONCE(mm->hardening_exec_dev_minor);
	id.ino = READ_ONCE(mm->hardening_exec_ino);
	if (!id.ino)
		return;

	uid = from_kuid_munged(&init_user_ns, current_uid());
	now = ktime_get_ns();

	spin_lock_irqsave(&hdn_brute_lock, flags);
	record = hdn_brute_find_or_reuse_record(
		&id, READ_ONCE(mm->hardening_exec_profile_id), uid);
	if (!record->crash_count ||
	    now - record->first_crash_ns > HDN_BRUTE_WINDOW_NS) {
		record->first_crash_ns = now;
		record->crash_count = 1;
	} else {
		record->crash_count++;
	}
	record->last_crash_ns = now;
	if (record->crash_count >= HDN_BRUTE_CRASH_LIMIT)
		record->penalty_until_ns = now + HDN_BRUTE_PENALTY_NS;
	spin_unlock_irqrestore(&hdn_brute_lock, flags);
}

static bool hdn_exec_rule_matches(const struct hdn_exec_rule_record *rule,
				  const struct linux_binprm *bprm,
				  const struct hdn_file_identity *file_id,
				  u64 parent_profile)
{
	if ((rule->flags & HDN_EXEC_COMPAT_LEASE) &&
	    (bprm->hardening_interpreted ||
	     !hdn_compat_path_matches(bprm->file, rule->file_path)))
		return false;

	if (rule->parent_profile_id &&
	    rule->parent_profile_id != parent_profile)
		return false;

	if ((rule->flags & HDN_EXEC_MATCH_FILE_ID) &&
	    !hdn_identity_matches(file_id, rule->file_dev_major,
				  rule->file_dev_minor, rule->file_ino))
		return false;

	if (rule->flags & HDN_EXEC_MATCH_ORIGINAL_ID) {
		if (!bprm->hardening_interpreted)
			return false;
		if (bprm->hardening_original_dev_major !=
		    rule->original_dev_major ||
		    bprm->hardening_original_dev_minor !=
		    rule->original_dev_minor ||
		    bprm->hardening_original_ino != rule->original_ino)
			return false;
	}

	if (rule->flags & HDN_EXEC_MATCH_VERITY_DIGEST) {
		if (file_id->verity_digest_size != rule->verity_digest_size ||
		    file_id->verity_digest_algorithm !=
		    rule->verity_digest_algorithm)
			return false;
		if (memcmp(file_id->verity_digest, rule->verity_digest,
			   rule->verity_digest_size))
			return false;
	}

	return true;
}

static bool hdn_policy_path_valid(const char *path)
{
	return path[0] == '/' && memchr(path, '\0', HDN_POLICY_PATH_LEN);
}

static int hdn_resolve_exec_rule_paths(struct hdn_exec_rule_record *rule)
{
	struct hdn_file_identity id;
	int ret;

	if (rule->flags & HDN_EXEC_RESOLVE_FILE_PATH) {
		ret = hdn_file_identity_from_path(rule->file_path, &id);
		if (ret)
			return ret;
		rule->file_dev_major = id.dev_major;
		rule->file_dev_minor = id.dev_minor;
		rule->file_ino = id.ino;
		rule->flags &= ~HDN_EXEC_RESOLVE_FILE_PATH;
		rule->flags |= HDN_EXEC_MATCH_FILE_ID;
		if (!(rule->flags & HDN_EXEC_COMPAT_LEASE))
			memset(rule->file_path, 0, sizeof(rule->file_path));
	}

	if (rule->flags & HDN_EXEC_RESOLVE_ORIGINAL_PATH) {
		ret = hdn_file_identity_from_path(rule->original_path, &id);
		if (ret)
			return ret;
		rule->original_dev_major = id.dev_major;
		rule->original_dev_minor = id.dev_minor;
		rule->original_ino = id.ino;
		rule->flags &= ~HDN_EXEC_RESOLVE_ORIGINAL_PATH;
		rule->flags |= HDN_EXEC_MATCH_ORIGINAL_ID;
		memset(rule->original_path, 0, sizeof(rule->original_path));
	}

	return 0;
}

static int hdn_resolve_module_rule_path(struct hdn_module_rule_record *rule)
{
	struct hdn_file_identity id;
	int ret;

	if (!(rule->flags & HDN_MODULE_RESOLVE_FILE_PATH))
		return 0;

	ret = hdn_file_identity_from_path(rule->file_path, &id);
	if (ret)
		return ret;
	rule->file_dev_major = id.dev_major;
	rule->file_dev_minor = id.dev_minor;
	rule->file_ino = id.ino;
	rule->flags &= ~HDN_MODULE_RESOLVE_FILE_PATH;
	rule->flags |= HDN_MODULE_MATCH_FILE_ID;
	memset(rule->file_path, 0, sizeof(rule->file_path));

	return 0;
}

static int hdn_resolve_object_rule_path(struct hdn_object_rule_record *rule)
{
	struct hdn_file_identity id;
	unsigned int lookup_flags;
	struct path path;
	int ret;

	if (!(rule->flags & HDN_OBJECT_RESOLVE_FILE_PATH))
		return 0;

	lookup_flags = (rule->flags & HDN_OBJECT_RESOLVE_NOFOLLOW_PATH) ?
		       0 : LOOKUP_FOLLOW;
	ret = kern_path(rule->file_path, lookup_flags, &path);
	if (ret)
		return ret;
	if ((rule->flags & HDN_OBJECT_MATCH_SUBTREE) &&
	    !S_ISDIR(d_inode(path.dentry)->i_mode)) {
		path_put(&path);
		return -ENOTDIR;
	}
	hdn_file_identity_from_inode(d_inode(path.dentry), &id);
	path_put(&path);
	if (!id.ino)
		return -ENOENT;
	rule->file_dev_major = id.dev_major;
	rule->file_dev_minor = id.dev_minor;
	rule->file_ino = id.ino;
	rule->flags &= ~(HDN_OBJECT_RESOLVE_FILE_PATH |
			 HDN_OBJECT_RESOLVE_NOFOLLOW_PATH);
	rule->flags |= HDN_OBJECT_MATCH_FILE_ID;
	memset(rule->file_path, 0, sizeof(rule->file_path));

	return 0;
}

static int hdn_resolve_policy_paths(struct hdn_policy *policy)
{
	u32 i;
	int ret;

	for (i = 0; i < policy->object_rule_count; i++) {
		ret = hdn_resolve_object_rule_path(&policy->object_rules[i]);
		if (ret)
			return ret;
	}

	for (i = 0; i < policy->exec_rule_count; i++) {
		ret = hdn_resolve_exec_rule_paths(&policy->exec_rules[i]);
		if (ret)
			return ret;
	}

	for (i = 0; i < policy->module_rule_count; i++) {
		ret = hdn_resolve_module_rule_path(&policy->module_rules[i]);
		if (ret)
			return ret;
	}

	return 0;
}

static bool hdn_inode_identity_matches(const struct inode *inode,
				       u64 dev_major, u64 dev_minor, u64 ino)
{
	if (!inode)
		return false;

	return MAJOR(inode->i_sb->s_dev) == dev_major &&
	       MINOR(inode->i_sb->s_dev) == dev_minor &&
	       inode->i_ino == ino;
}

static bool hdn_dentry_has_identity(struct dentry *dentry,
				    u64 dev_major, u64 dev_minor, u64 ino)
{
	struct dentry *pos;

	for (pos = dentry; pos; pos = pos->d_parent) {
		if (hdn_inode_identity_matches(d_inode_rcu(pos), dev_major,
					       dev_minor, ino))
			return true;
		if (IS_ROOT(pos))
			break;
	}

	return false;
}

static bool hdn_dentry_under_identity(struct dentry *dentry,
				      u64 dev_major, u64 dev_minor, u64 ino)
{
	bool under;
	unsigned seq;

	if (!dentry)
		return false;

	rcu_read_lock();
	seq = read_seqbegin(&rename_lock);
	under = hdn_dentry_has_identity(dentry, dev_major, dev_minor, ino);
	if (read_seqretry(&rename_lock, seq)) {
		read_seqlock_excl(&rename_lock);
		under = hdn_dentry_has_identity(dentry, dev_major, dev_minor,
						ino);
		read_sequnlock_excl(&rename_lock);
	}
	rcu_read_unlock();

	return under;
}

static bool
hdn_object_rule_matches_dentry(const struct hdn_object_rule_record *rule,
			       struct dentry *dentry,
			       const struct hdn_file_identity *file_id,
			       u64 profile_id, u64 access_flag)
{
	if (rule->profile_id != profile_id)
		return false;
	if (!((rule->flags | rule->audit_flags) & access_flag))
		return false;
	if (rule->flags & HDN_OBJECT_MATCH_UNIX_ABSTRACT)
		return false;

	if (rule->flags & HDN_OBJECT_MATCH_SUBTREE)
		return hdn_dentry_under_identity(dentry, rule->file_dev_major,
						 rule->file_dev_minor,
						 rule->file_ino);

	if ((rule->flags & HDN_OBJECT_MATCH_FILE_ID) &&
	    !hdn_identity_matches(file_id, rule->file_dev_major,
				  rule->file_dev_minor, rule->file_ino))
		return false;

	return true;
}

static bool
hdn_object_rule_matches_unix_abstract(
	const struct hdn_object_rule_record *rule, const char *name,
	size_t name_len, u64 profile_id, u64 access_flag)
{
	size_t rule_len;

	if (rule->profile_id != profile_id)
		return false;
	if (!(rule->flags & access_flag))
		return false;
	if (!(rule->flags & HDN_OBJECT_MATCH_UNIX_ABSTRACT))
		return false;

	rule_len = strnlen(rule->file_path, sizeof(rule->file_path));
	if (!rule_len || rule_len >= sizeof(rule->file_path))
		return false;
	if (rule_len != name_len)
		return false;

	return !memcmp(rule->file_path, name, name_len);
}

enum hdn_object_decision {
	HDN_OBJECT_DECISION_DENY = BIT(0),
	HDN_OBJECT_DECISION_AUDIT = BIT(1),
};

static unsigned int hdn_object_dentry_decision(struct dentry *dentry,
					       u64 profile_id, u64 access_flag)
{
	struct hdn_file_identity file_id;
	struct hdn_policy *policy;
	unsigned int decision = 0;
	u32 i;

	if (!dentry)
		return 0;

	hdn_file_identity_from_inode(d_inode(dentry), &file_id);
	if (!file_id.ino)
		return 0;

	rcu_read_lock();
	policy = rcu_dereference(hdn_active_policy);
	if (policy) {
		for (i = 0; i < policy->object_rule_count; i++) {
			if (!hdn_object_rule_matches_dentry(
				    &policy->object_rules[i], dentry, &file_id,
				    profile_id, access_flag))
				continue;
			if (policy->object_rules[i].flags & access_flag)
				decision |= HDN_OBJECT_DECISION_DENY;
			if (policy->object_rules[i].audit_flags & access_flag)
				decision |= HDN_OBJECT_DECISION_AUDIT;
			if (decision & HDN_OBJECT_DECISION_DENY)
				break;
		}
	}
	rcu_read_unlock();

	return decision;
}

static unsigned int hdn_object_access_decision(const struct path *path,
					       u64 profile_id, u64 access_flag)
{
	if (!path || !path->dentry)
		return 0;

	return hdn_object_dentry_decision(path->dentry, profile_id, access_flag);
}

static bool hdn_object_access_denied(const struct path *path, u64 profile_id,
				     u64 access_flag)
{
	return hdn_object_access_decision(path, profile_id, access_flag) &
	       HDN_OBJECT_DECISION_DENY;
}

static int hdn_apply_object_decision(unsigned int decision,
				     enum hdn_authority authority,
				     enum hdn_transition transition,
				     int error, u64 object_id)
{
	if (decision & HDN_OBJECT_DECISION_DENY)
		return hdn_deny_object(authority, transition,
				       HDN_REASON_OBJECT_POLICY, error, object_id);

	if ((decision & HDN_OBJECT_DECISION_AUDIT) &&
	    hdn_record_event_object_flags(authority, transition,
					  HDN_REASON_NONE,
					  HDN_DECISION_ALLOW_AUDIT, 0,
					  object_id, 0))
		hdn_audit(authority, transition, HDN_REASON_NONE,
			  HDN_DECISION_ALLOW_AUDIT, 0);

	return 0;
}

static bool hdn_object_unix_abstract_denied(const char *name, size_t name_len,
					    u64 profile_id, u64 access_flag)
{
	struct hdn_policy *policy;
	bool denied = false;
	u32 i;

	if (!name || !name_len)
		return false;

	rcu_read_lock();
	policy = rcu_dereference(hdn_active_policy);
	if (policy) {
		for (i = 0; i < policy->object_rule_count; i++) {
			if (!hdn_object_rule_matches_unix_abstract(
				    &policy->object_rules[i], name, name_len,
				    profile_id, access_flag))
				continue;
			denied = true;
			break;
		}
	}
	rcu_read_unlock();

	return denied;
}

int hdn_authorize_object_access(const struct path *path, int mode)
{
	const struct inode *inode;
	unsigned int decision;
	u64 profile_id;
	u64 object_id;

	if (!path || !path->dentry)
		return 0;

	inode = d_inode(path->dentry);
	if (!inode)
		return 0;

	profile_id = hdn_current_profile_id();
	object_id = hdn_path_object_id(path);
	if (hdn_object_access_denied(path, profile_id, HDN_OBJECT_DENY_ACCESS))
		return hdn_deny_object(HDN_AUTH_OBJECT_ACCESS,
				       HDN_TRANS_OBJECT_ACCESS,
				       HDN_REASON_OBJECT_POLICY, -EACCES,
				       object_id);

	if (!S_ISREG(inode->i_mode))
		return 0;

	if (mode & MAY_READ) {
		decision = hdn_object_access_decision(
			path, profile_id, HDN_OBJECT_DENY_READ);
		if (decision)
			return hdn_apply_object_decision(
				decision, HDN_AUTH_OBJECT_ACCESS,
				HDN_TRANS_OBJECT_ACCESS, -EACCES, object_id);
	}
	if (mode & MAY_WRITE) {
		decision = hdn_object_access_decision(
			path, profile_id, HDN_OBJECT_DENY_WRITE);
		if (decision)
			return hdn_apply_object_decision(
				decision, HDN_AUTH_OBJECT_ACCESS,
				HDN_TRANS_OBJECT_ACCESS, -EACCES, object_id);
	}
	if (mode & MAY_EXEC) {
		decision = hdn_object_access_decision(
			path, profile_id, HDN_OBJECT_DENY_EXEC);
		if (decision)
			return hdn_apply_object_decision(
				decision, HDN_AUTH_OBJECT_ACCESS,
				HDN_TRANS_OBJECT_ACCESS, -EACCES, object_id);
	}

	return 0;
}

int hdn_authorize_object_stat(const struct path *path)
{
	const struct inode *inode;

	if (!path || !path->dentry)
		return 0;

	inode = d_inode(path->dentry);
	if (!inode)
		return 0;

	if (!hdn_object_access_denied(path, hdn_current_profile_id(),
				      HDN_OBJECT_DENY_STAT))
		return 0;

	return hdn_deny_object(HDN_AUTH_OBJECT_STAT, HDN_TRANS_OBJECT_STAT,
			       HDN_REASON_OBJECT_POLICY, -EACCES,
			       hdn_path_object_id(path));
}

int hdn_authorize_object_list(const struct path *path)
{
	const struct inode *inode;

	if (!path || !path->dentry)
		return 0;

	inode = d_inode(path->dentry);
	if (!inode || !S_ISDIR(inode->i_mode))
		return 0;

	if (!hdn_object_access_denied(path, hdn_current_profile_id(),
				      HDN_OBJECT_DENY_LIST))
		return 0;

	return hdn_deny_object(HDN_AUTH_OBJECT_LIST, HDN_TRANS_OBJECT_LIST,
			       HDN_REASON_OBJECT_POLICY, -EACCES,
			       hdn_path_object_id(path));
}

int hdn_authorize_object_find(const struct path *path)
{
	const struct inode *inode;
	unsigned int decision;

	if (!path || !path->dentry)
		return 0;

	inode = d_inode(path->dentry);
	if (!inode)
		return 0;

	decision = hdn_object_access_decision(path, hdn_current_profile_id(),
					      HDN_OBJECT_DENY_FIND);
	return hdn_apply_object_decision(decision, HDN_AUTH_OBJECT_FIND,
				 HDN_TRANS_OBJECT_FIND, -ENOENT,
				 hdn_path_object_id(path));
}

static bool hdn_readdir_dot_entry(const char *name, int namlen)
{
	return (namlen == 1 && name[0] == '.') ||
	       (namlen == 2 && name[0] == '.' && name[1] == '.');
}

bool hdn_object_readdir_entry_visible(const struct file *file,
				      const char *name, int namlen, u64 ino)
{
	const struct hdn_object_rule_record *rule;
	struct hdn_policy *policy;
	struct dentry *dir;
	struct inode *dir_inode;
	u64 profile_id;
	u64 dev_major;
	u64 dev_minor;
	bool visible = true;
	u32 i;

	if (!file || !name || namlen <= 0 || !ino)
		return true;
	if (hdn_readdir_dot_entry(name, namlen))
		return true;

	dir = file->f_path.dentry;
	if (!dir)
		return true;

	dir_inode = file_inode(file);
	if (!dir_inode || !dir_inode->i_sb)
		return true;

	profile_id = hdn_current_profile_id();
	dev_major = MAJOR(dir_inode->i_sb->s_dev);
	dev_minor = MINOR(dir_inode->i_sb->s_dev);

	rcu_read_lock();
	policy = rcu_dereference(hdn_active_policy);
	if (!policy)
		goto out;

	for (i = 0; i < policy->object_rule_count; i++) {
		rule = &policy->object_rules[i];
		if (rule->profile_id != profile_id)
			continue;
		if (!(rule->flags & HDN_OBJECT_DENY_FIND))
			continue;
		if (rule->file_dev_major == dev_major &&
		    rule->file_dev_minor == dev_minor &&
		    rule->file_ino == ino) {
			visible = false;
			break;
		}
		if ((rule->flags & HDN_OBJECT_MATCH_SUBTREE) &&
		    hdn_dentry_under_identity(dir, rule->file_dev_major,
					     rule->file_dev_minor,
					     rule->file_ino)) {
			visible = false;
			break;
		}
	}

out:
	rcu_read_unlock();
	return visible;
}

static int hdn_authorize_object_read_path(const struct path *path)
{
	unsigned int decision;

	if (!path || !path->dentry)
		return 0;

	decision = hdn_object_access_decision(path, hdn_current_profile_id(),
					      HDN_OBJECT_DENY_READ);
	return hdn_apply_object_decision(decision, HDN_AUTH_OBJECT_READ,
				 HDN_TRANS_OBJECT_READ, -EACCES,
				 hdn_path_object_id(path));
}

static bool hdn_object_can_stream_io(const struct inode *inode)
{
	umode_t mode;

	if (!inode)
		return false;

	mode = inode->i_mode;
	return S_ISREG(mode) || S_ISFIFO(mode) || S_ISCHR(mode) ||
	       S_ISBLK(mode) || S_ISSOCK(mode);
}

int hdn_authorize_object_read(const struct path *path)
{
	const struct inode *inode;

	if (!path || !path->dentry)
		return 0;

	inode = d_inode(path->dentry);
	if (!hdn_object_can_stream_io(inode))
		return 0;

	return hdn_authorize_object_read_path(path);
}

static int hdn_authorize_object_read_file(struct file *file)
{
	struct inode *inode;
	unsigned int decision;

	if (!file)
		return 0;

	inode = file_inode(file);
	if (!hdn_object_can_stream_io(inode))
		return 0;

	decision = hdn_object_access_decision(&file->f_path,
					      hdn_current_profile_id(),
					      HDN_OBJECT_DENY_READ);
	return hdn_apply_object_decision(decision, HDN_AUTH_OBJECT_READ,
				 HDN_TRANS_OBJECT_READ, -EACCES,
				 hdn_file_object_id(file));
}

int hdn_authorize_object_readlink(const struct path *path)
{
	const struct inode *inode;

	if (!path || !path->dentry)
		return 0;

	inode = d_inode(path->dentry);
	if (!inode || (!S_ISLNK(inode->i_mode) &&
		       (!inode->i_op || !inode->i_op->readlink)))
		return 0;

	return hdn_authorize_object_read_path(path);
}

static int hdn_authorize_object_dentry_flag(const struct dentry *dentry,
					    u64 deny_flag,
					    enum hdn_authority authority,
					    enum hdn_transition transition,
					    bool require_dir)
{
	struct inode *inode;
	unsigned int decision;

	if (!dentry)
		return 0;

	inode = d_inode(dentry);
	if (!inode)
		return 0;

	if (require_dir && !S_ISDIR(inode->i_mode))
		return 0;

	decision = hdn_object_dentry_decision((struct dentry *)dentry,
					      hdn_current_profile_id(),
					      deny_flag);
	return hdn_apply_object_decision(decision, authority, transition,
				 -EACCES, hdn_inode_object_id(inode));
}

int hdn_authorize_object_delete(const struct dentry *dentry)
{
	return hdn_authorize_object_dentry_flag(
		dentry, HDN_OBJECT_DENY_DELETE, HDN_AUTH_OBJECT_DELETE,
		HDN_TRANS_OBJECT_DELETE, false);
}

int hdn_authorize_object_create(const struct dentry *dir)
{
	return hdn_authorize_object_dentry_flag(
		dir, HDN_OBJECT_DENY_CREATE, HDN_AUTH_OBJECT_CREATE,
		HDN_TRANS_OBJECT_CREATE, true);
}

static int hdn_authorize_object_create_operation(
	const struct dentry *dir, u64 deny_flag, enum hdn_authority authority,
	enum hdn_transition transition)
{
	int ret;

	ret = hdn_authorize_object_dentry_flag(dir, deny_flag, authority,
					       transition, true);
	if (ret)
		return ret;
	return hdn_authorize_object_create(dir);
}

static bool hdn_object_mode_requests_setid(umode_t mode)
{
	if (mode & S_ISUID)
		return true;

	return (mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP);
}

static int hdn_authorize_object_setid_dentry(const struct dentry *dentry,
					     bool require_dir)
{
	return hdn_authorize_object_dentry_flag(
		dentry, HDN_OBJECT_DENY_SETID, HDN_AUTH_OBJECT_SETID,
		HDN_TRANS_OBJECT_SETID, require_dir);
}

static int hdn_authorize_object_setid_create(const struct dentry *dir,
					     umode_t mode)
{
	if (!hdn_object_mode_requests_setid(mode))
		return 0;

	return hdn_authorize_object_setid_dentry(dir, true);
}

static int hdn_authorize_object_setid_attr(const struct dentry *dentry,
					   umode_t mode)
{
	if (!hdn_object_mode_requests_setid(mode))
		return 0;

	return hdn_authorize_object_setid_dentry(dentry, false);
}

static int hdn_authorize_object_delete_operation(
	const struct dentry *dentry, u64 deny_flag,
	enum hdn_authority authority, enum hdn_transition transition)
{
	int ret;

	ret = hdn_authorize_object_dentry_flag(dentry, deny_flag, authority,
					       transition, false);
	if (ret)
		return ret;
	return hdn_authorize_object_delete(dentry);
}

int hdn_authorize_object_creat(const struct dentry *dir, umode_t mode)
{
	int ret;

	ret = hdn_authorize_object_setid_create(dir, mode);
	if (ret)
		return ret;

	return hdn_authorize_object_create_operation(
		dir, HDN_OBJECT_DENY_CREAT, HDN_AUTH_OBJECT_CREAT,
		HDN_TRANS_OBJECT_CREAT);
}

int hdn_authorize_object_mkdir(const struct dentry *dir)
{
	return hdn_authorize_object_create_operation(
		dir, HDN_OBJECT_DENY_MKDIR, HDN_AUTH_OBJECT_MKDIR,
		HDN_TRANS_OBJECT_MKDIR);
}

int hdn_authorize_object_mknod(const struct dentry *dir, umode_t mode)
{
	int ret;

	ret = hdn_authorize_object_setid_create(dir, mode);
	if (ret)
		return ret;

	return hdn_authorize_object_create_operation(
		dir, HDN_OBJECT_DENY_MKNOD, HDN_AUTH_OBJECT_MKNOD,
		HDN_TRANS_OBJECT_MKNOD);
}

int hdn_authorize_object_unix_bind(const struct dentry *dir)
{
	return hdn_authorize_object_dentry_flag(
		dir, HDN_OBJECT_DENY_UNIX_BIND, HDN_AUTH_OBJECT_UNIX_BIND,
		HDN_TRANS_OBJECT_UNIX_BIND, true);
}

int hdn_authorize_object_symlink(const struct dentry *dir)
{
	return hdn_authorize_object_create_operation(
		dir, HDN_OBJECT_DENY_SYMLINK, HDN_AUTH_OBJECT_SYMLINK,
		HDN_TRANS_OBJECT_SYMLINK);
}

int hdn_authorize_object_unlink(const struct dentry *dentry)
{
	return hdn_authorize_object_delete_operation(
		dentry, HDN_OBJECT_DENY_UNLINK, HDN_AUTH_OBJECT_UNLINK,
		HDN_TRANS_OBJECT_UNLINK);
}

int hdn_authorize_object_rmdir(const struct dentry *dentry)
{
	return hdn_authorize_object_delete_operation(
		dentry, HDN_OBJECT_DENY_RMDIR, HDN_AUTH_OBJECT_RMDIR,
		HDN_TRANS_OBJECT_RMDIR);
}

int hdn_authorize_object_link_source(const struct dentry *dentry)
{
	struct inode *inode;
	unsigned int decision;

	if (!dentry)
		return 0;

	inode = d_inode(dentry);
	if (!inode || !S_ISREG(inode->i_mode))
		return 0;

	decision = hdn_object_dentry_decision((struct dentry *)dentry,
					      hdn_current_profile_id(),
					      HDN_OBJECT_DENY_LINK);
	return hdn_apply_object_decision(decision, HDN_AUTH_OBJECT_LINK,
				 HDN_TRANS_OBJECT_LINK, -EACCES,
				 hdn_inode_object_id(inode));
}

int hdn_authorize_object_link_target(const struct dentry *dir)
{
	return hdn_authorize_object_dentry_flag(
		dir, HDN_OBJECT_DENY_LINK_TARGET,
		HDN_AUTH_OBJECT_LINK_TARGET,
		HDN_TRANS_OBJECT_LINK_TARGET, true);
}

static bool hdn_object_attr_request(unsigned int ia_valid)
{
	return ia_valid & (ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_SIZE |
			   ATTR_ATIME | ATTR_MTIME |
			   ATTR_ATIME_SET | ATTR_MTIME_SET | ATTR_CTIME_SET |
			   ATTR_TIMES_SET | ATTR_TOUCH);
}

static bool hdn_object_utime_request(unsigned int ia_valid)
{
	return ia_valid & (ATTR_ATIME | ATTR_MTIME | ATTR_ATIME_SET |
			   ATTR_MTIME_SET | ATTR_CTIME_SET |
			   ATTR_TIMES_SET | ATTR_TOUCH);
}

static int hdn_authorize_object_dentry_policy(const struct dentry *dentry,
					      u64 deny_flag,
					      enum hdn_authority authority,
					      enum hdn_transition transition)
{
	return hdn_authorize_object_dentry_flag(dentry, deny_flag, authority,
						transition, false);
}

static int hdn_authorize_object_attr_dentry(const struct dentry *dentry)
{
	return hdn_authorize_object_dentry_policy(dentry, HDN_OBJECT_DENY_ATTR,
						  HDN_AUTH_OBJECT_ATTR,
						  HDN_TRANS_OBJECT_ATTR);
}

static int hdn_authorize_object_truncate_dentry(const struct dentry *dentry)
{
	return hdn_authorize_object_dentry_policy(
		dentry, HDN_OBJECT_DENY_TRUNCATE,
		HDN_AUTH_OBJECT_TRUNCATE, HDN_TRANS_OBJECT_TRUNCATE);
}

int hdn_authorize_object_rename(const struct dentry *dentry)
{
	return hdn_authorize_object_dentry_policy(
		dentry, HDN_OBJECT_DENY_RENAME,
		HDN_AUTH_OBJECT_RENAME, HDN_TRANS_OBJECT_RENAME);
}

int hdn_authorize_object_rename_target(const struct dentry *dir)
{
	return hdn_authorize_object_dentry_flag(
		dir, HDN_OBJECT_DENY_RENAME_TARGET,
		HDN_AUTH_OBJECT_RENAME_TARGET,
		HDN_TRANS_OBJECT_RENAME_TARGET, true);
}

int hdn_authorize_object_attr(const struct dentry *dentry,
			      unsigned int ia_valid, umode_t mode)
{
	int ret;

	if (ia_valid & ATTR_SIZE) {
		ret = hdn_authorize_object_truncate_dentry(dentry);
		if (ret)
			return ret;
	}

	if (ia_valid & ATTR_MODE) {
		ret = hdn_authorize_object_setid_attr(dentry, mode);
		if (ret)
			return ret;

		ret = hdn_authorize_object_dentry_policy(
			dentry, HDN_OBJECT_DENY_CHMOD, HDN_AUTH_OBJECT_CHMOD,
			HDN_TRANS_OBJECT_CHMOD);
		if (ret)
			return ret;
	}

	if (ia_valid & (ATTR_UID | ATTR_GID)) {
		ret = hdn_authorize_object_dentry_policy(
			dentry, HDN_OBJECT_DENY_CHOWN, HDN_AUTH_OBJECT_CHOWN,
			HDN_TRANS_OBJECT_CHOWN);
		if (ret)
			return ret;
	}

	if (hdn_object_utime_request(ia_valid)) {
		ret = hdn_authorize_object_dentry_policy(
			dentry, HDN_OBJECT_DENY_UTIME, HDN_AUTH_OBJECT_UTIME,
			HDN_TRANS_OBJECT_UTIME);
		if (ret)
			return ret;
	}

	if (!hdn_object_attr_request(ia_valid))
		return 0;

	return hdn_authorize_object_attr_dentry(dentry);
}

int hdn_authorize_object_fileattr(const struct dentry *dentry)
{
	return hdn_authorize_object_attr_dentry(dentry);
}

int hdn_authorize_object_filegetattr(const struct dentry *dentry)
{
	return hdn_authorize_object_dentry_policy(dentry, HDN_OBJECT_DENY_STAT,
						  HDN_AUTH_OBJECT_STAT,
						  HDN_TRANS_OBJECT_STAT);
}

int hdn_authorize_object_xattr(const struct dentry *dentry,
			       enum hdn_xattr_operation operation)
{
	int ret;

	if (operation == HDN_XATTR_SET) {
		ret = hdn_authorize_object_dentry_policy(
			dentry, HDN_OBJECT_DENY_SETXATTR,
			HDN_AUTH_OBJECT_SETXATTR,
			HDN_TRANS_OBJECT_SETXATTR);
		if (ret)
			return ret;
	} else if (operation == HDN_XATTR_REMOVE) {
		ret = hdn_authorize_object_dentry_policy(
			dentry, HDN_OBJECT_DENY_REMOVEXATTR,
			HDN_AUTH_OBJECT_REMOVEXATTR,
			HDN_TRANS_OBJECT_REMOVEXATTR);
		if (ret)
			return ret;
	}

	ret = hdn_authorize_object_dentry_policy(dentry, HDN_OBJECT_DENY_XATTR,
						 HDN_AUTH_OBJECT_XATTR,
						 HDN_TRANS_OBJECT_XATTR);
	if (ret)
		return ret;

	if (operation == HDN_XATTR_SET || operation == HDN_XATTR_REMOVE)
		return hdn_authorize_object_attr_dentry(dentry);

	return 0;
}

static int hdn_authorize_object_exec_file(struct file *file)
{
	struct inode *inode;
	unsigned int decision;

	if (!file)
		return 0;

	inode = file_inode(file);
	if (!inode || !S_ISREG(inode->i_mode))
		return 0;

	decision = hdn_object_access_decision(&file->f_path,
					      hdn_current_profile_id(),
					      HDN_OBJECT_DENY_EXEC);
	return hdn_apply_object_decision(decision, HDN_AUTH_OBJECT_EXEC,
				 HDN_TRANS_OBJECT_EXEC, -EACCES,
				 hdn_file_object_id(file));
}

int hdn_authorize_object_write(const struct path *path)
{
	const struct inode *inode;
	unsigned int decision;

	if (!path || !path->dentry)
		return 0;

	inode = d_inode(path->dentry);
	if (!hdn_object_can_stream_io(inode))
		return 0;

	decision = hdn_object_access_decision(path, hdn_current_profile_id(),
					      HDN_OBJECT_DENY_WRITE);
	return hdn_apply_object_decision(decision, HDN_AUTH_OBJECT_WRITE,
				 HDN_TRANS_OBJECT_WRITE, -EACCES,
				 hdn_path_object_id(path));
}

static int hdn_authorize_object_append_only(const struct path *path,
					    u64 object_id, bool append_write)
{
	const struct inode *inode;
	unsigned int decision;

	if (!path || !path->dentry)
		return 0;

	inode = d_inode(path->dentry);
	if (!inode || !S_ISREG(inode->i_mode))
		return 0;

	decision = hdn_object_access_decision(path, hdn_current_profile_id(),
					      HDN_OBJECT_APPEND_ONLY);
	if (append_write)
		return hdn_apply_object_decision(
			decision & HDN_OBJECT_DECISION_AUDIT,
			HDN_AUTH_OBJECT_APPEND, HDN_TRANS_OBJECT_APPEND,
			-EACCES, object_id);
	if (!(decision & HDN_OBJECT_DECISION_DENY))
		return 0;

	return hdn_apply_object_decision(decision, HDN_AUTH_OBJECT_APPEND,
				 HDN_TRANS_OBJECT_APPEND, -EACCES, object_id);
}

int hdn_authorize_object_write_open(const struct path *path, bool append_write)
{
	int ret;

	ret = hdn_authorize_object_write(path);
	if (ret)
		return ret;

	return hdn_authorize_object_append_only(path, hdn_path_object_id(path),
						append_write);
}

int hdn_authorize_object_write_file(struct file *file, bool append_write)
{
	int ret;

	if (!file)
		return 0;

	ret = hdn_authorize_object_write(&file->f_path);
	if (ret)
		return ret;

	return hdn_authorize_object_append_only(&file->f_path,
						hdn_file_object_id(file),
						append_write);
}
EXPORT_SYMBOL_GPL(hdn_authorize_object_write_file);

int hdn_authorize_object_lock(struct file *file, unsigned int cmd)
{
	if (!file || cmd == F_UNLCK)
		return 0;

	if (!hdn_object_access_denied(&file->f_path, hdn_current_profile_id(),
				      HDN_OBJECT_DENY_LOCK))
		return 0;

	return hdn_deny_object(HDN_AUTH_OBJECT_LOCK,
			       HDN_TRANS_OBJECT_LOCK,
			       HDN_REASON_OBJECT_POLICY, -EACCES,
			       hdn_file_object_id(file));
}

int hdn_authorize_object_watch(const struct path *path)
{
	if (!path || !path->dentry)
		return 0;

	if (!hdn_object_access_denied(path, hdn_current_profile_id(),
				      HDN_OBJECT_DENY_WATCH))
		return 0;

	return hdn_deny_object(HDN_AUTH_OBJECT_WATCH,
			       HDN_TRANS_OBJECT_WATCH,
				       HDN_REASON_OBJECT_POLICY, -EACCES,
				       hdn_path_object_id(path));
}

int hdn_authorize_object_receive(struct file *file)
{
	if (!file)
		return 0;

	if (!hdn_object_access_denied(&file->f_path, hdn_current_profile_id(),
				      HDN_OBJECT_DENY_RECEIVE))
		return 0;

	return hdn_deny_object(HDN_AUTH_OBJECT_RECEIVE,
			       HDN_TRANS_OBJECT_RECEIVE,
			       HDN_REASON_OBJECT_POLICY, -EACCES,
			       hdn_file_object_id(file));
}

static bool hdn_fcntl_cmd_controls_file(unsigned int cmd)
{
	switch (cmd) {
	case FIOCLEX:
	case FIONCLEX:
	case FIONBIO:
	case FIOASYNC:
	case F_DUPFD:
	case F_DUPFD_CLOEXEC:
	case F_SETFD:
	case F_SETFL:
	case F_SETLK:
	case F_SETLKW:
#ifdef F_SETLK64
#if F_SETLK64 != F_SETLK
	case F_SETLK64:
#endif
#endif
#ifdef F_SETLKW64
#if F_SETLKW64 != F_SETLKW
	case F_SETLKW64:
#endif
#endif
	case F_SETOWN:
	case F_SETOWN_EX:
	case F_SETSIG:
	case F_SETLEASE:
	case F_NOTIFY:
	case F_SETPIPE_SZ:
	case F_ADD_SEALS:
	case F_SET_RW_HINT:
	case F_SETDELEG:
	case F_OFD_SETLK:
	case F_OFD_SETLKW:
		return true;
	default:
		return false;
	}
}

int hdn_authorize_object_ioctl(struct file *file, unsigned int cmd)
{
	int ret;

	if (!file)
		return 0;

	if (hdn_fcntl_cmd_controls_file(cmd)) {
		ret = hdn_authorize_object_fcntl(file, cmd);
		if (ret)
			return ret;
	}

	if (!hdn_object_access_denied(&file->f_path, hdn_current_profile_id(),
				      HDN_OBJECT_DENY_IOCTL))
		return 0;

	return hdn_deny_object(HDN_AUTH_OBJECT_IOCTL,
			       HDN_TRANS_OBJECT_IOCTL,
			       HDN_REASON_OBJECT_POLICY, -EACCES,
			       hdn_file_object_id(file));
}

int hdn_authorize_object_fcntl(struct file *file, unsigned int cmd)
{
	if (!file || !hdn_fcntl_cmd_controls_file(cmd))
		return 0;

	if (!hdn_object_access_denied(&file->f_path, hdn_current_profile_id(),
				      HDN_OBJECT_DENY_FCNTL))
		return 0;

	return hdn_deny_object(HDN_AUTH_OBJECT_FCNTL,
			       HDN_TRANS_OBJECT_FCNTL,
			       HDN_REASON_OBJECT_POLICY, -EACCES,
			       hdn_file_object_id(file));
}

int hdn_authorize_object_mount(const struct path *path)
{
	if (!hdn_object_access_denied(path, hdn_current_profile_id(),
				      HDN_OBJECT_DENY_MOUNT))
		return 0;

	return hdn_deny_object(HDN_AUTH_OBJECT_MOUNT,
			       HDN_TRANS_OBJECT_MOUNT,
			       HDN_REASON_OBJECT_POLICY, -EACCES,
			       hdn_path_object_id(path));
}

int hdn_authorize_object_mount_source(const struct path *path)
{
	if (!hdn_object_access_denied(path, hdn_current_profile_id(),
				      HDN_OBJECT_DENY_MOUNT_SOURCE))
		return 0;

	return hdn_deny_object(HDN_AUTH_OBJECT_MOUNT_SOURCE,
			       HDN_TRANS_OBJECT_MOUNT_SOURCE,
			       HDN_REASON_OBJECT_POLICY, -EACCES,
			       hdn_path_object_id(path));
}

int hdn_authorize_object_umount(const struct path *path)
{
	if (!hdn_object_access_denied(path, hdn_current_profile_id(),
				      HDN_OBJECT_DENY_UMOUNT))
		return 0;

	return hdn_deny_object(HDN_AUTH_OBJECT_UMOUNT,
			       HDN_TRANS_OBJECT_UMOUNT,
			       HDN_REASON_OBJECT_POLICY, -EACCES,
			       hdn_path_object_id(path));
}

int hdn_authorize_object_truncate(const struct path *path)
{
	if (!hdn_object_access_denied(path, hdn_current_profile_id(),
				      HDN_OBJECT_DENY_TRUNCATE))
		return 0;

	return hdn_deny_object(HDN_AUTH_OBJECT_TRUNCATE,
			       HDN_TRANS_OBJECT_TRUNCATE,
			       HDN_REASON_OBJECT_POLICY, -EACCES,
			       hdn_path_object_id(path));
}

int hdn_authorize_object_unix_connect(const struct path *path)
{
	if (!hdn_object_access_denied(path, hdn_current_profile_id(),
				      HDN_OBJECT_DENY_UNIX_CONNECT))
		return 0;

	return hdn_deny_object(HDN_AUTH_OBJECT_UNIX_CONNECT,
			       HDN_TRANS_OBJECT_UNIX_CONNECT,
			       HDN_REASON_OBJECT_POLICY, -EACCES,
			       hdn_path_object_id(path));
}

int hdn_authorize_object_unix_listen(const struct path *path)
{
	if (!hdn_object_access_denied(path, hdn_current_profile_id(),
				      HDN_OBJECT_DENY_UNIX_LISTEN))
		return 0;

	return hdn_deny_object(HDN_AUTH_OBJECT_UNIX_LISTEN,
			       HDN_TRANS_OBJECT_UNIX_LISTEN,
			       HDN_REASON_OBJECT_POLICY, -EACCES,
			       hdn_path_object_id(path));
}

int hdn_authorize_object_unix_accept(const struct path *path)
{
	if (!hdn_object_access_denied(path, hdn_current_profile_id(),
				      HDN_OBJECT_DENY_UNIX_ACCEPT))
		return 0;

	return hdn_deny_object(HDN_AUTH_OBJECT_UNIX_ACCEPT,
			       HDN_TRANS_OBJECT_UNIX_ACCEPT,
			       HDN_REASON_OBJECT_POLICY, -EACCES,
			       hdn_path_object_id(path));
}

int hdn_authorize_object_unix_send(const struct path *path)
{
	if (!hdn_object_access_denied(path, hdn_current_profile_id(),
				      HDN_OBJECT_DENY_UNIX_SEND))
		return 0;

	return hdn_deny_object(HDN_AUTH_OBJECT_UNIX_SEND,
			       HDN_TRANS_OBJECT_UNIX_SEND,
			       HDN_REASON_OBJECT_POLICY, -EACCES,
			       hdn_path_object_id(path));
}

int hdn_authorize_object_unix_recv(const struct path *path)
{
	if (!hdn_object_access_denied(path, hdn_current_profile_id(),
				      HDN_OBJECT_DENY_UNIX_RECV))
		return 0;

	return hdn_deny_object(HDN_AUTH_OBJECT_UNIX_RECV,
			       HDN_TRANS_OBJECT_UNIX_RECV,
			       HDN_REASON_OBJECT_POLICY, -EACCES,
			       hdn_path_object_id(path));
}

static bool hdn_unix_abstract_name(const struct sockaddr_un *addr,
				   unsigned int addr_len, const char **name,
				   size_t *name_len)
{
	size_t offset = offsetof(struct sockaddr_un, sun_path);

	if (!addr || addr_len <= offset + 1)
		return false;
	if (addr->sun_path[0])
		return false;

	*name = addr->sun_path + 1;
	*name_len = addr_len - offset - 1;
	return *name_len > 0;
}

int hdn_authorize_object_unix_abstract(
	const struct sockaddr_un *addr, unsigned int addr_len,
	enum hdn_unix_abstract_operation operation)
{
	enum hdn_authority authority;
	enum hdn_transition transition;
	const char *name;
	size_t name_len;
	u64 deny_flag;

	if (!hdn_unix_abstract_name(addr, addr_len, &name, &name_len))
		return 0;

	switch (operation) {
	case HDN_UNIX_ABSTRACT_CONNECT:
		deny_flag = HDN_OBJECT_DENY_UNIX_CONNECT;
		authority = HDN_AUTH_OBJECT_UNIX_CONNECT;
		transition = HDN_TRANS_OBJECT_UNIX_CONNECT;
		break;
	case HDN_UNIX_ABSTRACT_BIND:
		deny_flag = HDN_OBJECT_DENY_UNIX_BIND;
		authority = HDN_AUTH_OBJECT_UNIX_BIND;
		transition = HDN_TRANS_OBJECT_UNIX_BIND;
		break;
	case HDN_UNIX_ABSTRACT_LISTEN:
		deny_flag = HDN_OBJECT_DENY_UNIX_LISTEN;
		authority = HDN_AUTH_OBJECT_UNIX_LISTEN;
		transition = HDN_TRANS_OBJECT_UNIX_LISTEN;
		break;
	case HDN_UNIX_ABSTRACT_ACCEPT:
		deny_flag = HDN_OBJECT_DENY_UNIX_ACCEPT;
		authority = HDN_AUTH_OBJECT_UNIX_ACCEPT;
		transition = HDN_TRANS_OBJECT_UNIX_ACCEPT;
		break;
	case HDN_UNIX_ABSTRACT_SEND:
		deny_flag = HDN_OBJECT_DENY_UNIX_SEND;
		authority = HDN_AUTH_OBJECT_UNIX_SEND;
		transition = HDN_TRANS_OBJECT_UNIX_SEND;
		break;
	case HDN_UNIX_ABSTRACT_RECV:
		deny_flag = HDN_OBJECT_DENY_UNIX_RECV;
		authority = HDN_AUTH_OBJECT_UNIX_RECV;
		transition = HDN_TRANS_OBJECT_UNIX_RECV;
		break;
	default:
		return 0;
	}

	if (!hdn_object_unix_abstract_denied(name, name_len,
					     hdn_current_profile_id(),
					     deny_flag))
		return 0;

	return hdn_deny_object(authority, transition,
			       HDN_REASON_OBJECT_POLICY, -EACCES,
			       hdn_bytes_object_id(name, name_len));
}

static bool hdn_module_rule_matches(const struct hdn_module_rule_record *rule,
				    const struct hdn_file_identity *file_id,
				    u64 profile_id)
{
	if (rule->profile_id != profile_id)
		return false;
	/* The normal module loader performs the cryptographic check next. */
	if ((rule->flags & HDN_MODULE_MATCH_TRUSTED_SIGNATURE) &&
	    !is_module_sig_enforced())
		return false;

	if ((rule->flags & HDN_MODULE_MATCH_FILE_ID) &&
	    !hdn_identity_matches(file_id, rule->file_dev_major,
				  rule->file_dev_minor, rule->file_ino))
		return false;

	if (rule->flags & HDN_MODULE_MATCH_VERITY_DIGEST) {
		if (file_id->verity_digest_size != rule->verity_digest_size ||
		    file_id->verity_digest_algorithm !=
		    rule->verity_digest_algorithm)
			return false;
		if (memcmp(file_id->verity_digest, rule->verity_digest,
			   rule->verity_digest_size))
			return false;
	}

	return true;
}

static bool hdn_module_file_allowed(struct file *file, u64 profile_id)
{
	struct hdn_file_identity file_id;
	struct hdn_policy *policy;
	bool allowed = false;
	u32 i;

	hdn_file_identity_from_file(file, &file_id);

	rcu_read_lock();
	policy = rcu_dereference(hdn_active_policy);
	if (!policy) {
		allowed = true;
	} else {
		for (i = 0; i < policy->module_rule_count; i++) {
			if (!hdn_module_rule_matches(&policy->module_rules[i],
						     &file_id, profile_id))
				continue;
			allowed = true;
			break;
		}
	}
	rcu_read_unlock();

	return allowed;
}

static bool hdn_firmware_name_allowed(const char *name, u64 profile_id)
{
	struct hdn_policy *policy;
	bool allowed = false;
	u32 i;

	if (!name)
		return false;

	rcu_read_lock();
	policy = rcu_dereference(hdn_active_policy);
	if (!policy) {
		allowed = true;
	} else {
		for (i = 0; i < policy->firmware_rule_count; i++) {
			const struct hdn_firmware_rule_record *rule =
				&policy->firmware_rules[i];

			if (rule->profile_id != profile_id)
				continue;
			if (rule->flags & HDN_FIRMWARE_MATCH_ANY) {
				allowed = true;
				break;
			}
			if (strncmp(rule->name, name, HDN_FIRMWARE_NAME_LEN))
				continue;
			allowed = true;
			break;
		}
	}
	rcu_read_unlock();

	return allowed;
}

static bool hdn_subject_rule_matches(const struct hdn_subject_rule_record *rule,
				     const struct cred *cred)
{
	if (rule->flags == HDN_SUBJECT_MATCH_UID) {
		kuid_t uid = make_kuid(&init_user_ns, rule->id);

		return uid_valid(uid) &&
		       (uid_eq(cred->uid, uid) || uid_eq(cred->euid, uid) ||
			uid_eq(cred->suid, uid) || uid_eq(cred->fsuid, uid));
	}

	if (rule->flags == HDN_SUBJECT_MATCH_GID) {
		kgid_t gid = make_kgid(&init_user_ns, rule->id);

		return gid_valid(gid) &&
		       (gid_eq(cred->gid, gid) || gid_eq(cred->egid, gid) ||
			gid_eq(cred->sgid, gid) || gid_eq(cred->fsgid, gid) ||
			groups_search(cred->group_info, gid));
	}

	return false;
}

static u64 hdn_subject_profile_id(const struct hdn_policy *policy,
				  const struct cred *cred)
{
	u32 i;

	if (!policy || !cred)
		return 0;

	for (i = 0; i < policy->subject_rule_count; i++) {
		if (hdn_subject_rule_matches(&policy->subject_rules[i], cred))
			return policy->subject_rules[i].profile_id;
	}

	return 0;
}

static u64 hdn_transition_profile_id(const struct cred *cred, bool privileged)
{
	struct hdn_policy *policy;
	u64 profile_id;

	rcu_read_lock();
	policy = rcu_dereference(hdn_active_policy);
	if (privileged)
		profile_id = policy ? policy->privileged_profile_id :
				      HDN_PROFILE_PRIVILEGED;
	else {
		profile_id = hdn_subject_profile_id(policy, cred);
		if (!profile_id)
			profile_id = policy ? policy->default_profile_id :
					      HDN_PROFILE_DEFAULT;
	}
	rcu_read_unlock();

	return profile_id;
}

static u64 hdn_exec_profile_id(struct linux_binprm *bprm)
{
	struct hdn_file_identity file_id;
	struct hdn_policy *policy;
	u64 parent_profile;
	u64 profile_id = 0;
	u64 epoch;
	unsigned int sequence;
	u32 i;

retry:
	profile_id = 0;
	bprm->hardening_compat_epoch = 0;
	bprm->hardening_compat_managed = false;
	memset(bprm->hardening_compat_path, 0, sizeof(bprm->hardening_compat_path));
	bprm->hardening_profile_pinned = false;
	bprm->hardening_profile_inherit_audit = false;
	hdn_file_identity_from_file(bprm->file, &file_id);
	parent_profile = hdn_current_profile_id();

	rcu_read_lock();
	sequence = read_seqbegin(&hdn_policy_publication_lock);
	epoch = atomic64_read(&hdn_policy_epoch);
	policy = rcu_dereference(hdn_active_policy);
	if (policy) {
		for (i = 0; i < policy->exec_rule_count; i++) {
			if (policy->exec_rules[i].flags & HDN_EXEC_COMPAT_LEASE) {
				const struct hdn_exec_rule_record *rule = &policy->exec_rules[i];

				/* Failed bindings cannot fall back to embedded ELF grants. */
				if (hdn_compat_path_matches(bprm->file, rule->file_path) ||
				    hdn_identity_matches(&file_id, rule->file_dev_major,
						 rule->file_dev_minor, rule->file_ino) ||
				    (file_id.verity_digest_size == rule->verity_digest_size &&
				     file_id.verity_digest_algorithm == rule->verity_digest_algorithm &&
				     !memcmp(file_id.verity_digest, rule->verity_digest, rule->verity_digest_size)))
					bprm->hardening_compat_managed = true;
				if (!READ_ONCE(hdn_compat_policy_enabled))
					continue;
			}
			if (!hdn_exec_rule_matches(&policy->exec_rules[i],
						   bprm, &file_id,
						   parent_profile))
				continue;
			if (policy->exec_rules[i].flags &
			    HDN_EXEC_INHERIT_PROFILE) {
				profile_id = parent_profile;
				bprm->hardening_profile_inherit_audit =
					policy->exec_rules[i].flags &
					HDN_EXEC_AUDIT_INHERIT;
			} else {
				profile_id =
					policy->exec_rules[i].target_profile_id;
			}
			bprm->hardening_profile_pinned = true;
			if (policy->exec_rules[i].flags & HDN_EXEC_COMPAT_LEASE) {
				bprm->hardening_compat_epoch = epoch;
				memcpy(bprm->hardening_compat_path,
				       policy->exec_rules[i].file_path,
				       sizeof(bprm->hardening_compat_path));
			}
			break;
		}
	}
	if (read_seqretry(&hdn_policy_publication_lock, sequence)) {
		rcu_read_unlock();
		goto retry;
	}
	rcu_read_unlock();

	if (profile_id)
		return profile_id;

	/*
	 * Sandboxes cannot enumerate the inode identities mounted later as their
	 * payload. A signed launcher profile may retain its boundary for an
	 * otherwise unmatched, non-privileged child exec. Explicit rules above
	 * and privileged transitions always take precedence.
	 */
	if (!hdn_bprm_privileged(bprm) &&
	    hdn_profile_id_flag_enabled(
		    parent_profile, HDN_PROFILE_INHERIT_UNMATCHED_EXEC)) {
		bprm->hardening_profile_pinned = true;
		return parent_profile;
	}

	return hdn_transition_profile_id(bprm->cred, hdn_bprm_privileged(bprm));
}

static bool hdn_creds_privileged(const struct cred *new,
				 const struct cred *old)
{
	if (uid_eq(new->euid, GLOBAL_ROOT_UID))
		return true;
	if (gid_eq(new->egid, GLOBAL_ROOT_GID))
		return true;
	if (new->user_ns != old->user_ns)
		return true;
	if (!cap_issubset(new->cap_permitted, old->cap_permitted))
		return true;
	if (!cap_issubset(new->cap_effective, old->cap_effective))
		return true;

	return false;
}

static bool hdn_creds_changed(const struct cred *new, const struct cred *old)
{
	if (!uid_eq(new->uid, old->uid) || !uid_eq(new->euid, old->euid) ||
	    !uid_eq(new->suid, old->suid) || !uid_eq(new->fsuid, old->fsuid))
		return true;
	if (!gid_eq(new->gid, old->gid) || !gid_eq(new->egid, old->egid) ||
	    !gid_eq(new->sgid, old->sgid) || !gid_eq(new->fsgid, old->fsgid))
		return true;
	if (new->user_ns != old->user_ns)
		return true;
	if (new->group_info != old->group_info)
		return true;
	if (!cap_isidentical(new->cap_inheritable, old->cap_inheritable))
		return true;
	if (!cap_isidentical(new->cap_permitted, old->cap_permitted))
		return true;
	if (!cap_isidentical(new->cap_effective, old->cap_effective))
		return true;
	if (!cap_isidentical(new->cap_bset, old->cap_bset))
		return true;
	if (!cap_isidentical(new->cap_ambient, old->cap_ambient))
		return true;

	return false;
}

static bool hdn_kuid_became_root(kuid_t new, kuid_t old)
{
	return uid_eq(new, GLOBAL_ROOT_UID) && !uid_eq(old, GLOBAL_ROOT_UID);
}

static bool hdn_kgid_became_root(kgid_t new, kgid_t old)
{
	return gid_eq(new, GLOBAL_ROOT_GID) && !gid_eq(old, GLOBAL_ROOT_GID);
}

static bool hdn_creds_gain_root_group(const struct cred *new,
				      const struct cred *old)
{
	return groups_search(new->group_info, GLOBAL_ROOT_GID) &&
	       !groups_search(old->group_info, GLOBAL_ROOT_GID);
}

static bool hdn_creds_widen_privilege(const struct cred *new,
				      const struct cred *old)
{
	if (hdn_kuid_became_root(new->uid, old->uid) ||
	    hdn_kuid_became_root(new->euid, old->euid) ||
	    hdn_kuid_became_root(new->suid, old->suid) ||
	    hdn_kuid_became_root(new->fsuid, old->fsuid))
		return true;
	if (hdn_kgid_became_root(new->gid, old->gid) ||
	    hdn_kgid_became_root(new->egid, old->egid) ||
	    hdn_kgid_became_root(new->sgid, old->sgid) ||
	    hdn_kgid_became_root(new->fsgid, old->fsgid))
		return true;
	if (hdn_creds_gain_root_group(new, old))
		return true;
	if (new->user_ns != old->user_ns)
		return true;
	if (!cap_issubset(new->cap_inheritable, old->cap_inheritable))
		return true;
	if (!cap_issubset(new->cap_permitted, old->cap_permitted))
		return true;
	if (!cap_issubset(new->cap_effective, old->cap_effective))
		return true;
	if (!cap_issubset(new->cap_bset, old->cap_bset))
		return true;
	if (!cap_issubset(new->cap_ambient, old->cap_ambient))
		return true;

	return false;
}

static u64 hdn_creds_object_id(const struct cred *new)
{
	return ((u64)from_kuid(&init_user_ns, new->euid) << 32) |
	       from_kgid(&init_user_ns, new->egid);
}

static bool hdn_inode_trusted_for_exec(const struct inode *inode)
{
	if (!inode)
		return false;
	if (!uid_eq(inode->i_uid, GLOBAL_ROOT_UID))
		return false;
	if (inode->i_mode & 0022)
		return false;

	return true;
}

static bool hdn_path_trusted_for_exec(const struct path *path)
{
	struct path walker;
	struct dentry *dentry;
	bool trusted = false;

	if (!path || !path->dentry)
		return false;

	walker = *path;
	path_get(&walker);
	for (;;) {
		if (!hdn_inode_trusted_for_exec(d_inode(walker.dentry)))
			goto out;

		if (walker.dentry == walker.mnt->mnt_root) {
			if (follow_up(&walker))
				continue;
			break;
		}

		if (unlikely(IS_ROOT(walker.dentry))) {
			dput(walker.dentry);
			walker.dentry = dget(walker.mnt->mnt_root);
			continue;
		}

		dentry = dget_parent(walker.dentry);
		dput(walker.dentry);
		walker.dentry = dentry;
	}

	trusted = true;
out:
	path_put(&walker);
	return trusted;
}

static int hdn_authorize_trusted_exec(struct linux_binprm *bprm)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_TRUSTED_EXEC))
		return 0;
	if (!hdn_profile_flag_enabled(HDN_PROFILE_ENFORCE_TRUSTED_EXEC))
		return 0;
	if (hdn_profile_allows(HDN_AUTH_TRUSTED_EXEC_BYPASS,
			       HDN_TRANS_EXEC))
		return 0;
	if (hdn_path_trusted_for_exec(&bprm->file->f_path))
		return 0;

	return hdn_deny_object(HDN_AUTH_TRUSTED_EXEC_BYPASS,
			       HDN_TRANS_EXEC,
			       HDN_REASON_UNTRUSTED_EXEC_PATH, -EACCES,
			       hdn_file_object_id(bprm->file));
}

static bool hdn_kuid_nonroot(kuid_t uid)
{
	return uid_valid(uid) && !uid_eq(uid, GLOBAL_ROOT_UID);
}

static bool hdn_kgid_nonroot(kgid_t gid)
{
	return gid_valid(gid) && !gid_eq(gid, GLOBAL_ROOT_GID);
}

static bool hdn_path_untrusted_for_user_tpe(const struct path *path)
{
	struct mnt_idmap *idmap;
	struct dentry *parent;
	struct inode *dir_inode;
	struct inode *file_inode;
	kuid_t dir_uid;
	kgid_t dir_gid;
	bool untrusted = true;

	if (!path || !path->dentry || !path->mnt)
		return true;

	file_inode = d_inode(path->dentry);
	if (!file_inode)
		return true;

	parent = dget_parent(path->dentry);
	dir_inode = d_inode(parent);
	if (!dir_inode)
		goto out;

	idmap = mnt_idmap(path->mnt);
	dir_uid = vfsuid_into_kuid(i_uid_into_vfsuid(idmap, dir_inode));
	dir_gid = vfsgid_into_kgid(i_gid_into_vfsgid(idmap, dir_inode));

	if (!uid_valid(dir_uid) || !gid_valid(dir_gid))
		goto out;
	if (hdn_kuid_nonroot(dir_uid))
		goto out;
	if (dir_inode->i_mode & S_IWOTH)
		goto out;
	if ((dir_inode->i_mode & S_IWGRP) && hdn_kgid_nonroot(dir_gid))
		goto out;
	if (file_inode->i_mode & S_IWOTH)
		goto out;

	untrusted = false;
out:
	dput(parent);
	return untrusted;
}

static int hdn_authorize_untrusted_user_file(struct file *file,
					     enum hdn_transition transition)
{
	const struct cred *cred = current_cred();

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_TRUSTED_EXEC))
		return 0;
	if (!file)
		return 0;
	if (!hdn_profile_flag_enabled(HDN_PROFILE_DENY_UNTRUSTED_USER_EXEC))
		return 0;
	if (uid_eq(cred->uid, GLOBAL_ROOT_UID))
		return 0;
	if (hdn_profile_allows(HDN_AUTH_TRUSTED_EXEC_BYPASS,
			       transition))
		return 0;
	if (!hdn_path_untrusted_for_user_tpe(&file->f_path))
		return 0;

	return hdn_deny_object(HDN_AUTH_TRUSTED_EXEC_BYPASS,
			       transition,
			       HDN_REASON_UNTRUSTED_EXEC_PATH, -EACCES,
			       hdn_file_object_id(file));
}

static int hdn_authorize_untrusted_user_exec(struct linux_binprm *bprm)
{
	return hdn_authorize_untrusted_user_file(bprm->file, HDN_TRANS_EXEC);
}

static bool hdn_chroot_containment_enabled(void)
{
	return IS_ENABLED(CONFIG_SECURITY_HARDENING_CHROOT_CONTAINMENT) &&
	       hdn_profile_flag_enabled(HDN_PROFILE_CHROOT_CONTAINED);
}

static bool hdn_path_under_current_root(const struct path *path)
{
	struct path root;
	bool under;

	get_fs_root(current->fs, &root);
	under = path_is_under(path, &root);
	path_put(&root);
	return under;
}

int hdn_mmap_rewrite(struct hdn_mmap_request *req)
{
	if (req->file && (req->prot & PROT_READ)) {
		int ret = hdn_authorize_object_read_file(req->file);

		if (ret)
			return ret;
	}

	if (req->file && (req->prot & PROT_WRITE)) {
		switch (req->flags & MAP_TYPE) {
		case MAP_SHARED:
		case MAP_SHARED_VALIDATE: {
			int ret = hdn_authorize_object_write_file(req->file, false);

			if (ret)
				return ret;
			break;
		}
		}
	}

	if (req->file && (req->prot & PROT_EXEC)) {
		int ret = hdn_authorize_object_exec_file(req->file);

		if (ret)
			return ret;
	}

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_USER_WX))
		return 0;

	if (req->read_implies_exec &&
	    !hdn_memory_allows(HDN_MEM_ALLOW_READ_IMPLIES_EXEC)) {
		req->prot &= ~PROT_EXEC;
		hdn_rewrite_object(HDN_AUTH_MMAP, HDN_TRANS_MMAP,
				   HDN_REASON_READ_IMPLIES_EXEC,
				   hdn_file_object_id(req->file));
	}

	if (req->file && (req->prot & PROT_EXEC)) {
		int ret = hdn_authorize_untrusted_user_file(req->file,
							    HDN_TRANS_MMAP);

		if (ret)
			return ret;
	}

	if (req->file && !req->pgoff && (req->prot & PROT_EXEC) &&
	    hdn_file_has_executable_gnu_stack(req->file) &&
	    !hdn_memory_allows(HDN_MEM_ALLOW_EXEC_STACK_ELF) &&
	    !hdn_exec_memory_allows(HDN_MEM_ALLOW_EXEC_STACK_ELF)) {
		return hdn_deny_object(HDN_AUTH_MMAP, HDN_TRANS_MMAP,
				       HDN_REASON_EXEC_STACK_ELF, -EACCES,
				       hdn_file_object_id(req->file));
	}

	if ((req->prot & PROT_WRITE) && (req->prot & PROT_EXEC) &&
	    !hdn_memory_allows(HDN_MEM_ALLOW_WX)) {
		hdn_record_rwxmap_denial(HDN_AUTH_MMAP, HDN_TRANS_MMAP,
					 hdn_file_object_id(req->file));
		return hdn_deny_object(HDN_AUTH_MMAP, HDN_TRANS_MMAP,
				       HDN_REASON_USER_WX_MAPPING, -EACCES,
				       hdn_file_object_id(req->file));
	}

	if (!req->file && (req->flags & MAP_FIXED) &&
	    (req->prot & PROT_EXEC) &&
	    !hdn_memory_allows(HDN_MEM_ALLOW_FIXED_ANON_EXEC))
		return hdn_deny_object(HDN_AUTH_MMAP, HDN_TRANS_MMAP,
				       HDN_REASON_FIXED_ANON_EXEC_MAPPING,
				       -EACCES, req->addr);

	return 0;
}

void hdn_mmap_committed(const struct hdn_mmap_request *req)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_RWXMAP_AUDIT))
		return;
	if (!req->file || req->pgoff || !(req->prot & PROT_EXEC))
		return;
	if (!hdn_file_has_executable_gnu_stack(req->file))
		return;

	hdn_record_event_object_flags(HDN_AUTH_MMAP, HDN_TRANS_MMAP,
				      HDN_REASON_EXEC_STACK_ELF,
				      HDN_DECISION_ALLOW_AUDIT, 0,
				      hdn_file_object_id(req->file), 0);
}

int hdn_mprotect_validate(struct hdn_mprotect_request *req)
{
	bool relro_allowed;
	bool relro_target;
	bool removes_write;
	bool textrel_allowed;
	bool textrel_mprotect;
	bool adds_exec;
	bool adds_read;
	bool adds_write;

	adds_read = !(req->oldflags & VM_READ) && (req->newflags & VM_READ);
	adds_exec = !(req->oldflags & VM_EXEC) && (req->newflags & VM_EXEC);
	adds_write = !(req->oldflags & VM_WRITE) && (req->newflags & VM_WRITE);
	removes_write = (req->oldflags & VM_WRITE) &&
			!(req->newflags & VM_WRITE);
	if (adds_read && req->vma && req->vma->vm_file) {
		int ret = hdn_authorize_object_read_file(req->vma->vm_file);

		if (ret)
			return ret;
	}

	if (adds_write && (req->newflags & VM_SHARED) && req->vma &&
	    req->vma->vm_file) {
		int ret = hdn_authorize_object_write_file(req->vma->vm_file,
							  false);

		if (ret)
			return ret;
	}

	if (adds_exec && req->vma && req->vma->vm_file) {
		int ret = hdn_authorize_object_exec_file(req->vma->vm_file);

		if (ret)
			return ret;
	}

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_USER_WX))
		return 0;

	relro_target = hdn_mprotect_targets_relro(req);
	relro_allowed = hdn_memory_allows(HDN_MEM_ALLOW_RELRO_WRITE);
	if (relro_target && adds_write && !(req->oldflags & VM_MAYWRITE) &&
	    !relro_allowed)
		return hdn_deny_object(HDN_AUTH_MPROTECT,
				       HDN_TRANS_MPROTECT,
				       HDN_REASON_RELRO_WRITE, -EACCES,
				       hdn_vma_object_id(req->vma));
	if (relro_target && removes_write && !relro_allowed)
		req->newflags &= ~VM_MAYWRITE;
	if (relro_target && adds_write && relro_allowed)
		hdn_record_event_object_flags(HDN_AUTH_MPROTECT,
					      HDN_TRANS_MPROTECT,
					      HDN_REASON_RELRO_WRITE,
					      HDN_DECISION_ALLOW_AUDIT, 0,
					      hdn_vma_object_id(req->vma), 0);

	textrel_mprotect = hdn_mprotect_is_textrel(req);
	textrel_allowed =
		hdn_memory_allows(HDN_MEM_ALLOW_TEXTREL_MPROTECT) ||
		hdn_exec_memory_allows(HDN_MEM_ALLOW_TEXTREL_MPROTECT);

	if ((req->newflags & VM_WRITE) && (req->newflags & VM_EXEC) &&
	    !hdn_memory_allows(HDN_MEM_ALLOW_WX)) {
		hdn_record_textrel_mprotect(req, HDN_DECISION_DENY_AUDIT,
					    -EACCES);
		hdn_record_rwxmap_denial(HDN_AUTH_MPROTECT,
					 HDN_TRANS_MPROTECT,
					 hdn_vma_object_id(req->vma));
		return hdn_deny_object(HDN_AUTH_MPROTECT, HDN_TRANS_MPROTECT,
				       HDN_REASON_USER_WX_MAPPING, -EACCES,
				       hdn_vma_object_id(req->vma));
	}

	if (adds_exec && req->vma && req->vma->vm_file) {
		int ret = hdn_authorize_untrusted_user_file(req->vma->vm_file,
							    HDN_TRANS_MPROTECT);

		if (ret)
			return ret;
	}
	if (!textrel_allowed && textrel_mprotect)
		return hdn_deny_object(HDN_AUTH_MPROTECT, HDN_TRANS_MPROTECT,
				       HDN_REASON_TEXTREL_MPROTECT,
				       -EACCES, hdn_vma_object_id(req->vma));

	if (adds_exec && (req->oldflags & VM_WRITE) &&
	    !hdn_memory_allows(HDN_MEM_ALLOW_EXEC_AFTER_WRITE) &&
	    !hdn_jit_mprotect_allows(req) &&
	    !(textrel_allowed && textrel_mprotect)) {
		hdn_record_textrel_mprotect(req, HDN_DECISION_DENY_AUDIT,
					    -EACCES);
		return hdn_deny_object(HDN_AUTH_MPROTECT, HDN_TRANS_MPROTECT,
				       HDN_REASON_EXEC_AFTER_WRITE, -EACCES,
				       hdn_vma_object_id(req->vma));
	}

	hdn_record_textrel_mprotect(req, HDN_DECISION_ALLOW_AUDIT, 0);

	return 0;
}

int hdn_authorize_exec(struct linux_binprm *bprm)
{
	const struct cred *old = current_cred();
	kuid_t locked_uid;
	bool privileged;
	u64 profile_id;
	int ret;

	bprm->hardening_profile_id = hdn_exec_profile_id(bprm);
	profile_id = bprm->hardening_profile_id;
	bprm->hardening_exec_memory_flags =
		hdn_file_elf_memory_flags(bprm->file);
	/* Compatibility grants come solely from the approved profile. */
	if (bprm->hardening_compat_managed)
		bprm->hardening_exec_memory_flags = 0;
	privileged = hdn_bprm_privileged(bprm);
	bprm->hardening_privileged_exec = privileged;
	bprm->hardening_privileged_lineage =
		current->mm &&
		READ_ONCE(current->mm->hardening_privileged_lineage);
	ret = hdn_apply_privexec_limits(bprm);
	if (ret)
		return ret;
	locked_uid = hdn_kernel_lockout_cred_uid(old);
	if (uid_valid(locked_uid))
		return hdn_kernel_lockout_deny(HDN_TRANS_EXEC, locked_uid);
	ret = hdn_authorize_object_exec_file(bprm->file);
	if (ret)
		return ret;
	ret = hdn_authorize_trusted_exec(bprm);
	if (ret)
		return ret;
	ret = hdn_authorize_untrusted_user_exec(bprm);
	if (ret)
		return ret;
	if (privileged &&
	    (hdn_profile_flag_enabled(HDN_PROFILE_DENY_UNPRIVILEGED_PRIVEXEC) ||
	     hdn_profile_id_flag_enabled(profile_id,
					 HDN_PROFILE_DENY_UNPRIVILEGED_PRIVEXEC)) &&
	    !hdn_current_privexec_admin())
		return hdn_deny_object(HDN_AUTH_CRED_CHANGE,
				       HDN_TRANS_CRED_CHANGE,
				       HDN_REASON_UNPRIVILEGED_PRIVEXEC,
				       -EACCES,
				       hdn_file_object_id(bprm->file));
	ret = hdn_brute_authorize_exec(bprm, profile_id);
	if (ret)
		return ret;
	if (!hdn_creds_widen_privilege(bprm->cred, old))
		return 0;
	if (hdn_profile_id_allows(profile_id, HDN_AUTH_CRED_CHANGE,
				  HDN_TRANS_CRED_CHANGE))
		return 0;

	return hdn_deny_object(HDN_AUTH_CRED_CHANGE, HDN_TRANS_CRED_CHANGE,
			       HDN_REASON_PROFILE_DENIED, -EPERM,
			       profile_id);
}

int hdn_authorize_creds(const struct cred *new, const struct cred *old)
{
	kuid_t locked_uid;

	locked_uid = hdn_kernel_lockout_cred_uid(new);
	if (uid_valid(locked_uid)) {
		send_sig(SIGKILL, current, 0);
		return hdn_kernel_lockout_deny(HDN_TRANS_CRED_CHANGE,
					       locked_uid);
	}

	if (!hdn_creds_changed(new, old))
		return 0;
	if (!hdn_creds_widen_privilege(new, old))
		return 0;
	if (current->in_execve)
		return 0;
	if (hdn_profile_allows(HDN_AUTH_CRED_CHANGE, HDN_TRANS_CRED_CHANGE))
		return 0;

	return hdn_deny_object(HDN_AUTH_CRED_CHANGE, HDN_TRANS_CRED_CHANGE,
			       HDN_REASON_PROFILE_DENIED, -EPERM,
			       hdn_creds_object_id(new));
}

static u64 hdn_exec_args_object_id(const struct linux_binprm *bprm)
{
	u64 argc = bprm->argc < 0 ? 0 : (u32)bprm->argc;
	u64 envc = bprm->envc < 0 ? 0 : (u32)bprm->envc;

	return (argc << 32) | envc;
}

void hdn_exec_committed(struct linux_binprm *bprm)
{
	struct hdn_file_identity id;
	struct mm_struct *mm = current->mm;
	u64 profile_id = bprm->hardening_profile_id;

	if (!mm)
		return;
	if (!profile_id)
		profile_id = hdn_exec_profile_id(bprm);
	hdn_file_identity_from_file(bprm->file, &id);
	WRITE_ONCE(mm->hardening_exec_dev_major, id.dev_major);
	WRITE_ONCE(mm->hardening_exec_dev_minor, id.dev_minor);
	WRITE_ONCE(mm->hardening_exec_ino, id.ino);
	WRITE_ONCE(mm->hardening_exec_profile_id, profile_id);
	memcpy(mm->hardening_compat_path, bprm->hardening_compat_path,
	       sizeof(mm->hardening_compat_path));
	WRITE_ONCE(mm->hardening_compat_revoked, false);
	smp_store_release(&mm->hardening_compat_epoch, bprm->hardening_compat_epoch);
	WRITE_ONCE(mm->hardening_exec_memory_flags,
		   bprm->hardening_exec_memory_flags);
	WRITE_ONCE(mm->hardening_exec_privileged,
		   bprm->hardening_privileged_exec);
	WRITE_ONCE(mm->hardening_exec_profile_pinned,
		   bprm->hardening_profile_pinned);
	WRITE_ONCE(mm->hardening_privileged_lineage,
		   bprm->hardening_privileged_lineage ||
		   bprm->hardening_privileged_exec);
	hdn_mm_set_profile(mm, profile_id);
	hdn_apply_suid_spectre(bprm);
	if (bprm->hardening_profile_inherit_audit)
		hdn_record_event_object_flags(
			HDN_AUTH_EXEC, HDN_TRANS_EXEC_INHERIT, HDN_REASON_NONE,
			HDN_DECISION_ALLOW_AUDIT, 0,
			hdn_file_object_id(bprm->file),
			hdn_current_chroot_event_flags());
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_EXEC_AUDIT)) {
		u64 event_flags = hdn_current_chroot_event_flags();

		hdn_record_event_object_flags(HDN_AUTH_EXEC, HDN_TRANS_EXEC,
					      HDN_REASON_NONE,
					      HDN_DECISION_ALLOW_AUDIT, 0,
					      hdn_file_object_id(bprm->file),
					      event_flags);
		hdn_record_event_object_flags(HDN_AUTH_EXEC,
					      HDN_TRANS_EXEC_ARGS,
					      HDN_REASON_NONE,
					      HDN_DECISION_ALLOW_AUDIT, 0,
					      hdn_exec_args_object_id(bprm),
					      event_flags);
	}
}

void hdn_task_exit(long code)
{
	int sig = code & 0x7f;

	if (!sig)
		return;

	hdn_brute_mark_daemon_parent(current->mm, sig);
	hdn_brute_record_crash(current->mm, sig);
}

bool hdn_block_privileged_coredump(int sig)
{
	if (suid_dumpable)
		return false;
	if (sig != SIGXCPU && sig != SIGXFSZ)
		return false;
	if (!current->mm)
		return false;
	if (!READ_ONCE(current->mm->hardening_privileged_lineage))
		return false;

	hdn_record_event_object_flags(HDN_AUTH_NONE, HDN_TRANS_COREDUMP,
				      HDN_REASON_PRIVILEGED_DESCENDANT_COREDUMP,
				      HDN_DECISION_DENY_AUDIT, -EPERM,
				      sig, hdn_current_chroot_event_flags());
	return true;
}

void hdn_creds_committed(const struct cred *new, const struct cred *old)
{
	u64 profile_id;

	if (!current->mm)
		return;
	if (!hdn_creds_changed(new, old))
		return;

	if (new->user_ns != old->user_ns)
		profile_id = hdn_userns_profile_id(new->user_ns);
	else if (READ_ONCE(current->mm->hardening_exec_profile_pinned))
		return;
	else
		profile_id =
			hdn_transition_profile_id(new,
						  hdn_creds_privileged(new,
								       old));
	hdn_mm_set_profile(current->mm, profile_id);
}

int hdn_authorize_userns(const struct cred *new)
{
	u16 max_level;

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_UNPRIV_USERNS))
		return 0;

	if (!hdn_profile_allows(HDN_AUTH_USERNS_CREATE,
				HDN_TRANS_USERNS_CREATE))
		return hdn_deny(HDN_AUTH_USERNS_CREATE,
				HDN_TRANS_USERNS_CREATE,
				HDN_REASON_PROFILE_DENIED, -EPERM);

	max_level = hdn_profile_max_userns_level(hdn_current_profile_id());
	if (max_level && new->user_ns->level >= max_level)
		return hdn_deny_object(HDN_AUTH_USERNS_CREATE,
				       HDN_TRANS_USERNS_CREATE,
				       HDN_REASON_USERNS_DEPTH, -EPERM,
				       new->user_ns->level + 1);

	return 0;
}

int hdn_authorize_bpf_prog_load(u32 prog_type, u32 prog_flags,
				bool is_kernel, bool privileged)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_UNPRIV_BPF))
		return 0;
	if (is_kernel)
		return 0;
	if (hdn_profile_allows(HDN_AUTH_BPF_LOAD, HDN_TRANS_BPF_LOAD))
		return 0;

	return hdn_deny_object(HDN_AUTH_BPF_LOAD, HDN_TRANS_BPF_LOAD,
			       HDN_REASON_PROFILE_DENIED, -EPERM, prog_type);
}

int hdn_authorize_bpf_command(unsigned int cmd, bool is_kernel)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_UNPRIV_BPF))
		return 0;
	if (is_kernel)
		return 0;
	if (hdn_profile_allows(HDN_AUTH_BPF_LOAD, HDN_TRANS_BPF_LOAD))
		return 0;

	return hdn_deny_object(HDN_AUTH_BPF_LOAD, HDN_TRANS_BPF_LOAD,
			       HDN_REASON_PROFILE_DENIED, -EPERM, cmd);
}

int hdn_authorize_vm86(unsigned int cmd)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_VM86))
		return 0;
	if (hdn_profile_allows(HDN_AUTH_RAW_IO, HDN_TRANS_RAW_IO))
		return 0;

	return hdn_deny_object(HDN_AUTH_RAW_IO, HDN_TRANS_RAW_IO,
			       HDN_REASON_PROFILE_DENIED, -EPERM, cmd);
}

int hdn_authorize_perf_event_open(bool kernel_access, bool namespaces,
				  pid_t pid, int cpu, unsigned long flags)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_UNPRIV_PERF_KERNEL))
		return 0;
	if (!kernel_access && !namespaces)
		return 0;
	if (hdn_profile_allows(HDN_AUTH_PERF_OPEN, HDN_TRANS_PERF_OPEN))
		return 0;

	return hdn_deny_object(HDN_AUTH_PERF_OPEN, HDN_TRANS_PERF_OPEN,
			       HDN_REASON_PROFILE_DENIED, -EACCES,
			       ((u64)(u32)pid << 32) | (u32)cpu);
}

static u64 hdn_task_profile_id(struct task_struct *task)
{
	struct mm_struct *mm;
	u64 profile_id;

	mm = get_task_mm(task);
	if (!mm)
		return HDN_PROFILE_PRIVILEGED;

	profile_id = hdn_mm_profile_id(mm);
	mmput(mm);

	return profile_id;
}

static u64 hdn_task_profile_id_nosleep(struct task_struct *task)
{
	struct mm_struct *mm;
	u64 profile_id = HDN_PROFILE_PRIVILEGED;

	task_lock(task);
	mm = task->mm;
	if (mm)
		profile_id = hdn_mm_profile_id(mm);
	task_unlock(task);

	return profile_id;
}

static bool hdn_signal_target_is_direct_child(struct task_struct *target)
{
	return rcu_dereference(target->real_parent) == current;
}

int hdn_authorize_signal(struct task_struct *target, int sig)
{
	u64 target_profile_id;

	if (!target || target == current)
		return 0;
	if (same_thread_group(current, target))
		return 0;
	if (hdn_signal_target_is_direct_child(target))
		return 0;

	target_profile_id = hdn_task_profile_id_nosleep(target);
	if (hdn_current_profile_id() == target_profile_id)
		return 0;
	if (hdn_profile_allows(HDN_AUTH_SIGNAL, HDN_TRANS_SIGNAL))
		return 0;

	return hdn_deny_object(HDN_AUTH_SIGNAL, HDN_TRANS_SIGNAL,
			       HDN_REASON_PROFILE_DENIED, -EPERM,
			       task_pid_nr(target));
}

static int hdn_authorize_object_ptrace_target(struct task_struct *target)
{
	struct file *exe_file;
	int ret = 0;

	if (!target || target == current)
		return 0;

	exe_file = get_task_exe_file(target);
	if (!exe_file)
		return 0;

	if (hdn_object_access_denied(&exe_file->f_path, hdn_current_profile_id(),
				     HDN_OBJECT_DENY_PTRACE))
		ret = hdn_deny_object(HDN_AUTH_OBJECT_PTRACE,
				      HDN_TRANS_OBJECT_PTRACE,
				      HDN_REASON_OBJECT_POLICY, -EPERM,
				      hdn_file_object_id(exe_file));

	fput(exe_file);
	return ret;
}

int hdn_authorize_ptrace(struct task_struct *target, long request,
			 unsigned long addr, unsigned long data)
{
	int ret;

	if (target == current)
		return 0;

	ret = hdn_authorize_object_ptrace_target(target);
	if (ret)
		return ret;

	return hdn_authorize_ptrace_profile(hdn_task_profile_id(target),
					    task_pid_nr(target));
}

int hdn_authorize_ptrace_access(struct task_struct *target, unsigned int mode)
{
	u64 target_profile_id;

	if (mode & PTRACE_MODE_ATTACH)
		return hdn_authorize_ptrace(target, 0, 0, 0);
	if (!target || target == current || same_thread_group(current, target))
		return 0;

	target_profile_id = hdn_task_profile_id(target);
	if (hdn_current_profile_id() == target_profile_id)
		return 0;
	if (hdn_profile_allows(HDN_AUTH_PROC_DISCLOSE,
			       HDN_TRANS_PROCFS_READ))
		return 0;
	if (hdn_profile_allows(HDN_AUTH_PTRACE, HDN_TRANS_PTRACE))
		return 0;

	return hdn_deny_object(HDN_AUTH_PROC_DISCLOSE, HDN_TRANS_PROCFS_READ,
			       HDN_REASON_PROFILE_DENIED, -EPERM,
			       task_pid_nr(target));
}

int hdn_authorize_ptrace_profile(u64 target_profile_id, pid_t target_pid)
{
	if (hdn_current_profile_id() == target_profile_id)
		return 0;
	if (hdn_profile_allows(HDN_AUTH_PTRACE, HDN_TRANS_PTRACE))
		return 0;

	return hdn_deny_object(HDN_AUTH_PTRACE, HDN_TRANS_PTRACE,
			       HDN_REASON_PROFILE_DENIED, -EPERM,
			       target_pid);
}

int hdn_authorize_process_memory(struct task_struct *target,
				 struct mm_struct *mm,
				 enum hdn_process_memory_operation operation)
{
	u64 target_profile_id;
	u64 object_id;

	if (!target || target == current)
		return 0;
	if (same_thread_group(current, target))
		return 0;
	if (mm == current->mm)
		return 0;

	target_profile_id = hdn_mm_profile_id(mm);
	if (hdn_current_profile_id() == target_profile_id)
		return 0;
	if (hdn_profile_allows(HDN_AUTH_PROCESS_MEMORY,
			       HDN_TRANS_PROCESS_MEMORY))
		return 0;

	object_id = ((u64)operation << 32) | (u32)task_pid_nr(target);
	return hdn_deny_object(HDN_AUTH_PROCESS_MEMORY,
			       HDN_TRANS_PROCESS_MEMORY,
			       HDN_REASON_PROFILE_DENIED, -EPERM,
			       object_id);
}

int hdn_authorize_memory_migrate(struct task_struct *target,
				 struct mm_struct *mm,
				 enum hdn_memory_migrate_operation operation)
{
	u64 target_profile_id;
	u64 object_id;

	if (!target || target == current)
		return 0;
	if (same_thread_group(current, target))
		return 0;
	if (mm == current->mm)
		return 0;

	target_profile_id = hdn_mm_profile_id(mm);
	if (hdn_current_profile_id() == target_profile_id)
		return 0;
	if (hdn_profile_allows(HDN_AUTH_MEMORY_MIGRATE,
			       HDN_TRANS_MEMORY_MIGRATE))
		return 0;

	object_id = ((u64)operation << 32) | (u32)task_pid_nr(target);
	return hdn_deny_object(HDN_AUTH_MEMORY_MIGRATE,
			       HDN_TRANS_MEMORY_MIGRATE,
			       HDN_REASON_PROFILE_DENIED, -EPERM,
			       object_id);
}

int hdn_authorize_process_fd(struct task_struct *target,
			     enum hdn_process_fd_operation operation)
{
	u64 target_profile_id;
	u64 object_id;

	if (!target || target == current)
		return 0;
	if (same_thread_group(current, target))
		return 0;

	target_profile_id = hdn_task_profile_id(target);
	if (hdn_current_profile_id() == target_profile_id)
		return 0;
	if (hdn_profile_allows(HDN_AUTH_PROCESS_FD, HDN_TRANS_PROCESS_FD))
		return 0;

	object_id = ((u64)operation << 32) | (u32)task_pid_nr(target);
	return hdn_deny_object(HDN_AUTH_PROCESS_FD, HDN_TRANS_PROCESS_FD,
			       HDN_REASON_PROFILE_DENIED, -EPERM,
			       object_id);
}

void hdn_record_ptrace_audit(struct task_struct *target, long request,
			     int error)
{
	enum hdn_decision_action action;

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_PTRACE_AUDIT))
		return;
	if (request != PTRACE_ATTACH && request != PTRACE_SEIZE)
		return;

	action = error ? HDN_DECISION_DENY_AUDIT : HDN_DECISION_ALLOW_AUDIT;
	hdn_record_event_object_flags(HDN_AUTH_PTRACE, HDN_TRANS_PTRACE,
				      HDN_REASON_NONE, action, error,
				      task_pid_nr(target), 0);
}

int hdn_authorize_ptrace_exec_read(struct mm_struct *mm, unsigned long addr,
				   int len, unsigned int gup_flags)
{
	struct vm_area_struct *vma;
	unsigned long end;

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_PTRACE_READEXEC))
		return 0;
	if (len <= 0 || (gup_flags & FOLL_WRITE) || !(gup_flags & FOLL_FORCE))
		return 0;
	if (hdn_profile_allows(HDN_AUTH_PTRACE_EXEC_READ,
			       HDN_TRANS_PTRACE_EXEC_READ))
		return 0;

	if (check_add_overflow(addr, (unsigned long)len, &end))
		end = ULONG_MAX;

	for (vma = find_vma_intersection(mm, addr, end); vma;
	     vma = find_vma_intersection(mm, vma->vm_end, end)) {
		if ((vma->vm_flags & VM_EXEC) && !(vma->vm_flags & VM_READ))
			return hdn_deny_object(HDN_AUTH_PTRACE_EXEC_READ,
					       HDN_TRANS_PTRACE_EXEC_READ,
					       HDN_REASON_PTRACE_EXEC_READ,
					       -EPERM, addr);
		if (vma->vm_end >= end)
			break;
	}

	return 0;
}

static bool hdn_task_has_current_uid(struct task_struct *target)
{
	const struct cred *cred;
	kuid_t uid = current_uid();
	kuid_t euid = current_euid();
	bool visible;

	rcu_read_lock();
	cred = __task_cred(target);
	visible = uid_eq(uid, cred->uid) || uid_eq(uid, cred->euid) ||
		  uid_eq(euid, cred->uid) || uid_eq(euid, cred->euid);
	rcu_read_unlock();

	return visible;
}

static bool hdn_proc_task_configured_kgid(kgid_t *kgid)
{
	kgid_t candidate;
	int gid;

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_PROC_HIDE))
		return false;

	gid = READ_ONCE(hdn_proc_task_gid);
	if (gid < 0)
		return false;

	candidate = make_kgid(&init_user_ns, (gid_t)gid);
	if (!gid_valid(candidate))
		return false;

	if (kgid)
		*kgid = candidate;
	return true;
}

static bool hdn_current_in_proc_task_gid(void)
{
	kgid_t kgid;

	if (!hdn_proc_task_configured_kgid(&kgid))
		return false;

	return in_group_p(kgid);
}

bool hdn_proc_task_group_kgid(kgid_t *kgid)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_PROC_TASK_MODES))
		return false;

	return hdn_proc_task_configured_kgid(kgid);
}

bool hdn_proc_task_visible(struct task_struct *target)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_PROC_HIDE))
		return true;
	if (!target)
		return false;
	if (target == current || same_thread_group(current, target))
		return true;
	if (hdn_task_has_current_uid(target))
		return true;
	if (hdn_current_in_proc_task_gid())
		return true;
	if (hdn_profile_allows(HDN_AUTH_PROC_DISCLOSE, HDN_TRANS_PROCFS_READ))
		return true;
	if (hdn_profile_allows(HDN_AUTH_PROC_TASK_VIEW, HDN_TRANS_PROCFS_READ))
		return true;

	return false;
}

bool hdn_proc_memmap_disclose(struct task_struct *target, struct mm_struct *mm)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_PROC_MEMMAP))
		return true;
	if (!mm)
		return true;
	if (mm == current->mm)
		return true;
	if (target && (target == current || same_thread_group(current, target)))
		return true;
	if (hdn_profile_allows(HDN_AUTH_PROC_DISCLOSE, HDN_TRANS_PROCFS_READ))
		return true;

	return false;
}

bool hdn_proc_resource_disclose(void)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_PROC_MEMMAP))
		return true;
	if (hdn_profile_allows(HDN_AUTH_PROC_DISCLOSE, HDN_TRANS_PROCFS_READ))
		return true;

	return false;
}

int hdn_authorize_proc_memmap_read(struct task_struct *target,
				   struct mm_struct *mm)
{
	if (hdn_proc_memmap_disclose(target, mm))
		return 0;

	return hdn_authorize(HDN_AUTH_PROC_DISCLOSE, HDN_TRANS_PROCFS_READ,
			     HDN_REASON_PROFILE_DENIED, -EPERM);
}

int hdn_authorize_proc_sensitive_read(struct task_struct *target,
				      struct mm_struct *mm)
{
	if (hdn_proc_memmap_disclose(target, mm))
		return 0;

	return hdn_authorize(HDN_AUTH_PROC_DISCLOSE, HDN_TRANS_PROCFS_READ,
			     HDN_REASON_PROFILE_DENIED, -EPERM);
}

int hdn_authorize_proc_sensitive_write(struct task_struct *target,
				       struct mm_struct *mm)
{
	if (hdn_proc_memmap_disclose(target, mm))
		return 0;

	return hdn_authorize(HDN_AUTH_PROC_DISCLOSE, HDN_TRANS_PROCFS_READ,
			     HDN_REASON_PROFILE_DENIED, -EPERM);
}

int hdn_authorize_proc_resource_read(void)
{
	if (hdn_proc_resource_disclose())
		return 0;

	return hdn_authorize(HDN_AUTH_PROC_DISCLOSE, HDN_TRANS_PROCFS_READ,
			     HDN_REASON_PROFILE_DENIED, -EPERM);
}

bool hdn_kernel_symbol_disclose_allowed(void)
{
	bool audit = false;

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_SYMBOL_LOOKUP))
		return true;

	return hdn_profile_id_authorizes(hdn_current_profile_id(),
					 HDN_AUTH_PROC_DISCLOSE, &audit);
}

int hdn_authorize_kernel_symbol_lookup_transition(enum hdn_transition transition)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_SYMBOL_LOOKUP))
		return 0;

	return hdn_authorize(HDN_AUTH_PROC_DISCLOSE,
			     transition, HDN_REASON_PROFILE_DENIED, -EPERM);
}

int hdn_authorize_kernel_symbol_lookup(void)
{
	return hdn_authorize_kernel_symbol_lookup_transition(
		HDN_TRANS_DEBUGFS_ACCESS);
}

int hdn_authorize_pidfd_open(struct task_struct *target)
{
	if (!target)
		return 0;
	if (!hdn_task_visible_from_chroot(target))
		return hdn_deny_object(HDN_AUTH_CHROOT_ADMIN, HDN_TRANS_CHROOT,
				       HDN_REASON_CHROOT_OUTSIDE_TASK,
				       -EPERM, task_pid_nr(target));
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_PROC_HIDE))
		return 0;
	if (target == current || same_thread_group(current, target))
		return 0;
	if (hdn_signal_target_is_direct_child(target))
		return 0;
	if (hdn_task_has_current_uid(target))
		return 0;
	if (hdn_current_in_proc_task_gid())
		return 0;
	if (hdn_profile_allows(HDN_AUTH_PROC_DISCLOSE, HDN_TRANS_PROCFS_READ))
		return 0;
	if (hdn_profile_allows(HDN_AUTH_PROC_TASK_VIEW, HDN_TRANS_PROCFS_READ))
		return 0;

	return hdn_deny_object(HDN_AUTH_PROC_TASK_VIEW, HDN_TRANS_PROCFS_READ,
			       HDN_REASON_PROFILE_DENIED, -EPERM,
			       task_pid_nr(target));
}

int hdn_authorize_module_from_user(unsigned long len)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_MODULE_FILE_ONLY))
		return 0;

	return hdn_deny_object(HDN_AUTH_MODULE_LOAD, HDN_TRANS_MODULE_LOAD,
			       HDN_REASON_RAW_MODULE_IMAGE, -EPERM, len);
}

int hdn_authorize_module_from_file(struct file *file, int flags)
{
	u64 profile_id = hdn_current_profile_id();

	if (hdn_profile_allows(HDN_AUTH_MODULE_LOAD, HDN_TRANS_MODULE_LOAD))
		goto check_module;

	return hdn_deny_object(HDN_AUTH_MODULE_LOAD, HDN_TRANS_MODULE_LOAD,
			       HDN_REASON_PROFILE_DENIED, -EPERM,
			       hdn_file_object_id(file));

check_module:
	if (hdn_module_file_allowed(file, profile_id))
		return 0;

	return hdn_deny_object(HDN_AUTH_MODULE_LOAD, HDN_TRANS_MODULE_LOAD,
			       HDN_REASON_UNTRUSTED_MODULE, -EPERM,
			       hdn_file_object_id(file));
}

int hdn_authorize_module_autoload(const char *name)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_MODULE_AUTOLOAD))
		return 0;
	if (hdn_profile_allows(HDN_AUTH_MODULE_AUTOLOAD,
			       HDN_TRANS_MODULE_AUTOLOAD))
		return 0;

	return hdn_deny_object(HDN_AUTH_MODULE_AUTOLOAD,
			       HDN_TRANS_MODULE_AUTOLOAD,
				       HDN_REASON_MODULE_AUTOLOAD, -EPERM,
				       hdn_string_object_id(name));
}

int hdn_authorize_module_autoload_control(void)
{
	int ret;

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_MODULE_AUTOLOAD))
		return 0;

	ret = hdn_require_policy_admin(HDN_TRANS_MODULE_AUTOLOAD);
	if (ret)
		return ret;
	if (hdn_profile_allows(HDN_AUTH_MODULE_AUTOLOAD,
			       HDN_TRANS_MODULE_AUTOLOAD))
		return 0;

	return hdn_deny_object(HDN_AUTH_MODULE_AUTOLOAD,
			       HDN_TRANS_MODULE_AUTOLOAD,
			       HDN_REASON_MODULE_AUTOLOAD, -EPERM,
			       hdn_string_object_id("kernel.modprobe"));
}

#ifdef CONFIG_SECURITY_HARDENING_PROC_IPADDR
#define HDN_PROC_IP_CONN_BITS 8
#define HDN_PROC_IP_CONN_BUCKETS (1U << HDN_PROC_IP_CONN_BITS)
#define HDN_PROC_IP_UNIX_BITS 8
#define HDN_PROC_IP_UNIX_BUCKETS (1U << HDN_PROC_IP_UNIX_BITS)

struct hdn_proc_ip_conn_entry {
	struct hlist_node node;
	struct signal_struct *sig;
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
	__be32 curr_ip;
};

struct hdn_proc_ip_unix_entry {
	struct hlist_node node;
	const struct sock *sk;
	__be32 curr_ip;
};

static struct hlist_head hdn_proc_ip_conn_table[HDN_PROC_IP_CONN_BUCKETS];
static DEFINE_SPINLOCK(hdn_proc_ip_conn_lock);
static struct hlist_head hdn_proc_ip_unix_table[HDN_PROC_IP_UNIX_BUCKETS];
static DEFINE_SPINLOCK(hdn_proc_ip_unix_lock);

static __be32 hdn_current_proc_ip(void)
{
	unsigned long flags;
	__be32 curr_ip;

	spin_lock_irqsave(&current->sighand->siglock, flags);
	curr_ip = current->signal->hdn_curr_ip;
	spin_unlock_irqrestore(&current->sighand->siglock, flags);

	return curr_ip;
}

static void hdn_set_current_proc_ip(__be32 curr_ip)
{
	unsigned long flags;

	spin_lock_irqsave(&current->sighand->siglock, flags);
	current->signal->hdn_curr_ip = curr_ip;
	current->signal->hdn_used_accept = true;
	spin_unlock_irqrestore(&current->sighand->siglock, flags);
}

static u32 hdn_proc_ip_conn_hash(__be32 saddr, __be32 daddr,
				 __be16 sport, __be16 dport)
{
	u32 key = (__force u32)saddr;

	key ^= rol32((__force u32)daddr, 16);
	key ^= (u32)(__force u16)sport << 16;
	key ^= (__force u16)dport;
	return hash_32(key, HDN_PROC_IP_CONN_BITS);
}

static bool hdn_proc_ip_conn_match(const struct hdn_proc_ip_conn_entry *entry,
				   __be32 saddr, __be32 daddr,
				   __be16 sport, __be16 dport)
{
	return entry->saddr == saddr && entry->daddr == daddr &&
	       entry->sport == sport && entry->dport == dport;
}

static u32 hdn_proc_ip_unix_hash(const struct sock *sk)
{
	return hash_ptr(sk, HDN_PROC_IP_UNIX_BITS);
}

static void hdn_drop_proc_ip_connection_locked(struct signal_struct *sig)
{
	struct hdn_proc_ip_conn_entry *entry;
	struct hlist_node *tmp;
	u32 bucket;

	if (!sig->hdn_conn_tracked)
		return;

	bucket = hdn_proc_ip_conn_hash(sig->hdn_conn_saddr,
				       sig->hdn_conn_daddr,
				       sig->hdn_conn_sport,
				       sig->hdn_conn_dport);
	hlist_for_each_entry_safe(entry, tmp, &hdn_proc_ip_conn_table[bucket],
				  node) {
		if (entry->sig != sig)
			continue;
		hlist_del(&entry->node);
		kfree(entry);
		break;
	}

	sig->hdn_conn_saddr = 0;
	sig->hdn_conn_daddr = 0;
	sig->hdn_conn_sport = 0;
	sig->hdn_conn_dport = 0;
	sig->hdn_conn_tracked = false;
}

void hdn_drop_proc_ip_connection(struct signal_struct *sig)
{
	unsigned long flags;

	if (!sig)
		return;

	spin_lock_irqsave(&hdn_proc_ip_conn_lock, flags);
	hdn_drop_proc_ip_connection_locked(sig);
	spin_unlock_irqrestore(&hdn_proc_ip_conn_lock, flags);
}

void hdn_track_proc_ip_connection(const struct sock *sk)
{
	struct hdn_proc_ip_conn_entry *entry;
	struct signal_struct *sig = current->signal;
	const struct inet_sock *inet;
	unsigned long flags;
	__be32 curr_ip;
	u32 bucket;

	if (!sk || sk->sk_protocol != IPPROTO_TCP)
		return;
	if (sk->sk_family != AF_INET && sk->sk_family != AF_UNSPEC)
		return;

	inet = inet_sk(sk);
	if (!inet->inet_rcv_saddr || !inet->inet_daddr ||
	    !inet->inet_sport || !inet->inet_dport)
		return;

	curr_ip = hdn_current_proc_ip();
	if (!curr_ip)
		return;

	entry = kmalloc_obj(*entry, GFP_ATOMIC);
	if (!entry)
		return;

	entry->sig = sig;
	entry->saddr = inet->inet_rcv_saddr;
	entry->daddr = inet->inet_daddr;
	entry->sport = inet->inet_sport;
	entry->dport = inet->inet_dport;
	entry->curr_ip = curr_ip;

	bucket = hdn_proc_ip_conn_hash(entry->saddr, entry->daddr,
				       entry->sport, entry->dport);

	spin_lock_irqsave(&hdn_proc_ip_conn_lock, flags);
	hdn_drop_proc_ip_connection_locked(sig);
	sig->hdn_conn_saddr = entry->saddr;
	sig->hdn_conn_daddr = entry->daddr;
	sig->hdn_conn_sport = entry->sport;
	sig->hdn_conn_dport = entry->dport;
	sig->hdn_conn_tracked = true;
	hlist_add_head(&entry->node, &hdn_proc_ip_conn_table[bucket]);
	spin_unlock_irqrestore(&hdn_proc_ip_conn_lock, flags);
}

void hdn_track_unix_proc_ip(const struct sock *sk)
{
	struct hdn_proc_ip_unix_entry *entry;
	unsigned long flags;
	__be32 curr_ip;
	u32 bucket;

	if (!sk || (sk->sk_family != AF_UNIX && sk->sk_family != AF_LOCAL))
		return;

	curr_ip = hdn_current_proc_ip();
	if (!curr_ip)
		return;

	entry = kmalloc_obj(*entry, GFP_ATOMIC);
	if (!entry)
		return;

	entry->sk = sk;
	entry->curr_ip = curr_ip;
	bucket = hdn_proc_ip_unix_hash(sk);

	spin_lock_irqsave(&hdn_proc_ip_unix_lock, flags);
	hlist_add_head(&entry->node, &hdn_proc_ip_unix_table[bucket]);
	spin_unlock_irqrestore(&hdn_proc_ip_unix_lock, flags);
}

static __be32 hdn_consume_unix_proc_ip(const struct sock *sk)
{
	struct hdn_proc_ip_unix_entry *entry;
	struct hlist_node *tmp;
	unsigned long flags;
	__be32 curr_ip = 0;
	u32 bucket;

	if (!sk)
		return 0;

	bucket = hdn_proc_ip_unix_hash(sk);

	spin_lock_irqsave(&hdn_proc_ip_unix_lock, flags);
	hlist_for_each_entry_safe(entry, tmp, &hdn_proc_ip_unix_table[bucket],
				  node) {
		if (entry->sk != sk)
			continue;

		curr_ip = entry->curr_ip;
		hlist_del(&entry->node);
		kfree(entry);
		break;
	}
	spin_unlock_irqrestore(&hdn_proc_ip_unix_lock, flags);

	return curr_ip;
}

void hdn_drop_unix_proc_ip(const struct sock *sk)
{
	hdn_consume_unix_proc_ip(sk);
}

static __be32 hdn_consume_proc_ip_connection(const struct inet_sock *inet)
{
	struct hdn_proc_ip_conn_entry *entry;
	struct hlist_node *tmp;
	unsigned long flags;
	__be32 curr_ip = 0;
	u32 bucket;

	bucket = hdn_proc_ip_conn_hash(inet->inet_daddr,
				       inet->inet_rcv_saddr,
				       inet->inet_dport,
				       inet->inet_sport);

	spin_lock_irqsave(&hdn_proc_ip_conn_lock, flags);
	hlist_for_each_entry_safe(entry, tmp, &hdn_proc_ip_conn_table[bucket],
				  node) {
		if (!hdn_proc_ip_conn_match(entry, inet->inet_daddr,
					    inet->inet_rcv_saddr,
					    inet->inet_dport,
					    inet->inet_sport))
			continue;

		curr_ip = entry->curr_ip;
		entry->sig->hdn_conn_tracked = false;
		hlist_del(&entry->node);
		kfree(entry);
		break;
	}
	spin_unlock_irqrestore(&hdn_proc_ip_conn_lock, flags);

	return curr_ip;
}

void hdn_attach_proc_ip(const struct sock *sk)
{
	const struct inet_sock *inet;
	__be32 curr_ip;

	if (!sk)
		return;

	if (sk->sk_family == AF_UNIX || sk->sk_family == AF_LOCAL) {
		curr_ip = hdn_consume_unix_proc_ip(sk);
		if (curr_ip)
			hdn_set_current_proc_ip(curr_ip);
		return;
	}

	if (!sk || sk->sk_protocol != IPPROTO_TCP)
		return;
	if (sk->sk_family != AF_INET && sk->sk_family != AF_UNSPEC)
		return;

	inet = inet_sk(sk);
	if (!inet->inet_daddr)
		return;

	curr_ip = hdn_consume_proc_ip_connection(inet);
	if (!curr_ip)
		curr_ip = inet->inet_daddr;

	hdn_set_current_proc_ip(curr_ip);
}

void hdn_signal_fork(struct signal_struct *child)
{
	struct signal_struct *parent = current->signal;
	unsigned long flags;

	spin_lock_irqsave(&current->sighand->siglock, flags);
	child->hdn_curr_ip = parent->hdn_curr_ip;
	child->hdn_used_accept = false;
	if (parent->hdn_used_accept) {
		parent->hdn_curr_ip = 0;
		parent->hdn_used_accept = false;
	}
	spin_unlock_irqrestore(&current->sighand->siglock, flags);
}
#else
void hdn_attach_proc_ip(const struct sock *sk)
{
}

void hdn_track_proc_ip_connection(const struct sock *sk)
{
}

void hdn_drop_proc_ip_connection(struct signal_struct *sig)
{
}

void hdn_track_unix_proc_ip(const struct sock *sk)
{
}

void hdn_drop_unix_proc_ip(const struct sock *sk)
{
}

void hdn_signal_fork(struct signal_struct *child)
{
}
#endif

int hdn_authorize_firmware(const char *name)
{
	u64 profile_id = hdn_current_profile_id();

	if (hdn_profile_allows(HDN_AUTH_FIRMWARE_LOAD,
			       HDN_TRANS_FIRMWARE_LOAD))
		goto check_firmware;

	return hdn_deny_object(HDN_AUTH_FIRMWARE_LOAD,
			       HDN_TRANS_FIRMWARE_LOAD,
			       HDN_REASON_PROFILE_DENIED, -EPERM,
			       hdn_string_object_id(name));

check_firmware:
	if (hdn_firmware_name_allowed(name, profile_id))
		return 0;

	return hdn_deny_object(HDN_AUTH_FIRMWARE_LOAD,
			       HDN_TRANS_FIRMWARE_LOAD,
			       HDN_REASON_UNTRUSTED_FIRMWARE, -EPERM,
			       hdn_string_object_id(name));
}

#define HDN_NONUSER_NAMESPACE_FLAGS \
	(CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID | \
	 CLONE_NEWNET | CLONE_NEWCGROUP | CLONE_NEWTIME)

int hdn_authorize_namespace_create(unsigned long flags)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_NAMESPACE_PROFILES))
		return 0;
	if (!(flags & HDN_NONUSER_NAMESPACE_FLAGS))
		return 0;
	if (hdn_profile_allows(HDN_AUTH_NAMESPACE_ADMIN,
			       HDN_TRANS_NAMESPACE_CREATE))
		return 0;

	return hdn_deny_object(HDN_AUTH_NAMESPACE_ADMIN,
			       HDN_TRANS_NAMESPACE_CREATE,
			       HDN_REASON_PROFILE_DENIED, -EPERM, flags);
}

int hdn_authorize_namespace_join(const struct user_namespace *owner,
				 unsigned long nstype)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_NAMESPACE_PROFILES))
		return 0;
	if (!nstype)
		return 0;

	return hdn_authorize_namespace_join_profile(hdn_userns_profile_id(owner),
						    nstype);
}

int hdn_authorize_namespace_join_profile(u64 profile_id, unsigned long nstype)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_NAMESPACE_PROFILES))
		return 0;
	if (!nstype)
		return 0;

	if (profile_id == hdn_current_profile_id())
		return 0;
	if (hdn_profile_allows(HDN_AUTH_NAMESPACE_ADMIN,
			       HDN_TRANS_NAMESPACE_JOIN))
		return 0;

	return hdn_deny_object(HDN_AUTH_NAMESPACE_ADMIN,
			       HDN_TRANS_NAMESPACE_JOIN,
			       HDN_REASON_NAMESPACE_PROFILE_WIDEN, -EPERM,
			       profile_id);
}

int hdn_authorize_chroot(const struct path *path)
{
	if (!hdn_chroot_containment_enabled())
		return 0;
	if (!current_chrooted())
		return 0;
	if (hdn_profile_allows(HDN_AUTH_CHROOT_ADMIN, HDN_TRANS_CHROOT))
		return 0;

	return hdn_deny_object(HDN_AUTH_CHROOT_ADMIN, HDN_TRANS_CHROOT,
			       HDN_REASON_CHROOT_REENTRY, -EPERM,
			       hdn_path_object_id(path));
}

void hdn_chroot_committed(const struct path *path)
{
	if (!hdn_chroot_containment_enabled())
		return;

	set_fs_pwd(current->fs, path);
}

int hdn_authorize_chdir(const struct path *path)
{
	if (hdn_object_access_denied(path, hdn_current_profile_id(),
				     HDN_OBJECT_DENY_CHDIR))
		return hdn_deny_object(HDN_AUTH_OBJECT_CHDIR,
				       HDN_TRANS_OBJECT_CHDIR,
				       HDN_REASON_OBJECT_POLICY, -EACCES,
				       hdn_path_object_id(path));

	if (!hdn_chroot_containment_enabled())
		return 0;
	if (!current_chrooted())
		return 0;
	if (hdn_path_under_current_root(path))
		return 0;
	if (hdn_profile_allows(HDN_AUTH_CHROOT_ADMIN, HDN_TRANS_CHDIR))
		return 0;

	return hdn_deny_object(HDN_AUTH_CHROOT_ADMIN, HDN_TRANS_CHDIR,
			       HDN_REASON_CHROOT_ESCAPE, -EPERM,
			       hdn_path_object_id(path));
}

void hdn_record_chdir(const struct path *path)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_CHDIR_AUDIT))
		return;

	hdn_record_event_object_flags(HDN_AUTH_NONE, HDN_TRANS_CHDIR,
				      HDN_REASON_NONE,
				      HDN_DECISION_ALLOW_AUDIT, 0,
				      hdn_path_object_id(path), 0);
}

int hdn_authorize_pivot_root(const struct path *new_root,
			     const struct path *put_old)
{
	if (!hdn_chroot_containment_enabled())
		return 0;
	if (!current_chrooted())
		return 0;
	if (hdn_profile_allows(HDN_AUTH_CHROOT_ADMIN, HDN_TRANS_PIVOT_ROOT))
		return 0;

	return hdn_deny_object(HDN_AUTH_CHROOT_ADMIN, HDN_TRANS_PIVOT_ROOT,
			       HDN_REASON_PIVOT_ROOT_IN_CHROOT, -EPERM,
			       hdn_path_object_id(new_root));
}

static bool hdn_chroot_restricted_op_enabled(void)
{
	if (!hdn_chroot_containment_enabled())
		return false;
	if (!current->fs || !current->nsproxy || !current->nsproxy->mnt_ns)
		return false;
	if (!current_chrooted())
		return false;
	if (hdn_profile_allows(HDN_AUTH_CHROOT_ADMIN, HDN_TRANS_CHROOT))
		return false;

	return true;
}

static bool hdn_task_root_under_current_root(struct task_struct *target)
{
	struct path current_root;
	struct path target_root;
	bool visible = false;
	bool have_target_root = false;

	get_fs_root(current->fs, &current_root);
	task_lock(target);
	if (target->fs) {
		get_fs_root(target->fs, &target_root);
		have_target_root = true;
	}
	task_unlock(target);

	if (have_target_root) {
		visible = path_equal(&current_root, &target_root) ||
			  path_is_under(&target_root, &current_root);
		path_put(&target_root);
	}
	path_put(&current_root);

	return visible;
}

bool hdn_task_visible_from_chroot(struct task_struct *target)
{
	if (!target)
		return false;
	if (target == current || same_thread_group(current, target))
		return true;
	if (!hdn_chroot_restricted_op_enabled())
		return true;
	if (READ_ONCE(target->exit_state) & (EXIT_ZOMBIE | EXIT_DEAD))
		return false;

	return hdn_task_root_under_current_root(target);
}

int hdn_authorize_chroot_signal(struct task_struct *target, int sig)
{
	if (hdn_task_visible_from_chroot(target))
		return 0;

	return hdn_deny_object(HDN_AUTH_CHROOT_ADMIN, HDN_TRANS_CHROOT,
			       HDN_REASON_CHROOT_OUTSIDE_TASK, -EPERM,
			       target ? task_pid_nr(target) : 0);
}

int hdn_authorize_chroot_fowner(struct pid *pid, int type)
{
	struct task_struct *task;
	int ret = 0;
	u64 object_id = 0;

	if (!pid || !hdn_chroot_restricted_op_enabled())
		return 0;
	if (type == PIDTYPE_MAX)
		type = PIDTYPE_PID;
	if (type < 0 || type >= PIDTYPE_MAX)
		return 0;

	read_lock(&tasklist_lock);
	do_each_pid_task(pid, type, task) {
		if (!hdn_task_visible_from_chroot(task)) {
			object_id = task_pid_nr(task);
			ret = -EPERM;
			break;
		}
	} while_each_pid_task(pid, type, task);
	read_unlock(&tasklist_lock);

	if (!ret)
		return 0;

	return hdn_deny_object(HDN_AUTH_CHROOT_ADMIN, HDN_TRANS_CHROOT,
			       HDN_REASON_CHROOT_OUTSIDE_TASK, ret, object_id);
}

int hdn_authorize_chroot_chmod(const struct path *path, umode_t mode)
{
	if (!hdn_chroot_restricted_op_enabled())
		return 0;

	return hdn_deny_object(HDN_AUTH_CHROOT_ADMIN, HDN_TRANS_CHROOT,
			       HDN_REASON_CHROOT_CHMOD, -EPERM,
			       hdn_path_object_id(path));
}

int hdn_authorize_chroot_mknod(umode_t mode, dev_t dev)
{
	if (!S_ISCHR(mode) && !S_ISBLK(mode))
		return 0;
	if (!hdn_chroot_restricted_op_enabled())
		return 0;

	return hdn_deny_object(HDN_AUTH_CHROOT_ADMIN, HDN_TRANS_CHROOT,
			       HDN_REASON_CHROOT_MKNOD, -EPERM,
			       new_encode_dev(dev));
}

int hdn_authorize_chroot_shmat(int shmid)
{
	if (!hdn_chroot_restricted_op_enabled())
		return 0;

	return hdn_deny_object(HDN_AUTH_CHROOT_ADMIN, HDN_TRANS_CHROOT,
			       HDN_REASON_CHROOT_SHMAT, -EPERM, shmid);
}

int hdn_authorize_protected_shmat(u64 creator_profile_id, int shmid)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_SYSVIPC))
		return 0;
	if (!creator_profile_id)
		return 0;
	if (creator_profile_id == hdn_current_profile_id())
		return 0;
	if (!hdn_profile_id_flag_enabled(creator_profile_id,
					 HDN_PROFILE_PROTECT_SHM))
		return 0;

	return hdn_deny_object(HDN_AUTH_IPC_ADMIN, HDN_TRANS_SYSVIPC_ACCESS,
			       HDN_REASON_PROTECTED_SHM, -EACCES, shmid);
}

int hdn_authorize_chroot_nice(struct task_struct *target, int nice)
{
	if (!target)
		target = current;
	if (nice >= task_nice(target))
		return 0;
	if (!hdn_chroot_restricted_op_enabled())
		return 0;

	return hdn_deny_object(HDN_AUTH_CHROOT_ADMIN, HDN_TRANS_CHROOT,
			       HDN_REASON_CHROOT_NICE, -EPERM,
			       task_pid_nr(target));
}

int hdn_authorize_chroot_rename(const struct path *old_dir,
				struct dentry *old_dentry,
				const struct path *new_dir,
				struct dentry *new_dentry,
				unsigned int flags)
{
	struct path old_path;
	struct path new_path;

	if (!old_dir || !old_dentry || !new_dir || !new_dentry)
		return 0;
	if (!d_is_dir(old_dentry))
		return 0;
	if (!hdn_chroot_restricted_op_enabled())
		return 0;

	old_path.mnt = old_dir->mnt;
	old_path.dentry = old_dentry;
	new_path.mnt = new_dir->mnt;
	new_path.dentry = new_dentry;

	if (!hdn_path_under_current_root(&old_path))
		return 0;
	if (hdn_path_under_current_root(&new_path))
		return 0;

	return hdn_deny_object(HDN_AUTH_CHROOT_ADMIN, HDN_TRANS_CHROOT,
			       HDN_REASON_CHROOT_RENAME, -EXDEV,
			       hdn_path_object_id(&old_path));
}

int hdn_authorize_chroot_unix(const struct path *peer_root)
{
	struct path current_root;
	bool same_root;

	if (!peer_root || !peer_root->dentry)
		return 0;
	if (!hdn_chroot_restricted_op_enabled())
		return 0;

	get_fs_root(current->fs, &current_root);
	same_root = path_equal(&current_root, peer_root);
	path_put(&current_root);
	if (same_root)
		return 0;

	return hdn_deny_object(HDN_AUTH_CHROOT_ADMIN, HDN_TRANS_CHROOT,
			       HDN_REASON_CHROOT_ABSTRACT_UNIX, -EPERM,
			       hdn_path_object_id(peer_root));
}

static bool hdn_chroot_restricted_capability(int cap)
{
	switch (cap) {
	case CAP_LINUX_IMMUTABLE:
	case CAP_NET_ADMIN:
	case CAP_SYS_MODULE:
	case CAP_SYS_RAWIO:
	case CAP_SYS_PACCT:
	case CAP_SYS_ADMIN:
	case CAP_SYS_BOOT:
	case CAP_SYS_TIME:
	case CAP_NET_RAW:
	case CAP_SYS_TTY_CONFIG:
	case CAP_IPC_OWNER:
	case CAP_SETFCAP:
	case CAP_SYSLOG:
	case CAP_MAC_ADMIN:
		return true;
	default:
		return false;
	}
}

static int hdn_authorize_chroot_capability(const struct cred *cred, int cap)
{
	if (!hdn_chroot_restricted_capability(cap))
		return 0;
	if (!hdn_chroot_restricted_op_enabled())
		return 0;
	if (cred != current_real_cred())
		return 0;

	return hdn_deny_object(HDN_AUTH_CHROOT_ADMIN, HDN_TRANS_CHROOT,
			       HDN_REASON_CHROOT_CAPABILITY, -EPERM, cap);
}

int hdn_authorize_capability(const struct cred *cred, int cap,
			     unsigned int opts)
{
	const struct hdn_profile_record *profile;
	u64 capability_mask;
	bool audit;
	bool deny;
	int ret;

	if (!cap_valid(cap) || cred != current_real_cred())
		return 0;

	ret = hdn_authorize_chroot_capability(cred, cap);
	if (ret)
		return ret;

	capability_mask = 1ULL << cap;
	rcu_read_lock();
	profile = hdn_profile_by_id(hdn_current_profile_id());
	deny = profile->capability_deny & capability_mask;
	audit = profile->capability_audit & capability_mask;
	rcu_read_unlock();

	if (deny) {
		if (opts & CAP_OPT_NOAUDIT)
			return -EPERM;
		return hdn_deny_object(HDN_AUTH_NONE, HDN_TRANS_CAPABILITY,
				       HDN_REASON_CAPABILITY_PROFILE, -EPERM, cap);
	}

	if (audit && !(opts & CAP_OPT_NOAUDIT) &&
	    hdn_record_event_object_flags(HDN_AUTH_NONE,
					  HDN_TRANS_CAPABILITY,
					  HDN_REASON_NONE,
					  HDN_DECISION_ALLOW_AUDIT, 0,
					  cap, 0))
		hdn_audit(HDN_AUTH_NONE, HDN_TRANS_CAPABILITY,
			  HDN_REASON_NONE, HDN_DECISION_ALLOW_AUDIT, 0);

	return 0;
}

int hdn_authorize_chroot_mount(const struct path *path)
{
	u64 object_id = path ? hdn_path_object_id(path) : 0;

	if (!hdn_chroot_restricted_op_enabled())
		return 0;

	return hdn_deny_object(HDN_AUTH_CHROOT_ADMIN, HDN_TRANS_MOUNT,
			       HDN_REASON_CHROOT_MOUNT, -EPERM, object_id);
}

int hdn_authorize_chroot_file_handle(void)
{
	if (!hdn_chroot_restricted_op_enabled())
		return 0;

	return hdn_deny_object(HDN_AUTH_CHROOT_ADMIN, HDN_TRANS_CHROOT,
			       HDN_REASON_CHROOT_FILE_HANDLE, -EPERM, 0);
}

int hdn_authorize_chroot_sysctl(const char *name)
{
	if (!hdn_chroot_restricted_op_enabled())
		return 0;

	return hdn_deny_object(HDN_AUTH_CHROOT_ADMIN, HDN_TRANS_CHROOT,
			       HDN_REASON_CHROOT_SYSCTL, -EPERM,
			       hdn_string_object_id(name));
}

int hdn_authorize_time_change(enum hdn_time_operation operation)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_TIME_ADMIN))
		return 0;
	if (hdn_profile_allows(HDN_AUTH_TIME_ADMIN, HDN_TRANS_TIME_CHANGE))
		return 0;

	return hdn_deny_object(HDN_AUTH_TIME_ADMIN, HDN_TRANS_TIME_CHANGE,
			       HDN_REASON_PROFILE_DENIED, -EPERM, operation);
}

void hdn_record_time_change(enum hdn_time_operation operation)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_TIME_AUDIT))
		return;

	hdn_record_event_object_flags(HDN_AUTH_TIME_ADMIN,
				      HDN_TRANS_TIME_CHANGE, HDN_REASON_NONE,
				      HDN_DECISION_ALLOW_AUDIT, 0, operation, 0);
}

int hdn_authorize_resource_limit(unsigned int resource)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_RESOURCE_ADMIN))
		return 0;
	if (hdn_profile_allows(HDN_AUTH_RESOURCE_ADMIN,
			       HDN_TRANS_RESOURCE_LIMIT))
		return 0;

	return hdn_deny_object(HDN_AUTH_RESOURCE_ADMIN,
			       HDN_TRANS_RESOURCE_LIMIT,
			       HDN_REASON_PROFILE_DENIED, -EPERM, resource);
}

void hdn_record_resource_limit(unsigned int resource)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_RESOURCE_AUDIT))
		return;

	hdn_record_event_object_flags(HDN_AUTH_RESOURCE_ADMIN,
				      HDN_TRANS_RESOURCE_LIMIT, HDN_REASON_NONE,
				      HDN_DECISION_ALLOW_AUDIT, 0, resource, 0);
}

#define HDN_RESOURCE_OBJECT_RESOURCE_SHIFT	56
#define HDN_RESOURCE_OBJECT_WANTED_MASK \
	((1ULL << HDN_RESOURCE_OBJECT_RESOURCE_SHIFT) - 1)

static u64 hdn_resource_pressure_object(unsigned int resource,
					unsigned long wanted)
{
	return ((u64)(resource & 0xff) <<
		HDN_RESOURCE_OBJECT_RESOURCE_SHIFT) |
	       min_t(u64, wanted, HDN_RESOURCE_OBJECT_WANTED_MASK);
}

int hdn_authorize_profile_resource_limit(struct task_struct *target,
					 unsigned int resource,
					 const struct rlimit *new_rlim)
{
	const struct hdn_resource_rule_record *rule;
	struct hdn_policy *policy;
	unsigned long wanted = 0;
	u64 profile_id;
	u32 i;
	bool denied = false;

	if (!new_rlim || resource >= RLIM_NLIMITS)
		return 0;

	profile_id = hdn_task_profile_id(target);

	rcu_read_lock();
	policy = rcu_dereference(hdn_active_policy);
	if (!policy)
		goto out;

	for (i = 0; i < policy->resource_rule_count; i++) {
		rule = &policy->resource_rules[i];
		if (rule->profile_id != profile_id || rule->resource != resource)
			continue;

		if (rule->soft_limit != HDN_RESOURCE_LIMIT_INFINITY &&
		    (u64)new_rlim->rlim_cur > rule->soft_limit) {
			wanted = new_rlim->rlim_cur;
			denied = true;
			break;
		}
		if (rule->hard_limit != HDN_RESOURCE_LIMIT_INFINITY &&
		    (u64)new_rlim->rlim_max > rule->hard_limit) {
			wanted = new_rlim->rlim_max;
			denied = true;
			break;
		}
	}

out:
	rcu_read_unlock();
	if (!denied)
		return 0;

	return hdn_deny_object(HDN_AUTH_RESOURCE_ADMIN,
			       HDN_TRANS_RESOURCE_LIMIT,
			       HDN_REASON_RESOURCE_PROFILE_LIMIT, -EPERM,
			       hdn_resource_pressure_object(resource, wanted));
}

void hdn_record_resource_pressure(unsigned int resource, unsigned long wanted)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_RESOURCE_AUDIT))
		return;

	hdn_record_event_object_flags(HDN_AUTH_RESOURCE_ADMIN,
				      HDN_TRANS_RESOURCE_LIMIT, HDN_REASON_NONE,
				      HDN_DECISION_ALLOW_AUDIT, 0,
				      hdn_resource_pressure_object(resource,
								   wanted),
				      0);
}

int hdn_authorize_block_device(dev_t dev)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_BLOCK_DEVICE_RESTRICT))
		return 0;
	if (hdn_profile_allows(HDN_AUTH_BLOCK_DEVICE_ACCESS,
			       HDN_TRANS_BLOCK_DEVICE_ACCESS))
		return 0;

	return hdn_deny_object(HDN_AUTH_BLOCK_DEVICE_ACCESS,
			       HDN_TRANS_BLOCK_DEVICE_ACCESS,
			       HDN_REASON_PROFILE_DENIED, -EPERM,
			       new_encode_dev(dev));
}

int hdn_authorize_block_device_admin(dev_t dev, unsigned int command)
{
	u64 object = ((u64)command << 32) | new_encode_dev(dev);

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_BLOCK_DEVICE_RESTRICT))
		return 0;
	if (hdn_profile_allows(HDN_AUTH_BLOCK_DEVICE_ADMIN,
			       HDN_TRANS_BLOCK_DEVICE_ADMIN))
		return 0;

	return hdn_deny_object(HDN_AUTH_BLOCK_DEVICE_ADMIN,
			       HDN_TRANS_BLOCK_DEVICE_ADMIN,
			       HDN_REASON_PROFILE_DENIED, -EPERM,
			       object);
}

void hdn_record_fs_protection(unsigned int reason, int error,
			      unsigned long inode)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_FS_PROTECTION_AUDIT))
		return;

	switch (reason) {
	case HDN_REASON_PROTECTED_SYMLINK:
	case HDN_REASON_PROTECTED_HARDLINK:
	case HDN_REASON_PROTECTED_FIFO:
	case HDN_REASON_PROTECTED_REGULAR:
	case HDN_REASON_SYMLINK_OWNER_MISMATCH:
		break;
	default:
		return;
	}

	hdn_record_event_object_flags(HDN_AUTH_NONE, HDN_TRANS_FS_PROTECTION,
				      reason, HDN_DECISION_DENY_AUDIT,
				      error, inode, 0);
}

void hdn_record_fork(struct task_struct *child)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_FORK_AUDIT))
		return;

	hdn_record_event_object_flags(HDN_AUTH_NONE, HDN_TRANS_FORK,
				      HDN_REASON_NONE,
				      HDN_DECISION_ALLOW_AUDIT, 0,
				      task_pid_nr(child), 0);
}

void hdn_record_fork_failure(int error)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_FORKFAIL_AUDIT))
		return;
	if (error != -EAGAIN && error != -ENOMEM)
		return;

	hdn_record_event_object_flags(HDN_AUTH_NONE, HDN_TRANS_FORK,
				      HDN_REASON_FORK_FAILED,
				      HDN_DECISION_DENY_AUDIT, error,
				      0, 0);
}

void hdn_record_process_account(long code, int group_dead)
{
	if (!group_dead)
		return;
	if (!hdn_profile_flag_enabled(HDN_PROFILE_AUDIT_PROCESS_ACCOUNT))
		return;

	hdn_record_event_object_flags(HDN_AUTH_NONE,
				      HDN_TRANS_PROCESS_ACCOUNT,
				      HDN_REASON_NONE,
				      HDN_DECISION_ALLOW_AUDIT, 0,
				      (u64)(u32)code,
				      hdn_current_chroot_event_flags());
}

#define HDN_SIGNAL_OBJECT_SIGNAL_SHIFT	56
#define HDN_SIGNAL_OBJECT_ADDR_MASK \
	((1ULL << HDN_SIGNAL_OBJECT_SIGNAL_SHIFT) - 1)

static bool hdn_auditable_signal(int sig)
{
	switch (sig) {
	case SIGSEGV:
	case SIGILL:
	case SIGABRT:
	case SIGBUS:
		return true;
	default:
		return false;
	}
}

void hdn_record_signal(int sig, const void __user *addr,
		       struct task_struct *target)
{
	u64 object;

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_SIGNAL_AUDIT))
		return;
	if (!hdn_auditable_signal(sig))
		return;
	if (!target)
		return;
	if (fatal_signal_pending(target))
		return;

	object = ((u64)(sig & 0xff) << HDN_SIGNAL_OBJECT_SIGNAL_SHIFT) |
		 ((u64)(unsigned long)addr & HDN_SIGNAL_OBJECT_ADDR_MASK);
	hdn_record_event_object_flags(HDN_AUTH_NONE, HDN_TRANS_SIGNAL,
				      HDN_REASON_NONE,
				      HDN_DECISION_ALLOW_AUDIT, 0,
				      object, 0);
}

int hdn_authorize_sysvipc_access(const struct ipc_namespace *ns,
				 const struct kern_ipc_perm *ipcp,
				 int requested_mode, int granted_mode)
{
	int strict_mode;
	kuid_t euid;
	kgid_t egid;

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_SYSVIPC))
		return 0;
	if (!ns || !ipcp || !requested_mode)
		return 0;
	if (hdn_profile_allows(HDN_AUTH_IPC_ADMIN,
			       HDN_TRANS_SYSVIPC_ACCESS))
		return 0;

	euid = current_euid();
	egid = current_egid();
	if (uid_eq(euid, ipcp->cuid) || uid_eq(euid, ipcp->uid))
		return 0;

	strict_mode = ipcp->mode;
	if (strict_mode & 0007)
		strict_mode = 0;
	else if (gid_eq(egid, ipcp->cgid) || gid_eq(egid, ipcp->gid))
		strict_mode >>= 3;
	else
		strict_mode = 0;

	if (!(requested_mode & ~granted_mode & 0007) &&
	    (requested_mode & ~strict_mode & 0007) &&
	    !ns_capable_noaudit(ns->user_ns, CAP_IPC_OWNER))
		return hdn_deny_object(HDN_AUTH_IPC_ADMIN,
				       HDN_TRANS_SYSVIPC_ACCESS,
				       HDN_REASON_OVERPERMISSIVE_IPC,
				       -EACCES, ipcp->id);

	return 0;
}

int hdn_authorize_posix_mqueue_access(const struct ipc_namespace *ns,
				      const struct inode *inode,
				      int requested_mode)
{
	int strict_mode;
	kuid_t euid;
	kgid_t egid;

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_POSIX_MQUEUE))
		return 0;
	if (!ns || !inode || !requested_mode)
		return 0;
	if (hdn_profile_allows(HDN_AUTH_IPC_ADMIN,
			       HDN_TRANS_POSIX_MQUEUE_ACCESS))
		return 0;

	euid = current_euid();
	egid = current_egid();
	if (uid_eq(euid, inode->i_uid))
		return 0;

	strict_mode = inode->i_mode;
	if (strict_mode & 0007)
		strict_mode = 0;
	else if (gid_eq(egid, inode->i_gid) || in_group_p(inode->i_gid))
		strict_mode >>= 3;
	else
		strict_mode = 0;

	if (requested_mode & ~strict_mode & 0007 &&
	    !ns_capable_noaudit(ns->user_ns, CAP_IPC_OWNER))
		return hdn_deny_object(HDN_AUTH_IPC_ADMIN,
				       HDN_TRANS_POSIX_MQUEUE_ACCESS,
				       HDN_REASON_OVERPERMISSIVE_IPC,
				       -EACCES, hdn_inode_object_id(inode));

	return 0;
}

int hdn_authorize_tty_injection(unsigned int cmd)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_TTY_INJECTION))
		return 0;
	if (hdn_profile_allows(HDN_AUTH_TTY_INJECT, HDN_TRANS_TTY_INJECT))
		return 0;

	return hdn_deny_object(HDN_AUTH_TTY_INJECT, HDN_TRANS_TTY_INJECT,
			       HDN_REASON_TTY_INJECTION, -EPERM, cmd);
}

static bool hdn_tty_is_pty_master(const struct tty_struct *tty)
{
	return tty && tty->driver &&
	       tty->driver->type == TTY_DRIVER_TYPE_PTY &&
	       tty->driver->subtype == PTY_TYPE_MASTER;
}

static bool hdn_tty_is_pty_slave(const struct tty_struct *tty)
{
	return tty && tty->driver &&
	       tty->driver->type == TTY_DRIVER_TYPE_PTY &&
	       tty->driver->subtype == PTY_TYPE_SLAVE;
}

void hdn_tty_record_broker(struct tty_struct *tty)
{
	struct pid *broker;
	struct pid *old = NULL;
	unsigned long flags;

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_TTY_ACCESS) ||
	    !hdn_tty_is_pty_slave(tty))
		return;

	broker = get_pid(task_tgid(current));
	spin_lock_irqsave(&tty->ctrl.lock, flags);
	if (!tty->ctrl.session) {
		old = tty->hdn_session_broker;
		tty->hdn_session_broker = broker;
		broker = NULL;
	}
	spin_unlock_irqrestore(&tty->ctrl.lock, flags);
	put_pid(old);
	put_pid(broker);
}

void hdn_tty_record_session_broker(struct tty_struct *tty)
{
	struct task_struct *parent;
	struct pid *broker = NULL;
	struct pid *old;
	unsigned long flags;

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_TTY_ACCESS) ||
	    !hdn_tty_is_pty_slave(tty))
		return;

	rcu_read_lock();
	parent = rcu_dereference(current->real_parent);
	if (parent && !same_thread_group(parent, current))
		broker = get_pid(task_tgid(parent));
	rcu_read_unlock();

	spin_lock_irqsave(&tty->ctrl.lock, flags);
	old = tty->hdn_session_broker;
	tty->hdn_session_broker = broker;
	spin_unlock_irqrestore(&tty->ctrl.lock, flags);
	put_pid(old);
}

void hdn_tty_release_session_broker(struct tty_struct *tty)
{
	struct pid *broker;
	unsigned long flags;

	if (!tty)
		return;

	spin_lock_irqsave(&tty->ctrl.lock, flags);
	broker = tty->hdn_session_broker;
	tty->hdn_session_broker = NULL;
	spin_unlock_irqrestore(&tty->ctrl.lock, flags);
	put_pid(broker);
}

static bool hdn_tty_is_session_broker(struct tty_struct *tty)
{
	struct pid *broker;
	struct task_struct *leader;
	struct task_struct *parent;
	struct pid *session;
	unsigned long flags;
	bool allowed = false;

	spin_lock_irqsave(&tty->ctrl.lock, flags);
	session = get_pid(tty->ctrl.session);
	broker = get_pid(tty->hdn_session_broker);
	spin_unlock_irqrestore(&tty->ctrl.lock, flags);
	if (broker) {
		allowed = broker == task_tgid(current);
		put_pid(broker);
		if (allowed) {
			put_pid(session);
			return true;
		}
	}
	if (!session)
		return false;

	rcu_read_lock();
	leader = pid_task(session, PIDTYPE_SID);
	if (leader) {
		parent = rcu_dereference(leader->real_parent);
		allowed = same_thread_group(leader, current) ||
			  (parent && same_thread_group(parent, current));
	}
	rcu_read_unlock();
	put_pid(session);

	return allowed;
}

int hdn_authorize_tty_access(struct tty_struct *tty,
			     enum hdn_tty_access_operation operation)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_TTY_ACCESS))
		return 0;
	if (!tty)
		return 0;
	if (hdn_tty_is_pty_master(tty))
		return 0;
	if (current->signal && current->signal->tty == tty)
		return 0;
	if (hdn_tty_is_session_broker(tty))
		return 0;
	if (hdn_profile_allows(HDN_AUTH_TTY_ACCESS, HDN_TRANS_TTY_ACCESS))
		return 0;

	return hdn_deny_object(HDN_AUTH_TTY_ACCESS, HDN_TRANS_TTY_ACCESS,
			       HDN_REASON_TTY_ACCESS, -EACCES, operation);
}

int hdn_authorize_mount_type(const struct file_system_type *type)
{
	int ret;

	ret = hdn_authorize_chroot_mount(NULL);
	if (ret)
		return ret;

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_FUSE_RESTRICT))
		return 0;
	if (!type || !type->name)
		return 0;
	if (strcmp(type->name, "fuse") && strcmp(type->name, "fuseblk"))
		return 0;
	if (hdn_profile_allows(HDN_AUTH_FUSE_MOUNT, HDN_TRANS_FUSE_MOUNT))
		return 0;

	return hdn_deny_object(HDN_AUTH_FUSE_MOUNT, HDN_TRANS_FUSE_MOUNT,
			       HDN_REASON_FUSE_RESTRICTED, -EPERM,
				       hdn_string_object_id(type->name));
}

int hdn_authorize_writable_mount(const struct file_system_type *type,
				 bool requested_readonly)
{
	const char *name = "mount";

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_ROFS))
		return 0;
	if (requested_readonly)
		return 0;
	if (!hdn_profile_flag_enabled(HDN_PROFILE_ENFORCE_READONLY_MOUNTS))
		return 0;
	if (hdn_profile_allows(HDN_AUTH_ROFS_RELAX, HDN_TRANS_MOUNT))
		return 0;

	if (type && type->name)
		name = type->name;

	return hdn_deny_object(HDN_AUTH_ROFS_RELAX, HDN_TRANS_MOUNT,
			       HDN_REASON_ROFS_RELAX, -EPERM,
			       hdn_string_object_id(name));
}

void hdn_record_mount(const struct path *path)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_MOUNT_AUDIT))
		return;

	hdn_record_event_object_flags(HDN_AUTH_MOUNT_ADMIN, HDN_TRANS_MOUNT,
				      HDN_REASON_NONE,
				      HDN_DECISION_ALLOW_AUDIT, 0,
				      hdn_path_object_id(path), 0);
}

int hdn_authorize_rofs_relax(const struct vfsmount *mnt,
			     bool currently_readonly, bool requested_readonly)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_ROFS))
		return 0;
	if (!currently_readonly || requested_readonly)
		return 0;
	if (hdn_profile_allows(HDN_AUTH_ROFS_RELAX, HDN_TRANS_ROFS_RELAX))
		return 0;

	return hdn_deny_object(HDN_AUTH_ROFS_RELAX, HDN_TRANS_ROFS_RELAX,
			       HDN_REASON_ROFS_RELAX, -EPERM,
			       hdn_vfsmount_object_id(mnt));
}

int hdn_authorize_super_rofs_relax(const struct super_block *sb,
				   bool currently_readonly,
				   bool requested_readonly)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_ROFS))
		return 0;
	if (!currently_readonly || requested_readonly)
		return 0;
	if (hdn_profile_allows(HDN_AUTH_ROFS_RELAX, HDN_TRANS_ROFS_RELAX))
		return 0;

	return hdn_deny_object(HDN_AUTH_ROFS_RELAX, HDN_TRANS_ROFS_RELAX,
			       HDN_REASON_ROFS_RELAX, -EPERM,
			       hdn_super_object_id(sb));
}

int hdn_authorize_usb_attach(unsigned int busnum, unsigned int portnum)
{
	u64 object_id = ((u64)busnum << 32) | portnum;

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_USB_RESTRICT))
		return 0;
	if (hdn_profile_allows(HDN_AUTH_USB_ATTACH, HDN_TRANS_USB_ATTACH))
		return 0;

	return hdn_deny_object(HDN_AUTH_USB_ATTACH, HDN_TRANS_USB_ATTACH,
			       HDN_REASON_PROFILE_DENIED, -EPERM,
			       object_id);
}

int hdn_authorize_usb_monitor(unsigned int busnum)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_USB_RESTRICT))
		return 0;
	if (hdn_profile_allows(HDN_AUTH_USB_MONITOR, HDN_TRANS_USB_MONITOR))
		return 0;

	return hdn_deny_object(HDN_AUTH_USB_MONITOR, HDN_TRANS_USB_MONITOR,
			       HDN_REASON_PROFILE_DENIED, -EPERM, busnum);
}

static bool hdn_socket_family_is_local(int family)
{
	return family == AF_UNSPEC || family == AF_UNIX || family == AF_LOCAL;
}

static int hdn_socket_family(const struct socket *sock,
			     const struct sockaddr *addr, int addrlen)
{
	if (addr && addrlen >= sizeof(addr->sa_family) &&
	    addr->sa_family != AF_UNSPEC)
		return addr->sa_family;
	if (sock && sock->sk)
		return sock->sk->sk_family;

	return AF_UNSPEC;
}

static u64 hdn_socket_object_id(int family, int type, int protocol)
{
	return ((u64)(u32)family << 32) |
	       ((u64)(u32)(type & SOCK_TYPE_MASK) << 16) |
	       (u16)protocol;
}

static u64 hdn_socket_object_id_from_sock(const struct socket *sock,
					  int family)
{
	int type = sock ? sock->type : 0;
	int protocol = 0;

	if (sock && sock->sk)
		protocol = sock->sk->sk_protocol;

	return hdn_socket_object_id(family, type, protocol);
}

static u64 hdn_socket_endpoint_object_id(const struct socket *sock,
					 int family,
					 const struct sockaddr *addr,
					 int addrlen)
{
	u64 type = sock ? sock->type & SOCK_TYPE_MASK : 0;

	if (!addr)
		return hdn_socket_object_id_from_sock(sock, family);

	if (family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
		const struct sockaddr_in *sin = (const void *)addr;

		return ((u64)AF_INET << 56) | (type << 48) |
		       ((u64)be16_to_cpu(sin->sin_port) << 32) |
		       be32_to_cpu(sin->sin_addr.s_addr);
	}

	if (family == AF_INET6 && addrlen >= sizeof(struct sockaddr_in6)) {
		const struct sockaddr_in6 *sin6 = (const void *)addr;
		u64 hash = hdn_bytes_object_id(&sin6->sin6_addr,
					       sizeof(sin6->sin6_addr));

		return ((u64)AF_INET6 << 56) | (type << 48) |
		       ((u64)be16_to_cpu(sin6->sin6_port) << 32) |
		       (hash & 0xffffffffULL);
	}

	return hdn_socket_object_id_from_sock(sock, family);
}

int hdn_authorize_socket_create(int family, int type, int protocol,
				bool kernel)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_SOCKET_RESTRICT))
		return 0;
	if (kernel || hdn_socket_family_is_local(family))
		return 0;
	if (hdn_profile_allows(HDN_AUTH_SOCKET_CREATE,
			       HDN_TRANS_SOCKET_CREATE))
		return 0;

	return hdn_deny_object(HDN_AUTH_SOCKET_CREATE,
			       HDN_TRANS_SOCKET_CREATE,
			       HDN_REASON_PROFILE_DENIED, -EPERM,
			       hdn_socket_object_id(family, type, protocol));
}

int hdn_authorize_socket_connect(const struct socket *sock,
				 const struct sockaddr *addr, int addrlen)
{
	int family = hdn_socket_family(sock, addr, addrlen);

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_SOCKET_RESTRICT))
		return 0;
	if (hdn_socket_family_is_local(family))
		return 0;
	if (hdn_profile_allows(HDN_AUTH_SOCKET_CONNECT,
			       HDN_TRANS_SOCKET_CONNECT))
		return 0;

	return hdn_deny_object(HDN_AUTH_SOCKET_CONNECT,
			       HDN_TRANS_SOCKET_CONNECT,
			       HDN_REASON_PROFILE_DENIED, -EPERM,
			       hdn_socket_endpoint_object_id(sock, family,
							     addr, addrlen));
}

int hdn_authorize_socket_server(const struct socket *sock,
				const struct sockaddr *addr, int addrlen)
{
	int family = hdn_socket_family(sock, addr, addrlen);

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_SOCKET_RESTRICT))
		return 0;
	if (hdn_socket_family_is_local(family))
		return 0;
	if (hdn_profile_allows(HDN_AUTH_SOCKET_SERVER,
			       HDN_TRANS_SOCKET_SERVER))
		return 0;

	return hdn_deny_object(HDN_AUTH_SOCKET_SERVER,
			       HDN_TRANS_SOCKET_SERVER,
			       HDN_REASON_PROFILE_DENIED, -EPERM,
			       hdn_socket_endpoint_object_id(sock, family,
							     addr, addrlen));
}

bool hdn_blackhole_remote_skb(const struct sk_buff *skb)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_NET_BLACKHOLE))
		return false;
	if (!skb || !skb->dev)
		return false;

	return !(skb->dev->flags & IFF_LOOPBACK);
}
EXPORT_SYMBOL_GPL(hdn_blackhole_remote_skb);

#define HDN_TCP_LASTACK_RETRIES 4

unsigned int hdn_tcp_lastack_retries(unsigned int retry_until)
{
	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_NET_BLACKHOLE))
		return retry_until;
	if (retry_until <= HDN_TCP_LASTACK_RETRIES)
		return retry_until;

	return HDN_TCP_LASTACK_RETRIES;
}

static bool hdn_policy_has_profile(const struct hdn_policy *policy, u64 id)
{
	u32 i;

	for (i = 0; i < policy->profile_count; i++) {
		if (policy->profiles[i].profile_id == id)
			return true;
	}

	return false;
}

static int hdn_validate_profile_ids(const struct hdn_policy *policy)
{
	u64 valid_authorities = hdn_valid_authority_low_mask();
	u64 valid_authorities_hi = hdn_valid_authority_high_mask();
	u64 valid_memory = HDN_MEM_ALLOW_WX |
			   HDN_MEM_ALLOW_EXEC_AFTER_WRITE |
			   HDN_MEM_ALLOW_FIXED_ANON_EXEC |
			   HDN_MEM_ALLOW_READ_IMPLIES_EXEC |
			   HDN_MEM_ALLOW_JIT_EXEC_AFTER_WRITE |
			   HDN_MEM_ALLOW_EXEC_STACK_ELF |
			   HDN_MEM_ALLOW_TEXTREL_MPROTECT |
			   HDN_MEM_ALLOW_RELRO_WRITE;
	u64 valid_profile_flags = HDN_PROFILE_RESPONSE_KILL_DENY |
				  HDN_PROFILE_RESPONSE_KILL_MEMORY |
				  HDN_PROFILE_RESPONSE_KILL_KERNEL_SURFACE |
				  HDN_PROFILE_ENFORCE_TRUSTED_EXEC |
				  HDN_PROFILE_CHROOT_CONTAINED |
				  HDN_PROFILE_DENY_UNPRIVILEGED_PRIVEXEC |
				  HDN_PROFILE_ENFORCE_READONLY_MOUNTS |
				  HDN_PROFILE_DENY_UNTRUSTED_USER_EXEC |
				  HDN_PROFILE_AUDIT_PROCESS_ACCOUNT |
				  HDN_PROFILE_PROTECT_SHM |
				  HDN_PROFILE_INHERIT_UNMATCHED_EXEC |
				  (IS_ENABLED(CONFIG_SECURITY_HARDENING_SYSFS_VIEW) ?
				   HDN_PROFILE_SYSFS_MASK : 0);
	u64 valid_capabilities = (1ULL << (CAP_LAST_CAP + 1)) - 1;
	u64 valid_exec_flags = HDN_EXEC_MATCH_FILE_ID |
			       HDN_EXEC_MATCH_ORIGINAL_ID |
			       HDN_EXEC_MATCH_VERITY_DIGEST |
			       HDN_EXEC_RESOLVE_FILE_PATH |
			       HDN_EXEC_RESOLVE_ORIGINAL_PATH |
			       HDN_EXEC_INHERIT_PROFILE |
			       HDN_EXEC_AUDIT_INHERIT | HDN_EXEC_COMPAT_LEASE;
	u64 exec_match_flags = HDN_EXEC_MATCH_FILE_ID |
			       HDN_EXEC_MATCH_ORIGINAL_ID |
			       HDN_EXEC_MATCH_VERITY_DIGEST |
			       HDN_EXEC_RESOLVE_FILE_PATH |
			       HDN_EXEC_RESOLVE_ORIGINAL_PATH;
	u64 valid_subject_flags = HDN_SUBJECT_MATCH_UID |
				  HDN_SUBJECT_MATCH_GID;
	u64 valid_object_flags = HDN_OBJECT_MATCH_FILE_ID |
				 HDN_OBJECT_RESOLVE_FILE_PATH |
				 HDN_OBJECT_DENY_WRITE |
				 HDN_OBJECT_DENY_READ |
				 HDN_OBJECT_DENY_DELETE |
				 HDN_OBJECT_DENY_CREATE |
				 HDN_OBJECT_DENY_EXEC |
				 HDN_OBJECT_APPEND_ONLY |
				 HDN_OBJECT_DENY_LINK |
				 HDN_OBJECT_MATCH_SUBTREE |
				 HDN_OBJECT_DENY_ATTR |
				 HDN_OBJECT_DENY_ACCESS |
				 HDN_OBJECT_DENY_STAT |
				 HDN_OBJECT_DENY_LIST |
				 HDN_OBJECT_DENY_FIND |
				 HDN_OBJECT_RESOLVE_NOFOLLOW_PATH |
					 HDN_OBJECT_DENY_IOCTL |
					 HDN_OBJECT_DENY_LOCK |
				 HDN_OBJECT_DENY_WATCH |
				 HDN_OBJECT_DENY_XATTR |
				 HDN_OBJECT_DENY_RECEIVE |
				 HDN_OBJECT_DENY_FCNTL |
				 HDN_OBJECT_DENY_CHDIR |
				 HDN_OBJECT_DENY_MOUNT |
				 HDN_OBJECT_DENY_UMOUNT |
				 HDN_OBJECT_DENY_TRUNCATE |
				 HDN_OBJECT_DENY_RENAME |
				 HDN_OBJECT_DENY_UNIX_CONNECT |
				 HDN_OBJECT_DENY_CHMOD |
				 HDN_OBJECT_DENY_CHOWN |
				 HDN_OBJECT_DENY_UTIME |
				 HDN_OBJECT_DENY_SETXATTR |
				 HDN_OBJECT_DENY_REMOVEXATTR |
					 HDN_OBJECT_DENY_CREAT |
					 HDN_OBJECT_DENY_MKDIR |
					 HDN_OBJECT_DENY_MKNOD |
					 HDN_OBJECT_DENY_SYMLINK |
					 HDN_OBJECT_DENY_UNLINK |
					 HDN_OBJECT_DENY_RMDIR |
					 HDN_OBJECT_DENY_UNIX_BIND |
					 HDN_OBJECT_DENY_UNIX_LISTEN |
					 HDN_OBJECT_DENY_UNIX_ACCEPT |
					 HDN_OBJECT_DENY_UNIX_SEND |
					 HDN_OBJECT_DENY_UNIX_RECV |
					 HDN_OBJECT_DENY_RENAME_TARGET |
				     HDN_OBJECT_DENY_LINK_TARGET |
				     HDN_OBJECT_DENY_MOUNT_SOURCE |
				     HDN_OBJECT_DENY_SETID |
				     HDN_OBJECT_DENY_PTRACE |
				     HDN_OBJECT_MATCH_UNIX_ABSTRACT;
	u64 valid_object_audit_flags = HDN_OBJECT_DENY_WRITE |
				       HDN_OBJECT_DENY_READ |
				       HDN_OBJECT_APPEND_ONLY |
				       HDN_OBJECT_DENY_DELETE |
				       HDN_OBJECT_DENY_CREATE |
				       HDN_OBJECT_DENY_EXEC |
				       HDN_OBJECT_DENY_LINK |
				       HDN_OBJECT_DENY_FIND |
				       HDN_OBJECT_DENY_SETID;
	u64 valid_module_flags = HDN_MODULE_MATCH_FILE_ID |
				 HDN_MODULE_MATCH_VERITY_DIGEST |
				 HDN_MODULE_RESOLVE_FILE_PATH |
				 HDN_MODULE_MATCH_TRUSTED_SIGNATURE;
	u32 i, j;

	for (i = 0; i < policy->profile_count; i++) {
		if (!policy->profiles[i].profile_id ||
		    policy->profiles[i].profile_id == HDN_PROFILE_REVOKED)
			return -EINVAL;
		if (policy->profiles[i].authority_allow & ~valid_authorities)
			return -EINVAL;
		if (policy->profiles[i].authority_audit & ~valid_authorities)
			return -EINVAL;
		if (policy->profiles[i].authority_allow_hi &
		    ~valid_authorities_hi)
			return -EINVAL;
		if (policy->profiles[i].authority_audit_hi &
		    ~valid_authorities_hi)
			return -EINVAL;
		if (policy->profiles[i].memory_flags & ~valid_memory)
			return -EINVAL;
		if (policy->profiles[i].flags & ~valid_profile_flags)
			return -EINVAL;
		if (policy->profiles[i].capability_deny & ~valid_capabilities)
			return -EINVAL;
		if (policy->profiles[i].capability_audit & ~valid_capabilities)
			return -EINVAL;
		if (policy->profiles[i].umask & ~0777)
			return -EINVAL;
		if (policy->profiles[i].max_userns_level > 32 ||
		    policy->profiles[i].reserved32)
			return -EINVAL;
		for (j = i + 1; j < policy->profile_count; j++) {
			if (policy->profiles[i].profile_id ==
			    policy->profiles[j].profile_id)
				return -EINVAL;
		}
	}

	if (!hdn_policy_has_profile(policy, policy->default_profile_id))
		return -EINVAL;
	if (!hdn_policy_has_profile(policy, policy->privileged_profile_id))
		return -EINVAL;

	for (i = 0; i < policy->subject_rule_count; i++) {
		const struct hdn_subject_rule_record *rule =
			&policy->subject_rules[i];

		if (!hdn_policy_has_profile(policy, rule->profile_id))
			return -EINVAL;
		if (!rule->flags || (rule->flags & ~valid_subject_flags))
			return -EINVAL;
		if ((rule->flags & valid_subject_flags) !=
		    HDN_SUBJECT_MATCH_UID &&
		    (rule->flags & valid_subject_flags) !=
		    HDN_SUBJECT_MATCH_GID)
			return -EINVAL;
		if (rule->reserved)
			return -EINVAL;
		if ((rule->flags & HDN_SUBJECT_MATCH_UID) &&
		    !uid_valid(make_kuid(&init_user_ns, rule->id)))
			return -EINVAL;
		if ((rule->flags & HDN_SUBJECT_MATCH_GID) &&
		    !gid_valid(make_kgid(&init_user_ns, rule->id)))
			return -EINVAL;
	}

	for (i = 0; i < policy->object_rule_count; i++) {
		const struct hdn_object_rule_record *rule =
			&policy->object_rules[i];

		if (!hdn_policy_has_profile(policy, rule->profile_id))
			return -EINVAL;
		if (!rule->flags || (rule->flags & ~valid_object_flags) ||
		    (rule->audit_flags & ~valid_object_audit_flags))
			return -EINVAL;
		if (!(rule->flags & (HDN_OBJECT_DENY_WRITE |
				     HDN_OBJECT_DENY_READ |
				     HDN_OBJECT_DENY_DELETE |
				     HDN_OBJECT_DENY_CREATE |
				     HDN_OBJECT_DENY_EXEC |
				     HDN_OBJECT_APPEND_ONLY |
				     HDN_OBJECT_DENY_LINK |
				     HDN_OBJECT_DENY_ATTR |
				     HDN_OBJECT_DENY_ACCESS |
				     HDN_OBJECT_DENY_STAT |
				     HDN_OBJECT_DENY_LIST |
				     HDN_OBJECT_DENY_FIND |
					     HDN_OBJECT_DENY_IOCTL |
					     HDN_OBJECT_DENY_LOCK |
				     HDN_OBJECT_DENY_WATCH |
				     HDN_OBJECT_DENY_XATTR |
				     HDN_OBJECT_DENY_RECEIVE |
				     HDN_OBJECT_DENY_FCNTL |
				     HDN_OBJECT_DENY_CHDIR |
				     HDN_OBJECT_DENY_MOUNT |
				     HDN_OBJECT_DENY_UMOUNT |
				     HDN_OBJECT_DENY_TRUNCATE |
				     HDN_OBJECT_DENY_RENAME |
				     HDN_OBJECT_DENY_UNIX_CONNECT |
				     HDN_OBJECT_DENY_CHMOD |
				     HDN_OBJECT_DENY_CHOWN |
				     HDN_OBJECT_DENY_UTIME |
				     HDN_OBJECT_DENY_SETXATTR |
				     HDN_OBJECT_DENY_REMOVEXATTR |
				     HDN_OBJECT_DENY_CREAT |
				     HDN_OBJECT_DENY_MKDIR |
					     HDN_OBJECT_DENY_MKNOD |
					     HDN_OBJECT_DENY_SYMLINK |
					     HDN_OBJECT_DENY_UNLINK |
					     HDN_OBJECT_DENY_RMDIR |
					     HDN_OBJECT_DENY_UNIX_BIND |
					     HDN_OBJECT_DENY_UNIX_LISTEN |
					     HDN_OBJECT_DENY_UNIX_ACCEPT |
					     HDN_OBJECT_DENY_UNIX_SEND |
					     HDN_OBJECT_DENY_UNIX_RECV |
					     HDN_OBJECT_DENY_RENAME_TARGET |
					     HDN_OBJECT_DENY_LINK_TARGET |
					     HDN_OBJECT_DENY_MOUNT_SOURCE |
					     HDN_OBJECT_DENY_SETID |
					     HDN_OBJECT_DENY_PTRACE)) &&
		    !rule->audit_flags)
			return -EINVAL;
		if ((rule->flags & HDN_OBJECT_MATCH_FILE_ID) &&
		    (rule->flags & HDN_OBJECT_RESOLVE_FILE_PATH))
			return -EINVAL;
		if ((rule->flags & HDN_OBJECT_MATCH_UNIX_ABSTRACT) &&
		    (rule->flags & (HDN_OBJECT_MATCH_FILE_ID |
				    HDN_OBJECT_RESOLVE_FILE_PATH |
				    HDN_OBJECT_MATCH_SUBTREE |
				    HDN_OBJECT_RESOLVE_NOFOLLOW_PATH)))
			return -EINVAL;
		if ((rule->flags & HDN_OBJECT_RESOLVE_NOFOLLOW_PATH) &&
		    !(rule->flags & HDN_OBJECT_RESOLVE_FILE_PATH))
			return -EINVAL;
		if ((rule->flags & HDN_OBJECT_MATCH_SUBTREE) &&
		    !(rule->flags & (HDN_OBJECT_MATCH_FILE_ID |
				     HDN_OBJECT_RESOLVE_FILE_PATH)))
			return -EINVAL;
		if ((rule->flags & HDN_OBJECT_MATCH_SUBTREE) &&
		    (rule->flags & HDN_OBJECT_RESOLVE_NOFOLLOW_PATH))
			return -EINVAL;
		if ((rule->flags & HDN_OBJECT_MATCH_UNIX_ABSTRACT) &&
		    !(rule->flags & (HDN_OBJECT_DENY_UNIX_CONNECT |
				     HDN_OBJECT_DENY_UNIX_BIND |
				     HDN_OBJECT_DENY_UNIX_LISTEN |
				     HDN_OBJECT_DENY_UNIX_ACCEPT |
				     HDN_OBJECT_DENY_UNIX_SEND |
				     HDN_OBJECT_DENY_UNIX_RECV)))
			return -EINVAL;
		if ((rule->flags & HDN_OBJECT_MATCH_FILE_ID) && !rule->file_ino)
			return -EINVAL;
		if ((rule->flags & HDN_OBJECT_RESOLVE_FILE_PATH) &&
		    !hdn_policy_path_valid(rule->file_path))
			return -EINVAL;
		if ((rule->flags & HDN_OBJECT_MATCH_UNIX_ABSTRACT) &&
		    (!rule->file_path[0] ||
		     !memchr(rule->file_path, '\0', HDN_POLICY_PATH_LEN)))
			return -EINVAL;
	}

	for (i = 0; i < policy->exec_rule_count; i++) {
		const struct hdn_exec_rule_record *rule = &policy->exec_rules[i];

		if (rule->flags & HDN_EXEC_COMPAT_LEASE) {
			const struct hdn_profile_record *profile;

			if (!IS_ENABLED(CONFIG_FS_VERITY))
				return -EOPNOTSUPP;
			if (!(rule->flags & HDN_EXEC_MATCH_VERITY_DIGEST) ||
			    !(rule->flags & (HDN_EXEC_MATCH_FILE_ID | HDN_EXEC_RESOLVE_FILE_PATH)) ||
			    rule->flags & (HDN_EXEC_INHERIT_PROFILE | HDN_EXEC_AUDIT_INHERIT |
					   HDN_EXEC_MATCH_ORIGINAL_ID | HDN_EXEC_RESOLVE_ORIGINAL_PATH) ||
			    !rule->parent_profile_id || !hdn_policy_path_valid(rule->file_path) ||
			    rule->target_profile_id == policy->default_profile_id ||
			    rule->target_profile_id == policy->privileged_profile_id)
				return -EINVAL;
			/* Leases cannot be selected through UID/GID or inheritance. */
			for (j = 0; j < policy->subject_rule_count; j++)
				if (policy->subject_rules[j].profile_id == rule->target_profile_id)
					return -EINVAL;
			/* v1 leases admit memory transitions, not scoped object ACLs.
			 * Revocation must not turn a profile-specific deny into no rule.
			 */
			for (j = 0; j < policy->object_rule_count; j++)
				if (policy->object_rules[j].profile_id == rule->target_profile_id)
					return -EINVAL;
			for (j = 0; j < policy->exec_rule_count; j++) {
				const struct hdn_exec_rule_record *other = &policy->exec_rules[j];

				if (!(other->flags & HDN_EXEC_COMPAT_LEASE) &&
				    (other->target_profile_id == rule->target_profile_id ||
				     ((other->flags & HDN_EXEC_INHERIT_PROFILE) &&
				      (!other->parent_profile_id ||
				       other->parent_profile_id == rule->target_profile_id))))
					return -EINVAL;
			}
			profile = NULL;
			for (j = 0; j < policy->profile_count; j++)
				if (policy->profiles[j].profile_id == rule->target_profile_id)
					profile = &policy->profiles[j];
			if (!profile)
				return -EINVAL;
			if (profile->flags & HDN_PROFILE_INHERIT_UNMATCHED_EXEC ||
			    profile->memory_flags & ~(HDN_MEM_ALLOW_FIXED_ANON_EXEC |
						      HDN_MEM_ALLOW_JIT_EXEC_AFTER_WRITE))
				return -EINVAL;
		}

		if (rule->flags & HDN_EXEC_INHERIT_PROFILE) {
			if (rule->target_profile_id)
				return -EINVAL;
		} else if (!hdn_policy_has_profile(policy,
						   rule->target_profile_id)) {
			return -EINVAL;
		}
		if ((rule->flags & HDN_EXEC_AUDIT_INHERIT) &&
		    !(rule->flags & HDN_EXEC_INHERIT_PROFILE))
			return -EINVAL;
		if (rule->parent_profile_id &&
		    !hdn_policy_has_profile(policy, rule->parent_profile_id))
			return -EINVAL;
		if (!rule->flags || (rule->flags & ~valid_exec_flags))
			return -EINVAL;
		if (!(rule->flags & exec_match_flags))
			return -EINVAL;
		if ((rule->flags & HDN_EXEC_MATCH_FILE_ID) &&
		    (rule->flags & HDN_EXEC_RESOLVE_FILE_PATH))
			return -EINVAL;
		if ((rule->flags & HDN_EXEC_MATCH_ORIGINAL_ID) &&
		    (rule->flags & HDN_EXEC_RESOLVE_ORIGINAL_PATH))
			return -EINVAL;
		if ((rule->flags & HDN_EXEC_MATCH_FILE_ID) && !rule->file_ino)
			return -EINVAL;
		if ((rule->flags & HDN_EXEC_MATCH_ORIGINAL_ID) &&
		    !rule->original_ino)
			return -EINVAL;
		if ((rule->flags & HDN_EXEC_RESOLVE_FILE_PATH) &&
		    !hdn_policy_path_valid(rule->file_path))
			return -EINVAL;
		if ((rule->flags & HDN_EXEC_RESOLVE_ORIGINAL_PATH) &&
		    !hdn_policy_path_valid(rule->original_path))
			return -EINVAL;
		if (rule->flags & HDN_EXEC_MATCH_VERITY_DIGEST) {
			if (!rule->verity_digest_size ||
			    rule->verity_digest_size >
			    sizeof(rule->verity_digest))
				return -EINVAL;
		}
	}

	for (i = 0; i < policy->module_rule_count; i++) {
		const struct hdn_module_rule_record *rule =
			&policy->module_rules[i];

		if (!hdn_policy_has_profile(policy, rule->profile_id))
			return -EINVAL;
		if (!rule->flags || (rule->flags & ~valid_module_flags))
			return -EINVAL;
		if ((rule->flags & HDN_MODULE_MATCH_FILE_ID) &&
		    (rule->flags & HDN_MODULE_RESOLVE_FILE_PATH))
			return -EINVAL;
		if ((rule->flags & HDN_MODULE_MATCH_FILE_ID) && !rule->file_ino)
			return -EINVAL;
		if ((rule->flags & HDN_MODULE_RESOLVE_FILE_PATH) &&
		    !hdn_policy_path_valid(rule->file_path))
			return -EINVAL;
		if (rule->flags & HDN_MODULE_MATCH_VERITY_DIGEST) {
			if (!rule->verity_digest_size ||
			    rule->verity_digest_size >
			    sizeof(rule->verity_digest))
				return -EINVAL;
		}
	}

	for (i = 0; i < policy->firmware_rule_count; i++) {
		const struct hdn_firmware_rule_record *rule =
			&policy->firmware_rules[i];

		if (!hdn_policy_has_profile(policy, rule->profile_id))
			return -EINVAL;
		if (rule->flags & ~HDN_FIRMWARE_MATCH_ANY)
			return -EINVAL;
		if ((rule->flags & HDN_FIRMWARE_MATCH_ANY) && rule->name[0])
			return -EINVAL;
		if (!(rule->flags & HDN_FIRMWARE_MATCH_ANY) &&
		    (!rule->name[0] ||
		     !memchr(rule->name, '\0', sizeof(rule->name))))
			return -EINVAL;
	}

	for (i = 0; i < policy->resource_rule_count; i++) {
		const struct hdn_resource_rule_record *rule =
			&policy->resource_rules[i];

		if (!hdn_policy_has_profile(policy, rule->profile_id))
			return -EINVAL;
		if (rule->resource >= RLIM_NLIMITS)
			return -EINVAL;
		if (rule->reserved)
			return -EINVAL;
		if (rule->soft_limit > rule->hard_limit)
			return -EINVAL;
	}

	return 0;
}

static int hdn_verify_policy_signature(const u8 *blob, size_t count,
				       size_t *payload_len)
{
	const size_t marker_len = sizeof(HDN_POLICY_SIG_STRING) - 1;
	struct module_signature ms;
	size_t signed_len;
	size_t sig_len;
	int ret;

	if (count <= marker_len + sizeof(ms))
		return -ENODATA;
	if (memcmp(blob + count - marker_len, HDN_POLICY_SIG_STRING, marker_len))
		return -ENODATA;

	signed_len = count - marker_len;
	memcpy(&ms, blob + signed_len - sizeof(ms), sizeof(ms));
	ret = mod_check_sig(&ms, signed_len, "hardening policy");
	if (ret)
		return ret;

	sig_len = be32_to_cpu(ms.sig_len);
	*payload_len = signed_len - sig_len - sizeof(ms);
	if (*payload_len < sizeof(struct hdn_policy_header))
		return -EBADMSG;

	return verify_pkcs7_signature(blob, *payload_len,
				      blob + *payload_len, sig_len,
				      VERIFY_USE_SECONDARY_KEYRING,
				      VERIFYING_UNSPECIFIED_SIGNATURE,
				      NULL, NULL);
}

static int hdn_policy_page_count(const struct hdn_policy *policy)
{
	return PAGE_ALIGN(policy->alloc_size) >> PAGE_SHIFT;
}

static bool hdn_sealed_range_contains(const void *base, unsigned int pages,
				      unsigned long address)
{
	unsigned long start = (unsigned long)base;
	unsigned long size = (unsigned long)pages << PAGE_SHIFT;
	unsigned long end;

	if (!base || !pages)
		return false;
	if (check_add_overflow(start, size, &end))
		return false;

	return address >= start && address < end;
}

static bool hdn_policy_address_is_sealed(const struct hdn_policy *policy,
					 unsigned long address)
{
	if (!policy || !READ_ONCE(policy->sealed))
		return false;

	return hdn_sealed_range_contains(policy, hdn_policy_page_count(policy),
					 address);
}

static u32 hdn_sealed_address_class(unsigned long address)
{
	const struct hdn_mitigation_state *mitigations;
	const struct hdn_policy *policy;
	u32 type = 0;

	mitigations = READ_ONCE(hdn_mitigations);
	if (mitigations && READ_ONCE(mitigations->sealed) &&
	    hdn_sealed_range_contains(mitigations, mitigations->sealed_pages,
				      address))
		return 2; /* mitigation state */

	rcu_read_lock();
	policy = rcu_dereference(hdn_active_policy);
	if (hdn_policy_address_is_sealed(policy, address)) {
		type = 1; /* policy */
		goto out_unlock;
	}
	policy = rcu_dereference(hdn_previous_policy);
	if (hdn_policy_address_is_sealed(policy, address))
		type = 1;
out_unlock:
	rcu_read_unlock();
	return type;
}

void hdn_report_sealed_write_fault(unsigned long address)
{
	u32 type = hdn_sealed_address_class(address);

	if (!type)
		return;

	hdn_record_event_object_flags(HDN_AUTH_NONE, HDN_TRANS_SEALED_DATA,
				      HDN_REASON_SEALED_DATA_WRITE,
				      HDN_DECISION_DENY_AUDIT, -EFAULT,
				      type, 0);
}

void hdn_report_kernel_mapping_violation(int error)
{
	/* No virtual address, PFN, or caller address crosses the event ABI. */
	hdn_record_event(HDN_AUTH_NONE, HDN_TRANS_KERNEL_MAPPING,
			 error == -EPERM ? HDN_REASON_SEALED_DATA_WRITE :
			 HDN_REASON_KERNEL_WX_MAPPING, HDN_DECISION_DENY_AUDIT, error);
}

void hdn_report_kernel_text_transition(u64 generation, enum hdn_reason reason,
				       int error)
{
	/* A monotonic transition number is an audit identifier, never an address. */
	hdn_record_event_object_flags(HDN_AUTH_NONE, HDN_TRANS_KERNEL_TEXT, reason,
				      error ? HDN_DECISION_DENY_AUDIT :
				      HDN_DECISION_ALLOW_AUDIT, error, generation, 0);
}

void hdn_report_kernel_deferred(enum hdn_transition transition, u64 generation,
				enum hdn_reason reason)
{
	bool denied = reason == HDN_REASON_KERNEL_USER_ACCESS_DENIED;

	hdn_record_event_object_flags(HDN_AUTH_NONE, transition, reason,
				      denied ? HDN_DECISION_DENY_AUDIT : HDN_DECISION_ALLOW_AUDIT,
				      denied ? -EFAULT : 0, generation,
				      HDN_EVENT_DEFERRED_KERNEL);
}

void hdn_report_kernel_seal(u32 type, int error)
{
	hdn_record_event_object_flags(HDN_AUTH_NONE, HDN_TRANS_KERNEL_SEAL,
				      HDN_REASON_KERNEL_SEAL_STATE,
				      error ? HDN_DECISION_DENY_AUDIT : HDN_DECISION_ALLOW_AUDIT,
				      error, type, 0);
}

void hdn_report_kernel_page_transition(u64 generation, enum hdn_reason reason, int error)
{
	hdn_record_event_object_flags(HDN_AUTH_NONE, HDN_TRANS_KERNEL_MAPPING, reason,
				      error ? HDN_DECISION_DENY_AUDIT : HDN_DECISION_ALLOW_AUDIT,
				      error, generation, 0);
}

void hdn_report_control_flow_failure(unsigned long kind)
{
	/* A closed six-class value, never a code address, target hash or stack
	 * byte. This runs only after the architecture installed its fatal domain. */
	if (kind < 1 || kind > 6)
		kind = 6;
	hdn_record_event_object_flags(HDN_AUTH_NONE, HDN_TRANS_KERNEL_TEXT,
				      HDN_REASON_CONTROL_FLOW_VIOLATION,
				      HDN_DECISION_DENY_AUDIT, -EPERM, kind, 0);
}

#ifdef CONFIG_SECURITY_HARDENING_KERNSEAL
static int hdn_policy_seal_validate(const void *data, size_t size)
{
	const struct hdn_policy *policy = data;
	size_t offset = sizeof(*policy), bytes;

	if (policy->alloc_size != size || !policy->sealed || !policy->seal)
		return -EINVAL;
#define HDN_VALIDATE_ARRAY(array, count) do { \
	if (check_mul_overflow((size_t)policy->count, sizeof(*policy->array), &bytes) || \
	    offset > size || bytes > size - offset || \
	    (const void *)policy->array != (const u8 *)data + offset) \
		return -EINVAL; \
	offset += bytes; \
} while (0)
	HDN_VALIDATE_ARRAY(profiles, profile_count);
	HDN_VALIDATE_ARRAY(subject_rules, subject_rule_count);
	HDN_VALIDATE_ARRAY(object_rules, object_rule_count);
	HDN_VALIDATE_ARRAY(exec_rules, exec_rule_count);
	HDN_VALIDATE_ARRAY(module_rules, module_rule_count);
	HDN_VALIDATE_ARRAY(firmware_rules, firmware_rule_count);
	HDN_VALIDATE_ARRAY(resource_rules, resource_rule_count);
#undef HDN_VALIDATE_ARRAY
	if (offset != size)
		return -EINVAL;
	return hdn_validate_profile_ids(policy);
}

static int hdn_mitigation_seal_validate(const void *data, size_t size)
{
	const struct hdn_mitigation_state *state = data;

	return size == PAGE_SIZE && state->abi_version == HDN_POLICY_ABI_VERSION &&
	       state->sealed_pages == 1 && state->sealed && state->seal &&
	       state->flags == hdn_build_mitigation_flags() &&
	       state->flags2 == hdn_build_mitigation_flags2() ? 0 : -EINVAL;
}

static struct hdn_seal *hdn_policy_seal_handle(const void *data)
{
	return ((const struct hdn_policy *)data)->seal;
}

static struct hdn_seal *hdn_mitigation_seal_handle(const void *data)
{
	return ((const struct hdn_mitigation_state *)data)->seal;
}

const struct hdn_seal_type hdn_policy_seal_type = {
	.id = 1,
	.minimum_size = sizeof(struct hdn_policy),
	.maximum_size = HDN_MAX_POLICY_SIZE + sizeof(struct hdn_policy),
	.alignment = __alignof__(struct hdn_policy),
	.readers = HDN_SEAL_READER_RCU_REFCOUNT,
	.replacement = HDN_SEAL_REPLACE_COPY_RCU,
	.validate = hdn_policy_seal_validate,
	.handle = hdn_policy_seal_handle,
};
const struct hdn_seal_type hdn_mitigation_seal_type = {
	.id = 2,
	.minimum_size = PAGE_SIZE,
	.maximum_size = PAGE_SIZE,
	.alignment = __alignof__(struct hdn_mitigation_state),
	.readers = HDN_SEAL_READER_IMMORTAL,
	.replacement = HDN_SEAL_REPLACE_NONE,
	.validate = hdn_mitigation_seal_validate,
	.handle = hdn_mitigation_seal_handle,
};
#endif

static int hdn_policy_seal(struct hdn_policy *policy)
{
	int ret;

	policy->sealed = true;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_KERNSEAL))
		return hdn_seal_finish(policy->seal, &hdn_policy_seal_type);
	set_vm_flush_reset_perms(policy);
	ret = set_memory_ro((unsigned long)policy,
			    hdn_policy_page_count(policy));
	if (ret) {
		if (!set_memory_rw((unsigned long)policy,
				   hdn_policy_page_count(policy)))
			policy->sealed = false;
	}

	return ret;
}

static void hdn_policy_unseal(struct hdn_policy *policy)
{
	if (policy && policy->sealed)
		set_memory_rw((unsigned long)policy,
			      hdn_policy_page_count(policy));
}

static void hdn_policy_free(struct hdn_policy *policy)
{
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_KERNSEAL)) {
		if (policy)
			WARN_ON_ONCE(hdn_seal_destroy(policy->seal, &hdn_policy_seal_type));
		return;
	}
	hdn_policy_unseal(policy);
	vfree(policy);
}

static void hdn_policy_free_workfn(struct work_struct *work_item)
{
	struct hdn_policy_free_work *work =
		container_of(work_item, struct hdn_policy_free_work, work);

	hdn_policy_free(work->policy);
	kfree(work);
}

static void hdn_policy_free_rcu(struct rcu_head *rcu)
{
	struct hdn_policy_free_work *work =
		container_of(rcu, struct hdn_policy_free_work, rcu);

	queue_work(system_unbound_wq, &work->work);
}

static void hdn_policy_free_after_rcu(struct hdn_policy *policy)
{
	struct hdn_policy_free_work *work;

	if (!policy)
		return;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_KERNSEAL)) {
		WARN_ON_ONCE(hdn_seal_retire(policy->seal, &hdn_policy_seal_type));
		return;
	}

	work = kmalloc_obj(*work, GFP_KERNEL);
	if (!work) {
		synchronize_rcu();
		hdn_policy_free(policy);
		return;
	}

	work->policy = policy;
	INIT_WORK(&work->work, hdn_policy_free_workfn);
	call_rcu(&work->rcu, hdn_policy_free_rcu);
}

static u64 hdn_policy_generation(const struct hdn_policy *policy)
{
	return policy ? policy->generation : 0;
}

/* Paired with exec selection; rollback also consumes a fresh, never reused epoch. */
static struct hdn_policy *hdn_publish_policy(struct hdn_policy *policy, bool rollback)
{
	struct hdn_policy *old;
	unsigned long flags;

	lockdep_assert_held(&hdn_policy_mutex);
	write_seqlock_irqsave(&hdn_policy_publication_lock, flags);
	if (!atomic64_inc_return(&hdn_policy_epoch))
		panic("HDN policy epoch exhausted");
	WRITE_ONCE(hdn_compat_policy_enabled, policy && !rollback &&
		   (policy->generation > hdn_compat_generation_highwater ||
		    (!hdn_compat_after_rollback && policy->generation == hdn_compat_generation_highwater)));
	if (policy && policy->generation > hdn_compat_generation_highwater)
		hdn_compat_after_rollback = false;
	if (rollback)
		hdn_compat_after_rollback = true;
	if (policy && policy->generation > hdn_compat_generation_highwater)
		hdn_compat_generation_highwater = policy->generation;
	old = rcu_replace_pointer(hdn_active_policy, policy,
				  lockdep_is_held(&hdn_policy_mutex));
	write_sequnlock_irqrestore(&hdn_policy_publication_lock, flags);
	return old;
}

struct hdn_policy_replace_context {
	bool retain_active_as_previous;
};

static const void *hdn_policy_replace_publish(void *context, const void *next)
{
	const struct hdn_policy_replace_context *replace = context;
	struct hdn_policy *old;

	lockdep_assert_held(&hdn_policy_mutex);
	old = hdn_publish_policy((struct hdn_policy *)next, false);
	if (!replace->retain_active_as_previous)
		return old;
	return rcu_replace_pointer(hdn_previous_policy, old,
				   lockdep_is_held(&hdn_policy_mutex));
}

static bool hdn_policy_base_matches(const struct hdn_policy *policy,
				    const struct hdn_policy *active)
{
	return policy->expected_generation == HDN_POLICY_EXPECT_ANY ||
	       policy->expected_generation == hdn_policy_generation(active);
}

static int hdn_refresh_policy(struct hdn_policy *policy)
{
	struct hdn_policy *active;
	const struct hdn_policy_replace_context replace = {};
	u64 generation = policy->generation;
	enum hdn_reason reason = HDN_REASON_NONE;
	int ret = 0;

	ret = hdn_capabilities_require(policy->required_capabilities);
	if (ret)
		return ret;
	mutex_lock(&hdn_policy_mutex);
	if (hdn_phase != HDN_PHASE_RUNTIME) {
		ret = -EPERM;
		reason = HDN_REASON_INVALID_PHASE;
		goto out_unlock;
	}

	active = rcu_dereference_protected(hdn_active_policy,
					   lockdep_is_held(&hdn_policy_mutex));
	if (!active) {
		ret = -ENODATA;
		reason = HDN_REASON_INVALID_POLICY;
		goto out_unlock;
	}
	if (policy->generation != active->generation ||
	    memcmp(policy->source_digest, active->source_digest,
		   sizeof(policy->source_digest))) {
		ret = -ESTALE;
		reason = HDN_REASON_POLICY_IDENTITY_MISMATCH;
		goto out_unlock;
	}

	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_KERNSEAL)) {
		ret = hdn_seal_replace(policy->seal, &hdn_policy_seal_type,
				       hdn_policy_replace_publish, (void *)&replace);
		if (ret) {
			reason = HDN_REASON_INVALID_POLICY;
			goto out_unlock;
		}
		active = NULL; /* KERNSEAL retired the evicted publication. */
	} else {
		active = hdn_publish_policy(policy, false);
	}
	mutex_unlock(&hdn_policy_mutex);

	hdn_policy_free_after_rcu(active);
	hdn_record_event_object_flags(HDN_AUTH_POLICY_ADMIN,
				      HDN_TRANS_POLICY_REFRESH,
				      HDN_REASON_NONE,
				      HDN_DECISION_ALLOW_AUDIT, 0,
				      generation, 0);
	return 0;

out_unlock:
	mutex_unlock(&hdn_policy_mutex);
	return hdn_deny_object(HDN_AUTH_POLICY_ADMIN,
			       HDN_TRANS_POLICY_REFRESH, reason, ret,
			       policy->generation);
}

static int hdn_stage_policy(struct hdn_policy *policy)
{
	struct hdn_policy *active;
	struct hdn_policy *old_staged;
	u64 generation = policy->generation;
	enum hdn_phase phase;
	int ret = 0;

	mutex_lock(&hdn_policy_mutex);
	phase = hdn_phase;
	if (!hdn_policy_mutable_phase(phase)) {
		mutex_unlock(&hdn_policy_mutex);
		return hdn_deny_object(HDN_AUTH_POLICY_ADMIN,
				       HDN_TRANS_POLICY_LOAD,
				       HDN_REASON_SEALED_RUNTIME, -EPERM,
				       policy->generation);
	}

	active = rcu_dereference_protected(hdn_active_policy,
					   lockdep_is_held(&hdn_policy_mutex));
	if (!hdn_policy_base_matches(policy, active)) {
		ret = -ESTALE;
		goto out_base_mismatch;
	}
	if (active && policy->generation < active->generation) {
		ret = -ESTALE;
		goto out_unlock;
	}

	old_staged = hdn_staged_policy;
	hdn_staged_policy = policy;
	mutex_unlock(&hdn_policy_mutex);

	hdn_policy_free(old_staged);
	hdn_record_event_object_flags(HDN_AUTH_POLICY_ADMIN,
				      HDN_TRANS_POLICY_LOAD, HDN_REASON_NONE,
				      HDN_DECISION_ALLOW_AUDIT, 0,
				      generation, 0);

	return 0;

out_unlock:
	mutex_unlock(&hdn_policy_mutex);
	return hdn_deny_object(HDN_AUTH_POLICY_ADMIN, HDN_TRANS_POLICY_LOAD,
			       HDN_REASON_POLICY_DOWNGRADE, ret,
			       policy->generation);

out_base_mismatch:
	mutex_unlock(&hdn_policy_mutex);
	return hdn_deny_object(HDN_AUTH_POLICY_ADMIN, HDN_TRANS_POLICY_LOAD,
			       HDN_REASON_POLICY_BASE_MISMATCH, ret,
			       policy->generation);
}

static int hdn_commit_policy(void)
{
	struct hdn_policy *policy = NULL;
	struct hdn_policy *old;
	struct hdn_policy *older;
	const struct hdn_policy_replace_context replace = {
		.retain_active_as_previous = true,
	};
	u64 generation = 0;
	enum hdn_reason reason;
	enum hdn_phase phase;
	int ret = 0;

	ret = hdn_require_policy_admin(HDN_TRANS_POLICY_COMMIT);
	if (ret)
		return ret;

	mutex_lock(&hdn_policy_mutex);
	phase = hdn_phase;
	if (!hdn_policy_mutable_phase(phase)) {
		ret = -EPERM;
		reason = HDN_REASON_SEALED_RUNTIME;
		goto out_unlock;
	}

	policy = hdn_staged_policy;
	if (policy)
		generation = policy->generation;
	if (!policy) {
		ret = -ENODATA;
		reason = HDN_REASON_NO_STAGED_POLICY;
		goto out_unlock;
	}
	ret = hdn_capabilities_require(policy->required_capabilities);
	if (ret) {
		reason = HDN_REASON_INVALID_POLICY;
		goto out_unlock;
	}

	old = rcu_dereference_protected(hdn_active_policy,
					lockdep_is_held(&hdn_policy_mutex));
	if (!hdn_policy_base_matches(policy, old)) {
		ret = -ESTALE;
		reason = HDN_REASON_POLICY_BASE_MISMATCH;
		goto out_unlock;
	}
	if (old && policy->generation < old->generation) {
		ret = -ESTALE;
		reason = HDN_REASON_POLICY_DOWNGRADE;
		goto out_unlock;
	}

	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_KERNSEAL)) {
		ret = hdn_seal_replace(policy->seal, &hdn_policy_seal_type,
				       hdn_policy_replace_publish, (void *)&replace);
		if (ret) {
			reason = HDN_REASON_INVALID_POLICY;
			goto out_unlock;
		}
		old = NULL;
		older = NULL; /* KERNSEAL retired the displaced previous policy. */
	} else {
		old = hdn_publish_policy(policy, false);
		older = rcu_replace_pointer(hdn_previous_policy, old,
					    lockdep_is_held(&hdn_policy_mutex));
	}
	hdn_staged_policy = NULL;
	mutex_unlock(&hdn_policy_mutex);

	hdn_policy_free_after_rcu(older);
	hdn_record_event_object_flags(HDN_AUTH_POLICY_ADMIN,
				      HDN_TRANS_POLICY_COMMIT, HDN_REASON_NONE,
				      HDN_DECISION_ALLOW_AUDIT, 0,
				      generation, 0);

	return 0;

out_unlock:
	mutex_unlock(&hdn_policy_mutex);
	return hdn_deny_object(HDN_AUTH_POLICY_ADMIN, HDN_TRANS_POLICY_COMMIT,
			       reason, ret,
			       generation);
}

static int hdn_rollback_policy(void)
{
	struct hdn_policy *active;
	struct hdn_policy *previous;
	struct hdn_policy *staged;
	u64 generation;
	enum hdn_phase phase;
	int ret;

	ret = hdn_require_policy_admin(HDN_TRANS_POLICY_ROLLBACK);
	if (ret)
		return ret;

	mutex_lock(&hdn_policy_mutex);
	phase = hdn_phase;
	if (!hdn_policy_mutable_phase(phase)) {
		mutex_unlock(&hdn_policy_mutex);
		return hdn_deny_object(HDN_AUTH_POLICY_ADMIN,
				       HDN_TRANS_POLICY_ROLLBACK,
				       HDN_REASON_SEALED_RUNTIME, -EPERM,
				       phase);
	}

	active = rcu_dereference_protected(hdn_active_policy,
					   lockdep_is_held(&hdn_policy_mutex));
	previous = rcu_dereference_protected(hdn_previous_policy,
					     lockdep_is_held(&hdn_policy_mutex));
	ret = hdn_capabilities_require(previous ? previous->required_capabilities : 0);
	if (ret) {
		mutex_unlock(&hdn_policy_mutex);
		return hdn_deny(HDN_AUTH_POLICY_ADMIN, HDN_TRANS_POLICY_ROLLBACK,
				HDN_REASON_INVALID_POLICY, ret);
	}
	staged = hdn_staged_policy;
	generation = previous ? previous->generation : 0;
	hdn_staged_policy = NULL;
	hdn_publish_policy(previous, true);
	rcu_assign_pointer(hdn_previous_policy, active);
	mutex_unlock(&hdn_policy_mutex);

	hdn_policy_free(staged);
	hdn_record_event_object_flags(HDN_AUTH_POLICY_ADMIN,
				      HDN_TRANS_POLICY_ROLLBACK,
				      HDN_REASON_NONE, HDN_DECISION_ALLOW_AUDIT,
				      0, generation, 0);

	return 0;
}

enum hdn_policy_load_mode {
	HDN_POLICY_LOAD_STAGE,
	HDN_POLICY_LOAD_REFRESH,
};

static int hdn_load_policy_blob(const char __user *buf, size_t count,
				enum hdn_policy_load_mode mode)
{
	const struct hdn_policy_header *header;
	struct hdn_policy *policy;
	struct hdn_seal *seal = NULL;
	enum hdn_transition transition;
	u8 *blob;
	size_t payload_len;
	size_t expect;
	size_t profile_bytes;
	size_t subject_rule_bytes;
	size_t object_rule_bytes;
	size_t exec_rule_bytes;
	size_t module_rule_bytes;
	size_t firmware_rule_bytes;
	size_t resource_rule_bytes;
	size_t alloc_size;
	u32 i;
	int ret;
	bool invalid_audited = false;

	transition = mode == HDN_POLICY_LOAD_REFRESH ?
		     HDN_TRANS_POLICY_REFRESH : HDN_TRANS_POLICY_LOAD;
	ret = hdn_require_policy_admin(transition);
	if (ret)
		return ret;
	if (count < sizeof(*header) || count > HDN_MAX_SIGNED_POLICY_SIZE)
		return -EINVAL;

	blob = memdup_user(buf, count);
	if (IS_ERR(blob))
		return PTR_ERR(blob);

	ret = hdn_verify_policy_signature(blob, count, &payload_len);
	if (ret) {
		ret = hdn_deny(HDN_AUTH_POLICY_ADMIN, transition,
			       HDN_REASON_INVALID_POLICY, ret);
		invalid_audited = true;
		goto out_blob;
	}
	ret = -EINVAL;
	if (payload_len > HDN_MAX_POLICY_SIZE)
		goto out_blob;

	header = (const struct hdn_policy_header *)blob;
	if (header->magic != HDN_POLICY_MAGIC)
		goto out_blob;
	if (header->abi_version != HDN_POLICY_ABI_VERSION)
		goto out_blob;
	if (header->header_size < sizeof(*header) ||
	    header->header_size > payload_len)
		goto out_blob;
	if (header->profile_size < sizeof(struct hdn_profile_record))
		goto out_blob;
	if (header->subject_rule_size <
	    sizeof(struct hdn_subject_rule_record))
		goto out_blob;
	if (header->object_rule_size < sizeof(struct hdn_object_rule_record))
		goto out_blob;
	if (header->exec_rule_size < sizeof(struct hdn_exec_rule_record))
		goto out_blob;
	if (header->module_rule_size < sizeof(struct hdn_module_rule_record))
		goto out_blob;
	if (header->firmware_rule_size < sizeof(struct hdn_firmware_rule_record))
		goto out_blob;
	if (header->resource_rule_size < sizeof(struct hdn_resource_rule_record))
		goto out_blob;
	if (header->flags & ~HDN_CAP_KNOWN_MASK)
		goto out_blob;
	if (hdn_capabilities_require(header->flags)) {
		ret = -EOPNOTSUPP;
		goto out_blob;
	}
	if (!header->profile_count ||
	    header->profile_count > HDN_MAX_PROFILES)
		goto out_blob;
	if (header->subject_rule_count > HDN_MAX_SUBJECT_RULES)
		goto out_blob;
	if (header->object_rule_count > HDN_MAX_OBJECT_RULES)
		goto out_blob;
	if (header->exec_rule_count > HDN_MAX_EXEC_RULES)
		goto out_blob;
	if (header->module_rule_count > HDN_MAX_MODULE_RULES)
		goto out_blob;
	if (header->firmware_rule_count > HDN_MAX_FIRMWARE_RULES)
		goto out_blob;
	if (header->resource_rule_count > HDN_MAX_RESOURCE_RULES)
		goto out_blob;
	if (check_mul_overflow((size_t)header->profile_count,
			       (size_t)header->profile_size, &profile_bytes))
		goto out_blob;
	if (check_mul_overflow((size_t)header->subject_rule_count,
			       (size_t)header->subject_rule_size,
			       &subject_rule_bytes))
		goto out_blob;
	if (check_mul_overflow((size_t)header->object_rule_count,
			       (size_t)header->object_rule_size,
			       &object_rule_bytes))
		goto out_blob;
	if (check_mul_overflow((size_t)header->exec_rule_count,
			       (size_t)header->exec_rule_size,
			       &exec_rule_bytes))
		goto out_blob;
	if (check_mul_overflow((size_t)header->module_rule_count,
			       (size_t)header->module_rule_size,
			       &module_rule_bytes))
		goto out_blob;
	if (check_mul_overflow((size_t)header->firmware_rule_count,
			       (size_t)header->firmware_rule_size,
			       &firmware_rule_bytes))
		goto out_blob;
	if (check_mul_overflow((size_t)header->resource_rule_count,
			       (size_t)header->resource_rule_size,
			       &resource_rule_bytes))
		goto out_blob;
	if (check_add_overflow((size_t)header->header_size, profile_bytes,
			       &expect))
		goto out_blob;
	if (check_add_overflow(expect, subject_rule_bytes, &expect))
		goto out_blob;
	if (check_add_overflow(expect, object_rule_bytes, &expect))
		goto out_blob;
	if (check_add_overflow(expect, exec_rule_bytes, &expect))
		goto out_blob;
	if (check_add_overflow(expect, module_rule_bytes, &expect))
		goto out_blob;
	if (check_add_overflow(expect, firmware_rule_bytes, &expect))
		goto out_blob;
	if (check_add_overflow(expect, resource_rule_bytes, &expect))
		goto out_blob;
	if (expect != payload_len)
		goto out_blob;

	if (check_add_overflow(struct_size(policy, profiles,
					   header->profile_count),
			       array_size(header->subject_rule_count,
					  sizeof(struct hdn_subject_rule_record)),
			       &alloc_size))
		goto out_blob;
	if (check_add_overflow(alloc_size,
			       array_size(header->object_rule_count,
					  sizeof(struct hdn_object_rule_record)),
			       &alloc_size))
		goto out_blob;
	if (check_add_overflow(alloc_size,
			       array_size(header->exec_rule_count,
					  sizeof(struct hdn_exec_rule_record)),
			       &alloc_size))
		goto out_blob;
	if (check_add_overflow(alloc_size,
			       array_size(header->module_rule_count,
					  sizeof(struct hdn_module_rule_record)),
			       &alloc_size))
		goto out_blob;
	if (check_add_overflow(alloc_size,
			       array_size(header->firmware_rule_count,
					  sizeof(struct hdn_firmware_rule_record)),
			       &alloc_size))
		goto out_blob;
	if (check_add_overflow(alloc_size,
			       array_size(header->resource_rule_count,
					  sizeof(struct hdn_resource_rule_record)),
			       &alloc_size))
		goto out_blob;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_KERNSEAL)) {
		seal = hdn_seal_create(&hdn_policy_seal_type, alloc_size, NUMA_NO_NODE);
		if (IS_ERR(seal)) {
			ret = PTR_ERR(seal);
			goto out_blob;
		}
		policy = hdn_seal_write(seal, &hdn_policy_seal_type);
	} else {
		policy = vzalloc(alloc_size);
	}
	if (!policy) {
		if (seal)
			hdn_seal_destroy(seal, &hdn_policy_seal_type);
		ret = -ENOMEM;
		goto out_blob;
	}

	policy->seal = seal;
	policy->alloc_size = alloc_size;
	policy->required_capabilities = header->flags;
	policy->profile_count = header->profile_count;
	policy->subject_rule_count = header->subject_rule_count;
	policy->object_rule_count = header->object_rule_count;
	policy->exec_rule_count = header->exec_rule_count;
	policy->module_rule_count = header->module_rule_count;
	policy->firmware_rule_count = header->firmware_rule_count;
	policy->resource_rule_count = header->resource_rule_count;
	policy->generation = header->generation;
	policy->expected_generation = header->expected_generation;
	policy->default_profile_id = header->default_profile_id;
	policy->privileged_profile_id = header->privileged_profile_id;
	sha256(blob, payload_len, policy->source_digest);
	policy->subject_rules =
		(struct hdn_subject_rule_record *)&policy->profiles[header->profile_count];
	policy->object_rules =
		(struct hdn_object_rule_record *)&policy->subject_rules[header->subject_rule_count];
	policy->exec_rules =
		(struct hdn_exec_rule_record *)&policy->object_rules[header->object_rule_count];
	policy->module_rules =
		(struct hdn_module_rule_record *)&policy->exec_rules[header->exec_rule_count];
	policy->firmware_rules =
		(struct hdn_firmware_rule_record *)&policy->module_rules[header->module_rule_count];
	policy->resource_rules =
		(struct hdn_resource_rule_record *)&policy->firmware_rules[header->firmware_rule_count];

	for (i = 0; i < header->profile_count; i++) {
		const u8 *src = blob + header->header_size +
				((size_t)i * header->profile_size);

		memcpy(&policy->profiles[i], src, sizeof(policy->profiles[i]));
		policy->profiles[i].name[HDN_PROFILE_NAME_LEN - 1] = '\0';
	}

	for (i = 0; i < header->subject_rule_count; i++) {
		const u8 *src = blob + header->header_size + profile_bytes +
				((size_t)i * header->subject_rule_size);

		memcpy(&policy->subject_rules[i], src,
		       sizeof(policy->subject_rules[i]));
	}

	for (i = 0; i < header->object_rule_count; i++) {
		const u8 *src = blob + header->header_size + profile_bytes +
				subject_rule_bytes +
				((size_t)i * header->object_rule_size);

		memcpy(&policy->object_rules[i], src,
		       sizeof(policy->object_rules[i]));
	}

	for (i = 0; i < header->exec_rule_count; i++) {
		const u8 *src = blob + header->header_size + profile_bytes +
				subject_rule_bytes + object_rule_bytes +
				((size_t)i * header->exec_rule_size);

		memcpy(&policy->exec_rules[i], src,
		       sizeof(policy->exec_rules[i]));
	}

	for (i = 0; i < header->module_rule_count; i++) {
		const u8 *src = blob + header->header_size + profile_bytes +
				subject_rule_bytes + object_rule_bytes +
				exec_rule_bytes +
				((size_t)i * header->module_rule_size);

		memcpy(&policy->module_rules[i], src,
		       sizeof(policy->module_rules[i]));
	}

	for (i = 0; i < header->firmware_rule_count; i++) {
		const u8 *src = blob + header->header_size + profile_bytes +
				subject_rule_bytes + object_rule_bytes +
				exec_rule_bytes + module_rule_bytes +
				((size_t)i * header->firmware_rule_size);

		memcpy(&policy->firmware_rules[i], src,
		       sizeof(policy->firmware_rules[i]));
	}

	for (i = 0; i < header->resource_rule_count; i++) {
		const u8 *src = blob + header->header_size + profile_bytes +
				subject_rule_bytes + object_rule_bytes +
				exec_rule_bytes + module_rule_bytes +
				firmware_rule_bytes +
				((size_t)i * header->resource_rule_size);

		memcpy(&policy->resource_rules[i], src,
		       sizeof(policy->resource_rules[i]));
	}

	ret = hdn_validate_profile_ids(policy);
	if (ret) {
		hdn_policy_free(policy);
		goto out_blob;
	}
	ret = hdn_resolve_policy_paths(policy);
	if (ret) {
		hdn_policy_free(policy);
		goto out_blob;
	}
	ret = hdn_validate_profile_ids(policy);
	if (ret) {
		hdn_policy_free(policy);
		goto out_blob;
	}

	ret = hdn_policy_seal(policy);
	if (ret)
		goto out_policy;

	if (mode == HDN_POLICY_LOAD_REFRESH)
		ret = hdn_refresh_policy(policy);
	else
		ret = hdn_stage_policy(policy);
	if (ret)
		goto out_policy;

	policy = NULL;

out_policy:
	hdn_policy_free(policy);

out_blob:
	kvfree(blob);
	if (ret == -EINVAL && !invalid_audited)
		ret = hdn_deny(HDN_AUTH_POLICY_ADMIN, transition,
			       HDN_REASON_INVALID_POLICY, ret);
	return ret;
}

static ssize_t hdn_policy_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	int ret;

	if (*ppos != 0)
		return -ESPIPE;

	ret = hdn_load_policy_blob(buf, count, HDN_POLICY_LOAD_STAGE);
	if (ret)
		return ret;

	*ppos += count;
	return count;
}

static const struct file_operations hdn_policy_fops = {
	.write = hdn_policy_write,
	.llseek = noop_llseek,
};

static ssize_t hdn_refresh_write(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	int ret;

	if (*ppos != 0)
		return -ESPIPE;

	ret = hdn_load_policy_blob(buf, count, HDN_POLICY_LOAD_REFRESH);
	if (ret)
		return ret;

	*ppos += count;
	return count;
}

static const struct file_operations hdn_refresh_fops = {
	.write = hdn_refresh_write,
	.llseek = noop_llseek,
};

static ssize_t hdn_commit_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	int ret;

	if (*ppos != 0)
		return -ESPIPE;

	ret = hdn_commit_policy();
	if (ret)
		return ret;

	*ppos += count;
	return count;
}

static const struct file_operations hdn_commit_fops = {
	.write = hdn_commit_write,
	.llseek = noop_llseek,
};

static ssize_t hdn_rollback_write(struct file *file, const char __user *buf,
				  size_t count, loff_t *ppos)
{
	int ret;

	if (*ppos != 0)
		return -ESPIPE;

	ret = hdn_rollback_policy();
	if (ret)
		return ret;

	*ppos += count;
	return count;
}

static const struct file_operations hdn_rollback_fops = {
	.write = hdn_rollback_write,
	.llseek = noop_llseek,
};

static int hdn_phase_show(struct seq_file *m, void *v)
{
	enum hdn_phase phase = READ_ONCE(hdn_phase);

	seq_printf(m, "%s\n", hdn_phase_name(phase));
	return 0;
}

static int hdn_phase_open(struct inode *inode, struct file *file)
{
	return single_open(file, hdn_phase_show, NULL);
}

static int hdn_set_phase(enum hdn_phase phase)
{
	enum hdn_phase old;
	int ret = 0;

	ret = hdn_require_policy_admin(HDN_TRANS_PHASE_CHANGE);
	if (ret)
		return ret;

	mutex_lock(&hdn_policy_mutex);
	old = hdn_phase;
	if (!hdn_phase_can_transition(old, phase))
		ret = -EPERM;
	else
		WRITE_ONCE(hdn_phase, phase);
	mutex_unlock(&hdn_policy_mutex);

	if (ret)
		return hdn_deny_object(HDN_AUTH_POLICY_ADMIN,
				       HDN_TRANS_PHASE_CHANGE,
				       HDN_REASON_INVALID_PHASE, ret, phase);

	return 0;
}

static ssize_t hdn_phase_write(struct file *file, const char __user *buf,
			       size_t count, loff_t *ppos)
{
	enum hdn_phase phase;
	char *phase_buf;
	int ret;

	if (*ppos != 0)
		return -ESPIPE;
	if (!count || count > 32)
		return -EINVAL;

	phase_buf = memdup_user_nul(buf, count);
	if (IS_ERR(phase_buf))
		return PTR_ERR(phase_buf);

	ret = hdn_parse_phase(phase_buf, &phase);
	kfree(phase_buf);
	if (ret)
		return ret;

	ret = hdn_set_phase(phase);
	if (ret)
		return ret;

	*ppos += count;
	return count;
}

static const struct file_operations hdn_phase_fops = {
	.open = hdn_phase_open,
	.read = seq_read,
	.write = hdn_phase_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static void hdn_reset_audit_flood_buckets_locked(void)
{
	memset(hdn_audit_flood_buckets, 0, sizeof(hdn_audit_flood_buckets));
}

static int hdn_set_audit_flood_burst(u32 burst)
{
	unsigned long flags;
	int ret;

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_AUDIT_FLOOD))
		return -EOPNOTSUPP;
	if (burst < HDN_AUDIT_FLOOD_MIN_BURST ||
	    burst > HDN_AUDIT_FLOOD_MAX_BURST)
		return -ERANGE;

	ret = hdn_require_policy_admin(HDN_TRANS_PHASE_CHANGE);
	if (ret)
		return ret;

	spin_lock_irqsave(&hdn_event_lock, flags);
	WRITE_ONCE(hdn_audit_flood_burst, burst);
	hdn_reset_audit_flood_buckets_locked();
	spin_unlock_irqrestore(&hdn_event_lock, flags);

	return 0;
}

static int hdn_set_audit_flood_window_ms(u64 window_ms)
{
	unsigned long flags;
	u64 window_ns;
	int ret;

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_AUDIT_FLOOD))
		return -EOPNOTSUPP;
	if (window_ms < HDN_AUDIT_FLOOD_MIN_WINDOW_MS ||
	    window_ms > HDN_AUDIT_FLOOD_MAX_WINDOW_MS)
		return -ERANGE;

	window_ns = window_ms * NSEC_PER_MSEC;
	ret = hdn_require_policy_admin(HDN_TRANS_PHASE_CHANGE);
	if (ret)
		return ret;

	spin_lock_irqsave(&hdn_event_lock, flags);
	WRITE_ONCE(hdn_audit_flood_window_ns, window_ns);
	hdn_reset_audit_flood_buckets_locked();
	spin_unlock_irqrestore(&hdn_event_lock, flags);

	return 0;
}

static int hdn_audit_flood_burst_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%u\n", READ_ONCE(hdn_audit_flood_burst));
	return 0;
}

static int hdn_audit_flood_burst_open(struct inode *inode, struct file *file)
{
	return single_open(file, hdn_audit_flood_burst_show, NULL);
}

static ssize_t hdn_audit_flood_burst_write(struct file *file,
					   const char __user *buf,
					   size_t count, loff_t *ppos)
{
	unsigned int burst;
	int ret;

	if (*ppos != 0)
		return -ESPIPE;

	ret = kstrtouint_from_user(buf, count, 10, &burst);
	if (ret)
		return ret;

	ret = hdn_set_audit_flood_burst(burst);
	if (ret)
		return ret;

	*ppos += count;
	return count;
}

static const struct file_operations hdn_audit_flood_burst_fops = {
	.open = hdn_audit_flood_burst_open,
	.read = seq_read,
	.write = hdn_audit_flood_burst_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static int hdn_audit_flood_window_ms_show(struct seq_file *m, void *v)
{
	u64 window_ms = READ_ONCE(hdn_audit_flood_window_ns) / NSEC_PER_MSEC;

	seq_printf(m, "%llu\n", (unsigned long long)window_ms);
	return 0;
}

static int hdn_audit_flood_window_ms_open(struct inode *inode,
					  struct file *file)
{
	return single_open(file, hdn_audit_flood_window_ms_show, NULL);
}

static ssize_t hdn_audit_flood_window_ms_write(struct file *file,
					       const char __user *buf,
					       size_t count, loff_t *ppos)
{
	unsigned long long window_ms;
	int ret;

	if (*ppos != 0)
		return -ESPIPE;

	ret = kstrtoull_from_user(buf, count, 10, &window_ms);
	if (ret)
		return ret;

	ret = hdn_set_audit_flood_window_ms(window_ms);
	if (ret)
		return ret;

	*ppos += count;
	return count;
}

static const struct file_operations hdn_audit_flood_window_ms_fops = {
	.open = hdn_audit_flood_window_ms_open,
	.read = seq_read,
	.write = hdn_audit_flood_window_ms_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static int hdn_status_show(struct seq_file *m, void *v)
{
	struct hdn_policy *policy;
	struct hdn_policy *previous;
	struct hdn_policy *staged;
	struct hdn_seal_stats seal_stats;
	struct hdn_stack_stats stack_stats;
	enum hdn_phase phase;
	unsigned long event_flags;
	u64 audit_flood_window_ns;
	u32 audit_flood_burst;
	u64 audit_flood_suppressed_total;
	u32 audit_flood_last_action;
	u32 audit_flood_last_authority;
	u32 audit_flood_last_transition;
	u32 audit_flood_last_reason;

	hdn_seal_get_stats(&seal_stats);
	hdn_stack_get_stats(&stack_stats);

#ifdef CONFIG_SECURITY_HARDENING_KERNEL_WX
	struct hdn_text_window_stats text_stats;
#endif
#ifdef CONFIG_SECURITY_HARDENING_EXECMEM
	struct hdn_execmem_stats page_stats;
	struct execmem_bpf_stats bpf_stats;
#endif
#ifdef CONFIG_SECURITY_HARDENING_SLAB_LAYOUT
	struct hdn_slab_layout_stats slab_stats;

	hdn_slab_layout_stats(&slab_stats);
	seq_printf(m, "slab_layout_state: %s\n", slab_stats.active ? "active" : "initializing");
	seq_printf(m, "slab_layout_test_interface: %u\n",
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_SLAB_LAYOUT_TEST));
	if (ns_capable(&init_user_ns, CAP_SYS_ADMIN)) {
		seq_printf(m, "slab_layout_allocation_attempts: %llu\n",
			   slab_stats.allocation_attempts);
		seq_printf(m, "slab_layout_allocation_failures: %llu\n",
			   slab_stats.allocation_failures);
		seq_printf(m, "slab_layout_slabs: %llu\n", slab_stats.slabs);
		seq_printf(m, "slab_layout_fallbacks: %llu\n", slab_stats.fallback);
		seq_printf(m, "slab_layout_no_offset_room: %llu\n", slab_stats.no_offset_room);
		seq_printf(m, "slab_layout_offset_slabs: %llu\n", slab_stats.offset_slabs);
		seq_printf(m, "slab_layout_offset_bytes: %llu\n", slab_stats.offset_bytes);
		seq_printf(m, "slab_layout_original_objects: %llu\n",
			   slab_stats.original_objects);
		seq_printf(m, "slab_layout_placed_objects: %llu\n",
			   slab_stats.placed_objects);
		seq_printf(m, "slab_layout_displaced_objects: %llu\n",
			   slab_stats.displaced_objects);
	}
#else
	seq_puts(m, "slab_layout_state: disabled\nslab_layout_test_interface: 0\n");
#endif
#ifdef CONFIG_SECURITY_HARDENING_AUTOSLAB
	{
		struct hdn_alloc_stats stats;

		hdn_alloc_get_stats(&stats);
		seq_printf(m, "autoslab_state: %s\n", stats.ready ? "active" : "initializing");
		seq_printf(m, "autoslab_metadata_version: 1\nautoslab_cache_budget: 2048\n");
		seq_printf(m, "autoslab_caches: %u\n", stats.caches);
		if (ns_capable(&init_user_ns, CAP_SYS_ADMIN)) {
			seq_printf(m, "autoslab_typed: %llu\n", stats.typed);
			seq_printf(m, "autoslab_successful: %llu\n", stats.successful);
			seq_printf(m, "autoslab_failed: %llu\n", stats.failed);
			seq_printf(m, "autoslab_mandatory: %llu\n", stats.mandatory);
			seq_printf(m, "autoslab_early: %llu\n", stats.early);
			seq_printf(m, "autoslab_rejected: %llu\n", stats.rejected);
		}
	}
#else
	seq_puts(m, "autoslab_state: disabled\n");
#endif
#ifdef CONFIG_SECURITY_HARDENING_SLAB_JITTER
	{
		struct hdn_jitter_stats stats;

		hdn_jitter_get_stats(&stats);
		seq_printf(m, "critical_jitter_state: %s\n", !stats.entropy_ready ? "initializing" :
			   stats.early_live ? "degraded-entropy" : "active");
		seq_puts(m, "critical_jitter_metadata_version: 1\n");
		seq_puts(m, "critical_jitter_classes: credentials,files,backing-files\n");
		seq_puts(m, "critical_jitter_placement_slots: 8\n");
		seq_puts(m, "critical_jitter_queue_limit_per_class: 128\n");
		if (ns_capable(&init_user_ns, CAP_SYS_ADMIN)) {
			seq_printf(m, "critical_jitter_allocations: %llu\n", stats.allocations);
			seq_printf(m, "critical_jitter_allocation_failures: %llu\n",
				   stats.allocation_failures);
			seq_printf(m, "critical_jitter_retired: %llu\n", stats.retired);
			seq_printf(m, "critical_jitter_released: %llu\n", stats.released);
			seq_printf(m, "critical_jitter_quarantined: %u\n", stats.quarantined);
			seq_printf(m, "critical_jitter_pressure: %llu\n", stats.pressure);
			seq_printf(m, "critical_jitter_early_live: %llu\n", stats.early_live);
			seq_printf(m, "critical_jitter_failures: %llu\n", stats.integrity_failures);
			seq_printf(m, "critical_jitter_cred_allocations: %llu\n",
				   stats.classes[HDN_JITTER_CRED].allocations);
			seq_printf(m, "critical_jitter_cred_allocation_failures: %llu\n",
				   stats.classes[HDN_JITTER_CRED].allocation_failures);
			seq_printf(m, "critical_jitter_cred_retired: %llu\n",
				   stats.classes[HDN_JITTER_CRED].retired);
			seq_printf(m, "critical_jitter_cred_released: %llu\n",
				   stats.classes[HDN_JITTER_CRED].released);
			seq_printf(m, "critical_jitter_cred_quarantined: %u\n",
				   stats.classes[HDN_JITTER_CRED].quarantined);
			seq_printf(m, "critical_jitter_cred_pressure: %llu\n",
				   stats.classes[HDN_JITTER_CRED].pressure);
			seq_printf(m, "critical_jitter_file_allocations: %llu\n",
				   stats.classes[HDN_JITTER_FILE].allocations);
			seq_printf(m, "critical_jitter_file_allocation_failures: %llu\n",
				   stats.classes[HDN_JITTER_FILE].allocation_failures);
			seq_printf(m, "critical_jitter_file_retired: %llu\n",
				   stats.classes[HDN_JITTER_FILE].retired);
			seq_printf(m, "critical_jitter_file_released: %llu\n",
				   stats.classes[HDN_JITTER_FILE].released);
			seq_printf(m, "critical_jitter_file_quarantined: %u\n",
				   stats.classes[HDN_JITTER_FILE].quarantined);
			seq_printf(m, "critical_jitter_file_pressure: %llu\n",
				   stats.classes[HDN_JITTER_FILE].pressure);
			seq_printf(m, "critical_jitter_backing_file_allocations: %llu\n",
				   stats.classes[HDN_JITTER_BACKING_FILE].allocations);
			seq_printf(m, "critical_jitter_backing_file_allocation_failures: %llu\n",
				   stats.classes[HDN_JITTER_BACKING_FILE].allocation_failures);
			seq_printf(m, "critical_jitter_backing_file_retired: %llu\n",
				   stats.classes[HDN_JITTER_BACKING_FILE].retired);
			seq_printf(m, "critical_jitter_backing_file_released: %llu\n",
				   stats.classes[HDN_JITTER_BACKING_FILE].released);
			seq_printf(m, "critical_jitter_backing_file_quarantined: %u\n",
				   stats.classes[HDN_JITTER_BACKING_FILE].quarantined);
			seq_printf(m, "critical_jitter_backing_file_pressure: %llu\n",
				   stats.classes[HDN_JITTER_BACKING_FILE].pressure);
		}
	}
#else
	seq_puts(m, "critical_jitter_state: disabled\n");
#endif
	seq_printf(m, "kernexec_page_tables: %s\n", hdn_pt_state());
	seq_printf(m, "kernexec_firmware_wx: %s\n", hdn_pt_firmware_state());
	seq_printf(m, "kernexec_terminal_handoff: %s\n", hdn_pt_terminal_state());
#ifdef CONFIG_SECURITY_HARDENING_PGTABLE
	if (ns_capable(&init_user_ns, CAP_SYS_ADMIN)) {
		struct hdn_pt_stats stats;

		hdn_pt_get_stats(&stats);
		seq_printf(m, "kernexec_page_table_allocations: %llu\n", stats.allocated);
		seq_printf(m, "kernexec_page_table_retirements: %llu\n", stats.retired);
		seq_printf(m, "kernexec_page_table_owned_pages: %llu\n", stats.active_pages);
		seq_printf(m, "kernexec_page_table_reserve_pages: %llu\n", stats.reserve_pages);
		seq_printf(m, "kernexec_page_table_allocation_failures: %llu\n", stats.allocation_failures);
		seq_printf(m, "kernexec_foreign_code_ranges: %llu\n", stats.foreign_code_ranges);
		seq_printf(m, "kernexec_foreign_code_pages: %llu\n", stats.foreign_code_pages);
	}
#endif
#ifdef CONFIG_SECURITY_HARDENING_EXECMEM
	hdn_execmem_get_stats(&page_stats);
	execmem_bpf_get_stats(&bpf_stats);
	seq_printf(m, "kernexec_allocations: %llu\n", page_stats.allocations);
	seq_printf(m, "kernexec_owned_pages: %llu\n", page_stats.live_pages);
	seq_printf(m, "kernexec_finalized: %llu\n", page_stats.finalized);
	seq_printf(m, "kernexec_retired: %llu\n", page_stats.retired);
	seq_printf(m, "kernexec_failed_retirements: %llu\n", page_stats.failed_retirements);
	seq_printf(m, "bpf_execmem_state: %s\n",
		   !IS_ENABLED(CONFIG_SECURITY_HARDENING_BPF_EXECMEM) ? "disabled" :
		   bpf_stats.exhausted && page_stats.bpf_live_pages >=
		   (execmem_bpf_capacity() >> PAGE_SHIFT) * 3 / 4 ? "exhausted" :
		   bpf_stats.exhausted || page_stats.bpf_failed_retirements ? "degraded" :
		   execmem_bpf_capacity() ? "active" : "initializing");
	seq_printf(m, "bpf_execmem_test_interface: %u\n",
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_BPF_EXECMEM_TEST));
	if (ns_capable(&init_user_ns, CAP_SYS_ADMIN)) {
		seq_printf(m, "bpf_execmem_capacity_bytes: %lu\n", execmem_bpf_capacity());
		seq_printf(m, "bpf_execmem_live_pages: %llu\n", page_stats.bpf_live_pages);
		seq_printf(m, "bpf_execmem_quarantined_pages: %llu\n", page_stats.bpf_quarantined_pages);
		seq_printf(m, "bpf_execmem_failed_retirements: %llu\n",
			   page_stats.bpf_failed_retirements);
		seq_printf(m, "bpf_execmem_quarantine_limit_pages: %llu\n",
			   page_stats.bpf_quarantine_limit_pages);
		seq_printf(m, "bpf_execmem_quarantine_pressure_releases: %llu\n",
			   page_stats.bpf_quarantine_pressure_releases);
		seq_printf(m, "bpf_execmem_allocation_attempts: %llu\n",
			   bpf_stats.allocation_attempts);
		seq_printf(m, "bpf_execmem_allocation_successes: %llu\n",
			   bpf_stats.allocation_successes);
		seq_printf(m, "bpf_execmem_allocation_failures: %llu\n",
			   bpf_stats.allocation_failures);
		seq_printf(m, "bpf_execmem_requested_bytes: %llu\n",
			   bpf_stats.requested_bytes);
		seq_printf(m, "bpf_execmem_reserved_bytes: %llu\n",
			   bpf_stats.reserved_bytes);
		seq_printf(m, "bpf_execmem_internal_slack_bytes: %llu\n",
			   bpf_stats.reserved_bytes - bpf_stats.requested_bytes);
	}
#endif
#ifdef CONFIG_SECURITY_HARDENING_KERNEL_WX
	hdn_text_get_stats(&text_stats);
	seq_puts(m, "kernexec_text_windows: active\n");
	seq_printf(m, "kernexec_text_started: %llu\n", text_stats.started);
	seq_printf(m, "kernexec_text_completed: %llu\n", text_stats.completed);
	seq_printf(m, "kernexec_text_rejected: %llu\n", text_stats.rejected);
	seq_printf(m, "kernexec_deferred_kernel_overflow: %llu\n",
		   text_stats.audit_omitted);
	seq_printf(m, "kernexec_deferred_kernel_events: %llu\n",
		   text_stats.audit_deferred);
	seq_printf(m, "kernexec_gdt: %s\n", hdn_gdt_state());
	seq_printf(m, "kernexec_idt: %s\n", hdn_idt_sealed() ? "active" :
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_GDT) ? "initializing" : "disabled");
	seq_printf(m, "kernexec_ldt: %s\n", !IS_ENABLED(CONFIG_MODIFY_LDT_SYSCALL) ?
		   "not-applicable" : IS_ENABLED(CONFIG_SECURITY_HARDENING_LDT) ? "active" : "disabled");
	seq_printf(m, "kernexec_text_active: %u\n", text_stats.active);
#else
	seq_puts(m, "kernexec_text_windows: disabled\n");
	seq_puts(m, "kernexec_gdt: disabled\n");
	seq_puts(m, "kernexec_idt: disabled\nkernexec_ldt: disabled\n");
#endif
	mutex_lock(&hdn_policy_mutex);
	policy = rcu_dereference_protected(hdn_active_policy,
					   lockdep_is_held(&hdn_policy_mutex));
	previous = rcu_dereference_protected(hdn_previous_policy,
					     lockdep_is_held(&hdn_policy_mutex));
	staged = hdn_staged_policy;
	phase = READ_ONCE(hdn_phase);
	seq_puts(m, "compatibility_intent_version: 1\n");
	seq_printf(m, "compatibility_binding_version: %u\n", IS_ENABLED(CONFIG_FS_VERITY) ? 1 : 0);
	seq_printf(m, "application_compatibility: %s\n",
		   !IS_ENABLED(CONFIG_FS_VERITY) ? "unsupported" :
		   hdn_compat_policy_enabled ? "available" : "approval-required");
	seq_puts(m, "application_remediation: restart-then-update-application\n");
	seq_puts(m, "legacy_emulation: no-supported-patterns\n");
	seq_printf(m, "respectre_state: %s\n",
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_RESPECTRE) ? "compiler-instrumented" : "disabled");
	seq_printf(m, "respectre_coverage: %s\n",
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_RESPECTRE) ?
		   "selected-c-dataflow" : "none");
	seq_printf(m, "respectre_report_schema: %u\n",
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_RESPECTRE) ? 1 : 0);
	seq_printf(m, "respectre_analyzer_version: %u\n",
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_RESPECTRE) ? 1 : 0);
	seq_printf(m, "respectre_compiler_abi: %s\n",
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_RESPECTRE) ? "gcc-16" : "none");
	seq_printf(m, "respectre_store_bypass: %s\n",
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_RESPECTRE) ?
		   "software-serialization" : "disabled");
	seq_printf(m, "respectre_test_interface: %u\n",
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_RESPECTRE_TEST));
	seq_printf(m, "abi_version: %u\n", HDN_POLICY_ABI_VERSION);
	hdn_capabilities_show(m);
	seq_printf(m, "capability_required_mask: 0x%x\n",
		   policy ? policy->required_capabilities : 0);
	seq_printf(m, "capability_requirements: %s\n",
		   !policy ? "no-policy" : !policy->required_capabilities ? "unconstrained" :
		   hdn_capabilities_require(policy->required_capabilities) ?
		   "unsatisfied" : "satisfied");
	seq_printf(m, "latent_entropy_mixing: %u\n",
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_LATENT_ENTROPY));
	seq_printf(m, "kernexec_private_allocations: %u\n",
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_EXECMEM));
	seq_printf(m, "kernseal_typed_objects: %u\n",
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_KERNSEAL));
	seq_printf(m, "kernseal_state: %s\n",
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_KERNSEAL) ? "active" : "disabled");
	if (ns_capable(&init_user_ns, CAP_SYS_ADMIN)) {
		seq_printf(m, "kernseal_allocations: %llu\n", seal_stats.allocations);
		seq_printf(m, "kernseal_live_objects: %llu\n", seal_stats.live_objects);
		seq_printf(m, "kernseal_live_pages: %llu\n", seal_stats.live_pages);
		seq_printf(m, "kernseal_live_payload_bytes: %llu\n",
			   seal_stats.live_payload_bytes);
		seq_printf(m, "kernseal_live_granule_bytes: %llu\n",
			   seal_stats.live_granule_bytes);
		seq_printf(m, "kernseal_fragmentation_bytes: %llu\n",
			   seal_stats.live_granule_bytes - seal_stats.live_payload_bytes);
		seq_printf(m, "kernseal_seal_operations: %llu\n", seal_stats.seal_operations);
		seq_printf(m, "kernseal_publications: %llu\n", seal_stats.publications);
		seq_printf(m, "kernseal_replacements: %llu\n", seal_stats.replacements);
		seq_printf(m, "kernseal_retirements: %llu\n", seal_stats.retirements);
		seq_printf(m, "kernseal_discards: %llu\n", seal_stats.discards);
		seq_printf(m, "kernseal_rejections: %llu\n", seal_stats.rejections);
		seq_printf(m, "kernseal_allocation_failures: %llu\n",
			   seal_stats.allocation_failures);
		seq_printf(m, "kernseal_replacement_total_ns: %llu\n",
			   seal_stats.replacement_total_ns);
		seq_printf(m, "kernseal_replacement_max_ns: %llu\n",
			   seal_stats.replacement_max_ns);
	}
	seq_printf(m, "initify_image_aliases: %s\n",
		   !IS_ENABLED(CONFIG_SECURITY_HARDENING_INITIFY) ? "disabled" :
		   hdn_init_aliases_retired() ? "retired" : "initializing");
	seq_printf(m, "initify_reclaimed_bytes: %lu\n", hdn_init_reclaimed_bytes());
	seq_printf(m, "static_lifetime_analysis: %u\n",
		   IS_ENABLED(CONFIG_GCC_PLUGIN_HDN_LIFETIME));
	seq_printf(m, "constify_test_interface: %u\n",
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_CONSTIFY_TEST));
	seq_printf(m, "rap_state: %s\n", hdn_rap_state());
	seq_printf(m, "rap_metadata_version: %u\n",
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_RAP) ? HDN_RAP_VERSION : 0);
	seq_printf(m, "rap_transfer_abi: %u\n",
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_RAP) ? HDN_RAP_ABI : 0);
	seq_printf(m, "rap_failure_classes: %u\n",
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_RAP) ? HDN_RAP_FAILURE_CLASSES : 0);
	seq_printf(m, "rap_build_identity: %s\n", hdn_rap_build_identity());
	seq_printf(m, "rap_xor_state: %s\n",
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_RAP) ? "base-only" : "disabled");
	seq_printf(m, "private_stacks_state: %s\n", hdn_stack_state());
	seq_printf(m, "private_stacks_test_interface: %u\n",
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_PRIVATE_STACKS_TEST));
	seq_printf(m, "kvm_state_test_interface: %u\n",
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_KVM_STATE_TEST));
	if (ns_capable(&init_user_ns, CAP_SYS_ADMIN)) {
		seq_printf(m, "private_stacks_allocation_attempts: %llu\n",
			   stack_stats.allocation_attempts);
		seq_printf(m, "private_stacks_allocations: %llu\n", stack_stats.allocations);
		seq_printf(m, "private_stacks_allocation_failures: %llu\n",
			   stack_stats.allocation_failures);
		seq_printf(m, "private_stacks_live: %llu\n", stack_stats.live_stacks);
		seq_printf(m, "private_stacks_publications: %llu\n", stack_stats.publications);
		seq_printf(m, "private_stacks_retirements: %llu\n", stack_stats.retirements);
		seq_printf(m, "private_stacks_diagnostic_reads: %llu\n",
			   stack_stats.diagnostic_reads);
		seq_printf(m, "private_stacks_diagnostic_read_failures: %llu\n",
			   stack_stats.diagnostic_read_failures);
		seq_printf(m, "private_stacks_construction_bytes: %llu\n",
			   stack_stats.construction_bytes);
		seq_printf(m, "private_stacks_task_switches: %llu\n", stack_stats.task_switches);
		seq_printf(m, "private_stacks_async_root_entries: %llu\n",
			   stack_stats.async_root_entries);
	}
	seq_printf(m, "rap_error_test_interface: %u\n",
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_RAP_ERROR_TEST));
	seq_printf(m, "rap_test_interface: %u\n",
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_RAP_TEST));
	seq_printf(m, "uderef_state: %s\n", hdn_uderef_state());
#ifdef CONFIG_SECURITY_HARDENING_UDEREF
	seq_printf(m, "uderef_build_id: %20phN\n", vmlinux_build_id);
	seq_puts(m, "uderef_site_scheme: buildid-fnv1a64-v1\n");
#endif
	seq_printf(m, "sysfs_visibility_version: %u\n",
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_SYSFS_VIEW) ?
		   HDN_SYSFS_VISIBILITY_VERSION : 0);
	seq_printf(m, "sysfs_discovery_view: %s\n",
		   !IS_ENABLED(CONFIG_SECURITY_HARDENING_SYSFS_VIEW) ? "disabled" :
		   hdn_sysfs_hidden_classes() ? "restricted" : "base");
	seq_printf(m, "uderef_smap_repairs: %llu\n", hdn_uderef_repairs());
	seq_puts(m, "latent_entropy_credited_bits: 0\n");
	seq_printf(m, "latent_entropy_test_interface: %u\n",
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_LATENT_ENTROPY_TEST));
#ifdef CONFIG_X86_64
	seq_printf(m, "constify_state: %s\n",
		   !IS_ENABLED(CONFIG_SECURITY_HARDENING_KERNEL_WX) ? "upstream-rodata" :
		   READ_ONCE(kernel_set_to_readonly) ? "active" : "initializing");
	seq_printf(m, "kernexec_cpa_wx: %u\n", kernel_wx_enforced());
	seq_printf(m, "kernexec_cpa_state: %s\n",
		   !IS_ENABLED(CONFIG_SECURITY_HARDENING_KERNEL_WX) ? "disabled" :
		   kernel_wx_enforced() ? "active" : "unsupported");
	seq_printf(m, "kernexec_static_alias_guard: %s\n",
		   !IS_ENABLED(CONFIG_SECURITY_HARDENING_KERNEL_WX) ? "disabled" :
		   READ_ONCE(kernel_set_to_readonly) ? "active" : "unsealed");
#else
	seq_puts(m, "constify_state: upstream-rodata\n");
	seq_puts(m, "kernexec_cpa_wx: 0\nkernexec_cpa_state: unsupported\n");
	seq_puts(m, "kernexec_static_alias_guard: unsupported\n");
#endif
	seq_printf(m, "phase: %s\n", hdn_phase_name(phase));
	seq_printf(m, "phase_id: %u\n", phase);
	seq_printf(m, "policy_loaded: %u\n", policy ? 1 : 0);
	seq_printf(m, "policy_staged: %u\n", staged ? 1 : 0);
	seq_printf(m, "policy_sealed: %u\n",
		   policy && policy->sealed ? 1 : 0);
	seq_printf(m, "staged_policy_sealed: %u\n",
		   staged && staged->sealed ? 1 : 0);
	seq_printf(m, "rollback_available: %u\n",
		   (policy || previous) ? 1 : 0);
	seq_printf(m, "generation: %llu\n",
		   policy ? (unsigned long long)policy->generation : 0);
	seq_printf(m, "expected_generation: %llu\n",
		   policy ? (unsigned long long)policy->expected_generation :
			    (unsigned long long)HDN_POLICY_EXPECT_ANY);
	seq_printf(m, "staged_generation: %llu\n",
		   staged ? (unsigned long long)staged->generation : 0);
	seq_printf(m, "staged_expected_generation: %llu\n",
		   staged ? (unsigned long long)staged->expected_generation :
			    (unsigned long long)HDN_POLICY_EXPECT_ANY);
		seq_printf(m, "profile_count: %u\n",
		   policy ? policy->profile_count :
			    (unsigned int)ARRAY_SIZE(hdn_builtin_profiles));
			seq_printf(m, "subject_rule_count: %u\n",
			   policy ? policy->subject_rule_count : 0);
		seq_printf(m, "object_rule_count: %u\n",
			   policy ? policy->object_rule_count : 0);
			seq_printf(m, "exec_rule_count: %u\n",
			   policy ? policy->exec_rule_count : 0);
	seq_printf(m, "module_rule_count: %u\n",
		   policy ? policy->module_rule_count : 0);
	seq_printf(m, "firmware_rule_count: %u\n",
		   policy ? policy->firmware_rule_count : 0);
	seq_printf(m, "resource_rule_count: %u\n",
		   policy ? policy->resource_rule_count : 0);
	seq_printf(m, "default_profile: %llu\n",
		   policy ? (unsigned long long)policy->default_profile_id :
			    (unsigned long long)HDN_PROFILE_DEFAULT);
	seq_printf(m, "privileged_profile: %llu\n",
		   policy ? (unsigned long long)policy->privileged_profile_id :
			    (unsigned long long)HDN_PROFILE_PRIVILEGED);
	seq_printf(m, "current_profile: %llu\n",
		   (unsigned long long)hdn_current_profile_id());
	seq_printf(m, "current_exec_memory_flags: 0x%llx\n",
		   (unsigned long long)hdn_current_exec_memory_flags());
	seq_printf(m, "current_mntns_profile: %llu\n",
		   (unsigned long long)hdn_current_mntns_profile_id());
	seq_printf(m, "mitigations_sealed: %u\n",
		   hdn_mitigations && hdn_mitigations->sealed ? 1 : 0);
	seq_printf(m, "mitigation_pages: %u\n",
		   hdn_mitigations ? hdn_mitigations->sealed_pages : 0);
	seq_printf(m, "mitigation_flags: 0x%llx\n",
		   hdn_mitigations ?
		   (unsigned long long)hdn_mitigations->flags : 0);
	seq_printf(m, "mitigation_flags2: 0x%llx\n",
		   hdn_mitigations ?
		   (unsigned long long)hdn_mitigations->flags2 : 0);
	seq_printf(m, "mitigation_hardened_usercopy: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_HARDENED_USERCOPY));
	seq_printf(m, "mitigation_init_on_alloc: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_INIT_ON_ALLOC));
	seq_printf(m, "mitigation_init_on_free: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_INIT_ON_FREE));
	seq_printf(m, "mitigation_init_stack_zero: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_INIT_STACK_ZERO));
	seq_printf(m, "mitigation_kstack_erase: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_KSTACK_ERASE));
	seq_printf(m, "mitigation_zero_call_used_regs: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_ZERO_CALL_USED_REGS));
	seq_printf(m, "mitigation_fortify_source: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_FORTIFY_SOURCE));
	seq_printf(m, "mitigation_randstruct: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_RANDSTRUCT));
	seq_printf(m, "mitigation_slab_freelist_random: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_SLAB_FREELIST_RANDOM));
	seq_printf(m, "mitigation_slab_freelist_hardened: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_SLAB_FREELIST_HARDENED));
	seq_printf(m, "mitigation_random_kmalloc_caches: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_RANDOM_KMALLOC_CACHES));
	seq_printf(m, "mitigation_slab_buckets: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_SLAB_BUCKETS));
	seq_printf(m, "mitigation_slab_merge_disabled: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_SLAB_MERGE_DISABLED));
	seq_printf(m, "mitigation_randomize_kstack: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_RANDOMIZE_KSTACK));
	seq_printf(m, "mitigation_rand_threadstack: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_RAND_THREADSTACK));
	seq_printf(m, "mitigation_vmap_stack: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_VMAP_STACK));
	seq_printf(m, "mitigation_thread_info_in_task: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_THREAD_INFO_IN_TASK));
	seq_printf(m, "mitigation_stackprotector_strong: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_STACKPROTECTOR_STRONG));
	seq_printf(m, "mitigation_cfi: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_CFI));
	seq_printf(m, "mitigation_fineibt: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_FINEIBT));
	seq_printf(m, "mitigation_list_hardened: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_LIST_HARDENED));
	seq_printf(m, "mitigation_strict_kernel_rwx: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_STRICT_KERNEL_RWX));
	seq_printf(m, "mitigation_strict_module_rwx: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_STRICT_MODULE_RWX));
	seq_printf(m, "mitigation_dmesg_restrict: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_DMESG_RESTRICT));
	seq_printf(m, "mitigation_proc_mem_restrict: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_PROC_MEM_RESTRICT));
	seq_printf(m, "mitigation_kptr_restrict: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_KPTR_RESTRICT));
	seq_printf(m, "mitigation_brute_throttle: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_BRUTE_THROTTLE));
	seq_printf(m, "mitigation_kernel_lockout: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_KERNEL_LOCKOUT));
	seq_printf(m, "mitigation_proc_memmap_redact: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_PROC_MEMMAP_REDACT));
	seq_printf(m, "mitigation_userfaultfd_restrict: %u\n",
		   hdn_mitigation2_enabled(HDN_MITIGATION2_USERFAULTFD_RESTRICT));
	seq_printf(m, "mitigation_page_table_check: %u\n",
		   hdn_mitigation2_enabled(HDN_MITIGATION2_PAGE_TABLE_CHECK));
	seq_printf(m, "mitigation_mmap_min_addr: %u\n",
		   hdn_mitigation2_enabled(HDN_MITIGATION2_MMAP_MIN_ADDR));
	seq_printf(m, "mitigation_io_uring_sysctl_lock: %u\n",
		   hdn_mitigation2_enabled(
			   HDN_MITIGATION2_IO_URING_SYSCTL_LOCK));
	seq_printf(m, "mitigation_module_autoload_path: %u\n",
		   hdn_mitigation2_enabled(
			   HDN_MITIGATION2_MODULE_AUTOLOAD_PATH));
	seq_printf(m, "mitigation_kexec_load_disable: %u\n",
		   hdn_mitigation2_enabled(
			   HDN_MITIGATION2_KEXEC_LOAD_DISABLE));
	seq_printf(m, "mitigation_module_load_disable: %u\n",
		   hdn_mitigation2_enabled(
			   HDN_MITIGATION2_MODULE_LOAD_DISABLE));
	seq_printf(m, "mitigation_module_request_name: %u\n",
		   hdn_mitigation2_enabled(
			   HDN_MITIGATION2_MODULE_REQUEST_NAME));
	seq_printf(m, "mitigation_module_autoload_context: %u\n",
		   hdn_mitigation2_enabled(
			   HDN_MITIGATION2_MODULE_AUTOLOAD_CONTEXT));
	seq_printf(m, "mitigation_privexec_arg_stack_limits: %u\n",
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_PROC_MEMMAP));
	seq_printf(m, "mitigation_memfd_noexec: %u\n",
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_MEMFD_NOEXEC));
	seq_printf(m, "mitigation_kernel_symbol_lookup_gate: %u\n",
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_SYMBOL_LOOKUP));
	seq_printf(m, "kernel_lockout_banned_uids: %u\n",
		   hdn_kernel_lockout_count());
	seq_printf(m, "mitigation_sysvipc_harden: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_SYSVIPC_HARDEN));
	seq_printf(m, "mitigation_posix_mqueue_harden: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_POSIX_MQUEUE_HARDEN));
	seq_printf(m, "mitigation_tty_injection_harden: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_TTY_INJECTION_HARDEN));
	seq_printf(m, "mitigation_tty_access_harden: %u\n",
		   hdn_mitigation2_enabled(HDN_MITIGATION2_TTY_ACCESS_HARDEN));
	seq_printf(m, "mitigation_fuse_restrict: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_FUSE_RESTRICT));
	seq_printf(m, "mitigation_rofs_harden: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_ROFS_HARDEN));
	seq_printf(m, "mitigation_sysfs_restrict: %u\n",
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_SYSFS_VIEW));
	seq_printf(m, "mitigation_proc_hide: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_PROC_HIDE));
	seq_printf(m, "proc_task_gid: %d\n", READ_ONCE(hdn_proc_task_gid));
	seq_printf(m, "proc_task_modes: %u\n",
		   IS_ENABLED(CONFIG_SECURITY_HARDENING_PROC_TASK_MODES));
	seq_printf(m, "mitigation_usb_restrict: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_USB_RESTRICT));
	seq_printf(m, "mitigation_usb_monitor_restrict: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_USB_RESTRICT));
	seq_printf(m, "mitigation_socket_restrict: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_SOCKET_RESTRICT));
	seq_printf(m, "mitigation_net_blackhole: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_NET_BLACKHOLE));
	seq_printf(m, "mitigation_tcp_no_simult_connect: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_TCP_NO_SIMULT_CONNECT));
	seq_printf(m, "mitigation_sealed_data_report: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_SEALED_DATA_REPORT));
	seq_printf(m, "mitigation_audit_flood_control: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_AUDIT_FLOOD));
	seq_printf(m, "mitigation_exec_audit: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_EXEC_AUDIT));
	seq_printf(m, "mitigation_chdir_audit: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_CHDIR_AUDIT));
	seq_printf(m, "mitigation_mount_audit: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_MOUNT_AUDIT));
	seq_printf(m, "mitigation_time_admin: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_TIME_ADMIN));
	seq_printf(m, "mitigation_time_audit: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_TIME_AUDIT));
	seq_printf(m, "mitigation_resource_admin: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_RESOURCE_ADMIN));
	seq_printf(m, "mitigation_resource_audit: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_RESOURCE_AUDIT));
	seq_printf(m, "mitigation_block_device_restrict: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_BLOCK_DEVICE_RESTRICT));
	seq_printf(m, "mitigation_fork_audit: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_FORK_AUDIT));
	seq_printf(m, "mitigation_forkfail_audit: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_FORKFAIL_AUDIT));
	seq_printf(m, "mitigation_fs_protection_audit: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_FS_PROTECTION_AUDIT));
	seq_printf(m, "mitigation_ptrace_audit: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_PTRACE_AUDIT));
	seq_printf(m, "mitigation_ptrace_readexec: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_PTRACE_READEXEC));
	seq_printf(m, "mitigation_consistent_setxid: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_CONSISTENT_SETXID));
	seq_printf(m, "mitigation_module_autoload: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_MODULE_AUTOLOAD));
	seq_printf(m, "mitigation_proc_ipaddr: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_PROC_IPADDR));
	seq_printf(m, "mitigation_signal_audit: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_SIGNAL_AUDIT));
	seq_printf(m, "mitigation_symlink_owner: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_SYMLINK_OWNER));
	seq_printf(m, "mitigation_rwxmap_audit: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_RWXMAP_AUDIT));
	seq_printf(m, "mitigation_suid_spectre: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_SUID_SPECTRE));
	seq_printf(m, "mitigation_unpriv_bpf_lockdown: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_UNPRIV_BPF_LOCKDOWN));
	seq_printf(m, "mitigation_unpriv_perf_lockdown: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_UNPRIV_PERF_LOCKDOWN));
	seq_printf(m, "mitigation_bpf_jit_harden: %u\n",
		   hdn_mitigation_enabled(HDN_MITIGATION_BPF_JIT_HARDEN));
	spin_lock_irqsave(&hdn_event_lock, event_flags);
	audit_flood_window_ns = hdn_audit_flood_window_ns;
	audit_flood_burst = hdn_audit_flood_burst;
	audit_flood_suppressed_total = hdn_audit_flood_suppressed_total;
	audit_flood_last_action = hdn_audit_flood_last_action;
	audit_flood_last_authority = hdn_audit_flood_last_authority;
	audit_flood_last_transition = hdn_audit_flood_last_transition;
	audit_flood_last_reason = hdn_audit_flood_last_reason;
	spin_unlock_irqrestore(&hdn_event_lock, event_flags);
	seq_printf(m, "audit_flood_window_ns: %llu\n",
		   (unsigned long long)audit_flood_window_ns);
	seq_printf(m, "audit_flood_window_ms: %llu\n",
		   (unsigned long long)(audit_flood_window_ns / NSEC_PER_MSEC));
	seq_printf(m, "audit_flood_burst: %u\n", audit_flood_burst);
	seq_printf(m, "audit_flood_suppressed_total: %llu\n",
		   (unsigned long long)audit_flood_suppressed_total);
	seq_printf(m, "audit_flood_last_action: %u\n",
		   audit_flood_last_action);
	seq_printf(m, "audit_flood_last_authority: %u\n",
		   audit_flood_last_authority);
	seq_printf(m, "audit_flood_last_transition: %u\n",
		   audit_flood_last_transition);
	seq_printf(m, "audit_flood_last_reason: %u\n",
		   audit_flood_last_reason);
	mutex_unlock(&hdn_policy_mutex);

	return 0;
}

static int hdn_status_open(struct inode *inode, struct file *file)
{
	return single_open(file, hdn_status_show, NULL);
}

static const struct file_operations hdn_status_fops = {
	.open = hdn_status_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static void hdn_show_profile(struct seq_file *m,
			     const struct hdn_profile_record *profile)
{
	seq_printf(m, "id=%llu name=%s authority_allow=0x%llx authority_allow_hi=0x%llx authority_audit=0x%llx authority_audit_hi=0x%llx memory_flags=0x%llx flags=0x%llx capability_deny=0x%llx capability_audit=0x%llx\n",
		   (unsigned long long)profile->profile_id,
		   profile->name,
		   (unsigned long long)profile->authority_allow,
		   (unsigned long long)profile->authority_allow_hi,
		   (unsigned long long)profile->authority_audit,
		   (unsigned long long)profile->authority_audit_hi,
		   (unsigned long long)profile->memory_flags,
		   (unsigned long long)profile->flags,
		   (unsigned long long)profile->capability_deny,
		   (unsigned long long)profile->capability_audit);
}

static int hdn_profiles_show(struct seq_file *m, void *v)
{
	struct hdn_policy *policy;
	u32 i;

	rcu_read_lock();
	policy = rcu_dereference(hdn_active_policy);
	if (policy) {
		for (i = 0; i < policy->profile_count; i++)
			hdn_show_profile(m, &policy->profiles[i]);
	} else {
		for (i = 0; i < ARRAY_SIZE(hdn_builtin_profiles); i++)
			hdn_show_profile(m, &hdn_builtin_profiles[i]);
	}
	rcu_read_unlock();

	return 0;
}

static int hdn_profiles_open(struct inode *inode, struct file *file)
{
	return single_open(file, hdn_profiles_show, NULL);
}

static const struct file_operations hdn_profiles_fops = {
	.open = hdn_profiles_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int hdn_events_show(struct seq_file *m, void *v)
{
	struct hdn_event *events;
	unsigned long flags;
	u64 start;
	u64 end;
	u32 count = 0;
	u32 i;

	events = kcalloc(HDN_EVENT_RING_SIZE, sizeof(*events), GFP_KERNEL);
	if (!events)
		return -ENOMEM;

	spin_lock_irqsave(&hdn_event_lock, flags);
	end = hdn_event_sequence;
	start = end > HDN_EVENT_RING_SIZE ? end - HDN_EVENT_RING_SIZE : 0;
	for (i = 0; start + i < end; i++) {
		struct hdn_event event = hdn_events[(start + i) %
						    HDN_EVENT_RING_SIZE];

		if (event.sequence == start + i)
			events[count++] = event;
	}
	spin_unlock_irqrestore(&hdn_event_lock, flags);

	for (i = 0; i < count; i++) {
		seq_printf(m, "sequence=%llu timestamp_ns=%llu event_id=%u pid=%u uid=%u profile=%llu authority=%u transition=%u action=%u reason=%u error=%d subject=%llu object=%llu flags=0x%llx\n",
			   (unsigned long long)events[i].sequence,
			   (unsigned long long)events[i].timestamp_ns,
			   events[i].event_id, events[i].pid, events[i].uid,
			   (unsigned long long)events[i].profile_id,
			   events[i].authority, events[i].transition,
			   events[i].action, events[i].reason, events[i].error,
			   (unsigned long long)events[i].subject_id,
			   (unsigned long long)events[i].object_id,
			   (unsigned long long)events[i].flags);
	}

	kfree(events);
	return 0;
}

static int hdn_events_open(struct inode *inode, struct file *file)
{
	return single_open(file, hdn_events_show, NULL);
}

static __poll_t hdn_events_poll(struct file *file, poll_table *wait)
{
	poll_wait(file, &hdn_event_wait, wait);

	return EPOLLIN | EPOLLRDNORM;
}

static const struct file_operations hdn_events_fops = {
	.open = hdn_events_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.poll = hdn_events_poll,
	.release = single_release,
};

static int hdn_probe_sealed_write_fault(void)
{
	const struct hdn_mitigation_state *mitigations;
	u32 value = HDN_POLICY_ABI_VERSION;
	long ret;

	mitigations = READ_ONCE(hdn_mitigations);
	if (!mitigations || !READ_ONCE(mitigations->sealed))
		return -ENODEV;

	ret = copy_to_kernel_nofault((void *)&mitigations->abi_version,
				     &value, sizeof(value));
	if (ret == -EFAULT)
		return 0;
	if (ret)
		return ret;

	return -EIO;
}

static ssize_t hdn_sealed_write_probe_write(struct file *file,
					    const char __user *buf,
					    size_t count, loff_t *ppos)
{
	int ret;

	if (*ppos != 0)
		return -ESPIPE;
	if (!count)
		return 0;

	ret = hdn_require_policy_admin(HDN_TRANS_SEALED_DATA);
	if (ret)
		return ret;

	ret = hdn_probe_sealed_write_fault();
	if (ret)
		return ret;

	*ppos += count;
	return count;
}

static const struct file_operations hdn_sealed_write_probe_fops = {
	.write = hdn_sealed_write_probe_write,
	.llseek = noop_llseek,
};

static ssize_t hdn_kernel_lockout_probe_write(struct file *file,
					      const char __user *buf,
					      size_t count, loff_t *ppos)
{
	unsigned int raw_uid;
	kuid_t uid;
	int ret;

	if (*ppos != 0)
		return -ESPIPE;
	if (!count)
		return 0;

	ret = hdn_require_policy_admin(HDN_TRANS_KERNEL_LOCKOUT);
	if (ret)
		return ret;

	ret = kstrtouint_from_user(buf, count, 10, &raw_uid);
	if (ret)
		return ret;

	uid = make_kuid(&init_user_ns, raw_uid);
	if (!uid_valid(uid))
		return -EINVAL;
	if (uid_eq(uid, GLOBAL_ROOT_UID))
		return -EPERM;

	ret = hdn_kernel_lockout_ban_uid(uid);
	if (ret)
		return ret;

	*ppos += count;
	return count;
}

static const struct file_operations hdn_kernel_lockout_probe_fops = {
	.write = hdn_kernel_lockout_probe_write,
	.llseek = noop_llseek,
};

static int __init hdn_securityfs_init(void)
{
	/* Only initialization and its rollback need these construction handles. */
	struct dentry *hdn_fs_dir;
	struct dentry *hdn_fs_policy = NULL, *hdn_fs_refresh = NULL;
	struct dentry *hdn_fs_commit = NULL, *hdn_fs_rollback = NULL;
	struct dentry *hdn_fs_phase = NULL, *hdn_fs_profiles = NULL;
	struct dentry *hdn_fs_status = NULL, *hdn_fs_events = NULL;
	struct dentry *hdn_fs_sealed_write_probe = NULL;
	struct dentry *hdn_fs_kernel_lockout_probe = NULL;
	struct dentry *hdn_fs_audit_flood_burst = NULL;
	struct dentry *hdn_fs_audit_flood_window_ms = NULL;
	int ret;

	ret = hdn_mitigations_init();
	if (ret) {
		if (IS_ENABLED(CONFIG_SECURITY_HARDENING_KERNSEAL))
			panic("HDN could not construct immutable mitigation state");
		return ret;
	}

	hdn_fs_dir = securityfs_create_dir("hardening", NULL);
	if (IS_ERR(hdn_fs_dir))
		return PTR_ERR(hdn_fs_dir);

	hdn_fs_status = securityfs_create_file("status", 0444, hdn_fs_dir,
					       NULL, &hdn_status_fops);
	if (IS_ERR(hdn_fs_status))
		goto fail;

	hdn_fs_profiles = securityfs_create_file("profiles", 0400, hdn_fs_dir,
						 NULL, &hdn_profiles_fops);
	if (IS_ERR(hdn_fs_profiles))
		goto fail;

	hdn_fs_events = securityfs_create_file("events", 0400, hdn_fs_dir,
					       NULL, &hdn_events_fops);
	if (IS_ERR(hdn_fs_events))
		goto fail;

	hdn_fs_policy = securityfs_create_file("policy", 0200, hdn_fs_dir,
					       NULL, &hdn_policy_fops);
	if (IS_ERR(hdn_fs_policy))
		goto fail;

	hdn_fs_refresh = securityfs_create_file("refresh", 0200, hdn_fs_dir,
						NULL, &hdn_refresh_fops);
	if (IS_ERR(hdn_fs_refresh))
		goto fail;

	hdn_fs_commit = securityfs_create_file("commit", 0200, hdn_fs_dir,
					       NULL, &hdn_commit_fops);
	if (IS_ERR(hdn_fs_commit))
		goto fail;

	hdn_fs_rollback = securityfs_create_file("rollback", 0200, hdn_fs_dir,
						 NULL, &hdn_rollback_fops);
	if (IS_ERR(hdn_fs_rollback))
		goto fail;

	hdn_fs_phase = securityfs_create_file("phase", 0600, hdn_fs_dir,
					      NULL, &hdn_phase_fops);
	if (IS_ERR(hdn_fs_phase))
		goto fail;

	hdn_fs_sealed_write_probe =
		securityfs_create_file("sealed_write_probe", 0200,
				       hdn_fs_dir, NULL,
				       &hdn_sealed_write_probe_fops);
	if (IS_ERR(hdn_fs_sealed_write_probe))
		goto fail;

	hdn_fs_kernel_lockout_probe =
		securityfs_create_file("kernel_lockout_probe", 0200,
				       hdn_fs_dir, NULL,
				       &hdn_kernel_lockout_probe_fops);
	if (IS_ERR(hdn_fs_kernel_lockout_probe))
		goto fail;

	hdn_fs_audit_flood_burst =
		securityfs_create_file("audit_flood_burst", 0600,
				       hdn_fs_dir, NULL,
				       &hdn_audit_flood_burst_fops);
	if (IS_ERR(hdn_fs_audit_flood_burst))
		goto fail;

	hdn_fs_audit_flood_window_ms =
		securityfs_create_file("audit_flood_window_ms", 0600,
				       hdn_fs_dir, NULL,
				       &hdn_audit_flood_window_ms_fops);
	if (IS_ERR(hdn_fs_audit_flood_window_ms))
		goto fail;

	return 0;

fail:
	securityfs_remove(hdn_fs_audit_flood_window_ms);
	securityfs_remove(hdn_fs_audit_flood_burst);
	securityfs_remove(hdn_fs_kernel_lockout_probe);
	securityfs_remove(hdn_fs_sealed_write_probe);
	securityfs_remove(hdn_fs_phase);
	securityfs_remove(hdn_fs_rollback);
	securityfs_remove(hdn_fs_commit);
	securityfs_remove(hdn_fs_refresh);
	securityfs_remove(hdn_fs_policy);
	securityfs_remove(hdn_fs_events);
	securityfs_remove(hdn_fs_profiles);
	securityfs_remove(hdn_fs_status);
	securityfs_remove(hdn_fs_dir);
	return -ENOMEM;
}
late_initcall(hdn_securityfs_init);
