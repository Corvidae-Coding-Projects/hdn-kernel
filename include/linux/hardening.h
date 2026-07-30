/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_HARDENING_H
#define _LINUX_HARDENING_H

#include <linux/mm_types.h>
#include <linux/types.h>
#include <linux/uidgid_types.h>
#include <uapi/linux/hardening.h>

struct cred;
struct dentry;
struct file;
struct file_system_type;
struct ipc_namespace;
struct inode;
struct kern_ipc_perm;
struct linux_binprm;
struct mnt_namespace;
struct path;
struct pid;
struct sockaddr;
struct signal_struct;
struct rlimit;
struct sk_buff;
struct sock;
struct sockaddr_un;
struct socket;
struct super_block;
struct task_struct;
struct tty_struct;
struct user_namespace;
struct vfsmount;
struct vm_area_struct;

struct hdn_mmap_request {
	struct file *file;
	unsigned long addr;
	unsigned long len;
	unsigned long prot;
	unsigned long flags;
	unsigned long pgoff;
	bool read_implies_exec;
};

struct hdn_mprotect_request {
	struct vm_area_struct *vma;
	unsigned long start;
	unsigned long end;
	unsigned long reqprot;
	unsigned long prot;
	vm_flags_t oldflags;
	vm_flags_t newflags;
};

enum hdn_process_memory_operation {
	HDN_PROCESS_MEMORY_READ = 1,
	HDN_PROCESS_MEMORY_WRITE = 2,
	HDN_PROCESS_MEMORY_MADVISE = 3,
	HDN_PROCESS_MEMORY_MRELEASE = 4,
};

enum hdn_memory_migrate_operation {
	HDN_MEMORY_MIGRATE_MOVE_PAGES = 1,
	HDN_MEMORY_MIGRATE_MIGRATE_PAGES = 2,
};

enum hdn_process_fd_operation {
	HDN_PROCESS_FD_GETFD = 1,
};

enum hdn_tty_access_operation {
	HDN_TTY_ACCESS_READ = 1,
	HDN_TTY_ACCESS_WRITE = 2,
	HDN_TTY_ACCESS_IOCTL = 3,
};

enum hdn_xattr_operation {
	HDN_XATTR_READ = 1,
	HDN_XATTR_LIST = 2,
	HDN_XATTR_SET = 3,
	HDN_XATTR_REMOVE = 4,
};

enum hdn_unix_abstract_operation {
	HDN_UNIX_ABSTRACT_CONNECT = 1,
	HDN_UNIX_ABSTRACT_BIND = 2,
	HDN_UNIX_ABSTRACT_LISTEN = 3,
	HDN_UNIX_ABSTRACT_ACCEPT = 4,
	HDN_UNIX_ABSTRACT_SEND = 5,
	HDN_UNIX_ABSTRACT_RECV = 6,
};

u64 hdn_mntns_profile_id(const struct mnt_namespace *ns);
u64 hdn_current_mntns_profile_id(void);

#ifdef CONFIG_SECURITY_HARDENING
int hdn_authorize(enum hdn_authority authority,
		  enum hdn_transition transition,
		  enum hdn_reason reason, int error);
int hdn_authorize_profile(enum hdn_authority authority,
			  enum hdn_transition transition,
			  enum hdn_reason reason, int error, u64 profile_id);
int hdn_mmap_rewrite(struct hdn_mmap_request *req);
void hdn_mmap_committed(const struct hdn_mmap_request *req);
int hdn_mprotect_validate(struct hdn_mprotect_request *req);
int hdn_authorize_exec(struct linux_binprm *bprm);
void hdn_exec_committed(struct linux_binprm *bprm);
void hdn_task_exit(long code);
bool hdn_block_privileged_coredump(int sig);
void hdn_brute_check_fork(void);
int hdn_kernel_lockout_check_fork(void);
void hdn_report_kernel_lockout(void);
void hdn_bprm_record_original(struct linux_binprm *bprm, struct file *file);
void hdn_bprm_note_interpreter(struct linux_binprm *bprm);
int hdn_authorize_creds(const struct cred *new, const struct cred *old);
void hdn_creds_committed(const struct cred *new, const struct cred *old);
int hdn_authorize_userns(const struct cred *new);
int hdn_authorize_bpf_prog_load(u32 prog_type, u32 prog_flags,
				bool is_kernel, bool privileged);
int hdn_authorize_bpf_command(unsigned int cmd, bool is_kernel);
int hdn_authorize_vm86(unsigned int cmd);
int hdn_authorize_perf_event_open(bool kernel_access, bool namespaces,
				  pid_t pid, int cpu, unsigned long flags);
int hdn_authorize_ptrace(struct task_struct *target, long request,
			 unsigned long addr, unsigned long data);
int hdn_authorize_ptrace_access(struct task_struct *target, unsigned int mode);
int hdn_authorize_ptrace_profile(u64 target_profile_id, pid_t target_pid);
int hdn_authorize_ptrace_exec_read(struct mm_struct *mm, unsigned long addr,
				   int len, unsigned int gup_flags);
int hdn_authorize_process_memory(struct task_struct *target,
				 struct mm_struct *mm,
				 enum hdn_process_memory_operation operation);
int hdn_authorize_memory_migrate(struct task_struct *target,
				 struct mm_struct *mm,
				 enum hdn_memory_migrate_operation operation);
int hdn_authorize_process_fd(struct task_struct *target,
			     enum hdn_process_fd_operation operation);
void hdn_record_ptrace_audit(struct task_struct *target, long request,
			     int error);
bool hdn_proc_task_visible(struct task_struct *target);
bool hdn_proc_task_group_kgid(kgid_t *kgid);
bool hdn_proc_memmap_disclose(struct task_struct *target, struct mm_struct *mm);
bool hdn_proc_resource_disclose(void);
int hdn_authorize_proc_memmap_read(struct task_struct *target,
				   struct mm_struct *mm);
int hdn_authorize_proc_sensitive_read(struct task_struct *target,
				      struct mm_struct *mm);
int hdn_authorize_proc_sensitive_write(struct task_struct *target,
				       struct mm_struct *mm);
int hdn_authorize_proc_resource_read(void);
bool hdn_kernel_symbol_disclose_allowed(void);
int hdn_authorize_kernel_symbol_lookup(void);
int hdn_authorize_kernel_symbol_lookup_transition(enum hdn_transition transition);
int hdn_authorize_pidfd_open(struct task_struct *target);
bool hdn_task_visible_from_chroot(struct task_struct *target);
int hdn_authorize_chroot_signal(struct task_struct *target, int sig);
int hdn_authorize_signal(struct task_struct *target, int sig);
int hdn_authorize_chroot_fowner(struct pid *pid, int type);
int hdn_authorize_module_from_user(unsigned long len);
int hdn_authorize_module_from_file(struct file *file, int flags);
int hdn_authorize_module_autoload(const char *name);
int hdn_authorize_module_autoload_control(void);
int hdn_authorize_firmware(const char *name);
int hdn_authorize_object_create(const struct dentry *dir);
int hdn_authorize_object_delete(const struct dentry *dentry);
int hdn_authorize_object_creat(const struct dentry *dir, umode_t mode);
int hdn_authorize_object_mkdir(const struct dentry *dir);
int hdn_authorize_object_mknod(const struct dentry *dir, umode_t mode);
int hdn_authorize_object_symlink(const struct dentry *dir);
int hdn_authorize_object_unlink(const struct dentry *dentry);
int hdn_authorize_object_rmdir(const struct dentry *dentry);
int hdn_authorize_object_rename(const struct dentry *dentry);
int hdn_authorize_object_rename_target(const struct dentry *dir);
int hdn_authorize_object_link_source(const struct dentry *dentry);
int hdn_authorize_object_link_target(const struct dentry *dir);
int hdn_authorize_object_access(const struct path *path, int mode);
int hdn_authorize_object_stat(const struct path *path);
int hdn_authorize_object_list(const struct path *path);
int hdn_authorize_object_find(const struct path *path);
bool hdn_object_readdir_entry_visible(const struct file *file,
				      const char *name, int namlen, u64 ino);
int hdn_authorize_object_read(const struct path *path);
int hdn_authorize_object_readlink(const struct path *path);
int hdn_authorize_object_attr(const struct dentry *dentry,
			      unsigned int ia_valid, umode_t mode);
int hdn_authorize_object_fileattr(const struct dentry *dentry);
int hdn_authorize_object_filegetattr(const struct dentry *dentry);
int hdn_authorize_object_xattr(const struct dentry *dentry,
			       enum hdn_xattr_operation operation);
int hdn_authorize_object_write(const struct path *path);
int hdn_authorize_object_write_open(const struct path *path,
				    bool append_write);
int hdn_authorize_object_write_file(struct file *file, bool append_write);
int hdn_authorize_object_ioctl(struct file *file, unsigned int cmd);
int hdn_authorize_object_lock(struct file *file, unsigned int cmd);
int hdn_authorize_object_watch(const struct path *path);
int hdn_authorize_object_receive(struct file *file);
int hdn_authorize_object_fcntl(struct file *file, unsigned int cmd);
int hdn_authorize_object_mount(const struct path *path);
int hdn_authorize_object_mount_source(const struct path *path);
int hdn_authorize_object_umount(const struct path *path);
int hdn_authorize_object_truncate(const struct path *path);
int hdn_authorize_object_unix_connect(const struct path *path);
int hdn_authorize_object_unix_bind(const struct dentry *dir);
int hdn_authorize_object_unix_listen(const struct path *path);
int hdn_authorize_object_unix_accept(const struct path *path);
int hdn_authorize_object_unix_send(const struct path *path);
int hdn_authorize_object_unix_recv(const struct path *path);
int hdn_authorize_object_unix_abstract(
	const struct sockaddr_un *addr, unsigned int addr_len,
	enum hdn_unix_abstract_operation operation);
int hdn_authorize_namespace_create(unsigned long flags);
int hdn_authorize_namespace_join(const struct user_namespace *owner,
				 unsigned long nstype);
int hdn_authorize_namespace_join_profile(u64 profile_id,
					 unsigned long nstype);
int hdn_authorize_chroot(const struct path *path);
void hdn_chroot_committed(const struct path *path);
int hdn_authorize_chdir(const struct path *path);
void hdn_record_chdir(const struct path *path);
int hdn_authorize_pivot_root(const struct path *new_root,
			     const struct path *put_old);
int hdn_authorize_chroot_chmod(const struct path *path, umode_t mode);
int hdn_authorize_chroot_mknod(umode_t mode, dev_t dev);
int hdn_authorize_chroot_shmat(int shmid);
int hdn_authorize_protected_shmat(u64 creator_profile_id, int shmid);
int hdn_authorize_chroot_nice(struct task_struct *target, int nice);
int hdn_authorize_chroot_rename(const struct path *old_dir,
				struct dentry *old_dentry,
				const struct path *new_dir,
				struct dentry *new_dentry,
				unsigned int flags);
int hdn_authorize_chroot_unix(const struct path *peer_root);
int hdn_authorize_capability(const struct cred *cred, int cap,
			     unsigned int opts);
int hdn_authorize_chroot_mount(const struct path *path);
int hdn_authorize_chroot_file_handle(void);
int hdn_authorize_chroot_sysctl(const char *name);
int hdn_authorize_time_change(enum hdn_time_operation operation);
void hdn_record_time_change(enum hdn_time_operation operation);
int hdn_authorize_resource_limit(unsigned int resource);
int hdn_authorize_profile_resource_limit(struct task_struct *target,
					 unsigned int resource,
					 const struct rlimit *new_rlim);
void hdn_record_resource_limit(unsigned int resource);
void hdn_record_resource_pressure(unsigned int resource, unsigned long wanted);
int hdn_authorize_block_device(dev_t dev);
int hdn_authorize_block_device_admin(dev_t dev, unsigned int command);
void hdn_record_fs_protection(unsigned int reason, int error,
			      unsigned long inode);
void hdn_record_fork(struct task_struct *child);
void hdn_record_fork_failure(int error);
void hdn_record_process_account(long code, int group_dead);
void hdn_record_signal(int sig, const void __user *addr,
		       struct task_struct *target);
int hdn_authorize_sysvipc_access(const struct ipc_namespace *ns,
				 const struct kern_ipc_perm *ipcp,
				 int requested_mode, int granted_mode);
int hdn_authorize_posix_mqueue_access(const struct ipc_namespace *ns,
				      const struct inode *inode,
				      int requested_mode);
int hdn_authorize_tty_injection(unsigned int cmd);
int hdn_authorize_tty_access(struct tty_struct *tty,
			     enum hdn_tty_access_operation operation);
void hdn_tty_record_broker(struct tty_struct *tty);
void hdn_tty_record_received_file(struct file *file);
void hdn_tty_record_session_broker(struct tty_struct *tty);
void hdn_tty_release_session_broker(struct tty_struct *tty);
int hdn_authorize_mount_type(const struct file_system_type *type);
int hdn_authorize_writable_mount(const struct file_system_type *type,
				 bool requested_readonly);
void hdn_record_mount(const struct path *path);
int hdn_authorize_rofs_relax(const struct vfsmount *mnt,
			     bool currently_readonly, bool requested_readonly);
int hdn_authorize_super_rofs_relax(const struct super_block *sb,
				   bool currently_readonly,
				   bool requested_readonly);
int hdn_authorize_usb_attach(unsigned int busnum, unsigned int portnum);
int hdn_authorize_usb_monitor(unsigned int busnum);
int hdn_authorize_socket_create(int family, int type, int protocol,
				bool kernel);
int hdn_authorize_socket_connect(const struct socket *sock,
				 const struct sockaddr *addr, int addrlen);
int hdn_authorize_socket_server(const struct socket *sock,
				const struct sockaddr *addr, int addrlen);
bool hdn_blackhole_remote_skb(const struct sk_buff *skb);
unsigned int hdn_tcp_lastack_retries(unsigned int retry_until);
void hdn_report_sealed_write_fault(unsigned long address);
void hdn_attach_proc_ip(const struct sock *sk);
void hdn_track_proc_ip_connection(const struct sock *sk);
void hdn_drop_proc_ip_connection(struct signal_struct *sig);
void hdn_track_unix_proc_ip(const struct sock *sk);
void hdn_drop_unix_proc_ip(const struct sock *sk);
void hdn_signal_fork(struct signal_struct *child);
void hdn_mm_set_profile(struct mm_struct *mm, u64 profile_id);
u64 hdn_current_profile_id(void);
u64 hdn_mm_profile_id(const struct mm_struct *mm);
void hdn_userns_init_profile(struct user_namespace *ns);
u64 hdn_userns_profile_id(const struct user_namespace *ns);
#else
static inline int hdn_authorize(enum hdn_authority authority,
				enum hdn_transition transition,
				enum hdn_reason reason, int error)
{
	return 0;
}

static inline int hdn_authorize_profile(enum hdn_authority authority,
					enum hdn_transition transition,
					enum hdn_reason reason, int error,
					u64 profile_id)
{
	return 0;
}

static inline int hdn_mmap_rewrite(struct hdn_mmap_request *req)
{
	return 0;
}

static inline void hdn_mmap_committed(const struct hdn_mmap_request *req)
{
}

static inline int hdn_mprotect_validate(struct hdn_mprotect_request *req)
{
	return 0;
}

static inline int hdn_authorize_exec(struct linux_binprm *bprm)
{
	return 0;
}

static inline void hdn_exec_committed(struct linux_binprm *bprm)
{
}

static inline void hdn_task_exit(long code)
{
}

static inline bool hdn_block_privileged_coredump(int sig)
{
	return false;
}

static inline void hdn_brute_check_fork(void)
{
}

static inline int hdn_kernel_lockout_check_fork(void)
{
	return 0;
}

static inline void hdn_report_kernel_lockout(void)
{
}

static inline void hdn_bprm_record_original(struct linux_binprm *bprm,
					    struct file *file)
{
}

static inline void hdn_bprm_note_interpreter(struct linux_binprm *bprm)
{
}

static inline int hdn_authorize_creds(const struct cred *new,
				      const struct cred *old)
{
	return 0;
}

static inline void hdn_creds_committed(const struct cred *new,
				       const struct cred *old)
{
}

static inline int hdn_authorize_userns(const struct cred *new)
{
	return 0;
}

static inline int hdn_authorize_bpf_prog_load(u32 prog_type, u32 prog_flags,
					      bool is_kernel, bool privileged)
{
	return 0;
}

static inline int hdn_authorize_bpf_command(unsigned int cmd, bool is_kernel)
{
	return 0;
}

static inline int hdn_authorize_vm86(unsigned int cmd)
{
	return 0;
}

static inline int hdn_authorize_perf_event_open(bool kernel_access,
						bool namespaces, pid_t pid,
						int cpu, unsigned long flags)
{
	return 0;
}

static inline int hdn_authorize_ptrace(struct task_struct *target,
				       long request, unsigned long addr,
				       unsigned long data)
{
	return 0;
}

static inline int hdn_authorize_ptrace_access(struct task_struct *target,
					      unsigned int mode)
{
	return 0;
}

static inline int hdn_authorize_ptrace_profile(u64 target_profile_id,
					       pid_t target_pid)
{
	return 0;
}

static inline int hdn_authorize_ptrace_exec_read(struct mm_struct *mm,
						 unsigned long addr, int len,
						 unsigned int gup_flags)
{
	return 0;
}

static inline int hdn_authorize_process_memory(
	struct task_struct *target, struct mm_struct *mm,
	enum hdn_process_memory_operation operation)
{
	return 0;
}

static inline int hdn_authorize_memory_migrate(
	struct task_struct *target, struct mm_struct *mm,
	enum hdn_memory_migrate_operation operation)
{
	return 0;
}

static inline int hdn_authorize_process_fd(
	struct task_struct *target, enum hdn_process_fd_operation operation)
{
	return 0;
}

static inline void hdn_record_ptrace_audit(struct task_struct *target,
					   long request, int error)
{
}

static inline bool hdn_proc_task_visible(struct task_struct *target)
{
	return true;
}

static inline bool hdn_proc_task_group_kgid(kgid_t *kgid)
{
	return false;
}

static inline bool hdn_proc_memmap_disclose(struct task_struct *target,
					    struct mm_struct *mm)
{
	return true;
}

static inline bool hdn_proc_resource_disclose(void)
{
	return true;
}

static inline int hdn_authorize_proc_memmap_read(struct task_struct *target,
						 struct mm_struct *mm)
{
	return 0;
}

static inline int hdn_authorize_proc_sensitive_read(struct task_struct *target,
						    struct mm_struct *mm)
{
	return 0;
}

static inline int hdn_authorize_proc_sensitive_write(struct task_struct *target,
						     struct mm_struct *mm)
{
	return 0;
}

static inline int hdn_authorize_proc_resource_read(void)
{
	return 0;
}

static inline bool hdn_kernel_symbol_disclose_allowed(void)
{
	return true;
}

static inline int hdn_authorize_kernel_symbol_lookup(void)
{
	return 0;
}

static inline int
hdn_authorize_kernel_symbol_lookup_transition(enum hdn_transition transition)
{
	return 0;
}

static inline int hdn_authorize_pidfd_open(struct task_struct *target)
{
	return 0;
}

static inline bool hdn_task_visible_from_chroot(struct task_struct *target)
{
	return true;
}

static inline int hdn_authorize_chroot_signal(struct task_struct *target,
					      int sig)
{
	return 0;
}

static inline int hdn_authorize_signal(struct task_struct *target, int sig)
{
	return 0;
}

static inline int hdn_authorize_chroot_fowner(struct pid *pid, int type)
{
	return 0;
}

static inline int hdn_authorize_module_from_user(unsigned long len)
{
	return 0;
}

static inline int hdn_authorize_module_from_file(struct file *file, int flags)
{
	return 0;
}

static inline int hdn_authorize_module_autoload(const char *name)
{
	return 0;
}

static inline int hdn_authorize_module_autoload_control(void)
{
	return 0;
}

static inline int hdn_authorize_firmware(const char *name)
{
	return 0;
}

static inline int hdn_authorize_object_create(const struct dentry *dir)
{
	return 0;
}

static inline int hdn_authorize_object_delete(const struct dentry *dentry)
{
	return 0;
}

static inline int hdn_authorize_object_creat(const struct dentry *dir,
					     umode_t mode)
{
	return 0;
}

static inline int hdn_authorize_object_mkdir(const struct dentry *dir)
{
	return 0;
}

static inline int hdn_authorize_object_mknod(const struct dentry *dir,
					     umode_t mode)
{
	return 0;
}

static inline int hdn_authorize_object_symlink(const struct dentry *dir)
{
	return 0;
}

static inline int hdn_authorize_object_unlink(const struct dentry *dentry)
{
	return 0;
}

static inline int hdn_authorize_object_rmdir(const struct dentry *dentry)
{
	return 0;
}

static inline int hdn_authorize_object_rename(const struct dentry *dentry)
{
	return 0;
}

static inline int hdn_authorize_object_rename_target(const struct dentry *dir)
{
	return 0;
}

static inline int hdn_authorize_object_link_source(const struct dentry *dentry)
{
	return 0;
}

static inline int hdn_authorize_object_link_target(const struct dentry *dir)
{
	return 0;
}

static inline int hdn_authorize_object_access(const struct path *path, int mode)
{
	return 0;
}

static inline int hdn_authorize_object_stat(const struct path *path)
{
	return 0;
}

static inline int hdn_authorize_object_list(const struct path *path)
{
	return 0;
}

static inline int hdn_authorize_object_find(const struct path *path)
{
	return 0;
}

static inline bool hdn_object_readdir_entry_visible(const struct file *file,
						    const char *name,
						    int namlen, u64 ino)
{
	return true;
}

static inline int hdn_authorize_object_read(const struct path *path)
{
	return 0;
}

static inline int hdn_authorize_object_readlink(const struct path *path)
{
	return 0;
}

static inline int hdn_authorize_object_attr(const struct dentry *dentry,
					    unsigned int ia_valid,
					    umode_t mode)
{
	return 0;
}

static inline int hdn_authorize_object_fileattr(const struct dentry *dentry)
{
	return 0;
}

static inline int hdn_authorize_object_filegetattr(const struct dentry *dentry)
{
	return 0;
}

static inline int hdn_authorize_object_xattr(const struct dentry *dentry,
					     enum hdn_xattr_operation operation)
{
	return 0;
}

static inline int hdn_authorize_object_write(const struct path *path)
{
	return 0;
}

static inline int hdn_authorize_object_write_open(const struct path *path,
						  bool append_write)
{
	return 0;
}

static inline int hdn_authorize_object_write_file(struct file *file,
						  bool append_write)
{
	return 0;
}

static inline int hdn_authorize_object_ioctl(struct file *file,
					     unsigned int cmd)
{
	return 0;
}

static inline int hdn_authorize_object_lock(struct file *file, unsigned int cmd)
{
	return 0;
}

static inline int hdn_authorize_object_watch(const struct path *path)
{
	return 0;
}

static inline int hdn_authorize_object_receive(struct file *file)
{
	return 0;
}

static inline int hdn_authorize_object_fcntl(struct file *file,
					     unsigned int cmd)
{
	return 0;
}

static inline int hdn_authorize_namespace_create(unsigned long flags)
{
	return 0;
}

static inline int hdn_authorize_namespace_join(const struct user_namespace *owner,
					       unsigned long nstype)
{
	return 0;
}

static inline int hdn_authorize_namespace_join_profile(u64 profile_id,
						       unsigned long nstype)
{
	return 0;
}

static inline int hdn_authorize_chroot(const struct path *path)
{
	return 0;
}

static inline void hdn_chroot_committed(const struct path *path)
{
}

static inline int hdn_authorize_chdir(const struct path *path)
{
	return 0;
}

static inline void hdn_record_chdir(const struct path *path)
{
}

static inline int hdn_authorize_pivot_root(const struct path *new_root,
					   const struct path *put_old)
{
	return 0;
}

static inline int hdn_authorize_chroot_chmod(const struct path *path,
					     umode_t mode)
{
	return 0;
}

static inline int hdn_authorize_chroot_mknod(umode_t mode, dev_t dev)
{
	return 0;
}

static inline int hdn_authorize_chroot_shmat(int shmid)
{
	return 0;
}

static inline int hdn_authorize_protected_shmat(u64 creator_profile_id,
						int shmid)
{
	return 0;
}

static inline int hdn_authorize_chroot_nice(struct task_struct *target,
					    int nice)
{
	return 0;
}

static inline int hdn_authorize_chroot_rename(const struct path *old_dir,
					      struct dentry *old_dentry,
					      const struct path *new_dir,
					      struct dentry *new_dentry,
					      unsigned int flags)
{
	return 0;
}

static inline int hdn_authorize_chroot_unix(const struct path *peer_root)
{
	return 0;
}

static inline int hdn_authorize_capability(const struct cred *cred, int cap,
					    unsigned int opts)
{
	return 0;
}

static inline int hdn_authorize_time_change(enum hdn_time_operation operation)
{
	return 0;
}

static inline void hdn_record_time_change(enum hdn_time_operation operation)
{
}

static inline int hdn_authorize_resource_limit(unsigned int resource)
{
	return 0;
}

static inline int hdn_authorize_profile_resource_limit(struct task_struct *target,
						      unsigned int resource,
						      const struct rlimit *new_rlim)
{
	return 0;
}

static inline void hdn_record_resource_limit(unsigned int resource)
{
}

static inline void hdn_record_resource_pressure(unsigned int resource,
						unsigned long wanted)
{
}

static inline int hdn_authorize_block_device(dev_t dev)
{
	return 0;
}

static inline int hdn_authorize_block_device_admin(dev_t dev,
						   unsigned int command)
{
	return 0;
}

static inline void hdn_record_fs_protection(unsigned int reason, int error,
					    unsigned long inode)
{
}

static inline void hdn_record_fork(struct task_struct *child)
{
}

static inline void hdn_record_fork_failure(int error)
{
}

static inline void hdn_record_process_account(long code, int group_dead)
{
}

static inline void hdn_record_signal(int sig, const void __user *addr,
				     struct task_struct *target)
{
}

static inline int hdn_authorize_sysvipc_access(const struct ipc_namespace *ns,
					       const struct kern_ipc_perm *ipcp,
					       int requested_mode,
					       int granted_mode)
{
	return 0;
}

static inline int hdn_authorize_posix_mqueue_access(const struct ipc_namespace *ns,
						    const struct inode *inode,
						    int requested_mode)
{
	return 0;
}

static inline int hdn_authorize_tty_injection(unsigned int cmd)
{
	return 0;
}

static inline int hdn_authorize_tty_access(
	struct tty_struct *tty, enum hdn_tty_access_operation operation)
{
	return 0;
}

static inline void hdn_tty_record_broker(struct tty_struct *tty)
{
}

static inline void hdn_tty_record_received_file(struct file *file)
{
}

static inline void hdn_tty_record_session_broker(struct tty_struct *tty)
{
}

static inline void hdn_tty_release_session_broker(struct tty_struct *tty)
{
}

static inline int hdn_authorize_chroot_mount(const struct path *path)
{
	return 0;
}

static inline int hdn_authorize_chroot_file_handle(void)
{
	return 0;
}

static inline int hdn_authorize_chroot_sysctl(const char *name)
{
	return 0;
}

static inline int hdn_authorize_mount_type(const struct file_system_type *type)
{
	return 0;
}

static inline int hdn_authorize_writable_mount(const struct file_system_type *type,
					       bool requested_readonly)
{
	return 0;
}

static inline int hdn_authorize_object_mount(const struct path *path)
{
	return 0;
}

static inline int hdn_authorize_object_mount_source(const struct path *path)
{
	return 0;
}

static inline int hdn_authorize_object_umount(const struct path *path)
{
	return 0;
}

static inline int hdn_authorize_object_truncate(const struct path *path)
{
	return 0;
}

static inline int hdn_authorize_object_unix_connect(const struct path *path)
{
	return 0;
}

static inline int hdn_authorize_object_unix_bind(const struct dentry *dir)
{
	return 0;
}

static inline int hdn_authorize_object_unix_listen(const struct path *path)
{
	return 0;
}

static inline int hdn_authorize_object_unix_accept(const struct path *path)
{
	return 0;
}

static inline int hdn_authorize_object_unix_send(const struct path *path)
{
	return 0;
}

static inline int hdn_authorize_object_unix_recv(const struct path *path)
{
	return 0;
}

static inline int hdn_authorize_object_unix_abstract(
	const struct sockaddr_un *addr, unsigned int addr_len,
	enum hdn_unix_abstract_operation operation)
{
	return 0;
}

static inline void hdn_record_mount(const struct path *path)
{
}

static inline int hdn_authorize_rofs_relax(const struct vfsmount *mnt,
					   bool currently_readonly,
					   bool requested_readonly)
{
	return 0;
}

static inline int hdn_authorize_super_rofs_relax(const struct super_block *sb,
						 bool currently_readonly,
						 bool requested_readonly)
{
	return 0;
}

static inline int hdn_authorize_usb_attach(unsigned int busnum,
					   unsigned int portnum)
{
	return 0;
}

static inline int hdn_authorize_usb_monitor(unsigned int busnum)
{
	return 0;
}

static inline int hdn_authorize_socket_create(int family, int type,
					      int protocol, bool kernel)
{
	return 0;
}

static inline int hdn_authorize_socket_connect(const struct socket *sock,
					       const struct sockaddr *addr,
					       int addrlen)
{
	return 0;
}

static inline int hdn_authorize_socket_server(const struct socket *sock,
					      const struct sockaddr *addr,
					      int addrlen)
{
	return 0;
}

static inline bool hdn_blackhole_remote_skb(const struct sk_buff *skb)
{
	return false;
}

static inline unsigned int hdn_tcp_lastack_retries(unsigned int retry_until)
{
	return retry_until;
}

static inline void hdn_report_sealed_write_fault(unsigned long address)
{
}

static inline void hdn_attach_proc_ip(const struct sock *sk)
{
}

static inline void hdn_track_proc_ip_connection(const struct sock *sk)
{
}

static inline void hdn_drop_proc_ip_connection(struct signal_struct *sig)
{
}

static inline void hdn_track_unix_proc_ip(const struct sock *sk)
{
}

static inline void hdn_drop_unix_proc_ip(const struct sock *sk)
{
}

static inline void hdn_signal_fork(struct signal_struct *child)
{
}

static inline void hdn_mm_set_profile(struct mm_struct *mm, u64 profile_id)
{
}

static inline u64 hdn_current_profile_id(void)
{
	return HDN_PROFILE_DEFAULT;
}

static inline u64 hdn_mm_profile_id(const struct mm_struct *mm)
{
	return HDN_PROFILE_DEFAULT;
}

static inline void hdn_userns_init_profile(struct user_namespace *ns)
{
}

static inline u64 hdn_userns_profile_id(const struct user_namespace *ns)
{
	return HDN_PROFILE_DEFAULT;
}
#endif

#endif /* _LINUX_HARDENING_H */
