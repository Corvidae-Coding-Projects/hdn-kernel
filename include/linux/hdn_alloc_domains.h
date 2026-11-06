/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_HDN_ALLOC_DOMAINS_H
#define _LINUX_HDN_ALLOC_DOMAINS_H
#define HDN_ALLOC_TIER_BASE 256
/* Shared with the build compiler; no kernel type dependencies. */
enum hdn_alloc_domain {
	HDN_ALLOC_ORDINARY,
	HDN_ALLOC_IPC_QUEUE,
	HDN_ALLOC_IPC_SEGMENT,
	HDN_ALLOC_SEM_ARRAY,
	HDN_ALLOC_SEM_UNDO,
	HDN_ALLOC_UNDO_LIST,
	HDN_ALLOC_SHM,
	HDN_ALLOC_SHM_FILE,
	HDN_ALLOC_IPC_NAMESPACE,
	HDN_ALLOC_KEY_PAYLOAD,
	HDN_ALLOC_ID_EXTENTS,
	HDN_ALLOC_TIME_NAMESPACE,
	HDN_ALLOC_MOUNT_NAMESPACE,
	HDN_ALLOC_MOUNTPOINT,
	HDN_ALLOC_KEY_TAG,
	HDN_ALLOC_KEY_USER,
	HDN_ALLOC_KEY_RESTRICTION,
	HDN_ALLOC_KEY_AUTH,
	HDN_ALLOC_KEYRING_NODE,
	HDN_ALLOC_KEYRING_SHORTCUT,
	HDN_ALLOC_SEAL_METADATA,
	HDN_ALLOC_MODULE,
	HDN_ALLOC_CRED,
	HDN_ALLOC_FILE,
	HDN_ALLOC_BACKING_FILE,
	HDN_ALLOC_KEY,
	HDN_ALLOC_NSPROXY,
	HDN_ALLOC_PID_NAMESPACE,
	HDN_ALLOC_USER_NAMESPACE,
	HDN_ALLOC_UTS_NAMESPACE,
	HDN_ALLOC_NET_NAMESPACE,
	HDN_ALLOC_MOUNT,
	HDN_ALLOC_PID,
	HDN_ALLOC_MQUEUE,
	HDN_ALLOC_MSG_HEAD,
	HDN_ALLOC_JITTER_META,
	HDN_ALLOC_JITTER_TEST,
	HDN_ALLOC_DOMAIN_MAX,
};

#define HDN_ALLOC_TYPE_DOMAINS(X) \
	X(msg_queue, IPC_QUEUE, "ipc/msg.c") \
	X(msg_msgseg, IPC_SEGMENT, "ipc/msgutil.c") \
	X(sem_array, SEM_ARRAY, "ipc/sem.c") \
	X(sem_undo, SEM_UNDO, "ipc/sem.c") \
	X(sem_undo_list, UNDO_LIST, "ipc/sem.c") \
	X(shmid_kernel, SHM, "ipc/shm.c") \
	X(shm_file_data, SHM_FILE, "ipc/shm.c") \
	X(ipc_namespace, IPC_NAMESPACE, "include/linux/ipc_namespace.h") \
	X(user_key_payload, KEY_PAYLOAD, "include/keys/user-type.h") \
	X(uid_gid_extent, ID_EXTENTS, "include/linux/user_namespace.h") \
	X(time_namespace, TIME_NAMESPACE, "include/linux/time_namespace.h") \
	X(mnt_namespace, MOUNT_NAMESPACE, "fs/mount.h") \
	X(mountpoint, MOUNTPOINT, "fs/mount.h") \
	X(key_tag, KEY_TAG, "include/linux/key.h") \
	X(key_user, KEY_USER, "security/keys/internal.h") \
	X(key_restriction, KEY_RESTRICTION, "include/linux/key.h") \
	X(request_key_auth, KEY_AUTH, "include/keys/request_key_auth-type.h") \
	X(assoc_array_node, KEYRING_NODE, "include/linux/assoc_array_priv.h") \
	X(assoc_array_shortcut, KEYRING_SHORTCUT, "include/linux/assoc_array_priv.h") \
	X(hdn_seal, SEAL_METADATA, "security/hardening/seal.c")
#endif
