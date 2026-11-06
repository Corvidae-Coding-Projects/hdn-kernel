// SPDX-License-Identifier: GPL-2.0-only
/* Describe the native policy ABI to the offline compiler; no authority or I/O. */
#include <stddef.h>
#include <stdio.h>
#include <linux/hardening.h>
#include <linux/fsverity.h>

#define FIELD(type, member) \
	printf("\"" #member "\":[%zu,%zu],", offsetof(struct type, member), \
	       sizeof(((struct type *)0)->member))
#define RECORD(name, type, maximum) \
	printf("\"" name "\":{\"size\":%zu,\"maximum\":%u,\"fields\":{", \
	       sizeof(struct type), maximum)
#define END_RECORD() printf("\"_end\":[0,0]}}")

int main(void)
{
	const unsigned int endian = 1;

	printf("{\"schema\":1,\"byteorder\":\"%s\",\"abi\":%u,\"magic\":%u,"
	       "\"max_policy\":%u,\"path_size\":%u,\"measure_verity\":%lu,"
	       "\"lease_flags\":%llu,\"memory_mask\":%llu,\"inherit_flag\":%llu,"
	       "\"header\":{\"size\":%zu,\"fields\":{",
	       *(const unsigned char *)&endian ? "little" : "big",
	       HDN_POLICY_ABI_VERSION, HDN_POLICY_MAGIC, HDN_MAX_POLICY_SIZE,
	       HDN_POLICY_PATH_LEN, (unsigned long)FS_IOC_MEASURE_VERITY,
	       (unsigned long long)(HDN_EXEC_RESOLVE_FILE_PATH | HDN_EXEC_MATCH_VERITY_DIGEST | HDN_EXEC_COMPAT_LEASE),
	       (unsigned long long)(HDN_MEM_ALLOW_FIXED_ANON_EXEC | HDN_MEM_ALLOW_JIT_EXEC_AFTER_WRITE),
	       (unsigned long long)HDN_PROFILE_INHERIT_UNMATCHED_EXEC,
	       sizeof(struct hdn_policy_header));
#define H(member) FIELD(hdn_policy_header, member)
	H(magic); H(abi_version); H(header_size); H(profile_size); H(profile_count);
	H(flags); H(subject_rule_size); H(subject_rule_count); H(object_rule_size);
	H(object_rule_count); H(exec_rule_size); H(exec_rule_count); H(module_rule_size);
	H(module_rule_count); H(firmware_rule_size); H(firmware_rule_count);
	H(resource_rule_size); H(resource_rule_count); H(generation);
	H(expected_generation); H(default_profile_id); H(privileged_profile_id);
	END_RECORD();
	printf(",\"records\":{");
	RECORD("profile", hdn_profile_record, HDN_MAX_PROFILES);
	FIELD(hdn_profile_record, profile_id); FIELD(hdn_profile_record, memory_flags);
	FIELD(hdn_profile_record, flags); END_RECORD(); printf(",");
	RECORD("subject_rule", hdn_subject_rule_record, HDN_MAX_SUBJECT_RULES);
	FIELD(hdn_subject_rule_record, profile_id); END_RECORD(); printf(",");
	RECORD("object_rule", hdn_object_rule_record, HDN_MAX_OBJECT_RULES);
	FIELD(hdn_object_rule_record, profile_id);
	END_RECORD(); printf(",");
	RECORD("exec_rule", hdn_exec_rule_record, HDN_MAX_EXEC_RULES);
#define E(member) FIELD(hdn_exec_rule_record, member)
	E(target_profile_id); E(parent_profile_id); E(flags); E(verity_digest_size);
	E(verity_digest_algorithm); E(verity_digest); E(file_path);
	END_RECORD(); printf(",");
	RECORD("module_rule", hdn_module_rule_record, HDN_MAX_MODULE_RULES);
	END_RECORD(); printf(",");
	RECORD("firmware_rule", hdn_firmware_rule_record, HDN_MAX_FIRMWARE_RULES);
	END_RECORD(); printf(",");
	RECORD("resource_rule", hdn_resource_rule_record, HDN_MAX_RESOURCE_RULES);
	END_RECORD(); puts("}}");
	return ferror(stdout) ? 1 : 0;
}
