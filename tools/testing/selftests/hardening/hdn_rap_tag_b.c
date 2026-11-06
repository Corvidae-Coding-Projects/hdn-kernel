// SPDX-License-Identifier: GPL-2.0-only
#ifdef HDN_RAP_PROTO_CONFLICT
extern int rap_external(long value);
#else
extern int rap_external(int value);
#endif
static typeof(&rap_external) rap_external_ref __attribute__((used)) = rap_external;
#ifdef HDN_RAP_PROVIDER_CONFLICT
static int (*const __hdn_rap_prototype_shared_type)(long)
#else
static int (*const __hdn_rap_prototype_shared_type)(int)
#endif
	__attribute__((used, section(".discard.hdn_rap.type_providers"))) =
#ifdef HDN_RAP_PROVIDER_NONZERO
	rap_external;
#else
	0;
#endif
#ifdef HDN_RAP_TAG_CONFLICT
struct rap_shared_tag { unsigned int value; };
#else
struct rap_shared_tag { unsigned long value; };
#endif
unsigned long rap_tag_b(struct rap_shared_tag *value)
{
	return value->value;
}
