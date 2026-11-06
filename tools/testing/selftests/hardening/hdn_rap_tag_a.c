// SPDX-License-Identifier: GPL-2.0-only
/* Link/report alongside tag_b; conflicting layouts must fail the build gate. */
struct rap_shared_tag { unsigned long value; };
extern int rap_external(int value);
static typeof(&rap_external) rap_external_ref __attribute__((used)) = rap_external;
static int (*const __hdn_rap_prototype_shared_type)(int)
	__attribute__((used, section(".discard.hdn_rap.type_providers"))) = 0;
unsigned long rap_tag_a(struct rap_shared_tag *value)
{
	return value->value;
}
