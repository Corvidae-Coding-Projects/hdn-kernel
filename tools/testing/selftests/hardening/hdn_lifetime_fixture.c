// SPDX-License-Identifier: GPL-2.0-only
/* Compile-only lifetime seeds. HDN_LIFETIME_BAD introduces gate failures. */
#define INIT __attribute__((section(".init.text"), __noinline__, used))
#define INITDATA __attribute__((section(".init.data"), used))
#define SEALED __attribute__((section(".data..ro_after_init"), used))

struct dispatch { int (*call)(int); };
static int initialized_setting SEALED;
static int boot_input INITDATA;

static int runtime_operation(int value)
{
	return value + initialized_setting;
}

static const struct dispatch immutable_dispatch __attribute__((used)) = {
	.call = runtime_operation,
};

int lifetime_fixture_init(int value);
int lifetime_fixture_runtime(int value);

int INIT lifetime_fixture_init(int value)
{
	boot_input = value;
	initialized_setting = boot_input;
	return initialized_setting;
}

int lifetime_fixture_runtime(int value)
{
	return immutable_dispatch.call(value);
}

#ifdef HDN_LIFETIME_BAD
int lifetime_fixture_bad(int value);

static struct dispatch mutable_dispatch __attribute__((used)) = {
	.call = runtime_operation,
};
/* Both a relocation and an initializer reference must expose this edge. */
int (*retained_init_callback)(int) = lifetime_fixture_init;

int lifetime_fixture_bad(int value)
{
	volatile int *alias = &initialized_setting;
	*alias = value;
	/* Keep callee-hidden mutation as an exact address/call edge even when
	 * optimization removes the builtin operation itself. */
	__builtin_memcpy(&initialized_setting, &value, sizeof(value));
	return lifetime_fixture_init(mutable_dispatch.call(value));
}
#endif
