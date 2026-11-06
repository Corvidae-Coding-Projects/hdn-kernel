// SPDX-License-Identifier: GPL-2.0-only
/* Standalone compiler/ELF fixture; runtime cases belong in the guest corpus. */
struct rap_pair { long value; void *owner; };
enum rap_choice { RAP_NEGATIVE = -1, RAP_FIRST, RAP_SECOND };
struct rap_flexible { enum rap_choice choice; char data[]; };
long rap_flexible_read(struct rap_flexible *value) { return value->choice; }
long rap_integer(long value) { return value + 7; }
long rap_pointer(struct rap_pair *value) { return value->value; }
long rap_invoke(long (*function)(long), long value) { return function(value); }
long rap_invoke_pointer(long (*function)(struct rap_pair *), struct rap_pair *value)
{
	return function(value);
}
long rap_two(long (*first)(long), long (*second)(long), long value)
{
	return first(value) + second(value + 1);
}
long rap_stack_args(long (*function)(long, long, long, long, long, long, long, long), long value)
{
	return function(value, 2, 3, 4, 5, 6, 7, 8);
}
long rap_memory_target(long (**function)(long), long value)
{
	return (*function)(value);
}

/* The stackleak plugin uses this exact opaque, register-preserving call.
 * Its return address must be protected even though it is not CALL_INSN RTL. */
long rap_stack_depth(long value)
{
	asm volatile("call __sanitizer_cov_stack_depth" : : : "memory");
	return value + 1;
}

long rap_preempt_calls(long value)
{
	asm volatile("call __SCT__preempt_schedule" : : : "memory");
	asm volatile("call __SCT__preempt_schedule_notrace" : : : "memory");
	asm volatile("call preempt_schedule_thunk" : : : "memory");
	asm volatile("call preempt_schedule_notrace_thunk" : : : "memory");
	return value + 1;
}

extern long rap_case0(long), rap_case1(long), rap_case2(long), rap_case3(long);
extern long rap_case4(long), rap_case5(long), rap_case6(long), rap_case7(long);
long rap_switch(unsigned int choice, long value)
{
	switch (choice) {
	case 0: return rap_case0(value);
	case 1: return rap_case1(value);
	case 2: return rap_case2(value);
	case 3: return rap_case3(value);
	case 4: return rap_case4(value);
	case 5: return rap_case5(value);
	case 6: return rap_case6(value);
	case 7: return rap_case7(value);
	default: return -1;
	}
}

long rap_computed(unsigned int choice, long value)
{
	static void * const labels[] = { &&first, &&second, &&third };

	if (choice >= sizeof(labels) / sizeof(labels[0]))
		return -1;
	goto *labels[choice];
first:
	return rap_case0(value);
second:
	return rap_case1(value);
third:
	return rap_case2(value);
}
