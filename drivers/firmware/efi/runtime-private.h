/* SPDX-License-Identifier: GPL-2.0-only */
/* Included after union efi_rts_args. The submitting task owns all copies until
 * the worker has completed (including its firmware-fault recovery path).
 */
#ifdef CONFIG_SECURITY_HARDENING_PRIVATE_STACKS
#define EFI_ARG_IN	BIT(0)
#define EFI_ARG_OUT	BIT(1)
#define EFI_ARG_SIZE	BIT(2)
#define EFI_ARG_NAME	BIT(3)
#define EFI_ARG_OPTIONAL BIT(4)

struct efi_private_arg {
	void *original, *copy;
	unsigned long size;
	unsigned long *actual;
	unsigned int flags;
};

struct efi_private_request {
	union efi_rts_args args;
	struct efi_private_arg buffers[8];
	unsigned int count;
	unsigned long *result_size, capacity;
	efi_status_t error;
	void **capsule_copies;
	unsigned long nr_capsules;
};

static unsigned long efi_private_name_size(const efi_char16_t *name,
					  unsigned long size)
{
	unsigned long i;

	if (!name)
		return 0;
	for (i = 0; i < size / sizeof(*name); i++)
		if (!name[i])
			return (i + 1) * sizeof(*name);
	return 0;
}

static void *efi_private_arg(struct efi_private_request *request, void *original,
			    unsigned long size, unsigned int flags)
{
	struct efi_private_arg *arg;

	if (request->error != EFI_SUCCESS)
		return NULL;
	if (!original) {
		if (!(flags & EFI_ARG_OPTIONAL))
			request->error = EFI_INVALID_PARAMETER;
		return NULL;
	}
	if (request->count == ARRAY_SIZE(request->buffers)) {
		request->error = EFI_INVALID_PARAMETER;
		return NULL;
	}
	arg = &request->buffers[request->count++];
	arg->original = original;
	arg->size = size;
	arg->flags = flags;
	arg->copy = kvzalloc(max(size, 1UL), GFP_KERNEL);
	if (!arg->copy) {
		request->error = EFI_OUT_OF_RESOURCES;
		return NULL;
	}
	if (flags & EFI_ARG_IN)
		memcpy(arg->copy, original, size);
	return arg->copy;
}

static void efi_private_free(struct efi_private_request *request)
{
	unsigned int i;
	unsigned long j;

	if (!request)
		return;
	for (j = 0; j < request->nr_capsules; j++) {
		efi_capsule_header_t *capsule = request->capsule_copies[j];

		/* Capsule contents are input-only; firmware must not rewrite its
		 * header. The allocation size is not taken back from that header. */
		kvfree(capsule);
	}
	kvfree(request->capsule_copies);
	for (i = 0; i < request->count; i++)
		kvfree_sensitive(request->buffers[i].copy,
				 max(request->buffers[i].size, 1UL));
	kfree_sensitive(request);
}

static efi_capsule_header_t **
efi_private_capsules(struct efi_private_request *request,
		     efi_capsule_header_t **original, unsigned long count,
		     bool update)
{
	efi_capsule_header_t **array;
	unsigned long bytes, i;

	if (!count || !original || check_mul_overflow(count, sizeof(*array), &bytes)) {
		request->error = EFI_INVALID_PARAMETER;
		return NULL;
	}
	array = efi_private_arg(request, original, bytes, EFI_ARG_IN);
	if (!array)
		return NULL;
	request->capsule_copies = kvcalloc(count, sizeof(void *), GFP_KERNEL);
	if (!request->capsule_copies) {
		request->error = EFI_OUT_OF_RESOURCES;
		return NULL;
	}
	request->nr_capsules = count;
	for (i = 0; i < count; i++) {
		efi_capsule_header_t header;
		unsigned long size;

		if (!array[i]) {
			request->error = EFI_INVALID_PARAMETER;
			break;
		}
		header = *array[i];
		if (header.headersize < sizeof(header) || header.imagesize < header.headersize) {
			request->error = EFI_INVALID_PARAMETER;
			break;
		}
		/* UpdateCapsule's persistent payload remains described by the
		 * caller-owned physical scatter list. These virtual copies are
		 * transient call arguments and are never substituted into it. */
		size = update ? header.imagesize : header.headersize;
		request->capsule_copies[i] = kvmalloc(size, GFP_KERNEL);
		if (!request->capsule_copies[i]) {
			request->error = EFI_OUT_OF_RESOURCES;
			break;
		}
		memcpy(request->capsule_copies[i], array[i], size);
		array[i] = request->capsule_copies[i];
	}
	return array;
}

static struct efi_private_request *
efi_private_prepare(enum efi_rts_ids id, const union efi_rts_args *original)
{
	struct efi_private_request *r = kzalloc_obj(*r);
	unsigned long size;

	if (!r)
		return NULL;
	r->args = *original;
#define COPY(member, size, flags) \
	r->args.member = efi_private_arg(r, original->member, size, flags)
#define FIXED(member, flags) COPY(member, sizeof(*original->member), flags)
#define NAME(member) do { \
	size = efi_private_name_size(original->member, EFI_VAR_NAME_LEN); \
	if (!size) r->error = EFI_INVALID_PARAMETER; \
	COPY(member, size, EFI_ARG_IN); \
} while (0)
	switch (id) {
	case EFI_GET_TIME:
		FIXED(GET_TIME.time, EFI_ARG_OUT);
		FIXED(GET_TIME.capabilities, EFI_ARG_OUT | EFI_ARG_OPTIONAL);
		break;
	case EFI_SET_TIME:
		FIXED(SET_TIME.time, EFI_ARG_IN);
		break;
	case EFI_GET_WAKEUP_TIME:
		FIXED(GET_WAKEUP_TIME.enabled, EFI_ARG_OUT);
		FIXED(GET_WAKEUP_TIME.pending, EFI_ARG_OUT);
		FIXED(GET_WAKEUP_TIME.time, EFI_ARG_OUT);
		break;
	case EFI_SET_WAKEUP_TIME:
		FIXED(SET_WAKEUP_TIME.time, EFI_ARG_IN | EFI_ARG_OPTIONAL);
		break;
	case EFI_GET_VARIABLE:
		NAME(GET_VARIABLE.name);
		FIXED(GET_VARIABLE.vendor, EFI_ARG_IN);
		FIXED(GET_VARIABLE.attr, EFI_ARG_OUT | EFI_ARG_OPTIONAL);
		FIXED(GET_VARIABLE.data_size, EFI_ARG_IN | EFI_ARG_OUT | EFI_ARG_SIZE);
		if (r->error != EFI_SUCCESS)
			break;
		size = *original->GET_VARIABLE.data_size;
		r->result_size = r->args.GET_VARIABLE.data_size;
		r->capacity = size;
		if (!original->GET_VARIABLE.data && size) {
			r->error = EFI_INVALID_PARAMETER;
			break;
		}
		/* Preserve a zero-length query's output-length check as well. */
		COPY(GET_VARIABLE.data, size, EFI_ARG_OUT | EFI_ARG_OPTIONAL);
		if (r->args.GET_VARIABLE.data)
			r->buffers[r->count - 1].actual = r->args.GET_VARIABLE.data_size;
		break;
	case EFI_GET_NEXT_VARIABLE:
		FIXED(GET_NEXT_VARIABLE.name_size, EFI_ARG_IN | EFI_ARG_OUT | EFI_ARG_SIZE);
		FIXED(GET_NEXT_VARIABLE.vendor, EFI_ARG_IN | EFI_ARG_OUT);
		if (r->error != EFI_SUCCESS)
			break;
		size = *original->GET_NEXT_VARIABLE.name_size;
		r->result_size = r->args.GET_NEXT_VARIABLE.name_size;
		r->capacity = size;
		if (!efi_private_name_size(original->GET_NEXT_VARIABLE.name, size))
			r->error = EFI_INVALID_PARAMETER;
		COPY(GET_NEXT_VARIABLE.name, size, EFI_ARG_OUT | EFI_ARG_NAME);
		if (r->args.GET_NEXT_VARIABLE.name)
			memcpy(r->args.GET_NEXT_VARIABLE.name, original->GET_NEXT_VARIABLE.name,
			       efi_private_name_size(original->GET_NEXT_VARIABLE.name, size));
		if (r->args.GET_NEXT_VARIABLE.name)
			r->buffers[r->count - 1].actual = r->args.GET_NEXT_VARIABLE.name_size;
		break;
	case EFI_SET_VARIABLE:
		NAME(SET_VARIABLE.name);
		FIXED(SET_VARIABLE.vendor, EFI_ARG_IN);
		if (!original->SET_VARIABLE.data && original->SET_VARIABLE.data_size)
			r->error = EFI_INVALID_PARAMETER;
		COPY(SET_VARIABLE.data, original->SET_VARIABLE.data_size, EFI_ARG_IN | EFI_ARG_OPTIONAL);
		break;
	case EFI_QUERY_VARIABLE_INFO:
		FIXED(QUERY_VARIABLE_INFO.storage_space, EFI_ARG_OUT);
		FIXED(QUERY_VARIABLE_INFO.remaining_space, EFI_ARG_OUT);
		FIXED(QUERY_VARIABLE_INFO.max_variable_size, EFI_ARG_OUT);
		break;
	case EFI_GET_NEXT_HIGH_MONO_COUNT:
		FIXED(GET_NEXT_HIGH_MONO_COUNT.high_count, EFI_ARG_OUT);
		break;
	case EFI_UPDATE_CAPSULE:
		r->args.UPDATE_CAPSULE.capsules = efi_private_capsules(r,
			original->UPDATE_CAPSULE.capsules, original->UPDATE_CAPSULE.count, true);
		break;
	case EFI_QUERY_CAPSULE_CAPS:
		r->args.QUERY_CAPSULE_CAPS.capsules = efi_private_capsules(r,
			original->QUERY_CAPSULE_CAPS.capsules, original->QUERY_CAPSULE_CAPS.count, false);
		FIXED(QUERY_CAPSULE_CAPS.max_size, EFI_ARG_OUT);
		FIXED(QUERY_CAPSULE_CAPS.reset_type, EFI_ARG_OUT);
		break;
	case EFI_ACPI_PRM_HANDLER:
		if (!original->ACPI_PRM_HANDLER.context_size) {
			r->error = EFI_INVALID_PARAMETER;
			break;
		}
		COPY(ACPI_PRM_HANDLER.context, original->ACPI_PRM_HANDLER.context_size, EFI_ARG_IN | EFI_ARG_OUT);
		if (original->ACPI_PRM_HANDLER.param_size) {
			r->args.ACPI_PRM_HANDLER.param_buffer_addr = (unsigned long)
				efi_private_arg(r, (void *)(unsigned long)original->ACPI_PRM_HANDLER.param_buffer_addr,
					original->ACPI_PRM_HANDLER.param_size, EFI_ARG_IN | EFI_ARG_OUT);
		} else if (object_is_on_stack((void *)(unsigned long)original->ACPI_PRM_HANDLER.param_buffer_addr)) {
			r->error = EFI_INVALID_PARAMETER;
		}
		break;
	default:
		r->error = EFI_UNSUPPORTED;
	}
#undef NAME
#undef FIXED
#undef COPY
	return r;
}

static efi_status_t efi_private_complete(struct efi_private_request *r,
					  efi_status_t status)
{
	unsigned int i;

	if (status == EFI_SUCCESS) {
		if (r->result_size && *r->result_size > r->capacity)
			return EFI_DEVICE_ERROR;
		for (i = 0; i < r->count; i++) {
			struct efi_private_arg *arg = &r->buffers[i];
			unsigned long size = arg->actual ? *arg->actual : arg->size;

			if (size > arg->size ||
			    ((arg->flags & EFI_ARG_NAME) &&
			     !efi_private_name_size(arg->copy, size)))
				return EFI_DEVICE_ERROR;
		}
	}
	for (i = 0; i < r->count; i++) {
		struct efi_private_arg *arg = &r->buffers[i];
		unsigned long size = arg->actual ? *arg->actual : arg->size;

		if ((arg->flags & EFI_ARG_OUT) &&
		    (status == EFI_SUCCESS ||
		     ((arg->flags & EFI_ARG_SIZE) && status == EFI_BUFFER_TOO_SMALL)))
			memcpy(arg->original, arg->copy, size);
	}
	return status;
}
#endif
