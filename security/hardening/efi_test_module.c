// SPDX-License-Identifier: GPL-2.0-only
/* Read-only real-firmware probes. Run only in the disposable EFI test guest. */
#include <linux/efi.h>
#include <linux/module.h>
#include <linux/slab.h>

struct efi_probe_args {
	efi_char16_t name[16];
	efi_guid_t vendor;
	u32 attr;
	unsigned long size;
	u8 data;
};

static int __init efi_private_probe_init(void)
{
	struct efi_probe_args stack = {
		.name = L"SecureBoot", .vendor = EFI_GLOBAL_VARIABLE_GUID,
		.size = sizeof(stack.data),
	};
	struct efi_probe_args *heap;
	efi_status_t from_stack, from_heap;
	efi_time_t time;
	efi_time_cap_t caps;
	int error = 0;
	unsigned int exercised = 0;

	if (!efi_enabled(EFI_RUNTIME_SERVICES) || !efi.get_variable) {
		pr_info("HDN EFI private-stack probe unavailable: no runtime services\n");
		return -ENODEV;
	}
	heap = kmemdup(&stack, sizeof(stack), GFP_KERNEL);
	if (!heap)
		return -ENOMEM;
	from_stack = efi.get_variable(stack.name, &stack.vendor, &stack.attr,
				      &stack.size, &stack.data);
	from_heap = efi.get_variable(heap->name, &heap->vendor, &heap->attr,
				     &heap->size, &heap->data);
	if (from_stack != from_heap ||
	    ((from_stack == EFI_SUCCESS || from_stack == EFI_BUFFER_TOO_SMALL) &&
	     stack.size != heap->size) ||
	    (from_stack == EFI_SUCCESS &&
	     (stack.size != 1 || stack.data != heap->data || stack.attr != heap->attr)))
		error = -EIO;
	if (from_stack == EFI_SUCCESS) {
		exercised++;
		/* A zero-capacity query must copy back the required native UINTN,
		 * including when the firmware itself uses a 32-bit UINTN. */
		stack.size = 0;
		from_stack = efi.get_variable(stack.name, &stack.vendor, NULL,
					      &stack.size, NULL);
		if (from_stack != EFI_BUFFER_TOO_SMALL || stack.size != 1)
			error = -EIO;
	} else if (from_stack != EFI_NOT_FOUND && from_stack != EFI_UNSUPPORTED) {
		/* Device/access errors are not accepted as successful coverage. */
		error = -EIO;
	}
	if (efi.get_time) {
		from_stack = efi.get_time(&time, &caps);
		if (from_stack != EFI_SUCCESS && from_stack != EFI_UNSUPPORTED)
			error = -EIO;
		if (from_stack == EFI_SUCCESS)
			exercised++;
		if (from_stack == EFI_SUCCESS &&
		    (time.year < 1900 || time.year > 9999 || !time.month || time.month > 12 ||
		     !time.day || time.day > 31 || time.hour > 23 || time.minute > 59 || time.second > 59))
			error = -EIO;
	}
	kfree_sensitive(heap);
	if (!error && !exercised) {
		pr_info("HDN EFI output probes unavailable: no supported read service\n");
		return -EOPNOTSUPP;
	}
	pr_info("HDN EFI private-stack read-only probes: %s\n", error ? "failed" : "completed");
	return error;
}

static void __exit efi_private_probe_exit(void) { }
module_init(efi_private_probe_init);
module_exit(efi_private_probe_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("HDN private-stack read-only EFI runtime probes");
