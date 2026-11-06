/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/uuid.h>

#ifdef CONFIG_ACPI_PRMT
void init_prmt(void);
bool acpi_prm_handler_available(const guid_t *handler_guid);
/* Parameter blobs are copied before worker execution. Any embedded pointers
 * must refer to storage shared with that worker, never a caller stack. */
int acpi_call_prm_handler(guid_t handler_guid, void *param_buffer, size_t param_size);
#else
static inline void init_prmt(void) { }
static inline bool acpi_prm_handler_available(const guid_t *handler_guid) { return false; }
static inline int acpi_call_prm_handler(guid_t handler_guid, void *param_buffer, size_t param_size)
{
	return -EOPNOTSUPP;
}
#endif
