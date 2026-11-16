/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _HDN_RAP_TAG_FIXTURE_H
#define _HDN_RAP_TAG_FIXTURE_H

/* A header-owned tag is a cross-unit interface.  The whole-build gate must
 * accept matching layouts and reject a translation unit which changes it.
 */
#ifdef HDN_RAP_TAG_CONFLICT
struct rap_shared_tag { unsigned int value; };
#else
struct rap_shared_tag { unsigned long value; };
#endif

#endif
