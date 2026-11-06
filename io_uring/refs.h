/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IOU_REQ_REF_H
#define IOU_REQ_REF_H

#include <linux/refcount.h>
#include <linux/io_uring_types.h>

static inline __must_check bool req_ref_inc_not_zero(struct io_kiocb *req)
{
	WARN_ON_ONCE(!(req->flags & REQ_F_REFCOUNT));
	/* The timeout lock protects discovery; zero must remain terminal. */
	return refcount_inc_not_zero_acquire(&req->refs);
}

static inline __must_check bool req_ref_put_and_test_atomic(struct io_kiocb *req)
{
	WARN_ON_ONCE(!(data_race(req->flags) & REQ_F_REFCOUNT));
	return refcount_dec_and_test(&req->refs);
}

static inline __must_check bool req_ref_put_and_test(struct io_kiocb *req)
{
	if (likely(!(req->flags & REQ_F_REFCOUNT)))
		return true;

	return refcount_dec_and_test(&req->refs);
}

static inline void req_ref_get(struct io_kiocb *req)
{
	WARN_ON_ONCE(!(req->flags & REQ_F_REFCOUNT));
	refcount_inc(&req->refs);
}

static inline void req_ref_put(struct io_kiocb *req)
{
	WARN_ON_ONCE(!(req->flags & REQ_F_REFCOUNT));
	refcount_dec(&req->refs);
}

static inline void __io_req_set_refcount(struct io_kiocb *req, int nr)
{
	if (!(req->flags & REQ_F_REFCOUNT)) {
		req->flags |= REQ_F_REFCOUNT;
		refcount_set(&req->refs, nr);
	}
}

static inline void io_req_set_refcount(struct io_kiocb *req)
{
	__io_req_set_refcount(req, 1);
}
#endif
