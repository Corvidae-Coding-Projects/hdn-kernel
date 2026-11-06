// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2002 Richard Henderson
 * Copyright (C) 2001 Rusty Russell, 2002, 2010 Rusty Russell IBM.
 * Copyright (C) 2023 Luis Chamberlain <mcgrof@kernel.org>
 * Copyright (C) 2024 Mike Rapoport IBM.
 */

#define pr_fmt(fmt) "execmem: " fmt

#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/vmalloc.h>
#include <linux/execmem.h>
#include <linux/maple_tree.h>
#include <linux/set_memory.h>
#include <linux/moduleloader.h>
#include <linux/text-patching.h>
#include <linux/overflow.h>
#include <linux/hdn_execmem.h>
#include <linux/hash.h>
#include <linux/random.h>

#include <asm/tlbflush.h>

#include "internal.h"

static struct execmem_info *execmem_info __ro_after_init;
static struct execmem_info default_execmem_info __ro_after_init;
static atomic64_t execmem_bpf_attempts;
static atomic64_t execmem_bpf_successes;
static atomic64_t execmem_bpf_failures;
static atomic64_t execmem_bpf_requested_bytes;
static atomic64_t execmem_bpf_reserved_bytes;
static atomic_t execmem_bpf_exhausted;

unsigned long execmem_bpf_capacity(void)
{
	struct execmem_range *range;

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_BPF_EXECMEM) || !execmem_info)
		return 0;
	range = &execmem_info->ranges[EXECMEM_BPF];
	return range->end - range->start;
}

u64 execmem_bpf_allocation_failures(void)
{
	return atomic64_read(&execmem_bpf_failures);
}

void execmem_bpf_get_stats(struct execmem_bpf_stats *stats)
{
	stats->allocation_attempts = atomic64_read(&execmem_bpf_attempts);
	stats->allocation_successes = atomic64_read(&execmem_bpf_successes);
	stats->allocation_failures = atomic64_read(&execmem_bpf_failures);
	stats->requested_bytes = atomic64_read(&execmem_bpf_requested_bytes);
	stats->reserved_bytes = atomic64_read(&execmem_bpf_reserved_bytes);
	stats->exhausted = atomic_read(&execmem_bpf_exhausted);
}

bool execmem_bpf_contains(const void *address, size_t size)
{
	const struct execmem_range *range;
	unsigned long start = (unsigned long)address;

	if (!IS_ENABLED(CONFIG_SECURITY_HARDENING_BPF_EXECMEM) || !execmem_info || !size)
		return false;
	range = &execmem_info->ranges[EXECMEM_BPF];
	return start >= range->start && start < range->end &&
		size <= range->end - start;
}

#if IS_ENABLED(CONFIG_SECURITY_HARDENING_BPF_EXECMEM_TEST)
u64 execmem_bpf_test_base_token(void)
{
	if (!execmem_info)
		return 0;
	return hash_long(execmem_info->ranges[EXECMEM_BPF].start, BITS_PER_LONG);
}

int execmem_bpf_test_bucket(const void *address)
{
	const struct execmem_range *range;
	unsigned long width, offset;

	if (!execmem_bpf_contains(address, 1))
		return -ERANGE;
	range = &execmem_info->ranges[EXECMEM_BPF];
	width = max_t(unsigned long, (range->end - range->start) / 64, PAGE_SIZE);
	offset = (unsigned long)address - range->start;
	return min_t(unsigned long, offset / width, 63);
}
#endif

#ifdef CONFIG_MMU
static void *execmem_vmalloc(struct execmem_range *range, size_t size,
			     pgprot_t pgprot, unsigned long vm_flags)
{
	bool kasan = range->flags & EXECMEM_KASAN_SHADOW;
	gfp_t gfp_flags = GFP_KERNEL | __GFP_NOWARN;
	unsigned int align = range->alignment;
	unsigned long start = range->start;
	unsigned long end = range->end;
	unsigned long pivot = start;
	void *p;

	if (kasan)
		vm_flags |= VM_DEFER_KMEMLEAK;

	if (range->flags & EXECMEM_RANDOMIZE) {
		unsigned long stride = max_t(unsigned long, align, PAGE_SIZE);
		unsigned long first = ALIGN(start, stride);
		unsigned long slots;

		/* Account for vmalloc's trailing guard; keep both searches in-domain. */
		if (first >= end || end - first <= PAGE_SIZE || size > end - first - PAGE_SIZE)
			return NULL;
		slots = (end - first - PAGE_SIZE - size) / stride + 1;
		if (slots > U32_MAX)
			return NULL;
		pivot = first + get_random_u32_below(slots) * stride;
	}

	p = __vmalloc_node_range(size, align, pivot, end, gfp_flags,
				 pgprot, vm_flags, NUMA_NO_NODE,
				 __builtin_return_address(0));
	if (!p && pivot != start)
		p = __vmalloc_node_range(size, align, start,
					 min(end, pivot + size + PAGE_SIZE), gfp_flags,
					 pgprot, vm_flags, NUMA_NO_NODE,
					 __builtin_return_address(0));
	if (!p && range->fallback_start) {
		start = range->fallback_start;
		end = range->fallback_end;
		p = __vmalloc_node_range(size, align, start, end, gfp_flags,
					 pgprot, vm_flags, NUMA_NO_NODE,
					 __builtin_return_address(0));
	}

	if (!p) {
		pr_warn_ratelimited("unable to allocate memory\n");
		return NULL;
	}

	if (kasan && (kasan_alloc_module_shadow(p, size, GFP_KERNEL) < 0)) {
		vfree(p);
		return NULL;
	}

	return p;
}

struct vm_struct *execmem_vmap(size_t size)
{
	struct execmem_range *range;
	struct vm_struct *area;

	if (!execmem_info || !size || size > ((size_t)INT_MAX << PAGE_SHIFT))
		return NULL;
	range = &execmem_info->ranges[EXECMEM_MODULE_DATA];
	area = __get_vm_area_node(size, range->alignment, PAGE_SHIFT, VM_ALLOC,
				  range->start, range->end, NUMA_NO_NODE,
				  GFP_KERNEL, __builtin_return_address(0));
	if (!area && range->fallback_start)
		area = __get_vm_area_node(size, range->alignment, PAGE_SHIFT, VM_ALLOC,
					  range->fallback_start, range->fallback_end,
					  NUMA_NO_NODE, GFP_KERNEL, __builtin_return_address(0));

	return area;
}
#else
static void *execmem_vmalloc(struct execmem_range *range, size_t size,
			     pgprot_t pgprot, unsigned long vm_flags)
{
	return vmalloc(size);
}
#endif /* CONFIG_MMU */

#ifdef CONFIG_ARCH_HAS_EXECMEM_ROX
struct execmem_cache {
	struct mutex mutex;
	struct maple_tree busy_areas;
	struct maple_tree free_areas;
	unsigned int pending_free_cnt;	/* protected by mutex */
};

/* delay to schedule asynchronous free if fast path free fails */
#define FREE_DELAY	(msecs_to_jiffies(10))

/* mark entries in busy_areas that should be freed asynchronously */
#define PENDING_FREE_MASK	(1 << (PAGE_SHIFT - 1))

static struct execmem_cache execmem_cache = {
	.mutex = __MUTEX_INITIALIZER(execmem_cache.mutex),
	.busy_areas = MTREE_INIT_EXT(busy_areas, MT_FLAGS_LOCK_EXTERN,
				     execmem_cache.mutex),
	.free_areas = MTREE_INIT_EXT(free_areas, MT_FLAGS_LOCK_EXTERN,
				     execmem_cache.mutex),
};

static inline unsigned long mas_range_len(struct ma_state *mas)
{
	return mas->last - mas->index + 1;
}

static int execmem_force_rw(void *ptr, size_t size)
{
	unsigned int nr = PAGE_ALIGN(size) >> PAGE_SHIFT;
	unsigned long addr = (unsigned long)ptr;
	int ret;

	ret = set_memory_nx(addr, nr);
	if (ret)
		return ret;

	return set_memory_rw(addr, nr);
}

int execmem_restore_rox(void *ptr, size_t size)
{
	unsigned int nr;
	unsigned long addr = (unsigned long)ptr;

	if (!size)
		return 0;
	if (!PAGE_ALIGNED(addr) || size > ((size_t)INT_MAX << PAGE_SHIFT))
		return -EINVAL;
	nr = PAGE_ALIGN(size) >> PAGE_SHIFT;
	return set_memory_rox(addr, nr);
}

static void execmem_cache_clean(struct work_struct *work)
{
	struct maple_tree *free_areas = &execmem_cache.free_areas;
	struct mutex *mutex = &execmem_cache.mutex;
	MA_STATE(mas, free_areas, 0, ULONG_MAX);
	void *area;

	mutex_lock(mutex);
	mas_for_each(&mas, area, ULONG_MAX) {
		size_t size = mas_range_len(&mas);

		if (IS_ALIGNED(size, PMD_SIZE) &&
		    IS_ALIGNED(mas.index, PMD_SIZE)) {
			struct vm_struct *vm = find_vm_area(area);

			/* A free PMD-sized slice need not own the entire vmalloc. */
			if (WARN_ON_ONCE(!vm) || vm->addr != area ||
			    ((size_t)vm->nr_pages << PAGE_SHIFT) != size)
				continue;
			mas_store_gfp(&mas, NULL, GFP_KERNEL);
			/* VM_FLUSH_RESET_PERMS unmaps and flushes before restoring RW. */
			vfree(area);
		}
	}
	mutex_unlock(mutex);
}

static DECLARE_WORK(execmem_cache_clean_work, execmem_cache_clean);

static int execmem_cache_add_locked(void *ptr, size_t size, gfp_t gfp_mask)
{
	struct maple_tree *free_areas = &execmem_cache.free_areas;
	unsigned long addr = (unsigned long)ptr;
	MA_STATE(mas, free_areas, addr - 1, addr + 1);
	unsigned long lower, upper;
	void *area = NULL;

	lower = addr;
	upper = addr + size - 1;

	area = mas_walk(&mas);
	if (area && mas.last == addr - 1)
		lower = mas.index;

	area = mas_next(&mas, ULONG_MAX);
	if (area && mas.index == addr + size)
		upper = mas.last;

	mas_set_range(&mas, lower, upper);
	return mas_store_gfp(&mas, (void *)lower, gfp_mask);
}

static int execmem_cache_add(void *ptr, size_t size, gfp_t gfp_mask)
{
	guard(mutex)(&execmem_cache.mutex);

	return execmem_cache_add_locked(ptr, size, gfp_mask);
}

static bool within_range(struct execmem_range *range, struct ma_state *mas,
			 size_t size)
{
	unsigned long addr = mas->index;

	if (addr >= range->start && addr < range->end &&
	    size <= range->end - addr)
		return true;

	if (range->fallback_start &&
	    addr >= range->fallback_start && addr < range->fallback_end &&
	    size <= range->fallback_end - addr)
		return true;

	return false;
}

static void *__execmem_cache_alloc(struct execmem_range *range, size_t size)
{
	struct maple_tree *free_areas = &execmem_cache.free_areas;
	struct maple_tree *busy_areas = &execmem_cache.busy_areas;
	MA_STATE(mas_free, free_areas, 0, ULONG_MAX);
	MA_STATE(mas_busy, busy_areas, 0, ULONG_MAX);
	struct mutex *mutex = &execmem_cache.mutex;
	unsigned long addr, last, area_size = 0;
	void *area, *ptr = NULL;
	int err;

	mutex_lock(mutex);
	mas_for_each(&mas_free, area, ULONG_MAX) {
		area_size = mas_range_len(&mas_free);

		if (area_size >= size && within_range(range, &mas_free, size))
			break;
	}

	if (area_size < size)
		goto out_unlock;

	addr = mas_free.index;
	last = mas_free.last;

	/* insert allocated size to busy_areas at range [addr, addr + size) */
	mas_set_range(&mas_busy, addr, addr + size - 1);
	err = mas_store_gfp(&mas_busy, (void *)addr, GFP_KERNEL);
	if (err)
		goto out_unlock;

	mas_store_gfp(&mas_free, NULL, GFP_KERNEL);
	if (area_size > size) {
		void *ptr = (void *)(addr + size);

		/*
		 * re-insert remaining free size to free_areas at range
		 * [addr + size, last]
		 */
		mas_set_range(&mas_free, addr + size, last);
		err = mas_store_gfp(&mas_free, ptr, GFP_KERNEL);
		if (err) {
			mas_store_gfp(&mas_busy, NULL, GFP_KERNEL);
			goto out_unlock;
		}
	}
	ptr = (void *)addr;

out_unlock:
	mutex_unlock(mutex);
	return ptr;
}

static int execmem_cache_populate(struct execmem_range *range, size_t size)
{
	unsigned long vm_flags = VM_ALLOW_HUGE_VMAP | VM_FLUSH_RESET_PERMS;
	struct vm_struct *vm;
	size_t alloc_size;
	int err = -ENOMEM;
	void *p;

	if (check_add_overflow(size, PMD_SIZE - 1, &alloc_size))
		return -EOVERFLOW;
	alloc_size &= PMD_MASK;
	p = execmem_vmalloc(range, alloc_size, PAGE_KERNEL, vm_flags);
	if (!p) {
		alloc_size = size;
		p = execmem_vmalloc(range, alloc_size, PAGE_KERNEL, vm_flags);
	}

	if (!p)
		return err;

	vm = find_vm_area(p);
	if (!vm)
		goto err_free_mem;

	/* fill memory with instructions that will trap */
	execmem_fill_trapping_insns(p, alloc_size);

	err = set_memory_rox((unsigned long)p, vm->nr_pages);
	if (err)
		goto err_free_mem;

	err = execmem_cache_add(p, alloc_size, GFP_KERNEL);
	if (err)
		goto err_free_mem;

	return 0;

err_free_mem:
	vfree(p);
	return err;
}

static void *execmem_cache_alloc(struct execmem_range *range, size_t size)
{
	void *p;
	int err;

	p = __execmem_cache_alloc(range, size);
	if (p)
		return p;

	err = execmem_cache_populate(range, size);
	if (err)
		return NULL;

	return __execmem_cache_alloc(range, size);
}

static inline bool is_pending_free(void *ptr)
{
	return ((unsigned long)ptr & PENDING_FREE_MASK);
}

static inline void *pending_free_set(void *ptr)
{
	return (void *)((unsigned long)ptr | PENDING_FREE_MASK);
}

static inline void *pending_free_clear(void *ptr)
{
	return (void *)((unsigned long)ptr & ~PENDING_FREE_MASK);
}

static int __execmem_cache_free(struct ma_state *mas, void *ptr, gfp_t gfp_mask)
{
	size_t size = mas_range_len(mas);
	int err;

	err = execmem_force_rw(ptr, size);
	if (err)
		return err;

	execmem_fill_trapping_insns(ptr, size);
	err = execmem_restore_rox(ptr, size);
	if (err)
		return err;

	err = execmem_cache_add_locked(ptr, size, gfp_mask);
	if (err)
		return err;

	mas_store_gfp(mas, NULL, gfp_mask);
	return 0;
}

static void execmem_cache_free_slow(struct work_struct *work);
static DECLARE_DELAYED_WORK(execmem_cache_free_work, execmem_cache_free_slow);

static void execmem_cache_free_slow(struct work_struct *work)
{
	struct maple_tree *busy_areas = &execmem_cache.busy_areas;
	MA_STATE(mas, busy_areas, 0, ULONG_MAX);
	void *area;

	guard(mutex)(&execmem_cache.mutex);

	if (!execmem_cache.pending_free_cnt)
		return;

	mas_for_each(&mas, area, ULONG_MAX) {
		if (!is_pending_free(area))
			continue;

		area = pending_free_clear(area);
		if (__execmem_cache_free(&mas, area, GFP_KERNEL))
			continue;

		execmem_cache.pending_free_cnt--;
	}

	if (execmem_cache.pending_free_cnt)
		schedule_delayed_work(&execmem_cache_free_work, FREE_DELAY);
	else
		schedule_work(&execmem_cache_clean_work);
}

static bool execmem_cache_free(void *ptr)
{
	struct maple_tree *busy_areas = &execmem_cache.busy_areas;
	unsigned long addr = (unsigned long)ptr;
	MA_STATE(mas, busy_areas, addr, addr);
	void *area;
	int err;

	guard(mutex)(&execmem_cache.mutex);

	area = mas_walk(&mas);
	if (!area)
		return false;
	/* Only the allocation base owns the range; never consume an interior free. */
	if (WARN_ON_ONCE(addr != mas.index || is_pending_free(area)))
		return true;

	err = __execmem_cache_free(&mas, area, GFP_KERNEL | __GFP_NORETRY);
	if (err) {
		/*
		 * mas points to exact slot we've got the area from, nothing
		 * else can modify the tree because of the mutex, so there
		 * won't be any allocations in mas_store_gfp() and it will just
		 * change the pointer.
		 */
		area = pending_free_set(area);
		mas_store_gfp(&mas, area, GFP_KERNEL);
		execmem_cache.pending_free_cnt++;
		schedule_delayed_work(&execmem_cache_free_work, FREE_DELAY);
		return true;
	}

	schedule_work(&execmem_cache_clean_work);

	return true;
}

#else /* CONFIG_ARCH_HAS_EXECMEM_ROX */
/*
 * when ROX cache is not used the permissions defined by architectures for
 * execmem ranges that are updated before use (e.g. EXECMEM_MODULE_TEXT) must
 * be writable anyway
 */
static inline int execmem_force_rw(void *ptr, size_t size)
{
	return 0;
}

static void *execmem_cache_alloc(struct execmem_range *range, size_t size)
{
	return NULL;
}

static bool execmem_cache_free(void *ptr)
{
	return false;
}
#endif /* CONFIG_ARCH_HAS_EXECMEM_ROX */

static void *__execmem_alloc(enum execmem_type type, size_t size, bool writable)
{
	struct execmem_range *range;
	size_t requested = size;
	bool bpf = IS_ENABLED(CONFIG_SECURITY_HARDENING_BPF_EXECMEM) && execmem_is_bpf(type);
	bool use_cache;
	unsigned long vm_flags = VM_FLUSH_RESET_PERMS;
	pgprot_t pgprot;
	void *p = NULL;

	if (!execmem_info || (unsigned int)type >= EXECMEM_TYPE_MAX || !size ||
	    size > ((size_t)INT_MAX << PAGE_SHIFT))
		return NULL;
	range = &execmem_info->ranges[type];
	if (bpf)
		atomic64_inc(&execmem_bpf_attempts);
	use_cache = range->flags & EXECMEM_ROX_CACHE;
	pgprot = range->pgprot;
	size = PAGE_ALIGN(size);

	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_EXECMEM) && type != EXECMEM_MODULE_DATA) {
		bool initial_rox = !writable && (use_cache || type == EXECMEM_KPROBES);

		p = execmem_vmalloc(range, size, PAGE_KERNEL, vm_flags);
		if (!p) {
			if (bpf) {
				atomic64_inc(&execmem_bpf_failures);
				atomic_set(&execmem_bpf_exhausted, 1);
			}
			return NULL;
		}
		if (hdn_execmem_claim_type(p, type)) {
			vfree(p);
			if (bpf) {
				atomic64_inc(&execmem_bpf_failures);
				atomic_set(&execmem_bpf_exhausted, 1);
			}
			return NULL;
		}
		if (initial_rox) {
#ifdef CONFIG_ARCH_HAS_EXECMEM_ROX
			execmem_fill_trapping_insns(p, size);
#endif
			if (set_memory_rox((unsigned long)p, size >> PAGE_SHIFT)) {
				execmem_free(p);
				return NULL;
			}
		}
		if (bpf) {
			atomic64_inc(&execmem_bpf_successes);
			atomic64_add(requested, &execmem_bpf_requested_bytes);
			atomic64_add(size, &execmem_bpf_reserved_bytes);
			atomic_set(&execmem_bpf_exhausted, 0);
		}
		return kasan_reset_tag(p);
	}

	if (use_cache)
		p = execmem_cache_alloc(range, size);
	else
		p = execmem_vmalloc(range, size, pgprot, vm_flags);

	return kasan_reset_tag(p);
}

void *execmem_alloc(enum execmem_type type, size_t size)
{
	return __execmem_alloc(type, size, false);
}

void *execmem_alloc_rw(enum execmem_type type, size_t size)
{
	void *p __free(execmem) = __execmem_alloc(type, size, true);
	int err;

	if (!p)
		return NULL;
	if (IS_ENABLED(CONFIG_SECURITY_HARDENING_EXECMEM) && type != EXECMEM_MODULE_DATA)
		return no_free_ptr(p);

	err = execmem_force_rw(p, size);
	if (err)
		return NULL;

	return no_free_ptr(p);
}

void execmem_free(void *ptr)
{
	/*
	 * This memory may be RO, and freeing RO memory in an interrupt is not
	 * supported by vmalloc.
	 */
	WARN_ON(in_interrupt());

	if (hdn_execmem_free(ptr))
		return;
	if (!execmem_cache_free(ptr))
		vfree(ptr);
}

bool execmem_is_rox(enum execmem_type type)
{
	if (!execmem_info || (unsigned int)type >= EXECMEM_TYPE_MAX)
		return false;
	return !!(execmem_info->ranges[type].flags & EXECMEM_ROX_CACHE);
}

static bool execmem_validate(struct execmem_info *info)
{
	struct execmem_range *r = &info->ranges[EXECMEM_DEFAULT];

	if (!r->alignment || !r->start || !r->end || !pgprot_val(r->pgprot)) {
		pr_crit("Invalid parameters for execmem allocator, module loading will fail");
		return false;
	}

	if (!IS_ENABLED(CONFIG_ARCH_HAS_EXECMEM_ROX)) {
		for (int i = EXECMEM_DEFAULT; i < EXECMEM_TYPE_MAX; i++) {
			r = &info->ranges[i];

			if (r->flags & EXECMEM_ROX_CACHE) {
				pr_warn_once("ROX cache is not supported\n");
				r->flags &= ~EXECMEM_ROX_CACHE;
			}
		}
	}

	return true;
}

static void execmem_init_missing(struct execmem_info *info)
{
	struct execmem_range *default_range = &info->ranges[EXECMEM_DEFAULT];

	for (int i = EXECMEM_DEFAULT + 1; i < EXECMEM_TYPE_MAX; i++) {
		struct execmem_range *r = &info->ranges[i];

		if (!r->start) {
			if (execmem_is_bpf(i) && i != EXECMEM_BPF) {
				*r = info->ranges[EXECMEM_BPF];
				continue;
			}
			if (i == EXECMEM_MODULE_DATA)
				r->pgprot = PAGE_KERNEL;
			else
				r->pgprot = default_range->pgprot;
			r->alignment = default_range->alignment;
			r->start = default_range->start;
			r->end = default_range->end;
			r->flags = default_range->flags;
			r->fallback_start = default_range->fallback_start;
			r->fallback_end = default_range->fallback_end;
		}
	}
}

struct execmem_info * __weak execmem_arch_setup(void)
{
	return NULL;
}

static void __init __execmem_init(void)
{
	struct execmem_info *info = execmem_arch_setup();

	if (!info) {
		info = execmem_info = &default_execmem_info;
		info->ranges[EXECMEM_DEFAULT].start = VMALLOC_START;
		info->ranges[EXECMEM_DEFAULT].end = VMALLOC_END;
		info->ranges[EXECMEM_DEFAULT].pgprot = PAGE_KERNEL_EXEC;
		info->ranges[EXECMEM_DEFAULT].alignment = 1;
	}

	if (!execmem_validate(info))
		return;

	execmem_init_missing(info);

	execmem_info = info;
}

#ifdef CONFIG_ARCH_WANTS_EXECMEM_LATE
static int __init execmem_late_init(void)
{
	__execmem_init();
	return 0;
}
core_initcall(execmem_late_init);
#else
void __init execmem_init(void)
{
	__execmem_init();
}
#endif
