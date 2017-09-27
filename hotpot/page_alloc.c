/*
 * Distributed Shared NVM.
 *
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * This file describes NVM management (nvmm) subsystem. Basically, we
 * manage NVM in the same way as DRAM: each NVM page has a dsnvm_page
 * structure associated with it to describe runtime status. Moreover,
 * dsnvm_page is persistent, which could help us to recovery from crash.
 *
 * Above that, we have a buddy allocator and per-cpu free page lists that
 * serve page alloc/free requests.
 */

#include <linux/log2.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/hash.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/rwsem.h>
#include <linux/kernel.h>
#include <linux/bitops.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/cpumask.h>

#include "dsnvm.h"

/*
 * Something should be mentioned in the paper:
 * Though we use volatile data structures to allocate/free those non-volatile
 * data structures, all manipulation can be failure-atomic even if a failure
 * happens in the middle of allocation/free. Since all non-volatile data structures
 * have their `flag` to indicate whether or not it has been allocated.
 *
 * So.. we can reconstruct everything during recovery with the help of `flag`s.
 */

struct dsnvm_buddy *buddy;

/* DSNVM metadata area */
struct dsnvm_page *dsnvm_map;

static struct dsnvm_client_file *dsnvm_filemap;
static DECLARE_BITMAP(filemap_slot, NR_DSNVM_FILE);
static DEFINE_SPINLOCK(dsnvm_filemap_lock);

struct dsnvm_log_record *dsnvm_logmap;
DECLARE_BITMAP(logmap_slot, DSNVM_MAX_LOG_RECORDS);
DEFINE_SPINLOCK(dsnvm_logmap_lock);

struct on_region_info *dsnvm_onmap;
DECLARE_BITMAP(onmap_slot, DSNVM_MAX_ON_REGION_INFO);
DEFINE_SPINLOCK(dsnvm_onmap_lock);

struct replica_region_info *dsnvm_replicamap;
DECLARE_BITMAP(replicamap_slot, DSNVM_MAX_REPLICA_REGION_INFO);
DEFINE_SPINLOCK(dsnvm_replicamap_lock);

unsigned long dsnvm_pfn_offset;
unsigned long dsnvm_phys_addr;
unsigned long dsnvm_virt_addr;
unsigned long dsnvm_usable_phys_addr;
unsigned long dsnvm_usable_virt_addr;

/*
 * nr of pages used for struct dsnvm_page array
 * nr of pages used for dsnvm_client_file array
 * nr of pages used for dsnvm log records array
 * nr of pages used for dsnvm on_region array
 * nr of pages used for dsnvm replica_region array
 */
unsigned long dsnvm_nr_pages_map;
unsigned long dsnvm_nr_pages_filemap;
unsigned long dsnvm_nr_pages_logmap;
unsigned long dsnvm_nr_pages_onmap;
unsigned long dsnvm_nr_pages_replicamap;

/*
 * nr of all pages
 * nr of pages used for metadata
 * nr of pages after metadata
 *
 * Note that:
 * nr_pages_metadata = nr_pages_map + nr_pages_bitmap + nr_pages_filemap + nr_pages_logmap +
 * 			nr_pages_onmap + nr_pages_replicamap;
 * nr_pages_usable = nr_pages - nr_pages_metadata;
 */
unsigned long dsnvm_nr_pages;
unsigned long dsnvm_nr_pages_metadata;
unsigned long dsnvm_nr_pages_usable;

/*
 * wait_table			-- the array holding the hash table
 * wait_table_hash_nr_entries	-- the size of the hash table array
 * wait_table_bits		-- wait_table_size == (1 << wait_table_bits)
 *
 * The purpose of all these is to keep track of the people waiting for a page
 * to become available and make them runnable again when possible. The trouble
 * is that this consumes a lot of space, especially when so few things wait on
 * pages at a given time. So instead of using per-page waitqueues, we use a
 * waitqueue hash table.
 *
 * The bucket discipline is to sleep on the same queue when colliding and wake
 * all in that wait queue when removing. When something wakes, it must check to
 * be sure its page is truly available, a la thundering herd. The cost of a
 * collision is great, but given the expected load of the table, they should be
 * so rare as to be outweighed by the benefits from the saved space.
 */
static wait_queue_head_t *wait_table;
unsigned long wait_table_hash_nr_entries;
unsigned long wait_table_bits;

/*
 * Helper functions to size the waitqueue hash table.
 * Essentially these want to choose hash table sizes sufficiently
 * large so that collisions trying to wait on pages are rare.
 * But in fact, the number of active page waitqueues on typical
 * systems is ridiculously low, less than 200. So this is even
 * conservative, even though it seems large.
 *
 * The constant DSNVM_PAGES_PER_WAITQUEUE specifies the ratio of pages to
 * waitqueues, i.e. the size of the waitq table given the number of pages.
 */
#define DSNVM_PAGES_PER_WAITQUEUE	256
static inline unsigned long __wait_table_hash_nr_entries(unsigned long pages)
{
	unsigned long size = 1;

	pages /= DSNVM_PAGES_PER_WAITQUEUE;

	while (size < pages)
		size <<= 1;

	/* Limit wait table to a reasonable size. */
	size = min(size, 4096UL);
	size = max(size, 4UL);

	return size;
}

/*
 * This is an integer logarithm so that shifts can be used later
 * to extract the more random high bits from the multiplicative
 * hash function before the remainder is taken.
 */
static inline unsigned long __wait_table_bits(unsigned long size)
{
	return ffz(~size);
}

static int init_dsnvm_wait_table(unsigned long nr_pages)
{
	int i;
	size_t alloc_size;

	wait_table_hash_nr_entries = __wait_table_hash_nr_entries(nr_pages);
	wait_table_bits = __wait_table_bits(wait_table_hash_nr_entries);
	alloc_size = wait_table_hash_nr_entries * sizeof(wait_queue_head_t);

	wait_table = kmalloc(alloc_size, GFP_KERNEL);
	if (!wait_table)
		return -ENOMEM;

	for (i = 0; i < wait_table_hash_nr_entries; i++)
		init_waitqueue_head(wait_table + i);

	return 0;
}

static void destroy_dsnvm_wait_table(void)
{
	if (wait_table)
		kfree(wait_table);
}

/**
 * dsnvm_page_waitqueue
 * @page: the page to ask
 * @Return the wait_queue_head_t pointer this @page hashed to.
 *
 * In order to wait for pages to become available, there must be waitqueues
 * associated with pages. By using a hash table of waitqueues where the bucket
 * discipline is to maintain all waiters on the same queue and wake all when
 * any of the pages become available, and for the woken contexts to check to
 * be sure the appropriate page become available, this saves sapce at a cost
 * of "thundering herd" phenomena during race hash collisions.
 */
wait_queue_head_t *dsnvm_page_waitqueue(struct dsnvm_page *page)
{
	return &wait_table[hash_ptr(page, wait_table_bits)];
}

int sleep_on_dsnvm_page(void *unused)
{
	io_schedule();
	return 0;
}

unsigned char *page_flag_text[] = {
	"locked",
	"committed",
	"accessed",
	"dirty",
	"LRU",
	"active",
	"unevictable",
	"inxact",
	"replica",
	"private",
	"owner"
};

void dump_dsnvm_page(struct dsnvm_page *page, const unsigned char *reason)
{
#define INFO_LEN 128
	int bit;
	unsigned char info[INFO_LEN], *b;

	if (!page)
		return;

	b = info;
	b += scnprintf(b, INFO_LEN, "pfn=%lu,", dsnvm_page_to_pfn(page));
	b += scnprintf(b, INFO_LEN, "d_pfn=%lu,", dsnvm_page_to_dsnvm_pfn(page));
	b += scnprintf(b, INFO_LEN, "map=%d,", dsnvm_page_mapcount(page));
	b += scnprintf(b, INFO_LEN, "ref=%d,", dsnvm_page_refcount(page));
	b += scnprintf(b, INFO_LEN, "private=%#lx,", dsnvm_page_private(page));

	for_each_set_bit (bit, &page->flags, __NR_DSNVM_PAGE_FLAGS) {
		b += scnprintf(b, INFO_LEN, "%s,", page_flag_text[bit]);
	}

	b -= 1;
	*b = '\0';

	pr_crit("[Page]: %s", info);
	if (reason)
		pr_crit("Page dumped because of: %s", reason);
#undef INFO_LEN
}

static inline void set_dsnvm_page_order(struct dsnvm_page *page, int order)
{
	set_dsnvm_page_private(page, order);
	DSNVM_SetPageBuddy(page);
}

static inline void clear_dsnvm_page_order(struct dsnvm_page *page)
{
	DSNVM_ClearPageBuddy(page);
	set_dsnvm_page_private(page, 0);
}

static inline void expand(struct dsnvm_buddy *dsnvm_buddy, struct dsnvm_page *page,
			  int low, int high, struct dsnvm_free_area *area)
{
	unsigned long size = 1 << high;

	while (high > low) {
		area--;
		high--;
		size >>= 1;

		list_add(&page[size].lru, &area->free_list);
		area->nr_free++;
		set_dsnvm_page_order(&page[size], high);
	}
}

/*
 * Go through the free lists, do the hard work of removing an element from the
 * buddy allocator. Call me with the buddy->lock already held.
 */
static struct dsnvm_page *__rmqueue(struct dsnvm_buddy *dsnvm_buddy,
				    unsigned int order)
{
	unsigned int current_order;
	struct dsnvm_free_area *area;
	struct dsnvm_page *page;

	mod_buddy_stat(dsnvm_buddy, NR_FREE_DSNVM_PAGES, -(1 << order));

	for (current_order = order; current_order < DSNVM_MAX_ORDER; ++current_order) {
		area = &(dsnvm_buddy->free_area[current_order]);
		page = list_first_entry_or_null(&area->free_list,
						struct dsnvm_page, lru);
		if (!page)
			continue;

		list_del(&page->lru);
		clear_dsnvm_page_order(page);
		area->nr_free--;
		expand(dsnvm_buddy, page, order, current_order, area);
		return page;
	}
	return NULL;
}

/*
 * Obtain a specified number of elements from the buddy allocator, all under
 * a single hold of the lock, for efficiency.  Add them to the supplied list.
 * Returns the number of new pages which were placed at *list.
 */
static int rmqueue_bulk(struct dsnvm_buddy *dsnvm_buddy, unsigned int order,
			unsigned int count, struct list_head *list, bool cold)
{
	int i;

	spin_lock(&dsnvm_buddy->lock);
	for (i = 0; i < count; ++i) {
		struct dsnvm_page *page;
		
		page = __rmqueue(dsnvm_buddy, order);
		if (unlikely(!page))
			break;

		/*
		 * Split buddy pages returned by expand() are received here
		 * in physical page order. The page is added to the callers and
		 * list and the list head then moves forward. From the callers
		 * perspective, the linked list is ordered by page number in
		 * some conditions. This is useful for IO devices that can
		 * merge IO requests if the physical pages are ordered
		 * properly.
		 */
		if (likely(!cold))
			list_add(&page->lru, list);
		else
			list_add_tail(&page->lru, list);
		list = &page->lru;
	}
	spin_unlock(&dsnvm_buddy->lock);

	return i;
}

/* Allocate a page, use pcplists for order-0 allocations */
static __always_inline struct dsnvm_page *
buffered_rmqueue(struct dsnvm_buddy *dsnvm_buddy, unsigned int order)
{
	struct dsnvm_page *page;
	unsigned long flags;
	bool cold = false;

	if (likely(order == 0)) {
		struct dsnvm_per_cpu_pages *pcp;
		struct list_head *list;

		local_irq_save(flags);
		pcp = &this_cpu_ptr(dsnvm_buddy->pageset)->pcp;
		list = &pcp->lists;
		if (list_empty(list)) {
			pcp->count += rmqueue_bulk(dsnvm_buddy, 0, pcp->batch,
						   list, cold);
			if (unlikely(list_empty(list)))
				goto failed;
		}

		if (cold)
			page = list_entry(list->prev, struct dsnvm_page, lru);
		else
			page = list_entry(list->next, struct dsnvm_page, lru);

		list_del(&page->lru);
		pcp->count--;
	} else {
		spin_lock_irqsave(&dsnvm_buddy->lock, flags);
		page = __rmqueue(dsnvm_buddy, order);
		spin_unlock(&dsnvm_buddy->lock);
		if (!page)
			goto failed;
	}

	local_irq_restore(flags);
	return page;

failed:
	local_irq_restore(flags);
	return NULL;
}

/*
 * Prepare a new allocated @page of @order.
 * No private field anymore, refcount is set to 1, mapcount is set to 0.
 * DSNVM Buddy allocator is simple and designed for Hotpot. Live with it.
 */
static __always_inline void
prep_new_dsnvm_page(struct dsnvm_page *page, unsigned int order)
{
	set_dsnvm_page_private(page, 0);
	set_dsnvm_page_refcount(page, 1);
	set_dsnvm_page_mapcount(page, 0);
}

static __always_inline struct dsnvm_page *
get_page_from_freelist(struct dsnvm_buddy *dsnvm_buddy, unsigned int order)
{
	struct dsnvm_page *page;

	page = buffered_rmqueue(dsnvm_buddy, order);
	if (page)
		prep_new_dsnvm_page(page, order);

	return page;
}

static struct dsnvm_page *__alloc_dsnvm_pages_slowpath(struct dsnvm_buddy *dsnvm_buddy,
							unsigned int order)
{
	return NULL;
}

/**
 * Common API - __alloc_dsnvm_pages
 * @order: order of the pages
 *
 * Return the pointer to the first allocated NVM page structure
 * Note that the new page will not be put into LRU here.
 * Also note that the page has: @refcount=1, @mapcount=0.
 */
struct dsnvm_page *__alloc_dsnvm_pages(unsigned int order)
{
	struct dsnvm_page *page;

	page = get_page_from_freelist(buddy, order);
	if (likely(page))
		goto out;

	/* Try to reclaim some pages */
	page = __alloc_dsnvm_pages_slowpath(buddy, order);

out:
	return page;
}

/**
 * Common API - alloc_dsnvm_pages
 * @order: order of the pages
 *
 * Return the pointer to the first allocated NVM page
 */
void *alloc_dsnvm_pages(unsigned int order)
{
	struct dsnvm_page *page;

	page = __alloc_dsnvm_pages(order);
	if (!page)
		return NULL;

	return (void *)dsnvm_page_to_virt(page);
}

/**
 * Common API - alloc_dsnvm_page
 *
 * Allocate one NVM page, and return its kernel virtual address
 */
void *alloc_dsnvm_page(void)
{
	return alloc_dsnvm_pages(0);
}

/**
 * Common API - alloc_dsnvm_page_pfn
 *
 * Allocate one NVM page, and return its PFN
 */
unsigned long alloc_dsnvm_page_pfn(void)
{
	void *addr;
	unsigned long dsnvm_pfn;

	addr = alloc_dsnvm_page();
	if (unlikely(!addr))
		return 0;

	dsnvm_pfn = virt_to_dsnvm_pfn((unsigned long)addr);
	return dsnvm_pfn_to_pfn(dsnvm_pfn);
}

#define DSNVM_PAGE_FLAGS_CHECK_AT_FREE		\
(						\
	(1UL << DSNVM_PG_locked)	|	\
	(1UL << DSNVM_PG_lru)		|	\
	(1UL << DSNVM_PG_inxact)		\
)

static __always_inline int
__free_dsnvm_pages_ok(struct dsnvm_page *page)
{
#if 0
	if (unlikely(atomic_read(&page->mapcount) != 0)) {
		dump_dsnvm_page(page, "nonzero mapcount");
		return 1;
	}

	if (unlikely(atomic_read(&page->refcount) != 0)) {
		dump_dsnvm_page(page, "nonzero refcount");
		return 1;
	}

	if (unlikely(page->flags & DSNVM_PAGE_FLAGS_CHECK_AT_FREE)) {
		dump_dsnvm_page(page, "bad page flags");
		return 1;
	}
#endif

	return 0;
}

static __always_inline void
free_dsnvm_pages_cleanup(struct dsnvm_page *page, unsigned int order)
{
	int i;
	struct dsnvm_page *p;

	for (i = 0; i < (1 << order); i++) {
		p = page + i;
		p->flags = 0;
		barrier();
	}
}

static __always_inline bool
free_dsnvm_pages_ok(struct dsnvm_page *page, unsigned int order)
{
	int i, bad;

	for (i = 0, bad = 0; i < (1 << order); i++)
		bad += __free_dsnvm_pages_ok(page + i);

	if (unlikely(bad))
		return false;

	free_dsnvm_pages_cleanup(page, order);
	return true;
}

/*
 * Locate the struct page for both the matching buddy in our
 * pair (buddy1) and the combined O(n+1) page they form (page).
 *
 * 1) Any buddy B1 will have an order O twin B2 which satisfies
 * the following equation:
 *     B2 = B1 ^ (1 << O)
 * For example, if the starting buddy (buddy2) is #8 its order
 * 1 buddy is #10:
 *     B2 = 8 ^ (1 << 1) = 8 ^ 2 = 10
 *
 * 2) Any buddy B will have an order O+1 parent P which
 * satisfies the following equation:
 *     P = B & ~(1 << O)
 */
static inline unsigned long
__find_buddy_index(unsigned long page_idx, unsigned int order)
{
	return page_idx ^ (1 << order);
}

/*
 * This function checks whether a page is free && is the buddy
 * we can do coalesce a page and its buddy if
 * (a) the buddy is in the buddy system &&
 * (b) a page and its buddy have the same order
 *
 * For recording whether a page is in the buddy system, we set ->mapcount
 * PAGE_BUDDY_MAPCOUNT_VALUE.
 *
 * Setting, clearing, and testing mapcount PAGE_BUDDY_MAPCOUNT_VALUE is
 * serialized by zone->lock.
 *
 * For recording page's order, we use dsnvm_page_private(page).
 */
static inline int dsnvm_page_is_buddy(struct dsnvm_page *buddy, unsigned int order)
{
	if (DSNVM_PageBuddy(buddy) && dsnvm_page_order(buddy) == order)
		return 1;
	return 0;
}

/* Call me with buddy->lock held */
static void __free_one_dsnvm_page(struct dsnvm_buddy *dsnvm_buddy,
				  struct dsnvm_page *page, unsigned int order)
{
	unsigned long page_idx;
	unsigned long buddy_idx;
	unsigned long combined_idx;
	struct dsnvm_page *buddy;

	mod_buddy_stat(dsnvm_buddy, NR_FREE_DSNVM_PAGES, 1 << order);

	/* Yes, everthing is about dsnvm_pfn aligned */
	page_idx = dsnvm_page_to_dsnvm_pfn(page) & ((1 << DSNVM_MAX_ORDER) - 1);

	BUG_ON(page_idx & ((1 << order) - 1));

	while (order < (DSNVM_MAX_ORDER - 1)) {
		buddy_idx = __find_buddy_index(page_idx, order);
		buddy = page + (buddy_idx - page_idx);

		if (!dsnvm_page_is_buddy(buddy, order))
			break;

		list_del(&buddy->lru);
		dsnvm_buddy->free_area[order].nr_free--;
		clear_dsnvm_page_order(buddy);

		combined_idx = buddy_idx & page_idx;
		page = page + (combined_idx - page_idx);
		page_idx = combined_idx;
		order++;
	}

	set_dsnvm_page_order(page, order);

	list_add(&page->lru, &dsnvm_buddy->free_area[order].free_list);
	dsnvm_buddy->free_area[order].nr_free++;
}

static void free_one_dsnvm_page(struct dsnvm_buddy *dsnvm_buddy,
				struct dsnvm_page *page, unsigned int order)
{
	spin_lock(&buddy->lock);
	__free_one_dsnvm_page(dsnvm_buddy, page, order);
	spin_unlock(&buddy->lock);
}

/*
 * Frees a number of pages from the PCP lists
 */
static void free_dsnvm_pcppages_bulk(struct dsnvm_buddy *dsnvm_buddy, int count,
				     struct dsnvm_per_cpu_pages *pcp)
{
	struct dsnvm_page *page;
	struct list_head *list = &pcp->lists;

	spin_lock(&buddy->lock);
	while (count) {
		page = list_entry(list->prev, struct dsnvm_page, lru);

		/* must delete as __free_one_page list manipulates */
		list_del(&page->lru);

		__free_one_dsnvm_page(dsnvm_buddy, page, 0);

		count--;
	}
	spin_unlock(&buddy->lock);
}

/*
 * Free a 0-order page to the pcp list
 *
 * BIT FAT NOTE for order = 0 case:
 * Make sure the page that you are going to free is NOT in the LRU list!!!
 * If it was added to LRU list previously, use put_dsnvm_page() instead.
 */
void free_hot_cold_dsnvm_page(struct dsnvm_page *page, bool cold)
{
	unsigned long flags;
	struct dsnvm_per_cpu_pages *pcp;

	local_irq_save(flags);
	pcp = &this_cpu_ptr(buddy->pageset)->pcp;
	if (!cold)
		list_add(&page->lru, &pcp->lists);
	else
		list_add_tail(&page->lru, &pcp->lists);
	pcp->count++;

	/* Put some pages back to buddy allocator */
	if (pcp->count >= pcp->high) {
		unsigned long batch = pcp->batch;
		free_dsnvm_pcppages_bulk(buddy, batch, pcp);
		pcp->count -= batch;
	}

	local_irq_restore(flags);
}

void free_hot_cold_dsnvm_page_list(struct list_head *list, bool cold)
{
        struct dsnvm_page *page, *next;

	list_for_each_entry_safe(page, next, list, lru)
		free_hot_cold_dsnvm_page(page, cold);
}

/* Internal function that does not check refcount */
static __always_inline void
___free_dsnvm_pages(struct dsnvm_page *page, unsigned int order)
{
	if (likely(free_dsnvm_pages_ok(page, order))) {
		if (order == 0)
			free_hot_cold_dsnvm_page(page, false);
		else
			free_one_dsnvm_page(buddy, page, order);
	}
}

/**
 * Common API - __free_dsnvm_pages
 *
 * @page: the pointer to the first page structure
 * @order: order of this page list
 */
void __free_dsnvm_pages(struct dsnvm_page *page, unsigned int order)
{
	/*
	 * In Hotpot, only LRU isolated pages will use get dsnvm pages.
	 * If we fail to free here, it basically (only) means the page
	 * is currently at isolated page list. (Sep 19, 2016)
	 */
	if (put_dsnvm_page_testzero(page))
		___free_dsnvm_pages(page, order);
}

/**
 * Common API - free_dsnvm_pages
 *
 * @addr: kernel virtual address of the first page
 * @order: order of this page list
 *
 * BIT FAT NOTE for order = 0 case:
 * Make sure the page that you are going to free is NOT in the LRU list!!!
 * If it was added to LRU list previously, use put_dsnvm_page() instead.
 */
void free_dsnvm_pages(void *addr, unsigned int order)
{
	if (virt_is_dsnvm((unsigned long)addr))
		__free_dsnvm_pages(virt_to_dsnvm_page((unsigned long)addr), order);
}

/**
 * Common API - free_dsnvm_page
 *
 * Free just one page by the kernel virtual address
 *
 * BIT FAT NOTE for order = 0 case:
 * Make sure the page that you are going to free is NOT in the LRU list!!!
 * If it was added to LRU list previously, use put_dsnvm_page() instead.
 */
void free_dsnvm_page(void *addr)
{
	free_dsnvm_pages(addr, 0);
}

/**
 * Common API - free_dsnvm_page
 *
 * Free just one page by the PFN
 *
 * BIT FAT NOTE for order = 0 case:
 * Make sure the page that you are going to free is NOT in the LRU list!!!
 * If it was added to LRU list previously, use put_dsnvm_page() instead.
 */
void free_dsnvm_page_pfn(unsigned long pfn)
{
	if (unlikely(!pfn_is_dsnvm(pfn)))
		return;

	free_dsnvm_page((void *)pfn_to_dsnvm_virt(pfn));
}

static int dsnvm_buddy_batchsize(struct dsnvm_buddy *buddy)
{
	int batch;

	/*
	 * The per-cpu-pages pools are set to around 1000th of the
	 * size of the zone.  But no more than 1/2 of a meg.
	 *
	 * OK, so we don't know how big the cache is.  So guess.
	 */
	batch = buddy->nr_pages / 1024;
	if (batch * PAGE_SIZE > 512 * 1024)
		batch = (512 * 1024) / PAGE_SIZE;
	batch /= 4;		/* We effectively *= 4 below */
	if (batch < 1)
		batch = 1;

	/*
	 * Clamp the batch to a 2^n - 1 value. Having a power
	 * of 2 value was found to be more likely to have
	 * suboptimal cache aliasing properties in some cases.
	 *
	 * For example if 2 tasks are alternately allocating
	 * batches of pages, one task can end up with a lot
	 * of pages of one half of the possible page colors
	 * and the other with pages of the other colors.
	 *
	 * (batch will be 31, normally)
	 */
	batch = rounddown_pow_of_two(batch + batch/2) - 1;

	return batch;
}

/*
 * pcp->high and pcp->batch values are related and dependent on one another:
 * ->batch must never be higher then ->high.
 * The following function updates them in a safe manner without read side
 * locking.
 *
 * Any new users of pcp->batch and pcp->high should ensure they can cope with
 * those fields changing asynchronously (acording the the above rule).
 *
 * mutex_is_locked(&pcp_batch_high_lock) required when calling this function
 * outside of boot time (or some other assurance that no concurrent updaters
 * exist).
 */
static void pageset_update(struct dsnvm_per_cpu_pages *pcp,
			   unsigned long high, unsigned long batch)
{
       /* start with a fail safe value for batch */
	pcp->batch = 1;
	smp_wmb();

       /* Update high, then batch, in order */
	pcp->high = high;
	smp_wmb();

	pcp->batch = batch;
}

static void pageset_set_batch_and_high(struct dsnvm_per_cpu_pageset *p, unsigned long batch)
{
	/* why 6 times of batch? */
	pageset_update(&p->pcp, 6 * batch, max(1UL, 1 * batch));
}

/*
 * Free [start_dsnvm_pfn, end_dsnvm_pfn] pages into buddy allocator
 * This is called at initilization stage to push all usable pages into buddy.
 */
static void __free_pages_all_early(unsigned long start, unsigned long end)
{
	int order;
	struct dsnvm_page *page;

	while (start < end) {
		order = min(DSNVM_MAX_ORDER - 1UL, __ffs(start));

		while (start + (1UL << order) > end)
			order--;

		page = dsnvm_pfn_to_dsnvm_page(start);

		/* refcount=0, call internal free func */
		___free_dsnvm_pages(page, order);

		start += (1UL << order);
	}
}

static int init_dsnvm_buddy_allocator(void)
{
	int cpu, order;

	buddy = kzalloc(sizeof(*buddy), GFP_KERNEL);
	if (!buddy)
		return -ENOMEM;

	/* The first page after metadata area (dsnvm_pfn, not pfn!)
	 * Note that it has been roundup to DSNVM_MAX_ORDER_NR_PAGES */
	buddy->start_dsnvm_pfn = dsnvm_nr_pages_metadata;

	/* Only manage usable NVM pages */
	/* Note that it has been rounddown to DSNVM_MAX_ORDER_NR_PAGES */
	buddy->nr_pages = dsnvm_nr_pages_usable;

	pr_info("Buddy Allocator: start_dsnvm_pfn: %lu, nr_pages: %lu",
		buddy->start_dsnvm_pfn, buddy->nr_pages);

	spin_lock_init(&buddy->lock);

	/* Initialize per-cpu page lists: */
	buddy->pageset = alloc_percpu(struct dsnvm_per_cpu_pageset);
	for_each_online_cpu(cpu) {
		struct dsnvm_per_cpu_pageset *pageset;
		struct dsnvm_per_cpu_pages *pcp;

		pageset = per_cpu_ptr(buddy->pageset, cpu);
		pcp = &pageset->pcp;

		pcp->count = 0;
		INIT_LIST_HEAD(&pcp->lists);

		/* Set pcp->batch and pcp->high */
		pageset_set_batch_and_high(pageset, dsnvm_buddy_batchsize(buddy));
	}

	/* Initialize free-area lists: */
	for (order = 0; order < DSNVM_MAX_ORDER; order++) {
		INIT_LIST_HEAD(&buddy->free_area[order].free_list);
		buddy->free_area[order].nr_free = 0;
	}

	/* Alright, 'free' all usable NVM pages into buddy allocator: */
	__free_pages_all_early(buddy->start_dsnvm_pfn,
			buddy->start_dsnvm_pfn + buddy->nr_pages);

	return 0;
}

static void destroy_dsnvm_buddy_allocator(void)
{
	kfree(buddy);
}

/*
 * About 1% of whole NVM pages are used for storing metadata used by this
 * allocator. All NVM pages after those metadata pages are free game. :)
 *
 * Also note that, NVM allocator is initialized when dsnvm fs is mounted.
 * Becasue only at mounting time we can know the whole NVM physical range.
 * and it will be destroyed at umounting time. Hence always reset variables
 * properly to avoid getting stale stuffs.
 */
int init_dsnvm_allocator(struct dsnvm_sb_info *sbi)
{
	unsigned long bytes, dsnvm_pfn;
	struct dsnvm_page *page;
	int ret;

	dsnvm_pfn_offset = sbi->phys_addr >> PAGE_SHIFT;
	dsnvm_phys_addr = sbi->phys_addr;
	dsnvm_virt_addr = sbi->virt_addr;
	dsnvm_nr_pages = sbi->nr_pages;

	/* Reserve nvm pages for dsnvm_page array */
	bytes = dsnvm_nr_pages * sizeof(struct dsnvm_page);
	dsnvm_nr_pages_map = DIV_ROUND_UP(bytes, DSNVM_PAGE_SIZE);
	dsnvm_map = (struct dsnvm_page *)dsnvm_virt_addr;

	for_each_dsnvm_page (dsnvm_pfn, page) {
		memset(page, 0, sizeof(*page));
		INIT_LIST_HEAD(&page->lru);
		INIT_LIST_HEAD(&page->rmap);
	}

	BUILD_BUG_ON(DSNVM_MAX_FILE_SIZE % DSNVM_PAGE_SIZE);
	BUILD_BUG_ON(DSNVM_MAX_FILE_SIZE % DR_SIZE);
	BUILD_BUG_ON(NR_DSNVM_FILE < 1);

	/* Reserve nvm pages for dsnvm_client_file */
	bitmap_clear(filemap_slot, 0,  NR_DSNVM_FILE);
	bytes = NR_DSNVM_FILE * sizeof(struct dsnvm_client_file);
	dsnvm_nr_pages_filemap = DIV_ROUND_UP(bytes, DSNVM_PAGE_SIZE);
	dsnvm_filemap = (struct dsnvm_client_file *)(
			dsnvm_virt_addr +
			dsnvm_nr_pages_map * DSNVM_PAGE_SIZE);

	/* Reserve nvm pages for dsnvm_log_record */
	bitmap_clear(logmap_slot, 0, DSNVM_MAX_LOG_RECORDS);
	bytes = DSNVM_MAX_LOG_RECORDS * sizeof(struct dsnvm_log_record);
	dsnvm_nr_pages_logmap = DIV_ROUND_UP(bytes, DSNVM_PAGE_SIZE);
	dsnvm_logmap = (struct dsnvm_log_record *)(
			dsnvm_virt_addr +
			dsnvm_nr_pages_map * DSNVM_PAGE_SIZE +
			dsnvm_nr_pages_filemap * DSNVM_PAGE_SIZE);

	/* Reserve nvm pages for on_region_info */
	bitmap_clear(onmap_slot, 0, DSNVM_MAX_ON_REGION_INFO);
	bytes = DSNVM_MAX_ON_REGION_INFO * sizeof(struct on_region_info);
	dsnvm_nr_pages_onmap = DIV_ROUND_UP(bytes, DSNVM_PAGE_SIZE);
	dsnvm_onmap = (struct on_region_info *)(
			dsnvm_virt_addr +
			dsnvm_nr_pages_map * DSNVM_PAGE_SIZE +
			dsnvm_nr_pages_filemap * DSNVM_PAGE_SIZE +
			dsnvm_nr_pages_logmap * DSNVM_PAGE_SIZE);

	/* Reserve nvm pages for replica_region_info */
	bitmap_clear(replicamap_slot, 0, DSNVM_MAX_REPLICA_REGION_INFO);
	bytes = DSNVM_MAX_REPLICA_REGION_INFO * sizeof(struct replica_region_info);
	dsnvm_nr_pages_replicamap = DIV_ROUND_UP(bytes, DSNVM_PAGE_SIZE);
	dsnvm_replicamap = (struct replica_region_info *)(
			dsnvm_virt_addr +
			dsnvm_nr_pages_map * DSNVM_PAGE_SIZE +
			dsnvm_nr_pages_filemap * DSNVM_PAGE_SIZE +
			dsnvm_nr_pages_logmap * DSNVM_PAGE_SIZE +
			dsnvm_nr_pages_onmap * DSNVM_PAGE_SIZE);

	/* Calculate how many nvm pages are still usable */
	dsnvm_nr_pages_metadata = dsnvm_nr_pages_map +
				  dsnvm_nr_pages_filemap + dsnvm_nr_pages_logmap +
				  dsnvm_nr_pages_onmap + dsnvm_nr_pages_replicamap;

	/*
	 * FAT NOTE:
	 *
	 * Roundup and Rounddown to make buddy allocator's life easier.
	 */

	dsnvm_nr_pages_metadata = round_up(dsnvm_nr_pages_metadata, DSNVM_MAX_ORDER_NR_PAGES);
	pr_info("After roundup, dsnvm_nr_pages_metadata = %lu", dsnvm_nr_pages_metadata);

	dsnvm_nr_pages_usable = dsnvm_nr_pages - dsnvm_nr_pages_metadata;
	dsnvm_nr_pages_usable = round_down(dsnvm_nr_pages_usable, DSNVM_MAX_ORDER_NR_PAGES);
	pr_info("After rounddown, dsnvm_nr_pages_usable = %lu", dsnvm_nr_pages_usable);

	dsnvm_usable_phys_addr = dsnvm_phys_addr + dsnvm_nr_pages_metadata * DSNVM_PAGE_SIZE;
	dsnvm_usable_virt_addr = dsnvm_virt_addr + dsnvm_nr_pages_metadata * DSNVM_PAGE_SIZE;

	sbi->nr_pages_map = dsnvm_nr_pages_map;
	sbi->nr_pages_metadata = dsnvm_nr_pages_metadata;
	sbi->nr_pages_usable = dsnvm_nr_pages_usable;
	sbi->usable_phys_addr = dsnvm_usable_phys_addr;
	sbi->usable_virt_addr = dsnvm_usable_virt_addr;

	ret = init_dsnvm_buddy_allocator();
	if (ret)
		return ret;

	ret = init_dsnvm_rmap_cache();
	if (ret) {
		destroy_dsnvm_buddy_allocator();
		return ret;
	}

	ret = init_dsnvm_wait_table(dsnvm_nr_pages);
	if (ret) {
		destroy_dsnvm_buddy_allocator();
		destroy_dsnvm_rmap_cache();
		return ret;
	}

	ret = init_dsnvm_kswapd();
	if (ret) {
		destroy_dsnvm_buddy_allocator();
		destroy_dsnvm_wait_table();
		destroy_dsnvm_rmap_cache();
		return ret;
	}

	return 0;
}

void destroy_dsnvm_allocator(void)
{
	/*
	 * Make sure kswapd is out, so it will not touch any
	 * ioremapped NVM area, which will bring kernel panic.
	 */
	stop_dsnvm_kswapd();
	mdelay(10);
	wakeup_dsnvm_kswapd();
	mdelay(10);
	barrier();

	destroy_dsnvm_buddy_allocator();

	destroy_dsnvm_wait_table();
	destroy_dsnvm_rmap_cache();
}

/*
 * dsnvm_client_file array management
 */

struct dsnvm_client_file *alloc_dsnvm_file(void)
{
	int i, j, bit;
	struct dsnvm_client_file *f;
	struct dn_region_info *dr;

	spin_lock(&dsnvm_filemap_lock);
	bit = find_first_zero_bit(filemap_slot, NR_DSNVM_FILE);
	if (unlikely(bit == NR_DSNVM_FILE)) {
		DSNVM_WARN("Max NR_DSNVM_FILE: %d is running out\n",
			NR_DSNVM_FILE);
		spin_unlock(&dsnvm_filemap_lock);
		return NULL;
	}
	set_bit(bit, filemap_slot);
	spin_unlock(&dsnvm_filemap_lock);

	f = dsnvm_filemap + bit;
	memset(f, 0, sizeof(struct dsnvm_client_file));

	/* Init this structure and flush back */
	spin_lock_init(&f->lock);
	for (i = 0; i < DSNVM_MAX_REGIONS; i++) {
		dr = &(f->regions[i]);
		spin_lock_init(&dr->region_lock);
		kref_init(&dr->region_ref);
		INIT_HLIST_NODE(&dr->hlist);
		for (j = 0; j < DR_PAGE_NR; j++) {
			spin_lock_init(&dr->page_lock[j]);
		}
	}
	return f;
}

void free_dsnvm_file(struct dsnvm_client_file *f)
{
	unsigned int bit;

	if (WARN_ON(!f))
		return;

	bit = (unsigned int)(f - dsnvm_filemap);
	if (unlikely(bit >= NR_DSNVM_FILE)) {
		DSNVM_BUG();
		return;
	}

	/* Clear this structure and flush back */
	spin_lock(&dsnvm_filemap_lock);
	clear_bit(bit, filemap_slot);

	/* MUST do this with lock held, since this slot might be
	 * allocated immediately after releasing the lock. */
	memset(f, 0,  sizeof(*f));
	dsnvm_flush_buffer(f, sizeof(*f));
	spin_unlock(&dsnvm_filemap_lock);
}

/*
 * DSNVM Redo Log Management
 *
 * Use: echo 32 > /proc/dsnvm to enable DSNVM_PRINTK_LOG
 */

struct dsnvm_log_record *alloc_dsnvm_log(int info, int *log_id)
{
	struct dsnvm_log_record *log;
	int bit;

	spin_lock(&dsnvm_logmap_lock);
	bit = find_first_zero_bit(logmap_slot, DSNVM_MAX_LOG_RECORDS);
	if (unlikely(bit == DSNVM_MAX_LOG_RECORDS)) {
		pr_crit("Out of log, adjust");
		spin_unlock(&dsnvm_logmap_lock);
		*log_id = -1;
		return NULL;
	}
	set_bit(bit, logmap_slot);
	spin_unlock(&dsnvm_logmap_lock);

	log = dsnvm_logmap + bit;
	*log_id = bit;

	memset(log, 0, sizeof(*log));

	DSNVM_PRINTK_LOG("Alloc log_id: %d, log_rec: %p, xact_id: %d",
		bit, log, info);

	return log;
}

void free_dsnvm_log(struct dsnvm_log_record *log)
{
	unsigned int bit;

	if (WARN_ON(!log))
		return;

	bit = (unsigned int)(log - dsnvm_logmap);
	if (unlikely(bit >= DSNVM_MAX_LOG_RECORDS)) {
		DSNVM_BUG();
		return;
	}

	DSNVM_PRINTK_LOG("Free log_id: %d, log_rec: %p, xact_id: %d",
		bit, log, log->xact_id);

	spin_lock(&dsnvm_logmap_lock);
	clear_bit(bit, logmap_slot);

	/* MUST do this with lock held, since this slot might be
	 * allocated immediately after releasing the lock. */
	memset(log, 0, sizeof(*log));

	/* Make sure log_id is flushed back first */
	dsnvm_flush_buffer(&log->log_id, sizeof(log->log_id));
	spin_unlock(&dsnvm_logmap_lock);
}

struct dsnvm_log_record *find_log_by_xact_id(int xact_id)
{
	int bit;
	struct dsnvm_log_record *log;

	spin_lock(&dsnvm_logmap_lock);
	for_each_set_bit(bit, logmap_slot, DSNVM_MAX_LOG_RECORDS) {
		log = dsnvm_logmap + bit;
		if (log->xact_id == xact_id) {
			spin_unlock(&dsnvm_logmap_lock);

			DSNVM_PRINTK_LOG("Found log_id: %d, log_rec: %p, xact_id: %d",
				bit, log, xact_id);
			return log;
		}
	}
	spin_unlock(&dsnvm_logmap_lock);
	return NULL;
}

struct dsnvm_log_record *find_log_by_log_id(unsigned int log_id)
{
	struct dsnvm_log_record *log;

	if (log_id >= DSNVM_MAX_LOG_RECORDS)
		return NULL;

	spin_lock(&dsnvm_logmap_lock);
	log = dsnvm_logmap + log_id;
	/* Check if this log is active */
	if (unlikely(!test_bit(log_id, logmap_slot)))
		log = NULL;
	spin_unlock(&dsnvm_logmap_lock);

	return log;
}

/*
 * Replica Region Management
 */

void free_dsnvm_replica_region_info(struct replica_region_info *r)
{
	unsigned int bit;

	if (WARN_ON(!r))
		return;

	bit = (unsigned int)(r - dsnvm_replicamap);
	if (unlikely(bit >= DSNVM_MAX_REPLICA_REGION_INFO)) {
		DSNVM_BUG();
		return;
	}

	DSNVM_PRINTK("Free REPLICA_REGION dr_no:%lu", r->dr_no);

	spin_lock(&dsnvm_replicamap_lock);
	clear_bit(bit, replicamap_slot);

	/* MUST do this with lock held, since this slot might be
	 * allocated immediately after releasing the lock. */
	memset(r, 0, sizeof(*r));
	dsnvm_flush_buffer(r, sizeof(*r));
	spin_unlock(&dsnvm_replicamap_lock);
}

struct replica_region_info *alloc_dsnvm_replica_region_info(void)
{
	int i, bit;
	struct replica_region_info *r;

	spin_lock(&dsnvm_replicamap_lock);
	bit = find_first_zero_bit(replicamap_slot, DSNVM_MAX_REPLICA_REGION_INFO);
	if (unlikely(bit == DSNVM_MAX_REPLICA_REGION_INFO)) {
		DSNVM_WARN("DSNVM_MAX_REPLICA_REGION_INFO: %d is running out\n",
			DSNVM_MAX_REPLICA_REGION_INFO);
		spin_unlock(&dsnvm_replicamap_lock);
		return NULL;
	}
	set_bit(bit, replicamap_slot);
	spin_unlock(&dsnvm_replicamap_lock);

	r = dsnvm_replicamap + bit;

	/* Init and flush back */
	memset(r, 0, sizeof(*r));
	spin_lock_init(&r->region_lock);
	kref_init(&r->region_ref);
	INIT_HLIST_NODE(&r->hlist);
	for (i = 0; i < DR_PAGE_NR; i++) {
		spin_lock_init(&r->page_lock[i]);
	}
	return r;
}

/*
 * ON Region Management
 */

void free_dsnvm_on_region_info(struct on_region_info *r)
{
	unsigned int bit;

	if (WARN_ON(!r))
		return;

	bit = (unsigned int)(r - dsnvm_onmap);
	if (unlikely(bit >= DSNVM_MAX_ON_REGION_INFO)) {
		DSNVM_BUG();
		return;
	}

	DSNVM_PRINTK("Free ON_REGION dr_no %lu", r->dr_no);

	spin_lock(&dsnvm_onmap_lock);
	clear_bit(bit, onmap_slot);

	/* MUST do this with lock held, since this slot might be
	 * allocated immediately after releasing the lock. */
	memset(r, 0, sizeof(*r));
	dsnvm_flush_buffer(r, sizeof(*r));
	spin_unlock(&dsnvm_onmap_lock);
}

struct on_region_info *alloc_dsnvm_on_region_info(void)
{
	int i, bit;
	struct on_region_info *r;

	spin_lock(&dsnvm_onmap_lock);
	bit = find_first_zero_bit(onmap_slot, DSNVM_MAX_ON_REGION_INFO);
	if (unlikely(bit >= DSNVM_MAX_ON_REGION_INFO)) {
		DSNVM_WARN("DSNVM_MAX_ON_REGION_INFO: %d is running out\n ",
			DSNVM_MAX_ON_REGION_INFO);
		spin_unlock(&dsnvm_onmap_lock);
		return NULL;
	}
	set_bit(bit, onmap_slot);
	spin_unlock(&dsnvm_onmap_lock);

	r = dsnvm_onmap + bit;

	/* Init and flush back */
	memset(r, 0, sizeof(*r));
	spin_lock_init(&r->region_lock);
	kref_init(&r->region_ref);
	INIT_HLIST_NODE(&r->hlist);
	for (i = 0; i < DR_PAGE_NR; i++) {
		spin_lock_init(&r->page_lock[i]);
	}
	return r;
}
