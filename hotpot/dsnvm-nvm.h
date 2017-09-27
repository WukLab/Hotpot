/*
 * Distributed Shared NVM
 *
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * This header file describes everything about NVM management.
 */

#ifndef _INCLUDE_DSNVM_NVMM_H_
#define _INCLUDE_DSNVM_NVMM_H_

#include <linux/wait.h>
#include <linux/hash.h>
#include <linux/sched.h>
#include <linux/kernel.h>

#define DSNVM_MAX_ORDER			3
#define DSNVM_MAX_ORDER_NR_PAGES	(1 << (DSNVM_MAX_ORDER - 1))

enum dsnvm_buddy_stat_item {
	NR_FREE_DSNVM_PAGES,

	NR_DSNVM_BUDDY_STATS
};

struct dsnvm_per_cpu_pages {
	/* NR of pages in the list */
	int count;

	/*
	 * It is the number of total pages in each zone that a hot per cpu
	 * pagelist can have before it gets flushed back to buddy allocator.
	 */
	int high;

	/* Chunk size for buddy add/remove */
	int batch;

	struct list_head lists;
};

struct dsnvm_per_cpu_pageset {
	struct dsnvm_per_cpu_pages pcp;
};

struct dsnvm_free_area {
	struct list_head free_list;
	unsigned long nr_free;
};

struct dsnvm_buddy {
	unsigned long start_dsnvm_pfn;
	unsigned long nr_pages;
	struct dsnvm_per_cpu_pageset __percpu *pageset;

	/* free areas of different sizes */
	struct dsnvm_free_area free_area[DSNVM_MAX_ORDER];

	/* buddy statistics */
	atomic_long_t	vm_stat[NR_DSNVM_BUDDY_STATS];

	/* Primarily protects free_area */
	spinlock_t lock;
};

static inline void mod_buddy_stat(struct dsnvm_buddy *dsnvm_buddy,
			enum dsnvm_buddy_stat_item item, long delta)
{
	atomic_long_add(delta, &dsnvm_buddy->vm_stat[item]);
}

extern struct dsnvm_buddy *buddy;

struct dsnvm_sb_info;

/*
 * Each NVM page in the system has a struct dsnvm_page associated with
 * it to keep track of whatever it is we are using the dsnvm page for
 * at the moment. Note that we have no way to track which tasks are using
 * a page, though rmap can tell us what PTEs are mapping it.
 */
struct dsnvm_page {
	/* First double word block */
	unsigned long flags;		/* Atomic flags.
					 * See dsnvm_page_flags below.
					 */

	atomic_t mapcount;		/* Count of ptes mapping in mms.
					 * 0  means no pte references this page frame
					 * 1  means this page frame is non-shared
					 * >1 means this page frame is shared
					 */

	atomic_t refcount;		/* Reference count
					 * Keep page safe if someone is still
					 * using the page while another one
					 * is trying to free it.
					 */

	/* Second double word block */
	struct list_head lru;		/* Either on active or inactive list if
					 * LRU flag is set.
					 * Note that this field is used elsewhere
					 * whenever page is in a list.
					 */

	/* Third double word block */
	struct list_head rmap;		/* Reverse mapping
					 * List of PTEs that point to this page.
					 */

	unsigned long private;		/* Reverse linking to replica_region_info
					 * This is valid iff PG_replica is true.
					 *
					 * or the page_order of a page if the page
					 * is currently in the free list of buddy
					 * allocator
					 */
};

/*
 * DSNVM_PageBuddy() indicate that the page is free and in the buddy system.
 *
 * The trick is that mapcount is used to store extra info when the page is not
 * currently mapped by userspace program.
 */
#define DSNVM_PAGE_BUDDY_MAPCOUNT_VALUE	(-128)

static inline int DSNVM_PageBuddy(struct dsnvm_page *page)
{
	return atomic_read(&page->mapcount) == DSNVM_PAGE_BUDDY_MAPCOUNT_VALUE;
}

static inline void DSNVM_SetPageBuddy(struct dsnvm_page *page)
{
	atomic_set(&page->mapcount, DSNVM_PAGE_BUDDY_MAPCOUNT_VALUE);
}

static inline void DSNVM_ClearPageBuddy(struct dsnvm_page *page)
{
	atomic_set(&page->mapcount, 0);
}

#define set_dsnvm_page_private(page, v)	((page)->private = (v))
#define dsnvm_page_private(page)	((page)->private)

/*
 * This function returns the order of a free page in the buddy system. In
 * general, page_zone(page)->lock must be held by the caller to prevent the
 * page from being allocated in parallel and returning garbage as the order.
 * If a caller does not hold page_zone(page)->lock, it must guarantee that the
 * page cannot be allocated or merged in parallel. Alternatively, it must
 * handle invalid values gracefully, and use page_order_unsafe() below.
 */
static inline unsigned int dsnvm_page_order(struct dsnvm_page *page)
{
	/* PageBuddy() must be checked by the caller */
	return dsnvm_page_private(page);
}

/*
 * Like page_order(), but for callers who cannot afford to hold the zone lock.
 * PageBuddy() should be checked first by the caller to minimize race window,
 * and invalid values must be handled gracefully.
 *
 * READ_ONCE is used so that if the caller assigns the result into a local
 * variable and e.g. tests it for valid range before using, the compiler cannot
 * decide to remove the variable and inline the page_private(page) multiple
 * times, potentially observing different values in the tests and the actual
 * use of the result.
 */
#define page_order_unsafe(page)		READ_ONCE(dsnvm_page_private(page))

/*
 * Helpers to manipulate @page->mapcount
 */
static inline int dsnvm_page_mapcount(struct dsnvm_page *page)
{
	return atomic_read(&page->mapcount);
}

static inline int dsnvm_page_mapped(struct dsnvm_page *page)
{
	return dsnvm_page_mapcount(page) > 0;
}

static inline void set_dsnvm_page_mapcount(struct dsnvm_page *page, int v)
{
	atomic_set(&page->mapcount, v);
}

/*
 * Helpers to manipulate @page->refcount
 */
static inline void set_dsnvm_page_refcount(struct dsnvm_page *page, int v)
{
	atomic_set(&page->refcount, v);
}

static inline int dsnvm_page_refcount(struct dsnvm_page *page)
{
	return atomic_read(&page->refcount);
}

void dump_dsnvm_page(struct dsnvm_page *page, const unsigned char *reason);

#define DSNVM_BUG_ON_PAGE(cond, page)						\
do {										\
	if (unlikely(cond)) {							\
		dump_dsnvm_page(page, "BUG_ON_PAGE(" __stringify(cond)")");	\
		WARN_ON(1);							\
	}									\
} while (0)

/**
 * put_dsnvm_page_testzero	-	Dec ref count
 *
 * Decrement page reference count,
 * return TRUE if it falls to zero.
 */
static inline int put_dsnvm_page_testzero(struct dsnvm_page *page)
{
	DSNVM_BUG_ON_PAGE(atomic_read(&page->refcount) <= 0, page);
	return atomic_dec_and_test(&page->refcount);
}

void put_dsnvm_page(struct dsnvm_page *page);
void put_dsnvm_page_pfn(unsigned long pfn);

/**
 * get_dsnvm_page	-	Increment page reference count
 *
 * Note that getting a DSNVM page requires that the page was already
 * allocated by buddy allocator, which means @refcount >= 1.
 */
static inline void get_dsnvm_page(struct dsnvm_page *page)
{
	DSNVM_BUG_ON_PAGE(atomic_read(&page->refcount) <= 0, page);
	atomic_inc(&page->refcount);
}

/**
 * get_dsnvm_page_unless_zero
 *
 * Try to dec page refcount unless the page has a ref count of zero.
 * Return FALSE if that is the case.
 */
static inline int get_dsnvm_page_unless_zero(struct dsnvm_page *page)
{
	return atomic_inc_not_zero(&page->refcount);
}

/*
 * Okay, it is dangerous to point to the original page table entry. But it
 * should be fine in our context, because page table pages will not be freed
 * (I guess) and its position never change.
 *
 * Not sure if this file-mapped vma will be splitted or merged with other vma.
 * We may need vma to flush TLB and have the opportunity to get locked ptep.
 */
struct dsnvm_rmap {
	pte_t *page_table;
	struct vm_area_struct *vma;
	unsigned long address;
	struct list_head next;
};

enum dsnvm_page_flags {
	DSNVM_PG_locked,		/* Page is locked. Don't touch. */
	DSNVM_PG_committed,		/* Page is committed */
	DSNVM_PG_accessed,		/* Page has been accessed */
	DSNVM_PG_dirty,			/* Page has been written to */
	DSNVM_PG_lru,			/* Page is in lru list */
	DSNVM_PG_active,		/* Page is in lru active list */
	DSNVM_PG_unevictable,		/* Page is "unevictable" */
	DSNVM_PG_inxact,		/* This is a copied page for a transaction */
	DSNVM_PG_replica,		/* This is a replica page */
	DSNVM_PG_private,		/* The private field is meaningful */
	DSNVM_PG_owner,

	__NR_DSNVM_PAGE_FLAGS
};

#define TEST_DSNVM_PAGE_FLAG(uname, lname)					\
static inline int DSNVM_Page##uname(const struct dsnvm_page *page)		\
{										\
	return test_bit(DSNVM_PG_##lname, &page->flags);			\
}

#define SET_DSNVM_PAGE_FLAG(uname, lname)					\
static inline void DSNVM_SetPage##uname(struct dsnvm_page *page)		\
{										\
	set_bit(DSNVM_PG_##lname, &page->flags);				\
}

#define CLEAR_DSNVM_PAGE_FLAG(uname, lname)					\
static inline void DSNVM_ClearPage##uname(struct dsnvm_page *page)		\
{										\
	clear_bit(DSNVM_PG_##lname, &page->flags);				\
}

#define __SET_DSNVM_PAGE_FLAG(uname, lname)					\
static inline void __DSNVM_SetPage##uname(struct dsnvm_page *page)		\
{										\
	__set_bit(DSNVM_PG_##lname, &page->flags);				\
}

#define __CLEAR_DSNVM_PAGE_FLAG(uname, lname)					\
static inline void __DSNVM_ClearPage##uname(struct dsnvm_page *page)		\
{										\
	__clear_bit(DSNVM_PG_##lname, &page->flags);				\
}

#define DSNVM_TEST_SET_FLAG(uname, lname)					\
static inline int DSNVM_TestSetPage##uname(struct dsnvm_page *page)		\
{										\
	return test_and_set_bit(DSNVM_PG_##lname, &page->flags);		\
}

#define DSNVM_TEST_CLEAR_FLAG(uname, lname)					\
static inline int DSNVM_TestClearPage##uname(struct dsnvm_page *page)		\
{										\
	return test_and_clear_bit(DSNVM_PG_##lname, &page->flags);		\
}

#define __DSNVM_TEST_SET_FLAG(uname, lname)					\
static inline int __DSNVM_TestSetPage##uname(struct dsnvm_page *page)		\
{										\
	return __test_and_set_bit(DSNVM_PG_##lname, &page->flags);		\
}

#define __DSNVM_TEST_CLEAR_FLAG(uname, lname)					\
static inline int __DSNVM_TestClearPage##uname(struct dsnvm_page *page)		\
{										\
	return __test_and_clear_bit(DSNVM_PG_##lname, &page->flags);		\
}

#define DSNVM_PAGE_FLAG(uname, lname)						\
	TEST_DSNVM_PAGE_FLAG(uname, lname)					\
	SET_DSNVM_PAGE_FLAG(uname, lname)					\
	CLEAR_DSNVM_PAGE_FLAG(uname, lname)					\
	__SET_DSNVM_PAGE_FLAG(uname, lname)					\
	__CLEAR_DSNVM_PAGE_FLAG(uname, lname)					\
	DSNVM_TEST_SET_FLAG(uname, lname)					\
	DSNVM_TEST_CLEAR_FLAG(uname, lname)					\
	__DSNVM_TEST_SET_FLAG(uname, lname)					\
	__DSNVM_TEST_CLEAR_FLAG(uname, lname)

DSNVM_PAGE_FLAG(Locked, locked)
DSNVM_PAGE_FLAG(Committed, committed)
DSNVM_PAGE_FLAG(Accessed, accessed)
DSNVM_PAGE_FLAG(Dirty, dirty)
DSNVM_PAGE_FLAG(LRU, lru)
DSNVM_PAGE_FLAG(Active, active)
DSNVM_PAGE_FLAG(Unevictable, unevictable)
DSNVM_PAGE_FLAG(Inxact, inxact)
DSNVM_PAGE_FLAG(Replica, replica)
DSNVM_PAGE_FLAG(Private, private)
DSNVM_PAGE_FLAG(Owner, owner)

extern int sleep_on_dsnvm_page(void *unused);
extern wait_queue_head_t *dsnvm_page_waitqueue(struct dsnvm_page *page);
/* externed for proc */
extern unsigned long wait_table_hash_nr_entries;
extern unsigned long wait_table_bits;

/**
 * __lock_page
 * @page: the page to lock
 *
 * This function gets a lock on the page.
 * Assuming we need to sleep to get it.
 */
static inline void __lock_dsnvm_page(struct dsnvm_page *page)
{
	DEFINE_WAIT_BIT(wait, &page->flags, DSNVM_PG_locked);

	__wait_on_bit_lock(dsnvm_page_waitqueue(page), &wait,
			sleep_on_dsnvm_page, TASK_UNINTERRUPTIBLE);
}

static inline void wake_up_dsnvm_page(struct dsnvm_page *page, int bit)
{
	__wake_up_bit(dsnvm_page_waitqueue(page), &page->flags, bit);
}

/**
 * trylock_dsnvm_page
 * @page: the page to lock
 *
 * Try to lock a dsnvm page, return 1 on success.
 */
static inline int trylock_dsnvm_page(struct dsnvm_page *page)
{
	return (likely(!DSNVM_TestSetPageLocked(page)));
}

static inline void lock_dsnvm_page(struct dsnvm_page *page)
{
	might_sleep();
	if (!trylock_dsnvm_page(page))
		__lock_dsnvm_page(page);
}

/**
 * unlock_dsnvm_page
 * @page: the page to unlock
 *
 * Unlocks the page and wakes up sleepers in ___wait_on_page_locked().
 * The mb is necessary to enforce ordering between the clear_bit and the read
 * of the waitqueue (to avoid SMP races with a parallel wait_on_page_locked()).
 */
static inline void unlock_dsnvm_page(struct dsnvm_page *page)
{
	WARN_ON(!DSNVM_PageLocked(page));

	barrier();
	DSNVM_ClearPageLocked(page);
	smp_mb__after_clear_bit();
	wake_up_dsnvm_page(page, DSNVM_PG_locked);
}

/* The dsnvm_page array */
extern struct dsnvm_page *dsnvm_map;

/*
 * Iterate over all dsnvm pages
 * @dsnvm_pfn: unsigned long dsnvm pfn
 * @page: the dsnvm_page structure
 */
#define for_each_dsnvm_page(dsnvm_pfn, page)				\
	for (dsnvm_pfn = 0, page = dsnvm_map;				\
	     dsnvm_pfn < dsnvm_nr_pages;				\
	     dsnvm_pfn++, page++)

/*
 * Iterate over all usable dsnvm pages
 * @dsnvm_pfn: unsigned long dsnvm pfn
 * @page: the dsnvm_page structure
 */
#define for_each_usable_dsnvm_page(dsnvm_pfn, page)			\
	for (dsnvm_pfn = dsnvm_nr_pages_metadata,			\
	     page = dsnvm_pfn_to_dsnvm_page(dsnvm_nr_pages_metadata);	\
	     dsnvm_pfn < dsnvm_nr_pages;				\
	     dsnvm_pfn++, page++)

/*
 * Caution: Do NOT use any of the following variables out of nvmm.c
 * Except for proc.c, the only reason they are externed.
 */

extern unsigned long dsnvm_pfn_offset;
extern unsigned long dsnvm_phys_addr;
extern unsigned long dsnvm_virt_addr;
extern unsigned long dsnvm_usable_phys_addr;
extern unsigned long dsnvm_usable_virt_addr;

extern unsigned long dsnvm_nr_pages;
extern unsigned long dsnvm_nr_pages_map;
extern unsigned long dsnvm_nr_pages_filemap;
extern unsigned long dsnvm_nr_pages_logmap;
extern unsigned long dsnvm_nr_pages_onmap;
extern unsigned long dsnvm_nr_pages_replicamap;

extern unsigned long dsnvm_nr_pages_metadata;
extern unsigned long dsnvm_nr_pages_usable;

extern struct dsnvm_log_record *dsnvm_logmap;
extern DECLARE_BITMAP(logmap_slot, DSNVM_MAX_LOG_RECORDS);
extern spinlock_t dsnvm_logmap_lock;

extern struct on_region_info *dsnvm_onmap;
extern DECLARE_BITMAP(onmap_slot, DSNVM_MAX_ON_REGION_INFO);
extern spinlock_t dsnvm_onmap_lock;

extern struct replica_region_info *dsnvm_replicamap;
extern DECLARE_BITMAP(replicamap_slot, DSNVM_MAX_REPLICA_REGION_INFO);
extern spinlock_t dsnvm_replicamap_lock;

/*
 *                dsnvm_pfn_offset
 *                     \
 *                      \ |<--   NVM   -->|
 * pfn         0 .........|...............|............. MAX_PFN
 * dsnvm_pfn              0...............dsnvm_nr_pages
 */

/*
 * BIG FAT NOTE:
 * Always check if pfn/dsnvm_pfn/phys/virt belongs to dsnvm, before
 * you call any of the following conversion helpers. Passing address
 * that is part of dsnvm ioremapped area may cause kernel crash.
 */

static inline bool dsnvm_pfn_valid(unsigned long dsnvm_pfn)
{
	if (likely(dsnvm_pfn < dsnvm_nr_pages)) {
		return true;
	}
	return false;
}

static inline bool dsnvm_pfn_metadata(unsigned long dsnvm_pfn)
{
	BUG_ON(!dsnvm_pfn_valid(dsnvm_pfn));
	if (dsnvm_pfn_valid(dsnvm_pfn))
		if (dsnvm_pfn < dsnvm_nr_pages_metadata)
			return true;
	return false;
}

static inline bool dsnvm_pfn_usable(unsigned long dsnvm_pfn)
{
	BUG_ON(!dsnvm_pfn_valid(dsnvm_pfn));
	if (dsnvm_pfn_valid(dsnvm_pfn))
		return !dsnvm_pfn_metadata(dsnvm_pfn);
	return false;
}

static inline unsigned long dsnvm_pfn_to_pfn(unsigned long dsnvm_pfn)
{
	BUG_ON(!dsnvm_pfn_valid(dsnvm_pfn));
	return dsnvm_pfn + dsnvm_pfn_offset;
}

static inline unsigned long pfn_to_dsnvm_pfn(unsigned long pfn)
{
	unsigned long dsnvm_pfn = pfn - dsnvm_pfn_offset;
	BUG_ON(!dsnvm_pfn_valid(dsnvm_pfn));
	return dsnvm_pfn;
}

static inline struct dsnvm_page *dsnvm_pfn_to_dsnvm_page(unsigned long dsnvm_pfn)
{
	BUG_ON(!dsnvm_pfn_valid(dsnvm_pfn));
	return (dsnvm_map + dsnvm_pfn);
}

static inline struct dsnvm_page *pfn_to_dsnvm_page(unsigned long pfn)
{
	unsigned long dsnvm_pfn = pfn_to_dsnvm_pfn(pfn);
	BUG_ON(!dsnvm_pfn_valid(dsnvm_pfn));
	return dsnvm_pfn_to_dsnvm_page(dsnvm_pfn);
}

static inline unsigned long dsnvm_page_to_dsnvm_pfn(struct dsnvm_page *page)
{
	unsigned long dsnvm_pfn = (unsigned long)(page - dsnvm_map);
	BUG_ON(!dsnvm_pfn_valid(dsnvm_pfn));
	return dsnvm_pfn;
}

static inline unsigned long dsnvm_page_to_pfn(struct dsnvm_page *page)
{
	unsigned long dsnvm_pfn = dsnvm_page_to_dsnvm_pfn(page);
	BUG_ON(!dsnvm_pfn_valid(dsnvm_pfn));
	return dsnvm_pfn_to_pfn(dsnvm_pfn);
}

/* Check if pfn falls into NVM pfn range */
static inline bool pfn_is_dsnvm(unsigned long pfn)
{
	unsigned long dsnvm_pfn;
	if (pfn < dsnvm_pfn_offset)
		return false;
	dsnvm_pfn = pfn_to_dsnvm_pfn(pfn);
	return dsnvm_pfn_valid(dsnvm_pfn);
}

/* Check if phys falls into NVM physical address range */
static inline bool phys_is_dsnvm(unsigned long phys)
{
	unsigned long pfn = (phys >> PAGE_SHIFT);
	return pfn_is_dsnvm(pfn);
}

/* Check if kaddr falls into NVM virtual address range */
static inline bool virt_is_dsnvm(unsigned long kaddr)
{
	if (kaddr >= dsnvm_virt_addr)
		if (kaddr < (dsnvm_virt_addr + dsnvm_nr_pages * DSNVM_PAGE_SIZE))
			return true;
	return false;
}

/* return the dsnvm_pfn this kaddr falls into */
static inline unsigned long virt_to_dsnvm_pfn(unsigned long kaddr)
{
	unsigned long dsnvm_pfn = (kaddr - dsnvm_virt_addr) / PAGE_SIZE;
	BUG_ON(!dsnvm_pfn_valid(dsnvm_pfn));
	return dsnvm_pfn;
}

static inline struct dsnvm_page *virt_to_dsnvm_page(unsigned long kaddr)
{
	unsigned long dsnvm_pfn = virt_to_dsnvm_pfn(kaddr);
	BUG_ON(!dsnvm_pfn_valid(dsnvm_pfn));
	return dsnvm_pfn_to_dsnvm_page(dsnvm_pfn);
}

/* return the base address of the page this dsnvm_pfn points to */
static inline unsigned long dsnvm_pfn_to_virt(unsigned long dsnvm_pfn)
{
	BUG_ON(!dsnvm_pfn_valid(dsnvm_pfn));
	return dsnvm_virt_addr + dsnvm_pfn * PAGE_SIZE;
}

static inline unsigned long pfn_to_dsnvm_virt(unsigned long pfn)
{
	unsigned long dsnvm_pfn = pfn_to_dsnvm_pfn(pfn);
	BUG_ON(!dsnvm_pfn_valid(dsnvm_pfn));
	return dsnvm_pfn_to_virt(dsnvm_pfn);
}

static inline unsigned long dsnvm_page_to_virt(struct dsnvm_page *page)
{
	unsigned long dsnvm_pfn = dsnvm_page_to_dsnvm_pfn(page);
	BUG_ON(!dsnvm_pfn_valid(dsnvm_pfn));
	return dsnvm_pfn_to_virt(dsnvm_pfn);
}

void free_dsnvm_pages_list(struct list_head *page_list);

int init_dsnvm_allocator(struct dsnvm_sb_info *sbi);
void destroy_dsnvm_allocator(void);

/*
 * Buddy allocator
 */

struct dsnvm_page *__alloc_dsnvm_pages(unsigned int order);
void *alloc_dsnvm_pages(unsigned int order);
void *alloc_dsnvm_page(void);
unsigned long alloc_dsnvm_page_pfn(void);

void __free_dsnvm_pages(struct dsnvm_page *page, unsigned int order);
void free_dsnvm_pages(void *addr, unsigned int order);
void free_dsnvm_page(void *addr);
void free_dsnvm_page_pfn(unsigned long pfn);
void free_hot_cold_dsnvm_page(struct dsnvm_page *page, bool cold);
void free_hot_cold_dsnvm_page_list(struct list_head *list, bool cold);

/*
 * Page replacement related
 */

static inline int current_is_dsnvm_kswapd(void)
{
	return current->flags & PF_KSWAPD;
}

/**
 * lru_to_dsnvm_page
 * @_head: the head of LRU list
 *
 * Grab the page at the TAIL of the LRU list.
 * We have a FIFO feeling.
 */
#define lru_to_dsnvm_page(_head) \
	(list_entry((_head)->prev, struct dsnvm_page, lru))

#ifdef CONFIG_DSNVM_SWAP
extern atomic_t nr_active;
extern atomic_t nr_inactive;

/* direct reclaiming */
unsigned long try_to_free_dsnvm_pages(void);

int init_dsnvm_kswapd(void);
void stop_dsnvm_kswapd(void);
void wakeup_dsnvm_kswapd(void);

void lru_remove_page(struct dsnvm_page *page);
void lru_add_active(struct dsnvm_page *page);
void lru_add_inactive(struct dsnvm_page *page);

int dsnvm_page_accessed(struct dsnvm_page *page);
void mark_dsnvm_page_accessed(struct dsnvm_page *page);
void activate_dsnvm_page(struct dsnvm_page *page);
void deactivate_dsnvm_page(struct dsnvm_page *page);
#else
/* direct reclaiming */
static inline unsigned long try_to_free_dsnvm_pages(void){return 0;}

static inline int init_dsnvm_kswapd(void){return 0;}
static inline void stop_dsnvm_kswapd(void){}
static inline void wakeup_dsnvm_kswapd(void){}

static inline void lru_remove_page(struct dsnvm_page *page){}
static inline void lru_add_active(struct dsnvm_page *page){}
static inline void lru_add_inactive(struct dsnvm_page *page){}

static inline int dsnvm_page_accessed(struct dsnvm_page *page){return 0;}
static inline void mark_dsnvm_page_accessed(struct dsnvm_page *page){}
static inline void activate_dsnvm_page(struct dsnvm_page *page){}
static inline void deactivate_dsnvm_page(struct dsnvm_page *page){}
#endif

/*
 * Reserve mapping related
 */

enum dsnvm_swap_status {
	DSNVM_SWAP_FAIL,
	DSNVM_SWAP_AGAIN,
	DSNVM_SWAP_SUCCESS,
};

int init_dsnvm_rmap_cache(void);
void destroy_dsnvm_rmap_cache(void);
enum dsnvm_swap_status dsnvm_try_to_unmap(struct dsnvm_page *page);
int dsnvm_page_add_rmap(struct dsnvm_page *, pte_t *, struct vm_area_struct *);
void dsnvm_page_remove_rmap(struct dsnvm_page *, pte_t *, struct vm_area_struct *);

/*
 * file array related
 */

struct dsnvm_client_file *alloc_dsnvm_file(void);
void free_dsnvm_file(struct dsnvm_client_file *);

/*
 * redo-log array related
 */
struct dsnvm_log_record *alloc_dsnvm_log(int info, int *log_id);
void free_dsnvm_log(struct dsnvm_log_record *log);
struct dsnvm_log_record *find_log_by_xact_id(int xact_id);
struct dsnvm_log_record *find_log_by_log_id(unsigned int log_id);

/*
 * replica region array related
 */
struct replica_region_info;
void free_dsnvm_replica_region_info(struct replica_region_info *);
struct replica_region_info *alloc_dsnvm_replica_region_info(void);

/*
 * on region array related
 */
struct on_region_info;
void free_dsnvm_on_region_info(struct on_region_info *);
struct on_region_info *alloc_dsnvm_on_region_info(void);

#endif /* _INCLUDE_DSNVM_NVMM_H_ */
