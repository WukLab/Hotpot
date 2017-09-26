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
 * Thie file describes LRU list mgmt for DSNVM page eviction
 */

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

#include "dsnvm.h"

#ifdef CONFIG_DSNVM_SWAP
static DEFINE_SPINLOCK(lru_lock);
static LIST_HEAD(active_list);
static LIST_HEAD(inactive_list);
atomic_t nr_active = ATOMIC_INIT(0);
atomic_t nr_inactive = ATOMIC_INIT(0);

static struct task_struct *__dsnvm_kswapd;
static wait_queue_head_t dsnvm_kswapd_wait;

static inline void add_dsnvm_page_to_active_list(struct dsnvm_page *page)
{
	list_add(&page->lru, &active_list);
	atomic_inc(&nr_active);
}

static inline void add_dsnvm_page_to_inactive_list(struct dsnvm_page *page)
{
	list_add(&page->lru, &inactive_list);
	atomic_inc(&nr_inactive);
}

static inline void del_dsnvm_page_from_active_list(struct dsnvm_page *page)
{
	list_del(&page->lru);
	atomic_dec(&nr_active);
}

static inline void del_dsnvm_page_from_inactive_list(struct dsnvm_page *page)
{
	list_del(&page->lru);
	atomic_dec(&nr_inactive);
}

/*
 * Enter with NO lock held.
 */
static __always_inline void
__put_single_dsnvm_page(struct dsnvm_page *page)
{
	if (DSNVM_PageLRU(page)) {
		spin_lock_irq(&lru_lock);

		/*
		 * When this function is called, the @page->refcount is 0.
		 * Which means this page can not be isolated from LRU list.
		 * Hence the main purpose of this function, is to serialize
		 * part of dsnvm_isolate_lru_pages().
		 */
		DSNVM_BUG_ON_PAGE(!DSNVM_PageLRU(page), page);

		if (DSNVM_PageActive(page)) {
			del_dsnvm_page_from_active_list(page);
			DSNVM_ClearPageActive(page);
		} else
			del_dsnvm_page_from_inactive_list(page);
		DSNVM_ClearPageLRU(page);
		spin_unlock_irq(&lru_lock);
	}

	free_hot_cold_dsnvm_page(page, false);
}
#else
static inline void __put_single_dsnvm_page(struct dsnvm_page *page)
{
	free_hot_cold_dsnvm_page(page, false);
}
#endif /* CONFIG_DSNVM_SWAP */

/**
 * put_dsnvm_page	-	Put a single dsnvm page (order = 0)
 *
 * Drop a reference of the page, free the page if it fell to 0.
 * Remove the page from LRU list if it is in.
 *
 * The main difference between put_dsnvm_page() and free_dsnvm_page()
 * is that:
 *	put_dsnvm_page() will check LRU and handle it properly.
 *	free_dsnvm_page() will NOT check LRU
 *
 * So basically, the usage of these functions are:
 *	alloc_dsnvm_page()	|	alloc_dsnvm_page()
 *				|
 *				|	lru_add_active/inactive()
 *				|
 *	..			|	..
 *	do sth with page	|	do sth with page
 *	..			|	..
 *				|
 *	free_dsnvm_page()	|	put_dsnvm_page()
 */
void put_dsnvm_page(struct dsnvm_page *page)
{
	if (put_dsnvm_page_testzero(page))
		__put_single_dsnvm_page(page);
}

void put_dsnvm_page_pfn(unsigned long pfn)
{
	if (unlikely(!pfn_is_dsnvm(pfn)))
		return;

	put_dsnvm_page(pfn_to_dsnvm_page(pfn));
}

#ifdef CONFIG_DSNVM_SWAP
/**
 * lru_remove_page
 * @page: the page to remove
 *
 * Remove a page from LRU list
 */
void lru_remove_page(struct dsnvm_page *page)
{
	/*
	 * A previous COW page is promoted to ON_REGION page.
	 * Unfortunately, the page was isolated from the LRU list at the
	 * same time. What we do is just return, and don't putback the page
	 * to LRU list later.
	 */
	if (unlikely(!DSNVM_PageLRU(page))) {
		if (likely(DSNVM_PageOwner(page)))
			return;
		else
			DSNVM_BUG_ON_PAGE(!DSNVM_PageLRU(page), page);
	}

	spin_lock_irq(&lru_lock);

	if (DSNVM_PageActive(page)) {
		del_dsnvm_page_from_active_list(page);
		DSNVM_ClearPageActive(page);
	} else
		del_dsnvm_page_from_inactive_list(page);

	DSNVM_ClearPageLRU(page);

	spin_unlock_irq(&lru_lock);
}

/**
 * lru_add_active
 * @page: the page to add
 *
 * Add a dsnvm page to active LRU list
 */
void lru_add_active(struct dsnvm_page *page)
{
	DSNVM_BUG_ON_PAGE(DSNVM_PageActive(page) || DSNVM_PageLRU(page), page);

	dump_dsnvm_page(page, "Adding to active lru");

	DSNVM_SetPageLRU(page);
	DSNVM_SetPageActive(page);

	spin_lock_irq(&lru_lock);
	add_dsnvm_page_to_active_list(page);
	spin_unlock_irq(&lru_lock);
}

/**
 * lru_add_inactive
 * @page: the page to add
 *
 * Add a dsnvm page to inactive LRU list
 */
void lru_add_inactive(struct dsnvm_page *page)
{
	DSNVM_BUG_ON_PAGE(DSNVM_PageActive(page) || DSNVM_PageLRU(page), page);

	DSNVM_SetPageLRU(page);

	spin_lock_irq(&lru_lock);
	add_dsnvm_page_to_inactive_list(page);
	spin_unlock_irq(&lru_lock);
}

/**
 * deactivate_dsnvm_page
 * @page: page to deactivate
 *
 * This function hints the reclaimer that @page is a good reclaim candidate.
 * @page is moved to the inactive list to speed up its reclaim. It is moved
 * to the head of the list, rather than the tail.
 */
void deactivate_dsnvm_page(struct dsnvm_page *page)
{
	if (!DSNVM_PageLRU(page))
		return;

	if (DSNVM_PageUnevictable(page))
		return;

	if (dsnvm_page_mapped(page))
		return;

	spin_lock_irq(&lru_lock);
	if (DSNVM_PageActive(page)) {
		del_dsnvm_page_from_active_list(page);
		add_dsnvm_page_to_inactive_list(page);
	}
	DSNVM_ClearPageActive(page);
	DSNVM_ClearPageAccessed(page);
	list_move_tail(&page->lru, &inactive_list);
	spin_unlock_irq(&lru_lock);
}

/**
 * activate_dsnvm_page
 * @page: the LRU page in question
 *
 * This function will move @page from inactive list into
 * active list, and sets the PG_active flag of this page.
 * If @page is currently isolated, then it just returns.
 */
void activate_dsnvm_page(struct dsnvm_page *page)
{
	spin_lock_irq(&lru_lock);
	if (DSNVM_PageLRU(page) && !DSNVM_PageActive(page) &&
			!DSNVM_PageUnevictable(page)) {
		del_dsnvm_page_from_inactive_list(page);
		DSNVM_SetPageActive(page);
		add_dsnvm_page_to_active_list(page);
	}
	spin_unlock_irq(&lru_lock);
}

static __used unsigned long get_page_reverse_dr_no(struct dsnvm_page *page)
{
	struct dsnvm_rmap *rmap;

	list_for_each_entry(rmap, &page->rmap, next) {
		struct vm_area_struct *vma;
		struct dsnvm_client_file *file;
		struct dn_region_info *dr;
		unsigned long vaddr;

		vaddr = rmap->address;
		vma = rmap->vma;
		file = DSNVM_FILE(vma);
		dr = get_dn_region(file, vaddr);

		return dr->dr_no;
	}
	return 0;
}

static void putback_lru_dsnvm_page(struct dsnvm_page *page);

/*
 * Free pages pull from inactive LRU list.
 * Do the unmap if page is mapped.
 * Inform the ON if it is a replica page.
 */
static void free_dsnvm_pages_and_notify(struct list_head *page_list)
{
	int ret;
	struct dsnvm_page *page, *next;
	LIST_HEAD(pages_to_free);

	if (list_empty(page_list))
		return;

	list_for_each_entry_safe(page, next, page_list, lru) {
		if (DSNVM_PageReplica(page)) {
			ret = free_replica_page_notify_on(page);
			if (unlikely(ret)) {
				/* putback to inactive lru */
				__DSNVM_ClearPageActive(page);
				putback_lru_dsnvm_page(page);
				continue;
			} else {
				clear_dsnvm_page_rr_info(page);
				DSNVM_ClearPageReplica(page);
			}
		}

		if (dsnvm_page_mapped(page)) {
			lock_dsnvm_page(page);
			dsnvm_try_to_unmap(page);
			unlock_dsnvm_page(page);
		}

		BUG_ON(DSNVM_PageLRU(page));
		free_hot_cold_dsnvm_page(page, true);
	}
}

/**
 * mark_dsnvm_page_accessed
 * @page: the LRU page in question
 *
 * inactive, unaccessed		->	inactive, accessed
 * inactive, accessed		->	active, unaccessed
 * active, unaccessed		->	active, accessed
 * active, accessed		->	active, accessed
 */
void mark_dsnvm_page_accessed(struct dsnvm_page *page)
{
	if (!DSNVM_PageActive(page) && !DSNVM_PageUnevictable(page) &&
			DSNVM_PageAccessed(page)) {
		/*
		 * If the page is in LRU list, just activate it here.
		 * Otherwise the page was isolated, leave it alone.
		 *
		 * shrink_dsnvm_page_list() might trigger DSNVM_WARN_ON
		 * if we set page active when page is in isolated state.
		 */
		if (DSNVM_PageLRU(page)) {
			activate_dsnvm_page(page);
			DSNVM_ClearPageAccessed(page);
		}
	} else if (!DSNVM_PageAccessed(page)) {
		DSNVM_SetPageAccessed(page);
	}
}

/*
 * Note that we use test_and_clear_bit()
 * So after this func, all involved PTES are cleared.
 */
static __always_inline int dsnvm_page_accessed_one(struct dsnvm_rmap *rmap)
{
	int accessed;
	pte_t *ptep = rmap->page_table;

	accessed = test_and_clear_bit(_PAGE_BIT_ACCESSED,
				(unsigned long *)&ptep->pte);
#ifdef DSNVM_KERNEL_EXPORT_TLB_FLUSH
	if (accessed)
		flush_tlb_page(rmap->vma, rmap->address);
#endif
	return accessed;
}

/**
 * dsnvm_page_accessed
 * @page: the page to test
 *
 * Test if @page is accessed. Quick test_and_clear_accessed for
 * all mappings to this page. Return the number of ptes which
 * accessed this page. Must entry with page lock held.
 */
int dsnvm_page_accessed(struct dsnvm_page *page)
{
	int mapcount = 0;
	int accessed = 0;
	struct dsnvm_rmap *rmap;

	DSNVM_WARN_ON(!DSNVM_PageLocked(page));

	if (dsnvm_page_mapped(page)) {
		list_for_each_entry(rmap, &page->rmap, next) {
			mapcount++;
			accessed += dsnvm_page_accessed_one(rmap);
		}
		DSNVM_WARN_ON(mapcount != dsnvm_page_mapcount(page));
	}
	return accessed;
}

enum dsnvm_page_actions {
	DSNVM_PAGE_RECLAIM,
	DSNVM_PAGE_KEEP,
	DSNVM_PAGE_ACTIVATE,
};

static __always_inline enum dsnvm_page_actions
dsnvm_page_check_accesses(struct dsnvm_page *page)
{
	int accessed_ptes, accessed_page;

	accessed_ptes = dsnvm_page_accessed(page);
	accessed_page = DSNVM_TestClearPageAccessed(page);

	if (accessed_ptes) {
		/*
		 * BIG FAT NOTE:
		 *
		 * All mapped pages are put into inactive LRU list and the
		 * PG_accessed bit is NOT set at begining.
		 *
		 * All mapped pages start out with page table references from
		 * the instantiating fault, so we need to look twice if a mapped
		 * page is used more than once.
		 *
		 * Mark it accessed and spare it for another trip around the
		 * inactive list. Another page table reference before next shrink
		 * will lead to its activation.
		 *
		 * Note: the mark is set for activated pages as well so that
		 * recently deactivated but used pages are quickly recovered.
		 */
		DSNVM_SetPageAccessed(page);

		if (accessed_page || accessed_ptes > 1)
			return DSNVM_PAGE_ACTIVATE;

		return DSNVM_PAGE_KEEP;
	}
	return DSNVM_PAGE_RECLAIM;
}

/**
 * dsnvm_isolate_lru_pages
 * @src:	The LRU list to pull dsnvm pages from
 * @dst:	The temp list to put pages on to.
 * @nr_to_scan:	The number of pages to look through on the list
 * @nr_scanned: The number of pages that were scanned
 * @Return:	How many pages were moved into @dst
 *
 * The lru_lock is heavily contended. Some of the functions that shrink the
 * lists perform better by taking out a batch of pages and working on them
 * outside the LRU lock.
 *
 * Enter with @lru_lock held.
 */
static unsigned long dsnvm_isolate_lru_pages(struct list_head *src,
					     struct list_head *dst,
					     unsigned long nr_to_scan,
					     unsigned long *nr_scanned)
{
	unsigned long scan, nr_taken = 0;

	for (scan = 0; scan < nr_to_scan && !list_empty(src); scan++) {
		struct dsnvm_page *page;

		/* Grab the page at the TAIL of src list */
		page = lru_to_dsnvm_page(src);

		DSNVM_BUG_ON_PAGE(!DSNVM_PageLRU(page), page);
		DSNVM_BUG_ON_PAGE(DSNVM_PageOwner(page), page);

		/*
		 * Do not touch inxact pages:
		 * . It will be accessed frequently in theory.
		 * . It might be currently being promoted from COW page
		 *   to ON_REGION page.
		 */
		if (unlikely(DSNVM_PageInxact(page))) {
			list_move(&page->lru, src);
			continue;
		}

		/*
		 * The DSNVM page is beging freed elsewhere.
		 * Move it to the head of src list and go next.
		 */
		if (unlikely(!get_dsnvm_page_unless_zero(page))) {
			/*
			 * It is safe to move list since we are
			 * protected by @lru_lock. The free func
			 * can not manipulate those 2 pointers.
			 * Check __put_single_dsnvm_page().
			 */
			list_move(&page->lru, src);
			continue;
		}

		/*
		 * We are safe at this point: this page will not be
		 * freed elsewhere in the middle of LRU manipulating.
		 * And it will be freed by us later if we are the last
		 * customer.
		 */
		DSNVM_ClearPageLRU(page);
		if (DSNVM_PageActive(page))
			del_dsnvm_page_from_active_list(page);
		else
			del_dsnvm_page_from_inactive_list(page);

		list_add(&page->lru, dst);
		nr_taken++;
	}
	return nr_taken;
}

/**
 * putback_lru_dsnvm_page()
 *
 * Put previously isolated page onto appropriate LRU list.
 *
 * Enter with NO lock held.
 */
static void putback_lru_dsnvm_page(struct dsnvm_page *page)
{
	DSNVM_BUG_ON_PAGE(DSNVM_PageLRU(page), page);

	if (unlikely(DSNVM_PageOwner(page))) {
		__DSNVM_ClearPageActive(page);
		return;
	}

	spin_lock(&lru_lock);
	DSNVM_SetPageLRU(page);
	if (DSNVM_PageActive(page))
		add_dsnvm_page_to_active_list(page);
	else
		add_dsnvm_page_to_inactive_list(page);
	spin_unlock(&lru_lock);

	/*
	 * Drop a reference grabbed from isolate.
	 */
	put_dsnvm_page(page);
}

/**
 * putback_inactive_dsnvm_pages()
 *
 * Put pages, which were isolated from inactive LRU list, back to LRU lists.
 * If PageActive is set, the page is put back to active LRU list. Otherwise,
 * put it back to inactive LRU list.
 *
 * Enter with lru_lock held.
 */
static void putback_inactive_dsnvm_pages(struct list_head *page_list,
					 struct list_head *pages_to_free)
{
	struct dsnvm_page *page;

	/* put back any unfreeable pages */
	while (!list_empty(page_list)) {
		page = lru_to_dsnvm_page(page_list);
		list_del(&page->lru);

		DSNVM_BUG_ON_PAGE(DSNVM_PageLRU(page), page);

		if (unlikely(DSNVM_PageOwner(page))) {
			__DSNVM_ClearPageActive(page);
			continue;
		}

		if (put_dsnvm_page_testzero(page)) {
			/* We are the last one, no one will
			 * compete with us. Use non-atomic bitop */
			__DSNVM_ClearPageActive(page);
			list_add(&page->lru, pages_to_free);
			continue;
		}

		DSNVM_SetPageLRU(page);
		if (DSNVM_PageActive(page))
			add_dsnvm_page_to_active_list(page);
		else
			add_dsnvm_page_to_inactive_list(page);
	}
}

enum dsnvm_lru_list {
	DSNVM_LRU_INACTIVE,
	DSNVM_LRU_ACTIVE,
};

/**
 * putback_active_dsnvm_pages()
 *
 * Put pages, which were isolated from active LRU list, back to LRU lists.
 * The list to insert is specified by @lru. If we are the last user of a
 * page, then put it into @pages_to_free list to be freed later.
 *
 * Enter with @lru_lock held.
 */
static void putback_active_dsnvm_pages(struct list_head *list,
				       struct list_head *pages_to_free,
				       enum dsnvm_lru_list lru)
{
	struct dsnvm_page *page;

	while (!list_empty(list)) {
		page = lru_to_dsnvm_page(list);
		list_del(&page->lru);

		DSNVM_BUG_ON_PAGE(DSNVM_PageLRU(page), page);

		if (unlikely(DSNVM_PageOwner(page))) {
			__DSNVM_ClearPageActive(page);
			continue;
		}

		if (put_dsnvm_page_testzero(page)) {
			/* We are the last one, no one will
			 * compete with us. Use non-atomic bitop */
			__DSNVM_ClearPageActive(page);
			list_add(&page->lru, pages_to_free);
			continue;
		}

		DSNVM_SetPageLRU(page);
		if (lru == DSNVM_LRU_ACTIVE)
			add_dsnvm_page_to_active_list(page);
		else
			add_dsnvm_page_to_inactive_list(page);
	}
}

/**
 * shrink_dsnvm_page_list()
 *
 * It iterates over every dsnvm page in @page_list, and takes three actions
 * against each dsnvm page's history activity:
 *	1) Activate, move the dsnvm page to active LRU list later
 *	2) Keep, keep the dsnvm page in inactive LRU list
 *	3) Reclaim, free the dsnvm page away.
 *
 * Note that it works on isolated dsnvm page list, which will be inserted
 * into two LRU lists later.
 *
 * Enter with no locks held.
 */
static unsigned long shrink_dsnvm_page_list(struct list_head *page_list,
					    bool force_reclaim)
{
	LIST_HEAD(ret_pages);
	LIST_HEAD(free_pages);
	unsigned long nr_activated = 0;
	unsigned long nr_reclaimed = 0;
	struct dsnvm_page *page;
	enum dsnvm_page_actions action;

	while (!list_empty(page_list)) {
		action = DSNVM_PAGE_RECLAIM;
		page = lru_to_dsnvm_page(page_list);
		list_del(&page->lru);

		if (unlikely(DSNVM_PageUnevictable(page) ||
			     DSNVM_PageInxact(page) ||
			     DSNVM_PageDirty(page)) ||
			     DSNVM_PageOwner(page))
			goto keep;

		/* Locked already, skip it */
		if (!trylock_dsnvm_page(page))
			goto keep;

		DSNVM_BUG_ON_PAGE(DSNVM_PageActive(page), page);

		if (!force_reclaim)
			action = dsnvm_page_check_accesses(page);

		switch(action) {
		case DSNVM_PAGE_ACTIVATE:
			goto activate_locked;
		case DSNVM_PAGE_KEEP:
			goto keep_locked;
		case DSNVM_PAGE_RECLAIM:
			; /* try to reclaim page below */
		}

#if 0
		/*
		 * The page is mapped into the page tables of
		 * one or more processes, try to unmap them here:
		 */
		if (dsnvm_page_mapped(page)) {
			switch (dsnvm_try_to_unmap(page)) {
			case DSNVM_SWAP_AGAIN:
				goto keep_locked;
			case DSNVM_SWAP_FAIL:
				goto activate_locked;
			case DSNVM_SWAP_SUCCESS:
				; /* try to reclaim page below */
			}
		}
#endif

		list_add(&page->lru, &free_pages);
		unlock_dsnvm_page(page);
		nr_reclaimed++;
		continue;

activate_locked:
		/*
		 * Just mark the page as active, it will be
		 * moved into the active list later properly.
		 */
		DSNVM_BUG_ON_PAGE(DSNVM_PageActive(page), page);
		DSNVM_SetPageActive(page);
		nr_activated++;
keep_locked:
		unlock_dsnvm_page(page);
keep:
		list_add(&page->lru, &ret_pages);
		DSNVM_BUG_ON_PAGE(DSNVM_PageLRU(page), page);
	}

	count_dsnvm_events(DSNVM_PGACTIVATE, nr_activated);
	if (current_is_dsnvm_kswapd())
		count_dsnvm_events(DSNVM_PGRECLAIM_KSWAPD, nr_reclaimed);
	else
		count_dsnvm_events(DSNVM_PGRECLAIM_DIRECT, nr_reclaimed);

	/*
	 * Free page is simple
	 * But updating metadata is a challenge
	 */
	free_dsnvm_pages_and_notify(&free_pages);

	list_splice(&ret_pages, page_list);

	return nr_reclaimed;
}

/* Return the number of reclaimed dsnvm pages */
static unsigned long shrink_dsnvm_inactive_list(unsigned long nr_to_scan)
{
	LIST_HEAD(page_list);
	LIST_HEAD(pages_to_free);
	unsigned long nr_taken;
	unsigned long nr_scanned;
	unsigned long nr_reclaimed;

	spin_lock_irq(&lru_lock);
	nr_taken = dsnvm_isolate_lru_pages(&inactive_list,
					   &page_list,
					   nr_to_scan,
					   &nr_scanned);
	spin_unlock_irq(&lru_lock);

	if (nr_taken == 0)
		return 0;

	/* Do the real reclaiming */
	nr_reclaimed = shrink_dsnvm_page_list(&page_list, false);

	/* Move the pages back to LRU lists: */
	spin_lock_irq(&lru_lock);
	putback_inactive_dsnvm_pages(&page_list, &pages_to_free);
	spin_unlock_irq(&lru_lock);

	/*
	 * @pages_to_free hold pages that have no refcounts.
	 * This means the previous user has already released
	 * this page and will update DN/ON/REPLICA info itself.
	 * Thus, just free the page back to allocator here.
	 */
	free_hot_cold_dsnvm_page_list(&pages_to_free, true);

	return nr_reclaimed;
}

static void shrink_dsnvm_active_list(unsigned long nr_to_scan)
{
	int accessed;
	unsigned long nr_taken;
	unsigned long nr_scanned;
	unsigned long nr_deactivate = 0;
	LIST_HEAD(l_hold);
	LIST_HEAD(l_active);
	LIST_HEAD(l_inactive);
	struct dsnvm_page *page;

	spin_lock_irq(&lru_lock);
	nr_taken = dsnvm_isolate_lru_pages(&active_list,
					   &l_hold,
					   nr_to_scan,
					   &nr_scanned);
	spin_unlock_irq(&lru_lock);

	if (nr_taken == 0)
		return;

	while (!list_empty(&l_hold)) {
		page = lru_to_dsnvm_page(&l_hold);
		list_del(&page->lru);

		if (DSNVM_PageUnevictable(page) || DSNVM_PageInxact(page)) {
			putback_lru_dsnvm_page(page);
			continue;
		}

		lock_dsnvm_page(page);
		accessed = dsnvm_page_accessed(page);
		unlock_dsnvm_page(page);

		if (accessed) {
			list_add(&page->lru, &l_active);
			continue;
		}

		nr_deactivate++;
		list_add(&page->lru, &l_inactive);
		DSNVM_ClearPageActive(page);
	}

	count_dsnvm_events(DSNVM_PGDEACTIVATE, nr_deactivate);

	/*
	 * Move the pages back to LRU lists,
	 * @l_hold will have those to be freed pages after this:
	 */
	spin_lock_irq(&lru_lock);
	putback_active_dsnvm_pages(&l_active, &l_hold, DSNVM_LRU_ACTIVE);
	putback_active_dsnvm_pages(&l_inactive, &l_hold, DSNVM_LRU_INACTIVE);
	spin_unlock_irq(&lru_lock);

	/*
	 * @l_hold hold pages that have no refcounts.
	 * This means the previous user has already released
	 * this page and will update DN/ON/REPLICA info itself.
	 * Thus, just free the page back to allocator here.
	 */
	free_hot_cold_dsnvm_page_list(&l_hold, true);
}

/*
 * Called by both direct and periodical reclaiming.
 * It tries to shrink active list first, so some pages would be moved into
 * inactive list. And then it shrinks inactive list to free some pages away
 * or activiate some pages back to active list.
 */
static unsigned long do_balance_dsnvm_pages(unsigned long nr_to_scan)
{
	unsigned long nr_reclaimed;

	shrink_dsnvm_active_list(nr_to_scan);
	nr_reclaimed = shrink_dsnvm_inactive_list(nr_to_scan);

	return nr_reclaimed;
}

static void do_kswapd_balance_dsnvm_pages(void)
{
	unsigned long nr_reclaimed;
	unsigned long nr_to_scan = 100;

	nr_reclaimed = do_balance_dsnvm_pages(nr_to_scan);
}

static int dsnvm_kswapd(void *data)
{
	int ret, node = numa_node_id();
	const struct cpumask *cpumask;
	DEFINE_WAIT(wait);

	/*
	 * TODO: Create dsnvm-kswapd for per node
	 */
	cpumask = cpumask_of_node(node);
	if (!cpumask_empty(cpumask))
		set_cpus_allowed_ptr(current, cpumask);

	current->flags |= PF_MEMALLOC | PF_KSWAPD;
	set_freezable();

	pr_crit("dsnvm-kswapd (PID %d) is running", current->pid);
	for ( ; ; ) {
		prepare_to_wait(&dsnvm_kswapd_wait, &wait, TASK_INTERRUPTIBLE);
		if (!freezing(current))
			schedule();
		finish_wait(&dsnvm_kswapd_wait, &wait);

		ret = try_to_freeze();
		if (kthread_should_stop())
			break;

		if (!ret) {
			count_dsnvm_event(DSNVM_KSWAPD_RUN);
			do_kswapd_balance_dsnvm_pages();
		}
	}
	pr_crit("dsnvm-kswapd (PID %d) exited", current->pid);
	return 0;
}

/**
 * try_to_free_dsnvm_pages
 *
 * Direct dsnvm page reclaim. This is invoked if there is no free
 * dsnvm pages available. If this fails, we are running out of NVM.
 *
 * Return:	0, if no dsnvm pages reclaimed,
 *		else, the number of dsnvm pages reclaimed.
 */
unsigned long try_to_free_dsnvm_pages(void)
{
	unsigned long nr_reclaimed;
	unsigned long nr_to_scan = 200;

	count_dsnvm_event(DSNVM_DIRECT_RUN);
	nr_reclaimed = do_balance_dsnvm_pages(nr_to_scan);

	return nr_reclaimed;
}

/**
 * wakeup_dsnvm_kswapd
 *
 * DSNVM is low on free memory, so wake dsnvm_kswapd to
 * swap cold pages out and make some room for new friends.
 */
void wakeup_dsnvm_kswapd(void)
{
	if (!waitqueue_active(&dsnvm_kswapd_wait))
		return;
	wake_up_interruptible(&dsnvm_kswapd_wait);
}

int init_dsnvm_kswapd(void)
{
	INIT_LIST_HEAD(&active_list);
	INIT_LIST_HEAD(&inactive_list);
	atomic_set(&nr_active, 0);
	atomic_set(&nr_inactive, 0);

	init_waitqueue_head(&dsnvm_kswapd_wait);

	__dsnvm_kswapd = kthread_run(dsnvm_kswapd, NULL, "dsnvm-kswapd");
	if (IS_ERR(__dsnvm_kswapd)) {
		pr_err("error: fail to start dsnvm-kswapd");
		return PTR_ERR(dsnvm_kswapd);
	}
	return 0;
}

void stop_dsnvm_kswapd(void)
{
	if (__dsnvm_kswapd) {
		kthread_stop(__dsnvm_kswapd);
		__dsnvm_kswapd = NULL;
	}
}
#endif /* CONFIG_DSNVM_SWAP */
