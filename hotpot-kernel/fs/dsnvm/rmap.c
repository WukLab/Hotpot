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
 * Reverse Mapping of DSNVM Page
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

static struct kmem_cache *dsnvm_rmap_cachep;

static struct dsnvm_rmap *alloc_dsnvm_rmap(void)
{
	return kmem_cache_zalloc(dsnvm_rmap_cachep, GFP_KERNEL);
}

static void free_dsnvm_rmap(struct dsnvm_rmap *rmap)
{
	if (!rmap)
		return;
	kmem_cache_free(dsnvm_rmap_cachep, rmap);
}

int init_dsnvm_rmap_cache(void)
{
	dsnvm_rmap_cachep = kmem_cache_create("dsnvm_rmap_cache",
			    sizeof(struct dsnvm_rmap), 0,
			    (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD),
			    NULL);

	if (!dsnvm_rmap_cachep)
		return -ENOMEM;

	return 0;
}

void destroy_dsnvm_rmap_cache(void)
{
	if (!dsnvm_rmap_cachep)
		return;
	kmem_cache_destroy(dsnvm_rmap_cachep);
	dsnvm_rmap_cachep = NULL;
}

/* Lock DSNVM page first */
int dsnvm_page_add_rmap(struct dsnvm_page *page, pte_t *pte,
			struct vm_area_struct *vma)
{
	struct dsnvm_rmap *rmap, *pos;

	DSNVM_BUG_ON_PAGE(!DSNVM_PageLocked(page), page);

	DSNVM_PRINTK_VM("dsnvm_pfn: %lu, pte: %p",
		dsnvm_page_to_dsnvm_pfn(page), pte);

	rmap = alloc_dsnvm_rmap();
	if (!rmap)
		return -ENOMEM;
	rmap->page_table = pte;
	rmap->vma = vma;

	if (list_empty(&page->rmap)) {
		list_add(&rmap->next, &page->rmap);
		atomic_inc(&page->mapcount);
		return 0;
	}

	list_for_each_entry(pos, &page->rmap, next) {
		if (unlikely(pos->page_table == pte)) {
			free_dsnvm_rmap(rmap);
			DSNVM_BUG("pte: %p", pte);
			dump_dsnvm_page(page, "pte exist");
			return -EEXIST;
		}
	}

	list_add(&rmap->next, &page->rmap);
	atomic_inc(&page->mapcount);

	return 0;
}

static void __dsnvm_page_remove_rmap_all(struct dsnvm_page *page)
{
	while (!list_empty(&page->rmap)) {
		struct dsnvm_rmap *rmap;

		rmap = list_first_entry(&page->rmap, struct dsnvm_rmap, next);
		list_del(&rmap->next);
		atomic_dec(&page->mapcount);
		free_dsnvm_rmap(rmap);
	}
}

/* Lock DSNVM page first */
void dsnvm_page_remove_rmap(struct dsnvm_page *page, pte_t *pte,
			    struct vm_area_struct *vma)
{
	struct dsnvm_rmap *rmap;

	DSNVM_BUG_ON_PAGE(!DSNVM_PageLocked(page), page);

	if (unlikely(!pte)) {
		/* FIXME: workaround for free_dn_regions */
		__dsnvm_page_remove_rmap_all(page);
		return;
	}

	DSNVM_PRINTK_VM("dsnvm_pfn: %lu, pte: %p",
		dsnvm_page_to_dsnvm_pfn(page), pte);

	if (unlikely(list_empty(&page->rmap))) {
		dump_dsnvm_page(page, "Page reverse mapping is NULL");
		DSNVM_BUG();
		return;
	}

	list_for_each_entry(rmap, &page->rmap, next) {
		if (rmap->page_table == pte) {
			list_del(&rmap->next);
			atomic_dec(&page->mapcount);
			free_dsnvm_rmap(rmap);
			return;
		}
	}

	DSNVM_BUG("fail to find pte: %p", pte);
	dump_dsnvm_page(page, "fail to find pte");
}

/**
 * dsnvm_try_to_unmap
 * @page: the page to get unmapped
 *
 * Tries to remove all the page table entries which are mapping this
 * page, used int the pageout path. Caller must hold the page lock.
 *
 * Return:
 *	DSNVM_SWAP_SUCCESS	- we succeeded in removing all mappings
 *	DSNVM_SWAP_AGAIN	- we missed a mapping, try again later
 *	DSNVM_SWAP_FAIL		- the page is unswappable
 */
enum dsnvm_swap_status dsnvm_try_to_unmap(struct dsnvm_page *page)
{
	struct dsnvm_rmap *rmap;
	pte_t *pte;
	pte_t pteval;

	DSNVM_BUG_ON_PAGE(!DSNVM_PageLocked(page), page);

	if (!dsnvm_page_mapped(page))
		return DSNVM_SWAP_SUCCESS;

	list_for_each_entry(rmap, &page->rmap, next) {
		pte = rmap->page_table;
		if (!pte) {
			DSNVM_BUG();
			dump_dsnvm_page(page, NULL);
			continue;
		}

		/* Clear the PTE */
		pteval = native_ptep_get_and_clear(pte);
		if (unlikely(pte_pfn(pteval) != dsnvm_page_to_pfn(page))) {
			DSNVM_BUG("pte_pfn: %lu, page_pfn: %lu",
				pte_pfn(pteval), dsnvm_page_to_pfn(page));
			continue;
		}

#ifdef DSNVM_KERNEL_EXPORT_TLB_FLUSH
		if (pte_accessible(pte))
			flush_tlb_page(rmap->vma, rmap->address);
#endif
	}
	return DSNVM_SWAP_SUCCESS;
}
