/*
 * Distributed Shared NVM. Owner node code.
 *
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * This file describes functions for Owner Node (ON).
 */

#include <linux/fs.h>
#include <linux/kref.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/hashtable.h>

#include "dsnvm.h"

/*
 * Each client node maintains only one hashtable for owner regions,
 * and it serves requests from other DNs and CD. We use a spinlock to
 * protect this hashtable, and use reference count to protect hashtable
 * bucket itself from being released in a busy state.
 */
static DEFINE_HASHTABLE(ht_on_region, HASH_TABLE_SIZE_BIT);
static DEFINE_SPINLOCK(ht_lock);

/**
 * ht_add_on_region
 *
 * Add one on_region_info structure into ht_on_region.
 * If succeed, this new region will be available for DNs.
 */
int __must_check ht_add_on_region(struct on_region_info *new)
{
	struct on_region_info *r;

	if (!new)
		return -EINVAL;

	spin_lock(&ht_lock);
	hash_for_each_possible(ht_on_region, r, hlist, new->dr_no) {
		if (unlikely(r->dr_no == new->dr_no)) {
			spin_unlock(&ht_lock);
			return -EEXIST;
		}
	}
	hash_add(ht_on_region, &new->hlist, new->dr_no);
	spin_unlock(&ht_lock);

	return 0;
}

/**
 * remove_on_region
 *
 * Remove one on_region_info structure from ht_on_region,
 * and free the structure if it can be removed.
 * Failed if the reference count still > 1.
 */
int remove_on_region(unsigned long dr_no)
{
	struct on_region_info *r;

	spin_lock(&ht_lock);
	hash_for_each_possible(ht_on_region, r, hlist, dr_no) {
		if (likely(r->dr_no == dr_no)) {
#if 0
			if (likely(atomic_read(&r->region_ref.refcount) == 1)) {
				hash_del(&r->hlist);
				spin_unlock(&ht_lock);
				free_dsnvm_on_region_info(r);
				return 0;
			} else {
				spin_unlock(&ht_lock);
				return -EBUSY;
			}
#endif
			hash_del(&r->hlist);
			spin_unlock(&ht_lock);
			free_dsnvm_on_region_info(r);
			return 0;

		}
	}
	spin_unlock(&ht_lock);

	return -ENOENT;
}

/**
 * ht_get_on_region
 * @dr_no: Global DR number
 *
 * Get the pointer to on_region_info by dr_no
 * and increment its reference count.
 */
struct on_region_info *ht_get_on_region(unsigned long dr_no)
{
	struct on_region_info *r;

	spin_lock(&ht_lock);
	hash_for_each_possible(ht_on_region, r, hlist, dr_no) {
		if (likely(r->dr_no == dr_no)) {
			kref_get(&r->region_ref);
			spin_unlock(&ht_lock);
			return r;
		}
	}
	spin_unlock(&ht_lock);

	return NULL;
}

static void on_region_release(struct kref *ref)
{
	struct on_region_info *r = container_of(ref, struct on_region_info, region_ref);
	WARN(1, "Error usage of get/put of region: %ld", r->dr_no);
}

/**
 * put_on_region
 * @r: on region in question
 *
 * Decrement reference count of on_region_info.
 */
void put_on_region(struct on_region_info *r)
{
	if (!r)
		return;

	if (likely(r && hash_hashed(&r->hlist)))
		kref_put(&r->region_ref, on_region_release);
	else
		DSNVM_WARN();
}

struct on_region_info *find_or_alloc_on_region(unsigned long dr_no)
{
	struct on_region_info *on;
	int ret;

	on = ht_get_on_region(dr_no);
	if (!on) {
		on = alloc_dsnvm_on_region_info();
		if (!on) {
			DSNVM_WARN("dr_no: %lu", dr_no);
			goto out;
		}

		/* dr_no works like the flag field of ON_REGION */
		on->dr_no = dr_no;
		dsnvm_flush_buffer(&on->dr_no, sizeof(on->dr_no));

		/* Add to hashlist */
		ret = ht_add_on_region(on);
		if (ret) {
			DSNVM_WARN();
			free_dsnvm_on_region_info(on);
			on = NULL;
			goto out;
		}

		/* Counter for proc fs */
		count_dsnvm_event(DSNVM_OWNER_REGION_CREATED);
	}
out:
	return on;
}

static void free_on_region_pages(struct on_region_info *r, bool inittime)
{
	int i;
	unsigned long pfn;
	struct on_page_info *page_info;

	for (i = 0; i < DR_PAGE_NR; i++) {
		page_info = &(r->mapping[i]);
		pfn = page_info->local_pfn;
		if (likely(pfn)) {
			if (unlikely(!pfn_is_dsnvm(pfn)))
				DSNVM_BUG("Big Bug");
			free_dsnvm_page_pfn(pfn);
		} else {
			if (inittime) /* not allocated */
				continue;
			/*
			 * TODO: ON_REGION NVM pages were evicted.
			 * Remove this if we do not need to handle
			 * this case.
			 */
		}
	}
}

/*
 * Free all ON_REGIONS in this machine.
 * Called at unmounting time, before sending leaving message to server.
 *
 * TODO:
 *	Of course, we need to let CD and DNs know that this machine is no
 *	longer maintaining these ON_REGIONs, and all following page-fetch
 *	requests should not be made into this machine anymore. Therefore,
 *	we need to:
 *		1) Tell CD that this ON_REGION is being moved.
 *		2) Tell DNs that this ON_REGION is being moved.
 */
void free_all_on_regions(void)
{
	int bkt;
	struct on_region_info *on_region;

	spin_lock(&ht_lock);

	if (hash_empty(ht_on_region)) {
		spin_unlock(&ht_lock);
		return;
	}

	hash_for_each(ht_on_region, bkt, on_region, hlist) {
#if 0
		WARN_ONCE(atomic_read(&on_region->region_ref.refcount) != 1,
			  "Incompatible use of get/put_on_region (dr_no: %lu)",
			  on_region->dr_no);
#endif
		hash_del(&on_region->hlist);
		free_on_region_pages(on_region, false);
		free_dsnvm_on_region_info(on_region);
	}

	spin_unlock(&ht_lock);
}

/*
 * Try to allocate pages for this owner region
 */
static int init_new_on_region(struct on_region_info *r)
{
	int i;
	unsigned long pfn;
	struct dsnvm_page *page;
	struct on_page_info *page_info;

	for (i = 0; i < DR_PAGE_NR; i++) {
		page_info = &(r->mapping[i]);
		memset(page_info, 0, sizeof(*page_info));

		pfn = alloc_dsnvm_page_pfn();
		if (!pfn) {
			free_on_region_pages(r, true);
			return -ENOMEM;
		}

		/*
		 * ON_REGION pages can not be evicted
		 */
		page = pfn_to_dsnvm_page(pfn);

		DSNVM_SetPageUnevictable(page);
		DSNVM_SetPageCommitted(page);
		DSNVM_SetPageOwner(page);

		page_info->local_pfn = pfn;
		dsnvm_flush_buffer(&page_info->local_pfn,
			sizeof(page_info->local_pfn));
	}
	return 0;
}

int handle_create_region_at_on(struct dsnvm_request *request,
			       char *__reply, unsigned int *reply_len,
			       int sender_id)
{
	unsigned long dr_no = request->dr_no;
	struct on_region_info *r;
	struct dsnvm_reply *reply;
	int ret;

	DSNVM_PRINTK("Receive create ON region request, dr_no: %lu", dr_no);

	reply = (struct dsnvm_reply *)__reply;
	*reply_len = sizeof(unsigned int);

	/* Only CD can issue this command */
	if (unlikely(sender_id != 0)) {
		DSNVM_BUG("EPERM from node %2d", sender_id);
		reply->status = DSNVM_EPERM;
		return 0;
	}

	r = ht_get_on_region(dr_no);
	if (unlikely(r)) {
		DSNVM_BUG("existed region, dr_no: %lu", dr_no);
		put_on_region(r);
		reply->status = DSNVM_EEXIST;
		return 0;
	}

	r = alloc_dsnvm_on_region_info();
	if (unlikely(!r)) {
		DSNVM_WARN("dr_no: %lu", dr_no);
		reply->status = DSNVM_ENOMEM;
		return 0;
	}

	/* dr_no works like the flag field of ON_REGION */
	r->dr_no = dr_no;
	dsnvm_flush_buffer(&r->dr_no, sizeof(r->dr_no));

	ret = ht_add_on_region(r);

	if (unlikely(ret)) {
		reply->status = DSNVM_EINVAL;
		if (ret == -EEXIST) {
			/*
			 * This can only can happen if CD issues two commands at
			 * the same time and CD allow multiple outgoing commands.
			 * Anyway, take care if this happen in the future.
			 */
			reply->status = DSNVM_EEXIST;
		}
		DSNVM_WARN("dr_no: %lu", dr_no);
		return 0;
	}

	/*
	 * Since we it is a ON_REGION and we are ON, so all NVM pages of
	 * this region should be allocated. If, some of these pages being
	 * evicted later, our PF handler should take care of this.
	 */
	if (init_new_on_region(r)) {
		if (remove_on_region(r->dr_no))
			DSNVM_BUG();
		reply->status = DSNVM_ENOMEM;
		return 0;
	}

	reply->status = DSNVM_REPLY_SUCCESS;
	count_dsnvm_event(DSNVM_OWNER_REGION_CREATED);

	DSNVM_PRINTK("ON_REGION (dr_no: %lu) created", r->dr_no);

	return 0;
}

int handle_remove_region_at_on(struct dsnvm_request *request,
			       char *reply_addr,
			       unsigned int *reply_len,
			       int sender_id)
{
	unsigned long dr_no = request->dr_no;
	struct status_reply_msg *reply = (struct status_reply_msg *)reply_addr;
	int ret;

	*reply_len = sizeof(struct status_reply_msg);

	/* Only CD can issue this command */
	if (unlikely(sender_id != 0)) {
		reply->status = DSNVM_EPERM;
		return 0;
	}

	ret = remove_on_region(dr_no);

	if (likely(ret == 0))
		reply->status = DSNVM_REPLY_SUCCESS;
	else if (ret == -ENOENT)
		reply->status = DSNVM_ENOREGION;
	else if (ret == -EBUSY)
		reply->status = DSNVM_EBUSY;

	return 0;
}

/*
 * ibapi_send_reply_opt needs a real buffer to send the failed reason.
 * Use some value inside stack is wrong. Here, we use a static array
 * that each bucket is for each node. (Just assume that a node can only
 * at 1 outgoing pf request.)
 *
 * In order to use virt_to_phys(), we have to use kmalloced address.
 */
static struct page_fetch_failed_reason *pff_reason;

int alloc_pff_reason_array(void)
{
	pff_reason = kzalloc(sizeof(*pff_reason) * DSNVM_MAX_NODE, GFP_KERNEL);
	if (!pff_reason)
		return -ENOMEM;
	return 0;
}

void free_pff_reason_array(void)
{
	DSNVM_WARN_ON(!pff_reason);
	if (pff_reason)
		kfree(pff_reason);
}

/*
 * Handle a page-fetch request from DN. This is critial path in DSNVM,
 * which takes 1 usec now, so try our best to optimize this function.
 */
int handle_page_fetch(char *input_addr, unsigned long *reply_addr,
		      unsigned int *reply_len, int sender_id, bool is_coherent)
{
	struct dsnvm_request_page_fetch *request;
	struct on_region_info *r = NULL;
	struct on_page_info *page_info;
	unsigned long dr_no;
	unsigned int dro, new_owner;
	struct page_fetch_failed_reason *failure;

	failure = &pff_reason[sender_id];

	request = (struct dsnvm_request_page_fetch *)input_addr;

	dr_no = request->dr_no;
	dro = request->dro;

	if (unlikely(dro > DR_PAGE_NR)) {
		DSNVM_BUG("invalid dro: %u, senderid: %d", dro, sender_id);
		failure->reason = DSNVM_INVALID_DRO;
		goto error;
	}

	r = ht_get_on_region(dr_no);
	if (unlikely(!r)) {
		/* Check if this ON was migrated out */
		new_owner = proxy_find_new_owner(dr_no);
		if (likely(new_owner)) {
			failure->reason = DSNVM_ON_MIGRATED_TO_NEW_OWNER;
			failure->new_owner = new_owner;
		} else {
			DSNVM_BUG("non-exist: dr_no: %lu, dro: %u, senderid: %d",
				dr_no, dro, sender_id);
			failure->reason = DSNVM_NONEXIST_DR_NO;
		}
		goto error;
	}

	page_info = &r->mapping[dro];

	/*
	 * block page-fetch during xact commit of this page for MRMW
	 * for MRSW, we will not have this case
	 * It's OK to not lock page_lock here, cos writing to this flag is under locking
	 */
	while (unlikely(page_info->if_blocked_by_commit_xact == 1)) {
		count_dsnvm_event(DSNVM_XACT_BLOCK_PAGE_FETCH);

		failure->reason = DSNVM_REPLY_PAGE_IN_OTHER_XACT;
		goto error;
	}

	spin_lock(&r->page_lock[dro]);
	if (unlikely(!page_info->local_pfn)) {
		/*
		 * ON_REGION pages are PG_Unevictable, so if
		 * the local_pfn is zero, the system is crashed.
		 */
		spin_unlock(&r->page_lock[dro]);
		put_on_region(r);
		DSNVM_BUG();
		failure->reason = DSNVM_ON_PAGE_NOT_MAPPED;
		goto error;
	}

	/*
	 * The first write make the DN a non-coherent node in ON's view.
	 * The first read make the DN a coherent node in ON's dn_list.
	 */
	count_dsnvm_event(DSNVM_OWNER_REMOTE_PAGE_FETCH);
	if (!is_coherent) {
		count_dsnvm_event(DSNVM_OWNER_REMOTE_PAGE_FETCH_NON_COHERENT);
	} else {
		count_dsnvm_event(DSNVM_OWNER_REMOTE_PAGE_FETCH_COHERENT);
		if (test_and_set_bit(sender_id, page_info->dn_list)) {
			/*
			 * XXX: DN is asking this NVM page again. It might
		 	 * due to a page eviction in DN or other reasons?
		 	 * Use set_bit() instead if we do not need this.
			 */
		}
	}

	/* Count page-fetch events from different DNs, used by dynamic
	 * load-balance or ON migration code. */
	atomic_inc(&r->nr_page_fetch[sender_id]);

	*reply_addr = page_info->local_pfn << DSNVM_PAGE_SHIFT;
	*reply_len = DSNVM_PAGE_SIZE;
	spin_unlock(&r->page_lock[dro]);

	ibapi_free_recv_buf(input_addr);
	put_on_region(r);
	return 0;

error:
	*reply_addr = (unsigned long)virt_to_phys(failure);
	*reply_len = sizeof(*failure);

	ibapi_free_recv_buf(input_addr);
	put_on_region(r);
	return 0;
}

/* Remove a DN from coherent dn_list */
void on_remove_coherent_node(unsigned long dr_no, unsigned int dro,
			     unsigned int node)
{
	struct on_region_info *on_region;
	struct on_page_info *page_info;

	if (unlikely(!DRO_VALID(dro) || node > DSNVM_MAX_NODE)) {
		DSNVM_BUG();
		return;
	}

	on_region = ht_get_on_region(dr_no);
	if (unlikely(!on_region)) {
		DSNVM_BUG();
		return;
	}

	page_info = &on_region->mapping[dro];

	spin_lock(&on_region->page_lock[dro]);
	if (unlikely(!test_and_clear_bit(node, page_info->dn_list)))
		DSNVM_WARN("this dn was not coherent");
	spin_unlock(&on_region->page_lock[dro]);
	put_on_region(on_region);
}

void dump_on_region_info(unsigned long dr_no)
{
	unsigned int dro, nr_valid;
	struct on_region_info *r;
	struct on_page_info *pi;
	unsigned char buf[64];

	r = ht_get_on_region(dr_no);
	if (!r) {
		pr_info("[%s:%d] fail to find dr_no: %lu",
			__func__, __LINE__, dr_no);
		return;
	}

	pr_info("Dump ON_REGION: dr_no = %lu, owner_id: %u", r->dr_no, DSNVM_LOCAL_ID);
	for (dro = 0, nr_valid = 0; dro < DR_PAGE_NR; dro++) {
		unsigned long pfn;

		pi = &r->mapping[dro];
		pfn = pi->local_pfn;
		bitmap_scnlistprintf(buf, 64, pi->dn_list, DSNVM_MAX_NODE);
		if (pfn_is_dsnvm(pfn)) {
			nr_valid++;
			pr_info("\tdro = %6u, pfn = %lu, d_pfn = %lu, dn_list: %s",
				dro, pfn, pfn_to_dsnvm_pfn(pfn), buf);
		}
	}

	pr_info("Total ON_REGION pages: %u", nr_valid);
	if (nr_valid != DR_PAGE_NR) {
		DSNVM_WARN("This is BUG, dear!");
	}
}
