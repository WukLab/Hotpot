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
 * This file describes functions for replica handling.
 */

#include <linux/kref.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/hashtable.h>

#include "dsnvm.h"

/*
 * Like ON region hashtable, each client node maintains only one hashtable
 * for replica handling, and it serves requests from ONs and CD. We use a
 * spinlock to protect this hashtable, and use reference count to protect
 * hashtable bucket itself from being released in a busy state.
 */
static DEFINE_HASHTABLE(ht_replica_region, HASH_TABLE_SIZE_BIT);
static DEFINE_SPINLOCK(ht_lock);

int ht_add_replica_region(struct replica_region_info *new)
{
	struct replica_region_info *r;

	if (!new)
		return -EINVAL;

	spin_lock(&ht_lock);
	hash_for_each_possible(ht_replica_region, r, hlist, new->dr_no) {
		if (unlikely(r->dr_no == new->dr_no)) {
			spin_unlock(&ht_lock);
			return -EEXIST;
		}
	}
	hash_add(ht_replica_region, &new->hlist, new->dr_no);
	spin_unlock(&ht_lock);

	return 0;
}

int ht_remove_replica_region(unsigned long dr_no)
{
	struct replica_region_info *r;

	spin_lock(&ht_lock);
	hash_for_each_possible(ht_replica_region, r, hlist, dr_no) {
		if (likely(r->dr_no == dr_no)) {
			if (likely(atomic_read(&r->region_ref.refcount) == 1)) {
				hash_del(&r->hlist);
				spin_unlock(&ht_lock);
				free_dsnvm_replica_region_info(r);
				return 0;
			} else {
				spin_unlock(&ht_lock);
				return -EBUSY;
			}
		}
	}
	spin_unlock(&ht_lock);

	return -ENOENT;
}

struct replica_region_info *ht_get_replica_region(unsigned long dr_no)
{
	struct replica_region_info *r;

	spin_lock(&ht_lock);
	hash_for_each_possible(ht_replica_region, r, hlist, dr_no) {
		if (likely(r->dr_no == dr_no)) {
			kref_get(&r->region_ref);
			spin_unlock(&ht_lock);
			return r;
		}
	}
	spin_unlock(&ht_lock);

	return NULL;
}

static void ht_replica_region_release(struct kref *ref)
{
	struct replica_region_info *r;
	r = container_of(ref, struct replica_region_info, region_ref);
	WARN(1, "Error usage of get/put of replica region: %ld", r->dr_no);
}

void ht_put_replica_region(struct replica_region_info *r)
{
	if (!r)
		return;

	if (likely(r && hash_hashed(&r->hlist)))
		kref_put(&r->region_ref, ht_replica_region_release);
	else
		DSNVM_WARN();
}

/**
 * find_or_alloc_replica
 * dr_no:	data region number
 * owner_id:	owner node id
 *
 * Find replica_region_info by dr_no. If it is not exist in the hashtable,
 * allocate a new one and insert it into hashtable.
 */
struct replica_region_info *find_or_alloc_replica(unsigned long dr_no,
						  unsigned int owner_id)
{
	struct replica_region_info *rn;

	rn = ht_get_replica_region(dr_no);
	if (!rn) {
		rn = alloc_dsnvm_replica_region_info();
		if (!rn) {
			DSNVM_WARN();
			goto out;
		}

		rn->owner_id = owner_id;
		dsnvm_flush_buffer(&rn->owner_id, sizeof(rn->owner_id));

		/*
		 * dr_no works like the sentinel flag
		 * Once dr_no is persistent, the strtucre is valid in NVM
		 */
		rn->dr_no = dr_no;
		dsnvm_flush_buffer(&rn->dr_no, sizeof(rn->dr_no));

		/* Add to hashlist */
		ht_add_replica_region(rn);

		/* Counter for proc fs */
		count_dsnvm_event(DSNVM_REPLICA_REGION_CREATED);
	}
out:
	return rn;
}

static void free_replica_region_pages(struct replica_region_info *r)
{
	int i;
	unsigned long pfn;
	struct dsnvm_page *page;

	for (i = 0; i < DR_PAGE_NR; i++) {
		pfn = r->mapping[i];
		if (likely(pfn)) {
			page = pfn_to_dsnvm_page(pfn);
			put_dsnvm_page_pfn(pfn);
		} else {
			/*
			 * TODO: Replica NVM pages were evicted.
			 * Remove this if we do not need to handle
			 * this case.
			 */
		}
	}
}

/*
 * Called at unmounting time
 *
 * TODO: Tell ON that I am leaving.
 */
void free_all_replica_regions(void)
{
	int bkt;
	struct replica_region_info *r;

	spin_lock(&ht_lock);

	if (hash_empty(ht_replica_region)) {
		spin_unlock(&ht_lock);
		return;
	}

	hash_for_each(ht_replica_region, bkt, r, hlist) {
/*
		WARN_ONCE(atomic_read(&r->region_ref.refcount) != 1,
			  "Incompatible use of get/put_replica_region (dr_no: %lu)",
			  r->dr_no);
*/
		hash_del(&r->hlist);
		free_replica_region_pages(r);
		free_dsnvm_replica_region_info(r);
	}

	spin_unlock(&ht_lock);
}

/*
 * This function describes:
 *	DN handler for creating/updating replica pages
 *
 * Related IB APIs:
 * 	ibapi_multi_atomic_send_yy
 *	ibapi_multi_atomic_send
 *
 * Allocate new REPLICA_REGION or DSNVM_PAGE if they do not exist.
 * Update requested replica pages to meet the rep_degree.
 */
int dsnvm_handle_receive_replica(int node_id, int nr_reqs, struct atomic_struct *reqs,
				 char *output_buf, unsigned int *output_size)
{
	int nr_areas;
	int i, j;
	unsigned long *reply_bitmap;
	struct dsnvm_commit_request_header *request_header;
	struct dr_no_dro_page_offset *meta_for_areas;

	count_dsnvm_event(DSNVM_REPLICATION_RX);

	meta_for_areas = reqs[1].vaddr;
	request_header = reqs[0].vaddr;
	nr_areas = request_header->nr_reqs;

	reply_bitmap = (unsigned long *)output_buf;
	*output_size = BITS_TO_LONGS(nr_areas) * sizeof(unsigned long);
	bitmap_clear(reply_bitmap, 0, nr_areas);

	if (unlikely(nr_areas != nr_reqs - 2)) {
		DSNVM_BUG();
		return 0;
	}

	DSNVM_PRINTK("Sender-ID: %d nr_areas %d", node_id, nr_areas);

	for (i = 0; i < nr_areas; i++) {
		unsigned int dro = meta_for_areas[i].dro;
		unsigned long dr_no = meta_for_areas[i].dr_no;
		struct replica_region_info *rr;
		unsigned long pfn;
		struct dsnvm_page *page;
		void *dst, *src;

		for (j = 0; j < i; j++) {
			if (dr_no == meta_for_areas[j].dr_no &&
			    dro == meta_for_areas[j].dro) {
				break;
			}
		}

		/* Alreay seen this page */
		if (unlikely(j != i)) {
			DSNVM_BUG("make_replication always send full page! "
				"dr_no: %lu dro: %u", dr_no, dro);
			continue;
		}

		rr = ht_get_replica_region(dr_no);
		if (!rr) {
			/* Allocate a new REPLICA_REGION */
			rr = alloc_dsnvm_replica_region_info();
			if (!rr) {
				DSNVM_BUG();
				return 0;
			}

			rr->owner_id = node_id;
			dsnvm_flush_buffer(&rr->owner_id, sizeof(rr->owner_id));

			/* dr_no works like the sentinel flag */
			/* Once dr_no is persistent, the strtucre is valid in NVM */
			rr->dr_no = dr_no;
			dsnvm_flush_buffer(&rr->dr_no, sizeof(rr->dr_no));

			ht_add_replica_region(rr);
			count_dsnvm_event(DSNVM_REPLICA_REGION_CREATED);
		}

		if (rr->mapping[dro] == 0) {
			/* Allocate a new DSNVM_PAGE */
			pfn = alloc_dsnvm_page_pfn();
			if (!pfn) {
				pr_crit("[%s:%d] OOM", __func__, __LINE__);
				continue;
			}

			/* Mark this page inactive, a.k.a Replica */
			page = pfn_to_dsnvm_page(pfn);

			DSNVM_SetPageReplica(page);
			DSNVM_SetPageCommitted(page);
			set_dsnvm_page_rr_info(page, rr);
			lru_add_inactive(page);

			spin_lock(&rr->page_lock[dro]);
			rr->mapping[dro] = pfn;
			dsnvm_flush_buffer(&rr->mapping[dro], sizeof(rr->mapping[dro]));
			spin_unlock(&rr->page_lock[dro]);

			DSNVM_PRINTK("Insert new pfn %lu for replica dr_no %lu dro %u",
				pfn, dr_no, dro);
		} else {
			/* Already have the page */
			pfn = rr->mapping[dro];
			page = pfn_to_dsnvm_page(pfn);

			DSNVM_PRINTK("Get existing pfn %lu for replica dr_no %lu dro %u",
				pfn, dr_no, dro);
		}

		lock_dsnvm_page(page);
		if (likely(!DSNVM_PageInxact(page))) {
			/* Always copy a whole page */
			src = reqs[i + 2].vaddr;
			dst = (void *)pfn_to_dsnvm_virt(pfn);

			memcpy(dst, src, PAGE_SIZE);
			dsnvm_flush_buffer(dst, PAGE_SIZE);

			DSNVM_PRINTK("Copy replica page (dr_no: %lu, dro: %u), from %p to %p",
				dr_no, dro, src, dst);

			DSNVM_SetPageCommitted(page);

			/* Mark this page as succeed */
			set_bit(i, reply_bitmap);
		}
		unlock_dsnvm_page(page);
	}

	for (i = 0; i < nr_reqs; i++) {
		ibapi_free_recv_buf(reqs[i].vaddr);
	}
	return 0;
}

/*
 * Find a new node to make one more replica.
 * nid == 0 means we fail to find that node, sending node
 * should keep this replica page then.
 */
static unsigned int find_new_replica_node(struct on_region_info *on,
					  unsigned int dro, unsigned int sender_id)
{
	unsigned int nid = 0, i;
	struct on_page_info *on_page = &on->mapping[dro];

	spin_lock(&on->page_lock[dro]);
	for_each_clear_bit(i, on_page->dn_list, DSNVM_MAX_NODE) {
		if (unlikely(!test_bit(i, DSNVM_CLIENT_MACHINES)))
			continue;

		/* though they two should have bits set */
		if (unlikely(i == DSNVM_LOCAL_ID || i == sender_id))
			continue;

		nid = i;
		break;
	}
	spin_unlock(&on->page_lock[dro]);

	if (unlikely(i == DSNVM_MAX_NODE))
		nid = 0;
	else
		DSNVM_PRINTK("Find node: %u as the new replica node", nid);

	return nid;
}

/**
 * This function describes:
 *	ON's handler for that a replica page was freed elsewhere
 *
 * Related IB APIs:
 * 	ibapi_send_reply
 */
int dsnvm_handle_free_replica_page(char *msg, char *reply_addr,
				   unsigned int *reply_len, int sender_id)
{
	struct dsnvm_commit_request_header req_header;
	struct dr_no_dro_page_offset meta_for_replica_areas;
	struct max_reply_msg *reply_msg;
	struct atomic_struct reqs[3];

	unsigned int dro, nid;
	unsigned long pfn, dr_no;
	struct on_region_info *on;
	struct on_page_info *on_page;
	struct dsnvm_request_free_replica_page *request;
	struct dsnvm_reply_free_replica_page *reply;

	request = (struct dsnvm_request_free_replica_page *)msg;
	reply = (struct dsnvm_reply_free_replica_page *)reply_addr;
	reply->status = DSNVM_REPLY_KEEP_REPLICA_PAGE;
	*reply_len = sizeof(*reply);

	dr_no = request->dr_no;
	dro = request->dro;

	DSNVM_PRINTK("Request from node: %d, dr_no: %lu, dro: %u",
		sender_id, dr_no, dro);

	reply_msg = kmalloc(sizeof(*reply_msg), GFP_KERNEL);
	if (!reply_msg)
		return -ENOMEM;

	/* Find ON_REGION page */
	on = ht_get_on_region(dr_no);
	if (unlikely(!on)) {
		DSNVM_BUG("dr_no: %lu", dr_no);
		goto out;
	}

	spin_lock(&on->page_lock[dro]);
	on_page = &on->mapping[dro];
	pfn = on_page->local_pfn;
	/* Use physical address of the page */
	reqs[2].vaddr = (void *)(pfn << PAGE_SHIFT);
	reqs[2].len = PAGE_SIZE;
	spin_unlock(&on->page_lock[dro]);

	/* Fill requests */
	req_header.op = DSNVM_OP_SEND_REPLICA_XACT;
	req_header.nr_reqs = 1;
	reqs[0].vaddr = &req_header;
	reqs[0].len = sizeof(struct dsnvm_commit_repdegree_request_header);

	meta_for_replica_areas.dr_no = dr_no;
	meta_for_replica_areas.dro = dro;
	meta_for_replica_areas.page_offset = 0;
	reqs[1].vaddr = &meta_for_replica_areas;
	reqs[1].len = sizeof(struct dr_no_dro_page_offset);

	nid = find_new_replica_node(on, dro, sender_id);
	if (unlikely(!nid)) {
		DSNVM_PRINTK("Can not find any node to make replica for "
			"dr_no: %lu, dro: %u, sender_id: %d",
			dr_no, dro, sender_id);
		goto out;
	}

	DSNVM_PRINTK("Sending make-replica request to node: %u", nid);
	ibapi_atomic_send_yy(nid, reqs, 3, (void *)reply_msg);
	if (test_bit(0, (unsigned long *)reply_msg)) {
		reply->status = DSNVM_REPLY_SUCCESS;
		DSNVM_PRINTK("node: %u succeed to make replica", nid);
	} else {
		DSNVM_PRINTK("node: %u failed to make replica", nid);
	}

out:
	ibapi_free_recv_buf(msg);
	kfree(reply_msg);

	return 0;
}

static unsigned int replica_page_dro(struct replica_region_info *r,
				     struct dsnvm_page *page)
{
	int dro;
	unsigned long pfn;

	pfn = dsnvm_page_to_pfn(page);

	for (dro = 0; dro < DR_PAGE_NR; dro++) {
		if (pfn == r->mapping[dro])
			break;
	}
	return dro;
}

/* Called from /proc/dsnvm */
void proc_free_replica_page_notify_on(unsigned long dr_no, unsigned int dro)
{
	int ret;
	struct replica_region_info *r;
	struct dsnvm_page *page;

	r = ht_get_replica_region(dr_no);
	if (!r) {
		pr_info("no replica region");
		return;
	}

	if (!r->mapping[dro]) {
		pr_info("replica page missing");
		return;
	}

	page = pfn_to_dsnvm_page(r->mapping[dro]);
	
	ret = free_replica_page_notify_on(page);
	if (ret)
		return;

	pr_info("replica page freed via /proc/dsnvm, dr_no: %lu, dro: %u",
		dr_no, dro);

	clear_dsnvm_page_rr_info(page);
	DSNVM_ClearPageReplica(page);

	if (dsnvm_page_mapped(page)) {
		lock_dsnvm_page(page);
		dsnvm_try_to_unmap(page);
		unlock_dsnvm_page(page);
	} else
		pr_info("this replica page was not mapped");

	put_dsnvm_page(page);
}

/*
 * Called when a replica page is going to be evicted.
 * Send notify to ON, asking ON if we are allowed to evict.
 * If not, return -EPERM
 */
int free_replica_page_notify_on(struct dsnvm_page *page)
{
	int ret;
	unsigned int dro;
	struct replica_region_info *r;
	struct dsnvm_request_free_replica_page request;
	struct dsnvm_reply_free_replica_page reply;

	if (unlikely(!page))
		return -EINVAL;

	r = dsnvm_page_rr_info(page);
	if (unlikely(!r)) {
		dump_dsnvm_page(page, "Can not find rr pointer");
		return -EFAULT;
	}

	r = ht_get_replica_region(r->dr_no);
	if (unlikely(!r)) {
		DSNVM_BUG("dr_no: %lu", r->dr_no);
		dump_dsnvm_page(page, NULL);
		return -EFAULT;
	}

	spin_lock(&r->region_lock);
	dro = replica_page_dro(r, page);
	spin_unlock(&r->region_lock);

	if (unlikely(dro == DR_PAGE_NR)) {
		DSNVM_BUG("fail to find page in rr, dr_no: %lu", r->dr_no);
		dump_dsnvm_page(page, NULL);
		ret = -EFAULT;
		goto out;
	}

	request.op = DSNVM_OP_FREE_REPLICA_PAGE;
	request.dr_no = r->dr_no;
	request.dro = dro;

	DSNVM_PRINTK("Send free_replica to ON: %d, dr_no: %lu, dro: %u",
		r->owner_id, r->dr_no, dro);

	/* Send to ON */
	ibapi_send_reply(r->owner_id, (char *)&request, sizeof(request),
		(char *)&reply);

	if (unlikely(reply.status != DSNVM_REPLY_SUCCESS)) {
		DSNVM_WARN("%s", dsnvm_status_string(reply.status));
		ret = -EPERM;
		goto out;
	}

	spin_lock(&r->region_lock);
	r->mapping[dro] = 0;
	dsnvm_flush_buffer(&r->mapping[dro], sizeof(r->mapping[dro]));
	spin_unlock(&r->region_lock);

	ret = 0;
out:
	ht_put_replica_region(r);
	return ret;
}

void dump_replica_region_info(unsigned long dr_no)
{
	unsigned int dro, nr_valid;
	struct replica_region_info *r;

	r = ht_get_replica_region(dr_no);
	if (!r) {
		pr_info("[%s:%d] fail to find dr_no: %lu",
			__func__, __LINE__, dr_no);
		return;
	}

	pr_info("Dump REPLICA_REGION: dr_no = %lu, owner_id: %u", r->dr_no, r->owner_id);
	for (dro = 0, nr_valid = 0; dro < DR_PAGE_NR; dro++) {
		unsigned long pfn = r->mapping[dro];
		if (pfn_is_dsnvm(pfn)) {
			nr_valid++;
			pr_info("\tdro = %6u, pfn = %lu, d_pfn = %lu",
				dro, pfn, pfn_to_dsnvm_pfn(pfn));
		}
	}
	pr_info("Total replica pages: %u", nr_valid);
}
