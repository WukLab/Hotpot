/*
 * Distributed Shared Non-Volatile Memory
 *
 * Copyright (C) 2016-2017 Wuklab, Purdue. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * MRSW master in kernel
 */

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/sched.h>
#include <linux/random.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/bitops.h>
#include <linux/memory.h>
#include <linux/kthread.h>
#include <linux/pagemap.h>

#include "dsnvm.h"
#include "xact-uthash.h"

#ifdef DSNVM_MODE_MRSW_IN_KERNEL

struct dsnvm_cd_xact_rec {
	int			xact_id;
	int			num_reqs;
	struct dr_no_dro	*requests;
	struct list_head	next;
};

struct dsnvm_cd_page_in_xact {
	int			key;
	int			if_in_xact;
	UT_hash_handle		hh;
};

static DEFINE_SPINLOCK(mrsw_xact_rec_lock);
static LIST_HEAD(mrsw_xact_list);

static DEFINE_SPINLOCK(mrsw_xact_page_lock);
static struct dsnvm_cd_page_in_xact *ht_mrsw_page_in_xact;

int handle_mrsw_begin(char *send_msg, unsigned int send_msg_size,
		      char *reply_addr, unsigned int *reply_len, int sender_id)
{
	int xact_id, i;
	int nr_reqs, hash_key;
	unsigned long dr_no;
	unsigned int dro;
	struct dr_no_dro *dr_requests;
	struct status_reply_msg *reply;
	struct dsnvm_cd_xact_rec *xact_rec;
	struct dsnvm_cd_page_in_xact *htentry = NULL;

	count_dsnvm_event(DSNVM_MRSW_MASTER_BEGIN);

	reply = (struct status_reply_msg *)reply_addr;
	*reply_len = sizeof(struct status_reply_msg);

	/* Extract metadata from incoming message */
	memcpy(&xact_id, send_msg + sizeof(int), sizeof(int));
	nr_reqs = (send_msg_size - 2 * sizeof(int)) / sizeof(struct dr_no_dro);
	dr_requests = (struct dr_no_dro *)(send_msg + 2 * sizeof(int));

	DSNVM_PRINTK("[%s:%d] START sender:%d xact_id: %d nr_reqs: %d",
		__func__, __LINE__, sender_id, xact_id, nr_reqs);

	/*
	 * Check the whole hashlist first and then insert each page rec into
	 * hashlist if none of the requested pages are in xact state.
	 *
	 * Locking: Use mrsw_xact_page_lock to serialize hashlist manipulations
	 */
	spin_lock(&mrsw_xact_page_lock);
	for (i = 0; i < nr_reqs; i++) {
		dr_no = dr_requests[i].dr_no;
		dro = dr_requests[i].dro;
		hash_key = dr_no * DR_PAGE_NR + dro;

		HASH_FIND_INT(ht_mrsw_page_in_xact, &hash_key, htentry);
		if (htentry) {
			/* Already locked by another xact */
			spin_unlock(&mrsw_xact_page_lock);
			reply->status = DSNVM_RETRY;
			count_dsnvm_event(DSNVM_MRSW_MASTER_BEGIN_RETRY);

			DSNVM_PRINTK("[%s:%d] page %d dr_no %lu dro %u hashkey %d EXISTS",
				__func__, __LINE__, i, dr_no, dro, hash_key);

			ibapi_free_recv_buf(send_msg);
			return 0;
		}
	}

	/* Insert to hash list */
	for (i = 0; i < nr_reqs; i++) {
		dr_no = dr_requests[i].dr_no;
		dro = dr_requests[i].dro;
		hash_key = dr_no * DR_PAGE_NR + dro;

		htentry = kmalloc(sizeof(struct dsnvm_cd_page_in_xact), GFP_KERNEL);
		if (unlikely(!htentry)) {
			spin_unlock(&mrsw_xact_page_lock);

			DSNVM_WARN("OOM");
			reply->status = DSNVM_ENOMEM;
			count_dsnvm_event(DSNVM_MRSW_MASTER_BEGIN_FAIL);
			ibapi_free_recv_buf(send_msg);
			return 0;
		}

		htentry->key = hash_key;
		htentry->if_in_xact = 1;
		HASH_ADD_INT(ht_mrsw_page_in_xact, key, htentry);

		DSNVM_PRINTK("[%s:%d] page %d dr_no %lu dro %u hashkey %d INSERT",
			__func__, __LINE__, i, dr_no, dro, hash_key);
	}
	spin_unlock(&mrsw_xact_page_lock);

	/*
	 * Successfully checked and inserted all pages into hashlist,
	 * now add this transaction record into another rec hashlist.
	 *
	 * Locking: Use mrsw_xact_rec_lock to protect mrsw_xact_list
	 */
	xact_rec = kmalloc(sizeof(struct dsnvm_cd_xact_rec), GFP_KERNEL);
	if (!xact_rec) {
		DSNVM_WARN("OOM");

		reply->status = DSNVM_ENOMEM;
		count_dsnvm_event(DSNVM_MRSW_MASTER_BEGIN_FAIL);
		ibapi_free_recv_buf(send_msg);
		return 0;
	}

	/*
	 * Because the original send_msg will be be freed later,
	 * so we must copy dr_no_no info into a safe place.
	 */
	dr_requests = kmalloc(send_msg_size - 2 * sizeof(int), GFP_KERNEL);
	if (!dr_requests) {
		DSNVM_WARN("OOM");

		reply->status = DSNVM_ENOMEM;
		count_dsnvm_event(DSNVM_MRSW_MASTER_BEGIN_FAIL);
		kfree(xact_rec);
		ibapi_free_recv_buf(send_msg);
		return 0;
	}
	memcpy(dr_requests, send_msg + 2 * sizeof(int), send_msg_size - 2 * sizeof(int));

	xact_rec->xact_id = xact_id;
	xact_rec->num_reqs = nr_reqs;
	xact_rec->requests = dr_requests;

	/* Save the xact record */
	spin_lock(&mrsw_xact_rec_lock);
	list_add(&xact_rec->next, &mrsw_xact_list);
	spin_unlock(&mrsw_xact_rec_lock);

	reply->status = DSNVM_REPLY_SUCCESS;
	count_dsnvm_event(DSNVM_MRSW_MASTER_BEGIN_SUCCEED);

	DSNVM_PRINTK("[%s:%d] EXIT sender:%d xact_id: %d nr_reqs: %d xact_id %d",
		__func__, __LINE__, sender_id, xact_id, nr_reqs, xact_id);
	ibapi_free_recv_buf(send_msg);

	return 0;
}

int handle_mrsw_commit(char *send_msg, unsigned int send_msg_size,
		       char *reply_addr,
		       unsigned int *reply_len, int sender_id)
{
	int xact_id, i;
	struct dsnvm_cd_xact_rec *currentry, *tempentry;
	struct dsnvm_cd_page_in_xact *htentry = NULL;
	struct status_reply_msg *reply;

	count_dsnvm_event(DSNVM_MRSW_MASTER_COMMIT);

	reply = (struct status_reply_msg *)reply_addr;
	*reply_len = sizeof(struct status_reply_msg);

	memcpy(&xact_id, send_msg + sizeof(int), sizeof(int));

	DSNVM_PRINTK("[%s:%d] Commit-Xact xact_id: %d",
		__func__, __LINE__, xact_id);

	/*
	 * Locking:	mrsw_xact_rec_lock
	 *		mrsw_xact_page_lock
	 */
	spin_lock(&mrsw_xact_rec_lock);
	list_for_each_entry_safe(currentry, tempentry, &mrsw_xact_list, next) {
		if (currentry->xact_id == xact_id) {
			/* Remove all related xact page records */
			spin_lock(&mrsw_xact_page_lock);
			for (i = 0; i < currentry->num_reqs; i++) {
				unsigned long dr_no = currentry->requests[i].dr_no;
				unsigned int dro = currentry->requests[i].dro;
				int hash_key = dr_no * DR_PAGE_NR + dro;

				DSNVM_PRINTK("[%s:%d] request %d dr_no %lu dro %u hashkey %d",
					__func__, __LINE__, i, dr_no, dro, hash_key);

				HASH_FIND_INT(ht_mrsw_page_in_xact, &hash_key, htentry);
				if (likely(htentry)) {
					HASH_DEL(ht_mrsw_page_in_xact, htentry);
					kfree(htentry);
				} else {
					/* No one should ever touched this record. */
					DSNVM_BUG("xact id: %d, dr_no: %lu, dro: %u", xact_id, dr_no, dro);
					spin_unlock(&mrsw_xact_page_lock);
					spin_unlock(&mrsw_xact_rec_lock);
					goto error;
				}
			}
			spin_unlock(&mrsw_xact_page_lock);

			/* Remove the xact record and free mem */
			list_del(&currentry->next);
			if (currentry->requests)
				kfree(currentry->requests);
			kfree(currentry);

			spin_unlock(&mrsw_xact_rec_lock);
			reply->status = DSNVM_REPLY_SUCCESS;

			DSNVM_PRINTK("[%s:%d] return successful",
				__func__, __LINE__);

			ibapi_free_recv_buf(send_msg);
			return 0;
		}
	}
	spin_unlock(&mrsw_xact_rec_lock);

error:
	reply->status = DSNVM_REPLY_INVALID;
	DSNVM_PRINTK("[%s:%d] return failed, xact_id: %d",
		__func__, __LINE__, xact_id);
	ibapi_free_recv_buf(send_msg);

	return 0;
}
#else
int handle_mrsw_begin(char *send_msg, unsigned int send_msg_size,
		      char *reply_addr, unsigned int *reply_len, int sender_id)
{
	DSNVM_BUG();
	return 0;
}

int handle_mrsw_commit(char *send_msg, unsigned int send_msg_size,
		       char *reply_addr,
		       unsigned int *reply_len, int sender_id)
{
	DSNVM_BUG();
	return 0;
}
#endif /* DSNVM_MODE_MRSW_IN_KERNEL */
