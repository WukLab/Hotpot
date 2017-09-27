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
 * Live Migration of ON_REGION
 *
 * During migration, normal page-fetchs are still severed by the original ON.
 * To start migration of an ON_REGION, no pages inside this region should be in
 * transaction, which means no update will be allowed during migration.
 * (Sounds like a stop-and-copy for transaction-commit.)
 *
 * To optimize for the case where transaction and migration contends the same
 * DN_REGION, we actually can implement pre-copy migration by push pages to new
 * owner iteratively with a typically very short stop-and copy phase.
 * (Check Live Migration of Virtual Machines)
 */

#include <linux/list.h>
#include <linux/errno.h>
#include <linux/ktime.h>
#include <linux/kthread.h>
#include <linux/hrtimer.h>
#include <linux/spinlock.h>

#include "dsnvm.h"

#if 0
#define DSNVM_PROFILE
#endif
#include "dsnvm-profile.h"

static DEFINE_SPINLOCK(on_region_proxy_lock);
static LIST_HEAD(on_region_proxy);

static int proxy_add(unsigned long dr_no, unsigned int new_owner)
{
	int ret;
	struct on_region_proxy *new, *p;

	new = kmalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		return -ENOMEM;

	new->dr_no = dr_no;
	new->new_owner = new_owner;
	getnstimeofday(&new->c_time);

	spin_lock(&on_region_proxy_lock);
	if (list_empty(&on_region_proxy)) {
		list_add(&new->next, &on_region_proxy);
		ret = 0;
		goto unlock;
	}

	list_for_each_entry(p, &on_region_proxy, next) {
		if (unlikely(p->dr_no == dr_no)) {
			kfree(new);

			/*
			 * TODO:
			 * Back and forth, this is possible.
			 * Remove proxy at some time.
			 */
			ret = -EEXIST;
			goto unlock;
		}
	}

	ret = 0;
	list_add(&new->next, &on_region_proxy);

unlock:
	spin_unlock(&on_region_proxy_lock);
	return ret;
}

/**
 * proxy_find_new_owner
 * @dr_no: dr_no to search in the proxy list
 *
 * RETURN:
 *	the node id of the new owner if found
 *	0 on failure
 */
unsigned int proxy_find_new_owner(unsigned long dr_no)
{
	unsigned int nid = 0;
	struct on_region_proxy *p;

	spin_lock(&on_region_proxy_lock);
	if (list_empty(&on_region_proxy))
		goto unlock;

	list_for_each_entry(p, &on_region_proxy, next) {
		if (p->dr_no == dr_no) {
			nid = p->new_owner;
			goto unlock;
		}
	}

unlock:
	spin_unlock(&on_region_proxy_lock);
	return nid;
}

void proxy_exit(void)
{
	struct on_region_proxy *p;

	while (!list_empty(&on_region_proxy)) {
		p = list_first_entry(&on_region_proxy, struct on_region_proxy, next);
		list_del(&p->next);
		kfree(p);
	}
}

static int check_new_on_integrity(struct on_region_info *on)
{
	int nr_missing;
	unsigned int dro;
	struct on_page_info *pi;

	for (dro = 0, nr_missing = 0; dro < DR_PAGE_NR; dro++) {
		pi = &on->mapping[dro];

		if (pi->local_pfn == 0) {
			pr_info("Missing dr_no: %lu, dro: %u", on->dr_no, dro);
			nr_missing++;
		}
	}

	if (nr_missing) {
		pr_info("Missing total %d pages", nr_missing);
		return -EFAULT;
	}

	clear_on_region_migrating_in(on);

	return 0;
}

/*
 * This function is called by the new owner only. And it is called during the
 * last notify from original owner.
 *
 * We merge pages of dn_region and replica_region into new on_region. Since the
 * original on_region only sent us a subset of ON pages.
 *
 * Entry with @dn->region_lock held if any.
 */
static int merge_dn_replica_to_new_on(unsigned long dr_no, int sender_id,
				      struct dn_region_info *dn,
				      struct replica_region_info *rn,
				      struct migrate_on_chunk_notify *header)
{

	int ret = 0;
	unsigned int dro;
	unsigned long on_pfn, replica_pfn, dn_coherent_pfn;
	struct on_region_info *on;
	struct dsnvm_page *page;

	/* MUST have been created in previous handler */
	on = ht_get_on_region(dr_no);
	if (!on) {
		DSNVM_BUG("dr_no: %lu, sender_id: %u", dr_no, sender_id);
		ret = -EPERM;
		goto out;
	}

	/* Save all history stat from ex */
	memcpy(on->nr_page_fetch, header->nr_page_fetch,
		sizeof(on->nr_page_fetch));
	memcpy(on->nr_commit_total, header->nr_commit_total,
		sizeof(on->nr_commit_total));
	memcpy(on->nr_commit_bytes_total, header->nr_commit_bytes_total,
		sizeof(on->nr_commit_bytes_total));

	for (dro = 0; dro < DR_PAGE_NR; dro++) {
		on_pfn = on->mapping[dro].local_pfn;
		replica_pfn = rn? rn->mapping[dro] : 0;
		dn_coherent_pfn = dn? dn->coherent_mapping[dro] : 0;

		/* New ON_REGION already has this page */
		if (on_pfn) {
			/*
			 * We are becoming the owner now. No need to store
			 * previous replica page, which may be created because
			 * user application specified a high replica-degree before.
			 */
			if (replica_pfn) {
				put_dsnvm_page_pfn(replica_pfn);
			}

			if (dn) {
				/*
				 * Means this DN has fetched this page before,
				 * and the first touch is write. So remote ON
				 * sent this page to new owner now.
				 */
				if (dn->mapping[dro] != 0 &&
				    dn->coherent_mapping[dro] == 0) {
					dn->coherent_mapping[dro] = on_pfn;
				}
			}
			continue;
		}

		/*
		 * Alright, original ON has not sent this page, which means
		 * we must have this page locally. Either in replica or in dn.
		 * Or, it might be a replica page shared by dn. Hmm.. god
		 */

		if (dn_coherent_pfn) {
			on->mapping[dro].local_pfn = dn_coherent_pfn;
			page = pfn_to_dsnvm_page(dn_coherent_pfn);

			DSNVM_SetPageUnevictable(page);

			/* Set PG_owner first then try to remove */
			DSNVM_SetPageOwner(page);
			lru_remove_page(page);

			/* replica page shared by dn */
			if (dn_coherent_pfn == replica_pfn) {
				clear_dsnvm_page_rr_info(page);
				DSNVM_ClearPageReplica(page);
			}
			continue;
		}

		if (replica_pfn) {
			on->mapping[dro].local_pfn = replica_pfn;
			page = pfn_to_dsnvm_page(replica_pfn);

			clear_dsnvm_page_rr_info(page);
			DSNVM_ClearPageReplica(page);
			DSNVM_SetPageUnevictable(page);

			DSNVM_SetPageOwner(page);
			lru_remove_page(page);
			continue;
		}

		/* Should have this page locally. This is BUG if reachs here. */
		DSNVM_WARN_ONCE("dr_no: %lu, dro: %d", dr_no, dro);
	}

	ret = check_new_on_integrity(on);

out:
	return ret;
}

/*
 * This function describes:
 *	Handler for migration notify
 *
 * Related IB API:
 *	ibapi_send_reply
 *
 * Note that:
 * The original ON will scan its dn_list and send us only pages that we have
 * not fetched. For those fetched pages, they will be demoted to REPLICA page
 * during dsnvm_file_release (check dn.c for details.), or they are still
 * reside in DN region.
 *
 * Anyway.. things become very very tricky..
 */
int handle_migrate_on_chunk_finished_notify(char *msg, char *reply_addr,
					    unsigned int *reply_len, int sender_id)
{
	int ret;
	struct migrate_on_chunk_notify *header;
	struct status_reply_msg *reply;
	unsigned long dr_no;
	unsigned int new_owner;
	struct dn_region_info *dn;
	struct replica_region_info *rn;

	header = (struct migrate_on_chunk_notify *)msg;
	reply = (struct status_reply_msg *)reply_addr;
	reply->status = DSNVM_REPLY_SUCCESS;
	*reply_len = sizeof(*reply);

	dr_no = header->dr_no;
	new_owner = header->new_owner;

	DSNVM_PRINTK_MIGRATE("dr_no: %lu, new_owner: %u, sender_id: %d",
		dr_no, new_owner, sender_id);

	if (new_owner != DSNVM_LOCAL_ID) {
		dn = ht_get_dn_region(dr_no);
		if (dn) {
			spin_lock(&dn->region_lock);
			dn->owner_id = new_owner;
			dsnvm_flush_buffer(&dn->owner_id, sizeof(dn->owner_id));
			spin_unlock(&dn->region_lock);

			DSNVM_PRINTK_MIGRATE("dr_no: %lu, dn update ownership from %d -> %u",
				dr_no, sender_id, new_owner);
		}

		rn = ht_get_replica_region(dr_no);
		if (rn) {
			spin_lock(&rn->region_lock);
			rn->owner_id = new_owner;
			dsnvm_flush_buffer(&rn->owner_id, sizeof(rn->owner_id));
			spin_unlock(&rn->region_lock);

			DSNVM_PRINTK_MIGRATE("dr_no: %lu, rn update ownership from %d -> %u",
				dr_no, sender_id, new_owner);
		}
	} else {
		/*
		 * Why hold @dn->region_lock?
		 *
		 * Short answer:
		 * To serialize with __free_dn_region_pages().
		 *
		 * Boring answer:
		 * Migration make things complicated. Incoming migration can
		 * happen when a dn region is going to be freed. If it happens,
		 * we have to make sure two things: 1) no REPLICA and ON region
		 * exist at the same time. 2) local cached coherent pages are
		 * transferred to new ON properly.
		 *
		 * Serialize with __free_dn_region_pages can guarantee both.
		 *
		 * If __free_dn_region_pages() get the lock first, then it will
		 * demote all its coherent pages to REPLICA pages. When we acquired
		 * lock, we will have all the pages ready in the @rn.
		 *
		 * If we get the lock first, then we will change @dn to make it
		 * have the DN==ON case feeling, and free REPLICA region. Later
		 * when __free_dn_region_pages acquired the lock, it will behave
		 * like the DN==ON case properly.
		 *
		 *    - Jesus.
		 */

		dn = ht_get_dn_region(dr_no);
		if (dn)
			spin_lock(&dn->region_lock);

		/* Find rn after locking */
		rn = ht_get_replica_region(dr_no);

		ret = merge_dn_replica_to_new_on(dr_no, sender_id, dn, rn, header);
		if (unlikely(ret)) {
			DSNVM_WARN("Fail to merge dr_no: %lu", dr_no);
			reply->status = DSNVM_REPLY_FAIL_TO_MERGE;
		}

		/*
		 * New ON_REGION is all set.
		 * Say goodbye to its replica copy if any.
		 */
		if (rn)
			free_dsnvm_replica_region_info(rn);

		if (dn) {
			dn->owner_id = new_owner;
			dsnvm_flush_buffer(&dn->owner_id, sizeof(dn->owner_id));
			spin_unlock(&dn->region_lock);
		}

		count_dsnvm_event(DSNVM_NR_REGION_MIGRATED_IN);
	}

	return 0;
}

/*
 * This function describes:
 *	Send notifications to all on-line clients about ownership change
 *
 * Related IB API:
 *	ibapi_send_reply
 */
static int migrate_on_chunk_finished_notify(struct on_region_info *on,
					    unsigned int new_owner)
{
	int nid, ret = -EFAULT;
	struct status_reply_msg reply;
	struct migrate_on_chunk_notify *header;

	header = kmalloc(sizeof(*header), GFP_KERNEL);
	if (!header)
		return -ENOMEM;

	header->op = DSNVM_OP_MIGRATE_ON_CHUNK_NOTIFY;
	header->dr_no = on->dr_no;
	header->new_owner = new_owner;

	/* Pass hitory stats to new owner */
	memcpy(header->nr_page_fetch, on->nr_page_fetch,
		sizeof(header->nr_page_fetch));
	memcpy(header->nr_commit_total, on->nr_commit_total,
		sizeof(header->nr_commit_total));
	memcpy(header->nr_commit_bytes_total, on->nr_commit_bytes_total,
		sizeof(header->nr_commit_bytes_total));

	/* Send to new owner first, let him prepare */
	ibapi_send_reply(new_owner, (char *)header, sizeof(*header),
		(char *)&reply);
	if (unlikely(reply.status != DSNVM_REPLY_SUCCESS)) {
		DSNVM_PRINTK_MIGRATE("new_owner %u refused migration dr_no %lu; reason: %s",
			new_owner, on->dr_no, dsnvm_status_string(reply.status));
		goto out;
	}

	/* Send to server */
	ibapi_send_reply(0, (char *)header, sizeof(*header),
		(char *)&reply);
	if (unlikely(reply.status != DSNVM_REPLY_SUCCESS)) {
		DSNVM_PRINTK_MIGRATE("CD refused migration dr_no: %lu new_owner: %u",
			on->dr_no, new_owner);
		goto out;
	}

	/* Now the rest */
	for_each_set_bit(nid, DSNVM_CLIENT_MACHINES, DSNVM_MAX_NODE) {
		if (nid == DSNVM_LOCAL_ID)
			continue;

		if (nid == new_owner)
			continue;

		DSNVM_PRINTK_MIGRATE("Send to node: %d", nid);

		ibapi_send_reply(nid, (char *)header, sizeof(*header),
			(char *)&reply);
	}

	ret = 0;
out:
	kfree(header);
	return ret;
}

static int demote_all_on_pages(struct on_region_info *on,
			       struct replica_region_info **passed_rn)
{
	int i;
	struct replica_region_info *rn;

	rn = find_or_alloc_replica(on->dr_no, DSNVM_LOCAL_ID);
	if (unlikely(!rn))
		return -ENOMEM;
	replica_region_set_flag(rn, _REPLICA_IN_MIGRATION_CONTEXT);
	*passed_rn = rn;

	for (i = 0; i < DR_PAGE_NR; i++) {
		struct on_page_info *on_page;
		struct dsnvm_page *page;
		unsigned long pfn, old_pfn;

		on_page = &on->mapping[i];
		pfn = on_page->local_pfn;

		/*
		 * If we have an existing replica page, free it.
		 * Since replica pages were put into LRU, use
		 * put page.
		 */
		old_pfn = rn->mapping[i];
		if (old_pfn)
			put_dsnvm_page_pfn(old_pfn);

		/* Set the new mapping */
		rn->mapping[i] = pfn;
		dsnvm_flush_buffer(&rn->mapping[i], sizeof(rn->mapping[i]));

		/* Demote page to inactive, a.k.a Replica */
		page = pfn_to_dsnvm_page(pfn);

		DSNVM_ClearPageOwner(page);
		DSNVM_ClearPageUnevictable(page);
		DSNVM_SetPageReplica(page);
		set_dsnvm_page_rr_info(page, rn);
		lru_add_inactive(page);
	}
	return 0;
}

static int demote_untouched_on_pages(struct on_region_info *on,
				     struct dn_region_info *dn,
				     struct replica_region_info **passed_rn,
				     int *nr_demoted_pages)
{
	int i;
	struct replica_region_info *rn;

	rn = find_or_alloc_replica(on->dr_no, DSNVM_LOCAL_ID);
	if (unlikely(!rn))
		return -ENOMEM;
	replica_region_set_flag(rn, _REPLICA_IN_MIGRATION_CONTEXT);
	*passed_rn = rn;

	*nr_demoted_pages = 0;
	for (i = 0; i < DR_PAGE_NR; i++) {
		/*
		 * 1) This page has not been touched,
		 * 2) or the first touch is write
		 * (Check do_local_owner_fault() for detail)
		 *
		 * Then we need to demote this page a replica page.
		 */
		if (dn->coherent_mapping[i] == 0) {
			struct on_page_info *on_page;
			unsigned long old_pfn, pfn;
			struct dsnvm_page *page;

			on_page = &on->mapping[i];
			pfn = on_page->local_pfn;

			old_pfn = rn->mapping[i];
			if (old_pfn)
				put_dsnvm_page_pfn(old_pfn);

			/* Set the new mapping */
			rn->mapping[i] = pfn;
			dsnvm_flush_buffer(&rn->mapping[i], sizeof(rn->mapping[i]));

			/* Demote page to inactive, a.k.a Replica */
			page = pfn_to_dsnvm_page(pfn);
			DSNVM_ClearPageOwner(page);
			DSNVM_ClearPageUnevictable(page);
			DSNVM_SetPageReplica(page);

			set_dsnvm_page_rr_info(page, rn);
			lru_add_inactive(page);

			*nr_demoted_pages += 1;
		}
	}

	if (*nr_demoted_pages == 0) {
		free_dsnvm_replica_region_info(rn);
		*passed_rn = NULL;
	}

	return 0;
}

/*
 * This function describes:
 *	DN's handler for a new migrated ON chunk
 *
 * Related IB APIs:
 *	ibapi_atomic_send_yy
 *
 * Note that:
 * Here, we don't check if original ON_REGION has finished sending
 * pages. We wait until the final notify, then we check if we have
 * all the ON_REGION pages.
 */
int handle_migrate_on_chunk(int sender_id, int nr_reqs, struct atomic_struct *reqs,
			    char *output_buf, unsigned int *output_size, bool no_page)
{
	struct on_region_info *on;
	struct migrate_on_chunk_header *header;
	unsigned int *dro_array = NULL, dro;
	int i, nr_pages;
	unsigned long dr_no, pfn;
	struct status_reply_msg *reply;

	/* Fill reply info first */
	reply = (struct status_reply_msg *)output_buf;
	reply->status = DSNVM_REPLY_SUCCESS;
	*output_size = sizeof(*reply);

	header = reqs[0].vaddr;
	dr_no = header->dr_no;
	nr_pages = header->nr_pages;

	DSNVM_PRINTK_MIGRATE("Sender: %d, dr_no: %lu, nr_pages: %d, no_page: %d",
		sender_id, dr_no, nr_pages, no_page);

	/*
	 * A special case where we already have fetched all pages within this
	 * region in a coherent way. So just allocate an ON_REGION and return:
	 */
	if (no_page)
		goto alloc;

	dro_array = reqs[1].vaddr;

	/* We have 2 reqs for metadata */
	if (unlikely(nr_pages != nr_reqs - 2)) {
		DSNVM_BUG("unmatched: nr_pages: %d, nr_reqs: %d",
			nr_pages, nr_reqs);
		reply->status = DSNVM_REPLY_INVALID;
		goto out;
	}

	/*
	 * Note that:
	 *
	 * Truly, it will allocate an on_region and insert it into
	 * hashtable. And at the same time, it is possible that this
	 * node already has a replica region. However, this is not:
	 *	WARN_ON(REGION_IS_LOCAL(r) && REGION_IS_REPLICA(r))
	 *
	 * Because the owner_id field of DN_REGION still point to the
	 * original owner! Moreover, the whole cluster still know that
	 * the original owner is the owner for this region.
	 */
alloc:
	on = find_or_alloc_on_region(dr_no);
	if (unlikely(!on)) {
		reply->status = DSNVM_ENOMEM;
		goto out;
	}

	mark_on_region_migrating_in(on);

	/* Yes, Virginia, we are done. */
	if (no_page)
		goto out;

	for (i = 0; i < nr_pages; i++) {
		void *src, *dst;
		struct dsnvm_page *page;

		dro = dro_array[i];
		pfn = alloc_dsnvm_page_pfn();
		if (!pfn) {
			DSNVM_WARN("OOM");
			reply->status = DSNVM_ENOMEM;
			goto out;
		}

		dst = (void *)pfn_to_dsnvm_virt(pfn);
		src = (void *)reqs[i + 2].vaddr;

		DSNVM_PRINTK_MIGRATE("dro: %u, copy %p -> %p", dro, src, dst);

		memcpy(dst, src, PAGE_SIZE);
		dsnvm_flush_buffer(dst, PAGE_SIZE);

		on->mapping[dro].local_pfn = pfn;
		dsnvm_flush_buffer(&on->mapping[dro].local_pfn, sizeof(unsigned long));

		page = pfn_to_dsnvm_page(pfn);
		DSNVM_SetPageOwner(page);
		DSNVM_SetPageUnevictable(page);
		DSNVM_SetPageCommitted(page);
	}

	count_dsnvm_events(DSNVM_NR_PAGES_MIGRATED_IN, nr_pages);

out:
	for (i = 0; i < nr_reqs; i++) {
                if (reqs[i].vaddr)
                        ibapi_free_recv_buf(reqs[i].vaddr);
	}

	return 0;
}

/* Send all atomic requests to remote new owner */
static int do_migrate_on_chunk(struct on_region_info *on,
			       unsigned int new_owner, int *nr_sent_pages)
{
	int ret, i;
	int nr_pages, nr_round, reply;
	struct migrate_on_chunk_header *header;
	struct atomic_struct *reqs;
	unsigned int *dro_array;

	ret = -ENOMEM;
	reqs = kmalloc(sizeof(*reqs) * (MAX_NR_PAGES_PER_REQUEST + 2), GFP_KERNEL);
	if (!reqs)
		return ret;

	dro_array = kmalloc(sizeof(*dro_array) * MAX_NR_PAGES_PER_REQUEST, GFP_KERNEL);
	if (!dro_array) {
		kfree(reqs);
		return ret;
	}

	header = kmalloc(sizeof(*header), GFP_KERNEL);
	if (!header) {
		kfree(dro_array);
		kfree(reqs);
		return ret;
	}

	ret = 0;

	/* Fill first 2 header which are metadata */
	header->op = DSNVM_OP_MIGRATE_ON_CHUNK;
	header->dr_no = on->dr_no;
	reqs[0].vaddr = header;
	reqs[0].len = sizeof(*header);
	reqs[1].vaddr = dro_array;

	nr_round = 0;
	nr_pages = 0;
	*nr_sent_pages = 0;

	for (i = 0; i < DR_PAGE_NR; i++) {
		struct on_page_info *on_page;
		unsigned long pfn;

		on_page = &on->mapping[i];
		pfn = on_page->local_pfn;

		/* Skip if this node alreay have a committed coherent page */
		if (test_bit(new_owner, on_page->dn_list))
			continue;

		reqs[nr_pages + 2].vaddr = (void *)(pfn << PAGE_SHIFT);
		reqs[nr_pages + 2].len = PAGE_SIZE;
		dro_array[nr_pages++] = i;

		DSNVM_PRINTK_MIGRATE("Found new dro: %u, nr_pages: %d", i, nr_pages-1);

		/* Send this packet */
		if (nr_pages == MAX_NR_PAGES_PER_REQUEST) {
			header->nr_pages = MAX_NR_PAGES_PER_REQUEST;
			reqs[1].len = sizeof(*dro_array) * nr_pages;

			DSNVM_PRINTK_MIGRATE("Round: %d, nr_pages: %d", nr_round, nr_pages);

			ibapi_atomic_send_yy(new_owner, reqs, nr_pages + 2, (void *)&reply);

			if (unlikely(reply != DSNVM_REPLY_SUCCESS)) {
				DSNVM_WARN();
				goto out;
			}

			nr_pages = 0;
			nr_round++;
			*nr_sent_pages += MAX_NR_PAGES_PER_REQUEST;
		}
	}

	if (nr_pages > 0) {
		header->nr_pages = nr_pages;
		reqs[1].len = sizeof(*dro_array) * nr_pages;

		DSNVM_PRINTK_MIGRATE("Round: %d, nr_pages: %d", nr_round, nr_pages);

		ibapi_atomic_send_yy(new_owner, reqs, nr_pages + 2, (void *)&reply);
		if (unlikely(reply != DSNVM_REPLY_SUCCESS))
			DSNVM_WARN();

		nr_round++;
		*nr_sent_pages += nr_pages;
	}

	/*
	 * A special case where remote new owner has fetched all pages
	 * in a coherent way. Anyway, we are lucky. But at least tell
	 * him what is going on:
	 */
	if (unlikely(nr_round == 0)) {
		header->op = DSNVM_OP_MIGRATE_ON_CHUNK_NO_PAGE;
		header->nr_pages = 0;

		DSNVM_PRINTK_MIGRATE("no_page case for dr_no: %lu, to node: %d",
			on->dr_no, new_owner);

		ibapi_atomic_send_yy(new_owner, reqs, 1, (void *)&reply);
		if (unlikely(reply != DSNVM_REPLY_SUCCESS))
			DSNVM_WARN();
	}

	DSNVM_PRINTK_MIGRATE("Total nr of sent pages: %d, total rounds: %d",
		*nr_sent_pages, nr_round);

out:
	kfree(header);
	kfree(reqs);
	kfree(dro_array);
	return ret;
}

/* Entry with @region_lock held */
static __always_inline void
update_local_dn_region(struct dn_region_info *dn, unsigned int new_owner)
{
	if (dn) {
		dn->owner_id = new_owner;
		dsnvm_flush_buffer(&dn->owner_id, sizeof(dn->owner_id));
	}
}

/*
 * This function describes:
 * 	ON wants to migrate a ON chunk to a new DN
 *
 * Related IB APIs:
 *	ibapi_atomic_send_yy
 */
int migrate_on_chunk(unsigned long dr_no, unsigned int new_owner)
{
	int ret, nr_demoted_pages = 0, nr_sent_pages = 0;
	struct on_region_info *on;
	struct dn_region_info *dn;
	struct replica_region_info *rn = NULL;
	DEFINE_PROFILE_TS(t_start, t_end, t_diff)

	__START_PROFILE(t_start);

	if (!test_bit(new_owner, DSNVM_CLIENT_MACHINES)) {
		DSNVM_BUG("new_owner: %u", new_owner);
		return -EINVAL;
	}

	on = ht_get_on_region(dr_no);
	if (unlikely(!on)) {
		DSNVM_BUG("dr_no: %lu", dr_no);
		return -EINVAL;
	}

	/* Check if any ON_PAGES are in transaction: */
	spin_lock(&on->region_lock);
	if (unlikely(is_on_region_in_transaction(on))) {
		spin_unlock(&on->region_lock);
		DSNVM_PRINTK_MIGRATE("dr_no: %lu is in xact, abort migrating", dr_no);
		return -EBUSY;
	}

	/*
	 * Mark this ON_REGION is currently migrating out.
	 * No more transaction afterwards, but it still can serve
	 * normal page-fetch:
	 */
	mark_on_region_migrating_out(on);
	spin_unlock(&on->region_lock);

#if 0
#define pr_fail_line()	pr_info("[%s] Fail at line: %d", __func__, __LINE__)
#else
#define pr_fail_line()	do { } while (0)
#endif

#define unlock_dn_region(dn)			\
do {						\
	if (dn)					\
		spin_unlock(&dn->region_lock);	\
} while (0)

	dn = ht_get_dn_region(dr_no);
	if (unlikely(!dn)) {
		/*
		 * If there is no local application currently using this region.
		 * then there is no DN_REGION in the hashtable. Which means, we
		 * need to demote all ON_REGION pages to REPLICA_REGION pages.
		 *
		 * Pages state transition: active-committed -> inactive-committed
		 */
		ret = demote_all_on_pages(on, &rn);
		if (ret) {
			pr_fail_line();
			return ret;
		}
		nr_demoted_pages = DR_PAGE_NR;
	} else {
		/*
		 * Demote pages that have not been touched by local application OR
		 * pages that the first touch is WRITE, then there is no coherent_mapping
		 * for this specific write-first page:
		 *
		 * Hold dn->region_lock in case it is freed in the middle.
		 */
		spin_lock(&dn->region_lock);
		ret = demote_untouched_on_pages(on, dn, &rn, &nr_demoted_pages);
		if (ret) {
			spin_unlock(&dn->region_lock);
			pr_fail_line();
			return ret;
		}
	}

	/* Send all data pages to remote DN: */
	ret = do_migrate_on_chunk(on, new_owner, &nr_sent_pages);
	if (ret) {
		pr_fail_line();
		unlock_dn_region(dn);
		return ret;
	}

	count_dsnvm_events(DSNVM_NR_PAGES_MIGRATED_OUT, nr_sent_pages);

	/* Notify all online clients and CD */
	ret = migrate_on_chunk_finished_notify(on, new_owner);
	if (ret) {
		pr_fail_line();
		unlock_dn_region(dn);
		return ret;
	}

	/* Add to proxy list before removing ON_REGION */
	proxy_add(dr_no, new_owner);

	/*
	 * Final step, update local dn region if any,
	 * then we are safe to free local on_region
	 */
	update_local_dn_region(dn, new_owner);
	unlock_dn_region(dn);

	remove_on_region(dr_no);

	/* Only at this point, replica_region is visible */
	if (likely(rn))
		replica_region_clear_flag(rn, _REPLICA_IN_MIGRATION_CONTEXT);

	__END_PROFILE(t_start, t_end, t_diff);
	__PROFILE_PRINTK("Mig Lat: %lldns dr_no: %lu new_owner: %u nr_demoted: %d nr_sent: %d",
		timespec_to_ns(&t_diff), dr_no, new_owner, nr_demoted_pages, nr_sent_pages);

	return 0;
#undef pr_fail_line
#undef unlock_dn_region
}

static __always_inline void
shift_record(struct on_region_info *on, unsigned int nid_hottest)
{
	memmove(&on->record_hottest[0], &on->record_hottest[1],
		sizeof(unsigned int) * (NR_RECORD_HOTTEST_NODE - 1));
	on->record_hottest[NR_RECORD_HOTTEST_NODE - 1] = nid_hottest;
}

static __always_inline bool
check_history_record(struct on_region_info *on, unsigned int nid_hottest)
{
	int i;
	bool answer = true;

	for (i = 0; i < NR_RECORD_HOTTEST_NODE; i++) {
		if (on->record_hottest[i] != nid_hottest) {
			answer = false;
			break;
		}
	}

	return answer;
}

/*
 * Minimum number of commit bytes that a node can be
 * considered as a condidate for migration.
 */
long min_bytes_per_tw = 30*1024;

/*
 * This determins the minimum number of pages that a node must have of this
 * region to be considered as a condidate for migration.
 * The larger this parameter is, the less the migration cost is.
 */
int min_nr_page_fetched = DR_PAGE_NR / 32;

unsigned long wakeup_interval_ms = 1000*15;

/**
 * on_need_migration()
 *
 * Check if @on needs to be migrated to another hot node
 */
static bool on_need_migration(struct on_region_info *on, unsigned int *new_owner)
{
	int i;
	unsigned int nid_hottest;
	atomic64_t nr_commit_bytes[DSNVM_MAX_NODE], max;

	/* Add this time-window's stat to total and then clear */
	for (i = 0; i < DSNVM_MAX_NODE; i++) {
		atomic_add(atomic_read(&on->nr_commit[i]),
			&on->nr_commit_total[i]);

		atomic64_add(atomic64_read(&on->nr_commit_bytes[i]),
			&on->nr_commit_bytes_total[i]);
	}
	memcpy(nr_commit_bytes, on->nr_commit_bytes, sizeof(nr_commit_bytes));
	memset(on->nr_commit, 0, sizeof(on->nr_commit));
	memset(on->nr_commit_bytes, 0, sizeof(on->nr_commit_bytes));

	/*
	 * Even if migration is disabled, the stats of this time-window
	 * still need to be cleaned up.
	 */
	if (!enable_migration)
		return false;

	nid_hottest = DSNVM_LOCAL_ID;
	atomic64_set(&max, 0);

	/* Find the hottest node of this time-window */
	for (i = 0; i < DSNVM_MAX_NODE; i++) {
		if (unlikely(!test_bit(i, DSNVM_CLIENT_MACHINES)))
			continue;

		if (atomic64_read(&nr_commit_bytes[i]) > atomic64_read(&max)) {
			nid_hottest = i;
			atomic64_set(&max, atomic64_read(&nr_commit_bytes[i]));
		}
	}

	if (nid_hottest == DSNVM_LOCAL_ID) {
		DSNVM_PRINTK_MIGRATE("Myself is the hottest for dr_no: %lu",
			on->dr_no);
		shift_record(on, DSNVM_LOCAL_ID);
		return false;
	}

	/* Check time-window throughput: */
	if (atomic64_read(&max) < min_bytes_per_tw) {
		count_dsnvm_event(DSNVM_MIGRATE_REJECTED_BY_COMMIT);
		DSNVM_PRINTK_MIGRATE("Node: %u dr_no: %lu; "
			"Throuput: %ld bytes, Min_Throughput: %ld bytes",
			nid_hottest, on->dr_no, atomic64_read(&max), min_bytes_per_tw);
		shift_record(on, 0);
		return false;
	}

	/* Check migration cost: */
	if (atomic_read(&on->nr_page_fetch[nid_hottest]) < min_nr_page_fetched) {
		count_dsnvm_event(DSNVM_MIGRATE_REJECTED_BY_COST);
		DSNVM_PRINTK_MIGRATE("Node: %u dr_no: %lu; "
			"Cost: %d, Max_Cost: %d", nid_hottest, on->dr_no,
			DR_PAGE_NR - atomic_read(&on->nr_page_fetch[nid_hottest]),
			DR_PAGE_NR - min_nr_page_fetched);
		shift_record(on, nid_hottest);
		return false;
	}
#if 0
	/*
	 * Shift into record.
	 * Get an answer of to migrate or not to migrate.
	 */
	if (!check_history_record(on, nid_hottest)) {
		DSNVM_PRINTK_MIGRATE("Node: %u dr_no: %lu fail to pass history record check",
			nid_hottest, on->dr_no);
		shift_record(on, nid_hottest);
		return false;
	}
#endif
	*new_owner = nid_hottest;

	DSNVM_PRINTK_MIGRATE("Decide to migrate dr_no: %lu to nid_hottest: %u",
		on->dr_no, nid_hottest);

	return true;
}

static struct task_struct *dsnvm_migrated;
static wait_queue_head_t dsnvm_migrated_wait;

static struct hrtimer dsnvm_migrated_wakeup_timer;

static void __dsnvm_migrated_func(void)
{
	int i;

	/* Safer to go through list instead of hashtable, beacuse
	 * ON region may be removed inside this loop. */
	for_each_set_bit(i, onmap_slot, DSNVM_MAX_ON_REGION_INFO) {
		struct on_region_info *on = dsnvm_onmap + i;
		unsigned long dr_no;
		unsigned int new_owner;
		int ret;

		if (on_need_migration(on, &new_owner)) {
			dr_no = on->dr_no;
			ret = migrate_on_chunk(on->dr_no, new_owner);
			if (ret == -EBUSY) {
				DSNVM_PRINTK_MIGRATE("Migration conflicts with xact (dr_no: %lu)",
					on->dr_no);
			}
			count_dsnvm_event(DSNVM_NR_REGION_MIGRATED_OUT);

			DSNVM_PRINTK("Region dr_no: %lu was migrated to node: %u",
				dr_no, new_owner);
		}
	}
}

static int dsnvm_migrated_func(void *data)
{
	DEFINE_WAIT(wait);

	current->flags |= PF_MEMALLOC;

	pr_crit("dsnvm-migrated (PID %d) is running", current->pid);

	for ( ; ; ) {
		prepare_to_wait(&dsnvm_migrated_wait, &wait, TASK_INTERRUPTIBLE);
		schedule();
		finish_wait(&dsnvm_migrated_wait, &wait);

		if (kthread_should_stop())
			break;

		count_dsnvm_event(DSNVM_MIGRATED_RUN);
		__dsnvm_migrated_func();
	}

	pr_crit("dsnvm-migrated (PID %d) exited", current->pid);

	return 0;
}

bool enable_migration = false;

static enum hrtimer_restart wakeup_dsnvm_migrated(struct hrtimer *t)
{
	/* migrate-deamon is migrating */
	if (!waitqueue_active(&dsnvm_migrated_wait))
		goto out;

	wake_up_interruptible(&dsnvm_migrated_wait);

out:
        hrtimer_forward_now(t, ms_to_ktime(wakeup_interval_ms));
        return HRTIMER_RESTART;
}

int init_dsnvm_migrated(void)
{
	init_waitqueue_head(&dsnvm_migrated_wait);
	dsnvm_migrated = kthread_run(dsnvm_migrated_func, NULL, "dsnvm-migrated");
	if (IS_ERR(dsnvm_migrated)) {
		pr_err("error: fail to start dsnvm-migrated");
		return PTR_ERR(dsnvm_migrated);
	}

	hrtimer_init(&dsnvm_migrated_wakeup_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	dsnvm_migrated_wakeup_timer.function = wakeup_dsnvm_migrated;
	hrtimer_start(&dsnvm_migrated_wakeup_timer,
		ms_to_ktime(wakeup_interval_ms), HRTIMER_MODE_REL);

	return 0;
}

void stop_dsnvm_migrated(void)
{
	hrtimer_cancel(&dsnvm_migrated_wakeup_timer);
	if (dsnvm_migrated) {
		kthread_stop(dsnvm_migrated);
		dsnvm_migrated = NULL;
	}
}
