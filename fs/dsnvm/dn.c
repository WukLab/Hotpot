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
 * This file describes functions for Data Node (DN).
 */

#include <linux/time.h>
#include <linux/kref.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>

#include "dsnvm.h"
#include "dsnvm-vm.h"

#if 0
#define DSNVM_PROFILE
#endif
#include "dsnvm-profile.h"

/*
 * Hashtable of all open regions, in the context of DN.
 * Note that this hashtable only contains *opened* regions.
 */
static DEFINE_HASHTABLE(ht_dn_region, HASH_TABLE_SIZE_BIT);
static DEFINE_SPINLOCK(ht_lock);

int __must_check ht_add_dn_region(struct dn_region_info *new)
{
	struct dn_region_info *r;

	if (!new)
		return -EINVAL;

	spin_lock(&ht_lock);
	hash_for_each_possible(ht_dn_region, r, hlist, new->dr_no) {
		if (unlikely(r->dr_no == new->dr_no)) {
			spin_unlock(&ht_lock);
			return -EEXIST;
		}
	}
	hash_add(ht_dn_region, &new->hlist, new->dr_no);
	spin_unlock(&ht_lock);

	return 0;
}

/**
 * ht_remove_dn_region
 *
 * Remove a dn_region_info structure from the ht_dn_region hashtable.
 * Note that it succeed if and only if no one is using this dn_region.
 * This function is called when a dsnvm_client_file is going to close().
 */
int ht_remove_dn_region(unsigned long dr_no)
{
	struct dn_region_info *r;

	spin_lock(&ht_lock);
	hash_for_each_possible(ht_dn_region, r, hlist, dr_no) {
		if (likely(r->dr_no == dr_no)) {
#if 0
			if (likely(atomic_read(&r->region_ref.refcount) == 1)) {
				hash_del(&r->hlist);
				spin_unlock(&ht_lock);
				/*
				 * dn_region_info can not be freed, since
				 * they are embedded in dsnvm_client_file.
				 */
				return 0;
			} else {
				spin_unlock(&ht_lock);
				return -EBUSY;
			}
#endif
			hash_del(&r->hlist);
			spin_unlock(&ht_lock);
			return 0;
		}
	}
	spin_unlock(&ht_lock);

	return -ENOENT;
}

struct dn_region_info *ht_get_dn_region(unsigned long dr_no)
{
	struct dn_region_info *r;

	spin_lock(&ht_lock);
	hash_for_each_possible(ht_dn_region, r, hlist, dr_no) {
		if (likely(r->dr_no == dr_no)) {
			kref_get(&r->region_ref);
			spin_unlock(&ht_lock);
			return r;
		}
	}
	spin_unlock(&ht_lock);

	return NULL;
}

static void ht_dn_region_release(struct kref *ref)
{
	struct dn_region_info *r = container_of(ref, struct dn_region_info, region_ref);
	WARN(1, "Error usage of get/put of dn_region: %ld", r->dr_no);
}

void ht_put_dn_region(struct dn_region_info *r)
{
	if (!r)
		return;

	if (likely(r && hash_hashed(&r->hlist)))
		kref_put(&r->region_ref, ht_dn_region_release);
	else
		DSNVM_WARN();
}

/**
 * dn_region_set_coherent_mapping
 * @r:			DN region
 * @dro:		dr offset
 * @pfn:		Newly allocated DSNVM page
 * @is_coherent:	This is a coherent/committed mapping
 *
 * Establish a mapping between DR_NO+DRO --> PFN and set its corresponding
 * mapping valid bit. Both mapping and coherence_mapping are set.
 */
void dn_region_set_coherent_mapping(struct dn_region_info *r, unsigned int dro,
				    unsigned long pfn, bool is_coherent)
{
	if (unlikely(!r || !DRO_VALID(dro) || !pfn_is_dsnvm(pfn))) {
		DSNVM_BUG();
		return;
	}

	spin_lock(&r->page_lock[dro]);
	r->mapping[dro] = pfn;
	if (is_coherent)
		r->coherent_mapping[dro] = pfn;
	dn_region_set_mapping_valid(r, dro);
	spin_unlock(&r->page_lock[dro]);
}

/*
 * Only set mapping, not touching coherent_mapping
 */
void dn_region_set_mapping(struct dn_region_info *r, unsigned int dro,
			   unsigned long pfn)
{
	if (unlikely(!r || !DRO_VALID(dro) || !pfn_is_dsnvm(pfn))) {
		DSNVM_BUG();
		return;
	}

	spin_lock(&r->page_lock[dro]);
	r->mapping[dro] = pfn;
	spin_unlock(&r->page_lock[dro]);
}

/**
 * dn_region_clear_mapping
 *
 * Clear a mapping between DR_NO+DRO --> PFN
 * and clear its corresponding valid mapping bit.
 */
unsigned long dn_region_clear_mapping(struct dn_region_info *r,
				      unsigned int dro)
{
	unsigned long pfn;

	if (unlikely(!r || !DRO_VALID(dro))) {
		DSNVM_BUG();
		return 0;
	}

	spin_lock(&r->page_lock[dro]);
	pfn = r->mapping[dro];
	r->mapping[dro] = 0;
	r->coherent_mapping[dro] = 0;
	dn_region_clear_mapping_valid(r, dro);
	spin_unlock(&r->page_lock[dro]);

	return pfn;
}

/*
 * Free COW dirty pages, which are not commited by user.
 * Demote commited pages, that were fetched from remote ON, to local REPLICA
 * page. If local already have this replica page, then free the fetched page.
 * (Page state transition: Active-Committed -> Inactive-Committed)
 *
 * Pages are pulled from LRU list, since we are using put_dsnvm_page_pfn().
 * Also, all related rmap should be removed.
 *
 * Entry with @dn->region_lock held.
 */
static void __free_dn_region_pages(struct dsnvm_client_file *f,
				   struct dn_region_info *r,
				   unsigned long dr_index)
{
	int dro;
	unsigned long pfn, coherent_pfn;
	struct dsnvm_page *coherent_page;
	struct replica_region_info *replica;
	unsigned long user_vaddr;

	WARN_ON(REGION_IS_LOCAL(r) && REGION_IS_REPLICA(r));

	user_vaddr = f->vm_start + dr_index * DR_PAGE_NR * PAGE_SIZE;

	/*
	 * mapping[dro] may points to COW dirty page that has not been committed,
	 * or points to a local ON or REPLICA page, or points to a commited-page
	 * fetched from remote ON.
	 *
	 * coherent_mapping[dro] always points to commited page, either local
	 * ON/REPLICA case or remote ON case.
	 */
	for (dro = 0; dro < DR_PAGE_NR; dro++, user_vaddr += PAGE_SIZE) {
		pfn = r->mapping[dro];
		coherent_pfn = r->coherent_mapping[dro];

		/*
		 * mapping[dro] == 0 means:
		 * 1) The page has not been accessed
		 * 2) The page might be reclaimed
		 */
		if (!pfn)
			continue;

		if (pfn != coherent_pfn) {
			/*
			 * This is COW dirty page that
			 * has not been committed, discards it
			 */
			put_dsnvm_page_pfn(pfn);
		}

		if (!coherent_pfn)
			continue;

		/*
		 * Now we have: pfn == coherent_pfn,
		 * Four cases:
		 * 	1) Shared with local ON_REGION
		 * 	2) Shared with local REPLICA_REGION
		 * 	3) Coherent page fetched from remote ON,
		 * 	   but local REPLICA_REGION has a different page
		 * 	4) Coherent page fetched from remote ON,
		 * 	   but local REPLICA_REGION does NOT has this page
		 */

		/* Case 1, just remove rmap */
		if (REGION_IS_LOCAL(r)) {
			coherent_page = pfn_to_dsnvm_page(coherent_pfn);

			/* FIXME: Don't know what is going on. dsnvm_get_pte can not
			 * give us the right pte as it does in page-fault handler.
			 * To be stupid, remove all rmaps */
			lock_dsnvm_page(coherent_page);
			dsnvm_page_remove_rmap(coherent_page, NULL, NULL);
			unlock_dsnvm_page(coherent_page);
			continue;
		}

		replica = find_or_alloc_replica(r->dr_no, r->owner_id);
		if (unlikely(!replica)) {
			DSNVM_WARN("dr_no: %lu", r->dr_no);
			continue;
		}

		spin_lock(&replica->page_lock[dro]);
		if (replica->mapping[dro] == 0) {
			/*
			 * Case 4): Demote
			 * This replica dro has no valid page established so far.
			 * So we demote from active-commited to inactive-commited.
			 */
			coherent_page = pfn_to_dsnvm_page(coherent_pfn);

			lock_dsnvm_page(coherent_page);
			dsnvm_page_remove_rmap(coherent_page, NULL, NULL);
			unlock_dsnvm_page(coherent_page);

			DSNVM_SetPageReplica(coherent_page);
			set_dsnvm_page_rr_info(coherent_page, replica);
			replica->mapping[dro] = coherent_pfn;
		} else if (replica->mapping[dro] != coherent_pfn) {
			/*
			 * Case 3): Discard
			 * Local REPLICA_REGION already have this committed page.
			 * So we need to free this extra commited page.
			 */
			put_dsnvm_page_pfn(coherent_pfn);
		} else {
			/*
			 * Case 2): Remove rmap
			 * This case means REPLICA_PAGE is used by page-fault to
			 * establish coherent_pfn. As case 1, remove rmap is enough.
			 */
			coherent_page = pfn_to_dsnvm_page(coherent_pfn);
			lock_dsnvm_page(coherent_page);
			dsnvm_page_remove_rmap(coherent_page, NULL, NULL);
			unlock_dsnvm_page(coherent_page);
		}
		spin_unlock(&replica->page_lock[dro]);
	}
}

/*
 * Called when dsnvm_file is going to close. The context is dsnvm_release,
 * and we free all resources this file has claimed. Regions are removed
 * from hashtable iff nobody else is using this region.
 */
void free_dn_regions(struct dsnvm_client_file *f)
{
	int ret;
	unsigned long i;
	struct dn_region_info *dr;

	for_each_mmaped_region(i, dr, f) {
		/*
		 * Check migrate.c: handle_migrate_on_chunk_finished_notify()
		 * to see why we need this @dn->region_lock.
		 */
		spin_lock(&dr->region_lock);
		__free_dn_region_pages(f, dr, DR_INDEX(dr, f));
		spin_unlock(&dr->region_lock);

		/*
		 * Try to remove this region from hashtable.
		 *
		 * ret == -EBUSY means there are some other applications
		 * mmaping into this file and this region at the same time.
		 */
		if (likely(dr->dr_no)) {
			ret = ht_remove_dn_region(dr->dr_no);
			if (unlikely(ret)) {
				if (ret == -EBUSY)
					continue;
				else {
					/*
					 * TODO:
					 * This could happen if applications only
					 * do open() and does not use mmap(). Since
					 * dn regions are queued into hashtable during
					 * mmap(). (open()-> ... ->close())
					 *
					 * But it is bug if open()->mmap() ... ->close()
					 * and we are here.
					 */
				}
			}
		} else {
			/*
			 * TODO:
			 * Depends on whether we allocate all regions
			 * at mmap() time or vma fault time.
			 */
		}
	}
}

/*
 * DN == ON case, ON_REGION is maintained by DN itself.
 *
 * Since we use COW in this case, so if the first operation is read, DN_REGION
 * will share the original NVM page of ON_REGION. Later if this shared page is
 * written to by DN thread, then pfn_mkwrite will do COW for this page.
 *
 * If the first operation is _write_, PF handler has allocated a new NVM page
 * already. We need to copy the data from orginal NVM page of ON_REGION to the
 * newly allocated page.
 */
static __always_inline int do_local_owner_fault(struct dn_region_info *dn_region,
						unsigned int dro,
						unsigned long new_pfn,
						int is_write)
{
	unsigned long dr_no = dn_region->dr_no;
	struct on_region_info *on_region;
	struct on_page_info *page_info;
	DEFINE_PROFILE_TS(t_start, t_end, t_diff)

	__START_PROFILE(t_start);

	on_region = ht_get_on_region(dr_no);
	if (unlikely(!on_region)) {
		DSNVM_BUG();
		return -EINVAL;
	}

	count_dsnvm_event(DSNVM_LOCAL_OWNER_FAULT);

	/* Count fake page-fetch events myself, used by dynamic
	 * load-balance or ON migration code. */
	atomic_inc(&on_region->nr_page_fetch[DSNVM_LOCAL_ID]);

	page_info = &on_region->mapping[dro];

	spin_lock(&on_region->page_lock[dro]);
	if (unlikely(!page_info->local_pfn)){
		/*
		 * ON_REGION pages are PG_Unevictable, so if
		 * the local_pfn is zero, the system is crashed.
		 */
		spin_unlock(&on_region->page_lock[dro]);
		put_on_region(on_region);
		DSNVM_BUG();
		return -EFAULT;
	}

	if (!is_write) {
		/* Coherent */
		if (unlikely(test_and_set_bit(DSNVM_LOCAL_ID, page_info->dn_list))) {
			/*
			 * XXX: DN is asking this NVM page again. It might
			 * due to a page eviction in DN or other reasons?
			 * Use set_bit() instead if we do not need this.
			 */
		}
	} else {
		/*
		 * Non-Coherent
		 * All pages of a ON_REGION are clean and committed. If the first
		 * operation is write, PF handler has allocated a new page for us,
		 * and we copy the data here.
		 */
		memcpy((void *)pfn_to_dsnvm_virt(new_pfn),
		       (void *)pfn_to_dsnvm_virt(page_info->local_pfn),
		       DSNVM_PAGE_SIZE);
	}
	spin_unlock(&on_region->page_lock[dro]);

	__END_PROFILE(t_start, t_end, t_diff);
	__PROFILE_PRINTK("[%s] latency: %lld (ns). dr_no %lu, dro %u",
		__func__, timespec_to_ns(&t_diff), dn_region->dr_no, dro);

	return 0;
}

/*
 * DN != ON && DN != RN case, ON_REGION is maintained by remote ON.
 *
 * No need to use spinlock here, since 1) concurrent faults were blocked by
 * dsnvm_vma_fault (so it is impossible to ask DN twice for the same page),
 * 2) no other code/threads would touch this dro at this time.
 */
#define __MAX_NR_RETRY_PAGE_FETCH	500
static __always_inline int do_remote_fault(struct dn_region_info *dr,
					   unsigned int dro,
					   unsigned long new_pfn,
					   bool is_write)
{
	int ret = 0;
	int reply_size;
	int nr_retry;
	struct dsnvm_request_page_fetch request;
	unsigned long reply_addr;
	struct page_fetch_failed_reason *failure;
	DEFINE_PROFILE_TS(t_start, t_end, t_diff)

	count_dsnvm_event(DSNVM_REMOTE_FAULT);

	if (unlikely(!dr->owner_id || dr->owner_id > DSNVM_MAX_NODE)) {
		DSNVM_BUG();
		return -EFAULT;
	}

	/*
	 * The first write make this DN a non-coherent node in ON's view.
	 * The first read make this DN a coherent node in ON's dn_list.
	 */
	if (is_write) {
		request.op = DSNVM_OP_FETCH_PAGE;
		count_dsnvm_event(DSNVM_REMOTE_FAULT_NON_COHERENT);
	} else {
		request.op = DSNVM_OP_FETCH_PAGE_COHERENT;
		count_dsnvm_event(DSNVM_REMOTE_FAULT_COHERENT);
	}
	request.dr_no = dr->dr_no;
	request.dro = dro;

	nr_retry = 0;
retry:
	__START_PROFILE(t_start);
	reply_size = ibapi_send_reply_opt(dr->owner_id, (char *)&request,
				sizeof(request), (void **)(&reply_addr));
	__END_PROFILE(t_start, t_end, t_diff);
	__PROFILE_PRINTK("[%s:%d] page-fetch latency: %lld (ns). dr_no %lu, dro %u",
		__func__, __LINE__, timespec_to_ns(&t_diff), dr->dr_no, dro);

	if (unlikely(reply_size != DSNVM_PAGE_SIZE)) {
		if (unlikely(reply_size != sizeof(*failure))) {
			DSNVM_BUG("unknown reply size: %d, dr_no: %lu, dro: %u",
				reply_size, dr->dr_no, dro);
			ret = -EIO;
			goto out;
		}

		failure = (void *)reply_addr;

		/* Check handle_page_fetch() for possible reasons */
		if (failure->reason == DSNVM_ON_MIGRATED_TO_NEW_OWNER) {
			/*
			 * The remote ON_REGION was migrated to another node.
			 * And a page fault happens before the final notify from
			 * remote ON. This can happen within a very short time.
			 * But it does happen.
			 *
			 * To avoid more pf before receiving the final notify,
			 * update the owner_id here.
			 */
			dr->owner_id = failure->new_owner;
			dsnvm_flush_buffer(&dr->owner_id, sizeof(dr->owner_id));

			if (dr->owner_id != DSNVM_LOCAL_ID)
				goto retry;
			else {
				/*
				 * We are the owner now!
				 * Rerun everything then..
				 */
				ret = -EAGAIN;
				goto out;
			}
		} else if (failure->reason == DSNVM_REPLY_PAGE_IN_OTHER_XACT) {
			if (nr_retry == __MAX_NR_RETRY_PAGE_FETCH) {
				DSNVM_WARN("Give up page-fetch (retry %d); "
					"dr_no: %lu, dro: %u, owner: %u ",
					__MAX_NR_RETRY_PAGE_FETCH, dr->dr_no, dro, dr->owner_id);
				ret = -EIO;
				goto out;
			}
			count_dsnvm_event(DSNVM_PAGE_FETCH_RETRY);
			udelay(2 * nr_retry);
			nr_retry++;
			goto retry;
		}

		DSNVM_BUG("dr_no: %lu, dro: %u, reason (%d): %s",
			dr->dr_no, dro, failure->reason,
			dsnvm_status_string(failure->reason));
		ret = -EIO;
		goto out;
	}

	/*
	 * Got reply message virtual address from ibapi
	 * just need to copy it to the right place
	 */
	__START_PROFILE(t_start);
	memcpy((void *)pfn_to_dsnvm_virt(new_pfn),
	       (void *)(reply_addr),
	       DSNVM_PAGE_SIZE);
	dsnvm_flush_buffer((void *)pfn_to_dsnvm_virt(new_pfn), DSNVM_PAGE_SIZE);
	__END_PROFILE(t_start, t_end, t_diff);
	__PROFILE_PRINTK("[%s:%d] memcpy+clflush latency: %lld (ns)",
		__func__, __LINE__, timespec_to_ns(&t_diff));

out:
	/* Free reply messsage in ibapi */
	ibapi_free_recv_buf((void *)reply_addr);
	return ret;
}

/*
 * DN == RN case, REPLICA_REGION is maintained by DN itself.
 *
 * Since we use COW in this case, so if the first operation is read, DN_REGION
 * will share the original NVM page of REPLICA_REGION. Later if this shared page
 * is written to by DN thread, then pfn_mkwrite will do COW for this page.
 *
 * If the first operation is _write_, PF handler has allocated a new NVM page
 * already. We need to copy the data from orginal NVM page of REPLICA_REGION to
 * the newly allocated page.
 */
static __always_inline int do_local_replica_fault(struct dn_region_info *dn_region,
						  unsigned int dro,
						  unsigned long new_pfn,
						  int is_write)
{
	unsigned long dr_no = dn_region->dr_no;
	struct replica_region_info *replica_region;
	struct dsnvm_page *page;
	unsigned long pfn;

	replica_region = ht_get_replica_region(dr_no);
	if (unlikely(!replica_region)) {
		DSNVM_BUG();
		return -EINVAL;
	}

	count_dsnvm_event(DSNVM_LOCAL_REPLICA_FAULT);

	/* Count fake page-fetch events myself, used by dynamic
	 * load-balance or ON migration code. */
	atomic_inc(&replica_region->nr_page_fetch[DSNVM_LOCAL_ID]);

	spin_lock(&replica_region->page_lock[dro]);
	pfn = replica_region->mapping[dro];
	if (unlikely(!pfn_is_dsnvm(pfn))) {
		spin_unlock(&replica_region->page_lock[dro]);
		ht_put_replica_region(replica_region);
		if (pfn == 0) {
			/*
			 * A special case where this page was not created
			 * within this REPLICA_REGION.
			 */
			return do_remote_fault(dn_region, dro, new_pfn, is_write);
		} else {
			DSNVM_BUG("dr_no: %lu, dro: %u", dr_no, dro);
			return -EFAULT;
		}
	}

	/*
	 * All pages of a REPLICA_REGION are clean and committed. If the first
	 * operation is write, PF handler has allocated a new page for us,
	 * and we copy the data here.
	 *
	 * Since it is a write so this page was marked as writable, so it
	 * won't run into pfn_mkwrite later.
	 */
	if (is_write) {
		memcpy((void *)pfn_to_dsnvm_virt(new_pfn),
		       (void *)pfn_to_dsnvm_virt(pfn),
		       DSNVM_PAGE_SIZE);
	} else {
		page = pfn_to_dsnvm_page(pfn);

		/*
		 * TODO:
		 * The reason we clear this flag is Yiying wants to know
		 * that a replica page is shared. But we can know if a replica
		 * page is shared by reading its mapcount. If mapcount > 0,
		 * then it is mapped by DN_REGIONs.
		 */
		lock_dsnvm_page(page);
		DSNVM_ClearPageReplica(page);
		unlock_dsnvm_page(page);
	}
	spin_unlock(&replica_region->page_lock[dro]);

	ht_put_replica_region(replica_region);
	return 0;
}

int dn_region_handle_fault(struct dn_region_info *r, unsigned int dro,
			   unsigned long pfn, int is_write)
{
	if (REGION_IS_LOCAL(r))
		return do_local_owner_fault(r, dro, pfn, is_write);
	else if (REGION_IS_REPLICA(r))
		return do_local_replica_fault(r, dro, pfn, is_write);
	else
		return do_remote_fault(r, dro, pfn, is_write);

	return -EFAULT;
}

int extend_one_region(struct dsnvm_client_file *f, int dr_index)
{
	struct dn_region_info *r;
	struct dsnvm_request_extend_file request;
	struct dsnvm_reply_extend_file reply;
	int reply_len;
	DEFINE_PROFILE_TS(t_start, t_end, t_diff)

	request.op = DSNVM_OP_EXTEND_ONE_REGION;
	request.dr_index = dr_index;
	strncpy(request.name, f->name, DSNVM_MAX_NAME);

	/*
	 * Ask CD to create a new region.
	 *
	 * TODO:
	 * There are three options of the timing of create new region:
	 *	1) open(), CD prealloc enough regions (not feasible)
	 *	2) mmap(), DN ask CD to create all mmap regions
	 *	3) page fault. When PF triggered and dr_no is 0, then ask CD.
	 *
	 * Option 1) is not feasible seems we do not know how many regions a DN
	 * will use until mmap() time. Option 2) should be more efficient than
	 * option 3) at runtime, but 2) would master IB bandwidth and NVM pages
	 * if a lot of the regions are never being accessed.
	 */
	__START_PROFILE(t_start);
	reply_len = ibapi_send_reply(0, (char *)&request,
				sizeof(request), (char *)&reply);
	__END_PROFILE(t_start, t_end, t_diff);
	__PROFILE_PRINTK("extend_one_region IB latency: %lld (ns)",
		timespec_to_ns(&t_diff));

	if (unlikely(reply_len > sizeof(reply))) {
		DSNVM_BUG();
		return -EIO;
	}

	if (unlikely(reply.status != DSNVM_REPLY_SUCCESS)) {
		DSNVM_WARN("%s", dsnvm_status_string(reply.status));
		return -EPERM;
	}

	/*
	 * Great, CD replied us with new region's DR_NO and owner_id.
	 */

	if (unlikely(!reply.owner_id || reply.owner_id > DSNVM_MAX_NODE)) {
		DSNVM_BUG("invalid owner node_id: %u", reply.owner_id);
		return -EIO;
	}

	r = &(f->regions[dr_index]);
	r->dr_no = reply.dr_no;
	r->owner_id = reply.owner_id;

	return 0;
}
