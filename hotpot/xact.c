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
 * KISS and Murphy's law, we keep that in mind.
 */

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/log2.h>
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

#include <asm/tlbflush.h>
#include <linux/dsnvm-interface.h>
#include "dsnvm.h"

#if 0
#define DSNVM_PROFILE
#endif
#include "dsnvm-profile.h"

/**
 * xact_free_log_data
 *
 * Free data_area buffers that were allocated by IB layer and
 * then free this log slot within NVM area.
 */
static void xact_free_log_data(struct dsnvm_log_record *log)
{
	int i, nr_areas;

	if (unlikely(!log)) {
		DSNVM_BUG();
		return;
	}

	nr_areas = log->nr_areas;

	/* Free buffers allocated by IB: */
	for (i = 0; i < nr_areas; i++) {
		void *vaddr = log->data_areas[i].vaddr;

		DSNVM_PRINTK("Free buffer of log_id %d xact_id %d, vaddr: %p",
			log->log_id, log->xact_id, vaddr);

		if (vaddr) {
			ibapi_free_recv_buf(vaddr);
			log->data_areas[i].vaddr = NULL;
		}
	}

	/* Free log slot */
	free_dsnvm_log(log);
}

static DECLARE_BITMAP(xact_ids_free_map, DSNVM_MAX_XACT);
static DEFINE_SPINLOCK(xact_id_lock);

#define xact_id_offset	(DSNVM_LOCAL_ID * DSNVM_MAX_XACT)

static void dsnvm_init_xact_ids(void)
{
	bitmap_clear(xact_ids_free_map, 0, DSNVM_MAX_XACT);
}

static int get_next_xact_id(void)
{
	int local_id;

	spin_lock(&xact_id_lock);
	local_id = find_first_zero_bit(xact_ids_free_map, DSNVM_MAX_XACT);
	if (unlikely(local_id == DSNVM_MAX_XACT)) {
		DSNVM_BUG("Running out of xact id");
		spin_unlock(&xact_id_lock);
		return -1;
	}
	set_bit(local_id, xact_ids_free_map);
	spin_unlock(&xact_id_lock);

	DSNVM_PRINTK("Alloc xact id of bitmap: %d xact id %d\n",
		local_id, local_id + xact_id_offset);

	return local_id + xact_id_offset;
}

static void free_xact_id(int id)
{
	int local_id = id - xact_id_offset;

	DSNVM_PRINTK("Freeing xact_id: %d, local_id: %d", id, local_id);

	if (unlikely(local_id < 0 || local_id >= DSNVM_MAX_XACT)) {
		DSNVM_WARN();
		return;
	}

	spin_lock(&xact_id_lock);
	clear_bit(local_id, xact_ids_free_map);
	spin_unlock(&xact_id_lock);
}

/*
 * This function describes:
 *	DN's handler for coherence updates from ON
 *
 * Related IB APIs:
 *	ibapi_multi_atomic_send_yy
 *	ibapi_multi_atomic_send
 *
 * ON pushes coherent updates to DN in phase 2 of commit protocol.
 * DN that receives this update will update if its local DN_REGION pages if any,
 * or update its local REPLICA_REGION pages if any. If none of DN_REGION or
 * REPLICA_REGION page exist, just ignore this page and report this to ON.
 *
 * Note that: No page or region will be created in this handler.
 *
 * TODO:
 *	What if both REPLICA_REGION and DN_REGION have page, update both of them?
 */
int dsnvm_handle_receive_coherence(int node_id, int nr_reqs,
				   struct atomic_struct *reqs,
				   char *output_buf, unsigned int *output_size)
{
	int i, nr_areas;
	struct dsnvm_commit_request_header *request_header;
	struct dr_no_dro_page_offset *meta_for_areas;
	unsigned long *reply_bitmap;

	count_dsnvm_event(DSNVM_COHERENCE_RX);

	/* Get request metadata */
	meta_for_areas = reqs[1].vaddr;
	request_header = reqs[0].vaddr;
	nr_areas = request_header->nr_reqs;

	/* Indicating which area is succefully updated */
	reply_bitmap = (unsigned long *)output_buf;
	*output_size = BITS_TO_LONGS(nr_areas) * sizeof(unsigned long);
	bitmap_clear(reply_bitmap, 0, nr_areas); 

	/* We have 2 metadata requests */
	if (unlikely(nr_areas != nr_reqs - 2)) {
		DSNVM_BUG("nr_areas %d nr_reqs %d", nr_areas, nr_reqs);
		return 0;
	}

	DSNVM_PRINTK("Sender-ID: %d nr_areas %d", node_id, nr_areas);

	for (i = 0; i < nr_areas; i++) {
		unsigned long dr_no = meta_for_areas[i].dr_no;
		unsigned int dro = meta_for_areas[i].dro;
		unsigned long pgoft = meta_for_areas[i].page_offset;
		unsigned long pfn = 0;
		size_t len;
		struct dn_region_info *dr;
		struct dsnvm_page *page;
		void *dst, *src;
		bool coherent_page = false;

		/*
		 * Find DN region from hashtable
		 *
		 * Note that: we can find this DN_REGION if and only if the
		 * application is still using dsnvm_client_file. All DN_REGIONs
		 * will be removed from the hashtable once the app close dsnvm.
		 *
		 * Hence it should be normal and okay that dr == NULL happens
		 * a lot. Since, for another reason, DN will NOT tell remote ON
		 * that local DNs are no longer valid, however remote ON will
		 * search its dn_list for coherent DNs (check make_coherence_and_replication())
		 */
		dr = ht_get_dn_region(dr_no);
		if (dr) {
			spin_lock(&dr->page_lock[dro]);
			pfn = dr->coherent_mapping[dro];
			if (pfn_is_dsnvm(pfn))
				coherent_page = true;
			else
				/* A partial DN region with this page missing */
				coherent_page = false;
			spin_unlock(&dr->page_lock[dro]);
		}

		/* Either no DN or partial DN region, then */
		/* Try to find it out from REPLICA_REGION hashtable: */
		if (!coherent_page) {
			struct replica_region_info *rr;

			rr = ht_get_replica_region(dr_no);
			if (!rr) {
				/* No RR, then skip this page */
				DSNVM_PRINTK("No action (1) for dr_no: %lu, dro: %u",
					dr_no, dro);
				continue;
			}

			spin_lock(&rr->page_lock[dro]);
			pfn = rr->mapping[dro];
			if (!pfn_is_dsnvm(pfn)) {
				/*
				 * If we reach here, it means:
				 *	a. No DN or partial DN region with this page missing
				 *	b. partial RN region with this page missing
				 *
				 * Thus skip this page
				 */
				spin_unlock(&rr->page_lock[dro]);
				DSNVM_PRINTK("No action (2) for dr_no: %lu, dro: %u",
					dr_no, dro);
				continue;
			}
			spin_unlock(&rr->page_lock[dro]);
		}

		/* Either a coherent DN page or replica page */
		page = pfn_to_dsnvm_page(pfn);

		/*
		 * Only update if the page is
		 * 	in committed state, AND
		 * 	not in a xact
		 */
		lock_dsnvm_page(page);
		if (likely(!DSNVM_PageInxact(page) && DSNVM_PageCommitted(page))) {
			/* The source address (buffer allocated by IB): */
			src = reqs[i + 2].vaddr;
			len = reqs[i + 2].len;

			/* Well, for safety.. */
			WARN_ON((pgoft + len) > PAGE_SIZE);

			/* The destination address (within DN or RN): */
			dst = (void *)(pfn_to_dsnvm_virt(pfn) + pgoft);

			/* Do the real update: */
			memcpy(dst, src, len);
			dsnvm_flush_buffer(dst, len);

			set_bit(i, reply_bitmap);

			count_dsnvm_event(DSNVM_COHERENCE_NR_UPDATED_PAGES);

			DSNVM_PRINTK("Actual update to dr_no: %lu dro: %u, "
				"cp data: %p -> %p, len: %zu", dr_no, dro, src, dst, len);
		} else {
			DSNVM_PRINTK("Trying to commit to a page currently "
				"in another xact dr_no %lu dro %u", dr_no, dro);

			unlock_dsnvm_page(page);
			break;
		}
		unlock_dsnvm_page(page);
	}

	for (i = 0; i < nr_reqs; i++) {
		ibapi_free_recv_buf(reqs[i].vaddr);
	}

	return 0;
}

/* util struct used only in this function */
struct dsnvm_page_char {
	char	data[DSNVM_PAGE_SIZE];
};

/*
 * This function describes:
 *	Make more replicas to meet rep_degree
 *
 * Related IB API:
 *	ibapi_multi_atomic_send_yy
 *	ibapi_multi_atomic_send
 *
 * RETURN:
 *	0 on success
 *	nagative value on failure
 */
static int make_replication(int commit_node_id, int nr_areas,
		struct dr_no_dro_page_offset *meta_for_areas, struct atomic_struct *reqs,
		int *nr_reps_per_area, int if_do_send_yy, struct atomic_struct **xact_reqs,
		struct dr_no_dro_page_offset **meta_for_replica_areas, int **coherence_succeed_node,
		struct max_reply_msg *reply_msg)
{
	int i, j, ret = 0;
	int nr_redundant_pages, nr_redundant_dns;
	struct dr_no_dro *redundant_page_info;
	struct dsnvm_page_char *redundant_page_data;
	int *redundant_page_area_index;

	int pos[DSNVM_MAX_NODE];
	int send_dn_list[DSNVM_MAX_NODE];
	int nr_areas_per_dn[DSNVM_MAX_NODE];
	struct dsnvm_commit_request_header req_header[DSNVM_MAX_NODE];

	redundant_page_info = kmalloc(sizeof(*redundant_page_info) * nr_areas, GFP_KERNEL);
	if (!redundant_page_info)
		return -ENOMEM;

	redundant_page_area_index = kmalloc(sizeof(int) * nr_areas, GFP_KERNEL);
	if (!redundant_page_area_index) {
		kfree(redundant_page_info);
		return -ENOMEM;
	}

	redundant_page_data = kmalloc(sizeof(*redundant_page_data) * nr_areas, GFP_KERNEL);
	if (!redundant_page_data) {
		kfree(redundant_page_area_index);
		kfree(redundant_page_info);
		return -ENOMEM;
	}

	/*
	 * Reset Arrays. Note that some arrays are already allocated by
	 * the make_coherence_and_replication():
	 */
	for (i = 0; i < DSNVM_MAX_NODE; i++) {
		nr_areas_per_dn[i] = 0;
		pos[i] = -1;

		/* Will be updated later */
		req_header[i].nr_reqs = 0;
		req_header[i].op = DSNVM_OP_SEND_REPLICA_XACT;

		/* The first metadata request */
		xact_reqs[i][0].vaddr = &req_header[i];
		xact_reqs[i][0].len = sizeof(struct dsnvm_commit_repdegree_request_header);

		/* The second metadata request */
		xact_reqs[i][1].vaddr = meta_for_replica_areas[i];
	}

	/*
	 * Make a copy of the page that need replication,
	 * then copy the new data from reqs[] to this copy.
	 * Send the combined page to redundant DN.
	 */
	nr_redundant_pages = 0;
	for (i = 0; i < nr_areas; i++) {
		unsigned long dr_no = meta_for_areas[i].dr_no;
		unsigned int dro = meta_for_areas[i].dro;
		unsigned long pgoft = meta_for_areas[i].page_offset;
		struct on_region_info *on;
		struct on_page_info *on_page;
		void *src, *dst;
		size_t len;

		/* Already meet rep_degree */
		if (nr_reps_per_area[i] < 1)
			continue;

		for (j = 0; j < nr_redundant_pages; j ++) {
			if (dr_no == redundant_page_info[j].dr_no &&
			    dro == redundant_page_info[j].dro) {
				break;
			}
		}

		/* First time see this page */
		if (j == nr_redundant_pages) {
			/* reverse index into meta_for_areas array */
			redundant_page_area_index[nr_redundant_pages] = i;
			redundant_page_info[nr_redundant_pages].dr_no = dr_no; 
			redundant_page_info[nr_redundant_pages].dro = dro; 
			nr_redundant_pages++;

			/* Self-ON case, use physical address */
			if (if_do_send_yy)
				continue;

			on = ht_get_on_region(dr_no);
			if (unlikely(!on)) {
				DSNVM_BUG();
				ret = -EFAULT;
				goto out;
			}

			/* Make a whole copy of the page */
			on_page = &on->mapping[dro];
			src = (void *)(pfn_to_dsnvm_virt(on_page->local_pfn));
			dst = redundant_page_data[j].data;
			memcpy(dst, src, PAGE_SIZE);
		}

		/* Self-ON case, use physical address */
		if (if_do_send_yy)
			continue;

		/* Update the xact required portion inside this copy: */
		len = reqs[i + 2].len;
		src = reqs[i + 2].vaddr;
		dst = redundant_page_data[j].data + pgoft;
/* FIXME */
#if 0
		WARN_ON((len + pgoft) > PAGE_SIZE);
		memcpy(dst, src, len);
#endif
	}

	DSNVM_PRINTK("nr_redundant_pages = %d", nr_redundant_pages);

	/*
	 * Now construct send_dn_list array for redundant_pages
	 * We iterate all redundant_pages, find suitable DN for each page.
	 */
	nr_redundant_dns = 0;
	for (i = 0; i < nr_redundant_pages; i++) {
		unsigned long dr_no = redundant_page_info[i].dr_no;
		unsigned int dro = redundant_page_info[i].dro;
		int area_index = redundant_page_area_index[i];
		int node, curr_pos, curr_req;
		int nr_remain_replica;

		nr_remain_replica = nr_reps_per_area[area_index];
		for (node = 0; node < DSNVM_MAX_NODE; node++) {
			if (node == commit_node_id || node == DSNVM_LOCAL_ID)
				continue;

			/* Off-line */
			if (unlikely(!test_bit(node, DSNVM_CLIENT_MACHINES)))
				continue;

			/*
			 * This node already made a coherent copy.
			 *
			 * Note that it is okay to use just one area to see
			 * if we need to send redundant page to this node.
			 * Since if a node reports failure for one area, it
			 * means this node does not have this page.
			 */
			if (coherence_succeed_node[node][area_index]) {
				DSNVM_PRINTK("Node: %d area_index: %d dr_no: %lu dro: %u",
					node, area_index, dr_no, dro);
				continue;
			}

			/* Check if we found enough ON alreay: */
			if (nr_remain_replica <= 0)
				break;
			nr_remain_replica--;

			/* First time see this node */
			if (pos[node] == -1) {
				pos[node] = nr_redundant_dns;
				send_dn_list[nr_redundant_dns++] = node;

				DSNVM_PRINTK("Add node: %d to replica_dn list", node);
			}

			curr_pos = pos[node];
			curr_req = nr_areas_per_dn[curr_pos];

			/* Self-ON case, use physical address */
			if (if_do_send_yy) {
				struct dn_region_info *dn;
				void *kern_paddr;

				dn = ht_get_dn_region(dr_no);
				if (unlikely(!dn)) {
					DSNVM_BUG("dr_no: %lu", dr_no);
					ret = -EFAULT;
					goto out;
				}

				kern_paddr = (void *)(dn->coherent_mapping[dro] << PAGE_SHIFT);
				xact_reqs[curr_pos][curr_req + 2].vaddr = kern_paddr;
			} else {
			/* Use virtual address of the copied page */
				xact_reqs[curr_pos][curr_req + 2].vaddr = redundant_page_data[i].data;
			}

			/* Always send the whole page */
			xact_reqs[curr_pos][curr_req + 2].len = PAGE_SIZE;
			meta_for_replica_areas[curr_pos][curr_req].dr_no = dr_no;
			meta_for_replica_areas[curr_pos][curr_req].dro = dro;
			meta_for_replica_areas[curr_pos][curr_req].page_offset = 0;

			nr_areas_per_dn[curr_pos]++;
			if (unlikely(nr_areas_per_dn[curr_pos] >= MAX_ATOMIC_SEND_NUM)) {
				DSNVM_BUG("Too many requests in one atomic-send");
				ret = -EFAULT;
				goto out;
			}
		}
	}

	/* Last step, fill the first 2 metadata requests: */
	for (i = 0; i < nr_redundant_dns; i++) {
		if (unlikely(nr_areas_per_dn[i] == 0)) {
			ret = DSNVM_REPLY_CANNOT_MAKE_ENOUGH_REPLICA;
			goto out;
		}
		req_header[i].nr_reqs = nr_areas_per_dn[i];
		xact_reqs[i][1].len = nr_areas_per_dn[i] * sizeof(struct dr_no_dro_page_offset);
		nr_areas_per_dn[i] += 2;
	}

	if (likely(nr_redundant_dns > 0)) {
		DSNVM_PRINTK("Before sending redundant data to total %d DNs",
			nr_redundant_dns);	

		/*
		 * ibapi_multi_atomic_send_yy:	xact_reqs use Physical Address
		 * ibapi_multi_atomic_send:	xact_reqs use Virtual Kernel Address
		 */
		if (if_do_send_yy) {
			ibapi_multi_atomic_send_yy(nr_redundant_dns, send_dn_list,
				xact_reqs, nr_areas_per_dn, reply_msg);
		} else {
			ibapi_multi_atomic_send(nr_redundant_dns, send_dn_list,
				xact_reqs, nr_areas_per_dn, reply_msg);
		}
		DSNVM_PRINTK("After sending redundant data to total %d DNs",
			nr_redundant_dns);	
	} else {
		DSNVM_PRINTK("Can not find any DN to replicate");
	}

	count_dsnvm_events(DSNVM_REPLICATION_TX, nr_redundant_dns);

	ret = 0;
out:
	kfree(redundant_page_info);
	kfree(redundant_page_data);
	kfree(redundant_page_area_index);
	return ret;
}

/*
 * This function describes:
 * 	Push coherence updates and
 * 	meet replica degree
 *
 * Related IB API:
 *	ibapi_multi_atomic_send_yy
 *	ibapi_multi_atomic_send
 *
 * RETURN:
 *	0 on success
 *	nagative value on failure
 */
static int make_coherence_and_replication(int commit_node_id, int nr_areas,
		struct dr_no_dro_page_offset *meta_for_areas, struct atomic_struct *reqs,
		int *nr_reps_per_area, int if_from_single_on_handler, int if_do_send_yy)
{
	int i, j, ret = 0;
	int **dn_area_map_to_area = NULL;
	int **coherence_succeed_node = NULL;

	int nr_coherence_dns = 0;

	int pos[DSNVM_MAX_NODE];
	int send_dn_list[DSNVM_MAX_NODE];
	int nr_areas_per_dn[DSNVM_MAX_NODE];

	struct max_reply_msg *reply_msg = NULL;
	struct atomic_struct **xact_reqs = NULL;
	struct dr_no_dro_page_offset **meta_for_replica_areas = NULL;
	struct dsnvm_commit_request_header req_header[DSNVM_MAX_NODE];

	ret = -ENOMEM;
	reply_msg = kmalloc(sizeof(*reply_msg) * DSNVM_MAX_NODE, GFP_KERNEL);
	if (!reply_msg)
		goto out;

	xact_reqs = kmalloc(sizeof(*xact_reqs) * DSNVM_MAX_NODE, GFP_KERNEL);
	if (!xact_reqs)
		goto out;

	meta_for_replica_areas = kmalloc(sizeof(*meta_for_replica_areas) * DSNVM_MAX_NODE, GFP_KERNEL);
	if (!meta_for_replica_areas)
		goto out;

	dn_area_map_to_area = kmalloc(sizeof(int *) * DSNVM_MAX_NODE, GFP_KERNEL);
	if (!dn_area_map_to_area)
		goto out;
	
	coherence_succeed_node = kmalloc(sizeof(int *) * DSNVM_MAX_NODE, GFP_KERNEL);
	if (!coherence_succeed_node)
		goto out;

	/* Allocate array for per NODE */
	for (i = 0; i < DSNVM_MAX_NODE; i++) {
		dn_area_map_to_area[i] = kzalloc(sizeof(int) * nr_areas, GFP_KERNEL);
		if (!dn_area_map_to_area[i])
			goto out;

		coherence_succeed_node[i] = kzalloc(sizeof(int) * nr_areas, GFP_KERNEL);
		if (!coherence_succeed_node[i])
			goto out;

		/* Need 2 more requestes for metadata */
		xact_reqs[i] = kmalloc(sizeof(struct atomic_struct) * (nr_areas + 2), GFP_KERNEL);
		if (!xact_reqs[i])
			goto out;

		meta_for_replica_areas[i] = kzalloc(sizeof(struct dr_no_dro_page_offset) * nr_areas, GFP_KERNEL);
		if (!meta_for_replica_areas[i])
			goto out;

		nr_areas_per_dn[i] = 0;

		pos[i] = -1;

		/* Will be updated later */
		req_header[i].nr_reqs = 0;
		req_header[i].op = DSNVM_OP_SEND_COHERENCE_XACT;

		/* The first metadata request */
		xact_reqs[i][0].vaddr = &req_header[i];
		xact_reqs[i][0].len = sizeof(struct dsnvm_commit_repdegree_request_header);

		/* The second metadata request */
		xact_reqs[i][1].vaddr = meta_for_replica_areas[i];
	}

	DSNVM_PRINTK("Commit-NodeID: %d, nr_areas: %d "
		"from_single_on_handler %d do_send_yy %d",
		commit_node_id, nr_areas, if_from_single_on_handler, if_do_send_yy);

	/*
	 * Get all the DNs that have at least one data page in the xact
	 * these are the coherence nodes that we need to send the xact to
	 */
	for (i = 0; i < nr_areas; i++) {
		unsigned long dr_no = meta_for_areas[i].dr_no;
		unsigned int dro = meta_for_areas[i].dro;
		unsigned long pgoft = meta_for_areas[i].page_offset;
		struct on_region_info *on_dr;
		struct on_page_info *on_page;
		int node, curr_pos, curr_area;

		on_dr = ht_get_on_region(dr_no);
		if (unlikely(!on_dr)) {
			DSNVM_BUG("commit_node_id: %d, local_node_id: %d "
				"dr_no: %lu, dro: %u", commit_node_id,
				DSNVM_LOCAL_ID, dr_no, dro);
			continue;
		}

		BUG_ON(is_on_region_migrating_out(on_dr));

		spin_lock(&on_dr->page_lock[dro]);
		on_page = &on_dr->mapping[dro];

		/* Find out what DN nodes need coherence update */
		for_each_set_bit(node, on_page->dn_list, DSNVM_MAX_NODE) {
			if (node == DSNVM_LOCAL_ID)
				continue;

			/* Off-line */
			if (unlikely(!test_bit(node, DSNVM_CLIENT_MACHINES)))
				continue;

			/* Do NOT send back to the commiting node */
			if (node == commit_node_id)
				continue;

			/* First time see this DN node */
			if (pos[node] == -1) {
				/* record the index of this node within send list */
				pos[node] = nr_coherence_dns;
				send_dn_list[nr_coherence_dns++] = node;

				DSNVM_PRINTK("Add node: %d to coherence_dn list", node);
			}

			/* Alright, then update those arrays... */
			curr_pos = pos[node];
			curr_area = nr_areas_per_dn[curr_pos];

			/* Store kernel vaddr and len for this area */
			/* The first 2 are metadata, so we have a 2 shift */
			xact_reqs[curr_pos][curr_area + 2].vaddr = reqs[i].vaddr;
			xact_reqs[curr_pos][curr_area + 2].len = reqs[i].len;

			/* Update the second metadata request */
			meta_for_replica_areas[curr_pos][curr_area].dr_no = dr_no;
			meta_for_replica_areas[curr_pos][curr_area].dro = dro;
			meta_for_replica_areas[curr_pos][curr_area].page_offset = pgoft;

			/* Save area_idx used later to calculate nr_rep_per_area */
			dn_area_map_to_area[curr_pos][curr_area] = i;

			nr_areas_per_dn[curr_pos]++;
			if (unlikely(nr_areas_per_dn[curr_pos] >= MAX_ATOMIC_SEND_NUM)) {
				DSNVM_BUG("Too many areas in one xact");
				ret = -EFAULT;
				goto out;
			}

		}
		spin_unlock(&on_dr->page_lock[dro]);
	}

	/* Update the first 2 metadata requests */
	for (i = 0; i < nr_coherence_dns; i++) {
		if (unlikely(nr_areas_per_dn[i] == 0)) {
			ret = DSNVM_REPLY_CANNOT_MAKE_ENOUGH_REPLICA;
			goto out;
		}

		/* 1st req */
		req_header[i].nr_reqs = nr_areas_per_dn[i];
		/* 2st req */
		xact_reqs[i][1].len = nr_areas_per_dn[i] * sizeof(struct dr_no_dro_page_offset);
		nr_areas_per_dn[i] += 2;
	}

	/* Now send to remote DNs */
	if (likely(nr_coherence_dns > 0)) {
		DSNVM_PRINTK("Before sending coherence data to total %d DNs", nr_coherence_dns);
		/*
		 * ibapi_multi_atomic_send_yy:	xact_reqs use Physical Address
		 * ibapi_multi_atomic_send:	xact_reqs use Virtual Kernel Address
		 */
		if (if_do_send_yy == 1) {
			ibapi_multi_atomic_send_yy(nr_coherence_dns, send_dn_list,
				xact_reqs, nr_areas_per_dn, reply_msg);
		} else {
			ibapi_multi_atomic_send(nr_coherence_dns, send_dn_list,
				xact_reqs, nr_areas_per_dn, reply_msg);
		}
		DSNVM_PRINTK("After sending coherence data to total %d DNs", nr_coherence_dns);
	} else {
		/* no one has ever send us a page-fetch, how sad it is */
		DSNVM_PRINTK("No remote coherent DN involved");
	}
	count_dsnvm_events(DSNVM_COHERENCE_TX, nr_coherence_dns);

	/* Collect status reported by remote ONs: */
	for (i = 0; i < nr_coherence_dns; i++) {
		unsigned long *reply_bitmap = NULL;

		reply_bitmap = (unsigned long *)(&reply_msg[i]);
		for (j = 0; j < nr_areas_per_dn[i] - 2; j++) {
			int area_idx = dn_area_map_to_area[i][j];
			int node_id = send_dn_list[i];

			if (test_bit(j, reply_bitmap)) {
				/* Cool, this DN counts a valid replica copy */
				nr_reps_per_area[area_idx]--;
				coherence_succeed_node[node_id][area_idx] = 1;
			} else {
				coherence_succeed_node[node_id][area_idx] = 0;
			}
		}
	}

	/* Check if we meet the rep_degree: */
	for (i = 0; i < nr_areas; i++) {
		if (nr_reps_per_area[i] > 0)
			break;
	}

	/*
	 * If these ONs alone can NOT meet the replication degree, ON will
	 * choose new DNs that do not have a copy of the data and send the
	 * data to them
	 */
	if (i != nr_areas) {
		DSNVM_PRINTK("Need to make more replicas");

		count_dsnvm_event(DSNVM_REPLICATION_NEED_EXTRA);
		ret = make_replication(commit_node_id, nr_areas, meta_for_areas,
			reqs, nr_reps_per_area, if_do_send_yy, xact_reqs, meta_for_replica_areas,
			coherence_succeed_node, reply_msg);
	} else {
		ret = 0;
		DSNVM_PRINTK("NO need to make more replicas"); 
	}

out:
	if (reply_msg)
		kfree(reply_msg);

	if (xact_reqs) {
		for (i = 0; i < DSNVM_MAX_NODE; i++) {
			if (xact_reqs[i])
				kfree(xact_reqs[i]);
		}
		kfree(xact_reqs);
	}

	if (dn_area_map_to_area) {
		for (i = 0; i < DSNVM_MAX_NODE; i++) {
			if (dn_area_map_to_area[i])
				kfree(dn_area_map_to_area[i]);
		}
		kfree(dn_area_map_to_area);
	}

	if (coherence_succeed_node) {
		for (i = 0; i < DSNVM_MAX_NODE; i++) {
			if (coherence_succeed_node[i])
				kfree(coherence_succeed_node[i]);
		}
		kfree(coherence_succeed_node);
	}

	if (meta_for_replica_areas) {
		for (i = 0; i < DSNVM_MAX_NODE; i++) {
			if (meta_for_replica_areas[i])
				kfree(meta_for_replica_areas[i]);
		}
		kfree(meta_for_replica_areas);
	}

	return ret;
}

/*
 * This functions describes:
 *	ON handler for phase 1 of commit protocol
 *
 * Related IB API:
 *	ibapi_multi_atomic_send_yy
 *
 * It will record (pointers of) data and metadata in a redo-log and try to
 * lock requested local ON pages by set if_blocked_by_commit_xact to 1. It will
 * only succeed if and only if all requested local ON pages are locked.
 */
int dsnvm_handle_request_commit_xact(int sender_id, int nr_reqs,
				     struct atomic_struct *reqs,
				     char *reply_addr, unsigned int *reply_len)
{
	struct dsnvm_commit_repdegree_request_header *meta_msg;
	struct dr_no_dro_page_offset *meta_for_areas;
	struct status_reply_msg *reply;
	struct dsnvm_log_record *log_rec;
	int nr_areas, log_id, rep_degree, xact_id;
	int i, j;
	int failed_area = 0;

	count_dsnvm_event(DSNVM_MRMW_REMOTE_ON_N_RX);

	transaction_enter();

	if (unlikely(nr_reqs <= 1)) {
		DSNVM_BUG("no data req in commit xact");
		reply->status = DSNVM_NO_DATA_IN_REQUEST;
		transaction_exit();
		return 0;
	}

	/* Fill reply message first */
	reply = (struct status_reply_msg *)reply_addr;
	reply->status = DSNVM_REPLY_SUCCESS;
	*reply_len = sizeof(struct status_reply_msg);

	/* Get metadata from header requests */
	meta_for_areas = reqs[1].vaddr;
	meta_msg = reqs[0].vaddr;
	nr_areas = meta_msg->nr_reqs;
	rep_degree = meta_msg->rep_degree;
	xact_id = meta_msg->xact_id;

	/* First two requests are metadata */
	/* Check dsnvm_request_commit_xact_to_ons for details */
	if (unlikely(nr_areas != nr_reqs - 2)) {
		DSNVM_BUG("nr_areas: %d, nr_reqs: %d",nr_areas, nr_reqs);
		reply->status = DSNVM_REQ_AREA_DONT_MACTH;
		transaction_exit();
		return 0;
	}

	/* Allocate redo log in this ON */
	log_rec = alloc_dsnvm_log(xact_id, &log_id);
	if (unlikely(!log_rec)) {
		DSNVM_WARN("No more logs");
		reply->status = DSNVM_REPLY_LOG_FULL;
		transaction_exit();
		return 0;
	}

	/* Save metadata into redo-log */
	log_rec->xact_id = xact_id;
	log_rec->sender_id = sender_id;
	log_rec->state = DSNVM_LOG_NOT_TO_REPLAY | DSNVM_LOG_PHASE_1_MIDDLE;
	log_rec->nr_areas = nr_areas;
	log_rec->rep_degree = rep_degree;
	log_rec->meta_for_areas = meta_for_areas;
	for (i = 0; i < nr_areas; i++) {
		unsigned long dr_no = meta_for_areas[i].dr_no;
		unsigned int dro = meta_for_areas[i].dro;

		/*
		 * Save area info into redo-log
		 *
		 * Note that: reqs buffers are allocated by IB layer, we are
		 * just saving the virtual kernel address of these buffers into
		 * our log_rec. Those buffers are freed by Hotpot when we call
		 * xact_free_log_data().
		 */
		log_rec->data_areas[i].vaddr = reqs[i+2].vaddr;
		log_rec->data_areas[i].len = reqs[i+2].len;

		DSNVM_PRINTK("Logging area[%d]: dr_no %lu dro %u, VA: %p len: %zu",
			i, dr_no, dro, reqs[i+2].vaddr, reqs[i+2].len);
	}

	/* Flush back all log except log_id first */
	dsnvm_flush_buffer(log_rec, sizeof(*log_rec));

	/* Now set log_id and flush back, make this log valid persistent */
	log_rec->log_id = log_id;
	dsnvm_flush_buffer(&log_rec->log_id, sizeof(log_rec->log_id));

	DSNVM_PRINTK("Sender-ID: %d, log_id: %d, xact_id: %d, "
		"nr_reqs: %d, nr_area: %d, rep_degree: %d",
		sender_id, log_id, xact_id, nr_reqs, nr_areas, rep_degree);

	/* Redo-log saved, now block ON_REGION pages */
	for (i = 0; i < nr_areas; i++) {
		struct on_region_info *on_dr;
		struct on_page_info *on_page;
		unsigned long dr_no = meta_for_areas[i].dr_no;
		unsigned int dro = meta_for_areas[i].dro;

		on_dr = ht_get_on_region(dr_no);
		if (unlikely(!on_dr)) {
			if (likely(proxy_find_new_owner(dr_no) > 0)) {
				/*
				 * The ON_REGION was migrated out in short
				 * period before this.
				 */
				reply->status = DSNVM_REPLY_ON_REGION_MIGRATING_OUT;
			} else {
				reply->status = DSNVM_ENOREGION;
				DSNVM_BUG("Receiving area that's not owned by myself: "
					"Sender-ID: %d, dr_no %lu, dro %u",
					sender_id, dr_no, dro);
			}

			failed_area = i;
			goto error;
		}

		/*
		 * Locks:
		 *	@on->region_lock
		 *	  @on->page_lock[dro]
		 */
		spin_lock(&on_dr->region_lock);
		if (unlikely(is_on_region_migrating_out(on_dr))) {
			spin_unlock(&on_dr->region_lock);
			DSNVM_PRINTK("dr_no: %lu is migrating out", dr_no);

			count_dsnvm_event(DSNVM_XACT_REJECT_DUE_TO_MIGRATION);
			reply->status = DSNVM_REPLY_ON_REGION_MIGRATING_OUT;
			failed_area = i;
			goto error;
		}

		spin_lock(&on_dr->page_lock[dro]);
		on_page = &on_dr->mapping[dro];
		for (j = 0; j < i; j++) {
			if (dr_no == meta_for_areas[j].dr_no &&
			    dro == meta_for_areas[j].dro) {
				break;
			}
		}

		/* First time see this page */
		if (likely(j == i)) {
			if (unlikely(on_page->if_blocked_by_commit_xact == 1)) {
				/*
				 * Blocked by another XACT
				 */

				DSNVM_PRINTK_BLOCK("Concurrent block dr_no %lu dro %u",
					 dr_no, dro);

				reply->status = DSNVM_REPLY_PAGE_IN_OTHER_XACT;
				spin_unlock(&on_dr->page_lock[dro]);
				spin_unlock(&on_dr->region_lock);

				count_dsnvm_event(DSNVM_XACT_REJECT_DUE_TO_BLOCKED_PAGES);
				failed_area = i;
				goto error;
			} else {
				/*
				 * Mark this ON_REGION page as blocked
				 */
				on_page->if_blocked_by_commit_xact = 1;

				/* Bookkeeping for migration: */
				inc_pages_in_transaction(on_dr);

				DSNVM_PRINTK_BLOCK("Block dr_no %lu dro %u",
					dr_no, dro);
			}
		}
		spin_unlock(&on_dr->page_lock[dro]);
		spin_unlock(&on_dr->region_lock);

		/*
		 * No need to flush the received data,
		 * since RDMA already writes to NVM (and thus persistent).
		 */
	}

	/* Change log state and flush back */
	log_rec->state = DSNVM_LOG_NOT_TO_REPLAY | DSNVM_LOG_PHASE_1_SUCCEED;
	dsnvm_flush_buffer(&log_rec->state, sizeof(log_rec->state));

	transaction_exit();

	return 0;

error:
	for (i = 0; i < failed_area; i++) {
		struct on_region_info *on_dr;
		struct on_page_info *on_page;
		unsigned long dr_no = meta_for_areas[i].dr_no;
		unsigned int dro = meta_for_areas[i].dro;

		for (j = 0; j < i; j++) {
			if (dr_no == meta_for_areas[j].dr_no &&
			    dro == meta_for_areas[j].dro) {
				break;
			}
		}

		/* Already seen this page */
		if (j != i)
			continue;

		on_dr = ht_get_on_region(dr_no);
		if (unlikely(!on_dr))
			continue;

		BUG_ON(is_on_region_migrating_out(on_dr));

		/*
		 * Revert those blocked ON_REGION pages back to unblocked.
		 * If it is unblocked at the beginning, then it is BUG()!
		 */
		spin_lock(&on_dr->page_lock[dro]);
		on_page = &on_dr->mapping[dro];
		if (likely(on_page->if_blocked_by_commit_xact == 1)) {
			on_page->if_blocked_by_commit_xact = 0;

			/* Bookkeeping for migration: */
			dec_pages_in_transaction(on_dr);
		} else
			DSNVM_BUG();
		spin_unlock(&on_dr->page_lock[dro]);

		DSNVM_PRINTK_BLOCK("Unblock (revert) dr_no %lu dro %u",
			dr_no, dro);
	}

	/* Failed, so free this redo-log, including buffers */
	xact_free_log_data(log_rec);

	transaction_exit();

	return 0;
}

/*
 * This functions describes:
 *	ON handler for phase 2 of commit protocol
 *
 * Related IB API:
 *	ibapi_multi_send_reply
 *
 * It will do the actual commit: send replicas to coherent and redundant copies,
 * and copy data from redo-log to local ON_REGION pages.
 */
int dsnvm_handle_commit_xact(char *msg, char *reply_addr, unsigned int *reply_len, int sender_id)
{
	struct dr_no_dro_page_offset *meta_for_areas;
	struct dsnvm_commit_xact_id_request_header *meta_msg;
	struct dsnvm_log_record *xact_log;
	struct status_reply_msg *reply;
	int *nr_reps_per_area;
	int i, ret, log_id;
	int nr_areas, rep_degree, xact_id;

	transaction_enter();

	reply = (struct status_reply_msg *)reply_addr;
	*reply_len = sizeof(struct status_reply_msg);

	/* Get request metadata */
	meta_msg = (struct dsnvm_commit_xact_id_request_header *)msg;
	xact_id = meta_msg->xact_id;

	/* Find saved redo-log by xact_id */
	xact_log = find_log_by_xact_id(xact_id);
	if (unlikely(!xact_log)) {
		DSNVM_BUG("Sender-ID: %d, xact_id: %d", sender_id, xact_id);
		transaction_exit();
		reply->status = DSNVM_REPLY_NO_LOG;
		return 0;
	}
	log_id = xact_log->log_id;

	/* Change log state and flush back */
	xact_log->state = DSNVM_LOG_NOT_TO_REPLAY | DSNVM_LOG_PHASE_2_MIDDLE;
	dsnvm_flush_buffer(&xact_log->state, sizeof(xact_log->state));

	/* Get saved metadata */
	meta_for_areas = xact_log->meta_for_areas;
	rep_degree = xact_log->rep_degree;
	nr_areas = xact_log->nr_areas;

	DSNVM_PRINTK("Sender-ID: %d, xact_id: %d, log_id: %d, nr_areas: %d "
		"rep_degree: %d", sender_id, xact_id, log_id, nr_areas, rep_degree);

	nr_reps_per_area = kmalloc(nr_areas * sizeof(int), GFP_KERNEL);
	if (!nr_reps_per_area) {
		reply->status = DSNVM_ENOMEM;
		goto error;
	}
	for (i = 0; i < nr_areas; i++) {
		/* Myself is a copy */
		nr_reps_per_area[i] = rep_degree - 1;
	}

	/* Step I: send replicas to coherent and redundant copies */
	ret = make_coherence_and_replication(sender_id, nr_areas, meta_for_areas,
					     xact_log->data_areas,
					     nr_reps_per_area, 0, 0); 

	if (unlikely(ret)) {
		reply->status = DSNVM_REPLY_CANNOT_MAKE_ENOUGH_REPLICA;
		goto error;
	}

	/* Step II: commit locally */
	for (i = 0; i < nr_areas; i++) {
		unsigned long dr_no = meta_for_areas[i].dr_no;
		unsigned int dro = meta_for_areas[i].dro;
		unsigned long pgoft =  meta_for_areas[i].page_offset;
		struct atomic_struct *data_area = &xact_log->data_areas[i];
		struct on_region_info *on_dr;
		struct on_page_info *on_page;
		void *dst, *src;

		on_dr = ht_get_on_region(dr_no);
		if (unlikely(!on_dr)) {
			DSNVM_BUG("Commit locally without ON: %lu, Sender-ID: %d",
				dr_no, sender_id);
			continue;
		}

		BUG_ON(is_on_region_migrating_out(on_dr));

		spin_lock(&on_dr->page_lock[dro]);
		on_page = &on_dr->mapping[dro];

		/*
		 * Already marked by phase 1: dsnvm_handle_request_commit_xact()
		 * It is BUG() if the ON_REGION page is unblocked at the beginning.
		 */
		if (likely(on_page->if_blocked_by_commit_xact == 1)) {
			if (unlikely(!on_page->local_pfn)) {
				DSNVM_BUG("no local pfn for on page dr_no %lu dro %u",
					dr_no, dro);
				reply->status = DSNVM_REPLY_INVALID;
				spin_unlock(&on_dr->page_lock[dro]);
				goto error;
			}

			/* Well, for safety... */
			WARN_ON((pgoft + data_area->len) > PAGE_SIZE);

			/* The destination address that within a ON_PAGE */
			dst = (void *)(pfn_to_dsnvm_virt(on_page->local_pfn) + pgoft);

			/* The source address of the saved area, in redo-log */
			src = data_area->vaddr;

			/* Do the actual commit! */
			memcpy(dst, src, data_area->len);
			dsnvm_flush_buffer(dst, data_area->len);

			/* Hacker: MUST match those info printed at phase 1 handler */
			DSNVM_PRINTK("Actual commit to dr_no: %lu dro: %u, "
				"cp data: %p -> %p, len: %zu", dr_no, dro, src, dst, data_area->len);
		} else {
			DSNVM_BUG("ON %d trying to commit to a non-blocked page dr_no %lu dro %u",
				DSNVM_LOCAL_ID, dr_no, dro);

			reply->status = DSNVM_REPLY_INVALID;
			spin_unlock(&on_dr->page_lock[dro]);
			goto error;
		}
		spin_unlock(&on_dr->page_lock[dro]);
	}

	/* Change log state and flush back */
	xact_log->state = DSNVM_LOG_NOT_TO_REPLAY | DSNVM_LOG_PHASE_2_SUCCEED;
	dsnvm_flush_buffer(&xact_log->state, sizeof(xact_log->state));

	/* Do not free reply, since IB needs to send the reply first */
	reply->status = DSNVM_REPLY_SUCCESS;

	ibapi_free_recv_buf(msg);
	if (nr_reps_per_area)
		kfree(nr_reps_per_area);

	transaction_exit();

	return 0;

error:
	ibapi_free_recv_buf(msg);
	if (nr_reps_per_area)
		kfree(nr_reps_per_area);

	/*
	 * The commiting node will restart 3-phase commit protocol,
	 * thus this redo-log won't be used anymore. Need a new one
	 * while handling phase-1.
	 */
	xact_free_log_data(xact_log);

	transaction_exit();

	return 0;
}

/*
 * This functions describes:
 *	ON handler for phase 3 of commit protocol
 *
 * Related IB API:
 *	ibapi_multi_send_reply
 *
 * It will deleta redo-log and unlock all related ON_PAGEs.
 * For strong ordering, we need reply.
 */
int dsnvm_handle_ack_commit_xact(char *msg, char *reply_addr,
				 unsigned int *reply_len, int sender_id,
				 bool revert)
{
	struct status_reply_msg *reply;
	struct dsnvm_commit_xact_id_request_header *meta_msg;
	struct dr_no_dro_page_offset *meta_for_areas;
	struct dsnvm_log_record *xact_log;
	int nr_areas, xact_id, log_id;
	int i, j;

	transaction_enter();

	reply = (struct status_reply_msg *)reply_addr;
	reply->status = DSNVM_REPLY_SUCCESS;
	*reply_len = sizeof(struct status_reply_msg);

	/* Get request metadata */
	meta_msg = (struct dsnvm_commit_xact_id_request_header *)msg;
	xact_id = meta_msg->xact_id;

	/* Find saved redo-log by xact_id */
	xact_log = find_log_by_xact_id(xact_id);
	if (unlikely(!xact_log)) {
		DSNVM_BUG("Fail to find log, Sender-ID: %d, xact_id: %d, revert? %d",
			sender_id, xact_id, revert);
		reply->status = DSNVM_REPLY_NO_LOG;
		goto out;
	}
	log_id = xact_log->log_id;

	/* Change log state and flush back */
	xact_log->state = DSNVM_LOG_NOT_TO_REPLAY | DSNVM_LOG_PHASE_3_MIDDLE;
	dsnvm_flush_buffer(&xact_log->state, sizeof(xact_log->state));

	/* Get saved metadata */
	meta_for_areas = xact_log->meta_for_areas;
	nr_areas = xact_log->nr_areas;

	DSNVM_PRINTK("Sender-ID: %d, xact_id: %d, log_id: %d, nr_areas: %d ",
		sender_id, xact_id, log_id, nr_areas);

	for (i = 0; i < nr_areas; i++) {
		struct on_region_info *on;
		struct on_page_info *page_info;
		unsigned long dr_no = meta_for_areas[i].dr_no;
		unsigned int dro = meta_for_areas[i].dro;
		struct atomic_struct *data_area = &xact_log->data_areas[i];

		for (j = 0; j < i; j++) {
			if (dr_no == meta_for_areas[j].dr_no &&
			    dro == meta_for_areas[j].dro) {
				break;
			}
		}

		/* Already seen this page */
		if (j != i)
			continue;

		on = ht_get_on_region(dr_no);
		if (unlikely(!on)) {
			if (unlikely(proxy_find_new_owner(dr_no) == 0)) {
				reply->status = DSNVM_REPLY_BUG;
				DSNVM_BUG("dr_no: %lu, dro: %u", dr_no, dro);
			}
			continue;
		}

		BUG_ON(is_on_region_migrating_out(on));

		/*
		 * Already marked by phase 1: dsnvm_handle_request_commit_xact()
		 * It is BUG() if the ON_REGION page is unblocked at the beginning.
		 */
		spin_lock(&on->page_lock[dro]);
		page_info = &on->mapping[dro];
		if (likely(page_info->if_blocked_by_commit_xact == 1)) {
			page_info->if_blocked_by_commit_xact = 0;

			/* Bookkeeping for migration: */
			dec_pages_in_transaction(on);

			/* counts a valid commit */
			if (!revert) {
				atomic_inc(&on->nr_commit[sender_id]);
				atomic64_add(data_area->len, &on->nr_commit_bytes[sender_id]);
			}
		} else {
			DSNVM_BUG("Sender-ID: %d xact_id: %d, revert? %d, "
				"dr_no: %lu, dro: %u", sender_id, xact_id, revert, dr_no, dro);
			reply->status = DSNVM_REPLY_BUG;
		}
		dsnvm_flush_buffer(&page_info->if_blocked_by_commit_xact, sizeof(int));
		spin_unlock(&on->page_lock[dro]);

		DSNVM_PRINTK_BLOCK("Unblock dr_no %lu dro %u",
			dr_no, dro);
	}

	/* Safe to delete redo-log */
	xact_free_log_data(xact_log);

out:
	ibapi_free_recv_buf(msg);

	transaction_exit();

	if (revert)
		count_dsnvm_event(DSNVM_XACT_REVERT_RX);

	return 0;
}

/*
 * This functions describes:
 *	ON handler for special case which only 1 ON involved
 *
 * Related IB API:
 *	ibapi_atomic_send_yy
 *
 * Phase 1:	Lock local ON_PAGEs requested by commiting node
 * Phase 2:	a) Make coherence copies,
 *		b) Copy data to ON_PAGEs
 * Phase 3:	Unlock local ON_PAGEs requested by commiting node
 */
int dsnvm_handle_commit_xact_single_on(int sender_id, int nr_reqs,
				       struct atomic_struct *reqs,
				       char *reply_addr, unsigned int *reply_len)
{
	struct dsnvm_commit_repdegree_request_header *meta_msg;
	struct dr_no_dro_page_offset *meta_for_areas;
	struct dsnvm_log_record *log_rec;
	struct on_region_info *on_dr;
	struct on_page_info *on_page;
	struct status_reply_msg *reply;
	unsigned int dro, page_offset;
	unsigned long dr_no;
	int *nr_reps_per_area = NULL;
	int i, j;
	int xact_id, rep_degree, ret, nr_areas;
	int log_id;
	int failed_area = 0;
	size_t len;

	count_dsnvm_event(DSNVM_SINGLE_REMOTE_ON_XACT_RX);

	transaction_enter();

	/* Fill reply info first */
	reply = (struct status_reply_msg *)reply_addr;
	reply->status = DSNVM_REPLY_INVALID;
	*reply_len = sizeof(struct status_reply_msg);

	if (unlikely(nr_reqs <= 1)) {
		DSNVM_BUG("no data req in commit xact");
		reply->status = DSNVM_NO_DATA_IN_REQUEST;
		transaction_exit();
		return 0;
	}

	/* Get request metadata */
	meta_for_areas = reqs[1].vaddr;
	meta_msg = reqs[0].vaddr;
	nr_areas = meta_msg->nr_reqs;
	rep_degree = meta_msg->rep_degree;
	xact_id = meta_msg->xact_id;

	/* First two reqs are metadata */
	if (unlikely(nr_areas != nr_reqs - 2)) {
		DSNVM_BUG("nr_areas: %d, nr_reqs %d", nr_areas, nr_reqs);
                reply->status = DSNVM_REQ_AREA_DONT_MACTH;
		transaction_exit();
		return 0;
	}

	/* Allocate redo-log */
	log_rec = alloc_dsnvm_log(xact_id, &log_id);
	if (unlikely(!log_rec)) {
		reply->status = DSNVM_REPLY_LOG_FULL;
		transaction_exit();
		return 0;
	}

	/* Save metadata into redo-log */
	log_rec->xact_id = xact_id;
	log_rec->sender_id = sender_id;
	log_rec->single_on = 1;
	log_rec->state = DSNVM_LOG_TO_REPLAY | DSNVM_LOG_PHASE_1_MIDDLE;
	log_rec->nr_areas = nr_areas;
	log_rec->meta_for_areas = meta_for_areas;
	log_rec->rep_degree = rep_degree;
	for (i = 0; i < nr_areas; i++) {
		unsigned long dr_no = meta_for_areas[i].dr_no;
		unsigned int dro = meta_for_areas[i].dro;

		/*
		 * Save area info into redo-log
		 *
		 * Note that: reqs buffers are allocated by IB layer, we are
		 * just saving the virtual kernel address of these buffers into
		 * our log_rec. Those buffers are freed by Hotpot when we call
		 * xact_free_log_data().
		 */
		log_rec->data_areas[i].vaddr = reqs[i+2].vaddr;
		log_rec->data_areas[i].len = reqs[i+2].len;

		DSNVM_PRINTK("Logging area[%d]: dr_no %lu dro %u, VA: %p len: %zu",
			i, dr_no, dro, reqs[i+2].vaddr, reqs[i+2].len);
	}

	/* Flush back all log except log_id first */
	dsnvm_flush_buffer(log_rec, sizeof(*log_rec));

	/* Now set log_id and flush back, make this log valid persistent */
	log_rec->log_id = log_id;
	dsnvm_flush_buffer(&log_rec->log_id, sizeof(log_rec->log_id));

	DSNVM_PRINTK("Sender-ID: %d, log_id: %d, xact_id: %d, "
		"nr_reqs: %d, nr_area: %d, rep_degree: %d",
		sender_id, log_id, xact_id, nr_reqs, nr_areas, rep_degree);

	nr_reps_per_area = kmalloc(nr_areas * sizeof(int), GFP_KERNEL);
	if (unlikely(!nr_reps_per_area)) {
		DSNVM_BUG();
		reply->status = DSNVM_ENOMEM;
		xact_free_log_data(log_rec);
		transaction_exit();
		return 0;
	}

	/*
	 * Phase 1:
	 *	Block all ON_REGION pages involved in this xact
	 */
	for (i = 0; i < nr_areas; i++) {
		/* This ON counts a valid copy */
		nr_reps_per_area[i] = rep_degree - 1;
		dro = meta_for_areas[i].dro;
		dr_no = meta_for_areas[i].dr_no;

		on_dr = ht_get_on_region(dr_no);
		if (unlikely(!on_dr)) {
			if (likely(proxy_find_new_owner(dr_no) > 0)) {
				reply->status = DSNVM_REPLY_ON_REGION_MIGRATING_OUT;
			} else {
				DSNVM_BUG("non-exist dr_no %lu dro %u", dr_no, dro);
				reply->status = DSNVM_NONEXIST_DR_NO;
			}

			failed_area = i;
			goto error;
		}

		/* No transaction above ON that is migrating out: */
		spin_lock(&on_dr->region_lock);
		if (unlikely(is_on_region_migrating_out(on_dr))) {
			spin_unlock(&on_dr->region_lock);
			DSNVM_PRINTK("dr_no: %lu is migrating out", dr_no);

			count_dsnvm_event(DSNVM_XACT_REJECT_DUE_TO_MIGRATION);
			reply->status = DSNVM_REPLY_ON_REGION_MIGRATING_OUT;
			failed_area = i;
			goto error;
		}

		spin_lock(&on_dr->page_lock[dro]);
		on_page = &on_dr->mapping[dro];
		for (j = 0; j < i; j++) {
			if (dr_no == meta_for_areas[j].dr_no &&
			    dro == meta_for_areas[j].dro) {
				break;
			}
		}

		/* First time see this page */
		if (likely(j == i)) {
			if (unlikely(on_page->if_blocked_by_commit_xact == 1)) {
				/*
				 * Blocked by another XACT
				 */
				DSNVM_PRINTK_BLOCK("Concurrent block dr_no %lu dro %u",
					 dr_no, dro);

				reply->status = DSNVM_REPLY_PAGE_IN_OTHER_XACT;
				spin_unlock(&on_dr->page_lock[dro]);
				spin_unlock(&on_dr->region_lock);
				put_on_region(on_dr);

				count_dsnvm_event(DSNVM_XACT_REJECT_DUE_TO_BLOCKED_PAGES);
				failed_area = i;
				goto error;
			} else {
				/*
				 * Mark this ON_REGION page as blocked
				 */
				reply->status = DSNVM_REPLY_SUCCESS;
				on_page->if_blocked_by_commit_xact = 1;

				/* Bookkeeping for migration: */
				inc_pages_in_transaction(on_dr);

				DSNVM_PRINTK_BLOCK("Block dr_no %lu dro %u",
					dr_no, dro);
			}
		}
		spin_unlock(&on_dr->page_lock[dro]);
		spin_unlock(&on_dr->region_lock);
		put_on_region(on_dr);
	}
	log_rec->state = DSNVM_LOG_TO_REPLAY | DSNVM_LOG_PHASE_1_SUCCEED;

	/*
	 * If error happens below, we should unblock all ON_REGION
	 * pages that were blocked by the above code.
	 */
	failed_area = nr_areas;

	/*
	 * Phase 2:
	 *	I) make coherence and replicas
	 */
	log_rec->state = DSNVM_LOG_TO_REPLAY | DSNVM_LOG_PHASE_2_MIDDLE;
	dsnvm_flush_buffer(&log_rec->state, sizeof(log_rec->state));

	ret = make_coherence_and_replication(sender_id, nr_areas, meta_for_areas,
					     reqs+2, nr_reps_per_area, 1, 0); 

	if (unlikely(ret)) {
		reply->status = DSNVM_REPLY_CANNOT_MAKE_ENOUGH_REPLICA;
		goto error;
	}

	/*
	 * Phase 2:
	 *	II) Do the actual commiting, copy data to ON_PAGE
	 */
	for (i = 0; i < nr_areas; i++) {
		unsigned long to_kvaddr, from_kvaddr;

		dro = meta_for_areas[i].dro;
		dr_no = meta_for_areas[i].dr_no;
		page_offset = meta_for_areas[i].page_offset;

		on_dr = ht_get_on_region(dr_no);
		if (unlikely(!on_dr)) {
			DSNVM_BUG("non-exist dr_no %lu dro %u", dr_no, dro);
			continue;
		}

		BUG_ON(is_on_region_migrating_out(on_dr));

		/*
		 * Already marked by the above phase 1.
		 * It is BUG() if the ON_REGION page is unblocked here.
		 */
		spin_lock(&on_dr->page_lock[dro]);
		on_page = &on_dr->mapping[dro];
		if (likely(on_page->if_blocked_by_commit_xact == 1)) {
			if (unlikely(!pfn_is_dsnvm(on_page->local_pfn))) {
				DSNVM_BUG();
				reply->status = DSNVM_REPLY_INVALID;
				spin_unlock(&on_dr->page_lock[dro]);
				put_on_region(on_dr);
				goto error;
			}

			/* The destination address that within a ON_PAGE */
			to_kvaddr = pfn_to_dsnvm_virt(on_page->local_pfn);
			to_kvaddr += page_offset;

			/* The source address of the saved area, in redo-log */
			from_kvaddr = (unsigned long)reqs[i+2].vaddr;
			len = reqs[i+2].len;

			/* Well, for safety... */
			WARN_ON((page_offset + len) > PAGE_SIZE);

			/* Do the actual commit! */
			memcpy((void *)to_kvaddr, (void *)from_kvaddr, len);
			dsnvm_flush_buffer((void *)to_kvaddr, len);
			nr_reps_per_area[i]--;

			DSNVM_PRINTK("Actual commit to dr_no: %lu dro: %u, "
				"cp data: %#lx -> %#lx, len: %zu",
				dr_no, dro, from_kvaddr, to_kvaddr, len);
		} else {
			DSNVM_BUG("Commit to non-blocked page dr_no %lu dro %u", dr_no, dro);
			reply->status = DSNVM_REPLY_INVALID;
			spin_unlock(&on_dr->page_lock[dro]);
			put_on_region(on_dr);
			goto error;
		}
		spin_unlock(&on_dr->page_lock[dro]);
		put_on_region(on_dr);
	}
	log_rec->state = DSNVM_LOG_TO_REPLAY | DSNVM_LOG_PHASE_2_SUCCEED;

	/*
	 * Phase 3:
	 * 	Unblock all ON_REGION pages involved in this xact
	 */
	log_rec->state = DSNVM_LOG_TO_REPLAY | DSNVM_LOG_PHASE_3_MIDDLE;
	dsnvm_flush_buffer(&log_rec->state, sizeof(log_rec->state));
	for (i = 0; i < nr_areas; i++) {
		struct atomic_struct *data_area = &log_rec->data_areas[i];
		dro = meta_for_areas[i].dro;
		dr_no = meta_for_areas[i].dr_no;

		for (j = 0; j < i; j++) {
			if (dr_no == meta_for_areas[j].dr_no &&
			    dro == meta_for_areas[j].dro) {
				break;
			}
		}

		/* Already seen this page before */
		if (j != i)
			continue;

		on_dr = ht_get_on_region(dr_no);
		if (unlikely(!on_dr)) {
			reply->status = DSNVM_NONEXIST_DR_NO;
			DSNVM_BUG("non-exist dr_no %lu dro %u\n", dr_no, dro);
			goto error;
		}

		BUG_ON(is_on_region_migrating_out(on_dr));

		spin_lock(&on_dr->page_lock[dro]);
		on_page = &on_dr->mapping[dro];
		if (likely(on_page->if_blocked_by_commit_xact == 1)) {
			on_page->if_blocked_by_commit_xact = 0;

			/* Bookkeeping for migration: */
			dec_pages_in_transaction(on_dr);
			atomic_inc(&on_dr->nr_commit[sender_id]);
			atomic64_add(data_area->len, &on_dr->nr_commit_bytes[sender_id]);
		} else
			DSNVM_BUG("dr_no %lu dro %u", dr_no, dro);
		spin_unlock(&on_dr->page_lock[dro]);
		dsnvm_flush_buffer(&on_page->if_blocked_by_commit_xact, sizeof(int));
		put_on_region(on_dr);

		DSNVM_PRINTK_BLOCK("Unblock dr_no %lu dro %u",
			dr_no, dro);
	}

	failed_area = 0;
	reply->status = DSNVM_REPLY_SUCCESS;

	xact_free_log_data(log_rec);

	if (nr_reps_per_area)
		kfree(nr_reps_per_area);

	transaction_exit();

	return 0;

error:
	for (i = 0; i < failed_area; i++) {
		dro = meta_for_areas[i].dro;
		dr_no = meta_for_areas[i].dr_no;

		for (j = 0; j < i; j++) {
			if (dr_no == meta_for_areas[j].dr_no &&
			    dro == meta_for_areas[j].dro) {
				break;
			}
		}
	
		/* Already seen this page before */
		if (j != i)
			continue;

		on_dr = ht_get_on_region(dr_no);
		if (unlikely(!on_dr))
			continue;

		BUG_ON(is_on_region_migrating_out(on_dr));

		/*
		 * Revert those blocked ON_REGION pages back to unblocked.
		 * If it is unblocked at the beginning, then it is BUG()!
		 */
		spin_lock(&on_dr->page_lock[dro]);
		on_page = &on_dr->mapping[dro];
		if (likely(on_page->if_blocked_by_commit_xact == 1)) {
			on_page->if_blocked_by_commit_xact = 0;

			/* Bookkeeping for migration: */
			dec_pages_in_transaction(on_dr);
		} else
			DSNVM_BUG("dr_no: %lu, dro: %u", dr_no, dro);
		spin_unlock(&on_dr->page_lock[dro]);
		dsnvm_flush_buffer(&on_page->if_blocked_by_commit_xact, sizeof(int));
		put_on_region(on_dr);

		DSNVM_PRINTK_BLOCK("Unblock (revert) dr_no %lu dro %u",
			dr_no, dro);
	}

	xact_free_log_data(log_rec);

	if (nr_reps_per_area)
		kfree(nr_reps_per_area);

	transaction_exit();

	return 0;
}

static const unsigned char *namestrings[] = {
	"front_remote_ons",
	"back_remote_ons",
	"MRSW Model"
};

/*
 * This function describes:
 *	MRSW whole commit phase, and
 *	MRMW commit xact phase 1
 *
 * Related IB API:
 *	ibapi_multi_atomic_send_yy
 *
 * Request to commit the xact at all ONs that are involved in the xact at the
 * same time (actually, front and back sets), and send all metadata and specific
 * data to remote ONs.
 *
 * The handler of remote ON will allocate a redo-log for xact areas.
 *
 * RETURN:
 *	0 on success
 *	DSNVM_RETRY
 *	negative value on failure
 */
static int dsnvm_request_commit_xact_to_ons(struct vm_area_struct **vma,
					    int nr_remote_ons, unsigned int *remote_ons,
					    int nr_areas, struct atomic_struct *areas,
					    int rep_degree, int xact_id,
					    int *nr_remote_ons_need_revert,
					    unsigned int *remote_ons_need_revert,
					    int name_id)
{
	int i, j, ret = 0;
	unsigned int nr_areas_per_on[DSNVM_MAX_NODE];
	struct dsnvm_commit_repdegree_request_header req_header[DSNVM_MAX_NODE];
	struct dr_no_dro_page_offset **meta_for_areas;
	struct atomic_struct **xact_reqs;
	struct max_reply_msg *reply_msg;

#ifdef DSNVM_MODE_MRSW
	count_dsnvm_event(DSNVM_SINGLE_REMOTE_ON_XACT_TX);
#endif

	for (i = 0; i < nr_remote_ons; i++)
		DSNVM_PRINTK("%s, NODE-ID: %d",
			namestrings[name_id], remote_ons[i]);

	/* Allocate arrays */
	reply_msg = kmalloc(sizeof(*reply_msg) * nr_remote_ons, GFP_KERNEL);
	if (!reply_msg)
		return -ENOMEM;

	xact_reqs = kmalloc(sizeof(*xact_reqs) * nr_remote_ons, GFP_KERNEL);
	if (!xact_reqs) {
		kfree(reply_msg);
		return -ENOMEM;
	}

	meta_for_areas = kmalloc(sizeof(*meta_for_areas) * nr_remote_ons, GFP_KERNEL);
	if (!meta_for_areas) {
		kfree(xact_reqs);
		return -ENOMEM;
	}

	/* Initialize these arrays */
	for (i = 0; i < nr_remote_ons; i++) {
		meta_for_areas[i] = kmalloc(sizeof(struct dr_no_dro_page_offset) * nr_areas, GFP_KERNEL);
		if (!meta_for_areas[i]) {
			ret = -ENOMEM;
			goto out;
		}

		/* Need 2 more metadata reqs, thus always prepare 2 more */
		xact_reqs[i] = kmalloc(sizeof(struct atomic_struct) * (nr_areas + 2), GFP_KERNEL);
		if (!xact_reqs[i]) {
			ret = -ENOMEM;
			goto out;
		}

		nr_areas_per_on[i] = 0;

#ifdef DSNVM_MODE_MRSW
		/*
		 * For MRSW, each ON can acts on it on and does not need three phases.
		 * This is the same as MRMW single_on commit
		 */
		req_header[i].op = DSNVM_OP_COMMIT_XACT_SINGLE_ON;
#else
		req_header[i].op = DSNVM_OP_REQUEST_COMMIT_XACT;
#endif

		/* will be updated below */
		req_header[i].nr_reqs = 0;
		req_header[i].xact_id = xact_id;
		/* Myself is a copy */
		req_header[i].rep_degree = rep_degree - 1;

		/* Fill the first metadata request */
		xact_reqs[i][0].vaddr = &req_header[i];
		xact_reqs[i][0].len = sizeof(struct dsnvm_commit_repdegree_request_header);

		/* Fill the second metadata request */
		/* Will update .len field below */
		xact_reqs[i][1].vaddr = meta_for_areas[i];
	}

	/* This loop assign areas to each node array */
	for (i = 0; i < nr_areas; i++) {
		unsigned int dro;
		struct dn_region_info *dr;
		struct vm_area_struct *v = vma[i];
		struct dsnvm_client_file *f = DSNVM_FILE(v);
		unsigned long kern_pfn, kern_paddr;
		unsigned long vaddr = (unsigned long)areas[i].vaddr;
		unsigned long pgoft = (unsigned long)areas[i].vaddr % PAGE_SIZE;
		int curr_on = 0, curr_on_reqs;

		dro = virt_to_dro(vaddr, f);
		dr = get_dn_region(f, vaddr); 
		if (unlikely(!DR_MMAPED(dr, f))) {
			DSNVM_BUG();
			ret = -EFAULT;
			goto out;
		}

		/* Skip local ON pages */
		if (dr->owner_id == DSNVM_LOCAL_ID) {
			continue;
		}

		/*
		 * Find the slot in remote_on array
		 * Note that since we separate remote_ons into front and back
		 * sets, so this loop may fail to find the owner_id in the
		 * passed remote_ons[] array, which is totally okay.
		 */
		for (j = 0; j < nr_remote_ons; j++) {
			if (remote_ons[j] == dr->owner_id) {
				curr_on = j;
				break;
			}
		}

		/* Belongs to another list */
		if (j == nr_remote_ons) {
			continue;
		}

                DSNVM_PRINTK("Remote-ON: %d dr_no: %lu dro: %u",
                        remote_ons[curr_on], dr->dr_no, dro);

		/* Save the metadata on the per-node basis */
		curr_on_reqs = nr_areas_per_on[curr_on];
		meta_for_areas[curr_on][curr_on_reqs].dr_no = dr->dr_no;
		meta_for_areas[curr_on][curr_on_reqs].dro = dro;
		meta_for_areas[curr_on][curr_on_reqs].page_offset = pgoft;

		spin_lock(&dr->page_lock[dro]);
		kern_pfn = dr->mapping[dro];
		kern_paddr = kern_pfn << PAGE_SHIFT;
		spin_unlock(&dr->page_lock[dro]);

		/*
		 * Yes, Virginia, it is physical address.
		 * We are using ibapi_multi_atomic_send_yy, which uses physical
		 * address to register DMA. The vaddr name is confusing though.
		 */
		xact_reqs[curr_on][curr_on_reqs+2].vaddr = (void *)(kern_paddr + pgoft);
		xact_reqs[curr_on][curr_on_reqs+2].len = areas[i].len;

		/* It's BUG, since we already split it out */
		WARN_ON((pgoft + areas[i].len) > PAGE_SIZE);

		nr_areas_per_on[curr_on]++;

		if (unlikely(nr_areas_per_on[curr_on] >= MAX_ATOMIC_SEND_NUM)) {
			DSNVM_BUG("too many areas in one xact, aborting xact");
			ret = -EFAULT;
			goto out;
		}
	}

	/* Fill the req_header array */
	for (i = 0; i < nr_remote_ons; i++) {
		/*
		 * Blame migration.
		 * Ownership changed in the middle.
		 */
		if (unlikely(nr_areas_per_on[i] == 0)) {
			ret = DSNVM_RETRY;
			goto out;
		}

		req_header[i].nr_reqs = nr_areas_per_on[i];

		xact_reqs[i][1].len = nr_areas_per_on[i] * sizeof(struct dr_no_dro_page_offset);

		DSNVM_PRINTK("%s node-id: %2d nr_reqs %d",
			namestrings[name_id], remote_ons[i], nr_areas_per_on[i]);

		/* including the two headers */
		nr_areas_per_on[i] += 2;
	}

	DSNVM_PRINTK("Before sending (phase 1) multicast to total %d nodes",
		nr_remote_ons);
	ibapi_multi_atomic_send_yy(nr_remote_ons, remote_ons, xact_reqs,
		nr_areas_per_on, reply_msg);
	DSNVM_PRINTK("After sending (phase 1) multicast to total %d nodes",
		nr_remote_ons);

	/*
	 * Remote ON can reply:
	 *	DSNVM_REPLY_SUCCESS			ret = 0
	 *	DSNVM_ENOREGION				ret = -EFAULT
	 *	DSNVM_NO_DATA_IN_REQUEST		ret = -EFAULT
	 *	DSNVM_REQ_AREA_DONT_MACTH		ret = -EFAULT
	 *	DSNVM_REPLY_LOG_FULL			ret = -EFAULT
	 *	DSNVM_REPLY_PAGE_IN_OTHER_XACT		ret = DSNVM_RETRY
	 *	DSNVM_REPLY_ON_REGION_MIGRATING_OUT	ret = DSNVM_RETRY
	 *
	 * Any other reply-status means BUG, memory leak or something.
	 */
	ret = 0;
	for (i = 0; i < nr_remote_ons; i++) {
		struct status_reply_msg *status_reply;

		status_reply = (struct status_reply_msg *)(&reply_msg[i]);
		if (likely(status_reply->status == DSNVM_REPLY_SUCCESS)) {
			/*
			 * Record this node in case we need to revert
			 * its ON_REGION state back to unblocked
			 */
			remote_ons_need_revert[*nr_remote_ons_need_revert] = remote_ons[i];
			*nr_remote_ons_need_revert += 1;

			DSNVM_PRINTK("i = %d, nr_remote_ons = %d, Node: %d succeed, "
				"add to revert list", i, nr_remote_ons, remote_ons[i]);
		} else {
			DSNVM_PRINTK("[%s:%d] i = %d, nr_remote_ons = %d, xact_id = %d, Node: %d, reports: %s (%d)",
				__func__, __LINE__, i, nr_remote_ons, xact_id, remote_ons[i],
				dsnvm_status_string(status_reply->status), status_reply->status);

			for (j = 0; j < nr_remote_ons; j++) {
				DSNVM_PRINTK("   %s remote_ons[%d] = node_id %d",
				namestrings[name_id], j, remote_ons[j]);
			}

			if (likely(status_reply->status == DSNVM_REPLY_PAGE_IN_OTHER_XACT ||
				   status_reply->status == DSNVM_REPLY_ON_REGION_MIGRATING_OUT))
				ret = DSNVM_RETRY;
			else
				ret = -EFAULT;
		}
	}

	/* DEBUG only */
	for (i = 0; i < *nr_remote_ons_need_revert; i++) {
		DSNVM_PRINTK("   %s remote_ons_need_revert[%d] = node_id %d",
		namestrings[name_id], i, remote_ons_need_revert[i]);
	}

out:
	if (reply_msg)
		kfree(reply_msg);
	if (xact_reqs) {
		for (i = 0; i < nr_remote_ons; i++)
			if (xact_reqs[i])
				kfree(xact_reqs[i]);
		kfree(xact_reqs);
	}
	if (meta_for_areas) {
		for (i = 0; i < nr_remote_ons; i++)
			if(meta_for_areas[i])
				kfree(meta_for_areas[i]);
		kfree(meta_for_areas);
	}
	return ret;
}

/*
 * This function describes:
 *	MRMW Commit Phase 2
 *
 * Related IB API:
 *	ibapi_multi_send_reply
 *
 * RETURN:
 *	0 on success
 *	DSNVM_RETRY
 *	negative value on failure
 */
#ifndef DSNVM_MODE_MRSW
static int dsnvm_make_commit_xact_to_ons(int nr_remote_ons, unsigned int *remote_ons,
					 int nr_areas, struct atomic_struct *areas,
					 int xact_id)
{
	int i, ret = 0;
	struct dsnvm_commit_xact_id_request_header req_header;
	struct max_reply_msg *reply_msg;
	struct atomic_struct *send_msg_array;

	req_header.op = DSNVM_OP_COMMIT_XACT;
	req_header.xact_id = xact_id;

	/* Allocate arrays */
	reply_msg = kmalloc(sizeof(*reply_msg) * nr_remote_ons, GFP_KERNEL);
	if (!reply_msg)
		return -ENOMEM;

	send_msg_array = kmalloc(sizeof(*send_msg_array) * nr_remote_ons, GFP_KERNEL);
	if (!send_msg_array) {
		kfree(reply_msg);
		return -ENOMEM;
	}

	for (i = 0; i < nr_remote_ons; i++) {
		/* Fill the send message */
		send_msg_array[i].vaddr = &req_header;
		send_msg_array[i].len = sizeof(req_header);

		DSNVM_PRINTK("Send to NODE-ID: %d, xact_id: %d",
			remote_ons[i], xact_id);
	}

	/* Send the message */
	DSNVM_PRINTK("Before sending (phase 2) multicast to total %d nodes", nr_remote_ons);
	ibapi_multi_send_reply(nr_remote_ons, remote_ons, send_msg_array, reply_msg);
	DSNVM_PRINTK("After sending (phase 2) multicast to total %d nodes", nr_remote_ons);

	/*
	 * TODO:
	 * Like the phase 1 revert, we need to record which ONs succeed and which failed.
	 * So we could revert properly in begin_xact_helper if error happens.
	 */
	ret = 0;
	for (i = 0; i < nr_remote_ons; i++) {
		struct status_reply_msg *status_reply;
		status_reply = (struct status_reply_msg *)(&reply_msg[i]);

		if (status_reply->status == DSNVM_REPLY_INVALID ||
		    status_reply->status == DSNVM_REPLY_CANNOT_MAKE_ENOUGH_REPLICA) {
			DSNVM_PRINTK("commit phase 2 aborts %s",
				dsnvm_status_string(status_reply->status));
			ret = -EFAULT;
			if (status_reply->status == DSNVM_REPLY_CANNOT_MAKE_ENOUGH_REPLICA)
				ret = DSNVM_RETRY;
			goto out;
		}
	}

out:
	if (reply_msg)
		kfree(reply_msg);
	if (send_msg_array)
		kfree(send_msg_array);
	return ret;
}
#endif

/*
 * This function describes:
 *	MRMW special case, only one remote ON involved
 *
 * Related IB API:
 *	ibapi_atomic_send_yy
 *
 * No need to do 3-phase commit in commiting node, just do everything in one go.
 * Note that the remote handler still need to do the 3-phase locally.
 *
 * RETURN:
 *	0 on success
 *	DSNVM_RETRY
 *	negative value on failure
 */
#ifndef DSNVM_MODE_MRSW
static int dsnvm_commit_xact_to_single_on(struct vm_area_struct **vma,
					  unsigned int owner_id, int nr_areas,
					  struct atomic_struct *areas,
					  int rep_degree, int xact_id)
{
	struct dsnvm_commit_repdegree_request_header req_header;
	struct dr_no_dro_page_offset *meta_for_areas;
	struct atomic_struct *xact_reqs;
	struct status_reply_msg reply;
	int i, nr_valid_areas, ret = 0;
	DEFINE_PROFILE_TS(t_start, t_end, t_diff)

	count_dsnvm_event(DSNVM_SINGLE_REMOTE_ON_XACT_TX);

	DSNVM_PRINTK("Remote ON: %u, xact_id %d", owner_id, xact_id);

	meta_for_areas = kzalloc(sizeof(*meta_for_areas) * nr_areas, GFP_KERNEL);
	if (!meta_for_areas)
		return -ENOMEM;

	/* Need 2 more metadata reqs, thus always prepare 2 more */
	xact_reqs = kzalloc(sizeof(*xact_reqs) * (nr_areas + 2), GFP_KERNEL);
	if (!xact_reqs) {
		kfree(meta_for_areas);
		return -ENOMEM;
	}

	for (i = 0, nr_valid_areas = 0; i < nr_areas; i++) {
		unsigned int dro;
		struct dn_region_info *dr;
		struct vm_area_struct *v = vma[i];
		struct dsnvm_client_file *f = DSNVM_FILE(v);
		unsigned long user_vaddr = (unsigned long)areas[i].vaddr;
		unsigned long pgoft = user_vaddr % DSNVM_PAGE_SIZE;
		unsigned long kern_pfn, kern_paddr;

		dro = virt_to_dro(user_vaddr, f);
		dr = get_dn_region(f, user_vaddr); 
		if (unlikely(!DR_MMAPED(dr, f))) {
			DSNVM_BUG();
			ret = -EFAULT;
			goto out;
		}

		/* Well, since we passed all areas */
		if (dr->owner_id != owner_id) {
			continue;
		}

		DSNVM_PRINTK("area[%d]: dr_no %lu dro %u",
			nr_valid_areas, dr->dr_no, dro);

		/* Use mapping[dro] */
		spin_lock(&dr->page_lock[dro]);
		kern_pfn = dr->mapping[dro];
		kern_paddr = kern_pfn << PAGE_SHIFT;
		spin_unlock(&dr->page_lock[dro]);

		meta_for_areas[nr_valid_areas].dr_no = dr->dr_no;
		meta_for_areas[nr_valid_areas].dro = dro;
		meta_for_areas[nr_valid_areas].page_offset = pgoft;

		/* Save to requests array */
		/* And yes, we need physical address.. */
		xact_reqs[nr_valid_areas+2].vaddr = (void *)(kern_paddr + pgoft);
		xact_reqs[nr_valid_areas+2].len = areas[i].len;
		nr_valid_areas++;

		/* It's BUG, since we already split it out */
		WARN_ON((pgoft + areas[i].len) > PAGE_SIZE);
	}

	if (unlikely(nr_valid_areas + 2 >= MAX_ATOMIC_SEND_NUM)) {
		DSNVM_BUG("too many areas in one xact, aborting xact");
		ret = -EACCES;
		goto out;
	}

	/*
	 * Without migration, nr_valid_areas must > 0.
	 * But with migration, nr_valid_areas may == 0.
	 */
	if (unlikely(nr_valid_areas == 0)) {
		ret = DSNVM_RETRY;
		goto out;
	}

	/* Myself is a copy */
	req_header.rep_degree = rep_degree - 1;
	req_header.nr_reqs = nr_valid_areas;
	req_header.op = DSNVM_OP_COMMIT_XACT_SINGLE_ON;

	/* The first metadata request */
	xact_reqs[0].vaddr = &req_header;
	xact_reqs[0].len = sizeof(req_header);

	/* The second metadata request */
	xact_reqs[1].vaddr = meta_for_areas;
	xact_reqs[1].len = nr_valid_areas * sizeof(*meta_for_areas);

	/* Now send to remote ON */
	DSNVM_PRINTK("Before sending to remote ON: %u, nr_areas: %d",
		owner_id, nr_valid_areas);

	/* plus 2 metadata */
	nr_valid_areas += 2;

	__START_PROFILE(t_start);
#if 0
	ibapi_atomic_send_yy(owner_id, xact_reqs, nr_valid_areas, (char *)&reply);
#else
	ibapi_multi_atomic_send_yy(1, &owner_id, &xact_reqs, &nr_valid_areas, (void *)&reply);
#endif
	__END_PROFILE(t_start, t_end, t_diff);
	__PROFILE_PRINTK("latency: %lld ns", timespec_to_ns(&t_diff));

	DSNVM_PRINTK("After sending to remote ON: %u", owner_id);

	/*
	 * Remote ON can reply:
	 *	DSNVM_REPLY_SUCCESS			ret = 0
	 *	DSNVM_NO_DATA_IN_REQUEST		ret = -EFAULT
	 *	DSNVM_REQ_AREA_DONT_MACTH		ret = -EFAULT
	 *	DSNVM_REPLY_LOG_FULL			ret = -EFAULT
	 *	DSNVM_ENOMEM				ret = -EFAULT
	 *	DSNVM_NONEXIST_DR_NO			ret = -EFAULT
	 *	DSNVM_REPLY_PAGE_IN_OTHER_XACT		ret = DSNVM_RETRY
	 *	DSNVM_REPLY_ON_REGION_MIGRATING_OUT	ret = DSNVM_RETRY
	 *	DSNVM_REPLY_CANNOT_MAKE_ENOUGH_REPLICA	ret = DSNVM_RETRY
	 *
	 * Any other reply-status means BUG, memory leak or something.
	 */
	ret = reply.status;
	if (unlikely(ret == DSNVM_REPLY_PAGE_IN_OTHER_XACT ||
		     ret == DSNVM_REPLY_CANNOT_MAKE_ENOUGH_REPLICA ||
		     ret == DSNVM_REPLY_ON_REGION_MIGRATING_OUT)) {
		DSNVM_PRINTK("remote ON: %u ask us to retry!", owner_id);
		ret = DSNVM_RETRY;
	} else if (likely(ret == DSNVM_REPLY_SUCCESS)) {
		DSNVM_PRINTK("remote ON: %u report success!", owner_id);
		ret = 0;
	} else {
		DSNVM_PRINTK("remote ON: %u report %s", owner_id, dsnvm_status_string(ret));
		ret = -EFAULT;
	}

out:
	kfree(xact_reqs);
	kfree(meta_for_areas);

	return ret;
}
#endif

struct dr_no_dro_len {
	__u64	dr_no;
	__u32	dro;
	size_t	len;
};

/*
 * Commit Phase 1 of ON==DN case pages
 * this is the same as request_commit_xact to a remote ON
 * but locally, we don't need to maintain a log or do any data copying at this phase
 * local is already doing COW during the xact
 *
 * RETURN:
 *	0 on success
 *	DSNVM_RETRY
 *	negative value on failure
 */
static int phase_1_of_self_on(int nr_pages, int *failed_page,
			      struct dr_no_dro_len *pages)
{
	int i, ret;

	/* No DN==ON case pages, do nothing */
	if (unlikely(nr_pages == 0))
		return 0;

	DSNVM_PRINTK("nr_pages_self_on: %d", nr_pages);

	ret = 0;
	*failed_page = 0;
	for (i = 0; i < nr_pages; i++) {
		struct on_region_info *on_dr;
		struct on_page_info *on_page;
		unsigned int dro;
		unsigned long dr_no;

		dr_no = pages[i].dr_no;
		dro = pages[i].dro;

		on_dr = ht_get_on_region(dr_no);
		if (unlikely(!on_dr)) {
			if (likely(proxy_find_new_owner(dr_no) > 0)) {
				/*
				 * The ON_REGION was migrated out in short
				 * period before this.
				 */
				ret = DSNVM_RETRY;
			} else {
				DSNVM_BUG("non-exist ON_REGION dr_no: %lu", dr_no);
				ret = -EFAULT;
			}

			*failed_page = i;
			break;
		}

		/* No transaction above ON that is migrating out: */
		spin_lock(&on_dr->region_lock);
		if (unlikely(is_on_region_migrating_out(on_dr))) {
			spin_unlock(&on_dr->region_lock);
			DSNVM_PRINTK("dr_no: %lu is migrating out", dr_no);

			/* Allow it retry, it is okay. */
			count_dsnvm_event(DSNVM_XACT_REJECT_DUE_TO_MIGRATION);
			ret = DSNVM_RETRY;
			*failed_page = i;
			break;
		}

		spin_lock(&on_dr->page_lock[dro]);
		on_page = &on_dr->mapping[dro];
		if (unlikely(on_page->if_blocked_by_commit_xact == 1)) {
			DSNVM_PRINTK_BLOCK("Concurrent block dr_no %lu dro %u",
				 dr_no, dro);

			/* Blocked by another xact, retry */
			ret = DSNVM_RETRY;
			spin_unlock(&on_dr->page_lock[dro]);
			spin_unlock(&on_dr->region_lock);
			put_on_region(on_dr);

			count_dsnvm_event(DSNVM_XACT_REJECT_DUE_TO_BLOCKED_PAGES);
			*failed_page = i;
			break;
		} else {
			DSNVM_PRINTK_BLOCK("Block dr_no %lu dro %u",
				dr_no, dro);

			/* Mark this page occupied: */
			on_page->if_blocked_by_commit_xact = 1;

			/* Bookkeeping, for migration: */
			inc_pages_in_transaction(on_dr);
		}
		spin_unlock(&on_dr->page_lock[dro]);
		spin_unlock(&on_dr->region_lock);

		put_on_region(on_dr);
		dsnvm_flush_buffer(on_page, sizeof(on_page));
	}

	/* Revert all local ON pages if error happens later */
	if (i == nr_pages)
		*failed_page = nr_pages;
	return ret;
}

/*
 * Commit Phase 2 of ON==DN case pages
 * Push coherence and replica to other nodes 
 *
 * RETURN:
 *	0 on success
 *	DSNVM_RETRY
 *	negative value on failure
 */
static int phase_2_of_self_on(int nr_pages, int nr_areas,
			      struct dr_no_dro_page_offset *meta_for_areas,
			      struct atomic_struct *coherence_replication_reqs,
			      unsigned int *nr_reps_per_area)
{
	int ret = 0;

	/* No DN==ON case pages, do nothing */
	if (unlikely(nr_pages == 0))
		return 0;

	DSNVM_PRINTK("nr_pages_self_on: %d", nr_pages);

	ret = make_coherence_and_replication(DSNVM_LOCAL_ID, nr_areas, meta_for_areas,
					     coherence_replication_reqs, nr_reps_per_area, 0, 1); 

	return ret;
}

/*
 *  Commit Phase 3 of ON==DN case pages
 *  Unlock all ON_PAGES involved
 *
 * RETURN:
 *	0 on success
 *	negative value on failure
 */
static int phase_3_of_self_on(int nr_pages, struct dr_no_dro_len *pages)
{
	int i, ret = 0;

	/* No DN==ON case pages, do nothing */
	if (unlikely(nr_pages == 0))
		return 0;

	DSNVM_PRINTK("nr_pages_self_on: %d", nr_pages);

	for (i = 0; i < nr_pages; i++) {
		struct on_region_info *on_dr;
		struct on_page_info *on_page;
		unsigned long dr_no;
		unsigned int dro;

		dr_no = pages[i].dr_no;
		dro = pages[i].dro;

		on_dr = ht_get_on_region(dr_no);
		if (unlikely(!on_dr)) {
			DSNVM_BUG("dr_no: %lu", dr_no);
			ret = -EFAULT;
			continue;
		}

		BUG_ON(is_on_region_migrating_out(on_dr));

		spin_lock(&on_dr->page_lock[dro]);
		on_page = &on_dr->mapping[dro];
		if (likely(on_page->if_blocked_by_commit_xact == 1)) {
			on_page->if_blocked_by_commit_xact = 0;

			/* Bookkeeping, for migration: */
			dec_pages_in_transaction(on_dr);
			atomic_inc(&on_dr->nr_commit[DSNVM_LOCAL_ID]);
			atomic64_add(pages[i].len, &on_dr->nr_commit_bytes[DSNVM_LOCAL_ID]);
		} else
			DSNVM_BUG();
		spin_unlock(&on_dr->page_lock[dro]);
		put_on_region(on_dr);
		dsnvm_flush_buffer(on_page, sizeof(on_page));

		DSNVM_PRINTK_BLOCK("Unblock dr_no %lu dro %u",
			dr_no, dro);
	}

	return ret;
}

/*
 * Scan all DSNVM pages within this xact
 * Four cases:
 *	1) Clean page, remote ON	(clean)
 *	2) Clean page, local ON		(clean)
 *	3) COW page, remote ON		(cow->committed)
 *	4) COW page, local ON		(promote)
 *
 * Basically, DSNVM pages are marked:
 *	 Committed	for case 1, 2, 3, 4
 *	!Dirty		for case 1, 2, 3, 4
 *	!Inxact		for case 1, 2, 3, 4
 *	!Unevictable	for case 1, 3
 *	 Unevictable	for case 2, 4
 *
 * RETURN:
 *	0 on success
 *	negative value on failure
 */
static int scan_xact_pages(int nr_areas, struct dr_no_dro_page_offset *meta,
			   struct vm_area_struct **vma, struct atomic_struct *areas)
{
	int i, j, ret = 0;

	for (i = 0; i < nr_areas; i++) {
		unsigned int dro;
		struct dsnvm_page *page;
		struct dn_region_info *dr;
		struct on_region_info *on_dr = NULL;
		struct on_page_info *on_page;
		struct vm_area_struct *v = vma[i];
		struct dsnvm_client_file *f = DSNVM_FILE(v);
		unsigned long vaddr = (unsigned long)areas[i].vaddr;

		for (j = 0; j < i; j++) {
			if (meta[i].dr_no == meta[j].dr_no &&
			    meta[i].dro == meta[j].dro)
				break;
		}

		/* seen this page before */
		if (j < i)
			continue;

		dro = virt_to_dro(vaddr, f);
		dr = get_dn_region(f, vaddr); 
		if (unlikely(!DR_MMAPED(dr, f))) {
			DSNVM_BUG();
			ret = -EFAULT;
			break;
		}

		if (!dr->mapping[dro] || !dn_region_test_mapping_valid(dr, dro)) {
			DSNVM_BUG();
			ret = -EFAULT;
			break;
		}

		/*
		 * COW page or
		 * shared ON_REGION page or
		 * committed fetched page
		 */
		page = pfn_to_dsnvm_page(dr->mapping[dro]);

		if (dr->mapping[dro] == dr->coherent_mapping[dro]) {
			/*
			 * Get on_dr to tell later part of this function if on_dr
			 * exist or not (if DN=ON)
			 */
			on_dr = ht_get_on_region(dr->dr_no);
		} else {
			pte_t *ptep;
			struct dsnvm_page *old_on_page, *new_on_page;
			struct dsnvm_rmap *rmap;
			unsigned long new_pfn, old_pfn;

			/*
			 * For case 3, old_pfn points to the original
			 * coherent DSNVM page fetched from remote ON.
			 *
			 * For case 4, old_pfn points to the original
			 * ON_REGION page.
			 */
			spin_lock(&dr->page_lock[dro]);
			old_pfn = dr->coherent_mapping[dro];
			new_pfn = dr->mapping[dro];
			dr->coherent_mapping[dro] = new_pfn;
			spin_unlock(&dr->page_lock[dro]);

			on_dr = ht_get_on_region(dr->dr_no);
			if (on_dr) {
				/*
				 * Case 4 - Promote COW page to ON_REGION page
				 */
				spin_lock(&on_dr->page_lock[dro]);
				on_page = &on_dr->mapping[dro];
				old_pfn = on_page->local_pfn;

				/*
				 * Set this new page as Owner Page
				 * and try to remove it from LRU list
				 */
				new_on_page = pfn_to_dsnvm_page(new_pfn);
				DSNVM_SetPageOwner(new_on_page);
				lru_remove_page(new_on_page);
				barrier();

				/* Update metadata */
				on_page->local_pfn = new_pfn;
				dsnvm_flush_buffer(&on_page->local_pfn, sizeof(new_pfn));

				spin_unlock(&on_dr->page_lock[dro]);

				DSNVM_PRINTK("Case 4 dr_no %lu, dro %u Promote dsnvm_pfn %lu "
					"Remove old dsnvm_pfn %lu", dr->dr_no, dro,
					pfn_to_dsnvm_pfn(new_pfn), pfn_to_dsnvm_pfn(old_pfn));
			} else {
				DSNVM_PRINTK("Case 3 dr_no %lu dro %u (cow -> committed)",
					dr->dr_no, dro);
			}

			/* Free the old coherent or ON_REGION page */
			if (!pfn_is_dsnvm(old_pfn)) {
				if (likely(old_pfn == 0))
					goto no_begin_xact;

				DSNVM_BUG("pfn: %lu", old_pfn);
				ret = -EFAULT;
				break;
			} else {
				/* Case 4 */
				old_on_page = pfn_to_dsnvm_page(old_pfn);
				DSNVM_ClearPageInxact(old_on_page);
				DSNVM_ClearPageUnevictable(old_on_page);
				DSNVM_ClearPageOwner(old_on_page);

				/*
				 * We are replacing the ON_REGION page.
				 * So actually we need to updata all mapped userspace pages.
				 */
				if (unlikely(dsnvm_page_mapped(old_on_page))) {
					DSNVM_BUG("This means you have more than one application "
					"running on DSNVM that use this file, which is the case "
					"Hotpot does not supoort now.");
					dump_dsnvm_page(page, NULL);
					ret = -EPERM;
					break;
				}
				free_dsnvm_page_pfn(old_pfn);
			}

no_begin_xact:
			/* Set PTE to read-only (only one PTE) */
			list_for_each_entry(rmap, &page->rmap, next) {
				ptep = rmap->page_table;
				if (unlikely(!ptep)) {
					DSNVM_BUG();
					ret = -EFAULT;
					goto out;
				}

				clear_bit(_PAGE_BIT_RW, (unsigned long *)&ptep->pte);
				flush_tlb_page(rmap->vma, rmap->address);
			}
		}

		mark_dsnvm_page_accessed(page);

		lock_dsnvm_page(page);
		if (on_dr)
			DSNVM_SetPageUnevictable(page);
		else
			DSNVM_ClearPageUnevictable(page);
		DSNVM_SetPageCommitted(page);
		DSNVM_ClearPageDirty(page);
		DSNVM_ClearPageInxact(page);
		unlock_dsnvm_page(page);

		dsnvm_flush_buffer(page, sizeof(page));
	}

out:
	return ret;
}

#ifdef DSNVM_MODE_MRSW
/*
 * MRSW final step - Inform CD about this completion if it is not atomic-commit.
 *
 * RETURN:
 *	0 on success
 *	negative value on failure
 */
static int mrsw_final_call_to_cd(bool atomic_commit, int xact_id)
{
	int ret = 0;
	int nodeid;

#ifdef DSNVM_MODE_MRSW_IN_KERNEL
	/* hardcoded node 1 */
	nodeid = DSNVM_MRSW_MASTER_NODE;
#else
	/* CD */
	nodeid = 0;
#endif

	/*
	 * If it is atomic-commit, then there is no need to
	 * contact CD, since there is no begin-xact context created
	 * at CD side.
	 */
	if (!atomic_commit) {
		int send_msg[2];
		struct status_reply_msg reply;

		send_msg[0] = DSNVM_OP_MRSW_COMMIT_XACT;
		send_msg[1] = xact_id;

		/* Send to CD */
		ibapi_send_reply(nodeid, (char *)send_msg,
			sizeof(int) * 2, (char *)(&reply));

		if (reply.status == DSNVM_REPLY_SUCCESS) {
			ret = 0;
			DSNVM_PRINTK("MRSW commit to CD succeed xactid %d", xact_id);
		} else {
			/* Permission Denied */
			ret = -EACCES;
			DSNVM_PRINTK("MRSW commit to CD fail xactid %d", xact_id);
		}
	}
	return ret;
}
#endif

/*
 * One thing to note:
 *
 * In MRSW mode, each involved remote ON will perform 3-phase commit locally.
 * Hence if remote ON report success after dsnvm_request_commit_xact_to_ons(),
 * that means the remote ON has already performd 3-phase commit. No need to send
 * any revert requests to these ONs.
 *
 * So, with some remote ONs succeed, some failed, is this okay? Yes, it is okay.
 * System will not crash or something, everthing is taken care of. Also, user
 * program will retry commit this transaction later.
 *
 * On the contrary, in MRMW mode, remote ON only finished phase 1 after success
 * of dsnvm_request_commit_xact_to_ons. Hence, we need to revert these successful
 * remote ONs.
 */
static void revert_remote(int xact_id, int nr_remote_ons_revert,
			  unsigned int *remote_ons_revert)
{
#ifndef DSNVM_MODE_MRSW
	DSNVM_PRINTK1("Ack (revert) commit transaction: %d, revert %d nodes",
		xact_id, nr_remote_ons_revert);

	if (nr_remote_ons_revert > 0) {
		int i;
		struct max_reply_msg *reply_array;
		struct atomic_struct *msg_array;
		struct dsnvm_commit_xact_id_request_header *header;

		header = kmalloc(sizeof(*header), GFP_KERNEL);
		if (!header) {
			WARN_ON(1);
			return;
		}
		header->op = DSNVM_OP_ACK_COMMIT_XACT_REVERT;
		header->xact_id = xact_id;

		msg_array = kmalloc(sizeof(*msg_array) * nr_remote_ons_revert, GFP_KERNEL);
		if (!msg_array) {
			WARN_ON(1);
			return;
		}

		reply_array = kmalloc(sizeof(*reply_array) * nr_remote_ons_revert, GFP_KERNEL);
		if (!reply_array) {
			WARN_ON(1);
			return;
		}

		for (i = 0; i < nr_remote_ons_revert; i++) {
			msg_array[i].vaddr = (void *)header;
			msg_array[i].len = sizeof(*header);
		}

		/*
		 * Only revert those ONs that are marked blocked by us
		 */
		for (i = 0; i < nr_remote_ons_revert; i++) {
			DSNVM_PRINTK("i = %d, node_id = %d",
				i, remote_ons_revert[i]);
		}

		ibapi_multi_send_reply(nr_remote_ons_revert, remote_ons_revert, msg_array, reply_array);

		for (i = 0; i < nr_remote_ons_revert; i++) {
			struct status_reply_msg *status_reply;
			status_reply = (struct status_reply_msg *)(&reply_array[i]);
			if (unlikely(status_reply->status != DSNVM_REPLY_SUCCESS)) {
				DSNVM_WARN("remote on id: %u, failed reason: %s",
					remote_ons_revert[i],
					dsnvm_status_string(status_reply->status));
			}
		}

		kfree(header);
		kfree(msg_array);
		kfree(reply_array);
	}
#endif
}

static void revert_local(int failed_self_on_page,
			 struct dr_no_dro_len *pages_self_on)
{
	int i;

	for (i = 0; i < failed_self_on_page; i++) {
		struct on_region_info *on_dr;
		struct on_page_info *on_page;
		unsigned long dr_no;
		unsigned int dro;

		dr_no = pages_self_on[i].dr_no;
		dro = pages_self_on[i].dro;

		on_dr = ht_get_on_region(dr_no);
		if (unlikely(!on_dr))
			continue;

		spin_lock(&on_dr->page_lock[dro]);
		on_page = &on_dr->mapping[dro];
		if (likely(on_page->if_blocked_by_commit_xact == 1)) {
			on_page->if_blocked_by_commit_xact = 0;

			/* Bookkeeping for migration: */
			dec_pages_in_transaction(on_dr);
		} else
			DSNVM_BUG();
		spin_unlock(&on_dr->page_lock[dro]);
		put_on_region(on_dr);

		DSNVM_PRINTK_BLOCK("Unblock (revert) dr_no %lu dro %u",
			dr_no, dro);
	}
}

/*
 * Revert remote or local ON pages that were locked by commit phase 1.
 * Revert is needed if some error happen betweeen phase 1 and phase 3.
 * Revert is done in exactly the same order we do phase 1.
 */
static void revert(int xact_id, int failed_self_on_page, struct dr_no_dro_len *pages_self_on,
		   int nr_front_remote_ons_revert, unsigned int *front_remote_ons_revert,
		   int nr_back_remote_ons_revert, unsigned int *back_remote_ons_revert)
{
	revert_remote(xact_id, nr_front_remote_ons_revert, front_remote_ons_revert);
	revert_local(failed_self_on_page, pages_self_on);
	revert_remote(xact_id, nr_back_remote_ons_revert, back_remote_ons_revert);
}

/*
 * The vaddr passed into this function does not need to be page aligned,
 * and length is at most PAGE_SIZE. This is already handled by
 * begin_or_commit_xact_user.
 */
static int dsnvm_commit_xact(struct vm_area_struct **vma,
			     int nr_areas, struct atomic_struct *areas,
			     int rep_degree, unsigned int xact_id)
{
	int i, j, ret = 0;
	bool atomic_commit = false;

	DECLARE_BITMAP(bitmap_remote_ons, DSNVM_MAX_NODE);
	int nr_remote_ons = 0, nr_front_remote_ons = 0, nr_back_remote_ons = 0;
	unsigned int *remote_ons = NULL, *front_remote_ons = NULL, *back_remote_ons = NULL;

	unsigned int nr_front_remote_ons_revert = 0, nr_back_remote_ons_revert = 0;
	unsigned int *front_remote_ons_revert = NULL, *back_remote_ons_revert = NULL;

	int				failed_self_on_page = 0;
	int				nr_pages_self_on = 0;		/* NR of DN==ON case pages */
	int				nr_areas_self_on = 0;		/* NR of DN==ON case areas */
	struct dr_no_dro_len		*pages_self_on = NULL;		/* DN==ON case pages */
	struct dr_no_dro_page_offset	*meta_for_areas_self_on = NULL;	/* DN==ON case areas */
	struct dr_no_dro_page_offset	*meta_for_areas = NULL;
	unsigned int			*nr_reps_per_area_self_on = NULL;
	struct atomic_struct		*coherence_replication_reqs_self_on = NULL;
	struct dsnvm_log_record		*log_rec = NULL;

	if (unlikely(xact_id == -1)) {
		/*
		 * Atomic-commit
		 * which is not norm
		 */
		atomic_commit = true;
		xact_id = get_next_xact_id();
		if (unlikely(xact_id == -1))
			return -EBUSY;

		count_dsnvm_event(DSNVM_XACT_ATOMIC_COMMIT);
	} else {
		/*
		 * MRSW or MRMW
		 * which we've saved a redo-log at begin-xact
		 */
		log_rec = find_log_by_xact_id(xact_id);
		if (unlikely(!log_rec)) {
			DSNVM_WARN("xact-id: %d", xact_id);
			return -EFAULT;
		}

		log_rec->state = DSNVM_LOG_CN_COMMIT;

#ifdef DSNVM_MODE_MRSW
		count_dsnvm_event(DSNVM_XACT_MRSW_COMMIT);
#else
		count_dsnvm_event(DSNVM_XACT_MRMW_COMMIT);
#endif
	}
	count_dsnvm_event(DSNVM_XACT_COMMIT);

	/* Set a reasonable replica degree */
	if (rep_degree > atomic_read(&nr_client_machines))
		rep_degree = atomic_read(&nr_client_machines);

	meta_for_areas = kzalloc(sizeof(*meta_for_areas) * nr_areas, GFP_KERNEL);
	if (!meta_for_areas)
		return -ENOMEM;

	/*
	 * This loop separate DN==ON case and remote ON case,
	 * and save metadata of each area to be used later.
	 */
	bitmap_clear(bitmap_remote_ons, 0, DSNVM_MAX_NODE);
	for (i = 0; i < nr_areas; i++) {
		unsigned int dro;
		struct dn_region_info *dr;
		struct vm_area_struct *v = vma[i];
		struct dsnvm_client_file *f = DSNVM_FILE(v);
		unsigned long vaddr = (unsigned long)areas[i].vaddr;
		unsigned long kern_pfn, kern_paddr;

		dro = virt_to_dro(vaddr, f);
		dr = get_dn_region(f, vaddr);
		if (unlikely(!DR_MMAPED(dr, f))) {
			DSNVM_BUG();
			ret = -EFAULT;
			goto out;
		}

		/* You must have a valid page to commit */
		if (unlikely(!dn_region_test_mapping_valid(dr, dro))) {
			ret = -EFAULT;
			goto out;
		}

		/* Save area metadata, for both DN==ON and remote ON case: */
		meta_for_areas[i].dr_no = dr->dr_no;
		meta_for_areas[i].dro = dro;
		meta_for_areas[i].page_offset = vaddr % PAGE_SIZE; 

		if (dr->owner_id != DSNVM_LOCAL_ID) {
			/* Remote ON case: */
			set_bit(dr->owner_id, bitmap_remote_ons);
		} else {
			/* DN==ON case: */
			if (nr_areas_self_on == 0) {
				meta_for_areas_self_on =
					kzalloc(sizeof(*meta_for_areas_self_on) * nr_areas, GFP_KERNEL);
				if (!meta_for_areas_self_on) {
					ret = -ENOMEM;
					goto out;
				}
				nr_reps_per_area_self_on =
					kzalloc(nr_areas * sizeof(int), GFP_KERNEL);
				if (!nr_reps_per_area_self_on) {
					ret = -ENOMEM;
					goto out;
				}
				coherence_replication_reqs_self_on =
					kzalloc(nr_areas * sizeof(struct atomic_struct), GFP_KERNEL);
				if (!coherence_replication_reqs_self_on) {
					ret = -ENOMEM;
					goto out;
				}
			}

			/* Save area metadata, only for DN==ON case: */
			meta_for_areas_self_on[nr_areas_self_on].dr_no = dr->dr_no;
			meta_for_areas_self_on[nr_areas_self_on].dro = dro;
			meta_for_areas_self_on[nr_areas_self_on].page_offset = vaddr % DSNVM_PAGE_SIZE; 

			/* Myself is a copy */
			/* DO NOT minus 1 again later! */
			nr_reps_per_area_self_on[nr_areas_self_on] = rep_degree - 1;

			/*
			 * Yes, Virginia.
			 * We are using the right Physical address here.
			 */
			kern_pfn = dr->mapping[dro];
			kern_paddr = kern_pfn << PAGE_SHIFT;
			coherence_replication_reqs_self_on[nr_areas_self_on].vaddr =
				(void *)(kern_paddr + meta_for_areas[i].page_offset);
			coherence_replication_reqs_self_on[nr_areas_self_on].len = areas[i].len;

			nr_areas_self_on++;

			/* Save area info into page info, ignore redundant pages: */
			if (nr_pages_self_on == 0) {
				pages_self_on = kzalloc(sizeof(*pages_self_on) * nr_areas, GFP_KERNEL);
				if (!pages_self_on) {
					ret = -ENOMEM;
					goto out;
				}
			}

			/* Check if we have seen this page before */
			for (j = 0; j < nr_pages_self_on; j++)
				if (dr->dr_no == pages_self_on[j].dr_no &&
				    dro == pages_self_on[j].dro)
					break;
			/* no */
			if (j == nr_pages_self_on) {
				pages_self_on[nr_pages_self_on].dr_no = dr->dr_no;
				pages_self_on[nr_pages_self_on].dro = dro;
				pages_self_on[nr_pages_self_on++].len = areas[i].len;
			}
		}
	}

	/*
	 * In order to avoid livelock in MRMW mode, phase 1, revert, and phase 3
	 * need to be done on the order of NODE-IDs. Hence we separate nodes
	 * into front_remote_ons that have smaller NODE-IDs than DSNVM_LOCAL_ID,
	 * and back_remote_ons that have larger NODE-IDs than DSNVM_MAX_NODE:
	 */
	for_each_set_bit(i, bitmap_remote_ons, DSNVM_MAX_NODE) {
		if (nr_remote_ons == 0) {
			remote_ons = kmalloc(sizeof(*remote_ons) * atomic_read(&nr_client_machines), GFP_KERNEL);
			if (!remote_ons) {
				ret = -ENOMEM;
				goto out;
			}
		}
		remote_ons[nr_remote_ons++] = i;

		/* Now separate them */
		if (i < DSNVM_LOCAL_ID) {
			if (nr_front_remote_ons == 0) {
				/* First time, allocate arrays */
				front_remote_ons = kmalloc(sizeof(*front_remote_ons) *
						atomic_read(&nr_client_machines), GFP_KERNEL);
				if (!front_remote_ons) {
					ret = -ENOMEM;
					goto out;
				}

				front_remote_ons_revert = kmalloc(sizeof(*front_remote_ons_revert) *
							atomic_read(&nr_client_machines), GFP_KERNEL);
				if (!front_remote_ons_revert) {
					ret = -ENOMEM;
					goto out;
				}
			}
			front_remote_ons[nr_front_remote_ons++] = i;
			DSNVM_PRINTK("new front remote ON: %2d", i);
		} else if (i > DSNVM_LOCAL_ID) {
			if (nr_back_remote_ons == 0) {
				/* First time, allocate arrays */
				back_remote_ons = kmalloc(sizeof(*back_remote_ons) *
						atomic_read(&nr_client_machines), GFP_KERNEL);
				if (!back_remote_ons) {
					ret = -ENOMEM;
					goto out;
				}

				back_remote_ons_revert = kmalloc(sizeof(*back_remote_ons_revert) *
							atomic_read(&nr_client_machines), GFP_KERNEL);
				if (!back_remote_ons_revert) {
					ret = -ENOMEM;
					goto out;
				}
			}
			back_remote_ons[nr_back_remote_ons++] = i;
			DSNVM_PRINTK("new back remote ON: %2d", i);
		} else {
			DSNVM_BUG();
			ret = -EFAULT;
			goto out;
		}
	}

	/*
	 * Don't be afraid, let us rock!
	 */

#if 0
#define pr_fail_line()	pr_info("[%s] Fail at line: %d, xact_id: %d", \
				__func__, __LINE__, xact_id)
#else
#define pr_fail_line()	do { } while (0)
#endif

#ifdef DSNVM_MODE_MRSW
	/* No need to commit sequentially */
	ret = phase_1_of_self_on(nr_pages_self_on, &failed_self_on_page, pages_self_on);
	if (unlikely(ret)) {
		pr_fail_line();
		goto revert;
	}

	if (nr_remote_ons > 0) {
		/*
		 * Use front_remote_ons_revert is okay, cause there is
		 * no need for sequential commit. But make sure it is not NULL.
		 */
		if (!front_remote_ons_revert) {
			front_remote_ons_revert = kmalloc(sizeof(*front_remote_ons_revert) *
						atomic_read(&nr_client_machines), GFP_KERNEL);
			if (!front_remote_ons_revert) {
				ret = -ENOMEM;
				goto out;
			}
		}
		ret = dsnvm_request_commit_xact_to_ons(vma, nr_remote_ons, remote_ons,
						       nr_areas, areas, rep_degree, xact_id,
						       &nr_front_remote_ons_revert, front_remote_ons_revert, 2);
		if (unlikely(ret)) {
			pr_fail_line();
			goto revert;
		}
	}
#else
	if (nr_remote_ons == 0) {
		/*
		 * No remote ONs involved, do everything locally
		 * If errors happens within phase 1, we need to revert below.
		 */
		count_dsnvm_event(DSNVM_MRMW_REMOTE_ON_0);
		ret = phase_1_of_self_on(nr_pages_self_on, &failed_self_on_page, pages_self_on);
		if (unlikely(ret)) {
			pr_fail_line();
			goto revert;
		}
	} else if (nr_remote_ons == 1) {
		/*
		 * Special case: only involving one remote ON
		 * No need to do 3-phase commit, do everything in one go.
		 * Note that we still do phase 1 sequentially based on NODE-ID.
		 */
		count_dsnvm_event(DSNVM_MRMW_REMOTE_ON_1);
		if (nr_front_remote_ons > 0) {
			DSNVM_PRINTK("MRMW nr_front_remote_ons = 1");
			ret = dsnvm_commit_xact_to_single_on(vma, front_remote_ons[0],
							nr_areas, areas, rep_degree, xact_id);
			if (unlikely(ret)) {
				pr_fail_line();
				goto revert;
			}

			ret = phase_1_of_self_on(nr_pages_self_on, &failed_self_on_page, pages_self_on);
			if (unlikely(ret)) {
				pr_fail_line();
				goto revert;
			}
		} else {
			DSNVM_PRINTK("MRMW nr_back_remote_ons = 1");
			ret = phase_1_of_self_on(nr_pages_self_on, &failed_self_on_page, pages_self_on);
			if (unlikely(ret)) {
				pr_fail_line();
				goto revert;
			}

			ret = dsnvm_commit_xact_to_single_on(vma, back_remote_ons[0],
							nr_areas, areas, rep_degree, xact_id);
			if (unlikely(ret)) {
				pr_fail_line();
				goto revert;
			}
		}
	} else if (nr_remote_ons > 1) {
		/*
		 * Normal MRMW inovolving more than one remote ON
		 * Need a 3-phase commit
		 */
		
		count_dsnvm_event(DSNVM_MRMW_REMOTE_ON_N);

		/*
		 * MRMW commit xact phase 1
	 	 * Phase 1 of commit xact needs to done in this order:
	 	 *    . front_remote_ons
	 	 *    . pages_self_on
	 	 *    . back_remote_ons
	 	 */
		if (nr_front_remote_ons > 0) {
			ret = dsnvm_request_commit_xact_to_ons(vma, nr_front_remote_ons, front_remote_ons,
						       nr_areas, areas, rep_degree, xact_id,
						       &nr_front_remote_ons_revert, front_remote_ons_revert, 0);
			if (unlikely(ret)) {
				pr_fail_line();
				goto revert;
			}
		}

		ret = phase_1_of_self_on(nr_pages_self_on, &failed_self_on_page, pages_self_on);
		if (unlikely(ret)) {
			pr_fail_line();
			goto revert;
		}

		if (nr_back_remote_ons > 0) {
			ret = dsnvm_request_commit_xact_to_ons(vma, nr_back_remote_ons, back_remote_ons,
						       nr_areas, areas, rep_degree, xact_id,
						       &nr_back_remote_ons_revert, back_remote_ons_revert, 1);
			if (unlikely(ret)) {
				pr_fail_line();
				goto revert;
			}
		}

		/*
		 * MRMW commit xact phase 2
		 * The order of nodes does not matter cause we have already
		 * locked remote ON pages. So just use remote_ons array.
		 */
		ret = dsnvm_make_commit_xact_to_ons(nr_remote_ons, remote_ons, nr_areas, areas, xact_id);
		if (unlikely(ret)) {
			pr_fail_line();
			goto revert;
		}
	}
#endif

	/*
	 * MRMW Phase 2 of DN==ON case pages
	 * MRSW Phase 2 of DN==ON case pages
	 */
	ret = phase_2_of_self_on(nr_pages_self_on, nr_areas_self_on, meta_for_areas_self_on,
				coherence_replication_reqs_self_on, nr_reps_per_area_self_on);
	if (unlikely(ret)) {
		pr_fail_line();
		goto revert;
	}

#ifdef DSNVM_MODE_MRSW
	ret = phase_3_of_self_on(nr_pages_self_on, pages_self_on);
	if (unlikely(ret)) {
		pr_fail_line();
		goto revert;
	}

	/*
	 * MRSW just does 3-phase in one go, like the special case of MRMW.
	 * Thus no need to ack (phase 3) remote ons, just tell CD that this
	 * xact has finished:
	 */
	ret = mrsw_final_call_to_cd(atomic_commit, xact_id);
	if (unlikely(ret)) {
		pr_fail_line();
		goto revert;
	}
#else
	/*
	 * MRMW Phase 3
	 * If it is the special case (nr_remote_ons = 1), the remote ON just
	 * does 3-phase in one go. Thus there is no ordering requirement.
	 * If it is the normal case (nr_remote_ons > 1), the ack (phase 3)
	 * needs to be done in the order of NODE-IDs:
	 */
	if (nr_remote_ons == 0 || nr_remote_ons == 1) {
		ret = phase_3_of_self_on(nr_pages_self_on, pages_self_on);
		if (unlikely(ret)) {
			pr_fail_line();
			goto revert;
		}
	} else {
		/*
	 	 * Phase 3 of this case needs to be done in this order:
	 	 *    . front_remote_ons
	 	 *    . pages_self_on
	 	 *    . back_remote_ons
		 */
		unsigned int nr_max;
		struct atomic_struct *msg_array;
		struct max_reply_msg *reply_array;
		struct dsnvm_commit_xact_id_request_header *header;

		header = kmalloc(sizeof(*header), GFP_KERNEL);
		if (!header) {
			ret = -ENOMEM;
			goto revert;
		}
		header->op = DSNVM_OP_ACK_COMMIT_XACT;
		header->xact_id = xact_id;

		/* Just use the same array for both front and back */
		nr_max = max(nr_front_remote_ons, nr_back_remote_ons);

		msg_array = kmalloc(nr_max * sizeof(*msg_array), GFP_KERNEL);
		if (!msg_array) {
			ret = -ENOMEM;
			goto revert;
		}

		reply_array = kmalloc(nr_max * sizeof(*reply_array), GFP_KERNEL);
		if (!reply_array) {
			ret = -ENOMEM;
			goto revert;
		}

		for (i = 0; i < nr_max; i++) {
			msg_array[i].vaddr = (void *)header;
			msg_array[i].len = sizeof(*header);
		}

		DSNVM_PRINTK("Ack commit transaction: %d", xact_id);

		/*
		 * Do the phase 3
		 * Based on node-id sequence
		 *
		 * Remote ONs can reply:
		 *	DSNVM_REPLY_SUCCESS
		 *	DSNVM_REPLY_NO_LOG
		 *	DSNVM_REPLY_BUG
		 */
		if (nr_front_remote_ons > 0) {
			ibapi_multi_send_reply(nr_front_remote_ons,
				front_remote_ons, msg_array, reply_array);

			for (i = 0; i < nr_front_remote_ons; i++) {
				struct status_reply_msg *status_reply;
				status_reply = (struct status_reply_msg *)(&reply_array[i]);
				if (unlikely(status_reply->status != DSNVM_REPLY_SUCCESS)) {
					DSNVM_WARN("Remote ON id: %u, failed reason: %s",
						front_remote_ons[i],
						dsnvm_status_string(status_reply->status));
				}
			}
		}

		phase_3_of_self_on(nr_pages_self_on, pages_self_on);

		if (nr_back_remote_ons > 0) {
			ibapi_multi_send_reply(nr_back_remote_ons,
				back_remote_ons, msg_array, reply_array);

			for (i = 0; i < nr_back_remote_ons; i++) {
				struct status_reply_msg *status_reply;
				status_reply = (struct status_reply_msg *)(&reply_array[i]);
				if (unlikely(status_reply->status != DSNVM_REPLY_SUCCESS)) {
					DSNVM_WARN("remote on id: %u, failed reason: %s",
						back_remote_ons[i],
						dsnvm_status_string(status_reply->status));
				}
			}
		}

		kfree(header);
		kfree(msg_array);
		kfree(reply_array);
	}
#endif

	/*
	 * Alright, 3-phase commit transaction has finished,
	 * now let us do the final step: Scan all DSNVM pages involved in this
	 * transaction, and do proper cleanup or promotion based on page state.
	 *
	 * XXX: What if this fails? How to rollback all remote-ON?
	 */
	WARN_ON(scan_xact_pages(nr_areas, meta_for_areas, vma, areas));

	/* Release the redo-log if MRSW or MRMW */
	if (log_rec) {
		if (log_rec->meta_for_areas) {
			int order;

			order = ilog2(DIV_ROUND_UP(sizeof(*log_rec->meta_for_areas) *
				      log_rec->nr_areas, PAGE_SIZE));
			free_dsnvm_pages(log_rec->meta_for_areas, order);
		}
		free_dsnvm_log(log_rec);
	}

	ret = 0;
	goto out;

revert:
	count_dsnvm_events(DSNVM_XACT_REVERT_TX,
		nr_front_remote_ons_revert + nr_back_remote_ons_revert);

	revert(xact_id,
		failed_self_on_page,
		pages_self_on,
		nr_front_remote_ons_revert,
		front_remote_ons_revert,
		nr_back_remote_ons_revert,
		back_remote_ons_revert);

out:
	free_xact_id(xact_id);

	/* Alright this is ugly, I admit */
	if (coherence_replication_reqs_self_on)
		kfree(coherence_replication_reqs_self_on);
	if (remote_ons)
		kfree(remote_ons);
	if (front_remote_ons)
		kfree(front_remote_ons);
	if (back_remote_ons)
		kfree(back_remote_ons);
	if (front_remote_ons_revert)
		kfree(front_remote_ons_revert);
	if (back_remote_ons_revert)
		kfree(back_remote_ons_revert);
	if (pages_self_on)
		kfree(pages_self_on);
	if (meta_for_areas_self_on)
		kfree(meta_for_areas_self_on);
	if (meta_for_areas)
		kfree(meta_for_areas);
	if (nr_reps_per_area_self_on)
		kfree(nr_reps_per_area_self_on);

	/* Bookkeeping */
	if (ret == DSNVM_RETRY)
		count_dsnvm_event(DSNVM_XACT_COMMIT_RETRY);
	else if (ret == 0)
		count_dsnvm_event(DSNVM_XACT_COMMIT_SUCCEED);
	else {
		/*
		 * Convert everything to -EINVAL
		 * Maybe not a good idea..
		 */
		ret = -EINVAL;
		count_dsnvm_event(DSNVM_XACT_COMMIT_FAIL);
	}

	return ret;
#undef pr_fail_line
}

/*
 * Begin Transaction for both MRMW and MRSW:
 * Fetch and get pages ready for all area related pages.
 * If it is MRSW, we need to contact CD.
 */
static int dsnvm_begin_xact(struct vm_area_struct **vma,
			    int nr_areas, struct atomic_struct *areas)
{
	int order = 0;
	int nr_pages, log_id;
	int ret, xact_id = -1;
	int i, j, failed_area;
	struct dsnvm_log_record *log_rec = NULL;
	struct dr_no_dro_page_offset *meta_for_areas = NULL;

#ifdef DSNVM_MODE_MRSW
	struct status_reply_msg reply;
	struct dr_no_dro *pages;
	void *msg;
	size_t size;

	/* The first 2 int are OP and xact_id */
	size = sizeof(int) * 2 + sizeof(*pages) * nr_areas;
	msg = kmalloc(size, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	/* Shift to pages */
	pages = msg + sizeof(int) * 2;

	count_dsnvm_event(DSNVM_XACT_MRSW_BEGIN);
#else
	struct dr_no_dro *pages = kmalloc(sizeof(*pages) * nr_areas, GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	count_dsnvm_event(DSNVM_XACT_MRMW_BEGIN);
#endif
	count_dsnvm_event(DSNVM_XACT_BEGIN);

	/* Allocate transaction ID */
	xact_id = get_next_xact_id();
	if (unlikely(xact_id == -1)) {
		DSNVM_WARN("MRSW Begin-Xact fail not able to get xact ID");
		ret = -EFAULT;
		goto error_free;
	}

	/* Allocate redo log for committing node */
	log_rec = alloc_dsnvm_log(xact_id, &log_id);
	if (unlikely(!log_rec)) {
		DSNVM_WARN("No more logs");
		ret = -ENOMEM;
		goto error_free;
	}

	/* Allocating meta array from NVM */
	order = ilog2(DIV_ROUND_UP(sizeof(*meta_for_areas) * nr_areas, PAGE_SIZE));
	meta_for_areas = alloc_dsnvm_pages(order);
	if (!meta_for_areas) {
		DSNVM_WARN("order: %d", order);
		ret = -ENOMEM;
		goto error_free;
	}

	log_rec->log_id = log_id;
	log_rec->xact_id = xact_id;
	log_rec->sender_id = DSNVM_LOCAL_ID;
	log_rec->state = DSNVM_LOG_CN_BEGIN;

	/* has duplicates, careful while doing recovery */
	log_rec->meta_for_areas = meta_for_areas;
	log_rec->nr_areas = nr_areas;

	for (i = 0, failed_area = -1, nr_pages = 0; i < nr_areas; i++) {
		struct dsnvm_page *page;
		struct dn_region_info *dr;
		struct vm_area_struct *v = vma[i];
		struct dsnvm_client_file *f = DSNVM_FILE(v);
		unsigned long pfn, vaddr = (unsigned long)areas[i].vaddr;
		unsigned int dro;

		dro = virt_to_dro(vaddr, f);
		dr = get_dn_region(f, vaddr); 
		if (unlikely(!DR_MMAPED(dr, f))) {
			DSNVM_BUG();
			ret = -EFAULT;
			failed_area = i;
			goto error;
		}

		/* Check if we have seen this page before */
		for (j = 0; j < nr_pages; j++) {
			if (dr->dr_no == pages[j].dr_no &&
			    dro == pages[j].dro)
				break;
		}

		if (j == nr_pages) {
			/* no */
			pages[nr_pages].dr_no = dr->dr_no;
			pages[nr_pages].dro = dro;

			/* Save to redo-log */
			meta_for_areas[nr_pages].dr_no = dr->dr_no;
			meta_for_areas[nr_pages].dro = dro;

			nr_pages++;
		} else {
			/* yes */
			continue;
		}

		/*
		 * Fetch page if the mapping is not established.
		 * Mark these pages read-only, so we could know
		 * this when user commit this transaction.
		 */
		if (!dn_region_test_mapping_valid(dr, dro)) {
			ret = dsnvm_get_faulting_page(v, vaddr, 0);
			if (ret != VM_FAULT_NOPAGE) {
				DSNVM_WARN();
				ret = -EFAULT;
				failed_area = i;
				goto error;
			}
		}

		/*
		 * Compete with pfn_mkwrite from the thread who won begin_xact.
		 * This lock ensures us the lastest mapping[] pfn against COW.
		 */
		spin_lock(&dr->page_lock[dro]);
		pfn = dr->mapping[dro];

		if (unlikely(!pfn_is_dsnvm(pfn))) {
			spin_unlock(&dr->page_lock[dro]);
			DSNVM_BUG();
			ret = -EFAULT;
			failed_area = i;
			goto error;
		}

		page = pfn_to_dsnvm_page(pfn);
		lock_dsnvm_page(page);

		/*
		 * Xact can only be started with CLEAN pages. If pages have
		 * already been modified, user must use atomic-commit first
		 * to submit the changes.
		 */
		if (DSNVM_PageDirty(page) ||
		    test_bit(dro, dr->pfn_mkwrite_busy)) {
			unlock_dsnvm_page(page);
			spin_unlock(&dr->page_lock[dro]);

			DSNVM_PRINTK("[pid %u] [cpu %d] Abort xact due to dirty page"
				"(dr_no: %lu, dro: %u) mapping_pfn: %lu, coherent_mapping_pfn %lu, old_pfn: %lu",
				current->pid, smp_processor_id(), dr->dr_no, dro,
				dr->mapping[dro], dr->coherent_mapping[dro], dsnvm_page_to_pfn(page));

			ret = -EPERM;
			failed_area = i;
			goto error;
		}

		/*
		 * Competing with another thread. Only one thread of a node is
		 * allowed to begin transaction!
		 */
		if (unlikely(DSNVM_PageInxact(page))) {
			unlock_dsnvm_page(page);
			spin_unlock(&dr->page_lock[dro]);
			cpu_relax();

			DSNVM_PRINTK("[pid %u] [cpu %d]: Begin-Xact concurrent (dr_no: %lu, dro: %u) "
				"mapping_pfn: %lu, coherent_mapping_pfn: %lu, old_pfn: %lu",
				current->pid, smp_processor_id(), dr->dr_no, dro,
				dr->mapping[dro], dr->coherent_mapping[dro], dsnvm_page_to_pfn(page));

			ret = DSNVM_RETRY;
			failed_area = i;
			goto error;
		}

		/*
		 * All good, pin this page in memory for the duration of the xact.
		 * This page is not yet committed (will change to committed state
		 * at xact commit time).
		 */
		DSNVM_SetPageInxact(page);
		DSNVM_SetPageUnevictable(page);

		unlock_dsnvm_page(page);
		spin_unlock(&dr->page_lock[dro]);

		/* We've touched this page */
		mark_dsnvm_page_accessed(page);
	}

	/*
	 * This is the special feature of MRSW: Only a single writer (of a page)
	 * can exist at one time. To ensure this, CD will sequentialize all transactions
	 * that request to the same pages.
	 */
#ifdef DSNVM_MODE_MRSW
	*(int *)msg = DSNVM_OP_MRSW_BEGIN_XACT;
	*((int *)msg+1) = xact_id;

#ifdef DSNVM_MODE_MRSW_IN_KERNEL
	ibapi_send_reply(DSNVM_MRSW_MASTER_NODE, msg, size, (char *)(&reply));
#else
	ibapi_send_reply(0, msg, size, (char *)(&reply));
#endif

        if (likely(reply.status == DSNVM_REPLY_SUCCESS)){
		DSNVM_PRINTK("MRSW Begin-Xact Succeed");
	} else if (reply.status == DSNVM_RETRY) {
		DSNVM_PRINTK("MRSW Begin-Xact Retry");

		count_dsnvm_event(DSNVM_XACT_BEGIN_RETRY);
		failed_area = nr_areas;
		ret = DSNVM_RETRY;
		goto error;
	} else {
		DSNVM_WARN("MRSW Begin-Xact failed, reason: %s",
			dsnvm_status_string(reply.status));

		failed_area = nr_areas;
		ret = -EFAULT;
		goto error;
	}

	kfree(msg);
#else
	kfree(pages);
#endif

	count_dsnvm_event(DSNVM_XACT_BEGIN_SUCCEED);
	return xact_id;

error:
	/*
	 * [0, failed_area) DSNVM pages are marked Inxact by this functiom, and
	 * this thread at this moment. So if we encounter BUG or busy Inxact page,
	 * we MUST revert back these DSNVM pages to their original state. If not,
	 * no one will clear the Inxact flag and all threads will keep looping.
	 */
	for (i = 0; i < failed_area; i++) {
		struct dsnvm_page *page;
		struct dn_region_info *dr;
		struct vm_area_struct *v = vma[i];
		struct dsnvm_client_file *f = DSNVM_FILE(v);
		unsigned long pfn, vaddr = (unsigned long)areas[i].vaddr;
		unsigned int dro;

		dro = virt_to_dro(vaddr, f);
		dr = get_dn_region(f, vaddr); 

		/*
		 * Note that: Use mapping[] is okay. Since if we were competing
		 * with pfn_mkwrite above, that means there is another thread
		 * wins xact already, and we never gonna reach here. So we are
		 * clearing the right page here.
		 */
		spin_lock(&dr->page_lock[dro]);
		pfn = dr->mapping[dro];
		spin_unlock(&dr->page_lock[dro]);

		page = pfn_to_dsnvm_page(pfn);
		lock_dsnvm_page(page);
		DSNVM_ClearPageInxact(page);
		DSNVM_ClearPageUnevictable(page);
		unlock_dsnvm_page(page);
	}

error_free:
	if (xact_id != -1)
		free_xact_id(xact_id);

	if (log_rec) {
		if (log_rec->meta_for_areas)
			free_dsnvm_pages(log_rec->meta_for_areas, order);
		free_dsnvm_log(log_rec);
	}

#ifdef DSNVM_MODE_MRSW
	kfree(msg);
#else
	kfree(pages);
#endif
	return ret;
}

/* 
 * commit a range of addresses
 * and flush only the dirty one
 * TODO: change function name
 */
static int dsnvm_begin_or_commit_xact_user_single(unsigned long start,
						  size_t len, int dummy)
{
	struct vm_area_struct *vma;
	struct vm_area_struct **vma_array;
	struct mm_struct *mm = current->mm;
	struct dsnvm_client_file *f;
	unsigned long start_page_aligned, end_page_aligned, curr_addr; 
	struct atomic_struct *areas;
	int rep_degree = 1;
	int num_dirty_pages = 0, num_pages = 0;
	int i, ret = 0;

	DSNVM_PRINTK("[pid: %u] [cpu: %d] start %#lx len %zu rep_degree %d",
			current->pid, smp_processor_id(),
			start, len, rep_degree);

	if (unlikely(!len || !start))
		return -EINVAL;

	down_read(&mm->mmap_sem);
	vma = find_vma(mm, start);
	if (unlikely(!vma)) {
		pr_info("commit-only: no vma");
		up_read(&mm->mmap_sem);
		return -EINVAL;
	}

	f = DSNVM_FILE(vma);
	if (unlikely(!f)) {
		pr_info("commit-only: wrong vma");
		up_read(&mm->mmap_sem);
		return -EINVAL;
	}
	up_read(&mm->mmap_sem);

	if (unlikely(start + len > vma->vm_end)) {
		pr_info("commit-only: exceed mmaped address range. "
			"start: %#lx, len: %zu, end: %#lx",
			start, len, vma->vm_end);
		return -EINVAL;
	}

	start_page_aligned = round_up(start, DSNVM_PAGE_SIZE);
	end_page_aligned = round_down(start + len, DSNVM_PAGE_SIZE);
	num_pages = (end_page_aligned - start_page_aligned) / DSNVM_PAGE_SIZE;

	DSNVM_PRINTK("[%#lx - %lx], nr_pages = %d",
		start_page_aligned, end_page_aligned, num_pages);

	if (!num_pages) {
		pr_info("commit-only: no pages involved");
		return 0;
	}

	areas = kmalloc(sizeof(*areas) * num_pages, GFP_KERNEL);
	if (!areas)
		return -ENOMEM;

	for (i = 0; i < num_pages; i++) {
		struct dn_region_info *dr;
		struct dsnvm_page *page;
		unsigned int dro;
		unsigned long pfn;

		curr_addr = start_page_aligned + i * DSNVM_PAGE_SIZE;

		dro = virt_to_dro(curr_addr, f);
		dr = get_dn_region(f, curr_addr);
		if (unlikely(!DR_MMAPED(dr, f))) {
			DSNVM_BUG();
			ret = -EFAULT;
			goto out;
		}

		DSNVM_PRINTK("curr_addr %lx dro %u dr_no %lu",
				curr_addr, dro, dr->dr_no);

		spin_lock(&dr->page_lock[dro]);
		pfn = dr->mapping[dro];
		if (unlikely(!pfn)) {
			spin_unlock(&dr->page_lock[dro]);
			continue;
		}
		page = pfn_to_dsnvm_page(pfn);
		if (DSNVM_PageDirty(page)) {
			areas[num_dirty_pages].vaddr = (void *)curr_addr;
			areas[num_dirty_pages].len = DSNVM_PAGE_SIZE;

			DSNVM_PRINTK("dirty page vaddr %lx i %d num_dirty_pages %d "
				     "vma %p areavadddr %p len %zu",
				curr_addr, i, num_dirty_pages, vma,
				areas[num_dirty_pages].vaddr, areas[num_dirty_pages].len);
			num_dirty_pages++;
		}
		spin_unlock(&dr->page_lock[dro]);
	}

	if (!num_dirty_pages) {
		pr_info("commit-only: no dirty pages in this range: [%#lx - %#lx]",
			start_page_aligned, end_page_aligned);

		ret = 0;
		goto out;
	}

	vma_array = kmalloc(num_dirty_pages * sizeof(*vma_array), GFP_KERNEL);
	if (!vma_array) {
		ret = -ENOMEM;
		goto out;
	}
	for (i = 0; i < num_dirty_pages; i++) {
		vma_array[i] = vma;
	}

	ret = dsnvm_commit_xact(vma_array, num_dirty_pages, areas, rep_degree, -1);

	kfree(vma_array);
out:
	kfree(areas);
	return ret;
}

static int area_compare(const void *a, const void *b)
{
	const dsnvm_addr_len *ap = a, *bp = b;

	if (ap->vaddr != bp->vaddr)
		return ap->vaddr > bp->vaddr? 1 : -1;
	return 0;
}

/*
 * User Interface, invoked when msync() SYSCALL is called.
 * This function just do the necessary sanitary checking,
 * and then call begin or commit helpers:
 */
static int dsnvm_begin_or_commit_xact_user(unsigned long start, size_t len,
					   int if_begin_xact)
{
	int i, nr_areas, ret = 0;
	int estimated_nr_areas;
	unsigned long total_size;
	struct xact_header header;
	struct vm_area_struct **vma;			/* vma pointer array */
	dsnvm_addr_len *orig_areas, *areas;		/* area structure array */

	DSNVM_PRINTK("[pid: %u] [cpu: %d] start %#lx len %zu if_begin_xact %d",
			current->pid, smp_processor_id(),
			start, len, if_begin_xact);

	if (unlikely(!len || !start))
		return -EINVAL;

	/*
	 * User begin xact by only passing area infos,
	 * replica degree and xact_id forms the header if commit xact:
	 */
	if (!if_begin_xact) {
		if (copy_from_user(&header, (void *)start, sizeof(header)))
			return -EFAULT;
		start += sizeof(header);
	}

	/* Save original area info */
	orig_areas = kmalloc(sizeof(*orig_areas) * len, GFP_KERNEL);
	if (!orig_areas)
		return -ENOMEM;
	if (copy_from_user(orig_areas, (void *)start, sizeof(*orig_areas) * len)) {
		kfree(orig_areas);
		return -EFAULT;
	}

	/*
	 * Estimate how many areas we may need to allocate.
	 * This is necessary because length field can exceed PAGE_SIZE,
	 * but the minimum manageable unit is page:
	 */
	total_size = 0;
	estimated_nr_areas = 0;
	for (i = 0; i < len; i++) {
		total_size += orig_areas[i].len;
		estimated_nr_areas += (orig_areas[i].len + PAGE_SIZE - 1) / PAGE_SIZE;
	}

	if (unlikely(!total_size || !estimated_nr_areas)) {
		kfree(orig_areas);
		return -EINVAL;
	} else {
		areas = kmalloc(estimated_nr_areas * sizeof(*areas), GFP_KERNEL);
		if (!areas) {
			kfree(orig_areas);
			return -ENOMEM;
		}

		/*
		 * The vma pointer array used to store corresponding vma for
		 * each area. Two reasons: 1) we support multiple VMAs at one
		 * time, 2) Improve performance. No find_vma anymore later.
		 */
		vma = kmalloc(estimated_nr_areas * sizeof(*vma), GFP_KERNEL);
		if (!vma) {
			kfree(orig_areas);
			kfree(areas);
			return -ENOMEM;
		}
	}

	/*
	 * Okay, now let's sanitize the user passed orig_areas,
	 * then store them in a safe place:
	 */
	nr_areas = 0;
	for (i = 0; i < len; i++) {
		unsigned long user_vaddr = orig_areas[i].vaddr;
		unsigned int  user_len = orig_areas[i].len;
		struct mm_struct *mm = current->mm;
		struct dsnvm_client_file *f;
		struct vm_area_struct *v;

		if (unlikely(!user_len))
			continue;

		down_read(&mm->mmap_sem);
		v = find_vma(mm, user_vaddr);
		if (unlikely(!v)) {
			up_read(&mm->mmap_sem);
			continue;
		}

		f = DSNVM_FILE(v);
		if (unlikely(!f)) {
			/* 
			 * Not a DSNVM mapped VMA, which means user passed
			 * us the wrong address.
			 */
			up_read(&mm->mmap_sem);
			continue;
		}
		up_read(&mm->mmap_sem);

		/* You can not cross this area */
		if (unlikely(user_vaddr + user_len > v->vm_end)) {
			ret = -EINVAL;
			goto out;
		}

		/*
		 * Okay, this area is valid. Now we split it into multiple
		 * areas if it spans multiple pages. Be careful not to exceed
		 * the allocated array:
		 */
		areas[nr_areas].vaddr = user_vaddr;
		while (PFN_DOWN(areas[nr_areas].vaddr) <
		       PFN_DOWN(areas[nr_areas].vaddr + user_len)) {
			unsigned long this_len = PAGE_SIZE - areas[nr_areas].vaddr % PAGE_SIZE;

			areas[nr_areas++].len = this_len;
			user_len -= this_len;

			if (user_len)
				areas[nr_areas].vaddr = areas[nr_areas - 1].vaddr + this_len;
		}
		if (user_len)
			areas[nr_areas++].len = user_len;
	}

	/*
	 * Alright, this is useless... cause we will separate remote ons
	 * into front/local/back when we do commit-xact..
	 */
	sort(areas, nr_areas, sizeof(*areas), area_compare, NULL);
	for (i = 0; i < nr_areas; i++) {
		down_read(&current->mm->mmap_sem);
		vma[i] = find_vma(current->mm, areas[i].vaddr);
		up_read(&current->mm->mmap_sem);
	}

	if (nr_areas > 0) {
		/*
		 * REMOVEME:
		 * This is too ugly. All because we mixed struct atomic_struct
		 * and dsnvm_addr_len together..
		 * 
		 * One solution is to use 16 bytes dsnvm_addr_len instead of 12.
		 */
		struct atomic_struct *__areas;
		__areas = kmalloc(sizeof(struct atomic_struct) * nr_areas, GFP_KERNEL);
		if (!__areas) {
			ret = -ENOMEM;
			goto out;
		}
		for (i = 0; i < nr_areas; i++) {
			__areas[i].vaddr = (void *)areas[i].vaddr;
			__areas[i].len = areas[i].len;

			DSNVM_PRINTK("areas[%d]: vaddr = %p, len = %zu",
				i, __areas[i].vaddr, __areas[i].len);
		}

		transaction_enter();

		/*
		 * Final call..
		 */
		if (if_begin_xact)
			ret = dsnvm_begin_xact(vma, nr_areas, __areas);
		else
			ret = dsnvm_commit_xact(vma, nr_areas, __areas,
					header.rep_degree, header.xact_id);

		transaction_exit();

		kfree(__areas);
	}

out:
	kfree(orig_areas);
	kfree(areas);
	kfree(vma);

	return ret;
}

int dsnvm_init_xact(void)
{
	dsnvm_init_xact_ids();

	dsnvmapi = kmalloc(sizeof(struct dsnvm_apis), GFP_KERNEL);
	if (!dsnvmapi)
		return -ENOMEM;

	dsnvm_reg_begin_or_commit_xact_user_single(dsnvm_begin_or_commit_xact_user_single);
	dsnvm_reg_begin_or_commit_xact_user(dsnvm_begin_or_commit_xact_user);	

	return 0;
}
