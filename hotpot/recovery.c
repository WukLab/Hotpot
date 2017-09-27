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

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/time.h>
#include <linux/slab.h>
#include <linux/kref.h>
#include <linux/sched.h>
#include <linux/random.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/hashtable.h>
#include <linux/types.h>
#include <linux/atomic.h>

#include "dsnvm.h"

#if 0
#define DSNVM_PROFILE
#endif
#include "dsnvm-profile.h"

struct promotion_notify {
	unsigned int op;
	unsigned long dr_no;
};

int dsnvm_handle_notify_all_promotion(char *input_addr, unsigned int req_len, int sender_id)
{
	struct promotion_notify *request;
	struct dn_region_info *r;
	unsigned long dr_no;

	request = (struct promotion_notify *)input_addr;
	dr_no = request->dr_no;

	DSNVM_PRINTK("Receive DN->ON promotion notity from node: %d, for dr_no: %lu",
		sender_id, dr_no);

	r = ht_get_dn_region(dr_no);
	if (r) {
		DSNVM_PRINTK("ON changed, from [node %2d] -> [node %2d], for dr_no: %lu",
			r->owner_id, sender_id, dr_no);

		r->owner_id = sender_id;
	} else {
		DSNVM_PRINTK("Skip dr_no: %lu", dr_no);
	}

	return 0;
}

/*
 * Tell all online machines about this promotion
 */
static void notify_all_on_online_machines(unsigned long dr_no)
{
	int i, nr_nodes = 0;
	int node_array[DSNVM_MAX_NODE];
	struct atomic_struct send_array[DSNVM_MAX_NODE];
	struct promotion_notify request;

	for_each_set_bit(i, DSNVM_CLIENT_MACHINES, DSNVM_MAX_NODE) {
		if (i == DSNVM_LOCAL_ID)
			continue;

		node_array[nr_nodes] = i;
		nr_nodes++;

		DSNVM_PRINTK("dr_no: %lu going to send to node: %d, nr_nodes = %d",
			dr_no, i, nr_nodes);
	}

	if (nr_nodes == 0) {
		DSNVM_PRINTK("There is no other online machines");
		return;
	}

	request.op = DSNVM_OP_NOTIFY_PROMOTED_NEW_ON;
	request.dr_no = dr_no;
	for (i = 0; i < nr_nodes; i++) {
		send_array[i].vaddr = &request;
		send_array[i].len = sizeof(request);
	}

	DSNVM_PRINTK("Notify for dr_no: %lu", dr_no);

	ibapi_multi_send(nr_nodes, node_array, send_array);
}

struct fetch_committed_page {
	unsigned int op;
	unsigned long dr_no;
	unsigned int dro;
};

int dsnvm_handle_fetch_commited_dn_page(char *msg, char *reply_addr, unsigned int *reply_len, int sender_id)
{
	struct fetch_committed_page *request;
	struct dn_region_info *dn_region;
	unsigned long dr_no;
	unsigned int dro;
	unsigned long pfn, kvaddr;

	*reply_len = sizeof(unsigned int);

	request = (struct fetch_committed_page *)msg;
	dr_no = request->dr_no;
	dro = request->dro;

	if (unlikely(dro > DR_PAGE_NR)) {
		DSNVM_WARN("dr_no: %lu, dro: %u", dr_no, dro);
		*(int *)reply_addr = DSNVM_REPLY_INVALID;
		return 0;
	}

	DSNVM_PRINTK("Receive from node: %d, dr_no: %lu, dro: %u",
		sender_id, dr_no, dro);

	dn_region = ht_get_dn_region(dr_no);
	if (unlikely(!dn_region)) {
		DSNVM_PRINTK("dr_no: %lu does not exist", dr_no);

		*(int *)reply_addr = DSNVM_REPLY_INVALID;
		return 0;
	}

	pfn = dn_region->coherent_mapping[dro];
	if (unlikely(!pfn)) {
		*(int *)reply_addr = DSNVM_REPLY_INVALID;
		return 0;
	}

	kvaddr = pfn_to_dsnvm_virt(pfn);
	memcpy((void *)(reply_addr+4), (void *)kvaddr, DSNVM_PAGE_SIZE);
	
	*reply_len += DSNVM_PAGE_SIZE;

	return 0;
}

static struct max_reply_msg *reply_array = NULL;

int fetch_committed_DN_page(unsigned long dr_no, unsigned int dro,
			    struct dn_region_info *dn_region,
			    struct on_page_info *on_page_info)
{
	struct fetch_committed_page request;
	int status, ret = 0;
	int i, nr_dn = 0, node = 0;
	int dn_array[DSNVM_MAX_NODE];
	struct atomic_struct send_array[DSNVM_MAX_NODE];
	unsigned long pfn, kvaddr;
	struct dsnvm_page *page;

	for_each_set_bit(node, dn_region->other_dn_list, DSNVM_MAX_NODE) {
		if (node == DSNVM_LOCAL_ID)
			continue;

		dn_array[nr_dn] = node;
		nr_dn++;

		DSNVM_PRINTK("dr_no: %lu, dro: %u, going to send to node: %d, nr_dn = %d",
			dr_no, dro, node, nr_dn);
	}

	if (nr_dn == 0) {
		DSNVM_PRINTK("No available DNs for dr_no: %lu, dro: %u", dr_no, dro);
		return 0;
	}

	request.op = DSNVM_OP_FETCH_COMMITTED_DN_PAGE;
	request.dr_no = dr_no;
	request.dro =dro;

	for (i = 0; i < nr_dn; i++) {
		send_array[i].vaddr = &request;
		send_array[i].len = sizeof(request);
	}

	ibapi_multi_send_reply(nr_dn, dn_array, send_array, reply_array);

	for (i = 0; i < nr_dn; i++) {
		status = *(int *)(&reply_array[i]);
	
		if (status == DSNVM_REPLY_SUCCESS) {
			DSNVM_PRINTK("dr_no:%lu, dro: %u, node %d succeed",
				dr_no, dro, dn_array[i]);

			/*
			 * Allocate a new page for the new ON_REGION page
			 * and copy the new data into the new page.
			 */
			pfn = alloc_dsnvm_page_pfn();
			on_page_info->local_pfn = pfn;
			dsnvm_flush_buffer(&on_page_info->local_pfn,
				sizeof(on_page_info->local_pfn));

			page = pfn_to_dsnvm_page(pfn);
			DSNVM_SetPageUnevictable(page);

			kvaddr = pfn_to_dsnvm_virt(pfn);
			memcpy((void *)kvaddr, (void *)&reply_array[i] + 4, DSNVM_PAGE_SIZE);
			break;
		} else {
			DSNVM_PRINTK("dr_no:%lu, dro: %u, node %d failed",
				dr_no, dro, dn_array[i]);
		}
	}

	return ret;
}

void promote_DN_to_ON(unsigned long dr_no)
{
	struct on_region_info *on_region;
	struct dn_region_info *dn_region;
	struct on_page_info *on_page_info;
	unsigned long pfn, coherent_pfn;
	unsigned int dro;
	int ret;
	DEFINE_PROFILE_TS(t_start, t_end, t_diff)

	DSNVM_PRINTK("Recovery, promote dr_no: %lu", dr_no);

	dn_region = ht_get_dn_region(dr_no);
	if (unlikely(!dn_region)) {
		DSNVM_WARN("DN_REGION: %lu is not queued into hashtable", dr_no);
		return;
	}

	if (unlikely(REGION_IS_LOCAL(dn_region))) {
		DSNVM_WARN("Self owner of dr_no: %lu", dr_no);
		goto put_dn;
	}

	on_region = alloc_dsnvm_on_region_info();
	if (unlikely(!on_region)) {
		DSNVM_WARN("OOM");
		goto put_dn;
	}

	/* dr_no works like the flag field of ON_REGION */
	on_region->dr_no = dr_no;
	dsnvm_flush_buffer(&on_region->dr_no, sizeof(on_region->dr_no));

	/* Add to hashlist */
	ret = ht_add_on_region(on_region);
	if (ret) {
		DSNVM_WARN();
		goto free_on;
	}

	/* Counter for proc fs */
	count_dsnvm_event(DSNVM_OWNER_REGION_CREATED);

	/* Always use the same array */
	reply_array = kmalloc(sizeof(*reply_array) * DSNVM_MAX_NODE, GFP_KERNEL);
	if (unlikely(!reply_array)) {
		ret = -ENOMEM;
		goto free_on;
	}

	__START_PROFILE(t_start);
	for (dro = 0; dro < DR_PAGE_NR; dro++) {
		on_page_info = &on_region->mapping[dro];
		pfn = dn_region->mapping[dro];
		coherent_pfn = dn_region->coherent_mapping[dro];

		/*
		 * Promotion Single Page
		 *
		 * The coherent_pfn could be the original clean page
		 * fetched from the old ON, or it can be the replica
		 * page. Anyway, if coherent_pfn is valid, then we
		 * could promote it to be new ON_REGION page.
		 */
		if (pfn_is_dsnvm(coherent_pfn)) {
			DSNVM_PRINTK("promote dro: %u, pfn: %lu to ON_REGION page",
				dro, coherent_pfn);

			on_page_info->local_pfn = coherent_pfn;
			continue;
		}

		/*
		 * Fetch from remote DNs
		 */
		DSNVM_PRINTK("fetch dro: %u from remote DNs", dro);

		ret = fetch_committed_DN_page(dr_no, dro, dn_region, on_page_info);
		if (unlikely(ret)) {
			DSNVM_WARN("dr_no: %lu dro: %u", dr_no, dro);
			break;
		}
	}

	notify_all_on_online_machines(dr_no);

	__END_PROFILE(t_start, t_end, t_diff);
	__PROFILE_PRINTK("Promotion DN->ON latency: %lld ns", timespec_to_ns(&t_diff));

	kfree(reply_array);
	ht_put_dn_region(dn_region);
	return;

free_on:
	free_dsnvm_on_region_info(on_region);
put_dn:
	ht_put_dn_region(dn_region);
}
