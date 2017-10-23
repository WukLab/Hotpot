/*
 * Distributed Shared NVM. The Server.
 *
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>
#include <pthread.h>

#include "client.h"
#include "dsnvm-server.h"

#if 0
#define printk_xact
#endif
#ifdef printk_xact
static void dsnvm_printk_xact(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	printf("\033[34mDSNVM-SERVER: \033[0m");
	vfprintf(stdout, fmt, args);
	printf("\n\033[0m");
}
#else
static inline void dsnvm_printk_xact(const char *fmt, ...) { }
#endif

#if 1
#define printk
#endif
#ifdef printk
static void dsnvm_printk(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	printf("\033[32mDSNVM-SERVER: \033[0m");
	vfprintf(stdout, fmt, args);
	printf("\n\033[0m");
}
#else
static inline void dsnvm_printk(const char *fmt, ...) { }
#endif

/* List of all dsnvm files and its lock */
static pthread_spinlock_t dsnvm_files_lock;
static struct list_head dsnvm_files;
static unsigned int DSNVM_LOCAL_ID;
static unsigned long DR_NO_COUNTER;

#ifdef DSNVM_MODE_MRSW
struct dsnvm_cd_xact_rec {
	int xact_id;
	int num_reqs;
	struct dr_no_dro *requests;
	struct list_head next;
};

struct dsnvm_cd_page_in_xact {
	int key;
	int if_in_xact;
	UT_hash_handle hh;
};

static pthread_spinlock_t mrsw_xact_rec_lock;
static struct list_head mrsw_xact_list;

static pthread_spinlock_t mrsw_xact_page_lock;
static struct dsnvm_cd_page_in_xact *ht_mrsw_page_in_xact;
#endif

/*
 * DSNVM_CLIENT_MACHINES are established dsnvm clients, that are available
 * for this server and other dsnvm clients. Client invoke machine_join/leave
 * to add itself to server's known list.
 */
static pthread_mutex_t machine_lock = PTHREAD_MUTEX_INITIALIZER;
DECLARE_BITMAP(DSNVM_CLIENT_MACHINES, DSNVM_MAX_NODE);

static struct dsnvm_server_file *alloc_dsnvm_file(unsigned char *s)
{
	struct dsnvm_server_file *f;

	f = malloc(sizeof(*f));
	if (f) {
		memset(f, 0, sizeof(*f));
		memcpy(f->name, s, DSNVM_MAX_NAME);
		INIT_LIST_HEAD(&f->next);
	}
	return f;
}

__used static void free_dsnvm_file(struct dsnvm_server_file *f)
{
	free(f);
}

/*
 * TODO:
 * find_dsnvm_file(), add_dsnvm_file(), remove_dsnvm_file()
 * are NOT multiple-thread safe now! We build as single-thread first,
 * it is always stupid to assume single-thread is okay. Ambition grows.
 * Anyway, be careful, and make it safe later.
 */
static struct dsnvm_server_file *find_dsnvm_file(unsigned char *s)
{
	struct dsnvm_server_file *f, *ret;

	ret = NULL;
	pthread_spin_lock(&dsnvm_files_lock);
	if (list_empty(&dsnvm_files))
		goto out;

	list_for_each_entry(f, &dsnvm_files, next) {
		if (!strncmp((char *)f->name, (char *)s, DSNVM_MAX_NAME)) {
			ret = f;
			break;
		}
	}

out:
	pthread_spin_unlock(&dsnvm_files_lock);
	return ret;
}

static int add_dsnvm_file(struct dsnvm_server_file *f)
{
	if (!f)
		return -EINVAL;

	if (find_dsnvm_file(f->name))
		return -EEXIST;

	list_add(&f->next, &dsnvm_files);
	return 0;
}

__used static int remove_dsnvm_file(struct dsnvm_server_file *f)
{
	if (!f)
		return -EINVAL;

	if (!find_dsnvm_file(f->name))
		return -ENOENT;

	list_del(&f->next);
	return 0;
}

/*
 * This functions returns a global unique DR_NO.
 * TODO: some randomizations?
 */
static unsigned long assign_global_dr_no(void)
{
	return DR_NO_COUNTER++;
}

/*
 * Choose a owner node for a data region.
 *
 * TODO: the pick can base on:
 *	Cluster topology
 *	NVM resource of machines
 *	Previous assigning history
 *	etc.
 */
static int LAST_ASSIGNED_OWNER_NODE;
static int assign_owner_node(struct dsnvm_server_file *f, int sender_id)
{
	int node;

round:
	for_each_set_bit (node, DSNVM_CLIENT_MACHINES, DSNVM_MAX_NODE) {
		if (unlikely(node == 0)) {
			DSNVM_BUG("Crashed");
			continue;
		}

		if (node > LAST_ASSIGNED_OWNER_NODE) {
			LAST_ASSIGNED_OWNER_NODE = node;
			break;
		}
	}

	if (node == DSNVM_MAX_NODE) {
		LAST_ASSIGNED_OWNER_NODE = 0;
		goto round;
	}

	return node;
}

/**
 * establish_owner_node
 * @f:		The dsnvm file context
 * @index:	The index of the DR within file
 * @owner_node: Node was chosed to be owner node
 * @dr_no:	Global DR_NO of this region
 *
 * Ask @owner_node to establish a new ON region.
 */
static int establish_owner_node(struct dsnvm_server_file *f, int index,
				int owner_node, unsigned long dr_no)
{
	struct dsnvm_request request;
	struct dsnvm_reply reply;
	struct cd_region_info *r;
	unsigned int size;

	request.op = DSNVM_OP_CREAT_REGION_AT_ON;
	request.dr_no = dr_no;
	size = sizeof(__u64) + sizeof(__u64);

	ibapi_send_reply(owner_node, (char *)&request, size, (char *)&reply);

	if (reply.status != DSNVM_REPLY_SUCCESS) {
		DSNVM_WARN("%s", dsnvm_status_string(reply.status));
		return -EIO;
	}

	dsnvm_printk("[%s:%d] assign [dr_no: %5lu] --> [owner_id: %2d]",
		__func__, __LINE__, dr_no, owner_node);

	/*
	 * Established succefully, update metadata then.
	 */
	r = &(f->regions[index]);
	r->dr_no = dr_no;
	r->owner_id = owner_node;
	set_bit(index, f->dr_map);

	return 0;
}

/*
 * NR_PREALLOCATED_REGIONS determines how many data regions
 * we are going to pre-allocate for a brand-new dsnvm file.
 *
 * DN_PREFER_ITSELF determins whether we use the DN itself to
 * be ON. If so, then it is DN==ON, it should speed up normal
 * cases. If not, then we choose an ON other than this DN.
 */
#define NR_PREALLOCATED_REGIONS	32
#define DN_PREFER_ITSELF	false

static int init_new_dsnvm_file(struct dsnvm_server_file *f, int sender_id)
{
	int index, owner_node, nr_established = 0;
	unsigned long dr_no;

	dsnvm_printk("[%s:%d] Preallocate %d regions for: %s",
		__func__, __LINE__, NR_PREALLOCATED_REGIONS, f->name);

	for (index = 0; index < NR_PREALLOCATED_REGIONS; index++) {
		if (DN_PREFER_ITSELF)
			owner_node = sender_id;
		else
			owner_node = assign_owner_node(f, sender_id);

		dr_no = assign_global_dr_no();

		if (!establish_owner_node(f, index, owner_node, dr_no))
			nr_established++;
	}
	return nr_established;
}

static pthread_spinlock_t handle_open_lock;

static void handle_open(char *input, char *output,
			unsigned int *reply_len, int sender_id, bool create)
{
	int idx, nr_dr = 0;
	unsigned char *s;
	struct __region_info *region;
	struct dsnvm_server_file *f;
	struct dsnvm_request_open_file *request;
	struct dsnvm_reply *reply;

	dsnvm_printk("[%s:%d] Receive open() request from node: %2d",
		__func__, __LINE__, sender_id);

	request = (struct dsnvm_request_open_file *)input;
	reply = (struct dsnvm_reply *)output;

	pthread_spin_lock(&handle_open_lock);

	s = request->name;
	f = find_dsnvm_file(s);
	if (!f) {
		if (!create) {
			reply->status = DSNVM_OPEN_NON_EXIST_FILE;
			*reply_len = sizeof(unsigned int);
			goto out;
		}

		f = alloc_dsnvm_file(s);
		if (!f) {
			reply->status = DSNVM_CREAT_FILE_FAIL;
			*reply_len = sizeof(unsigned int);
			goto out;
		}
		init_new_dsnvm_file(f, sender_id);
		add_dsnvm_file(f);
	}

	/*
	 * Report to DN with all data region info
	 */

	region = &reply->base[0];
	for_each_set_bit (idx, f->dr_map, DSNVM_MAX_REGIONS) {
		region->dr_no = f->regions[idx].dr_no;
		region->owner_id = f->regions[idx].owner_id;

		set_bit(sender_id, f->regions[idx].dn_list);
		bitmap_copy(region->dn_list, f->regions[idx].dn_list, DSNVM_MAX_NODE);

		region++;
		nr_dr++;
	}

	reply->nr_dr = nr_dr;

	reply->status = DSNVM_REPLY_SUCCESS;
	*reply_len = 2*sizeof(__u32) + nr_dr*sizeof(struct __region_info);

out:
	pthread_spin_unlock(&handle_open_lock);
}

static pthread_spinlock_t extend_lock;

static void handle_extend_one_region(char *input, unsigned int input_len,
				     char *output, unsigned int *reply_len,
				     int sender_id)
{
	struct dsnvm_request_extend_file *request;
	struct dsnvm_reply_extend_file *reply;
	struct dsnvm_server_file *f;
	struct cd_region_info *r;
	int owner_node;
	unsigned long dr_no;

	request = (struct dsnvm_request_extend_file *)input;
	reply = (struct dsnvm_reply_extend_file *)output;
	*reply_len = sizeof(__u32);

	pthread_spin_lock(&extend_lock);

	f = find_dsnvm_file(request->name);
	if (unlikely(!f)) {
		/*
		 * This request type only happens
		 * after dsnvm file is opened.
		 */
		reply->status = DSNVM_ENOENT;
		goto out;
	}

	if (unlikely(request->dr_index > DSNVM_MAX_REGIONS)) {
		reply->status = DSNVM_EINVAL;
		goto out;
	}

	r = &(f->regions[request->dr_index]);
	if (r->dr_no != 0) {
		/*
		 * Two reasons:
		 *	1) Two machines competing
		 *	2) BUG
		 */
		if (likely(r->owner_id != 0)) {
			goto okay;
		} else {
			reply->status = DSNVM_EINVAL;
			goto out;
		}
	}

	if (DN_PREFER_ITSELF)
		owner_node = sender_id;
	else
		owner_node = assign_owner_node(f, sender_id);

	dr_no = assign_global_dr_no();

	if (establish_owner_node(f, request->dr_index, owner_node, dr_no)) {
		reply->status = DSNVM_EPERM;
		goto out;
	}

okay:
	reply->status = DSNVM_REPLY_SUCCESS;
	reply->dr_no = r->dr_no;
	reply->owner_id = r->owner_id;
	*reply_len = sizeof(*reply);

out:
	pthread_spin_unlock(&extend_lock);
}

static void handle_machine_join(char *input, unsigned int input_len,
				char *output, unsigned int *output_len,
				int sender_id)
{
	int node;
	struct dsnvm_request_machine_event request;
	struct dsnvm_reply_machine_event reply;
	struct dsnvm_reply_machine_join *reply_join;
	struct dsnvm_request_machine_join *request_join;

	request_join = (void *)input;
	reply_join = (struct dsnvm_reply_machine_join *)output;
	*output_len = sizeof(struct dsnvm_reply_machine_join);

	dsnvm_printk("[%s:%d] Receive machine join from node %d",
		__func__, __LINE__, sender_id);

	/*
	 * Sanity Check
	 */
	if (request_join->xact_mode != XACT_MODE ||
	    request_join->dr_page_nr_shift != DR_PAGE_NR_SHIFT ||
	    request_join->dsnvm_max_regions_shift != DSNVM_MAX_REGIONS_SHIFT) {
		DSNVM_BUG("Mismatched configure from node: %d\n", sender_id);

		printf("Node: mode: %d, DR_PAGE_NR_SHIFT: %d, MAX_REGION_SHIFT: %d\n",
				request_join->xact_mode,
				request_join->dr_page_nr_shift,
				request_join->dsnvm_max_regions_shift);
		printf("CD: mode: %d, DR_PAGE_NR_SHIFT: %d, MAX_REGION_SHIFT: %d\n",
				XACT_MODE, DR_PAGE_NR_SHIFT, DSNVM_MAX_REGIONS_SHIFT);

		reply_join->status = DSNVM_EPERM;
		return;
	}

	if (unlikely(test_bit(sender_id, DSNVM_CLIENT_MACHINES))) {
		DSNVM_BUG("Node: %d joined twice", sender_id);
		reply_join->status = DSNVM_EEXIST;
		return;
	}

	/*
	 * Inform all online machines
	 */

	request.op = DSNVM_OP_RECEIVE_MACHINE_JOIN;
	request.node_id = sender_id;

	for_each_set_bit(node, DSNVM_CLIENT_MACHINES, DSNVM_MAX_NODE) {
		if (unlikely(node == 0)) {
			DSNVM_BUG("Crashed")
			continue;
		}

		if (node == sender_id)
			continue;

		ibapi_send_reply(node, (char *)&request, sizeof(request), (char *)&reply);

		if (reply.status != DSNVM_REPLY_SUCCESS) {
			reply_join->status = DSNVM_EPERM;
			return;
		}
	}

	/*
	 * Alright, we have a consent from all online machines
	 *
	 * For MRSW in kernel:
	 *	DSNVM_MODE_MRSW_IN_KERNEL is used as the MRSW sync point,
	 *	we do not treat it as a normal hotpot node.
	 */

#ifdef DSNVM_MODE_MRSW_IN_KERNEL
	if (sender_id != DSNVM_MRSW_MASTER_NODE)
#endif
		set_bit(sender_id, DSNVM_CLIENT_MACHINES);

	reply_join->status = DSNVM_REPLY_SUCCESS;
	bitmap_copy(reply_join->DSNVM_CLIENT_MACHINES, DSNVM_CLIENT_MACHINES,
			DSNVM_MAX_NODE);
}

static void handle_machine_leave(char *input, unsigned int input_len,
				 char *output, unsigned int *output_len,
				 int sender_id)
{
	int node;
	struct dsnvm_request_machine_event request;
	struct dsnvm_reply_machine_event reply;

	*output_len = 4;

	dsnvm_printk("[%s:%d] Receive machine leave from node %d",
		__func__, __LINE__, sender_id);

	if (unlikely(!test_bit(sender_id, DSNVM_CLIENT_MACHINES))) {
#ifdef DSNVM_MODE_MRSW_IN_KERNEL
		if (sender_id == DSNVM_MRSW_MASTER_NODE) {
			*(int *)output = DSNVM_REPLY_SUCCESS;
			return;
		}
#endif
		DSNVM_BUG("not joined");
		*(int *)output = DSNVM_ENOENT;
		return;
	}

	/*
	 * Inform all online machines
	 */

	request.op = DSNVM_OP_RECEIVE_MACHINE_LEAVE;
	request.node_id = sender_id;

	for_each_set_bit(node, DSNVM_CLIENT_MACHINES, DSNVM_MAX_NODE) {
		if (unlikely(node == 0)) {
			DSNVM_BUG("Crashed")
			continue;
		}

		if (node == sender_id)
			continue;

		ibapi_send_reply(node, (char *)&request, sizeof(request), (char *)&reply);

		if (reply.status != DSNVM_REPLY_SUCCESS) {
			*(int *)output = reply.status;
			return;
		}
	}

	/*
	 * Good to leave
	 */

	clear_bit(sender_id, DSNVM_CLIENT_MACHINES);

	*(int *)output = DSNVM_REPLY_SUCCESS;
}

static void handle_migrate_on_chunk_finished_notify(char *input,
			unsigned int input_len, char *output,
			unsigned int *output_len, int sender_id)
{
	struct migrate_on_chunk_notify *header;
	unsigned long dr_no;
	unsigned int new_owner, i;
	struct dsnvm_server_file *f;

	*output_len = 4;
	*(int *)output = DSNVM_REPLY_SUCCESS;

	header = (struct migrate_on_chunk_notify *)input;
	dr_no = header->dr_no;
	new_owner = header->new_owner;

	pthread_spin_lock(&dsnvm_files_lock);
	list_for_each_entry(f, &dsnvm_files, next) {
		for (i = 0; i < DSNVM_MAX_REGIONS; i++) {
			struct cd_region_info *r = &f->regions[i];

			if (r->dr_no == dr_no) {
				dsnvm_printk("[%s:%d] dr_no: %lu, change ownership from %u -> %u",
					__func__, __LINE__, dr_no, r->owner_id, new_owner);

				r->owner_id = new_owner;
				pthread_spin_unlock(&dsnvm_files_lock);
				return;
			}
		}
	}
	pthread_spin_unlock(&dsnvm_files_lock);
}

#ifdef DSNVM_MODE_MRSW

#ifndef DSNVM_MODE_MRSW_IN_KERNEL

static void handle_mrsw_begin_xact(char *send_msg, unsigned int send_msg_size,
				   char *output, unsigned int *reply_len, int sender_id)
{
	int xact_id, i;
	int nr_reqs, hash_key;
	unsigned long dr_no;
	unsigned int dro;
	struct dr_no_dro *dr_requests;
	struct status_reply_msg *reply;
	struct dsnvm_cd_xact_rec *xact_rec;
	struct dsnvm_cd_page_in_xact *htentry = NULL;

	reply = (struct status_reply_msg *)output;
	*reply_len = sizeof(struct status_reply_msg);

	/* Extract metadata from incoming message */
	memcpy(&xact_id, send_msg + sizeof(int), sizeof(int));
	nr_reqs = (send_msg_size - 2 * sizeof(int)) / sizeof(struct dr_no_dro);
	dr_requests = (struct dr_no_dro *)(send_msg + 2 * sizeof(int));

	dsnvm_printk_xact("[%s:%d] START sender:%d xact_id: %d nr_reqs: %d",
		__func__, __LINE__, sender_id, xact_id, nr_reqs);

	/*
	 * Check the whole hashlist first and then insert each page rec into
	 * hashlist if none of the requested pages are in xact state.
	 *
	 * Locking: Use mrsw_xact_page_lock to serialize hashlist manipulations
	 */
	pthread_spin_lock(&mrsw_xact_page_lock);
	for (i = 0; i < nr_reqs; i++) {
		dr_no = dr_requests[i].dr_no;
		dro = dr_requests[i].dro;
		hash_key = dr_no * DR_PAGE_NR + dro;

		HASH_FIND_INT(ht_mrsw_page_in_xact, &hash_key, htentry);
		if (htentry) {
			/* Already locked by another xact */
			pthread_spin_unlock(&mrsw_xact_page_lock);
			reply->status = DSNVM_RETRY;
			free(send_msg);

			dsnvm_printk_xact("[%s:%d] page %d dr_no %lu dro %u hashkey %d EXISTS",
				__func__, __LINE__, i, dr_no, dro, hash_key);

			return;
		}
	}

	/* Insert to hash list */
	for (i = 0; i < nr_reqs; i++) {
		dr_no = dr_requests[i].dr_no;
		dro = dr_requests[i].dro;
		hash_key = dr_no * DR_PAGE_NR + dro;

		htentry = malloc(sizeof(struct dsnvm_cd_page_in_xact));
		if (unlikely(!htentry)) {
			pthread_spin_unlock(&mrsw_xact_page_lock);

			DSNVM_WARN("OOM");
			reply->status = DSNVM_ENOMEM;
			free(send_msg);
			return;
		}

		htentry->key = hash_key;
		htentry->if_in_xact = 1;
		HASH_ADD_INT(ht_mrsw_page_in_xact, key, htentry);

		dsnvm_printk_xact("[%s:%d] page %d dr_no %lu dro %u hashkey %d INSERT",
			__func__, __LINE__, i, dr_no, dro, hash_key);
	}
	pthread_spin_unlock(&mrsw_xact_page_lock);

	/*
	 * Successfully checked and inserted all pages into hashlist,
	 * now add this transaction record into another rec hashlist.
	 *
	 * Locking: Use mrsw_xact_rec_lock to protect mrsw_xact_list
	 */
	xact_rec = malloc(sizeof(struct dsnvm_cd_xact_rec));
	if (!xact_rec) {
		DSNVM_WARN("OOM");

		reply->status = DSNVM_ENOMEM;
		free(send_msg);
		return;
	}

	/*
	 * Because the original send_msg will be be freed later, so we must
	 * copy dr_no_no info into a safe place.
	 */
	dr_requests = malloc(send_msg_size - 2 * sizeof(int));
	if (!dr_requests) {
		DSNVM_WARN("OOM");

		reply->status = DSNVM_ENOMEM;
		free(xact_rec);
		free(send_msg);
		return;
	}
	memcpy(dr_requests, send_msg + 2 * sizeof(int), send_msg_size - 2 * sizeof(int));

	xact_rec->xact_id = xact_id;
	xact_rec->num_reqs = nr_reqs;
	xact_rec->requests = dr_requests;

	/* Save the xact record */
	pthread_spin_lock(&mrsw_xact_rec_lock);
	list_add(&xact_rec->next, &mrsw_xact_list);
	pthread_spin_unlock(&mrsw_xact_rec_lock);

	reply->status = DSNVM_REPLY_SUCCESS;
	free(send_msg);

	dsnvm_printk_xact("[%s:%d] EXIT sender:%d xact_id: %d nr_reqs: %d xact_id %d",
		__func__, __LINE__, sender_id, xact_id, nr_reqs, xact_id);
}

static void handle_mrsw_commit_xact(char *send_msg, unsigned int send_msg_size,
				   char *output, unsigned int *reply_len, int sender_id)
{
	int xact_id, i;
	struct dsnvm_cd_xact_rec *currentry, *tempentry;
	struct dsnvm_cd_page_in_xact *htentry = NULL;
	struct status_reply_msg *reply;

	reply = (struct status_reply_msg *)output;
	*reply_len = sizeof(struct status_reply_msg);

	memcpy(&xact_id, send_msg + sizeof(int), sizeof(int));

	dsnvm_printk_xact("[%s:%d] Commit-Xact xact_id: %d",
		__func__, __LINE__, xact_id);

	/*
	 * Locking:	mrsw_xact_rec_lock
	 *		mrsw_xact_page_lock
	 */
	pthread_spin_lock(&mrsw_xact_rec_lock);
	list_for_each_entry_safe(currentry, tempentry, &mrsw_xact_list, next) {
		if (currentry->xact_id == xact_id) {
			/* Remove all related xact page records */
			pthread_spin_lock(&mrsw_xact_page_lock);
			for (i = 0; i < currentry->num_reqs; i++) {
				unsigned long dr_no = currentry->requests[i].dr_no;
				unsigned int dro = currentry->requests[i].dro;
				int hash_key = dr_no * DR_PAGE_NR + dro;

				dsnvm_printk_xact("[%s:%d] request %d dr_no %lu dro %u hashkey %d",
					__func__, __LINE__, i, dr_no, dro, hash_key);

				HASH_FIND_INT(ht_mrsw_page_in_xact, &hash_key, htentry);
				if (likely(htentry)) {
					HASH_DEL(ht_mrsw_page_in_xact, htentry);
					free(htentry);
				} else {
					/* No one should ever touched this record. */
					DSNVM_BUG("xact id: %d, dr_no: %lu, dro: %u", xact_id, dr_no, dro);
					pthread_spin_unlock(&mrsw_xact_page_lock);
					pthread_spin_unlock(&mrsw_xact_rec_lock);
					goto error;
				}
			}
			pthread_spin_unlock(&mrsw_xact_page_lock);

			/* Remove the xact record and free mem */
			list_del(&currentry->next);
			if (currentry->requests)
				free(currentry->requests);
			free(currentry);

			pthread_spin_unlock(&mrsw_xact_rec_lock);
			reply->status = DSNVM_REPLY_SUCCESS;
			free(send_msg);

			dsnvm_printk_xact("[%s:%d] return successful",
				__func__, __LINE__);

			return;
		}
	}
	pthread_spin_unlock(&mrsw_xact_rec_lock);

error:
	reply->status = DSNVM_REPLY_INVALID;
	free(send_msg);
	dsnvm_printk_xact("[%s:%d] return failed, xact_id: %d",
		__func__, __LINE__, xact_id);
}

#else

static void handle_mrsw_begin_xact(char *send_msg, unsigned int send_msg_size,
				   char *output, unsigned int *reply_len, int sender_id)
{
	struct status_reply_msg *reply;

	DSNVM_BUG("from node: %d", sender_id);

	reply = (struct status_reply_msg *)output;
	reply->status = DSNVM_REPLY_INVALID;
	*reply_len = sizeof(struct status_reply_msg);
}

static void handle_mrsw_commit_xact(char *send_msg, unsigned int send_msg_size,
				   char *output, unsigned int *reply_len, int sender_id)
{
	struct status_reply_msg *reply;

	DSNVM_BUG("from node: %d", sender_id);

	reply = (struct status_reply_msg *)output;
	reply->status = DSNVM_REPLY_INVALID;
	*reply_len = sizeof(struct status_reply_msg);
}

#endif /* DSNVM_MODE_MRSW_IN_KERNEL */

#endif /* DSNVM_MODE_MRSW */

static void handle_bad_request(struct dsnvm_request *request,
			       struct dsnvm_reply *reply,
			       unsigned int *reply_len, int sender_id)
{
	fprintf(stderr, "Bad Rquest from node %d, OP: %d\n",
		sender_id, request->op);
	reply->status = DSNVM_INVALID_OP;
	*reply_len = sizeof(unsigned int);
}

static void handle_test(struct dsnvm_request *request,
		       struct dsnvm_reply *reply,
		       unsigned int *reply_len, int sender_id)
{
	reply->status = DSNVM_REPLY_SUCCESS;
	*reply_len = sizeof(unsigned int);
	printf("handle_test\n");
}

/*
 * Both input and output buffers were allocated by IB layer.
 * We only need to tell IB layer how long @output_len is.
 */
static int IB_SEND_REPLY_handler(char *input, unsigned int input_len,
				 char *output, unsigned int *output_len,
				 int sender_id)
{
	struct dsnvm_request *request;
	struct dsnvm_reply *reply;

	request = (struct dsnvm_request *)input;
	reply = (struct dsnvm_reply *)output;

	switch (request->op) {
	case DSNVM_OP_OPEN:
		handle_open(input, output, output_len, sender_id, false);
		break;
	case DSNVM_OP_OPEN_OR_CREAT:
		handle_open(input, output, output_len, sender_id, true);
		break;
	case DSNVM_OP_EXTEND_ONE_REGION:
		handle_extend_one_region(input, input_len, output, output_len, sender_id);
		break;
	case DSNVM_OP_SEND_MACHINE_JOIN:
		/* Serialize all join/leave events.. oh well, for tmux users.. */
		pthread_mutex_lock(&machine_lock);
		handle_machine_join(input, input_len, output, output_len, sender_id);
		pthread_mutex_unlock(&machine_lock);
		break;
	case DSNVM_OP_SEND_MACHINE_LEAVE:
		pthread_mutex_lock(&machine_lock);
		handle_machine_leave(input, input_len, output, output_len, sender_id);
		pthread_mutex_unlock(&machine_lock);
		break;
	case DSNVM_OP_MIGRATE_ON_CHUNK_NOTIFY:
		handle_migrate_on_chunk_finished_notify(input, input_len, output, output_len, sender_id);
		break;
#ifdef DSNVM_MODE_MRSW
	case DSNVM_OP_MRSW_BEGIN_XACT:
		handle_mrsw_begin_xact(input, input_len, output, output_len, sender_id);
		break;
	case DSNVM_OP_MRSW_COMMIT_XACT:
		handle_mrsw_commit_xact(input, input_len, output, output_len, sender_id);
		break;
#endif
	case DSNVM_OP_TEST:
		handle_test(request, reply, output_len, sender_id);
		break;
	default:
		handle_bad_request(request, reply, output_len, sender_id);
	}

	return 0;
}

static int IB_SEND_handler(char *addr, unsigned int size)
{
#ifdef DSNVM_MODE_MRSW
	struct dsnvm_request *request;

	request = (struct dsnvm_request *)addr;

	switch (request->op) {
	default:
		printf("IB_SEND_handler error type %d\n", request->op);
	}
#endif
	return 0;
}

void init_dsnvm_server(void)
{
	DR_NO_COUNTER = 1;
	DSNVM_LOCAL_ID = 0;
	INIT_LIST_HEAD(&dsnvm_files);

	pthread_spin_init(&extend_lock,  PTHREAD_PROCESS_PRIVATE);
	pthread_spin_init(&dsnvm_files_lock, PTHREAD_PROCESS_PRIVATE);
	pthread_spin_init(&handle_open_lock, PTHREAD_PROCESS_PRIVATE);

#ifdef DSNVM_MODE_MRSW
	INIT_LIST_HEAD(&mrsw_xact_list);
	pthread_spin_init(&mrsw_xact_rec_lock, PTHREAD_PROCESS_PRIVATE);
	pthread_spin_init(&mrsw_xact_page_lock, PTHREAD_PROCESS_PRIVATE);
	dsnvm_printk("Transaction Model: MRSW");
#ifdef DSNVM_MODE_MRSW_IN_KERNEL
	dsnvm_printk("  MRSW Master Node: %d", DSNVM_MRSW_MASTER_NODE);
#endif
#else
	dsnvm_printk("Transaction Model: MRMW");
#endif

	LAST_ASSIGNED_OWNER_NODE = 0;
	bitmap_clear(DSNVM_CLIENT_MACHINES, 0, DSNVM_MAX_NODE);

	ibapi_reg_send_handler(IB_SEND_handler);
	ibapi_reg_send_reply_handler(IB_SEND_REPLY_handler);
}
