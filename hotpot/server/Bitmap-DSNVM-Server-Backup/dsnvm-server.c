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

#define __used                 __attribute__((__used__))

#if 0
#define printk_xact
#endif
#ifdef printk_xact
__used static void dsnvm_printk_xact(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	printf("\033[34mDSNVM-SERVER: \033[0m");
	vfprintf(stdout, fmt, args);
	printf("\n\033[0m");
}
#else
static void dsnvm_printk_xact(const char *fmt, ...) { }
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
static void dsnvm_printk(const char *fmt, ...) { }
#endif

/* List of all dsnvm files. Single thread */
static struct list_head dsnvm_files;
static unsigned int DSNVM_LOCAL_ID;
static unsigned long DR_NO_COUNTER;

/* ON_REGION hashtable and its lock */
static pthread_spinlock_t ht_cd_on_region_list_lock;
static struct cd_on_region_info *ht_cd_on_region_list = NULL;

#ifdef DSNVM_MODE_MRSW
struct cd_xact_rec {
	int			xact_id;
	int			sender_id;
	int			nr_areas;
	struct dr_no_dro	*areas;
	UT_hash_handle		hh;
};

/* xact-record hashtable and its lock */
static pthread_spinlock_t ht_cd_xact_rec_list_lock;
static struct cd_xact_rec *ht_cd_xact_rec_list = NULL;
#endif

/*
 * DSNVM_CLIENT_MACHINES are established dsnvm clients, that are available
 * for this server and other dsnvm clients. Client invoke machine_join/leave
 * to add itself to server's known list.
 */
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

/* Do a linear search. */
static struct dsnvm_server_file *find_dsnvm_file(unsigned char *s)
{
	struct dsnvm_server_file *f;

	if (list_empty(&dsnvm_files))
		return NULL;

	list_for_each_entry(f, &dsnvm_files, next) {
		if (!strncmp((char *)f->name, (char *)s, DSNVM_MAX_NAME))
			return f;
	}
	return NULL;
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

static int ht_insert_new_on(unsigned long dr_no_lu, unsigned int owner_id)
{
	struct cd_on_region_info *region;
	int dr_no;
	int ret;

	dr_no = (int)dr_no_lu;

	pthread_spin_lock(&ht_cd_on_region_list_lock);
	HASH_FIND_INT(ht_cd_on_region_list, &dr_no, region);
	if (!region) {
		region = malloc(sizeof(*region));
		if (!region) {
			DSNVM_WARN("OOM");
			ret = -ENOMEM;
			goto unlock;
		}

		region->dr_no = dr_no;
		region->owner_id = owner_id;
		pthread_spin_init(&region->lock, PTHREAD_PROCESS_PRIVATE);
		HASH_ADD_INT(ht_cd_on_region_list, dr_no, region);

#if 1
		dsnvm_printk("[%s:%d] insert dr_no: %d, owner_id: %u into ON REGION hashtable",
			__func__, __LINE__, dr_no, owner_id);
#endif
	} else {
		dsnvm_printk("[%s:%d] dr_no: %d, owner_id: %u exist",
			__func__, __LINE__, dr_no, owner_id);
	}

	ret = 0;
unlock:
	pthread_spin_unlock(&ht_cd_on_region_list_lock);
	return ret;
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
	int ret;

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

	ret = ht_insert_new_on(dr_no, owner_node);

	return ret;
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

	s = request->name;
	f = find_dsnvm_file(s);
	if (!f) {
		if (!create) {
			reply->status = DSNVM_OPEN_NON_EXIST_FILE;
			*reply_len = sizeof(unsigned int);
			return;
		}

		f = alloc_dsnvm_file(s);
		if (!f) {
			reply->status = DSNVM_CREAT_FILE_FAIL;
			*reply_len = sizeof(unsigned int);
			return;
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
		pthread_spin_unlock(&extend_lock);
		return;
	}

	if (unlikely(request->dr_index > DSNVM_MAX_REGIONS)) {
		reply->status = DSNVM_EINVAL;
		pthread_spin_unlock(&extend_lock);
		return;
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
			pthread_spin_unlock(&extend_lock);
			return;
		}
	}

	if (DN_PREFER_ITSELF)
		owner_node = sender_id;
	else
		owner_node = assign_owner_node(f, sender_id);

	dr_no = assign_global_dr_no();

	if (establish_owner_node(f, request->dr_index, owner_node, dr_no)) {
		reply->status = DSNVM_EPERM;
		pthread_spin_unlock(&extend_lock);
		return;
	}

okay:
	reply->status = DSNVM_REPLY_SUCCESS;
	reply->dr_no = r->dr_no;
	reply->owner_id = r->owner_id;
	*reply_len = sizeof(*reply);

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

	reply_join = (struct dsnvm_reply_machine_join *)output;
	*output_len = sizeof(struct dsnvm_reply_machine_join);

	dsnvm_printk("[%s:%d] Receive machine join from node %d",
		__func__, __LINE__, sender_id);

	if (unlikely(test_bit(sender_id, DSNVM_CLIENT_MACHINES))) {
		DSNVM_BUG("join twice");
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
	 */

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
	unsigned int new_owner;
	struct cd_on_region_info *region = NULL;
	int hash_key;

	*output_len = 4;
	*(int *)output = DSNVM_REPLY_SUCCESS;

	header = (struct migrate_on_chunk_notify *)input;
	dr_no = header->dr_no;
	new_owner = header->new_owner;

	/* Find ON_REGION by dr_no from hashtable */
	hash_key = (int)dr_no;
	HASH_FIND_INT(ht_cd_on_region_list, &hash_key, region);
	if (unlikely(!region)) {
		DSNVM_BUG("sender_id: %d, dr_no: %lu does not exist in hashtable!",
			sender_id, dr_no);
		return;
	}

	if (likely(region->dr_no == dr_no && region->owner_id == sender_id)) {
		dsnvm_printk("[%s:%d] dr_no: %lu, change ownership from %u -> %u",
			__func__, __LINE__, dr_no, sender_id, new_owner);
		region->owner_id = new_owner;
		return;
	} else
		DSNVM_BUG("sender_id: %d, dr_no: %lu\n", sender_id, dr_no);
}

#ifdef DSNVM_MODE_MRSW

static void revert(int nr_areas, int failed_area, struct dr_no_dro *areas,
		   int sender_id, int xact_id)
{
	int i, hash_key;
	unsigned long dr_no;
	unsigned int dro;
	struct cd_on_region_info *region;

	for (i = 0; i < failed_area; i++) {
		dr_no = areas[i].dr_no;
		dro = areas[i].dro;
		hash_key = (int)dr_no;

		HASH_FIND_INT(ht_cd_on_region_list, &hash_key, region);
		if (unlikely(!region)) {
			DSNVM_BUG("dr_no: %lu, sender: %d, xact_id: %d",
				dr_no, sender_id, xact_id);
			continue;
		}

		pthread_spin_lock(&region->lock);
		if (unlikely(!test_and_clear_bit(dro, region->in_xact_bitmap))) {
			DSNVM_BUG("dr_no: %lu, dro: %d, sender: %d, xact_id: %d "
				"Page was not inxact (revert)",
				dr_no, dro, sender_id, xact_id);
		}
		pthread_spin_unlock(&region->lock);
	}
}

static void handle_mrsw_begin_xact(char *send_msg, unsigned int send_msg_size,
				   char *output, unsigned int *reply_len, int sender_id)
{
	int xact_id, i, failed_area;
	int nr_areas, hash_key;
	unsigned long dr_no;
	unsigned int dro;
	struct dr_no_dro *areas;
	struct status_reply_msg *reply;
	struct cd_xact_rec *xact_rec = NULL;
	struct cd_on_region_info *region = NULL;

	reply = (struct status_reply_msg *)output;
	*reply_len = sizeof(struct status_reply_msg);

	/* Extract metadata from incoming message */
	memcpy(&xact_id, send_msg + sizeof(int), sizeof(int));
	nr_areas = (send_msg_size - 2 * sizeof(int)) / sizeof(struct dr_no_dro);
	areas = (struct dr_no_dro *)(send_msg + 2 * sizeof(int));

	dsnvm_printk_xact("[%s:%d] Sender: %d xact_id: %d nr_areas: %d",
		__func__, __LINE__, sender_id, xact_id, nr_areas);

	failed_area = 0;
	for (i = 0; i < nr_areas; i++) {
		dr_no = areas[i].dr_no;
		dro = areas[i].dro;
		hash_key = (int)dr_no;

		if (unlikely(dro >= DR_PAGE_NR)) {
			DSNVM_BUG("Sender: %d, dr_no: %lu, dro: %u",
				sender_id, dr_no, dro);

			reply->status = DSNVM_REPLY_BUG;
			failed_area = i;
			goto revert;
		}

		/* Find ON_REGION by dr_no from hashtable */
		HASH_FIND_INT(ht_cd_on_region_list, &hash_key, region);
		if (likely(region)) {
			pthread_spin_lock(&region->lock);
			if (unlikely(test_and_set_bit(dro, region->in_xact_bitmap))) {
				pthread_spin_unlock(&region->lock);
				/*
				 * Already blocked by another xact
				 * Do revert and let client retry.
				 */
				dsnvm_printk_xact("[%s:%d] Sender: %d, dr_no: %lu, dro: %u blocked by other",
					__func__, __LINE__, sender_id, dr_no, dro);
				reply->status = DSNVM_RETRY;
				failed_area = i;
				goto revert;
			}
			pthread_spin_unlock(&region->lock);

			dsnvm_printk_xact("[%s:%d] Sender: %d, dr_no: %lu, dro: %u, we block",
				__func__, __LINE__, sender_id, dr_no, dro);

		} else {
			DSNVM_BUG("Sender: %d, dr_no: %lu not in hashtable",
				sender_id, dr_no);

			reply->status = DSNVM_ENOREGION;
			failed_area = i;
			goto revert;
		}
	}

	failed_area = nr_areas;

	/*
	 * Because the original send_msg will be be freed later, so we must
	 * copy dr_no_no info into a safe place.
	 */
	areas = malloc(send_msg_size - 2 * sizeof(int));
	if (!areas) {
		DSNVM_WARN("OOM");
		reply->status = DSNVM_ENOMEM;
		goto revert;
	}
	memcpy(areas, send_msg + 2 * sizeof(int), send_msg_size - 2 * sizeof(int));

	/* Create and insert xact-record into list */
	xact_rec = malloc(sizeof(*xact_rec));
	if (!xact_rec) {
		DSNVM_WARN("OOM");
		free(areas);
		reply->status = DSNVM_ENOMEM;
		goto revert;
	}
	xact_rec->sender_id = sender_id;
	xact_rec->xact_id = xact_id;
	xact_rec->nr_areas = nr_areas;
	xact_rec->areas = areas;

	pthread_spin_lock(&ht_cd_xact_rec_list_lock);
	HASH_ADD_INT(ht_cd_xact_rec_list, xact_id, xact_rec);
	pthread_spin_unlock(&ht_cd_xact_rec_list_lock);

	reply->status = DSNVM_REPLY_SUCCESS;
	free(send_msg);
	return;

revert:
	revert(nr_areas, failed_area, areas, sender_id, xact_id);
	
	free(send_msg);
	if (xact_rec)
		free(xact_rec);
}

static void handle_mrsw_commit_xact(char *send_msg, unsigned int send_msg_size,
				   char *output, unsigned int *reply_len, int sender_id)
{
	int xact_id, i;
	struct status_reply_msg *reply;
	struct cd_xact_rec *xact_rec;
	struct dr_no_dro *areas;
	int nr_areas;

	reply = (struct status_reply_msg *)output;
	reply->status = DSNVM_REPLY_SUCCESS;
	*reply_len = sizeof(struct status_reply_msg);

	/* xact-id is the second int */
	memcpy(&xact_id, send_msg + sizeof(int), sizeof(int));

	dsnvm_printk_xact("[%s:%d] Sender: %d, xact_id: %d",
		__func__, __LINE__, sender_id, xact_id);

	HASH_FIND_INT(ht_cd_xact_rec_list, &xact_id, xact_rec);
	if (unlikely(!xact_rec)) {
		DSNVM_WARN("Sender: %d, xact_id: %d no record",
			sender_id, xact_id);
		reply->status = DSNVM_REPLY_BUG;
		goto out;
	}

	if (unlikely(xact_rec->sender_id != sender_id)) {
		DSNVM_WARN("%d %d", xact_rec->sender_id, sender_id);
		reply->status = DSNVM_REPLY_BUG;
		goto out;
	}

	areas = xact_rec->areas;
	nr_areas = xact_rec->nr_areas;
	for (i = 0; i < nr_areas; i++) {
		unsigned long dr_no = areas[i].dr_no;
		unsigned int dro = areas[i].dro;
		struct cd_on_region_info *region;
		int hash_key;

		hash_key = (int)dr_no;
		HASH_FIND_INT(ht_cd_on_region_list, &hash_key, region);
		if (unlikely(!region)) {
			DSNVM_BUG("non-exist dr_no: %lu, dro: %d, sender: %d, xact_id: %d",
				dr_no, dro, sender_id, xact_id);

			reply->status = DSNVM_REPLY_BUG;
			continue;
		}

		/* Now clear the inxact bit */
		pthread_spin_lock(&region->lock);
		if (unlikely(!test_and_clear_bit(dro, region->in_xact_bitmap))) {
			pthread_spin_unlock(&region->lock);
			DSNVM_BUG("dr_no: %lu, dro: %d, sender: %d, xact_id: %d. Page was not inxact",
				dr_no, dro, sender_id, xact_id);

			reply->status = DSNVM_REPLY_BUG;
			continue;
		}
		pthread_spin_unlock(&region->lock);
	}

	pthread_spin_lock(&ht_cd_xact_rec_list_lock);
	HASH_DEL(ht_cd_xact_rec_list, xact_rec);
	pthread_spin_unlock(&ht_cd_xact_rec_list_lock);

	free(xact_rec->areas);
	free(xact_rec);

	dsnvm_printk_xact("[%s:%d] Sender: %d, xact_id: %d finished, rec freed",
		__func__, __LINE__, sender_id, xact_id);

out:
	free(send_msg);
}
#endif

static void handle_bad_request(struct dsnvm_request *request,
			       struct dsnvm_reply *reply,
			       unsigned int *reply_len, int sender_id)
{
	fprintf(stderr, "Bad Rquest from node %d, OP: %d\n",
		sender_id, request->op);
	reply->status = DSNVM_INVALID_OP;
	*reply_len = sizeof(unsigned int);
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
		handle_machine_join(input, input_len, output, output_len, sender_id);
		break;
	case DSNVM_OP_SEND_MACHINE_LEAVE:
		handle_machine_leave(input, input_len, output, output_len, sender_id);
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

	pthread_spin_init(&ht_cd_on_region_list_lock, PTHREAD_PROCESS_PRIVATE);
	pthread_spin_init(&extend_lock, PTHREAD_PROCESS_PRIVATE);

#ifdef DSNVM_MODE_MRSW
	pthread_spin_init(&ht_cd_xact_rec_list_lock, PTHREAD_PROCESS_PRIVATE);
	dsnvm_printk("Transaction Model: MRSW");
#else
	dsnvm_printk("Transaction Model: MRMW");
#endif

	LAST_ASSIGNED_OWNER_NODE = 0;
	bitmap_clear(DSNVM_CLIENT_MACHINES, 0, DSNVM_MAX_NODE);

	ibapi_reg_send_handler(IB_SEND_handler);
	ibapi_reg_send_reply_handler(IB_SEND_REPLY_handler);
}
