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

/*
 * Only has two states:
 *	DSNVM_NORMAL
 *	DSNVM_IN_TRANSACTION
 *
 * Following cases means IN_TRANSACTION:
 *	DN that start begin/commit_xact
 *	ON that in the handlers of phase-1/2/3
 *
 * We update this only through helpers. And this can be used by
 * recovery code to determine the necessary reconstruct ops.
 */
static atomic_t dsnvm_state = ATOMIC_INIT(0);

void transaction_enter(void)
{
	atomic_add(1, &dsnvm_state);
}

void transaction_exit(void)
{
	atomic_sub(1, &dsnvm_state);
}

char *dsnvm_state_string(void)
{
	if (atomic_read(&dsnvm_state) > 0)
		return "In Transaction Context";
	else
		return "Normal Context";
}

static struct kmem_cache *dsnvm_reply_cachep;
static struct kmem_cache *dsnvm_status_reply_cachep;
static struct kmem_cache *max_reply_cachep;
static struct kmem_cache *dsnvm_status_and_data_reply_cachep;
static struct kmem_cache *dsnvm_request_cachep;
static struct kmem_cache *dsnvm_reply_page_fetch_cachep;

/*
 * Besides allocating the object, we also initialize
 * basic locks and other variables in case we forget
 * to do these stuff.
 */

struct dsnvm_request *alloc_dsnvm_request(void)
{
	return kmem_cache_zalloc(dsnvm_request_cachep, GFP_KERNEL);
}

struct dsnvm_reply *alloc_dsnvm_reply(void)
{
	return kmem_cache_zalloc(dsnvm_reply_cachep, GFP_KERNEL);
}

struct dsnvm_reply_page_fetch *alloc_dsnvm_reply_page_fetch(void)
{
	return kmem_cache_zalloc(dsnvm_reply_page_fetch_cachep, GFP_KERNEL);
}

struct status_reply_msg *alloc_dsnvm_status_reply(void)
{
	return kmem_cache_zalloc(dsnvm_status_reply_cachep, GFP_KERNEL);
}

struct max_reply_msg *alloc_max_reply(void)
{
	return kmem_cache_zalloc(max_reply_cachep, GFP_KERNEL);
}

struct status_and_data_reply_msg *alloc_dsnvm_status_and_data_reply(void)
{
	return kmem_cache_zalloc(dsnvm_status_and_data_reply_cachep, GFP_KERNEL);
}

void free_dsnvm_request(struct dsnvm_request *r)
{
	if (!r)
		return;
	kmem_cache_free(dsnvm_request_cachep, r);
}

void free_dsnvm_reply(struct dsnvm_reply *r)
{
	if (!r)
		return;
	kmem_cache_free(dsnvm_reply_cachep, r);
}

void free_dsnvm_reply_page_fetch(struct dsnvm_reply_page_fetch *r)
{
	if (!r)
		return;
	kmem_cache_free(dsnvm_reply_page_fetch_cachep, r);
}

void free_dsnvm_status_reply(struct status_reply_msg *r)
{
	if (!r)
		return;
	kmem_cache_free(dsnvm_status_reply_cachep, r);
}

void free_max_reply(struct max_reply_msg *r)
{
	if (!r)
		return;
	kmem_cache_free(max_reply_cachep, r);
}

void free_dsnvm_status_and_data_reply(struct status_and_data_reply_msg *r)
{
	if (!r)
		return;
	kmem_cache_free(dsnvm_status_and_data_reply_cachep, r);
}

static int init_max_reply_cache(void)
{
	max_reply_cachep = kmem_cache_create("max_reply_cache",
				sizeof(struct max_reply_msg), 0,
			    (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD),
			    NULL);
	if (!max_reply_cachep)
		return -ENOMEM;
	return 0;
}

static int init_dsnvm_reply_cache(void)
{
	dsnvm_reply_cachep = kmem_cache_create("dsnvm_reply_cache",
			     DSNVM_MAX_REPLY_LEN, 0,
			     (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD),
			     NULL);

	if (!dsnvm_reply_cachep)
		return -ENOMEM;

	return 0;
}

static int init_dsnvm_reply_page_fetch_cache(void)
{
	dsnvm_reply_page_fetch_cachep = kmem_cache_create("dsnvm_reply_page_fetch_cache",
					sizeof(struct dsnvm_reply_page_fetch), 0,
					(SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD),
					NULL);

	if (!dsnvm_reply_page_fetch_cachep)
		return -ENOMEM;

	return 0;
}

static int init_dsnvm_status_reply_cache(void)
{
	dsnvm_status_reply_cachep = kmem_cache_create("dsnvm_status_reply_cache",
			     sizeof(struct status_reply_msg), 0,
			     (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD),
			     NULL);

	if (!dsnvm_status_reply_cachep)
		return -ENOMEM;

	return 0;
}

static int init_dsnvm_status_and_data_reply_cache(void)
{
	dsnvm_status_and_data_reply_cachep =
		kmem_cache_create("dsnvm_status_and_data_reply_cache",
				  sizeof(struct status_and_data_reply_msg), 0,
				  (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD),
				  NULL);

	if (!dsnvm_status_and_data_reply_cachep)
		return -ENOMEM;

	return 0;
}

static int init_dsnvm_request_cache(void)
{
	dsnvm_request_cachep = kmem_cache_create("dsnvm_request_cache",
			       sizeof(struct dsnvm_request), 0,
			       (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD),
			       NULL);

	if (!dsnvm_request_cachep)
		return -ENOMEM;

	return 0;
}

static void destroy_dsnvm_request_cache(void)
{
	if (!dsnvm_request_cachep)
		return;
	kmem_cache_destroy(dsnvm_request_cachep);
	dsnvm_request_cachep = NULL;
}

static void destroy_dsnvm_reply_cache(void)
{
	if (!dsnvm_reply_cachep)
		return;
	kmem_cache_destroy(dsnvm_reply_cachep);
	dsnvm_reply_cachep = NULL;
}

static void destroy_dsnvm_reply_page_fetch_cache(void)
{
	if (!dsnvm_reply_page_fetch_cachep)
		return;
	kmem_cache_destroy(dsnvm_reply_page_fetch_cachep);
	dsnvm_reply_page_fetch_cachep = NULL;
}

static void destroy_dsnvm_status_reply_cache(void)
{
	if (!dsnvm_status_reply_cachep)
		return;
	kmem_cache_destroy(dsnvm_status_reply_cachep);
	dsnvm_status_reply_cachep = NULL;
}

static void destroy_dsnvm_status_and_data_reply_cache(void)
{
	if (!dsnvm_status_and_data_reply_cachep)
		return;
	kmem_cache_destroy(dsnvm_status_and_data_reply_cachep);
	dsnvm_status_and_data_reply_cachep = NULL;
}

/*
 * DSNVM client is only available after dsnvm filesystem is mounted.
 * Hence as a client machine, it will send CD machine_join at mounting
 * time and send CD machine_leave at unmounting time.
 *
 * DSNVM server will _not_ send any requests to this machine any more
 * after a successful leaving, even if IB layer is still connected.
 */

static DEFINE_SPINLOCK(machine_bitmap_lock);
DECLARE_BITMAP(DSNVM_CLIENT_MACHINES, DSNVM_MAX_NODE);
atomic_t nr_client_machines;

void dsnvm_send_machine_join(void)
{
	int bit;
	struct dsnvm_request_machine_join request;
	struct dsnvm_reply_machine_join reply;

	request.op = DSNVM_OP_SEND_MACHINE_JOIN;
	request.dr_page_nr_shift = DR_PAGE_NR_SHIFT;
	request.dsnvm_max_regions_shift = DSNVM_MAX_REGIONS_SHIFT;
	request.xact_mode = XACT_MODE;

	/* CD only */
	ibapi_send_reply(0, (char *)&request, sizeof(request), (char *)&reply);

	if (unlikely(reply.status != DSNVM_REPLY_SUCCESS)) {
		DSNVM_BUG("ERROR: fail to join server because %s",
			dsnvm_status_string(reply.status));
		return;
	}

	atomic_set(&nr_client_machines, 0);
	bitmap_clear(DSNVM_CLIENT_MACHINES, 0, DSNVM_MAX_NODE);

	spin_lock(&machine_bitmap_lock);
	bitmap_copy(DSNVM_CLIENT_MACHINES, reply.DSNVM_CLIENT_MACHINES, DSNVM_MAX_NODE);
	for_each_set_bit(bit, DSNVM_CLIENT_MACHINES, DSNVM_MAX_NODE) {
		atomic_inc(&nr_client_machines);
	}
	spin_unlock(&machine_bitmap_lock);

#ifdef DSNVM_MODE_MRSW_IN_KERNEL
	if (DSNVM_LOCAL_ID == DSNVM_MRSW_MASTER_NODE &&
	    atomic_read(&nr_client_machines) != 0)
		DSNVM_BUG();
#endif

	DSNVM_PRINTK("DSNVM client machine joined server successfully");
}

void dsnvm_send_machine_leave(void)
{
	int out, in;

	out = DSNVM_OP_SEND_MACHINE_LEAVE;
	ibapi_send_reply(0, (char *)&out, 4, (char *)&in);
	if (in != DSNVM_REPLY_SUCCESS)
		DSNVM_BUG();
	DSNVM_PRINTK("DSNVM client machine leaved server successfully");
}

static void handle_receive_machine_join(char *input_addr, char *_reply,
					unsigned int *reply_len, int sender_id)
{
	struct dsnvm_request_machine_event *request;
	struct dsnvm_reply_machine_event *reply;

	request = (struct dsnvm_request_machine_event *)input_addr;
	reply = (struct dsnvm_reply_machine_event *)_reply;
	*reply_len = sizeof(*reply);

	if (unlikely(sender_id != 0)) {
		DSNVM_BUG();
		reply->status = DSNVM_EPERM;
		return;
	}

	DSNVM_PRINTK("Receive [machine join] from CD for node %u", request->node_id);

	spin_lock(&machine_bitmap_lock);
	if (unlikely(test_and_set_bit(request->node_id, DSNVM_CLIENT_MACHINES)))
		DSNVM_WARN("node %u join more than once", request->node_id);
	atomic_inc(&nr_client_machines);
	spin_unlock(&machine_bitmap_lock);

	reply->status = DSNVM_REPLY_SUCCESS;
}

static void handle_receive_machine_leave(char *input_addr, char *_reply,
					 unsigned int *reply_len, int sender_id)
{
	struct dsnvm_request_machine_event *request;
	struct dsnvm_reply_machine_event *reply;

	request = (struct dsnvm_request_machine_event *)input_addr;
	reply = (struct dsnvm_reply_machine_event *)_reply;
	*reply_len = sizeof(*reply);

	if (unlikely(sender_id != 0)) {
		DSNVM_BUG();
		reply->status = DSNVM_EPERM;
		return;
	}

	pr_crit("Receive [machine leave] from CD for node %u", request->node_id);

	spin_lock(&machine_bitmap_lock);
	if (unlikely(!test_and_clear_bit(request->node_id, DSNVM_CLIENT_MACHINES)))
		DSNVM_WARN();
	atomic_dec(&nr_client_machines);
	spin_unlock(&machine_bitmap_lock);

	reply->status = DSNVM_REPLY_SUCCESS;
}

static void handle_bad_send_reply(struct dsnvm_reply *reply,
				  unsigned int *reply_len, int sender_id)
{
	DSNVM_WARN("Unknown request from Node: %d", sender_id);
	reply->status = DSNVM_INVALID_OP;
	*reply_len = sizeof(unsigned int);
}

atomic_t BARRIER_COUNTER;

static void dist_sync_barrier_notify_other_nodes(void)
{
	int request, reply;
	int i, bit;
	int nr_nodes = 0;
	int nodes[DSNVM_MAX_NODE];
 
	request = DSNVM_OP_SYNC_BARRIER;

	spin_lock(&machine_bitmap_lock);
	for_each_set_bit(bit, DSNVM_CLIENT_MACHINES, DSNVM_MAX_NODE) {
		if (unlikely(bit == DSNVM_LOCAL_ID))
			continue;
		nodes[nr_nodes++] = bit;
	}
	spin_unlock(&machine_bitmap_lock);

	DSNVM_PRINTK_BARRIER("Send barrier notify to total %d nodes", nr_nodes);

	for (i = 0; i < nr_nodes; i++) {
		ibapi_send_reply(nodes[i], (char *)&request, sizeof(request),
			(char *)&reply);

		if (reply == DSNVM_REPLY_SUCCESS) {
			DSNVM_PRINTK_BARRIER("node %d succeed", nodes[i]);
		} else {
			DSNVM_WARN();
			DSNVM_PRINTK_BARRIER("node %d failed", nodes[i]);
		}
	}
}

unsigned int BARRIER_TIME_LIMIT =3600;

/*
 * The SYSCALL entry:
 */
static void dist_sync_barrier(void)
{
	unsigned long round = 0;
	int num_node;
	struct timespec start, now, diff;

	dist_sync_barrier_notify_other_nodes();

	atomic_inc(&BARRIER_COUNTER);

	DSNVM_PRINTK_BARRIER("Entering with barrier counter: %d",
		atomic_read(&BARRIER_COUNTER));

	getnstimeofday(&start);
	while (unlikely(atomic_read(&BARRIER_COUNTER) <
			atomic_read(&nr_client_machines))) {
		round++;

		getnstimeofday(&now);
		diff = timespec_sub(now, start);

		if (diff.tv_sec > BARRIER_TIME_LIMIT) {
			pr_warning("Barrier blocked more than %d secs, break\n",
				BARRIER_TIME_LIMIT);
			goto out;
		}
	}

out:
	DSNVM_PRINTK_BARRIER("Barrier unblocked (%lu rounds)", round);

	//atomic_set(&BARRIER_COUNTER, 1);
	num_node = atomic_read(&nr_client_machines);
	atomic_sub(num_node, &BARRIER_COUNTER);

	return;
}

static int dist_sync_barrier_handler(char *msg, char *reply_addr,
				     unsigned int *reply_len, int sender_id)
{

	int *reply;

//	if (unlikely(atomic_read(&BARRIER_COUNTER) ==
//			atomic_read(&nr_client_machines))) {
//		DSNVM_BUG("barrier counter %d greather than num machines %d sender_id %d\n",
//				atomic_read(&BARRIER_COUNTER), atomic_read(&nr_client_machines), sender_id);
		//DSNVM_WARN();
//		cpu_relax();
//	}

	reply = (int *)reply_addr;
	*reply = DSNVM_REPLY_SUCCESS;
	*reply_len = sizeof(int);

	DSNVM_PRINTK_BARRIER("Receive barrier notify from node: %d, barrier_counter: %d",
		sender_id, atomic_read(&BARRIER_COUNTER));

	atomic_inc(&BARRIER_COUNTER);

	return 0;
}

static atomic_t nr_proposals = ATOMIC_INIT(0);
static DEFINE_SPINLOCK(proposed_mmap_addr_lock);
static unsigned long proposed_mmap_addr[DSNVM_MAX_NODE];

struct mmap_consensus_notify {
	int		op;
	unsigned long	brk;
};

/* Send brk to all online nodes */
static void mmap_consensus_notify_other_nodes(unsigned long brk)
{
	struct mmap_consensus_notify request;
	int reply, i, bit, nr_nodes = 0;
	int nodes[DSNVM_MAX_NODE];

	request.op = DSNVM_OP_MMAP_CONSENSUS;
	request.brk = brk;

	spin_lock(&machine_bitmap_lock);
	for_each_set_bit(bit, DSNVM_CLIENT_MACHINES, DSNVM_MAX_NODE) {
		if (unlikely(bit == DSNVM_LOCAL_ID))
			continue;
		nodes[nr_nodes++] = bit;
	}
	spin_unlock(&machine_bitmap_lock);

	DSNVM_PRINTK("Sending brk: %#lx to total %d nodes", brk, nr_nodes);

	for (i = 0; i < nr_nodes; i++) {
		ibapi_send_reply(nodes[i], (char *)&request, sizeof(request),
			(char *)&reply);

		if (likely(reply == DSNVM_REPLY_SUCCESS)) {
			DSNVM_PRINTK("Node %d succeed", nodes[i]);
		} else {
			DSNVM_WARN();
			DSNVM_PRINTK("Node %d failed", nodes[i]);
		}
	}
}

/*
 * Handle a incomg mmap_consensus request
 * Record its proposed address and increment the barrier counter.
 */
static int mmap_consensus_handler(char *msg, char *reply_addr,
				  unsigned int *reply_len, int sender_id)
{
	int *reply;
	unsigned long brk;
	struct mmap_consensus_notify *request;

	reply = (int *)reply_addr;
	*reply = DSNVM_REPLY_SUCCESS;
	*reply_len = sizeof(int);

	request = (struct mmap_consensus_notify *)msg;
	brk = request->brk;

	DSNVM_PRINTK("Receive mmap proposal: %#lx, from node %d", brk, sender_id);

	/* Why twice */
	spin_lock(&proposed_mmap_addr_lock);
	if (unlikely(proposed_mmap_addr[sender_id] != 0)) {
		pr_info("sender_id: %d, old_mmap_addr: %#lx, new_mmap_addr: %#lx",
			sender_id, proposed_mmap_addr[sender_id], brk);
	}

	proposed_mmap_addr[sender_id] = brk;
	spin_unlock(&proposed_mmap_addr_lock);

	atomic_inc(&nr_proposals);

	return 0;
}

static void do_mmap_consensus(unsigned long *addr, unsigned long len)
{
	int nid, max_node = 0;
	unsigned long ret, max_brk = 0;

	spin_lock(&proposed_mmap_addr_lock);
	for (nid = 0; nid < DSNVM_MAX_NODE; nid++) {
		if (proposed_mmap_addr[nid] > max_brk) {
			max_brk = proposed_mmap_addr[nid];
			max_node = nid;
		}
	}
	spin_unlock(&proposed_mmap_addr_lock);

	if (unlikely(!max_node || !max_brk))
		DSNVM_BUG();

	DSNVM_PRINTK("Winner is node: %d, brk: %#lx", max_node, max_brk);

	/*
	 * This is the fixed mmap starting address
	 * For all online clients that called mmap():
	 */
	*addr = max_brk;

	ret = dsnvm_brk(max_brk + len);

	DSNVM_PRINTK("Try to adjust to %#lx, new brk is %#lx", max_brk + len, ret);
}

static void mmap_consensus(struct file *file, unsigned long *addr, unsigned long len)
{
	struct mm_struct *mm = current->mm;

	if (!file || !addr)
		return;

	if (!file->private_data) {
		pr_info("WARNING: No DSNVM file attached");
		return;
	}

	/* Count myself as a proposal */
	spin_lock(&proposed_mmap_addr_lock);
	proposed_mmap_addr[DSNVM_LOCAL_ID] = mm->brk;
	spin_unlock(&proposed_mmap_addr_lock);
	atomic_inc(&nr_proposals);

	/* Notify and wait... */
	mmap_consensus_notify_other_nodes(mm->brk);
	while (atomic_read(&nr_proposals) !=
	       atomic_read(&nr_client_machines)) {
		cpu_relax();
	}

	do_mmap_consensus(addr, len);

	/* Clean up for next round */
	atomic_set(&nr_proposals, 0);
	memset(proposed_mmap_addr, 0, sizeof(proposed_mmap_addr));
}

/*
 * SYSCALL hooks
 * Only valid while dsnvm-net and dsnvm are installed.
 */
static const struct dist_hooks hooks = {
	.dist_lock_hook = (int (*)(void *))ibapi_lock,
	.dist_unlock_hook = (int (*)(void *))ibapi_unlock,
	.dist_create_lock_hook = (int (*)(unsigned int, void *, unsigned int, void *))ibapi_create_lock,
	.dist_sync_barrier_hook = dist_sync_barrier,

	.dist_mmap_consensus_hook = mmap_consensus,
};

static int init_dist_locks(void)
{
	atomic_set(&BARRIER_COUNTER, 0);
	return register_dist_lock_hooks(&hooks);
}

static void destroy_dist_locks(void)
{
	unregister_dist_lock_hooks();
}

static int IB_SEND_handler(char *input_addr, unsigned int req_len, int sender_id)
{
	struct dsnvm_request *request = (struct dsnvm_request *)input_addr;

	if (!request) { // no such req now || req_len < sizeof(struct dsnvm_request)) {
		/* Keep remote waiting? */
		DSNVM_BUG();
		return -EINVAL;
	}

	count_dsnvm_event(DSNVM_IB_SEND_REQ);
	count_dsnvm_event(DSNVM_IB_REQUESTS);
	count_dsnvm_events(DSNVM_IB_BYTES, (long)req_len);

	log_msg_bytes(req_len);

	switch(request->op) {
	case DSNVM_OP_NOTIFY_PROMOTED_NEW_ON:
		return dsnvm_handle_notify_all_promotion(input_addr, req_len, sender_id);
	default:
		DSNVM_BUG();
		return -EINVAL;
	}
	return -EINVAL;
}

static int IB_SEND_REPLY_OPT_handler(char *input_addr, unsigned int input_size,
				 unsigned long *reply, unsigned int *reply_len,
				 int sender_id)
{
	struct dsnvm_request *request = (struct dsnvm_request *)input_addr;

	switch(request->op) {
	case DSNVM_OP_FETCH_PAGE:
		/*
		 * DN asks for a page of data (non-coherent)
		 */
		handle_page_fetch(input_addr, reply, reply_len, sender_id, false);
		break;
	case DSNVM_OP_FETCH_PAGE_COHERENT:
		/*
		 * DN asks for a page of data, and mark it as coherent
		 */
		handle_page_fetch(input_addr, reply, reply_len, sender_id, true);
		break;
	default:
		*reply_len = sizeof(int);
		*reply = DSNVM_INVALID_OP;
		DSNVM_BUG("Invalid OP: %d", request->op);
		break;
	}

	count_dsnvm_event(DSNVM_IB_SEND_REPLY_OPT_REQ);
	count_dsnvm_event(DSNVM_IB_REQUESTS);
	count_dsnvm_events(DSNVM_IB_BYTES, input_size);
	count_dsnvm_events(DSNVM_IB_BYTES, *reply_len);

	log_msg_bytes(input_size + *reply_len);

	return 0;
}

static void handle_test(struct dsnvm_reply *reply,
			unsigned int *reply_len, int sender_id)
{
	pr_info("handle_test\n");
	reply->status = DSNVM_REPLY_SUCCESS;
	*reply_len = sizeof(unsigned int);
}

static int IB_SEND_REPLY_handler(char *input_addr, unsigned int input_size,
				 char *reply, unsigned int *reply_len,
				 int sender_id)
{
	struct dsnvm_request *request = (struct dsnvm_request *)input_addr;

	switch(request->op) {
	case DSNVM_OP_CREAT_REGION_AT_ON:
		/*
		 * CD asks to create a new region
		 */
		handle_create_region_at_on(request, reply, reply_len, sender_id);
		break;
	case DSNVM_OP_REMOVE_REGION_AT_ON:
		/*
		 * CD asks to remove a old region
		 */
		handle_remove_region_at_on(request, reply, reply_len, sender_id);
		break;
	case DSNVM_OP_FREE_REPLICA_PAGE:
		/*
		 * DN asks for a page of data, and mark it as coherent
		 */
		dsnvm_handle_free_replica_page(input_addr, reply, reply_len, sender_id);
		break;
	case DSNVM_OP_COMMIT_XACT:
		dsnvm_handle_commit_xact(input_addr, reply, reply_len, sender_id);
		break;
	case DSNVM_OP_ACK_COMMIT_XACT:
		dsnvm_handle_ack_commit_xact(input_addr, reply, reply_len, sender_id, false);
		break;
	case DSNVM_OP_ACK_COMMIT_XACT_REVERT:
		dsnvm_handle_ack_commit_xact(input_addr, reply, reply_len, sender_id, true);
		break;
	case DSNVM_OP_RECEIVE_MACHINE_JOIN:
		/*
		 * CD tells me a new machine added
		 */
		handle_receive_machine_join(input_addr, reply, reply_len, sender_id);
		break;
	case DSNVM_OP_RECEIVE_MACHINE_LEAVE:
		/*
		 * CD tells me an old machined leaved
		 */
		handle_receive_machine_leave(input_addr, reply, reply_len, sender_id);
		break;
	case DSNVM_OP_SYNC_BARRIER:
		dist_sync_barrier_handler(input_addr, reply, reply_len, sender_id);
		break;
	case DSNVM_OP_MMAP_CONSENSUS:
		mmap_consensus_handler(input_addr, reply, reply_len, sender_id);
		break;
	case DSNVM_OP_FETCH_COMMITTED_DN_PAGE:
		dsnvm_handle_fetch_commited_dn_page(input_addr, reply, reply_len, sender_id);
		break;
	case DSNVM_OP_MIGRATE_ON_CHUNK_NOTIFY:
		handle_migrate_on_chunk_finished_notify(input_addr, reply, reply_len, sender_id);
		break;
	case DSNVM_OP_TEST:
		handle_test((struct dsnvm_reply *)reply, reply_len, sender_id);
		break;
	case DSNVM_OP_MRSW_BEGIN_XACT:
		handle_mrsw_begin(input_addr, input_size, reply, reply_len, sender_id);
		break;
	case DSNVM_OP_MRSW_COMMIT_XACT:
		handle_mrsw_commit(input_addr, input_size, reply, reply_len, sender_id);
		break;
	default:
		handle_bad_send_reply((struct dsnvm_reply *)reply, reply_len, sender_id);
		break;
	}

	count_dsnvm_event(DSNVM_IB_SEND_REPLY_REQ);
	count_dsnvm_event(DSNVM_IB_REQUESTS);
	count_dsnvm_events(DSNVM_IB_BYTES, input_size);
	count_dsnvm_events(DSNVM_IB_BYTES, *reply_len);

	log_msg_bytes(input_size + *reply_len);

	return 0;
}

static __always_inline size_t
count_atomic_send_bytes(struct atomic_struct *reqs, unsigned int nr_reqs)
{
	unsigned int i;
	size_t len;

	for (i = 0, len = 0; i < nr_reqs; i++) {
		if (reqs[i].len > DSNVM_PAGE_SIZE) {
			count_dsnvm_event(DSNVM_IB_FALSE_REQUEST_LEN);
			continue;
		}
		len += reqs[i].len;
	}

	return len;
}

static int IB_ATOMIC_SEND_handler(struct atomic_struct *reqs, uint32_t nr_reqs, 
		char *output_buf, unsigned int *output_size, int sender_id)
{
	int request_type;
	char *req_msg;
	size_t input_len = 0;

	if (unlikely(!nr_reqs)) {
		DSNVM_BUG("nr_reqs = 0");
		return DSNVM_ERROR_RECV_MSG_FORMAT;
	}

	req_msg = (char *)reqs[0].vaddr;
	memcpy(&request_type, req_msg, sizeof(int));

	switch (request_type) {
	case DSNVM_OP_REQUEST_COMMIT_XACT:
		dsnvm_handle_request_commit_xact(sender_id, nr_reqs, reqs, output_buf, output_size);
		break;
	case DSNVM_OP_COMMIT_XACT_SINGLE_ON:
		dsnvm_handle_commit_xact_single_on(sender_id, nr_reqs, reqs, output_buf, output_size);
		break;
	case DSNVM_OP_SEND_COHERENCE_XACT:
		dsnvm_handle_receive_coherence(sender_id, nr_reqs, reqs, output_buf, output_size);
		break;
	case DSNVM_OP_SEND_REPLICA_XACT:
		dsnvm_handle_receive_replica(sender_id, nr_reqs, reqs, output_buf, output_size);
		break;
	case DSNVM_OP_MIGRATE_ON_CHUNK:
		handle_migrate_on_chunk(sender_id, nr_reqs, reqs, output_buf, output_size, false);
		break;
	case DSNVM_OP_MIGRATE_ON_CHUNK_NO_PAGE:
		handle_migrate_on_chunk(sender_id, nr_reqs, reqs, output_buf, output_size, true);
		break;
	default:
		DSNVM_BUG("[%s:%d] [pid %u] unknown request type %d",
			__func__, __LINE__, current->pid, request_type);
		*(int *)output_buf = DSNVM_ERROR_RECV_MSG_FORMAT;
		*output_size = sizeof(int);
		break;
	}

	count_dsnvm_event(DSNVM_IB_ATOMIC_SEND_REQ);
	count_dsnvm_event(DSNVM_IB_REQUESTS);
	count_dsnvm_events(DSNVM_IB_BYTES, *output_size);

	input_len = count_atomic_send_bytes(reqs, nr_reqs);
	count_dsnvm_events(DSNVM_IB_BYTES, input_len);

	log_msg_bytes(*output_size + input_len);

	return 0;
}

int init_dsnvm_client_cache(void)
{
	int ret = 0;

	/* SYSCALL */
	ret = init_dist_locks();
	if (ret) {
		pr_err("error: Unable to register dist-hooks");
		return ret;
	}

	/* kmemcaches */

	ret = init_dsnvm_request_cache();
	if (ret) {
		pr_err("error: fail to create dsnvm request cache");
		return ret;
	}

	ret = init_dsnvm_reply_cache();
	if (ret) {
		pr_err("error: fail to create dsnvm reply cache");
		return ret;
	}

	ret = init_max_reply_cache();
	if (ret) {
		pr_err("error: fail to create max_reply cache");
		return ret;
	}

	ret = init_dsnvm_status_reply_cache();
	if (ret) {
		pr_err("error: fail to create status_reply cache");
		return ret;
	}

	ret = init_dsnvm_status_and_data_reply_cache();
	if (ret) {
		pr_err("error: fail to create status_and_data_reply cache");
		return ret;
	}

	ret = init_dsnvm_reply_page_fetch_cache();
	if (ret) {
		pr_err("error: fail to create dsnvm_reply_page_fetch cache");
		return ret;
	}

	return 0;
}

void destroy_dsnvm_client_cache(void)
{
	destroy_dsnvm_reply_cache();
	destroy_dsnvm_reply_page_fetch_cache();
	destroy_dsnvm_status_reply_cache();
	destroy_dsnvm_status_and_data_reply_cache();
	destroy_dsnvm_request_cache();

	/* SYSCALL */
	destroy_dist_locks();
}

unsigned int DSNVM_LOCAL_ID = 0;

/* Setup all IB stuff used by dsnvm client here */
int dsnvm_client_init_ib(char *servername, int ibport,
			 unsigned long total_size)
{
	int nodeid;

	nodeid = ibapi_establish_conn(servername, ibport, total_size);
	if (nodeid <= 0)
		return -EIO;

	if (nodeid > DSNVM_MAX_NODE) {
		pr_err("hmm..too many machines");
		return -EIO;
	}

	DSNVM_LOCAL_ID = (unsigned int)nodeid;

	ibapi_reg_send_handler(IB_SEND_handler);
	ibapi_reg_send_reply_handler(IB_SEND_REPLY_handler);
	ibapi_reg_send_reply_opt_handler(IB_SEND_REPLY_OPT_handler);
	ibapi_reg_atomic_send_handler(IB_ATOMIC_SEND_handler);

	return 0;
}
