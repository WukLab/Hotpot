/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * This file describes the customized RDMA-stack used by Hotpot.
 * Check LITE (SOSP'17) for more design details.
 *
 * This module need 2 parameters: server's IP and port number.
 * You can pass them during installation, for example:
 * 	insmod hotpot_net.ko ip=192.168.1.1 port=18500
 */

#define pr_fmt(fmt) "hotpot-net: " fmt

#include "net.h"
#include <rdma/ib_verbs.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_user_verbs.h>
#include <linux/bug.h>
#include <linux/kernel.h>

#define DEBUG_SHINYEH
//This is the version modified from 000be840c215d5da3011a2c7b486d5ae122540c4
//It adds LOCKS, sge, and other things  into the system
//Client.h is also modified.
//Server is also modified to match this patch
//Patch SERIAL_VERSION_ID: 04202300
//Please make sure that this version is not fully tested inside dsnvm (interactions are not fully tested)

atomic_t global_reqid;
//#define DEBUG_IBV

//spinlock_t send_req_lock[TOTAL_CONNECTIONS];

#ifdef TEST_PRINTK
#define test_printk(x...)	pr_crit(x)
#else
#define test_printk(x...)	do {} while (0)
#endif

///////////////////////////////////////////
//Client.c global parameter
///////////////////////////////////////////

int num_parallel_connection = NUM_PARALLEL_CONNECTION;

#define SRCADDR INADDR_ANY
#define DSTADDR ((unsigned long int)0xc0a87b01) /* 192.168.123.1 */


static const int        RDMA_BUFFER_SIZE = 4096;
static const int	RDMA_PAGE_SIZE = 4096;
const int SEND_REPLY_WAIT = -1;
const int SEND_REPLY_EMPTY = -2;
static int              page_size;
struct pingpong_context *ctx;
int                     *routs;
int                     rcnt, scnt;
enum ib_mtu mtu;
int                     sl;
int                     curr_node;
int                     ib_port = 1;
int                     NODE_ID = -1;

struct client_data full_connect_data[MAX_CONNECTION];
struct client_data my_QPset[MAX_CONNECTION];
static struct task_struct *thread_poll_cq, *thread_handler;

#define HASH_TABLE_SIZE_BIT 10
DEFINE_HASHTABLE(MR_HASHTABLE, HASH_TABLE_SIZE_BIT);
spinlock_t MR_HASHTABLE_LOCK[1<<HASH_TABLE_SIZE_BIT];


enum ib_mtu client_mtu_to_enum(int mtu)
{
	switch (mtu) {
	case 256:  return IB_MTU_256;
	case 512:  return IB_MTU_512;
	case 1024: return IB_MTU_1024;
	case 2048: return IB_MTU_2048;
	case 4096: return IB_MTU_4096;
	default:   return -1;
	}
}

//
//
//



static void poll_cq(struct ib_cq *cq, void *cq_context);

//static struct ib_device *ibv_add_port(struct pingpong_context *device, u8 port);
static void ibv_add_one(struct ib_device *device);
static void ibv_release_dev(struct device *dev);
static void ibv_remove_one(struct ib_device *device);
inline int client_get_connection_by_atomic_number(int target_node, int priority);



static struct ib_client ibv_client = {
	.name   = "ibv_server",
	.add    = ibv_add_one,
	.remove = ibv_remove_one
};

static struct class ibv_class = {
	.name    = "infiniband_ibvs",
	.dev_release = ibv_release_dev
};

struct ib_device *ib_dev;
struct ib_pd *ctx_pd;
//struct pingpong_context **ctx;

static void poll_cq(struct ib_cq *cq, void *cq_context)
{
  struct ib_wc wc;
  int ret;
  while (1) {
    ret = ib_req_notify_cq(cq, 0);
	printk(KERN_ALERT "ib_req_notify_cq returned %d\n", ret);
    while (ib_poll_cq(cq, 1, &wc)){
     // on_completion(&wc);
      //schedule();
    }
  }

}

static void ibv_add_one(struct ib_device *device)
{
	//ctx = (struct pingpong_context **)kmalloc(TOTAL_CONNECTIONS*sizeof(struct pingpong_context *), GFP_KERNEL);
        ctx = (struct pingpong_context *)kmalloc(sizeof(struct pingpong_context), GFP_KERNEL);
	ib_dev = device;
	ctx_pd = ib_alloc_pd(device);
	if (!ctx_pd) {
		printk(KERN_ALERT "Couldn't allocate PD\n");
	}

	return;
}

static void ibv_remove_one(struct ib_device *device)
{
	return;
}

static void ibv_release_dev(struct device *dev)
{
	
}
static struct pingpong_context *client_init_ctx(int size, int rx_depth, int port, unsigned long total_size)
{
	int i;
	int num_connections = MAX_CONNECTION;
	ctx = (struct pingpong_context*)kmalloc(sizeof(struct pingpong_context), GFP_KERNEL);
	memset(ctx, 0, sizeof(struct pingpong_context));
	if(!ctx)
	{
		test_printk(KERN_ALERT "FAIL to initialize ctx in client_init_ctx\n");
		return NULL;
	}
	ctx->size = size;
	ctx->send_flags = IB_SEND_SIGNALED;
	ctx->rx_depth = rx_depth;
	ctx->num_connections = num_connections;
	ctx->num_node = MAX_NODE;
	ctx->num_parallel_connection = NUM_PARALLEL_CONNECTION;
	

	ctx->context = (struct ib_context *)ib_dev;
	if(!ctx->context)
	{
		test_printk(KERN_ALERT "Fail to initialize device / ctx->context\n");
		return NULL;
	}
	ctx->channel = NULL;
	ctx->pd = ib_alloc_pd(ib_dev);
	if(!ctx->pd)
	{
		test_printk(KERN_ALERT "Fail to initialize pd / ctx->pd\n");
		return NULL;
	}
	ctx->proc = ib_get_dma_mr(ctx->pd, IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ);
	ctx->send_state = (enum s_state *)kmalloc(num_connections * sizeof(enum s_state), GFP_KERNEL);	
	ctx->recv_state = (enum r_state *)kmalloc(num_connections * sizeof(enum r_state), GFP_KERNEL);
	
	//Customized part
	ctx->num_alive_connection = (atomic_t *)kmalloc(ctx->num_node*sizeof(atomic_t), GFP_KERNEL);
	memset(ctx->num_alive_connection, 0, ctx->num_node*sizeof(atomic_t));
	for(i=0;i<ctx->num_node;i++)
		atomic_set(&ctx->num_alive_connection[i], 0);

	ctx->recv_num = (int *)kmalloc(ctx->num_connections*sizeof(int), GFP_KERNEL);
	memset(ctx->recv_num, 0, ctx->num_connections*sizeof(int));
	
	ctx->atomic_request_num = (atomic_t *)kmalloc(ctx->num_node*sizeof(atomic_t), GFP_KERNEL);
	memset(ctx->atomic_request_num, 0, ctx->num_node*sizeof(atomic_t));
	for(i=0;i<ctx->num_node;i++)
		atomic_set(&ctx->atomic_request_num[i], -1);
	ctx->atomic_request_num_high = (atomic_t *)kmalloc(ctx->num_node*sizeof(atomic_t), GFP_KERNEL);
	memset(ctx->atomic_request_num_high, 0, ctx->num_node*sizeof(atomic_t));
	for(i=0;i<ctx->num_node;i++)
		atomic_set(&ctx->atomic_request_num_high[i], -1);
	
	ctx->thread_state = (enum t_state *)kmalloc(MAX_PARALLEL_THREAD * sizeof(enum t_state), GFP_KERNEL);
	memset(ctx->thread_state, 0, MAX_PARALLEL_THREAD * sizeof(enum t_state));
	
	atomic_set(&ctx->parallel_thread_num,0);

	atomic_set(&ctx->alive_connection, 0);
	atomic_set(&ctx->num_completed_threads, 0);

	//Send_Reply
      	//ctx->send_reply_wait_inbox = (int *)kmalloc(MAX_PARALLEL_THREAD * sizeof(int), GFP_KERNEL);
	//for(i=0;i<MAX_PARALLEL_THREAD;i++)
	//	ctx->send_reply_wait_inbox[i]=SEND_REPLY_EMPTY;
	//atomic_set(&ctx->send_reply_wait_num,0);
	//ctx->send_reply_inbox = (char **)kmalloc(MAX_PARALLEL_THREAD * sizeof(char *), GFP_KERNEL);
	
	ctx->atomic_buffer = (struct atomic_struct **)kmalloc(num_connections * sizeof(struct atomic_struct *), GFP_KERNEL);
	ctx->atomic_buffer_total_length = (int *)kmalloc(num_connections * sizeof(int), GFP_KERNEL);
	for(i=0;i<num_connections;i++)
		ctx->atomic_buffer_total_length[i]=0;
	ctx->atomic_buffer_cur_length = (int *)kmalloc(num_connections * sizeof(int), GFP_KERNEL);
	for(i=0;i<num_connections;i++)
		ctx->atomic_buffer_cur_length[i]=-1;
	

	//MR protect
	ctx->mr_set = (struct client_ibv_mr *)kmalloc(MAX_PARALLEL_THREAD * sizeof(struct client_ibv_mr), GFP_KERNEL);
	atomic_set(&ctx->used_mr_num, 0);

	ctx->cq = ib_create_cq((struct ib_device *)ctx->context, poll_cq, NULL, NULL, rx_depth*4+1, 0);
	if(!ctx->cq)
	{
		test_printk(KERN_ALERT "Fail to create cq / ctx->cq\n");
		return NULL;
	}
	ctx->send_cq = (struct ib_cq **)kmalloc(num_connections * sizeof(struct ib_cq *), GFP_KERNEL);
	
	//congestion related things
	ctx->connection_congestion_status = (atomic_t *)kmalloc(num_connections * sizeof(atomic_t), GFP_KERNEL);
	for(i=0;i<num_connections;i++)
		atomic_set(&ctx->connection_congestion_status[i], CONGESTION_FREE);
	ctx->connection_timer_start = (ktime_t *)kmalloc(num_connections * sizeof(ktime_t), GFP_KERNEL);
	ctx->connection_timer_end = (ktime_t *)kmalloc(num_connections * sizeof(ktime_t), GFP_KERNEL);
	
	//atomic multicast send related things
	
	ctx->first_packet_header = kmalloc(sizeof(struct ibapi_header) * MAX_MULTICAST_HOP, GFP_KERNEL);
	ctx->other_packet_header = kmalloc(sizeof(struct ibapi_header) * MAX_MULTICAST_HOP * MAX_LENGTH_OF_ATOMIC, GFP_KERNEL);
	ctx->output_header_addr = kmalloc(sizeof(void *) * MAX_MULTICAST_HOP * MAX_LENGTH_OF_ATOMIC, GFP_KERNEL);
	ctx->mid_addr = kmalloc(sizeof(void *) * MAX_MULTICAST_HOP * MAX_LENGTH_OF_ATOMIC, GFP_KERNEL);
	ctx->first_header_addr = kmalloc(sizeof(void *) * MAX_MULTICAST_HOP, GFP_KERNEL);
	ctx->connection_id_array = kmalloc(sizeof(int) * MAX_MULTICAST_HOP, GFP_KERNEL);
	ctx->length_addr_array = kmalloc(sizeof(uintptr_t) * MAX_MULTICAST_HOP, GFP_KERNEL);
	
	ctx->qp = (struct ib_qp **)kmalloc(num_connections * sizeof(struct ib_qp *), GFP_KERNEL);
	if(!ctx->qp)
	{
		test_printk(KERN_ALERT "Fail to create master qp / ctx->qp\n");
		return NULL;
	}

	for(i=0;i<num_connections;i++)
	{
		struct ib_qp_attr attr;
		struct ib_qp_init_attr init_attr = {
			.cap = {
				.max_send_wr = MAX_ATOMIC_SEND_NUM + 2,
				.max_recv_wr = rx_depth,
				.max_send_sge = 2,
				.max_recv_sge = 2
			},
			.qp_type = IB_QPT_RC
		};

		struct ib_qp_attr attr1 = {
			.qp_state = IB_QPS_INIT,
			.pkey_index = 0,
			.port_num = port,
			.qp_access_flags = IB_ACCESS_REMOTE_WRITE|IB_ACCESS_REMOTE_READ|IB_ACCESS_LOCAL_WRITE|IB_ACCESS_REMOTE_ATOMIC,
			.path_mtu = IB_MTU_4096,
			.retry_cnt = 7,
			.rnr_retry = 7
		};
	
		ctx->send_state[i] = SS_INIT;
		ctx->recv_state[i] = RS_INIT;
		ctx->send_cq[i] = ib_create_cq((struct ib_device *)ctx->context, poll_cq, NULL, NULL, rx_depth+1, 0);

		init_attr.send_cq = ctx->send_cq[i];
		init_attr.recv_cq = ctx->cq;

		ctx->qp[i] = ib_create_qp(ctx->pd, &init_attr);
		if(!ctx->qp[i])
		{
			test_printk(KERN_ALERT "Fail to create qp[%d]\n", i);
			return NULL;
		}
		ib_query_qp(ctx->qp[i], &attr, IB_QP_CAP, &init_attr);
		if(init_attr.cap.max_inline_data >= size)
		{
			ctx->send_flags |= IB_SEND_INLINE;
		}
		
		if(ib_modify_qp(ctx->qp[i], &attr1,
				IB_QP_STATE		|
				IB_QP_PKEY_INDEX	|
				IB_QP_PORT		|
				IB_QP_ACCESS_FLAGS))
		{
			test_printk(KERN_ALERT "Fail to modify qp[%d]\n", i);
			ib_destroy_qp(ctx->qp[i]);
			return NULL;
		}
	}

	//test_printk(KERN_ALERT "I am here for client_init_ctx\n");
	return ctx;
}
int client_init_interface(int ib_port, unsigned long total_size)
{
	int	size = 4096;
	int	rx_depth = RECV_DEPTH;
	int	i;
	int 	x;
	int	ret;
	mtu = IB_MTU_4096;
	sl = 0;
	routs = (int *)kmalloc(MAX_CONNECTION * sizeof(int), GFP_KERNEL);

	for(i=0;i<MAX_CONNECTION;i++)
	{
		routs[i]=0;
	}
	//srand48(time(NULL));
	page_size = 4096;
	x = rdma_port_get_link_layer(ib_dev, ib_port);
	rcnt = 0;
	scnt = 0;
	ctx = client_init_ctx(size,rx_depth,ib_port, total_size);
	if(!ctx)
	{
		test_printk(KERN_ALERT "Fail to do client_init_ctx\n");
		return 1;
	}

	ret = ib_query_port((struct ib_device *)ctx->context, ib_port, &ctx->portinfo);
	if(ret<0)
	{
		test_printk(KERN_ALERT "Fail to query port\n");
	}
	//test_printk(KERN_ALERT "I am here before return client_init_interface\n");
	return 0;

}
int client_get_random_number(void)
{
	int random_number;
	get_random_bytes(&random_number, sizeof(int));
	return random_number;
}
int client_gen_msg(char *msg, int connection_id)
{
	//int gid[33];
	struct pingpong_dest my_dest;
	my_dest.lid = ctx->portinfo.lid;
	/*if(ctx->portinfo.link_layer!= IB_LINK_LAYER_ETHERNET && !my_dest.lid)
	{
		test_printk("Could not get local connection_id %d\n", connection_id);
		return 1;
	}*/
	memset(&my_dest.gid, 0, sizeof(union ib_gid));
	my_dest.node_id = NODE_ID;
	my_dest.qpn = ctx->qp[connection_id]->qp_num;
	my_dest.psn = client_get_random_number() & 0xffffff;
	//inet_ntop(AF_INET6, &my_dest.gid, gid, sizeof(union ib_gid));
	//client_gid_to_wire_gid(&my_dest.gid, gid);
	sprintf(msg, "%04x:%04x:%06x:%06x:%s", my_dest.node_id, my_dest.lid, my_dest.qpn,my_dest.psn, "00000000000000000000000000000000");
	return 0;
}
void client_wire_gid_to_gid(const char *wgid, union ib_gid *gid)
{
	char tmp[9];
	uint32_t v32;
	int i;

	for (tmp[8] = 0, i = 0; i < 4; ++i) 
	{
		memcpy(tmp, wgid + i * 8, 8);
		sscanf(tmp, "%x", &v32);
		*(uint32_t *)(&gid->raw[i * 4]) = ntohl(v32);
	}
}
int client_msg_to_pingpong_dest(char *msg, struct pingpong_dest *rem_dest)
{
	char gid[33];
	sscanf(msg, "%x:%x:%x:%x:%s", &rem_dest->node_id, &rem_dest->lid, &rem_dest->qpn, &rem_dest->psn, gid);
	client_wire_gid_to_gid(gid, &rem_dest->gid);
	return 0;
}
uintptr_t client_ib_reg_mr_addr(void *addr, size_t length)
{
	return (uintptr_t)ib_dma_map_single((struct ib_device *)ctx->context, addr, length, DMA_BIDIRECTIONAL); 
}
uintptr_t client_ib_reg_mr_phys_addr(void *addr, size_t length)
{
	struct ib_device *ibd = (void *)ctx->context;
	return (uintptr_t)phys_to_dma(ibd->dma_device, (phys_addr_t)addr);
}
struct client_ibv_mr *client_ib_reg_mr(struct ib_pd *pd, void *addr, size_t length, enum ib_access_flags access)
{
	struct client_ibv_mr *ret;
	struct ib_mr *proc;
	proc = ib_get_dma_mr(pd, access);
	ret = (struct client_ibv_mr *)kmalloc(sizeof(struct client_ibv_mr), GFP_KERNEL);
	//ret = &ctx->mr_set[client_get_mr_id_by_semaphore()];
	//ret->lkey = ctx->proc->lkey;
	//ret->rkey = ctx->proc->rkey;
	ret->addr = (void *)ib_dma_map_single((struct ib_device *)ctx->context, addr, length, DMA_BIDIRECTIONAL); 
	ret->length = length;
	ret->lkey = proc->lkey;
	ret->rkey = proc->rkey;
	ret->node_id = NODE_ID;
	//test_printk(KERN_CRIT "length %d addr:%x lkey:%x rkey:%x\n", (int) length, (unsigned int)ret->addr, ret->lkey, ret->rkey);
	return ret;
}
void header_cache_free(void *ptr)
{
	//printk(KERN_CRIT "free %x\n", ptr);
	kmem_cache_free(header_cache, ptr);
}
int client_post_receives_message(int connection_id, int depth)
{
	struct ib_recv_wr wr, *bad_wr = NULL;
	struct ib_sge sge[2];
	int i;
		for(i=0;i<depth;i++)
		{
			char *temp_addr, *temp_header_addr;
			uintptr_t mid_addr, mid_header_addr;
			struct ibapi_post_receive_intermediate_struct *p_r_i_struct;
			
			temp_addr = (char *)kmem_cache_alloc(post_receive_cache, GFP_KERNEL);
			//temp_header_addr = (char *)kmalloc(sizeof(struct ibapi_header), GFP_KERNEL); //kmem_cache_alloc(header_cache, GFP_KERNEL);
			temp_header_addr = (char *)kmem_cache_alloc(header_cache, GFP_KERNEL);
			//printk(KERN_CRIT, "alloc %x\n", temp_header_addr);
			p_r_i_struct = (struct ibapi_post_receive_intermediate_struct *)kmem_cache_alloc(intermediate_cache, GFP_KERNEL);
			
			p_r_i_struct->header = (uintptr_t)temp_header_addr;
			p_r_i_struct->msg = (uintptr_t)temp_addr;
			
			mid_addr = client_ib_reg_mr_addr(temp_addr, RDMA_BUFFER_SIZE*4);
			mid_header_addr = client_ib_reg_mr_addr(temp_header_addr, sizeof(struct ibapi_header));
			
			sge[0].addr = (uintptr_t)mid_header_addr;
			sge[0].length = sizeof(struct ibapi_header);
			sge[0].lkey = ctx->proc->lkey;

			sge[1].addr = (uintptr_t)mid_addr;
			sge[1].length = RDMA_BUFFER_SIZE*4;
			sge[1].lkey = ctx->proc->lkey;
			
			wr.wr_id = (uint64_t)p_r_i_struct;
			wr.next = NULL;
			wr.sg_list = sge;
			wr.num_sge = 2;
			
			ib_post_recv(ctx->qp[connection_id], &wr, &bad_wr);
		}
	return depth;
}

int client_ktcp_recv(struct socket *sock, unsigned char *buf, int len)
{
	struct msghdr msg;
	struct kvec iov;

	{
	if(sock->sk==NULL) return 0;

	iov.iov_base=buf;
	iov.iov_len=len;

	msg.msg_control=NULL;
	msg.msg_controllen=0;
	msg.msg_flags=0;
	msg.msg_name=NULL;
	msg.msg_namelen=0;
	msg.msg_iov=(struct iovec *)&iov;
	msg.msg_iovlen=1;
	}
	//printk(KERN_INFO "ktcp_recv.sock_recvmsg");
	//size=sock_recvmsg(sock,&msg,len,msg.msg_flags);
	kernel_recvmsg(sock, &msg, &iov, 1, iov.iov_len, 0);
	//printk(KERN_INFO "ktcp_recved");tyh-
	//printk("the message is : %s\n",buf);
	return 0;

}
int client_ktcp_send(struct socket *sock,char *buf,int len) 
{
	
	struct msghdr msg;
	struct kvec iov;
//	printk(KERN_INFO "ktcp_send\n");
	if(sock==NULL)
	{
		printk("ksend the cscok is NULL\n");
		return -1;
	}

	iov.iov_base=buf;
	iov.iov_len=len;

	msg.msg_control=NULL;
	msg.msg_controllen=0;
	msg.msg_flags=0;
	msg.msg_iov=(struct iovec *)&iov;
	msg.msg_iovlen=1;
	msg.msg_name=NULL;
	msg.msg_namelen=0;

	//printk(KERN_INFO "ktcp_send.sock_sendmsg");
	kernel_sendmsg(sock,&msg,&iov, 1, iov.iov_len);
	//printk(KERN_INFO "message sent!");
	return 0;
}
static int client_connect_ctx(int connection_id, int port, int my_psn, enum ib_mtu mtu, int sl, struct pingpong_dest *dest)//int sgid_idx always set to -1
{
	struct ib_qp_attr attr = {
		.qp_state	= IB_QPS_RTR,
		.path_mtu	= mtu,
		.dest_qp_num	= dest->qpn,
		.rq_psn		= dest->psn,
		.max_dest_rd_atomic	= 10,
		.min_rnr_timer	= 12,
		.ah_attr	= {
			//.is_global	= 0,
			.dlid		= dest->lid,
			.sl		= sl,
			.src_path_bits	= 0,
			.port_num	= port
		}
	};
	/*if(dest->gid.global.interface_id)
	{
		//attr.ah_attr.is_global = 1;
		attr.ah_attr.grh.hop_limit = 1;
		attr.ah_attr.grh.dgid = dest->gid;
		attr.ah_attr.grh.sgid_index = -1; //Always set to -1
	}*/

	if(ib_modify_qp(ctx->qp[connection_id], &attr, 
		IB_QP_STATE	|
		IB_QP_AV	|
		IB_QP_PATH_MTU	|
		IB_QP_DEST_QPN	|
		IB_QP_RQ_PSN	|
		IB_QP_MAX_DEST_RD_ATOMIC	|
		IB_QP_MIN_RNR_TIMER))
	{
		test_printk(KERN_ALERT "Fail to modify QP to RTR at connection %d\n", connection_id);
		return 1;
	}


	attr.qp_state	= IB_QPS_RTS;
	attr.timeout	= 14;
	attr.retry_cnt	= 7;
	attr.rnr_retry	= 7;
	attr.sq_psn	= my_psn;
	attr.max_rd_atomic = 10; //was 1
	if(ib_modify_qp(ctx->qp[connection_id], &attr,
		IB_QP_STATE	|
		IB_QP_TIMEOUT	|
		IB_QP_RETRY_CNT	|
		IB_QP_RNR_RETRY	|
		IB_QP_SQ_PSN	|
		IB_QP_MAX_QP_RD_ATOMIC))
	{
		test_printk(KERN_ALERT "Fail to modify QP to RTS at connection %d\n", connection_id);
		return 2;
	}
	return 0;
}
int client_add_newnode(char *msg)
{
	struct pingpong_dest rem_dest;
	struct pingpong_dest my_dest;
	int ret;
	int cur_connection;
	down(&add_newnode_mutex);
	//test_printk(KERN_ALERT "start do add_node with %s\n", msg);
	
	client_msg_to_pingpong_dest(msg, &rem_dest);
	cur_connection = (rem_dest.node_id*ctx->num_parallel_connection)+atomic_read(&ctx->num_alive_connection[rem_dest.node_id]);
	client_msg_to_pingpong_dest(my_QPset[cur_connection].server_information_buffer, &my_dest);

	if(cur_connection+1%ctx->num_parallel_connection==0)
		ret = client_connect_ctx(cur_connection, ib_port, my_dest.psn, mtu, sl+1, &rem_dest);
	else
		ret = client_connect_ctx(cur_connection, ib_port, my_dest.psn, mtu, sl, &rem_dest);	
	if(ret)
        {
                test_printk("fail to chreate new node inside add_newnode function\n");
                up(&add_newnode_mutex);
                return 1;
        }
	routs[cur_connection] += client_post_receives_message(cur_connection, RECV_DEPTH);

	atomic_inc(&ctx->num_alive_connection[rem_dest.node_id]);
	atomic_inc(&ctx->alive_connection);
	up(&add_newnode_mutex);	
	do_exit(0);
}

int send_handle(char *addr, uint32_t length, int sender_id)
{
	//test_printk(KERN_ALERT "receive %s\n", addr);
	return 0;
}
int handle_send_reply(char *input_buf, uint32_t size, char *output_buf, uint32_t *output_size, int sender_id)//return output_size
{
	//uint32_t ret_length;
	//ret_length = size;
	//sprintf(output_buf, "%.*s", size, input_buf);
	//memcpy(output_buf, input_buf, size);
	output_buf[0]='o';
	output_buf[1]='k';
	
	//test_printk(KERN_ALERT "receive %s return with %d\n", input_buf, ret_length);
	
	//memcpy(output_size, &ret_length, sizeof(uint32_t));
	*output_size = 2;
	return 0;
}
int handle_send_reply_opt(char *input_buf, uint32_t size, void **output_buf, uint32_t *output_size, int sender_id)//return output_size
{
	char *ret;
	ret = kmalloc(4096, GFP_KERNEL);
	*output_buf = ret;
	
	*output_size = 12288;
	ibapi_free_recv_buf(input_buf);
	return 0;
}
int handle_atomic_send(struct atomic_struct *input_list, uint32_t length, char *output_buf, uint32_t *output_size, int sender_id)
{
	/*
	int i;
	test_printk(KERN_ALERT "Receive %d\n", length);
	for(i=0;i<length;i++)
	{
		test_printk(KERN_ALERT "%d: %.*s\n", i, (int)input_list[i].length, (char *)input_list[i].addr);
	}
	*/
	output_buf[0] = 'o';
	output_buf[1] = 'k';
	*output_size = 2;
	return 0;
}

int client_find_qp_id_by_qpnum(uint32_t qp_num)
{
	int i;
	for(i=0;i<ctx->num_connections;i++)
	{
		if(ctx->qp[i]->qp_num==qp_num)
			return i;
	}
	return -1;
}
//int waiting_queue_handler(struct wait_queue_head_t *input_wq)
int waiting_queue_handler(void)
{
	struct send_and_reply_format *new_request;
	//struct list_head *ptr;
	allow_signal(SIGKILL);
	while(1)
	{
		/*wait_event_interruptible(wq, !list_empty(&(request_list.list)));*/
		while(list_empty(&(request_list.list)))
		{
			schedule();
			if(kthread_should_stop())
			{
				test_printk(KERN_ALERT "Stop waiting_event_handler\n");
				return 0;
			}
		}
		spin_lock(&wq_lock);
		//for(ptr = request_list.list.next;ptr!=&request_list;ptr=ptr->next)
		//{				
			new_request = list_entry(request_list.list.next, struct send_and_reply_format, list);

		spin_unlock(&wq_lock);
			switch(new_request->type)
			{
				case MSG_GET_FINISH:
					test_printk("Handler terminated\n");
					spin_unlock(&wq_lock);
					do_exit(0);
					break;
				case MSG_DO_POST_RECEIVE:
					client_post_receives_message(new_request->src_id, new_request->length);
					break;					
				case MSG_SERVER_SEND:
					ctx->send_handler(new_request->msg, new_request->length, new_request->src_id);
					break;
				case MSG_CLIENT_SEND:
					ctx->send_handler(new_request->msg, new_request->length, new_request->src_id);
					break;
				case MSG_PASS_MR:
				{
					struct client_ibv_mr *input_mr = (struct client_ibv_mr *)kmalloc(sizeof(struct client_ibv_mr), GFP_KERNEL);
					memcpy(input_mr, new_request->msg, sizeof(struct client_ibv_mr));
					//struct client_ibv_mr *input_mr = (struct client_ibv_mr *)new_request->msg;
					//kmem_cache_free(post_receive_cache, new_request->msg);
					client_free_recv_buf(new_request->msg);
					break;
				}
				case MSG_GET_SEND_AND_REPLY_1:
				{
					char *ret;
				    	uint32_t ret_size;
					int ret_priority = LOW_PRIORITY;
					int connection_id;
					uintptr_t tempaddr;
					//ret = (char *)kmalloc(RDMA_BUFFER_SIZE*4, GFP_KERNEL);
					
					ret = (char *)kmem_cache_alloc(post_receive_cache, GFP_KERNEL);
					ctx->send_reply_handler(new_request->msg, new_request->length, ret, &ret_size, new_request->src_id);
					tempaddr = client_ib_reg_mr_addr(ret, ret_size);
				    	connection_id = client_get_connection_by_atomic_number(new_request->src_id, ret_priority);
					//client_send_message_addr(connection_id, MSG_GET_SEND_AND_REPLY_2, (void *)tempaddr, ret_size, new_request->inbox_id);
					client_send_message_sge(connection_id, MSG_GET_SEND_AND_REPLY_2, (void *)tempaddr, ret_size, new_request->inbox_addr, new_request->inbox_semaphore, ret_priority);
					//kmem_cache_free(post_receive_cache, ret);
					client_free_recv_buf(ret);
					break;
				}
				case MSG_GET_SEND_AND_REPLY_OPT_1:
				{
					unsigned long ret_addr;
				    	uint32_t ret_size;
					int ret_priority = LOW_PRIORITY;
					int connection_id;
					uintptr_t tempaddr;
					
					ctx->send_reply_opt_handler(new_request->msg, new_request->length, (void **)&ret_addr, &ret_size, new_request->src_id);
					tempaddr = client_ib_reg_mr_phys_addr((void *)ret_addr, ret_size);
				    	connection_id = client_get_connection_by_atomic_number(new_request->src_id, ret_priority);
					//client_send_message_addr(connection_id, MSG_GET_SEND_AND_REPLY_2, (void *)tempaddr, ret_size, new_request->inbox_id);
					client_send_message_sge(connection_id, MSG_GET_SEND_AND_REPLY_OPT_2, (void *)tempaddr, ret_size, new_request->inbox_addr, new_request->inbox_semaphore, ret_priority);
					break;
				}
				case MSG_GET_ATOMIC_MID:
				{
					char *ret;
				    	uint32_t ret_size;
					int ret_priority = LOW_PRIORITY;
					int connection_id;
					uintptr_t tempaddr;
					
					ret = (char *)kmem_cache_alloc(post_receive_cache, GFP_KERNEL);
					ctx->atomic_send_handler((struct atomic_struct *)new_request->msg, new_request->length, ret, &ret_size, new_request->src_id);
					tempaddr = client_ib_reg_mr_addr(ret, ret_size);
				    	connection_id = client_get_connection_by_atomic_number(new_request->src_id, ret_priority);
					
					//client_send_message_addr(connection_id, MSG_GET_ATOMIC_REPLY, (void *)tempaddr, ret_size, new_request->inbox_id);
					client_send_message_sge(connection_id, MSG_GET_ATOMIC_REPLY, (void *)tempaddr, ret_size, new_request->inbox_addr, new_request->inbox_semaphore, ret_priority);
					//mem_cache_free(post_receive_cache, ret);
					client_free_recv_buf(ret);
					break;
				}
				case MSG_GET_ATOMIC_SINGLE_MID:
				{
					ctx->atomic_single_send_handler((struct atomic_struct *)new_request->msg, new_request->length, new_request->src_id);
					break;
				}
				case MSG_GET_REMOTEMR:
				{
					//down(&request_mr[*(int*)ptr]);
					int length;
					int connection_id;
					void *addr;
					struct client_ibv_mr *ret_mr;
					uintptr_t tempaddr;
					memcpy(&length, new_request->msg, new_request->length);
					
					connection_id = client_get_connection_by_atomic_number(new_request->src_id, LOW_PRIORITY);
					
					addr = kmalloc(length * sizeof(char), GFP_KERNEL);
					memset(addr, 0, length * sizeof(char));
					ret_mr = client_ib_reg_mr(ctx->pd, addr, length, IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ);
					tempaddr = client_ib_reg_mr_addr(ret_mr, sizeof(struct client_ibv_mr));
					//client_send_message_addr(connection_id, MSG_GET_REMOTEMR_REPLY, (void *)tempaddr, sizeof(struct client_ibv_mr), new_request->inbox_id);
					client_send_message_sge(connection_id, MSG_GET_REMOTEMR_REPLY, (void *)tempaddr, sizeof(struct client_ibv_mr), new_request->inbox_addr, new_request->inbox_semaphore, LOW_PRIORITY);
					//kmem_cache_free(post_receive_cache, new_request->msg);
					client_free_recv_buf(new_request->msg);
					//test_printk(KERN_CRIT "send %x %x %x\n", (unsigned int)ret_mr->addr, ret_mr->lkey, ret_mr->rkey);
					break;
				}
				default:
					test_printk(KERN_ALERT "receive weird event %d\n", new_request->type);
			}
			spin_lock(&wq_lock);
			list_del(&new_request->list);
			spin_unlock(&wq_lock);
			//kfree(new_request);
			kmem_cache_free(s_r_cache, new_request);
		//}
		//spin_unlock(&wq_lock);
	}
}

int atomic_send_reply_thread_helper(void *input)
{
	char *ret;
	uint32_t ret_size;
	int ret_priority = LOW_PRIORITY;
	int connection_id;
	uintptr_t tempaddr;
	struct send_and_reply_format *new_request;

	new_request = (struct send_and_reply_format *)input;

	ret = (char *)kmem_cache_alloc(post_receive_cache, GFP_KERNEL);
	//test_printk(KERN_CRIT "%u\n", new_request->src_id);

//	printk(KERN_CRIT "[%s] [%d] numreqs %d sender %d\n",
//			__func__, current->pid, new_request->length, new_request->src_id);
	ctx->atomic_send_handler((struct atomic_struct *)new_request->msg, new_request->length, ret, &ret_size, new_request->src_id);

	//printk(KERN_CRIT "[%s] [%d] got reply msg %p %lx\n",
	//		__func__, current->pid, ret, *(unsigned long *)ret);
	tempaddr = client_ib_reg_mr_addr(ret, ret_size);
	connection_id = client_get_connection_by_atomic_number(new_request->src_id, ret_priority);

	client_send_message_sge(connection_id, MSG_GET_ATOMIC_REPLY, (void *)tempaddr, ret_size, new_request->inbox_addr, new_request->inbox_semaphore, ret_priority);
	//kmem_cache_free(post_receive_cache, ret);
	client_free_recv_buf(ret);
	kmem_cache_free(s_r_cache, input);

	return 0;
}

int atomic_send_thread_helper(void *input)
{
	struct send_and_reply_format *new_request;

	new_request = (struct send_and_reply_format *)input;

	//printk(KERN_CRIT "[%s] [%d] numreqs %d sender %d\n",
	//		__func__, current->pid, new_request->length, new_request->src_id);
	ctx->atomic_single_send_handler((struct atomic_struct *)new_request->msg, new_request->length, new_request->src_id);

	return 0;
}

static int client_poll_cq(struct ib_cq *target_cq)
{
	int ne;
	struct ib_wc wc[NUM_PARALLEL_CONNECTION];
	int i, connection_id;
	allow_signal(SIGKILL);
	//set_current_state(TASK_INTERRUPTIBLE);


	while(1)
	{
		do{
			//set_current_state(TASK_RUNNING);
			ne = ib_poll_cq(target_cq, NUM_PARALLEL_CONNECTION, wc);
			if(ne < 0)
			{
				test_printk(KERN_ALERT "poll CQ failed %d\n", ne);
				return 1;
			}
			/*if(ne >= 1)
				break;*/
			#ifdef DEBUG_SHINYEH
			schedule();
			//set_current_state(TASK_INTERRUPTIBLE);
			if(kthread_should_stop())
			{
				test_printk(KERN_ALERT "Stop cq and return\n");
				return 0;
			}
			//msleep(1);
			#endif
		}while(ne < 1);
		//set_current_state(TASK_RUNNING);
		for(i=0;i<ne;++i)
		{
			if(wc[i].status != IB_WC_SUCCESS)
			{
				test_printk(KERN_ALERT "failed status (%d) for wr_id %d\n", wc[i].status, (int) wc[i].wr_id);
			}
			if((int) wc[i].opcode == IB_WC_RECV)
			{
				//test_printk(KERN_ALERT "receive something\n");
				char *addr;
				int type;
				struct ibapi_post_receive_intermediate_struct *p_r_i_struct = (struct ibapi_post_receive_intermediate_struct*)wc[i].wr_id;
				struct ibapi_header *header_addr;

				header_addr = (struct ibapi_header*)p_r_i_struct->header;
				addr = (char *)p_r_i_struct->msg;
				connection_id = client_find_qp_id_by_qpnum(wc[i].qp->qp_num);
				ctx->recv_num[connection_id]++;
				type = header_addr->type;
				if(type == MSG_CLIENT_SEND || type == MSG_SERVER_SEND)
				{
					struct send_and_reply_format *recv;
					recv = kmem_cache_alloc(s_r_cache, GFP_KERNEL);
					recv->length = header_addr->length;
					recv->src_id = header_addr->src_id;
					recv->msg = addr;
					recv->type = type;

					spin_lock(&wq_lock);
					list_add_tail(&(recv->list), &request_list.list);
					spin_unlock(&wq_lock);
					//kmem_cache_free(header_cache, header_addr);
					header_cache_free(header_addr);
				}
				else if(type == MSG_GET_SEND_AND_REPLY_1 || type == MSG_GET_SEND_AND_REPLY_OPT_1)
				{
					struct send_and_reply_format *recv;
					
					recv = kmem_cache_alloc(s_r_cache, GFP_KERNEL);
					recv->src_id = header_addr->src_id;
					recv->inbox_addr = header_addr->inbox_addr;
					recv->inbox_semaphore = header_addr->inbox_semaphore;
					recv->length = header_addr->length;
					recv->msg = addr;
					recv->type = type;
					
					spin_lock(&wq_lock);
					list_add_tail(&(recv->list), &request_list.list);
					spin_unlock(&wq_lock);
					//kmem_cache_free(header_cache, header_addr);
					header_cache_free(header_addr);
				}
				else if(type == MSG_PASS_MR)
				{	
					struct send_and_reply_format *recv;
					recv = kmem_cache_alloc(s_r_cache, GFP_KERNEL);
					recv->msg = addr;
					recv->length = header_addr->length;
					recv->type = type;

					spin_lock(&wq_lock);
					list_add_tail(&(recv->list), &request_list.list);
					spin_unlock(&wq_lock);
					//kmem_cache_free(header_cache, header_addr);
					header_cache_free(header_addr);
				}
				else if(type == MSG_GET_REMOTEMR)
				{
					struct send_and_reply_format *recv;
					recv = kmem_cache_alloc(s_r_cache, GFP_KERNEL);
					
					
					recv->src_id = header_addr->src_id;
					recv->inbox_addr = header_addr->inbox_addr;
					recv->inbox_semaphore = header_addr->inbox_semaphore;
					recv->length = header_addr->length;
					recv->msg = addr;
					recv->type = type;

					spin_lock(&wq_lock);
					list_add_tail(&(recv->list), &request_list.list);
					spin_unlock(&wq_lock);
					//kmem_cache_free(header_cache, header_addr);
					header_cache_free(header_addr);
					
				}
				else if(type == MSG_NODE_JOIN)
				{
					struct task_struct *thread_create_new_node;
                                        thread_create_new_node = kthread_create((void *)client_add_newnode, addr, "create new node");
                                        //pthread_create(&thread_create_new_node, NULL, (void *)&client_add_newnode, strdupa(ctx->recv_msg[connection_id]->data.newnode_msg));
                                        if(IS_ERR(thread_create_new_node))
                                        {
                                                test_printk(KERN_ALERT "Fail to create a new thread for new node\n");
                                        }
                                        else
                                        {
                                                wake_up_process(thread_create_new_node);
                                        }
					//kmem_cache_free(header_cache, header_addr);
					header_cache_free(header_addr);
	
				}
				else if(type == MSG_GET_ATOMIC_START || type == MSG_GET_ATOMIC_SINGLE_START)
				{
					int request_len = *(int *)addr;

					test_printk(KERN_CRIT "connection %d receive atomic reqs with length %d\n",connection_id, (int)*addr);

					ctx->atomic_buffer[connection_id] = kmalloc(request_len * sizeof(struct atomic_struct), GFP_ATOMIC);
					if (unlikely(!ctx->atomic_buffer[connection_id])) {
						WARN(1, "request_len: %d", request_len);
						BUG();
					}

					ctx->atomic_buffer_total_length[connection_id] = request_len;
					ctx->atomic_buffer_cur_length[connection_id] = 0;
					//kmem_cache_free(header_cache, header_addr);
					header_cache_free(header_addr);
				}
				else if(type == MSG_GET_ATOMIC_MID || type == MSG_GET_ATOMIC_SINGLE_MID)
				{
					int cur_number;
					if(ctx->atomic_buffer_cur_length[connection_id]<0)
					{
						printk(KERN_CRIT "IB_BUG:RECEIVE ATOMIC_MID without getting ATOMIC_START: from connection :%d data len: %d file type %d cur_len in ctx:%d\n", connection_id,  header_addr->length, type, ctx->atomic_buffer_cur_length[connection_id]);
					}
					cur_number = ctx->atomic_buffer_cur_length[connection_id];
					test_printk(KERN_CRIT "%d receive atomic reqs cur_number %d vaddr %lx len %d num-atomic-receieved %d as type %d\n", connection_id, cur_number, addr, header_addr->length, ctx->atomic_buffer_cur_length[connection_id], type);
					//char *temp_memspace;
					//temp_memspace = kmalloc(RDMA_BUFFER_SIZE*4, GFP_KERNEL);
					//memcpy(temp_memspace, addr, header_addr->length);
					//ctx->atomic_buffer[connection_id][cur_number].vaddr = temp_memspace;
					ctx->atomic_buffer[connection_id][cur_number].vaddr = addr;

					ctx->atomic_buffer[connection_id][cur_number].len = header_addr->length;
//printk(KERN_CRIT "receive atomic reqs cur_number %d vaddr %lx len %d num-atomic-receieved %d\n", 
//		cur_number, addr, header_addr->length, ctx->atomic_buffer_cur_length[connection_id]);
					ctx->atomic_buffer_cur_length[connection_id]++;
					if(ctx->atomic_buffer_cur_length[connection_id]==ctx->atomic_buffer_total_length[connection_id])
					{
						//ctx->atomic_send_handler(ctx->atomic_buffer[connection_id], ctx->atomic_buffer_cur_length[connection_id]);
						struct send_and_reply_format *recv;
						recv = kmem_cache_alloc(s_r_cache, GFP_KERNEL);
						
						recv->msg = (char *)ctx->atomic_buffer[connection_id];
						recv->src_id = header_addr->src_id;
						recv->inbox_addr = header_addr->inbox_addr;
						recv->inbox_semaphore = header_addr->inbox_semaphore;
						//recv->length = header_addr->length;
						recv->length = ctx->atomic_buffer_total_length[connection_id];
						recv->type = type;
					
	//					printk(KERN_CRIT "MSG_GET_ATOMIC_MID length %d type %d\n", recv->length, recv->type);

						/* temprory fix to always create new thread of handler for atomic operations, TODO: create new apis to do this separately from normal atomic operations */
						if (type == MSG_GET_ATOMIC_MID)
						{
							kthread_run(atomic_send_reply_thread_helper, (void *)recv, "atomicsendreply handler");
						}
						if (type == MSG_GET_ATOMIC_SINGLE_MID)
						{
							kthread_run(atomic_send_thread_helper, (void *)recv, "atomicsendreply handler");
						}	
						ctx->atomic_buffer_cur_length[connection_id]=-1;
						/* normal atomic operations that use the same thread of handler */
						//spin_lock(&wq_lock);
						//list_add_tail(&(recv->list), &request_list.list);
						//spin_unlock(&wq_lock);
					}
					//kmem_cache_free(header_cache, header_addr);
					header_cache_free(header_addr);
				}
				else if(type == MSG_GET_SEND_AND_REPLY_2 || type == MSG_GET_ATOMIC_REPLY || type == MSG_GET_REMOTEMR_REPLY ||\
					type == MSG_CREATE_LOCK_REPLY || type == MSG_ASSIGN_LOCK || type == MSG_ASK_LOCK_REPLY)
				{
					if(header_addr->length > 5120)
					{
						printk(KERN_CRIT "IB_BUG: connection %d receive type %d with len %d addr: %Lx semaphore: %Lx\n", connection_id, type, header_addr->length, header_addr->inbox_addr, header_addr->inbox_semaphore);
					}
					
					test_printk(KERN_CRIT "%d receive type %d with len %d addr: %x semaphore: %x\n", connection_id, type, header_addr->length, header_addr->inbox_addr, header_addr->inbox_semaphore);
					memcpy((void *)header_addr->inbox_addr, addr, header_addr->length);
					memcpy((void *)header_addr->inbox_semaphore, &header_addr->length, sizeof(uint32_t));
					//*(int *)header_addr->inbox_semaphore = header_addr->length;
					client_free_recv_buf(addr);
					//kmem_cache_free(header_cache, header_addr);
					header_cache_free(header_addr);
					//int recv_inbox_id = wc[i].ex.imm_data/WRAP_UP_NUM_FOR_WAITING_INBOX;
					//memcpy(ctx->send_reply_inbox[recv_inbox_id], addr, wc[i].byte_len);
					//ctx->send_reply_wait_inbox[recv_inbox_id] = wc[i].byte_len;
				}
				else if(type == MSG_GET_SEND_AND_REPLY_OPT_2)
				{
					//*(header_addr->inbox_addr) = addr;
					//memcpy((void *)header_addr->inbox_addr, &addr, sizeof(void *));
					*(void **)header_addr->inbox_addr = addr;
					*(int *)header_addr->inbox_semaphore = header_addr->length;
					//kmem_cache_free(header_cache, header_addr);
					header_cache_free(header_addr);
				}
				else
				{
					test_printk(KERN_ALERT "Weird type received from connection: %d as %d\n", connection_id, type);
				}
				if(ctx->recv_num[connection_id]==ctx->rx_depth/4)
				{
					//client_post_receives_message(connection_id, 1);
					//ctx->recv_num[connection_id]=1;
					
					struct send_and_reply_format *recv;
					recv = kmem_cache_alloc(s_r_cache, GFP_KERNEL);
					
					
					recv->src_id = connection_id;
					recv->length = ctx->rx_depth/4;
					recv->type = MSG_DO_POST_RECEIVE;

					spin_lock(&wq_lock);
					list_add_tail(&(recv->list), &request_list.list);
					spin_unlock(&wq_lock);
					//kmem_cache_free(header_cache, header_addr);
					ctx->recv_num[connection_id]=ctx->recv_num[connection_id] - ctx->rx_depth/4;
				}
				kmem_cache_free(intermediate_cache, p_r_i_struct);
			}
			/*
			else if ((int)wc[i].opcode == IB_WC_SEND)
			{
				//test_printk(KERN_ALERT "send something\n");
				
				int type = wc[i].wr_id/WRAP_UP_NUM_FOR_TYPE;
				waiting_id = (int) (wc[i].wr_id %WRAP_UP_NUM_FOR_TYPE)/ WRAP_UP_NUM_FOR_WRID;
				if(type == MSG_GET_SEND_AND_REPLY_1)
				{
					ctx->thread_state[waiting_id] = TS_DONE;
				}
				else if(type == MSG_GET_SEND_AND_REPLY_2)
				{
					ctx->thread_state[waiting_id] = TS_DONE;
				}
				else if(type == MSG_CLIENT_SEND)
				{	
					//connection_id =  (int) wc[i].wr_id % WRAP_UP_NUM_FOR_WRID;
					//test_printk(KERN_ALERT "release %d on connection %d\n", waiting_id, connection_id);
					ctx->thread_state[waiting_id]=TS_DONE;
				}
				else if(type == MSG_GET_REMOTEMR)
				{
					ctx->thread_state[waiting_id]=TS_DONE;
				}
				else if(type == MSG_GET_REMOTEMR_REPLY)
				{
					ctx->thread_state[waiting_id]=TS_DONE;
				}
				else if(type == MSG_GET_ATOMIC_START)
				{
					ctx->thread_state[waiting_id]=TS_DONE;
				}
				else if(type == MSG_GET_ATOMIC_MID)
				{
					ctx->thread_state[waiting_id]=TS_DONE;
				}
				else
				{
					
					connection_id =  (int) wc[i].wr_id % WRAP_UP_NUM_FOR_WRID;
					test_printk(KERN_ALERT "Weird Type Sent from connection: %d as %d\n", connection_id, type);
				}
			}
			else if ((int)wc[i].opcode == IB_WC_RDMA_WRITE)
			{
				waiting_id = (int) (wc[i].wr_id %WRAP_UP_NUM_FOR_TYPE)/ WRAP_UP_NUM_FOR_WRID;
				ctx->thread_state[waiting_id] = TS_DONE;

			}
			else if ((int)wc[i].opcode == IB_WC_RDMA_READ)
			{
				waiting_id = (int) (wc[i].wr_id %WRAP_UP_NUM_FOR_TYPE)/ WRAP_UP_NUM_FOR_WRID;
				ctx->thread_state[waiting_id] = TS_DONE;
			}*/
			else
			{	
				connection_id = client_find_qp_id_by_qpnum(wc[i].qp->qp_num);
				test_printk(KERN_ALERT "%d Recv weird event as %d\n", connection_id, (int)wc[i].opcode);
			}

		}
	}
	do_exit(0);
	return 0;
}
inline int client_get_congestion_status(int connection_id)
{
	return atomic_read(&ctx->connection_congestion_status[connection_id]);
}
inline int client_get_connection_by_atomic_number(int target_node, int priority)
{	
	return atomic_inc_return(&ctx->atomic_request_num[target_node])%(atomic_read(&ctx->num_alive_connection[target_node])) + NUM_PARALLEL_CONNECTION * target_node;
	
	
	/*int ret;
	ret = atomic_read(&ctx->num_alive_connection[target_node]);
	if(ret==0)
	{
		test_printk(KERN_ALERT "interact with no node %d without any connection\n", target_node);
		return 1;
	}
	
	//down(&atomic_accessing_lock[target_node]);
	
	//ret = atomic_add_return(1,&ctx->atomic_request_num[target_node])%ret + ctx->num_parallel_connection * target_node;
	
	ret = atomic_add_return(1,&ctx->atomic_request_num[target_node])%ret + NUM_PARALLEL_CONNECTION * target_node;
	
	
	//ctx->atomic_request_num[target_node]++;
	//up(&atomic_accessing_lock[target_node]);
	//test_printk(KERN_ALERT "inside atomic number ta:%d ctx->ato:%d ctx->num:%d ctx->req:%d ret:%d real_ret:%d paral:%d\n", target_node, ctx->atomic_request_num[target_node], ctx->num_alive_connection[target_node], ctx->atomic_request_num[target_node], ret, ctx->num_parallel_connection*target_node + ret, ctx->num_parallel_connection);
	//ret = ctx->num_parallel_connection*target_node + ret;
	return ret;*/
}
inline int client_get_waiting_id_by_semaphore(void)
{
	//int ret;
	return atomic_inc_return(&ctx->parallel_thread_num) % MAX_PARALLEL_THREAD;
	//ctx->parallel_thread_num++;
	/*if(ctx->parallel_thread_num==MAX_PARALLEL_THREAD)
	{
		ctx->parallel_thread_num=0;
	}*/
	//return ret;
}


int client_get_mr_id_by_semaphore(void)
{   
    return atomic_inc_return(&ctx->used_mr_num) % MAX_PARALLEL_THREAD;
}
/*int client_send_message_api(int connection_id, int type, struct client_ibv_mr *input_mr, int inbox_id)
{	
	//printk(KERN_INFO "send start %d\n", connection_id);
	struct ib_send_wr wr, *bad_wr = NULL;
    	struct ib_sge sge;
    	int ret;
    	//int waiting_id = client_get_waiting_id_by_semaphore();
	int ne, i;
	struct ib_wc wc[2];
	//down(&connection_lock[connection_id]);
	spin_lock(&connection_lock[connection_id]);
    	memset(&wr, 0, sizeof(wr));
    	memset(&sge, 0, sizeof(struct ib_sge));
    
	//ctx->thread_state[waiting_id] = TS_WAIT;
	//wr.wr_id = connection_id + waiting_id * WRAP_UP_NUM_FOR_WRID + type * WRAP_UP_NUM_FOR_TYPE;
	wr.wr_id = type;
	wr.opcode = IB_WR_SEND_WITH_IMM;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.send_flags = IB_SEND_SIGNALED;
	wr.ex.imm_data = type + inbox_id * WRAP_UP_NUM_FOR_WAITING_INBOX;
	sge.addr = (uint64_t)input_mr->addr;
	sge.length = input_mr->length;
	sge.lkey = input_mr->lkey;
	ret = ib_post_send(ctx->qp[connection_id], &wr, &bad_wr);
	if(ret==0){
		do{
			ne = ib_poll_cq(ctx->send_cq[connection_id], 1, wc);
			if(ne < 0)
			{
				test_printk(KERN_ALERT "poll send_cq failed at connection %d\n", connection_id);
				return 1;
			}
		}while(ne<1);
		for(i=0;i<ne;i++)
		{
			if(wc[i].status!=IB_WC_SUCCESS)
			{
				test_printk(KERN_ALERT "send failed at connection %d\n", connection_id);
				return 2;
			}
			else
				break;
		}
		
	}
	else{
		test_printk(KERN_INFO "send fail %d\n", connection_id);
	}
	//up(&connection_lock[connection_id]);
	//printk(KERN_INFO "send end %d\n", connection_id);
	spin_unlock(&connection_lock[connection_id]);
	return ret;
}*/
void client_setup_ibapi_header(uint32_t src_id, uint64_t inbox_addr, uint64_t inbox_semaphore, uint32_t length, int priority, int type, struct ibapi_header *output_header)
{
	output_header->src_id = src_id;
	output_header->inbox_addr = inbox_addr;
	output_header->inbox_semaphore = inbox_semaphore;
	output_header->length = length;
	output_header->priority = priority;
	output_header->type = type;
}
int client_send_message_sge(int connection_id, int type, void *addr, int size, uint64_t inbox_addr, uint64_t inbox_semaphore, int priority)
{	
	struct ib_send_wr wr, *bad_wr = NULL;
    	struct ib_sge sge[2];
    	int ret;
	int ne, i;
	struct ib_wc wc[2];

	struct ibapi_header output_header;
	void *output_header_addr;
	
	spin_lock(&connection_lock[connection_id]);
	
    	memset(&wr, 0, sizeof(wr));
    	memset(sge, 0, sizeof(struct ib_sge)*2);
    
	wr.wr_id = type;
	wr.opcode = IB_WR_SEND;
	wr.sg_list = sge;
	wr.num_sge = 2;
	wr.send_flags = IB_SEND_SIGNALED;
	
	client_setup_ibapi_header(NODE_ID, inbox_addr, inbox_semaphore, size, priority, type, &output_header);
	output_header_addr = (void *)client_ib_reg_mr_addr(&output_header, sizeof(struct ibapi_header));
	sge[0].addr = (uintptr_t)output_header_addr;
	sge[0].length = sizeof(struct ibapi_header);
	sge[0].lkey = ctx->proc->lkey;
	
	sge[1].addr = (uintptr_t)addr;
	sge[1].length = size;
	sge[1].lkey = ctx->proc->lkey;

	ret = ib_post_send(ctx->qp[connection_id], &wr, &bad_wr);
 
	if(ret==0){
		ctx->connection_timer_start[connection_id] = ktime_add_ns(ktime_get(), 10000); //10usec
		do{
			ne = ib_poll_cq(ctx->send_cq[connection_id], 1, wc);
			if(ne < 0)
			{
				test_printk(KERN_ALERT "poll send_cq failed at connection %d\n", connection_id);
				return 1;
			}
			ctx->connection_timer_end[connection_id] = ktime_get();
		}while(ne<1&&ktime_compare(ctx->connection_timer_start[connection_id], ctx->connection_timer_end[connection_id])>0);
		if(ne<1)//break by timeout
		{
			atomic_add(50, &ctx->connection_congestion_status[connection_id]);
			//test_printk(KERN_ALERT "congestion at connection %d\n", connection_id);
			do{
				ne = ib_poll_cq(ctx->send_cq[connection_id], 1, wc);
				if(ne < 0)
				{
					test_printk(KERN_ALERT "poll send_cq failed at connection %d\n", connection_id);
					return 1;
				}
			}while(ne<1);
		}
		else
			atomic_sub(1, &ctx->connection_congestion_status[connection_id]);
		for(i=0;i<ne;i++)
		{
			if(wc[i].status!=IB_WC_SUCCESS)
			{
				test_printk(KERN_ALERT "send failed at connection %d as %d\n", connection_id, wc[i].status);
				return 2;
			}
		}
	}
	else{
		test_printk(KERN_INFO "send fail %d\n", connection_id);
	}
	spin_unlock(&connection_lock[connection_id]);
	return ret;
}
int client_send_message_sge_without_lock(int connection_id, int type, void *addr, int size, uint64_t inbox_addr, uint64_t inbox_semaphore, int priority)
{	
	struct ib_send_wr wr, *bad_wr = NULL;
    	struct ib_sge sge[2];
    	int ret;
	int ne, i;
	struct ib_wc wc[2];

	struct ibapi_header output_header;
	void *output_header_addr;
	
	//spin_lock(&connection_lock[connection_id]);
	
    	memset(&wr, 0, sizeof(wr));
    	memset(sge, 0, sizeof(struct ib_sge)*2);
    
	wr.wr_id = type;
	wr.opcode = IB_WR_SEND;
	wr.sg_list = sge;
	wr.num_sge = 2;
	wr.send_flags = IB_SEND_SIGNALED;
	
	client_setup_ibapi_header(NODE_ID, inbox_addr, inbox_semaphore, size, priority, type, &output_header);
	output_header_addr = (void *)client_ib_reg_mr_addr(&output_header, sizeof(struct ibapi_header));
	sge[0].addr = (uintptr_t)output_header_addr;
	sge[0].length = sizeof(struct ibapi_header);
	sge[0].lkey = ctx->proc->lkey;
	sge[1].addr = (uintptr_t)addr;
	sge[1].length = size;
	sge[1].lkey = ctx->proc->lkey;

	ret = ib_post_send(ctx->qp[connection_id], &wr, &bad_wr);
 
	if(ret==0){
		ctx->connection_timer_start[connection_id] = ktime_add_ns(ktime_get(), 10000); //10usec
		do{
			ne = ib_poll_cq(ctx->send_cq[connection_id], 1, wc);
			if(ne < 0)
			{
				test_printk(KERN_ALERT "poll send_cq failed at connection %d\n", connection_id);
				return 1;
			}
			ctx->connection_timer_end[connection_id] = ktime_get();
		}while(ne<1&&ktime_compare(ctx->connection_timer_start[connection_id], ctx->connection_timer_end[connection_id])>0);
		if(ne<1)//break by timeout
		{
			atomic_add(50, &ctx->connection_congestion_status[connection_id]);
			//test_printk(KERN_ALERT "congestion at connection %d\n", connection_id);
			do{
				ne = ib_poll_cq(ctx->send_cq[connection_id], 1, wc);
				if(ne < 0)
				{
					test_printk(KERN_ALERT "poll send_cq failed at connection %d\n", connection_id);
					return 1;
				}
			}while(ne<1);
		}
		else
			atomic_sub(1, &ctx->connection_congestion_status[connection_id]);
		for(i=0;i<ne;i++)
		{
			if(wc[i].status!=IB_WC_SUCCESS)
			{
				test_printk(KERN_ALERT "send failed at connection %d as %d\n", connection_id, wc[i].status);
				return 2;
			}
		}
	}
	else{
		test_printk(KERN_INFO "send fail %d\n", connection_id);
	}
	//spin_unlock(&connection_lock[connection_id]);
	return ret;
}
int client_send_message_sge_without_lock_and_polling(int connection_id, int type, void *addr, int size, uint64_t inbox_addr, uint64_t inbox_semaphore, int priority, void *output_header_addr)
{	
	struct ib_send_wr wr, *bad_wr = NULL;
    	struct ib_sge sge[2];
    	int ret;

	
	//spin_lock(&connection_lock[connection_id]);
	
    	memset(&wr, 0, sizeof(wr));
    	memset(sge, 0, sizeof(struct ib_sge)*2);
    
	wr.wr_id = type;
	wr.opcode = IB_WR_SEND;
	wr.sg_list = sge;
	wr.num_sge = 2;
	wr.send_flags = IB_SEND_SIGNALED;
	
	//Output header should be processed outside of this function since ending before polling may cause problem (memory space is free without actually sending out)
	//client_setup_ibapi_header(NODE_ID, inbox_addr, inbox_semaphore, size, priority, type, &output_header);
	//output_header_addr = (void *)client_ib_reg_mr_addr(&output_header, sizeof(struct ibapi_header));
	sge[0].addr = (uintptr_t)output_header_addr;
	sge[0].length = sizeof(struct ibapi_header);
	sge[0].lkey = ctx->proc->lkey;
	
	sge[1].addr = (uintptr_t)addr;
	sge[1].length = size;
	sge[1].lkey = ctx->proc->lkey;

	ret = ib_post_send(ctx->qp[connection_id], &wr, &bad_wr);
	return ret;
}
int client_send_message_sge_with_polling_only(int connection_id)
{
	int ne,i;
	struct ib_wc wc[2];
	do{
		ne = ib_poll_cq(ctx->send_cq[connection_id], 1, wc);
		if(ne < 0)
		{
			test_printk(KERN_ALERT "poll send_cq failed at connection %d\n", connection_id);
			return 1;
		}
	}while(ne<1);
	for(i=0;i<ne;i++)
	{
		if(wc[i].status!=IB_WC_SUCCESS)
		{
			test_printk(KERN_ALERT "send failed at connection %d as %d\n", connection_id, wc[i].status);
			return 2;
		}
		else
			break;
	}
	return 0;
	
}

int client_send_request(int connection_id, enum mode s_mode, struct client_ibv_mr *input_mr, void *addr, int size)
{
	struct ib_send_wr wr, *bad_wr = NULL;
	struct ib_sge sge;
	//struct client_ibv_mr *ret;
	int ret;
	uintptr_t tempaddr;
	int ne, i;
	struct ib_wc wc[2];

	int waiting_id = client_get_waiting_id_by_semaphore();
	spin_lock(&connection_lock[connection_id]);
	ctx->thread_state[waiting_id] = TS_WAIT;

	memset(&wr, 0, sizeof(struct ib_send_wr));
	memset(&sge, 0, sizeof(struct ib_sge));

	wr.wr_id = connection_id + waiting_id * WRAP_UP_NUM_FOR_WRID;
	wr.opcode = (s_mode == M_WRITE) ? IB_WR_RDMA_WRITE : IB_WR_RDMA_READ;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.send_flags = IB_SEND_SIGNALED;

	wr.wr.rdma.remote_addr = (uintptr_t) input_mr->addr;
	wr.wr.rdma.rkey = input_mr->rkey;
	//ret = client_ib_reg_mr(ctx->pd, addr, size, IB_ACCESS_LOCAL_WRITE);
	tempaddr = client_ib_reg_mr_addr(addr, size);
	//sge.addr = (uint64_t)ret->addr;
	//sge.length = ret->length;
	//sge.lkey = ret->lkey;
	sge.addr = tempaddr;
	sge.length = size;
	sge.lkey = ctx->proc->lkey;

	ret = ib_post_send(ctx->qp[connection_id], &wr, &bad_wr);
	//while(ctx->thread_state[waiting_id]==TS_WAIT)
	//	cpu_relax();
	if(ret==0){
		do{
			ne = ib_poll_cq(ctx->send_cq[connection_id], 1, wc);
			if(ne < 0)
			{
				test_printk(KERN_ALERT "poll send_cq failed at connection %d\n", connection_id);
				return 1;
			}
		}while(ne<1);
		for(i=0;i<ne;i++)
		{
			if(wc[i].status!=IB_WC_SUCCESS)
			{
				test_printk(KERN_ALERT "send request failed at connection %d as %d\n", connection_id, wc[i].status);
				return 2;
			}
			else
				break;
		}
		
	}
	else{
		test_printk(KERN_INFO "send fail %d\n", connection_id);
	}
	spin_unlock(&connection_lock[connection_id]);
	return 0;
}
int ibapi_rdma_write(int target_node, uint64_t mr_key, void *local_addr, int size, int priority)
{
	int connection_id = client_get_connection_by_atomic_number(target_node, priority);
	struct client_ibv_mr *mr_addr;
	mr_addr = client_id_to_mr(mr_key);
	if(!mr_addr)
		return 1;
	client_send_request(connection_id, M_WRITE, mr_addr, local_addr, size);
	return 0;
}
EXPORT_SYMBOL(ibapi_rdma_write);

int ibapi_rdma_read(int target_node, uint64_t mr_key, void *local_addr, int size, int priority)
{
	int connection_id = client_get_connection_by_atomic_number(target_node, priority);
	struct client_ibv_mr *mr_addr;
	mr_addr = client_id_to_mr(mr_key);
	if(!mr_addr)
		return 1;
	client_send_request(connection_id, M_READ, mr_addr, local_addr, size);
	return 0;
}
EXPORT_SYMBOL(ibapi_rdma_read);

int client_compare_swp(int connection_id, struct client_ibv_mr *remote_mr, void *addr, uint64_t guess_value, uint64_t swp_value)
{
	//test_printk(KERN_CRIT "answer: %llu guess: %llu swp: %llu\n", *(uint64_t *)addr, guess_value, swp_value);
	struct ib_send_wr wr, *bad_wr = NULL;
	struct ib_sge sge;
	uintptr_t tempaddr;
	int ret;
	int ne, i;
	struct ib_wc wc[2];
	//int flags;
	//spin_lock_irqsave(&connection_lock[connection_id], flags);
    
	memset(&wr, 0, sizeof(wr));
	memset(&sge, 0, sizeof(sge));

	wr.wr_id = connection_id;
	wr.opcode = IB_WR_ATOMIC_CMP_AND_SWP;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.send_flags = IB_SEND_SIGNALED;
	wr.wr.atomic.remote_addr = (uintptr_t)remote_mr->addr;
	wr.wr.atomic.rkey = remote_mr->rkey;
	
	wr.wr.atomic.compare_add = guess_value;
	wr.wr.atomic.swap = swp_value;
        
	//ret_mr = client_register_memory_api(connection_id, addr, sizeof(uint64_t), IBV_ACCESS_LOCAL_WRITE);
	tempaddr = client_ib_reg_mr_addr(addr, sizeof(uint64_t));
    
	sge.addr = tempaddr;
	sge.length = sizeof(uint64_t);
	sge.lkey = ctx->proc->lkey;

	ret = ib_post_send(ctx->qp[connection_id], &wr, &bad_wr);
	
	if(ret==0){
		do{
			ne = ib_poll_cq(ctx->send_cq[connection_id], 1, wc);
			if(ne < 0)
			{
				test_printk(KERN_CRIT "poll send_cq failed at connection %d\n", connection_id);
				//spin_unlock_irqrestore(&connection_lock[connection_id], flags);
				return 1;
			}
		}while(ne<1);
		for(i=0;i<ne;i++)
		{
			if(wc[i].status!=IB_WC_SUCCESS)
			{
				test_printk(KERN_CRIT "send cmp request failed at connection %d as %d\n", connection_id, wc[i].status);
				//spin_unlock_irqrestore(&connection_lock[connection_id], flags);
				return 2;
			}
			else
				break;
		}
		
	}
	else{
		test_printk(KERN_INFO "send fail %d\n", connection_id);
	}
	
	//spin_unlock(&connection_lock[connection_id]);

	//Check swp value
	if(memcmp(addr, &guess_value, sizeof(uint64_t))==0)
	{
		//test_printk(KERN_CRIT "answer: %llu guess: %llu\n", *(uint64_t *)addr, guess_value);
		return 0;
	}
	return 1;
}

/*int ibapi_rdma_fetch_add(int target_node, struct client_ibv_mr *mr_addr, void *local_addr, unsigned long long size, int priority)
{
    int connection_id = client_get_connection_by_atomic_number(target_node, priority);
    client_fetch_add(connection_id, mr_addr, local_addr, size);
    return 0;
}*/
int ibapi_rdma_swp(int target_node, struct client_ibv_mr *mr_addr, void *local_addr, unsigned long long guess, unsigned long long swp_value, int priority)
{
    int connection_id = client_get_connection_by_atomic_number(target_node, priority);
    return client_compare_swp(connection_id, mr_addr, local_addr, guess, swp_value);
}
EXPORT_SYMBOL(ibapi_rdma_swp);

int ibapi_send_message(int target_node, void *addr, int size)
{
	int priority = LOW_PRIORITY;
	int connection_id = client_get_connection_by_atomic_number(target_node, priority);
	uintptr_t tempaddr;
	tempaddr = client_ib_reg_mr_addr(addr, size);
	//client_send_message_addr(connection_id, MSG_CLIENT_SEND, (void *)tempaddr, size, 0);
	client_send_message_sge(connection_id, MSG_CLIENT_SEND, (void *)tempaddr, size, 0, 0, priority);

	return connection_id;
}
EXPORT_SYMBOL(ibapi_send_message);

int ibapi_send_reply(int target_node, char *msg, int size, char *output_msg)
{
	uintptr_t tempaddr;
	int priority = LOW_PRIORITY;
    	int wait_send_reply_id;
	int connection_id = client_get_connection_by_atomic_number(target_node, priority);
	wait_send_reply_id = SEND_REPLY_WAIT;
	tempaddr = client_ib_reg_mr_addr(msg, size);
	//client_send_message_addr(connection_id, MSG_GET_SEND_AND_REPLY_1, (void *)tempaddr, size, wait_send_reply_id);
	client_send_message_sge(connection_id, MSG_GET_SEND_AND_REPLY_1, (void *)tempaddr, size, (uint64_t)output_msg, (uint64_t)&wait_send_reply_id, priority);
	while(wait_send_reply_id==SEND_REPLY_WAIT)
		cpu_relax();
	return wait_send_reply_id;
}
EXPORT_SYMBOL(ibapi_send_reply);

int ibapi_send_reply_opt(int target_node, char *msg, int size, void **output_msg)
{
	uintptr_t tempaddr;
	int priority = LOW_PRIORITY;
    	int wait_send_reply_id;
	int connection_id = client_get_connection_by_atomic_number(target_node, priority);
	wait_send_reply_id = SEND_REPLY_WAIT;
	tempaddr = client_ib_reg_mr_addr(msg, size);
	//client_send_message_addr(connection_id, MSG_GET_SEND_AND_REPLY_1, (void *)tempaddr, size, wait_send_reply_id);
	client_send_message_sge(connection_id, MSG_GET_SEND_AND_REPLY_OPT_1, (void *)tempaddr, size, (uint64_t)output_msg, (uint64_t)&wait_send_reply_id, priority);
	while(wait_send_reply_id==SEND_REPLY_WAIT)
		cpu_relax();
	return wait_send_reply_id;
}
EXPORT_SYMBOL(ibapi_send_reply_opt);
int ibapi_atomic_send(int target_node, struct atomic_struct *input_atomic, int length, char *output_msg)
{
	int i;
	int priority = LOW_PRIORITY;
	uintptr_t tempaddr;
	int wait_send_reply_id;
	void *mid_addr;
	int connection_id = client_get_connection_by_atomic_number(target_node, priority);
	//ctx->send_reply_wait_inbox[wait_send_reply_id] = SEND_REPLY_WAIT;
	spin_lock(&connection_lock[connection_id]);
	wait_send_reply_id = SEND_REPLY_WAIT;
	tempaddr = client_ib_reg_mr_addr(&length, sizeof(int));
	test_printk(KERN_CRIT "ibapi_atomic_send tempaddr %lx length %d\n", tempaddr, length);
	client_send_message_sge_without_lock(connection_id, MSG_GET_ATOMIC_START, (void *)tempaddr, sizeof(int), 0, 0, priority);
	test_printk(KERN_CRIT "ibapi_atomic_send sent header\n");
	for(i=0;i<length;i++)
	{
		mid_addr = (void *)client_ib_reg_mr_addr(input_atomic[i].vaddr, input_atomic[i].len);
		//client_send_message_addr_without_lock(connection_id, MSG_GET_ATOMIC_MID, mid_addr, input_atomic[i].length, wait_send_reply_id);
		//printk(KERN_CRIT "regular [%s] req %d paddr %lx len %d\n", __func__, i, mid_addr, input_atomic[i].vaddr, input_atomic[i].len);
		test_printk(KERN_CRIT "ibapi_atomic_send send msg %d paddr %lx vaddr %lx len %d\n", 
				i, mid_addr, input_atomic[i].vaddr, input_atomic[i].len);
		client_send_message_sge_without_lock(connection_id, MSG_GET_ATOMIC_MID, mid_addr, input_atomic[i].len, (uint64_t)output_msg, (uint64_t)&wait_send_reply_id, priority);
		test_printk(KERN_CRIT "ibapi_atomic_send sent msg %d paddr %lx vaddr %lx len %d\n", 
				i, mid_addr, input_atomic[i].vaddr, input_atomic[i].len);
	}
	spin_unlock(&connection_lock[connection_id]);
	while(wait_send_reply_id==SEND_REPLY_WAIT)
		cpu_relax();
	test_printk(KERN_CRIT "ibapi_atomic_send done\n");
	return wait_send_reply_id;
}
EXPORT_SYMBOL(ibapi_atomic_send);

int ibapi_atomic_send_yy(int target_node, struct atomic_struct *input_atomic, int length, char *output_msg)
{
	int i;
	int priority = LOW_PRIORITY;
	uintptr_t tempaddr;
	int wait_send_reply_id;
	void *mid_addr;
	int connection_id = client_get_connection_by_atomic_number(target_node, priority);
	//ctx->send_reply_wait_inbox[wait_send_reply_id] = SEND_REPLY_WAIT;
	spin_lock(&connection_lock[connection_id]);
	wait_send_reply_id = SEND_REPLY_WAIT;
	tempaddr = client_ib_reg_mr_addr(&length, sizeof(int));
	test_printk(KERN_CRIT "yy-ibapi_atomic_send tempaddr %lx length %d\n", tempaddr, length);
	client_send_message_sge_without_lock(connection_id, MSG_GET_ATOMIC_START, (void *)tempaddr, sizeof(int), 0, 0, priority);
	test_printk("ibapi_atomic_send sent header\n");
	for(i=0;i<length;i++)
	{
		if (i > 1)
			mid_addr = (void *)client_ib_reg_mr_phys_addr(input_atomic[i].vaddr, input_atomic[i].len);
		else
			/* The first two metadata requests */
			mid_addr = (void *)client_ib_reg_mr_addr(input_atomic[i].vaddr, input_atomic[i].len);
		
		//client_send_message_addr_without_lock(connection_id, MSG_GET_ATOMIC_MID, mid_addr, input_atomic[i].length, wait_send_reply_id);
		test_printk("ibapi_atomic_send send msg %d paddr %lx vaddr %lx len %d\n", 
				i, mid_addr, input_atomic[i].vaddr, input_atomic[i].len);
		client_send_message_sge_without_lock(connection_id, MSG_GET_ATOMIC_MID, mid_addr, input_atomic[i].len, (uint64_t)output_msg, (uint64_t)&wait_send_reply_id, priority);
		test_printk("ibapi_atomic_send sent msg %d paddr %lx vaddr %lx len %d\n", 
				i, mid_addr, input_atomic[i].vaddr, input_atomic[i].len);
	}
	spin_unlock(&connection_lock[connection_id]);
	while(wait_send_reply_id==SEND_REPLY_WAIT)
		cpu_relax();
	test_printk("ibapi_atomic_send done\n");
	return wait_send_reply_id;
}
EXPORT_SYMBOL(ibapi_atomic_send_yy);

int ibapi_atomic_single_send_yy(int target_node, struct atomic_struct *input_atomic, int length)
{
	int i;
	int priority = LOW_PRIORITY;
	uintptr_t tempaddr;
	void *mid_addr;
	int connection_id = client_get_connection_by_atomic_number(target_node, priority);
	//ctx->send_reply_wait_inbox[wait_send_reply_id] = SEND_REPLY_WAIT;
	spin_lock(&connection_lock[connection_id]);
	tempaddr = client_ib_reg_mr_addr(&length, sizeof(int));
//	printk(KERN_CRIT "ibapi_atomic_send tempaddr %lx length %d\n", tempaddr, length);
	client_send_message_sge_without_lock(connection_id, MSG_GET_ATOMIC_SINGLE_START, (void *)tempaddr, sizeof(int), 0, 0, priority);
//	printk(KERN_CRIT "ibapi_atomic_send sent header\n");
	for(i=0;i<length;i++)
	{
		if (i > 1)
		mid_addr = (void *)client_ib_reg_mr_phys_addr(input_atomic[i].vaddr, input_atomic[i].len);
		else
		mid_addr = (void *)client_ib_reg_mr_addr(input_atomic[i].vaddr, input_atomic[i].len);
		//client_send_message_addr_without_lock(connection_id, MSG_GET_ATOMIC_MID, mid_addr, input_atomic[i].length, wait_send_reply_id);
//		printk(KERN_CRIT "ibapi_atomic_send send msg %d paddr %lx vaddr %lx len %d\n", 
//				i, mid_addr, input_atomic[i].vaddr, input_atomic[i].len);
		client_send_message_sge_without_lock(connection_id, MSG_GET_ATOMIC_SINGLE_MID, mid_addr, input_atomic[i].len, 0, 0, priority);
//		printk(KERN_CRIT "ibapi_atomic_send sent msg %d paddr %lx vaddr %lx len %d\n", 
//				i, mid_addr, input_atomic[i].vaddr, input_atomic[i].len);
	}
	spin_unlock(&connection_lock[connection_id]);
	return 0;
}
EXPORT_SYMBOL(ibapi_atomic_single_send_yy);

int ibapi_multi_atomic_send(int number_of_node, int *target_node, struct atomic_struct **input_atomic, int *length, struct max_reply_msg *output_msg)
{
	int i, j;
	void **output_header_addr, **first_header_addr;
	struct atomic_struct *ptr;

	struct ibapi_header *first_packet_header, *other_packet_header;
	int *connection_id_array;
	uintptr_t *length_addr_array;
	void **mid_addr;

	if (!output_msg || !target_node || !input_atomic || !length)
		return -1;
	spin_lock(&multicast_lock);//Need to ensure that there is only one multicast at a single time in order to avoid potential deadlock resource handling problem
	//spin_lock_irqsave(&multicast_lock, multicast_flags);
	
	first_packet_header = ctx->first_packet_header;
	other_packet_header = ctx->other_packet_header;
	connection_id_array = ctx->connection_id_array;
	length_addr_array = ctx->length_addr_array;
	output_header_addr = ctx->output_header_addr;
	first_header_addr = ctx->first_header_addr;
	mid_addr = ctx->mid_addr;
	for(j=0;j<number_of_node;j++)
	{
		connection_id_array[j] = client_get_connection_by_atomic_number(target_node[j], LOW_PRIORITY);
		spin_lock(&connection_lock[connection_id_array[j]]);
		output_msg[j].length = SEND_REPLY_WAIT;
		length_addr_array[j] = client_ib_reg_mr_addr(&length[j], sizeof(int));
		
		client_setup_ibapi_header(NODE_ID, 0, 0, sizeof(int), LOW_PRIORITY, MSG_GET_ATOMIC_START, &first_packet_header[j]);
		first_header_addr[j] = (void *)client_ib_reg_mr_addr(&first_packet_header[j], sizeof(struct ibapi_header));
		client_send_message_sge_without_lock_and_polling(connection_id_array[j], MSG_GET_ATOMIC_START, (void *)length_addr_array[j], sizeof(int), 0, 0, LOW_PRIORITY, first_header_addr[j]);
		test_printk(KERN_CRIT "atomic_send to connection %d with length %d start\n", connection_id_array[j], length[j]);
		//client_send_message_sge_with_polling_only(connection_id_array[j]);
		ptr = input_atomic[j];
		for(i=0;i<length[j];i++)
		{
			mid_addr[j*MAX_MULTICAST_HOP+i] = (void *)client_ib_reg_mr_addr(ptr[i].vaddr, ptr[i].len);
			client_setup_ibapi_header(NODE_ID, (uint64_t)output_msg[j].msg, (uint64_t)&output_msg[j].length, ptr[i].len, LOW_PRIORITY, MSG_GET_ATOMIC_MID, &other_packet_header[j*MAX_MULTICAST_HOP+i]);
			test_printk(KERN_CRIT "[%s] req %d paddr %lx len %d mid_addr %lx\n", __func__, i, ptr[i].vaddr, ptr[i].len, mid_addr[j*MAX_MULTICAST_HOP+i]);
			output_header_addr[j*MAX_MULTICAST_HOP+i] = (void *)client_ib_reg_mr_addr(&other_packet_header[j*MAX_MULTICAST_HOP+i], sizeof(struct ibapi_header));
			client_send_message_sge_without_lock_and_polling(connection_id_array[j], MSG_GET_ATOMIC_MID, mid_addr[j*MAX_MULTICAST_HOP+i], ptr[i].len, (uint64_t)output_msg[j].msg, (uint64_t)&output_msg[j].length, LOW_PRIORITY, output_header_addr[j*MAX_MULTICAST_HOP+i]);
			//client_send_message_sge_with_polling_only(connection_id_array[j]);
		}
		test_printk(KERN_CRIT "atomic_send to connection %d with length %d end\n", connection_id_array[j], length[j]);
	}
	for(j=0;j<number_of_node;j++)
	{
		for(i=0;i<length[j]+1;i++)//+1 is using to match the first packet inside atomic send
			client_send_message_sge_with_polling_only(connection_id_array[j]);
		spin_unlock(&connection_lock[connection_id_array[j]]);
	}
	spin_unlock(&multicast_lock);
	for(j=0;j<number_of_node;j++)
	{
		//test_printk(KERN_CRIT "atomic_send %d with len %d to %d\n", j, length[j], connection_id_array[j]);
		//for(i=0;i<length[j]+1;i++)//+1 is using to match the first packet inside atomic send
		//{
		//	client_send_message_sge_with_polling_only(connection_id_array[j]);
		//}
		while(output_msg[j].length==SEND_REPLY_WAIT)
			cpu_relax();
		//spin_unlock(&connection_lock[connection_id_array[j]]);
		test_printk(KERN_CRIT "output_msg[j].length %d\n", output_msg[j].length);
		test_printk(KERN_CRIT "[%s] replymsg %p\n", __func__, output_msg[j]);
	}
	//spin_unlock_irqrestore(&multicast_lock, multicast_flags);
	return 0;
}
EXPORT_SYMBOL(ibapi_multi_atomic_send);

int ibapi_multi_atomic_send_yy(int number_of_node, int *target_node, struct atomic_struct **input_atomic, int *length, struct max_reply_msg *output_msg)
{
	int i, j;
	void **output_header_addr, **first_header_addr;
	struct atomic_struct *ptr;
	struct ibapi_header *first_packet_header, *other_packet_header;
	int *connection_id_array;
	uintptr_t *length_addr_array;
	void **mid_addr;

	if (!output_msg || !target_node || !input_atomic || !length)
		return -1;

	spin_lock(&multicast_lock);//Need to ensure that there is only one multicast at a single time in order to avoid potential deadlock resource handling problem
	//spin_lock_irqsave(&multicast_lock, multicast_flags);
	
	first_packet_header = ctx->first_packet_header;
	other_packet_header = ctx->other_packet_header;
	connection_id_array = ctx->connection_id_array;
	length_addr_array = ctx->length_addr_array;
	output_header_addr = ctx->output_header_addr;
	first_header_addr = ctx->first_header_addr;
	mid_addr = ctx->mid_addr;
	for(j=0;j<number_of_node;j++)
	{
		connection_id_array[j] = client_get_connection_by_atomic_number(target_node[j], LOW_PRIORITY);
		spin_lock(&connection_lock[connection_id_array[j]]);
		output_msg[j].length = SEND_REPLY_WAIT;
		length_addr_array[j] = client_ib_reg_mr_addr(&length[j], sizeof(int));
		
		client_setup_ibapi_header(NODE_ID, 0, 0, sizeof(int), LOW_PRIORITY, MSG_GET_ATOMIC_START, &first_packet_header[j]);
		first_header_addr[j] = (void *)client_ib_reg_mr_addr(&first_packet_header[j], sizeof(struct ibapi_header));
		test_printk(KERN_CRIT "yy-send to %d with length %d start\n", connection_id_array[j], length[j]);
		client_send_message_sge_without_lock_and_polling(connection_id_array[j], MSG_GET_ATOMIC_START, (void *)length_addr_array[j], sizeof(int), 0, 0, LOW_PRIORITY, first_header_addr[j]);
		//client_send_message_sge_with_polling_only(connection_id_array[j]);
		
		ptr = input_atomic[j];
		for(i=0;i<length[j];i++)
		{
			if (i > 1)
				mid_addr[j*MAX_MULTICAST_HOP+i] = (void *)client_ib_reg_mr_phys_addr(ptr[i].vaddr, ptr[i].len);
			else
				mid_addr[j*MAX_MULTICAST_HOP+i] = (void *)client_ib_reg_mr_addr(ptr[i].vaddr, ptr[i].len);
			test_printk(KERN_CRIT "yy[%s] req %d paddr %lx len %d mid_addr %lx\n", __func__, i, ptr[i].vaddr, ptr[i].len, mid_addr[j*MAX_MULTICAST_HOP+i]);
			client_setup_ibapi_header(NODE_ID, (uint64_t)output_msg[j].msg, (uint64_t)&output_msg[j].length, ptr[i].len, LOW_PRIORITY, MSG_GET_ATOMIC_MID, &other_packet_header[j*MAX_LENGTH_OF_ATOMIC+i]);
			output_header_addr[j*MAX_LENGTH_OF_ATOMIC+i] = (void *)client_ib_reg_mr_addr(&other_packet_header[j*MAX_LENGTH_OF_ATOMIC+i], sizeof(struct ibapi_header));
			client_send_message_sge_without_lock_and_polling(connection_id_array[j], MSG_GET_ATOMIC_MID, mid_addr[j*MAX_MULTICAST_HOP+i], ptr[i].len, (uint64_t)output_msg[j].msg, (uint64_t)&output_msg[j].length, LOW_PRIORITY, output_header_addr[j*MAX_LENGTH_OF_ATOMIC+i]);
			//client_send_message_sge_with_polling_only(connection_id_array[j]);
			//printk(KERN_CRIT "[%s] after send req %d paddr %lx len %d mid_addr %lx\n", __func__, i, ptr[i].vaddr, ptr[i].len, mid_addr);
		}
		test_printk(KERN_CRIT "yy-send to %d with length %d end \n", connection_id_array[j], length[j]);
		test_printk(KERN_CRIT "[%s] after all send\n", __func__);
	}
	for(j=0;j<number_of_node;j++)
	{
		for(i=0;i<length[j]+1;i++)//+1 is using to match the first packet inside atomic send
		{
			client_send_message_sge_with_polling_only(connection_id_array[j]);
			//printk(KERN_CRIT "[%s] after send poll req %d\n", __func__, i);
		}
		spin_unlock(&connection_lock[connection_id_array[j]]);
	}
	spin_unlock(&multicast_lock);
	for(j=0;j<number_of_node;j++)
	{
		test_printk(KERN_CRIT "yy-atomic_multi_send to %d with len %d to %d\n", j, length[j], connection_id_array[j]);
		//for(i=0;i<length[j]+1;i++)//+1 is using to match the first packet inside atomic send
		//{
		//	client_send_message_sge_with_polling_only(connection_id_array[j]);
			//printk(KERN_CRIT "[%s] after send poll req %d\n", __func__, i);
		//}
		//printk(KERN_CRIT "[%s] after all send poll req\n", __func__);
		while(output_msg[j].length==SEND_REPLY_WAIT)
			cpu_relax();
		output_msg[j].length = output_msg[j].length;
		//printk(KERN_CRIT "[%s:%d] First INT: %d, of node %d", __func__, __LINE__, *((int *)(&output_msg[j])), j);
		//spin_unlock(&connection_lock[connection_id_array[j]]);
		//printk(KERN_CRIT "output_msg[j].length %d\n", output_msg[j].length);
	}
	//spin_unlock_irqrestore(&multicast_lock, multicast_flags);
	//spin_unlock(&multicast_lock);
	return 0;
}
EXPORT_SYMBOL(ibapi_multi_atomic_send_yy);
uint64_t ibapi_alloc_remote_mem(int target_node, int size)
{
	uintptr_t tempaddr;
	int wait_send_reply_id;
	struct client_ibv_mr *ret_mr = (struct client_ibv_mr *)kmalloc(sizeof(struct client_ibv_mr), GFP_KERNEL);
	int connection_id = client_get_connection_by_atomic_number(target_node, LOW_PRIORITY);
	uint64_t ret_key;

	wait_send_reply_id = SEND_REPLY_WAIT;
	tempaddr = client_ib_reg_mr_addr(&size, sizeof(int));
	//client_send_message_addr(connection_id, MSG_GET_REMOTEMR, (void *)tempaddr, sizeof(int), wait_send_reply_id);
	client_send_message_sge(connection_id, MSG_GET_REMOTEMR, (void *)tempaddr, sizeof(int), (uint64_t)ret_mr, (uint64_t)&wait_send_reply_id, LOW_PRIORITY);

	while(wait_send_reply_id==SEND_REPLY_WAIT)
		cpu_relax();
	ret_key = client_hash_mr(ret_mr);
	return ret_key;
}
EXPORT_SYMBOL(ibapi_alloc_remote_mem);

int ibapi_multi_send_reply(int number_of_target, int *target_array, struct atomic_struct *input_atomic, struct max_reply_msg* reply)
{
	int i;
	int *connection_id_array;
	struct ibapi_header *ibapi_header_array;
	void **first_header_addr;
	unsigned long multicast_flags;
	uintptr_t *length_addr_array;
	//spin_lock(&multicast_lock);//Need to ensure that there is only one multicast at a single time in order to avoid potential deadlock resource handling problem
	spin_lock_irqsave(&multicast_lock, multicast_flags);
	
	ibapi_header_array = ctx->first_packet_header;
	connection_id_array = ctx->connection_id_array;
	length_addr_array = ctx->length_addr_array;
	first_header_addr = ctx->first_header_addr;
	if(number_of_target>MAX_MULTICAST_HOP)
	{
		printk(KERN_CRIT "too many targets. limitation: %d\n", MAX_MULTICAST_HOP);
		spin_unlock_irqrestore(&multicast_lock, multicast_flags);
		return 1;
	}
	for(i=0;i<number_of_target;i++)//setup all the reply information and get all the resources and send out the message without polling
	{
		connection_id_array[i] = client_get_connection_by_atomic_number(target_array[i], LOW_PRIORITY);
		reply[i].length = SEND_REPLY_WAIT;
		//Lock the connection
		spin_lock(&connection_lock[connection_id_array[i]]);

		length_addr_array[i] = client_ib_reg_mr_addr(input_atomic[i].vaddr, input_atomic[i].len);
		
		//Output header should be processed outside of this function since ending before polling may cause problem (memory space is free without actually sending out)
		client_setup_ibapi_header(NODE_ID, (uint64_t)reply[i].msg, (uint64_t)&reply[i].length, input_atomic[i].len, LOW_PRIORITY, MSG_GET_SEND_AND_REPLY_1, &ibapi_header_array[i]);
		first_header_addr[i] = (void *)client_ib_reg_mr_addr(&ibapi_header_array[i], sizeof(struct ibapi_header));

		test_printk(KERN_CRIT "multi send reply to %d with length %d\n", connection_id_array[i], input_atomic[i].len);
		client_send_message_sge_without_lock_and_polling(connection_id_array[i], MSG_GET_SEND_AND_REPLY_1, (void *)length_addr_array[i], input_atomic[i].len, (uint64_t)reply[i].msg, (uint64_t)&reply[i].length, LOW_PRIORITY, first_header_addr[i]);
	}
	for(i=0;i<number_of_target;i++)//Do polling for each used connection
	{
		client_send_message_sge_with_polling_only(connection_id_array[i]);
		spin_unlock(&connection_lock[connection_id_array[i]]);
	}
	spin_unlock_irqrestore(&multicast_lock, multicast_flags);
	for(i=0;i<number_of_target;i++)//Get data from each send_reply
	{
		while(reply[i].length==SEND_REPLY_WAIT)
			cpu_relax();
		//spin_unlock(&connection_lock[connection_id_array[i]]);
	}
	//spin_unlock_irqrestore(&multicast_lock, multicast_flags);
	//spin_unlock(&multicast_lock);
	return 0;
}
EXPORT_SYMBOL(ibapi_multi_send_reply);
int ibapi_multi_send(int number_of_target, int *target_array, struct atomic_struct *input_atomic)
{
	int i;
	int *connection_id_array;
	struct ibapi_header *ibapi_header_array;
	void **first_header_addr;
	unsigned long multicast_flags;
	uintptr_t *length_addr_array;
	spin_lock_irqsave(&multicast_lock, multicast_flags);
	connection_id_array = ctx->connection_id_array;
	ibapi_header_array = ctx->first_packet_header;
	length_addr_array = ctx->length_addr_array;
	first_header_addr = ctx->first_header_addr;

	if(number_of_target>MAX_MULTICAST_HOP)
	{
		printk(KERN_CRIT "too many targets. limitation: %d\n", MAX_MULTICAST_HOP);
		spin_unlock_irqrestore(&multicast_lock, multicast_flags);
		return 1;
	}
	//spin_lock(&multicast_lock);//Need to ensure that there is only one multicast at a single time in order to avoid potential deadlock resource handling problem
	for(i=0;i<number_of_target;i++)//setup all the reply information and get all the resources and send out the message without polling
	{
		connection_id_array[i] = client_get_connection_by_atomic_number(target_array[i], LOW_PRIORITY);
		spin_lock(&connection_lock[connection_id_array[i]]);

		length_addr_array[i] = client_ib_reg_mr_addr(input_atomic[i].vaddr, input_atomic[i].len);
		
		//Output header should be processed outside of this function since ending before polling may cause problem (memory space is free without actually sending out)
		client_setup_ibapi_header(NODE_ID, 0, 0, input_atomic[i].len, LOW_PRIORITY, MSG_CLIENT_SEND, &ibapi_header_array[i]);
		first_header_addr[i] = (void *)client_ib_reg_mr_addr(&ibapi_header_array[i], sizeof(struct ibapi_header));
		
		//client_send_message_addr_without_lock_and_polling(connection_id_array[i], MSG_CLIENT_SEND, mid_addr, input_atomic[i].length, 0);
		client_send_message_sge_without_lock_and_polling(connection_id_array[i], MSG_CLIENT_SEND, (void *)length_addr_array[i], input_atomic[i].len, 0, 0, LOW_PRIORITY, first_header_addr[i]);
	}
	for(i=0;i<number_of_target;i++)//Do polling for each used connection
		client_send_message_sge_with_polling_only(connection_id_array[i]);
	for(i=0;i<number_of_target;i++)//Get data from each send_reply
		spin_unlock(&connection_lock[connection_id_array[i]]);
	//spin_unlock(&multicast_lock);
	spin_unlock_irqrestore(&multicast_lock, multicast_flags);
	return 0;
}
EXPORT_SYMBOL(ibapi_multi_send);


int ibapi_create_lock(int target_node, char *msg, int size, remote_spinlock_t *output_mr)
{
	int connection_id;
	int wait_send_reply_id;
	uintptr_t tempaddr;
	if(target_node!=SERVER_ID)
	{
		test_printk(KERN_CRIT "%d is not server: 0\n", target_node);
		return 1;
	}
	connection_id = client_get_connection_by_atomic_number(target_node, HIGH_PRIORITY);
	wait_send_reply_id = SEND_REPLY_WAIT;	
	tempaddr = client_ib_reg_mr_addr(msg, size);
	//client_send_message_addr(connection_id, MSG_CREATE_LOCK, (void *)tempaddr, size, wait_send_reply_id);
	client_send_message_sge(connection_id, MSG_CREATE_LOCK, (void *)tempaddr, size, (uint64_t)output_mr, (uint64_t)&wait_send_reply_id, HIGH_PRIORITY);
	while(wait_send_reply_id==SEND_REPLY_WAIT)
		cpu_relax();
	return wait_send_reply_id;
}
EXPORT_SYMBOL(ibapi_create_lock);

int ibapi_ask_lock(int target_node, int target_num, remote_spinlock_t *output_mr)
{
	int connection_id;
	int wait_send_reply_id;
	uintptr_t tempaddr;
	uint64_t empty_check=0;
	if(target_node!=SERVER_ID)
	{
		test_printk(KERN_CRIT "%d is not server: 0\n", target_node);
		return 1;
	}
	connection_id = client_get_connection_by_atomic_number(target_node, HIGH_PRIORITY);
	wait_send_reply_id = SEND_REPLY_WAIT;
	tempaddr = client_ib_reg_mr_addr(&target_num, sizeof(int));
	//client_send_message_addr(connection_id, MSG_ASK_LOCK, (void *)tempaddr, sizeof(int), wait_send_reply_id);
	client_send_message_sge(connection_id, MSG_ASK_LOCK, (void *)tempaddr, sizeof(int), (uint64_t)output_mr, (uint64_t)&wait_send_reply_id, HIGH_PRIORITY);
	while(wait_send_reply_id==SEND_REPLY_WAIT)
		cpu_relax();
	if(memcmp(output_mr, &empty_check, sizeof(uint64_t))==0)//FAIL 
		return 1;
	else
		return 0;
}
EXPORT_SYMBOL(ibapi_ask_lock);

int ibapi_lock(remote_spinlock_t *input_key)
{
	uint64_t guess = LOCK_AVAILABLE;
	uint64_t swp = LOCK_LOCK;
	uint64_t ret;
	int test;
	unsigned long flags;
	int connection_id;
	//test_printk(KERN_CRIT "test interrupt %d:%d\n", t_id, smp_processor_id());
	//local_irq_save(flagBig);
	//test_printk(KERN_CRIT "disable interrupt %d:%d\n", t_id, smp_processor_id());
    	connection_id = client_get_connection_by_atomic_number(SERVER_ID, KEY_PRIORITY);
	spin_lock_irqsave(&connection_lock[connection_id], flags);
    	test = client_compare_swp(connection_id, input_key, &ret, guess, swp);
	if(!test)
	{
		//test_printk(KERN_CRIT "lock success %d %llu\n", test, ret);
		//local_irq_restore(flags);
		spin_unlock_irqrestore(&connection_lock[connection_id], flags);
		//local_irq_restore(flagBig);
		return 0;
	}
	else
	{
		int wait_send_reply_id;
		uintptr_t tempaddr;
		uint64_t assigned_key_from_server=0;
		
		//test_printk(KERN_CRIT "%d lock 1st trial fail %d %d\n", t_id, test, ret);
		//Please be aware that this design works (only when)/(since) the mr.addr is identical to the virtual address in the server side
		wait_send_reply_id = SEND_REPLY_WAIT;
		tempaddr = client_ib_reg_mr_addr(input_key, sizeof(struct client_ibv_mr));
		//client_send_message_addr_without_lock(connection_id, MSG_RESERVE_LOCK, (void *)tempaddr, sizeof(struct client_ibv_mr), wait_send_reply_id);
		client_send_message_sge_without_lock(connection_id, MSG_RESERVE_LOCK, (void *)tempaddr, sizeof(struct client_ibv_mr), (uint64_t)&assigned_key_from_server, (uint64_t)&wait_send_reply_id, KEY_PRIORITY);	
		spin_unlock_irqrestore(&connection_lock[connection_id], flags);	

		while(wait_send_reply_id==SEND_REPLY_WAIT)
			cpu_relax();

		//test = ibapi_rdma_swp(SERVER_ID, input_key, &ret, assigned_key_from_server, swp, HIGH_PRIORITY);
		spin_lock_irqsave(&connection_lock[connection_id], flags);
    		test = client_compare_swp(connection_id, input_key, &ret, assigned_key_from_server, swp);
		spin_unlock_irqrestore(&connection_lock[connection_id], flags);
		
		//local_irq_restore(flagBig);
		
		if(!test)
		{
			//test_printk(KERN_CRIT "%d:%d lock success finally with assigned %llu and %llu\n", t_id, wait_send_reply_id, assigned_key_from_server, ret);
			return 0;
		}
		else
		{
			test_printk(KERN_CRIT "Second trial fail assigned:%llu ret:%llu\n", assigned_key_from_server, ret);
			return 1;
		}
	}
	return 0;
}
EXPORT_SYMBOL(ibapi_lock);

int ibapi_unlock(remote_spinlock_t *input_key)
{
	uint64_t guess = LOCK_LOCK;
	uint64_t swp = LOCK_USED;
	uint64_t ret;
	int test;
    	int connection_id = client_get_connection_by_atomic_number(SERVER_ID, KEY_PRIORITY);
	unsigned long flags;
       	//local_irq_save(flags); 
	//test = ibapi_rdma_swp(SERVER_ID, input_key, &ret, guess, swp, HIGH_PRIORITY);
	//local_irq_restore(flags);
	//if(i>=1499)
	//	test_printk(KERN_CRIT "%d last unlock test\n",t_id);
	//test_printk(KERN_CRIT "Prepare to do unlock %d\n", t_id);
	//spin_lock(&connection_lock[connection_id]);
	spin_lock_irqsave(&connection_lock[connection_id], flags);
    	test = client_compare_swp(connection_id, input_key, &ret, guess, swp);
	//spin_unlock(&connection_lock[connection_id]);
	spin_unlock_irqrestore(&connection_lock[connection_id], flags);
	if(!test)
	{
//		if(i>=1499)
//			test_printk(KERN_CRIT "%d unlock success %llu\n", t_id, ret);
		return 0;
	}
	else
	{
		test_printk(KERN_CRIT "unlock fail %llu\n", ret);
		return 0;
	}
	return 0;
}
EXPORT_SYMBOL(ibapi_unlock);
void client_free_recv_buf(void *input_buf)
{
	kmem_cache_free(post_receive_cache, input_buf);
}
EXPORT_SYMBOL(client_free_recv_buf);
void ibapi_free_recv_buf(void *input_buf)
{
	kmem_cache_free(post_receive_cache, input_buf);
}
EXPORT_SYMBOL(ibapi_free_recv_buf);

inline void get_cycle_start(void)
{
	cycle_start = get_cycles();
}
void get_cycle_end(void)
{
	cycle_end = get_cycles();
	test_printk(KERN_ALERT "inner run for %llu\n", cycle_end-cycle_start);
}

inline void get_time_start(void)
{
	time_start = ktime_get();
}
void get_time_end(void)
{
	time_end = ktime_get();
	test_printk(KERN_ALERT "run for %lld\n", (long long) ktime_to_ns(ktime_sub(time_end, time_start)));
}
void get_time_difference(int tid, ktime_t inputtime)
{
	time_end = ktime_get();
	test_printk(KERN_ALERT "thread %d run for %lld\n", tid, (long long) ktime_to_ns(ktime_sub(time_end, inputtime)));
}
int mid_send(int *a)
{
	ktime_t self_time;
	char *test;
	int i;
	int j=*a;
	int priority;
	if(j==3)
		priority=HIGH_PRIORITY;
	else
		priority=LOW_PRIORITY;
	test = kmalloc(4096*sizeof(char), GFP_KERNEL);
	memset(test, 0x7b, 4096);
	test_printk(KERN_ALERT "start send\n");
	//get_time_start();
	self_time = ktime_get();
	for(i=0;i<250;i++)
	{
		ibapi_send_message(1, test, 4096);
		//test_printk("%d %d\n", j, ibapi_send_message(1, test, 4096, priority));
	}
	get_time_difference(j, self_time);
	do_exit(0);
	return 0;
}
int mid_send_reply(int *a)
{	
	char *ttest;
	char *reply;
	int i;
	int j = *a;
	ktime_t self_time;
	int ret;
	printk(KERN_INFO "start send/reply\n");
	ttest = kmalloc(4096*sizeof(char), GFP_KERNEL);
	reply = kmalloc(5192*sizeof(char), GFP_KERNEL);
	memset(ttest, 0x70, 4096);
	self_time = ktime_get();
	for(i=0;i<100;i++)	
		ret = ibapi_send_reply(1, ttest, 4096, reply);
	//test_printk(KERN_CRIT "%.*s\n", ret, reply);
	//get_time_difference();
	get_time_difference(j, self_time);
	return 0;
}
int mid_atomic_send(int *t_input)
{
	char *a, *b, *c, *d, *e, *reply;
	struct atomic_struct *temp_ato;
	int ret;
	int i;
	int j = *t_input;
	ktime_t self_time;
	temp_ato = kmalloc(sizeof(struct atomic_struct)*16, GFP_KERNEL);
	reply = kmalloc(4096, GFP_KERNEL);
	a = kmalloc(512, GFP_KERNEL);
	b = kmalloc(512, GFP_KERNEL);
	c = kmalloc(512, GFP_KERNEL);
	d = kmalloc(512, GFP_KERNEL);
	e = kmalloc(512, GFP_KERNEL);
	memset(a, 0x7a, 512);
	memset(b, 0x7b, 512);
	memset(c, 0x7c, 512);
	memset(d, 0x7d, 512);
	memset(e, 0x7e, 512);
	temp_ato[0].vaddr = a;
	temp_ato[0].len = 512;
	temp_ato[1].vaddr = b;
	temp_ato[1].len = 512;
	temp_ato[2].vaddr = c;
	temp_ato[2].len = 512;
	temp_ato[3].vaddr = d;
	temp_ato[3].len = 512;
	temp_ato[4].vaddr = e;
	temp_ato[4].len = 512;
	self_time = ktime_get();
	for(i=0;i<100;i++)	
		ret = ibapi_atomic_send(1, temp_ato, 5, reply);
	get_time_difference(j, self_time);
	return 0;
}
int mid_multi_atomic_send(int *t_input)
{
	char *a, *b, *c, *d, *e;
	struct atomic_struct *temp_ato;
	struct atomic_struct **big_ato;
	int *target_array;
	int i;
	struct max_reply_msg *reply;
	int *atomic_length;
	int j = *t_input;
	ktime_t self_time;
	target_array = kmalloc(sizeof(int)*16, GFP_KERNEL);
	target_array[0] = 0;
	target_array[1] = 1;
	target_array[2] = 2;
	target_array[3] = 3;
	big_ato = kmalloc(sizeof(struct atomic_struct*)*16, GFP_KERNEL);
	reply = kmalloc(sizeof(struct max_reply_msg) * 16, GFP_KERNEL);
	atomic_length = kmalloc(sizeof(int)*16, GFP_KERNEL);
	for(i=0;i<4;i++)
	{
		temp_ato = kmalloc(sizeof(struct atomic_struct)*16, GFP_KERNEL);
		reply = kmalloc(4096, GFP_KERNEL);
		a = kmalloc(512, GFP_KERNEL);
		b = kmalloc(512, GFP_KERNEL);
		c = kmalloc(512, GFP_KERNEL);
		d = kmalloc(512, GFP_KERNEL);
		e = kmalloc(512, GFP_KERNEL);
		memset(a, 0x7a, 512);
		memset(b, 0x7b, 512);
		memset(c, 0x7c, 512);
		memset(d, 0x7d, 512);
		memset(e, 0x7e, 512);
		temp_ato[0].vaddr = a;
		temp_ato[0].len = 512;
		temp_ato[1].vaddr = b;
		temp_ato[1].len = 512;
		temp_ato[2].vaddr = c;
		temp_ato[2].len = 512;
		temp_ato[3].vaddr = d;
		temp_ato[3].len = 512;
		temp_ato[4].vaddr = e;
		temp_ato[4].len = 512;
		atomic_length[i] = 5;
		big_ato[i]=temp_ato;
	}
	//for(i=0;i<4;i++)
	//{
	//	test_printk(KERN_ALERT "atomic %d from target %d:%.*s\n", i, target_array[i], reply[i].length, reply[i].msg);
	//}
	self_time = ktime_get();
	for(i=0;i<50;i++)
	{
		ibapi_multi_atomic_send(4, target_array, big_ato, atomic_length, reply);
	}
	get_time_difference(j, self_time);
	return 0;
}
int mid_multi_send_reply(int *t_input)
{
	char *a, *b, *c, *d;
	struct max_reply_msg *reply;
	struct atomic_struct *temp_ato;
	int number_of_target = 4;
	int *target_array;
	int i;
	int j = *t_input;
	ktime_t self_time;
	target_array = kmalloc(sizeof(int)*number_of_target, GFP_KERNEL);
	temp_ato = kmalloc(sizeof(struct atomic_struct)*number_of_target, GFP_KERNEL);
	reply = kmalloc(sizeof(struct max_reply_msg)*number_of_target, GFP_KERNEL);
	a = kmalloc(512, GFP_KERNEL);
	b = kmalloc(512, GFP_KERNEL);
	c = kmalloc(512, GFP_KERNEL);
	d = kmalloc(512, GFP_KERNEL);
	memset(a, 0x7a, 512);
	memset(b, 0x7b, 512);
	memset(c, 0x7c, 512);
	memset(d, 0x7d, 512);
	temp_ato[0].vaddr = a;
	temp_ato[0].len = 512;
	temp_ato[1].vaddr = b;
	temp_ato[1].len = 512;
	temp_ato[2].vaddr = c;
	temp_ato[2].len = 512;
	temp_ato[3].vaddr = d;
	temp_ato[3].len = 512;
	target_array[0] = 0;
	target_array[1] = 1;
	target_array[2] = 2;
	target_array[3] = 3;
	//for(i=0;i<4;i++)
	//{
	//	test_printk(KERN_CRIT "%d:%.*s\n", reply[i].length, reply[i].length, reply[i].msg);
	//}
	self_time = ktime_get();
	for(i=0;i<50;i++)
	{
		ibapi_multi_send_reply(4, target_array, temp_ato, reply);
	}
	get_time_difference(j, self_time);
	return 0;
}
int mid_multi_send(int *t_input)
{
	char *a, *b, *c, *d;
	struct atomic_struct *temp_ato;
	int number_of_target = 4;
	int *target_array;
	int j = *t_input;
	int i;
	ktime_t self_time;
	target_array = kmalloc(sizeof(int)*number_of_target, GFP_KERNEL);
	temp_ato = kmalloc(sizeof(struct atomic_struct)*number_of_target, GFP_KERNEL);
	a = kmalloc(512, GFP_KERNEL);
	b = kmalloc(512, GFP_KERNEL);
	c = kmalloc(512, GFP_KERNEL);
	d = kmalloc(512, GFP_KERNEL);
	memset(a, 0x7a, 512);
	memset(b, 0x7b, 512);
	memset(c, 0x7c, 512);
	memset(d, 0x7d, 512);
	temp_ato[0].vaddr = a;
	temp_ato[0].len = 512;
	temp_ato[1].vaddr = b;
	temp_ato[1].len = 512;
	temp_ato[2].vaddr = c;
	temp_ato[2].len = 512;
	temp_ato[3].vaddr = d;
	temp_ato[3].len = 512;
	target_array[0] = 0;
	target_array[1] = 1;
	target_array[2] = 2;
	target_array[3] = 3;
	self_time = ktime_get();
	for(i=0;i<50;i++)
	{
		ibapi_multi_send(4, target_array, temp_ato);
	}
	get_time_difference(j, self_time);
	return 0;
}
int ibapi_reg_send_handler(int (*input_funptr)(char *addr, uint32_t size, int sender_id))
{
	ctx->send_handler = input_funptr;
	return 0;
}
EXPORT_SYMBOL(ibapi_reg_send_handler);
int ibapi_reg_send_reply_handler(int (*input_funptr)(char *input_addr, uint32_t input_size, char *output_addr, uint32_t *output_size, int sender_id))
{
	ctx->send_reply_handler = input_funptr;
	return 0;
}
EXPORT_SYMBOL(ibapi_reg_send_reply_handler);
int ibapi_reg_send_reply_opt_handler(int (*input_funptr)(char *input_addr, uint32_t input_size, unsigned long *output_addr, uint32_t *output_size, int sender_id))
{
	ctx->send_reply_opt_handler = (void *)input_funptr;
	return 0;
}
EXPORT_SYMBOL(ibapi_reg_send_reply_opt_handler);
int ibapi_reg_atomic_send_handler(int (*input_funptr)(struct atomic_struct *input_list, uint32_t length, char *output_buf, uint32_t *output_size, int sender_id))
{
	ctx->atomic_send_handler = input_funptr;
	return 0;
}
EXPORT_SYMBOL(ibapi_reg_atomic_send_handler);

int ibapi_reg_atomic_single_send_handler(int (*input_funptr)(struct atomic_struct *input_list, uint32_t length, int sender_id))
{
	ctx->atomic_single_send_handler = input_funptr;
	return 0;
}
EXPORT_SYMBOL(ibapi_reg_atomic_single_send_handler);

int thread_k = 0;
int thread_k_char[1000];
int outter_loop = 1000;
int inner_loop = 100;
int thread_test(int *a)
{
	//int j = *a;
	int i;
	int k;
	remote_spinlock_t key;
	//schedule();
	ibapi_ask_lock(0, 0, &key);
	//test_printk(KERN_CRIT "%d-%d:%d: %x %x %x\n", NODE_ID, smp_processor_id(), j, key.addr, key.lkey, key.rkey);
	//ssleep(3);
	for(i=0;i<outter_loop;i++)
	{
		ibapi_lock(&key);
		for(k=0;k<inner_loop;k++)
			thread_k++;
		//test_printk(KERN_CRIT "%d:%d:%d = %d\n", NODE_ID, j, i, thread_k);
		ibapi_unlock(&key);
		//schedule();
	}
	//test_printk(KERN_CRIT "%d:%d unlock and finish\n", NODE_ID, j);
	//ssleep(1);
	//test_printk(KERN_CRIT "%d:%d exit\n", NODE_ID, j);
	do_exit(0);
	return 0;
}

int ibapi_pass_mr(int target_node, uint64_t mr_key)
{	
	int priority = LOW_PRIORITY;
	int connection_id = client_get_connection_by_atomic_number(target_node, priority);
	struct client_ibv_mr *pass_mr;
	uintptr_t tempaddr;
	pass_mr = client_id_to_mr(mr_key);
	if(!pass_mr)
		return 1;
	tempaddr = client_ib_reg_mr_addr(pass_mr, sizeof(struct client_ibv_mr));
	client_send_message_sge(connection_id, MSG_PASS_MR, (void *)tempaddr, sizeof(struct client_ibv_mr), 0, 0, priority);
	return 0;
}

struct client_ibv_mr *client_id_to_mr(uint64_t input_key)
{
	int found = 0;
	struct hash_client_ibv_mr *current_hash_ptr;
	rcu_read_lock();
	hash_for_each_possible_rcu(MR_HASHTABLE, current_hash_ptr, hlist, input_key)
	{
		found = 1;
		break;
	}
	rcu_read_unlock();
	if(!found)
		return 0;
	return current_hash_ptr->data;
}

uint64_t client_hash_mr(struct client_ibv_mr *input_mr)
{
	uint64_t temp_id = (uint64_t)input_mr->node_id << 32;
	uint64_t key = temp_id + (uint32_t)input_mr->rkey;
	int bucket = hash_min(key, HASH_TABLE_SIZE_BIT);
	struct hash_client_ibv_mr *entry;
	entry = kmalloc(sizeof(struct hash_client_ibv_mr), GFP_KERNEL);
	entry->data = input_mr;
	entry->node_id = input_mr->node_id;
	spin_lock(&(MR_HASHTABLE_LOCK[bucket]));
	hash_add_rcu(MR_HASHTABLE, &entry->hlist, key);
	spin_unlock(&(MR_HASHTABLE_LOCK[bucket]));
	return key;
}

static int param_port = 0;
static char param_ip[64];
static unsigned ip_a, ip_b, ip_c, ip_d;

module_param_named(port, param_port, int, 0444);
module_param_string(ip, param_ip, sizeof(param_ip), 0444);

int ibapi_establish_conn(char *servername, int ib_port, unsigned long total_size)
{
	int     ret;
	int     i;

	struct ib_cq *target_cq;
	//struct ib_cq *target_send_cq;
	int server_id = 0;
	struct pingpong_dest	my_dest;
	struct pingpong_dest	rem_dest;
	int port = param_port;

	struct sockaddr_in	addr;
	struct socket		*excsocket;
	char		*port_buf;
	int		sockfd = -1;
	char		msg[sizeof LID_SEND_RECV_FORMAT];
	char		recv_msg[sizeof LID_SEND_RECV_FORMAT+30];
	int		ask_number_of_MR_set = 0;
	test_printk(KERN_CRIT "Start establish connection\n");
	ret = client_init_interface(ib_port, total_size);
	//test_printk(KERN_ALERT "ret %d\n", ret);
	
	ctx->send_handler = send_handle;
	ctx->send_reply_handler = handle_send_reply;
	ctx->atomic_send_handler = handle_atomic_send;
	ctx->send_reply_opt_handler = handle_send_reply_opt;
	//Do initialization for semaphore
	sema_init(&add_newnode_mutex, 1);
	//sema_init(&mr_mutex,1);
	//sema_init(&get_thread_waiting_number_mutex, 1);
	//sema_init(&get_thread_waiting_number_semaphore, MAX_PARALLEL_THREAD);
	/*for(i=0;i<MAX_NODE;i++)	
	{
		sema_init(&atomic_accessing_lock[i],1);
	}*/
	for(i=0;i<MAX_CONNECTION;i++)
	{
		//sema_init(&connection_lock[i],1);
		spin_lock_init(&connection_lock[i]);
	}
	//Initialize waiting_queue/request list related items
	spin_lock_init(&wq_lock);
	init_waitqueue_head(&wq);
	INIT_LIST_HEAD(&(request_list.list));

	//Initialize multicast spin_lock
	spin_lock_init(&multicast_lock);

	//Initialize HASHTABLE
	hash_init(MR_HASHTABLE);
	for(i=0;i< 1<<HASH_TABLE_SIZE_BIT;i++)
	{
		spin_lock_init(&(MR_HASHTABLE_LOCK[i]));
	}
	//kthread_run(waiting_queue_handler, NULL, "waiting queue handler");
	thread_handler = kthread_create((void *)waiting_queue_handler, NULL, "wq_poller");
	if(IS_ERR(thread_handler))
	{
		test_printk(KERN_ALERT "Fail to do handler\n");
		return -1;
	}
	wake_up_process(thread_handler);
	
	//Build cache for memory --> slab
	post_receive_cache = kmem_cache_create("post_receive_buffer", RDMA_BUFFER_SIZE*4, 0, (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD), NULL);
	s_r_cache = kmem_cache_create("send_reply_cache", sizeof(struct send_and_reply_format), 0, (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD), NULL);
	header_cache = kmem_cache_create("header_cache", sizeof(struct ibapi_header), 0, (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD | SLAB_HWCACHE_ALIGN), NULL);
	intermediate_cache = kmem_cache_create("intermediate_cache", sizeof(struct ibapi_post_receive_intermediate_struct), 0, (SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD), NULL);
	
	//Start handling completion cq
	//This part need to be done on Monday
	target_cq = ctx->cq;	
	thread_poll_cq = kthread_create((void *)client_poll_cq, target_cq, "cq_poller");
	if(IS_ERR(thread_poll_cq))
	{
		test_printk(KERN_ALERT "Fail to do poll cq\n");
		return -2;
	}
	wake_up_process(thread_poll_cq);
	
	
	/*target_send_cq = ctx->send_cq;	
	thread_poll_send_cq = kthread_create((void *)client_poll_cq, target_send_cq, "cq_send_poller");
	if(IS_ERR(thread_poll_send_cq))
	{
		test_printk(KERN_ALERT "Fail to do poll cq\n");
		return 1;
	}
	wake_up_process(thread_poll_send_cq);*/


	

	memset(&my_dest, 0, sizeof(struct pingpong_dest));
	memset(&rem_dest, 0, sizeof(struct pingpong_dest));
	test_printk(KERN_INFO "establish connection id %d name %s\n", server_id, servername);

	
	port_buf = (char*)kmalloc(sizeof(char)*16, GFP_KERNEL);
	memset(port_buf, 0, 16);
	/*if(asprintf(&port_buf, "%d", port)<0)
	{
		test_printk(KERN_ALERT "asprintf error\n");
		return NULL;
	}*/
	sprintf(port_buf, "%d", port);

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl((((((ip_a << 8) | ip_b) << 8) | ip_c) << 8) | ip_d);
	test_printk(KERN_ALERT "establish connection to %x to port %d\n",addr.sin_addr.s_addr, port);
	sockfd = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &excsocket);
	ret = excsocket->ops->connect(excsocket, (struct sockaddr *)&addr, sizeof(addr), 0);
	if(sockfd < 0)
	{
		test_printk(KERN_ALERT "fail to connect to %d\n", ret);
		return -3;
	}
	client_ktcp_recv(excsocket,(char *)&NODE_ID, sizeof(int));
	test_printk(KERN_ALERT "Receive %d\n", NODE_ID);
	if(NODE_ID<=0)
	{
		test_printk(KERN_ALERT "fail to get NODE_ID as %d\n", NODE_ID);
		return -4;
	}
	client_ktcp_recv(excsocket, (char *)&ask_number_of_MR_set, sizeof(int));	
	test_printk(KERN_ALERT "Receive %d\n", ask_number_of_MR_set);
	
	if(ask_number_of_MR_set < 1 || ask_number_of_MR_set > MAX_CONNECTION)
	{
		test_printk(KERN_ALERT "ask too many required MR set from server %d\n", ask_number_of_MR_set);
		return -5;
	}
	//kmalloc(RDMA_BUFFER_SIZE, GFP_KERNEL);
	for(i=0;i<ctx->num_parallel_connection;i++)//This part need to be modified into max(num_parallel_connection, ask_number_of_MR_set) in the future.
	{
		int cur_connection = server_id + i;
		routs[cur_connection] += client_post_receives_message(cur_connection, RECV_DEPTH);
	}
	for(i=0;i<ask_number_of_MR_set;i++)
	{
		client_gen_msg(msg, i);
		//test_printk(KERN_ALERT "%d: %s\n", i, msg);
		memcpy(&my_QPset[i].server_information_buffer, &msg, sizeof(msg));
		client_ktcp_send(excsocket, msg, sizeof(LID_SEND_RECV_FORMAT));
		udelay(100);
	}
	
	for(i=0;i<ctx->num_parallel_connection;i++)
	{
		int cur_connection = server_id + i;
		client_ktcp_recv(excsocket, recv_msg, sizeof(LID_SEND_RECV_FORMAT));
		test_printk(KERN_ALERT "get %s\n", recv_msg);
		client_msg_to_pingpong_dest(recv_msg, &rem_dest);
		client_msg_to_pingpong_dest(my_QPset[cur_connection].server_information_buffer, &my_dest);
		if(cur_connection+1%ctx->num_parallel_connection==0)
			ret = client_connect_ctx(cur_connection, ib_port, my_dest.psn, mtu, sl, &rem_dest);
		else
			ret = client_connect_ctx(cur_connection, ib_port, my_dest.psn, mtu, sl, &rem_dest);
		if(ret)
		{
			test_printk(KERN_ALERT "Fail to do connection with %d\n", i);
			return -6;
		}
		test_printk(KERN_ALERT "Do connection with server by %s\n", recv_msg);
		//ctx->num_alive_connection[server_id]++;
		atomic_inc(&ctx->num_alive_connection[server_id]);
	}
	if(sockfd)
		sys_close(sockfd);

	test_printk(KERN_ALERT "return before establish connection with NODE_ID: %d\n", NODE_ID);
	return NODE_ID;
}
EXPORT_SYMBOL(ibapi_establish_conn);

static int __init ibv_init_module(void)
{
	int ret;

	sscanf(param_ip, "%u.%u.%u.%u", &ip_a, &ip_b, &ip_c, &ip_d);
	if (ip_a > 255 || ip_b > 255 || ip_c > 255 || ip_d > 255) {
		pr_info("Invalid IP: %s\n", param_ip);
		return -EINVAL;
	}
	pr_info("Server IP: %s Port: %d\n", param_ip, param_port);

	BUILD_BUG_ON(FIELD_SIZEOF(struct ib_wc, wr_id) < sizeof(void *));

	ret = class_register(&ibv_class);
	if (ret) {
		pr_err("couldn't register class ibv\n");
		return ret;
	}

	ret = ib_register_client(&ibv_client);
	if (ret) {
		pr_err("couldn't register IB client\n");
		class_unregister(&ibv_class);
		return ret;
	}
	atomic_set(&global_reqid, 0);

	pr_info("Hotpot network module installed\n");

	return 0;
}

static void __exit ibv_cleanup_module(void)
{
	if (thread_poll_cq) {
		kthread_stop(thread_poll_cq);
		thread_poll_cq = NULL;
		test_printk(KERN_INFO "Kill poll cq thread\n");
	}

	if (thread_handler) {
		struct send_and_reply_format *recv;
		recv = (struct send_and_reply_format *)kmalloc(sizeof(struct send_and_reply_format), GFP_ATOMIC);
		recv->type = MSG_GET_FINISH;
		//INIT_LIST_HEAD(&recv->list);

		kthread_stop(thread_handler);
		thread_handler = NULL;
		test_printk(KERN_INFO "Kill handler thread\n");
		spin_lock(&wq_lock);
		list_add_tail(&(recv->list), &request_list.list);
		spin_unlock(&wq_lock);
		/*wake_up_interruptible(&wq);*/
	}

	if (post_receive_cache)
		kmem_cache_destroy(post_receive_cache);
	if (header_cache)
		kmem_cache_destroy(header_cache);
	if (s_r_cache)
		kmem_cache_destroy(s_r_cache);
	if (intermediate_cache)
		kmem_cache_destroy(intermediate_cache);
	ib_unregister_client(&ibv_client);
	class_unregister(&ibv_class);

	pr_info("Hotpot network module removed\n");
}

module_init(ibv_init_module);
module_exit(ibv_cleanup_module);

MODULE_AUTHOR("yiying, shinyeh");
MODULE_LICENSE("GPL");
