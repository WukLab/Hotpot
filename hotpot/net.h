/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Header for Hotpot's customized RDMA stack only.
 */

#ifndef HAVE_CLIENT_H
#define HAVE_CLIENT_H

#include <linux/sched.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/socket.h>
#include <linux/sort.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/kthread.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/memory.h>
#include <linux/pagemap.h>
#include <linux/buffer_head.h>
#include <asm/tlbflush.h>
#include <linux/semaphore.h>
#include <linux/completion.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/parser.h>
#include <linux/random.h>
#include <linux/jiffies.h>
#include <linux/device.h>
#include <linux/atomic.h>
#include <rdma/ib_verbs.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <linux/types.h>
#include <linux/syscalls.h>

#include <linux/semaphore.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/spinlock_types.h>
#include <linux/hashtable.h>

#include "dsnvm-common.h"

#define MESSAGE_SIZE			4096
#define CIRCULAR_BUFFER_LENGTH		256
#define MAX_NODE			24
#define RECV_DEPTH			256
#define NUM_PARALLEL_CONNECTION		4
#define MAX_PARALLEL_THREAD		64
#define LID_SEND_RECV_FORMAT		"0000:0000:000000:000000:00000000000000000000000000000000"
#define MAX_CONNECTION MAX_NODE * NUM_PARALLEL_CONNECTION //Assume that MAX_CONNECTION is smaller than 256
#define WRAP_UP_NUM_FOR_WRID 256 //since there are 64 bits in wr_id, we are going to use 9-12 bits to do thread id waiting passing
#define WRAP_UP_NUM_FOR_CIRCULAR_ID 256
#define WRAP_UP_NUM_FOR_WAITING_INBOX 256
#define WRAP_UP_NUM_FOR_TYPE 65536 //since there are 64 bits in wr_id, we are going to use 9-12 bits to do thread id waiting passing
//const int MESSAGE_SIZE = 4096;
//const int CIRCULAR_BUFFER_LENGTH = 256;
//const int MAX_NODE = 4;
#define SERVER_ID 0

#define HIGH_PRIORITY		4
#define LOW_PRIORITY		0
#define KEY_PRIORITY		8
#define CONGESTION_ALERT	2
#define CONGESTION_WARNING	1
#define CONGESTION_FREE		0

//MULTICAST RELATED
#define MAX_MULTICAST_HOP	256
#define MAX_LENGTH_OF_ATOMIC	256

wait_queue_head_t wq;
spinlock_t wq_lock;

struct semaphore add_newnode_mutex;
spinlock_t connection_lock[MAX_CONNECTION];
spinlock_t multicast_lock; //only one multicast can be executed at a single time
//struct semaphore atomic_accessing_lock[MAX_NODE];
//struct semaphore mr_mutex;
//struct semaphore get_thread_waiting_number_semaphore;
//struct semaphore get_thread_waiting_number_mutex;
//struct semaphore send_reply_wait_semaphore;
//struct semaphore send_reply_wait_mutex;

ktime_t time_start, time_end, thread_start;
inline void get_time_start(void);
void get_time_end(void);
uint64_t cycle_start, cycle_end;
inline void get_cycle_start(void);
void get_cycle_end(void);

struct kmem_cache *post_receive_cache;
struct kmem_cache *s_r_cache;
struct kmem_cache *header_cache;
struct kmem_cache *intermediate_cache;


enum mode {
  M_WRITE,
  M_READ
};
enum lock_state{
    LOCK_USED,
    LOCK_AVAILABLE,
    LOCK_LOCK,
    LOCK_ASSIGNED
};

struct ibapi_post_receive_intermediate_struct
{
	uintptr_t header;
	uintptr_t msg;
};

struct ibapi_header{
	uint32_t        src_id;
	uint64_t        inbox_addr;
	uint64_t        inbox_semaphore;
	uint32_t        length;
	int             priority;
	int             type;
};
struct client_ibv_mr {
	//struct ib_device	*context;
	//struct ib_pd		*pd;
	void			*addr;
	size_t			length;
	//uint32_t		handle;
	uint32_t		lkey;
	uint32_t		rkey;
	uint32_t		node_id;
};
typedef struct client_ibv_mr remote_spinlock_t;
struct hash_client_ibv_mr{
	uint32_t node_id;
	struct client_ibv_mr *data;
	struct hlist_node hlist;
};
struct send_and_reply_format
{       
        uint32_t        src_id;
        uint64_t        inbox_addr;
	uint64_t	inbox_semaphore;
        uint32_t        length;
	int		type;
        char            *msg;
	struct list_head list;
};

struct send_and_reply_format request_list;

enum {
    MSG_MR,
    MSG_DONE,
    MSG_NODE_JOIN,
    MSG_SERVER_SEND,
    MSG_CLIENT_SEND,
    MSG_CREATE_LOCK,
    MSG_CREATE_LOCK_REPLY,
    MSG_RESERVE_LOCK,
    MSG_ASSIGN_LOCK,
    MSG_ASK_LOCK,
    MSG_ASK_LOCK_REPLY,
    MSG_GET_REMOTEMR,
    MSG_GET_REMOTEMR_REPLY,
    MSG_GET_SEND_AND_REPLY_1,
    MSG_GET_SEND_AND_REPLY_2,
    MSG_GET_ATOMIC_START,
    MSG_GET_ATOMIC_MID,
    MSG_GET_ATOMIC_REPLY,
    MSG_GET_ATOMIC_SINGLE_START,
    MSG_GET_ATOMIC_SINGLE_MID,
    MSG_PASS_MR,
    MSG_GET_SEND_AND_REPLY_OPT_1,
    MSG_GET_SEND_AND_REPLY_OPT_2,
    MSG_GET_FINISH,
    MSG_DO_POST_RECEIVE
};
struct buf_message
{
	char buf[MESSAGE_SIZE];
};


enum {
	PINGPONG_RECV_WRID = 1,
	PINGPONG_SEND_WRID = 2,
};


struct pingpong_context {
	struct ib_context	*context;
	struct ib_comp_channel *channel;
	struct ib_pd		*pd;
	struct ib_cq		*cq; // one completion queue for all qps
	struct ib_cq		**send_cq;
	struct ib_qp		**qp; // multiple queue pair for multiple connections
	int			 size;
	int			 send_flags;
	int			 rx_depth;
//	int			 pending;
	struct ib_port_attr     portinfo;
	int 			num_connections;
    int             num_node;
    int             num_parallel_connection;
    atomic_t             *num_alive_connection;
    struct ib_mr *proc;


    int *recv_num;
    atomic_t *atomic_request_num;
    atomic_t *atomic_request_num_high;
    atomic_t parallel_thread_num;
    

	enum s_state {
		SS_INIT,
		SS_MR_SENT,
        SS_RDMA_WAIT,
		SS_RDMA_SENT,
		SS_DONE_SENT,
        SS_MSG_WAIT,
        SS_MSG_SENT,
        SS_GET_REMOTE_WAIT,
        SS_GET_REMOTE_DONE,
        MSG_GET_SEND_AND_REPLY
	} *send_state;

	enum r_state {
		RS_INIT,
		RS_MR_RECV,
        RS_RDMA_WAIT,
        RS_RDMA_RECV,
		RS_DONE_RECV
	} *recv_state;
    
    enum t_state {
		TS_WAIT,
		TS_DONE
	} *thread_state;
    
    atomic_t send_reply_wait_num;
     
    struct atomic_struct **atomic_buffer;
    int *atomic_buffer_total_length;
    int *atomic_buffer_cur_length;

    atomic_t used_mr_num;
    struct client_ibv_mr *mr_set;

   	int (*send_handler)(char *addr, uint32_t size, int sender_id);
	int (*send_reply_handler)(char *input_addr, uint32_t input_size, char *output_addr, uint32_t *output_size, int sender_id);
	int (*atomic_send_handler)(struct atomic_struct *input_list, uint32_t length, char *output_buf, uint32_t *output_size, int sender_id);
	int (*atomic_single_send_handler)(struct atomic_struct *input_list, uint32_t length, int sender_id);
	int (*send_reply_opt_handler)(char *input_buf, uint32_t size, void **output_buf, uint32_t *output_size, int sender_id);
	atomic_t* connection_congestion_status;
	ktime_t* connection_timer_start;
	ktime_t* connection_timer_end;
	
	struct ibapi_header *first_packet_header, *other_packet_header;
	int *connection_id_array;
	uintptr_t *length_addr_array;
	void **output_header_addr;
	void **first_header_addr;
	void **mid_addr;

	//Needed for cross-nodes-implementation
        atomic_t alive_connection;
	atomic_t num_completed_threads;
};


struct pingpong_dest {
    int node_id;
	int lid;
	int qpn;
	int psn;
	union ib_gid gid;
};

struct client_data{
    char server_information_buffer[sizeof(LID_SEND_RECV_FORMAT)];
};

/*struct atomic_struct{
    void *  addr;
    size_t  length;
};*/

static int client_connect_ctx(int connection_id, int port, int my_psn,
			  enum ib_mtu mtu, int sl,
			  struct pingpong_dest *dest);

static struct pingpong_context *client_init_ctx(int size,int rx_depth, int port, unsigned long total_size);
int client_init_interface(int ib_port, unsigned long total_size);

int client_send_message_sge(int connection_id, int type, void *addr, int size, uint64_t inbox_addr, uint64_t inbox_semaphore, int priority);
int client_send_request(int connection_id, enum mode s_mode, struct client_ibv_mr *input_mr, void *addr, int size);

int client_msg_to_pingpong_dest(char *msg, struct pingpong_dest *rem_dest);
int client_gen_msg(char *msg, int connection_id);
int client_post_receives_message(int connection_id, int n);

int client_add_newnode(char *msg);
static int client_poll_cq(struct ib_cq *target_cq);
int client_close_ctx(struct pingpong_context *ctx);


struct client_ibv_mr *client_ib_reg_mr(struct ib_pd *pd, void *addr, size_t length, enum ib_access_flags access);

int client_get_mr_id_by_semaphore(void);
int client_get_port_info(struct ib_context *context, int port, struct ib_port_attr *attr);
void client_wire_gid_to_gid(const char *wgid, union ib_gid *gid);
void client_gid_to_wire_gid(const union ib_gid *gid, char wgid[]);

//===================OLD Design================
//int ibapi_establish_conn(char *servername, int ib_port, unsigned long total_size);
//int ibapi_rdma_write(int connection_id, struct client_ibv_mr *mr_addr, void *local_addr, int size);
//int ibapi_rdma_read(int connection_id, struct client_ibv_mr *mr_addr, void *local_addr, int size);
//int ibapi_get_remote_mr(int connection_id, void *addr, int size, struct client_ibv_mr *ret_mr);
//int ibapi_send_message(int target_node, void *addr, int size);
//int ibapi_send_reply(int target_node, char *msg, int size, char *output_msg);
//===================OLD Design===============
//Three register functions to handle send, send_reply, and atomic_send (stands for atomic_send_reply)


//===================NEW design==============
int ibapi_reg_send_handler(int (*input_funptr)(char *addr, uint32_t length, int sender_id));
int ibapi_reg_send_reply_handler(int (*input_funptr)(char *input_buf, uint32_t size, char *output_buf, uint32_t *output_size, int sender_id));
int ibapi_reg_atomic_send_handler(int (*input_funptr)(struct atomic_struct *input_list, uint32_t length, char *output_buf, uint32_t *output_size, int sender_id));
int ibapi_reg_atomic_single_send_handler(int (*input_funptr)(struct atomic_struct *input_list, uint32_t length, int sender_id));
int ibapi_reg_send_reply_opt_handler(int (*input_funptr)(char *input_buf, uint32_t size, unsigned long *output_buf, uint32_t *output_size, int sender_id));
//Do establish connections between server and new client
int ibapi_establish_conn(char *servername, int ib_port, unsigned long total_size);
uint64_t ibapi_alloc_remote_mem(int node_id, int size);

//Do atomic_send_reply. Returned value is the length of output_msg (similar to socket programming)
int ibapi_atomic_send(int target_node, struct atomic_struct *input_atomic, int length, char *output_msg);
//Do send.
int ibapi_send_message(int node_id, void *local_addr, int size);
//Do send_reply. Returned value is the length of output_msg (similar to socket programming)
int ibapi_send_reply(int node_id, char *send_msg, int send_size, char *ack_msg);
//Haven't implemented teardown_conn
int ibapi_teardown_conn(void);
int ibapi_rdma_write(int target_node, uint64_t mr_key, void *local_addr, int size, int priority);
int ibapi_rdma_read(int target_node, uint64_t mr_key, void *local_addr, int size, int priority);

//HASH_RELATED

struct client_ibv_mr *client_id_to_mr(uint64_t input_key);
uint64_t client_hash_mr(struct client_ibv_mr *input_mr);

int ibapi_lock(remote_spinlock_t *input_key);
int ibapi_unlock(remote_spinlock_t *input_key);
int ibapi_ask_lock(int target_node, int target_num, remote_spinlock_t *output_mr);
int ibapi_create_lock(int target_node, char *msg, int size, remote_spinlock_t *output_mr);
inline void ibapi_free_recv_buf(void *input_buf);
inline void client_free_recv_buf(void *input_buf);
int ibapi_send_reply_opt(int target_node, char *msg, int size, void **output_msg);

#endif /* HAVE_CLIENT_H */
