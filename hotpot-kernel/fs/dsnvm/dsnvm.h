/*
 * Distributed Shared NVM
 *
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _INCLUDE_DSNVM_H_
#define _INCLUDE_DSNVM_H_

#ifdef  pr_fmt
#undef  pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/hashtable.h>

//#define DSNVM_DUMP_MSG
#ifdef DSNVM_DUMP_MSG
extern struct file *fp;
void write_2_msg_file(const char *buf);
void log_msg_bytes(size_t nr_bytes);
#else
static inline void open_msg_dump_file(void) { }
static inline void close_msg_dump_file(void) { }
static inline void write_2_msg_file(const char *buf) { }
static inline void log_msg_bytes(size_t nr_bytes) { }
#endif

/*
 * Maximum number of logs in NVM area
 * Maximum numebr of ON_REGION can be creaated
 * Maximum numebr of REPLICA_REGION can be creaated
 */
#define DSNVM_MAX_LOG_RECORDS		64
#define DSNVM_MAX_ON_REGION_INFO	256
#define DSNVM_MAX_REPLICA_REGION_INFO	256

#include "dsnvm-common.h"
#include "dsnvm-nvm.h"
#include "dsnvm-fs.h"
#include "dsnvm-on.h"
#include "dsnvm-dn.h"
#include "dsnvm-replica.h"
#include "dsnvm-xact.h"
#include "dsnvm-event.h"
#include "dsnvm-pmem.h"
#include "dsnvm-migrate.h"

#define TOTAL_CONNECTIONS		1
#define ATOMIC_MAX_SIZE			4096

#define DSNVM_SUCCEED			0
#define DSNVM_FAIL			1

#define DSNVM_ERROR_RECV_MSG_FORMAT	1

/* on_region_info hashtable size: 2^10 */
#define HASH_TABLE_SIZE_BIT		10

void transaction_enter(void);
void transaction_exit(void);
char *dsnvm_state_string(void);

int dsnvm_client_init_ib(char *servername, int port, unsigned long total_size);

/*
 * InfiniBand APIs
 */

void client_free_recv_buf(void *input_buf);
void ibapi_free_recv_buf(void *input_buf);
int ibapi_establish_conn(char *servername, int ib_port, unsigned long total_size);

int ibapi_atomic_send(int target_node, struct atomic_struct *input_atomic, int length, char *reply);
int ibapi_send_message(int node_id, void *local_addr, int size);
int ibapi_send_reply(int node_id, char *send_msg, int send_size, char *ack_msg);
int ibapi_send_reply_opt(int target_node, char *msg, int size, void **output_msg);
int ibapi_teardown_conn(void);
int ibapi_reg_send_handler(void *);
int ibapi_reg_send_reply_handler(void *);
int ibapi_reg_send_reply_opt_handler(void *);
int ibapi_reg_atomic_send_handler(void *);
int ibapi_atomic_send_reply(int node_id, int num_reqs, dsnvm_addr_len *reqs, char *ack_msg);
int ibapi_teardown_conn(void);
int ibapi_multi_atomic_send(int number_of_node, int *target_node, struct atomic_struct **input_atomic, int *length, struct max_reply_msg *output_msg);
int ibapi_multi_send_reply(int number_of_target, int *target_array, struct atomic_struct *input_atomic, struct max_reply_msg* reply);
int ibapi_multi_send(int number_of_target, int *target_array, struct atomic_struct *input_atomic);

int ibapi_atomic_send_yy(int target_node, struct atomic_struct *input_atomic, int length, char *reply);
int ibapi_multi_atomic_send_yy(int number_of_node, int *target_node, struct atomic_struct **input_atomic, int *length, struct max_reply_msg *output_msg);

extern char *server_name;
extern int ib_port_no;
extern unsigned int DSNVM_LOCAL_ID;
extern DECLARE_BITMAP(DSNVM_CLIENT_MACHINES, DSNVM_MAX_NODE);
extern atomic_t nr_client_machines;

#define DSNVM_BUG_ON(condition)		BUG_ON(condition)
#define DSNVM_WARN_ON(condition)	WARN_ON(condition)

#define DSNVM_BUG(format...)					\
do {								\
	pr_warn("----------------[ cut here ]----------------");\
	pr_warn("DSNVM BUG: CPU: %d PID: %d at %s:%d %s()!",	\
		raw_smp_processor_id(), current->pid,		\
		__FILE__, __LINE__, __func__);			\
	pr_warn(format);					\
	/* mount option: error=panic */				\
	if (err_panic)						\
		panic("dsnvm bug");				\
} while (0);

#define DSNVM_WARN(format...)					\
do {								\
	pr_warn("----------------[ cut here ]----------------");\
	pr_warn("DSNVM WARNING: CPU: %d PID: %d at %s:%d %s()!",\
		raw_smp_processor_id(), current->pid,		\
		__FILE__, __LINE__, __func__);			\
	pr_warn(format);					\
} while (0);

#define DSNVM_WARN_ONCE(format...)				\
do {								\
	static bool __warned;					\
	if (!__warned) {					\
		DSNVM_WARN(format);				\
		__warned = true;				\
	}							\
} while (0);

struct dsnvm_request *alloc_dsnvm_request(void);
struct dsnvm_reply *alloc_dsnvm_reply(void);
struct dsnvm_reply_page_fetch *alloc_dsnvm_reply_page_fetch(void);
struct status_reply_msg *alloc_dsnvm_status_reply(void);
struct status_and_data_reply_msg *alloc_status_and_data_dsnvm_reply(void);
struct max_reply_msg *alloc_max_reply(void);

void free_dsnvm_request(struct dsnvm_request *);
void free_dsnvm_reply(struct dsnvm_reply *);
void free_dsnvm_reply_page_fetch(struct dsnvm_reply_page_fetch *r);
void free_dsnvm_status_reply(struct status_reply_msg *r);
void free_dsnvm_status_and_data_reply(struct status_and_data_reply_msg *r);
void free_max_reply(struct max_reply_msg *r);

int init_dsnvm_client_cache(void);
void destroy_dsnvm_client_cache(void);

void dsnvm_send_machine_join(void);
void dsnvm_send_machine_leave(void);

/* proc.c */
int create_dsnvm_proc_file(void);
void remove_dsnvm_proc_file(void);

/*
 * SYSCALL Interface
 */

extern atomic_t BARRIER_COUNTER;

/* mm/mmap.c */
unsigned long dsnvm_brk(unsigned long brk);

struct dist_hooks {
	int (*dist_lock_hook)(void *);
	int (*dist_unlock_hook)(void *);
	int (*dist_create_lock_hook)(unsigned int, void *, unsigned int, void *);
	void (*dist_sync_barrier_hook)(void);

	void (*dist_mmap_consensus_hook)(struct file *file, unsigned long *addr, unsigned long len);
};

int register_dist_lock_hooks(const struct dist_hooks *hooks);
void unregister_dist_lock_hooks(void);

int ibapi_lock(void *);
int ibapi_unlock(void *);
int ibapi_create_lock(int , char *, int , void *);

int dsnvm_handle_notify_all_promotion(char *input_addr, unsigned int req_len, int sender_id);
void promote_DN_to_ON(unsigned long dr_no);
int dsnvm_handle_fetch_commited_dn_page(char *msg, char *reply_addr, unsigned int *reply_len, int sender_id);

#endif /* _INCLUDE_DSNVM_H_ */
