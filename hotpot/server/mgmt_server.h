#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include "uthash.h"
#include "dsnvm-us-netbase.h"
//#include "buddy.h"

#define _GNU_SOURCE

#define ATOMIC_MAX_SIZE 4096
#define CHECKPOINT_THRESH 10000 //1000000
#define CHECKPOINT_THRESH_COUNT 100000 //100 //1000000
#define CHECKPOINT_SIZE 100

//#define DSNVM_DEBUG
//#define DSNVM_DEBUG1

#ifdef DSNVM_DEBUG
#define dsnvm_printf(x...) do { printf(x); } while (0)
#else
#define dsnvm_printf(x...) do { } while (0)
#endif

#ifdef DSNVM_DEBUG1
#define dsnvm_printf1(x...) do { printf(x); } while (0)
#else
#define dsnvm_printf1(x...) do { } while (0)
#endif

#ifndef DSNVM_SETUP
#define DSNVM_SETUP

struct file_ht_struct {
	char filename[255];
//	unsigned long vma_start;
	int fd;
	UT_hash_handle hh;
};

struct file_ht_struct *filemap;

int num_node;

enum task {
	CREATE_FILE,
	OPEN_FILE,
	DELETE_FILE,
	READ_FILE,
	WRITE_FILE,
	SYNC_FILE
};

enum _node_status {
		EMPTY,
		CREATED,
		OPENED,
		CLOSED
};
enum _file_mode {
	READ_WRITE,
	READ_ONLY,
};
struct _file_metadata {
	int fd;
	unsigned long vma_start;
	enum _file_mode mode;
	enum _node_status *node_status;
	int num_opened_node;
};

#define MAX_FILES 1000

struct _file_metadata file_metadata[MAX_FILES];
	
// -- access functions
int create_file(int node_id, int app_id, const char *filename, enum _file_mode mode);
int open_file(int node_id, int app_id, const char *filename, unsigned long size);
//int read_data(int node_id, int app_id, const char *filename, unsigned long offset, int size);

// -- network functions

struct sockaddr_in *node_addr;

//int network_init(int num_node, const char *server_list[]);
int network_init(int ib_port);
//int network_reply(int node_id, char *content);
int handle_remote_request(int node_id, char *msg, int size);


#endif
