#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <pthread.h>

#include "mgmt_server.h"

int allocate_vma_for_file(int app_id, unsigned long size, unsigned long *vma_result)
{
	//return vm_alloc(app_id, size, vma_result);
	return 0;
}

int open_file(int node_id, int app_id, const char *filename, unsigned long size)
{
	int fd;
	struct file_ht_struct *s;

	dsnvm_printf("open_file %s node %d app %d size %d\n", filename, node_id, app_id, size);	
	HASH_FIND_STR(filemap, filename, s);
	if (!s) {
		printf("no file found\n");
		return 1;
	}
	fd = s->fd;

	file_metadata[fd].node_status[node_id] = OPENED;
	file_metadata[fd].num_opened_node++;
/*
	unsigned long file_vma_start;

	if (lookup_file(app_id, filename
	file_vma_start = allocate_vma_for_file(app_id, size, &file_vma_start);

	char *content = malloc(sizeof(filename)+sizeof(file_vma_start));
	
	memcpy();
	memcpy();

	network_reply(node_id, content);
*/
	// let the calling node do an mmap with this vm address
	return 0;	
}
