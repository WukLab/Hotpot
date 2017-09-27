#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <pthread.h>

#include "mgmt_server.h"

int create_file(int node_id, int app_id, const char *filename, enum _file_mode mode)
{
	int fd;
	struct file_ht_struct *s = malloc(sizeof(struct file_ht_struct));
	struct file_ht_struct *temp = NULL;
	memcpy(s->filename, filename, 255);

	dsnvm_printf("create file node %d app %d name %s mode %d\n", node_id, app_id, filename, mode);
	while (1) {
		fd = rand() % MAX_FILES;
		HASH_FIND_STR(filemap, filename, temp);
		if (!temp)
			continue;
		s->fd = fd;	
		break;
	}

	HASH_ADD_STR(filemap, filename, s);

	file_metadata[fd].fd = fd;
	file_metadata[fd].mode = mode;
	file_metadata[fd].node_status[node_id] = CREATED;

	return 0;
}
