#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/time.h>
#include <netdb.h>
#include <malloc.h>
#include <getopt.h>
#include <time.h>



#include <infiniband/verbs.h>

#include "client.h"
#include "mgmt_server.h"

#define LISTEN_BACKLOG 10
//#define LISTEN_PORT 18515
//#define SEND_BUF_LENGTH 2048
static const int RDMA_BUFFER_SIZE = 2048;


char *strdupa1 (const char *s) {
    char *d = malloc (strlen (s) + 1);   // Space for length plus nul
    if (d == NULL) return NULL;          // No memory
    strcpy (d,s);                        // Copy the characters
    return d;                            // Return the new string
}

//Please be aware that below structs and definitions are also used in server side network_handler.c
//#define LID_SEND_RECV_FORMAT "0000:000000:000000:00000000000000000000000000000000"
//#define MAX_NODE 32
#define SERVER_INFORMATION_BUFFER_SIZE 256
void *get_in_addr(struct sockaddr *sa) {
  return sa->sa_family == AF_INET
    ? (void *) &(((struct sockaddr_in*)sa)->sin_addr)
    : (void *) &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int handle_remote_request(int node_id, char *msg, int size)
{
	printf("handle_remote_request got msg %s\n", msg);

	
    
	//ibapi_send_msg(node_id, reply_msg, sizeof(reply_msg));

	return 0;

	enum task tsk = *((enum task *)msg); 
	int app_id = *((int *)(msg+sizeof(enum task)));
	char filename[255];
	enum _file_mode mode;
	//int size;
	
	memcpy(filename, msg+sizeof(enum task)+sizeof(int), 255);
	printf("handle_remote_request node %d msg %s filename %s\n", node_id, msg, filename);

	switch (tsk) {
	case CREATE_FILE:
		mode = *((enum _file_mode *)(msg+sizeof(enum task)+sizeof(int)+255));
		create_file(node_id, app_id, filename, mode);
		break;
	case OPEN_FILE:
		size = *((int *)(msg+sizeof(enum task)+sizeof(int)+255));
		open_file(node_id, app_id, filename, size);
		break;
	case DELETE_FILE:
		break;
	case READ_FILE:
		break;
	case WRITE_FILE:
		break;
	case SYNC_FILE:
		break;
	default:
		break;
	}
	return 0;
}

int network_reply(int node_id, char *content)
{
	return 0;
}
int server_test_function()
{
    
    int target;
    char *testtest;
    testtest=calloc(RDMA_BUFFER_SIZE, sizeof(char));
    int choice;
    struct client_ibv_mr *testmr;
    int *mr_flag;
    mr_flag = calloc(MAX_NODE,sizeof(int));
    do
    {   
        printf("Interact with ?\n");
        scanf("%d", &target);
    }while(target==0);
    testmr = calloc(MAX_NODE,sizeof(struct client_ibv_mr));
    server_get_remotemr(target,testtest,RDMA_BUFFER_SIZE,&testmr[target]);
    mr_flag[target]=1;
    int i;
    char *input_ato;
    struct atomic_struct *temp_ato;
    while(1)
    {
        printf("1. RDMA WRITE \n2. RDMA READ \n3. SEND MESSAGE\n4. SEND-REPLY PAIR\n5. ATOMIC SEND\n6. CHANGE TARGET\n");
        scanf("%d", &choice);
        switch(choice)
        {
            case 1:
                printf("With ?\n");
                scanf("%s", testtest);
                server_rdma_write(target, &testmr[target], testtest, RDMA_BUFFER_SIZE);
                //client_send_request(target, M_WRITE, testtest, RDMA_BUFFER_SIZE);
                //ibapi_rdma_write(target, &ctx->peer_mr[target], testtest, RDMA_BUFFER_SIZE);
                break;
            case 2:
                server_rdma_read(target, &testmr[target], testtest, RDMA_BUFFER_SIZE);
                //ibapi_rdma_read(target, &ctx->peer_mr[target], testtest, RDMA_BUFFER_SIZE);
                printf("%d: %s\n", target, testtest);
                break;
            case 3:
                printf("with ?\n");
                scanf("%s", testtest);
                ibapi_send_message(target, testtest, RDMA_BUFFER_SIZE);
                break;
            case 4:
                printf("with ?\n");
                scanf("%s", testtest);
                char *abc;
                abc = calloc(4096, sizeof(char));
                ibapi_send_reply(target, testtest, strlen(testtest), abc);
                printf("%s\n", abc);
                break;
            case 5:
                temp_ato = malloc(sizeof(struct atomic_struct)*16);
                char *reply = malloc(4096);
                int ret_size;
                for(i=0;i<16;i++)
                {
                    input_ato = malloc(32);
                    scanf("%s", input_ato);
                    temp_ato[i].vaddr = input_ato;
                    temp_ato[i].len = strlen(input_ato);
                    if(!strcmp(input_ato, "exit"))
                        break;
                }
                i=i+1;
                server_atomic_send_reply(target, temp_ato, i, reply, &ret_size);
                break;
            case 6:
                printf("change to ?\n");
                scanf("%d", &target);
                {
                    if(mr_flag[target]==1)
                        break;
                    server_get_remotemr(target,testtest,RDMA_BUFFER_SIZE,&testmr[target]);
                    mr_flag[target]=1;
                }
                break;
            /*case 4:
                printf("send to ?\n");
                scanf("%d", &target);
                printf("with size ?\n");
                scanf("%d", &size);
                //strcpy(ctx->send_msg[target]->data.newnode_msg, testtest);
                //client_send_message(target, MSG_CLIENT_SEND);
                
                testmr = malloc(sizeof(struct ibv_mr));
                ibapi_get_remotemr(target,testtest,size,testmr);
                printf("%lu.%lu\n", (long unsigned int)testmr->addr, (long unsigned int)testmr->lkey);
                printf("With ?\n");
                scanf("%s", testtest);
                ibapi_rdma_write(target, testmr, testtest, size);
                strcpy(testtest, "!!");
                ibapi_rdma_read(target, testmr, testtest, size);
                printf("%d: %s\n", target, testtest);
                break;*/
            default:
                printf("Error input\n");
        }
        memset(testtest, 0, RDMA_BUFFER_SIZE);
        
    }
}
//  =======================================================
//  Old form: int network_init(int num_node, const char *server_list[])
//  =======================================================
int network_init(int ib_port)
{
    
    ibapi_init(ib_port);
    //server_test_function();
    while(1);
    //pthread_t               thread_test;
    //pthread_create(&thread_test, NULL, (void *)server_test_function, NULL);
    //printf("Since this code is using to test cluster building, the following RDMA would not be processed\n");

    //pthread_join(thread_test, NULL);
    
    /*
    for (i = 0; i < num_node; i++) {
		ibapi_establish_connection(i, strdupa1(server_list[i+1]));
	}
	for (i = 0; i < num_node; i++) {
		if (ibapi_exchange_mr(i, M_WRITE) != 0)
			break;
	}
	ibapi_accept_request();
    */

	return 0;
}
