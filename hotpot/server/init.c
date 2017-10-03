#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>

#include <pthread.h>
#include "mgmt_server.h"

#include <getopt.h>

#define STRING_LENGTH 128

int establish_cluster(int ib_port)
{
    network_init(ib_port);
	return 0;
}

int application_init(int app_id)
{
	// init virtual memory address allocator for each application
//	vm_allocator_new(48);
	return 0;
}
static void usage(const char *argv0)
{
	printf("Usage:\n");
	printf("  %s            start a server and wait for connection\n", argv0);
	printf("\n");
	printf("Options:\n");
	printf("  -l, --listen-port=<port>   (Required) use <port> to listen hotpot connections\n");
	printf("  -i, --ib-port=<port>       (Optional) use <port> of IB device (default 1)\n");
}

int listen_port = -1;

int main(int argc, char *argv[])
{
    int     ib_port = 1;
    char    hostname[STRING_LENGTH];
    gethostname(hostname, STRING_LENGTH);//Get own host name

    static struct option long_options[] = {
  	{ "ib-port",		1,	0,	'i' },
	{ "listen-port",	1,	0,	'l'},
	{ NULL,			0,	NULL,	0 }
    };

    while (1) {
		int c;

		c = getopt_long(argc, argv, "i:l:", long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'i':
			ib_port = strtol(optarg, NULL, 0);
			if (ib_port < 0) {
				usage(argv[0]);
				return 1;
			}
			break;
		case 'l':
			listen_port = strtol(optarg, NULL, 0);
			if (listen_port < 0) {
				usage(argv[0]);
				return 1;
			}
			break;
		default:
			usage(argv[0]);
			return 1;
		}
    }

    if (listen_port <= 0) {
	usage(argv[0]);
	return 1;
    }

    printf("Hostname:        %s\n", hostname);
    printf("IB Device Port:  %d\n", ib_port);
    printf("Listen Port:     %d\n", listen_port);
    
    //  =======================================================
    //  Establish cluster as a main API
    //  Which could be found in main.c
    //  Old form: establish_cluster(num_node, argv);
    establish_cluster(ib_port);
    //  =======================================================
    return 0;
}
