/*

This set is the basic local read/write page fault latency
and remote page fault latency and COW latency.

1.
	CD:
		05
	Client:
		11 (Maintain all regions)
	OP:
		One local read page fault latency

[root@wuklab11: test]# ./test-page-fault-latency.o 
NR_REGIONS: 100
NR_PAGES: 1000
MMAP_LEN: 4096000
DSNVM Total Latency:			796799.000000 (ns)
DSNVM Average Latency:			796.799000 (ns)
File Total Latency:			690851.000000 (ns)
File Average Latency:			690.851000 (ns)
Anouymous Total Latency:		344169.000000 (ns)
Anonymous Average Latency:		344.169000 (ns)

2.
	CD:
		05
	Client:
		11 (Maintain all regions)
		10 (No regions maintained, just run app)
	OP:
		One remote read page fault latency

[root@wuklab10 test]# ./test-page-fault-latency.o 
NR_REGIONS: 100
NR_PAGES: 1000
MMAP_LEN: 4096000
DSNVM Total Latency:			9726944.000000 (ns)
DSNVM Average Latency:			9726.944000 (ns)
File Total Latency:			743316.000000 (ns)
File Average Latency:			743.316000 (ns)
Anouymous Total Latency:		333392.000000 (ns)
Anonymous Average Latency:		333.392000 (ns)

3.
	CD:
		05
	Client:
		11 (Maintain all regions)
	OP:
		One local write page fault latency

[root@wuklab11: test]# ./test-page-fault-latency.o 
NR_REGIONS: 100
NR_PAGES: 1000
MMAP_LEN: 4096000
DSNVM Total Latency:			1916271.000000 (ns)
DSNVM Average Latency:			1916.271000 (ns)
File Total Latency:			1007333.000000 (ns)
File Average Latency:			1007.333000 (ns)
Anouymous Total Latency:		796359.000000 (ns)
Anonymous Average Latency:		796.359000 (ns)

4.
	CD:
		05
	Client:
		11 (Maintain all regions)
		10 (No regions maintained, just run app)
	OP:
		One remote write page fault latency

[root@wuklab10 test]# ./test-page-fault-latency.o 
NR_REGIONS: 100
NR_PAGES: 1000
MMAP_LEN: 4096000
DSNVM Total Latency:			9800714.000000 (ns)
DSNVM Average Latency:			9800.714000 (ns)
File Total Latency:			1058473.000000 (ns)
File Average Latency:			1058.473000 (ns)
Anouymous Total Latency:		725105.000000 (ns)
Anonymous Average Latency:		725.105000 (ns)

5.
	CD:
		05
	Client:
		11 (Maintain all regions)
	OP:
		One local read page fault + pfn_mkwritw

[root@wuklab11 test]# ./test-page-fault-latency.o
NR_REGIONS: 100
NR_PAGES: 1000
MMAP_LEN: 4096000
DSNVM Total Latency:			2757613.000000 (ns)
DSNVM Average Latency:			2757.613000 (ns)
File Total Latency:			1606352.000000 (ns)
File Average Latency:			1606.352000 (ns)
Anouymous Total Latency:		1186810.000000 (ns)
Anonymous Average Latency:		1186.810000 (ns)

 */

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/syscall.h>

#include "../dsnvm-helper.h"
#include "../dsnvm-common.h"

static void die(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	fputc('\n', stderr);
	exit(-1);
}

static double diff_ns(struct timespec *start, struct timespec *end)
{
	double time;

	time = (end->tv_sec - start->tv_sec) * 1000 * 1000 * 1000;
	time += (end->tv_nsec - start->tv_nsec);

	return time;
}

#define NR_REGIONS	20
#define NR_PAGES	(NR_REGIONS * DR_PAGE_NR)

static int fd_dsnvm, fd_file;
static void *virt_dsnvm, *virt_file, *virt_anony = NULL;
static size_t mmap_len;

static void open_and_mmap_files(void)
{
	mmap_len = DSNVM_PAGE_SIZE * DR_PAGE_NR * NR_REGIONS;

	printf("NR_REGIONS: %d\nNR_PAGES: %d\nMMAP_LEN: %zu\n",
		NR_REGIONS, NR_PAGES, mmap_len);

	/* Open DSNVM file */
	fd_dsnvm = open("/mnt/dsnvm/abc", O_RDWR | O_CREAT);
	if (fd_dsnvm < 0)
		die("Can not open file (1): %s", strerror(fd_dsnvm));

	fd_file = open("./unused-mmaped-file", O_RDWR);
	if (fd_file < 0)
		die("Can not open file (2): %s", strerror(fd_file));

	/* mmap DSNVM regions */
	virt_dsnvm = mmap(NULL, mmap_len, PROT_WRITE, MAP_SHARED, fd_dsnvm, 0);
	if (virt_dsnvm == MAP_FAILED)
		die("Can not mmap (1): %s", strerror(errno));

	/* mmap file of local filesystem */
	virt_file = mmap(NULL, mmap_len, PROT_WRITE, MAP_SHARED, fd_file, 0);
	if (virt_file == MAP_FAILED)
		die("Can not mmap (2): %s", strerror(errno));

	/* Anonymous pages */
	virt_anony = malloc(mmap_len);
	if (!virt_anony)
		die("Can not malloc: %s", strerror(errno));
}

static void close_files(void)
{
	if (fd_dsnvm > 0)
		close(fd_dsnvm);
	if (fd_file > 0)
		close(fd_file);
	if (!virt_anony)
		free(virt_anony);
}

static void do_test(void)
{
	int i;
	int *foo, bar;
	double average_lat, total_lat;
	struct timespec start, end;

/* DSNVM */
	foo = (int *)virt_dsnvm;
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (i = 0; i < NR_PAGES; i++) {
		bar = *foo;	/* Read Fault */
		*foo = 0;	/* Write Fault or COW */
		foo += DSNVM_PAGE_SIZE / sizeof(int);
	}
	clock_gettime(CLOCK_MONOTONIC, &end);

	total_lat = diff_ns(&start, &end);
	average_lat = total_lat / NR_PAGES;
	printf("DSNVM Total Latency:\t\t\t%f (ns)\n", total_lat);
	printf("DSNVM Average Latency:\t\t\t%f (ns)\n", average_lat);

/* Local File */
	foo = (int *)virt_file;
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (i = 0; i < NR_PAGES; i++) {
		bar = *foo;	/* Read Fault */
		*foo = 0;	/* Write Fault or nothing */
		foo += DSNVM_PAGE_SIZE / sizeof(int);
	}
	clock_gettime(CLOCK_MONOTONIC, &end);

	total_lat = diff_ns(&start, &end);
	average_lat = total_lat / NR_PAGES;
	printf("File Total Latency:\t\t\t%f (ns)\n", total_lat);
	printf("File Average Latency:\t\t\t%f (ns)\n", average_lat);

/* Anonymous */
	foo = (int *)virt_anony;
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (i = 0; i < NR_PAGES; i++) {
		bar = *foo;	/* Read Fault */
		*foo = 0;	/* Write Fault or nothing */
		foo += DSNVM_PAGE_SIZE / sizeof(int);
	}
	clock_gettime(CLOCK_MONOTONIC, &end);

	total_lat = diff_ns(&start, &end);
	average_lat = total_lat / NR_PAGES;
	printf("Anouymous Total Latency:\t\t%f (ns)\n", total_lat);
	printf("Anonymous Average Latency:\t\t%f (ns)\n", average_lat);
}

int main(int argc, char *argv[])
{
	open_and_mmap_files();
	do_test();
	close_files();

	return 0;
}
