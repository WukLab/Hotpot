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
#include "dsnvm.h"

#define NR_REGIONS		16
#define NR_PAGES		(NR_REGIONS * DR_PAGE_NR)

#define NR_REPLICA		1
#define	NR_XACT_AREAS		32
#define	XACT_AREA_SIZE		1024
#define NR_THREADS_PER_NODE	1

#define LOOPS 512
static double begin_lat[LOOPS];
static double commit_lat[LOOPS];

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

static int fd_dsnvm;
static void *virt_dsnvm;
static size_t mmap_len;

static void open_and_mmap_files(void)
{
	mmap_len = DSNVM_PAGE_SIZE * DR_PAGE_NR * NR_REGIONS;

	printf("NR_REGIONS: %d\nNR_PAGES: %d\nMMAP_LEN: %zu\n",
		NR_REGIONS, NR_PAGES, mmap_len);

	/* Open DSNVM file */
	fd_dsnvm = open("/mnt/hotpot/abc", O_RDWR | O_CREAT);
	if (fd_dsnvm < 0)
		die("Can not open file (1): %s", strerror(fd_dsnvm));

	/* mmap DSNVM regions */
	virt_dsnvm = mmap(NULL, mmap_len, PROT_WRITE, MAP_SHARED, fd_dsnvm, 0);
	if (virt_dsnvm == MAP_FAILED)
		die("Can not mmap (1): %s", strerror(errno));
}

static void close_files(void)
{
	if (fd_dsnvm > 0)
		close(fd_dsnvm);
}

static DECLARE_BITMAP(random_bitmap, NR_PAGES);

static int get_unique_random(void)
{
	int page_no;

	while (1) {
		page_no = rand() % NR_PAGES;
		if (likely(!test_and_set_bit(page_no, random_bitmap)))
			break;
	}
	return page_no;
}

static int get_random(void)
{
	return rand() % NR_PAGES;
}

static struct dsnvm_xact_header *xact_header;
static struct dsnvm_addr_len *xact_areas;
static void *xact_struct;

static void init_xact_area(int loop)
{
	int i;
	unsigned long base;
	int page_no;

	for (i = 0; i < NR_XACT_AREAS; i++) {
		page_no = get_random();
		xact_areas[i].addr = page_no * DSNVM_PAGE_SIZE + (unsigned long)(virt_dsnvm);
		xact_areas[i].len = XACT_AREA_SIZE;
	}
}

static void init_xact(void)
{
	size_t malloc_size;

	malloc_size = sizeof(struct dsnvm_xact_header);
	malloc_size += NR_XACT_AREAS*sizeof(struct dsnvm_addr_len);

	xact_struct = malloc(malloc_size);
	if (!xact_struct)
		die("OOM");

	xact_header = xact_struct;
	xact_header->rep_degree = NR_REPLICA;
	xact_header->xact_id = -1;

	xact_areas = xact_struct + sizeof(struct dsnvm_xact_header);
}

static void sleep_random(void)
{
	int sec = rand() % 3;
	printf("Sleep %d sec...\n", sec);
	sleep(sec);
}

static void begin_xact(int thread_id, int *xact_id, int loop)
{
	int ret, sec;
	unsigned long round = 0;
	struct timespec start, end;

retry:
	clock_gettime(CLOCK_MONOTONIC, &start);
	ret = msync(xact_areas, NR_XACT_AREAS, DSNVM_BEGIN_XACT_FLAG);
	clock_gettime(CLOCK_MONOTONIC, &end);
	begin_lat[loop] = diff_ns(&start, &end);

	if (unlikely(ret == DSNVM_RETRY)) {
		sleep_random();
		round++;
		if (round > 20)
			die("Thread %d: too many retry begin xact rounds (%lu)", thread_id, round);
		goto retry;
	} else if (unlikely(ret < 0)) {
		die("Thread %d: fail to start transaction", thread_id);
	}
	*xact_id = ret;
}

static void commit_xact(int thread_id, int xact_id, int loop)
{
	int ret, sec;
	unsigned long round = 0;
	struct timespec start, end;

	xact_header->xact_id = xact_id;

retry:
	clock_gettime(CLOCK_MONOTONIC, &start);
	ret = msync(xact_struct, NR_XACT_AREAS, DSNVM_COMMIT_XACT_FLAG);
	clock_gettime(CLOCK_MONOTONIC, &end);
	commit_lat[loop] = diff_ns(&start, &end);

	if (ret == DSNVM_RETRY) {
		sleep_random();
		round++;
		if (round > 20)
			die("Thread %d: too many retry commit xact id %d rounds (%lu)", thread_id, xact_id, round);
		goto retry;
	} else if (unlikely(ret < 0)) {
		die("Thread %d: fail to commit transaction id %d ret %d", thread_id, xact_id, ret);
	}
}

static pthread_barrier_t local_barrier;

static void *thread_func(void *arg)
{
	int thread_id = *(int *)arg;
	int i, *foo, bar, loop;
	int xact_id = 0;

	/* Local barrier */
	pthread_barrier_wait(&local_barrier);

	for (loop = 0; loop < LOOPS; loop++) {
		init_xact_area(loop);

		begin_xact(thread_id, &xact_id, loop);

		for (i = 0; i < NR_XACT_AREAS; i++) {
			bar = *((int *)(xact_areas[i].addr));
		}

		commit_xact(thread_id, xact_id, loop);
	}

	return NULL;
}

void show_perf_num(void)
{
	int i;
	double total;

	for (i = 0, total = 0; i < LOOPS; i++) {
		total += begin_lat[i];
	}
	printf("Begin XACT Average Latency: %20f (ns)\n\n", total/LOOPS);

	for (i = 0, total = 0; i < LOOPS; i++) {
		total += commit_lat[i];
	}
	printf("Commit XACT Average Latency: %20f (ns)\n", total/LOOPS);
}

static fetch_all_pages(void)
{
	int i, j;
	unsigned long va;

	for (i = 0; i < NR_PAGES; i++) {
		va = (unsigned long)virt_dsnvm + i * DSNVM_PAGE_SIZE;
		j = *(int *)va;
	}
}

/**
 * 1) Use read page fault to bring all pages in
 * 2) Global Distributed Barrier
 * 3) Begin XACT
 * 4)    do something
 * 5) Commit XACT
 * 6) Global Distributed Barrier
 * 7) Close files and exit
 */
int main(int argc, char *argv[])
{
	int i, ret, *foo, bar;
	int args[NR_THREADS_PER_NODE];
	pthread_t tid[NR_THREADS_PER_NODE];

	srand(time(NULL) + getpid());
	open_and_mmap_files();
	init_xact();

	ret = pthread_barrier_init(&local_barrier, NULL, NR_THREADS_PER_NODE);
	if (ret)
		die("fail to init local barrier");

	//fetch_all_pages();

	for (i = 0; i < NR_THREADS_PER_NODE; i++) {
		args[i] = i;
		ret = pthread_create(&tid[i], NULL, thread_func, &args[i]);
		if (ret)
			die("fail to create thread");
	}

	for (i = 0; i < NR_THREADS_PER_NODE; i++) {
		ret = pthread_join(tid[i], NULL);
		if (ret)
			die("fail to join");
	}

	show_perf_num();

	/* sync between clients */
	/* clean up */
	close_files();
	if (!xact_struct)
		free(xact_struct);

	return 0;
}
