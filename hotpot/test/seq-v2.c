/*
 * each xact has NR_XACT_AREAS areas
 * each area's fixed starting address is: 0MB, 1MB, .... NR_XACT_AREAS MB
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
#include "dsnvm.h"

#define NR_REGIONS		35		/* mmaped range, must > nr_xact_areas */
#define NR_PAGES		(NR_REGIONS * DR_PAGE_NR)

#define STRIDE			(1024*1024)	/* 1MB stride */

#define	XACT_AREA_SIZE		1024		/* each area is 1KB */
#define	NR_XACT_AREAS		32		/* each xact has 32KB */
#define NR_REPLICA		2		/* rep_degree is 2 */
#define NR_THREADS_PER_NODE	1

/*
 * Maximum loops is 1000
 * but it will be adjusted within NR_PAGES
 */
#define LOOPS 512
static int nr_loops = LOOPS;
static double begin_lat[NR_THREADS_PER_NODE][LOOPS];
static double commit_lat[NR_THREADS_PER_NODE][LOOPS];
static double begincall_lat[NR_THREADS_PER_NODE][LOOPS];
static double commitcall_lat[NR_THREADS_PER_NODE][LOOPS];

static bool debug = false;

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

	printf("nr_regions: %d\n", NR_REGIONS);
	printf("mmap_len: %dMB\n", mmap_len/1024/1024);

	/* Open DSNVM file */
	fd_dsnvm = open("/mnt/dsnvm/abc", O_RDWR | O_CREAT);
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

static struct dsnvm_xact_header *xact_header[NR_THREADS_PER_NODE];
static struct dsnvm_addr_len *xact_areas[NR_THREADS_PER_NODE];
static void *xact_struct[NR_THREADS_PER_NODE];

static void init_xact_area(int thread_id, int loop)
{
	int i, j;
	unsigned long base;
	unsigned long offset;

	base = (unsigned long)virt_dsnvm;
	offset = loop * XACT_AREA_SIZE;

	for (i = 0; i < NR_XACT_AREAS; i++) {
		xact_areas[thread_id][i].addr = base + i * STRIDE + offset;
		xact_areas[thread_id][i].len = XACT_AREA_SIZE;

		if (debug) {
			printf("Loop: %4d, xact_areas[%3d].addr: %#lx\n",
				loop, i, xact_areas[thread_id][i].addr);
		}
	}
}

/*
 * Allocate xact array
 */
static void init_xact(void)
{
	size_t malloc_size;
	int i;

	malloc_size = sizeof(struct dsnvm_xact_header);
	malloc_size += NR_XACT_AREAS*sizeof(struct dsnvm_addr_len);

	for (i = 0; i < NR_THREADS_PER_NODE; i++) {
		xact_struct[i] = malloc(malloc_size);
		if (!xact_struct[i])
			die("OOM");

		xact_header[i] = xact_struct[i];
		xact_header[i]->rep_degree = NR_REPLICA;
		xact_header[i]->xact_id = -1;

		xact_areas[i] = xact_struct[i] + sizeof(struct dsnvm_xact_header);
	}
}

static void sleep_random(void)
{
	int sec = rand() % 10;
	printf("Sleep %d msec...\n", sec * 10);
	usleep(sec * 1000 * 10);
}

#define MAX_NR_RETRY	10000
static void begin_xact(int thread_id, int *xact_id, int loop)
{
	int ret, sec;
	unsigned long round = 0;
	struct timespec start, end;

retry:
	clock_gettime(CLOCK_MONOTONIC, &start);
	ret = msync(xact_areas[thread_id], NR_XACT_AREAS, DSNVM_BEGIN_XACT_FLAG);
	clock_gettime(CLOCK_MONOTONIC, &end);
	begin_lat[thread_id][loop] = diff_ns(&start, &end);

	if (unlikely(ret == DSNVM_RETRY)) {
		//sleep_random();
		round++;
		if (round > MAX_NR_RETRY)
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

	xact_header[thread_id]->xact_id = xact_id;

retry:
	clock_gettime(CLOCK_MONOTONIC, &start);
	ret = msync(xact_struct[thread_id], NR_XACT_AREAS, DSNVM_COMMIT_XACT_FLAG);
	clock_gettime(CLOCK_MONOTONIC, &end);
	commit_lat[thread_id][loop] = diff_ns(&start, &end);

	if (ret == DSNVM_RETRY) {
		//sleep_random();
		round++;
		if (round > MAX_NR_RETRY)
			die("Thread %d: too many retry commit xact id %d rounds (%lu)",
				thread_id, xact_id, round);
		goto retry;
	} else if (unlikely(ret < 0)) {
		die("Thread %d: fail to commit transaction id %d ret %d",
			thread_id, xact_id, ret);
	}
}

static pthread_barrier_t local_barrier;

static void *thread_func(void *arg)
{
	int thread_id = *(int *)arg;
	int i, *foo, bar, loop;
	int xact_id = 0;
	struct timespec start, end;

	/* local barrier */
	pthread_barrier_wait(&local_barrier);

	/* the mainloop */
	for (loop = 0; loop < nr_loops; loop++) {

		init_xact_area(thread_id, loop);

		if (debug)
			continue;

		clock_gettime(CLOCK_MONOTONIC, &start);
		begin_xact(thread_id, &xact_id, loop);
		clock_gettime(CLOCK_MONOTONIC, &end);

		begincall_lat[thread_id][loop] = diff_ns(&start, &end);
		for (i = 0; i < NR_XACT_AREAS; i++) {
			bar = *((int *)(xact_areas[thread_id][i].addr));
		}

		clock_gettime(CLOCK_MONOTONIC, &start);
		commit_xact(thread_id, xact_id, loop);
		clock_gettime(CLOCK_MONOTONIC, &end);
		commitcall_lat[thread_id][loop] = diff_ns(&start, &end);
	}

	return NULL;
}

static double av_begin[NR_THREADS_PER_NODE];
static double av_commit[NR_THREADS_PER_NODE];

static void __show_perf_num(int thread_id)
{
	int i;
	double total;

	printf("Thead %d\n", thread_id);

	for (i = 0, total = 0; i < nr_loops; i++) {
		total += begin_lat[thread_id][i];
	}
	av_begin[thread_id] = total/nr_loops;
	printf("  Begin XACT Average Latency:\t %20f\t (ns)\n", total/nr_loops);
	
	for (i = 0, total = 0; i < nr_loops; i++) {
		total += begincall_lat[thread_id][i];
	}
	printf("  Begin call Latency:\t %20f\t (ns)\n", total/nr_loops);

	for (i = 0, total = 0; i < nr_loops; i++) {
		total += commit_lat[thread_id][i];
	}
	av_commit[thread_id] = total/nr_loops;
	printf("  Commit XACT Average Latency:\t %20f\t (ns)\n", total/nr_loops);

	for (i = 0, total = 0; i < nr_loops; i++) {
		total += commitcall_lat[thread_id][i];
	}
	printf("  Commit call Average Latency:\t %20f\t (ns)\n", total/nr_loops);
}

static void show_perf_num(void)
{
	int i;
	double ac = 0, ab = 0;

	for (i = 0; i < NR_THREADS_PER_NODE; i++)
		__show_perf_num(i);

	for (i = 0; i < NR_THREADS_PER_NODE; i++) {
		ab += av_begin[i];
		ac += av_commit[i];
	}
	printf("** Average begin latency:  %20f\n", ab / NR_THREADS_PER_NODE);
	printf("** Average commit latency: %20f\n", ac / NR_THREADS_PER_NODE);
}

/* pass "-d" to turn on debug mode and dryrun */
int main(int argc, char *argv[])
{
	int i, ret, *foo, bar;
	int args[NR_THREADS_PER_NODE];
	pthread_t tid[NR_THREADS_PER_NODE];

	if (argc == 2 && !strcmp(argv[1], "-d")) {
		debug = true;
		printf("debug mode\n");
	}

	if (NR_XACT_AREAS > NR_REGIONS)
		die("nr_regions(%d) is smaller than nr_xact_areas(%d)",
			NR_REGIONS, NR_XACT_AREAS);

	if (LOOPS > NR_PAGES)
		nr_loops = NR_PAGES;

	printf("nr_pages:\t%d\n", NR_PAGES);
	printf("nr_loops:\t%d\n", nr_loops);

	srand(time(NULL) + getpid());
	open_and_mmap_files();
	init_xact();

	ret = pthread_barrier_init(&local_barrier, NULL, NR_THREADS_PER_NODE);
	if (ret)
		die("fail to init local barrier");

	sleep_random();
	dist_sync_barrier();

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

	if (!debug)
		show_perf_num();

	/* sync between clients */
	/* clean up */
	close_files();

	return 0;
}

