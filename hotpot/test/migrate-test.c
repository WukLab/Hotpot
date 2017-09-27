#include <assert.h>
#include <math.h>
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

#ifdef print_all
#define dsnvm_printf	printf
#else
static void dsnvm_printf(const unsigned char *fmt, ...) { }
#endif

#define noid_id	1
#define nr_node 2

#define nr_mmaped_regions		32
#define nr_mmaped_pages			(nr_mmaped_regions * DR_PAGE_NR)

static int nr_bytes_per_area		= 4096;
static int nr_areas_per_xact		= 200;
static int nr_replica_degree		= 1;
static int NR_THREADS_PER_NODE		= 1;

#define nr_xact_per_run			100
#define nr_run				20

static double begin_xact_latency[nr_run][nr_xact_per_run];
static double commit_xact_latency[nr_run][nr_xact_per_run];

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

#define DIST_CONCENSUS_MMAP	(MAP_SHARED | 0x100)
#define NORMAP_MMAP		(MAP_SHARED)

static void open_and_mmap_files(void)
{
	mmap_len = DSNVM_PAGE_SIZE * DR_PAGE_NR * nr_mmaped_regions;

	dsnvm_printf("nr_mmaped_regions: %d\nnr_mmaped_pages: %d\nMMAP_LEN: %zu\n",
		nr_mmaped_regions, nr_mmaped_pages, mmap_len);

	/* Open DSNVM file */
	fd_dsnvm = open("/mnt/dsnvm/migration-test", O_RDWR | O_CREAT);
	if (fd_dsnvm < 0)
		die("Can not open file (1): %s", strerror(fd_dsnvm));

	/* mmap DSNVM regions */
	virt_dsnvm = mmap(NULL, mmap_len, PROT_WRITE, NORMAP_MMAP, fd_dsnvm, 0);
	if (virt_dsnvm == MAP_FAILED)
		die("Can not mmap (1): %s", strerror(errno));
}

static void close_files(void)
{
	if (fd_dsnvm > 0)
		close(fd_dsnvm);
}

static struct dsnvm_xact_header *xact_header;
static struct dsnvm_addr_len *xact_areas;
static void *xact_struct;

//=========================================================================
//= Multiplicative LCG for generating uniform(0.0, 1.0) random numbers    =
//=   - x_n = 7^5*x_(n-1)mod(2^31 - 1)                                    =
//=   - With x seeded to 1 the 10000th x value should be 1043618065       =
//=   - From R. Jain, "The Art of Computer Systems Performance Analysis," =
//=     John Wiley & Sons, 1991. (Page 443, Figure 26.2)                  =
//=========================================================================
double rand_val(int seed)
{
	const long  a =      16807;  // Multiplier
	const long  m = 2147483647;  // Modulus
	const long  q =     127773;  // m div a
	const long  r =       2836;  // m mod a
	long        x_div_q;         // x divided by q
	long        x_mod_q;         // x modulo q
	long        x_new;           // New x value

	static long x;               // Random int value

	// Set the seed if argument is non-zero and then return zero
	if (seed > 0) {
		x = seed;
		return(0.0);
	}

	// RNG using integer arithmetic
	x_div_q = x / q;
	x_mod_q = x % q;
	x_new = (a * x_mod_q) - (r * x_div_q);
	if (x_new > 0)
		x = x_new;
	else
		x = x_new + m;

	// Return a random value between 0.0 and 1.0
	return((double) x / m);
}

static double C = 0;

/* Return the variable X, belongs [1, N] */
static int zipf(double alpha, int N)
{
	int i, zipf_value;
	double ran, sum_prob;

	/* first time, normalize C */
	if (C == 0) {
		rand_val(1);
		for (i = 1; i <= N; i++)
			C += 1.0 / pow((double)i, alpha);
		C = 1.0 / C;
	}

	do {
		ran = rand_val(0);
	} while ((ran == 0) || (ran == 1));

	sum_prob = 0;
	for (i = 1; i <= N; i++) {
		sum_prob += C / pow((double)i, alpha);
		if (sum_prob >= ran) {
			zipf_value = i;
			break;
		}
	}

	assert((zipf_value >=1) && (zipf_value <= N));

	return zipf_value;
}

/* Return the probability of varibale X in Zipf distribution */
static double zipf_prob(int X, double alpha, int N)
{
	int i;
	double prob;

	/* first time, normalize C */
	if (C == 0) {
		for (i = 1; i <= N; i++)
			C += 1.0 / pow((double)i, alpha);
		C = 1.0 / C;
	}

	if (X <= 0)
		X = 1;
	else if (X >= N)
		X = N;

	prob = C / pow((double)X, alpha);

	return prob;
}

static double alpha = 1;
static int N = nr_run;

static void init_xact_area(int run)
{
	int i;
	unsigned long base;
	int _nr_bytes;

	if (run >= nr_mmaped_regions)
		run = nr_mmaped_regions - 1;

	base = run * DR_PAGE_NR;

	_nr_bytes = nr_bytes_per_area * zipf_prob(run, alpha, N);

	printf("run[%d], nr_bytes_per_area: %d\n", run, _nr_bytes);

	for (i = 0; i < nr_areas_per_xact; i++) {
		xact_areas[i].len = _nr_bytes;
		xact_areas[i].addr = (base + i) * DSNVM_PAGE_SIZE +
			(unsigned long)(virt_dsnvm);
	}
}

static void init_xact(void)
{
	size_t malloc_size;

	malloc_size = sizeof(struct dsnvm_xact_header);
	malloc_size += nr_areas_per_xact*sizeof(struct dsnvm_addr_len);

	xact_struct = malloc(malloc_size);
	if (!xact_struct)
		die("OOM");

	xact_header = xact_struct;
	xact_header->rep_degree = nr_replica_degree;
	xact_header->xact_id = -1;

	xact_areas = xact_struct + sizeof(struct dsnvm_xact_header);
}

static void sleep_random(void)
{
	int sec = rand() % 5;
	dsnvm_printf("Sleep %d sec...\n", sec);
	sleep(sec);
}

static void begin_xact(int thread_id, int *xact_id, int run, int round)
{
	int ret, sec;
	int retry = 0;
	struct timespec start, end;

retry:
	clock_gettime(CLOCK_MONOTONIC, &start);
	ret = msync(xact_areas, nr_areas_per_xact, DSNVM_BEGIN_XACT_FLAG);
	clock_gettime(CLOCK_MONOTONIC, &end);

	begin_xact_latency[run][round] = diff_ns(&start, &end);

	dsnvm_printf("Thread %d - Begin Transaction Latency:\t\t\t%f (ns)\n", thread_id, diff_ns(&start, &end));

	if (unlikely(ret == DSNVM_RETRY)) {
		sleep_random();
		retry++;
		if (retry > 20)
			die("Thread %d: too many retry begin xact retry (%d)", thread_id, retry);
		goto retry;
	} else if (unlikely(ret < 0)) {
		die("Thread %d: fail to begin transaction", thread_id);
	}
	dsnvm_printf("Thread %d: got xact_id: %d, retry: %d\n", thread_id, ret, retry);
	*xact_id = ret;
}

static void commit_xact(int thread_id, int xact_id, int run, int round)
{
	int ret, sec;
	int retry = 0;
	struct timespec start, end;

	xact_header->xact_id = xact_id;

retry:
	clock_gettime(CLOCK_MONOTONIC, &start);
	ret = msync(xact_struct, nr_areas_per_xact, DSNVM_COMMIT_XACT_FLAG);
	clock_gettime(CLOCK_MONOTONIC, &end);

	commit_xact_latency[run][round] = diff_ns(&start, &end);

	dsnvm_printf("Thread %d - Commit Transaction Latency:\t\t\t%f (ns)\n", thread_id, diff_ns(&start, &end));

	if (ret == DSNVM_RETRY) {
		sleep_random();
		retry++;
		if (retry > 20)
			die("Thread %d: too many retry commit xact id %d retry (%d)", thread_id, xact_id, retry);
		goto retry;
	} else if (unlikely(ret < 0)) {
		die("Thread %d: fail to commit transaction id %d ret %d", thread_id, xact_id, ret);
	}
}

static pthread_barrier_t local_barrier;

static void *thread_func(void *arg)
{
	int thread_id = *(int *)arg;
	int i, *foo, bar, round, run;
	int xact_id = 0;

	/* Local barrier */
	pthread_barrier_wait(&local_barrier);

	/*
	 * Each run:
	 *	Run different distribution of areas
	 *
	 * Within each run:
	 * 	Run the same xact areas nr_xact_per_run times,
	 * 	then get an average latency.
	 */
	for (run = 0; run < nr_run; run++) {
		init_xact_area(run);

		/* Then run the same xact multiple times */
		for (round = 0; round < nr_xact_per_run; round++) {
			begin_xact(thread_id, &xact_id, run, round);

			for (i = 0; i < nr_areas_per_xact; i++) {
				bar = *((int *)(xact_areas[i].addr));
			}

			commit_xact(thread_id, xact_id, run, round);
		}
	}

	return NULL;
}

void show_perf_num(void)
{
	int run, round;
	double total;
	double begin_avg[nr_run];
	double commit_avg[nr_run];

	dsnvm_printf("Begin Latency:\n");
	for (run = 0; run < nr_run; run++) {
		dsnvm_printf("Run[%2d]  ", run);
		for (round = 0, total = 0; round < nr_xact_per_run; round++) {
			total += begin_xact_latency[run][round];
			dsnvm_printf("%f ", begin_xact_latency[run][round]);
		}
		dsnvm_printf("\n");
		begin_avg[run] = total/nr_xact_per_run;
	}

	dsnvm_printf("Commit Latency:\n");
	for (run = 0; run < nr_run; run++) {
		dsnvm_printf("Run[%2d]  ", run);
		for (round = 0, total = 0; round < nr_xact_per_run; round++) {
			total += commit_xact_latency[run][round];
			dsnvm_printf("%f ", commit_xact_latency[run][round]);
		}
		dsnvm_printf("\n");
		commit_avg[run] = total/nr_xact_per_run;
	}

	printf("Average:\n");
	for (run = 0; run < nr_run; run++) {
		printf("Run[%d]:\n", run);
		printf("\tBegin:  %20f\n", begin_avg[run]);
		printf("\tCommit: %20f\n\n", commit_avg[run]);
	}
}

void show_config(void)
{
	printf("nr_bytes_per_area:        %d\n", nr_bytes_per_area);
	printf("nr_areas_per_xact:        %d\n", nr_areas_per_xact);
	printf("nr_xact_per_run:          %d\n", nr_xact_per_run);
	printf("nr_run:                   %d\n", nr_run);
	printf("nr_replica_degree:        %d\n", nr_replica_degree);

	printf("nr_mmaped_regions:        %d\n", nr_mmaped_regions);
	printf("region_size:              %dMB\n", DR_SIZE >> 20);
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

#if 0
	printf("Preloading %d MB data, please wait...\n", mmap_len >> 20);
	foo = (int *)virt_dsnvm;
	for (i = 0; i < nr_mmaped_pages; i++) {
		bar = *foo;
		foo += DSNVM_PAGE_SIZE / sizeof(int);
	}

	printf("Done, now waiting on distributed barrier...\n");
#endif

	//dist_sync_barrier();

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
	show_config();

	/* sync between clients */
	/* clean up */
	close_files();
	if (!xact_struct)
		free(xact_struct);

	return 0;
}
