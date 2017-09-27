/*
 * Hotpot Migration Zipf Test
 *
 * Mechanism:
 *  We use a trace log generated from zipf ditribution
 *  The log specifies the property of each xact:
 * 	1) usec before a xact call begin
 * 	2) usec before a xact call commit
 * 	3) All areas' address
 * 	4) All areas' length
 *
 * Note:
 *  The default region size is: 4MB
 *
 * The trace generater is: workload/python_zipf/zipf_python.py
 * The trace logs are in: workload/python_zipf/SOCC17/
 */

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

/*
 * This should match zipf_python.py's G_NUM_OF_REQUEST
 */
#define NR_XACT			100000

#define NR_REPLICA		1

#define NR_AREAS_PER_XACT	10
static int nr_areas_per_xact = NR_AREAS_PER_XACT;

#define NR_MAX_RETRY		1000000

#ifdef debug
#define DEBUG_printf	printf
#else
static void DEBUG_printf(const unsigned char *fmt, ...) { }
#endif

static void die(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	fputc('\n', stderr);
	exit(-1);
}

static double *begin_lat;
static double *commit_lat;

static void alloc_perf_array(void)
{
	begin_lat = malloc(sizeof(double) * NR_XACT);
	if (!begin_lat)
		die("oom");
	
	commit_lat = malloc(sizeof(double) * NR_XACT);
	if (!commit_lat)
		die("oom");
}

static void free_perf_array(void)
{
	if (begin_lat)
		free(begin_lat);
	if (commit_lat)
		free(commit_lat);
}

struct xact_desc {
	int nr_ms_before_begin;
	int nr_ms_before_commit;
	unsigned long addr_oft[NR_AREAS_PER_XACT];
	int length[NR_AREAS_PER_XACT];
};

static struct xact_desc *desc;

static int fd_dsnvm;
static void *virt_dsnvm;
static size_t mmap_len;

#define DIST_CONCENSUS_MMAP	(MAP_SHARED | 0x100)
#define NORMAP_MMAP		(MAP_SHARED)

/*
 * This nr_mmaped_regions should be larger than the address range in the zipf log.
 *
 * For example, if the zipf_python.py use G_NR_HOTPOT_REGIONS=32, it means the
 * generated address range is [0, 32*4MB). Our mamped range must be larger than
 * this to avoid out of boundary access.
 */
#define nr_mmaped_regions	40
#define NR_PAGES		(nr_mmaped_regions * DR_PAGE_NR)

static void open_and_mmap_files(void)
{
	mmap_len = DSNVM_PAGE_SIZE * DR_PAGE_NR * nr_mmaped_regions;

	/* Open DSNVM file */
	fd_dsnvm = open("/mnt/dsnvm/zipf", O_RDWR | O_CREAT);
	if (fd_dsnvm < 0)
		die("Can not open file (1): %s", strerror(fd_dsnvm));

	/* mmap DSNVM regions */
	virt_dsnvm = mmap(NULL, mmap_len, PROT_WRITE, NORMAP_MMAP, fd_dsnvm, 0);
	if (virt_dsnvm == MAP_FAILED)
		die("Can not mmap (1): %s", strerror(errno));
}

static struct dsnvm_xact_header *xact_header;
static struct dsnvm_addr_len *xact_areas;
static void *xact_struct;

static void init_xact(int nr_areas)
{
	size_t malloc_size;

	malloc_size = sizeof(struct dsnvm_xact_header);
	malloc_size += nr_areas*sizeof(struct dsnvm_addr_len);

	xact_struct = malloc(malloc_size);
	if (!xact_struct)
		die("OOM");

	xact_header = xact_struct;
	xact_header->rep_degree = NR_REPLICA;
	xact_header->xact_id = -1;

	xact_areas = xact_struct + sizeof(struct dsnvm_xact_header);
}

static double diff_ns(struct timespec *start, struct timespec *end)
{
	double time;

	time = (end->tv_sec - start->tv_sec) * 1000 * 1000 * 1000;
	time += (end->tv_nsec - start->tv_nsec);

	return time;
}

static void begin_xact(int idx, int *xact_id, int nr_areas)
{
	int ret, sec;
	int retry = 0;
	struct timespec start, end;

retry:
	clock_gettime(CLOCK_MONOTONIC, &start);
	ret = msync(xact_areas, nr_areas, DSNVM_BEGIN_XACT_FLAG);
	clock_gettime(CLOCK_MONOTONIC, &end);

	if (idx >= 0)
		begin_lat[idx] = diff_ns(&start, &end);

	DEBUG_printf("Begin Transaction Latency:\t\t\t%f (ns)\n", diff_ns(&start, &end));

	if (unlikely(ret == DSNVM_RETRY)) {
		retry++;
		if (retry > NR_MAX_RETRY)
			die("Too many retry begin xact retry (%d)", retry);
		goto retry;
	} else if (unlikely(ret < 0)) {
		die("Fail to begin transaction");
	}
	DEBUG_printf("Got xact_id: %d, retry: %d\n", ret, retry);
	*xact_id = ret;
}

static void commit_xact(int idx, int xact_id, int nr_areas)
{
	int ret, sec;
	int retry = 0;
	struct timespec start, end;

	xact_header->xact_id = xact_id;

retry:
	clock_gettime(CLOCK_MONOTONIC, &start);
	ret = msync(xact_struct, nr_areas, DSNVM_COMMIT_XACT_FLAG);
	clock_gettime(CLOCK_MONOTONIC, &end);

	if (idx >= 0)
		commit_lat[idx] = diff_ns(&start, &end);

	DEBUG_printf("Commit Transaction Latency:\t\t\t%f (ns)\n", diff_ns(&start, &end));

	if (ret == DSNVM_RETRY) {
		retry++;
		if (retry > NR_MAX_RETRY)
			die("Too many retry commit xact id %d retry (%d)", xact_id, retry);
		goto retry;
	} else if (unlikely(ret < 0)) {
		die("Fail to commit transaction id %d ret %d", xact_id, ret);
	}
}

void show_perf_num(void)
{
	int i;
	double total;

	DEBUG_printf("Begin Latency:\n");
	for (i = 0, total = 0; i < NR_XACT; i++) {
		total += begin_lat[i];
		DEBUG_printf(" [%2d] %20f (ns)\n", i, begin_lat[i]);
	}
	printf("Begin XACT Average Latency:\t\t%20f (us)\n", (total/NR_XACT)/1000);

	DEBUG_printf("Commit Latency:\n");
	for (i = 0, total = 0; i < NR_XACT; i++) {
		total += commit_lat[i];
		DEBUG_printf(" [%2d] %20f (ns)\n", i, commit_lat[i]);
	}
	printf("Commit XACT Average Latency:\t\t%20f (us)\n", (total/NR_XACT)/1000);
}

int nr_nodes = 4;

#define NR_WARMUP_XACT_AREAS 8
void warmup(int nid)
{
	int region_index = nid;
	int round = nr_mmaped_regions / nr_nodes;
	int _round = DR_PAGE_NR / NR_WARMUP_XACT_AREAS;
	int i, j, k =0;
	int xact_id;

	printf("warmup, wait..\n");

	/* region */
	for (i = 0; i < round; i++) {
		/* within a region */
		for (j = 0; j < _round; j++) {
			for (k = 0; k < NR_WARMUP_XACT_AREAS; k++) {
				xact_areas[k].addr = (unsigned long)virt_dsnvm +
					(region_index * DR_PAGE_NR + j * NR_WARMUP_XACT_AREAS + k) * DSNVM_PAGE_SIZE;
				xact_areas[k].len = DSNVM_PAGE_SIZE;
			}

			begin_xact(-1, &xact_id, NR_WARMUP_XACT_AREAS);
			commit_xact(-1, xact_id, NR_WARMUP_XACT_AREAS);
		}
		region_index += nr_nodes;
	}
}

void disable_hotpot_migration(void)
{
	system("echo enable_migration=0 > /proc/dsnvm");
	printf("Disable Hotpot Migration\n");
}

void enable_hotpot_migration(void)
{
	system("echo enable_migration=1 > /proc/dsnvm");
	printf("Enable Hotpot Migration\n");
}

int main(int argc, char *argv[])
{
	FILE *f_zipf;
	char line[256];
	int time, i, j;
	char c;
	int nr_areas;
	unsigned long addr_oft;
	int length;
	int p_time = 0;
	struct timespec start, end;
	int nid;
	int *foo, bar;

	if (argc < 3)
		die("$: ./a.out filename nid");

	nid = atoi(argv[2]);
	if (nid < 0 || nid > DSNVM_MAX_NODE)
		die("invalid nid: %d", nid);
	printf("nid: %d\n", nid);

	f_zipf = fopen(argv[1], "r");
	if (!f_zipf)
		die("fail to open: %s", argv[2]);

	desc = malloc(sizeof(*desc) * NR_XACT);
	if (!desc)
		die("oom");
	alloc_perf_array();

	open_and_mmap_files();

	init_xact(NR_AREAS_PER_XACT);

	while (fgets(line, sizeof(line), f_zipf)) {
		struct xact_desc *p = &desc[i / 2];
		int offset = 0, forward_count = 0;

		if (i % 2 == 0) {
			/* Begin line */
			sscanf(line, "%d,%c,%d%n", &time, &c, &nr_areas, &forward_count);
			offset = forward_count;
			
			if (nr_areas > NR_AREAS_PER_XACT || nr_areas <= 0)
				die("adjust parameters");

			for (j = 0; j < nr_areas; j++) {
				sscanf(line + offset, ",%lu,%d%n", &p->addr_oft[j], &p->length[j], &forward_count);
				offset += forward_count;
			}

			p->nr_ms_before_begin = time - p_time;
			p_time = time;
		} else {
			/* Commit line */
			sscanf(line, "%d", &time);

			p->nr_ms_before_commit = time - p_time;
			p_time = time;
		}

		i++;
	}

	nr_areas_per_xact = nr_areas;
	printf("areas per xact: %d\n", nr_areas_per_xact);
	printf("nr xacts: %d\n", NR_XACT);

	disable_hotpot_migration();

	//warmup(nid);

	printf("Waiting on dist barrier..\n");
	//dist_sync_barrier();

	//enable_hotpot_migration();

	clock_gettime(CLOCK_MONOTONIC, &start);
	for (i = 0; i < NR_XACT; i++) {
		int xact_id;
		struct xact_desc *p = &desc[i];

		for (j = 0; j < nr_areas_per_xact; j++) {
			if (p->addr_oft[j] >= mmap_len)
				die("invalid address offset");
			xact_areas[j].addr = (unsigned long)(virt_dsnvm) + p->addr_oft[j];
			xact_areas[j].len = p->length[j];
		}

		usleep(p->nr_ms_before_begin);
		begin_xact(i, &xact_id, nr_areas_per_xact);

		usleep(p->nr_ms_before_commit);
		commit_xact(i, xact_id, nr_areas_per_xact);
	}
	clock_gettime(CLOCK_MONOTONIC, &end);

	printf("Total %d xacts runtime is:\t\t\t%f (ms)\n", NR_XACT, diff_ns(&start, &end) / 1000000);
	show_perf_num();

	free_perf_array();

	fclose(f_zipf);
	close(fd_dsnvm);
	if (!xact_struct)
		free(xact_struct);
	return 0;
}
