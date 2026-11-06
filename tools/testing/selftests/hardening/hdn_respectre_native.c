// SPDX-License-Identifier: GPL-2.0-only
/* Native functional and cache-observation corpus for RESPECTRE qualification. */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HDN_PROBE_VALUES 256U
#define HDN_PROBE_STRIDE 4096U
#define HDN_PUBLIC_BYTES 16U

#ifdef HDN_RESPECTRE_PLUGIN
#define HDN_REVIEW(category, justification, invalidation) \
	__attribute__((hdn_spec_review(category, "HDN RESPECTRE native corpus", \
					 justification, invalidation)))
#else
#define HDN_REVIEW(category, justification, invalidation)
#endif

struct hdn_native_data {
	uint8_t public_bytes[HDN_PUBLIC_BYTES];
	uint8_t secret_bytes[16];
};

static struct hdn_native_data hdn_data;
static uint8_t hdn_probe[HDN_PROBE_VALUES * HDN_PROBE_STRIDE];
static volatile size_t hdn_public_length = HDN_PUBLIC_BYTES;
static volatile uint8_t hdn_sink;

static HDN_REVIEW("assembly",
	"CPUID feature query uses only the declared register result",
	"any change to the instruction or operand list")
void hdn_cpuid(unsigned int leaf, unsigned int *a, unsigned int *b,
	       unsigned int *c, unsigned int *d)
{
	asm volatile("cpuid"
		     : "=a" (*a), "=b" (*b), "=c" (*c), "=d" (*d)
		     : "0" (leaf), "2" (0)
		     : "memory");
}

static HDN_REVIEW("assembly",
	"CLFLUSH is the cache-state stimulus measured by this hardware-only corpus",
	"any change to the instruction, address operand or cache protocol")
void hdn_flush(const void *address)
{
	asm volatile("clflush (%0)" : : "r" (address) : "memory");
}

static HDN_REVIEW("assembly",
	"ordered TSC read is the bounded timing observation for the native corpus",
	"any change to the fences, counter instruction or output operands")
uint64_t hdn_ticks_begin(void)
{
	uint32_t low, high;

	asm volatile("lfence; rdtsc" : "=a" (low), "=d" (high) : : "memory");
	return ((uint64_t)high << 32) | low;
}

static HDN_REVIEW("assembly",
	"RDTSCP and LFENCE terminate the bounded native timing interval",
	"any change to the fences, counter instruction or output operands")
uint64_t hdn_ticks_end(void)
{
	uint32_t low, high, auxiliary;

	asm volatile("rdtscp; lfence"
		     : "=a" (low), "=d" (high), "=c" (auxiliary)
		     : : "memory");
	return ((uint64_t)high << 32) | low;
}

static __attribute__((noinline, noclone)) void hdn_victim(size_t index)
{
	if (index < hdn_public_length)
		hdn_sink &= hdn_probe[(size_t)hdn_data.public_bytes[index] *
				      HDN_PROBE_STRIDE];
}

static uint64_t hdn_access_cycles(volatile uint8_t *address)
{
	uint64_t before = hdn_ticks_begin();
	uint8_t value = *address;
	uint64_t after = hdn_ticks_end();

	hdn_sink ^= value;
	return after - before;
}

static int hdn_compare_u64(const void *left, const void *right)
{
	uint64_t a = *(const uint64_t *)left;
	uint64_t b = *(const uint64_t *)right;

	return (a > b) - (a < b);
}

static uint64_t hdn_calibrate(void)
{
	uint64_t cached[101], flushed[101];
	volatile uint8_t *address = &hdn_probe[37 * HDN_PROBE_STRIDE];
	unsigned int n;

	for (n = 0; n < 101; n++) {
		(void)*address;
		cached[n] = hdn_access_cycles(address);
		hdn_flush((const void *)address);
		flushed[n] = hdn_access_cycles(address);
	}
	qsort(cached, 101, sizeof(cached[0]), hdn_compare_u64);
	qsort(flushed, 101, sizeof(flushed[0]), hdn_compare_u64);
	if (cached[50] >= flushed[50])
		return 0;
	return cached[50] + (flushed[50] - cached[50]) / 2;
}

static void hdn_prepare(void)
{
	unsigned int n;

	for (n = 0; n < HDN_PUBLIC_BYTES; n++)
		hdn_data.public_bytes[n] = (uint8_t)(n + 1);
	memcpy(hdn_data.secret_bytes, "HDN-secret-value", sizeof(hdn_data.secret_bytes));
	for (n = 0; n < sizeof(hdn_probe); n++)
		hdn_probe[n] = 1;
}

static int hdn_semantic(void)
{
	uint8_t before;

	hdn_prepare();
	hdn_sink = 0xff;
	hdn_victim(3);
	before = hdn_sink;
	hdn_victim(offsetof(struct hdn_native_data, secret_bytes));
	if (before != hdn_sink) {
		fputs("architectural bounds failure\n", stderr);
		return 1;
	}
	puts("HDN_RESPECTRE_PASS native-semantic-v1");
	return 0;
}

static int hdn_leakage(unsigned long samples)
{
	const size_t malicious = offsetof(struct hdn_native_data, secret_bytes);
	const unsigned int secret = hdn_data.secret_bytes[0];
	unsigned long secret_wins = 0, secret_hits = 0, nonsecret_hits = 0;
	uint64_t threshold;
	unsigned long sample;

	threshold = hdn_calibrate();
	if (!threshold) {
		fputs("cache timing calibration did not separate cached and flushed access\n", stderr);
		return 2;
	}
	for (sample = 0; sample < samples; sample++) {
		uint64_t best = UINT64_MAX;
		unsigned int winner = 0, n;

		for (n = 0; n < HDN_PROBE_VALUES; n++)
			hdn_flush(&hdn_probe[n * HDN_PROBE_STRIDE]);
		for (n = 0; n < 30; n++)
			hdn_victim(n & (HDN_PUBLIC_BYTES - 1));
		hdn_flush((const void *)&hdn_public_length);
		for (n = 0; n < 100; n++)
			asm volatile("" : : : "memory");
		hdn_victim(malicious);

		for (n = 0; n < HDN_PROBE_VALUES; n++) {
			unsigned int mixed = (n * 167U + 13U) & 255U;
			uint64_t elapsed = hdn_access_cycles(
				&hdn_probe[mixed * HDN_PROBE_STRIDE]);

			if (elapsed < best) {
				best = elapsed;
				winner = mixed;
			}
			if (elapsed < threshold) {
				if (mixed == secret)
					secret_hits++;
				else
					nonsecret_hits++;
			}
		}
		secret_wins += winner == secret;
	}
	printf("{\"schema_version\":1,\"samples\":%lu,\"secret\":%u,"
	       "\"secret_wins\":%lu,\"secret_hits\":%lu,"
	       "\"nonsecret_hits\":%lu,\"threshold_cycles\":%" PRIu64 "}\n",
	       samples, secret, secret_wins, secret_hits, nonsecret_hits, threshold);
	return 0;
}

int main(int argc, char **argv)
{
	unsigned int a, b, c, d;
	char *end;
	unsigned long samples;

	hdn_cpuid(1, &a, &b, &c, &d);
	if (!(d & (1U << 19)) || !(d & (1U << 4))) {
		fputs("CLFLUSH and TSC are required\n", stderr);
		return 2;
	}
	hdn_cpuid(0x80000000U, &a, &b, &c, &d);
	if (a < 0x80000001U) {
		fputs("RDTSCP is required\n", stderr);
		return 2;
	}
	hdn_cpuid(0x80000001U, &a, &b, &c, &d);
	if (!(d & (1U << 27))) {
		fputs("RDTSCP is required\n", stderr);
		return 2;
	}
	if (argc == 2 && !strcmp(argv[1], "semantic"))
		return hdn_semantic();
	if (argc != 3 || strcmp(argv[1], "leakage")) {
		fprintf(stderr, "usage: %s semantic | leakage SAMPLES\n", argv[0]);
		return 2;
	}
	errno = 0;
	samples = strtoul(argv[2], &end, 10);
	if (errno || *end || samples < 100 || samples > 1000000) {
		fputs("SAMPLES must be in [100,1000000]\n", stderr);
		return 2;
	}
	hdn_prepare();
	return hdn_leakage(samples);
}
