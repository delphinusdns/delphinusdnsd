/*
 * Copyright (c) 2014-2021 Peter J. Philipp <pjp@delphinusdns.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>
#include <bitstring.h>

#ifdef __linux__
#include <grp.h>
#define __USE_BSD 1
#include <endian.h>
#include <bsd/stdlib.h>
#include <bsd/string.h>
#include <bsd/sys/queue.h>
#define __unused
#include <bsd/sys/tree.h>
#include <bsd/sys/endian.h>
#else /* not linux */
#include <sys/queue.h>
#include <sys/tree.h>
#endif /* __linux__ */

#include "ddd-dns.h"
#include "ddd-db.h"

void 			add_rrlimit(int, u_int16_t *, int, char *);
int 			check_rrlimit(int, u_int16_t *, int, char *);
extern void 		dolog(int, char *, ...);
static u_int16_t 	hash_rrlimit(u_int16_t *, int);
char 			*rrlimit_setup(int);

struct rrlimit {
	uint8_t pointer;
	time_t times[256];
} __attribute__((packed));

int ratelimit = 0;
int ratelimit_packets_per_second = 6;

int ratelimit_cidr = 0;
int ratelimit_cidr6 = 0;

char *
rrlimit_setup(int size)
{
	char *ptr;

	if (size > 255)
		return NULL;	

	size = 65536 * ((size * sizeof(time_t)) + sizeof(uint8_t));

	ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED |\
		MAP_ANON, -1, 0);

	if (ptr == MAP_FAILED) {
		dolog(LOG_ERR, "failed to setup rlimit mmap segment, exit\n");
		exit(1);
	}

	memset(ptr, 0, size);

	return (ptr);
}

int
check_rrlimit(int size, uint16_t *ip, int sizeip, char *rrlimit_ptr)
{
	struct rrlimit *rl;
	struct in6_addr ia6;
	in_addr_t ia, netmask;
	uint16_t hash = 0;
	int count = 0, i;
	uint8_t offset;
	time_t now;
	char *tmp;

	if (sizeip == 4) {
		ia = *(in_addr_t *)ip;
		if (ratelimit_cidr) {
			switch (ratelimit_cidr) {
			case 8:
				netmask = inet_addr("255.0.0.0");
				ia = ia & netmask;
				break;
			case 16:
				netmask = inet_addr("255.255.0.0");
				ia = ia & netmask;
				break;
			case 24:
				netmask = inet_addr("255.255.255.0");
				ia = ia & netmask;
				break;
			}
		}
		hash = hash_rrlimit((uint16_t *)&ia, sizeip);
	} else if (sizeip == 16) { 
		memcpy((char *)&ia6, (char *)ip, sizeip);
			
		if (ratelimit_cidr6) {
			switch (ratelimit_cidr6) {
			case 32:
				ia6.__u6_addr.__u6_addr32[1] = 0;
				/* FALLTHROUGH */
			case 64:
				ia6.__u6_addr.__u6_addr32[2] = 0;
				ia6.__u6_addr.__u6_addr32[3] = 0;
				break;
			}
		}

		hash = hash_rrlimit((uint16_t *)&ia6, sizeip);
	}
		
	tmp = rrlimit_ptr + (hash * ((size * sizeof(time_t)) + sizeof(u_int8_t)));
	rl = (struct rrlimit *)tmp;
	
	offset = rl->pointer;
	
	now = time(NULL);

	for (i = 0; i < size; i++) {
		if (difftime(now, rl->times[(offset + i) % size]) <= 1)
			count++;
		else
			break;
	}
	
	if (count > ratelimit_packets_per_second)
		return 1;

	return 0;
}


void
add_rrlimit(int size, u_int16_t *ip, int sizeip, char *rrlimit_ptr)
{
	struct rrlimit *rl;
	struct in6_addr ia6;
	in_addr_t ia = 0, netmask = 0;
	uint16_t hash = 0;
	int offset;
	time_t now;
	char *tmp;

	if (sizeip == 4) {
		ia = *(in_addr_t *)ip;
		if (ratelimit_cidr) {
			switch (ratelimit_cidr) {
			case 8:
				netmask = inet_addr("255.0.0.0");
				ia = ia & netmask;
				break;
			case 16:
				netmask = inet_addr("255.255.0.0");
				ia = ia & netmask;
				break;
			case 24:
				netmask = inet_addr("255.255.255.0");
				ia = ia & netmask;
				break;
			}
		}

		hash = hash_rrlimit((uint16_t *)&ia, sizeip);
	} else if (sizeip == 16) { 
		memcpy((char *)&ia6, (char *)ip, sizeip);
			
		if (ratelimit_cidr6) {
			switch (ratelimit_cidr6) {
			case 32:
				ia6.__u6_addr.__u6_addr32[1] = 0;
				/* FALLTHROUGH */
			case 64:
				ia6.__u6_addr.__u6_addr32[2] = 0;
				ia6.__u6_addr.__u6_addr32[3] = 0;
				break;
			}
		}

		hash = hash_rrlimit((uint16_t *)&ia6, sizeip);
	}

	tmp = rrlimit_ptr + (hash * ((size * sizeof(time_t)) + sizeof(u_int8_t)));
	rl = (struct rrlimit *)tmp;
	
	offset = rl->pointer;

	offset--;
	if (offset < 0)
		offset = size - 1;

	now = time(NULL);

	rl->times[offset] = now;
	rl->pointer = offset;	/* XXX race */
	
}

static u_int16_t
hash_rrlimit(u_int16_t *ip, int size)
{
	uint64_t total = 0;
	int i, j;

	for (i = 0, j = 0; i < size; i += 2) {
		total += (uint64_t)ip[j++];	
	}

	total %= 0xffff;

	return ((uint16_t)total);
}	
