/* 
 * Copyright (c) 2014 Peter J. Philipp
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 */
#include "include.h"
#include "dns.h"
#include "db.h"

void 			add_rrlimit(int, u_int16_t *, int, char *);
int 			check_rrlimit(int, u_int16_t *, int, char *);
extern void 		dolog(int, char *, ...);
static u_int16_t 	hash_rrlimit(u_int16_t *, int);
char 			*rrlimit_setup(int);

struct rrlimit {
	u_int8_t pointer;
	time_t times[256];
};

int ratelimit = 0;
int ratelimit_packets_per_second = 6;

char *
rrlimit_setup(int size)
{
	char *ptr;

	if (size > 255)
		return NULL;	

	size = 65536 * ((size * sizeof(time_t)) + sizeof(u_int8_t));

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
check_rrlimit(int size, u_int16_t *ip, int sizeip, char *rrlimit_ptr)
{
	struct rrlimit *rl;
	u_int16_t hash;
	int count = 0, i;
	u_int8_t offset;
	time_t now;
	char *tmp;

	hash = hash_rrlimit(ip, sizeip);

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
	u_int16_t hash;
	int offset;
	time_t now;
	char *tmp;

	hash = hash_rrlimit(ip, sizeip);

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
	u_int64_t total = 0;
	int i, j;

	for (i = 0, j = 0; i < size; i += 2) {
		total += (u_int64_t)ip[j++];	
	}

	total %= 0xffff;

	return ((u_int16_t)total);
}	
