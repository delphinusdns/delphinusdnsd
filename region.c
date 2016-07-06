/* 
 * Copyright (c) 2010-2015 Peter J. Philipp
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
#include "ddd-include.h"
#include "ddd-dns.h"
#include "ddd-db.h"

u_int8_t 	find_region(struct sockaddr_storage *, int);
in_addr_t 	getmask(int);
int 		getmask6(int, struct sockaddr_in6 *);
void 		init_region(void);
int 		insert_region(char *, char *, u_int8_t);

SLIST_HEAD(listhead, entry) head;

static struct entry {
	char name[INET6_ADDRSTRLEN];
	int family;
	struct sockaddr_storage hostmask;
	struct sockaddr_storage netmask;
	u_int8_t region; 
	u_int8_t prefixlen;
	SLIST_ENTRY(entry) region_entry;
} *n2, *np;


static const char rcsid[] = "$Id: region.c,v 1.3 2016/07/06 05:12:51 pjp Exp $";

/*
 * INIT_REGION - initialize the region singly linked list
 */

void
init_region(void)
{
	SLIST_INIT(&head);
	return;
}

/*
 * INSERT_REGION - insert particular address and prefix length  and region 
 * 			into the
 * 			singly linked list at "head", if the address contains
 *			a colon then it is assumed to be an IPv6 address.
 *			return -1 on error, 0 on successful insertion
 */

int
insert_region(char *address, char *prefixlen, u_int8_t region)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	int pnum;
	int ret;

	pnum = atoi(prefixlen);
	n2 = malloc(sizeof(struct entry));      /* Insert after. */

	if (strchr(address, ':') != NULL) {
		n2->family = AF_INET6;
		sin6 = (struct sockaddr_in6 *)&n2->hostmask;
		if ((ret = inet_pton(AF_INET6, address, &sin6->sin6_addr.s6_addr)) != 1)
			return (-1);
		sin6->sin6_family = AF_INET6;
		sin6 = (struct sockaddr_in6 *)&n2->netmask;
		sin6->sin6_family = AF_INET6;
		if (getmask6(pnum, sin6) < 0) 
			return(-1);
		n2->region = region;
		n2->prefixlen = pnum;
	} else {

		n2->family = AF_INET;
		sin = (struct sockaddr_in *)&n2->hostmask;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = inet_addr(address);
		sin = (struct sockaddr_in *)&n2->netmask;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = getmask(pnum);
		n2->region = region;
		n2->prefixlen = pnum;

	}

	SLIST_INSERT_HEAD(&head, n2, region_entry);

	return (0);
}

/*
 * FIND_REGION - walk the region list and find the correponding network with
 * 		 the highest prefix length, so that a /24 has more precedence 
 *			than
 *		 a /8 for example.  IPv6 and IPv4 addresses are kept seperate
 */

u_int8_t
find_region(struct sockaddr_storage *sst, int family)
{
	struct sockaddr_in *sin, *sin0;
	struct sockaddr_in6 *sin6, *sin60, *sin61;
	u_int32_t hostmask, netmask;
	u_int32_t a;
#ifdef __amd64
	u_int64_t *hm[2], *nm[2], *a6[2];
#else
	u_int32_t *hm[4], *nm[4], *a6[4];
#endif
	u_int8_t region = 0xff;
	u_int8_t prefixlen = 0;

	SLIST_FOREACH(np, &head, region_entry) {
		if (np->family == AF_INET) {
			if (family != AF_INET)
				continue;
			sin = (struct sockaddr_in *)sst;
			a = sin->sin_addr.s_addr;
			sin = (struct sockaddr_in *)&np->hostmask;
			sin0 = (struct sockaddr_in *)&np->netmask;
			hostmask = sin->sin_addr.s_addr;
			netmask = sin0->sin_addr.s_addr;
			if ((hostmask & netmask) == (a & netmask)) {
				if (np->prefixlen >= prefixlen) {
					region = np->region;
					prefixlen = np->prefixlen;
				} 
			} /* if hostmask */
		} else if (np->family == AF_INET6) {
			if (family != AF_INET6)
				continue;
			sin6 = (struct sockaddr_in6 *)sst;
			sin60 = (struct sockaddr_in6 *)&np->hostmask;	
			sin61 = (struct sockaddr_in6 *)&np->netmask;
#ifdef __amd64
			/* 
			 * If this is on a 64 bit machine, we'll benefit
			 * by using 64 bit registers, this should make it
			 * a tad faster...
			 */
			hm[0] = (u_int64_t *)&sin60->sin6_addr.s6_addr;
			hm[1] = (hm[0] + 1);
			nm[0] = (u_int64_t *)&sin61->sin6_addr.s6_addr;
			nm[1] = (nm[0] + 1);
			a6[0] = (u_int64_t *)&sin6->sin6_addr.s6_addr;
			a6[1] = (a6[0] + 1);
			if (	((*hm[0] & *nm[0]) == (*a6[0] & *nm[0]))&&
				((*hm[1] & *nm[1]) == (*a6[1] & *nm[1]))) {
#else
			hm[0] = (u_int32_t *)&sin60->sin6_addr.s6_addr;
			hm[1] = (hm[0] + 1); hm[2] = (hm[1] + 1);
			hm[3] = (hm[2] + 1);
			nm[0] = (u_int32_t *)&sin61->sin6_addr.s6_addr;
			nm[1] = (nm[0] + 1); nm[2] = (nm[1] + 1);
			nm[3] = (nm[2] + 1);
			a6[0] = (u_int32_t *)&sin6->sin6_addr.s6_addr;
			a6[1] = (a6[0] + 1); a6[2] = (a6[1] + 1);
			a6[3] = (a6[2] + 1);
			if (	((*hm[0] & *nm[0]) == (*a6[0] & *nm[0]))&&
				((*hm[1] & *nm[1]) == (*a6[1] & *nm[1]))&&
				((*hm[2] & *nm[2]) == (*a6[2] & *nm[2]))&&
				((*hm[3] & *nm[3]) == (*a6[3] & *nm[3]))) {
#endif

				if (np->prefixlen >= prefixlen) {
					region = np->region;
					prefixlen = np->prefixlen;
				}
			} /* if ip6 address */
			
		} /* if AF_INET6 */
	} /* SLIST */

	return (region);
}

/*
 * GETMASK - get the v4 netmask given by prefix length, return netmask in 
 * 		network byte order, function can't fail unless prefix length
 *		supplied is > 32
 */

in_addr_t
getmask(int prefixlen)
{
	in_addr_t ret = 0xffffffff;

	/* I know it's cheating */
	if (prefixlen > 31)
		return (htonl(ret));

	ret >>= prefixlen;		/* 0x00ffffff */
	ret = ~ret; 		/* 0xff000000 */

	return (htonl(ret));
}

/*
 * GETMASK6 - like getmask() but works on a supplied sockaddr_in6 instead of
 *   		returning results as return address.  Function cannot fail
 * 		unless prefix length supplied is > 128.  At which point a buffer
 *		overflow is possible.
 */

int
getmask6(int prefixlen, struct sockaddr_in6 *sin6)
{
	int i, j;
	u_int32_t *nm[4];

	if (prefixlen > 128 || prefixlen < 0)
		return (-1);

	memset(&sin6->sin6_addr.s6_addr, 0xff, sizeof(sin6->sin6_addr.s6_addr));
	nm[0] = (u_int32_t *)sin6->sin6_addr.s6_addr;
	nm[1] = (nm[0] + 1); nm[2] = (nm[1] + 1);
	nm[3] = (nm[2] + 1);

	for (i = 0, j = 0; j < prefixlen; j++) {
		if (*nm[i] == 1) {
			*nm[i] = 0;
			i++;
		} else
			*nm[i] >>= 1;
	}
	*nm[0] = htonl(~ *nm[0]);
	*nm[1] = htonl(~ *nm[1]);
	*nm[2] = htonl(~ *nm[2]);
	*nm[3] = htonl(~ *nm[3]);
	
	return (0);
}
