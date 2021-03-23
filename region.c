/*
 * Copyright (c) 2010-2021 Peter J. Philipp <pjp@delphinusdns.org>
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

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>

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

u_int8_t 	find_region(struct sockaddr_storage *, int);
in_addr_t 	getmask(int);
int 		getmask6(int, struct sockaddr_in6 *);
void 		init_region(void);
int 		insert_region(char *, char *, u_int8_t);

SLIST_HEAD(listhead, regionentry) regionhead;

static struct regionentry {
	char name[INET6_ADDRSTRLEN];
	int family;
	struct sockaddr_storage hostmask;
	struct sockaddr_storage netmask;
	u_int8_t region; 
	u_int8_t prefixlen;
	SLIST_ENTRY(regionentry) region_entry;
} *n2, *np;


/*
 * INIT_REGION - initialize the region singly linked list
 */

void
init_region(void)
{
	SLIST_INIT(&regionhead);
	return;
}

/*
 * INSERT_REGION - insert particular address and prefix length  and region 
 * 			into the
 * 			singly linked list at "regionhead", if the address 
 *			contains
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
	n2 = malloc(sizeof(struct regionentry));      /* Insert after. */

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

	SLIST_INSERT_HEAD(&regionhead, n2, region_entry);

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

	SLIST_FOREACH(np, &regionhead, region_entry) {
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
