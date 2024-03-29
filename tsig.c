/*
 * Copyright (c) 2019-2023 Peter J. Philipp <pbug44@delphinusdns.org>
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

/*
 * this file is based on filter.c 
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

int	find_tsig(struct sockaddr_storage *, int);
void	init_tsig(void);
int	insert_tsig(char *, char *);
int	find_tsig_key(char *, int, char *, int);
void	init_tsig_key(void);
int	insert_tsig_key(char *, int, char *, int);
void	clean_tsig_keys(void);

extern void 		dolog(int, char *, ...);
extern in_addr_t 	getmask(int);
extern int 		getmask6(int, struct sockaddr_in6 *);
extern int		memcasecmp(u_char *, u_char *, int);

extern int debug, verbose;

int tsig = 0;		/* tsig is off by default */
SLIST_HEAD(, tsigkeyentry) tsigkeyhead;

static struct tsigkeyentry {
	char *keyname;
	int keynamelen;
	char *key;
	int keylen;
	SLIST_ENTRY(tsigkeyentry) tsig_key_entry;
} *tk2, *tknp;


SLIST_HEAD(, tsigentry) tsighead;
static struct tsigentry {
	char name[INET6_ADDRSTRLEN];
	int family;
	struct sockaddr_storage hostmask;
	struct sockaddr_storage netmask;
	uint8_t prefixlen;
	SLIST_ENTRY(tsigentry) tsig_entry;
} *tsign2, *tsignp;


/*
 * INIT_FILTER - initialize the tsig singly linked list
 */

void
init_tsig(void)
{
	SLIST_INIT(&tsighead);
	return;
}

/*
 * INSERT_FILTER - insert an address and prefixlen into the tsig slist
 */

int
insert_tsig(char *address, char *prefixlen)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	int pnum;
	int ret;

	pnum = atoi(prefixlen);
#if __OpenBSD__
	tsign2 = malloc_conceal(sizeof(struct tsigentry));
#else
	tsign2 = malloc(sizeof(struct tsigentry));      /* Insert after. */
#endif


	if (strchr(address, ':') != NULL) {
		tsign2->family = AF_INET6;
		sin6 = (struct sockaddr_in6 *)&tsign2->hostmask;
		if ((ret = inet_pton(AF_INET6, address, &sin6->sin6_addr.s6_addr)) != 1)
			return (-1);
		sin6->sin6_family = AF_INET6;
		sin6 = (struct sockaddr_in6 *)&tsign2->netmask;
		sin6->sin6_family = AF_INET6;
		if (getmask6(pnum, sin6) < 0) 
			return(-1);
		tsign2->prefixlen = pnum;
	} else {

		tsign2->family = AF_INET;
		sin = (struct sockaddr_in *)&tsign2->hostmask;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = inet_addr(address);
		sin = (struct sockaddr_in *)&tsign2->netmask;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = getmask(pnum);
		tsign2->prefixlen = pnum;

	}

	SLIST_INSERT_HEAD(&tsighead, tsign2, tsig_entry);

	return (0);
}

/*
 * FIND_FILTER - walk the tsig list and find the correponding network 
 *		   if a network matches return 1, if no match is found return
 *		   0.
 */

int
find_tsig(struct sockaddr_storage *sst, int family)
{
	struct sockaddr_in *sin, *sin0;
	struct sockaddr_in6 *sin6, *sin60, *sin61;
	uint32_t hostmask, netmask;
	uint32_t a;
#ifdef __amd64
	uint64_t *hm[2], *nm[2], *a6[2];
#else
	uint32_t *hm[4], *nm[4], *a6[4];
#endif

	SLIST_FOREACH(tsignp, &tsighead, tsig_entry) {
		if (tsignp->family == AF_INET) {
			if (family != AF_INET)
				continue;
			sin = (struct sockaddr_in *)sst;
			a = sin->sin_addr.s_addr;
			sin = (struct sockaddr_in *)&tsignp->hostmask;
			sin0 = (struct sockaddr_in *)&tsignp->netmask;
			hostmask = sin->sin_addr.s_addr;
			netmask = sin0->sin_addr.s_addr;
			if ((hostmask & netmask) == (a & netmask)) {
				return (1);
			} /* if hostmask */
		} else if (tsignp->family == AF_INET6) {
			if (family != AF_INET6)
				continue;
			sin6 = (struct sockaddr_in6 *)sst;
			sin60 = (struct sockaddr_in6 *)&tsignp->hostmask;	
			sin61 = (struct sockaddr_in6 *)&tsignp->netmask;
#ifdef __amd64
			/* 
			 * If this is on a 64 bit machine, we'll benefit
			 * by using 64 bit registers, this should make it
			 * a tad faster...
			 */
			hm[0] = (uint64_t *)&sin60->sin6_addr.s6_addr;
			hm[1] = (hm[0] + 1);
			nm[0] = (uint64_t *)&sin61->sin6_addr.s6_addr;
			nm[1] = (nm[0] + 1);
			a6[0] = (uint64_t *)&sin6->sin6_addr.s6_addr;
			a6[1] = (a6[0] + 1);
			if (	((*hm[0] & *nm[0]) == (*a6[0] & *nm[0]))&&
				((*hm[1] & *nm[1]) == (*a6[1] & *nm[1]))) {
#else
			hm[0] = (uint32_t *)&sin60->sin6_addr.s6_addr;
			hm[1] = (hm[0] + 1); hm[2] = (hm[1] + 1);
			hm[3] = (hm[2] + 1);
			nm[0] = (uint32_t *)&sin61->sin6_addr.s6_addr;
			nm[1] = (nm[0] + 1); nm[2] = (nm[1] + 1);
			nm[3] = (nm[2] + 1);
			a6[0] = (uint32_t *)&sin6->sin6_addr.s6_addr;
			a6[1] = (a6[0] + 1); a6[2] = (a6[1] + 1);
			a6[3] = (a6[2] + 1);

			if (	((*hm[0] & *nm[0]) == (*a6[0] & *nm[0]))&&
				((*hm[1] & *nm[1]) == (*a6[1] & *nm[1]))&&
				((*hm[2] & *nm[2]) == (*a6[2] & *nm[2]))&&
				((*hm[3] & *nm[3]) == (*a6[3] & *nm[3]))) {
#endif

					return (1);
			} /* if ip6 address */
			
		} /* if AF_INET6 */
	} /* SLIST */

	return (0);
}



/*
 * INIT_TSIG_KEY - initialize the tsig key singly linked list
 */

void
init_tsig_key(void)
{
	SLIST_INIT(&tsigkeyhead);
	return;
}

/*
 * INSERT_TSIG - insert an address and prefixlen into the tsig slist
 */

int
insert_tsig_key(char *key, int keylen, char *keyname, int keynamelen)
{
#if __OpenBSD__
	tk2 = malloc_conceal(sizeof(struct tsigkeyentry));
#else
	tk2 = malloc(sizeof(struct tsigkeyentry));      /* Insert after. */
#endif
	if (tk2 == NULL)
		return -1;

#if __OpenBSD__
	tk2->key = malloc_conceal(keylen);
#else
	tk2->key = malloc(keylen);
#endif
	if (tk2->key == NULL)
		return -1;

	memcpy(tk2->key, key, keylen);
	tk2->keylen = keylen;

#if __OpenBSD__
	tk2->keyname = malloc_conceal(keynamelen);
#else
	tk2->keyname = malloc(keynamelen);
#endif

	if (tk2->keyname == NULL) {
		return -1;
	}
	memcpy(tk2->keyname, keyname, keynamelen);
	tk2->keynamelen = keynamelen;

	SLIST_INSERT_HEAD(&tsigkeyhead, tk2, tsig_key_entry);

	return (0);
}

/*
 * FIND_TSIG_KEY - walk the tsig list and find the correponding key
 */

int
find_tsig_key(char *keyname, int keynamelen, char *key, int keylen)
{
	SLIST_FOREACH(tknp, &tsigkeyhead, tsig_key_entry) {
		if (keynamelen == tknp->keynamelen &&
			memcasecmp((u_char *)tknp->keyname, (u_char *)keyname, keynamelen) == 0) {
		
			if (keylen < tknp->keylen)
				return -1;
		
			memcpy(key, tknp->key, tknp->keylen);

			return (tknp->keylen);
		}
	} /* SLIST */

	return -1;
}

void
clean_tsig_keys(void)
{
	SLIST_FOREACH(tknp, &tsigkeyhead, tsig_key_entry) {
		if (!tknp->keynamelen || !tknp->keylen)
			continue;

		explicit_bzero((u_char *)tknp->keyname, tknp->keynamelen);
		explicit_bzero((u_char *)tknp->key, tknp->keylen);
		tknp->keylen = 0;
		tknp->keynamelen = 0;
	}

	return;
}
