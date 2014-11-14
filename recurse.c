/*
 * Copyright (c) 2010-2014 Peter J. Philipp
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

extern struct question 	*build_fake_question(char *, int, u_int16_t);
extern struct question 	*build_question(char *, int);
extern void 		build_reply(struct sreply *, int, char *, int, struct question *, struct sockaddr *, socklen_t, struct domain *, struct domain *, u_int8_t, int, int, struct recurses *);
extern void 		dolog(int, char *, ...);
extern int 		free_question(struct question *);
extern int 		get_soa(DB *, struct question *, struct domain *, int);
extern in_addr_t 	getmask(int);
extern int 		getmask6(int, struct sockaddr_in6 *);
extern int 		lookup_zone(DB *, struct question *, struct domain *, int *, char *, int);
extern int 		memcasecmp(u_char *, u_char *, int);
extern void 		reply_a(struct sreply *, DB *);
extern void 		reply_aaaa(struct sreply *, DB *);
extern void 		reply_cname(struct sreply *);
extern void 		reply_mx(struct sreply *, DB *);
extern void 		reply_ns(struct sreply *, DB *);
extern void 		reply_noerror(struct sreply *);
extern void 		reply_nxdomain(struct sreply *);
extern void 		reply_ptr(struct sreply *);
extern void 		reply_soa(struct sreply *);
extern void 		reply_txt(struct sreply *sreply);
extern void 		slave_shutdown(void);
extern void 		update_db(DB *, struct domain *);

int 	contains(u_char *, u_char *);
void 	init_recurse(void);
int 	insert_recurse(char *, char *);
int 	fakerecurse(DB *, struct recurses *, struct ns *, int);
int 	find_recurse(struct sockaddr_storage *, int);
int 	level(u_char *);
int 	lookup_a(DB *, struct recurses *, struct ns *);
int 	lookup_aaaa(DB *, struct recurses *, struct ns *);
int 	lookup_ns(DB *, struct recurses *);
int 	negative_cache(DB *, struct recurses *);
int 	netlookup(DB *, struct recurses *);
int 	netlookup6(DB *, struct recurses *);
void 	recurseloop(int, int *, DB *);
int 	recurse_parse(DB *, struct recurses *, u_char *, u_int16_t);
void 	reply_raw(DB *, struct recurses *, struct domain *, int *);
void 	reply_raw_cname(DB *, struct recurses *, struct domain *, int *);
void 	reply_raw_noerror(DB *, struct recurses *, struct domain *, int *);
void 	reply_raw_nxdomain(DB *, struct recurses *, struct domain *, int *);
void 	remove_zone(DB *, struct domain *);

extern int debug, verbose;

#ifndef MIN
#define MIN(a,b)	((a < b) ? a : b)
#endif

SLIST_HEAD(listhead, recurseentry) recursehead;

static struct recurseentry {
	char name[INET6_ADDRSTRLEN];
	int family;
	struct sockaddr_storage hostmask;
	struct sockaddr_storage netmask;
	u_int8_t prefixlen;
	SLIST_ENTRY(recurseentry) recurse_entry;
} *rn2, *rnp;


static const char rcsid[] = "$Id: recurse.c,v 1.1.1.1 2014/11/14 08:09:04 pjp Exp $";

/*
 * INIT_RECURSE - initialize the recurse singly linked list
 */

void
init_recurse(void)
{
	SLIST_INIT(&recursehead);
	return;
}

/*
 * INSERT_RECURSE - insert an address and prefixlen into the recurse slist
 */

int
insert_recurse(char *address, char *prefixlen)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	int pnum;
	int ret;

	pnum = atoi(prefixlen);
	rn2 = malloc(sizeof(struct recurseentry));      /* Insert after. */

	if (strchr(address, ':') != NULL) {
		rn2->family = AF_INET6;
		sin6 = (struct sockaddr_in6 *)&rn2->hostmask;
		if ((ret = inet_pton(AF_INET6, address, &sin6->sin6_addr.s6_addr)) != 1)
			return (-1);
		sin6->sin6_family = AF_INET6;
		sin6 = (struct sockaddr_in6 *)&rn2->netmask;
		sin6->sin6_family = AF_INET6;
		if (getmask6(pnum, sin6) < 0) 
			return(-1);
		rn2->prefixlen = pnum;
	} else {

		rn2->family = AF_INET;
		sin = (struct sockaddr_in *)&rn2->hostmask;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = inet_addr(address);
		sin = (struct sockaddr_in *)&rn2->netmask;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = getmask(pnum);
		rn2->prefixlen = pnum;

	}

	SLIST_INSERT_HEAD(&recursehead, rn2, recurse_entry);

	return (0);
}

/*
 * FIND_RECURSE - walk the recurse list and find the correponding network 
 *		   if a network matches return 1, if no match is found return
 *		   0.
 */

int
find_recurse(struct sockaddr_storage *sst, int family)
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

	SLIST_FOREACH(rnp, &recursehead, recurse_entry) {
		if (rnp->family == AF_INET) {
			if (family != AF_INET)
				continue;
			sin = (struct sockaddr_in *)sst;
			a = sin->sin_addr.s_addr;
			sin = (struct sockaddr_in *)&rnp->hostmask;
			sin0 = (struct sockaddr_in *)&rnp->netmask;
			hostmask = sin->sin_addr.s_addr;
			netmask = sin0->sin_addr.s_addr;
			if ((hostmask & netmask) == (a & netmask)) {
				return (1);
			} /* if hostmask */
		} else if (rnp->family == AF_INET6) {
			if (family != AF_INET6)
				continue;
			sin6 = (struct sockaddr_in6 *)sst;
			sin60 = (struct sockaddr_in6 *)&rnp->hostmask;	
			sin61 = (struct sockaddr_in6 *)&rnp->netmask;
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

					return (1);
			} /* if ip6 address */
			
		} /* if AF_INET6 */
	} /* SLIST */

	return (0);
}

void 
recurseloop(int sp, int *raw, DB *db)
{
	int sel, ret;
	int maxso, len;
	socklen_t slen = sizeof(struct sockaddr_storage);
	fd_set rset;
	struct timeval tv;
	struct srecurseheader rh;
	struct domain sd;
	struct dns_header *dh;
	struct sockaddr_storage ssin;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	
	int type, lzerrno, wildcard = 0;
		
	char fakereplystring[DNS_MAXNAME + 1];
	char buf[2048];
	char address[INET6_ADDRSTRLEN];

	SLIST_INIT(&recurseshead);

	for (;;) {
		/*
		 * launch all fakesr requests
		 */
		SLIST_FOREACH(sr1, &recurseshead, recurses_entry) {
			if (sr1->isfake && !sr1->launched) {
				dolog(LOG_DEBUG, "launching question (fakesr) for %s", sr1->question->hdr->name);
				sr1->launched = 1;
				type = lookup_zone(db, sr1->question, &sd, &lzerrno, (char *)fakereplystring, wildcard);
				if (type < 0) {
         				netlookup(db, sr1);
				} else {
					SLIST_REMOVE(&recurseshead, sr1, recurses, recurses_entry);
					sr1->callback->hascallback--;
					free_question(sr1->question);
					free(sr1);
 				}
			}

			/*
 			 * while we're going through the list to look for 
			 * fakesr launches we may as well expire recurses
			 * that have timed out (> 10 seconds)
			 */			
			if (difftime(time(NULL), sr1->received) >= 30) {
				/* only remove if we don't have any callbacks
			 	 * outstanding...
				 */
				if (! sr1->hascallback) {
					dolog(LOG_DEBUG, "removing recurses struct");
					SLIST_REMOVE(&recurseshead, sr1, recurses, recurses_entry);
					if (sr1->so != -1) {
						if (close(sr1->so) < 0)
							dolog(LOG_ERR, "close: %m");
						sr1->so = -1;
					}
	
					if (sr1->callback)
						sr1->callback->hascallback--;

					free_question(sr1->question);
					free(sr1);
				}
			}
		}
		FD_ZERO(&rset);
		
		maxso = sp;
		FD_SET(sp, &rset);

		/* XXX remember recurseshead is for struct recurses */
		SLIST_FOREACH(sr1, &recurseshead, recurses_entry) {
			if (sr1->so != -1) {
				if (maxso < sr1->so)
					maxso = sr1->so;

				FD_SET(sr1->so, &rset);
			}
		}

		tv.tv_sec = 1;
		tv.tv_usec = 0;
		sel = select(maxso + 1, &rset, NULL, NULL, &tv);
		if (sel < 0) {
			dolog(LOG_INFO, "select: %m");
			continue;
		} else if (sel == 0) {
			/* timeout */	
			continue;	
		}

		if (FD_ISSET(sp, &rset)) {
			ret = recv(sp, (char *)&rh, sizeof(rh), 0);
			if (ret < 0) {
				dolog(LOG_INFO, "recv: %m");
				continue;
			}

			/* place request on struct recurses linked list */

			sr = calloc(sizeof(struct recurses), 1);
			if (sr == NULL) {
				dolog(LOG_ERR, "calloc: %m");
				continue;
			}	

			memcpy(&sr->query, &rh.buf, 512);
			sr->len = rh.len;
			sr->af = rh.af;
			sr->proto = rh.proto;
			sr->so = -1;
			sr->callback = NULL;
			sr->hascallback = 0;
			sr->isfake = 0;
			sr->packetcount = 0;
			sr->lookrecord = NULL;
			memcpy(&sr->source, &rh.source, sizeof(struct sockaddr_storage));
			memcpy(&sr->dest, &rh.dest, sizeof(struct sockaddr_storage));
			sr->received = time(NULL);

			sr->question = build_question(sr->query, sr->len);
			if (sr->question == NULL) {
				dolog(LOG_ERR, "malformed question in recurse.c");
				free(sr);
				continue;
			}
	
			type = lookup_zone(db, sr->question, &sd, &lzerrno, (char *)fakereplystring, wildcard);
			if (type < 0) {
				if (lzerrno == ERR_NOERROR && 
					(sd.flags & DOMAIN_NEGATIVE_CACHE) ==
						DOMAIN_NEGATIVE_CACHE) {

					reply_raw_nxdomain(db, sr, &sd, raw);
					free_question(sr->question);
					free(sr);
					continue;
					
				}
				if (netlookup(db, sr) < 0)
					continue;

				SLIST_INSERT_HEAD(&recurseshead, sr, recurses_entry);	
			} else {
				dolog(LOG_DEBUG, "we had the record in our cache, reply action");
				/* check if zone is expired */

				if ((! (sd.flags & DOMAIN_STATIC_ZONE)) &&
				     (sd.created + sd.ttl < time(NULL))) {
					remove_zone(db, &sd);	
	
					/* continue with netlookup */
			
					if (netlookup(db, sr) < 0)
						continue;

					SLIST_INSERT_HEAD(&recurseshead, sr, recurses_entry);
					continue;
				}

				if (type == DNS_TYPE_CNAME)
					reply_raw_cname(db, sr, &sd, raw);
				else
					reply_raw(db, sr, &sd, raw);

				free_question(sr->question);
				free(sr);
				continue;
			}
	
		} /* FD_ISSET(sp) */

		SLIST_FOREACH(sr1, &recurseshead, recurses_entry) {
			if (sr1->so != -1 && FD_ISSET(sr1->so, &rset)) {
				/*
				 * we got a reply from the nameserver we 
				 * queried, now we must parse the input 
				 */
				
				slen = sizeof(struct sockaddr_storage);	
				if ((len = recvfrom(sr1->so, buf, sizeof(buf), 0, (struct sockaddr *)&ssin, &slen)) < 0) {
					if (errno != EWOULDBLOCK)
						dolog(LOG_ERR, "recvfrom: %m");
					continue;
				}
	
#if 1
				/* XXX do some checking of expected IP address */

				switch (ssin.ss_family) {
				case AF_INET:
					sin = (struct sockaddr_in *)&ssin;
					if (sin->sin_addr.s_addr != sr1->a[0]) {
						dolog(LOG_ERR, "return address is not from right nameserver");
						continue;
					}
					break;
				case AF_INET6:
					sin6 = (struct sockaddr_in6*)&ssin;
					if (memcmp((char *)&sin6->sin6_addr, (char *)&sr1->aaaa[0], sizeof(struct in6_addr)) != 0) {
						inet_ntop(AF_INET6, &sin6->sin6_addr, address, sizeof(address));
						
						dolog(LOG_ERR, "return IPv6 address (%s) is not from right nameserver", address);
						continue;
					}
					break;
				}
#endif
				
				if (len < sizeof(struct dns_header)) {
					dolog(LOG_ERR, "size malformed on reply len=%d", len);
					/* on error, we just go out and wait for the real ID, this sucks! XXX */
					continue;
				}

				dh = (struct dns_header*)&buf[0];

				if (ntohs(dh->id) != sr1->id) {
					dolog(LOG_ERR, "unexpected dns ID (%u != %u)", ntohs(dh->id), sr1->id);
					/* on error, we just go out and wait for the real ID, this sucks! XXX */
					continue;
				}

				if (! (ntohs(dh->query) & DNS_REPLY)) {
					dolog(LOG_ERR, "reply is not a DNS reply");
					continue;
				}

				/* XXX */

				if (close(sr1->so) < 0)
					dolog(LOG_ERR, "close: %m");

				sr1->so = -1;

				if (ntohs(dh->query) & DNS_NAMEERR) {
					negative_cache(db, sr1);
					dolog(LOG_DEBUG, "added negative cache for domain \"%s\"", sr1->question->converted_name);
					/* reply negatively */
					reply_raw_nxdomain(db, sr1, &sd, raw);
					goto remove;
				}

				sr1->authoritative = 0;
				recurse_parse(db, sr1, (u_char*)&buf, len);

				/* check if we're flooding anything */
				if (sr1->packetcount > 50) {
					dolog(LOG_ERR, "packetcount is over 50, I think I'm flooding something, abort()");
					slave_shutdown();
					abort();
				}

				type = lookup_zone(db, sr1->question, &sd, &lzerrno, (char *)fakereplystring, wildcard);
				if (type < 0) {
					dolog(LOG_DEBUG, "lookup_zone failed, doing netlookup");

					if (sr1->authoritative == DNS_TYPE_NS &&
						netlookup(db, sr1) < 0) {
						dolog(LOG_DEBUG, "subsequent netlookup failed");

					}

					if (sr1->authoritative == DNS_TYPE_SOA) {	
						dolog(LOG_DEBUG, "got an authoritative SOA answer, we'd reply an SOA here");
						memset(&sd, 0, sizeof(struct domain));
						get_soa(db, sr1->question, &sd, wildcard);

						reply_raw_noerror(db, sr, &sd, raw);
						if (sr1->callback)
							sr1->callback->hascallback--;
						goto remove;
					}

					continue;
				} else {
					/* we've found the record we're looking
				 	 * for do something with it.. 	
					 */

					if (sr1->isfake) {
						/* do another netlookup with the callback */
						dolog(LOG_DEBUG, "sr is fake, doing netlookup on the callback");
	
						if (netlookup(db, sr1->callback) < 0) {
							dolog(LOG_DEBUG, "callback netlookup failed");
						}

						sr1->callback->hascallback--;
						/* XXX continue; */


					} else {
						if (type == DNS_TYPE_CNAME)
							reply_raw_cname(db, sr, &sd, raw);
						else
							reply_raw(db, sr1, &sd, raw);
					}
				}
remove:
				/* only remove if we don't have any callbacks
			 	 * outstanding...
				 */
				if (! sr1->hascallback) {
					SLIST_REMOVE(&recurseshead, sr1, recurses, recurses_entry);
					free_question(sr1->question);
					free(sr1);
				}

			} /* FD_ISSET(sr1->so */
		} /* SLIST_FOREACH(sr... */

#if 0
/*
   	I drew this on a notepad one night, I think that's supposed to how
 	it shoudl go...

     +----------------+                 +--------------------------+
     |                |                 |                          |
     |                v                 v                          |
     |  -------------------- select -------------------            |
     |          ||                           ||                    |
     |          ||                           ||                    |
     |        +----+                       +----+                  |
     |        |    | take request          |    |  parse reply     |
     |        +----+ from authoritative    +----+  and insert      |
     |          ||   side                /         new record      |
     |          ||                      /                          |
     |          ||                     /                           |
     |          ||    +---------------+                            |
     |          ||   /                                             |
     |          ||  / bad or expired                               |
     |        +----+=====================>+----+  lookup record    |
     |        |    | lookup name in db    |    |  on the net       |
     |        +----+                      +----+-------------------+
     |          ||
     |          || good
     |          ||
     |        +----+
     |        |    | reply
     |        +----+
     |          ||
     |          ||
     |          ||
     |        +----+
     +--------|    | cleanup
              +----+

*/

#endif


	} /* for(;;) */

	/* NOTREACHED */
}

/*
 * LOOKUP_NS - given an address try to look up the nameservers anywhere along
 *             its path. return number of servers reachable or -1 on error.
 */

int
lookup_ns(DB *db, struct recurses *sr)
{
	int ret, plen, i;
	int onemore = 0;
	char *p;

	DBT key, data;

	struct domain *sd, mydomain;

	p = sr->question->hdr->name;
	plen = sr->question->hdr->namelen;

	do {
again:
		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));

		key.data = (char *)p;
		key.size = plen;

		data.data = NULL;
		data.size = 0;

		ret = db->get(db, NULL, &key, &data, 0);
		if (ret != 0) {
			if (*p != 0) {
				plen -= (*p + 1);
				p = (p + (*p + 1));
				sr->indicator++;
			} 

			/* XXX this is different from lookup_zone(), not
			 * sure how it even works there...
			 */
			if (*p == 0 && ! onemore) {
				plen = 1;
				onemore = 1;	
				sr->indicator++;
				goto again; 	/* XXX */
			}
		} else { 
			/* we have a lookup */
	
			if (data.size != sizeof(struct domain)) {
				dolog(LOG_ERR, "btree db is damaged");
				return (-1);
			}	
	
#if 0
			dolog(LOG_DEBUG, "we gots a lookup, yay!\n");
#endif

			/* 
			 * record which record we used
			 */

			sr->lookrecord = (u_char *)p;

			memcpy((char *)&mydomain, (char *)data.data, sizeof(struct domain));
			sd = (struct domain *)&mydomain;
	
			/* 
			 * If we're not a static zone (like hints) and we're
			 * expired then we go on to the next indicator..
			 * .. but first we must remove this zone...
			 */
			if ((! (sd->flags & DOMAIN_STATIC_ZONE)) && 
				(time(NULL) > (sd->created + sd->ttl))) {

				remove_zone(db, sd);
				
				if (*p != 0) {
					plen -= (*p + 1);
					p = (p + (*p + 1));
					sr->indicator++;
					continue;
				} else {
					return (-1);
				}
			}
			/*
			 * If we have a negative cache, then just return with
			 * error.
			 */
			if ((sd->flags & DOMAIN_NEGATIVE_CACHE) &&
				(time(NULL) <= (sd->created + sd->ttl))) {
				return (-1);
			}

			sr->aaaa_count = 0;
			sr->a_count = 0;
			sr->a_ptr = 0;

			for (i = 0; i < sd->ns_count; i++) {
				if (sr->af == AF_INET6) {
					if (lookup_aaaa(db, sr, &sd->ns[(sd->ns_ptr + i) % sd->ns_count] ) < 0) 
						continue;
					sr->aaaa_count++;
				} else {
					if (lookup_a(db, sr, &sd->ns[(sd->ns_ptr + i) % sd->ns_count] ) < 0) 
						continue;
					sr->a_count++;
				}
			}

			if (sd->ns_count)
				sd->ns_ptr = (sd->ns_ptr + 1) % sd->ns_count;
			else
				sd->ns_ptr = 0;

			update_db(db, sd);

			break;
		}

	} while (*p != 0 && ret != 0);
	
#if 1
	dolog(LOG_DEBUG, "got %d addresses for %s, indicator %d\n", sr->a_count, sr->question->hdr->name, sr->indicator);

#endif

	return ((sr->af == AF_INET6) ? sr->aaaa_count : sr->a_count);
}


/*
 * LOOKUP_A - given a path, lookup the A record in that record
 * 
 */

int
lookup_a(DB *db, struct recurses *sr, struct ns *ns)
{
	int ret, plen;
	char *p;

	DBT key, data;

	struct domain *sd, sdomain;
	int found = 0;

	p = ns->nsserver;
	plen = ns->nslen;

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	key.data = (char *)p;
	key.size = plen;

	data.data = NULL;
	data.size = 0;

	found = 0;

	ret = db->get(db, NULL, &key, &data, 0);
	if (ret == 0) {
		if (data.size != sizeof(struct domain)) {
			dolog(LOG_ERR, "btree db is damaged");
			return (-1);
		}	

		memcpy((char*)&sdomain, data.data, sizeof(struct domain));
		sd = &sdomain;

		if ((sd->flags & DOMAIN_HAVE_A) == DOMAIN_HAVE_A) {
			memcpy((char *)&sr->a[sr->a_count], (char *)&sd->a[0], sizeof(in_addr_t));
			sd->a_count++;
			found = 1;

		}
	}	

	if (! found) {
		dolog(LOG_DEBUG, "calling fakerecurse");
		fakerecurse(db, sr, ns, DNS_TYPE_A);
		return (-1);
	}

	return (0);
}

/* 
 * NEGATIVE_CACHE - cache a lookup as negative (NXDOMAIN)
 * 
 */

int
negative_cache(DB *db, struct recurses *sr)
{
	struct domain sd;

	memset(&sd, 0, sizeof(sd));

	sd.zonelen = sr->question->hdr->namelen;

	memcpy((char *)&sd.zone, (char *)sr->question->hdr->name, sd.zonelen);

#if __linux__
	strncpy((char *)&sd.zonename, (char *)sr->question->converted_name, DNS_MAXNAME);
	sd.zonename[DNS_MAXNAME] = 0;
#else
	strlcpy((char *)&sd.zonename, (char *)sr->question->converted_name, DNS_MAXNAME + 1);
#endif                        

	sd.created = time(NULL);
	sd.ttl = NEGATIVE_CACHE_TIME;		/* 10 minutes */

	sd.flags |= DOMAIN_NEGATIVE_CACHE;

	update_db(db, &sd);

	return (0);
}

/* 
 * RECURSE_PARSE - based on compress_label.
 *
 */

int
recurse_parse(DB *db, struct recurses *sr, u_char *buf, u_int16_t offset)
{
	u_char *label[256];		/* should be enough */
	static u_char converted_name[256][256];
	u_int8_t cn_len[256];
	u_char *end = &buf[offset];
	int update;
	int rrcount[3];		/* RR count answer, authoritative, additional */
	int pointer = 0;	/* default answer */
	int txtlen;

	char abuf[INET6_ADDRSTRLEN];

	DBT key, data;

	struct domain sdomain;
	struct dns_header *dh;
	struct question {
		u_int16_t type;
		u_int16_t class;
	} __attribute__((packed));
	struct answer {
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 
	} __attribute__((packed));
	struct mysoa {
         	u_int32_t serial;
                u_int32_t refresh;
                u_int32_t retry;
                u_int32_t expire;
                u_int32_t minttl;
        } __attribute__((packed));

	struct answer *a;
	struct mysoa *mysoa;
	struct soa *soa;
	struct ns ns;

	u_int i, j, k;
	u_int16_t *compressor;
	u_int16_t c;
	u_int16_t *preference;

	int found = 0;

	u_char *p, *q, *r;

	dh = (struct dns_header*)&buf[0];
	rrcount[pointer++] = ntohs(dh->answer);	
	rrcount[pointer++] = ntohs(dh->nsrr);
	rrcount[pointer++] = ntohs(dh->additional);
	
	pointer = 0;
	while (rrcount[pointer] == 0) {
		pointer++;
		if (pointer > 2)
			return (-1);
	}

	p = &buf[sizeof(struct dns_header)];
	label[0] = p;
	
	while (p <= end && *p) {
		p += *p;
		p++;
	}	
		
	/* 
	 * the question label was bogus, we'll just get out of there, return 0
	 */

	if (p > end)
		return (-1);

	p += sizeof(struct question);	
	p++;	/* one more */
	/* start of answer/additional/authoritative */	

	for (i = 1; i < 100; i++) {
		label[i] = p;

		while (p <= end && *p) {
			if ((*p & 0xc0) == 0xc0) {
				p++;
				break;
			}
			p += *p;
			p++;

			if (p > end)
				goto end;
		}	
			
		p++;	/* one more */


		a = (struct answer *)p;
		p += sizeof(struct answer);	

		if (p > end)
			goto end;

		switch (ntohs(a->type)) {
		case DNS_TYPE_A:
			p += sizeof(in_addr_t);
			break;
		case DNS_TYPE_AAAA:
			p += 16;		/* sizeof 4 * 32 bit */
			break;
		case DNS_TYPE_TXT:
			p += *p;
			p++;
			break;
		case DNS_TYPE_MX:
			p += sizeof(u_int16_t);	 /* mx_priority */
			/* FALLTHROUGH */
		case DNS_TYPE_NS:	
		case DNS_TYPE_PTR:
		case DNS_TYPE_CNAME:
			label[++i] = p;
			while (p <= end && *p) {
				if ((*p & 0xc0) == 0xc0) {
					p++;
					break;
				}
				p += *p;
				p++;

				if (p > end)
					goto end;
			}	

			p++;	/* one more */
			break;
		case DNS_TYPE_SOA:
			/* nsserver */
			label[++i] = p;
			while (p <= end && *p) {
				if ((*p & 0xc0) == 0xc0) {
					p++;
					break;
				}
				p += *p;
				p++;
				if (p > end)
					goto end;
			}	

			p++;	/* one more */

			if (p > end)
				goto end;

			/* responsible person */
			label[++i] = p;
			while (p <= end && *p) {
				if ((*p & 0xc0) == 0xc0) {
					p++;
					break;
				}
				p += *p;
				p++;
			}	

			p++;	/* one more */

			if (p > end)
				goto end;

			p += sizeof(struct mysoa);	/* advance struct soa */

			break;
		default:
			break;
			/* XXX */
		} /* switch */

		if (p >= end)
			break;
	} /* for (i *) */

	/* 
	 * go through our list of labels and expand them from possible 
	 * compression, then we make our next pass..
	 */

	for (j = 0; j <= i; j++) {
		q = converted_name[j];
		p = label[j];
again:
		for (; *p ; p += *p, p++) {
			if ((*p & 0xc0) == 0xc0)
				break;

			r = (p + 1);

			*q++ = *p;

			for (k = 0; k < *p; k++)
				*q++ = tolower(r[k]);
		}
		
		if ((*p & 0xc0) == 0xc0) {
			compressor = (u_int16_t *)p;
			c = (ntohs(*compressor) & ~(0xc000));
			for (k = 0; k <= i; k++) {
				found = 0;
				for (r = label[k]; *r; r += *r, r++) {
					if (r - buf == c) {
						p = r;
						found = 1;
					}
						

					/*
					 * we're searching for an offset in
					 * non-compressed form, but we 
					 * encountered compression, so we 
					 * break and go to the next label
					 */

					if ((*r & 0xc0) == 0xc0) {
						break;
					}
				}

				if (found) {
					/* 
					 * pretend we found a match but we
					 * have compression inside pointing
					 * down, then break this, it's corrupt
					 * it's a possible loop attempt	
					 */
					if ((*r & 0xc0) == 0xc0) {
						compressor = (u_int16_t *)r;
						if ((ntohs(*compressor) & ~0xc000) >= c) 
							break;
					}

					goto again;
				}
			}

			/* 
			 * if we fall through the for loop, we didn't find the
			 * recursive label... corrupt.
			 */

			dolog(LOG_ERR, "corrupt compression");
			return (-1);
		}

		*q++ = '\0';	/* don't forget this */
		cn_len[j] = (q - converted_name[j]);
			
	} /* for (j .. */

#if 0
	for (j = 0; j <= i; j++) {
		dolog(LOG_DEBUG, "%s with length %u", converted_name[j], cn_len[j]);
	}
#endif

	p = &buf[sizeof(struct dns_header)];
	label[0] = p;
	
	while (p <= end && *p) {
		p += *p;
		p++;
	}	
		
	/* 
	 * the question label was bogus, we'll just get out of there, return 0
	 */

	if (p > end)
		return (-1);

	p += sizeof(struct question);	
	p++;	/* one more */
	/* start of answer/additional/authoritative */	

	for (i = 1; i < 100; i++) {
		label[i] = p;

		while (p <= end && *p) {
			if ((*p & 0xc0) == 0xc0) {
				p++;
				break;
			}
			p += *p;
			p++;

			if (p > end)
				goto end;
		}	
			
		p++;	/* one more */


		a = (struct answer *)p;
		p += sizeof(struct answer);	

		/* load our record */
		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));

		key.data = (char *)converted_name[i];
		key.size = cn_len[i];

		data.data = NULL;
		data.size = 0;

		memset((char *)&sdomain, 0, sizeof(struct domain));
		if (db->get(db, NULL, &key, &data, 0) == 0) {
			if (data.size != sizeof(struct domain)) {
				dolog(LOG_INFO, "damaged btree database");
				return -1;
			}

			memcpy((char *)&sdomain, (char *)data.data, data.size);

		}


		if (sdomain.zone == NULL) {
			memcpy(&sdomain.zone, converted_name[i], cn_len[i]);
			sdomain.zonelen = cn_len[i];
		}


		switch (ntohs(a->type)) {
		case DNS_TYPE_A:
			/* 
			 * scan addresses in this struct domain and check if
			 * this one exists already...
			 */

			update = 1;
			for (j = 0; j < sdomain.a_count; j++) {	
				if (memcmp(&sdomain.a[j], p, sizeof(in_addr_t)) == 0) {
#if 0
					dolog(LOG_INFO, "record exists already");
#endif
					update = 0;
				}
			}
	
			if (j >= RECORD_COUNT) {
				dolog(LOG_INFO, "db can't hold any more records\n");
				update = 0;
			}
			
			/*
			 * check if we're a 2nd level domain or higher and
			 * if we were directly querying the zone...
			 */

			if (update) {
				if (level(sr->lookrecord) > 1) {
					if (!contains(sr->lookrecord, converted_name[i])) {
						memcpy(ns.nsserver, converted_name[i], cn_len[i]);
						ns.nslen = cn_len[i];

						fakerecurse(db, sr, &ns, DNS_TYPE_A);
						update = 0;
					} 
				} 
			} 
			

			if (update) {
				memcpy(&sdomain.a[j], p, sizeof(in_addr_t));	
				sdomain.a_count++;
				sdomain.region[j] = 0xff;
				sdomain.a_ptr = 0;
				sdomain.flags |= DOMAIN_HAVE_A;
				sdomain.flags &= ~(DOMAIN_NEGATIVE_CACHE);
				sdomain.created = time(NULL);
				sdomain.ttl = ntohl(a->ttl);
		
				if (! (sdomain.flags & DOMAIN_STATIC_ZONE)) {
					update_db(db, &sdomain);
					inet_ntop(AF_INET, p, abuf, sizeof(abuf));	
					dolog(LOG_DEBUG, "updateing zone %s with address %s ttl= %u, lookrecord = %s", converted_name[i], abuf, sdomain.ttl, sr->lookrecord);
				}
			} 

			p += sizeof(in_addr_t);
			if (pointer > 2) {
				dolog(LOG_ERR, "there is more records than indicated in the header!!!");
				return (-1);
			}
			rrcount[pointer]--;
			if (rrcount[pointer] == 0)
				pointer++;

			break;
		case DNS_TYPE_AAAA:
			/* 
			 * scan addresses in this struct domain and check if
			 * this one exists already...
			 */

			update = 1;
			for (j = 0; j < sdomain.aaaa_count; j++) {	
				if (memcmp(&sdomain.aaaa[j], p, sizeof(struct in6_addr)) == 0) {
#if 0
					dolog(LOG_INFO, "record exists already");
#endif
					update = 0;
				}
			}
	
			if (j >= RECORD_COUNT) {
				dolog(LOG_INFO, "db can't hold any more records\n");
				update = 0;
			}

			/*
			 * check if we're a 2nd level domain or higher and
			 * if we were directly querying the zone...
			 */

			if (update) {
				if (level(sr->lookrecord) > 1) {
					if (!contains(sr->lookrecord, converted_name[i])) {
						memcpy(ns.nsserver, converted_name[i], cn_len[i]);
						ns.nslen = cn_len[i];

						fakerecurse(db, sr, &ns, DNS_TYPE_AAAA);
						update = 0;
					} 
				} 
			} 

			if (update) {
				memcpy(&sdomain.aaaa[j], p, sizeof(struct in6_addr));	
				sdomain.aaaa_count++;
				sdomain.aaaa_ptr = 0;
				sdomain.flags |= DOMAIN_HAVE_AAAA;
				sdomain.flags &= ~(DOMAIN_NEGATIVE_CACHE);
				sdomain.created = time(NULL);
				sdomain.ttl = ntohl(a->ttl);
		
				if (! (sdomain.flags & DOMAIN_STATIC_ZONE)) {
					update_db(db, &sdomain);
					inet_ntop(AF_INET6, p, abuf, sizeof(abuf));	
					dolog(LOG_DEBUG, "updateing zone %s with address %s ttl= %u\n", converted_name[i], abuf, sdomain.ttl);
				}
			} 

			if (pointer > 2) {
				dolog(LOG_ERR, "there is more records than indicated in the header!!!");
				return (-1);
			}
			rrcount[pointer]--;
			if (rrcount[pointer] == 0)
				pointer++;

			p += 16;		/* sizeof 4 * 32 bit */
			break;
		case DNS_TYPE_TXT:
			txtlen = (*p);

			memcpy(&sdomain.txt, (p + 1), txtlen);
			sdomain.txtlen = txtlen;
			
			sdomain.flags |= DOMAIN_HAVE_TXT;
			sdomain.flags &= ~(DOMAIN_NEGATIVE_CACHE);
			sdomain.created = time(NULL);
			sdomain.ttl = ntohl(a->ttl);
	
			if (! (sdomain.flags & DOMAIN_STATIC_ZONE)) {
				update_db(db, &sdomain);
			}

			if (pointer > 2) {
				dolog(LOG_ERR, "there is more records than indicated in the header!!!");
				return (-1);
			}

			rrcount[pointer]--;
			if (rrcount[pointer] == 0)
				pointer++;


			p += *p;
			p++;
			break;
		case DNS_TYPE_MX:
			preference = (u_int16_t *)p;
			p += sizeof(u_int16_t);	 /* mx_priority */
			/* FALLTHROUGH */
		case DNS_TYPE_NS:	
		case DNS_TYPE_PTR:
		case DNS_TYPE_CNAME:
			label[++i] = p;
			while (p <= end && *p) {
				if ((*p & 0xc0) == 0xc0) {
					p++;
					break;
				}
				p += *p;
				p++;

				if (p > end)
					goto end;
			}	

			if (ntohs(a->type) == DNS_TYPE_CNAME) {
				/* 
				 * we check this as well as the A and AAAA
				 * types since it may be possible to glue
				 * a CNAME instead of an A and thus poison
				 * our cache...
				 */
				if (level(sr->lookrecord) > 1) {
					if (!contains(sr->lookrecord, converted_name[i - 1])) {

						memcpy(ns.nsserver, converted_name[i - 1], cn_len[i - 1]);
						ns.nslen = cn_len[i];

						fakerecurse(db, sr, &ns, DNS_TYPE_A);
						rrcount[pointer]--;
						if (rrcount[pointer] == 0)
							pointer++;
						p++;
						break;
					} 
				} 
				
				memcpy(&sdomain.cname, converted_name[i], cn_len[i]);
				sdomain.cnamelen = cn_len[i];
				
				sdomain.flags |= DOMAIN_HAVE_CNAME;
				sdomain.flags &= ~(DOMAIN_NEGATIVE_CACHE);
				sdomain.created = time(NULL);
				sdomain.ttl = ntohl(a->ttl);
		
				if (! (sdomain.flags & DOMAIN_STATIC_ZONE)) {
					update_db(db, &sdomain);
#if 1
					dolog(LOG_DEBUG, "updateing zone %s with PTR name %s ttl= %u\n", converted_name[i - 1], converted_name[i], sdomain.ttl);
#endif
				}

				if (pointer > 2) {
					dolog(LOG_ERR, "there is more records than indicated in the header!!!");
					return (-1);
				}

				rrcount[pointer]--;
				if (rrcount[pointer] == 0)
					pointer++;
			} else if (ntohs(a->type) == DNS_TYPE_PTR) {
				memcpy(&sdomain.ptr, converted_name[i], cn_len[i]);
				sdomain.ptrlen = cn_len[i];
				
				sdomain.flags |= DOMAIN_HAVE_PTR;
				sdomain.flags &= ~(DOMAIN_NEGATIVE_CACHE);
				sdomain.created = time(NULL);
				sdomain.ttl = ntohl(a->ttl);
		
				if (! (sdomain.flags & DOMAIN_STATIC_ZONE)) {
					update_db(db, &sdomain);
#if 1
					dolog(LOG_DEBUG, "updateing zone %s with PTR name %s ttl= %u\n", converted_name[i - 1], converted_name[i], sdomain.ttl);
#endif
				}

				if (pointer > 2) {
					dolog(LOG_ERR, "there is more records than indicated in the header!!!");
					return (-1);
				}

				rrcount[pointer]--;
				if (rrcount[pointer] == 0)
					pointer++;
			} else if (ntohs(a->type) == DNS_TYPE_NS) {
				update = 1;
				for (j = 0; j < sdomain.ns_count; j++) {	
					if (memcasecmp((u_char *)sdomain.ns[j].nsserver, (u_char *)converted_name[i], MIN(cn_len[i], sdomain.ns[j].nslen)) == 0) {
#if 0
						dolog(LOG_INFO, "record exists already");
#endif
						update = 0;
					}
				}
		
				if (j >= RECORD_COUNT) {
					dolog(LOG_INFO, "db can't hold any more records\n");
					update = 0;
				}

				if (update) {
					memcpy(sdomain.ns[j].nsserver, converted_name[i], cn_len[i]);
					sdomain.ns[j].nslen = cn_len[i];
					
					sdomain.ns_count++;
					sdomain.ns_ptr = 0;
					sdomain.flags |= DOMAIN_HAVE_NS;
					sdomain.flags &= ~(DOMAIN_NEGATIVE_CACHE);
					sdomain.created = time(NULL);
					sdomain.ttl = ntohl(a->ttl);
			
					if (! (sdomain.flags & DOMAIN_STATIC_ZONE)) {
						update_db(db, &sdomain);
#if 0
						dolog(LOG_DEBUG, "updateing zone %s with NS name %s ttl= %u\n", converted_name[i - 1], converted_name[i], sdomain.ttl);
#endif
					}
				} /* if update */
				if (pointer > 2) {
					dolog(LOG_ERR, "there is more records than indicated in the header!!!");
					return (-1);
				}

				rrcount[pointer]--;
				if (pointer == 1) 	/* authoritative */
					sr->authoritative = DNS_TYPE_NS;
				if (rrcount[pointer] == 0)
					pointer++;

			} else if (ntohs(a->type) == DNS_TYPE_MX) {
				update = 1;
				for (j = 0; j < sdomain.mx_count; j++) {	
					if (memcasecmp((u_char *)sdomain.mx[j].exchange, (u_char *)converted_name[i], MIN(cn_len[i], sdomain.mx[j].exchangelen)) == 0) {
						update = 0;
					}
				}
		
				if (j >= RECORD_COUNT) {
					dolog(LOG_INFO, "db can't hold any more records\n");
					update = 0;
				}

				if (update) {
					memcpy(&sdomain.mx[j].exchange, converted_name[i], cn_len[i]);
					sdomain.mx[j].exchangelen = cn_len[i];
					sdomain.mx[j].preference = ntohs(*preference);
					
					sdomain.mx_count++;
					sdomain.mx_ptr = 0;
					sdomain.flags |= DOMAIN_HAVE_MX;
					sdomain.flags &= ~(DOMAIN_NEGATIVE_CACHE);
					sdomain.created = time(NULL);
					sdomain.ttl = ntohl(a->ttl);
			
					if (! (sdomain.flags & DOMAIN_STATIC_ZONE)) {
						update_db(db, &sdomain);
#if 0
						dolog(LOG_DEBUG, "updateing zone %s with MX name %s ttl= %u\n", converted_name[i - 1], converted_name[i], sdomain.ttl);
#endif
					}
				} /* if update */
				if (pointer > 2) {
					dolog(LOG_ERR, "there is more records than indicated in the header!!!");
					return (-1);
				}

				rrcount[pointer]--;
#if 0
				if (pointer == 1) 	/* authoritative */
					sr->authoritative = DNS_TYPE_MX;
#endif
				if (rrcount[pointer] == 0)
					pointer++;

			} /* if type ns */

			p++;	/* one more */
			break;
		case DNS_TYPE_SOA:
			/* nsserver */
			label[++i] = p;
			while (p <= end && *p) {
				if ((*p & 0xc0) == 0xc0) {
					p++;
					break;
				}
				p += *p;
				p++;
				if (p > end)
					goto end;
			}	

			p++;	/* one more */

			if (p > end)
				goto end;

			/* responsible person */
			label[++i] = p;
			while (p <= end && *p) {
				if ((*p & 0xc0) == 0xc0) {
					p++;
					break;
				}
				p += *p;
				p++;
			}	

			p++;	/* one more */

			if (p > end)
				goto end;

			mysoa = (struct mysoa *)p;
			p += sizeof(struct mysoa);	/* advance struct soa */

			/* malloc struct soa */

			soa = malloc(sizeof(struct soa));
			if (soa == NULL) {	
				dolog(LOG_ERR, "malloc: %m");	
				return (-1);
			}
			
			memcpy(soa->nsserver, converted_name[i - 1], cn_len[i - 1]);
			soa->nsserver_len = cn_len[i - 1];
			memcpy(soa->responsible_person, converted_name[i], cn_len[i]);
			soa->rp_len = cn_len[i];
			soa->serial = ntohl(mysoa->serial);
			soa->refresh = ntohl(mysoa->refresh);
			soa->retry = ntohl(mysoa->retry);
			soa->expire = ntohl(mysoa->expire);
			soa->minttl = ntohl(mysoa->minttl);

			memcpy(&sdomain.soa, soa, sizeof(sdomain.soa));
			free(soa);

			sdomain.flags |= DOMAIN_HAVE_SOA;
			sdomain.created = time(NULL);
			sdomain.ttl = htonl(a->ttl);

			if (! (sdomain.flags & DOMAIN_STATIC_ZONE)) {
				update_db(db, &sdomain);
			}

			if (pointer > 2) {
				dolog(LOG_ERR, "there is more records than indicated in the header!!!");
				return (-1);
			}

			rrcount[pointer]--;
			if (pointer == 1)		/* authoritative */
				sr->authoritative = DNS_TYPE_SOA;
			if (rrcount[pointer] == 0)
				pointer++;


			break;
		default:
			break;
			/* XXX */
		} /* switch */

		if (p >= end)
			break;
	} /* for (i *) */


	return (0);

end:
	dolog(LOG_DEBUG, "mangled input packet");
	return (-1);

}


/* 
 * NETLOOKUP - do a internet lookup of the requested internet record
 * 
 */

int
netlookup(DB *db, struct recurses *sr)
{
	struct sockaddr_in sin;
	struct dns_header *dh;

	char buf[2048];
	int flag;


	/* do the network stuff then */
	/* XXX should be IPv6 ready */

	if (sr->af == AF_INET6)
		return (netlookup6(db, sr));
	
	if (sr->so != -1) {
		if (close(sr->so) < 0) 
			dolog(LOG_ERR, "close: %m");
	}	

	sr->so = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sr->so < 0) {
		dolog(LOG_ERR, "socket: %m");
		sr->so = -1;
		return (-1);
	}

	sr->port = arc4random() & 0xffff;
	/*
	 * we have to avoid picking servers already
	 * running ..
	 */
	if (sr->port < 1024)
		sr->port += 1024;

	sr->id = arc4random() & 0xffff;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(sr->port);
	sin.sin_addr.s_addr = INADDR_ANY;

	if (bind(sr->so, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		dolog(LOG_ERR, "bind: %m");
		if (close(sr->so) < 0) {
			dolog(LOG_ERR, "close: %m");
		}
		sr->so = -1;
		return (-1);
	}

	/* 
	 * make this socket nonblocking 
	 */

	if ((flag = fcntl(sr->so,  F_GETFL)) < 0) {
		dolog(LOG_INFO, "fcntl 3: %m");
	}
	flag |= O_NONBLOCK;
	if (fcntl(sr->so, F_SETFL, flag) < 0) {
		dolog(LOG_INFO, "fcntl 4: %m");
	}

	if (lookup_ns(db, sr) <= 0) {
		dolog(LOG_ERR, "can't establish any servers to reach for zone \"%s\"", sr->question->converted_name);
		if (close(sr->so) < 0) {
			dolog(LOG_ERR, "close: %m");
		}
		sr->so = -1;
		return (-1);
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(53);

	sin.sin_addr.s_addr = sr->a[0];

	/* XXX we use buf here in order to preserve
	 * the state of query...
	 */
	memcpy(buf, sr->query, sr->len);
	dh = (struct dns_header *)&buf[0];
	NTOHS(dh->query);
	UNSET_DNS_RECURSION(dh);
	HTONS(dh->query);
	dh->id = htons(sr->id);

#if 1
	dolog(LOG_INFO, "sending request with id %u\n", sr->id);

#endif

	if (sendto(sr->so, buf, sr->len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		dolog(LOG_ERR, "sendto: %m");
		if (close(sr->so) < 0) {
			dolog(LOG_ERR, "close: %m");
		}
		sr->so = -1;
		return (-1);
	}

	sr->sent_last_query = time(NULL);
	sr->packetcount++;
		
	
	return (0);
}

/*
 * FAKERECURSE - create a fake query of type A, for a nameserver that has
 *		 no glued A record, attach a callback to the struct recurses
 *		 that did the initiation for this...
 */

int
fakerecurse(DB *db, struct recurses *sr, struct ns *ns, int type)
{
	struct recurses *fakesr;
	struct dns_header *dh;
	
	char *p;

	int len;
	u_int16_t *qtype, *qclass;

	/* check if we have already started a fakerecurse on the same name */

	SLIST_FOREACH(sr2, &recurseshead, recurses_entry) {
		if (memcasecmp((u_char *)ns->nsserver, (u_char *)sr2->question->hdr->name, MIN(ns->nslen, sr2->question->hdr->namelen)) == 0) {
			dolog(LOG_INFO, "already have a fakerecurse structure with name %s, drop\n", ns->nsserver);
			return (-1);
		}
	}
	

	/* place request on struct recurses linked list */

	fakesr = calloc(sizeof(struct recurses), 1);
	if (fakesr == NULL) {
		dolog(LOG_ERR, "calloc: %m");
		return (-1);
	}	


	fakesr->af = sr->af;
	fakesr->proto = sr->proto;
	fakesr->so = -1;
	fakesr->callback = sr;
	sr->hascallback++;
	fakesr->hascallback = 0;
	fakesr->isfake = 1;
	fakesr->launched = 0;
	fakesr->received = time(NULL);
	fakesr->packetcount = 0;
	fakesr->lookrecord = NULL;

	fakesr->question = build_fake_question(ns->nsserver, ns->nslen, htons(type));
	if (fakesr->question == NULL) {
		dolog(LOG_ERR, "malformed question in recurse.c");
		free(fakesr);
		return (-1);
	}

	/* construct the question packet */

	len = sizeof(struct dns_header);
	dh = (struct dns_header *)fakesr->query;
	dh->id = htons(1);
	SET_DNS_QUERY(dh);
	HTONS(dh->query);
	dh->question = htons(1);
	dh->answer = 0;
	dh->nsrr = 0;	
	dh->additional = 0;

	p = (char *)&fakesr->query[len];
	memcpy(p, ns->nsserver, ns->nslen);
	len += ns->nslen;
	qtype = (u_int16_t *)&fakesr->query[len];	
	*qtype = fakesr->question->hdr->qtype;
	len += sizeof(u_int16_t);
	qclass = (u_int16_t *)&fakesr->query[len];
	*qclass = fakesr->question->hdr->qclass;
	len += sizeof(u_int16_t);

	fakesr->len = len;

	SLIST_INSERT_HEAD(&recurseshead, fakesr, recurses_entry);	

	return (0);
}

/*
 * REPLY_RAW - 
 * 
 *
 */

void
reply_raw(DB *db, struct recurses *sr, struct domain *sd, int *raw)
{
	int so;
	struct sreply sreply;

	dolog(LOG_DEBUG, "reply_raw called");

	switch (sr->af) {
	case AF_INET:
		so = raw[0];
		break;
	case AF_INET6:
		so = raw[1];
		break;
	default:
		dolog(LOG_ERR, "reply_raw(): unknown address family in struct recurses");
		return;
	}

	switch (sr->proto) {
	case IPPROTO_UDP:
		break;
	default:
		dolog(LOG_ERR, "reply_raw(): can't do any protocol other than udp right now");
		return;
	}

	build_reply(&sreply, so, sr->query, sr->len, sr->question, NULL, 0, sd, NULL, 0xff, 0, 0, sr);

	switch (ntohs(sr->question->hdr->qtype)) {
	case DNS_TYPE_A:	
		reply_a(&sreply, db);
		break;
	case DNS_TYPE_AAAA:
		reply_aaaa(&sreply, db);
		break;
	case DNS_TYPE_NS:
		reply_ns(&sreply, db);
		break;
	case DNS_TYPE_PTR:
		reply_ptr(&sreply);
		break;
	case DNS_TYPE_MX:
		reply_mx(&sreply, db);
		break;
	case DNS_TYPE_SOA:
		reply_soa(&sreply);
		break;
	case DNS_TYPE_CNAME:
		reply_cname(&sreply);
		break;
	case DNS_TYPE_TXT:
		reply_txt(&sreply);
		break;
	default:
		dolog(LOG_ERR, "other types have not been implemented yet");
		break;
	}

	return;	
}

void
reply_raw_cname(DB *db, struct recurses *sr, struct domain *sd, int *raw)
{
	int so;
	struct sreply sreply;

	dolog(LOG_DEBUG, "reply_raw called");

	switch (sr->af) {
	case AF_INET:
		so = raw[0];
		break;
	case AF_INET6:
		so = raw[1];
		break;
	default:
		dolog(LOG_ERR, "reply_raw_cname(): unknown address family in struct recurses");
		return;
	}

	switch (sr->proto) {
	case IPPROTO_UDP:
		break;
	default:
		dolog(LOG_ERR, "reply_raw_cname(): can't do any protocol other than udp right now");
		return;
	}

	build_reply(&sreply, so, sr->query, sr->len, sr->question, NULL, 0, sd, NULL, 0xff, 0, 0, sr);

	reply_cname(&sreply);

	return;	
}

/*
 * REMOVE_ZONE - remove a zone from the database (it probably expired)
 *
 *
 */

void
remove_zone(DB *db, struct domain *sd)
{
	DBT key;
	char *zone;
	int zonelen;

	zone = sd->zone;
	zonelen = sd->zonelen;

	key.data = (char *)zone;
	key.size = zonelen;
	
	if (db->del(db, NULL, &key, 0) != 0) {
		dolog(LOG_ERR, "could not delete zone %s: %m", zone);
	}

	dolog(LOG_DEBUG, "deleting zone %s\n", zone);

	free(zone);

	return;
}

void
reply_raw_noerror(DB *db, struct recurses *sr, struct domain *sd, int *raw)
{
	int so;
	struct sreply sreply;

	dolog(LOG_DEBUG, "reply_raw_noerror called");

	switch (sr->af) {
	case AF_INET:
		so = raw[0];
		break;
	case AF_INET6:
		so = raw[1];
		break;
	default:
		dolog(LOG_ERR, "reply_raw_noerror(): unknown address family in struct recurses");
		return;
	}

	switch (sr->proto) {
	case IPPROTO_UDP:
		break;
	default:
		dolog(LOG_ERR, "reply_raw_noerror(): can't do any protocol other than udp right now");
		return;
	}

	build_reply(&sreply, so, sr->query, sr->len, sr->question, NULL, 0, sd, NULL, 0xff, 0, 0, sr);

	reply_noerror(&sreply);

	return;	
}

void
reply_raw_nxdomain(DB *db, struct recurses *sr, struct domain *sd, int *raw)
{
	int so;
	struct sreply sreply;

	dolog(LOG_DEBUG, "reply_raw_nxdomain called");

	switch (sr->af) {
	case AF_INET:
		so = raw[0];
		break;
	case AF_INET6:
		so = raw[1];
		break;
	default:
		dolog(LOG_ERR, "reply_raw_nxdomain(): unknown address family in struct recurses");
		return;
	}

	switch (sr->proto) {
	case IPPROTO_UDP:
		break;
	default:
		dolog(LOG_ERR, "reply_raw_nxdomain(): can't do any protocol other than udp right now");
		return;
	}

	build_reply(&sreply, so, sr->query, sr->len, sr->question, NULL, 0, sd, NULL, 0xff, 0, 0, sr);

	reply_nxdomain(&sreply);

	return;	
}


/*
 * LEVEL - traverse a domain name and count how many levels it has
 * 	   first level is a TLD, then a 2nd level domain and so on.
 */

int
level(u_char *p)
{
	int level = 0;

	while (*p) {
		level++;
		p += ((*p) + 1);
	}
		
	return (level);
}

/*
 * CONTAINS - check if domain name A is contained in domain name B
 *
 */

int
contains(u_char *a, u_char *b)
{
	u_char *p = a;
	u_char *q = b;
	u_int plen = 0, qlen = 0;

	while (*p) {
		plen += (*p) + 1;
		p += ((*p) + 1);
	}	

	while (*q) {
		qlen += ((*q) + 1);
		q += ((*q) + 1);
	}
		
	p = a;
	q = b;

	while (*q) {
		if ((plen == qlen) && memcasecmp((u_char *)p, (u_char *)q, qlen) == 0)
			return (1);
		
		qlen -= ((*q) + 1);
		q += ((*q) + 1);
	}

	return (0);
}

/* 
 * NETLOOKUP6 - do an ipv6 lookup of the requested internet record
 * 
 */

int
netlookup6(DB *db, struct recurses *sr)
{
	struct sockaddr_in6 sin6;
	struct dns_header *dh;

	char buf[2048];
	int flag;

	if (sr->so != -1) {
		if (close(sr->so) < 0) 
			dolog(LOG_ERR, "close: %m");
	}	

	sr->so = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (sr->so < 0) {
		dolog(LOG_ERR, "socket6: %m");
		sr->so = -1;
		return (-1);
	}

	sr->port = arc4random() & 0xffff;
	/*
	 * we have to avoid picking servers already
	 * running ..
	 */
	if (sr->port < 1024)
		sr->port += 1024;

	sr->id = arc4random() & 0xffff;

	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = htons(sr->port);
#ifndef __linux__
	sin6.sin6_len = sizeof(struct sockaddr_in6);
#endif

	if (bind(sr->so, (struct sockaddr *)&sin6, sizeof(sin6)) < 0) {
		dolog(LOG_ERR, "bind: %m");
		if (close(sr->so) < 0) {
			dolog(LOG_ERR, "close: %m");
		}
		sr->so = -1;
		return (-1);
	}

	/* 
	 * make this socket nonblocking 
	 */

	if ((flag = fcntl(sr->so,  F_GETFL)) < 0) {
		dolog(LOG_INFO, "fcntl 3: %m");
	}
	flag |= O_NONBLOCK;
	if (fcntl(sr->so, F_SETFL, flag) < 0) {
		dolog(LOG_INFO, "fcntl 4: %m");
	}

	if (lookup_ns(db, sr) <= 0) {
		dolog(LOG_ERR, "can't establish any servers to reach for zone \"%s\"", sr->question->converted_name);
		if (close(sr->so) < 0) {
			dolog(LOG_ERR, "close: %m");
		}
		sr->so = -1;
		return (-1);
	}

	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = htons(53);

	/* pjp */
	memcpy((char *)&sin6.sin6_addr, (char *)&sr->aaaa[0], sizeof(struct in6_addr));

	/* XXX we use buf here in order to preserve
	 * the state of query...
	 */
	memcpy(buf, sr->query, sr->len);
	dh = (struct dns_header *)&buf[0];
	NTOHS(dh->query);
	UNSET_DNS_RECURSION(dh);
	HTONS(dh->query);
	dh->id = htons(sr->id);

#if 1
	dolog(LOG_INFO, "sending request with id %u\n", sr->id);

#endif

	if (sendto(sr->so, buf, sr->len, 0, (struct sockaddr *)&sin6, sizeof(sin6)) < 0) {
		dolog(LOG_ERR, "sendto6: %m");
		if (close(sr->so) < 0) {
			dolog(LOG_ERR, "close: %m");
		}
		sr->so = -1;
		return (-1);
	}

	sr->sent_last_query = time(NULL);
	sr->packetcount++;
		
	
	return (0);
}

/*
 * LOOKUP_AAAA - given a path, lookup the AAAA record in that record
 * 
 */

int
lookup_aaaa(DB *db, struct recurses *sr, struct ns *ns)
{
	int ret, plen;
	char *p;

	DBT key, data;

	struct domain *sd, sdomain;
	int found = 0;

	p = ns->nsserver;
	plen = ns->nslen;

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	key.data = (char *)p;
	key.size = plen;

	data.data = NULL;
	data.size = 0;

	found = 0;

	ret = db->get(db, NULL, &key, &data, 0);
	if (ret == 0) {
		if (data.size != sizeof(struct domain)) {
			dolog(LOG_ERR, "btree db is damaged");
			return (-1);
		}	

		memcpy((char*)&sdomain, data.data, sizeof(struct domain));
		sd = &sdomain;

		if ((sd->flags & DOMAIN_HAVE_AAAA) == DOMAIN_HAVE_AAAA) {
			memcpy((char *)&sr->aaaa[sr->aaaa_count], (char *)&sd->aaaa[0], sizeof(struct in6_addr));
			sd->a_count++;
			found = 1;

		}
	}	

	if (! found) {
		dolog(LOG_DEBUG, "calling fakerecurse");
		fakerecurse(db, sr, ns, DNS_TYPE_AAAA);
		return (-1);
	}

	return (0);
}
