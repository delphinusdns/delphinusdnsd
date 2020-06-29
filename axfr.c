/*
 * Copyright (c) 2011-2020 Peter J. Philipp
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

/*
 * $Id: axfr.c,v 1.44 2020/06/29 16:22:05 pjp Exp $
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>

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
#include "imsg.h"
#else /* not linux */
#include <sys/queue.h>
#include <sys/tree.h>
#ifdef __FreeBSD__
#include "imsg.h"
#else
#include <imsg.h>
#endif /* __FreeBSD__ */
#endif /* __linux__ */

#ifndef NTOHS
#include "endian.h"
#endif

#include "ddd-dns.h"
#include "ddd-db.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

void	axfrloop(int *, int, char **, ddDB *, struct imsgbuf *ibuf);
void	axfr_connection(int, char *, int, ddDB *, char *, int);
int	build_header(ddDB *, char *, char *, struct question *, int);
int	build_soa(ddDB *, char *, int, struct rbtree *, struct question *);
int	checklabel(ddDB *, struct rbtree *, struct rbtree *, struct question *);
int	find_axfr(struct sockaddr_storage *, int);
void	gather_notifydomains(ddDB *);
void	init_axfr(void);
void	init_notifyddd(void);
int	insert_axfr(char *, char *);
int	insert_notifyddd(char *, char *);
void	notifypacket(int, void *, void *, int);
void    notifyddds(int *);
void	reap(int);

extern void 	pack(char *, char *, int);
extern void 	pack32(char *, u_int32_t);
extern void 	pack16(char *, u_int16_t);
extern void 	pack8(char *, u_int8_t);
extern uint32_t unpack32(char *);
extern uint16_t unpack16(char *);
extern void 	unpack(char *, char *, int);

extern int 		get_record_size(ddDB *, char *, int);
extern in_addr_t 	getmask(int);
extern int 		getmask6(int, struct sockaddr_in6 *);
extern void		reply_fmterror(struct sreply *, ddDB *);
extern void		reply_nxdomain(struct sreply *, ddDB *);
extern struct rbtree *	get_soa(ddDB *, struct question *);
extern int		compress_label(u_char *, int, int);
extern u_int16_t	create_anyreply(struct sreply *, char *, int, int, int);
extern struct question	*build_fake_question(char *, int, u_int16_t, char *, int);
extern struct question	*build_question(char *, int, int, char *);
extern int		free_question(struct question *);
extern void		dolog(int, char *, ...);
extern void 		build_reply(struct sreply *, int, char *, int, struct question *, struct sockaddr *, socklen_t, struct rbtree *, struct rbtree *, u_int8_t, int, int, char *);

extern struct rbtree * find_rrset(ddDB *db, char *name, int len);
extern struct rrset * find_rr(struct rbtree *rbt, u_int16_t rrtype);
extern int display_rr(struct rrset *rrset);
extern int rotate_rr(struct rrset *rrset);

extern int domaincmp(struct node *e1, struct node *e2);
extern char * dns_label(char *, int *);
extern int additional_tsig(struct question *, char *, int, int, int, int, HMAC_CTX *);
extern int find_tsig_key(char *keyname, int keynamelen, char *key, int keylen);

int notify = 0;				/* do not notify when set to 0 */

extern int debug, verbose;
extern time_t time_changed;
extern int tsig;
extern long glob_time_offset;

SLIST_HEAD(, axfrentry) axfrhead;

static struct axfrentry {
	char name[INET6_ADDRSTRLEN];
	int family;
	struct sockaddr_storage hostmask;
	struct sockaddr_storage netmask;
	u_int8_t prefixlen;
	SLIST_ENTRY(axfrentry) axfr_entry;
} *an2, *anp;

SLIST_HEAD(notifylisthead, notifyentry) notifyhead;

static struct notifyentry {
	char domain[DNS_MAXNAME];
	int domainlen;
	u_int16_t *ids;
	u_int16_t *attempts;
	int usetsig;
	int numadd;
	struct mzone *mzone;
	SLIST_ENTRY(notifyentry) notify_entry;
} *notn2, *notnp;

extern int domaincmp(struct node *e1, struct node *e2);
static int 	check_notifyreply(struct dns_header *, struct question *, struct sockaddr_storage *, int, struct notifyentry *, int);

SLIST_HEAD(mzones ,mzone)  mzones;

/*
 * INIT_AXFR - initialize the axfr singly linked list
 */

void
init_axfr(void)
{
	SLIST_INIT(&axfrhead);
	return;
}

/*
 * INSERT_AXFR - insert an address and prefixlen into the axfr slist
 */

int
insert_axfr(char *address, char *prefixlen)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	int pnum;
	int ret;

	pnum = atoi(prefixlen);
	an2 = malloc(sizeof(struct axfrentry));      /* Insert after. */

	if (strchr(address, ':') != NULL) {
		an2->family = AF_INET6;
		sin6 = (struct sockaddr_in6 *)&an2->hostmask;
		if ((ret = inet_pton(AF_INET6, address, &sin6->sin6_addr.s6_addr)) != 1)
			return (-1);
		sin6->sin6_family = AF_INET6;
		sin6 = (struct sockaddr_in6 *)&an2->netmask;
		sin6->sin6_family = AF_INET6;
		if (getmask6(pnum, sin6) < 0) 
			return(-1);
		an2->prefixlen = pnum;
	} else {

		an2->family = AF_INET;
		sin = (struct sockaddr_in *)&an2->hostmask;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = inet_addr(address);
		sin = (struct sockaddr_in *)&an2->netmask;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = getmask(pnum);
		an2->prefixlen = pnum;

	}

	SLIST_INSERT_HEAD(&axfrhead, an2, axfr_entry);

	return (0);
}

/*
 * FIND_AXFR - walk the axfr list and find the correponding network 
 *		   if a network matches return 1, if no match is found return
 *		   0.
 */

int
find_axfr(struct sockaddr_storage *sst, int family)
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

	SLIST_FOREACH(anp, &axfrhead, axfr_entry) {
		if (anp->family == AF_INET) {
			if (family != AF_INET)
				continue;
			sin = (struct sockaddr_in *)sst;
			a = sin->sin_addr.s_addr;
			sin = (struct sockaddr_in *)&anp->hostmask;
			sin0 = (struct sockaddr_in *)&anp->netmask;
			hostmask = sin->sin_addr.s_addr;
			netmask = sin0->sin_addr.s_addr;
			if ((hostmask & netmask) == (a & netmask)) {
				return (1);
			} /* if hostmask */
		} else if (anp->family == AF_INET6) {
			if (family != AF_INET6)
				continue;
			sin6 = (struct sockaddr_in6 *)sst;
			sin60 = (struct sockaddr_in6 *)&anp->hostmask;	
			sin61 = (struct sockaddr_in6 *)&anp->netmask;
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
axfrloop(int *afd, int sockcount, char **ident, ddDB *db, struct imsgbuf *ibuf)
{
	fd_set rset;

	struct timeval tv;
	struct sockaddr_storage from;
	struct sockaddr_in6 *sin6;
	struct sockaddr_in *sin;
	struct dns_header *dh;
	struct question *question;
	struct imsg	imsg;
	struct mzone_dest *md;

	int i, so, len;
	int n, count;
	int sel, maxso = 0;
	int is_ipv6, axfr_acl;
	int notifyfd[2];
	int packetlen;
	int tcpflags;

	socklen_t fromlen;
	char buf[512];
	char buf0[512];
	char *packet;
	
	time_t now;
	pid_t pid;

	char address[INET6_ADDRSTRLEN];

#if __OpenBSD__
        if (pledge("stdio inet proc recvfd", NULL) < 0)
 {
                dolog(LOG_ERR, "pledge %s", strerror(errno));
                exit(1);
        }
#endif

	signal(SIGCHLD, reap);

	for (i = 0; i < sockcount; i++) {
		listen(afd[i], 5);
	}

	if (notify) {
		/* 
		 * If a zonefile has changed in the last half hour then 
		 * gather all notifydomains and start the notify process
		 */

		notifyfd[0] = -1;
		notifyfd[1] = -1;

		now = time(NULL);
		if (difftime(now, time_changed) <= 1800) {
			gather_notifydomains(db);
			notifyfd[0] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			notifyfd[1] = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

			memset((char *)&from, 0, sizeof(from));
			sin = (struct sockaddr_in *)&from;
			sin->sin_family = AF_INET;
			sin->sin_port = htons(0);
	
			if (bind(notifyfd[0], (struct sockaddr *)sin, sizeof(*sin)) < 0) {
				dolog(LOG_INFO, "bind notify: %s\n", strerror(errno));
			}

			memset((char *)&from, 0, sizeof(from));
			sin6 = (struct sockaddr_in6 *)&from;
			sin6->sin6_family = AF_INET6;
			sin6->sin6_port = htons(0);
#ifndef __linux__
			sin6->sin6_len = sizeof(struct sockaddr_in6);
#endif
	
			if (bind(notifyfd[1], (struct sockaddr *)sin6, sizeof(*sin6)) < 0) {
				dolog(LOG_INFO, "bind notify6: %s\n", strerror(errno));
			}

			memset((char *)&from, 0, sizeof(from));

			notifyddds((int *)&notifyfd);
		}
	}


	for (;;) {

		FD_ZERO(&rset);
		maxso = 0;

		for (i = 0; i < sockcount; i++) {
			FD_SET(afd[i], &rset);
			if (maxso < afd[i])
				maxso = afd[i];
		}

		FD_SET(ibuf->fd, &rset);
		if (ibuf->fd > maxso)
			maxso = ibuf->fd;
		
		if (notify) {
			/*
			 * go through every zone, removing those with all
			 * IP's notified...
		 	 */
			SLIST_FOREACH_SAFE(notnp, &notifyhead, notify_entry, notn2) {
				count = 0;
				SLIST_FOREACH(md, &notnp->mzone->dest, entries) {
					if (md->notified == 0)
						count++;
				}

				if (count == notnp->numadd) {
#if DEBUG
					dolog(LOG_INFO, "removed domain \"%s\"\n", notnp->mzone->humanname);
#endif
					SLIST_REMOVE(&notifyhead, notnp, notifyentry, notify_entry);
				}
				
			}

			if (SLIST_EMPTY(&notifyhead)) {
				dolog(LOG_INFO, "notifys have been completed, closing notify descriptors!\n");
				if (notifyfd[0] > -1)
					close(notifyfd[0]);

				if (notifyfd[1] > -1)
					close(notifyfd[1]);

				notifyfd[0] = -1;	
				notifyfd[1] = -1;	
		
				notify = 0;
			}

			if (notifyfd[0] > -1) {
				FD_SET(notifyfd[0], &rset);
				if (maxso < notifyfd[0])
					maxso = notifyfd[0];
			}
			
			if (notifyfd[1] > -1) {
				FD_SET(notifyfd[1], &rset);
				if (maxso < notifyfd[1])
					maxso = notifyfd[1];
			}
		}
	
		tv.tv_sec = 10;
		tv.tv_usec = 0;

		sel = select(maxso + 1, &rset, NULL, NULL, &tv);
	
		if (sel == 0) {
			if (notify) {
				if (notifyfd[0] > -1 || notifyfd[1] > -1) {
					notifyddds((int *)&notifyfd);
				}

			}
		
			continue;
		}
		if (sel < 0) {
			if (errno != EINTR)
				dolog(LOG_INFO, "select: %s\n", strerror(errno));
			continue;
		}

		for (i = 0; i < sockcount; i++) {
			if (FD_ISSET(afd[i], &rset)) {
				fromlen = sizeof(struct sockaddr_storage);

				so = accept(afd[i], (struct sockaddr*)&from, &fromlen);
				if (so < 0) {
						dolog(LOG_INFO, "afd accept: %s\n", strerror(errno));
						continue;
				}

				if (from.ss_family == AF_INET6) {
					is_ipv6 = 1;	
			
					fromlen = sizeof(struct sockaddr_in6);
					sin6 = (struct sockaddr_in6 *)&from;
					inet_ntop(AF_INET6, (void*)&sin6->sin6_addr, (char*)&address, sizeof(address));
					axfr_acl = find_axfr((struct sockaddr_storage *)sin6, AF_INET6);

				} else if (from.ss_family == AF_INET) {
					is_ipv6 = 0;
					
					fromlen = sizeof(struct sockaddr_in);
					sin = (struct sockaddr_in *)&from;
					inet_ntop(AF_INET, (void*)&sin->sin_addr, (char*)&address, sizeof(address));

					axfr_acl = find_axfr((struct sockaddr_storage *)sin, AF_INET);

				} else {
					dolog(LOG_INFO, "afd accept unknown family %d, close\n", from.ss_family);
					close(so);
					continue;
				}

				if (! axfr_acl)	{
						dolog(LOG_INFO, "connection from %s was not in our axfr acl, drop\n", address);
						close(so);
						continue;
				 }

				dolog(LOG_INFO, "AXFR connection from %s on interface \"%s\"\n", address, ident[i]);

				switch (pid = fork()) {
				case 0:
					axfr_connection(so, address, is_ipv6, db, NULL, 0);
					exit(0);
					/*NOTREACHED*/	
				default:
					close(so);
					break;
				}

			} /* if(FD_ISSET..) */

		} /* for (i.. */
	
		if (FD_ISSET(ibuf->fd, &rset)) {
			if ((n = imsg_read(ibuf)) < 0 && errno != EAGAIN) {
				dolog(LOG_ERR, "imsg read failure %s\n", strerror(errno));
				continue;
			}

			if (n == 0) {
				/* child died? */
				dolog(LOG_INFO, "sigpipe on child? exiting.\n");
				exit(1);
			}

			for(;;) {
				if ((n = imsg_get(ibuf, &imsg)) < 0) {
					dolog(LOG_ERR, "imsg read error: %s\n", strerror(errno));
					break;
				} else {
					if (n == 0)
						break;
					packetlen = imsg.hdr.len - IMSG_HEADER_SIZE;

					switch (imsg.hdr.type) {
					case IMSG_XFR_MESSAGE:
						dolog(LOG_INFO, "received xfr via message passing\n");
						packet = calloc(1, packetlen);
						if (packet == NULL) {
							dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
							break;
						}

						memcpy(packet, imsg.data, packetlen);
						so = imsg.fd;

						if ((tcpflags = fcntl(so, F_GETFL, 0)) < 0) {
							dolog(LOG_INFO, "can't query fcntl flags\n");
							close(so);
							free(packet);
							break;
						}

						/* turn off nonblocking */	
						tcpflags &= ~O_NONBLOCK;

						if (fcntl(so, F_SETFL, tcpflags) < 0) {
							dolog(LOG_INFO, "can't turn off non-blocking\n");
							close(so);
							free(packet);
							break;
						}
						
						memset((char *)&from, 0, sizeof(from));
						fromlen = sizeof(struct sockaddr_storage);
						if (getpeername(so, (struct sockaddr *)&from, &fromlen) < 0) {
							dolog(LOG_ERR, "getpeername: %s\n", strerror(errno));
							close(so);
							free(packet);
							break;
						}
						if (from.ss_family == AF_INET6) {
							is_ipv6 = 1;	
					
							fromlen = sizeof(struct sockaddr_in6);
							sin6 = (struct sockaddr_in6 *)&from;
							inet_ntop(AF_INET6, (void*)&sin6->sin6_addr, (char*)&address, sizeof(address));
							axfr_acl = find_axfr((struct sockaddr_storage *)sin6, AF_INET6);

						} else if (from.ss_family == AF_INET) {
							is_ipv6 = 0;
							
							fromlen = sizeof(struct sockaddr_in);
							sin = (struct sockaddr_in *)&from;
							inet_ntop(AF_INET, (void*)&sin->sin_addr, (char*)&address, sizeof(address));

							axfr_acl = find_axfr((struct sockaddr_storage *)sin, AF_INET);

						} else {
							dolog(LOG_INFO, "afd accept unknown family %d, close\n", from.ss_family);
							close(so);
							free(packet);
							break;
						}

						if (! axfr_acl)	{
							dolog(LOG_INFO, "connection from %s was not in our axfr acl, drop\n", address);
							close(so);
							free(packet);
							break;
				 		}

						dolog(LOG_INFO, "AXFR connection from %s passed via descriptor-passing\n", address);

						switch (pid = fork()) {
							case 0:
								axfr_connection(so, address, is_ipv6, db, packet, packetlen);
								exit(0);
								/*NOTREACHED*/	
							default:
								close(so);
								free(packet);
								break;
						}

						break;
					default:
						dolog(LOG_ERR, "received bad message %d on AXFR imsg\n", imsg.hdr.type);
						break;
					}
					imsg_free(&imsg);
				} /* else */
			} /* for (;;) */
		} /* if (FD_ISSET..) */

		if (notify) {
			if (notifyfd[0] > -1 && FD_ISSET(notifyfd[0], &rset)) {
				fromlen = sizeof(struct sockaddr_storage);
				len = recvfrom(notifyfd[0], buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
				if (len < 0) {
					dolog(LOG_INFO, "recvfrom: %s\n", strerror(errno));
				}

				if (len < sizeof(struct dns_header)) {
					dolog(LOG_INFO, "received bogus reply on notify port, drop\n");
					continue;
				}

				dh = (struct dns_header *)&buf[0];
				if (ntohs(dh->question) != 1) {
					dolog(LOG_INFO, "question header on notify reply not 1, drop\n");
					continue;
				}
		
				if (! (ntohs(dh->query) & DNS_REPLY)) {
					dolog(LOG_INFO, "question header is not a reply, drop\n");
					continue;
				}

				/* save buf */
				memcpy(&buf0, buf, len);
				question = build_question(buf0, len, ntohs(dh->additional), NULL);
				if (question == NULL) {
					dolog(LOG_INFO, "build_question failed on notify reply, drop\n");
					continue;
				}
		
				/* now walk our notnp list and check the tsig */
				SLIST_FOREACH(notnp, &notifyhead, notify_entry) {
					if (memcmp(question->hdr->name, notnp->domain, notnp->domainlen) == 0) {
						break;
					}
				}

				if (notnp == NULL) {
					dolog(LOG_INFO, "returned name not in list of notify domains\n");
					continue;
				}


				sin = (struct sockaddr_in *)&from;
				inet_ntop(AF_INET, (void*)&sin->sin_addr, (char*)&address, sizeof(address));

				if (notnp->usetsig) {
					free_question(question);

					SLIST_FOREACH(md, &notnp->mzone->dest, entries) {
						if (sin->sin_addr.s_addr == (((struct sockaddr_in *)md)->sin_addr.s_addr))
							break;
					}

					if (md == NULL) {
						dolog(LOG_INFO, "returned packet not from a source we notified, \"%s\"\n", address);
						continue;
					}

					question = build_question(buf, len, ntohs(dh->additional), md->requestmac);
					if (question == NULL) {
						dolog(LOG_INFO, "build_question + tsig  failed on notify reply, drop\n");
						continue;
					}
				}


				SLIST_FOREACH_SAFE(notnp, &notifyhead, notify_entry, notn2) {
					for (i = 0; i < notify; i++) {
						if (check_notifyreply(dh, question, 
							(struct sockaddr_storage *) sin, AF_INET, notnp, i) < 0) {
						dolog(LOG_INFO, "got a reply from a notify host (%s) DNS->ID %u that says: %04x\n", address, ntohs(dh->id), ntohs(dh->query));
					 	}
					}
				}
			
				free_question(question);

				if (SLIST_EMPTY(&notifyhead)) {
					dolog(LOG_INFO, "notifys have been completed, closing notify descriptors!\n");
					if (notifyfd[0] > -1)
						close(notifyfd[0]);

					if (notifyfd[1] > -1)
						close(notifyfd[1]);

					notifyfd[0] = -1;	
					notifyfd[1] = -1;	
			
					notify = 0;
				}
			}

			if (notifyfd[1] > -1 && FD_ISSET(notifyfd[1], &rset)) {
				fromlen = sizeof(struct sockaddr_storage);
				len = recvfrom(notifyfd[1], buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
				if (len < 0) {
					dolog(LOG_INFO, "recvfrom: %s\n", strerror(errno));
				}

				if (len < sizeof(struct dns_header)) {
					dolog(LOG_INFO, "received bogus reply on notify port, drop\n");
					continue;
				}

				dh = (struct dns_header *)&buf[0];
				if (ntohs(dh->question) != 1) {
					dolog(LOG_INFO, "question header on notify reply not 1, drop\n");
					continue;
				}
		
				if (! (ntohs(dh->query) & DNS_REPLY)) {
					dolog(LOG_INFO, "question header is not a reply, drop\n");
					continue;
				}

				sin6 = (struct sockaddr_in6 *)&from;
				inet_ntop(AF_INET6, (void*)&sin6->sin6_addr, (char*)&address, sizeof(address));

				/* save buf */
				memcpy(buf0, buf, len);
				question = build_question(buf0, len, ntohs(dh->additional), NULL);
				if (question == NULL) {
					dolog(LOG_INFO, "build_question failed on notify reply, drop\n");
					continue;
				}

				/* now walk our notnp list and check the tsig */
				SLIST_FOREACH(notnp, &notifyhead, notify_entry) {
					if (memcmp(question->hdr->name, notnp->domain, notnp->domainlen) == 0) {
						break;
					}
				}

				if (notnp == NULL) {
					dolog(LOG_INFO, "returned name not in list of notify domains\n");
					continue;
				}


				if (notnp->usetsig) {
					free_question(question);
					SLIST_FOREACH(md, &notnp->mzone->dest, entries) {
						if (memcmp((void *)&sin6->sin6_addr, (void*)&((struct sockaddr_in6 *)md)->sin6_addr, sizeof(struct in6_addr)) == 0)
							break;
					}

					if (md == NULL) {
						dolog(LOG_INFO, "returned packet not from a source we notified, \"%s\"\n", address);
						continue;
					}

					question = build_question(buf, len, ntohs(dh->additional), md->requestmac);
					if (question == NULL) {
						dolog(LOG_INFO, "build_question + tsig  failed on notify reply, drop\n");
						continue;
					}
				}


				SLIST_FOREACH_SAFE(notnp, &notifyhead, notify_entry, notn2) {
					for (i = 0; i < notify; i++) {
						if (check_notifyreply(dh, question, 
							(struct sockaddr_storage *) sin6, AF_INET6, notnp, i) < 0) {
							dolog(LOG_INFO, "got a reply from a notify host (%s) DNS->ID %u that says: %04x\n", address, ntohs(dh->id), ntohs(dh->query));
					    }
					}
				}
			
				free_question(question);

				if (SLIST_EMPTY(&notifyhead)) {
					dolog(LOG_INFO, "notifys have been completed, closing notify descriptors!\n");
					if (notifyfd[0] > -1)
						close(notifyfd[0]);

					if (notifyfd[1] > -1)
						close(notifyfd[1]);

					notifyfd[0] = -1;	
					notifyfd[1] = -1;	

					notify = 0;
				}
			}
	
		}

	} /* for (;;) */

}

/*
 * AXFR_CONNECTION - this is the main core of AXFR engine, forked
 *
 */

void
axfr_connection(int so, char *address, int is_ipv6, ddDB *db, char *packet, int packetlen)
{

	char buf[4000];
	char tsigkey[512];
	char *p = &buf[0];
	char *q;
	char *reply, *replybuf;

	int len, dnslen = 0;
	int offset = 0;
	int qlen;
	int outlen;
	int rrcount;
	int envelopcount;
	int rs;
	int tsigkeylen;

	struct node *n, *nx;
	struct dns_header *dh, *odh;
	struct sreply sreply;
	struct question *question, *fq;
	struct rbtree *rbt = NULL, *rbt2 = NULL, *saverbt = NULL, *soa = NULL;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;

	ddDBT key, data;
	HMAC_CTX *tsigctx = NULL;

	if ((replybuf = calloc(1, 0xffff + 3)) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		close(so);
		exit(1);
	}
		

	if (packetlen > sizeof(buf)) {
		dolog(LOG_ERR, "buffer size of buf is smaller than given packet, drop\n");
		close(so);
		exit(1);
	}

	for (;;) {
		if (packetlen == 0) {
			len = recv(so, p + offset, sizeof(buf) - offset, 0);
			if (len <= 0) {
				close(so);
				exit(1);
			}
	
		} else {
			len = packetlen;
			memcpy(p, packet, packetlen);
			packetlen = 0;
		}
		
		/* 
		 * do a little dance here because we don't know if the
		 * input is fragmented or not...
		 */
		if (offset + len >= 2) {	
			dnslen = unpack16(p);
			NTOHS(dnslen);
		} else {
			offset += len;
			continue;
		}

		/* sanity check around dnslen */
		if (dnslen > 0 && (dnslen + 2) != (offset + len)) {
			continue;
		}
	

		/* by now the packet should be normalized */	
		
		dh = (struct dns_header *)(p + 2);

		if ((ntohs(dh->query) & DNS_REPLY)) {
			dolog(LOG_INFO, "AXFR dns packet is not a question, drop\n");
			goto drop;	
		}

		if (ntohs(dh->question) != 1) {	
			dolog(LOG_INFO, "AXFR dns packet does not have a question count of 1 (RFC 5936, page 9), reply fmterror\n");
			
			build_reply(&sreply, so, (p + 2), dnslen, NULL, NULL, 0, NULL, NULL, 0xff, 1, 0, replybuf);

			reply_fmterror(&sreply, NULL);
			goto drop;	
		}

		if ((question = build_question((p + 2), dnslen, ntohs(dh->additional), NULL)) == NULL) {
			dolog(LOG_INFO, "AXFR malformed question, drop\n");
			goto drop;
		}

		if (ntohs(question->hdr->qclass) != DNS_CLASS_IN) {
			dolog(LOG_INFO, "AXFR question wasn't for class DNS_CLASS_IN, drop\n");
			goto drop;
		}

		switch (ntohs(question->hdr->qtype)) {
		case DNS_TYPE_AXFR:
		case DNS_TYPE_IXFR:
		case DNS_TYPE_SOA:
				break;
		default:
			dolog(LOG_INFO, "AXFR question wasn't for valid types (ixfr, axfr, soa) with requested type %d, drop\n", ntohs(question->hdr->qtype));	
			goto drop;

		}

		if (question->tsig.have_tsig && question->tsig.tsigerrorcode != 0) {
			dolog(LOG_INFO, "AXFR question had TSIG errors, code 0x%02x, drop\n", question->tsig.tsigerrorcode);
			goto drop;
		}

		/* now we can be reasonably sure that it's an AXFR for us */

		reply = calloc(1, 0xffff + 2);	
		if (reply == NULL) {
			dolog(LOG_INFO, "internal error: %s\n", strerror(errno));
			goto drop;
		}

		odh = (struct dns_header *)(reply + 2);

		q = question->hdr->name;
		qlen = question->hdr->namelen;

		rbt = find_rrset(db, q, qlen);
		if (rbt == NULL) {
			rbt2 = get_soa(db, question);
			if (rbt2 == NULL) {
				dolog(LOG_INFO, "internal error: %s\n", strerror(errno));
				goto drop;
			}
			build_reply(&sreply, so, (p + 2), dnslen, question, NULL, 0, rbt2, NULL, 0xff, 1, 0, replybuf);
			reply_nxdomain(&sreply, NULL);
			dolog(LOG_INFO, "AXFR request for zone %s, no db entry, nxdomain -> drop\n", question->converted_name);
			goto drop;
		}
		
		/*
		 * check if we have an SOA record 
		 */

		if ((rrset = find_rr(rbt, DNS_TYPE_SOA)) == NULL) {
			rbt2 = get_soa(db, question);
			if (rbt2 == NULL) {
				dolog(LOG_INFO, "internal error: %s\n", strerror(errno));
				goto drop;
			}
			build_reply(&sreply, so, (p + 2), dnslen, question, NULL, 0, rbt2, NULL, 0xff, 1, 0, replybuf);
			reply_nxdomain(&sreply, NULL);
			
			dolog(LOG_INFO, "AXFR request for zone %s, which has no SOA for the zone, nxdomain -> drop\n", question->converted_name);
			goto drop;
		} else {
			soa = rbt;
		}

		if (ntohs(question->hdr->qtype) == DNS_TYPE_SOA) {
			dolog(LOG_INFO, "TCP SOA request for zone \"%s\", replying...\n", question->converted_name);
			outlen = 0;
			outlen = build_header(db, (reply + 2), (p + 2), question, 1);
			outlen = build_soa(db, (reply + 2), outlen, soa, question);
			if (question->tsig.tsigverified == 1) {
				struct dns_header *odh;

				odh = (struct dns_header *)&reply[2];
				outlen = additional_tsig(question, (reply + 2), 0xffff, outlen, 0, 0, NULL);
				NTOHS(odh->additional); 
				odh->additional++;
				HTONS(odh->additional);
			}

			pack16(reply, htons(outlen));
			len = send(so, reply, outlen + 2, 0);
			if (len <= 0) {
				goto drop;
			}

			outlen = 0;
			offset = 0;
			p = &buf[0];

			free (reply);

			continue;
		}

		/* initialize tsig */

		if (question->tsig.tsigverified) {
			if ((tsigkeylen = find_tsig_key(question->tsig.tsigkey, 
				question->tsig.tsigkeylen, (char *)&tsigkey, sizeof(tsigkey))) < 0) {
				dolog(LOG_ERR, "AXFR could not get tsigkey..odd, drop\n");
				goto drop;
			
			}

			tsigctx = HMAC_CTX_new();
			if (HMAC_Init_ex(tsigctx, (const void *)&tsigkey, tsigkeylen, EVP_sha256(), NULL) == 0) {
				dolog(LOG_ERR, "AXFR tsig initialization error, drop\n");
				goto drop;
			}
		}

		dolog(LOG_INFO, "%s request for zone \"%s\", replying...\n", 
			(ntohs(question->hdr->qtype) == DNS_TYPE_AXFR ? "AXFR"
				: "IXFR"), question->converted_name);


		outlen = build_header(db, (reply + 2), (p + 2), question, 0);
		outlen = build_soa(db, (reply + 2), outlen, soa, question);
		rrcount = 1;
		envelopcount = 1;
		
		RB_FOREACH_SAFE(n, domaintree, &db->head, nx) {
			rs = n->datalen;
			if ((rbt = calloc(1, sizeof(struct rbtree))) == NULL) {
				dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
				goto drop;
			}
			if ((saverbt = calloc(1, sizeof(struct rbtree))) == NULL) {
				dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
				goto drop;
			}

			memcpy((char*)rbt, (char*)n->data, sizeof(struct rbtree));
			memcpy((char*)saverbt,(char*)n->data, sizeof(struct rbtree));

			if (checklabel(db, rbt, soa, question)) {
				fq = build_fake_question(rbt->zone, rbt->zonelen, 0, NULL, 0);
				build_reply(&sreply, so, (p + 2), dnslen, fq, NULL, 0, rbt, NULL, 0xff, 1, 0, replybuf);
				outlen = create_anyreply(&sreply, (reply + 2), 65535, outlen, 0);
				free_question(fq);
	
				if ((rrset = find_rr(rbt, DNS_TYPE_NS)) != NULL) {
					rrp = TAILQ_FIRST(&rrset->rr_head);
					if (rrp != NULL && 
						((struct ns *)rrp->rdata)->ns_type & NS_TYPE_DELEGATE) {
						TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
							fq = build_fake_question(((struct ns *)rrp->rdata)->nsserver,
								((struct ns *)rrp->rdata)->nslen, 0, NULL, 0);
							rbt2 = find_rrset(db, fq->hdr->name, fq->hdr->namelen);
							if (rbt2 == NULL) {
								free_question(fq);
								continue;
							}

							build_reply(&sreply, so, (p + 2), dnslen, fq, NULL, 0, rbt2, NULL, 0xff, 1, 0, replybuf);
							outlen = create_anyreply(&sreply, (reply + 2), 65535, outlen, 0);
							if (rbt2) {
								free(rbt2);
								rbt2 = NULL;
							}
							free_question(fq);
						
						} /* TAILQ_FOREACH */
					} /* if (rrp != NULL */
				} /* if (find_rr */
			} /* if checklabel */

			/*
			 * if we accumulate 60000 bytes out of the maximum
			 * 65535 bytes then we fragment.  
			 */
			/* XXX */
			if (outlen > 60000) {
				pack16(reply, htons(outlen));
			
				/* set the rrcount in there */

				NTOHS(odh->answer);
				odh->answer += rrcount;
				HTONS(odh->answer);

				if (question->tsig.have_tsig && question->tsig.tsigverified) {
					int tmplen = outlen;

					outlen = additional_tsig(question, (reply + 2), 65000, outlen, 0, envelopcount, tsigctx);
					if (tmplen != outlen) {
						odh->additional = htons(1);

						HMAC_CTX_reset(tsigctx);
						if (HMAC_Init_ex(tsigctx, (const void *)&tsigkey, tsigkeylen, EVP_sha256(), NULL) == 0) {
							dolog(LOG_ERR, "AXFR tsig initialization error, drop\n");
							goto drop;
						}
					}

					envelopcount++;

					pack16(reply, htons(outlen));
				}

				len = send(so, reply, outlen + 2, 0);
				if (len <= 0) {
					goto drop;
				}
			
				rrcount = 0;
				outlen = build_header(db, (reply + 2), (p + 2), question, 0);
			}

			memset(&key, 0, sizeof(key));	
			memset(&data, 0, sizeof(data));
			if (rbt) {
				free(rbt);
				rbt = NULL;
			}
			if (rbt2) {
				free(rbt2);
				rbt2 = NULL;
			}
		}  /* RB_FOREACH */

		outlen = build_soa(db, (reply + 2), outlen, soa, question);
		rrcount++;

		pack16(reply, htons(outlen));

		/* set the rrcount in there */

		NTOHS(odh->answer);
		odh->answer += rrcount;
		HTONS(odh->answer);

		if (question->tsig.have_tsig && question->tsig.tsigverified) {
			if (envelopcount == 1)
				envelopcount = -1;
			else
				envelopcount = -2;

			outlen = additional_tsig(question, (reply + 2), 65000, outlen, 0, envelopcount, tsigctx);
			odh->additional = htons(1);

			pack16(reply, htons(outlen));

			HMAC_CTX_free(tsigctx);
		}

		len = send(so, reply, outlen + 2, 0);
		if (len <= 0) 	
			goto drop;

		goto drop;

	} /* for(;;) */

	

drop:
	if (soa) {
		free (soa);
		soa = NULL;
	}

	if (rbt) {
		free (rbt);
		rbt = NULL;
	}
	
	if (rbt2) {
		free (rbt2);
		rbt2 = NULL;
	}

	if (saverbt) {
		free (saverbt);
		saverbt = NULL;
	}

	close(so);
	exit(0);
}

/* 
 * REAP - reap the child that is zombied by now, this is a sighandler for
 *			SIGCHLD
 */

void 
reap(int sig)
{
        int status;
        pid_t pid;

        while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        }
}


/* 
 * build_header - build a header reply
 *
 */

int 
build_header(ddDB *db, char *reply, char *buf, struct question *q, int answercount)
{
	struct dns_header *odh;
	u_int16_t outlen;

	odh = (struct dns_header *)reply;
	outlen = sizeof(struct dns_header);

	/* copy question to reply */
	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
	/* blank query */
	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	outlen += (q->hdr->namelen + 4);

	SET_DNS_REPLY(odh);
	SET_DNS_AUTHORITATIVE(odh);
	
	/* XXX */
	HTONS(odh->query);

	odh->question = htons(1);
	odh->answer = htons(answercount);
	odh->nsrr = 0;
	odh->additional = 0;

	return (outlen);
}



/*
 * BUILD_SOA - build an SOA answer
 */

int
build_soa(ddDB *db, char *reply, int offset, struct rbtree *rbt, struct question *q)
{
	char *p;
	char *label;
	char *plabel;
		
	int labellen;
	int tmplen;

        struct answer {
                char name[2];
                u_int16_t type;
                u_int16_t class;
                u_int32_t ttl;
                u_int16_t rdlength;      /* 12 */
                char rdata;             
        } __attribute__((packed));

	struct answer *answer;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;	

	if ((rrset = find_rr(rbt, DNS_TYPE_SOA)) == NULL) {
		return 0;
	}
	if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
		return 0;
	}
	
	answer = (struct answer *)(&reply[offset]);

	answer->name[0] = 0xc0;
	answer->name[1] = 0x0c;
	answer->type = htons(DNS_TYPE_SOA);
	answer->class = htons(DNS_CLASS_IN);
	answer->ttl = htonl(rrset->ttl);

	offset += 12;			/* up to rdata length */

	p = (char *)&answer->rdata;


	label = ((struct soa *)rrp->rdata)->nsserver;
	labellen = ((struct soa *)rrp->rdata)->nsserver_len;

	plabel = label;

	if (offset + labellen <= 65535)
		memcpy(&reply[offset], (char *)plabel, labellen);
	else 
		return (offset); /* XXX */
	
	offset += labellen;

	/* compress the label if possible */
	if ((tmplen = compress_label((u_char*)reply, offset, labellen)) > 0) {
		offset = tmplen;
	}

	label = ((struct soa *)rrp->rdata)->responsible_person;
	labellen = ((struct soa *)rrp->rdata)->rp_len;
	plabel = label;

	if (offset + labellen <= 65535)
		memcpy(&reply[offset], (char *)plabel, labellen);
	else 
		return (offset); /* XXX */

	offset += labellen;

	/* 2 compress the label if possible */

	if ((tmplen = compress_label((u_char*)reply, offset, labellen)) > 0) {
		offset = tmplen;
	}


	/* XXX */
	if ((offset + sizeof(u_int32_t)) >= 65535 ) {
		/* XXX server error reply? */
		return (offset);
	}
	pack32(&reply[offset], htonl(((struct soa *)rrp->rdata)->serial));
	offset += sizeof(u_int32_t);
	
	if ((offset + sizeof(u_int32_t)) >= 65535 ) {
		return (offset);
	}
	pack32(&reply[offset], htonl(((struct soa *)rrp->rdata)->refresh));
	offset += sizeof(u_int32_t);

	if ((offset + sizeof(u_int32_t)) >= 65535 ) {
		return (offset);
	}
	pack32(&reply[offset], htonl(((struct soa *)rrp->rdata)->retry));
	offset += sizeof(u_int32_t);

	if ((offset + sizeof(u_int32_t)) >= 65535 ) {
		return (offset);
	}
	pack32(&reply[offset], htonl(((struct soa *)rrp->rdata)->expire));
	offset += sizeof(u_int32_t);

	if ((offset + sizeof(u_int32_t)) > 65535 ) {
		return (offset);
	}
	pack32(&reply[offset], htonl(((struct soa *)rrp->rdata)->minttl));
	offset += sizeof(u_int32_t);

	answer->rdlength = htons(&reply[offset] - &answer->rdata);
	
	return (offset);
}

int
checklabel(ddDB *db, struct rbtree *rbt, struct rbtree *soa, struct question *q)
{
	struct rbtree *tmprbt;
	struct rrset *rrset;
	char *p;
	int plen;

	if (memcmp(rbt, soa, sizeof(struct rbtree)) == 0)	
		return 1;
	
	p = rbt->zone;
	plen = rbt->zonelen;

	do {
		if (*p == '\0')
			return (0);

		tmprbt = find_rrset(db, p, plen);
		if (tmprbt == NULL) {
			plen -= (*p + 1);
			p = (p + (*p + 1));

			free(tmprbt);
			continue;
		}
	
		/*
 		 * the encountered label has an SOA before we got to the
		 * root, so we skip this record entirely...
		 */

		if ((rrset = find_rr(tmprbt, DNS_TYPE_SOA)) != NULL) {
			free (tmprbt);
			return (0);
		}

			
		/*
		 * and check the next label...
		 */

		plen -= (*p + 1);
		p = (p + (*p + 1));

		free(tmprbt);
		
	} while (memcmp(p, q->hdr->name, q->hdr->namelen) != 0);

	
	return (1);
}

void 
gather_notifydomains(ddDB *db)
{
	ddDBT key, data;
	
	time_t now, soatime;
	struct tm *tm;

	char timestring[128];
	char buf[128];

	struct node *n, *nx;
	struct rbtree *rbt;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct mzone *mz;
	struct mzone_dest *md;
	int i;

	SLIST_INIT(&notifyhead);
	
	now = time(NULL);
	tm = localtime(&now);

	/* adjust for offset taken before chroot */
	tm->tm_gmtoff = glob_time_offset;

	if (tm != NULL)
		strftime(timestring, sizeof(timestring), "%Y%m%d", tm);
	else
		snprintf(timestring, sizeof(timestring), "19700101");

	now = time(NULL);

	memset(&key, 0, sizeof(key));	
	memset(&data, 0, sizeof(data));
	
	RB_FOREACH_SAFE(n, domaintree, &db->head, nx) {
		rbt = (struct rbtree *)n->data;

		if ((rrset = find_rr(rbt, DNS_TYPE_SOA)) != NULL) {
			rrp = TAILQ_FIRST(&rrset->rr_head);
			notn2 = malloc(sizeof(struct notifyentry));
			if (notn2 == NULL) {
				continue;
			}

			notn2->ids = calloc(notify, sizeof(u_int16_t));
			if (notn2->ids == NULL) {
				free(notn2);
				continue;
			}

			notn2->attempts = calloc(notify, sizeof(u_int16_t));
			if (notn2->attempts == NULL) {
				free(notn2);
				continue;
			}
	
			memcpy(notn2->domain, rbt->zone, rbt->zonelen);
			notn2->domainlen = rbt->zonelen;


			SLIST_FOREACH(mz, &mzones, mzone_entry) {
				if (notn2->domainlen == mz->zonenamelen &&
					memcmp(notn2->domain, mz->zonename, notn2->domainlen) == 0) {
					break;
				}
			}

			if (mz == NULL) {
				dolog(LOG_INFO, "skipping zone \"%s\" due to no mzone entry for it!\n", rbt->humanname);
				free(notn2->attempts);
				free(notn2);
				continue;
			}

			notn2->mzone = mz;

			i = 0;
			/* initialize notifications to 1 */
			SLIST_FOREACH(md, &mz->dest, entries) {
				md->notified = 1;
				i++;	
			}

			notn2->numadd = i;

			soatime = (time_t)((struct soa *)rrp->rdata)->serial;
			snprintf(buf, sizeof(buf), "%u", ((struct soa *)rrp->rdata)->serial);

			if (strncmp(buf, timestring, strlen(timestring)) == 0) {
				dolog(LOG_INFO, "inserting zone \"%s\" for notification...\n", rbt->humanname);
				SLIST_INSERT_HEAD(&notifyhead, notn2, notify_entry);
			} else if (difftime(now, soatime) < 1800 && difftime(now, soatime) > 0) {
				dolog(LOG_INFO, "2 inserting zone \"%s\" for notification...\n", rbt->humanname);
				SLIST_INSERT_HEAD(&notifyhead, notn2, notify_entry);
			} else {
#if 0
				dolog(LOG_INFO, "SOA serial for zone \"%s\" did not make sense (%s), not notifying\n", rbt->humanname, buf);
#endif
				free(notn2->attempts);
				free(notn2);
			}
		}

		memset(&key, 0, sizeof(key));	
		memset(&data, 0, sizeof(data));
	} 

	return;
}

void
notifyddds(int *notifyfd)
{
	struct mzone_dest *md;
	int so;
	int i, remove;

	i = 0;

	SLIST_FOREACH_SAFE(notnp, &notifyhead, notify_entry, notn2) {
		remove = 0;
		SLIST_FOREACH(md, &notnp->mzone->dest, entries) {
			if (md->notifydest.ss_family == AF_INET) 
				so = notifyfd[0];
			else
				so = notifyfd[1];

			notnp->ids[i] = arc4random() & 0xffff;
			notnp->attempts[i]++;
			if (notnp->attempts[i] > 10) {
				dolog(LOG_INFO, "notify entry removed due to timeout\n");
				remove = 1;
				break;
			} 

			if (md->notified == 1)
				notifypacket(so, notnp, md, i);

			i++;
		}

		if (remove) {
			dolog(LOG_INFO, "removed domain \"%s\"\n", notnp->mzone->humanname);
			SLIST_REMOVE(&notifyhead, notnp, notifyentry, notify_entry);
		}
	}

	return;
}

void
notifypacket(int so, void *vnotnp, void *vmd, int packetcount)
{
	struct notifyentry *notnp = (struct notifyentry *)vnotnp;
	struct mzone *mz = (struct mzone *)notnp->mzone;
	struct mzone_dest *md = (struct mzone_dest *)vmd;
	struct sockaddr_in bsin, *sin;
	struct sockaddr_in6 bsin6, *sin6;
	struct sockaddr_storage savesin, newsin;
	char packet[512];
	char *questionname;
	u_int16_t *classtype;
	struct dns_header *dnh;
	struct question *fq = NULL;
	int outlen = 0, slen, ret;
	int sinlen;

	
	memcpy(&newsin, (char *)&mz->notifybind, sizeof(struct sockaddr_storage));
	sinlen = sizeof(struct sockaddr_storage);
	if (getsockname(so, (struct sockaddr *)&savesin, &sinlen) < 0) {
		dolog(LOG_INFO, "getsockname error\n");
		return;
	}

	if (mz->notifybind.ss_family == AF_INET) {
		struct sockaddr_in *tmpsin = (struct sockaddr_in *)&newsin;


		tmpsin->sin_port = ((struct sockaddr_in *)&savesin)->sin_port;

		if (bind(so, (struct sockaddr *)tmpsin, sizeof(struct sockaddr_in)) < 0) {
			dolog(LOG_INFO, "can't bind to bind address found in mzone for zone \"%s\"", mz->humanname);
			return;
		}
	} else if (mz->notifybind.ss_family == AF_INET6) {
		struct sockaddr_in6 *tmpsin = (struct sockaddr_in6 *)&newsin;

		tmpsin->sin6_port = ((struct sockaddr_in6 *)&savesin)->sin6_port;
#ifndef __linux__
		tmpsin->sin6_len = sizeof(struct sockaddr_in6);	
#endif

		if (bind(so, (struct sockaddr *)tmpsin, sizeof(struct sockaddr_in6)) < 0) {
			dolog(LOG_INFO, "can't bind to v6 bind address found in mzone for zone \"%s\"", mz->humanname);
			return;
		}
	}

	memset(&packet, 0, sizeof(packet));
	dnh = (struct dns_header *)&packet[0];

	dnh->id = htons(notnp->ids[packetcount]);
	SET_DNS_NOTIFY(dnh);
	SET_DNS_AUTHORITATIVE(dnh);	
	SET_DNS_QUERY(dnh);
	HTONS(dnh->query);
	
	dnh->question = htons(1);

	outlen += sizeof(struct dns_header);
	questionname = (char *)&packet[outlen];

	memcpy(questionname, notnp->domain, notnp->domainlen);
	outlen += notnp->domainlen;
	
	classtype = (u_int16_t *)&packet[outlen];
	classtype[0] = htons(DNS_TYPE_SOA);
	classtype[1] = htons(DNS_CLASS_IN);

	outlen += (2 * sizeof(u_int16_t));

	/* work out the tsig stuff */
	if (md->tsigkey != NULL) {
		char *tsigname;
		int tsignamelen;

		tsigname = dns_label(md->tsigkey, &tsignamelen);
		if (tsigname == NULL) {
			dolog(LOG_INFO, "dns_label()");
			return;
		}
	
		if ((fq = build_fake_question(notnp->domain, notnp->domainlen, 0, tsigname, tsignamelen)) == NULL) {
			return;
		}
	
		outlen = additional_tsig(fq, packet, sizeof(packet), outlen, 1, 0, NULL);

		dnh->additional = htons(1);

		memcpy(&md->requestmac, fq->tsig.tsigmac, 32);
		notnp->usetsig = 1;
		
		free(tsigname);
		free_question(fq);
	} else {
		notnp->usetsig = 0;
	}

	if (savesin.ss_family == AF_INET) {
		struct sockaddr_in *tmpsin = (struct sockaddr_in *)&md->notifydest;

		slen = sizeof(struct sockaddr_in);
		sin = (struct sockaddr_in *)&md->notifydest;
		memset(&bsin, 0, sizeof(bsin));
		bsin.sin_family = AF_INET;
		bsin.sin_port = htons(md->port);
		bsin.sin_addr.s_addr = tmpsin->sin_addr.s_addr;

		ret = sendto(so, packet, outlen, 0, (struct sockaddr *)&bsin, slen);
	} else {
		struct sockaddr_in6 *tmpsin = (struct sockaddr_in6 *)&md->notifydest;

		slen = sizeof(struct sockaddr_in6);
		sin6 = (struct sockaddr_in6 *)&md->notifydest;
		memset(&bsin6, 0, sizeof(bsin6));
		bsin6.sin6_family = AF_INET6;
		bsin6.sin6_port = htons(md->port);
#ifndef __linux__
		bsin6.sin6_len = sizeof(struct sockaddr_in6);
#endif
		memcpy(&bsin6.sin6_addr, &tmpsin->sin6_addr, 16);

		ret = sendto(so, packet, outlen, 0, (struct sockaddr *)&bsin6, slen);
	}

	if (ret < 0) {
		dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
	}

	/* as soon as the sendto is done we want to bind back to 0.0.0.0 */
	if (mz->notifybind.ss_family == AF_INET) {
		struct sockaddr_in *tmpsin = (struct sockaddr_in *)&savesin;

		if (bind(so, (struct sockaddr *)tmpsin, sizeof(struct sockaddr_in)) < 0) {
			dolog(LOG_INFO, "can't unbind from bind address found in mzone for zone \"%s\"", mz->humanname);
			return;
		}
	} else if (mz->notifybind.ss_family == AF_INET6) {
		struct sockaddr_in6 *tmpsin = (struct sockaddr_in6 *)&savesin;

		if (bind(so, (struct sockaddr *)tmpsin, sizeof(struct sockaddr_in6)) < 0) {
			dolog(LOG_INFO, "can't unbind from bind address found in mzone for zone \"%s\"", mz->humanname);
			return;
		}
	}
	
	return;
}

int 
check_notifyreply(struct dns_header *dh, struct question *question, struct sockaddr_storage *ss, int af, struct notifyentry *notnp, int count)
{
	struct mzone_dest *md, *md2;
	struct sockaddr_in6 *sin6, *sin62 = NULL;
	struct sockaddr_in *sin, *sin2 = NULL;
	char address[INET6_ADDRSTRLEN];
	u_int16_t ntohsquery;

	switch (af) {
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)ss;
		inet_ntop(AF_INET6, (void*)&sin6->sin6_addr, (char*)&address, sizeof(address));
		break;	
	case AF_INET:
		sin = (struct sockaddr_in *)ss;
		inet_ntop(AF_INET, (void*)&sin->sin_addr, (char*)&address, sizeof(address));
		break;
	default:
		return -1;
		break;
	}

	ntohsquery = ntohs(dh->query);

	if (ntohs(dh->id) == notnp->ids[count] &&
		(((ntohsquery & DNS_NOTIFY) && (ntohsquery & DNS_AUTH)) || 
		(ntohsquery & (DNS_AUTH | DNS_REPLY)) ||
		(ntohsquery & (DNS_AUTH | DNS_REPLY | DNS_NOTIFY))) && 
		ntohs(question->hdr->qtype) == DNS_TYPE_SOA &&
		ntohs(question->hdr->qclass) == DNS_CLASS_IN &&
		question->hdr->namelen == notnp->domainlen && 
		memcmp(question->hdr->name, notnp->domain, notnp->domainlen) == 0) {

		if (notnp->usetsig && question->tsig.tsigverified != 1) {
			dolog(LOG_ERR, "tsig'ed notify answer was not validated from \"%s\", errorcode = 0x%02x\n", address, question->tsig.tsigerrorcode);
			return -1;
		}

		SLIST_FOREACH_SAFE(md, &notnp->mzone->dest, entries, md2) {

			if (md->notifydest.ss_family != af)
				continue;

			if (af == AF_INET6)  {
				sin62 = (struct sockaddr_in6 *)&md->notifydest;
				if (memcmp(&sin6->sin6_addr, &sin62->sin6_addr, 16) == 0 && md->notified == 1) {
					dolog(LOG_INFO, "notify success! removing address \"%s\" for zone \"%s\" from notify contact list\n", address, question->converted_name);
					md->notified = 0;
				}
			} else {
				sin2 = (struct sockaddr_in *)&md->notifydest;
				if (sin->sin_addr.s_addr == sin2->sin_addr.s_addr && md->notified == 1) {
					dolog(LOG_INFO, "notify success! removing address \"%s\" for zone \"%s\" from notify contact list\n", address, question->converted_name);
					md->notified = 0;
				}
			} /* if af==AF_INET6 */
		} /* SLIST_FOREACH */
	} 

	return 0;
}
