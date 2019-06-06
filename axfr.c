/*
 * Copyright (c) 2011-2019 Peter J. Philipp
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
 * $Id: axfr.c,v 1.28 2019/06/06 15:08:00 pjp Exp $
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
void	init_notifyslave(void);
int	insert_axfr(char *, char *);
int	insert_notifyslave(char *, char *, char *);
void	notifypacket(int, void *, void *, int);
void	notifyslaves(int *);
void	reap(int);

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
extern void 		build_reply(struct sreply *, int, char *, int, struct question *, struct sockaddr *, socklen_t, struct rbtree *, struct rbtree *, u_int8_t, int, int, struct recurses *);

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

SLIST_HEAD(, axfrentry) axfrhead;

static struct axfrentry {
	char name[INET6_ADDRSTRLEN];
	int family;
	struct sockaddr_storage hostmask;
	struct sockaddr_storage netmask;
	u_int8_t prefixlen;
	SLIST_ENTRY(axfrentry) axfr_entry;
} *an2, *anp;

SLIST_HEAD(, notifyslaveentry) notifyslavehead;

static struct notifyslaveentry {
	char name[INET6_ADDRSTRLEN];
	int family;
	struct sockaddr_storage hostmask;
	struct sockaddr_storage netmask;
	u_int8_t prefixlen;
	char *tsigname;
	int tsignamelen;
	char tsigrequestmac[32];
	SLIST_ENTRY(notifyslaveentry) notifyslave_entry;
} *nfslnp2, *nfslnp;



SLIST_HEAD(notifylisthead, notifyentry) notifyhead;

static struct notifyentry {
	char domain[DNS_MAXNAME];
	int domainlen;
	u_int16_t *ids;
	u_int16_t *attempts;
	SLIST_ENTRY(notifyentry) notify_entry;
} *notn2, *notnp;

extern int domaincmp(struct node *e1, struct node *e2);
static int 	check_notifyreply(struct dns_header *, struct question *, struct sockaddr_storage *, int, struct notifyentry *, int);


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

/*
 * INIT_NOTIFYSLAVE - initialize the axfr singly linked list
 */

void
init_notifyslave(void)
{
	SLIST_INIT(&notifyslavehead);
	return;
}

/*
 * INSERT_NOTIFYSLAVE - insert an address and prefixlen into the notifyslave slist
 */

int
insert_notifyslave(char *address, char *prefixlen, char *tsigkey)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	int pnum, tsignamelen; 
	int ret;

	tsignamelen = strlen(tsigkey);
	if (strcmp(tsigkey, "NOKEY") == 0) {
		tsigkey = NULL;
		tsignamelen = 0;
	}

	pnum = atoi(prefixlen);
	nfslnp2 = calloc(1, sizeof(struct notifyslaveentry));      /* Insert after. */
	if (nfslnp2 == NULL)
		return (-1);


	if (strchr(address, ':') != NULL) {
		nfslnp2->family = AF_INET6;
		sin6 = (struct sockaddr_in6 *)&nfslnp2->hostmask;
		if ((ret = inet_pton(AF_INET6, address, &sin6->sin6_addr.s6_addr)) != 1)
			return (-1);
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(53);
		sin6 = (struct sockaddr_in6 *)&nfslnp2->netmask;
		sin6->sin6_family = AF_INET6;
		if (getmask6(pnum, sin6) < 0) 
			return(-1);
		nfslnp2->prefixlen = pnum;
	} else {

		nfslnp2->family = AF_INET;
		sin = (struct sockaddr_in *)&nfslnp2->hostmask;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = inet_addr(address);
		sin->sin_port = htons(53);
		sin = (struct sockaddr_in *)&nfslnp2->netmask;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = getmask(pnum);
		nfslnp2->prefixlen = pnum;

	}

	if (tsignamelen != 0) {
		nfslnp2->tsigname = dns_label(tsigkey, &tsignamelen);
		if (nfslnp2->tsigname == NULL) {
			return -1;
		}
		nfslnp2->tsignamelen = tsignamelen;
	} else {
		nfslnp2->tsigname = NULL;
		nfslnp2->tsignamelen = 0;
	}

	SLIST_INSERT_HEAD(&notifyslavehead, nfslnp2, notifyslave_entry);

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

	int i, so, len;
	int n;
	int sel, maxso = 0;
	int is_ipv6, axfr_acl;
	int notifyfd[2];
	int packetlen;

	socklen_t fromlen;
	char buf[512];
	char *packet;
	char requestmac[32];
	
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
			sin->sin_family = AF_INET6;
			sin->sin_port = htons(0);
	
			if (bind(notifyfd[1], (struct sockaddr *)sin, sizeof(*sin6)) < 0) {
				dolog(LOG_INFO, "bind notify6: %s\n", strerror(errno));
			}

			memset((char *)&from, 0, sizeof(from));

			notifyslaves((int *)&notifyfd);
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
				if (notifyfd[0] > -1 || notifyfd[1] > -1)
					notifyslaves((int *)&notifyfd);	
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
						dolog(LOG_ERR, "received bad message on AXFR imsg\n");
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

				/* get our request mac */
				SLIST_FOREACH(nfslnp, &notifyslavehead, notifyslave_entry) {
					struct sockaddr_in *sin2 = (struct sockaddr_in *)&nfslnp->hostmask;

					if (memcmp((char *)&sin->sin_addr.s_addr, (char *)&sin2->sin_addr.s_addr, sizeof(struct in_addr)) == 0) {
						memcpy(requestmac, nfslnp->tsigrequestmac, 32);
						break;
					}
				}

				if (nfslnp == NULL)
					question = build_question(buf, len, ntohs(dh->additional), NULL);
				else
					question = build_question(buf, len, ntohs(dh->additional), requestmac);

				if (question == NULL) {
					dolog(LOG_INFO, "build_question failed on notify reply, drop\n");
					continue;
				}

				sin = (struct sockaddr_in *)&from;
				inet_ntop(AF_INET, (void*)&sin->sin_addr, (char*)&address, sizeof(address));

#ifdef __linux__
				SLIST_FOREACH(notnp, &notifyhead, notify_entry) {
#else
				SLIST_FOREACH_SAFE(notnp, &notifyhead, notify_entry, notn2) {
#endif
					for (i = 0; i < notify; i++) {
						if (check_notifyreply(dh, question, 
							(struct sockaddr_storage *) sin, AF_INET, notnp, i) < 0) {
						dolog(LOG_INFO, "got a reply from a notify host (%s) DNS->ID %u that says: %04x\n", address, ntohs(dh->id), ntohs(dh->query));
					 	}
					}
				}
			
				free_question(question);

				if (SLIST_EMPTY(&notifyslavehead)) {
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

				/* get our request mac */
				SLIST_FOREACH(nfslnp, &notifyslavehead, notifyslave_entry) {
					struct sockaddr_in6 *sin2 = (struct sockaddr_in6 *)&nfslnp->hostmask;

					if (memcmp((char *)&sin6->sin6_addr, (char *)&sin2->sin6_addr, sizeof(struct in6_addr)) == 0) {
						memcpy(requestmac, nfslnp->tsigrequestmac, 32);
						break;
					}
				}

				if (nfslnp == NULL)
					question = build_question(buf, len, ntohs(dh->additional), NULL);
				else
					question = build_question(buf, len, ntohs(dh->additional), requestmac);
				if (question == NULL) {
					dolog(LOG_INFO, "build_question failed on notify reply, drop\n");
					continue;
				}


#ifdef __linux
				SLIST_FOREACH(notnp, &notifyhead, notify_entry) {
#else
				SLIST_FOREACH_SAFE(notnp, &notifyhead, notify_entry, notn2) {
#endif
					for (i = 0; i < notify; i++) {
						if (check_notifyreply(dh, question, 
							(struct sockaddr_storage *) sin6, AF_INET6, notnp, i) < 0) {
							dolog(LOG_INFO, "got a reply from a notify host (%s) DNS->ID %u that says: %04x\n", address, ntohs(dh->id), ntohs(dh->query));
					    }
					}
				}
			
				free_question(question);

				if (SLIST_EMPTY(&notifyslavehead)) {
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
	char *reply;

	int len, dnslen;
	int offset = 0;
	int qlen;
	int outlen;
	int rrcount;
	int envelopcount;
	int rs;
	int tsigkeylen;

	u_int16_t *tmp;
	
	struct node *n, *nx;
	struct dns_header *dh, *odh;
	struct sreply sreply;
	struct question *question, *fq;
	struct rbtree *rbt = NULL, *rbt2 = NULL, *saverbt = NULL, *soa = NULL;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;

	ddDBT key, data;
	HMAC_CTX *tsigctx = NULL;

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
			tmp = (u_int16_t *)p;
			dnslen = ntohs(*tmp);	
		} else {
			offset += len;
			continue;
		}
		if (dnslen + 2 != offset + len) {
			offset += len;
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
			
			build_reply(&sreply, so, (p + 2), dnslen, NULL, NULL, 0, NULL, NULL, 0xff, 1, 0, NULL);

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
			dolog(LOG_INFO, "AXFR question had TSIG errors, code %02x, drop\n", question->tsig.tsigerrorcode);
			goto drop;
		}

		/* now we can be reasonably sure that it's an AXFR for us */

		reply = calloc(1, 65538);	
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
			build_reply(&sreply, so, (p + 2), dnslen, question, NULL, 0, rbt2, NULL, 0xff, 1, 0, NULL);
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
			build_reply(&sreply, so, (p + 2), dnslen, question, NULL, 0, rbt2, NULL, 0xff, 1, 0, NULL);
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
		
			tmp = (u_int16_t *)reply;
			*tmp = htons(outlen);
		
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
				build_reply(&sreply, so, (p + 2), dnslen, fq, NULL, 0, rbt, NULL, 0xff, 1, 0, NULL);
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

							build_reply(&sreply, so, (p + 2), dnslen, fq, NULL, 0, rbt2, NULL, 0xff, 1, 0, NULL);
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
				tmp = (u_int16_t *)reply;
				*tmp = htons(outlen);
			
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

					tmp = (u_int16_t *)reply; 
					*tmp = htons(outlen);
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

		tmp = (u_int16_t *)reply;
		*tmp = htons(outlen);

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

			tmp = (u_int16_t *)reply; 
			*tmp = htons(outlen);

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
	
	NTOHS(odh->query);

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
	u_int32_t *soa_val;

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
	answer->ttl = htonl(((struct soa *)rrp->rdata)->ttl);

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
	soa_val = (u_int32_t *)&reply[offset];
	*soa_val = htonl(((struct soa *)rrp->rdata)->serial);
	offset += sizeof(u_int32_t);
	
	if ((offset + sizeof(u_int32_t)) >= 65535 ) {
		return (offset);
	}
	soa_val = (u_int32_t *)&reply[offset];
	*soa_val = htonl(((struct soa *)rrp->rdata)->refresh);
	offset += sizeof(u_int32_t);

	if ((offset + sizeof(u_int32_t)) >= 65535 ) {
		return (offset);
	}
	soa_val = (u_int32_t *)&reply[offset];
	*soa_val = htonl(((struct soa *)rrp->rdata)->retry);
	offset += sizeof(u_int32_t);

	if ((offset + sizeof(u_int32_t)) >= 65535 ) {
		return (offset);
	}
	soa_val = (u_int32_t *)&reply[offset];
	*soa_val = htonl(((struct soa *)rrp->rdata)->expire);
	offset += sizeof(u_int32_t);

	if ((offset + sizeof(u_int32_t)) > 65535 ) {
		return (offset);
	}
	soa_val = (u_int32_t *)&reply[offset];
	*soa_val = htonl(((struct soa *)rrp->rdata)->minttl);
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

	SLIST_INIT(&notifyhead);
	
	now = time(NULL);
	tm = localtime(&now);
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
				free(notn2);
			}
		}

		memset(&key, 0, sizeof(key));	
		memset(&data, 0, sizeof(data));
	} 

	return;
}

void 
notifyslaves(int *notifyfd)
{
	int so;
	int i;

	i = 0;
	SLIST_FOREACH(nfslnp, &notifyslavehead, notifyslave_entry) {
		if (nfslnp->family == AF_INET6) {	
			so = notifyfd[1];
		} else {
			so = notifyfd[0];
		}
#if 0
		dolog(LOG_INFO, "notifying %s...\n", nfslnp->name);
#endif

#ifdef __linux__
		SLIST_FOREACH(notnp, &notifyhead, notify_entry) {
#else
		SLIST_FOREACH_SAFE(notnp, &notifyhead, notify_entry, notn2) {
#endif
			notnp->ids[i] = arc4random() & 0xffff;
			notnp->attempts[i]++;
			if (notnp->attempts[i] > 10) {
				dolog(LOG_INFO, "notify entry removed due to timeout\n");
				SLIST_REMOVE(&notifyhead, notnp, notifyentry, notify_entry);
			} 

			notifypacket(so, nfslnp, notnp, i);
		}

		i++;
	}

	return;
}

void
notifypacket(int so, void *vnse, void *vnotnp, int packetcount)
{
	struct notifyslaveentry *nse = (struct notifyslaveentry *)vnse;
	struct notifyentry *notnp = (struct notifyentry *)vnotnp;
	struct sockaddr_in bsin, *sin;
	struct sockaddr_in6 bsin6, *sin6;
	char packet[512];
	char *questionname;
	u_int16_t *classtype;
	struct dns_header *dnh;
	struct question *fq = NULL;
	int outlen = 0, slen, ret;

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
	if (nse->tsignamelen != 0) {
		if ((fq = build_fake_question(notnp->domain, notnp->domainlen, 0, nse->tsigname, nse->tsignamelen)) == NULL) {
			return;
		}
	
		outlen = additional_tsig(fq, packet, sizeof(packet), outlen, 1, 0, NULL);

		dnh->additional = htons(1);

		memcpy(nse->tsigrequestmac, fq->tsig.tsigmac, 32);

		free_question(fq);
	}
		
	if (nse->family == AF_INET) {
		slen = sizeof(struct sockaddr_in);
		sin = (struct sockaddr_in *)&nse->hostmask;
		memset(&bsin, 0, sizeof(bsin));
		bsin.sin_family = AF_INET;
		bsin.sin_port = htons(53);
		bsin.sin_addr.s_addr = sin->sin_addr.s_addr;

		ret = sendto(so, packet, outlen, 0, (struct sockaddr *)&bsin, slen);
	} else {
		slen = sizeof(struct sockaddr_in6);
		sin6 = (struct sockaddr_in6 *)&nse->hostmask;
		memset(&bsin6, 0, sizeof(bsin6));
		bsin6.sin6_family = AF_INET6;
		bsin6.sin6_port = htons(53);
		memcpy(&bsin6.sin6_addr, &sin6->sin6_addr, 16);

		ret = sendto(so, packet, outlen, 0, (struct sockaddr *)sin6, slen);
	}

	if (ret < 0) {
		dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
	}
	
	return;
}

int 
check_notifyreply(struct dns_header *dh, struct question *question, struct sockaddr_storage *ss, int af, struct notifyentry *notnp, int count)
{
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
#ifdef __linux__
			SLIST_FOREACH(nfslnp, &notifyslavehead, notifyslave_entry) {
#else
			SLIST_FOREACH_SAFE(nfslnp, &notifyslavehead, notifyslave_entry, nfslnp2) {
#endif
				if (tsig && nfslnp->tsignamelen != 0 && question->tsig.tsigverified != 1) {
					dolog(LOG_ERR, "tsig'ed notify answer was not validated, errorcode = %02x\n", question->tsig.tsigerrorcode);
					continue;
				}

				if (nfslnp->family != af)
					continue;

				if (af == AF_INET6)  {
					sin62 = (struct sockaddr_in6 *)&nfslnp->hostmask;
					if (memcmp(&sin6->sin6_addr, &sin62->sin6_addr, 16) == 0) {
						dolog(LOG_INFO, "notify success! removing address \"%s\" from notify contact list\n", address);
						SLIST_REMOVE(&notifyslavehead, nfslnp, notifyslaveentry, notifyslave_entry);
					}
				} else {
					sin2 = (struct sockaddr_in *)&nfslnp->hostmask;
					if (sin->sin_addr.s_addr == sin2->sin_addr.s_addr) {
						dolog(LOG_INFO, "notify success! removing address \"%s\" from notify contact list\n", address);
						SLIST_REMOVE(&notifyslavehead, nfslnp, notifyslaveentry, notifyslave_entry);
					}
			} /* if af==AF_INET6 */
		} /* SLIST_FOREACH */
	} 

	return 0;
}
