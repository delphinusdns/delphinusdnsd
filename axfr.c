/*
 * Copyright (c) 2011-2023 Peter J. Philipp <pbug44@delphinusdns.org>
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
#include "ddd-crypto.h"

void	axfrloop(struct cfg *, char **, ddDB *, struct imsgbuf *, struct imsgbuf *);
void	axfr_connection(int, char *, int, ddDB *, char *, int);
int	build_header(ddDB *, char *, char *, struct question *, int, int);
int	build_soa(ddDB *, char *, int, struct rbtree *, struct question *);
int	checklabel(ddDB *, struct rbtree *, struct rbtree *, struct question *);
int	find_axfr(struct sockaddr_storage *, int);
void	gather_notifydomains(ddDB *);
void	init_axfr(void);
void	init_notifyddd(void);
int	insert_axfr(char *, char *);
int	insert_notifyddd(char *, char *);
void	notifypacket(struct imsgbuf *, int, void *, void *, int);
void    notifyddds(struct imsgbuf *, int *);
void	reap(int);
int 	axfr_acceptloop(struct cfg *, struct imsgbuf *, struct imsgbuf *, struct imsgbuf *);
int	request_socket(struct imsgbuf *, int);
int	sendforme(struct imsgbuf *, int, char *, int, struct sockaddr *, int);

extern void 	pack(char *, char *, int);
extern void 	pack32(char *, uint32_t);
extern void 	pack16(char *, uint16_t);
extern void 	pack8(char *, uint8_t);
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
extern uint16_t	create_anyreply(struct sreply *, char *, int, int, int, uint32_t, uint);
extern struct question	*build_fake_question(char *, int, uint16_t, char *, int);
extern struct question	*build_question(char *, int, uint16_t, char *);
extern int		free_question(struct question *);
extern void		dolog(int, char *, ...);
extern void 		build_reply(struct sreply *, int, char *, int, struct question *, struct sockaddr *, socklen_t, struct rbtree *, struct rbtree *, uint8_t, int, int, char *);

extern struct rbtree * find_rrset(ddDB *db, char *name, int len);
extern struct rrset * find_rr(struct rbtree *rbt, uint16_t rrtype);
extern int display_rr(struct rrset *rrset);
extern int rotate_rr(struct rrset *rrset);

extern int domaincmp(struct node *e1, struct node *e2);
extern char * dns_label(char *, int *);
extern int additional_tsig(struct question *, char *, int, int, int, int, DDD_HMAC_CTX *, uint16_t);
extern int find_tsig_key(char *keyname, int keynamelen, char *key, int keylen);
extern int have_zone(char *zonename, int zonelen);
extern void ddd_shutdown(void);
extern int              find_filter(struct sockaddr_storage *, int);
extern int              find_passlist(struct sockaddr_storage *, int);
extern int              find_axfr(struct sockaddr_storage *, int);
extern int              find_tsig(struct sockaddr_storage *, int);
extern struct rrset *   find_rr(struct rbtree *rbt, uint16_t rrtype);
extern uint8_t          find_region(struct sockaddr_storage *, int);
extern struct imsgbuf *        register_cortex(struct imsgbuf *, int);




int notify = 0;				/* do not notify when set to 0 */

extern int debug, verbose;
extern time_t time_changed;
extern int tsig;
extern long glob_time_offset;
extern struct zonetree zonehead;
extern struct walkentry *we1, *wep;
extern int primary_axfr_old_behaviour;
extern int strictaxfr;
extern char *identstring;
extern uint16_t axfrport;

SLIST_HEAD(, axfrentry) axfrhead;

static struct axfrentry {
	char name[INET6_ADDRSTRLEN];
	int family;
	struct sockaddr_storage hostmask;
	struct sockaddr_storage netmask;
	uint8_t prefixlen;
	SLIST_ENTRY(axfrentry) axfr_entry;
} *an2, *anp;

SLIST_HEAD(notifylisthead, notifyentry) notifyhead;

static struct notifyentry {
	char domain[DNS_MAXNAME];
	int domainlen;
	uint16_t *ids;
	uint16_t *attempts;
	int usetsig;
	int numadd;
	struct mzone *mzone;
	SLIST_ENTRY(notifyentry) notify_entry;
} *notn2, *notnp;

struct axfr_acceptmsg {
	char address[INET6_ADDRSTRLEN];
	struct sockaddr_storage from;
	int fromlen;
	int passlist;
	int blocklist;
	int filter;
	int require_tsig;
	int axfr_acl;
	int aregion;
	int intidx;
	int af;
	int tsig;
	char packet[1024];
	int packetlen;
} __packed ;

extern int domaincmp(struct node *e1, struct node *e2);
static int 	check_notifyreply(struct dns_header *, struct question *, struct sockaddr_storage *, int, struct notifyentry *, int);
struct axfr_acceptmsg * accept_from_loop(struct imsgbuf *, char *, int, int *, int *, int *, int *, struct sockaddr_in **, struct sockaddr_in6 **);

extern SLIST_HEAD(mzones ,mzone)  mzones;


#define SEND_TO_PARENT	do { \
	if (from->sa_family == AF_INET6) { \
		fromlen = sizeof(struct sockaddr_in6); \
		sin6 = (struct sockaddr_in6 *)from; \
		inet_ntop(AF_INET6, (void *)&sin6->sin6_addr, (char *)&address, sizeof(address)); \
		aregion = find_region((struct sockaddr_storage *)sin6, AF_INET6); \
		filter = find_filter((struct sockaddr_storage *)sin6, AF_INET6); \
		if (passlist) { \
			blocklist = find_passlist((struct sockaddr_storage *)sin6, AF_INET6); \
		} \
		axfr_acl = find_axfr((struct sockaddr_storage *)sin6, AF_INET6); \
		require_tsig = 0; \
		if (tsig) { \
			require_tsig = find_tsig((struct sockaddr_storage *)sin6, AF_INET6); \
		} \
	} else if (from->sa_family == AF_INET) { \
		fromlen = sizeof(struct sockaddr_in); \
		sin = (struct sockaddr_in *)from; \
		inet_ntop(AF_INET, (void *)&sin->sin_addr, (char *)&address, sizeof(address)); \
		aregion = find_region((struct sockaddr_storage *)sin, AF_INET); \
		filter = find_filter((struct sockaddr_storage *)sin, AF_INET); \
		if (passlist) { \
			blocklist = find_passlist((struct sockaddr_storage *)sin, AF_INET); \
		} \
		axfr_acl = find_axfr((struct sockaddr_storage *)sin, AF_INET); \
		require_tsig = 0; \
		if (tsig) { \
			require_tsig = find_tsig((struct sockaddr_storage *)sin, AF_INET); \
		} \
	} else { \
		dolog(LOG_INFO, "TCP packet received on descriptor %u interface \"%s\" had weird address family (%u), drop\n", so, cfg->ident[i], from->sa_family); \
		close(so); \
		goto cont; \
	} \
	if (filter && require_tsig == 0) { \
		dolog(LOG_INFO, "TCP connection refused on descriptor %u interface \"%s\" from %s, filter policy, drop\n", so, cfg->ident[i], address); \
		close(so); \
		goto cont; \
	} \
	if (passlist && blocklist == 0) { \
		dolog(LOG_INFO, "TCP connection refused on descriptor %u interface \"%s\" from %s, passlist policy\n", so, cfg->ident[i], address); \
		close(so); \
		goto cont; \
	} \
	strlcpy((char *)&acceptmsg->address, (char *)&address, sizeof(acceptmsg->address)); \
	memcpy((char *)&acceptmsg->from, (char *)&from, sizeof(struct sockaddr_storage)); \
	pack32((char *)&acceptmsg->passlist,passlist); \
	pack32((char *)&acceptmsg->blocklist,blocklist); \
	pack32((char *)&acceptmsg->filter,filter); \
	pack32((char *)&acceptmsg->require_tsig,require_tsig); \
	pack32((char *)&acceptmsg->axfr_acl,axfr_acl); \
	pack32((char *)&acceptmsg->aregion,aregion); \
	pack32((char *)&acceptmsg->fromlen,fromlen); \
	pack32((char *)&acceptmsg->intidx,i); \
	pack32((char *)&acceptmsg->af,from->sa_family); \
	pack32((char *)&acceptmsg->tsig, require_tsig); \
	imsg_compose(ibuf, IMSG_NOTIFY_MESSAGE,  \
		0, 0, so, acceptmsg, sizeof(struct axfr_acceptmsg)); \
	msgbuf_write(&ibuf->w); \
	memset(acceptmsg, 0, sizeof(struct axfr_acceptmsg)); \
	fromlen = 0; \
	passlist = 0; \
	blocklist = 0; \
	filter = 0; \
	require_tsig = 0; \
	axfr_acl = 0; \
	aregion = 0; \
} while (0)	/* pass to parent */

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
	uint32_t hostmask, netmask;
	uint32_t a;
#ifdef __amd64
	uint64_t *hm[2], *nm[2], *a6[2];
#else
	uint32_t *hm[4], *nm[4], *a6[4];
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

void 
axfrloop(struct cfg *cfg, char **ident, ddDB *db, struct imsgbuf *ibuf, struct imsgbuf *cortex)
{
	fd_set rset;

	struct timeval tv;
	struct sockaddr_storage from;
	struct sockaddr_in6 *sin6;
	struct sockaddr_in *sin;
	struct dns_header *dh;
	struct question *question;
	struct imsgbuf	accept_ibuf, notify_ibuf;
	struct mzone_dest *md;
	struct axfr_acceptmsg *acceptmsg;

	int i, so, len;
	int count;
	int sel, maxso = 0;
	int is_ipv6, axfr_acl;
	int notifyfd[2];
	int idx, x;

	socklen_t fromlen;
	char buf[512];
	char buf0[512];
	
	time_t now;
	pid_t pid;

	char address[INET6_ADDRSTRLEN];

	signal(SIGCHLD, reap);

	/* set up acceptloop sandbox */
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, PF_UNSPEC, &cfg->my_imsg[MY_IMSG_ACCEPT].imsg_fds[0]) < 0) {
		dolog(LOG_INFO, "socketpair() failed\n");
		ddd_shutdown();
		exit(1);
	}
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, PF_UNSPEC, &cfg->my_imsg[MY_IMSG_NOTIFY].imsg_fds[0]) < 0) {
		dolog(LOG_INFO, "socketpair() failed\n");
		ddd_shutdown();
		exit(1);
	}


	pid = fork();
	switch (pid) {
	case -1:
		dolog(LOG_ERR, "fork(): %s\n", strerror(errno));
		ddd_shutdown();
		exit(1);
	case 0:
		ibuf = register_cortex(cortex, MY_IMSG_AXFR_ACCEPT);
		close(cortex->fd);
		
		close(cfg->my_imsg[MY_IMSG_ACCEPT].imsg_fds[1]);
		imsg_init(&accept_ibuf, cfg->my_imsg[MY_IMSG_ACCEPT].imsg_fds[0]);
		close(cfg->my_imsg[MY_IMSG_NOTIFY].imsg_fds[1]);
		imsg_init(&notify_ibuf, cfg->my_imsg[MY_IMSG_NOTIFY].imsg_fds[0]);
		setproctitle("AXFR accept engine on port %d", axfrport);
		axfr_acceptloop(cfg, &accept_ibuf, &notify_ibuf, ibuf);
		/* NOTREACHED */
		exit(1);
	default:
		/* close the tcp descriptors we don't need them anymore */
		for (i = 0; i < cfg->sockcount; i++)  {
				close(cfg->axfrt[i]);
				//close(cfg->axfr[i]);
		}

		close(cfg->my_imsg[MY_IMSG_ACCEPT].imsg_fds[0]);
		imsg_init(&accept_ibuf, cfg->my_imsg[MY_IMSG_ACCEPT].imsg_fds[1]);
		close(cfg->my_imsg[MY_IMSG_NOTIFY].imsg_fds[0]);
		imsg_init(&notify_ibuf, cfg->my_imsg[MY_IMSG_NOTIFY].imsg_fds[1]);
		break;
	}

#if __OpenBSD__
        if (pledge("stdio proc sendfd recvfd", NULL) == -1) {
                dolog(LOG_ERR, "pledge %s", strerror(errno));
                exit(1);
        }
#endif

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
			notifyfd[0] = request_socket(&notify_ibuf, IMSG_NOTIFY4_MESSAGE);
			notifyfd[1] = request_socket(&notify_ibuf, IMSG_NOTIFY6_MESSAGE);

			if (notifyfd[0] == -1 || notifyfd[1] == -1)
				dolog(LOG_INFO, "notifyfd's were -1\n");


			if (notifyfd[0] != -1 && notifyfd[1] != -1)
				notifyddds(&notify_ibuf, (int *)&notifyfd);
		}
	}


	for (;;) {

		FD_ZERO(&rset);
		maxso = 0;

		if (maxso < cfg->my_imsg[MY_IMSG_ACCEPT].imsg_fds[1])
			maxso = cfg->my_imsg[MY_IMSG_ACCEPT].imsg_fds[1];

		FD_SET(cfg->my_imsg[MY_IMSG_ACCEPT].imsg_fds[1], &rset);

#if 0
		/* this is the cortex descriptor */
		FD_SET(ibuf->fd, &rset);
		if (ibuf->fd > maxso)
			maxso = ibuf->fd;
#endif
		
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

				close(notify_ibuf.fd);

				/*
				 * we are done sending descriptors so update
				 * the pledge losing "sendfd"
				 */
#if __OpenBSD__
				if (pledge("stdio proc recvfd", NULL) == -1) {
					dolog(LOG_ERR, "pledge %s", strerror(errno));
					ddd_shutdown();
					exit(1);
				}
#endif

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
					notifyddds(&notify_ibuf, (int *)&notifyfd);
				}

			}
		
			continue;
		}
		if (sel < 0) {
			if (errno != EINTR)
				dolog(LOG_INFO, "select: %s\n", strerror(errno));
			continue;
		}

		if (FD_ISSET(cfg->my_imsg[MY_IMSG_ACCEPT].imsg_fds[1], &rset)) {
			acceptmsg = accept_from_loop(&accept_ibuf, (char *)&address, \
				sizeof(address), &is_ipv6, &axfr_acl, &idx, \
				&so, &sin, &sin6);
			if (acceptmsg == NULL) {
				dolog(LOG_INFO, "accept_from_loop: %s\n", strerror(errno));
				continue;
			}
			if (! axfr_acl)	{
				dolog(LOG_INFO, "connection from %s was not in our axfr acl, drop\n", address);
				close(so);
				continue;
			 }

			for (x = 0; x < cfg->sockcount; x++) {
				if (strcasecmp(address, ident[x]) == 0) {
					idx = x;
					break;
				}
			}

			/* last resort this could be wrong */
			if (x == cfg->sockcount)
				idx = 0;

			dolog(LOG_INFO, "AXFR connection from %s on interface \"%s\"\n", address, ident[idx]);
			/* and then we fork ... */
			switch (pid = fork()) {
			case 0:
				axfr_connection(so, address, is_ipv6, db, acceptmsg->packet, acceptmsg->packetlen);
				exit(0);
				/*NOTREACHED*/	
			default:
				close(so);
				free(acceptmsg);
				break;
			}

		} /* if(FD_ISSET..) */

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

	/* NOTREACHED */
}

/*
 * AXFR_CONNECTION - this is the main core of AXFR engine, forked
 *
 */

void
axfr_connection(int so, char *address, int is_ipv6, ddDB *db, char *packet, int packetlen)
{

	char *buf;
	char tsigkey[512];
	char *p, *q;
	char *reply, *replybuf;

	int len, dnslen = 0;
	int offset = 0;
	int qlen;
	int outlen;
	int rrcount;
	int envelopcount;
	int tsigkeylen;

	struct zoneentry find, *res;
	struct dns_header *dh, *odh;
	struct sreply sreply;
	struct question *question, *fq;
	struct rbtree *rbt = NULL, *rbt2 = NULL, *soa = NULL;
	struct rrset *rrset = NULL;

	ddDBT key, data;
	DDD_HMAC_CTX *tsigctx = NULL;
	DDD_EVP_MD *md = NULL;
		

	md = (DDD_EVP_MD *)delphinusdns_EVP_get_digestbyname("sha256");
	if (md == NULL) {
		dolog(LOG_ERR, "md initialization error, drop\n");
		close(so);
		exit(1);
	}

#define DDD_AXFR_RECBUF	(0xffff + 3)

	if ((buf = calloc(1, DDD_AXFR_RECBUF)) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		close(so);
		exit(1);
	}

	p = &buf[0];

	if ((replybuf = calloc(1, 0xffff + 3)) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		close(so);
		exit(1);
	}
		

	if (packetlen > DDD_AXFR_RECBUF) {
		dolog(LOG_ERR, "buffer size of buf is smaller than given packet, drop\n");
		close(so);
		exit(1);
	}

	for (;;) {
		if (packetlen == 0) {
			len = recv(so, p + offset, DDD_AXFR_RECBUF - offset, 0);
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

		question->aa = 1;

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

		if (have_zone(q, qlen) != 1) {
			dolog(LOG_INFO, "%s not in our list of zones, drop\n",
				question->converted_name);
			goto drop;
		}

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
			outlen = build_header(db, (reply + 2), (p + 2), question, 1, 1);
			outlen = build_soa(db, (reply + 2), outlen, soa, question);
			if (question->tsig.tsigverified == 1) {
				struct dns_header *odh;

				odh = (struct dns_header *)&reply[2];
				outlen = additional_tsig(question, (reply + 2), 0xffff, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);
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

			tsigctx = delphinusdns_HMAC_CTX_new();
			if (tsigctx == NULL) {
				dolog(LOG_ERR, "delphinusdns_HMAC_CTX_new()\n");
				goto drop;
			}
		
			if (delphinusdns_HMAC_Init_ex(tsigctx, (const void *)&tsigkey, tsigkeylen, md, NULL) == 0) {
				dolog(LOG_ERR, "AXFR tsig initialization error, drop\n");
				goto drop;
			}
		} else {
			if (strictaxfr) {
				dolog(LOG_ERR, "%s request for zone \"%s\","\
					" not authenticated, drop\n", \
					(ntohs(question->hdr->qtype) == \
						DNS_TYPE_AXFR ? "AXFR" \
					: "IXFR"), question->converted_name);

				goto drop;
			}
		}

		dolog(LOG_INFO, "%s request for zone \"%s\", replying...\n", 
			(ntohs(question->hdr->qtype) == DNS_TYPE_AXFR ? "AXFR"
				: "IXFR"), question->converted_name);


		outlen = build_header(db, (reply + 2), (p + 2), question, 0, 1);
		outlen = build_soa(db, (reply + 2), outlen, soa, question);
		rrcount = 1;
		envelopcount = 1;

		memcpy(find.name, q, qlen);
		find.namelen = qlen;

		if ((res = RB_FIND(zonetree, &zonehead, &find)) == NULL) {
			dolog(LOG_INFO, "internal error getting zonename\n");
			goto drop;
		}

		TAILQ_FOREACH(wep, &res->walkhead, walk_entry) {
			rbt = wep->rbt;

			if (checklabel(db, rbt, soa, question)) {
				fq = build_fake_question(rbt->zone, rbt->zonelen, 0, NULL, 0);
				fq->aa = 1;
				build_reply(&sreply, so, (p + 2), dnslen, fq, NULL, 0, rbt, NULL, 0xff, 1, 0, replybuf);
				
				outlen = create_anyreply(&sreply, (reply + 2), 65535, outlen, 0, res->zonenumber, 0);
				free_question(fq);
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

					outlen = additional_tsig(question, (reply + 2), 65000, outlen, 0, envelopcount, tsigctx, DEFAULT_TSIG_FUDGE);
					if (tmplen != outlen) {
						odh->additional = htons(1);

						delphinusdns_HMAC_CTX_reset(tsigctx);
						if (delphinusdns_HMAC_Init_ex(tsigctx, (const void *)&tsigkey, tsigkeylen, md, NULL) == 0) {
							dolog(LOG_ERR, "AXFR tsig initialization error 2, drop\n");
							goto drop;
						}

					} 

					pack16(reply, htons(outlen));

					envelopcount++;

				}

				len = send(so, reply, outlen + 2, 0);
				if (len <= 0) {
					goto drop;
				}
			
				rrcount = 0;
				outlen = build_header(db, (reply + 2), (p + 2), question, 0, primary_axfr_old_behaviour ? 1 : 0);
			}

			memset(&key, 0, sizeof(key));	
			memset(&data, 0, sizeof(data));
			if (rbt) {
				rbt = NULL;
			}
			if (rbt2) {
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

			outlen = additional_tsig(question, (reply + 2), 65000, outlen, 0, envelopcount, tsigctx, DEFAULT_TSIG_FUDGE);
			odh->additional = htons(1);

			pack16(reply, htons(outlen));

			delphinusdns_HMAC_CTX_free(tsigctx);
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
		rbt = NULL;
	}
	
	if (rbt2) {
		rbt2 = NULL;
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
build_header(ddDB *db, char *reply, char *buf, struct question *q, int answercount, int questioncount)
{
	struct dns_header *odh;
	uint16_t outlen;

	odh = (struct dns_header *)reply;
	outlen = sizeof(struct dns_header);

	if (questioncount) {
		/* copy question to reply */
		memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
		outlen += (q->hdr->namelen + 4);
	}

	/* blank query */
	memset((char *)&odh->query, 0, sizeof(uint16_t));

	SET_DNS_REPLY(odh);
	SET_DNS_AUTHORITATIVE(odh);
	
	/* XXX */
	HTONS(odh->query);

	if (questioncount)
		odh->question = htons(1);
	else
		odh->question = 0;

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
	char *label;
	char *plabel;
		
	int labellen;
	int tmplen;

        struct answer {
                uint16_t type;
                uint16_t class;
                uint32_t ttl;
                uint16_t rdlength;      /* 12 */
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
	
	pack(&reply[offset], q->hdr->name, q->hdr->namelen);
	offset += q->hdr->namelen;

	answer = (struct answer *)(&reply[offset]);

	answer->type = htons(DNS_TYPE_SOA);
	answer->class = htons(DNS_CLASS_IN);
	answer->ttl = htonl(rrset->ttl);

	offset += 10;			/* up to rdata length */

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
	if ((offset + sizeof(uint32_t)) >= 65535 ) {
		/* XXX server error reply? */
		return (offset);
	}
	pack32(&reply[offset], htonl(((struct soa *)rrp->rdata)->serial));
	offset += sizeof(uint32_t);
	
	if ((offset + sizeof(uint32_t)) >= 65535 ) {
		return (offset);
	}
	pack32(&reply[offset], htonl(((struct soa *)rrp->rdata)->refresh));
	offset += sizeof(uint32_t);

	if ((offset + sizeof(uint32_t)) >= 65535 ) {
		return (offset);
	}
	pack32(&reply[offset], htonl(((struct soa *)rrp->rdata)->retry));
	offset += sizeof(uint32_t);

	if ((offset + sizeof(uint32_t)) >= 65535 ) {
		return (offset);
	}
	pack32(&reply[offset], htonl(((struct soa *)rrp->rdata)->expire));
	offset += sizeof(uint32_t);

	if ((offset + sizeof(uint32_t)) > 65535 ) {
		return (offset);
	}
	pack32(&reply[offset], htonl(((struct soa *)rrp->rdata)->minttl));
	offset += sizeof(uint32_t);

	answer->rdlength = htons(&reply[offset] - &answer->rdata);
	
	return (offset);
}

int
checklabel(ddDB *db, struct rbtree *rbt, struct rbtree *soa, struct question *q)
{
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

			notn2->ids = calloc(notify, sizeof(uint16_t));
			if (notn2->ids == NULL) {
				free(notn2);
				continue;
			}

			notn2->attempts = calloc(notify, sizeof(uint16_t));
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
notifyddds(struct imsgbuf *ibuf, int *notifyfd)
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

			notnp->ids[i] = arc4random_uniform(0xffff);
			notnp->attempts[i]++;
			if (notnp->attempts[i] > 10) {
				dolog(LOG_INFO, "notify entry removed due to timeout\n");
				remove = 1;
				break;
			} 

			if (md->notified == 1)
				notifypacket(ibuf, so, notnp, md, i);

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
notifypacket(struct imsgbuf *ibuf, int so, void *vnotnp, void *vmd, int packetcount)
{
	struct notifyentry *notnp = (struct notifyentry *)vnotnp;
	struct mzone *mz = (struct mzone *)notnp->mzone;
	struct mzone_dest *md = (struct mzone_dest *)vmd;
	struct sockaddr_in bsin;
	struct sockaddr_in6 bsin6;
	struct sockaddr_storage newsin;
	char packet[512];
	char *questionname;
	uint16_t *classtype;
	struct dns_header *dnh;
	struct question *fq = NULL;
	int outlen = 0, slen;
	int af = md->notifydest.ss_family;
	
	memcpy(&newsin, (char *)&mz->notifybind, sizeof(struct sockaddr_storage));
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
	
	classtype = (uint16_t *)&packet[outlen];
	classtype[0] = htons(DNS_TYPE_SOA);
	classtype[1] = htons(DNS_CLASS_IN);

	outlen += (2 * sizeof(uint16_t));

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
	
		outlen = additional_tsig(fq, packet, sizeof(packet), outlen, 1, 0, NULL, DEFAULT_TSIG_FUDGE);

		dnh->additional = htons(1);

		memcpy(&md->requestmac, fq->tsig.tsigmac, 32);
		notnp->usetsig = 1;
		
		free(tsigname);
		free_question(fq);
	} else {
		notnp->usetsig = 0;
	}

	if (af == AF_INET) {
		struct sockaddr_in *tmpsin = (struct sockaddr_in *)&md->notifydest;

		slen = sizeof(struct sockaddr_in);
		memset(&bsin, 0, sizeof(bsin));
		bsin.sin_family = AF_INET;
		bsin.sin_port = htons(md->port);
		bsin.sin_addr.s_addr = tmpsin->sin_addr.s_addr;

		so = sendforme(ibuf, so, packet, outlen, (struct sockaddr *)&bsin, slen);
		if (so == -1) {
			dolog(LOG_INFO, "sendforme failed, we seem to have lost our descriptor!\n");
		}
	} else {
		struct sockaddr_in6 *tmpsin = (struct sockaddr_in6 *)&md->notifydest;

		slen = sizeof(struct sockaddr_in6);
		memset(&bsin6, 0, sizeof(bsin6));
		bsin6.sin6_family = AF_INET6;
		bsin6.sin6_port = htons(md->port);
#ifndef __linux__
		bsin6.sin6_len = sizeof(struct sockaddr_in6);
#endif
		memcpy(&bsin6.sin6_addr, &tmpsin->sin6_addr, 16);

		so = sendforme(ibuf, so, packet, outlen, (struct sockaddr *)&bsin6, slen);
		if (so == -1) {
			dolog(LOG_INFO, "sendforme failed, we seem to have lost our descriptor!\n");
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
	uint16_t ntohsquery;

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


struct axfr_acceptmsg *
accept_from_loop(struct imsgbuf *a_imsgbuf, char *address, int asz, int *ip6, int *acl, int *idx, int *so, struct sockaddr_in **sin, struct sockaddr_in6 **sin6)
{
	size_t n, datalen;
	struct imsg a_imsg;
	static struct sockaddr_storage from;
	struct axfr_acceptmsg *acceptmsg;

	acceptmsg = (struct axfr_acceptmsg *)calloc(1, sizeof(struct axfr_acceptmsg));
	if (acceptmsg == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		ddd_shutdown();
		exit(1);
	}

	if (((n = imsg_read(a_imsgbuf)) == -1 && errno != EAGAIN) || n == 0) {
		dolog(LOG_INFO, "got error from TCP accept child, it likely died, exit\n");
		ddd_shutdown();
		exit(1);
	}

	for (;;) {
		if ((n = imsg_get(a_imsgbuf, &a_imsg)) == -1) {
			free(acceptmsg);
			return NULL;
		}

		if (n == 0) {
			free(acceptmsg);
			return NULL;
		}

		datalen = a_imsg.hdr.len - IMSG_HEADER_SIZE;
		if (datalen != sizeof(struct axfr_acceptmsg)) {
			dolog(LOG_INFO, "wrong sized acceptmsg, continuing...\n");
			free(acceptmsg);
			return NULL;
		}	

		memcpy((char *)acceptmsg, (char *)a_imsg.data, datalen);

		strlcpy((char *)address, (char *)acceptmsg->address, asz);
		memcpy((char *)&from, (char *)&acceptmsg->from, sizeof(struct sockaddr_storage));

		if (acceptmsg->af == AF_INET) {
			*sin = (struct sockaddr_in *)&from;
			*ip6 = 0;
		} else {
			*sin6 = (struct sockaddr_in6 *)&from;
			*ip6 = 1;
		}

		*acl = unpack32((char *)&acceptmsg->axfr_acl);
		*idx = unpack32((char *)&acceptmsg->intidx);
		*so = a_imsg.fd;

		break;
	}

	return (acceptmsg);
}


int
axfr_acceptloop(struct cfg *cfg, struct imsgbuf *ibuf, struct imsgbuf *notify_ibuf, struct imsgbuf *cortex)
{
	int maxso;
	int i = 0, sel, so;
	int passlist = 0, blocklist = 0;
	int filter = 0, require_tsig = 0, axfr_acl = 0;
	int aregion;
	fd_set rset;
	char address[INET6_ADDRSTRLEN];
	struct axfr_acceptmsg *acceptmsg;
	struct imsg imsg;
	size_t datalen;

	socklen_t fromlen = sizeof(struct sockaddr_storage);

	struct sockaddr_storage ss;
	struct sockaddr *from = (void *)&ss;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	char *packet;
	int packetlen;
	int tcpflags;
	int dummy = 42;
	int nomore_notifies = 0;

	size_t n;

	packet = calloc(1, 65535 + 3);
	if (packet == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		ddd_shutdown();
		exit(1);
	}
	acceptmsg = (struct axfr_acceptmsg *)calloc(1, sizeof(struct axfr_acceptmsg));
	if (acceptmsg == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		ddd_shutdown();
		exit(1);
	}

#if __OpenBSD__
	if (pledge("stdio inet sendfd recvfd", NULL) == -1) {
		perror("pledge");
		ddd_shutdown();
		exit(1);
	}
#endif
	
	
	for (i = 0; i < cfg->sockcount; i++) {
		listen(cfg->axfrt[i], 5);
	}

	for (;;) {
		maxso = 0;

		FD_ZERO(&rset);
		for (i = 0; i < cfg->sockcount; i++)  {
			if (maxso < cfg->axfrt[i])
				maxso = cfg->axfrt[i];
	
			FD_SET(cfg->axfrt[i], &rset);
		}

		FD_SET(cortex->fd, &rset);
		if (maxso < cortex->fd)
			maxso = cortex->fd;

		if (nomore_notifies == 0) {
			FD_SET(notify_ibuf->fd, &rset);
			if (maxso < notify_ibuf->fd)
				maxso = notify_ibuf->fd;
		}

		sel = select(maxso + 1, &rset, NULL, NULL, NULL);

		if (sel <= 0) {
			dolog(LOG_INFO, "select: %s\n", strerror(errno));
			continue;
		}

		for (i = 0; i < cfg->sockcount; i++) {
			if (FD_ISSET(cfg->axfrt[i], &rset)) {
				fromlen = sizeof(struct sockaddr_storage);
				memset(acceptmsg, 0, sizeof(struct axfr_acceptmsg));

				so = accept(cfg->axfrt[i], (struct sockaddr*)from, &fromlen);
		
				if (so < 0) {
					dolog(LOG_INFO, "axfr accept: %s\n", strerror(errno));
					continue;
				}

				SEND_TO_PARENT;
			}
		}

		if (FD_ISSET(cortex->fd, &rset)) {
			if ((n = imsg_read(cortex)) < 0 && errno != EAGAIN) {
				dolog(LOG_ERR, "imsg read failure %s\n", strerror(errno));
				continue;
			}

			if (n == 0) {
				/* child died? */
				dolog(LOG_INFO, "sigpipe on child? AXFR process exiting.\n");
				exit(1);
			}

			for(;;) {
				if ((n = imsg_get(cortex, &imsg)) < 0) {
					dolog(LOG_ERR, "imsg read error: %s\n", strerror(errno));
					break;
				} else {
					if (n == 0)
						break;
					packetlen = imsg.hdr.len - IMSG_HEADER_SIZE;

					switch (imsg.hdr.type) {
					case IMSG_XFR_MESSAGE:
						dolog(LOG_INFO, "received xfr via message passing\n");

						so = imsg.fd;

						if (packetlen > sizeof(acceptmsg->packet)) {
							dolog(LOG_INFO, "packetlen is too large, won't fit\n");
							close(so);
							break;
						}
							
						memcpy(packet, imsg.data, packetlen);

						if ((tcpflags = fcntl(so, F_GETFL, 0)) < 0) {
							dolog(LOG_INFO, "can't query fcntl flags\n");
							close(so);
							break;
						}

						/* turn off nonblocking */	
						tcpflags &= ~O_NONBLOCK;

						if (fcntl(so, F_SETFL, tcpflags) < 0) {
							dolog(LOG_INFO, "can't turn off non-blocking\n");
							close(so);
							break;
						}
						
						memset((char *)from, 0, sizeof(struct sockaddr_storage));
						fromlen = sizeof(struct sockaddr_storage);
						if (getpeername(so, (struct sockaddr *)from, &fromlen) < 0) {
							dolog(LOG_ERR, "getpeername: %s\n", strerror(errno));
							close(so);
							break;
						}
		
						if (from->sa_family == AF_INET)
							i = 0;
						else
							i = 1;

						memcpy(acceptmsg->packet, packet, packetlen);
						acceptmsg->packetlen = packetlen;

						SEND_TO_PARENT;
						break;
					} /* switch */
					imsg_free(&imsg);
				} /* else */
			} /* for (;;) */
		} /* if (FD_ISSET..) */

		if (FD_ISSET(notify_ibuf->fd, &rset)) {
			if ((n = imsg_read(notify_ibuf)) < 0 && errno != EAGAIN) {
				dolog(LOG_ERR, "2 imsg read failure %s\n", strerror(errno));
				continue;
			}

			if (n == 0) {
				/* child died? */
				dolog(LOG_INFO, "NOTIFY imsg descriptor closing\n");
				close(notify_ibuf->fd);
				nomore_notifies = 1;
				continue;
			}

			for(;;) {
				if ((n = imsg_get(notify_ibuf, &imsg)) < 0) {
					dolog(LOG_ERR, "imsg read error: %s\n", strerror(errno));
					break;
				} else {
					if (n == 0)
						break;

					datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
					switch (imsg.hdr.type) {
					case IMSG_NOTIFY4_MESSAGE:
						if (nomore_notifies == 1)
							break;

						so = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
						if (so == -1) {
							dolog(LOG_INFO, "socket: %s\n", strerror(errno));
						}
						memset((char *)from, 0, sizeof(ss));
						sin = (struct sockaddr_in *)from;
						sin->sin_family = AF_INET;
						sin->sin_port = htons(0);
						if (bind(so, (struct sockaddr *)sin, sizeof(*sin)) < 0) {
							dolog(LOG_INFO, "bind notify: %s\n", strerror(errno));
						}
						imsg_compose(notify_ibuf, IMSG_NOTIFY4_MESSAGE, 0, 0, so, &dummy, sizeof(int));
						msgbuf_write(&notify_ibuf->w);
						break;

					case IMSG_NOTIFY6_MESSAGE:
						if (nomore_notifies == 1)
							break;

						so = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
						if (so == -1) {
							dolog(LOG_INFO, "socket: %s\n", strerror(errno));
						}
						memset((char *)from, 0, sizeof(ss));
						sin6 = (struct sockaddr_in6 *)from;
						sin6->sin6_family = AF_INET6;
						sin6->sin6_port = htons(0);
#ifndef __linux__
						sin6->sin6_len = sizeof(struct sockaddr_in6);
#endif
						if (bind(so, (struct sockaddr *)sin6, sizeof(*sin6)) < 0) {
							dolog(LOG_INFO, "bind notify6: %s\n", strerror(errno));
						}

						imsg_compose(notify_ibuf, IMSG_NOTIFY6_MESSAGE, 0, 0, so, &dummy, sizeof(int));
						msgbuf_write(&notify_ibuf->w);
						break;
					case IMSG_SENDFORME_MESSAGE:
						if (nomore_notifies == 1)
							break;

						if (datalen != sizeof(struct axfr_acceptmsg)) {
							dolog(LOG_INFO, "datalen does not equal sizeof(struct axfr_acceptmsg)\n");
							break;
						}
						memcpy ((char *)acceptmsg, (char *)imsg.data, datalen);
						so = imsg.fd;
		
						if (unpack32((char *)&acceptmsg->af) == AF_INET) {
							if (sendto(so, (char *)&acceptmsg->packet, unpack32((char *)&acceptmsg->packetlen), 0, (struct sockaddr *)&acceptmsg->from, sizeof(struct sockaddr_in)) < 0)
								dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
						} else if (acceptmsg->af == AF_INET6) {
							if (sendto(so, (char *)&acceptmsg->packet, unpack32((char *)&acceptmsg->packetlen), 0, (struct sockaddr *)&acceptmsg->from, sizeof(struct sockaddr_in6)) < 0)
								dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
						} else {
							dolog(LOG_INFO, "unknown af %d\n", acceptmsg->af);
						}
					

						/* and pass it back */
						imsg_compose(notify_ibuf, IMSG_SENDFORME_MESSAGE, 0, 0, so, &dummy, sizeof(int));
						msgbuf_write(&notify_ibuf->w);
						break;
					} /* switch */
				} /* else */
			} /* for(;;) */

		} /* FD_ISSET */
cont:
		continue;

	} 	/* for (;;)  */

	/* NOTREACHED */
}

int
request_socket(struct imsgbuf *ibuf, int code)
{
	int maxso, sel;
	fd_set rset;
	struct timeval tv;
	struct imsg imsg;
	int so;
	int dummy = 42;
	size_t n;

	imsg_compose(ibuf, code, 0, 0, -1, &dummy, sizeof(int));
	msgbuf_write(&ibuf->w);

	for (;;) {
		FD_ZERO(&rset);

		FD_SET(ibuf->fd, &rset);
		if (maxso < ibuf->fd)
			maxso = ibuf->fd;

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		sel = select(maxso + 1, &rset, NULL, NULL, &tv);

		if (sel == 0) {
			dolog(LOG_INFO, "select: %s\n", strerror(errno));
			break;
		}
		if ((n = imsg_read(ibuf)) < 0 && errno != EAGAIN) {
			dolog(LOG_ERR, "2 imsg read failure %s\n", strerror(errno));
			continue;
		}

		if (n == 0) {
			/* child died? */
			dolog(LOG_INFO, "sigpipe on child? AXFR process exiting.\n");
			exit(1);
		}

		if ((n = imsg_get(ibuf, &imsg)) < 0) {
			dolog(LOG_ERR, "imsg read error: %s\n", strerror(errno));
			return -1;
		} else {
			if (n == 0)
				break;

			switch (imsg.hdr.type) {
			case IMSG_NOTIFY4_MESSAGE:
				so = imsg.fd;
				break;
			case IMSG_NOTIFY6_MESSAGE:
				so = imsg.fd;
				break;
			}
		}

		imsg_free(&imsg);
		return (so);
	}

	return (-1);
}

int
sendforme(struct imsgbuf *ibuf, int so, char *packet, int outlen, struct sockaddr *sa, int slen) 
{
	int maxso, sel;
	fd_set rset;
	struct timeval tv;
	size_t n;
	struct imsg imsg;
	struct axfr_acceptmsg *acceptmsg;

	if ((acceptmsg = (void *)calloc(1, sizeof(struct axfr_acceptmsg))) == NULL)
		return (so);

	if (outlen > sizeof(acceptmsg->packet)) {
		free(acceptmsg);
		return (so);
	}

	memcpy(acceptmsg->packet, packet, outlen);
	pack32((char *)&acceptmsg->packetlen, outlen);

	pack32((char *)&acceptmsg->af, sa->sa_family);

	memcpy((char *)&acceptmsg->from, (char *)sa, slen);
	pack32((char *)&acceptmsg->fromlen, slen);

	imsg_compose(ibuf, IMSG_SENDFORME_MESSAGE, 0, 0, so, (char *)acceptmsg, sizeof(struct axfr_acceptmsg));
	msgbuf_write(&ibuf->w);

	free(acceptmsg);

	for (;;) {
		FD_ZERO(&rset);

		FD_SET(ibuf->fd, &rset);
		if (maxso < ibuf->fd)
			maxso = ibuf->fd;

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		sel = select(maxso + 1, &rset, NULL, NULL, &tv);

		if (sel == 0) {
			dolog(LOG_INFO, "select: %s\n", strerror(errno));
			break;
		}

		if ((n = imsg_read(ibuf)) < 0 && errno != EAGAIN) {
			dolog(LOG_ERR, "2 imsg read failure %s\n", strerror(errno));
			continue;
		}

		if (n == 0) {
			/* child died? */
			dolog(LOG_INFO, "sigpipe on child? AXFR process exiting.\n");
			exit(1);
		}

		if ((n = imsg_get(ibuf, &imsg)) < 0) {
			dolog(LOG_ERR, "imsg read error: %s\n", strerror(errno));
			return -1;
		} else {
			if (n == 0)
				break;

			switch (imsg.hdr.type) {
			case IMSG_SENDFORME_MESSAGE:
				so = imsg.fd;
				break;
			default:
				dolog(LOG_INFO, "wrong message %d\n", imsg.hdr.type);
				break;
			}
		}

		imsg_free(&imsg);
		return (so);
	}

	return (-1);
}
