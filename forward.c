/*
 * Copyright (c) 2020 Peter J. Philipp
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
 * $Id: forward.c,v 1.22 2020/07/13 22:02:26 pjp Exp $
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/select.h>
#include <sys/mman.h>
#include <sys/resource.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>

#include <unistd.h>
#include <fcntl.h>

#ifdef __linux__
#include <grp.h>
#define __USE_BSD 1
#include <endian.h>
#include <bsd/stdlib.h>
#include <bsd/string.h>
#include <bsd/unistd.h>
#include <bsd/sys/queue.h>
#define __unused
#include <bsd/sys/tree.h>
#include <bsd/sys/endian.h>
#include "imsg.h"
#else /* not linux */
#include <sys/queue.h>
#include <sys/tree.h>
#ifdef __FreeBSD__
#include <sys/endian.h>
#include "imsg.h"
#else
#include <imsg.h>
#endif /* __FreeBSD__ */
#endif /* __linux__ */

#ifndef NTOHS
#include "endian.h"
#endif

#include <openssl/hmac.h>

#include "ddd-dns.h"
#include "ddd-db.h"

TAILQ_HEAD(forwardentrys, forwardentry) forwardhead;

struct forwardentry {
	char name[INET6_ADDRSTRLEN];
	int family;
	struct sockaddr_storage host;
	uint16_t destport;
	char *tsigkey;
	int active;
	TAILQ_ENTRY(forwardentry) forward_entry;
} *fw2, *fwp;

SLIST_HEAD(, forwardqueue) fwqhead;

struct forwardqueue {
	uint32_t longid;			/* a long identifier */
	time_t time;				/* time created */
	struct sockaddr_storage host;		/* remote host to query */
	uint16_t id;				/* new id to query */
	uint16_t port;				/* remote port to query */
	struct sockaddr_in oldhost4;		/* old v4 host source */
	struct sockaddr_in6 oldhost6;		/* old v6 host source */
	uint16_t oldid;				/* old id source */
	uint16_t oldport;			/* the old port */
	int oldfamily;				/* old family */
	int oldsel;				/* this indicates which sock */
	int so;					/* open connected socket */
	int returnso;				/* return socket (TCP) */
	int istcp;				/* whether we're tcp */
	int family;				/* our family */
	char *tsigkey;				/* which key we use for query */
	uint64_t tsigtimefudge;			/* passed tsigtimefudge */
	char mac[32];				/* passed mac from query */
	int haveoldmac;				/* do we have an old mac? */
	char oldkeyname[256];			/* old key name */
	int oldkeynamelen;			/* old key name len */
	char oldmac[32];			/* old mac */
	struct forwardentry *cur_forwardentry;	/* current forwardentry */
	int dnssecok;				/* DNSSEC in anwers */
	SLIST_ENTRY(forwardqueue) entries;	/* next entry */
} *fwq1, *fwq2, *fwqp;

void	init_forward(void);
int	insert_forward(int, struct sockaddr_storage *, uint16_t, char *);
void	forwardloop(ddDB *, struct cfg *, struct imsgbuf *, struct imsgbuf *);
void	forwardthis(ddDB *, struct cfg *, int, struct sforward *);
void	sendit(struct forwardqueue *, struct sforward *);
void	returnit(ddDB *, struct cfg *, struct forwardqueue *, char *, int, struct imsgbuf *);
struct tsig * check_tsig(char *, int, char *);
void	fwdparseloop(struct imsgbuf *, struct imsgbuf *, struct cfg *);
void	changeforwarder(struct forwardqueue *);
void 	stirforwarders(void);

extern void 	dolog(int, char *, ...);
extern void      pack(char *, char *, int);
extern void     pack16(char *, u_int16_t);
extern void     pack32(char *, u_int32_t);
extern uint16_t unpack16(char *);
extern uint32_t unpack32(char *);
extern void     ddd_shutdown(void);
extern int      additional_opt(struct question *, char *, int, int);
extern int      additional_tsig(struct question *, char *, int, int, int, int, HMAC_CTX *);
extern struct question	*build_question(char *, int, int, char *);
extern struct question	*build_fake_question(char *, int, u_int16_t, char *, int);
extern int	free_question(struct question *);
extern char *	dns_label(char *, int *);
extern int	find_tsig_key(char *, int, char *, int);
extern int	memcasecmp(u_char *, u_char *, int);
extern char *	expand_compression(u_char *, u_char *, u_char *, u_char *, int *, int);
extern int	expire_rr(ddDB *, char *, int, u_int16_t, time_t);
extern int 	expire_db(ddDB *, int);
extern void 	build_reply(struct sreply *, int, char *, int, struct question *, struct sockaddr *, socklen_t, struct rbtree *, struct rbtree *, u_int8_t, int, int, char *);
extern struct rbtree * Lookup_zone(ddDB *, char *, int, int, int);
extern struct rbtree *  lookup_zone(ddDB *, struct question *, int *, int *, char *, int);
extern char *convert_name(char *, int);
extern int	cacheit(u_char *, u_char *, u_char *, struct imsgbuf *, struct imsgbuf *, struct cfg *);

extern int 	reply_a(struct sreply *, ddDB *);
extern int 	reply_aaaa(struct sreply *, ddDB *);
extern int 	reply_any(struct sreply *, ddDB *);
extern int 	reply_cname(struct sreply *, ddDB *);
extern int	reply_notify(struct sreply *, ddDB *);
extern int 	reply_soa(struct sreply *, ddDB *);
extern int 	reply_mx(struct sreply *, ddDB *);
extern int 	reply_naptr(struct sreply *, ddDB *);
extern int 	reply_ns(struct sreply *, ddDB *);
extern int 	reply_ptr(struct sreply *, ddDB *);
extern int 	reply_srv(struct sreply *, ddDB *);
extern int 	reply_sshfp(struct sreply *, ddDB *);
extern int 	reply_tlsa(struct sreply *, ddDB *);
extern int 	reply_txt(struct sreply *, ddDB *);
extern int      reply_rrsig(struct sreply *, ddDB *);
extern int	reply_dnskey(struct sreply *, ddDB *);
extern int	reply_ds(struct sreply *, ddDB *);
extern int	reply_nsec(struct sreply *, ddDB *);
extern int	reply_nsec3(struct sreply *, ddDB *);
extern int	reply_nsec3param(struct sreply *, ddDB *);
extern struct rbtree * create_rr(ddDB *, char *, int, int, void *, uint32_t);
extern void flag_rr(struct rbtree *rbt);
extern struct rbtree * find_rrset(ddDB *, char *, int);

/*
 * XXX everything but txt and naptr, works...
 */

static struct reply_logic rlogic[] = {
	/* { DNS_TYPE_A, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname }, */
	/* { DNS_TYPE_A, DNS_TYPE_NS, BUILD_OTHER, reply_ns }, */
	{ DNS_TYPE_A, DNS_TYPE_A, BUILD_OTHER, reply_a },
	/* { DNS_TYPE_AAAA, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname }, */
	/* { DNS_TYPE_AAAA, DNS_TYPE_NS, BUILD_OTHER, reply_ns }, */
	{ DNS_TYPE_AAAA, DNS_TYPE_AAAA, BUILD_OTHER, reply_aaaa },
	{ DNS_TYPE_DNSKEY, DNS_TYPE_DNSKEY, BUILD_OTHER, reply_dnskey },
	{ DNS_TYPE_SOA, DNS_TYPE_SOA, BUILD_OTHER, reply_soa },
	{ DNS_TYPE_SOA, DNS_TYPE_NS, BUILD_OTHER, reply_ns },
	/* { DNS_TYPE_MX, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname }, */
	/* { DNS_TYPE_MX, DNS_TYPE_NS, BUILD_OTHER, reply_ns }, */
	{ DNS_TYPE_MX, DNS_TYPE_MX, BUILD_OTHER, reply_mx },
	/* { DNS_TYPE_TXT, DNS_TYPE_TXT, BUILD_OTHER, reply_txt }, */
	{ DNS_TYPE_NS, DNS_TYPE_NS, BUILD_OTHER, reply_ns },
	{ DNS_TYPE_ANY, DNS_TYPE_ANY, BUILD_OTHER, reply_any },
	{ DNS_TYPE_DS, DNS_TYPE_DS, BUILD_OTHER, reply_ds },
	{ DNS_TYPE_SSHFP, DNS_TYPE_SSHFP, BUILD_OTHER, reply_sshfp },
	{ DNS_TYPE_TLSA, DNS_TYPE_TLSA, BUILD_OTHER, reply_tlsa },
	{ DNS_TYPE_SRV, DNS_TYPE_SRV, BUILD_OTHER, reply_srv },
	{ DNS_TYPE_CNAME, DNS_TYPE_CNAME, BUILD_OTHER, reply_cname },
	{ DNS_TYPE_CNAME, DNS_TYPE_NS, BUILD_OTHER, reply_ns },
	{ DNS_TYPE_NSEC3PARAM, DNS_TYPE_NSEC3PARAM, BUILD_OTHER, reply_nsec3param },
	/* { DNS_TYPE_PTR, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname }, */
	/* { DNS_TYPE_PTR, DNS_TYPE_NS, BUILD_OTHER, reply_ns }, */
	{ DNS_TYPE_PTR, DNS_TYPE_PTR, BUILD_OTHER, reply_ptr },
	/* { DNS_TYPE_NAPTR, DNS_TYPE_NAPTR, BUILD_OTHER, reply_naptr }, */
	{ DNS_TYPE_NSEC3, DNS_TYPE_NSEC3, BUILD_OTHER, reply_nsec3 },
	{ DNS_TYPE_NSEC, DNS_TYPE_NSEC, BUILD_OTHER, reply_nsec },
	{ DNS_TYPE_RRSIG, DNS_TYPE_RRSIG, BUILD_OTHER, reply_rrsig },
	{ 0, 0, 0, NULL }
};


extern int debug, verbose;
extern int tsig;
extern int dnssec;
extern int cache;
extern int forward;


/*
 * INIT_FORWARD - initialize the forward linked lists
 */

void
init_forward(void)
{
	TAILQ_INIT(&forwardhead);
	SLIST_INIT(&fwqhead);
	return;
}

/*
 * INSERT_FORWARD - insert into the forward slist
 */

int
insert_forward(int family, struct sockaddr_storage *ip, uint16_t port, char *tsigkey)
{
	static int active = 0;

	fw2 = calloc(1, sizeof(struct forwardentry));
	if (fw2 == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		return 1;
	}

	fw2->family = family;

	switch (fw2->family) {
	case AF_INET:
		inet_ntop(AF_INET, &((struct sockaddr_in *)ip)->sin_addr, fw2->name, sizeof(fw2->name));
		break;
	case AF_INET6:
		inet_ntop(AF_INET6, &((struct sockaddr_in6 *)ip)->sin6_addr, fw2->name, sizeof(fw2->name));
		break;
	}

	memcpy(&fw2->host, ip, sizeof(struct sockaddr_storage));
	fw2->destport = port;

	if (strcmp(tsigkey, "NOKEY") == 0)
		fw2->tsigkey = NULL;
	else {
		fw2->tsigkey = strdup(tsigkey);
		if (fw2->tsigkey == NULL) {
			dolog(LOG_INFO, "strdup: %s\n", strerror(errno));
			return 1;
		}
	}

	if (! active)
		fw2->active = 1;

	active = 1;
			
	TAILQ_INSERT_HEAD(&forwardhead, fw2, forward_entry);

	return (0);
}

void
forwardloop(ddDB *db, struct cfg *cfg, struct imsgbuf *ibuf, struct imsgbuf *cortex)
{
	struct timeval tv;
	struct imsg imsg;
	struct imsgbuf parse_ibuf, biparse_ibuf, *pibuf, *bpibuf;
	struct rr_imsg *ri;
	struct sf_imsg *sf;

	char *buf;
	char *rdata;
	struct rbtree *rbt = NULL;

	int max, sel;
	int len, need;
	int pi[2];
	int bipi[2];
	int i, count;
	u_int packetcount = 0;

	ssize_t n, datalen;
	fd_set rset;
	pid_t pid;

	char *ptr;
	time_t now, time0;

	ptr = cfg->shptr;

	forward = 0; 		/* in this process we don't need forward on */
	dolog(LOG_INFO, "FORWARD: expired %d records from non-forwarding DB\n",  expire_db(db, 1));

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, PF_UNSPEC, &pi[0]) < 0) {
		dolog(LOG_INFO, "socketpair() failed\n");
		ddd_shutdown();
		exit(1);
	}
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, PF_UNSPEC, &bipi[0]) < 0) {
		dolog(LOG_INFO, "socketpair() failed\n");
		ddd_shutdown();
		exit(1);
	}

	pid = fork();
	switch (pid) {
	case -1:
		dolog(LOG_INFO, "fork() failed\n");
		ddd_shutdown();
		exit(1);
	case 0:
		for (i = 0; i < cfg->sockcount; i++)
			close(cfg->dup[i]);

		close(ibuf->fd);
		close(cortex->fd);
		close(pi[1]);
		close(bipi[1]);
		imsg_init(&parse_ibuf, pi[0]);
		imsg_init(&biparse_ibuf, bipi[0]);
		
		setproctitle("forward parse engine");
		fwdparseloop(&parse_ibuf, &biparse_ibuf, cfg);
		/* NOTREACHED */

		break;
	default:
		close(pi[0]);
		close(bipi[0]);
		imsg_init(&parse_ibuf, pi[1]);
		imsg_init(&biparse_ibuf, bipi[1]);

		pibuf = &parse_ibuf;
		bpibuf = &biparse_ibuf;
		break;
	}

	buf = calloc(1, (0xffff + 2));
	if (buf == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		ddd_shutdown();
		exit(1);
	}

	for (;;) {
		/*
		 * due to our strategy (which kinda sucks) stir some
		 * entropy into the active forwarder
		 */
		if (packetcount++ && packetcount % 1000 == 0)
			stirforwarders();

		FD_ZERO(&rset);	
		FD_SET(ibuf->fd, &rset);
		if (ibuf->fd > max)
			max = ibuf->fd;
		FD_SET(bpibuf->fd, &rset);
		if (bpibuf->fd > max)
			max = bpibuf->fd;

		SLIST_FOREACH(fwq1, &fwqhead, entries) {
			if (fwq1->so > max)
				max = fwq1->so;
	
			FD_SET(fwq1->so, &rset);
		}

		/*
		 * set a timeout for idle periods, which we'll use to expire
	     * the db
		 */

		tv.tv_sec = 10;
		tv.tv_usec = 0;

		sel = select(max + 1, &rset, NULL, NULL, &tv);
		if (sel == -1) {	
			dolog(LOG_INFO, "select error\n");
			continue;
		}
		if (sel == 0) {
			if (cache) {
				time0 = time(NULL);
				count = expire_db(db, 0);

				now = time(NULL);
#if DEBUG
				dolog(LOG_INFO, "%f seconds spent in expire_db()\n", difftime(now, time0));
#endif
				if (count)
					dolog(LOG_INFO, "Forward CACHE expire_db: expired %d RR's\n", count);
			}
			continue;
		}

		
		time0 = time(NULL);
		SLIST_FOREACH_SAFE(fwq1, &fwqhead, entries, fwqp) {
			if (FD_ISSET(fwq1->so, &rset)) {
				if (fwq1->istcp) {
					tv.tv_sec = 2;
					tv.tv_usec = 0;

					if (setsockopt(fwq1->so, SOL_SOCKET, SO_RCVTIMEO, &tv, 
							sizeof(tv)) < 0) {
							goto drop;
					}

					len = recv(fwq1->so, buf, 2, MSG_WAITALL);
					if (len <= 0) 
						goto drop;

					need = ntohs(unpack16(buf));
					len = recv(fwq1->so, buf, need, MSG_WAITALL | MSG_PEEK);
					if (len <= 0) 
						goto drop;

					time0 = time(NULL);
					returnit(db, cfg, fwq1, buf, len, pibuf);
					now = time(NULL);
#if DEBUG
					dolog(LOG_INFO, "%f seconds spent in returnit tcp\n", difftime(now, time0));
#endif
				} else {
					len = recv(fwq1->so, buf, 0xffff, 0);
					if (len < 0) 
						goto drop;

					time0 = time(NULL);
					returnit(db, cfg, fwq1, buf, len, pibuf);
					now = time(NULL);
#if DEBUG
					dolog(LOG_INFO, "%f seconds spent in returnit udp\n", difftime(now, time0));
#endif
				}

drop:

				SLIST_REMOVE(&fwqhead, fwq1, forwardqueue, entries);
				close(fwq1->so);
				fwq1->so = -1;

				if (fwq1->returnso != -1)
					close(fwq2->returnso);
				
				if (fwq1->tsigkey)
					free(fwq1->tsigkey);

				free(fwq1);

			}
		}

		now = time(NULL);
#if DEBUG
		dolog(LOG_INFO, "%f seconds spent in singly linked list\n", difftime(now, time0));
#endif 


		if (FD_ISSET(ibuf->fd, &rset)) {
			time_t time0, now;

			time0 = time(NULL);
			if ((n = imsg_read(ibuf)) < 0 && errno != EAGAIN) {
				dolog(LOG_ERR, "imsg read failure %s\n", strerror(errno));
				continue;
			}
			now = time(NULL);
#if DEBUG
			dolog(LOG_INFO, "%f seconds spent in imsg_read\n", difftime(now, time0));
#endif
			if (n == 0) {
				/* child died? */
				dolog(LOG_INFO, "sigpipe on child?  forward process exiting.\n");
				exit(1);
			}

			for (;;) {
				time0 = time(NULL);
				errno = 0;
				if ((n = imsg_get(ibuf, &imsg)) <= 0) {
					if (n != 0)
						dolog(LOG_ERR, "imsg read error: %s\n", strerror(errno));
					break;
				} else {
					now = time(NULL);
#if DEBUG
					dolog(LOG_INFO, "%f seconds spent in imsg_get\n", difftime(now, time0));
#endif

					if (n == 0)
						break;

					datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
					if (datalen != sizeof(int)) {
						imsg_free(&imsg);
						break;
					}

					switch(imsg.hdr.type) {
					case IMSG_FORWARD_UDP:
#if DEBUG
						dolog(LOG_INFO, "received UDP message from mainloop\n");
#endif
						if (datalen != sizeof(int))
							break;

						memcpy(&i, imsg.data, sizeof(i));


						sf = (struct sf_imsg *)&ptr[0];
						sf = &sf[i];
		
						rdata = malloc(sizeof(struct sforward));
						if (rdata == NULL) {
							dolog(LOG_ERR, " cache insertion failed\n");
							imsg_free(&imsg);
							break;
						}

						memcpy(rdata, &sf->u.s.sf, sizeof(struct sforward));
						time0 = time(NULL);


#if DEBUG
						now = time(NULL);	
						dolog(LOG_INFO, "%f seconds lag between forward from mainloop\n", difftime(now, ((struct sforward *)rdata)->gotit));
#endif

						forwardthis(db, cfg, -1, (struct sforward *)rdata);	
						now = time(NULL);
#if DEBUG
						dolog(LOG_INFO, "%f seconds spent in forwardthis udp\n", difftime(now, time0));
#endif
						free(rdata);
						/* aquire lock */
						while (ptr[cfg->shptrsize - 16] == '*')
							usleep(arc4random() % 300);
						ptr[cfg->shptrsize - 16] = '*';

						sf->u.s.read = 1;

						ptr[cfg->shptrsize - 16] = ' ';	/* release */

						break;

					case IMSG_FORWARD_TCP:
#if DEBUG
						dolog(LOG_INFO, "received TCP message and descriptor\n");
#endif
						if (datalen != sizeof(int))
							break;

						memcpy(&i, imsg.data, sizeof(i));

						sf = (struct sf_imsg *)&ptr[0];
						sf = &sf[i];
		
						rdata = malloc(sizeof(struct sforward));
						if (rdata == NULL) {
							dolog(LOG_ERR, " cache insertion failed\n");
							imsg_free(&imsg);
							break;
						}

						memcpy(rdata, &sf->u.s.sf, sizeof(struct sforward));
						time0 = time(NULL);
						forwardthis(db, cfg, imsg.fd, (struct sforward *)rdata);
						now = time(NULL);
#if DEBUG
						dolog(LOG_INFO, "%f seconds spent in forwardthis tcp\n", difftime(now, time0));
#endif
						free(rdata);
						/* aquire lock */
						while (ptr[cfg->shptrsize - 16] == '*')
							usleep(arc4random() % 300);
						ptr[cfg->shptrsize - 16] = '*';

						sf->u.s.read = 1;

						ptr[cfg->shptrsize - 16] = ' ';	/* release */
						break;
					}

					imsg_free(&imsg);
				}
	
				continue;
			} /* for (;;) */
		} /* FD_ISSET... */

		if (FD_ISSET(bpibuf->fd, &rset)) {
			time0 = time(NULL);
			if ((n = imsg_read(bpibuf)) < 0 && errno != EAGAIN) {
				dolog(LOG_ERR, "imsg read failure %s\n", strerror(errno));
				continue;
			}
			if (n == 0) {
				/* child died? */
				dolog(LOG_INFO, "sigpipe on child?  forward process biparse.ibuf exiting.\n");
				exit(1);
			}

			for (;;) {
				if ((n = imsg_get(bpibuf, &imsg)) < 0) {
					dolog(LOG_ERR, "imsg read error 2: %s\n", strerror(errno));
					break;
				} else {
					if (n == 0)
						break;

					datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

					switch(imsg.hdr.type) {
					case IMSG_RR_ATTACHED:
						if (datalen != sizeof(int))
							break;

						memcpy(&i, imsg.data, sizeof(i));

						while (cfg->shptr2[cfg->shptr2size - 16] == '*')
							usleep(arc4random() % 300);

						cfg->shptr2[cfg->shptr2size - 16] = '*';
						ri = (struct rr_imsg *)&cfg->shptr2[0];
						for (i = 0; i < SHAREDMEMSIZE; i++, ri++) {
							if (unpack32((char *)&ri->u.s.read) == 0) {
								rdata = malloc(ri->rri_rr.buflen);
								if (rdata == NULL) {
									dolog(LOG_ERR, " cache insertion failed\n");
									pack32((char *)&ri->u.s.read, 1);
									continue;
								}

								memcpy(rdata, &ri->rri_rr.un, ri->rri_rr.buflen);

								if ((rbt = create_rr(db, ri->rri_rr.name, 
										ri->rri_rr.namelen, ri->rri_rr.rrtype, 
										(void *)rdata, ri->rri_rr.ttl)) == NULL) {
									dolog(LOG_ERR, "cache insertion failed 2\n");
									free(rdata);
									pack32((char *)&ri->u.s.read, 1);
									continue;
								}
								flag_rr(rbt);

								pack32((char *)&ri->u.s.read, 1);
							} /* if */
						} /* for */
						cfg->shptr2[cfg->shptr2size - 16] = ' ';

						now = time(NULL);

#if DEBUG
						dolog(LOG_INFO, "%f seconds spent in shared memory\n", difftime(now, time0));
#endif
						break;
		
					default:
						break;
					}
					imsg_free(&imsg);
					break;
				} /* if */
			} /* for (;;) */
		} /* FD_ISSET...bpibuf */

	} /* for (;;) */

	/* NOTREACHED */
}

void
forwardthis(ddDB *db, struct cfg *cfg, int so, struct sforward *sforward)
{
	struct question *q;
	struct sreply sreply;
	struct reply_logic *rl = NULL;
	struct sockaddr_storage *from = NULL;
	struct dns_header *dh;
	struct rbtree *rbt = NULL;

	char buf[512];
	char replystring[DNS_MAXNAME + 1];
	static char *replybuf = NULL;
	int len, slen;

	int fromlen, returnval, lzerrno;
	int istcp = (so == -1 ? 0 : 1);

	int found = 0;
	time_t now;
	char *p;
	socklen_t namelen;
	time_t highexpire;

#if __OpenBSD__
	highexpire = 67768036191673199;
#else
	highexpire = 2147483647;
#endif

	if (replybuf == NULL) {
		replybuf = calloc(1, 0xffff + 2);
		if (replybuf == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			ddd_shutdown();
			exit(1);
		}
	} else
		memset(replybuf, 0, 0xffff + 2);
	
	now = time(NULL);
	p = sforward->buf;

	SLIST_FOREACH_SAFE(fwq1, &fwqhead, entries, fwq2) {
		if (difftime(now, fwq1->time) > 15) {
			SLIST_REMOVE(&fwqhead, fwq1, forwardqueue, entries);
			if (fwq1->returnso != -1) {
				close(fwq1->returnso);
				fwq1->returnso = -1;
			}
			if (fwq1->so != -1)
				close(fwq1->so);

			if (fwq1->tsigkey)
				free(fwq1->tsigkey);
			free(fwq1);
			continue;
		}
	
		found = 0;
		switch (fwq1->oldfamily) {
		case AF_INET:
			if (memcmp(&fwq1->oldhost4.sin_addr.s_addr, 
				&sforward->from4.sin_addr.s_addr, 
				sizeof(struct in_addr)) == 0 &&
				fwq1->oldport == sforward->rport &&
				fwq1->oldid == sforward->header.id) {
				/* found, break... */
					found = 1;
			}
			break;
		case AF_INET6:
			if (memcmp(&fwq1->oldhost6.sin6_addr, 
				&sforward->from6.sin6_addr, 16) == 0 && 
				fwq1->oldport == sforward->rport &&
				fwq1->oldid == sforward->header.id) {
				/* found, break... */
					found = 1;
			}
			break;
		}

		if (found)
			break;
	}

	if (fwq1 == NULL) {
		int count;

		if (! cache)
			goto newqueue;

		/* check cache and expire it, then send if it remains */
		if ((count = expire_rr(db, sforward->buf, sforward->buflen, 
			ntohs(sforward->type), now)) != 0) {
			dolog(LOG_INFO, "Forward CACHE expired %d records\n", count);
			rbt = find_rrset(db, sforward->buf, sforward->buflen);
			if (rbt == NULL) {
				dolog(LOG_INFO, "no such record in our cache, skip\n");
				goto newqueue;
			}
		}
		/* sforward->type is in netbyte order */
		if (Lookup_zone(db, sforward->buf, sforward->buflen, 
			ntohs(sforward->type), 0) != NULL) {
			/* we have a cache */
#if 0
			dolog(LOG_INFO, "replying %s type %d out of the cache\n", convert_name(sforward->buf, sforward->buflen), ntohs(sforward->type));
#endif
			/* build a pseudo question packet */
			dh = (struct dns_header *)&buf[0];
			pack16((char *)&dh->id, sforward->header.id);
			p = (char *)&dh[1];

			pack(p, sforward->buf, sforward->buflen);
			p += sforward->buflen;
			pack16(p, sforward->type);
			p += sizeof(uint16_t);
			pack16(p, htons(DNS_CLASS_IN));
			p += sizeof(uint16_t);

			len = (p - buf);
			/* pseudo question packet done */

			switch (sforward->family) {
			case AF_INET:
				from = (struct sockaddr_storage *)&sforward->from4;
				fromlen = sizeof(struct sockaddr_in);
				break;
			case AF_INET6:
				from = (struct sockaddr_storage *)&sforward->from6;
				fromlen = sizeof(struct sockaddr_in6);
				break;
			default:
				dolog(LOG_INFO, "unknown address family, drop\n");
				return;
			}
			
			if (sforward->havemac)
				q = build_fake_question(sforward->buf, sforward->buflen,
					sforward->type, sforward->tsigname, 
					sforward->tsignamelen);
			else
				q = build_fake_question(sforward->buf, sforward->buflen,
					sforward->type, NULL, 0);
		

			if (q == NULL) {
				dolog(LOG_INFO, "build_fake_question failed\n");
				goto newqueue;
			}
	
			q->aa = 0;
			q->rd = 1;
			
			rbt = lookup_zone(db, q, &returnval, &lzerrno, (char *)&replystring, sizeof(replystring));
			if (rbt == NULL) {
				dolog(LOG_INFO, "lookup_zone failed\n");
				goto newqueue;
			}
			
			q->edns0len = sforward->edns0len;
			if (dnssec && sforward->dnssecok)
				q->dnssecok = 1;

			build_reply(&sreply, 
				(istcp ? so : cfg->dup[sforward->oldsel]),
				buf, len, q, (struct sockaddr *)from, fromlen, 
				rbt, NULL, 0xff, istcp, 0, replybuf); 


			/* from delphinusdnsd.c */
			for (rl = &rlogic[0]; rl->rrtype != 0; rl++) {
			    if (rl->rrtype == ntohs(q->hdr->qtype)) {
				slen = (*rl->reply)(&sreply, cfg->db);
				if (slen < 0) {
					/*
					 * we may have a non-dnssec answer cached without RRSIG
					 * at this point the rl->reply will fail.. expire it
					 * and fill it with dnssec data if available
					 */
					expire_rr(db, q->hdr->name, q->hdr->namelen, 
							ntohs(q->hdr->qtype), highexpire);
					free_question(q);
					goto newqueue;
				}
				break;
			    } /* if rl->rrtype == */
			}

			if (rl->rrtype == 0) {
				dolog(LOG_INFO, "we did not have any right answer in our cache, skip to newqueue\n");
				goto newqueue;
			}

			free_question(q);
			/* at this point we return everythign is done */
			return;
		}

		/* create a new queue and send it */

newqueue:

		TAILQ_FOREACH(fw2, &forwardhead, forward_entry) {
			if (fw2->active == 1)
				break;
		}

		if (fw2 == NULL) {
			TAILQ_FOREACH(fwp, &forwardhead, forward_entry) {
				if (fwp != fw2) {
					fw2 = fwp;
					fw2->active = 1;
					break;
				}
			}

			if (fw2 == NULL) {
				dolog(LOG_INFO, "FORWARD: no suitable destinations found\n");
				return;
			}
				
		}
		
		fwq1 = calloc(1, sizeof(struct forwardqueue));
		if (fwq1 == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			return;
		}
		fwq1->oldfamily = sforward->family;
		fwq1->oldsel = sforward->oldsel;

		switch (sforward->family) {
		case AF_INET:
			memcpy(&fwq1->oldhost4, &sforward->from4, sizeof(struct sockaddr_in));
			break;
		case AF_INET6:
			memcpy(&fwq1->oldhost6, &sforward->from6, sizeof(struct sockaddr_in));
			break;
		}

		fwq1->oldport = sforward->rport;
		fwq1->oldid = sforward->header.id;

		fwq1->port = fw2->destport;
		fwq1->cur_forwardentry = fw2;
		fwq1->longid = arc4random();
		fwq1->id = fwq1->longid % 0xffff;	
		fwq1->time = now;
		if (so == -1)
			fwq1->istcp = 0;
		else
			fwq1->istcp = 1;	


		memcpy((char *)&fwq1->host, (char *)&fw2->host, sizeof(struct sockaddr_storage));

		fwq1->family = fw2->family;
		if (fw2->tsigkey) {
			fwq1->tsigkey = strdup(fw2->tsigkey);
			if (fwq1->tsigkey == NULL) {
				dolog(LOG_ERR, "FORWARD strdup: %s\n", strerror(errno));
				free(fwq1);
				return;
			}
		} else
			fwq1->tsigkey = NULL;

		/* connect the UDP sockets */

		fwq1->so = socket(fw2->family, (fwq1->istcp != 1) ? SOCK_DGRAM : SOCK_STREAM, 0);
		if (fwq1->so < 0) {
			dolog(LOG_ERR, "FORWARD socket: %s\n", strerror(errno));
			if (fwq1->tsigkey)
				free(fwq1->tsigkey);
			free(fwq1);
			return;
		}

		namelen = (fw2->family == AF_INET) ? sizeof(struct sockaddr_in) \
			: sizeof(struct sockaddr_in6);

		if (connect(fwq1->so, (struct sockaddr *)&fwq1->host, namelen) < 0) {
			dolog(LOG_ERR, "FORWARD can't connect: %s\n", strerror(errno));

			changeforwarder(fwq1);

			if (fwq1->tsigkey)
				free(fwq1->tsigkey);

			free(fwq1);
			return;
		}

		fwq1->returnso = so;

		/* are we TSIG'ed?  save key and mac */
		if (sforward->havemac) {
			fwq1->haveoldmac = 1;
			memcpy(&fwq1->oldkeyname, &sforward->tsigname, sizeof(fwq1->oldkeyname));
			fwq1->oldkeynamelen = sforward->tsignamelen;
			memcpy(&fwq1->oldmac, &sforward->mac, sizeof(fwq1->oldmac));
			fwq1->tsigtimefudge = sforward->tsigtimefudge;
		} else
			fwq1->haveoldmac = 0;
				
		SLIST_INSERT_HEAD(&fwqhead, fwq1, entries);

		sendit(fwq1, sforward);
	} else {
		/* resend this one */
		
		fwq1->time = now;
		sendit(fwq1, sforward);
	}

	return;	
}

void
sendit(struct forwardqueue *fwq, struct sforward *sforward)
{
	struct dns_header *dh;
	struct question *q;
	char *buf, *p, *packet;
	char *tsigname;
	int len = 0, outlen;
	int tsignamelen = 0;

	buf = calloc(1, (0xffff + 2));
	if (buf == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		return;	
	}

	if (fwq->tsigkey) {
		tsigname = dns_label(fwq->tsigkey, &tsignamelen);
		if (tsigname == NULL) {
			dolog(LOG_INFO, "dns_label failed\n");
			free(buf);
			return;
		}
	} else {
		tsigname = NULL;
		tsignamelen = 0;
	}

	q = build_fake_question(sforward->buf, sforward->buflen, sforward->type, tsigname, tsignamelen);

	if (q == NULL) {
		dolog(LOG_INFO, "build_fake_question failed\n");
		free(buf);
		return;
	}

	q->edns0len = sforward->edns0len;
	if (q->edns0len > 16384)
		q->edns0len = 16384;
	
	if (fwq->istcp == 1) {
		p = &buf[2];
	} else
		p = &buf[0];
		
	packet = p;
	dh = (struct dns_header *)p;
	
	memcpy((char *)dh, (char *)&sforward->header, sizeof(struct dns_header));
	dh->id = htons(fwq->id);
	dh->question = htons(1);	
	dh->answer = 0; dh->nsrr = 0; dh->additional = htons(1);

	memset((char *)&dh->query, 0, sizeof(dh->query));

	SET_DNS_QUERY(dh);
	SET_DNS_RECURSION(dh);
	HTONS(dh->query);

	p += sizeof(struct dns_header);
	len += sizeof(struct dns_header);

	memcpy(p, sforward->buf, sforward->buflen);
	p += sforward->buflen;
	len += sforward->buflen;
	
	pack16(p, sforward->type);
	p += 2;
	pack16(p, sforward->class);

	p += 2;
	len += 4;	/* type and class */

	/* additionals */
		
	if (dnssec && sforward->dnssecok) {
		q->dnssecok = 1;
	}

	outlen = additional_opt(q, packet, 0xffff, len);
	len = outlen;

	if (tsigname) {
		outlen = additional_tsig(q, packet, 0xffff, len, 1, 0, NULL);
		dh->additional = htons(2);	
	}

	memcpy(&fwq->mac, &q->tsig.tsigmac, 32);

	len = outlen;
	p = packet + outlen;
	
	if (fwq->istcp == 1) {
		pack16(buf, htons(len));
		if (fwq->so != -1 && send(fwq->so, buf, len + 2, 0) < 0) {
			dolog(LOG_INFO, "send() failed changing forwarder: %s\n", strerror(errno));
			changeforwarder(fwq);
		}
	} else {
		if (fwq->so != -1 && send(fwq->so, buf, len, 0) < 0) {
			dolog(LOG_INFO, "send() failed (udp) changing forwarder %s\n", strerror(errno));
			changeforwarder(fwq);
		}
	}

	
	free(buf);
	free_question(q);

	return;
}

void
returnit(ddDB *db, struct cfg *cfg, struct forwardqueue *fwq, char *rbuf, int rlen, struct imsgbuf *ibuf)
{
	struct timeval tv;
	struct dns_header *dh;
	struct question *q;
	struct fwdpq *fwdpq, *fwdpq0;
	struct imsg imsg;

	static char *buf = NULL;
	char *p;

	int so;
	int i; 	/* = v/r */
	int sel, rc;
	int len = 0;
	int outlen;

	socklen_t tolen;
	fd_set rset;
	ssize_t n, datalen;
	time_t time0, now;

	if (buf == NULL) {
		buf = calloc(1, 0xffff + 2);
		if (buf == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			return;	
		}
	} else
		memset(buf, 0, 0xffff + 2);

	if (fwq->istcp == 1) {
		p = &buf[2];
		len = 2;
	} else {
		p = buf;
		so = cfg->dup[fwq->oldsel];
	}
		
	if (rlen <= sizeof(struct dns_header)) {
		dolog(LOG_INFO, "FORWARD returnit, returned packet is too small");	
		return;
	}

	memcpy(p, rbuf, rlen);
	dh = (struct dns_header *)p;
	
	if (! (ntohs(dh->query) & DNS_REPLY)) {
		dolog(LOG_INFO, "FORWARD returnit, returned packet is not a reply\n");
		return;
	}

	if (dh->id != htons(fwq->id)) {
		/* returned packet ID does not match */
		dolog(LOG_INFO, "FORWARD returnit, returned packet ID does not match %d vs %d\n", ntohs(dh->id), fwq->id);
		return;
	}

	/* send it on to our sandbox */
	fwdpq = (struct fwdpq *)calloc(1, sizeof(struct fwdpq));
	if (fwdpq == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		return;
	}

	memcpy(&fwdpq->mac, &fwq->mac, sizeof(fwdpq->mac));

	if (fwq->istcp) {
		fwdpq->buflen = rlen;
	} else {
		if (rlen > sizeof(fwdpq->buf)) {
			dolog(LOG_INFO, "can't send packet to parser, too big\n");
			return;
		}

		memcpy(&fwdpq->buf[0], p, rlen);
		fwdpq->buflen = rlen;

	}

	if (fwq->tsigkey)
		fwdpq->tsigcheck = 1;
	else
		fwdpq->tsigcheck = 0;
	
	if (cache)
		fwdpq->cache = 1;
	else
		fwdpq->cache = 0;

	if (fwq->istcp)
		fwdpq->istcp = 1;
	else
		fwdpq->istcp = 0;
	
	/* lock */
	while (cfg->shptr3[0] == '*')
		usleep(arc4random() % 300);

	cfg->shptr3[0] = '*';

	fwdpq0 = (struct fwdpq *)&cfg->shptr3[16];
	for (i = 0; i < SHAREDMEMSIZE3; i++, fwdpq0++) {
		if (unpack32((char *)&fwdpq0->read) == 1) {
				memcpy(fwdpq0, fwdpq, sizeof(struct fwdpq));
				pack32((char *)&fwdpq0->read, 0);
				break;
		}
	}

	if (imsg_compose(ibuf, IMSG_PARSE_MESSAGE, 0, 0, (fwq->istcp == 1) ? fwq->so : -1, &i, sizeof(i)) < 0) {
			dolog(LOG_INFO, "imsg_compose: %s\n", strerror(errno));
			free(fwdpq);
			return;
	}
	msgbuf_write(&ibuf->w);

	cfg->shptr3[0] = ' ';
	
	for (;;) {
		FD_ZERO(&rset);
		FD_SET(ibuf->fd, &rset);

		tv.tv_sec = 4;
		tv.tv_usec = 0;

		sel = select(ibuf->fd + 1, &rset, NULL, NULL, &tv);

		if (sel < 0) {
			dolog(LOG_ERR, "returnit internal error around select, drop\n");
			continue;
		}
		if (sel == 0) {
			dolog(LOG_ERR, "returnit internal error around select (timeout), drop\n");
			return;
		}

		if (FD_ISSET(ibuf->fd, &rset)) {
			time0 = time(NULL);
			if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN) {
				dolog(LOG_ERR, "returnit internal error around imsg_read, drop\n");
				continue;
			}
			now = time(NULL);
#if DEBUG
			dolog(LOG_INFO, "%f seconds spent in imsg_read 2\n", difftime(now, time0));
#endif
			if (n == 0) {
				dolog(LOG_INFO, "imsg peer died?  shutting down\n");
				ddd_shutdown();
				exit(1);
			}
			
		} else {
			/* the ibuf has no selectable fd */
			continue;
		}
			

		for (;;) {
			time0 = time(NULL);
			if ((n = imsg_get(ibuf, &imsg)) == -1) {
				dolog(LOG_ERR, "returnit internal error around imsg_get, drop\n");
				break;
			}
			now = time(NULL);
#if DEBUG
			dolog(LOG_INFO, "%f seconds spent in imsg_get\n", difftime(now, time0));
#endif

			if (n == 0) {
#if DEBUG
				dolog(LOG_INFO, "n == 0, odd...\n");
#endif
				break;
			}
		
			datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
			switch (imsg.hdr.type) {
			case IMSG_PARSEERROR_MESSAGE:
					if (datalen != sizeof(int)) {
							dolog(LOG_ERR, "bad parsereply message, drop\n");
							imsg_free(&imsg);
							free(fwdpq);
							return;
					}

					memcpy(&rc, imsg.data, datalen);

						if (rc != PARSE_RETURN_ACK) {
							dolog(LOG_ERR, "returnit parser did not ACK this (%d), drop\n", rc);
							imsg_free(&imsg);
							free(fwdpq);
							return;
						}

						imsg_free(&imsg);
						break;
			case IMSG_PARSEREPLY_MESSAGE:

					if (datalen != sizeof(int)) {
							dolog(LOG_ERR, "bad parsereply message, drop\n");
							imsg_free(&imsg);
							free(fwdpq);
							return;
					}

					memcpy(&i, imsg.data, sizeof(int));

					/* lock */
					while (cfg->shptr3[0] == '*')
						usleep(arc4random() % 300);

					cfg->shptr3[0] = '*';

					fwdpq0 = (struct fwdpq *)&cfg->shptr3[16];
					fwdpq0 = &fwdpq0[i];

					memcpy(fwdpq, fwdpq0, sizeof(struct fwdpq));

					pack32((char *)&fwdpq0->read, 1);
					cfg->shptr3[0] = ' ';

				if (fwq->istcp == 1) 
					fwq->so = imsg.fd;

				imsg_free(&imsg);
				goto endimsg;
				break;
			default:
				dolog(LOG_INFO, "received unexpected IMSG\n");
				imsg_free(&imsg);
				break;
			}

			/*  back to select */
			break;
		}	/* for (;;) */
	} /* for (;;) */

endimsg:
				
	if (fwq->tsigkey && (fwdpq->tsig.have_tsig == 0 || fwdpq->tsig.tsigverified == 0)) {
		dolog(LOG_INFO, "FORWARD returnit, TSIG didn't check out error code = %d\n", fwdpq->tsig.tsigerrorcode);
		free(fwdpq);
		return;
	}

	if (fwdpq->tsig.have_tsig) {
		NTOHS(dh->additional);
		if (dh->additional > 0)
			dh->additional--;
		HTONS(dh->additional);
	}

	if (fwdpq->tsigcheck)
		rlen = fwdpq->tsig.tsigoffset;

	free(fwdpq);
	
	/* add new tsig if needed */
	pack16((char *)&dh->id, fwq->oldid);

	NTOHS(dh->query);
	dh->query &= ~(DNS_AUTH);		/* take AA answers out */
	SET_DNS_RECURSION(dh);
	SET_DNS_RECURSION_AVAIL(dh);
	HTONS(dh->query);
	
	if (fwq->haveoldmac) {
		q = build_fake_question(p, rlen, DNS_TYPE_A, fwq->oldkeyname, fwq->oldkeynamelen);

		if (q == NULL) {
			dolog(LOG_INFO, "build_fake_question failed\n");
			return;
		}

		memcpy(&q->tsig.tsigmac, &fwq->oldmac, 32);
		q->tsig.tsigmaclen = 32;
		q->tsig.tsigalglen = 13;
		q->tsig.tsigerrorcode = 0;
		q->tsig.tsigorigid = fwq->oldid;
		q->tsig.have_tsig = 1;
		q->tsig.tsig_timefudge = fwq->tsigtimefudge;

		outlen = additional_tsig(q, p, 0xffff, rlen, 0, 0, NULL);
		if (outlen == rlen) {
			dolog(LOG_INFO, "additional tsig failed\n");
		} else {
			rlen = outlen;

			NTOHS(dh->additional);
			dh->additional++;
			HTONS(dh->additional);

			free_question(q);
		}
	}

	len += rlen;
	
	if (fwq->istcp == 1) {
		pack16(buf, htons(rlen));
		if (send(fwq->returnso, buf, len, 0) != len)
			dolog(LOG_INFO, "send(): %s\n", strerror(errno));
		close(fwq->returnso);	/* only close the tcp stream */
		fwq->returnso = -1;	

	} else {
		
		switch (fwq->oldfamily) {
		case AF_INET:
			tolen = sizeof(struct sockaddr_in);
			if (sendto(so, buf, len, 0, (struct sockaddr *)&fwq->oldhost4, tolen) < 0)
				dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
			break;
		default:
			tolen = sizeof(struct sockaddr_in6);
			if (sendto(so, buf, len, 0, (struct sockaddr *)&fwq->oldhost6, tolen) < 0)
				dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
			break;
		}
	}

	return;
}

struct tsig *
check_tsig(char *buf, int len, char *mac)
{
	char pseudo_packet[4096];		/* for tsig */
	char expand[DNS_MAXNAME + 1];
	u_int rollback, i, j;
	u_int16_t type, rdlen;
	u_int32_t ttl;
	u_int64_t timefudge;
	int elen = 0;
	int additional;

	char *o, *pb;

	struct dns_tsigrr *tsigrr = NULL;
	struct dns_optrr *opt = NULL;
	struct dns_header *hdr; 
	struct tsig *rtsig;

	
	hdr = (struct dns_header *)&buf[0];
	
	rtsig = (void *)calloc(1, sizeof(struct tsig));
	if (rtsig == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		return NULL;
	}

	rtsig->tsigoffset = len;

	rollback = i = sizeof(struct dns_header);
	/* the name is parsed here */
	elen = 0;
	memset(&expand, 0, sizeof(expand));
	pb = expand_compression((u_char *)&buf[i], (u_char *)buf, (u_char *)&buf[len], (u_char *)&expand, &elen, sizeof(expand));
	if (pb == NULL) {
		dolog(LOG_INFO, "expand_compression() failed -2\n");
		free(rtsig);
		return NULL;
	}
	i = (pb - buf);
	if (i > len) {
		free(rtsig);
		return NULL;
	}

	i += (2 * sizeof(u_int16_t));	/*  type,class */

	/* skip any payloads other than additional */
	
	additional = ntohs(hdr->additional);
	j = ntohs(hdr->answer) + ntohs(hdr->nsrr) + ntohs(hdr->additional);

	for (;j > 0; j--) {
		rollback = i;
		/* the name is parsed here */
		elen = 0;
		memset(&expand, 0, sizeof(expand));
		pb = expand_compression((u_char *)&buf[i], (u_char *)buf, (u_char *)&buf[len], (u_char *)&expand, &elen, sizeof(expand));
		if (pb == NULL) {
			dolog(LOG_INFO, "expand_compression() failed -1\n");
			free(rtsig);
			return NULL;
		}
		i = (pb - buf);
		if (i > len) {
			free(rtsig);
			return NULL;
		}

		type = ntohs(unpack16(&buf[i]));
		if (type == DNS_TYPE_OPT || type == DNS_TYPE_TSIG) {
			i = rollback;
			break;
		}
			
		i += 8;		/* skip type, class, ttl */
		if (i > len) {
			free(rtsig);
			return NULL;
		}
		
		rdlen = unpack16(&buf[i]);
		i += 2;			/* skip rdlen */
		i += ntohs(rdlen);	/* skip rdata, next */

		if (i > len) {
			free(rtsig);
			return NULL;
		}
	}

	
	/* check for edns0 opt rr */
	do {
		/* if we don't have an additional section, break */
		if (additional < 1) 
			break;

		rollback = i;

		/* check that the minimum optrr fits */
		/* 10 */
		if (i + sizeof(struct dns_optrr) > len) {
			i = rollback;
			break;
		}

		opt = (struct dns_optrr *)&buf[i];
		if (opt->name[0] != 0) {
			i = rollback;
			break;
		}

		if (ntohs(opt->type) != DNS_TYPE_OPT) {
			i = rollback;
			break;
		}

		/* RFC 3225 */
		ttl = ntohl(opt->ttl);

		i += 11 + ntohs(opt->rdlen);
		if (i > len) {
			free(rtsig);
			return NULL;
		}
		additional--;
	} while (0);
	/* check for TSIG rr */
	do {
		u_int16_t val16, tsigerror, tsigotherlen;
		u_int16_t fudge;
		u_int32_t val32;
		int elen, tsignamelen;
		char tsigkey[512];
		u_char sha256[32];
		u_int shasize = sizeof(sha256);
		time_t now, tsigtime;
		int pseudolen1, pseudolen2, ppoffset = 0;
		int pseudolen3 , pseudolen4;

		rtsig->have_tsig = 0;
		rtsig->tsigerrorcode = 1;

		/* if we don't have an additional section, break */
		if (additional < 1) {
			break;
		}

		memset(rtsig->tsigkey, 0, sizeof(rtsig->tsigkey));
		memset(rtsig->tsigalg, 0, sizeof(rtsig->tsigalg));
		memset(rtsig->tsigmac, 0, sizeof(rtsig->tsigmac));
		rtsig->tsigkeylen = rtsig->tsigalglen = rtsig->tsigmaclen = 0;

		/* the key name is parsed here */
		rollback = i;
		rtsig->tsigoffset = i;

		elen = 0;
		memset(&expand, 0, sizeof(expand));
		pb = expand_compression((u_char *)&buf[i], (u_char *)buf, (u_char *)&buf[len], (u_char *)&expand, &elen, sizeof(expand));
		if (pb == NULL) {
			dolog(LOG_INFO, "expand_compression() failed\n");
			free(rtsig);
			return NULL;
		}
		i = (pb - buf);
		pseudolen1 = i;

		memcpy(rtsig->tsigkey, expand, elen);
		rtsig->tsigkeylen = elen;


		if (i + 10 > len) {	/* type + class + ttl + rdlen == 10 */
			i = rollback;
			break;
		}

		/* type */
		o = &buf[i];
		val16 = unpack16(o);
		if (ntohs(val16) != DNS_TYPE_TSIG) {
			i = rollback;
			break;
		}
		i += 2;
		o += 2;
		pseudolen2 = i;

		rtsig->have_tsig = 1;

		/* we don't have any tsig keys configured, no auth done */
		if (tsig == 0) {
			i = rollback;
			break;
		}

		rtsig->tsigerrorcode = DNS_BADKEY;

		/* class */
		val16 = unpack16(o);
		if (ntohs(val16) != DNS_CLASS_ANY) {
#if DEBUG
			dolog(LOG_INFO, "TSIG not class ANY\n");
#endif
			i = rollback;
			break;
		}
		i += 2;
		o += 2;
	
		/* ttl */
		val32 = unpack32(o);
		if (ntohl(val32) != 0) {
#if DEBUG
			dolog(LOG_INFO, "TSIG not TTL 0\n");
#endif
			i = rollback;
			break;
		}
		i += 4;	
		o += 4;
			
		/* rdlen */
		val16 = unpack16(o);
		if (ntohs(val16) != (len - (i + 2))) {
#if DEBUG
			dolog(LOG_INFO, "TSIG not matching RDLEN\n");
#endif
			i = rollback;
			break;
		}
		i += 2;
		o += 2;
		pseudolen3 = i;

		/* the algorithm name is parsed here */
		elen = 0;
		memset(&expand, 0, sizeof(expand));
		pb = expand_compression((u_char *)&buf[i], (u_char *)buf, (u_char *)&buf[len], (u_char *)&expand, &elen, sizeof(expand));
		if (pb == NULL) {
			dolog(LOG_INFO, "expand_compression() failed 2\n");
			free(rtsig);
			return NULL;
		}
		i = (pb - buf);
		pseudolen4 = i;

		memcpy(rtsig->tsigalg, expand, elen);
		rtsig->tsigalglen = elen;
			
		/* now check for MAC type, since it's given once again */
		if (elen == 11) {
			if (expand[0] != 9 ||
				memcasecmp(&expand[1], "hmac-sha1", 9) != 0) {
				break;
			}
		} else if (elen == 13) {
			if (expand[0] != 11 ||
				memcasecmp(&expand[1], "hmac-sha256", 11) != 0) {
				break;
			}
		} else if (elen == 26) {
			if (expand[0] != 8 ||
				memcasecmp(&expand[1], "hmac-md5", 8) != 0) {
				break;
			}
		} else {
			break;
		}

		/* 
		 * this is a delayed (moved down) check of the key, we don't
		 * know if this is a TSIG packet until we've chekced the TSIG
		 * type, that's why it's delayed...
		 */

		if ((tsignamelen = find_tsig_key(rtsig->tsigkey, rtsig->tsigkeylen, (char *)&tsigkey, sizeof(tsigkey))) < 0) {
			/* we don't have the name configured, let it pass */
			i = rollback;
			break;
		}
		
		if (i + sizeof(struct dns_tsigrr) > len) {
			i = rollback;
			break;
		}

		tsigrr = (struct dns_tsigrr *)&buf[i];
		/* XXX */
#ifndef __OpenBSD__
		timefudge = be64toh(tsigrr->timefudge);
#else
		timefudge = betoh64(tsigrr->timefudge);
#endif
		fudge = (u_int16_t)(timefudge & 0xffff);
		tsigtime = (u_int64_t)(timefudge >> 16);

		rtsig->tsig_timefudge = tsigrr->timefudge;
		
		i += (8 + 2);		/* timefudge + macsize */

		if (ntohs(tsigrr->macsize) != 32) {
#if DEBUG
			dolog(LOG_INFO, "bad macsize\n");
#endif
			rtsig->tsigerrorcode = DNS_BADSIG; 
			break; 
		}

		i += ntohs(tsigrr->macsize);
	

		/* now get the MAC from packet with length rollback */
		NTOHS(hdr->additional);
		hdr->additional--;
		HTONS(hdr->additional);

		/* origid */
		o = &buf[i];
		val16 = unpack16(o);
		i += 2;
		o += 2;
		if (hdr->id != val16)
			hdr->id = val16;
		rtsig->tsigorigid = val16;

		/* error */
		tsigerror = unpack16(o);
		i += 2;
		o += 2;

		/* other len */
		tsigotherlen = unpack16(o);
		i += 2;
		o += 2;

		ppoffset = 0;

		/* check if we have a request mac, this means it's an answer */
		if (mac) {
			o = &pseudo_packet[ppoffset];
			pack16(o, htons(32));
			ppoffset += 2;

			memcpy(&pseudo_packet[ppoffset], mac, 32);
			ppoffset += 32;
		}

		memcpy(&pseudo_packet[ppoffset], buf, pseudolen1);
		ppoffset += pseudolen1;
		memcpy((char *)&pseudo_packet[ppoffset], &buf[pseudolen2], 6); 
		ppoffset += 6;

		memcpy((char *)&pseudo_packet[ppoffset], &buf[pseudolen3], pseudolen4 - pseudolen3);
		ppoffset += (pseudolen4 - pseudolen3);

		memcpy((char *)&pseudo_packet[ppoffset], (char *)&tsigrr->timefudge, 8); 
		ppoffset += 8;

		o = &pseudo_packet[ppoffset];
		pack16(o, tsigerror);
		ppoffset += 2;
		o += 2;

		o = &pseudo_packet[ppoffset];
		pack16(o, tsigotherlen);
		ppoffset += 2;
		o += 2;

		memcpy(&pseudo_packet[ppoffset], &buf[i], len - i);
		ppoffset += (len - i);

		/* check for BADTIME before the HMAC memcmp as per RFC 2845 */
		now = time(NULL);
		/* outside our fudge window */
		if (tsigtime < (now - fudge) || tsigtime > (now + fudge)) {
#if DEBUG
			dolog(LOG_INFO, "outside of our fudge window\n");
#endif
			rtsig->tsigerrorcode = DNS_BADTIME;
			break;
		}

		HMAC(EVP_sha256(), tsigkey, tsignamelen, (unsigned char *)pseudo_packet, 
			ppoffset, (unsigned char *)&sha256, &shasize);



#if __OpenBSD__
		if (timingsafe_memcmp(sha256, tsigrr->mac, sizeof(sha256)) != 0) {
#else
		if (memcmp(sha256, tsigrr->mac, sizeof(sha256)) != 0) {
#endif
#if DEBUG
			dolog(LOG_INFO, "HMAC did not verify\n");
#endif
			rtsig->tsigerrorcode = DNS_BADSIG;
			break;
		}

		/* copy the mac for error coding */
		memcpy(rtsig->tsigmac, tsigrr->mac, sizeof(rtsig->tsigmac));
		rtsig->tsigmaclen = 32;
		
		/* we're now authenticated */
		rtsig->tsigerrorcode = 0;
		rtsig->tsigverified = 1;
		
	} while (0);

	/* parse type and class from the question */
	return (rtsig);
}

void
fwdparseloop(struct imsgbuf *ibuf, struct imsgbuf *bibuf, struct cfg *cfg)
{
	int fd = ibuf->fd;
	int sel, istcp = 0;
	int rlen, tmp, rc, i;

	struct tsig *stsig = NULL;
	struct fwdpq *fwdpq, *fwdpq0;
	struct imsg imsg;
	struct dns_header *dh;

	char *packet;
	u_char *end, *estart;
	fd_set rset;
	ssize_t n, datalen;
	int flags;

	flags = fcntl(bibuf->fd, F_GETFL);
	if (flags < 0) {
		dolog(LOG_INFO, "fcntl: %s\n", strerror(errno));
	} else {
		flags |= O_NONBLOCK;
		if (fcntl(bibuf->fd, F_SETFL, &flags, sizeof(flags)) < 0) {
			dolog(LOG_INFO, "fcntl: %s\n", strerror(errno));
		}
	}

#if __OpenBSD__
	if (pledge("stdio sendfd recvfd", NULL) < 0) {
		perror("pledge");
		ddd_shutdown();
		exit(1);
	}
#endif


	fwdpq = (struct fwdpq *)calloc(1, sizeof(struct fwdpq));
	if (fwdpq == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		ddd_shutdown();
		exit(1);
	}


	for (;;) {
		FD_ZERO(&rset);
		FD_SET(fd, &rset);

		sel = select(fd + 1, &rset, NULL, NULL, NULL);

		if (sel < 0) {
			continue;
		}

		if (FD_ISSET(fd, &rset)) {
			if (((n = imsg_read(ibuf)) == -1 && errno != EAGAIN) || n == 0) {
				continue;
			}

			for (;;) {
			
				if ((n = imsg_get(ibuf, &imsg)) == -1) {
					break;
				}

				if (n == 0) {
					break;
				}

				datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

				switch (imsg.hdr.type) {
				case IMSG_PARSE_MESSAGE:
					/* XXX magic numbers */
					if (datalen != sizeof(int)) {
						rc = PARSE_RETURN_NAK;
						imsg_compose(ibuf, IMSG_PARSEERROR_MESSAGE, 0, 0, imsg.fd, &rc, sizeof(int));
						msgbuf_write(&ibuf->w);
						break;
					}
					
					memcpy(&i, imsg.data, datalen);

					/* lock */
					while (cfg->shptr3[0] == '*')
						usleep(arc4random() % 300);

					cfg->shptr3[0] = '*';

					fwdpq0 = (struct fwdpq *)&cfg->shptr3[16];
					fwdpq0 = &fwdpq0[i];

					memcpy(fwdpq, fwdpq0, sizeof(struct fwdpq));
					pack32((char *)&fwdpq0->read, 1);

					cfg->shptr3[0] = ' '; 	/* unlock */

					istcp = fwdpq->istcp;

					if (istcp) {
						packet = malloc(fwdpq->buflen);
						if (packet == NULL) {
							dolog(LOG_INFO, "malloc %s\n", strerror(errno));
							rc = PARSE_RETURN_NAK;
							/* send the descriptor back to them */
							imsg_compose(ibuf, IMSG_PARSEERROR_MESSAGE, 0, 0, imsg.fd, &rc, sizeof(int));
							msgbuf_write(&ibuf->w);
							break;
						}

						if (recv(imsg.fd, packet, fwdpq->buflen, MSG_WAITALL) < 0) {
							dolog(LOG_INFO, "recv in forward sandbox: %s\n", strerror(errno));
							rc = PARSE_RETURN_NAK;
							/* send the descriptor back to them */
							imsg_compose(ibuf, IMSG_PARSEERROR_MESSAGE, 0, 0, imsg.fd, &rc, sizeof(int));
							msgbuf_write(&ibuf->w);
							free(packet);
							break;
						}
						dolog(LOG_INFO, "received %d bytes from descriptor %d\n", fwdpq->buflen, imsg.fd);
					} else
						packet = &fwdpq->buf[0];

					if (istcp) {
						tmp = fwdpq->buflen;
					} else {
						tmp = fwdpq->buflen;
					}

					if (tmp < sizeof(struct dns_header)) {
						/* SEND NAK */
						rc = PARSE_RETURN_NAK;
						imsg_compose(ibuf, IMSG_PARSEERROR_MESSAGE, 0, 0, (istcp) ? imsg.fd : -1, &rc, sizeof(int));
						msgbuf_write(&ibuf->w);
						if (istcp)
							free(packet);
						break;
					}
					dh = (struct dns_header *)packet;

					if (! (ntohs(dh->query) & DNS_REPLY)) {
						rc = PARSE_RETURN_NOTAREPLY;
						imsg_compose(ibuf, IMSG_PARSEERROR_MESSAGE, 0, 0, (istcp) ? imsg.fd : -1, &rc, sizeof(int));
						msgbuf_write(&ibuf->w);
						if (istcp)
							free(packet);
						break;
					}

					/* 
					 * if questions aren't exactly 1 then reply NAK
					 */

					if (ntohs(dh->question) != 1) {
						/*
						 * all valid answers have a
						 * question, so this is good
						 */
						rc = PARSE_RETURN_NOQUESTION;
						imsg_compose(ibuf, IMSG_PARSEERROR_MESSAGE, 0, 0, (istcp) ? imsg.fd : -1, &rc, sizeof(int));
						msgbuf_write(&ibuf->w);
						if (istcp)
							free(packet);
						break;
					}
					/* insert parsing logic here */

					/* check for cache */
					if (fwdpq->cache) {
							estart = packet;
							rlen = tmp;
							end = &packet[rlen];

							if (cacheit(packet, estart, end, ibuf, bibuf, cfg) < 0) {
								dolog(LOG_INFO, "cacheit failed\n");
							}
					}

					/* check to see if we tsig */
			
					if (fwdpq->tsigcheck) {
							rlen = tmp;
							stsig = check_tsig((char *)packet, rlen, fwdpq->mac);
							if (stsig == NULL) {
								dolog(LOG_INFO, "FORWARD parser, malformed reply packet\n");
								rc = PARSE_RETURN_MALFORMED;

								imsg_compose(ibuf, IMSG_PARSEERROR_MESSAGE, 0, 0, (istcp) ? imsg.fd : -1, &rc, sizeof(int));
								msgbuf_write(&ibuf->w);
			
								if (istcp)
									free(packet);
								break;
							}

							memcpy(&fwdpq->tsig, stsig, sizeof(struct tsig));
					}

					fwdpq->rc = PARSE_RETURN_ACK;

					cfg->shptr3[0] = '*';

					fwdpq0 = (struct fwdpq *)&cfg->shptr3[16];
					for (i = 0; i < SHAREDMEMSIZE3; i++, fwdpq0++) {
						if (unpack32((char *)&fwdpq0->read) == 1) {
							memcpy(fwdpq0, fwdpq, sizeof(struct fwdpq));
							pack32((char *)&fwdpq0->read, 0);
							break;
						}
					}

					imsg_compose(ibuf, IMSG_PARSEREPLY_MESSAGE, 0, 0, (istcp) ? imsg.fd : -1, &i, sizeof(int));
					msgbuf_write(&ibuf->w);

					cfg->shptr3[0] = ' ';

					free(stsig);

					if (istcp)
						free(packet);
					break;
				} /* switch */

				imsg_free(&imsg);
				break;
			} /* for(;;) */
		} /* FD_ISSET */
	} /* for(;;) */

	/* NOTREACHED */
}

void
changeforwarder(struct forwardqueue *fwq)
{
	fw2 = fwq->cur_forwardentry;

	if ((fwp = TAILQ_PREV(fw2, forwardentrys, forward_entry)) == NULL) {
		if ((fwp = TAILQ_NEXT(fw2, forward_entry)) == NULL) {
			return;
		}
		
		fw2->active = 0;
		fwp->active = 1;
	} else {
		fw2->active = 0;
		fwp->active = 1;
	}

	return;
}

void
stirforwarders(void)
{
	int randomforwarder;
	int count = 0;

	TAILQ_FOREACH(fwp, &forwardhead, forward_entry) {
		fwp->active = 0;
		count++;
	}

	randomforwarder = arc4random() % count;	
	
	count = 0;
	TAILQ_FOREACH(fwp, &forwardhead, forward_entry) {
		if (randomforwarder == count) {
			dolog(LOG_INFO, "stirforwarders: %s is now active\n", fwp->name);
			fwp->active = 1;
		}
		
		count++;
	}
}
