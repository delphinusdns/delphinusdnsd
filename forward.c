/*
 * Copyright (c) 2020-2024 Peter J. Philipp <pbug44@delphinusdns.org>
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
#include <sys/uio.h>
#include <sys/select.h>
#include <sys/mman.h>
#include <sys/resource.h>

#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <ctype.h>

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
#include <sys/capsicum.h>
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

TAILQ_HEAD(forwardentrys, forwardentry) forwardhead;

struct forwardentry {
	char name[INET6_ADDRSTRLEN];
	int family;
	struct sockaddr_storage host;
	uint16_t destport;
	char *tsigkey;
	int active;
	uint8_t region;
	TAILQ_ENTRY(forwardentry) forward_entry;
} *fw2, *fwp;

SLIST_HEAD(, forwardqueue) fwqhead;

struct forwardqueue {
	char orig_dnsname[DNS_MAXNAME];		/* what we reply with */
	char dnsname[DNS_MAXNAME];		/* the request name */
	char dnsnamelen;			/* the len of dnsname */
	uint32_t sessid;			/* session id per forward */
	uint32_t longid;			/* a long identifier */
	time_t time;				/* time created */
	int tries;				/* how many times we rtrnsmt */
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
	int answered;				/* return was given flag */
	uint16_t type;				/* the type of query */
	int istcp;				/* whether we're tcp */
	int family;				/* our family */
	char *tsigkey;				/* which key we use for query */
	uint64_t tsigtimefudge;			/* passed tsigtimefudge */
	char mac[DNS_HMAC_SHA256_SIZE * 5];	/* passed mac from query */
	int haveoldmac;				/* do we have an old mac? */
	char oldkeyname[256];			/* old key name */
	int oldkeynamelen;			/* old key name len */
	char oldmac[DNS_HMAC_SHA256_SIZE];	/* old mac */
	struct forwardentry *cur_forwardentry;	/* current forwardentry */
	int dnssecok;				/* DNSSEC in anwers */
	uint16_t edns0len;			/* EDNS0 length as negotiated */
	uint8_t region;				/* the region of the request */
	SLIST_ENTRY(forwardqueue) entries;	/* next entry */
} *fwq1, *fwq2, *fwq3, *fwqp;

struct offregion {
	int i;
	uint8_t region;
};


SLIST_HEAD(, closequeue) closehead;

struct closequeue {
	time_t timeout;
	uint32_t sessid;
	int econnreset;
	SLIST_ENTRY(closequeue) entries;	/* next entry */
} *cq1, *cq2, *cqp;

void			init_forward(void);

int			insert_forward(int, struct sockaddr_storage *, uint16_t, char *);
void			forwardloop(ddDB *, struct cfg *, struct imsgbuf *, struct imsgbuf *);
void			forwardthis(ddDB *, struct cfg *, int, struct sforward *);
int			sendit(struct forwardqueue *, struct sforward *);
int			returnit(ddDB *, struct cfg *, struct forwardqueue *, char *, int, struct imsgbuf *);
struct tsig * 		check_tsig(char *, int, char *);
void			fwdparseloop(struct imsgbuf *, struct imsgbuf *, struct cfg *);
void			changeforwarder(struct forwardqueue *);
void 			stirforwarders(void);
int 			rawsend(int, char *, uint16_t, struct sockaddr_in *, int, struct cfg *);
int 			rawsend6(int, char *, uint16_t, struct sockaddr_in6 *, int, struct cfg *);
void 			dump_cache(ddDB *, struct imsgbuf *);
void 			parse_lowercase(char *, int);
void 			wrap64(char *, int, char *);

extern uint16_t		udp_cksum(uint16_t *, uint16_t, struct ip *, struct udphdr *);
extern uint16_t		udp_cksum6(uint16_t *, uint16_t, struct ip6_hdr *, struct udphdr *);
extern void		dolog(int, char *, ...);
extern void		pack(char *, char *, int);
extern void		pack16(char *, uint16_t);
extern void		pack32(char *, uint32_t);
extern uint16_t		unpack16(char *);
extern uint32_t		unpack32(char *);
extern void		ddd_shutdown(void);
extern int		additional_opt(struct question *, char *, int, int, struct sockaddr *, socklen_t, uint16_t);
extern int		additional_tsig(struct question *, char *, int, int, int, int, HMAC_CTX *, uint16_t);
extern struct question*	build_fake_question(char *, int, uint16_t, char *, int);
extern int		free_question(struct question *);
extern char *		dns_label(char *, int *);
extern int		find_tsig_key(char *, int, char *, int);
extern int		memcasecmp(u_char *, u_char *, int);
extern char *		expand_compression(u_char *, u_char *, u_char *, u_char *, int *, int);
extern int		expire_rr(ddDB *, char *, int, uint16_t, time_t);
extern int 		expire_db(ddDB *, int);
extern void 		build_reply(struct sreply *, int, char *, int, struct question *, struct sockaddr *, socklen_t, struct rbtree *, struct rbtree *, uint8_t, int, int, char *);
extern struct rbtree *	Lookup_zone(ddDB *, char *, int, int, int);
extern struct rbtree *	lookup_zone(ddDB *, struct question *, int *, int *, char *, int);
extern int		cacheit(u_char *, u_char *, u_char *, struct imsgbuf *, struct imsgbuf *, struct cfg *);

extern int 		reply_a(struct sreply *, int *, ddDB *);
extern int 		reply_aaaa(struct sreply *, int *, ddDB *);
extern int 		reply_any(struct sreply *, int *, ddDB *);
extern int 		reply_cname(struct sreply *, int *, ddDB *);
extern int		reply_notify(struct sreply *, int *, ddDB *);
extern int 		reply_soa(struct sreply *, int *, ddDB *);
extern int 		reply_mx(struct sreply *, int *, ddDB *);
extern int 		reply_naptr(struct sreply *, int *, ddDB *);
extern int 		reply_ns(struct sreply *, int *, ddDB *);
extern int 		reply_ptr(struct sreply *, int *, ddDB *);
extern int 		reply_srv(struct sreply *, int *, ddDB *);
extern int 		reply_sshfp(struct sreply *, int *, ddDB *);
extern int 		reply_tlsa(struct sreply *,  int *,ddDB *);
extern int 		reply_txt(struct sreply *, int *, ddDB *);
extern int      	reply_rrsig(struct sreply *, int *, ddDB *);
extern int		reply_dnskey(struct sreply *, int *, ddDB *);
extern int		reply_ds(struct sreply *, int *, ddDB *);
extern int		reply_nsec(struct sreply *, int *, ddDB *);
extern int		reply_nsec3(struct sreply *, int *, ddDB *);
extern int		reply_nsec3param(struct sreply *, int *, ddDB *);
extern int		reply_generic(struct sreply *, int *, ddDB *);
extern struct rbtree * 	create_rr(ddDB *, char *, int, int, void *, uint32_t, uint16_t);
extern void 		flag_rr(struct rbtree *rbt, uint32_t);
extern struct rbtree * 	find_rrset(ddDB *, char *, int);
extern int		randomize_dnsname(char *, int);
extern int		lower_dnsname(char *buf, int len);
extern void		sm_lock(char *, size_t);
extern void		sm_unlock(char *, size_t);
extern struct rrset * 	find_rr(struct rbtree *rbt, uint16_t rrtype);
extern int 		rr_duplicate(ddDB *, char *, int, uint16_t, char *);
extern size_t 		plength(void *, void *);
extern u_int 		nowrap_dec(u_int, u_int);
extern char *		get_dns_type(int, int);

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
extern int strictx20i;
extern int forwardstrategy;
extern char *identstring;
extern uint32_t zonenumber;
extern uint16_t fudge_forward;


uint16_t 	wrap6to4region = 0xffff;


/*
 * INIT_FORWARD - initialize the forward linked lists
 */

void
init_forward(void)
{
	TAILQ_INIT(&forwardhead);
	SLIST_INIT(&fwqhead);
	SLIST_INIT(&closehead);
	return;
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
	int i, count, skip;
	int econnreset = 0;
	int returned = 0;
	uint32_t sessid;
	u_int packetcount = 0;

	ssize_t n, datalen;
	fd_set rset;
	pid_t pid;

	char *ptr;
	
	ptr = cfg->shm[SM_FORWARD].shptr;

	forward = 0; 		/* in this process we don't need forward on */
	dolog(LOG_INFO, "FORWARD: expired %d records from non-forwarding DB\n",  expire_db(db, TTL_EXPIRE_ALL));

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
#ifndef __OpenBSD__
                /* OpenBSD has minherit() */
                if (munmap(cfg->shm[SM_FORWARD].shptr, 
			cfg->shm[SM_FORWARD].shptrsize) == -1) {
                        dolog(LOG_INFO, "unmapping shptr failed: %s\n", \
                                strerror(errno));
                }
#endif
		cfg->shm[SM_FORWARD].shptrsize = 0;

		close(ibuf->fd);
		close(cortex->fd);
		close(pi[1]);
		close(bipi[1]);
		close(cfg->raw[0]);
		close(cfg->raw[1]);
		imsg_init(&parse_ibuf, pi[0]);
		imsg_init(&biparse_ibuf, bipi[0]);
		
		setproctitle("forward parse engine [%s]",
			(identstring != NULL ? identstring : ""));

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

	zonenumber = 0;		/* reset this to 0 */

	for (;;) {
		/*
		 * due to our strategy (which kinda sucks) stir some
		 * entropy into the active forwarder
		 */
		if (forwardstrategy == STRATEGY_SINGLE && packetcount++ 
			&& packetcount % 1000 == 0)
			stirforwarders();

		FD_ZERO(&rset);	
		FD_SET(ibuf->fd, &rset);
		econnreset = 0;
		if (ibuf->fd > max)
			max = ibuf->fd;
		FD_SET(bpibuf->fd, &rset);
		if (bpibuf->fd > max)
			max = bpibuf->fd;

		SLIST_FOREACH_SAFE(cq2, &closehead, entries, cqp) {
			if (difftime(time(NULL), cq2->timeout) >= 120) {
				/* clean up the left-behinds */
				SLIST_REMOVE(&closehead, cq2, closequeue, entries);
				free(cq2);
			}
		}


		SLIST_FOREACH(fwq1, &fwqhead, entries) {
			if (fwq1->so == -1)
				continue;

			if (fwq1->so > max)
				max = fwq1->so;
	
			FD_SET(fwq1->so, &rset);
#if DEBUG
			dolog(LOG_INFO, "set fwq1->so (%d)\n", fwq1->so);
#endif
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
				count = expire_db(db, TTL_EXPIRE_RR);
				if (count)
					dolog(LOG_INFO, "Forward CACHE expire_db: expired %d RR's\n", count);
			}
			continue;
		}

		
		SLIST_FOREACH_SAFE(fwq1, &fwqhead, entries, fwq3) {
			if (FD_ISSET(fwq1->so, &rset)) {
#if DEBUG
					dolog(LOG_INFO, "fwq1->so %d isset\n", fwq1->so);
#endif
				skip = 0;
				SLIST_FOREACH_SAFE(cq2, &closehead, entries, cqp) {
					if (fwq1->sessid == cq2->sessid) {
						if (! cq2->econnreset)
							skip = 1;
#if DEBUG	
						dolog(LOG_INFO, "skip = 1\n");
#endif
						SLIST_REMOVE(&closehead, cq2, closequeue, entries);
						free(cq2);
						break;
					}
				}

				returned = 0;

				if (fwq1->istcp == DDD_IS_TCP) {
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

					if (skip)
						goto drop;
					
#if DEBUG
					dolog(LOG_INFO, "fwq1->so %d returnit\n", fwq1->so);
#endif
					returned = returnit(db, cfg, fwq1, buf, len, pibuf);
				} else {
					len = recv(fwq1->so, buf, 0xffff, 0);
					if (len < 0) {
						if (errno == ECONNREFUSED) {
							econnreset = 1;
							goto drop;
						}
#if DEBUG
						dolog(LOG_INFO, "recv: %s\n", strerror(errno));
#endif
						goto drop;
					}

					if (skip)
						goto drop;
#if DEBUG
					dolog(LOG_INFO, "udp fwq1->so %d returnit\n", fwq1->so);
#endif

					returned = returnit(db, cfg, fwq1, buf, len, pibuf);
				}


drop:
				/* delete all instances with the same sessid */
				sessid = fwq1->sessid;
				SLIST_REMOVE(&fwqhead, fwq1, forwardqueue, entries);
				close(fwq1->so);
				fwq1->so = -1;

				if (fwq1->returnso != -1) {
					close(fwq1->returnso);
					fwq1->returnso = -1;
				}
							
				if (fwq1->tsigkey)
					free(fwq1->tsigkey);

				free(fwq1);

				if (returned == -1) {
					continue;
				}

				cq1 = calloc(1, sizeof(struct closequeue));
				if (cq1 == NULL) {
					dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
					continue;	
				}
				if (econnreset)
					cq1->econnreset = 1;
				cq1->sessid = sessid;
				cq1->timeout = time(NULL);
				SLIST_INSERT_HEAD(&closehead, cq1, entries);

				FD_ZERO(&rset); 	/* go back to select */

			}
		}

		if (FD_ISSET(ibuf->fd, &rset)) {
			if ((n = imsg_read(ibuf)) < 0 && errno != EAGAIN) {
				dolog(LOG_ERR, "imsg read failure %s\n", strerror(errno));
				continue;
			}

			if (n == 0) {
				/* child died? */
				dolog(LOG_INFO, "sigpipe on child?  forward process exiting.\n");
				exit(1);
			}

			for (;;) {
				errno = 0;
				if ((n = imsg_get(ibuf, &imsg)) <= 0) {
					if (n != 0)
						dolog(LOG_ERR, "imsg read error: %s\n", strerror(errno));
					break;
				} else {
					if (n == 0)
						break;

					datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
					if (datalen != sizeof(int)) {
						imsg_free(&imsg);
						break;
					}

					switch(imsg.hdr.type) {
					case IMSG_DUMP_CACHE:
						dump_cache(db, ibuf);
						break;
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


						forwardthis(db, cfg, -1, (struct sforward *)rdata);	
						free(rdata);
						sm_lock(ptr, cfg->shm[SM_FORWARD].shptrsize);
						sf->u.s.read = 1;
						sm_unlock(ptr, cfg->shm[SM_FORWARD].shptrsize);

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
						forwardthis(db, cfg, imsg.fd, (struct sforward *)rdata);
						free(rdata);
						/* aquire lock */
						sm_lock(ptr, cfg->shm[SM_FORWARD].shptrsize);
						sf->u.s.read = 1;
						sm_unlock(ptr, cfg->shm[SM_FORWARD].shptrsize);

						break;
					}

					imsg_free(&imsg);
				}
	
				continue;
			} /* for (;;) */
		} /* FD_ISSET... */

		if (FD_ISSET(bpibuf->fd, &rset)) {
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

						sm_lock(cfg->shm[SM_RESOURCE].shptr, 
								cfg->shm[SM_RESOURCE].shptrsize);
						ri = (struct rr_imsg *)&cfg->shm[SM_RESOURCE].shptr[0];
						for (i = 0; i < SHAREDMEMSIZE; i++, ri++) {
							if (unpack32((char *)&ri->u.s.read) == 0) {
								rdata = malloc(ri->rri_rr.buflen);
								if (rdata == NULL) {
									dolog(LOG_ERR, " cache insertion failed\n");
									pack32((char *)&ri->u.s.read, 1);
									continue;
								}

								memcpy(rdata, &ri->rri_rr.un, ri->rri_rr.buflen);

								if (lower_dnsname(ri->rri_rr.name, ri->rri_rr.namelen) == -1) {
									dolog(LOG_INFO, "lower_dnsname failed\n");
									free (rdata);
									pack32((char *)&ri->u.s.read, 1);
									continue;
								}


								if (rr_duplicate(db, ri->rri_rr.name, \
									ri->rri_rr.namelen, ri->rri_rr.rrtype, \
									rdata)) {
										free(rdata);
										pack32((char *)&ri->u.s.read, 1);
										continue;
								}	

								if ((rbt = create_rr(db, ri->rri_rr.name, 
										ri->rri_rr.namelen, ri->rri_rr.rrtype, 
										(void *)rdata, ri->rri_rr.ttl, ri->rri_rr.buflen)) == NULL) {
									dolog(LOG_ERR, "cache insertion failed 2\n");
									free(rdata);
									pack32((char *)&ri->u.s.read, 1);
									continue;
								}

								flag_rr(rbt, RBT_CACHE);
	
								if (unpack32((char *)&ri->rri_rr.authentic) == 1) 
									flag_rr(rbt, RBT_DNSSEC);

								pack32((char *)&ri->u.s.read, 1);
							} /* if */
						} /* for */
						sm_unlock(cfg->shm[SM_RESOURCE].shptr,
							cfg->shm[SM_RESOURCE].shptrsize);

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
	struct dns_header *odh;

	char buf[512];
	char replystring[DNS_MAXNAME + 1];
	char savednsname[DNS_MAXNAME];
	static char *replybuf = NULL;
	int len, slen;

	int fromlen, returnval, lzerrno;
	int istcp = (so == -1 ? DDD_IS_UDP : DDD_IS_TCP);
	int sretlen = 0;

	int on = 1;
	int found = 0;
	time_t now;
	char *p;
	socklen_t namelen;
	time_t highexpire;
	uint32_t sessid;
	int firstrun = 0;

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

	sessid = 0;
	SLIST_FOREACH_SAFE(fwq1, &fwqhead, entries, fwq2) {
		if (difftime(now, fwq1->time) > 5) {
			SLIST_FOREACH_SAFE(cq2, &closehead, entries, cqp) {
				if (fwq1->sessid == cq2->sessid) {
					SLIST_REMOVE(&closehead, cq2, closequeue, entries);
					fwq1->answered = 1;
					free(cq2);
					return;
				}
			}

			odh = (struct dns_header *)&buf[(fwq1->istcp == DDD_IS_TCP) ? 2 : 0];
			/* send a servfail and remove from list */
			odh->id = fwq1->oldid;
			odh->query = DNS_REPLY;
			SET_DNS_RCODE_SERVFAIL(odh);
			HTONS(odh->query);
			odh->question = htons(1);
			odh->answer = 0;
			odh->nsrr = 0;
			odh->additional = 0;

			p = &buf[sizeof(struct dns_header)];
			pack(p, fwq1->orig_dnsname, fwq1->dnsnamelen);
			p += fwq1->dnsnamelen;
			pack16(p, htons(DNS_CLASS_IN));
			p += 2;
			pack16(p, fwq1->type);
			p += 2;

			if (fwq1->answered == 0) {
				if (fwq1->istcp == DDD_IS_TCP) {
					pack16(&buf[0], htons(plength(p, &buf[2])));
					send(fwq1->returnso, buf, plength(p, &buf[0]), 0);
				} else {
					switch (fwq1->oldfamily) {
					case AF_INET:
						rawsend(cfg->raw[0], buf, plength(p, &buf[0]), &fwq1->oldhost4, fwq1->oldsel, cfg);
						break;
					case AF_INET6:
						rawsend6(cfg->raw[1], buf, plength(p, &buf[0]), &fwq1->oldhost6, fwq1->oldsel, cfg);
						break;
					}
				}
			}

			SLIST_REMOVE(&fwqhead, fwq1, forwardqueue, entries);
			if (fwq1->returnso != -1) {
				close(fwq1->returnso);
				fwq1->returnso = -1;
			}
			if (fwq1->so != -1)
				close(fwq1->so);

			if (fwq1->tsigkey)
				free(fwq1->tsigkey);

			sessid = fwq1->sessid;
			free(fwq1);

			cq1 = calloc(1, sizeof(struct closequeue));
			if (cq1 == NULL) {
				dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
				continue;	
			}
			cq1->sessid = sessid;
			cq1->timeout = time(NULL);
			SLIST_INSERT_HEAD(&closehead, cq1, entries);

			continue;
		}

		p = sforward->buf;
	
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
	
		/* set our name to lower case for db work */
		memcpy(&savednsname, sforward->buf, sforward->buflen);
		if (lower_dnsname(sforward->buf, sforward->buflen) == -1) {
			dolog(LOG_INFO, "lower_dnsname failed, drop\n");
			return;
		}

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
			ntohs(sforward->type), 0) != NULL ||
			Lookup_zone(db, sforward->buf, sforward->buflen,
			DNS_TYPE_CNAME, 0) != NULL) {
			/* we have a cache */
			/* build a pseudo question packet */
			dh = (struct dns_header *)&buf[0];
			pack16((char *)&dh->id, sforward->header.id);
			p = (char *)&dh[1];

			/* make sure we reply as it was given */
			pack(p, savednsname, sforward->buflen);
			p += sforward->buflen;
			pack16(p, sforward->type);
			p += sizeof(uint16_t);
			pack16(p, htons(DNS_CLASS_IN));
			p += sizeof(uint16_t);

			len = (plength(p, buf));
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
			
			/* XXX no ntohs() for sforward->type here */
			if (sforward->havemac)
				q = build_fake_question(savednsname, sforward->buflen,
					sforward->type, sforward->tsigname, 
					sforward->tsignamelen);
			else
				q = build_fake_question(savednsname, sforward->buflen,
					sforward->type, NULL, 0);
		

			if (q == NULL) {
				dolog(LOG_INFO, "build_fake_question failed\n");
				goto newqueue;
			}

			if (sforward->edns0len)
				q->edns0len = sforward->edns0len;
	
			q->aa = 0;
			q->rd = 1;
			
			rbt = lookup_zone(db, q, &returnval, &lzerrno, (char *)&replystring, sizeof(replystring));
			if (rbt == NULL) {
				dolog(LOG_INFO, "lookup_zone failed\n");
				free_question(q);
				goto newqueue;
			}
			
			if (dnssec && sforward->dnssecok)
				q->dnssecok = 1;

			/* we have a cache but it's not DNSSEC'ed */
			if (q->dnssecok && ! (rbt->flags & RBT_DNSSEC)) {
				/* expire the record and grab it anew */
				expire_rr(db, sforward->buf, sforward->buflen, 
					ntohs(sforward->type), highexpire);
				free_question(q);
				goto newqueue;
			}

			q->rawsocket = 1;
			build_reply(&sreply, 
				(istcp == DDD_IS_TCP ? so : -1), buf, len, q, 
				(struct sockaddr *)from, fromlen, 
				rbt, NULL, 0xff, istcp, 0, replybuf); 

			/* are we a CNAME? if not then search our logic */
			if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
				slen = reply_cname(&sreply, &sretlen, cfg->db);
				if (slen <= 0) {
					/*
					 * we may have a non-dnssec answer cached without RRSIG
					 * at this point the rl->reply will fail.. expire it
					 * and fill it with dnssec data if available
					 */
					expire_db(db, TTL_EXPIRE_RR);
					free_question(q);
					goto newqueue;
				}

				switch (from->ss_family) {
				case AF_INET:
					rawsend(cfg->raw[0], sreply.replybuf, sretlen, &sforward->from4, sforward->oldsel, cfg);
					break;
				case AF_INET6:
					rawsend6(cfg->raw[1], sreply.replybuf, sretlen, &sforward->from6, sforward->oldsel, cfg);
					break;
				}
			} else {
				/* if we are faking answers with wrap64 */
				if (wrap6to4region != 0xffff &&
					sforward->region == \
						wrap6to4region) {
					struct rrset *rrset1;
					struct rr *myrr;

					char ip6buf[INET6_ADDRSTRLEN];
					char *ip6 = &ip6buf[0];

					strlcpy(ip6buf, "::ffff:127.0.0.1", sizeof(ip6buf));

					rrset1 = find_rr(rbt, DNS_TYPE_A);
					if (rrset1 != NULL) {
						char ipbuf[INET_ADDRSTRLEN];
						myrr = TAILQ_FIRST(&rrset1->rr_head);
						if (myrr != NULL) {
							inet_ntop(AF_INET, &((struct a *)myrr->rdata)->a, ipbuf, sizeof(ipbuf));
							snprintf(ip6buf, sizeof(ip6buf), "::ffff:%s", ipbuf);
						}
					}

					wrap64(sreply.replybuf, sretlen, ip6);
				}

				/* from delphinusdnsd.c */
				for (rl = &rlogic[0]; rl->rrtype != 0; rl++) {
				    if (rl->rrtype == q->hdr->qtype) {
					slen = (*rl->reply)(&sreply, &sretlen, cfg->db);
					if (slen < 0) {
						/*
						 * we may have a non-dnssec answer cached without RRSIG
						 * at this point the rl->reply will fail.. expire it
						 * and fill it with dnssec data if available
						 */
						expire_rr(db, q->hdr->name, q->hdr->namelen, 
								q->hdr->qtype, highexpire);
						free_question(q);
						goto newqueue;
					}

					switch (from->ss_family) {
					case AF_INET:
						rawsend(cfg->raw[0], sreply.replybuf, sretlen, &sforward->from4, sforward->oldsel, cfg);
						break;
					case AF_INET6:
						rawsend6(cfg->raw[1], sreply.replybuf, sretlen, &sforward->from6, sforward->oldsel, cfg);
						break;
					}
					break;
				    }
				}

				if (rl->rrtype == 0) {
					switch (q->hdr->qtype) {
						/* FALLTHROUGH for all listed */
					case 18: /* AFSDB */ case 42: /* APL */ case 257: /* CAA */
					case 60: /* CDNSKEY */ case 59: /* CDS */ case 37: /* CERT */
					case 62: /* CSYNC */ case 49: /* DHCID */ case 39: /* DNAME */
					case 108: /* EUI48 */ case 109: /* EUI64 */ case 13: /* HINFO */
					case 55: /* HIP */ case 45: /* IPSECKEY */ case 25: /* KEY */
					case 36: /* KX */ case 29: /* LOC */ case 61: /* OPENPGPKEY */
					case 17: /* RP */ case 24: /* SIG */ case 53: /* SMIMEA */
					case 249: /* TKEY */ case 256: /* URI */ 
#if DEBUG
						dolog(LOG_INFO, "replying generic RR %d\n", 
							q->hdr->qtype);
#endif
						if (reply_generic(&sreply, &sretlen, cfg->db) < 0) {
							expire_rr(db, q->hdr->name, q->hdr->namelen, 
								q->hdr->qtype, highexpire);
							free_question(q);
							goto newqueue;
						} 
						switch (from->ss_family) {
						case AF_INET:
							rawsend(cfg->raw[0], sreply.replybuf, sretlen, &sforward->from4, sforward->oldsel, cfg);
							break;
						case AF_INET6:
							rawsend6(cfg->raw[1], sreply.replybuf, sretlen, &sforward->from6, sforward->oldsel, cfg);
							break;
						}
						break;
					default:
							dolog(LOG_INFO, 
								"no answer in our cache, skip to newqueue\n");
							free_question(q);
							goto newqueue;
							break;
					}

					/* NOTREACHED */
				}

				free_question(q);
				/* at this point we return everythign is done */
				return;
			}
		} 

		/* create a new queue and send it */
newqueue:
		/* loop over our forwarders and send a request */
		sessid = arc4random();

		TAILQ_FOREACH(fw2, &forwardhead, forward_entry) {
			char temporary_name[512];

			if ((forwardstrategy == STRATEGY_SINGLE) && (fw2->active == 0))
				continue;

			fwq1 = calloc(1, sizeof(struct forwardqueue));
			if (fwq1 == NULL) {
				dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
				return;
			}
			memcpy(&fwq1->orig_dnsname, sforward->buf, sforward->buflen);
			memcpy(&temporary_name, sforward->buf, sforward->buflen);

			if (randomize_dnsname((char *)&temporary_name, sforward->buflen) == -1) {
				dolog(LOG_INFO, "randomize_dnsname failed\n");
				free (fwq1);
				return;
			}

			memcpy(&fwq1->dnsname, temporary_name, sforward->buflen);
			fwq1->dnsnamelen = sforward->buflen;

			fwq1->oldfamily = sforward->family;
			fwq1->oldsel = sforward->oldsel;

			switch (sforward->family) {
			case AF_INET:
				memcpy(&fwq1->oldhost4, &sforward->from4, sizeof(struct sockaddr_in));
				break;
			case AF_INET6:
				memcpy(&fwq1->oldhost6, &sforward->from6, sizeof(struct sockaddr_in6));
				break;
			}

			fwq1->oldport = sforward->rport;
			fwq1->oldid = sforward->header.id;
			fwq1->type = sforward->type;
			fwq1->edns0len = sforward->edns0len;
			fwq1->region = sforward->region;

			fwq1->port = fw2->destport;
			fwq1->cur_forwardentry = fw2;
			fwq1->sessid = sessid;
			fwq1->longid = arc4random();
			fwq1->id = fwq1->longid % 0xffff;	
			fwq1->time = now;
			fwq1->tries = 1;
			if (so == -1)
				fwq1->istcp = DDD_IS_UDP;
			else
				fwq1->istcp = DDD_IS_TCP;	


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

			fwq1->so = socket(fw2->family, (fwq1->istcp != DDD_IS_TCP) ? SOCK_DGRAM : SOCK_STREAM, 0);
			if (fwq1->so < 0) {
				int save_errno = errno;

				dolog(LOG_ERR, "FORWARD socket: %s\n", strerror(errno));
				if (fwq1->tsigkey)
					free(fwq1->tsigkey);
				free(fwq1);

				if (save_errno == EMFILE || save_errno == ENFILE) {
					/*
					 * we've run out of descriptors, this likely causes a 
					 * deadlock situation so expire all fwq's and closequeues
					 */

					SLIST_FOREACH_SAFE(fwq1, &fwqhead, entries, fwq3) {
						SLIST_REMOVE(&fwqhead, fwq1, forwardqueue, entries);
						if (fwq1->so != -1)
							close(fwq1->so);
						if (fwq1->returnso != -1)
							close(fwq1->returnso);

						if (fwq1->tsigkey)
							free(fwq1->tsigkey);
						free(fwq1);
					}
					SLIST_FOREACH_SAFE(cq2, &closehead, entries, cqp) {
						
						SLIST_REMOVE(&closehead, cq2, closequeue, entries);
						free(cq2);
					}
				}
				return;
			}
			if (setsockopt(fwq1->so, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0){
				dolog(LOG_INFO, "setsockopt failed: %s\n", strerror(errno));
				/* not really fatal */
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

			if (fwq1->istcp == DDD_IS_TCP) {
				if (! firstrun++)
					fwq1->returnso = so;
				else {
					fwq1->returnso = dup(so);
					if (fwq1->returnso == -1) {
						if (fwq1->tsigkey)
							free(fwq1->tsigkey);

						free(fwq1);
						return;
					}
				}
			} else
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

			if (sendit(fwq1, sforward) < 0) {
				if (forwardstrategy == STRATEGY_SPRAY) {
					if (fwq1->istcp == DDD_IS_TCP)
						goto servfail;
					else
						continue;
				} else {
					goto servfail;
				}
			}

#if 0
			if (fwq1->istcp == DDD_IS_TCP)
				break;
#endif
		}
	} else {
		/* resend this one */
		
		/* fwq1->time = now; */
		if (difftime(now, fwq1->time + (fwq1->tries * fwq1->tries)) > -1) {
			if (sendit(fwq1, sforward) < 0)
				goto servfail;
		}
	}


	return;	

servfail:

	odh = (struct dns_header *)&buf[fwq1->istcp == DDD_IS_TCP ? 2 : 0];
	/* send a servfail and remove from list */
	odh->id = fwq1->oldid;
	odh->query = DNS_REPLY;
	SET_DNS_RCODE_SERVFAIL(odh);
	HTONS(odh->query);
	odh->question = htons(1);
	odh->answer = 0;
	odh->nsrr = 0;
	odh->additional = 0;

	p = &buf[sizeof(struct dns_header)];
	pack(p, fwq1->orig_dnsname, fwq1->dnsnamelen);
	p += fwq1->dnsnamelen;
	pack16(p, htons(DNS_CLASS_IN));
	p += 2;
	pack16(p, fwq1->type);
	p += 2;

	if (fwq1->istcp == DDD_IS_TCP) {
		pack16(&buf[0], htons(plength(p, &buf[2])));
		send(fwq1->returnso, buf, plength(p, &buf[0]), 0);
		close(fwq1->returnso);
		fwq1->returnso = -1;
	} else {
		switch (fwq1->oldfamily) {
		case AF_INET:
			rawsend(cfg->raw[0], buf, plength(p, &buf[0]), &fwq1->oldhost4, fwq1->oldsel, cfg);
			break;
		case AF_INET6:
			rawsend6(cfg->raw[1], buf, plength(p, &buf[0]), &fwq1->oldhost6, fwq1->oldsel, cfg);
			break;
		}
	}

	fwq1->answered = 1;

	return;
}

int
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
		return (-1);
	}

	if (fwq->tsigkey) {
		tsigname = dns_label(fwq->tsigkey, &tsignamelen);
		if (tsigname == NULL) {
			dolog(LOG_INFO, "dns_label failed\n");
			free(buf);
			return (-1);
		}
	} else {
		tsigname = NULL;
		tsignamelen = 0;
	}

	q = build_fake_question(fwq->orig_dnsname, fwq->dnsnamelen, sforward->type, tsigname, tsignamelen);

	if (q == NULL) {
		dolog(LOG_INFO, "build_fake_question failed\n");
		free(buf);
		return (-1);
	}

	if (sforward->edns0len)
		q->edns0len = sforward->edns0len;

	if (q->edns0len > 16384)
		q->edns0len = 16384;
	
	if (fwq->istcp == DDD_IS_TCP) {
		p = &buf[2];
	} else
		p = &buf[0];
		
	packet = p;
	dh = (struct dns_header *)p;
	
	memcpy((char *)dh, (char *)&sforward->header, sizeof(struct dns_header));
	dh->id = htons(fwq->id);
	dh->question = htons(1);	
	dh->answer = 0; dh->nsrr = 0; dh->additional = 0;

	memset((char *)&dh->query, 0, sizeof(dh->query));

	SET_DNS_QUERY(dh);
	SET_DNS_RECURSION(dh);
	HTONS(dh->query);

	p += sizeof(struct dns_header);
	len += sizeof(struct dns_header);

	memcpy(p, fwq->dnsname, fwq->dnsnamelen);
	p += fwq->dnsnamelen;
	len += fwq->dnsnamelen;
	
	pack16(p, sforward->type);
	p += 2;
	pack16(p, sforward->class);

	p += 2;
	len += 4;	/* type and class */

	/* additionals */
		
	if (dnssec && sforward->dnssecok) {
		q->dnssecok = 1;
	}


	if (sforward->edns0len) {
		outlen = additional_opt(q, packet, 0xffff, len, NULL, 0, 0);
		if (outlen > len) {
			NTOHS(dh->additional);
			dh->additional++;
			HTONS(dh->additional);
		}
		len = outlen;
	}

	if (tsigname) {
		outlen = additional_tsig(q, packet, 0xffff, len, 1, 0, NULL, fudge_forward);
		if (outlen > len) {
			NTOHS(dh->additional);
			dh->additional++;
			HTONS(dh->additional);
		}
		len = outlen;
	}

	memcpy(&fwq->mac[fwq->tries++ * DNS_HMAC_SHA256_SIZE], &q->tsig.tsigmac, DNS_HMAC_SHA256_SIZE);

	p = packet + len;
	
	if (fwq->istcp == DDD_IS_TCP) {
		pack16(buf, htons(len));
		if (fwq->so != -1 && send(fwq->so, buf, len + 2, 0) < 0) {
			dolog(LOG_INFO, "send() failed changing forwarder: %s\n", strerror(errno));
			changeforwarder(fwq);
			goto fail;
		}
	} else {
		if (fwq->so != -1 && send(fwq->so, buf, len, 0) < 0) {
			dolog(LOG_INFO, "send() failed (udp) changing forwarder %s\n", strerror(errno));
			changeforwarder(fwq);
			goto fail;
		}
	}

	
	free(buf);
	free_question(q);

	return (0);

fail:
	free(buf);
	free_question(q);

	return (-1);
}

int
returnit(ddDB *db, struct cfg *cfg, struct forwardqueue *fwq, char *rbuf, int rlen, struct imsgbuf *ibuf)
{
	struct timeval tv;
	struct dns_header *dh;
	struct question *q;
	static struct pkt_imsg *pi = NULL;
	struct pkt_imsg *pi0;
	struct imsg imsg;
	struct offregion offr;

	static char *buf = NULL;
	char *p;

	int i; 	/* = v/r */
	int sel, rc;
	int len = 0;
	int outlen;

	fd_set rset;
	ssize_t n, datalen;

	if (buf == NULL) {
		buf = calloc(1, 0xffff + 2);
		if (buf == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			return (-1);	
		}
	} else
		memset(buf, 0, 0xffff + 2);

	if (fwq->istcp == DDD_IS_TCP) {
		p = &buf[2];
		len = 2;
	} else {
		p = buf;
	}
		
	if (rlen <= sizeof(struct dns_header)) {
		dolog(LOG_INFO, "FORWARD returnit, returned packet is too small");	
		return (-1);
	}

	memcpy(p, rbuf, rlen);
	dh = (struct dns_header *)p;
	
	if (! (ntohs(dh->query) & DNS_REPLY)) {
		dolog(LOG_INFO, "FORWARD returnit, returned packet is not a reply\n");
		return (-1);
	}

	if (dh->id != htons(fwq->id)) {
		/* returned packet ID does not match */
		dolog(LOG_INFO, "FORWARD returnit, returned packet ID does not match %d vs %d\n", ntohs(dh->id), fwq->id);
		return (-1);
	}

	if (rlen < (sizeof(struct dns_header) + fwq->dnsnamelen)) {
		/* the packet size can't fit the question name */
		dolog(LOG_INFO, "FORWARD returnit, question name can't fit in packet thus it gets dropped\n");
		return (-1);
	} else {
		if (strictx20i) {
			if (memcmp((char *)&dh[1], fwq->dnsname, fwq->dnsnamelen) != 0) {
				dolog(LOG_INFO, "reply for a question we didn't send, drop\n");
				return (-1);
			}
		} else {
			if (memcasecmp((u_char *)&dh[1], (u_char *)fwq->dnsname, fwq->dnsnamelen) != 0) {
				dolog(LOG_INFO, "reply for a question we didn't send, drop\n");
				return (-1);
			}

		}
	}


	/* send it on to our sandbox */
	if (pi == NULL) {
		pi = (struct pkt_imsg *)calloc(1, sizeof(struct pkt_imsg) - sysconf(_SC_PAGESIZE));
		if (pi == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			return (-1);
		}
	} else {
		memset(pi, 0, sizeof(struct pkt_imsg) - sysconf(_SC_PAGESIZE));
	}

	memcpy(&pi->pkt_s.mac, &fwq->mac, sizeof(pi->pkt_s.mac));

	if (fwq->istcp == DDD_IS_TCP) {
		pack32((char *)&pi->pkt_s.buflen, rlen);
	} else {
		if (rlen > (sizeof(struct pkt_imsg) - (sizeof(pi->pkt_s) + sysconf(_SC_PAGESIZE)))) {
			dolog(LOG_INFO, "can't send UDP packet to parser, too big\n");
			return (-1);
		}

		memcpy(&pi->pkt_s.buf, p, rlen);
		pack32((char *)&pi->pkt_s.buflen, rlen);
	}

	if (fwq->tsigkey)
		pack32((char *)&pi->pkt_s.tsigcheck, 1);
	else
		pack32((char *)&pi->pkt_s.tsigcheck, 0);
	
	if (cache)
		pack32((char *)&pi->pkt_s.cache, 1);
	else
		pack32((char *)&pi->pkt_s.cache, 0);

	if (fwq->istcp == DDD_IS_TCP)
		pack32((char *)&pi->pkt_s.istcp, DDD_IS_TCP);
	else
		pack32((char *)&pi->pkt_s.istcp, DDD_IS_UDP);
	
	/* lock */
	sm_lock(cfg->shm[SM_PACKET].shptr, cfg->shm[SM_PACKET].shptrsize);
	pi0 = (struct pkt_imsg *)&cfg->shm[SM_PACKET].shptr[0];
	for (i = 0; i < SHAREDMEMSIZE3; i++, pi0++) {
		if (unpack32((char *)&pi0->pkt_s.read) == 1) {
				memcpy(pi0, pi, sizeof(struct pkt_imsg) - sysconf(_SC_PAGESIZE));
				pack32((char *)&pi0->pkt_s.read, 0);
				break;
		}
	}

	sm_unlock(cfg->shm[SM_PACKET].shptr, cfg->shm[SM_PACKET].shptrsize);

	offr.i = i;
	offr.region = fwq->region;

	if (imsg_compose(ibuf, IMSG_PARSE_MESSAGE, 0, 0, (fwq->istcp == DDD_IS_TCP) ? fwq->so : -1, &offr, sizeof(struct offregion)) < 0) {
			dolog(LOG_INFO, "imsg_compose: %s\n", strerror(errno));
			return (-1);
	}
	msgbuf_write(&ibuf->w);
	
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
			return (-1);
		}

		if (FD_ISSET(ibuf->fd, &rset)) {
			if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN) {
				dolog(LOG_ERR, "returnit internal error around imsg_read, drop\n");
				continue;
			}
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
			if ((n = imsg_get(ibuf, &imsg)) == -1) {
				dolog(LOG_ERR, "returnit internal error around imsg_get, drop\n");
				break;
			}
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
							return (-1);
					}

					memcpy(&rc, imsg.data, datalen);

						if (rc != PARSE_RETURN_ACK) {
							dolog(LOG_ERR, "returnit parser did not ACK this (%d), drop\n", rc);
							imsg_free(&imsg);
							return (-1);
						}

						imsg_free(&imsg);
						break;
			case IMSG_PARSEREPLY_MESSAGE:

					if (datalen != sizeof(int)) {
							dolog(LOG_ERR, "bad parsereply message, drop\n");
							imsg_free(&imsg);
							return (-1);
					}

					memcpy(&i, imsg.data, sizeof(int));

					/* lock */
					sm_lock(cfg->shm[SM_PACKET].shptr, 
						cfg->shm[SM_PACKET].shptrsize);
					pi0 = (struct pkt_imsg *)&cfg->shm[SM_PACKET].shptr[0];
					pi0 = &pi0[i];

					memcpy(pi, pi0, sizeof(struct pkt_imsg) - sysconf(_SC_PAGESIZE));

					pack32((char *)&pi0->pkt_s.read, 1);
					sm_unlock(cfg->shm[SM_PACKET].shptr, 
						cfg->shm[SM_PACKET].shptrsize);

				if (fwq->istcp == DDD_IS_TCP) 
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
	if (fwq->tsigkey && (unpack32((char *)&pi->pkt_s.tsig.have_tsig) == 0 \
		|| unpack32((char *)&pi->pkt_s.tsig.tsigverified) == 0)) {
		char ipdest[INET6_ADDRSTRLEN];

		switch (fwq->family) {
		case AF_INET:
			inet_ntop(fwq->family, &((struct sockaddr_in *)&fwq->host)->sin_addr, (void*)&ipdest, sizeof(ipdest));
			break;
		case AF_INET6:
			inet_ntop(fwq->family, &((struct sockaddr_in6 *)&fwq->host)->sin6_addr, (void*)&ipdest, sizeof(ipdest));
			break;	
		}

		dolog(LOG_ERR, "FORWARD returnit, TSIG didn't check out error code = %d from %s port %u (ID: %x)\n", unpack32((char *)&pi->pkt_s.tsig.tsigerrorcode), ipdest, fwq->port, fwq->id);
		return (-1);
	}

	/* read back our, now modified packet */
	memcpy(p, &pi->pkt_s.buf, rlen);
	dh = (struct dns_header *)p;


#if 0
	if (unpack32((char *)&pi->pkt_s.tsig.have_tsig) == 1) {
		NTOHS(dh->additional);
		if (dh->additional > 0)
			dh->additional = nowrap_dec(dh->additional, 1);
		HTONS(dh->additional);
	}
#endif

	if (unpack32((char *)&pi->pkt_s.tsigcheck) == 1)
		rlen = unpack32((char *)&pi->pkt_s.tsig.tsigoffset);

	
	/* add new tsig if needed */
	pack16((char *)&dh->id, fwq->oldid);

	NTOHS(dh->query);
	dh->query &= ~(DNS_AUTH);		/* take AA answers out */
	SET_DNS_RECURSION(dh);
	SET_DNS_RECURSION_AVAIL(dh);
	HTONS(dh->query);

	/* restore any possible 0x20 caseings, must be after TSIG checks  */
	memcpy((char *)&dh[1], fwq->orig_dnsname, fwq->dnsnamelen);

	/*
	 * if the region matches return a v4 mapped v6 address
	 */

	if (wrap6to4region != 0xffff && 
		fwq->region == (uint8_t)wrap6to4region) {
		struct rbtree *rbt;
		struct rrset *rrset1 = NULL;
		struct rr *myrr;

		char ip6buf[INET6_ADDRSTRLEN];
		char *ip6 = ip6buf;

		strlcpy(ip6buf, "::ffff:127.0.0.1", sizeof(ip6buf));

		rbt = find_rrset(db, fwq->orig_dnsname, fwq->dnsnamelen);

		if (rbt != NULL)
			rrset1 = find_rr(rbt, DNS_TYPE_A);

		if (rrset1 != NULL) {
			char ipbuf[INET_ADDRSTRLEN];
			myrr = TAILQ_FIRST(&rrset1->rr_head);
			if (myrr != NULL) {
				inet_ntop(AF_INET, &((struct a *)myrr->rdata)->a, ipbuf, sizeof(ipbuf));
				snprintf(ip6buf, sizeof(ip6buf), "::ffff:%s", ipbuf);
			}
		}

		wrap64(fwq->istcp == DDD_IS_UDP ? buf: &buf[2], rlen, ip6);
	}

	if (fwq->istcp == DDD_IS_UDP && rlen > (fwq->edns0len ? fwq->edns0len : 512)) {
		SET_DNS_TRUNCATION(dh);
		dh->answer = 0;
		dh->nsrr = 0;
		dh->additional = 0;

		/* shave off the rest */
		rlen = (sizeof(struct dns_header) + fwq->dnsnamelen + \
			(2 * sizeof(uint16_t)));
	}

	if (fwq->haveoldmac) {
		q = build_fake_question(fwq->orig_dnsname, fwq->dnsnamelen, htons(DNS_TYPE_A), fwq->oldkeyname, fwq->oldkeynamelen);

		if (q == NULL) {
			dolog(LOG_INFO, "build_fake_question failed\n");
			return (-1);
		}
		
		if (fwq->edns0len)
			q->edns0len = fwq->edns0len;

		memcpy(&q->tsig.tsigmac, &fwq->oldmac, DNS_HMAC_SHA256_SIZE);
		q->tsig.tsigmaclen = DNS_HMAC_SHA256_SIZE;
		q->tsig.tsigalglen = 13;
		q->tsig.tsigerrorcode = 0;
		q->tsig.tsigorigid = fwq->oldid;
		q->tsig.have_tsig = 1;
		q->tsig.tsig_timefudge = fwq->tsigtimefudge;

		outlen = additional_tsig(q, p, 0xffff, rlen, 0, 0, NULL, fudge_forward);
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
	
	if (fwq->istcp == DDD_IS_TCP) {
		pack16(buf, htons(rlen));
		if (send(fwq->returnso, buf, len, 0) != len)
			dolog(LOG_INFO, "send(): %s\n", strerror(errno));
		close(fwq->returnso);	/* only close the tcp stream */
		fwq->returnso = -1;	

	} else {
		
		switch (fwq->oldfamily) {
		case AF_INET:
			rawsend(cfg->raw[0], buf, len, &fwq->oldhost4, fwq->oldsel, cfg);
			break;
		case AF_INET6:
			rawsend6(cfg->raw[1], buf, len, &fwq->oldhost6, fwq->oldsel, cfg);
			break;
		}
	}

	fwq->answered = 1;

	return (0);
}

struct tsig *
check_tsig(char *buf, int len, char *mac)
{
	char pseudo_packet[4096];		/* for tsig */
	char expand[DNS_MAXNAME + 1];
	u_int rollback, i, j;
	uint16_t type, rdlen;
	uint64_t timefudge;
	int elen = 0;
	int additional;

	char *o, *pb;

	struct dns_tsigrr *tsigrr = NULL;
	struct dns_optrr *opt = NULL;
	struct dns_header *hdr; 
	struct tsig *rtsig;

	const DDD_EVP_MD *md;
	
	md = (DDD_EVP_MD *)delphinusdns_EVP_get_digestbyname("sha256");
	if (md == NULL) {
		dolog(LOG_INFO, "could not initialize md\n");
		return NULL;
	}
		
	hdr = (struct dns_header *)&buf[0];
	
#if __OpenBSD__
	rtsig = (void *)calloc_conceal(1, sizeof(struct tsig));
#else
	rtsig = (void *)calloc(1, sizeof(struct tsig));
#endif
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
#if __OpenBSD__
		freezero(rtsig, sizeof(struct tsig));
#else
		free(rtsig);
#endif
		return NULL;
	}
	i = (plength(pb, buf));
	if (i > len) {
#if __OpenBSD__
		freezero(rtsig, sizeof(struct tsig));
#else
		free(rtsig);
#endif
		return NULL;
	}

	i += (2 * sizeof(uint16_t));	/*  type,class */

	/* skip any payloads other than additional */
	
	additional = ntohs(hdr->additional);
	j = ntohs(hdr->answer) + ntohs(hdr->nsrr) + ntohs(hdr->additional);

	for (;j > 0; j = nowrap_dec(j, 1)) {
		rollback = i;
		/* the name is parsed here */
		elen = 0;
		memset(&expand, 0, sizeof(expand));
		pb = expand_compression((u_char *)&buf[i], (u_char *)buf, (u_char *)&buf[len], (u_char *)&expand, &elen, sizeof(expand));
		if (pb == NULL) {
			dolog(LOG_INFO, "expand_compression() failed -1\n");
#if __OpenBSD__
			freezero(rtsig, sizeof(struct tsig));
#else
			free(rtsig);
#endif
			return NULL;
		}
		i = (plength(pb, buf));
		if (i > len) {
#if __OpenBSD__
			freezero(rtsig, sizeof(struct tsig));
#else
			free(rtsig);
#endif
			return NULL;
		}

		type = ntohs(unpack16(&buf[i]));
		if (type == DNS_TYPE_OPT || type == DNS_TYPE_TSIG) {
			i = rollback;
			break;
		}
			
		i += 8;		/* skip type, class, ttl */
		if (i > len) {
#if __OpenBSD__
			freezero(rtsig, sizeof(struct tsig));
#else
			free(rtsig);
#endif
			return NULL;
		}
		
		rdlen = unpack16(&buf[i]);
		i += 2;			/* skip rdlen */
		i += ntohs(rdlen);	/* skip rdata, next */

		if (i > len) {
#if __OpenBSD__
			freezero(rtsig, sizeof(struct tsig));
#else
			free(rtsig);
#endif
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

#if 0
		/* RFC 3225 */
		ttl = ntohl(opt->ttl);
#endif

		i += 11 + ntohs(opt->rdlen);
		if (i > len) {
#if __OpenBSD__
			freezero(rtsig, sizeof(struct tsig));
#else
			free(rtsig);
#endif
			return NULL;
		}
		additional--;
	} while (0);
	/* check for TSIG rr */
	do {
		uint16_t val16, tsigerror, tsigotherlen;
		uint16_t fudge;
		uint32_t val32;
		int elen, tsignamelen;
		char tsigkey[512];
		u_char sha256[DNS_HMAC_SHA256_SIZE];
		u_int shasize = sizeof(sha256);
		time_t now, tsigtime;
		int pseudolen1, pseudolen2, ppoffset = 0;
		int pseudolen3 , pseudolen4;
		int mcheck = 0;
		char *macoffset = NULL;

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
#if __OpenBSD__
			freezero(rtsig, sizeof(struct tsig));
#else
			free(rtsig);
#endif
			return NULL;
		}
		i = (plength(pb, buf));
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
#if __OpenBSD__
			freezero(rtsig, sizeof(struct tsig));
#else
			free(rtsig);
#endif
			return NULL;
		}
		i = (plength(pb, buf));
		pseudolen4 = i;

		memcpy(rtsig->tsigalg, expand, elen);
		rtsig->tsigalglen = elen;
			
		/* now check for MAC type, since it's given once again */
		if (elen == 11) {
			if (expand[0] != 9 ||
				memcasecmp((u_char *)&expand[1], (u_char *)"hmac-sha1", 9) != 0) {
				break;
			}
		} else if (elen == 13) {
			if (expand[0] != 11 ||
				memcasecmp((u_char *)&expand[1], (u_char *)"hmac-sha256", 11) != 0) {
				break;
			}
		} else if (elen == 26) {
			if (expand[0] != 8 ||
				memcasecmp((u_char *)&expand[1], (u_char *)"hmac-md5", 8) != 0) {
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
		fudge = (uint16_t)(timefudge & 0xffff);
		tsigtime = (uint64_t)(timefudge >> 16);

		rtsig->tsig_timefudge = tsigrr->timefudge;
		
		i += (8 + 2);		/* timefudge + macsize */

		if (ntohs(tsigrr->macsize) != DNS_HMAC_SHA256_SIZE) {
#if DEBUG
			dolog(LOG_INFO, "bad macsize\n");
#endif
			rtsig->tsigerrorcode = DNS_BADSIG; 
			break; 
		}

		i += ntohs(tsigrr->macsize);
	

		/* now get the MAC from packet with length rollback */
		NTOHS(hdr->additional);
		hdr->additional = nowrap_dec(hdr->additional, 1);
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

		/* add mac, we always check answers */
		o = &pseudo_packet[ppoffset];
		pack16(o, htons(DNS_HMAC_SHA256_SIZE));
		ppoffset += 2;

		macoffset = &pseudo_packet[ppoffset];
#if 0
		memcpy(&pseudo_packet[ppoffset], &mac[0], DNS_HMAC_SHA256_SIZE);
#endif
		ppoffset += DNS_HMAC_SHA256_SIZE;

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

		for (mcheck = 0; mcheck < 5; mcheck++) {
			rtsig->tsigerrorcode = 0;

			memcpy(macoffset, &mac[DNS_HMAC_SHA256_SIZE * mcheck], DNS_HMAC_SHA256_SIZE);
			
			delphinusdns_HMAC(md, tsigkey, tsignamelen, 
					(unsigned char *)pseudo_packet, ppoffset, 
							(unsigned char *)&sha256, &shasize);

#if defined __OpenBSD__ || defined __FreeBSD__
			if (timingsafe_memcmp(sha256, tsigrr->mac, sizeof(sha256)) != 0) {
#else
			if (memcmp(sha256, tsigrr->mac, sizeof(sha256)) != 0) {
#endif
#if DEBUG
				dolog(LOG_INFO, "HMAC %d did not verify\n", mcheck);
#endif
				rtsig->tsigerrorcode = DNS_BADSIG;
				if (mcheck == 4)
					goto errout;
			} else 
				break;
		} /* for mcheck */

		/* copy the mac for error coding */
		memcpy(rtsig->tsigmac, tsigrr->mac, sizeof(rtsig->tsigmac));
		rtsig->tsigmaclen = DNS_HMAC_SHA256_SIZE;
		
		/* we're now authenticated */
		rtsig->tsigerrorcode = 0;
		rtsig->tsigverified = 1;
		
	} while (0);

errout:

	/* parse type and class from the question */
	return (rtsig);
}

void
fwdparseloop(struct imsgbuf *ibuf, struct imsgbuf *bibuf, struct cfg *cfg)
{
	int fd = ibuf->fd;
	int sel, istcp = DDD_IS_UDP;
	int rlen, tmp, rc, i;

	struct tsig *stsig = NULL;
	struct pkt_imsg *pi, *pi0;
	struct imsg imsg;
	struct dns_header *dh;

	char mac[DNS_HMAC_SHA256_SIZE * 5];
	char *packet = NULL;
	char *q = NULL;
	u_char *end, *estart;
	fd_set rset;
	ssize_t n, datalen;
	int flags;

#ifdef __FreeBSD__
        cap_rights_t rights;
#endif

	flags = fcntl(bibuf->fd, F_GETFL);
	if (flags < 0) {
		dolog(LOG_INFO, "fcntl: %s\n", strerror(errno));
	} else {
		flags |= O_NONBLOCK;
		if (fcntl(bibuf->fd, F_SETFL, &flags) < 0) {
			dolog(LOG_INFO, "fcntl: %s\n", strerror(errno));
		}
	}

	setlogmask(LOG_UPTO(LOG_ERR));

#if __OpenBSD__
	if (pledge("stdio sendfd recvfd unveil", NULL) < 0) {
		perror("pledge");
		ddd_shutdown();
		exit(1);
	}
	if (unveil(NULL, NULL) == -1) {
		perror("unveil");
		ddd_shutdown();
		exit(1);
	}
#endif
#ifdef __FreeBSD__
	cap_rights_init(&rights, CAP_WRITE, CAP_READ, CAP_EVENT);

	if (cap_rights_limit(fd, &rights) < 0) {
		dolog(LOG_ERR, "cap_rights_limit: %s\n", strerror(errno));
		ddd_shutdown();
		exit(1);
	}
#endif


	pi = (struct pkt_imsg *)calloc(1, sizeof(struct pkt_imsg) - sysconf(_SC_PAGESIZE));
	if (pi == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		ddd_shutdown();
		exit(1);
	}


	for (;;) {
		if (istcp == DDD_IS_TCP && packet != NULL) {
			free(packet);
			packet = NULL;
		}

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
				if (istcp == DDD_IS_TCP && packet != NULL) {
					free(packet);
					packet = NULL;
				}
			
				if ((n = imsg_get(ibuf, &imsg)) == -1) {
					break;
				}

				if (n == 0) {
					break;
				}

				datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

				switch (imsg.hdr.type) {
				case IMSG_PARSE_MESSAGE:
					if (datalen != sizeof(struct offregion)) {
						rc = PARSE_RETURN_NAK;
						imsg_compose(ibuf, IMSG_PARSEERROR_MESSAGE, 0, 0, imsg.fd, &rc, sizeof(int));
						msgbuf_write(&ibuf->w);
						break;
					}
					
					q = imsg.data;
					i = unpack32(q);

					/* lock */
					sm_lock(cfg->shm[SM_PACKET].shptr, 
						cfg->shm[SM_PACKET].shptrsize);
					pi0 = (struct pkt_imsg *)&cfg->shm[SM_PACKET].shptr[0];
					pi0 = &pi0[i];

					memcpy(pi, pi0, sizeof(struct pkt_imsg) - sysconf(_SC_PAGESIZE));
					pack32((char *)&pi0->pkt_s.read, 1);

					sm_unlock(cfg->shm[SM_PACKET].shptr, 
							cfg->shm[SM_PACKET].shptrsize);

					istcp = unpack32((char *)&pi->pkt_s.istcp);

					if (istcp == DDD_IS_TCP) {
						packet = malloc(unpack32((char *)&pi->pkt_s.buflen));
						if (packet == NULL) {
							dolog(LOG_INFO, "malloc %s\n", strerror(errno));
							rc = PARSE_RETURN_NAK;
							/* send the descriptor back to them */
							imsg_compose(ibuf, IMSG_PARSEERROR_MESSAGE, 0, 0, imsg.fd, &rc, sizeof(int));
							msgbuf_write(&ibuf->w);
							break;
						}


						rlen = unpack32((char *)&pi->pkt_s.buflen);

						if (recv(imsg.fd, packet, rlen, MSG_WAITALL) < 0) {
							dolog(LOG_INFO, "recv in forward sandbox: %s\n", strerror(errno));
							rc = PARSE_RETURN_NAK;
							/* send the descriptor back to them */
							imsg_compose(ibuf, IMSG_PARSEERROR_MESSAGE, 0, 0, imsg.fd, &rc, sizeof(int));
							msgbuf_write(&ibuf->w);
							free(packet);
							packet = NULL;
							break;
						}
#if DEBUG
						dolog(LOG_INFO, "received %d bytes from descriptor %d\n", unpack32((char *)&pi->pkt_s.buflen), imsg.fd);
#endif
					} else
						packet = &pi->pkt_s.buf[0];

					tmp = unpack32((char *)&pi->pkt_s.buflen);
					if (tmp < sizeof(struct dns_header)) {
						/* SEND NAK */
						rc = PARSE_RETURN_NAK;
						imsg_compose(ibuf, IMSG_PARSEERROR_MESSAGE, 0, 0, (istcp == DDD_IS_TCP) ? imsg.fd : -1, &rc, sizeof(int));
						msgbuf_write(&ibuf->w);
						if (istcp == DDD_IS_TCP) {
							free(packet);
							packet = NULL;
						}
						break;
					}
					dh = (struct dns_header *)packet;

					if (! (ntohs(dh->query) & DNS_REPLY)) {
						rc = PARSE_RETURN_NOTAREPLY;
						imsg_compose(ibuf, IMSG_PARSEERROR_MESSAGE, 0, 0, (istcp == DDD_IS_TCP) ? imsg.fd : -1, &rc, sizeof(int));
						msgbuf_write(&ibuf->w);
						if (istcp == DDD_IS_TCP) {
							free(packet);
							packet = NULL;
						}
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
						imsg_compose(ibuf, IMSG_PARSEERROR_MESSAGE, 0, 0, (istcp == DDD_IS_TCP) ? imsg.fd : -1, &rc, sizeof(int));
						msgbuf_write(&ibuf->w);
						if (istcp == DDD_IS_TCP) {
							free(packet);
							packet = NULL;
						}
						break;
					}

					rlen = tmp;
			
					if (unpack32((char *)&pi->pkt_s.tsigcheck)) {
							memcpy((char *)&mac, (char *)&pi->pkt_s.mac, sizeof(mac));
							stsig = check_tsig((char *)packet, rlen, mac);
							if (stsig == NULL) {
								dolog(LOG_INFO, "FORWARD parser, malformed reply packet\n");
								rc = PARSE_RETURN_MALFORMED;

								imsg_compose(ibuf, IMSG_PARSEERROR_MESSAGE, 0, 0, (istcp == DDD_IS_TCP) ? imsg.fd : -1, &rc, sizeof(int));
								msgbuf_write(&ibuf->w);
			
								if (istcp == DDD_IS_TCP) {
									free(packet);
									packet = NULL;
								}
								break;
							}

							memcpy(&pi->pkt_s.tsig, stsig, sizeof(struct tsig));
					}

					/* 
					 * lowercase names - linux doesn't
					 * 	so we must hack around it
					 */

					parse_lowercase(packet, rlen);

					/* check for cache */
					if (unpack32((char *)&pi->pkt_s.cache)) {
							estart = (u_char *)packet;
							rlen = tmp;
							end = (u_char *)&packet[rlen];

							if (cacheit((u_char *)packet, estart, end, ibuf, bibuf, cfg) < 0) {
								dolog(LOG_INFO, "cacheit failed\n");
							}
					}

#if 0
					/*
					 * if we wrap IPv6 to IPv4, modify it
					 *
					 */
					if ((wrap6to4region != 0xffff) &&
						region == (uint8_t)wrap6to4region) {
						wrap64(packet, rlen, "::ffff:1.2.3.4");
					}
#endif


					pack32((char *)&pi->pkt_s.rc, PARSE_RETURN_ACK);

					sm_lock(cfg->shm[SM_PACKET].shptr, 
						cfg->shm[SM_PACKET].shptrsize);
					pi0 = (struct pkt_imsg *)&cfg->shm[SM_PACKET].shptr[0];
					for (i = 0; i < SHAREDMEMSIZE3; i++, pi0++) {
						if (unpack32((char *)&pi0->pkt_s.read) == 1) {
							memcpy(pi0, pi, sizeof(struct pkt_imsg) - sysconf(_SC_PAGESIZE));
							if (istcp == DDD_IS_TCP) {
								memcpy(pi0->pkt_s.buf, packet, rlen);
								pack32((char *)&pi0->pkt_s.buflen, rlen);
							}
							pack32((char *)&pi0->pkt_s.read, 0);
							break;
						}
					}

					imsg_compose(ibuf, IMSG_PARSEREPLY_MESSAGE, 0, 0, (istcp == DDD_IS_TCP) ? imsg.fd : -1, &i, sizeof(int));
					msgbuf_write(&ibuf->w);

					sm_unlock(cfg->shm[SM_PACKET].shptr, 
							cfg->shm[SM_PACKET].shptrsize);

					free(stsig);

					if (istcp == DDD_IS_TCP) {
						free(packet);
						packet = NULL;
					}
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
	if (forwardstrategy == STRATEGY_SPRAY)
		return;

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

	if (forwardstrategy == STRATEGY_SPRAY)
		return;

	TAILQ_FOREACH(fwp, &forwardhead, forward_entry) {
		fwp->active = 0;
		count++;
	}

	if (count == 0)
		return;

	randomforwarder = arc4random_uniform(count);

	count = 0;
	TAILQ_FOREACH(fwp, &forwardhead, forward_entry) {
		if (randomforwarder == count) {
			dolog(LOG_INFO, "stirforwarders: %s is now active\n", fwp->name);
			fwp->active = 1;
		}

		count++;
	}
}

int
rawsend(int so, char *buf, uint16_t len, struct sockaddr_in *sin, int oldsel, struct cfg *cfg)
{
	struct udphdr uh;	
	struct ip ip;
	struct msghdr msg;
	struct iovec iov[2];

	if (len == 0) {
		dolog(LOG_INFO, "rawsend:  not sending with len == 0\n");
		return 0;
	}

	memcpy(&ip.ip_src.s_addr, (void*)&(((struct sockaddr_in *)&cfg->ss[oldsel])->sin_addr.s_addr), sizeof(in_addr_t));
	memcpy(&ip.ip_dst.s_addr, (void*)&sin->sin_addr, sizeof(in_addr_t));
	ip.ip_p = IPPROTO_UDP;

	memset(&uh, 0, sizeof(uh));
	uh.uh_sport = htons(cfg->port);
	uh.uh_dport = sin->sin_port;
	uh.uh_ulen = htons(len + sizeof(struct udphdr));
	uh.uh_sum = 0;
	uh.uh_sum = udp_cksum((uint16_t *)buf,  \
			len + sizeof(struct udphdr), &ip, &uh);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = sin;
	msg.msg_namelen = sizeof(struct sockaddr_in);
	iov[0].iov_base = &uh;
	iov[0].iov_len = sizeof(struct udphdr);
	iov[1].iov_base = buf;
	iov[1].iov_len = len;
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;
	
	return (sendmsg(so, &msg, 0));
}
int
rawsend6(int so, char *buf, uint16_t len, struct sockaddr_in6 *sin6, int oldsel,  struct cfg *cfg)
{
	struct udphdr uh;	
	struct ip6_hdr ip6;
	struct msghdr msg;
	struct iovec iov[2];

	if (len == 0) {
		dolog(LOG_INFO, "rawsend:  not sending with len == 0\n");
		return 0;
	}

	memcpy(&ip6.ip6_src, (void*)&(((struct sockaddr_in6 *)&cfg->ss[oldsel])->sin6_addr), sizeof(struct in6_addr));
	memcpy(&ip6.ip6_dst, (void*)&sin6->sin6_addr, sizeof(struct in6_addr));
	ip6.ip6_nxt = IPPROTO_UDP;


	memset(&uh, 0, sizeof(uh));
	uh.uh_sport = htons(cfg->port);
	uh.uh_dport = sin6->sin6_port;
	uh.uh_ulen = htons(len + sizeof(struct udphdr));
	uh.uh_sum = 0;
	uh.uh_sum = udp_cksum6((uint16_t *)buf,  \
			len + sizeof(struct udphdr), &ip6, &uh);

#ifdef __linux__
	sin6->sin6_port = htons(IPPROTO_UDP);
#endif

	memset(&msg, 0, sizeof(msg));

	msg.msg_name = sin6;
	msg.msg_namelen = sizeof(struct sockaddr_in6);

	iov[0].iov_base = &uh;
	iov[0].iov_len = sizeof(struct udphdr);
	iov[1].iov_base = buf;
	iov[1].iov_len = len;
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;
	
	return (sendmsg(so, &msg, 0));
}

void
dump_cache(ddDB *db, struct imsgbuf *ibuf)
{
	struct node *walk, *walk0;
	struct rbtree *rbt = NULL;
	struct rrset *rr;
	char rrbuf[512];
	char buf[512];
	time_t now, ttl;
	int i;
	
	dolog(LOG_INFO, "dumping cache\n");
	now = time(NULL);

	RB_FOREACH_SAFE(walk, domaintree, &db->head, walk0) {
		rbt = (struct rbtree *)walk->data;
		if (rbt == NULL)
			continue;

		memset(&rrbuf, 0, sizeof(rrbuf));

		for (i = DNS_TYPE_A; i < DNS_TYPE_MAX; i++) {
			if ((rr = find_rr(rbt, i)) == NULL)
				continue;
			else {
				snprintf(buf, sizeof(buf), " %s:%llu,"
					, get_dns_type(rr->rrtype, 1)
					, (ttl = rr->ttl - (time_t)difftime(now, rr->created)) >= 0 ? ttl : 0);

				strlcat(rrbuf, buf, sizeof(rrbuf));
			}
		}

		snprintf(buf, sizeof(buf), "%-32s%s", rbt->humanname, rrbuf);
		imsg_compose(ibuf, IMSG_DUMP_CACHEREPLY, 0, 0, -1, buf, strlen(buf) + 1);
		msgbuf_write(&ibuf->w);
	}

	imsg_compose(ibuf, IMSG_DUMP_CACHEREPLYEOF, 0, 0, -1, "*", 1);
	msgbuf_write(&ibuf->w);
}

void
parse_lowercase(char *packet, int len)
{
	struct dns_header *hdr = (struct dns_header *)packet;
	u_char expand[DNS_MAXNAME + 1];
	char *end_name = NULL;
	int rlen, i, elen = 0;
	int tmplen;
	uint16_t val16;
	

	if (len < sizeof(struct dns_header))
		return;

	i = sizeof(struct dns_header);
        elen = 0;
        memset(&expand, 0, sizeof(expand));
        end_name = expand_compression((u_char *)&packet[i], (u_char *)packet, (u_char *)&packet[len], (u_char *)&expand, &elen, sizeof(expand));
        if (end_name == NULL) {
                dolog(LOG_ERR, "expand_compression() failed 1, bad formatted question name\n");
                return;
        }

	rlen = (plength(end_name, (void *)&packet[i]));
        if (rlen == elen) {
		lower_dnsname((char *)&packet[i], rlen);
	}

	i += (rlen + sizeof(uint16_t) + sizeof(uint16_t)); /* skip clas,type */
	
	tmplen = ntohs(hdr->answer) + ntohs(hdr->nsrr) + ntohs(hdr->additional);

	for (int j = 0; (i <= len) && (j < tmplen); j++) {
		elen = 0;
		memset(&expand, 0, sizeof(expand));
		end_name = expand_compression((u_char *)&packet[i], (u_char *)\
			packet, (u_char *)&packet[len], (u_char *)&expand, \
			&elen, sizeof(expand));
        	if (end_name == NULL) {
                	dolog(LOG_ERR, "expand_compression() failed 2, bad formatted name\n");
                	return;
        	}
		rlen = (plength(end_name, (void *)&packet[i]));
		lower_dnsname((char *)&packet[i], rlen);

		i += rlen;
		
		val16 = unpack16((char *)&packet[i]);
		switch (ntohs(val16)) {	
		case DNS_TYPE_CNAME:
		case DNS_TYPE_NS:
		case DNS_TYPE_PTR:
			if ((i + 10) > len)
				goto out;

			i += 8;		/* type, class, ttl */
			val16 = unpack16((char *)&packet[i]);

			i += 2;		/* rdlen */
			
			elen = 0;
			memset(&expand, 0, sizeof(expand));
			end_name = expand_compression((u_char *)&packet[i], (u_char *)\
				packet, (u_char *)&packet[len], (u_char *)&expand, \
				&elen, sizeof(expand));
			if (end_name == NULL) {
				dolog(LOG_ERR, "expand_compression() failed 3, bad formatted name\n");
				return;
			}
			rlen = (plength(end_name, (void *)&packet[i]));
			if (rlen == ntohs(val16))
				lower_dnsname(&packet[i], rlen);

			if ((i + ntohs(val16)) > len)
				goto out;

			i += ntohs(val16);
			break;
		default:
			if ((i + 8) > len)
				goto out;

			i += 8;		/* type, class, ttl */
			val16 = unpack16((char *)&packet[i]);

			if ((2 + i + ntohs(val16)) > len)
				goto out;

			i += (2 + ntohs(val16));		/* rdlen + rdlen contents */
			break;	
		}	/* switch */
	} /* for(;;) */

out:
	/* we're done here just return */
	return;
}

void
wrap64(char *packet, int len, char *alternative)
{
	struct dns_header *dh = NULL;
	struct aaaa *sqa;
	u_char expand[DNS_MAXNAME + 1];
	char *end_name;
	char *p, *begin, *end;
	int rlen, elen = 0;
	int countrr = 0;

	uint16_t val16;

	if (packet == NULL)
		return;

	begin = p = packet;
	end = packet + len;

	if (len < sizeof(struct dns_header))
		return;

	dh = (struct dns_header *)p;

	countrr = ntohs(dh->answer) + ntohs(dh->nsrr) + ntohs(dh->additional);

	p += sizeof(struct dns_header);
	len -= sizeof(struct dns_header);	
	
        elen = 0;
        memset(&expand, 0, sizeof(expand));
        end_name = expand_compression((u_char *)p, (u_char *)packet, (u_char *)end, (u_char *)&expand, &elen, sizeof(expand));
        if (end_name == NULL) {
                dolog(LOG_ERR, "expand_compression() failed 1, bad formatted question name\n");
                return;
        }

	rlen = (plength(end_name, (void *)p));
        if (rlen == elen) {
		p += rlen;
		len -= rlen;
	}
	
	p += (sizeof(uint16_t) + sizeof(uint16_t)); 	/* skip class,type */
	len -= (sizeof(uint16_t) + sizeof(uint16_t));
	
	for (int j = 0, i = 0; (i <= len) && (j < countrr); j++) {
		elen = 0;
		memset(&expand, 0, sizeof(expand));
		end_name = expand_compression((u_char *)&p[i], (u_char *)\
			begin, (u_char *)end, (u_char *)&expand, \
			&elen, sizeof(expand));
        	if (end_name == NULL) {
                	dolog(LOG_ERR, "expand_compression() failed 2, bad formatted name\n");
                	return;
        	}
		rlen = (plength(end_name, (void *)&p[i]));
		i += rlen;
		
		val16 = unpack16((char *)&p[i]);
		switch (ntohs(val16)) {
		case DNS_TYPE_AAAA:
			if ((i + 8) > len)
				goto out;

			i += 8;		/* type, class, ttl */
			val16 = unpack16((char *)&p[i]);

			if ((2 + i + ntohs(val16)) > len)
				goto out;


			i += 2;
			sqa = (struct aaaa *)&p[i];
			if (alternative) {
				inet_pton(AF_INET6, alternative, (void *)&sqa->aaaa);
			} else {
				inet_pton(AF_INET6, "::ffff:127.0.0.1", (void *)&sqa->aaaa);
			}
			i += (ntohs(val16));		/* rdata contents */

			break;

		default:
			if ((i + 8) > len)
				goto out;

			i += 8;		/* type, class, ttl */
			val16 = unpack16((char *)&p[i]);

			if ((2 + i + ntohs(val16)) > len)
				goto out;

			i += (2 + ntohs(val16));		/* rdlen + rdlen contents */
			break;	
		}
	}
out:
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
