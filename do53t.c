/*
 * Copyright (c) 2022 Peter J. Philipp <pjp@delphinusdns.org>
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
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/resource.h>

#include <net/if.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <ctype.h>
#include <pwd.h>
#include <ifaddrs.h>
#include <dirent.h>
#include <signal.h>
#include <time.h>

#ifdef __linux__
#include <linux/bpf.h>
#include <linux/filter.h>
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
#include "ddd-config.h"

/* prototypes */

extern char		*convert_name(char *, int);
extern char *		get_dns_type(int, int);
extern int		free_question(struct question *);
extern int		reply_nodata(struct sreply *, int *, ddDB *);
extern int		reply_notify(struct sreply *, int *, ddDB *);
extern int 		find_filter(struct sockaddr_storage *, int);
extern int 		find_passlist(struct sockaddr_storage *, int);
extern int 		memcasecmp(u_char *, u_char *, int);
extern int 		notifysource(struct question *, struct sockaddr_storage *);
extern int 		reply_badvers(struct sreply *, int *, ddDB *);
extern int 		reply_fmterror(struct sreply *, int *, ddDB *);
extern int 		reply_noerror(struct sreply *, int *, ddDB *);
extern int 		reply_notauth(struct sreply *, int *, ddDB *);
extern int 		reply_notimpl(struct sreply *, int *, ddDB *);
extern int 		reply_ns(struct sreply *, int *, ddDB *);
extern int 		reply_nxdomain(struct sreply *, int *, ddDB *);
extern int 		reply_refused(struct sreply *, int *, ddDB *, int);
extern int 		reply_version(struct sreply *, int *, ddDB *);
extern int 		send_to_parser(struct cfg *, struct imsgbuf *, char *, int, struct parsequestion *);
extern int 		tsigpassname_contains(char *, int, int *);
extern int     		find_axfr(struct sockaddr_storage *, int);
extern int      	find_tsig(struct sockaddr_storage *, int);
extern struct question	*build_fake_question(char *, int, uint16_t, char *, int);
extern struct question	*convert_question(struct parsequestion *, int);
extern struct rbtree * 	get_soa(ddDB *, struct question *);
extern struct rbtree * 	lookup_zone(ddDB *, struct question *, int *, int *, char *, int);
extern struct rbtree *  Lookup_zone(ddDB *, char *, uint16_t, uint16_t, int);
extern struct rrset * 	find_rr(struct rbtree *rbt, uint16_t rrtype);
extern uint16_t 	unpack16(char *);
extern uint32_t 	unpack32(char *);
extern uint8_t 		find_region(struct sockaddr_storage *, int);
extern void		sm_lock(char *, size_t);
extern void		sm_unlock(char *, size_t);
extern void 		build_reply(struct sreply *, int, char *, int, struct question *, struct sockaddr *, socklen_t, struct rbtree *, struct rbtree *, uint8_t, int, int, char *, struct tls *);
extern void 		ddd_shutdown(void);
extern void 		dolog(int, char *, ...);
extern void 		pack(char *, char *, int);
extern void 		pack16(char *, uint16_t);
extern void 		pack32(char *, uint32_t);
extern void 		pack8(char *, uint8_t);
extern void 		parseloop(struct cfg *, struct imsgbuf *, int);
extern void 		unpack(char *, char *, int);

void 			tcploop(struct cfg *, struct imsgbuf *, struct imsgbuf *);

extern struct reply_logic rlogic[];

TAILQ_HEAD(, tcpentry) tcphead;

struct tcpentry {
	int intidx;
	uint bytes_read;
	int bytes_expected;
	uint bytes_limit;
	int seen;		/* seen heading bytes */
	int so;
	time_t last_used;
	char buf[0xffff + 3];	
	char *address;
	uint16_t ms_timeout;
	TAILQ_ENTRY(tcpentry) tcpentries;
} *tcpn1, *tcpn2, *tcpnp;

/* global variables */

extern char *__progname;
extern int axfrport;
extern int ratelimit;
extern int ratelimit_packets_per_second;
extern int passlist;
extern int tsig;
extern int dnssec;
extern int raxfrflag;
extern u_int max_udp_payload;
extern uint8_t rdomain;
extern uint8_t forward_rdomain;
extern int cookies;

extern int debug;
extern int verbose;
extern int bflag;
extern int iflag;
extern int lflag;
extern int nflag;
extern int bcount;
extern int icount;
extern int forward;
extern int forwardtsig;
extern int strictx20i;
extern int forwardstrategy;
extern int zonecount;
extern int tsigpassname;
extern int cache;
extern uint16_t port;
extern uint32_t cachesize;
extern char *bind_list[255];
extern char *interface_list[255];
extern char *identstring;
extern pid_t *ptr;
extern long glob_time_offset;

/*
 * TCPLOOP - does the polling of tcp descriptors and if ready receives the 
 * 		requests, builds the question and calls for replies, loops
 *
 */
		
void
tcploop(struct cfg *cfg, struct imsgbuf *ibuf, struct imsgbuf *cortex)
{
	fd_set rset;
	int sel;
	int ret;
	int len, slen = 0;
	int i;
	int istcp = 1;
	int maxso;
	int so;
	int type0, type1;
	int lzerrno;
	int filter = 0;
	int blocklist = 1;
	int require_tsig = 0;
	int axfr_acl = 0;
	int passnamewc;
	pid_t idata;
	uint conncnt = 0;
	int tcpflags;
	pid_t pid;

	uint8_t aregion;			/* region where the address comes from */

	char *pbuf;
	char *replybuf = NULL;
	char address[INET6_ADDRSTRLEN];
	char replystring[DNS_MAXNAME + 1];
	char fakereplystring[DNS_MAXNAME + 1];

	struct sockaddr_storage ss;

	socklen_t fromlen = sizeof(struct sockaddr_storage);

	struct sockaddr *from = (void *)&ss;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	struct question *question = NULL, *fakequestion = NULL;
	struct rbtree *rbt0 = NULL, *rbt1 = NULL;
	struct rrset *csd;
	struct rr *rr_csd;
	struct sf_imsg sf, *sfi = NULL;
	
	struct sreply sreply;
	struct reply_logic *rl = NULL;
	struct timeval tv = { 10, 0};
	struct imsgbuf parse_ibuf;
	struct imsgbuf *pibuf;
	struct parsequestion pq;

	struct sforward *sforward;
	int ix;
	int sretlen;

	TAILQ_INIT(&tcphead);

	sforward = (struct sforward *)calloc(1, sizeof(struct sforward));
	if (sforward == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		ddd_shutdown();
		exit(1);
	}

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, PF_UNSPEC, &cfg->my_imsg[MY_IMSG_PARSER].imsg_fds[0]) < 0) {
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
#ifndef __OpenBSD__
		/* OpenBSD has minherit() */
		if (munmap(cfg->shm[SM_FORWARD].shptr, 
				cfg->shm[SM_FORWARD].shptrsize) == -1) {
			dolog(LOG_INFO, "unmapping shptr failed: %s\n", \
				strerror(errno));
		}
#endif
		cfg->shm[SM_FORWARD].shptrsize = 0;
		for (i = 0; i < cfg->sockcount; i++)  {
				close(cfg->tcp[i]);
		}
		close(ibuf->fd);
		close(cortex->fd);
		close(cfg->my_imsg[MY_IMSG_PARSER].imsg_fds[1]);
		imsg_init(&parse_ibuf, cfg->my_imsg[MY_IMSG_PARSER].imsg_fds[0]);
		setproctitle("tcp parse engine %d [%s]", cfg->pid,
			(identstring != NULL ? identstring : ""));
		parseloop(cfg, &parse_ibuf, DDD_IS_TCP);
		/* NOTREACHED */
		exit(1);
	default:
		close(cfg->my_imsg[MY_IMSG_PARSER].imsg_fds[0]);
		imsg_init(&parse_ibuf, cfg->my_imsg[MY_IMSG_PARSER].imsg_fds[1]);
		pibuf = &parse_ibuf;
		break;
	}
	
#if __OpenBSD__
	if (pledge("stdio inet sendfd recvfd", NULL) < 0) {
		perror("pledge");
		ddd_shutdown();
		exit(1);
	}
#endif

	replybuf = calloc(1, 65536);
	if (replybuf == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		ddd_shutdown();
		exit(1);
	}


	/* 
	 * listen on descriptors
	 */

	for (i = 0; i < cfg->sockcount; i++) {
		listen(cfg->tcp[i], 5);
	}

	for (;;) {
		maxso = 0;

		FD_ZERO(&rset);
		for (i = 0; i < cfg->sockcount; i++)  {
			if (maxso < cfg->tcp[i])
				maxso = cfg->tcp[i];
	
			FD_SET(cfg->tcp[i], &rset);
		}

		TAILQ_FOREACH(tcpnp, &tcphead, tcpentries) {
			if (maxso < tcpnp->so)
				maxso = tcpnp->so;

			FD_SET(tcpnp->so, &rset);
		}
	
		tv.tv_sec = 3;
		tv.tv_usec = 0;

		sel = select(maxso + 1, &rset, NULL, NULL, &tv);

		if (sel < 0) {
			dolog(LOG_INFO, "select: %s\n", strerror(errno));
			continue;
		}

		if (sel == 0) {
			TAILQ_FOREACH_SAFE(tcpnp, &tcphead, tcpentries, tcpn1) {
				if ((tcpnp->last_used + 3) < time(NULL)) {
					dolog(LOG_INFO, "tcp timeout on interface \"%s\" for address %s\n", cfg->ident[tcpnp->intidx], tcpnp->address);
					TAILQ_REMOVE(&tcphead, tcpnp, tcpentries);
					close(tcpnp->so);
					free(tcpnp->address);
					free(tcpnp);
					if (conncnt > 0)
						conncnt--;
				}
			}
			continue;
		}
			
		for (i = 0; i < cfg->sockcount; i++) {
			if (FD_ISSET(cfg->tcp[i], &rset)) {
				fromlen = sizeof(struct sockaddr_storage);

				so = accept(cfg->tcp[i], (struct sockaddr*)from, &fromlen);
		
				if (so < 0) {
					dolog(LOG_INFO, "tcp accept: %s\n", strerror(errno));
					continue;
				}

				if (from->sa_family == AF_INET6) {

					fromlen = sizeof(struct sockaddr_in6);
					sin6 = (struct sockaddr_in6 *)from;
					inet_ntop(AF_INET6, (void *)&sin6->sin6_addr, (char *)&address, sizeof(address));
					aregion = find_region((struct sockaddr_storage *)sin6, AF_INET6);
					filter = find_filter((struct sockaddr_storage *)sin6, AF_INET6);
					if (passlist) {
						blocklist = find_passlist((struct sockaddr_storage *)sin6, AF_INET6);
					}
					axfr_acl = find_axfr((struct sockaddr_storage *)sin6, AF_INET6);

					require_tsig = 0;
					if (tsig) {
						require_tsig = find_tsig((struct sockaddr_storage *)sin6, AF_INET6);
					}
				} else if (from->sa_family == AF_INET) {
					
					fromlen = sizeof(struct sockaddr_in);
					sin = (struct sockaddr_in *)from;
					inet_ntop(AF_INET, (void *)&sin->sin_addr, (char *)&address, sizeof(address));
					aregion = find_region((struct sockaddr_storage *)sin, AF_INET);
					filter = find_filter((struct sockaddr_storage *)sin, AF_INET);
					if (passlist) {
						blocklist = find_passlist((struct sockaddr_storage *)sin, AF_INET);
					}
					axfr_acl = find_axfr((struct sockaddr_storage *)sin, AF_INET);
					
					require_tsig = 0;
					if (tsig) {
						require_tsig = find_tsig((struct sockaddr_storage *)sin, AF_INET);
					}
				} else {
					dolog(LOG_INFO, "TCP packet received on descriptor %u interface \"%s\" had weird address family (%u), drop\n", so, cfg->ident[i], from->sa_family);
					close(so);
					continue;
				}


				if (filter && require_tsig == 0) {
					dolog(LOG_INFO, "TCP connection refused on descriptor %u interface \"%s\" from %s, filter policy, drop\n", so, cfg->ident[i], address);
#if 0
					build_reply(&sreply, so, pbuf, len, NULL, from, fromlen, NULL, NULL, aregion, istcp, 0, replybuf, NULL);
					slen = reply_refused(&sreply, &sretlen, NULL, 0);
#endif
					close(so);
					continue;
				}

				if (passlist && blocklist == 0) {
					dolog(LOG_INFO, "TCP connection refused on descriptor %u interface \"%s\" from %s, passlist policy\n", so, cfg->ident[i], address);
					close(so);
					continue;
				}

				if (conncnt >= 64) {
					dolog(LOG_INFO, "TCP connection refused on descriptor %u interface \"%s\" from %s, too many TCP connections", so
						, cfg->ident[i], address);
					close(so);
					continue;
				}

				if ((tcpflags = fcntl(so, F_GETFL, 0)) < 0) {
					dolog(LOG_INFO, "tcp fcntl can't query fcntl flags\n");
					close(so);
					continue;
				}
				
				tcpflags |= O_NONBLOCK;
				if (fcntl(so, F_SETFL, tcpflags) < 0) {
					dolog(LOG_INFO, "tcp fcntl can't set nonblocking\n");
					close(so);
					continue;
				}
				
				tcpn1 = malloc(sizeof(struct tcpentry));
				if (tcpn1 == NULL) {
					dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
					close(so);
					continue;
				}
				tcpn1->bytes_read = 0;
				tcpn1->bytes_expected = 0;
				tcpn1->bytes_limit = 0;
				tcpn1->seen = 0;
				tcpn1->so = so;
				tcpn1->last_used = time(NULL);
				tcpn1->ms_timeout = 0;
				tcpn1->intidx = i;
				tcpn1->address = strdup(address);
				
				TAILQ_INSERT_TAIL(&tcphead, tcpn1, tcpentries);
				conncnt++;

			} /* FD_ISSET */
		}

		TAILQ_FOREACH_SAFE(tcpnp, &tcphead, tcpentries, tcpn1) {
			if (FD_ISSET(tcpnp->so, &rset)) {

				if (tcpnp->bytes_read < 2)
					len = recv(tcpnp->so, &tcpnp->buf[tcpnp->bytes_read], 2, 0);
				else
					len = recv(tcpnp->so, &tcpnp->buf[tcpnp->bytes_read], tcpnp->bytes_expected, 0);

				if (len <= 0) {
					if (errno == EWOULDBLOCK) {
						continue;
					}
					TAILQ_REMOVE(&tcphead, tcpnp, tcpentries);
					close(tcpnp->so);
					free(tcpnp->address);
					free(tcpnp);
					if (conncnt > 0)
						conncnt--;
					continue;
				} /* if len */
	
				tcpnp->bytes_read += len;
				tcpnp->bytes_expected -= len;

				if (tcpnp->bytes_expected < 0)
					tcpnp->bytes_expected = 0;

				if (tcpnp->seen == 0 && tcpnp->bytes_read >= 2) {
						uint16_t u16tmp;

						u16tmp = unpack16(&tcpnp->buf[0]);
						tcpnp->bytes_expected = ntohs(u16tmp) - (tcpnp->bytes_read - 2);
						tcpnp->bytes_limit = ntohs(u16tmp) + 2;
						tcpnp->seen = 1;
				} 

				/*
				 * disallow continuing if we only have the
				 * length and nothing else
				 */

				if (tcpnp->bytes_read <= 2)
					continue;

				if ((tcpnp->bytes_read) < tcpnp->bytes_limit) 
					continue;

				len = tcpnp->bytes_limit - 2;
				pbuf = &tcpnp->buf[2];
				so = tcpnp->so;

				if (len > DNS_MAXTCP || len < sizeof(struct dns_header)){
					dolog(LOG_INFO, "TCP packet on descriptor %u interface \"%s\" illegal dns packet length from %s, drop\n", so, cfg->ident[tcpnp->intidx], tcpnp->address);

					goto drop;
				}


				ret = send_to_parser(cfg, pibuf, pbuf, len, &pq);
				switch (ret) {	
				case -1:
					goto drop;
				case PARSE_RETURN_NOTAQUESTION:
					dolog(LOG_INFO, "TCP packet on descriptor %u interface \"%s\" dns header from %s is not a question, drop\n", so, cfg->ident[tcpnp->intidx], tcpnp->address);
					goto drop;
				case PARSE_RETURN_NOQUESTION:
					dolog(LOG_INFO, "TCP packet on descriptor %u interface \"%s\" header from %s has no question, drop\n", so, cfg->ident[tcpnp->intidx], tcpnp->address);
					/* format error */
					build_reply(&sreply, so, pbuf, len, NULL, from, fromlen, NULL, NULL, aregion, istcp, 0, replybuf, NULL);
					slen = reply_fmterror(&sreply, &sretlen, NULL);
					dolog(LOG_INFO, "TCP question on descriptor %d interface \"%s\" from %s, did not have question of 1 replying format error\n", so, cfg->ident[tcpnp->intidx], tcpnp->address);
					goto drop;
				case PARSE_RETURN_MALFORMED:
					dolog(LOG_INFO, "TCP packet on descriptor %u interface \"%s\" malformed question from %s, drop\n", so, cfg->ident[tcpnp->intidx], tcpnp->address);
					goto drop;
				case PARSE_RETURN_NAK:
					dolog(LOG_INFO, "TCP packet on descriptor %u interface \"%s\" illegal dns packet length from %s, drop\n", so, cfg->ident[tcpnp->intidx], tcpnp->address);
					goto drop;
				case PARSE_RETURN_NOTAUTH:
					if (filter && pq.tsig.have_tsig == 0) {
						build_reply(&sreply, so, pbuf, len, NULL, from, fromlen, NULL, NULL, aregion, istcp, 0, replybuf, NULL);
						slen = reply_refused(&sreply, &sretlen, NULL, 0);
						dolog(LOG_INFO, "TCP connection refused on descriptor %u interface \"%s\" from %s (ttl=TCP, region=%d) replying REFUSED, not a tsig\n", so, cfg->ident[tcpnp->intidx], tcpnp->address, aregion);
						goto drop;
					}

					/* FALLTHROUGH */
				default:
					question = convert_question(&pq, 1);
					if (question == NULL) {
						dolog(LOG_INFO, "TCP packet on descriptor %u interface \"%s\" internal error from %s, drop\n", so, cfg->ident[tcpnp->intidx], tcpnp->address);
						goto drop;
					}

					break;
				}

				/* goto drop beyond this point should goto out instead */
				fakequestion = NULL;
				/* handle tcp notifications , XXX not tested */
				if (question->notify) {
					if (question->tsig.have_tsig && notifysource(question, (struct sockaddr_storage *)from) &&
							question->tsig.tsigverified == 1) {
							dolog(LOG_INFO, "on TCP descriptor %u interface \"%s\" authenticated dns NOTIFY packet from %s, replying NOTIFY\n", so, cfg->ident[tcpnp->intidx], tcpnp->address);
							snprintf(replystring, DNS_MAXNAME, "NOTIFY");
							build_reply(&sreply, so, pbuf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, replybuf, NULL);
							slen = reply_notify(&sreply, &sretlen, NULL);
							/* send notify to replicant process */
							idata = (pid_t)question->hdr->namelen;
							imsg_compose(ibuf, IMSG_NOTIFY_MESSAGE, 
									0, 0, -1, question->hdr->name, idata);
							msgbuf_write(&ibuf->w);
							goto tcpout;
					} else if (question->tsig.have_tsig && question->tsig.tsigerrorcode != 0) {
						dolog(LOG_INFO, "on TCP descriptor %u interface \"%s\" not authenticated dns NOTIFY packet (code = %d) from %s, replying notauth\n", so, cfg->ident[tcpnp->intidx], question->tsig.tsigerrorcode, tcpnp->address);
						snprintf(replystring, DNS_MAXNAME, "NOTAUTH");
						build_reply(&sreply, so, pbuf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, replybuf, NULL);
						slen = reply_notauth(&sreply, &sretlen, NULL);
						goto tcpout;
					}

					if (notifysource(question, (struct sockaddr_storage *)from)) {
						dolog(LOG_INFO, "on TCP descriptor %u interface \"%s\" dns NOTIFY packet from %s, replying NOTIFY\n", so, cfg->ident[tcpnp->intidx], tcpnp->address);
						snprintf(replystring, DNS_MAXNAME, "NOTIFY");
						build_reply(&sreply, so, pbuf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, replybuf, NULL);
						slen = reply_notify(&sreply, &sretlen, NULL);
						/* send notify to replicant process */
						idata = (pid_t)question->hdr->namelen;
						imsg_compose(ibuf, IMSG_NOTIFY_MESSAGE, 
								0, 0, -1, question->hdr->name, idata);
						msgbuf_write(&ibuf->w);
						goto tcpout;
					} else {
						/* RFC 1996 - 3.10 is probably broken, replying REFUSED */
						dolog(LOG_INFO, "on TCP descriptor %u interface \"%s\" dns NOTIFY packet from %s, NOT in our list of PRIMARY servers replying REFUSED\n", so, cfg->ident[tcpnp->intidx], tcpnp->address);
						snprintf(replystring, DNS_MAXNAME, "REFUSED");
						build_reply(&sreply, so, pbuf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, replybuf, NULL);
						slen = reply_refused(&sreply, &sretlen, NULL, 1);

						goto tcpout;
					}
				} /* if question->notify */

				/* set keepalive value that we advertise */
				if (question->tcpkeepalive) {
					tcpnp->ms_timeout = DDD_TCP_TIMEOUT;
				}

				if (question->tsig.have_tsig && question->tsig.tsigerrorcode != 0)  {
					if (question->tsig.have_tsig &&
						question->tsig.tsigerrorcode == DNS_BADTIME &&
						tsigpassname &&
						! (question->hdr->namelen <= 1) &&
						tsigpassname_contains(question->hdr->name, question->hdr->namelen, &passnamewc)) {
							dolog(LOG_INFO, "passing on TCP name %s despite it not authenticating the TSIG\n", question->converted_name);
					} else {
							dolog(LOG_INFO, "on TCP descriptor %u interface \"%s\" not authenticated dns packet (code = %d) from %s, replying notauth\n", so, cfg->ident[tcpnp->intidx], question->tsig.tsigerrorcode, tcpnp->address);
							snprintf(replystring, DNS_MAXNAME, "NOTAUTH");
							build_reply(&sreply, so, pbuf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, replybuf, NULL);
							slen = reply_notauth(&sreply, &sretlen, NULL);
							goto tcpout;
					}
				}
				/* hack around whether we're edns version 0 */

				/*
				 * we check now for AXFR's in the query and deny if not found
				 * in our list of AXFR'ers
				 */

				switch (ntohs(question->hdr->qtype)) {
				case DNS_TYPE_AXFR:
				case DNS_TYPE_IXFR:
					if (! axfr_acl) {
						dolog(LOG_INFO, "AXFR connection from %s on interface \"%s\" was not in our axfr acl, drop\n", tcpnp->address, cfg->ident[tcpnp->intidx]);
							
						snprintf(replystring, DNS_MAXNAME, "DROP");
						slen = 0;
						goto tcpout;
					}
					break;
				default:
					break;
				}

				if (ntohs(question->hdr->qclass) == DNS_CLASS_CH &&
					ntohs(question->hdr->qtype) == DNS_TYPE_TXT &&
					strcasecmp(question->converted_name, "version.bind.") == 0) {
						snprintf(replystring, DNS_MAXNAME, "VERSION");
						build_reply(&sreply, so, pbuf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, replybuf, NULL);
						slen = reply_version(&sreply, &sretlen, NULL);
						goto tcpout;
				}

				rbt0 = lookup_zone(cfg->db, question, &type0, &lzerrno, (char *)&replystring, sizeof(replystring));
				if (type0 < 0) {
	
					switch (lzerrno) {
					default:
						dolog(LOG_INFO, "invalid lzerrno! dropping\n");
						/* FALLTHROUGH */
					case ERR_DROP:
						snprintf(replystring, DNS_MAXNAME, "DROP");
						slen = 0;
						goto tcpout;

					case ERR_REFUSED:
						snprintf(replystring, DNS_MAXNAME, "REFUSED");
						build_reply(&sreply, so, pbuf, len, question, from, fromlen, rbt0, NULL, aregion, istcp, 0, replybuf, NULL);
						slen = reply_refused(&sreply, &sretlen, NULL, 1);
						goto tcpout;
						break;
					case ERR_NODATA:
						if (rbt0) {
							rbt0 = NULL;
						}

						rbt0 = get_soa(cfg->db, question);
						if (rbt0 != NULL) {
							snprintf(replystring, DNS_MAXNAME, "NODATA");
							build_reply(&sreply, so, pbuf, len, question, from, fromlen, rbt0, NULL, aregion, istcp, 0, replybuf, NULL);
							slen = reply_nodata(&sreply, &sretlen, cfg->db);
						} else {
							if (forward)
								goto forwardtcp;

							snprintf(replystring, DNS_MAXNAME, "REFUSED");
							build_reply(&sreply, so, pbuf, len, question, from, fromlen, rbt0, NULL, aregion, istcp, 0, replybuf, NULL);
							slen = reply_refused(&sreply, &sretlen, cfg->db, 1);
						}

						goto tcpout;
						break;

					case ERR_NXDOMAIN:
							snprintf(replystring, DNS_MAXNAME, "NXDOMAIN");

						/* 
					   * lookup an authoritative soa 
					 	 */
						if (rbt0 != NULL) {
			
							build_reply(	&sreply, so, pbuf, len, question, 
											from, fromlen, rbt0, NULL, 
											aregion, istcp, 0, replybuf, NULL);

							slen = reply_nxdomain(&sreply, &sretlen, cfg->db);
					 	}
						goto tcpout;

					case ERR_FORWARD:
forwardtcp:
						if (forwardtsig) {
								if (question->tsig.have_tsig && 
									question->tsig.tsigverified) {
									snprintf(replystring, DNS_MAXNAME, "FORWARD");
								} else {
									if (question->tsig.have_tsig &&
										question->tsig.tsigerrorcode == DNS_BADTIME &&
										tsigpassname &&
										tsigpassname_contains(question->hdr->name, question->hdr->namelen, &passnamewc)) {
										snprintf(replystring, DNS_MAXNAME,
											"FORWARD");

										dolog(LOG_INFO, "TCP passing %s despite being a TSIG unauthenticated query\n", question->converted_name);
									} else {
										snprintf(replystring, DNS_MAXNAME, "REFUSED");
										build_reply(&sreply, so, pbuf, len, question, from, fromlen, rbt1, rbt0, aregion, istcp, 0, replybuf, NULL);
										slen = reply_refused(&sreply, &sretlen, cfg->db, 1);
										goto tcpout;
									}
								}
						} else
								snprintf(replystring, DNS_MAXNAME, "FORWARD");

						/* send query to forward process/cortex */
						if (len > 4000) {
							dolog(LOG_INFO, "question is larger than 4000 bytes, not forwarding\n");
							goto tcpout;
						}

						switch (from->sa_family) {
						case AF_INET:
							memcpy(&sforward->from4, from, fromlen);
							sforward->rport = sin->sin_port;
							sforward->family = AF_INET;
							break;
						case AF_INET6:
							memcpy(&sforward->from6, from, fromlen);
							sforward->rport = sin6->sin6_port;
							sforward->family = AF_INET6;
							break;
						}
						
						memcpy(&sforward->buf, question->hdr->original_name, question->hdr->namelen);
						sforward->buflen = question->hdr->namelen;
		
						memcpy((char *)&sforward->header, pbuf, sizeof(struct dns_header));
						sforward->type = question->hdr->qtype;
						sforward->class = question->hdr->qclass;

						sforward->edns0len = question->edns0len;
						sforward->dnssecok = question->dnssecok;

						if (question->tsig.have_tsig && question->tsig.tsigverified) {
							sforward->havemac = 1;
							memcpy((char *)&sforward->tsigname, question->tsig.tsigkey, question->tsig.tsigkeylen);
							sforward->tsignamelen = question->tsig.tsigkeylen;
							memcpy(&sforward->mac, question->tsig.tsigmac, sizeof(sforward->mac));
							sforward->tsigtimefudge = question->tsig.tsig_timefudge;
						} else
							sforward->havemac = 0;

						sforward->gotit = time(NULL);
						memcpy(&sf.sfi_sf, sforward, sizeof(struct sforward));
						
						/* wait for lock */
						sm_lock(cfg->shm[SM_FORWARD].shptr,
								cfg->shm[SM_FORWARD].shptrsize);

						for (sfi = (struct sf_imsg *)&cfg->shm[SM_FORWARD].shptr[0], 
								ix = 0;
								ix < SHAREDMEMSIZE; ix++, sfi++) {
									if (unpack32((char *)&sfi->u.s.read) == 1) {
										memcpy(sfi, &sf, sizeof(struct sf_imsg) - sysconf(_SC_PAGESIZE));
										pack32((char *)&sfi->u.s.read, 0);
										break;
									}
						}

						if (ix == SHAREDMEMSIZE) {
							dolog(LOG_INFO, "delphinusdnsd tcp: can't find an open slot in sharedmemsize\n");
							goto tcpout;
						}

						sm_unlock(cfg->shm[SM_FORWARD].shptr, 
							cfg->shm[SM_FORWARD].shptrsize);

						imsg_compose(ibuf, IMSG_FORWARD_TCP,
							0, 0, so, &ix,  sizeof(int));
						msgbuf_write(&ibuf->w);
						slen = 0;

						if (lflag)
							dolog(LOG_INFO, "request on descriptor %u interface \"%s\" from %s (ttl=TCP, region=%d, tta=NA) for \"%s\" type=%s class=%u, %s%s%s%s%s answering \"%s\" (bytes=%d/%d, sum=NA)\n", so, cfg->ident[tcpnp->intidx], tcpnp->address, aregion, question->converted_name, get_dns_type(ntohs(question->hdr->qtype), 1), ntohs(question->hdr->qclass), (question->edns0len) ? "edns0, " : "", (question->dnssecok) ? "dnssecok, " : "", (question->tsig.tsigverified ? "tsig, " : ""), (question->cookie.have_cookie ? "cookie, " : ""),  (question->tcpkeepalive ? "keepalive, ": "" ), replystring, len + 2, slen);

						if (fakequestion != NULL) {
							free_question(fakequestion);
						}
			
						free_question(question);
						
						if (rbt0) {
							rbt0 = NULL;
						}
						if (rbt1) {
							rbt1 = NULL;
						}
						TAILQ_REMOVE(&tcphead, tcpnp, tcpentries);
						close(tcpnp->so);
						free(tcpnp->address);
						free(tcpnp);
						if (conncnt > 0)
							conncnt--;
						continue;
						break;

					case ERR_NOERROR:
						/*
 						 * this is hackish not sure if this should be here
						 */

						snprintf(replystring, DNS_MAXNAME, "NOERROR");

						/*
						 * lookup an authoritative soa
						 */

						if (rbt0) {
							rbt0 = NULL;
						}

						rbt0 = get_soa(cfg->db, question);
						if (rbt0 != NULL) {

								build_reply(	&sreply, so, pbuf, len, 
												question, from, fromlen, 
												rbt0, NULL, aregion, istcp, 
												0, replybuf, NULL);

								slen = reply_noerror(&sreply, &sretlen, cfg->db);
			
								goto tcpout;
						}

						snprintf(replystring, DNS_MAXNAME, "DROP");
						slen = 0;
						goto tcpout;

					case ERR_DELEGATE:
						if (rbt0 != NULL) {
			
							build_reply(	&sreply, so, pbuf, len, question, 
											from, fromlen, rbt0, NULL, 
											aregion, istcp, 0, replybuf, NULL);

							slen = reply_ns(&sreply, &sretlen, cfg->db);
						} else {
							slen = 0;
							snprintf(replystring, DNS_MAXNAME, "DROP");

						}
						goto tcpout;
						

					}
				}

				switch (type0) {
				case DNS_TYPE_CNAME:
					csd = find_rr(rbt0, DNS_TYPE_SOA);
					if (csd == NULL)
						break;

					rr_csd = TAILQ_FIRST(&csd->rr_head);
					if (rr_csd == NULL)
						break;
					
					fakequestion = build_fake_question(((struct cname *)rr_csd)->cname, ((struct cname *)rr_csd)->cnamelen, question->hdr->qtype, NULL, 0);
					if (fakequestion == NULL) {	
						dolog(LOG_INFO, "fakequestion failed\n");
						break;
					}

					rbt1 = lookup_zone(cfg->db, fakequestion, &type1, &lzerrno, (char *)&fakereplystring, sizeof(fakereplystring));
					/* break CNAMES pointing to CNAMES */
					if (type1 == DNS_TYPE_CNAME)
						type1 = 0;
					
					break;	
				default:

					break;
				}

				/*
				 * Allow CLASS IN, CHAOS and others are
				 * not implemented and so we build a reply for
				 * that and go out.
				 */

				switch (ntohs(question->hdr->qclass)) {
				case DNS_CLASS_IN:
					break;
				default:
					 build_reply(	&sreply, so, pbuf, len, question, 
									from, fromlen, NULL, NULL, aregion, 
									istcp, 0, replybuf, NULL);

					slen = reply_notimpl(&sreply, &sretlen, NULL);
					snprintf(replystring, DNS_MAXNAME, "NOTIMPL");
					goto tcpout;
				}

				/* IXFR and AXFR are special types for TCP handle separately */
				switch (ntohs(question->hdr->qtype)) {
				case DNS_TYPE_IXFR:
					/* FALLTHROUGH */
				case DNS_TYPE_AXFR:
					dolog(LOG_INFO, "composed AXFR message to axfr process\n");
					imsg_compose(ibuf, IMSG_XFR_MESSAGE, 0, 0, tcpnp->so, tcpnp->buf, tcpnp->bytes_read);
					msgbuf_write(&ibuf->w);
					TAILQ_REMOVE(&tcphead, tcpnp, tcpentries);
					free(tcpnp->address);
					free(tcpnp);
					if (conncnt > 0)
						conncnt--;
					continue;
					break;

				}

				for (rl = &rlogic[0]; rl->rrtype != 0; rl++) {
					if (rl->rrtype == ntohs(question->hdr->qtype)) {
						if (rl->type0 == type0) {
							switch (rl->buildtype) {
							case BUILD_CNAME:
								build_reply(&sreply, so, pbuf, len, question, 
									from, fromlen, rbt0, ((type1 > 0) ? rbt1 : 
									NULL), aregion, istcp, 0, replybuf, NULL);
								break;
							case BUILD_OTHER:
								build_reply(&sreply, so, pbuf, len, question, 
									from, fromlen, rbt0, NULL, aregion, istcp, 
									0, replybuf, NULL);
								break;
							}
						} else {
							continue;
						}
							
						slen = (*rl->reply)(&sreply, &sretlen, cfg->db);
						break;
					} /* if rl->rrtype == */
				}

				if (rl->rrtype == 0) {
					/*
					 * ANY unknown RR TYPE gets a NOTIMPL
					 */

					/*
					 * except for delegations 
					 */
					
					if (type0 == DNS_TYPE_NS) {
						build_reply(&sreply, so, pbuf, len, question, from, \
							fromlen, rbt0, NULL, aregion, istcp, 
							0, replybuf, NULL);

						slen = reply_ns(&sreply, &sretlen, cfg->db);

					} else {

						build_reply(&sreply, so, pbuf, len, question, from, \
						fromlen, NULL, NULL, aregion, istcp, 
						0, replybuf, NULL);
		
						slen = reply_notimpl(&sreply, &sretlen, NULL);
						snprintf(replystring, DNS_MAXNAME, "NOTIMPL");
					}
				}
			
		tcpout:
				if (lflag)
					dolog(LOG_INFO, "request on descriptor %u interface \"%s\" from %s (ttl=TCP, region=%d, tta=NA) for \"%s\" type=%s class=%u, %s%s%s%s%s answering \"%s\" (bytes=%d/%d, sum=NA)\n", so, cfg->ident[tcpnp->intidx], tcpnp->address, aregion, question->converted_name, get_dns_type(ntohs(question->hdr->qtype), 1), ntohs(question->hdr->qclass), (question->edns0len) ? "edns0, " : "", (question->dnssecok) ? "dnssecok, " : "", (question->tsig.tsigverified ? "tsig, " : ""),(question->cookie.have_cookie ? "cookie, " : ""),  (question->tcpkeepalive ? "keepalive, " : ""), replystring, len + 2, slen);


				if (fakequestion != NULL) {
					free_question(fakequestion);
				}
	
				free_question(question);
				
				if (rbt0) {
					rbt0 = NULL;
				}
				if (rbt1) {
					rbt1 = NULL;
				}

				/*
				 * we are restarting this connection, so that the remote
				 * end can ask again, with tcp if they want, so reset
				 * everything
				 */

				memset(tcpnp->buf, 0, sizeof(tcpnp->buf));
				tcpnp->bytes_read = 0;
				tcpnp->bytes_expected = 0;
				tcpnp->bytes_limit = 0;
				tcpnp->seen = 0;
				tcpnp->last_used = time(NULL);
			}	/* END ISSET */
			continue;
	drop:
		
			if (rbt0) {	
				rbt0 = NULL;
			}

			if (rbt1) {
				rbt1 = NULL;
			}

			TAILQ_REMOVE(&tcphead, tcpnp, tcpentries);
			close(tcpnp->so);
			free(tcpnp->address);
			free(tcpnp);
			if (conncnt > 0)
				conncnt--;

			continue;
		
		} /* TAILQ_FOREACH_SAFE */

		/*
		 * kick off the idlers 
		 */

		TAILQ_FOREACH_SAFE(tcpnp, &tcphead, tcpentries, tcpn1) {
			if (((tcpnp->ms_timeout == 0) && (tcpnp->last_used + 3) \
				< time(NULL)) ||
			(tcpnp->ms_timeout && (tcpnp->last_used + \
				(tcpnp->ms_timeout / 10)) < time(NULL))) {
					dolog(LOG_INFO, "tcp timeout on interface \"%s\" for address %s\n", cfg->ident[tcpnp->intidx], tcpnp->address);
					TAILQ_REMOVE(&tcphead, tcpnp, tcpentries);
					close(tcpnp->so);
					free(tcpnp->address);
					free(tcpnp);
					if (conncnt > 0)
						conncnt--;
			}
		}
	}  /* for (;;) */

	/* NOTREACHED */
}
