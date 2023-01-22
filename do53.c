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

extern char 		*convert_name(char *, int);
extern char *		get_dns_type(int, int);
extern int		free_question(struct question *);
extern int		reply_nodata(struct sreply *, int *, ddDB *);
extern int		reply_notify(struct sreply *, int *, ddDB *);
extern int 		check_rrlimit(int, uint16_t *, int, char *);
extern int 		find_filter(struct sockaddr_storage *, int);
extern int 		find_passlist(struct sockaddr_storage *, int);
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
extern struct imsgbuf * register_cortex(struct imsgbuf *, int);
extern struct question	*build_fake_question(char *, int, uint16_t, char *, int);
extern struct question	*build_question(char *, int, uint16_t, char *);
extern struct question	*convert_question(struct parsequestion *, int);
extern struct rbtree * 	get_soa(ddDB *, struct question *);
extern struct rbtree * 	lookup_zone(ddDB *, struct question *, int *, int *, char *, int);
extern struct rrset * 	find_rr(struct rbtree *rbt, uint16_t rrtype);
extern uint16_t 	unpack16(char *);
extern uint32_t 	unpack32(char *);
extern uint8_t 		find_region(struct sockaddr_storage *, int);
extern void		sm_lock(char *, size_t);
extern void		sm_unlock(char *, size_t);
extern void 		add_rrlimit(int, uint16_t *, int, char *);
extern void 		build_reply(struct sreply *, int, char *, int, struct question *, struct sockaddr *, socklen_t, struct rbtree *, struct rbtree *, uint8_t, int, int, char *, struct tls *);
extern void 		ddd_shutdown(void);
extern void 		dolog(int, char *, ...);
extern void 		pack(char *, char *, int);
extern void 		pack16(char *, uint16_t);
extern void 		pack32(char *, uint32_t);
extern void 		pack8(char *, uint8_t);
extern void 		parseloop(struct cfg *, struct imsgbuf *, int);
extern void 		tcploop(struct cfg *, struct imsgbuf *, struct imsgbuf *);
extern void		tlsloop(struct cfg *, struct imsgbuf *, struct imsgbuf *);
extern void 		unpack(char *, char *, int);

int			reply_cache(int, struct sockaddr *, int, struct querycache *, char *, int, char *, uint16_t *, uint16_t *, uint16_t *);
int			add_cache(struct querycache *, char *, int, struct question *,  char *, int, uint16_t);
uint16_t		crc16(uint8_t *, int);
int			intcmp(struct csnode *, struct csnode *);
int			same_refused(u_char *, void *, int, void *, int);

void			mainloop(struct cfg *, struct imsgbuf *);

extern struct reply_logic rlogic[];

/* trees */

RB_HEAD(qctree, csnode) qchead = RB_INITIALIZER(&qchead);
RB_PROTOTYPE(qctree, csnode, entry, intcmp)
RB_GENERATE(qctree, csnode, entry, intcmp)

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

extern char *rptr;
extern int ratelimit_backlog;
extern DDD_EVP_MD *md5_md;

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
extern int tls;


/*
 * MAINLOOP - does the polling of udp descriptors and if ready 
 *		receives the requests, builds the question and calls 
 *		for replies, loops
 *
 */
		
void
mainloop(struct cfg *cfg, struct imsgbuf *ibuf)
{
	fd_set rset;
	pid_t pid;

	int sel, oldsel;
	int len, slen = 0;
	int i, nomore = 0;
	int istcp = 1;
	int maxso;
	int so;
	int type0, type1;
	int lzerrno;
	int filter = 0;
	int rcheck = 0;
	int blocklist = 1;
	int require_tsig = 0;
	int addrlen;
	pid_t idata;

	uint32_t received_ttl;
	u_char *ttlptr;

	uint8_t aregion;			/* region where the address comes from */

	char buf[4096];
	char *replybuf = NULL;
	char address[INET6_ADDRSTRLEN];
	char replystring[DNS_MAXNAME + 1];
	char fakereplystring[DNS_MAXNAME + 1];
	union {
		struct cmsghdr hdr;
		u_char buf[CMSG_SPACE(sizeof(uint8_t)) + 
				CMSG_SPACE(sizeof(struct timeval))];
	} cmsgbuf;

	struct sockaddr_storage ss;

	socklen_t fromlen = sizeof(struct sockaddr_storage);

	struct sockaddr *from = (void *)&ss;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	struct question *question = NULL, *fakequestion = NULL;
	struct parsequestion pq;
	struct rbtree *rbt0 = NULL, *rbt1 = NULL;
	struct rrset *csd;
	struct rr *rr_csd;
	struct sf_imsg sf, *sfi = NULL;
	
	struct sreply sreply;
	struct reply_logic *rl = NULL;
	struct timeval tv = { 10, 0};
	struct timeval rectv0, rectv1, *prectv;

	struct msghdr msgh;
	struct cmsghdr *cmsg = NULL;
	struct iovec iov;
	struct imsgbuf *tls_ibuf, *tcp_ibuf, *udp_ibuf, parse_ibuf;
	struct imsgbuf *pibuf;

	struct sforward *sforward;
	static struct querycache qc;

	int ret;
	int ix;
	int sretlen;
	int passnamewc;
	u_int md_len;

	DDD_EVP_MD_CTX *rctx;
	DDD_EVP_MD *md;
	u_char rdigest[MD5_DIGEST_LENGTH];
	time_t refusedtime = 0;
	uint16_t crc;
	struct csnode *ni;
	struct csentry *ei;
	char cdomainname[DNS_MAXNAME + 1];
	uint16_t cclass, ctype;

	memset(&rectv0, 0, sizeof(struct timeval));
	memset(&rectv1, 0, sizeof(struct timeval));
	
	pid = fork();
	switch (pid) {
	case -1:
		dolog(LOG_ERR, "fork(): %s\n", strerror(errno));
		ddd_shutdown();
		exit(1);
	case 0:
		for (i = 0; i < cfg->sockcount; i++)  {
				close(cfg->udp[i]);
				if (axfrport && axfrport != port)
					close(cfg->axfr[i]);
				if (tls)
					close(cfg->tls[i]);
		}
		tcp_ibuf = register_cortex(ibuf, MY_IMSG_TCP);
		if (tcp_ibuf == NULL) {
			ddd_shutdown();
			exit(1);
		}
		/* shptr has no business in a tcp parse process */
		if (forward) {
#if __OpenBSD__
			minherit(cfg->shm[SM_FORWARD].shptr, 	
				cfg->shm[SM_FORWARD].shptrsize,
				MAP_INHERIT_NONE);
#endif
		}

		/* turn off tls */
		tls = 0;

		setproctitle("TCP engine %d [%s]", cfg->pid, 
				(identstring != NULL ? identstring : ""));
		tcploop(cfg, tcp_ibuf, ibuf);
		/* NOTREACHED */
		exit(1);
	default:
		for (i = 0; i < cfg->sockcount; i++)  {
				close(cfg->tcp[i]);
		}
		break;
	}

	if (tls) {
		pid = fork();
		switch (pid) {
		case -1:
			dolog(LOG_ERR, "fork(): %s\n", strerror(errno));
			ddd_shutdown();
			exit(1);
		case 0:
			for (i = 0; i < cfg->sockcount; i++)  {
					close(cfg->udp[i]);
					if (axfrport && axfrport != port)
						close(cfg->axfr[i]);
			}
			tls_ibuf = register_cortex(ibuf, MY_IMSG_TLS);
			if (tls_ibuf == NULL) {
				ddd_shutdown();
				exit(1);
			}
			/* shptr has no business in a tcp parse process */
			if (forward) {
#if __OpenBSD__
				minherit(cfg->shm[SM_FORWARD].shptr, 	
					cfg->shm[SM_FORWARD].shptrsize,
					MAP_INHERIT_NONE);
#endif
			}

			setproctitle("TLS engine %d [%s]", cfg->pid, 
					(identstring != NULL ? identstring : ""));
			tlsloop(cfg, tls_ibuf, ibuf);
			/* NOTREACHED */
			exit(1);
		default:
			for (i = 0; i < cfg->sockcount; i++)  {
				close(cfg->tls[i]);
			}

			/* turn off tls */
			tls = 0;

			break;
		}
	}

	/* shptr has no business in a udp parse process */
	if (forward) {
#if __OpenBSD__
		minherit(cfg->shm[SM_FORWARD].shptr, 
			cfg->shm[SM_FORWARD].shptrsize,
			MAP_INHERIT_NONE);
#endif
	}

	sforward = (struct sforward *)calloc(1, sizeof(struct sforward));
	if (sforward == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		ddd_shutdown();
		exit(1);
	}

	/* we need to initialize our md with md5_md */
	md = md5_md;

	rctx = delphinusdns_EVP_MD_CTX_new();
	if (rctx == NULL) {
		dolog(LOG_ERR, "DDD_EVP_MD_CTX_new failed\n");
		ddd_shutdown();
		exit(1);
	}
	

	replybuf = calloc(1, 65536);
	if (replybuf == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		ddd_shutdown();
		exit(1);
	}

	qc.bufsize = QC_REPLYSIZE;
	qc.cm = sizeof(qc.cs) / sizeof(qc.cs[0]);
	qc.cp = 0;

	if ((ni = malloc(sizeof(struct csnode))) == NULL) {
		dolog(LOG_ERR, "malloc: %s\n", strerror(errno));
		ddd_shutdown();
		exit(1);
	}
	ni->requestlen = QC_REQUESTSIZE;
	TAILQ_INIT(&ni->head);

	for (i = 0; i < qc.cm; i++) {
		qc.cs[i].replylen = qc.bufsize;
		qc.cs[i].reply = malloc(qc.bufsize);
		qc.cs[i].request = malloc(QC_REQUESTSIZE);
		if ((qc.cs[i].reply == NULL) || (qc.cs[i].request == NULL)) {
			dolog(LOG_ERR, "malloc: %s\n", strerror(errno));
			ddd_shutdown();
			exit(1);
		}
		qc.cs[i].domainname = malloc(DNS_MAXNAME + 1);
		if (qc.cs[i].domainname == NULL) {
			dolog(LOG_ERR, "malloc: %s\n", strerror(errno));
			ddd_shutdown();
			exit(1);
		}

		if ((ei = malloc(sizeof(struct csentry))) == NULL) {
			dolog(LOG_ERR, "malloc: %s\n", strerror(errno));
			ddd_shutdown();
			exit(1);
		}
		ei->cs = &qc.cs[i];
		TAILQ_INSERT_HEAD(&ni->head, ei, entries);
	}

	/* we initialize the RB only once as its requestsize is static */
	RB_INSERT(qctree, &qchead, ni);

	udp_ibuf = register_cortex(ibuf, MY_IMSG_UDP);
	if (udp_ibuf == NULL) {
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
		/* close udp decriptors */
		for (i = 0; i < cfg->sockcount; i++)  {
				close(cfg->udp[i]);
				if (axfrport && axfrport != port)
					close(cfg->axfr[i]);
		}
		close(ibuf->fd);
		close(udp_ibuf->fd);
		close(cfg->my_imsg[MY_IMSG_PARSER].imsg_fds[1]);
		imsg_init(&parse_ibuf, cfg->my_imsg[MY_IMSG_PARSER].imsg_fds[0]);
		setproctitle("udp parse engine %d [%s]", cfg->pid, 
			(identstring != NULL ? identstring : ""));
		parseloop(cfg, &parse_ibuf, 0);
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

	for (;;) {
		maxso = 0;

		FD_ZERO(&rset);
		for (i = 0; i < cfg->sockcount; i++)  {
			if (maxso < cfg->udp[i])
				maxso = cfg->udp[i];

			if (axfrport && axfrport != port && maxso < cfg->axfr[i])
				maxso = cfg->axfr[i];

			FD_SET(cfg->udp[i], &rset);

			if (axfrport && axfrport != port)
				FD_SET(cfg->axfr[i], &rset);
		}
	
		tv.tv_sec = 10;
		tv.tv_usec = 0;

		sel = select(maxso + 1, &rset, NULL, NULL, &tv);

		if (sel < 0) {
			dolog(LOG_INFO, "select: %s\n", strerror(errno));
			continue;
		}

		if (sel == 0) {
			if (nomore)
				continue;

			idata = 42;
			imsg_compose(ibuf, IMSG_CRIPPLE_NEURON,
				0, 0, -1, &idata, sizeof(idata));
			msgbuf_write(&ibuf->w);

			nomore = 1;

			continue;
		}
			
		for (i = 0; i < cfg->sockcount; i++) {
			if (axfrport && axfrport != port && FD_ISSET(cfg->axfr[i], &rset)) {
				istcp = 0;
				so = cfg->axfr[i];

				goto axfrentry;
			}

			if (FD_ISSET(cfg->udp[i], &rset)) {
				istcp = 0;
				so = cfg->udp[i];
				oldsel = i;
axfrentry:
				fromlen = sizeof(struct sockaddr_storage);

				memset(&msgh, 0, sizeof(msgh));
				iov.iov_base = buf;
				iov.iov_len = sizeof(buf);
				msgh.msg_name = from;
				msgh.msg_namelen = fromlen;
				msgh.msg_iov = &iov;
				msgh.msg_iovlen = 1;
				msgh.msg_control = (struct cmsghdr*)&cmsgbuf.buf;
				msgh.msg_controllen = sizeof(cmsgbuf);
			
				len = recvmsg(so, &msgh, 0);
				if (len < 0) {
					dolog(LOG_INFO, "recvmsg: on descriptor %u interface \"%s\" %s\n", so, cfg->ident[i], strerror(errno));
					continue;
				}

				if ((msgh.msg_flags & MSG_TRUNC) ||
					(msgh.msg_flags & MSG_CTRUNC)) {
					dolog(LOG_INFO, "recvmsg: on descriptor %u interface \"%s\" control message truncated\n", so, cfg->ident[i]);
					continue;
				}

				received_ttl = 0;

				for (cmsg = CMSG_FIRSTHDR(&msgh);
                   			cmsg != NULL;
                   			cmsg = CMSG_NXTHDR(&msgh,cmsg)) {
                      				if (cmsg->cmsg_level == IPPROTO_IP
#ifdef __linux__ 
                        				&& cmsg->cmsg_type == IP_TTL) {
#else

                        				&& cmsg->cmsg_type == IP_RECVTTL) {
#endif
										
                              			ttlptr = (u_char *) CMSG_DATA(cmsg);
                              			received_ttl = (u_int)*ttlptr;
                      				}

									if (cmsg->cmsg_level == IPPROTO_IPV6 &&
                         				cmsg->cmsg_type == IPV6_HOPLIMIT) {

										if (cmsg->cmsg_len != 
												CMSG_LEN(sizeof(int))) {
											dolog(LOG_INFO, "IPV6_HOPLIMIT cmsg->cmsg_len == %d\n", cmsg->cmsg_len);
											continue;
										}

										ttlptr = (u_char *) CMSG_DATA(cmsg);
										received_ttl = (u_int)*ttlptr;
                     				}

									if (cmsg->cmsg_level == SOL_SOCKET &&
										cmsg->cmsg_type == SCM_TIMESTAMP) {

										if (cmsg->cmsg_len !=
											CMSG_LEN(sizeof(struct timeval))) {
											dolog(LOG_INFO, "SCM_TIMESTAMP cmsg->cmsg_len == %d\n", cmsg->cmsg_len);
											continue;
										}

										prectv = (struct timeval *) CMSG_DATA(cmsg);
										memcpy((char *)&rectv0, (char *)prectv, sizeof(struct timeval));
									}
				}
	
				if (from->sa_family == AF_INET6) {

					fromlen = sizeof(struct sockaddr_in6);
					sin6 = (struct sockaddr_in6 *)from;
					inet_ntop(AF_INET6, (void *)&sin6->sin6_addr, (char *)&address, sizeof(address));
					addrlen = strlen(address);
					if (ratelimit) {
						add_rrlimit(ratelimit_backlog, (uint16_t *)&sin6->sin6_addr, sizeof(sin6->sin6_addr), rptr);

						rcheck = check_rrlimit(ratelimit_backlog, (uint16_t *)&sin6->sin6_addr, sizeof(sin6->sin6_addr), rptr);
					}

					aregion = find_region((struct sockaddr_storage *)sin6, AF_INET6);
					filter = 0;
					filter = find_filter((struct sockaddr_storage *)sin6, AF_INET6);
					if (passlist) {
						blocklist = find_passlist((struct sockaddr_storage *)sin6, AF_INET6);
					}
					
					require_tsig = 0;
					if (tsig) {
						require_tsig = find_tsig((struct sockaddr_storage *)sin6, AF_INET6);
					}

				} else if (from->sa_family == AF_INET) {
					
					fromlen = sizeof(struct sockaddr_in);
					sin = (struct sockaddr_in *)from;
					inet_ntop(AF_INET, (void *)&sin->sin_addr, (char *)&address, sizeof(address));
					addrlen = strlen(address);
					if (ratelimit) {
						add_rrlimit(ratelimit_backlog, (uint16_t *)&sin->sin_addr.s_addr, sizeof(sin->sin_addr.s_addr), rptr);

						rcheck = check_rrlimit(ratelimit_backlog, (uint16_t *)&sin->sin_addr.s_addr, sizeof(sin->sin_addr.s_addr), rptr);
					}

					aregion = find_region((struct sockaddr_storage *)sin, AF_INET);
					filter = 0;
					filter = find_filter((struct sockaddr_storage *)sin, AF_INET);
					if (passlist) {
						blocklist = find_passlist((struct sockaddr_storage *)sin, AF_INET);
					}

					require_tsig = 0;
					if (tsig) {
						require_tsig = find_tsig((struct sockaddr_storage *)sin, AF_INET);
					}

				} else {
					dolog(LOG_INFO, "packet received on descriptor %u interface \"%s\" had weird address family (%u), drop\n", so, cfg->ident[i], from->sa_family);
					goto drop;
				}

				/* if UDP packet check length for minimum / maximum */
				if (len > DNS_MAXUDP || len < sizeof(struct dns_header)){
					dolog(LOG_INFO, "on descriptor %u interface \"%s\" illegal dns packet length from %s, drop\n", so, cfg->ident[i], address);
					goto drop;
				}

				if ((time(NULL) & ~3) == (refusedtime & ~3) && same_refused(rdigest, (void *)&buf[2], len - 2, (void *)address, addrlen)) {
					dolog(LOG_INFO, "short circuiting multiple refused from %s, drop\n", address);	
					goto drop;
				}
				refusedtime = 0;


				if (filter && require_tsig == 0) {

					build_reply(&sreply, so, buf, len, NULL, from, fromlen, NULL, NULL, aregion, istcp, 0, replybuf, NULL);
					delphinusdns_EVP_DigestInit_ex(rctx, md, NULL);
					delphinusdns_EVP_DigestUpdate(rctx, (void*)&buf[2], len - 2);
					delphinusdns_EVP_DigestUpdate(rctx, address, addrlen);
					delphinusdns_EVP_DigestFinal_ex(rctx, rdigest, &md_len);
					refusedtime = time(NULL);

					slen = reply_refused(&sreply, &sretlen, NULL, 0);

					dolog(LOG_INFO, "UDP connection refused on descriptor %u interface \"%s\" from %s (ttl=%d, region=%d) replying REFUSED, filter policy\n", so, cfg->ident[i], address, received_ttl, aregion);
					goto drop;
				}

				if (passlist && blocklist == 0) {

					build_reply(&sreply, so, buf, len, NULL, from, fromlen, NULL, NULL, aregion, istcp, 0, replybuf, NULL);
					delphinusdns_EVP_DigestInit_ex(rctx, md, NULL);
					delphinusdns_EVP_DigestUpdate(rctx, (void*)&buf[2], len - 2);
					delphinusdns_EVP_DigestUpdate(rctx, address, addrlen);
					delphinusdns_EVP_DigestFinal_ex(rctx, rdigest, &md_len);
					refusedtime = time(NULL);
					slen = reply_refused(&sreply, &sretlen, NULL, 0);

					dolog(LOG_INFO, "UDP connection refused on descriptor %u interface \"%s\" from %s (ttl=%d, region=%d) replying REFUSED, passlist policy\n", so, cfg->ident[i], address, received_ttl, aregion);
					goto drop;
				}

				if (ratelimit && rcheck) {
					dolog(LOG_INFO, "UDP connection refused on descriptor %u interface \"%s\" from %s (ttl=%d, region=%d) ratelimit policy dropping packet\n", so, cfg->ident[i], address, received_ttl, aregion);
					goto drop;
				}
				/*
				 * before we parse the message, check our
				 * cache if we've seen it before, and short
				 * circuit with a somewhat pretty message
				 */

				if ((slen = reply_cache(so, from, fromlen, &qc, buf, len, (char *)&cdomainname, &cclass, &ctype, &crc)) > 0) {
					if (lflag) {
						double diffms;

						/* we have no struct question so give back a small answer */

						gettimeofday(&rectv1, NULL);
						if (rectv1.tv_sec - rectv0.tv_sec > 0) {
							rectv1.tv_usec += 1000000;
							rectv1.tv_sec--;
						}
						diffms = (((double)rectv1.tv_sec - (double)rectv0.tv_sec) \
								* 1000) + \
							(double)(rectv1.tv_usec - rectv0.tv_usec) / 1000;

						dolog(LOG_INFO, "request on descriptor %u interface \"%s\" from %s (ttl=%u, region=%d, tta=%2.3fms) for \"%s\" type=%s class=%u, answering \"CACHEHIT\" (bytes=%d/%d, sum=%x)\n", so, cfg->ident[i], address, received_ttl, aregion, diffms, cdomainname, get_dns_type(ntohs(ctype), 1), ntohs(cclass), len, slen, crc);
					/* post-filling of build_reply for stats */
					}

					goto drop;
				}

				crc = crc16((uint8_t *)buf, len);

				ret = send_to_parser(cfg, pibuf, buf, len, &pq);
				switch (ret) {	
				case -1:
					goto drop;
				case PARSE_RETURN_NOTAQUESTION:
					dolog(LOG_INFO, "on descriptor %u interface \"%s\" dns header from %s is not a question, drop\n", so, cfg->ident[i], address);
					goto drop;
				case PARSE_RETURN_NOQUESTION:
					dolog(LOG_INFO, "on descriptor %u interface \"%s\" header from %s has no question, drop\n", so, cfg->ident[i], address);
					/* format error */
					build_reply(&sreply, so, buf, len, NULL, from, fromlen, NULL, NULL, aregion, istcp, 0, replybuf, NULL);
					slen = reply_fmterror(&sreply, &sretlen, NULL);
					dolog(LOG_INFO, "question on descriptor %d interface \"%s\" from %s, did not have question of 1 replying format error\n", so, cfg->ident[i], address);
					goto drop;
				case PARSE_RETURN_MALFORMED:
					dolog(LOG_INFO, "on descriptor %u interface \"%s\" malformed question from %s, drop\n", so, cfg->ident[i], address);
					goto drop;
				case PARSE_RETURN_NAK:
					dolog(LOG_INFO, "on descriptor %u interface \"%s\" illegal dns packet length from %s, drop\n", so, cfg->ident[i], address);
					goto drop;
				case PARSE_RETURN_NOTAUTH:
					if (filter && pq.tsig.have_tsig == 0) {
						build_reply(&sreply, so, buf, len, NULL, from, fromlen, NULL, NULL, aregion, istcp, 0, replybuf, NULL);
						delphinusdns_EVP_DigestInit_ex(rctx, md, NULL);
						delphinusdns_EVP_DigestUpdate(rctx, (void*)&buf[2], len - 2);
						delphinusdns_EVP_DigestUpdate(rctx, address, addrlen);
						delphinusdns_EVP_DigestFinal_ex(rctx, rdigest, &md_len);
refusedtime = time(NULL);
						slen = reply_refused(&sreply, &sretlen, NULL, 0);
						dolog(LOG_INFO, "UDP connection refused on descriptor %u interface \"%s\" from %s (ttl=%d, region=%d) replying REFUSED, not a tsig\n", so, cfg->ident[i], address, received_ttl, aregion);
						goto drop;
					}

					/* FALLTHROUGH */
				default:
					question = convert_question(&pq, 1);
					if (question == NULL) {
						dolog(LOG_INFO, "on descriptor %u interface \"%s\" internal error from %s, drop\n", so, cfg->ident[i], address);
						goto drop;
					}

					break;
				}

		
				/* goto drop beyond this point should goto out instead */

				/* check if there was cookies that had errors */
				if (question->cookie.have_cookie && question->cookie.error == 1) {
						dolog(LOG_INFO, "on descriptor %u interface \"%s\" BADCOOKIE from %s, replying format error\n", so, cfg->ident[i], address);
						snprintf(replystring, DNS_MAXNAME, "FMTERROR");
						build_reply(&sreply, so, buf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, replybuf, NULL);
						slen = reply_fmterror(&sreply, &sretlen, NULL);
						goto udpout;
				}

				/* handle notifications */
				if (question->notify) {
					if (question->tsig.have_tsig && notifysource(question, (struct sockaddr_storage *)from) &&
							question->tsig.tsigverified == 1) {
							dolog(LOG_INFO, "on descriptor %u interface \"%s\" authenticated dns NOTIFY packet from %s, replying NOTIFY\n", so, cfg->ident[i], address);
							snprintf(replystring, DNS_MAXNAME, "NOTIFY");
							build_reply(&sreply, so, buf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, replybuf, NULL);
							slen = reply_notify(&sreply, &sretlen, NULL);
							/* send notify to replicant process */
							idata = (pid_t)question->hdr->namelen;
							imsg_compose(udp_ibuf, IMSG_NOTIFY_MESSAGE, 
									0, 0, -1, question->hdr->name, idata);
							msgbuf_write(&udp_ibuf->w);
							goto udpout;
					
					} else if (question->tsig.have_tsig && question->tsig.tsigerrorcode != 0) {
							dolog(LOG_INFO, "on descriptor %u interface \"%s\" not authenticated dns NOTIFY packet (code = %d) from %s, replying notauth\n", so, cfg->ident[i], question->tsig.tsigerrorcode, address);
							snprintf(replystring, DNS_MAXNAME, "NOTAUTH");
							build_reply(&sreply, so, buf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, replybuf, NULL);
							slen = reply_notauth(&sreply, &sretlen, NULL);
							goto udpout;
					}

					if (notifysource(question, (struct sockaddr_storage *)from)) {
						dolog(LOG_INFO, "on descriptor %u interface \"%s\" dns NOTIFY packet from %s, replying NOTIFY\n", so, cfg->ident[i], address);
						snprintf(replystring, DNS_MAXNAME, "NOTIFY");
						build_reply(&sreply, so, buf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, replybuf, NULL);
						slen = reply_notify(&sreply, &sretlen, NULL);
							idata = (pid_t)question->hdr->namelen;
							imsg_compose(udp_ibuf, IMSG_NOTIFY_MESSAGE, 
									0, 0, -1, question->hdr->name, idata);
							msgbuf_write(&udp_ibuf->w);
						goto udpout;
					} else {
						/* RFC 1996 - 3.10 is probably broken reply REFUSED */
						dolog(LOG_INFO, "on descriptor %u interface \"%s\" dns NOTIFY packet from %s, NOT in our list of PRIMARY servers replying REFUSED\n", so, cfg->ident[i], address);
						snprintf(replystring, DNS_MAXNAME, "REFUSED");
						build_reply(&sreply, so, buf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, replybuf, NULL);
						delphinusdns_EVP_DigestInit_ex(rctx, md, NULL);
						delphinusdns_EVP_DigestUpdate(rctx, (void*)&buf[2], len - 2);
						delphinusdns_EVP_DigestUpdate(rctx, address, addrlen);
						delphinusdns_EVP_DigestFinal_ex(rctx, rdigest, &md_len);
						refusedtime = time(NULL);

						slen = reply_refused(&sreply, &sretlen, NULL, 1);

						goto udpout;
					}
				} /* if question->notify */

				if (question->tsig.have_tsig && question->tsig.tsigerrorcode != 0)  {
					/* if the name on the passlist is not present */ 
					if (question->tsig.have_tsig &&
						question->tsig.tsigerrorcode == DNS_BADTIME &&
						tsigpassname &&
							! (question->hdr->namelen <= 1) &&
							tsigpassname_contains(question->hdr->name, question->hdr->namelen, &passnamewc)) {
							dolog(LOG_INFO, "passing %s despite being a TSIG unauthenticated query\n", question->converted_name);
					} else {
							dolog(LOG_INFO, "on descriptor %u interface \"%s\" not authenticated dns packet (code = %d) from %s, replying notauth\n", so, cfg->ident[i], question->tsig.tsigerrorcode, address);
							snprintf(replystring, DNS_MAXNAME, "NOTAUTH");
							build_reply(&sreply, so, buf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, replybuf, NULL);
							slen = reply_notauth(&sreply, &sretlen, NULL);
							/* add this reply to the cache */
							add_cache(&qc, &buf[2], len - 2, question, sreply.replybuf, sretlen, crc);
							goto udpout;
					}
				}
				/* hack around whether we're edns version 0 */
				if (question->ednsversion != 0) {
					build_reply(&sreply, so, buf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, replybuf, NULL);
					slen = reply_badvers(&sreply, &sretlen, NULL);
					/* add this reply to the cache */
					add_cache(&qc, &buf[2], len - 2, question, sreply.replybuf, sretlen, crc);

					dolog(LOG_INFO, "on descriptor %u interface \"%s\" edns version is %u from %s, replying badvers\n", so, cfg->ident[i], question->ednsversion, address);

					snprintf(replystring, DNS_MAXNAME, "BADVERS");
					goto udpout;
				}

				if (ntohs(question->hdr->qclass) == DNS_CLASS_CH &&
					ntohs(question->hdr->qtype) == DNS_TYPE_TXT &&
					strcasecmp(question->converted_name, "version.bind.") == 0) {
							snprintf(replystring, DNS_MAXNAME, "VERSION");
							build_reply(&sreply, so, buf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, replybuf, NULL);
							slen = reply_version(&sreply, &sretlen, NULL);
							/* add this reply to the cache */
							add_cache(&qc, &buf[2], len - 2, question, sreply.replybuf, sretlen, crc);
							goto udpout;
				}

				fakequestion = NULL;

				rbt0 = lookup_zone(cfg->db, question, &type0, &lzerrno, (char *)&replystring, sizeof(replystring));
				if (type0 < 0) {
					switch (lzerrno) {
					default:
						dolog(LOG_INFO, "invalid lzerrno! dropping\n");
						/* FALLTHROUGH */
					case ERR_DROP:
						snprintf(replystring, DNS_MAXNAME, "DROP");
						slen = 0;
						goto udpout;
					case ERR_REFUSED:
						snprintf(replystring, DNS_MAXNAME, "REFUSED");

						build_reply(&sreply, so, buf, len, question, from, fromlen, rbt0, NULL, aregion, istcp, 0, replybuf, NULL);
						delphinusdns_EVP_DigestInit_ex(rctx, md, NULL);
						delphinusdns_EVP_DigestUpdate(rctx, (void*)&buf[2], len - 2);
						delphinusdns_EVP_DigestUpdate(rctx, address, addrlen);
						delphinusdns_EVP_DigestFinal_ex(rctx, rdigest, &md_len);
						refusedtime = time(NULL);
						slen = reply_refused(&sreply, &sretlen, NULL, 1);

						goto udpout;
						break;
					case ERR_NXDOMAIN:
						/*
						 * lookup_zone could not find an RR for the
						 * question at all -> nxdomain
						 */
						snprintf(replystring, DNS_MAXNAME, "NXDOMAIN");

					       /*
					 	* lookup an authoritative soa 
					 	*/
					
						if (rbt0 != NULL) {
							build_reply(&sreply, so, buf, len, question, from, \
							fromlen, rbt0, NULL, aregion, istcp, \
							0, replybuf, NULL);

							slen = reply_nxdomain(&sreply, &sretlen, cfg->db);
							/* add this reply to the cache */
							add_cache(&qc, &buf[2], len - 2, question, sreply.replybuf, sretlen, crc);

						}
						goto udpout;
						break;

					case ERR_NODATA:
						if (rbt1) {
							rbt1 = NULL;
						}

						rbt1 = get_soa(cfg->db, question);
						if (rbt1 != NULL) {
							snprintf(replystring, DNS_MAXNAME, "NODATA");
							build_reply(&sreply, so, buf, len, question, from, fromlen, rbt1, rbt0, aregion, istcp, 0, replybuf, NULL);
							slen = reply_nodata(&sreply, &sretlen, cfg->db);
						} else {
							if (forward)
								goto forwardudp;
							build_reply(&sreply, so, buf, len, question, from, fromlen, rbt1, rbt0, aregion, istcp, 0, replybuf, NULL);
							delphinusdns_EVP_DigestInit_ex(rctx, md, NULL);
							delphinusdns_EVP_DigestUpdate(rctx, (void*)&buf[2], len - 2);
							delphinusdns_EVP_DigestUpdate(rctx, address, addrlen);
							delphinusdns_EVP_DigestFinal_ex(rctx, rdigest, &md_len);
							refusedtime = time(NULL);


							slen = reply_refused(&sreply, &sretlen, cfg->db, 1);
							snprintf(replystring, DNS_MAXNAME, "REFUSED");
						}
						goto udpout;
						break;
	
					case ERR_FORWARD:
forwardudp:
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

											dolog(LOG_INFO, "passing %s despite being a TSIG unauthenticated query\n", question->converted_name);
									} else {
											snprintf(replystring, DNS_MAXNAME, "REFUSED");
											build_reply(&sreply, so, buf, len, question, from, fromlen, rbt1, rbt0, aregion, istcp, 0, replybuf, NULL);

											delphinusdns_EVP_DigestInit_ex(rctx, md, NULL);
											delphinusdns_EVP_DigestUpdate(rctx, (void*)&buf[2], len - 2);
											delphinusdns_EVP_DigestUpdate(rctx, address, addrlen);
											delphinusdns_EVP_DigestFinal_ex(rctx, rdigest, &md_len);
											refusedtime = time(NULL);

											slen = reply_refused(&sreply, &sretlen, cfg->db, 1);
											goto udpout;
									}
								}
						} else
								snprintf(replystring, DNS_MAXNAME, "FORWARD");

						/* send query to forward process/cortex */

						if (len > 4000) {
							dolog(LOG_INFO, "question is larger than 4000 bytes, not forwarding\n");
							goto udpout;
						}

						memset(sforward, 0, sizeof(struct sforward));
						sforward->oldsel = oldsel;

						switch (from->sa_family) {
						case AF_INET:
							sforward->rport = sin->sin_port;
							memcpy((char *)&sforward->from4, sin, fromlen);
							sforward->family = AF_INET;
						
							break;
						case AF_INET6:
							sforward->rport = sin6->sin6_port;
							memcpy((char *)&sforward->from6, sin6, fromlen);
							sforward->family = AF_INET6;
						
							break;
						}
						
						memcpy(&sforward->buf, question->hdr->original_name, question->hdr->namelen);
						sforward->buflen = question->hdr->namelen;
		
						memcpy((char *)&sforward->header, buf, sizeof(struct dns_header));
						sforward->type = question->hdr->qtype;
						sforward->class = question->hdr->qclass;
						sforward->edns0len = MIN(question->edns0len, max_udp_payload);
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
							dolog(LOG_INFO, "delphinusdnsd udp: can't find an open slot in sharedmemsize\n");
							goto udpout;
						}

						sm_unlock(cfg->shm[SM_FORWARD].shptr, 
								cfg->shm[SM_FORWARD].shptrsize);

						imsg_compose(udp_ibuf, IMSG_FORWARD_UDP,
							0, 0, -1, &ix, sizeof(int));

						msgbuf_write(&udp_ibuf->w);
						goto udpout;
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
							build_reply(&sreply, so, buf, len, question, from, \
								fromlen, rbt0, NULL, aregion, istcp, 0, 
								replybuf, NULL);

							slen = reply_noerror(&sreply, &sretlen, cfg->db);
							/* add this reply to the cache */
							add_cache(&qc, &buf[2], len - 2, question, sreply.replybuf, sretlen, crc);

							goto udpout;
						} 

						snprintf(replystring, DNS_MAXNAME, "DROP");
						slen = 0;
						goto udpout;

					case ERR_DELEGATE:
						if (rbt0 != NULL) {
							build_reply(&sreply, so, buf, len, question, from, \
							fromlen, rbt0, NULL, aregion, istcp, \
							0, replybuf, NULL);

							slen = reply_ns(&sreply, &sretlen, cfg->db);
							/* add this reply to the cache */
							add_cache(&qc, &buf[2], len - 2, question, sreply.replybuf, sretlen, crc);
						} else {
							slen = 0;
							snprintf(replystring, DNS_MAXNAME, "DROP");
						}

						goto udpout;
						break;
						
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
					 build_reply(&sreply, so, buf, len, question, from, \
							fromlen, NULL, NULL, aregion, istcp, 0, \
							replybuf, NULL);

					slen = reply_notimpl(&sreply, &sretlen, NULL);
					/* add this reply to the cache */
					add_cache(&qc, &buf[2], len - 2, question, sreply.replybuf, sretlen, crc);
					snprintf(replystring, DNS_MAXNAME, "NOTIMPL");
					goto udpout;
				}

				for (rl = &rlogic[0]; rl->rrtype != 0; rl++) {
					if (rl->rrtype == ntohs(question->hdr->qtype)) {
						if (rl->type0 == type0) {
							switch (rl->buildtype) {
							case BUILD_CNAME:
								build_reply(&sreply, so, buf, len, question,
									from, fromlen, rbt0, ((type1 > 0) ? rbt1 : 
									NULL), aregion, istcp, 0, replybuf, NULL);
								break;
							case BUILD_OTHER:
								build_reply(&sreply, so, buf, len, question, 
									from, fromlen, rbt0, NULL, aregion, istcp,
									0, replybuf, NULL);
								break;
							}
						} else {
							continue;
						}

						slen = (*rl->reply)(&sreply, &sretlen, cfg->db);
						/* add this reply to the cache */
						add_cache(&qc, &buf[2], len - 2, question, sreply.replybuf, sretlen, crc);
						break;
					} /* if rl->rrtype == */
				}

				if (rl->rrtype == 0) {
					/*
					 * ANY unkown RR TYPE gets a NOTIMPL
					 */
					/*
					 * except for delegations
					 */
					
					if (type0 == DNS_TYPE_NS) {

						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, rbt0, NULL, aregion, istcp, 0, \
							replybuf, NULL);

						slen = reply_ns(&sreply, &sretlen, cfg->db);
						/* add this reply to the cache */
						add_cache(&qc, &buf[2], len - 2, question, sreply.replybuf, sretlen, crc);
					} else {

						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, NULL, NULL, aregion, istcp, 0, \
							replybuf, NULL);

						slen = reply_notimpl(&sreply, &sretlen, NULL);
						/* add this reply to the cache */
						add_cache(&qc, &buf[2], len - 2, question, sreply.replybuf, sretlen, crc);

						snprintf(replystring, DNS_MAXNAME, "NOTIMPL");
					}
				}
			
		udpout:
				if (lflag) {
					double diffms;

					gettimeofday(&rectv1, NULL);
					if (rectv1.tv_sec - rectv0.tv_sec > 0) {
						rectv1.tv_usec += 1000000;
						rectv1.tv_sec--;
					}
					diffms = (((double)rectv1.tv_sec - (double)rectv0.tv_sec) \
							* 1000) + \
						(double)(rectv1.tv_usec - rectv0.tv_usec) / 1000;

					dolog(LOG_INFO, "request on descriptor %u interface \"%s\" from %s (ttl=%u, region=%d, tta=%2.3fms) for \"%s\" type=%s class=%u, %s%s%s%sanswering \"%s\" (bytes=%d/%d, sum=%x)\n", so, cfg->ident[i], address, received_ttl, aregion, diffms, question->converted_name, get_dns_type(ntohs(question->hdr->qtype), 1), ntohs(question->hdr->qclass), (question->edns0len ? "edns0, " : ""), (question->dnssecok ? "dnssecok, " : ""), (question->tsig.tsigverified ? "tsig, " : ""), (question->cookie.have_cookie ? "cookie, " : "") , replystring, len, slen, crc);

				}

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

			}	/* END ISSET */

		} /* for */

	drop:
		
		if (rbt0) {	
			rbt0 = NULL;
		}

		if (rbt1) {
			rbt1 = NULL;
		}

		continue;
	}  /* for (;;) */

	/* NOTREACHED */
}

/*
 * ADD_CACHE - add up to (size of cache) entries to the cache.
 *
 */

int
add_cache(struct querycache *qc, char *buf, int len, struct question *q,  char *reply, int replylen, uint16_t crc)
{
	DDD_EVP_MD_CTX *ctx;
	const DDD_EVP_MD *md = md5_md;
	u_char rdigest[MD5_DIGEST_LENGTH];	
	u_int md_len;
	struct csnode *n, *res, find;
	struct csentry *np;

	if (replylen == -1 || replylen > qc->bufsize)
		return -1;

	/* don't cache cookied requests, it's not an error either */
	if (cookies && q->cookie.have_cookie && q->cookie.error == 0)
		return 0;

	qc->cp = (qc->cp + 1) % qc->cm;
	
	/* find the node tailq with the appropriate slot */
	RB_FOREACH(n, qctree, &qchead) {
		TAILQ_FOREACH(np, &n->head, entries)
			if (np->cs == &qc->cs[qc->cp])
				goto next;
	}

	if (n == NULL) {
		dolog(LOG_INFO, "querycache damaged\n");
		return (-1);
	}
next:
	/* remove the tailq */
	TAILQ_REMOVE(&n->head, np, entries);
	/* if the tree node is empty remove it too */
	if (TAILQ_EMPTY(&n->head)) {
		RB_REMOVE(qctree, &qchead, n);
		free(n);
	}

	memcpy(np->cs->reply, reply, replylen);
	np->cs->replylen = replylen;

	if (len > QC_REQUESTSIZE) {
		ctx = delphinusdns_EVP_MD_CTX_new();
		if (ctx == NULL)
			return -1;
		if (md == NULL) {
			return -1;
		}
		delphinusdns_EVP_DigestInit_ex(ctx, md, NULL);
		delphinusdns_EVP_DigestUpdate(ctx, buf, len);
		delphinusdns_EVP_DigestFinal_ex(ctx, rdigest, &md_len);
		delphinusdns_EVP_MD_CTX_free(ctx);
	} else {
		memcpy(np->cs->request, buf, len);
	}

	strlcpy(np->cs->domainname, q->converted_name, DNS_MAXNAME + 1);
	np->cs->class = q->hdr->qclass;
	np->cs->type = q->hdr->qtype;
	np->cs->crc = crc;
	memcpy(np->cs->digest, rdigest, MD5_DIGEST_LENGTH);
	np->cs->requestlen = len + 2; /* XXX */

		
	find.requestlen = len + 2;
	/* search for a node with the same length index */
	if ((res = RB_FIND(qctree, &qchead, &find)) == NULL) {
		/* not found, insert what we have in a new node */
		n = malloc(sizeof(struct csnode));
		if (n == NULL) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
			return -1;
		}

		n->requestlen = len + 2;
		TAILQ_INIT(&n->head);
			
		RB_INSERT(qctree, &qchead, n);
		res = n;
	}

	/* add our tailq at the end of head */
	TAILQ_INSERT_HEAD(&res->head, np, entries);

	return 0;
}

int
reply_cache(int so, struct sockaddr *sa, int salen, struct querycache *qc, char *buf, int len, char *dn, uint16_t *class, uint16_t *type, uint16_t *crc)
{
	u_char rdigest[MD5_DIGEST_LENGTH];	
	u_int md_len;
	int needhash = 1;
	struct csnode find, *res;
	struct csentry *np;
	DDD_EVP_MD_CTX *ctx = NULL;
	DDD_EVP_MD *md = md5_md;

	ctx = delphinusdns_EVP_MD_CTX_new();
	if (ctx == NULL)
		return -1;

	if (md == NULL)
		return -1;

	find.requestlen = len;
	res = RB_FIND(qctree, &qchead, &find); 

	if (res != NULL) {
		TAILQ_FOREACH(np, &res->head, entries) {
			if ((len - 2) <= QC_REQUESTSIZE) {
				if (memcmp(&buf[2], np->cs->request, len - 2) == 0) {
					goto sendit;
				}
			} else {
				if (needhash) {
					delphinusdns_EVP_DigestInit_ex(ctx, md, NULL);
					delphinusdns_EVP_DigestUpdate(ctx, &buf[2], len - 2);
					delphinusdns_EVP_DigestFinal_ex(ctx, rdigest, &md_len);
					needhash = 0;
				}

				if (memcmp(rdigest, np->cs->digest, MD5_DIGEST_LENGTH) == 0) {
					goto sendit;
				}
			}
		}
	}

	delphinusdns_EVP_MD_CTX_free(ctx);
	return (0);

sendit:
	
	delphinusdns_EVP_MD_CTX_free(ctx);
	strlcpy(dn, np->cs->domainname, DNS_MAXNAME + 1);
	*class = np->cs->class;
	*type = np->cs->type;
	*crc = np->cs->crc;					/* crc accounting */
	memcpy(np->cs->reply, buf, 2);    	/* add query ID */

	return (sendto(so, np->cs->reply, 
		np->cs->replylen, 0, sa, salen));
	
}

uint16_t
crc16(uint8_t *buf, int len)
{
	uint16_t ret = 0;
	int i, rem;

	rem = len % 4;

	for (i = 0; i < (len - rem); i += 4) {
		ret += buf[i]; ret += buf[i + 1];
		ret += buf[i + 2]; ret += buf[i + 3];
	}

	switch (rem) {
	case 3:
		ret += buf[(len - rem) + 0]; ret += buf[(len - rem) + 1];
		ret += buf[(len - rem) + 2];
		break;
	case 2:
		ret += buf[(len - rem) + 0]; ret += buf[(len - rem) + 1];
		break;
	case 1:
		ret += buf[(len - rem) + 0];
		break;
	default:
		break;
	}

	return (ret);
}

int
intcmp(struct csnode *e1, struct csnode *e2)
{
	return (e1->requestlen < e2->requestlen ? -1 : e1->requestlen > \
		e2->requestlen);
}

int
same_refused(u_char *old_digest, void *buf, int len, void *address, int addrlen)
{
	DDD_EVP_MD_CTX *ctx;
	const DDD_EVP_MD *md = md5_md;
	u_char rdigest[MD5_DIGEST_LENGTH];	
	u_int md_len;

	if (md == NULL) {
		return 0;
	}

	ctx = delphinusdns_EVP_MD_CTX_new();
	if (ctx == NULL) {
		return 0;
	}

	delphinusdns_EVP_DigestInit_ex(ctx, md, NULL);
	delphinusdns_EVP_DigestUpdate(ctx, buf, len);
	delphinusdns_EVP_DigestUpdate(ctx, address, addrlen);
	delphinusdns_EVP_DigestFinal_ex(ctx, rdigest, &md_len);
	delphinusdns_EVP_MD_CTX_free(ctx);

	if (md_len != MD5_DIGEST_LENGTH)
		return (0);

	if (memcmp(rdigest, old_digest, sizeof(rdigest)) == 0)
		return (1);

	return (0);
}
