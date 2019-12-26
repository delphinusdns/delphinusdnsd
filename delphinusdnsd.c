/* 
 * Copyright (c) 2002-2019 Peter J. Philipp
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
 * $Id: delphinusdnsd.c,v 1.96 2019/12/26 15:51:04 pjp Exp $
 */


#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/queue.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/un.h>

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
#include "ddd-config.h"

/* prototypes */

extern void 	pack(char *, char *, int);
extern void 	pack32(char *, u_int32_t);
extern void 	pack16(char *, u_int16_t);
extern void 	pack8(char *, u_int8_t);
extern uint32_t unpack32(char *);
extern uint16_t unpack16(char *);
extern void 	unpack(char *, char *, int);

extern void 	add_rrlimit(int, u_int16_t *, int, char *);
extern void 	axfrloop(int *, int, char **, ddDB *, struct imsgbuf *);
extern void	replicantloop(ddDB *, struct imsgbuf *, struct imsgbuf *);
extern struct question	*build_fake_question(char *, int, u_int16_t, char *, int);
extern int 	check_ent(char *, int);
extern int 	check_rrlimit(int, u_int16_t *, int, char *);
extern void 	collects_init(void);
extern void 	dolog(int, char *, ...);
extern int     	find_axfr(struct sockaddr_storage *, int);
extern int 	find_filter(struct sockaddr_storage *, int);
extern u_int8_t find_region(struct sockaddr_storage *, int);
extern int 	find_whitelist(struct sockaddr_storage *, int);
extern int      find_tsig(struct sockaddr_storage *, int);
extern char *	get_dns_type(int, int);
extern void 	init_dnssec(void);
extern void 	init_region(void);
extern int	init_entlist(ddDB *);
extern void 	init_filter(void);
extern void 	init_whitelist(void);
extern void 	init_tsig(void);
extern void 	init_notifyslave(void);
extern struct rbtree * 	lookup_zone(ddDB *, struct question *, int *, int *, char *);
extern struct rbtree *  Lookup_zone(ddDB *, char *, u_int16_t, u_int16_t, int);
extern int 	memcasecmp(u_char *, u_char *, int);
extern int 	reply_a(struct sreply *, ddDB *);
extern int 	reply_aaaa(struct sreply *, ddDB *);
extern int 	reply_any(struct sreply *, ddDB *);
extern int 	reply_badvers(struct sreply *, ddDB *);
extern int	reply_nodata(struct sreply *, ddDB *);
extern int 	reply_cname(struct sreply *, ddDB *);
extern int 	reply_fmterror(struct sreply *, ddDB *);
extern int 	reply_notauth(struct sreply *, ddDB *);
extern int 	reply_notimpl(struct sreply *, ddDB *);
extern int 	reply_nxdomain(struct sreply *, ddDB *);
extern int 	reply_noerror(struct sreply *, ddDB *);
extern int	reply_notify(struct sreply *, ddDB *);
extern int 	reply_soa(struct sreply *, ddDB *);
extern int 	reply_mx(struct sreply *, ddDB *);
extern int 	reply_naptr(struct sreply *, ddDB *);
extern int 	reply_ns(struct sreply *, ddDB *);
extern int 	reply_ptr(struct sreply *, ddDB *);
extern int 	reply_refused(struct sreply *, ddDB *);
extern int 	reply_srv(struct sreply *, ddDB *);
extern int 	reply_sshfp(struct sreply *, ddDB *);
extern int 	reply_tlsa(struct sreply *, ddDB *);
extern int 	reply_txt(struct sreply *, ddDB *);
extern int 	reply_version(struct sreply *, ddDB *);
extern int      reply_rrsig(struct sreply *, ddDB *);
extern int	reply_dnskey(struct sreply *, ddDB *);
extern int	reply_ds(struct sreply *, ddDB *);
extern int	reply_nsec(struct sreply *, ddDB *);
extern int	reply_nsec3(struct sreply *, ddDB *);
extern int	reply_nsec3param(struct sreply *, ddDB *);
extern char 	*rrlimit_setup(int);
extern char 	*dns_label(char *, int *);
extern void 	slave_shutdown(void);
extern int 	get_record_size(ddDB *, char *, int);
extern struct question		*build_question(char *, int, int, char *);
extern int			free_question(struct question *);
extern struct rbtree * create_rr(ddDB *db, char *name, int len, int type, void *rdata);
extern struct rbtree * find_rrset(ddDB *db, char *name, int len);
extern struct rrset * find_rr(struct rbtree *rbt, u_int16_t rrtype);
extern int 	add_rr(struct rbtree *, char *, int, u_int16_t, void *);
extern int 	display_rr(struct rrset *rrset);
extern int 	notifysource(struct question *, struct sockaddr_storage *);
extern int 	drop_privs(char *, struct passwd *);
extern struct rbtree * 	get_soa(ddDB *, struct question *);
extern struct rbtree *	get_ns(ddDB *, struct rbtree *, int *);


struct question		*convert_question(struct parsequestion *);
void 			build_reply(struct sreply *, int, char *, int, struct question *, struct sockaddr *, socklen_t, struct rbtree *, struct rbtree *, u_int8_t, int, int, void *, char *);
int 			compress_label(u_char *, u_int16_t, int);
int			determine_glue(ddDB *db);
void			mainloop(struct cfg *, struct imsgbuf **);
void 			master_reload(int);
void 			master_shutdown(int);
void 			setup_master(ddDB *, char **, char *, struct imsgbuf *ibuf);
void 			setup_unixsocket(char *, struct imsgbuf *);
void 			slave_signal(int);
void 			tcploop(struct cfg *, struct imsgbuf **);
void 			parseloop(struct cfg *, struct imsgbuf **);

/* aliases */


#define MYDB_PATH "/var/db/delphinusdns"

/* structs */

static struct reply_logic {
	int rrtype;
	int type0;
	int buildtype;
#define BUILD_CNAME	1
#define BUILD_OTHER	2
	int (*reply)(struct sreply *, ddDB *);
} rlogic[] = {
	{ DNS_TYPE_A, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_A, DNS_TYPE_NS, BUILD_OTHER, reply_ns },
	{ DNS_TYPE_A, DNS_TYPE_A, BUILD_OTHER, reply_a },
	{ DNS_TYPE_AAAA, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_AAAA, DNS_TYPE_NS, BUILD_OTHER, reply_ns },
	{ DNS_TYPE_AAAA, DNS_TYPE_AAAA, BUILD_OTHER, reply_aaaa },
	{ DNS_TYPE_DNSKEY, DNS_TYPE_DNSKEY, BUILD_OTHER, reply_dnskey },
	{ DNS_TYPE_SOA, DNS_TYPE_SOA, BUILD_OTHER, reply_soa },
	{ DNS_TYPE_SOA, DNS_TYPE_NS, BUILD_OTHER, reply_ns },
	{ DNS_TYPE_MX, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_MX, DNS_TYPE_NS, BUILD_OTHER, reply_ns },
	{ DNS_TYPE_MX, DNS_TYPE_MX, BUILD_OTHER, reply_mx },
	{ DNS_TYPE_TXT, DNS_TYPE_TXT, BUILD_OTHER, reply_txt },
	{ DNS_TYPE_NS, DNS_TYPE_NS, BUILD_OTHER, reply_ns },
	{ DNS_TYPE_ANY, DNS_TYPE_ANY, BUILD_OTHER, reply_any },
	{ DNS_TYPE_DS, DNS_TYPE_DS, BUILD_OTHER, reply_ds },
	{ DNS_TYPE_SSHFP, DNS_TYPE_SSHFP, BUILD_OTHER, reply_sshfp },
	{ DNS_TYPE_TLSA, DNS_TYPE_TLSA, BUILD_OTHER, reply_tlsa },
	{ DNS_TYPE_SRV, DNS_TYPE_SRV, BUILD_OTHER, reply_srv },
	{ DNS_TYPE_CNAME, DNS_TYPE_CNAME, BUILD_OTHER, reply_cname },
	{ DNS_TYPE_CNAME, DNS_TYPE_NS, BUILD_OTHER, reply_ns },
	{ DNS_TYPE_NSEC3PARAM, DNS_TYPE_NSEC3PARAM, BUILD_OTHER, reply_nsec3param },
	{ DNS_TYPE_PTR, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_PTR, DNS_TYPE_NS, BUILD_OTHER, reply_ns },
	{ DNS_TYPE_PTR, DNS_TYPE_PTR, BUILD_OTHER, reply_ptr },
	{ DNS_TYPE_NAPTR, DNS_TYPE_NAPTR, BUILD_OTHER, reply_naptr },
	{ DNS_TYPE_NSEC3, DNS_TYPE_NSEC3, BUILD_OTHER, reply_nsec3 },
	{ DNS_TYPE_NSEC, DNS_TYPE_NSEC, BUILD_OTHER, reply_nsec },
	{ DNS_TYPE_RRSIG, DNS_TYPE_RRSIG, BUILD_OTHER, reply_rrsig },
	{ 0, 0, 0, NULL }
};

TAILQ_HEAD(, tcpentry) tcphead;

struct tcpentry {
	int intidx;
	uint bytes_read;
	int bytes_expected;
	uint bytes_limit;
	int seen;		/* seen heading bytes */
	int so;
	time_t last_used;
	char buf[65537];	
	char *address;
	TAILQ_ENTRY(tcpentry) tcpentries;
} *tcpn1, *tcpn2, *tcpnp;

/* global variables */

extern char *__progname;
extern int axfrport;
extern int ratelimit;
extern int ratelimit_packets_per_second;
extern int whitelist;
extern int tsig;
extern int dnssec;
extern int raxfrflag;

static int reload = 0;
static int mshutdown = 0;
static int msig;
static char *rptr;
static int ratelimit_backlog;

int debug = 0;
int verbose = 0;
int bflag = 0;
int iflag = 0;
int lflag = 0;
int nflag = 0;
int bcount = 0;
int icount = 0;
u_int16_t port = 53;
u_int32_t cachesize = 0;
char *bind_list[255];
char *interface_list[255];
#ifndef DD_VERSION
char *versionstring = "delphinusdnsd-1.4";
uint8_t vslen = 17;
#else
char *versionstring = DD_VERSION;
uint8_t vslen = DD_VERSION_LEN;
#endif
int *ptr = NULL;

/* 
 * MAIN - set up arguments, set up database, set up sockets, call mainloop
 *
 */

int
main(int argc, char *argv[], char *environ[])
{
	static int udp[DEFAULT_SOCKET];
	static int tcp[DEFAULT_SOCKET];
	static int afd[DEFAULT_SOCKET];
	static int uafd[DEFAULT_SOCKET];
	int n;

	int ch, i, j;
	int gai_error;
	int salen;
	int found = 0;
	int on = 1;

	pid_t pid;

	static char *ident[DEFAULT_SOCKET];
	char *conffile = CONFFILE;
	char buf[512];
	char **av = NULL;
	char *socketpath = SOCKPATH;
	
	struct passwd *pw;
	struct addrinfo hints, *res0, *res;
	struct ifaddrs *ifap, *pifap;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct cfg *cfg;
	struct imsgbuf  **parent_ibuf, **child_ibuf;

	static ddDB *db;

	
	if (geteuid() != 0) {
		fprintf(stderr, "must be started as root\n");
		exit(1);
	}

	av = argv;

#if __linux__
	setproctitle_init(argc, av, environ);
#endif


	while ((ch = getopt(argc, argv, "b:df:i:ln:p:s:v")) != -1) {
		switch (ch) {
		case 'b':
			bflag = 1;
			if (bcount > 253) {
				fprintf(stderr, "too many -b flags\n");
				exit(1);
			}
			bind_list[bcount++] = optarg;	
			break;
		case 'd':
			debug = 1;
			break;
		case 'f':
			conffile = optarg;
			break;
		case 'i':
			iflag = 1;
			if (icount > 254) {
				fprintf(stderr, "too many -i flags\n");
				exit(1);
			}
			interface_list[icount++] = optarg;
			break;
		case 'l':
			lflag = 1;
			break;
		case 'n':
			nflag = atoi(optarg);
			break;
		case 'p':
			port = atoi(optarg) & 0xffff;
			break;
		case 's':
			socketpath = optarg;
			break;
		case 'v':
			verbose++;
			break;
		default:
			fprintf(stderr, "usage: delphinusdnsd [-i interface] [-b bindaddress] [-f configfile] [-p portnumber] [-drv]\n");
			exit (1);
		}
	}

	if (bflag && iflag) {
		fprintf(stderr, "you may specify -i or -b but not both\n");
		exit(1);
	}

	/*
	 * calling daemon before a sleuth of configurations ala rwhod.c
	 */
	
	if (! debug)
		daemon(0,0);
	else {
		int status;
		/*
		 * clean up any zombies left behind, this is only in debug mode
		 */

		while (waitpid(-1, &status, WNOHANG) > 0);
	
		/*
		 * even if in debug mode we want to have our own parent group
		 * for reasons in that regress needs it when killing debug
		 * mode delphinusdnsd
		 */

#if __linux__
		if (setpgrp() < 0) {
#else
		if (setpgrp(0, 0) < 0) {
#endif
			perror("setpgrp");
			exit(1);
		}
	}


	openlog(__progname, LOG_PID | LOG_NDELAY, LOG_DAEMON);
	dolog(LOG_INFO, "starting up\n");

	/* cfg struct */
	cfg = calloc(1, sizeof(struct cfg));
	if (cfg == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		exit(1);
	}
	/* imsg structs */
	
	parent_ibuf = calloc(MY_IMSG_MAX + nflag, sizeof(struct imsgbuf *));
	if (parent_ibuf == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		exit(1);
	}

	child_ibuf = calloc(MY_IMSG_MAX + nflag, sizeof(struct imsgbuf *));
	if (child_ibuf == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		exit(1);
	}

	for (i = 0; i < MY_IMSG_MAX + nflag; i++) {
		child_ibuf[i] = calloc(1, sizeof(struct imsgbuf));
		if (child_ibuf[i] == NULL) {
			dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
			exit(1);
		}
		parent_ibuf[i] = calloc(1, sizeof(struct imsgbuf));
		if (parent_ibuf[i] == NULL) {
			dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
			exit(1);
		}
	}

		
		
	/*
	 * make a shared memory segment for signaling kills between 
	 * processes...
	 */

	
	ptr = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED |\
		MAP_ANON, -1, 0);

	if (ptr == MAP_FAILED) {
		dolog(LOG_ERR, "failed to setup mmap segment, exit\n");
		exit(1);
	}

	*ptr = 0;
	
	/* open internal database */

	db = dddbopen();
	if (db == NULL) {
		dolog(LOG_INFO, "dddbopen() failed\n");
		slave_shutdown();
		exit(1);
	}

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, PF_UNSPEC, &cfg->my_imsg[MY_IMSG_MASTER].imsg_fds[0]) < 0) {
		dolog(LOG_INFO, "socketpair() failed\n");
		slave_shutdown();
		exit(1);
	}

	pid = fork();
	switch (pid) {
	case -1:
		dolog(LOG_ERR, "fork(): %s\n", strerror(errno));
		exit(1);
	case 0:
		close(cfg->my_imsg[MY_IMSG_MASTER].imsg_fds[0]);
		imsg_init(child_ibuf[MY_IMSG_MASTER], cfg->my_imsg[MY_IMSG_MASTER].imsg_fds[1]);
		break;
	default:
		close(cfg->my_imsg[MY_IMSG_MASTER].imsg_fds[1]);
		imsg_init(parent_ibuf[MY_IMSG_MASTER], cfg->my_imsg[MY_IMSG_MASTER].imsg_fds[0]);

		setup_master(db, av, socketpath, parent_ibuf[MY_IMSG_MASTER]);
		/* NOTREACHED */
		exit(1);
	}

	if (! debug) {
		switch (pid = fork()) {
		case -1:
			dolog(LOG_ERR, "fork(): %s\n", strerror(errno));
			exit(1);
		case 0:
			/*
			 * add signals here too
			 */

			signal(SIGPIPE, SIG_IGN);

			signal(SIGTERM, slave_signal);
			signal(SIGINT, slave_signal);
			signal(SIGQUIT, slave_signal);

			setup_unixsocket(socketpath, child_ibuf[MY_IMSG_MASTER]);
			slave_shutdown();	
			exit(1);
		default:
			break;
		}
	} 


	/* end of setup_master code */
		
	init_region();
	init_filter();
	init_whitelist();
	init_dnssec();
	init_tsig();
	TAILQ_INIT(&tcphead);

	if (parse_file(db, conffile, 0) < 0) {
		dolog(LOG_INFO, "parsing config file failed\n");
		slave_shutdown();
		exit(1);
	}

	if (determine_glue(db) < 0) {
		dolog(LOG_INFO, "determine_glue() failed\n");
		slave_shutdown();
		exit(1);
	}

	if (init_entlist(db) < 0) {
		dolog(LOG_INFO, "creating entlist failed\n");
		slave_shutdown();
		exit(1);
	}

	/* ratelimiting setup */
	if (ratelimit) {
		ratelimit_backlog = ratelimit_packets_per_second * 2;
		rptr = rrlimit_setup(ratelimit_backlog);
		if (rptr == NULL) {
			dolog(LOG_INFO, "ratelimiting error\n");
			slave_shutdown();
			exit(1);
		}
	}
	

	pw = getpwnam(DEFAULT_PRIVILEGE);
	if (pw == NULL) {
		dolog(LOG_INFO, "getpwnam: %s\n", strerror(errno));
		slave_shutdown();
		exit(1);
	}

	if (bcount > DEFAULT_SOCKET) {
		dolog(LOG_INFO, "not enough sockets available\n");
		slave_shutdown();
		exit(1);
	}

	if (bflag) {
		for (i = 0; i < bcount; i++) {
			memset(&hints, 0, sizeof(hints));

			if (strchr(bind_list[i], ':') != NULL) {
				hints.ai_family = AF_INET6;
			} else {
				hints.ai_family = AF_INET;
			}

			hints.ai_socktype = SOCK_DGRAM;
			hints.ai_protocol = IPPROTO_UDP;
			hints.ai_flags = AI_NUMERICHOST;

			snprintf(buf, sizeof(buf) - 1, "%u", port);

			if ((gai_error = getaddrinfo(bind_list[i], buf, &hints, &res0)) != 0) {
				dolog(LOG_INFO, "getaddrinfo: %s\n", gai_strerror(gai_error));
				slave_shutdown();
				exit (1);
        		}

			res = res0;

			if ((udp[i] = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
				dolog(LOG_INFO, "socket: %s\n", strerror(errno));
				slave_shutdown();
				exit(1);
			}
        
			if (bind(udp[i], res->ai_addr, res->ai_addrlen) < 0) {
				dolog(LOG_INFO, "bind: %s\n", strerror(errno));
				slave_shutdown();
				exit(1);
			}

			if (res->ai_family == AF_INET) {
				if (setsockopt(udp[i], IPPROTO_IP, IP_RECVTTL,
					&on, sizeof(on)) < 0) {
				dolog(LOG_INFO, "setsockopt: %s\n", strerror(errno));
				}
			} else if (res->ai_family == AF_INET6) {
				/* RFC 3542 page 30 */
				on = 1;
     				if (setsockopt(udp[i], IPPROTO_IPV6, 
					IPV6_RECVHOPLIMIT, &on, sizeof(on)) < 0) {
					dolog(LOG_INFO, "setsockopt: %s\n", strerror(errno));
				}
			}

			ident[i] = bind_list[i];

			/* tcp below */
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_protocol = IPPROTO_TCP;
			hints.ai_flags = AI_NUMERICHOST;

			snprintf(buf, sizeof(buf) - 1, "%u", port);

			if ((gai_error = getaddrinfo(bind_list[i], buf, &hints, &res0)) != 0) {
				dolog(LOG_INFO, "getaddrinfo: %s\n", gai_strerror(gai_error));
				slave_shutdown();
				exit (1);
        		}

			res = res0;

			if ((tcp[i] = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
				dolog(LOG_INFO, "tcp socket: %s\n", strerror(errno));
				slave_shutdown();
				exit(1);
			}
       			if (setsockopt(tcp[i], SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
				dolog(LOG_INFO, "setsockopt: %s\n", strerror(errno));
				slave_shutdown();
				exit(1);
			} 
			if (bind(tcp[i], res->ai_addr, res->ai_addrlen) < 0) {
				dolog(LOG_INFO, "tcp bind: %s\n", strerror(errno));
				slave_shutdown();
				exit(1);
			}

			if (axfrport && axfrport != port) {
				/* axfr port below */
				hints.ai_socktype = SOCK_STREAM;
				hints.ai_protocol = IPPROTO_TCP;
				hints.ai_flags = AI_NUMERICHOST;

				snprintf(buf, sizeof(buf) - 1, "%u", axfrport);

				if ((gai_error = getaddrinfo(bind_list[i], buf, &hints, &res0)) != 0) {
					dolog(LOG_INFO, "getaddrinfo: %s\n", gai_strerror(gai_error));
					slave_shutdown();
					exit (1);
				}

				res = res0;

				if ((afd[i] = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
					dolog(LOG_INFO, "tcp socket: %s\n", strerror(errno));
					slave_shutdown();
					exit(1);
				}
				if (setsockopt(afd[i], SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
					dolog(LOG_INFO, "setsockopt: %s\n", strerror(errno));
					slave_shutdown();
					exit(1);
				} 
				if (bind(afd[i], res->ai_addr, res->ai_addrlen) < 0) {
					dolog(LOG_INFO, "tcp bind: %s\n", strerror(errno));
					slave_shutdown();
					exit(1);
				}

				if ((uafd[i] = socket(res->ai_family, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
					dolog(LOG_INFO, "axfr udp socket: %s\n", strerror(errno));
					slave_shutdown();
					exit(1);
				}
				if (bind(uafd[i], res->ai_addr, res->ai_addrlen) < 0) {
					dolog(LOG_INFO, "axfr udp socket bind: %s\n", strerror(errno));
					slave_shutdown();
					exit(1);
				}
			} else if (axfrport && axfrport == port) {
				afd[i] = -1;
			}

		} /* for .. bcount */

	} else {
		if (getifaddrs(&ifap) < 0) {
			dolog(LOG_INFO, "getifaddrs\n");
			slave_shutdown();
			exit(1);
		}

		for (pifap = ifap, i = 0; i < DEFAULT_SOCKET && pifap; pifap = pifap->ifa_next, i++) {

			found = 0;

			/* we want only one interface not the rest */
			if (icount > 0) {
				for (j = 0; j < icount; j++) {
					if (strcmp(pifap->ifa_name, interface_list[j]) == 0) {
						found = 1;
					}
				}

				if (! found) {
					i--;
					continue;
				}

			}
			if ((pifap->ifa_flags & IFF_UP) != IFF_UP) {
				dolog(LOG_INFO, "skipping interface %s\n", pifap->ifa_name);
				i--;
				continue;
			}

			if (pifap->ifa_addr->sa_family == AF_INET) {
				sin = (struct sockaddr_in *)pifap->ifa_addr;
				sin->sin_port = htons(port);
				salen = sizeof(struct sockaddr_in);
				/* no address bound to this interface */
				if (sin->sin_addr.s_addr == INADDR_ANY) {
					i--;
					continue;
				}
			} else if (pifap->ifa_addr->sa_family == AF_INET6) {
				sin6 = (struct sockaddr_in6 *)pifap->ifa_addr;
				sin6->sin6_port = htons(port);
				/* no address bound to this interface */
				salen = sizeof(struct sockaddr_in6);

			} else {
				dolog(LOG_DEBUG, "unknown address family %d\n", pifap->ifa_addr->sa_family);
				i--;
				continue;
			}
				

			if ((udp[i] = socket(pifap->ifa_addr->sa_family, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
				dolog(LOG_INFO, "socket: %s\n", strerror(errno));
				slave_shutdown();
				exit(1);
			}
			
			if (bind(udp[i], (struct sockaddr *)pifap->ifa_addr, salen) < 0) {
				dolog(LOG_INFO, "bind: %s\n", strerror(errno));
				slave_shutdown();
				exit(1);
			}

			if (pifap->ifa_addr->sa_family == AF_INET) {
				if (setsockopt(udp[i], IPPROTO_IP, IP_RECVTTL,
					&on, sizeof(on)) < 0) {
				dolog(LOG_INFO, "setsockopt: %s\n", strerror(errno));
				}
			} else if (pifap->ifa_addr->sa_family == AF_INET6) {
				/* RFC 3542 page 30 */
				on = 1;
     				if (setsockopt(udp[i], IPPROTO_IPV6, 
					IPV6_RECVHOPLIMIT, &on, sizeof(on)) < 0) {
					dolog(LOG_INFO, "setsockopt: %s\n", strerror(errno));
				}
			}


			ident[i] = pifap->ifa_name;

			if ((tcp[i] = socket(pifap->ifa_addr->sa_family, SOCK_STREAM, IPPROTO_TCP)) < 0) {
				dolog(LOG_INFO, "tcp socket: %s\n", strerror(errno));
				slave_shutdown();
				exit(1);
			}
       			if (setsockopt(tcp[i], SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
				dolog(LOG_INFO, "setsockopt: %s\n", strerror(errno));
				slave_shutdown();
				exit(1);
			} 
			
			if (bind(tcp[i], (struct sockaddr *)pifap->ifa_addr, salen) < 0) {
				dolog(LOG_INFO, "tcp bind: %s\n", strerror(errno));
				slave_shutdown();
				exit(1);
			}		


			/* axfr socket */
			if (axfrport && axfrport != port) {
				if ((afd[i] = socket(pifap->ifa_addr->sa_family, SOCK_STREAM, IPPROTO_TCP)) < 0) {
					dolog(LOG_INFO, "tcp socket: %s\n", strerror(errno));
					slave_shutdown();
					exit(1);
				}
				if (setsockopt(afd[i], SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
					dolog(LOG_INFO, "setsockopt: %s\n", strerror(errno));
					slave_shutdown();
					exit(1);
				} 

				((struct sockaddr_in *)pifap->ifa_addr)->sin_port = htons(axfrport);
				
				if (bind(afd[i], (struct sockaddr *)pifap->ifa_addr, salen) < 0) {
					dolog(LOG_INFO, "tcp bind: %s\n", strerror(errno));
					slave_shutdown();
					exit(1);
				}
				if ((uafd[i] = socket(pifap->ifa_addr->sa_family, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
					dolog(LOG_INFO, "axfr udp socket: %s\n", strerror(errno));
					slave_shutdown();
					exit(1);
				}
				if (bind(uafd[i], (struct sockaddr *)pifap->ifa_addr, salen) < 0) {
					dolog(LOG_INFO, "udp axfr bind: %s\n", strerror(errno));
					slave_shutdown();
					exit(1);
				}
			} else if (axfrport && axfrport == port) {
				afd[i] = -1;
			}

		} /* AF_INET */

		if (i >= DEFAULT_SOCKET) {
			dolog(LOG_INFO, "not enough sockets available\n");
			slave_shutdown();
			exit(1);
		}
	} /* if bflag? */

#if __OpenBSD__
	if (unveil(DELPHINUS_RZONE_PATH, "rwc")  < 0) {
		perror("unveil");
		slave_shutdown();
		exit(1);
	}
	if (unveil(pw->pw_dir, "wc") < 0) {
		perror("unveil");
		slave_shutdown();
		exit(1);
	}

#endif

	/*
	 * add signals
	 */

	signal(SIGPIPE, SIG_IGN);

	signal(SIGTERM, slave_signal);
	signal(SIGINT, slave_signal);
	signal(SIGQUIT, slave_signal);

	/* 
	 * start our axfr process 
	 */

	if (axfrport) {	
		if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, &cfg->my_imsg[MY_IMSG_AXFR].imsg_fds[0]) < 0) {
			dolog(LOG_INFO, "socketpair() failed\n");
			slave_shutdown();
			exit(1);
		}
		switch (pid = fork()) {
		case -1:
			dolog(LOG_ERR, "fork() failed: %s\n", strerror(errno));
			slave_shutdown();
			exit(1);
		case 0:
			/* chroot to the drop priv user home directory */
#ifdef DEFAULT_LOCATION
			if (drop_privs(DEFAULT_LOCATION, pw) < 0) {
#else
			if (drop_privs(pw->pw_dir, pw) < 0) {
#endif
				dolog(LOG_INFO, "axfr dropping privileges\n", strerror(errno));
				slave_shutdown();
				exit(1);
			}
#if __OpenBSD__
			if (pledge("stdio inet proc id sendfd recvfd unveil", NULL) < 0) {
				perror("pledge");
				exit(1);
			}
#endif

			/* close descriptors that we don't need */
			for (j = 0; j < i; j++) {
				close(tcp[j]);
				close(udp[j]);
				if (axfrport && axfrport != port)
					close(uafd[j]);
			}

			setproctitle("AXFR engine on port %d", axfrport);

			/* don't need master here */
			close(cfg->my_imsg[MY_IMSG_MASTER].imsg_fds[1]);
			close(cfg->my_imsg[MY_IMSG_AXFR].imsg_fds[1]);
			imsg_init(parent_ibuf[MY_IMSG_AXFR], cfg->my_imsg[MY_IMSG_AXFR].imsg_fds[0]);

			axfrloop(afd, (axfrport == port) ? 0 : i, ident, db, parent_ibuf[MY_IMSG_AXFR]);
			/* NOTREACHED */
			exit(1);
		default:
			/* close afd descriptors, they aren't needed here */
			for (j = 0; j < i; j++) {
				if (axfrport && axfrport != port)
					close(afd[j]);
			}
			/* XXX these are reversed because we need to use child_ibuf later */
			close(cfg->my_imsg[MY_IMSG_AXFR].imsg_fds[0]);
			imsg_init(child_ibuf[MY_IMSG_AXFR], cfg->my_imsg[MY_IMSG_AXFR].imsg_fds[1]);

			break;
		}
	
	} /* axfrport */

	if (raxfrflag) {

		if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, &cfg->my_imsg[MY_IMSG_RAXFR].imsg_fds[0]) < 0) {
			dolog(LOG_INFO, "socketpair() failed\n");
			slave_shutdown();
			exit(1);
		}

		switch (pid = fork()) {
		case -1:
			dolog(LOG_ERR, "fork() failed: %s\n", strerror(errno));
			slave_shutdown();
			exit(1);
		case 0:
			/* chroot to the drop priv user home directory */
			if (drop_privs(DELPHINUS_RZONE_PATH, pw) < 0) {
				dolog(LOG_INFO, "raxfr dropping privileges failed", strerror(errno));
				slave_shutdown();
				exit(1);
			}

#if __OpenBSD__
			if (unveil("/replicant", "rwc") < 0) {
				perror("unveil");
				slave_shutdown();
				exit(1);
			}

			if (pledge("stdio inet proc id sendfd recvfd unveil cpath wpath rpath", NULL) < 0) {
				perror("pledge");
				slave_shutdown();
				exit(1);
			}
#endif

			/* close descriptors that we don't need */
			for (j = 0; j < i; j++) {
				close(tcp[j]);
				close(udp[j]);
			}

			setproctitle("Replicant engine");

			/* don't need master here */
#if 0
			close(cfg->my_imsg[MY_IMSG_MASTER].imsg_fds[1]);
#endif
			/* close any axfr's */
			close(cfg->my_imsg[MY_IMSG_AXFR].imsg_fds[0]);
			/* close the replicant parent */
			close(cfg->my_imsg[MY_IMSG_RAXFR].imsg_fds[1]);
			imsg_init(parent_ibuf[MY_IMSG_RAXFR], cfg->my_imsg[MY_IMSG_RAXFR].imsg_fds[0]);

			replicantloop(db, parent_ibuf[MY_IMSG_RAXFR], child_ibuf[MY_IMSG_MASTER]);

			/* NOTREACHED */
			exit(1);

		default:

			close(cfg->my_imsg[MY_IMSG_RAXFR].imsg_fds[0]);
			imsg_init(child_ibuf[MY_IMSG_RAXFR], cfg->my_imsg[MY_IMSG_RAXFR].imsg_fds[1]);
		
			break;
		}

	} /* raxfrflag */

	/* the rest of the daemon goes on in TCP and UDP loops */
#ifdef DEFAULT_LOCATION
	if (drop_privs(DEFAULT_LOCATION, pw) < 0) {
#else
	if (drop_privs(pw->pw_dir, pw) < 0) {
#endif
		dolog(LOG_INFO, "dropping privileges failed\n");
		slave_shutdown();
		exit(1);
	}
#if __OpenBSD__
	if (unveil(NULL, NULL) < 0) {
		dolog(LOG_INFO, "unveil locking failed: %s\n", strerror(errno));
		slave_shutdown();
		exit(1);
	}
	if (pledge("stdio inet proc id sendfd recvfd", NULL) < 0) {
		perror("pledge");
		exit(1);
	}
#endif

	/* what follows is a bit mangled code, we set up nflag + 1 amount of
	 * server instances (1 per cpu?) and if we're recursive we also set up
	 * the same amount of recursive instances all connected through a 
	 * socketpair() so that it looks somewhat like this (with 4 instances):
	 *
     	 *     replies      <---     [] ---- [] recursive end
     	 *                           |
     	 *     replies      <---     [] ---- []
      	 *    request * --->         |
     	 *     replies      <---     [] ---- []
     	 *                           |
     	 *     replies      <---     [] ---- []
	 *
	 */

	cfg->pid = 0;
	cfg->nth = 0;

	for (n = 0; n < nflag; n++) {
		if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, &cfg->my_imsg[MY_IMSG_MAX + n].imsg_fds[0]) < 0) {
			dolog(LOG_INFO, "socketpair() failed\n");
			slave_shutdown();
			exit(1);
		}

		switch (pid = fork()) {
		case 0:
			cfg->pid = getpid();
			cfg->nth = n;
			cfg->sockcount = i;
			cfg->db = db;
			for (i = 0; i < cfg->sockcount; i++) {
				cfg->udp[i] = udp[i];
				cfg->tcp[i] = tcp[i];

				if (axfrport && axfrport != port)
					cfg->axfr[i] = uafd[i];

				cfg->ident[i] = strdup(ident[i]);
			}

			close(cfg->my_imsg[MY_IMSG_MAX + n].imsg_fds[0]);
			imsg_init(child_ibuf[MY_IMSG_MAX + n], cfg->my_imsg[MY_IMSG_MAX + n].imsg_fds[1]);
			
			setproctitle("child %d pid %d", n, cfg->pid);
			(void)mainloop(cfg, child_ibuf);

			/* NOTREACHED */
		default:	
			close(cfg->my_imsg[MY_IMSG_MAX + n].imsg_fds[1]);
			imsg_init(child_ibuf[MY_IMSG_MAX + n], cfg->my_imsg[MY_IMSG_MAX + n].imsg_fds[0]);
			break;
		} /* switch pid= fork */
	} /* for (.. nflag */

	cfg->sockcount = i;
	cfg->db = db;
	for (i = 0; i < cfg->sockcount; i++) {
		cfg->udp[i] = udp[i];
		cfg->tcp[i] = tcp[i];

		if (axfrport && axfrport != port)
			cfg->axfr[i] = uafd[i];

		cfg->ident[i] = strdup(ident[i]);
	}

	(void)mainloop(cfg, child_ibuf);

	/* NOTREACHED */
	return (0);
}



/*
 * COMPRESS_LABEL - 	compress a DNS name, must be passed an entire reply
 *			with the to be compressed name before the offset of 
 *			that reply.
 */

int
compress_label(u_char *buf, u_int16_t offset, int labellen)
{
	u_char *label[256];		/* should be enough */
	u_char *end = &buf[offset];
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
	struct soa {
         	u_int32_t serial;
                u_int32_t refresh;
                u_int32_t retry;
                u_int32_t expire;
                u_int32_t minttl;
        } __attribute__((packed));

	struct answer *a;

	u_int i, j;
	u_int checklen;

	u_char *p, *e;
	u_char *compressmark;


	p = &buf[sizeof(struct dns_header)];
	label[0] = p;
	
	while (p <= end && *p) {
		p += *p;
		p++;
	}	
		
	/* 
	 * the question label was bogus, we'll just get out of there, return 0
	 */

	if (p >= end)
		return (0);

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

			if (p >= end)
				goto end;
		}	
			
		p++;	/* one more */


		a = (struct answer *)p;
		p += sizeof(struct answer);	

		/* Thanks FreeLogic! */
		if (p >= end)
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
		case DNS_TYPE_TLSA:
			p += 2;
			switch (*p) {
			case 1:
				p += DNS_TLSA_SIZE_SHA256 + 1;
				break;
			case 2:
				p += DNS_TLSA_SIZE_SHA512 + 1;
				break;
			default:
				/* XXX */
				goto end;
			}

			break;
		case DNS_TYPE_SSHFP:
			p++;
			switch (*p) {
			case 1:
				p += DNS_SSHFP_SIZE_SHA1 + 1;
				break;
			case 2:
				p += DNS_SSHFP_SIZE_SHA256 + 1;
				break;
			default:
				/* XXX */
				goto end;
			}

			break;	
		case DNS_TYPE_SRV:
			p += (2 * sizeof(u_int16_t)); /* priority, weight */
			/* the port will be assumed in the fall through for
			   mx_priority..
			*/
			/* FALLTHROUGH */
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

				if (p >= end)
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
				if (p >= end)
					goto end;
			}	

			p++;	/* one more */

			if (p >= end)
				break;

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

			if (p >= end)
				break;

			p += sizeof(struct soa);	/* advance struct soa */

			break;
		case DNS_TYPE_NAPTR:
			p += (2 * sizeof(u_int16_t)); /* order and preference */
			p += *p; /* flags */
			p++;
			p += *p; /* services */
			p++;
			p += *p; /* regexp */
			p++;
			
			label[++i] = p;
			while (p <= end && *p) {
				if ((*p & 0xc0) == 0xc0) {
					p++;
					break;
				}
				p += *p;
				p++;

				if (p >= end)
					goto end;
			}	

			p++;	/* one more */
			break;

		default:
			break;
			/* XXX */
		} /* switch */

		if (p >= end)
			break;
	} /* for (i *) */

end:
	
	p = &buf[offset - labellen];
	checklen = labellen;

	for (;*p != 0;) {
		for (j = 0; j < i; j++) {
			for (e = label[j]; *e; e += *e, e++) {
				if ((*e & 0xc0) == 0xc0) 
					break;

				if (memcasecmp(e, p, checklen) == 0) {
					/* e is now our compress offset */
					compressmark = e;
					goto out;		/* found one */
				}  
			}	/* for (e .. */
	
		} /* for (j .. */ 

		if (*p > DNS_MAXLABEL)
			return 0;		/* totally bogus label */

		checklen -= *p;
		p += *p;
		checklen--;
		p++;
	}

	return (0);	 	/* no compression possible */

out:
	/* take off our compress length */
	offset -= checklen;
	/* write compressed label */
	pack16(&buf[offset], htons((compressmark - &buf[0]) | 0xc000));

	offset += sizeof(u_int16_t);	

	return (offset);
}



/*
 * MAINLOOP - does the polling of tcp & udp descriptors and if ready receives the 
 * 		requests, builds the question and calls for replies, loops
 *
 */
		
void
mainloop(struct cfg *cfg, struct imsgbuf **ibuf)
{
	fd_set rset;
	pid_t pid;

	int sel;
	int len, slen = 0;
	int is_ipv6;
	int i;
	int istcp = 1;
	int maxso;
	int so;
	int type0, type1;
	int lzerrno;
	int filter = 0;
	int rcheck = 0;
	int blacklist = 1;
	int require_tsig = 0;
	int sp; 
	int idata;

	u_int32_t received_ttl;
	u_int32_t imsg_type;
	u_char *ttlptr;

	u_int8_t aregion;			/* region where the address comes from */

	char buf[4096];
	char *replybuf = NULL;
	char address[INET6_ADDRSTRLEN];
	char replystring[DNS_MAXNAME + 1];
	char fakereplystring[DNS_MAXNAME + 1];
	char controlbuf[64];

	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} sockaddr_large;

	socklen_t fromlen = sizeof(sockaddr_large);

	struct sockaddr *from = (void *)&sockaddr_large;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	struct question *question = NULL, *fakequestion = NULL;
	struct parsequestion pq;
	struct rbtree *rbt0 = NULL, *rbt1 = NULL;
	struct rrset *csd;
	struct rr *rr_csd;
	
	struct sreply sreply;
	struct reply_logic *rl = NULL;
	struct timeval tv = { 10, 0};

	struct msghdr msgh;
	struct cmsghdr *cmsg = NULL;
	struct iovec iov;
	struct imsgbuf tcp_ibuf, parse_ibuf;
	struct imsgbuf *pibuf;
	struct imsg imsg;

	ssize_t n, datalen;
	

	replybuf = calloc(1, 65536);
	if (replybuf == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		slave_shutdown();
		exit(1);
	 }

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, &cfg->my_imsg[MY_IMSG_PARSER].imsg_fds[0]) < 0) {
		dolog(LOG_INFO, "socketpair() failed\n");
		slave_shutdown();
		exit(1);
	}

	pid = fork();
	switch (pid) {
	case -1:
		dolog(LOG_ERR, "fork(): %s\n", strerror(errno));
		exit(1);
	case 0:
		for (i = 0; i < cfg->sockcount; i++)  {
				close(cfg->udp[i]);
				close(cfg->tcp[i]);
				if (axfrport && axfrport != port)
					close(cfg->axfr[i]);
		}
		close(cfg->my_imsg[MY_IMSG_MASTER].imsg_fds[1]);
		close(cfg->my_imsg[MY_IMSG_AXFR].imsg_fds[1]);
		close(cfg->my_imsg[MY_IMSG_PARSER].imsg_fds[1]);
		imsg_init(ibuf[MY_IMSG_PARSER], cfg->my_imsg[MY_IMSG_PARSER].imsg_fds[0]);
		setproctitle("udp parse engine %d", cfg->pid);
		parseloop(cfg, ibuf);
		/* NOTREACHED */
		exit(1);
	default:
		close(cfg->my_imsg[MY_IMSG_PARSER].imsg_fds[0]);
		imsg_init(&parse_ibuf, cfg->my_imsg[MY_IMSG_PARSER].imsg_fds[1]);
		pibuf = &parse_ibuf;
		break;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, &cfg->my_imsg[MY_IMSG_TCP].imsg_fds[0]) < 0) {
		dolog(LOG_INFO, "socketpair() failed\n");
		slave_shutdown();
		exit(1);
	}

	pid = fork();
	switch (pid) {
	case -1:
		dolog(LOG_ERR, "fork(): %s\n", strerror(errno));
		exit(1);
	case 0:
		for (i = 0; i < cfg->sockcount; i++)  {
				close(cfg->udp[i]);
				if (axfrport && axfrport != port)
					close(cfg->axfr[i]);
		}
		close(cfg->my_imsg[MY_IMSG_PARSER].imsg_fds[1]); /* we open our own */
		close(cfg->my_imsg[MY_IMSG_MASTER].imsg_fds[1]);
		close(cfg->my_imsg[MY_IMSG_TCP].imsg_fds[1]);
		imsg_init(ibuf[MY_IMSG_TCP], cfg->my_imsg[MY_IMSG_TCP].imsg_fds[0]);
		setproctitle("TCP engine %d", cfg->pid);
		tcploop(cfg, ibuf);
		/* NOTREACHED */
		exit(1);
	default:
		for (i = 0; i < cfg->sockcount; i++)  {
				close(cfg->tcp[i]);
		}
		close(cfg->my_imsg[MY_IMSG_TCP].imsg_fds[0]);
		imsg_init(&tcp_ibuf, cfg->my_imsg[MY_IMSG_TCP].imsg_fds[1]);
		break;
	}

#if __OpenBSD__
	if (pledge("stdio inet sendfd recvfd", NULL) < 0) {
		perror("pledge");
		exit(1);
	}
#endif


	sp = cfg->recurse;

	for (;;) {
		is_ipv6 = 0;
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
			/* send an imsg hello to the root owned process */

			idata = 42;
			imsg_compose(ibuf[MY_IMSG_MASTER], IMSG_HELLO_MESSAGE, 
				0, 0, -1, &idata, sizeof(idata));
			msgbuf_write(&ibuf[MY_IMSG_MASTER]->w);

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
axfrentry:
				fromlen = sizeof(sockaddr_large);

				memset(&msgh, 0, sizeof(msgh));
				iov.iov_base = buf;
				iov.iov_len = sizeof(buf);
				msgh.msg_name = from;
				msgh.msg_namelen = fromlen;
				msgh.msg_iov = &iov;
				msgh.msg_iovlen = 1;
				msgh.msg_control = (struct cmsghdr*)&controlbuf;
				msgh.msg_controllen = sizeof(controlbuf);
			
				len = recvmsg(so, &msgh, 0);
				if (len < 0) {
					dolog(LOG_INFO, "recvmsg: on descriptor %u interface \"%s\" %s\n", so, cfg->ident[i], strerror(errno));
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
											dolog(LOG_INFO, "cmsg->cmsg_len == %d\n", cmsg->cmsg_len);
											continue;
										}

										ttlptr = (u_char *) CMSG_DATA(cmsg);
										received_ttl = (u_int)*ttlptr;
                     				}
				}
	
				if (from->sa_family == AF_INET6) {
					is_ipv6 = 1;

					fromlen = sizeof(struct sockaddr_in6);
					sin6 = (struct sockaddr_in6 *)from;
					inet_ntop(AF_INET6, (void *)&sin6->sin6_addr, (char *)&address, sizeof(address));
					if (ratelimit) {
						add_rrlimit(ratelimit_backlog, (u_int16_t *)&sin6->sin6_addr, sizeof(sin6->sin6_addr), rptr);

						rcheck = check_rrlimit(ratelimit_backlog, (u_int16_t *)&sin6->sin6_addr, sizeof(sin6->sin6_addr), rptr);
					}

					aregion = find_region((struct sockaddr_storage *)sin6, AF_INET6);
					filter = 0;
					filter = find_filter((struct sockaddr_storage *)sin6, AF_INET6);
					if (whitelist) {
						blacklist = find_whitelist((struct sockaddr_storage *)sin6, AF_INET6);
					}
					
					require_tsig = 0;
					if (tsig) {
						require_tsig = find_tsig((struct sockaddr_storage *)sin6, AF_INET6);
					}

				} else if (from->sa_family == AF_INET) {
					is_ipv6 = 0;
					
					fromlen = sizeof(struct sockaddr_in);
					sin = (struct sockaddr_in *)from;
					inet_ntop(AF_INET, (void *)&sin->sin_addr, (char *)&address, sizeof(address));
					if (ratelimit) {
						add_rrlimit(ratelimit_backlog, (u_int16_t *)&sin->sin_addr.s_addr, sizeof(sin->sin_addr.s_addr), rptr);

						rcheck = check_rrlimit(ratelimit_backlog, (u_int16_t *)&sin->sin_addr.s_addr, sizeof(sin->sin_addr.s_addr), rptr);
					}

					aregion = find_region((struct sockaddr_storage *)sin, AF_INET);
					filter = 0;
					filter = find_filter((struct sockaddr_storage *)sin, AF_INET);
					if (whitelist) {
						blacklist = find_whitelist((struct sockaddr_storage *)sin, AF_INET);
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

				if (filter && require_tsig == 0) {

					build_reply(&sreply, so, buf, len, NULL, from, fromlen, NULL, NULL, aregion, istcp, 0, NULL, replybuf);
					slen = reply_refused(&sreply, NULL);

					dolog(LOG_INFO, "UDP connection refused on descriptor %u interface \"%s\" from %s (ttl=%d, region=%d) replying REFUSED, filter policy\n", so, cfg->ident[i], address, received_ttl, aregion);
					goto drop;
				}

				if (whitelist && blacklist == 0) {

					build_reply(&sreply, so, buf, len, NULL, from, fromlen, NULL, NULL, aregion, istcp, 0, NULL, replybuf);
					slen = reply_refused(&sreply, NULL);

					dolog(LOG_INFO, "UDP connection refused on descriptor %u interface \"%s\" from %s (ttl=%d, region=%d) replying REFUSED, whitelist policy\n", so, cfg->ident[i], address, received_ttl, aregion);
					goto drop;
				}

				if (ratelimit && rcheck) {
					dolog(LOG_INFO, "UDP connection refused on descriptor %u interface \"%s\" from %s (ttl=%d, region=%d) ratelimit policy dropping packet\n", so, cfg->ident[i], address, received_ttl, aregion);
					goto drop;
				}
					
				/* pjp - branch to pledge parser here */
				imsg_type = IMSG_PARSE_MESSAGE;
				
				if (imsg_compose(pibuf, imsg_type, 
					0, 0, -1, buf, len) < 0) {
					dolog(LOG_INFO, "imsg_compose %s\n", strerror(errno));
				}
				msgbuf_write(&pibuf->w);

				FD_ZERO(&rset);
				FD_SET(pibuf->fd, &rset);

				tv.tv_sec = 10;
				tv.tv_usec = 0;

				sel = select(pibuf->fd + 1, &rset, NULL, NULL, &tv);

				if (sel < 0) {
					dolog(LOG_ERR, "internal error around select, dropping packet\n");
					goto drop;
				}

				if (sel == 0) {
					dolog(LOG_ERR, "internal error, timeout on parse imsg, drop\n");
					goto drop;
				}

				if (FD_ISSET(pibuf->fd, &rset)) {
	
						if (((n = imsg_read(pibuf)) == -1 && errno != EAGAIN) || n == 0) {
							dolog(LOG_ERR, "internal error, timeout on parse imsg, drop\n");
							goto drop;
						}

						for (;;) {
						
							if ((n = imsg_get(pibuf, &imsg)) == -1) {
								break;
							}

							if (n == 0) {
								break;
							}

							datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

							switch (imsg.hdr.type) {
							case IMSG_PARSEREPLY_MESSAGE:
								if (datalen != sizeof(struct parsequestion)) {
									dolog(LOG_ERR, "datalen != sizeof(struct parsequestion), can't work with this, drop\n");
									goto drop;
								}
					
								memcpy((char *)&pq, imsg.data, datalen);

								if (pq.rc != PARSE_RETURN_ACK) {
									switch (pq.rc) {
									case PARSE_RETURN_MALFORMED:
										dolog(LOG_INFO, "on descriptor %u interface \"%s\" malformed question from %s, drop\n", so, cfg->ident[i], address);
										imsg_free(&imsg);
										goto drop;
									case PARSE_RETURN_NOQUESTION:
										dolog(LOG_INFO, "on descriptor %u interface \"%s\" header from %s has no question, drop\n", so, cfg->ident[i], address);
										/* format error */
										build_reply(&sreply, so, buf, len, NULL, from, fromlen, NULL, NULL, aregion, istcp, 0, NULL, replybuf);
										slen = reply_fmterror(&sreply, NULL);
										dolog(LOG_INFO, "question on descriptor %d interface \"%s\" from %s, did not have question of 1 replying format error\n", so, cfg->ident[i], address);
										imsg_free(&imsg);
										goto drop;
									case PARSE_RETURN_NOTAQUESTION:
										dolog(LOG_INFO, "on descriptor %u interface \"%s\" dns header from %s is not a question, drop\n", so, cfg->ident[i], address);
										imsg_free(&imsg);
										goto drop;
									case PARSE_RETURN_NAK:
										dolog(LOG_INFO, "on descriptor %u interface \"%s\" illegal dns packet length from %s, drop\n", so, cfg->ident[i], address);
										imsg_free(&imsg);
										goto drop;
									case PARSE_RETURN_NOTAUTH:
										/* we didn't see a tsig header */
										if (filter && pq.tsig.have_tsig == 0) {
											build_reply(&sreply, so, buf, len, NULL, from, fromlen, NULL, NULL, aregion, istcp, 0, NULL, replybuf);
											slen = reply_refused(&sreply, NULL);
											dolog(LOG_INFO, "UDP connection refused on descriptor %u interface \"%s\" from %s (ttl=%d, region=%d) replying REFUSED, not a tsig\n", so, cfg->ident[i], address, received_ttl, aregion);
											imsg_free(&imsg);
											goto drop;
										}
									}
								}

								question = convert_question(&pq);
								if (question == NULL) {
									dolog(LOG_INFO, "on descriptor %u interface \"%s\" internal error from %s, drop\n", so, cfg->ident[i], address);
									imsg_free(&imsg);
									goto drop;
								}

											
									
								break;
							} /* switch */

							imsg_free(&imsg);
						} /* for (;;) */
				} else { 	 /* FD_ISSET */
					goto drop;
				}

				/* goto drop beyond this point should goto out instead */
				/* handle notifications */
				if (question->notify) {
					if (question->tsig.have_tsig && notifysource(question, (struct sockaddr_storage *)from) &&
							question->tsig.tsigverified == 1) {
							dolog(LOG_INFO, "on descriptor %u interface \"%s\" authenticated dns NOTIFY packet from %s, replying NOTIFY\n", so, cfg->ident[i], address);
							snprintf(replystring, DNS_MAXNAME, "NOTIFY");
							build_reply(&sreply, so, buf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, NULL, replybuf);
							slen = reply_notify(&sreply, NULL);

							/* send notify to replicant process */
							idata = question->hdr->namelen;
							imsg_compose(ibuf[MY_IMSG_RAXFR], IMSG_NOTIFY_MESSAGE, 
									0, 0, -1, question->hdr->name, idata);
							msgbuf_write(&ibuf[MY_IMSG_RAXFR]->w);
							goto udpout;
					
					} else if (question->tsig.have_tsig && question->tsig.tsigerrorcode != 0) {
							dolog(LOG_INFO, "on descriptor %u interface \"%s\" not authenticated dns NOTIFY packet (code = %d) from %s, replying notauth\n", so, cfg->ident[i], question->tsig.tsigerrorcode, address);
							snprintf(replystring, DNS_MAXNAME, "NOTAUTH");
							build_reply(&sreply, so, buf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, NULL, replybuf);
							slen = reply_notauth(&sreply, NULL);
							goto udpout;
					}

					if (notifysource(question, (struct sockaddr_storage *)from)) {
						dolog(LOG_INFO, "on descriptor %u interface \"%s\" dns NOTIFY packet from %s, replying NOTIFY\n", so, cfg->ident[i], address);
						snprintf(replystring, DNS_MAXNAME, "NOTIFY");
						build_reply(&sreply, so, buf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, NULL, replybuf);
						slen = reply_notify(&sreply, NULL);
							/* send notify to replicant process */
							idata = question->hdr->namelen;
							imsg_compose(ibuf[MY_IMSG_RAXFR], IMSG_NOTIFY_MESSAGE, 
									0, 0, -1, question->hdr->name, idata);
							msgbuf_write(&ibuf[MY_IMSG_RAXFR]->w);
						goto udpout;
					} else {
						/* RFC 1996 - 3.10 is probably broken reply REFUSED */
						dolog(LOG_INFO, "on descriptor %u interface \"%s\" dns NOTIFY packet from %s, NOT in our list of MASTER servers replying REFUSED\n", so, cfg->ident[i], address);
						snprintf(replystring, DNS_MAXNAME, "REFUSED");
						build_reply(&sreply, so, buf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, NULL, replybuf);
						slen = reply_refused(&sreply, NULL);

						goto udpout;
					}
				} /* if question->notify */

				if (question->tsig.have_tsig && question->tsig.tsigerrorcode != 0)  {
					dolog(LOG_INFO, "on descriptor %u interface \"%s\" not authenticated dns packet (code = %d) from %s, replying notauth\n", so, cfg->ident[i], question->tsig.tsigerrorcode, address);
					snprintf(replystring, DNS_MAXNAME, "NOTAUTH");
					build_reply(&sreply, so, buf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, NULL, replybuf);
					slen = reply_notauth(&sreply, NULL);
					goto udpout;
				}
				/* hack around whether we're edns version 0 */
				if (question->ednsversion != 0) {
					build_reply(&sreply, so, buf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, NULL, replybuf);
					slen = reply_badvers(&sreply, NULL);

					dolog(LOG_INFO, "on TCP descriptor %u interface \"%s\" edns version is %u from %s, replying badvers\n", so, cfg->ident[i], question->ednsversion, address);

					snprintf(replystring, DNS_MAXNAME, "BADVERS");
					goto udpout;
				}

				if (ntohs(question->hdr->qclass) == DNS_CLASS_CH &&
					ntohs(question->hdr->qtype) == DNS_TYPE_TXT &&
					strcasecmp(question->converted_name, "version.bind.") == 0) {
							snprintf(replystring, DNS_MAXNAME, "VERSION");
							build_reply(&sreply, so, buf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, NULL, replybuf);
							slen = reply_version(&sreply, NULL);
							goto udpout;
				}

				fakequestion = NULL;

				rbt0 = lookup_zone(cfg->db, question, &type0, &lzerrno, (char *)&replystring);
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

						build_reply(&sreply, so, buf, len, question, from, fromlen, rbt0, NULL, aregion, istcp, 0, NULL, replybuf);
						slen = reply_refused(&sreply, NULL);
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
							0, NULL, replybuf);

							slen = reply_nxdomain(&sreply, cfg->db);
						}
						goto udpout;
						break;

					case ERR_NODATA:
						if (rbt1) {
							free(rbt1);
							rbt1 = NULL;
						}

						rbt1 = get_soa(cfg->db, question);
						if (rbt1 != NULL) {
							snprintf(replystring, DNS_MAXNAME, "NODATA");
							build_reply(&sreply, so, buf, len, question, from, fromlen, rbt1, rbt0, aregion, istcp, 0, NULL, replybuf);
							slen = reply_nodata(&sreply, cfg->db);
						} else {
							build_reply(&sreply, so, buf, len, question, from, fromlen, rbt1, rbt0, aregion, istcp, 0, NULL, replybuf);
							slen = reply_refused(&sreply, cfg->db);
							snprintf(replystring, DNS_MAXNAME, "REFUSED");
						}
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
							free (rbt0);
							rbt0 = NULL;
						}
						
						rbt0 = get_soa(cfg->db, question);
						if (rbt0 != NULL) {
							build_reply(&sreply, so, buf, len, question, from, \
								fromlen, rbt0, NULL, aregion, istcp, 0, 
								NULL, replybuf);

							slen = reply_noerror(&sreply, cfg->db);

							goto udpout;
						} 

						snprintf(replystring, DNS_MAXNAME, "DROP");
						slen = 0;
						goto udpout;

					case ERR_DELEGATE:
						if (rbt0 != NULL) {
							build_reply(&sreply, so, buf, len, question, from, \
							fromlen, rbt0, NULL, aregion, istcp, \
							0, NULL, replybuf);

							slen = reply_ns(&sreply, cfg->db);
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

					rbt1 = lookup_zone(cfg->db, fakequestion, &type1, &lzerrno, (char *)&fakereplystring);
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
							NULL, replybuf);

					slen = reply_notimpl(&sreply, NULL);
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
									NULL), aregion, istcp, 0, NULL, replybuf);
								break;
							case BUILD_OTHER:
								build_reply(&sreply, so, buf, len, question, 
									from, fromlen, rbt0, NULL, aregion, istcp,
									0, NULL, replybuf);
								break;
							}
						} else {
							continue;
						}
							
						slen = (*rl->reply)(&sreply, cfg->db);
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
							NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);
					} else {


						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, NULL, NULL, aregion, istcp, 0, \
							NULL, replybuf);

						slen = reply_notimpl(&sreply, NULL);
						snprintf(replystring, DNS_MAXNAME, "NOTIMPL");
					}
				}
			
		udpout:
				if (lflag) {
					dolog(LOG_INFO, "request on descriptor %u interface \"%s\" from %s (ttl=%u, region=%d) for \"%s\" type=%s class=%u, %s%s%sanswering \"%s\" (%d/%d)\n", so, cfg->ident[i], address, received_ttl, aregion, question->converted_name, get_dns_type(ntohs(question->hdr->qtype), 1), ntohs(question->hdr->qclass), (question->edns0len ? "edns0, " : ""), (question->dnssecok ? "dnssecok, " : ""), (question->tsig.tsigverified ? "tsig, " : "") , replystring, len, slen);

				}

				if (fakequestion != NULL) {
					free_question(fakequestion);
				}
	
				free_question(question);

				if (rbt0) {
					free (rbt0);
					rbt0 = NULL;
				}
				if (rbt1) {
					free (rbt1);
					rbt1 = NULL;
				}

			}	/* END ISSET */

		} /* for */

	drop:
		
		if (rbt0) {	
			free(rbt0);
			rbt0 = NULL;
		}

		if (rbt1) {
			free(rbt1);
			rbt1 = NULL;
		}

		continue;
	}  /* for (;;) */

	/* NOTREACHED */
}

/*
 * BUILD_REPLY - a function that populates struct reply from arguments, doesn't
 * 		 return anything.  This replaces the alias BUILD_REPLY.
 *
 */

void
build_reply(struct sreply *reply, int so, char *buf, int len, struct question *q, struct sockaddr *sa, socklen_t slen, struct rbtree *rbt1, struct rbtree *rbt2, u_int8_t region, int istcp, int deprecated0, void *sr, char *replybuf)
{
	reply->so = so;
	reply->buf = buf;
	reply->len = len;
	reply->q = q;
	reply->sa = sa;
	reply->salen = slen;
	reply->rbt1 = rbt1;
	reply->rbt2 = rbt2;
	reply->region = region;
	reply->istcp = istcp;
	reply->wildcard = 0;
	reply->sr = NULL;
	reply->replybuf = replybuf;

	return;
}
		

/*
 * The master process, waits to be killed, if any other processes are killed
 * and they indicate shutdown through the shared memory segment it will kill
 * the rest of processes in the parent group.
 */

void 
setup_master(ddDB *db, char **av, char *socketpath, struct imsgbuf *ibuf)
{
	pid_t pid;
	int sel, max = 0;

	ssize_t n;
	fd_set rset;

	struct timeval tv;
	struct imsg imsg;

#if __OpenBSD__
	if (unveil(socketpath, "rwc")  < 0) {
		perror("unveil");
		exit(1);
	}
	if (unveil("/usr/local/sbin/delphinusdnsd", "rx")  < 0) {
		perror("unveil");
		exit(1);
	}
	if (pledge("stdio wpath cpath exec proc", NULL) < 0) {
		perror("pledge");
		exit(1);
	}
#endif
	
#ifndef NO_SETPROCTITLE
	setproctitle("master");
#endif

	pid = getpid();

	signal(SIGTERM, master_shutdown);
	signal(SIGINT, master_shutdown);
	signal(SIGQUIT, master_shutdown);
	signal(SIGHUP, master_reload);

	FD_ZERO(&rset);	
	for (;;) {
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		FD_SET(ibuf->fd, &rset);
		if (ibuf->fd > max)
			max = ibuf->fd;
	
		sel = select(max + 1, &rset, NULL, NULL, &tv);
		/* on signal or timeout check...*/
		if (sel < 1) {
			if (*ptr) {
				dolog(LOG_INFO, "pid %u died, killing delphinusdnsd\n", *ptr);
				master_shutdown(SIGTERM);
			}

			if (mshutdown) {
				dolog(LOG_INFO, "shutting down on signal %d\n", msig);
				if (! debug)
					unlink(socketpath);

				pid = getpgrp();
				killpg(pid, msig);

				exit(0);
			}

			if (reload) {
				signal(SIGTERM, SIG_IGN);

				pid = getpgrp();
				killpg(pid, SIGTERM);
				if (munmap(ptr, sizeof(int)) < 0) {
					dolog(LOG_ERR, "munmap: %s\n", strerror(errno));
				}
			
				if (! debug)
					unlink(socketpath);

				dolog(LOG_INFO, "restarting on SIGHUP or command\n");

				closelog();
#ifndef NO_SETPROCTITLE
#if __linux__
				setproctitle(NULL);
#endif
#endif
				if (execvp("/usr/local/sbin/delphinusdnsd", av) < 0) {
					dolog(LOG_ERR, "execvp: %s\n", strerror(errno));
				}
				/* NOTREACHED */
				exit(1);
			}		
			continue;
		}
	
		if (FD_ISSET(ibuf->fd, &rset)) {

			if ((n = imsg_read(ibuf)) < 0 && errno != EAGAIN) {
				dolog(LOG_ERR, "imsg read failure %s\n", strerror(errno));
				continue;
			}
			if (n == 0) {
				/* child died? */
				dolog(LOG_INFO, "sigpipe on child?  exiting.\n");
				exit(1);
			}

			for (;;) {
				if ((n = imsg_get(ibuf, &imsg)) < 0) {
					dolog(LOG_ERR, "imsg read error: %s\n", strerror(errno));
					break;
				} else {
					if (n == 0)
						break;

					switch(imsg.hdr.type) {
					case IMSG_HELLO_MESSAGE:
						/* dolog(LOG_DEBUG, "received hello from child\n"); */
						break;
					case IMSG_RELOAD_MESSAGE:
						reload = 1;
						break;	
					case IMSG_SHUTDOWN_MESSAGE:
						mshutdown = 1;
						msig = SIGTERM;
						break;
					}

					imsg_free(&imsg);
				}
			} /* for (;;) */
		} /* FD_ISSET... */
	} /* for (;;) */

	/* NOTREACHED */
}

/* 
 *  master_shutdown - unlink pid file and kill parent group
 */

void
master_shutdown(int sig)
{
	msig = sig;
	mshutdown = 1;
}

/* 
 * slave_signal - a slave got a signal, call slave_shutdown and exit..
 */

void
slave_signal(int sig)
{
	slave_shutdown();
	dolog(LOG_INFO, "shutting down on signal\n");
	exit(1);
}

/*
 * master_reload - reload the delphinusdnsd system
 */

void
master_reload(int sig)
{
	reload = 1;
}


/*
 * TCPLOOP - does the polling of tcp descriptors and if ready receives the 
 * 		requests, builds the question and calls for replies, loops
 *
 */
		
void
tcploop(struct cfg *cfg, struct imsgbuf **ibuf)
{
	fd_set rset;
	int sel;
	int len, slen = 0, length = 0;
	int is_ipv6;
	int i;
	int istcp = 1;
	int maxso;
	int so;
	int type0, type1;
	int lzerrno;
	int filter = 0;
	int blacklist = 1;
	int require_tsig = 0;
	int axfr_acl = 0;
	int sp; 
	int idata;
	uint conncnt = 0;
	int tcpflags;
	pid_t pid;

	u_int8_t aregion;			/* region where the address comes from */

	char *pbuf;
	char *replybuf = NULL;
	char address[INET6_ADDRSTRLEN];
	char replystring[DNS_MAXNAME + 1];
	char fakereplystring[DNS_MAXNAME + 1];

	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} sockaddr_large;

	socklen_t fromlen = sizeof(sockaddr_large);

	struct sockaddr *from = (void *)&sockaddr_large;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	struct question *question = NULL, *fakequestion = NULL;
	struct rbtree *rbt0 = NULL, *rbt1 = NULL;
	struct rrset *csd;
	struct rr *rr_csd;
	
	struct sreply sreply;
	struct reply_logic *rl = NULL;
	struct timeval tv = { 10, 0};
	struct imsgbuf parse_ibuf;
	struct imsgbuf *pibuf;
	struct imsg imsg;
	struct parsequestion pq;

	ssize_t n, datalen;
	u_int32_t imsg_type;

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, &cfg->my_imsg[MY_IMSG_PARSER].imsg_fds[0]) < 0) {
		dolog(LOG_INFO, "socketpair() failed\n");
		slave_shutdown();
		exit(1);
	}

	pid = fork();
	switch (pid) {
	case -1:
		dolog(LOG_ERR, "fork(): %s\n", strerror(errno));
		exit(1);
	case 0:
		for (i = 0; i < cfg->sockcount; i++)  {
				close(cfg->tcp[i]);
				if (axfrport && axfrport != port)
					close(cfg->axfr[i]);
		}
		close(cfg->my_imsg[MY_IMSG_AXFR].imsg_fds[1]);
		close(cfg->my_imsg[MY_IMSG_TCP].imsg_fds[0]);
		close(cfg->my_imsg[MY_IMSG_PARSER].imsg_fds[1]);
		imsg_init(ibuf[MY_IMSG_PARSER], cfg->my_imsg[MY_IMSG_PARSER].imsg_fds[0]);
		setproctitle("tcp parse engine %d", cfg->pid);
		parseloop(cfg, ibuf);
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
		exit(1);
	}
#endif


	replybuf = calloc(1, 65536);
	if (replybuf == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		slave_shutdown();
		exit(1);
	}


	sp = cfg->recurse;

	/* 
	 * listen on descriptors
	 */

	for (i = 0; i < cfg->sockcount; i++) {
		listen(cfg->tcp[i], 5);
	}

	for (;;) {
		is_ipv6 = 0;
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
#ifndef __linux__
			TAILQ_FOREACH_SAFE(tcpnp, &tcphead, tcpentries, tcpn1) {
#else
			TAILQ_FOREACH(tcpnp, &tcphead, tcpentries) {
#endif
			
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
				fromlen = sizeof(sockaddr_large);

				so = accept(cfg->tcp[i], (struct sockaddr*)from, &fromlen);
		
				if (so < 0) {
					dolog(LOG_INFO, "tcp accept: %s\n", strerror(errno));
					continue;
				}

				if (from->sa_family == AF_INET6) {
					is_ipv6 = 1;

					fromlen = sizeof(struct sockaddr_in6);
					sin6 = (struct sockaddr_in6 *)from;
					inet_ntop(AF_INET6, (void *)&sin6->sin6_addr, (char *)&address, sizeof(address));
					aregion = find_region((struct sockaddr_storage *)sin6, AF_INET6);
					filter = find_filter((struct sockaddr_storage *)sin6, AF_INET6);
					if (whitelist) {
						blacklist = find_whitelist((struct sockaddr_storage *)sin6, AF_INET6);
					}
					axfr_acl = find_axfr((struct sockaddr_storage *)sin6, AF_INET6);

					require_tsig = 0;
					if (tsig) {
						require_tsig = find_tsig((struct sockaddr_storage *)sin6, AF_INET6);
					}
				} else if (from->sa_family == AF_INET) {
					is_ipv6 = 0;
					
					fromlen = sizeof(struct sockaddr_in);
					sin = (struct sockaddr_in *)from;
					inet_ntop(AF_INET, (void *)&sin->sin_addr, (char *)&address, sizeof(address));
					aregion = find_region((struct sockaddr_storage *)sin, AF_INET);
					filter = find_filter((struct sockaddr_storage *)sin, AF_INET);
					if (whitelist) {
						blacklist = find_whitelist((struct sockaddr_storage *)sin, AF_INET);
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
					dolog(LOG_INFO, "TCP connection refused on descriptor %u interface \"%s\" from %s, filter policy\n", so, cfg->ident[i], address);
					build_reply(&sreply, so, pbuf, len, NULL, from, fromlen, NULL, NULL, aregion, istcp, 0, NULL, replybuf);
					slen = reply_refused(&sreply, NULL);
					close(so);
					continue;
				}

				if (whitelist && blacklist == 0) {
					dolog(LOG_INFO, "TCP connection refused on descriptor %u interface \"%s\" from %s, whitelist policy\n", so, cfg->ident[i], address);
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
				tcpn1->intidx = i;
				tcpn1->address = strdup(address);
				
				TAILQ_INSERT_TAIL(&tcphead, tcpn1, tcpentries);
				conncnt++;

			} /* FD_ISSET */
		}

#ifndef __linux__
		TAILQ_FOREACH_SAFE(tcpnp, &tcphead, tcpentries, tcpn1) {
#else
		TAILQ_FOREACH(tcpnp, &tcphead, tcpentries) {
#endif
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
						tcpnp->bytes_expected = ntohs(*((u_int16_t *)&tcpnp->buf[0]));
						tcpnp->bytes_limit = tcpnp->bytes_expected;
						tcpnp->seen = 1;
				}

				if ((tcpnp->bytes_read - 2) != tcpnp->bytes_limit) 
					continue;

				len = tcpnp->bytes_read - 2;
				pbuf = &tcpnp->buf[2];
				so = tcpnp->so;

				if (len > DNS_MAXUDP || len < sizeof(struct dns_header)){
					dolog(LOG_INFO, "TCP packet on descriptor %u interface \"%s\" illegal dns packet length from %s, drop\n", so, cfg->ident[tcpnp->intidx], tcpnp->address);

					goto drop;
				}

				imsg_type = IMSG_PARSE_MESSAGE;
				if (imsg_compose(pibuf, imsg_type, 
					0, 0, -1, pbuf, len) < 0) {
					dolog(LOG_INFO, "imsg_compose %s\n", strerror(errno));
				}
				msgbuf_write(&pibuf->w);

				FD_ZERO(&rset);
				FD_SET(pibuf->fd, &rset);

				tv.tv_sec = 10;
				tv.tv_usec = 0;

				sel = select(pibuf->fd + 1, &rset, NULL, NULL, &tv);

				if (sel < 0) {
					dolog(LOG_ERR, "tcploop internal error around select, dropping packet\n");
					goto drop;
				}

				if (sel == 0) {
					dolog(LOG_ERR, "tcploop internal error, timeout on parse imsg, drop\n");
					goto drop;
				}
	
				if (((n = imsg_read(pibuf)) == -1 && errno != EAGAIN) || n == 0) {
					dolog(LOG_ERR, "tcploop internal error, timeout on parse imsg, drop\n");
					goto drop;
				}

				for (;;) {
				
					if ((n = imsg_get(pibuf, &imsg)) == -1) {
						break;
					}

					if (n == 0) {
						break;
					}

					datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

					switch (imsg.hdr.type) {
					case IMSG_PARSEREPLY_MESSAGE:
						if (datalen != sizeof(struct parsequestion)) {
							dolog(LOG_ERR, "tcploop datalen != sizeof(struct parsequestion), can't work with this, drop\n");
							imsg_free(&imsg);
							goto drop;
						}
			
						memcpy((char *)&pq, imsg.data, datalen);

						if (pq.rc != PARSE_RETURN_ACK) {
							switch (pq.rc) {
							case PARSE_RETURN_MALFORMED:
								dolog(LOG_INFO, "TCP packet on descriptor %u interface \"%s\" malformed question from %s, drop\n", so, cfg->ident[tcpnp->intidx], tcpnp->address);
								imsg_free(&imsg);
								goto drop;
							case PARSE_RETURN_NOQUESTION:
								dolog(LOG_INFO, "TCP packet on descriptor %u interface \"%s\" header from %s has no question, drop\n", so, cfg->ident[tcpnp->intidx], tcpnp->address);
								/* format error */
								build_reply(&sreply, so, pbuf, len, NULL, from, fromlen, NULL, NULL, aregion, istcp, 0, NULL, replybuf);
								slen = reply_fmterror(&sreply, NULL);
								dolog(LOG_INFO, "TCP question on descriptor %d interface \"%s\" from %s, did not have question of 1 replying format error\n", so, cfg->ident[tcpnp->intidx], tcpnp->address);
								imsg_free(&imsg);
								goto drop;
							case PARSE_RETURN_NOTAQUESTION:
								dolog(LOG_INFO, "TCP packet on descriptor %u interface \"%s\" dns header from %s is not a question, drop\n", so, cfg->ident[tcpnp->intidx], tcpnp->address);
								imsg_free(&imsg);
								goto drop;
							case PARSE_RETURN_NAK:
								dolog(LOG_INFO, "TCP packet on descriptor %u interface \"%s\" illegal dns packet length from %s, drop\n", so, cfg->ident[tcpnp->intidx], tcpnp->address);
								imsg_free(&imsg);
								goto drop;
							case PARSE_RETURN_NOTAUTH:
								if (filter && pq.tsig.have_tsig == 0) {
									build_reply(&sreply, so, pbuf, len, NULL, from, fromlen, NULL, NULL, aregion, istcp, 0, NULL, replybuf);
									slen = reply_refused(&sreply, NULL);
									dolog(LOG_INFO, "TCP connection refused on descriptor %u interface \"%s\" from %s (ttl=TCP, region=%d) replying REFUSED, not a tsig\n", so, cfg->ident[tcpnp->intidx], tcpnp->address, aregion);
									imsg_free(&imsg);
									goto drop;
								}
							}
						}	

						question = convert_question(&pq);
						if (question == NULL) {
							dolog(LOG_INFO, "TCP packet on descriptor %u interface \"%s\" internal error from %s, drop\n", so, cfg->ident[tcpnp->intidx], tcpnp->address);
							imsg_free(&imsg);
							goto drop;
						}
							
					
						break;
					} /* switch */

					imsg_free(&imsg);
				} /* for (;;) */

				/* pjp end of parseloop branch */
				/* goto drop beyond this point should goto out instead */
				fakequestion = NULL;
				/* handle tcp notifications , XXX not tested */
				if (question->notify) {
					if (question->tsig.have_tsig && notifysource(question, (struct sockaddr_storage *)from) &&
							question->tsig.tsigverified == 1) {
							dolog(LOG_INFO, "on TCP descriptor %u interface \"%s\" authenticated dns NOTIFY packet from %s, replying NOTIFY\n", so, cfg->ident[tcpnp->intidx], tcpnp->address);
							snprintf(replystring, DNS_MAXNAME, "NOTIFY");
							build_reply(&sreply, so, pbuf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, NULL, replybuf);
							slen = reply_notify(&sreply, NULL);
							/* send notify to replicant process */
							idata = question->hdr->namelen;
							imsg_compose(ibuf[MY_IMSG_RAXFR], IMSG_NOTIFY_MESSAGE, 
									0, 0, -1, question->hdr->name, idata);
							msgbuf_write(&ibuf[MY_IMSG_RAXFR]->w);
							goto tcpout;
					
					} else if (question->tsig.have_tsig && question->tsig.tsigerrorcode != 0) {
							dolog(LOG_INFO, "on TCP descriptor %u interface \"%s\" not authenticated dns NOTIFY packet (code = %d) from %s, replying notauth\n", so, cfg->ident[tcpnp->intidx], question->tsig.tsigerrorcode, tcpnp->address);
							snprintf(replystring, DNS_MAXNAME, "NOTAUTH");
							build_reply(&sreply, so, pbuf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, NULL, replybuf);
							slen = reply_notauth(&sreply, NULL);
							goto tcpout;
					}

					if (notifysource(question, (struct sockaddr_storage *)from)) {
						dolog(LOG_INFO, "on TCP descriptor %u interface \"%s\" dns NOTIFY packet from %s, replying NOTIFY\n", so, cfg->ident[tcpnp->intidx], tcpnp->address);
						snprintf(replystring, DNS_MAXNAME, "NOTIFY");
						build_reply(&sreply, so, pbuf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, NULL, replybuf);
						slen = reply_notify(&sreply, NULL);
						/* send notify to replicant process */
						idata = question->hdr->namelen;
						imsg_compose(ibuf[MY_IMSG_RAXFR], IMSG_NOTIFY_MESSAGE, 
								0, 0, -1, question->hdr->name, idata);
						msgbuf_write(&ibuf[MY_IMSG_RAXFR]->w);
						goto tcpout;
					} else {
						/* RFC 1996 - 3.10 is probably broken, replying REFUSED */
						dolog(LOG_INFO, "on TCP descriptor %u interface \"%s\" dns NOTIFY packet from %s, NOT in our list of MASTER servers replying REFUSED\n", so, cfg->ident[tcpnp->intidx], tcpnp->address);
						snprintf(replystring, DNS_MAXNAME, "REFUSED");
						build_reply(&sreply, so, pbuf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, NULL, replybuf);
						slen = reply_refused(&sreply, NULL);

						goto tcpout;
					}
				} /* if question->notify */

				if (question->tsig.have_tsig && question->tsig.tsigerrorcode != 0)  {
					dolog(LOG_INFO, "on TCP descriptor %u interface \"%s\" not authenticated dns packet (code = %d) from %s, replying notauth\n", so, cfg->ident[tcpnp->intidx], question->tsig.tsigerrorcode, tcpnp->address);
					snprintf(replystring, DNS_MAXNAME, "NOTAUTH");
					build_reply(&sreply, so, pbuf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, NULL, replybuf);
					slen = reply_notauth(&sreply, NULL);
					goto tcpout;
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
						build_reply(&sreply, so, pbuf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, NULL, replybuf);
						slen = reply_version(&sreply, NULL);
						goto tcpout;
				}

				rbt0 = lookup_zone(cfg->db, question, &type0, &lzerrno, (char *)&replystring);
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
						build_reply(&sreply, so, pbuf, len, question, from, fromlen, rbt0, NULL, aregion, istcp, 0, NULL, replybuf);
						slen = reply_refused(&sreply, NULL);
						goto tcpout;
						break;
					case ERR_NODATA:
								if (rbt0) {
									free(rbt0);
									rbt0 = NULL;
								}

								rbt0 = get_soa(cfg->db, question);
								if (rbt0 != NULL) {
									snprintf(replystring, DNS_MAXNAME, "NODATA");
									build_reply(&sreply, so, pbuf, len, question, from, fromlen, rbt0, NULL, aregion, istcp, 0, NULL, replybuf);
									slen = reply_nodata(&sreply, cfg->db);
								} else {
									snprintf(replystring, DNS_MAXNAME, "REFUSED");
									build_reply(&sreply, so, pbuf, len, question, from, fromlen, rbt0, NULL, aregion, istcp, 0, NULL, replybuf);
									slen = reply_refused(&sreply, cfg->db);
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
											aregion, istcp, 0, NULL,
											replybuf);

							slen = reply_nxdomain(&sreply, cfg->db);
					 	}
						goto tcpout;
					case ERR_NOERROR:
						/*
 						 * this is hackish not sure if this should be here
						 */

						snprintf(replystring, DNS_MAXNAME, "NOERROR");

						/*
						 * lookup an authoritative soa
						 */

						if (rbt0) {
							free(rbt0);
							rbt0 = NULL;
						}

						rbt0 = get_soa(cfg->db, question);
						if (rbt0 != NULL) {

								build_reply(	&sreply, so, pbuf, len, 
												question, from, fromlen, 
												rbt0, NULL, aregion, istcp, 
												0, NULL, replybuf);

								slen = reply_noerror(&sreply, cfg->db);
			
								goto tcpout;
						}

						snprintf(replystring, DNS_MAXNAME, "DROP");
						slen = 0;
						goto tcpout;

					case ERR_DELEGATE:
						if (rbt0 != NULL) {
			
							build_reply(	&sreply, so, pbuf, len, question, 
											from, fromlen, rbt0, NULL, 
											aregion, istcp, 0, NULL,
											replybuf);

							slen = reply_ns(&sreply, cfg->db);
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

					rbt1 = lookup_zone(cfg->db, fakequestion, &type1, &lzerrno, (char *)&fakereplystring);
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
									istcp, 0, NULL, replybuf);

					slen = reply_notimpl(&sreply, NULL);
					snprintf(replystring, DNS_MAXNAME, "NOTIMPL");
					goto tcpout;
				}

				/* IXFR and AXFR are special types for TCP handle seperately */
				switch (ntohs(question->hdr->qtype)) {
				case DNS_TYPE_IXFR:
					/* FALLTHROUGH */
				case DNS_TYPE_AXFR:
					dolog(LOG_INFO, "composed AXFR message to axfr process\n");
					imsg_compose(ibuf[MY_IMSG_AXFR], IMSG_XFR_MESSAGE, 0, 0, tcpnp->so, tcpnp->buf, tcpnp->bytes_read);
					msgbuf_write(&ibuf[MY_IMSG_AXFR]->w);
					TAILQ_REMOVE(&tcphead, tcpnp, tcpentries);
					close(tcpnp->so);
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
									NULL), aregion, istcp, 0, NULL, replybuf);
								break;
							case BUILD_OTHER:
								build_reply(&sreply, so, pbuf, len, question, 
									from, fromlen, rbt0, NULL, aregion, istcp, 
									0, NULL, replybuf);
								break;
							}
						} else {
							continue;
						}
							
						slen = (*rl->reply)(&sreply, cfg->db);
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
							0, NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);

					} else {

						build_reply(&sreply, so, pbuf, len, question, from, \
						fromlen, NULL, NULL, aregion, istcp, 
						0, NULL, replybuf);
		
						slen = reply_notimpl(&sreply, NULL);
						snprintf(replystring, DNS_MAXNAME, "NOTIMPL");
					}
				}
			
		tcpout:
				if (lflag)
					dolog(LOG_INFO, "request on descriptor %u interface \"%s\" from %s (ttl=TCP, region=%d) for \"%s\" type=%s class=%u, %s%s%s answering \"%s\" (%d/%d)\n", so, cfg->ident[tcpnp->intidx], tcpnp->address, aregion, question->converted_name, get_dns_type(ntohs(question->hdr->qtype), 1), ntohs(question->hdr->qclass), (question->edns0len) ? "edns0, " : "", (question->dnssecok) ? "dnssecok, " : "", (question->tsig.tsigverified ? "tsig, " : ""), replystring, len, slen);


				if (fakequestion != NULL) {
					free_question(fakequestion);
				}
	
				free_question(question);
				
				if (rbt0) {
					free(rbt0);
					rbt0 = NULL;
				}
				if (rbt1) {
					free (rbt1);
					rbt1 = NULL;
				}

				/*
				 * we are restarting this connection, so that the remote
				 * end can ask again, with tcp if they want, so reset
				 * everything
				 */

				memset(pbuf, 0, length);
				tcpnp->bytes_read = 0;
				tcpnp->bytes_expected = 0;
				tcpnp->bytes_limit = 0;
				tcpnp->seen = 0;
				tcpnp->last_used = time(NULL);
			}	/* END ISSET */
			continue;
	drop:
		
			if (rbt0) {	
				free(rbt0);
				rbt0 = NULL;
			}

			if (rbt1) {
				free(rbt1);
				rbt1 = NULL;
			}

			TAILQ_REMOVE(&tcphead, tcpnp, tcpentries);
			close(tcpnp->so);
			free(tcpnp->address);
			free(tcpnp);
			if (conncnt > 0)
				conncnt--;

			continue;
		} /* TAILQ_FOREACH */

		/*
		 * kick off the idlers 
		 */

#ifndef __linux__
		TAILQ_FOREACH_SAFE(tcpnp, &tcphead, tcpentries, tcpn1) {
#else
		TAILQ_FOREACH(tcpnp, &tcphead, tcpentries) {
#endif
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
	}  /* for (;;) */

	/* NOTREACHED */
}

void
parseloop(struct cfg *cfg, struct imsgbuf **ibuf)
{
	struct imsg imsg;
	struct imsgbuf *mybuf = ibuf[MY_IMSG_PARSER];
	struct dns_header *dh = NULL;
	struct question *question = NULL;
	struct parsequestion pq;
	char *packet;
	fd_set rset;
	int sel;
	int require_tsig = 0;
	int fd = mybuf->fd;
	ssize_t n, datalen;

#if __OpenBSD__
	if (pledge("stdio", NULL) < 0) {
		perror("pledge");
		slave_shutdown();
		exit(1);
	}
#endif

	packet = calloc(1, 16384);
	if (packet == NULL) {
		dolog(LOG_ERR, "calloc: %m");
		slave_shutdown();
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

			if (((n = imsg_read(mybuf)) == -1 && errno != EAGAIN) || n == 0) {
				continue;
			}

			for (;;) {
			
				if ((n = imsg_get(mybuf, &imsg)) == -1) {
					break;
				}

				if (n == 0) {
					break;
				}

				datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
				require_tsig = 0;

				switch (imsg.hdr.type) {
				case IMSG_PARSE_MESSAGE:
					memset(&pq, 0, sizeof(struct parsequestion));

					/* XXX magic numbers */
					if (datalen > 16384) {
						pq.rc = PARSE_RETURN_NAK;
						imsg_compose(mybuf, IMSG_PARSEREPLY_MESSAGE, 0, 0, -1, &pq, sizeof(struct parsequestion));
						msgbuf_write(&mybuf->w);
						break;
					}
					memcpy(packet, imsg.data, datalen);

					if (datalen < sizeof(struct dns_header)) {
						/* SEND NAK */
						pq.rc = PARSE_RETURN_NAK;
						imsg_compose(ibuf[MY_IMSG_PARSER], IMSG_PARSEREPLY_MESSAGE, 0, 0, -1, &pq, sizeof(struct parsequestion));
						msgbuf_write(&ibuf[MY_IMSG_PARSER]->w);
						msgbuf_write(&mybuf->w);
						break;
					}
					/* pjp */
					dh = (struct dns_header *)packet;

					if ((ntohs(dh->query) & DNS_REPLY)) {
						/* we want to reply with a NAK here */
						pq.rc = PARSE_RETURN_NOTAQUESTION;
						imsg_compose(mybuf, IMSG_PARSEREPLY_MESSAGE, 0, 0, -1, &pq, sizeof(struct parsequestion));
						msgbuf_write(&mybuf->w);
						break;
					}

					/* 
					 * if questions aren't exactly 1 then reply NAK
					 */

					if (ntohs(dh->question) != 1) {
						/* XXX reply nak here */
						pq.rc = PARSE_RETURN_NOQUESTION;
						imsg_compose(mybuf, IMSG_PARSEREPLY_MESSAGE, 0, 0, -1, &pq, sizeof(struct parsequestion));
						msgbuf_write(&mybuf->w);
						break;
					}

					if ((question = build_question(packet, datalen, ntohs(dh->additional), NULL)) == NULL) {
						/* XXX reply nak here */
						pq.rc = PARSE_RETURN_MALFORMED;
						imsg_compose(mybuf, IMSG_PARSEREPLY_MESSAGE, 0, 0, -1, &pq, sizeof(struct parsequestion));
						msgbuf_write(&mybuf->w);
						break;
					}
					
					memcpy(pq.name, question->hdr->name, question->hdr->namelen);
					pq.namelen = question->hdr->namelen;
					pq.qtype = question->hdr->qtype;
					pq.qclass = question->hdr->qclass;
					strlcpy(pq.converted_name, question->converted_name, sizeof(pq.converted_name));
					pq.edns0len = question->edns0len;
					pq.ednsversion = question->ednsversion;
					pq.rd = question->rd;
					pq.dnssecok = question->dnssecok;
					pq.badvers = question->badvers;
					pq.rc = PARSE_RETURN_ACK;
					pq.tsig.have_tsig = question->tsig.have_tsig;
					pq.tsig.tsigverified = question->tsig.tsigverified;
					pq.tsig.tsigerrorcode = question->tsig.tsigerrorcode;
					if (pq.tsig.have_tsig == 0 || pq.tsig.tsigerrorcode)
						pq.rc = PARSE_RETURN_NOTAUTH;
					memcpy(&pq.tsig.tsigmac, question->tsig.tsigmac, sizeof(pq.tsig.tsigmac));
					pq.tsig.tsigmaclen = question->tsig.tsigmaclen;
					memcpy(&pq.tsig.tsigkey, question->tsig.tsigkey, sizeof(pq.tsig.tsigkey));
					pq.tsig.tsigkeylen = question->tsig.tsigkeylen;	
					memcpy(&pq.tsig.tsigalg, question->tsig.tsigalg, sizeof(pq.tsig.tsigalg));
					pq.tsig.tsigalglen = question->tsig.tsigalglen;
					pq.tsig.tsig_timefudge = question->tsig.tsig_timefudge;
					pq.tsig.tsigorigid = question->tsig.tsigorigid;
					pq.notify = question->notify;

					imsg_compose(mybuf, IMSG_PARSEREPLY_MESSAGE, 0, 0, -1, (char *)&pq, sizeof(struct parsequestion));
					msgbuf_write(&mybuf->w);
					/* send it */
					free_question(question);
					break;
				}

				imsg_free(&imsg);


			} /* inner for(;;) */

		} /* FD_ISSET */

	} /* outter for(;;) */

	/* NOTREACHED */
}

/*
 * CONVERT_QUESTION - convert a struct parsequestion from parse process to 
 *			struct question
 */
 
struct question	*
convert_question(struct parsequestion *pq)
{
	struct question *q;

	q = (void *)calloc(1, sizeof(struct question));
	if (q == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		return NULL;
	}
	q->hdr = (void *)calloc(1, sizeof(struct dns_question_hdr));
	if (q->hdr == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		free(q);
		return NULL;
	}
	
	q->hdr->name = strdup(pq->name);
	if (q->hdr->name == NULL) {
		dolog(LOG_INFO, "strdup: %s\n", strerror(errno));
		free(q->hdr);
		free(q);
		return NULL;
	}
		
	q->hdr->namelen = pq->namelen;
	q->hdr->qtype = pq->qtype;
	q->hdr->qclass = pq->qclass;
	
	q->converted_name = strdup(pq->converted_name);
	if (q->converted_name == NULL) {
		dolog(LOG_INFO, "strdup: %s\n", strerror(errno));
		free(q->hdr);
		free(q);
		return NULL;
	}

	q->edns0len = pq->edns0len;
	q->ednsversion = pq->ednsversion;
	q->rd = pq->rd;
	q->dnssecok = pq->dnssecok;
	q->badvers = pq->badvers;
	q->tsig.have_tsig = pq->tsig.have_tsig;
	q->tsig.tsigverified = pq->tsig.tsigverified;
	q->tsig.tsigerrorcode = pq->tsig.tsigerrorcode;

	memcpy(&q->tsig.tsigmac, pq->tsig.tsigmac, sizeof(q->tsig.tsigmac));
	memcpy(&q->tsig.tsigalg, pq->tsig.tsigalg, sizeof(q->tsig.tsigalg));
	memcpy(&q->tsig.tsigkey, pq->tsig.tsigkey, sizeof(q->tsig.tsigkey));

	q->tsig.tsigmaclen = pq->tsig.tsigmaclen;
	q->tsig.tsigalglen = pq->tsig.tsigalglen;
	q->tsig.tsigkeylen = pq->tsig.tsigkeylen;

	q->tsig.tsig_timefudge = pq->tsig.tsig_timefudge;
	q->tsig.tsigorigid = pq->tsig.tsigorigid;

	q->notify = pq->notify;

	return (q);
}

void
setup_unixsocket(char *socketpath, struct imsgbuf *ibuf)
{
	int so, nso;
	int sel, slen;
	int len;
	char buf[512];
	struct sockaddr_un sun, *psun;
	struct timeval tv;
	struct dddcomm *dc;
	struct passwd *pw;
	fd_set rset;
	uid_t uid;
	gid_t gid;

	setproctitle("unix controlling socket");

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlcpy(sun.sun_path, socketpath, sizeof(sun.sun_path)) >= sizeof(sun.sun_path)) {
		slave_shutdown();
		exit(1);
	}
#ifndef __linux__
	sun.sun_len = SUN_LEN(&sun);
#endif

	/* only root, 0100 == nonexecute */
	if (umask(0177) < 0) {
		slave_shutdown();
		exit(1);
	}

	so = socket(AF_UNIX, SOCK_STREAM, 0);
	if (so < 0) {
		slave_shutdown();
		exit(1);
	}

	if (bind(so, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		slave_shutdown();
		exit(1);
	}

	pw = getpwnam(DEFAULT_PRIVILEGE);
	if (pw == NULL) {
		perror("getpwnam");
		slave_shutdown();
		exit(1);
	}

#ifdef DEFAULT_LOCATION
	if (drop_privs(DEFAULT_LOCATION, pw) < 0) {
#else
	if (drop_privs(pw->pw_dir, pw) < 0) {
#endif
		dolog(LOG_INFO, "dropping privileges failed in unix socket\n");
		slave_shutdown();
		exit(1);
	}

	listen(so, 5);

#if __OpenBSD__
	if (pledge("stdio rpath wpath cpath unix proc", NULL) < 0) {
		perror("pledge");
		slave_shutdown();
		exit(1);
	}
#endif


	for (;;) {
		FD_ZERO(&rset);
		FD_SET(so, &rset);

		sel = select(so + 1, &rset, NULL, NULL, NULL);
		if (sel < 0) {
			continue;
		}	
					
		
		if (FD_ISSET(so, &rset)) {
			if ((nso = accept(so, (struct sockaddr*)&psun, &slen)) < 0)
				continue;

#if __OpenBSD__
			if (getpeereid(nso, &uid, &gid) < 0) {
				close(nso);
				continue;
			}
#endif
			tv.tv_sec = 2;
			tv.tv_usec = 0;
			if (setsockopt(so, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
				close(nso);
				continue;
			}

			len = recv(nso, buf, sizeof(buf), 0);
			if (len < 0 || len < sizeof(struct dddcomm)) {
				close(nso);
				continue;
			}

			dc = (struct dddcomm *)&buf[0];		
			if (dc->command == IMSG_RELOAD_MESSAGE || 
				dc->command == IMSG_SHUTDOWN_MESSAGE) {
				int idata;
				
				idata = 1;
				imsg_compose(ibuf, dc->command, 
					0, 0, -1, &idata, sizeof(idata));
				msgbuf_write(&ibuf->w);
				send(nso, buf, len, 0);
				close(nso);
				exit(0);
			}
			send(nso, buf, len, 0);
			close(nso);
		} /* FD_ISSET */
	} /* for (;;) */
	
	/* NOTREACHED */
}

int
determine_glue(ddDB *db)
{
	struct rbtree *rbt, *rbt0;
	struct rrset *rrset;
	ddDBT key, data;
	int rs;
	struct node *n, *nx;
	int len;
	int have_soa = 0, have_ns = 0;
	char *p;

        RB_FOREACH_SAFE(n, domaintree, &db->head, nx) {
                rs = n->datalen;
                if ((rbt = calloc(1, rs)) == NULL) {
                        dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
                        exit(1);
                }

                memcpy((char *)rbt, (char *)n->data, n->datalen);

		rrset = find_rr(rbt, DNS_TYPE_SOA);
		if (rrset != NULL) {
			have_soa = 1;
		}
		rrset = find_rr(rbt, DNS_TYPE_NS);
		if (rrset != NULL) {
			have_ns = 1;
		}
		
		free(rbt);
	}

	if (! have_soa || ! have_ns) {
		dolog(LOG_INFO, "did not detect NS and SOA entries, they must be present!\n");
		return -1;
	}

	/* mark SOA's */
        RB_FOREACH_SAFE(n, domaintree, &db->head, nx) {
                rs = n->datalen;
                if ((rbt = calloc(1, rs)) == NULL) {
                        dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
                        exit(1);
                }

                memcpy((char *)rbt, (char *)n->data, n->datalen);

		rrset = find_rr(rbt, DNS_TYPE_SOA);
		if (rrset == NULL) {
			free(rbt);
			continue;
		}

		rbt->flags |= RBT_APEX;

		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));

		key.data = (char *)rbt->zone;
		key.size = rbt->zonelen;	

		data.data = (void *)rbt;
		data.size = sizeof(struct rbtree);

		if (db->put(db, &key, &data) != 0) {
			dolog(LOG_INFO, "db->put failed\n");
			free(rbt);
			return -1;
		}

		free(rbt);
	}

	/* mark glue */
        RB_FOREACH_SAFE(n, domaintree, &db->head, nx) {
                rs = n->datalen;
                if ((rbt = calloc(1, rs)) == NULL) {
                        dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
                        exit(1);
                }

                memcpy((char *)rbt, (char *)n->data, n->datalen);

		if (rbt->flags & RBT_APEX) {
			free(rbt);
			continue;
		}

		rrset = find_rr(rbt, DNS_TYPE_NS);
		if (rrset == NULL) {
			free(rbt);
			continue;
		}

		rbt->flags |= RBT_GLUE;

		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));

		key.data = (char *)rbt->zone;
		key.size = rbt->zonelen;	

		data.data = (void *)rbt;
		data.size = sizeof(struct rbtree);

		if (db->put(db, &key, &data) != 0) {
			dolog(LOG_INFO, "db->put failed\n");
			free(rbt);
			return -1;
		}

		free(rbt);
	}
        RB_FOREACH_SAFE(n, domaintree, &db->head, nx) {
                rs = n->datalen;
                if ((rbt = calloc(1, rs)) == NULL) {
                        dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
                        exit(1);
                }

                memcpy((char *)rbt, (char *)n->data, n->datalen);


		p = rbt->zone;
		len = rbt->zonelen;

		rbt0 = find_rrset(db, rbt->zone, rbt->zonelen);
		while (! (rbt0->flags & RBT_APEX)) {
			if (rbt0->flags & RBT_GLUE) {
				/* repeat */
				free(rbt0);
				p = rbt->zone;
				len = rbt->zonelen;
				rbt0 = find_rrset(db, p, len);

				while (!(rbt0->flags & RBT_GLUE)) {
					rbt0->flags |= RBT_GLUE;

					memset(&key, 0, sizeof(key));
					memset(&data, 0, sizeof(data));

					key.data = (char *)p;
					key.size = len;

					data.data = (void *)rbt0;
					data.size = sizeof(struct rbtree);

					if (db->put(db, &key, &data) != 0) {
						dolog(LOG_INFO, "db->put failed\n");
						free(rbt);
						return -1;
					}

					free(rbt0);

					len -= (*p + 1);
					p += (*p + 1);

					/* there could be ENT's so do loop */
					while ((rbt0 = find_rrset(db, p, len)) == NULL) {
						len -= (*p + 1);
						p += (*p + 1);
		
					}
				} 

				break;
			}
			free(rbt0);
	
			len -= (1 + *p);
			p += (1 + *p);

			/* there could be ENT's so do loop */
			while ((rbt0 = find_rrset(db, p, len)) == NULL) {
				len -= (*p + 1);
				p += (*p + 1);

			}
		}

		free(rbt);
	}

	return 0;
}
