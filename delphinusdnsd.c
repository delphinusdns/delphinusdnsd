/* 
 * Copyright (c) 2002-2017 Peter J. Philipp
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
 * $Id: delphinusdnsd.c,v 1.26 2017/11/27 05:06:46 pjp Exp $
 */

#include "ddd-include.h"
#include "ddd-dns.h"
#include "ddd-db.h" 
#include "ddd-config.h"

/* prototypes */

extern void 	add_rrlimit(int, u_int16_t *, int, char *);
extern void 	axfrloop(int *, int, char **, ddDB *, struct imsgbuf *);
extern struct question	*build_fake_question(char *, int, u_int16_t);
extern int 	check_ent(char *, int);
extern int 	check_rrlimit(int, u_int16_t *, int, char *);
extern u_int16_t check_qtype(struct domain *, u_int16_t, int, int *);
extern void 	collects_init(void);
extern void 	dolog(int, char *, ...);
extern int     	find_axfr(struct sockaddr_storage *, int);
extern int 	find_filter(struct sockaddr_storage *, int);
extern int 	find_recurse(struct sockaddr_storage *, int);
extern u_int8_t find_region(struct sockaddr_storage *, int);
extern int 	find_whitelist(struct sockaddr_storage *, int);
extern char *	get_dns_type(int, int);
extern void 	init_dnssec(void);
extern void 	init_recurse(void);
extern void 	init_region(void);
extern int	init_entlist(ddDB *);
extern void 	init_filter(void);
extern void 	init_notifyslave(void);
extern void 	init_whitelist(void);
extern struct domain * 	lookup_zone(ddDB *, struct question *, int *, int *, char *);
extern int 	memcasecmp(u_char *, u_char *, int);
extern void 	recurseloop(int sp, int *, ddDB *);
extern void 	receivelog(char *, int);
extern int 	reply_a(struct sreply *, ddDB *);
extern int 	reply_aaaa(struct sreply *, ddDB *);
extern int 	reply_any(struct sreply *);
extern int 	reply_badvers(struct sreply *);
extern int	reply_nodata(struct sreply *);
extern int 	reply_cname(struct sreply *);
extern int 	reply_fmterror(struct sreply *);
extern int 	reply_notimpl(struct sreply *);
extern int 	reply_nxdomain(struct sreply *, ddDB *);
extern int 	reply_noerror(struct sreply *, ddDB *);
extern int 	reply_soa(struct sreply *);
extern int 	reply_mx(struct sreply *, ddDB *);
extern int 	reply_naptr(struct sreply *, ddDB *);
extern int 	reply_ns(struct sreply *, ddDB *);
extern int 	reply_ptr(struct sreply *);
extern int 	reply_refused(struct sreply *);
extern int 	reply_srv(struct sreply *, ddDB *);
extern int 	reply_sshfp(struct sreply *);
extern int 	reply_tlsa(struct sreply *);
extern int 	reply_txt(struct sreply *);
extern int 	reply_version(struct sreply *);
extern int      reply_rrsig(struct sreply *, ddDB *);
extern int	reply_dnskey(struct sreply *);
extern int	reply_ds(struct sreply *);
extern int	reply_nsec(struct sreply *);
extern int	reply_nsec3(struct sreply *, ddDB *);
extern int	reply_nsec3param(struct sreply *);
extern int 	remotelog(int, char *, ...);
extern char 	*rrlimit_setup(int);
extern char 	*dns_label(char *, int *);
extern void 	slave_shutdown(void);
extern int 	get_record_size(ddDB *, char *, int);
extern void *	find_substruct(struct domain *, u_int16_t);

struct question		*build_question(char *, int, int);
void 			build_reply(struct sreply *, int, char *, int, struct question *, struct sockaddr *, socklen_t, struct domain *, struct domain *, u_int8_t, int, int, struct recurses *, char *);
int 			compress_label(u_char *, u_int16_t, int);
int			free_question(struct question *);
struct domain * 	get_soa(ddDB *, struct question *);
int			lookup_type(int);
void			mainloop(struct cfg *, struct imsgbuf **);
void 			master_reload(int);
void 			master_shutdown(int);
void 			recurseheader(struct srecurseheader *, int, struct sockaddr_storage *, struct sockaddr_storage *, int);
void 			setup_master(ddDB *, char **, struct imsgbuf *ibuf);
void 			slave_signal(int);
void 			tcploop(struct cfg *, struct imsgbuf **);

/* aliases */

#ifndef DEFAULT_PRIVILEGE
#define DEFAULT_PRIVILEGE "_ddd"
#endif

#define PIDFILE "/var/run/delphinusdnsd.pid"
#define MYDB_PATH "/var/db/delphinusdns"

/* global variables */

extern char *__progname;
extern struct logging logging;
extern int axfrport;
extern int ratelimit;
extern int ratelimit_packets_per_second;
extern int whitelist;
extern int dnssec;

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
char *versionstring = "delphinusdnsd-current";
uint8_t vslen = 21;
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
	int lfd = -1;
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
	
	struct passwd *pw;
	struct addrinfo hints, *res0, *res;
	struct ifaddrs *ifap, *pifap;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct cfg *cfg;
	struct imsgbuf  **parent_ibuf, **child_ibuf;

	static ddDB *db;

	
	if (geteuid() != 0) {
		fprintf(stderr, "must be started as root\n"); /* .. dolt */
		exit(1);
	}

	av = argv;
#if __linux__
	setproctitle_init(argc, av, environ);
#endif


	while ((ch = getopt(argc, argv, "b:df:i:ln:p:v")) != -1) {
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


	openlog(__progname, LOG_PID | LOG_NDELAY, LOG_DAEMON);
	dolog(LOG_INFO, "starting up\n");

	/* cfg struct */
	cfg = calloc(1, sizeof(struct cfg));
	if (cfg == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		exit(1);
	}
	/* imsg structs */
	
	parent_ibuf = calloc(3 + nflag, sizeof(struct imsgbuf *));
	if (parent_ibuf == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		exit(1);
	}

	child_ibuf = calloc(3 + nflag, sizeof(struct imsgbuf *));
	if (child_ibuf == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		exit(1);
	}

	for (i = 0; i < 3 + nflag; i++) {
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

	/* make a master program that holds the pidfile, boss of ... eek */

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, &cfg->my_imsg[MY_IMSG_MASTER].imsg_fds[0]) < 0) {
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
		setup_master(db, av, parent_ibuf[MY_IMSG_MASTER]);
		/* NOTREACHED */
		exit(1);
	}

	/* end of setup_master code */
		
	init_region();
	init_filter();
	init_whitelist();
	init_notifyslave();
	init_dnssec();

	if (parse_file(db, conffile) < 0) {
		dolog(LOG_INFO, "parsing config file failed\n");
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
#ifdef __NetBSD__
				if (setsockopt(udp[i], IPPROTO_IP, IP_TTL,
					&on, sizeof(on)) < 0) {
#else
				if (setsockopt(udp[i], IPPROTO_IP, IP_RECVTTL,
					&on, sizeof(on)) < 0) {
#endif
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
			} /* axfrport */

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
#ifdef __NetBSD__
				if (setsockopt(udp[i], IPPROTO_IP, IP_TTL,
					&on, sizeof(on)) < 0) {
#else
				if (setsockopt(udp[i], IPPROTO_IP, IP_RECVTTL,
					&on, sizeof(on)) < 0) {
#endif
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
			} /* axfrport */

		} /* AF_INET */

		if (i >= DEFAULT_SOCKET) {
			dolog(LOG_INFO, "not enough sockets available\n");
			slave_shutdown();
			exit(1);
		}
	} /* if bflag? */

	/* if we are binding a log socket do it now */
	if (logging.bind == 1 || logging.active == 1)  {
		switch (logging.loghost2.ss_family) {
	 	case AF_INET:
			lfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (lfd < 0) {
				dolog(LOG_INFO, "logging socket: %s\n", strerror(errno));
				slave_shutdown();
				exit(1);
			}
			sin = (struct sockaddr_in *)&logging.loghost2;
			sin->sin_port = htons(logging.logport2);
			break;
		case AF_INET6:
			lfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
			if (lfd < 0) {	
				dolog(LOG_INFO, "logging socket: %s\n", strerror(errno));
				slave_shutdown();
				exit(1);
			}
			sin6 = (struct sockaddr_in6 *)&logging.loghost2;
			sin6->sin6_port = htons(logging.logport2);
			break;
		}

		if (logging.bind == 1) {
			if (bind(lfd, (struct sockaddr *)&logging.loghost2, 
				((logging.loghost2.ss_family == AF_INET6) ?	
				 	sizeof(struct sockaddr_in6) :
					sizeof(struct sockaddr_in))	
				) < 0) {
				dolog(LOG_INFO, "binding log socket: %s\n", strerror(errno));
				slave_shutdown();
				exit(1);
			}
	
#ifndef __linux__
			if (shutdown(lfd, SHUT_WR) < 0) {
				dolog(LOG_INFO, "shutdown log socket: %s\n", strerror(errno));
				slave_shutdown();
				exit(1);
			}
#endif
				
		} else {
			if (connect(lfd, (struct sockaddr *)&logging.loghost2,
				((logging.loghost2.ss_family == AF_INET6) ?	
				 	sizeof(struct sockaddr_in6) :
					sizeof(struct sockaddr_in))) < 0) {
					dolog(LOG_INFO, "connecting log socket: %s\n", strerror(errno));
					slave_shutdown();
					exit(1);
			}

			if (shutdown(lfd, SHUT_RD) < 0) {
				dolog(LOG_INFO, "shutdown log socket: %s\n", strerror(errno));
				slave_shutdown();
				exit(1);
			}
	
		} /* if logging.bind */
				
	} /* if logging.bind */

	/* chroot to the drop priv user home directory */
	if (chroot(pw->pw_dir) < 0) {
		dolog(LOG_INFO, "chroot: %s\n", strerror(errno));
		slave_shutdown();
		exit(1);
	}

	if (chdir("/") < 0) {
		dolog(LOG_INFO, "chdir: %s\n", strerror(errno));
		slave_shutdown();
		exit(1);
	}

#if __OpenBSD__
	if (pledge("stdio inet proc id sendfd recvfd", NULL) < 0) {
		perror("pledge");
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
	 * I open the log again after the chroot just in case I can't
	 * reach the old /dev/log anymore.
 	 */

	closelog();
	openlog(__progname, LOG_PID | LOG_NDELAY, LOG_DAEMON);

	/* set groups */

	if (setgroups(1, &pw->pw_gid) < 0) {
		dolog(LOG_INFO, "setgroups: %s\n", strerror(errno));
		slave_shutdown();
		exit(1);
	}

#if defined __OpenBSD__ || defined __FreeBSD__
	if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) < 0) {
		dolog(LOG_INFO, "setresgid: %s\n", strerror(errno));
		slave_shutdown();
		exit(1);
	}

	if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) < 0) {
		dolog(LOG_INFO, "setresuid: %s\n", strerror(errno));
		slave_shutdown();
		exit(1);
	}

#else
	if (setgid(pw->pw_gid) < 0) {
		dolog(LOG_INFO, "setgid: %s\n", strerror(errno));
		slave_shutdown();
		exit(1);
	}
	if (setuid(pw->pw_uid) < 0) {
		dolog(LOG_INFO, "setuid: %s\n", strerror(errno));
		slave_shutdown();
		exit(1);
	}
#endif

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
		case 0:
			/* close descriptors that we don't need */
			for (j = 0; j < i; j++) {
				close(tcp[j]);
				close(udp[j]);
				if (axfrport && axfrport != port)
					close(uafd[j]);
			}

#if !defined __APPLE__
			setproctitle("AXFR engine on port %d", axfrport);
#endif

			/* don't need master here */
			close(cfg->my_imsg[MY_IMSG_MASTER].imsg_fds[1]);
			close(cfg->my_imsg[MY_IMSG_AXFR].imsg_fds[1]);
			imsg_init(parent_ibuf[MY_IMSG_AXFR], cfg->my_imsg[MY_IMSG_AXFR].imsg_fds[0]);

			axfrloop(afd, i, ident, db, parent_ibuf[MY_IMSG_AXFR]);
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

	for (n = 0; n < nflag; n++) {
		switch (pid = fork()) {
		case 0:
			cfg->sockcount = i;
			cfg->db = db;
			for (i = 0; i < cfg->sockcount; i++) {
				cfg->udp[i] = udp[i];
				cfg->tcp[i] = tcp[i];

				if (axfrport && axfrport != port)
					cfg->axfr[i] = uafd[i];

				cfg->ident[i] = strdup(ident[i]);
			}

			cfg->log = lfd;

			
			(void)mainloop(cfg, child_ibuf);

			/* NOTREACHED */
		default:	
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
	cfg->log = lfd;


	(void)mainloop(cfg, child_ibuf);

	/* NOTREACHED */
	return (0);
}


/*
 * BUILD_QUESTION - fill the question structure with the DNS query.
 */

struct question *
build_question(char *buf, int len, int additional) 
{
	u_int i;
	u_int namelen = 0;
	u_int16_t *qtype, *qclass;
	u_int32_t ttl;
	int num_label;

	char *p, *end_name = NULL;

	struct dns_optrr *opt = NULL;
	struct question *q = NULL;
	struct dns_header *hdr = (struct dns_header *)buf;

	/* find the end of name */
	for (i = sizeof(struct dns_header); i < len; i++) {
		/* XXX */
		if (buf[i] == 0) {
			end_name = &buf[i];			
			break;
		}
	}

	/* 
	 * implies i >= len , because end_name still points to NULL and not
	 * &buf[i]
	 */

	if (end_name == NULL) {
		dolog(LOG_INFO, "query name is not null terminated\n");
		return NULL;
	}

	/* parse the size of the name */
	for (i = sizeof(struct dns_header), num_label = 0; i < len && &buf[i] < end_name;) {
		u_int labellen;

		++num_label;
		
		labellen = (u_int)buf[i];	

		/* 
		 * do some checks on the label, if it's 0 or over 63 it's
		 * illegal, also if it reaches beyond the entire name it's
		 * also illegal.
		 */
		if (labellen == 0) {
			dolog(LOG_INFO, "illegal label len (0)\n");
			return NULL;
		}
		if (labellen > DNS_MAXLABEL) {
			dolog(LOG_INFO, "illegal label len (> 63)\n");
			return NULL;
		}
		if (labellen > (end_name - &buf[i])) {
			dolog(LOG_INFO, "label len extends beyond name\n");
			return NULL;
		}

		i += (labellen + 1);
		namelen += labellen;
	}
	
	if (&buf[i] != end_name || i >= len) {
		dolog(LOG_INFO, "query name is maliciously malformed\n");
		return NULL;
	}

	if (i > DNS_MAXNAME) {
		dolog(LOG_INFO, "query name is too long (%u)\n", i);
		return NULL;
	}

	
	/* check if there is space for qtype and qclass */
	if (len < ((end_name - &buf[0]) + (2 * sizeof(u_int16_t)))) {
		dolog(LOG_INFO, "question rr is truncated\n");
		return NULL;
	}
		
	
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
	q->hdr->namelen = (end_name - &buf[sizeof(struct dns_header)]) + 1;	/* XXX */
	q->hdr->name = (void *) calloc(1, q->hdr->namelen);
	if (q->hdr->name == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		free(q->hdr);
		free(q);
		return NULL;
	}
	q->converted_name = (void *)calloc(1, namelen + num_label + 2);
	if (q->converted_name == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));	
		free(q->hdr->name);
		free(q->hdr);
		free(q);
		return NULL;
	}

	p = q->converted_name;

	/* 
	 * parse the name again this time filling the labels 
	 * XXX this is expensive going over the buffer twice
	 */
	for (i = sizeof(struct dns_header); i < len && &buf[i] < end_name;) {
		u_int labelend;


		/* check for compression */
		if ((buf[i] & 0xc0) == 0xc0) {
			dolog(LOG_INFO, "question has compressed name, drop\n");
			free_question(q);
			return NULL;	/* XXX should say error */
		}

		labelend = (u_int)buf[i] + 1 + i; /* i = offset, plus contents of buf[i], + 1 */

		/* 
 		 * i is reused here to count every character, this is not 
		 * a bug!
		 */

		for (i++; i < labelend; i++) {
			int c0; 

			c0 = buf[i];
			*p++ = tolower(c0);
		}

		*p++ = '.';
	}

	/* XXX */
	if (&buf[sizeof(struct dns_header)] == end_name) 
		*p++ = '.';

	*p = '\0';

	/* check for edns0 opt rr */
	do {
		/* if we don't have an additional section, break */
		if (additional != 1)
			break;

		i += (2 * sizeof(u_int16_t)) + 1;

		/* check that the minimum optrr fits */
		/* 10 */
		if (i + sizeof(struct dns_optrr) > len)
			break;

		opt = (struct dns_optrr *)&buf[i];
		if (opt->name[0] != 0)
			break;

		if (ntohs(opt->type) != DNS_TYPE_OPT)
			break;

		/* RFC 3225 */
		ttl = ntohl(opt->ttl);
		if (((ttl >> 16) & 0xff) != 0)
			q->ednsversion = (ttl >> 16) & 0xff;

		q->edns0len = ntohs(opt->class);
		if (q->edns0len < 512)
			q->edns0len = 512;	/* RFC 6891 - page 10 */

		if (ttl & DNSSEC_OK)
			q->dnssecok = 1;
	} while (0);

	/* fill our name into the dns header struct */
		
	memcpy(q->hdr->name, &buf[sizeof(struct dns_header)], q->hdr->namelen);
	
	/* make it lower case */

	for (i = 0; i < q->hdr->namelen; i++) {
		int c0;

		c0 = q->hdr->name[i];
		if (isalpha(c0)) {
			q->hdr->name[i] = tolower(c0);
		}
	}

	/* parse type and class from the question */

	qtype = (u_int16_t *)(end_name + 1);
	qclass = (u_int16_t *)(end_name + sizeof(u_int16_t) + 1);		

	memcpy((char *)&q->hdr->qtype, (char *)qtype, sizeof(u_int16_t));
	memcpy((char *)&q->hdr->qclass, (char *)qclass, sizeof(u_int16_t));

	/* make note of whether recursion is desired */
	q->rd = ((ntohs(hdr->query) & DNS_RECURSE) == DNS_RECURSE);

	return (q);
}

/*
 * FREE_QUESTION - free a question struct
 *
 */

int
free_question(struct question *q)
{
	free(q->hdr->name);
	free(q->hdr);
	free(q->converted_name);
	free(q);
	
	return 0;
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
	u_int16_t *compressor;

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
	compressor = (u_int16_t *)&buf[offset];	

	*compressor = (compressmark - &buf[0]);
	*compressor |= 0xc000;

	/* network byte order */
	HTONS(*compressor);

	offset += sizeof(u_int16_t);	

	return (offset);
}



/*
 * GET_SOA - get authoritative soa for a particular domain
 */

struct domain *
get_soa(ddDB *db, struct question *question)
{
	struct domain *sd = NULL;

	int plen;
	int ret = 0;
	int rs;
	
	ddDBT key, data;

	char *p;

	p = question->hdr->name;
	plen = question->hdr->namelen;

	do {

		rs = get_record_size(db, p, plen);
		if (rs < 0) {
			return NULL;
		}

		if ((sd = calloc(1, rs)) == NULL) {
			return NULL;
		}

		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));

		key.data = (char *)p;
		key.size = plen;

		data.data = NULL;
		data.size = rs;

		ret = db->get(db, &key, &data);
		if (ret != 0) {
			plen -= (*p + 1);
			p = (p + (*p + 1));
			free (sd);
			continue;
		}
		
		if (data.size != rs) {
			dolog(LOG_INFO, "btree db is damaged, drop\n");
			free(sd);
			return (NULL);
		}

		memcpy((char *)sd, (char *)data.data, data.size);

		if ((sd->flags & DOMAIN_HAVE_SOA) == DOMAIN_HAVE_SOA)  {
			/* we'll take this one */
			return (sd);	
		} else {
			plen -= (*p + 1);
			p = (p + (*p + 1));
		} 

		free(sd);
	} while (*p);

	return (NULL);
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
	int len, slen;
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
	int sp; 
	int lfd;
	int idata;

       u_int32_t received_ttl;
#if defined __FreeBSD__ || defined __OpenBSD__
	u_char *ttlptr;
#else
	int *ttlptr;
#endif

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
	socklen_t logfromlen = sizeof(struct sockaddr_storage);

	struct sockaddr *from = (void *)&sockaddr_large;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct sockaddr_storage logfrom;

	struct dns_header *dh;
	struct question *question = NULL, *fakequestion = NULL;
	struct domain *sd0 = NULL, *sd1 = NULL;
	struct domain_cname *csd;
	
	struct sreply sreply;
	struct timeval tv = { 10, 0};

	struct msghdr msgh;
	struct cmsghdr *cmsg = NULL;
	struct iovec iov;
	struct imsgbuf tcp_ibuf;
	
	replybuf = calloc(1, 65536);
	if (replybuf == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		slave_shutdown();
		exit(1);
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
		close(cfg->my_imsg[MY_IMSG_MASTER].imsg_fds[1]);
		close(cfg->my_imsg[MY_IMSG_TCP].imsg_fds[1]);
		imsg_init(ibuf[MY_IMSG_TCP], cfg->my_imsg[MY_IMSG_TCP].imsg_fds[0]);
		setproctitle("TCP engine");
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
	lfd = cfg->log;

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
	
		if (logging.bind == 1) {
			if (maxso < lfd)
				maxso = lfd;
			FD_SET(lfd, &rset);
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
#elif defined __NetBSD__
                        				&& cmsg->cmsg_type == IP_TTL) {

#else

                        				&& cmsg->cmsg_type == IP_RECVTTL) {
#endif
										
#if defined __FreeBSD__ || defined __OpenBSD__ 

                              			ttlptr = (u_char *) CMSG_DATA(cmsg);
                              			received_ttl = (u_int)*ttlptr;
#else

                              			ttlptr = (int *) CMSG_DATA(cmsg);
                              			received_ttl = (u_int)*ttlptr;
#endif
                      				}

									if (cmsg->cmsg_level == IPPROTO_IPV6 &&
                         				cmsg->cmsg_type == IPV6_HOPLIMIT) {

										if (cmsg->cmsg_len != 
												CMSG_LEN(sizeof(int))) {
											dolog(LOG_INFO, "cmsg->cmsg_len == %d\n", cmsg->cmsg_len);
											continue;
										}

#ifdef __NetBSD__
										ttlptr = (int *) CMSG_DATA(cmsg);
#else
										ttlptr = (u_char *) CMSG_DATA(cmsg);
#endif


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
					filter = find_filter((struct sockaddr_storage *)sin6, AF_INET6);
					if (whitelist) {
						blacklist = find_whitelist((struct sockaddr_storage *)sin6, AF_INET6);
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
					filter = find_filter((struct sockaddr_storage *)sin, AF_INET);
					if (whitelist) {
						blacklist = find_whitelist((struct sockaddr_storage *)sin, AF_INET);
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

				dh = (struct dns_header *)&buf[0];	

				/* check if we're a question or reply, drop replies */
				if ((ntohs(dh->query) & DNS_REPLY)) {
					dolog(LOG_INFO, "on descriptor %u interface \"%s\" dns header from %s is not a question, drop\n", so, cfg->ident[i], address);
					goto drop;
				}

				/* 
				 * if questions aren't exactly 1 then drop
				 */

				if (ntohs(dh->question) != 1) {
					dolog(LOG_INFO, "on descriptor %u interface \"%s\" header from %s has no question, drop\n", so, cfg->ident[i], address);

					/* format error */
					build_reply(&sreply, so, buf, len, NULL, from, fromlen, NULL, NULL, aregion, istcp, 0, NULL, replybuf);

					slen = reply_fmterror(&sreply);
					dolog(LOG_INFO, "question on descriptor %d interface \"%s\" from %s, did not have question of 1 replying format error\n", so, cfg->ident[i], address);
					goto drop;
				}

				if (filter) {

					build_reply(&sreply, so, buf, len, NULL, from, fromlen, NULL, NULL, aregion, istcp, 0, NULL, replybuf);
					slen = reply_refused(&sreply);

					dolog(LOG_INFO, "UDP connection refused on descriptor %u interface \"%s\" from %s (ttl=%d, region=%d) replying REFUSED, filter policy\n", so, cfg->ident[i], address, received_ttl, aregion);
					goto drop;
				}

				if (whitelist && blacklist == 0) {

					build_reply(&sreply, so, buf, len, NULL, from, fromlen, NULL, NULL, aregion, istcp, 0, NULL, replybuf);
					slen = reply_refused(&sreply);

					dolog(LOG_INFO, "UDP connection refused on descriptor %u interface \"%s\" from %s (ttl=%d, region=%d) replying REFUSED, whitelist policy\n", so, cfg->ident[i], address, received_ttl, aregion);
					goto drop;
				}

				if (ratelimit && rcheck) {
					dolog(LOG_INFO, "UDP connection refused on descriptor %u interface \"%s\" from %s (ttl=%d, region=%d) ratelimit policy dropping packet\n", so, cfg->ident[i], address, received_ttl, aregion);
					goto drop;
				}
					
				if ((question = build_question(buf, len, ntohs(dh->additional))) == NULL) {
					dolog(LOG_INFO, "on descriptor %u interface \"%s\" malformed question from %s, drop\n", so, cfg->ident[i], address);
					goto drop;
				}

				/* goto drop beyond this point should goto out instead */

				/* hack around whether we're edns version 0 */
				if (question->ednsversion != 0) {
					build_reply(&sreply, so, buf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, NULL, replybuf);
					slen = reply_badvers(&sreply);

					dolog(LOG_INFO, "on descriptor %u interface \"%s\" edns version is %u from %s, replying badvers\n", so, cfg->ident[i], question->ednsversion, address);

					snprintf(replystring, DNS_MAXNAME, "BADVERS");
					goto udpout;
				}

				fakequestion = NULL;

				sd0 = lookup_zone(cfg->db, question, &type0, &lzerrno, (char *)&replystring);
				if (type0 < 0) {
					switch (lzerrno) {
					default:
						dolog(LOG_INFO, "invalid lzerrno! dropping\n");
						/* FALLTHROUGH */
					case ERR_DROP:
						snprintf(replystring, DNS_MAXNAME, "DROP");
						goto udpout;
					case ERR_REFUSED:
						if (ntohs(question->hdr->qclass) == DNS_CLASS_CH &&
							ntohs(question->hdr->qtype) == DNS_TYPE_TXT &&
								strcasecmp(question->converted_name, "version.bind.") == 0) {
								snprintf(replystring, DNS_MAXNAME, "VERSION");
								build_reply(&sreply, so, buf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, NULL, replybuf);
								slen = reply_version(&sreply);
								goto udpout;
						}
						snprintf(replystring, DNS_MAXNAME, "REFUSED");
#if 0
						fakequestion = build_fake_question(sd0->zone, sd0->zonelen, DNS_TYPE_SOA);
						if (fakequestion == NULL) {
							dolog(LOG_INFO, "fakequestion failed\n");
							break;
						}
#endif

						build_reply(&sreply, so, buf, len, question, from, fromlen, sd0, NULL, aregion, istcp, 0, NULL, replybuf);
						slen = reply_refused(&sreply);
						goto udpout;
						break;
					case ERR_NXDOMAIN:
						/* check if our question is for an ENT */
						if (check_ent(question->hdr->name, question->hdr->namelen) == 1) {
							if (dnssec) {
								goto udpnoerror;
							} else {
								snprintf(replystring, DNS_MAXNAME, "NODATA");
								build_reply(&sreply, so, buf, len, question, from, fromlen, sd0, NULL, aregion, istcp, 0, NULL, replybuf);
								slen = reply_nodata(&sreply);
								goto udpout;
								break;
							}	
						} else {
							goto udpnxdomain;
						}
					case ERR_NOERROR:
							/*
							 * this is hackish not sure if this should be here
							 */

udpnoerror:

							snprintf(replystring, DNS_MAXNAME, "NOERROR");

							/*
							 * lookup an authoritative soa
							 */

							if (sd0) {
								free (sd0);
								sd0 = NULL;
							}
						
							sd0 = get_soa(cfg->db, question);
							if (sd0 != NULL) {

									build_reply(&sreply, so, buf, len, question, from, \
										fromlen, sd0, NULL, aregion, istcp, 0, 
										NULL, replybuf);

									slen = reply_noerror(&sreply, cfg->db);
							} 
							goto udpout;
					}
				}

				switch (type0) {
				case 0:
udpnxdomain:
						if (check_ent(question->hdr->name, question->hdr->namelen) == 1) {
							if (dnssec) {
								goto udpnoerror;
							} else {
								snprintf(replystring, DNS_MAXNAME, "NODATA");
								build_reply(&sreply, so, buf, len, question, from, fromlen, sd0, NULL, aregion, istcp, 0, NULL, replybuf);
								slen = reply_nodata(&sreply);
								goto udpout;
							}	
						}

						/*
						 * lookup_zone could not find an RR for the
						 * question at all -> nxdomain
						 */
						snprintf(replystring, DNS_MAXNAME, "NXDOMAIN");

						/* 
						 * lookup an authoritative soa 
						 */
					
						if (sd0 != NULL) {
								build_reply(&sreply, so, buf, len, question, from, \
								fromlen, sd0, NULL, aregion, istcp, \
								0, NULL, replybuf);

								slen = reply_nxdomain(&sreply, cfg->db);
						}
						goto udpout;
				case DNS_TYPE_CNAME:
					csd = (struct domain_cname *)find_substruct(sd0, INTERNAL_TYPE_CNAME);
					fakequestion = build_fake_question(csd->cname, csd->cnamelen, question->hdr->qtype);
					if (fakequestion == NULL) {	
						dolog(LOG_INFO, "fakequestion failed\n");
						break;
					}

					sd1 = lookup_zone(cfg->db, fakequestion, &type1, &lzerrno, (char *)&fakereplystring);
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

					slen = reply_notimpl(&sreply);
					snprintf(replystring, DNS_MAXNAME, "NOTIMPL");
					goto udpout;
				}
		
				switch (ntohs(question->hdr->qtype)) {
				case DNS_TYPE_A:
					if (type0 == DNS_TYPE_CNAME) {

						build_reply(&sreply, so, buf, len, question, from, 	\
							fromlen, sd0, ((type1 > 0) ? sd1 : NULL), \
							aregion, istcp, 0, NULL, replybuf);

						slen = reply_cname(&sreply);
					} else if (type0 == DNS_TYPE_NS) {

						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, sd0, NULL, aregion, istcp, 0, \
							NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);
						break;
					} else if (type0 == DNS_TYPE_A) {

						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, sd0, NULL, aregion, istcp, 0, 
							NULL, replybuf);

						slen = reply_a(&sreply, cfg->db);
						break;		/* must break here */
					}

					break;

				case DNS_TYPE_ANY:
					build_reply(&sreply, so, buf, len, question, from, \
						fromlen, sd0, NULL, aregion, istcp, 0, NULL,
						replybuf);

					slen = reply_any(&sreply);
					break;		/* must break here */
				case DNS_TYPE_NSEC3PARAM:
					build_reply(&sreply, so, buf, len, question, from, \
						fromlen, sd0, NULL, aregion, istcp, 0, NULL,
						replybuf);

					slen = reply_nsec3param(&sreply);
					break;

				case DNS_TYPE_NSEC3:
					build_reply(&sreply, so, buf, len, question, from, \
						fromlen, sd0, NULL, aregion, istcp, 0, NULL,
						replybuf);

					slen = reply_nxdomain(&sreply, cfg->db);
					break;

				case DNS_TYPE_NSEC:
					build_reply(&sreply, so, buf, len, question, from, \
						fromlen, sd0, NULL, aregion, istcp, 0, NULL,
						replybuf);

					slen = reply_nsec(&sreply);
					break;

				case DNS_TYPE_DS:
					build_reply(&sreply, so, buf, len, question, from, \
						fromlen, sd0, NULL, aregion, istcp, 0, NULL,
						replybuf);

					slen = reply_ds(&sreply);
					break;

				case DNS_TYPE_DNSKEY:
					build_reply(&sreply, so, buf, len, question, from, \
						fromlen, sd0, NULL, aregion, istcp, 0, NULL,
						replybuf);

					slen = reply_dnskey(&sreply);
					break;

				case DNS_TYPE_RRSIG:
					build_reply(&sreply, so, buf, len, question, from, \
						fromlen, sd0, NULL, aregion, istcp, 0, NULL,
						replybuf);

					slen = reply_rrsig(&sreply, cfg->db);
					break;		/* must break here */


				case DNS_TYPE_AAAA:
					
					if (type0 == DNS_TYPE_CNAME) {

						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, sd0, ((type1 > 0) ? sd1 : NULL), \
							aregion, istcp, 0, NULL, replybuf);

						slen = reply_cname(&sreply);
					} else if (type0 == DNS_TYPE_NS) {

						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, sd0, NULL, aregion, istcp, 0, \
							NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);
						break;
					 } else if (type0 == DNS_TYPE_AAAA) {

						build_reply(&sreply, so, buf, len, question, from, 
							fromlen, sd0, NULL, aregion, istcp, 0, 
							NULL, replybuf);

						slen = reply_aaaa(&sreply, cfg->db);
						break;		/* must break here */
					}

					break;
				case DNS_TYPE_MX:
					
					if (type0 == DNS_TYPE_CNAME) {

						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, sd0, ((type1 > 0) ? sd1 : NULL), \
							aregion, istcp, 0, NULL, replybuf);

						slen = reply_cname(&sreply);
	   				} else if (type0 == DNS_TYPE_NS) {

						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, sd0, NULL, aregion, istcp, 0, \
							NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);
						break;
					} else if (type0 == DNS_TYPE_MX) {
						build_reply(&sreply, so, buf, len, question, from,  \
							fromlen, sd0, NULL, aregion, istcp, 0, \
							NULL, replybuf);
						slen = reply_mx(&sreply, cfg->db);
						break;		/* must break here */
					}

					break;
				case DNS_TYPE_SOA:
					if (type0 == DNS_TYPE_SOA) {

						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, sd0, NULL, aregion, istcp, 0, \
							NULL, replybuf);

						slen = reply_soa(&sreply);
					} else if (type0 == DNS_TYPE_NS) {

						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, sd0, NULL, aregion, istcp, 0, \
							NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);
						break;
					}
					break;
				case DNS_TYPE_NS:
					if (type0 == DNS_TYPE_NS) {

						build_reply(&sreply, so, buf, len, question, from,  \
							fromlen, sd0, NULL, aregion, istcp, 0, \
							NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);
					}
					break;

				case DNS_TYPE_TLSA:
					if (type0 == DNS_TYPE_TLSA) {
						build_reply(&sreply, so, buf, len, question, from,  \
							fromlen, sd0, NULL, aregion, istcp, 0, \
							NULL, replybuf);

						slen = reply_tlsa(&sreply);
					}
					break;

				case DNS_TYPE_SSHFP:
					if (type0 == DNS_TYPE_SSHFP) {
						build_reply(&sreply, so, buf, len, question, from,  \
							fromlen, sd0, NULL, aregion, istcp, 0, \
							NULL, replybuf);

						slen = reply_sshfp(&sreply);
					}
					break;


				case DNS_TYPE_SRV:
					if (type0 == DNS_TYPE_SRV) {

						build_reply(&sreply, so, buf, len, question, from,  \
							fromlen, sd0, NULL, aregion, istcp, 0, \
							NULL, replybuf);

						slen = reply_srv(&sreply, cfg->db);
					}
					break;

				case DNS_TYPE_NAPTR:
					if (type0 == DNS_TYPE_NAPTR) {

						build_reply(&sreply, so, buf, len, question, from,  \
							fromlen, sd0, NULL, aregion, istcp, 0, \
							NULL, replybuf);

						slen = reply_naptr(&sreply, cfg->db);
					}
					break;

				case DNS_TYPE_CNAME:
					if (type0 == DNS_TYPE_CNAME) {

						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, sd0, NULL, aregion, istcp, 0, \
							NULL, replybuf);

						slen = reply_cname(&sreply);
					} else if (type0 == DNS_TYPE_NS) {

						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, sd0, NULL, aregion, istcp, 0, \
							NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);
						break;
					}
					break;

				case DNS_TYPE_PTR:
					if (type0 == DNS_TYPE_CNAME) {

						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, sd0, ((type1 > 0) ? sd1 : NULL) \
							, aregion, istcp, 0, NULL, replybuf);

						slen = reply_cname(&sreply);
					} else if (type0 == DNS_TYPE_NS) {

						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, sd0, NULL, aregion, istcp, 0, \
							NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);
						break;
					} else if (type0 == DNS_TYPE_PTR) {

						build_reply(&sreply, so, buf, len, question, from, 	
								fromlen, sd0, NULL, aregion, istcp, 0, \
								NULL, replybuf);

						slen = reply_ptr(&sreply);
						break;		/* must break here */
					}
					break;
				case DNS_TYPE_TXT:
					if (type0 == DNS_TYPE_TXT) {

						build_reply(&sreply, so, buf, len, question, from,  \
							fromlen, sd0, NULL, aregion, istcp, 0, \
							NULL, replybuf);

						slen = reply_txt(&sreply);
					}
					break;

				default:

					/*
					 * ANY unkown RR TYPE gets a NOTIMPL
					 */
					/*
					 * except for delegations 
					 */
					
					if (type0 == DNS_TYPE_NS) {

						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, sd0, NULL, aregion, istcp, 0, \
							NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);
					} else {


						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, NULL, NULL, aregion, istcp, 0, \
							NULL, replybuf);

						slen = reply_notimpl(&sreply);
						snprintf(replystring, DNS_MAXNAME, "NOTIMPL");
					}
					break;
				}
			
		udpout:
				if (lflag) {
					dolog(LOG_INFO, "request on descriptor %u interface \"%s\" from %s (ttl=%u, region=%d) for \"%s\" type=%s class=%u, %s%sanswering \"%s\" (%d/%d)\n", so, cfg->ident[i], address, received_ttl, aregion, question->converted_name, get_dns_type(ntohs(question->hdr->qtype), 1), ntohs(question->hdr->qclass), (question->edns0len ? "edns0, " : ""), (question->dnssecok ? "dnssecok, " : "") , replystring, len, slen);

				}

				if (logging.active == 1 && logging.bind == 0) {
					remotelog(lfd, "request on descriptor %u interface \"%s\" from %s (ttl=%u, region=%d) for \"%s\" type=%s class=%u, %s%sanswering \"%s\" (%d/%d)", so, cfg->ident[i], address, received_ttl, aregion, question->converted_name, get_dns_type(ntohs(question->hdr->qtype), 1), ntohs(question->hdr->qclass), (question->edns0len ? "edns0, ": ""), (question->dnssecok ? "dnssecok" : ""), replystring, len, slen);
				}

				if (fakequestion != NULL) {
					free_question(fakequestion);
				}
	
				free_question(question);

				if (sd0) {
					free (sd0);
					sd0 = NULL;
				}
				if (sd1) {
					free (sd1);
					sd1 = NULL;
				}

			}	/* END ISSET */

		} /* for */

		if (logging.bind == 1 && FD_ISSET(lfd, &rset)) {
			logfromlen = sizeof(struct sockaddr_storage);
			len = recvfrom(lfd, buf, sizeof(buf), 0, (struct sockaddr *)&logfrom, &logfromlen);
			if (len < 0) {
				dolog(LOG_INFO, "recvfrom: logging %s\n", strerror(errno));
			} else
				receivelog(buf, len);
		}

	drop:
		
		if (sd0) {	
			free(sd0);
			sd0 = NULL;
		}

		if (sd1) {
			free(sd1);
			sd1 = NULL;
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
build_reply(struct sreply *reply, int so, char *buf, int len, struct question *q, struct sockaddr *sa, socklen_t slen, struct domain *sd1, struct domain *sd2, u_int8_t region, int istcp, int deprecated0, struct recurses *sr, char *replybuf)
{
	reply->so = so;
	reply->buf = buf;
	reply->len = len;
	reply->q = q;
	reply->sa = sa;
	reply->salen = slen;
	reply->sd1 = sd1;
	reply->sd2 = sd2;
	reply->region = region;
	reply->istcp = istcp;
	reply->wildcard = 0;
	reply->sr = sr;
	reply->replybuf = replybuf;

	return;
}
		

void
recurseheader(struct srecurseheader *rh, int proto, struct sockaddr_storage *src, struct sockaddr_storage *dst, int family) 
{
	struct sockaddr_in *sin, *sin0;
	struct sockaddr_in6 *sin6, *sin60;

	rh->af = family;
	rh->proto = proto;

	if (family == AF_INET) {
		sin = (struct sockaddr_in *)&rh->dest;
		sin0 = (struct sockaddr_in *)dst;
		sin->sin_family = sin0->sin_family;
		sin->sin_port = sin0->sin_port;
		memcpy((char *)&sin->sin_addr.s_addr, 
			(char *)&sin0->sin_addr.s_addr,
			sizeof(sin->sin_addr.s_addr));
		sin = (struct sockaddr_in *)&rh->source;
		sin0 = (struct sockaddr_in *)src;
		sin->sin_family = sin0->sin_family;
		sin->sin_port = sin0->sin_port;
		memcpy((char *)&sin->sin_addr.s_addr, 
			(char *)&sin0->sin_addr.s_addr,
			sizeof(sin->sin_addr.s_addr));
	} else if (family == AF_INET6) {
		sin6 = (struct sockaddr_in6 *)&rh->dest;
		sin60 = (struct sockaddr_in6 *)dst;

		sin6->sin6_family = sin60->sin6_family;
		sin6->sin6_port = sin60->sin6_port;
		
		memcpy((char *)&sin6->sin6_addr, 
			(char *)&sin60->sin6_addr,
			sizeof(sin6->sin6_addr));

		sin6 = (struct sockaddr_in6 *)&rh->source;
		sin60 = (struct sockaddr_in6 *)src;

		sin6->sin6_family = sin60->sin6_family;
		sin6->sin6_port = sin60->sin6_port;
		
		memcpy((char *)&sin6->sin6_addr, 
			(char *)&sin60->sin6_addr,
			sizeof(sin6->sin6_addr));
	}
	
	
	return;
}

/*
 * The master process, waits to be killed, if any other processes are killed
 * and they indicate shutdown through the shared memory segment it will kill
 * the rest of processes in the parent group.
 */

void 
setup_master(ddDB *db, char **av, struct imsgbuf *ibuf)
{
	char buf[512];
	pid_t pid;
	int fd;
	int sel, max = 0;

	ssize_t n;
	fd_set rset;

	struct timeval tv;
	struct domain *idata;
	struct imsg imsg;

#if __OpenBSD__
	if (pledge("stdio wpath cpath exec proc", NULL) < 0) {
		perror("pledge");
		exit(1);
	}
#endif
	
	idata = (struct domain *)calloc(1, SIZENODE); 
	if (idata == NULL) {
		dolog(LOG_ERR, "couldn't malloc memory for idata\n");
		pid = getpgrp();
		killpg(pid, SIGTERM);
		exit(1);
	}
			
	setproctitle("delphinusdnsd master");

	fd = open(PIDFILE, O_WRONLY | O_APPEND | O_CREAT, 0644);
	if (fd < 0) {
		dolog(LOG_ERR, "couldn't install pid file, exiting...\n");
		pid = getpgrp();
		killpg(pid, SIGTERM);
		exit(1);
	}
	
	pid = getpid();
	snprintf(buf, sizeof(buf), "%u\n", pid);

	write(fd, buf, strlen(buf));	
	close(fd);

	signal(SIGTERM, master_shutdown);
	signal(SIGINT, master_shutdown);
	signal(SIGQUIT, master_shutdown);
	signal(SIGHUP, master_reload);

	FD_ZERO(&rset);	
	for (;;) {
		tv.tv_sec = 10;
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
				unlink(PIDFILE);

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
			
				unlink(PIDFILE);

				dolog(LOG_INFO, "restarting on SIGHUP\n");

				closelog();
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


int
lookup_type(int internal_type)
{
	int array[INTERNAL_TYPE_MAX];

	array[INTERNAL_TYPE_A] = DOMAIN_HAVE_A;
	array[INTERNAL_TYPE_AAAA] = DOMAIN_HAVE_AAAA;
	array[INTERNAL_TYPE_CNAME] = DOMAIN_HAVE_CNAME;
	array[INTERNAL_TYPE_NS] = DOMAIN_HAVE_NS;
	array[INTERNAL_TYPE_DNSKEY] =DOMAIN_HAVE_DNSKEY;
	array[INTERNAL_TYPE_DS] = DOMAIN_HAVE_DS;
	array[INTERNAL_TYPE_MX] = DOMAIN_HAVE_MX;
	array[INTERNAL_TYPE_NAPTR] = DOMAIN_HAVE_NAPTR;
	array[INTERNAL_TYPE_NSEC] = DOMAIN_HAVE_NSEC;
	array[INTERNAL_TYPE_NSEC3] = DOMAIN_HAVE_NSEC3;
	array[INTERNAL_TYPE_NSEC3PARAM] = DOMAIN_HAVE_NSEC3PARAM;
	array[INTERNAL_TYPE_PTR] = DOMAIN_HAVE_PTR;
	array[INTERNAL_TYPE_RRSIG] = -1;
	array[INTERNAL_TYPE_SOA] = DOMAIN_HAVE_SOA;
	array[INTERNAL_TYPE_SRV] = DOMAIN_HAVE_SRV;
	array[INTERNAL_TYPE_SSHFP] = DOMAIN_HAVE_SSHFP;
	array[INTERNAL_TYPE_TLSA] = DOMAIN_HAVE_TLSA;
	array[INTERNAL_TYPE_TXT] = DOMAIN_HAVE_TXT;

	if (internal_type < 0 || internal_type > INTERNAL_TYPE_MAX)
		return -1;

	return(array[internal_type]);
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
	int len, slen, length;
	int is_ipv6;
	int i;
	int istcp = 1;
	int maxso;
	int so;
	int type0, type1;
	int lzerrno;
	int filter = 0;
	int blacklist = 1;
	int axfr_acl = 0;
	int sp; 
	int lfd;

	u_int8_t aregion;			/* region where the address comes from */

	char *pbuf;
	char buf[4096];
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

	struct dns_header *dh;
	struct question *question = NULL, *fakequestion = NULL;
	struct domain *sd0 = NULL, *sd1 = NULL;
	struct domain_cname *csd;
	
	struct sreply sreply;
	struct timeval tv = { 10, 0};

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
	lfd = cfg->log;

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
	
		tv.tv_sec = 10;
		tv.tv_usec = 0;

		sel = select(maxso + 1, &rset, NULL, NULL, &tv);

		if (sel < 0) {
			dolog(LOG_INFO, "select: %s\n", strerror(errno));
			continue;
		}

		if (sel == 0) {
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
				} else {
					dolog(LOG_INFO, "TCP packet received on descriptor %u interface \"%s\" had weird address family (%u), drop\n", so, cfg->ident[i], from->sa_family);
					close(so);
					continue;
				}


				if (filter) {
					dolog(LOG_INFO, "TCP connection refused on descriptor %u interface \"%s\" from %s, filter policy\n", so, cfg->ident[i], address);
					close(so);
					continue;
				}

				if (whitelist && blacklist == 0) {
					dolog(LOG_INFO, "TCP connection refused on descriptor %u interface \"%s\" from %s, whitelist policy\n", so, cfg->ident[i], address);
					close(so);
					continue;
				}

				/*
				 * We wrap a 3 second alarm, 3000 ms is a long
				 * time on the Internet so this is ok...
				 */
				tv.tv_sec = 3;
				tv.tv_usec = 0;
				if (setsockopt(so, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
					dolog(LOG_INFO, "setsockopt: %s\n", strerror(errno));
					close(so);
					continue;
				}

				len = recv(so, buf, 2, MSG_WAITALL | MSG_PEEK);
				if (len < 0) {
					if (errno == EWOULDBLOCK) {
						dolog(LOG_INFO, "TCP socket timed out on descriptor %d interface \"%s\" from %s\n", so, cfg->ident[i], address);
					}
					close(so);
					continue;
				} /* if len */

				if (len != 2) {
					close(so);
					continue;
				}

				length = ntohs(*((u_int16_t *)&buf[0]));
				if ((length + 2) > sizeof(buf)) {
					close(so);
					continue;
				}

				len = recv(so, buf, (length + 2), MSG_WAITALL);
				if (len < 0) {
					if (errno == EWOULDBLOCK) {
						dolog(LOG_INFO, "TCP socket timed out on descriptor %d interface \"%s\" from %s\n", so, cfg->ident[i], address);
					}
					close(so);
					continue;
				} /* if len */

				if (len == 0) {
					close(so);
					continue;
				}

				if (len >= 2) {	
					length = ntohs(*((u_int16_t *)&buf[0]));
				}

				len = length;
				pbuf = &buf[2];

				if (len > DNS_MAXUDP || len < sizeof(struct dns_header)){
					dolog(LOG_INFO, "TCP packet on descriptor %u interface \"%s\" illegal dns packet length from %s, drop\n", so, cfg->ident[i], address);
					goto drop;
				}

				dh = (struct dns_header *)&pbuf[0];	

				/* check if we're a question or reply, drop replies */
				if ((ntohs(dh->query) & DNS_REPLY)) {
					dolog(LOG_INFO, "TCP packet on descriptor %u interface \"%s\" dns header from %s is not a question, drop\n", so, cfg->ident[i], address);
					goto drop;
				}

				/* 
				 * if questions aren't exactly 1 then drop
				 */

				if (ntohs(dh->question) != 1) {
					dolog(LOG_INFO, "TCP packet on descriptor %u interface \"%s\" header from %s has no question, drop\n", so, cfg->ident[i], address);

					/* format error */
					build_reply(	&sreply, so, pbuf, len, NULL, 
									from, fromlen, NULL, NULL, aregion, 
									istcp, 0, NULL, replybuf);

					slen = reply_fmterror(&sreply);
					dolog(LOG_INFO, "TCP question on descriptor %d interface \"%s\" from %s, did not have question of 1 replying format error\n", so, cfg->ident[i], address);
					goto drop;
				}
					
				if ((question = build_question(pbuf, len, ntohs(dh->additional))) == NULL) {
					dolog(LOG_INFO, "TCP packet on descriptor %u interface \"%s\" malformed question from %s, drop\n", so, cfg->ident[i], address);
					goto drop;
				}
				/* goto drop beyond this point should goto out instead */
				fakequestion = NULL;

				/*
				 * we check now for AXFR's in the query and deny if not found
				 * in our list of AXFR'ers
				 */

				switch (ntohs(question->hdr->qtype)) {
				case DNS_TYPE_AXFR:
				case DNS_TYPE_IXFR:
					if (! axfr_acl) {
						dolog(LOG_INFO, "AXFR connection from %s on interface \"%s\" was not in our axfr acl, drop\n", address, cfg->ident[i]);
							
						snprintf(replystring, DNS_MAXNAME, "DROP");
						goto tcpout;
					}
					break;
				default:
					break;
				}

				sd0 = lookup_zone(cfg->db, question, &type0, &lzerrno, (char *)&replystring);
				if (type0 < 0) {
	
					switch (lzerrno) {
					default:
						dolog(LOG_INFO, "invalid lzerrno! dropping\n");
						/* FALLTHROUGH */
					case ERR_DROP:
						snprintf(replystring, DNS_MAXNAME, "DROP");
						goto tcpout;

					case ERR_REFUSED:
						if (ntohs(question->hdr->qclass) == DNS_CLASS_CH &&
							ntohs(question->hdr->qtype) == DNS_TYPE_TXT &&
								strcasecmp(question->converted_name, "version.bind.") == 0) {
								snprintf(replystring, DNS_MAXNAME, "VERSION");
								build_reply(&sreply, so, pbuf, len, question, from, fromlen, NULL, NULL, aregion, istcp, 0, NULL, replybuf);
								slen = reply_version(&sreply);
								goto tcpout;
						}
						snprintf(replystring, DNS_MAXNAME, "REFUSED");
						build_reply(&sreply, so, pbuf, len, question, from, fromlen, sd0, NULL, aregion, istcp, 0, NULL, replybuf);
						slen = reply_refused(&sreply);
						goto tcpout;
						break;
					case ERR_NXDOMAIN:
						/* check if our question is for an ENT */
						if (check_ent(question->hdr->name, question->hdr->namelen) == 1) {
							if (dnssec) {
								goto tcpnoerror;
							} else {
								snprintf(replystring, DNS_MAXNAME, "NODATA");
								build_reply(&sreply, so, pbuf, len, question, from, fromlen, sd0, NULL, aregion, istcp, 0, NULL, replybuf);
								slen = reply_nodata(&sreply);
								goto tcpout;
								break;
							}	
						} else {
							goto tcpnxdomain;
						}
					case ERR_NOERROR:
						/*
 						 * this is hackish not sure if this should be here
						 */

tcpnoerror:
						snprintf(replystring, DNS_MAXNAME, "NOERROR");

						/*
						 * lookup an authoritative soa
						 */

						if (sd0) {
							free(sd0);
							sd0 = NULL;
						}

						sd0 = get_soa(cfg->db, question);
						if (sd0 != NULL) {

								build_reply(	&sreply, so, pbuf, len, 
												question, from, fromlen, 
												sd0, NULL, aregion, istcp, 
												0, NULL, replybuf);

								slen = reply_noerror(&sreply, cfg->db);
						}
						goto tcpout;

					}
				}

				switch (type0) {
				case 0:
					/* check for ents */
					if (check_ent(question->hdr->name, question->hdr->namelen) == 1) {
						if (dnssec) {
							goto tcpnoerror;
						} else {
							snprintf(replystring, DNS_MAXNAME, "NODATA");
							build_reply(&sreply, so, pbuf, len, question, from, fromlen, sd0, NULL, aregion, istcp, 0, NULL, replybuf);
							slen = reply_nodata(&sreply);
							goto tcpout;
						}	
					}


					/*
					 * lookup_zone could not find an RR for the
					 * question at all -> nxdomain
					 */
tcpnxdomain:
					snprintf(replystring, DNS_MAXNAME, "NXDOMAIN");

					/* 
					 * lookup an authoritative soa 
					 */
					if (sd0 != NULL) {
			
							build_reply(	&sreply, so, pbuf, len, question, 
											from, fromlen, sd0, NULL, 
											aregion, istcp, 0, NULL,
											replybuf);

							slen = reply_nxdomain(&sreply, cfg->db);
					}
					goto tcpout;
				case DNS_TYPE_CNAME:
					csd = (struct domain_cname *)find_substruct(sd0, INTERNAL_TYPE_CNAME);
					fakequestion = build_fake_question(csd->cname, csd->cnamelen, question->hdr->qtype);
					if (fakequestion == NULL) {	
						dolog(LOG_INFO, "fakequestion failed\n");
						break;
					}

					sd1 = lookup_zone(cfg->db, fakequestion, &type1, &lzerrno, (char *)&fakereplystring);
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

					slen = reply_notimpl(&sreply);
					snprintf(replystring, DNS_MAXNAME, "NOTIMPL");
					goto tcpout;
				}
		
				switch (ntohs(question->hdr->qtype)) {
				case DNS_TYPE_IXFR:
					/* FALLTHROUGH */
				case DNS_TYPE_AXFR:
					dolog(LOG_INFO, "composed AXFR message to axfr process\n");
					imsg_compose(ibuf[MY_IMSG_AXFR], IMSG_XFR_MESSAGE, 0, 0, so, buf, len + 2);
					msgbuf_write(&ibuf[MY_IMSG_AXFR]->w);
					close(so);
					continue;
					break;
				case DNS_TYPE_A:
					if (type0 == DNS_TYPE_CNAME) {
						build_reply(&sreply, so, pbuf, len, question, from, 	\
							fromlen, sd0, ((type1 > 0) ? sd1 : NULL), \
							aregion, istcp, 0, NULL, replybuf);
						slen = reply_cname(&sreply);
					} else if (type0 == DNS_TYPE_NS) {

						build_reply(&sreply, so, pbuf, len, question, 
									from, fromlen, sd0, NULL, 
									aregion, istcp, 0, NULL,
									replybuf);

						slen = reply_ns(&sreply, cfg->db);
						break;
					} else if (type0 == DNS_TYPE_A) {
						build_reply(&sreply, so, pbuf, len, question, from, \
							fromlen, sd0, NULL, aregion, istcp, 0, 
							NULL, replybuf);
						slen = reply_a(&sreply, cfg->db);
						break;		/* must break here */
					}

					break;

				case DNS_TYPE_ANY:
					build_reply(&sreply, so, pbuf, len, question, from, \
						fromlen, sd0, NULL, aregion, istcp, 0, 
						NULL, replybuf);

					slen = reply_any(&sreply);
					break;		/* must break here */
				case DNS_TYPE_NSEC3PARAM:
					build_reply(&sreply, so, pbuf, len, question, from, \
						fromlen, sd0, NULL, aregion, istcp, 0, 
						NULL, replybuf);

					slen = reply_nsec3param(&sreply);
					break;		/* must break here */
					
				case DNS_TYPE_NSEC3:
					build_reply(&sreply, so, pbuf, len, question, from, \
						fromlen, sd0, NULL, aregion, istcp, 0, 
						NULL, replybuf);

					slen = reply_nxdomain(&sreply, cfg->db);
					break;		/* must break here */
					
				case DNS_TYPE_DS:
					build_reply(&sreply, so, pbuf, len, question, from, \
						fromlen, sd0, NULL, aregion, istcp, 0, 
						NULL, replybuf);

					slen = reply_ds(&sreply);
					break;		/* must break here */
					
				case DNS_TYPE_DNSKEY:
					build_reply(&sreply, so, pbuf, len, question, from, \
						fromlen, sd0, NULL, aregion, istcp, 0, 
						NULL, replybuf);

					slen = reply_dnskey(&sreply);
					break;		/* must break here */
					
				case DNS_TYPE_RRSIG:
					build_reply(&sreply, so, pbuf, len, question, from, \
						fromlen, sd0, NULL, aregion, istcp, 0, 
						NULL, replybuf);

					slen = reply_rrsig(&sreply, cfg->db);
					break;		/* must break here */
					
				case DNS_TYPE_AAAA:
					
					if (type0 == DNS_TYPE_CNAME) {
						build_reply(&sreply, so, pbuf, len, question, from, \
							fromlen, sd0, ((type1 > 0) ? sd1 : NULL), \
							aregion, istcp, 0, NULL, replybuf);
						slen = reply_cname(&sreply);
					} else if (type0 == DNS_TYPE_NS) {
						build_reply(&sreply, so, pbuf, len, question, from, \
							fromlen, sd0, NULL, aregion, istcp, 
							0, NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);
						break;
					 } else if (type0 == DNS_TYPE_AAAA) {
						build_reply(&sreply, so, pbuf, len, question, from, 
							fromlen, sd0, NULL, aregion, istcp, 
							0, NULL, replybuf);

						slen = reply_aaaa(&sreply, cfg->db);
						break;		/* must break here */
					}

					break;
				case DNS_TYPE_MX:
					
					if (type0 == DNS_TYPE_CNAME) {
						build_reply(&sreply, so, pbuf, len, question, from, \
							fromlen, sd0, ((type1 > 0) ? sd1 : NULL), \
							aregion, istcp, 0, NULL, replybuf);

						slen = reply_cname(&sreply);

					} else if (type0 == DNS_TYPE_NS) {
						build_reply(&sreply, so, pbuf, len, question, from, \
							fromlen, sd0, NULL, aregion, istcp, 
							0, NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);

						break;
					} else if (type0 == DNS_TYPE_MX) {
						build_reply(&sreply, so, pbuf, len, question, from,  \
							fromlen, sd0, NULL, aregion, istcp, 
							0, NULL, replybuf);

						slen = reply_mx(&sreply, cfg->db);
						break;		/* must break here */
					}

					break;
				case DNS_TYPE_SOA:
					if (type0 == DNS_TYPE_SOA) {
						build_reply(&sreply, so, pbuf, len, question, from, \
							fromlen, sd0, NULL, aregion, istcp, 
							0, NULL, replybuf);

						slen = reply_soa(&sreply);
					} else if (type0 == DNS_TYPE_NS) {
						build_reply(&sreply, so, pbuf, len, question, from, \
							fromlen, sd0, NULL, aregion, istcp, 
							0, NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);
						break;
					}
					break;
				case DNS_TYPE_NS:
					if (type0 == DNS_TYPE_NS) {
						build_reply(&sreply, so, pbuf, len, question, from,  \
							fromlen, sd0, NULL, aregion, istcp, 
							0, NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);
					}
					break;

				case DNS_TYPE_TLSA:
					if (type0 == DNS_TYPE_TLSA) {
						build_reply(&sreply, so, pbuf, len, question, from,  \
							fromlen, sd0, NULL, aregion, istcp, 
							0, NULL, replybuf);

						slen = reply_tlsa(&sreply);
					}
					break;

				case DNS_TYPE_SSHFP:
					if (type0 == DNS_TYPE_SSHFP) {
						build_reply(&sreply, so, pbuf, len, question, from,  \
							fromlen, sd0, NULL, aregion, istcp, 
							0, NULL, replybuf);

						slen = reply_sshfp(&sreply);
					}
					break;


				case DNS_TYPE_SRV:
					if (type0 == DNS_TYPE_SRV) {
						build_reply(&sreply, so, pbuf, len, question, from,  \
							fromlen, sd0, NULL, aregion, istcp, 
							0, NULL, replybuf);

						slen = reply_srv(&sreply, cfg->db);
					}
					break;

				case DNS_TYPE_NAPTR:
					if (type0 == DNS_TYPE_NAPTR) {
						build_reply(&sreply, so, pbuf, len, question, from,  \
							fromlen, sd0, NULL, aregion, istcp, 
							0, NULL, replybuf);

						slen = reply_naptr(&sreply, cfg->db);
					}
					break;

				case DNS_TYPE_CNAME:
					if (type0 == DNS_TYPE_CNAME) {
						build_reply(&sreply, so, pbuf, len, question, from, \
							fromlen, sd0, NULL, aregion, istcp, 
							0, NULL, replybuf);

						slen = reply_cname(&sreply);
					} else if (type0 == DNS_TYPE_NS) {
						build_reply(&sreply, so, pbuf, len, question, from, \
							fromlen, sd0, NULL, aregion, istcp, 
							0, NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);
						break;
					}
					break;

				case DNS_TYPE_PTR:
					if (type0 == DNS_TYPE_CNAME) {
						build_reply(&sreply, so, pbuf, len, question, from, \
							fromlen, sd0, ((type1 > 0) ? sd1 : NULL) \
							, aregion, istcp, 0, NULL,
							replybuf);

						slen = reply_cname(&sreply);

					} else if (type0 == DNS_TYPE_NS) {

						build_reply(&sreply, so, pbuf, len, question, from, \
							fromlen, sd0, NULL, aregion, istcp, 
							0, NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);

						break;
					} else if (type0 == DNS_TYPE_PTR) {

						build_reply(&sreply, so, pbuf, len, question, from, 	
								fromlen, sd0, NULL, aregion, istcp, 
								0, NULL, replybuf);

						slen = reply_ptr(&sreply);
						break;		/* must break here */
					}
					break;

				case DNS_TYPE_TXT:
					if (type0 == DNS_TYPE_TXT) {

						build_reply(&sreply, so, pbuf, len, question, from,  \
							fromlen, sd0, NULL, aregion, istcp, 
							0, NULL, replybuf);

						slen = reply_txt(&sreply);
					}
					break;

				default:

					/*
					 * ANY unknown RR TYPE gets a NOTIMPL
					 */

					/*
					 * except for delegations 
					 */
					
					if (type0 == DNS_TYPE_NS) {
						build_reply(&sreply, so, pbuf, len, question, from, \
							fromlen, sd0, NULL, aregion, istcp, 
							0, NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);

					} else {

						build_reply(&sreply, so, pbuf, len, question, from, \
						fromlen, NULL, NULL, aregion, istcp, 
						0, NULL, replybuf);
		
						slen = reply_notimpl(&sreply);
						snprintf(replystring, DNS_MAXNAME, "NOTIMPL");
					}
					break;
				}
			
		tcpout:
				if (lflag)
					dolog(LOG_INFO, "request on descriptor %u interface \"%s\" from %s (ttl=TCP, region=%d) for \"%s\" type=%s class=%u, %s%s answering \"%s\" (%d/%d)\n", so, cfg->ident[i], address, aregion, question->converted_name, get_dns_type(ntohs(question->hdr->qtype), 1), ntohs(question->hdr->qclass), (question->edns0len) ? "edns0, " : "", (question->dnssecok) ? "dnssecok, " : "", replystring, len, slen);


				if (fakequestion != NULL) {
					free_question(fakequestion);
				}
	
				free_question(question);
				
				if (sd0) {
					free(sd0);
					sd0 = NULL;
				}
				if (sd1) {
					free (sd1);
					sd1 = NULL;
				}

				close(so);
			}	/* END ISSET */
		} /* for (i = 0;;)... */
	drop:
		
		if (sd0) {	
			free(sd0);
			sd0 = NULL;
		}

		if (sd1) {
			free(sd1);
			sd1 = NULL;
		}

		close(so);

		continue;
	}  /* for (;;) */

	/* NOTREACHED */
}
