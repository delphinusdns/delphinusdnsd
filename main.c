/* 
 * Copyright (c) 2002-2015 Peter J. Philipp
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
#include "config.h"

/* prototypes */

extern void 	add_rrlimit(int, u_int16_t *, int, char *);
extern void 	axfrloop(int *, int, char **, DB *);
extern int 	check_rrlimit(int, u_int16_t *, int, char *);
extern void 	collects_init(void);
extern void 	dolog(int, char *, ...);
extern int 	find_filter(struct sockaddr_storage *, int);
extern int 	find_recurse(struct sockaddr_storage *, int);
extern u_int8_t find_region(struct sockaddr_storage *, int);
extern int 	find_whitelist(struct sockaddr_storage *, int);
extern int 	find_wildcard(struct sockaddr_storage *, int);
extern void 	init_wildcard(void);
extern void 	init_recurse(void);
extern void 	init_region(void);
extern void 	init_filter(void);
extern void 	init_notifyslave(void);
extern void 	init_whitelist(void);
extern void 	recurseloop(int sp, int *, DB *);
extern void 	receivelog(char *, int);
extern int 	reply_a(struct sreply *, DB *);
extern int 	reply_aaaa(struct sreply *, DB *);
extern int 	reply_any(struct sreply *);
extern int 	reply_cname(struct sreply *);
extern int 	reply_fmterror(struct sreply *);
extern int 	reply_notimpl(struct sreply *);
extern int 	reply_nxdomain(struct sreply *);
extern int 	reply_noerror(struct sreply *);
extern int 	reply_soa(struct sreply *);
extern int 	reply_mx(struct sreply *, DB *);
extern int 	reply_naptr(struct sreply *, DB *);
extern int 	reply_ns(struct sreply *, DB *);
extern int 	reply_ptr(struct sreply *);
extern int 	reply_refused(struct sreply *);
extern int 	reply_spf(struct sreply *);
extern int 	reply_srv(struct sreply *, DB *);
extern int 	reply_sshfp(struct sreply *);
extern int 	reply_txt(struct sreply *);
extern int      reply_rrsig(struct sreply *, DB *);
extern int	reply_dnskey(struct sreply *);
extern int 	remotelog(int, char *, ...);
extern char 	*rrlimit_setup(int);

struct question		*build_fake_question(char *, int, u_int16_t);
struct question		*build_question(char *, int, int);
void 			build_reply(struct sreply *, int, char *, int, struct question *, struct sockaddr *, socklen_t, struct domain *, struct domain *, u_int8_t, int, int, struct recurses *, char *);
int 			compress_label(u_char *, u_int16_t, int);
u_int16_t		check_qtype(struct domain *, u_int16_t, int, int *);
char 			*dns_label(char *, int *);
int			free_question(struct question *);
char 			*get_dns_type(int dnstype);
struct domain * 	get_soa(DB *, struct question *);
int			lookup_type(int);
struct domain * 	lookup_zone(DB *, struct question *, int *, int *, char *);
int 			get_record_size(DB *, char *, int);
void *			find_substruct(struct domain *, u_int16_t);
void			mainloop(struct cfg *);
void 			master_reload(int);
void 			master_shutdown(int);
int 			memcasecmp(u_char *, u_char *, int);
void 			recurseheader(struct srecurseheader *, int, struct sockaddr_storage *, struct sockaddr_storage *, int);
void 			setup_master(DB *, DB_ENV *, char **);
void 			slave_signal(int);
void 			slave_shutdown(void);

/* aliases */

#ifndef DEFAULT_PRIVILEGE
#define DEFAULT_PRIVILEGE "_ddd"
#endif

#define PIDFILE "/var/run/delphinusdnsd.pid"
#define MYDB_PATH "/var/db/delphinusdns"


struct typetable {
	char *type;
	int number;
} TT[] = {
	{ "A", DNS_TYPE_A},
	{ "NS", DNS_TYPE_NS},
	{ "CNAME", DNS_TYPE_CNAME},
	{ "SOA", DNS_TYPE_SOA},
	{ "PTR", DNS_TYPE_PTR},
	{ "MX", DNS_TYPE_MX},
	{ "TXT", DNS_TYPE_TXT},
	{ "AAAA", DNS_TYPE_AAAA},
	{ "ANY", DNS_TYPE_ANY },
	{ "SRV", DNS_TYPE_SRV },
	{ "SPF", DNS_TYPE_SPF },
	{ "SSHFP", DNS_TYPE_SSHFP },
	{ "NAPTR", DNS_TYPE_NAPTR },
	{ "RRSIG", DNS_TYPE_RRSIG },
	{ "DNSKEY", DNS_TYPE_DNSKEY },
	{ NULL, 0}
};


/* global variables */

extern char *__progname;
extern struct logging logging;
extern int axfrport;
extern int ratelimit;
extern int ratelimit_packets_per_second;
extern int whitelist;

static int *ptr = NULL;
static int reload = 0;
static int mshutdown = 0;
static int msig;
static char *database;
static char mydatabase[512];
static char *rptr;
static int ratelimit_backlog;

int debug = 0;
int verbose = 0;
int bflag = 0;
int iflag = 0;
int lflag = 0;
int nflag = 0;
int rflag = 0;
int bcount = 0;
int icount = 0;
u_int16_t port = 53;
u_int32_t cachesize = 0;
char *bind_list[255];
char *interface_list[255];

/* singly linked list for tcp operations */
SLIST_HEAD(listhead, tcps) tcpshead;

static struct tcps {
	char *input;
	char *ident;
	char *address;
	int offset;
	int length;
	int maxlen;
	int so;
	int isv6;
	u_int8_t region;
	int wildcard;
	time_t time;
	SLIST_ENTRY(tcps) tcps_entry;
} *tn1, *tnp, *tntmp;


static const char rcsid[] = "$Id: main.c,v 1.12 2015/06/24 05:00:28 pjp Exp $";

/* 
 * MAIN - set up arguments, set up database, set up sockets, call mainloop
 *
 */

int
main(int argc, char *argv[])
{
	static int udp[DEFAULT_SOCKET];
	static int tcp[DEFAULT_SOCKET];
	static int afd[DEFAULT_SOCKET];
	static int uafd[DEFAULT_SOCKET];
	int raw[2];
	int lfd = -1;
	int fd, n;

	int ch, i, j;
	int gai_error;
	int salen, ret;
	int found = 0;
	int on = 1;
	int sp[2];

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

	static DB_ENV *dbenv;
	static DB *db;
	
	key_t key;

	if (geteuid() != 0) {
		fprintf(stderr, "must be started as root\n"); /* .. dolt */
		exit(1);
	}

	av = argv;

	while ((ch = getopt(argc, argv, "b:c:df:i:ln:p:rv")) != -1) {
		switch (ch) {
		case 'b':
			bflag = 1;
			if (bcount > 253) {
				fprintf(stderr, "too many -b flags\n");
				exit(1);
			}
			bind_list[bcount++] = optarg;	
			break;
		case 'c':
#if !defined __OpenBSD__ 
			cachesize = atoi(optarg);
#else
			cachesize = strtonum(optarg, 1, 0xffffffff, NULL);
#endif
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
		case 'r':
			rflag = 1;
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
	
	if ((ret = db_env_create(&dbenv, 0)) != 0) {
		dolog(LOG_INFO, "db_env_create: %s\n", db_strerror(ret));
		slave_shutdown();
		exit(1);
	}

	key = ftok("/usr/local/sbin/delphinusdnsd", 1);
	if (key == (key_t)-1) {
		dolog(LOG_INFO, "ftok failed, does /usr/local/sbin/delphinusdnsd exist?\n");
		slave_shutdown();
		exit(1);
	}
		

	if ((ret = dbenv->set_shm_key(dbenv, key)) != 0) {
		dolog(LOG_INFO, "dbenv->set_shm_key failed\n");
		slave_shutdown();
		exit(1);
	}

	/* set cache size , if requested */

	if (cachesize) {
		if ((ret = dbenv->set_cachesize(dbenv, 0, cachesize, 0)) != 0) {
			dolog(LOG_INFO, "dbenv->set_cachesize: %s\n", 
				db_strerror(ret));
			slave_shutdown();
			exit(1);
		}
	}

	(void)mkdir(MYDB_PATH, 0700);
	snprintf(mydatabase, sizeof(mydatabase), "%s/%ld", 
		MYDB_PATH, (long)getpid());

	if (mkdir(mydatabase, 0750) < 0) {
		if (errno != EEXIST) {
			dolog(LOG_ERR, "mkdir: %s\n", strerror(errno));
			exit(1);
		}
	}

	if ((ret = dbenv->open(dbenv, mydatabase, DB_CREATE | \
		DB_INIT_LOCK | DB_INIT_MPOOL | DB_SYSTEM_MEM, \
		S_IRUSR | S_IWUSR)) != 0) {
		dolog(LOG_INFO, "dbenv->open failed: %s\n", db_strerror(ret));
		slave_shutdown();
		exit(1);
	}

        if (db_create((DB **)&db, (DB_ENV *)dbenv, 0) != 0) {
                dolog(LOG_INFO, "db_create: %s\n", strerror(errno));
		slave_shutdown();
                exit(1);
        }

	/* 
	 * we want to run multiple instances of different versions so we'll
	 * make a temporary database...
	 */


	snprintf(mydatabase, sizeof(mydatabase), "%s/%ld/ddd.db", 
		MYDB_PATH, (long)getpid());

	(void)unlink(mydatabase);

	database = mydatabase;


	fd = open(database, O_WRONLY | O_CREAT, 0600);
	if (fd < 0) {
		dolog(LOG_INFO, "open: %s\n", strerror(errno));
	}
	close(fd);

        if (db->open(db, NULL, database, NULL, DB_BTREE, DB_CREATE, 0600) != 0) {
                dolog(LOG_INFO, "db->open: %s\n", strerror(errno));
                db->close(db, DB_NOSYNC);
		slave_shutdown();
                exit(1);
        }

	/* make a master program that holds the pidfile, boss of ... eek */

	pid = fork();
	switch (pid) {
	case -1:
		dolog(LOG_ERR, "fork(): %s\n", strerror(errno));
		exit(1);
	case 0:
		break;
	default:
		setup_master(db, dbenv, av);
		/* NOTREACHED */
		exit(1);
	}

	/* end of setup_master code */
		
	init_wildcard();
	init_region();
	init_filter();
	init_whitelist();
	init_notifyslave();

	if (parse_file(db, conffile) < 0) {
		dolog(LOG_INFO, "parsing config file failed\n");
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

			if (axfrport) {
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
			if (axfrport) {
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

	if (rflag == 1) {
		if ((raw[0] = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
			dolog(LOG_INFO, "raw socket: %s\n", strerror(errno));
			slave_shutdown();
			exit(1);
		}

		if (setsockopt(raw[0], IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
			dolog(LOG_INFO, "raw setsockopt: %s\n", strerror(errno));
			slave_shutdown();
			exit(1);	
		}

		if ((raw[1] = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP)) < 0) {
			dolog(LOG_INFO, "raw socket[1]: %s\n", strerror(errno));
			slave_shutdown();
			exit(1);
		}
		
	} /* rflag */


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
		switch (pid = fork()) {
		case 0:
			/* close descriptors that we don't need */
			for (j = 0; j < i; j++) {
				close(tcp[j]);
				close(udp[j]);
				close(uafd[j]);
			}

			if (rflag) {
				close(raw[0]);
				close(raw[1]);
			}

#if !defined __linux__ && !defined __APPLE__
			setproctitle("AXFR engine on port %d", axfrport);
#endif

			axfrloop(afd, i, ident, db);
			/* NOTREACHED */
			exit(1);
		default:
			/* close afd descriptors, they aren't needed here */
			for (j = 0; j < i; j++) {
				close(afd[j]);
			}

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
			if (rflag) {
					/* 
					 * set up socket pair
					 */
					
					if (socketpair(AF_UNIX, SOCK_DGRAM, 0, (int *)&sp) < 0) {
						dolog(LOG_INFO, "socketpair: %s\n", strerror(errno));
						slave_shutdown();
						exit(1);
					}
			
					switch (pid = fork()) {
					case -1:
						dolog(LOG_INFO, "fork: %s\n", strerror(errno));
						slave_shutdown();
						exit(1);

					case 0:	
						for (j = 0; j < i; j++) {
							close(tcp[j]);
							close(udp[j]);
						}
						close (sp[1]);	

						/* NOTREACHED */
						break;

					default:
						close(raw[0]);
						close(raw[1]);
						close (sp[0]);
						break;
					} /* switch */
				}	/* rflag */

			
			cfg->sockcount = i;
			cfg->db = db;
			for (i = 0; i < cfg->sockcount; i++) {
				cfg->udp[i] = udp[i];
				cfg->tcp[i] = tcp[i];

				if (axfrport)
					cfg->axfr[i] = uafd[i];

				cfg->ident[i] = strdup(ident[i]);
			}
			cfg->recurse = (rflag ? sp[1] : -1);
			cfg->log = lfd;

			
			(void)mainloop(cfg);

			/* NOTREACHED */
		default:	
			break;
		} /* switch pid= fork */
	} /* for (.. nflag */

	if (rflag) {
			/* 
			 * set up socket pair
			 */
			
			if (socketpair(AF_UNIX, SOCK_DGRAM, 0, (int *)&sp) < 0) {
				dolog(LOG_INFO, "socketpair: %s\n", strerror(errno));
				slave_shutdown();
				exit(1);
			}
	
			switch (pid = fork()) {
			case -1:
				dolog(LOG_INFO, "fork: %s\n", strerror(errno));
				slave_shutdown();
				exit(1);

			case 0:	
				for (j = 0; j < i; j++) {
					close(tcp[j]);
					close(udp[j]);
					close(uafd[j]);
				}
				close (sp[1]);	

				/* NOTREACHED */
				break;

			default:
				close(raw[0]);
				close(raw[1]);
				close (sp[0]);
				break;
			} /* switch */
			
	}	/* rflag */

	
	cfg->sockcount = i;
	cfg->db = db;
	for (i = 0; i < cfg->sockcount; i++) {
		cfg->udp[i] = udp[i];
		cfg->tcp[i] = tcp[i];

		if (axfrport)
			cfg->axfr[i] = uafd[i];

		cfg->ident[i] = strdup(ident[i]);
	}
	cfg->log = lfd;


	(void)mainloop(cfg);

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
	int num_label;

	char *p, *end_name = NULL;

	struct dns_optrr *opt = NULL;
	struct question *q = NULL;

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

		/* if we got options here I don't want to know about them */
		if (ntohs(opt->rdlen) > 0)
			break;

		/* RFC 3225 */
		if (ntohl(opt->ttl) & DNSSEC_OK)
			q->dnssecok = 1;
		else if (ntohl(opt->ttl) != 0)
			break;

		q->edns0len = ntohs(opt->class);
		if (q->edns0len < 512)
			q->edns0len = 512;	/* RFC 6891 - page 10 */

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
 * DNS_LABEL - build a DNS NAME (with labels) from a canonical name
 * 
 */

char *
dns_label(char *name, int *returnlen)
{
	int len, newlen = 0;
	int i, lc = 0;			/* lc = label count */

	char *dnslabel, *p;
	char *labels[255];
	char **pl;
	char tname[DNS_MAXNAME + 1];	/* 255 bytes  + 1*/
	char *pt = &tname[0];


	if (name == NULL) 
		return NULL;

#if __linux__
	strncpy(tname, name, sizeof(tname));
	tname[sizeof(tname) - 1] = 0;
#else
	strlcpy(tname, name, sizeof(tname));
#endif

	len = strlen(tname);
	if (tname[len - 1] == '.') 
		tname[len - 1] = '\0';

	for (pl=labels;pl<&labels[254]&&(*pl=strsep(&pt,"."))!= NULL;pl++,lc++)
		newlen += strlen(*pl);

	newlen += lc;			/* add label count to length */


	/* make the buffer space, add 1 for trailing NULL */
	if ((dnslabel = malloc(newlen + 1)) == NULL) {
		return NULL;
	}

	*returnlen = newlen + 1;
	dnslabel[newlen] = '\0';	/* trailing NULL */

	for (i = 0, p = dnslabel; i < lc; i++) {
		len = strlen(labels[i]);
		*p++ = len;
#if __linux__
		/* XXX */
		strncpy(p, labels[i], newlen - (p - dnslabel) + 1);
		p[newlen - (p - dnslabel)] = 0;
#else
		strlcpy(p, labels[i], newlen - (p - dnslabel) + 1);
#endif
		p += len;
	}

	/*
	 * XXX hack to make all DNS names lower case, we only preserve
	 * case on compressed answers..
	 */

	for (i = 0, p = dnslabel; i < *returnlen; i++) {
		int c;
		
		c = *p;
		if (isalpha(c))
			*p = tolower(c);
		p++;
	}

	dolog(LOG_DEBUG, "converting name= %s\n", name);

	return dnslabel;
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
		case DNS_TYPE_SPF:
			p += *p;
			p++;
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
 * MEMCASECMP - 	check if buffer is identical to another buffer with 
 *			one exception if a character is alphabetic it's 
 *			compared to it's lower case value so that heLLo is 
 * 			the same as hello
 */

int
memcasecmp(u_char *b1, u_char *b2, int len)
{
	int i;
	int identical = 1;

	for (i = 0; i < len; i++) {
		int c0, c1;
	
		c0 = b1[i];
		c1 = b2[i];

		if ((isalpha(c0) ? tolower(c0) : c0) != 
			(isalpha(c1) ? tolower(c1) : c1)) {
			identical = 0;
			break;
		}
	}

	if (identical) 
		return 0;

	return 1;	/* XXX */
}
	

/*
 * LOOKUP_ZONE - look up a zone filling sd and returning RR TYPE, if error
 *		 occurs returns -1, and sets errno on what type of error.
 */


struct domain *
lookup_zone(DB *db, struct question *question, int *returnval, int *lzerrno, char *replystring)
{

	struct domain *sd = NULL;
	struct domain_ns *nsd;
	int plen, onemore = 0;
	int ret = 0;
	int error;
	int w = 0;
	int rs;

	char *p;
	
	DBT key, data;

	p = question->hdr->name;
	plen = question->hdr->namelen;
	onemore = 0;


	rs = get_record_size(db, p, plen);
	if (rs < 0) {
		*lzerrno = ERR_DROP;
		*returnval = -1;
		return (NULL);
	}
	if ((sd = (struct domain *)calloc(1, rs)) == NULL) {
		*lzerrno = ERR_DROP; /* only free on ERR_DROP */
		*returnval = -1;
		return (NULL);	
	}

	*returnval = 0;

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	key.data = (char *)p;
	key.size = plen;

	data.data = NULL;
	data.size = rs;

	ret = db->get(db, NULL, &key, &data, 0);
	if (ret != 0) {
		*lzerrno = ERR_NXDOMAIN;
		*returnval = -1;
		return (sd);
	}
	
	if (data.size != rs) {
		dolog(LOG_INFO, "btree db is damaged, drop\n");
		free(sd);
		sd = NULL;
		*lzerrno = ERR_DROP;	/* free on ERR_DROP */
		*returnval = -1;
		return (NULL);
	}

	memcpy((char *)sd, (char *)data.data, data.size);
	snprintf(replystring, DNS_MAXNAME, "%s", sd->zonename);


	if (sd->flags & DOMAIN_HAVE_NS) {
		nsd = (struct domain_ns *)find_substruct(sd, INTERNAL_TYPE_NS);
		if (w && nsd->ns_type == 0) {	
			*lzerrno = ERR_NXDOMAIN;
			*returnval = -1;
			return (sd);
		}

		/*
		 * we're of ns_type > 0, return an NS record
		 */

		if (nsd->ns_type > 0) {
			*returnval = DNS_TYPE_NS;
			*lzerrno = ERR_NOERROR;
			goto out;
		}
	}

	*returnval = check_qtype(sd, ntohs(question->hdr->qtype), 0, &error);
	if (*returnval == 0) {
		*lzerrno = ERR_NOERROR;
		*returnval = -1;
		return (sd);
	}

out:
	return(sd);
}

/*
 * BUILD_FAKE_QUESTION - fill the fake question structure with the DNS query.
 */

struct question *
build_fake_question(char *name, int namelen, u_int16_t type)
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
	q->hdr->namelen = namelen;
	q->hdr->name = (void *) calloc(1, q->hdr->namelen);
	if (q->hdr->name == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		free(q->hdr);
		free(q);
		return NULL;
	}
	q->converted_name = NULL;

	/* fill our name into the dns header struct */
	
	memcpy(q->hdr->name, name, q->hdr->namelen);
	
	q->hdr->qtype = type;
	q->hdr->qclass = htons(DNS_CLASS_IN);

	return (q);
}

/*
 * GET_SOA - get authoritative soa for a particular domain
 */

struct domain *
get_soa(DB *db, struct question *question)
{
	struct domain *sd = NULL;

	int plen;
	int ret = 0;
	int wildcard = 0;
	int rs;
	
	DBT key, data;

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

		ret = db->get(db, NULL, &key, &data, 0);
		if (ret != 0) {
			/*
			 * If we're not wildcarding end the search here and
			 * return with -1 
			 */
			if (! wildcard) 
				return (NULL);

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
 * GET_DNS_TYPE - take integer and compare to table, then spit back a static
 * 		  string with the result.  This function can't fail.
 */

char *
get_dns_type(int dnstype)
{
	static char type[128];
	struct typetable *t;

	t = TT;

	while (t->type != NULL) {
		if (dnstype == t->number)
			break;	
	
		t = (t + 1);
	}

	if (t->type == NULL) {
		snprintf(type, sizeof(type) - 1, "%u", dnstype);
	} else
		snprintf(type, sizeof(type) - 1, "%s(%u)", t->type, dnstype);

	return (type);	
}	

/*
 * MAINLOOP - does the polling of tcp & udp descriptors and if ready receives the 
 * 		requests, builds the question and calls for replies, loops
 *
 */
		
void
mainloop(struct cfg *cfg)
{
	fd_set rset;
	int sel;
	int len, slen;
	int is_ipv6;
	int i;
	int istcp = 1;
	int maxso;
	int so;
	int type0, type1;
	int lzerrno;
	int wildcard = 0;
	int filter = 0;
	int rcheck = 0;
	int blacklist = 1;
	int sp; 
	int lfd;

       u_int32_t received_ttl;
#if defined __FreeBSD__ || defined __OpenBSD__
	u_char *ttlptr;
#else
	int *ttlptr;
#endif

	u_int8_t aregion;			/* region where the address comes from */

	char *pbuf;
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
	socklen_t namelen = sizeof(struct sockaddr_storage);
	socklen_t logfromlen = sizeof(struct sockaddr_storage);

	struct sockaddr *from = (void *)&sockaddr_large;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct sockaddr_storage sto;
	struct sockaddr_storage logfrom;

	struct dns_header *dh;
	struct question *question, *fakequestion;
	struct domain *sd0 = NULL, *sd1 = NULL;
	struct domain_cname *csd;
	
	struct sreply sreply;
	struct srecurseheader rh;
	struct timeval tv = { 10, 0};

	struct msghdr msgh;
	struct cmsghdr *cmsg;
	struct iovec iov;
	
	int flag;
	int recursion = 0;


	SLIST_INIT(&tcpshead);
	collects_init();

	replybuf = calloc(1, 65536);
	if (replybuf == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		slave_shutdown();
		exit(1);
	 }


	sp = cfg->recurse;
	lfd = cfg->log;

	/* 
	 * set descriptors nonblocking, and listen on them
	 */

	for (i = 0; i < cfg->sockcount; i++) {
		listen(cfg->tcp[i], 5);
	}
	
	for (;;) {
		is_ipv6 = 0;
		maxso = 0;
		/* 
		 * check for timeouts 
		 */

#ifdef __linux__
		SLIST_FOREACH(tnp, &tcpshead, tcps_entry) {
#else
		SLIST_FOREACH_SAFE(tnp, &tcpshead, tcps_entry, tntmp) {
#endif
			if ((tnp->time + 10) < time(NULL)) {
				free(tnp->input);
				free(tnp->ident);
				free(tnp->address);
				close(tnp->so);
				SLIST_REMOVE(&tcpshead, tnp, tcps, tcps_entry);		
 				free(tnp);
			}
		}

		FD_ZERO(&rset);
		for (i = 0; i < cfg->sockcount; i++)  {
			if (maxso < cfg->tcp[i])
				maxso = cfg->tcp[i];
	
			if (maxso < cfg->udp[i])
				maxso = cfg->udp[i];

			if (axfrport && maxso < cfg->axfr[i])
				maxso = cfg->axfr[i];

			FD_SET(cfg->tcp[i], &rset);
			FD_SET(cfg->udp[i], &rset);

			if (axfrport)
				FD_SET(cfg->axfr[i], &rset);
		}
	
		SLIST_FOREACH(tnp, &tcpshead, tcps_entry) {
			if (maxso < tnp->so)
				maxso = tnp->so;

			FD_SET(tnp->so, &rset);
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
#ifdef __linux__
			SLIST_FOREACH(tnp, &tcpshead, tcps_entry) {
#else
			SLIST_FOREACH_SAFE(tnp, &tcpshead, tcps_entry, tntmp) {
#endif
				if ((tnp->time + 10) < time(NULL)) {
					free(tnp->input);
					free(tnp->ident);
					free(tnp->address);
					close(tnp->so);
					SLIST_REMOVE(&tcpshead, tnp, tcps, tcps_entry);		
					free(tnp);
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
					wildcard = find_wildcard((struct sockaddr_storage *)sin6, AF_INET6);
					filter = find_filter((struct sockaddr_storage *)sin6, AF_INET6);
					if (whitelist) {
						blacklist = find_whitelist((struct sockaddr_storage *)sin6, AF_INET6);
					}
				} else if (from->sa_family == AF_INET) {
					is_ipv6 = 0;
					
					fromlen = sizeof(struct sockaddr_in);
					sin = (struct sockaddr_in *)from;
					inet_ntop(AF_INET, (void *)&sin->sin_addr, (char *)&address, sizeof(address));
					wildcard = find_wildcard((struct sockaddr_storage *)sin, AF_INET);
					aregion = find_region((struct sockaddr_storage *)sin, AF_INET);
					filter = find_filter((struct sockaddr_storage *)sin, AF_INET);
					if (whitelist) {
						blacklist = find_whitelist((struct sockaddr_storage *)sin, AF_INET);
					}
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
				 * make this socket nonblocking 
				 */

				if ((flag = fcntl(so,  F_GETFL)) < 0) {
					dolog(LOG_INFO, "fcntl: %s\n", strerror(errno));
				}
				flag |= O_NONBLOCK;
				if (fcntl(so, F_SETFL, flag) < 0) {
					dolog(LOG_INFO, "fcntl 2: %s\n", strerror(errno));
				}


				/* fill the tcps struct */

				tn1 = malloc(sizeof(struct tcps));
				if (tn1 == NULL) {
					dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
					close(so);
					continue;
				}

				tn1->input = (char *)malloc(0xffff + 2);
				if (tn1->input == NULL) {
					dolog(LOG_INFO, "tcp malloc 2: %s\n", strerror(errno));
					close(so);
					continue;
				}	

				tn1->offset = 0;
				tn1->length = 0;
				tn1->maxlen = 0xffff + 2;
				tn1->so = so;
				tn1->isv6 = is_ipv6;	
				tn1->ident = strdup(cfg->ident[i]);
				tn1->address = strdup(address);
				tn1->region = aregion;
				tn1->wildcard = wildcard;
				tn1->time = time(NULL);

				SLIST_INSERT_HEAD(&tcpshead, tn1, tcps_entry);
	
			} /* FD_ISSET(); */
		} /* if sockcount */

#ifdef __linux__
		SLIST_FOREACH(tnp, &tcpshead, tcps_entry) {
#else
		SLIST_FOREACH_SAFE(tnp, &tcpshead, tcps_entry, tntmp) {
#endif
			if (FD_ISSET(tnp->so, &rset)) {
					
				istcp = 1;
				len = recv(tnp->so, tnp->input + tnp->offset, tnp->maxlen - tnp->offset, 0);
				if (len < 0) {
					if (errno == EWOULDBLOCK)
					continue;
					else {
						free(tnp->input);
						free(tnp->ident);
						free(tnp->address);
						close(tnp->so);
						SLIST_REMOVE(&tcpshead, tnp, tcps, tcps_entry);		
						free(tnp);
						continue;
					}
				} /* if len */

				if (len == 0) {
					free(tnp->input);
					free(tnp->ident);
					free(tnp->address);
					close(tnp->so);
					SLIST_REMOVE(&tcpshead, tnp, tcps, tcps_entry);		
					free(tnp);
					continue;
				}

				tnp->offset += len;
				tnp->time = time(NULL);

				if (tnp->offset >= 2) {	
					tnp->length = ntohs(*((u_int16_t *) tnp->input));
				}

				/*
				 * only go on if the full packet was written
				 */

				if (tnp->length + 2 != tnp->offset)
					continue;

				len = tnp->length;
				pbuf = tnp->input + 2;

				/* if UDP packet check length for minimum / maximum */
				if (len > DNS_MAXUDP || len < sizeof(struct dns_header)){
					dolog(LOG_INFO, "TCP packet on descriptor %u interface \"%s\" illegal dns packet length from %s, drop\n", tnp->so, tnp->ident, tnp->address);
					goto drop;
				}

				dh = (struct dns_header *)&pbuf[0];	

				/* check if we're a question or reply, drop replies */
				if ((ntohs(dh->query) & DNS_REPLY)) {
					dolog(LOG_INFO, "TCP packet on descriptor %u interface \"%s\" dns header from %s is not a question, drop\n", tnp->so, tnp->ident, tnp->address);
					goto drop;
				}

				/* 
				 * if questions aren't exactly 1 then drop
				 */

				if (ntohs(dh->question) != 1) {
					dolog(LOG_INFO, "TCP packet on descriptor %u interface \"%s\" header from %s has no question, drop\n", tnp->so, tnp->ident, tnp->address);

					/* format error */
					build_reply(	&sreply, tnp->so, pbuf, len, NULL, 
									from, fromlen, NULL, NULL, tnp->region, 
									istcp, tnp->wildcard, NULL, replybuf);

					slen = reply_fmterror(&sreply);
					dolog(LOG_INFO, "TCP question on descriptor %d interface \"%s\" from %s, did not have question of 1 replying format error\n", tnp->so, tnp->ident, tnp->address);
					goto drop;
				}
					

				if ((question = build_question(pbuf, len, ntohs(dh->additional))) == NULL) {
					dolog(LOG_INFO, "TCP packet on descriptor %u interface \"%s\" malformed question from %s, drop\n", tnp->so, tnp->ident, tnp->address);
					goto drop;
				}

				/* goto drop beyond this point should goto out instead */
				fakequestion = NULL;

				sd0 = lookup_zone(cfg->db, question, &type0, &lzerrno, (char *)&replystring);
				if (type0 < 0) {
	
					switch (lzerrno) {
					default:
						dolog(LOG_INFO, "invalid lzerrno! dropping\n");
						/* FALLTHROUGH */
					case ERR_DROP:
						snprintf(replystring, DNS_MAXNAME, "DROP");
						goto tcpout;

					case ERR_NXDOMAIN:
						goto tcpnxdomain;
					case ERR_NOERROR:
						/*
 						 * this is hackish not sure if this should be here
						 */

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

								build_reply(	&sreply, tnp->so, pbuf, len, 
												question, from, fromlen, 
												sd0, NULL, tnp->region, istcp, 
												tnp->wildcard, NULL, replybuf);

								slen = reply_noerror(&sreply);
						}
						goto tcpout;

					}
				}

				switch (type0) {
				case 0:
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
			
							build_reply(	&sreply, tnp->so, pbuf, len, question, 
											from, fromlen, sd0, NULL, 
											tnp->region, istcp, tnp->wildcard, NULL,
											replybuf);

							slen = reply_nxdomain(&sreply);
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
					 build_reply(	&sreply, tnp->so, pbuf, len, question, 
									from, fromlen, NULL, NULL, tnp->region, 
									istcp, tnp->wildcard, NULL, replybuf);

					slen = reply_notimpl(&sreply);
					snprintf(replystring, DNS_MAXNAME, "NOTIMPL");
					goto tcpout;
				}
		
				switch (ntohs(question->hdr->qtype)) {
				case DNS_TYPE_A:
					if (type0 == DNS_TYPE_CNAME) {
						build_reply(&sreply, tnp->so, pbuf, len, question, from, 	\
							fromlen, sd0, ((type1 > 0) ? sd1 : NULL), \
							tnp->region, istcp, tnp->wildcard, NULL, replybuf);
						slen = reply_cname(&sreply);
					} else if (type0 == DNS_TYPE_NS) {

						build_reply(&sreply, tnp->so, pbuf, len, question, 
									from, fromlen, sd0, NULL, 
									tnp->region, istcp, tnp->wildcard, NULL,
									replybuf);

						slen = reply_ns(&sreply, cfg->db);
						break;
					} else if (type0 == DNS_TYPE_A) {
						build_reply(&sreply, tnp->so, pbuf, len, question, from, \
							fromlen, sd0, NULL, tnp->region, istcp, tnp->wildcard, 
							NULL, replybuf);
						slen = reply_a(&sreply, cfg->db);
						break;		/* must break here */
					}

					break;

				case DNS_TYPE_ANY:
					build_reply(&sreply, tnp->so, pbuf, len, question, from, \
						fromlen, sd0, NULL, tnp->region, istcp, tnp->wildcard, 
						NULL, replybuf);

					slen = reply_any(&sreply);
					break;		/* must break here */
				case DNS_TYPE_DNSKEY:
					build_reply(&sreply, tnp->so, pbuf, len, question, from, \
						fromlen, sd0, NULL, tnp->region, istcp, tnp->wildcard, 
						NULL, replybuf);

					slen = reply_dnskey(&sreply);
					break;		/* must break here */
					
				case DNS_TYPE_RRSIG:
					build_reply(&sreply, tnp->so, pbuf, len, question, from, \
						fromlen, sd0, NULL, tnp->region, istcp, tnp->wildcard, 
						NULL, replybuf);

					slen = reply_rrsig(&sreply, cfg->db);
					break;		/* must break here */
					
				case DNS_TYPE_AAAA:
					
					if (type0 == DNS_TYPE_CNAME) {
						build_reply(&sreply, tnp->so, pbuf, len, question, from, \
							fromlen, sd0, ((type1 > 0) ? sd1 : NULL), \
							tnp->region, istcp, tnp->wildcard, NULL, replybuf);
						slen = reply_cname(&sreply);
					} else if (type0 == DNS_TYPE_NS) {
						build_reply(&sreply, tnp->so, pbuf, len, question, from, \
							fromlen, sd0, NULL, tnp->region, istcp, 
							tnp->wildcard, NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);
						break;
					 } else if (type0 == DNS_TYPE_AAAA) {
						build_reply(&sreply, tnp->so, pbuf, len, question, from, 
							fromlen, sd0, NULL, tnp->region, istcp, 
							tnp->wildcard, NULL, replybuf);

						slen = reply_aaaa(&sreply, cfg->db);
						break;		/* must break here */
					}

					break;
				case DNS_TYPE_MX:
					
					if (type0 == DNS_TYPE_CNAME) {
						build_reply(&sreply, tnp->so, pbuf, len, question, from, \
							fromlen, sd0, ((type1 > 0) ? sd1 : NULL), \
							tnp->region, istcp, tnp->wildcard, NULL, replybuf);

						slen = reply_cname(&sreply);

					} else if (type0 == DNS_TYPE_NS) {
						build_reply(&sreply, tnp->so, pbuf, len, question, from, \
							fromlen, sd0, NULL, tnp->region, istcp, 
							tnp->wildcard, NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);

						break;
					} else if (type0 == DNS_TYPE_MX) {
						build_reply(&sreply, tnp->so, pbuf, len, question, from,  \
							fromlen, sd0, NULL, tnp->region, istcp, 
							tnp->wildcard, NULL, replybuf);

						slen = reply_mx(&sreply, cfg->db);
						break;		/* must break here */
					}

					break;
				case DNS_TYPE_SOA:
					if (type0 == DNS_TYPE_SOA) {
						build_reply(&sreply, tnp->so, pbuf, len, question, from, \
							fromlen, sd0, NULL, tnp->region, istcp, 
							tnp->wildcard, NULL, replybuf);

						slen = reply_soa(&sreply);
					} else if (type0 == DNS_TYPE_NS) {
						build_reply(&sreply, tnp->so, pbuf, len, question, from, \
							fromlen, sd0, NULL, tnp->region, istcp, 
							tnp->wildcard, NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);
						break;
					}
					break;
				case DNS_TYPE_NS:
					if (type0 == DNS_TYPE_NS) {
						build_reply(&sreply, tnp->so, pbuf, len, question, from,  \
							fromlen, sd0, NULL, tnp->region, istcp, 
							tnp->wildcard, NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);
					}
					break;

				case DNS_TYPE_SSHFP:
					if (type0 == DNS_TYPE_SSHFP) {
						build_reply(&sreply, tnp->so, pbuf, len, question, from,  \
							fromlen, sd0, NULL, tnp->region, istcp, 
							tnp->wildcard, NULL, replybuf);

						slen = reply_sshfp(&sreply);
					}
					break;


				case DNS_TYPE_SRV:
					if (type0 == DNS_TYPE_SRV) {
						build_reply(&sreply, tnp->so, pbuf, len, question, from,  \
							fromlen, sd0, NULL, tnp->region, istcp, 
							tnp->wildcard, NULL, replybuf);

						slen = reply_srv(&sreply, cfg->db);
					}
					break;

				case DNS_TYPE_NAPTR:
					if (type0 == DNS_TYPE_NAPTR) {
						build_reply(&sreply, tnp->so, pbuf, len, question, from,  \
							fromlen, sd0, NULL, tnp->region, istcp, 
							tnp->wildcard, NULL, replybuf);

						slen = reply_naptr(&sreply, cfg->db);
					}
					break;

				case DNS_TYPE_CNAME:
					if (type0 == DNS_TYPE_CNAME) {
						build_reply(&sreply, tnp->so, pbuf, len, question, from, \
							fromlen, sd0, NULL, tnp->region, istcp, 
							tnp->wildcard, NULL, replybuf);

						slen = reply_cname(&sreply);
					} else if (type0 == DNS_TYPE_NS) {
						build_reply(&sreply, tnp->so, pbuf, len, question, from, \
							fromlen, sd0, NULL, tnp->region, istcp, 
							tnp->wildcard, NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);
						break;
					}
					break;

				case DNS_TYPE_PTR:
					if (type0 == DNS_TYPE_CNAME) {
						build_reply(&sreply, tnp->so, pbuf, len, question, from, \
							fromlen, sd0, ((type1 > 0) ? sd1 : NULL) \
							, tnp->region, istcp, tnp->wildcard, NULL,
							replybuf);

						slen = reply_cname(&sreply);

					} else if (type0 == DNS_TYPE_NS) {

						build_reply(&sreply, tnp->so, pbuf, len, question, from, \
							fromlen, sd0, NULL, tnp->region, istcp, 
							tnp->wildcard, NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);

						break;
					} else if (type0 == DNS_TYPE_PTR) {

						build_reply(&sreply, tnp->so, pbuf, len, question, from, 	
								fromlen, sd0, NULL, tnp->region, istcp, 
								tnp->wildcard, NULL, replybuf);

						slen = reply_ptr(&sreply);
						break;		/* must break here */
					}
					break;

				case DNS_TYPE_TXT:
					if (type0 == DNS_TYPE_TXT) {

						build_reply(&sreply, tnp->so, pbuf, len, question, from,  \
							fromlen, sd0, NULL, tnp->region, istcp, 
							tnp->wildcard, NULL, replybuf);

						slen = reply_txt(&sreply);
					}
					break;

				case DNS_TYPE_SPF:
					if (type0 == DNS_TYPE_SPF) {

						build_reply(&sreply, tnp->so, pbuf, len, question, from,  \
							fromlen, sd0, NULL, tnp->region, istcp, 	
							tnp->wildcard, NULL, replybuf);

						slen = reply_spf(&sreply);
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
						build_reply(&sreply, tnp->so, pbuf, len, question, from, \
							fromlen, sd0, NULL, aregion, istcp, 
							tnp->wildcard, NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);

					} else {

						build_reply(&sreply, tnp->so, pbuf, len, question, from, \
						fromlen, NULL, NULL, tnp->region, istcp, 
						tnp->wildcard, NULL, replybuf);
		
						slen = reply_notimpl(&sreply);
						snprintf(replystring, DNS_MAXNAME, "NOTIMPL");
					}
					break;
				}
			
		tcpout:
				if (lflag)
					dolog(LOG_INFO, "request on descriptor %u interface \"%s\" from %s (ttl=TCP, region=%d) for \"%s\" type=%s class=%u, %s%s answering \"%s\" (%d/%d)\n", tnp->so, tnp->ident, tnp->address, tnp->region, question->converted_name, get_dns_type(ntohs(question->hdr->qtype)), ntohs(question->hdr->qclass), (question->edns0len) ? "edns0, " : "", (question->dnssecok) ? "dnssecok, " : "", replystring, len, slen);


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

			}	/* END ISSET */

			memset(tnp->input, 0, tnp->maxlen);
			tnp->offset = 0;

		} /* SLIST_FOREACH */

		/* UDP marriage */
		for (i = 0; i < cfg->sockcount; i++) {
			if (axfrport && FD_ISSET(cfg->axfr[i], &rset)) {
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
	
				if (rflag) {
					if (getsockname(so, (struct sockaddr*)&sto, &namelen) < 0) {
						dolog(LOG_INFO, "getsockname failed: %s\n", strerror(errno));
					}
					
					memset(&rh, 0, sizeof(rh));
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
					wildcard = find_wildcard((struct sockaddr_storage *)sin6, AF_INET6);
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
					wildcard = find_wildcard((struct sockaddr_storage *)sin, AF_INET);
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
					build_reply(&sreply, so, buf, len, NULL, from, fromlen, NULL, NULL, aregion, istcp, wildcard, NULL, replybuf);

					slen = reply_fmterror(&sreply);
					dolog(LOG_INFO, "question on descriptor %d interface \"%s\" from %s, did not have question of 1 replying format error\n", so, cfg->ident[i], address);
					goto drop;
				}

				if (filter) {

					build_reply(&sreply, so, buf, len, NULL, from, fromlen, NULL, NULL, aregion, istcp, wildcard, NULL, replybuf);
					slen = reply_refused(&sreply);

					dolog(LOG_INFO, "UDP connection refused on descriptor %u interface \"%s\" from %s (ttl=%d, region=%d) replying REFUSED, filter policy\n", so, cfg->ident[i], address, received_ttl, aregion);
					goto drop;
				}

				if (whitelist && blacklist == 0) {

					build_reply(&sreply, so, buf, len, NULL, from, fromlen, NULL, NULL, aregion, istcp, wildcard, NULL, replybuf);
					slen = reply_refused(&sreply);

					dolog(LOG_INFO, "UDP connection refused on descriptor %u interface \"%s\" from %s (ttl=%d, region=%d) replying REFUSED, whitelist policy\n", so, cfg->ident[i], address, received_ttl, aregion);
					goto drop;
				}

				if (ratelimit && rcheck) {
					dolog(LOG_INFO, "UDP connection refused on descriptor %u interface \"%s\" from %s (ttl=%d, region=%d) ratelimit policy dropping packet\n", so, cfg->ident[i], address, received_ttl, aregion);
					goto drop;
				}
					
				if (rflag && recursion) {
					memcpy(&rh.buf, buf, len);
					rh.len = len;
				}

				if ((question = build_question(buf, len, ntohs(dh->additional))) == NULL) {
					dolog(LOG_INFO, "on descriptor %u interface \"%s\" malformed question from %s, drop\n", so, cfg->ident[i], address);
					goto drop;
				}

				/* goto drop beyond this point should goto out instead */
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

					case ERR_NXDOMAIN:
						goto udpnxdomain;
					case ERR_NOERROR:
						if (rflag && recursion) {
							snprintf(replystring, DNS_MAXNAME, "RECURSE");
							if (send(sp, (char *)&rh, sizeof(rh), 0) < 0) {
								dolog(LOG_INFO, "send sp: %s\n", strerror(errno));
							}

							goto udpout;
						} else {
							/*
							 * this is hackish not sure if this should be here
							 */

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
										fromlen, sd0, NULL, aregion, istcp, wildcard, 
										NULL, replybuf);

									slen = reply_noerror(&sreply);
							}
							goto udpout;
						} /* else rflag */
					}
				}

				switch (type0) {
				case 0:
udpnxdomain:
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
								wildcard, NULL, replybuf);

								slen = reply_nxdomain(&sreply);
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
							fromlen, NULL, NULL, aregion, istcp, wildcard, \
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
							aregion, istcp, wildcard, NULL, replybuf);

						slen = reply_cname(&sreply);
					} else if (type0 == DNS_TYPE_NS) {

						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, sd0, NULL, aregion, istcp, wildcard, \
							NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);
						break;
					} else if (type0 == DNS_TYPE_A) {

						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, sd0, NULL, aregion, istcp, wildcard, 
							NULL, replybuf);

						slen = reply_a(&sreply, cfg->db);
						break;		/* must break here */
					}

					break;

				case DNS_TYPE_ANY:
					build_reply(&sreply, so, buf, len, question, from, \
						fromlen, sd0, NULL, aregion, istcp, wildcard, NULL,
						replybuf);

					slen = reply_any(&sreply);
					break;		/* must break here */
				case DNS_TYPE_DNSKEY:
					build_reply(&sreply, so, buf, len, question, from, \
						fromlen, sd0, NULL, aregion, istcp, wildcard, NULL,
						replybuf);

					slen = reply_dnskey(&sreply);
					break;

				case DNS_TYPE_RRSIG:
					build_reply(&sreply, so, buf, len, question, from, \
						fromlen, sd0, NULL, aregion, istcp, wildcard, NULL,
						replybuf);

					slen = reply_rrsig(&sreply, cfg->db);
					break;		/* must break here */


				case DNS_TYPE_AAAA:
					
					if (type0 == DNS_TYPE_CNAME) {

						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, sd0, ((type1 > 0) ? sd1 : NULL), \
							aregion, istcp, wildcard, NULL, replybuf);

						slen = reply_cname(&sreply);
					} else if (type0 == DNS_TYPE_NS) {

						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, sd0, NULL, aregion, istcp, wildcard, \
							NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);
						break;
					 } else if (type0 == DNS_TYPE_AAAA) {

						build_reply(&sreply, so, buf, len, question, from, 
							fromlen, sd0, NULL, aregion, istcp, wildcard, 
							NULL, replybuf);

						slen = reply_aaaa(&sreply, cfg->db);
						break;		/* must break here */
					}

					break;
				case DNS_TYPE_MX:
					
					if (type0 == DNS_TYPE_CNAME) {

						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, sd0, ((type1 > 0) ? sd1 : NULL), \
							aregion, istcp, wildcard, NULL, replybuf);

						slen = reply_cname(&sreply);
	   				} else if (type0 == DNS_TYPE_NS) {

						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, sd0, NULL, aregion, istcp, wildcard, \
							NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);
						break;
					} else if (type0 == DNS_TYPE_MX) {
						build_reply(&sreply, so, buf, len, question, from,  \
							fromlen, sd0, NULL, aregion, istcp, wildcard, \
							NULL, replybuf);
						slen = reply_mx(&sreply, cfg->db);
						break;		/* must break here */
					}

					break;
				case DNS_TYPE_SOA:
					if (type0 == DNS_TYPE_SOA) {

						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, sd0, NULL, aregion, istcp, wildcard, \
							NULL, replybuf);

						slen = reply_soa(&sreply);
					} else if (type0 == DNS_TYPE_NS) {

						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, sd0, NULL, aregion, istcp, wildcard, \
							NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);
						break;
					}
					break;
				case DNS_TYPE_NS:
					if (type0 == DNS_TYPE_NS) {

						build_reply(&sreply, so, buf, len, question, from,  \
							fromlen, sd0, NULL, aregion, istcp, wildcard, \
							NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);
					}
					break;

				case DNS_TYPE_SSHFP:
					if (type0 == DNS_TYPE_SSHFP) {
						build_reply(&sreply, so, buf, len, question, from,  \
							fromlen, sd0, NULL, aregion, istcp, wildcard, \
							NULL, replybuf);

						slen = reply_sshfp(&sreply);
					}
					break;


				case DNS_TYPE_SRV:
					if (type0 == DNS_TYPE_SRV) {

						build_reply(&sreply, so, buf, len, question, from,  \
							fromlen, sd0, NULL, aregion, istcp, wildcard, \
							NULL, replybuf);

						slen = reply_srv(&sreply, cfg->db);
					}
					break;

				case DNS_TYPE_NAPTR:
					if (type0 == DNS_TYPE_NAPTR) {

						build_reply(&sreply, so, buf, len, question, from,  \
							fromlen, sd0, NULL, aregion, istcp, wildcard, \
							NULL, replybuf);

						slen = reply_naptr(&sreply, cfg->db);
					}
					break;

				case DNS_TYPE_CNAME:
					if (type0 == DNS_TYPE_CNAME) {

						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, sd0, NULL, aregion, istcp, wildcard, \
							NULL, replybuf);

						slen = reply_cname(&sreply);
					} else if (type0 == DNS_TYPE_NS) {

						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, sd0, NULL, aregion, istcp, wildcard, \
							NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);
						break;
					}
					break;

				case DNS_TYPE_PTR:
					if (type0 == DNS_TYPE_CNAME) {

						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, sd0, ((type1 > 0) ? sd1 : NULL) \
							, aregion, istcp, wildcard, NULL, replybuf);

						slen = reply_cname(&sreply);
					} else if (type0 == DNS_TYPE_NS) {

						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, sd0, NULL, aregion, istcp, wildcard, \
							NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);
						break;
					} else if (type0 == DNS_TYPE_PTR) {

						build_reply(&sreply, so, buf, len, question, from, 	
								fromlen, sd0, NULL, aregion, istcp, wildcard, \
								NULL, replybuf);

						slen = reply_ptr(&sreply);
						break;		/* must break here */
					}
					break;
				case DNS_TYPE_TXT:
					if (type0 == DNS_TYPE_TXT) {

						build_reply(&sreply, so, buf, len, question, from,  \
							fromlen, sd0, NULL, aregion, istcp, wildcard, \
							NULL, replybuf);

						slen = reply_txt(&sreply);
					}
					break;
				case DNS_TYPE_SPF:
					if (type0 == DNS_TYPE_SPF) {

						build_reply(&sreply, so, buf, len, question, from,  \
							fromlen, sd0, NULL, aregion, istcp, wildcard, \
							NULL, replybuf);

						slen = reply_spf(&sreply);
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
							fromlen, sd0, NULL, aregion, istcp, wildcard, \
							NULL, replybuf);

						slen = reply_ns(&sreply, cfg->db);
					} else {


						build_reply(&sreply, so, buf, len, question, from, \
							fromlen, NULL, NULL, aregion, istcp, wildcard, \
							NULL, replybuf);

						slen = reply_notimpl(&sreply);
						snprintf(replystring, DNS_MAXNAME, "NOTIMPL");
					}
					break;
				}
			
		udpout:
				if (lflag) {
					dolog(LOG_INFO, "request on descriptor %u interface \"%s\" from %s (ttl=%u, region=%d) for \"%s\" type=%s class=%u, %s%sanswering \"%s\" (%d/%d)\n", so, cfg->ident[i], address, received_ttl, aregion, question->converted_name, get_dns_type(ntohs(question->hdr->qtype)), ntohs(question->hdr->qclass), (question->edns0len ? "edns0, " : ""), (question->dnssecok ? "dnssecok, " : "") , replystring, len, slen);

				}

				if (logging.active == 1 && logging.bind == 0) {
					remotelog(lfd, "request on descriptor %u interface \"%s\" from %s (ttl=%u, region=%d) for \"%s\" type=%s class=%u, %s%sanswering \"%s\" (%d/%d)", so, cfg->ident[i], address, received_ttl, aregion, question->converted_name, get_dns_type(ntohs(question->hdr->qtype)), ntohs(question->hdr->qclass), (question->edns0len ? "edns0, ": ""), (question->dnssecok ? "dnssecok" : ""), replystring, len, slen);
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
build_reply(struct sreply *reply, int so, char *buf, int len, struct question *q, struct sockaddr *sa, socklen_t slen, struct domain *sd1, struct domain *sd2, u_int8_t region, int istcp, int wildcard, struct recurses *sr, char *replybuf)
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
	reply->wildcard = wildcard;
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
setup_master(DB *db, DB_ENV *dbenv, char **av)
{
	DB *destroy;
	char buf[512];
	pid_t pid;
	int fd, ret;
	
#if !defined __linux__ && !defined __APPLE__
	setproctitle("delphinusdnsd master");
#endif

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

	for (;;) {
		sleep(1);

		if (*ptr) {
			dolog(LOG_INFO, "pid %u died, killing delphinusdnsd\n", *ptr);
			master_shutdown(SIGTERM);
		}

		if (mshutdown) {
			dolog(LOG_INFO, "shutting down on signal %d\n", msig);
			unlink(PIDFILE);
			db->close(db, 0);


		        if (db_create((DB **)&destroy, (DB_ENV *)dbenv, 0) != 0) {
				dolog(LOG_INFO, "db_create: %s\n", strerror(errno));
			}

			ret = destroy->remove(destroy, database, NULL, 0);
			if (ret != 0) {
				dolog(LOG_INFO, "db->remove: %s\n", db_strerror(ret));
			}

			dbenv->close(dbenv, 0);

			/* clean up our database */
			pid = getpid();
			snprintf(buf, sizeof(buf), "%s/%lu/__db.001", MYDB_PATH, 
				(long)getpid());
			unlink(buf);
			snprintf(buf, sizeof(buf), "%s/%lu", MYDB_PATH, 
				(long)getpid());
			
			rmdir(buf);

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
			db->close(db, 0);

		        if (db_create((DB **)&destroy, (DB_ENV *)dbenv, 0) != 0) {
				dolog(LOG_INFO, "db_create: %s\n", strerror(errno));
			}

			ret = destroy->remove(destroy, database, NULL, 0);
			if (ret != 0) {
				dolog(LOG_INFO, "db->remove: %s\n", db_strerror(ret));
			}

			dbenv->close(dbenv, 0);

			/* clean up our database */
			pid = getpid();
			snprintf(buf, sizeof(buf), "%s/%lu/__db.001", MYDB_PATH, 
				(long)getpid());
			unlink(buf);
			snprintf(buf, sizeof(buf), "%s/%lu", MYDB_PATH, 
				(long)getpid());
			
			rmdir(buf);

			dolog(LOG_INFO, "restarting on SIGHUP\n");

			closelog();
			if (execvp("/usr/local/sbin/delphinusdnsd", av) < 0) {
					dolog(LOG_ERR, "execvp: %s\n", strerror(errno));
			}
			/* NOTREACHED */
			exit(1);
		}	
	}

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
 * slave_shutdown - a slave wishes to shutdown, enter its pid into the 
 *			shutdown shared memory and return.
 */

void
slave_shutdown(void)
{
	pid_t pid;

	pid = getpid();

	*ptr = pid;
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
 * CHECK_QTYPE - check the query type and return appropriately if we have 
 *		 such a record in our DB..
 *		 returns 0 on error, or the DNS TYPE from 1 through 65535
 * 		 when the return is 0 the error variable is set with the error
 *		 code (-1 or -2)
 */

u_int16_t
check_qtype(struct domain *sd, u_int16_t type, int nxdomain, int *error)
{
	u_int16_t returnval;

	switch (type) {

	case DNS_TYPE_ANY:
			returnval = DNS_TYPE_ANY;
			break;

	case DNS_TYPE_A:
		if ((sd->flags & DOMAIN_HAVE_A) == DOMAIN_HAVE_A)  {
			returnval = DNS_TYPE_A;
			break;
		} else if ((sd->flags & DOMAIN_HAVE_CNAME) == 						DOMAIN_HAVE_CNAME) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_AAAA:
		if ((sd->flags & DOMAIN_HAVE_AAAA) == DOMAIN_HAVE_AAAA)  {
			returnval = DNS_TYPE_AAAA;
			break;
		} else if ((sd->flags & DOMAIN_HAVE_CNAME) == 						DOMAIN_HAVE_CNAME) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_MX:
		if ((sd->flags & DOMAIN_HAVE_MX) == 
				DOMAIN_HAVE_MX)  {
			returnval = DNS_TYPE_MX;
			break;
		} else if ((sd->flags & DOMAIN_HAVE_CNAME) == 						DOMAIN_HAVE_CNAME) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_PTR:
		if ((sd->flags & DOMAIN_HAVE_PTR) == DOMAIN_HAVE_PTR)  {
			returnval = DNS_TYPE_PTR;
			break;
		} else if ((sd->flags & DOMAIN_HAVE_CNAME) == 						DOMAIN_HAVE_CNAME) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;

	case DNS_TYPE_SOA:
		if ((sd->flags & DOMAIN_HAVE_SOA) == DOMAIN_HAVE_SOA) {

			returnval = DNS_TYPE_SOA;
			break;
		}

		if (nxdomain)
			*error = -2;
		else
			*error = -1;

		return 0;

	case DNS_TYPE_SSHFP:
		if ((sd->flags & DOMAIN_HAVE_SSHFP) == DOMAIN_HAVE_SSHFP) {
			returnval = DNS_TYPE_SSHFP;
			break;
		}

		*error = -1;
		return 0;

	case DNS_TYPE_SRV:	
		if ((sd->flags & DOMAIN_HAVE_SRV) == DOMAIN_HAVE_SRV) {
			returnval = DNS_TYPE_SRV;
			break;
		}

		*error = -1;
		return 0;

	case DNS_TYPE_NAPTR:
		if ((sd->flags & DOMAIN_HAVE_NAPTR) == DOMAIN_HAVE_NAPTR) {
				returnval = DNS_TYPE_NAPTR;
				break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_CNAME:
		if ((sd->flags & DOMAIN_HAVE_CNAME) == DOMAIN_HAVE_CNAME) {
				returnval = DNS_TYPE_CNAME;
				break;
		}

		*error = -1;
		return 0;

	case DNS_TYPE_NS:
		if ((sd->flags & DOMAIN_HAVE_NS) == DOMAIN_HAVE_NS) {
			returnval = DNS_TYPE_NS;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_TXT:
		if ((sd->flags & DOMAIN_HAVE_TXT) == DOMAIN_HAVE_TXT)  {
			returnval = DNS_TYPE_TXT;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_SPF:
		if ((sd->flags & DOMAIN_HAVE_SPF) == DOMAIN_HAVE_SPF)  {
			returnval = DNS_TYPE_SPF;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_RRSIG:
		if ((sd->flags & DOMAIN_HAVE_RRSIG) == DOMAIN_HAVE_RRSIG)  {
			returnval = DNS_TYPE_RRSIG;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_DNSKEY:
		if ((sd->flags & DOMAIN_HAVE_DNSKEY) == DOMAIN_HAVE_DNSKEY)  {
			returnval = DNS_TYPE_DNSKEY;
			break;
		}

		*error = -1;
		return 0;
	default: /* RR's that we don't support, but have a zone for */

		*error = -1;
		return 0;
		break;
	}

	return (returnval);
}

int 
get_record_size(DB *db, char *converted_name, int converted_namelen)
{
	struct domain *sdomain;
	DBT key, data;
	int ret;

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	key.data = (char *)converted_name;
	key.size = converted_namelen;

	data.data = NULL;
	data.size = sizeof(struct domain);

	if ((ret = db->get(db, NULL, &key, &data, 0)) == 0) {
		sdomain = (struct domain *)data.data;
		return (sdomain->len);
	} else {
		if (debug && ret != DB_NOTFOUND )
			dolog(LOG_INFO, "db->get: %s\n", strerror(errno));
	}

	return sizeof(struct domain);
}

/* find a substruct in struct domain, first match wins */

void *
find_substruct(struct domain *ssd, u_int16_t type)
{
	struct domain_generic *sdg = NULL;
	void *ptr = NULL;
	void *vssd = (void *)ssd;

	switch (type) {
	case INTERNAL_TYPE_SOA:
		if (! (ssd->flags & DOMAIN_HAVE_SOA))
			return NULL;
		break;
	case INTERNAL_TYPE_A:
		if (! (ssd->flags & DOMAIN_HAVE_A))
			return NULL;
		break;
	case INTERNAL_TYPE_AAAA:
		if (! (ssd->flags & DOMAIN_HAVE_AAAA))
			return NULL;
		break;
	case INTERNAL_TYPE_MX:
		if (! (ssd->flags & DOMAIN_HAVE_MX))
			return NULL;
		break;
	case INTERNAL_TYPE_NS:
		if (! (ssd->flags & DOMAIN_HAVE_NS))
			return NULL;
		break;
	case INTERNAL_TYPE_CNAME:
		if (! (ssd->flags & DOMAIN_HAVE_CNAME))
			return NULL;
		break;
	case INTERNAL_TYPE_PTR:
		if (! (ssd->flags & DOMAIN_HAVE_PTR))
			return NULL;
		break;
	case INTERNAL_TYPE_TXT:
		if (! (ssd->flags & DOMAIN_HAVE_TXT))
			return NULL;
		break;
	case INTERNAL_TYPE_SPF:
		if (! (ssd->flags & DOMAIN_HAVE_SPF))
			return NULL;
		break;
	case INTERNAL_TYPE_SRV:
		if (! (ssd->flags & DOMAIN_HAVE_SRV))
			return NULL;
		break;
	case INTERNAL_TYPE_SSHFP:
		if (! (ssd->flags & DOMAIN_HAVE_SSHFP))
			return NULL;
		break;
	case INTERNAL_TYPE_NAPTR:
		if (! (ssd->flags & DOMAIN_HAVE_NAPTR))
			return NULL;
		break;
	case INTERNAL_TYPE_DNSKEY:
		if (! (ssd->flags & DOMAIN_HAVE_DNSKEY))
			return NULL;
		break;
	case INTERNAL_TYPE_DS:
		if (! (ssd->flags & DOMAIN_HAVE_DS))
			return NULL;
		break;
	case INTERNAL_TYPE_NSEC:
		if (! (ssd->flags & DOMAIN_HAVE_NSEC))
			return NULL;
		break;
	case INTERNAL_TYPE_RRSIG:
		if (! (ssd->flags & DOMAIN_HAVE_RRSIG))
			return NULL;
		break;
	default:
		return NULL;
		break;
	}
	
	for (ptr = (void *)(vssd + sizeof(struct domain)); \
		ptr <= (void *)(vssd + ssd->len); \
		ptr += sdg->len) {
		sdg = (struct domain_generic *)ptr;
		if (type == sdg->type) {
			return (ptr);
		}
	}

	return NULL;
}

int
lookup_type(int internal_type)
{
	int array[INTERNAL_TYPE_MAX];

	array[INTERNAL_TYPE_A] = DNS_TYPE_A;
	array[INTERNAL_TYPE_AAAA] = DNS_TYPE_AAAA;
	array[INTERNAL_TYPE_CNAME] = DNS_TYPE_CNAME;
	array[INTERNAL_TYPE_NS] = DNS_TYPE_NS;
	array[INTERNAL_TYPE_DNSKEY] =DNS_TYPE_DNSKEY;
	array[INTERNAL_TYPE_DS] = DNS_TYPE_DS;
	array[INTERNAL_TYPE_MX] = DNS_TYPE_MX;
	array[INTERNAL_TYPE_NAPTR] = DNS_TYPE_NAPTR;
	array[INTERNAL_TYPE_NSEC] = DNS_TYPE_NSEC;
	array[INTERNAL_TYPE_PTR] = DNS_TYPE_PTR;
	array[INTERNAL_TYPE_SOA] = DNS_TYPE_SOA;
	array[INTERNAL_TYPE_SPF] = DNS_TYPE_SPF;
	array[INTERNAL_TYPE_SRV] = DNS_TYPE_SRV;
	array[INTERNAL_TYPE_SSHFP] = DNS_TYPE_SSHFP;
	array[INTERNAL_TYPE_TXT] = DNS_TYPE_TXT;

	if (internal_type < 0 || internal_type > INTERNAL_TYPE_MAX)
		return -1;

	return(array[internal_type]);
}
