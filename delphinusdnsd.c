/*
 * Copyright (c) 2002-2023 Peter J. Philipp <pjp@delphinusdns.org>
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

#include <tls.h>

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

#include <openssl/evp.h>

#include "ddd-dns.h"
#include "ddd-db.h" 
#include "ddd-crypto.h"
#include "ddd-config.h"

/* prototypes */

extern char 		*rrlimit_setup(int);
extern int		free_question(struct question *);
extern int		init_entlist(ddDB *);
extern int		reply_caa(struct sreply *, int *, ddDB *);
extern int		reply_cdnskey(struct sreply *, int *, ddDB *);
extern int		reply_cds(struct sreply *, int *, ddDB *);
extern int		reply_dnskey(struct sreply *, int *, ddDB *);
extern int		reply_ds(struct sreply *, int *, ddDB *);
extern int		reply_hinfo(struct sreply *, int *, ddDB *);
extern int		reply_https(struct sreply *, int *, ddDB *);
extern int		reply_loc(struct sreply *, int *, ddDB *);
extern int		reply_nodata(struct sreply *, int *, ddDB *);
extern int		reply_notify(struct sreply *, int *, ddDB *);
extern int		reply_nsec(struct sreply *, int *, ddDB *);
extern int		reply_nsec3(struct sreply *, int *, ddDB *);
extern int		reply_nsec3param(struct sreply *, int *, ddDB *);
extern int		reply_rp(struct sreply *, int *, ddDB *);
extern int		reply_svcb(struct sreply *, int *, ddDB *);
extern int 		check_ent(char *, int);
extern int 		check_rrlimit(int, uint16_t *, int, char *);
extern int 		display_rr(struct rrset *rrset);
extern int 		drop_privs(char *, struct passwd *);
extern int 		find_filter(struct sockaddr_storage *, int);
extern int 		find_passlist(struct sockaddr_storage *, int);
extern int 		get_record_size(ddDB *, char *, int);
extern int 		memcasecmp(u_char *, u_char *, int);
extern int 		notifysource(struct question *, struct sockaddr_storage *);
extern int 		reply_a(struct sreply *, int *, ddDB *);
extern int 		reply_aaaa(struct sreply *, int *, ddDB *);
extern int 		reply_any(struct sreply *, int *, ddDB *);
extern int 		reply_badvers(struct sreply *, int *, ddDB *);
extern int 		reply_cname(struct sreply *, int *, ddDB *);
extern int 		reply_eui48(struct sreply *, int *, ddDB *);
extern int 		reply_eui64(struct sreply *, int *, ddDB *);
extern int 		reply_fmterror(struct sreply *, int *, ddDB *);
extern int 		reply_ipseckey(struct sreply *, int *, ddDB *);
extern int 		reply_kx(struct sreply *, int *, ddDB *);
extern int 		reply_mx(struct sreply *, int *, ddDB *);
extern int 		reply_naptr(struct sreply *, int *, ddDB *);
extern int 		reply_noerror(struct sreply *, int *, ddDB *);
extern int 		reply_notauth(struct sreply *, int *, ddDB *);
extern int 		reply_notimpl(struct sreply *, int *, ddDB *);
extern int 		reply_ns(struct sreply *, int *, ddDB *);
extern int 		reply_nxdomain(struct sreply *, int *, ddDB *);
extern int 		reply_ptr(struct sreply *, int *, ddDB *);
extern int 		reply_refused(struct sreply *, int *, ddDB *, int);
extern int 		reply_soa(struct sreply *, int *, ddDB *);
extern int 		reply_srv(struct sreply *, int *, ddDB *);
extern int 		reply_sshfp(struct sreply *, int *, ddDB *);
extern int 		reply_tlsa(struct sreply *, int *, ddDB *);
extern int 		reply_txt(struct sreply *, int *, ddDB *);
extern int 		reply_version(struct sreply *, int *, ddDB *);
extern int 		reply_zonemd(struct sreply *, int *, ddDB *);
extern int      	reply_rrsig(struct sreply *, int *, ddDB *);
extern struct question	*build_question(char *, int, uint16_t, char *);
extern struct rbtree * 	find_rrset(ddDB *db, char *name, int len);
extern struct rrset * 	find_rr(struct rbtree *rbt, uint16_t rrtype);
extern uint16_t 	unpack16(char *);
extern uint32_t 	unpack32(char *);
extern void		forwardloop(ddDB *, struct cfg *, struct imsgbuf *, struct imsgbuf *);
extern void		mainloop(struct cfg *, struct imsgbuf *);
extern void		replicantloop(ddDB *, struct imsgbuf *);
extern void	 	init_filter(void);
extern void	 	init_notifyddd(void);
extern void	 	init_passlist(void);
extern void	 	init_tsig(void);
extern void 		axfrloop(struct cfg *, char **, ddDB *, struct imsgbuf *, struct imsgbuf *);
extern void 		ddd_shutdown(void);
extern void 		dolog(int, char *, ...);
extern void 		init_dnssec(void);
extern void 		init_region(void);
extern void 		pack(char *, char *, int);
extern void 		pack16(char *, uint16_t);
extern void 		pack32(char *, uint32_t);
extern void 		pack8(char *, uint8_t);
extern void 		populate_zone(ddDB *db);
extern void 		unpack(char *, char *, int);

char *			sm_init(size_t, size_t);
int			bind_this_pifap(struct ifaddrs *, int, int);
int			bind_this_res(struct addrinfo *, int);
int			determine_glue(ddDB *db);
int 			send_to_parser(struct cfg *, struct imsgbuf *, char *, int, struct parsequestion *);
size_t			sm_size(size_t, size_t);
struct imsgbuf * 	register_cortex(struct imsgbuf *, int);
struct question		*convert_question(struct parsequestion *, int);
void			nomore_neurons(struct imsgbuf *);
void			setup_cortex(struct imsgbuf *);
void			sm_lock(char *, size_t);
void			sm_unlock(char *, size_t);
void			sm_zebra(char *, size_t, size_t);
void 			build_reply(struct sreply *, int, char *, int, struct question *, struct sockaddr *, socklen_t, struct rbtree *, struct rbtree *, uint8_t, int, int, char *, struct tls *);
void 			ddd_signal(int);
void 			parseloop(struct cfg *, struct imsgbuf *, int);
void 			primary_reload(int);
void 			primary_shutdown(int);
void 			setup_primary(ddDB *, char **, char *, struct imsgbuf *);
void 			setup_unixsocket(char *, struct imsgbuf *);
#if notyet
int			enc_cpy(u_char *, u_char *, int, uint64_t);
int			dec_cpy(u_char *, u_char *, int, uint64_t);
#endif

/* aliases */

#define MYDB_PATH "/var/db/delphinusdns"

/* structs */

/* reply_logic is mirrored with forward.c */
struct reply_logic rlogic[] = {
	{ DNS_TYPE_A, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_A, DNS_TYPE_NS, BUILD_OTHER, reply_ns },
	{ DNS_TYPE_A, DNS_TYPE_A, BUILD_OTHER, reply_a },
	{ DNS_TYPE_AAAA, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_AAAA, DNS_TYPE_NS, BUILD_OTHER, reply_ns },
	{ DNS_TYPE_AAAA, DNS_TYPE_AAAA, BUILD_OTHER, reply_aaaa },
	{ DNS_TYPE_DNSKEY, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_DNSKEY, DNS_TYPE_DNSKEY, BUILD_OTHER, reply_dnskey },
	{ DNS_TYPE_CDNSKEY, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_CDNSKEY, DNS_TYPE_CDNSKEY, BUILD_OTHER, reply_cdnskey },
	{ DNS_TYPE_SOA, DNS_TYPE_SOA, BUILD_OTHER, reply_soa },
	{ DNS_TYPE_SOA, DNS_TYPE_NS, BUILD_OTHER, reply_ns },
	{ DNS_TYPE_MX, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_MX, DNS_TYPE_NS, BUILD_OTHER, reply_ns },
	{ DNS_TYPE_MX, DNS_TYPE_MX, BUILD_OTHER, reply_mx },
	{ DNS_TYPE_TXT, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_TXT, DNS_TYPE_TXT, BUILD_OTHER, reply_txt },
	{ DNS_TYPE_NS, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_NS, DNS_TYPE_NS, BUILD_OTHER, reply_ns },
	{ DNS_TYPE_ANY, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_ANY, DNS_TYPE_ANY, BUILD_OTHER, reply_any },
	{ DNS_TYPE_DS, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_DS, DNS_TYPE_DS, BUILD_OTHER, reply_ds },
	{ DNS_TYPE_CDS, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_CDS, DNS_TYPE_CDS, BUILD_OTHER, reply_cds },
	{ DNS_TYPE_SSHFP, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_SSHFP, DNS_TYPE_SSHFP, BUILD_OTHER, reply_sshfp },
	{ DNS_TYPE_TLSA, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_TLSA, DNS_TYPE_TLSA, BUILD_OTHER, reply_tlsa },
	{ DNS_TYPE_SRV, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_SRV, DNS_TYPE_SRV, BUILD_OTHER, reply_srv },
	{ DNS_TYPE_CNAME, DNS_TYPE_CNAME, BUILD_OTHER, reply_cname },
	{ DNS_TYPE_CNAME, DNS_TYPE_NS, BUILD_OTHER, reply_ns },
	{ DNS_TYPE_NSEC3PARAM, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_NSEC3PARAM, DNS_TYPE_NSEC3PARAM, BUILD_OTHER, reply_nsec3param },
	{ DNS_TYPE_PTR, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_PTR, DNS_TYPE_NS, BUILD_OTHER, reply_ns },
	{ DNS_TYPE_PTR, DNS_TYPE_PTR, BUILD_OTHER, reply_ptr },
	{ DNS_TYPE_NAPTR, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_NAPTR, DNS_TYPE_NAPTR, BUILD_OTHER, reply_naptr },
	{ DNS_TYPE_NSEC3, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_NSEC3, DNS_TYPE_NSEC3, BUILD_OTHER, reply_nsec3 },
	{ DNS_TYPE_NSEC, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_NSEC, DNS_TYPE_NSEC, BUILD_OTHER, reply_nsec },
	{ DNS_TYPE_RRSIG, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_RRSIG, DNS_TYPE_RRSIG, BUILD_OTHER, reply_rrsig },
	{ DNS_TYPE_CAA, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_CAA, DNS_TYPE_CAA, BUILD_OTHER, reply_caa },
	{ DNS_TYPE_RP, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_RP, DNS_TYPE_RP, BUILD_OTHER, reply_rp },
	{ DNS_TYPE_HINFO, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_HINFO, DNS_TYPE_HINFO, BUILD_OTHER, reply_hinfo },
	{ DNS_TYPE_ZONEMD, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_ZONEMD, DNS_TYPE_ZONEMD, BUILD_OTHER, reply_zonemd },
	{ DNS_TYPE_LOC, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_LOC, DNS_TYPE_LOC, BUILD_OTHER, reply_loc },
	{ DNS_TYPE_EUI48, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_EUI48, DNS_TYPE_EUI48, BUILD_OTHER, reply_eui48 },
	{ DNS_TYPE_EUI64, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_EUI64, DNS_TYPE_EUI64, BUILD_OTHER, reply_eui64 },
	{ DNS_TYPE_SVCB, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_SVCB, DNS_TYPE_SVCB, BUILD_OTHER, reply_svcb },
	{ DNS_TYPE_HTTPS, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_HTTPS, DNS_TYPE_HTTPS, BUILD_OTHER, reply_https },
	{ DNS_TYPE_KX, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_KX, DNS_TYPE_KX, BUILD_OTHER, reply_kx },
	{ DNS_TYPE_IPSECKEY, DNS_TYPE_CNAME, BUILD_CNAME, reply_cname },
	{ DNS_TYPE_IPSECKEY, DNS_TYPE_IPSECKEY, BUILD_OTHER, reply_ipseckey },
	{ 0, 0, 0, NULL }
};

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

int reload = 0;
int mshutdown = 0;
int msig;

DDD_EVP_MD *md5_md;
char *rptr = NULL;
int ratelimit_backlog;

int debug = 0;
int verbose = 0;
int bflag = 0;
int iflag = 0;
int lflag = 0;
int nflag = 0;
int bcount = 0;
int icount = 0;
int forward = 0;
int forwardtsig = 0;
int strictx20i = 1;
int forwardstrategy = STRATEGY_SPRAY;
int zonecount = 0;
int tsigpassname = 0;
int cache = 0;
uint16_t port = 53;
uint32_t cachesize = 0;
char *bind_list[255];
char *interface_list[255];
char *identstring = NULL;
#ifndef DD_VERSION
char *versionstring = "delphinusdnsd-1.7";
uint8_t vslen = 17;
#else
char *versionstring = DD_VERSION;
uint8_t vslen = DD_VERSION_LEN;
#endif
pid_t *ptr = 0;
long glob_time_offset = 0;

int tls = 0;
uint16_t tls_port = 853;
char *tls_certfile = NULL;
char *tls_keyfile = NULL;
char *tls_protocols = NULL;
char *tls_ciphers = NULL;

static char iv[16];
static char encryptkey[16];


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
	static int tlss[DEFAULT_SOCKET];
	int n;

	int ch, i, j;
	int gai_error;
	int salen;
	int found = 0;
	int on = 1;
	int usesp = 0;

	pid_t pid;

	static char *ident[DEFAULT_SOCKET];
	char *conffile = CONFFILE;
	char buf[PATH_MAX];
	char **av = NULL;
	char *socketpath = SOCKPATH;
	
	struct passwd *pw;
	struct addrinfo hints, *res0, *res;
	struct ifaddrs *ifap, *pifap;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct cfg *cfg;
	struct imsgbuf cortex_ibuf;
	struct imsgbuf *ibuf;
	struct rlimit rlimits;

	static ddDB *db;
	
	time_t now;
	struct tm *ltm;

	char *shptr;

#ifdef __FreeBSD__
        cap_rights_t rights;
#endif

	
	if (geteuid() != 0) {
		fprintf(stderr, "must be started as root\n");
		exit(1);
	}

	now = time(NULL);
	ltm = localtime(&now);
	glob_time_offset = ltm->tm_gmtoff;

	av = argv;

#if __linux__
	setproctitle_init(argc, av, environ);
#endif

	while ((ch = getopt(argc, argv, "b:df:I:i:ln:p:s:v")) != -1) {
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
		case 'I':
			identstring = optarg;
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
			usesp = 1;
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

	if (identstring != NULL && usesp) {
		fprintf(stderr, "cannot specify -I and -s together\n");
		exit(1);
	}

	if (identstring) {
		snprintf(buf, sizeof(buf), "/var/run/delphinusdnsd-%s.sock",
			identstring);

		if ((socketpath = strdup(buf)) == NULL) {
			perror("strdup");
			exit(1);
		}
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

	/*
	 * make a shared memory segment for signaling kills between 
	 * processes...
	 */

	
	ptr = mmap(NULL, sizeof(pid_t), PROT_READ | PROT_WRITE, MAP_SHARED |\
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
		ddd_shutdown();
		exit(1);
	}


	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, PF_UNSPEC, &cfg->my_imsg[MY_IMSG_CORTEX].imsg_fds[0]) < 0) {
		dolog(LOG_INFO, "socketpair() failed\n");
		ddd_shutdown();
		exit(1);
	}

	pid = fork();
	switch (pid) {
	case -1:
		dolog(LOG_ERR, "fork(): %s\n", strerror(errno));
		exit(1);
	case 0:
		close(cfg->my_imsg[MY_IMSG_CORTEX].imsg_fds[0]);
		imsg_init(&cortex_ibuf, cfg->my_imsg[MY_IMSG_CORTEX].imsg_fds[1]);
		setup_cortex(&cortex_ibuf);
		/* NOTREACHED */
		exit(1);

		break;
	default:
		close(cfg->my_imsg[MY_IMSG_CORTEX].imsg_fds[1]);
		imsg_init(&cortex_ibuf, cfg->my_imsg[MY_IMSG_CORTEX].imsg_fds[0]);
	}

	pid = fork();
	switch (pid) {
	case -1:
		dolog(LOG_ERR, "fork(): %s\n", strerror(errno));
		exit(1);
	case 0:
		ibuf = register_cortex(&cortex_ibuf, MY_IMSG_PRIMARY);
		if (ibuf != NULL) {
			setup_primary(db, av, socketpath, ibuf);
		}
		/* NOTREACHED */
		ddd_shutdown();
		exit(1);
		break;
	default:
		break;
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

			signal(SIGTERM, ddd_signal);
			signal(SIGINT, ddd_signal);
			signal(SIGQUIT, ddd_signal);

			ibuf = register_cortex(&cortex_ibuf, MY_IMSG_UNIXCONTROL);
			if (ibuf != NULL) {
				setup_unixsocket(socketpath, ibuf);
			}
			ddd_shutdown();	
			exit(1);
		default:
			break;
		}
	} 


	/* end of setup_primary code */
#if USE_WOLFSSL
	wolfCrypt_Init();
#endif

	md5_md = (DDD_EVP_MD *)delphinusdns_EVP_get_digestbyname("md5");
	if (md5_md == NULL) {
		dolog(LOG_ERR, "unknown message digest 'md5'\n");
		ddd_shutdown();
		exit(1);
	}
		
	init_region();
	init_filter();
	init_passlist();
	init_dnssec();
	init_tsig();

	if (parse_file(db, conffile, 0) < 0) {
		dolog(LOG_INFO, "parsing config file failed\n");
		ddd_shutdown();
		exit(1);
	}

	/* initialize keys for the life of the program */
	arc4random_buf(&iv, sizeof(iv));
	arc4random_buf(&encryptkey, sizeof(encryptkey));

	if (zonecount && determine_glue(db) < 0) {
		dolog(LOG_INFO, "determine_glue() failed\n");
		ddd_shutdown();
		exit(1);
	}

	if (zonecount && init_entlist(db) < 0) {
		dolog(LOG_INFO, "creating entlist failed\n");
		ddd_shutdown();
		exit(1);
	}

	if (tls) {
		struct tls_config *tls_config;
		uint32_t protocols = (TLS_PROTOCOL_TLSv1_2 | TLS_PROTOCOLS_DEFAULT);
		tls_init();

		tls_config = tls_config_new();
		if (tls_config == NULL) {
			dolog(LOG_ERR, "tls_config_new()\n");
			ddd_shutdown();
			exit(1);
		}

		if ((cfg->ctx = tls_server()) == NULL) {
			dolog(LOG_ERR, "tls_server()\n");
			ddd_shutdown();
			exit(1);
		}

		if (tls_protocols) {
			if (tls_config_parse_protocols(&protocols, 
					tls_protocols) < 0) {
				
				dolog(LOG_ERR, "tls_config_parse_protocols()\n");
				ddd_shutdown();
				exit(1);
			}
		}
			
		if (tls_config_set_protocols(tls_config, protocols) < 0) {
			dolog(LOG_ERR, "tls_config_set_protocols()\n");
			ddd_shutdown();
			exit(1);
		}
	

		if (tls_config_set_ciphers(tls_config, tls_ciphers) < 0) {
			dolog(LOG_ERR, "tls_config_set_ciphers()\n");
			ddd_shutdown();
			exit(1);
		}
	
		if (! tls_certfile || tls_config_set_cert_file(tls_config,
			tls_certfile) < 0) {
			dolog(LOG_ERR, "tls_config_set_cert_file()\n");
			ddd_shutdown();
			exit(1);
		}
		
		if (! tls_keyfile || tls_config_set_key_file(tls_config,
			tls_keyfile) < 0) {
			dolog(LOG_ERR, "tls_config_set_key_file()\n");
			ddd_shutdown();
			exit(1);
		}

		tls_config_verify_client_optional(tls_config);

		
		if (tls_configure(cfg->ctx, tls_config) < 0) {
			dolog(LOG_ERR, "tls_configure: %s\n", tls_error(cfg->ctx));
			ddd_shutdown();
			exit(1);
		}

		tls_config_clear_keys(tls_config);

#if defined __OpenBSD__ || defined __Linux__
		freezero(tls_certfile, strlen(tls_certfile));
		freezero(tls_keyfile, strlen(tls_keyfile));
#else
		memset(tls_certfile, 0, strlen(tls_certfile));
		memset(tls_keyfile, 0, strlen(tls_keyfile));
		free(tls_certfile);
		free(tls_keyfile);
#endif
	}

#ifdef __OpenBSD__
	if (setrtable(rdomain) < 0) {
		dolog(LOG_INFO, "setrtable: %s\n", strerror(errno));
		ddd_shutdown();
		exit(1);
	}
#endif

	/* ratelimiting setup */
	if (ratelimit) {
		ratelimit_backlog = ratelimit_packets_per_second * 2;
		rptr = rrlimit_setup(ratelimit_backlog);
		if (rptr == NULL) {
			dolog(LOG_INFO, "ratelimiting error\n");
			ddd_shutdown();
			exit(1);
		}
	}

	pw = getpwnam(DEFAULT_PRIVILEGE);
	if (pw == NULL) {
		dolog(LOG_INFO, "getpwnam: %s\n", strerror(errno));
		ddd_shutdown();
		exit(1);
	}

	if (bcount > DEFAULT_SOCKET) {
		dolog(LOG_INFO, "not enough sockets available\n");
		ddd_shutdown();
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
				ddd_shutdown();
				exit (1);
        		}

			res = res0;

			udp[i] = bind_this_res(res, 0);
			memcpy((void *)&cfg->ss[i], (void *)res->ai_addr, res->ai_addrlen);

			if (res->ai_family == AF_INET) {
				on = 1;
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
				ddd_shutdown();
				exit (1);
        		}

			res = res0;

			if ((tcp[i] = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
				dolog(LOG_INFO, "tcp socket: %s\n", strerror(errno));
				ddd_shutdown();
				exit(1);
			}
			if (setsockopt(tcp[i], SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
				dolog(LOG_INFO, "setsockopt: %s\n", strerror(errno));
				ddd_shutdown();
				exit(1);
			} 
			if (setsockopt(tcp[i], SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0) {
				dolog(LOG_INFO, "setsockopt: %s\n", strerror(errno));
				ddd_shutdown();
				exit(1);
			} 
#ifdef __FreeBSD__
			if (cap_enter() < 0) {
				dolog(LOG_ERR, "cap_enter: %s\n", strerror(errno));
				ddd_shutdown();
				exit(1);
			}

			cap_rights_init(&rights, CAP_BIND, CAP_LISTEN, CAP_ACCEPT, CAP_READ, CAP_WRITE, CAP_EVENT, CAP_SETSOCKOPT, CAP_CONNECT, CAP_FCNTL, CAP_GETPEERNAME);
			if (cap_rights_limit(tcp[i], &rights) < 0) {
				dolog(LOG_ERR, "cap_rights_limit: %s\n", strerror(errno));
				ddd_shutdown();
				exit(1);
			}
#endif
			if (bind(tcp[i], res->ai_addr, res->ai_addrlen) < 0) {
				dolog(LOG_INFO, "tcp bind: %s\n", strerror(errno));
				ddd_shutdown();
				exit(1);
			}

			/* tls below */
			if (tls) {
				hints.ai_socktype = SOCK_STREAM;
				hints.ai_protocol = IPPROTO_TCP;
				hints.ai_flags = AI_NUMERICHOST;

				snprintf(buf, sizeof(buf) - 1, "%u", tls_port);

				if ((gai_error = getaddrinfo(bind_list[i], buf, &hints, &res0)) != 0) {
					dolog(LOG_INFO, "getaddrinfo: %s\n", gai_strerror(gai_error));
					ddd_shutdown();
					exit (1);
				}

				res = res0;

				if ((tlss[i] = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
					dolog(LOG_INFO, "tls socket: %s\n", strerror(errno));
					ddd_shutdown();
					exit(1);
				}
				if (setsockopt(tlss[i], SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
					dolog(LOG_INFO, "setsockopt: %s\n", strerror(errno));
					ddd_shutdown();
					exit(1);
				} 
				if (setsockopt(tlss[i], SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0) {
					dolog(LOG_INFO, "setsockopt: %s\n", strerror(errno));
					ddd_shutdown();
					exit(1);
				} 
#ifdef __FreeBSD__
				if (cap_enter() < 0) {
					dolog(LOG_ERR, "cap_enter: %s\n", strerror(errno));
					ddd_shutdown();
					exit(1);
				}

				cap_rights_init(&rights, CAP_BIND, CAP_LISTEN, CAP_ACCEPT, CAP_READ, CAP_WRITE, CAP_EVENT, CAP_SETSOCKOPT, CAP_CONNECT, CAP_FCNTL, CAP_GETPEERNAME);
				if (cap_rights_limit(tlss[i], &rights) < 0) {
					dolog(LOG_ERR, "cap_rights_limit: %s\n", strerror(errno));
					ddd_shutdown();
					exit(1);
				}
#endif
				if (bind(tlss[i], res->ai_addr, res->ai_addrlen) < 0) {
					dolog(LOG_INFO, "tls bind: %s\n", strerror(errno));
					ddd_shutdown();
					exit(1);
				}

			}

			if (axfrport && axfrport != port) {
				populate_zone(db);
				/* axfr port below */
				hints.ai_socktype = SOCK_STREAM;
				hints.ai_protocol = IPPROTO_TCP;
				hints.ai_flags = AI_NUMERICHOST;

				snprintf(buf, sizeof(buf) - 1, "%u", axfrport);

				if ((gai_error = getaddrinfo(bind_list[i], buf, &hints, &res0)) != 0) {
					dolog(LOG_INFO, "getaddrinfo: %s\n", gai_strerror(gai_error));
					ddd_shutdown();
					exit (1);
				}

				res = res0;

				if ((afd[i] = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
					dolog(LOG_INFO, "axfr socket: %s\n", strerror(errno));
					ddd_shutdown();
					exit(1);
				}
#ifdef __FreeBSD__
				cap_rights_init(&rights, CAP_BIND, CAP_LISTEN, CAP_ACCEPT, CAP_READ, CAP_WRITE, CAP_EVENT, CAP_SETSOCKOPT, CAP_CONNECT, CAP_FCNTL, CAP_GETPEERNAME);

				if (cap_rights_limit(afd[i], &rights) < 0) {
					dolog(LOG_ERR, "cap_rights_limit: %s\n", strerror(errno));
					ddd_shutdown();
					exit(1);
				}
#endif
				if (setsockopt(afd[i], SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
					dolog(LOG_INFO, "setsockopt: %s\n", strerror(errno));
					ddd_shutdown();
					exit(1);
				} 
				if (setsockopt(afd[i], SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0) {
					dolog(LOG_INFO, "setsockopt: %s\n", strerror(errno));
					ddd_shutdown();
					exit(1);
				} 
				if (bind(afd[i], res->ai_addr, res->ai_addrlen) < 0) {
					dolog(LOG_INFO, "axfr bind: %s\n", strerror(errno));
					ddd_shutdown();
					exit(1);
				}

				if ((uafd[i] = socket(res->ai_family, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
					dolog(LOG_INFO, "axfr udp socket: %s\n", strerror(errno));
					ddd_shutdown();
					exit(1);
				}
#ifdef __FreeBSD__
				cap_rights_init(&rights, CAP_BIND, CAP_LISTEN, CAP_ACCEPT, CAP_READ, CAP_WRITE, CAP_EVENT, CAP_SETSOCKOPT, CAP_CONNECT, CAP_FCNTL, CAP_GETPEERNAME);

				if (cap_rights_limit(uafd[i], &rights) < 0) {
					dolog(LOG_ERR, "cap_rights_limit: %s\n", strerror(errno));
					ddd_shutdown();
					exit(1);
				}
#endif
				if (bind(uafd[i], res->ai_addr, res->ai_addrlen) < 0) {
					dolog(LOG_INFO, "axfr udp socket bind: %s\n", strerror(errno));
					ddd_shutdown();
					exit(1);
				}
			} else if (axfrport && axfrport == port) {
				populate_zone(db);
				afd[i] = -1;
			}

		} /* for .. bcount */

	} else {
		if (getifaddrs(&ifap) < 0) {
			dolog(LOG_INFO, "getifaddrs\n");
			ddd_shutdown();
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

			/* ifa_addrs can be NULL */
			if (pifap->ifa_addr == NULL) {
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

			udp[i] = bind_this_pifap(pifap, 0, salen);
			memcpy((void *)&cfg->ss[i], (void *)pifap->ifa_addr, salen);

			if (pifap->ifa_addr->sa_family == AF_INET) {
				on = 1;
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
				ddd_shutdown();
				exit(1);
			}
#ifdef __FreeBSD__
				cap_rights_init(&rights, CAP_BIND, CAP_LISTEN, CAP_ACCEPT, CAP_READ, CAP_WRITE, CAP_EVENT, CAP_SETSOCKOPT, CAP_CONNECT, CAP_FCNTL, CAP_GETPEERNAME);

				if (cap_rights_limit(tcp[i], &rights) < 0) {
					dolog(LOG_ERR, "cap_rights_limit: %s\n", strerror(errno));
					ddd_shutdown();
					exit(1);
				}
#endif
       			if (setsockopt(tcp[i], SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
				dolog(LOG_INFO, "setsockopt: %s\n", strerror(errno));
				ddd_shutdown();
				exit(1);
			} 
			if (setsockopt(tcp[i], SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0) {
				dolog(LOG_INFO, "setsockopt: %s\n", strerror(errno));
				ddd_shutdown();
				exit(1);
			} 
			
			if (bind(tcp[i], (struct sockaddr *)pifap->ifa_addr, salen) < 0) {
				dolog(LOG_INFO, "tcp bind: %s\n", strerror(errno));
				ddd_shutdown();
				exit(1);
			}		

			if (tls) {
				if (pifap->ifa_addr->sa_family == AF_INET) {
					sin = (struct sockaddr_in *)pifap->ifa_addr;
					sin->sin_port = htons(tls_port);
				} else if (pifap->ifa_addr->sa_family == AF_INET6) {
					sin6 = (struct sockaddr_in6 *)pifap->ifa_addr;
					sin6->sin6_port = htons(tls_port);
				} else {
					dolog(LOG_DEBUG, "unknown address family %d\n", pifap->ifa_addr->sa_family);
					ddd_shutdown();
					exit(1);
				}

				if ((tlss[i] = socket(pifap->ifa_addr->sa_family, SOCK_STREAM, IPPROTO_TCP)) < 0) {
					dolog(LOG_INFO, "tls socket: %s\n", strerror(errno));
					ddd_shutdown();
					exit(1);
				}
#ifdef __FreeBSD__
					cap_rights_init(&rights, CAP_BIND, CAP_LISTEN, CAP_ACCEPT, CAP_READ, CAP_WRITE, CAP_EVENT, CAP_SETSOCKOPT, CAP_CONNECT, CAP_FCNTL, CAP_GETPEERNAME);

					if (cap_rights_limit(tlss[i], &rights) < 0) {
						dolog(LOG_ERR, "cap_rights_limit: %s\n", strerror(errno));
						ddd_shutdown();
						exit(1);
					}
#endif
				if (setsockopt(tlss[i], SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
					dolog(LOG_INFO, "setsockopt: %s\n", strerror(errno));
					ddd_shutdown();
					exit(1);
				} 
				if (setsockopt(tlss[i], SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0) {
					dolog(LOG_INFO, "setsockopt: %s\n", strerror(errno));
					ddd_shutdown();
					exit(1);
				} 
				
				if (bind(tlss[i], (struct sockaddr *)pifap->ifa_addr, salen) < 0) {
					dolog(LOG_INFO, "tcp bind: %s\n", strerror(errno));
					ddd_shutdown();
					exit(1);
				}		

			}

			/* axfr socket */
			if (axfrport && axfrport != port) {
				populate_zone(db);
				if ((afd[i] = socket(pifap->ifa_addr->sa_family, SOCK_STREAM, IPPROTO_TCP)) < 0) {
					dolog(LOG_INFO, "tcp socket: %s\n", strerror(errno));
					ddd_shutdown();
					exit(1);
				}
#ifdef __FreeBSD__
				cap_rights_init(&rights, CAP_BIND, CAP_LISTEN, CAP_ACCEPT, CAP_READ, CAP_WRITE, CAP_EVENT, CAP_SETSOCKOPT, CAP_CONNECT, CAP_FCNTL, CAP_GETPEERNAME);

				if (cap_rights_limit(afd[i], &rights) < 0) {
					dolog(LOG_ERR, "cap_rights_limit: %s\n", strerror(errno));
					ddd_shutdown();
					exit(1);
				}
#endif
				if (setsockopt(afd[i], SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
					dolog(LOG_INFO, "setsockopt: %s\n", strerror(errno));
					ddd_shutdown();
					exit(1);
				} 
				if (setsockopt(afd[i], SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0) {
					dolog(LOG_INFO, "setsockopt: %s\n", strerror(errno));
					ddd_shutdown();
					exit(1);
				} 

				((struct sockaddr_in *)pifap->ifa_addr)->sin_port = htons(axfrport);
				
				if (bind(afd[i], (struct sockaddr *)pifap->ifa_addr, salen) < 0) {
					dolog(LOG_INFO, "tcp bind: %s\n", strerror(errno));
					ddd_shutdown();
					exit(1);
				}
				if ((uafd[i] = socket(pifap->ifa_addr->sa_family, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
					dolog(LOG_INFO, "axfr udp socket: %s\n", strerror(errno));
					ddd_shutdown();
					exit(1);
				}
				if (bind(uafd[i], (struct sockaddr *)pifap->ifa_addr, salen) < 0) {
					dolog(LOG_INFO, "udp axfr bind: %s\n", strerror(errno));
					ddd_shutdown();
					exit(1);
				}
			} else if (axfrport && axfrport == port) {
				populate_zone(db);
				afd[i] = -1;
			}

		} /* AF_INET */

		if (i >= DEFAULT_SOCKET) {
			dolog(LOG_INFO, "not enough sockets available\n");
			ddd_shutdown();
			exit(1);
		}
	} /* if bflag? */

	if ((cfg->raw[0] = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
		dolog(LOG_INFO, "raw0 socket: %s\n", strerror(errno));
		ddd_shutdown();
		exit(1);
	}
	shutdown(cfg->raw[0], SHUT_RD);
#ifdef __FreeBSD__
	cap_rights_init(&rights, CAP_BIND, CAP_WRITE,  CAP_EVENT,  CAP_CONNECT);

	if (cap_rights_limit(cfg->raw[0], &rights) < 0) {
		dolog(LOG_ERR, "cap_rights_limit: %s\n", strerror(errno));
		ddd_shutdown();
		exit(1);
	}
#endif
	if ((cfg->raw[1] = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP)) < 0) {
		dolog(LOG_INFO, "raw1 socket: %s\n", strerror(errno));
		ddd_shutdown();
		exit(1);
	}
	shutdown(cfg->raw[1], SHUT_RD);
	cfg->port = port;

#ifdef __FreeBSD__
	cap_rights_init(&rights, CAP_BIND, CAP_WRITE, CAP_EVENT, CAP_CONNECT);

	if (cap_rights_limit(cfg->raw[1], &rights) < 0) {
		dolog(LOG_ERR, "cap_rights_limit: %s\n", strerror(errno));
		ddd_shutdown();
		exit(1);
	}
#endif

#if __OpenBSD__
	if (unveil(DELPHINUS_RZONE_PATH, "rwc")  < 0) {
		perror("unveil");
		ddd_shutdown();
		exit(1);
	}
	/* XXX pjp */
	if (strcmp(pw->pw_dir, DELPHINUS_RZONE_PATH) == 0) {
		if (unveil(pw->pw_dir, "wc") < 0) {
			perror("unveil");
			ddd_shutdown();
			exit(1);
		}
	} else {
		if (unveil(pw->pw_dir, "r") < 0) {
			perror("unveil");
			ddd_shutdown();
			exit(1);
		}
	}
#endif


	/*
	 * add signals
	 */

	signal(SIGPIPE, SIG_IGN);

	signal(SIGTERM, ddd_signal);
	signal(SIGINT, ddd_signal);
	signal(SIGQUIT, ddd_signal);

	/* 
	 * start our axfr process 
	 */

	if (axfrport) {	
		switch (pid = fork()) {
		case -1:
			dolog(LOG_ERR, "fork() failed: %s\n", strerror(errno));
			ddd_shutdown();
			exit(1);
		case 0:
			ibuf = register_cortex(&cortex_ibuf, MY_IMSG_AXFR);
			if (ibuf == NULL) {
				ddd_shutdown();
				exit(1);
			}

			/* chroot to the drop priv user home directory */
#ifdef DEFAULT_LOCATION
			if (drop_privs(DEFAULT_LOCATION, pw) < 0) {
#else
			if (drop_privs(pw->pw_dir, pw) < 0) {
#endif
				dolog(LOG_INFO, "axfr dropping privileges\n", strerror(errno));
				ddd_shutdown();
				exit(1);
			}
#if __OpenBSD__
			if (pledge("stdio inet proc id sendfd recvfd unveil", NULL) < 0) {
				perror("pledge");
				ddd_shutdown();
				exit(1);
			}
#endif

			/* close descriptors that we don't need */
			for (j = 0; j < i; j++) {
				close(tcp[j]);
				close(udp[j]);
				if (tls)
					close(tlss[j]);
				if (axfrport && axfrport != port)
					close(uafd[j]);
				else
					cfg->axfr[j] = uafd[j];

				if (axfrport && axfrport != port)
					cfg->axfrt[j] = afd[j];

			}

			cfg->sockcount = i;

			close(cfg->raw[0]);
			close(cfg->raw[1]);

			setproctitle("AXFR engine [%s]", (identstring != NULL ? identstring : ""));
			axfrloop(cfg, ident, db, ibuf, &cortex_ibuf);
			/* NOTREACHED */
			exit(1);
		default:
			/* close axfr descriptors, they aren't needed here */
			for (j = 0; j < i; j++) {
				if (axfrport && axfrport != port)
					close(afd[j]);
			}
			break;
		}
	
	} /* axfrport */
	
	/* raxfr */
	if (raxfrflag) {
		switch (pid = fork()) {
		case -1:
			dolog(LOG_ERR, "fork() failed: %s\n", strerror(errno));
			ddd_shutdown();
			exit(1);
		case 0:
			ibuf = register_cortex(&cortex_ibuf, MY_IMSG_RAXFR);
			if (ibuf == NULL) {
				ddd_shutdown();
				exit(1);
			}

			/* chroot to the drop priv user home directory */
			if (drop_privs(DELPHINUS_RZONE_PATH, pw) < 0) {
				dolog(LOG_INFO, "raxfr dropping privileges failed", strerror(errno));
				ddd_shutdown();
				exit(1);
			}

#if __OpenBSD__
			if (unveil("/replicant", "rwc") < 0) {
				perror("unveil");
				ddd_shutdown();
				exit(1);
			}

			if (pledge("stdio inet proc id sendfd recvfd unveil cpath wpath rpath", NULL) < 0) {
				perror("pledge");
				ddd_shutdown();
				exit(1);
			}
#endif

			/* close descriptors that we don't need */
			for (j = 0; j < i; j++) {
				close(tcp[j]);
				close(udp[j]);

				if (tls)
					close(tlss[j]);

				if (axfrport && axfrport != port)
					close(uafd[j]);
			}
			close(cfg->raw[0]);
			close(cfg->raw[1]);

			setproctitle("Replicant engine [%s]", (identstring != NULL ? identstring : ""));

			replicantloop(db, ibuf);

			/* NOTREACHED */
			exit(1);

		default:
			break;
		}

	} /* raxfrflag */
	/* start our forwarding process */
	
	if (forward) {	
		/* initialize the only global shared memory segment */
		shptr = sm_init(SHAREDMEMSIZE, sizeof(struct sf_imsg));
		cfg->shm[SM_FORWARD].shptr = shptr;
		cfg->shm[SM_FORWARD].shptrsize = sm_size(SHAREDMEMSIZE, sizeof(struct sf_imsg));
		sm_zebra(shptr, SHAREDMEMSIZE, sizeof(struct sf_imsg));

		switch (pid = fork()) {
		case -1:
			dolog(LOG_ERR, "fork() failed: %s\n", strerror(errno));
			ddd_shutdown();
			exit(1);
		case 0:
			ibuf = register_cortex(&cortex_ibuf, MY_IMSG_FORWARD);
			if (ibuf == NULL) {
				ddd_shutdown();
				exit(1);
			}

			/* initialize shared memory for forward here */
			shptr = sm_init(SHAREDMEMSIZE, sizeof(struct rr_imsg));
			cfg->shm[SM_RESOURCE].shptr = shptr;
			cfg->shm[SM_RESOURCE].shptrsize = sm_size(SHAREDMEMSIZE, sizeof(struct rr_imsg));
			sm_zebra(shptr, SHAREDMEMSIZE, sizeof(struct rr_imsg));

			shptr = sm_init(SHAREDMEMSIZE3, sizeof(struct pkt_imsg));
			cfg->shm[SM_PACKET].shptr = shptr;
			cfg->shm[SM_PACKET].shptrsize = sm_size(SHAREDMEMSIZE3, sizeof(struct pkt_imsg));
			sm_zebra(shptr, SHAREDMEMSIZE3, sizeof(struct pkt_imsg));


			/* raise fd limits to hard limit */

			if (getrlimit(RLIMIT_NOFILE, &rlimits) != -1) {

				rlimits.rlim_cur = rlimits.rlim_max;
				if (setrlimit(RLIMIT_NOFILE, &rlimits) == -1) {
					dolog(LOG_INFO, "could not raise fd limit in forward process\n");
				}
			}
#ifdef __OpenBSD__
			/* set up rdomain if specified as a forwarding option */
			if (setrtable(forward_rdomain) < 0) {
				dolog(LOG_INFO, "forward setrtable: %s\n", strerror(errno));
				ddd_shutdown();
				exit(1);
			}
#endif

			/* chroot to the drop priv user home directory */
#ifdef DEFAULT_LOCATION
			if (drop_privs(DEFAULT_LOCATION, pw) < 0) {
#else
			if (drop_privs(pw->pw_dir, pw) < 0) {
#endif
				dolog(LOG_INFO, "forward dropping privileges\n", strerror(errno));
				ddd_shutdown();
				exit(1);
			}
#if __OpenBSD__
			if (unveil("/", "") < 0) {
				dolog(LOG_INFO, "unveil locking failed: %s\n", strerror(errno));
				ddd_shutdown();
				exit(1);
			}

			if (unveil(NULL, NULL) < 0) {
				dolog(LOG_INFO, "unveil locking failed: %s\n", strerror(errno));
				ddd_shutdown();
				exit(1);
			}
			if (pledge("stdio inet proc id sendfd recvfd", NULL) < 0) {
				perror("pledge");
				ddd_shutdown();
				exit(1);
			}
#endif

			/* close descriptors that we don't need */
			for (j = 0; j < i; j++) {
				close(tcp[j]);
				close(udp[j]);

				if (tls)
					close(tlss[j]);

				if (axfrport && axfrport != port)
					close(uafd[j]);

			}

			cfg->sockcount = i;
			cfg->db = db;

			/* shptr has no business in parse process */
#if __OpenBSD__
			minherit(cfg->shm[SM_FORWARD].shptr, 
				cfg->shm[SM_FORWARD].shptrsize,
				MAP_INHERIT_NONE);
#endif

			setproctitle("FORWARD engine [%s]", (identstring != NULL ? identstring : ""));
			forwardloop(db, cfg, ibuf, &cortex_ibuf);
			/* NOTREACHED */
			exit(1);
		default:
			break;
		}
	
	} /* forward */

	close(cfg->raw[0]);
	close(cfg->raw[1]);

	/* the rest of the daemon goes on in TCP and UDP loops */

	shptr = sm_init(SHAREDMEMSIZE, sizeof(struct pq_imsg));
	cfg->shm[SM_PARSEQUESTION].shptr = shptr;
	cfg->shm[SM_PARSEQUESTION].shptrsize = sm_size(SHAREDMEMSIZE, sizeof(struct pq_imsg));
	sm_zebra(shptr, SHAREDMEMSIZE, sizeof(struct pq_imsg));

	shptr = sm_init(SHAREDMEMSIZE3, sizeof(struct pkt_imsg));
	cfg->shm[SM_INCOMING].shptr = shptr;
	cfg->shm[SM_INCOMING].shptrsize = sm_size(SHAREDMEMSIZE3, sizeof(struct pkt_imsg));
	sm_zebra(shptr, SHAREDMEMSIZE3, sizeof(struct pkt_imsg));

#ifdef DEFAULT_LOCATION
	if (drop_privs(DEFAULT_LOCATION, pw) < 0) {
#else
	if (drop_privs(pw->pw_dir, pw) < 0) {
#endif
		dolog(LOG_INFO, "dropping privileges failed\n");
		ddd_shutdown();
		exit(1);
	}
#if __OpenBSD__
	if (unveil(NULL, NULL) < 0) {
		dolog(LOG_INFO, "unveil locking failed: %s\n", strerror(errno));
		ddd_shutdown();
		exit(1);
	}
	if (pledge("stdio inet proc id sendfd recvfd", NULL) < 0) {
		perror("pledge");
		ddd_shutdown();
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
		switch (pid = fork()) {
		case 0:
			cfg->pid = getpid();
			cfg->nth = n;
			cfg->sockcount = i;
			cfg->db = db;
			for (i = 0; i < cfg->sockcount; i++) {
				cfg->udp[i] = udp[i];
				cfg->tcp[i] = tcp[i];

				if (tls)
					cfg->tls[i] = tlss[i];

				if (axfrport && axfrport != port)
					cfg->axfr[i] = uafd[i];

				cfg->ident[i] = strdup(ident[i]);
	
			}

			setproctitle("child %d pid %d [%s]", n, cfg->pid, 
				(identstring != NULL ? identstring : ""));

			(void)mainloop(cfg, &cortex_ibuf);

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

		if (tls)
			cfg->tls[i] = tlss[i];

		if (axfrport && axfrport != port)
			cfg->axfr[i] = uafd[i];

		cfg->ident[i] = strdup(ident[i]);
	}

	(void)mainloop(cfg, &cortex_ibuf);

	/* NOTREACHED */
	return (0);
}

/*
 * BUILD_REPLY - a function that populates struct reply from arguments, doesn't
 * 		 return anything.  This replaces the alias BUILD_REPLY.
 *
 */

void
build_reply(struct sreply *reply, int so, char *buf, int len, struct question *q, struct sockaddr *sa, socklen_t slen, struct rbtree *rbt1, struct rbtree *rbt2, uint8_t region, int istcp, int deprecated0, char *replybuf, struct tls *ctx)
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
	reply->replybuf = replybuf;
	reply->ctx = ctx;

	return;
}
		

/*
 * The primary process, waits to be killed, if any other processes are killed
 * and they indicate shutdown through the shared memory segment it will kill
 * the rest of processes in the parent group.
 */

void 
setup_primary(ddDB *db, char **av, char *socketpath, struct imsgbuf *ibuf)
{
	pid_t pid;
	int sel, max = 0;

	ssize_t n;
	fd_set rset;

	struct timeval tv;
	struct imsg imsg;
#ifdef __FreeBSD__
        cap_rights_t rights;
#endif

#if __OpenBSD__
	if (unveil(socketpath, "rwc")  < 0) {
		perror("unveil");
		ddd_shutdown();
		exit(1);
	}
	if (unveil("/usr/local/sbin/delphinusdnsd", "rx")  < 0) {
		perror("unveil");
		ddd_shutdown();
		exit(1);
	}
	if (unveil(NULL, NULL) < 0) {
		perror("unveil");
		ddd_shutdown();
		exit(1);
	}
	if (pledge("stdio wpath cpath exec proc", NULL) < 0) {
		perror("pledge");
		ddd_shutdown();
		exit(1);
	}
#endif
#ifdef __FreeBSD__
	cap_rights_init(&rights, CAP_WRITE, CAP_READ, CAP_EVENT);

	if (cap_rights_limit(ibuf->fd, &rights) < 0) {
		dolog(LOG_ERR, "cap_rights_limit: %s\n", strerror(errno));
		ddd_shutdown();
		exit(1);
	}
#endif
#ifndef NO_SETPROCTITLE
	setproctitle("primary [%s]", (identstring != NULL ? identstring : ""));
#endif

	pid = getpid();

	signal(SIGTERM, primary_shutdown);
	signal(SIGINT, primary_shutdown);
	signal(SIGQUIT, primary_shutdown);
	signal(SIGHUP, primary_reload);

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
				primary_shutdown(SIGTERM);
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
				if (munmap(ptr, sizeof(pid_t)) < 0) {
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
				dolog(LOG_INFO, "sigpipe on child?  delphinusdnsd primary process exiting.\n");
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
#if DEBUG
						dolog(LOG_INFO, "received shutdown from cortex\n");
#endif
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
 *  primary_shutdown - unlink pid file and kill parent group
 */

void
primary_shutdown(int sig)
{
	msig = sig;
	mshutdown = 1;
}

/* 
 * ddd_signal - delphinusdnsd got a signal, call ddd_shutdown and exit..
 */

void
ddd_signal(int sig)
{
	ddd_shutdown();
	dolog(LOG_INFO, "shutting down on signal\n");
	exit(1);
}

/*
 * primary_reload - reload the delphinusdnsd system
 */

void
primary_reload(int sig)
{
	reload = 1;
}

void
parseloop(struct cfg *cfg, struct imsgbuf *ibuf, int istcp)
{
	struct imsg imsg;
	struct imsgbuf *mybuf = ibuf;
	struct dns_header *dh = NULL;
	struct question *question = NULL;
	struct parsequestion pq;
	struct pkt_imsg *incoming0;
	char *packet;
	fd_set rset;
	uint64_t key;
	int sel, i;
	int incoming_offset = 0;
	int fd = mybuf->fd;
	ssize_t n, datalen;
	struct pq_imsg *pq0;
	int clen = 0;
#ifdef __FreeBSD__
        cap_rights_t rights;
#endif

#if __OpenBSD__
	if (pledge("stdio", NULL) < 0) {
		perror("pledge");
		ddd_shutdown();
		exit(1);
	}
#endif
#ifdef __FreeBSD__
	cap_rights_init(&rights, CAP_WRITE, CAP_READ , CAP_EVENT);

	if (cap_rights_limit(fd, &rights) < 0) {
		dolog(LOG_ERR, "cap_rights_limit: %s\n", strerror(errno));
		ddd_shutdown();
		exit(1);
	}
#endif

	packet = calloc(2, 65536); 
	if (packet == NULL) {
		dolog(LOG_ERR, "calloc: %m");
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

				switch (imsg.hdr.type) {
				case IMSG_PARSE_MESSAGE:
					if (datalen != sizeof(uint64_t)) {
						dolog(LOG_ERR, "datalen of imsg is not sizeof uint64_t!\n");
						goto out;
					}

					memset(&pq, 0, sizeof(struct parsequestion));
					memcpy((char *)&key, imsg.data, datalen);
					incoming_offset = (key & 0xffff);
					incoming0 = (struct pkt_imsg *)&cfg->shm[SM_INCOMING].shptr[0];
					incoming0 += incoming_offset;
					datalen = unpack32((char *)&incoming0->u.i.buflen);
					memcpy((char *)packet,
						(char *)&incoming0->u.i.buf, datalen);
#if notyet
						dolog(LOG_INFO, "internal SHAREDMEM3 decrypt failed\n");
						goto out;
					}
#endif
	
					datalen = unpack32((char *)&incoming0->u.i.buflen);

					sm_lock(cfg->shm[SM_INCOMING].shptr, 
						cfg->shm[SM_INCOMING].shptrsize);
					pack32((char *)&incoming0->u.i.read, 1);
					sm_unlock(cfg->shm[SM_INCOMING].shptr, 
						cfg->shm[SM_INCOMING].shptrsize);


					arc4random_buf((char *)&key, sizeof(uint64_t));
					key <<= 16;		/* XXX i cannot be bigger than 65535! */

					if (datalen > (65535 + 2)) {
						pq.rc = PARSE_RETURN_NAK;
						sm_lock(cfg->shm[SM_PARSEQUESTION].shptr, 
								cfg->shm[SM_PARSEQUESTION].shptrsize);

						pq0 = (struct pq_imsg *)&cfg->shm[SM_PARSEQUESTION].shptr[0];
						for (i = 0; i < SHAREDMEMSIZE; i++, pq0++) {
							if (unpack32((char *)&pq0->u.s.read) == 1) {
								key = ((key & 0xffffffffffff0000ULL) + i);
								memcpy((char *)&pq0->pqi_pq, (char *)&pq, sizeof(struct parsequestion) - PQ_PAD);
								pack32((char *)&pq0->pqi_clen, clen);
								pack32((char *)&pq0->u.s.read, 0);
								break;
							}
						}
						sm_unlock(cfg->shm[SM_PARSEQUESTION].shptr, 
								cfg->shm[SM_PARSEQUESTION].shptrsize);
						if (i == SHAREDMEMSIZE) {
							dolog(LOG_INFO, "increase SHAREDMEMSIZE for pq_imsg!!!\n");
							break;

						} else {
							imsg_compose(mybuf, IMSG_PARSEREPLY_MESSAGE, 0, 0, -1, (char *)&key, sizeof(key));
							msgbuf_write(&mybuf->w);
						}
						break;
					}

					if (datalen < sizeof(struct dns_header)) {
						pq.rc = PARSE_RETURN_NAK;
						sm_lock(cfg->shm[SM_PARSEQUESTION].shptr, 
							cfg->shm[SM_PARSEQUESTION].shptrsize);

						pq0 = (struct pq_imsg *)&cfg->shm[SM_PARSEQUESTION].shptr[0];
						for (i = 0; i < SHAREDMEMSIZE; i++, pq0++) {
							if (unpack32((char *)&pq0->u.s.read) == 1) {
								key = ((key & 0xffffffffffff0000ULL) + i);
								memcpy((char *)&pq0->pqi_pq, (char *)&pq, sizeof(struct parsequestion) - PQ_PAD);
								pack32((char *)&pq0->pqi_clen, clen);
								pack32((char *)&pq0->u.s.read, 0);
								break;
							}
						}
						sm_unlock(cfg->shm[SM_PARSEQUESTION].shptr, 
							cfg->shm[SM_PARSEQUESTION].shptrsize);
						if (i == SHAREDMEMSIZE) {
							dolog(LOG_INFO, "increase SHAREDMEMSIZE for pq_imsg!!!\n");
							break;

						} else {
							imsg_compose(mybuf, IMSG_PARSEREPLY_MESSAGE, 0, 0, -1, (char *)&key, sizeof(key));
							msgbuf_write(&mybuf->w);
						}
						break;
					}
					dh = (struct dns_header *)packet;

					if ((ntohs(dh->query) & DNS_REPLY)) {
						/* we want to reply with a NAK here */
						pq.rc = PARSE_RETURN_NOTAQUESTION;
						sm_lock(cfg->shm[SM_PARSEQUESTION].shptr, 
							cfg->shm[SM_PARSEQUESTION].shptrsize);

						pq0 = (struct pq_imsg *)&cfg->shm[SM_PARSEQUESTION].shptr[0];
						for (i = 0; i < SHAREDMEMSIZE; i++, pq0++) {
							if (unpack32((char *)&pq0->u.s.read) == 1) {
								key = ((key & 0xffffffffffff0000ULL) + i);
								memcpy((char *)&pq0->pqi_pq, (char *)&pq, sizeof(struct parsequestion) - PQ_PAD);
								pack32((char *)&pq0->pqi_clen, clen);
								pack32((char *)&pq0->u.s.read, 0);
								break;
							}
						}
						sm_unlock(cfg->shm[SM_PARSEQUESTION].shptr, 
							cfg->shm[SM_PARSEQUESTION].shptrsize);
						if (i == SHAREDMEMSIZE) {
							dolog(LOG_INFO, "increase SHAREDMEMSIZE for pq_imsg!!!\n");
							break;
						} else {
							imsg_compose(mybuf, IMSG_PARSEREPLY_MESSAGE, 0, 0, -1, (char *)&key, sizeof(key));
							msgbuf_write(&mybuf->w);
						}
						break;
					}

					/* 
					 * if questions aren't exactly 1 then reply NAK
					 */

					if (ntohs(dh->question) != 1) {
						/* XXX reply nak here */
						pq.rc = PARSE_RETURN_NOQUESTION;
						sm_lock(cfg->shm[SM_PARSEQUESTION].shptr, 
								cfg->shm[SM_PARSEQUESTION].shptrsize);

						pq0 = (struct pq_imsg *)&cfg->shm[SM_PARSEQUESTION].shptr[0];
						for (i = 0; i < SHAREDMEMSIZE; i++, pq0++) {
							if (unpack32((char *)&pq0->u.s.read) == 1) {
								key = ((key & 0xffffffffffff0000ULL) + i);
								memcpy((char *)&pq0->pqi_pq, (char *)&pq, sizeof(struct parsequestion) - PQ_PAD);
								pack32((char *)&pq0->pqi_clen, clen);
								pack32((char *)&pq0->u.s.read, 0);
								break;
							}
						}
						sm_unlock(cfg->shm[SM_PARSEQUESTION].shptr,
							cfg->shm[SM_PARSEQUESTION].shptrsize);
						if (i == SHAREDMEMSIZE) {
							dolog(LOG_INFO, "increase SHAREDMEMSIZE for pq_imsg!!!\n");
							break;
						} else {
							imsg_compose(mybuf, IMSG_PARSEREPLY_MESSAGE, 0, 0, -1, (char *)&key, sizeof(key));
							msgbuf_write(&mybuf->w);
						}
						break;
					}

					if ((question = build_question(packet, datalen, ntohs(dh->additional), NULL)) == NULL) {
						/* XXX reply nak here */
						pq.rc = PARSE_RETURN_MALFORMED;
						sm_lock(cfg->shm[SM_PARSEQUESTION].shptr, 
							cfg->shm[SM_PARSEQUESTION].shptrsize);

						pq0 = (struct pq_imsg *)&cfg->shm[SM_PARSEQUESTION].shptr[0];
						for (i = 0; i < SHAREDMEMSIZE; i++, pq0++) {
							if (unpack32((char *)&pq0->u.s.read) == 1) {
								key = ((key & 0xffffffffffff0000ULL) + i);
								memcpy((char *)&pq0->pqi_pq, (char *)&pq, sizeof(struct parsequestion) - PQ_PAD);
								pack32((char *)&pq0->pqi_clen, clen);
								pack32((char *)&pq0->u.s.read, 0);
								break;
							}
						}
						sm_unlock(cfg->shm[SM_PARSEQUESTION].shptr, 
							cfg->shm[SM_PARSEQUESTION].shptrsize);
						if (i == SHAREDMEMSIZE) {
							dolog(LOG_INFO, "increase SHAREDMEMSIZE for pq_imsg!!!\n");
						} else {
							imsg_compose(mybuf, IMSG_PARSEREPLY_MESSAGE, 0, 0, -1, (char *)&key, sizeof(key));
							msgbuf_write(&mybuf->w);
						}
						break;
					}
					
					memcpy(pq.name, question->hdr->name, question->hdr->namelen);
					memcpy(pq.original_name, question->hdr->original_name, question->hdr->namelen);
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
					memcpy((char *)&pq.cookie, (char *)&question->cookie, sizeof(struct dns_cookie));
					if (istcp)
						pq.tcpkeepalive = question->tcpkeepalive;
					else
						pq.tcpkeepalive = 0;
		

					/* put it in shared memory */
					sm_lock(cfg->shm[SM_PARSEQUESTION].shptr, 
						cfg->shm[SM_PARSEQUESTION].shptrsize);

					pq0 = (struct pq_imsg *)&cfg->shm[SM_PARSEQUESTION].shptr[0];
					for (i = 0; i < SHAREDMEMSIZE; i++, pq0++) {
						if (unpack32((char *)&pq0->u.s.read) == 1) {
							key = ((key & 0xffffffffffff0000ULL) + i);
							memcpy((char *)&pq0->pqi_pq, (char *)&pq, sizeof(struct parsequestion) - PQ_PAD);
							pack32((char *)&pq0->pqi_clen, clen);
							pack32((char *)&pq0->u.s.read, 0);
							break;
						}
					}
					if (i == SHAREDMEMSIZE) {
						dolog(LOG_INFO, "increase SHAREDMEMSIZE for pq_imsg!!!\n");
						sm_unlock(cfg->shm[SM_PARSEQUESTION].shptr, 
							cfg->shm[SM_PARSEQUESTION].shptrsize);

						free_question(question);
						break;
					} else {
						imsg_compose(mybuf, IMSG_PARSEREPLY_MESSAGE, 0, 0, -1, (char *)&key, sizeof(key));
						msgbuf_write(&mybuf->w);
					}
					sm_unlock(cfg->shm[SM_PARSEQUESTION].shptr, 
							cfg->shm[SM_PARSEQUESTION].shptrsize);
					/* send it */
					free_question(question);
					break;
				}
out:

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
convert_question(struct parsequestion *pq, int authoritative)
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
	
	q->hdr->name = calloc(1, pq->namelen);
	if (q->hdr->name == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		free(q->hdr);
		free(q);
		return NULL;
	}
	memcpy(q->hdr->name, pq->name, pq->namelen);

	q->hdr->original_name = calloc(1, pq->namelen);
	if (q->hdr->original_name == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		free(q->hdr->name);
		free(q->hdr);
		free(q);
		return NULL;
	}
	memcpy(q->hdr->original_name, pq->original_name, pq->namelen);
		
	q->hdr->namelen = pq->namelen;
	q->hdr->qtype = pq->qtype;
	q->hdr->qclass = pq->qclass;
	
	q->converted_name = strdup(pq->converted_name);
	if (q->converted_name == NULL) {
		dolog(LOG_INFO, "strdup: %s\n", strerror(errno));
		free(q->hdr->name);
		free(q->hdr->original_name);
		free(q->hdr);
		free(q);
		return NULL;
	}

	q->edns0len = pq->edns0len;
	q->ednsversion = pq->ednsversion;
	q->rd = pq->rd;
	q->aa = authoritative;
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
	q->rawsocket = 0;
	q->tcpkeepalive = pq->tcpkeepalive;

	memcpy((char *)&q->cookie, (char *)&pq->cookie, sizeof(struct dns_cookie));

	return (q);
}

void
setup_unixsocket(char *socketpath, struct imsgbuf *ibuf)
{

	ssize_t n;

	int datalen;
	int so, nso;
	int sel, max;
	socklen_t slen = sizeof(struct sockaddr_un);
	int len;
	char buf[512];
	char rbuf[512];
	struct imsg imsg;
	struct sockaddr_un sun, *psun;
	struct timeval tv;
	struct dddcomm *dc;
	struct passwd *pw;
	fd_set rset;
	pid_t idata;
#if __OpenBSD__
	gid_t gid;
	uid_t uid;
#endif

	setproctitle("unix controlling socket [%s]", 
		(identstring != NULL ? identstring : ""));

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlcpy(sun.sun_path, socketpath, sizeof(sun.sun_path)) >= sizeof(sun.sun_path)) {
		ddd_shutdown();
		for (int count=0;count < 10;) {
			sleep(1);
			count++;
		}
		exit(1);
	}
#ifndef __linux__
	sun.sun_len = SUN_LEN(&sun);
#endif

	/* only root, 0100 == nonexecute */
	if (umask(0177) < 0) {
		ddd_shutdown();
		exit(1);
	}

	so = socket(AF_UNIX, SOCK_STREAM, 0);
	if (so < 0) {
		ddd_shutdown();
		exit(1);
	}

	if (bind(so, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		ddd_shutdown();
		for (;;) {
			sleep(1);
		}
	}

	pw = getpwnam(DEFAULT_PRIVILEGE);
	if (pw == NULL) {
		perror("getpwnam");
		ddd_shutdown();
		exit(1);
	}

#ifdef DEFAULT_LOCATION
	if (drop_privs(DEFAULT_LOCATION, pw) < 0) {
#else
	if (drop_privs(pw->pw_dir, pw) < 0) {
#endif
		dolog(LOG_INFO, "dropping privileges failed in unix socket\n");
		ddd_shutdown();
		exit(1);
	}

	listen(so, 5);

#if __OpenBSD__
	if (pledge("stdio rpath wpath cpath unix proc", NULL) < 0) {
		perror("pledge");
		ddd_shutdown();
		exit(1);
	}
#endif

	max = 0;

	for (;;) {
		FD_ZERO(&rset);
		FD_SET(so, &rset);
		if (so > max)
			max = so;
#if 0
		FD_SET(ibuf->fd, &rset);
		if (ibuf->fd > max)
			max = ibuf->fd;
#endif

		sel = select(max + 1, &rset, NULL, NULL, NULL);
		if (sel < 0) {
			continue;
		}	

		if (FD_ISSET(so, &rset)) {
			slen = sizeof(struct sockaddr_un);
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

			len = recv(nso, rbuf, sizeof(rbuf), 0);
			if (len < 0 || len < sizeof(struct dddcomm)) {
				close(nso);
				continue;
			}

			dc = (struct dddcomm *)&rbuf[0];		
			if (dc->command == IMSG_RELOAD_MESSAGE || 
				dc->command == IMSG_SHUTDOWN_MESSAGE) {
				
				idata = getpid();
				imsg_compose(ibuf, dc->command, 
					0, 0, -1, &idata, sizeof(idata));
				msgbuf_write(&ibuf->w);
				/* exit here before but it caused sigpipes */
			} else if (dc->command == IMSG_DUMP_CACHE) {
				idata = getpid();
				imsg_compose(ibuf, dc->command, 
					0, 0, -1, &idata, sizeof(idata));
				msgbuf_write(&ibuf->w);

				for (;;) {
					tv.tv_sec = 2;
					tv.tv_usec = 0;

					FD_ZERO(&rset);
					FD_SET(ibuf->fd, &rset);

					sel = select(ibuf->fd + 1, &rset, NULL, NULL, &tv);
					if (sel <= 0)
						break;

					if ((n = imsg_read(ibuf)) < 0) {
						dolog(LOG_ERR, "imsg read failure %s\n", strerror(errno));
						break;
					}
					if (n == 0) {
						break;
					}

					for (;;) {
						if ((n = imsg_get(ibuf, &imsg)) < 0) {
							dolog(LOG_ERR, "imsg read error: %s\n", strerror(errno));
							break;
						} else {
							if (n == 0)
								break;

							datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

							switch(imsg.hdr.type) {
							case IMSG_DUMP_CACHEREPLYEOF:
								imsg_free(&imsg);
								goto out;
								break;
							case IMSG_DUMP_CACHEREPLY:
								if (datalen < 1)
									break;

								memcpy(buf, imsg.data, datalen);
								buf[datalen - 1] = '\n';

								send(nso, buf, datalen, 0);
								break;
							}	
							imsg_free(&imsg);
						} /* else */
					} /* for (;;) */
				} /* for ;; */

			} /* else if */
out:
			send(nso, rbuf, len, 0);
			close(nso);
		} /* FD_ISSET */
		continue;
	} /* for (;;) */
	
	/* NOTREACHED */
}

int
determine_glue(ddDB *db)
{
	struct rbtree *rbt, *rbt0;
	struct rrset *rrset;
	struct node *n, *nx;
	int len;
	int have_soa = 0, have_ns = 0;
	char *p;

        RB_FOREACH_SAFE(n, domaintree, &db->head, nx) {
		rbt = (struct rbtree *)n->data;

		rrset = find_rr(rbt, DNS_TYPE_SOA);
		if (rrset != NULL) {
			have_soa = 1;
		}
		rrset = find_rr(rbt, DNS_TYPE_NS);
		if (rrset != NULL) {
			have_ns = 1;
		}
		
	}

	if (! have_soa || ! have_ns) {
		dolog(LOG_INFO, "did not detect NS and SOA entries, they must be present!\n");
		return -1;
	}

	/* mark SOA's */
        RB_FOREACH_SAFE(n, domaintree, &db->head, nx) {
		rbt = (struct rbtree *)n->data;

		rrset = find_rr(rbt, DNS_TYPE_SOA);
		if (rrset == NULL) {
			continue;
		}

		rbt->flags |= RBT_APEX;
	}

	/* mark glue */
        RB_FOREACH_SAFE(n, domaintree, &db->head, nx) {
		rbt = (struct rbtree *)n->data;

		if (rbt->flags & RBT_APEX) {
			continue;
		}

		rrset = find_rr(rbt, DNS_TYPE_NS);
		if (rrset == NULL) {
			continue;
		}

		rbt->flags |= RBT_GLUE;
	}

        RB_FOREACH_SAFE(n, domaintree, &db->head, nx) {
		rbt = (struct rbtree *)n->data;


		p = rbt->zone;
		len = rbt->zonelen;

		rbt0 = find_rrset(db, rbt->zone, rbt->zonelen);
		while (! (rbt0->flags & RBT_APEX)) {
			if (rbt0->flags & RBT_GLUE) {
				/* repeat */
				p = rbt->zone;
				len = rbt->zonelen;
				rbt0 = find_rrset(db, p, len);

				while (!(rbt0->flags & RBT_GLUE)) {
					rbt0->flags |= RBT_GLUE;

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
	
			len -= (1 + *p);
			p += (1 + *p);

			/* there could be ENT's so do loop */
			while ((rbt0 = find_rrset(db, p, len)) == NULL) {
				len -= (*p + 1);
				p += (*p + 1);

			}
		}

	}

	return 0;
}

void
setup_cortex(struct imsgbuf *ibuf)
{
	int max = 0;
	int datalen, nomore = 0;

	ssize_t n;
	fd_set rset;

	struct imsg imsg;
	struct passwd *pw;

	SLIST_HEAD(, neuron) neuronhead;
	struct neuron {
		int desc;
		pid_t pid;
		struct imsgbuf ibuf;
		SLIST_ENTRY(neuron) entries;
	} *neup, *neup2, *neup3;

	SLIST_INIT(&neuronhead);

	setproctitle("cortex [%s]", (identstring != NULL ? identstring : ""));

	pw = getpwnam(DEFAULT_PRIVILEGE);
	if (pw == NULL) {
		perror("getpwnam");
		ddd_shutdown();
		exit(1);
	}

#ifdef DEFAULT_LOCATION
	if (drop_privs(DEFAULT_LOCATION, pw) < 0) {
#else
	if (drop_privs(pw->pw_dir, pw) < 0) {
#endif
		dolog(LOG_INFO, "dropping privileges failed in cortex\n");
		ddd_shutdown();
		exit(1);
	}

#if __OpenBSD__
#if 0
	if (unveil("/", "") == -1) {
		dolog(LOG_INFO, "unveil cortex: %s\n", strerror(errno));
		/* XXX notice no exit here */
	}
#endif

	if (unveil(NULL, NULL) == -1) {
		dolog(LOG_INFO, "unveil cortex: %s\n", strerror(errno));
		ddd_shutdown();
		exit(1);
	}

	if (pledge("stdio sendfd recvfd", NULL) < 0) {
		perror("pledge");
		exit(1);
	}
#endif
	
	for (;;) {
		FD_ZERO(&rset);	
		FD_SET(ibuf->fd, &rset);
		if (ibuf->fd > max)
			max = ibuf->fd;

		SLIST_FOREACH(neup, &neuronhead, entries) {
			if (neup->ibuf.fd > max)
				max = neup->ibuf.fd;

			FD_SET(neup->ibuf.fd, &rset);
		}
	
		select(max + 1, &rset, NULL, NULL, NULL);

		SLIST_FOREACH(neup, &neuronhead, entries) {
			if (FD_ISSET(neup->ibuf.fd, &rset)) {
				if ((n = imsg_read(&neup->ibuf)) < 0 && errno != EAGAIN) {
					dolog(LOG_ERR, "imsg read failure %s\n", strerror(errno));
					continue;
				}
				if (n == 0) {
					/* child died? */
					dolog(LOG_INFO, "sigpipe on child?  delphinusdnsd cortex process exiting.\n");
					SLIST_FOREACH(neup2, &neuronhead, entries) {
						if (neup2->desc == MY_IMSG_PRIMARY)
							break;
					}
					/* didn't find it?  skip */
					if (neup2 == NULL) {
						ddd_shutdown(); /* last resort */
						exit(1);
					}
					imsg_compose(&neup2->ibuf, IMSG_SHUTDOWN_MESSAGE, 0, 0, -1, NULL, 0);
					msgbuf_write(&neup2->ibuf.w);

					for (int count=0;count < 10;count++) {
						sleep(1);
					}
					exit(1);
				}

				for (;;) {
					if ((n = imsg_get(&neup->ibuf, &imsg)) < 0) {
						dolog(LOG_ERR, "imsg read error: %s\n", strerror(errno));
						break;
					} else {
						if (n == 0)
							break;

#if DEBUG
						dolog(LOG_INFO, "received imsg type %d from %d\n", imsg.hdr.type, imsg.hdr.pid);
#endif
						datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

						switch(imsg.hdr.type) {
						/* forward duplicated sockets to forward process */ 	
						case IMSG_FORWARD_TCP:
							SLIST_FOREACH(neup2, &neuronhead, entries) {
								if (neup2->desc == MY_IMSG_FORWARD)
									break;
							}
							/* didn't find it?  skip */
							if (neup2 == NULL) {
								/* XXX this can't fail but if it does, throw so out */
								close(imsg.fd);
								break;
							}

							imsg_compose(&neup2->ibuf, IMSG_FORWARD_TCP, 0, 0, imsg.fd, imsg.data, datalen);
							msgbuf_write(&neup2->ibuf.w);
							
							break;
						case IMSG_FORWARD_UDP:
							SLIST_FOREACH(neup2, &neuronhead, entries) {
								if (neup2->desc == MY_IMSG_FORWARD)
									break;
							}
							/* didn't find it?  skip */
							if (neup2 == NULL) 
								break;

							imsg_compose(&neup2->ibuf, IMSG_FORWARD_UDP, 0, 0, -1, imsg.data, datalen);
							msgbuf_write(&neup2->ibuf.w);

							
							break;
							
						/* hellos go to the primary */
						case IMSG_HELLO_MESSAGE:
						case IMSG_SHUTDOWN_MESSAGE:
						case IMSG_RELOAD_MESSAGE:
							SLIST_FOREACH(neup2, &neuronhead, entries) {
								if (neup2->desc == MY_IMSG_PRIMARY)
									break;
							}
							/* didn't find it?  skip */
							if (neup2 == NULL)
								break;

#if DEBUG
							dolog(LOG_INFO, "relaying shutdown from %d to %d\n", imsg.hdr.pid, neup2->pid);
#endif
							
							imsg_compose(&neup2->ibuf, imsg.hdr.type, 0, 0, -1, imsg.data, datalen);
							msgbuf_write(&neup2->ibuf.w);
							
							break;
						case IMSG_SPREAD_MESSAGE:
							SLIST_FOREACH(neup2, &neuronhead, entries) {
								imsg_compose(&neup2->ibuf, IMSG_SPREAD_MESSAGE, 0, 0, -1, imsg.data, datalen);
								msgbuf_write(&neup2->ibuf.w);
							}

							break;
						case IMSG_XFR_MESSAGE:
							SLIST_FOREACH(neup2, &neuronhead, entries) {
								if (neup2->desc == MY_IMSG_AXFR_ACCEPT)
									break;
							}
							/* didn't find it?  skip */
							if (neup2 == NULL)
								break;
							
							imsg_compose(&neup2->ibuf, IMSG_XFR_MESSAGE, 0, 0, imsg.fd, imsg.data, datalen);
							msgbuf_write(&neup2->ibuf.w);
							break;
						case IMSG_NOTIFY_MESSAGE:
							SLIST_FOREACH(neup2, &neuronhead, entries) {
								if (neup2->desc == MY_IMSG_RAXFR)
									break;
							}
							/* didn't find it?  skip */
							if (neup2 == NULL)
								break;

						
							imsg_compose(&neup2->ibuf, IMSG_NOTIFY_MESSAGE, 0, 0, -1, imsg.data, datalen);
							msgbuf_write(&neup2->ibuf.w);
							break;
						case IMSG_DUMP_CACHE:
							SLIST_FOREACH(neup2, &neuronhead, entries) {
								if (neup2->desc == MY_IMSG_FORWARD)
									break;
							}
							/* didn't find it?  skip */
							if (neup2 == NULL)
								break;

						
							imsg_compose(&neup2->ibuf, IMSG_DUMP_CACHE, 0, 0, -1, imsg.data, datalen);
							msgbuf_write(&neup2->ibuf.w);
							break;

						case IMSG_DUMP_CACHEREPLYEOF:
						case IMSG_DUMP_CACHEREPLY:
							SLIST_FOREACH(neup2, &neuronhead, entries) {
								if (neup2->desc == MY_IMSG_UNIXCONTROL)
									break;
							}
							/* didn't find it?  skip */
							if (neup2 == NULL)
								break;

						
							imsg_compose(&neup2->ibuf, imsg.hdr.type, 0, 0, -1, imsg.data, datalen);
							msgbuf_write(&neup2->ibuf.w);
							break;

						default:
							/* unknown imsg */
							break;
						}

						imsg_free(&imsg);
					}
				} /* for (;;) */
				
			} /* if maxneurons */
		} /* for maxneurons */

		if (FD_ISSET(ibuf->fd, &rset)) {
			if ((n = imsg_read(ibuf)) < 0 && errno != EAGAIN) {
				dolog(LOG_ERR, "imsg read failure %s\n", strerror(errno));
				continue;
			}
			if (n == 0) {
				/* child died? */
				dolog(LOG_INFO, "sigpipe on child?  delphinusdnsd cortex process exiting.\n");
				SLIST_FOREACH(neup2, &neuronhead, entries) {
					if (neup2->desc == MY_IMSG_PRIMARY)
						break;
				}
				/* didn't find it?  skip */
				if (neup2 == NULL) {
					ddd_shutdown(); /* last resort */
					exit(1);
				}
				imsg_compose(&neup2->ibuf, IMSG_SHUTDOWN_MESSAGE, 0, 0, -1, NULL, 0);
				msgbuf_write(&neup2->ibuf.w);

				for (int count = 0; count < 10; count++) {
					sleep(1);
				}
				exit(1);
			}

			for (;;) {
				if ((n = imsg_get(ibuf, &imsg)) < 0) {
					dolog(LOG_ERR, "imsg read error: %s\n", strerror(errno));
					break;
				} else {
					if (n == 0)
						break;

					datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

					if (nomore == 1) {
						imsg_free(&imsg);
						break;
					}

					switch(imsg.hdr.type) {
					case IMSG_CRIPPLE_NEURON:
						if (datalen != sizeof(int))
							break;
						nomore = 1;
						break;
					case IMSG_SETUP_NEURON:
						if (datalen != sizeof(int))
							break;

						neup3 = calloc(sizeof(struct neuron), 1);
						if (neup3 == NULL) {
							break;
						}
						
						memcpy((char *)&neup3->desc, (char *)imsg.data, sizeof(int));
						neup3->pid = (pid_t)imsg.hdr.pid;
#if DEBUG
						dolog(LOG_INFO, "registered pid %u with description %d\n", neup3->pid, neup3->desc);
#endif
						imsg_init(&neup3->ibuf, imsg.fd);

						SLIST_INSERT_HEAD(&neuronhead, neup3, entries);
						break;
					default:
						break;
					}

					imsg_free(&imsg);
				}
			} /* for (;;) */
		} /* IF_ISSET(ibuf... */
	} /* for(;;) */

	/* NOTREACHED */
}

/*
 * REGISTER_CORTEX - register with the cortex process via imsg
 */

struct imsgbuf *
register_cortex(struct imsgbuf *cortex, int type)
{
	int fd[2];
	struct imsgbuf *ibuf;
	int desc = type;


	ibuf = calloc(sizeof(struct imsgbuf), 1);
	if (ibuf == NULL)
		return NULL;

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, PF_UNSPEC, &fd[0]) < 0) {
		return NULL;
	}

	imsg_init(ibuf, fd[0]);
		
	/* send the cortex a setup neuron */
	imsg_compose(cortex, IMSG_SETUP_NEURON, 0, 0, fd[1], &desc, sizeof(int));
	msgbuf_write(&cortex->w);
		
	return (ibuf);
}

void
nomore_neurons(struct imsgbuf *cortex)
{
	int desc = 1;

	imsg_compose(cortex, IMSG_CRIPPLE_NEURON, 0, 0, -1, &desc, sizeof(int));
	msgbuf_write(&cortex->w);
}


int
bind_this_res(struct addrinfo *res, int shut)
{
	int on;
	int so;

	if ((so = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
		dolog(LOG_INFO, "socket: %s\n", strerror(errno));
		ddd_shutdown();
		exit(1);
	}

	on = 1;
	if (setsockopt(so, SOL_SOCKET, SO_REUSEPORT,
		&on, sizeof(on)) < 0) {
		dolog(LOG_INFO, "setsockopt: %s\n", strerror(errno));
	}

	if (setsockopt(so, SOL_SOCKET, SO_TIMESTAMP,
		&on, sizeof(on)) < 0) {
		dolog(LOG_INFO, "setsockopt timestamp: %s\n", strerror(errno));
	}

	if (bind(so, res->ai_addr, res->ai_addrlen) < 0) {
		dolog(LOG_INFO, "bind: %s\n", strerror(errno));
		ddd_shutdown();
		exit(1);
	}

	return (so);
}

int
bind_this_pifap(struct ifaddrs *pifap, int shut, int salen)
{
	int on;
	int so;

	if ((so = socket(pifap->ifa_addr->sa_family, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		dolog(LOG_INFO, "socket: %s\n", strerror(errno));
		ddd_shutdown();
		exit(1);
	}

	on = 1;
	if (setsockopt(so, SOL_SOCKET, SO_REUSEPORT,
		&on, sizeof(on)) < 0) {
		dolog(LOG_INFO, "setsockopt: %s\n", strerror(errno));
	}

	if (setsockopt(so, SOL_SOCKET, SO_TIMESTAMP,
		&on, sizeof(on)) < 0) {
		dolog(LOG_INFO, "setsockopt timestamp: %s\n", strerror(errno));
	}


	if (bind(so, (struct sockaddr *)pifap->ifa_addr, salen) < 0) {
		dolog(LOG_INFO, "bind: %s\n", strerror(errno));
		ddd_shutdown();
		exit(1);
	}
	return (so);
}

char *
sm_init(size_t members, size_t size_member)
{
	char *shptr;
	size_t shsize;
	void *sf;
	size_t j;

	/* initialize the global shared memory segment */

	shsize = sm_size(members, size_member);
	shptr = mmap(NULL, shsize, PROT_READ | PROT_WRITE, MAP_SHARED |\
		MAP_ANON, -1, 0);

	if (shptr == MAP_FAILED) {
		dolog(LOG_ERR, "failed to setup  mmap segment, exit\n");
		ddd_shutdown();
		exit(1);
	}

	/* initialize (set first 4 bytes in each member to 1) */
	for (sf = (void *)&shptr[0], j = 0; j < members; j++, sf += size_member) {
		pack32((char *)sf, 1);
	}

	sm_unlock(shptr, shsize);
	return (shptr);
}

void
sm_zebra(char *shmptr, size_t members, size_t size_member)
{
	char *guardpage;
	size_t i;

	for (i = 1; i <= members; i++) {
		guardpage = (shmptr + (i * size_member)) - sysconf(_SC_PAGESIZE);
		if (mprotect(guardpage, sysconf(_SC_PAGESIZE), PROT_NONE) == -1) {	
			dolog(LOG_INFO, "sm_zebra mprotect: %s\n", strerror(errno));
			ddd_shutdown();
			exit(1);
		}
	}
}


size_t
sm_size(size_t members, size_t size_member)
{
	return (16 + (members * size_member));
}

void
sm_lock(char *shm, size_t end)
{
	char *lock = (char *)&shm[end - 16];	
	uint32_t value;

	while ((value = arc4random()) == SM_NOLOCK);

	for (;;) {
		while (unpack32(lock) != SM_NOLOCK) {
			usleep(arc4random() % 300);
		}
		pack32(lock, value);		/* race here */
		if (unpack32(lock) == value) 	/* check for race here */
			return;
	}

	/* NOTREACHED */
}

void
sm_unlock(char *shm, size_t end)
{
	char *lock = (char *)&shm[end - 16];	

	pack32(lock, SM_NOLOCK);
}

/*
 * SEND_TO_PARSER - send a received packet to the parser with imsg
 *
 */

int
send_to_parser(struct cfg *cfg, struct imsgbuf *pibuf, char *buf, int len, struct parsequestion *pq)
{
	struct timeval tv;
	struct imsg imsg;
	struct pq_imsg *pq0;
	struct pkt_imsg *incoming;
	ssize_t n, datalen;
	uint64_t key;
	fd_set rset;
	uint32_t imsg_type;
	int pq_offset;
	int sel, i;
	int clen = 0;

	arc4random_buf((char *)&key, sizeof(uint64_t));
	key <<= 16;		/* XXX i cannot be bigger than 65535! */

	/* write to shared memory slot */
	sm_lock(cfg->shm[SM_INCOMING].shptr, cfg->shm[SM_INCOMING].shptrsize);

	incoming = (struct pkt_imsg *)&cfg->shm[SM_INCOMING].shptr[0];
	for (i = 0; i < SHAREDMEMSIZE3; i++, incoming++) {
		if (unpack32((char *)&incoming->u.i.read) == 1) {
			key = ((key & 0xffffffffffff0000ULL) + i);
			memcpy((char *)&incoming->u.i.buf, (char *)buf, 
					MIN(len, (sizeof(incoming->u.buf) - \
					sizeof(incoming->u.i) - 16)));
#if notyet
			if (clen == 0) {
				sm_unlock(cfg->shm[SM_INCOMING].shptr, 
					cfg->shm[SM_INCOMING].shptrsize);
				return (-1);
			}
#endif
			pack32((char *)&incoming->u.i.buflen, len);
			pack32((char *)&incoming->u.i.bufclen, clen);
			pack32((char *)&incoming->u.i.read, 0);
			break;
		}
	}

	sm_unlock(cfg->shm[SM_INCOMING].shptr, 
		cfg->shm[SM_INCOMING].shptrsize);

	if (i == SHAREDMEMSIZE3) {
		dolog(LOG_INFO, "increase SHAREDMEMSIZE3 for SM_INCOMING!!!\n");
		return (-1);
	} else {
		imsg_type = IMSG_PARSE_MESSAGE;
		if (imsg_compose(pibuf, imsg_type, 0, 0, -1, (char *)&key, sizeof(key)) < 0) {
			dolog(LOG_INFO, "imsg_compose %s\n", strerror(errno));
			return -1;
		}

		msgbuf_write(&pibuf->w);
	}


	/* branch to pledge parser here */

	FD_ZERO(&rset);
	FD_SET(pibuf->fd, &rset);

	tv.tv_sec = 10;
	tv.tv_usec = 0;

	sel = select(pibuf->fd + 1, &rset, NULL, NULL, &tv);

	if (sel < 0) {
		dolog(LOG_ERR, "internal error around select, dropping packet\n");
		return -1;
	}

	if (sel == 0) {
		dolog(LOG_ERR, "internal error, timeout on parse imsg, drop\n");
		return -1;
	}

	if (FD_ISSET(pibuf->fd, &rset)) {

		if (((n = imsg_read(pibuf)) == -1 && errno != EAGAIN) || n == 0) {
			dolog(LOG_ERR, "internal error, parse child likely died, exit\n");
			exit(1);
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
				if (datalen != sizeof(uint64_t)) {
					dolog(LOG_ERR, "datalen != sizeof(uint64_t), can't work with this, drop\n");
					return (-1);
				}

				memcpy((char *)&key, imsg.data, datalen);
				pq_offset = key & 0xffff; /* XXX 65535 limit */
				pq0 = (struct pq_imsg *)&cfg->shm[SM_PARSEQUESTION].shptr[0];
				pq0 += pq_offset;

				len = unpack32((char *)&pq0->pqi_len);
				/* pjp */
				memcpy((char *)pq, (char *)&pq0->pqi_pq, sizeof(struct parsequestion) - PQ_PAD);
#if notyet
					dolog(LOG_ERR, "decryption of parsequestion failed\n"); 
					return (-1);
				}
#endif

				sm_lock(cfg->shm[SM_PARSEQUESTION].shptr, 
						cfg->shm[SM_PARSEQUESTION].shptrsize);
				pack32((char *)&pq0->u.s.read, 1);
				sm_unlock(cfg->shm[SM_PARSEQUESTION].shptr, 
						cfg->shm[SM_PARSEQUESTION].shptrsize);

				if (pq->rc != PARSE_RETURN_ACK) {
					switch (pq->rc) {
					case PARSE_RETURN_MALFORMED:
						imsg_free(&imsg);
						return PARSE_RETURN_MALFORMED;
					case PARSE_RETURN_NOQUESTION:
						imsg_free(&imsg);
						return PARSE_RETURN_NOQUESTION; 
					case PARSE_RETURN_NOTAQUESTION:
						imsg_free(&imsg);
						return PARSE_RETURN_NOTAQUESTION;
					case PARSE_RETURN_NAK:
						imsg_free(&imsg);
						return PARSE_RETURN_NAK;

					case PARSE_RETURN_NOTAUTH:
						imsg_free(&imsg);
						return PARSE_RETURN_NOTAUTH;
					} /* switch */
				} /* if */
				break;
			} /* switch */
			imsg_free(&imsg);
		} /* for (;;) */
	}  /* FD_ISSET */

	return PARSE_RETURN_ACK;
}

#if notyet

int
enc_cpy(u_char *outbuf, u_char *inbuf, int len, uint64_t key)
{
	EVP_CIPHER_CTX *ctx = NULL;
	char tiv[16];
	uint64_t *mask = (uint64_t *)encryptkey;
	int tmplen = 0, outlen = 0;
	*mask = key;

	memcpy(&tiv, iv, sizeof(tiv));

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		return 0;

	if (!EVP_CipherInit_ex(ctx, EVP_aes_128_ecb(), NULL, NULL, NULL, 1)) {
		goto err;
	}
	//if (!EVP_CipherInit_ex(ctx, NULL, NULL, encryptkey, iv, 1)) {
	if (!EVP_CipherInit_ex(ctx, NULL, NULL, encryptkey, NULL, 1)) {
		goto err;
	}
#if 0
	if (!EVP_CIPHER_CTX_set_iv(ctx, iv, sizeof(iv))) {
		goto err;
	}
#endif
	if (!EVP_CIPHER_CTX_set_key_length(ctx, sizeof(encryptkey))) {
		goto err;
	}

	outlen = len;
	if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, len)) {
		goto err;
	}

#if 0
	tmplen = len - outlen;
#endif

	if (!EVP_CipherFinal_ex(ctx, outbuf + outlen, &tmplen)) {
		goto err;
	}

	EVP_CIPHER_CTX_free(ctx);
	return (outlen + tmplen);

err:
	EVP_CIPHER_CTX_free(ctx);
	return (0);
}

int
dec_cpy(u_char *outbuf, u_char *inbuf, int len, uint64_t key)
{
	EVP_CIPHER_CTX *ctx = NULL;
	char tiv[16];
	uint64_t *mask = (uint64_t *)encryptkey;
	int oldlen = len;
	int outlen, tmplen;

	*mask = key;

	memcpy(&tiv, iv, sizeof(tiv));

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		return 0;

	if (!EVP_CipherInit_ex(ctx, EVP_aes_128_ecb(), NULL, NULL, NULL, 0)) {
		goto err;
	}
	//if (!EVP_CipherInit_ex(ctx, NULL, NULL, encryptkey, iv, 0)) {
	if (!EVP_CipherInit_ex(ctx, NULL, NULL, encryptkey, NULL, 0)) {
		goto err;
	}
#if 0
	if (!EVP_CIPHER_CTX_set_iv(ctx, iv, sizeof(iv))) {
		goto err;
	}
#endif
	if (!EVP_CIPHER_CTX_set_key_length(ctx, sizeof(encryptkey))) {
		goto err;
	}

	outlen = len;
	if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, len)) {
		goto err;
	}

	if (!EVP_CipherFinal_ex(ctx, outbuf + outlen, &tmplen)) {
		goto err;
	}

	EVP_CIPHER_CTX_free(ctx);

	return (oldlen);

err:
	EVP_CIPHER_CTX_free(ctx);
	return (0);	
}
#endif /* not yet */
