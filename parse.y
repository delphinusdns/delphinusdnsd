/*
 * Copyright (c) 2014-2024 Peter J. Philipp.  All rights reserved.
 * Copyright (c) 2008 Gilles Chehade <gilles@poolp.org>
 * Copyright (c) 2008 Pierre-Yves Ritschard <pyr@openbsd.org>
 * Copyright (c) 2002, 2003, 2004 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2001 Daniel Hartmeier.  All rights reserved.
 * Copyright (c) 2001 Theo de Raadt.  All rights reserved.
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

%{
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/wait.h>

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
#include <signal.h>
#include <time.h>
#include <pwd.h>

#if __OpenBSD__
#include <siphash.h>
#else
#include "siphash.h"
#endif


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
#else /* not linux */
#include <sys/queue.h>
#include <sys/tree.h>
#endif /* __linux__ */


#include "ddd-dns.h"
#include "ddd-db.h"

void 		yyerror(const char *);
int		yylex(void);

extern void 	pack(char *, char *, int);
extern void 	pack32(char *, uint32_t);
extern void 	pack16(char *, uint16_t);
extern void 	pack8(char *, uint8_t);
extern uint32_t unpack32(char *);
extern uint16_t unpack16(char *);
extern void 	unpack(char *, char *, int);

extern int	memcasecmp(u_char *, u_char *, int);
extern struct rrtab 	*rrlookup(char *);
extern int	base32hex_decode(u_char *, u_char *);
extern void 	dolog(int, char *, ...);
extern char 	*dns_label(char *, int *);
extern uint8_t find_region(struct sockaddr_storage *, int);
extern int 	insert_apex(char *, char *, int);
extern int 	insert_nsec3(char *, char *, char *, int);
extern int 	insert_region(char *, char *, uint8_t);
extern int 	insert_axfr(char *, char *);
extern int 	insert_notifyddd(char *, char *);
extern int 	insert_filter(char *, char *);
extern int	insert_forward(int, struct sockaddr_storage *, uint16_t, char *);
extern int 	insert_passlist(char *, char *);
extern int      insert_tsigpassname(char *);
extern int	insert_tsig(char *, char *);
extern int	insert_tsig_key(char *, int, char *, int);
extern int	insert_zone(char *);
extern void 	ddd_shutdown(void);
extern int 	mybase64_encode(u_char const *, size_t, char *, size_t);
extern int 	mybase64_decode(char const *, u_char *, size_t);
extern struct rbtree * create_rr(ddDB *, char *, int, int, void *, uint32_t, uint16_t);
extern struct rbtree * find_rrset(ddDB *db, char *name, int len);
extern struct rrset * find_rr(struct rbtree *rbt, uint16_t rrtype);
extern int display_rr(struct rrset *rrset);
extern void flag_rr(struct rbtree *, uint32_t);
extern int pull_rzone(struct rzone *, time_t);
extern int finalize_nsec3(void);
extern int param_human2tlv(char *, char *, int *);

extern int tsigpassname;
extern int passlist;
extern int tsig;
extern int notify;
extern int errno;
extern int debug;
extern int forward;
extern int forwardtsig;
extern int strictx20i;
extern int forwardstrategy;
extern uint16_t wrap6to4region;
extern int cache;
extern int zonecount;
extern int verbose;
extern int bflag;
extern int iflag;
extern int lflag;
extern int nflag;
extern int bcount;
extern int icount;
extern int ratelimit;
extern int ratelimit_packets_per_second;
extern int ratelimit_cidr;
extern int ratelimit_cidr6;
extern uint16_t port;
extern uint32_t cachesize;
extern char *bind_list[255];
extern char *interface_list[255];
extern char *versionstring;
extern uint8_t vslen;
extern int tls;
extern char *tls_keyfile;
extern char *tls_certfile;
extern char *tls_protocols;
extern char *tls_ciphers;
extern uint16_t tls_port;




TAILQ_HEAD(files, file)          files = TAILQ_HEAD_INITIALIZER(files);
TAILQ_HEAD(rzonefiles, file)	 rzonefiles = TAILQ_HEAD_INITIALIZER(rzonefiles);

static struct file {
        TAILQ_ENTRY(file)       file_entry;
        FILE                    *stream;
        char                    *name;
        int                     lineno;
        int                     errors;
	int			descend;
#define DESCEND_NO		0
#define DESCEND_YES		1
} *file, *topfile, *rzonefile;

TAILQ_HEAD(txtentries, txts)	 txtentries = TAILQ_HEAD_INITIALIZER(txtentries);

static struct txts {
	TAILQ_ENTRY(txts)	txt_entry;
	char			*text;
} *txt0, *txt1;

SLIST_HEAD(rzones, rzone)	rzones = SLIST_HEAD_INITIALIZER(rzones);
SLIST_HEAD(mzones ,mzone)	mzones = SLIST_HEAD_INITIALIZER(mzones);

struct nb notifybind;

#define STATE_IP 1
#define STATE_ZONE 2

#define NO_RZONEFILE	0
#define RZONEFILE	1

#define DELPHINUSVERSION	1

#define CONFIG_START            0x1
#define CONFIG_VERSION          0x2
#define CONFIG_REGION           0x4
#define CONFIG_ZONE             0x8
#define CONFIG_INCLUDE          0x10
#define CONFIG_WILDCARDONLYFOR  0x20
#define CONFIG_RECURSEFOR       0x40
#define CONFIG_LOGGING          0x80		/* deprecated */
#define CONFIG_AXFRFOR          0x100
#define CONFIG_ZINCLUDE		0x400
#define CONFIG_RZONE		0x800

typedef struct {
	union {
		char *string;
		int64_t intval;
		float floatval;
	} v;
	int lineno;
} YYSTYPE;

#ifdef __APPLE__
#define YYSTYPE_IS_DECLARED 1
#endif

static int version = 0;
static int state = 0;
static uint8_t region = 0;
static uint64_t confstatus = 0;
static ddDB *mydb;
static char *current_zone = NULL;
static int pullzone = 1;
static int notsigs = 0;


YYSTYPE yylval;


int cookies = 1;
char *cookiesecret;
int cookiesecret_len;
char *converted_name;
int converted_namelen;
uint32_t zonenumber = 0;
ddDBT key, data;
int axfrport = 0;
int strictaxfr = 0;
time_t time_changed;
int dnssec = 0;
int raxfrflag = 0;
int tcpanyonly = 0;
int replicant_axfr_old_behaviour = 0;
int primary_axfr_old_behaviour = 0;
u_int max_udp_payload = 1232;
uint16_t fudge_forward = DEFAULT_TSIG_FUDGE;
uint8_t rdomain = 0;
uint8_t forward_rdomain = 0;
struct mzone *mz0, *mz;
struct rzone *rz0, *rz;

char 		*check_rr(char *, char *, int, int *);
int 		fill_a(ddDB *, char *, char *, int, char *);
int 		fill_aaaa(ddDB *, char *, char *, int, char *);
int 		fill_ptr(ddDB *, char *, char *, int, char *);
int 		fill_cname(ddDB *, char *, char *, int, char *);
int 		fill_mx(ddDB *, char *, char *, int, int, char *);
int 		fill_kx(ddDB *, char *, char *, int, int, char *);
int 		fill_naptr(ddDB *, char *, char *, int, int, int, char *, char *, char *, char *);
int 		fill_ns(ddDB *, char *, char *, int, char *);
int 		fill_soa(ddDB *, char *, char *, int, char *, char *, int, int, int, int, int);
int		fill_loc(ddDB *, char *, char *, int, uint8_t, uint8_t, float, char *, uint8_t, uint8_t, float, char *, uint32_t, uint32_t, uint32_t, uint32_t);
int 		fill_sshfp(ddDB *, char *, char *, int, int, int, char *);
int 		fill_srv(ddDB *, char *, char *, int, int, int, int, char *);
int 		fill_tlsa(ddDB *, char *, char *,int, uint8_t, uint8_t, uint8_t, char *);
int 		fill_txt(ddDB *, char *, char *, int);
int 		fill_eui48(ddDB *, char *, char *, int, char *);
int 		fill_eui64(ddDB *, char *, char *, int, char *);
int		fill_dnskey(ddDB *, char *, char *, uint32_t, uint16_t, uint8_t, uint8_t, char *, uint16_t);
int		fill_rrsig(ddDB *, char *, char *, uint32_t, char *, uint8_t, uint8_t, uint32_t, uint64_t, uint64_t, uint16_t, char *, char *);
int 		fill_nsec(ddDB *, char *, char *, uint32_t, char *, char *);
int		fill_nsec3param(ddDB *, char *, char *, uint32_t, uint8_t, uint8_t, uint16_t, char *);
int		fill_nsec3(ddDB *, char *, char *, uint32_t, uint8_t, uint8_t, uint16_t, char *, char *, char *, char *);
int		fill_ds(ddDB *, char *, char *, uint32_t, uint16_t, uint8_t, uint8_t, char *, uint16_t);
int		fill_rp(ddDB *, char *, char *, int, char *, char *);
int		fill_hinfo(ddDB *, char *, char *, int, char *, char *);
int		fill_caa(ddDB *, char *, char *, int, uint8_t, char *, char *);
int 		fill_zonemd(ddDB *, char *, char *, int, uint32_t, uint8_t, uint8_t, char *, int);
int		fill_ipseckey(ddDB *, char *, char *, int, uint8_t, uint8_t, uint8_t, char *, char *);
int		fill_cert(ddDB *, char *, char *, int, char *, uint16_t, uint8_t, char *);
int		fill_https(ddDB *, char *, char *, int, uint16_t, char *, char *);
int		fill_svcb(ddDB *, char *, char *, int, uint16_t, char *, char *);


void		create_nsec_bitmap(char *, char *, int *);
int             findeol(void);
int 		get_ip(char *, int);
char 		*get_prefixlen(char *, char *, int);
int 		get_quotedstring(char *, int);
int 		get_string(char *, int);
int		hex2bin(char *, int, char *);
int             lgetc(int);
struct tab * 	lookup(struct tab *, char *);
int             lungetc(int);
int 		parse_file(ddDB *, char *, uint32_t, int);
struct file     *pushfile(const char *, int, int, int, int);
void		cleanup_files(void);
int             popfile(int);
static int 	temp_inet_net_pton_ipv6(const char *, void *, size_t);
int 		yyparse(void);
static struct rzone * add_rzone(void);
static struct mzone * add_mzone(void);
static int	pull_remote_zone(struct rzone *);
int		notifysource(struct question *, struct sockaddr_storage *);
int		dottedquad(char *);
void		clean_txt(void);
int		add_txt(char *, int);


%}


%token VERSION OBRACE EBRACE REGION RZONE AXFRFOR 
%token DOT COLON TEXT WOF INCLUDE ZONE COMMA CRLF 
%token ERROR OPTIONS FILTER MZONE
%token PASSLIST ZINCLUDE PRIMARY PRIMARYPORT TSIGAUTH
%token TSIG NOTIFYDEST NOTIFYBIND PORT FORWARD
%token INCOMINGTSIG DESTINATION CACHE STRICTX20
%token BYTELIMIT FUDGE TSIGPASSNAME RDOMAIN
%token FORWARDSTRATEGY TXT WRAP64REGION

%token <v.string> POUND
%token <v.string> SEMICOLON
%token <v.string> STRING
%token <v.string> IP
%token <v.string> IPV6
%token <v.string> SLASH
%token <v.string> QUOTEDSTRING

%token <v.intval> NUMBER
%token <v.floatval> FLOAT

%type <v.string> quotednumber quotedfilename ipcidr 
%type <v.string> txtstatements

%start cmd_list

%%
cmd_list:
	| cmd_list cmd
	;

cmd	:  	
	version 
	| rzone
	| mzone
	| tsigauth
	| include
	| zinclude
	| zone
	| region CRLF
	| axfr CRLF
	| passlist CRLF
	| tsig CRLF
	| tsigpassname CRLF
	| filter CRLF
	| forward CRLF
	| comment CRLF
	| options
	;


comment:
	comment comments
	| comments
	;

comments: 
 	SEMICOLON 
	| POUND 
	;

version:
	VERSION quotednumber SEMICOLON CRLF
	{
		version = atoi($2);
#if 0
		if (version != DELPHINUSVERSION) {
			dolog(LOG_ERR, "version of configfile is wrong,"
					" must be \"%d\"!\n", DELPHINUSVERSION);
			return (-1);
		}
#endif
		free ($2);
		
		confstatus |= CONFIG_VERSION;
	}
	;


quotednumber:
	QUOTEDSTRING
	{
		if (debug) 
			printf("quotednumber is %s\n", $$);
	}
	;

include:
		includes CRLF
		;

includes:
	INCLUDE quotedfilename SEMICOLON {
		struct file     *nfile;
	
		if ((confstatus & CONFIG_VERSION) != CONFIG_VERSION) {
			dolog(LOG_INFO, "There must be a version at the top of the first configfile\n");
			return (-1);
		}

		if (file->descend == DESCEND_YES) {
			if ((nfile = pushfile($2, 0, DESCEND_YES, NO_RZONEFILE, -1)) == NULL) {
				fprintf(stderr, "failed to include file %s\n", $2);
				free($2);
				return (-1);
			}

			file = nfile;
			lungetc('\n');
		}

		free($2);
	}
	;

zinclude:
		zincludes CRLF
		;

zincludes:
	ZINCLUDE quotedfilename SEMICOLON {
		struct file     *nfile;
	
		if ((confstatus & CONFIG_VERSION) != CONFIG_VERSION) {
			dolog(LOG_INFO, "There must be a version at the top of the first configfile\n");
			return (-1);
		}

		if (file->descend == DESCEND_YES) {
			if ((nfile = pushfile($2, 0, DESCEND_NO, NO_RZONEFILE, -1)) == NULL) {
				fprintf(stderr, "failed to include file %s\n", $2);
				free($2);
				return (-1);
			}

			file = nfile;
			lungetc('\n');
		}

		free($2);
	}
	;

quotedfilename:
	QUOTEDSTRING
	{
		if (debug)
			printf("quotedfilename is %s\n", $1);
	}
	;


tsigauth:
	TSIGAUTH STRING QUOTEDSTRING SEMICOLON CRLF {
		char key[512];
		char *keyname = NULL;
		int keylen = 0, keynamelen = 0;
	
		if (! notsigs) {
			if ((keylen = mybase64_decode($3, (u_char *)key, sizeof(key))) < 0) {
				dolog(LOG_ERR, "can't decode tsig base64\n");
				return -1;
			}

			keyname = dns_label($2, &keynamelen);
			if (keyname == NULL) {
				dolog(LOG_ERR, "dns_label: %s\n", strerror(errno));
				return -1;
			}

			insert_tsig_key(key, keylen, keyname, keynamelen);

			explicit_bzero(&key, sizeof(key));
			keylen = 0;
		}

		free($2);
#if __OpenBSD__
		freezero($3, strlen($3));
		freezero(keyname, keynamelen);
#else
		free($3);
		free(keyname);
#endif
	}
	;
mzone:
	MZONE mzonelabel mzonecontent {
		mz = add_mzone();
		if (mz == NULL) {
			dolog(LOG_INFO, "add_mzone failed\n");
			return (-1);
		}
		SLIST_INIT(&mz->dest);
	}
	;

mzonelabel:
	QUOTEDSTRING
	;

mzonecontent:
	OBRACE mzonestatements EBRACE CRLF
	| OBRACE CRLF mzonestatements EBRACE CRLF
	;

mzonestatements 	:  		
				mzonestatements mzonestatement 
				| mzonestatement 
				;

mzonestatement:
	
	STRING QUOTEDSTRING SEMICOLON CRLF
	{
		mz = SLIST_FIRST(&mzones);
		if (mz == NULL) {
			mz = add_mzone();
			SLIST_INIT(&mz->dest);
		}

		if (strcmp($1, "zonename") == 0) {
			mz->humanname = strdup($2);
			if (mz->humanname == NULL) {
				perror("strdup");
				return -1;
			}

			mz->zonename = dns_label(mz->humanname, &mz->zonenamelen);
			if (mz->zonename == NULL) {
				fprintf(stderr, "could not convert zone to dns_label\n");
				return -1;
			}
		}
		
		free($1);
		free($2);
	}
	|
	NOTIFYDEST ipcidr PORT NUMBER STRING SEMICOLON CRLF
	{
		struct sockaddr_in *sin;
		struct sockaddr_in6 *sin6;
		struct mzone_dest *md;

		mz = SLIST_FIRST(&mzones);
		if (mz == NULL) {
			mz = add_mzone();
			SLIST_INIT(&mz->dest);
		}

		md = calloc(sizeof(struct mzone_dest), 1);
		if (md == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			return (-1);
		}

		sin = (struct sockaddr_in *)&md->notifydest;
		sin6 = (struct sockaddr_in6 *)&md->notifydest;

		if (strchr($2, ':')) {
			inet_pton(AF_INET6, $2, &sin6->sin6_addr);
			md->port = $4 & 0xffff;
			md->notifydest.ss_family = AF_INET6;
			if (strcmp($5, "NOKEY") == 0) {
				md->tsigkey = NULL;
			} else {
				md->tsigkey = strdup($5);
				if (md->tsigkey == NULL) {
					perror("stdup");
					return -1;
				}
			}
			

			SLIST_INSERT_HEAD(&mz->dest, md, entries);

			notify++;
		} else {
			inet_pton(AF_INET, $2, &sin->sin_addr.s_addr);
			md->notifydest.ss_family = AF_INET;
			md->port = $4 & 0xffff;

			if (strcmp($5, "NOKEY") == 0) {
				md->tsigkey = NULL;
			} else {
				md->tsigkey = strdup($5);
				if (md->tsigkey == NULL) {
					perror("stdup");
					return -1;
				}
			}

			SLIST_INSERT_HEAD(&mz->dest, md, entries);
			notify++;
		}

		
		free($2);
		free($5);
	}
	|
	NOTIFYDEST ipcidr STRING SEMICOLON CRLF
	{
		struct sockaddr_in *sin;
		struct sockaddr_in6 *sin6;
		struct mzone_dest *md;

		mz = SLIST_FIRST(&mzones);
		if (mz == NULL) {
			mz = add_mzone();
			SLIST_INIT(&mz->dest);
		}

		md = calloc(sizeof(struct mzone_dest), 1);
		if (md == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			return (-1);
		}

		sin = (struct sockaddr_in *)&md->notifydest;
		sin6 = (struct sockaddr_in6 *)&md->notifydest;

		if (strchr($2, ':')) {
			inet_pton(AF_INET6, $2, &sin6->sin6_addr);
			md->notifydest.ss_family = AF_INET6;
			md->port = 53;
			if (strcmp($3, "NOKEY") == 0) {
				md->tsigkey = NULL;
			} else {
				md->tsigkey = strdup($3);
				if (md->tsigkey == NULL) {
					perror("stdup");
					return -1;
				}
			}
			

			SLIST_INSERT_HEAD(&mz->dest, md, entries);

			notify++;
		} else {
			inet_pton(AF_INET, $2, &sin->sin_addr.s_addr);
			md->notifydest.ss_family = AF_INET;
			md->port = 53;

			if (strcmp($3, "NOKEY") == 0) {
				md->tsigkey = NULL;
			} else {
				md->tsigkey = strdup($3);
				if (md->tsigkey == NULL) {
					perror("stdup");
					return -1;
				}
			}

			SLIST_INSERT_HEAD(&mz->dest, md, entries);
			notify++;
		}

		
		free($2);
		free($3);
	}
	|
	NOTIFYBIND ipcidr SEMICOLON CRLF
	{
		struct sockaddr_in *sin;
		struct sockaddr_in6 *sin6;

		mz = SLIST_FIRST(&mzones);
		if (mz == NULL) {
			mz = add_mzone();
			SLIST_INIT(&mz->dest);
		}
			
		sin = (struct sockaddr_in *)&mz->notifybind;
		sin6 = (struct sockaddr_in6 *)&mz->notifybind;

		if (strchr($2, ':')) {
			mz->notifybind.ss_family = AF_INET6;
			inet_pton(AF_INET6, $2, &sin6->sin6_addr);
		} else {
			mz->notifybind.ss_family = AF_INET;
			inet_pton(AF_INET, $2, &sin->sin_addr.s_addr);
		}
		free($2);
	}
	| comment CRLF
	;

rzone:
	RZONE rzonelabel rzonecontent {
		struct file     *nfile;
		struct rzone *lrz;
		struct stat sb;

		/* we must pull the last zone added */
		lrz = SLIST_FIRST(&rzones);
		if (lrz == NULL || lrz->filename == NULL) {
			fprintf(stderr, "incomplete rzone, missing filename\n");
			return -1;
		}
		if (lstat(lrz->filename, &sb) < 0 || sb.st_size == 0) {
			if (pullzone && pull_remote_zone(lrz) < 0) {
				dolog(LOG_ERR, "can't pull zone %s into filename %s, stop.\n", lrz->zonename, lrz->filename);
				return -1;
			}

		}

		if (file->descend == DESCEND_YES) {
			if ((nfile = pushfile(lrz->filename, 0, DESCEND_NO, RZONEFILE, -1)) == NULL) {
				fprintf(stderr, "failed to include rzone file %s\n", lrz->filename);
				return (-1);
			}

			rzonefile = nfile;
		}

		(void)add_rzone();
		raxfrflag = 1;
	}
	;

rzonelabel:
	QUOTEDSTRING
	;

rzonecontent:
	OBRACE rzonestatements EBRACE CRLF
	| OBRACE CRLF rzonestatements EBRACE CRLF
	;

rzonestatements 	:  		
				rzonestatements rzonestatement 
				| rzonestatement 
				;

rzonestatement:
	
	PRIMARYPORT NUMBER SEMICOLON CRLF
	{
		rz = SLIST_FIRST(&rzones);
		if (rz == NULL) {
				return -1;
		}

		rz->active = 1;
		rz->primaryport = $2 & 0xffff;

	}
	|
	PRIMARY ipcidr SEMICOLON CRLF
	{	
		struct sockaddr_in *sin;
		struct sockaddr_in6 *sin6;
		char *p;

		rz = SLIST_FIRST(&rzones);
		if (rz == NULL) {
				return -1;
		}
	
		rz->active = 1;
		p = strdup($2);
		if (p == NULL) {
			perror("strdup");
			return -1;
		}

		rz->primary = p;

		sin = (struct sockaddr_in *)&rz->storage;
		sin6 = (struct sockaddr_in6 *)&rz->storage;

		if (strchr(rz->primary, ':')) {
			rz->storage.ss_family = AF_INET6;
#ifndef __linux__
			rz->storage.ss_len = 16;
#endif
			inet_pton(AF_INET6, rz->primary, &sin6->sin6_addr);
		} else {
			rz->storage.ss_family = AF_INET;
#ifndef __linux__
			rz->storage.ss_len = 4;
#endif
			inet_pton(AF_INET, rz->primary, &sin->sin_addr.s_addr);
		}


		free($2);
	}
	|
	STRING QUOTEDSTRING SEMICOLON CRLF
	{
		char *p;

		rz = SLIST_FIRST(&rzones);
		if (rz == NULL) {
			fprintf(stderr, "SLIST_FIRST failed\n");
			return -1;
		}

		rz->active = 1;
		p = strdup($2);
		if (p == NULL) {
			perror("strdup");
			return -1;
		}

		if (strcmp($1, "zonename") == 0) {
			rz->zonename = p;
	
			rz->zone = dns_label(p, &rz->zonelen);
			if (rz->zone == NULL) {
				perror("dns_label");
				return -1;
			} 
		} else if (strcmp($1, "filename") == 0) {
			rz->filename = p;

		} else if (strcmp($1, "tsigkey") == 0) {
			rz->tsigkey = p;
		}

		free($1);
		free($2);
	}
	|
	STRING NUMBER COMMA NUMBER COMMA NUMBER SEMICOLON CRLF
	{
		if (strcmp($1, "constraints") == 0) {
			rz = SLIST_FIRST(&rzones);
			if (rz == NULL) {
					return -1;
			}
		
			rz->active = 1;
			
			rz->constraints.refresh = $2;
			rz->constraints.retry = $4;
			rz->constraints.expire = $6;
		}

		free ($1);
	}
	|
	BYTELIMIT NUMBER SEMICOLON CRLF
	{
		rz = SLIST_FIRST(&rzones);
		if (rz == NULL) {
				return -1;
		}

		rz->active = 1;
		rz->bytelimit = $2;
	}
	| comment CRLF
	;

/* zone */

zone:
	ZONE zonelabel zonecontent
	{
		zonecount++;
	}
	;

zonelabel:
	QUOTEDSTRING
	{
		if (insert_zone($1) < 0) {
			return -1;
		}

		zonenumber++;

		free($1);
	}
	;

zonecontent:
		OBRACE zonestatements EBRACE CRLF
		| OBRACE CRLF zonestatements EBRACE CRLF
		;


zonestatements 	:  		
				zonestatements zonestatement 
				| zonestatement 
				;


zonestatement:

		/* centroid.eu,soa,3600,uranus.centroid.eu.,hostcontact.centroid.eu.,1258740680,3600,1800,7200,3600 */

		STRING COMMA STRING COMMA NUMBER COMMA STRING COMMA STRING COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER CRLF 
		{
			if (strcasecmp($3, "soa") == 0) {
				if (fill_soa(mydb, $1, $3, $5, $7, $9, $11, $13, $15, $17, $19) < 0) {
					return -1;
				}

#if DEBUG
				if (debug)
					printf("%s SOA\n", $1);
#endif
			} else {
				if (debug)
					printf("soa error\n");
				return -1;
			}

			
			free ($1);
			free ($3);
			free ($7);
			free ($9);
		}
		|
		STRING COMMA TXT COMMA NUMBER COMMA txtstatements CRLF
		{
			if (fill_txt(mydb, $1, "txt", $5) < 0) {	
				return -1;
			}
			clean_txt();
		}
		|
		STRING COMMA STRING COMMA NUMBER COMMA QUOTEDSTRING CRLF
		{
			if (strcasecmp($3, "eui48") == 0) {
				if (fill_eui48(mydb, $1, $3, $5, $7) < 0) {
					return -1;
				}
			} else if (strcasecmp($3, "eui64") == 0) {
				if (fill_eui64(mydb, $1, $3, $5, $7) < 0) {
					return -1;
				}
			} else {
				if (debug)
					printf("another eui48 like record I don't know?\n");
				return (-1);
			}

			free ($1);
			free ($3);
			free ($7);
		}
		|
		STRING COMMA STRING COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA QUOTEDSTRING COMMA QUOTEDSTRING CRLF
		{
			if (strcasecmp($3, "ipseckey") == 0) { 
				if (fill_ipseckey(mydb, $1, $3, $5, $7, $9, $11, $13, $15) < 0) {
					dolog(LOG_ERR, "error in ipseckey\n");
					return -1;
				}

			} else {
				if (debug)
					printf("another record I don't know about?");
				return (-1);
			}

			free ($1);
			free ($3);
			free ($13);
			free ($15);
		}
		|
		STRING COMMA STRING COMMA NUMBER COMMA STRING COMMA NUMBER COMMA NUMBER COMMA QUOTEDSTRING CRLF
		{
			if (strcasecmp($3, "cert") == 0) { 
				if (fill_cert(mydb, $1, $3, $5, $7, $9, $11, $13) < 0) {
					dolog(LOG_ERR, "error in cert\n");
					return -1;
				}

			} else {
				if (debug)
					printf("another record I don't know about?");
				return (-1);
			}

			free ($1);
			free ($3);
			free ($13);
		}
		| 
		STRING COMMA STRING COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA FLOAT COMMA STRING COMMA NUMBER COMMA NUMBER COMMA FLOAT COMMA STRING COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER CRLF
		{
			if (strcasecmp($3, "loc") == 0) {
				if (fill_loc(mydb, $1, $3, $5, $7, $9, $11, $13, $15, $17, $19, $21, $23, $25, $27, $29) < 0) {
					return -1;
				}
			}

			free($1);
			free($3);
			free($13);
			free($21);
		}
		|
		STRING COMMA STRING COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA QUOTEDSTRING CRLF
		{
			if (strcasecmp($3, "sshfp") == 0) { 
				if (fill_sshfp(mydb, $1, $3, $5, $7, $9, $11) < 0) {
					return -1;
				}

			} else {
				if (debug)
					printf("another sshfp record I don't know about?");
				return (-1);
			}

			free ($1);
			free ($3);
			free ($11);
		}
		|
		STRING COMMA STRING COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA STRING CRLF
		{
			if (strcasecmp($3, "srv") == 0) { 
				if (fill_srv(mydb, $1, $3, $5, $7, $9, $11, $13) < 0) {
					return -1;
				}
#if DEBUG
				if (debug)
					printf("SRV\n");
#endif
			} else if (strcasecmp($3, "zonemd") == 0) { 
				int hexlen;
				char tmpbuf[DIGEST_LENGTH];

				hexlen = hex2bin($13, strlen($13), tmpbuf);
				if (fill_zonemd(mydb, $1, $3, $5, $7, $9, $11, tmpbuf, hexlen) < 0) {
					return -1;
				}
			} else {
				if (debug)
					printf("2 another record I don't know about?");
				return (-1);
			}

			free ($1);
			free ($3);
			free ($13);
		}
		|
		STRING COMMA STRING COMMA NUMBER COMMA STRING CRLF {
			if (strcasecmp($3, "ns") == 0 || 
				strcasecmp($3, "delegate") == 0 ||
				strcasecmp($3, "hint") == 0) {
				if (fill_ns(mydb, $1, $3, $5, $7) < 0) {
					return -1;
				}

#if DEBUG
				if (debug)
					printf("%s NS\n", $1);
#endif

			} else if (strcasecmp($3, "ptr") == 0) {
				if (fill_ptr(mydb, $1, $3, $5, $7) < 0) {
					return -1;
				}

#if DEBUG
				if (debug)
					printf("%s PTR\n", $1);
#endif

			} else if (strcasecmp($3, "cname") == 0) {
				if (fill_cname(mydb, $1, $3, $5, $7) < 0) {
					return -1;
				}

#if DEBUG
				if (debug)
					printf("%s CNAME\n", $3);
#endif

			} else {
				if (debug)
					printf("%s other\n", $3);
				return -1;
			}

			free ($1);
			free ($3);
			free ($7);
		}
		|
		STRING COMMA STRING COMMA NUMBER COMMA IPV6 CRLF {
			if (strcasecmp($3, "aaaa") == 0) {
				if (fill_aaaa(mydb, $1, $3, $5, $7) < 0) {
					return -1;
				}

#if DEBUG
				if (debug)
					printf("%s AAAA\n", $1);
#endif
			} else {

				if (debug)
					printf("error AAAA\n");
				return (-1);
			}
			free ($1);
			free ($3);
			free ($7);
		}
		|
		STRING COMMA STRING COMMA NUMBER COMMA IP CRLF 
		{
			if (strcasecmp($3, "a") == 0) { 
				if (fill_a(mydb, $1, $3, $5, $7) < 0) {
					dolog(LOG_DEBUG, "fill_a returns");
					return -1;
				}

#if DEBUG
				if (debug)
					printf("%s A\n", $1);
#endif

			} else {
				if (debug)
					printf("another a record?\n");
				return -1;
			}

			free ($1);
			free ($3);
			free ($7);
		}
		|
		STRING COMMA STRING COMMA NUMBER COMMA NUMBER COMMA STRING CRLF
		{
			if (strcasecmp($3, "mx") == 0) { 
				if (fill_mx(mydb, $1, $3, $5, $7, $9) < 0) {
					return -1;
				}

#if DEBUG
				if (debug)
					printf("%s MX -> %lld %s\n", $1, $7, $9);
#endif

			} else if (strcasecmp($3, "kx") == 0) {
				if (fill_kx(mydb, $1, $3, $5, $7, $9) < 0) {
					return -1;
				}

#if DEBUG
				if (debug)
					printf("%s MX -> %lld %s\n", $1, $7, $9);
#endif
				
			} else {
				if (debug)
					printf("another record I don't know about?");
				return (-1);
			}

			free ($1);
			free ($3);
			free ($9);
		}
		|
		STRING COMMA STRING COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA QUOTEDSTRING COMMA QUOTEDSTRING COMMA QUOTEDSTRING COMMA STRING CRLF
		{
			if (strcasecmp($3, "naptr") == 0) {
				if (fill_naptr(mydb, $1, $3, $5, $7, $9, $11, $13, $15, $17) < 0) {	
					return -1;
				}

#if DEBUG
				if (debug)
					printf(" %s NAPTR\n", $1);
#endif
			} else {
				if (debug)
					printf("another naptr like record I don't know?\n");
				return (-1);
			}

			free ($1);
			free ($3);
			free ($11);
			free ($13);
			free ($15);
			free ($17);
		}
		|
		STRING COMMA STRING COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA QUOTEDSTRING CRLF
		{
			if (! dnssec) {
				dolog(LOG_INFO, "WARNING DNSSEC DNSKEY/DS/NSEC3PARAM/TLSA RR but no dnssec enabled!\n");
			}

			if (strcasecmp($3, "dnskey") == 0) {
				if (fill_dnskey(mydb, $1, $3, $5, $7, $9, $11, $13, DNS_TYPE_DNSKEY) < 0) {	
					return -1;
				}

#if DEBUG
				if (debug)
					printf(" %s DNSKEY\n", $1);
#endif
			} else if (strcasecmp($3, "cdnskey") == 0) {
				if (fill_dnskey(mydb, $1, $3, $5, $7, $9, $11, $13, DNS_TYPE_CDNSKEY) < 0) {	
					return -1;
				}

#if DEBUG
				if (debug)
					printf(" %s CDNSKEY\n", $1);
#endif
			} else if (strcasecmp($3, "ds") == 0) {
				if (fill_ds(mydb, $1, $3, $5, $7, $9, $11, $13, DNS_TYPE_DS) < 0) {
					return -1;
				}
#if DEBUG
				if (debug)
					printf(" %s DS\n", $1);
#endif
			} else if (strcasecmp($3, "cds") == 0) {
				if (fill_ds(mydb, $1, $3, $5, $7, $9, $11, $13, DNS_TYPE_CDS) < 0) {
					return -1;
				}
#if DEBUG
				if (debug)
					printf(" %s DS\n", $1);
#endif
			} else if (strcasecmp($3, "nsec3param") == 0) {
				if (fill_nsec3param(mydb, $1, $3, $5, $7, $9, $11, $13) < 0) {
					return -1;
				}
#if DEBUG
				if (debug)
					printf(" %s NSEC3PARAM\n", $1);
#endif
			} else if (strcasecmp($3, "tlsa") == 0) {
				if (fill_tlsa(mydb, $1, $3, $5, $7, $9, $11, $13) < 0) {
					return -1;
				}
#if DEBUG
				if (debug)
					printf(" %s TLSA\n", $1);
#endif
			} else {
				if (debug)
					printf("another dnskey like record I don't know?\n");
				return (-1);
			}

			free ($1); 
			free ($3);
			free ($13);
		}
		|
		STRING COMMA STRING COMMA NUMBER COMMA STRING COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA STRING COMMA QUOTEDSTRING CRLF
		{
			if (strcasecmp($3, "rrsig") == 0) {
				if (! dnssec) {
					dolog(LOG_INFO, "WARNING DNSSEC RRSIG RR but no dnssec enabled!\n");
				}

				if (fill_rrsig(mydb, $1, $3, $5, $7, $9, $11, $13, $15, $17, $19, $21, $23) < 0) {	
					fprintf(stderr, "fill_rrsig failed\n");
					return -1;
				}

#if DEBUG
				if (debug)
					printf(" %s RRSIG\n", $1);
#endif
			} else {
				if (debug)
					printf("another rrsig like record I don't know?\n");
				return (-1);
			}

			free ($1); 
			free ($3);
			free ($7);
			free ($21);
			free ($23);
		}
		|
		STRING COMMA STRING COMMA NUMBER COMMA STRING COMMA QUOTEDSTRING CRLF
		{
			if (strcasecmp($3, "nsec") == 0) {
				if (! dnssec) {
					dolog(LOG_INFO, "WARNING DNSSEC NSEC RR but no dnssec enabled!\n");
				}

				if (fill_nsec(mydb, $1, $3, $5, $7, $9) < 0) {
					return -1;
				}

#if DEBUG
				if (debug)
					printf(" %s NSEC\n", $1);
#endif
			} else {
				if (debug)
					printf("another nsec like record I don't know?\n");
				return (-1);
			}

			free ($1); 
			free ($3);
			free ($7);
			free ($9);
		}
		|
		STRING COMMA STRING COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA QUOTEDSTRING COMMA QUOTEDSTRING COMMA QUOTEDSTRING CRLF
		{
			if (strcasecmp($3, "nsec3") == 0) {
				if (! dnssec) {
					dolog(LOG_INFO, "WARNING DNSSEC NSEC3 RR but no dnssec enabled!\n");
				}

				if (fill_nsec3(mydb, $1, $3, $5, $7, $9, $11, $13, $15, $17, NULL) < 0) {
					return -1;
				}

#if DEBUG
				if (debug)
					printf(" %s NSEC3\n", $1);
#endif
			}



			free ($1);
			free ($3);
			free ($13);
			free ($15);
			free ($17);
		}
		|
		STRING COMMA STRING COMMA NUMBER COMMA NUMBER COMMA STRING COMMA QUOTEDSTRING CRLF
		{
			if (strcasecmp($3, "caa") == 0) { 
				if (fill_caa(mydb, $1, $3, $5, $7, $9, $11) < 0) {
					return -1;
				}

#if DEBUG
				if (debug)
					printf("%s CAA -> %lld %s \"%s\"\n", $1, $7, $9, $11);
#endif
			} else if (strcasecmp($3, "svcb") == 0) {
				if (fill_svcb(mydb, $1, $3, $5, $7, $9, $11) < 0) {	
					return -1;
				}

#ifndef __linux__
				if (debug)
					printf("%s SVCB -> %llu %s %s\n", $1, $7, $9, $11);
#endif

			} else if (strcasecmp($3, "https") == 0) {
				if (fill_https(mydb, $1, $3, $5, $7, $9, $11) < 0) {	
					return -1;
				}

#ifndef __linux__
				if (debug)
					printf("%s HTTPS -> %llu %s %s\n", $1, $7, $9, $11);
#endif
			} else {
				if (debug)
					printf("another record I don't know about?");
				return (-1);
			}

			free ($1);
			free ($3);
			free ($9);
			free ($11);

		}
		|
		STRING COMMA STRING COMMA NUMBER COMMA QUOTEDSTRING COMMA QUOTEDSTRING CRLF
		{
			/* HINFO */
			if (strcasecmp($3, "hinfo") == 0) { 
				if (fill_hinfo(mydb, $1, $3, $5, $7, $9) < 0) {
					return -1;
				}

#if DEBUG
				if (debug)
					printf("%s HINFO -> \"%s\" \"%s\"\n", $1, $7, $9);
#endif

			} else {
				if (debug)
					printf("another record I don't know about?");
				return (-1);
			}

			free ($1);
			free ($3);
			free ($7);
			free ($9);
		}
		|
		STRING COMMA STRING COMMA NUMBER COMMA STRING COMMA STRING CRLF
		{
			/* RP */
			if (strcasecmp($3, "rp") == 0) { 
				if (fill_rp(mydb, $1, $3, $5, $7, $9) < 0) {
					return -1;
				}

#if DEBUG
				if (debug)
					printf("%s RP -> %s %s\n", $1, $7, $9);
#endif

			} else {
				if (debug)
					printf("another record I don't know about?");
				return (-1);
			}

			free ($1);
			free ($3);
			free ($7);
			free ($9);
		}
		| comment CRLF
		;


txtstatements:		txt_l 	{ $$ = NULL; }
			;	

txt_l:			QUOTEDSTRING	{ if (add_txt($1, 0) < 0) return -1; }
			| QUOTEDSTRING COMMA txt_l { if (add_txt($1, 0) < 0) return -1;}
			;


options:
	OPTIONS optionscontent
	{
		if ((confstatus & CONFIG_VERSION) != CONFIG_VERSION) {
                        dolog(LOG_INFO, "There must be a version at the top of the first configfile\n");
                        return (-1);
                }
	}
	;

optionscontent:
			OBRACE optionsstatements EBRACE CRLF
			| OBRACE CRLF optionsstatements EBRACE CRLF
			;

optionsstatements:
			optionsstatement 
			| optionsstatements optionsstatement 
			;
			
optionsstatement:

	STRING SEMICOLON CRLF
	{
		if (file->descend == DESCEND_YES) {
			if (strcasecmp($1, "dnssec") == 0) {
				dolog(LOG_DEBUG, "DNSSEC enabled\n");
				dnssec = 1;
			} else if (strcasecmp($1, "log") == 0) {
				dolog(LOG_DEBUG, "logging on\n");
				lflag = 1;
			} else if (strcasecmp($1, "tcp-on-any-only") == 0) {
				dolog(LOG_DEBUG, "TCP on ANY only\n");
				tcpanyonly = 1;
			} else if (strcasecmp($1, "nocookies") == 0) {
				dolog(LOG_DEBUG, "turning cookies off\n");
				cookies = 0;
			} else if (strcasecmp($1, "replicant-axfr-old-behaviour") == 0) {
				dolog(LOG_DEBUG, "using old AXFR behaviour (broken)\n");
				replicant_axfr_old_behaviour = 1;
			} else if (strcasecmp($1, "primary-axfr-old-behaviour") == 0) {
				dolog(LOG_DEBUG, "using old primary AXFR behaviour (no questions in axfr)\n");
				primary_axfr_old_behaviour = 1;
			} else if (strcasecmp($1, "strictaxfr") == 0) {
				dolog(LOG_DEBUG, "only allowing authenticated AXFR's\n");
				strictaxfr = 1;
			}
		}
	}
	|
	STRING QUOTEDSTRING SEMICOLON CRLF
	{
		if (file->descend == DESCEND_YES) {
			if (strcasecmp($1, "interface") == 0) {
				iflag = 1;
				if (icount > 253) {
					dolog(LOG_ERR, "too many interface keywords in options\n");
					return (-1);
				}
		
				dolog(LOG_DEBUG, "interface \"%s\" added\n", $2);
				interface_list[icount++] = $2;
			} else if (strcasecmp($1, "tls-certfile") == 0) {
				tls_certfile = strdup($2);
				if (tls_certfile == NULL) {
					dolog(LOG_INFO, "strdup: %s\n", strerror(errno));
					return -1;
				}
			} else if (strcasecmp($1, "tls-keyfile") == 0) {
				tls_keyfile = strdup($2);
				if (tls_keyfile == NULL) {
					dolog(LOG_INFO, "strdup: %s\n", strerror(errno));
					return -1;
				}
			} else if (strcasecmp($1, "tls-protocols") == 0) {
				tls_protocols = strdup($2);
				if (tls_protocols == NULL) {
					dolog(LOG_INFO, "strdup: %s\n", strerror(errno));
					return -1;
				}
			} else if (strcasecmp($1, "tls-ciphers") == 0) {
				tls_ciphers = strdup($2);
				if (tls_ciphers == NULL) {
					dolog(LOG_INFO, "strdup: %s\n", strerror(errno));
					return -1;
				}
			} else if (strcasecmp($1, "versionstring") == 0) {
				if (strlen($2) > 255) {
					dolog(LOG_ERR, "versionstring too long\n");
					return (-1);
				}

				versionstring = strdup($2);
				vslen = strlen(versionstring);
			} else if (strcasecmp($1, "cookie-secret") == 0) {
				cookiesecret_len = 
					mybase64_decode((const char *)$2, (u_char *)cookiesecret,
						cookiesecret_len);

				if (cookiesecret_len < 0) {
					dolog(LOG_ERR, "cookie-secret had errors (base64)\n");
					return (-1);
				}
				if (cookiesecret_len < SIPHASH_KEY_LENGTH) {
					dolog(LOG_ERR, "cookie-secret too short (16 bytes min)\n");
					return (-1);
				}

			}
		}
	}
	|
	PORT NUMBER SEMICOLON CRLF
	{
		port = $2 & 0xffff;
		dolog(LOG_DEBUG, "listening on port %d\n", port);
	}
	|
	STRING NUMBER SEMICOLON CRLF
	{
		if (file->descend == DESCEND_YES) {
			if (strcasecmp($1, "axfrport") == 0) {
				if ($2 > 0 && $2 <= 65535) {
					dolog(LOG_DEBUG, "axfrport at %d\n", $2);
					axfrport = $2;
				}
			} else if (strcasecmp($1, "fork") == 0) {
				dolog(LOG_DEBUG, "forking %d times\n", $2);
				nflag = $2;
			} else if (strcasecmp($1, "ratelimit-pps") == 0) {
				if ($2 > 127 || $2 < 1) {
					dolog(LOG_ERR, "ratelimit packets per second must be between 1 and 127, or leave it off!\n");
					return -1;
				}	
				ratelimit = 1;
				ratelimit_packets_per_second = $2;
				dolog(LOG_DEBUG, "ratelimiting to %d packets per second\n", ratelimit_packets_per_second);
			} else if (strcasecmp($1, "ratelimit-cidr") == 0) {
				if (($2 != 8) && ($2 != 16) && ($2 != 24)) {
					dolog(LOG_ERR, "ratelimit-cidr must be 8, 16, or 24, or leave it off!\n");
					return -1;
				}
				ratelimit_cidr = $2;
			} else if (strcasecmp($1, "ratelimit-cidr6") == 0) {
				if (($2 != 64) && ($2 != 32)) {
					dolog(LOG_ERR, "ratelimit-cidr6 must be 32 or 64, or leave it off!\n");
					return -1;
				}
				ratelimit_cidr6 = $2;
			} else if (strcasecmp($1, "max-udp-payload") == 0) {
				max_udp_payload = $2;

				dolog(LOG_DEBUG, "max-udp-payload is now %u\n", max_udp_payload);
			} else if (strcasecmp($1, "tls-port") == 0) {
				tls = 1;
				tls_port = $2;
				
				dolog(LOG_DEBUG, "tls-pot is %u\n", tls_port);
			}	
		}
	}
	|
	STRING ipcidr SEMICOLON CRLF
	{
		if (file->descend == DESCEND_YES) {
			if (strcasecmp($1, "bind") == 0) {
				bflag = 1;
				if (bcount > 253) {
					dolog(LOG_ERR, "too many bind keywords in options\n");
					return (-1);
				}
				dolog(LOG_DEBUG, "binding to %s\n", $2);
				bind_list[bcount++] = $2;
			} else if (strcasecmp($1, "notifybind") == 0) {
				dolog(LOG_DEBUG, "notifies binding to %s\n", $2);
				if (strchr($2, ':') == NULL) {
					inet_pton(AF_INET, $2, &notifybind.addr);
					notifybind.af = AF_INET;
				} else {
					inet_pton(AF_INET6, $2, &notifybind.addr6);
					notifybind.af = AF_INET6;
				}
			}
		}
	}
	|
	NOTIFYBIND ipcidr SEMICOLON CRLF
	{
		dolog(LOG_DEBUG, "notifies binding to %s\n", $2);
		if (strchr($2, ':') == NULL) {
			inet_pton(AF_INET, $2, &notifybind.addr);
			notifybind.af = AF_INET;
		} else {
			inet_pton(AF_INET6, $2, &notifybind.addr6);
			notifybind.af = AF_INET6;
		}
	}
	|
	RDOMAIN NUMBER SEMICOLON CRLF
	{
		if ($2 > 255 || $2 < 0) {
			dolog(LOG_INFO, "bad rdomain number (0-255)\n");
			return -1;
		}

		rdomain = $2;
		forward_rdomain = rdomain;
		
		dolog(LOG_DEBUG, "default rdomain is now %u\n", rdomain);
	}
	| comment CRLF
	;

/* tsig { .. } */

tsig:
	TSIG tsigcontent
	{
		if ((confstatus & CONFIG_VERSION) != CONFIG_VERSION) {
                        dolog(LOG_INFO, "There must be a version at the top of the first configfile\n");
                        return (-1);
                }
	}
	;

tsigcontent:
			OBRACE tsigstatements EBRACE 
			| OBRACE CRLF tsigstatements EBRACE 
			;

tsigstatements 	:  		
				tsigstatements tsigstatement 
				| tsigstatement 
				;

tsigstatement	:	ipcidr SEMICOLON CRLF
			{
					char prefixlength[INET_ADDRSTRLEN];
					char *dst;
					

					if (file->descend == DESCEND_YES) {
							if ((dst = get_prefixlen($1, (char *)&prefixlength, sizeof(prefixlength))) == NULL)  {
								return (-1);
							}

							if (insert_tsig(dst, prefixlength) < 0) {
								dolog(LOG_ERR, "insert_tsig, line %d\n", file->lineno);
								return (-1);
							}
			
							if (debug)
								printf("tsig inserted %s address\n", $1);
			
							tsig = 1;

							free (dst);
					}

					free ($1);
			}
			| comment CRLF
			;	

/* tsigpassname { .. } */

tsigpassname:
	TSIGPASSNAME tsigpassnamecontent
	{
		if ((confstatus & CONFIG_VERSION) != CONFIG_VERSION) {
                        dolog(LOG_INFO, "There must be a version at the top of the first configfile\n");
                        return (-1);
                }
	}
	;

tsigpassnamecontent:
			OBRACE tsigpassnamestatements EBRACE 
			| OBRACE CRLF tsigpassnamestatements EBRACE 
			;

tsigpassnamestatements 	:  		
				tsigpassnamestatements tsigpassnamestatement 
				| tsigpassnamestatement 
				;

tsigpassnamestatement	:	QUOTEDSTRING SEMICOLON CRLF
			{
					if (insert_tsigpassname($1) != 0) {
						dolog(LOG_INFO, "insert_tsigpassname failed\n");
						return -1;
					}

					tsigpassname = 1;
					free ($1);
			}
			| comment CRLF
			;	

/* passlist "these hosts" { .. } */

passlist:
	PASSLIST passlistcontent
	{
		if ((confstatus & CONFIG_VERSION) != CONFIG_VERSION) {
                        dolog(LOG_INFO, "There must be a version at the top of the first configfile\n");
                        return (-1);
                }
	}
	;

passlistcontent:
			OBRACE passliststatements EBRACE 
			| OBRACE CRLF passliststatements EBRACE 
			;

passliststatements 	:  		
				passliststatements passliststatement 
				| passliststatement 
				;

passliststatement	:	ipcidr SEMICOLON CRLF
			{
					char prefixlength[INET_ADDRSTRLEN];
					char *dst;
					

					if (file->descend == DESCEND_YES) {
							if ((dst = get_prefixlen($1, (char *)&prefixlength, sizeof(prefixlength))) == NULL)  {
								return (-1);
							}

							if (insert_passlist(dst, prefixlength) < 0) {
								dolog(LOG_ERR, "insert_passlist, line %d\n", file->lineno);
								return (-1);
							}
			
							if (debug)
								printf("passlist inserted %s address\n", $1);
			
							passlist = 1;

							free (dst);
					}

					free ($1);
			}
			| comment CRLF
			;	

/* forward { .. } */

forward:
	FORWARD forwardcontent
	{
		if ((confstatus & CONFIG_VERSION) != CONFIG_VERSION) {
                        dolog(LOG_INFO, "There must be a version at the top of the first configfile\n");
                        return (-1);
                }

		forward = 1;
	}
	;

forwardcontent:
			OBRACE forwardstatements EBRACE 
			| OBRACE CRLF forwardstatements EBRACE 
			;

forwardstatements 	:  		
				forwardstatements forwardstatement 
				| forwardstatement 
				;

forwardstatement	:	INCOMINGTSIG STRING SEMICOLON CRLF
			{
				if (strcmp($2, "yes") == 0 ||
					strcmp($2, "on") == 0 ||
					strcmp($2, "1") == 0) {
					forwardtsig = 1;
				}

				free($2);
			}
			| DESTINATION ipcidr PORT NUMBER STRING STRING SEMICOLON CRLF
			{
				struct sockaddr_storage sso;
				struct sockaddr_in *sin = (struct sockaddr_in *)&sso;
				struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&sso;

				memset(&sso, 0, sizeof(struct sockaddr_storage));

				if (strchr($2, ':') != NULL) {
					inet_pton(AF_INET6, $2, &sin6->sin6_addr);
					sin6->sin6_family = AF_INET6;
					sin6->sin6_port = htons($4);
#ifndef __linux__
					sin6->sin6_len = sizeof(struct sockaddr_in6);
#endif
					insert_forward(AF_INET6, &sso, $4, $6);
				} else {
					inet_pton(AF_INET, $2, &sin->sin_addr);
					sin->sin_family = AF_INET;
					sin->sin_port = htons($4);
					insert_forward(AF_INET, &sso, $4, $6);
				}

					
				free($5);
				free($6);
			}
			| CACHE STRING SEMICOLON CRLF
			{
				if (strcmp($2, "yes") == 0 ||
					strcmp($2, "on") == 0)

					cache = 1;

	
				free ($2);
			}
			| STRICTX20 STRING SEMICOLON CRLF
			{
				if (strcmp($2, "no") == 0 ||
					strcmp($2, "off") == 0)

					strictx20i = 0;
	
				free ($2);
			}
			| FUDGE NUMBER SEMICOLON CRLF
			{
				if ($2 > 65535 || $2 < 1) {
                        		dolog(LOG_INFO, "Fudge value out of Range (1-65535)\n");
                        		return (-1);
				}	
	
				fudge_forward = $2;
			}
			| RDOMAIN NUMBER SEMICOLON CRLF
			{
				if ($2 > 255 || $2 < 0) {
                        		dolog(LOG_INFO, "rdomain value out of Range (0-255)\n");
                        		return (-1);
				}	

				forward_rdomain = $2;
			}
			| FORWARDSTRATEGY STRING SEMICOLON CRLF
			{
				if (strcmp($2, "single") == 0)
					forwardstrategy = STRATEGY_SINGLE;	
				else if (strcmp($2, "spray") == 0)
					forwardstrategy = STRATEGY_SPRAY;

				free($2);
			}
			| WRAP64REGION NUMBER SEMICOLON CRLF
			{
				wrap6to4region = $2;
			}
			| comment CRLF
			;	

/* filter "these hosts" { .. } */

filter:
	FILTER filtercontent
	{
		if ((confstatus & CONFIG_VERSION) != CONFIG_VERSION) {
                        dolog(LOG_INFO, "There must be a version at the top of the first configfile\n");
                        return (-1);
                }
	}
	;

filtercontent:
			OBRACE filterstatements EBRACE 
			| OBRACE CRLF filterstatements EBRACE 
			;

filterstatements 	:  		
				filterstatements filterstatement 
				| filterstatement 
				;

filterstatement	:	ipcidr SEMICOLON CRLF
			{
					char prefixlength[INET_ADDRSTRLEN];
					char *dst;
					

					if (file->descend == DESCEND_YES) {
							if ((dst = get_prefixlen($1, (char *)&prefixlength, sizeof(prefixlength))) == NULL)  {
								return (-1);
							}

							if (insert_filter(dst, prefixlength) < 0) {
								dolog(LOG_ERR, "insert_filter, line %d\n", file->lineno);
								return (-1);
							}
			
							if (debug)
								printf("filter inserted %s address\n", $1);

							free (dst);
					}

					free ($1);
			}
			| comment CRLF
			;	

/* axfr-for {  .. } */

axfr:
	AXFRFOR axfrcontent
	{
		if ((confstatus & CONFIG_VERSION) != CONFIG_VERSION) {
                        dolog(LOG_INFO, "There must be a version at the top of the first configfile\n");
                        return (-1);
                }
	}
	;

axfrcontent:
			OBRACE axfrstatements EBRACE 
			| OBRACE CRLF axfrstatements EBRACE 
			;

axfrstatements 	:  		
				axfrstatements axfrstatement 
				| axfrstatement 
				;

axfrstatement	:	ipcidr SEMICOLON CRLF
			{
					char prefixlength[INET_ADDRSTRLEN];
					char *dst;
					

					if (file->descend == DESCEND_YES) {
							if ((dst = get_prefixlen($1, (char *)&prefixlength, sizeof(prefixlength))) == NULL)  {
								return (-1);
							}

							if (insert_axfr(dst, prefixlength) < 0) {
								dolog(LOG_ERR, "insert_axfr, line %d\n", file->lineno);
								return (-1);
							}
			
							if (debug)
								printf("axfr inserted %s address\n", $1);

							free (dst);

					}

					free ($1);
			}
			| comment CRLF
			;	

/* region "lacnic" { .. } */

region:
	REGION regionlabel regioncontent
	{
		if ((confstatus & CONFIG_VERSION) != CONFIG_VERSION) {
			dolog(LOG_INFO, "There must be a version at the top of the first configfile\n");
			return (-1);
		}

		region++;
	}
	;

regionlabel:
	QUOTEDSTRING
	;	

regioncontent:
			OBRACE regionstatements EBRACE
			| OBRACE CRLF regionstatements EBRACE
			;

regionstatements 	:  		
				regionstatements regionstatement 
				| regionstatement 
				;

regionstatement		:	ipcidr SEMICOLON CRLF
				{
					char prefixlength[INET_ADDRSTRLEN];
					char *dst;
				
					if (file->descend == DESCEND_YES) {
							if ((dst = get_prefixlen($1, (char *)&prefixlength, sizeof(prefixlength))) == NULL)  {
								return (-1);
							}

							if (insert_region(dst, prefixlength, region) < 0) {
								dolog(LOG_ERR, "insert_region, line %d\n", file->lineno);
								return (-1);
							}
							
							if (debug)
								printf("%s ipv4 address\n", dst);

							free (dst);

					}

					free ($1);
				}
				| comment CRLF
				;

ipcidr: 
	IP 
	| IPV6 
	;


%%

struct tab {
	char *val;
	int num;
	int state;
};


struct tab cmdtab[] = {
	{ "axfr-for", AXFRFOR, STATE_IP },
	{ "bytelimit", BYTELIMIT, 0 },
	{ "cache", CACHE, 0 },
	{ "destination", DESTINATION, 0 },
	{ "filter", FILTER, STATE_IP },
	{ "forward", FORWARD, 0 },
	{ "forwardstrategy", FORWARDSTRATEGY, 0},
	{ "fudge", FUDGE, 0 },
	{ "include", INCLUDE, 0 },
	{ "incoming-tsig", INCOMINGTSIG, 0 },
	{ "mzone", MZONE, 0},
	{ "notifybind", NOTIFYBIND, 0},
	{ "notifydest", NOTIFYDEST, 0},
	{ "options", OPTIONS, 0 },
	{ "passlist", PASSLIST, STATE_IP },
	{ "port", PORT, 0},
	{ "primary", PRIMARY, 0 },
	{ "primaryport", PRIMARYPORT, 0 },
	{ "rdomain", RDOMAIN, 0 },
	{ "region", REGION, STATE_IP },
	{ "rzone", RZONE, 0 },
	{ "strictx20", STRICTX20, 0},
	{ "tsig", TSIG, 0 },
	{ "tsig-auth", TSIGAUTH, 0 }, 
	{ "tsigpassname", TSIGPASSNAME, 0 },
	{ "txt", TXT, 0 },
	{ "wildcard-only-for", WOF, STATE_IP },
	{ "wrap6to4region", WRAP64REGION, 0 },
	{ "version", VERSION, 0 },
	{ "zinclude", ZINCLUDE, 0 },
	{ "zone", ZONE, 0 },
	{ NULL, 0, 0}};



void 
yyerror(const char *str)
{
	dolog(LOG_ERR, "%s file: %s line: %d\n", str, file->name, file->lineno);
	ddd_shutdown();
	exit (1);
}

int 
yywrap() 
{
	return 1;
}

int
parse_file(ddDB *db, char *filename, uint32_t flags, int fd)
{
	int errors = 0;

	mydb = db;
	memset(&notifybind, 0, sizeof(struct nb));

	if (flags & PARSEFILE_FLAG_NOSOCKET)
		pullzone = 0;

	if (flags & PARSEFILE_FLAG_NOTSIGKEYS)
		notsigs = 1;

	if ((flags & PARSEFILE_FLAG_ZONEFD) != PARSEFILE_FLAG_ZONEFD) {
		cookiesecret_len = 128;		/* XXX 16 */
		cookiesecret = malloc(cookiesecret_len);
		if (cookiesecret == NULL) {
			dolog(LOG_ERR, "malloc: %s\n", strerror(errno));
			return (-1);
		}
		arc4random_buf(cookiesecret, cookiesecret_len);
		(void)add_rzone();

	} else
		filename = NULL;


        if ((file = pushfile(filename, 0, (filename == NULL) ? DESCEND_NO : DESCEND_YES, NO_RZONEFILE, fd)) == NULL) {
                return (-1);
        }

        topfile = file;


	if (yyparse() < 0) {
		dolog(LOG_ERR, "error %d: %s line: %d\n", errors, file->name, file->lineno);
		return (-1);
	}
        errors = file->errors;
        popfile(0);


	if ((flags & PARSEFILE_FLAG_ZONEFD) != PARSEFILE_FLAG_ZONEFD) {
		while (!TAILQ_EMPTY(&rzonefiles)) {
			/* handle the rzone files */
			topfile = file = TAILQ_FIRST(&rzonefiles);

			if (yyparse() < 0) {
				dolog(LOG_ERR, "error: %s line: %d\n", \
					file->name, file->lineno);
				return (-1);
			}

			errors = file->errors;
			popfile(1);
		}
	} 

	if (dnssec)
		finalize_nsec3();

	cleanup_files();

#if DEBUG
	dolog(LOG_INFO, "configuration file read\n");
#endif
	
	return 0;
}

int
yylex(void) 
{
	struct tab *p;
	static char buf[DIGEST_LENGTH];
	static char dst[INET6_ADDRSTRLEN];
	char *cp = NULL;
	int c, cpos;
	static int setupstate = 0;
#ifndef __NetBSD__
	const char *errstr;
#endif


	do {
		c = lgetc(0);
	} while ((c == ' ') || (c == '\t'));
	
	if (c == EOF)
		return 0;

	if (c == '\n') {
		file->lineno++;

		while ((c = lgetc(0)) != EOF && (c == '\n' || c == ' ' || c == '\t'))
			if (c == '\n')
				file->lineno++;
		lungetc(c);


#ifdef LEXDEBUG
		if (debug) 
			printf("returning %s\n", "crlf");
#endif
		
		return CRLF;
	}

	switch (state) {
	case STATE_IP:
		if (c == ':' || isalnum(c)) {
			lungetc(c);
			get_ip(buf, sizeof(buf) - 1);
		
			yylval.v.string = strdup(buf);
			if (yylval.v.string == NULL) {
				dolog(LOG_ERR, "yylex: %s\n", strerror(errno));
				ddd_shutdown();
				exit(1);
			}
#ifdef LEXDEBUG
			if (debug)
				printf("returning %s\n", "IP");
#endif
			return (IP);
		}
		/* FALLTHROUGH */
	default:
		if (c == '}') {
#ifdef LEXDEBUG
			if (debug)
				printf("returning %s\n", "ebrace");
#endif
			setupstate = 0;
			state = 0;
			return EBRACE;
		}
		
		if (c == '{') {
			if (setupstate)
				state = setupstate;
#ifdef LEXDEBUG
			if (debug)
				printf("returning %s\n", "obrace");
#endif
			return OBRACE;
		}
		
		if (c == '/') {
#ifdef LEXDEBUG
			if (debug)
				printf("returning %s\n", "slash");
#endif
			return SLASH;
		}

		if (c == ',')  {
#ifdef LEXDEBUG
			if (debug)
				printf("returning %s\n", "comma");
#endif
			return COMMA;
		}


		if (c == ';') {
			while ((c = lgetc(0)) != EOF && c != '\n');
			lungetc(c);
#ifdef LEXDEBUG
			if (debug)
				printf("returning %s\n", "semicolon");
#endif
			return SEMICOLON;
		}

		if (c == '#') {
			while ((c = lgetc(0)) != EOF && c != '\n');
			lungetc(c);
#ifdef LEXDEBUG
			if (debug)
				printf("returning %s\n", "pound");
#endif
			return POUND;
		}

		if (c == '"') {
			int len;

			get_quotedstring(buf, sizeof(buf) - 1);

			if ((cp = strrchr(buf, '"'))) {
				cpos = cp - buf;
				//c = buf[cpos];
				buf[cpos] = '\0';
			}

			len = strlen(buf) + 1;	
#if __OpenBSD__
			yylval.v.string = calloc_conceal(1, len);
#else
			yylval.v.string = calloc(1, len);
#endif
			if (yylval.v.string == NULL) {
				dolog(LOG_ERR, "yylex: %s\n", strerror(errno));
				ddd_shutdown();
				exit(1);
			}

			strlcpy(yylval.v.string, buf, len);

#ifdef LEXDEBUG
			if (debug) {
				printf("returning %s\n", "quotedstring");
				printf("quotedstring is %s\n", buf);
			}
#endif
			explicit_bzero(&buf, len);

			return QUOTEDSTRING;
		}

		if (isalnum(c) || c == '.' || c == ':' || c == '-' || \
				c == '_' || c == '*') {
			lungetc(c);
			get_string(buf, sizeof(buf) - 1);
		
			if ((cp = strpbrk(buf, " \n"))) {
				cpos = cp - buf;
				c = buf[cpos];
				buf[cpos] = '\0';
			}

			p = lookup(cmdtab, buf);
			if (p != NULL) {
#ifdef LEXDEBUG
				if (debug)
					printf("returning %s\n", p->val);
#endif
				yylval.v.string = strdup(p->val);
				if (yylval.v.string == NULL) {
					dolog(LOG_ERR, "yylex: %s\n", strerror(errno));
					ddd_shutdown();
					exit(1);
				}
				setupstate = p->state;
				return (p->num);
			}

			yylval.v.string = strdup(buf);
			if (yylval.v.string == NULL) {
				dolog(LOG_ERR, "yylex: %s\n", strerror(errno));
				ddd_shutdown();
				exit(1);
			}


			memset(&dst, 0, sizeof(dst));
			if (strchr(buf, ':') != NULL) {
			   if (inet_net_pton(AF_INET6, buf, &dst, sizeof(dst)) == -1) {
				if (errno == EAFNOSUPPORT && 
					temp_inet_net_pton_ipv6(buf, &dst, sizeof(dst)) != -1) 
#if LEXDEBUG
					if (debug)
						printf("returning IPV6\n");
#endif
					return IPV6;
			   } else {

#if LEXDEBUG
					if (debug)
						printf("returning IPV6\n");
#endif
					return IPV6;
			   }
			}					

			memset(&dst, 0, sizeof(dst));
			if (dottedquad(buf) && 
			  inet_net_pton(AF_INET, buf, &dst, sizeof(dst)) != -1){
#if LEXDEBUG
				if (debug)
					printf("returning %s\n", "IP");
#endif
				return IP;
			}

			for (cp = &buf[0]; *cp != '\0'; cp++) {
				if ((! isdigit((int)*cp)) && (*cp != '.'))
					break;
			}	

			if (*cp != '\0' || (buf[0] == '.' && buf[1] == '\0')) {
#ifdef LEXDEBUG
				printf("returning %s (%s)\n", "STRING", buf);
#endif
				return (STRING);
			}

#ifdef LEXDEBUG
			dolog(LOG_DEBUG, "returning %s\n", "NUMBER");
#endif

			free (yylval.v.string);

			if (strchr(buf, '.') != NULL) {
				yylval.v.floatval = atof(buf);
				return (FLOAT);
			}
	
#if ! defined __APPLE__ && ! defined __NetBSD__
			yylval.v.intval = strtonum(buf, 0, LLONG_MAX, &errstr);
#else
			yylval.v.intval = atoll(buf);
#endif

			return (NUMBER);
		}

		break;
	}

	printf("returning %c\n", c);
	return (c);
}	

int
get_quotedstring(char *buf, int n)
{
	int c;
	int stack = 0;
	char *cs;

	explicit_bzero(buf, n);
	cs = buf;

	for (; --n > 0;) {
		c = lgetc(0);
		if (c == '\n') {
			*cs = '\0';
			lungetc(c);
			return (0);
		} else if (c == '"') {
			if (stack == 0) {
				*cs++ = c;
				*cs = '\0';		
				return (0);
			} else {
				stack--;
			}
		} else if (c == '\\') {
			if (stack == 0) {
				stack++;
				continue;
			} else {
				stack--;
			}
		} else 
			stack = 0;
				

		*cs++ = c;
	}
	
	return (1);
}

int
get_string(char *buf, int n)
{
	int c;
	char *cs;

	cs = buf;

	for (; --n > 0;) {
		c = lgetc(0);
		if (c == '\n' || c == ' ' || c == ',' || c == ';' || ! (isprint(c) || c == '-' || c == '_')) {
			*cs = '\0';
			lungetc(c);
			return (0);
		}

		*cs++ = c;
	}
	
	return (1);
}

struct tab *
lookup(struct tab *cmdtab, char *keyword)
{
	struct tab *p;

	for (p = cmdtab; p->val != NULL; p++) {
		if (strcmp(p->val, keyword) == 0)
			return (p);
	}

	return (NULL);
}

int
get_ip(char *buf, int n)
{
	int c;
	char *cs;

	cs = buf;

	for (; --n > 0;) {
		c = lgetc(0);
		if (c == ',' || c == '\n' || ! (isalnum(c) || c == '/' || c == ':' || c == '.')) {
			*cs = '\0';
			lungetc(c);
			return (0);
		}

		*cs++ = c;
	}
	
	return (1);
}

char * 
check_rr(char *domainname, char *mytype, int itype, int *converted_namelen)
{
	struct rrtab *rr;
	char *converted_name, *p;
	int i;
	
	
	if ((rr = rrlookup(mytype)) == NULL) {
		dolog(LOG_ERR, "error input line %d\n", file->lineno);
		ddd_shutdown();
		exit(1);
	}
	
	if (rr->type != itype) {
		dolog(LOG_ERR, "error input line %d, expected itype = %d, had %d\n", file->lineno, itype, rr->type);
		return NULL;
	}

	if (strlen(domainname) > (DNS_MAXNAME - 2)) {
		dolog(LOG_ERR, "domain name too long, line %d\n", file->lineno);
		ddd_shutdown();
		exit(1);
	}

	for (i = 0, p = domainname; i < strlen(domainname); i++) {
		*p = tolower((int)*p);
		p++;
	}

	if ((strlen(domainname) == 1) && (domainname[0] == '.')) {
		converted_name = malloc(1);
		if (converted_name == NULL) {
			dolog(LOG_ERR, "malloc failed\n");
			ddd_shutdown();
			exit(1);
		}

		*converted_namelen = 1;
		*converted_name = '\0';
	} else if ((strlen(domainname) == 1) && (domainname[0] == '*')) {
		converted_name = malloc(1);
		if (converted_name == NULL) {
			dolog(LOG_ERR, "malloc failed\n");
			ddd_shutdown();
			exit(1);
		}

		*converted_namelen = 1;
		*converted_name = '*';
	} else {
		converted_name = dns_label(domainname, converted_namelen);

		if (converted_name == NULL) {
			dolog(LOG_ERR, "error processing domain name line %d\n", file->lineno);
			ddd_shutdown();
			exit(1);
		}
	}

	return (converted_name);
}

int
fill_ipseckey(ddDB *db, char *name, char *type, int myttl, uint8_t precedence, uint8_t gwtype, uint8_t alg, char *gateway, char *key)
{
	struct rbtree *rbt;
	struct ipseckey *ipseckey;
	char *myname, *converted_name;
	int len, converted_namelen;
	int i;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_IPSECKEY, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	if ((ipseckey = calloc(1, sizeof(struct ipseckey))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}

	
	ipseckey->gwtype = gwtype;

	switch (gwtype) {
	case 1:
		inet_pton(AF_INET, gateway, &ipseckey->gateway.ip4);
		break;
	case 2:
		inet_pton(AF_INET6, gateway, &ipseckey->gateway.ip6);
		break;
			
	case 3:
		myname = dns_label(gateway, (int *)&len);	
		if (myname == NULL) {
			dolog(LOG_INFO, "illegal nameserver, skipping line %d\n", file->lineno);
			return 0;
		}

		if (len > 0xff || len < 0) {
			dolog(LOG_INFO, "illegal len value , line %d\n", file->lineno);
			return -1;
		}

		ipseckey->dnsnamelen = len;
		memcpy(&ipseckey->gateway.dnsname, myname, len);
		free(myname);

		break;

	default:
		/* a zero set gateway */
		break;
	}

	ipseckey->precedence = precedence;
	ipseckey->alg = alg;

	if (alg != 0) {
		int ret;

		ret = mybase64_decode(key, (u_char *)ipseckey->key, sizeof(ipseckey->key));
		if (ret < 0)  {
			dolog(LOG_INFO, "ipseckey invalid key\n");
			return (-1);
		}

		ipseckey->keylen = ret;
	} else
		ipseckey->keylen = 0;

	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_IPSECKEY, ipseckey, myttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	if (converted_name)
		free (converted_name);

	
	return (0);


}


int
fill_cert(ddDB *db, char *name, char *type, int myttl, char *certtype, uint16_t keytag, uint8_t alg, char *certificate)
{
	struct rbtree *rbt;
	struct cert *cert;
	char *converted_name;
	int converted_namelen;
	int i, ret;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_CERT, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	if ((cert = calloc(1, sizeof(struct cert))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}

	if (strcasecmp(certtype, "PKIX") == 0) {
		cert->type = CERT_PKIX;
	} else if (strcasecmp(certtype, "SPKI") == 0) {
		cert->type = CERT_SPKI;
	} else if (strcasecmp(certtype, "PGP") == 0) {
		cert->type = CERT_PGP;
	} else if (strcasecmp(certtype, "IPKIX") == 0) {
		cert->type = CERT_IPKIX;
	} else if (strcasecmp(certtype, "ISPKI") == 0) {
		cert->type = CERT_ISPKI;
	} else if (strcasecmp(certtype, "IPGP") == 0) {
		cert->type = CERT_IPGP;
	} else if (strcasecmp(certtype, "ACPKIX") == 0) {
		cert->type = CERT_ACPKIX;
	} else if (strcasecmp(certtype, "IACPKIX") == 0) {
		cert->type = CERT_IACPKIX;
	} else if (strcasecmp(certtype, "URI") == 0) {
		cert->type = CERT_URI;
	} else if (strcasecmp(certtype, "OID") == 0) {
		cert->type = CERT_OID;
	} else {
		cert->type = atoi(certtype);
	}
		
	cert->keytag = keytag;
	cert->algorithm = alg;

	ret = mybase64_decode(certificate, (u_char *)cert->cert, sizeof(cert->cert));
	if (ret < 0)  {
		dolog(LOG_INFO, "cert invalid base64\n");
		return (-1);
	}

	cert->certlen = ret;

	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_CERT, cert, myttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	if (converted_name)
		free (converted_name);

	
	return (0);
}


int
fill_cname(ddDB *db, char *name, char *type, int myttl, char *hostname)
{
	struct rbtree *rbt;
	struct cname *cname;
	char *myname, *converted_name;
	int len, converted_namelen;
	int i;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_CNAME, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	if ((cname = calloc(1, sizeof(struct cname))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}


	myname = dns_label(hostname, (int *)&len);	
	if (myname == NULL) {
		dolog(LOG_INFO, "illegal nameserver, skipping line %d\n", file->lineno);
		return 0;
	}

	if (len > 0xff || len < 0) {
		dolog(LOG_INFO, "illegal len value , line %d\n", file->lineno);
		return -1;
	}

	cname->cnamelen = len;
	memcpy((char *)cname->cname, myname, len);

	free(myname);

	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_CNAME, cname, myttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	if (converted_name)
		free (converted_name);

	
	return (0);
}

int
fill_ptr(ddDB *db, char *name, char *type, int myttl, char *hostname)
{
	struct ptr *ptr;
	struct rbtree *rbt;
	int len, converted_namelen;
	char *myname, *converted_name;
	int i;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_PTR, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	myname = dns_label(hostname, (int *)&len);	
	if (myname == NULL) {
		dolog(LOG_INFO, "illegal nameserver, skipping line %d\n", file->lineno);
		return 0;
	}

	if (len > 0xff || len < 0) {
		dolog(LOG_INFO, "illegal len value , line %d\n", file->lineno);
		return -1;
	}

	if ((ptr = calloc(1, sizeof(struct ptr))) == NULL) {
		dolog(LOG_ERR, "calloc %s\n", strerror(errno));
		return -1;
	}

	ptr->ptrlen = len;
	memcpy((char *)ptr->ptr, myname, len);

	free(myname);

	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_PTR, ptr, myttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	if (converted_name)
		free (converted_name);

	
	return (0);

}

/* first two dnssec RRs! */
int		
fill_dnskey(ddDB *db, char *name, char *type, uint32_t myttl, uint16_t flags, uint8_t protocol, uint8_t algorithm, char *pubkey, uint16_t rrtype)
{
	struct dnskey *dnskey;
	struct rbtree *rbt;
	int converted_namelen;
	char *converted_name;
	int i, ret;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, rrtype, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	if ((dnskey = calloc(1, sizeof(struct dnskey))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}

	dnskey->flags = flags;
	dnskey->protocol = protocol;
	dnskey->algorithm = algorithm;

	/* feed our base64 key to the public key */
	ret = mybase64_decode(pubkey, (u_char *)dnskey->public_key, sizeof(dnskey->public_key));
	if (ret < 0) 
		return (-1);

	dnskey->publickey_len = ret;
	
	
	rbt = create_rr(db, converted_name, converted_namelen, rrtype, dnskey, myttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	
	if (converted_name)
		free (converted_name);

	
	return (0);

}

int
fill_rrsig(ddDB *db, char *name, char *type, uint32_t myttl, char *typecovered, uint8_t algorithm, uint8_t labels, uint32_t original_ttl, uint64_t sig_expiration, uint64_t sig_inception, uint16_t keytag, char *signers_name, char *signature)
{
	ddDBT key, data;
	struct rbtree *rbt;
	struct rrsig *rrsig;
	int converted_namelen, signers_namelen;
	char *converted_name, *signers_name2;
	struct rrtab *rr;
	int i, ret;
	char tmpbuf[32];
	struct tm tmbuf;
	time_t timebuf;
#if 0
	int rrtype = RRSIG_RRSET;
#endif

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_RRSIG, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	if ((rr = rrlookup(typecovered)) == NULL) {
		return (-1);
	}

	switch (rr->type) {
	case DNS_TYPE_RRSIG:
		fprintf(stderr, "can't RRSIG an RRSIG!\n");
		return (-1);
		break;
	}

	if ((rrsig = calloc(1, sizeof(struct rrsig))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}

	
	rrsig->type_covered = rr->type;
	rrsig->algorithm = algorithm;
	rrsig->labels = labels;
	rrsig->original_ttl = original_ttl;

#if __FreeBSD__ || __NetBSD__ || __linux__
	snprintf(tmpbuf, sizeof(tmpbuf), "%lu", sig_expiration);
#else
	snprintf(tmpbuf, sizeof(tmpbuf), "%llu", sig_expiration);
#endif
	if (strptime(tmpbuf, "%Y%m%d%H%M%S", &tmbuf) == NULL) {
		perror("sig_expiration");
		return (-1);	
	}
	timebuf = timegm(&tmbuf);
	rrsig->signature_expiration = timebuf;
#if __FreeBSD__ || __NetBSD__ || __linux__
	snprintf(tmpbuf, sizeof(tmpbuf), "%lu", sig_inception);
#else
	snprintf(tmpbuf, sizeof(tmpbuf), "%llu", sig_inception);
#endif
	if (strptime(tmpbuf, "%Y%m%d%H%M%S", &tmbuf) == NULL) {
		perror("sig_inception");
		return (-1);	
	}
	timebuf = timegm(&tmbuf);
	rrsig->signature_inception = timebuf;
	rrsig->key_tag = keytag;

	signers_name2 = check_rr(signers_name, type, DNS_TYPE_RRSIG, &signers_namelen);
	if (signers_name2 == NULL) {
		return (-1);
	}

	memcpy(&rrsig->signers_name, signers_name2, signers_namelen);
	rrsig->signame_len = signers_namelen;

	
	/* feed our base64 key the signature */
	ret = mybase64_decode(signature, (u_char *)rrsig->signature, sizeof(rrsig->signature));

	if (ret < 0) 
		return (-1);

	rrsig->signature_len = ret;

	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_RRSIG, rrsig, original_ttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}

	/* flag this rrset as being a DNSSEC rrset */

	flag_rr(rbt, RBT_DNSSEC);

        memset(&key, 0, sizeof(key));
        memset(&data, 0, sizeof(data));

        key.data = (char *)converted_name;
        key.size = converted_namelen;

        data.data = (void*)rbt;
        data.size = sizeof(struct rbtree);

        if (db->put(db, &key, &data) != 0) {
                return -1;
        }

	if (signers_name2)
		free(signers_name2);

	if (converted_name)
		free (converted_name);


	return (0);

}

int
fill_ds(ddDB *db, char *name, char *type, uint32_t myttl, uint16_t keytag, uint8_t algorithm, uint8_t digesttype, char *digest, uint16_t rrtype)
{
	struct rbtree *rbt;
	struct ds *ds;
	int converted_namelen;
	char *converted_name;
	int i;
	int ret;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, rrtype, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	if ((ds = calloc(1, sizeof(struct ds))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}

	ds->key_tag = keytag;
	ds->algorithm = algorithm;
	ds->digest_type = digesttype; 
	
	ret = hex2bin(digest, strlen(digest), ds->digest);
	ds->digestlen = ret;

	/* rrtype = DNS_TYPE_DS / DNS_TYPE_CDS */
	rbt = create_rr(db, converted_name, converted_namelen, rrtype, ds, myttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	if (converted_name)
		free (converted_name);

	
	return (0);

}

int
fill_nsec3(ddDB *db, char *name, char *type, uint32_t myttl, uint8_t algorithm, uint8_t flags, uint16_t iterations, char *salt, char *nextname, char *bitmap, char *unhashed_name)
{
	struct nsec3 *nsec3;
	struct rbtree *rbt;
	int i;
	int tmpbitmap;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_NSEC3, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	if (dnssec) {
#ifdef DEBUG
		dolog(LOG_INFO, "inserting %s\n", name);
#endif
		insert_nsec3(current_zone, name, converted_name, converted_namelen);
	}

	for (i = 0; i < strlen(nextname); i++) {
		nextname[i] = tolower((int)nextname[i]);
	}


	if ((nsec3 = calloc(1, sizeof(struct nsec3))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}

	nsec3->algorithm = algorithm;
	nsec3->flags = flags;
	nsec3->iterations = iterations;
	if (strcasecmp(salt, "-") == 0) {
		nsec3->saltlen = 0;
	} else {
		nsec3->saltlen = (strlen(salt) / 2);
		hex2bin(salt, strlen(salt), nsec3->salt);
	}

	nsec3->nextlen = base32hex_decode((u_char *)nextname, (u_char*)&nsec3->next);
	if (nsec3->nextlen == 0) {
		dolog(LOG_INFO, "base32_decode faulty");
		return -1;
	}

	/* XXX create/manage bitmap */
	create_nsec_bitmap(bitmap, nsec3->bitmap, &tmpbitmap);
		
	nsec3->bitmap_len = (uint16_t)tmpbitmap;

#if 0
	/* we had a bug and this found it */
	printf(";nsec3->bitmap == \"%s\", nsec3->bitmap_len == %d\n", bitmap, nsec3->bitmap_len);
#endif
	
	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_NSEC3, nsec3, myttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}

	if (unhashed_name != NULL)
		rbt->unhashed_name = unhashed_name;
	else
		rbt->unhashed_name = NULL;

	if (converted_name)
		free (converted_name);
	

	return (0);
}

int
fill_nsec3param(ddDB *db, char *name, char *type, uint32_t myttl, uint8_t algorithm, uint8_t flags, uint16_t iterations, char *salt)
{
	struct rbtree *rbt;
	struct nsec3param *nsec3param;
	int i;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_NSEC3PARAM, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	if ((nsec3param = calloc(1, sizeof(struct nsec3param))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}

	nsec3param->algorithm = algorithm;
	nsec3param->flags = flags;
	nsec3param->iterations = iterations;
	if (strcasecmp(salt, "-") == 0) {
		nsec3param->saltlen = 0;
	} else {
		nsec3param->saltlen = (strlen(salt) / 2);
		hex2bin(salt, strlen(salt), nsec3param->salt);
	}
	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_NSEC3PARAM, nsec3param, myttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}

	if (converted_name)
		free (converted_name);
	

	return (0);
}

int
fill_nsec(ddDB *db, char *name, char *type, uint32_t myttl, char *domainname, char *bitmap)
{
	struct nsec *nsec;
	struct rbtree *rbt;
	int converted_namelen, converted_domainnamelen;
	char *converted_name, *converted_domainname;
	int i;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_NSEC, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	for (i = 0; i < strlen(domainname); i++) {
		domainname[i] = tolower((int)domainname[i]);
	}

	converted_domainname = check_rr(domainname, type, DNS_TYPE_NSEC, &converted_domainnamelen);
	if (converted_name == NULL) {
		if (debug)
			dolog(LOG_INFO, "check_rr failed\n");
		return -1;
	}

	if ((nsec = calloc(1, sizeof(struct nsec))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}

	memcpy(nsec->next, converted_domainname, converted_domainnamelen);
	nsec->next_len = converted_domainnamelen;

	create_nsec_bitmap(bitmap, nsec->bitmap, (int *)&nsec->bitmap_len);
	
	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_NSEC, nsec, myttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}

	if (converted_name)
		free (converted_name);
	

	return (0);

}


int
fill_naptr(ddDB *db, char *name, char *type, int myttl, int order, int preference, char *flags, char *services, char *regexp, char *replacement)
{
	struct rbtree *rbt;
	struct naptr *naptr;
	int converted_namelen;
	char *converted_name, *naptrname;
	int flagslen, serviceslen, regexplen, replacementlen;
	int i, naptr_namelen;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	if ((flagslen = strlen(flags)) > 255 ||
		(serviceslen = strlen(services)) > 255 ||
		(regexplen = strlen(regexp)) > 255 ||
		(replacementlen = strlen(replacement)) > 255) {

		dolog(LOG_ERR, "NAPTR record too long line %d\n", file->lineno);
		return (-1);
	}

	converted_name = check_rr(name, type, DNS_TYPE_NAPTR, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	if ((naptr = (struct naptr *)calloc(1, sizeof(struct naptr))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}

	naptr->order = order;
	naptr->preference = preference;

	memcpy(&naptr->flags, flags, flagslen);
	naptr->flagslen = flagslen;

	memcpy(&naptr->services, services, serviceslen);
	naptr->serviceslen = serviceslen;

	memcpy(&naptr->regexp, regexp, regexplen);
	naptr->regexplen = regexplen;

	naptrname = check_rr(replacement, type, DNS_TYPE_NAPTR, &naptr_namelen);
	if (naptrname == NULL) {
		return -1;
	}

	memcpy(&naptr->replacement, naptrname, naptr_namelen);
	naptr->replacementlen = naptr_namelen;

	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_NAPTR, naptr, myttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	if (naptrname)
		free (naptrname);

	if (converted_name)
		free (converted_name);

	
	return (0);

}

int
fill_eui48(ddDB *db, char *name, char *type, int myttl, char *eui48)
{
	struct rbtree *rbt;
	struct eui48 *eui;
	int converted_namelen;
	char *converted_name;
	int i;
	uint8_t e[6];

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_EUI48, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	if ((eui = (struct eui48 *)calloc(1, sizeof(struct eui48))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}

	sscanf(eui48, "%hhx-%hhx-%hhx-%hhx-%hhx-%hhx", &e[0], &e[1]
							, &e[2], &e[3]
							, &e[4], &e[5]);

	memcpy(&eui->eui48, &e, sizeof(eui->eui48));
	
	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_EUI48, eui, myttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	if (converted_name)
		free (converted_name);
	
	return (0);

}

int
fill_eui64(ddDB *db, char *name, char *type, int myttl, char *eui64)
{
	struct rbtree *rbt;
	struct eui64 *eui;
	int converted_namelen;
	char *converted_name;
	int i;
	uint8_t e[8];

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_EUI64, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	if ((eui = (struct eui64 *)calloc(1, sizeof(struct eui64))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}


	sscanf(eui64, "%hhx-%hhx-%hhx-%hhx-%hhx-%hhx-%hhx-%hhx", &e[0], &e[1]
						, &e[2], &e[3]
						, &e[4], &e[5], &e[6], &e[7]);

	memcpy(&eui->eui64, &e, sizeof(eui->eui64));

	
	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_EUI64, eui, myttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	if (converted_name)
		free (converted_name);
	

	return (0);

}

int
fill_svcb(ddDB *db, char *name, char *type, int myttl, uint16_t priority, char *target, char *param)
{
	struct rbtree *rbt;
	struct svcb *svcb;
	int converted_namelen, target_namelen;
	char *converted_name, *targetname;
	int len, i;
	u_char *tmp;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_SVCB, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	

	if ((svcb = (struct svcb *)calloc(1, sizeof(struct svcb))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}

	len = 65535;
	tmp = calloc(1, len);
	if (tmp == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}

	if (param_human2tlv(param, tmp, &len) < 0) {
		dolog(LOG_ERR, "param_human2tlv\n");
		return -1;
	}

	memcpy(&svcb->param, tmp, len);
	svcb->paramlen = len;

	svcb->priority = priority;

	targetname = check_rr(target, type, DNS_TYPE_SVCB, &target_namelen);
	if (targetname == NULL) {
		return -1;
	}

	memcpy(&svcb->target, targetname, target_namelen);
	svcb->targetlen = target_namelen;


	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_SVCB, svcb, myttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}

	if (targetname)
		free (targetname);
	
	if (converted_name)
		free (converted_name);
	
	free (tmp);


	return (0);

}

int
fill_https(ddDB *db, char *name, char *type, int myttl, uint16_t priority, char *target, char *param)
{
	struct rbtree *rbt;
	struct https *https;
	int converted_namelen, target_namelen;
	char *converted_name, *targetname;
	int len, i;
	u_char *tmp;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_HTTPS, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	

	if ((https = (struct https *)calloc(1, sizeof(struct https))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}

	len = 65535;
	tmp = calloc(1, len);
	if (tmp == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}

	if (param_human2tlv(param, tmp, &len) < 0) {
		dolog(LOG_ERR, "param_human2tlv\n");
		return -1;
	}

	memcpy(&https->param, tmp, len);
	https->paramlen = len;

	https->priority = priority;

	targetname = check_rr(target, type, DNS_TYPE_HTTPS, &target_namelen);
	if (targetname == NULL) {
		return -1;
	}

	memcpy(&https->target, targetname, target_namelen);
	https->targetlen = target_namelen;


	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_HTTPS, https, myttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}

	if (targetname)
		free (targetname);
	
	if (converted_name)
		free (converted_name);
	
	free (tmp);


	return (0);

}

int
fill_txt(ddDB *db, char *name, char *type, int myttl)
{
	char assemble[8192];
	struct rbtree *rbt;
	struct txt *txt;
	int converted_namelen;
	char *converted_name;
	int i, tmplen;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	if ((txt = (struct txt *)calloc(1, sizeof(struct txt))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}

	assemble[0] = '\0';

	TAILQ_FOREACH_SAFE(txt0, &txtentries, txt_entry, txt1) {
		int j, origlen;
		u_char tmp[8192];
		u_char *cp;

		origlen = strlen(txt0->text);
		if (origlen > 255) {
			cp = strdup(txt0->text);
			if (cp == NULL) {
				dolog(LOG_INFO, "strdup: %s\n", strerror(errno));
				return -1;
			}

			for (i = 0, j = 0, tmplen = origlen; tmplen > 0; tmplen -= 255) {
				tmp[i] = ((tmplen >= 255) ? 255 : tmplen);
				i++;
				memcpy(&tmp[i], &cp[j], (tmplen >= 255) ? 255 : tmplen);
				tmp[i + ((tmplen >= 255) ? 255 : tmplen)] = '\0';
				if (j == 0) {
					strlcpy(txt0->text, &tmp[1], origlen);
				} else {
					add_txt((char *)&tmp[i], 1);
				}
				i += 255;
				j += 255;
			}
			free(cp);
		}
	}

	tmplen = 0;
	TAILQ_FOREACH(txt0, &txtentries, txt_entry) {
		int l2, l = strlen(txt0->text);

		if (l > 255) {
			dolog(LOG_INFO, "illegal txt sub-size %d\n", l);
			return -1;
		}

		tmplen += l;
		tmplen++;	/* for size indicator */
		
		l2 = strlen(assemble);

		assemble[l2] = l;
		assemble[l2 + 1] = '\0';

		if (strlcat(assemble, txt0->text, sizeof(assemble)) >= 4096) {
			dolog(LOG_ERR, "fill_txt: more than 4096 characters in TXT RR\n");
			return -1;
		}
	}

	if (tmplen > 4096) {
		dolog(LOG_ERR, "fill_txt: more than 4096 characters in TXT RR\n");
		return -1;
	}

	converted_name = check_rr(name, type, DNS_TYPE_TXT, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	memcpy(&txt->txt, assemble, tmplen);
	txt->txtlen = tmplen;

	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_TXT, txt, myttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	if (converted_name)
		free (converted_name);
	
	return (0);

}

int
fill_tlsa(ddDB *db, char *name, char *type, int myttl, uint8_t usage, uint8_t selector, uint8_t matchtype, char *data)
{
	struct rbtree *rbt;
	struct tlsa *tlsa;
	int converted_namelen;
	char *converted_name;
	char *p, *ep, save;
	int len, i;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_TLSA, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	if ((tlsa = (struct tlsa *)calloc(1, sizeof(struct tlsa))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}

	tlsa->usage = usage;
	tlsa->selector = selector;
	tlsa->matchtype = matchtype;

	switch (matchtype) {
	case 1:
		len = tlsa->datalen = DNS_TLSA_SIZE_SHA256;
		break;
	case 2:
		len = tlsa->datalen = DNS_TLSA_SIZE_SHA512;
		break;
	default:
		dolog(LOG_ERR, "tlsa: unknown match type!\n");
		return -1;
	}

	p = data;
	for (i = 0; i < len; i++) {
		save = p[2];
		p[2] = '\0';
		tlsa->data[i] = strtol(p, &ep, 16);
		p[2] = save;
		p += 2;
	}



	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_TLSA, tlsa, myttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}

	if (converted_name)
		free (converted_name);

	
	return (0);

}

int
fill_sshfp(ddDB *db, char *name, char *type, int myttl, int alg, int fptype, char *fingerprint)
{
	struct sshfp *sshfp;
	struct rbtree *rbt;
	int converted_namelen;
	char *converted_name;
	int i;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_SSHFP, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	if ((sshfp = (struct sshfp *)calloc(1, sizeof(struct sshfp))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}

	sshfp->algorithm = alg;
	sshfp->fptype = fptype;

	switch (fptype) {
	case 1:
		sshfp->fplen = DNS_SSHFP_SIZE_SHA1;
		break;
	case 2:
		sshfp->fplen = DNS_SSHFP_SIZE_SHA256;
		break;
	default:
		dolog(LOG_ERR, "sshfp: unknown fingerprint type!\n");
		return -1;
	}

	memset(sshfp->fingerprint, 0, sizeof(sshfp->fingerprint));
	hex2bin(fingerprint, strlen(fingerprint), sshfp->fingerprint);


	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_SSHFP, sshfp, myttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}


	if (converted_name)
		free (converted_name);

	
	return (0);

}

int
fill_srv(ddDB *db, char *name, char *type, int myttl, int priority, int weight, int port, char *srvhost)
{
	struct srv *srv;
	struct rbtree *rbt;
	int converted_namelen;
	char *converted_name;
	char *srvname;
	int len, i;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_SRV, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	if ((srv = (struct srv *)calloc(1, sizeof(struct srv))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}

	srv->priority = priority;
	srv->weight = weight;
	srv->port = port;

	srvname = dns_label(srvhost, &len);
	if (srvname == NULL) {
		dolog(LOG_INFO, "illegal srv server, skipping line %d\n", file->lineno);
		return (-1);
	}

	srv->targetlen = len;
	memcpy((char *)&srv->target, srvname, len);

	/* bad hack workaround !!! */
	if (strcmp(srvhost, ".") == 0 && len > 1) 
		srv->targetlen = 1;

	free (srvname);

	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_SRV, srv, myttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	if (converted_name)
		free (converted_name);
	
	
	return (0);

}

int
fill_kx(ddDB *db, char *name, char *type, int myttl, int priority, char *kxhost)
{
	struct kx *kx;	
	struct rbtree *rbt;
	int converted_namelen;
	char *converted_name;
	char *kxname;
	int len, i;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_KX, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	if ((kx = (struct kx *)calloc(1, sizeof(struct kx))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}
	kx->preference = priority;

	kxname = dns_label(kxhost, &len);
	if (kxname == NULL) {
		dolog(LOG_INFO, "illegal kx server, skipping line %d\n", file->lineno);
		return (-1);
	}

	kx->exchangelen = len;
	memcpy((char *)&kx->exchange, kxname, len);
	free (kxname);

	
	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_KX, kx, myttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}

	if (converted_name)
		free (converted_name);
	

	return (0);

}

int
fill_mx(ddDB *db, char *name, char *type, int myttl, int priority, char *mxhost)
{
	struct smx *mx;	
	struct rbtree *rbt;
	int converted_namelen;
	char *converted_name;
	char *mxname;
	int len, i;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_MX, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	if ((mx = (struct smx *)calloc(1, sizeof(struct smx))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}
	mx->preference = priority;

	mxname = dns_label(mxhost, &len);
	if (mxname == NULL) {
		dolog(LOG_INFO, "illegal mx server, skipping line %d\n", file->lineno);
		return (-1);
	}

	mx->exchangelen = len;
	memcpy((char *)&mx->exchange, mxname, len);
	free (mxname);

	
	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_MX, mx, myttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}

	if (converted_name)
		free (converted_name);
	

	return (0);

}

int
fill_a(ddDB *db, char *name, char *type, int myttl, char *a)
{
	struct a *sa;
	struct rbtree *rbt;
	int converted_namelen;
	char *converted_name;
	in_addr_t *ia;
	int i;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_A, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}
	
	if ((sa = (struct a *)calloc(1, sizeof(struct a))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}

	ia = (in_addr_t *)&sa->a;
	if ((*ia = inet_addr(a)) == INADDR_ANY) {
		dolog(LOG_INFO, "could not parse A record on line %d\n", file->lineno);
		return (-1);
	}
		
	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_A, sa, myttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	if (converted_name)
		free (converted_name);

	
	return (0);

}


int
fill_aaaa(ddDB *db, char *name, char *type, int myttl, char *aaaa)
{
	struct aaaa *saaaa;
	struct rbtree *rbt;
	int converted_namelen;
	char *converted_name;
	struct in6_addr *ia6;
	int i;

	
	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_AAAA, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	if ((saaaa = (struct aaaa *)calloc(1, sizeof(struct aaaa))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}

	ia6 = (struct in6_addr *)&saaaa->aaaa;
	if (inet_pton(AF_INET6, (char *)aaaa, (char *)ia6) != 1) {
		dolog(LOG_INFO, "AAAA \"%s\" unparseable line %d\n", aaaa, file->lineno);
			return -1;
	}

	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_AAAA, saaaa, myttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	if (converted_name)
		free (converted_name);

	
	return (0);

}

int
fill_loc(ddDB *db, char *name, char *type, int myttl, uint8_t deglat, uint8_t minlat, float seclat, char *ns, uint8_t deglong, uint8_t minlong, float seclong, char *ew, uint32_t altitude, uint32_t size, uint32_t horprec, uint32_t vertprec)
{
	struct loc *loc;
	struct rbtree *rbt;
	int converted_namelen;
	char *converted_name, *p = NULL;
	int i, secs, remsecs;
	int exponent, mantissa;
	char human[16];

	unsigned int poweroften[10] = {1, 10, 100, 1000, 10000, 100000,
					1000000,10000000,100000000,1000000000};

	
	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_LOC, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	if ((loc = (struct loc *)calloc(1, sizeof(struct loc))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}

	/* fill loc here */

	loc->version = 0;

	for (exponent = 0; exponent < 9; exponent++) {
		if (size < poweroften[exponent + 1])
			break;
	}

	mantissa = size / poweroften[exponent];
	loc->size = (mantissa << 4) | exponent;

	secs = (int)seclat;
	snprintf(human, sizeof(human), "%2.3f", seclat);
	p = strchr(human, '.');
	p++;
	remsecs = atoi(p);

	switch (*ns) {
	case 'N':
	case 'n':
		loc->latitude = ((uint32_t)1 << 31) \
				+ (((((deglat * 60) + minlat) * 60) + secs) \
				* 1000) + remsecs;
		break;
	default: /* South */
		loc->latitude = ((uint32_t)1 << 31) \
				- (((((deglat * 60) + minlat) * 60) + secs) \
				* 1000) - remsecs;
		break;
	}

	secs = (int)seclong;
	snprintf(human, sizeof(human), "%2.3f", seclong);
	p = strchr(human, '.');
	p++;
	remsecs = atoi(p);

	switch (*ew) {
	case 'E':
	case 'e':
		loc->longitude = ((uint32_t)1 << 31) \
				+ (((((deglong * 60) + minlong) * 60) \
				+ secs) * 1000) + remsecs;
		break;
	default:  /* West */
		loc->longitude = ((uint32_t)1 << 31) \
				- (((((deglong * 60) + minlong) * 60) \
				+ secs) * 1000) - remsecs;
		break;
	}

 	loc->altitude =  altitude;

	for (exponent = 0; exponent < 9; exponent++) {
		if (horprec < poweroften[exponent + 1])
			break;
	}

	mantissa = horprec / poweroften[exponent];
	loc->horiz_pre = (mantissa << 4) | exponent;
	
	for (exponent = 0; exponent < 9; exponent++) {
		if (vertprec < poweroften[exponent + 1])
			break;
	}

	mantissa = vertprec / poweroften[exponent];
	loc->vert_pre = (mantissa << 4) | exponent;


	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_LOC, loc, myttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	if (converted_name)
		free (converted_name);

	
	return (0);

}


int
fill_ns(ddDB *db, char *name, char *type, int myttl, char *nameserver)
{
	struct ns *ns;
	struct rbtree *rbt;
	int len, converted_namelen;
	char *myname, *converted_name;
	char *n;
	int nstype, i;


	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	if (strcasecmp(type, "ns") == 0) {
		converted_name = check_rr(name, type, DNS_TYPE_NS, &converted_namelen);
		nstype = 0;
	} else if (strcasecmp(type, "hint") == 0) {
		converted_name = check_rr(name, type, DNS_TYPE_HINT, &converted_namelen);
		nstype = NS_TYPE_HINT;
	} else {
		converted_name = check_rr(name, type, DNS_TYPE_DELEGATE, &converted_namelen);
		nstype = NS_TYPE_DELEGATE; 	/* XXX see below */
	}

	if (converted_name == NULL) {
		dolog(LOG_INFO, "converted name == NULL\n");
		return -1;
	}

	/*
	 * check if this is not the apex of a zone, if it was we're almost
	 * guaranteed to have come across a SOA already and it's not flagged
	 * then set the delegate type, this should make it possible to have		 * "NS" records instead of "delegate" records which are delphinusdnsd
	 * internal
	 */

	if ((rbt = find_rrset(db, converted_name, converted_namelen)) != NULL) {
		struct rrset *rrset;
		rrset = find_rr(rbt, DNS_TYPE_SOA);
		if (rrset == NULL)
			nstype = NS_TYPE_DELEGATE;

	} 

	if ((ns = (struct ns *)calloc(1, sizeof(struct ns))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}

	myname = dns_label(nameserver, (int *)&len);	
	if (myname == NULL) {
		dolog(LOG_INFO, "illegal nameserver, skipping line %d\n", file->lineno);
		return -1;
	}

	if (len > 0xff || len < 0) {
		dolog(LOG_INFO, "illegal len value , line %d\n", file->lineno);
		return -1;
	}

	n = (char *)ns->nsserver;
	ns->nslen = len;
	memcpy((char *)n, myname, ns->nslen);

	free(myname);

	ns->ns_type = nstype; 

	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_NS, ns, myttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	if (converted_name)
		free (converted_name);

	
	return (0);

}

int
fill_caa(ddDB *db, char *name, char *type, int myttl, uint8_t flags, char *tag, char *value)
{
	struct caa *caa;
	struct rbtree *rbt;
	char *converted_name;
	int converted_namelen;
	int i;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	if (strlen(tag) > DNS_MAXNAME || strlen(value) > 1024) {
		dolog(LOG_INFO, "input too long\n");
		return -1;
	}

	converted_name = check_rr(name, type, DNS_TYPE_CAA, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	if ((caa = (struct caa *)calloc(1, sizeof(struct caa))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}

	caa->flags = flags;
	caa->taglen = strlen(tag);
	caa->valuelen = strlen(value);

	memcpy(caa->value, value, caa->valuelen);
	memcpy(caa->tag, tag, caa->taglen);

	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_CAA, caa, myttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	free (converted_name);


	return (0);
}

int
fill_hinfo(ddDB *db, char *name, char *type, int myttl, char *cpu, char *os)
{
	struct hinfo *hi;
	struct rbtree *rbt;
	char *converted_name;
	int converted_namelen;
	int i, oslen, cpulen;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	if ((hi = (struct hinfo *)calloc(1, sizeof(struct hinfo))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}

	converted_name = check_rr(name, type, DNS_TYPE_HINFO, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}


	oslen = strlen(os);
	cpulen = strlen(cpu);
	
	if (oslen > 255 || cpulen > 255)
		return -1;

	hi->cpulen = cpulen;
	hi->oslen = oslen;
	
	memcpy(&hi->cpu[0], cpu, cpulen);
	memcpy(&hi->os[0], os, oslen);

	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_HINFO, hi, myttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	if (converted_name)
		free (converted_name);

	
	return (0);

}

int
fill_rp(ddDB *db, char *name, char *type, int myttl, char *mbox, char *txt)
{
	struct rp *rp;
	struct rbtree *rbt;
	char *converted_name;
	int converted_namelen;
	int converted_mboxlen, converted_txtlen;
	char *converted_mbox, *converted_txt;
	int i;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	if ((rp = (struct rp *)calloc(1, sizeof(struct rp))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}

	converted_name = check_rr(name, type, DNS_TYPE_RP, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	converted_mbox = dns_label(mbox, &converted_mboxlen);
	converted_txt = dns_label(txt, &converted_txtlen);
	
	if (converted_mbox == NULL || converted_txt == NULL) {
		dolog(LOG_INFO, "wrong input on dnsname (dns_label)\n");
		return -1;
	}
	
	if (converted_mboxlen > DNS_MAXNAME || converted_txtlen > DNS_MAXNAME) {
		dolog(LOG_INFO, "input names too long\n");	
		return -1;
	}

	memcpy(rp->mbox, converted_mbox, converted_mboxlen);
	memcpy(rp->txt, converted_txt, converted_txtlen);
	rp->txtlen = converted_txtlen;
	rp->mboxlen = converted_mboxlen;
	
	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_RP, rp, myttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	if (converted_name)
		free (converted_name);

	free (converted_mbox);
	free (converted_txt);

	return (0);
}

int
fill_soa(ddDB *db, char *name, char *type, int myttl, char *auth, char *contact, int serial, int refresh, int retry, int expire, int ttl)
{
	struct rbtree *rbt;
	struct soa *soa;
	int len, converted_namelen;
	char *myname, *converted_name;
	int i;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_SOA, &converted_namelen);
	if (converted_name == NULL) {
		dolog(LOG_ERR, "error input line %d\n", file->lineno);
		return (-1);
	}

	if (dnssec) {
		insert_apex(name, converted_name, converted_namelen);
		current_zone = strdup(name);
	}

	if ((soa = (struct soa *)calloc(1, sizeof(struct soa))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}

	myname = dns_label(auth, (int *)&len);	
	if (myname == NULL) {
		dolog(LOG_INFO, "illegal nameserver, skipping line %d\n", file->lineno);
		return 0;
	}

	if (len > 0xff || len < 0) {
		dolog(LOG_INFO, "illegal len value , line %d\n", file->lineno);
		return -1;
	}

	soa->nsserver_len = len;
	memcpy((char *)&soa->nsserver, myname, len);
		
	free(myname);

	myname = dns_label(contact, (int *)&len);
	if (myname == NULL) {
		dolog(LOG_INFO, "illegal nameserver, skipping line %d\n", file->lineno);
		return 0;
	}

	if (len > 0xff || len < 0) {
		dolog(LOG_INFO, "illegal len value , line %d\n", file->lineno);
		return -1;
	}

	soa->rp_len = len;
	memcpy((char *)&soa->responsible_person, myname, len);

	free (myname);

	soa->serial = serial;
	soa->refresh = refresh;
	soa->retry = retry;
	soa->expire = expire;
	soa->minttl = ttl;

	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_SOA, soa, myttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	if (converted_name)
		free (converted_name);

	
	return (0);

}

int
fill_zonemd(ddDB *db, char *name, char *type, int myttl, uint32_t serial, uint8_t scheme, uint8_t alg, char *hash, int hashlen)
{
	struct rbtree *rbt;
	struct zonemd *zonemd;
	int converted_namelen;
	char *converted_name;
	int i;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_ZONEMD, &converted_namelen);
	if (converted_name == NULL) {
		dolog(LOG_ERR, "error input line %d\n", file->lineno);
		return (-1);
	}

	if (dnssec) {
		insert_apex(name, converted_name, converted_namelen);
		current_zone = strdup(name);
	}

	if ((zonemd = (struct zonemd *)calloc(1, sizeof(struct zonemd))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}

	zonemd->serial = serial;
	zonemd->scheme = scheme;
	zonemd->algorithm = alg;

	memcpy(&zonemd->hash, hash, hashlen);
	zonemd->hashlen = hashlen;

	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_ZONEMD, zonemd, myttl, 0);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	if (converted_name)
		free (converted_name);

	
	return (0);

}
struct file *
pushfile(const char *name, int secret, int descend, int rzone, int fd)
{
	struct stat sb;
        struct file     *nfile;

        if ((nfile = calloc(1, sizeof(struct file))) == NULL) {
                dolog(LOG_INFO, "warn: malloc\n");
                return (NULL);
        }
	if (name != NULL) {
		if ((nfile->name = strdup(name)) == NULL) {
			dolog(LOG_INFO, "warn: malloc\n");
			free(nfile);
			return (NULL);
		}
		if ((nfile->stream = fopen(nfile->name, "r")) == NULL) {
			dolog(LOG_INFO, "warn: %s\n", nfile->name);
			free(nfile->name);
			free(nfile);
			return (NULL);
		}

		fd = fileno(nfile->stream);
	} else {
		if ((nfile->name = strdup("[passed descriptor]")) == NULL) {
			dolog(LOG_INFO, "warn: malloc\n");
			free(nfile);
			return (NULL);
		}
		nfile->stream = fdopen(fd, "r");
		if (nfile->stream == NULL) {
			dolog(LOG_INFO, "warn: fdopen() %s\n", strerror(errno));
			free(nfile);
			return (NULL);
		}
	}

	if (fstat(fd, &sb) < 0) {
		dolog(LOG_INFO, "warn: %s\n", strerror(errno));
	}

	/* get the highest time of all included files */
	if (time_changed < sb.st_ctime)
		time_changed = (time_t)sb.st_ctime; /* ufs1 is only 32 bits */

        nfile->lineno = 1;
	nfile->descend = descend;

	if (rzone) 
        	TAILQ_INSERT_TAIL(&rzonefiles, nfile, file_entry);
	else
        	TAILQ_INSERT_TAIL(&files, nfile, file_entry);

        return (nfile);
}

#define MAXPUSHBACK     128

char    *parsebuf;
int      parseindex;
char     pushback_buffer[MAXPUSHBACK];
int      pushback_index = 0;

int
lgetc(int quotec)
{
        int             c;

        if (parsebuf) {
                /* Read character from the parsebuffer instead of input. */
                if (parseindex >= 0) {
                        c = parsebuf[parseindex++];
                        if (c != '\0')
                                return (c);
                        parsebuf = NULL;
                } else
                        parseindex++;
        }

        if (pushback_index)
                return (pushback_buffer[--pushback_index]);

        if (quotec) {
                if ((c = getc(file->stream)) == EOF) {
                        yyerror("reached end of file while parsing "
                            "quoted string");
                       if (file == topfile || popfile(0) == EOF)
                                return (EOF);
                        return (quotec);
                }
                return (c);
        }

        while ((c = getc(file->stream)) == EOF) {
                if (file == topfile || popfile(0) == EOF)
                        return (EOF);
        }
        return (c);
}

int
popfile(int rzone)
{
        struct file     *prev = NULL;

	if (rzone) {
		if ((prev = TAILQ_PREV(file, rzonefiles, file_entry)) != NULL)
			prev->errors += file->errors;
        	TAILQ_REMOVE(&rzonefiles, file, file_entry);
	} else {
		if ((prev = TAILQ_PREV(file, files, file_entry)) != NULL)
			prev->errors += file->errors;
        	TAILQ_REMOVE(&files, file, file_entry);
	}

        fclose(file->stream);
        free(file->name);
        free(file);
        file = prev;
        return (file ? 0 : EOF);
}

void
cleanup_files(void)
{
	while ((file = TAILQ_FIRST(&files))) {
        	TAILQ_REMOVE(&files, file, file_entry);
		free(file->name);
		free(file);
	}
	while ((file = TAILQ_FIRST(&rzonefiles))) {
        	TAILQ_REMOVE(&rzonefiles, file, file_entry);
		free(file->name);
		free(file);
	}
}
			

int
lungetc(int c)
{
        if (c == EOF) 
                return (EOF);

        if (parsebuf) {
                parseindex--;
                if (parseindex >= 0)
                        return (c);
        }
        if (pushback_index < MAXPUSHBACK-1)
                return (pushback_buffer[pushback_index++] = c);
        else
                return (EOF);
}

int
findeol(void)
{
        int     c;

        parsebuf = NULL;
        pushback_index = 0;

        /* skip to either EOF or the first real EOL */
        while (1) {
                c = lgetc(0);
                if (c == '\n') {
                        file->lineno++;
                        break;
                }
                if (c == EOF)
                        break;
        }
        return (ERROR);
}


/*
 * from opensmtpd, the license at the top is compatible with this stuff
 */

static int
temp_inet_net_pton_ipv6(const char *src, void *dst, size_t size)
{
        int     ret;
        int     bits;
        char    buf[sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:255:255:255:255/128")];
        char            *sep;
#if defined __OpenBSD__ || defined __FreeBSD__ || defined __linux__
        const char      *errstr;
#endif

        if (strlcpy(buf, src, sizeof buf) >= sizeof buf) {
                errno = EMSGSIZE;
                return (-1);
        }

        sep = strchr(buf, '/');
        if (sep != NULL)
                *sep++ = '\0';

        ret = inet_pton(AF_INET6, buf, dst);
        if (ret != 1) {
                return (-1);
	}

        if (sep == NULL)
                return 128;

#if ! defined __APPLE__ && ! defined __NetBSD__
        bits = strtonum(sep, 0, 128, &errstr);
        if (errstr)
                return (-1);
#else
	bits = atoi(sep);
#endif

        return bits;
}


char *
get_prefixlen(char *input, char *prefixlength, int plsize)
{
	int af = AF_INET;
	int prefixlen;
	char *ret, *p;

	if (strchr(input, ':') != NULL)
		af = AF_INET6;

	prefixlen = inet_net_pton(af, input, prefixlength, plsize);
	if (prefixlen < 0) {
		if (errno == EAFNOSUPPORT) {
			prefixlen = temp_inet_net_pton_ipv6(input, prefixlength, plsize);
		} else {
			if (debug)
				printf("not address family %d (%s)\n", af, input);
			return (NULL);
		}
	}
	
	if ((p = strchr(input, '/')) != NULL) {
		*p++ = '\0';
	} else {
		if (af == AF_INET)
			p = "32";
		else 
			p = "128";
	}

	snprintf(prefixlength, plsize, "%s", p);
	ret = strdup(input);
	return (ret);
}

void
create_nsec_bitmap(char *rrlist, char *bitmap, int *len)
{
	char tmp[8192];
	char *argv[256];	/* could be more XXX */
	char **ap;
	int argc = 0;
	int i, j, outlen = 0;
	struct rrtab *rr;

	/* short circuit for 0 len bitmaps (ENTS) */
	if (*rrlist == '\0') {
		pack32((char *)len, 0);
		return;
	}

	memset(&tmp, 0, sizeof(tmp));

	for (ap = argv; ap < &argv[255] && 
		(*ap = strsep(&rrlist, " ")) != NULL; argc++) {
		
		if (**ap != '\0') {
			ap++;
		} 
	}
	*ap = NULL;

	for (i = 0; i < argc; i++) {
		rr = rrlookup(argv[i]);
		if (rr != NULL) {
			switch (rr->type % 8) {
			case 0:
				tmp[rr->type / 8] |= 1 << 7;
				break;
			case 1:
				tmp[rr->type / 8] |= 1 << 6;
				break;
			case 2:
				tmp[rr->type / 8] |= 1 << 5;
				break;
			case 3:
				tmp[rr->type / 8] |= 1 << 4;
				break;
			case 4:
				tmp[rr->type / 8] |= 1 << 3;
				break;
			case 5:
				tmp[rr->type / 8] |= 1 << 2;
				break;
			case 6:
				tmp[rr->type / 8] |= 1 << 1;
				break;
			case 7:
				tmp[rr->type / 8] |= 1 << 0;
				break;
			}
		}
	}

	for (i = 0, outlen = 0; i < 255; i++) {
		for (j = 31; j >= 0; j--) {
			if (tmp[(i * 32) + j])
				break;
		}

		if (tmp[(i * 32) + j]) {
			bitmap[0 + outlen] = i;
			bitmap[1 + outlen] = j + 1;
			memcpy(&bitmap[2 + outlen], &tmp[i * 32], j + 1);

			outlen += 2;
			outlen += j + 1;
		}
		
	}

	pack32((char *)len, outlen);

	return;
}

int
hex2bin(char *input, int ilen, char *output)
{
	int i;
	int ret = 0;
	int num;

	for (i = 0; i < ilen; i++) {
		if (isalpha(input[i])) {
			num = (tolower(input[i]) - 'a') + 10;
		} else 
			num = input[i] - '0';

		num <<= 4;
		i++;

		if (isalpha(input[i])) {
			num += (tolower(input[i]) - 'a') + 10;
		} else 
			num += input[i] - '0';

		output[ret++] = num;
	}
	
	return (ret);	
}

/*
 * ADD_RZONE - add a stub (template) remote zone 
 */

static struct rzone *
add_rzone(void)
{	
	struct rzone *lrz;

	lrz = (struct rzone *)calloc(1, sizeof(struct rzone));
	if (lrz == NULL) {
		perror("calloc");
		return NULL;
	}

	lrz->zonename = NULL;
	lrz->primaryport = 53;
	lrz->primary = NULL;
	lrz->tsigkey = NULL;
	lrz->filename = NULL;
	memset(&lrz->storage, 0, sizeof(struct sockaddr_storage));
	lrz->constraints.refresh = 60;
	lrz->constraints.retry = 60;
	lrz->constraints.expire = 60;
	lrz->bytelimit = 0xffffffff;	/* 4 GB */

	SLIST_INSERT_HEAD(&rzones, lrz, rzone_entry);
	
	return (lrz);
}

static int
pull_remote_zone(struct rzone *lrz)
{
	struct passwd *pw;
	int status;
	pid_t pid;

	switch (pid = fork()) {
	case -1:
		dolog(LOG_ERR, "can't fork: %s\n", strerror(errno));
		return -1;
	case 0:
			pw = getpwnam(DEFAULT_PRIVILEGE);
			if (pw == NULL) {
				dolog(LOG_INFO, "getpwnam: %s\n", strerror(errno));
				exit(1);
			}

			/* chroot to the drop priv user home directory */
			if (chroot(DELPHINUS_RZONE_PATH) < 0) {
				dolog(LOG_INFO, "chroot: %s\n", strerror(errno));
				return -1;
			}

#if __OpenBSD__
			if (unveil("/", "rwc") < 0) {
				dolog(LOG_INFO, "unveil(1): %s\n", strerror(errno));
				return -1;
			}

			if (unveil(NULL, NULL) < 0) {
				dolog(LOG_INFO, "unveil: %s\n", strerror(errno));
				return -1;
			}
		
#endif

			if (chdir("/") < 0) {
				dolog(LOG_INFO, "chdir: %s\n", strerror(errno));
				return -1;
			}

			/* set groups */

			if (setgroups(1, &pw->pw_gid) < 0) {
				dolog(LOG_INFO, "setgroups: %s\n", strerror(errno));
				return -1;
			}

#if defined __OpenBSD__ || defined __FreeBSD__
			if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) < 0) {
				dolog(LOG_INFO, "setresgid: %s\n", strerror(errno));
				return -1;
			}

			if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) < 0) {
				dolog(LOG_INFO, "setresuid: %s\n", strerror(errno));
				return -1;
			}

#else
			if (setgid(pw->pw_gid) < 0) {
				dolog(LOG_INFO, "setgid: %s\n", strerror(errno));
				return -1;
			}

			if (setuid(pw->pw_uid) < 0) {
				dolog(LOG_INFO, "setuid: %s\n", strerror(errno));
				return -1;
			}
#endif


#if __OpenBSD__
			if (pledge("stdio rpath wpath cpath chown inet getpw", NULL) < 0) {
				dolog(LOG_INFO, "pledge: %s\n", strerror(errno));
				exit(1);
			}
#endif
	
			if (pull_rzone(lrz, time(NULL)) < 0)
				exit(1);
			
			exit(0);
	default:
		if (waitpid(pid, &status, 0) < 0) {
			return -1;
		}
		break;
	}

	return (0);
}

/*
 * ADD_MZONE - add a stub (template) primary zone 
 */

static struct mzone *
add_mzone(void)
{	
	struct mzone *lmz;

	lmz = (struct mzone *)calloc(1, sizeof(struct mzone));
	if (lmz == NULL) {
		perror("calloc");
		return NULL;
	}

	lmz->zonename = NULL;

	SLIST_INSERT_HEAD(&mzones, lmz, mzone_entry);

	return (lmz);
}

/*
 * NOTIFYSOURCE - XXX this could be improved 
 */

int
notifysource(struct question *q, struct sockaddr_storage *from)
{
	char *zone, *tsigkey;
	int zoneretlen, tsigretlen;
	struct sockaddr_in *rzs, *fromi = (struct sockaddr_in *)from;
	struct sockaddr_in6 *rzs6, *fromi6 = (struct sockaddr_in6 *)from;

	SLIST_FOREACH(rz, &rzones, rzone_entry) {
		if (! rz->active)
			continue;

		zone = dns_label(rz->zonename, &zoneretlen);
		if (zone == NULL) {
			dolog(LOG_ERR, "dns_label: %s\n", strerror(errno));
			return 0;
		}
			

		if (q->tsig.have_tsig && q->tsig.tsigverified) {
				tsigkey = dns_label(rz->tsigkey, &tsigretlen);
				if (tsigkey == NULL) {
					free(zone);
					continue;
				}	
				/* if we are the right zone, right tsigkey, and right primary IP/IP6 */
				if ((zoneretlen == q->hdr->namelen) &&
					(memcasecmp((u_char *)zone, (u_char *)q->hdr->name, zoneretlen) == 0) && 
					(tsigretlen == q->tsig.tsigkeylen) &&
					(memcasecmp((u_char *)tsigkey, (u_char *)q->tsig.tsigkey, tsigretlen) == 0) &&
					(rz->storage.ss_family == from->ss_family)) {
						free(tsigkey);
						free(zone);
						if (from->ss_family == AF_INET) {
							/* IPv4 notify */
							rzs = (struct sockaddr_in *)&rz->storage;
							
							if (fromi->sin_addr.s_addr == rzs->sin_addr.s_addr) {
#if 0
							if (memcmp((void*)&fromi->sin_addr, (void*)&rzs->sin_addr, 4) == 0) {
#endif
								return 1;
							}
						} else {
							/* IPv6 notify */
							rzs6 = (struct sockaddr_in6 *)&rz->storage;

							if (memcmp((void*)&fromi6->sin6_addr,
								(void*)&rzs6->sin6_addr, 16) == 0)
							return 1;
						}
				} else {
					free(tsigkey);
					free(zone);
				}
		} else {
				/* we don't have tsig here */

				if ((zoneretlen == q->hdr->namelen) &&
					(memcasecmp((u_char *)zone, (u_char *)q->hdr->name, zoneretlen) == 0) && 
					(rz->storage.ss_family == from->ss_family)) {
						free(zone);
						if (from->ss_family == AF_INET) {
							/* IPv4 notify */
							rzs = (struct sockaddr_in *)&rz->storage;
							
							if (fromi->sin_addr.s_addr == rzs->sin_addr.s_addr) {
								return 1;
							}
						} else {
							/* IPv6 notify */
							rzs6 = (struct sockaddr_in6 *)&rz->storage;

							if (memcmp((void*)&fromi6->sin6_addr,
								(void*)&rzs6->sin6_addr, 16) == 0)
							return 1;
						}
				} else {
#if DEBUG
					dolog(LOG_INFO, "notify for \"%s\" couldn't match", q->converted_name);
#endif
					free(zone);
				}
		} /* if havetsig */
	
	} /* SLIST_FOREACH */

	errno = ENOENT;

	return 0;
}

int
dottedquad(char *buf)
{
	char *q = buf, *p;
	int i;

	for (i = 0; i < 3; i++) {
		p = strchr(q, '.');
		if (p == NULL)
			return 0;

		q = p + 1;
	}

	return 1;
}

void
clean_txt(void)
{
	while(! TAILQ_EMPTY(&txtentries)) {
		txt0 = TAILQ_FIRST(&txtentries);
		TAILQ_REMOVE(&txtentries, txt0, txt_entry);
		free(txt0->text);	
		free(txt0);
	}
}

int
add_txt(char *string, int fixup)
{
	struct txts *txts;

	txts = calloc(1, sizeof(struct txts));
	if (txts == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		return (-1);
	}
	txts->text = strdup(string);
	if (txts->text == NULL) {
		dolog(LOG_INFO, "strdup: %s\n", strerror(errno));
		return (-1);
	}

	if (fixup)
		TAILQ_INSERT_TAIL(&txtentries, txts, txt_entry);
	else
		TAILQ_INSERT_HEAD(&txtentries, txts, txt_entry);
	return (0);
}
