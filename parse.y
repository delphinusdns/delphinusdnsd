/*
 * Copyright (c) 2014-2019 Peter J. Philipp.  All rights reserved.
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

/*
 * $Id: parse.y,v 1.94 2020/03/06 12:03:51 pjp Exp $
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
extern void 	pack32(char *, u_int32_t);
extern void 	pack16(char *, u_int16_t);
extern void 	pack8(char *, u_int8_t);
extern uint32_t unpack32(char *);
extern uint16_t unpack16(char *);
extern void 	unpack(char *, char *, int);

extern int	memcasecmp(u_char *, u_char *, int);
extern struct rrtab 	*rrlookup(char *);
extern int	base32hex_decode(u_char *, u_char *);
extern void 	dolog(int, char *, ...);
extern char 	*dns_label(char *, int *);
extern u_int8_t find_region(struct sockaddr_storage *, int);
extern int 	insert_apex(char *, char *, int);
extern int 	insert_nsec3(char *, char *, char *, int);
extern int 	insert_region(char *, char *, u_int8_t);
extern int 	insert_axfr(char *, char *);
extern int 	insert_notifyslave(char *, char *);
extern int 	insert_filter(char *, char *);
extern int 	insert_whitelist(char *, char *);
extern int	insert_tsig(char *, char *);
extern int	insert_tsig_key(char *, int, char *, int);
extern void 	slave_shutdown(void);
extern int 	mybase64_encode(u_char const *, size_t, char *, size_t);
extern int 	mybase64_decode(char const *, u_char *, size_t);
extern struct rbtree * create_rr(ddDB *db, char *name, int len, int type, void *rdata);
extern struct rbtree * find_rrset(ddDB *db, char *name, int len);
extern struct rrset * find_rr(struct rbtree *rbt, u_int16_t rrtype);
extern int add_rr(struct rbtree *rbt, char *name, int len, u_int16_t rrtype, void *rdata);
extern int display_rr(struct rrset *rrset);
extern void flag_rr(struct rbtree *);
extern int pull_rzone(struct rzone *, time_t);

extern int whitelist;
extern int tsig;
extern int notify;
extern int errno;
extern int debug;
extern int verbose;
extern int bflag;
extern int iflag;
extern int lflag;
extern int nflag;
extern int bcount;
extern int icount;
extern int ratelimit;
extern int ratelimit_packets_per_second;
extern u_int16_t port;
extern u_int32_t cachesize;
extern char *bind_list[255];
extern char *interface_list[255];
extern char *versionstring;
extern uint8_t vslen;



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

SLIST_HEAD(rzones, rzone)	rzones = SLIST_HEAD_INITIALIZER(rzones);
SLIST_HEAD(mzones ,mzone)	mzones = SLIST_HEAD_INITIALIZER(mzones);

#define STATE_IP 1
#define STATE_ZONE 2

#define NO_RZONEFILE	0
#define RZONEFILE	1

#define DELPHINUSVERSION	9

#define CONFIG_START            0x1
#define CONFIG_VERSION          0x2
#define CONFIG_REGION           0x4
#define CONFIG_ZONE             0x8
#define CONFIG_INCLUDE          0x10
#define CONFIG_WILDCARDONLYFOR  0x20
#define CONFIG_RECURSEFOR       0x40
#define CONFIG_LOGGING          0x80		/* deprecated */
#define CONFIG_AXFRFOR          0x100
#define CONFIG_AXFRPORT         0x200
#define CONFIG_ZINCLUDE		0x400
#define CONFIG_RZONE		0x800

typedef struct {
	union {
		char *string;
		int64_t intval;
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

YYSTYPE yylval;


char *converted_name;
int converted_namelen;
ddDBT key, data;
int axfrport = 0;
time_t time_changed;
int dnssec = 0;
int raxfrflag = 0;

char 		*check_rr(char *, char *, int, int *);
int 		fill_a(char *, char *, int, char *);
int 		fill_aaaa(char *, char *, int, char *);
int 		fill_ptr(char *, char *, int, char *);
int 		fill_cname(char *, char *, int, char *);
int 		fill_mx(char *, char *, int, int, char *);
int 		fill_naptr(char *, char *, int, int, int, char *, char *, char *, char *);
int 		fill_ns(char *, char *, int, char *);
int 		fill_soa(char *, char *, int, char *, char *, int, int, int, int, int);
int 		fill_sshfp(char *, char *, int, int, int, char *);
int 		fill_srv(char *, char *, int, int, int, int, char *);
int 		fill_tlsa(char *, char *,int, uint8_t, uint8_t, uint8_t, char *);
int 		fill_txt(char *, char *, int, char *);
int		fill_dnskey(char *, char *, u_int32_t, u_int16_t, u_int8_t, u_int8_t, char *);
int		fill_rrsig(char *, char *, u_int32_t, char *, u_int8_t, u_int8_t, u_int32_t, u_int64_t, u_int64_t, u_int16_t, char *, char *);
int 		fill_nsec(char *, char *, u_int32_t, char *, char *);
int		fill_nsec3param(char *, char *, u_int32_t, u_int8_t, u_int8_t, u_int16_t, char *);
int		fill_nsec3(char *, char *, u_int32_t, u_int8_t, u_int8_t, u_int16_t, char *, char *, char *);
int		fill_ds(char *, char *, u_int32_t, u_int16_t, u_int8_t, u_int8_t, char *);

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
int 		parse_file(ddDB *, char *, uint32_t);
struct file     *pushfile(const char *, int, int, int);
int             popfile(void);
static int 	temp_inet_net_pton_ipv6(const char *, void *, size_t);
int 		yyparse(void);
static struct rzone * add_rzone(void);
static struct mzone * add_mzone(void);
static int	pull_remote_zone(struct rzone *);
int		notifysource(struct question *, struct sockaddr_storage *);
int 		drop_privs(char *, struct passwd *);


%}


%token VERSION OBRACE EBRACE REGION RZONE AXFRFOR 
%token DOT COLON TEXT WOF INCLUDE ZONE COMMA CRLF 
%token ERROR AXFRPORT OPTIONS FILTER MZONE
%token WHITELIST ZINCLUDE MASTER MASTERPORT TSIGAUTH
%token TSIG NOTIFYDEST NOTIFYBIND PORT

%token <v.string> POUND
%token <v.string> SEMICOLON
%token <v.string> STRING
%token <v.string> IP
%token <v.string> IPV6
%token <v.string> SLASH
%token <v.string> QUOTEDSTRING

%token <v.intval> NUMBER

%type <v.string> quotednumber quotedfilename ipcidr

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
	| axfrport
	| include
	| zinclude
	| zone
	| region CRLF
	| axfr CRLF
	| whitelist CRLF
	| tsig CRLF
	| filter CRLF
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
		if (version != DELPHINUSVERSION) {
			dolog(LOG_ERR, "version of configfile is wrong,"
					" must be \"%d\"!\n", DELPHINUSVERSION);
			return (-1);
		}
		free ($2);
		
		confstatus |= CONFIG_VERSION;
	}
	;

axfrport:
	AXFRPORT quotednumber SEMICOLON CRLF
	{
		if ((confstatus & CONFIG_VERSION) != CONFIG_VERSION) {
			dolog(LOG_INFO, "There must be a version at the top of the first configfile\n");
			return (-1);
		}
		if (file->descend == DESCEND_YES) {
			axfrport = atoi($2);
		}
		free ($2);
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
			if ((nfile = pushfile($2, 0, DESCEND_YES, NO_RZONEFILE)) == NULL) {
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
			if ((nfile = pushfile($2, 0, DESCEND_NO, NO_RZONEFILE)) == NULL) {
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
			printf("quotedfilename is %s\n", $$);
	}
	;


tsigauth:
	TSIGAUTH STRING QUOTEDSTRING SEMICOLON CRLF {
		char key[512];
		char *keyname;
		int keylen, keynamelen;
	
		if ((keylen = mybase64_decode($3, key, sizeof(key))) < 0) {
			dolog(LOG_ERR, "can't decode tsig base64\n");
			return -1;
		}

		keyname = dns_label($2, &keynamelen);
		if (keyname == NULL) {
			dolog(LOG_ERR, "dns_label: %s\n", strerror(errno));
			return -1;
		}

		insert_tsig_key(key, keylen, keyname, keynamelen);

		free($2);
		free($3);
		free(keyname);
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
			if ((nfile = pushfile(lrz->filename, 0, DESCEND_NO, RZONEFILE)) == NULL) {
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
	
	MASTERPORT NUMBER SEMICOLON CRLF
	{
		rz = SLIST_FIRST(&rzones);
		if (rz == NULL) {
				return -1;
		}

		rz->active = 1;
		rz->masterport = $2 & 0xffff;

#ifdef __OpenBSD__
		if (debug)
			printf("at rzone %x, set masterport to %d\n", (unsigned int)rz, rz->masterport);
#endif
	}
	|
	MASTER ipcidr SEMICOLON CRLF
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

		rz->master = p;

		sin = (struct sockaddr_in *)&rz->storage;
		sin6 = (struct sockaddr_in6 *)&rz->storage;

		if (strchr(rz->master, ':')) {
			rz->storage.ss_family = AF_INET6;
#ifndef __linux__
			rz->storage.ss_len = 16;
#endif
			inet_pton(AF_INET6, rz->master, &sin6->sin6_addr);
		} else {
			rz->storage.ss_family = AF_INET;
#ifndef __linux__
			rz->storage.ss_len = 4;
#endif
			inet_pton(AF_INET, rz->master, &sin->sin_addr.s_addr);
		}

#ifdef __OpenBSD__
		if (debug)
			printf("at rzone %x, added master server at %s\n", (unsigned int)rz,
				p);
#endif

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
#ifdef __OpenBSD__
			if (debug)
				printf("at rzone %x, added zonename of %s\n", (unsigned int)rz, p);
#endif
		} else if (strcmp($1, "filename") == 0) {
			rz->filename = p;
#ifdef __OpenBSD__
			if (debug)
				printf("at rzone %x, added filename of %s\n", (unsigned int)rz, p);
#endif

		} else if (strcmp($1, "tsigkey") == 0) {
			rz->tsigkey = p;
#ifdef __OpenBSD__
			if (debug)
				printf("at rzone %x, added tsigkey of %s\n", (unsigned int)rz, p);
#endif
		}

		free($1);
		free($2);
	}
	| comment CRLF
	;

/* zone */

zone:
	ZONE zonelabel zonecontent
	{
#if 0
		if ((confstatus & CONFIG_VERSION) != CONFIG_VERSION) {
                        dolog(LOG_INFO, "There must be a version at the top of the first configfile\n");
                        return (-1);
                }
#endif
	}
	;

zonelabel:
	QUOTEDSTRING
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

		/* centroid.eu,soa,3600,uranus.centroid.eu.,hostmaster.centroid.eu.,1258740680,3600,1800,7200,3600 */

		STRING COMMA STRING COMMA NUMBER COMMA STRING COMMA STRING COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER CRLF 
		{
			if (strcasecmp($3, "soa") == 0) {
				if (fill_soa($1, $3, $5, $7, $9, $11, $13, $15, $17, $19) < 0) {
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
		STRING COMMA STRING COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA QUOTEDSTRING CRLF
		{
			if (strcasecmp($3, "sshfp") == 0) { 
				if (fill_sshfp($1, $3, $5, $7, $9, $11) < 0) {
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
				if (fill_srv($1, $3, $5, $7, $9, $11, $13) < 0) {
					return -1;
				}
#if DEBUG
				if (debug)
					printf("SRV\n");
#endif

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
				if (fill_ns($1, $3, $5, $7) < 0) {
					return -1;
				}

#if DEBUG
				if (debug)
					printf("%s NS\n", $1);
#endif

			} else if (strcasecmp($3, "ptr") == 0) {
				if (fill_ptr($1, $3, $5, $7) < 0) {
					return -1;
				}

#if DEBUG
				if (debug)
					printf("%s PTR\n", $1);
#endif

			} else if (strcasecmp($3, "cname") == 0) {
				if (fill_cname($1, $3, $5, $7) < 0) {
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
				if (fill_aaaa($1, $3, $5, $7) < 0) {
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
				if (fill_a($1, $3, $5, $7) < 0) {
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
				if (fill_mx($1, $3, $5, $7, $9) < 0) {
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
		STRING COMMA STRING COMMA NUMBER COMMA QUOTEDSTRING CRLF
		{
			if (strcasecmp($3, "txt") == 0) {
				if (fill_txt($1, $3, $5, $7) < 0) {	
					return -1;
				}

#if DEBUG
				if (debug)
					printf(" %s TXT -> %s\n", $1, $7);
#endif
			} else {
				if (debug)
					printf("another txt like record I don't know?\n");
				return (-1);
			}

			free ($1);
			free ($3);
			free ($7);
		}
		|
		STRING COMMA STRING COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA QUOTEDSTRING COMMA QUOTEDSTRING COMMA QUOTEDSTRING COMMA STRING CRLF
		{
			if (strcasecmp($3, "naptr") == 0) {
				if (fill_naptr($1, $3, $5, $7, $9, $11, $13, $15, $17) < 0) {	
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
				if (fill_dnskey($1, $3, $5, $7, $9, $11, $13) < 0) {	
					return -1;
				}

#if DEBUG
				if (debug)
					printf(" %s DNSKEY\n", $1);
#endif
			} else if (strcasecmp($3, "ds") == 0) {
				if (fill_ds($1, $3, $5, $7, $9, $11, $13) < 0) {
					return -1;
				}
#if DEBUG
				if (debug)
					printf(" %s DS\n", $1);
#endif
			} else if (strcasecmp($3, "nsec3param") == 0) {
				if (fill_nsec3param($1, $3, $5, $7, $9, $11, $13) < 0) {
					return -1;
				}
#if DEBUG
				if (debug)
					printf(" %s NSEC3PARAM\n", $1);
#endif
			} else if (strcasecmp($3, "tlsa") == 0) {
				if (fill_tlsa($1, $3, $5, $7, $9, $11, $13) < 0) {
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

				if (fill_rrsig($1, $3, $5, $7, $9, $11, $13, $15, $17, $19, $21, $23) < 0) {	
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

				if (fill_nsec($1, $3, $5, $7, $9) < 0) {
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

				if (fill_nsec3($1, $3, $5, $7, $9, $11, $13, $15, $17) < 0) {
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
		| comment CRLF
		;


options:
	OPTIONS optionslabel optionscontent
	{
		if ((confstatus & CONFIG_VERSION) != CONFIG_VERSION) {
                        dolog(LOG_INFO, "There must be a version at the top of the first configfile\n");
                        return (-1);
                }
	}
	;

optionslabel:
	QUOTEDSTRING 
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
			} else if (strcasecmp($1, "versionstring") == 0) {
				if (strlen($2) > 255) {
					dolog(LOG_ERR, "versionstring too long\n");
					return (-1);
				}

				versionstring = strdup($2);
				vslen = strlen(versionstring);
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
			if (strcasecmp($1, "fork") == 0) {
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
			}
		}
	}
	| comment CRLF
	;

/* tsig "these hosts" { .. } */

tsig:
	TSIG tsiglabel tsigcontent
	{
		if ((confstatus & CONFIG_VERSION) != CONFIG_VERSION) {
                        dolog(LOG_INFO, "There must be a version at the top of the first configfile\n");
                        return (-1);
                }
	}
	;

tsiglabel:
	QUOTEDSTRING
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

/* whitelist "these hosts" { .. } */

whitelist:
	WHITELIST whitelistlabel whitelistcontent
	{
		if ((confstatus & CONFIG_VERSION) != CONFIG_VERSION) {
                        dolog(LOG_INFO, "There must be a version at the top of the first configfile\n");
                        return (-1);
                }
	}
	;

whitelistlabel:
	QUOTEDSTRING
	;

whitelistcontent:
			OBRACE whiteliststatements EBRACE 
			| OBRACE CRLF whiteliststatements EBRACE 
			;

whiteliststatements 	:  		
				whiteliststatements whiteliststatement 
				| whiteliststatement 
				;

whiteliststatement	:	ipcidr SEMICOLON CRLF
			{
					char prefixlength[INET_ADDRSTRLEN];
					char *dst;
					

					if (file->descend == DESCEND_YES) {
							if ((dst = get_prefixlen($1, (char *)&prefixlength, sizeof(prefixlength))) == NULL)  {
								return (-1);
							}

							if (insert_whitelist(dst, prefixlength) < 0) {
								dolog(LOG_ERR, "insert_whitelist, line %d\n", file->lineno);
								return (-1);
							}
			
							if (debug)
								printf("whitelist inserted %s address\n", $1);
			
							whitelist = 1;

							free (dst);
					}

					free ($1);
			}
			| comment CRLF
			;	

/* filter "these hosts" { .. } */

filter:
	FILTER filterlabel filtercontent
	{
		if ((confstatus & CONFIG_VERSION) != CONFIG_VERSION) {
                        dolog(LOG_INFO, "There must be a version at the top of the first configfile\n");
                        return (-1);
                }
	}
	;

filterlabel:
	QUOTEDSTRING
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

/* axfr-for "these hosts" { .. } */

axfr:
	AXFRFOR axfrlabel axfrcontent
	{
		if ((confstatus & CONFIG_VERSION) != CONFIG_VERSION) {
                        dolog(LOG_INFO, "There must be a version at the top of the first configfile\n");
                        return (-1);
                }
	}
	;

axfrlabel:
	QUOTEDSTRING
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
	{ "axfrport", AXFRPORT, 0},
	{ "axfr-for", AXFRFOR, STATE_IP },
	{ "whitelist", WHITELIST, STATE_IP },
	{ "filter", FILTER, STATE_IP },
	{ "include", INCLUDE, 0 },
	{ "master", MASTER, 0 },
	{ "masterport", MASTERPORT, 0 },
	{ "mzone", MZONE, 0},
	{ "notifybind", NOTIFYBIND, 0},
	{ "notifydest", NOTIFYDEST, 0},
	{ "options", OPTIONS, 0 },
	{ "port", PORT, 0},
	{ "region", REGION, STATE_IP },
	{ "rzone", RZONE, 0 },
	{ "tsig", TSIG, 0 },
	{ "tsig-auth", TSIGAUTH, 0 }, 
	{ "wildcard-only-for", WOF, STATE_IP },
	{ "version", VERSION, 0 },
	{ "zinclude", ZINCLUDE, 0 },
	{ "zone", ZONE, 0 },
	{ NULL, 0, 0}};



void 
yyerror(const char *str)
{
	dolog(LOG_ERR, "%s file: %s line: %d\n", str, file->name, file->lineno);
	slave_shutdown();
	exit (1);
}

int 
yywrap() 
{
	return 1;
}

int
parse_file(ddDB *db, char *filename, uint32_t flags)
{
	int errors = 0;

	mydb = db;

	if (flags & PARSEFILE_FLAG_NOSOCKET)
		pullzone = 0;


	(void)add_rzone();

        if ((file = pushfile(filename, 0, DESCEND_YES, NO_RZONEFILE)) == NULL) {
                return (-1);
        }

        topfile = file;


	if (yyparse() < 0) {
		dolog(LOG_ERR, "error %d: %s line: %d\n", errors, file->name, file->lineno);
		return (-1);
	}
        errors = file->errors;
        popfile();


	while (!TAILQ_EMPTY(&rzonefiles)) {
		/* handle the rzone files */
		topfile = file = TAILQ_FIRST(&rzonefiles);

		if (yyparse() < 0) {
			dolog(LOG_ERR, "error: %s line: %d\n", file->name, file->lineno);
			return (-1);
		}

		errors = file->errors;
		popfile();
	}


#if DEBUG
	dolog(LOG_INFO, "configuration file read\n");
#endif
	
	return 0;
}

int
yylex(void) 
{
	struct tab *p;
	static char buf[4096];
	static char dst[INET6_ADDRSTRLEN];
	char *cp = NULL;
	int c, cpos;
	static int setupstate = 0;
	const char *errstr;


	do {
		c = lgetc(0);
	} while ((c == ' ') || (c == '\t'));
	
	if (c == EOF)
		return 0;

	if (c == '\n') {
		file->lineno++;

		while ((c = lgetc(0)) != EOF && (c == '\n' || c == '\t'))
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
				slave_shutdown();
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
			get_quotedstring(buf, sizeof(buf) - 1);

			if ((cp = strrchr(buf, '"'))) {
				cpos = cp - buf;
				c = buf[cpos];
				buf[cpos] = '\0';
			}

			yylval.v.string = strdup(buf);
			if (yylval.v.string == NULL) {
				dolog(LOG_ERR, "yylex: %s\n", strerror(errno));
				slave_shutdown();
				exit(1);
			}

#ifdef LEXDEBUG
			if (debug)
				printf("returning %s\n", "quotedstring");
#endif
			return QUOTEDSTRING;
		}

		if (c == '*') {
			yylval.v.string = strdup("*");
			if (yylval.v.string == NULL) {
				dolog(LOG_ERR, "yylex: %s\n", strerror(errno));
				slave_shutdown();
				exit(1);
			}
#ifdef LEXDEBUG
			if (debug)
				printf("returning %s\n", "string");
#endif
			return STRING;
		}

		if (isalnum(c) || c == '.' || c == ':' || c == '-' || c == '_') {
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
					slave_shutdown();
					exit(1);
				}
				setupstate = p->state;
				return (p->num);
			}

			yylval.v.string = strdup(buf);
			if (yylval.v.string == NULL) {
				dolog(LOG_ERR, "yylex: %s\n", strerror(errno));
				slave_shutdown();
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
			if (strchr(buf, '.') != NULL &&
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
#if ! defined __APPLE__ && ! defined __NetBSD__
			yylval.v.intval = strtonum(buf, 0, LLONG_MAX, &errstr);
#else
			yylval.v.intval = atoll(buf);
#endif

			return (NUMBER);
		}

		break;
	}

	return (c);
}	

int
get_quotedstring(char *buf, int n)
{
	int i, c;
	int stack = 0;
	char *cs;

	cs = buf;

	for (i = 0; --n > 0; ++i) {
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
	int i, c;
	char *cs;

	cs = buf;

	for (i = 0; --n > 0; ++i) {
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
	int i, c;
	char *cs;

	cs = buf;

	for (i = 0; --n > 0; ++i) {
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
		slave_shutdown();
		exit(1);
	}
	
	if (rr->type != itype) {
		dolog(LOG_ERR, "error input line %d, expected itype = %d, had %d\n", file->lineno, itype, rr->type);
		return NULL;
	}

	if (strlen(domainname) > (DNS_MAXNAME - 2)) {
		dolog(LOG_ERR, "domain name too long, line %d\n", file->lineno);
		slave_shutdown();
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
			slave_shutdown();
			exit(1);
		}

		*converted_namelen = 1;
		*converted_name = '\0';
	} else if ((strlen(domainname) == 1) && (domainname[0] == '*')) {
		converted_name = malloc(1);
		if (converted_name == NULL) {
			dolog(LOG_ERR, "malloc failed\n");
			slave_shutdown();
			exit(1);
		}

		*converted_namelen = 1;
		*converted_name = '*';
	} else {
		converted_name = dns_label(domainname, converted_namelen);

		if (converted_name == NULL) {
			dolog(LOG_ERR, "error processing domain name line %d\n", file->lineno);
			slave_shutdown();
			exit(1);
		}
	}

	return (converted_name);
}

int
fill_cname(char *name, char *type, int myttl, char *hostname)
{
	ddDB *db = mydb;
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
	cname->ttl = myttl;

	free(myname);

	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_CNAME, cname);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	if (converted_name)
		free (converted_name);

	free (rbt);
	
	return (0);
}

int
fill_ptr(char *name, char *type, int myttl, char *hostname)
{
	ddDB *db = mydb;
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
	ptr->ttl = myttl;

	free(myname);

	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_PTR, ptr);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	if (converted_name)
		free (converted_name);

	free (rbt);
	
	return (0);

}

/* first two dnssec RRs! */
int		
fill_dnskey(char *name, char *type, u_int32_t myttl, u_int16_t flags, u_int8_t protocol, u_int8_t algorithm, char *pubkey)
{
	ddDB *db = mydb;
	struct dnskey *dnskey;
	struct rbtree *rbt;
	int converted_namelen;
	char *converted_name;
	int i, ret;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_DNSKEY, &converted_namelen);
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
	dnskey->ttl = myttl;

	/* feed our base64 key to the public key */
	ret = mybase64_decode(pubkey, dnskey->public_key, sizeof(dnskey->public_key));
	if (ret < 0) 
		return (-1);

	dnskey->publickey_len = ret;
	
	
	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_DNSKEY, dnskey);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	
	if (converted_name)
		free (converted_name);

	free (rbt);
	
	return (0);

}

int
fill_rrsig(char *name, char *type, u_int32_t myttl, char *typecovered, u_int8_t algorithm, u_int8_t labels, u_int32_t original_ttl, u_int64_t sig_expiration, u_int64_t sig_inception, u_int16_t keytag, char *signers_name, char *signature)
{
	ddDB *db = mydb;
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
	rrsig->ttl = original_ttl;

	rrsig->original_ttl = original_ttl;
	snprintf(tmpbuf, sizeof(tmpbuf), "%llu", sig_expiration);
	if (strptime(tmpbuf, "%Y%m%d%H%M%S", &tmbuf) == NULL) {
		perror("sig_expiration");
		return (-1);	
	}
	timebuf = timegm(&tmbuf);
	rrsig->signature_expiration = timebuf;
	snprintf(tmpbuf, sizeof(tmpbuf), "%llu", sig_inception);
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
	ret = mybase64_decode(signature, rrsig->signature, sizeof(rrsig->signature));

	if (ret < 0) 
		return (-1);

	rrsig->signature_len = ret;

	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_RRSIG, rrsig);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}

	/* flag this rrset as being a DNSSEC rrset */

	flag_rr(rbt);

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

	free (rbt);

	return (0);

}

int
fill_ds(char *name, char *type, u_int32_t myttl, u_int16_t keytag, u_int8_t algorithm, u_int8_t digesttype, char *digest)
{
	ddDB *db = mydb;
	struct rbtree *rbt;
	struct ds *ds;
	int converted_namelen;
	char *converted_name;
	int i;
	int ret;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_DS, &converted_namelen);
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
	ds->ttl = myttl;

	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_DS, ds);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	if (converted_name)
		free (converted_name);

	free(rbt);
	
	return (0);

}

int
fill_nsec3(char *name, char *type, u_int32_t myttl, u_int8_t algorithm, u_int8_t flags, u_int16_t iterations, char *salt, char *nextname, char *bitmap)
{
	ddDB *db = mydb;
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

	nsec3->nextlen = base32hex_decode(nextname, (u_char*)&nsec3->next);
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
	
	nsec3->ttl = myttl;

	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_NSEC3, nsec3);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}

	if (converted_name)
		free (converted_name);
	
	free (rbt);

	return (0);
}

int
fill_nsec3param(char *name, char *type, u_int32_t myttl, u_int8_t algorithm, u_int8_t flags, u_int16_t iterations, char *salt)
{
	ddDB *db = mydb;
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
	nsec3param->ttl = myttl;

	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_NSEC3PARAM, nsec3param);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}

	if (converted_name)
		free (converted_name);
	
	free (rbt);

	return (0);
}

int
fill_nsec(char *name, char *type, u_int32_t myttl, char *domainname, char *bitmap)
{
	ddDB *db = mydb;
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

	memcpy(nsec->next_domain_name, converted_domainname, converted_domainnamelen);
	nsec->ndn_len = converted_domainnamelen;

	create_nsec_bitmap(bitmap, nsec->bitmap, (int *)&nsec->bitmap_len);
	nsec->ttl = myttl;
	
	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_NSEC, nsec);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}

	if (converted_name)
		free (converted_name);
	
	free (rbt);

	return (0);

}


int
fill_naptr(char *name, char *type, int myttl, int order, int preference, char *flags, char *services, char *regexp, char *replacement)
{
	ddDB *db = mydb;
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
	naptr->ttl = myttl;

	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_NAPTR, naptr);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	if (naptrname)
		free (naptrname);

	if (converted_name)
		free (converted_name);

	free (rbt);
	
	return (0);

}

int
fill_txt(char *name, char *type, int myttl, char *msg)
{
	ddDB *db = mydb;
	struct rbtree *rbt;
	struct txt *txt;
	int converted_namelen;
	char *converted_name;
	int len, i, j, tmplen, origlen;
	u_char *tmp;
	int messages = 1;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	origlen = tmplen = len = strlen(msg);
	while (tmplen > 255) {
		messages++;
		tmplen -= 255;
	}

	len += messages;

	if (len > 1024) {
		dolog(LOG_ERR, "fill_txt: more than 1024 characters in TXT RR\n");
		return -1;
	}

	tmp = malloc(len);
	if (tmp == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}
		
	for (i = 0, j = 0, tmplen = origlen; tmplen > 0; tmplen -= 255) {
		tmp[i] = ((tmplen >= 255) ? 255 : tmplen);
		i++;
		memcpy(&tmp[i], &msg[j], (tmplen >= 255) ? 255 : tmplen);
		i += 255;
		j += 255;
	}

	converted_name = check_rr(name, type, DNS_TYPE_TXT, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	if ((txt = (struct txt *)calloc(1, sizeof(struct txt))) == NULL) {
		dolog(LOG_ERR, "calloc: %s\n", strerror(errno));
		return -1;
	}

	memcpy(&txt->txt, tmp, len);
	txt->txtlen = len;
	txt->ttl = myttl;

	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_TXT, txt);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	if (converted_name)
		free (converted_name);
	
	free (rbt);
	free (tmp);


	return (0);

}

int
fill_tlsa(char *name, char *type, int myttl, uint8_t usage, uint8_t selector, uint8_t matchtype, char *data)
{
	ddDB *db = mydb;
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


	tlsa->ttl = myttl;

	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_TLSA, tlsa);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}

	if (converted_name)
		free (converted_name);

	free (rbt);
	
	return (0);

}

int
fill_sshfp(char *name, char *type, int myttl, int alg, int fptype, char *fingerprint)
{
	ddDB *db = mydb;
	struct sshfp *sshfp;
	struct rbtree *rbt;
	int converted_namelen;
	char *converted_name;
	int len, i;
	int ret;

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
		len = sshfp->fplen = DNS_SSHFP_SIZE_SHA1;
		break;
	case 2:
		len = sshfp->fplen = DNS_SSHFP_SIZE_SHA256;
		break;
	default:
		dolog(LOG_ERR, "sshfp: unknown fingerprint type!\n");
		return -1;
	}

	memset(sshfp->fingerprint, 0, sizeof(sshfp->fingerprint));
	ret = hex2bin(fingerprint, strlen(fingerprint), sshfp->fingerprint);

	sshfp->ttl = myttl;

	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_SSHFP, sshfp);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}


	if (converted_name)
		free (converted_name);

	free (rbt);
	
	return (0);

}

int
fill_srv(char *name, char *type, int myttl, int priority, int weight, int port, char *srvhost)
{
	ddDB *db = mydb;
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

	srv->ttl = myttl;
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
	srv->ttl = myttl;

	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_SRV, srv);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	if (converted_name)
		free (converted_name);
	
	free (rbt);
	
	return (0);

}

int
fill_mx(char *name, char *type, int myttl, int priority, char *mxhost)
{
	ddDB *db = mydb;
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
	mx->ttl = myttl;

	mxname = dns_label(mxhost, &len);
	if (mxname == NULL) {
		dolog(LOG_INFO, "illegal mx server, skipping line %d\n", file->lineno);
		return (-1);
	}

	mx->exchangelen = len;
	memcpy((char *)&mx->exchange, mxname, len);
	free (mxname);

	
	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_MX, mx);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}

	if (converted_name)
		free (converted_name);
	
	free (rbt);

	return (0);

}

int
fill_a(char *name, char *type, int myttl, char *a)
{
	ddDB *db = mydb;
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
	sa->ttl = myttl;
		
	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_A, sa);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	if (converted_name)
		free (converted_name);

	free (rbt);
	
	return (0);

}


int
fill_aaaa(char *name, char *type, int myttl, char *aaaa)
{
	ddDB *db = mydb;
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
		
	saaaa->ttl = myttl;

	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_AAAA, saaaa);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	if (converted_name)
		free (converted_name);

	free (rbt);
	
	return (0);

}


int
fill_ns(char *name, char *type, int myttl, char *nameserver)
{
	ddDB *db = mydb;
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

		free(rbt);
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
	ns->ttl = myttl;

	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_NS, ns);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	if (converted_name)
		free (converted_name);

	free (rbt);
	
	return (0);

}

int
fill_soa(char *name, char *type, int myttl, char *auth, char *contact, int serial, int refresh, int retry, int expire, int ttl)
{
	ddDB *db = mydb;
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
	soa->ttl = myttl;

	rbt = create_rr(db, converted_name, converted_namelen, DNS_TYPE_SOA, soa);
	if (rbt == NULL) {
		dolog(LOG_ERR, "create_rr failed\n");
		return -1;
	}
	
	if (converted_name)
		free (converted_name);

	free (rbt);
	
	return (0);

}

struct file *
pushfile(const char *name, int secret, int descend, int rzone)
{
	struct stat sb;
        struct file     *nfile;
	int fd;

        if ((nfile = calloc(1, sizeof(struct file))) == NULL) {
                dolog(LOG_INFO, "warn: malloc\n");
                return (NULL);
        }
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
                       if (file == topfile || popfile() == EOF)
                                return (EOF);
                        return (quotec);
                }
                return (c);
        }

        while ((c = getc(file->stream)) == EOF) {
                if (file == topfile || popfile() == EOF)
                        return (EOF);
        }
        return (c);
}

int
popfile(void)
{
        struct file     *prev;

        if ((prev = TAILQ_PREV(file, files, file_entry)) != NULL)
                prev->errors += file->errors;

        TAILQ_REMOVE(&files, file, file_entry);
        fclose(file->stream);
        free(file->name);
        free(file);
        file = prev;
        return (file ? 0 : EOF);
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
		
		if (*ap != '\0') {
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
	lrz->masterport = 53;
	lrz->master = NULL;
	lrz->tsigkey = NULL;
	lrz->filename = NULL;
	memset(&lrz->storage, 0, sizeof(struct sockaddr_storage));

	SLIST_INSERT_HEAD(&rzones, lrz, rzone_entry);
#ifdef __OpenBSD__
	if (debug)
		printf("added rzone at 0x%x\n", (unsigned int)lrz);
#endif
	
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

			if (drop_privs(DELPHINUS_RZONE_PATH, pw) < 0) {
				dolog(LOG_INFO, "can't drop privileges\n");
				exit(1);
			}

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
 * ADD_MZONE - add a stub (template) master zone 
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
			return 0;	/* I guess return 0 is error */
		}
			

		if (q->tsig.have_tsig && q->tsig.tsigverified) {
				tsigkey = dns_label(rz->tsigkey, &tsigretlen);
				if (tsigkey == NULL) {
					dolog(LOG_ERR, "dns_label: %s\n", strerror(errno));
					return 0;
				}	
				/* if we are the right zone, right tsigkey, and right master IP/IP6 */
				if ((zoneretlen == q->hdr->namelen) &&
					(memcasecmp(zone, q->hdr->name, zoneretlen) == 0) && 
					(tsigretlen == q->tsig.tsigkeylen) &&
					(memcasecmp(tsigkey, q->tsig.tsigkey, tsigretlen) == 0) &&
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
					(memcasecmp(zone, q->hdr->name, zoneretlen) == 0) && 
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
					free(zone);
				}
		} /* if havetsig */
	
	} /* SLIST_FOREACH */

	return 0;
}

int
drop_privs(char *chrootpath, struct passwd *pw)
{
	/* chroot to the drop priv user home directory */
	if (chroot(chrootpath) < 0) {
		dolog(LOG_INFO, "chroot: %s\n", strerror(errno));
		return -1;
	}

#if __OpenBSD__
	if (unveil("/", "rwc") < 0) {
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

	return 0;
}
