/*
 * Copyright (c) 2014-2017 Peter J. Philipp.  All rights reserved.
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
 * $Id: parse.y,v 1.47 2017/10/26 15:56:38 pjp Exp $
 */

%{
#include "ddd-include.h"
#include "ddd-dns.h"
#include "ddd-db.h"


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
extern void 	slave_shutdown(void);
extern int 	mybase64_encode(u_char const *, size_t, char *, size_t);
extern int 	mybase64_decode(char const *, u_char *, size_t);
extern int 	get_record_size(ddDB *, char *, int);
extern void *	find_substruct(struct domain *, u_int16_t);
void 		yyerror(const char *);

extern int whitelist;
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
static struct file {
        TAILQ_ENTRY(file)        file_entry;
        FILE                    *stream;
        char                    *name;
        int                      lineno;
        int                      errors;
} *file, *topfile;

#define STATE_IP 1
#define STATE_ZONE 2

#define DELPHINUSVERSION 7

#define CONFIG_START            0x1
#define CONFIG_VERSION          0x2
#define CONFIG_REGION           0x4
#define CONFIG_ZONE             0x8
#define CONFIG_INCLUDE          0x10
#define CONFIG_WILDCARDONLYFOR  0x20
#define CONFIG_RECURSEFOR       0x40
#define CONFIG_LOGGING          0x80
#define CONFIG_AXFRFOR          0x100
#define CONFIG_AXFRPORT         0x200

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

YYSTYPE yylval;


char *converted_name;
int converted_namelen;
ddDBT key, data;
struct logging logging;
int axfrport = 0;
time_t time_changed;
int dnssec = 0;

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
int 		get_record(struct domain *, char *, int);
int 		get_string(char *, int);
int		hex2bin(char *, int, char *);
int             lgetc(int);
struct tab * 	lookup(struct tab *, char *);
int             lungetc(int);
int 		parse_file(ddDB *, char *);
struct file     *pushfile(const char *, int);
int             popfile(void);
struct rrtab 	*rrlookup(char *);
void 		set_record(struct domain *, int, char *, int);
static int 	temp_inet_net_pton_ipv6(const char *, void *, size_t);
int 		yyparse(void);


struct rrtab {
        char *name;
        u_int16_t type;
	int16_t internal_type;
} myrrtab[] =  { 
 { "a",         DNS_TYPE_A, 		INTERNAL_TYPE_A } ,
 { "aaaa",      DNS_TYPE_AAAA,		INTERNAL_TYPE_AAAA },
 { "cname",     DNS_TYPE_CNAME, 	INTERNAL_TYPE_CNAME },
 { "delegate",  DNS_TYPE_DELEGATE, 	INTERNAL_TYPE_NS },
 { "dnskey", 	DNS_TYPE_DNSKEY, 	INTERNAL_TYPE_DNSKEY },
 { "ds", 	DNS_TYPE_DS, 		INTERNAL_TYPE_DS },
 { "hint",      DNS_TYPE_HINT,		INTERNAL_TYPE_NS }, 
 { "mx",        DNS_TYPE_MX, 		INTERNAL_TYPE_MX },
 { "naptr", 	DNS_TYPE_NAPTR,		INTERNAL_TYPE_NAPTR },
 { "ns",        DNS_TYPE_NS,		INTERNAL_TYPE_NS },
 { "nsec", 	DNS_TYPE_NSEC, 		INTERNAL_TYPE_NSEC },
 { "nsec3", 	DNS_TYPE_NSEC3,		INTERNAL_TYPE_NSEC3 },
 { "nsec3param", DNS_TYPE_NSEC3PARAM,	INTERNAL_TYPE_NSEC3PARAM },
 { "ptr",       DNS_TYPE_PTR,		INTERNAL_TYPE_PTR },
 { "rrsig", 	DNS_TYPE_RRSIG, 	-1 },
 { "soa",       DNS_TYPE_SOA, 		INTERNAL_TYPE_SOA },
 { "srv",       DNS_TYPE_SRV, 		INTERNAL_TYPE_SRV },
 { "sshfp", 	DNS_TYPE_SSHFP,		INTERNAL_TYPE_SSHFP },
 { "tlsa", 	DNS_TYPE_TLSA,		INTERNAL_TYPE_TLSA },
 { "txt",       DNS_TYPE_TXT,		INTERNAL_TYPE_TXT },
};




%}


%token VERSION OBRACE EBRACE REGION AXFRFOR 
%token DOT COLON TEXT WOF INCLUDE ZONE COMMA CRLF 
%token ERROR AXFRPORT LOGGING OPTIONS FILTER NOTIFY
%token WHITELIST

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
	| axfrport
	| include
	| zone
	| region CRLF
	| axfr CRLF
	| notify CRLF
	| whitelist CRLF
	| filter CRLF
	| logging
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

		axfrport = atoi($2);
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

		if ((nfile = pushfile($2, 0)) == NULL) {
			fprintf(stderr, "failed to include file %s\n", $2);
			free($2);
			return (-1);
		}

		free($2);

		file = nfile;
	}
	;

quotedfilename:
	QUOTEDSTRING
	{
		if (debug)
			printf("quotedfilename is %s\n", $$);
	}
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

		/* centroid.eu,soa,3600,uranus.centroid.eu.,pjp.solarscale.de.,1258740680,3600,1800,7200,3600 */

		STRING COMMA STRING COMMA NUMBER COMMA STRING COMMA STRING COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER CRLF 
		{
			if (strcasecmp($3, "soa") == 0) {
				if (fill_soa($1, $3, $5, $7, $9, $11, $13, $15, $17, $19) < 0) {
					return -1;
				}

				if (debug)
					printf("%s SOA\n", $1);
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
				if (debug)
					printf("SRV\n");

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

				if (debug)
					printf("%s NS\n", $1);

			} else if (strcasecmp($3, "ptr") == 0) {
				if (fill_ptr($1, $3, $5, $7) < 0) {
					return -1;
				}

				if (debug)
					printf("%s PTR\n", $1);

			} else if (strcasecmp($3, "cname") == 0) {
				if (fill_cname($1, $3, $5, $7) < 0) {
					return -1;
				}

				if (debug)
					printf("%s CNAME\n", $3);

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

				if (debug)
					printf("%s AAAA\n", $1);
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

				if (debug)
					printf("%s A\n", $1);

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

				if (debug)
					printf("%s MX -> %lld %s\n", $1, $7, $9);

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

				if (debug)
					printf(" %s TXT -> %s\n", $1, $7);
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

				if (debug)
					printf(" %s NAPTR\n", $1);
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

				if (debug)
					printf(" %s DNSKEY\n", $1);
			} else if (strcasecmp($3, "ds") == 0) {
				if (fill_ds($1, $3, $5, $7, $9, $11, $13) < 0) {
					return -1;
				}
				if (debug)
					printf(" %s DS\n", $1);
			} else if (strcasecmp($3, "nsec3param") == 0) {
				if (fill_nsec3param($1, $3, $5, $7, $9, $11, $13) < 0) {
					return -1;
				}
				if (debug)
					printf(" %s NSEC3PARAM\n", $1);
			} else if (strcasecmp($3, "tlsa") == 0) {
				if (fill_tlsa($1, $3, $5, $7, $9, $11, $13) < 0) {
					return -1;
				}
				if (debug)
					printf(" %s TLSA\n", $1);
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

				if (debug)
					printf(" %s RRSIG\n", $1);
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

				if (debug)
					printf(" %s NSEC\n", $1);
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

				if (debug)
					printf(" %s NSEC3\n", $1);
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
		if (strcasecmp($1, "dnssec") == 0) {
			dolog(LOG_DEBUG, "DNSSEC enabled\n");
			dnssec = 1;
		} else if (strcasecmp($1, "log") == 0) {
			dolog(LOG_DEBUG, "logging on\n");
			lflag = 1;
		}
	}
	|
	STRING QUOTEDSTRING SEMICOLON CRLF
	{
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
	|
	STRING NUMBER SEMICOLON CRLF
	{
		if (strcasecmp($1, "fork") == 0) {
			dolog(LOG_DEBUG, "forking %d times\n", $2);
			nflag = $2;
		} else if (strcasecmp($1, "port") == 0) {
			port = $2 & 0xffff;
			dolog(LOG_DEBUG, "listening on port %d\n", port);
		} else if (strcasecmp($1, "ratelimit-pps") == 0) {
			if ($2 > 127 || $2 < 1) {
				dolog(LOG_ERR, "ratelimit packets per second must be between 1 and 127, or leave it off!\n");
				return -1;
			}	
			ratelimit = 1;
			ratelimit_packets_per_second = $2;
			dolog(LOG_DEBUG, "ratelimiting to %d packets per second", ratelimit_packets_per_second);
		}
		
	}
	|
	STRING ipcidr SEMICOLON CRLF
	{
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
	| comment CRLF
	;

/* logging below */
	
logging:
	LOGGING logginglabel loggingcontent
	{
		if ((confstatus & CONFIG_VERSION) != CONFIG_VERSION) {
                        dolog(LOG_INFO, "There must be a version at the top of the first configfile\n");
                        return (-1);
                }
	}
	;

logginglabel:
	QUOTEDSTRING 
	;

loggingcontent:
			OBRACE loggingstatements EBRACE CRLF
			| OBRACE CRLF loggingstatements EBRACE CRLF
			;

loggingstatements:
			loggingstatement CRLF
			| loggingstatements loggingstatement CRLF
			;
			
loggingstatement:
	STRING STRING SEMICOLON 
	{
		char buf[512];
		
		if (strcasecmp($1, "logbind") == 0) {
			logging.active = 1;
			logging.bind = 0;

			gethostname(buf, sizeof(buf));
			logging.hostname = strdup(buf);
			if (logging.hostname == NULL) {
				dolog(LOG_ERR, "strdup failed\n");
				return (-1);
			}
	
			if (strcmp($2, "yes") == 0) {
				logging.bind = 1;
			}
		} else if (strcasecmp($1, "logpasswd") == 0) {
		
			logging.logpasswd = strdup($2);
		
			if (logging.logpasswd == NULL) {
				dolog(LOG_ERR, "strdup failed\n");
				return (-1);
			}

		} else {
			if (debug)
				printf("another logging statement I don't know?\n");
			return (-1);
		}

	}
	|
	STRING NUMBER SEMICOLON 
	{
		char buf[16];

		if (strcasecmp($1, "logport") == 0) {
			snprintf(buf, sizeof(buf), "%lld", $2);
			logging.logport = strdup(buf);
			if (logging.logport == NULL) {
				dolog(LOG_ERR, "strdup failed\n");
				return (-1);
			}
			logging.logport2 = $2;
		}
	}	
	|
	STRING ipcidr SEMICOLON
	{
		struct addrinfo hints, *res0;
		struct sockaddr_in6 *psin6;
		struct sockaddr_in *psin;
		int error;

		if (strcasecmp($1, "loghost") == 0) {
			logging.loghost = strdup($2);
			if (logging.loghost == NULL) {
				dolog(LOG_ERR, "strdup failed\n");

				return (-1);
			}

			if (strchr($2, ':') != NULL) {
				memset(&hints, 0, sizeof(hints));
				hints.ai_family = AF_INET6;
				hints.ai_socktype = SOCK_STREAM;
				hints.ai_flags = AI_NUMERICHOST;

				error = getaddrinfo($2, "www", &hints, &res0);
				if (error) {
					dolog(LOG_ERR, "%s line %d: %s\n", 
						file->name, file->lineno,
						gai_strerror(error));
	
					return (-1);
				}

				if (res0 == NULL) {
					dolog(LOG_ERR, "%s line %d: could not"
						" determine IPv6 address\n"
						, file->name, file->lineno);
					return (-1);
				}
	
				psin6 = (struct sockaddr_in6 *)&logging.loghost2;
				psin6->sin6_family = res0->ai_family;
				memcpy(psin6, res0->ai_addr, res0->ai_addrlen);
				freeaddrinfo(res0);
			} else {
				memset(&hints, 0, sizeof(hints));

				hints.ai_family = AF_INET;
				hints.ai_socktype = SOCK_STREAM;
				hints.ai_flags = AI_NUMERICHOST;

				error = getaddrinfo($2, "www", &hints, &res0);
				if (error) {
					dolog(LOG_ERR, "%s line %d: %s\n", 
						file->name, file->lineno,
						gai_strerror(error));
	
					return (-1);
				}

				if (res0 == NULL) {
					dolog(LOG_ERR, "%s line %d: could not"
						" determine IPv6 address\n"
						, file->name, file->lineno);
					return (-1);
				}
					
				psin = (struct sockaddr_in *)&logging.loghost2;
				psin->sin_family = res0->ai_family;
				memcpy(psin, res0->ai_addr, res0->ai_addrlen);

				freeaddrinfo(res0);
			}
		} else {
			if (debug)
				printf("2 another logging statement I don't know?\n");
			return (-1);
		}
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
					free ($1);
			}
			| comment CRLF
			;	


/* notify "these hosts" { .. } */

notify:
	NOTIFY notifylabel notifycontent
	{
		if ((confstatus & CONFIG_VERSION) != CONFIG_VERSION) {
                        dolog(LOG_INFO, "There must be a version at the top of the first configfile\n");
                        return (-1);
                }
	}
	;

notifylabel:
	QUOTEDSTRING
	;

notifycontent:
			OBRACE notifystatements EBRACE 
			| OBRACE CRLF notifystatements EBRACE 
			;

notifystatements 	:  		
				notifystatements notifystatement 
				| notifystatement 
				;

notifystatement	:	ipcidr SEMICOLON CRLF
			{
					char prefixlength[INET_ADDRSTRLEN];
					char *dst;
					

					if ((dst = get_prefixlen($1, (char *)&prefixlength, sizeof(prefixlength))) == NULL)  {
						return (-1);
					}

					if (insert_notifyslave(dst, prefixlength) < 0) {
						dolog(LOG_ERR, "insert_notifyslave, line %d\n", file->lineno);
						return (-1);
					}
		
					notify++;
	
					free (dst);
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
	{ "logging", LOGGING, 0 },
	{ "options", OPTIONS, 0 },
	{ "region", REGION, STATE_IP },
	{ "wildcard-only-for", WOF, STATE_IP },
	{ "version", VERSION, 0 },
	{ "zone", ZONE, 0 },
	{ "notify", NOTIFY, STATE_IP },
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
parse_file(ddDB *db, char *filename)
{
	int errors;

	mydb = db;

	memset(&logging, 0, sizeof(struct logging));
	logging.active = 0;


        if ((file = pushfile(filename, 0)) == NULL) {
                return (-1);
        }

        topfile = file;

	if (yyparse() < 0) {
		dolog(LOG_ERR, "error: %s line: %d\n", file->name, file->lineno);
		return (-1);
	}
        errors = file->errors;
        popfile();

#if DEBUG
	dolog(LOG_INFO, "configuration file read\n");
#endif
	
	return 0;
}

int
yylex() 
{
	struct tab *p;
	static char buf[512];
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
			yylval.v.intval = strtonum(buf, 0, 0x7fffffffffffffff, &errstr);
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

/* probably Copyright 2012 Kenneth R Westerback <krw@openbsd.org> */

int
kw_cmp(const void *k, const void *e)
{
        return (strcasecmp(k, ((const struct rrtab *)e)->name));
}


struct rrtab * 
rrlookup(char *keyword)
{
	static struct rrtab *p; 

	p = bsearch(keyword, myrrtab, sizeof(myrrtab)/sizeof(myrrtab[0]), 
		sizeof(myrrtab[0]), kw_cmp);
	
	return (p);
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
	void *sdomain, *tp;
	struct domain *ssd;
	struct domain_cname *ssd_cname;
	char *myname, *converted_name;
	int len, converted_namelen;
	int i, rs;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_CNAME, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	rs = get_record_size(db, converted_name, converted_namelen);
	if (rs < 0) {
		return (-1);
	}

	if ((sdomain = calloc(1, rs)) == NULL) {
		return -1;
	}
	
	ssd = (struct domain *)sdomain;

	if (get_record(ssd, converted_name, converted_namelen) < 0) {
		return (-1);
	}


	strlcpy((char *)ssd->zonename, (char *)name, DNS_MAXNAME + 1);
	memcpy(ssd->zone, converted_name, converted_namelen);
	ssd->zonelen = converted_namelen;

	ssd->ttl[INTERNAL_TYPE_CNAME] = myttl;

	ssd_cname = (struct domain_cname *) find_substruct(ssd, INTERNAL_TYPE_CNAME);
	if (ssd_cname == NULL) {
		rs += sizeof(struct domain_cname);	
#ifdef __OpenBSD__
		tp = reallocarray(sdomain, 1, rs);
#else
		tp = realloc(sdomain, rs);
#endif
		if (tp == NULL)
			return -1;
		sdomain = tp;
		ssd_cname = (sdomain + (rs - sizeof(struct domain_cname)));
		memset((char *)ssd_cname, 0, sizeof(struct domain_cname));
		ssd = (struct domain *)sdomain;
		ssd_cname->len = sizeof(struct domain_cname);
		ssd_cname->type = INTERNAL_TYPE_CNAME;
	} 

	ssd_cname->type = DNS_TYPE_CNAME;
	ssd_cname->len = sizeof(struct domain_cname);

	myname = dns_label(hostname, (int *)&len);	
	if (myname == NULL) {
		dolog(LOG_INFO, "illegal nameserver, skipping line %d\n", file->lineno);
		return 0;
	}

	if (len > 0xff || len < 0) {
		dolog(LOG_INFO, "illegal len value , line %d\n", file->lineno);
		return -1;
	}

	ssd_cname->cnamelen = len;
	memcpy((char *)ssd_cname->cname, myname, len);

	free(myname);

	ssd->flags |= DOMAIN_HAVE_CNAME;

	set_record(ssd, rs, converted_name, converted_namelen);
	
	if (converted_name)
		free (converted_name);

	free (sdomain);
	
	return (0);

}

int
fill_ptr(char *name, char *type, int myttl, char *hostname)
{
	ddDB *db = mydb;
	void *sdomain, *tp;
	struct domain *ssd;
	struct domain_ptr *ssd_ptr;
	int len, converted_namelen;
	char *myname, *converted_name;
	int i, rs;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_PTR, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

       	rs = get_record_size(db, converted_name, converted_namelen);
        if (rs < 0) {
                return (-1);
        }

        if ((sdomain = calloc(1, rs)) == NULL) {
                return -1;
        }

	ssd = (struct domain *)sdomain;

	if (get_record(ssd, converted_name, converted_namelen) < 0) {
		 return (-1);
	}


	strlcpy((char *)ssd->zonename, (char *)name, DNS_MAXNAME + 1);
	memcpy(ssd->zone, converted_name, converted_namelen);
	ssd->zonelen = converted_namelen;

	ssd->ttl[INTERNAL_TYPE_PTR] = myttl;

	ssd_ptr = (struct domain_ptr *) find_substruct(ssd, INTERNAL_TYPE_PTR);
        if (ssd_ptr == NULL) {
                rs += sizeof(struct domain_ptr);
#ifdef __OpenBSD__
                tp = reallocarray(sdomain, 1, rs);
#else
		tp = realloc(sdomain, rs);
#endif
                if (tp == NULL)
                        return -1;
                sdomain = tp;
                ssd_ptr = (sdomain + (rs - sizeof(struct domain_ptr)));
                memset((char *)ssd_ptr, 0, sizeof(struct domain_ptr));
		ssd = (struct domain *)sdomain;
		ssd_ptr->len = sizeof(struct domain_ptr);
		ssd_ptr->type = INTERNAL_TYPE_PTR;
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

	ssd_ptr->ptrlen = len;
	memcpy((char *)ssd_ptr->ptr, myname, len);

	free(myname);

	ssd->flags |= DOMAIN_HAVE_PTR;

	set_record(ssd, rs,  converted_name, converted_namelen);
	
	if (converted_name)
		free (converted_name);

	free (sdomain);
	
	return (0);

}

/* first two dnssec RRs! */
int		
fill_dnskey(char *name, char *type, u_int32_t myttl, u_int16_t flags, u_int8_t protocol, u_int8_t algorithm, char *pubkey)
{
	ddDB *db = mydb;
	void *sdomain, *tp;
	struct domain *ssd;
	struct domain_dnskey *ssd_dnskey;
	int converted_namelen;
	char *converted_name;
	int i, ret, rs;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_DNSKEY, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

        rs = get_record_size(db, converted_name, converted_namelen);
        if (rs < 0) {
                return (-1);
        }

        if ((sdomain = calloc(1, rs)) == NULL) {
                return (-1);
        }

	ssd = (struct domain *)sdomain;

	if (get_record(ssd, converted_name, converted_namelen) < 0) {
		return (-1);
	}


	strlcpy((char *)ssd->zonename, (char *)name, DNS_MAXNAME + 1);
	memcpy(ssd->zone, converted_name, converted_namelen);
	ssd->zonelen = converted_namelen;

	ssd->ttl[INTERNAL_TYPE_DNSKEY] = myttl;

        ssd_dnskey = (struct domain_dnskey *) find_substruct(ssd, INTERNAL_TYPE_DNSKEY);
        if (ssd_dnskey == NULL) {
                rs += sizeof(struct domain_dnskey);
#ifdef __OpenBSD__
                tp = reallocarray(sdomain, 1, rs);
#else
		tp = realloc(sdomain, rs);
#endif
                if (tp == NULL)
                        return -1;
                sdomain = tp;
                ssd_dnskey = (sdomain + (rs - sizeof(struct domain_dnskey)));
                memset((char *)ssd_dnskey, 0, sizeof(struct domain_dnskey));
		ssd = (struct domain *)sdomain;
		ssd_dnskey->len = sizeof(struct domain_dnskey);
		ssd_dnskey->type = INTERNAL_TYPE_DNSKEY;
        }

	ssd_dnskey->dnskey[ssd_dnskey->dnskey_count].flags = flags;
	ssd_dnskey->dnskey[ssd_dnskey->dnskey_count].protocol = protocol;
	ssd_dnskey->dnskey[ssd_dnskey->dnskey_count].algorithm = algorithm;

	/* feed our base64 key to the public key */
	ret = mybase64_decode(pubkey, ssd_dnskey->dnskey[ssd_dnskey->dnskey_count].public_key, sizeof(ssd_dnskey->dnskey[ssd_dnskey->dnskey_count].public_key));

	if (ret < 0) 
		return (-1);

	ssd_dnskey->dnskey[ssd_dnskey->dnskey_count].publickey_len = ret;
	
	ssd_dnskey->dnskey_count++;

	ssd->flags |= DOMAIN_HAVE_DNSKEY;

	set_record(ssd, rs, converted_name, converted_namelen);
	
	if (converted_name)
		free (converted_name);

	free (sdomain);
	
	return (0);

}

int
fill_rrsig(char *name, char *type, u_int32_t myttl, char *typecovered, u_int8_t algorithm, u_int8_t labels, u_int32_t original_ttl, u_int64_t sig_expiration, u_int64_t sig_inception, u_int16_t keytag, char *signers_name, char *signature)
{
	ddDB *db = mydb;
	void *sdomain, *tp;
	struct domain *ssd;
	struct domain_rrsig *ssd_rrsig;
	struct rrsig *rrsig;
	int converted_namelen, signers_namelen;
	char *converted_name, *signers_name2;
	struct rrtab *rr;
	int i, ret, rs;
	char tmpbuf[32];
	struct tm tmbuf;
	time_t timebuf;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_RRSIG, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

        rs = get_record_size(db, converted_name, converted_namelen);
        if (rs < 0) {
                return (-1);
        }

        if ((sdomain = calloc(1, rs)) == NULL) {
                return -1;
        }

	ssd = (struct domain *)sdomain;

	if (get_record(ssd, converted_name, converted_namelen) < 0) {
		return (-1);
	}

	strlcpy((char *)ssd->zonename, (char *)name, DNS_MAXNAME + 1);
	memcpy(ssd->zone, converted_name, converted_namelen);
	ssd->zonelen = converted_namelen;

	ssd->ttl[INTERNAL_TYPE_RRSIG] = myttl;

	if ((rr = rrlookup(typecovered)) == NULL) {
		return (-1);
	}

	switch (rr->type) {
	case DNS_TYPE_RRSIG:
		fprintf(stderr, "can't RRSIG an RRSIG!\n");
		return (-1);
		break;
	}

        ssd_rrsig = (struct domain_rrsig *) find_substruct(ssd, INTERNAL_TYPE_RRSIG);
        if (ssd_rrsig == NULL) {
                rs += sizeof(struct domain_rrsig);
#ifdef __OpenBSD__
                tp = reallocarray(sdomain, 1, rs);
#else
		tp = realloc(sdomain, rs);
#endif
                if (tp == NULL)
                        return -1;
                sdomain = tp;
                ssd_rrsig = (sdomain + (rs - sizeof(struct domain_rrsig)));
                memset((char *)ssd_rrsig, 0, sizeof(struct domain_rrsig));
		ssd = (struct domain *)sdomain;
		ssd_rrsig->len = sizeof(struct domain_rrsig);
		ssd_rrsig->type = INTERNAL_TYPE_RRSIG;
        }

	if (rr->internal_type == INTERNAL_TYPE_DNSKEY) {
#if DEBUG
		printf("filling hackaround type dnskey\n");
#endif
		rrsig = &ssd_rrsig->rrsig_dnskey[ssd_rrsig->rrsig_dnskey_count++];
	} else {
#if DEBUG
		printf("filling internal type %d\n", rr->internal_type);
#endif
		rrsig = &ssd_rrsig->rrsig[rr->internal_type];
	}


	rrsig->type_covered = rr->type;
	rrsig->algorithm = algorithm;
	rrsig->labels = labels;

#if 0
	if (ssd->ttl[rr->internal_type] != original_ttl) {
		return (-1);
	}
#endif

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

	memcpy(rrsig->signers_name, signers_name2, signers_namelen);
	rrsig->signame_len = signers_namelen;

	
	/* feed our base64 key the signature */
	ret = mybase64_decode(signature, rrsig->signature, sizeof(rrsig->signature));

	if (ret < 0) 
		return (-1);

	rrsig->signature_len = ret;
	
	ssd->flags |= DOMAIN_HAVE_RRSIG;

	/* pjp */
	set_record(ssd, rs, converted_name, converted_namelen);
	
	if (signers_name2)
		free (signers_name2);

	if (converted_name)
		free (converted_name);

	free (sdomain);

	return (0);

}

int
fill_ds(char *name, char *type, u_int32_t myttl, u_int16_t keytag, u_int8_t algorithm, u_int8_t digesttype, char *digest)
{
	ddDB *db = mydb;
	void *sdomain, *tp;
	struct domain *ssd;
	struct domain_ds *ssd_ds;
	int converted_namelen;
	char *converted_name;
	int i, rs;
	int ret;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_DS, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

        rs = get_record_size(db, converted_name, converted_namelen);
        if (rs < 0) {
                return (-1);
        }

        if ((sdomain = calloc(1, rs)) == NULL) {
                return -1;
        }

	ssd = (struct domain *)sdomain;

	if (get_record(ssd, converted_name, converted_namelen) < 0) {
		return (-1);
	}


	strlcpy((char *)ssd->zonename, (char *)name, DNS_MAXNAME + 1);
	memcpy(ssd->zone, converted_name, converted_namelen);
	ssd->zonelen = converted_namelen;

	ssd->ttl[INTERNAL_TYPE_DS] = myttl;

        ssd_ds = (struct domain_ds *) find_substruct(ssd, INTERNAL_TYPE_DS);
        if (ssd_ds == NULL) {
                rs += sizeof(struct domain_ds);
#ifdef __OpenBSD__
                tp = reallocarray(sdomain, 1, rs);
#else
		tp = realloc(sdomain, rs);
#endif
                if (tp == NULL)
                        return -1;
                sdomain = tp;
                ssd_ds = (sdomain + (rs - sizeof(struct domain_ds)));
                memset((char *)ssd_ds, 0, sizeof(struct domain_ds));
		ssd = (struct domain *)sdomain;
		ssd_ds->len = sizeof(struct domain_ds);
		ssd_ds->type = INTERNAL_TYPE_DS;
        }

	ssd_ds->ds[ssd_ds->ds_count].key_tag = keytag;
	ssd_ds->ds[ssd_ds->ds_count].algorithm = algorithm;
	ssd_ds->ds[ssd_ds->ds_count].digest_type = digesttype; 
	
#if 0
	memcpy(ssd_ds->ds[ssd_ds->ds_count].digest, digest, strlen(digest));
	ssd_ds->ds[ssd_ds->ds_count].digestlen = strlen(digest);	
#endif

	ret = hex2bin(digest, strlen(digest), ssd_ds->ds[ssd_ds->ds_count].digest);

	ssd_ds->ds[ssd_ds->ds_count].digestlen = ret;

	ssd_ds->ds_count++;
		
	ssd->flags |= DOMAIN_HAVE_DS;

	set_record(sdomain, rs, converted_name, converted_namelen);

	if (converted_name)
		free (converted_name);

	free(sdomain);
	
	return (0);

}

int
fill_nsec3(char *name, char *type, u_int32_t myttl, u_int8_t algorithm, u_int8_t flags, u_int16_t iterations, char *salt, char *nextname, char *bitmap)
{
	ddDB *db = mydb;
	void *sdomain, *tp;
	struct domain *ssd;
	struct domain_nsec3 *ssd_nsec3;
	int i, rs;

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

        rs = get_record_size(db, converted_name, converted_namelen);
        if (rs < 0) {
		if (debug)
			dolog(LOG_INFO, "get_record_size failed\n");
                return (-1);
        }

        if ((sdomain = calloc(1, rs)) == NULL) {
		if (debug)
			dolog(LOG_INFO, "calloc failed\n");
                return -1;
        }

	ssd = (struct domain *)sdomain;

	if (get_record(ssd, converted_name, converted_namelen) < 0) {
		return (-1);
	}


	strlcpy((char *)ssd->zonename, (char *)name, DNS_MAXNAME + 1);
	memcpy(ssd->zone, converted_name, converted_namelen);
	ssd->zonelen = converted_namelen;

	ssd->ttl[INTERNAL_TYPE_NSEC3] = myttl;


	for (i = 0; i < strlen(nextname); i++) {
		nextname[i] = tolower((int)nextname[i]);
	}

	ssd_nsec3 = (struct domain_nsec3 *)find_substruct(ssd, INTERNAL_TYPE_NSEC3);
	if (ssd_nsec3 == NULL) {
		rs += sizeof(struct domain_nsec3);
#ifdef __OpenBSD__
		tp = reallocarray(sdomain, 1, rs);
#else
		tp = realloc(sdomain, rs);
#endif
		if (tp == NULL) {
			dolog(LOG_INFO, "reallocarray failed\n");
			free (sdomain);
			return -1;
		}
		sdomain = tp;
		ssd_nsec3 = (sdomain + (rs - sizeof(struct domain_nsec3)));
		memset((char *)ssd_nsec3, 0, sizeof(struct domain_nsec3));
		ssd = (struct domain *)sdomain;
		ssd_nsec3->len = sizeof(struct domain_nsec3);
		ssd_nsec3->type = INTERNAL_TYPE_NSEC3;
	}

	ssd_nsec3->nsec3.algorithm = algorithm;
	ssd_nsec3->nsec3.flags = flags;
	ssd_nsec3->nsec3.iterations = iterations;
	if (strcasecmp(salt, "-") == 0) {
		ssd_nsec3->nsec3.saltlen = 0;
	} else {
		ssd_nsec3->nsec3.saltlen = (strlen(salt) / 2);
		hex2bin(salt, strlen(salt), ssd_nsec3->nsec3.salt);
	}

	ssd_nsec3->nsec3.nextlen = base32hex_decode(nextname, (u_char*)&ssd_nsec3->nsec3.next);
	if (ssd_nsec3->nsec3.nextlen == 0) {
		dolog(LOG_INFO, "base32_decode faulty");
		return -1;
	}

	/* XXX create/manage bitmap */
	create_nsec_bitmap(bitmap, ssd_nsec3->nsec3.bitmap, (int *)&ssd_nsec3->nsec3.bitmap_len);
	
	ssd->flags |= DOMAIN_HAVE_NSEC3;

	set_record(ssd, rs, converted_name, converted_namelen);

	if (converted_name)
		free (converted_name);
	
	free (sdomain);

	return (0);
}

int
fill_nsec3param(char *name, char *type, u_int32_t myttl, u_int8_t algorithm, u_int8_t flags, u_int16_t iterations, char *salt)
{
	ddDB *db = mydb;
	void *sdomain, *tp;
	struct domain *ssd;
	struct domain_nsec3param *ssd_nsec3param;
	int i, rs;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_NSEC3PARAM, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

        rs = get_record_size(db, converted_name, converted_namelen);
        if (rs < 0) {
		if (debug)
			dolog(LOG_INFO, "get_record_size failed\n");
                return (-1);
        }

        if ((sdomain = calloc(1, rs)) == NULL) {
		if (debug)
			dolog(LOG_INFO, "calloc failed\n");
                return -1;
        }

	ssd = (struct domain *)sdomain;

	if (get_record(ssd, converted_name, converted_namelen) < 0) {
		return (-1);
	}


	strlcpy((char *)ssd->zonename, (char *)name, DNS_MAXNAME + 1);
	memcpy(ssd->zone, converted_name, converted_namelen);
	ssd->zonelen = converted_namelen;

	ssd->ttl[INTERNAL_TYPE_NSEC3PARAM] = myttl;

	ssd_nsec3param = (struct domain_nsec3param *)find_substruct(ssd, INTERNAL_TYPE_NSEC3PARAM);
	if (ssd_nsec3param == NULL) {
		rs += sizeof(struct domain_nsec3param);
#ifdef __OpenBSD__
		tp = reallocarray(sdomain, 1, rs);
#else
		tp = realloc(sdomain, rs);
#endif
		if (tp == NULL) {
			dolog(LOG_INFO, "reallocarray failed\n");
			free (sdomain);
			return -1;
		}
		sdomain = tp;
		ssd_nsec3param = (sdomain + (rs - sizeof(struct domain_nsec3param)));
		memset((char *)ssd_nsec3param, 0, sizeof(struct domain_nsec3param));
		ssd = (struct domain *)sdomain;
		ssd_nsec3param->len = sizeof(struct domain_nsec3param);
		ssd_nsec3param->type = INTERNAL_TYPE_NSEC3PARAM;
	}

	ssd_nsec3param->nsec3param.algorithm = algorithm;
	ssd_nsec3param->nsec3param.flags = flags;
	ssd_nsec3param->nsec3param.iterations = iterations;
	if (strcasecmp(salt, "-") == 0) {
		ssd_nsec3param->nsec3param.saltlen = 0;
	} else {
		ssd_nsec3param->nsec3param.saltlen = (strlen(salt) / 2);
		hex2bin(salt, strlen(salt), ssd_nsec3param->nsec3param.salt);
	}

	ssd->flags |= DOMAIN_HAVE_NSEC3PARAM;

	set_record(ssd, rs, converted_name, converted_namelen);

	if (converted_name)
		free (converted_name);
	
	free (sdomain);

	return (0);
}

int
fill_nsec(char *name, char *type, u_int32_t myttl, char *domainname, char *bitmap)
{
	ddDB *db = mydb;
	void *sdomain, *tp;
	struct domain *ssd;
	struct domain_nsec *ssd_nsec;
	int converted_namelen, converted_domainnamelen;
	char *converted_name, *converted_domainname;
	int i, rs;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_NSEC, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

        rs = get_record_size(db, converted_name, converted_namelen);
        if (rs < 0) {
		if (debug)
			dolog(LOG_INFO, "get_record_size failed\n");
                return (-1);
        }

        if ((sdomain = calloc(1, rs)) == NULL) {
		if (debug)
			dolog(LOG_INFO, "calloc failed\n");
                return -1;
        }

	ssd = (struct domain *)sdomain;

	if (get_record(ssd, converted_name, converted_namelen) < 0) {
		return (-1);
	}


	strlcpy((char *)ssd->zonename, (char *)name, DNS_MAXNAME + 1);
	memcpy(ssd->zone, converted_name, converted_namelen);
	ssd->zonelen = converted_namelen;

	ssd->ttl[INTERNAL_TYPE_NSEC] = myttl;


	for (i = 0; i < strlen(domainname); i++) {
		domainname[i] = tolower((int)domainname[i]);
	}

	converted_domainname = check_rr(domainname, type, DNS_TYPE_NSEC, &converted_domainnamelen);
	if (converted_name == NULL) {
		if (debug)
			dolog(LOG_INFO, "check_rr failed\n");
		return -1;
	}

	ssd_nsec = (struct domain_nsec *)find_substruct(ssd, INTERNAL_TYPE_NSEC);
	if (ssd_nsec == NULL) {
		rs += sizeof(struct domain_nsec);
#ifdef __OpenBSD__
		tp = reallocarray(sdomain, 1, rs);
#else
		tp = realloc(sdomain, rs);
#endif
		if (tp == NULL) {
			dolog(LOG_INFO, "reallocarray failed\n");
			free (sdomain);
			return -1;
		}
		sdomain = tp;
		ssd_nsec = (sdomain + (rs - sizeof(struct domain_nsec)));
		memset((char *)ssd_nsec, 0, sizeof(struct domain_nsec));
		ssd = (struct domain *)sdomain;
		ssd_nsec->len = sizeof(struct domain_nsec);
		ssd_nsec->type = INTERNAL_TYPE_NSEC;
	}


	memcpy(ssd_nsec->nsec.next_domain_name, converted_domainname, converted_domainnamelen);
	ssd_nsec->nsec.ndn_len = converted_domainnamelen;

	/* XXX create/manage bitmap */
	create_nsec_bitmap(bitmap, ssd_nsec->nsec.bitmap, (int *)&ssd_nsec->nsec.bitmap_len);
	
	ssd->flags |= DOMAIN_HAVE_NSEC;

	set_record(ssd, rs, converted_name, converted_namelen);

	if (converted_name)
		free (converted_name);
	
	free (sdomain);

	return (0);

}


int
fill_naptr(char *name, char *type, int myttl, int order, int preference, char *flags, char *services, char *regexp, char *replacement)
{
	ddDB *db = mydb;
	void *sdomain, *tp;
	struct domain *ssd;
	struct domain_naptr *ssd_naptr;
	int converted_namelen;
	char *converted_name, *naptrname;
	int flagslen, serviceslen, regexplen, replacementlen;
	int i, naptr_namelen;
	int rs;

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

	rs = get_record_size(db, converted_name, converted_namelen);
	if (rs < 0) {
		return (-1);
	}

	if ((sdomain = calloc(1, rs)) == NULL) {
		return -1;
	}

	ssd = (struct domain *)sdomain;

	if (get_record(ssd, converted_name, converted_namelen) < 0) {
		return (-1);
	}


	strlcpy((char *)ssd->zonename, (char *)name, DNS_MAXNAME + 1);
	memcpy(ssd->zone, converted_name, converted_namelen);
	ssd->zonelen = converted_namelen;

	ssd->ttl[INTERNAL_TYPE_NAPTR] = myttl;

	ssd_naptr = (struct domain_naptr *)find_substruct(ssd, INTERNAL_TYPE_NAPTR);
	if (ssd_naptr == NULL) {
		rs += sizeof(struct domain_naptr);
#ifdef __OpenBSD__
		tp = reallocarray(sdomain, 1, rs);
#else
		tp = realloc(sdomain, rs);
#endif
		if (tp == NULL) 
			return -1;
	
		sdomain = tp;
		ssd_naptr = (sdomain + (rs - sizeof(struct domain_naptr)));
		memset((char *)ssd_naptr, 0, sizeof(struct domain_naptr));
		ssd = (struct domain *)sdomain;
		ssd_naptr->len = sizeof(struct domain_naptr);
		ssd_naptr->type = INTERNAL_TYPE_NAPTR;
	}

	ssd_naptr->naptr[ssd_naptr->naptr_count].order = order;
	ssd_naptr->naptr[ssd_naptr->naptr_count].preference = preference;

	memcpy(ssd_naptr->naptr[ssd_naptr->naptr_count].flags, flags, flagslen);
	ssd_naptr->naptr[ssd_naptr->naptr_count].flagslen = flagslen;

	memcpy(ssd_naptr->naptr[ssd_naptr->naptr_count].services, services, serviceslen);
	ssd_naptr->naptr[ssd_naptr->naptr_count].serviceslen = serviceslen;

	memcpy(ssd_naptr->naptr[ssd_naptr->naptr_count].regexp, regexp, regexplen);
	ssd_naptr->naptr[ssd_naptr->naptr_count].regexplen = regexplen;

	naptrname = check_rr(replacement, type, DNS_TYPE_NAPTR, &naptr_namelen);
	if (naptrname == NULL) {
		return -1;
	}

	memcpy(ssd_naptr->naptr[ssd_naptr->naptr_count].replacement, naptrname, naptr_namelen);
	ssd_naptr->naptr[ssd_naptr->naptr_count].replacementlen = naptr_namelen;
	
	ssd_naptr->naptr_count++;

	ssd->flags |= DOMAIN_HAVE_NAPTR;

	set_record(ssd, rs, converted_name, converted_namelen);
	
	if (naptrname)
		free (naptrname);

	if (converted_name)
		free (converted_name);

	free (sdomain);
	
	return (0);

}

int
fill_txt(char *name, char *type, int myttl, char *msg)
{
	ddDB *db = mydb;
	void *sdomain, *tp;
	struct domain *ssd;
	struct domain_txt *ssd_txt;
	int converted_namelen;
	char *converted_name;
	int len, i;
	int rs;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	if ((len = strlen(msg)) > 255) {
		dolog(LOG_ERR, "TXT record too long line %d\n", file->lineno);
		return (-1);
	}

	converted_name = check_rr(name, type, DNS_TYPE_TXT, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	rs = get_record_size(db, converted_name, converted_namelen);
	if (rs < 0) {
			return -1;
	}

	if ((sdomain = calloc(1, rs)) == NULL) {
		return -1;
	}

	ssd = (struct domain *)sdomain;

	if (get_record(ssd, converted_name, converted_namelen) < 0) {
		return -1;
	}


	strlcpy((char *)ssd->zonename, (char *)name, DNS_MAXNAME + 1);
	memcpy(ssd->zone, converted_name, converted_namelen);
	ssd->zonelen = converted_namelen;

	ssd->ttl[INTERNAL_TYPE_TXT] = myttl;

	ssd_txt = (struct domain_txt *) find_substruct(ssd, INTERNAL_TYPE_TXT);
	if (ssd_txt == NULL) {
		rs += sizeof(struct domain_txt);
#ifdef __OpenBSD__
		tp = reallocarray(sdomain, 1, rs);
#else
		tp = realloc(sdomain, rs);
#endif
		if (tp == NULL) {
			free(sdomain);
			return -1;
		}
	
		sdomain = tp;
		ssd_txt = (sdomain + (rs - sizeof(struct domain_txt)));
		memset((char *)ssd_txt, 0, sizeof(struct domain_txt));
		ssd = (struct domain *)sdomain;
		ssd_txt->len = sizeof(struct domain_txt);
		ssd_txt->type = INTERNAL_TYPE_TXT;
	}

	memcpy(ssd_txt->txt, msg, len);
	ssd_txt->txtlen = len;

	ssd->flags |= DOMAIN_HAVE_TXT;

	set_record(ssd, rs, converted_name, converted_namelen);
	
	if (converted_name)
		free (converted_name);
	
	free (sdomain);


	return (0);

}

int
fill_tlsa(char *name, char *type, int myttl, uint8_t usage, uint8_t selector, uint8_t matchtype, char *data)
{
	ddDB *db = mydb;
	void *sdomain, *tp;
	struct domain *ssd;
	struct domain_tlsa *ssd_tlsa;
	int converted_namelen;
	char *converted_name;
	char *p, *ep, save;
	int len, i;
	int rs;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_TLSA, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	rs = get_record_size(db, converted_name, converted_namelen);
	if (rs < 0) {
		return -1;
	}

	if ((sdomain = calloc(1, rs)) == NULL) {
		return -1;
	}

	ssd = (struct domain *)sdomain;

	if (get_record(ssd, converted_name, converted_namelen) < 0) {
		return (-1);
	}


	strlcpy((char *)ssd->zonename, (char *)name, DNS_MAXNAME + 1);
	memcpy(ssd->zone, converted_name, converted_namelen);
	ssd->zonelen = converted_namelen;

	ssd_tlsa = (struct domain_tlsa *)find_substruct(ssd, INTERNAL_TYPE_TLSA);
	if (ssd_tlsa == NULL) {
		rs += sizeof(struct domain_tlsa);
#ifdef __OpenBSD__
		tp = reallocarray(sdomain, 1, rs);
#else
		tp = realloc(sdomain, rs);
#endif
		if (tp == NULL) {
			free (sdomain);
			return -1;
		}

		sdomain = tp;
		ssd_tlsa = (sdomain + (rs - sizeof(struct domain_tlsa)));
		memset((char *)ssd_tlsa, 0, sizeof(struct domain_tlsa));
		ssd = (struct domain *)sdomain;
		ssd_tlsa->len = sizeof(struct domain_tlsa);
		ssd_tlsa->type = INTERNAL_TYPE_TLSA;
		
	}

	if (ssd_tlsa->tlsa_count >= RECORD_COUNT) {
		dolog(LOG_INFO, "%s: too many TLSA records for zone \"%s\", skipping line %d\n", file->name, name, file->lineno);
		return (-1);
	}

	ssd->ttl[INTERNAL_TYPE_TLSA] = myttl;

	ssd_tlsa->tlsa[ssd_tlsa->tlsa_count].usage = usage;
	ssd_tlsa->tlsa[ssd_tlsa->tlsa_count].selector = selector;
	ssd_tlsa->tlsa[ssd_tlsa->tlsa_count].matchtype = matchtype;

	switch (matchtype) {
	case 1:
		len = ssd_tlsa->tlsa[ssd_tlsa->tlsa_count].datalen = DNS_TLSA_SIZE_SHA256;
		break;
	case 2:
		len = ssd_tlsa->tlsa[ssd_tlsa->tlsa_count].datalen = DNS_TLSA_SIZE_SHA512;
		break;
	default:
		dolog(LOG_ERR, "tlsa: unknown match type!\n");
		return -1;
	}

	p = data;
	for (i = 0; i < len; i++) {
		save = p[2];
		p[2] = '\0';
		ssd_tlsa->tlsa[ssd_tlsa->tlsa_count].data[i] = strtol(p, &ep, 16);
		p[2] = save;
		p += 2;
	}


	ssd_tlsa->tlsa_count++;

	ssd->flags |= DOMAIN_HAVE_TLSA;

	set_record(ssd, rs, converted_name, converted_namelen);
	
	if (converted_name)
		free (converted_name);

	free (sdomain);
	
	return (0);

}

int
fill_sshfp(char *name, char *type, int myttl, int alg, int fptype, char *fingerprint)
{
	ddDB *db = mydb;
	void *sdomain, *tp;
	struct domain *ssd;
	struct domain_sshfp *ssd_sshfp;
	int converted_namelen;
	char *converted_name;
	char *p, *ep, save;
	int len, i;
	int rs;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_SSHFP, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	rs = get_record_size(db, converted_name, converted_namelen);
	if (rs < 0) {
		return -1;
	}

	if ((sdomain = calloc(1, rs)) == NULL) {
		return -1;
	}

	ssd = (struct domain *)sdomain;

	if (get_record(ssd, converted_name, converted_namelen) < 0) {
		return (-1);
	}


	strlcpy((char *)ssd->zonename, (char *)name, DNS_MAXNAME + 1);
	memcpy(ssd->zone, converted_name, converted_namelen);
	ssd->zonelen = converted_namelen;

	ssd_sshfp = (struct domain_sshfp *)find_substruct(ssd, INTERNAL_TYPE_SSHFP);
	if (ssd_sshfp == NULL) {
		rs += sizeof(struct domain_sshfp);
#ifdef __OpenBSD__
		tp = reallocarray(sdomain, 1, rs);
#else
		tp = realloc(sdomain, rs);
#endif
		if (tp == NULL) {
			free (sdomain);
			return -1;
		}

		sdomain = tp;
		ssd_sshfp = (sdomain + (rs - sizeof(struct domain_sshfp)));
		memset((char *)ssd_sshfp, 0, sizeof(struct domain_sshfp));
		ssd = (struct domain *)sdomain;
		ssd_sshfp->len = sizeof(struct domain_sshfp);
		ssd_sshfp->type = INTERNAL_TYPE_SSHFP;
		
	}

	if (ssd_sshfp->sshfp_count >= RECORD_COUNT) {
		dolog(LOG_INFO, "%s: too many SSHFP records for zone \"%s\", skipping line %d\n", file->name, name, file->lineno);
		return (-1);
	}

	ssd->ttl[INTERNAL_TYPE_SSHFP] = myttl;

	ssd_sshfp->sshfp[ssd_sshfp->sshfp_count].algorithm = alg;
	ssd_sshfp->sshfp[ssd_sshfp->sshfp_count].fptype = fptype;

	switch (fptype) {
	case 1:
		len = ssd_sshfp->sshfp[ssd_sshfp->sshfp_count].fplen = DNS_SSHFP_SIZE_SHA1;
		break;
	case 2:
		len = ssd_sshfp->sshfp[ssd_sshfp->sshfp_count].fplen = DNS_SSHFP_SIZE_SHA256;
		break;
	default:
		dolog(LOG_ERR, "sshfp: unknown fingerprint type!\n");
		return -1;
	}

	p = fingerprint;
	for (i = 0; i < len; i++) {
		save = p[2];
		p[2] = '\0';
		ssd_sshfp->sshfp[ssd_sshfp->sshfp_count].fingerprint[i] = strtol(p, &ep, 16);
		p[2] = save;
		p += 2;
	}


	ssd_sshfp->sshfp_count++;

	ssd->flags |= DOMAIN_HAVE_SSHFP;

	set_record(ssd, rs, converted_name, converted_namelen);
	
	if (converted_name)
		free (converted_name);

	free (sdomain);
	
	return (0);

}

int
fill_srv(char *name, char *type, int myttl, int priority, int weight, int port, char *srvhost)
{
	ddDB *db = mydb;
	void *sdomain, *tp;
	struct domain *ssd;
	struct domain_srv *ssd_srv;
	int converted_namelen;
	char *converted_name;
	char *srvname;
	int len, i;
	int rs;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_SRV, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	rs = get_record_size(db, converted_name, converted_namelen);
	if (rs < 0) {
		return (-1);
	}

	if ((sdomain = calloc(1, rs)) == NULL) {
		return -1;
	}

	ssd = (struct domain *)sdomain;

	if (get_record(ssd, converted_name, converted_namelen) < 0) {
		return (-1);
	}


	strlcpy((char *)ssd->zonename, (char *)name, DNS_MAXNAME + 1);
	memcpy(ssd->zone, converted_name, converted_namelen);
	ssd->zonelen = converted_namelen;

	ssd_srv = (struct domain_srv *)find_substruct(ssd, INTERNAL_TYPE_SRV);
	if (ssd_srv == NULL) {
		rs += sizeof(struct domain_srv);
#ifdef __OpenBSD__
		tp = reallocarray(sdomain, 1, rs);
#else
		tp = realloc(sdomain, rs);
#endif
		if (tp == NULL) {
			free (sdomain);
			return -1;
		}

		sdomain = tp;
		ssd_srv = (sdomain + (rs - sizeof(struct domain_srv)));
		memset((char *)ssd_srv, 0, sizeof(struct domain_srv));
		ssd = (struct domain *)sdomain;
		ssd_srv->len = sizeof(struct domain_srv);
		ssd_srv->type = INTERNAL_TYPE_SRV;
	}

	if (ssd_srv->srv_count >= RECORD_COUNT) {
		dolog(LOG_INFO, "%s: too many SRV records for zone \"%s\", skipping line %d\n", file->name, name, file->lineno);
		return (-1);
	}

	ssd->ttl[INTERNAL_TYPE_SRV] = myttl;

	ssd_srv->srv[ssd_srv->srv_count].priority = priority;
	ssd_srv->srv[ssd_srv->srv_count].weight = weight;
	ssd_srv->srv[ssd_srv->srv_count].port = port;

	srvname = dns_label(srvhost, &len);
	if (srvname == NULL) {
		dolog(LOG_INFO, "illegal srv server, skipping line %d\n", file->lineno);
		return (-1);
	}

	ssd_srv->srv[ssd_srv->srv_count].targetlen = len;
	memcpy((char *)ssd_srv->srv[ssd_srv->srv_count].target, srvname, len);

	/* bad hack workaround !!! */
	if (strcmp(srvhost, ".") == 0 && len > 1) 
		ssd_srv->srv[ssd_srv->srv_count].targetlen = 1;

	free (srvname);

	ssd_srv->srv_count++;

	ssd->flags |= DOMAIN_HAVE_SRV;

	set_record(ssd, rs, converted_name, converted_namelen);
	
	if (converted_name)
		free (converted_name);
	
	free (sdomain);
	
	return (0);

}

int
fill_mx(char *name, char *type, int myttl, int priority, char *mxhost)
{
	ddDB *db = mydb;
	void *sdomain, *tp;
	struct domain *ssd;
	struct domain_mx *ssd_mx;
	int converted_namelen;
	char *converted_name;
	char *mxname;
	int len, i;
	int rs;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_MX, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	rs = get_record_size(db, converted_name, converted_namelen);
	if (rs < 0) {
		return -1;
	}
	
	if ((sdomain = calloc(1, rs)) == NULL) {
		return -1;
	}

	ssd = (struct domain *)sdomain;

	if (get_record(ssd, converted_name, converted_namelen) < 0) {
		return (-1);
	}


	strlcpy((char *)ssd->zonename, (char *)name, DNS_MAXNAME + 1);
	memcpy(ssd->zone, converted_name, converted_namelen);
	ssd->zonelen = converted_namelen;

	ssd_mx = (struct domain_mx *)find_substruct(ssd, INTERNAL_TYPE_MX);

	if (ssd_mx == NULL) {

		rs += sizeof(struct domain_mx);
#ifdef __OpenBSD__
		tp = reallocarray(sdomain, 1, rs);
#else
		tp = realloc(sdomain, rs);
#endif
		if (tp == NULL) {
			free (sdomain);
			return -1;
		}

		sdomain = tp;
		ssd_mx = (sdomain + (rs - sizeof(struct domain_mx)));
		memset((char *)ssd_mx, 0, sizeof(struct domain_mx));
		ssd = (struct domain *)sdomain;
		ssd_mx->len = sizeof(struct domain_mx);
		ssd_mx->type = INTERNAL_TYPE_MX;

	}

	if (ssd_mx->mx_count >= RECORD_COUNT) {
		dolog(LOG_INFO, "%s: too many MX records for zone \"%s\", skipping line %d\n", file->name, name, file->lineno);
		return (-1);
	}

	ssd->ttl[INTERNAL_TYPE_MX] = myttl;
	ssd_mx->mx[ssd_mx->mx_count].preference = priority;

	mxname = dns_label(mxhost, &len);
	if (mxname == NULL) {
		dolog(LOG_INFO, "illegal mx server, skipping line %d\n", file->lineno);
		return (-1);
	}

	ssd_mx->mx[ssd_mx->mx_count].exchangelen = len;
	memcpy((char *)ssd_mx->mx[ssd_mx->mx_count].exchange, mxname, len);
	free (mxname);

	ssd_mx->mx_count++;

	ssd->flags |= DOMAIN_HAVE_MX;

	set_record(sdomain, rs, converted_name, converted_namelen);
	
	if (converted_name)
		free (converted_name);
	
	free (sdomain);

	return (0);

}

int
fill_a(char *name, char *type, int myttl, char *a)
{
	ddDB *db = mydb;
	void *sdomain, *tp;
	struct domain *ssd;
	struct domain_a *ssd_a;
	int converted_namelen;
	char *converted_name;
	in_addr_t *ia;
	int i, rs;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_A, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}
	
	rs = get_record_size(db, converted_name, converted_namelen);
	if (rs < 0) {
		return -1;
	}

	if ((sdomain = calloc(1, rs)) == NULL) {
		return -1;
	}

	ssd = (struct domain *)sdomain;

	if (get_record(ssd, converted_name, converted_namelen) < 0) {
		return (-1);
	}

	strlcpy((char *)ssd->zonename, (char *)name, DNS_MAXNAME + 1);
	memcpy(ssd->zone, converted_name, converted_namelen);
	ssd->zonelen = converted_namelen;

	ssd_a = (struct domain_a *)find_substruct(ssd, INTERNAL_TYPE_A);
	if (ssd_a == NULL) {
		rs += sizeof(struct domain_a);
#ifdef __OpenBSD__
		tp = reallocarray(sdomain, 1, rs);
#else
		tp = realloc(sdomain, rs);
#endif
		if (tp == NULL) {
			free (sdomain);
			return -1;
		}
		sdomain = tp;

		ssd_a = (sdomain + (rs - sizeof(struct domain_a)));
		memset((char *)ssd_a, 0, sizeof(struct domain_a));
		ssd = (struct domain *)sdomain;
		ssd_a->len = sizeof(struct domain_a);
		ssd_a->type = INTERNAL_TYPE_A;

	}

	if (ssd_a->a_count >= RECORD_COUNT) {
		dolog(LOG_INFO, "%s: too many A records for zone \"%s\", skipping line %d\n", file->name, name, file->lineno);
		return (-1);
	}

	ssd->ttl[INTERNAL_TYPE_A] = myttl;
	ia = (in_addr_t *)&ssd_a->a[ssd_a->a_count];

	if ((*ia = inet_addr(a)) == INADDR_ANY) {
		dolog(LOG_INFO, "could not parse A record on line %d\n", file->lineno);
		return (-1);
	}
		
	ssd_a->region[ssd_a->a_count] = 0xff;

	ssd_a->a_count++;
	ssd_a->a_ptr = 0;

	ssd->flags |= DOMAIN_HAVE_A;

	set_record(ssd, rs, converted_name, converted_namelen);
	
	if (converted_name)
		free (converted_name);

	free (sdomain);
	
	return (0);

}


int
fill_aaaa(char *name, char *type, int myttl, char *aaaa)
{
	ddDB *db = mydb;
	void *sdomain, *tp;
	struct domain_aaaa *ssd_aaaa;
	struct domain *ssd;
	int converted_namelen;
	char *converted_name;
	struct in6_addr *ia6;
	int i, rs;

	
	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_AAAA, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	rs = get_record_size(db, converted_name, converted_namelen);
	if (rs < 0) {
		return (-1);
	}

	if ((sdomain = calloc(1, rs)) == NULL) {
		return -1;
	}

	ssd = (struct domain *)sdomain;

	if (get_record(ssd, converted_name, converted_namelen) < 0) {
		return (-1);
	}


	strlcpy((char *)ssd->zonename, (char *)name, DNS_MAXNAME + 1);
	memcpy(ssd->zone, converted_name, converted_namelen);
	ssd->zonelen = converted_namelen;

	ssd_aaaa = (struct domain_aaaa *)find_substruct(ssd, INTERNAL_TYPE_AAAA);
	if (ssd_aaaa == NULL) {

			rs += sizeof(struct domain_aaaa);	
#ifdef __OpenBSD__
			tp = reallocarray(sdomain, 1, rs);
#else
			tp = realloc(sdomain, rs);
#endif
			if (tp == NULL) {
				free (sdomain);
				return -1;
			}

			sdomain = tp;
			
			ssd_aaaa = (sdomain + (rs - sizeof(struct domain_aaaa)));
			memset((char *)ssd_aaaa, 0, sizeof(struct domain_aaaa));
			ssd = (struct domain *)sdomain;
			ssd_aaaa->len = sizeof(struct domain_aaaa);
			ssd_aaaa->type = INTERNAL_TYPE_AAAA;

	}

	if (ssd_aaaa->aaaa_count >= RECORD_COUNT) {
		dolog(LOG_INFO, "%s: too many AAAA records for zone \"%s\", skipping line %d\n", file->name, name, file->lineno);
		return (-1);
	}

	ssd->ttl[INTERNAL_TYPE_AAAA] = myttl;

	ia6 = (struct in6_addr *)&ssd_aaaa->aaaa[ssd_aaaa->aaaa_count];
	if (inet_pton(AF_INET6, (char *)aaaa, (char *)ia6) != 1) {
		dolog(LOG_INFO, "AAAA \"%s\" unparseable line %d\n", aaaa, file->lineno);
			return -1;
	}
		
	ssd_aaaa->aaaa_count++;
	ssd_aaaa->aaaa_ptr = 0;

	ssd->flags |= DOMAIN_HAVE_AAAA;

	set_record(ssd, rs, converted_name, converted_namelen);
	
	if (converted_name)
		free (converted_name);

	free (sdomain);
	
	return (0);

}


int
fill_ns(char *name, char *type, int myttl, char *nameserver)
{
	ddDB *db = mydb;
	void *sdomain, *tp;
	struct domain *ssd;
	struct domain_ns *ssd_ns;
	int len, converted_namelen;
	char *myname, *converted_name;
	char *n;
	int nstype, i, rs;


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
		return -1;
	}

	rs = get_record_size(db, converted_name, converted_namelen);
	if (rs < 0) {
		return -1;
	}

	if ((sdomain = calloc(1, rs)) == NULL) {
		return -1;
	}

	ssd = (struct domain *)sdomain;

	if (get_record(ssd, converted_name, converted_namelen) < 0) {
		return (-1);
	}

	strlcpy((char *)ssd->zonename, (char *)name, DNS_MAXNAME + 1);
	memcpy(ssd->zone, converted_name, converted_namelen);
	ssd->zonelen = converted_namelen;

	/*
	 * check if this is not the apex of a zone, if it was we're almost
	 * guaranteed to have come across a SOA already and it's not flagged
	 * then set the delegate type, this should make it possible to have		 * "NS" records instead of "delegate" records which are delphinusdnsd
	 * internal
	 */

	if (!(ssd->flags & DOMAIN_HAVE_SOA))
		nstype = NS_TYPE_DELEGATE;

	ssd_ns = (struct domain_ns *) find_substruct(ssd, INTERNAL_TYPE_NS);
	if (ssd_ns == NULL) {
			rs += sizeof(struct domain_ns);
#ifdef __OpenBSD__
			tp = reallocarray(sdomain, 1, rs);
#else
			tp = realloc(sdomain, rs);
#endif
			if (tp == NULL) {
				free (sdomain);
				return -1;
			}
			sdomain = tp;
			ssd_ns = (sdomain + (rs - sizeof(struct domain_ns)));
			memset((char *)ssd_ns, 0, sizeof(struct domain_ns));
			ssd = (struct domain *)sdomain;
			ssd_ns->len = sizeof(struct domain_ns);
			ssd_ns->type = INTERNAL_TYPE_NS;
	}
	if (debug)
		dolog(LOG_INFO, "after substruct\n");
			
	if (ssd_ns->ns_count >= RECORD_COUNT) {
		dolog(LOG_INFO, "%s: too many NS records for zone \"%s\", skipping line %d\n", file->name, name, file->lineno);
		return (-1);
	}

	ssd->ttl[INTERNAL_TYPE_NS] = myttl;

	myname = dns_label(nameserver, (int *)&len);	
	if (myname == NULL) {
		dolog(LOG_INFO, "illegal nameserver, skipping line %d\n", file->lineno);
		return 0;
	}

	if (len > 0xff || len < 0) {
		dolog(LOG_INFO, "illegal len value , line %d\n", file->lineno);
		return -1;
	}

	n = (char *)ssd_ns->ns[ssd_ns->ns_count].nsserver;
	ssd_ns->ns[ssd_ns->ns_count].nslen = len;
	memcpy((char *)n, myname, ssd_ns->ns[ssd_ns->ns_count].nslen);

	free(myname);

	ssd_ns->ns_count++;
	ssd_ns->ns_ptr = 0;
	ssd_ns->ns_type = nstype; 

	ssd->flags |= DOMAIN_HAVE_NS;

	set_record(ssd, rs, converted_name, converted_namelen);
	
	if (converted_name)
		free (converted_name);

	free (sdomain);
	
	return (0);

}

int
fill_soa(char *name, char *type, int myttl, char *auth, char *contact, int serial, int refresh, int retry, int expire, int ttl)
{
	ddDB *db = mydb;
	void *sdomain, *tp;
	struct domain *ssd;
	struct domain_soa *ssd_soa;
	int len, converted_namelen;
	char *myname, *converted_name;
	int i, rs;

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

	rs = get_record_size(db, converted_name, converted_namelen);
	if (rs < 0) {
		return -1;
	}

	if ((sdomain = calloc(1, rs)) == NULL) {
		return -1;
	}

	ssd = (struct domain *)sdomain;

	if (get_record(ssd, converted_name, converted_namelen) < 0) {
		return (-1);
	}

	strlcpy((char *)ssd->zonename, (char *)name, DNS_MAXNAME + 1);
	memcpy(ssd->zone, converted_name, converted_namelen);
	ssd->zonelen = converted_namelen;

	ssd->ttl[INTERNAL_TYPE_SOA] = myttl;

	myname = dns_label(auth, (int *)&len);	
	if (myname == NULL) {
		dolog(LOG_INFO, "illegal nameserver, skipping line %d\n", file->lineno);
		return 0;
	}

	if (len > 0xff || len < 0) {
		dolog(LOG_INFO, "illegal len value , line %d\n", file->lineno);
		return -1;
	}

	ssd_soa = (struct domain_soa *)find_substruct(ssd, INTERNAL_TYPE_SOA);
	if (ssd_soa == NULL) {
		rs += sizeof(struct domain_soa);
#ifdef __OpenBSD__
		tp = reallocarray(sdomain, 1, rs);
#else
		tp = realloc(sdomain, rs);
#endif
		if (tp == NULL) {
			if (debug)
				dolog(LOG_DEBUG, "reallocarray failed %s\n", strerror(errno));
			
			free (sdomain);
			return -1;
		}

		sdomain = tp;
		ssd_soa = (sdomain + (rs - sizeof(struct domain_soa)));
		memset((char *)ssd_soa, 0, sizeof(struct domain_soa));
		ssd = (struct domain *)sdomain;
		ssd_soa->len = sizeof(struct domain_soa);
		ssd_soa->type = INTERNAL_TYPE_SOA;
	}

	ssd_soa->soa.nsserver_len = len;
	memcpy((char *)&ssd_soa->soa.nsserver[0], myname, len);
		
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

	ssd_soa->soa.rp_len = len;
	memcpy((char *)&ssd_soa->soa.responsible_person[0], myname, len);

	free (myname);

	ssd_soa->soa.serial = serial;
	ssd_soa->soa.refresh = refresh;
	ssd_soa->soa.retry = retry;
	ssd_soa->soa.expire = expire;
	ssd_soa->soa.minttl = ttl;

	ssd->flags |= DOMAIN_HAVE_SOA;
	
	set_record(ssd, rs, converted_name, converted_namelen);
	
	if (converted_name)
		free (converted_name);

	free (sdomain);
	
	return (0);

}

int
get_record(struct domain *sdomain, char *converted_name, int converted_namelen)
{
	ddDB *db = mydb; /* XXX */

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	key.data = (char *)converted_name;
	key.size = converted_namelen;

	data.data = NULL;
	data.size = 0;

	if (db->get(db, &key, &data) == 0) {

		memcpy((char *)sdomain, (char *)data.data, data.size);
	} else {
		if (debug)
			dolog(LOG_INFO, "db->get: %s\n", strerror(errno));

		memset((char *)sdomain, 0, sizeof(struct domain));
	}

	return 0;
}
	

void
set_record(struct domain *sdomain, int rs, char *converted_name, int converted_namelen)
{
	ddDB *db = mydb; /* XXX */
	int ret;

	/* everythign in parse.y should get this flag! */
	sdomain->len = rs;

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	key.data = (char *)converted_name;
	key.size = converted_namelen;

	data.data = (void*)sdomain;
	data.size = rs;

	if ((ret = db->put(db, &key, &data)) != 0) {
		//dolog(LOG_INFO, "db->put: %s\n" , db_strerror(ret));
		return;
	}

	return;
}
	

struct file *
pushfile(const char *name, int secret)
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

	*len = outlen;

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
