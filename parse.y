/*
 * Copyright (c) 2014 Peter J. Philipp.  All rights reserved.
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
#include "include.h"
#include "dns.h"
#include "db.h"


extern void 	dolog(int, char *, ...);
extern char 	*dns_label(char *, int *);
extern u_int8_t find_region(struct sockaddr_storage *, int);
extern int 	insert_region(char *, char *, u_int8_t);
extern int 	insert_axfr(char *, char *);
extern int 	insert_notifyslave(char *, char *);
extern int 	insert_filter(char *, char *);
extern int 	insert_recurse(char *, char *);
extern int 	insert_whitelist(char *, char *);
extern int 	insert_wildcard(char *, char *);
extern void 	slave_shutdown(void);
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
extern int rflag;
extern int bcount;
extern int icount;
extern int ratelimit;
extern int ratelimit_packets_per_second;
extern u_int16_t port;
extern u_int32_t cachesize;
extern char *bind_list[255];
extern char *interface_list[255];



TAILQ_HEAD(files, file)          files = TAILQ_HEAD_INITIALIZER(files);
static struct file {
        TAILQ_ENTRY(file)        entry;
        FILE                    *stream;
        char                    *name;
        int                      lineno;
        int                      errors;
} *file, *topfile;

#define STATE_IP 1
#define STATE_ZONE 2

#define WILDCARDVERSION 6

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
		int intval;
	} v;
	int lineno;
} YYSTYPE;

#ifdef __APPLE__
#define YYSTYPE_IS_DECLARED 1
#endif

static const char rcsid[] = "$Id: parse.y,v 1.1.1.1 2014/11/14 08:09:04 pjp Exp $";
static int version = 0;
static int state = 0;
static uint8_t region = 0;
static uint64_t confstatus = 0;
static DB *mydb;

YYSTYPE yylval;


char *converted_name;
int converted_namelen;
DBT key, data;
struct logging logging;
int axfrport = 0;
time_t time_changed;



char 		*check_rr(char *, char *, int, int *);
int 		fill_a(char *, char *, int, char *);
int 		fill_aaaa(char *, char *, int, char *);
int 		fill_balance(char *, char *, int, char *);
int 		fill_ptr(char *, char *, int, char *);
int 		fill_cname(char *, char *, int, char *);
int 		fill_mx(char *, char *, int, int, char *);
int 		fill_naptr(char *, char *, int, int, int, char *, char *, char *, char *);
int 		fill_ns(char *, char *, int, char *);
int 		fill_soa(char *, char *, int, char *, char *, int, int, int, int, int);
int 		fill_spf(char *, char *, int, char *);
int 		fill_sshfp(char *, char *, int, int, int, char *);
int 		fill_srv(char *, char *, int, int, int, int, char *);
int 		fill_txt(char *, char *, int, char *);
int             findeol(void);
int 		get_ip(char *, int);
char 		*get_prefixlen(char *, char *, int);
int 		get_quotedstring(char *, int);
int 		get_record(struct domain *, char *, int);
int 		get_string(char *, int);
int             lgetc(int);
struct tab * 	lookup(struct tab *, char *);
int             lungetc(int);
int 		parse_file(DB *, char *);
struct file     *pushfile(const char *, int);
int             popfile(void);
struct rrtab 	*rrlookup(struct rrtab *, char *);
void 		set_record(struct domain *, char *, int);
static int 	temp_inet_net_pton_ipv6(const char *, void *, size_t);
int 		yyparse(void);


struct rrtab {
        char *name;
        u_int16_t type;
} myrrtab[] =  { 
 { "a",         DNS_TYPE_A } ,
 { "soa",       DNS_TYPE_SOA },
 { "cname",     DNS_TYPE_CNAME },
 { "ptr",       DNS_TYPE_PTR },
 { "mx",        DNS_TYPE_MX },
 { "aaaa",      DNS_TYPE_AAAA },
 { "ns",        DNS_TYPE_NS },
 { "txt",       DNS_TYPE_TXT },
 { "hint",      DNS_TYPE_HINT }, 
 { "delegate",  DNS_TYPE_DELEGATE },
 { "balance",   DNS_TYPE_BALANCE }, 
 { "srv",       DNS_TYPE_SRV },
 { "spf",	DNS_TYPE_SPF },
 { "sshfp", 	DNS_TYPE_SSHFP },
 { "naptr", 	DNS_TYPE_NAPTR },
 { NULL, 0 },
};




%}


%token VERSION OBRACE EBRACE REGION AXFRFOR RECURSEFOR
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
	| wof CRLF
	| axfr CRLF
	| notify CRLF
	| whitelist CRLF
	| filter CRLF
	| recurse CRLF 
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
		if (version != WILDCARDVERSION) {
			dolog(LOG_ERR, "version of configfile is wrong,"
					" must be \"%d\"!\n", WILDCARDVERSION);
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
		if ((confstatus & CONFIG_VERSION) != CONFIG_VERSION) {
                        dolog(LOG_INFO, "There must be a version at the top of the first configfile\n");
                        return (-1);
                }
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

			} else if (strcasecmp($3, "balance") == 0) {
				if (fill_balance($1, $3, $5, $7) < 0) {
					return -1;
				}

				if (debug)
					printf("a balance record?\n");
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
					printf("%s MX -> %d %s\n", $1, $7, $9);

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
			} else if (strcasecmp($3, "spf") == 0) {
				if (fill_spf($1, $3, $5, $7) < 0) {	
					return -1;
				}

				if (debug)
					printf(" %s SPF -> %s\n", $1, $7);
			} else {
				if (debug)
					printf("another txt/spf like record I don't know?\n");
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
		if (strcasecmp($1, "recurse") == 0) {
			dolog(LOG_DEBUG, "recursive server on\n");
			rflag = 0; 	/* keep it off please! */
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
			snprintf(buf, sizeof(buf), "%d", $2);
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
						printf("recurse inserted %s address\n", $1);
	
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
						printf("recurse inserted %s address\n", $1);

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
						printf("recurse inserted %s address\n", $1);

					free (dst);
					free ($1);
			}
			| comment CRLF
			;	

/* recurse-for "these hosts" { .. } */

recurse:
	RECURSEFOR recurselabel recursecontent
	{
		if ((confstatus & CONFIG_VERSION) != CONFIG_VERSION) {
                        dolog(LOG_INFO, "There must be a version at the top of the first configfile\n");
                        return (-1);
                }
	}
	;

recurselabel:
	QUOTEDSTRING
	;

recursecontent:
			OBRACE recursestatements EBRACE
			| OBRACE CRLF recursestatements EBRACE
			;

recursestatements 	:  		
				recursestatements recursestatement 
				| recursestatement 
				;

recursestatement	:	ipcidr SEMICOLON CRLF
				{
					char prefixlength[INET_ADDRSTRLEN];
					char *dst;
				
					if ((dst = get_prefixlen($1, (char *)&prefixlength, sizeof(prefixlength))) == NULL)  {
						return (-1);
					}

					if (insert_recurse(dst, prefixlength) < 0) {
						dolog(LOG_ERR, "insert_recurse, line %d\n", file->lineno);
						return (-1);
					}
	
					if (debug)
						printf("recurse inserted %s address\n", $1);

					free (dst);
					free ($1);
				}
				| comment CRLF
				;	


/* wildcard-only-for "these hosts" { .. } */

wof:
	WOF woflabel wofcontent 
	{		 
		if ((confstatus & CONFIG_VERSION) != CONFIG_VERSION) {
                        dolog(LOG_INFO, "There must be a version at the top of the first configfile\n");
                        return (-1);
                }
	}
	;

woflabel:
	QUOTEDSTRING
	;

wofcontent:
			OBRACE wofstatements EBRACE 
			| OBRACE CRLF wofstatements EBRACE 
			;

wofstatements 	:  		
				wofstatements wofstatement  
				| wofstatement 
				;

wofstatement		:	ipcidr SEMICOLON CRLF
				{
					char prefixlength[INET_ADDRSTRLEN];
					char *dst;
				
					if ((dst = get_prefixlen($1, (char *)&prefixlength, sizeof(prefixlength))) == NULL)  {
						
						return (-1);
					}

					if (insert_wildcard(dst, prefixlength) < 0) {
						dolog(LOG_ERR, "insert_wildcard, line %d\n", file->lineno);
						return (-1);
					}
	
					if (debug)
						printf("wildcard inserted %s address\n", $1);

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
	{ "recurse-for", RECURSEFOR, STATE_IP },
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
parse_file(DB *db, char *filename)
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

	dolog(LOG_INFO, "configuration file read\n");
	
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
			yylval.v.intval = atoi(buf);

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

struct rrtab * 
rrlookup(struct rrtab *p, char *keyword)
{

	for (; p->name != NULL; p++) {
		if (strcasecmp(p->name, keyword) == 0)
			return (p);
	}
	
	return (NULL);
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
	
	
	if ((rr = rrlookup(myrrtab, mytype)) == NULL) {
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
	struct domain sdomain;
	char *myname, *converted_name;
	int len, converted_namelen;
	int i ;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_CNAME, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	memset(&sdomain, 0, sizeof(sdomain));
	if (get_record(&sdomain, converted_name, converted_namelen) < 0) {
		return (-1);
	}

#ifdef __linux__
	strncpy((char *)sdomain.zonename, (char *)name, DNS_MAXNAME + 1);
	sdomain.zonename[DNS_MAXNAME] = '\0';
#else
	strlcpy((char *)sdomain.zonename, (char *)name, DNS_MAXNAME + 1);
#endif
	memcpy(sdomain.zone, converted_name, converted_namelen);
	sdomain.zonelen = converted_namelen;

	sdomain.ttl = myttl;

	myname = dns_label(hostname, (int *)&len);	
	if (myname == NULL) {
		dolog(LOG_INFO, "illegal nameserver, skipping line %d\n", file->lineno);
		return 0;
	}

	if (len > 0xff || len < 0) {
		dolog(LOG_INFO, "illegal len value , line %d\n", file->lineno);
		return -1;
	}

	sdomain.cnamelen = len;
	memcpy((char *)&sdomain.cname[0], myname, len);

	free(myname);

	sdomain.flags |= DOMAIN_HAVE_CNAME;

	set_record(&sdomain, converted_name, converted_namelen);
	
	if (converted_name)
		free (converted_name);
	
	return (0);

}

int
fill_ptr(char *name, char *type, int myttl, char *hostname)
{
	struct domain sdomain;
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

	memset(&sdomain, 0, sizeof(sdomain));
	if (get_record(&sdomain, converted_name, converted_namelen) < 0) {
		 return (-1);
	}

#ifdef __linux__
	strncpy((char *)sdomain.zonename, (char *)name, DNS_MAXNAME + 1);
	sdomain.zonename[DNS_MAXNAME] = '\0';
#else
	strlcpy((char *)sdomain.zonename, (char *)name, DNS_MAXNAME + 1);
#endif
	memcpy(sdomain.zone, converted_name, converted_namelen);
	sdomain.zonelen = converted_namelen;

	sdomain.ttl = myttl;

	myname = dns_label(hostname, (int *)&len);	
	if (myname == NULL) {
		dolog(LOG_INFO, "illegal nameserver, skipping line %d\n", file->lineno);
		return 0;
	}

	if (len > 0xff || len < 0) {
		dolog(LOG_INFO, "illegal len value , line %d\n", file->lineno);
		return -1;
	}

	sdomain.ptrlen = len;
	memcpy((char *)&sdomain.ptr[0], myname, len);

	free(myname);

	sdomain.flags |= DOMAIN_HAVE_PTR;

	set_record(&sdomain, converted_name, converted_namelen);
	
	if (converted_name)
		free (converted_name);
	
	return (0);

}

/* based on fill_txt */
int
fill_spf(char *name, char *type, int myttl, char *msg)
{
	struct domain sdomain;
	int converted_namelen;
	char *converted_name;
	int len, i;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	if ((len = strlen(msg)) > 255) {
		dolog(LOG_ERR, "SPF record too long line %d\n", file->lineno);
		return (-1);
	}

	converted_name = check_rr(name, type, DNS_TYPE_SPF, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	memset(&sdomain, 0, sizeof(sdomain));
	if (get_record(&sdomain, converted_name, converted_namelen) < 0) {
		return (-1);
	}

#ifdef __linux__
	strncpy((char *)sdomain.zonename, (char *)name, DNS_MAXNAME + 1);
	sdomain.zonename[DNS_MAXNAME] = '\0';
#else
	strlcpy((char *)sdomain.zonename, (char *)name, DNS_MAXNAME + 1);
#endif
	memcpy(sdomain.zone, converted_name, converted_namelen);
	sdomain.zonelen = converted_namelen;

	sdomain.ttl = myttl;

	memcpy(&sdomain.spf, msg, len);
	sdomain.spflen = len;

	sdomain.flags |= DOMAIN_HAVE_SPF;

	set_record(&sdomain, converted_name, converted_namelen);
	
	if (converted_name)
		free (converted_name);
	
	return (0);

}


int
fill_naptr(char *name, char *type, int myttl, int order, int preference, char *flags, char *services, char *regexp, char *replacement)
{
	struct domain sdomain;
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

	memset(&sdomain, 0, sizeof(sdomain));
	if (get_record(&sdomain, converted_name, converted_namelen) < 0) {
		return (-1);
	}

#ifdef __linux__
	strncpy((char *)sdomain.zonename, (char *)name, DNS_MAXNAME + 1);
	sdomain.zonename[DNS_MAXNAME] = '\0';
#else
	strlcpy((char *)sdomain.zonename, (char *)name, DNS_MAXNAME + 1);
#endif
	memcpy(sdomain.zone, converted_name, converted_namelen);
	sdomain.zonelen = converted_namelen;

	sdomain.ttl = myttl;

	sdomain.naptr[sdomain.naptr_count].order = order;
	sdomain.naptr[sdomain.naptr_count].preference = preference;

	memcpy(&sdomain.naptr[sdomain.naptr_count].flags, flags, flagslen);
	sdomain.naptr[sdomain.naptr_count].flagslen = flagslen;

	memcpy(&sdomain.naptr[sdomain.naptr_count].services, services, serviceslen);
	sdomain.naptr[sdomain.naptr_count].serviceslen = serviceslen;

	memcpy(&sdomain.naptr[sdomain.naptr_count].regexp, regexp, regexplen);
	sdomain.naptr[sdomain.naptr_count].regexplen = regexplen;

	naptrname = check_rr(replacement, type, DNS_TYPE_NAPTR, &naptr_namelen);
	if (naptrname == NULL) {
		return -1;
	}

	memcpy(&sdomain.naptr[sdomain.naptr_count].replacement, naptrname, naptr_namelen);
	sdomain.naptr[sdomain.naptr_count].replacementlen = naptr_namelen;
	
	sdomain.naptr_count++;

	sdomain.flags |= DOMAIN_HAVE_NAPTR;

	set_record(&sdomain, converted_name, converted_namelen);
	
	if (naptrname)
		free (naptrname);

	if (converted_name)
		free (converted_name);
	
	return (0);

}

int
fill_txt(char *name, char *type, int myttl, char *msg)
{
	struct domain sdomain;
	int converted_namelen;
	char *converted_name;
	int len, i;

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

	memset(&sdomain, 0, sizeof(sdomain));
	if (get_record(&sdomain, converted_name, converted_namelen) < 0) {
		return (-1);
	}

#ifdef __linux__
	strncpy((char *)sdomain.zonename, (char *)name, DNS_MAXNAME + 1);
	sdomain.zonename[DNS_MAXNAME] = '\0';
#else
	strlcpy((char *)sdomain.zonename, (char *)name, DNS_MAXNAME + 1);
#endif
	memcpy(sdomain.zone, converted_name, converted_namelen);
	sdomain.zonelen = converted_namelen;

	sdomain.ttl = myttl;

	memcpy(&sdomain.txt, msg, len);
	sdomain.txtlen = len;

	sdomain.flags |= DOMAIN_HAVE_TXT;

	set_record(&sdomain, converted_name, converted_namelen);
	
	if (converted_name)
		free (converted_name);
	
	return (0);

}

/* based on fill_srv */
int
fill_sshfp(char *name, char *type, int myttl, int alg, int fptype, char *fingerprint)
{
	struct domain sdomain;
	int converted_namelen;
	char *converted_name;
	char *p, *ep, save;
	int len, i;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_SSHFP, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	memset(&sdomain, 0, sizeof(sdomain));
	if (get_record(&sdomain, converted_name, converted_namelen) < 0) {
		return (-1);
	}

#ifdef __linux__
	strncpy((char *)sdomain.zonename, (char *)name, DNS_MAXNAME + 1);
	sdomain.zonename[DNS_MAXNAME] = '\0';
#else
	strlcpy((char *)sdomain.zonename, (char *)name, DNS_MAXNAME + 1);
#endif
	memcpy(sdomain.zone, converted_name, converted_namelen);
	sdomain.zonelen = converted_namelen;

	if (sdomain.sshfp_count >= RECORD_COUNT) {
		dolog(LOG_INFO, "%s: too many SSHFP records for zone \"%s\", skipping line %d\n", file->name, name, file->lineno);
		return (-1);
	}

	sdomain.ttl = myttl;

	sdomain.sshfp[sdomain.sshfp_count].algorithm = alg;
	sdomain.sshfp[sdomain.sshfp_count].fptype = fptype;

	switch (fptype) {
	case 1:
		len = sdomain.sshfp[sdomain.sshfp_count].fplen = DNS_SSHFP_SIZE_SHA1;
		break;
	case 2:
		len = sdomain.sshfp[sdomain.sshfp_count].fplen = DNS_SSHFP_SIZE_SHA256;
		break;
	default:
		dolog(LOG_ERR, "sshfp: unknown fingerprint type!\n");
		return -1;
	}

	p = fingerprint;
	for (i = 0; i < len; i++) {
		save = p[2];
		p[2] = '\0';
		sdomain.sshfp[sdomain.sshfp_count].fingerprint[i] = strtol(p, &ep, 16);
		p[2] = save;
		p += 2;
	}


	sdomain.sshfp_count++;

	sdomain.flags |= DOMAIN_HAVE_SSHFP;

	set_record(&sdomain, converted_name, converted_namelen);
	
	if (converted_name)
		free (converted_name);
	
	return (0);

}

int
fill_srv(char *name, char *type, int myttl, int priority, int weight, int port, char *srvhost)
{
	struct domain sdomain;
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

	memset(&sdomain, 0, sizeof(sdomain));
	if (get_record(&sdomain, converted_name, converted_namelen) < 0) {
		return (-1);
	}

#ifdef __linux__
	strncpy((char *)sdomain.zonename, (char *)name, DNS_MAXNAME + 1);
	sdomain.zonename[DNS_MAXNAME] = '\0';
#else
	strlcpy((char *)sdomain.zonename, (char *)name, DNS_MAXNAME + 1);
#endif
	memcpy(sdomain.zone, converted_name, converted_namelen);
	sdomain.zonelen = converted_namelen;

	if (sdomain.srv_count >= RECORD_COUNT) {
		dolog(LOG_INFO, "%s: too many SRV records for zone \"%s\", skipping line %d\n", file->name, name, file->lineno);
		return (-1);
	}

	sdomain.ttl = myttl;

	sdomain.srv[sdomain.srv_count].priority = priority;
	sdomain.srv[sdomain.srv_count].weight = weight;
	sdomain.srv[sdomain.srv_count].port = port;

	srvname = dns_label(srvhost, &len);
	if (srvname == NULL) {
		dolog(LOG_INFO, "illegal srv server, skipping line %d\n", file->lineno);
		return (-1);
	}


	sdomain.srv[sdomain.srv_count].targetlen = len;
	memcpy((char *)&sdomain.srv[sdomain.srv_count].target, srvname, len);

	/* bad hack workaround !!! */
	if (strcmp(srvhost, ".") == 0 && len > 1) 
		sdomain.srv[sdomain.srv_count].targetlen = 1;

	free (srvname);

	sdomain.srv_count++;

	sdomain.flags |= DOMAIN_HAVE_SRV;

	set_record(&sdomain, converted_name, converted_namelen);
	
	if (converted_name)
		free (converted_name);
	
	return (0);

}

int
fill_mx(char *name, char *type, int myttl, int priority, char *mxhost)
{
	struct domain sdomain;
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

	memset(&sdomain, 0, sizeof(sdomain));
	if (get_record(&sdomain, converted_name, converted_namelen) < 0) {
		return (-1);
	}

#ifdef __linux__
	strncpy((char *)sdomain.zonename, (char *)name, DNS_MAXNAME + 1);
	sdomain.zonename[DNS_MAXNAME] = '\0';
#else
	strlcpy((char *)sdomain.zonename, (char *)name, DNS_MAXNAME + 1);
#endif
	memcpy(sdomain.zone, converted_name, converted_namelen);
	sdomain.zonelen = converted_namelen;

	if (sdomain.mx_count >= RECORD_COUNT) {
		dolog(LOG_INFO, "%s: too many MX records for zone \"%s\", skipping line %d\n", file->name, name, file->lineno);
		return (-1);
	}

	sdomain.ttl = myttl;
	sdomain.mx[sdomain.mx_count].preference = priority;

	mxname = dns_label(mxhost, &len);
	if (mxname == NULL) {
		dolog(LOG_INFO, "illegal mx server, skipping line %d\n", file->lineno);
		return (-1);
	}

	sdomain.mx[sdomain.mx_count].exchangelen = len;
	memcpy((char *)&sdomain.mx[sdomain.mx_count].exchange, mxname, len);
	free (mxname);

	sdomain.mx_count++;

	sdomain.flags |= DOMAIN_HAVE_MX;

	set_record(&sdomain, converted_name, converted_namelen);
	
	if (converted_name)
		free (converted_name);
	
	return (0);

}

int
fill_balance(char *name, char *type, int myttl, char *a)
{
	struct domain sdomain;
	int converted_namelen;
	char *converted_name;
	struct sockaddr_in sin;
	in_addr_t *ia;
	int i;

	for (i = 0; i < strlen(name); i++) {
		name[i] = tolower((int)name[i]);
	}

	converted_name = check_rr(name, type, DNS_TYPE_BALANCE, &converted_namelen);
	if (converted_name == NULL) {
		return -1;
	}

	memset(&sdomain, 0, sizeof(sdomain));
	if (get_record(&sdomain, converted_name, converted_namelen) < 0) {
		return (-1);
	}

#ifdef __linux__
	strncpy((char *)sdomain.zonename, (char *)name, DNS_MAXNAME + 1);
	sdomain.zonename[DNS_MAXNAME] = '\0';
#else
	strlcpy((char *)sdomain.zonename, (char *)name, DNS_MAXNAME + 1);
#endif
	memcpy(sdomain.zone, converted_name, converted_namelen);
	sdomain.zonelen = converted_namelen;

	if (sdomain.a_count >= RECORD_COUNT) {
		dolog(LOG_INFO, "%s: too many BALANCE records for zone \"%s\", skipping line %d\n", file->name, name, file->lineno);
		return (-1);
	}

	sdomain.ttl = myttl;
	ia = (in_addr_t *)&sdomain.a[sdomain.a_count];

	if ((*ia = inet_addr(a)) == INADDR_ANY) {
		dolog(LOG_INFO, "could not parse BALANCE record on line %d\n", file->lineno);
		return (-1);
	}


	memset(&sin, 0, sizeof(sin));
	sin.sin_addr.s_addr = *ia;
	sin.sin_family = AF_INET;
	sdomain.region[sdomain.a_count] = find_region((struct sockaddr_storage *)&sin, AF_INET);

	sdomain.a_count++;
	sdomain.a_ptr = 0;

	sdomain.flags |= DOMAIN_HAVE_A;

	set_record(&sdomain, converted_name, converted_namelen);
	
	if (converted_name)
		free (converted_name);
	
	return (0);

}

int
fill_a(char *name, char *type, int myttl, char *a)
{
	struct domain sdomain;
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

	memset(&sdomain, 0, sizeof(sdomain));
	if (get_record(&sdomain, converted_name, converted_namelen) < 0) {
		return (-1);
	}

#ifdef __linux__
	strncpy((char *)sdomain.zonename, (char *)name, DNS_MAXNAME + 1);
	sdomain.zonename[DNS_MAXNAME] = '\0';
#else
	strlcpy((char *)sdomain.zonename, (char *)name, DNS_MAXNAME + 1);
#endif
	memcpy(sdomain.zone, converted_name, converted_namelen);
	sdomain.zonelen = converted_namelen;

	if (sdomain.a_count >= RECORD_COUNT) {
		dolog(LOG_INFO, "%s: too many A records for zone \"%s\", skipping line %d\n", file->name, name, file->lineno);
		return (-1);
	}

	sdomain.ttl = myttl;
	ia = (in_addr_t *)&sdomain.a[sdomain.a_count];

	if ((*ia = inet_addr(a)) == INADDR_ANY) {
		dolog(LOG_INFO, "could not parse A record on line %d\n", file->lineno);
		return (-1);
	}
		
	sdomain.region[sdomain.a_count] = 0xff;

	sdomain.a_count++;
	sdomain.a_ptr = 0;

	sdomain.flags |= DOMAIN_HAVE_A;

	set_record(&sdomain, converted_name, converted_namelen);
	
	if (converted_name)
		free (converted_name);
	
	return (0);

}


int
fill_aaaa(char *name, char *type, int myttl, char *aaaa)
{
	struct domain sdomain;
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

	memset(&sdomain, 0, sizeof(sdomain));
	if (get_record(&sdomain, converted_name, converted_namelen) < 0) {
		return (-1);
	}

#ifdef __linux__
	strncpy((char *)sdomain.zonename, (char *)name, DNS_MAXNAME + 1);
	sdomain.zonename[DNS_MAXNAME] = '\0';
#else
	strlcpy((char *)sdomain.zonename, (char *)name, DNS_MAXNAME + 1);
#endif
	memcpy(sdomain.zone, converted_name, converted_namelen);
	sdomain.zonelen = converted_namelen;

	if (sdomain.aaaa_count >= RECORD_COUNT) {
		dolog(LOG_INFO, "%s: too many AAAA records for zone \"%s\", skipping line %d\n", file->name, name, file->lineno);
		return (-1);
	}

	sdomain.ttl = myttl;
	ia6 = (struct in6_addr *)&sdomain.aaaa[sdomain.aaaa_count];
	if (inet_pton(AF_INET6, (char *)aaaa, (char *)ia6) != 1) {
		dolog(LOG_INFO, "AAAA \"%s\" unparseable line %d\n", aaaa, file->lineno);
			return -1;
	}
		
	sdomain.aaaa_count++;
	sdomain.aaaa_ptr = 0;

	sdomain.flags |= DOMAIN_HAVE_AAAA;

	set_record(&sdomain, converted_name, converted_namelen);
	
	if (converted_name)
		free (converted_name);
	
	return (0);

}


int
fill_ns(char *name, char *type, int myttl, char *nameserver)
{
	struct domain sdomain;
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
		nstype = NS_TYPE_DELEGATE;
	}

	if (converted_name == NULL) {
		return -1;
	}

	memset(&sdomain, 0, sizeof(sdomain));
	if (get_record(&sdomain, converted_name, converted_namelen) < 0) {
		return (-1);
	}

#ifdef __linux__
	strncpy((char *)sdomain.zonename, (char *)name, DNS_MAXNAME + 1);
	sdomain.zonename[DNS_MAXNAME] = '\0';
#else
	strlcpy((char *)sdomain.zonename, (char *)name, DNS_MAXNAME + 1);
#endif
	memcpy(sdomain.zone, converted_name, converted_namelen);
	sdomain.zonelen = converted_namelen;

	if (sdomain.ns_count >= RECORD_COUNT) {
		dolog(LOG_INFO, "%s: too many NS records for zone \"%s\", skipping line %d\n", file->name, name, file->lineno);
		return (-1);
	}

	sdomain.ttl = myttl;

	myname = dns_label(nameserver, (int *)&len);	
	if (myname == NULL) {
		dolog(LOG_INFO, "illegal nameserver, skipping line %d\n", file->lineno);
		return 0;
	}

	if (len > 0xff || len < 0) {
		dolog(LOG_INFO, "illegal len value , line %d\n", file->lineno);
		return -1;
	}

	n = (char *)sdomain.ns[sdomain.ns_count].nsserver;
	sdomain.ns[sdomain.ns_count].nslen = len;
	memcpy((char *)n, myname, sdomain.ns[sdomain.ns_count].nslen);

	free(myname);

	sdomain.ns_count++;
	sdomain.ns_ptr = 0;
	sdomain.ns_type = nstype; 

	sdomain.flags |= DOMAIN_HAVE_NS;

	set_record(&sdomain, converted_name, converted_namelen);
	
	if (converted_name)
		free (converted_name);
	
	return (0);

}


/* centroid.eu,soa,3600,uranus.centroid.eu.,pjp.solarscale.de.,1258740680,3600,1800,7200,3600 */
int
fill_soa(char *name, char *type, int myttl, char *auth, char *contact, int serial, int retry, int refresh, int expire, int ttl)
{
	struct domain sdomain;
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

	memset(&sdomain, 0, sizeof(sdomain));
	if (get_record(&sdomain, converted_name, converted_namelen) < 0) {
		return (-1);
	}

#ifdef __linux__
	strncpy((char *)sdomain.zonename, (char *)name, DNS_MAXNAME + 1);
	sdomain.zonename[DNS_MAXNAME] = '\0';
#else
	strlcpy((char *)sdomain.zonename, (char *)name, DNS_MAXNAME + 1);
#endif
	memcpy(sdomain.zone, converted_name, converted_namelen);
	sdomain.zonelen = converted_namelen;

	sdomain.ttl = myttl;

	myname = dns_label(auth, (int *)&len);	
	if (myname == NULL) {
		dolog(LOG_INFO, "illegal nameserver, skipping line %d\n", file->lineno);
		return 0;
	}

	if (len > 0xff || len < 0) {
		dolog(LOG_INFO, "illegal len value , line %d\n", file->lineno);
		return -1;
	}

	sdomain.soa.nsserver_len = len;
	memcpy((char *)&sdomain.soa.nsserver[0], myname, len);
		
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

	sdomain.soa.rp_len = len;
	memcpy((char *)&sdomain.soa.responsible_person[0], myname, len);

	free (myname);

	sdomain.soa.serial = serial;
	sdomain.soa.refresh = refresh;
	sdomain.soa.retry = retry;
	sdomain.soa.expire = expire;
	sdomain.soa.minttl = ttl;

	sdomain.flags |= DOMAIN_HAVE_SOA;
	
	set_record(&sdomain, converted_name, converted_namelen);
	
	if (converted_name)
		free (converted_name);
	
	return (0);

}


int
get_record(struct domain *sdomain, char *converted_name, int converted_namelen)
{
	DB *db = mydb; /* XXX */

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	key.data = (char *)converted_name;
	key.size = converted_namelen;

	data.data = NULL;
	data.size = 0;

	if (db->get(db, NULL, &key, &data, 0) == 0) {

		if (data.size != sizeof(struct domain)) {
			dolog(LOG_INFO, "damaged btree database\n");
			return -1;
		}

		memcpy((char *)sdomain, (char *)data.data, data.size);
	} else {
		if (debug)
			dolog(LOG_INFO, "db->get: %s\n", strerror(errno));
	}

	return 0;
}
	

void
set_record(struct domain *sdomain, char *converted_name, int converted_namelen)
{
	DB *db = mydb; /* XXX */
	int ret;

	/* everythign in parse.y should get this flag! */
	sdomain->flags |= DOMAIN_STATIC_ZONE;

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	key.data = (char *)converted_name;
	key.size = converted_namelen;

	data.data = (void*)sdomain;
	data.size = sizeof(struct domain);

	if ((ret = db->put(db, NULL, &key, &data, 0)) != 0) {
		dolog(LOG_INFO, "db->put: %s\n" , db_strerror(ret));
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
        TAILQ_INSERT_TAIL(&files, nfile, entry);
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

        if ((prev = TAILQ_PREV(file, files, entry)) != NULL)
                prev->errors += file->errors;

        TAILQ_REMOVE(&files, file, entry);
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
#if defined __OpenBSD__ || defined __FreeBSD__
        const char      *errstr;
#endif

#ifndef __linux__
        if (strlcpy(buf, src, sizeof buf) >= sizeof buf) {
                errno = EMSGSIZE;
                return (-1);
        }
#else
	strncpy(buf, src, sizeof(buf));
	buf[sizeof(buf) - 1] = '\0';
#endif

        sep = strchr(buf, '/');
        if (sep != NULL)
                *sep++ = '\0';

        ret = inet_pton(AF_INET6, buf, dst);
        if (ret != 1) {
                return (-1);
	}

        if (sep == NULL)
                return 128;

#if ! defined __linux__ && ! defined __APPLE__ && ! defined __NetBSD__
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
