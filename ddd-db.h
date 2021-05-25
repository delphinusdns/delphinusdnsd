/*
 * Copyright (c) 2005-2021 Peter J. Philipp <pjp@delphinusdns.org>
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


#ifndef _DDD_DB_H
#define _DDD_DB_H

#include <sys/types.h>
#include <limits.h>

#include <openssl/hmac.h>
#include <openssl/md5.h>
#include "ddd-config.h"

#ifndef DEFAULT_CONFFILE
#define CONFFILE "/var/delphinusdnsd/etc/delphinusdns.conf"
#else
#define CONFFILE DEFAULT_CONFFILE
#endif

#define DEFAULT_SOCKET 64

#define PARSEFILE_FLAG_NOSOCKET 0x1


#define IMSG_HELLO_MESSAGE  0		/* hello the primary process a few */
#define IMSG_SPREAD_MESSAGE 1		/* spread a record to all childs */
#define IMSG_XFR_MESSAGE    2		/* forward message to axfr proc */
#define IMSG_PARSE_MESSAGE  4		/* pass message to pledge parser */
#define IMSG_PARSEREPLY_MESSAGE 5	/* return message from pledge parser */
#define IMSG_SHUTDOWN_MESSAGE 6		/* shut the server down */
#define IMSG_RELOAD_MESSAGE 7		/* reload/restart the server */
#define IMSG_PARSEAUTH_MESSAGE	8	/* parse message with auth required */
#define	IMSG_NOTIFY_MESSAGE	9	/* notify our replicant engine */
#define IMSG_SETUP_NEURON	10	/* set up a new imsg via fd passing */
#define IMSG_CRIPPLE_NEURON	11	/* no new neurons are needed */
#define IMSG_FORWARD_UDP	12	/* forward a UDP packet */
#define IMSG_FORWARD_TCP	13	/* forward a TCP packet (with fd) */
#define IMSG_RR_ATTACHED	14	/* an RR is sent through imsg */
#define IMSG_PARSEERROR_MESSAGE 15	/* return error message from pledge parser */

#define ERR_DROP	0x1
#define ERR_NXDOMAIN	0x2
#define ERR_NOERROR	0x4
#define ERR_REFUSED	0x8
#define	ERR_NODATA	0x10
#define ERR_DELEGATE	0x20
#define ERR_FORWARD	0x40

#define RECORD_COUNT	20
#define NEGATIVE_CACHE_TIME	600	/* DNS & Bind 3rd edition page 35 */

#ifndef DEFAULT_PRIVILEGE
#define DEFAULT_PRIVILEGE "_ddd"
#endif

/* db stuff */

struct dnskey {
	u_int16_t flags;
#define DNSKEY_ZONE_KEY			(1 << 7)
#define DNSKEY_SECURE_ENTRY		(1 << 15)
	u_int8_t protocol;		/* must be 3 */
	u_int8_t algorithm;		/* would be 5, RFC 3110 */
	char public_key[4096];
	u_int16_t publickey_len;
};

struct rrsig {
	u_int16_t type_covered;
	u_int8_t algorithm;	/* usually 5, RFC3110 */
	u_int8_t labels;
	u_int32_t original_ttl;
	u_int32_t signature_expiration;
	u_int32_t signature_inception;
	u_int16_t key_tag;
	char signers_name[DNS_MAXNAME];
	u_int8_t signame_len;
	char signature[4096];
	u_int16_t signature_len;
	uint32_t ttl;		/* RFC 4034 section 3, the TTL value of ... */
	int used;		/* if this RRSIG is used at all */
	time_t created;		/* when this was added to the cache */
};

struct nsec {
	char next_domain_name[DNS_MAXNAME];
	u_int8_t ndn_len;	/* next domain name length */
	char bitmap[8192];
	u_int16_t bitmap_len;
};

struct nsec3 {
	u_int8_t algorithm;
	u_int8_t flags;
	u_int16_t iterations;
	u_int8_t saltlen;
	char salt[256];
	char next[DNS_MAXNAME];
	u_int8_t nextlen;	/* next domain name length */
	char bitmap[8192];
	u_int16_t bitmap_len;
};

struct nsec3param {
	u_int8_t algorithm;
	u_int8_t flags;
	u_int16_t iterations;
	u_int8_t saltlen;
	char salt[256];
};

struct ds {
	u_int16_t key_tag;
	u_int8_t algorithm;
	u_int8_t digest_type;
	char digest[4096];
	u_int16_t digestlen;
};


struct soa {
	char nsserver[DNS_MAXNAME];
	u_int8_t nsserver_len;
	char responsible_person[DNS_MAXNAME];
	u_int8_t rp_len;
	u_int32_t serial;
	u_int32_t refresh;
	u_int32_t retry;
	u_int32_t expire;
	u_int32_t minttl;
};

struct smx {
	u_int16_t preference;		/* MX preference */
	char exchange[DNS_MAXNAME];	/* name of exchange server */
	int exchangelen;		/* length of exchange server name */
};

struct ns {
	char nsserver[DNS_MAXNAME];	/* NS name */
	int nslen;			/* length of NS */
        int ns_type;                    /* set if it's a delegation */
#define NS_TYPE_DELEGATE        0x1
#define NS_TYPE_HINT            0x2

};

struct srv {
	u_int16_t priority;		/* SRV 16 bit priority */
	u_int16_t weight;		/* 16 bit weight */
	u_int16_t port;			/* 16 bit port */
	char target[DNS_MAXNAME];	/* SRV target name */
	int targetlen;			/* SRV target name length */
};

struct sshfp {
	u_int8_t algorithm;		/* SSHFP algorithm */
	u_int8_t fptype;		/* SSHFP fingerprint type */
	char fingerprint[DNS_MAXNAME];  /* fingerprint */
	int fplen;			/* fingerprint length */
};

struct tlsa {
	u_int8_t usage;			/* TLSA usage */
	u_int8_t selector;		/* TLSA selector */
	u_int8_t matchtype;		/* TLSA matching type */
	char data[DNS_MAXNAME];  	/* TLSA data */
	int datalen;			/* data length */
};

struct naptr {
	u_int16_t order;		/* NAPTR 16 bit order */
	u_int16_t preference;		/* 16 bit preference */
	char flags[DNS_MAXNAME];	/* flags 255 bytes */
	int flagslen;			/* flags length */
	char services[DNS_MAXNAME];	/* services */
	int serviceslen;		/* services length */
	char regexp[DNS_MAXNAME];	/* regexp */
	int regexplen;			/* regexp len */
	char replacement[DNS_MAXNAME];	/* replacement this is a domain */
	int replacementlen;
};

struct cname {
        char cname[DNS_MAXNAME];                /* CNAME RR */
        int cnamelen;                           /* len of CNAME */
};

struct ptr {
        char ptr[DNS_MAXNAME];                  /* PTR RR */
        int ptrlen;                             /* len of PTR */
};

struct txt {
        char txt[1024];                  	/* TXT string */
        int txtlen;                             /* len of TXT */
};

struct hinfo {
	char cpu[255];
	int cpulen;
	char os[255];
	int oslen;
};

struct rp {
	char mbox[DNS_MAXNAME];
	int mboxlen;
	char txt[DNS_MAXNAME];
	int txtlen;
};

struct caa {
	uint8_t flags;
	char tag[DNS_MAXNAME];
	int taglen;
	char value[1024];	/* something reasonable, could be 65000! */
	int valuelen;
};

struct a {
        in_addr_t a;      /* IP addresses */
};

struct aaaa {
        struct in6_addr aaaa;     /* IPv6 addresses */
};

struct zonemd {
	uint32_t	serial;		/* reflects SOA serial */
	uint8_t 	scheme;		/* usually SIMPLE SCHEME */
#define ZONEMD_SIMPLE	1
	uint8_t		algorithm;	/* algorithm used for hash */
#define ZONEMD_SHA384	1
#define ZONEMD_SHA512	2		/* probably not ever used */
	char		hash[4096];	/* the hash itself */
	uint16_t	hashlen;	/* the length of the hash used */
};	

	

struct sreply {
	int so;			/* socket */
	char *buf;		/* question packet */
	int len;		/* question packet length */
	struct question *q;	/* struct question */
	struct sockaddr *sa;	/* struct sockaddr of question */
	int salen;		/* length of struct sockaddr */
	struct rbtree *rbt1;	/* first resolved domain */
	struct rbtree *rbt2;	/* CNAME to second resolved domain */
	u_int8_t region;	/* region of question */
	int istcp;		/* when set it's tcp */
	int wildcard;		/* wildcarding boolean */
	char *replybuf;		/* reply buffer */
};


/* ddd command socket */

#define SOCKPATH	"/var/run/delphinusdnsd.sock"
struct dddcomm {
	int command;
	union {
		pid_t rpid;
	} ret;
};


typedef struct {
	size_t size;
	char *data;
} ddDBT;

struct node {
        RB_ENTRY(node) rbentry;		/* the node entry */
	char domainname[DNS_MAXNAME + 1]; /* domain name key name */
        int len;			/* length of domain name */
	char *data;			/* data it points to */
	size_t datalen;			/* the length of the data */
};


extern int domaincmp(struct node *e1, struct node *e2);

RB_HEAD(domaintree, node);
RB_GENERATE_STATIC(domaintree, node, rbentry, domaincmp)
typedef struct __dddb {
	int (*put)(struct __dddb *, ddDBT *, ddDBT *);
	int (*get)(struct __dddb *, ddDBT *, ddDBT *);
	int (*close)(struct __dddb *);
	int (*remove)(struct __dddb *, ddDBT *);
	size_t offset;
	size_t size;
	char *nodes;
	struct domaintree head;
} ddDB; 


struct rr {
	void *rdata;
	uint16_t rdlen;
	time_t changed;
	uint32_t zonenumber;
	TAILQ_ENTRY(rr) entries;
};

struct rrset {
	u_int16_t rrtype;
	u_int32_t ttl;
	time_t created;
	TAILQ_ENTRY(rrset) entries;
	TAILQ_HEAD(rrh, rr) rr_head;
};


struct rbtree {
	char zone[DNS_MAXNAME];
	int zonelen;
	char humanname[DNS_MAXNAME + 1];
	uint32_t flags;			/* 32 bit flags */

#define RBT_DNSSEC		0x1 /* this rbtree entry is of type DNSSEC */
#define RBT_APEX		0x2 /* this rbtree entry is the apex of zone */
#define RBT_GLUE		0x4 /* this rbtree entry is GLUE data */
#define RBT_CACHE		0x8 /* this rbtree lies in the cache */

	TAILQ_HEAD(rrseth, rrset) rrset_head;
};

struct rrtab {
        char *name;
        u_int16_t type;
	u_int16_t internal_type;
};


struct cfg {
	int udp[DEFAULT_SOCKET];	/* udp sockets */
	int tcp[DEFAULT_SOCKET];	/* tcp socket */
	int axfr[DEFAULT_SOCKET];	/* axfr udp socket */
	char *ident[DEFAULT_SOCKET];	/* identification of interface */
	struct sockaddr_storage ss[DEFAULT_SOCKET];	/* some addr storage */
	struct my_imsg {
		int imsg_fds[2];
	} my_imsg[100];
#define MY_IMSG_CORTEX		0
#define MY_IMSG_AXFR 		1
#define MY_IMSG_TCP		2
#define MY_IMSG_PARSER		3
#define MY_IMSG_RAXFR		4
#define MY_IMSG_PRIMARY		5
#define MY_IMSG_UNIXCONTROL	6
#define MY_IMSG_UDP		7
#define MY_IMSG_FORWARD		8
#define MY_IMSG_MAX		9
	int raw[2];
#define RAW_IPSOCKET 0
#define RAW_IP6SOCKET 1
	u_short port;
	int sockcount;			/* set sockets */
	int nth;
	pid_t pid;
	char *shptr;			/* shared memory 1 */
	size_t shptrsize;
	char *shptr2;			/* shared memory 2 */
	size_t shptr2size;
	char *shptr3;			/* shared memory 3 */
	size_t shptr3size;
	char *shptr_pq;			/* shared memory 4 */
	size_t shptr_pqsize;
	ddDB *db;			/* database */
};

	
ddDB * dddbopen(void);
int dddbget(ddDB *, ddDBT *, ddDBT *);
int dddbput(ddDB *, ddDBT *, ddDBT *);
int dddbclose(ddDB *);

#define DDDB_NOTFOUND 	(-1)

int parse_file(ddDB *db, char *, uint32_t);
ddDB * opendatabase(ddDB *);

/* dig stuff */

#define BIND_FORMAT 	0x1
#define INDENT_FORMAT 	0x2
#define ZONE_FORMAT		0x4
#define DNSSEC_FORMAT	0x8
#define TCP_FORMAT		0x10

/* mzone */
struct mzone_dest {
	struct sockaddr_storage notifydest;
	SLIST_ENTRY(mzone_dest) entries;
	int	notified;
	char	requestmac[32];
	char 	*tsigkey;
	u_int16_t port;
};
	
struct mzone {
	SLIST_ENTRY(mzone)	mzone_entry;
	char 			*zonename;
	int			zonenamelen;
	char			*humanname;
	struct sockaddr_storage	notifybind;
	SLIST_HEAD(,mzone_dest)	dest;
};

#ifndef DEFAULT_RZONE_DIR
#define DELPHINUS_RZONE_PATH	"/var/delphinusdnsd/replicant"
#else
#define DELPHINUS_RZONE_PATH	DEFAULT_RZONE_DIR
#endif

struct soa_constraints {
	uint32_t refresh;
	uint32_t retry;
	uint32_t expire;
};

struct rzone {
	SLIST_ENTRY(rzone)	rzone_entry;
	int 			active;
	char 			*zonename;
	char			*zone;
	int			zonelen;
	u_int16_t		primaryport;
	char			*primary;
	struct sockaddr_storage storage;
	char			*tsigkey;
	char 			*filename;
	struct soa		soa;
	struct soa_constraints	constraints;
	uint32_t		bytelimit;
};

struct raxfr_logic {
	int rrtype;
	int dnssec;
	int (*raxfr)(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
};

struct scache {
	u_char *payload;
	u_char *estart;
	u_char *end;
	uint16_t rdlen;
	char *name;
	int namelen;
	uint32_t dnsttl;
	uint16_t rrtype;
	int authentic;
	struct imsgbuf *imsgbuf;
	struct imsgbuf *bimsgbuf;
	struct cfg *cfg;
};

struct cache_logic {
	int rrtype;
	int dnssec;
	int (*cacheit)(struct scache *);
};

/* reply logic */

struct reply_logic {
	int rrtype;
	int type0;
	int buildtype;
#define BUILD_CNAME	1
#define BUILD_OTHER	2
	int (*reply)(struct sreply *, int *, ddDB *);
};


#ifndef MIN
#define	MIN(a,b)	(((a) < (b))?(a):(b))
#endif

struct pq_imsg {
	union {
		struct {
			int read;		/* 4 */
			int len;		/* 8 */
			char pad[10];		/* 18 */
			struct parsequestion pq;
		} s;

		char pad[1024];
	} u;
#define pqi_pq u.s.pq
};

struct sf_imsg {
	union {
		struct {
			int read;		/* 4 */
			int len;		/* 8 */
			char pad[10];		/* 18 */
			struct sforward sf;	/* 924 */
		} s;

		char pad[1024];
	} u;
#define sfi_sf u.s.sf
};

struct rr_imsg {
	union {
		struct  {
			int read;				/* 4 */
			int len;				/* 8 */
			char pad[12];				/* 20 */

			struct {
				char name[DNS_MAXNAME + 1];	/* 256 */
				int namelen;			/* 260 */
				uint16_t rrtype;		/* 262 */
				uint32_t ttl;			/* 266 */
				int authentic;	
				
				uint16_t buflen;		

				char un[0];
			} rr;				
		} s;

		char pad[8192];
	} u;
#define rri_rr u.s.rr
}; /* end of struct rr_imsg */

struct pkt_imsg {
	union {
		struct {
			int read;
			int rc;
			int istcp;
			int cache;
			int tsigcheck;
			struct tsig tsig;
			char mac[5 * 32];
			int buflen;
			char buf[0];			
		} s;

		char buf[16384];
	} u;
#define pkt_s u.s
};							/* 16384 */


#define	SHAREDMEMSIZE	400
#define SHAREDMEMSIZE3	200
#define SM_NOLOCK	0x4e4c4e4b			/* NLCK */

struct walkentry {
        struct rbtree *rbt;
        TAILQ_ENTRY(walkentry) walk_entry;
};

struct zoneentry {
        char name[DNS_MAXNAME];
        int namelen;
        char *humanname;
	uint32_t zonenumber;
        TAILQ_HEAD(, walkentry) walkhead;
        RB_ENTRY(zoneentry) zone_entry;
};

RB_HEAD(zonetree, zoneentry);
RB_PROTOTYPE(zonetree, zoneentry, zone_entry, zonecmp);

extern int zonecmp(struct zoneentry *, struct zoneentry *);
	
struct pnentry {
	char name[DNS_MAXNAME];
	int namelen;
	char *humanname;
	int wildcard;
        RB_ENTRY(pnentry) pn_entry;
};

RB_HEAD(pntree, pnentry);
RB_PROTOTYPE(pntree, pnentry, pn_entry, pncmp);

extern int pncmp(struct pnentry *, struct pnentry *);

#define MAX_RECORDS_IN_RRSET		100		/* from sign.c */

struct querycache {
	int bufsize;
	struct {
		char digest[MD5_DIGEST_LENGTH];
		uint16_t crc;
		char *request;
		int requestlen;
		char *reply;
		int replylen;
	} cs[10];
	int cp;
	int cm;
};

#define QC_REQUESTSIZE	384
#define QC_REPLYSIZE	65536
	
#endif /* _DB_H */
