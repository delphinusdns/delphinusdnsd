/*
 * Copyright (c) 2005-2023 Peter J. Philipp <pjp@delphinusdns.org>
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

#if __NetBSD__
#include <machine/vmparam.h>
#elif __linux__
#define PAGE_SIZE DDD_PAGE_SIZE
#else
#include <machine/param.h>
#endif
#include <sys/types.h>
#include <limits.h>

#include "ddd-crypto.h"
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
#define IMSG_DUMP_CACHE		16	/* dump the forward cache */
#define IMSG_DUMP_CACHEREPLY	17	/* reply the dump of forward cache */
#define IMSG_DUMP_CACHEREPLYEOF	18	/* end of messages */
#define IMSG_FORWARD_TLS	19	/* forward a TLS packet XXX */

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
	uint16_t flags;
#define DNSKEY_ZONE_KEY			(1 << 7)
#define DNSKEY_SECURE_ENTRY		(1 << 15)
	uint8_t protocol;		/* must be 3 */
	uint8_t algorithm;		/* would be 5, RFC 3110 */
	char public_key[4096];
	uint16_t publickey_len;
};

struct cdnskey {
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;
	char public_key[4096];
	uint16_t publickey_len;
};

struct rrsig {
	uint16_t type_covered;
	uint8_t algorithm;	/* usually 5, RFC3110 */
	uint8_t labels;
	uint32_t original_ttl;
	uint32_t signature_expiration;
	uint32_t signature_inception;
	uint16_t key_tag;
	char signers_name[DNS_MAXNAME];
	uint8_t signame_len;
	char signature[4096];
	uint16_t signature_len;
	uint32_t ttl;		/* RFC 4034 section 3, the TTL value of ... */
	int used;		/* if this RRSIG is used at all */
	time_t created;		/* when this was added to the cache */
};

struct nsec {
	char next_domain_name[DNS_MAXNAME];
	uint8_t ndn_len;	/* next domain name length */
	char bitmap[8192];
	uint16_t bitmap_len;
};

struct nsec3 {
	uint8_t algorithm;
	uint8_t flags;
	uint16_t iterations;
	uint8_t saltlen;
	char salt[256];
	char next[DNS_MAXNAME];
	uint8_t nextlen;	/* next domain name length */
	char bitmap[8192];
	uint16_t bitmap_len;
};

struct nsec3param {
	uint8_t algorithm;
	uint8_t flags;
	uint16_t iterations;
	uint8_t saltlen;
	char salt[256];
};

struct ds {
	uint16_t key_tag;
	uint8_t algorithm;
	uint8_t digest_type;
	char digest[4096];
	uint16_t digestlen;
};

struct cds {
	uint16_t key_tag;
	uint8_t algorithm;
	uint8_t digest_type;
	char digest[4096];
	uint16_t digestlen;
};

struct soa {
	char nsserver[DNS_MAXNAME];
	uint8_t nsserver_len;
	char responsible_person[DNS_MAXNAME];
	uint8_t rp_len;
	uint32_t serial;
	uint32_t refresh;
	uint32_t retry;
	uint32_t expire;
	uint32_t minttl;
};

struct smx {
	uint16_t preference;		/* MX preference */
	char exchange[DNS_MAXNAME];	/* name of exchange server */
	int exchangelen;		/* length of exchange server name */
};

struct kx {
	uint16_t preference;		/* KX preference */
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
	uint16_t priority;		/* SRV 16 bit priority */
	uint16_t weight;		/* 16 bit weight */
	uint16_t port;			/* 16 bit port */
	char target[DNS_MAXNAME];	/* SRV target name */
	int targetlen;			/* SRV target name length */
};

struct sshfp {
	uint8_t algorithm;		/* SSHFP algorithm */
	uint8_t fptype;		/* SSHFP fingerprint type */
	char fingerprint[DNS_MAXNAME];  /* fingerprint */
	int fplen;			/* fingerprint length */
};

struct tlsa {
	uint8_t usage;			/* TLSA usage */
	uint8_t selector;		/* TLSA selector */
	uint8_t matchtype;		/* TLSA matching type */
	char data[DNS_MAXNAME];  	/* TLSA data */
	int datalen;			/* data length */
};

struct naptr {
	uint16_t order;		/* NAPTR 16 bit order */
	uint16_t preference;		/* 16 bit preference */
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
	char offsets[2048];			/* offsets of RR */
};

struct eui48 {
	uint8_t eui48[6];
};

struct eui64 {
	uint8_t eui64[8];
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

struct loc {
	uint8_t version;
	uint8_t size;
	uint8_t horiz_pre;
	uint8_t vert_pre;
	uint32_t latitude;
	uint32_t longitude;
	uint32_t altitude;
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


struct svcb {
	uint16_t	priority;		/* section 2.1 */
	char		target[DNS_MAXNAME];	/* <domain-name> */
	int		targetlen;
        char 		param[1024];            /* TXT string */
        int 		paramlen;               /* len of TXT */
	
};

struct https {
	uint16_t	priority;		/* mirrors svcb */
	char		target[DNS_MAXNAME];	/* <domain-name> */
	int		targetlen;
        char 		param[1024];            /* TXT string */
        int 		paramlen;               /* len of TXT */
	
};

struct ipseckey {
	uint8_t		precedence;		/* precedence */
	uint8_t		gwtype;			/* gateway type */
#define IPSECKEY_NOGATEWAY	0
#define IPSECKEY_IPV4		1
#define IPSECKEY_IPV6		2
#define	IPSECKEY_DOMAINNAME	3
	uint8_t		alg;			/* algorithm */
#define IPSECKEY_NOKEY		0
#define IPSECKEY_DSA		1
#define IPSECKEY_RSA		2
	union {
		in_addr_t ip4;			/* 4 byte IPv4 address */
		struct in6_addr ip6;		/* 16 byte IPv6 address */
		char dnsname[DNS_MAXNAME];	/* a dns name */
	} gateway;
	int dnsnamelen;
	char key[4096];				/* public key */
	int keylen;
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
	uint8_t region;	/* region of question */
	int istcp;		/* when set 1=tcp, 2=tls */
#define DDD_IS_UDP     0
#define DDD_IS_TCP     1
#define DDD_IS_TLS     2
	int wildcard;		/* wildcarding boolean */
	char *replybuf;		/* reply buffer */
	struct tls *ctx;	/* TLS context */
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
	uint16_t rrtype;
	uint32_t ttl;
	time_t created;
	TAILQ_ENTRY(rrset) entries;
	TAILQ_HEAD(rrh, rr) rr_head;
};

#define TTL_EXPIRE_RR	0
#define TTL_EXPIRE_ALL	1


struct rbtree {
	char zone[DNS_MAXNAME];
	int zonelen;
	char humanname[DNS_MAXNAME + 1];
	uint32_t flags;			/* 32 bit flags */

#define RBT_DNSSEC		0x1 /* this rbtree entry is of type DNSSEC */
#define RBT_APEX		0x2 /* this rbtree entry is the apex of zone */
#define RBT_GLUE		0x4 /* this rbtree entry is GLUE data */
#define RBT_CACHE		0x8 /* this rbtree lies in the cache */
#define RBT_WILDCARD		0x10 /* this rbtree is a wildcard */

	TAILQ_HEAD(rrseth, rrset) rrset_head;
};

struct rrtab {
        char *name;
        uint16_t type;
	uint16_t internal_type;
};


struct cfg {
	int udp[DEFAULT_SOCKET];	/* udp sockets */
	int tcp[DEFAULT_SOCKET];	/* tcp socket */
	int tls[DEFAULT_SOCKET];	/* tls socket */
	int axfr[DEFAULT_SOCKET];	/* axfr udp socket */
	char *ident[DEFAULT_SOCKET];	/* identification of interface */
	struct sockaddr_storage ss[DEFAULT_SOCKET];	/* some addr storage */
	struct tls *ctx;		/* the TLS context */
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
#define MY_IMSG_TLS		9
#define MY_IMSG_MAX		10
	int raw[2];
#define RAW_IPSOCKET 0
#define RAW_IP6SOCKET 1
	u_short port;
	int sockcount;			/* set sockets */
	int nth;
	pid_t pid;
	struct {
		char *shptr;			/* shared memory 1 */
		size_t shptrsize;
#define SM_FORWARD		0
#define SM_RESOURCE		1
#define SM_PACKET		2
#define SM_PARSEQUESTION 	3
#define SM_INCOMING		4
#define SM_MAX			5
	} shm[SM_MAX];
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
	uint16_t port;
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
	uint16_t		primaryport;
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
	int (*raxfr)(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
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
			int clen;		/* 12 */
			char pad[12];		/* 24 */
			struct parsequestion pq;
		} s;

		char pad[((2048 / PAGE_SIZE) + 1) * PAGE_SIZE];
	} u;
#define pqi_pq		u.s.pq
#define pqi_len		u.s.len
#define	pqi_clen	u.s.clen
	char guard[PAGE_SIZE];
};

struct sf_imsg {
	union {
		struct {
			int read;		/* 4 */
			int len;		/* 8 */
			int clen;		/* 12 */
			char pad[6];		/* 18 */
			struct sforward sf;	/* 924 */
		} s;

		char pad[((1024 / PAGE_SIZE) + 1) * PAGE_SIZE];
	} u;
#define sfi_sf u.s.sf
	char guard[PAGE_SIZE];
};

struct rr_imsg {
	union {
		struct  {
			int read;				/* 4 */
			int len;				/* 8 */
			int clen;				/* 12 */
			char pad[8];				/* 20 */

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

		char pad[((8192 / PAGE_SIZE) + 1) * PAGE_SIZE];
	} u;
#define rri_rr u.s.rr
	char guard[PAGE_SIZE];
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
			int bufclen;
			char buf[0];			
		} s;

		struct {
			int read;
			int buflen;
			int bufclen;
			int pad;
			char buf[0];
		} i;

		char buf[((71680 / PAGE_SIZE) + 1) * PAGE_SIZE];
	} u;
#define pkt_s u.s
	char guard[PAGE_SIZE];
};							/* variable */


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

/* querycache stuff below here */

struct cs {
	char digest[MD5_DIGEST_LENGTH];
	uint16_t crc;
	char *request;
	int requestlen;
	char *reply;
	int replylen;
	char *domainname;
	uint16_t type;
	uint16_t class;
}; 

struct csentry {
	TAILQ_ENTRY(csentry) entries;
	struct cs *cs;
};

struct csnode {
	RB_ENTRY(csnode) entry;
	TAILQ_HEAD(, csentry) head;
	int requestlen;
};

struct querycache {
	int bufsize;
	struct csnode tree;
	struct cs cs[10];
	int cp;
	int cm;
};

#define QC_REQUESTSIZE	384
#define QC_REPLYSIZE	65536
	
#endif /* _DB_H */
