/* 
 * Copyright (c) 2005-2019 Peter J. Philipp
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
 * $Id: ddd-db.h,v 1.31 2019/12/11 16:55:01 pjp Exp $
 */

#ifndef _DB_H
#define _DB_H

#include <sys/types.h>
#include <limits.h>

#include <openssl/hmac.h>
#include "ddd-config.h"

#ifndef DEFAULT_CONFFILE
#define CONFFILE "/etc/delphinusdns/delphinusdns.conf"
#else
#define CONFFILE DEFAULT_CONFFILE
#endif

#define DEFAULT_SOCKET 64

#define PARSEFILE_FLAG_NOSOCKET 0x1


#define IMSG_HELLO_MESSAGE  0		/* hello the master process a few */
#define IMSG_SPREAD_MESSAGE 1		/* spread a record to all childs */
#define IMSG_XFR_MESSAGE    2		/* forward message to axfr proc */
#define IMSG_XFRFD_MESSAGE  3		/* forward message fd to axfr proc */
#define IMSG_PARSE_MESSAGE  4		/* pass message to pledge parser */
#define IMSG_PARSEREPLY_MESSAGE 5	/* return message from pledge parser */
#define IMSG_SHUTDOWN_MESSAGE 6		/* shut the server down */
#define IMSG_RELOAD_MESSAGE 7		/* reload/restart the server */
#define IMSG_PARSEAUTH_MESSAGE	8	/* parse message with auth required */
#define	IMSG_NOTIFY_MESSAGE	9	/* notify our replicant engine */

#define ERR_DROP	0x1
#define ERR_NXDOMAIN	0x2
#define ERR_NOERROR	0x4
#define ERR_REFUSED	0x8
#define	ERR_NODATA	0x10
#define ERR_DELEGATE	0x20

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
	u_int32_t ttl;
} __attribute__((packed)); 

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
	u_int32_t ttl;
	int used;		/* if this RRSIG is used at all */
} __attribute__((packed)); 

#if 0
struct rrsig {
	struct internal_rrsig internal[3];
#define	RRSIG_RRSET	0
#define RRSIG_DNSKEY	1
#define RRSIG_DS	2
} __attribute__((packed)); 
#endif

struct nsec {
	char next_domain_name[DNS_MAXNAME];
	u_int8_t ndn_len;	/* next domain name length */
	char bitmap[8192];
	u_int16_t bitmap_len;
	u_int32_t ttl;
} __attribute__((packed));

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
	u_int32_t ttl;
} __attribute__((packed));

struct nsec3param {
	u_int8_t algorithm;
	u_int8_t flags;
	u_int16_t iterations;
	u_int8_t saltlen;
	char salt[256];
	u_int32_t ttl;
} __attribute__((packed));

struct ds {
	u_int16_t key_tag;
	u_int8_t algorithm;
	u_int8_t digest_type;
	char digest[4096];
	u_int16_t digestlen;
	u_int32_t ttl;
} __attribute__((packed)); 


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
	u_int32_t ttl;
} __attribute__((packed)); 

struct smx {
	u_int16_t preference;		/* MX preference */
	char exchange[DNS_MAXNAME];	/* name of exchange server */
	int exchangelen;		/* length of exchange server name */
	u_int32_t ttl;
} __attribute__((packed));

struct ns {
	char nsserver[DNS_MAXNAME];	/* NS name */
	int nslen;			/* length of NS */
        int ns_type;                    /* set if it's a delegation */
#define NS_TYPE_DELEGATE        0x1
#define NS_TYPE_HINT            0x2
	u_int32_t ttl;

} __attribute__((packed));

struct srv {
	u_int16_t priority;		/* SRV 16 bit priority */
	u_int16_t weight;		/* 16 bit weight */
	u_int16_t port;			/* 16 bit port */
	char target[DNS_MAXNAME];	/* SRV target name */
	int targetlen;			/* SRV target name length */
	u_int32_t ttl;
} __attribute__((packed));

struct sshfp {
	u_int8_t algorithm;		/* SSHFP algorithm */
	u_int8_t fptype;		/* SSHFP fingerprint type */
	char fingerprint[DNS_MAXNAME];  /* fingerprint */
	int fplen;			/* fingerprint length */
	u_int32_t ttl;
} __attribute__((packed));

struct tlsa {
	u_int8_t usage;			/* TLSA usage */
	u_int8_t selector;		/* TLSA selector */
	u_int8_t matchtype;		/* TLSA matching type */
	char data[DNS_MAXNAME];  	/* TLSA data */
	int datalen;			/* data length */
	u_int32_t ttl;
} __attribute__((packed));

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
	u_int32_t ttl;
} __attribute__((packed));

struct cname {
        char cname[DNS_MAXNAME];                /* CNAME RR */
        int cnamelen;                           /* len of CNAME */
	u_int32_t ttl;
} __attribute__((packed));

struct ptr {
        char ptr[DNS_MAXNAME];                  /* PTR RR */
        int ptrlen;                             /* len of PTR */
	u_int32_t ttl;
} __attribute__((packed));

struct txt {
        char txt[1024];                  	/* TXT string */
        int txtlen;                             /* len of TXT */
	u_int32_t ttl;
} __attribute__((packed));

struct a {
        in_addr_t a;      /* IP addresses */
	u_int32_t ttl;
} __attribute__((packed));

struct aaaa {
        struct in6_addr aaaa;     /* IPv6 addresses */
	u_int32_t ttl;
} __attribute__((packed));



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
	struct recurses *sr;	/* recurses struct for raw sockets */
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
	u_int32_t ttl;
	time_t changed;
	TAILQ_ENTRY(rr) entries;
};

struct rrset {
	u_int16_t rrtype;
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


	TAILQ_HEAD(, rrset) rrset_head;
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
	struct my_imsg {
		int imsg_fds[2];
	} my_imsg[100];
#define MY_IMSG_MASTER	0
#define MY_IMSG_AXFR 	1
#define MY_IMSG_TCP	2
#define MY_IMSG_PARSER	3
#define MY_IMSG_RAXFR	4
#define MY_IMSG_MAX	5
	int recurse;			/* recurse socket */
	int sockcount;			/* set sockets */
	int nth;
	pid_t pid;
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
} *mz, *mz0;

#ifndef DEFAULT_RZONE_DIR
#define DELPHINUS_RZONE_PATH	"/etc/delphinusdns/replicant"
#else
#define DELPHINUS_RZONE_PATH	DEFAULT_RZONE_DIR
#endif

struct rzone {
	SLIST_ENTRY(rzone)	rzone_entry;
	int 			active;
	char 			*zonename;
	char			*zone;
	int			zonelen;
	u_int16_t		masterport;
	char			*master;
	struct sockaddr_storage storage;
	char			*tsigkey;
	char 			*filename;
	struct	soa		soa;
} *rz, *rz0;

struct raxfr_logic {
	int rrtype;
	int dnssec;
	int (*raxfr)(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
};

#endif /* _DB_H */
