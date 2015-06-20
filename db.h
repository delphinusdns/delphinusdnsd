/* 
 * Copyright (c) 2005-2014 Peter J. Philipp
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
#ifndef _DB_H
#define _DB_H

#define CONFFILE "/etc/delphinusdns.conf"
#define DEFAULT_SOCKET 64

#define ERR_DROP	0x1
#define ERR_NXDOMAIN	0x2
#define ERR_NOERROR	0x4

#define RECORD_COUNT	20
#define NEGATIVE_CACHE_TIME	600	/* DNS & Bind 3rd edition page 35 */

#define INTERNAL_TYPE_SOA	0
#define INTERNAL_TYPE_A		1
#define INTERNAL_TYPE_AAAA	2
#define INTERNAL_TYPE_MX	3
#define INTERNAL_TYPE_NS	4
#define INTERNAL_TYPE_CNAME	5
#define INTERNAL_TYPE_PTR	6
#define INTERNAL_TYPE_TXT	7
#define INTERNAL_TYPE_SPF	8
#define INTERNAL_TYPE_SRV	9
#define INTERNAL_TYPE_SSHFP	10
#define INTERNAL_TYPE_NAPTR	11
#define INTERNAL_TYPE_DNSKEY	12
#define INTERNAL_TYPE_DS	13
#define INTERNAL_TYPE_NSEC	14
#define INTERNAL_TYPE_RRSIG	15
#define INTERNAL_TYPE_MAX	16

/* db stuff */

struct dnskey {
	u_int16_t flags;
#define DNSKEY_ZONE_KEY			(1 << 7)
#define DNSKEY_SECURE_ENTRY		(1 << 15)
	u_int8_t protocol;		/* must be 3 */
	u_int8_t algorithm;		/* would be 5, RFC 3110 */
	char public_key[4096];
	u_int16_t publickey_len;
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
} __attribute__((packed)); 

struct nsec {
	char next_domain_name[DNS_MAXNAME];
	u_int8_t ndn_len;	/* next domain name length */
	u_int16_t bitmap[256];	/* XXX? */
} __attribute__((packed));

struct ds {
	u_int16_t key_tag;
	u_int8_t algorithm;
	u_int8_t digest_type;
	char digest[4096];
	u_int16_t digestlen;
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
} __attribute__((packed)); 

struct smx {
	u_int16_t preference;		/* MX preference */
	char exchange[DNS_MAXNAME];	/* name of exchange server */
	int exchangelen;		/* length of exchange server name */
} __attribute__((packed));

struct ns {
	char nsserver[DNS_MAXNAME];	/* NS name */
	int nslen;			/* length of NS */
} __attribute__((packed));

struct srv {
	u_int16_t priority;		/* SRV 16 bit priority */
	u_int16_t weight;		/* 16 bit weight */
	u_int16_t port;			/* 16 bit port */
	char target[DNS_MAXNAME];	/* SRV target name */
	int targetlen;			/* SRV target name length */
} __attribute__((packed));

struct sshfp {
	u_int8_t algorithm;		/* SSHFP algorithm */
	u_int8_t fptype;		/* SSHFP fingerprint type */
	char fingerprint[DNS_MAXNAME];  /* fingerprint */
	int fplen;			/* fingerprint length */
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
} __attribute__((packed));

struct domain {
	u_int16_t type;
	u_int32_t len;
	char zone[DNS_MAXNAME];		/* name of zone in dns name format */
	int zonelen;			/* length of zone, above */
	char zonename[DNS_MAXNAME + 1]; /* name of zone in human readable */
	u_int64_t flags;		/* flags of zone */
#define DOMAIN_HAVE_A 		0x1
#define DOMAIN_HAVE_SOA 	0x2
#define DOMAIN_HAVE_CNAME 	0x4
#define DOMAIN_HAVE_PTR	  	0x8
#define DOMAIN_HAVE_MX		0x10
#define DOMAIN_HAVE_AAAA	0x20
#define DOMAIN_HAVE_NS		0x40
#define DOMAIN_HAVE_TXT		0x80
#define DOMAIN_HAVE_SRV		0x100
#define DOMAIN_HAVE_SPF		0x200
#define DOMAIN_HAVE_SSHFP	0x400
#define DOMAIN_HAVE_NAPTR	0x800
#define DOMAIN_HAVE_DNSKEY	0x1000
#define DOMAIN_HAVE_DS		0x2000
#define DOMAIN_HAVE_NSEC	0x4000
#define DOMAIN_HAVE_RRSIG	0x8000
	u_int32_t ttl[INTERNAL_TYPE_MAX];	/* time to lives */
	time_t created;			/* time created, for dynamic zones */
} __attribute__((packed));

struct domain_generic {
	u_int16_t type;
	u_int32_t len;
} __attribute__((packed));

struct domain_soa {
	u_int16_t type;
	u_int32_t len;
	struct soa soa;			/* start of authority */
} __attribute__((packed));

struct domain_rrsig {
	u_int16_t type;
	u_int32_t len;
	struct rrsig rrsig[INTERNAL_TYPE_MAX];	/* rrsig RR */
	int rrsig_count;			/* RRSIG count */
} __attribute__((packed));


struct domain_a {
	u_int16_t type;
	u_int32_t len;
	in_addr_t a[RECORD_COUNT];	/* IP addresses */
	u_int8_t region[RECORD_COUNT];	/* region of IP address */
	int a_ptr;			/* pointer to last used address */
	int a_count;			/* IP address count (max 10) */
} __attribute__((packed));

struct domain_aaaa {
	u_int16_t type;
	u_int32_t len;
	struct in6_addr	aaaa[RECORD_COUNT];	/* IPv6 addresses */
	int aaaa_count;			/* IPv6 address count (max 10) */
	int aaaa_ptr;			/* pointer to last used IPv6 address */
} __attribute__((packed));

struct domain_mx {
	u_int16_t type;
	u_int32_t len;
	struct smx mx[RECORD_COUNT];	/* MX addresses */
	int mx_count;			/* MX address count, max 10 */
	int mx_ptr;			/* pointer to last used MX adddress */
} __attribute__((packed));

struct domain_ns {
	u_int16_t type;
	u_int32_t len;
	struct ns ns[RECORD_COUNT];	/* NS resource records (max 10) */
	int ns_count;			/* count of NS records, (max 10) */
	int ns_ptr;			/* pointer to last used NS address */
	int ns_type;			/* set if it's a delegation */
#define NS_TYPE_DELEGATE	0x1
#define NS_TYPE_HINT		0x2
} __attribute__((packed));

struct domain_cname {
	u_int16_t type;
	u_int32_t len;
	char cname[DNS_MAXNAME];		/* CNAME RR */
	int cnamelen;				/* len of CNAME */
} __attribute__((packed));

struct domain_ptr {
	u_int16_t type;
	u_int32_t len;
	char ptr[DNS_MAXNAME];			/* PTR RR */
	int ptrlen;				/* len of PTR */
} __attribute__((packed));

struct domain_txt {
	u_int16_t type;
	u_int32_t len;
	char txt[DNS_MAXNAME];			/* TXT string */
	int txtlen;				/* len of TXT */
} __attribute__((packed));

struct domain_spf {
	u_int16_t type;
	u_int32_t len;
	char spf[DNS_MAXNAME];			/* SPF string */
	int spflen;				/* len of SPF */
} __attribute__((packed));

struct domain_srv {
	u_int16_t type;
	u_int32_t len;
	struct srv srv[RECORD_COUNT];		/* SRV resource record */
	int srv_count;				/* count of SRV RR */
} __attribute__((packed));

struct domain_sshfp {
	u_int16_t type;
	u_int32_t len;
	struct sshfp sshfp[RECORD_COUNT];	/* SSHFP resource record */
	int sshfp_count;			/* SSHFP RR count */
} __attribute__((packed));

struct domain_naptr {
	u_int16_t type;
	u_int32_t len;
	struct naptr naptr[RECORD_COUNT];	/* NAPTR RR, eek 20K! */
	int naptr_count;
} __attribute__((packed));

struct domain_dnskey {
	u_int16_t type;
	u_int32_t len;
	struct dnskey dnskey[RECORD_COUNT];	/* DNSKEY RR */
	int dnskey_count;			/* count of DNSKEY */
} __attribute__((packed));

struct domain_nsec {
	u_int16_t type;
	u_int32_t len;
	struct nsec nsec;			/* NSEC RR */
} __attribute__((packed));

struct domain_ds {
	u_int16_t type;
	u_int32_t len;
	struct ds ds;				/* DS RR */
} __attribute__((packed));


struct sreply {
	int so;			/* socket */
	char *buf;		/* question packet */
	int len;		/* question packet length */
	struct question *q;	/* struct question */
	struct sockaddr *sa;	/* struct sockaddr of question */
	int salen;		/* length of struct sockaddr */
	struct domain *sd1;	/* first resolved domain */
	struct domain *sd2;	/* CNAME to second resolved domain */
	u_int8_t region;	/* region of question */
	int istcp;		/* when set it's tcp */
	int wildcard;		/* wildcarding boolean */
	struct recurses *sr;	/* recurses struct for raw sockets */
	char *replybuf;		/* reply buffer */
};

struct srecurseheader {
	int af;					/* address family */
	int proto;				/* protocol UDP/TCP */
	struct sockaddr_storage source;		/* source + port */
	struct sockaddr_storage dest;		/* dest + port */
	int len;				/* length of question */
	char buf[512];				/* question buffer */
};


SLIST_HEAD(listhead2, recurses) recurseshead;

struct recurses {
	char query[512];		/* the query we received */
	int len;			/* length of query */

	int isfake;			/* received or faked */
	int launched;			/* is launched */
	int replied;			/* we replied to this question */
	int packetcount;		/* packet count of requests */
        int af;                                 /* address family */
        int proto;                              /* protocol UDP/TCP */
        struct sockaddr_storage source;         /* source + port */
        struct sockaddr_storage dest;           /* dest + port */

	time_t received;		/* received request time */
	time_t sent_last_query;		/* the last time we did a lookup */
	
	char upperlower[32];		/* uppercase / lowercase bitmap */
	int so; 			/* the socket we did a lookup with */
	u_short port;			/* port used on outgoing */
	u_int16_t id;			/* last id used */

	/* the below get loaded from the database upon each lookup */
	in_addr_t a[RECORD_COUNT];	/* IPv4 addresses of nameservers */
	int a_count;			/* IPv4 address count */
	int a_ptr;			/* pointer to last used address */
	struct in6_addr aaaa[RECORD_COUNT]; /* IPv6 addresses of nameservers */
	int aaaa_count;			/* IPv6 address count */
	int aaaa_ptr;			/* pointer to last used IPv6 address */

	/* the below is our indicator which part of the lookup we're at */

	u_char *lookrecord;		/* what zone lookup is it from */
	int indicator;			/* indicator of ns lookup */
	int authoritative;		/* last reply was authoritative, type */
	int hascallback;		/* some request has callback don't remove */

	struct question *question;	/* question struct */
	SLIST_ENTRY(recurses) recurses_entry;
	struct recurses *callback;	/* callback */
} *sr, *sr1, *sr2;
	
struct logging {
	int active;
	char *hostname;
	int bind;
	char *loghost;
	struct sockaddr_storage loghost2;
	char *logport;
	u_int16_t logport2;
	char *logpasswd;
};

struct cfg {
	int udp[DEFAULT_SOCKET];	/* udp sockets */
	int tcp[DEFAULT_SOCKET];	/* tcp socket */
	int axfr[DEFAULT_SOCKET];	/* axfr udp socket */
	char *ident[DEFAULT_SOCKET];	/* identification of interface */
	int recurse;			/* recurse socket */
	int log;			/* logging socket */
	int sockcount;			/* set sockets */
	DB *db;				/* database */
};
	
	
int parse_file(DB *db, char *);
DB * opendatabase(DB *);


#endif /* _DB_H */
