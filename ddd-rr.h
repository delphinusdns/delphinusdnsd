/*
 * Copyright (c) 2005-2023 Peter J. Philipp <pbug44@delphinusdns.org>
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

#ifndef _DDD_RR_H
#define _DDD_RR_H

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


#define DIGEST_LENGTH		4096	/* crypt or digest length maximally */
#define BITMAP_LENGTH		8192	/* full bitmap covering 65536 bits */

/* A RR - 	RFC 1035 */
struct a {
        in_addr_t a;      		/* IP address */
};


/* AAAA RR - 	RFC 3596 */
struct aaaa {
        struct in6_addr aaaa;     	/* IPv6 address */
};


/* CAA RR -	RFC 6844 */
struct caa {
	uint8_t flags;			/* flags */
	char tag[DNS_MAXNAME];		/* tag dname */
	int taglen;			/* tag length */
	char value[1024];		/* value of certification authority */	
	int valuelen;			/* value length */
};


/* CDNSKEY RR -	RFC 7344 */
struct cdnskey {
	uint16_t flags;			/* flags */
	uint8_t protocol;		/* protocol */
	uint8_t algorithm;		/* algorithm */
	char public_key[DIGEST_LENGTH];	/* public key */
	uint16_t publickey_len;		/* public key length */
};

/* CDS RR -	RFC 7344 */
struct cds {
	uint16_t key_tag;		/* key tag */
	uint8_t algorithm;		/* algorithm */
	uint8_t digest_type;		/* digest type */
	char digest[DIGEST_LENGTH];	/* digest */
	uint16_t digestlen;		/* digest length */
};

/* CNAME RR -	RFC 1035 */
struct cname {
        char cname[DNS_MAXNAME];	/* canonical name  */
        int cnamelen;			/* length */
};

/* DNSKEY RR -	RFC 4034 */
struct dnskey {
	uint16_t flags;					/* flags */
#define DNSKEY_ZONE_KEY			(1 << 7)
#define DNSKEY_SECURE_ENTRY		(1 << 15)
	uint8_t protocol;				/* protocol */	
	uint8_t algorithm;				/* algorithm */
	char public_key[DIGEST_LENGTH];			/* pubkey */
	uint16_t publickey_len;				/* pubkey length */
};

/* DS RR -	RFC 4034 */
struct ds {
	uint16_t key_tag;		/* key tag */
	uint8_t algorithm;		/* algorithm */
	uint8_t digest_type;		/* digest type */
	char digest[DIGEST_LENGTH];	/* digest */
	uint16_t digestlen;		/* digest length */
};

/* EUI48 RR -	RFC 7043 */
struct eui48 {
	uint8_t eui48[6];		/* EUI48 MAC */
};

/* EUI64 RR -	RFC 7043 */
struct eui64 {
	uint8_t eui64[8];		/* EUI64 MAC */
};

/* HINFO RR -	RFC 1035 */
struct hinfo {
	char cpu[DNS_MAXNAME + 1];	/* CPU <character-string> */
	int cpulen;			/* CPU length */
	char os[DNS_MAXNAME + 1];	/* OS <character-string> */
	int oslen;			/* OS length */
};

/* HTTPS RR -		draft-ietf-dnsop-svcb-https-11 */
struct https {
	uint16_t	priority;		/* priority */
	char		target[DNS_MAXNAME];	/* target */
	int		targetlen;		/* target length */
        char 		param[1024];            /* txt string */
        int 		paramlen;               /* txt length */
	
};

/* IPSECKEY RR -	RFC 4025 */	
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
		in_addr_t ip4;			/* IPv4 address */
		struct in6_addr ip6;		/* IPv6 address */
		char dnsname[DNS_MAXNAME];	/* dnsname */
	} gateway;
	int dnsnamelen;				/* dnsname length */
	char key[DIGEST_LENGTH];		/* public key */
	int keylen;				/* key length */
};

/* KX RR -	RFC 2230 */
struct kx {
	uint16_t preference;			/* preference */
	char exchange[DNS_MAXNAME];		/* exchange server */
	int exchangelen;			/* length exchange server */
};
	

/* LOC RR -	RFC 1876 */
struct loc {
	uint8_t version;			/* version */
	uint8_t size;				/* size */
	uint8_t horiz_pre;			/* horizontal pre */
	uint8_t vert_pre;			/* vertical pre */
	uint32_t latitude;			/* latitude */
	uint32_t longitude;			/* longitude */
	uint32_t altitude;			/* altitude */
};

/* NAPTR RR -	RFC 3403 */
struct naptr {
	uint16_t order;				/* order */
	uint16_t preference;			/*  preference */
	char flags[DNS_MAXNAME];		/* flags */
	int flagslen;				/* flags length */
	char services[DNS_MAXNAME];		/* services */
	int serviceslen;			/* services length */
	char regexp[DNS_MAXNAME];		/* regexp */
	int regexplen;				/* regexp len */
	char replacement[DNS_MAXNAME];		/* replacement */
	int replacementlen;			/* replacement length */
};

/* NS RR -	RFC 1035 */
struct ns {
	char nsserver[DNS_MAXNAME];		/* nsname */
	int nslen;				/* nsname length */
        int ns_type;                    	/* delegation type */
#define NS_TYPE_DELEGATE        0x1
#define NS_TYPE_HINT            0x2
};


/* NSEC RR -	RFC 4034 */
struct nsec {
	char next[DNS_MAXNAME];			/* next name */
	uint8_t next_len;			/* next name length */
	char bitmap[8192];			/* full bitmap */
	uint16_t bitmap_len;			/* bitmap length */
};

/* NSEC3 RR -		RFC 5155 */
struct nsec3 {
	uint8_t algorithm;			/* algorithm */
	uint8_t flags;				/* flags */
	uint16_t iterations;			/* iterations */
	char salt[256];				/* salt */
	uint8_t saltlen;			/* salt length */
	char next[DNS_MAXNAME];			/* next hash */
	uint8_t nextlen;			/* next hash length */
	char bitmap[8192];			/* full bitmap */
	uint16_t bitmap_len;			/* bitmap length */
};

/* NSEC3PARAM RR -	RFC 5155 */
struct nsec3param {
	uint8_t algorithm;			/* algorithm */
	uint8_t flags;				/* flags */
	uint16_t iterations;			/* iterations */
	char salt[256];				/* salt */
	uint8_t saltlen;			/* salt length */
};

/* PTR RR -		RFC 1035 */
struct ptr {
        char ptr[DNS_MAXNAME];                  /* ptr name */
        int ptrlen;                             /* length of ptr name */
};

/* RP RR -		RFC 1035 */
struct rp {
	char mbox[DNS_MAXNAME];			/* mailbox */
	int mboxlen;				/* mailbox length */
	char txt[DNS_MAXNAME];			/* txt */
	int txtlen;				/* txt length */
};


/* RRSIG RR -		RFC 4034 */
struct rrsig {
	uint16_t type_covered;			/* type covered */
	uint8_t algorithm;			/* algorithm */
	uint8_t labels;				/* num labels */
	uint32_t original_ttl;			/* original ttl */
	uint32_t signature_expiration;		/* signature expire */
	uint32_t signature_inception;		/* signature incept */
	uint16_t key_tag;			/* key tag */
	char signers_name[DNS_MAXNAME];		/* signers name */
	uint8_t signame_len;			/* signers length */
	char signature[DIGEST_LENGTH];		/* signature */
	uint16_t signature_len;			/* signature length */
	uint32_t ttl;				/* ttl value */
	int used;				/* is this RRSIG used flag */
	time_t created;				/* when added to the cache */
};


/* SOA RR -		RFC 1035 */
struct soa {
	char nsserver[DNS_MAXNAME];		/* 1st nameserver */
	uint8_t nsserver_len;			/* nameserver length */
	char responsible_person[DNS_MAXNAME];	/* responsible email */
	uint8_t rp_len;				/* email length */
	uint32_t serial;			/* serial */
	uint32_t refresh;			/* refresh */
	uint32_t retry;				/* retry */
	uint32_t expire;			/* expire */
	uint32_t minttl;			/* minimum ttl */
};


/* MX RR -		RFC 1035 */
struct smx {
	uint16_t preference;			/* preference */
	char exchange[DNS_MAXNAME];		/* name of exchange */
	int exchangelen;			/* length of exchange */
};

/* SRV RR -		RFC 2782 */
struct srv {
	uint16_t priority;			/* priority */
	uint16_t weight;			/* weight */
	uint16_t port;				/* port */
	char target[DNS_MAXNAME];		/* target name */
	int targetlen;				/* target name length */
};


/* SSHFP RR -		RFC 4255 */
struct sshfp {
	uint8_t algorithm;			/* algorithm */
	char fingerprint[DNS_MAXNAME];  	/* fingerprint */
	uint8_t fptype;				/* fingerprint type */
	int fplen;				/* fingerprint length */
};


/* SVCB RR -		see HTTPS draft */
struct svcb {
	uint16_t	priority;		/* priority */
	char		target[DNS_MAXNAME];	/* target */
	int		targetlen;		/* target length */
        char 		param[1024];            /* TXT string */
        int 		paramlen;               /* len of TXT */
	
};

/* TLSA RR -		RFC 6698 */
struct tlsa {
	uint8_t usage;				/* usage */
	uint8_t selector;			/* selector */
	uint8_t matchtype;			/* matching type */
	char data[DNS_MAXNAME];  		/* data */
	int datalen;				/* data length */
};


/* TXT RR -		RFC 1035 */
struct txt {
        char txt[4096];                  	/* txt string */
        int txtlen;                      	/* length */
};


/* ZONEMD RR -		RFC 8976 */
struct zonemd {
	uint32_t	serial;			/* serial */
	uint8_t 	scheme;			/* scheme */
#define ZONEMD_SIMPLE	1
	uint8_t		algorithm;		/* algorithm */
#define ZONEMD_SHA384	1
#define ZONEMD_SHA512	2
	char		hash[DIGEST_LENGTH];	/* hash */
	uint16_t	hashlen;		/* length of hash */
};	


#endif /* _DDD_RR_H */
