/*
 * Copyright (c) 2002-2024 Peter J. Philipp <pbug44@delphinusdns.org>
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

#ifndef _DDD_DNS_H
#define _DDD_DNS_H


/* RFC 1035 - page 26 */

struct dns_header {
	uint16_t	id;			/* ID of header */
	uint16_t query;
	uint16_t question;			/* # of question entries */
	uint16_t answer;			/* # of answer RR's */
	uint16_t nsrr;				/* # of NS RR's */
	uint16_t additional;			/* # additional RR's */
};

struct dns_hints {
	int proto;
	uint16_t id;
	uint16_t query;
	uint16_t question;
	uint16_t answer;
	uint16_t nsrr;
	uint16_t additional;
};

/*
 * resource record structure 
 * RFC 1035 - page 9
 */

struct dns_rr {
	char *name;				/* name of zone */
	char *question;				/* pointer to question */
	uint16_t type;				/* type of RR */
	uint16_t class;			/* class of reply */
	uint32_t ttl;				/* ttl of record */
	uint16_t rdlen;			/* length of record */
	char *rdata;				/* data of record */
};

/*
 * EDNS0 OPT RR, based on dns_rr 
 * RFC 6891 - page 7
 */

struct dns_optrr {
	char name[1];				/* always 0 */
	uint16_t type;				/* must be 41 */
	uint16_t class;			/* UDP payload size (4096) */
	uint32_t ttl;				/* extended RCODE */
	uint16_t rdlen;			/* length of all RDATA */
	char rdata[0];				/* attribute, value pairs */
}__attribute__((packed));

#define DNS_OPT_CODE_COOKIE		10		/* RFC 7873 */
#define DNS_OPT_CODE_TCP_KEEPALIVE	11		/* RFC 7828 */
#define DNS_OPT_CODE_PADDING		12		/* RFC 7830 */

#define DDD_TCP_TIMEOUT			4200		/* TCP_KEEPALIVE */

/*
 * TSIG RR, based on dns_rr 
 * RFC 2845  and RFC 4635 (for SHA-256)
 */

#define DNS_HMAC_SHA256_SIZE	32		/* hmac-sha256 256 bits */

struct dns_tsigrr {
	uint64_t timefudge;			/* time (48 bits) and fudge */
	uint16_t macsize;			/* MAC size == 32 */
	char mac[DNS_HMAC_SHA256_SIZE];		/* SHA-256 MAC */
	/* empty unless error == badtime */
} __attribute__((packed));

/* RFC 1035 - page 28 */
struct dns_question_hdr {
	char *name;
	char *original_name;
	u_int namelen;
	uint16_t qtype;
	uint16_t qclass;
};

/* 
 * flags RFC 1035, page 26
 */

#define DNS_REPLY	0x8000	/* if set response if not set query */
#define DNS_UPDATE	0x2800	/* a DNS Update RFC 2136 */
#define DNS_NOTIFY	0x2000	/* a NOTIFY query RFC 1996 */
#define DNS_SREQ	0x1000	/* if set a server status request (STATUS) */
#define DNS_INV		0x800	/* if set an inverse query */
#define DNS_AUTH	0x400	/* Authoritative Answer (AA) in replies */
#define DNS_TRUNC	0x200	/* Truncated (TC) */
#define DNS_RECURSE	0x100	/* if set Recursion Desired (RD) */
#define DNS_RECAVAIL	0x80	/* if set Recursion Available (RA) */
#define DNS_AD		0x20	/* if set, Authentic Data (AD), RFC 2535 */
#define DNS_CD		0x10	/* if set, Checking Disabled (CD), RFC 2535 */
/* lower 4 bits of RCODE's 0x00 through 0x0F, below */
#define DNS_NOTZONE	0xA	/* RCODE - Not within zone section RFC 2136 */
#define DNS_NOTAUTH	0x9	/* RCODE - Not Authenticated RFC 2845 */
#define DNS_NXRRSET	0x8	/* RCODE - RRSET should exist, but doesn't */
#define DNS_YXRRSET	0x7	/* RCODE - RRSET should not exist, but does */
#define DNS_YXDOMAIN	0x6	/* RCODE - Should not exist but does RFC 2136 */
#define	DNS_REFUSED	0x5	/* RCODE - Refused */
#define DNS_NOTIMPL	0x4	/* RCODE - Not Implemented */
#define DNS_NAMEERR	0x3	/* RCODE - Name Error, NXDOMAIN */
#define DNS_SERVFAIL	0x2	/* RCODE - Server Failure */
#define DNS_FORMATERR	0x1	/* RCODE - Format Error */
#define DNS_NOERR	0x0	/* RCODE - No error */

/* Extended RCODE's (part of EDNS0 RFC 2671) */

#define DNS_BADALG	0x15	/* RCODE (21) BADALG RFC 2930 sect. 2.6 */
#define DNS_BADNAME	0x14	/* RCODE (20) BADNAME RFC 2930 sect. 2.6 */
#define DNS_BADMODE	0x13	/* RCODE (19) BADMODE RFC 2930 sect. 2.6 */

/* When DNS_NOTAUTH, add a TSIG header with the following error codes */

#define DNS_BADTIME	0x12	/* RCODE (18) BADTIME RFC 2845 p. 3 */
#define DNS_BADKEY	0x11	/* RCODE (17) BADKEY RFC 2845 p. 3 */
#define DNS_BADSIG	0x10	/* RCODE (16) BADSIG RFC 2845 p. 3 */
#define DNS_BADVERS	0x10	/* RCODE (16) BADVERS RFC 2671 p. 6 */


/* END of Extended RCODE's */

/*
 * macros to set flags (must be converted to network byte order after)
 */

#define SET_DNS_REPLY(x)		((x)->query |= (DNS_REPLY))
#define SET_DNS_QUERY(x)		((x)->query &= ~(DNS_REPLY)) 
#define SET_DNS_NOTIFY(x)		((x)->query |= (DNS_NOTIFY))
#define SET_DNS_STATUS_REQ(x)		((x)->query |= (DNS_SREQ))
#define SET_DNS_INVERSE_QUERY(x)	((x)->query |= (DNS_INV))
#define SET_DNS_AUTHORITATIVE(x)	((x)->query |= (DNS_AUTH))
#define SET_DNS_TRUNCATION(x)		((x)->query |= (DNS_TRUNC))
#define SET_DNS_RECURSION(x)		((x)->query |= (DNS_RECURSE))
#define SET_DNS_RECURSION_AVAIL(x)	((x)->query |= (DNS_RECAVAIL))
#define SET_DNS_AUTHENTIC_DATA(x)	((x)->query |= (DNS_AD))
#define SET_DNS_CHECKING_DISABLED(x)	((x)->query |= (DNS_CD))
#define SET_DNS_RCODE_REFUSED(x)	((x)->query |= (DNS_REFUSED))
#define SET_DNS_RCODE_NOTIMPL(x)	((x)->query |= (DNS_NOTIMPL))
#define SET_DNS_RCODE_NAMEERR(x)	((x)->query |= (DNS_NAMEERR))
#define SET_DNS_RCODE_SERVFAIL(x)	((x)->query |= (DNS_SERVFAIL))
#define SET_DNS_RCODE_FORMATERR(x)	((x)->query |= (DNS_FORMATERR))
#define SET_DNS_RCODE_NOERR(x)		((x)->query |= (DNS_NOERR))
#define SET_DNS_RCODE_NOTAUTH(x)	((x)->query |= (DNS_NOTAUTH))

#define UNSET_DNS_NOTIFY(x)		((x)->query &= ~(DNS_NOTIFY))
#define UNSET_DNS_STATUS_REQ(x)		((x)->query &= ~(DNS_SREQ))
#define UNSET_DNS_INVERSE_QUERY(x)	((x)->query &= ~(DNS_INV))
#define UNSET_DNS_AUTHORITATIVE(x)	((x)->query &= ~(DNS_AUTH))
#define UNSET_DNS_TRUNCATION(x)		((x)->query &= ~(DNS_TRUNC))
#define UNSET_DNS_RECURSION(x)		((x)->query &= ~(DNS_RECURSE))
#define UNSET_DNS_RECURSION_AVAIL(x)	((x)->query &= ~(DNS_RECAVAIL))
#define UNSET_DNS_AUTHENTIC_DATA(x)	((x)->query &= ~(DNS_AD))
#define UNSET_DNS_CHECKING_DISABLED(x)	((x)->query &= ~(DNS_CD))
#define UNSET_DNS_RCODE_REFUSED(x)	((x)->query &= ~(DNS_REFUSED))
#define UNSET_DNS_RCODE_NOTIMPL(x)	((x)->query &= ~(DNS_NOTIMPL))
#define UNSET_DNS_RCODE_NAMEERR(x)	((x)->query &= ~(DNS_NAMEERR))
#define UNSET_DNS_RCODE_SERVFAIL(x)	((x)->query &= ~(DNS_SERVFAIL))
#define UNSET_DNS_RCODE_FORMATERR(x)	((x)->query &= ~(DNS_FORMATERR))
#define UNSET_DNS_RCODE_NOERR(x)	((x)->query &= ~(DNS_NOERR))
#define UNSET_DNS_RCODE_NOTAUTH(x)	((x)->query &= ~(DNS_NOTAUTH))

/* DNSSEC/EDNS0 options RFC 3225 */

#define DNSSEC_OK	0x8000

#define SET_DNS_ERCODE_DNSSECOK(x)	((x)->ttl |= (DNSSEC_OK))
#define UNSET_DNS_ERCODE_DNSSECOK(x)	((x)->ttl &= ~(DNSSEC_OK))

/* DNS types - RFC 1035 page 12 */

#define DNS_TYPE_A	1		/* start of RFC 1035 */
#define DNS_TYPE_NS	2
#define DNS_TYPE_CNAME	5
#define DNS_TYPE_SOA	6
#define DNS_TYPE_PTR	12
#define DNS_TYPE_HINFO	13
#define DNS_TYPE_MX	15
#define DNS_TYPE_TXT	16		/* end of RFC 1035 */
#define DNS_TYPE_RP	17		/* RFC 1183 */

#define DNS_TYPE_AAAA	28 		/* RFC 3596 */
#define DNS_TYPE_LOC	29		/* RFC 1876 */

#define DNS_TYPE_SRV	33		/* RFC 2782, page 8 */
#define DNS_TYPE_NAPTR	35		/* RFC 2915, page 3 */
#define DNS_TYPE_KX	36		/* RFC 2230, page 8 */
#define DNS_TYPE_CERT	37		/* RFC 4398, section 2 */
#define DNS_TYPE_OPT	41		/* RFC 6891, page 7 */
#define DNS_TYPE_DS	43		/* RFC 4034, section 5 */
#define DNS_TYPE_SSHFP	44		/* RFC 4255 */
#define DNS_TYPE_IPSECKEY	45	/* RFC 4025, section 1 */
#define DNS_TYPE_RRSIG	46		/* RFC 4034, section 3 */
#define DNS_TYPE_NSEC	47		/* RFC 4034, section 4 */
#define DNS_TYPE_DNSKEY	48		/* RFC 4034, section 2 */

#define DNS_TYPE_NSEC3	50		/* RFC 5155, section 3 */
#define DNS_TYPE_NSEC3PARAM	51	/* RFC 5155, section 4 */
#define DNS_TYPE_TLSA		52	/* RFC 6698, section 7.1 */
#define DNS_TYPE_SMIMEA		53	/* RFC 8162 */

#define DNS_TYPE_CDS		59	/* RFC 7344, RFC 8078 */
#define DNS_TYPE_CDNSKEY	60	/* RFC 7344, RFC 8078 */
#define DNS_TYPE_OPENPGPKEY	61	/* RFC 7929 */

#define DNS_TYPE_ZONEMD	63		/* RFC 8976 */
#define DNS_TYPE_SVCB	64		/* RFC 9460, section 2 */
#define DNS_TYPE_HTTPS	65		/* RFC 9460, section 9 */

#define DNS_TYPE_EUI48	108		/* RFC 7043 */
#define DNS_TYPE_EUI64	109		/* RFC 7043 */

#define DNS_TYPE_TKEY	249		/* RFC 2930 */
#define DNS_TYPE_TSIG	250		/* RFC 2845, page 3 */
#define DNS_TYPE_IXFR	251		/* RFC 1995, page 2  */
#define DNS_TYPE_AXFR	252		/* RFC 5936, page 10 */
#define DNS_TYPE_ANY	255
#define DNS_TYPE_CAA	257		/* RFC 8659 */
#define DNS_TYPE_MAX	258		/* the highest RR in implementation */

const static struct typetable {
	char *type;		/* RR type */
	char *longdesc;		/* long description */
	int rfc;		/* RFC number */
	int number;		/* RR number */
} TT[] = {
	{ "A", "A RR for IPv4 IP address", 1035, DNS_TYPE_A},
	{ "NS", "NS RR for domain servers", 1035, DNS_TYPE_NS},
	{ "CNAME", "CNAME canonical name pointers", 1035, DNS_TYPE_CNAME},
	{ "SOA", "SOA RR for Start of Authority records", 1035, DNS_TYPE_SOA},
	{ "PTR", "PTR RR for reverse delegation pointers", 1035, DNS_TYPE_PTR},
	{ "MX", "MX RR for Mail Exchange records", 1035, DNS_TYPE_MX},
	{ "TXT", "TXT RR for text records", 1035, DNS_TYPE_TXT},
	{ "AAAA", "AAAA RR, quad A records for IPv6", 3596, DNS_TYPE_AAAA},
	{ "ANY", "ANY shows many RR's in a set", 1035, DNS_TYPE_ANY },
	{ "SRV", "SRV service records for SIP, etc ...",  2782, DNS_TYPE_SRV },
	{ "SSHFP", "SSHFP SSH fingerprint records", 4255, DNS_TYPE_SSHFP },
	{ "NAPTR", "NAPTR NA Pointers for telephony", 2915, DNS_TYPE_NAPTR },
	{ "RRSIG", "RRSIG DNSSEC signature record", 4034, DNS_TYPE_RRSIG },
	{ "DNSKEY", "DNSKEY RR public key for DNSSEC", 4034, DNS_TYPE_DNSKEY },
	{ "NSEC", "NSEC negative denial of existance", 4034, DNS_TYPE_NSEC },
	{ "DS", "DS RR for delegating DNSSEC zones", 4034, DNS_TYPE_DS },
	{ "NSEC3", "NSEC3 hashed denial of existance", 5155, DNS_TYPE_NSEC3 },
	{ "NSEC3PARAM", "NSEC3PARAM for the APEX", 5155, DNS_TYPE_NSEC3PARAM },
	{ "TLSA", "TLSA RR, for TLS Authentic data", 6698, DNS_TYPE_TLSA },
	{ "RP", "RP RR, Responsible person", 1035, DNS_TYPE_RP },
	{ "HINFO", "HINFO RR, for Host Information", 1035, DNS_TYPE_HINFO },
	{ "CAA", "CAA Certificate Authority Auth", 8659, DNS_TYPE_CAA },
	{ "ZONEMD", "ZONEMD crypto hashed zones", 8976, DNS_TYPE_ZONEMD },
	{ "CDS", "CDS for dynamic DS RR's on the fly", 8078, DNS_TYPE_CDS },
	{ "CDNSKEY", "CDNSKEY also works dynamically", 8078, DNS_TYPE_CDNSKEY },
	{ "LOC", "LOC for displaying earth location data", 1876, DNS_TYPE_LOC },
	{ "EUI48", "EUI48 RR, for 48 bit MAC addresses", 7043, DNS_TYPE_EUI48 },
	{ "EUI64", "EUI64 RR, for 64 bit MAC addresses", 7043, DNS_TYPE_EUI64 },
	{ "SVCB", "SVCB RR", 9460, DNS_TYPE_SVCB },
	{ "HTTPS", "HTTPS grants HTTPS on other ports", 9460, DNS_TYPE_HTTPS },
	{ "KX", "KX RR, for Key eXchange records", 2230, DNS_TYPE_KX },
	{ "IPSECKEY", "IPSECKEY for IPSEC records", 4025, DNS_TYPE_IPSECKEY },
	{ "CERT", "CERT for certificates of many kinds", 4398, DNS_TYPE_CERT },
	{ NULL, NULL, 0}
};

/* DNS types 0xff00 -> 0xfffe (private use) RFC 5395, page 8 */

#define DNS_TYPE_BALANCE 	0xfffe		/* split horizon dns */
#define DNS_TYPE_DELEGATE 	0xfffd		/* ns delegations */
#define DNS_TYPE_HINT		0xfffc		/* root hint */



/* DNS CLASSES - RFC 1035 page 13 */

#define DNS_CLASS_IN	1		/* internet */
#define DNS_CLASS_CH	3		/* chaos */
#define DNS_CLASS_HS	4		/* hesiod */

#define DNS_CLASS_NONE	254		/* none class RFC 2136 */
#define DNS_CLASS_ANY	255		/* any class */

/* limits */

#define DNS_MAXLABEL	63
#define DNS_MAXNAME	255
#define DNS_MAXUDP	512
#define DNS_MAXTCP	65535

/* SSHFP fingerprint sizes */

#define DNS_SSHFP_SIZE_SHA1	20	/* RFC 4255 */
#define DNS_SSHFP_SIZE_SHA256	32 	/* RFC 6594 */

/* TLSA fingerprint sizes */

#define DNS_TLSA_SIZE_SHA256	32	/* RFC 6698 */
#define DNS_TLSA_SIZE_SHA512	64	/* RFC 6698 */

struct tsig {
	int have_tsig;				/* 4 */
	int tsigverified;			/* 8 */
	int tsigerrorcode;			/* 12 */
	char tsigalg[DNS_MAXNAME];		/* 267 */
	int tsigalglen;				/* 271 */
	char tsigkey[DNS_MAXNAME];		/* 526 */
	int tsigkeylen;				/* 530 */
	char tsigmac[DNS_HMAC_SHA256_SIZE];	/* 562 */
	int tsigmaclen;				/* 566 */
	uint64_t tsig_timefudge;		/* 574 */
	uint16_t tsigorigid;			/* 576 */
	int tsigoffset;				/* 580 */
};

#define DEFAULT_TSIG_FUDGE	300

struct dns_cookie {
	int have_cookie;
	int error;
	char clientcookie[8];
	uint8_t version;
	uint32_t timestamp;
	char servercookie[32];
	uint8_t servercookie_len;
};

struct question {
	struct dns_question_hdr *hdr;
	char *converted_name;
	uint16_t edns0len;
	uint8_t ednsversion;
	int rawsocket;
	int aa;
	int rd;
	int dnssecok;
	int badvers;
	int notify;
	struct tsig tsig;
	struct dns_cookie cookie;
	int tcpkeepalive;
};

struct parsequestion {
	char name[DNS_MAXNAME];
	char original_name[DNS_MAXNAME];
	u_int namelen;
	uint16_t qtype;
	uint16_t qclass;
	char converted_name[DNS_MAXNAME + 1];
	uint16_t edns0len;
	uint8_t ednsversion;
	int rd;
	int dnssecok;
	int tcpkeepalive;
	int notify;
	int badvers;
	struct tsig tsig;
	struct dns_cookie cookie;
	int rc;		/* return code */
#define PARSE_RETURN_ACK	0
#define PARSE_RETURN_NAK	1
#define PARSE_RETURN_MALFORMED	2
#define PARSE_RETURN_NOQUESTION 3
#define PARSE_RETURN_NOTAQUESTION 4
#define PARSE_RETURN_NOTAUTH	5
#define PARSE_RETURN_NOTAREPLY	6	/* fwdpq */
	pid_t pid;	/* originating pid */
#define PQ_PAD			16
	char pad[PQ_PAD];
};
	
struct sforward {
	int family;			/* 4 */
	time_t gotit;			/* 12 */

	struct sockaddr_in from4;	/* 28 */
	struct sockaddr_in6 from6;	/* 56 */

	int oldsel;			/* 60 */
	uint16_t rport;			/* 62 */
	char buf[512];			/* 574 */
	int buflen;			/* 578 */
	struct dns_header header;	/* 592 */
	uint16_t type;			/* 594 */
	uint16_t class;			/* 596 */
	uint16_t edns0len;		/* 598 */
	int dnssecok;			/* 602 */

	int havemac;			/* 606 */
	char tsigname[256];		/* 862 */
	int tsignamelen;		/* 866 */
	uint64_t tsigtimefudge;		/* 874 */

	char mac[DNS_HMAC_SHA256_SIZE];	/* 906 */
	uint8_t region;			/* 907 */
};

#define STRATEGY_SPRAY			0	/* all forwarders */
#define STRATEGY_SINGLE			1	/* one at a time */

	

#endif /* DNS_H */
