/* 
 * Copyright (c) 2002-2020 Peter J. Philipp
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

#ifndef _DNS_H
#define _DNS_H


/* RFC 1035 - page 26 */

struct dns_header {
	u_int16_t	id;			/* ID of header */
	u_int16_t query;
	u_int16_t question;			/* # of question entries */
	u_int16_t answer;			/* # of answer RR's */
	u_int16_t nsrr;				/* # of NS RR's */
	u_int16_t additional;			/* # additional RR's */
};

struct dns_hints {
	int proto;
	u_int16_t id;
	u_int16_t query;
	u_int16_t question;
	u_int16_t answer;
	u_int16_t nsrr;
	u_int16_t additional;
};

/*
 * resource record structure 
 * RFC 1035 - page 9
 */

struct dns_rr {
	char *name;				/* name of zone */
	char *question;				/* pointer to question */
	u_int16_t type;				/* type of RR */
	u_int16_t class;			/* class of reply */
	u_int32_t ttl;				/* ttl of record */
	u_int16_t rdlen;			/* length of record */
	char *rdata;				/* data of record */
};

/*
 * EDNS0 OPT RR, based on dns_rr 
 * RFC 6891 - page 7
 */

struct dns_optrr {
	char name[1];				/* always 0 */
	u_int16_t type;				/* must be 41 */
	u_int16_t class;			/* UDP payload size (4096) */
	u_int32_t ttl;				/* extended RCODE */
	u_int16_t rdlen;			/* length of all RDATA */
	char rdata[0];				/* attribute, value pairs */
}__attribute__((packed));

/*
 * TSIG RR, based on dns_rr 
 * RFC 2845  and RFC 4635 (for SHA-256)
 */

struct dns_tsigrr {
	u_int64_t timefudge;			/* time (48 bits) and fudge */
	u_int16_t macsize;			/* MAC size == 32 */
	char mac[32];				/* SHA-256 MAC */
	/* empty unless error == badtime */
} __attribute__((packed));

/* RFC 1035 - page 28 */
struct dns_question_hdr {
	char *name;
	char *original_name;
	u_int namelen;
	u_int16_t qtype;
	u_int16_t qclass;
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

#define DNS_TYPE_AAAA	28 		/* quad A - RFC 3596 */

#define DNS_TYPE_SRV	33		/* RFC 2782, page 8 */
#define DNS_TYPE_NAPTR	35		/* RFC 2915, page 3 */
#define DNS_TYPE_OPT	41		/* RFC 6891, page 7 */
#define DNS_TYPE_DS	43		/* RFC 4034, section 5 */
#define DNS_TYPE_SSHFP	44		/* RFC 4255 */
#define DNS_TYPE_RRSIG	46		/* RFC 4034, section 3 */
#define DNS_TYPE_NSEC	47		/* RFC 4034, section 4 */
#define DNS_TYPE_DNSKEY	48		/* RFC 4034, section 2 */

#define DNS_TYPE_NSEC3	50		/* RFC 5155, section 3 */
#define DNS_TYPE_NSEC3PARAM	51	/* RFC 5155, section 4 */
#define DNS_TYPE_TLSA	52		/* RFC 6698, section 7.1 */

#define DNS_TYPE_TKEY	249		/* RFC 2930 */
#define DNS_TYPE_TSIG	250		/* RFC 2845, page 3 */
#define DNS_TYPE_IXFR	251		/* RFC 1995, page 2  */
#define DNS_TYPE_AXFR	252		/* RFC 5936, page 10 */
#define DNS_TYPE_ANY	255
#define DNS_TYPE_CAA	257		/* RFC 8659 */

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
	char tsigmac[32];			/* 562 */
	int tsigmaclen;				/* 566 */
	u_int64_t tsig_timefudge;		/* 574 */
	u_int16_t tsigorigid;			/* 576 */
	int tsigoffset;				/* 580 */
};

#define DEFAULT_TSIG_FUDGE	300

struct question {
	struct dns_question_hdr *hdr;
	char *converted_name;
	u_int16_t edns0len;
	u_int8_t ednsversion;
	int rawsocket;
	int aa;
	int rd;
	int dnssecok;
	int badvers;
	int notify;
	struct tsig tsig;
};

struct parsequestion {
	char name[DNS_MAXNAME];
	char original_name[DNS_MAXNAME];
	u_int namelen;
	u_int16_t qtype;
	u_int16_t qclass;
	char converted_name[DNS_MAXNAME + 1];
	u_int16_t edns0len;
	u_int8_t ednsversion;
	int rd;
	int dnssecok;
	int notify;
	int badvers;
	struct tsig tsig;
	int rc;		/* return code */
#define PARSE_RETURN_ACK	0
#define PARSE_RETURN_NAK	1
#define PARSE_RETURN_MALFORMED	2
#define PARSE_RETURN_NOQUESTION 3
#define PARSE_RETURN_NOTAQUESTION 4
#define PARSE_RETURN_NOTAUTH	5
#define PARSE_RETURN_NOTAREPLY	6	/* fwdpq */
	pid_t pid;	/* originating pid */
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

	char mac[32];			/* 906 */
};

	

#endif /* DNS_H */
