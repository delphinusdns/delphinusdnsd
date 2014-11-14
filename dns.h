/* 
 * Copyright (c) 2002-2014 Peter J. Philipp
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

/* RFC 1035 - page 28 */
struct dns_question_hdr {
	char *name;
	u_int namelen;
	u_int16_t qtype;
	u_int16_t qclass;
};



/* 
 * flags RFC 1035, page 26
 */

#define DNS_REPLY	0x8000	/* if set response if not set query */
#define DNS_NOTIFY	0x2000	/* a NOTIFY query RFC 1996 */
#define DNS_SREQ	0x1000	/* if set a server status request (STATUS) */
#define DNS_INV		0x800	/* if set an inverse query */
#define DNS_AUTH	0x400	/* Authoritative Answer (AA) in replies */
#define DNS_TRUNC	0x200	/* Truncated (TC) */
#define DNS_RECURSE	0x100	/* if set Recursion Desired (RD) */
#define DNS_RECAVAIL	0x80	/* if set Recursion Available (RA) */
#define DNS_BADTIME	0x12	/* RCODE (18) BADTIME RFC 2845 p. 3 */
#define DNS_BADKEY	0x11	/* RCODE (17) BADKEY RFC 2845 p. 3 */
#define DNS_BADSIG	0x10	/* RCODE (16) BADSIG RFC 2845 p. 3 */
#define	DNS_REFUSED	0x5	/* RCODE - Refused */
#define DNS_NOTIMPL	0x4	/* RCODE - Not Implemented */
#define DNS_NAMEERR	0x3	/* RCODE - Name Error, NXDOMAIN */
#define DNS_SERVFAIL	0x2	/* RCODE - Server Failure */
#define DNS_FORMATERR	0x1	/* RCODE - Format Error */
#define DNS_NOERR	0x0	/* RCODE - No error */

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
#define SET_DNS_RCODE_REFUSED(x)	((x)->query |= (DNS_REFUSED))
#define SET_DNS_RCODE_NOTIMPL(x)	((x)->query |= (DNS_NOTIMPL))
#define SET_DNS_RCODE_NAMEERR(x)	((x)->query |= (DNS_NAMEERR))
#define SET_DNS_RCODE_SERVFAIL(x)	((x)->query |= (DNS_SERVFAIL))
#define SET_DNS_RCODE_FORMATERR(x)	((x)->query |= (DNS_FORMATERR))
#define SET_DNS_RCODE_NOERR(x)		((x)->query |= (DNS_NOERR))

#define UNSET_DNS_NOTIFY(x)		((x)->query &= ~(DNS_NOTIFY))
#define UNSET_DNS_STATUS_REQ(x)		((x)->query &= ~(DNS_SREQ))
#define UNSET_DNS_INVERSE_QUERY(x)	((x)->query &= ~(DNS_INV))
#define UNSET_DNS_AUTHORITATIVE(x)	((x)->query &= ~(DNS_AUTH))
#define UNSET_DNS_TRUNCATION(x)		((x)->query &= ~(DNS_TRUNC))
#define UNSET_DNS_RECURSION(x)		((x)->query &= ~(DNS_RECURSE))
#define UNSET_DNS_RECURSION_AVAIL(x)	((x)->query &= ~(DNS_RECAVAIL))
#define UNSET_DNS_RCODE_REFUSED(x)	((x)->query &= ~(DNS_REFUSED))
#define UNSET_DNS_RCODE_NOTIMPL(x)	((x)->query &= ~(DNS_NOTIMPL))
#define UNSET_DNS_RCODE_NAMEERR(x)	((x)->query &= ~(DNS_NAMEERR))
#define UNSET_DNS_RCODE_SERVFAIL(x)	((x)->query &= ~(DNS_SERVFAIL))
#define UNSET_DNS_RCODE_FORMATERR(x)	((x)->query &= ~(DNS_FORMATERR))
#define UNSET_DNS_RCODE_NOERR(x)	((x)->query &= ~(DNS_NOERR))

/* DNSSEC/EDNS0 options RFC 3225 */

#define DNSSEC_OK	0x8000

#define SET_DNS_ERCODE_DNSSECOK(x)	((x)->ttl |= (DNSSEC_OK))
#define UNSET_DNS_ERCODE_DNSSECOK(x)	((x)->ttl &= ~(DNSSEC_OK))

/* DNS types - RFC 1035 page 12 */

#define DNS_TYPE_A	1
#define DNS_TYPE_NS	2
#define DNS_TYPE_CNAME	5
#define DNS_TYPE_SOA	6
#define DNS_TYPE_PTR	12
#define DNS_TYPE_MX	15
#define DNS_TYPE_TXT	16

#define DNS_TYPE_SRV	33		/* RFC 2782, page 8 */
#define DNS_TYPE_NAPTR	35		/* RFC 2915, page 3 */
#define DNS_TYPE_OPT	41		/* RFC 6891, page 7 */
#define DNS_TYPE_SSHFP	44		/* RFC 4255 */

#define DNS_TYPE_SPF	99		/* RFC 4408 */

#define DNS_TYPE_TSIG	250		/* RFC 2845, page 3 */
#define DNS_TYPE_IXFR	251		/* RFC 1995, page 2  */
#define DNS_TYPE_AXFR	252		/* RFC 5936, page 10 */
#define DNS_TYPE_ANY	255

/* DNS types 0xff00 -> 0xfffe (private use) RFC 5395, page 8 */

#define DNS_TYPE_BALANCE 	0xfffe		/* split horizon dns */
#define DNS_TYPE_DELEGATE 	0xfffd		/* ns delegations */
#define DNS_TYPE_HINT		0xfffc		/* root hint */

/* quad A - RFC 3596 */
#define DNS_TYPE_AAAA	28


/* DNS CLASSES - RFC 1035 page 13 */

#define DNS_CLASS_IN	1		/* internet */
#define DNS_CLASS_CH	3		/* chaos */
#define DNS_CLASS_HS	4		/* hesiod */

#define DNS_CLASS_ANY	255		/* any class */

/* limits */

#define DNS_MAXLABEL	63
#define DNS_MAXNAME	255
#define DNS_MAXUDP	512

/* SSHFP fingerprint sizes */

#define DNS_SSHFP_SIZE_SHA1	20	/* RFC 4255 */
#define DNS_SSHFP_SIZE_SHA256	32 	/* RFC 6594 */


struct question {
	struct dns_question_hdr *hdr;
	char *converted_name;
	int edns0len;
	int dnssecok;
};

#endif /* DNS_H */
