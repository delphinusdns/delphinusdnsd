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

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>

#ifdef __linux__
#include <grp.h>
#define __USE_BSD 1
#include <endian.h>
#include <bsd/stdlib.h>
#include <bsd/string.h>
#include <bsd/sys/queue.h>
#define __unused
#include <bsd/sys/tree.h>
#include <bsd/sys/endian.h>
#else /* not linux */
#include <sys/queue.h>
#include <sys/tree.h>
#endif /* __linux__ */

#ifndef NTOHS
#include "endian.h"
#endif

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "ddd-dns.h"
#include "ddd-db.h"

/* prototypes */

extern void 	pack(char *, char *, int);
extern void 	pack32(char *, uint32_t);
extern void 	pack16(char *, uint16_t);
extern void 	pack8(char *, uint8_t);
extern uint32_t unpack32(char *);
extern uint16_t unpack16(char *);
extern void 	unpack(char *, char *, int);

extern int     		checklabel(ddDB *, struct rbtree *, struct rbtree *, struct question *);
extern int		additional_wildcard(char *, int, struct rbtree *, char *, int, int, int *, ddDB *);
extern int 		additional_nsec3(char *, int, int, struct rbtree *, char *, int, int, int *, int);
extern int 		additional_a(char *, int, struct rbtree *, char *, int, int, int *);
extern int 		additional_aaaa(char *, int, struct rbtree *, char *, int, int, int *);
extern int 		additional_mx(char *, int, struct rbtree *, char *, int, int, int *);
extern int 		additional_ds(char *, int, struct rbtree *, char *, int, int, int *);
extern int 		additional_ptr(char *, int, struct rbtree *, char *, int, int, int *);
extern int 		additional_opt(struct question *, char *, int, int, struct sockaddr *, socklen_t);
extern int 		additional_tsig(struct question *, char *, int, int, int, int, HMAC_CTX *, uint16_t);
extern int 		additional_rrsig(char *, int, int, struct rbtree *, char *, int, int, int *, int);
extern int 		additional_nsec(char *, int, int, struct rbtree *, char *, int, int, int);
extern struct question 	*build_fake_question(char *, int, uint16_t, char *, int);
extern int 		compress_label(u_char *, int, int);
extern void 		dolog(int, char *, ...);
extern int 		free_question(struct question *);
extern int 		get_record_size(ddDB *, char *, int);

extern char *		dns_label(char *, int *);
extern char * hash_name(char *name, int len, struct nsec3param *n3p);
extern struct rbtree * find_rrset(ddDB *db, char *name, int len);
extern struct rbtree * find_rrsetwild(ddDB *db, char *name, int len);
extern struct rrset * find_rr(struct rbtree *rbt, uint16_t rrtype);
extern int display_rr(struct rrset *rrset);
extern int rotate_rr(struct rrset *rrset);
extern char * find_next_closer_nsec3(char *zonename, int zonelen, char *hashname);
extern struct rbtree * find_nsec3_cover_next_closer(char *name, int namelen, struct rbtree *, ddDB *db);
extern struct rbtree * find_nsec3_match_closest(char *name, int namelen, struct rbtree *, ddDB *db);
extern struct rbtree * find_nsec3_wildcard_closest(char *name, int namelen, struct rbtree *, ddDB *db);
extern struct rbtree * find_nsec3_match_qname(char *name, int namelen, struct rbtree *, ddDB *db);
extern struct rbtree * find_nsec3_match_qname_wild(char *, int, struct rbtree *, ddDB *);
extern struct rbtree * find_closest_encloser(ddDB *db, char *name, int namelen);
extern struct rbtree *		get_soa(ddDB *, struct question *);
extern struct rbtree *		get_ns(ddDB *, struct rbtree *, int *);
extern struct rbtree *		Lookup_zone(ddDB *, char *, uint16_t, uint16_t, int);
extern int 			dn_contains(char *, int, char *, int);
extern struct zoneentry *	zone_findzone(struct rbtree *);
extern struct rbtree * find_closest_encloser_nsec3(char *, int, struct rbtree *, ddDB *);


uint16_t 	create_anyreply(struct sreply *, char *, int, int, int, uint32_t, uint);
int		reply_zonemd(struct sreply *, int *, ddDB *);
int		reply_caa(struct sreply *, int *, ddDB *);
int		reply_hinfo(struct sreply *, int *, ddDB *);
int		reply_rp(struct sreply *, int *, ddDB *);
int		reply_generic(struct sreply *, int *, ddDB *);
int 		reply_a(struct sreply *, int *, ddDB *);
int		reply_nsec3(struct sreply *, int *, ddDB *);
int		reply_nsec3param(struct sreply *, int *, ddDB *);
int		reply_nsec(struct sreply *, int *,  ddDB *);
int		reply_dnskey(struct sreply *, int *, ddDB *);
int		reply_cdnskey(struct sreply *, int *, ddDB *);
int		reply_ds(struct sreply *, int *, ddDB *);
int		reply_cds(struct sreply *, int *, ddDB *);
int		reply_rrsig(struct sreply *, int *, ddDB *);
int 		reply_aaaa(struct sreply *, int *, ddDB *);
int 		reply_mx(struct sreply *, int *, ddDB *);
int 		reply_ns(struct sreply *, int *, ddDB *);
int 		reply_notimpl(struct sreply *, int *, ddDB *);
int 		reply_nxdomain(struct sreply *, int *, ddDB *);
int 		reply_noerror(struct sreply *, int *, ddDB *);
int		reply_badvers(struct sreply *, int *, ddDB *);
int		reply_nodata(struct sreply *, int *, ddDB *);
int 		reply_soa(struct sreply *, int *, ddDB *);
int 		reply_ptr(struct sreply *, int *, ddDB *);
int 		reply_txt(struct sreply *, int *, ddDB *);
int 		reply_version(struct sreply *, int *, ddDB *);
int 		reply_srv(struct sreply *, int *, ddDB *);
int 		reply_naptr(struct sreply *, int *, ddDB *);
int 		reply_sshfp(struct sreply *, int *, ddDB *);
int		reply_tlsa(struct sreply *, int *, ddDB *);
int		reply_loc(struct sreply *, int *, ddDB *);
int 		reply_cname(struct sreply *, int *, ddDB *);
int 		reply_any(struct sreply *, int *, ddDB *);
int 		reply_refused(struct sreply *, int *, ddDB *, int);
int 		reply_fmterror(struct sreply *, int *, ddDB *);
int 		reply_notauth(struct sreply *, int *, ddDB *);
int		reply_notify(struct sreply *, int *, ddDB *);
struct rbtree * find_nsec(char *name, int namelen, struct rbtree *, ddDB *db);
int 		nsec_comp(const void *a, const void *b);
int 		count_dots(char *name);
char * 		base32hex_encode(u_char *input, int len);
void 		set_reply_flags(struct rbtree *, struct dns_header *, struct question *);
int		reply_sendpacket(char *, uint16_t, struct sreply *, int *);
int		reply_generic_dnskey(struct sreply *, int *, ddDB *, uint16_t);
int		reply_generic_ds(struct sreply *, int *, ddDB *, uint16_t);
static uint32_t determine_zone(struct rbtree *);

extern int debug, verbose, dnssec, tcpanyonly;
extern char *versionstring;
extern uint8_t vslen;
extern u_int max_udp_payload;



/* 
 * REPLY_A() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_a(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	uint16_t outlen = 0;
	int a_count;

	struct answer {
		char name[2];
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
		in_addr_t rdata;		/* 16 */
	} __attribute__((packed));

	struct answer *answer;

	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;

	struct rbtree *rbt = sreply->rbt1;
	struct rbtree *authority;
	struct rrset *rrset = NULL;
	struct rr *rrp;
	
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	uint16_t rollback;
	time_t now;
	uint32_t zonenumberx;

	zonenumberx = determine_zone(rbt);

	now = time(NULL);

	if ((rrset = find_rr(rbt, DNS_TYPE_A)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}
	
	if (!istcp && q->edns0len > 512)
		replysize = MIN(q->edns0len, max_udp_payload);


	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
	memset((char *)&odh->query, 0, sizeof(uint16_t));

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	set_reply_flags(rbt, odh, q);

	odh->question = htons(1);
	odh->answer = htons(0);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	a_count = 0;

	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		if (rrp->zonenumber != zonenumberx)
			continue;
		/*
		 * answer->name is a pointer to the request (0xc00c) 
		 */

		answer->name[0] = 0xc0;				/* 1 byte */
		answer->name[1] = 0x0c;				/* 2 bytes */
		answer->type = q->hdr->qtype;			/* 4 bytes */	
		answer->class = q->hdr->qclass;			/* 6 bytes */

		if (q->aa)
			answer->ttl = htonl(rrset->ttl); 		/* 10 b */
		else
			answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

		answer->rdlength = htons(sizeof(in_addr_t));	/* 12 bytes */

		memcpy((char *)&answer->rdata, 
			(char *)&((struct a *)rrp->rdata)->a, 
			sizeof(in_addr_t));			/* 16 bytes */

		a_count++;
		outlen += 16;

		/* can we afford to write another header? if no truncate */
		if (outlen + 16 > replysize) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}


		/* set new offset for answer */
		answer = (struct answer *)&reply[outlen];
	} 

	odh->answer = htons(a_count);

	/* Add RRSIG reply_a */
	if (dnssec && q->dnssecok && (rbt->flags & RBT_DNSSEC)) {
		int tmplen = 0;
		int origlen = outlen;
		int retcount;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_A, rbt, reply, replysize, outlen, &retcount, q->aa);
	
		if (tmplen == 0) {
			/* we're forwarding and had no RRSIG return with -1 */
			if (q->aa != 1)
				return -1;

			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->answer = htons(a_count + retcount);	

		
		if (rbt->flags & RBT_WILDCARD) {
			authority = get_soa(db, q);
			if (authority == NULL) {
				if (q->aa != 1)
					return -1;

				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}
			tmplen = additional_wildcard(q->hdr->name, q->hdr->namelen, authority, reply, replysize, outlen, &retcount, db);
			if (tmplen != 0) {
				outlen = tmplen;
				odh->nsrr = htons(retcount);	
			}
		}
			

	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	retlen = reply_sendpacket(reply, outlen, sreply, sretlen);

	/*
	 * update order XXX 
	 */

	rotate_rr(rrset);
	
	return (retlen);
}

/* 
 * REPLY_NSEC3PARAM() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_nsec3param(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	uint16_t outlen = 0;
	int a_count;

	struct answer {
		char name[2];
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
		uint8_t algorithm;
		uint8_t flags;
		uint16_t iterations;
		uint8_t saltlen;
	} __attribute__((packed));

	struct answer *answer;

	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;

	struct rbtree *rbt = sreply->rbt1;
	struct rbtree *authority;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	uint16_t rollback;
	int saltlen;
	
	time_t now;

	now = time(NULL);

	if ((rrset = find_rr(rbt, DNS_TYPE_NSEC3PARAM)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}
	
	if (!istcp && q->edns0len > 512)
		replysize = MIN(q->edns0len, max_udp_payload);

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
	memset((char *)&odh->query, 0, sizeof(uint16_t));

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	set_reply_flags(rbt, odh, q);

	odh->question = htons(1);
	odh->answer = htons(1);
	odh->nsrr = 0;
	odh->additional = 0;


	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	a_count = 0;

	rrp = TAILQ_FIRST(&rrset->rr_head);
	if (rrp == 0)
		return -1;

	saltlen = ((struct nsec3param *)rrp->rdata)->saltlen;
	if ((outlen + sizeof(struct answer) + saltlen ) > replysize) {
		NTOHS(odh->query);
		SET_DNS_TRUNCATION(odh);
		HTONS(odh->query);
		odh->answer = 0;
		odh->nsrr = 0; 
		odh->additional = 0;
		outlen = rollback;
		goto out;
	}

		

	/*
	 * answer->name is a pointer to the request (0xc00c) 
	 */

	answer->name[0] = 0xc0;				/* 1 byte */
	answer->name[1] = 0x0c;				/* 2 bytes */
	answer->type = q->hdr->qtype;			/* 4 bytes */	
	answer->class = q->hdr->qclass;			/* 6 bytes */

	if (q->aa) 
		answer->ttl = htonl(rrset->ttl);
	else
		answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

	answer->rdlength = htons(((struct nsec3param *)rrp->rdata)->saltlen + 5);	/* 5 = rest */

	answer->algorithm = ((struct nsec3param *)rrp->rdata)->algorithm;
	answer->flags = ((struct nsec3param *)rrp->rdata)->flags;
	answer->iterations = htons(((struct nsec3param *)rrp->rdata)->iterations);
	answer->saltlen = saltlen;
	outlen += sizeof(struct answer);
	
	if (saltlen) {
		memcpy(&reply[outlen], 
			&((struct nsec3param*)rrp->rdata)->salt, 	
			saltlen);

		outlen += saltlen;
	}

	a_count++;

	/* set new offset for answer */
	answer = (struct answer *)&reply[outlen];


	/* Add RRSIG reply_nsec3 */
	if (dnssec && q->dnssecok && (rbt->flags & RBT_DNSSEC)) {
		int tmplen = 0;
		int origlen = outlen;
		int retcount;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_NSEC3PARAM, rbt, reply, replysize, outlen, &retcount, q->aa);
		
		if (tmplen == 0) {
			/* we're forwarding and had no RRSIG return with -1 */
			if (q->aa != 1)
				return -1;

			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			outlen = rollback;
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->answer = htons(a_count + retcount);	

		if (rbt->flags & RBT_WILDCARD) {
			authority = get_soa(db, q);
			if (authority == NULL) {
				if (q->aa != 1)
					return -1;

				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}
			tmplen = additional_wildcard(q->hdr->name, q->hdr->namelen, authority, reply, replysize, outlen, &retcount, db);
			if (tmplen != 0) {
				outlen = tmplen;
				odh->nsrr = htons(retcount);	
			}
		}
			
	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}


/* 
 * REPLY_NSEC3() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_nsec3(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	uint16_t outlen = 0;
	int a_count;

	struct answer {
		char name[2];
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
		uint8_t algorithm;
		uint8_t flags;
		uint16_t iterations;
		uint8_t saltlen;
	} __attribute__((packed));

	struct answer *answer;

	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct rbtree *rbt = sreply->rbt1;
	struct rbtree *authority;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	uint16_t rollback;
	uint8_t *somelen;
	int bitmaplen, saltlen, nextlen;

	time_t now;

	now = time(NULL);

	if ((rrset = find_rr(rbt, DNS_TYPE_A)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}
	
	if (!istcp && q->edns0len > 512)
		replysize = MIN(q->edns0len, max_udp_payload);


	/* RFC 5155 section 7.2.8 */
	/* perhaps we are accompanied by an rrsig */
	if (find_rr(rbt, DNS_TYPE_NSEC3) && find_rr(rbt, DNS_TYPE_RRSIG)) {
		return (reply_nxdomain(sreply, sretlen, db));
	}
	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
	memset((char *)&odh->query, 0, sizeof(uint16_t));

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	set_reply_flags(rbt, odh, q);

	odh->question = htons(1);
	odh->answer = htons(1);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	a_count = 0;

	rrp = TAILQ_FIRST(&rrset->rr_head);
	if (rrp == 0)
		return -1;

	saltlen = ((struct nsec3 *)rrp->rdata)->saltlen;
	bitmaplen = ((struct nsec3 *)rrp->rdata)->bitmap_len;
	nextlen = ((struct nsec3 *)rrp->rdata)->nextlen;

	if ((outlen + sizeof(struct answer) + 
		nextlen + saltlen + 1 + bitmaplen) > replysize) {
		NTOHS(odh->query);
		SET_DNS_TRUNCATION(odh);
		HTONS(odh->query);
		odh->answer = 0;
		odh->nsrr = 0; 
		odh->additional = 0;
		outlen = rollback;
		goto out;
	}

	/*
	 * answer->name is a pointer to the request (0xc00c) 
	 */

	answer->name[0] = 0xc0;				/* 1 byte */
	answer->name[1] = 0x0c;				/* 2 bytes */
	answer->type = q->hdr->qtype;			/* 4 bytes */	
	answer->class = q->hdr->qclass;			/* 6 bytes */

	if (q->aa)
		answer->ttl = htonl(rrset->ttl); /* 10 b */
	else
		answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));
	
	answer->rdlength = htons(nextlen + bitmaplen + saltlen + 6);  /* 6 = rest */

	answer->algorithm = ((struct nsec3 *)rrp->rdata)->algorithm;
	answer->flags = ((struct nsec3 *)rrp->rdata)->flags;
	answer->iterations = htons(((struct nsec3 *)rrp->rdata)->iterations);
	answer->saltlen = saltlen;
	outlen += sizeof(struct answer);
	
	if (saltlen) {
		memcpy(&reply[outlen], 
			(char *)&((struct nsec3 *)rrp->rdata)->salt, 
			saltlen);

		outlen += saltlen;
	}

	somelen = (uint8_t *)&reply[outlen];
	*somelen = nextlen;

	outlen += 1;

	memcpy(&reply[outlen], ((struct nsec3 *)rrp->rdata)->next, nextlen);

	outlen += nextlen;

	memcpy(&reply[outlen], ((struct nsec3 *)rrp->rdata)->bitmap, bitmaplen);
	outlen += bitmaplen;

	a_count++;

	/* set new offset for answer */
	answer = (struct answer *)&reply[outlen];


	/* Add RRSIG reply_nsec3 */
	if (dnssec && q->dnssecok && (rbt->flags & RBT_DNSSEC)) {
		int tmplen = 0;
		int origlen = outlen;
		int retcount;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_NSEC3, rbt, reply, replysize, outlen, &retcount, q->aa);
		
		if (tmplen == 0) {
			/* we're forwarding and had no RRSIG return with -1 */
			if (q->aa != 1)
				return -1;

			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->answer = htons(a_count + retcount + 1);	

		if (rbt->flags & RBT_WILDCARD) {
			authority = get_soa(db, q);
			if (authority == NULL) {
				if (q->aa != 1)
					return -1;

				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}
			tmplen = additional_wildcard(q->hdr->name, q->hdr->namelen, authority, reply, replysize, outlen, &retcount, db);
			if (tmplen != 0) {
				outlen = tmplen;
				odh->nsrr = htons(retcount);	
			}
		}
			
	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}

/*
 * REPLY_ZONEMD - (based on REPLY_CAA)
 */

int
reply_zonemd(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	uint16_t outlen = 0;
	int zonemd_count;
	int zonemdlen, hashlen;

	struct answer {
		char name[2];
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
	} __attribute__((packed));

	struct answer *answer;

	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct rbtree *rbt = sreply->rbt1;
	struct rbtree *authority;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;	
	
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	uint16_t rollback;
	time_t now;
	uint32_t zonenumberx;

	zonenumberx = determine_zone(rbt);
	now = time(NULL);

	if ((rrset = find_rr(rbt, DNS_TYPE_ZONEMD)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}
	
	if (!istcp && q->edns0len > 512)
		replysize = MIN(q->edns0len, max_udp_payload);

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	memset((char *)&odh->query, 0, sizeof(uint16_t));
	set_reply_flags(rbt, odh, q);

	odh->question = htons(1);
	odh->answer = htons(1);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	zonemd_count = 0;

	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		if (rrp->zonenumber != zonenumberx)
			continue;
		switch (((struct zonemd *)rrp->rdata)->algorithm) {
		case ZONEMD_SHA384:
			hashlen = SHA384_DIGEST_LENGTH;
			zonemdlen = sizeof(uint32_t) + sizeof(uint8_t) + \
				sizeof(uint8_t) + hashlen;
			break;
		default:
			return -1;
		}

		if ((outlen + sizeof(struct answer) + 2 + \
			zonemdlen) > replysize) {	

			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		answer->name[0] = 0xc0;				/* 1 byte */
		answer->name[1] = 0x0c;				/* 2 bytes */
		answer->type = q->hdr->qtype;			/* 4 bytes */	
		answer->class = q->hdr->qclass;			/* 6 bytes */

		if (q->aa)
			answer->ttl = htonl(rrset->ttl); 		/* 10 b */
		else
			answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));


		zonemd_count++;
		outlen += 12;

		pack32(&reply[outlen], htonl(((struct zonemd *)rrp->rdata)->serial));
		outlen += 4;
		pack8(&reply[outlen++], ((struct zonemd *)rrp->rdata)->scheme);
		pack8(&reply[outlen++], ((struct zonemd *)rrp->rdata)->algorithm);
		pack(&reply[outlen],((struct zonemd *)rrp->rdata)->hash, hashlen);
		outlen += hashlen;

		answer->rdlength = htons(6 + hashlen);

		/* set new offset for answer */
		answer = (struct answer *)&reply[outlen];
	} 

	odh->answer = htons(zonemd_count);
	

	/* Add RRSIG reply_nsec */
	if (dnssec && q->dnssecok && (rbt->flags & RBT_DNSSEC)) {
		int tmplen = 0;
		int origlen = outlen;
		int retcount;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_ZONEMD, rbt, reply, replysize, outlen, &retcount, q->aa);
		
		if (tmplen == 0) {

			/* we're forwarding and had no RRSIG return with -1 */
			if (q->aa != 1)
				return -1;

			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->answer = htons(zonemd_count + retcount);	

		if (rbt->flags & RBT_WILDCARD) {
			authority = get_soa(db, q);
			if (authority == NULL) {
				if (q->aa != 1)
					return -1;

				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}
			tmplen = additional_wildcard(q->hdr->name, q->hdr->namelen, authority, reply, replysize, outlen, &retcount, db);
			if (tmplen != 0) {
				outlen = tmplen;
				odh->nsrr = htons(retcount);	
			}
		}
			
	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}


/*
 * REPLY_CAA 
 */

int
reply_caa(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	uint16_t outlen = 0;
	int caa_count;

	struct answer {
		char name[2];
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
	} __attribute__((packed));

	struct answer *answer;

	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct rbtree *rbt = sreply->rbt1;
	struct rbtree *authority;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;	
	
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	uint16_t rollback;
	int valuelen, taglen;
	time_t now;
	uint32_t zonenumberx;

	zonenumberx = determine_zone(rbt);
	now = time(NULL);

	if ((rrset = find_rr(rbt, DNS_TYPE_CAA)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}
	
	if (!istcp && q->edns0len > 512)
		replysize = MIN(q->edns0len, max_udp_payload);

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	memset((char *)&odh->query, 0, sizeof(uint16_t));
	set_reply_flags(rbt, odh, q);

	odh->question = htons(1);
	odh->answer = htons(1);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	caa_count = 0;

	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		if (rrp->zonenumber != zonenumberx)
			continue;
		if ((outlen + sizeof(struct answer) + 2 + \
			((struct caa *)rrp->rdata)->taglen + \
			((struct caa *)rrp->rdata)->valuelen) > replysize) {	

			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		answer->name[0] = 0xc0;				/* 1 byte */
		answer->name[1] = 0x0c;				/* 2 bytes */
		answer->type = q->hdr->qtype;			/* 4 bytes */	
		answer->class = q->hdr->qclass;			/* 6 bytes */

		if (q->aa)
			answer->ttl = htonl(rrset->ttl); 		/* 10 b */
		else
			answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));


		caa_count++;
		outlen += 12;

		taglen = ((struct caa *)rrp->rdata)->taglen;
		valuelen = ((struct caa *)rrp->rdata)->valuelen;
	
		pack8(&reply[outlen++], ((struct caa *)rrp->rdata)->flags);
		pack8(&reply[outlen++], taglen);
		pack(&reply[outlen], ((struct caa *)rrp->rdata)->tag, taglen);
		outlen += taglen;
		pack(&reply[outlen],((struct caa *)rrp->rdata)->value,valuelen);
		outlen += valuelen;

		answer->rdlength = htons(2 + taglen + valuelen);

		/* set new offset for answer */
		answer = (struct answer *)&reply[outlen];
	} 

	odh->answer = htons(caa_count);
	

	/* Add RRSIG reply_nsec */
	if (dnssec && q->dnssecok && (rbt->flags & RBT_DNSSEC)) {
		int tmplen = 0;
		int origlen = outlen;
		int retcount;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_CAA, rbt, reply, replysize, outlen, &retcount, q->aa);
		
		if (tmplen == 0) {

			/* we're forwarding and had no RRSIG return with -1 */
			if (q->aa != 1)
				return -1;

			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->answer = htons(caa_count + retcount);	

		if (rbt->flags & RBT_WILDCARD) {
			authority = get_soa(db, q);
			if (authority == NULL) {
				if (q->aa != 1)
					return -1;

				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}
			tmplen = additional_wildcard(q->hdr->name, q->hdr->namelen, authority, reply, replysize, outlen, &retcount, db);
			if (tmplen != 0) {
				outlen = tmplen;
				odh->nsrr = htons(retcount);	
			}
		}
			
	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}

int
reply_hinfo(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	uint16_t outlen = 0;
	int hinfo_count;

	struct answer {
		char name[2];
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
	} __attribute__((packed));

	struct answer *answer;

	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct rbtree *rbt = sreply->rbt1;
	struct rbtree *authority;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;	
	
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	uint16_t rollback;
	time_t now;
	uint32_t zonenumberx;

	zonenumberx = determine_zone(rbt);
	now = time(NULL);

	if ((rrset = find_rr(rbt, DNS_TYPE_HINFO)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}
	
	if (!istcp && q->edns0len > 512)
		replysize = MIN(q->edns0len, max_udp_payload);

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	memset((char *)&odh->query, 0, sizeof(uint16_t));
	set_reply_flags(rbt, odh, q);

	odh->question = htons(1);
	odh->answer = htons(1);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	hinfo_count = 0;

	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		if (rrp->zonenumber != zonenumberx)
			continue;
		if ((outlen + sizeof(struct answer) + 2 + \
			((struct hinfo *)rrp->rdata)->cpulen + \
			((struct hinfo *)rrp->rdata)->oslen) > replysize) {	

			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		answer->name[0] = 0xc0;				/* 1 byte */
		answer->name[1] = 0x0c;				/* 2 bytes */
		answer->type = q->hdr->qtype;			/* 4 bytes */	
		answer->class = q->hdr->qclass;			/* 6 bytes */

		if (q->aa)
			answer->ttl = htonl(rrset->ttl); 		/* 10 b */
		else
			answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));


		hinfo_count++;
		outlen += 12;

		pack8(&reply[outlen++], ((struct hinfo *)rrp->rdata)->cpulen);
		pack(&reply[outlen], ((struct hinfo *)rrp->rdata)->cpu, 
			((struct hinfo *)rrp->rdata)->cpulen);
		outlen += ((struct hinfo *)rrp->rdata)->cpulen;
		pack8(&reply[outlen++], ((struct hinfo *)rrp->rdata)->oslen);
		pack(&reply[outlen], ((struct hinfo *)rrp->rdata)->os, 
			((struct hinfo *)rrp->rdata)->oslen);
		outlen += ((struct hinfo *)rrp->rdata)->oslen;

		answer->rdlength = htons(2 + \
			((struct hinfo *)rrp->rdata)->oslen + \
			((struct hinfo *)rrp->rdata)->cpulen);

		/* set new offset for answer */
		answer = (struct answer *)&reply[outlen];
	} 

	odh->answer = htons(hinfo_count);
	

	/* Add RRSIG reply_nsec */
	if (dnssec && q->dnssecok && (rbt->flags & RBT_DNSSEC)) {
		int tmplen = 0;
		int origlen = outlen;
		int retcount;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_HINFO, rbt, reply, replysize, outlen, &retcount, q->aa);
		
		if (tmplen == 0) {

			/* we're forwarding and had no RRSIG return with -1 */
			if (q->aa != 1)
				return -1;

			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->answer = htons(hinfo_count + retcount);	

		if (rbt->flags & RBT_WILDCARD) {
			authority = get_soa(db, q);
			if (authority == NULL) {
				if (q->aa != 1)
					return -1;

				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}
			tmplen = additional_wildcard(q->hdr->name, q->hdr->namelen, authority, reply, replysize, outlen, &retcount, db);
			if (tmplen != 0) {
				outlen = tmplen;
				odh->nsrr = htons(retcount);	
			}
		}
			
	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}

int
reply_rp(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	uint16_t outlen = 0;
	int rp_count;

	struct answer {
		char name[2];
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
	} __attribute__((packed));

	struct answer *answer;

	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct rbtree *rbt = sreply->rbt1;
	struct rbtree *authority;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;	
	
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	uint16_t rollback;
	time_t now;
	uint32_t zonenumberx;

	zonenumberx = determine_zone(rbt);
	now = time(NULL);

	if ((rrset = find_rr(rbt, DNS_TYPE_RP)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}
	
	if (!istcp && q->edns0len > 512)
		replysize = MIN(q->edns0len, max_udp_payload);

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	memset((char *)&odh->query, 0, sizeof(uint16_t));
	set_reply_flags(rbt, odh, q);

	odh->question = htons(1);
	odh->answer = htons(1);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	rp_count = 0;

	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		if (rrp->zonenumber != zonenumberx)
			continue;
		if ((outlen + sizeof(struct answer) + \
			((struct rp *)rrp->rdata)->mboxlen + \
			((struct rp *)rrp->rdata)->txtlen) > replysize) {	

			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		answer->name[0] = 0xc0;				/* 1 byte */
		answer->name[1] = 0x0c;				/* 2 bytes */
		answer->type = q->hdr->qtype;			/* 4 bytes */	
		answer->class = q->hdr->qclass;			/* 6 bytes */

		if (q->aa)
			answer->ttl = htonl(rrset->ttl); 		/* 10 b */
		else
			answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));


		rp_count++;
		outlen += 12;

		pack(&reply[outlen], ((struct rp *)rrp->rdata)->mbox, 
			((struct rp *)rrp->rdata)->mboxlen);
		outlen += ((struct rp *)rrp->rdata)->mboxlen;

		pack(&reply[outlen], ((struct rp *)rrp->rdata)->txt, 
			((struct rp *)rrp->rdata)->txtlen);
		outlen += ((struct rp *)rrp->rdata)->txtlen;

		answer->rdlength = htons(((struct rp *)rrp->rdata)->mboxlen + \
			((struct rp *)rrp->rdata)->txtlen);

		/* set new offset for answer */
		answer = (struct answer *)&reply[outlen];
	} 

	odh->answer = htons(rp_count);
	

	/* Add RRSIG reply_nsec */
	if (dnssec && q->dnssecok && (rbt->flags & RBT_DNSSEC)) {
		int tmplen = 0;
		int origlen = outlen;
		int retcount;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_RP, rbt, reply, replysize, outlen, &retcount, q->aa);
		
		if (tmplen == 0) {

			/* we're forwarding and had no RRSIG return with -1 */
			if (q->aa != 1)
				return -1;

			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->answer = htons(rp_count + retcount);	

		if (rbt->flags & RBT_WILDCARD) {
			authority = get_soa(db, q);
			if (authority == NULL) {
				if (q->aa != 1)
					return -1;

				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}
			tmplen = additional_wildcard(q->hdr->name, q->hdr->namelen, authority, reply, replysize, outlen, &retcount, db);
			if (tmplen != 0) {
				outlen = tmplen;
				odh->nsrr = htons(retcount);	
			}
		}
			
	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}

/* 
 * REPLY_NSEC() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_nsec(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	uint16_t outlen = 0;
	int a_count;

	struct answer {
		char name[2];
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
	} __attribute__((packed));

	struct answer *answer;

	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct rbtree *rbt = sreply->rbt1;
	struct rbtree *authority;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;	
	
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	uint16_t rollback;
	int ndnlen, bitmaplen;
	time_t now;

	now = time(NULL);

	if ((rrset = find_rr(rbt, DNS_TYPE_A)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}
	
	if (!istcp && q->edns0len > 512)
		replysize = MIN(q->edns0len, max_udp_payload);

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	memset((char *)&odh->query, 0, sizeof(uint16_t));
	set_reply_flags(rbt, odh, q);

	odh->question = htons(1);
	odh->answer = htons(1);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	a_count = 0;

	rrp = TAILQ_FIRST(&rrset->rr_head);
	if (rrp == 0)
		return -1;
	
	ndnlen = ((struct nsec *)rrp->rdata)->ndn_len;
	bitmaplen = ((struct nsec *)rrp->rdata)->bitmap_len;	

	if ((outlen + sizeof(struct answer) + ndnlen + bitmaplen) > replysize) {
		NTOHS(odh->query);
		SET_DNS_TRUNCATION(odh);
		HTONS(odh->query);
		odh->answer = 0;
		odh->nsrr = 0; 
		odh->additional = 0;
		outlen = rollback;
		goto out;
	}

	/*
	 * answer->name is a pointer to the request (0xc00c) 
	 */

	answer->name[0] = 0xc0;				/* 1 byte */
	answer->name[1] = 0x0c;				/* 2 bytes */
	answer->type = q->hdr->qtype;			/* 4 bytes */	
	answer->class = q->hdr->qclass;			/* 6 bytes */

	if (q->aa) 
		answer->ttl = htonl(rrset->ttl); /* 10 b */
	else
		answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

	answer->rdlength = htons(ndnlen + bitmaplen);	

	outlen += sizeof(struct answer);

	memcpy(&reply[outlen], ((struct nsec *)rrp->rdata)->next_domain_name,
		ndnlen);

	outlen += ndnlen;

	memcpy(&reply[outlen], ((struct nsec *)rrp->rdata)->bitmap, bitmaplen);
	outlen += bitmaplen;

	a_count++;

	/* set new offset for answer */
	answer = (struct answer *)&reply[outlen];


	/* Add RRSIG reply_nsec */
	if (dnssec && q->dnssecok && (rbt->flags & RBT_DNSSEC)) {
		int tmplen = 0;
		int origlen = outlen;
		int retcount;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_NSEC, rbt, reply, replysize, outlen, &retcount, q->aa);
		
		if (tmplen == 0) {

			/* we're forwarding and had no RRSIG return with -1 */
			if (q->aa != 1)
				return -1;

			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->answer = htons(a_count + retcount + 1);	

		if (rbt->flags & RBT_WILDCARD) {
			authority = get_soa(db, q);
			if (authority == NULL) {
				if (q->aa != 1)
					return -1;

				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}
			tmplen = additional_wildcard(q->hdr->name, q->hdr->namelen, authority, reply, replysize, outlen, &retcount, db);
			if (tmplen != 0) {
				outlen = tmplen;
				odh->nsrr = htons(retcount);	
			}
		}
			
	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}

/* 
 * REPLY_DS() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_ds(struct sreply *sreply, int *sretlen, ddDB *db)
{
	return (reply_generic_ds(sreply, sretlen, db, DNS_TYPE_DS));
}

int
reply_cds(struct sreply *sreply, int *sretlen, ddDB *db)
{
	return (reply_generic_ds(sreply, sretlen, db, DNS_TYPE_CDS));
}

int
reply_generic_ds(struct sreply *sreply, int *sretlen, ddDB *db, uint16_t rrtype)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	uint16_t outlen = 0;
	int a_count;

	struct answer {
		char name[2];
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
		uint16_t key_tag;
		uint8_t algorithm;
		uint8_t digest_type;
	} __attribute__((packed));

	struct answer *answer;

	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct rbtree *rbt = sreply->rbt1;
	struct rbtree *authority;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	uint16_t rollback;
	time_t now;
	uint32_t zonenumberx;

	zonenumberx = determine_zone(rbt);
	now = time(NULL);

	if ((rrset = find_rr(rbt, rrtype)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}
	
	if (!istcp && q->edns0len > 512)
		replysize = MIN(q->edns0len, max_udp_payload);

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	memset((char *)&odh->query, 0, sizeof(uint16_t));
	set_reply_flags(rbt, odh, q);

	odh->question = htons(1);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	a_count = 0;

	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		if (rrp->zonenumber != zonenumberx)
			continue;
		if ((outlen + sizeof(struct answer) + 
			((struct ds *)rrp->rdata)->digestlen) > replysize) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		/*
		 * answer->name is a pointer to the request (0xc00c) 
		 */

		answer->name[0] = 0xc0;				/* 1 byte */
		answer->name[1] = 0x0c;				/* 2 bytes */
		answer->type = q->hdr->qtype;			/* 4 bytes */	
		answer->class = q->hdr->qclass;			/* 6 bytes */

		if (q->aa)
			answer->ttl = htonl(rrset->ttl); /* 10 */
		else
			answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));
	

		answer->rdlength = htons(((struct ds *)rrp->rdata)->digestlen + 4);	/* 12 bytes */

		answer->key_tag = htons(((struct ds *)rrp->rdata)->key_tag);
		answer->algorithm = ((struct ds *)rrp->rdata)->algorithm;
		answer->digest_type = ((struct ds *)rrp->rdata)->digest_type;
			
		outlen += sizeof(struct answer);

		memcpy(&reply[outlen], ((struct ds *)rrp->rdata)->digest,
			((struct ds *)rrp->rdata)->digestlen);

		outlen += ((struct ds *)rrp->rdata)->digestlen;

		a_count++;
		/* set new offset for answer */
		answer = (struct answer *)&reply[outlen];
	} 

	odh->answer = htons(a_count);

	/* Add RRSIG reply_ds */
	if (dnssec && q->dnssecok && (rbt->flags & RBT_DNSSEC)) {
		int tmplen = 0;
		int origlen = outlen;
		int retcount;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, rrtype, rbt, reply, replysize, outlen, &retcount, q->aa);
		
		if (tmplen == 0) {

			/* we're forwarding and had no RRSIG return with -1 */
			if (q->aa != 1)
				return -1;

			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen) {
			NTOHS(odh->answer);
			odh->answer += retcount;
			HTONS(odh->answer);
		}

		if (rbt->flags & RBT_WILDCARD) {
			authority = get_soa(db, q);
			if (authority == NULL) {
				if (q->aa != 1)
					return -1;

				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}
			tmplen = additional_wildcard(q->hdr->name, q->hdr->namelen, authority, reply, replysize, outlen, &retcount, db);
			if (tmplen != 0) {
				outlen = tmplen;
				odh->nsrr = htons(retcount);	
			}
		}
			
	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	retlen = reply_sendpacket(reply, outlen, sreply, sretlen); 
	rotate_rr(rrset);

	return (retlen);
}

/* 
 * REPLY_DNSKEY() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_dnskey(struct sreply *sreply, int *sretlen, ddDB *db)
{

	return (reply_generic_dnskey(sreply, sretlen, db, DNS_TYPE_DNSKEY));

}

int
reply_cdnskey(struct sreply *sreply, int *sretlen, ddDB *db)
{

	return (reply_generic_dnskey(sreply, sretlen, db, DNS_TYPE_CDNSKEY));

}

int
reply_generic_dnskey(struct sreply *sreply, int *sretlen, ddDB *db, uint16_t rrtype)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	uint16_t outlen = 0;
	int dnskey_count;

	struct answer {
		char name[2];
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
		uint16_t flags;
		uint8_t protocol;
		uint8_t algorithm;
	} __attribute__((packed));

	struct answer *answer;

	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct rbtree *rbt = sreply->rbt1;
	struct rbtree *authority;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	int rrsig_count = 0;
	uint16_t rollback;
	time_t now;
	uint32_t zonenumberx;

	zonenumberx = determine_zone(rbt);
	now = time(NULL);

	if ((rrset = find_rr(rbt, rrtype)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}
	
	if (!istcp && q->edns0len > 512)
		replysize = MIN(q->edns0len, max_udp_payload);

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	memset((char *)&odh->query, 0, sizeof(uint16_t));
	set_reply_flags(rbt, odh, q);

	odh->question = htons(1);
	odh->answer = htons(0);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	dnskey_count = 0;

	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		if (rrp->zonenumber != zonenumberx)
			continue;
		if ((outlen + sizeof(struct answer) + 
			((struct dnskey *)rrp->rdata)->publickey_len) > replysize) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		/*
		 * answer->name is a pointer to the request (0xc00c) 
		 */

		answer->name[0] = 0xc0;				/* 1 byte */
		answer->name[1] = 0x0c;				/* 2 bytes */
		answer->type = q->hdr->qtype;			/* 4 bytes */	
		answer->class = q->hdr->qclass;			/* 6 bytes */

		if (q->aa)
			answer->ttl = htonl(rrset->ttl);
		else
			answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

		answer->rdlength = htons(((struct dnskey *)rrp->rdata)->publickey_len + 4);	/* 12 bytes */

		answer->flags = htons(((struct dnskey *)rrp->rdata)->flags);
		answer->protocol = ((struct dnskey *)rrp->rdata)->protocol;
		answer->algorithm = ((struct dnskey *)rrp->rdata)->algorithm;
			
		outlen += sizeof(struct answer);

		memcpy(&reply[outlen], ((struct dnskey*)rrp->rdata)->public_key,
			((struct dnskey *)rrp->rdata)->publickey_len);

		outlen += ((struct dnskey *)rrp->rdata)->publickey_len;

		dnskey_count++;
		/* set new offset for answer */
		answer = (struct answer *)&reply[outlen];
	} 

	odh->answer = htons(dnskey_count);

	/* Add RRSIG reply_dnskey */
	if (dnssec && q->dnssecok && (rbt->flags & RBT_DNSSEC)) {
		int tmplen = 0;
		int origlen = outlen;
	
		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, rrtype, rbt, reply, replysize, outlen, &rrsig_count, q->aa);
		
		if (tmplen == 0) {

			/* we're forwarding and had no RRSIG return with -1 */
			if (q->aa != 1)
				return -1;

			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->answer = htons(dnskey_count + rrsig_count);	

		if (rbt->flags & RBT_WILDCARD) {
			int retcount;

			authority = get_soa(db, q);
			if (authority == NULL) {
				if (q->aa != 1)
					return -1;

				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}
			tmplen = additional_wildcard(q->hdr->name, q->hdr->namelen, authority, reply, replysize, outlen, &retcount, db);
			if (tmplen != 0) {
				outlen = tmplen;
				odh->nsrr = htons(retcount);	
			}
		}
			
	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}

/*
 * REPLY_RRSIG() - replies a DNS question (*q) on socket (so)
 *
 */


int		
reply_rrsig(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	uint16_t outlen = 0;
	int a_count;

	struct answer {
		char name[2];
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
		in_addr_t rdata;		/* 16 */
	} __attribute__((packed));

	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct rbtree *rbt = sreply->rbt1;
	
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	int tmplen = 0;
	uint16_t rollback;

	if ((find_rr(rbt, DNS_TYPE_RRSIG)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}
	
	if (! istcp && q->edns0len > 512)
		replysize = MIN(q->edns0len, max_udp_payload);

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	memset((char *)&odh->query, 0, sizeof(uint16_t));
	set_reply_flags(rbt, odh, q);

	odh->question = htons(1);
	odh->nsrr = 0;
	odh->additional = 0;

	tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, -1, rbt, reply, replysize, outlen, &a_count, q->aa);
	if (tmplen == 0) {
		/* we're forwarding and had no RRSIG return with -1 */
		if (q->aa != 1)
			return -1;

		NTOHS(odh->query);
		SET_DNS_TRUNCATION(odh);
		HTONS(odh->query);
		odh->answer = 0;
		odh->nsrr = 0; 
		odh->additional = 0;
		outlen = rollback;
		goto out;
	}
	outlen = tmplen;

	odh->answer = htons(a_count);

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}

/* 
 * REPLY_AAAA() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_aaaa(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	uint16_t outlen = 0;
	int aaaa_count;

	struct answer {
		char name[2];
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
		char rdata;		/* 12 + 16 */
	} __attribute__((packed));

	struct answer *answer;

	int so = sreply->so;
	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct sockaddr *sa = sreply->sa;
	int salen = sreply->salen;
	struct rbtree *rbt = sreply->rbt1;
	struct rbtree *authority;
	struct rr *rrp = NULL;
	struct rrset *rrset = NULL;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	uint16_t rollback;
	time_t now;
	uint32_t zonenumberx;

	zonenumberx = determine_zone(rbt);
	now = time(NULL);

	if ((rrset = find_rr(rbt, DNS_TYPE_AAAA)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}

	if (! istcp && q->edns0len > 512)
		replysize = MIN(q->edns0len, max_udp_payload);
	

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	memset((char *)&odh->query, 0, sizeof(uint16_t));
	set_reply_flags(rbt, odh, q);

	odh->question = htons(1);
	odh->answer = htons(0);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
			q->hdr->namelen + 4);
		

	aaaa_count = 0;

	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		if (rrp->zonenumber != zonenumberx)
			continue;
		answer->name[0] = 0xc0;
		answer->name[1] = 0x0c;
		answer->type = q->hdr->qtype;
		answer->class = q->hdr->qclass;
		
		if (q->aa)
			answer->ttl = htonl(rrset->ttl);
		else
			answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

		answer->rdlength = htons(sizeof(struct in6_addr));

		memcpy((char *)&answer->rdata, (char *)&((struct aaaa *)rrp->rdata)->aaaa, sizeof(struct in6_addr));
		outlen += 28;

		aaaa_count++;

		/* set new offset for answer */
		answer = (struct answer *)&reply[outlen];
	};

	odh->answer = htons(aaaa_count);

	/* RRSIG reply_aaaa */
	if (dnssec && q->dnssecok && (rbt->flags & RBT_DNSSEC)) {
		int tmplen = 0;
		int origlen = outlen;
		int retcount;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_AAAA, rbt, reply, replysize, outlen, &retcount, q->aa);
	
		if (tmplen == 0) {

			/* we're forwarding and had no RRSIG return with -1 */
			if (q->aa != 1)
				return -1;

			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->answer = htons(aaaa_count + retcount);	

		if (rbt->flags & RBT_WILDCARD) {
			authority = get_soa(db, q);
			if (authority == NULL) {
				if (q->aa != 1)
					return -1;

				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}
			tmplen = additional_wildcard(q->hdr->name, q->hdr->namelen, authority, reply, replysize, outlen, &retcount, db);
			if (tmplen != 0) {
				outlen = tmplen;
				odh->nsrr = htons(retcount);	
			}
		}
			
	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}


	if (istcp) {
		char *tmpbuf;

		tmpbuf = malloc(outlen + 2);
		if (tmpbuf == 0) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
		}
		pack16(tmpbuf, htons(outlen));
		memcpy(&tmpbuf[2], reply, outlen);

		if ((retlen = send(so, tmpbuf, outlen + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if (q->rawsocket) {
			*sretlen = retlen = outlen;
		} else {
			if ((*sretlen = retlen = sendto(so, 
					reply, outlen, 0, sa, salen)) < 0) {
				dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
			}
		}
	}

	retlen = reply_sendpacket(reply, outlen, sreply, sretlen);
	rotate_rr(rrset);

	return (retlen);
}

/* 
 * REPLY_MX() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_mx(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	int mx_count;
	char *name;
	uint16_t outlen = 0;
	uint16_t namelen;
	int tmplen = 0;

	struct answer {
		char name[2];
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
		uint16_t mx_priority;
		char exchange;
	} __attribute__((packed));

	struct answer *answer;

	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct rbtree *rbt = sreply->rbt1;
	struct rbtree *rbt0 = NULL;
	struct rbtree *authority;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	uint16_t rollback;
	time_t now;

	int addiscount;

	SLIST_HEAD(, addis) addishead;
	struct addis {
		char name[DNS_MAXNAME];
		int namelen;
		int contained;
		SLIST_ENTRY(addis) addis_entries;
	} *ad0, *ad1;
	uint32_t zonenumberx;

	zonenumberx = determine_zone(rbt);

	SLIST_INIT(&addishead);
	/* check for apex, delegations */

	now = time(NULL);
	
	if ((rrset = find_rr(rbt, DNS_TYPE_MX)) == 0)
		return -1;


	if (istcp) {
		replysize = 65535;
	}
	
	if (! istcp && q->edns0len > 512)
		replysize = MIN(q->edns0len, max_udp_payload);

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	memset((char *)&odh->query, 0, sizeof(uint16_t));
	set_reply_flags(rbt, odh, q);

	odh->question = htons(1);
	odh->answer = htons(0);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	mx_count = 0;

	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		if (rrp->zonenumber != zonenumberx)
			continue;
		answer->name[0] = 0xc0;
		answer->name[1] = 0x0c;
		answer->type = q->hdr->qtype;
		answer->class = q->hdr->qclass;
		
		if (q->aa)
			answer->ttl = htonl(rrset->ttl);
		else
			answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

		answer->rdlength = htons(sizeof(uint16_t) + ((struct smx *)rrp->rdata)->exchangelen);

		answer->mx_priority = htons(((struct smx *)rrp->rdata)->preference);
		memcpy((char *)&answer->exchange, (char *)((struct smx *)rrp->rdata)->exchange, ((struct smx *)rrp->rdata)->exchangelen);

		name = ((struct smx *)rrp->rdata)->exchange;
		namelen = ((struct smx *)rrp->rdata)->exchangelen;

		outlen += (12 + 2 + ((struct smx *)rrp->rdata)->exchangelen);

		/* can we afford to write another header? if no truncate */
		if ((outlen + 12 + 2 + ((struct smx *)rrp->rdata)->exchangelen) > replysize) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		ad0 = malloc(sizeof(struct addis));
		if (ad0 == NULL) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
			return -1;
		}

		memcpy(ad0->name, name, namelen);
		ad0->namelen = namelen;

		if (dn_contains(name, namelen, rbt->zone, rbt->zonelen) == 1)
			ad0->contained = 1;
		else
			ad0->contained = 0;

		SLIST_INSERT_HEAD(&addishead, ad0, addis_entries);

		/* set new offset for answer */
		answer = (struct answer *)&reply[outlen];
		mx_count++;
	} 

	odh->answer = htons(mx_count);

	/* RRSIG reply_mx*/

	if (dnssec && q->dnssecok && (rbt->flags & RBT_DNSSEC)) {
		int origlen = outlen;
		int retcount;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_MX, rbt, reply, replysize, outlen, &retcount, q->aa);

		if (tmplen == 0) {

			/* we're forwarding and had no RRSIG return with -1 */
			if (q->aa != 1)
				return -1;

			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->answer = htons(mx_count + retcount);	

		if (rbt->flags & RBT_WILDCARD) {
			authority = get_soa(db, q);
			if (authority == NULL) {
				if (q->aa != 1)
					return -1;

				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}
			tmplen = additional_wildcard(q->hdr->name, q->hdr->namelen, authority, reply, replysize, outlen, &retcount, db);
			if (tmplen != 0) {
				outlen = tmplen;
				odh->nsrr = htons(retcount);	
			}
		}
			
	}

	/* tack on additional A or AAAA records */

	SLIST_FOREACH(ad0, &addishead, addis_entries) {
		if (ad0->contained == 0)
			continue;

		addiscount = 0;
		rbt0 = find_rrset(db, ad0->name, ad0->namelen);
		if (rbt0 != NULL && find_rr(rbt0, DNS_TYPE_AAAA) != NULL) {
			tmplen = additional_aaaa(ad0->name, ad0->namelen, rbt0, reply, replysize, outlen, &addiscount);
			if (tmplen == 0) {
				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}

			outlen = tmplen;
			NTOHS(odh->additional);
			odh->additional += addiscount;
			HTONS(odh->additional);

			/* additional RRSIG for the additional AAAA */
			if (dnssec && q->dnssecok && (rbt0->flags & RBT_DNSSEC)) {
				int retcount;

				tmplen = additional_rrsig(ad0->name, ad0->namelen, DNS_TYPE_AAAA, rbt0, reply, replysize, outlen, &retcount, q->aa);

				if (tmplen == 0) {
					/* we're forwarding and had no RRSIG return with -1 */
					if (q->aa != 1)
						return -1;

					NTOHS(odh->query);
					SET_DNS_TRUNCATION(odh);
					HTONS(odh->query);
					odh->answer = 0;
					odh->nsrr = 0; 
					odh->additional = 0;
					outlen = rollback;
					goto out;
				}

				NTOHS(odh->additional);
				odh->additional += retcount;
				HTONS(odh->additional);

				outlen = tmplen;
			}

			rbt0 = NULL;
		}

		addiscount = 0;
		rbt0 = find_rrset(db, ad0->name, ad0->namelen);
		if (rbt0 != NULL && find_rr(rbt0, DNS_TYPE_A) != NULL) {
			tmplen = additional_a(ad0->name, ad0->namelen, rbt0, reply, replysize, outlen, &addiscount);
			if (tmplen == 0) {
				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}

			outlen = tmplen;
			NTOHS(odh->additional);
			odh->additional += addiscount;
			HTONS(odh->additional);

			/* additional RRSIG for the additional A RR */
			if (dnssec && q->dnssecok && (rbt0->flags & RBT_DNSSEC)) {
				int retcount;

				tmplen = additional_rrsig(ad0->name, ad0->namelen, DNS_TYPE_A, rbt0, reply, replysize, outlen, &retcount, q->aa);

				if (tmplen == 0) {
					/* we're forwarding and had no RRSIG return with -1 */
					if (q->aa != 1)
						return -1;

					NTOHS(odh->query);
					SET_DNS_TRUNCATION(odh);
					HTONS(odh->query);
					odh->answer = 0;
					odh->nsrr = 0; 
					odh->additional = 0;
					outlen = rollback;
					goto out;
				}

				NTOHS(odh->additional);
				odh->additional += retcount;
				HTONS(odh->additional);

				outlen = tmplen;

				if (rbt->flags & RBT_WILDCARD) {
					authority = get_soa(db, q);
					if (authority == NULL) {
						if (q->aa != 1)
							return -1;

						NTOHS(odh->query);
						SET_DNS_TRUNCATION(odh);
						HTONS(odh->query);
						odh->answer = 0;
						odh->nsrr = 0; 
						odh->additional = 0;
						outlen = rollback;
						goto out;
					}
					tmplen = additional_wildcard(q->hdr->name, q->hdr->namelen, authority, reply, replysize, outlen, &retcount, db);
					if (tmplen != 0) {
						outlen = tmplen;
						odh->nsrr = htons(retcount);	
					}
				}
					
			}

			rbt0 = NULL;
		}

	}

out:
	while (!SLIST_EMPTY(&addishead)) {  /* clean up */
		ad1 = SLIST_FIRST(&addishead);
		SLIST_REMOVE_HEAD(&addishead, addis_entries);
		free(ad1);
	}

	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}

/* 
 * REPLY_NS() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_ns(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	int tmplen = 0;
	int ns_count;
	char *name;
	uint16_t outlen = 0;
	uint16_t namelen;

	struct answer {
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
		char ns;
	} __attribute__((packed));

	struct answer *answer;

	int so = sreply->so;
	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct sockaddr *sa = sreply->sa;
	int salen = sreply->salen;
	struct rbtree *rbt = sreply->rbt1;
	struct rbtree *rbt0 = NULL, *rbt1 = NULL;
	struct rbtree *authority;
	struct rbtree *nrbt = NULL;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	uint16_t rollback;
	int delegation, addiscount;
	int addcount = 0;
	int retcount;
	time_t now;

	SLIST_HEAD(, addis) addishead;
	struct addis {
		char name[DNS_MAXNAME];
		int namelen;
		SLIST_ENTRY(addis) addis_entries;
	} *ad0, *ad1;
	uint32_t zonenumberx;

	zonenumberx = determine_zone(rbt);
	SLIST_INIT(&addishead);
	/* check for apex, delegations */
	
	now = time(NULL);

	rbt1 = get_ns(db, rbt, &delegation);

	if ((rrset = find_rr(rbt, DNS_TYPE_NS)) == NULL) {
		return -1;
	}

	if (istcp) {
		replysize = 65535;
	}

	if (! istcp && q->edns0len > 512)
		replysize = MIN(q->edns0len, max_udp_payload);
	
	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);


	outlen += (q->hdr->namelen + 4);
	rollback = outlen;
	
	memset((char *)&odh->query, 0, sizeof(uint16_t));
	/* no set_reply_flags here, it differs */

	SET_DNS_REPLY(odh);
	
	if (! delegation && q->aa)
		SET_DNS_AUTHORITATIVE(odh);

	if (q->rd) {
		SET_DNS_RECURSION(odh);
			
		if (! q->aa)
			SET_DNS_RECURSION_AVAIL(odh);
	}
	
	HTONS(odh->query);

	odh->question = htons(1);
	odh->answer = 0;
	odh->nsrr = 0;
	odh->additional = 0;


	ns_count = 0;

	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		if (rrp->zonenumber != zonenumberx)
			continue;
		memcpy(&reply[outlen], rbt1->zone, rbt1->zonelen);
		answer = (struct answer *)(&reply[outlen] + rbt1->zonelen);
		answer->type = htons(DNS_TYPE_NS);
		answer->class = q->hdr->qclass;

		if (q->aa)
			answer->ttl = htonl(rrset->ttl);
		else
			answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

		name = ((struct ns *)rrp->rdata)->nsserver;
		namelen = ((struct ns *)rrp->rdata)->nslen;

		answer->rdlength = htons(namelen);

		memcpy((char *)&answer->ns, (char *)name, namelen);

		outlen += (10 + namelen + rbt1->zonelen);

		ad0 = malloc(sizeof(struct addis));
		if (ad0 == NULL) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
			return -1;
		}

		memcpy(ad0->name, name, namelen);
		ad0->namelen = namelen;

		SLIST_INSERT_HEAD(&addishead, ad0, addis_entries);

		/* compress the label if possible */
		if ((tmplen = compress_label((u_char*)reply, outlen, namelen)) > 0) {
			/* XXX */
			outlen = tmplen;
		}

		answer->rdlength = htons(&reply[outlen] - &answer->ns);
		ns_count++;
	} 

	if (delegation) {
		odh->answer = 0;
		odh->nsrr = htons(ns_count);	
	} else {
		odh->answer = htons(ns_count);
		odh->nsrr = 0;
	}

	/* add RRSIG reply_ns */
	if (dnssec && q->dnssecok && (rbt->flags & RBT_DNSSEC)) {
		int origlen = outlen;
		int retcount;

		tmplen = additional_rrsig(rbt1->zone, rbt1->zonelen, DNS_TYPE_NS, rbt1, reply, replysize, outlen, &retcount, q->aa);

		if (tmplen == 0) {
			/* we're forwarding and had no RRSIG return with -1 */
			if (q->aa != 1)
				return -1;

			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		outlen = tmplen;
		if (outlen > origlen) {
			if (odh->answer)
				odh->answer = htons(ns_count + retcount);	
			else if (odh->nsrr)
				odh->nsrr = htons(ns_count + retcount);	
		}

		if (delegation) {
			tmplen = additional_ds(rbt1->zone, rbt1->zonelen, rbt1, reply, replysize, outlen, &addcount);
			if (tmplen != 0) {
				outlen = tmplen;

				NTOHS(odh->nsrr);	
				odh->nsrr += addcount;
				HTONS(odh->nsrr);

				tmplen = additional_rrsig(rbt1->zone, rbt1->zonelen, DNS_TYPE_DS, rbt1, reply, replysize, outlen, &retcount, q->aa);

				if (tmplen == 0) {
					/* we're forwarding and had no RRSIG return with -1 */
					if (q->aa != 1)
						return -1;

					NTOHS(odh->query);
					SET_DNS_TRUNCATION(odh);
					HTONS(odh->query);
					odh->answer = 0;
					odh->nsrr = 0; 
					odh->additional = 0;
					outlen = rollback;
					goto out;
				}

				outlen = tmplen;

				NTOHS(odh->nsrr);	
				odh->nsrr += retcount;
				HTONS(odh->nsrr);

			} else {
				rbt0 = get_soa(db, q);
				if (rbt0 == NULL) {
					return -1;
				}

				nrbt = find_nsec3_match_qname(rbt1->zone, rbt1->zonelen, rbt0, db);
				if (nrbt != NULL) {
					tmplen = additional_nsec3(nrbt->zone, nrbt->zonelen, DNS_TYPE_NSEC3, nrbt, reply, replysize, outlen, &retcount, q->aa);

					if (tmplen == 0) {
						NTOHS(odh->query);
						SET_DNS_TRUNCATION(odh);
						HTONS(odh->query);
						odh->answer = 0;
						odh->nsrr = 0; 
						odh->additional = 0;
						outlen = rollback;
						goto out;
					}

					outlen = tmplen;

					/* additional_nsec3 adds an RRSIG automatically */
					NTOHS(odh->nsrr);	
					odh->nsrr += retcount;
					HTONS(odh->nsrr);

				}

			}  /* nrbt != NULL */
		} /* else tmplen != 0 */
	} /* if delegation */

	/* tack on additional A or AAAA records */

	SLIST_FOREACH(ad0, &addishead, addis_entries) {
		addiscount = 0;
		rbt0 = find_rrset(db, ad0->name, ad0->namelen);
		if (rbt0 != NULL && find_rr(rbt0, DNS_TYPE_AAAA) != NULL) {
			tmplen = additional_aaaa(ad0->name, ad0->namelen, rbt0, reply, replysize, outlen, &addiscount);
			if (tmplen == 0) {
				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}

			outlen = tmplen;
			NTOHS(odh->additional);
			odh->additional += addiscount;
			HTONS(odh->additional);

			/* additional RRSIG for the additional AAAA */
			if (dnssec && q->dnssecok && (rbt0->flags & RBT_DNSSEC)) {
				tmplen = additional_rrsig(ad0->name, ad0->namelen, DNS_TYPE_AAAA, rbt0, reply, replysize, outlen, &retcount, q->aa);

				if (tmplen == 0) {
					/* we're forwarding and had no RRSIG return with -1 */
					if (q->aa != 1)
						return -1;

					NTOHS(odh->query);
					SET_DNS_TRUNCATION(odh);
					HTONS(odh->query);
					odh->answer = 0;
					odh->nsrr = 0; 
					odh->additional = 0;
					outlen = rollback;
					goto out;
				}

				NTOHS(odh->additional);
				odh->additional += retcount;
				HTONS(odh->additional);

				outlen = tmplen;
			}

			rbt0 = NULL;
		}


		addiscount = 0;
		rbt0 = find_rrset(db, ad0->name, ad0->namelen);
		if (rbt0 != NULL && find_rr(rbt0, DNS_TYPE_A) != NULL) {
			tmplen = additional_a(ad0->name, ad0->namelen, rbt0, reply, replysize, outlen, &addiscount);
			if (tmplen == 0) {
				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}

			outlen = tmplen;
			NTOHS(odh->additional);
			odh->additional += addiscount;
			HTONS(odh->additional);

			/* additional RRSIG for the additional A RR */
			if (dnssec && q->dnssecok && (rbt0->flags & RBT_DNSSEC)) {
				int retcount;

				tmplen = additional_rrsig(ad0->name, ad0->namelen, DNS_TYPE_A, rbt0, reply, replysize, outlen, &retcount, q->aa);

				if (tmplen == 0) {
					/* we're forwarding and had no RRSIG return with -1 */
					if (q->aa != 1)
						return -1;

					NTOHS(odh->query);
					SET_DNS_TRUNCATION(odh);
					HTONS(odh->query);
					odh->answer = 0;
					odh->nsrr = 0; 
					odh->additional = 0;
					outlen = rollback;
					goto out;
				}

				NTOHS(odh->additional);
				odh->additional += retcount;
				HTONS(odh->additional);

				outlen = tmplen;
			}

			rbt0 = NULL;
		}

		if (rbt->flags & RBT_WILDCARD) {
			authority = get_soa(db, q);
			if (authority == NULL) {
				if (q->aa != 1)
					return -1;

				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}
			tmplen = additional_wildcard(q->hdr->name, q->hdr->namelen, authority, reply, replysize, outlen, &retcount, db);
			if (tmplen != 0) {
				outlen = tmplen;
				odh->nsrr = htons(retcount);	
			}
		}
	}

out:
	while (!SLIST_EMPTY(&addishead)) {  /* clean up */
		ad1 = SLIST_FIRST(&addishead);
		SLIST_REMOVE_HEAD(&addishead, addis_entries);
		free(ad1);
	}


	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	if (istcp) {
		char *tmpbuf;

		tmpbuf = malloc(outlen + 2);
		if (tmpbuf == 0) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
		}
		pack16(tmpbuf, htons(outlen));
		memcpy(&tmpbuf[2], reply, outlen);
		if ((retlen = send(so, tmpbuf, outlen + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if (q->rawsocket) {
			*sretlen = retlen = outlen;
		} else {
			if ((*sretlen = retlen = sendto(so, 
					reply, outlen, 0, sa, salen)) < 0) {
				dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
			}
		}
	}

	retlen = reply_sendpacket(reply, outlen, sreply, sretlen);
	rotate_rr(rrset);

	return (retlen);
}


/* 
 * REPLY_CNAME() - replies a DNS question (*q) on socket (so)
 *
 */


int
reply_cname(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	uint16_t outlen;
	int i, tmplen;
	int labellen;
	char *label, *plabel;

	struct answer {
		char name[2];
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
		char rdata;		
	} __attribute__((packed));

	struct answer *answer;

	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct rbtree *rbt = sreply->rbt1;
	struct rbtree *authority;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	uint16_t rollback;
	time_t now;

	now = time(NULL);

	if ((rrset = find_rr(rbt, DNS_TYPE_CNAME)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}

	if (! istcp && q->edns0len > 512)
		replysize = MIN(q->edns0len, max_udp_payload);

	odh = (struct dns_header *)&reply[0];
	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	/* copy question to reply */
	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);


	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	/* blank query */
	memset((char *)&odh->query, 0, sizeof(uint16_t));
	set_reply_flags(rbt, odh, q);

	odh->question = htons(1);
	odh->answer = htons(1);
	odh->nsrr = 0;
	odh->additional = 0;
	
	rrp = TAILQ_FIRST(&rrset->rr_head);
	if (rrp == 0)
		return -1;

	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	answer->name[0] = 0xc0;
	answer->name[1] = 0x0c;
	answer->type = htons(DNS_TYPE_CNAME);
	answer->class = q->hdr->qclass;

	if (q->aa)
		answer->ttl = htonl(rrset->ttl);
	else
		answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

	outlen += 12;			/* up to rdata length */

	label = (char *)&((struct cname *)rrp->rdata)->cname;
	labellen = ((struct cname *)rrp->rdata)->cnamelen;

	plabel = label;

	/* copy label to reply */
	for (i = outlen; i < replysize; i++) {
		if (i - outlen == labellen)
			break;
		
		reply[i] = *plabel++;
	}

	if (i >= replysize) 
		return (retlen);

	outlen = i;
	
	/* compress the label if possible */
	if ((tmplen = compress_label((u_char*)reply, outlen, labellen)) > 0) {
		/* XXX */
		outlen = tmplen;
	}

	answer->rdlength = htons(&reply[outlen] - &answer->rdata);

	if (dnssec && q->dnssecok && (rbt->flags & RBT_DNSSEC)) {
		int retcount;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_CNAME, rbt, reply, replysize, outlen, &retcount, q->aa);
	
		if (tmplen == 0) {
			/* we're forwarding and had no RRSIG return with -1 */
			if (q->aa != 1)
				return -1;

			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		outlen = tmplen;

		NTOHS(odh->answer);
		odh->answer += retcount;
		HTONS(odh->answer);

		if (rbt->flags & RBT_WILDCARD) {
			authority = get_soa(db, q);
			if (authority == NULL) {
				if (q->aa != 1)
					return -1;

				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}
			tmplen = additional_wildcard(q->hdr->name, q->hdr->namelen, authority, reply, replysize, outlen, &retcount, db);
			if (tmplen != 0) {
				outlen = tmplen;
				odh->nsrr = htons(retcount);	
			}
		}
			
	}
	
out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}

/* 
 * REPLY_PTR() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_ptr(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	uint16_t outlen;
	int i, tmplen;
	int labellen;
	char *label, *plabel;

	struct answer {
		char name[2];
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
		char rdata;		
	} __attribute__((packed));

	struct answer *answer;

	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct rbtree *rbt = sreply->rbt1;
	struct rbtree *authority;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	uint16_t rollback;
	time_t now;

	now = time(NULL);
	if ((rrset = find_rr(rbt, DNS_TYPE_PTR)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}

	if (! istcp && q->edns0len > 512)
		replysize = MIN(q->edns0len, max_udp_payload);
	
	odh = (struct dns_header *)&reply[0];
	outlen = sizeof(struct dns_header);


	if (len > replysize) {
		return (retlen);
	}

	rrp = TAILQ_FIRST(&rrset->rr_head);
	if (rrp == 0)
		return -1;

	/* copy question to reply */
	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	/* blank query */
	memset((char *)&odh->query, 0, sizeof(uint16_t));
	set_reply_flags(rbt, odh, q);

	odh->question = htons(1);
	odh->answer = htons(1);
	odh->nsrr = 0;
	odh->additional = 0;

	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	answer->name[0] = 0xc0;
	answer->name[1] = 0x0c;
	answer->type = q->hdr->qtype;
	answer->class = q->hdr->qclass;
	
	if (q->aa)
		answer->ttl = htonl(rrset->ttl);
	else
		answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

	outlen += 12;			/* up to rdata length */

	label = ((struct ptr *)rrp->rdata)->ptr;
	labellen = ((struct ptr *)rrp->rdata)->ptrlen;

	plabel = label;

	/* copy label to reply */
	for (i = outlen; i < replysize; i++) {
		if (i - outlen == labellen)
			break;
		
		reply[i] = *plabel++;
	}

	if (i >= replysize) {
		return (retlen);
	}

	outlen = i;
	
	/* compress the label if possible */
	if ((tmplen = compress_label((u_char*)reply, outlen, labellen)) > 0) {
		outlen = tmplen;
	}

	answer->rdlength = htons(&reply[outlen] - &answer->rdata);

	if (dnssec && q->dnssecok && (rbt->flags & RBT_DNSSEC)) {
		int retcount;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_PTR, rbt, reply, replysize, outlen, &retcount, q->aa);

		if (tmplen == 0) {
			/* we're forwarding and had no RRSIG return with -1 */
			if (q->aa != 1)
				return -1;

			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}
		outlen = tmplen;

		NTOHS(odh->answer);
		odh->answer += retcount;
		HTONS(odh->answer);

		if (rbt->flags & RBT_WILDCARD) {
			authority = get_soa(db, q);
			if (authority == NULL) {
				if (q->aa != 1)
					return -1;

				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}
			tmplen = additional_wildcard(q->hdr->name, q->hdr->namelen, authority, reply, replysize, outlen, &retcount, db);
			if (tmplen != 0) {
				outlen = tmplen;
				odh->nsrr = htons(retcount);	
			}
		}
			
	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}
	
	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}

/* 
 * REPLY_SOA() - replies a DNS question (*q) on socket (so)
 *
 */


int
reply_soa(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	uint16_t outlen;
	int i, tmplen;
	int labellen;
	char *label, *plabel;

	struct answer {
		char name[2];
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
		char rdata;		
	} __attribute__((packed));

	struct answer *answer;

	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct rbtree *rbt = sreply->rbt1;
	struct rbtree *authority;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	uint16_t rollback;
	time_t now;

	now = time(NULL);

	if ((rrset = find_rr(rbt, DNS_TYPE_SOA)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}

	if (! istcp && q->edns0len > 512)
		replysize = MIN(q->edns0len, max_udp_payload);
	
	/* st */

	odh = (struct dns_header *)&reply[0];
	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	/* copy question to reply */
	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	/* blank query */
	memset((char *)&odh->query, 0, sizeof(uint16_t));
	set_reply_flags(rbt, odh, q);

	odh->question = htons(1);
	odh->answer = htons(1);
	odh->nsrr = 0;
	odh->additional = 0;

	rrp = TAILQ_FIRST(&rrset->rr_head);
	if (rrp == 0)
		return -1;

	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	answer->name[0] = 0xc0;
	answer->name[1] = 0x0c;
	answer->type = q->hdr->qtype;
	answer->class = q->hdr->qclass;

	if (q->aa)
		answer->ttl = htonl(rrset->ttl);
	else
		answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

	outlen += 12;			/* up to rdata length */

	label = ((struct soa *)rrp->rdata)->nsserver;
	labellen = ((struct soa *)rrp->rdata)->nsserver_len;

	plabel = label;

	/* copy label to reply */
	for (i = outlen; i < replysize; i++) {
		if (i - outlen == labellen)
			break;
		
		reply[i] = *plabel++;
	}

	if (i >= replysize) {
		return (retlen);
	}

	outlen = i;
	
	/* compress the label if possible */
	if ((tmplen = compress_label((u_char*)reply, outlen, labellen)) > 0) {
		outlen = tmplen;
	}

	label = ((struct soa *)rrp->rdata)->responsible_person;
	labellen = ((struct soa *)rrp->rdata)->rp_len;
	plabel = label;

	for (i = outlen; i < replysize; i++) {
		if (i - outlen == labellen)
			break;
		
		reply[i] = *plabel++;
	}

	if (i >= replysize) {
		return (retlen);
	}

	outlen = i;

	/* 2 compress the label if possible */

	if ((tmplen = compress_label((u_char*)reply, outlen, labellen)) > 0) {
		outlen = tmplen;
	}


	if (outlen + sizeof(uint32_t) > replysize) {
		return (retlen);
	}
	pack32(&reply[outlen], htonl(((struct soa *)rrp->rdata)->serial));
	outlen += sizeof(uint32_t);
	
	if ((outlen + sizeof(uint32_t)) > replysize) {
		return (retlen);
	}
	pack32(&reply[outlen], htonl(((struct soa *)rrp->rdata)->refresh));
	outlen += sizeof(uint32_t);

	if ((outlen + sizeof(uint32_t)) > replysize) {
		return (retlen);
	}
	pack32(&reply[outlen], htonl(((struct soa *)rrp->rdata)->retry));
	outlen += sizeof(uint32_t);

	if ((outlen + sizeof(uint32_t)) > replysize) {
		return (retlen);
	}
	pack32(&reply[outlen], htonl(((struct soa *)rrp->rdata)->expire));
	outlen += sizeof(uint32_t);

	if ((outlen + sizeof(uint32_t)) > replysize) {
		return (retlen);
	}
	pack32(&reply[outlen], htonl(((struct soa *)rrp->rdata)->minttl));
	outlen += sizeof(uint32_t);

	answer->rdlength = htons(&reply[outlen] - &answer->rdata);

	/* RRSIG reply_soa */
	if (dnssec && q->dnssecok && (rbt->flags & RBT_DNSSEC)) {
		int tmplen = 0;
		int origlen = outlen;
		int retcount;
	
		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_SOA, rbt, reply, replysize, outlen, &retcount, q->aa);
	
		if (tmplen == 0) {
			/* we're forwarding and had no RRSIG return with -1 */
			if (q->aa != 1)
				return -1;

			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen) {
			NTOHS(odh->answer);
			odh->answer += retcount;
			HTONS(odh->answer);
		}

		if (rbt->flags & RBT_WILDCARD) {
			authority = get_soa(db, q);
			if (authority == NULL) {
				if (q->aa != 1)
					return -1;

				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}
			tmplen = additional_wildcard(q->hdr->name, q->hdr->namelen, authority, reply, replysize, outlen, &retcount, db);
			if (tmplen != 0) {
				outlen = tmplen;
				odh->nsrr = htons(retcount);	
			}
		}
			
	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}

	
	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}

/* 
 * REPLY_TXT() - replies a DNS question (*q) on socket (so)
 *
 */


int
reply_txt(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	uint16_t outlen;
	char *p;

	struct answer {
		char name[2];
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
		char rdata;		
	} __attribute__((packed));

	struct answer *answer;

	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct rbtree *rbt = sreply->rbt1;
	struct rbtree *authority;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	uint16_t rollback;
	int txt_count = 0;
	time_t now;
	uint32_t zonenumberx;

	zonenumberx = determine_zone(rbt);

	now = time(NULL);

	if ((rrset = find_rr(rbt, DNS_TYPE_TXT)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}

	if (! istcp && q->edns0len > 512)
		replysize = MIN(q->edns0len, max_udp_payload);
	
	/* st */

	odh = (struct dns_header *)&reply[0];
	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	/* copy question to reply */
	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	/* blank query */
	memset((char *)&odh->query, 0, sizeof(uint16_t));
	set_reply_flags(rbt, odh, q);

	odh->question = htons(1);
	odh->answer = htons(1);
	odh->nsrr = 0;
	odh->additional = 0;

	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	txt_count = 0;

	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		if (rrp->zonenumber != zonenumberx)
			continue;
		/*
		 * answer->name is a pointer to the request (0xc00c) 
		 */

		answer->name[0] = 0xc0;				/* 1 byte */
		answer->name[1] = 0x0c;				/* 2 bytes */
		answer->type = q->hdr->qtype;			/* 4 bytes */	
		answer->class = q->hdr->qclass;			/* 6 bytes */

		if (q->aa)
			answer->ttl = htonl(rrset->ttl); /* 10 b */
		else
			answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

		/* 12 bytes */
		answer->rdlength = htons(((struct txt *)rrp->rdata)->txtlen);
		outlen += 12;

		p = (char *)&answer->rdata;

		memcpy(p, ((struct txt *)rrp->rdata)->txt, ((struct txt *)rrp->rdata)->txtlen);
		outlen += (((struct txt *)rrp->rdata)->txtlen);

		txt_count++;

		/* can we afford to write more, if no truncate */
		if (outlen > replysize) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}


		/* set new offset for answer */
		answer = (struct answer *)&reply[outlen];
	} 

	odh->answer = htons(txt_count);

	/* Add RRSIG reply_txt */
	if (dnssec && q->dnssecok && (rbt->flags & RBT_DNSSEC)) {
		int tmplen = 0;
		int origlen = outlen;
		int retcount;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_TXT, rbt, reply, replysize, outlen, &retcount, q->aa);
	
		if (tmplen == 0) {
			/* we're forwarding and had no RRSIG return with -1 */
			if (q->aa != 1)
				return -1;

			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen) {
			NTOHS(odh->answer);
			odh->answer += retcount;
			HTONS(odh->answer);
		}

		if (rbt->flags & RBT_WILDCARD) {
			authority = get_soa(db, q);
			if (authority == NULL) {
				if (q->aa != 1)
					return -1;

				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}
			tmplen = additional_wildcard(q->hdr->name, q->hdr->namelen, authority, reply, replysize, outlen, &retcount, db);
			if (tmplen != 0) {
				outlen = tmplen;
				odh->nsrr = htons(retcount);	
			}
		}
			
	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}


/* 
 * REPLY_VERSION() - replies a DNS question (*q) on socket (so)
 *
 */


int
reply_version(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	uint16_t outlen;
	char *p;

	struct answer {
		char name[2];
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
		char rdata;		
	} __attribute__((packed));

	struct answer *answer;

	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;

	if (istcp) {
		replysize = 65535;
	}

	if (! istcp && q->edns0len > 512)
		replysize = MIN(q->edns0len, max_udp_payload);
	
	/* st */

	odh = (struct dns_header *)&reply[0];
	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	/* copy question to reply */
	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);

	outlen += (q->hdr->namelen + 4);

	/* blank query */
	memset((char *)&odh->query, 0, sizeof(uint16_t));
	set_reply_flags(NULL, odh, q);

	odh->question = htons(1);
	odh->answer = htons(1);
	odh->nsrr = 0;
	odh->additional = 0;

	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	answer->name[0] = 0xc0;
	answer->name[1] = 0x0c;
	answer->type = q->hdr->qtype;
	answer->class = q->hdr->qclass;
	answer->ttl = htonl(3600);

	outlen += 12;			/* up to rdata length */

	p = (char *)&answer->rdata;

	*p = vslen;
	memcpy((p + 1), versionstring, vslen);
	outlen += (vslen + 1);

	answer->rdlength = htons(vslen + 1);

	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}

/* 
 * REPLY_LOC() - replies a DNS question (*q) on socket (so)
 *			(based on reply_tlsa)
 */


int
reply_loc(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	int loc_count;
	uint16_t outlen;

	struct answer {
		char name[2];
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
		uint8_t version;
		uint8_t size;
		uint8_t horiz_pre;
		uint8_t vert_pre;
		uint32_t latitude;
		uint32_t longitude;
		uint32_t altitude;
	} __attribute__((packed));

	struct answer *answer;

	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct rbtree *rbt = sreply->rbt1;
	struct rbtree *authority;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	uint16_t rollback;
	time_t now;
	uint32_t zonenumberx;

	zonenumberx = determine_zone(rbt);
	now = time(NULL);

	if ((rrset = find_rr(rbt, DNS_TYPE_LOC)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}

	if (! istcp && q->edns0len > 512)
		replysize = MIN(q->edns0len, max_udp_payload);
	

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	memset((char *)&odh->query, 0, sizeof(uint16_t));
	set_reply_flags(rbt, odh, q);

	odh->question = htons(1);
	odh->answer = htons(0);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	loc_count = 0;
	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		if (rrp->zonenumber != zonenumberx)
			continue;
		answer->name[0] = 0xc0;
		answer->name[1] = 0x0c;
		answer->type = q->hdr->qtype;
		answer->class = q->hdr->qclass;

		if (q->aa)
			answer->ttl = htonl(rrset->ttl);
		else
			answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

		answer->rdlength = htons((4 + (3 * sizeof(uint32_t)))); 
		answer->version = ((struct loc *)rrp->rdata)->version;
		answer->size = ((struct loc *)rrp->rdata)->size;
		answer->horiz_pre = ((struct loc *)rrp->rdata)->horiz_pre;
		answer->vert_pre = ((struct loc *)rrp->rdata)->vert_pre;
		answer->latitude = htonl(((struct loc *)rrp->rdata)->latitude);
		answer->longitude = htonl(((struct loc *)rrp->rdata)->longitude);
		answer->altitude = htonl(((struct loc *)rrp->rdata)->altitude);

		/* set new offset for answer */
		outlen += (12 + 4 + 12); 
		answer = (struct answer *)&reply[outlen];
		loc_count++;
	}

	odh->answer = htons(loc_count);

	/* RRSIG reply_loc */
	if (dnssec && q->dnssecok && (rbt->flags & RBT_DNSSEC)) {
		int tmplen = 0;
		int origlen = outlen;
		int retcount;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_LOC, rbt, reply, replysize, outlen, &retcount, q->aa);
	
		if (tmplen == 0) {
			/* we're forwarding and had no RRSIG return with -1 */
			if (q->aa != 1)
				return -1;

			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->answer = htons(loc_count + retcount);	

		if (rbt->flags & RBT_WILDCARD) {
			authority = get_soa(db, q);
			if (authority == NULL) {
				if (q->aa != 1)
					return -1;

				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}
			tmplen = additional_wildcard(q->hdr->name, q->hdr->namelen, authority, reply, replysize, outlen, &retcount, db);
			if (tmplen != 0) {
				outlen = tmplen;
				odh->nsrr = htons(retcount);	
			}
		}
			
	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}

/* 
 * REPLY_TLSA() - replies a DNS question (*q) on socket (so)
 *			(based on reply_sshfp)
 */


int
reply_tlsa(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	int tlsa_count;
	uint16_t outlen;

	struct answer {
		char name[2];
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
		uint8_t usage; 
		uint8_t selector;
		uint8_t matchtype;
		char target;
	} __attribute__((packed));

	struct answer *answer;

	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct rbtree *rbt = sreply->rbt1;
	struct rbtree *authority;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	int istcp = sreply->istcp;
	int typelen = 0;
	int replysize = 512;
	int retlen = -1;
	uint16_t rollback;
	time_t now;
	uint32_t zonenumberx;

	zonenumberx = determine_zone(rbt);
	now = time(NULL);

	if ((rrset = find_rr(rbt, DNS_TYPE_TLSA)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}

	if (! istcp && q->edns0len > 512)
		replysize = MIN(q->edns0len, max_udp_payload);
	

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	memset((char *)&odh->query, 0, sizeof(uint16_t));
	set_reply_flags(rbt, odh, q);

	odh->question = htons(1);
	odh->answer = htons(0);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	tlsa_count = 0;
	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		if (rrp->zonenumber != zonenumberx)
			continue;
		answer->name[0] = 0xc0;
		answer->name[1] = 0x0c;
		answer->type = q->hdr->qtype;
		answer->class = q->hdr->qclass;

		if (q->aa)
			answer->ttl = htonl(rrset->ttl);
		else
			answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

		switch (((struct tlsa *)rrp->rdata)->matchtype) {
		case 1:
			typelen = DNS_TLSA_SIZE_SHA256;
			break;
		case 2:
			typelen = DNS_TLSA_SIZE_SHA512;
			break;
		default:
			dolog(LOG_ERR, "oops bad tlsa type? not returning a packet!\n");
			return (retlen);
		}

		answer->rdlength = htons((3 * sizeof(uint8_t)) + typelen); 
		answer->usage = ((struct tlsa *)rrp->rdata)->usage;
		answer->selector = ((struct tlsa *)rrp->rdata)->selector;
		answer->matchtype = ((struct tlsa *)rrp->rdata)->matchtype;

		memcpy((char *)&answer->target, (char *)((struct tlsa *)rrp->rdata)->data, ((struct tlsa *)rrp->rdata)->datalen);

		/* set new offset for answer */
		outlen += (12 + 3 + ((struct tlsa *)rrp->rdata)->datalen);
		answer = (struct answer *)&reply[outlen];
		tlsa_count++;
	}

	odh->answer = htons(tlsa_count);

	/* RRSIG reply_tlsa */
	if (dnssec && q->dnssecok && (rbt->flags & RBT_DNSSEC)) {
		int tmplen = 0;
		int origlen = outlen;
		int retcount;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_TLSA, rbt, reply, replysize, outlen, &retcount, q->aa);
	
		if (tmplen == 0) {
			/* we're forwarding and had no RRSIG return with -1 */
			if (q->aa != 1)
				return -1;

			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->answer = htons(tlsa_count + retcount);	

		if (rbt->flags & RBT_WILDCARD) {
			authority = get_soa(db, q);
			if (authority == NULL) {
				if (q->aa != 1)
					return -1;

				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}
			tmplen = additional_wildcard(q->hdr->name, q->hdr->namelen, authority, reply, replysize, outlen, &retcount, db);
			if (tmplen != 0) {
				outlen = tmplen;
				odh->nsrr = htons(retcount);	
			}
		}
			
	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}


/* 
 * REPLY_SSHFP() - replies a DNS question (*q) on socket (so)
 *			(based on reply_srv)
 */


int
reply_sshfp(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	int sshfp_count;
	uint16_t outlen;

	struct answer {
		char name[2];
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
		uint8_t sshfp_alg;
		uint8_t sshfp_type;
		char target;
	} __attribute__((packed));

	struct answer *answer;

	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct rbtree *rbt = sreply->rbt1;
	struct rbtree *authority;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	int istcp = sreply->istcp;
	int typelen = 0;
	int replysize = 512;
	int retlen = -1;
	uint16_t rollback;
	time_t now;
	uint32_t zonenumberx;

	zonenumberx = determine_zone(rbt);
	now = time(NULL);

	if ((rrset = find_rr(rbt, DNS_TYPE_SSHFP)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}

	if (! istcp && q->edns0len > 512)
		replysize = MIN(q->edns0len, max_udp_payload);
	

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	memset((char *)&odh->query, 0, sizeof(uint16_t));
	set_reply_flags(rbt, odh, q);

	odh->question = htons(1);
	odh->answer = htons(0);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	sshfp_count = 0;
	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		if (rrp->zonenumber != zonenumberx)
			continue;
		answer->name[0] = 0xc0;
		answer->name[1] = 0x0c;
		answer->type = q->hdr->qtype;
		answer->class = q->hdr->qclass;
		
		if (q->aa)
			answer->ttl = htonl(rrset->ttl);
		else
			answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

		switch (((struct sshfp *)rrp->rdata)->fptype) {
		case 1:
			typelen = DNS_SSHFP_SIZE_SHA1;
			break;
		case 2:
			typelen = DNS_SSHFP_SIZE_SHA256;
			break;
		default:
			dolog(LOG_ERR, "oops bad sshfp type? not returning a packet!\n");
			return (retlen);
		}

		answer->rdlength = htons((2 * sizeof(uint8_t)) + typelen); 
		answer->sshfp_alg = ((struct sshfp *)rrp->rdata)->algorithm;
		answer->sshfp_type = ((struct sshfp *)rrp->rdata)->fptype;

		memcpy((char *)&answer->target, (char *)((struct sshfp *)rrp->rdata)->fingerprint, ((struct sshfp *)rrp->rdata)->fplen);

		/* set new offset for answer */
		outlen += (12 + 2 + ((struct sshfp *)rrp->rdata)->fplen);
		answer = (struct answer *)&reply[outlen];
		sshfp_count++;
	}

	odh->answer = htons(sshfp_count);

	/* RRSIG reply_sshfp */
	if (dnssec && q->dnssecok && (rbt->flags & RBT_DNSSEC)) {
		int tmplen = 0;
		int origlen = outlen;
		int retcount;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_SSHFP, rbt, reply, replysize, outlen, &retcount, q->aa);
	
		if (tmplen == 0) {
			/* we're forwarding and had no RRSIG return with -1 */
			if (q->aa != 1)
				return -1;

			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->answer = htons(sshfp_count + retcount);	

		if (rbt->flags & RBT_WILDCARD) {
			authority = get_soa(db, q);
			if (authority == NULL) {
				if (q->aa != 1)
					return -1;

				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}
			tmplen = additional_wildcard(q->hdr->name, q->hdr->namelen, authority, reply, replysize, outlen, &retcount, db);
			if (tmplen != 0) {
				outlen = tmplen;
				odh->nsrr = htons(retcount);	
			}
		}
			
	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}


/* 
 * REPLY_NAPTR() - replies a DNS question (*q) on socket (so)
 *			(based on reply_srv)
 */


int
reply_naptr(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	int naptr_count;
	uint16_t outlen;

	struct answer {
		char name[2];
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
		uint16_t naptr_order;
		uint16_t naptr_preference;
		char rest;
	} __attribute__((packed));

	struct answer *answer;

	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct rbtree *rbt = sreply->rbt1;
	struct rbtree *authority;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	int istcp = sreply->istcp;
	int replysize = 512;
	int tmplen, savelen;
	int namelen;
	char *p;
	int retlen = -1;
	uint16_t rollback;
	time_t now;
	uint32_t zonenumberx;

	zonenumberx = determine_zone(rbt);
	now = time(NULL);

	if ((rrset = find_rr(rbt, DNS_TYPE_NAPTR)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}
	
	if (! istcp && q->edns0len > 512)
		replysize = MIN(q->edns0len, max_udp_payload);

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	memset((char *)&odh->query, 0, sizeof(uint16_t));
	set_reply_flags(rbt, odh, q);

	odh->question = htons(1);
	odh->answer = htons(0);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	naptr_count = 0;

	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		if (rrp->zonenumber != zonenumberx)
			continue;
		savelen = outlen;
		answer->name[0] = 0xc0;
		answer->name[1] = 0x0c;
		answer->type = q->hdr->qtype;
		answer->class = q->hdr->qclass;
	
		if (q->aa)
			answer->ttl = htonl(rrset->ttl);
		else
			answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

		answer->naptr_order = htons(((struct naptr *)rrp->rdata)->order);
		answer->naptr_preference = htons(((struct naptr *)rrp->rdata)->preference);

		p = (char *)&answer->rest;

		*p = ((struct naptr *)rrp->rdata)->flagslen;
		memcpy((p + 1), ((struct naptr *)rrp->rdata)->flags, ((struct naptr *)rrp->rdata)->flagslen);
		p += (((struct naptr *)rrp->rdata)->flagslen + 1);
		outlen += (1 + ((struct naptr *)rrp->rdata)->flagslen);

		/* services */
		*p = ((struct naptr *)rrp->rdata)->serviceslen;
		memcpy((p + 1), ((struct naptr *)rrp->rdata)->services, ((struct naptr *)rrp->rdata)->serviceslen);
		p += (((struct naptr *)rrp->rdata)->serviceslen + 1);
		outlen += (1 + ((struct naptr *)rrp->rdata)->serviceslen);
		
		/* regexp */
		*p = ((struct naptr *)rrp->rdata)->regexplen;
		memcpy((p + 1), ((struct naptr *)rrp->rdata)->regexp, ((struct naptr *)rrp->rdata)->regexplen);
		p += (((struct naptr *)rrp->rdata)->regexplen + 1);
		outlen += (1 + ((struct naptr *)rrp->rdata)->regexplen);
	
		/* replacement */

		memcpy((char *)p, (char *)((struct naptr *)rrp->rdata)->replacement, ((struct naptr *)rrp->rdata)->replacementlen);
	
		namelen = ((struct naptr *)rrp->rdata)->replacementlen;

		outlen += (12 + 4 + ((struct naptr *)rrp->rdata)->replacementlen);

		/* compress the label if possible */
		if ((tmplen = compress_label((u_char*)reply, outlen, namelen)) > 0) {
			outlen = tmplen;
		}

		answer->rdlength = htons(outlen - (savelen + 12));

		/* can we afford to write another header? if no truncate */
		if ((outlen + 12 + 4 + ((struct naptr *)rrp->rdata)->replacementlen + ((struct naptr *)rrp->rdata)->flagslen + 1 + ((struct naptr *)rrp->rdata)->serviceslen + 1 + ((struct naptr *)rrp->rdata)->regexplen + 1) > replysize) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		/* set new offset for answer */
		answer = (struct answer *)&reply[outlen];
		naptr_count++;
	}

	odh->answer = htons(naptr_count);

	/* RRSIG reply_naptr*/

	if (dnssec && q->dnssecok && (rbt->flags & RBT_DNSSEC)) {
		int origlen = outlen;
		int retcount;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_NAPTR, rbt, reply, replysize, outlen, &retcount, q->aa);

		if (tmplen == 0) {
			/* we're forwarding and had no RRSIG return with -1 */
			if (q->aa != 1)
				return -1;

			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->answer = htons(naptr_count + retcount);	

		if (rbt->flags & RBT_WILDCARD) {
			authority = get_soa(db, q);
			if (authority == NULL) {
				if (q->aa != 1)
					return -1;

				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}
			tmplen = additional_wildcard(q->hdr->name, q->hdr->namelen, authority, reply, replysize, outlen, &retcount, db);
			if (tmplen != 0) {
				outlen = tmplen;
				odh->nsrr = htons(retcount);	
			}
		}
			
	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}


/* 
 * REPLY_SRV() - replies a DNS question (*q) on socket (so)
 *			(based on reply_mx)
 */


int
reply_srv(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	int srv_count;
	uint16_t outlen;

	struct answer {
		char name[2];
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
		uint16_t srv_priority;
		uint16_t srv_weight;
		uint16_t srv_port;
		char target;
	} __attribute__((packed));

	struct answer *answer;

	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct rbtree *rbt = sreply->rbt1;
	struct rbtree *authority;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	int tmplen;
	uint16_t rollback;
	time_t now;
	uint32_t zonenumberx;

	zonenumberx = determine_zone(rbt);
	now = time(NULL);

	if ((rrset = find_rr(rbt, DNS_TYPE_SRV)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}
	
	if (! istcp && q->edns0len > 512)
		replysize = MIN(q->edns0len, max_udp_payload);

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	memset((char *)&odh->query, 0, sizeof(uint16_t));
	set_reply_flags(rbt, odh, q);

	odh->question = htons(1);
	odh->answer = htons(0);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	srv_count = 0;
	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		if (rrp->zonenumber != zonenumberx)
			continue;
		answer->name[0] = 0xc0;
		answer->name[1] = 0x0c;
		answer->type = q->hdr->qtype;
		answer->class = q->hdr->qclass;

		if (q->aa)
			answer->ttl = htonl(rrset->ttl);
		else
			answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

		answer->rdlength = htons((3 * sizeof(uint16_t)) + ((struct srv *)rrp->rdata)->targetlen);

		answer->srv_priority = htons(((struct srv *)rrp->rdata)->priority);
		answer->srv_weight = htons(((struct srv *)rrp->rdata)->weight);
		answer->srv_port = htons(((struct srv *)rrp->rdata)->port);

		memcpy((char *)&answer->target, (char *)((struct srv *)rrp->rdata)->target, ((struct srv *)rrp->rdata)->targetlen);

		outlen += (12 + 6 + ((struct srv *)rrp->rdata)->targetlen);

		/* can we afford to write another header? if no truncate */
		if ((outlen + 12 + 6 + ((struct srv *)rrp->rdata)->targetlen) > replysize) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		/* set new offset for answer */
		answer = (struct answer *)&reply[outlen];
		srv_count++;
	}

	odh->answer = htons(srv_count);

	if (dnssec && q->dnssecok && (rbt->flags & RBT_DNSSEC)) {
		int origlen = outlen;
		int retcount;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_SRV, rbt, reply, replysize, outlen, &retcount, q->aa);

		if (tmplen == 0) {
			/* we're forwarding and had no RRSIG return with -1 */
			if (q->aa != 1)
				return -1;

			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->answer = htons(srv_count + retcount);	

		if (rbt->flags & RBT_WILDCARD) {
			authority = get_soa(db, q);
			if (authority == NULL) {
				if (q->aa != 1)
					return -1;

				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}
			tmplen = additional_wildcard(q->hdr->name, q->hdr->namelen, authority, reply, replysize, outlen, &retcount, db);
			if (tmplen != 0) {
				outlen = tmplen;
				odh->nsrr = htons(retcount);	
			}
		}
			
	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}


/*
 * REPLY_NOTIMPL - reply "Not Implemented" 
 *
 */


int
reply_notimpl(struct sreply  *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	uint16_t outlen;

	char *buf = sreply->buf;
	int len = sreply->len;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;

	if (istcp) {
		replysize = 65535;
	}


	odh = (struct dns_header *)&reply[0];
		
	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, len);

	memset((char *)&odh->query, 0, sizeof(uint16_t));

	SET_DNS_REPLY(odh);
	SET_DNS_RCODE_NOTIMPL(odh);

	HTONS(odh->query);		

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}

/* 
 * REPLY_NXDOMAIN() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_nxdomain(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	uint16_t outlen;
	int i, tmplen;
	int labellen;
	char *label, *plabel;
	uint16_t rollback;

	struct answer {
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 10 */
		char rdata;		
	} __attribute__((packed));

	struct answer *answer;

	int so = sreply->so;
	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct sockaddr *sa = sreply->sa;
	int salen = sreply->salen;
	struct rbtree *rbt = sreply->rbt1;
	struct rrset *rrset = NULL;
	struct rbtree *rbt0 = NULL;
	struct rr *rrp = NULL;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	int addrec = 0;
	
	struct {
		char name[DNS_MAXNAME];
		int len;
	} uniq[3];
		
	int rruniq = 0;

	if (istcp) {
		replysize = 65535;
	}

	if (!istcp && q->edns0len > 512)
		replysize = MIN(q->edns0len, max_udp_payload);
	
	odh = (struct dns_header *)&reply[0];
	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);

	}

	/* 
	 * no SOA, use the old code
	 */

	if ((rrset = find_rr(rbt, DNS_TYPE_SOA)) == 0) {

		memcpy(reply, buf, len);
		memset((char *)&odh->query, 0, sizeof(uint16_t));

		SET_DNS_REPLY(odh);
		SET_DNS_RCODE_NAMEERR(odh);

		if (q->rd) {
			SET_DNS_RECURSION(odh);
				
			if (! q->aa)
				SET_DNS_RECURSION_AVAIL(odh);
		}

		HTONS(odh->query);		
		if (istcp) {
			char *tmpbuf;

			tmpbuf = malloc(len + 2);
			if (tmpbuf == 0) {
				dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
			}
			pack16(tmpbuf, htons(len));
			memcpy(&tmpbuf[2], reply, len);

			if ((retlen = send(so, tmpbuf, len + 2, 0)) < 0) {
				dolog(LOG_INFO, "send: %s\n", strerror(errno));
			}
			free(tmpbuf);
		} else {
			if (q->rawsocket) {
				*sretlen = retlen = outlen;
			} else {
				if ((*sretlen = retlen = sendto(so, 
					reply, len, 0, sa, salen)) < 0) {
					dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
				}
			}
		}

		return (retlen);
	}

	rrp = TAILQ_FIRST(&rrset->rr_head);
	if (rrp == 0)
		return -1;

	/* copy question to reply */
	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);

	outlen += (q->hdr->namelen + 4); 
	rollback = outlen;

	/* blank query */
	memset((char *)&odh->query, 0, sizeof(uint16_t));
	SET_DNS_RCODE_NAMEERR(odh);
	HTONS(odh->query);
	set_reply_flags(rbt, odh, q);

	odh->question = htons(1);
	odh->answer = 0;
	odh->nsrr = htons(1);
	odh->additional = 0;

	memcpy(&reply[outlen], rbt->zone, rbt->zonelen);
	outlen += rbt->zonelen;

	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4 + rbt->zonelen);

	answer->type = htons(DNS_TYPE_SOA);
	answer->class = q->hdr->qclass;

	answer->ttl = htonl(rrset->ttl);

	outlen += 10;   /* sizeof(struct answer)  up to rdata length */


	label = ((struct soa *)rrp->rdata)->nsserver;
	labellen = ((struct soa *)rrp->rdata)->nsserver_len;

	plabel = label;

	/* copy label to reply */
	for (i = outlen; i < replysize; i++) {
		if (i - outlen == labellen)
			break;
		
		reply[i] = *plabel++;
	}

	if (i >= replysize) {
		return (retlen);
	}

	outlen = i;
	
	/* compress the label if possible */
	if ((tmplen = compress_label((u_char*)reply, outlen, labellen)) > 0) {
		outlen = tmplen;
	}

	label = ((struct soa *)rrp->rdata)->responsible_person;
	labellen = ((struct soa *)rrp->rdata)->rp_len;
	plabel = label;

	for (i = outlen; i < replysize; i++) {
		if (i - outlen == labellen)
			break;
		
		reply[i] = *plabel++;
	}

	if (i >= replysize) {
		return (retlen);
	}

	outlen = i;

	/* 2 compress the label if possible */

	if ((tmplen = compress_label((u_char*)reply, outlen, labellen)) > 0) {
		outlen = tmplen;
	}


	/* XXX */
	if ((outlen + sizeof(uint32_t)) > replysize) {
		/* XXX server error reply? */
		return (retlen);
	}
	pack32(&reply[outlen], htonl(((struct soa *)rrp->rdata)->serial));
	outlen += sizeof(uint32_t);
	
	if ((outlen + sizeof(uint32_t)) > replysize) {
		return (retlen);
	}
	pack32(&reply[outlen], htonl(((struct soa *)rrp->rdata)->refresh));
	outlen += sizeof(uint32_t);

	if ((outlen + sizeof(uint32_t)) > replysize) {
		return (retlen);
	}
	pack32(&reply[outlen], htonl(((struct soa *)rrp->rdata)->retry));
	outlen += sizeof(uint32_t);

	if ((outlen + sizeof(uint32_t)) > replysize) {
		return (retlen);
	}
	pack32(&reply[outlen], htonl(((struct soa *)rrp->rdata)->expire));
	outlen += sizeof(uint32_t);

	if ((outlen + sizeof(uint32_t)) > replysize) {
		return (retlen);
	}
	pack32(&reply[outlen], htonl(((struct soa *)rrp->rdata)->minttl));
	outlen += sizeof(uint32_t);

	answer->rdlength = htons(&reply[outlen] - &answer->rdata);

	/* RRSIG reply_nxdomain */
	if (dnssec && q->dnssecok && (rbt->flags & RBT_DNSSEC)) {
		int tmplen = 0;
		int origlen = outlen;
		int retcount;

		tmplen = additional_rrsig(rbt->zone, rbt->zonelen, DNS_TYPE_SOA, rbt, reply, replysize, outlen, &retcount, q->aa);
	
		if (tmplen == 0) {
			/* we're forwarding and had no RRSIG return with -1 */
			if (q->aa != 1)
				return -1;

			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen) {
			NTOHS(odh->nsrr);
			odh->nsrr += retcount;	
			HTONS(odh->nsrr);
		}

		origlen = outlen;
		if (find_rr(rbt, DNS_TYPE_NSEC3PARAM)) {
			rbt0 = find_nsec3_cover_next_closer(q->hdr->name, q->hdr->namelen, rbt, db);
			if (rbt0 == 0)
				goto out;

			memcpy(&uniq[rruniq].name, rbt0->zone, rbt0->zonelen);
			uniq[rruniq++].len = rbt0->zonelen;
			
			tmplen = additional_nsec3(rbt0->zone, rbt0->zonelen, DNS_TYPE_NSEC3, rbt0, reply, replysize, outlen, &retcount, q->aa);

			if (tmplen == 0) {
				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}

			outlen = tmplen;

			if (outlen > origlen) {
				NTOHS(odh->nsrr);
				odh->nsrr += retcount;	
				HTONS(odh->nsrr);
			}

			origlen = outlen;

			rbt0 = find_nsec3_match_closest(q->hdr->name, q->hdr->namelen, rbt, db);
			if (rbt0 == 0)
				goto out;

			memcpy(&uniq[rruniq].name, rbt0->zone, rbt0->zonelen);
			uniq[rruniq++].len = rbt0->zonelen;

			if (memcmp(uniq[0].name, uniq[1].name, uniq[1].len) != 0) {
				tmplen = additional_nsec3(rbt0->zone, rbt0->zonelen, DNS_TYPE_NSEC3, rbt0, reply, replysize, outlen, &retcount, q->aa);
				addrec = 1;
			}

			if (tmplen == 0) {
				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}

			outlen = tmplen;

			if (outlen > origlen && addrec) {
				NTOHS(odh->nsrr);
				odh->nsrr += retcount;
				HTONS(odh->nsrr);
			}

			addrec = 0;
			origlen = outlen;

			rbt0 = find_nsec3_wildcard_closest(q->hdr->name, q->hdr->namelen, rbt, db);
			if (rbt0 == 0)
				goto out;

			memcpy(&uniq[rruniq].name, rbt0->zone, rbt0->zonelen);
			uniq[rruniq++].len = rbt0->zonelen;

			if (memcmp(uniq[0].name, uniq[2].name, uniq[2].len) != 0&&
				memcmp(uniq[1].name, uniq[2].name, uniq[2].len) != 0) {
				tmplen = additional_nsec3(rbt0->zone, rbt0->zonelen, DNS_TYPE_NSEC3, rbt0, reply, replysize, outlen, &retcount, q->aa);
				addrec = 1;
			}
			
			if (tmplen == 0) {
				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}

			outlen = tmplen;

			if (outlen > origlen && addrec) {
				NTOHS(odh->nsrr);
				odh->nsrr += retcount;
				HTONS(odh->nsrr);
			}
			addrec = 0;

		} /* if (find_rr(... DNS_TYPE_NSEC3PARAM) */
	}

	if (replysize < outlen) {
		NTOHS(odh->query);
		SET_DNS_TRUNCATION(odh);
		HTONS(odh->query);
		odh->answer = 0;
		odh->nsrr = 0; 
		odh->additional = 0;
		outlen = rollback;
		goto out;
	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}


	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}

/* 
 * REPLY_REFUSED() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_refused(struct sreply *sreply, int *sretlen, ddDB *db, int haveq)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	uint16_t outlen = 0;

	int len = sreply->len;
	char *buf = sreply->buf;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;

	struct question *q = sreply->q;

	if (istcp) {
		replysize = 65535;
	}

	memset(reply, 0, replysize);

	odh = (struct dns_header *)&reply[0];

	if (len > replysize) {
		return (retlen);
	}


	if (haveq) {
		memcpy(&reply[0], buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
		outlen += (sizeof(struct dns_header) + q->hdr->namelen + 4); 
	} else {
		memcpy(&reply[0], buf, len);
		outlen += len;
	}

	memset((char *)&odh->query, 0, sizeof(uint16_t));
	SET_DNS_RCODE_REFUSED(odh);
	HTONS(odh->query);

	odh->answer = 0;			/* reset any answers */
	odh->nsrr = 0;				/* reset any authoritave */

	if (haveq)
		set_reply_flags(NULL, odh, q);
	else
		odh->question = htons(1);

	if (haveq && q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);

		if (q->edns0len > 512)
			replysize = MIN(q->edns0len, max_udp_payload);

		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}

/* 
 * REPLY_NOTAUTH() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_notauth(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	uint16_t outlen = 0;
	uint16_t tmplen;

	int len = sreply->len;
	char *buf = sreply->buf;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;

	struct question *q = sreply->q;

	if (istcp) {
		replysize = 65535;
	}

	memset(reply, 0, replysize);

	odh = (struct dns_header *)&reply[0];


	if (len > replysize) {
		return (retlen);
	}

	memset((char *)&odh->query, 0, sizeof(uint16_t));
	memcpy(&reply[0], buf, sizeof(struct dns_header) + q->hdr->namelen + 4);

	outlen += (sizeof(struct dns_header) + q->hdr->namelen + 4); 


	SET_DNS_REPLY(odh);
	SET_DNS_RCODE_NOTAUTH(odh);

	HTONS(odh->query);		

	
	odh->additional = 0;
	tmplen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);
	
	if (tmplen != 0)
		outlen = tmplen;

	odh->additional = htons(1);

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}

/* 
 * REPLY_NOTIFY() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_notify(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	uint16_t outlen = 0;
	uint16_t tmplen;

	int len = sreply->len;
	char *buf = sreply->buf;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;

	struct question *q = sreply->q;

	if (istcp) {
		replysize = 65535;
	}

	memset(reply, 0, replysize);

	odh = (struct dns_header *)&reply[0];

	if (len > replysize) {
		return (retlen);
	}

	memset((char *)&odh->query, 0, sizeof(uint16_t));

	memcpy(&reply[0], buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
	outlen += (sizeof(struct dns_header) + q->hdr->namelen + 4); 


	SET_DNS_REPLY(odh);
	SET_DNS_NOTIFY(odh);

	if (q->aa)
		SET_DNS_AUTHORITATIVE(odh);

	SET_DNS_RCODE_NOERR(odh);

	HTONS(odh->query);		

	if (q->tsig.have_tsig && q->tsig.tsigverified) {
		odh->additional = 0;
		tmplen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);
		if (tmplen != 0)
			outlen = tmplen;
		odh->additional = htons(1);

	}

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}
/* 
 * REPLY_FMTERROR() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_fmterror(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	uint16_t outlen;

	int len = sreply->len;
	char *buf = sreply->buf;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;

	if (istcp) {
		replysize = 65535;
	}

	memset(reply, 0, replysize);

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy((char *)&odh->id, buf, sizeof(uint16_t));
	memset((char *)&odh->query, 0, sizeof(uint16_t));

	SET_DNS_REPLY(odh);
	SET_DNS_RCODE_FORMATERR(odh);

	HTONS(odh->query);		

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}

/* 
 * REPLY_NOERROR() - replies a DNS question (*q) on socket (so)
 *		     based on reply_nxdomain
 *
 */

int
reply_noerror(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	uint16_t outlen;
	int i, tmplen;
	int labellen;
	char *label, *plabel;
	uint16_t rollback;

	struct answer {
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
		char rdata;		
	} __attribute__((packed));

	struct answer *answer;

	int so = sreply->so;
	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct sockaddr *sa = sreply->sa;
	int salen = sreply->salen;
	struct rbtree *rbt = sreply->rbt1;
	struct rrset *rrset = NULL;
	struct rbtree *rbt0 = NULL;
	struct rr *rrp = NULL;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;

	struct {
		char name[DNS_MAXNAME];
		int len;
	} uniq[3];
		
	int rruniq = 0;

	if (istcp) {
		replysize = 65535;
	}

	if (! istcp && q->edns0len > 512)
		replysize = MIN(q->edns0len, max_udp_payload);
	
	odh = (struct dns_header *)&reply[0];
	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);

	}


	/* 
	 * no SOA, use the old code
	 */

	if ((rrset = find_rr(rbt, DNS_TYPE_SOA)) == 0) {
		memcpy(reply, buf, len);

		memset((char *)&odh->query, 0, sizeof(uint16_t));
		set_reply_flags(rbt, odh, q);

		if (istcp) {
			char *tmpbuf;

			tmpbuf = malloc(len + 2);
			if (tmpbuf == 0) {
				dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
			}
			pack16(tmpbuf, htons(len));
			memcpy(&tmpbuf[2], reply, len);

			if ((retlen = send(so, tmpbuf, len + 2, 0)) < 0) {
				dolog(LOG_INFO, "send: %s\n", strerror(errno));
			}
			free(tmpbuf);
		} else {
			if (q->rawsocket) {
				*sretlen = retlen = outlen;
			} else {
				if ((*sretlen = retlen = sendto(so, 
					reply, len, 0, sa, salen)) < 0) {
					dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
				}
			}
		}

		return (retlen);
	}

	rrp = TAILQ_FIRST(&rrset->rr_head);
	if (rrp == 0)
		return -1;
	
	/* copy question to reply */
	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);

	outlen += (q->hdr->namelen + 4); 
	rollback = outlen;

	/* blank query */
	memset((char *)&odh->query, 0, sizeof(uint16_t));
	set_reply_flags(rbt, odh, q);

	odh->question = htons(1);
	odh->answer = 0;
	odh->nsrr = htons(1);
	odh->additional = 0;

	memcpy(&reply[outlen], rbt->zone, rbt->zonelen);
	outlen += rbt->zonelen;

	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4 + rbt->zonelen);

	answer->type = htons(DNS_TYPE_SOA);
	answer->class = q->hdr->qclass;

	answer->ttl = htonl(rrset->ttl);

	outlen += 10;			/* up to rdata length */


	label = ((struct soa *)rrp->rdata)->nsserver;
	labellen = ((struct soa *)rrp->rdata)->nsserver_len;

	plabel = label;

	/* copy label to reply */
	for (i = outlen; i < replysize; i++) {
		if (i - outlen == labellen)
			break;
		
		reply[i] = *plabel++;
	}

	if (i >= replysize) {
		return (retlen);
	}

	outlen = i;
	
	/* compress the label if possible */
	if ((tmplen = compress_label((u_char*)reply, outlen, labellen)) > 0) {
		outlen = tmplen;
	}

	label = ((struct soa *)rrp->rdata)->responsible_person;
	labellen = ((struct soa *)rrp->rdata)->rp_len;
	plabel = label;

	for (i = outlen; i < replysize; i++) {
		if (i - outlen == labellen)
			break;
		
		reply[i] = *plabel++;
	}

	if (i >= replysize) {
		return (retlen);
	}

	outlen = i;

	/* 2 compress the label if possible */

	if ((tmplen = compress_label((u_char*)reply, outlen, labellen)) > 0) {
		outlen = tmplen;
	}

	
	/* XXX */
	if ((outlen + sizeof(uint32_t)) > replysize) {
		/* XXX server error reply? */
		return (retlen);
	}
	pack32(&reply[outlen], htonl(((struct soa *)rrp->rdata)->serial));
	outlen += sizeof(uint32_t);
	
	if ((outlen + sizeof(uint32_t)) > replysize) {
		return (retlen);
	}
	pack32(&reply[outlen], htonl(((struct soa *)rrp->rdata)->refresh));
	outlen += sizeof(uint32_t);

	if ((outlen + sizeof(uint32_t)) > replysize) {
		return (retlen);
	}
	pack32(&reply[outlen], htonl(((struct soa *)rrp->rdata)->retry));
	outlen += sizeof(uint32_t);

	if ((outlen + sizeof(uint32_t)) > replysize) {
		return (retlen);
	}
	pack32(&reply[outlen], htonl(((struct soa *)rrp->rdata)->expire));
	outlen += sizeof(uint32_t);

	if ((outlen + sizeof(uint32_t)) > replysize) {
		return (retlen);
	}
	pack32(&reply[outlen], htonl(((struct soa *)rrp->rdata)->minttl));
	outlen += sizeof(uint32_t);

	answer->rdlength = htons(&reply[outlen] - &answer->rdata);
	/* RRSIG reply_nxdomain */
	if (dnssec && q->dnssecok && (rbt->flags & RBT_DNSSEC)) {
		int tmplen = 0;
		int origlen = outlen;
		int retcount;

		tmplen = additional_rrsig(rbt->zone, rbt->zonelen, DNS_TYPE_SOA, rbt, reply, replysize, outlen, &retcount, q->aa);
	
		if (tmplen == 0) {
			/* we're forwarding and had no RRSIG return with -1 */
			if (q->aa != 1)
				return -1;

			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->nsrr = htons(1 + retcount);	

		origlen = outlen;
		if (find_rr(rbt, DNS_TYPE_NSEC)) {
			rbt0 = Lookup_zone(db, q->hdr->name, q->hdr->namelen, DNS_TYPE_NSEC, 0);
			if (rbt0 != NULL) {
				tmplen = additional_nsec(q->hdr->name, q->hdr->namelen, DNS_TYPE_NSEC, rbt0, reply, replysize, outlen, q->aa);
			}
		} else if (find_rr(rbt, DNS_TYPE_NSEC3PARAM)) {
			rbt0 = find_nsec3_match_qname(q->hdr->name, q->hdr->namelen, rbt, db);
			if (rbt0 == NULL)
				goto out;

			memcpy(&uniq[rruniq].name, rbt0->zone, rbt0->zonelen);
			uniq[rruniq++].len = rbt0->zonelen;

			tmplen = additional_nsec3(rbt0->zone, rbt0->zonelen, DNS_TYPE_NSEC3, rbt0, reply, replysize, outlen, &retcount, q->aa);
		}

		if (tmplen == 0) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen) {
			NTOHS(odh->nsrr);
			odh->nsrr += retcount;
			HTONS(odh->nsrr);
		}

		

		rbt0 = find_rrsetwild(db, q->hdr->name, q->hdr->namelen);
		if (rbt0) {
			struct rbtree *ncn, *rbt1;

			ncn = find_closest_encloser_nsec3(rbt0->zone, rbt0->zonelen, rbt, db);
			if (ncn == NULL) {
				goto out;
			}

			tmplen = additional_nsec3(ncn->zone, ncn->zonelen, DNS_TYPE_NSEC3, ncn, reply, replysize, outlen, &retcount, q->aa);

			if (tmplen == 0) {
				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}

			outlen = tmplen;

			NTOHS(odh->nsrr);
			odh->nsrr += retcount;
			HTONS(odh->nsrr);


			rbt1 = find_nsec3_match_qname_wild(q->hdr->name, q->hdr->namelen, rbt, db);

			if (rbt1 == NULL)
				goto out;

			tmplen = additional_nsec3(rbt1->zone, rbt1->zonelen, DNS_TYPE_NSEC3, rbt1, reply, replysize, outlen, &retcount, q->aa);

			if (tmplen == 0) {
				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}

			outlen = tmplen;

			NTOHS(odh->nsrr);
			odh->nsrr += retcount;
			HTONS(odh->nsrr);
		}
	}

	if (replysize < outlen) {
		NTOHS(odh->query);
		SET_DNS_TRUNCATION(odh);
		HTONS(odh->query);
		odh->answer = 0;
		odh->nsrr = 0; 
		odh->additional = 0;
		outlen = rollback;
		goto out;
	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}
	
	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}

int
reply_any(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	uint16_t outlen;

	char *buf = sreply->buf;
	int len = sreply->len;
	struct rbtree *rbt = sreply->rbt1;
	struct question *q = sreply->q;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	uint16_t rollback;
	struct zoneentry *res = NULL;

	if (istcp) {
		replysize = 65535;
	}

	if (! istcp && q->edns0len > 512)
		replysize = MIN(q->edns0len, max_udp_payload);
	
	/* st */

	odh = (struct dns_header *)&reply[0];
	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	/* copy question to reply */
	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	/* blank query */
	memset((char *)&odh->query, 0, sizeof(uint16_t));
	set_reply_flags(NULL, odh, q);

	odh->question = htons(1);
	odh->answer = 0;
	odh->nsrr = 0;
	odh->additional = 0;

	
	/*
	 * Check if we're UDP and have the tcp-on-any-only option set
	 */
	if (!istcp && tcpanyonly == 1) {
		NTOHS(odh->query);
		SET_DNS_TRUNCATION(odh);
		HTONS(odh->query);
		odh->answer = 0;
		odh->nsrr = 0; 
		odh->additional = 0;
		outlen = rollback;
		goto skip;	
	}

	res = zone_findzone(rbt);
	if (res == NULL) {
		dolog(LOG_ERR, "no zoneentry found for %s, this is an error\n", rbt->humanname);
		return -1;
	}

	outlen = create_anyreply(sreply, (char *)reply, replysize, outlen, 1, res->zonenumber, 1);
	if (outlen == 0) {
		return (retlen);
	} else if (istcp == 0 && outlen == 65535) {
		odh->answer = 0;
		odh->nsrr = 0;
		odh->additional = 0;
		outlen = rollback;
	}

	if (dnssec && q->dnssecok && (rbt->flags & RBT_DNSSEC)) {
		if (rbt->flags & RBT_WILDCARD) {
			struct rbtree *authority;
			int retcount, tmplen;

			authority = get_soa(db, q);
			if (authority == NULL) {
				if (q->aa != 1)
					return -1;

				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto skip;
			}
			tmplen = additional_wildcard(q->hdr->name, q->hdr->namelen, authority, reply, replysize, outlen, &retcount, db);
			if (tmplen != 0) {
				outlen = tmplen;
				odh->nsrr = htons(retcount);	
			}
		}
	}

skip:

	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}
			
	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}

/*
 * CREATE_ANYREPLY - pack an entire zone record into an any reply or axfr
 * 
 */

uint16_t
create_anyreply(struct sreply *sreply, char *reply, int rlen, int offset, int soa, uint32_t zonenumberx, uint compress)
{
	int a_count, aaaa_count, ns_count, mx_count, srv_count, sshfp_count;
	int txt_count;
	int tlsa_count, typelen, zonemd_count;
	int ds_count, dnskey_count;
	int naptr_count, rrsig_count;
	int caa_count, rp_count, hinfo_count;
	int tmplen;
	struct answer {
		uint16_t type;		/* 0 */
                uint16_t class;	/* 2 */
                uint32_t ttl;		/* 4 */
                uint16_t rdlength;      /* 8 */
		char rdata[0];		/* 10 */
	} __packed;
	struct answer *answer;
	struct rbtree *rbt = sreply->rbt1;
	struct rrset *rrset = NULL;

	struct rr *rrp = NULL;
	struct question *q = sreply->q;
	struct dns_header *odh = (struct dns_header *)reply;
	int labellen;
	char *label, *plabel;
	uint16_t namelen = 0;
	uint16_t *dnskey_flags;
	uint16_t *ds_keytag;
	uint16_t *nsec3_iterations;
	uint8_t *sshfp_alg, *sshfp_fptype, *ds_alg, *ds_digesttype;
	uint8_t *dnskey_protocol, *dnskey_alg, *tlsa_usage, *tlsa_selector;
	uint8_t *tlsa_matchtype;
	uint8_t *nsec3param_alg, *nsec3param_flags, *nsec3param_saltlen;
	uint8_t *nsec3_alg, *nsec3_flags, *nsec3_saltlen, *nsec3_hashlen;
	char *name, *p;
	int i;
	time_t now;

	now = time(NULL);
	if (soa && (rrset = find_rr(rbt, DNS_TYPE_SOA)) != 0) {
		NTOHS(odh->answer);
		odh->answer++;
		HTONS(odh->answer);

		rrp = TAILQ_FIRST(&rrset->rr_head);
		if (rrp == 0)
			return -1;

		if ((offset + q->hdr->namelen) > rlen) {
			goto truncate;
		}

		memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
		offset += q->hdr->namelen;

		if (compress) {
			if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
				offset = tmplen;
			} 
		}

		answer = (struct answer *)&reply[offset];

		answer->type = htons(DNS_TYPE_SOA);
		answer->class = htons(DNS_CLASS_IN);
		
		if (q->aa)
			answer->ttl = htonl(rrset->ttl);
		else
			answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

		offset += 10;		/* up to rdata length */


		label = ((struct soa *)rrp->rdata)->nsserver;
		labellen = ((struct soa *)rrp->rdata)->nsserver_len;

		plabel = label;

		/* copy label to reply */
		for (i = offset; i < rlen; i++) {
                	if (i - offset == labellen)
                        	break;
                
			reply[i] = *plabel++;
        	}

		if (i >= rlen) {
			goto truncate;
        	}
	
		offset = i;
	
		/* compress the label if possible */
		if (compress) {
			if ((tmplen = compress_label((u_char*)reply, offset, labellen)) > 0) {
				offset = tmplen;
			}
		}

		label = ((struct soa *)rrp->rdata)->responsible_person;
		labellen = ((struct soa *)rrp->rdata)->rp_len;
		plabel = label;

		for (i = offset; i < rlen; i++) {
			if (i - offset == labellen)
				break;

			reply[i] = *plabel++;
		}

		if (i >= rlen) {
			goto truncate;
		}

        	offset = i;

        	/* 2 compress the label if possible */

		if (compress) {
			if ((tmplen = compress_label((u_char*)reply, offset, labellen)) > 0) {
				offset = tmplen;
			}
		}

		if ((offset + sizeof(uint32_t)) > rlen) {
			goto truncate;
        	}

		pack32(&reply[offset], htonl(((struct soa *)rrp->rdata)->serial));
		offset += sizeof(uint32_t);      
        
        	if ((offset + sizeof(uint32_t)) > rlen) {
			goto truncate;
        	}
	
		pack32(&reply[offset], htonl(((struct soa *)rrp->rdata)->refresh));
		offset += sizeof(uint32_t);    

		if ((offset + sizeof(uint32_t)) > rlen) {
			goto truncate;
        	}

		pack32(&reply[offset], htonl(((struct soa *)rrp->rdata)->retry));
		offset += sizeof(uint32_t);       

		if ((offset + sizeof(uint32_t)) > rlen) {
			goto truncate;
		}

		pack32(&reply[offset], htonl(((struct soa *)rrp->rdata)->expire));
		offset += sizeof(uint32_t);

		if ((offset + sizeof(uint32_t)) > rlen) {
			goto truncate;
        	}

		pack32(&reply[offset], htonl(((struct soa *)rrp->rdata)->minttl));
		offset += sizeof(uint32_t);

		answer->rdlength = htons(&reply[offset] - answer->rdata);

	}
	if ((rrset = find_rr(rbt, DNS_TYPE_RRSIG)) != 0) {
		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen,
			-1, rbt, reply, rlen, offset, &rrsig_count, q->aa);

			if (tmplen == 0)
				goto truncate;

			offset = tmplen;

			NTOHS(odh->answer);
			odh->answer += rrsig_count;
			HTONS(odh->answer);
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_CDNSKEY)) != 0) {
		int cdnskey_count;

		cdnskey_count = 0;
		TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
			if (rrp->zonenumber != zonenumberx)
				continue;
			if (offset + q->hdr->namelen > rlen)
				goto truncate;

			memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
			offset += q->hdr->namelen;

			if (compress) {
				if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
					offset = tmplen;
				} 
			}

			answer = (struct answer *)&reply[offset];

			answer->type = htons(DNS_TYPE_CDNSKEY);
			answer->class = htons(DNS_CLASS_IN);
		
			if (q->aa)
				answer->ttl = htonl(rrset->ttl);
			else
				answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

			answer->rdlength = htons(namelen);

			offset += 10;		/* struct answer */

			if (offset + sizeof(*dnskey_flags) + sizeof(*dnskey_protocol) + sizeof(*dnskey_alg) > rlen)
				goto truncate;

			pack16(&reply[offset], htons(((struct cdnskey *)rrp->rdata)->flags));
			offset += sizeof(uint16_t);
			
			dnskey_protocol = (uint8_t *)&reply[offset];
			*dnskey_protocol = ((struct cdnskey *)rrp->rdata)->protocol;
	
			offset++;

			dnskey_alg = (uint8_t *)&reply[offset];
			*dnskey_alg = ((struct cdnskey *)rrp->rdata)->algorithm;

			offset++;

			memcpy(&reply[offset], 
				((struct cdnskey *)rrp->rdata)->public_key,
				((struct cdnskey *)rrp->rdata)->publickey_len);

			offset += ((struct cdnskey *)rrp->rdata)->publickey_len;

			answer->rdlength = htons(&reply[offset] - answer->rdata);

			cdnskey_count++;

		} 

		NTOHS(odh->answer);
		odh->answer += cdnskey_count;
		HTONS(odh->answer);
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_DNSKEY)) != 0) {
		dnskey_count = 0;
		TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
			if (rrp->zonenumber != zonenumberx)
				continue;
			if (offset + q->hdr->namelen > rlen)
				goto truncate;

			memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
			offset += q->hdr->namelen;

			if (compress) {
				if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
					offset = tmplen;
				} 
			}

			answer = (struct answer *)&reply[offset];

			answer->type = htons(DNS_TYPE_DNSKEY);
			answer->class = htons(DNS_CLASS_IN);
		
			if (q->aa)
				answer->ttl = htonl(rrset->ttl);
			else
				answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

			answer->rdlength = htons(namelen);

			offset += 10;		/* struct answer */

			if (offset + sizeof(*dnskey_flags) + sizeof(*dnskey_protocol) + sizeof(*dnskey_alg) > rlen)
				goto truncate;

			pack16(&reply[offset], htons(((struct dnskey *)rrp->rdata)->flags));
			offset += sizeof(uint16_t);
			
			dnskey_protocol = (uint8_t *)&reply[offset];
			*dnskey_protocol = ((struct dnskey *)rrp->rdata)->protocol;
	
			offset++;

			dnskey_alg = (uint8_t *)&reply[offset];
			*dnskey_alg = ((struct dnskey *)rrp->rdata)->algorithm;

			offset++;

			memcpy(&reply[offset], 
				((struct dnskey *)rrp->rdata)->public_key,
				((struct dnskey *)rrp->rdata)->publickey_len);

			offset += ((struct dnskey *)rrp->rdata)->publickey_len;

			answer->rdlength = htons(&reply[offset] - answer->rdata);

			dnskey_count++;

		} 

		NTOHS(odh->answer);
		odh->answer += dnskey_count;
		HTONS(odh->answer);
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_HINFO)) != 0) {
		hinfo_count = 0;

		TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
			if (rrp->zonenumber != zonenumberx)
				continue;
			if (offset + q->hdr->namelen > rlen)
				goto truncate;

			memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
			offset += q->hdr->namelen;

			if (compress) {
				if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
					offset = tmplen;
				} 
			}

			answer = (struct answer *)&reply[offset];

			answer->type = htons(DNS_TYPE_HINFO);
			answer->class = htons(DNS_CLASS_IN);

			if (q->aa)
				answer->ttl = htonl(rrset->ttl);
			else
				answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

			answer->rdlength = htons(namelen);

			offset += 10;		/* struct answer */

			if ((offset + 2 + \
				((struct hinfo *)rrp->rdata)->oslen + \
				((struct hinfo *)rrp->rdata)->cpulen) > rlen)
				goto truncate;

			pack8(&reply[offset++], ((struct hinfo *)rrp->rdata)->cpulen);

			pack(&reply[offset], ((struct hinfo *)rrp->rdata)->cpu,((struct hinfo *)rrp->rdata)->cpulen);
			offset += ((struct hinfo *)rrp->rdata)->cpulen;

			pack8(&reply[offset++], ((struct hinfo *)rrp->rdata)->oslen);
			pack(&reply[offset], ((struct hinfo *)rrp->rdata)->os,((struct hinfo *)rrp->rdata)->oslen);
			offset += ((struct hinfo *)rrp->rdata)->oslen;


			answer->rdlength = htons(&reply[offset] - answer->rdata);

			hinfo_count++;

			NTOHS(odh->answer);
			odh->answer += 1;
			HTONS(odh->answer);

		} 
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_LOC)) != 0) {
		int loc_count = 0;

		TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
			if (rrp->zonenumber != zonenumberx)
				continue;
			if (offset + q->hdr->namelen > rlen)
				goto truncate;

			memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
			offset += q->hdr->namelen;

			if (compress) {
				if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
					offset = tmplen;
				} 
			}

			answer = (struct answer *)&reply[offset];

			answer->type = htons(DNS_TYPE_LOC);
			answer->class = htons(DNS_CLASS_IN);

			if (q->aa)
				answer->ttl = htonl(rrset->ttl);
			else
				answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

			answer->rdlength = htons(namelen);

			offset += 10;		/* struct answer */

			if ((offset + 4 + (3 * sizeof(uint32_t))) > rlen)
				goto truncate;

			pack8(&reply[offset], ((struct loc *)rrp->rdata)->version);
			offset++;
			pack8(&reply[offset], ((struct loc *)rrp->rdata)->size);
			offset++;
			pack8(&reply[offset], ((struct loc *)rrp->rdata)->horiz_pre);
			offset++;
			pack8(&reply[offset], ((struct loc *)rrp->rdata)->vert_pre);
			offset++;


			pack32(&reply[offset], htonl(((struct loc *)rrp->rdata)->latitude));
			offset += 4;
			pack32(&reply[offset], htonl(((struct loc *)rrp->rdata)->longitude));
			offset += 4;
			pack32(&reply[offset], htonl(((struct loc *)rrp->rdata)->altitude));
			offset += 4;
			

			answer->rdlength = htons(&reply[offset] - answer->rdata);

			loc_count++;

			NTOHS(odh->answer);
			odh->answer += 1;
			HTONS(odh->answer);

		} 
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_RP)) != 0) {
		rp_count = 0;

		TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
			if (rrp->zonenumber != zonenumberx)
				continue;
			if (offset + q->hdr->namelen > rlen)
				goto truncate;

			memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
			offset += q->hdr->namelen;

			if (compress) {
				if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
					offset = tmplen;
				} 
			}

			answer = (struct answer *)&reply[offset];

			answer->type = htons(DNS_TYPE_RP);
			answer->class = htons(DNS_CLASS_IN);

			if (q->aa)
				answer->ttl = htonl(rrset->ttl);
			else
				answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

			answer->rdlength = htons(namelen);

			offset += 10;		/* struct answer */

			if ((offset + \
				((struct rp *)rrp->rdata)->mboxlen + \
				((struct rp *)rrp->rdata)->txtlen) > rlen)
				goto truncate;

			pack(&reply[offset], ((struct rp *)rrp->rdata)->mbox,((struct rp *)rrp->rdata)->mboxlen);
			offset += ((struct rp *)rrp->rdata)->mboxlen;

			pack(&reply[offset], ((struct rp *)rrp->rdata)->txt,((struct rp *)rrp->rdata)->txtlen);
			offset += ((struct rp *)rrp->rdata)->txtlen;


			answer->rdlength = htons(&reply[offset] - answer->rdata);

			rp_count++;

			NTOHS(odh->answer);
			odh->answer += 1;
			HTONS(odh->answer);

		} 
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_CAA)) != 0) {
		caa_count = 0;

		TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
			if (rrp->zonenumber != zonenumberx)
				continue;
			if (offset + q->hdr->namelen > rlen)
				goto truncate;

			memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
			offset += q->hdr->namelen;

			if (compress) {
				if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
					offset = tmplen;
				} 
			}

			answer = (struct answer *)&reply[offset];

			answer->type = htons(DNS_TYPE_CAA);
			answer->class = htons(DNS_CLASS_IN);

			if (q->aa)
				answer->ttl = htonl(rrset->ttl);
			else
				answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

			answer->rdlength = htons(namelen);

			offset += 10;		/* struct answer */

			if ((offset + 2 + \
				((struct caa *)rrp->rdata)->taglen + \
				((struct caa *)rrp->rdata)->valuelen) > rlen)
				goto truncate;

			pack8(&reply[offset++], ((struct caa *)rrp->rdata)->flags);
			pack8(&reply[offset++], ((struct caa *)rrp->rdata)->taglen);
			pack(&reply[offset], ((struct caa *)rrp->rdata)->tag,((struct caa *)rrp->rdata)->taglen);
			offset += ((struct caa *)rrp->rdata)->taglen;

			pack(&reply[offset], ((struct caa *)rrp->rdata)->value,((struct caa *)rrp->rdata)->valuelen);
			offset += ((struct caa *)rrp->rdata)->valuelen;


			answer->rdlength = htons(&reply[offset] - answer->rdata);

			caa_count++;

			NTOHS(odh->answer);
			odh->answer += 1;
			HTONS(odh->answer);

		} 
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_CDS)) != 0) {
		int cds_count = 0;

		TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
			if (rrp->zonenumber != zonenumberx)
				continue;
			if (offset + q->hdr->namelen > rlen)
				goto truncate;

			memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
			offset += q->hdr->namelen;

			if (compress) {
				if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
					offset = tmplen;
				} 
			}

			answer = (struct answer *)&reply[offset];

			answer->type = htons(DNS_TYPE_CDS);
			answer->class = htons(DNS_CLASS_IN);

			if (q->aa)
				answer->ttl = htonl(rrset->ttl);
			else
				answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

			answer->rdlength = htons(namelen);

			offset += 10;		/* struct answer */

			if (offset + sizeof(*ds_keytag) + sizeof(*ds_alg) + sizeof(*ds_digesttype) > rlen)
				goto truncate;

			pack16(&reply[offset], htons(((struct cds *)rrp->rdata)->key_tag));
			offset += sizeof(uint16_t);
			
			ds_alg = (uint8_t *)&reply[offset];
			*ds_alg = ((struct cds *)rrp->rdata)->algorithm;
	
			offset++;

			ds_digesttype = (uint8_t *)&reply[offset];
			*ds_digesttype = ((struct cds *)rrp->rdata)->digest_type;

			offset++;

			memcpy(&reply[offset], ((struct cds *)rrp->rdata)->digest,((struct cds *)rrp->rdata)->digestlen);

			offset += ((struct ds *)rrp->rdata)->digestlen;

			answer->rdlength = htons(&reply[offset] - answer->rdata);

			cds_count++;

			NTOHS(odh->answer);
			odh->answer += 1;
			HTONS(odh->answer);

		} 
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_DS)) != 0) {
		ds_count = 0;

		TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
			if (rrp->zonenumber != zonenumberx)
				continue;
			if (offset + q->hdr->namelen > rlen)
				goto truncate;

			memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
			offset += q->hdr->namelen;

			if (compress) {
				if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
					offset = tmplen;
				} 
			}

			answer = (struct answer *)&reply[offset];

			answer->type = htons(DNS_TYPE_DS);
			answer->class = htons(DNS_CLASS_IN);

			if (q->aa)
				answer->ttl = htonl(rrset->ttl);
			else
				answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

			answer->rdlength = htons(namelen);

			offset += 10;		/* struct answer */

			if (offset + sizeof(*ds_keytag) + sizeof(*ds_alg) + sizeof(*ds_digesttype) > rlen)
				goto truncate;

			pack16(&reply[offset], htons(((struct ds *)rrp->rdata)->key_tag));
			offset += sizeof(uint16_t);
			
			ds_alg = (uint8_t *)&reply[offset];
			*ds_alg = ((struct ds *)rrp->rdata)->algorithm;
	
			offset++;

			ds_digesttype = (uint8_t *)&reply[offset];
			*ds_digesttype = ((struct ds *)rrp->rdata)->digest_type;

			offset++;

			memcpy(&reply[offset], ((struct ds *)rrp->rdata)->digest,((struct ds *)rrp->rdata)->digestlen);

			offset += ((struct ds *)rrp->rdata)->digestlen;

			answer->rdlength = htons(&reply[offset] - answer->rdata);

			ds_count++;

			NTOHS(odh->answer);
			odh->answer += 1;
			HTONS(odh->answer);

		} 
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_NSEC3)) != 0) {
		rrp = TAILQ_FIRST(&rrset->rr_head);
		if (rrp == 0)
			return -1;

		if (offset + q->hdr->namelen > rlen)
			goto truncate;

		memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
		offset += q->hdr->namelen;

		if (compress) {
			if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
				offset = tmplen;
			} 
		}

		answer = (struct answer *)&reply[offset];

		answer->type = htons(DNS_TYPE_NSEC3);
		answer->class = htons(DNS_CLASS_IN);

		if (q->aa)
			answer->ttl = htonl(rrset->ttl);
		else
			answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));


		answer->rdlength = htons(namelen);

		offset += 10;		/* struct answer */

		if (offset + sizeof(*nsec3_alg) + sizeof(*nsec3_flags) 
			+ sizeof(*nsec3_iterations) 
			+ sizeof(*nsec3_saltlen)
			+ ((struct nsec3 *)rrp->rdata)->saltlen 
			+ sizeof(*nsec3_hashlen)
			+ ((struct nsec3 *)rrp->rdata)->nextlen 
			+ ((struct nsec3 *)rrp->rdata)->bitmap_len > rlen)
			goto truncate;

		nsec3_alg = (uint8_t *)&reply[offset];
		*nsec3_alg = ((struct nsec3 *)rrp->rdata)->algorithm;

		offset++;

		nsec3_flags = (uint8_t *)&reply[offset];
		*nsec3_flags = ((struct nsec3 *)rrp->rdata)->flags;

		offset++;

		pack16(&reply[offset], htons(((struct nsec3 *)rrp->rdata)->iterations));
		offset += sizeof(uint16_t);

		nsec3_saltlen = (uint8_t *)&reply[offset];
		*nsec3_saltlen = ((struct nsec3 *)rrp->rdata)->saltlen;
		offset++;
	
		memcpy(&reply[offset], &((struct nsec3 *)rrp->rdata)->salt,
			((struct nsec3 *)rrp->rdata)->saltlen);	
		
		offset += ((struct nsec3 *)rrp->rdata)->saltlen;	

		nsec3_hashlen = (uint8_t *)&reply[offset];
		*nsec3_hashlen = ((struct nsec3 *)rrp->rdata)->nextlen;
		offset++;

		memcpy(&reply[offset], &((struct nsec3 *)rrp->rdata)->next,
			((struct nsec3 *)rrp->rdata)->nextlen);	
		
		offset += ((struct nsec3 *)rrp->rdata)->nextlen;

		memcpy(&reply[offset], &((struct nsec3 *)rrp->rdata)->bitmap,
			((struct nsec3 *)rrp->rdata)->bitmap_len);

		offset += ((struct nsec3 *)rrp->rdata)->bitmap_len;

		answer->rdlength = htons(&reply[offset] - answer->rdata);

		NTOHS(odh->answer);
		odh->answer += 1;
		HTONS(odh->answer);

	}
	if ((rrset = find_rr(rbt, DNS_TYPE_NSEC3PARAM)) != 0) {
		rrp = TAILQ_FIRST(&rrset->rr_head);
		if (rrp == 0)
			return -1;

		if (offset + q->hdr->namelen > rlen)
			goto truncate;

		memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
		offset += q->hdr->namelen;

		if (compress) {
			if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
				offset = tmplen;
			} 
		}

		answer = (struct answer *)&reply[offset];

		answer->type = htons(DNS_TYPE_NSEC3PARAM);
		answer->class = htons(DNS_CLASS_IN);

		if (q->aa)
			answer->ttl = htonl(rrset->ttl);
		else
			answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

		answer->rdlength = htons(namelen);

		offset += 10;		/* struct answer */

		if (offset + sizeof(((struct nsec3param *)rrp->rdata)->algorithm)
			+ sizeof(((struct nsec3param *)rrp->rdata)->flags) 
			+ sizeof(((struct nsec3param *)rrp->rdata)->iterations)
			+ sizeof(((struct nsec3param *)rrp->rdata)->saltlen) > rlen)
			goto truncate;

		nsec3param_alg = (uint8_t *)&reply[offset];
		*nsec3param_alg = ((struct nsec3param *)rrp->rdata)->algorithm;

		offset++;

		nsec3param_flags = (uint8_t *)&reply[offset];
		*nsec3param_flags = ((struct nsec3param *)rrp->rdata)->flags;

		offset++;

		pack16(&reply[offset], htons(((struct nsec3param *)rrp->rdata)->iterations));
		offset += sizeof(uint16_t);

		nsec3param_saltlen = (uint8_t *)&reply[offset];
		*nsec3param_saltlen = ((struct nsec3param *)rrp->rdata)->saltlen;

		offset++;
	
		memcpy(&reply[offset], &((struct nsec3param *)rrp->rdata)->salt,
			((struct nsec3param *)rrp->rdata)->saltlen);	
		
		offset += ((struct nsec3param *)rrp->rdata)->saltlen;

		answer->rdlength = htons(&reply[offset] - answer->rdata);


		NTOHS(odh->answer);
		odh->answer += 1;
		HTONS(odh->answer);

	}
	if ((rrset = find_rr(rbt, DNS_TYPE_NSEC)) != 0) {
		rrp = TAILQ_FIRST(&rrset->rr_head);
		if (rrp == 0)
			return -1;

		if (offset + q->hdr->namelen > rlen)
			goto truncate;

		memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
		offset += q->hdr->namelen;

		if (compress) {
			if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
				offset = tmplen;
			} 
		}

		answer = (struct answer *)&reply[offset];

		answer->type = htons(DNS_TYPE_NSEC);
		answer->class = htons(DNS_CLASS_IN);

		if (q->aa)
			answer->ttl = htonl(rrset->ttl);
		else
			answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

		answer->rdlength = htons(namelen);

		offset += 10;		/* struct answer */

		if (offset + ((struct nsec *)rrp->rdata)->ndn_len > rlen)
			goto truncate;

		memcpy((char *)&answer->rdata, (char *)((struct nsec *)rrp->rdata)->next_domain_name, ((struct nsec *)rrp->rdata)->ndn_len);

		offset += ((struct nsec *)rrp->rdata)->ndn_len;

		if (offset + ((struct nsec *)rrp->rdata)->bitmap_len > rlen)
			goto truncate;
			
		memcpy((char *)&reply[offset], ((struct nsec *)rrp->rdata)->bitmap, ((struct nsec *)rrp->rdata)->bitmap_len);

		offset += ((struct nsec *)rrp->rdata)->bitmap_len;
		
		answer->rdlength = htons(&reply[offset] - answer->rdata);


		NTOHS(odh->answer);
		odh->answer += 1;
		HTONS(odh->answer);

	}
	if ((rrset = find_rr(rbt, DNS_TYPE_NS)) != 0) {
		ns_count = 0;

		TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
			if (rrp->zonenumber != zonenumberx)
				continue;
			if (offset + q->hdr->namelen > rlen)
				goto truncate;

			memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
			offset += q->hdr->namelen;

			if (compress) {
				if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
					offset = tmplen;
				} 
			}

			answer = (struct answer *)&reply[offset];

			answer->type = htons(DNS_TYPE_NS);
			answer->class = htons(DNS_CLASS_IN);

			if (q->aa)
				answer->ttl = htonl(rrset->ttl);
			else
				answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

			answer->rdlength = htons(namelen);

			offset += 10;		/* struct answer */

			name = ((struct ns *)rrp->rdata)->nsserver;
			namelen = ((struct ns *)rrp->rdata)->nslen;

			if (offset + namelen > rlen)
				goto truncate;

			memcpy((char *)&answer->rdata, (char *)name, namelen);

			offset += namelen;
			
			/* compress the label if possible */
			if (compress) {
				if ((tmplen = compress_label((u_char*)reply, offset, namelen)) > 0) {
					offset = tmplen;
				}
			}

			answer->rdlength = htons(&reply[offset] - answer->rdata);

			ns_count++;
		}

		NTOHS(odh->answer);
		odh->answer += ns_count;
		HTONS(odh->answer);

	}
	if ((rrset = find_rr(rbt, DNS_TYPE_PTR)) != 0) {

		rrp = TAILQ_FIRST(&rrset->rr_head);
		if (rrp == 0)
			return -1;

		NTOHS(odh->answer);
		odh->answer++;
		HTONS(odh->answer);

		if ((offset + q->hdr->namelen) > rlen) {
			goto truncate;
		}

		memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
		offset += q->hdr->namelen;

		if (compress) {
			if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
				offset = tmplen;
			} 
		}

		answer = (struct answer *)&reply[offset];

		answer->type = htons(DNS_TYPE_PTR);
		answer->class = htons(DNS_CLASS_IN);
		
		if (q->aa)
			answer->ttl = htonl(rrset->ttl);
		else
			answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

		offset += 10;		/* up to rdata length */

		label = ((struct ptr *)rrp->rdata)->ptr;
		labellen = ((struct ptr *)rrp->rdata)->ptrlen;

		plabel = label;

		/* copy label to reply */
		for (i = offset; i < rlen; i++) {
                	if (i - offset == labellen)
                        	break;
                
			reply[i] = *plabel++;
        	}

		if (i >= rlen) {
			goto truncate;
        	}
	
		offset = i;
	
		/* compress the label if possible */
		if (compress) {
			if ((tmplen = compress_label((u_char*)reply, offset, labellen)) > 0) {
				offset = tmplen;
			}
		}

		answer->rdlength = htons(&reply[offset] - answer->rdata);
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_MX)) != 0) {

		mx_count = 0;
		TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
			if (rrp->zonenumber != zonenumberx)
				continue;
			if ((offset + q->hdr->namelen) > rlen) {
				goto truncate;
			}

			memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
			offset += q->hdr->namelen;

			if (compress) {
				if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
					offset = tmplen;
				} 
			}

		
			if (offset + 12 > rlen)
				goto truncate;

			answer = (struct answer *)&reply[offset];

			answer->type = htons(DNS_TYPE_MX);
			answer->class = htons(DNS_CLASS_IN);

			if (q->aa)
				answer->ttl = htonl(rrset->ttl);
			else
				answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

			answer->rdlength = htons(sizeof(uint16_t) + ((struct smx *)rrp->rdata)->exchangelen);

			offset += 10;		/* up to rdata length */
			
			pack16(&reply[offset], htons(((struct smx *)rrp->rdata)->preference));
			offset += sizeof(uint16_t);

			if (offset + ((struct smx *)rrp->rdata)->exchangelen > rlen)
				goto truncate;

			memcpy((char *)&reply[offset], (char *)((struct smx *)rrp->rdata)->exchange, ((struct smx *)rrp->rdata)->exchangelen);

			offset += ((struct smx *)rrp->rdata)->exchangelen;

			if (compress) {
				if ((tmplen = compress_label((u_char*)reply, offset, ((struct smx *)rrp->rdata)->exchangelen)) > 0) {
					offset = tmplen;
				} 
			}

			answer->rdlength = htons(&reply[offset] - answer->rdata);
			mx_count++;
		}

		NTOHS(odh->answer);
		odh->answer += mx_count;
		HTONS(odh->answer);

	}
	if ((rrset = find_rr(rbt, DNS_TYPE_TXT)) != 0) {
		txt_count = 0;
		TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
			if (rrp->zonenumber != zonenumberx)
				continue;

			if ((offset + q->hdr->namelen) > rlen) {
				goto truncate;
			}

			memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
			offset += q->hdr->namelen;

			if (compress) {
				if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
					offset = tmplen;
				} 
			}

			answer = (struct answer *)&reply[offset];


			if (offset + 10 > rlen)
				goto truncate;

			answer->type = htons(DNS_TYPE_TXT);
			answer->class = htons(DNS_CLASS_IN);
		
			if (q->aa)
				answer->ttl = htonl(rrset->ttl);
			else
				answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

			offset += 10;		/* up to rdata length */

			if (offset + ((struct txt *)rrp->rdata)->txtlen > rlen)
				goto truncate;

			p = (char *)&answer->rdata;
			memcpy(p, ((struct txt *)rrp->rdata)->txt, ((struct txt *)rrp->rdata)->txtlen);
			offset += (((struct txt *)rrp->rdata)->txtlen);

			answer->rdlength = htons(((struct txt *)rrp->rdata)->txtlen);

			txt_count++;

		}

		NTOHS(odh->answer);
		odh->answer += txt_count;
		HTONS(odh->answer);
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_ZONEMD)) != 0) {

		zonemd_count = 0;
		TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
			if (rrp->zonenumber != zonenumberx)
				continue;
			if ((offset + q->hdr->namelen) > rlen) {
				goto truncate;
			}

			memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
			offset += q->hdr->namelen;

			if (compress) {
				if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
					offset = tmplen;
				} 
			}

		
			if (offset + 12 > rlen)
				goto truncate;

			answer = (struct answer *)&reply[offset];

			answer->type = htons(DNS_TYPE_ZONEMD);
			answer->class = htons(DNS_CLASS_IN);
	
			if (q->aa)
				answer->ttl = htonl(rrset->ttl);
			else
				answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

			typelen = ((struct zonemd *)rrp->rdata)->hashlen;
			answer->rdlength = htons((2 * sizeof(uint8_t)) + sizeof(uint32_t) + typelen);

			offset += 10;		/* up to rdata length */

			if (offset + typelen > rlen)
				goto truncate;
			
			pack32(&reply[offset], htonl(((struct zonemd *)rrp->rdata)->serial));
			offset += 4;
			pack8(&reply[offset++], ((struct zonemd *)rrp->rdata)->scheme);
			pack8(&reply[offset++], ((struct zonemd *)rrp->rdata)->algorithm);
			pack(&reply[offset], ((struct zonemd *)rrp->rdata)->hash, ((struct zonemd *)rrp->rdata)->hashlen);

			offset += ((struct zonemd *)rrp->rdata)->hashlen;

			answer->rdlength = htons(&reply[offset] - answer->rdata);
			zonemd_count++;
		}

		NTOHS(odh->answer);
		odh->answer += zonemd_count;
		HTONS(odh->answer);

	}

	if ((rrset = find_rr(rbt, DNS_TYPE_TLSA)) != 0) {

		tlsa_count = 0;
		TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
			if (rrp->zonenumber != zonenumberx)
				continue;
			if ((offset + q->hdr->namelen) > rlen) {
				goto truncate;
			}

			memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
			offset += q->hdr->namelen;

			if (compress) {
				if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
					offset = tmplen;
				} 
			}

		
			if (offset + 12 > rlen)
				goto truncate;

			answer = (struct answer *)&reply[offset];

			answer->type = htons(DNS_TYPE_TLSA);
			answer->class = htons(DNS_CLASS_IN);
	
			if (q->aa)
				answer->ttl = htonl(rrset->ttl);
			else
				answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

			typelen = ((struct tlsa *)rrp->rdata)->matchtype == 1 ? DNS_TLSA_SIZE_SHA256 : DNS_TLSA_SIZE_SHA512;
			answer->rdlength = htons((3 * sizeof(uint8_t)) + typelen);

			offset += 10;		/* up to rdata length */
			
			tlsa_usage = (uint8_t *)&reply[offset];
			*tlsa_usage = ((struct tlsa *)rrp->rdata)->usage;

			offset++;

			tlsa_selector = (uint8_t *)&reply[offset];
			*tlsa_selector = ((struct tlsa *)rrp->rdata)->selector;

			offset++;

			tlsa_matchtype = (uint8_t *)&reply[offset];
			*tlsa_matchtype = ((struct tlsa *)rrp->rdata)->matchtype;

			offset++;

			if (offset + ((struct tlsa *)rrp->rdata)->datalen > rlen)
				goto truncate;

			memcpy((char *)&reply[offset], (char *)((struct tlsa *)rrp->rdata)->data, ((struct tlsa *)rrp->rdata)->datalen);

			offset += ((struct tlsa *)rrp->rdata)->datalen;

			answer->rdlength = htons(&reply[offset] - answer->rdata);
			tlsa_count++;
		}

		NTOHS(odh->answer);
		odh->answer += tlsa_count;
		HTONS(odh->answer);

	}
	if ((rrset = find_rr(rbt, DNS_TYPE_SSHFP)) != 0) {

		sshfp_count = 0;
		TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
			if (rrp->zonenumber != zonenumberx)
				continue;
			if ((offset + q->hdr->namelen) > rlen) {
				goto truncate;
			}

			memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
			offset += q->hdr->namelen;

			if (compress) {
				if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
					offset = tmplen;
				} 
			}

		
			if (offset + 12 > rlen)
				goto truncate;

			answer = (struct answer *)&reply[offset];

			answer->type = htons(DNS_TYPE_SSHFP);
			answer->class = htons(DNS_CLASS_IN);
			if (q->aa)
				answer->ttl = htonl(rrset->ttl);
			else
				answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

			answer->rdlength = htons((2 * sizeof(uint8_t)) + ((struct sshfp *)rrp->rdata)->fplen);

			offset += 10;		/* up to rdata length */
			
			sshfp_alg = (uint8_t *)&reply[offset];
			*sshfp_alg = ((struct sshfp *)rrp->rdata)->algorithm;

			offset++;

			sshfp_fptype = (uint8_t *)&reply[offset];
			*sshfp_fptype = ((struct sshfp *)rrp->rdata)->fptype;

			offset++;

			if (offset + ((struct sshfp *)rrp->rdata)->fplen > rlen)
				goto truncate;

			memcpy((char *)&reply[offset], (char *)((struct sshfp *)rrp->rdata)->fingerprint, ((struct sshfp *)rrp->rdata)->fplen);

			offset += ((struct sshfp *)rrp->rdata)->fplen;

			answer->rdlength = htons(&reply[offset] - answer->rdata);
			sshfp_count++;
		}

		NTOHS(odh->answer);
		odh->answer += sshfp_count;
		HTONS(odh->answer);

	}
	if ((rrset = find_rr(rbt, DNS_TYPE_NAPTR)) != 0) {
		naptr_count = 0;
		TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
			if (rrp->zonenumber != zonenumberx)
				continue;
			if ((offset + q->hdr->namelen) > rlen) {
				goto truncate;
			}

			memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
			offset += q->hdr->namelen;

			if (compress) {
				if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
					offset = tmplen;
				} 
			}

		
			if (offset + 12 > rlen)
				goto truncate;

			answer = (struct answer *)&reply[offset];

			answer->type = htons(DNS_TYPE_NAPTR);
			answer->class = htons(DNS_CLASS_IN);
			if (q->aa)
				answer->ttl = htonl(rrset->ttl);
			else
				answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

			answer->rdlength = htons((2 * sizeof(uint16_t)) + ((struct naptr *)rrp->rdata)->flagslen + 1 + ((struct naptr *)rrp->rdata)->serviceslen + 1 + ((struct naptr *)rrp->rdata)->regexplen + 1 + ((struct naptr *)rrp->rdata)->replacementlen);

			offset += 10;		/* up to rdata length */
			
			pack16(&reply[offset], htons(((struct naptr *)rrp->rdata)->order));
			offset += sizeof(uint16_t);

			pack16(&reply[offset], htons(((struct naptr *)rrp->rdata)->preference));
			offset += sizeof(uint16_t);

			/* flags */
			if (offset + ((struct naptr *)rrp->rdata)->flagslen + 1> rlen)
				goto truncate;

			reply[offset] = ((struct naptr *)rrp->rdata)->flagslen;
			offset++;

			memcpy((char *)&reply[offset], (char *)((struct naptr *)rrp->rdata)->flags, ((struct naptr *)rrp->rdata)->flagslen);

			offset += ((struct naptr *)rrp->rdata)->flagslen;
			/* services */
			if (offset + ((struct naptr *)rrp->rdata)->serviceslen + 1 > rlen)
				goto truncate;

			reply[offset] = ((struct naptr *)rrp->rdata)->serviceslen;
			offset++;

			memcpy((char *)&reply[offset], (char *)((struct naptr *)rrp->rdata)->services, ((struct naptr *)rrp->rdata)->serviceslen);

			offset += ((struct naptr *)rrp->rdata)->serviceslen;
			/* regexp */
			if (offset + ((struct naptr *)rrp->rdata)->regexplen + 1> rlen)
				goto truncate;

			reply[offset] = ((struct naptr *)rrp->rdata)->regexplen;
			offset++;

			memcpy((char *)&reply[offset], (char *)((struct naptr *)rrp->rdata)->regexp, ((struct naptr *)rrp->rdata)->regexplen);

			offset += ((struct naptr *)rrp->rdata)->regexplen;
			/* replacement */
			if (offset + ((struct naptr *)rrp->rdata)->replacementlen > rlen)
				goto truncate;

			memcpy((char *)&reply[offset], (char *)((struct naptr *)rrp->rdata)->replacement, ((struct naptr *)rrp->rdata)->replacementlen);

			offset += ((struct naptr *)rrp->rdata)->replacementlen;

			if (compress) {
				if ((tmplen = compress_label((u_char*)reply, offset, ((struct naptr *)rrp->rdata)->replacementlen)) > 0) {
					offset = tmplen;
				} 
			}

			answer->rdlength = htons(&reply[offset] - answer->rdata);
			naptr_count++;
		}

		NTOHS(odh->answer);
		odh->answer += naptr_count;
		HTONS(odh->answer);

	}
	if ((rrset = find_rr(rbt, DNS_TYPE_SRV)) != 0) {
		srv_count = 0;
		TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
			if (rrp->zonenumber != zonenumberx)
				continue;
			if ((offset + q->hdr->namelen) > rlen) {
				goto truncate;
			}

			memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
			offset += q->hdr->namelen;

			if (compress) {
				if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
					offset = tmplen;
				} 
			}

		
			if (offset + 12 > rlen)
				goto truncate;

			answer = (struct answer *)&reply[offset];

			answer->type = htons(DNS_TYPE_SRV);
			answer->class = htons(DNS_CLASS_IN);
			if (q->aa)
				answer->ttl = htonl(rrset->ttl);
			else
				answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

			answer->rdlength = htons((3 * sizeof(uint16_t)) + ((struct srv *)rrp->rdata)->targetlen);

			offset += 10;		/* up to rdata length */
			
			pack16(&reply[offset], htons(((struct srv *)rrp->rdata)->priority));
			offset += sizeof(uint16_t);

			pack16(&reply[offset], htons(((struct srv *)rrp->rdata)->weight));
			offset += sizeof(uint16_t);

			pack16(&reply[offset], htons(((struct srv *)rrp->rdata)->port));
			offset += sizeof(uint16_t);

			if (offset + ((struct srv *)rrp->rdata)->targetlen > rlen)
				goto truncate;

			memcpy((char *)&reply[offset], (char *)((struct srv *)rrp->rdata)->target, ((struct srv *)rrp->rdata)->targetlen);

			offset += ((struct srv *)rrp->rdata)->targetlen;

			if (compress) {
				if ((tmplen = compress_label((u_char*)reply, offset, ((struct srv *)rrp->rdata)->targetlen)) > 0) {
					offset = tmplen;
				} 
			}

			answer->rdlength = htons(&reply[offset] - answer->rdata);
			srv_count++;
		}

		NTOHS(odh->answer);
		odh->answer += srv_count;
		HTONS(odh->answer);

	}

	if ((rrset = find_rr(rbt, DNS_TYPE_CNAME)) != 0) {
		rrp = TAILQ_FIRST(&rrset->rr_head);
		if (rrp == 0)
			return -1;

		NTOHS(odh->answer);
		odh->answer++;
		HTONS(odh->answer);

		if ((offset + q->hdr->namelen) > rlen) {
			goto truncate;
		}

		memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
		offset += q->hdr->namelen;

		if (compress) {
			if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
				offset = tmplen;
			} 
		}

		answer = (struct answer *)&reply[offset];

		answer->type = htons(DNS_TYPE_CNAME);
		answer->class = htons(DNS_CLASS_IN);
		if (q->aa)
			answer->ttl = htonl(rrset->ttl);
		else
			answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));
				

		offset += 10;		/* up to rdata length */

		label = ((struct cname *)rrp->rdata)->cname;
		labellen = ((struct cname *)rrp->rdata)->cnamelen;

		plabel = label;

		/* copy label to reply */
		for (i = offset; i < rlen; i++) {
                	if (i - offset == labellen)
                        	break;
                
			reply[i] = *plabel++;
        	}

		if (i >= rlen) {
			goto truncate;
        	}
	
		offset = i;
	
		/* compress the label if possible */
		if (compress) {
        		if ((tmplen = compress_label((u_char*)reply, offset, labellen)) > 0) {
                		offset = tmplen;
        		}
		}

		answer->rdlength = htons(&reply[offset] - answer->rdata);
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_A)) != 0) {
		a_count = 0;

		TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
			if (rrp->zonenumber != zonenumberx)
				continue;
			if (offset + q->hdr->namelen > rlen)
				goto truncate;

			memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
			offset += q->hdr->namelen;

			if (compress) {
				if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
					offset = tmplen;
				} 
			}

			answer = (struct answer *)&reply[offset];

			answer->type = htons(DNS_TYPE_A);
			answer->class = htons(DNS_CLASS_IN);

			if (q->aa)
				answer->ttl = htonl(rrset->ttl);
			else
				answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

			answer->rdlength = htons(sizeof(in_addr_t));

			memcpy((char *)&answer->rdata, (char *)&((struct a *)rrp->rdata)->a, 
				sizeof(in_addr_t));			

			a_count++;
			offset += 14;

			answer = (struct answer *)&reply[offset];

		}

		NTOHS(odh->answer);
		odh->answer += a_count;
		HTONS(odh->answer);
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_AAAA)) != 0) {
		aaaa_count = 0;

		TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
			if (rrp->zonenumber != zonenumberx)
				continue;
			if (offset + q->hdr->namelen > rlen)
				goto truncate;

			memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
			offset += q->hdr->namelen;

			if (compress) {
				if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
					offset = tmplen;
				} 
			}

			answer = (struct answer *)&reply[offset];

			answer->type = htons(DNS_TYPE_AAAA);
			answer->class = htons(DNS_CLASS_IN);
			if (q->aa)
				answer->ttl = htonl(rrset->ttl);
			else
				answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

			answer->rdlength = htons(sizeof(struct in6_addr));
			offset += 10;

 			memcpy((char *)&reply[offset] ,(char *)&((struct aaaa *)rrp->rdata)->aaaa, sizeof(struct in6_addr));
			offset += 16;

			aaaa_count++;
		}

		NTOHS(odh->answer);
		odh->answer += aaaa_count;
		HTONS(odh->answer);
	}

	return (offset);

truncate:
	NTOHS(odh->query);
	SET_DNS_TRUNCATION(odh);
	HTONS(odh->query);

	return (65535);
}

/* 
 * REPLY_BADVERS() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_badvers(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	uint16_t outlen;

	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;

	if (istcp) {
		replysize = 65535;
	}

	if (!istcp && q->edns0len > 512)
		replysize = MIN(q->edns0len, max_udp_payload);
	
	odh = (struct dns_header *)&reply[0];
	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);

	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
	memset((char *)&odh->query, 0, sizeof(uint16_t));

	outlen += (q->hdr->namelen + 4);

	SET_DNS_REPLY(odh);

	HTONS(odh->query);

	odh->question = htons(1);
	odh->answer = 0;
	odh->nsrr = 0;
	odh->additional = 0;

	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		q->badvers = 1;
		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}


/* 
 * REPLY_NODATA() - replies a DNS question (*q) on socket (so) based on 
 *		 	reply_badvers().
 *
 */

int
reply_nodata(struct sreply *sreply, int *sretlen, ddDB *db)
{
	return (reply_noerror(sreply, sretlen, db));
}

/* 
 * REPLY_GENERIC() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_generic(struct sreply *sreply, int *sretlen, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	uint16_t outlen = 0;
	int gen_count;

	struct answer {
		char name[2];
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
		in_addr_t rdata;		/* 16 */
	} __attribute__((packed));

	struct answer *answer;

	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;

	struct rbtree *rbt = sreply->rbt1;
	struct rbtree *authority;
	struct rrset *rrset = NULL;
	struct rr *rrp;
	
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	uint16_t rollback;
	time_t now;
	uint32_t zonenumberx;

	zonenumberx = determine_zone(rbt);
	now = time(NULL);

	if ((rrset = find_rr(rbt, ntohs(q->hdr->qtype))) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}
	
	if (!istcp && q->edns0len > 512)
		replysize = MIN(q->edns0len, max_udp_payload);

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	memset((char *)&odh->query, 0, sizeof(uint16_t));
	set_reply_flags(rbt, odh, q);

	odh->question = htons(1);
	odh->answer = htons(0);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	gen_count = 0;

	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		if (rrp->zonenumber != zonenumberx)
			continue;
		/* can we afford to write another header? if no truncate */
		if ((outlen + 12 + rrp->rdlen) > replysize) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}
		/*
		 * answer->name is a pointer to the request (0xc00c) 
		 */

		answer->name[0] = 0xc0;				/* 1 byte */
		answer->name[1] = 0x0c;				/* 2 bytes */
		answer->type = q->hdr->qtype;			/* 4 bytes */	
		answer->class = q->hdr->qclass;			/* 6 bytes */

		if (q->aa)
			answer->ttl = htonl(rrset->ttl); 		/* 10 b */
		else
			answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

		answer->rdlength = htons(rrp->rdlen);

		memcpy((char *)&answer->rdata, (char *)rrp->rdata, 
			rrp->rdlen);

		gen_count++;
		outlen += (12 + rrp->rdlen);

		/* set new offset for answer */
		answer = (struct answer *)&reply[outlen];
	} 

	odh->answer = htons(gen_count);

	/* Add RRSIG reply_a */
	if (dnssec && q->dnssecok && (rbt->flags & RBT_DNSSEC)) {
		int tmplen = 0;
		int origlen = outlen;
		int retcount;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, ntohs(q->hdr->qtype), rbt, reply, replysize, outlen, &retcount, q->aa);
	
		if (tmplen == 0) {
			/* we're forwarding and had no RRSIG return with -1 */
			if (q->aa != 1)
				return -1;

			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			odh->answer = 0;
			odh->nsrr = 0; 
			odh->additional = 0;
			outlen = rollback;
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->answer = htons(gen_count + retcount);	

		if (rbt->flags & RBT_WILDCARD) {
			authority = get_soa(db, q);
			if (authority == NULL) {
				if (q->aa != 1)
					return -1;

				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				odh->answer = 0;
				odh->nsrr = 0; 
				odh->additional = 0;
				outlen = rollback;
				goto out;
			}
			tmplen = additional_wildcard(q->hdr->name, q->hdr->namelen, authority, reply, replysize, outlen, &retcount, db);
			if (tmplen != 0) {
				outlen = tmplen;
				odh->nsrr = htons(retcount);	
			}
		}
			
	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen, sreply->sa, sreply->salen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL, DEFAULT_TSIG_FUDGE);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	return (reply_sendpacket(reply, outlen, sreply, sretlen));
}

void
set_reply_flags(struct rbtree *rbt, struct dns_header *odh, struct question *q)
{
	NTOHS(odh->query);		/* just in case */

	SET_DNS_REPLY(odh);

	if (q->aa)
		SET_DNS_AUTHORITATIVE(odh);

	if (q->rd) {
		SET_DNS_RECURSION(odh);
			
		if (! q->aa) {
			SET_DNS_RECURSION_AVAIL(odh);

			if (rbt && dnssec && q->dnssecok && 
					(rbt->flags & RBT_DNSSEC)) {
				SET_DNS_AUTHENTIC_DATA(odh);
			}
		}
	}

	HTONS(odh->query);
}

int
reply_sendpacket(char *reply, uint16_t len, struct sreply *sreply, int *sretlen)
{
	int so = sreply->so;
	struct question *q = sreply->q;
	struct sockaddr *sa = sreply->sa;
	socklen_t salen = sreply->salen;

	int retlen = -1;
	int istcp = sreply->istcp;
	char *tmpbuf;

	if (istcp) {

		tmpbuf = malloc(len + 2);
		if (tmpbuf == 0) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
			return (-1);
		}
		pack16(tmpbuf, htons(len));
		memcpy(&tmpbuf[2], reply, len);

		if ((retlen = send(so, tmpbuf, len + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if (q && q->rawsocket) {
			*sretlen = retlen = len;
		} else {
			if ((*sretlen = retlen = sendto(so, 
					reply, len, 0, sa, salen)) < 0) {
				dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
			}
		}
	}

	return (retlen);
}


static uint32_t
determine_zone(struct rbtree *rbt)
{
	struct zoneentry *res = NULL;
	uint32_t zonenumberx = (uint32_t)-1;

	if (rbt->flags & RBT_CACHE) {
		zonenumberx = (uint32_t)-1;
	} else {
		res = zone_findzone(rbt);
		if (res != NULL)
			zonenumberx = res->zonenumber;
		else
			zonenumberx = (uint32_t)-1;
	}

	return (zonenumberx);
}
