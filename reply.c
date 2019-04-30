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
 * $Id: reply.c,v 1.77 2019/04/30 10:21:00 pjp Exp $
 */

#include "ddd-include.h"
#include "ddd-dns.h"
#include "ddd-db.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>


/* prototypes */

extern int     		checklabel(ddDB *, struct rbtree *, struct rbtree *, struct question *);
extern int 		additional_nsec3(char *, int, int, struct rbtree *, char *, int, int);
extern int 		additional_a(char *, int, struct rbtree *, char *, int, int, int *);
extern int 		additional_aaaa(char *, int, struct rbtree *, char *, int, int, int *);
extern int 		additional_mx(char *, int, struct rbtree *, char *, int, int, int *);
extern int 		additional_ptr(char *, int, struct rbtree *, char *, int, int, int *);
extern int 		additional_opt(struct question *, char *, int, int);
extern int 		additional_tsig(struct question *, char *, int, int, int, int, HMAC_CTX *);
extern int 		additional_rrsig(char *, int, int, struct rbtree *, char *, int, int, int);
extern int 		additional_nsec(char *, int, int, struct rbtree *, char *, int, int);
extern struct question 	*build_fake_question(char *, int, u_int16_t, char *, int);
extern int 		compress_label(u_char *, int, int);
extern void 		dolog(int, char *, ...);
extern int 		free_question(struct question *);
extern struct rbtree * 	lookup_zone(ddDB *, struct question *, int *, int *, char *);
extern void 		slave_shutdown(void);
extern int 		get_record_size(ddDB *, char *, int);
extern char *		dns_label(char *, int *);

extern struct rbtree * find_rrset(ddDB *db, char *name, int len);
extern struct rrset * find_rr(struct rbtree *rbt, u_int16_t rrtype);
extern int display_rr(struct rrset *rrset);
extern int rotate_rr(struct rrset *rrset);


struct rbtree 	*Lookup_zone(ddDB *, char *, u_int16_t, u_int16_t, int);
u_int16_t 	create_anyreply(struct sreply *, char *, int, int, int);
int 		reply_a(struct sreply *, ddDB *);
int		reply_nsec3(struct sreply *, ddDB *);
int		reply_nsec3param(struct sreply *, ddDB *);
int		reply_nsec(struct sreply *, ddDB *);
int		reply_dnskey(struct sreply *, ddDB *);
int		reply_ds(struct sreply *, ddDB *);
int		reply_rrsig(struct sreply *, ddDB *);
int 		reply_aaaa(struct sreply *, ddDB *);
int 		reply_mx(struct sreply *, ddDB *);
int 		reply_ns(struct sreply *, ddDB *);
int 		reply_notimpl(struct sreply *, ddDB *);
int 		reply_nxdomain(struct sreply *, ddDB *);
int 		reply_noerror(struct sreply *, ddDB *);
int		reply_badvers(struct sreply *, ddDB *);
int		reply_nodata(struct sreply *, ddDB *);
int 		reply_soa(struct sreply *, ddDB *);
int 		reply_ptr(struct sreply *, ddDB *);
int 		reply_txt(struct sreply *, ddDB *);
int 		reply_version(struct sreply *, ddDB *);
int 		reply_srv(struct sreply *, ddDB *);
int 		reply_naptr(struct sreply *, ddDB *);
int 		reply_sshfp(struct sreply *, ddDB *);
int		reply_tlsa(struct sreply *, ddDB *);
int 		reply_cname(struct sreply *, ddDB *);
int 		reply_any(struct sreply *, ddDB *);
int 		reply_refused(struct sreply *, ddDB *);
int 		reply_fmterror(struct sreply *, ddDB *);
int 		reply_notauth(struct sreply *, ddDB *);
struct rbtree * find_nsec(char *name, int namelen, struct rbtree *, ddDB *db);
int 		nsec_comp(const void *a, const void *b);
char * 		convert_name(char *name, int namelen);
int 		count_dots(char *name);
char * 		base32hex_encode(u_char *input, int len);
struct rbtree * find_nsec3_cover_next_closer(char *name, int namelen, struct rbtree *, ddDB *db);
struct rbtree * find_nsec3_match_closest(char *name, int namelen, struct rbtree *, ddDB *db);
struct rbtree * find_nsec3_wildcard_closest(char *name, int namelen, struct rbtree *, ddDB *db);
struct rbtree * find_nsec3_match_qname(char *name, int namelen, struct rbtree *, ddDB *db);

extern int debug, verbose, dnssec;
extern char *versionstring;
extern uint8_t vslen;



/* 
 * REPLY_A() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_a(struct sreply *sreply, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	u_int16_t outlen = 0;
	int a_count;

	struct answer {
		char name[2];
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 /* 12 */
		in_addr_t rdata;		/* 16 */
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
	struct rr *rrp;
	
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	u_int16_t rollback;

	if ((rrset = find_rr(rbt, DNS_TYPE_A)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}
	
	if (!istcp && q->edns0len > 512)
		replysize = q->edns0len;

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	SET_DNS_REPLY(odh);
	SET_DNS_AUTHORITATIVE(odh);

	if (q->rd) {
		SET_DNS_RECURSION(odh);
	}

	HTONS(odh->query);

	odh->question = htons(1);
	odh->answer = htons(0);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	a_count = 0;

	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		/*
		 * answer->name is a pointer to the request (0xc00c) 
		 */

		answer->name[0] = 0xc0;				/* 1 byte */
		answer->name[1] = 0x0c;				/* 2 bytes */
		answer->type = q->hdr->qtype;			/* 4 bytes */	
		answer->class = q->hdr->qclass;			/* 6 bytes */
		answer->ttl = htonl(((struct a *)rrp->rdata)->ttl); /* 10 b */

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
	if (dnssec && q->dnssecok && rbt->dnssec) {
		int tmplen = 0;
		int origlen = outlen;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_A, rbt, reply, replysize, outlen, 0);
	
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

		if (outlen > origlen)
			odh->answer = htons(a_count + 1);	

	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	if (istcp) {
		char *tmpbuf;
		u_int16_t *plen;

		tmpbuf = malloc(outlen + 2);
		if (tmpbuf == 0) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
		}
		plen = (u_int16_t *)tmpbuf;
		*plen = htons(outlen);
		
		memcpy(&tmpbuf[2], reply, outlen);

		if ((retlen = send(so, tmpbuf, outlen + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if ((retlen = sendto(so, reply, outlen, 0, sa, salen)) < 0) {
			dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
		}
	}

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
reply_nsec3param(struct sreply *sreply, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	u_int16_t outlen = 0;
	int a_count;

	struct answer {
		char name[2];
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 /* 12 */
		u_int8_t algorithm;
		u_int8_t flags;
		u_int16_t iterations;
		u_int8_t saltlen;
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
	struct rr *rrp = NULL;
	
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	u_int16_t rollback;
	int saltlen;

	if ((rrset = find_rr(rbt, DNS_TYPE_NSEC3PARAM)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}
	
	if (!istcp && q->edns0len > 512)
		replysize = q->edns0len;

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	SET_DNS_REPLY(odh);
	SET_DNS_AUTHORITATIVE(odh);

	if (q->rd) {
		SET_DNS_RECURSION(odh);
	}

	HTONS(odh->query);

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
	answer->ttl = htonl(((struct nsec3param *)rrp->rdata)->ttl);

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
	if (dnssec && q->dnssecok && rbt->dnssec) {
		int tmplen = 0;
		int origlen = outlen;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_NSEC3PARAM, rbt, reply, replysize, outlen, 0);
		
		if (tmplen == 0) {
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
			odh->answer = htons(a_count + 1 + 1);	
	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}


	if (istcp) {
		char *tmpbuf;
		u_int16_t *plen;

		tmpbuf = malloc(outlen + 2);
		if (tmpbuf == 0) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
		}
		plen = (u_int16_t *)tmpbuf;
		*plen = htons(outlen);
		
		memcpy(&tmpbuf[2], reply, outlen);

		if ((retlen = send(so, tmpbuf, outlen + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if ((retlen = sendto(so, reply, outlen, 0, sa, salen)) < 0) {
			dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
		}
	}

	return (retlen);
}


/* 
 * REPLY_NSEC3() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_nsec3(struct sreply *sreply, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	u_int16_t outlen = 0;
	int a_count;

	struct answer {
		char name[2];
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 /* 12 */
		u_int8_t algorithm;
		u_int8_t flags;
		u_int16_t iterations;
		u_int8_t saltlen;
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
	struct rr *rrp = NULL;
	
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	u_int16_t rollback;
	u_int8_t *somelen;
	int bitmaplen, saltlen, nextlen;

	if ((rrset = find_rr(rbt, DNS_TYPE_A)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}
	
	if (!istcp && q->edns0len > 512)
		replysize = q->edns0len;


	/* RFC 5155 section 7.2.8 */
	/* perhaps we are accompanied by an rrsig */
	if (find_rr(rbt, DNS_TYPE_NSEC3) && find_rr(rbt, DNS_TYPE_RRSIG)) {
		return (reply_nxdomain(sreply, db));
	}
	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	SET_DNS_REPLY(odh);
	SET_DNS_AUTHORITATIVE(odh);

	if (q->rd) {
		SET_DNS_RECURSION(odh);
	}

	HTONS(odh->query);

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
	answer->ttl = htonl(((struct nsec3 *)rrp->rdata)->ttl); /* 10 b */
	
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

	somelen = (u_int8_t *)&reply[outlen];
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
	if (dnssec && q->dnssecok && rbt->dnssec) {
		int tmplen = 0;
		int origlen = outlen;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_NSEC3, rbt, reply, replysize, outlen, 0);
		
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

		if (outlen > origlen)
			odh->answer = htons(a_count + 1 + 1);	
	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	if (istcp) {
		char *tmpbuf;
		u_int16_t *plen;

		tmpbuf = malloc(outlen + 2);
		if (tmpbuf == 0) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
		}
		plen = (u_int16_t *)tmpbuf;
		*plen = htons(outlen);
		
		memcpy(&tmpbuf[2], reply, outlen);

		if ((retlen = send(so, tmpbuf, outlen + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if ((retlen = sendto(so, reply, outlen, 0, sa, salen)) < 0) {
			dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
		}
	}

	return (retlen);
}

/* 
 * REPLY_NSEC() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_nsec(struct sreply *sreply, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	u_int16_t outlen = 0;
	int a_count;

	struct answer {
		char name[2];
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 /* 12 */
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
	struct rr *rrp = NULL;	
	
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	u_int16_t rollback;
	int ndnlen, bitmaplen;

	if ((rrset = find_rr(rbt, DNS_TYPE_A)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}
	
	if (!istcp && q->edns0len > 512)
		replysize = q->edns0len;

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	SET_DNS_REPLY(odh);
	SET_DNS_AUTHORITATIVE(odh);

	if (q->rd) {
		SET_DNS_RECURSION(odh);
	}

	HTONS(odh->query);

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
	answer->ttl = htonl(((struct nsec *)rrp->rdata)->ttl); /* 10 b */

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
	if (dnssec && q->dnssecok && rbt->dnssec) {
		int tmplen = 0;
		int origlen = outlen;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_NSEC, rbt, reply, replysize, outlen, 0);
		
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

		if (outlen > origlen)
			odh->answer = htons(a_count + 1 + 1);	

	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	if (istcp) {
		char *tmpbuf;
		u_int16_t *plen;

		tmpbuf = malloc(outlen + 2);
		if (tmpbuf == 0) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
		}
		plen = (u_int16_t *)tmpbuf;
		*plen = htons(outlen);
		
		memcpy(&tmpbuf[2], reply, outlen);

		if ((retlen = send(so, tmpbuf, outlen + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if ((retlen = sendto(so, reply, outlen, 0, sa, salen)) < 0) {
			dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
		}
	}


	return (retlen);
}

/* 
 * REPLY_DS() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_ds(struct sreply *sreply, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	u_int16_t outlen = 0;
	int a_count;

	struct answer {
		char name[2];
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 /* 12 */
		u_int16_t key_tag;
		u_int8_t algorithm;
		u_int8_t digest_type;
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
	struct rr *rrp = NULL;
	
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	u_int16_t rollback;

	if ((rrset = find_rr(rbt, DNS_TYPE_DS)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}
	
	if (!istcp && q->edns0len > 512)
		replysize = q->edns0len;

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	SET_DNS_REPLY(odh);
	SET_DNS_AUTHORITATIVE(odh);

	if (q->rd) {
		SET_DNS_RECURSION(odh);
	}

	HTONS(odh->query);

	odh->question = htons(1);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	a_count = 0;

	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
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
		answer->ttl = htonl(((struct ds *)rrp->rdata)->ttl); /* 10 */

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
	if (dnssec && q->dnssecok && rbt->dnssec) {
		int tmplen = 0;
		int origlen = outlen;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_DS, rbt, reply, replysize, outlen, 0);
		
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

		if (outlen > origlen)
			odh->answer = htons(a_count + 1 + 1);	
	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	if (istcp) {
		char *tmpbuf;
		u_int16_t *plen;

		tmpbuf = malloc(outlen + 2);
		if (tmpbuf == 0) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
		}
		plen = (u_int16_t *)tmpbuf;
		*plen = htons(outlen);
		
		memcpy(&tmpbuf[2], reply, outlen);

		if ((retlen = send(so, tmpbuf, outlen + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if ((retlen = sendto(so, reply, outlen, 0, sa, salen)) < 0) {
			dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
		}
	}

	rotate_rr(rrset);

	return (retlen);
}

/* 
 * REPLY_DNSKEY() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_dnskey(struct sreply *sreply, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	u_int16_t outlen = 0;
	int dnskey_count;

	struct answer {
		char name[2];
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 /* 12 */
		u_int16_t flags;
		u_int8_t protocol;
		u_int8_t algorithm;
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
	struct rrset *rrset2 = NULL;
	struct rr *rrp = NULL;
	
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	int rrsig_count = 0;
	u_int16_t rollback;

	if ((rrset = find_rr(rbt, DNS_TYPE_DNSKEY)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}
	
	if (!istcp && q->edns0len > 512)
		replysize = q->edns0len;

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	SET_DNS_REPLY(odh);
	SET_DNS_AUTHORITATIVE(odh);

	if (q->rd) {
		SET_DNS_RECURSION(odh);
	}

	HTONS(odh->query);

	odh->question = htons(1);
	odh->answer = htons(0);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	dnskey_count = 0;

	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
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
		answer->ttl = htonl(((struct dnskey *)rrp->rdata)->ttl);

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
	if (dnssec && q->dnssecok && rbt->dnssec) {
		int tmplen = 0;
		int origlen = outlen;
	
		if ((rrset2 = find_rr(rbt, DNS_TYPE_RRSIG)) == 0)
			goto out;


		rrsig_count = 0;
		TAILQ_FOREACH(rrp, &rrset2->rr_head, entries) {
			if (((struct rrsig *)rrp->rdata)->type_covered != DNS_TYPE_DNSKEY)
				continue;

			origlen = outlen; 

			tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_DNSKEY, rbt, reply, replysize, outlen, rrsig_count);
		
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

			rrsig_count++;
			if (outlen > origlen)
				odh->answer = htons(dnskey_count + rrsig_count);	
		}

	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	if (istcp) {
		char *tmpbuf;
		u_int16_t *plen;

		tmpbuf = malloc(outlen + 2);
		if (tmpbuf == 0) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
		}
		plen = (u_int16_t *)tmpbuf;
		*plen = htons(outlen);
		
		memcpy(&tmpbuf[2], reply, outlen);

		if ((retlen = send(so, tmpbuf, outlen + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if ((retlen = sendto(so, reply, outlen, 0, sa, salen)) < 0) {
			dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
		}
	}

	return (retlen);
}

/*
 * REPLY_RRSIG() - replies a DNS question (*q) on socket (so)
 *
 */


int		
reply_rrsig(struct sreply *sreply, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	u_int16_t outlen = 0;
	int a_count;

	struct answer {
		char name[2];
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 /* 12 */
		in_addr_t rdata;		/* 16 */
	} __attribute__((packed));

	int so = sreply->so;
	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct sockaddr *sa = sreply->sa;
	int salen = sreply->salen;
	struct rbtree *rbt = sreply->rbt1;
	struct rrset *rrset = NULL;
#if 0
	struct rr *rrp = NULL;
#endif
	
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	int tmplen = 0;
	u_int16_t rollback;

	if ((find_rr(rbt, DNS_TYPE_RRSIG)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}
	
	if (! istcp && q->edns0len > 512)
		replysize = q->edns0len;

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	SET_DNS_REPLY(odh);
	SET_DNS_AUTHORITATIVE(odh);

	if (q->rd) {
		SET_DNS_RECURSION(odh);
	}

	HTONS(odh->query);

	odh->question = htons(1);
	odh->nsrr = 0;
	odh->additional = 0;

	a_count = 0;

	TAILQ_FOREACH(rrset, &rbt->rrset_head, entries) {
		if (rrset->rrtype == DNS_TYPE_DNSKEY) {
			odh->answer = htons(a_count++);
			tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_DNSKEY, rbt, reply, replysize, outlen, 0);
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
		} else  {
			odh->answer = htons(a_count++);
			tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, rrset->rrtype, rbt, reply, replysize, outlen, 0);
			if (tmplen == 0) {
				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				goto out;
			}
			outlen = tmplen;
		}
	}

	odh->answer = htons(a_count);

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	if (istcp) {
		char *tmpbuf;
		u_int16_t *plen;

		tmpbuf = malloc(outlen + 2);
		if (tmpbuf == 0) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
		}
		plen = (u_int16_t *)tmpbuf;
		*plen = htons(outlen);
		
		memcpy(&tmpbuf[2], reply, outlen);

		if ((retlen = send(so, tmpbuf, outlen + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if ((retlen = sendto(so, reply, outlen, 0, sa, salen)) < 0) {
			dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
		}
	}

	return (retlen);


}

/* 
 * REPLY_AAAA() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_aaaa(struct sreply *sreply, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	u_int16_t outlen = 0;
	int aaaa_count;

	struct answer {
		char name[2];
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 /* 12 */
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
	struct rr *rrp = NULL;
	struct rrset *rrset = NULL;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	u_int16_t rollback;

	if ((rrset = find_rr(rbt, DNS_TYPE_AAAA)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}

	if (! istcp && q->edns0len > 512)
		replysize = q->edns0len;
	

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	SET_DNS_REPLY(odh);
	SET_DNS_AUTHORITATIVE(odh);
	
	if (q->rd) {
		SET_DNS_RECURSION(odh);
	}

	HTONS(odh->query);

	odh->question = htons(1);
	odh->answer = htons(0);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
			q->hdr->namelen + 4);
		

	aaaa_count = 0;

	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		answer->name[0] = 0xc0;
		answer->name[1] = 0x0c;
		answer->type = q->hdr->qtype;
		answer->class = q->hdr->qclass;
		answer->ttl = htonl(((struct aaaa *)rrp->rdata)->ttl);

		answer->rdlength = htons(sizeof(struct in6_addr));

		memcpy((char *)&answer->rdata, (char *)&((struct aaaa *)rrp->rdata)->aaaa, sizeof(struct in6_addr));
		outlen += 28;

		aaaa_count++;

		/* set new offset for answer */
		answer = (struct answer *)&reply[outlen];
	};

	odh->answer = htons(aaaa_count);

	/* RRSIG reply_aaaa */
	if (dnssec && q->dnssecok && rbt->dnssec) {
		int tmplen = 0;
		int origlen = outlen;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_AAAA, rbt, reply, replysize, outlen, 0);
	
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

		if (outlen > origlen)
			odh->answer = htons(aaaa_count + 1);	

	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}


	if (istcp) {
		char *tmpbuf;
		u_int16_t *plen;

		tmpbuf = malloc(outlen + 2);
		if (tmpbuf == 0) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
		}
		plen = (u_int16_t *)tmpbuf;
		*plen = htons(outlen);
	
		memcpy(&tmpbuf[2], reply, outlen);

		if ((retlen = send(so, tmpbuf, outlen + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if ((retlen = sendto(so, reply, outlen, 0, sa, salen)) < 0) {
			dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
		}
	}

	rotate_rr(rrset);

	return (retlen);
}

/* 
 * REPLY_MX() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_mx(struct sreply *sreply, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	int mx_count;
	u_int16_t *plen;
	char *name;
	u_int16_t outlen = 0;
	u_int16_t namelen;
	int tmplen = 0;

	struct answer {
		char name[2];
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 /* 12 */
		u_int16_t mx_priority;
		char exchange;
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
	struct rr *rrp = NULL;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	u_int16_t rollback;
	
	if ((rrset = find_rr(rbt, DNS_TYPE_MX)) == 0)
		return -1;


	if (istcp) {
		replysize = 65535;
	}
	
	if (! istcp && q->edns0len > 512)
		replysize = q->edns0len;

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	SET_DNS_REPLY(odh);
	SET_DNS_AUTHORITATIVE(odh);
	
	if (q->rd) {
		SET_DNS_RECURSION(odh);
	}

	HTONS(odh->query);

	odh->question = htons(1);
	odh->answer = htons(0);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	mx_count = 0;

	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		answer->name[0] = 0xc0;
		answer->name[1] = 0x0c;
		answer->type = q->hdr->qtype;
		answer->class = q->hdr->qclass;
		answer->ttl = htonl(((struct smx *)rrp->rdata)->ttl);

		answer->rdlength = htons(sizeof(u_int16_t) + ((struct smx *)rrp->rdata)->exchangelen);

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

		/* set new offset for answer */
		answer = (struct answer *)&reply[outlen];
		mx_count++;
	} 

	odh->answer = htons(mx_count);

	/* RRSIG reply_mx*/

	if (dnssec && q->dnssecok && rbt->dnssec) {
		int origlen = outlen;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_MX, rbt, reply, replysize, outlen, 0);

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

		if (outlen > origlen)
			odh->answer = htons(mx_count + 1);	

	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL);

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
		plen = (u_int16_t *)tmpbuf;
		*plen = htons(outlen);
			
		memcpy(&tmpbuf[2], reply, outlen);
		if ((retlen = send(so, tmpbuf, outlen + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if ((retlen = sendto(so, reply, outlen, 0, sa, salen)) < 0) {
			dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
		}
	}

	return (retlen);
}

/* 
 * REPLY_NS() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_ns(struct sreply *sreply, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	int tmplen = 0;
	int ns_count;
	u_int16_t *plen;
	char *name;
	u_int16_t outlen = 0;
	u_int16_t namelen;

	struct answer {
		char name[2];
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 /* 12 */
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
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	u_int16_t rollback;
	int ns_type;

	if ((rrset = find_rr(rbt, DNS_TYPE_NS)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}

	if (! istcp && q->edns0len > 512)
		replysize = q->edns0len;
	
	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);

	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;
	
	SET_DNS_REPLY(odh);
	SET_DNS_AUTHORITATIVE(odh);

	if (q->rd) {
		SET_DNS_RECURSION(odh);
	}
	
	HTONS(odh->query);

	odh->question = htons(1);
	odh->answer = 0;
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	ns_count = 0;

	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		answer->name[0] = 0xc0;
		answer->name[1] = 0x0c;
		answer->type = htons(DNS_TYPE_NS);
		answer->class = q->hdr->qclass;
		answer->ttl = htonl(((struct ns *)rrp->rdata)->ttl);

		name = ((struct ns *)rrp->rdata)->nsserver;
		namelen = ((struct ns *)rrp->rdata)->nslen;
		ns_type = ((struct ns *)rrp->rdata)->ns_type;

		answer->rdlength = htons(namelen);

		memcpy((char *)&answer->ns, (char *)name, namelen);

		outlen += (12 + namelen);

		/* compress the label if possible */
		if ((tmplen = compress_label((u_char*)reply, outlen, namelen)) > 0) {
			/* XXX */
			outlen = tmplen;
		}

		answer->rdlength = htons(&reply[outlen] - &answer->ns);


		/* set new offset for answer */
		answer = (struct answer *)&reply[outlen];
		ns_count++;
	} 

	switch (ns_type) {
	case NS_TYPE_DELEGATE:
		odh->answer = 0;
		odh->nsrr = htons(ns_count);	
		break;
	default:
		odh->answer = htons(ns_count);
		odh->nsrr = 0;
		break;
	}


	/* add RRSIG reply_ns */
	if (dnssec && q->dnssecok && rbt->dnssec) {
		int origlen = outlen;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_NS, rbt, reply, replysize, outlen, 0);

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
			if (odh->answer)
				odh->answer = htons(ns_count + 1);	
			else if (odh->nsrr)
				odh->nsrr = htons(ns_count + 1);	
		}
	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL);

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
		plen = (u_int16_t *)tmpbuf;
		*plen = htons(outlen);
		
		memcpy(&tmpbuf[2], reply, outlen);
		if ((retlen = send(so, tmpbuf, outlen + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if ((retlen = sendto(so, reply, outlen, 0, sa, salen)) < 0) {
			dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
		}
	}

	rotate_rr(rrset);

	return (retlen);
}


/* 
 * REPLY_CNAME() - replies a DNS question (*q) on socket (so)
 *
 */


int
reply_cname(struct sreply *sreply, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	u_int16_t outlen;
	char *p;
	int i, tmplen;
	int labellen;
	char *label, *plabel;
	int addcount;
	u_int16_t *plen;

	struct answer {
		char name[2];
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 /* 12 */
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
	struct rbtree *rbt1 = sreply->rbt2;
	struct rr *rrp = NULL;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	u_int16_t rollback;

	if ((rrset = find_rr(rbt, DNS_TYPE_CNAME)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}

	if (! istcp && q->edns0len > 512)
		replysize = q->edns0len;

	odh = (struct dns_header *)&reply[0];
	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	/* copy question to reply */
	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);

	/* blank query */
	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	SET_DNS_REPLY(odh);
	SET_DNS_AUTHORITATIVE(odh);

	if (q->rd) {
		SET_DNS_RECURSION(odh);
	}

	HTONS(odh->query);

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
	answer->ttl = htonl(((struct cname *)rrp->rdata)->ttl);

	outlen += 12;			/* up to rdata length */

	p = (char *)&answer->rdata;

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

	if (dnssec && q->dnssecok && rbt->dnssec) {
		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_CNAME, rbt, reply, replysize, outlen, 0);
	
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

		NTOHS(odh->answer);
		odh->answer++;
		HTONS(odh->answer);
	}
	
	if (ntohs(q->hdr->qtype) == DNS_TYPE_A && rbt1 != 0) {
		tmplen = additional_a(((struct cname *)rrp->rdata)->cname, ((struct cname *)rrp->rdata)->cnamelen, rbt1, reply, replysize, outlen, &addcount);

		if (tmplen > 0)
			outlen = tmplen;

		NTOHS(odh->answer);
		odh->answer += addcount;
		HTONS(odh->answer);

		if (dnssec && q->dnssecok && rbt1->dnssec) {
			tmplen = additional_rrsig(((struct cname *)rrp->rdata)->cname, ((struct cname *)rrp->rdata)->cnamelen, DNS_TYPE_A, rbt1, reply, replysize, outlen, 0);
		
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

			NTOHS(odh->answer);
			odh->answer++;
			HTONS(odh->answer);
		}
	} else if (ntohs(q->hdr->qtype) == DNS_TYPE_AAAA && rbt1 != 0) {
		tmplen = additional_aaaa(((struct cname *)rrp->rdata)->cname, ((struct cname *)rrp->rdata)->cnamelen, rbt1, reply, replysize, outlen, &addcount);

		if (tmplen > 0)
			outlen = tmplen;

		NTOHS(odh->answer);
		odh->answer += addcount;
		HTONS(odh->answer);

		if (dnssec && q->dnssecok && rbt1->dnssec) {
			tmplen = additional_rrsig(((struct cname *)rrp->rdata)->cname, ((struct cname *)rrp->rdata)->cnamelen, DNS_TYPE_AAAA, rbt1, reply, replysize, outlen, 0);
		
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

			NTOHS(odh->answer);
			odh->answer++;
			HTONS(odh->answer);
		}
	} else if (ntohs(q->hdr->qtype) == DNS_TYPE_MX && rbt1 != 0) {
		tmplen = additional_mx(((struct cname *)rrp->rdata)->cname, ((struct cname *)rrp->rdata)->cnamelen, rbt1, reply, replysize, outlen, &addcount);

		if (tmplen > 0)
			outlen = tmplen;

		NTOHS(odh->answer);
		odh->answer += addcount;
		HTONS(odh->answer);

		if (dnssec && q->dnssecok && rbt1->dnssec) {
			tmplen = additional_rrsig(((struct cname *)rrp->rdata)->cname, ((struct cname *)rrp->rdata)->cnamelen, DNS_TYPE_MX, rbt1, reply, replysize, outlen, 0);
		
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

			NTOHS(odh->answer);
			odh->answer++;
			HTONS(odh->answer);
		}
	} else if (ntohs(q->hdr->qtype) == DNS_TYPE_PTR && rbt1 != 0) {
		tmplen = additional_ptr(((struct cname *)rrp->rdata)->cname, ((struct cname *)rrp->rdata)->cnamelen, rbt1, reply, replysize, outlen, &addcount);

		if (tmplen > 0)
			outlen = tmplen;

		NTOHS(odh->answer);
		odh->answer += addcount;
		HTONS(odh->answer);

		if (dnssec && q->dnssecok && rbt1->dnssec) {
			tmplen = additional_rrsig(((struct cname *)rrp->rdata)->cname, ((struct cname *)rrp->rdata)->cnamelen, DNS_TYPE_PTR, rbt1, reply, replysize, outlen, 0);
		
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

			NTOHS(odh->answer);
			odh->answer++;
			HTONS(odh->answer);
		}
	}	

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL);

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
		plen = (u_int16_t *)tmpbuf;
		*plen = htons(outlen);
			
		memcpy(&tmpbuf[2], reply, outlen);

		if ((retlen = send(so, tmpbuf, outlen + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if ((retlen = sendto(so, reply, outlen, 0, sa, salen)) < 0) {
			dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
		}	
	}

	return (retlen);
}

/* 
 * REPLY_PTR() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_ptr(struct sreply *sreply, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	u_int16_t outlen;
	char *p;
	int i, tmplen;
	int labellen;
	char *label, *plabel;

	struct answer {
		char name[2];
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 /* 12 */
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
	struct rr *rrp = NULL;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	u_int16_t rollback;

	if ((rrset = find_rr(rbt, DNS_TYPE_PTR)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}

	if (! istcp && q->edns0len > 512)
		replysize = q->edns0len;
	
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
	/* blank query */
	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	SET_DNS_REPLY(odh);
	SET_DNS_AUTHORITATIVE(odh);
	
	if (q->rd) {
		SET_DNS_RECURSION(odh);
	}


	HTONS(odh->query);

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
	answer->ttl = htonl(((struct ptr *)rrp->rdata)->ttl);

	outlen += 12;			/* up to rdata length */

	p = (char *)&answer->rdata;

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

	if (dnssec && q->dnssecok && rbt->dnssec) {
		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_PTR, rbt, reply, replysize, outlen, 0);

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

		NTOHS(odh->answer);
		odh->answer++;
		HTONS(odh->answer);

	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen);
	}
	
	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	if (istcp) {
		char *tmpbuf;
		u_int16_t *plen;

		tmpbuf = malloc(outlen + 2);
		if (tmpbuf == 0) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
		}
		plen = (u_int16_t *)tmpbuf;
		*plen = htons(outlen);
		
		memcpy(&tmpbuf[2], reply, outlen);

		if ((retlen = send(so, tmpbuf, outlen + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if ((retlen = sendto(so, reply, outlen, 0, sa, salen)) < 0) {
			dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
		}
	}

	return (retlen);
}

/* 
 * REPLY_SOA() - replies a DNS question (*q) on socket (so)
 *
 */


int
reply_soa(struct sreply *sreply, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	u_int16_t outlen;
	char *p;
	u_int32_t *soa_val;
	int i, tmplen;
	int labellen;
	char *label, *plabel;

	struct answer {
		char name[2];
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 /* 12 */
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
	struct rr *rrp = NULL;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	u_int16_t rollback;

	if ((rrset = find_rr(rbt, DNS_TYPE_SOA)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}

	if (! istcp && q->edns0len > 512)
		replysize = q->edns0len;
	
	/* st */

	odh = (struct dns_header *)&reply[0];
	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	/* copy question to reply */
	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
	/* blank query */
	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	SET_DNS_REPLY(odh);
	SET_DNS_AUTHORITATIVE(odh);
	
	if (q->rd) {
		SET_DNS_RECURSION(odh);
	}

	NTOHS(odh->query);

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
	answer->ttl = htonl(((struct soa *)rrp->rdata)->ttl);

	outlen += 12;			/* up to rdata length */

	p = (char *)&answer->rdata;


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


	if (outlen + sizeof(u_int32_t) > replysize) {
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(((struct soa *)rrp->rdata)->serial);
	outlen += sizeof(u_int32_t);
	
	if ((outlen + sizeof(u_int32_t)) > replysize) {
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(((struct soa *)rrp->rdata)->refresh);
	outlen += sizeof(u_int32_t);

	if ((outlen + sizeof(u_int32_t)) > replysize) {
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(((struct soa *)rrp->rdata)->retry);
	outlen += sizeof(u_int32_t);

	if ((outlen + sizeof(u_int32_t)) > replysize) {
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(((struct soa *)rrp->rdata)->expire);
	outlen += sizeof(u_int32_t);

	if ((outlen + sizeof(u_int32_t)) > replysize) {
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(((struct soa *)rrp->rdata)->minttl);
	outlen += sizeof(u_int32_t);

	answer->rdlength = htons(&reply[outlen] - &answer->rdata);

	/* RRSIG reply_soa */
	if (dnssec && q->dnssecok && rbt->dnssec) {
		int tmplen = 0;
		int origlen = outlen;
	
		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_SOA, rbt, reply, replysize, outlen, 0);
	
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
			NTOHS(odh->answer);
			odh->answer++;
			HTONS(odh->answer);
		}
	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen);
	}

	
	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	if (istcp) {
		char *tmpbuf;
		u_int16_t *plen;

		tmpbuf = malloc(outlen + 2);
		if (tmpbuf == 0) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
		}
		plen = (u_int16_t *)tmpbuf;
		*plen = htons(outlen);
		
		memcpy(&tmpbuf[2], reply, outlen);

		if ((retlen = send(so, tmpbuf, outlen + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if ((retlen = sendto(so, reply, outlen, 0, sa, salen)) < 0) {
			dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
		}
	}

	return (retlen);
}

/* 
 * REPLY_TXT() - replies a DNS question (*q) on socket (so)
 *
 */


int
reply_txt(struct sreply *sreply, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	u_int16_t outlen;
	char *p;

	struct answer {
		char name[2];
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 /* 12 */
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
	struct rr *rrp = NULL;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	u_int16_t rollback;

	if ((rrset = find_rr(rbt, DNS_TYPE_TXT)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}

	if (! istcp && q->edns0len > 512)
		replysize = q->edns0len;
	
	/* st */

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
	/* blank query */
	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	SET_DNS_REPLY(odh);
	SET_DNS_AUTHORITATIVE(odh);
	
	if (q->rd) {
		SET_DNS_RECURSION(odh);
	}

	HTONS(odh->query);

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
	answer->ttl = htonl(((struct txt *)rrp->rdata)->ttl);

	outlen += 12;			/* up to rdata length */

	p = (char *)&answer->rdata;

	memcpy(p, ((struct txt *)rrp->rdata)->txt, ((struct txt *)rrp->rdata)->txtlen);
	outlen += (((struct txt *)rrp->rdata)->txtlen);

	answer->rdlength = htons(((struct txt *)rrp->rdata)->txtlen);

	/* Add RRSIG reply_txt */
	if (dnssec && q->dnssecok && rbt->dnssec) {
		int tmplen = 0;
		int origlen = outlen;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_TXT, rbt, reply, replysize, outlen, 0);
	
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

		if (outlen > origlen)
			odh->answer = htons(2);	

	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}


	if (istcp) {
		char *tmpbuf;
		u_int16_t *plen;

		tmpbuf = malloc(outlen + 2);
		if (tmpbuf == 0) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
		}
		plen = (u_int16_t *)tmpbuf;
		*plen = htons(outlen);
		
		memcpy(&tmpbuf[2], reply, outlen);

		if ((retlen = send(so, tmpbuf, outlen + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if ((retlen = sendto(so, reply, outlen, 0, sa, salen)) < 0) {
			dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
		}
	}

	return (retlen);
}


/* 
 * REPLY_VERSION() - replies a DNS question (*q) on socket (so)
 *
 */


int
reply_version(struct sreply *sreply, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	u_int16_t outlen;
	char *p;

	struct answer {
		char name[2];
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 /* 12 */
		char rdata;		
	} __attribute__((packed));

	struct answer *answer;

	int so = sreply->so;
	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct sockaddr *sa = sreply->sa;
	int salen = sreply->salen;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	u_int16_t rollback;

	if (istcp) {
		replysize = 65535;
	}

	if (! istcp && q->edns0len > 512)
		replysize = q->edns0len;
	
	/* st */

	odh = (struct dns_header *)&reply[0];
	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	/* copy question to reply */
	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
	/* blank query */
	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	SET_DNS_REPLY(odh);
	SET_DNS_AUTHORITATIVE(odh);
	
	if (q->rd) {
		SET_DNS_RECURSION(odh);
	}

	HTONS(odh->query);

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

		outlen = additional_opt(q, reply, replysize, outlen);
	}

	if (istcp) {
		char *tmpbuf;
		u_int16_t *plen;

		tmpbuf = malloc(outlen + 2);
		if (tmpbuf == 0) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
		}
		plen = (u_int16_t *)tmpbuf;
		*plen = htons(outlen);
		
		memcpy(&tmpbuf[2], reply, outlen);

		if ((retlen = send(so, tmpbuf, outlen + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if ((retlen = sendto(so, reply, outlen, 0, sa, salen)) < 0) {
			dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
		}
	}

	return (retlen);
}

/* 
 * REPLY_TLSA() - replies a DNS question (*q) on socket (so)
 *			(based on reply_sshfp)
 */


int
reply_tlsa(struct sreply *sreply, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	int tlsa_count;
	u_int16_t *plen;
	u_int16_t outlen;

	struct answer {
		char name[2];
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 /* 12 */
		u_int8_t usage; 
		u_int8_t selector;
		u_int8_t matchtype;
		char target;
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
	struct rr *rrp = NULL;
	int istcp = sreply->istcp;
	int typelen = 0;
	int replysize = 512;
	int retlen = -1;
	u_int16_t rollback;

	if ((rrset = find_rr(rbt, DNS_TYPE_TLSA)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}

	if (! istcp && q->edns0len > 512)
		replysize = q->edns0len;
	

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	SET_DNS_REPLY(odh);
	SET_DNS_AUTHORITATIVE(odh);
	
	if (q->rd) {
		SET_DNS_RECURSION(odh);
	}

	HTONS(odh->query);

	odh->question = htons(1);
	odh->answer = htons(0);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	tlsa_count = 0;
	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		answer->name[0] = 0xc0;
		answer->name[1] = 0x0c;
		answer->type = q->hdr->qtype;
		answer->class = q->hdr->qclass;
		answer->ttl = htonl(((struct tlsa *)rrp->rdata)->ttl);

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

		answer->rdlength = htons((3 * sizeof(u_int8_t)) + typelen); 
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
	if (dnssec && q->dnssecok && rbt->dnssec) {
		int tmplen = 0;
		int origlen = outlen;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_TLSA, rbt, reply, replysize, outlen, 0);
	
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

		if (outlen > origlen)
			odh->answer = htons(tlsa_count + 1);	

	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL);

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
		plen = (u_int16_t *)tmpbuf;
		*plen = htons(outlen);
			
		memcpy(&tmpbuf[2], reply, outlen);
		if ((retlen = send(so, tmpbuf, outlen + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if ((retlen = sendto(so, reply, outlen, 0, sa, salen)) < 0) {
			dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
		}
	}

	return (retlen);
}


/* 
 * REPLY_SSHFP() - replies a DNS question (*q) on socket (so)
 *			(based on reply_srv)
 */


int
reply_sshfp(struct sreply *sreply, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	int sshfp_count;
	u_int16_t *plen;
	u_int16_t outlen;

	struct answer {
		char name[2];
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 /* 12 */
		u_int8_t sshfp_alg;
		u_int8_t sshfp_type;
		char target;
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
	struct rr *rrp = NULL;
	int istcp = sreply->istcp;
	int typelen = 0;
	int replysize = 512;
	int retlen = -1;
	u_int16_t rollback;

	if ((rrset = find_rr(rbt, DNS_TYPE_SSHFP)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}

	if (! istcp && q->edns0len > 512)
		replysize = q->edns0len;
	

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	SET_DNS_REPLY(odh);
	SET_DNS_AUTHORITATIVE(odh);
	
	if (q->rd) {
		SET_DNS_RECURSION(odh);
	}

	HTONS(odh->query);

	odh->question = htons(1);
	odh->answer = htons(0);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	sshfp_count = 0;
	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		answer->name[0] = 0xc0;
		answer->name[1] = 0x0c;
		answer->type = q->hdr->qtype;
		answer->class = q->hdr->qclass;
		answer->ttl = htonl(((struct sshfp *)rrp->rdata)->ttl);

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

		answer->rdlength = htons((2 * sizeof(u_int8_t)) + typelen); 
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
	if (dnssec && q->dnssecok && rbt->dnssec) {
		int tmplen = 0;
		int origlen = outlen;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_SSHFP, rbt, reply, replysize, outlen, 0);
	
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

		if (outlen > origlen)
			odh->answer = htons(sshfp_count + 1);	

	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL);

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
		plen = (u_int16_t *)tmpbuf;
		*plen = htons(outlen);
			
		memcpy(&tmpbuf[2], reply, outlen);
		if ((retlen = send(so, tmpbuf, outlen + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if ((retlen = sendto(so, reply, outlen, 0, sa, salen)) < 0) {
			dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
		}
	}

	return (retlen);
}


/* 
 * REPLY_NAPTR() - replies a DNS question (*q) on socket (so)
 *			(based on reply_srv)
 */


int
reply_naptr(struct sreply *sreply, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	int naptr_count;
	u_int16_t *plen;
	char *name;
	u_int16_t outlen;
	u_int16_t namelen;

	struct answer {
		char name[2];
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 /* 12 */
		u_int16_t naptr_order;
		u_int16_t naptr_preference;
		char rest;
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
	struct rr *rrp = NULL;
	int istcp = sreply->istcp;
	int replysize = 512;
	int tmplen, savelen;
	char *p;
	int retlen = -1;
	u_int16_t rollback;

	if ((rrset = find_rr(rbt, DNS_TYPE_NAPTR)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}
	
	if (! istcp && q->edns0len > 512)
		replysize = q->edns0len;

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	SET_DNS_REPLY(odh);
	SET_DNS_AUTHORITATIVE(odh);
	
	if (q->rd) {
		SET_DNS_RECURSION(odh);
	}

	HTONS(odh->query);

	odh->question = htons(1);
	odh->answer = htons(0);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	naptr_count = 0;

	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		savelen = outlen;
		answer->name[0] = 0xc0;
		answer->name[1] = 0x0c;
		answer->type = q->hdr->qtype;
		answer->class = q->hdr->qclass;
		answer->ttl = htonl(((struct naptr *)rrp->rdata)->ttl);

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
	
		name = ((struct naptr *)rrp->rdata)->replacement;
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

	if (dnssec && q->dnssecok && rbt->dnssec) {
		int origlen = outlen;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_NAPTR, rbt, reply, replysize, outlen, 0);

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

		if (outlen > origlen)
			odh->answer = htons(naptr_count + 1);	

	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL);

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
		plen = (u_int16_t *)tmpbuf;
		*plen = htons(outlen);
			
		memcpy(&tmpbuf[2], reply, outlen);
		if ((retlen = send(so, tmpbuf, outlen + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if ((retlen = sendto(so, reply, outlen, 0, sa, salen)) < 0) {
			dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
		}
	}

	return (retlen);
}


/* 
 * REPLY_SRV() - replies a DNS question (*q) on socket (so)
 *			(based on reply_mx)
 */


int
reply_srv(struct sreply *sreply, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	int srv_count;
	u_int16_t *plen;
	char *name;
	u_int16_t outlen;
	u_int16_t namelen;

	struct answer {
		char name[2];
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 /* 12 */
		u_int16_t srv_priority;
		u_int16_t srv_weight;
		u_int16_t srv_port;
		char target;
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
	struct rr *rrp = NULL;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	int tmplen;
	u_int16_t rollback;

	if ((rrset = find_rr(rbt, DNS_TYPE_SRV)) == 0)
		return -1;

	if (istcp) {
		replysize = 65535;
	}
	
	if (! istcp && q->edns0len > 512)
		replysize = q->edns0len;

	odh = (struct dns_header *)&reply[0];

	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	SET_DNS_REPLY(odh);
	SET_DNS_AUTHORITATIVE(odh);
	
	if (q->rd) {
		SET_DNS_RECURSION(odh);
	}

	HTONS(odh->query);

	odh->question = htons(1);
	odh->answer = htons(0);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	srv_count = 0;
	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		answer->name[0] = 0xc0;
		answer->name[1] = 0x0c;
		answer->type = q->hdr->qtype;
		answer->class = q->hdr->qclass;
		answer->ttl = htonl(((struct srv *)rrp->rdata)->ttl);

		answer->rdlength = htons((3 * sizeof(u_int16_t)) + ((struct srv *)rrp->rdata)->targetlen);

		answer->srv_priority = htons(((struct srv *)rrp->rdata)->priority);
		answer->srv_weight = htons(((struct srv *)rrp->rdata)->weight);
		answer->srv_port = htons(((struct srv *)rrp->rdata)->port);

		memcpy((char *)&answer->target, (char *)((struct srv *)rrp->rdata)->target, ((struct srv *)rrp->rdata)->targetlen);

		name = ((struct srv *)rrp->rdata)->target;
		namelen = ((struct srv *)rrp->rdata)->targetlen;

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

	if (dnssec && q->dnssecok && rbt->dnssec) {
		int origlen = outlen;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, DNS_TYPE_SRV, rbt, reply, replysize, outlen, 0);

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

		if (outlen > origlen)
			odh->answer = htons(srv_count + 1);	

	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen);
	}

	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL);

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
		plen = (u_int16_t *)tmpbuf;
		*plen = htons(outlen);
			
		memcpy(&tmpbuf[2], reply, outlen);
		if ((retlen = send(so, tmpbuf, outlen + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if ((retlen = sendto(so, reply, outlen, 0, sa, salen)) < 0) {
			dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
		}
	}

	return (retlen);
}


/*
 * REPLY_NOTIMPL - reply "Not Implemented" 
 *
 */


int
reply_notimpl(struct sreply  *sreply, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	u_int16_t outlen;

	int so = sreply->so;
	char *buf = sreply->buf;
	int len = sreply->len;
	struct sockaddr *sa = sreply->sa;
	int salen = sreply->salen;
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

	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	SET_DNS_REPLY(odh);
	SET_DNS_RCODE_NOTIMPL(odh);

	HTONS(odh->query);		


	if (istcp) {
		char *tmpbuf;
		u_int16_t *plen;

		tmpbuf = malloc(outlen + 2);
		if (tmpbuf == 0) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
		}
		plen = (u_int16_t *)tmpbuf;
		*plen = htons(outlen);
		
		memcpy(&tmpbuf[2], reply, outlen);

		if ((retlen = send(so, tmpbuf, outlen + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if ((retlen = sendto(so, reply, len, 0, sa, salen)) < 0) {
			dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
		}
	}

	return (retlen);
}

/* 
 * REPLY_NXDOMAIN() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_nxdomain(struct sreply *sreply, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	u_int16_t outlen;
	char *p;
	u_int32_t *soa_val;
	int i, tmplen;
	int labellen;
	char *label, *plabel;
	u_int16_t rollback;

	struct answer {
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 /* 10 */
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
		replysize = q->edns0len;
	
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
		memset((char *)&odh->query, 0, sizeof(u_int16_t));

		SET_DNS_REPLY(odh);
		SET_DNS_RCODE_NAMEERR(odh);

		if (q->rd) {
			SET_DNS_RECURSION(odh);
		}

		HTONS(odh->query);		
		if (istcp) {
			char *tmpbuf;
			u_int16_t *plen;

			tmpbuf = malloc(len + 2);
			if (tmpbuf == 0) {
				dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
			}
			plen = (u_int16_t *)tmpbuf;
			*plen = htons(len);
			
			memcpy(&tmpbuf[2], reply, len);

			if ((retlen = send(so, tmpbuf, len + 2, 0)) < 0) {
				dolog(LOG_INFO, "send: %s\n", strerror(errno));
			}
			free(tmpbuf);
		} else {
			if ((retlen = sendto(so, reply, len, 0, sa, salen)) < 0) {
				dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
			}
		}

		return (retlen);
	}

	rrp = TAILQ_FIRST(&rrset->rr_head);
	if (rrp == 0)
		return -1;

	/* copy question to reply */
	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
	/* blank query */
	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	outlen += (q->hdr->namelen + 4); 
	rollback = outlen;

	SET_DNS_REPLY(odh);
	SET_DNS_AUTHORITATIVE(odh);

	SET_DNS_RCODE_NAMEERR(odh);

	if (q->rd) {
		SET_DNS_RECURSION(odh);
	}
	
	NTOHS(odh->query);

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
	answer->ttl = htonl(((struct soa *)rrp->rdata)->ttl);

	outlen += 10;   /* sizeof(struct answer)  up to rdata length */

	p = (char *)&answer->rdata;

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
	if ((outlen + sizeof(u_int32_t)) > replysize) {
		/* XXX server error reply? */
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(((struct soa *)rrp->rdata)->serial);
	outlen += sizeof(u_int32_t);
	
	if ((outlen + sizeof(u_int32_t)) > replysize) {
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(((struct soa *)rrp->rdata)->refresh);
	outlen += sizeof(u_int32_t);

	if ((outlen + sizeof(u_int32_t)) > replysize) {
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(((struct soa *)rrp->rdata)->retry);
	outlen += sizeof(u_int32_t);

	if ((outlen + sizeof(u_int32_t)) > replysize) {
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(((struct soa *)rrp->rdata)->expire);
	outlen += sizeof(u_int32_t);

	if ((outlen + sizeof(u_int32_t)) > replysize) {
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(((struct soa *)rrp->rdata)->minttl);
	outlen += sizeof(u_int32_t);

	answer->rdlength = htons(&reply[outlen] - &answer->rdata);

	/* RRSIG reply_nxdomain */
	if (dnssec && q->dnssecok && rbt->dnssec) {
		int tmplen = 0;
		int origlen = outlen;

		tmplen = additional_rrsig(rbt->zone, rbt->zonelen, DNS_TYPE_SOA, rbt, reply, replysize, outlen, 0);
	
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

		if (outlen > origlen)
			odh->nsrr = htons(2);	

		origlen = outlen;
		if (find_rr(rbt, DNS_TYPE_NSEC3PARAM)) {
			rbt0 = find_nsec3_cover_next_closer(q->hdr->name, q->hdr->namelen, rbt, db);
			if (rbt0 == 0)
				goto out;

			memcpy(&uniq[rruniq].name, rbt0->zone, rbt0->zonelen);
			uniq[rruniq++].len = rbt0->zonelen;
			
			tmplen = additional_nsec3(rbt0->zone, rbt0->zonelen, DNS_TYPE_NSEC3, rbt0, reply, replysize, outlen);
			free (rbt0);

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

			if (outlen > origlen)
			odh->nsrr = htons(4);

			origlen = outlen;

			rbt0 = find_nsec3_match_closest(q->hdr->name, q->hdr->namelen, rbt, db);
			if (rbt0 == 0)
				goto out;

			memcpy(&uniq[rruniq].name, rbt0->zone, rbt0->zonelen);
			uniq[rruniq++].len = rbt0->zonelen;

			if (memcmp(uniq[0].name, uniq[1].name, uniq[1].len) != 0) {
				tmplen = additional_nsec3(rbt0->zone, rbt0->zonelen, DNS_TYPE_NSEC3, rbt0, reply, replysize, outlen);
				addrec = 1;
			}

			free (rbt0);
			
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
				odh->nsrr += 2;
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
				tmplen = additional_nsec3(rbt0->zone, rbt0->zonelen, DNS_TYPE_NSEC3, rbt0, reply, replysize, outlen);
				addrec = 1;
			}
			free (rbt0);
			
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
				odh->nsrr += 2;
				HTONS(odh->nsrr);
			}
			addrec = 0;

		} /* if (find_rr(... DNS_TYPE_NSEC3PARAM) */
	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen);
	}


	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	if (istcp) {
		char *tmpbuf;
		u_int16_t *plen;

		tmpbuf = malloc(outlen + 2);
		if (tmpbuf == 0) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
		}
		plen = (u_int16_t *)tmpbuf;
		*plen = htons(outlen);
		
		memcpy(&tmpbuf[2], reply, outlen);

		if ((retlen = send(so, tmpbuf, outlen + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if ((retlen = sendto(so, reply, outlen, 0, sa, salen)) < 0) {
			dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
		}
	} 

	return (retlen);
}

/* 
 * REPLY_REFUSED() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_refused(struct sreply *sreply, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	u_int16_t outlen;

	int so = sreply->so;
	int len = sreply->len;
	char *buf = sreply->buf;
	struct sockaddr *sa = sreply->sa;
	int salen = sreply->salen;
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

	memcpy((char *)&odh->id, buf, sizeof(u_int16_t));
	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	SET_DNS_REPLY(odh);
	SET_DNS_RCODE_REFUSED(odh);

	HTONS(odh->query);		

	if (istcp) {
		char *tmpbuf;
		u_int16_t *plen;

		tmpbuf = malloc(outlen + 2);
		if (tmpbuf == 0) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
		}
		plen = (u_int16_t *)tmpbuf;
		*plen = htons(outlen);
		
		memcpy(&tmpbuf[2], reply, outlen);

		if ((retlen = send(so, tmpbuf, outlen + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if ((retlen = sendto(so, reply, sizeof(struct dns_header), 0, sa, salen)) < 0) {
			dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
		}
	}

	return (retlen);
}

/* 
 * REPLY_NOTAUTH() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_notauth(struct sreply *sreply, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	u_int16_t outlen = 0;
	u_int16_t tmplen;

	int so = sreply->so;
	int len = sreply->len;
	char *buf = sreply->buf;
	struct sockaddr *sa = sreply->sa;
	int salen = sreply->salen;
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

	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	/* copy question to reply */
	if (istcp)
		memcpy(&reply[0], &buf[2], sizeof(struct dns_header) + q->hdr->namelen + 4);
	else
		memcpy(&reply[0], buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
		

	outlen += (sizeof(struct dns_header) + q->hdr->namelen + 4); 


	SET_DNS_REPLY(odh);
	SET_DNS_RCODE_NOTAUTH(odh);

	HTONS(odh->query);		

	odh->additional = htons(1);
	
	tmplen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL);
	
	if (tmplen != 0)
		outlen = tmplen;

	if (istcp) {
		char *tmpbuf;
		u_int16_t *plen;

		tmpbuf = malloc(outlen + 2);
		if (tmpbuf == 0) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
		}
		plen = (u_int16_t *)tmpbuf;
		*plen = htons(outlen);
		
		memcpy(&tmpbuf[2], reply, outlen);

		if ((retlen = send(so, tmpbuf, outlen + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if ((retlen = sendto(so, reply, outlen, 0, sa, salen)) < 0) {
			dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
		}
	}

	return (retlen);
}

/* 
 * REPLY_FMTERROR() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_fmterror(struct sreply *sreply, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	u_int16_t outlen;

	int so = sreply->so;
	int len = sreply->len;
	char *buf = sreply->buf;
	struct sockaddr *sa = sreply->sa;
	int salen = sreply->salen;
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

	memcpy((char *)&odh->id, buf, sizeof(u_int16_t));
	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	SET_DNS_REPLY(odh);
	SET_DNS_RCODE_FORMATERR(odh);

	HTONS(odh->query);		

	if (istcp) {
		char *tmpbuf;
		u_int16_t *plen;

		tmpbuf = malloc(outlen + 2);
		if (tmpbuf == 0) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
		}
		plen = (u_int16_t *)tmpbuf;
		*plen = htons(outlen);
		
		memcpy(&tmpbuf[2], reply, outlen);

		if ((retlen = send(so, tmpbuf, outlen + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if ((retlen = sendto(so, reply, sizeof(struct dns_header), 0, sa, salen)) < 0) {
			dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
		}
	}

	return (retlen);
}

/* 
 * REPLY_NOERROR() - replies a DNS question (*q) on socket (so)
 *		     based on reply_nxdomain
 *
 */

int
reply_noerror(struct sreply *sreply, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	u_int16_t outlen;
	char *p;
	u_int32_t *soa_val;
	int i, tmplen;
	int labellen;
	char *label, *plabel;
	u_int16_t rollback;

	struct answer {
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 /* 12 */
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
		replysize = q->edns0len;
	
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
		memset((char *)&odh->query, 0, sizeof(u_int16_t));

		SET_DNS_REPLY(odh);

		if (q->rd) {
			SET_DNS_RECURSION(odh);
		}

		HTONS(odh->query);		

		if (istcp) {
			char *tmpbuf;
			u_int16_t *plen;

			tmpbuf = malloc(len + 2);
			if (tmpbuf == 0) {
				dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
			}
			plen = (u_int16_t *)tmpbuf;
			*plen = htons(len);
			
			memcpy(&tmpbuf[2], reply, len);

			if ((retlen = send(so, tmpbuf, len + 2, 0)) < 0) {
				dolog(LOG_INFO, "send: %s\n", strerror(errno));
			}
			free(tmpbuf);
		} else {
			if ((retlen = sendto(so, reply, len, 0, sa, salen)) < 0) {
				dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
			}
		}

		return (retlen);
	}

	rrp = TAILQ_FIRST(&rrset->rr_head);
	if (rrp == 0)
		return -1;
	
	/* copy question to reply */
	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
	/* blank query */
	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	outlen += (q->hdr->namelen + 4); 
	rollback = outlen;

	SET_DNS_REPLY(odh);
	SET_DNS_AUTHORITATIVE(odh);

	if (q->rd) {
		SET_DNS_RECURSION(odh);
	}

	NTOHS(odh->query);

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

	answer->ttl = htonl(((struct soa *)rrp->rdata)->ttl);

	outlen += 10;			/* up to rdata length */

	p = (char *)&answer->rdata;

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
	if ((outlen + sizeof(u_int32_t)) > replysize) {
		/* XXX server error reply? */
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(((struct soa *)rrp->rdata)->serial);
	outlen += sizeof(u_int32_t);
	
	if ((outlen + sizeof(u_int32_t)) > replysize) {
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(((struct soa *)rrp->rdata)->refresh);
	outlen += sizeof(u_int32_t);

	if ((outlen + sizeof(u_int32_t)) > replysize) {
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(((struct soa *)rrp->rdata)->retry);
	outlen += sizeof(u_int32_t);

	if ((outlen + sizeof(u_int32_t)) > replysize) {
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(((struct soa *)rrp->rdata)->expire);
	outlen += sizeof(u_int32_t);

	if ((outlen + sizeof(u_int32_t)) > replysize) {
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(((struct soa *)rrp->rdata)->minttl);
	outlen += sizeof(u_int32_t);

	answer->rdlength = htons(&reply[outlen] - &answer->rdata);
	/* RRSIG reply_nxdomain */
	if (dnssec && q->dnssecok && rbt->dnssec) {
		int tmplen = 0;
		int origlen = outlen;

		tmplen = additional_rrsig(rbt->zone, rbt->zonelen, DNS_TYPE_SOA, rbt, reply, replysize, outlen, 0);
	
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

		if (outlen > origlen)
			odh->nsrr = htons(2);	

		origlen = outlen;
		if (find_rr(rbt, DNS_TYPE_NSEC)) {
			rbt0 = Lookup_zone(db, q->hdr->name, q->hdr->namelen, htons(DNS_TYPE_NSEC), 0);
			tmplen = additional_nsec(q->hdr->name, q->hdr->namelen, DNS_TYPE_NSEC, rbt0, reply, replysize, outlen);
			free(rbt0);
		} else if (find_rr(rbt, DNS_TYPE_NSEC3PARAM)) {
			rbt0 = find_nsec3_match_qname(q->hdr->name, q->hdr->namelen, rbt, db);
			if (rbt0 == 0)
				goto out;

			memcpy(&uniq[rruniq].name, rbt0->zone, rbt0->zonelen);
			uniq[rruniq++].len = rbt0->zonelen;

			tmplen = additional_nsec3(rbt0->zone, rbt0->zonelen, DNS_TYPE_NSEC3, rbt0, reply, replysize, outlen);
			free (rbt0);
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

		if (outlen > origlen)
			odh->nsrr = htons(4);
	}

out:
	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen);
	}
	
	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	if (istcp) {
		char *tmpbuf;
		u_int16_t *plen;

		tmpbuf = malloc(outlen + 2);
		if (tmpbuf == 0) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
		}
		plen = (u_int16_t *)tmpbuf;
		*plen = htons(outlen);
	
		memcpy(&tmpbuf[2], reply, outlen);

		if ((retlen = send(so, tmpbuf, outlen + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if ((retlen = sendto(so, reply, outlen, 0, sa, salen)) < 0) {
			dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
		}
	}

	return (retlen);
}

/* 
 * Lookup_zone: wrapper for lookup_zone() et al.
 */

struct rbtree *
Lookup_zone(ddDB *db, char *name, u_int16_t namelen, u_int16_t type, int wildcard)
{
	struct rbtree *rbt;
	struct question *fakequestion;
	char fakereplystring[DNS_MAXNAME + 1];
	int mytype;
	int lzerrno;

	fakequestion = build_fake_question(name, namelen, type, NULL, 0);
	if (fakequestion == 0) {
		dolog(LOG_INFO, "fakequestion(2) failed\n");
		return (0);
	}

	rbt = lookup_zone(db, fakequestion, &mytype, &lzerrno, (char *)&fakereplystring);

	if (rbt == 0) {
		free_question(fakequestion);
		return (0);
	}

	free_question(fakequestion);
	
	return (rbt);
}

int
reply_any(struct sreply *sreply, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	u_int16_t outlen;

	int so = sreply->so;
	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct sockaddr *sa = sreply->sa;
	int salen = sreply->salen;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	u_int16_t rollback;

	if (istcp) {
		replysize = 65535;
	}

	if (! istcp && q->edns0len > 512)
		replysize = q->edns0len;
	
	/* st */

	odh = (struct dns_header *)&reply[0];
	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);
	}

	/* copy question to reply */
	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
	/* blank query */
	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	outlen += (q->hdr->namelen + 4);
	rollback = outlen;

	SET_DNS_REPLY(odh);
	SET_DNS_AUTHORITATIVE(odh);
	
	if (q->rd) {
		SET_DNS_RECURSION(odh);
	}

	NTOHS(odh->query);

	odh->question = htons(1);
	odh->answer = 0;
	odh->nsrr = 0;
	odh->additional = 0;

	outlen = create_anyreply(sreply, (char *)reply, replysize, outlen, 1);
	if (outlen == 0) {
		return (retlen);
	} else if (istcp == 0 && outlen == 65535) {
		odh->answer = 0;
		odh->nsrr = 0;
		odh->additional = 0;
		outlen = rollback;
	}


	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen);
	}
			
	if (q->tsig.tsigverified == 1) {
		outlen = additional_tsig(q, reply, replysize, outlen, 0, 0, NULL);

		NTOHS(odh->additional);	
		odh->additional++;
		HTONS(odh->additional);
	}

	if (istcp) {
		char *tmpbuf;
		u_int16_t *plen;

		tmpbuf = malloc(outlen + 2);
		if (tmpbuf == 0) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
		}
		plen = (u_int16_t *)tmpbuf;
		*plen = htons(outlen);
		
		memcpy(&tmpbuf[2], reply, outlen);

		if ((retlen = send(so, tmpbuf, outlen + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if ((retlen = sendto(so, reply, outlen, 0, sa, salen)) < 0) {
			dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
		}
	}

	return (retlen);
}

/*
 * CREATE_ANYREPLY - pack an entire zone record into an any reply or axfr
 * 
 */

u_int16_t
create_anyreply(struct sreply *sreply, char *reply, int rlen, int offset, int soa)
{
	int a_count, aaaa_count, ns_count, mx_count, srv_count, sshfp_count;
	int tlsa_count, typelen;
	int ds_count, dnskey_count;
	int naptr_count, rrsig_count;
	int tmplen;
	struct answer {
		u_int16_t type;		/* 0 */
                u_int16_t class;	/* 2 */
                u_int32_t ttl;		/* 4 */
                u_int16_t rdlength;      /* 8 */
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
	u_int32_t *soa_val;
	u_int16_t namelen;
	u_int16_t *mx_priority, *srv_priority, *srv_port, *srv_weight;
	u_int16_t *naptr_order, *naptr_preference, *ds_keytag;
	u_int16_t *dnskey_flags, *nsec3param_iterations;
	u_int16_t *nsec3_iterations;
	u_int8_t *sshfp_alg, *sshfp_fptype, *ds_alg, *ds_digesttype;
	u_int8_t *dnskey_protocol, *dnskey_alg, *tlsa_usage, *tlsa_selector;
	u_int8_t *tlsa_matchtype;
	u_int8_t *nsec3param_alg, *nsec3param_flags, *nsec3param_saltlen;
	u_int8_t *nsec3_alg, *nsec3_flags, *nsec3_saltlen, *nsec3_hashlen;
	char *name, *p;
	int i;

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

		if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
			offset = tmplen;
		} 

		answer = (struct answer *)&reply[offset];

		answer->type = htons(DNS_TYPE_SOA);
		answer->class = htons(DNS_CLASS_IN);
		answer->ttl = htonl(((struct soa *)rrp->rdata)->ttl);

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
        	if ((tmplen = compress_label((u_char*)reply, offset, labellen)) > 0) {
                	offset = tmplen;
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

		if ((tmplen = compress_label((u_char*)reply, offset, labellen)) > 0) {
                	offset = tmplen;
        	}

		if ((offset + sizeof(u_int32_t)) > rlen) {
			goto truncate;
        	}

		soa_val = (u_int32_t *)&reply[offset];
		*soa_val = htonl(((struct soa *)rrp->rdata)->serial);
		offset += sizeof(u_int32_t);      
        
        	if ((offset + sizeof(u_int32_t)) > rlen) {
			goto truncate;
        	}
	
		soa_val = (u_int32_t *)&reply[offset];
		*soa_val = htonl(((struct soa *)rrp->rdata)->refresh);
		offset += sizeof(u_int32_t);    

		if ((offset + sizeof(u_int32_t)) > rlen) {
			goto truncate;
        	}

		soa_val = (u_int32_t *)&reply[offset];
		*soa_val = htonl(((struct soa *)rrp->rdata)->retry);
		offset += sizeof(u_int32_t);       

		if ((offset + sizeof(u_int32_t)) > rlen) {
			goto truncate;
		}

		soa_val = (u_int32_t *)&reply[offset];
		*soa_val = htonl(((struct soa *)rrp->rdata)->expire);
		offset += sizeof(u_int32_t);

		if ((offset + sizeof(u_int32_t)) > rlen) {
			goto truncate;
        	}

		soa_val = (u_int32_t *)&reply[offset];
		*soa_val = htonl(((struct soa *)rrp->rdata)->minttl);
		offset += sizeof(u_int32_t);

		answer->rdlength = htons(&reply[offset] - answer->rdata);

	}
	if ((rrset = find_rr(rbt, DNS_TYPE_RRSIG)) != 0) {
		int dnskey_count = 0;

		rrsig_count = 0;
		dnskey_count = 0;
		TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
			tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen,
				((struct rrsig *)rrp->rdata)->type_covered, rbt, reply, rlen, offset, ((struct rrsig *)rrp->rdata)->type_covered == DNS_TYPE_DNSKEY ? dnskey_count : 0);
		
			if (tmplen == 0)
				goto truncate;

			offset = tmplen;
			if (((struct rrsig *)rrp->rdata)->type_covered == DNS_TYPE_DNSKEY)
				dnskey_count++;

			rrsig_count++;
		} 

		NTOHS(odh->answer);
		odh->answer += rrsig_count;
		HTONS(odh->answer);

	}
	if ((rrset = find_rr(rbt, DNS_TYPE_DNSKEY)) != 0) {
		dnskey_count = 0;
		TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
			if (offset + q->hdr->namelen > rlen)
				goto truncate;

			memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
			offset += q->hdr->namelen;

			if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
				offset = tmplen;
			} 

			answer = (struct answer *)&reply[offset];

			answer->type = htons(DNS_TYPE_DNSKEY);
			answer->class = htons(DNS_CLASS_IN);
			answer->ttl = htonl(((struct dnskey *)rrp->rdata)->ttl);

			answer->rdlength = htons(namelen);

			offset += 10;		/* struct answer */

			if (offset + sizeof(*dnskey_flags) + sizeof(*dnskey_protocol) + sizeof(*dnskey_alg) > rlen)
				goto truncate;

			dnskey_flags = (u_int16_t *)&reply[offset];
			*dnskey_flags = htons(((struct dnskey *)rrp->rdata)->flags);

			offset += sizeof(u_int16_t);
			
			dnskey_protocol = (u_int8_t *)&reply[offset];
			*dnskey_protocol = ((struct dnskey *)rrp->rdata)->protocol;
	
			offset++;

			dnskey_alg = (u_int8_t *)&reply[offset];
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
	if ((rrset = find_rr(rbt, DNS_TYPE_DS)) != 0) {
		ds_count = 0;

		TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
			if (offset + q->hdr->namelen > rlen)
				goto truncate;

			memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
			offset += q->hdr->namelen;

			if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
				offset = tmplen;
			} 

			answer = (struct answer *)&reply[offset];

			answer->type = htons(DNS_TYPE_DS);
			answer->class = htons(DNS_CLASS_IN);
			answer->ttl = htonl(((struct ds *)rrp->rdata)->ttl);

			answer->rdlength = htons(namelen);

			offset += 10;		/* struct answer */

			if (offset + sizeof(*ds_keytag) + sizeof(*ds_alg) + sizeof(*ds_digesttype) > rlen)
				goto truncate;

			ds_keytag = (u_int16_t *)&reply[offset];
			*ds_keytag = htons(((struct ds *)rrp->rdata)->key_tag);

			offset += sizeof(u_int16_t);
			
			ds_alg = (u_int8_t *)&reply[offset];
			*ds_alg = ((struct ds *)rrp->rdata)->algorithm;
	
			offset++;

			ds_digesttype = (u_int8_t *)&reply[offset];
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

		if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
			offset = tmplen;
		} 

		answer = (struct answer *)&reply[offset];

		answer->type = htons(DNS_TYPE_NSEC3);
		answer->class = htons(DNS_CLASS_IN);
		answer->ttl = htonl(((struct nsec3 *)rrp->rdata)->ttl);

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

		nsec3_alg = (u_int8_t *)&reply[offset];
		*nsec3_alg = ((struct nsec3 *)rrp->rdata)->algorithm;

		offset++;

		nsec3_flags = (u_int8_t *)&reply[offset];
		*nsec3_flags = ((struct nsec3 *)rrp->rdata)->flags;

		offset++;

		nsec3_iterations = (u_int16_t *)&reply[offset];
		*nsec3_iterations = htons(((struct nsec3 *)rrp->rdata)->iterations);
		offset += sizeof(u_int16_t);

		nsec3_saltlen = (u_int8_t *)&reply[offset];
		*nsec3_saltlen = ((struct nsec3 *)rrp->rdata)->saltlen;
		offset++;
	
		memcpy(&reply[offset], &((struct nsec3 *)rrp->rdata)->salt,
			((struct nsec3 *)rrp->rdata)->saltlen);	
		
		offset += ((struct nsec3 *)rrp->rdata)->saltlen;	

		nsec3_hashlen = (u_int8_t *)&reply[offset];
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

		if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
			offset = tmplen;
		} 

		answer = (struct answer *)&reply[offset];

		answer->type = htons(DNS_TYPE_NSEC3PARAM);
		answer->class = htons(DNS_CLASS_IN);
		answer->ttl = htonl(((struct nsec3param *)rrp->rdata)->ttl);

		answer->rdlength = htons(namelen);

		offset += 10;		/* struct answer */

		if (offset + sizeof(((struct nsec3param *)rrp->rdata)->algorithm)
			+ sizeof(((struct nsec3param *)rrp->rdata)->flags) 
			+ sizeof(((struct nsec3param *)rrp->rdata)->iterations)
			+ sizeof(((struct nsec3param *)rrp->rdata)->saltlen) > rlen)
			goto truncate;

		nsec3param_alg = (u_int8_t *)&reply[offset];
		*nsec3param_alg = ((struct nsec3param *)rrp->rdata)->algorithm;

		offset++;

		nsec3param_flags = (u_int8_t *)&reply[offset];
		*nsec3param_flags = ((struct nsec3param *)rrp->rdata)->flags;

		offset++;

		nsec3param_iterations = (u_int16_t *)&reply[offset];
		*nsec3param_iterations = htons(((struct nsec3param *)rrp->rdata)->iterations);
		offset += sizeof(u_int16_t);

		nsec3param_saltlen = (u_int8_t *)&reply[offset];
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

		if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
			offset = tmplen;
		} 

		answer = (struct answer *)&reply[offset];

		answer->type = htons(DNS_TYPE_NSEC);
		answer->class = htons(DNS_CLASS_IN);
		answer->ttl = htonl(((struct nsec *)rrp->rdata)->ttl);

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
			if (offset + q->hdr->namelen > rlen)
				goto truncate;

			memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
			offset += q->hdr->namelen;

			if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
				offset = tmplen;
			} 

			answer = (struct answer *)&reply[offset];

			answer->type = htons(DNS_TYPE_NS);
			answer->class = htons(DNS_CLASS_IN);
			answer->ttl = htonl(((struct ns *)rrp->rdata)->ttl);

			answer->rdlength = htons(namelen);

			offset += 10;		/* struct answer */

			name = ((struct ns *)rrp->rdata)->nsserver;
			namelen = ((struct ns *)rrp->rdata)->nslen;

			if (offset + namelen > rlen)
				goto truncate;

			memcpy((char *)&answer->rdata, (char *)name, namelen);

			offset += namelen;
			
			/* compress the label if possible */
			if ((tmplen = compress_label((u_char*)reply, offset, namelen)) > 0) {
				offset = tmplen;
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

		if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
			offset = tmplen;
		} 

		answer = (struct answer *)&reply[offset];

		answer->type = htons(DNS_TYPE_PTR);
		answer->class = htons(DNS_CLASS_IN);
		answer->ttl = htonl(((struct ptr *)rrp->rdata)->ttl);

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
        	if ((tmplen = compress_label((u_char*)reply, offset, labellen)) > 0) {
                	offset = tmplen;
        	}

		answer->rdlength = htons(&reply[offset] - answer->rdata);
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_MX)) != 0) {

		mx_count = 0;
		TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
			if ((offset + q->hdr->namelen) > rlen) {
				goto truncate;
			}

			memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
			offset += q->hdr->namelen;

			if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
				offset = tmplen;
			} 

		
			if (offset + 12 > rlen)
				goto truncate;

			answer = (struct answer *)&reply[offset];

			answer->type = htons(DNS_TYPE_MX);
			answer->class = htons(DNS_CLASS_IN);
			answer->ttl = htonl(((struct smx *)rrp->rdata)->ttl);
			answer->rdlength = htons(sizeof(u_int16_t) + ((struct smx *)rrp->rdata)->exchangelen);

			offset += 10;		/* up to rdata length */
			
			mx_priority = (u_int16_t *)&reply[offset];
			*mx_priority = htons(((struct smx *)rrp->rdata)->preference);

			offset += sizeof(u_int16_t);

			if (offset + ((struct smx *)rrp->rdata)->exchangelen > rlen)
				goto truncate;

			memcpy((char *)&reply[offset], (char *)((struct smx *)rrp->rdata)->exchange, ((struct smx *)rrp->rdata)->exchangelen);

			offset += ((struct smx *)rrp->rdata)->exchangelen;

			if ((tmplen = compress_label((u_char*)reply, offset, ((struct smx *)rrp->rdata)->exchangelen)) > 0) {
				offset = tmplen;
			} 

			answer->rdlength = htons(&reply[offset] - answer->rdata);
			mx_count++;
		}

		NTOHS(odh->answer);
		odh->answer += mx_count;
		HTONS(odh->answer);

	}
	if ((rrset = find_rr(rbt, DNS_TYPE_TXT)) != 0) {
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

		if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
			offset = tmplen;
		} 

		answer = (struct answer *)&reply[offset];

		answer->type = htons(DNS_TYPE_TXT);
		answer->class = htons(DNS_CLASS_IN);
		answer->ttl = htonl(((struct txt *)rrp->rdata)->ttl);

		offset += 10;		/* up to rdata length */

		if (offset + ((struct txt *)rrp->rdata)->txtlen > rlen)
			goto truncate;

		p = (char *)&answer->rdata;
		memcpy(p, ((struct txt *)rrp->rdata)->txt, ((struct txt *)rrp->rdata)->txtlen);
		offset += (((struct txt *)rrp->rdata)->txtlen);

		answer->rdlength = htons(((struct txt *)rrp->rdata)->txtlen);

	}
	if ((rrset = find_rr(rbt, DNS_TYPE_TLSA)) != 0) {

		tlsa_count = 0;
		TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
			if ((offset + q->hdr->namelen) > rlen) {
				goto truncate;
			}

			memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
			offset += q->hdr->namelen;

			if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
				offset = tmplen;
			} 

		
			if (offset + 12 > rlen)
				goto truncate;

			answer = (struct answer *)&reply[offset];

			answer->type = htons(DNS_TYPE_TLSA);
			answer->class = htons(DNS_CLASS_IN);
			answer->ttl = htonl(((struct tlsa *)rrp->rdata)->ttl);

			typelen = ((struct tlsa *)rrp->rdata)->matchtype == 1 ? DNS_TLSA_SIZE_SHA256 : DNS_TLSA_SIZE_SHA512;
			answer->rdlength = htons((3 * sizeof(u_int8_t)) + typelen);

			offset += 10;		/* up to rdata length */
			
			tlsa_usage = (u_int8_t *)&reply[offset];
			*tlsa_usage = ((struct tlsa *)rrp->rdata)->usage;

			offset++;

			tlsa_selector = (u_int8_t *)&reply[offset];
			*tlsa_selector = ((struct tlsa *)rrp->rdata)->selector;

			offset++;

			tlsa_matchtype = (u_int8_t *)&reply[offset];
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
			if ((offset + q->hdr->namelen) > rlen) {
				goto truncate;
			}

			memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
			offset += q->hdr->namelen;

			if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
				offset = tmplen;
			} 

		
			if (offset + 12 > rlen)
				goto truncate;

			answer = (struct answer *)&reply[offset];

			answer->type = htons(DNS_TYPE_SSHFP);
			answer->class = htons(DNS_CLASS_IN);
			answer->ttl = htonl(((struct sshfp *)rrp->rdata)->ttl);
			answer->rdlength = htons((2 * sizeof(u_int8_t)) + ((struct sshfp *)rrp->rdata)->fplen);

			offset += 10;		/* up to rdata length */
			
			sshfp_alg = (u_int8_t *)&reply[offset];
			*sshfp_alg = ((struct sshfp *)rrp->rdata)->algorithm;

			offset++;

			sshfp_fptype = (u_int8_t *)&reply[offset];
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
			if ((offset + q->hdr->namelen) > rlen) {
				goto truncate;
			}

			memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
			offset += q->hdr->namelen;

			if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
				offset = tmplen;
			} 

		
			if (offset + 12 > rlen)
				goto truncate;

			answer = (struct answer *)&reply[offset];

			answer->type = htons(DNS_TYPE_NAPTR);
			answer->class = htons(DNS_CLASS_IN);
			answer->ttl = htonl(((struct naptr *)rrp->rdata)->ttl);
			answer->rdlength = htons((2 * sizeof(u_int16_t)) + ((struct naptr *)rrp->rdata)->flagslen + 1 + ((struct naptr *)rrp->rdata)->serviceslen + 1 + ((struct naptr *)rrp->rdata)->regexplen + 1 + ((struct naptr *)rrp->rdata)->replacementlen);

			offset += 10;		/* up to rdata length */
			
			naptr_order = (u_int16_t *)&reply[offset];
			*naptr_order = htons(((struct naptr *)rrp->rdata)->order);

			offset += sizeof(u_int16_t);

			naptr_preference = (u_int16_t *)&reply[offset];
			*naptr_preference = htons(((struct naptr *)rrp->rdata)->preference);

			offset += sizeof(u_int16_t);

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

			if ((tmplen = compress_label((u_char*)reply, offset, ((struct naptr *)rrp->rdata)->replacementlen)) > 0) {
				offset = tmplen;
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
			if ((offset + q->hdr->namelen) > rlen) {
				goto truncate;
			}

			memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
			offset += q->hdr->namelen;

			if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
				offset = tmplen;
			} 

		
			if (offset + 12 > rlen)
				goto truncate;

			answer = (struct answer *)&reply[offset];

			answer->type = htons(DNS_TYPE_SRV);
			answer->class = htons(DNS_CLASS_IN);
			answer->ttl = htonl(((struct srv *)rrp->rdata)->ttl);
			answer->rdlength = htons((3 * sizeof(u_int16_t)) + ((struct srv *)rrp->rdata)->targetlen);

			offset += 10;		/* up to rdata length */
			
			srv_priority = (u_int16_t *)&reply[offset];
			*srv_priority = htons(((struct srv *)rrp->rdata)->priority);

			offset += sizeof(u_int16_t);

			srv_weight = (u_int16_t *)&reply[offset];
			*srv_weight = htons(((struct srv *)rrp->rdata)->weight);

			offset += sizeof(u_int16_t);

			srv_port = (u_int16_t *)&reply[offset];
			*srv_port = htons(((struct srv *)rrp->rdata)->port);

			offset += sizeof(u_int16_t);

			if (offset + ((struct srv *)rrp->rdata)->targetlen > rlen)
				goto truncate;

			memcpy((char *)&reply[offset], (char *)((struct srv *)rrp->rdata)->target, ((struct srv *)rrp->rdata)->targetlen);

			offset += ((struct srv *)rrp->rdata)->targetlen;

			if ((tmplen = compress_label((u_char*)reply, offset, ((struct srv *)rrp->rdata)->targetlen)) > 0) {
				offset = tmplen;
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

		if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
			offset = tmplen;
		} 

		answer = (struct answer *)&reply[offset];

		answer->type = htons(DNS_TYPE_CNAME);
		answer->class = htons(DNS_CLASS_IN);
		answer->ttl = htonl(((struct cname *)rrp->rdata)->ttl);

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
        	if ((tmplen = compress_label((u_char*)reply, offset, labellen)) > 0) {
                	offset = tmplen;
        	}

		answer->rdlength = htons(&reply[offset] - answer->rdata);
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_A)) != 0) {
		a_count = 0;

		TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
			if (offset + q->hdr->namelen > rlen)
				goto truncate;

			memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
			offset += q->hdr->namelen;

			if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
				offset = tmplen;
			} 

			answer = (struct answer *)&reply[offset];

			answer->type = htons(DNS_TYPE_A);
			answer->class = htons(DNS_CLASS_IN);
			answer->ttl = htonl(((struct a *)rrp->rdata)->ttl);
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
			if (offset + q->hdr->namelen > rlen)
				goto truncate;

			memcpy(&reply[offset], q->hdr->name, q->hdr->namelen);
			offset += q->hdr->namelen;

			if ((tmplen = compress_label((u_char*)reply, offset, q->hdr->namelen)) > 0) {
				offset = tmplen;
			} 

			answer = (struct answer *)&reply[offset];

			answer->type = htons(DNS_TYPE_AAAA);
			answer->class = htons(DNS_CLASS_IN);
			answer->ttl = htonl(((struct aaaa *)rrp->rdata)->ttl);
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
reply_badvers(struct sreply *sreply, ddDB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	u_int16_t outlen;

	int so = sreply->so;
	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct sockaddr *sa = sreply->sa;
	int salen = sreply->salen;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;

	if (istcp) {
		replysize = 65535;
	}

	if (!istcp && q->edns0len > 512)
		replysize = q->edns0len;
	
	odh = (struct dns_header *)&reply[0];
	outlen = sizeof(struct dns_header);

	if (len > replysize) {
		return (retlen);

	}

	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	outlen += (q->hdr->namelen + 4);

	SET_DNS_REPLY(odh);
	SET_DNS_AUTHORITATIVE(odh);
	
	HTONS(odh->query);

	odh->question = htons(1);
	odh->answer = 0;
	odh->nsrr = 0;
	odh->additional = 0;

	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		q->badvers = 1;
		outlen = additional_opt(q, reply, replysize, outlen);
	}

	if (istcp) {
		char *tmpbuf;
		u_int16_t *plen;

		tmpbuf = malloc(outlen + 2);
		if (tmpbuf == 0) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
		}
		plen = (u_int16_t *)tmpbuf;
		*plen = htons(outlen);
		
		memcpy(&tmpbuf[2], reply, outlen);

		if ((retlen = send(so, tmpbuf, outlen + 2, 0)) < 0) {
			dolog(LOG_INFO, "send: %s\n", strerror(errno));
		}
		free(tmpbuf);
	} else {
		if ((retlen = sendto(so, reply, outlen, 0, sa, salen)) < 0) {
			dolog(LOG_INFO, "sendto: %s\n", strerror(errno));
		}
	}

	return (retlen);
}


/* 
 * REPLY_NODATA() - replies a DNS question (*q) on socket (so) based on 
 *		 	reply_badvers().
 *
 */

int
reply_nodata(struct sreply *sreply, ddDB *db)
{
	return (reply_noerror(sreply, db));
}
