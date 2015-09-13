/* 
 * Copyright (c) 2005-2015 Peter J. Philipp
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
#include "include.h"
#include "dns.h"
#include "db.h"

#include <openssl/sha.h>

/* prototypes */

extern int     		checklabel(DB *, struct domain *, struct domain *, struct question *);
extern int 		additional_nsec3(char *, int, int, struct domain *, char *, int, int);
extern int 		additional_a(char *, int, struct domain *, char *, int, int, int *);
extern int 		additional_aaaa(char *, int, struct domain *, char *, int, int, int *);
extern int 		additional_mx(char *, int, struct domain *, char *, int, int, int *);
extern int 		additional_ptr(char *, int, struct domain *, char *, int, int, int *);
extern int 		additional_opt(struct question *, char *, int, int);
extern int 		additional_rrsig(char *, int, int, struct domain *, char *, int, int, int);
extern int 		additional_nsec(char *, int, int, struct domain *, char *, int, int);
extern struct question 	*build_fake_question(char *, int, u_int16_t);
extern int 		compress_label(u_char *, int, int);
extern void 		dolog(int, char *, ...);
extern int 		free_question(struct question *);
extern struct domain * 	lookup_zone(DB *, struct question *, int *, int *, char *);
extern void 		slave_shutdown(void);
extern void *		find_substruct(struct domain *, u_int16_t);
extern int 		get_record_size(DB *, char *, int);
extern char *		dns_label(char *, int *);
extern int 		lookup_type(int internal_type);

struct domain 	*Lookup_zone(DB *, char *, u_int16_t, u_int16_t, int);
void 		collects_init(void);
u_int16_t 	create_anyreply(struct sreply *, char *, int, int, int);
u_short 	in_cksum(const u_short *, register int, int);
int 		reply_a(struct sreply *, DB *);
int		reply_nsec3(struct sreply *, DB *);
int		reply_nsec3param(struct sreply *);
int		reply_nsec(struct sreply *);
int		reply_dnskey(struct sreply *);
int		reply_ds(struct sreply *);
int		reply_rrsig(struct sreply *, DB *);
int 		reply_aaaa(struct sreply *, DB *);
int 		reply_mx(struct sreply *, DB *);
int 		reply_ns(struct sreply *, DB *);
int 		reply_notimpl(struct sreply *);
int 		reply_nxdomain(struct sreply *, DB *);
int 		reply_noerror(struct sreply *, DB *);
int 		reply_soa(struct sreply *);
int 		reply_ptr(struct sreply *);
int 		reply_txt(struct sreply *);
int 		reply_version(struct sreply *);
int 		reply_spf(struct sreply *);
int 		reply_srv(struct sreply *, DB *);
int 		reply_naptr(struct sreply *, DB *);
int 		reply_sshfp(struct sreply *);
int 		reply_cname(struct sreply *);
int 		reply_any(struct sreply *);
int 		reply_refused(struct sreply *);
int 		reply_fmterror(struct sreply *);
int		reply_raw2(int, char *, int, struct recurses *);
int 		reply_raw6(int, char *, int, struct recurses *);
void 		update_db(DB *, struct domain *);
struct domain * find_nsec(char *name, int namelen, struct domain *sd, DB *db);
int 		nsec_comp(const void *a, const void *b);
char * 		convert_name(char *name, int namelen);
int 		count_dots(char *name);
char * 		base32hex_encode(u_char *input, int len);
struct domain * find_nsec3_cover_next_closer(char *name, int namelen, struct domain *sd, DB *db);
struct domain * find_nsec3_match_closest(char *name, int namelen, struct domain *sd, DB *db);
struct domain * find_nsec3_wildcard_closest(char *name, int namelen, struct domain *sd, DB *db);
struct domain * find_nsec3_match_qname(char *name, int namelen, struct domain *sd, DB *db);

#ifdef __linux__
static int 	udp_cksum(const struct iphdr *, const struct udphdr *, int);
#else
static int 	udp_cksum(const struct ip *, const struct udphdr *, int);
#endif

SLIST_HEAD(listhead, collects) collectshead;

struct collects {
	char *name;
	u_int16_t namelen;
	u_int16_t type;
	struct domain *sd;
        SLIST_ENTRY(collects) collect_entry;
} *cn1, *cn2, *cnp;

extern int debug, verbose, dnssec;
extern char *versionstring;
extern uint8_t vslen;


#define RRSIG_ALIAS(mytype) do {					\
				odh->answer = htons(a_count++);		\
				tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, mytype, sd, reply, replysize, outlen, 0);					\
				if (tmplen == 0) {					\
					NTOHS(odh->query);				\
					SET_DNS_TRUNCATION(odh);		\
					HTONS(odh->query);				\
					goto out;						\
				}									\
				outlen = tmplen;					\
			} while (0);

static const char rcsid[] = "$Id: reply.c,v 1.36 2015/09/13 05:57:35 pjp Exp $";

/* 
 * REPLY_A() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_a(struct sreply *sreply, DB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	u_int16_t outlen = 0;
	int a_count;
	int mod, pos;

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
	struct domain *sd = sreply->sd1;
	struct domain_a *sda = NULL;
	
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;

	if ((sda = find_substruct(sd, INTERNAL_TYPE_A)) == NULL)
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

	SET_DNS_REPLY(odh);
	if (sreply->sr == NULL)
		SET_DNS_AUTHORITATIVE(odh);
	else	
		SET_DNS_RECURSION_AVAIL(odh);

	HTONS(odh->query);

	odh->question = htons(1);
	odh->answer = htons(sda->a_count);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	a_count = 0;
	pos = sda->a_ptr;
	mod = sda->a_count;

	do {
		/*
		 * answer->name is a pointer to the request (0xc00c) 
		 */

		answer->name[0] = 0xc0;				/* 1 byte */
		answer->name[1] = 0x0c;				/* 2 bytes */
		answer->type = q->hdr->qtype;			/* 4 bytes */	
		answer->class = q->hdr->qclass;			/* 6 bytes */
		if (sreply->sr != NULL)
			answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_A] - (time(NULL) - sd->created));
		else
			answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_A]);			/* 10 bytes */

		answer->rdlength = htons(sizeof(in_addr_t));	/* 12 bytes */

		memcpy((char *)&answer->rdata, (char *)&sda->a[pos++ % mod], 
			sizeof(in_addr_t));			/* 16 bytes */

		a_count++;
		outlen += 16;

		/* can we afford to write another header? if no truncate */
		if (sda->a_count > 1 && outlen + 16 > replysize) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			goto out;
		}


		/* set new offset for answer */
		answer = (struct answer *)&reply[outlen];
	} while (a_count < RECORD_COUNT && --sda->a_count);

	/* Add RRSIG reply_a */
	if (dnssec && q->dnssecok) {
		int tmplen = 0;
		int origlen = outlen;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, INTERNAL_TYPE_A, sd, reply, replysize, outlen, 0);
	
		if (tmplen == 0) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->answer = htons(a_count + 1);	

	}

	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen);
	}

out:
	if (sreply->sr != NULL) {
		retlen = reply_raw2(so, reply, outlen, sreply->sr);
	} else {
		if (istcp) {
			char *tmpbuf;
			u_int16_t *plen;

			tmpbuf = malloc(outlen + 2);
			if (tmpbuf == NULL) {
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

	} /* if (->sr) */
	/*
	 * update a_ptr setting 
	 */

	sda->a_ptr = (sda->a_ptr + 1) % mod;
	sda->a_count = mod;
	update_db(db, sd);

	return (retlen);
}

/* 
 * REPLY_NSEC3PARAM() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_nsec3param(struct sreply *sreply)
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
	struct domain *sd = sreply->sd1;
	struct domain_nsec3param *sdnsec3param = NULL;
	
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	int i;

	if ((sdnsec3param = find_substruct(sd, INTERNAL_TYPE_NSEC3PARAM)) == NULL)
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

	SET_DNS_REPLY(odh);
	if (sreply->sr == NULL)
		SET_DNS_AUTHORITATIVE(odh);
	else	
		SET_DNS_RECURSION_AVAIL(odh);

	HTONS(odh->query);

	odh->question = htons(1);
	odh->answer = htons(1);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	a_count = 0;

	if ((outlen + sizeof(struct answer) + 
		sdnsec3param->nsec3param.saltlen ) > replysize) {
		NTOHS(odh->query);
		SET_DNS_TRUNCATION(odh);
		HTONS(odh->query);
		goto out;
	}

	/*
	 * answer->name is a pointer to the request (0xc00c) 
	 */

	answer->name[0] = 0xc0;				/* 1 byte */
	answer->name[1] = 0x0c;				/* 2 bytes */
	answer->type = q->hdr->qtype;			/* 4 bytes */	
	answer->class = q->hdr->qclass;			/* 6 bytes */
	if (sreply->sr != NULL)
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_NSEC3] - (time(NULL) - sd->created));
	else
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_NSEC3]);			/* 10 bytes */

	answer->rdlength = htons(sdnsec3param->nsec3param.saltlen + 5);	/* 5 = rest */

	answer->algorithm = sdnsec3param->nsec3param.algorithm;
	answer->flags = sdnsec3param->nsec3param.flags;
	answer->iterations = htons(sdnsec3param->nsec3param.iterations);
	answer->saltlen = sdnsec3param->nsec3param.saltlen;
	outlen += sizeof(struct answer);
	
	if (sdnsec3param->nsec3param.saltlen) {
		memcpy(&reply[outlen], &sdnsec3param->nsec3param.salt, sdnsec3param->nsec3param.saltlen);
		outlen += sdnsec3param->nsec3param.saltlen;
	}

	a_count++;

	/* set new offset for answer */
	answer = (struct answer *)&reply[outlen];


	/* Add RRSIG reply_nsec3 */
	if (dnssec && q->dnssecok) {
		int tmplen = 0;
		int origlen = outlen;

		for (i = 0; i < a_count; i++) {
			origlen = outlen; 

			tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, INTERNAL_TYPE_NSEC3PARAM, sd, reply, replysize, outlen, i);
		
			if (tmplen == 0) {
				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				goto out;
			}

			outlen = tmplen;

			if (outlen > origlen)
				odh->answer = htons(a_count + 1 + i);	
		}

		}

	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen);
	}

out:
	if (sreply->sr != NULL) {
		retlen = reply_raw2(so, reply, outlen, sreply->sr);
	} else {
		if (istcp) {
			char *tmpbuf;
			u_int16_t *plen;

			tmpbuf = malloc(outlen + 2);
			if (tmpbuf == NULL) {
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

	} /* if (->sr) */

	return (retlen);
}


/* 
 * REPLY_NSEC3() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_nsec3(struct sreply *sreply, DB *db)
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
	struct domain *sd = sreply->sd1;
	struct domain_nsec3 *sdnsec3 = NULL;
	
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	int i;
	u_int8_t *somelen;

	if ((sdnsec3 = find_substruct(sd, INTERNAL_TYPE_NSEC3)) == NULL)
		return -1;

	if (istcp) {
		replysize = 65535;
	}
	
	if (!istcp && q->edns0len > 512)
		replysize = q->edns0len;


	/* RFC 5155 section 7.2.8 */
	/* we are the sole RR here, or perhaps we are accompanied by an rrsig */
	if ((sd->flags == DOMAIN_HAVE_NSEC)  ||
		(sd->flags == (DOMAIN_HAVE_NSEC3 | DOMAIN_HAVE_RRSIG))) {
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

	SET_DNS_REPLY(odh);
	if (sreply->sr == NULL)
		SET_DNS_AUTHORITATIVE(odh);
	else	
		SET_DNS_RECURSION_AVAIL(odh);

	HTONS(odh->query);

	odh->question = htons(1);
	odh->answer = htons(1);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	a_count = 0;

	if ((outlen + sizeof(struct answer) + sdnsec3->nsec3.nextlen + 
		sdnsec3->nsec3.saltlen + 1 + 
		sdnsec3->nsec3.bitmap_len) > replysize) {
		NTOHS(odh->query);
		SET_DNS_TRUNCATION(odh);
		HTONS(odh->query);
		goto out;
	}

	/*
	 * answer->name is a pointer to the request (0xc00c) 
	 */

	answer->name[0] = 0xc0;				/* 1 byte */
	answer->name[1] = 0x0c;				/* 2 bytes */
	answer->type = q->hdr->qtype;			/* 4 bytes */	
	answer->class = q->hdr->qclass;			/* 6 bytes */
	if (sreply->sr != NULL)
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_NSEC3] - (time(NULL) - sd->created));
	else
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_NSEC3]);			/* 10 bytes */

	answer->rdlength = htons(sdnsec3->nsec3.nextlen + sdnsec3->nsec3.bitmap_len + sdnsec3->nsec3.saltlen + 6);	/* 6 = rest */

	answer->algorithm = sdnsec3->nsec3.algorithm;
	answer->flags = sdnsec3->nsec3.flags;
	answer->iterations = htons(sdnsec3->nsec3.iterations);
	answer->saltlen = sdnsec3->nsec3.saltlen;
	outlen += sizeof(struct answer);
	
	if (sdnsec3->nsec3.saltlen) {
		memcpy(&reply[outlen], &sdnsec3->nsec3.salt, sdnsec3->nsec3.saltlen);
		outlen += sdnsec3->nsec3.saltlen;
	}

	somelen = (u_int8_t *)&reply[outlen];
	*somelen = sdnsec3->nsec3.nextlen;

	outlen += 1;

	memcpy(&reply[outlen], sdnsec3->nsec3.next, sdnsec3->nsec3.nextlen);

	outlen += sdnsec3->nsec3.nextlen;

	memcpy(&reply[outlen], sdnsec3->nsec3.bitmap, sdnsec3->nsec3.bitmap_len);
	outlen += sdnsec3->nsec3.bitmap_len;

	a_count++;

	/* set new offset for answer */
	answer = (struct answer *)&reply[outlen];


	/* Add RRSIG reply_nsec3 */
	if (dnssec && q->dnssecok) {
		int tmplen = 0;
		int origlen = outlen;

		for (i = 0; i < a_count; i++) {
			origlen = outlen; 

			tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, INTERNAL_TYPE_NSEC3, sd, reply, replysize, outlen, i);
		
			if (tmplen == 0) {
				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				goto out;
			}

			outlen = tmplen;

			if (outlen > origlen)
				odh->answer = htons(a_count + 1 + i);	
		}

		}

	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen);
	}

out:
	if (sreply->sr != NULL) {
		retlen = reply_raw2(so, reply, outlen, sreply->sr);
	} else {
		if (istcp) {
			char *tmpbuf;
			u_int16_t *plen;

			tmpbuf = malloc(outlen + 2);
			if (tmpbuf == NULL) {
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

	} /* if (->sr) */

	return (retlen);
}

/* 
 * REPLY_NSEC() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_nsec(struct sreply *sreply)
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
	struct domain *sd = sreply->sd1;
	struct domain_nsec *sdnsec = NULL;
	
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	int i;

	if ((sdnsec = find_substruct(sd, INTERNAL_TYPE_NSEC)) == NULL)
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

	SET_DNS_REPLY(odh);
	if (sreply->sr == NULL)
		SET_DNS_AUTHORITATIVE(odh);
	else	
		SET_DNS_RECURSION_AVAIL(odh);

	HTONS(odh->query);

	odh->question = htons(1);
	odh->answer = htons(1);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	a_count = 0;

	if ((outlen + sizeof(struct answer) + sdnsec->nsec.ndn_len + 
		sdnsec->nsec.bitmap_len) > replysize) {
		NTOHS(odh->query);
		SET_DNS_TRUNCATION(odh);
		HTONS(odh->query);
		goto out;
	}

	/*
	 * answer->name is a pointer to the request (0xc00c) 
	 */

	answer->name[0] = 0xc0;				/* 1 byte */
	answer->name[1] = 0x0c;				/* 2 bytes */
	answer->type = q->hdr->qtype;			/* 4 bytes */	
	answer->class = q->hdr->qclass;			/* 6 bytes */
	if (sreply->sr != NULL)
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_NSEC] - (time(NULL) - sd->created));
	else
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_NSEC]);			/* 10 bytes */

	answer->rdlength = htons(sdnsec->nsec.ndn_len + sdnsec->nsec.bitmap_len);	

	outlen += sizeof(struct answer);

	memcpy(&reply[outlen], sdnsec->nsec.next_domain_name,
		sdnsec->nsec.ndn_len);

	outlen += sdnsec->nsec.ndn_len;

	memcpy(&reply[outlen], sdnsec->nsec.bitmap, sdnsec->nsec.bitmap_len);
	outlen += sdnsec->nsec.bitmap_len;

	a_count++;

	/* set new offset for answer */
	answer = (struct answer *)&reply[outlen];


	/* Add RRSIG reply_nsec */
	if (dnssec && q->dnssecok) {
		int tmplen = 0;
		int origlen = outlen;

		for (i = 0; i < a_count; i++) {
			origlen = outlen; 

			tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, INTERNAL_TYPE_NSEC, sd, reply, replysize, outlen, i);
		
			if (tmplen == 0) {
				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				goto out;
			}

			outlen = tmplen;

			if (outlen > origlen)
				odh->answer = htons(a_count + 1 + i);	
		}

		}

	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen);
	}

out:
	if (sreply->sr != NULL) {
		retlen = reply_raw2(so, reply, outlen, sreply->sr);
	} else {
		if (istcp) {
			char *tmpbuf;
			u_int16_t *plen;

			tmpbuf = malloc(outlen + 2);
			if (tmpbuf == NULL) {
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

	} /* if (->sr) */

	return (retlen);
}

/* 
 * REPLY_DS() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_ds(struct sreply *sreply)
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
	struct domain *sd = sreply->sd1;
	struct domain_ds *sdds = NULL;
	
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	int i;

	if ((sdds = find_substruct(sd, INTERNAL_TYPE_DS)) == NULL)
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

	SET_DNS_REPLY(odh);
	if (sreply->sr == NULL)
		SET_DNS_AUTHORITATIVE(odh);
	else	
		SET_DNS_RECURSION_AVAIL(odh);

	HTONS(odh->query);

	odh->question = htons(1);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	a_count = 0;

	do {
		if ((outlen + sizeof(struct answer) + 
			sdds->ds[a_count].digestlen) > replysize) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			goto out;
		}

		/*
		 * answer->name is a pointer to the request (0xc00c) 
		 */

		answer->name[0] = 0xc0;				/* 1 byte */
		answer->name[1] = 0x0c;				/* 2 bytes */
		answer->type = q->hdr->qtype;			/* 4 bytes */	
		answer->class = q->hdr->qclass;			/* 6 bytes */
		if (sreply->sr != NULL)
			answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_DS] - (time(NULL) - sd->created));
		else
			answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_DS]);			/* 10 bytes */

		answer->rdlength = htons(sdds->ds[a_count].digestlen + 4);	/* 12 bytes */

		answer->key_tag = htons(sdds->ds[a_count].key_tag);
		answer->algorithm = sdds->ds[a_count].algorithm;
		answer->digest_type = sdds->ds[a_count].digest_type;
			
		outlen += sizeof(struct answer);

		memcpy(&reply[outlen], sdds->ds[a_count].digest,
			sdds->ds[a_count].digestlen);

		outlen += sdds->ds[a_count].digestlen;

		a_count++;
		/* set new offset for answer */
		answer = (struct answer *)&reply[outlen];
	} while (a_count < RECORD_COUNT && --sdds->ds_count);

	odh->answer = htons(a_count);

	/* Add RRSIG reply_ds */
	if (dnssec && q->dnssecok) {
		int tmplen = 0;
		int origlen = outlen;

		for (i = 0; i < a_count; i++) {
			origlen = outlen; 

			tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, INTERNAL_TYPE_DS, sd, reply, replysize, outlen, i);
		
			if (tmplen == 0) {
				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				goto out;
			}

			outlen = tmplen;

			if (outlen > origlen)
				odh->answer = htons(a_count + 1 + i);	
		}

		}

	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen);
	}

out:
	if (sreply->sr != NULL) {
		retlen = reply_raw2(so, reply, outlen, sreply->sr);
	} else {
		if (istcp) {
			char *tmpbuf;
			u_int16_t *plen;

			tmpbuf = malloc(outlen + 2);
			if (tmpbuf == NULL) {
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

	} /* if (->sr) */

	return (retlen);
}

/* 
 * REPLY_DNSKEY() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_dnskey(struct sreply *sreply)
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
	struct domain *sd = sreply->sd1;
	struct domain_dnskey *sdkey = NULL;
	
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	int i;

	if ((sdkey = find_substruct(sd, INTERNAL_TYPE_DNSKEY)) == NULL)
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

	SET_DNS_REPLY(odh);
	if (sreply->sr == NULL)
		SET_DNS_AUTHORITATIVE(odh);
	else	
		SET_DNS_RECURSION_AVAIL(odh);

	HTONS(odh->query);

	odh->question = htons(1);
	odh->answer = htons(sdkey->dnskey_count);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	a_count = 0;

	do {
		if ((outlen + sizeof(struct answer) + 
			sdkey->dnskey[a_count].publickey_len) > replysize) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			goto out;
		}

		/*
		 * answer->name is a pointer to the request (0xc00c) 
		 */

		answer->name[0] = 0xc0;				/* 1 byte */
		answer->name[1] = 0x0c;				/* 2 bytes */
		answer->type = q->hdr->qtype;			/* 4 bytes */	
		answer->class = q->hdr->qclass;			/* 6 bytes */
		if (sreply->sr != NULL)
			answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_DNSKEY] - (time(NULL) - sd->created));
		else
			answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_DNSKEY]);			/* 10 bytes */

		answer->rdlength = htons(sdkey->dnskey[a_count].publickey_len + 4);	/* 12 bytes */

		answer->flags = htons(sdkey->dnskey[a_count].flags);
		answer->protocol = sdkey->dnskey[a_count].protocol;
		answer->algorithm = sdkey->dnskey[a_count].algorithm;
			
		outlen += sizeof(struct answer);

		memcpy(&reply[outlen], sdkey->dnskey[a_count].public_key,
			sdkey->dnskey[a_count].publickey_len);

		outlen += sdkey->dnskey[a_count].publickey_len;

		a_count++;
		/* set new offset for answer */
		answer = (struct answer *)&reply[outlen];
	} while (a_count < RECORD_COUNT && --sdkey->dnskey_count);

	/* Add RRSIG reply_dnskey */
	if (dnssec && q->dnssecok) {
		int tmplen = 0;
		int origlen = outlen;

		for (i = 0; i < a_count; i++) {
			origlen = outlen; 

			tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, INTERNAL_TYPE_DNSKEY, sd, reply, replysize, outlen, i);
		
			if (tmplen == 0) {
				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				goto out;
			}

			outlen = tmplen;

			if (outlen > origlen)
				odh->answer = htons(a_count + 1 + i);	
		}

		}

	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen);
	}

out:
	if (sreply->sr != NULL) {
		retlen = reply_raw2(so, reply, outlen, sreply->sr);
	} else {
		if (istcp) {
			char *tmpbuf;
			u_int16_t *plen;

			tmpbuf = malloc(outlen + 2);
			if (tmpbuf == NULL) {
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

	} /* if (->sr) */

	return (retlen);
}

/*
 * REPLY_RRSIG() - replies a DNS question (*q) on socket (so)
 *
 */


int		
reply_rrsig(struct sreply *sreply, DB *db)
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
	struct domain *sd = sreply->sd1;
	struct domain_rrsig *sdrr = NULL;
	
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;
	int tmplen = 0;
	int i;

	if ((sdrr = find_substruct(sd, INTERNAL_TYPE_RRSIG)) == NULL)
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

	SET_DNS_REPLY(odh);
	if (sreply->sr == NULL)
		SET_DNS_AUTHORITATIVE(odh);
	else	
		SET_DNS_RECURSION_AVAIL(odh);

	HTONS(odh->query);

	odh->question = htons(1);
	odh->nsrr = 0;
	odh->additional = 0;

	a_count = 0;

	if (sd->flags & DOMAIN_HAVE_A) {
		RRSIG_ALIAS(INTERNAL_TYPE_A);
	}
	if (sd->flags & DOMAIN_HAVE_SOA) {
		RRSIG_ALIAS(INTERNAL_TYPE_SOA);
	}
	if (sd->flags & DOMAIN_HAVE_CNAME) {
		RRSIG_ALIAS(INTERNAL_TYPE_CNAME);
	}
	if (sd->flags & DOMAIN_HAVE_PTR) {
		RRSIG_ALIAS(INTERNAL_TYPE_PTR);
	}
	if (sd->flags & DOMAIN_HAVE_MX) {
		RRSIG_ALIAS(INTERNAL_TYPE_MX);
	}
	if (sd->flags & DOMAIN_HAVE_AAAA) {
		RRSIG_ALIAS(INTERNAL_TYPE_AAAA);
	}
	if (sd->flags & DOMAIN_HAVE_NS) {
		RRSIG_ALIAS(INTERNAL_TYPE_NS);
	}
	if (sd->flags & DOMAIN_HAVE_TXT) {
		RRSIG_ALIAS(INTERNAL_TYPE_TXT);
	}
	if (sd->flags & DOMAIN_HAVE_SRV) {
		RRSIG_ALIAS(INTERNAL_TYPE_SRV);
	}
	if (sd->flags & DOMAIN_HAVE_SPF) {
		RRSIG_ALIAS(INTERNAL_TYPE_SPF);
	}
	if (sd->flags & DOMAIN_HAVE_SSHFP) {
		RRSIG_ALIAS(INTERNAL_TYPE_SSHFP);
	}
	if (sd->flags & DOMAIN_HAVE_NAPTR) {
		RRSIG_ALIAS(INTERNAL_TYPE_NAPTR);
	}
	if (sd->flags & DOMAIN_HAVE_DNSKEY) {
		for (i = 0; i < sdrr->rrsig_dnskey_count; i++) {
			odh->answer = htons(a_count++);
			tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, INTERNAL_TYPE_DNSKEY, sd, reply, replysize, outlen, i);
			if (tmplen == 0) {
				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				goto out;
			}

			outlen = tmplen;
		}
	}
	if (sd->flags & DOMAIN_HAVE_DS) {
		RRSIG_ALIAS(INTERNAL_TYPE_DS);
	}
	if (sd->flags & DOMAIN_HAVE_NSEC) {
		RRSIG_ALIAS(INTERNAL_TYPE_NSEC);
	}

	odh->answer = htons(a_count);

	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen);
	}

out:
	if (sreply->sr != NULL) {
		retlen = reply_raw2(so, reply, outlen, sreply->sr);
	} else {
		if (istcp) {
			char *tmpbuf;
			u_int16_t *plen;

			tmpbuf = malloc(outlen + 2);
			if (tmpbuf == NULL) {
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

	} /* if (->sr) */

	return (retlen);


}

/* 
 * REPLY_AAAA() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_aaaa(struct sreply *sreply, DB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	u_int16_t outlen = 0;
	int aaaa_count;
	int mod, pos;

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
	struct domain *sd = sreply->sd1;
	struct domain_aaaa *sdaaaa = NULL;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;

	if ((sdaaaa = find_substruct(sd, INTERNAL_TYPE_AAAA)) == NULL)
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

	SET_DNS_REPLY(odh);
	if (sreply->sr == NULL)
		SET_DNS_AUTHORITATIVE(odh);
	else
		SET_DNS_RECURSION_AVAIL(odh);
	
	HTONS(odh->query);

	odh->question = htons(1);
	odh->answer = htons(sdaaaa->aaaa_count);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
			q->hdr->namelen + 4);
		

	aaaa_count = 0;
	pos = sdaaaa->aaaa_ptr;
	mod = sdaaaa->aaaa_count;

	do {
		answer->name[0] = 0xc0;
		answer->name[1] = 0x0c;
		answer->type = q->hdr->qtype;
		answer->class = q->hdr->qclass;
		if (sreply->sr != NULL)
			answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_AAAA] - (time(NULL) - sd->created));
		else
			answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_AAAA]);			/* 10 bytes */

		answer->rdlength = htons(sizeof(struct in6_addr));

		memcpy((char *)&answer->rdata, (char *)&sdaaaa->aaaa[pos++ % mod], sizeof(struct in6_addr));
		outlen += 28;

		/* can we afford to write another header? if no truncate */
		if (sdaaaa->aaaa_count > 1 && outlen + 28 > replysize) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			goto out;
		}

		aaaa_count++;

		/* set new offset for answer */
		answer = (struct answer *)&reply[outlen];
	} while (aaaa_count < RECORD_COUNT && --sdaaaa->aaaa_count);

	/* RRSIG reply_aaaa */
	if (dnssec && q->dnssecok) {
		int tmplen = 0;
		int origlen = outlen;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, INTERNAL_TYPE_AAAA, sd, reply, replysize, outlen, 0);
	
		if (tmplen == 0) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->answer = htons(aaaa_count + 1);	

	}

	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen);
	}

out:
	if (sreply->sr != NULL) {
		retlen = reply_raw2(so, reply, outlen, sreply->sr);
	} else {
		if (istcp) {
			char *tmpbuf;
			u_int16_t *plen;

			tmpbuf = malloc(outlen + 2);
			if (tmpbuf == NULL) {
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
	}

	sdaaaa->aaaa_ptr = (sdaaaa->aaaa_ptr + 1) % mod;
	sdaaaa->aaaa_count = mod;			
	update_db(db, sd);

	return (retlen);
}

/* 
 * REPLY_MX() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_mx(struct sreply *sreply, DB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	struct domain *sd0 = NULL;
	int mx_count;
	u_int16_t *plen;
	char *name;
	u_int16_t outlen = 0;
	u_int16_t namelen;
	int additional = 0;
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
	struct domain *sd = sreply->sd1;
	struct domain_mx *sdmx = NULL;
	int istcp = sreply->istcp;
	int wildcard = sreply->wildcard;
	int replysize = 512;
	int retlen = -1;
	
	struct domain *sdhave_a = NULL, *sdhave_aaaa = NULL;

	if ((sdmx = find_substruct(sd, INTERNAL_TYPE_MX)) == NULL) {
		dolog(LOG_INFO, "no such record MX!\n");
		return -1;
	}


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

	SET_DNS_REPLY(odh);

	if (sreply->sr == NULL) {
		SET_DNS_AUTHORITATIVE(odh);
	} else
		SET_DNS_RECURSION_AVAIL(odh);
	
	HTONS(odh->query);

	odh->question = htons(1);
	odh->answer = htons(sdmx->mx_count);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	mx_count = 0;
	do {
		answer->name[0] = 0xc0;
		answer->name[1] = 0x0c;
		answer->type = q->hdr->qtype;
		answer->class = q->hdr->qclass;
		if (sreply->sr != NULL)
			answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_MX] - (time(NULL) - sd->created));
		else
			answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_MX]);

		answer->rdlength = htons(sizeof(u_int16_t) + sdmx->mx[mx_count].exchangelen);

		answer->mx_priority = htons(sdmx->mx[mx_count].preference);
		memcpy((char *)&answer->exchange, (char *)sdmx->mx[mx_count].exchange, sdmx->mx[mx_count].exchangelen);

		name = sdmx->mx[mx_count].exchange;
		namelen = sdmx->mx[mx_count].exchangelen;

		sd0 = Lookup_zone(db, name, namelen, htons(DNS_TYPE_A), wildcard);
		if (sd0 != NULL) {
			cn1 = malloc(sizeof(struct collects));
			if (cn1 != NULL) {
				cn1->name = malloc(namelen);
				if (cn1->name != NULL) {
					memcpy(cn1->name, name, namelen);
					cn1->namelen = namelen;
					cn1->sd = sd0;
					cn1->type = DNS_TYPE_A;

					SLIST_INSERT_HEAD(&collectshead, cn1, collect_entry);
				}				
			}
		}
		sd0 = Lookup_zone(db, name, namelen, htons(DNS_TYPE_AAAA), wildcard);
		if (sd0 != NULL) {
			cn1 = malloc(sizeof(struct collects));
			if (cn1 != NULL) {
				cn1->name = malloc(namelen);
				if (cn1->name != NULL) {
					memcpy(cn1->name, name, namelen);
					cn1->namelen = namelen;
					cn1->sd = sd0;
					cn1->type = DNS_TYPE_AAAA;

					SLIST_INSERT_HEAD(&collectshead, cn1, collect_entry);
				}				
			}
		}

		outlen += (12 + 2 + sdmx->mx[mx_count].exchangelen);

		/* can we afford to write another header? if no truncate */
		if (sdmx->mx_count > 1 && (outlen + 12 + 2 + sdmx->mx[mx_count].exchangelen) > replysize) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			goto out;
		}

		/* set new offset for answer */
		answer = (struct answer *)&reply[outlen];
	} while (++mx_count < RECORD_COUNT && --sdmx->mx_count);

	/* RRSIG reply_mx*/

	if (dnssec && q->dnssecok) {
		int origlen = outlen;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, INTERNAL_TYPE_MX, sd, reply, replysize, outlen, 0);

		if (tmplen == 0) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->answer = htons(mx_count + 1);	

	}

	/* write additional */

	SLIST_FOREACH(cnp, &collectshead, collect_entry) {
		int addcount;

		switch (cnp->type) {
		case DNS_TYPE_A:
			tmplen = additional_a(cnp->name, cnp->namelen, cnp->sd, reply, replysize, outlen, &addcount);
			if (addcount)
				sdhave_a = cnp->sd;
			additional += addcount;
			break;
		case DNS_TYPE_AAAA:
			tmplen = additional_aaaa(cnp->name, cnp->namelen, cnp->sd, reply, replysize, outlen, &addcount);
			if (addcount)
				sdhave_aaaa = cnp->sd;
			additional += addcount;
			break;
		}

		if (tmplen > 0) {
			outlen = tmplen;
		}
	}

	if (dnssec && q->dnssecok) {
		if (sdhave_a) {
			int origlen = outlen;

			tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, INTERNAL_TYPE_A, sdhave_a, reply, replysize, outlen, 0);

			if (tmplen == 0) {
				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				goto out;
			}

			outlen = tmplen;
			if (outlen > origlen)
				additional++;

		} 

		if (sdhave_aaaa) {
			int origlen = outlen;

			tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, INTERNAL_TYPE_AAAA, sdhave_aaaa, reply, replysize, outlen, 0);

			if (tmplen == 0) {
				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				goto out;
			}

			outlen = tmplen;
			if (outlen > origlen)
				additional++;
		}
	}

	odh->additional = htons(additional);	

	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen);
	}

out:
	while (!SLIST_EMPTY(&collectshead)) {
		cn1 = SLIST_FIRST(&collectshead);
		SLIST_REMOVE_HEAD(&collectshead, collect_entry);
		free(cn1->name);
		free(cn1->sd);
		free(cn1);
	}

	if (sreply->sr != NULL) {
		retlen = reply_raw2(so, reply, outlen, sreply->sr);
	} else {
		if (istcp) {
			char *tmpbuf;

			tmpbuf = malloc(outlen + 2);
			if (tmpbuf == NULL) {
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
	}

	return (retlen);
}

/* 
 * REPLY_NS() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_ns(struct sreply *sreply, DB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	struct domain *sd0;
	int tmplen = 0;
	int ns_count;
	int mod, pos;
	u_int16_t *plen;
	char *name;
	u_int16_t outlen = 0;
	u_int16_t namelen;
	int additional = 0;

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
	struct domain *sd = sreply->sd1;
	struct domain_ns *sdns = NULL;
	int istcp = sreply->istcp;
	int wildcard = sreply->wildcard;
	int replysize = 512;
	int retlen = -1;
	struct domain *sdhave_a = NULL, *sdhave_aaaa = NULL;

	if ((sdns = find_substruct(sd, INTERNAL_TYPE_NS)) == NULL)
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

	SET_DNS_REPLY(odh);

	if (sreply->sr == NULL) {
		switch (sdns->ns_type) {
		case 0:
			SET_DNS_AUTHORITATIVE(odh);
			break;
		default:
			SET_DNS_RECURSION(odh);
			break;
		}
	} else
		SET_DNS_RECURSION_AVAIL(odh);

	
	HTONS(odh->query);

	odh->question = htons(1);
	switch (sdns->ns_type) {
	case NS_TYPE_DELEGATE:
		odh->answer = 0;
		odh->nsrr = htons(sdns->ns_count);	
		break;
	default:
		odh->answer = htons(sdns->ns_count);
		odh->nsrr = 0;
		break;
	}
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	ns_count = 0;
	mod = sdns->ns_count;
	pos = sdns->ns_ptr;

	do {
		answer->name[0] = 0xc0;
		answer->name[1] = 0x0c;
		answer->type = htons(DNS_TYPE_NS);
		answer->class = q->hdr->qclass;
		if (sreply->sr != NULL)
			answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_NS] - (time(NULL) - sd->created));
		else
			answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_NS]);

		name = sdns->ns[pos % mod].nsserver;
		namelen = sdns->ns[pos % mod].nslen;

		answer->rdlength = htons(namelen);

		memcpy((char *)&answer->ns, (char *)name, namelen);

		sd0 = Lookup_zone(db, name, namelen, htons(DNS_TYPE_A), wildcard);
		if (sd0 != NULL) {
			cn1 = malloc(sizeof(struct collects));
			if (cn1 != NULL) {
				cn1->name = malloc(namelen);
				if (cn1->name != NULL) {
					memcpy(cn1->name, name, namelen);
					cn1->namelen = namelen;
					cn1->sd = sd0;
					cn1->type = DNS_TYPE_A;

					SLIST_INSERT_HEAD(&collectshead, cn1, collect_entry);
				}				
			}
			
		}
		sd0 = Lookup_zone(db, name, namelen, htons(DNS_TYPE_AAAA), wildcard);
		if (sd0 != NULL) {
			cn1 = malloc(sizeof(struct collects));
			if (cn1 != NULL) {
				cn1->name = malloc(namelen);
				if (cn1->name != NULL) {
					memcpy(cn1->name, name, namelen);
					cn1->namelen = namelen;
					cn1->sd = sd0;
					cn1->type = DNS_TYPE_AAAA;

					SLIST_INSERT_HEAD(&collectshead, cn1, collect_entry);

				}				
			}
		
		}

		outlen += (12 + namelen);

		/* compress the label if possible */
		if ((tmplen = compress_label((u_char*)reply, outlen, namelen)) > 0) {
			/* XXX */
			outlen = tmplen;
		}

		answer->rdlength = htons(&reply[outlen] - &answer->ns);


		/* can we afford to write another header? if no truncate */
		if (sdns->ns_count > 1 && (outlen + 12 + sdns->ns[pos % mod].nslen) > replysize) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			goto out;
		}

		pos++;
		/* set new offset for answer */
		answer = (struct answer *)&reply[outlen];
	} while (++ns_count < RECORD_COUNT && --sdns->ns_count);


	/* add RRSIG reply_ns */
	if (dnssec && q->dnssecok) {
		int origlen = outlen;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, INTERNAL_TYPE_NS, sd, reply, replysize, outlen, 0);

		if (tmplen == 0) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
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

	/* shuffle through our linked collect structure and add additional */

	SLIST_FOREACH(cnp, &collectshead, collect_entry) {
		int tmplen = 0;
		int addcount = 0;

		switch (cnp->type) {
		case DNS_TYPE_A:
			tmplen = additional_a(cnp->name, cnp->namelen, cnp->sd, reply, replysize, outlen, &addcount);
			if (addcount)
				sdhave_a = cnp->sd;

			additional += addcount;
			break;
		case DNS_TYPE_AAAA:
			tmplen = additional_aaaa(cnp->name, cnp->namelen, cnp->sd, reply, replysize, outlen, &addcount);
			if (addcount)
				sdhave_aaaa = cnp->sd;
			additional += addcount;
			break;
		}

		if (tmplen > 0)
			outlen = tmplen;

	}
	
	/* Add RRSIG */
	if (dnssec && q->dnssecok) {
		if (sdhave_a) {
			int origlen = outlen;
			tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, INTERNAL_TYPE_A, sdhave_a, reply, replysize, outlen, 0);

			if (tmplen == 0) {
				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				goto out;
			}

			outlen = tmplen;

			if (outlen > origlen)
				additional++;
		} 

		if (sdhave_aaaa) {
			int origlen = outlen;

			tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, INTERNAL_TYPE_AAAA, sdhave_aaaa, reply, replysize, outlen, 0);

			if (tmplen == 0) {
				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				goto out;
			}

			outlen = tmplen;

			if (outlen > origlen)
				additional++;
		}
	}

	odh->additional = htons(additional);	

	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen);
	}

out:
	while (!SLIST_EMPTY(&collectshead)) {
		cn1 = SLIST_FIRST(&collectshead);
		SLIST_REMOVE_HEAD(&collectshead, collect_entry);
		free(cn1->name);
		free(cn1->sd);
		free(cn1);
	}

	if (sreply->sr != NULL) {
		retlen = reply_raw2(so, reply, outlen, sreply->sr);
	} else {
		if (istcp) {
			char *tmpbuf;

			tmpbuf = malloc(outlen + 2);
			if (tmpbuf == NULL) {
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
	}

	sdns->ns_ptr = (sdns->ns_ptr + 1) % mod;
	sdns->ns_count = mod;	

	update_db(db, sd);

	return (retlen);
}


/* 
 * REPLY_CNAME() - replies a DNS question (*q) on socket (so)
 *
 */


int
reply_cname(struct sreply *sreply)
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
	struct domain *sd = sreply->sd1;
	struct domain *sd1 = sreply->sd2;
	struct domain_cname *sdcname = NULL;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;

	if ((sdcname = find_substruct(sd, INTERNAL_TYPE_CNAME)) == NULL)
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

	SET_DNS_REPLY(odh);
	if (sreply->sr == NULL)
		SET_DNS_AUTHORITATIVE(odh);
	else
		SET_DNS_RECURSION_AVAIL(odh);
	
	HTONS(odh->query);

	odh->question = htons(1);
	odh->answer = htons(1);
	odh->nsrr = 0;
	odh->additional = 0;

	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	answer->name[0] = 0xc0;
	answer->name[1] = 0x0c;
	answer->type = htons(DNS_TYPE_CNAME);
	answer->class = q->hdr->qclass;
	if (sreply->sr != NULL)
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_CNAME] - (time(NULL) - sd->created));
	else
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_CNAME]);

	outlen += 12;			/* up to rdata length */

	p = (char *)&answer->rdata;

	label = &sdcname->cname[0];
	labellen = sdcname->cnamelen;

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

	
	if (ntohs(q->hdr->qtype) == DNS_TYPE_A && sd1 != NULL) {
		tmplen = additional_a(sdcname->cname, sdcname->cnamelen, sd1, reply, replysize, outlen, &addcount);

		if (tmplen > 0)
			outlen = tmplen;

		NTOHS(odh->answer);
		odh->answer += addcount;
		HTONS(odh->answer);
	} else if (ntohs(q->hdr->qtype) == DNS_TYPE_AAAA && sd1 != NULL) {
		tmplen = additional_aaaa(sdcname->cname, sdcname->cnamelen, sd1, reply, replysize, outlen, &addcount);

		if (tmplen > 0)
			outlen = tmplen;

		NTOHS(odh->answer);
		odh->answer += addcount;
		HTONS(odh->answer);
	} else if (ntohs(q->hdr->qtype) == DNS_TYPE_MX && sd1 != NULL) {
		tmplen = additional_mx(sdcname->cname, sdcname->cnamelen, sd1, reply, replysize, outlen, &addcount);

		if (tmplen > 0)
			outlen = tmplen;

		NTOHS(odh->answer);
		odh->answer += addcount;
		HTONS(odh->answer);
	} else if (ntohs(q->hdr->qtype) == DNS_TYPE_PTR && sd1 != NULL) {
		tmplen = additional_ptr(sdcname->cname, sdcname->cnamelen, sd1, reply, replysize, outlen, &addcount);

		if (tmplen > 0)
			outlen = tmplen;

		NTOHS(odh->answer);
		odh->answer += addcount;
		HTONS(odh->answer);
	}	

	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen);
	}

	if (sreply->sr != NULL) {
		retlen = reply_raw2(so, reply, outlen, sreply->sr);
	} else {
		if (istcp) {
			char *tmpbuf;

			tmpbuf = malloc(outlen + 2);
			if (tmpbuf == NULL) {
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
	}

	return (retlen);
}

/* 
 * REPLY_PTR() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_ptr(struct sreply *sreply)
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
	struct domain *sd = sreply->sd1;
	struct domain_ptr *sdptr = NULL;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;

	if ((sdptr = find_substruct(sd, INTERNAL_TYPE_PTR)) == NULL)
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

	SET_DNS_REPLY(odh);
	if (sreply->sr == NULL)
		SET_DNS_AUTHORITATIVE(odh);
	else
		SET_DNS_RECURSION_AVAIL(odh);
	
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
	if (sreply->sr != NULL)
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_PTR] - (time(NULL) - sd->created));
	else
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_PTR]);

	outlen += 12;			/* up to rdata length */

	p = (char *)&answer->rdata;

	label = &sdptr->ptr[0];
	labellen = sdptr->ptrlen;

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

	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen);
	}
	
	if (sreply->sr != NULL) {
		retlen = reply_raw2(so, reply, outlen, sreply->sr);
	} else {
		if (istcp) {
			char *tmpbuf;
			u_int16_t *plen;

			tmpbuf = malloc(outlen + 2);
			if (tmpbuf == NULL) {
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
	}

	return (retlen);
}

/* 
 * REPLY_SOA() - replies a DNS question (*q) on socket (so)
 *
 */


int
reply_soa(struct sreply *sreply)
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

	struct soa {
		char *nsserver;
		char *responsible_person;
		u_int32_t serial;
		u_int32_t refresh;
		u_int32_t retry;
		u_int32_t expire;
		u_int32_t minttl;
	};
		

	struct answer *answer;

	int so = sreply->so;
	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct sockaddr *sa = sreply->sa;
	int salen = sreply->salen;
	struct domain *sd = sreply->sd1;
	struct domain_soa *sdsoa = NULL;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;

	if ((sdsoa = find_substruct(sd, INTERNAL_TYPE_SOA)) == NULL)
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

	SET_DNS_REPLY(odh);
	if (sreply->sr == NULL)
		SET_DNS_AUTHORITATIVE(odh);
	else
		SET_DNS_RECURSION_AVAIL(odh);
	
	NTOHS(odh->query);

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
	if (sreply->sr != NULL)
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_SOA] - (time(NULL) - sd->created));
	else
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_SOA]);

	outlen += 12;			/* up to rdata length */

	p = (char *)&answer->rdata;


	label = sdsoa->soa.nsserver;
	labellen = sdsoa->soa.nsserver_len;

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

	label = sdsoa->soa.responsible_person;
	labellen = sdsoa->soa.rp_len;
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
	if ((outlen + sizeof(sdsoa->soa.serial)) > replysize) {
		/* XXX server error reply? */
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(sdsoa->soa.serial);
	outlen += sizeof(sdsoa->soa.serial);	/* XXX */
	
	/* XXX */
	if ((outlen + sizeof(sdsoa->soa.refresh)) > replysize) {
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(sdsoa->soa.refresh);
	outlen += sizeof(sdsoa->soa.refresh);	/* XXX */

	if ((outlen + sizeof(sdsoa->soa.retry)) > replysize) {
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(sdsoa->soa.retry);
	outlen += sizeof(sdsoa->soa.retry);	/* XXX */

	if ((outlen + sizeof(sdsoa->soa.expire)) > replysize) {
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(sdsoa->soa.expire);
	outlen += sizeof(sdsoa->soa.expire);

	if ((outlen + sizeof(sdsoa->soa.minttl)) > replysize) {
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(sdsoa->soa.minttl);
	outlen += sizeof(sdsoa->soa.minttl);

	answer->rdlength = htons(&reply[outlen] - &answer->rdata);

	/* RRSIG reply_soa */
	if (dnssec && q->dnssecok) {
		int tmplen = 0;
		int origlen = outlen;
	
		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, INTERNAL_TYPE_SOA, sd, reply, replysize, outlen, 0);
	
		if (tmplen == 0) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen) {
			NTOHS(odh->answer);
			odh->answer++;
			HTONS(odh->answer);
		}
	}

	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen);
	}

out:
	
	if (sreply->sr != NULL) {
		retlen = reply_raw2(so, reply, outlen, sreply->sr);
	} else {
		if (istcp) {
			char *tmpbuf;
			u_int16_t *plen;

			tmpbuf = malloc(outlen + 2);
			if (tmpbuf == NULL) {
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
	}

	return (retlen);
}

/* 
 * REPLY_SPF() - replies a DNS question (*q) on socket (so)
 * 			based on reply_txt...
 */


int
reply_spf(struct sreply *sreply)
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
	struct domain *sd = sreply->sd1;
	struct domain_spf *sdspf = NULL;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;

	if ((sdspf = find_substruct(sd, INTERNAL_TYPE_SPF)) == NULL)
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

	SET_DNS_REPLY(odh);
	if (sreply->sr == NULL)
		SET_DNS_AUTHORITATIVE(odh);
	else
		SET_DNS_RECURSION_AVAIL(odh);
	
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
	if (sreply->sr != NULL)
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_SPF] - (time(NULL) - sd->created));
	else
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_SPF]);

	outlen += 12;			/* up to rdata length */

	p = (char *)&answer->rdata;

	*p = sdspf->spflen;
	memcpy((p + 1), sdspf->spf, sdspf->spflen);
	outlen += (sdspf->spflen + 1);

	answer->rdlength = htons(sdspf->spflen + 1);

	/* Add RRSIG reply_spf */
	if (dnssec && q->dnssecok) {
		int tmplen = 0;
		int origlen = outlen;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, INTERNAL_TYPE_SPF, sd, reply, replysize, outlen, 0);
	
		if (tmplen == 0) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->answer = htons(2);	

	}

	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen);
	}

out:

	if (sreply->sr != NULL) {
		retlen = reply_raw2(so, reply, outlen, sreply->sr);
	} else {
		if (istcp) {
			char *tmpbuf;
			u_int16_t *plen;

			tmpbuf = malloc(outlen + 2);
			if (tmpbuf == NULL) {
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
	}

	return (retlen);
}

/* 
 * REPLY_TXT() - replies a DNS question (*q) on socket (so)
 *
 */


int
reply_txt(struct sreply *sreply)
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
	struct domain *sd = sreply->sd1;
	struct domain_txt *sdtxt = NULL;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;

	if ((sdtxt = find_substruct(sd, INTERNAL_TYPE_TXT)) == NULL)
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

	SET_DNS_REPLY(odh);
	if (sreply->sr == NULL)
		SET_DNS_AUTHORITATIVE(odh);
	else
		SET_DNS_RECURSION_AVAIL(odh);
	
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
	if (sreply->sr != NULL)
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_TXT] - (time(NULL) - sd->created));
	else
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_TXT]);

	outlen += 12;			/* up to rdata length */

	p = (char *)&answer->rdata;

	*p = sdtxt->txtlen;
	memcpy((p + 1), sdtxt->txt, sdtxt->txtlen);
	outlen += (sdtxt->txtlen + 1);

	answer->rdlength = htons(sdtxt->txtlen + 1);

	/* Add RRSIG reply_txt */
	if (dnssec && q->dnssecok) {
		int tmplen = 0;
		int origlen = outlen;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, INTERNAL_TYPE_TXT, sd, reply, replysize, outlen, 0);
	
		if (tmplen == 0) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->answer = htons(2);	

	}

	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen);
	}

out:

	if (sreply->sr != NULL) {
		retlen = reply_raw2(so, reply, outlen, sreply->sr);
	} else {
		if (istcp) {
			char *tmpbuf;
			u_int16_t *plen;

			tmpbuf = malloc(outlen + 2);
			if (tmpbuf == NULL) {
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
	}

	return (retlen);
}


/* 
 * REPLY_VERSION() - replies a DNS question (*q) on socket (so)
 *
 */


int
reply_version(struct sreply *sreply)
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

	SET_DNS_REPLY(odh);
	if (sreply->sr == NULL)
		SET_DNS_AUTHORITATIVE(odh);
	else
		SET_DNS_RECURSION_AVAIL(odh);
	
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

	if (sreply->sr != NULL) {
		retlen = reply_raw2(so, reply, outlen, sreply->sr);
	} else {
		if (istcp) {
			char *tmpbuf;
			u_int16_t *plen;

			tmpbuf = malloc(outlen + 2);
			if (tmpbuf == NULL) {
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
	}

	return (retlen);
}

/* 
 * REPLY_SSHFP() - replies a DNS question (*q) on socket (so)
 *			(based on reply_srv)
 */


int
reply_sshfp(struct sreply *sreply)
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
	struct domain *sd = sreply->sd1;
	struct domain_sshfp *sdsshfp = NULL;
	int istcp = sreply->istcp;
	int typelen = 0;
	int replysize = 512;
	int retlen = -1;

	if ((sdsshfp = find_substruct(sd, INTERNAL_TYPE_SSHFP)) == NULL)
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

	SET_DNS_REPLY(odh);

	if (sreply->sr == NULL) {
		SET_DNS_AUTHORITATIVE(odh);
	} else
		SET_DNS_RECURSION_AVAIL(odh);
	
	HTONS(odh->query);

	odh->question = htons(1);
	odh->answer = htons(sdsshfp->sshfp_count);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	sshfp_count = 0;
	do {
		answer->name[0] = 0xc0;
		answer->name[1] = 0x0c;
		answer->type = q->hdr->qtype;
		answer->class = q->hdr->qclass;
		if (sreply->sr != NULL)
			answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_SSHFP] - (time(NULL) - sd->created));
		else
			answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_SSHFP]);

		switch (sdsshfp->sshfp[sshfp_count].fptype) {
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
		answer->sshfp_alg = sdsshfp->sshfp[sshfp_count].algorithm;
		answer->sshfp_type = sdsshfp->sshfp[sshfp_count].fptype;

		memcpy((char *)&answer->target, (char *)sdsshfp->sshfp[sshfp_count].fingerprint, sdsshfp->sshfp[sshfp_count].fplen);

		/* can we afford to write another header? if no truncate */
		if (sdsshfp->sshfp_count > 1 && (outlen + 12 + 2 + sdsshfp->sshfp[sshfp_count].fplen) > replysize) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			goto out;
		}

		/* set new offset for answer */
		outlen += (12 + 2 + sdsshfp->sshfp[sshfp_count].fplen);
		answer = (struct answer *)&reply[outlen];
	} while (++sshfp_count < RECORD_COUNT && --sdsshfp->sshfp_count);

	/* RRSIG reply_sshfp */
	if (dnssec && q->dnssecok) {
		int tmplen = 0;
		int origlen = outlen;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, INTERNAL_TYPE_SSHFP, sd, reply, replysize, outlen, 0);
	
		if (tmplen == 0) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->answer = htons(sshfp_count + 1);	

	}

	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen);
	}

out:
	if (sreply->sr != NULL) {
		retlen = reply_raw2(so, reply, outlen, sreply->sr);
	} else {
		if (istcp) {
			char *tmpbuf;

			tmpbuf = malloc(outlen + 2);
			if (tmpbuf == NULL) {
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
	}

	return (retlen);
}


/* 
 * REPLY_NAPTR() - replies a DNS question (*q) on socket (so)
 *			(based on reply_srv)
 */


int
reply_naptr(struct sreply *sreply, DB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	struct domain *sd0;
	int naptr_count;
	u_int16_t *plen;
	char *name;
	u_int16_t outlen;
	u_int16_t namelen;
	int additional = 0;

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
	struct domain *sd = sreply->sd1;
	struct domain_naptr *sdnaptr = NULL;
	int istcp = sreply->istcp;
	int wildcard = sreply->wildcard;
	int replysize = 512;
	int tmplen, savelen;
	char *p;
	int retlen = -1;

	struct domain *sdhave_a = NULL, *sdhave_aaaa = NULL;

	if ((sdnaptr = find_substruct(sd, INTERNAL_TYPE_NAPTR)) == NULL)
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

	SET_DNS_REPLY(odh);

	if (sreply->sr == NULL) {
		SET_DNS_AUTHORITATIVE(odh);
	} else
		SET_DNS_RECURSION_AVAIL(odh);
	
	HTONS(odh->query);

	odh->question = htons(1);
	odh->answer = htons(sdnaptr->naptr_count);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	naptr_count = 0;
	do {
		savelen = outlen;
		answer->name[0] = 0xc0;
		answer->name[1] = 0x0c;
		answer->type = q->hdr->qtype;
		answer->class = q->hdr->qclass;
		if (sreply->sr != NULL)
			answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_NAPTR] - (time(NULL) - sd->created));
		else
			answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_NAPTR]);

		answer->naptr_order = htons(sdnaptr->naptr[naptr_count].order);
		answer->naptr_preference = htons(sdnaptr->naptr[naptr_count].preference);

		p = (char *)&answer->rest;

		*p = sdnaptr->naptr[naptr_count].flagslen;
		memcpy((p + 1), sdnaptr->naptr[naptr_count].flags, sdnaptr->naptr[naptr_count].flagslen);
		p += (sdnaptr->naptr[naptr_count].flagslen + 1);
		outlen += (1 + sdnaptr->naptr[naptr_count].flagslen);

		/* services */
		*p = sdnaptr->naptr[naptr_count].serviceslen;
		memcpy((p + 1), sdnaptr->naptr[naptr_count].services, sdnaptr->naptr[naptr_count].serviceslen);
		p += (sdnaptr->naptr[naptr_count].serviceslen + 1);
		outlen += (1 + sdnaptr->naptr[naptr_count].serviceslen);
		
		/* regexp */
		*p = sdnaptr->naptr[naptr_count].regexplen;
		memcpy((p + 1), sdnaptr->naptr[naptr_count].regexp, sdnaptr->naptr[naptr_count].regexplen);
		p += (sdnaptr->naptr[naptr_count].regexplen + 1);
		outlen += (1 + sdnaptr->naptr[naptr_count].regexplen);
	
		/* replacement */

		memcpy((char *)p, (char *)sdnaptr->naptr[naptr_count].replacement, sdnaptr->naptr[naptr_count].replacementlen);
	
		name = sdnaptr->naptr[naptr_count].replacement;
		namelen = sdnaptr->naptr[naptr_count].replacementlen;

		outlen += (12 + 4 + sdnaptr->naptr[naptr_count].replacementlen);

		/* compress the label if possible */
		if ((tmplen = compress_label((u_char*)reply, outlen, namelen)) > 0) {
			outlen = tmplen;
		}

		answer->rdlength = htons(outlen - (savelen + 12));


		sd0 = Lookup_zone(db, name, namelen, htons(DNS_TYPE_A), wildcard);
		if (sd0 != NULL) {
			cn1 = malloc(sizeof(struct collects));
			if (cn1 != NULL) {
				cn1->name = malloc(namelen);
				if (cn1->name != NULL) {
					memcpy(cn1->name, name, namelen);
					cn1->namelen = namelen;
					cn1->sd = sd0;
					cn1->type = DNS_TYPE_A;

					SLIST_INSERT_HEAD(&collectshead, cn1, collect_entry);
				}				
			}
		}
		sd0 = Lookup_zone(db, name, namelen, htons(DNS_TYPE_AAAA), wildcard);
		if (sd0 != NULL) {
			cn1 = malloc(sizeof(struct collects));
			if (cn1 != NULL) {
				cn1->name = malloc(namelen);
				if (cn1->name != NULL) {
					memcpy(cn1->name, name, namelen);
					cn1->namelen = namelen;
					cn1->sd = sd0;
					cn1->type = DNS_TYPE_AAAA;

					SLIST_INSERT_HEAD(&collectshead, cn1, collect_entry);
				}				
			}
		}


		/* can we afford to write another header? if no truncate */
		if (sdnaptr->naptr_count > naptr_count && (outlen + 12 + 4 + sdnaptr->naptr[naptr_count + 1].replacementlen + sdnaptr->naptr[naptr_count + 1].flagslen + 1 + sdnaptr->naptr[naptr_count + 1].serviceslen + 1 + sdnaptr->naptr[naptr_count + 1].regexplen + 1) > replysize) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			goto out;
		}

		/* set new offset for answer */
		answer = (struct answer *)&reply[outlen];
	} while (++naptr_count < RECORD_COUNT && --sdnaptr->naptr_count);

	/* RRSIG reply_naptr*/

	if (dnssec && q->dnssecok) {
		int origlen = outlen;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, INTERNAL_TYPE_NAPTR, sd, reply, replysize, outlen, 0);

		if (tmplen == 0) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->answer = htons(naptr_count + 1);	

	}

	/* write additional */
	SLIST_FOREACH(cnp, &collectshead, collect_entry) {
		int addcount;

		switch (cnp->type) {
		case DNS_TYPE_A:
			tmplen = additional_a(cnp->name, cnp->namelen, cnp->sd, reply, replysize, outlen, &addcount);
			if (addcount)
				sdhave_a = cnp->sd;
			additional += addcount;
			break;
		case DNS_TYPE_AAAA:
			tmplen = additional_aaaa(cnp->name, cnp->namelen, cnp->sd, reply, replysize, outlen, &addcount);
			if (addcount)
				sdhave_aaaa = cnp->sd;
			additional += addcount;
			break;
		}

		if (tmplen > 0) {
			outlen = tmplen;
		}
	}

	if (dnssec && q->dnssecok) {
		if (sdhave_a) {
			int origlen = outlen;

			tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, INTERNAL_TYPE_A, sdhave_a, reply, replysize, outlen, 0);

			if (tmplen == 0) {
				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				goto out;
			}

			outlen = tmplen;
			if (outlen > origlen)
				additional++;

		} 

		if (sdhave_aaaa) {
			int origlen = outlen;

			tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, INTERNAL_TYPE_AAAA, sdhave_aaaa, reply, replysize, outlen, 0);

			if (tmplen == 0) {
				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				goto out;
			}

			outlen = tmplen;
			if (outlen > origlen)
				additional++;
		}
	}

	odh->additional = htons(additional);	

	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen);
	}

out:
	while (!SLIST_EMPTY(&collectshead)) {
		cn1 = SLIST_FIRST(&collectshead);
		SLIST_REMOVE_HEAD(&collectshead, collect_entry);
		free(cn1->name);
		free(cn1->sd);
		free(cn1);
	}

	if (sreply->sr != NULL) {
		retlen = reply_raw2(so, reply, outlen, sreply->sr);
	} else {
		if (istcp) {
			char *tmpbuf;

			tmpbuf = malloc(outlen + 2);
			if (tmpbuf == NULL) {
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
	}

	return (retlen);
}


/* 
 * REPLY_SRV() - replies a DNS question (*q) on socket (so)
 *			(based on reply_mx)
 */


int
reply_srv(struct sreply *sreply, DB *db)
{
	char *reply = sreply->replybuf;
	struct dns_header *odh;
	struct domain *sd0;
	int srv_count;
	u_int16_t *plen;
	char *name;
	u_int16_t outlen;
	u_int16_t namelen;
	int additional = 0;

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
	struct domain *sd = sreply->sd1;
	struct domain_srv *sdsrv = NULL;
	int istcp = sreply->istcp;
	int wildcard = sreply->wildcard;
	int replysize = 512;
	int retlen = -1;
	int tmplen;

	struct domain *sdhave_a = NULL, *sdhave_aaaa = NULL;

	if ((sdsrv = find_substruct(sd, INTERNAL_TYPE_SRV)) == NULL)
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

	SET_DNS_REPLY(odh);

	if (sreply->sr == NULL) {
		SET_DNS_AUTHORITATIVE(odh);
	} else
		SET_DNS_RECURSION_AVAIL(odh);
	
	HTONS(odh->query);

	odh->question = htons(1);
	odh->answer = htons(sdsrv->srv_count);
	odh->nsrr = 0;
	odh->additional = 0;

	/* skip dns header, question name, qtype and qclass */
	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4);

	srv_count = 0;
	do {
		answer->name[0] = 0xc0;
		answer->name[1] = 0x0c;
		answer->type = q->hdr->qtype;
		answer->class = q->hdr->qclass;
		if (sreply->sr != NULL)
			answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_SRV] - (time(NULL) - sd->created));
		else
			answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_SRV]);

		answer->rdlength = htons((3 * sizeof(u_int16_t)) + sdsrv->srv[srv_count].targetlen);

		answer->srv_priority = htons(sdsrv->srv[srv_count].priority);
		answer->srv_weight = htons(sdsrv->srv[srv_count].weight);
		answer->srv_port = htons(sdsrv->srv[srv_count].port);

		memcpy((char *)&answer->target, (char *)sdsrv->srv[srv_count].target, sdsrv->srv[srv_count].targetlen);

		name = sdsrv->srv[srv_count].target;
		namelen = sdsrv->srv[srv_count].targetlen;

		sd0 = Lookup_zone(db, name, namelen, htons(DNS_TYPE_A), wildcard);
		if (sd0 != NULL) {
			cn1 = malloc(sizeof(struct collects));
			if (cn1 != NULL) {
				cn1->name = malloc(namelen);
				if (cn1->name != NULL) {
					memcpy(cn1->name, name, namelen);
					cn1->namelen = namelen;
					cn1->sd = sd0;
					cn1->type = DNS_TYPE_A;

					SLIST_INSERT_HEAD(&collectshead, cn1, collect_entry);
				}				
			}
		}
		sd0 = Lookup_zone(db, name, namelen, htons(DNS_TYPE_AAAA), wildcard);
		if (sd0 != NULL) {
			cn1 = malloc(sizeof(struct collects));
			if (cn1 != NULL) {
				cn1->name = malloc(namelen);
				if (cn1->name != NULL) {
					memcpy(cn1->name, name, namelen);
					cn1->namelen = namelen;
					cn1->sd = sd0;
					cn1->type = DNS_TYPE_AAAA;

					SLIST_INSERT_HEAD(&collectshead, cn1, collect_entry);
				}				
			}
		}

		outlen += (12 + 6 + sdsrv->srv[srv_count].targetlen);

		/* can we afford to write another header? if no truncate */
		if (sdsrv->srv_count > 1 && (outlen + 12 + 6 + sdsrv->srv[srv_count].targetlen) > replysize) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			goto out;
		}

		/* set new offset for answer */
		answer = (struct answer *)&reply[outlen];
	} while (++srv_count < RECORD_COUNT && --sdsrv->srv_count);

	if (dnssec && q->dnssecok) {
		int origlen = outlen;

		tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, INTERNAL_TYPE_SRV, sd, reply, replysize, outlen, 0);

		if (tmplen == 0) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->answer = htons(srv_count + 1);	

	}

	/* write additional */
	SLIST_FOREACH(cnp, &collectshead, collect_entry) {
		int addcount;

		switch (cnp->type) {
		case DNS_TYPE_A:
			tmplen = additional_a(cnp->name, cnp->namelen, cnp->sd, reply, replysize, outlen, &addcount);
			if (addcount)
				sdhave_a = cnp->sd;
			additional += addcount;
			break;
		case DNS_TYPE_AAAA:
			tmplen = additional_aaaa(cnp->name, cnp->namelen, cnp->sd, reply, replysize, outlen, &addcount);
			if (addcount)
				sdhave_aaaa = cnp->sd;
			additional += addcount;
			break;
		}

		if (tmplen > 0) {
			outlen = tmplen;
		}
	}

	if (dnssec && q->dnssecok) {
		if (sdhave_a) {
			int origlen = outlen;

			tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, INTERNAL_TYPE_A, sdhave_a, reply, replysize, outlen, 0);

			if (tmplen == 0) {
				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				goto out;
			}

			outlen = tmplen;
			if (outlen > origlen)
				additional++;

		} 

		if (sdhave_aaaa) {
			int origlen = outlen;

			tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen, INTERNAL_TYPE_AAAA, sdhave_aaaa, reply, replysize, outlen, 0);

			if (tmplen == 0) {
				NTOHS(odh->query);
				SET_DNS_TRUNCATION(odh);
				HTONS(odh->query);
				goto out;
			}

			outlen = tmplen;
			if (outlen > origlen)
				additional++;
		}
	}

	odh->additional = htons(additional);	

	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen);
	}

out:
	while (!SLIST_EMPTY(&collectshead)) {
		cn1 = SLIST_FIRST(&collectshead);
		SLIST_REMOVE_HEAD(&collectshead, collect_entry);
		free(cn1->name);
		free(cn1->sd);
		free(cn1);
	}

	if (sreply->sr != NULL) {
		retlen = reply_raw2(so, reply, outlen, sreply->sr);
	} else {
		if (istcp) {
			char *tmpbuf;

			tmpbuf = malloc(outlen + 2);
			if (tmpbuf == NULL) {
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
	}

	return (retlen);
}


/*
 * REPLY_NOTIMPL - reply "Not Implemented" 
 *
 */


int
reply_notimpl(struct sreply  *sreply)
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
		if (tmpbuf == NULL) {
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
reply_nxdomain(struct sreply *sreply, DB *db)
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
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 /* 10 */
		char rdata;		
	} __attribute__((packed));

	struct soa {
		char *nsserver;
		char *responsible_person;
		u_int32_t serial;
		u_int32_t refresh;
		u_int32_t retry;
		u_int32_t expire;
		u_int32_t minttl;
	};
		

	struct answer *answer;

	int so = sreply->so;
	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct sockaddr *sa = sreply->sa;
	int salen = sreply->salen;
	struct domain *sd = sreply->sd1;
	struct domain *sd0 = NULL;
	struct domain_soa *sdsoa = NULL;
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

	/* 
	 * no SOA, use the old code
	 */

	if ((sd->flags & DOMAIN_HAVE_SOA) != DOMAIN_HAVE_SOA) {

		memcpy(reply, buf, len);
		memset((char *)&odh->query, 0, sizeof(u_int16_t));

		SET_DNS_REPLY(odh);
		if (sreply->sr != NULL) {
			SET_DNS_RECURSION_AVAIL(odh);
		}
		SET_DNS_RCODE_NAMEERR(odh);

		

		HTONS(odh->query);		
		if (sreply->sr != NULL) {
			retlen = reply_raw2(so, reply, len, sreply->sr);
		} else {
			if (istcp) {
				char *tmpbuf;
				u_int16_t *plen;

				tmpbuf = malloc(len + 2);
				if (tmpbuf == NULL) {
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
		}

		return (retlen);
	}

	if ((sdsoa = find_substruct(sd, INTERNAL_TYPE_SOA)) == NULL)
		return -1;

	/* copy question to reply */
	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
	/* blank query */
	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	outlen += (q->hdr->namelen + 4); 

	SET_DNS_REPLY(odh);
	if (sreply->sr != NULL)
		SET_DNS_RECURSION_AVAIL(odh);
	else
		SET_DNS_AUTHORITATIVE(odh);

	SET_DNS_RCODE_NAMEERR(odh);
	
	NTOHS(odh->query);

	odh->question = htons(1);
	odh->answer = 0;
	odh->nsrr = htons(1);
	odh->additional = 0;

	memcpy(&reply[outlen], sd->zone, sd->zonelen);
	outlen += sd->zonelen;

	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4 + sd->zonelen);

	answer->type = htons(DNS_TYPE_SOA);
	answer->class = q->hdr->qclass;
	if (sreply->sr != NULL)
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_SOA] - (time(NULL) - sd->created));
	else
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_SOA]);

	outlen += 10;   /* sizeof(struct answer)  up to rdata length */

	p = (char *)&answer->rdata;

	label = &sdsoa->soa.nsserver[0];
	labellen = sdsoa->soa.nsserver_len;

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

	label = sdsoa->soa.responsible_person;
	labellen = sdsoa->soa.rp_len;
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
	if ((outlen + sizeof(sdsoa->soa.serial)) > replysize) {
		/* XXX server error reply? */
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(sdsoa->soa.serial);
	outlen += sizeof(sdsoa->soa.serial);
	
	if ((outlen + sizeof(sdsoa->soa.refresh)) > replysize) {
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(sdsoa->soa.refresh);
	outlen += sizeof(sdsoa->soa.refresh);

	if ((outlen + sizeof(sdsoa->soa.retry)) > replysize) {
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(sdsoa->soa.retry);
	outlen += sizeof(sdsoa->soa.retry);

	if ((outlen + sizeof(sdsoa->soa.expire)) > replysize) {
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(sdsoa->soa.expire);
	outlen += sizeof(sdsoa->soa.expire);

	if ((outlen + sizeof(sdsoa->soa.minttl)) > replysize) {
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(sdsoa->soa.minttl);
	outlen += sizeof(sdsoa->soa.minttl);

	answer->rdlength = htons(&reply[outlen] - &answer->rdata);

	/* RRSIG reply_nxdomain */
	if (dnssec && q->dnssecok) {
		int tmplen = 0;
		int origlen = outlen;

		tmplen = additional_rrsig(sd->zone, sd->zonelen, INTERNAL_TYPE_SOA, sd, reply, replysize, outlen, 0);
	
		if (tmplen == 0) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->nsrr = htons(2);	

		origlen = outlen;
		if (sd->flags & DOMAIN_HAVE_NSEC) {
			sd0 = find_nsec(q->hdr->name, q->hdr->namelen, sd, db);
			if (sd0 == NULL)
				goto out;
			tmplen = additional_nsec(sd0->zone, sd0->zonelen, INTERNAL_TYPE_NSEC, sd0, reply, replysize, outlen);
			free (sd0);
		} else if (sd->flags & DOMAIN_HAVE_NSEC3PARAM) {
			sd0 = find_nsec3_cover_next_closer(q->hdr->name, q->hdr->namelen, sd, db);
			if (sd0 == NULL)
				goto out;
			tmplen = additional_nsec3(sd0->zone, sd0->zonelen, INTERNAL_TYPE_NSEC3, sd0, reply, replysize, outlen);
			free (sd0);
		}

		if (tmplen == 0) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->nsrr = htons(4);

		origlen = outlen;
		if (sd->flags & DOMAIN_HAVE_NSEC) {
			tmplen = additional_nsec(sd->zone, sd->zonelen, INTERNAL_TYPE_NSEC, sd, reply, replysize, outlen);
		} else if (sd->flags & DOMAIN_HAVE_NSEC3PARAM) {
			sd0 = find_nsec3_match_closest(q->hdr->name, q->hdr->namelen, sd, db);
			if (sd0 == NULL)
				goto out;
			tmplen = additional_nsec3(sd0->zone, sd0->zonelen, INTERNAL_TYPE_NSEC3, sd0, reply, replysize, outlen);
			free (sd0);
			
		}	

		if (tmplen == 0) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->nsrr = htons(6);

		origlen = outlen;
		if (sd->flags & DOMAIN_HAVE_NSEC3PARAM) {
			sd0 = find_nsec3_wildcard_closest(q->hdr->name, q->hdr->namelen, sd, db);
			if (sd0 == NULL)
				goto out;
			tmplen = additional_nsec3(sd0->zone, sd0->zonelen, INTERNAL_TYPE_NSEC3, sd0, reply, replysize, outlen);
			free (sd0);
			
		}	

		if (tmplen == 0) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->nsrr = htons(8);

	}

	if (q->edns0len) {
		/* tag on edns0 opt record */
		odh->additional = htons(1);
		outlen = additional_opt(q, reply, replysize, outlen);
	}

out:

	if (sreply->sr != NULL) {
		retlen = reply_raw2(so, reply, outlen, sreply->sr);
	} else {
	
		if (istcp) {
			char *tmpbuf;
			u_int16_t *plen;

			tmpbuf = malloc(outlen + 2);
			if (tmpbuf == NULL) {
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
	} /* sreply->sr.. */

	return (retlen);
}

/* 
 * REPLY_REFUSED() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_refused(struct sreply *sreply)
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
		if (tmpbuf == NULL) {
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
 * REPLY_FMTERROR() - replies a DNS question (*q) on socket (so)
 *
 */

int
reply_fmterror(struct sreply *sreply)
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
		if (tmpbuf == NULL) {
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
reply_noerror(struct sreply *sreply, DB *db)
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
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 /* 12 */
		char rdata;		
	} __attribute__((packed));

	struct soa {
		char *nsserver;
		char *responsible_person;
		u_int32_t serial;
		u_int32_t refresh;
		u_int32_t retry;
		u_int32_t expire;
		u_int32_t minttl;
	};
		

	struct answer *answer;

	int so = sreply->so;
	char *buf = sreply->buf;
	int len = sreply->len;
	struct question *q = sreply->q;
	struct sockaddr *sa = sreply->sa;
	int salen = sreply->salen;
	struct domain *sd = sreply->sd1;
	struct domain *sd0 = NULL;
	struct domain_soa *sdsoa = NULL;
	int istcp = sreply->istcp;
	int replysize = 512;
	int retlen = -1;

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

	if ((sd->flags & DOMAIN_HAVE_SOA) != DOMAIN_HAVE_SOA) {

		memcpy(reply, buf, len);
		memset((char *)&odh->query, 0, sizeof(u_int16_t));

		SET_DNS_REPLY(odh);
#if 0
		SET_DNS_RCODE_NAMEERR(odh);
#endif

		HTONS(odh->query);		

		if (istcp) {
			char *tmpbuf;
			u_int16_t *plen;

			tmpbuf = malloc(len + 2);
			if (tmpbuf == NULL) {
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

	if ((sdsoa = find_substruct(sd, INTERNAL_TYPE_SOA)) == NULL)
		return -1;

	/* copy question to reply */
	memcpy(reply, buf, sizeof(struct dns_header) + q->hdr->namelen + 4);
	/* blank query */
	memset((char *)&odh->query, 0, sizeof(u_int16_t));

	outlen += (q->hdr->namelen + 4); 

	SET_DNS_REPLY(odh);
	if (sreply->sr != NULL)
		SET_DNS_RECURSION_AVAIL(odh);
	else
		SET_DNS_AUTHORITATIVE(odh);

	NTOHS(odh->query);

	odh->question = htons(1);
	odh->answer = 0;
	odh->nsrr = htons(1);
	odh->additional = 0;

	memcpy(&reply[outlen], sd->zone, sd->zonelen);
	outlen += sd->zonelen;

	answer = (struct answer *)(&reply[0] + sizeof(struct dns_header) + 
		q->hdr->namelen + 4 + sd->zonelen);

	answer->type = htons(DNS_TYPE_SOA);
	answer->class = q->hdr->qclass;

	if (sreply->sr != NULL)
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_SOA] - (time(NULL) - sd->created));
	else
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_SOA]);

	outlen += 10;			/* up to rdata length */

	p = (char *)&answer->rdata;

	label = sdsoa->soa.nsserver;
	labellen = sdsoa->soa.nsserver_len;

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

	label = &sdsoa->soa.responsible_person[0];
	labellen = sdsoa->soa.rp_len;
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
	if ((outlen + sizeof(sdsoa->soa.serial)) > replysize) {
		/* XXX server error reply? */
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(sdsoa->soa.serial);
	outlen += sizeof(sdsoa->soa.serial);
	
	if ((outlen + sizeof(sdsoa->soa.refresh)) > replysize) {
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(sdsoa->soa.refresh);
	outlen += sizeof(sdsoa->soa.refresh);

	if ((outlen + sizeof(sdsoa->soa.retry)) > replysize) {
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(sdsoa->soa.retry);
	outlen += sizeof(sdsoa->soa.retry);

	if ((outlen + sizeof(sdsoa->soa.expire)) > replysize) {
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(sdsoa->soa.expire);
	outlen += sizeof(sdsoa->soa.expire);

	if ((outlen + sizeof(sdsoa->soa.minttl)) > replysize) {
		return (retlen);
	}
	soa_val = (u_int32_t *)&reply[outlen];
	*soa_val = htonl(sdsoa->soa.minttl);
	outlen += sizeof(sdsoa->soa.minttl);

	answer->rdlength = htons(&reply[outlen] - &answer->rdata);
	/* RRSIG reply_nxdomain */
	if (dnssec && q->dnssecok) {
		int tmplen = 0;
		int origlen = outlen;

		tmplen = additional_rrsig(sd->zone, sd->zonelen, INTERNAL_TYPE_SOA, sd, reply, replysize, outlen, 0);
	
		if (tmplen == 0) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->nsrr = htons(2);	

		origlen = outlen;
		if (sd->flags & DOMAIN_HAVE_NSEC) {
			sd0 = Lookup_zone(db, q->hdr->name, q->hdr->namelen, htons(DNS_TYPE_NSEC), 0);
			tmplen = additional_nsec(q->hdr->name, q->hdr->namelen, INTERNAL_TYPE_NSEC, sd0, reply, replysize, outlen);
			free(sd0);
		} else if (sd->flags & DOMAIN_HAVE_NSEC3PARAM) {
			sd0 = find_nsec3_match_qname(q->hdr->name, q->hdr->namelen, sd, db);
			if (sd0 == NULL)
				goto out;
			tmplen = additional_nsec3(sd0->zone, sd0->zonelen, INTERNAL_TYPE_NSEC3, sd0, reply, replysize, outlen);
			free (sd0);
		}

		if (tmplen == 0) {
			NTOHS(odh->query);
			SET_DNS_TRUNCATION(odh);
			HTONS(odh->query);
			goto out;
		}

		outlen = tmplen;

		if (outlen > origlen)
			odh->nsrr = htons(4);
	}

	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen);
	}
	
out:
	if (sreply->sr != NULL) {
		retlen = reply_raw2(so, reply, outlen, sreply->sr);
	} else {
		if (istcp) {
			char *tmpbuf;
			u_int16_t *plen;

			tmpbuf = malloc(outlen + 2);
			if (tmpbuf == NULL) {
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
	}

	return (retlen);
}

void
update_db(DB *db, struct domain *sd)
{
	int ret;
	int i = 0;
	DBT key, data;

	
	do {
		if (++i == 32) {
			dolog(LOG_ERR, "could not update zone for 32 tries, giving up entire database, quit");
			slave_shutdown();
			exit(1);
		}

		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));

		key.data = sd->zone;
		key.size = sd->zonelen;

		data.data = (char *)sd;
		data.size = sd->len;
		
		ret = db->put(db, NULL, &key, &data, 0);
	} while (ret != 0);

	return;	
}

/* 
 * Lookup_zone: wrapper for lookup_zone() et al.
 */

struct domain *
Lookup_zone(DB *db, char *name, u_int16_t namelen, u_int16_t type, int wildcard)
{
	struct domain *sd;
	struct question *fakequestion;
	char fakereplystring[DNS_MAXNAME + 1];
	int mytype;
	int lzerrno;

	fakequestion = build_fake_question(name, namelen, type);
	if (fakequestion == NULL) {
		dolog(LOG_INFO, "fakequestion(2) failed\n");
		return (NULL);
	}

#if 0
	sd = calloc(sizeof(struct domain), 1);
	if (sd == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		free_question(fakequestion);
		return (NULL);
	}
#endif

	sd = lookup_zone(db, fakequestion, &mytype, &lzerrno, (char *)&fakereplystring);

	if (sd == NULL) {
		free_question(fakequestion);
		return (NULL);
	}

	free_question(fakequestion);
	
	return (sd);
}

void 
collects_init(void)
{
	SLIST_INIT(&collectshead);
}

int
reply_raw2(int so, char *reply, int outlen, struct recurses *sr)
{
	char buf[2048];
#ifdef __linux__
	struct iphdr *ip;
#else
	struct ip *ip;
#endif
	struct udphdr *udp;
	int udplen = outlen + sizeof(struct udphdr);
	struct sockaddr_in *sin_src, *sin_dst;
	int retlen = -1;

	if (sr->af == AF_INET6) {
		retlen = reply_raw6(so, reply, outlen, sr);
		return (retlen);
	}

#ifdef __linux__
	ip = (struct iphdr *)&buf[0];
#else
	ip = (struct ip *)&buf[0];
#endif
	udp = (struct udphdr *)&buf[sizeof(struct ip)];
	memcpy(&buf[sizeof(struct ip) + sizeof(struct udphdr)], reply, outlen);

#ifdef __linux__
	ip->version = IPVERSION;
	ip->ihl = sizeof(struct iphdr) >> 2;

	ip->tos = 0;
	ip->tot_len = htons(udplen + sizeof(struct iphdr));
	ip->id = arc4random() & 0xffff;
	ip->frag_off = htons(IP_DF);
	ip->ttl = 64;
	ip->protocol = IPPROTO_UDP;
	ip->check = 0;
	sin_dst = (struct sockaddr_in *)(&sr->dest);
	ip->saddr = sin_dst->sin_addr.s_addr;
	sin_src = (struct sockaddr_in *)(&sr->source);
	ip->daddr = sin_src->sin_addr.s_addr;

	ip->check = 0;	
	ip->check = in_cksum((u_short*)ip, sizeof(struct iphdr), ip->check);
#else
	ip->ip_v = IPVERSION;
	ip->ip_hl = sizeof(struct ip) >> 2;

	ip->ip_tos = 0;

#ifdef __OpenBSD__
	ip->ip_len = htons(udplen + sizeof(struct ip));
#else
	ip->ip_len = udplen + sizeof(struct ip);
#endif

	ip->ip_id = arc4random();

#ifdef __OpenBSD__
	ip->ip_off = htons(IP_DF);
#else
	ip->ip_off = IP_DF;
#endif

	ip->ip_ttl = 64;
	ip->ip_p = IPPROTO_UDP;

	sin_src = (struct sockaddr_in *)(&sr->source);
	ip->ip_dst.s_addr = sin_src->sin_addr.s_addr;
	sin_dst = (struct sockaddr_in *)(&sr->dest);
	ip->ip_src.s_addr = sin_dst->sin_addr.s_addr;

	ip->ip_sum = 0;	
	ip->ip_sum = in_cksum((u_short*)ip, sizeof(struct ip), ip->ip_sum);
#endif

#ifdef __linux__
	
	udp->source = sin_dst->sin_port;
	udp->dest = sin_src->sin_port;
	udp->len = htons(udplen);
	udp->check = 0;

	udp->check = udp_cksum(ip, udp, udplen);

#else
	udp->uh_sport = sin_dst->sin_port;
	udp->uh_dport = sin_src->sin_port;
	udp->uh_ulen = htons(udplen);
	udp->uh_sum = 0;

	udp->uh_sum = udp_cksum(ip, udp, udplen);
#endif

#ifdef __linux__
	if ((retlen = sendto(so, buf, sizeof(struct iphdr) + udplen, 0, (struct sockaddr *)(&sr->dest), sizeof(struct sockaddr))) < 0) {
#else
	if ((retlen = sendto(so, buf, sizeof(struct ip) + udplen, 0, (struct sockaddr *)(&sr->dest), sizeof(struct sockaddr))) < 0) {
#endif
		dolog(LOG_ERR, "sendto: %s\n", strerror(errno));
	}

	return (retlen);
}

/*
 * REPLY_RAW6 - do an ipv6 raw reply 
 *
 */

int
reply_raw6(int so, char *reply, int outlen, struct recurses *sr)
{
	char buf[2048];
	char csum[2048];

	struct udphdr *udp;
	int udplen = outlen + sizeof(struct udphdr);
	struct sockaddr_in6 *sin_src, *sin_dst;
	struct sockaddr_in6 sin6;
	
	struct ip6_hdr_pseudo *pseudo;
	int retlen = -1;

	udp = (struct udphdr *)&buf[0];
	memcpy(&buf[sizeof(struct udphdr)], reply, outlen);

	sin_src = (struct sockaddr_in6 *)(&sr->source);
	sin_dst = (struct sockaddr_in6 *)(&sr->dest);

#ifdef __linux__
	udp->source = sin_dst->sin6_port;
	udp->dest = sin_src->sin6_port;
	udp->len = htons(udplen);
	udp->check = 0;
#else
	udp->uh_sport = sin_dst->sin6_port;
	udp->uh_dport = sin_src->sin6_port;
	udp->uh_ulen = htons(udplen);
	udp->uh_sum = 0;
#endif

	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	memcpy((char *)&sin6.sin6_addr, (char *)&sin_dst->sin6_addr, sizeof(struct in6_addr));

	if (bind(so, (struct sockaddr *)&sin6, sizeof(sin6)) < 0) {
		dolog(LOG_ERR, "bind6: %s\n", strerror(errno));
		return (retlen);
        }
	
	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	memcpy(&sin6.sin6_addr, (char *)&sin_src->sin6_addr, sizeof(struct in6_addr));
	sin6.sin6_port = sin_src->sin6_port;
#ifndef __linux__
	sin6.sin6_len = sizeof(struct sockaddr_in6);
#endif

	pseudo = (struct ip6_hdr_pseudo *)&csum[0];
	pseudo->ip6ph_nxt = IPPROTO_UDP;
	pseudo->ip6ph_len = htons(udplen);
	memcpy((char *)&pseudo->ip6ph_src, &sin_dst->sin6_addr, sizeof(struct in6_addr));
	memcpy((char *)&pseudo->ip6ph_dst, &sin_src->sin6_addr, sizeof(struct in6_addr));

	memcpy((char *)&csum[sizeof(struct ip6_hdr_pseudo)], udp, udplen);

#ifdef __linux__
        udp->check = in_cksum((u_short *)&csum[0], sizeof(struct ip6_hdr_pseudo) + udplen, 0);
#else
        udp->uh_sum = in_cksum((u_short *)&csum[0], sizeof(struct ip6_hdr_pseudo) + udplen, 0);
#endif


	if ((retlen = sendto(so, buf, udplen, 0, (struct sockaddr *)(&sr->dest), sizeof(struct sockaddr_in6))) < 0) {
		dolog(LOG_ERR, "sendto: %s\n", strerror(errno));
	}

	return (retlen);
}





/* from print_udp.c */
/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

static int 
#ifdef __linux__
udp_cksum(const struct iphdr *ip, const struct udphdr *up, int len)
#else
udp_cksum(const struct ip *ip, const struct udphdr *up, int len)
#endif
{
        union phu {
                struct phdr {
                        u_int32_t src;
                        u_int32_t dst;
                        u_char mbz;
                        u_char proto;
                        u_int16_t len;
                } ph;
                u_int16_t pa[6];
        } phu;
        const u_int16_t *sp;
        u_int32_t sum;

        /* pseudo-header.. */
        phu.ph.len = htons((u_int16_t)len);
        phu.ph.mbz = 0;
        phu.ph.proto = IPPROTO_UDP;
#ifdef __linux__
        memcpy(&phu.ph.src, &ip->saddr, sizeof(u_int32_t));
        memcpy(&phu.ph.dst, &ip->daddr, sizeof(u_int32_t));
#else
        memcpy(&phu.ph.src, &ip->ip_src.s_addr, sizeof(u_int32_t));
        memcpy(&phu.ph.dst, &ip->ip_dst.s_addr, sizeof(u_int32_t));
#endif

        sp = &phu.pa[0];
        sum = sp[0]+sp[1]+sp[2]+sp[3]+sp[4]+sp[5];

        return in_cksum((u_short *)up, len, sum);
}

u_short
in_cksum(const u_short *addr, register int len, int csum)
{
        int nleft = len;
        const u_short *w = addr;
        u_short answer;
        int sum = csum;

        /*
         *  Our algorithm is simple, using a 32 bit accumulator (sum),
         *  we add sequential 16 bit words to it, and at the end, fold
         *  back all the carry bits from the top 16 bits into the lower
         *  16 bits.
         */
        while (nleft > 1)  {
                sum += *w++;
                nleft -= 2;
        }
        if (nleft == 1)
                sum += htons(*(u_char *)w<<8);

        /*
         * add back carry outs from top 16 bits to low 16 bits
         */
        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
        sum += (sum >> 16);                     /* add carry */
        answer = ~sum;                          /* truncate to 16 bits */
        return (answer);
}

int
reply_any(struct sreply *sreply)
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

	SET_DNS_REPLY(odh);
	if (sreply->sr == NULL)
		SET_DNS_AUTHORITATIVE(odh);
	else
		SET_DNS_RECURSION_AVAIL(odh);
	
	NTOHS(odh->query);

	odh->question = htons(1);
	odh->answer = 0;
	odh->nsrr = 0;
	odh->additional = 0;

	outlen = create_anyreply(sreply, (char *)reply, replysize, outlen, 1);
	if (outlen == 0) {
		return (retlen);
	}

	if (q->edns0len) {
		/* tag on edns0 opt record */
		NTOHS(odh->additional);
		odh->additional++;
		HTONS(odh->additional);

		outlen = additional_opt(q, reply, replysize, outlen);
	}
			
	if (sreply->sr != NULL) {
		retlen = reply_raw2(so, reply, outlen, sreply->sr);
	} else {
		if (istcp) {
			char *tmpbuf;
			u_int16_t *plen;

			tmpbuf = malloc(outlen + 2);
			if (tmpbuf == NULL) {
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
	int naptr_count, rrsig_count;
	int internal_type;
	int tmplen, pos, mod;
	struct answer {
		u_int16_t type;		/* 0 */
                u_int16_t class;	/* 2 */
                u_int32_t ttl;		/* 4 */
                u_int16_t rdlength;      /* 8 */
		char rdata[0];		/* 10 */
	} __packed;
	struct answer *answer;
	struct domain *sd = sreply->sd1;
	struct domain_soa *sdsoa = NULL;
	struct domain_txt *sdtxt = NULL;
	struct domain_cname *sdcname = NULL;
	struct domain_a *sda = NULL;
	struct domain_aaaa *sdaaaa = NULL;
	struct domain_srv *sdsrv = NULL;
	struct domain_naptr *sdnaptr = NULL;
	struct domain_ptr *sdptr = NULL;
	struct domain_ns *sdns = NULL;
	struct domain_mx *sdmx = NULL;
	struct domain_spf *sdspf = NULL;
	struct domain_sshfp *sdsshfp = NULL;
	struct domain_nsec *sdnsec = NULL;
	struct domain_rrsig *sdrrsig = NULL;
	struct question *q = sreply->q;
	struct dns_header *odh = (struct dns_header *)reply;
	int labellen;
	char *label, *plabel;
	u_int32_t *soa_val;
	u_int16_t namelen;
	u_int16_t *mx_priority, *srv_priority, *srv_port, *srv_weight;
	u_int16_t *naptr_order, *naptr_preference;
	u_int8_t *sshfp_alg, *sshfp_fptype;
	char *name, *p;
	int i;

	if ((sd->flags & DOMAIN_HAVE_SOA) && soa) {
		if ((sdsoa = (struct domain_soa *)find_substruct(sd, INTERNAL_TYPE_SOA)) == NULL)
			return 0;

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

		answer->type = htons(DNS_TYPE_SOA);
		answer->class = htons(DNS_CLASS_IN);
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_SOA]);

		offset += 10;		/* up to rdata length */

		label = sdsoa->soa.nsserver;
		labellen = sdsoa->soa.nsserver_len;

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

		label = sdsoa->soa.responsible_person;
		labellen = sdsoa->soa.rp_len;
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

		if ((offset + sizeof(sdsoa->soa.serial)) > rlen) {
			goto truncate;
        	}

		soa_val = (u_int32_t *)&reply[offset];
		*soa_val = htonl(sdsoa->soa.serial);
		offset += sizeof(sdsoa->soa.serial);      
        
        	if ((offset + sizeof(sdsoa->soa.refresh)) > rlen) {
			goto truncate;
        	}
	
		soa_val = (u_int32_t *)&reply[offset];
		*soa_val = htonl(sdsoa->soa.refresh);
		offset += sizeof(sdsoa->soa.refresh);    

		if ((offset + sizeof(sdsoa->soa.retry)) > rlen) {
			goto truncate;
        	}

		soa_val = (u_int32_t *)&reply[offset];
		*soa_val = htonl(sdsoa->soa.retry);
		offset += sizeof(sdsoa->soa.retry);       

		if ((offset + sizeof(sdsoa->soa.expire)) > rlen) {
			goto truncate;
		}

		soa_val = (u_int32_t *)&reply[offset];
		*soa_val = htonl(sdsoa->soa.expire);
		offset += sizeof(sdsoa->soa.expire);

		if ((offset + sizeof(sdsoa->soa.minttl)) > rlen) {
			goto truncate;
        	}

		soa_val = (u_int32_t *)&reply[offset];
		*soa_val = htonl(sdsoa->soa.minttl);
		offset += sizeof(sdsoa->soa.minttl);

		answer->rdlength = htons(&reply[offset] - answer->rdata);

	}
	if (sd->flags & DOMAIN_HAVE_RRSIG) {
		if ((sdrrsig = (struct domain_rrsig *)find_substruct(sd, INTERNAL_TYPE_RRSIG)) == NULL)
			return 0;

		rrsig_count = 0;
		for (internal_type = 0; internal_type < INTERNAL_TYPE_MAX; internal_type++) {
			int checktype;

			checktype = lookup_type(internal_type);
			if (checktype == -1)
				continue;

			if (sd->flags & checktype) {
				rrsig_count++;
				tmplen = additional_rrsig(q->hdr->name, q->hdr->namelen,
				internal_type, sd, reply, rlen, offset, 0);
	
				if (tmplen == 0)
					goto truncate;

				offset = tmplen;
			}
		} 

		NTOHS(odh->answer);
		odh->answer += rrsig_count;
		HTONS(odh->answer);

	}
	if (sd->flags & DOMAIN_HAVE_NSEC) {
		if ((sdnsec = (struct domain_nsec *)find_substruct(sd, INTERNAL_TYPE_NSEC)) == NULL)
			return 0;

		do {
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
			answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_NSEC]);

			answer->rdlength = htons(namelen);

			offset += 10;		/* struct answer */

			if (offset + sdnsec->nsec.ndn_len > rlen)
				goto truncate;

			memcpy((char *)&answer->rdata, (char *)sdnsec->nsec.next_domain_name, sdnsec->nsec.ndn_len);

			offset += sdnsec->nsec.ndn_len;

			if (offset + sdnsec->nsec.bitmap_len > rlen)
				goto truncate;
				
			memcpy((char *)&reply[offset], sdnsec->nsec.bitmap, sdnsec->nsec.bitmap_len);

			offset += sdnsec->nsec.bitmap_len;
			
			answer->rdlength = htons(&reply[offset] - answer->rdata);

		} while (0);

		NTOHS(odh->answer);
		odh->answer += 1;
		HTONS(odh->answer);

	}
	if (sd->flags & DOMAIN_HAVE_NS) {
		if ((sdns = (struct domain_ns *)find_substruct(sd, INTERNAL_TYPE_NS)) == NULL)
			return 0;
		ns_count = 0;
		mod = sdns->ns_count;
		pos = sdns->ns_ptr;

		do {
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
			answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_NS]);

			answer->rdlength = htons(namelen);

			offset += 10;		/* struct answer */

			name = sdns->ns[pos % mod].nsserver;
			namelen = sdns->ns[pos % mod].nslen;

			if (offset + namelen > rlen)
				goto truncate;

			memcpy((char *)&answer->rdata, (char *)name, namelen);

			offset += namelen;
			
			/* compress the label if possible */
			if ((tmplen = compress_label((u_char*)reply, offset, namelen)) > 0) {
				offset = tmplen;
			}

			answer->rdlength = htons(&reply[offset] - answer->rdata);


			/* can we afford to write another header? if no truncate */
			if (sdns->ns_count > 1 && (offset + sdns->ns[pos % mod].nslen) > rlen) {
                        goto truncate;
			}

			pos++;

		} while (++ns_count < RECORD_COUNT && --sdns->ns_count);

		NTOHS(odh->answer);
		odh->answer += ns_count;
		HTONS(odh->answer);

	}
	if (sd->flags & DOMAIN_HAVE_PTR) {
		if ((sdptr = (struct domain_ptr*)find_substruct(sd, INTERNAL_TYPE_PTR)) == NULL)
			return 0;

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
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_PTR]);

		offset += 10;		/* up to rdata length */

		label = sdptr->ptr;
		labellen = sdptr->ptrlen;

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
	if (sd->flags & DOMAIN_HAVE_MX) {
		if ((sdmx = (struct domain_mx*)find_substruct(sd, INTERNAL_TYPE_MX)) == NULL)
			return 0;

		mx_count = 0;
		do {
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
			answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_MX]);
			answer->rdlength = htons(sizeof(u_int16_t) + sdmx->mx[mx_count].exchangelen);

			offset += 10;		/* up to rdata length */
			
			mx_priority = (u_int16_t *)&reply[offset];
			*mx_priority = htons(sdmx->mx[mx_count].preference);

			offset += 2;

			if (offset + sdmx->mx[mx_count].exchangelen > rlen)
				goto truncate;

			memcpy((char *)&reply[offset], (char *)sdmx->mx[mx_count].exchange, sdmx->mx[mx_count].exchangelen);

			offset += sdmx->mx[mx_count].exchangelen;

			if ((tmplen = compress_label((u_char*)reply, offset, sdmx->mx[mx_count].exchangelen)) > 0) {
				offset = tmplen;
			} 

			/* can we afford to write another header? if no truncate */
			if (sdmx->mx_count > 1 && (offset + 12 + 2 + sdmx->mx[mx_count].exchangelen) > rlen) {
				goto truncate;
			}

			answer->rdlength = htons(&reply[offset] - answer->rdata);
		} while (++mx_count < RECORD_COUNT && --sdmx->mx_count);

		NTOHS(odh->answer);
		odh->answer += mx_count;
		HTONS(odh->answer);

	}
	if (sd->flags & DOMAIN_HAVE_SPF) {
		if ((sdspf = (struct domain_spf*)find_substruct(sd, INTERNAL_TYPE_SPF)) == NULL)
			return 0;

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

		answer->type = htons(DNS_TYPE_SPF);
		answer->class = htons(DNS_CLASS_IN);
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_SPF]);

		offset += 10;		/* up to rdata length */



		if (offset + sdspf->spflen + 1 > rlen)
			goto truncate;

		p = (char *)&answer->rdata;
		*p = sdspf->spflen;
		memcpy((p + 1), sdspf->spf, sdspf->spflen);
		offset += (sdspf->spflen + 1);

		answer->rdlength = htons(sdspf->spflen + 1);

	}
	if (sd->flags & DOMAIN_HAVE_TXT) {
		if ((sdtxt = (struct domain_txt *)find_substruct(sd, INTERNAL_TYPE_TXT)) == NULL)
			return 0;

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
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_TXT]);

		offset += 10;		/* up to rdata length */



		if (offset + sdtxt->txtlen + 1 > rlen)
			goto truncate;

		p = (char *)&answer->rdata;
		*p = sdtxt->txtlen;
		memcpy((p + 1), sdtxt->txt, sdtxt->txtlen);
		offset += (sdtxt->txtlen + 1);

		answer->rdlength = htons(sdtxt->txtlen + 1);

	}
	if (sd->flags & DOMAIN_HAVE_SSHFP) {
		if ((sdsshfp = (struct domain_sshfp *)find_substruct(sd, INTERNAL_TYPE_SSHFP)) == NULL)
			return 0;

		sshfp_count = 0;
		do {
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
			answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_SSHFP]);
			answer->rdlength = htons((2 * sizeof(u_int8_t)) + sdsshfp->sshfp[sshfp_count].fplen);

			offset += 10;		/* up to rdata length */
			
			sshfp_alg = (u_int8_t *)&reply[offset];
			*sshfp_alg = sdsshfp->sshfp[sshfp_count].algorithm;

			offset++;

			sshfp_fptype = (u_int8_t *)&reply[offset];
			*sshfp_fptype = sdsshfp->sshfp[sshfp_count].fptype;

			offset++;

			if (offset + sdsshfp->sshfp[sshfp_count].fplen > rlen)
				goto truncate;

			memcpy((char *)&reply[offset], (char *)sdsshfp->sshfp[sshfp_count].fingerprint, sdsshfp->sshfp[sshfp_count].fplen);

			offset += sdsshfp->sshfp[sshfp_count].fplen;

			/* can we afford to write another header? if no truncate */
			if (sdsshfp->sshfp_count > 1 && (offset + 12 + 2 + sdsshfp->sshfp[sshfp_count].fplen) > rlen) {
				goto truncate;
			}

			answer->rdlength = htons(&reply[offset] - answer->rdata);
		} while (++sshfp_count < RECORD_COUNT && --sdsshfp->sshfp_count);

		NTOHS(odh->answer);
		odh->answer += sshfp_count;
		HTONS(odh->answer);

	}
	if (sd->flags & DOMAIN_HAVE_NAPTR) {
		if ((sdnaptr = (struct domain_naptr *)find_substruct(sd, INTERNAL_TYPE_NAPTR)) == NULL)
			return 0;

		naptr_count = 0;
		do {
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
			answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_NAPTR]);
			answer->rdlength = htons((2 * sizeof(u_int16_t)) + sdnaptr->naptr[naptr_count].flagslen + 1 + sdnaptr->naptr[naptr_count].serviceslen + 1 + sdnaptr->naptr[naptr_count].regexplen + 1 + sdnaptr->naptr[naptr_count].replacementlen);

			offset += 10;		/* up to rdata length */
			
			naptr_order = (u_int16_t *)&reply[offset];
			*naptr_order = htons(sdnaptr->naptr[naptr_count].order);

			offset += 2;

			naptr_preference = (u_int16_t *)&reply[offset];
			*naptr_preference = htons(sdnaptr->naptr[naptr_count].preference);

			offset += 2;

			/* flags */
			if (offset + sdnaptr->naptr[naptr_count].flagslen + 1> rlen)
				goto truncate;

			reply[offset] = sdnaptr->naptr[naptr_count].flagslen;
			offset++;

			memcpy((char *)&reply[offset], (char *)sdnaptr->naptr[naptr_count].flags, sdnaptr->naptr[naptr_count].flagslen);

			offset += sdnaptr->naptr[naptr_count].flagslen;
			/* services */
			if (offset + sdnaptr->naptr[naptr_count].serviceslen + 1> rlen)
				goto truncate;

			reply[offset] = sdnaptr->naptr[naptr_count].serviceslen;
			offset++;

			memcpy((char *)&reply[offset], (char *)sdnaptr->naptr[naptr_count].services, sdnaptr->naptr[naptr_count].serviceslen);

			offset += sdnaptr->naptr[naptr_count].serviceslen;
			/* regexp */
			if (offset + sdnaptr->naptr[naptr_count].regexplen + 1> rlen)
				goto truncate;

			reply[offset] = sdnaptr->naptr[naptr_count].regexplen;
			offset++;

			memcpy((char *)&reply[offset], (char *)sdnaptr->naptr[naptr_count].regexp, sdnaptr->naptr[naptr_count].regexplen);

			offset += sdnaptr->naptr[naptr_count].regexplen;
			/* replacement */
			if (offset + sdnaptr->naptr[naptr_count].replacementlen > rlen)
				goto truncate;

			memcpy((char *)&reply[offset], (char *)sdnaptr->naptr[naptr_count].replacement, sdnaptr->naptr[naptr_count].replacementlen);

			offset += sdnaptr->naptr[naptr_count].replacementlen;

			if ((tmplen = compress_label((u_char*)reply, offset, sdnaptr->naptr[naptr_count].replacementlen)) > 0) {
				offset = tmplen;
			} 

			/* can we afford to write another header? if no truncate */
			if (sdnaptr->naptr_count > naptr_count && (offset + 12 + 4 + sdnaptr->naptr[naptr_count + 1].flagslen + 1) > rlen) {
				goto truncate;
			}

			answer->rdlength = htons(&reply[offset] - answer->rdata);
		} while (++naptr_count < RECORD_COUNT && --sdnaptr->naptr_count);

		NTOHS(odh->answer);
		odh->answer += naptr_count;
		HTONS(odh->answer);

	}
	if (sd->flags & DOMAIN_HAVE_SRV) {
		if ((sdsrv = (struct domain_srv *)find_substruct(sd, INTERNAL_TYPE_SRV)) == NULL)
			return 0;

		srv_count = 0;
		do {
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
			answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_SRV]);
			answer->rdlength = htons((3 * sizeof(u_int16_t)) + sdsrv->srv[srv_count].targetlen);

			offset += 10;		/* up to rdata length */
			
			srv_priority = (u_int16_t *)&reply[offset];
			*srv_priority = htons(sdsrv->srv[srv_count].priority);

			offset += 2;

			srv_weight = (u_int16_t *)&reply[offset];
			*srv_weight = htons(sdsrv->srv[srv_count].weight);

			offset += 2;

			srv_port = (u_int16_t *)&reply[offset];
			*srv_port = htons(sdsrv->srv[srv_count].port);

			offset += 2;

			if (offset + sdsrv->srv[srv_count].targetlen > rlen)
				goto truncate;

			memcpy((char *)&reply[offset], (char *)sdsrv->srv[srv_count].target, sdsrv->srv[srv_count].targetlen);

			offset += sdsrv->srv[srv_count].targetlen;

			if ((tmplen = compress_label((u_char*)reply, offset, sdsrv->srv[srv_count].targetlen)) > 0) {
				offset = tmplen;
			} 

			/* can we afford to write another header? if no truncate */
			if (sdsrv->srv_count > 1 && (offset + 12 + 6 + sdsrv->srv[srv_count].targetlen) > rlen) {
				goto truncate;
			}

			answer->rdlength = htons(&reply[offset] - answer->rdata);
		} while (++srv_count < RECORD_COUNT && --sdsrv->srv_count);

		NTOHS(odh->answer);
		odh->answer += srv_count;
		HTONS(odh->answer);

	}

	if (sd->flags & DOMAIN_HAVE_CNAME) {
		if ((sdcname = (struct domain_cname *)find_substruct(sd, INTERNAL_TYPE_CNAME)) == NULL)
			return 0;

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
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_CNAME]);

		offset += 10;		/* up to rdata length */

		label = sdcname->cname;
		labellen = sdcname->cnamelen;

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
	if (sd->flags & DOMAIN_HAVE_A) {
		if ((sda = (struct domain_a *)find_substruct(sd, INTERNAL_TYPE_A)) == NULL)
			return 0;

		a_count = 0;
		pos = sda->a_ptr;
		mod = sda->a_count;

		do {
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
			answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_A]);
			answer->rdlength = htons(sizeof(in_addr_t));

			memcpy((char *)&answer->rdata, (char *)&sda->a[pos++ % mod], 
				sizeof(in_addr_t));			

			a_count++;
			offset += 14;

			/* can we afford to write another header? if no truncate */
			if (sda->a_count > 1 && offset + 16 > rlen) {
				goto truncate;
			}

			answer = (struct answer *)&reply[offset];

		} while (a_count < RECORD_COUNT && --sda->a_count);

		NTOHS(odh->answer);
		odh->answer += a_count;
		HTONS(odh->answer);
	}
	if (sd->flags & DOMAIN_HAVE_AAAA) {
		if ((sdaaaa = (struct domain_aaaa *)find_substruct(sd, INTERNAL_TYPE_AAAA)) == NULL)
			return 0;

		NTOHS(odh->answer);
		odh->answer += sdaaaa->aaaa_count;
		HTONS(odh->answer);
		
		pos = sdaaaa->aaaa_ptr;
		mod = sdaaaa->aaaa_count;

		aaaa_count = 0;

		do {
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
			answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_AAAA]);
			answer->rdlength = htons(sizeof(struct in6_addr));
			offset += 10;

 			memcpy((char *)&reply[offset] ,(char *)&sdaaaa->aaaa[pos++ % mod], sizeof(struct in6_addr));
			offset += 16;

			/* can we afford to write another header? if no truncate */
			if (sdaaaa->aaaa_count > 1 && offset + 28 > rlen) {
				goto truncate;
			}

			aaaa_count++;
		} while (aaaa_count < RECORD_COUNT && --sdaaaa->aaaa_count);

	}

	return (offset);

truncate:
	NTOHS(odh->query);
	SET_DNS_TRUNCATION(odh);
	HTONS(odh->query);
	
	return (offset);
}

/* FIND_NSEC  */
/* finds the right nsec domainname in a zone */
struct domain *
find_nsec(char *name, int namelen, struct domain *sd, DB *db)
{
	DBT key, data;
	char *table, *tmp;
	char *nsecname;
	struct domainnames {
		char name[DNS_MAXNAME + 1];
		char next[DNS_MAXNAME + 1];
	} *dn;

	struct domain *sd0;
	struct domain_nsec *sdnsec;
	char *humanname;
	char *backname;
	char tmpname[DNS_MAXNAME];
	int tmplen;
	int backnamelen;
	int rs, ret;
	int i, names = 100;
	int j;

	humanname = convert_name(name, namelen);

	if ((sdnsec = find_substruct(sd, INTERNAL_TYPE_NSEC)) == NULL) {
		free (humanname);
		return (NULL);
	}

	
	table = calloc(names, sizeof(struct domainnames));	
	if (table == NULL) {
		free (humanname);
		return (NULL);
	}

	dn = (struct domainnames *)table;
	strlcpy(dn->name, sd->zonename, DNS_MAXNAME + 1);
	nsecname = convert_name(sdnsec->nsec.next_domain_name, sdnsec->nsec.ndn_len);
	strlcpy(dn->next, nsecname, DNS_MAXNAME + 1);
	
	rs = get_record_size(db, sdnsec->nsec.next_domain_name, sdnsec->nsec.ndn_len);
	if (rs < 0) {
		free (nsecname);
		free (humanname);
		free (table);
		return (NULL);
	}

	if ((sd0 = calloc(1, rs)) == NULL) {
		free (nsecname);
		free (humanname);
		free (table);
		return (NULL);
	}

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));
	
	key.data = sdnsec->nsec.next_domain_name;
	key.size = sdnsec->nsec.ndn_len;

	data.data = NULL;
	data.size = rs;

	ret = db->get(db, NULL, &key, &data, 0);	
	if (ret != 0) {
		free (nsecname);
		free (humanname);
		free (table);
		free (sd0);
		return (NULL);
	}

	memcpy(sd0, data.data, data.size);

	if ((sdnsec = find_substruct(sd0, INTERNAL_TYPE_NSEC)) == NULL) {
		free (nsecname);
		free (humanname);
		free (table);
		free (sd0);
		return (NULL);
	}

	i = 1;
	while (strcasecmp(nsecname, sd->zonename) != 0) {
		/* grow our table */
		if (i == names - 1) {
			names += 100;
	
			tmp = realloc(table, names * sizeof(struct domainnames));
			if (tmp == NULL) {
				free (nsecname);
				free (humanname);
				free (table);
				free (sd0);
				return (NULL);
			}
			table = tmp;
		}

		dn = ((struct domainnames *)table) + i;
		
		free (nsecname);
		strlcpy(dn->name, sd0->zonename, DNS_MAXNAME + 1);
		nsecname = convert_name(sdnsec->nsec.next_domain_name, sdnsec->nsec.ndn_len);
		strlcpy(dn->next, nsecname, DNS_MAXNAME + 1);
		
		rs = get_record_size(db, sdnsec->nsec.next_domain_name, sdnsec->nsec.ndn_len);
		if (rs < 0) {
			free (table);
			return (NULL);
		}

		memcpy(tmpname, sdnsec->nsec.next_domain_name, sdnsec->nsec.ndn_len);
		tmplen = sdnsec->nsec.ndn_len;

		free (sd0);
		if ((sd0 = calloc(1, rs)) == NULL) {
			free (humanname);
			free (table);
			return (NULL);
		}

		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));
		
		key.data = tmpname;
		key.size = tmplen;

		data.data = NULL;
		data.size = rs;

		ret = db->get(db, NULL, &key, &data, 0);	
		if (ret != 0) {
			free (humanname);
			free (table);
			free (sd0);
			return (NULL);
		}

		memcpy(sd0, data.data, data.size);

		if ((sdnsec = find_substruct(sd0, INTERNAL_TYPE_NSEC)) == NULL) {
			free (humanname);
			free (table);
			free (sd0);
			return (NULL);
		}

		i++;
	}

	free (nsecname);
	dn = ((struct domainnames *)table) + i;
	strlcpy(dn->next, ".", DNS_MAXNAME + 1);
	strlcpy(dn->name, humanname, DNS_MAXNAME + 1);

	i++;

	/* now we sort the shebang */

	qsort(table, i, sizeof(struct domainnames), nsec_comp);
	
	for (j = 0; j < i; j++) {
		dn = ((struct domainnames *)table) + j;
		
#if DEBUG
		if (debug)
			printf("%s\n", dn->name);
#endif

		if (strcmp(dn->next, ".") == 0)
			break;
	}

	dn = ((struct domainnames *)table) + (j - 1);	
	
	/* found it, get it via db after converting it */	
	
	/* free what we don't need */
	free (humanname);
	free (sd0);
	
	backname = dns_label(dn->name, &backnamelen);
	free (table);
	
	rs = get_record_size(db, backname, backnamelen);
	if (rs < 0) {
		free (backname);
		return (NULL);
	}

	if ((sd0 = calloc(1, rs)) == NULL) {
		free (backname);
		return (NULL);
	}

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));
	
	key.data = backname;
	key.size = backnamelen;

	data.data = NULL;
	data.size = rs;

	ret = db->get(db, NULL, &key, &data, 0);	
	if (ret != 0) {
		free (backname);
		free (sd0);
		return (NULL);
	}
	

	memcpy(sd0, data.data, data.size);
	free (backname);

	return (sd0);
}

char *
convert_name(char *name, int namelen)
{
	char *ret;
	char *p, *p0;
	int plen;
	int i;

	ret = calloc(namelen + 1, 1);
	if (ret == NULL) {
		return NULL;
	}

	memcpy(ret, name + 1, namelen - 1);
	
	p0 = ret;
	p = name;
	plen = namelen;

        while (*p != 0) {
		if (*p > 63)
			break;
		for (i = 0; i < *p; i++) {
			*p0++ = p[i + 1];
		}
		*p0++ = '.';
        	plen -= (*p + 1);
                p = (p + (*p + 1));
	}

	return (ret);
}

/* canonical sort compare */

int
nsec_comp(const void *a, const void *b)
{
	struct domainnames {
		char name[DNS_MAXNAME + 1];
		char next[DNS_MAXNAME + 1];
	};
	struct domainnames *dn0, *dn1;
	int dots0, dots1;

	dn0 = (struct domainnames *)a;
	dn1 = (struct domainnames *)b;

	/* count the dots we need this for canonical compare */

	dots0 = count_dots(dn0->name);
	dots1 = count_dots(dn1->name);

	if (dots0 > dots1)
		return 1;
	else if (dots1 > dots0)
		return -1;
	
			
	/* we have a tie, strcmp them */

	return (strcmp(dn0->name, dn1->name));
}

int
nsec3_comp(const void *a, const void *b) {
	struct domainnames {
		char name[DNS_MAXNAME + 1];
		char next[DNS_MAXNAME + 1];
	};
	struct domainnames *dn0, *dn1;

	dn0 = (struct domainnames *)a;
	dn1 = (struct domainnames *)b;

	return (strcmp(dn0->name, dn1->name));
}

int
count_dots(char *name)
{
	int i;
	int ret = 0;


	for (i = 0; i < strlen(name); i++) {
		if (name[i] == '.')
			ret++;
	}

	return(ret);
}

/* 
 * FIND_NEXT_CLOSER - find the next closest record
 */

struct domain *
find_next_closer(DB *db, char *name, int namelen)
{
	struct domain *sd = NULL;

	int plen;
	int ret = 0;
	int rs;
	
	DBT key, data;

	char *p;

	p = name;
	plen = namelen;

	do {
		rs = get_record_size(db, p, plen);
		if (rs < 0) {
			return NULL;
		}

		sd = calloc(rs, 1);
		if (sd == NULL) 
			return NULL;

		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));

		key.data = (char *)p;
		key.size = plen;

		data.data = NULL;
		data.size = rs;

		ret = db->get(db, NULL, &key, &data, 0);
		if (ret != 0) {
			plen -= (*p + 1);
			p = (p + (*p + 1));
			free (sd);
			continue;
		}
		
		if (data.size != rs) {
			dolog(LOG_INFO, "btree db is damaged, drop\n");
			free (sd);
			return (NULL);
		}

		memcpy((char *)sd, (char *)data.data, data.size);
		if (sd->flags & DOMAIN_HAVE_NSEC3) {
			plen -= (*p + 1);
			p = (p + (*p + 1));
			free (sd);
			continue;
		}

		return (sd);
	} while (*p);

	if (sd)
		free (sd);

	return NULL;
}

char *
hash_name(char *name, int len, struct nsec3param *n3p)
{
	SHA_CTX ctx;
	u_char md[20];
	int i;

	if (n3p->algorithm != 1) {
		dolog(LOG_INFO, "wrong algorithm: %d, expected 1\n", n3p->algorithm);
		return NULL;
	}

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, name, len);
	SHA1_Update(&ctx, n3p->salt, n3p->saltlen);
	SHA1_Final(md, &ctx);

	for (i = 0; i < n3p->iterations; i++) {
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, md, sizeof(md));
		SHA1_Update(&ctx, n3p->salt, n3p->saltlen);
		SHA1_Final(md, &ctx);
	}

	return (base32hex_encode(md, sizeof(md)));	
}

char *
base32hex_encode(u_char *input, int len)
{
	u_char *ui;
	u_int64_t tb = 0;
	int i;
	u_char *p;
	static char ret[32];
	
	u_char *character = "0123456789abcdefghijklmnopqrstuv=";

	p = &ret[0];
	ui = input;

	for (i = 0; i < len; i += 5) {
		tb = (*ui & 0xff);	
		tb <<= 8;

		if (i < len) 
			ui++;
		else 
			*ui = 0;
	
		tb |= (*ui & 0xff);
		tb <<= 8;

		if (i < len) 
			ui++;
		else 
			*ui = 0;

		tb |= (*ui & 0xff);

		tb <<= 8;

		if (i < len) 
			ui++;
		else 
			*ui = 0;

		tb |= (*ui & 0xff);

		tb <<= 8;

		if (i < len) 
			ui++;
		else 
			*ui = 0;

		tb |= (*ui & 0xff);

		if (i < len) 
			ui++;
		else 
			*ui = 0;

		*(p + 7) = character[(tb & 0x1f)];
		tb >>= 5;
		*(p + 6) = character[(tb & 0x1f)];
		tb >>= 5;
		*(p + 5) = character[(tb & 0x1f)];
		tb >>= 5;
		*(p + 4) = character[(tb & 0x1f)];
		tb >>= 5;
		*(p + 3) = character[(tb & 0x1f)];
		tb >>= 5;
		*(p + 2) = character[(tb & 0x1f)];
		tb >>= 5;
		*(p + 1) = character[(tb & 0x1f)];
		tb >>= 5;
		*(p + 0) = character[(tb & 0x1f)];

		p += 8;
	}

	return (ret);
}

/* COUNT_NSEC3_IN_ZONE - counts how many nsec3 records there is */

int
count_nsec3_in_zone(DB *db, struct domain *sd, struct question *question)
{
	DBT key, data;
	DBC *cursor;
	struct domain *sd0;
	int rs, count = 0;

	if (db->cursor(db, NULL, &cursor, 0) != 0) {
		dolog(LOG_INFO, "cn3iz db->cursor: %s\n", strerror(errno));
		return -1;
	}	

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	if (cursor->c_get(cursor, &key, &data, DB_FIRST) != 0) {
		dolog(LOG_INFO, "cn3iz cursor->c_get: %s\n", strerror(errno));
		return -1;
	}

	do {
		rs = data.size;
		if ((sd0 = calloc(1, rs)) == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			return(-1);
		}

		memcpy((char *)sd0, (char *)data.data, data.size);

		if (checklabel(db, sd0, sd, question) == 1) {
			if (sd0->flags & DOMAIN_HAVE_NSEC3)
				count++;	
		}

		free (sd0);

		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));

	}  while (cursor->c_get(cursor, &key, &data, DB_NEXT) == 0);

	cursor->c_close(cursor);

	return (count);
}

/*
 * FIND_NSEC3_MATCH_CLOSEST - find the closest matching encloser 
 *
 */

struct domain *
find_nsec3_match_closest(char *name, int namelen, struct domain *sd, DB *db)
{
	struct domainnames {
		char name[DNS_MAXNAME + 1];
		char next[DNS_MAXNAME + 1];
	} *dn;

	DBC *cursor;
	DBT key, data;

	char *hashname;
	char *backname;
	char *table, *tmp;
	int backnamelen;
	int rs, ret;
	int i, j;
	int count, hashnamelen;
	struct domain *sd0, *sd1;
	struct domain_nsec3param *n3p;
	struct question *question;

	if ((n3p = find_substruct(sd, INTERNAL_TYPE_NSEC3PARAM)) == NULL) {
		return NULL;
	}

	/* first off find  the next closer record */
	sd0 = find_next_closer(db, name, namelen);
	if (sd0 == NULL) {
		return NULL;
	}

#if DEBUG
	dolog(LOG_INFO, "next closer = %s\n", sd0->zonename);
#endif

	hashname = hash_name(sd0->zone, sd0->zonelen, &n3p->nsec3param);
	if (hashname == NULL) {
		dolog(LOG_INFO, "unable to get hashname\n");
		free (sd0);
		return NULL;
	}

#if DEBUG
	dolog(LOG_INFO, "hashname  = %s\n", hashname);
#endif
	
	/* now go through our zone and find NSEC3 domains */
	/* first pass, count the NSEC3 list */	
	
	/* we need question for checklabel() */
	question = build_fake_question(sd->zone, sd->zonelen, 0);
	if (question == NULL) {
		dolog(LOG_INFO, "build_fake_question failed\n");
		free (sd0);
		return NULL;
	}

	count = count_nsec3_in_zone(db, sd, question);

	/* realloc names structure to fit the NSEC3 names */
	
	tmp = calloc(count, sizeof(struct domainnames));
	if (tmp == NULL) {
		dolog(LOG_INFO, "realloc: %s\n", strerror(errno));
		free_question(question);
		free (sd0);
		return NULL;	
	}
		
	table = tmp;
	dn = (struct domainnames *)tmp;

	/* second pass, fill NSEC3 list */

	if (db->cursor(db, NULL, &cursor, 0) != 0) {
		dolog(LOG_INFO, "find_nsec3 db->cursor: %s\n", strerror(errno));
		free_question(question);
		free (sd0);
		return NULL;
	}	

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	if (cursor->c_get(cursor, &key, &data, DB_FIRST) != 0) {
		dolog(LOG_INFO, "find_nsec3 cursor->c_get: %s\n", strerror(errno));
		free_question(question);
		free (sd0);
		return NULL;
	}

	i = 1;

	do {
		rs = data.size;
		if ((sd1 = calloc(1, rs)) == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			free_question(question);
			free (sd0);
			return NULL;
		}

		memcpy((char *)sd1, (char *)data.data, data.size);

		if (checklabel(db, sd1, sd, question) == 1) {
			if (sd1->flags & DOMAIN_HAVE_NSEC3) {
				strlcpy(dn->name, sd1->zonename, DNS_MAXNAME + 1);
				strlcpy(dn->next, "-", DNS_MAXNAME + 1);
				dn++;
			}
		}

		free (sd1);

		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));

	}  while (cursor->c_get(cursor, &key, &data, DB_NEXT) == 0);

	cursor->c_close(cursor);
	free_question(question);

	/* now we sort the shebang */
	qsort(table, count, sizeof(struct domainnames), nsec3_comp);

	hashnamelen = strlen(hashname);
	for (j = 0; j < count; j++) {
		dn = ((struct domainnames *)table) + j;
		
		if (strncasecmp(dn->name, hashname, hashnamelen) == 0)
			break;
	}

	if (j == count) {
		dolog(LOG_INFO, "did not find hashname %s in list\n", hashname);
		free (sd0);	
		return NULL;
	}
	
	/* found it, get it via db after converting it */	
	
	/* free what we don't need */
	free (sd0);
	
	dolog(LOG_INFO, "converting %s\n", dn->name);
	backname = dns_label(dn->name, &backnamelen);
	free (table);
	
	rs = get_record_size(db, backname, backnamelen);
	if (rs < 0) {
		free (backname);
		return (NULL);
	}

	if ((sd0 = calloc(1, rs)) == NULL) {
		free (backname);
		return (NULL);
	}

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));
	
	key.data = backname;
	key.size = backnamelen;

	data.data = NULL;
	data.size = rs;

	ret = db->get(db, NULL, &key, &data, 0);	
	if (ret != 0) {
		free (backname);
		free (sd0);
		return (NULL);
	}
	

	memcpy(sd0, data.data, data.size);
	free (backname);

	dolog(LOG_INFO, "returning %s\n", sd0->zonename);
	return (sd0);
}

/*
 * FIND_NSEC3_WILDCARD_CLOSEST - finds the right nsec3 domainname in a zone 
 * 
 */
struct domain *
find_nsec3_wildcard_closest(char *name, int namelen, struct domain *sd, DB *db)
{
	struct domainnames {
		char name[DNS_MAXNAME + 1];
		char next[DNS_MAXNAME + 1];
	} *dn;

	DBC *cursor;
	DBT key, data;

	char *hashname;
	char *backname;
	char *table, *tmp;
	char wildcard[DNS_MAXNAME + 1];
	int backnamelen;
	int rs, ret;
	int i, j;
	int count;
	int golast = 0;
	struct domain *sd0, *sd1;
	struct domain_nsec3param *n3p;
	struct question *question;

	if ((n3p = find_substruct(sd, INTERNAL_TYPE_NSEC3PARAM)) == NULL) {
		return NULL;
	}

	/* first off find  the next closer record */
	sd0 = find_next_closer(db, name, namelen);
	if (sd0 == NULL) {
		return NULL;
	}

#if DEBUG
	dolog(LOG_INFO, "next closer = %s\n", sd0->zonename);
#endif

	snprintf(wildcard, sizeof(wildcard), "*.%s", sd0->zonename);
	backname = dns_label(wildcard, &backnamelen);

	hashname = hash_name(backname, backnamelen, &n3p->nsec3param);
	if (hashname == NULL) {
		dolog(LOG_INFO, "unable to get hashname\n");
		free (sd0);
		return NULL;
	}

#if DEBUG
	dolog(LOG_INFO, "hashname  = %s\n", hashname);
#endif
	
	table = calloc(1, sizeof(struct domainnames));	
	if (table == NULL) {
		free (sd0);
		return (NULL);
	}

	dn = (struct domainnames *)table;
	strlcpy(dn->name, hashname, DNS_MAXNAME + 1);
	strlcpy(dn->next, ".", DNS_MAXNAME + 1);

	/* now go through our zone and find NSEC3 domains */
	/* first pass, count the NSEC3 list */	
	
	/* we need question for checklabel() */
	question = build_fake_question(sd->zone, sd->zonelen, 0);
	if (question == NULL) {
		dolog(LOG_INFO, "build_fake_question failed\n");
		free (sd0);
		return NULL;
	}

	count = count_nsec3_in_zone(db, sd, question);
	count++;	

	/* realloc names structure to fit the NSEC3 names */
	
	tmp = realloc(table, count * sizeof(struct domainnames));
	if (tmp == NULL) {
		dolog(LOG_INFO, "realloc: %s\n", strerror(errno));
		free_question(question);
		free (sd0);
		return NULL;	
	}
		
	table = tmp;
	dn = (struct domainnames *)tmp;
	dn++;

	/* second pass, fill NSEC3 list */

	if (db->cursor(db, NULL, &cursor, 0) != 0) {
		dolog(LOG_INFO, "find_nsec3 db->cursor: %s\n", strerror(errno));
		free_question(question);
		free (sd0);
		return NULL;
	}	

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	if (cursor->c_get(cursor, &key, &data, DB_FIRST) != 0) {
		dolog(LOG_INFO, "find_nsec3 cursor->c_get: %s\n", strerror(errno));
		free_question(question);
		free (sd0);
		return NULL;
	}

	i = 1;

	do {
		rs = data.size;
		if ((sd1 = calloc(1, rs)) == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			free_question(question);
			free (sd0);
			return NULL;
		}

		memcpy((char *)sd1, (char *)data.data, data.size);

		if (checklabel(db, sd1, sd, question) == 1) {
			if (sd1->flags & DOMAIN_HAVE_NSEC3) {
				strlcpy(dn->name, sd1->zonename, DNS_MAXNAME + 1);
				strlcpy(dn->next, "-", DNS_MAXNAME + 1);
				dn++;
			}
		}

		free (sd1);

		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));

	}  while (cursor->c_get(cursor, &key, &data, DB_NEXT) == 0);

	cursor->c_close(cursor);
	free_question(question);

	/* now we sort the shebang */
	qsort(table, count, sizeof(struct domainnames), nsec3_comp);

	dn = ((struct domainnames *)table); 
	if (strcmp(dn->next, ".") == 0)
		golast = 1;
	
	for (j = 0; j < count; j++) {
		dn = ((struct domainnames *)table) + j;
		
		if ((! golast) && (strcmp(dn->next, ".") == 0))
			break;
	}

	dn = ((struct domainnames *)table) + (j - 1);	
	
	/* found it, get it via db after converting it */	
	
	/* free what we don't need */
	free (sd0);
	
	dolog(LOG_INFO, "converting %s\n", dn->name);
	backname = dns_label(dn->name, &backnamelen);
	free (table);
	
	rs = get_record_size(db, backname, backnamelen);
	if (rs < 0) {
		free (backname);
		return (NULL);
	}

	if ((sd0 = calloc(1, rs)) == NULL) {
		free (backname);
		return (NULL);
	}

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));
	
	key.data = backname;
	key.size = backnamelen;

	data.data = NULL;
	data.size = rs;

	ret = db->get(db, NULL, &key, &data, 0);	
	if (ret != 0) {
		free (backname);
		free (sd0);
		return (NULL);
	}
	

	memcpy(sd0, data.data, data.size);
	free (backname);

	dolog(LOG_INFO, "returning %s\n", sd0->zonename);
	return (sd0);
}

/*
 * FIND_NSEC3_COVER_NEXT_CLOSER - finds the right nsec3 domainname in a zone 
 * 
 */
struct domain *
find_nsec3_cover_next_closer(char *name, int namelen, struct domain *sd, DB *db)
{
	struct domainnames {
		char name[DNS_MAXNAME + 1];
		char next[DNS_MAXNAME + 1];
	} *dn;

	DBC *cursor;
	DBT key, data;

	char *hashname;
	char *backname;
	char *table, *tmp;
	int backnamelen;
	int rs, ret;
	int i, j;
	int count;
	int golast = 0;
	struct domain *sd0, *sd1;
	struct domain_nsec3param *n3p;
	struct question *question;

	if ((n3p = find_substruct(sd, INTERNAL_TYPE_NSEC3PARAM)) == NULL) {
		return NULL;
	}

	/* first off find  the next closer record */
	sd0 = find_next_closer(db, name, namelen);
	if (sd0 == NULL) {
		return NULL;
	}

#if DEBUG
	dolog(LOG_INFO, "next closer = %s\n", sd0->zonename);
#endif

	hashname = hash_name(sd0->zone, sd0->zonelen, &n3p->nsec3param);
	if (hashname == NULL) {
		dolog(LOG_INFO, "unable to get hashname\n");
		free (sd0);
		return NULL;
	}

#if DEBUG
	dolog(LOG_INFO, "hashname  = %s\n", hashname);
#endif
	
	table = calloc(1, sizeof(struct domainnames));	
	if (table == NULL) {
		free (sd0);
		return (NULL);
	}

	dn = (struct domainnames *)table;
	strlcpy(dn->name, hashname, DNS_MAXNAME + 1);
	strlcpy(dn->next, ".", DNS_MAXNAME + 1);

	/* now go through our zone and find NSEC3 domains */
	/* first pass, count the NSEC3 list */	
	
	/* we need question for checklabel() */
	question = build_fake_question(sd->zone, sd->zonelen, 0);
	if (question == NULL) {
		dolog(LOG_INFO, "build_fake_question failed\n");
		free (sd0);
		return NULL;
	}

	count = count_nsec3_in_zone(db, sd, question);
	count++;	

	/* realloc names structure to fit the NSEC3 names */
	
	tmp = realloc(table, count * sizeof(struct domainnames));
	if (tmp == NULL) {
		dolog(LOG_INFO, "realloc: %s\n", strerror(errno));
		free_question(question);
		free (sd0);
		return NULL;	
	}
		
	table = tmp;
	dn = (struct domainnames *)tmp;
	dn++;

	/* second pass, fill NSEC3 list */

	if (db->cursor(db, NULL, &cursor, 0) != 0) {
		dolog(LOG_INFO, "find_nsec3 db->cursor: %s\n", strerror(errno));
		free_question(question);
		free (sd0);
		return NULL;
	}	

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	if (cursor->c_get(cursor, &key, &data, DB_FIRST) != 0) {
		dolog(LOG_INFO, "find_nsec3 cursor->c_get: %s\n", strerror(errno));
		free_question(question);
		free (sd0);
		return NULL;
	}

	i = 1;

	do {
		rs = data.size;
		if ((sd1 = calloc(1, rs)) == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			free_question(question);
			free (sd0);
			return NULL;
		}

		memcpy((char *)sd1, (char *)data.data, data.size);

		if (checklabel(db, sd1, sd, question) == 1) {
			if (sd1->flags & DOMAIN_HAVE_NSEC3) {
				strlcpy(dn->name, sd1->zonename, DNS_MAXNAME + 1);
				strlcpy(dn->next, "-", DNS_MAXNAME + 1);
				dn++;
			}
		}

		free (sd1);

		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));

	}  while (cursor->c_get(cursor, &key, &data, DB_NEXT) == 0);

	cursor->c_close(cursor);
	free_question(question);

	/* now we sort the shebang */
	qsort(table, count, sizeof(struct domainnames), nsec3_comp);

	dn = ((struct domainnames *)table); 
	if (strcmp(dn->next, ".") == 0)
		golast = 1;
	
	for (j = 0; j < count; j++) {
		dn = ((struct domainnames *)table) + j;
		
		if ((! golast) && (strcmp(dn->next, ".") == 0))
			break;
	}

	dn = ((struct domainnames *)table) + (j - 1);	
	
	/* found it, get it via db after converting it */	
	
	/* free what we don't need */
	free (sd0);
	
	dolog(LOG_INFO, "converting %s\n", dn->name);
	backname = dns_label(dn->name, &backnamelen);
	free (table);
	
	rs = get_record_size(db, backname, backnamelen);
	if (rs < 0) {
		free (backname);
		return (NULL);
	}

	if ((sd0 = calloc(1, rs)) == NULL) {
		free (backname);
		return (NULL);
	}

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));
	
	key.data = backname;
	key.size = backnamelen;

	data.data = NULL;
	data.size = rs;

	ret = db->get(db, NULL, &key, &data, 0);	
	if (ret != 0) {
		free (backname);
		free (sd0);
		return (NULL);
	}
	

	memcpy(sd0, data.data, data.size);
	free (backname);

	dolog(LOG_INFO, "returning %s\n", sd0->zonename);
	return (sd0);
}

/*
 * FIND_NSEC3_MATCH_QNAME - find the matching QNAME and return NSEC3
 *
 */

struct domain *
find_nsec3_match_qname(char *name, int namelen, struct domain *sd, DB *db)
{
	struct domainnames {
		char name[DNS_MAXNAME + 1];
		char next[DNS_MAXNAME + 1];
	} *dn;

	DBC *cursor;
	DBT key, data;

	char *hashname;
	char *backname;
	char *table, *tmp;
	int backnamelen;
	int rs, ret;
	int i, j;
	int count, hashnamelen;
	struct domain *sd0, *sd1;
	struct domain_nsec3param *n3p;
	struct question *question;

	if ((n3p = find_substruct(sd, INTERNAL_TYPE_NSEC3PARAM)) == NULL) {
		return NULL;
	}

	hashname = hash_name(name, namelen,  &n3p->nsec3param);
	if (hashname == NULL) {
		dolog(LOG_INFO, "unable to get hashname\n");
		return NULL;
	}

#if DEBUG
	dolog(LOG_INFO, "hashname  = %s\n", hashname);
#endif
	
	/* now go through our zone and find NSEC3 domains */
	/* first pass, count the NSEC3 list */	
	
	/* we need question for checklabel() */
	question = build_fake_question(sd->zone, sd->zonelen, 0);
	if (question == NULL) {
		dolog(LOG_INFO, "build_fake_question failed\n");
		return NULL;
	}

	count = count_nsec3_in_zone(db, sd, question);

	/* realloc names structure to fit the NSEC3 names */
	
	tmp = calloc(count, sizeof(struct domainnames));
	if (tmp == NULL) {
		dolog(LOG_INFO, "realloc: %s\n", strerror(errno));
		free_question(question);
		return NULL;	
	}
		
	table = tmp;
	dn = (struct domainnames *)tmp;

	/* second pass, fill NSEC3 list */

	if (db->cursor(db, NULL, &cursor, 0) != 0) {
		dolog(LOG_INFO, "find_nsec3 db->cursor: %s\n", strerror(errno));
		free_question(question);
		return NULL;
	}	

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	if (cursor->c_get(cursor, &key, &data, DB_FIRST) != 0) {
		dolog(LOG_INFO, "find_nsec3 cursor->c_get: %s\n", strerror(errno));
		free_question(question);
		return NULL;
	}

	i = 1;

	do {
		rs = data.size;
		if ((sd1 = calloc(1, rs)) == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			free_question(question);
			return NULL;
		}

		memcpy((char *)sd1, (char *)data.data, data.size);

		if (checklabel(db, sd1, sd, question) == 1) {
			if (sd1->flags & DOMAIN_HAVE_NSEC3) {
				strlcpy(dn->name, sd1->zonename, DNS_MAXNAME + 1);
				strlcpy(dn->next, "-", DNS_MAXNAME + 1);
				dn++;
			}
		}

		free (sd1);

		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));

	}  while (cursor->c_get(cursor, &key, &data, DB_NEXT) == 0);

	cursor->c_close(cursor);
	free_question(question);

	/* now we sort the shebang */
	qsort(table, count, sizeof(struct domainnames), nsec3_comp);

	hashnamelen = strlen(hashname);
	for (j = 0; j < count; j++) {
		dn = ((struct domainnames *)table) + j;
		
		if (strncasecmp(dn->name, hashname, hashnamelen) == 0)
			break;
	}

	if (j == count) {
		free(table);
		return NULL;
	}
		
	
	/* found it, get it via db after converting it */	
	
	dolog(LOG_INFO, "converting %s\n", dn->name);
	backname = dns_label(dn->name, &backnamelen);
	free (table);
	
	rs = get_record_size(db, backname, backnamelen);
	if (rs < 0) {
		free (backname);
		return (NULL);
	}

	if ((sd0 = calloc(1, rs)) == NULL) {
		free (backname);
		return (NULL);
	}

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));
	
	key.data = backname;
	key.size = backnamelen;

	data.data = NULL;
	data.size = rs;

	ret = db->get(db, NULL, &key, &data, 0);	
	if (ret != 0) {
		free (backname);
		free (sd0);
		return (NULL);
	}
	

	memcpy(sd0, data.data, data.size);
	free (backname);

	dolog(LOG_INFO, "returning %s\n", sd0->zonename);
	return (sd0);
}

#if 0
static int
lookup_type(int internal_type)
{
	switch (internal_type) {
	case INTERNAL_TYPE_SOA:
		return DNS_TYPE_SOA;
	case INTERNAL_TYPE_A:
		return DNS_TYPE_A;
	case INTERNAL_TYPE_AAAA:
		return DNS_TYPE_AAAA;
	case INTERNAL_TYPE_MX:
		return DNS_TYPE_MX;
	case INTERNAL_TYPE_NS:
		return DNS_TYPE_NS;
	case INTERNAL_TYPE_CNAME:
		return DNS_TYPE_CNAME;
	case INTERNAL_TYPE_PTR:
		return DNS_TYPE_PTR;
	case INTERNAL_TYPE_TXT:
		return DNS_TYPE_TXT;
	case INTERNAL_TYPE_SPF:
		return DNS_TYPE_SPF;
	case INTERNAL_TYPE_SRV:
		return DNS_TYPE_SRV;
	case INTERNAL_TYPE_SSHFP:
		return DNS_TYPE_SSHFP;
	case INTERNAL_TYPE_NAPTR:
		return DNS_TYPE_NAPTR;
	case INTERNAL_TYPE_DNSKEY:
		return DNS_TYPE_DNSKEY;
	case INTERNAL_TYPE_DS:
		return DNS_TYPE_DS;
	case INTERNAL_TYPE_NSEC:
		return DNS_TYPE_NSEC;
	case INTERNAL_TYPE_NSEC3:
		return DNS_TYPE_NSEC3;
	case INTERNAL_TYPE_NSEC3PARAM:
		return DNS_TYPE_NSEC3PARAM;
	}

	/* NOTREACHED */
	return -1;
}
#endif 
