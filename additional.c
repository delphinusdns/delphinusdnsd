/*
 * Copyright (c) 2005-2022 Peter J. Philipp <pjp@delphinusdns.org>
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

#include <syslog.h>
#if __OpenBSD__ 
#include <siphash.h>
#else
#include "siphash.h"
#endif

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
#include "endian.h"
#else /* not linux */
#include <sys/queue.h>
#include <sys/tree.h>
#ifdef __FreeBSD__
#include <sys/endian.h>
#include "endian.h"
#endif /* __FreeBSD__ */
#endif /* __linux__ */


#include "ddd-dns.h"
#include "ddd-db.h"
#include "ddd-crypto.h"


int additional_a(char *, int, struct rbtree *, char *, int, int, int *);
int additional_aaaa(char *, int, struct rbtree *, char *, int, int, int *);
int additional_mx(char *, int, struct rbtree *, char *, int, int, int *);
int additional_ds(char *, int, struct rbtree *, char *, int, int, int *);
int additional_opt(struct question *, char *, int, int, struct sockaddr *, socklen_t, uint16_t);
int additional_ptr(char *, int, struct rbtree *, char *, int, int, int *);
int additional_rrsig(char *, int, int, struct rbtree *, char *, int, int, int *, int);
int additional_nsec(char *, int, int, struct rbtree *, char *, int, int, int *, int);
int additional_nsec3(char *, int, int, struct rbtree *, char *, int, int, int *, int);
int additional_tsig(struct question *, char *, int, int, int, int, DDD_HMAC_CTX *, uint16_t);
int additional_wildcard(char *, int, struct rbtree *, char *, int, int, int *, ddDB *);

extern void 	pack(char *, char *, int);
extern void 	pack32(char *, uint32_t);
extern void 	pack16(char *, uint16_t);
extern void 	pack8(char *, uint8_t);
extern uint32_t unpack32(char *);
extern uint16_t unpack16(char *);
extern void 	unpack(char *, char *, int);

extern int 		compress_label(u_char *, int, int);
extern struct rbtree * find_rrset(ddDB *db, char *name, int len);
extern struct rrset * find_rr(struct rbtree *rbt, uint16_t rrtype);
extern int display_rr(struct rrset *rrset);
extern int  find_tsig_key(char *, int, char *, int);
extern void      dolog(int, char *, ...);
extern char * hash_name(char *name, int len, struct nsec3param *n3p);
extern char * dns_label(char *, int *);
extern struct rbtree * find_rrsetwild(ddDB *, char *, int);
extern struct zoneentry * zone_findzone(struct rbtree *);
extern char * find_next_closer_nsec3(char *, int, char *);
extern struct rbtree * find_nsec3_match_qname_wild(char *, int, struct rbtree *, ddDB *);




extern int cookies;
extern char *cookiesecret;
extern int cookiesecret_len;
extern int dnssec;
extern int tls;


/*
 * ADDITIONAL_A - tag on an additional set of A records to packet
 */

int 
additional_a(char *name, int namelen, struct rbtree *rbt, char *reply, int replylen, int offset, int *retcount)
{
	int a_count = 0;
	int tmplen;
	int rroffset = offset;

	struct answer {
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
		in_addr_t rdata;		/* 16 */
	} __attribute__((packed));

	struct answer *answer;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	int tmpcount = 0;

	pack32((char *)retcount, 0);

	if ((rrset = find_rr(rbt, DNS_TYPE_A)) == NULL)
		return 0;

	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		rroffset = offset;
		if ((offset + namelen) > replylen)
			goto out;

		memcpy(&reply[offset], name, namelen);
		offset += namelen;
		tmplen = compress_label((u_char*)reply, offset, namelen);
		
		if (tmplen != 0) {
			offset = tmplen;
		}	
		if ((offset + sizeof(struct answer)) > replylen) {
			offset = rroffset;
			goto out;
		}

		answer = (struct answer *)&reply[offset];
		
		answer->type = htons(DNS_TYPE_A);
		answer->class = htons(DNS_CLASS_IN);
		answer->ttl = htonl(rrset->ttl);

		answer->rdlength = htons(sizeof(in_addr_t));

		memcpy((char *)&answer->rdata, (char *)&((struct a *)rrp->rdata)->a, sizeof(in_addr_t));
		offset += sizeof(struct answer);
		tmpcount++;

		a_count++;
	}

	pack32((char *)retcount, tmpcount);

out:
	return (offset);

}

/*
 * ADDITIONAL_AAAA - tag on an additional set of AAAA records to packet
 */

int 
additional_aaaa(char *name, int namelen, struct rbtree *rbt, char *reply, int replylen, int offset, int *retcount)
{
	int aaaa_count = 0;
	int tmplen;
	int rroffset = offset;

	struct answer {
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 
		struct in6_addr rdata;	
	} __attribute__((packed));

	struct answer *answer;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	int tmpcount = 0;

	pack32((char *)retcount, 0);

	if ((rrset = find_rr(rbt, DNS_TYPE_AAAA)) == NULL)
		return 0;

	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		rroffset = offset;
		if ((offset + namelen) > replylen)
			goto out;

		memcpy(&reply[offset], name, namelen);
		offset += namelen;
		tmplen = compress_label((u_char*)reply, offset, namelen);
		
		if (tmplen != 0) {
			offset = tmplen;
		}	

		if ((offset + sizeof(struct answer)) > replylen) {
			offset = rroffset;
			goto out;
		}

		answer = (struct answer *)&reply[offset];
		
		answer->type = htons(DNS_TYPE_AAAA);
		answer->class = htons(DNS_CLASS_IN);
		answer->ttl = htonl(rrset->ttl);

		answer->rdlength = htons(sizeof(struct in6_addr));

		memcpy((char *)&answer->rdata, (char *)&((struct aaaa *)rrp->rdata)->aaaa, sizeof(struct in6_addr));
		offset += sizeof(struct answer);
		tmpcount++;

		aaaa_count++;
	}

	pack32((char *)retcount, tmpcount);
out:
	return (offset);

}

/* 
 * ADDITIONAL_MX() - replies a DNS question (*q) on socket (so)
 *
 */

int 
additional_mx(char *name, int namelen, struct rbtree *rbt, char *reply, int replylen, int offset, int *retcount)
{
	int mx_count = 0;
	int tmplen;
	int rroffset = offset;

	struct answer {
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 
		uint16_t mx_priority;
	} __attribute__((packed));

	struct answer *answer;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	int tmpcount = 0;

	pack32((char *)retcount, 0);

	if ((rrset = find_rr(rbt, DNS_TYPE_MX)) == NULL)
		return 0;


	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		rroffset = offset;

		if ((offset + namelen) > replylen)
			return 0;

		memcpy(&reply[offset], name, namelen);
		offset += namelen;
		tmplen = compress_label((u_char*)reply, offset, namelen);
		
		if (tmplen != 0) {
			offset = tmplen;
		}	

		if ((offset + sizeof(struct answer)) > replylen) {
			offset = rroffset;
			return 0;
		}

		answer = (struct answer *)&reply[offset];
		
		answer->type = htons(DNS_TYPE_MX);
		answer->class = htons(DNS_CLASS_IN);
		answer->ttl = htonl(rrset->ttl);
		answer->mx_priority = htons(((struct smx *)rrp->rdata)->preference);

		offset += sizeof(struct answer);

		if ((offset + ((struct smx *)rrp->rdata)->exchangelen) > replylen) {
			offset = rroffset;
			return 0;
		}

		memcpy((char *)&reply[offset], (char *)((struct smx *)rrp->rdata)->exchange, ((struct smx *)rrp->rdata)->exchangelen);

		offset += ((struct smx *)rrp->rdata)->exchangelen; 
		tmplen = compress_label((u_char*)reply, offset, ((struct smx *)rrp->rdata)->exchangelen);
		
		if (tmplen != 0) {
			answer->rdlength = htons((((struct smx *)rrp->rdata)->exchangelen - (offset - tmplen)) + sizeof(uint16_t));
			offset = tmplen;
		} else
			answer->rdlength = htons(((struct smx *)rrp->rdata)->exchangelen + sizeof(uint16_t));


		tmpcount++;

		mx_count++;
	}
	
	pack32((char *)retcount, tmpcount);

	return (offset);

}

/* 
 * ADDITIONAL_PTR() - replies a DNS question (*q) on socket (so)
 *
 */


int 
additional_ptr(char *name, int namelen, struct rbtree *rbt, char *reply, int replylen, int offset, int *retcount)
{
	int tmplen;
	int rroffset = offset;

	struct answer {
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 
	} __attribute__((packed));

	struct answer *answer;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	int tmpcount = 0;

	pack32((char *)retcount, 0);

	if ((rrset = find_rr(rbt, DNS_TYPE_PTR)) == NULL)
		return 0;

	if ((offset + namelen) > replylen)
		goto out;

	memcpy(&reply[offset], name, namelen);
	offset += namelen;
	tmplen = compress_label((u_char*)reply, offset, namelen);
	
	if (tmplen != 0) {
		offset = tmplen;
	}	

	if ((offset + sizeof(struct answer)) > replylen) {
		offset = rroffset;
		goto out;
	}

	rrp = TAILQ_FIRST(&rrset->rr_head);
	if (rrp == NULL)
		return 0;

	answer = (struct answer *)&reply[offset];
	
	answer->type = htons(DNS_TYPE_PTR);
	answer->class = htons(DNS_CLASS_IN);
	answer->ttl = htonl(rrset->ttl);

	offset += sizeof(struct answer);

	if ((offset + ((struct ptr *)rrp->rdata)->ptrlen) > replylen) {
		offset = rroffset;
		goto out;
	}

	memcpy((char *)&reply[offset], (char *)((struct ptr *)rrp->rdata)->ptr, ((struct ptr *)rrp->rdata)->ptrlen);

	offset += ((struct ptr *)rrp->rdata)->ptrlen;
	tmplen = compress_label((u_char*)reply, offset, ((struct ptr *)rrp->rdata)->ptrlen);
		
	if (tmplen != 0) {
		answer->rdlength = htons(((struct ptr *)rrp->rdata)->ptrlen - (offset - tmplen));
		offset = tmplen;
	} else
		answer->rdlength = htons(((struct ptr *)rrp->rdata)->ptrlen);


	tmpcount++;
	pack32((char *)retcount, tmpcount);

out:
	return (offset);

}
/*
 * ADDITIONAL_TSIG - tag on an additional TSIG record to packet
 */

int 
additional_tsig(struct question *question, char *reply, int replylen, int offset, int request, int envelope, DDD_HMAC_CTX *tsigctx, uint16_t fudge) 
{
	struct dns_tsigrr *answer, *ppanswer, *timers;
	u_int macsize = DNS_HMAC_SHA256_SIZE;
	int tsignamelen;
	int ppoffset = 0;
	int ttlen = 0, rollback;
	char *pseudo_packet = NULL;
	char tsig_timers[512];
	struct dns_header *odh;
	char tsigkey[512];
	time_t now;
	static int priordigest = 1;
#ifdef __linux__
	uint64_t tmp64;
#endif

	pseudo_packet = malloc(replylen);
	if (pseudo_packet == NULL) {
		goto out;	
	}

	now = time(NULL);
#ifdef __linux__
	tmp64 = now;
#endif
	rollback = offset;

	if (envelope > 1 || envelope < -1) {
		ttlen = 0;
		if (priordigest) {
			pack16((char *)&tsig_timers[ttlen], htons(question->tsig.tsigmaclen));
			ttlen += 2;

			memcpy(&tsig_timers[ttlen], question->tsig.tsigmac, question->tsig.tsigmaclen);
			ttlen += question->tsig.tsigmaclen;

			delphinusdns_HMAC_Update(tsigctx, (u_char *)tsig_timers, ttlen);

			priordigest = 0;
		}

		question->tsig.tsigerrorcode = 0; 	/* to be sure */
	} else {
		if (request == 0) {
			if (question->tsig.tsigerrorcode && question->tsig.tsigerrorcode != DNS_BADTIME) {
				ppoffset = 0;
				pack16(&pseudo_packet[ppoffset], 0);
				ppoffset += 2;
			} else {
				/* RFC 2845 section 3.4.3 */
				ppoffset = 0;
				pack16(&pseudo_packet[ppoffset], htons(question->tsig.tsigmaclen));
				ppoffset += 2;

				memcpy(&pseudo_packet[ppoffset], question->tsig.tsigmac, question->tsig.tsigmaclen);
				ppoffset += question->tsig.tsigmaclen;
			}
		}
	}
			
	odh = (struct dns_header *)reply;
	memcpy(&pseudo_packet[ppoffset], &reply[0], offset);
	ppoffset += offset;

	if (envelope > 1 || envelope < -1) {
		delphinusdns_HMAC_Update(tsigctx, (u_char *)reply, offset);
	}

	if ((tsignamelen = find_tsig_key(question->tsig.tsigkey, 
		question->tsig.tsigkeylen, (char *)&tsigkey, sizeof(tsigkey))) < 0) {
		/* do nothing here? */
		memset(tsigkey, 0, sizeof(tsigkey));
		tsignamelen = 0;
	}

	if ((offset + 2 +  8 + 2 + question->tsig.tsigmaclen + 
		question->tsig.tsigkeylen + 
		question->tsig.tsigalglen + 2 + 2 + 4) > replylen) {
		dolog(LOG_ERR, "additional_tsig: is bigger than replylen\n");
		offset = rollback;
		goto out;
	}

	/* keyname */
	memcpy(&reply[offset], question->tsig.tsigkey, question->tsig.tsigkeylen);
	offset += question->tsig.tsigkeylen;

	memcpy(&pseudo_packet[ppoffset], question->tsig.tsigkey, question->tsig.tsigkeylen);
	ppoffset += question->tsig.tsigkeylen;

	/* type TSIG */
	pack16(&reply[offset], htons(DNS_TYPE_TSIG));
	offset += 2;

	/* class ANY */
	pack16(&reply[offset], htons(DNS_CLASS_ANY));
	offset += 2;
	
	pack16(&pseudo_packet[ppoffset], htons(DNS_CLASS_ANY));
	ppoffset += 2;

	/* ttl */
	pack32(&reply[offset], 0);
	offset += 4;

	pack32(&pseudo_packet[ppoffset], 0);
	ppoffset += 4;

	/* rdlen */
	if (question->tsig.tsigerrorcode == DNS_BADTIME) {
		pack16(&reply[offset], htons(2 + 8 + question->tsig.tsigalglen + question->tsig.tsigmaclen + 2 + 2 + 2 + 6));
	} else {
		pack16(&reply[offset], htons(2 + 8 + question->tsig.tsigalglen + question->tsig.tsigmaclen + 2 + 2 + 2));
	}
	offset += 2;

	memcpy(&reply[offset], question->tsig.tsigalg, question->tsig.tsigalglen);
	offset += question->tsig.tsigalglen;

	memcpy(&pseudo_packet[ppoffset], question->tsig.tsigalg, question->tsig.tsigalglen);
	ppoffset += question->tsig.tsigalglen;


	answer = (struct dns_tsigrr *)&reply[offset];
	if (envelope > 1 || envelope < -1) {
#ifdef __linux__
		answer->timefudge = htobe64(((uint64_t)tmp64 << 16) | (fudge & 0xffff));
#else
		answer->timefudge = htobe64(((uint64_t)now << 16) | (fudge & 0xffff));
#endif
	} else {
		if (request == 0 || envelope == 1) {
			answer->timefudge = question->tsig.tsig_timefudge;
		} else {
#ifdef __linux__
			answer->timefudge = htobe64((tmp64 << 16) | (fudge & 0xffff));
#else
			answer->timefudge = htobe64((now << 16) | (fudge & 0xffff));
#endif
		}
	}

	answer->macsize = htons(question->tsig.tsigmaclen);
	offset += (8 + 2);

	/* skip mac */
	offset += question->tsig.tsigmaclen;

	pack16(&reply[offset], odh->id);
	offset += 2;

	pack16(&reply[offset], htons(question->tsig.tsigerrorcode));
	offset += 2;
		
	if (question->tsig.tsigerrorcode == DNS_BADTIME) {
		pack16(&reply[offset], htons(6));
		offset += 2;

		pack16(&reply[offset], 0);
		offset += 2;
		
		pack32(&reply[offset], htonl(now & 0xffffffff));
		offset += 4;

	} else {
		pack16(&reply[offset], 0);
		offset += 2;
	}

	ppanswer = (struct dns_tsigrr *)&pseudo_packet[ppoffset];
	if (request == 0 || envelope == 1) 
		ppanswer->timefudge = question->tsig.tsig_timefudge;
	else
#ifdef __linux__
		ppanswer->timefudge = htobe64(((uint64_t)tmp64 << 16) | (fudge & 0xffff));
#else
		ppanswer->timefudge = htobe64(((uint64_t)now << 16) | (fudge & 0xffff));
#endif
	ppoffset += 8;


	/* error */
	pack16(&pseudo_packet[ppoffset], htons(question->tsig.tsigerrorcode));
	ppoffset += 2;
		
	/* other len */
	if (question->tsig.tsigerrorcode == DNS_BADTIME) {
		pack16(&pseudo_packet[ppoffset], htons(6));
		ppoffset += 2;

		pack16(&pseudo_packet[ppoffset], htons(0));
		ppoffset += 2;
		
		pack32(&pseudo_packet[ppoffset], htonl(now & 0xffffffff));
		ppoffset += 4;
	} else {
		pack16(&pseudo_packet[ppoffset], htons(0));
		ppoffset += 2;
	}


	if (envelope > 1 || envelope < -1) {
		if (envelope % 89 == 0 || envelope == -2)  {
			ttlen = 0;
			timers = (struct dns_tsigrr *)&tsig_timers[ttlen];
			timers->timefudge = htobe64(((uint64_t)now << 16) | (fudge & 0xffff));
			ttlen += 8;
			delphinusdns_HMAC_Update(tsigctx, (const unsigned char *)tsig_timers, ttlen);
		}
		

		/* we need it for the else */
		if (envelope % 89 == 0 || envelope == -2) {
			macsize = DNS_HMAC_SHA256_SIZE;
			delphinusdns_HMAC_Final(tsigctx, (unsigned char *)&answer->mac[0], (u_int *)&macsize);
			memcpy(question->tsig.tsigmac, &answer->mac[0], macsize);
			priordigest = 1;
		} else
			offset = rollback;

	} else {
		const DDD_EVP_MD *md;

		md = delphinusdns_EVP_get_digestbyname("sha256");
		if (question->tsig.tsigerrorcode == DNS_BADTIME) {
			delphinusdns_HMAC(md, tsigkey, tsignamelen, 
				(unsigned char *)pseudo_packet, ppoffset, 
				(unsigned char *)&answer->mac[0], (u_int *)&macsize);
		} else if (question->tsig.tsigerrorcode) {
			memset(&answer->mac[0], 0, question->tsig.tsigmaclen);
		} else {
			delphinusdns_HMAC(md, tsigkey, tsignamelen, 
				(unsigned char *)pseudo_packet, ppoffset, 
				(unsigned char *)&answer->mac[0], (u_int *)&macsize);

			memcpy(question->tsig.tsigmac, &answer->mac[0], macsize);
		}
	}

	free(pseudo_packet);

out:
	return (offset);

}

/*
 * ADDITIONAL_OPT - tag on an additional EDNS0 (OPT) record to packet
 */

int 
additional_opt(struct question *question, char *reply, int replylen, int offset, struct sockaddr *sa, socklen_t salen, uint16_t tlsbuf)
{
	struct dns_optrr *answer;
	uint16_t opt_code;
	int rcode = 0;

	if ((offset + sizeof(struct dns_optrr)) > replylen) {
		goto out;
	}

	answer = (struct dns_optrr *)&reply[offset];

	memset(answer->name, 0, sizeof(answer->name));
	answer->type = htons(DNS_TYPE_OPT);
	answer->class = htons(MIN(question->edns0len, replylen));
	if (dnssec && question->dnssecok)
		rcode =  DNSSEC_OK;

	if (question->badvers)
		rcode |= (0x1 << 24);

	answer->ttl = htonl(rcode); 	/* EXTENDED RCODE */

	answer->rdlen = htons(0);
	offset += sizeof(struct dns_optrr);

	/* if we've been given a client cookie reply with a server cookie */
	if (cookies && salen > 0 && 
		question->cookie.have_cookie && question->cookie.error == 0) {
		SIPHASH_CTX ctx;
		char digest[SIPHASH_DIGEST_LENGTH];
		uint8_t version = 1, reserved = 0;
		uint32_t timestamp, compts;
		struct sockaddr_in *sin;
		struct sockaddr_in6 *sin6;
		
		timestamp = (uint32_t)time(NULL);

		if (question->cookie.servercookie_len > 0) {
			int32_t dt32;

			compts = unpack32(&question->cookie.servercookie[4]);
			NTOHL(compts);
			dt32 = timestamp - compts;
			/* 1 hour in the past and 5 minutes in future is OK */
			if ((dt32 <= 3600) && (dt32 >= -300)) {
				/* check if we can pack opt code and length and payload (24) */
				if (offset + 8 + question->cookie.servercookie_len + 4 > replylen)
					goto out;

				opt_code = DNS_OPT_CODE_COOKIE;
				pack16(&reply[offset], htons(opt_code));
				offset += 2;
				pack16(&reply[offset], htons(8 + question->cookie.servercookie_len));
				offset += 2;

				pack(&reply[offset], (char *)&question->cookie.clientcookie, 8);
				offset += 8;
				pack((char *)&reply[offset], (char *)&question->cookie.servercookie, question->cookie.servercookie_len);
				offset += question->cookie.servercookie_len;

				answer->rdlen = htons(4 + 8 + question->cookie.servercookie_len);
				goto out;
			}
		}

		HTONL(timestamp);

		SipHash24_Init(&ctx, (const SIPHASH_KEY *)cookiesecret);
		SipHash24_Update(&ctx, question->cookie.clientcookie, sizeof(question->cookie.clientcookie));
		
		SipHash24_Update(&ctx, (char *)&version, 1);
		SipHash24_Update(&ctx, (char *)&reserved, 1);
		SipHash24_Update(&ctx, (char *)&reserved, 1);
		SipHash24_Update(&ctx, (char *)&reserved, 1);
		SipHash24_Update(&ctx, (char *)&timestamp, sizeof(timestamp));

		switch (sa->sa_family) {	
		case AF_INET:
			sin = (struct sockaddr_in *)sa;
			SipHash24_Update(&ctx, (char *)&sin->sin_addr.s_addr, sizeof(uint32_t));
			break;	
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)sa;
			SipHash24_Update(&ctx, (char *)&sin6->sin6_addr, sizeof(struct in6_addr));
			break;
		default:
			return (offset);
			break;
		}

		SipHash24_Final(&digest, &ctx);

		/* check if we can pack opt code and length and payload (24) */
		if (offset + 24 + 4 > replylen)
			goto out;

		opt_code = DNS_OPT_CODE_COOKIE;
		pack16(&reply[offset], htons(opt_code));
		offset += 2;
		pack16(&reply[offset], htons(24));
		offset += 2;

		pack(&reply[offset], (char *)&question->cookie.clientcookie, 8);
		offset += 8;
		pack8(&reply[offset++], version);
		pack8(&reply[offset++], reserved);
		pack8(&reply[offset++], reserved);
		pack8(&reply[offset++], reserved);
		pack32(&reply[offset], timestamp);
		offset += sizeof(timestamp);
		pack((char *)&reply[offset], (char *)&digest, sizeof(digest));
		offset += sizeof(digest);

		answer->rdlen = htons(4 + 24);
	}
	/* add padding if we're in the TLS process */
	if (tls && tlsbuf > 0) {
		if (offset + 2 + 2 + tlsbuf > replylen)
			goto out;

		opt_code = DNS_OPT_CODE_PADDING;
		pack16(&reply[offset], htons(opt_code));
		offset += 2;
		pack16(&reply[offset], htons(tlsbuf));
		offset += 2;
		
		arc4random_buf(&reply[offset], tlsbuf);
		offset += tlsbuf;

		NTOHS(answer->rdlen);
		answer->rdlen += (4 + tlsbuf);
		HTONS(answer->rdlen);
	}
out:
	return (offset);

}

/*
 * ADDITIONAL_RRSIG - tag on an additional RRSIG to the answer
 * 		type passed must be a DNS_TYPE!
 */

int 
additional_rrsig(char *name, int namelen, int inttype, struct rbtree *rbt, char *reply, int replylen, int offset, int *count, int authoritative)
{
	struct answer {
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
		uint16_t type_covered;
		uint8_t algorithm;
		uint8_t labels;
		uint32_t original_ttl;
		uint32_t sig_expiration;
		uint32_t sig_inception;
		uint16_t keytag;
	} __attribute__((packed));


	struct answer *answer;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	int tmplen, rroffset;
	int rrsig_count = 0;
	time_t now;

	now = time(NULL);

	if ((rrset = find_rr(rbt, DNS_TYPE_RRSIG)) == NULL)
		return 0;


	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		if (inttype != -1 && inttype != ((struct rrsig *)rrp->rdata)->type_covered)
			continue;

		/* check if we go over our return length */
		if ((offset + namelen) > replylen)
			return 0;

		memcpy(&reply[offset], name, namelen);
		offset += namelen;
		tmplen = compress_label((u_char*)reply, offset, namelen);

		if (tmplen != 0) {
			offset = tmplen;
		}

		if ((offset + sizeof(struct answer)) > replylen) {
			return 0;
		}
			
		rroffset = offset;
		answer = (struct answer *)&reply[offset];
		answer->type = htons(DNS_TYPE_RRSIG);
		answer->class = htons(DNS_CLASS_IN);

		if (authoritative)
			answer->ttl = htonl(((struct rrsig *)rrp->rdata)->ttl);
		else
			answer->ttl = htonl(((struct rrsig *)rrp->rdata)->ttl - (MIN(((struct rrsig *)rrp->rdata)->ttl , difftime(now, ((struct rrsig *)rrp->rdata)->created))));

		answer->type_covered = htons(((struct rrsig *)rrp->rdata)->type_covered);
		answer->algorithm = ((struct rrsig *)rrp->rdata)->algorithm;
		answer->labels = ((struct rrsig *)rrp->rdata)->labels;
		answer->original_ttl = htonl(((struct rrsig *)rrp->rdata)->original_ttl);
		answer->sig_expiration = htonl(((struct rrsig *)rrp->rdata)->signature_expiration);	
		answer->sig_inception = htonl(((struct rrsig *)rrp->rdata)->signature_inception);
		answer->keytag = htons(((struct rrsig *)rrp->rdata)->key_tag);
	
		offset += sizeof(struct answer);
		rroffset = offset;

		if ((offset + ((struct rrsig *)rrp->rdata)->signame_len) > replylen)
			return 0;

		memcpy(&reply[offset], ((struct rrsig *)rrp->rdata)->signers_name, ((struct rrsig *)rrp->rdata)->signame_len);

		offset += ((struct rrsig *)rrp->rdata)->signame_len;

		if ((offset + ((struct rrsig *)rrp->rdata)->signature_len) > replylen)
			return 0;

		memcpy(&reply[offset], ((struct rrsig *)rrp->rdata)->signature, ((struct rrsig *)rrp->rdata)->signature_len);
		offset += ((struct rrsig *)rrp->rdata)->signature_len;

		answer->rdlength = htons((offset - rroffset) + 18);

		rrsig_count++;
	}

	*count = rrsig_count;

	return (offset);
}

/*
 * ADDITIONAL_NSEC - tag on an additional NSEC with RRSIG to the answer
 * 		type passed must be a DNS_TYPE!
 */

int 
additional_nsec(char *name, int namelen, int inttype, struct rbtree *rbt, char *reply, int replylen, int offset, int *count, int authoritative)
{
	struct answer {
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
	} __attribute__((packed));

	struct answer *answer;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	int tmplen;
	int retcount;
	time_t now;

	now = time(NULL);

	if ((rrset = find_rr(rbt, DNS_TYPE_NSEC)) == NULL)
		goto out;

	rrp = TAILQ_FIRST(&rrset->rr_head);
	if (rrp == NULL)
		goto out;
	

	/* check if we go over our return length */
	if ((offset + namelen) > replylen)
		return 0;

	memcpy(&reply[offset], name, namelen);
	offset += namelen;
	tmplen = compress_label((u_char*)reply, offset, namelen);

	if (tmplen != 0) {
		offset = tmplen;
	}

	if ((offset + sizeof(struct answer)) > replylen) {
		return 0;
	}

	answer = (struct answer *)&reply[offset];
	answer->type = htons(DNS_TYPE_NSEC);
	answer->class = htons(DNS_CLASS_IN);
	if (authoritative)
		answer->ttl = htonl(rrset->ttl);
	else
		answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

	answer->rdlength = htons(((struct nsec *)rrp->rdata)->ndn_len + 
			((struct nsec *)rrp->rdata)->bitmap_len);
	
	offset += sizeof(*answer);

	memcpy(&reply[offset], ((struct nsec *)rrp->rdata)->next_domain_name,
                ((struct nsec *)rrp->rdata)->ndn_len);

	offset += ((struct nsec *)rrp->rdata)->ndn_len;

	memcpy(&reply[offset], ((struct nsec *)rrp->rdata)->bitmap, 
			((struct nsec *)rrp->rdata)->bitmap_len);
	offset += ((struct nsec *)rrp->rdata)->bitmap_len;

	tmplen = additional_rrsig(name, namelen, DNS_TYPE_NSEC, rbt, reply, replylen, offset, &retcount, authoritative);

	if (tmplen == 0) {
		goto out;
	}

	offset = tmplen;
	
	*count = retcount + 1;

out:
	return (offset);

}

/*
 * ADDITIONAL_NSEC3 - tag on an additional NSEC3 with RRSIG to the answer
 * 		type passed must be an DNS_TYPE!
 */

int 
additional_nsec3(char *name, int namelen, int inttype, struct rbtree *rbt, char *reply, int replylen, int offset, int *count, int authoritative)
{
	struct answer {
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
	struct rrset *rrset;
	struct rr *rrp;

	int tmplen;
	uint8_t *somelen;
	int retcount;
	time_t now;

	now = time(NULL);

	if ((rrset = find_rr(rbt, DNS_TYPE_NSEC3)) == NULL)
		goto out;

	rrp = TAILQ_FIRST(&rrset->rr_head);
	if (rrp == NULL)
		goto out;
	

	/* check if we go over our return length */
	if ((offset + namelen) > replylen)
		return 0;

	memcpy(&reply[offset], name, namelen);
	offset += namelen;
	tmplen = compress_label((u_char*)reply, offset, namelen);

	if (tmplen != 0) {
		offset = tmplen;
	}

	if ((offset + sizeof(struct answer)) > replylen) {
		return 0;
	}

	answer = (struct answer *)&reply[offset];
	answer->type = htons(DNS_TYPE_NSEC3);
	answer->class = htons(DNS_CLASS_IN);

	if (authoritative)
		answer->ttl = htonl(rrset->ttl);
	else
		answer->ttl = htonl(rrset->ttl - (MIN(rrset->ttl, difftime(now, rrset->created))));

	answer->rdlength = htons(6 + ((struct nsec3 *)rrp->rdata)->saltlen + 
			((struct nsec3 *)rrp->rdata)->nextlen + 
			((struct nsec3 *)rrp->rdata)->bitmap_len);
	answer->algorithm = ((struct nsec3 *)rrp->rdata)->algorithm;
	answer->flags = ((struct nsec3 *)rrp->rdata)->flags;
	answer->iterations = htons(((struct nsec3 *)rrp->rdata)->iterations);
	answer->saltlen = ((struct nsec3 *)rrp->rdata)->saltlen;
	
	offset += sizeof(*answer);

	if (((struct nsec3 *)rrp->rdata)->saltlen) {
		memcpy(&reply[offset], &((struct nsec3 *)rrp->rdata)->salt, 
				((struct nsec3 *)rrp->rdata)->saltlen);
		offset += ((struct nsec3 *)rrp->rdata)->saltlen;
	}

	somelen = (uint8_t *)&reply[offset];
	*somelen = ((struct nsec3 *)rrp->rdata)->nextlen;

	offset += 1;

	memcpy(&reply[offset], ((struct nsec3 *)rrp->rdata)->next, 
			((struct nsec3 *)rrp->rdata)->nextlen);

	offset += ((struct nsec3 *)rrp->rdata)->nextlen;

	memcpy(&reply[offset], ((struct nsec3 *)rrp->rdata)->bitmap, 
			((struct nsec3 *)rrp->rdata)->bitmap_len);
	offset += ((struct nsec3 *)rrp->rdata)->bitmap_len;

	tmplen = additional_rrsig(name, namelen, DNS_TYPE_NSEC3, rbt, reply, replylen, offset, &retcount, authoritative);

	if (tmplen == 0) {
		return 0;
	}

	offset = tmplen;
	*count = retcount + 1;

out:
	return (offset);

}

/* 
 * ADDITIONAL_DS() - replies a DNS question (*q) on socket (so)
 *			based on additional_mx()
 *
 */

int 
additional_ds(char *name, int namelen, struct rbtree *rbt, char *reply, int replylen, int offset, int *retcount)
{
	int ds_count = 0;
	int tmplen;
	int rroffset = offset;

	struct answer {
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 
		uint16_t key_tag;
		uint8_t algorithm;
		uint8_t digest_type;

	} __attribute__((packed));

	struct answer *answer;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	int tmpcount = 0;

	pack32((char *)retcount, 0);

	if ((rrset = find_rr(rbt, DNS_TYPE_DS)) == NULL)
		return 0;


	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		rroffset = offset;

		if ((offset + namelen) > replylen)
			return 0;

		memcpy(&reply[offset], name, namelen);
		offset += namelen;
		tmplen = compress_label((u_char*)reply, offset, namelen);
		
		if (tmplen != 0) {
			offset = tmplen;
		}	

		if ((offset + sizeof(struct answer)) > replylen) {
			offset = rroffset;
			return 0;
		}

		answer = (struct answer *)&reply[offset];
		
		answer->type = htons(DNS_TYPE_DS);
		answer->class = htons(DNS_CLASS_IN);
		answer->ttl = htonl(rrset->ttl);
		answer->key_tag = htons(((struct ds *)rrp->rdata)->key_tag);
		answer->algorithm = ((struct ds *)rrp->rdata)->algorithm;
		answer->digest_type = ((struct ds *)rrp->rdata)->digest_type; 

		offset += sizeof(struct answer);

		if ((offset + ((struct ds *)rrp->rdata)->digestlen) > replylen) {
			offset = rroffset;
			return 0;
		}

		memcpy(&reply[offset], ((struct ds *)rrp->rdata)->digest,
			((struct ds *)rrp->rdata)->digestlen);

		offset += ((struct ds *)rrp->rdata)->digestlen;

		answer->rdlength = htons(((struct ds *)rrp->rdata)->digestlen + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t));


		tmpcount++;

		ds_count++;
	}

	pack32((char *)retcount, tmpcount);

	return (offset);
}

/*
 * ADDITIONAL_WILDCARD - tag on NS, RRSIG and next closer NSEC3
 */

int 
additional_wildcard(char *qname, int qnamelen, struct rbtree *authority, char *reply, int replylen, int offset, int *count, ddDB *db)
{
        struct answer_ns {
                uint16_t type;
                uint16_t class;
                uint32_t ttl;
                uint16_t rdlength;      /* 12 */
                char ns[0];
        } __attribute__((packed));

	struct answer_nsec3 {
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 /* 12 */
		uint8_t algorithm;
		uint8_t flags;
		uint16_t iterations;
		uint8_t saltlen;
	} __attribute__((packed));

	struct rbtree *rbt0;
	struct answer_ns *answerns;
	struct answer_nsec3 *answer;
	struct rrset *rrset;
	struct rr *rrp;

	int tmplen;
	uint8_t *somelen;
	int retcount;
	int zonenumberx;

	char *name;
	int namelen;

	struct zoneentry *res = NULL;

	if ((rrset = find_rr(authority, DNS_TYPE_NS)) == NULL)
		goto out;

	res = zone_findzone(authority);
	if (res != NULL)
		zonenumberx = res->zonenumber;
	else
		zonenumberx = (uint32_t)-1;

	*count = 0;
		
	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		if (rrp->zonenumber != zonenumberx)
			continue;

		name = authority->zone;
		namelen = authority->zonelen;

		/* check if we go over our return length */
		if ((offset + namelen) > replylen)
			return 0;

		memcpy(&reply[offset], name, namelen);
		offset += namelen;
		tmplen = compress_label((u_char*)reply, offset, namelen);

		if (tmplen != 0) {
			offset = tmplen;
		}

		if ((offset + 10) > replylen) /* struct answer_ns */
			return 0;
		
		answerns = (struct answer_ns *)(&reply[offset]);
		answerns->type = htons(DNS_TYPE_NS);
		answerns->class = htons(DNS_CLASS_IN);
		
		answerns->ttl = htonl(rrset->ttl);

		name = ((struct ns *)rrp->rdata)->nsserver;
		namelen = ((struct ns *)rrp->rdata)->nslen;

		answerns->rdlength = htons(namelen);
		offset += 10;	/* struct answer_ns */

		if ((offset + namelen) > replylen)
			return 0;
		
		memcpy((char *)&answerns->ns, (char *)name, namelen);
		offset += namelen;

		tmplen = compress_label((u_char*)reply, offset, namelen);

		if (tmplen != 0) {
			offset = tmplen;
		}

		/* next round*/
		(*count)++;
	}

	/* tag on an additional rrsig to this */

	tmplen = additional_rrsig(authority->zone, authority->zonelen, DNS_TYPE_NS
		, authority, reply, replylen, offset, &retcount, 1);

	if (tmplen != 0)
		offset = tmplen;
	else
		return 0;

	(*count)++;

	rbt0 = find_nsec3_match_qname_wild(qname, qnamelen, authority, db);
	if (rbt0 == NULL)
		return 0;

	if ((rrset = find_rr(rbt0, DNS_TYPE_NSEC3)) == NULL) {
		dolog(LOG_INFO, "find_rr failed\n");
		return 0;
	}

	rrp = TAILQ_FIRST(&rrset->rr_head);
	if (rrp == NULL)
		return 0;
	
	name = rbt0->zone;
	namelen = rbt0->zonelen;

	/* check if we go over our return length */
	if ((offset + namelen) > replylen)
		return 0;

	memcpy(&reply[offset], name, namelen);
	offset += namelen;
	tmplen = compress_label((u_char*)reply, offset, namelen);

	if (tmplen != 0) {
		offset = tmplen;
	}

	if ((offset + sizeof(struct answer_nsec3)) > replylen) {
		return 0;
	}

	answer = (struct answer_nsec3 *)&reply[offset];
	answer->type = htons(DNS_TYPE_NSEC3);
	answer->class = htons(DNS_CLASS_IN);

	answer->ttl = htonl(rrset->ttl);

	answer->rdlength = htons(6 + ((struct nsec3 *)rrp->rdata)->saltlen + 
			((struct nsec3 *)rrp->rdata)->nextlen + 
			((struct nsec3 *)rrp->rdata)->bitmap_len);
	answer->algorithm = ((struct nsec3 *)rrp->rdata)->algorithm;
	answer->flags = ((struct nsec3 *)rrp->rdata)->flags;
	answer->iterations = htons(((struct nsec3 *)rrp->rdata)->iterations);
	answer->saltlen = ((struct nsec3 *)rrp->rdata)->saltlen;
	
	offset += sizeof(*answer);

	if (((struct nsec3 *)rrp->rdata)->saltlen) {
		memcpy(&reply[offset], &((struct nsec3 *)rrp->rdata)->salt, 
				((struct nsec3 *)rrp->rdata)->saltlen);
		offset += ((struct nsec3 *)rrp->rdata)->saltlen;
	}

	somelen = (uint8_t *)&reply[offset];
	*somelen = ((struct nsec3 *)rrp->rdata)->nextlen;

	offset += 1;

	memcpy(&reply[offset], ((struct nsec3 *)rrp->rdata)->next, 
			((struct nsec3 *)rrp->rdata)->nextlen);

	offset += ((struct nsec3 *)rrp->rdata)->nextlen;

	memcpy(&reply[offset], ((struct nsec3 *)rrp->rdata)->bitmap, 
			((struct nsec3 *)rrp->rdata)->bitmap_len);
	offset += ((struct nsec3 *)rrp->rdata)->bitmap_len;

	(*count)++;

	tmplen = additional_rrsig(name, namelen, DNS_TYPE_NSEC3, rbt0, reply, replylen, offset, &retcount, 1);

	if (tmplen == 0) {
		return 0;
	}

	offset = tmplen;
	(*count)++;

out:
	return (offset);

}
