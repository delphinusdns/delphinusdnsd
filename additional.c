/* 
 * Copyright (c) 2005-2018 Peter J. Philipp
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
 * $Id: additional.c,v 1.40 2020/09/30 10:07:31 pjp Exp $
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
#ifdef __FreeBSD__
#include <sys/endian.h>
#endif /* __FreeBSD__ */
#endif /* __linux__ */


#include "ddd-dns.h"
#include "ddd-db.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

int additional_a(char *, int, struct rbtree *, char *, int, int, int *);
int additional_aaaa(char *, int, struct rbtree *, char *, int, int, int *);
int additional_mx(char *, int, struct rbtree *, char *, int, int, int *);
int additional_ds(char *, int, struct rbtree *, char *, int, int, int *);
int additional_opt(struct question *, char *, int, int);
int additional_ptr(char *, int, struct rbtree *, char *, int, int, int *);
int additional_rrsig(char *, int, int, struct rbtree *, char *, int, int, int *, int);
int additional_nsec(char *, int, int, struct rbtree *, char *, int, int, int *, int);
int additional_nsec3(char *, int, int, struct rbtree *, char *, int, int, int *, int);
int additional_tsig(struct question *, char *, int, int, int, int, HMAC_CTX *);

extern void 	pack(char *, char *, int);
extern void 	pack32(char *, u_int32_t);
extern void 	pack16(char *, u_int16_t);
extern void 	pack8(char *, u_int8_t);
extern uint32_t unpack32(char *);
extern uint16_t unpack16(char *);
extern void 	unpack(char *, char *, int);

extern int 		compress_label(u_char *, int, int);
extern struct rbtree * find_rrset(ddDB *db, char *name, int len);
extern struct rrset * find_rr(struct rbtree *rbt, u_int16_t rrtype);
extern int display_rr(struct rrset *rrset);
extern int  find_tsig_key(char *, int, char *, int);
extern void      dolog(int, char *, ...);



extern int dnssec;


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
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 /* 12 */
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
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 
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
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 
		u_int16_t mx_priority;
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
			answer->rdlength = htons((((struct smx *)rrp->rdata)->exchangelen - (offset - tmplen)) + sizeof(u_int16_t));
			offset = tmplen;
		} else
			answer->rdlength = htons(((struct smx *)rrp->rdata)->exchangelen + sizeof(u_int16_t));


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
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 
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
additional_tsig(struct question *question, char *reply, int replylen, int offset, int request, int envelope, HMAC_CTX *tsigctx) 
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

			HMAC_Update(tsigctx, tsig_timers, ttlen);

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
		HMAC_Update(tsigctx, reply, offset);
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
		answer->timefudge = htobe64(((u_int64_t)tmp64 << 16) | (DEFAULT_TSIG_FUDGE & 0xffff));
#else
		answer->timefudge = htobe64(((u_int64_t)now << 16) | (DEFAULT_TSIG_FUDGE & 0xffff));
#endif
	} else {
		if (request == 0 || envelope == 1) {
			answer->timefudge = question->tsig.tsig_timefudge;
		} else {
#ifdef __linux__
			answer->timefudge = htobe64((tmp64 << 16) | (DEFAULT_TSIG_FUDGE & 0xffff));
#else
			answer->timefudge = htobe64((now << 16) | (DEFAULT_TSIG_FUDGE & 0xffff));
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
		ppanswer->timefudge = htobe64(((u_int64_t)tmp64 << 16) | (DEFAULT_TSIG_FUDGE & 0xffff));
#else
		ppanswer->timefudge = htobe64(((u_int64_t)now << 16) | (DEFAULT_TSIG_FUDGE & 0xffff));
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
			timers->timefudge = htobe64(((u_int64_t)now << 16) | (DEFAULT_TSIG_FUDGE & 0xffff));
			ttlen += 8;
			HMAC_Update(tsigctx, (const unsigned char *)tsig_timers, ttlen);
		}
		

		/* we need it for the else */
		if (envelope % 89 == 0 || envelope == -2) {
			macsize = DNS_HMAC_SHA256_SIZE;
			HMAC_Final(tsigctx, (unsigned char *)&answer->mac[0], (u_int *)&macsize);
			memcpy(question->tsig.tsigmac, &answer->mac[0], macsize);
			priordigest = 1;
		} else
			offset = rollback;

	} else {

		if (question->tsig.tsigerrorcode == DNS_BADTIME) {
			HMAC(EVP_sha256(), tsigkey, tsignamelen, 
				(unsigned char *)pseudo_packet, ppoffset, 
				(unsigned char *)&answer->mac[0], (u_int *)&macsize);
		} else if (question->tsig.tsigerrorcode) {
			memset(&answer->mac[0], 0, question->tsig.tsigmaclen);
		} else {
			HMAC(EVP_sha256(), tsigkey, tsignamelen, 
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
additional_opt(struct question *question, char *reply, int replylen, int offset)
{
	struct dns_optrr *answer;
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
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 /* 12 */
		u_int16_t type_covered;
		u_int8_t algorithm;
		u_int8_t labels;
		u_int32_t original_ttl;
		u_int32_t sig_expiration;
		u_int32_t sig_inception;
		u_int16_t keytag;
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
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 /* 12 */
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
	struct rrset *rrset;
	struct rr *rrp;

	int tmplen;
	u_int8_t *somelen;
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

	somelen = (u_int8_t *)&reply[offset];
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
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 
		u_int16_t key_tag;
		u_int8_t algorithm;
		u_int8_t digest_type;

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

		answer->rdlength = htons(((struct ds *)rrp->rdata)->digestlen + sizeof(u_int16_t) + sizeof(u_int8_t) + sizeof(u_int8_t));


		tmpcount++;

		ds_count++;
	}

	pack32((char *)retcount, tmpcount);

	return (offset);
}
