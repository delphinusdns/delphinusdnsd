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
 * $Id: additional.c,v 1.19 2019/02/15 15:11:34 pjp Exp $
 */

#include "ddd-include.h"
#include "ddd-dns.h"
#include "ddd-db.h"

int additional_a(char *, int, struct rbtree *, char *, int, int, int *);
int additional_aaaa(char *, int, struct rbtree *, char *, int, int, int *);
int additional_mx(char *, int, struct rbtree *, char *, int, int, int *);
int additional_opt(struct question *, char *, int, int);
int additional_ptr(char *, int, struct rbtree *, char *, int, int, int *);
int additional_rrsig(char *, int, int, struct rbtree *, char *, int, int, int);
int additional_nsec(char *, int, int, struct rbtree *, char *, int, int);
int additional_nsec3(char *, int, int, struct rbtree *, char *, int, int);

extern int 		compress_label(u_char *, int, int);
extern struct rbtree * find_rrset(ddDB *db, char *name, int len);
extern struct rrset * find_rr(struct rbtree *rbt, u_int16_t rrtype);
extern int display_rr(struct rrset *rrset);

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

	*retcount = 0;

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
		answer->ttl = htonl(((struct a *)rrp->rdata)->ttl);

		answer->rdlength = htons(sizeof(in_addr_t));

		memcpy((char *)&answer->rdata, (char *)&((struct a *)rrp->rdata)->a, sizeof(in_addr_t));
		offset += sizeof(struct answer);
		(*retcount)++;

		a_count++;
	}


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

	*retcount = 0;

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
		answer->ttl = htonl(((struct aaaa *)rrp->rdata)->ttl);

		answer->rdlength = htons(sizeof(struct in6_addr));

		memcpy((char *)&answer->rdata, (char *)&((struct aaaa *)rrp->rdata)->aaaa, sizeof(struct in6_addr));
		offset += sizeof(struct answer);
		(*retcount)++;

		aaaa_count++;
	}

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

	*retcount = 0;

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
		answer->ttl = htonl(((struct smx *)rrp->rdata)->ttl);
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


		(*retcount)++;

		mx_count++;
	}

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

	*retcount = 0;

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
	answer->ttl = htonl(((struct ptr *)rrp->rdata)->ttl);

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


	(*retcount)++;

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
	answer->class = htons(question->edns0len);
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
additional_rrsig(char *name, int namelen, int inttype, struct rbtree *rbt, char *reply, int replylen, int offset, int count)
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

	if ((rrset = find_rr(rbt, DNS_TYPE_RRSIG)) == NULL)
		goto out;

	rroffset = offset;

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

	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
		if (inttype != ((struct rrsig *)rrp->rdata)->type_covered)
			continue;

		answer = (struct answer *)&reply[offset];
		answer->type = htons(DNS_TYPE_RRSIG);
		answer->class = htons(DNS_CLASS_IN);
		answer->ttl = htonl(((struct rrsig *)rrp->rdata)->ttl);
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
	}


	answer->rdlength = htons((offset - rroffset) + 18);
out:
	return (offset);

}

/*
 * ADDITIONAL_NSEC - tag on an additional NSEC with RRSIG to the answer
 * 		type passed must be a DNS_TYPE!
 */

int 
additional_nsec(char *name, int namelen, int inttype, struct rbtree *rbt, char *reply, int replylen, int offset)
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
	int tmplen, rroffset;

	if ((rrset = find_rr(rbt, DNS_TYPE_NSEC)) == NULL)
		goto out;

	rrp = TAILQ_FIRST(&rrset->rr_head);
	if (rrp == NULL)
		goto out;
	
	rroffset = offset;

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
	answer->ttl = htonl(((struct nsec *)rrp->rdata)->ttl);
	answer->rdlength = htons(((struct nsec *)rrp->rdata)->ndn_len + 
			((struct nsec *)rrp->rdata)->bitmap_len);
	
	offset += sizeof(*answer);

	memcpy(&reply[offset], ((struct nsec *)rrp->rdata)->next_domain_name,
                ((struct nsec *)rrp->rdata)->ndn_len);

	offset += ((struct nsec *)rrp->rdata)->ndn_len;

	memcpy(&reply[offset], ((struct nsec *)rrp->rdata)->bitmap, 
			((struct nsec *)rrp->rdata)->bitmap_len);
	offset += ((struct nsec *)rrp->rdata)->bitmap_len;

	tmplen = additional_rrsig(name, namelen, DNS_TYPE_NSEC, rbt, reply, replylen, offset, 0);

	if (tmplen == 0) {
		goto out;
	}

	offset = tmplen;

out:
	return (offset);

}

/*
 * ADDITIONAL_NSEC3 - tag on an additional NSEC3 with RRSIG to the answer
 * 		type passed must be an DNS_TYPE!
 */

int 
additional_nsec3(char *name, int namelen, int inttype, struct rbtree *rbt, char *reply, int replylen, int offset)
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

	int tmplen, rroffset;
	u_int8_t *somelen;

	if ((rrset = find_rr(rbt, DNS_TYPE_NSEC3)) == NULL)
		goto out;

	rrp = TAILQ_FIRST(&rrset->rr_head);
	if (rrp == NULL)
		goto out;
	
	rroffset = offset;

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
	answer->ttl = htonl(((struct nsec3 *)rrp->rdata)->ttl);
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

	tmplen = additional_rrsig(name, namelen, DNS_TYPE_NSEC3, rbt, reply, replylen, offset, 0);

	if (tmplen == 0) {
		goto out;
	}

	offset = tmplen;

out:
	return (offset);

}
