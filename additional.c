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

int additional_a(char *, int, struct domain *, char *, int, int, int *);
int additional_aaaa(char *, int, struct domain *, char *, int, int, int *);
int additional_mx(char *, int, struct domain *, char *, int, int, int *);
int additional_opt(struct question *, char *, int, int);
int additional_ptr(char *, int, struct domain *, char *, int, int, int *);
int additional_rrsig(char *, int, int, struct domain *, char *, int, int, int);
int additional_nsec(char *, int, int, struct domain *, char *, int, int);
int additional_nsec3(char *, int, int, struct domain *, char *, int, int);

extern int 		compress_label(u_char *, int, int);
extern void *		find_substruct(struct domain *, u_int16_t);

extern int dnssec;

static const char rcsid[] = "$Id: additional.c,v 1.10 2015/09/12 14:08:54 pjp Exp $";


/*
 * ADDITIONAL_A - tag on an additional set of A records to packet
 */

int 
additional_a(char *name, int namelen, struct domain *sd, char *reply, int replylen, int offset, int *retcount)
{
	int a_count;
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
	struct domain_a *sda = NULL;

	*retcount = 0;

	if ((sda = (struct domain_a *)find_substruct(sd, INTERNAL_TYPE_A)) == NULL)
		return -1;
	

	/*
	 * We loop through our sd->a entries starting at the ptr offset
	 * first in the first loop and at the beginning until the ptr
	 * in the last loop.  This will shift answers based on a_ptr.
	 */

	for (a_count = sda->a_ptr; a_count < sda->a_count; a_count++) {
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
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_A]);

		answer->rdlength = htons(sizeof(in_addr_t));

		memcpy((char *)&answer->rdata, (char *)&sda->a[a_count], sizeof(in_addr_t));
		offset += sizeof(struct answer);
		(*retcount)++;

	}

	for (a_count = 0; a_count < sda->a_ptr; a_count++) {
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
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_A]);

		answer->rdlength = htons(sizeof(in_addr_t));

		memcpy((char *)&answer->rdata, (char *)&sda->a[a_count], sizeof(in_addr_t));
		offset += sizeof(struct answer);
		(*retcount)++;
	}


out:
	return (offset);

}

/*
 * ADDITIONAL_AAAA - tag on an additional set of AAAA records to packet
 */

int 
additional_aaaa(char *name, int namelen, struct domain *sd, char *reply, int replylen, int offset, int *retcount)
{
	int aaaa_count;
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
	struct domain_aaaa *sdaaaa = NULL;

	*retcount = 0;

	if ((sdaaaa = (struct domain_aaaa *)find_substruct(sd, INTERNAL_TYPE_AAAA)) == NULL)
		return -1;

	/*
	 * We loop through our sd->aaaa entries starting at the ptr offset
	 * first in the first loop and at the beginning until the ptr
	 * in the last loop.  This will shift answers based on a_ptr.
	 */

	for (aaaa_count = sdaaaa->aaaa_ptr; aaaa_count < sdaaaa->aaaa_count; aaaa_count++) {
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
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_AAAA]);

		answer->rdlength = htons(sizeof(struct in6_addr));

		memcpy((char *)&answer->rdata, (char *)&sdaaaa->aaaa[aaaa_count], sizeof(struct in6_addr));
		offset += sizeof(struct answer);
		(*retcount)++;

	}

	for (aaaa_count = 0; aaaa_count < sdaaaa->aaaa_ptr; aaaa_count++) {
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
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_AAAA]);

		answer->rdlength = htons(sizeof(struct in6_addr));


		memcpy((char *)&answer->rdata, (char *)&sdaaaa->aaaa[aaaa_count], sizeof(struct in6_addr));
		offset += sizeof(struct answer);
		(*retcount)++;
	}


out:
	return (offset);

}

/* 
 * ADDITIONAL_MX() - replies a DNS question (*q) on socket (so)
 *
 */

int 
additional_mx(char *name, int namelen, struct domain *sd, char *reply, int replylen, int offset, int *retcount)
{
	int mx_count;
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
	struct domain_mx *sdmx = NULL;

	*retcount = 0;

	if ((sdmx = (struct domain_mx *)find_substruct(sd, INTERNAL_TYPE_MX)) == NULL)
		return -1;

	/*
	 * We loop through our sdmx->mx entries starting at the ptr offset
	 * first in the first loop and at the beginning until the ptr
	 * in the last loop.  This will shift answers based on mx_ptr.
	 */

	for (mx_count = sdmx->mx_ptr; mx_count < sdmx->mx_count; mx_count++) {
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
		
		answer->type = htons(DNS_TYPE_MX);
		answer->class = htons(DNS_CLASS_IN);
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_MX]);
		answer->mx_priority = htons(sdmx->mx[mx_count].preference);

		offset += sizeof(struct answer);

		if ((offset + sdmx->mx[mx_count].exchangelen) > replylen) {
			offset = rroffset;
			goto out;
		}

		memcpy((char *)&reply[offset], (char *)sdmx->mx[mx_count].exchange, sdmx->mx[mx_count].exchangelen);

		offset += sdmx->mx[mx_count].exchangelen; 
		tmplen = compress_label((u_char*)reply, offset, sdmx->mx[mx_count].exchangelen);
		
		if (tmplen != 0) {
			answer->rdlength = htons((sdmx->mx[mx_count].exchangelen - (offset - tmplen)) + sizeof(u_int16_t));
			offset = tmplen;
		} else
			answer->rdlength = htons(sdmx->mx[mx_count].exchangelen + sizeof(u_int16_t));


		(*retcount)++;

	}

	for (mx_count = 0; mx_count < sdmx->mx_ptr; mx_count++) {
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
		answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_A]);

		offset += sizeof(struct answer);

		if ((offset + sdmx->mx[mx_count].exchangelen) > replylen) {
			offset = rroffset;
			goto out;
		}

		memcpy((char *)&reply[offset], (char *)sdmx->mx[mx_count].exchange, sdmx->mx[mx_count].exchangelen);

		offset += sdmx->mx[mx_count].exchangelen; 
		tmplen = compress_label((u_char *)reply, offset, sdmx->mx[mx_count].exchangelen);
		
		if (tmplen != 0) {

			answer->rdlength = htons((sdmx->mx[mx_count].exchangelen - (offset - tmplen)) + sizeof(u_int16_t));
			offset = tmplen;
		} else
			answer->rdlength = htons(sdmx->mx[mx_count].exchangelen + sizeof(u_int16_t));

		(*retcount)++;
	}


out:
	return (offset);

}

/* 
 * ADDITIONAL_PTR() - replies a DNS question (*q) on socket (so)
 *
 */


int 
additional_ptr(char *name, int namelen, struct domain *sd, char *reply, int replylen, int offset, int *retcount)
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
	struct domain_ptr *sdptr = NULL;

	*retcount = 0;

	if ((sdptr = (struct domain_ptr *)find_substruct(sd, INTERNAL_TYPE_PTR)) == NULL)
		return -1;

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
	
	answer->type = htons(DNS_TYPE_PTR);
	answer->class = htons(DNS_CLASS_IN);
	answer->ttl = htonl(sd->ttl[INTERNAL_TYPE_PTR]);

	offset += sizeof(struct answer);

	if ((offset + sdptr->ptrlen) > replylen) {
		offset = rroffset;
		goto out;
	}

	memcpy((char *)&reply[offset], (char *)sdptr->ptr, sdptr->ptrlen);

	offset += sdptr->ptrlen;
	tmplen = compress_label((u_char*)reply, offset, sdptr->ptrlen);
		
	if (tmplen != 0) {
		answer->rdlength = htons(sdptr->ptrlen - (offset - tmplen));
		offset = tmplen;
	} else
		answer->rdlength = htons(sdptr->ptrlen);


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

	answer->ttl = htonl(rcode); 	/* EXTENDED RCODE */

	answer->rdlen = htons(0);

	offset += sizeof(struct dns_optrr);

out:
	return (offset);

}

/*
 * ADDITIONAL_RRSIG - tag on an additional RRSIG to the answer
 * 		type passed must be an INTERNAL_TYPE!
 */

int 
additional_rrsig(char *name, int namelen, int inttype, struct domain *sd, char *reply, int replylen, int offset, int count)
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
	struct domain_rrsig *sdrr;
	struct rrsig *rrsig;
	int tmplen, rroffset;

	sdrr = (struct domain_rrsig *)find_substruct(sd, INTERNAL_TYPE_RRSIG);
	if (sdrr == NULL) 
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

	if (inttype == INTERNAL_TYPE_DNSKEY) {
		rrsig = &sdrr->rrsig_dnskey[count];
		if (rrsig->algorithm == 0)
			return 0;
	} else if (inttype == INTERNAL_TYPE_DS) {
		rrsig = &sdrr->rrsig_ds[count];
		if (rrsig->algorithm == 0)
			return 0;
	} else {
		rrsig = &sdrr->rrsig[inttype];	
	}

	answer = (struct answer *)&reply[offset];
	answer->type = htons(DNS_TYPE_RRSIG);
	answer->class = htons(DNS_CLASS_IN);
	answer->ttl = htonl(sd->ttl[inttype]);
	answer->type_covered = htons(rrsig->type_covered);
	answer->algorithm = rrsig->algorithm;
	answer->labels = rrsig->labels;
	answer->original_ttl = htonl(rrsig->original_ttl);
	answer->sig_expiration = htonl(rrsig->signature_expiration);	
	answer->sig_inception = htonl(rrsig->signature_inception);
	answer->keytag = htons(rrsig->key_tag);
	
	offset += sizeof(*answer);
	rroffset = offset;

	if ((offset + rrsig->signame_len) > replylen)
		return 0;

	memcpy(&reply[offset], rrsig->signers_name, rrsig->signame_len);

	offset += rrsig->signame_len;
#if 0
	tmplen = compress_label((u_char*)reply, offset, rrsig->signame_len);

	if (tmplen != 0) {
		offset = tmplen;
	}
#endif

	if ((offset + rrsig->signature_len) > replylen)
		return 0;

	memcpy(&reply[offset], rrsig->signature, rrsig->signature_len);
	offset += rrsig->signature_len;

	answer->rdlength = htons((offset - rroffset) + 18);
out:
	return (offset);

}

/*
 * ADDITIONAL_NSEC - tag on an additional NSEC with RRSIG to the answer
 * 		type passed must be an INTERNAL_TYPE!
 */

int 
additional_nsec(char *name, int namelen, int inttype, struct domain *sd, char *reply, int replylen, int offset)
{
	struct answer {
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 /* 12 */
	} __attribute__((packed));

	struct answer *answer;
	struct domain_nsec *sdnsec;
	int tmplen, rroffset;

	sdnsec = (struct domain_nsec *)find_substruct(sd, INTERNAL_TYPE_NSEC);
	if (sdnsec == NULL) 
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
	answer->ttl = htonl(sd->ttl[inttype]);
	answer->rdlength = htons(sdnsec->nsec.ndn_len + 
			sdnsec->nsec.bitmap_len);
	
	offset += sizeof(*answer);

	memcpy(&reply[offset], sdnsec->nsec.next_domain_name,
                sdnsec->nsec.ndn_len);

	offset += sdnsec->nsec.ndn_len;

	memcpy(&reply[offset], sdnsec->nsec.bitmap, sdnsec->nsec.bitmap_len);
	offset += sdnsec->nsec.bitmap_len;

	tmplen = additional_rrsig(name, namelen, INTERNAL_TYPE_NSEC, sd, reply, replylen, offset, 0);

	if (tmplen == 0) {
		goto out;
	}

	offset = tmplen;

out:
	return (offset);

}

/*
 * ADDITIONAL_NSEC3 - tag on an additional NSEC3 with RRSIG to the answer
 * 		type passed must be an INTERNAL_TYPE!
 */

int 
additional_nsec3(char *name, int namelen, int inttype, struct domain *sd, char *reply, int replylen, int offset)
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
	struct domain_nsec3 *sdnsec3;
	int tmplen, rroffset;
	u_int8_t *somelen;

	sdnsec3 = (struct domain_nsec3 *)find_substruct(sd, INTERNAL_TYPE_NSEC3);
	if (sdnsec3 == NULL) 
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
	answer->ttl = htonl(sd->ttl[inttype]);
	answer->rdlength = htons(6 + sdnsec3->nsec3.saltlen + 
			sdnsec3->nsec3.nextlen + sdnsec3->nsec3.bitmap_len);
	answer->algorithm = sdnsec3->nsec3.algorithm;
	answer->flags = sdnsec3->nsec3.flags;
	answer->iterations = htons(sdnsec3->nsec3.iterations);
	answer->saltlen = sdnsec3->nsec3.saltlen;
	
	offset += sizeof(*answer);

	if (sdnsec3->nsec3.saltlen) {
		memcpy(&reply[offset], &sdnsec3->nsec3.salt, sdnsec3->nsec3.saltlen);
		offset += sdnsec3->nsec3.saltlen;
	}

	somelen = (u_int8_t *)&reply[offset];
	*somelen = sdnsec3->nsec3.nextlen;

	offset += 1;

	memcpy(&reply[offset], sdnsec3->nsec3.next, sdnsec3->nsec3.nextlen);

	offset += sdnsec3->nsec3.nextlen;

	memcpy(&reply[offset], sdnsec3->nsec3.bitmap, sdnsec3->nsec3.bitmap_len);
	offset += sdnsec3->nsec3.bitmap_len;

#if 1
	tmplen = additional_rrsig(name, namelen, INTERNAL_TYPE_NSEC3, sd, reply, replylen, offset, 0);

	if (tmplen == 0) {
		goto out;
	}

	offset = tmplen;
#endif

out:
	return (offset);

}
