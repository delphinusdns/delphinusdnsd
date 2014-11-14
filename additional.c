/* 
 * Copyright (c) 2005-2014 Peter J. Philipp
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

extern int compress_label(u_char *, int, int);

static const char rcsid[] = "$Id: additional.c,v 1.1.1.1 2014/11/14 08:09:04 pjp Exp $";


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

	*retcount = 0;

	/*
	 * We loop through our sd->a entries starting at the ptr offset
	 * first in the first loop and at the beginning until the ptr
	 * in the last loop.  This will shift answers based on a_ptr.
	 */

	for (a_count = sd->a_ptr; a_count < sd->a_count; a_count++) {
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
		answer->ttl = htonl(sd->ttl);

		answer->rdlength = htons(sizeof(in_addr_t));

		memcpy((char *)&answer->rdata, (char *)&sd->a[a_count], sizeof(in_addr_t));
		offset += sizeof(struct answer);
		(*retcount)++;

	}

	for (a_count = 0; a_count < sd->a_ptr; a_count++) {
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
		answer->ttl = htonl(sd->ttl);

		answer->rdlength = htons(sizeof(in_addr_t));

		memcpy((char *)&answer->rdata, (char *)&sd->a[a_count], sizeof(in_addr_t));
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

	*retcount = 0;

	/*
	 * We loop through our sd->aaaa entries starting at the ptr offset
	 * first in the first loop and at the beginning until the ptr
	 * in the last loop.  This will shift answers based on a_ptr.
	 */

	for (aaaa_count = sd->aaaa_ptr; aaaa_count < sd->aaaa_count; aaaa_count++) {
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
		answer->ttl = htonl(sd->ttl);

		answer->rdlength = htons(sizeof(struct in6_addr));

		memcpy((char *)&answer->rdata, (char *)&sd->aaaa[aaaa_count], sizeof(struct in6_addr));
		offset += sizeof(struct answer);
		(*retcount)++;

	}

	for (aaaa_count = 0; aaaa_count < sd->aaaa_ptr; aaaa_count++) {
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
		answer->ttl = htonl(sd->ttl);

		answer->rdlength = htons(sizeof(struct in6_addr));


		memcpy((char *)&answer->rdata, (char *)&sd->aaaa[aaaa_count], sizeof(struct in6_addr));
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

	*retcount = 0;

	/*
	 * We loop through our sd->mx entries starting at the ptr offset
	 * first in the first loop and at the beginning until the ptr
	 * in the last loop.  This will shift answers based on mx_ptr.
	 */

	for (mx_count = sd->mx_ptr; mx_count < sd->mx_count; mx_count++) {
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
		answer->ttl = htonl(sd->ttl);
		answer->mx_priority = htons(sd->mx[mx_count].preference);

		offset += sizeof(struct answer);

		if ((offset + sd->mx[mx_count].exchangelen) > replylen) {
			offset = rroffset;
			goto out;
		}

		memcpy((char *)&reply[offset], (char *)sd->mx[mx_count].exchange, sd->mx[mx_count].exchangelen);

		offset += sd->mx[mx_count].exchangelen; 
		tmplen = compress_label((u_char*)reply, offset, sd->mx[mx_count].exchangelen);
		
		if (tmplen != 0) {
			answer->rdlength = htons((sd->mx[mx_count].exchangelen - (offset - tmplen)) + sizeof(u_int16_t));
			offset = tmplen;
		} else
			answer->rdlength = htons(sd->mx[mx_count].exchangelen + sizeof(u_int16_t));


		(*retcount)++;

	}

	for (mx_count = 0; mx_count < sd->mx_ptr; mx_count++) {
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
		answer->ttl = htonl(sd->ttl);

		offset += sizeof(struct answer);

		if ((offset + sd->mx[mx_count].exchangelen) > replylen) {
			offset = rroffset;
			goto out;
		}

		memcpy((char *)&reply[offset], (char *)sd->mx[mx_count].exchange, sd->mx[mx_count].exchangelen);

		offset += sd->mx[mx_count].exchangelen; 
		tmplen = compress_label((u_char *)reply, offset, sd->mx[mx_count].exchangelen);
		
		if (tmplen != 0) {

			answer->rdlength = htons((sd->mx[mx_count].exchangelen - (offset - tmplen)) + sizeof(u_int16_t));
			offset = tmplen;
		} else
			answer->rdlength = htons(sd->mx[mx_count].exchangelen + sizeof(u_int16_t));

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

	*retcount = 0;


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
	answer->ttl = htonl(sd->ttl);

	offset += sizeof(struct answer);

	if ((offset + sd->ptrlen) > replylen) {
		offset = rroffset;
		goto out;
	}

	memcpy((char *)&reply[offset], (char *)sd->ptr, sd->ptrlen);

	offset += sd->ptrlen;
	tmplen = compress_label((u_char*)reply, offset, sd->ptrlen);
		
	if (tmplen != 0) {
		answer->rdlength = htons(sd->ptrlen - (offset - tmplen));
		offset = tmplen;
	} else
		answer->rdlength = htons(sd->ptrlen);


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

	if ((offset + sizeof(struct dns_optrr)) > replylen) {
		goto out;
	}

	answer = (struct dns_optrr *)&reply[offset];

	memset(answer->name, 0, sizeof(answer->name));
	answer->type = htons(DNS_TYPE_OPT);
	answer->class = htons(question->edns0len);
	answer->ttl = htonl(0);

	answer->rdlen = htons(0);

	offset += sizeof(struct dns_optrr);

out:
	return (offset);

}
