/*
 * Copyright (c) 2020 Peter J. Philipp
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
 * $Id: cache.c,v 1.3 2020/07/10 10:42:27 pjp Exp $
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <sys/select.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>

#include <unistd.h>
#include <imsg.h>

#ifdef __linux__
#include <grp.h>
#define __USE_BSD 1
#include <endian.h>
#include <bsd/stdlib.h>
#include <bsd/string.h>
#include <bsd/unistd.h>
#include <bsd/sys/queue.h>
#define __unused
#include <bsd/sys/tree.h>
#include <bsd/sys/endian.h>
#include "imsg.h"
#else /* not linux */
#include <sys/queue.h>
#include <sys/tree.h>
#ifdef __FreeBSD__
#include <sys/endian.h>
#include "imsg.h"
#else
#include <imsg.h>
#endif /* __FreeBSD__ */
#endif /* __linux__ */

#ifndef NTOHS
#include "endian.h"
#endif

#include <openssl/hmac.h>

#include "ddd-dns.h"
#include "ddd-db.h"


extern void     dolog(int, char *, ...);
extern char * expand_compression(u_char *, u_char *, u_char *, u_char *, int *, int);
extern void      pack(char *, char *, int);
extern void     pack16(char *, u_int16_t);
extern void     pack32(char *, u_int32_t);
extern void     unpack(char *, char *, int);
extern uint16_t unpack16(char *);
extern uint32_t unpack32(char *);


extern int debug, verbose;
extern int tsig;
extern int dnssec;
extern int cache;

int cacheit(u_char *, u_char *, u_char *, struct imsgbuf *, struct imsgbuf *, char *);
struct scache * build_cache(u_char *, u_char *, u_char *, uint16_t, char *, int, uint32_t, uint16_t, struct imsgbuf *, struct imsgbuf *, char *);
void transmit_rr(struct scache *, void *, int);


int cache_a(struct scache *);
int cache_aaaa(struct scache *);
int cache_cname(struct scache *);
int cache_ns(struct scache *);
int cache_ptr(struct scache *);
int cache_mx(struct scache *);
int cache_txt(struct scache *);
int cache_dnskey(struct scache *);
int cache_rrsig(struct scache *);
int cache_nsec3param(struct scache *);
int cache_nsec3(struct scache *);
int cache_ds(struct scache *);
int cache_sshfp(struct scache *);
int cache_tlsa(struct scache *);
int cache_srv(struct scache *);
int cache_naptr(struct scache *);
int cache_soa(struct scache *);


/* The following alias helps with bounds checking all input, needed! */

#define BOUNDS_CHECK(cur, begin, rdlen, end) 		do {	\
	if ((cur - begin) > rdlen) {				\
		return -1;					\
	}							\
	if (cur > end)						\
		return -1;					\
} while (0)

static struct cache_logic supported_cache[] = {
	{ DNS_TYPE_A, 0, cache_a },
	{ DNS_TYPE_NS, 0, cache_ns },
	{ DNS_TYPE_MX, 0, cache_mx },
	{ DNS_TYPE_PTR, 0, cache_ptr },
	{ DNS_TYPE_AAAA, 0, cache_aaaa },
	{ DNS_TYPE_CNAME, 0, cache_cname },
	/* { DNS_TYPE_TXT, 0, cache_txt }, */
	{ DNS_TYPE_DNSKEY, 1, cache_dnskey },
	{ DNS_TYPE_RRSIG, 1, cache_rrsig },
	{ DNS_TYPE_NSEC3PARAM, 1, cache_nsec3param },
	{ DNS_TYPE_NSEC3, 1, cache_nsec3 },
	{ DNS_TYPE_DS, 1, cache_ds },
	{ DNS_TYPE_SSHFP, 0, cache_sshfp },
	{ DNS_TYPE_TLSA, 0, cache_tlsa },
	{ DNS_TYPE_SRV, 0, cache_srv },
	/* { DNS_TYPE_NAPTR, 0, cache_naptr }, */
	{ 0, 0, NULL }
};




struct scache *
build_cache(u_char *payload, u_char *estart, u_char *end, uint16_t rdlen, char *name, int namelen, uint32_t dnsttl, uint16_t dnstype, struct imsgbuf *imsgbuf, struct imsgbuf *bimsgbuf, char *ptr)
{
	static struct scache ret;

	memset(&ret, 0, sizeof(ret));
	ret.payload = payload;
	ret.estart = estart;
	ret.end = end;
	ret.rdlen = rdlen;
	ret.name = name;
	ret.namelen = namelen;
	ret.dnsttl = dnsttl;
	ret.rrtype = dnstype;
	ret.imsgbuf = imsgbuf;
	ret.bimsgbuf = bimsgbuf;
	ret.shared = ptr;

	return (&ret);
}

void
transmit_rr(struct scache *scache, void *rr, int rrsize)
{
	struct rr_imsg ri, *pri;
	int offset, i;

	memcpy(ri.imsg.rr.name, scache->name, sizeof(ri.imsg.rr.name));
	ri.imsg.rr.namelen = scache->namelen;

	ri.imsg.rr.ttl = scache->dnsttl;
	ri.imsg.rr.rrtype = scache->rrtype;

	memcpy(&ri.imsg.rr.un, rr, rrsize);
	ri.imsg.rr.buflen = rrsize;
	ri.read = 0;

	/* wait for lock */
	while (scache->shared[0] == '*') {
		usleep(arc4random() % 300);
	}

	scache->shared[0] = '*'; /* nice semaphore eh? */

	
	for (pri = (struct rr_imsg *)&scache->shared[16], i = 0; 
			i < SHAREDMEMSIZE; i++, pri++) {
		if (unpack32((char *)&pri->read) == 1) {
			memcpy(pri, &ri, sizeof(struct rr_imsg));
			pack32((char *)&pri->read, 0);
			break;
		}
	}
	
	if (i == SHAREDMEMSIZE) {
		dolog(LOG_INFO, "can't find an open slot in sharedmemsize\n");
	}

	scache->shared[0] = ' ';	/* release */
	
	offset = i;


}

int
cacheit(u_char *payload, u_char *estart, u_char *end, struct imsgbuf *imsgbuf, struct imsgbuf *bimsgbuf, char *ptr)
{
	struct dns_header *dh;
	struct scache *scache;
	char expand[DNS_MAXNAME + 1];
	int elen, i, x;
	int rlen = (end - estart);
	u_char *pb, *p = payload;
	
	uint16_t rrtype;
	uint16_t rdlen;
	uint32_t rrttl;
	
	struct cache_logic *cr;

	dh = (struct dns_header *)payload;
	p += sizeof(struct dns_header);	/* skip dns_header */
	
	elen = 0,
	memset(&expand, 0, sizeof(expand));
	
	pb = expand_compression(p, estart, end, (u_char *)&expand, &elen, sizeof
(expand));
	if (pb == NULL) {
		dolog(LOG_INFO, "expand_compression() failed in cacheit 1");
		return (-1);
	}

	i = (pb - estart);	
	
	if (i > rlen) {	
		dolog(LOG_INFO, "expand_compression() failed in cacheit 2");
		return (-1);
	}

	rrtype = ntohs(unpack16(pb));	

	/* caching and ANY question is a nono */
	if (rrtype == DNS_TYPE_ANY) {
		return -1;
	}
	
	pb += 4;	/* skip type and class */

	for (x = 0; x < ntohs(dh->answer); x++) {
		printf("%d out of %d\n", x, ntohs(dh->answer));
		elen = 0;
		memset(&expand, 0, sizeof(expand));
		pb = expand_compression(pb, estart, end, (u_char *)&expand, &elen, sizeof(expand));
		if (pb == NULL) {
			dolog(LOG_INFO, "expand_compression() failed in cacheit 3");
			return (-1);
		}

		i = (pb - estart);
		
		if (i > rlen) {
			dolog(LOG_INFO, "expand_compression() failed in cacheit 4");
			return (-1);
		}

		/* bounds check the rest of the RR to the RDATA */
		if (pb + 10 >= end) {
			dolog(LOG_INFO, "malformed reply, drop\n");
			return -1;
		}

		rrtype = ntohs(unpack16(pb));
		/* class in here not parsed */
		rrttl = ntohl(unpack32(pb + 4));
		rdlen = ntohs(unpack16(pb + 8));
		
		pb += 10;   /* skip answerd */
	
		scache = build_cache(pb, estart, end, rdlen, expand, elen, rrttl, rrtype, imsgbuf, bimsgbuf, ptr);
			
		for (cr = supported_cache; cr->rrtype != 0; cr++) {
			if (rrtype == cr->rrtype) {
				if ((*cr->cacheit)(scache) < 0) {
					dolog(LOG_INFO, "error parsing cache with rrtype %d\n", rrtype);
				}
				
				break;
			}
		}

		pb += rdlen;

	} /* for(x ... */
			
	i = 42;
	if (imsg_compose(bimsgbuf, IMSG_RR_ATTACHED, 0, 0, -1, &i, sizeof(int)) != 1) {
		dolog(LOG_INFO, "imsg_compose failed: %s\n", strerror(errno));
	}

	if (msgbuf_write(&bimsgbuf->w) == -1)
		dolog(LOG_ERR, "msgbuf_write: %s\n", strerror(errno));
		
	return (0);	
}

int 
cache_rrsig(struct scache *scache)
{
	struct rrsig rs;
	char *save;
	u_char *q = scache->payload;
	u_char expand[256];
	int max = sizeof(expand);
	int elen = 0;
	u_int16_t tmp;
	uint16_t rdlen = scache->rdlen;
	u_int32_t tmp4;
	u_char *p = q;

	memset(&rs, 0, sizeof(struct rrsig));

	BOUNDS_CHECK((q + 2), scache->payload, scache->rdlen, scache->end);
	tmp = unpack16(q);
	rs.type_covered = ntohs(tmp);
	q += 2;
	BOUNDS_CHECK((q + 1), scache->payload, scache->rdlen, scache->end);
	rs.algorithm = *q++;
	BOUNDS_CHECK((q + 1), scache->payload, scache->rdlen, scache->end);
	rs.labels = *q++;
	BOUNDS_CHECK((q + 4), scache->payload, scache->rdlen, scache->end);
	tmp4 = unpack32(q);
	rs.original_ttl = ntohl(tmp4);
	q += 4;
	BOUNDS_CHECK((q + 4), scache->payload, scache->rdlen, scache->end);
	tmp4 = unpack32(q);
	rs.signature_expiration = ntohl(tmp4);
	q += 4;
	BOUNDS_CHECK((q + 4), scache->payload, scache->rdlen, scache->end);
	tmp4 = unpack32(q);
	rs.signature_inception = ntohl(tmp4);
	q += 4;
	BOUNDS_CHECK((q + 2), scache->payload, scache->rdlen, scache->end);
	tmp = unpack16(q);
	rs.key_tag = ntohs(tmp);
	q += 2;
	
	memset(&expand, 0, sizeof(expand));
	save = expand_compression(q, scache->estart, scache->end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		fprintf(stderr, "expanding compression failure 2\n");
		return -1;
	} else  {
		q = save;
	}

	memcpy(&rs.signers_name, expand, elen);
	rs.signame_len = elen;

	rs.signature_len = (rdlen - (q - p));

	if (rs.signature_len > sizeof(rs.signature)) 
		return -1;
	memcpy(&rs.signature, q, rs.signature_len);
	q += rs.signature_len;

	transmit_rr(scache, (void *)&rs, sizeof(rs));

	return (q - scache->estart);
}

int 
cache_ds(struct scache *scache)
{
	struct ds d;
	u_int16_t tmpshort;
	uint16_t rdlen = scache->rdlen;
	u_char *p = scache->payload;
	u_char *q = p;

	memset(&d, 0, sizeof(struct ds));

	BOUNDS_CHECK((scache->payload + 2), q, scache->rdlen, scache->end);
	tmpshort = unpack16(p);
	d.key_tag = ntohs(tmpshort);
	p += 2;
	BOUNDS_CHECK((scache->payload + 1), q, scache->rdlen, scache->end);
	d.algorithm = *p++;
	BOUNDS_CHECK((scache->payload + 1), q, scache->rdlen, scache->end);
	d.digest_type = *p++;

	if ((rdlen - 4) < 0)
		return -1;
	d.digestlen = (rdlen - 4);
	if (d.digestlen > sizeof(d.digest))
		return -1;
	memcpy(&d.digest, p, d.digestlen);
	p += d.digestlen;


	transmit_rr(scache, &d, sizeof(d));

	return (p - scache->estart);
}

int 
cache_sshfp(struct scache *scache)
{
	struct sshfp s;
	uint16_t rdlen = scache->rdlen;
	u_char *p = scache->payload;
	u_char *q = p;

	memset(&s, 0, sizeof(struct sshfp));

	BOUNDS_CHECK((scache->payload + 1), q, scache->rdlen, scache->end);
	s.algorithm = *p++;
	BOUNDS_CHECK((scache->payload + 1), q, scache->rdlen, scache->end);
	s.fptype  = *p++;
	
	if (rdlen - 2 < 0)
		return -1;

	s.fplen = (rdlen - 2);
	if (s.fplen > sizeof(s.fingerprint))
		return -1;

	memcpy(&s.fingerprint, p, s.fplen);
	p += s.fplen;

	transmit_rr(scache, &s, sizeof(s));

	return (p - scache->estart);
}

int 
cache_dnskey(struct scache *scache)
{
	struct dnskey dk;
	u_int16_t tmpshort;
	uint16_t rdlen = scache->rdlen;
	u_char *p = scache->payload;
	u_char *q = p;


	memset(&dk, 0, sizeof(struct dnskey));

	BOUNDS_CHECK((scache->payload + 2), q, scache->rdlen, scache->end);
	tmpshort = unpack16(p);
	dk.flags = ntohs(tmpshort);
	p += 2;
	BOUNDS_CHECK((scache->payload + 1), q, scache->rdlen, scache->end);
	dk.protocol = *p++;
	BOUNDS_CHECK((scache->payload + 1), q, scache->rdlen, scache->end);
	dk.algorithm = *p++;
	
	if (rdlen - 4 < 0)
		return -1;
	dk.publickey_len = (rdlen - 4);
	if (dk.publickey_len > sizeof(dk.public_key))
		return -1;

	memcpy(&dk.public_key, p, dk.publickey_len);
	p += dk.publickey_len;

	transmit_rr(scache, &dk, sizeof(dk));

	return (p - scache->estart);
}


int 
cache_mx(struct scache *scache)
{
	struct smx mx;
	u_int16_t mxpriority;
	char *save;
	u_char *p = scache->payload;
	u_char *q = p;
	u_char expand[256];
	int max = sizeof(expand);
	int elen = 0;

	memset(&mx, 0, sizeof(struct smx));

	BOUNDS_CHECK((q + 2), scache->payload, scache->rdlen, scache->end);
	mxpriority = unpack16(q);

	q += 2;

	memset(&expand, 0, sizeof(expand));
	save = expand_compression(q, scache->estart, scache->end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		fprintf(stderr, "expanding compression failure 2\n");
		return -1;
	} else  {
		q = save;
	}

	memcpy(&mx.exchange, expand, sizeof(mx.exchange));
	mx.exchangelen = elen;
	mx.preference = mxpriority;

	transmit_rr(scache, &mx, sizeof(mx));

	return (q - scache->estart);
}

int 
cache_ptr(struct scache *scache)
{
	return (cache_ns(scache));
}

int
cache_nsec3(struct scache *scache)
{
	struct nsec3 n;
	u_char *p = scache->payload;
	uint16_t rdlen = scache->rdlen;
	u_int16_t iter;
	u_char *brr = scache->payload;	/* begin of rd record :-) */

	memset(&n, 0, sizeof(struct nsec3));

	BOUNDS_CHECK((scache->payload + 1), brr, scache->rdlen, scache->end);
	n.algorithm = *p++;
	BOUNDS_CHECK((scache->payload + 1), brr, scache->rdlen, scache->end);
	n.flags = *p++;

	BOUNDS_CHECK((scache->payload + 2), brr, scache->rdlen, scache->end);
	iter = unpack16(p);
	n.iterations = ntohs(iter);
	p += 2;

	BOUNDS_CHECK((scache->payload + 1), brr, scache->rdlen, scache->end);
	n.saltlen = *p++;
	memcpy(&n.salt, p, n.saltlen);
	p += n.saltlen;

	BOUNDS_CHECK((scache->payload + 1), brr, scache->rdlen, scache->end);
	n.nextlen = *p++;
	memcpy(&n.next, p, n.nextlen);
	p += n.nextlen;
	
	
	if (((rdlen - (p - brr)) + 1) < 0)
		return -1;

	/* XXX */
	n.bitmap_len = 	(rdlen - (p - brr));
	if (n.bitmap_len > sizeof(n.bitmap))
		return -1;

	memcpy(&n.bitmap, p, n.bitmap_len);
	p += n.bitmap_len;
	
	transmit_rr(scache, &n, sizeof(n));

	return (p - scache->estart);
}

int
cache_nsec3param(struct scache *scache)
{
	struct nsec3param np;
	u_int16_t iter;
	u_char *p = scache->payload;
	u_char *q = scache->payload;


	memset(&np, 0, sizeof(struct nsec3param));

	BOUNDS_CHECK((scache->payload + 1), q, scache->rdlen, scache->end);
	np.algorithm = *p++;
	BOUNDS_CHECK((scache->payload + 1), q, scache->rdlen, scache->end);
	np.flags = *p++;
	BOUNDS_CHECK((scache->payload + 2), q, scache->rdlen, scache->end);
	iter = unpack16(p);
	np.iterations = ntohs(iter);
	p += 2;
	BOUNDS_CHECK((scache->payload + 1), q, scache->rdlen, scache->end);
	np.saltlen = *p++;
	BOUNDS_CHECK((scache->payload + np.saltlen), q, scache->rdlen, scache->end);
	memcpy(&np.salt, p, np.saltlen);
	p += np.saltlen;
	
	transmit_rr(scache, &np, sizeof(np));

	return (p - scache->estart);
}


int
cache_txt(struct scache *scache)
{
	u_int8_t len;
	int i;
	uint16_t rdlen = scache->rdlen;
	u_char *p = scache->payload;
	u_char *q = p;

	/* we won't cache txts, for now */
	return -1;

	BOUNDS_CHECK(scache->payload, q, scache->rdlen, scache->end);
	len = rdlen;

	for (i = 0; i < rdlen; i++) {
		if (i % 256 == 0)
			continue;

	}

	p += i;
	
	return (p - scache->estart);
}

int
cache_ns(struct scache *scache)
{
	struct ns nsi;
	char *save;
	u_char *p = scache->payload;
	u_char *q = p;
	u_char expand[256];
	int max = sizeof(expand);
	int elen = 0;

	memset(&nsi, 0, sizeof(struct ns));
	memset(&expand, 0, sizeof(expand));
	save = expand_compression(q, scache->estart, scache->end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		fprintf(stderr, "expanding compression failure 2\n");
		return -1;
	} else  {
		q = save;
	}

	memcpy(&nsi.nsserver, expand, sizeof(nsi.nsserver));
	nsi.nslen = elen;

	transmit_rr(scache, &nsi, sizeof(nsi));

	return (q - scache->estart);
}

int 
cache_cname(struct scache *scache)
{
	return (cache_ns(scache));
}


int
cache_aaaa(struct scache *scache)
{
	struct aaaa aaaa;
	struct in6_addr ia;
	u_char *p = scache->payload;
	u_char *q = p;

	memset(&aaaa, 0, sizeof(struct aaaa));

	BOUNDS_CHECK((scache->payload + sizeof(ia)), q, scache->rdlen, scache->end);
	unpack((char *)&ia, p, sizeof(struct in6_addr));
	p += sizeof(ia);


	memcpy(&aaaa.aaaa, &ia, sizeof(aaaa.aaaa));
	transmit_rr(scache, &aaaa, sizeof(aaaa));

	return (p - scache->estart);
}

int
cache_a(struct scache *scache)
{
	struct in_addr ia;
	u_char *p = scache->payload;
	u_char *q = p;
	struct a ar;

	memset(&ar, 0, sizeof(ar));

	BOUNDS_CHECK((scache->payload + sizeof(ia)), q, scache->rdlen, scache->end);
	ar.a = unpack32(p);
	p += sizeof(ia);

	// memcpy(&ar.a, &ia, sizeof(ar.a));

	transmit_rr(scache, &ar, sizeof(ar));

	return (p - scache->estart);
}

int 
cache_tlsa(struct scache *scache)
{
	struct tlsa t;
	u_char *p = scache->payload;
	u_char *q = p;
	uint16_t rdlen = scache->rdlen;

	memset(&t, 0, sizeof(struct tlsa));

	BOUNDS_CHECK((scache->payload + 1), q, scache->rdlen, scache->end);
	t.usage = *p++;
	BOUNDS_CHECK((scache->payload + 1), q, scache->rdlen, scache->end);
	t.selector = *p++;
	BOUNDS_CHECK((scache->payload + 1), q, scache->rdlen, scache->end);
	t.matchtype = *p++;

	if (rdlen - 3 < 0)
		return -1;

	t.datalen = (rdlen - 3);
	
	if (t.datalen > sizeof(t.data))
		return -1;

	memcpy(&t.data, p, t.datalen);
	p += t.datalen;


	transmit_rr(scache, &t, sizeof(t));

	return (p - scache->estart);
}

int 
cache_srv(struct scache *scache)
{
	u_int16_t tmp16;
	struct srv s;
	char *save;
	u_char *p = scache->payload;
	u_char *q = p;
	u_char expand[256];
	int max = sizeof(expand);
	int elen = 0;

	memset(&s, 0, sizeof(struct srv));

	BOUNDS_CHECK((q + 2), scache->payload, scache->rdlen, scache->end);
	tmp16 = unpack16(q);
	s.priority = ntohs(tmp16);
	q += 2;
	BOUNDS_CHECK((q + 2), scache->payload, scache->rdlen, scache->end);
	tmp16 = unpack16(q);
	s.weight = ntohs(tmp16);
	q += 2;
	BOUNDS_CHECK((q + 2), scache->payload, scache->rdlen, scache->end);
	tmp16 = unpack16(q);
	s.port = ntohs(tmp16);
	q += 2;

	memset(&expand, 0, sizeof(expand));
	save = expand_compression(q, scache->estart, scache->end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		fprintf(stderr, "expanding compression failure 2\n");
		return -1;
	} else  {
		q = save;
	}

	memcpy(&s.target, expand, sizeof(s.target));
		
	transmit_rr(scache, (void*)&s, sizeof(s));

	return (q - scache->estart);
}

int 
cache_naptr(struct scache *scache)
{
	u_int16_t tmp16;
	struct naptr n;
	char *save;;
	u_char *p = scache->payload;
	u_char *q = p;
	u_char expand[256];
	int max = sizeof(expand);
	int elen = 0;
	int len, i;

	/* we won't cache naptr either for now */
	return -1;
	BOUNDS_CHECK((q + 2), scache->payload, scache->rdlen, scache->end);
	tmp16 = unpack16(q);
	n.order = ntohs(tmp16);
	q += 2;
	BOUNDS_CHECK((q + 2), scache->payload, scache->rdlen, scache->end);
	tmp16 = unpack16(q);
	n.preference = ntohs(tmp16);
	q += 2;

	
	/* flags */
	BOUNDS_CHECK((q + 1), scache->payload, scache->rdlen, scache->end);
	len = *q;
	q++;

	/* services */
	BOUNDS_CHECK((q + 1), scache->payload, scache->rdlen, scache->end);
	len = *q;
	q++;

	/* regexp */
	BOUNDS_CHECK((q + 1), scache->payload, scache->rdlen, scache->end);
	len = *q;
	q++;

	for (i = 0; i < len; i++) {
		BOUNDS_CHECK((q + 1), scache->payload, scache->rdlen, scache->end);
	}

	memset(&expand, 0, sizeof(expand));
	save = expand_compression(q, scache->estart, scache->end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		fprintf(stderr, "expanding compression failure 2\n");
		return -1;
	} else  {
		q = save;
	}

	return (q - scache->estart);
}
