/*
 * Copyright (c) 2020-2023 Peter J. Philipp <pbug44@delphinusdns.org>
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

#include "ddd-dns.h"
#include "ddd-db.h"
#include "ddd-crypto.h"


extern void     dolog(int, char *, ...);
extern char * expand_compression(u_char *, u_char *, u_char *, u_char *, int *, int);
extern void      pack(char *, char *, int);
extern void     pack16(char *, uint16_t);
extern void     pack32(char *, uint32_t);
extern void     unpack(char *, char *, int);
extern uint16_t unpack16(char *);
extern uint32_t unpack32(char *);
extern int lower_dnsname(char *, int);
extern void	sm_lock(char *, size_t);
extern void	sm_unlock(char *, size_t);
extern size_t	plength(void *, void *);


extern int debug, verbose;
extern int tsig;
extern int dnssec;
extern int cache;

int cacheit(u_char *, u_char *, u_char *, struct imsgbuf *, struct imsgbuf *, struct cfg *);
struct scache * build_cache(u_char *, u_char *, u_char *, uint16_t, char *, int, uint32_t, uint16_t, struct imsgbuf *, struct imsgbuf *, struct cfg *, int);
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
int cache_generic(struct scache *);


/* The following alias helps with bounds checking all input, needed! */

#define BOUNDS_CHECK(cur, begin, rdlen, end) 		do {	\
	if ((plength(cur, begin)) > rdlen) {			\
		return -1;					\
	}							\
	if (cur > end)						\
		return -1;					\
} while (0)

static struct cache_logic supported_cache[] = {
	{ DNS_TYPE_A, 0, cache_a },
	/* { DNS_TYPE_NS, 0, cache_ns }, */
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
build_cache(u_char *payload, u_char *estart, u_char *end, uint16_t rdlen, char *name, int namelen, uint32_t dnsttl, uint16_t dnstype, struct imsgbuf *imsgbuf, struct imsgbuf *bimsgbuf, struct cfg *cfg, int authentic)
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
	ret.cfg = cfg;
	ret.authentic = authentic;

	return (&ret);
}

void
transmit_rr(struct scache *scache, void *rr, int rrsize)
{
	struct rr_imsg ri, *pri;
	int i;

	/* we don't fit */
	if (rrsize > (sizeof(struct rr_imsg) - (sizeof(ri.rri_rr) + sysconf(_SC_PAGESIZE))))
		return;

	memcpy(ri.rri_rr.name, scache->name, sizeof(ri.rri_rr.name));
	ri.rri_rr.namelen = scache->namelen;

	if (lower_dnsname(ri.rri_rr.name, ri.rri_rr.namelen) == -1) {
		dolog(LOG_INFO, "lower_dnsname failed\n");
		return;
	}

	ri.rri_rr.ttl = scache->dnsttl;
	ri.rri_rr.rrtype = scache->rrtype;
	ri.rri_rr.authentic = scache->authentic;	
	

	memcpy(&ri.rri_rr.un, rr, rrsize);
	ri.rri_rr.buflen = rrsize;
	ri.u.s.read = 0;

	/* wait for lock */
	sm_lock(scache->cfg->shm[SM_RESOURCE].shptr, 
		scache->cfg->shm[SM_RESOURCE].shptrsize);
	
	for (pri = (struct rr_imsg *)&scache->cfg->shm[SM_RESOURCE].shptr[0], \
			i = 0; 
			i < SHAREDMEMSIZE; i++, pri++) {
		if (unpack32((char *)&pri->u.s.read) == 1) {
			memcpy(pri, &ri, sizeof(struct rr_imsg) - sysconf(_SC_PAGESIZE));
			pack32((char *)&pri->u.s.read, 0);
			break;
		}
	}
	
	if (i == SHAREDMEMSIZE) {
		dolog(LOG_INFO, "can't find an open slot in sharedmemsize\n");
	}

	sm_unlock(scache->cfg->shm[SM_RESOURCE].shptr, 
			scache->cfg->shm[SM_RESOURCE].shptrsize);
}

int
cacheit(u_char *payload, u_char *estart, u_char *end, struct imsgbuf *imsgbuf, struct imsgbuf *bimsgbuf, struct cfg *cfg)
{
	struct dns_header *dh;
	struct scache *scache;
	char expand[DNS_MAXNAME + 1];
	int elen, i, x;
	int rlen = 0;
	u_char *pb, *p = payload;
	
	uint16_t rrtype;
	uint16_t rdlen;
	uint32_t rrttl;
	
	struct cache_logic *cr;
	int authentic = 0;

	rlen = (plength(end, estart));

	dh = (struct dns_header *)payload;
	p += sizeof(struct dns_header);	/* skip dns_header */

	/* if the data sent back is authentic by the resolver set dnssecok */
	if (ntohs(dh->query) & DNS_AD)
		authentic = 1;
	
	elen = 0,
	memset(&expand, 0, sizeof(expand));
	
	pb = (u_char *)expand_compression(p, estart, end, (u_char *)&expand, &elen, sizeof
(expand));
	if (pb == NULL) {
		dolog(LOG_INFO, "expand_compression() failed in cacheit 1");
		return (-1);
	}

	i = (plength(pb, estart));	
	
	if (i > rlen) {	
		dolog(LOG_INFO, "expand_compression() failed in cacheit 2");
		return (-1);
	}

	rrtype = ntohs(unpack16((char *)pb));	

	/* caching ANY or RRSIG is a nono */
	if (rrtype == DNS_TYPE_ANY || rrtype == DNS_TYPE_RRSIG
		|| rrtype == DNS_TYPE_NS) {
		return -1;
	}
	
	pb += 4;	/* skip type and class */

	for (x = 0; x < ntohs(dh->answer); x++) {
#if DEBUG
		printf("%d out of %d\n", x, ntohs(dh->answer));
#endif
		elen = 0;
		memset(&expand, 0, sizeof(expand));
		pb = (u_char *)expand_compression(pb, estart, end, (u_char *)&expand, &elen, sizeof(expand));
		if (pb == NULL) {
			dolog(LOG_INFO, "expand_compression() failed in cacheit 3");
			return (-1);
		}

		i = (plength(pb, estart));
		
		if (i > rlen) {
			dolog(LOG_INFO, "expand_compression() failed in cacheit 4");
			return (-1);
		}

		/* bounds check the rest of the RR to the RDATA */
		if (pb + 10 >= end) {
			dolog(LOG_INFO, "malformed reply, drop\n");
			return -1;
		}

		rrtype = ntohs(unpack16((char *)pb));
		/* class in here not parsed */
		rrttl = ntohl(unpack32((char *)pb + 4));
		rdlen = ntohs(unpack16((char *)pb + 8));
		
		pb += 10;   /* skip answerd */
	
		scache = build_cache(pb, estart, end, rdlen, expand, elen, rrttl, rrtype, imsgbuf, bimsgbuf, cfg, authentic);
			
		for (cr = supported_cache; cr->rrtype != 0; cr++) {
			if (rrtype == cr->rrtype) {
				if ((*cr->cacheit)(scache) < 0) {
					dolog(LOG_INFO, "error parsing cache with rrtype %d\n", rrtype);
				}
				
				break;
			}
		}
		if (cr->rrtype == 0) {
			cache_generic(scache);
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
	uint16_t tmp;
	uint16_t rdlen = scache->rdlen;
	uint32_t tmp4;
	u_char *p = q;

	memset(&rs, 0, sizeof(struct rrsig));

	BOUNDS_CHECK((q + 2), scache->payload, scache->rdlen, scache->end);
	tmp = unpack16((char *)q);
	rs.type_covered = ntohs(tmp);
	q += 2;
	BOUNDS_CHECK((q + 1), scache->payload, scache->rdlen, scache->end);
	rs.algorithm = *q++;
	BOUNDS_CHECK((q + 1), scache->payload, scache->rdlen, scache->end);
	rs.labels = *q++;
	BOUNDS_CHECK((q + 4), scache->payload, scache->rdlen, scache->end);
	tmp4 = unpack32((char *)q);
	rs.original_ttl = ntohl(tmp4);
	q += 4;
	BOUNDS_CHECK((q + 4), scache->payload, scache->rdlen, scache->end);
	tmp4 = unpack32((char *)q);
	rs.signature_expiration = ntohl(tmp4);
	q += 4;
	BOUNDS_CHECK((q + 4), scache->payload, scache->rdlen, scache->end);
	tmp4 = unpack32((char *)q);
	rs.signature_inception = ntohl(tmp4);
	q += 4;
	BOUNDS_CHECK((q + 2), scache->payload, scache->rdlen, scache->end);
	tmp = unpack16((char *)q);
	rs.key_tag = ntohs(tmp);
	q += 2;
	
	memset(&expand, 0, sizeof(expand));
	save = expand_compression(q, scache->estart, scache->end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		fprintf(stderr, "expanding compression failure 2\n");
		return -1;
	} else  {
		q = (u_char *)save;
	}

	memcpy(&rs.signers_name, expand, elen);
	rs.signame_len = elen;

	rs.signature_len = (rdlen - (plength(q, p)));

	if (rs.signature_len > sizeof(rs.signature)) 
		return -1;
	memcpy(&rs.signature, q, rs.signature_len);
	q += rs.signature_len;

	transmit_rr(scache, (void *)&rs, sizeof(rs));

	return (plength(q, scache->estart));
}

int 
cache_ds(struct scache *scache)
{
	struct ds d;
	uint16_t tmpshort;
	uint16_t rdlen = scache->rdlen;
	u_char *p = scache->payload;
	u_char *q = p;

	memset(&d, 0, sizeof(struct ds));

	BOUNDS_CHECK((scache->payload + 2), q, scache->rdlen, scache->end);
	tmpshort = unpack16((char *)p);
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

	return (plength(p, scache->estart));
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

	return (plength(p, scache->estart));
}

int 
cache_dnskey(struct scache *scache)
{
	struct dnskey dk;
	uint16_t tmpshort;
	uint16_t rdlen = scache->rdlen;
	u_char *p = scache->payload;
	u_char *q = p;


	memset(&dk, 0, sizeof(struct dnskey));

	BOUNDS_CHECK((scache->payload + 2), q, scache->rdlen, scache->end);
	tmpshort = unpack16((char *)p);
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

	return (plength(p, scache->estart));
}


int 
cache_mx(struct scache *scache)
{
	struct smx mx;
	uint16_t mxpriority;
	char *save;
	u_char *p = scache->payload;
	u_char *q = p;
	u_char expand[256];
	int max = sizeof(expand);
	int elen = 0;

	memset(&mx, 0, sizeof(struct smx));

	BOUNDS_CHECK((q + 2), scache->payload, scache->rdlen, scache->end);
	mxpriority = unpack16((char *)q);

	q += 2;

	memset(&expand, 0, sizeof(expand));
	elen = 0;
	save = expand_compression(q, scache->estart, scache->end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		fprintf(stderr, "expanding compression failure 2\n");
		return -1;
	} else  {
		q = (u_char *)save;
	}

	memcpy(&mx.exchange, expand, sizeof(mx.exchange));
	if (lower_dnsname(mx.exchange, elen) == -1) {
		dolog(LOG_INFO, "lower_dnsname failed\n");
		return -1;
	}
	mx.exchangelen = elen;
	mx.preference = ntohs(mxpriority);

	transmit_rr(scache, &mx, sizeof(mx));

	return (plength(q, scache->estart));
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
	uint16_t iter;
	u_char *brr = scache->payload;	/* begin of rd record :-) */

	memset(&n, 0, sizeof(struct nsec3));

	BOUNDS_CHECK((scache->payload + 1), brr, scache->rdlen, scache->end);
	n.algorithm = *p++;
	BOUNDS_CHECK((scache->payload + 1), brr, scache->rdlen, scache->end);
	n.flags = *p++;

	BOUNDS_CHECK((scache->payload + 2), brr, scache->rdlen, scache->end);
	iter = unpack16((char *)p);
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
	
	
	if (((rdlen - (plength(p, brr))) + 1) < 0)
		return -1;

	/* XXX */
	n.bitmap_len = 	(rdlen - (plength(p, brr)));
	if (n.bitmap_len > sizeof(n.bitmap))
		return -1;

	memcpy(&n.bitmap, p, n.bitmap_len);
	p += n.bitmap_len;
	
	transmit_rr(scache, &n, sizeof(n));

	return (plength(p, scache->estart));
}

int
cache_nsec3param(struct scache *scache)
{
	struct nsec3param np;
	uint16_t iter;
	u_char *p = scache->payload;
	u_char *q = scache->payload;


	memset(&np, 0, sizeof(struct nsec3param));

	BOUNDS_CHECK((scache->payload + 1), q, scache->rdlen, scache->end);
	np.algorithm = *p++;
	BOUNDS_CHECK((scache->payload + 1), q, scache->rdlen, scache->end);
	np.flags = *p++;
	BOUNDS_CHECK((scache->payload + 2), q, scache->rdlen, scache->end);
	iter = unpack16((char *)p);
	np.iterations = ntohs(iter);
	p += 2;
	BOUNDS_CHECK((scache->payload + 1), q, scache->rdlen, scache->end);
	np.saltlen = *p++;
	BOUNDS_CHECK((scache->payload + np.saltlen), q, scache->rdlen, scache->end);
	memcpy(&np.salt, p, np.saltlen);
	p += np.saltlen;
	
	transmit_rr(scache, &np, sizeof(np));

	return (plength(p, scache->estart));
}


int
cache_txt(struct scache *scache)
{
	int i;
	uint16_t rdlen = scache->rdlen;
	u_char *p = scache->payload;
	u_char *q = p;

	/* we won't cache txts, for now */
	return -1;

	BOUNDS_CHECK(scache->payload, q, scache->rdlen, scache->end);

	for (i = 0; i < rdlen; i++) {
		if (i % 256 == 0)
			continue;

	}

	p += i;
	
	return (plength(p, scache->estart));
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
		q = (u_char *)save;
	}

	memcpy(&nsi.nsserver, expand, sizeof(nsi.nsserver));
	nsi.nslen = elen;

	transmit_rr(scache, &nsi, sizeof(nsi));

	return (plength(q, scache->estart));
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
	unpack((char *)&ia, (char *)p, sizeof(struct in6_addr));
	p += sizeof(ia);


	memcpy(&aaaa.aaaa, &ia, sizeof(aaaa.aaaa));
	transmit_rr(scache, &aaaa, sizeof(aaaa));

	return (plength(p, scache->estart));
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
	ar.a = unpack32((char *)p);
	p += sizeof(ia);

	transmit_rr(scache, &ar, sizeof(ar));

	return (plength(p, scache->estart));
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

	return (plength(p, scache->estart));
}

int 
cache_srv(struct scache *scache)
{
	uint16_t tmp16;
	struct srv s;
	char *save;
	u_char *p = scache->payload;
	u_char *q = p;
	u_char expand[256];
	int max = sizeof(expand);
	int elen = 0;

	memset(&s, 0, sizeof(struct srv));

	BOUNDS_CHECK((q + 2), scache->payload, scache->rdlen, scache->end);
	tmp16 = unpack16((char *)q);
	s.priority = ntohs(tmp16);
	q += 2;
	BOUNDS_CHECK((q + 2), scache->payload, scache->rdlen, scache->end);
	tmp16 = unpack16((char *)q);
	s.weight = ntohs(tmp16);
	q += 2;
	BOUNDS_CHECK((q + 2), scache->payload, scache->rdlen, scache->end);
	tmp16 = unpack16((char *)q);
	s.port = ntohs(tmp16);
	q += 2;

	memset(&expand, 0, sizeof(expand));
	save = expand_compression(q, scache->estart, scache->end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		fprintf(stderr, "expanding compression failure 2\n");
		return -1;
	} else  {
		q = (u_char *)save;
	}

	memcpy(&s.target, expand, elen);
	s.targetlen = elen;
		
	transmit_rr(scache, (void*)&s, sizeof(s));

	return (plength(q, scache->estart));
}

int 
cache_naptr(struct scache *scache)
{
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
#if 0
	tmp16 = unpack16(q);
	n.order = ntohs(tmp16);
#endif
	q += 2;
	BOUNDS_CHECK((q + 2), scache->payload, scache->rdlen, scache->end);
#if 0
	tmp16 = unpack16(q);
	n.preference = ntohs(tmp16);
#endif
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
		q = (u_char *)save;
	}

	return (plength(q, scache->estart));
}

int 
cache_generic(struct scache *scache)
{
	u_char *p = scache->payload;
	u_char *q = p;

	switch (scache->rrtype) {
	case 18: /* AFSDB */ case 42: /* APL */ case 257: /* CAA */
	case 60: /* CDNSKEY */ case 59: /* CDS */ case 37: /* CERT */
	case 62: /* CSYNC */ case 49: /* DHCID */ case 39: /* DNAME */
	case 108: /* EUI48 */ case 109: /* EUI64 */ case 13: /* HINFO */
	case 55: /* HIP */ case 45: /* IPSECKEY */ case 25: /* KEY */
	case 36: /* KX */ case 29: /* LOC */ case 61: /* OPENPGPKEY */
	case 17: /* RP */ case 24: /* SIG */ case 53: /* SMIMEA */
	case 249: /* TKEY */ case 256: /* URI */ 
		break;
	default:
		/* we don't cache unsupported types */
		return -1;
	}

	transmit_rr(scache, (void*)scache->payload, scache->rdlen);

	q += scache->rdlen;
	return (plength(q, scache->estart));
}
