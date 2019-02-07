/* 
 * Copyright (c) 2019 Peter J. Philipp
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
 * $Id: raxfr.c,v 1.4 2019/02/07 18:53:12 pjp Exp $
 */

#include "ddd-include.h"
#include "ddd-dns.h"
#include "ddd-db.h"

int raxfr_a(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);
int raxfr_aaaa(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);
int raxfr_cname(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);
int raxfr_ns(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);
int raxfr_ptr(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);
int raxfr_mx(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);
int raxfr_txt(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);
int raxfr_dnskey(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);
int raxfr_rrsig(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);
int raxfr_nsec3param(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);
int raxfr_nsec3(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);
int raxfr_ds(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);
int raxfr_sshfp(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t);

u_int16_t raxfr_skip(FILE *, u_char *, u_char *);
int raxfr_soa(FILE *, u_char *, u_char *, u_char *, struct soa *, int, u_int32_t);
int raxfr_peek(FILE *, u_char *, u_char *, u_char *, int *, int, u_int16_t *, u_int32_t);

static char * expand_compression(u_char *, u_char *, u_char *, u_char *, int *, int);

extern int                     memcasecmp(u_char *, u_char *, int);
extern char * dns_label(char *, int *);
extern char                    *get_dns_type(int, int);
extern int mybase64_encode(u_char const *, size_t, char *, size_t);
extern char *bin2hex(char *, int);
extern char *bitmap2human(char *, int);
extern char *convert_name(char *, int);
extern char *base32hex_encode(u_char *, int);
extern u_int64_t timethuman(time_t);



static char *
expand_compression(u_char *p, u_char *estart, u_char *end, u_char *expand, int *elen, int max)
{
	u_short tlen;
	u_char *save = NULL;
	u_int16_t *offset;

	/* expand name */
	while ((u_char)*p && p <= end) {
		/* test for compression */
		if ((*p & 0xc0) == 0xc0) {
			/* do not allow recursive compress pointers */
			if (! save) {
				save = p + 2;
			}
			offset = (u_int16_t *)p;
			/* do not allow forwards jumping */
			if ((p - estart) <= (ntohs(*offset) & (~0xc000))) {
				return NULL;
			}

			p = (estart + (ntohs(*offset) & (~0xc000)));
		} else {
			if (*elen + 1 >= max) {
				return NULL;
			}
			expand[(*elen)] = *p;
			(*elen)++;
			tlen = *p;
			p++;
			memcpy(&expand[*elen], p, tlen);
			p += tlen;
			if (*elen + tlen >= max) {
				return NULL;
			}
			*elen += tlen;
		}
	}

	if (p > end) {
		return NULL;
	}

	if (save == NULL) {
		p++;
		(*elen)++;
		return (p);
	} else {
		(*elen)++;
		return (save);
	}
}

int
raxfr_peek(FILE *f, u_char *p, u_char *estart, u_char *end, int *rrtype, int soacount, u_int16_t *rdlen, u_int32_t format)
{
	int rrlen;
	char *save;
	char *humanname;
	u_char expand[256];
	u_char *q = p;
	u_int16_t *rtype, *rclass, *rdtmp;
	u_int32_t *rttl;
	int elen = 0;
	int max = sizeof(expand);
	char *hightype;
	int i;

	memset(&expand, 0, sizeof(expand));
	save = expand_compression(q, estart, end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		fprintf(stderr, "expanding compression failure 0\n");
		return -1;
	} else 
		q = save;
	
	rtype = (u_int16_t *)q;
	q += 2;
	rclass = (u_int16_t *)q;
	q += 2;
	rttl = (u_int32_t *)q;
	q += 4;
	rdtmp = (u_int16_t *)q;
	*rdlen = ntohs(*rdtmp);
	q += 2;

	*rrtype = ntohs(*rtype);

	if (*rrtype == 41)	
		goto out;

	humanname = convert_name(expand, elen);
	if (humanname == NULL) {
		return -1;
	}

	hightype = get_dns_type(ntohs(*rtype), 0);

	for (i = 0; i < strlen(hightype); i++)
		hightype[i] = tolower(hightype[i]);

	if (f != NULL)  {

		if (soacount < 1) {
			if ((format & INDENT_FORMAT))
				fprintf(f, "  %s,%s,%d,",  humanname, hightype , ntohl(*rttl));
			else if ((format & ZONE_FORMAT)) {
				fprintf(f, "  %s,%s,%d,",  humanname, hightype , ntohl(*rttl));
			} else
				fprintf(f, "%s,%s,%d,", humanname, hightype , ntohl(*rttl));
		} else {
			if ((format & INDENT_FORMAT))
				fprintf(f, "  %s,%s,%d,",  humanname, hightype , ntohl(*rttl));
			else if ((format & ZONE_FORMAT)) {
				if (*rrtype != DNS_TYPE_SOA) {
					fprintf(f, "  %s,%s,%d,",  humanname, hightype , ntohl(*rttl));
				}
			} else {
				fprintf(f, "%s,%s,%d,", humanname, hightype , ntohl(*rttl));
			}
		}
	}

	free(humanname);

out:
	rrlen = (q - estart);
	return (rrlen);
}

u_int16_t
raxfr_skip(FILE *f, u_char *p, u_char *estart)
{
	u_char *q;
	u_int16_t *rdlen;

	if ((q = p - 2) <= estart)
		return 0;
	
	rdlen = (u_int16_t *)q;
	
	return ((u_int16_t)ntohs(*rdlen));
}

int
raxfr_soa(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, int soacount, u_int32_t format)
{
	u_int32_t *rvalue;
	char *save, *humanname;
	u_char *q = p;
	u_char expand[256];
	int max = sizeof(expand);
	int elen = 0;
	int soalimit = (format & ZONE_FORMAT) ? 1 : 2;

	memset(&expand, 0, sizeof(expand));
	save = expand_compression(q, estart, end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		fprintf(stderr, "expanding compression failure 2\n");
		return -1;
	} else  {
		q = save;
	}

	memset(&mysoa->nsserver, 0, sizeof(mysoa->nsserver));
	memcpy(&mysoa->nsserver, expand, elen);
	mysoa->nsserver_len = elen;
	humanname = convert_name(mysoa->nsserver, mysoa->nsserver_len);
	if (humanname == NULL) {
		return -1;
	}

	if (soacount < soalimit) {
		if (f != NULL)
			fprintf(f, "%s,", humanname);
	}

	free(humanname);

	elen = 0;
	memset(&expand, 0, sizeof(expand));
	save = expand_compression(q, estart, end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		fprintf(stderr, "expanding compression failure 4\n");
		return -1;
	} else  {
		q = save;
	}

	memset(&mysoa->responsible_person, 0, sizeof(mysoa->responsible_person));
	memcpy(&mysoa->responsible_person, expand, elen);
	mysoa->rp_len = elen;

	humanname = convert_name(mysoa->responsible_person, mysoa->rp_len);
	if (humanname == NULL) {
		return -1;
	}

	if (soacount < soalimit) {
		if (f != NULL) 
			fprintf(f, "%s,", humanname);
	}

	free(humanname);

	rvalue = (u_int32_t *)q;
	mysoa->serial = *rvalue;
	q += sizeof(u_int32_t);
	rvalue = (u_int32_t *)q;
	mysoa->refresh = *rvalue;
	q += sizeof(u_int32_t);
	rvalue = (u_int32_t *)q;
	mysoa->retry = *rvalue;
	q += sizeof(u_int32_t);
	rvalue = (u_int32_t *)q;
	mysoa->expire = *rvalue;
	q += sizeof(u_int32_t);
	rvalue = (u_int32_t *)q;
	mysoa->minttl = *rvalue;
	q += sizeof(u_int32_t);
	
	if (soacount < soalimit) {
		if (f != NULL) {
			fprintf(f, "%d,%d,%d,%d,%d\n", ntohl(mysoa->serial),
				ntohl(mysoa->refresh), ntohl(mysoa->retry),
				ntohl(mysoa->expire), ntohl(mysoa->minttl));
		}
	}
	
	
	return (q - estart);
}

int 
raxfr_rrsig(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen)
{
	struct rrsig rs;
	char *save, *humanname;
	u_char *q = p;
	u_char expand[256];
	int max = sizeof(expand);
	int elen = 0;
	u_int16_t *tmp;
	u_int32_t *tmp4;
	int len;
	u_char *b;

	tmp = (u_int16_t *)q;
	rs.type_covered = ntohs(*tmp);
	q += 2;
	rs.algorithm = *q++;
	rs.labels = *q++;
	tmp4 = (u_int32_t *)q;
	rs.original_ttl = ntohl(*tmp4);
	q += 4;
	tmp4 = (u_int32_t *)q;
	rs.signature_expiration = ntohl(*tmp4);
	q += 4;
	tmp4 = (u_int32_t *)q;
	rs.signature_inception = ntohl(*tmp4);
	q += 4;
	tmp = (u_int16_t *)q;
	rs.key_tag = ntohs(*tmp);
	q += 2;
	
	memset(&expand, 0, sizeof(expand));
	save = expand_compression(q, estart, end, (u_char *)&expand, &elen, max);
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

	b = calloc(1, 2 * rs.signature_len);
	if (b == NULL)
		return -1;

	if ((len = mybase64_encode(rs.signature, rs.signature_len, b, rs.signature_len * 2)) < 0) {
		free(b);
		return -1;
	}

	b[len] = '\0';


	humanname = convert_name(expand, elen);
	if (humanname == NULL) {
		free(b);
		return -1;
	}
	if (f != NULL) {
		fprintf(f, "%s,%u,%u,%u,%llu,%llu,%u,%s,\"%s\"\n", 
			get_dns_type(rs.type_covered, 0),
			rs.algorithm, rs.labels, rs.original_ttl, 
			timethuman(rs.signature_expiration), 
			timethuman(rs.signature_inception),
			rs.key_tag, humanname, b);
	}

	free(humanname);
	free(b);

	return (q - estart);
}

int 
raxfr_ds(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen)
{
	struct ds d;
	u_int16_t *tmpshort;

	tmpshort = (u_int16_t *)p;
	d.key_tag = ntohs(*tmpshort);
	p += 2;
	d.algorithm = *p++;
	d.digest_type = *p++;
	
	d.digestlen = (rdlen - 4);
	if (d.digestlen > sizeof(d.digest))
		return -1;
	memcpy(&d.digest, p, d.digestlen);
	p += d.digestlen;


	if (f != NULL) {
		fprintf(f, "%u,%u,%u,\"%s\"\n", d.key_tag, d.algorithm, 
			d.digest_type, base32hex_encode(d.digest, d.digestlen));
	}

	return (p - estart);
}

int 
raxfr_sshfp(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen)
{
	struct sshfp s;
	char *hex;

	s.algorithm = *p++;
	s.fptype  = *p++;
	
	s.fplen = (rdlen - 2);
	if (s.fplen > sizeof(s.fingerprint))
		return -1;

	memcpy(&s.fingerprint, p, s.fplen);
	p += s.fplen;

	hex = bin2hex(s.fingerprint, s.fplen);

	if (f != NULL) {
		fprintf(f, "%u,%u,\"%s\"\n", s.algorithm, s.fptype, hex);
	}

	return (p - estart);
}

int 
raxfr_dnskey(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen)
{
	struct dnskey dk;
	u_int16_t *tmpshort;
	char *b;
	int len;

	tmpshort = (u_int16_t *)p;
	dk.flags = ntohs(*tmpshort);
	p += 2;
	dk.protocol = *p++;
	dk.algorithm = *p++;
	
	dk.publickey_len = (rdlen - 4);
	if (dk.publickey_len > sizeof(dk.public_key))
		return -1;

	memcpy(&dk.public_key, p, dk.publickey_len);
	p += dk.publickey_len;

	b = calloc(1, dk.publickey_len * 2);
	if (b == NULL) {
		perror("calloc");
		return -1;
	}

	if ((len = mybase64_encode(dk.public_key, dk.publickey_len, b, dk.publickey_len * 2)) < 0) {
		free(b);
		return -1;
	}

	b[len] = '\0';

	if (f != NULL) {
		fprintf(f, "%u,%u,%u,\"%s\"\n", dk.flags, dk.protocol, 
			dk.algorithm, b);
	}

	free(b);
	return (p - estart);
}


int 
raxfr_mx(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen)
{
	u_int16_t *mxpriority;
	char *save, *humanname;
	u_char *q = p;
	u_char expand[256];
	int max = sizeof(expand);
	int elen = 0;

	mxpriority = (u_int16_t *)q;

	if (f != NULL)
		fprintf(f, "%u,", ntohs(*mxpriority));

	q += 2;

	memset(&expand, 0, sizeof(expand));
	save = expand_compression(q, estart, end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		fprintf(stderr, "expanding compression failure 2\n");
		return -1;
	} else  {
		q = save;
	}

	humanname = convert_name(expand, elen);
	if (humanname == NULL) {
		return -1;
	}

	if (f != NULL)
		fprintf(f, "%s\n", humanname);

	free(humanname);

	return (q - estart);
}

int 
raxfr_ptr(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen)
{
	return (raxfr_ns(f, p, estart, end, mysoa, rdlen));
}

int
raxfr_nsec3(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen)
{
	struct nsec3 n;
	u_int16_t *iter;
	u_char *brr = p;	/* begin of rd record :-) */

	n.algorithm = *p++;
	n.flags = *p++;

	iter = (u_int16_t *)p;
	n.iterations = ntohs(*iter);
	p += 2;

	n.saltlen = *p++;
	memcpy(&n.salt, p, n.saltlen);
	p += n.saltlen;

	n.nextlen = *p++;
	memcpy(&n.next, p, n.nextlen);
	p += n.nextlen;
	
	n.bitmap_len = 	(rdlen - (p - brr)) + 1;
	if (n.bitmap_len > sizeof(n.bitmap))
		return -1;

	memcpy(&n.bitmap, p, n.bitmap_len);
	p += n.bitmap_len;
	
	bitmap2human(n.bitmap, n.bitmap_len);

	if (f != NULL) {
		fprintf(f, "%u,%u,%u,\"%s\",\"%s\",\"%s\"\n", n.algorithm, 
				n.flags, n.iterations, 
				(n.saltlen == 0 ? "-" : 
					bin2hex(n.salt, n.saltlen)), 
				base32hex_encode(n.next, n.nextlen), 
				bitmap2human(n.bitmap, n.bitmap_len));
	}

	return (p - estart);
}

int
raxfr_nsec3param(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen)
{
	struct nsec3param np;
	u_int16_t *iter;
	char *hex;

	np.algorithm = *p++;
	np.flags = *p++;
	iter = (u_int16_t *)p;
	np.iterations = ntohs(*iter);
	p += 2;
	np.saltlen = *p++;
	memcpy(&np.salt, p, np.saltlen);
	p += np.saltlen;
	
	hex = bin2hex(np.salt, np.saltlen);

	if (f != NULL) {
		fprintf(f, "%u,%u,%u,\"%s\"\n", np.algorithm, np.flags, 
			np.iterations, 
			(np.saltlen == 0 ? "-" : bin2hex(np.salt, np.saltlen)));
	}

	return (p - estart);
}


int
raxfr_txt(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen)
{
	u_int8_t len;
	int i;

	len = *p;
	p++;

	if (f != NULL) 
		fprintf(f, "\"");

	for (i = 0; i < len; i++) {
		if (f != NULL) 
			fprintf(f, "%c", *p);	
		p++;
	}
	if (f != NULL)
		fprintf(f, "\"\n");
	
	
	return (p - estart);
}

int
raxfr_ns(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen)
{
	char *save, *humanname;
	u_char *q = p;
	u_char expand[256];
	int max = sizeof(expand);
	int elen = 0;

	memset(&expand, 0, sizeof(expand));
	save = expand_compression(q, estart, end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		fprintf(stderr, "expanding compression failure 2\n");
		return -1;
	} else  {
		q = save;
	}

	humanname = convert_name(expand, elen);
	if (humanname == NULL) {
		return -1;
	}

	if (f != NULL)
		fprintf(f, "%s\n", humanname);

	free(humanname);

	return (q - estart);
}

int 
raxfr_cname(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen)
{
	return (raxfr_ns(f, p, estart, end, mysoa, rdlen));
}


int
raxfr_aaaa(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen)
{
	char buf[INET6_ADDRSTRLEN];
	struct in6_addr *ia;

	ia = (struct in6_addr *)p;
	inet_ntop(AF_INET6, ia, buf, sizeof(buf));

	if (f != NULL) 
		fprintf(f, "%s\n", buf);

	p += sizeof(*ia);

	return (p - estart);
}

int
raxfr_a(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen)
{
	char buf[INET_ADDRSTRLEN];
	struct in_addr *ia;

	ia = (struct in_addr *)p;

	inet_ntop(AF_INET, ia, buf, sizeof(buf));
	
	if (f != NULL)
		fprintf(f, "%s\n", buf);

	p += sizeof(*ia);

	return (p - estart);
}