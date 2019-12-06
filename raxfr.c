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
 * $Id: raxfr.c,v 1.44 2019/12/06 16:28:35 pjp Exp $
 */

#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
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
#include "imsg.h"
#include "endian.h"
#else /* not linux */
#include <sys/queue.h>
#include <sys/tree.h>
#ifdef __FreeBSD__
#include "imsg.h"
#include "endian.h"
#else
#include <imsg.h>
#endif /* __FreeBSD__ */
#endif /* __linux__ */

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/hmac.h>

#include "ddd-dns.h"
#include "ddd-db.h"


#define MY_SOCK_TIMEOUT		-10

SLIST_HEAD(rzones ,rzone)  rzones;
LIST_HEAD(, myschedule)       myschedules = LIST_HEAD_INITIALIZER(myschedules);

struct myschedule {
	char zonename[DNS_MAXNAME + 1];
	time_t when;
	int action;
#define SCHEDULE_ACTION_RESTART	0x1
#define SCHEDULE_ACTION_REFRESH 0x2
#define SCHEDULE_ACTION_RETRY	0x3
	LIST_ENTRY(myschedule)	myschedule_entry;
} *sp0, *sp1, *spn;



int raxfr_a(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
int raxfr_aaaa(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
int raxfr_cname(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
int raxfr_ns(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
int raxfr_ptr(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
int raxfr_mx(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
int raxfr_txt(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
int raxfr_dnskey(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
int raxfr_rrsig(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
int raxfr_nsec3param(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
int raxfr_nsec3(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
int raxfr_ds(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
int raxfr_sshfp(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
int raxfr_tlsa(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
int raxfr_srv(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
int raxfr_naptr(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);

u_int16_t raxfr_skip(FILE *, u_char *, u_char *);
int raxfr_soa(FILE *, u_char *, u_char *, u_char *, struct soa *, int, u_int32_t, u_int16_t, HMAC_CTX *);
int raxfr_peek(FILE *, u_char *, u_char *, u_char *, int *, int, u_int16_t *, u_int32_t, HMAC_CTX *);
int raxfr_tsig(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen, HMAC_CTX *ctx, char *, int);
void			replicantloop(ddDB *, struct imsgbuf *, struct imsgbuf *);
static void		schedule_refresh(char *, time_t);
static void		schedule_retry(char *, time_t);
static void		schedule_restart(char *, time_t);
static void		schedule_delete(struct myschedule *);
static int 		rand_restarttime(void);
int64_t get_remote_soa(struct rzone *rzone);
int do_raxfr(FILE *, struct rzone *);
int pull_rzone(struct rzone *, time_t);

extern int                     memcasecmp(u_char *, u_char *, int);
extern char * dns_label(char *, int *);
extern char                    *get_dns_type(int, int);
extern int mybase64_encode(u_char const *, size_t, char *, size_t);
extern char *bin2hex(char *, int);
extern char *bitmap2human(char *, int);
extern char *convert_name(char *, int);
extern char *base32hex_encode(u_char *, int);
extern u_int64_t timethuman(time_t);
extern char * expand_compression(u_char *, u_char *, u_char *, u_char *, int *, int);
extern void	dolog(int, char *, ...);
extern struct rbtree * find_rrset(ddDB *db, char *name, int len);               
extern struct rrset * find_rr(struct rbtree *rbt, u_int16_t rrtype);    
extern struct question         *build_question(char *, int, int, char *);
extern int                      lookup_axfr(FILE *, int, char *, struct soa *, u_int32_t, char *, char *, int *, int *, int *);
extern int     find_tsig_key(char *, int, char *, int);
extern int tsig_pseudoheader(char *, uint16_t, time_t, HMAC_CTX *);

extern void 	pack(char *, char *, int);
extern void 	pack32(char *, u_int32_t);
extern void 	pack16(char *, u_int16_t);
extern void 	pack8(char *, u_int8_t);
extern uint32_t unpack32(char *);
extern uint16_t unpack16(char *);
extern void 	unpack(char *, char *, int);


/* The following alias helps with bounds checking all input, needed! */

#define BOUNDS_CHECK(cur, begin, rdlen, end) 		do {	\
	if ((cur - begin) > rdlen) {				\
		return -1;					\
	}							\
	if (cur > end)						\
		return -1;					\
} while (0)

static struct raxfr_logic supported[] = {
	{ DNS_TYPE_A, 0, raxfr_a },
	{ DNS_TYPE_NS, 0, raxfr_ns },
	{ DNS_TYPE_MX, 0, raxfr_mx },
	{ DNS_TYPE_PTR, 0, raxfr_ptr },
	{ DNS_TYPE_AAAA, 0, raxfr_aaaa },
	{ DNS_TYPE_CNAME, 0, raxfr_cname },
	{ DNS_TYPE_TXT, 0, raxfr_txt },
	{ DNS_TYPE_DNSKEY, 1, raxfr_dnskey },
	{ DNS_TYPE_RRSIG, 1, raxfr_rrsig },
	{ DNS_TYPE_NSEC3PARAM, 1, raxfr_nsec3param },
	{ DNS_TYPE_NSEC3, 1, raxfr_nsec3 },
	{ DNS_TYPE_DS, 1, raxfr_ds },
	{ DNS_TYPE_SSHFP, 0, raxfr_sshfp },
	{ DNS_TYPE_TLSA, 0, raxfr_tlsa },
	{ DNS_TYPE_SRV, 0, raxfr_srv },
	{ DNS_TYPE_NAPTR, 0, raxfr_naptr },
	{ 0, 0, NULL }
};


int
raxfr_peek(FILE *f, u_char *p, u_char *estart, u_char *end, int *rrtype, int soacount, u_int16_t *rdlen, u_int32_t format, HMAC_CTX *ctx)
{
	int rrlen;
	char *save;
	char *humanname;
	u_char expand[256];
	u_char *q = p;
	u_int16_t rtype, rclass, rdtmp;
	u_int32_t rttl;
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
	
	if ((q + 2) > end)
		return -1;

	rtype = unpack16(q);
	q += 2;

	if ((q + 2) > end)
		return -1;

	rclass = unpack16(q);
	q += 2;

	if ((q + 4) > end)
		return -1;

	rttl = unpack32(q);
	q += 4;

	if ((q + 2) > end)
		return -1;

	rdtmp = unpack16(q);	
	pack16((char *)rdlen, ntohs(rdtmp));
	
	q += 2;

	pack32((char *)rrtype, ntohs(rtype));

	if (ctx != NULL) {
		if (*rrtype != DNS_TYPE_TSIG) {
			HMAC_Update(ctx, p, q - p);
		}
	}

	if (*rrtype == 41 || *rrtype == DNS_TYPE_TSIG)	
		goto out;

	humanname = convert_name(expand, elen);
	if (humanname == NULL) {
		return -1;
	}

	hightype = get_dns_type(ntohs(rtype), 0);

	for (i = 0; i < strlen(hightype); i++)
		hightype[i] = tolower(hightype[i]);

	if (f != NULL)  {

		if (soacount < 1) {
			if ((format & INDENT_FORMAT))
				fprintf(f, "  %s,%s,%d,",  (*humanname == '\0' ? "." : humanname), hightype , ntohl(rttl));
			else if ((format & ZONE_FORMAT)) {
				fprintf(f, "  %s,%s,%d,", (*humanname == '\0' ? "." : humanname), hightype , ntohl(rttl));
			} else
				fprintf(f, "%s,%s,%d,", (*humanname == '\0' ? "." : humanname), hightype , ntohl(rttl));
		} else {
			if ((format & INDENT_FORMAT))
				fprintf(f, "  %s,%s,%d,", (*humanname == '\0' ? "." : humanname), hightype , ntohl(rttl));
			else if ((format & ZONE_FORMAT)) {
				if (*rrtype != DNS_TYPE_SOA) {
					fprintf(f, "  %s,%s,%d,", (*humanname == '\0' ? "." : humanname), hightype , ntohl(rttl));
				}
			} else {
				fprintf(f, "%s,%s,%d,", (*humanname == '\0' ? "." : humanname), hightype , ntohl(rttl));
			}
		}
	}

	fflush(f);

	free(humanname);

out:
	rrlen = (q - estart);
	return (rrlen);
}

u_int16_t
raxfr_skip(FILE *f, u_char *p, u_char *estart)
{
	u_char *q;
	u_int16_t rdlen;

	if ((q = p - 2) <= estart)
		return 0;
	
	rdlen = unpack16(q);
	
	return ((u_int16_t)ntohs(rdlen));
}

int
raxfr_soa(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, int soacount, u_int32_t format, u_int16_t rdlen, HMAC_CTX *ctx)
{
	u_int32_t rvalue;
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

	BOUNDS_CHECK(q, p, rdlen, end);

	memset(&mysoa->nsserver, 0, sizeof(mysoa->nsserver));
	memcpy(&mysoa->nsserver, expand, elen);
	mysoa->nsserver_len = elen;
	humanname = convert_name(mysoa->nsserver, mysoa->nsserver_len);
	if (humanname == NULL) {
		return -1;
	}

	if (soacount < soalimit) {
		if (f != NULL) {
			if (*humanname == '\0')	
				fprintf(f, ".,");
			else
				fprintf(f, "%s,", humanname);
		}
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

	BOUNDS_CHECK(q, p, rdlen, end);

	memset(&mysoa->responsible_person, 0, sizeof(mysoa->responsible_person));
	memcpy(&mysoa->responsible_person, expand, elen);
	mysoa->rp_len = elen;

	humanname = convert_name(mysoa->responsible_person, mysoa->rp_len);
	if (humanname == NULL) {
		return -1;
	}

	if (soacount < soalimit) {
		if (f != NULL) {
			if (*humanname == '\0')
				fprintf(f, ".,");
			else 
				fprintf(f, "%s,", humanname);
		}
	}

	free(humanname);

	BOUNDS_CHECK((q + 4), p, rdlen, end);
	rvalue = unpack32(q);
	mysoa->serial = rvalue;
	q += sizeof(u_int32_t);
	BOUNDS_CHECK((q + 4), p, rdlen, end);
	rvalue = unpack32(q);
	mysoa->refresh = rvalue;
	q += sizeof(u_int32_t);
	BOUNDS_CHECK((q + 4), p, rdlen, end);
	rvalue = unpack32(q);
	mysoa->retry = rvalue;
	q += sizeof(u_int32_t);
	BOUNDS_CHECK((q + 4), p, rdlen, end);
	rvalue = unpack32(q);
	mysoa->expire = rvalue;
	q += sizeof(u_int32_t);
	BOUNDS_CHECK((q + 4), p, rdlen, end);
	rvalue = unpack32(q);
	mysoa->minttl = rvalue;
	q += sizeof(u_int32_t);
	
	if (soacount < soalimit) {
		if (f != NULL) {
			fprintf(f, "%d,%d,%d,%d,%d\n", ntohl(mysoa->serial),
				ntohl(mysoa->refresh), ntohl(mysoa->retry),
				ntohl(mysoa->expire), ntohl(mysoa->minttl));
		}
	}

	if (ctx != NULL)
		HMAC_Update(ctx, p, q - p);
	
	return (q - estart);
}

int 
raxfr_rrsig(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen, HMAC_CTX *ctx)
{
	struct rrsig rs;
	char *save, *humanname;
	u_char *q = p;
	u_char expand[256];
	int max = sizeof(expand);
	int elen = 0;
	u_int16_t tmp;
	u_int32_t tmp4;
	int len;
	u_char *b;

	BOUNDS_CHECK((q + 2), p, rdlen, end);
	tmp = unpack16(q);
	rs.type_covered = ntohs(tmp);
	q += 2;
	BOUNDS_CHECK((q + 1), p, rdlen, end);
	rs.algorithm = *q++;
	BOUNDS_CHECK((q + 1), p, rdlen, end);
	rs.labels = *q++;
	BOUNDS_CHECK((q + 4), p, rdlen, end);
	tmp4 = unpack32(q);
	rs.original_ttl = ntohl(tmp4);
	q += 4;
	BOUNDS_CHECK((q + 4), p, rdlen, end);
	tmp4 = unpack32(q);
	rs.signature_expiration = ntohl(tmp4);
	q += 4;
	BOUNDS_CHECK((q + 4), p, rdlen, end);
	tmp4 = unpack32(q);
	rs.signature_inception = ntohl(tmp4);
	q += 4;
	BOUNDS_CHECK((q + 2), p, rdlen, end);
	tmp = unpack16(q);
	rs.key_tag = ntohs(tmp);
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
			rs.key_tag, 
			(*humanname == '\0' ? "." : humanname), b);
	}

	free(humanname);
	free(b);

	if (ctx != NULL)
		HMAC_Update(ctx, p, q - p);

	return (q - estart);
}

int 
raxfr_ds(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen, HMAC_CTX *ctx)
{
	struct ds d;
	u_int16_t tmpshort;
	u_char *q = p;

	BOUNDS_CHECK((p + 2), q, rdlen, end);
	tmpshort = unpack16(p);
	d.key_tag = ntohs(tmpshort);
	p += 2;
	BOUNDS_CHECK((p + 1), q, rdlen, end);
	d.algorithm = *p++;
	BOUNDS_CHECK((p + 1), q, rdlen, end);
	d.digest_type = *p++;

	if ((rdlen - 4) < 0)
		return -1;
	d.digestlen = (rdlen - 4);
	if (d.digestlen > sizeof(d.digest))
		return -1;
	memcpy(&d.digest, p, d.digestlen);
	p += d.digestlen;


	if (f != NULL) {
		fprintf(f, "%u,%u,%u,\"%s\"\n", d.key_tag, d.algorithm, 
			d.digest_type, bin2hex(d.digest, d.digestlen));
	}

	if (ctx != NULL)
		HMAC_Update(ctx, q, p - q);

	return (p - estart);
}

int 
raxfr_sshfp(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen, HMAC_CTX *ctx)
{
	struct sshfp s;
	char *hex;
	u_char *q = p;

	BOUNDS_CHECK((p + 1), q, rdlen, end);
	s.algorithm = *p++;
	BOUNDS_CHECK((p + 1), q, rdlen, end);
	s.fptype  = *p++;
	
	if (rdlen - 2 < 0)
		return -1;

	s.fplen = (rdlen - 2);
	if (s.fplen > sizeof(s.fingerprint))
		return -1;

	memcpy(&s.fingerprint, p, s.fplen);
	p += s.fplen;

	hex = bin2hex(s.fingerprint, s.fplen);

	if (f != NULL) {
		fprintf(f, "%u,%u,\"%s\"\n", s.algorithm, s.fptype, hex);
	}

	if (ctx != NULL)
		HMAC_Update(ctx, q, p - q);

	return (p - estart);
}

int 
raxfr_dnskey(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen, HMAC_CTX *ctx)
{
	struct dnskey dk;
	u_int16_t tmpshort;
	char *b;
	u_char *q = p;
	int len;

	BOUNDS_CHECK((p + 2), q, rdlen, end);
	tmpshort = unpack16(p);
	dk.flags = ntohs(tmpshort);
	p += 2;
	BOUNDS_CHECK((p + 1), q, rdlen, end);
	dk.protocol = *p++;
	BOUNDS_CHECK((p + 1), q, rdlen, end);
	dk.algorithm = *p++;
	
	if (rdlen - 4 < 0)
		return -1;
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

	if (ctx != NULL)
		HMAC_Update(ctx, q, p - q);

	return (p - estart);
}


int 
raxfr_mx(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen, HMAC_CTX *ctx)
{
	u_int16_t mxpriority;
	char *save, *humanname;
	u_char *q = p;
	u_char expand[256];
	int max = sizeof(expand);
	int elen = 0;

	BOUNDS_CHECK((q + 2), p, rdlen, end);
	mxpriority = unpack16(q);

	if (f != NULL)
		fprintf(f, "%u,", ntohs(mxpriority));

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

	if (f != NULL) {
		if (*humanname == '\0')
			fprintf(f, ".\n");
		else
			fprintf(f, "%s\n", humanname);
	}

	free(humanname);

	if (ctx != NULL)
		HMAC_Update(ctx, p, q - p);

	return (q - estart);
}

int 
raxfr_ptr(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen, HMAC_CTX *ctx)
{
	return (raxfr_ns(f, p, estart, end, mysoa, rdlen, ctx));
}

int
raxfr_nsec3(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen, HMAC_CTX *ctx)
{
	struct nsec3 n;
	u_int16_t iter;
	u_char *brr = p;	/* begin of rd record :-) */

	BOUNDS_CHECK((p + 1), brr, rdlen, end);
	n.algorithm = *p++;
	BOUNDS_CHECK((p + 1), brr, rdlen, end);
	n.flags = *p++;

	BOUNDS_CHECK((p + 2), brr, rdlen, end);
	iter = unpack16(p);
	n.iterations = ntohs(iter);
	p += 2;

	BOUNDS_CHECK((p + 1), brr, rdlen, end);
	n.saltlen = *p++;
	memcpy(&n.salt, p, n.saltlen);
	p += n.saltlen;

	BOUNDS_CHECK((p + 1), brr, rdlen, end);
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
	
	bitmap2human(n.bitmap, n.bitmap_len);

	if (f != NULL) {
		fprintf(f, "%u,%u,%u,\"%s\",\"%s\",\"%s\"\n", n.algorithm, 
				n.flags, n.iterations, 
				(n.saltlen == 0 ? "-" : 
					bin2hex(n.salt, n.saltlen)), 
				base32hex_encode(n.next, n.nextlen), 
				bitmap2human(n.bitmap, n.bitmap_len));
	}

	if (ctx != NULL)
		HMAC_Update(ctx, brr, p - brr);

	return (p - estart);
}

int
raxfr_nsec3param(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen, HMAC_CTX *ctx)
{
	struct nsec3param np;
	u_int16_t iter;
	char *hex;
	u_char *q = p;

	BOUNDS_CHECK((p + 1), q, rdlen, end);
	np.algorithm = *p++;
	BOUNDS_CHECK((p + 1), q, rdlen, end);
	np.flags = *p++;
	BOUNDS_CHECK((p + 2), q, rdlen, end);
	iter = unpack16(p);
	np.iterations = ntohs(iter);
	p += 2;
	BOUNDS_CHECK((p + 1), q, rdlen, end);
	np.saltlen = *p++;
	BOUNDS_CHECK((p + np.saltlen), q, rdlen, end);
	memcpy(&np.salt, p, np.saltlen);
	p += np.saltlen;
	
	hex = bin2hex(np.salt, np.saltlen);

	if (f != NULL) {
		fprintf(f, "%u,%u,%u,\"%s\"\n", np.algorithm, np.flags, 
			np.iterations, 
			(np.saltlen == 0 ? "-" : bin2hex(np.salt, np.saltlen)));
	}

	if (ctx != NULL)
		HMAC_Update(ctx, q, p - q);

	return (p - estart);
}


int
raxfr_txt(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen, HMAC_CTX *ctx)
{
	u_int8_t len;
	int i;
	u_char *q = p;

	BOUNDS_CHECK(p, q, rdlen, end);
	len = rdlen;

	if (f != NULL) 
		fprintf(f, "\"");

	for (i = 0; i < rdlen; i++) {
		if (i % 256 == 0)
			continue;

		if (f != NULL) 
			fprintf(f, "%c", p[i]);	
	}
	if (f != NULL)
		fprintf(f, "\"\n");

	p += i;
	
	if (ctx != NULL)
		HMAC_Update(ctx, q, p - q);
	
	return (p - estart);
}

int
raxfr_ns(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen, HMAC_CTX *ctx)
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

	if (f != NULL) {
		if (*humanname == '\0')
			fprintf(f, ".\n");
		else
			fprintf(f, "%s\n", humanname);
	}

	free(humanname);

	if (ctx != NULL) {
		HMAC_Update(ctx, p, q - p);
	}

	return (q - estart);
}

int 
raxfr_cname(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen, HMAC_CTX *ctx)
{
	return (raxfr_ns(f, p, estart, end, mysoa, rdlen, ctx));
}


int
raxfr_aaaa(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen, HMAC_CTX *ctx)
{
	char buf[INET6_ADDRSTRLEN];
	struct in6_addr ia;
	u_char *q = p;

	BOUNDS_CHECK((p + sizeof(ia)), q, rdlen, end);
	unpack((char *)&ia, p, sizeof(struct in6_addr));
	inet_ntop(AF_INET6, &ia, buf, sizeof(buf));

	if (f != NULL) 
		fprintf(f, "%s\n", buf);

	p += sizeof(ia);

	if (ctx != NULL)
		HMAC_Update(ctx, q, p - q);

	return (p - estart);
}

int
raxfr_a(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen, HMAC_CTX *ctx)
{
	char buf[INET_ADDRSTRLEN];
	struct in_addr ia;
	u_char *q = p;

	BOUNDS_CHECK((p + sizeof(ia)), q, rdlen, end);
	ia.s_addr = unpack32(p);

	inet_ntop(AF_INET, &ia, buf, sizeof(buf));
	
	if (f != NULL)
		fprintf(f, "%s\n", buf);

	p += sizeof(ia);

	if (ctx != NULL)
		HMAC_Update(ctx, q, p - q);

	return (p - estart);
}

int 
raxfr_tlsa(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen, HMAC_CTX *ctx)
{
	struct tlsa t;
	u_char *q = p;

	BOUNDS_CHECK((p + 1), q, rdlen, end);
	t.usage = *p++;
	BOUNDS_CHECK((p + 1), q, rdlen, end);
	t.selector = *p++;
	BOUNDS_CHECK((p + 1), q, rdlen, end);
	t.matchtype = *p++;

	if (rdlen - 3 < 0)
		return -1;

	t.datalen = (rdlen - 3);
	
	if (t.datalen > sizeof(t.data))
		return -1;

	memcpy(&t.data, p, t.datalen);
	p += t.datalen;

	if (f != NULL) {
		fprintf(f, "%u,%u,%u,\"%s\"\n", t.usage, t.selector, 
			t.matchtype, bin2hex(t.data, t.datalen));
	}

	if (ctx != NULL)
		HMAC_Update(ctx, q, p - q);

	return (p - estart);
}

int 
raxfr_srv(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen, HMAC_CTX *ctx)
{
	u_int16_t tmp16;
	struct srv s;
	char *save, *humanname;
	u_char *q = p;
	u_char expand[256];
	int max = sizeof(expand);
	int elen = 0;

	BOUNDS_CHECK((q + 2), p, rdlen, end);
	tmp16 = unpack16(q);
	s.priority = ntohs(tmp16);
	q += 2;
	BOUNDS_CHECK((q + 2), p, rdlen, end);
	tmp16 = unpack16(q);
	s.weight = ntohs(tmp16);
	q += 2;
	BOUNDS_CHECK((q + 2), p, rdlen, end);
	tmp16 = unpack16(q);
	s.port = ntohs(tmp16);
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

	if (f != NULL) {
		if (*humanname == '\0')
			fprintf(f, "%u,%u,%u,.\n", s.priority, s.weight, s.port);
		else
			fprintf(f, "%u,%u,%u,%s\n", s.priority, s.weight,
				s.port, humanname);
	}

	free(humanname);

	if (ctx != NULL)
		HMAC_Update(ctx, p, q - p);

	return (q - estart);
}

int 
raxfr_naptr(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen, HMAC_CTX *ctx)
{
	u_int16_t tmp16;
	struct naptr n;
	char *save, *humanname;
	u_char *q = p;
	u_char expand[256];
	int max = sizeof(expand);
	int elen = 0;
	int len, i;

	BOUNDS_CHECK((q + 2), p, rdlen, end);
	tmp16 = unpack16(q);
	n.order = ntohs(tmp16);
	q += 2;
	BOUNDS_CHECK((q + 2), p, rdlen, end);
	tmp16 = unpack16(q);
	n.preference = ntohs(tmp16);
	q += 2;

	if (f != NULL) {
		fprintf(f, "%u,%u,", n.order, n.preference);
	}

	
	/* flags */
	BOUNDS_CHECK((q + 1), p, rdlen, end);
	len = *q;
	q++;

	if (f != NULL) {
		fprintf(f, "\"");
		for (i = 0; i < len; i++) {
			BOUNDS_CHECK((q + 1), p, rdlen, end);
			fprintf(f, "%c", *q++);
		}
		fprintf(f, "\",");
	}
	/* services */
	BOUNDS_CHECK((q + 1), p, rdlen, end);
	len = *q;
	q++;

	if (f != NULL) {
		fprintf(f, "\"");
		for (i = 0; i < len; i++) {
			BOUNDS_CHECK((q + 1), p, rdlen, end);
			fprintf(f, "%c", *q++);
		}
		fprintf(f, "\",");
	}
	/* regexp */
	BOUNDS_CHECK((q + 1), p, rdlen, end);
	len = *q;
	q++;

	if (f != NULL) {
		fprintf(f, "\"");
		for (i = 0; i < len; i++) {
			BOUNDS_CHECK((q + 1), p, rdlen, end);
			fprintf(f, "%c", *q++);
		}
		fprintf(f, "\",");
	}

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

	if (f != NULL) {
		if (*humanname == '\0')
			fprintf(f, ".\n");
		else
			fprintf(f, "%s\n", humanname);
	}

	free(humanname);

	if (ctx != NULL)
		HMAC_Update(ctx, p, q - p);

	return (q - estart);
}

int 
raxfr_tsig(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, u_int16_t rdlen, HMAC_CTX *ctx, char *mac, int standardanswer)
{
	struct dns_tsigrr *sdt;
	char *save;
	char *keyname = NULL, *algname = NULL;
	char *rawkeyname = NULL, *rawalgname = NULL;
	char *otherdata;
	u_char expand[256];
	u_char *q = p;
	u_int16_t rtype, rclass, origid, tsigerror, otherlen;
	u_int32_t rttl;
	int rlen, rrlen = -1;
	int elen = 0;
	int max = sizeof(expand);
	int rawkeynamelen, rawalgnamelen;
	int macsize = 32;
	
	memset(&expand, 0, sizeof(expand));
	save = expand_compression(q, estart, end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		fprintf(stderr, "expanding compression failure 0\n");
		goto out;
	} else 
		q = save;

	keyname = convert_name(expand, elen);
	if (keyname == NULL) {
		goto out;
	}

	rawkeyname = malloc(elen);
	if (rawkeyname == NULL)
		goto out;

	memcpy(rawkeyname, expand, elen);
	rawkeynamelen = elen;
	
	if ((q + 2) > end)
		goto out;

	rtype = unpack16(q);
	q += 2;

	if (ntohs(rtype) != DNS_TYPE_TSIG)	
		goto out;
	
	if ((q + 2) > end)
		goto out;

	rclass = unpack16(q);
	q += 2;

	if (ntohs(rclass) != DNS_CLASS_ANY)
		goto out;

	if ((q + 4) > end)
		goto out;

	rttl = unpack32(q);
	q += 4;

	if (rttl != 0)
		goto out;

	/* skip rdlen because raxfr_peek already got it */
	if ((q + 2) > end)
		goto out;
	q += 2;

	rlen = (q - estart);

	memset(&expand, 0, sizeof(expand));
	elen = 0;
	save = expand_compression(q, estart, end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		fprintf(stderr, "expanding compression failure 0\n");
		goto out;
	} else 
		q = save;

	
	algname = convert_name(expand, elen);
	if (algname == NULL) {
		goto out;
	}

	rawalgname = malloc(elen);
	if (rawalgname == NULL)
		goto out;
	memcpy(rawalgname, expand, elen);
	rawalgnamelen = elen;
	
	if (strcasecmp(algname, "hmac-sha256.") != 0) {
		goto out;
	}

	if ((q + sizeof(struct dns_tsigrr)) > end) {
		goto out;
	}

	sdt = (struct dns_tsigrr *)q;
	q += sizeof(struct dns_tsigrr);

	if ((q + 2) > end)
		goto out;

	origid = unpack16(q);
	q += 2;

	if ((q + 2) > end)
		goto out;

	tsigerror = unpack16(q);
	q += 2;
		
	if ((q + 2) > end)
		goto out;

	otherlen = unpack16(q);
	q += 2;

	otherdata = q;
	q += ntohs(otherlen);

	if ((q - estart) != (rdlen + rlen)) {
		goto out;
	}

	/* do something with the gathered data */

	if (standardanswer) {
		/* dns message */
		HMAC_Update(ctx, rawkeyname, rawkeynamelen);
		HMAC_Update(ctx, (char *)&rclass, 2);
		HMAC_Update(ctx, (char *)&rttl, 4);
		HMAC_Update(ctx, rawalgname, rawalgnamelen);
		HMAC_Update(ctx, (char *)&sdt->timefudge, 8);
		HMAC_Update(ctx, (char *)&tsigerror, 2);
		HMAC_Update(ctx, (char *)&otherlen, 2);
		if (ntohs(otherlen))
			HMAC_Update(ctx, otherdata, ntohs(otherlen));

	} else {
		HMAC_Update(ctx, (char *)&sdt->timefudge, 8);
	}

	if (HMAC_Final(ctx, mac, &macsize) != 1) {
		goto out;
	}

#if __OpenBSD__
	if (timingsafe_memcmp(sdt->mac, mac, macsize) != 0) {	
#else
	if (memcmp(sdt->mac, mac, macsize) != 0) {	
#endif
#if 0
		int i;

		printf("the given mac: ");
		for (i = 0; i < macsize; i++) {
			printf("%02x", sdt->mac[i] & 0xff);
		}
		printf(" does not equal the calculated mac: ");
		for (i = 0; i < macsize; i++) {
			printf("%02x", mac[i]  & 0xff);
		}
		printf("\n");
#endif

		goto out; 
	}

	rrlen = (q - estart);

out:
	free(keyname);
	free(algname);
	free(rawkeyname);
	free(rawalgname);
	return (rrlen);
}


void
replicantloop(ddDB *db, struct imsgbuf *ibuf, struct imsgbuf *master_ibuf)
{
	struct rzone *lrz, *lrz0;
	time_t now, lastnow;
	int sel, endspurt = 0;
	int idata;
	int64_t serial;
	struct rbtree *rbt;
	struct rrset *rrset;
	struct rr *rrp;
	struct timeval tv;
	fd_set rset;
	int max = 0;

	struct imsg imsg;
	ssize_t         n, datalen;
	char *dn = NULL;	
	char *humanconv = NULL;

	int period, tot_refresh = 0, zonecount = 1;
	int add_period = 0;


#if __OpenBSD__
	if (pledge("stdio wpath rpath cpath inet", NULL) < 0) {
		perror("pledge");
		exit(1);
	}
#endif

	lastnow = time(NULL);

#ifdef __linux__
	SLIST_FOREACH(lrz, &rzones, rzone_entry) {
#else
	SLIST_FOREACH_SAFE(lrz, &rzones, rzone_entry, lrz0) {
#endif
		if (lrz->zonename == NULL)
			continue;

		dolog(LOG_INFO, "adding SOA values to zone %s\n", lrz->zonename);
		rbt = find_rrset(db, lrz->zone, lrz->zonelen);
		if (rbt == NULL) {
			dolog(LOG_INFO, "%s has no apex, removing zone from replicant engine\n", lrz->zonename);
			SLIST_REMOVE(&rzones, lrz, rzone, rzone_entry);
			continue;
		}
		
		rrset = find_rr(rbt, DNS_TYPE_SOA);
		if (rrset == NULL) {
			dolog(LOG_INFO, "%s has no SOA, removing zone from replicant engine\n", lrz->zonename);
			SLIST_REMOVE(&rzones, lrz, rzone, rzone_entry);
			free(rbt);
			continue;
		}
		rrp = TAILQ_FIRST(&rrset->rr_head);
		if (rrp == NULL) {
			dolog(LOG_INFO, "SOA record corrupted for zone %s, removing zone from replicant engine\n", lrz->zonename);
			SLIST_REMOVE(&rzones, lrz, rzone, rzone_entry);
			free(rbt);
			continue;
		}

		lrz->soa.serial = ((struct soa *)rrp->rdata)->serial;
		lrz->soa.refresh = ((struct soa *)rrp->rdata)->refresh;
		lrz->soa.retry = ((struct soa *)rrp->rdata)->retry;
		lrz->soa.expire = ((struct soa *)rrp->rdata)->expire;

		dolog(LOG_INFO, "%s -> %u, %u, %u, %u\n", lrz->zonename, 
			lrz->soa.serial, lrz->soa.refresh, lrz->soa.retry,
			lrz->soa.expire);

		zonecount++;
		tot_refresh += lrz->soa.refresh;

		free(rbt);
	}

	period = (tot_refresh / zonecount) / zonecount;
	add_period = period;

#ifdef __linux__
	SLIST_FOREACH(lrz, &rzones, rzone_entry) {
#else
	SLIST_FOREACH_SAFE(lrz, &rzones, rzone_entry, lrz0) {
#endif
		if (lrz->zonename == NULL)
			continue;

		now = time(NULL);
		now += period;
		dolog(LOG_INFO, "refreshing %s at %s\n", lrz->zonename, ctime(&now));
		schedule_refresh(lrz->zonename, now);
		period += add_period;
	}

	for (;;) {
		FD_ZERO(&rset);
		if (endspurt) {
			tv.tv_sec = 0;
			tv.tv_usec = 5000;
		} else {
			tv.tv_sec = 1;
			tv.tv_usec = 0;
		}

		FD_SET(ibuf->fd, &rset);

		if (ibuf->fd > max)
			max = ibuf->fd;

		
		sel = select(max + 1, &rset, NULL, NULL, &tv);
		if (sel == -1) {	
			dolog(LOG_INFO, "select error: %s\n", strerror(errno));
			continue;
		}

		now = time(NULL);

		/* some time safety */
		if (now < lastnow) {
			/* we had time go backwards, this is bad */
			dolog(LOG_ERR, "time went backwards!  rescheduling all schedules on refresh timeouts...\n");

			/* blow away all schedules and redo them */
			while (!LIST_EMPTY(&myschedules)) {
				sp0 = LIST_FIRST(&myschedules);
				LIST_REMOVE(sp0, myschedule_entry);
				free(sp0);
			}

			SLIST_FOREACH(lrz, &rzones, rzone_entry) {
				if (lrz->zonename == NULL)
					continue;
				schedule_refresh(lrz->zonename, now + lrz->soa.refresh);
			}

			lastnow = now;
			continue;
		}

		lastnow = now;

		if (FD_ISSET(ibuf->fd, &rset)) {
			if ((n = imsg_read(ibuf)) < 0 && errno != EAGAIN) {
				dolog(LOG_ERR, "imsg read failure %s\n", strerror(errno));
				continue;
			}
			if (n == 0) {
				/* child died? */
				dolog(LOG_INFO, "sigpipe on child?  exiting.\n");
				continue;
			}

			for (;;) {
				if ((n = imsg_get(ibuf, &imsg)) < 0) {
					dolog(LOG_ERR, "imsg read error: %s\n", strerror(errno));
					break;
				} else {
					if (n == 0)
						break;

					datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

					switch(imsg.hdr.type) {
					case IMSG_NOTIFY_MESSAGE:
						dn = malloc(datalen);
						if (dn == NULL) {
							dolog(LOG_INFO, "malloc: %s\n", strerror(errno)); 
							break;
						}

						memcpy(dn, imsg.data, datalen);

						SLIST_FOREACH(lrz, &rzones, rzone_entry) {
								if (lrz->zonename == NULL)
								continue;

								if (datalen == lrz->zonelen &&
										memcasecmp(lrz->zone, dn, datalen) == 0)
											break;
						}

						if (lrz != NULL) {
								dolog(LOG_DEBUG, "zone %s is being notified now\n", lrz->zonename);
								if ((serial = get_remote_soa(lrz)) == MY_SOCK_TIMEOUT) {
										dolog(LOG_INFO, "timeout upon notify, dropping\n");
								} else if (serial > lrz->soa.serial) {
										/* initiate AXFR and update zone */
										dolog(LOG_INFO, "zone %s new higher serial detected (%ld vs. %ld)\n", lrz->zonename, serial, lrz->soa.serial);

										if (pull_rzone(lrz, now) < 0) {
											dolog(LOG_INFO, "AXFR failed\n");
										} else {
												schedule_restart(lrz->zonename, now + rand_restarttime());
												endspurt = 1;
										}
									} /* else serial ... */
							} else {
								humanconv = convert_name(dn, datalen);
								if (humanconv != NULL) {
									dolog(LOG_DEBUG, "couldn't find an rzone for domainame %s\n", humanconv);
									free(humanconv);
								}
							}

							free(dn);
							break;
					} /* switch */

					imsg_free(&imsg);
				}
			}

			continue;
		}

#ifdef __linux__
		LIST_FOREACH(sp0, &myschedules, myschedule_entry) {
#else
		LIST_FOREACH_SAFE(sp0, &myschedules, myschedule_entry, sp1) {
#endif
			if (sp0->when <= now) {
				/* we hit a timeout on refresh */
				if (sp0->action == SCHEDULE_ACTION_REFRESH) {
					SLIST_FOREACH(lrz, &rzones, rzone_entry) {
						if (lrz->zonename == NULL)
							continue;

						if (strcmp(sp0->zonename, lrz->zonename) == 0)
							break;
					}

					if (lrz != NULL) {
						dolog(LOG_DEBUG, "zone %s is being refreshed now\n", sp0->zonename);
						/* must delete before adding any more */
						schedule_delete(sp0);
						if ((serial = get_remote_soa(lrz)) == MY_SOCK_TIMEOUT) {
							dolog(LOG_ERR, "SOA lookup for zone %s failed\n", lrz->zonename);
							/* we didn't get a reply and our socket timed out */
							schedule_retry(lrz->zonename, now + lrz->soa.retry);
							/* schedule a retry and go on */
						} else if (serial > lrz->soa.serial) {
							/* initiate AXFR and update zone */
							dolog(LOG_INFO, "zone %s new higher serial detected (%ld vs. %ld)\n", lrz->zonename, serial, lrz->soa.serial);

							if (pull_rzone(lrz, now) < 0) {
								dolog(LOG_ERR, "AXFR for zone %s failed\n", lrz->zonename);
								schedule_retry(lrz->zonename, now + lrz->soa.retry);
								goto out;
							}

							/* schedule restart */
							schedule_restart(lrz->zonename, now + rand_restarttime());
							endspurt = 1;
						} else {
							schedule_refresh(lrz->zonename, now + lrz->soa.refresh);
						}
					}

					goto out;
				} else if (sp0->action == SCHEDULE_ACTION_RETRY) {
					/* we hit a timeout on retry */

					SLIST_FOREACH(lrz, &rzones, rzone_entry) {
						if (lrz->zonename == NULL)
							continue;

						if (strcmp(sp0->zonename, lrz->zonename) == 0)
							break;
					}

					if (lrz != NULL) {
						dolog(LOG_INFO, "AXFR for zone %s is being retried now\n", sp0->zonename);
						schedule_delete(sp0);
						if ((serial = get_remote_soa(lrz)) == MY_SOCK_TIMEOUT) {
							dolog(LOG_ERR, "SOA lookup for zone %s failed\n", lrz->zonename);
							/* we didn't get a reply and our socket timed out */
							schedule_retry(lrz->zonename, now + lrz->soa.retry);
							/* schedule a retry and go on */
							goto out;
						} else if (serial > lrz->soa.serial) {
							/* initiate AXFR and update zone */

							dolog(LOG_INFO, "zone %s new higher serial detected (%ld vs. %ld)\n", lrz->zonename, serial, lrz->soa.serial);

							if (pull_rzone(lrz, now) < 0) {
								dolog(LOG_ERR, "AXFR for zone %s failed\n", lrz->zonename);
								schedule_retry(lrz->zonename, now + lrz->soa.retry);
								goto out;
							}

							/* schedule restart */
							schedule_restart(lrz->zonename, now + rand_restarttime());
							endspurt = 1;
					  } else {
							schedule_refresh(lrz->zonename, now + lrz->soa.refresh);
						}
					}
				
					goto out;
				} else if (sp0->action == SCHEDULE_ACTION_RESTART) {
					/* we hit a scheduling on restarting, nothing can save you now! */
					dolog(LOG_INFO, "I'm supposed to restart now, RESTART\n");

					idata = 1;
					imsg_compose(master_ibuf, IMSG_RELOAD_MESSAGE, 
						0, 0, -1, &idata, sizeof(idata));
					msgbuf_write(&master_ibuf->w);
					exit(0);
				}
		
			} 
out:	
			continue;
		} /* LIST_FOREACH schedules */
	} /* for (;;) */

	/* NOTREACHED */
}

static void
schedule_refresh(char *zonename, time_t seconds)
{
	sp0 = calloc(1, sizeof(struct myschedule));
	if (sp0 == NULL)
		return;

	strlcpy(sp0->zonename, zonename, sizeof(sp0->zonename));
	sp0->when = seconds;
	sp0->action = SCHEDULE_ACTION_REFRESH;

	LIST_INSERT_HEAD(&myschedules, sp0, myschedule_entry);
}

static void
schedule_retry(char *zonename, time_t seconds)
{
	sp0 = calloc(1, sizeof(struct myschedule));
	if (sp0 == NULL)
		return;

	strlcpy(sp0->zonename, zonename, sizeof(sp0->zonename));
	sp0->when = seconds;
	sp0->action = SCHEDULE_ACTION_RETRY;

	LIST_INSERT_HEAD(&myschedules, sp0, myschedule_entry);

}

static void
schedule_restart(char *zonename, time_t seconds)
{
	sp0 = calloc(1, sizeof(struct myschedule));
	if (sp0 == NULL)
		return;

	strlcpy(sp0->zonename, zonename, sizeof(sp0->zonename));
	sp0->when = seconds;
	sp0->action = SCHEDULE_ACTION_RESTART;

	LIST_INSERT_HEAD(&myschedules, sp0, myschedule_entry);

	dolog(LOG_INFO, "scheduling restart at %s", ctime(&seconds));
}

static void
schedule_delete(struct myschedule *sched)
{
	sched->action = 0;
	LIST_REMOVE(sched, myschedule_entry);
	free(sched);
}

/*
 * get the remote serial from the SOA, via TCP
 */

int64_t
get_remote_soa(struct rzone *rzone)
{
	int so;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	struct sockaddr *sa;
	struct soa mysoa;
	socklen_t slen = sizeof(struct sockaddr_in);

	char tsigpass[512];
	char *keyname;
	int tsigpasslen, keynamelen;
	int len, i, answers;
	int numansw, numaddi, numauth;
	int rrtype, soacount = 0;
	u_int16_t rdlen;
	char query[512];
	char *reply, *dupreply;
	struct raxfr_logic *sr;
	struct question *q;
	struct whole_header {
		struct dns_header dh;
	} *wh, *rwh;
	
	u_char *p, *name;

	u_char *end, *estart;
	int totallen, zonelen, rrlen;
	int replysize = 0;
	u_int16_t *tcpsize;
	u_int16_t *plen;
	u_int16_t tcplen;

	FILE *f = NULL;
	int format = 0;
	int dotsig = 1;
	time_t now;
	
	char shabuf[32];
	char *algname = NULL;

	HMAC_CTX *ctx;
	uint16_t hmaclen;
	int sacount = 0;
	

	if ((so = socket(rzone->storage.ss_family, SOCK_STREAM, 0)) < 0) {
		dolog(LOG_INFO, "get_remote_soa: %s\n", strerror(errno));
		return MY_SOCK_TIMEOUT;
	}

	if (rzone->storage.ss_family == AF_INET6) {
		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_family = AF_INET6;
		sin6.sin6_port = htons(rzone->masterport);
		memcpy(&sin6.sin6_addr, (void *)&((struct sockaddr_in6 *)(&rzone->storage))->sin6_addr, sizeof(struct in6_addr));
#ifndef __linux__
		sin6.sin6_len = sizeof(struct sockaddr_in6);
#endif
		sa = (struct sockaddr *)&sin6;
		slen = sizeof(struct sockaddr_in6);
	} else {
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons(rzone->masterport);
		sin.sin_addr.s_addr = ((struct sockaddr_in *)(&rzone->storage))->sin_addr.s_addr;
		sa = (struct sockaddr *)&sin;
	}

	if (strcmp(rzone->tsigkey, "NOKEY") != 0) {

		keyname = dns_label(rzone->tsigkey, &keynamelen);
		if (keyname == NULL) {
			dolog(LOG_ERR, "dns_label failed\n");
			close(so);
			return MY_SOCK_TIMEOUT;
		}

		if ((tsigpasslen = find_tsig_key(keyname, keynamelen, (char *)&tsigpass, sizeof(tsigpass))) < 0) {
			dolog(LOG_ERR, "do not have a record of TSIG key %s\n", rzone->tsigkey);
			close(so);
			return MY_SOCK_TIMEOUT;
		}

		dotsig = 1;

	} else {
		dotsig = 0;
	}

        if (connect(so, sa, slen) < 0) {
                dolog(LOG_INFO, "connect to master %s port %u: %s\n", rzone->master, rzone->masterport, strerror(errno));
				close(so);
				return(MY_SOCK_TIMEOUT);
        }



	replysize = 0xffff;
	memset(&query, 0, sizeof(query));
	
	tcpsize = (u_int16_t *)&query[0];
	wh = (struct whole_header *)&query[2];

	wh->dh.id = htons(arc4random() & 0xffff);
	wh->dh.query = 0;
	wh->dh.question = htons(1);
	wh->dh.answer = 0;
	wh->dh.nsrr = 0;
	wh->dh.additional = 0;

	SET_DNS_QUERY(&wh->dh);
	SET_DNS_RECURSION(&wh->dh);

	
	HTONS(wh->dh.query);

	totallen = sizeof(struct whole_header) + 2;

	name = dns_label(rzone->zonename, &len);
	if (name == NULL) {
		close(so);
		return(MY_SOCK_TIMEOUT);
	}

	zonelen = len;
	
	p = (char *)&wh[1];	
	
	memcpy(p, name, len);
	totallen += len;

	pack16(&query[totallen], htons(DNS_TYPE_SOA));
	totallen += sizeof(u_int16_t);
	
	pack16(&query[totallen], htons(DNS_CLASS_IN));
	totallen += sizeof(u_int16_t);

	/* we have a key, attach a TSIG payload */
	if (dotsig) {
		ctx = HMAC_CTX_new();
		HMAC_Init_ex(ctx, tsigpass, tsigpasslen, EVP_sha256(), NULL);
		HMAC_Update(ctx, &query[2], totallen - 2);

		now = time(NULL);
		if (tsig_pseudoheader(rzone->tsigkey, 300, now, ctx) < 0) {
			fprintf(stderr, "tsig_pseudoheader failed\n");
			return(MY_SOCK_TIMEOUT);
		}

		HMAC_Final(ctx, shabuf, &len);

		if (len != 32) {
			fprintf(stderr, "not expected len != 32\n");
			return(MY_SOCK_TIMEOUT);
		}

		HMAC_CTX_free(ctx);

		memcpy(&query[totallen], keyname, keynamelen);
		totallen += keynamelen;
		
		pack16(&query[totallen], htons(DNS_TYPE_TSIG));
		totallen += 2;

		pack16(&query[totallen], htons(DNS_CLASS_ANY));
		totallen += 2;

		pack32(&query[totallen], 0);
		totallen += 4;

		algname = dns_label("hmac-sha256", &len);
		if (algname == NULL) {
			return(MY_SOCK_TIMEOUT);
		}

		/* rdlen */
		pack16(&query[totallen], htons(len + 2 + 4 + 2 + 2 + 32 + 2 + 2 + 2));
		totallen += 2;

		/* algorithm name */
		memcpy(&query[totallen], algname, len);
		totallen += len;

		free(algname);

		/* time 1 */
		if (sizeof(time_t) == 4)	/* 32-bit time_t */
			pack16(&query[totallen], 0);
		else
			pack16(&query[totallen], htons((now >> 32) & 0xffff));
		totallen += 2;

		/* time 2 */
		pack32(&query[totallen], htonl((now & 0xffffffff)));
		totallen += 4;

		/* fudge */
		pack16(&query[totallen], htons(300));
		totallen += 2;
	
		/* hmac size */
		pack16(&query[totallen], htons(sizeof(shabuf)));
		totallen += 2;

		/* hmac */
		memcpy(&query[totallen], shabuf, sizeof(shabuf));
		totallen += sizeof(shabuf);

		/* original id */
		pack16(&query[totallen], wh->dh.id);
		totallen += 2;

		/* error */
		pack16(&query[totallen], 0);
		totallen += 2;
		
		/* other len */
		pack16(&query[totallen], 0);
		totallen += 2;

		wh->dh.additional = htons(1);
	}

	pack16((char *)tcpsize, htons(totallen - 2));

	if (send(so, query, totallen, 0) < 0) {
		close(so);
		return(MY_SOCK_TIMEOUT);
	}

	/* catch reply */

	reply = calloc(1, replysize + 2);
	if (reply == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		close(so);
		return(MY_SOCK_TIMEOUT);
	}
	dupreply = calloc(1, replysize + 2);
	if (dupreply == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		close(so);
		return(MY_SOCK_TIMEOUT);
	}
	
	if ((len = recv(so, reply, 2, MSG_PEEK | MSG_WAITALL)) < 0) {
		dolog(LOG_INFO, "recv: %s\n", strerror(errno));
		close(so);
		free(reply);  free(dupreply);
		return(MY_SOCK_TIMEOUT);
	}

	plen = (u_int16_t *)reply;
	tcplen = ntohs(*plen);

	if ((len = recv(so, reply, tcplen + 2, MSG_WAITALL)) < 0) {
		dolog(LOG_INFO, "recv: %s\n", strerror(errno));
		close(so);
		free(reply);  free(dupreply);
		return(MY_SOCK_TIMEOUT);
	}

	memcpy(dupreply, reply, len);
	rwh = (struct whole_header *)&reply[2];

	end = &reply[len];

	if (rwh->dh.id != wh->dh.id) {
		dolog(LOG_INFO, "DNS ID mismatch\n");
		close(so);
		free(reply);  free(dupreply);
		return(MY_SOCK_TIMEOUT);
	}

	if (!(htons(rwh->dh.query) & DNS_REPLY)) {
		dolog(LOG_INFO, "NOT a DNS reply\n");
		close(so);
		free(reply);  free(dupreply);
		return(MY_SOCK_TIMEOUT);
	}

	numansw = ntohs(rwh->dh.answer);
	numauth = ntohs(rwh->dh.nsrr);
	numaddi = ntohs(rwh->dh.additional);
	answers = numansw + numauth + numaddi;

	if (answers < 1) {	
		dolog(LOG_INFO, "NO ANSWER provided\n");
		close(so);
		free(reply);  free(dupreply);
		return(MY_SOCK_TIMEOUT);
	}

	q = build_question((char *)dupreply + 2, len - 2, wh->dh.additional, NULL);
	if (q == NULL) {
		dolog(LOG_INFO, "failed to build_question\n");
		close(so);
		free(reply);  free(dupreply);
		return(MY_SOCK_TIMEOUT);
	}
		
	if (memcasecmp(q->hdr->name, name, q->hdr->namelen) != 0) {
		dolog(LOG_INFO, "question name not for what we asked\n");
		close(so);
		free(reply);  free(dupreply);
		return(MY_SOCK_TIMEOUT);
	}

	if (ntohs(q->hdr->qclass) != DNS_CLASS_IN || ntohs(q->hdr->qtype) != DNS_TYPE_SOA) {
		dolog(LOG_INFO, "wrong class or type\n");
		close(so);
		free(reply);  free(dupreply);
		return(MY_SOCK_TIMEOUT);
	}

	
	p = (u_char *)&rwh[1];		
	
	p += q->hdr->namelen;
	p += sizeof(u_int16_t);	 	/* type */
	p += sizeof(u_int16_t);		/* class */

	/* end of question */
	

	estart = (u_char *)&rwh->dh;

	if (dotsig) {
		ctx = HMAC_CTX_new();
		HMAC_Init_ex(ctx, tsigpass, tsigpasslen, EVP_sha256(), NULL);
		hmaclen = htons(32);
		HMAC_Update(ctx, (char *)&hmaclen, sizeof(hmaclen));
		HMAC_Update(ctx, shabuf, sizeof(shabuf));
		hmaclen = rwh->dh.additional;		/* save additional */
		NTOHS(rwh->dh.additional);
		if (rwh->dh.additional)
			rwh->dh.additional--;
		HTONS(rwh->dh.additional);
		HMAC_Update(ctx, estart, (p - estart));
		rwh->dh.additional = hmaclen;		/* restore additional */
	}


	for (i = answers; i > 0; i--) {
		if ((rrlen = raxfr_peek(f, p, estart, end, &rrtype, 0, &rdlen, format, (dotsig == 1) ? ctx : NULL)) < 0) {
			dolog(LOG_INFO, "not a SOA reply, or ERROR\n");
			close(so);
			free(reply);  free(dupreply);
			return(MY_SOCK_TIMEOUT);
		}
		
		if (rrtype != DNS_TYPE_TSIG) 
			p = (estart + rrlen);

		if (rrtype == DNS_TYPE_SOA) {
			if ((len = raxfr_soa(f, p, estart, end, &mysoa, soacount, format, rdlen, (dotsig == 1) ? ctx : NULL)) < 0) {
				dolog(LOG_INFO, "raxfr_soa failed\n");
				close(so);
				free(reply);  free(dupreply);
				return(MY_SOCK_TIMEOUT);
			}
			p = (estart + len);
			soacount++;
		} else if (dotsig && (rrtype == DNS_TYPE_TSIG)) {
			/* do tsig checks here */
			if ((len = raxfr_tsig(f,p,estart,end,&mysoa,rdlen,ctx, (char *)&shabuf, (sacount++ == 0) ? 1 : 0)) < 0) {
				fprintf(stderr, "error with TSIG record\n");
				close(so);
				free(reply);  free(dupreply);
				return(MY_SOCK_TIMEOUT);
			}

			p = (estart + len);
		} else {
			for (sr = supported; sr->rrtype != 0; sr++) {
				if (rrtype == sr->rrtype) {
					if ((len = (*sr->raxfr)(f, p, estart, end, &mysoa, rdlen, (dotsig == 1) ? ctx : NULL)) < 0) {
						dolog(LOG_INFO, "error with rrtype %d\n", sr->rrtype);
						close(so);
						free(reply);  free(dupreply);
						return(MY_SOCK_TIMEOUT);
					}
					p = (estart + len);
					break;
				}
			}

			if (sr->rrtype == 0) {
				if (rrtype != 41 && rrtype != 250) {
					dolog(LOG_INFO, "unsupported RRTYPE %u\n", rrtype);
					close(so);
					free(reply);  free(dupreply);
					return(MY_SOCK_TIMEOUT);
				}
			} 
		} /* rrtype == DNS_TYPE_SOA */


	} /* for () */

	free(reply);  free(dupreply);

	close(so);

	if (dotsig) {
		HMAC_CTX_free(ctx);
	}

	return ((int64_t)ntohl(mysoa.serial));
}

int
do_raxfr(FILE *f, struct rzone *rzone)
{
	int so;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	struct sockaddr *sa;
	socklen_t slen = sizeof(struct sockaddr_in);
	
	u_int window = 32768;
	char tsigpass[512];
	char humanpass[1024];
	char *keyname;
	int tsigpasslen, keynamelen;
	u_int32_t format = (TCP_FORMAT | ZONE_FORMAT);
	int len, dotsig = 1;
	int segment = 0;
	int answers = 0;
	int additionalcount = 0;

	struct soa mysoa;


	if ((so = socket(rzone->storage.ss_family, SOCK_STREAM, 0)) < 0) {
		dolog(LOG_INFO, "get_remote_soa: %s\n", strerror(errno));
		return -1;
	}

#ifndef __linux__
	/* biggen the window */

	while (window && setsockopt(so, SOL_SOCKET, SO_RCVBUF, &window, sizeof(window)) != -1)
		window <<= 1;
#endif

	if (rzone->storage.ss_family == AF_INET6) {
		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_family = AF_INET6;
		sin6.sin6_port = htons(rzone->masterport);
		memcpy(&sin6.sin6_addr, (void *)&((struct sockaddr_in6 *)(&rzone->storage))->sin6_addr, sizeof(struct in6_addr));
#ifndef __linux__
		sin6.sin6_len = sizeof(struct sockaddr_in6);
#endif
		sa = (struct sockaddr *)&sin6;
		slen = sizeof(struct sockaddr_in6);
	} else {
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons(rzone->masterport);
		sin.sin_addr.s_addr = ((struct sockaddr_in *)(&rzone->storage))->sin_addr.s_addr;
		sa = (struct sockaddr *)&sin;
	}

        if (connect(so, sa, slen) < 0) {
                dolog(LOG_INFO, "connect to master %s port %u: %s\n", rzone->master, rzone->masterport, strerror(errno));
		close(so);
		return -1;
        }

	if (strcmp(rzone->tsigkey, "NOKEY") != 0) {
		keyname = dns_label(rzone->tsigkey, &keynamelen);
		if (keyname == NULL) {
			dolog(LOG_ERR, "dns_label failed\n");
			close(so);
			return -1;
		}

		if ((tsigpasslen = find_tsig_key(keyname, keynamelen, (char *)&tsigpass, sizeof(tsigpass))) < 0) {
			dolog(LOG_ERR, "do not have a record of TSIG key %s\n", rzone->tsigkey);
			close(so);
			return -1;
		}

		free(keyname);

		if ((len = mybase64_encode(tsigpass, tsigpasslen, humanpass, sizeof(humanpass))) < 0) {
			dolog(LOG_ERR, "base64_encode() failed\n");
			close(so);
			return -1;
		}

		humanpass[len] = '\0';
	} else {
		dotsig = 0;
	}

	segment = 0;
	answers = 0;
	additionalcount = 0;

	if (lookup_axfr(f, so, rzone->zonename, &mysoa, format, ((dotsig == 0) ? NULL : rzone->tsigkey), humanpass, &segment, &answers, &additionalcount) < 0) {
		dolog(LOG_ERR, "lookup_axfr() failed\n");
		close(so);
		return -1;
	}
				
	close(so);
	return (0);
}


int
pull_rzone(struct rzone *rzone, time_t now)
{
	char *p, *q;
	FILE *f;
	char buf[PATH_MAX];

	p = strrchr(rzone->filename, '/');
	if (p == NULL) {
		dolog(LOG_INFO, "can't determine temporary filename from %s\n", rzone->filename);
		return -1;
	}

	p++;
	q = p;
	if (*p == '\0') {
		dolog(LOG_INFO, "can't determine temporary filename from %s (2)\n", rzone->filename);
		return -1;
	}

	snprintf(buf, sizeof(buf), "%s.XXXXXXXXXXXXXX", p);	
	if ((mkstemp(buf)) == -1) {
		dolog(LOG_INFO, "can't determine temporary filename from %s (3)\n", rzone->filename);
		return -1;
	}

	p = &buf[0];
	umask(022);
		
	f = fopen(p, "w");
	if (f == NULL) {
		dolog(LOG_INFO, "can't create temporary filename for zone %s\n", rzone->zonename);
		return -1;
	}

	fprintf(f, "; REPLICANT file for zone %s gotten on %lld\n\n", rzone->zonename, now);
	
	if (do_raxfr(f, rzone) < 0) {
		dolog(LOG_INFO, "do_raxfr failed\n");
		return -1;
	}

	fclose(f);

	unlink(q);	
	if (link(p, q) < 0) {
		dolog(LOG_ERR, "can't link %s to %s\n", p, q);
		return -1;
	}

	unlink(p);

	return 0;
}

/*
 * restarttime is 80 seconds plus a random interval between 0 and 39
 */

static int
rand_restarttime(void)
{
	return (80 + (arc4random() % 40));
}
