/*
 * Copyright (c) 2019-2024 Peter J. Philipp <pbug44@delphinusdns.org>
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
#include <sys/select.h>
#include <sys/socket.h>
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
#include <fcntl.h>

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

#include "ddd-dns.h"
#include "ddd-db.h"
#include "ddd-crypto.h"


#define MY_SOCK_TIMEOUT		-10

extern SLIST_HEAD(rzones ,rzone)  rzones;
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


extern struct rzone *rz0, *rz;
extern int replicant_axfr_old_behaviour;

int raxfr_a(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_svcb(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_https(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_eui48(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_eui64(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_aaaa(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_cname(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_ns(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_caa(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_zonemd(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_rp(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_hinfo(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_ptr(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_mx(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_nsec(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_kx(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_ipseckey(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_cert(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_txt(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_dnskey(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_cdnskey(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_rrsig(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_nsec3param(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_nsec3(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_ds(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_cds(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_loc(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_sshfp(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_tlsa(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_srv(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_naptr(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
int raxfr_soa(FILE *, u_char *, u_char *, u_char *, struct soa *, int, uint32_t, uint16_t, DDD_HMAC_CTX *, struct soa_constraints *);

uint16_t raxfr_skip(FILE *, u_char *, u_char *);
int raxfr_peek(FILE *, u_char *, u_char *, u_char *, int *, int, uint16_t *, uint32_t, DDD_HMAC_CTX *, char *, int, int);
int raxfr_tsig(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx, char *, int);


void			replicantloop(ddDB *, struct imsgbuf *);
static void		schedule_refresh(char *, time_t);
static void		schedule_retry(char *, time_t);
static void		schedule_restart(char *, time_t);
static void		schedule_delete(struct myschedule *);
static int 		rand_restarttime(void);
int64_t get_remote_soa(struct rzone *rzone);
int do_raxfr(FILE *, struct rzone *);
int pull_rzone(struct rzone *, time_t);

extern int 		fill_a(ddDB *, char *, char *, int, char *);
extern int 		fill_aaaa(ddDB *, char *, char *, int, char *);
extern int 		fill_ptr(ddDB *, char *, char *, int, char *);
extern int 		fill_cname(ddDB *, char *, char *, int, char *);
extern int 		fill_mx(ddDB *, char *, char *, int, int, char *);
extern int 		fill_naptr(ddDB *, char *, char *, int, int, int, char *, char *, char *, char *);
extern int 		fill_ns(ddDB *, char *, char *, int, char *);
extern int 		fill_soa(ddDB *, char *, char *, int, char *, char *, int, int, int, int, int);
extern int 		fill_sshfp(ddDB *, char *, char *, int, int, int, char *);
extern int 		fill_srv(ddDB *, char *, char *, int, int, int, int, char *);
extern int 		fill_tlsa(ddDB *, char *, char *,int, uint8_t, uint8_t, uint8_t, char *);
extern int 		fill_txt(ddDB *, char *, char *, int, char *);
extern int		fill_dnskey(ddDB *, char *, char *, uint32_t, uint16_t, uint8_t, uint8_t, char *);
extern int		fill_rrsig(ddDB *, char *, char *, uint32_t, char *, uint8_t, uint8_t, uint32_t, uint64_t, uint64_t, uint16_t, char *, char *);
extern int 		fill_nsec(ddDB *, char *, char *, uint32_t, char *, char *);
extern int		fill_nsec3param(ddDB *, char *, char *, uint32_t, uint8_t, uint8_t, uint16_t, char *);
extern int		fill_nsec3(ddDB *, char *, char *, uint32_t, uint8_t, uint8_t, uint16_t, char *, char *, char *);
extern int		fill_ds(ddDB *, char *, char *, uint32_t, uint16_t, uint8_t, uint8_t, char *);

extern int                     memcasecmp(u_char *, u_char *, int);
extern char * dns_label(char *, int *);
extern char                    *get_dns_type(int, int);
extern int mybase64_encode(u_char const *, size_t, char *, size_t);
extern char *bin2hex(char *, int);
extern char *bitmap2human(char *, int);
extern char *convert_name(char *, int);
extern char *base32hex_encode(u_char *, int);
extern uint64_t timethuman(time_t);
extern char * expand_compression(u_char *, u_char *, u_char *, u_char *, int *, int);
extern void	dolog(int, char *, ...);
extern struct rbtree * find_rrset(ddDB *db, char *name, int namelen);               
extern struct rrset * find_rr(struct rbtree *rbt, uint16_t rrtype);    
extern struct question         *build_question(char *, int, uint16_t, char *);
extern int                      lookup_axfr(FILE *, int, char *, struct soa *, uint32_t, char *, char *, int *, int *, int *, struct soa_constraints *, uint32_t, int);
extern int     find_tsig_key(char *, int, char *, int);
extern int tsig_pseudoheader(char *, uint16_t, time_t, DDD_HMAC_CTX *);

extern void 	pack(char *, char *, int);
extern void 	pack32(char *, uint32_t);
extern void 	pack16(char *, uint16_t);
extern void 	pack8(char *, uint8_t);
extern uint32_t unpack32(char *);
extern uint16_t unpack16(char *);
extern void 	unpack(char *, char *, int);

extern int		dn_contains(char *, int, char *, int);
extern char *		param_tlv2human(char *, int, int);
extern char * 		ipseckey_type(struct ipseckey *);
extern char * 		cert_type(struct cert *);
extern void 		safe_fprintf(FILE *, char *, ...);
extern size_t		plength(void *, void *);
extern u_int		nowrap_dec(u_int, u_int);
extern void		ddd_shutdown(void);


/* The following alias helps with bounds checking all input, needed! */

#define BOUNDS_CHECK(cur, begin, rdlen, end) 		do {	\
	if ((plength(cur, begin)) > rdlen) {			\
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
	{ DNS_TYPE_NSEC, 1, raxfr_nsec },
	{ DNS_TYPE_NSEC3PARAM, 1, raxfr_nsec3param },
	{ DNS_TYPE_NSEC3, 1, raxfr_nsec3 },
	{ DNS_TYPE_DS, 1, raxfr_ds },
	{ DNS_TYPE_SSHFP, 0, raxfr_sshfp },
	{ DNS_TYPE_TLSA, 0, raxfr_tlsa },
	{ DNS_TYPE_SRV, 0, raxfr_srv },
	{ DNS_TYPE_NAPTR, 0, raxfr_naptr },
	{ DNS_TYPE_RP, 0, raxfr_rp },
	{ DNS_TYPE_HINFO, 0, raxfr_hinfo },
	{ DNS_TYPE_CAA, 0, raxfr_caa },
	{ DNS_TYPE_ZONEMD, 0, raxfr_zonemd },
	{ DNS_TYPE_CDNSKEY, 1, raxfr_cdnskey },
	{ DNS_TYPE_CDS, 1, raxfr_cds },
	{ DNS_TYPE_LOC, 0, raxfr_loc },
	{ DNS_TYPE_EUI48, 0, raxfr_eui48 },
	{ DNS_TYPE_EUI64, 0, raxfr_eui64 },
	{ DNS_TYPE_SVCB, 0, raxfr_svcb },
	{ DNS_TYPE_HTTPS, 0, raxfr_https },
	{ DNS_TYPE_KX, 0, raxfr_kx },
	{ DNS_TYPE_IPSECKEY, 0, raxfr_ipseckey },
	{ DNS_TYPE_CERT, 0, raxfr_cert },
	{ 0, 0, NULL }
};


int
raxfr_peek(FILE *f, u_char *p, u_char *estart, u_char *end, int *rrtype, int soacount, uint16_t *rdlen, uint32_t format, DDD_HMAC_CTX *ctx, char *zonename, int zonelen, int axfr)
{
	int rrlen;
	char *save;
	char *humanname;
	u_char expand[256];
	u_char *q = p;
	uint16_t rtype, rdtmp;
	uint32_t rttl;
	int elen = 0;
	int max = sizeof(expand);
	char *hightype;
	int i;


	memset(&expand, 0, sizeof(expand));
	save = expand_compression(q, estart, end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		safe_fprintf(stderr, "expanding compression failure 0\n");
		return -1;
	} else 
		q = (u_char *)save;
	
	if ((q + 2) > end)
		return -1;


	rtype = unpack16((char *)q);
	q += 2;

	if ((q + 2) > end)
		return -1;

#if 0
	rclass = unpack16((char *)q);
#endif
	q += 2;

	if ((q + 4) > end)
		return -1;

	rttl = unpack32((char *)q);
	q += 4;

	if ((q + 2) > end)
		return -1;

	rdtmp = unpack16((char *)q);	
	pack16((char *)rdlen, ntohs(rdtmp));
	
	q += 2;

	pack32((char *)rrtype, ntohs(rtype));

	if (ctx != NULL) {
		if (*rrtype != DNS_TYPE_TSIG) {
			delphinusdns_HMAC_Update(ctx, p, plength(q, p));
		}
	}

	if (*rrtype == 41 || *rrtype == DNS_TYPE_TSIG)	
		goto out;

	humanname = convert_name((char *)expand, elen);
	if (humanname == NULL) {
		return -1;
	}

	/* check for poison */
	if (axfr && !dn_contains((char *)expand, elen, zonename, zonelen)) {
		char *humanzone;

		humanzone = convert_name(zonename, zonelen);
		dolog(LOG_INFO, "possible poison in AXFR, %s not part of %s\n", humanname, humanzone);
		free(humanname);
		free(humanzone);
		return -1;
	}

	hightype = get_dns_type(ntohs(rtype), 0);

	for (i = 0; i < strlen(hightype); i++)
		hightype[i] = tolower(hightype[i]);

	if (f != NULL)  {

		if (soacount < 1) {
			if ((format & INDENT_FORMAT))
				safe_fprintf(f, "  %s,%s,%d,",  (*humanname == '\0' ? "." : humanname), hightype , ntohl(rttl));
			else if ((format & ZONE_FORMAT)) {
				safe_fprintf(f, "  %s,%s,%d,", (*humanname == '\0' ? "." : humanname), hightype , ntohl(rttl));
			} else
				safe_fprintf(f, "%s,%s,%d,", (*humanname == '\0' ? "." : humanname), hightype , ntohl(rttl));
		} else {
			if ((format & INDENT_FORMAT))
				safe_fprintf(f, "  %s,%s,%d,", (*humanname == '\0' ? "." : humanname), hightype , ntohl(rttl));
			else if ((format & ZONE_FORMAT)) {
				if (*rrtype != DNS_TYPE_SOA) {
					safe_fprintf(f, "  %s,%s,%d,", (*humanname == '\0' ? "." : humanname), hightype , ntohl(rttl));
				}
			} else {
				safe_fprintf(f, "%s,%s,%d,", (*humanname == '\0' ? "." : humanname), hightype , ntohl(rttl));
			}
		}
	}

	fflush(f);

	free(humanname);

out:
	rrlen = (plength(q, estart));
	return (rrlen);
}

uint16_t
raxfr_skip(FILE *f, u_char *p, u_char *estart)
{
	u_char *q;
	uint16_t rdlen;

	if ((q = p - 2) <= estart)
		return 0;
	
	rdlen = unpack16((char *)q);
	
	return ((uint16_t)ntohs(rdlen));
}

int
raxfr_soa(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, int soacount, uint32_t format, uint16_t rdlen, DDD_HMAC_CTX *ctx, struct soa_constraints *constraints)
{
	uint32_t rvalue;
	char *save, *humanname;
	u_char *q = p;
	u_char expand[256];
	int max = sizeof(expand);
	int elen = 0;
	int soalimit = (format & ZONE_FORMAT) ? 1 : 2;

	memset(&expand, 0, sizeof(expand));
	save = expand_compression(q, estart, end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		safe_fprintf(stderr, "expanding compression failure 2\n");
		return -1;
	} else  {
		q = (u_char *)save;
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
				safe_fprintf(f, ".,");
			else
				safe_fprintf(f, "%s,", humanname);
		}
	}

	free(humanname);

	elen = 0;
	memset(&expand, 0, sizeof(expand));
	save = expand_compression(q, estart, end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		safe_fprintf(stderr, "expanding compression failure 4\n");
		return -1;
	} else  {
		q = (u_char *)save;
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
				safe_fprintf(f, ".,");
			else 
				safe_fprintf(f, "%s,", humanname);
		}
	}

	free(humanname);

	BOUNDS_CHECK((q + 4), p, rdlen, end);
	rvalue = unpack32((char *)q);
	mysoa->serial = rvalue;
	q += sizeof(uint32_t);
	BOUNDS_CHECK((q + 4), p, rdlen, end);
	rvalue = unpack32((char *)q);
	mysoa->refresh = rvalue;
	q += sizeof(uint32_t);
	BOUNDS_CHECK((q + 4), p, rdlen, end);
	rvalue = unpack32((char *)q);
	mysoa->retry = rvalue;
	q += sizeof(uint32_t);
	BOUNDS_CHECK((q + 4), p, rdlen, end);
	rvalue = unpack32((char *)q);
	mysoa->expire = rvalue;
	q += sizeof(uint32_t);
	BOUNDS_CHECK((q + 4), p, rdlen, end);
	rvalue = unpack32((char *)q);
	mysoa->minttl = rvalue;
	q += sizeof(uint32_t);

	if (constraints->refresh > ntohl(mysoa->refresh) ||
		constraints->retry > ntohl(mysoa->retry) ||
		constraints->expire > ntohl(mysoa->expire)) {
		dolog(LOG_INFO, "raxfr_soa:  refresh/retry/expire values were below SOA constraints %u/%u, %u/%u, %u/%u, bailing out!\n", constraints->refresh, ntohl(mysoa->refresh), constraints->retry, ntohl(mysoa->retry), constraints->expire, ntohl(mysoa->expire));
		
		if (f != NULL) {
			safe_fprintf(f, "constraints failure\n");
			fflush(f);
		}

		return -1;
	}
	
	if (soacount < soalimit) {
		if (f != NULL) {
			safe_fprintf(f, "%d,%d,%d,%d,%d\n", ntohl(mysoa->serial),
				ntohl(mysoa->refresh), ntohl(mysoa->retry),
				ntohl(mysoa->expire), ntohl(mysoa->minttl));
		}
	}

	if (ctx != NULL)
		delphinusdns_HMAC_Update(ctx, p, plength(q, p));
	
	return (plength(q, estart));
}

int 
raxfr_rrsig(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
{
	struct rrsig rs;
	char *save, *humanname;
	u_char *q = p;
	u_char expand[256];
	int max = sizeof(expand);
	int elen = 0;
	uint16_t tmp;
	uint32_t tmp4;
	int len;
	u_char *b;

	BOUNDS_CHECK((q + 2), p, rdlen, end);
	tmp = unpack16((char *)q);
	rs.type_covered = ntohs(tmp);
	q += 2;
	BOUNDS_CHECK((q + 1), p, rdlen, end);
	rs.algorithm = *q++;
	BOUNDS_CHECK((q + 1), p, rdlen, end);
	rs.labels = *q++;
	BOUNDS_CHECK((q + 4), p, rdlen, end);
	tmp4 = unpack32((char *)q);
	rs.original_ttl = ntohl(tmp4);
	q += 4;
	BOUNDS_CHECK((q + 4), p, rdlen, end);
	tmp4 = unpack32((char *)q);
	rs.signature_expiration = ntohl(tmp4);
	q += 4;
	BOUNDS_CHECK((q + 4), p, rdlen, end);
	tmp4 = unpack32((char *)q);
	rs.signature_inception = ntohl(tmp4);
	q += 4;
	BOUNDS_CHECK((q + 2), p, rdlen, end);
	tmp = unpack16((char *)q);
	rs.key_tag = ntohs(tmp);
	q += 2;
	
	memset(&expand, 0, sizeof(expand));
	save = expand_compression(q, estart, end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		safe_fprintf(stderr, "expanding compression failure 2\n");
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

	b = calloc(1, 2 * rs.signature_len);
	if (b == NULL)
		return -1;

	if ((len = mybase64_encode((const u_char *)rs.signature, rs.signature_len, (char *)b, rs.signature_len * 2)) < 0) {
		free(b);
		return -1;
	}

	b[len] = '\0';


	humanname = convert_name((char *)expand, elen);
	if (humanname == NULL) {
		free(b);
		return -1;
	}

	if (f != NULL) {
#if __FreeBSD__
		safe_fprintf(f, "%s,%u,%u,%u,%lu,%lu,%u,%s,\"%s\"\n", 
#else
		safe_fprintf(f, "%s,%u,%u,%u,%llu,%llu,%u,%s,\"%s\"\n", 
#endif
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
		delphinusdns_HMAC_Update(ctx, p, plength(q, p));

	return (plength(q, estart));
}

int 
raxfr_zonemd(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
{
	struct zonemd zonemd;
	u_char *q = p;
	int i;

	BOUNDS_CHECK((p + 4), q, rdlen, end);
	memcpy(&zonemd.serial, p, 4);
	p += 4; 
	BOUNDS_CHECK((p + 1), q, rdlen, end);
	zonemd.scheme = *p;
	p++;
	BOUNDS_CHECK((p + 1), q, rdlen, end);
	zonemd.algorithm = *p;
	p++;
	switch (zonemd.algorithm) {
	case ZONEMD_SHA384:
		zonemd.hashlen = SHA384_DIGEST_LENGTH;
		break;
	default:
		return -1;
		break;
	}
	BOUNDS_CHECK((p + zonemd.hashlen), q, rdlen, end);
	memcpy(&zonemd.hash, p, zonemd.hashlen);
	p += zonemd.hashlen;

	if (f != NULL) {
		safe_fprintf(f, "%u,", zonemd.serial);
		safe_fprintf(f, "%u,", zonemd.scheme);
		safe_fprintf(f, "%u,", zonemd.algorithm);
		for (i = 0; i < zonemd.hashlen; i++) {
			safe_fprintf(f, "%02x", zonemd.hash[i] & 0xff);
		}
		safe_fprintf(f, "\n");
	}

	if (ctx != NULL)
		delphinusdns_HMAC_Update(ctx, q, plength(p, q));

	return (plength(p, estart));
}



int 
raxfr_caa(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
{
	struct caa caa;
	u_char *q = p;
	int i;

	BOUNDS_CHECK((p + 1), q, rdlen, end);
	caa.flags = *p;
	p++;
	BOUNDS_CHECK((p + 1), q, rdlen, end);
	caa.taglen = *p;
	p++;
	BOUNDS_CHECK((p + caa.taglen), q, rdlen, end);
	memcpy(&caa.tag, p, caa.taglen);
	p += caa.taglen;
	BOUNDS_CHECK((p + (rdlen - 2 - caa.taglen)), q, rdlen, end);
	caa.valuelen = rdlen - 2 - caa.taglen;
	memcpy(&caa.value, p, caa.valuelen);
	p += caa.valuelen;

	if (f != NULL) {
		safe_fprintf(f, "%u,", caa.flags);
		for (i = 0; i < caa.taglen; i++) {
			safe_fprintf(f, "%c", caa.tag[i]);
		}
		safe_fprintf(f, ",\"");
		for (i = 0; i < caa.valuelen; i++) {
			safe_fprintf(f, "%c", caa.value[i]);
		}
		safe_fprintf(f, "\"\n");
	}

	if (ctx != NULL)
		delphinusdns_HMAC_Update(ctx, q, plength(p, q));

	return (plength(p, estart));
}


int 
raxfr_hinfo(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
{
	struct hinfo hinfo;
	u_char *q = p;
	int i;

	BOUNDS_CHECK((p + 1), q, rdlen, end);
	hinfo.cpulen = *p;
	p++;
	BOUNDS_CHECK((p + hinfo.cpulen), q, rdlen, end);
	memcpy(&hinfo.cpu, p, hinfo.cpulen);
	p += hinfo.cpulen;
	BOUNDS_CHECK((p + 1), q, rdlen, end);
	hinfo.oslen = *p;
	p++;
	BOUNDS_CHECK((p + hinfo.oslen), q, rdlen, end);
	memcpy(&hinfo.os, p, hinfo.oslen);
	p += hinfo.oslen;

	if (f != NULL) {
		safe_fprintf(f, "\"");
		for (i = 0; i < hinfo.cpulen; i++) {
			safe_fprintf(f, "%c", hinfo.cpu[i]);
		}
		safe_fprintf(f, "\",\"");
		for (i = 0; i < hinfo.oslen; i++) {
			safe_fprintf(f, "%c", hinfo.os[i]);
		}
		safe_fprintf(f, "\"\n");
	}

	if (ctx != NULL)
		delphinusdns_HMAC_Update(ctx, q, plength(p, q));

	return (plength(p, estart));
}

int 
raxfr_cds(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
{
	struct cds d;
	uint16_t tmpshort;
	u_char *q = p;

	BOUNDS_CHECK((p + 2), q, rdlen, end);
	tmpshort = unpack16((char *)p);
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
		safe_fprintf(f, "%u,%u,%u,\"%s\"\n", d.key_tag, d.algorithm, 
			d.digest_type, bin2hex(d.digest, d.digestlen));
	}

	if (ctx != NULL)
		delphinusdns_HMAC_Update(ctx, q, plength(p, q));

	return (plength(p, estart));
}

int 
raxfr_ds(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
{
	struct ds d;
	uint16_t tmpshort;
	u_char *q = p;

	BOUNDS_CHECK((p + 2), q, rdlen, end);
	tmpshort = unpack16((char *)p);
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
		safe_fprintf(f, "%u,%u,%u,\"%s\"\n", d.key_tag, d.algorithm, 
			d.digest_type, bin2hex(d.digest, d.digestlen));
	}

	if (ctx != NULL)
		delphinusdns_HMAC_Update(ctx, q, plength(p, q));

	return (plength(p, estart));
}

int 
raxfr_sshfp(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
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
		safe_fprintf(f, "%u,%u,\"%s\"\n", s.algorithm, s.fptype, hex);
	}

	if (ctx != NULL)
		delphinusdns_HMAC_Update(ctx, q, plength(p, q));

	return (plength(p, estart));
}

int 
raxfr_cdnskey(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
{
	struct cdnskey dk;
	uint16_t tmpshort;
	char *b;
	u_char *q = p;
	int len;

	BOUNDS_CHECK((p + 2), q, rdlen, end);
	tmpshort = unpack16((char *)p);
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

	if ((len = mybase64_encode((const u_char *)dk.public_key, dk.publickey_len, b, dk.publickey_len * 2)) < 0) {
		free(b);
		return -1;
	}

	b[len] = '\0';

	if (f != NULL) {
		safe_fprintf(f, "%u,%u,%u,\"%s\"\n", dk.flags, dk.protocol, 
			dk.algorithm, b);
	}

	free(b);

	if (ctx != NULL)
		delphinusdns_HMAC_Update(ctx, q, plength(p, q));

	return (plength(p, estart));
}

int 
raxfr_ipseckey(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
{
	struct ipseckey ipk;
	char *b;
	u_char *q = p;
	int len, remainlen, elen = 0;
	u_char *save;
	u_char expand[256];
	int max = sizeof(expand);

	BOUNDS_CHECK((p + 1), q, rdlen, end);
	ipk.precedence = *p++;
	BOUNDS_CHECK((p + 1), q, rdlen, end);
	ipk.gwtype = *p++;
	BOUNDS_CHECK((p + 1), q, rdlen, end);
	ipk.alg = *p++;
	
	switch (ipk.gwtype) {
	case 0:
		ipk.dnsnamelen = 0;
		break;
	case 1:
		BOUNDS_CHECK((p + 4), q, rdlen, end);
		memcpy(&ipk.gateway.ip4, p, 4);
		p += 4;
		break;
	case 2:
		BOUNDS_CHECK((p + 16), q, rdlen, end);
		memcpy(&ipk.gateway.ip6, p, 16);
		p += 16;
		break;
	case 3:
		memset(&expand, 0, sizeof(expand));
		save = expand_compression(p, estart, end, (u_char *)&expand, &elen, max);
		if (save == NULL) {
			dolog(LOG_ERR, "expanding compression failure\n");
			return -1;
		} else  {
			memcpy(ipk.gateway.dnsname, p, (plength(save, p)));
			ipk.dnsnamelen = (plength(save, p));
			p = (u_char *)save;
		}

		break;
	}

	remainlen = rdlen - (plength(p, q));
	if (remainlen < 0 || remainlen > sizeof(ipk.key)) {
		dolog(LOG_ERR, "keylength out of range\n");
		return -1;
	}

	ipk.keylen = remainlen;
	memcpy(&ipk.key, p, remainlen);
	p += remainlen;


	b = malloc(remainlen * 2);
	if (b == NULL) {
		return -1;
	}

	if ((len = mybase64_encode((const u_char *)ipk.key, ipk.keylen, b, remainlen * 2)) < 0) {
		free(b);
		return -1;
	}

	b[len] = '\0';

	if (f != NULL) {
		safe_fprintf(f, "%u,%u,%u,\"%s\",\"%s\"\n", ipk.precedence, ipk.gwtype,
			ipk.alg, ipseckey_type(&ipk), b);
	}

	free(b);

	if (ctx != NULL)
		delphinusdns_HMAC_Update(ctx, q, plength(p, q));

	return (plength(p, estart));
}

int 
raxfr_cert(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
{
	struct cert certificate;
	uint16_t tmpshort;
	char *b;
	u_char *q = p;
	int len, remainlen;

	BOUNDS_CHECK((p + 2), q, rdlen, end);
	tmpshort = unpack16((char *)p);
	certificate.type = ntohs(tmpshort);
	p += 2;
	
	BOUNDS_CHECK((p + 2), q, rdlen, end);
	tmpshort = unpack16((char *)p); 
	certificate.keytag = ntohs(tmpshort);
	p += 2;

	BOUNDS_CHECK((p + 1), q, rdlen, end);
	certificate.algorithm = *p++;
	
	remainlen = rdlen - (plength(p, q));
	if (remainlen < 0 || remainlen > sizeof(certificate.cert)) {
		dolog(LOG_ERR, "cert length out of range\n");
		return -1;
	}

	certificate.certlen = remainlen;
	memcpy(&certificate.cert, p, remainlen);
	p += remainlen;

	b = malloc(remainlen * 2);
	if (b == NULL) {
		return -1;
	}

	if ((len = mybase64_encode((const u_char *)certificate.cert, 
		certificate.certlen, b, remainlen * 2)) < 0) {
		free(b);
		return -1;
	}

	b[len] = '\0';

	if (f != NULL) {
		safe_fprintf(f, "%s,%u,%u,\"%s\"\n", cert_type(&certificate),
			certificate.keytag, certificate.algorithm, b);
	}

	free(b);

	if (ctx != NULL)
		delphinusdns_HMAC_Update(ctx, q, plength(p, q));

	return (plength(p, estart));
}

int 
raxfr_dnskey(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
{
	struct dnskey dk;
	uint16_t tmpshort;
	char *b;
	u_char *q = p;
	int len;

	BOUNDS_CHECK((p + 2), q, rdlen, end);
	tmpshort = unpack16((char *)p);
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

	if ((len = mybase64_encode((const u_char *)dk.public_key, dk.publickey_len, b, dk.publickey_len * 2)) < 0) {
		free(b);
		return -1;
	}

	b[len] = '\0';

	if (f != NULL) {
		safe_fprintf(f, "%u,%u,%u,\"%s\"\n", dk.flags, dk.protocol, 
			dk.algorithm, b);
	}

	free(b);

	if (ctx != NULL)
		delphinusdns_HMAC_Update(ctx, q, plength(p, q));

	return (plength(p, estart));
}

int 
raxfr_nsec(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
{
	struct nsec n;
	char *save, *humanname;
	u_char *q = p;
	u_char expand[256];
	int max = sizeof(expand);
	int elen = 0;

	memset(&expand, 0, sizeof(expand));
	save = expand_compression(q, estart, end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		safe_fprintf(stderr, "expanding compression failure\n");
		return -1;
	} else  {
		q = (u_char *)save;
	}

	humanname = convert_name((char *)expand, elen);
	if (humanname == NULL) {
		return -1;
	}

	n.bitmap_len = 	(rdlen - (plength(q, p)));
	if (n.bitmap_len > sizeof(n.bitmap))
		return -1;

	memcpy(&n.bitmap, q, n.bitmap_len);
	q += n.bitmap_len;
	

	if (f != NULL) {
		if (*humanname == '\0')
			safe_fprintf(f, ".,\"%s\"\n", bitmap2human(n.bitmap, n.bitmap_len));
		else
			safe_fprintf(f, "%s,\"%s\"\n", humanname, bitmap2human(n.bitmap, n.bitmap_len));
	}

	free(humanname);

	if (ctx != NULL)
		delphinusdns_HMAC_Update(ctx, p, plength(q, p));

	return (plength(q, estart));
}

int 
raxfr_mx(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
{
	uint16_t mxpriority;
	char *save, *humanname;
	u_char *q = p;
	u_char expand[256];
	int max = sizeof(expand);
	int elen = 0;

	BOUNDS_CHECK((q + 2), p, rdlen, end);
	mxpriority = unpack16((char *)q);

	if (f != NULL)
		safe_fprintf(f, "%u,", ntohs(mxpriority));

	q += 2;

	memset(&expand, 0, sizeof(expand));
	save = expand_compression(q, estart, end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		safe_fprintf(stderr, "expanding compression failure 2\n");
		return -1;
	} else  {
		q = (u_char *)save;
	}

	humanname = convert_name((char *)expand, elen);
	if (humanname == NULL) {
		return -1;
	}

	if (f != NULL) {
		if (*humanname == '\0')
			safe_fprintf(f, ".\n");
		else
			safe_fprintf(f, "%s\n", humanname);
	}

	free(humanname);

	if (ctx != NULL)
		delphinusdns_HMAC_Update(ctx, p, plength(q, p));

	return (plength(q, estart));
}

int 
raxfr_kx(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
{
	uint16_t kxpriority;
	char *save, *humanname;
	u_char *q = p;
	u_char expand[256];
	int max = sizeof(expand);
	int elen = 0;

	BOUNDS_CHECK((q + 2), p, rdlen, end);
	kxpriority = unpack16((char *)q);

	if (f != NULL)
		safe_fprintf(f, "%u,", ntohs(kxpriority));

	q += 2;

	memset(&expand, 0, sizeof(expand));
	save = expand_compression(q, estart, end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		safe_fprintf(stderr, "expanding compression failure 2\n");
		return -1;
	} else  {
		q = (u_char *)save;
	}

	humanname = convert_name((char *)expand, elen);
	if (humanname == NULL) {
		return -1;
	}

	if (f != NULL) {
		if (*humanname == '\0')
			safe_fprintf(f, ".\n");
		else
			safe_fprintf(f, "%s\n", humanname);
	}

	free(humanname);

	if (ctx != NULL)
		delphinusdns_HMAC_Update(ctx, p, plength(q, p));

	return (plength(q, estart));
}

int 
raxfr_ptr(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
{
	return (raxfr_ns(f, p, estart, end, mysoa, rdlen, ctx));
}

int
raxfr_nsec3(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
{
	struct nsec3 n;
	uint16_t iter;
	u_char *brr = p;	/* begin of rd record :-) */

	BOUNDS_CHECK((p + 1), brr, rdlen, end);
	n.algorithm = *p++;
	BOUNDS_CHECK((p + 1), brr, rdlen, end);
	n.flags = *p++;

	BOUNDS_CHECK((p + 2), brr, rdlen, end);
	iter = unpack16((char *)p);
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
	
	
	if (((rdlen - (plength(p, brr))) + 1) < 0)
		return -1;

	/* XXX */
	n.bitmap_len = 	(rdlen - (plength(p, brr)));
	if (n.bitmap_len > sizeof(n.bitmap))
		return -1;

	memcpy(&n.bitmap, p, n.bitmap_len);
	p += n.bitmap_len;
	
#if 0
	/* XXX why is this here? */
	bitmap2human(n.bitmap, n.bitmap_len);
#endif

	if (f != NULL) {
		safe_fprintf(f, "%u,%u,%u,\"%s\",\"%s\",\"%s\"\n", n.algorithm, 
			n.flags, n.iterations, 
			(n.saltlen == 0 ? "-" : 
				bin2hex(n.salt, n.saltlen)), 
			base32hex_encode((u_char *)n.next, n.nextlen), 
			bitmap2human(n.bitmap, n.bitmap_len));
	}

	if (ctx != NULL)
		delphinusdns_HMAC_Update(ctx, brr, plength(p, brr));

	return (plength(p, estart));
}

int
raxfr_nsec3param(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
{
	struct nsec3param np;
	uint16_t iter;
	u_char *q = p;

	BOUNDS_CHECK((p + 1), q, rdlen, end);
	np.algorithm = *p++;
	BOUNDS_CHECK((p + 1), q, rdlen, end);
	np.flags = *p++;
	BOUNDS_CHECK((p + 2), q, rdlen, end);
	iter = unpack16((char *)p);
	np.iterations = ntohs(iter);
	p += 2;
	BOUNDS_CHECK((p + 1), q, rdlen, end);
	np.saltlen = *p++;
	BOUNDS_CHECK((p + np.saltlen), q, rdlen, end);
	memcpy(&np.salt, p, np.saltlen);
	p += np.saltlen;
	
	bin2hex(np.salt, np.saltlen);

	if (f != NULL) {
		safe_fprintf(f, "%u,%u,%u,\"%s\"\n", np.algorithm, np.flags, 
			np.iterations, 
			(np.saltlen == 0 ? "-" : bin2hex(np.salt, np.saltlen)));
	}

	if (ctx != NULL)
		delphinusdns_HMAC_Update(ctx, q, plength(p, q));

	return (plength(p, estart));
}

int
raxfr_https(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
{
	char *tmp;
	u_char *q = p;
	uint16_t priority;
	char *save, *humanname;
	u_char expand[256];
	int max = sizeof(expand);
	int elen = 0;

	BOUNDS_CHECK((q + 2), p, rdlen, end);
	priority = unpack16((char *)q);
	q += 2;

	memset(&expand, 0, sizeof(expand));
	save = expand_compression(q, estart, end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		safe_fprintf(stderr, "expanding compression failure 2\n");
		return -1;
	} else  {
		q = (u_char *)save;
	}

	humanname = convert_name((char *)expand, elen);
	if (humanname == NULL) {
		return -1;
	}

	BOUNDS_CHECK(q, p, rdlen, end);

	if (f != NULL) 
		safe_fprintf(f, "%u,%s,\"", ntohs(priority), (*humanname == '\0') ? "." : humanname);

	if (f != NULL) {
		tmp = param_tlv2human(q, plength(&p[rdlen], q), 0);
		if (tmp != NULL) {
			safe_fprintf(f, "%s", tmp);
			free(tmp);
		} 
	}

	q = &p[rdlen];

	if (f != NULL)
		safe_fprintf(f, "\"\n");


	if (ctx != NULL)
		delphinusdns_HMAC_Update(ctx, p, plength(q, p));
	
	return (plength(q, estart));
}

int
raxfr_svcb(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
{
	char *tmp;
	u_char *q = p;
	uint16_t priority;
	char *save, *humanname;
	u_char expand[256];
	int max = sizeof(expand);
	int elen = 0;

	BOUNDS_CHECK((q + 2), p, rdlen, end);
	priority = unpack16((char *)q);
	q += 2;

	memset(&expand, 0, sizeof(expand));
	save = expand_compression(q, estart, end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		safe_fprintf(stderr, "expanding compression failure 2\n");
		return -1;
	} else  {
		q = (u_char *)save;
	}

	humanname = convert_name((char *)expand, elen);
	if (humanname == NULL) {
		return -1;
	}


	BOUNDS_CHECK(q, p, rdlen, end);

	if (f != NULL) 
		safe_fprintf(f, "%u,%s,\"", ntohs(priority), (*humanname == '\0') ? "." : humanname);

	if (f != NULL) {
		tmp = param_tlv2human(q, plength(&p[rdlen], q), 0);
		if (tmp != NULL) {
			safe_fprintf(f, "%s", tmp);
			free(tmp);
		}
	}

	q = &p[rdlen];

	if (f != NULL)
		safe_fprintf(f, "\"\n");

	if (ctx != NULL)
		delphinusdns_HMAC_Update(ctx, p, plength(q, p));
	
	return (plength(q, estart));
}


int
raxfr_txt(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
{
	int i, j;
	u_char *q = p;
	uint16_t segmentlen = 256;

	BOUNDS_CHECK(p, q, rdlen, end);

	if (f != NULL)
		safe_fprintf(f, "\"");

	for (i = 0, j = 0; i < rdlen; i++, j++) {
		if (j % segmentlen == 0) {
			segmentlen = p[i] + 1;
			j = 0;

			if (i && f != NULL)
				safe_fprintf(f, "\",\"");

			continue;
		}

		if (f != NULL) 
			safe_fprintf(f, "%c", p[i]);	
	}
	if (f != NULL)
		safe_fprintf(f, "\"\n");

	p += i;
	
	if (ctx != NULL)
		delphinusdns_HMAC_Update(ctx, q, plength(p, q));
	
	return (plength(p, estart));
}

int
raxfr_rp(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
{
	char *save, *humanname;
	u_char *q = p;
	u_char expand[256];
	int max = sizeof(expand);
	int elen = 0;

	memset(&expand, 0, sizeof(expand));
	save = expand_compression(q, estart, end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		safe_fprintf(stderr, "expanding compression failure 2\n");
		return -1;
	} else  {
		q = (u_char *)save;
	}

	humanname = convert_name((char *)expand, elen);
	if (humanname == NULL) {
		return -1;
	}

	if (f != NULL) {
		safe_fprintf(f, "%s,", humanname);
	}

	free(humanname);

	memset(&expand, 0, sizeof(expand));
	elen = 0;
	save = expand_compression(q, estart, end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		safe_fprintf(stderr, "expanding compression failure 2\n");
		return -1;
	} else  {
		q = (u_char *)save;
	}

	humanname = convert_name((char *)expand, elen);
	if (humanname == NULL) {
		return -1;
	}

	if (f != NULL) {
		safe_fprintf(f, "%s\n", humanname);
	}

	free(humanname);





	if (ctx != NULL) {
		delphinusdns_HMAC_Update(ctx, p, plength(q, p));
	}

	return (plength(q, estart));
}

int
raxfr_ns(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
{
	u_char *q = p;
	char *save, *humanname;
	u_char expand[256];
	int max = sizeof(expand);
	int elen = 0;

	memset(&expand, 0, sizeof(expand));
	save = expand_compression(q, estart, end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		safe_fprintf(stderr, "expanding compression failure 2\n");
		return -1;
	} else  {
		q = (u_char *)save;
	}

	humanname = convert_name((char *)expand, elen);
	if (humanname == NULL) {
		return -1;
	}

	if (f != NULL) {
		if (*humanname == '\0')
			safe_fprintf(f, ".\n");
		else
			safe_fprintf(f, "%s\n", humanname);
	}

	free(humanname);

	if (ctx != NULL) {
		delphinusdns_HMAC_Update(ctx, p, plength(q, p));
	}

	return (plength(q, estart));
}

int 
raxfr_cname(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
{
	return (raxfr_ns(f, p, estart, end, mysoa, rdlen, ctx));
}


int
raxfr_aaaa(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
{
	char buf[INET6_ADDRSTRLEN];
	struct in6_addr ia;
	u_char *q = p;

	BOUNDS_CHECK((p + sizeof(ia)), q, rdlen, end);
	unpack((char *)&ia, (char *)p, sizeof(struct in6_addr));
	inet_ntop(AF_INET6, &ia, buf, sizeof(buf));

	if (f != NULL) 
		safe_fprintf(f, "%s\n", buf);

	p += sizeof(ia);

	if (ctx != NULL)
		delphinusdns_HMAC_Update(ctx, q, plength(p, q));

	return (plength(p, estart));
}

int 
raxfr_loc(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
{
	struct loc l;
	uint32_t tmp32;
	char latitude, longitude;
	uint32_t latsecfrac, latval, latsec, latmin, latdeg;
	uint32_t longsecfrac, longval, longsec, longmin, longdeg;
	int mantissa, exponent;
	uint32_t valsize, valhprec, valvprec;
	static u_int poweroften[10] = {1, 10, 100, 1000, 10000, 100000,
                                 1000000,10000000,100000000,1000000000};

	u_char *q = p;

	BOUNDS_CHECK((q + 1), p, rdlen, end);
	l.version = *q++;
	BOUNDS_CHECK((q + 1), p, rdlen, end);
	l.size = *q++;
	BOUNDS_CHECK((q + 1), p, rdlen, end);
	l.horiz_pre = *q++;
	BOUNDS_CHECK((q + 1), p, rdlen, end);
	l.vert_pre = *q++;
	BOUNDS_CHECK((q + 4), p, rdlen, end);
	tmp32 = unpack32((char *)q);
	l.latitude = ntohl(tmp32);
	q += 4;
	BOUNDS_CHECK((q + 4), p, rdlen, end);
	tmp32 = unpack32((char *)q);
	l.longitude = ntohl(tmp32);
	q += 4;
	BOUNDS_CHECK((q + 4), p, rdlen, end);
	tmp32 = unpack32((char *)q);
	l.altitude = ntohl(tmp32);
	q += 4;

	if (l.version != 0) {
		safe_fprintf(stderr, "wrong version\n");
		return -1;
	}
	
	if (l.longitude > (1 << 31)) {	
		longitude = 'E';
		longval = l.longitude - (1 << 31);
	} else {
		longitude = 'W';
		longval = l.longitude;
	}

	if (l.latitude > (1 << 31)) {
		latitude = 'N';
		latval = l.latitude - (1 << 31);
	} else {
		latitude = 'S';
		latval = l.latitude;
	}
		
	latsecfrac = latval % 1000;
	latval = latval / 1000;
	latsec = latval % 60;
	latval = latval / 60;
	latmin = latval % 60;
	latval = latval / 60;
	latdeg = latval;

	longsecfrac = longval % 1000;
	longval = longval / 1000;
	longsec = longval % 60;
	longval = longval / 60;
	longmin = longval % 60;
	longval = longval / 60;
	longdeg = longval;

	mantissa = (int)((l.size >> 4) & 0x0f) % 10;
	exponent = (int)((l.size >> 0) & 0x0f) % 10;

	valsize = mantissa * poweroften[exponent];

	mantissa = (int)((l.horiz_pre >> 4) & 0x0f) % 10;
	exponent = (int)((l.horiz_pre >> 0) & 0x0f) % 10;

	valhprec = mantissa * poweroften[exponent];
	
	mantissa = (int)((l.vert_pre >> 4) & 0x0f) % 10;
	exponent = (int)((l.vert_pre >> 0) & 0x0f) % 10;

	valvprec = mantissa * poweroften[exponent];

	if (f != NULL) {
		safe_fprintf(f, "%u,%u,%u.%.3u,%c,%u,%u,%u.%.3u,%c,%u,%u,%u,%u\n",
			latdeg, latmin, latsec, latsecfrac, latitude,
			longdeg, longmin, longsec, longsecfrac, longitude,
			l.altitude, valsize, valhprec, valvprec);
	}

	if (ctx != NULL)
		delphinusdns_HMAC_Update(ctx, p, plength(q, p));

	return (plength(q, estart));
}

int
raxfr_a(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
{
	char buf[INET_ADDRSTRLEN];
	struct in_addr ia;
	u_char *q = p;

	BOUNDS_CHECK((p + sizeof(ia)), q, rdlen, end);
	ia.s_addr = unpack32((char *)p);

	inet_ntop(AF_INET, &ia, buf, sizeof(buf));
	
	if (f != NULL)
		safe_fprintf(f, "%s\n", buf);

	p += sizeof(ia);

	if (ctx != NULL)
		delphinusdns_HMAC_Update(ctx, q, plength(p, q));

	return (plength(p, estart));
}

int
raxfr_eui48(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
{
	uint8_t e[6];
	u_char *q = p;

	BOUNDS_CHECK((p + 6), q, rdlen, end);
	memcpy(&e, p, 6);

	if (f != NULL)
		safe_fprintf(f, "\"%02x-%02x-%02x-%02x-%02x-%02x\"\n", e[0]
			, e[1], e[2], e[3], e[4], e[5]);

	p += 6;

	if (ctx != NULL)
		delphinusdns_HMAC_Update(ctx, q, plength(p, q));

	return (plength(p, estart));
}

int
raxfr_eui64(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
{
	u_char *q = p;
	uint8_t e[8];

	BOUNDS_CHECK((p + 8), q, rdlen, end);
	memcpy(&e, p, 8);

	if (f != NULL)
		safe_fprintf(f, "\"%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x\"\n", e[0]
			, e[1], e[2], e[3], e[4], e[5], e[6], e[7]);

	p += 8;

	if (ctx != NULL)
		delphinusdns_HMAC_Update(ctx, q, plength(p, q));

	return (plength(p, estart));
}

int 
raxfr_tlsa(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
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
		safe_fprintf(f, "%u,%u,%u,\"%s\"\n", t.usage, t.selector, 
			t.matchtype, bin2hex(t.data, t.datalen));
	}

	if (ctx != NULL)
		delphinusdns_HMAC_Update(ctx, q, plength(p, q));

	return (plength(p, estart));
}

int 
raxfr_srv(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
{
	uint16_t tmp16;
	struct srv s;
	char *save, *humanname;
	u_char *q = p;
	u_char expand[256];
	int max = sizeof(expand);
	int elen = 0;

	BOUNDS_CHECK((q + 2), p, rdlen, end);
	tmp16 = unpack16((char *)q);
	s.priority = ntohs(tmp16);
	q += 2;
	BOUNDS_CHECK((q + 2), p, rdlen, end);
	tmp16 = unpack16((char *)q);
	s.weight = ntohs(tmp16);
	q += 2;
	BOUNDS_CHECK((q + 2), p, rdlen, end);
	tmp16 = unpack16((char *)q);
	s.port = ntohs(tmp16);
	q += 2;

	memset(&expand, 0, sizeof(expand));
	save = expand_compression(q, estart, end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		safe_fprintf(stderr, "expanding compression failure 2\n");
		return -1;
	} else  {
		q = (u_char *)save;
	}

	humanname = convert_name((char *)expand, elen);
	if (humanname == NULL) {
		return -1;
	}

	if (f != NULL) {
		if (*humanname == '\0')
			safe_fprintf(f, "%u,%u,%u,.\n", s.priority, s.weight, s.port);
		else
			safe_fprintf(f, "%u,%u,%u,%s\n", s.priority, s.weight,
				s.port, humanname);
	}

	free(humanname);

	if (ctx != NULL)
		delphinusdns_HMAC_Update(ctx, p, plength(q, p));

	return (plength(q, estart));
}

int 
raxfr_naptr(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx)
{
	uint16_t tmp16;
	struct naptr n;
	char *save, *humanname;
	u_char *q = p;
	u_char expand[256];
	int max = sizeof(expand);
	int elen = 0;
	int len, i;

	BOUNDS_CHECK((q + 2), p, rdlen, end);
	tmp16 = unpack16((char *)q);
	n.order = ntohs(tmp16);
	q += 2;
	BOUNDS_CHECK((q + 2), p, rdlen, end);
	tmp16 = unpack16((char *)q);
	n.preference = ntohs(tmp16);
	q += 2;

	if (f != NULL) {
		safe_fprintf(f, "%u,%u,", n.order, n.preference);
	}

	
	/* flags */
	BOUNDS_CHECK((q + 1), p, rdlen, end);
	len = *q;
	q++;

	if (f != NULL) {
		safe_fprintf(f, "\"");
		for (i = 0; i < len; i++) {
			BOUNDS_CHECK((q + 1), p, rdlen, end);
			safe_fprintf(f, "%c", *q++);
		}
		safe_fprintf(f, "\",");
	}
	/* services */
	BOUNDS_CHECK((q + 1), p, rdlen, end);
	len = *q;
	q++;

	if (f != NULL) {
		safe_fprintf(f, "\"");
		for (i = 0; i < len; i++) {
			BOUNDS_CHECK((q + 1), p, rdlen, end);
			safe_fprintf(f, "%c", *q++);
		}
		safe_fprintf(f, "\",");
	}
	/* regexp */
	BOUNDS_CHECK((q + 1), p, rdlen, end);
	len = *q;
	q++;

	if (f != NULL) {
		safe_fprintf(f, "\"");
		for (i = 0; i < len; i++) {
			BOUNDS_CHECK((q + 1), p, rdlen, end);
			safe_fprintf(f, "%c", *q++);
		}
		safe_fprintf(f, "\",");
	}

	memset(&expand, 0, sizeof(expand));
	save = expand_compression(q, estart, end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		safe_fprintf(stderr, "expanding compression failure 2\n");
		return -1;
	} else  {
		q = (u_char *)save;
	}

	humanname = convert_name((char *)expand, elen);
	if (humanname == NULL) {
		return -1;
	}

	if (f != NULL) {
		if (*humanname == '\0')
			safe_fprintf(f, ".\n");
		else
			safe_fprintf(f, "%s\n", humanname);
	}

	free(humanname);

	if (ctx != NULL)
		delphinusdns_HMAC_Update(ctx, p, plength(q, p));

	return (plength(q, estart));
}

int 
raxfr_tsig(FILE *f, u_char *p, u_char *estart, u_char *end, struct soa *mysoa, uint16_t rdlen, DDD_HMAC_CTX *ctx, char *mac, int standardanswer)
{
	struct dns_tsigrr *sdt;
	char *save;
	char *keyname = NULL, *algname = NULL;
	char *rawkeyname = NULL, *rawalgname = NULL;
	char *otherdata;
	u_char expand[256];
	u_char *q = p;
	uint16_t rtype, rclass, tsigerror, otherlen;
	uint32_t rttl;
	int rlen, rrlen = -1;
	int elen = 0;
	int max = sizeof(expand);
	int rawkeynamelen, rawalgnamelen;
	int macsize = 32;
	
	memset(&expand, 0, sizeof(expand));
	save = expand_compression(q, estart, end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		safe_fprintf(stderr, "expanding compression failure 0\n");
		goto out;
	} else 
		q = (u_char *)save;

	keyname = convert_name((char *)expand, elen);
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

	rtype = unpack16((char *)q);
	q += 2;

	if (ntohs(rtype) != DNS_TYPE_TSIG)	
		goto out;
	
	if ((q + 2) > end)
		goto out;

	rclass = unpack16((char *)q);
	q += 2;

	if (ntohs(rclass) != DNS_CLASS_ANY)
		goto out;

	if ((q + 4) > end)
		goto out;

	rttl = unpack32((char *)q);
	q += 4;

	if (rttl != 0)
		goto out;

	/* skip rdlen because raxfr_peek already got it */
	if ((q + 2) > end)
		goto out;
	q += 2;

	rlen = (plength(q, estart));

	memset(&expand, 0, sizeof(expand));
	elen = 0;
	save = expand_compression(q, estart, end, (u_char *)&expand, &elen, max);
	if (save == NULL) {
		safe_fprintf(stderr, "expanding compression failure 0\n");
		goto out;
	} else 
		q = (u_char *)save;

	
	algname = convert_name((char *)expand, elen);
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

	q += 2;

	if ((q + 2) > end)
		goto out;

	tsigerror = unpack16((char *)q);
	q += 2;
		
	if ((q + 2) > end)
		goto out;

	otherlen = unpack16((char *)q);
	q += 2;

	otherdata = (char *)q;
	q += ntohs(otherlen);

	if ((plength(q, estart)) != (rdlen + rlen)) {
		goto out;
	}

	/* do something with the gathered data */

	if (standardanswer) {
		/* dns message */
		delphinusdns_HMAC_Update(ctx, (const u_char *)rawkeyname, rawkeynamelen);
		delphinusdns_HMAC_Update(ctx, (const u_char *)&rclass, 2);
		delphinusdns_HMAC_Update(ctx, (const u_char *)&rttl, 4);
		delphinusdns_HMAC_Update(ctx, (const u_char *)rawalgname, rawalgnamelen);
		delphinusdns_HMAC_Update(ctx, (const u_char *)&sdt->timefudge, 8);
		delphinusdns_HMAC_Update(ctx, (const u_char *)&tsigerror, 2);
		delphinusdns_HMAC_Update(ctx, (const u_char *)&otherlen, 2);
		if (ntohs(otherlen))
			delphinusdns_HMAC_Update(ctx, (const u_char *)otherdata, ntohs(otherlen));

	} else {
		delphinusdns_HMAC_Update(ctx, (const u_char *)&sdt->timefudge, 8);
	}

	if (delphinusdns_HMAC_Final(ctx, (u_char *)mac, (u_int *)&macsize) != 1) {
		goto out;
	}

#if defined __OpenBSD__ || defined __FreeBSD__
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

	rrlen = (plength(q, estart));

out:
	free(keyname);
	free(algname);
	free(rawkeyname);
	free(rawalgname);
	return (rrlen);
}


void
replicantloop(ddDB *db, struct imsgbuf *ibuf)
{
	time_t now, lastnow;
	int sel, endspurt = 0;
	int64_t serial;
	struct rbtree *rbt;
	struct rrset *rrset;
	struct rr *rrp;
	struct timeval tv;
	struct rzone *lrz, *lrz0;
#if DEBUG
	struct stat sb;
#endif
	struct imsg imsg;
	fd_set rset;
	int max = 0;
	int fd;

	ssize_t         n, datalen;
	char *dn = NULL;	
	char *humanconv = NULL;

	int period, tot_refresh = 0, zonecount = 1;
	int add_period = 0;

	struct iwantmanna {
		pid_t pid;
		char zone[DNS_MAXNAME + 1];
	} iw;


#if __OpenBSD__
	if (pledge("stdio wpath rpath cpath inet sendfd unveil", NULL) < 0) {
		perror("pledge");
		ddd_shutdown();
		exit(1);
	}
	if (unveil("/", "rwc") == -1) {
		perror("unveil");
		ddd_shutdown();
		exit(1);
	}
	if (unveil(NULL, NULL) == -1) {
		perror("unveil");
		ddd_shutdown();
		exit(1);
	}
#endif

	lastnow = time(NULL);

	SLIST_FOREACH_SAFE(lrz, &rzones, rzone_entry, lrz0) {
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
			continue;
		}
		rrp = TAILQ_FIRST(&rrset->rr_head);
		if (rrp == NULL) {
			dolog(LOG_INFO, "SOA record corrupted for zone %s, removing zone from replicant engine\n", lrz->zonename);
			SLIST_REMOVE(&rzones, lrz, rzone, rzone_entry);
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

	}

	period = (tot_refresh / zonecount) / zonecount;
	add_period = period;

	SLIST_FOREACH_SAFE(lrz, &rzones, rzone_entry, lrz0) {
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
				dolog(LOG_INFO, "sigpipe on child?  raxfr process exiting.\n");
				exit(1);
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
					case IMSG_IWANTMANNA_MESSAGE:
							if (datalen != sizeof(iw)) {
								dolog(LOG_INFO, "invalid IWANTMANNA request\n");
								break;
							}

							memcpy(&iw, imsg.data, datalen);
							/*
							 * grab the pid of the process and give them the
							 * filedescriptor
							 */
#if DEBUG
							dolog(LOG_INFO, "ok one manna for zone \"%s\" going to pid %d!\n", iw.zone, iw.pid);
#endif

							SLIST_FOREACH(lrz, &rzones, rzone_entry) {
								if (lrz->zonename == NULL)
									continue;

								if (strcmp(lrz->zonename, iw.zone) == 0) {
									char *p;

									p = strrchr(lrz->filename, '/');
									if (p == NULL)
										p = lrz->filename;
									else
										p++;

									fd = open(p, O_RDONLY, 0);
									if (fd == -1) {
										dolog(LOG_INFO, "%s: %s\n", 
											lrz->filename, strerror(errno));
										break;
									}
								}
							}

#if DEBUG
							fstat(fd, &sb);
							dolog(LOG_INFO, "inode == %lu\n", sb.st_ino);
#endif
							
							imsg_compose(ibuf, IMSG_HEREISMANNA_MESSAGE,
									0, 0, fd, &iw, sizeof(iw));

							msgbuf_write(&ibuf->w);
							endspurt = 0;

							
							break;
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
										memcasecmp((u_char*)lrz->zone, (u_char*)dn, datalen) == 0)
											break;
						}

						if (lrz != NULL) {
								dolog(LOG_DEBUG, "zone %s is being notified now\n", lrz->zonename);
								if ((serial = get_remote_soa(lrz)) == MY_SOCK_TIMEOUT) {
										dolog(LOG_INFO, "timeout (or tsig failure) upon notify, dropping\n");
								} else if (serial > lrz->soa.serial) {
										/* initiate AXFR and update zone */
										dolog(LOG_INFO, "zone %s new higher serial detected (%lld vs. %d)\n", lrz->zonename, serial, lrz->soa.serial);

										if (pull_rzone(lrz, now) < 0) {
											dolog(LOG_INFO, "AXFR failed\n");
										} else {
												schedule_restart(lrz->zonename, now + rand_restarttime());
												endspurt = 1;
												imsg_compose(ibuf, IMSG_IHAVEMANNA_MESSAGE,
													0, 0, -1, lrz->zonename, 
													strlen(lrz->zonename) + 1);

												msgbuf_write(&ibuf->w);
										}
										lrz->soa.serial = serial;

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

		LIST_FOREACH_SAFE(sp0, &myschedules, myschedule_entry, sp1) {
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
							dolog(LOG_INFO, "zone %s new higher serial detected (%lld vs. %d)\n", lrz->zonename, serial, lrz->soa.serial);

							if (pull_rzone(lrz, now) < 0) {
								dolog(LOG_ERR, "AXFR for zone %s failed\n", lrz->zonename);
								schedule_retry(lrz->zonename, now + lrz->soa.retry);
								goto out;
							}

							/* schedule restart */
							schedule_restart(lrz->zonename, now + rand_restarttime());
							lrz->soa.serial = serial;
							endspurt = 1;

							imsg_compose(ibuf, IMSG_IHAVEMANNA_MESSAGE,
								0, 0, -1, lrz->zonename, 
								strlen(lrz->zonename) + 1);

							msgbuf_write(&ibuf->w);
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

							dolog(LOG_INFO, "zone %s new higher serial detected (%lld vs. %d)\n", lrz->zonename, serial, lrz->soa.serial);

							if (pull_rzone(lrz, now) < 0) {
								dolog(LOG_ERR, "AXFR for zone %s failed\n", lrz->zonename);
								schedule_retry(lrz->zonename, now + lrz->soa.retry);
								goto out;
							}

							/* schedule restart */
							schedule_restart(lrz->zonename, now + rand_restarttime());
							lrz->soa.serial = serial;

							endspurt = 1;

							imsg_compose(ibuf, IMSG_IHAVEMANNA_MESSAGE,
								0, 0, -1, lrz->zonename, 
								strlen(lrz->zonename) + 1);

							msgbuf_write(&ibuf->w);

					  } else {
							schedule_refresh(lrz->zonename, now + lrz->soa.refresh);
						}
					}
				
					goto out;
				} else if (sp0->action == SCHEDULE_ACTION_RESTART) {
					/* we hit a scheduling on restarting, nothing can save you now! */
					dolog(LOG_INFO, "I'm supposed to restart now, RESTART\n");

#if 0
					idata = 1;
					imsg_compose(ibuf, IMSG_RELOAD_MESSAGE, 
						0, 0, -1, &idata, sizeof(idata));
					msgbuf_write(&ibuf->w);
					for (;;)
						sleep(1);
#endif
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

	return; /* XXX turned off for now */

	LIST_FOREACH(sp0, &myschedules, myschedule_entry) {
		if (sp0->action == SCHEDULE_ACTION_RESTART)
			break;
	}

	if (sp0 != NULL) {
		dolog(LOG_INFO, "found an existing restart entry, scheduling restart at %s", ctime(&sp0->when));
		return;
	}

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
	uint16_t rdlen;
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
	uint16_t *tcpsize;
	uint16_t *plen;
	uint16_t tcplen;

	FILE *f = NULL;
	int format = 0;
	int dotsig = 1;
	int seen_tsig = 0;
	time_t now;
	
	char shabuf[32];
	char *algname = NULL;

	DDD_HMAC_CTX *ctx;
	const DDD_EVP_MD *md;
	uint16_t hmaclen;
	int sacount = 0;
	

	if ((so = socket(rzone->storage.ss_family, SOCK_STREAM, 0)) < 0) {
		dolog(LOG_INFO, "get_remote_soa: %s\n", strerror(errno));
		return MY_SOCK_TIMEOUT;
	}

	if (rzone->storage.ss_family == AF_INET6) {
		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_family = AF_INET6;
		sin6.sin6_port = htons(rzone->primaryport);
		memcpy(&sin6.sin6_addr, (void *)&((struct sockaddr_in6 *)(&rzone->storage))->sin6_addr, sizeof(struct in6_addr));
#ifndef __linux__
		sin6.sin6_len = sizeof(struct sockaddr_in6);
#endif
		sa = (struct sockaddr *)&sin6;
		slen = sizeof(struct sockaddr_in6);
	} else {
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons(rzone->primaryport);
		sin.sin_addr.s_addr = ((struct sockaddr_in *)(&rzone->storage))->sin_addr.s_addr;
		sa = (struct sockaddr *)&sin;
	}

	if (rzone->tsigkey != NULL && strcmp(rzone->tsigkey, "NOKEY") != 0) {

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
                dolog(LOG_INFO, "connect to primary %s port %u: %s\n", rzone->primary, rzone->primaryport, strerror(errno));
				close(so);
				return(MY_SOCK_TIMEOUT);
        }



	replysize = 0xffff;
	memset(&query, 0, sizeof(query));
	
	tcpsize = (uint16_t *)&query[0];
	wh = (struct whole_header *)&query[2];

	wh->dh.id = htons(arc4random_uniform(0xffff));
	wh->dh.query = 0;
	wh->dh.question = htons(1);
	wh->dh.answer = 0;
	wh->dh.nsrr = 0;
	wh->dh.additional = 0;

	SET_DNS_QUERY(&wh->dh);
	SET_DNS_RECURSION(&wh->dh);

	
	HTONS(wh->dh.query);

	totallen = sizeof(struct whole_header) + 2;

	name = (u_char *)dns_label(rzone->zonename, &len);
	if (name == NULL) {
		close(so);
		return(MY_SOCK_TIMEOUT);
	}

	zonelen = len;
	
	p = (u_char *)&wh[1];	
	
	memcpy(p, name, len);
	totallen += len;

	pack16(&query[totallen], htons(DNS_TYPE_SOA));
	totallen += sizeof(uint16_t);
	
	pack16(&query[totallen], htons(DNS_CLASS_IN));
	totallen += sizeof(uint16_t);

	/* we have a key, attach a TSIG payload */
	if (dotsig) {
		ctx = delphinusdns_HMAC_CTX_new();
		md = (DDD_EVP_MD *)delphinusdns_EVP_get_digestbyname("sha256");
		if (md == NULL) {
			safe_fprintf(stderr, "md failed\n");
			return (MY_SOCK_TIMEOUT);
		}
		delphinusdns_HMAC_Init_ex(ctx, tsigpass, tsigpasslen, md, NULL);
		delphinusdns_HMAC_Update(ctx, (const u_char *)&query[2], totallen - 2);

		now = time(NULL);
		if (tsig_pseudoheader(rzone->tsigkey, DEFAULT_TSIG_FUDGE, now, ctx) < 0) {
			safe_fprintf(stderr, "tsig_pseudoheader failed\n");
			return(MY_SOCK_TIMEOUT);
		}

		delphinusdns_HMAC_Final(ctx, (u_char *)shabuf, (u_int *) &len);

		if (len != 32) {
			safe_fprintf(stderr, "not expected len != 32\n");
			return(MY_SOCK_TIMEOUT);
		}

		delphinusdns_HMAC_CTX_free(ctx);

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
		pack16(&query[totallen], htons(DEFAULT_TSIG_FUDGE));
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

	plen = (uint16_t *)reply;
	tcplen = ntohs(*plen);

	if ((len = recv(so, reply, tcplen + 2, MSG_WAITALL)) < 0) {
		dolog(LOG_INFO, "recv: %s\n", strerror(errno));
		close(so);
		free(reply);  free(dupreply);
		return(MY_SOCK_TIMEOUT);
	}

	memcpy(dupreply, reply, len);
	rwh = (struct whole_header *)&reply[2];

	end = (u_char *)&reply[len];

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

	q = build_question((char *)dupreply + 2, len - 2, ntohs(wh->dh.additional), NULL);
	if (q == NULL) {
		dolog(LOG_INFO, "failed to build_question\n");
		close(so);
		free(reply);  free(dupreply);
		return(MY_SOCK_TIMEOUT);
	}
		
	if (memcasecmp((u_char *)q->hdr->name, (u_char *)name, q->hdr->namelen) != 0) {
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
	p += sizeof(uint16_t);	 	/* type */
	p += sizeof(uint16_t);		/* class */

	/* end of question */
	

	estart = (u_char *)&rwh->dh;

	if (dotsig) {
		ctx = delphinusdns_HMAC_CTX_new();
		md = (DDD_EVP_MD *)delphinusdns_EVP_get_digestbyname("sha256");
		if (md == NULL) {
			dolog(LOG_INFO, "md failed\n");
			close(so);
			free(reply);  free(dupreply);
			return(MY_SOCK_TIMEOUT);
		}
		delphinusdns_HMAC_Init_ex(ctx, tsigpass, tsigpasslen, md, NULL);
		hmaclen = htons(32);
		delphinusdns_HMAC_Update(ctx, (u_char *)&hmaclen, sizeof(hmaclen));
		delphinusdns_HMAC_Update(ctx, (u_char *)shabuf, sizeof(shabuf));
		hmaclen = rwh->dh.additional;		/* save additional */
		NTOHS(rwh->dh.additional);
		if (rwh->dh.additional)
			rwh->dh.additional = nowrap_dec(rwh->dh.additional, 1);
		HTONS(rwh->dh.additional);
		delphinusdns_HMAC_Update(ctx, estart, (plength(p, estart)));
		rwh->dh.additional = hmaclen;		/* restore additional */
	}


	for (i = answers; i > 0; i--) {
		if ((rrlen = raxfr_peek(f, p, estart, end, &rrtype, 0, &rdlen, format, (dotsig == 1) ? ctx : NULL, (char *)name, zonelen, 0)) < 0) {
			dolog(LOG_INFO, "not a SOA reply, or ERROR\n");
			close(so);
			free(reply);  free(dupreply);
			return(MY_SOCK_TIMEOUT);
		}
		
		if (rrtype != DNS_TYPE_TSIG) 
			p = (estart + rrlen);

		if (rrtype == DNS_TYPE_SOA) {
			if ((len = raxfr_soa(f, p, estart, end, &mysoa, soacount, format, rdlen, (dotsig == 1) ? ctx : NULL, &rz->constraints)) < 0) {
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
				safe_fprintf(stderr, "error with TSIG record\n");
				close(so);
				free(reply);  free(dupreply);
				return(MY_SOCK_TIMEOUT);
			}

			seen_tsig = 1;

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
		delphinusdns_HMAC_CTX_free(ctx);
	}

	if (dotsig && seen_tsig != 1)
		return(MY_SOCK_TIMEOUT);

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

#define TSIGPASS_SIZE	512
#define HUMANPASS_SIZE  1024

	char *tsigpass;
	char *humanpass;
	char *keyname;
	int tsigpasslen, keynamelen;
	uint32_t format = (TCP_FORMAT | ZONE_FORMAT);
	int len, dotsig = 1;
	int segment = 0;
	int answers = 0;
	int additionalcount = 0;

	struct soa mysoa;

#if __OpenBSD__
	if ((tsigpass = calloc_conceal(1, TSIGPASS_SIZE)) == NULL) { 
#else
	if ((tsigpass = calloc(1, TSIGPASS_SIZE)) == NULL) {
#endif
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		return -1;
	}

#if __OpenBSD__
	if ((humanpass = calloc_conceal(1, HUMANPASS_SIZE)) == NULL) { 
#else
	if ((humanpass = calloc(1, HUMANPASS_SIZE)) == NULL) {
#endif
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
#if __OpenBSD__
		freezero(tsigpass, TSIGPASS_SIZE);
#else
		explicit_bzero(tsigpass, TSIGPASS_SIZE);
		free(tsigpass);
#endif
	}

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
		sin6.sin6_port = htons(rzone->primaryport);
		memcpy(&sin6.sin6_addr, (void *)&((struct sockaddr_in6 *)(&rzone->storage))->sin6_addr, sizeof(struct in6_addr));
#ifndef __linux__
		sin6.sin6_len = sizeof(struct sockaddr_in6);
#endif
		sa = (struct sockaddr *)&sin6;
		slen = sizeof(struct sockaddr_in6);
	} else {
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons(rzone->primaryport);
		sin.sin_addr.s_addr = ((struct sockaddr_in *)(&rzone->storage))->sin_addr.s_addr;
		sa = (struct sockaddr *)&sin;
	}

        if (connect(so, sa, slen) < 0) {
                dolog(LOG_INFO, "connect to primary %s port %u: %s\n", rzone->primary, rzone->primaryport, strerror(errno));
		close(so);
		return -1;
        }

	if (rzone->tsigkey != NULL && strcmp(rzone->tsigkey, "NOKEY") != 0) {
		keyname = dns_label(rzone->tsigkey, &keynamelen);
		if (keyname == NULL) {
			dolog(LOG_ERR, "dns_label failed\n");
			close(so);
			goto cleanup;
		}

		if ((tsigpasslen = find_tsig_key(keyname, keynamelen, (char *)tsigpass, TSIGPASS_SIZE)) < 0) {
			dolog(LOG_ERR, "do not have a record of TSIG key %s\n", rzone->tsigkey);
			close(so);
			goto cleanup;
		}

		free(keyname);

		if ((len = mybase64_encode((const u_char *)tsigpass, tsigpasslen, humanpass, HUMANPASS_SIZE)) < 0) {
			dolog(LOG_ERR, "base64_encode() failed\n");
			close(so);
			goto cleanup;
		}

		humanpass[len] = '\0';
	} else {
		dotsig = 0;
	}

	segment = 0;
	answers = 0;
	additionalcount = 0;

	if ((format & ZONE_FORMAT) && f != NULL) 
		safe_fprintf(f, "zone \"%s\" {\n", rzone->zonename);

	if (lookup_axfr(f, so, rzone->zonename, &mysoa, format, ((dotsig == 0) ? NULL : rzone->tsigkey), humanpass, &segment, &answers, &additionalcount, &rzone->constraints, rzone->bytelimit, replicant_axfr_old_behaviour) < 0) {
		/* close the zone */
		if ((format & ZONE_FORMAT) && f != NULL)
			safe_fprintf(f, "}\n");

		dolog(LOG_ERR, "lookup_axfr() failed\n");
		close(so);
		goto cleanup;
	}

	if ((format & ZONE_FORMAT) && f != NULL)
		safe_fprintf(f, "}\n");
				
	close(so);

#if __OpenBSD__
	freezero(tsigpass, TSIGPASS_SIZE);
	freezero(humanpass, HUMANPASS_SIZE);
#else
	explicit_bzero(tsigpass, TSIGPASS_SIZE);
	free(tsigpass);
	explicit_bzero(humanpass, HUMANPASS_SIZE);
	free(humanpass);
#endif

	return (0);

cleanup:
#if __OpenBSD__
	freezero(tsigpass, TSIGPASS_SIZE);
	freezero(humanpass, HUMANPASS_SIZE);
#else
	explicit_bzero(tsigpass, TSIGPASS_SIZE);
	free(tsigpass);
	explicit_bzero(humanpass, HUMANPASS_SIZE);
	free(humanpass);
#endif

	return -1;
}


int
pull_rzone(struct rzone *rzone, time_t now)
{
	int fd;
	char *p, *q;
	char save;
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

	save = *p;
	*p = '\0';

	if (access(".", W_OK | R_OK) == -1) {
		dolog(LOG_INFO, "%s: %s (must be writable and readable by %s)\n", rzone->filename, strerror(errno), DEFAULT_PRIVILEGE);
		*p = save;
		return -1;
	}

	*p = save;
	snprintf(buf, sizeof(buf), "%s.XXXXXXXXXXXXXX", p);	
	if ((fd = mkstemp(buf)) == -1) {
		dolog(LOG_INFO, "mkstemp: %s\n", rzone->filename, strerror(errno));
		return -1;
	}

	p = &buf[0];
	umask(022);
		
	f = fdopen(fd, "w");
	if (f == NULL) {
		dolog(LOG_INFO, "fdopen %s: %s\n", rzone->zonename, strerror(errno));
		return -1;
	}

#if __linux__ || __FreeBSD__
	safe_fprintf(f, "; REPLICANT file for zone %s gotten on %lu\n\n", rzone->zonename, now);
#else
	safe_fprintf(f, "; REPLICANT file for zone %s gotten on %lld\n\n", rzone->zonename, now);
#endif
	
	if (do_raxfr(f, rzone) < 0) {
		dolog(LOG_INFO, "do_raxfr failed\n");
		fclose(f);
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
	return (80 + arc4random_uniform(40));
}
