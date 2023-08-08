/*
 * Copyright (c) 2002-2023 Peter J. Philipp <pbug44@delphinusdns.org>
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
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <ctype.h>


#ifdef __linux__
#include <grp.h>
#define __USE_BSD 1
#include <endian.h>
#include <bsd/stdlib.h>
#include <bsd/string.h>
#include <bsd/unistd.h>
#include <bsd/vis.h>
#include <bsd/sys/queue.h>
#define __unused
#include <bsd/sys/tree.h>
#include <bsd/sys/endian.h>
#include "imsg.h"
#else /* not linux */
#include <vis.h>
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
#include "ddd-config.h"

/* prototypes */

void 			pack(char *, char *, int);
void 			pack32(char *, uint32_t);
void 			pack16(char *, uint16_t);
void 			pack8(char *, uint8_t);
uint32_t 		unpack32(char *);
uint16_t 		unpack16(char *);
void 			unpack(char *, char *, int);
int 			lower_dnsname(char *, int); 
int 			randomize_dnsname(char *, int);
ddDB *			ddd_read_manna(ddDB *, struct imsgbuf *, struct cfg *);
int			iwqueue_count(void);
ddDB *			rebuild_db(struct cfg *);
void			iwqueue_add(struct iwantmanna *, int);

int 			label_count(char *);
char * 			dns_label(char *, int *);
char * 			advance_label(char *, int *);
void 			ddd_shutdown(void);
int 			get_record_size(ddDB *, char *, int);
struct rbtree * 	get_soa(ddDB *, struct question *);
struct rbtree *		get_ns(ddDB *, struct rbtree *, int *);
struct rbtree * 	lookup_zone(ddDB *, struct question *, int *, int *, char *, int);
struct rbtree *		Lookup_zone(ddDB *, char *, uint16_t, uint16_t, int);
uint16_t 		check_qtype(struct rbtree *, uint16_t, int, int *);
struct question	*	build_fake_question(char *, int, uint16_t, char *, int);

char *			get_dns_type(int, int);
int 			memcasecmp(u_char *, u_char *, int);
int 			compress_label(u_char *, uint16_t, int);
struct question	*	build_question(char *, int, uint16_t, char *);
int			free_question(struct question *);
struct rrtab *		rrlookup(char *);
char * 			expand_compression(u_char *, u_char *, u_char *, u_char *, int *, int);
void 			log_diff(char *sha256, char *mac, int len);
int 			tsig_pseudoheader(char *, uint16_t, time_t, DDD_HMAC_CTX *);
char * 			bin2hex(char *, int);
uint64_t 		timethuman(time_t);
char * 			bitmap2human(char *, int);
int 			lookup_axfr(FILE *, int, char *, struct soa *, uint32_t, char *, char *, int *, int *, int *, struct soa_constraints *, uint32_t, int);
int			dn_contains(char *, int, char *, int);
uint16_t		udp_cksum(uint16_t *, uint16_t, struct ip *, struct udphdr *);
uint16_t		udp_cksum6(uint16_t *, uint16_t, struct ip6_hdr *, struct udphdr *);
char *			canonical_sort(char **, int, int *);
static int 		cs_cmp(const void *, const void *);
int 			add_cookie(char *, int, int, DDD_BIGNUM *, u_char *, int);
static uint16_t 	svcb_paramkey(char *);
char * 			param_tlv2human(char *, int, int);
int 			param_human2tlv(char *, char *, int *);
static int 		param_cmp(const void *, const void *);
static char * 		param_expand(char *, int, int);
char * 			ipseckey_type(struct ipseckey *);
char * 			input_sanitize(char *);
void 			safe_fprintf(FILE *, char *, ...);
size_t 			plength(void *, void *);
size_t 			plenmax(void *, void *, size_t);
u_int 			nowrap_dec(u_int, u_int);

struct zonemd * 	zonemd_hash_zonemd(struct rrset *, struct rbtree *);
void zonemd_hash_a(DDD_SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_eui48(DDD_SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_eui64(DDD_SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_svcb(DDD_SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_https(DDD_SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_aaaa(DDD_SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_soa(DDD_SHA512_CTX *, struct rrset *, struct rbtree *, uint32_t *);
void zonemd_hash_ns(DDD_SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_cname(DDD_SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_ptr(DDD_SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_txt(DDD_SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_rp(DDD_SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_hinfo(DDD_SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_srv(DDD_SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_naptr(DDD_SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_caa(DDD_SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_mx(DDD_SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_kx(DDD_SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_ipseckey(DDD_SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_tlsa(DDD_SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_loc(DDD_SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_sshfp(DDD_SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_ds(DDD_SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_dnskey(DDD_SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_cds(DDD_SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_cdnskey(DDD_SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_rrsig(DDD_SHA512_CTX *, struct rrset *, struct rbtree *, int);
void zonemd_hash_nsec3(DDD_SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_nsec3param(DDD_SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_nsec(DDD_SHA512_CTX *, struct rrset *, struct rbtree *);


int bytes_received;

/* externs */
extern int debug;
extern int *ptr;
extern int tsig;
extern int forward;
extern int zonecount;
extern int cookies;

extern void 	dolog(int, char *, ...);

extern struct rbtree * find_rrset(ddDB *db, char *name, int len);
extern struct rbtree * find_rrsetwild(ddDB *db, char *name, int len);
extern struct rrset * find_rr(struct rbtree *rbt, uint16_t rrtype);
extern int add_rr(struct rbtree *rbt, char *name, int len, uint16_t rrtype, void *rdata);
extern int display_rr(struct rrset *rrset);
extern int 	check_ent(char *, int);
extern int     find_tsig_key(char *, int, char *, int);
extern int      mybase64_decode(char const *, u_char *, size_t);

extern int raxfr_a(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_eui48(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_eui64(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_svcb(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_https(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_tlsa(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_srv(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_naptr(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_aaaa(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_cname(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_zonemd(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_ns(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_ptr(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_mx(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_kx(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_ipseckey(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_txt(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_dnskey(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_cdnskey(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_rrsig(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_nsec3param(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_nsec3(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_nsec(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_ds(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_cds(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_rp(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_caa(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_hinfo(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_sshfp(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern int raxfr_loc(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *);
extern uint16_t raxfr_skip(FILE *, u_char *, u_char *);
extern int raxfr_soa(FILE *, u_char *, u_char *, u_char *, struct soa *, int, uint32_t, uint16_t, DDD_HMAC_CTX *, struct soa_constraints *);
extern int raxfr_peek(FILE *, u_char *, u_char *, u_char *, int *, int, uint16_t *, uint32_t, DDD_HMAC_CTX *, char *, int, int);
extern int raxfr_tsig(FILE *, u_char *, u_char *, u_char *, struct soa *, uint16_t, DDD_HMAC_CTX *, char *, int);
extern char *convert_name(char *, int);
extern int	dddbclose(ddDB *);
extern void 	repopulate_zone(ddDB *db, char *zonename, int zonelen);
extern int 	merge_db(ddDB *, ddDB *);
extern void 	delete_zone(char *name, int len);


/* internals */
struct typetable {
	char *type;
	int number;
} TT[] = {
	{ "A", DNS_TYPE_A},
	{ "NS", DNS_TYPE_NS},
	{ "CNAME", DNS_TYPE_CNAME},
	{ "SOA", DNS_TYPE_SOA},
	{ "PTR", DNS_TYPE_PTR},
	{ "MX", DNS_TYPE_MX},
	{ "TXT", DNS_TYPE_TXT},
	{ "AAAA", DNS_TYPE_AAAA},
	{ "ANY", DNS_TYPE_ANY },
	{ "SRV", DNS_TYPE_SRV },
	{ "SSHFP", DNS_TYPE_SSHFP },
	{ "NAPTR", DNS_TYPE_NAPTR },
	{ "RRSIG", DNS_TYPE_RRSIG },
	{ "DNSKEY", DNS_TYPE_DNSKEY },
	{ "NSEC", DNS_TYPE_NSEC },
	{ "DS", DNS_TYPE_DS },
	{ "NSEC3", DNS_TYPE_NSEC3 },
	{ "NSEC3PARAM", DNS_TYPE_NSEC3PARAM },
	{ "TLSA", DNS_TYPE_TLSA },
	{ "RP", DNS_TYPE_RP },
	{ "HINFO", DNS_TYPE_HINFO },
	{ "CAA", DNS_TYPE_CAA },
	{ "ZONEMD", DNS_TYPE_ZONEMD },
	{ "CDS", DNS_TYPE_CDS },
	{ "CDNSKEY", DNS_TYPE_CDNSKEY },
	{ "LOC", DNS_TYPE_LOC },
	{ "EUI48", DNS_TYPE_EUI48 },
	{ "EUI64", DNS_TYPE_EUI64 },
	{ "SVCB", DNS_TYPE_SVCB },
	{ "HTTPS", DNS_TYPE_HTTPS },
	{ "KX", DNS_TYPE_KX },
	{ "IPSECKEY", DNS_TYPE_IPSECKEY },
	{ NULL, 0}
};

static struct rrtab myrrtab[] =  { 
 { "a",         DNS_TYPE_A, 		DNS_TYPE_A } ,
 { "aaaa",      DNS_TYPE_AAAA,		DNS_TYPE_AAAA },
 { "caa",	DNS_TYPE_CAA,		DNS_TYPE_CAA },
 { "cdnskey", 	DNS_TYPE_CDNSKEY,	DNS_TYPE_CDNSKEY },
 { "cds", 	DNS_TYPE_CDS,		DNS_TYPE_CDS },
 { "cname",     DNS_TYPE_CNAME, 	DNS_TYPE_CNAME },
 { "delegate",  DNS_TYPE_NS, 		DNS_TYPE_NS },
 { "dnskey", 	DNS_TYPE_DNSKEY, 	DNS_TYPE_DNSKEY },
 { "ds", 	DNS_TYPE_DS, 		DNS_TYPE_DS },
 { "eui48",	DNS_TYPE_EUI48,		DNS_TYPE_EUI48 },
 { "eui64",	DNS_TYPE_EUI64,		DNS_TYPE_EUI64 },
 { "hinfo",	DNS_TYPE_HINFO,		DNS_TYPE_HINFO },
 { "hint",      DNS_TYPE_HINT,		DNS_TYPE_NS }, 
 { "https", 	DNS_TYPE_HTTPS,		DNS_TYPE_HTTPS },
 { "ipseckey",	DNS_TYPE_IPSECKEY,	DNS_TYPE_IPSECKEY },
 { "kx",	DNS_TYPE_KX,		DNS_TYPE_KX },
 { "loc",	DNS_TYPE_LOC,		DNS_TYPE_LOC },
 { "mx",        DNS_TYPE_MX, 		DNS_TYPE_MX },
 { "naptr", 	DNS_TYPE_NAPTR,		DNS_TYPE_NAPTR },
 { "ns",        DNS_TYPE_NS,		DNS_TYPE_NS },
 { "nsec", 	DNS_TYPE_NSEC, 		DNS_TYPE_NSEC },
 { "nsec3", 	DNS_TYPE_NSEC3,		DNS_TYPE_NSEC3 },
 { "nsec3param", DNS_TYPE_NSEC3PARAM,	DNS_TYPE_NSEC3PARAM },
 { "ptr",       DNS_TYPE_PTR,		DNS_TYPE_PTR },
 { "rp",	DNS_TYPE_RP,		DNS_TYPE_RP },
 { "rrsig", 	DNS_TYPE_RRSIG, 	DNS_TYPE_RRSIG },
 { "soa",       DNS_TYPE_SOA, 		DNS_TYPE_SOA },
 { "srv",       DNS_TYPE_SRV, 		DNS_TYPE_SRV },
 { "sshfp", 	DNS_TYPE_SSHFP,		DNS_TYPE_SSHFP },
 { "svcb",	DNS_TYPE_SVCB,		DNS_TYPE_SVCB },
 { "tlsa", 	DNS_TYPE_TLSA,		DNS_TYPE_TLSA },
 { "txt",       DNS_TYPE_TXT,		DNS_TYPE_TXT },
 { "zonemd",	DNS_TYPE_ZONEMD,	DNS_TYPE_ZONEMD },
};



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
	{ DNS_TYPE_NSEC, 1, raxfr_nsec },
	{ 0, 0, NULL }
};

struct mandatorynode {
	RB_ENTRY(mandatorynode) entry;
	uint16_t key;
} *mn, *mn1;

static int param_mcmp(struct mandatorynode *, struct mandatorynode *);

static int
param_mcmp(struct mandatorynode *e1, struct mandatorynode *e2)
{
	return (e1->key < e2->key ? -1 : e1->key > e2->key);
}

RB_HEAD(mandatorytree, mandatorynode) mandatoryhead = RB_INITIALIZER(&mandatoryhead);
RB_PROTOTYPE(mandatorytree, mandatorynode, entry, param_mcmp)
RB_GENERATE(mandatorytree, mandatorynode, entry, param_mcmp)

TAILQ_HEAD(, iwqueue) iwqhead;
struct iwqueue *iwq, *iwq0, *iwq1;


/*
 * LABEL_COUNT - count the labels and return that number
 */

int 
label_count(char *name)
{
	int lc = 0;
	int wildcard = 0;
	char *p;
	
	if (name == NULL) 
		return -1;

	p = name;
	if (*p == '\001' && *(p + 1) == '*')
		wildcard = 1;

	while (*p != '\0') {
		lc++;
		p += (*p + 1);
	}

	if (wildcard)
		return (lc - 1);

	return (lc);
}

/*
 * DNS_LABEL - build a DNS NAME (with labels) from a canonical name
 * 
 */

char *
dns_label(char *name, int *returnlen)
{
	int len, newlen = 0;
	int i, lc = 0;			/* lc = label count */

	char *dnslabel, *p;
	char *labels[255];
	char **pl;
	static char tname[DNS_MAXNAME + 1];	/* 255 bytes  + 1*/
	char *pt = &tname[0];


	if (name == NULL) 
		return NULL;

	strlcpy(tname, name, sizeof(tname));

	len = strlen(tname);
	if (tname[len - 1] == '.') 
		tname[len - 1] = '\0';

	for (pl=labels;pl<&labels[254]&&(*pl=strsep(&pt,"."))!= NULL;pl++,lc++)
		newlen += strlen(*pl);

	newlen += lc;			/* add label count to length */


	/* make the buffer space, add 1 for trailing NULL */
	if ((dnslabel = malloc(newlen + 1)) == NULL) {
		return NULL;
	}

	pack32((char *)returnlen, (newlen + 1));
	dnslabel[newlen] = '\0';	/* trailing NULL */

	for (i = 0, p = dnslabel; i < lc; i++) {
		len = strlen(labels[i]);
		*p++ = len;
		strlcpy(p, labels[i], newlen - (plength(p,dnslabel)) + 1);
		p += len;
	}

	/*
	 * XXX hack to make all DNS names lower case, we only preserve
	 * case on compressed answers..
	 */

	for (i = 0, p = dnslabel; i < *returnlen; i++) {
		int c;
		
		c = *p;
		if (isalpha(c))
			*p = tolower(c);
		p++;
	}

#if DEBUG
	if (debug)
		dolog(LOG_DEBUG, "converting name= %s\n", name);
#endif

	return dnslabel;
}
/*
 * ddd_shutdown - delphinusdnsd wishes to shutdown, enter its pid into the 
 *			shutdown shared memory and return.
 */

void
ddd_shutdown(void)
{
	pid_t pid;

	pid = getpid();

	*ptr = pid;
}


/*
 * LOOKUP_ZONE - look up a zone filling rbtree and returning RR TYPE, if error
 *		 occurs returns -1, and sets errno on what type of error.
 */


struct rbtree *
lookup_zone(ddDB *db, struct question *question, int *returnval, int *lzerrno, char *replystring, int replystringsize)
{

	struct rbtree *rbt = NULL;
	struct rbtree *rbt0 = NULL;
	struct rrset *rrset = NULL;
	int plen, splen, error;

	char *p, *sp;
	
	p = question->hdr->name;
	plen = question->hdr->namelen;

	*returnval = 0;

	if (forward) {
		/* short circuit when we have no zones loaded */
		if (zonecount == 0) {
			*lzerrno = ERR_FORWARD;
			*returnval = -1;
		
			return NULL;
		}
	}
	/* if the find_rrset fails, the find_rr will not get questioned */
	if ((((rbt = find_rrset(db, p, plen)) == NULL) &&
		((rbt = find_rrsetwild(db, p, plen)) == NULL)) ||
		((ntohs(question->hdr->qtype) != DNS_TYPE_DS) && 
			(rbt->flags & RBT_GLUE)) ||
		((rbt->flags & RBT_DNSSEC) && (rrset = find_rr(rbt, DNS_TYPE_NSEC3)) != NULL)) {
		if (rbt == NULL) {
			splen = plen;
			sp = p;

			while ((rbt0 = find_rrset(db, sp, splen)) == NULL) {
				if (*sp == 0 && splen == 1)
					break;
				sp = advance_label(sp, &splen);
				if (sp == NULL)
					break;
			}

			if (rbt0 && rbt0->flags & RBT_GLUE)
				rbt = rbt0;
		}
		/* check our delegations */
		if (rbt && rbt->flags & RBT_GLUE) {
			while (rbt && (rbt->flags & RBT_GLUE)) {
				plen -= (*p + 1);
				p += (*p + 1);

				while ((rbt0 = find_rrset(db, p, plen)) == NULL) {
					p = advance_label(p, &plen);
					if (p == NULL)
						break;
				}

				if (rbt0->flags & RBT_GLUE) {
					rbt = rbt0;
				} else {
					/* answer the delegation */
					snprintf(replystring, replystringsize, "%s", rbt->humanname);
					*lzerrno = ERR_DELEGATE;
					*returnval = -1;
					return (rbt);
				}
			}
		}
				
		if (check_ent(p, plen) == 1) {
			*lzerrno = ERR_NODATA;
			*returnval = -1;

			return NULL;
		}
	
		/*
		 * We have a condition where a record does not exist but we
		 * move toward the apex of the record, and there may be 
		 * something.  We return NXDOMAIN if there is an apex with 
		 * SOA if not then we return REFUSED 
		 */
		while (*p != 0) {
			p = advance_label(p, &plen);
			if (p == NULL)
				return NULL;

			/* rbt was NULL */
			if ((rbt = find_rrset(db, p, plen)) != NULL) {
				if (find_rr(rbt, DNS_TYPE_SOA) != NULL) {
					*lzerrno = ERR_NXDOMAIN;
					*returnval = -1;
					return (rbt);
				}

				if ((rrset = find_rr(rbt, DNS_TYPE_NS)) != NULL) {
					snprintf(replystring, replystringsize, "%s", rbt->humanname);
					*lzerrno = ERR_DELEGATE;
					*returnval = -1;
					return (rbt);
				}
	
			}
		}
		if (forward)
			*lzerrno = ERR_FORWARD;
		else
			*lzerrno = ERR_REFUSED;
		*returnval = -1;
		return (NULL);
	}
	
	snprintf(replystring, replystringsize, "%s", rbt->humanname);

	if ((ntohs(question->hdr->qtype) != DNS_TYPE_DS) && 
		(rrset = find_rr(rbt, DNS_TYPE_NS)) != NULL &&
		! (rbt->flags & RBT_APEX)) {
		*returnval = -1;
		*lzerrno = ERR_DELEGATE;
		return (rbt);
	} 


	*returnval = check_qtype(rbt, ntohs(question->hdr->qtype), 0, &error);
	if (*returnval == 0) {
		*lzerrno = ERR_NOERROR;
		*returnval = -1;
		return (rbt);
	}

	return(rbt);
}

/*
 * GET_SOA - get authoritative soa for a particular domain
 */

struct rbtree *
get_soa(ddDB *db, struct question *question)
{
	struct rbtree *rbt = NULL;

	int plen;
	char *p;

	p = question->hdr->name;
	plen = question->hdr->namelen;

	do {
		struct rrset *rrset;

		rbt = find_rrset(db, p, plen);
		if (rbt == NULL) {
			if (*p == '\0')
				return (NULL);

			p = advance_label(p, &plen);
			if (p == NULL)
				return NULL;

			continue;
		}
		
		rrset = find_rr(rbt, DNS_TYPE_SOA);
		if (rrset != NULL) {
			/* we'll take this one */
			return (rbt);	
		} else {
			p = advance_label(p, &plen);
			if (p == NULL)
				return NULL;
		} 

	} while (*p);

	return (NULL);
}

/*
 * GET_NS - walk to delegation name
 */

struct rbtree *
get_ns(ddDB *db, struct rbtree *rbt, int *delegation)
{
	struct rrset *rrset = NULL;
	struct rbtree *rbt0;
	char *p;
	int len;

	if ((rrset = find_rr(rbt, DNS_TYPE_SOA)) == NULL) {
		pack32((char *)delegation, 1);
	} else {
		pack32((char *)delegation, 0);
		return (rbt);
	}

	p = rbt->zone;
	len = rbt->zonelen;	

	while (*p && len > 0) {
		rbt0 = Lookup_zone(db, p, len, DNS_TYPE_NS, 0);	
		if (rbt0 == NULL) {
			p = advance_label(p, &len);
			if (p == NULL)
				return NULL;
	
			continue;
		} else
			break;
	}
		
	if ((rrset = find_rr(rbt0, DNS_TYPE_SOA)) != NULL) {
		pack32((char *)delegation, 0);
		return (rbt);
	}
		
	return (rbt0);
}



/* 
 * Lookup_zone: wrapper for lookup_zone() et al. type must be htons()'ed!
 */

struct rbtree *
Lookup_zone(ddDB *db, char *name, uint16_t namelen, uint16_t type, int wildcard)
{
	struct rbtree *rbt;
	struct rrset *rrset = NULL;

	rbt = find_rrset(db, name, namelen);
	if (rbt != NULL) {
		rrset = find_rr(rbt, type);
		if (rrset != NULL) {
			return (rbt);
		} 
	}

	return NULL;
}

/*
 * CHECK_QTYPE - check the query type and return appropriately if we have 
 *		 such a record in our DB..
 *		 returns 0 on error, or the DNS TYPE from 1 through 65535
 * 		 when the return is 0 the error variable is set with the error
 *		 code (-1 or -2)
 */

uint16_t
check_qtype(struct rbtree *rbt, uint16_t type, int nxdomain, int *error)
{
	uint16_t returnval = -1;

	switch (type) {

	case DNS_TYPE_IXFR:
			returnval = DNS_TYPE_IXFR;
			break;
	case DNS_TYPE_AXFR:
			returnval = DNS_TYPE_AXFR;
			break;
	case DNS_TYPE_ANY:
			returnval = DNS_TYPE_ANY;
			break;

	case DNS_TYPE_A:
		if (find_rr(rbt, DNS_TYPE_A) != NULL) {
			returnval = DNS_TYPE_A;
			break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_AAAA:
		if (find_rr(rbt, DNS_TYPE_AAAA) != NULL) {
			returnval = DNS_TYPE_AAAA;
			break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_MX:
		if (find_rr(rbt, DNS_TYPE_MX) != NULL) {
			returnval = DNS_TYPE_MX;
			break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_PTR:
		if (find_rr(rbt, DNS_TYPE_PTR) != NULL) {
			returnval = DNS_TYPE_PTR;
			break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;

	case DNS_TYPE_SOA:
		if (find_rr(rbt, DNS_TYPE_SOA) != NULL) {
			returnval = DNS_TYPE_SOA;
			break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) { /* XXX */
			returnval = DNS_TYPE_CNAME;
			break;
		}

		if (nxdomain)
			*error = -2;
		else
			*error = -1;

		return 0;

	case DNS_TYPE_LOC:
		if (find_rr(rbt, DNS_TYPE_LOC) != NULL) {
			returnval = DNS_TYPE_LOC;
			break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;

	case DNS_TYPE_TLSA:
		if (find_rr(rbt, DNS_TYPE_TLSA) != NULL) {
			returnval = DNS_TYPE_TLSA;
			break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;

	case DNS_TYPE_CAA:
		if (find_rr(rbt, DNS_TYPE_CAA) != NULL) {
			returnval = DNS_TYPE_CAA;
			break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;

	case DNS_TYPE_RP:
		if (find_rr(rbt, DNS_TYPE_RP) != NULL) {
			returnval = DNS_TYPE_RP;
			break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;

	case DNS_TYPE_HINFO:
		if (find_rr(rbt, DNS_TYPE_HINFO) != NULL) {
			returnval = DNS_TYPE_HINFO;
			break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;

	case DNS_TYPE_SSHFP:
		if (find_rr(rbt, DNS_TYPE_SSHFP) != NULL) {
			returnval = DNS_TYPE_SSHFP;
			break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;

	case DNS_TYPE_SRV:	
		if (find_rr(rbt, DNS_TYPE_SRV) != NULL) {
			returnval = DNS_TYPE_SRV;
			break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;

	case DNS_TYPE_NAPTR:
		if (find_rr(rbt, DNS_TYPE_NAPTR) != NULL) {
				returnval = DNS_TYPE_NAPTR;
				break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_IPSECKEY:
		if (find_rr(rbt, DNS_TYPE_IPSECKEY) != NULL) {
			returnval = DNS_TYPE_IPSECKEY;
			break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
			returnval = DNS_TYPE_IPSECKEY;
			break;
		}
		
		*error = -1;
		return 0;
	case DNS_TYPE_KX:
		if (find_rr(rbt, DNS_TYPE_KX) != NULL) {
			returnval = DNS_TYPE_KX;
			break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
			returnval = DNS_TYPE_KX;
			break;
		}
		
		*error = -1;
		return 0;
	case DNS_TYPE_CNAME:
		if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
				returnval = DNS_TYPE_CNAME;
				break;
		}

		*error = -1;
		return 0;

	case DNS_TYPE_NS:
		if (find_rr(rbt, DNS_TYPE_NS) != NULL) {
			returnval = DNS_TYPE_NS;
			break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_TXT:
		if (find_rr(rbt, DNS_TYPE_TXT) != NULL) {
			returnval = DNS_TYPE_TXT;
			break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_RRSIG:
		if (find_rr(rbt, DNS_TYPE_RRSIG) != NULL) {
			returnval = DNS_TYPE_RRSIG;
			break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_NSEC3PARAM:
		if (find_rr(rbt, DNS_TYPE_NSEC3PARAM) != NULL) {
			returnval = DNS_TYPE_NSEC3PARAM;
			break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_NSEC3:
		if (find_rr(rbt, DNS_TYPE_NSEC3) != NULL) {
			returnval = DNS_TYPE_NSEC3;
			break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_NSEC:
		if (find_rr(rbt, DNS_TYPE_NSEC) != NULL) {
			returnval = DNS_TYPE_NSEC;
			break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_DS:
		if (find_rr(rbt, DNS_TYPE_DS) != NULL) {
			returnval = DNS_TYPE_DS;
			break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_CDS:
		if (find_rr(rbt, DNS_TYPE_CDS) != NULL) {
			returnval = DNS_TYPE_CDS;
			break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_DNSKEY:
		if (find_rr(rbt, DNS_TYPE_DNSKEY) != NULL) {
			returnval = DNS_TYPE_DNSKEY;
			break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_CDNSKEY:
		if (find_rr(rbt, DNS_TYPE_CDNSKEY) != NULL) {
			returnval = DNS_TYPE_CDNSKEY;
			break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_ZONEMD:
		if (find_rr(rbt, DNS_TYPE_ZONEMD) != NULL) {
			returnval = DNS_TYPE_ZONEMD;
			break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_EUI48:
		if (find_rr(rbt, DNS_TYPE_EUI48) != NULL) {
			returnval = DNS_TYPE_EUI48;
			break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_EUI64:
		if (find_rr(rbt, DNS_TYPE_EUI64) != NULL) {
			returnval = DNS_TYPE_EUI64;
			break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_SVCB:
		if (find_rr(rbt, DNS_TYPE_SVCB) != NULL) {
			returnval = DNS_TYPE_SVCB;
			break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_HTTPS:
		if (find_rr(rbt, DNS_TYPE_HTTPS) != NULL) {
			returnval = DNS_TYPE_HTTPS;
			break;
		} else if (find_rr(rbt, DNS_TYPE_CNAME) != NULL) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;
	default: /* RR's that we don't support, but have a zone for */

		*error = -1;
		return 0;
		break;
	}

	return (returnval);
}

/*
 * BUILD_FAKE_QUESTION - fill the fake question structure with the DNS query.
 */

struct question *
build_fake_question(char *name, int namelen, uint16_t type, char *tsigkey, int tsigkeylen)
{
	struct question *q;

	q = (void *)calloc(1, sizeof(struct question));
	if (q == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		return NULL;
	}

	q->hdr = (void *)calloc(1, sizeof(struct dns_question_hdr));
	if (q->hdr == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		free(q);
		return NULL;
	}
	q->hdr->namelen = namelen;
	q->hdr->name = (void *) calloc(1, q->hdr->namelen);
	if (q->hdr->name == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		free(q->hdr);
		free(q);
		return NULL;
	}
	q->hdr->original_name = (void *) calloc(1, q->hdr->namelen);
	if (q->hdr->original_name == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		free(q->hdr->name);
		free(q->hdr);
		free(q);
		return NULL;
	}
	q->converted_name = NULL;

	/* fill our name into the dns header struct */
	
	memcpy(q->hdr->original_name, name, q->hdr->namelen);
	memcpy(q->hdr->name, name, q->hdr->namelen);

	if (lower_dnsname(q->hdr->name, q->hdr->namelen) == -1) {
		free(q->hdr->original_name);
		free(q->hdr->name);
		free(q->hdr);
		free(q);
		return NULL;
	}
		
	
	q->hdr->qtype = type;
	q->hdr->qclass = htons(DNS_CLASS_IN);

	if (tsig) {
		char *alg;
		int alglen;

		if (tsigkeylen > sizeof(q->tsig.tsigkey)) {
			free(q->hdr->original_name);
			free(q->hdr->name);
			free(q->hdr);
			free(q);
			return NULL;
		}

		memcpy(&q->tsig.tsigkey, tsigkey, tsigkeylen);
		q->tsig.tsigkeylen = tsigkeylen;
	
		alg = dns_label("hmac-sha256.", &alglen);
		
		if (alg != NULL) {
			memcpy (&q->tsig.tsigalg, alg, alglen);
			q->tsig.tsigalglen = alglen;

			free(alg);

			q->tsig.tsigmaclen = DNS_HMAC_SHA256_SIZE;
		}
	}

	return (q);

}

/*
 * GET_DNS_TYPE - take integer and compare to table, then spit back a static
 * 		  string with the result.  This function can't fail.
 */

char *
get_dns_type(int dnstype, int withbracket)
{
	static char type[128];
	struct typetable *t;

	t = TT;

	while (t->type != NULL) {
		if (dnstype == t->number)
			break;	
	
		t = (t + 1);
	}

	if (t->type == NULL) {
		snprintf(type, sizeof(type) - 1, "%u", dnstype);
	} else {
		if (withbracket)
			snprintf(type, sizeof(type) - 1, "%s(%u)", t->type, dnstype);
		else
			snprintf(type, sizeof(type) - 1, "%s", t->type);
	}

	return (type);	
}	

/* 
 * MEMCASECMP - 	check if buffer is identical to another buffer with 
 *			one exception if a character is alphabetic it's 
 *			compared to it's lower case value so that heLLo is 
 * 			the same as hello
 */

int
memcasecmp(u_char *b1, u_char *b2, int len)
{
	int i;
	int identical = 1;

	for (i = 0; i < len; i++) {
		int c0, c1;
	
		c0 = b1[i];
		c1 = b2[i];

		if ((isalpha(c0) ? tolower(c0) : c0) != 
			(isalpha(c1) ? tolower(c1) : c1)) {
			identical = 0;
			break;
		}
	}

	if (identical) 
		return 0;

	return 1;	/* XXX */
}

/*
 * BUILD_QUESTION - fill the question structure with the DNS query.
 */

struct question *
build_question(char *buf, int len, uint16_t additional, char *mac)
{
	char pseudo_packet[4096];		/* for tsig */
	u_int rollback, i;
	uint16_t qtype, qclass;
	uint32_t ttl;
	uint64_t timefudge;
	int elen = 0;

	char *end_name = NULL;
	char *pb = NULL;
	char *o;
	char expand[DNS_MAXNAME + 1];

	struct dns_tsigrr *tsigrr = NULL;
	struct dns_optrr *opt = NULL;
	struct question *q = NULL;
	struct dns_header *hdr = (struct dns_header *)buf;

	const DDD_EVP_MD *md;

	/* find the end of name */
	elen = 0;
	memset(&expand, 0, sizeof(expand));
	end_name = expand_compression((u_char *)&buf[sizeof(struct dns_header)], (u_char *)buf, (u_char *)&buf[len], (u_char *)&expand, &elen, sizeof(expand));
	if (end_name == NULL) {
		dolog(LOG_ERR, "expand_compression() failed, bad formatted question name\n");
		return NULL;
	}

	if ((plength(end_name, &buf[sizeof(struct dns_header)])) < elen) {
		dolog(LOG_ERR, "compression in question #1\n");
		return NULL;
	}

	i = (plength(end_name, &buf[0]));

	
	/* check if there is space for qtype and qclass */
	if (len < ((plength(end_name, &buf[0])) + (2 * sizeof(uint16_t)))) {
		dolog(LOG_INFO, "question rr is truncated\n");
		return NULL;
	}
	/* check the class type so that $IP is erroring earlier */

	o = (end_name + sizeof(uint16_t));
	qclass = ntohs(unpack16(o));

	switch (qclass) {
	case DNS_CLASS_ANY:
	case DNS_CLASS_NONE:
	case DNS_CLASS_HS:
	case DNS_CLASS_CH:
	case DNS_CLASS_IN:
		break;
	default:
		dolog(LOG_INFO, "unsupported class %d\n", qclass);
		return NULL;
		break;
	}
	
	q = (void *)calloc(1, sizeof(struct question));
	if (q == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		return NULL;
	}
	q->hdr = (void *)calloc(1, sizeof(struct dns_question_hdr));
	if (q->hdr == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		free(q);
		return NULL;
	}
	q->hdr->namelen = (plength(end_name, &buf[sizeof(struct dns_header)]));
	q->hdr->name = (void *) calloc(1, q->hdr->namelen);
	if (q->hdr->name == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		free(q->hdr);
		free(q);
		return NULL;
	}
	q->hdr->original_name = (void *)calloc(1, q->hdr->namelen);
	if (q->hdr->original_name == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		free(q->hdr->name);
		free(q->hdr);
		free(q);
		return NULL;
	}

	/* XXX the below line can fail */
	(void)lower_dnsname(expand, elen);

	if ((q->converted_name = convert_name(expand, elen)) == NULL) {
		dolog(LOG_INFO, "error in convert_name()\n");
		free(q->hdr->name);
		free(q->hdr->original_name);
		free(q->hdr);
		free(q);
		return NULL;
	}

	i += (2 * sizeof(uint16_t)); 	/* type,class*/

	/* in IXFR an additional SOA entry is tacked on, we want to skip this */
	do {
		uint16_t val16;

		rollback = i;

		elen = 0;
		memset(&expand, 0, sizeof(expand));
		pb = expand_compression((u_char *)&buf[i], (u_char *)buf, (u_char *)&buf[len], (u_char *)&expand, &elen, sizeof(expand));
		if (pb == NULL) {
			i = rollback;
			break;
		}
		i = (plength(pb, buf));

		if (i + 10 > len) {	/* type + class + ttl + rdlen == 10 */
			i = rollback;
			break;
		}

		/* type */
		o = &buf[i];
		val16 = unpack16(o);
		if (ntohs(val16) != DNS_TYPE_SOA) {
			i = rollback;
			break;
		}
		i += 2;
		o += 2;
		/* class */
		val16 = unpack16(o);
		if (ntohs(val16) != DNS_CLASS_IN) {
			i = rollback;
			break;
		}
		i += 2;
		o += 2;
		/* ttl */
#if 0
		val32 = unpack32(o);
#endif
		i += 4;
		o += 4;
		val16 = unpack16(o);
		i += 2;

		if (i + ntohs(val16) > len) {	/* rdlen of SOA */
			i = rollback;
			break;
		}

		i += ntohs(val16);	
		o += ntohs(val16);
	} while (0);

	/* check for edns0 opt rr */
	do {
		/* if we don't have an additional section, break */
		if (additional < 1) 
			break;

		rollback = i;

		/* check that the minimum optrr fits */
		/* 10 */
		if (i + sizeof(struct dns_optrr) > len) {
			i = rollback;
			break;
		}

		opt = (struct dns_optrr *)&buf[i];
		if (opt->name[0] != 0) {
			i = rollback;
			break;
		}

		if (ntohs(opt->type) != DNS_TYPE_OPT) {
			i = rollback;
			break;
		}

		/* RFC 3225 */
		ttl = ntohl(opt->ttl);
		if (((ttl >> 16) & 0xff) != 0)
			q->ednsversion = (ttl >> 16) & 0xff;

		q->edns0len = ntohs(opt->class);
		if (q->edns0len < 512)
			q->edns0len = 512;	/* RFC 6891 - page 10 */

		if (ttl & DNSSEC_OK)
			q->dnssecok = 1;

		/* do go into the RDATA of the OPT */
		if (ntohs(opt->rdlen) >= 4) {
			int j = 0;
			uint16_t option_code, option_length, convlen;

			do {
				/* length 11 is the fixed part of OPT */
				option_code = unpack16(&buf[11 + i + j]);
				j += 2;
				option_length = unpack16(&buf[11 + i + j]);
				j += 2;

				if (j + ntohs(option_length) > ntohs(opt->rdlen)) {
					j += ntohs(option_length);
					break;
				}

				switch (ntohs(option_code)) {
				/* RFC 7873 DNS Cookies */
				case DNS_OPT_CODE_TCP_KEEPALIVE:
					q->tcpkeepalive = 1;
					break;
				case DNS_OPT_CODE_COOKIE:
					if (cookies) {
							q->cookie.have_cookie = 1;
							convlen = ntohs(option_length);
							if (convlen <= 40 && convlen >= 16) {
								unpack((char *)&q->cookie.clientcookie,
									(char *)&buf[11 + i + j], 8);			

								unpack((char *)&q->cookie.servercookie,
									(char *)&buf[11 + i + j + 8], convlen - 8);			
								q->cookie.servercookie_len = convlen - 8;
							} else if (convlen == 8) {
								unpack((char *)&q->cookie.clientcookie,
									(char *)&buf[11 + i + j], 8);			

								q->cookie.servercookie_len = 0;
							} else {
								/*
								 * we need to reply with 
								 * FORMERR here 
								 */
								q->cookie.error = 1;
								goto optskip;
							}
					}	
					break;
				default:
					/* skip */
					break;
				}

				j += ntohs(option_length);

			} while ((j + 4) <= ntohs(opt->rdlen));

			if (j > ntohs(opt->rdlen)) {
				/* full stop */
				free_question(q);
				dolog(LOG_INFO, "parsing EDNS options failed, options too long\n");
				return NULL;
			}
		}

optskip:

		i += 11 + ntohs(opt->rdlen);
		additional = nowrap_dec(additional, 1);
	} while (0);
	/* check for TSIG rr */
	do {
		uint16_t val16, tsigerror, tsigotherlen;
		uint16_t fudge;
		uint32_t val32;
		int elen, tsignamelen;
		char *pb;
		char expand[DNS_MAXNAME + 1];
		char tsigkey[512];
		u_char sha256[DNS_HMAC_SHA256_SIZE];
		u_int shasize = sizeof(sha256);
		time_t now, tsigtime;
		int pseudolen1, pseudolen2, ppoffset = 0;
		int pseudolen3 , pseudolen4;

		q->tsig.have_tsig = 0;
		q->tsig.tsigerrorcode = 1;

		/* if we don't have an additional section, break */
		if (additional < 1) {
			break;
		}

		memset(q->tsig.tsigkey, 0, sizeof(q->tsig.tsigkey));
		memset(q->tsig.tsigalg, 0, sizeof(q->tsig.tsigalg));
		memset(q->tsig.tsigmac, 0, sizeof(q->tsig.tsigmac));
		q->tsig.tsigkeylen = q->tsig.tsigalglen = q->tsig.tsigmaclen = 0;

		/* the key name is parsed here */
		rollback = i;
		elen = 0;
		memset(&expand, 0, sizeof(expand));
		pb = expand_compression((u_char *)&buf[i], (u_char *)buf, (u_char *)&buf[len], (u_char *)&expand, &elen, sizeof(expand));
		if (pb == NULL) {
			free_question(q);
			dolog(LOG_INFO, "expand_compression() failed, tsig keyname\n");
			return NULL;
		}
		i = (plength(pb, buf));
		pseudolen1 = i;

		memcpy(q->tsig.tsigkey, expand, elen);
		q->tsig.tsigkeylen = elen;


		if (i + 10 > len) {	/* type + class + ttl + rdlen == 10 */
			i = rollback;
			break;
		}

		/* type */
		o = &buf[i];
		val16 = unpack16(o);
		if (ntohs(val16) != DNS_TYPE_TSIG) {
			i = rollback;
			break;
		}
		i += 2;
		o += 2;
		pseudolen2 = i;

		q->tsig.have_tsig = 1;

		/* we don't have any tsig keys configured, no auth done */
		if (tsig == 0) {
			i = rollback;
#if 0
			dolog(LOG_INFO, "build_question(): received a TSIG request, but tsig is not turned on for this IP range, this could result in a '1' error reply\n");
#endif
			break;
		}

		q->tsig.tsigerrorcode = DNS_BADKEY;

		/* class */
		val16 = unpack16(o);
		if (ntohs(val16) != DNS_CLASS_ANY) {
			i = rollback;
			break;
		}
		i += 2;
		o += 2;
	
		/* ttl */
		val32 = unpack32(o);
		if (ntohl(val32) != 0) {
			i = rollback;
			break;
		}
		i += 4;	
		o += 4;
			
		/* rdlen */
		val16 = unpack16(o);
		if (ntohs(val16) != (len - (i + 2))) {
			i = rollback;
			break;
		}
		i += 2;
		o += 2;
		pseudolen3 = i;

		/* the algorithm name is parsed here */
		elen = 0;
		memset(&expand, 0, sizeof(expand));
		pb = expand_compression((u_char *)&buf[i], (u_char *)buf, (u_char *)&buf[len], (u_char *)&expand, &elen, sizeof(expand));
		if (pb == NULL) {
			free_question(q);
			dolog(LOG_INFO, "expand_compression() failed, tsig algorithm name\n");
			return NULL;
		}
		i = (plength(pb, buf));
		pseudolen4 = i;

		memcpy(q->tsig.tsigalg, expand, elen);
		q->tsig.tsigalglen = elen;
			
		/* now check for MAC type, since it's given once again */
		if (elen == 11) {
			if (expand[0] != 9 ||
				memcasecmp((u_char *)&expand[1], (u_char *)"hmac-sha1", 9) != 0) {
				break;
			}
		} else if (elen == 13) {
			if (expand[0] != 11 ||
				memcasecmp((u_char *)&expand[1], (u_char *)"hmac-sha256", 11) != 0) {
				break;
			}
		} else if (elen == 26) {
			if (expand[0] != 8 ||
				memcasecmp((u_char *)&expand[1], (u_char *)"hmac-md5", 8) != 0) {
				break;
			}
		} else {
			break;
		}

		/* 
		 * this is a delayed (moved down) check of the key, we don't
		 * know if this is a TSIG packet until we've chekced the TSIG
		 * type, that's why it's delayed...
		 */

		if ((tsignamelen = find_tsig_key(q->tsig.tsigkey, q->tsig.tsigkeylen, (char *)&tsigkey, sizeof(tsigkey))) < 0) {
			/* we don't have the name configured, let it pass */
			i = rollback;
			break;
		}
		
		if (i + sizeof(struct dns_tsigrr) > len) {
			i = rollback;
			break;
		}

		tsigrr = (struct dns_tsigrr *)&buf[i];
		/* XXX */
#ifndef __OpenBSD__
		timefudge = be64toh(tsigrr->timefudge);
#else
		timefudge = betoh64(tsigrr->timefudge);
#endif
		fudge = (uint16_t)(timefudge & 0xffff);
		tsigtime = (uint64_t)(timefudge >> 16);

		q->tsig.tsig_timefudge = tsigrr->timefudge;
		
		i += (8 + 2);		/* timefudge + macsize */

		if (ntohs(tsigrr->macsize) != DNS_HMAC_SHA256_SIZE) {
			q->tsig.tsigerrorcode = DNS_BADSIG; 
			break; 
		}

		i += ntohs(tsigrr->macsize);
	

		/* now get the MAC from packet with length rollback */
		NTOHS(hdr->additional);
		hdr->additional = nowrap_dec(hdr->additional, 1);
		HTONS(hdr->additional);

		/* origid */
		o = &buf[i];
		val16 = unpack16(o);
		i += 2;
		o += 2;
		if (hdr->id != val16)
			hdr->id = val16;
		q->tsig.tsigorigid = val16;

		/* error */
		tsigerror = unpack16(o);
		i += 2;
		o += 2;

		/* other len */
		tsigotherlen = unpack16(o);
		i += 2;
		o += 2;

		ppoffset = 0;

		/* check if we have a request mac, this means it's an answer */
		if (mac) {
			o = &pseudo_packet[ppoffset];
			pack16(o, htons(DNS_HMAC_SHA256_SIZE));
			ppoffset += 2;

			memcpy(&pseudo_packet[ppoffset], mac, DNS_HMAC_SHA256_SIZE);
			ppoffset += DNS_HMAC_SHA256_SIZE;
		}

		memcpy(&pseudo_packet[ppoffset], buf, pseudolen1);
		ppoffset += pseudolen1;
		memcpy((char *)&pseudo_packet[ppoffset], &buf[pseudolen2], 6); 
		ppoffset += 6;

		memcpy((char *)&pseudo_packet[ppoffset], &buf[pseudolen3], pseudolen4 - pseudolen3);
		ppoffset += (pseudolen4 - pseudolen3);

		memcpy((char *)&pseudo_packet[ppoffset], (char *)&tsigrr->timefudge, 8); 
		ppoffset += 8;

		o = &pseudo_packet[ppoffset];
		pack16(o, tsigerror);
		ppoffset += 2;
		o += 2;

		o = &pseudo_packet[ppoffset];
		pack16(o, tsigotherlen);
		ppoffset += 2;
		o += 2;

		memcpy(&pseudo_packet[ppoffset], &buf[i], len - i);
		ppoffset += (len - i);

		/* check for BADTIME before the HMAC memcmp as per RFC 2845 */
		now = time(NULL);
		/* outside our fudge window */
		if (tsigtime < (now - fudge) || tsigtime > (now + fudge)) {
			q->tsig.tsigerrorcode = DNS_BADTIME;
			break;
		}

		
		md = (DDD_EVP_MD *)delphinusdns_EVP_get_digestbyname("sha256");
		if (md == NULL) {
			dolog(LOG_INFO, "HMAC could not initialize\n");
			q->tsig.tsigerrorcode = DNS_BADSIG;
			break;
		}
		delphinusdns_HMAC(md, tsigkey, tsignamelen, (unsigned char *)pseudo_packet, 
			ppoffset, (unsigned char *)&sha256, &shasize);



#if __OpenBSD__
		if (timingsafe_memcmp(sha256, tsigrr->mac, sizeof(sha256)) != 0) {
#else
		if (memcmp(sha256, tsigrr->mac, sizeof(sha256)) != 0) {
#endif
#if DEBUG
			dolog(LOG_INFO, "HMAC did not verify\n");
#endif
			q->tsig.tsigerrorcode = DNS_BADSIG;
			break;
		}

		/* copy the mac for error coding */
		memcpy(q->tsig.tsigmac, tsigrr->mac, sizeof(q->tsig.tsigmac));
		q->tsig.tsigmaclen = DNS_HMAC_SHA256_SIZE;
		
		/* we're now authenticated */
		q->tsig.tsigerrorcode = 0;
		q->tsig.tsigverified = 1;
		
	} while (0);

	/* fill our name into the dns header struct */
		
	memcpy(q->hdr->name, &buf[sizeof(struct dns_header)], q->hdr->namelen);
	memcpy(q->hdr->original_name, &buf[sizeof(struct dns_header)], q->hdr->namelen);
	
	/* make hdr->name lower case */

	if (lower_dnsname(q->hdr->name, q->hdr->namelen) == -1) {
		dolog(LOG_INFO, "lower_dnsname failed\n");
		free(q->hdr->name);
		free(q->hdr->original_name);
		free(q->hdr);
		free(q->converted_name);
		free(q);
		return NULL;
	}

	/* parse type and class from the question */

	o = (end_name);
	qtype = unpack16(o);
	o = (end_name + sizeof(uint16_t));
	qclass = unpack16(o);

	memcpy((char *)&q->hdr->qtype, (char *)&qtype, sizeof(uint16_t));
	memcpy((char *)&q->hdr->qclass, (char *)&qclass, sizeof(uint16_t));

	/* make note of whether recursion is desired */
	q->rd = ((ntohs(hdr->query) & DNS_RECURSE) == DNS_RECURSE);

	/* are we a notify packet? */
	if ((ntohs(qtype) == DNS_TYPE_SOA) && (ntohs(qclass) == DNS_CLASS_IN))
		q->notify = ((ntohs(hdr->query) & (DNS_NOTIFY | DNS_AUTH)) \
			== (DNS_NOTIFY | DNS_AUTH));
	else
		q->notify = 0;

	return (q);
}

/*
 * FREE_QUESTION - free a question struct
 *
 */

int
free_question(struct question *q)
{
	if (q == NULL)
		return 0;

	free(q->hdr->name);
	free(q->hdr->original_name);
	free(q->hdr);
	free(q->converted_name);
	free(q);
	
	return 0;
}

/* probably Copyright 2012 Kenneth R Westerback <krw@openbsd.org> */

static int
kw_cmp(const void *k, const void *e)
{
        return (strcasecmp(k, ((const struct rrtab *)e)->name));
}


struct rrtab * 
rrlookup(char *keyword)
{
	static struct rrtab *p; 

	/* safety */
	if (keyword == NULL)
		return NULL;

	p = bsearch(keyword, myrrtab, sizeof(myrrtab)/sizeof(myrrtab[0]), 
		sizeof(myrrtab[0]), kw_cmp);
	
	return (p);
}	

/*
 * parse a domain name through a compression scheme and stay inside the bounds
 * returns NULL on error and pointer to the next object;
 */

char *
expand_compression(u_char *p, u_char *estart, u_char *end, u_char *expand, int *elen, int max)
{
	u_short tlen;
	u_char *save = NULL;
	uint16_t offset;

	*elen = 0;

	/* expand name */
	while ((u_char)*p && p <= end) {
		/* test for compression */
		if ((*p & 0xc0) == 0xc0) {
			/* do not allow recursive compress pointers */
			if (! save) {
				save = p + 2;
			}
			offset = unpack16((char *)p);
			/* offsets into the dns header are a nono */
			if ((ntohs(offset) & (~0xc000)) < sizeof(struct dns_header))
				return NULL;

			/* do not allow forwards jumping */
			if ((plenmax(p, estart, plength(end, estart))) <= (ntohs(offset) & (~0xc000))) {
				return NULL;
			}

			p = (estart + (ntohs(offset) & (~0xc000)));
		} else {
			if (*p > 63)
				return NULL;

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
		return ((char *)p);
	} else {
		(*elen)++;
		return ((char *)save);
	}
}

void
log_diff(char *sha256, char *mac, int len)
{
	char buf[512];
	char tbuf[16];
	int i;

	memset(&buf, 0, sizeof(buf));
	for (i = 0; i < DNS_HMAC_SHA256_SIZE; i++) {
		snprintf(tbuf, sizeof(tbuf), "%02x", sha256[i] & 0xff);	
		strlcat(buf, tbuf, sizeof(buf));
	}

	strlcat(buf, "\n", sizeof(buf));

	dolog(LOG_INFO, "our HMAC = %s\n", buf);

	memset(&buf, 0, sizeof(buf));
	for (i = 0; i < DNS_HMAC_SHA256_SIZE; i++) {
		snprintf(tbuf, sizeof(tbuf), "%02x", mac[i] & 0xff);	
		strlcat(buf, tbuf, sizeof(buf));
	}

	strlcat(buf, "\n", sizeof(buf));

	dolog(LOG_INFO, "given HMAC = %s\n", buf);

}

/*
 * TSIG_PSEUDOHEADER - assemble a pseudoheader and with a HMAC_CTX * and
 * 			update it within this function...
 */

int
tsig_pseudoheader(char *tsigkeyname, uint16_t fudge, time_t now, DDD_HMAC_CTX *ctx)
{
	char pseudo_packet[512];
	char *keyname = NULL;

	int ppoffset = 0;
	int len;

	char *p;

	keyname = dns_label(tsigkeyname, &len);
	if (keyname == NULL) {
		return -1;
	}

	/* name of key */
	memcpy(&pseudo_packet, keyname, len);
	ppoffset += len;	
	p = &pseudo_packet[len];

	free(keyname);

	/* class */
	pack16(p, htons(DNS_CLASS_ANY));
	ppoffset += 2;
	p += 2;

	/* TTL */
	pack32(p, 0);
	ppoffset += 4;
	p += 4;
		
	keyname = dns_label("hmac-sha256", &len);
	if (keyname == NULL) {
		return -1;
	}
	
	/* alg name */	
	memcpy(&pseudo_packet[ppoffset], keyname, len);
	ppoffset += len;
	p += len;

	free(keyname);

	/* time 1 and 2 */
	now = time(NULL);
	if (sizeof(time_t) == 4)	/* 32-bit time_t */
		pack16(p, 0);
	else
		pack16(p, htons((now >> 32) & 0xffff));
	ppoffset += 2;
	p += 2;

	pack32(p, htonl((now & 0xffffffff)));
	ppoffset += 4;
	p += 4;
	
	/* fudge */
	pack16(p, htons(fudge));
	ppoffset += 2;
	p += 2;

	/* error */

	pack16(p, 0);
	ppoffset += 2;
	p += 2;

	/* other len */
	
	pack16(p, 0);
	ppoffset += 2;
	p += 2;

	delphinusdns_HMAC_Update(ctx, (u_char *)pseudo_packet, ppoffset);

	return 0;
}


char *
bin2hex(char *bin, int len)
{
	static char hex[4096];
	char *p;
	int i;

	memset(&hex, 0, sizeof(hex));
	p = &hex[0];

	for (i = 0; i < len; i++) {
		snprintf(p, sizeof(hex), "%02x", bin[i] & 0xff);
		p += 2;
	}

	return ((char *)&hex);
}

uint64_t
timethuman(time_t timet)
{
	char timebuf[512];
	struct tm *tm;
	uint64_t retbuf;

	tm = gmtime((time_t *)&timet);
	strftime(timebuf, sizeof(timebuf), "%Y%m%d%H%M%S", tm);
	retbuf = atoll(timebuf);

	return(retbuf);
}


char *
bitmap2human(char *bitmap, int len)
{
	static char human[4096];
	char expanded_bitmap[32];
	uint16_t bit;
	int i, j, block, bitlen;
	int x;
	char *p;

	memset(&human, 0, sizeof(human));

	for (i = 0, p = bitmap; i < len;) {
		block = *p;
		p++;
		i++;
		memset(&expanded_bitmap, 0, sizeof(expanded_bitmap));
		bitlen = *p;
		p++;
		i++;
		memcpy(&expanded_bitmap, p, bitlen);
		p += bitlen;
		i += bitlen;
		for (j = 0; j < 32; j++) {
			if (expanded_bitmap[j] & 0x80) {
				x = 0;
				bit = (block * 256) + ((j * 8) + x);
				strlcat(human, get_dns_type(bit, 0), sizeof(human));
				strlcat(human, " ", sizeof(human));
			}
			if (expanded_bitmap[j] & 0x40) {
				x = 1;
				bit = (block * 256) + ((j * 8) + x);
				strlcat(human, get_dns_type(bit, 0), sizeof(human));
				strlcat(human, " ", sizeof(human));
			}
			if (expanded_bitmap[j] & 0x20) {
				x = 2;
				bit = (block * 256) + ((j * 8) + x);
				strlcat(human, get_dns_type(bit, 0), sizeof(human));
				strlcat(human, " ", sizeof(human));
			}
			if (expanded_bitmap[j] & 0x10) {
				x = 3;
				bit = (block * 256) + ((j * 8) + x);
				strlcat(human, get_dns_type(bit, 0), sizeof(human));
				strlcat(human, " ", sizeof(human));
			}
			if (expanded_bitmap[j] & 0x8) {
				x = 4;
				bit = (block * 256) + ((j * 8) + x);
				strlcat(human, get_dns_type(bit, 0), sizeof(human));
				strlcat(human, " ", sizeof(human));
			}
			if (expanded_bitmap[j] & 0x4) {
				x = 5;
				bit = (block * 256) + ((j * 8) + x);
				strlcat(human, get_dns_type(bit, 0), sizeof(human));
				strlcat(human, " ", sizeof(human));
			}
			if (expanded_bitmap[j] & 0x2) {
				x = 6;
				bit = (block * 256) + ((j * 8) + x);
				strlcat(human, get_dns_type(bit, 0), sizeof(human));
				strlcat(human, " ", sizeof(human));
			}
			if (expanded_bitmap[j] & 0x1) {
				x = 7;
				bit = (block * 256) + ((j * 8) + x);
				strlcat(human, get_dns_type(bit, 0), sizeof(human));
				strlcat(human, " ", sizeof(human));
			}

		}
	}
		
	if (human[strlen(human) - 1] == ' ')
		human[strlen(human) - 1] = '\0';

	return ((char *)&human);
}


int
lookup_axfr(FILE *f, int so, char *zonename, struct soa *mysoa, uint32_t format, char *tsigkey, char *tsigpass, int *segment, int *answers, int *additionalcount, struct soa_constraints *constraints, uint32_t bytelimit, int ob)
{
	char query[512];
#define SECRET_PSEUDO_PACKET_SIZE	512
	char *pseudo_packet;
	char shabuf[DNS_HMAC_SHA256_SIZE];
	char *reply;
	struct timeval tv, savetv;
	struct question *q = NULL;
	struct whole_header {
		uint16_t len;
		struct dns_header dh;
	} *wh, *rwh;
	struct raxfr_logic *sr;
	
	u_char *p, *name, *keyname;

	u_char *end, *estart;
	int len, totallen, zonelen, rrlen, rrtype;
	int soacount = 0;
	int segmentcount = 0;
	int count = 0;
	int have_question = 1;
	int seen_tsig = 0;
	uint16_t rdlen, *plen;
	uint16_t tcplen;
	
	DDD_HMAC_CTX *ctx;
	const DDD_EVP_MD *md;

	time_t now = 0;
	socklen_t sizetv;
	int sacount = 0;
	
#if __OpenBSD__
	pseudo_packet = calloc_conceal(1, SECRET_PSEUDO_PACKET_SIZE);
#else
	pseudo_packet = calloc(1, SECRET_PSEUDO_PACKET_SIZE);
#endif
	if (pseudo_packet == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		return -1;
	}

	md = (DDD_EVP_MD *)delphinusdns_EVP_get_digestbyname("sha256");
	if (md == NULL) {
		fprintf(stderr, "md failed!\n");
		goto cleanup;
	}
	if (!(format & TCP_FORMAT))
		goto cleanup;

	memset(&query, 0, sizeof(query));
	
	wh = (struct whole_header *)&query[0];
	
	wh->dh.id = htons(arc4random_uniform(0xffff));
	wh->dh.query = 0;
	wh->dh.question = htons(1);
	wh->dh.answer = 0;
	wh->dh.nsrr = 0;
	wh->dh.additional = htons(0);


	SET_DNS_QUERY(&wh->dh);
	SET_DNS_RECURSION(&wh->dh);
	HTONS(wh->dh.query);

	totallen = sizeof(struct whole_header);

	name = (u_char *)dns_label(zonename, &len);
	if (name == NULL) {
		dolog(LOG_INFO, "%s: dns_label failed\n", __FILE__);
		goto cleanup;
	}

	zonelen = len;
	
	p = (u_char *)&wh[1];	
	
	memcpy(p, name, len);
	totallen += len;
	p += len;

	pack16((char *)p, htons(DNS_TYPE_AXFR));
	totallen += sizeof(uint16_t);
	p += sizeof(uint16_t);
	
	pack16((char *)p, htons(DNS_CLASS_IN));
	totallen += sizeof(uint16_t);
	p += sizeof(uint16_t);

	/* we have a key, attach a TSIG payload */
	if (tsigkey) {

		if ((len = mybase64_decode(tsigpass, (u_char *)pseudo_packet, SECRET_PSEUDO_PACKET_SIZE)) < 0) {
			dolog(LOG_INFO, "%s: bad base64 password\n", __FILE__);
			goto cleanup;
		}
		
		ctx = delphinusdns_HMAC_CTX_new();
		delphinusdns_HMAC_Init_ex(ctx, pseudo_packet, len, md, NULL);
		delphinusdns_HMAC_Update(ctx, (u_char *)&query[2], totallen - 2);

		now = time(NULL);
		if (tsig_pseudoheader(tsigkey, DEFAULT_TSIG_FUDGE, now, ctx) < 0) {
			dolog(LOG_INFO, "%s: tsig_pseudoheader failed\n", __FILE__);
			goto cleanup;
		}

		delphinusdns_HMAC_Final(ctx, (u_char *)shabuf, (u_int *)&len);

		if (len != DNS_HMAC_SHA256_SIZE) {
			dolog(LOG_INFO, "%s: not expected HMAC len != 32\n", __FILE__);
			goto cleanup;
		}

		delphinusdns_HMAC_CTX_free(ctx);

		keyname = (u_char *)dns_label(tsigkey, &len);
		if (keyname == NULL) {
			dolog(LOG_INFO, "%s: dns_label() failed 2\n", __FILE__);
			goto cleanup;
		}

		memcpy(&query[totallen], keyname, len);
		totallen += len;
		
		p = (u_char *)&query[totallen];
		pack16((char *)p, htons(DNS_TYPE_TSIG));
		totallen += 2;
		p += 2;

		pack16((char *)p, htons(DNS_CLASS_ANY));
		totallen += 2;
		p += 2;

		pack32((char *)p, htonl(0));
		totallen += 4;
		p += 4;

		keyname = (u_char *)dns_label("hmac-sha256", &len);
		if (keyname == NULL) {
			dolog(LOG_INFO, "%s: dns_label() failed 3\n", __FILE__);
			goto cleanup;
		}

		/* 
		 * XXX rdlen was:
		 * len + 2 + 4 + 2 + 2 + DNS_HMAC_SHA256_SIZE + 2 + 2 + 2 
		 */

		pack16((char *)p, htons(len + 10 + DNS_HMAC_SHA256_SIZE + 6)); 
		totallen += 2;
		p += 2;

		/* algorithm name */
		memcpy(&query[totallen], keyname, len);
		totallen += len;
		p += len;

		/* time 1 */
		if (sizeof(time_t) == 4)		/* 32-bit time-t */
			pack16((char *)p, 0);
		else
			pack16((char *)p, htons((now >> 32) & 0xffff)); 
		totallen += 2;
		p += 2;

		/* time 2 */
		pack32((char *)p, htonl(now & 0xffffffff));
		totallen += 4;
		p += 4;

		/* fudge */
		pack16((char *)p, htons(DEFAULT_TSIG_FUDGE));
		totallen += 2;
		p += 2;
	
		/* hmac size */
		pack16((char *)p, htons(sizeof(shabuf)));
		totallen += 2;
		p += 2;

		/* hmac */
		memcpy(&query[totallen], shabuf, sizeof(shabuf));
		totallen += sizeof(shabuf);
		p += sizeof(shabuf);

		/* original id */
		pack16((char *)p, wh->dh.id);
		totallen += 2;
		p += 2;

		/* error */
		pack16((char *)p, 0);
		totallen += 2;
		p += 2;
		
		/* other len */
		pack16((char *)p, 0);
		totallen += 2;
		p += 2;

		wh->dh.additional = htons(1);
	}
	

	wh->len = htons(totallen - 2);

	if (send(so, query, totallen, 0) < 0) {
		perror("send");
		goto cleanup;
	}

	/* catch reply, totallen is reused here */
	totallen = 0;

	reply = calloc(1, 0xffff + 2);
	if (reply == NULL) {
		perror("calloc");
		goto cleanup;
	}

	if (tsigkey) {
		uint16_t maclen;
	
		if ((len = mybase64_decode(tsigpass, (u_char *)pseudo_packet, SECRET_PSEUDO_PACKET_SIZE)) < 0) {
			dolog(LOG_INFO, "%s: bad base64 password\n", __FILE__);
			goto cleanup;
		}
		
		ctx = delphinusdns_HMAC_CTX_new();
		delphinusdns_HMAC_Init_ex(ctx, pseudo_packet, len, md, NULL);
		maclen = htons(DNS_HMAC_SHA256_SIZE);
		delphinusdns_HMAC_Update(ctx, (u_char *)&maclen, sizeof(maclen));
		delphinusdns_HMAC_Update(ctx, (u_char *)shabuf, sizeof(shabuf));
	} else
		ctx = NULL;

	q = build_question((char *)&wh->dh, wh->len, wh->dh.additional, (tsigkey == NULL) ? NULL : shabuf);
	if (q == NULL) {
		dolog(LOG_INFO, "%s: failed build_question()\n", __FILE__);
		goto cleanup;
	}

	for (;;) {
		sizetv = sizeof(struct timeval);
		if (getsockopt(so, SOL_SOCKET, SO_RCVTIMEO, &savetv, &sizetv) < 0) {	
			dolog(LOG_INFO, "%s: getsockopt() %s\n", __FILE__, strerror(errno));
		}

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		if (setsockopt(so, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
			dolog(LOG_INFO, "setsockopt failed with sec 1, usec 0: %s\n", strerror(errno));
		}

		len = recv(so, reply, 2, MSG_PEEK | MSG_WAITALL);
		if (len <= 0) {	
			dolog(LOG_INFO, "recv failed peeking: %s\n", strerror(errno));
			break;
		}

		plen = (uint16_t *)reply;
		tcplen = ntohs(*plen) + 2;
		
		/* restore original timeout values */
		if (setsockopt(so, SOL_SOCKET, SO_RCVTIMEO, &savetv, sizeof(savetv)) < 0) {
			dolog(LOG_INFO, "setsockopt failed: %s\n", strerror(errno));
		}

		len = recv(so, reply, tcplen, MSG_WAITALL);
		if (len < 0) {
			dolog(LOG_INFO, "recv failed: %s\n", strerror(errno));
			goto cleanup;
		}

		totallen += len;

		if (totallen >= bytelimit) {
			dolog(LOG_INFO, "download exceeded byte limit\n");
			goto cleanup;
		}

		rwh = (struct whole_header *)&reply[0];
		bytes_received += ntohs(rwh->len);

		end = (u_char *)&reply[len];
		len = rwh->len;

		if (rwh->dh.id != wh->dh.id) {
			dolog(LOG_INFO, "DNS ID mismatch\n");
			goto cleanup;
		}

		if (!(htons(rwh->dh.query) & DNS_REPLY)) {
			dolog(LOG_INFO, "not a DNS reply\n");
			goto cleanup;
		}
		
		if (ntohs(rwh->dh.answer) < 1) {	
			dolog(LOG_INFO, "NO ANSWER provided\n");
			goto cleanup;
		}

		segmentcount = ntohs(rwh->dh.answer);
		if (tsigkey) {
			segmentcount += ntohs(rwh->dh.additional);
			*additionalcount += ntohs(rwh->dh.additional);
		} 
		*answers += segmentcount;

			
		if (memcmp(q->hdr->name, name, q->hdr->namelen) != 0) {
			dolog(LOG_INFO, "question name not for what we asked\n");
			goto cleanup;
		}

		if (q->hdr->qclass != htons(DNS_CLASS_IN) || q->hdr->qtype != htons(DNS_TYPE_AXFR)) {
			dolog(LOG_INFO, "wrong class or type\n");
			goto cleanup;
		}
		
		p = (u_char *)&rwh[1];		

		if (have_question) {
			p += q->hdr->namelen;
			p += sizeof(uint16_t);	 	/* type */
			p += sizeof(uint16_t);		/* class */
			/* end of question */

			if (! ob)
				have_question = 0;
		}

		estart = (u_char *)&rwh->dh;

		if (tsigkey) {
			uint16_t saveadd;

			saveadd = rwh->dh.additional;
			NTOHS(rwh->dh.additional);
			if (rwh->dh.additional)
				rwh->dh.additional = 
					nowrap_dec(rwh->dh.additional, 1);
			HTONS(rwh->dh.additional);
			delphinusdns_HMAC_Update(ctx, estart, plength(p,estart));
			rwh->dh.additional = saveadd;
		}

		(*segment)++;

		for (count = 0; count < segmentcount; count++) {
			char mac[DNS_HMAC_SHA256_SIZE];

			if ((rrlen = raxfr_peek(f, p, estart, end, &rrtype, soacount, &rdlen, format, ctx, (char *)name, zonelen, 1)) < 0) {
				dolog(LOG_INFO, "raxfr_peek() ERROR\n");
				goto cleanup;
			}

			if (tsigkey && (rrtype == DNS_TYPE_TSIG)) {
				uint16_t maclen;

				/* do tsig checks here */
				if ((len = raxfr_tsig(f,p,estart,end,mysoa,rdlen,ctx, (char *)&mac, (sacount++ == 0) ? 1 : 0)) < 0) {
					dolog(LOG_INFO, "ERROR with TSIG record\n");
					goto cleanup;
				}
		
				p = (estart + len);

				seen_tsig = 1;

				if ((len = mybase64_decode(tsigpass, (u_char *)pseudo_packet, SECRET_PSEUDO_PACKET_SIZE)) < 0) {
					dolog(LOG_INFO, "bad base64 password\n");
					goto cleanup;
				}

			 	if (delphinusdns_HMAC_CTX_reset(ctx) != 1) {
					dolog(LOG_INFO, "HMAC_CTX_reset failed!\n");
					goto cleanup;
				}
				
					
				if (delphinusdns_HMAC_Init_ex(ctx, pseudo_packet, len, md, NULL) != 1) {
					dolog(LOG_INFO, "HMAC_Init_ex failed!\n");
					goto cleanup;
				}
				maclen = htons(DNS_HMAC_SHA256_SIZE);
				delphinusdns_HMAC_Update(ctx, (u_char *)&maclen, sizeof(maclen));
				delphinusdns_HMAC_Update(ctx, (u_char *)mac, sizeof(mac));

				if (soacount > 1)
					goto out;

				/*
				 * oldbehaviour did not account for another 
				 * header 
				 */

				if (! ob) {
					len = recv(so, reply, 2, MSG_PEEK | MSG_WAITALL);
					if (len <= 0) {
						dolog(LOG_INFO, "mangled AXFR\n");
						goto cleanup;
					}

					tcplen = ntohs(unpack16(reply));

					if (tcplen < sizeof(struct whole_header)) {
						dolog(LOG_INFO, "parsing header after TSIG failed, boundary problem\n");
						goto cleanup;
					}
						
					len = recv(so, reply, sizeof(struct whole_header), MSG_PEEK | MSG_WAITALL);
					if (len < 0) {
						dolog(LOG_INFO, "recv(): %s\n", strerror(errno));
						goto cleanup;
					}

					rwh = (struct whole_header *)&reply[0];

					if (ntohs(unpack16((char *)&rwh->dh.question)) == 1) {
						have_question = 1;
					} 
					
					break;
				}
			} else
				p = (estart + rrlen);

			if (rrtype == DNS_TYPE_SOA) {
				if ((len = raxfr_soa(f, p, estart, end, mysoa, soacount, format, rdlen, ctx, constraints)) < 0) {
					dolog(LOG_INFO, "raxfr_soa failed\n");
					goto cleanup;
				}
				p = (estart + len);
				soacount++;

				/*
				 * the envelopes are done because we have
				 * two SOA's, continue here to catch the
				 * TSIG.
				 */
				if (soacount > 1)
					continue;
			} else {
				for (sr = supported; sr->rrtype != 0; sr++) {
					if (rrtype == sr->rrtype) {
						if ((len = (*sr->raxfr)(f, p, estart, end, mysoa, rdlen, ctx)) < 0) {
							dolog(LOG_INFO, "error with rrtype %d\n", sr->rrtype);
							goto cleanup;
						}
						p = (estart + len);
						break;
					}
				}

				if (sr->rrtype == 0) {
					if (rrtype != DNS_TYPE_TSIG) {
						dolog(LOG_INFO, "unsupported RRTYPE %d\n", rrtype);
						goto cleanup;
					} 
				} 
			}
		}
	}

	if ((len = recv(so, reply, 0xffff, 0)) > 0) {	
		dolog(LOG_INFO, "RAXFR WARN: received %d more bytes.\n", len);
		goto cleanup;
	}

out:

	if (tsigkey && ! seen_tsig) {
		dolog(LOG_INFO, "no final tsig RR seen (despite us requesting it), drop\n");
		goto cleanup;
	}

#if __OpenBSD__
	freezero(pseudo_packet, SECRET_PSEUDO_PACKET_SIZE);
#else
	explicit_bzero(pseudo_packet, SECRET_PSEUDO_PACKET_SIZE);
	free(pseudo_packet);
#endif

	if (tsigkey) {
		delphinusdns_HMAC_CTX_free(ctx);	
	}

	free_question(q);

	return 0;

cleanup:
#if __OpenBSD__
	freezero(pseudo_packet, SECRET_PSEUDO_PACKET_SIZE);
#else
	explicit_bzero(pseudo_packet, SECRET_PSEUDO_PACKET_SIZE);
	free(pseudo_packet);
#endif
	if (tsigkey) {
		delphinusdns_HMAC_CTX_free(ctx);
	}

	free_question(q);

	return -1;
}

/* 
 * DN_CONTAINS - is anchorname contained in name?
 */

int
dn_contains(char *name, int len, char *anchorname, int alen)
{
	char *p = name;
	int plen = len;

	while (plen >= alen) {
		if (plen == alen &&
			memcasecmp((u_char *)p, (u_char *)anchorname, alen) == 0) {
			return 1;
		}

		p = advance_label(p, &plen);
		if (p == NULL)
			return 0;
	}

	return 0;
}

/* pack functions */

void
pack32(char *buf, uint32_t value)
{
	pack(buf, (char *)&value, sizeof(uint32_t));
}	

void
pack16(char *buf, uint16_t value)
{
	pack(buf, (char *)&value, sizeof(uint16_t));
}

void
pack8(char *buf, uint8_t value)
{
	uint8_t *p;

	p = (uint8_t *)buf;
	*p = value;
}

void
pack(char *buf, char *input, int len)
{
	memcpy(buf, input, len);
}	

uint32_t
unpack32(char *buf)
{
	uint32_t ret = 0;
	
	unpack((char *)&ret, buf, sizeof(uint32_t));

	return (ret);
}

uint16_t
unpack16(char *buf)
{
	uint16_t ret = 0;
	
	unpack((char *)&ret, buf, sizeof(uint16_t));

	return (ret);
}

void
unpack(char *buf, char *input, int len)
{
	memcpy(buf, input, len);
}

/* https://tools.ietf.org/html/draft-vixie-dnsext-dns0x20-00 */
int
randomize_dnsname(char *buf, int len)
{
	char save[DNS_MAXNAME];
	char randompad[DNS_MAXNAME];
	char *p, *q;
	uint offset, labellen;
	int i;
	char ch;

	if (len > sizeof(save))
		return (-1);

	memcpy(save, buf, len);
	arc4random_buf(randompad, sizeof(randompad));

	q = &buf[0];
	for (p = q, offset = 0; offset <= len && *p != 0; offset += (*p + 1), p += (*p + 1)) {
		labellen = *p;

		if (labellen > DNS_MAXLABEL)
			goto err;	

		for (i = 1; i < (1 + labellen); i++) {
			ch = q[offset + i];
			q[offset + i] = (randompad[offset + i] & 1) ? toupper(ch) : ch;
		}
	}

	if (offset > len)
		goto err;

	return (0);

err:
	/* error condition, restore original buf */
	memcpy(buf, save, len);
	return (-1);
}

int
lower_dnsname(char *buf, int len)
{
	char *p, *q;
	char save[DNS_MAXNAME];
	uint offset, labellen;
	int i;
	char ch;

	if (len > sizeof(save))
		return (-1);

	if (len == 1 && buf[0] == '\0')
		return (0);

	memcpy(save, buf, len);

	q = &buf[0];
	for (p = q, offset = 0; offset <= len && *p != 0; offset += (*p + 1), p += (*p + 1)) {
		labellen = *p;
		/* we found compression in this name, just exit */
		if (*p & 0xC0)
			break;
		if (labellen > DNS_MAXLABEL)
			goto err;	

		for (i = 1; i < (1 + labellen); i++) {
			ch = tolower(q[offset + i]);
			q[offset + i] = ch;
		}
	}

	if (offset > len)
		goto err;

	return (0);

err:
	/* restore the old */

	memcpy(buf, save, len);
	return (-1);
}


/*
 * COMPRESS_LABEL - 	compress a DNS name, must be passed an entire reply
 *			with the to be compressed name before the offset of 
 *			that reply.
 */

int
compress_label(u_char *buf, uint16_t offset, int labellen)
{
	u_char *label[10000];
	u_char *end = &buf[offset];
	struct question {
		uint16_t type;
		uint16_t class;
	} __attribute__((packed));
	struct answer {
		uint16_t type;
		uint16_t class;
		uint32_t ttl;
		uint16_t rdlength;	 
	} __attribute__((packed));
	struct soa {
         	uint32_t serial;
                uint32_t refresh;
                uint32_t retry;
                uint32_t expire;
                uint32_t minttl;
        } __attribute__((packed));

	struct answer *a;

	u_int i, j;
	u_int checklen;

	u_char *p, *e;
	u_char *compressmark;

	int elen;
	char expand[DNS_MAXNAME + 1];
	char *end_name = NULL;


	p = &buf[sizeof(struct dns_header)];
	label[0] = p;
	
	elen = 0;
	memset(&expand, 0, sizeof(expand));
	end_name = expand_compression((u_char *)&buf[sizeof(struct dns_header)],(u_char *)buf, (u_char *)&buf[offset], (u_char *)&expand, &elen, sizeof(expand));
	if (end_name == NULL) {
		dolog(LOG_ERR, "expand_compression() failed, bad formatted question name\n");
		return(0);
	}

	if ((plength(end_name, (void *)buf)) < elen) {
		dolog(LOG_ERR, "compression in question compress_label #1\n");
		return(0);
	}

	p = (u_char *)end_name;

	p += sizeof(struct question);	
	p++;	/* one more */
	/* start of answer/additional/authoritative */	
	/* XXX 10000 in case of AXFR should satisfy a envelope size 64K */
	for (i = 1; i < 10000; i++) {
		label[i] = p;

		while (p <= end && *p) {
			if ((*p & 0xc0) == 0xc0) {
				p++;
				break;
			}
			p += *p;
			p++;

			if (p >= end)
				goto end;
		}	
			
		p++;	/* one more */


		a = (struct answer *)p;
		p += sizeof(struct answer);	

		/* Thanks FreeLogic! */
		if (p >= end)
			goto end;

		switch (ntohs(a->type)) {
		case DNS_TYPE_A:
			p += sizeof(in_addr_t);
			break;
		case DNS_TYPE_EUI48:
			p += 6;
			break;
		case DNS_TYPE_EUI64:
			p += 8;
			break;
		case DNS_TYPE_AAAA:
			p += 16;		/* sizeof 4 * 32 bit */
			break;
		case DNS_TYPE_LOC:
			p += (4 + (3 * sizeof(uint32_t)));
			break;
		case DNS_TYPE_TXT:
			p += *p;
			p++;
			break;
		case DNS_TYPE_TLSA:
			p += 2;
			switch (*p) {
			case 1:
				p += DNS_TLSA_SIZE_SHA256 + 1;
				break;
			case 2:
				p += DNS_TLSA_SIZE_SHA512 + 1;
				break;
			default:
				/* XXX */
				goto end;
			}

			break;
		case DNS_TYPE_SSHFP:
			p++;
			switch (*p) {
			case 1:
				p += DNS_SSHFP_SIZE_SHA1 + 1;
				break;
			case 2:
				p += DNS_SSHFP_SIZE_SHA256 + 1;
				break;
			default:
				/* XXX */
				goto end;
			}

			break;	
		case DNS_TYPE_SRV:
			p += (2 * sizeof(uint16_t)); /* priority, weight */
			/* the port will be assumed in the fall through for
			   mx_priority..
			*/
			/* FALLTHROUGH */
		case DNS_TYPE_KX:
			/* FALLTHROUGH */
		case DNS_TYPE_MX:
			p += sizeof(uint16_t);	 /* mx_priority */
			/* FALLTHROUGH */
		case DNS_TYPE_NS:	
		case DNS_TYPE_PTR:
		case DNS_TYPE_CNAME:
			label[++i] = p;
			while (p <= end && *p) {
				if ((*p & 0xc0) == 0xc0) {
					p++;
					break;
				}
				p += *p;
				p++;

				if (p >= end)
					goto end;
			}	

			p++;	/* one more */
			break;
		case DNS_TYPE_RP:
			label[++i] = p;
			while (p <= end && *p) {
				if ((*p & 0xc0) == 0xc0) {
					p++;
					break;
				}
				p += *p;
				p++;

				if (p >= end)
					goto end;
			}	

			p++;	/* one more */

			if (p >= end)
				goto end;

			label[++i] = p;
			while (p <= end && *p) {
				if ((*p & 0xc0) == 0xc0) {
					p++;
					break;
				}
				p += *p;
				p++;

				if (p >= end)
					goto end;
			}	

			p++;	/* one more */

			if (p >= end)
				goto end;

			break;
		case DNS_TYPE_SOA:
			/* nsserver */
			label[++i] = p;
			while (p <= end && *p) {
				if ((*p & 0xc0) == 0xc0) {
					p++;
					break;
				}
				p += *p;
				p++;
				if (p >= end)
					goto end;
			}	

			p++;	/* one more */

			if (p >= end)
				break;

			/* responsible person */
			label[++i] = p;
			while (p <= end && *p) {
				if ((*p & 0xc0) == 0xc0) {
					p++;
					break;
				}
				p += *p;
				p++;
			}	

			p++;	/* one more */

			if (p >= end)
				break;

			p += sizeof(struct soa);	/* advance struct soa */

			break;
		case DNS_TYPE_NAPTR:
			p += (2 * sizeof(uint16_t)); /* order and preference */
			p += *p; /* flags */
			p++;
			p += *p; /* services */
			p++;
			p += *p; /* regexp */
			p++;
			
			label[++i] = p;
			while (p <= end && *p) {
				if ((*p & 0xc0) == 0xc0) {
					p++;
					break;
				}
				p += *p;
				p++;

				if (p >= end)
					goto end;
			}	

			p++;	/* one more */
			break;
	
		case DNS_TYPE_DNSKEY:
		case DNS_TYPE_CDNSKEY:
		case DNS_TYPE_DS:
		case DNS_TYPE_CDS:
		case DNS_TYPE_NSEC3:
		case DNS_TYPE_NSEC3PARAM:
		case DNS_TYPE_RRSIG:
		case DNS_TYPE_CAA:
		case DNS_TYPE_HINFO:
		case DNS_TYPE_ZONEMD:
		case DNS_TYPE_SVCB:
		case DNS_TYPE_HTTPS:
		case DNS_TYPE_IPSECKEY:
			/* above are FALLTHROUGH */
		default:
			p += a->rdlength;
			break;
		} /* switch */

		if (p >= end)
			break;
	} /* for (i *) */

end:
	
	p = &buf[offset - labellen];
	checklen = labellen;

	for (;*p != 0 && checklen > 0;) {
		for (j = 0; j < i; j++) {
			for (e = label[j]; *e; e += *e, e++) {
				if ((*e & 0xc0) == 0xc0) 
					break;

				if (memcasecmp(e, p, checklen) == 0) {
					/* e is now our compress offset */
					compressmark = e;
					goto out;		/* found one */
				}  
			}	/* for (e .. */
	
		} /* for (j .. */ 

		if (*p > DNS_MAXLABEL)
			return 0;		/* totally bogus label */

		checklen = nowrap_dec(checklen, *p);
		p += *p;
		checklen = nowrap_dec(checklen, 1);
		p++;
	}

	return (0);	 	/* no compression possible */

out:
	/* take off our compress length */
	offset = nowrap_dec(offset, checklen);
	/* write compressed label */
	pack16((char *)&buf[offset], htons((compressmark - &buf[0]) | 0xc000));

	offset += sizeof(uint16_t);	

	return (offset);
}

void
zonemd_hash_a(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
{
	char *tmpkey;
        char *q, *r;
        char **canonsort;
        struct rr *rrp2 = NULL;

        uint16_t clen;
        int csort = 0;
	int i, rlen;

	
        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	
	canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
	if (canonsort == NULL) {
		dolog(LOG_INFO, "canonsort out of memory\n");
		return;
	}

	csort = 0;

	
	TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
		q = tmpkey;
		pack(q, rbt->zone, rbt->zonelen);
		q += rbt->zonelen;
		pack16(q, htons(DNS_TYPE_A));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(rrset->ttl));
		q += 4;
		pack16(q, htons(sizeof(in_addr_t)));
		q += 2;
		pack32(q, ((struct a *)rrp2->rdata)->a);
		q += 4;

		r = canonsort[csort] = calloc(1, 68000);
		if (r == NULL) {
			dolog(LOG_INFO, "c1 out of memory\n");
			return;
		}

		clen = (plength(q, tmpkey));
		pack16(r, clen);
		r += 2;
		pack(r, tmpkey, clen);
		csort++;
	}
                
	r = canonical_sort(canonsort, csort, &rlen);
	if (r == NULL) {
		dolog(LOG_INFO, "canonical_sort failed\n");
		return;
	}

	delphinusdns_SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);

	free(tmpkey);
}

void
zonemd_hash_eui48(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
{
	char *tmpkey;
        char *q, *r;
        char **canonsort;
        struct rr *rrp2 = NULL;

        uint16_t clen;
        int csort = 0;
	int i, rlen;

	
        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	
	canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
	if (canonsort == NULL) {
		dolog(LOG_INFO, "canonsort out of memory\n");
		return;
	}

	csort = 0;

	
	TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
		q = tmpkey;
		pack(q, rbt->zone, rbt->zonelen);
		q += rbt->zonelen;
		pack16(q, htons(DNS_TYPE_EUI48));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(rrset->ttl));
		q += 4;
		pack16(q, htons(6));
		q += 2;
		pack(q, ((struct eui48 *)rrp2->rdata)->eui48, 6);
		q += 6;

		r = canonsort[csort] = calloc(1, 68000);
		if (r == NULL) {
			dolog(LOG_INFO, "c1 out of memory\n");
			return;
		}

		clen = (plength(q, tmpkey));
		pack16(r, clen);
		r += 2;
		pack(r, tmpkey, clen);
		csort++;
	}
                
	r = canonical_sort(canonsort, csort, &rlen);
	if (r == NULL) {
		dolog(LOG_INFO, "canonical_sort failed\n");
		return;
	}

	delphinusdns_SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);

	free(tmpkey);
}

void
zonemd_hash_eui64(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
{
	char *tmpkey;
        char *q, *r;
        char **canonsort;
        struct rr *rrp2 = NULL;

        uint16_t clen;
        int csort = 0;
	int i, rlen;

	
        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	
	canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
	if (canonsort == NULL) {
		dolog(LOG_INFO, "canonsort out of memory\n");
		return;
	}

	csort = 0;

	
	TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
		q = tmpkey;
		pack(q, rbt->zone, rbt->zonelen);
		q += rbt->zonelen;
		pack16(q, htons(DNS_TYPE_EUI64));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(rrset->ttl));
		q += 4;
		pack16(q, htons(8));
		q += 2;
		pack(q, ((struct eui64 *)rrp2->rdata)->eui64, 8);
		q += 8;

		r = canonsort[csort] = calloc(1, 68000);
		if (r == NULL) {
			dolog(LOG_INFO, "c1 out of memory\n");
			return;
		}

		clen = (plength(q, tmpkey));
		pack16(r, clen);
		r += 2;
		pack(r, tmpkey, clen);
		csort++;
	}
                
	r = canonical_sort(canonsort, csort, &rlen);
	if (r == NULL) {
		dolog(LOG_INFO, "canonical_sort failed\n");
		return;
	}

	delphinusdns_SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);

	free(tmpkey);
}

void
zonemd_hash_aaaa(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
{
	char *tmpkey;
        char *q, *r;
        char **canonsort;
        struct rr *rrp2 = NULL;

        uint16_t clen;
        int csort = 0;
	int i, rlen;

	
        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	
	canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
	if (canonsort == NULL) {
		dolog(LOG_INFO, "canonsort out of memory\n");
		return;
	}

	csort = 0;

	TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
		q = tmpkey;
		pack(q, rbt->zone, rbt->zonelen);
		q += rbt->zonelen;
		pack16(q, htons(DNS_TYPE_AAAA));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		/* the below uses rrp! because we can't have an rrsig differ */
		pack32(q, htonl(rrset->ttl));
		q += 4;
		pack16(q, htons(sizeof(struct in6_addr)));
		q += 2;
		pack(q, (char *)&((struct aaaa *)rrp2->rdata)->aaaa, sizeof(struct in6_addr));
		q += sizeof(struct in6_addr);

		r = canonsort[csort] = malloc(68000);
		if (r == NULL) {
			dolog(LOG_INFO, "c1 out of memory\n");
			return;
		}

		clen = (plength(q, tmpkey));
		pack16(r, clen);
		r += 2;
		pack(r, tmpkey, clen);

		csort++;
	}

	r = canonical_sort(canonsort, csort, &rlen);
	if (r == NULL) {
		dolog(LOG_INFO, "canonical_sort failed\n");
		return;
	}

	delphinusdns_SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);
}

void
zonemd_hash_soa(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt, uint32_t *serial)
{
	char *tmpkey;
        char *p;
        struct rr *rrp = NULL;

	int keylen;

        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	rrp = TAILQ_FIRST(&rrset->rr_head);
	if (rrp == NULL) {
		dolog(LOG_INFO, "no SOA records but have rrset entry!\n");
		return;
	}

	p = tmpkey;
	
	pack(p, rbt->zone, rbt->zonelen);
	p += rbt->zonelen;
	pack16(p, htons(DNS_TYPE_SOA));
	p += 2;
	pack16(p, htons(DNS_CLASS_IN));
	p += 2;
	pack32(p, htonl(rrset->ttl));
	p += 4;
	pack16(p, htons(((struct soa *)rrp->rdata)->nsserver_len + ((struct soa *)rrp->rdata)->rp_len + 4 + 4 + 4 + 4 + 4));
	p += 2;
	pack(p, ((struct soa *)rrp->rdata)->nsserver, ((struct soa *)rrp->rdata)->nsserver_len);
	p += ((struct soa *)rrp->rdata)->nsserver_len;
	pack(p, ((struct soa *)rrp->rdata)->responsible_person, ((struct soa *)rrp->rdata)->rp_len);
	p += ((struct soa *)rrp->rdata)->rp_len;
	pack32(p, htonl(((struct soa *)rrp->rdata)->serial));
	p += sizeof(uint32_t);

	*serial = ((struct soa *)rrp->rdata)->serial;

	pack32(p, htonl(((struct soa *)rrp->rdata)->refresh));
	p += sizeof(uint32_t);
	pack32(p, htonl(((struct soa *)rrp->rdata)->retry));
	p += sizeof(uint32_t);

	pack32(p, htonl(((struct soa *)rrp->rdata)->expire));
	p += sizeof(uint32_t);
	pack32(p, htonl(((struct soa *)rrp->rdata)->minttl));
	p += sizeof(uint32_t);

	keylen = (plength(p, tmpkey));

	delphinusdns_SHA384_Update(ctx, tmpkey, keylen);

	free(tmpkey);
}
void
zonemd_hash_ns(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
{
	char *tmpkey;
        char *q, *r;
        char **canonsort;
        struct rr *rrp2 = NULL;

        uint16_t clen;
        int csort = 0;
	int i, rlen;

	
        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	
	canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
	if (canonsort == NULL) {
		dolog(LOG_INFO, "canonsort out of memory\n");
		return;
	}

	csort = 0;

	TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
		q = tmpkey;
		pack(q, rbt->zone, rbt->zonelen);
		q += rbt->zonelen;
		pack16(q, htons(DNS_TYPE_NS));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(rrset->ttl));
		q += 4;
		pack16(q, htons(((struct ns *)rrp2->rdata)->nslen));
		q += 2;
		memcpy(q, ((struct ns *)rrp2->rdata)->nsserver, ((struct ns *)rrp2->rdata)->nslen);
		q += ((struct ns *)rrp2->rdata)->nslen;

		r = canonsort[csort] = malloc(68000);
		if (r == NULL) {
			dolog(LOG_INFO, "c1 out of memory\n");
			return;
		}

		clen = (plength(q, tmpkey));
		pack16(r, clen);
		r += 2;
		pack(r, tmpkey, clen);

		csort++;
	}

	r = canonical_sort(canonsort, csort, &rlen);
	if (r == NULL) {
		dolog(LOG_INFO, "canonical_sort failed\n");
		return;
	}

	delphinusdns_SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);

}
void
zonemd_hash_cname(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
{
	char *tmpkey;
        char *p;

	int keylen;
        struct rr *rrp = NULL;

	
        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	rrp = TAILQ_FIRST(&rrset->rr_head);
	if (rrp == NULL) {
		dolog(LOG_INFO, "no CNAME records but have flags!\n");
		return;
	}


	p = &tmpkey[0];
	
	pack(p, rbt->zone, rbt->zonelen);
	p += rbt->zonelen;
	pack16(p, htons(DNS_TYPE_CNAME));
	p += 2;
	pack16(p, htons(DNS_CLASS_IN));
	p += 2;
	pack32(p, htonl(rrset->ttl));
	p += 4;
	pack16(p, htons(((struct cname *)rrp->rdata)->cnamelen));
	p += 2;
	pack(p, ((struct cname *)rrp->rdata)->cname, ((struct cname *)rrp->rdata)->cnamelen);
	p += ((struct cname *)rrp->rdata)->cnamelen;

	keylen = (plength(p, tmpkey));     

	delphinusdns_SHA384_Update(ctx, tmpkey, keylen);

	free(tmpkey);
}


void
zonemd_hash_ptr(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
{
	char *tmpkey;
        char *p;

	int keylen;
        struct rr *rrp = NULL;

	
        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	rrp = TAILQ_FIRST(&rrset->rr_head);
	if (rrp == NULL) {
		dolog(LOG_INFO, "no PTR records but have flags!\n");
		return;
	}


	p = &tmpkey[0];

	pack(p, rbt->zone, rbt->zonelen);
	p += rbt->zonelen;
	pack16(p, htons(DNS_TYPE_PTR));
	p += 2;
	pack16(p, htons(DNS_CLASS_IN));
	p += 2;
	pack32(p, htonl(rrset->ttl));
	p += 4;
	pack16(p, htons(((struct ptr *)rrp->rdata)->ptrlen));
	p += 2;
	pack(p, ((struct ptr *)rrp->rdata)->ptr, ((struct ptr *)rrp->rdata)->ptrlen);
	p += ((struct ptr *)rrp->rdata)->ptrlen;
	
	keylen = (plength(p, tmpkey));     

	delphinusdns_SHA384_Update(ctx, tmpkey, keylen);

	free(tmpkey);

}
void
zonemd_hash_https(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
{
	char *tmpkey;
        char *q, *r;
        char **canonsort;
        struct rr *rrp2 = NULL;

        uint16_t clen;
        int csort = 0;
	int i, rlen;

	
        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	
	canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
	if (canonsort == NULL) {
		dolog(LOG_INFO, "canonsort out of memory\n");
		return;
	}

	csort = 0;

	TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
		q = tmpkey;
		pack(q, rbt->zone, rbt->zonelen);
		q += rbt->zonelen;
		pack16(q, htons(DNS_TYPE_HTTPS));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		/* the below uses rrp! because we can't have an rrsig differ */
		pack32(q, htonl(rrset->ttl));
		q += 4;

		pack16(q, htons(((struct https *)rrp2->rdata)->priority));
		q += 2;
		
		pack(q, (char *)((struct https *)rrp2->rdata)->target, ((struct https *)rrp2->rdata)->targetlen);
		q += ((struct https *)rrp2->rdata)->targetlen;


		pack16(q, htons(((struct https *)rrp2->rdata)->paramlen));
		q += 2;
		pack(q, (char *)((struct https *)rrp2->rdata)->param, ((struct https *)rrp2->rdata)->paramlen);
		q += ((struct https *)rrp2->rdata)->paramlen;

		r = canonsort[csort] = malloc(68000);
		if (r == NULL) {
			dolog(LOG_INFO, "c1 out of memory\n");
			return;
		}
		clen = (plength(q, tmpkey));
		pack16(r, clen);
		r += 2;
		pack(r, tmpkey, clen);

		csort++;
	}

	r = canonical_sort(canonsort, csort, &rlen);
	if (r == NULL) {
		dolog(LOG_INFO, "canonical_sort failed\n");
		return;
	}

	delphinusdns_SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);


}
void
zonemd_hash_svcb(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
{
	char *tmpkey;
        char *q, *r;
        char **canonsort;
        struct rr *rrp2 = NULL;

        uint16_t clen;
        int csort = 0;
	int i, rlen;

	
        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	
	canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
	if (canonsort == NULL) {
		dolog(LOG_INFO, "canonsort out of memory\n");
		return;
	}

	csort = 0;

	TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
		q = tmpkey;
		pack(q, rbt->zone, rbt->zonelen);
		q += rbt->zonelen;
		pack16(q, htons(DNS_TYPE_SVCB));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		/* the below uses rrp! because we can't have an rrsig differ */
		pack32(q, htonl(rrset->ttl));
		q += 4;

		pack16(q, htons(((struct svcb *)rrp2->rdata)->priority));
		q += 2;
		
		pack(q, (char *)((struct svcb *)rrp2->rdata)->target, ((struct svcb *)rrp2->rdata)->targetlen);
		q += ((struct svcb *)rrp2->rdata)->targetlen;


		pack16(q, htons(((struct svcb *)rrp2->rdata)->paramlen));
		q += 2;
		pack(q, (char *)((struct svcb *)rrp2->rdata)->param, ((struct svcb *)rrp2->rdata)->paramlen);
		q += ((struct svcb *)rrp2->rdata)->paramlen;

		r = canonsort[csort] = malloc(68000);
		if (r == NULL) {
			dolog(LOG_INFO, "c1 out of memory\n");
			return;
		}
		clen = (plength(q, tmpkey));
		pack16(r, clen);
		r += 2;
		pack(r, tmpkey, clen);

		csort++;
	}

	r = canonical_sort(canonsort, csort, &rlen);
	if (r == NULL) {
		dolog(LOG_INFO, "canonical_sort failed\n");
		return;
	}

	delphinusdns_SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);


}
void
zonemd_hash_txt(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
{
	char *tmpkey;
        char *q, *r;
        char **canonsort;
        struct rr *rrp2 = NULL;

        uint16_t clen;
        int csort = 0;
	int i, rlen;

	
        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	
	canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
	if (canonsort == NULL) {
		dolog(LOG_INFO, "canonsort out of memory\n");
		return;
	}

	csort = 0;

	TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
		q = tmpkey;
		pack(q, rbt->zone, rbt->zonelen);
		q += rbt->zonelen;
		pack16(q, htons(DNS_TYPE_TXT));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		/* the below uses rrp! because we can't have an rrsig differ */
		pack32(q, htonl(rrset->ttl));
		q += 4;
		pack16(q, htons(((struct txt *)rrp2->rdata)->txtlen));
		q += 2;
		pack(q, (char *)((struct txt *)rrp2->rdata)->txt, ((struct txt *)rrp2->rdata)->txtlen);
		q += ((struct txt *)rrp2->rdata)->txtlen;

		r = canonsort[csort] = malloc(68000);
		if (r == NULL) {
			dolog(LOG_INFO, "c1 out of memory\n");
			return;
		}
		clen = (plength(q, tmpkey));
		pack16(r, clen);
		r += 2;
		pack(r, tmpkey, clen);

		csort++;
	}

	r = canonical_sort(canonsort, csort, &rlen);
	if (r == NULL) {
		dolog(LOG_INFO, "canonical_sort failed\n");
		return;
	}

	delphinusdns_SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);


}
void
zonemd_hash_rp(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
{
	char *tmpkey;
        char *q, *r;
        char **canonsort;
        struct rr *rrp2 = NULL;

        uint16_t clen;
        int csort = 0;
	int i, rlen;

	
        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	
	canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
	if (canonsort == NULL) {
		dolog(LOG_INFO, "canonsort out of memory\n");
		return;
	}

	csort = 0;

	TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
		q = tmpkey;
		pack(q, rbt->zone, rbt->zonelen);
		q += rbt->zonelen;
		pack16(q, htons(DNS_TYPE_RP));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(rrset->ttl));
		q += 4;
		pack16(q, htons(((struct rp *)rrp2->rdata)->mboxlen + ((struct rp *)rrp2->rdata)->txtlen));
		q += 2;

		pack(q, ((struct rp *)rrp2->rdata)->mbox, ((struct rp *)rrp2->rdata)->mboxlen);
		q += ((struct rp *)rrp2->rdata)->mboxlen;

		pack(q, ((struct rp *)rrp2->rdata)->txt, ((struct rp *)rrp2->rdata)->txtlen);
		q += ((struct rp *)rrp2->rdata)->txtlen;

		r = canonsort[csort] = malloc(68000);
		if (r == NULL) {
        		dolog(LOG_INFO, "c1 out of memory\n");
        		return;
		}

		clen = (plength(q, tmpkey));
		pack16(r, clen);
		r += 2;
		pack(r, tmpkey, clen);

		csort++;
	}


	r = canonical_sort(canonsort, csort, &rlen);
	if (r == NULL) {
		dolog(LOG_INFO, "canonical_sort failed\n");
		return;
	}

	delphinusdns_SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);


}


void
zonemd_hash_hinfo(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
{
	char *tmpkey;
        char *q, *r;
        char **canonsort;
        struct rr *rrp2 = NULL;

        uint16_t clen;
        int csort = 0;
	int i, rlen;

	
        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	
	canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
	if (canonsort == NULL) {
		dolog(LOG_INFO, "canonsort out of memory\n");
		return;
	}

	csort = 0;

	TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
		q = tmpkey;
		pack(q, rbt->zone, rbt->zonelen);
		q += rbt->zonelen;
		pack16(q, htons(DNS_TYPE_HINFO));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(rrset->ttl));
		q += 4;
		pack16(q, htons(2 + ((struct hinfo *)rrp2->rdata)->cpulen + ((struct hinfo *)rrp2->rdata)->oslen));
		q += 2;
		
		pack8(q, ((struct hinfo *)rrp2->rdata)->cpulen);
		q++;
		pack(q, ((struct hinfo *)rrp2->rdata)->cpu, ((struct hinfo *)rrp2->rdata)->cpulen);
		q += ((struct hinfo *)rrp2->rdata)->cpulen;
		
		pack8(q, ((struct hinfo *)rrp2->rdata)->oslen);
		q++;
		pack(q, ((struct hinfo *)rrp2->rdata)->os, ((struct hinfo *)rrp2->rdata)->oslen);
		q += ((struct hinfo *)rrp2->rdata)->oslen;
		
		r = canonsort[csort] = malloc(68000);
		if (r == NULL) {
		        dolog(LOG_INFO, "c1 out of memory\n");
		        return;
		}
		
		clen = (plength(q, tmpkey));
		pack16(r, clen);
		r += 2;
		pack(r, tmpkey, clen);
		
		csort++;
	}

	r = canonical_sort(canonsort, csort, &rlen);
	if (r == NULL) {
		dolog(LOG_INFO, "canonical_sort failed\n");
		return;
	}

	delphinusdns_SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);

	

}
void
zonemd_hash_srv(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
{
	char *tmpkey;
        char *q, *r;
        char **canonsort;
        struct rr *rrp2 = NULL;

        uint16_t clen;
        int csort = 0;
	int i, rlen;

	
        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	
	canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
	if (canonsort == NULL) {
		dolog(LOG_INFO, "canonsort out of memory\n");
		return;
	}

	csort = 0;

	TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
		q = tmpkey;
		pack(q, rbt->zone, rbt->zonelen);
		q += rbt->zonelen;
		pack16(q, htons(DNS_TYPE_SRV));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(rrset->ttl));
		q += 4;
		pack16(q, htons(2 + 2 + 2 + ((struct srv *)rrp2->rdata)->targetlen));
		q += 2;
		pack16(q, htons(((struct srv *)rrp2->rdata)->priority));
		q += 2;
		pack16(q, htons(((struct srv *)rrp2->rdata)->weight));
		q += 2;
		pack16(q, htons(((struct srv *)rrp2->rdata)->port));
		q += 2;
		pack(q, ((struct srv *)rrp2->rdata)->target, ((struct srv *)rrp2->rdata)->targetlen);
		q += ((struct srv *)rrp2->rdata)->targetlen;
		r = canonsort[csort] = malloc(68000);
		if (r == NULL) {
		        dolog(LOG_INFO, "c1 out of memory\n");
		        return;
		}

		clen = (plength(q, tmpkey));
		pack16(r, clen);
		r += 2;
		pack(r, tmpkey, clen);

		csort++;

	}

	r = canonical_sort(canonsort, csort, &rlen);
	if (r == NULL) {
		dolog(LOG_INFO, "canonical_sort failed\n");
		return;
	}

	delphinusdns_SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);
	

}


void
zonemd_hash_naptr(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
{
	char *tmpkey;
        char *q, *r;
        char **canonsort;
        struct rr *rrp2 = NULL;

        uint16_t clen;
        int csort = 0;
	int i, rlen;

	
        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	
	canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
	if (canonsort == NULL) {
		dolog(LOG_INFO, "canonsort out of memory\n");
		return;
	}

	csort = 0;

	TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
		q = tmpkey;
		pack(q, rbt->zone, rbt->zonelen);
		q += rbt->zonelen;
		pack16(q, htons(DNS_TYPE_NAPTR));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(rrset->ttl));
		q += 4;
		pack16(q, htons(2 + 2 + 1 + ((struct naptr *)rrp2->rdata)->flagslen + 1 + ((struct naptr *)rrp2->rdata)->serviceslen + 1 + ((struct naptr *)rrp2->rdata)->regexplen + ((struct naptr *)rrp2->rdata)->replacementlen));
		q += 2;
		pack16(q, htons(((struct naptr *)rrp2->rdata)->order));
		q += 2;
		pack16(q, htons(((struct naptr *)rrp2->rdata)->preference));
		q += 2;
		
		pack8(q, ((struct naptr *)rrp2->rdata)->flagslen);
		q++;
		pack(q, ((struct naptr *)rrp2->rdata)->flags, ((struct naptr *)rrp2->rdata)->flagslen);
		q += ((struct naptr *)rrp2->rdata)->flagslen;

		pack8(q, ((struct naptr *)rrp2->rdata)->serviceslen);
		q++;
		pack(q, ((struct naptr *)rrp2->rdata)->services, ((struct naptr *)rrp2->rdata)->serviceslen);
		q += ((struct naptr *)rrp2->rdata)->serviceslen;
		
		pack8(q, ((struct naptr *)rrp2->rdata)->regexplen);
		q++;
		pack(q, ((struct naptr *)rrp2->rdata)->regexp, ((struct naptr *)rrp2->rdata)->regexplen);
		q += ((struct naptr *)rrp2->rdata)->regexplen;
		
		pack(q, ((struct naptr *)rrp2->rdata)->replacement, ((struct naptr *)rrp2->rdata)->replacementlen);
		q += ((struct naptr *)rrp2->rdata)->replacementlen;
		
		r = canonsort[csort] = malloc(68000);
		if (r == NULL) {
		        dolog(LOG_INFO, "c1 out of memory\n");
		        return;
		}
		
		clen = (plength(q, tmpkey));
		pack16(r, clen);
		r += 2;
		pack(r, tmpkey, clen);

		csort++;
	}

	r = canonical_sort(canonsort, csort, &rlen);
	if (r == NULL) {
		dolog(LOG_INFO, "canonical_sort failed\n");
		return;
	}

	delphinusdns_SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);
}


void
zonemd_hash_caa(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
{
	char *tmpkey;
        char *q, *r;
        char **canonsort;
        struct rr *rrp2 = NULL;

        uint16_t clen;
        int csort = 0;
	int i, rlen;

	
        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	
	canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
	if (canonsort == NULL) {
		dolog(LOG_INFO, "canonsort out of memory\n");
		return;
	}

	csort = 0;

	TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
		q = tmpkey;
		pack(q, rbt->zone, rbt->zonelen);
		q += rbt->zonelen;
		pack16(q, htons(DNS_TYPE_CAA));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(rrset->ttl));
		q += 4;
		pack16(q, htons(1 + 1 + ((struct caa *)rrp2->rdata)->taglen + ((struct caa *)rrp2->rdata)->valuelen));
		q += 2;
		
		pack8(q, ((struct caa *)rrp2->rdata)->flags);
		q++;
		pack8(q, ((struct caa *)rrp2->rdata)->taglen);
		q++;
		pack(q, ((struct caa *)rrp2->rdata)->tag, ((struct caa *)rrp2->rdata)->taglen);
		q += ((struct caa *)rrp2->rdata)->taglen;
		pack(q, ((struct caa *)rrp2->rdata)->value, ((struct caa *)rrp2->rdata)->valuelen);
		q += ((struct caa *)rrp2->rdata)->valuelen;
		
		r = canonsort[csort] = malloc(68000);
		if (r == NULL) {
		        dolog(LOG_INFO, "c1 out of memory\n");
		        return;
		}

		clen = (plength(q, tmpkey));
		pack16(r, clen);
		r += 2;
		pack(r, tmpkey, clen);

		csort++;
	}

	r = canonical_sort(canonsort, csort, &rlen);
	if (r == NULL) {
		dolog(LOG_INFO, "canonical_sort failed\n");
		return;
	}

	delphinusdns_SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);

}

void
zonemd_hash_ipseckey(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
{
	char *tmpkey;
        char *q, *r;
        char **canonsort;
        struct rr *rrp2 = NULL;

        uint16_t clen;
        int csort = 0;
	int i, rlen;
	int gwlen;

	
        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	
	canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
	if (canonsort == NULL) {
		dolog(LOG_INFO, "canonsort out of memory\n");
		return;
	}

	csort = 0;

	TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
		q = tmpkey;
		pack(q, rbt->zone, rbt->zonelen);
		q += rbt->zonelen;
		pack16(q, htons(DNS_TYPE_IPSECKEY));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(rrset->ttl));
		q += 4;
		pack16(q, htons(2 + ((struct kx *)rrp2->rdata)->exchangelen));
		q += 2;

		pack8(q, ((struct ipseckey *)rrp2->rdata)->precedence);
		q++;
		pack8(q, ((struct ipseckey *)rrp2->rdata)->gwtype);
		q++;
		pack8(q, ((struct ipseckey *)rrp2->rdata)->alg);
		q++;

		switch (((struct ipseckey *)rrp2->rdata)->gwtype) {
		case 1:
			gwlen = 4;
			break;
		case 2:
			gwlen = 16;
			break;
		case 3:
			gwlen = ((struct ipseckey *)rrp2->rdata)->dnsnamelen;
			break;
		default:
			gwlen = 0;
			break;
		}

		if (gwlen) {
			memcpy(q, (char *)&((struct ipseckey *)rrp2->rdata)->gateway, gwlen);
			q += gwlen;
		}

		memcpy(q, ((struct ipseckey *)rrp2->rdata)->key, ((struct ipseckey *)rrp2->rdata)->keylen);
		q += ((struct kx *)rrp2->rdata)->exchangelen;
		
		r = canonsort[csort] = malloc(68000);
		if (r == NULL) {
			dolog(LOG_INFO, "c1 out of memory\n");
			return;
		}

		clen = (plength(q, tmpkey));
		pack16(r, clen);
		r += 2;
		pack(r, tmpkey, clen);
		
		csort++;
	}

	r = canonical_sort(canonsort, csort, &rlen);
	if (r == NULL) {
		dolog(LOG_INFO, "canonical_sort failed\n");
		return;
	}

	delphinusdns_SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);
}


void
zonemd_hash_kx(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
{
	char *tmpkey;
        char *q, *r;
        char **canonsort;
        struct rr *rrp2 = NULL;

        uint16_t clen;
        int csort = 0;
	int i, rlen;

	
        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	
	canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
	if (canonsort == NULL) {
		dolog(LOG_INFO, "canonsort out of memory\n");
		return;
	}

	csort = 0;

	TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
		q = tmpkey;
		pack(q, rbt->zone, rbt->zonelen);
		q += rbt->zonelen;
		pack16(q, htons(DNS_TYPE_KX));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(rrset->ttl));
		q += 4;
		pack16(q, htons(2 + ((struct kx *)rrp2->rdata)->exchangelen));
		q += 2;
		pack16(q, htons(((struct kx *)rrp2->rdata)->preference));
		q += 2;
		memcpy(q, ((struct kx *)rrp2->rdata)->exchange, ((struct kx *)rrp2->rdata)->exchangelen);
		q += ((struct kx *)rrp2->rdata)->exchangelen;
		
		r = canonsort[csort] = malloc(68000);
		if (r == NULL) {
			dolog(LOG_INFO, "c1 out of memory\n");
			return;
		}

		clen = (plength(q, tmpkey));
		pack16(r, clen);
		r += 2;
		pack(r, tmpkey, clen);
		
		csort++;
	}

	r = canonical_sort(canonsort, csort, &rlen);
	if (r == NULL) {
		dolog(LOG_INFO, "canonical_sort failed\n");
		return;
	}

	delphinusdns_SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);
}


void
zonemd_hash_nsec(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
{
	char *tmpkey;
        char *q, *r;
        char **canonsort;
        struct rr *rrp2 = NULL;

        uint16_t clen;
        int csort = 0;
	int i, rlen;

	
        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	
	canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
	if (canonsort == NULL) {
		dolog(LOG_INFO, "canonsort out of memory\n");
		return;
	}

	csort = 0;

	TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
		q = tmpkey;
		pack(q, rbt->zone, rbt->zonelen);
		q += rbt->zonelen;
		pack16(q, htons(DNS_TYPE_NSEC));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(rrset->ttl));
		q += 4;
		pack16(q, htons(((struct nsec *)rrp2->rdata)->next_len + \
			((struct nsec *)rrp2->rdata)->bitmap_len));
		q += 2;
		memcpy(q, ((struct nsec *)rrp2->rdata)->next, ((struct nsec *)rrp2->rdata)->next_len);
		q += ((struct nsec *)rrp2->rdata)->next_len;
		memcpy(q, ((struct nsec *)rrp2->rdata)->bitmap, ((struct nsec *)rrp2->rdata)->bitmap_len);
		q += ((struct nsec *)rrp2->rdata)->bitmap_len;
		
		r = canonsort[csort] = malloc(68000);
		if (r == NULL) {
			dolog(LOG_INFO, "c1 out of memory\n");
			return;
		}

		clen = (plength(q, tmpkey));
		pack16(r, clen);
		r += 2;
		pack(r, tmpkey, clen);
		
		csort++;
	}

	r = canonical_sort(canonsort, csort, &rlen);
	if (r == NULL) {
		dolog(LOG_INFO, "canonical_sort failed\n");
		return;
	}

	delphinusdns_SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);
}

void
zonemd_hash_mx(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
{
	char *tmpkey;
        char *q, *r;
        char **canonsort;
        struct rr *rrp2 = NULL;

        uint16_t clen;
        int csort = 0;
	int i, rlen;

	
        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	
	canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
	if (canonsort == NULL) {
		dolog(LOG_INFO, "canonsort out of memory\n");
		return;
	}

	csort = 0;

	TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
		q = tmpkey;
		pack(q, rbt->zone, rbt->zonelen);
		q += rbt->zonelen;
		pack16(q, htons(DNS_TYPE_MX));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(rrset->ttl));
		q += 4;
		pack16(q, htons(2 + ((struct smx *)rrp2->rdata)->exchangelen));
		q += 2;
		pack16(q, htons(((struct smx *)rrp2->rdata)->preference));
		q += 2;
		memcpy(q, ((struct smx *)rrp2->rdata)->exchange, ((struct smx *)rrp2->rdata)->exchangelen);
		q += ((struct smx *)rrp2->rdata)->exchangelen;
		
		r = canonsort[csort] = malloc(68000);
		if (r == NULL) {
			dolog(LOG_INFO, "c1 out of memory\n");
			return;
		}

		clen = (plength(q, tmpkey));
		pack16(r, clen);
		r += 2;
		pack(r, tmpkey, clen);
		
		csort++;
	}

	r = canonical_sort(canonsort, csort, &rlen);
	if (r == NULL) {
		dolog(LOG_INFO, "canonical_sort failed\n");
		return;
	}

	delphinusdns_SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);
}

void
zonemd_hash_loc(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
{
	char *tmpkey;
        char *q, *r;
        char **canonsort;
        struct rr *rrp2 = NULL;

        uint16_t clen;
        int csort = 0;
	int i, rlen;

	
        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	
	canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
	if (canonsort == NULL) {
		dolog(LOG_INFO, "canonsort out of memory\n");
		return;
	}

	csort = 0;

	TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
		q = tmpkey;
		pack(q, rbt->zone, rbt->zonelen);
		q += rbt->zonelen;
		pack16(q, htons(DNS_TYPE_LOC));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(rrset->ttl));
		q += 4;
		pack16(q, htons(4 + (3 * sizeof(uint32_t))));
		q += 2;
		pack8(q, ((struct loc *)rrp2->rdata)->version);
		q++;
		pack8(q, ((struct loc *)rrp2->rdata)->size);
		q++;
		pack8(q, ((struct loc *)rrp2->rdata)->horiz_pre);
		q++;
		pack8(q, ((struct loc *)rrp2->rdata)->vert_pre);
		q++;
		pack32(q, ((struct loc *)rrp2->rdata)->latitude);
		q++;
		pack32(q, ((struct loc *)rrp2->rdata)->longitude);
		q++;
		pack32(q, ((struct loc *)rrp2->rdata)->altitude);
		q++;
		r = canonsort[csort] = malloc(68000);
		if (r == NULL) {
			dolog(LOG_INFO, "c1 out of memory\n");
			return;
		}
		
		clen = (plength(q, tmpkey));
		pack16(r, clen);
		r += 2;
		pack(r, tmpkey, clen);

		csort++;
	}

	r = canonical_sort(canonsort, csort, &rlen);
	if (r == NULL) {
		dolog(LOG_INFO, "canonical_sort failed\n");
		return;
	}

	delphinusdns_SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);
}

void
zonemd_hash_tlsa(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
{
	char *tmpkey;
        char *q, *r;
        char **canonsort;
        struct rr *rrp2 = NULL;

        uint16_t clen;
        int csort = 0;
	int i, rlen;

	
        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	
	canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
	if (canonsort == NULL) {
		dolog(LOG_INFO, "canonsort out of memory\n");
		return;
	}

	csort = 0;

	TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
		q = tmpkey;
		pack(q, rbt->zone, rbt->zonelen);
		q += rbt->zonelen;
		pack16(q, htons(DNS_TYPE_TLSA));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(rrset->ttl));
		q += 4;
		pack16(q, htons(1 + 1 + 1 + ((struct tlsa *)rrp2->rdata)->datalen));
		q += 2;
		pack8(q, ((struct tlsa *)rrp2->rdata)->usage);
		q++;
		pack8(q, ((struct tlsa *)rrp2->rdata)->selector);
		q++;
		pack8(q, ((struct tlsa *)rrp2->rdata)->matchtype);
		q++;
		pack(q, ((struct tlsa *)rrp2->rdata)->data, ((struct tlsa *)rrp2->rdata)->datalen);
		q += ((struct tlsa *)rrp2->rdata)->datalen;
		r = canonsort[csort] = malloc(68000);
		if (r == NULL) {
			dolog(LOG_INFO, "c1 out of memory\n");
			return;
		}
		
		clen = (plength(q, tmpkey));
		pack16(r, clen);
		r += 2;
		pack(r, tmpkey, clen);

		csort++;
	}

	r = canonical_sort(canonsort, csort, &rlen);
	if (r == NULL) {
		dolog(LOG_INFO, "canonical_sort failed\n");
		return;
	}

	delphinusdns_SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);
}


void
zonemd_hash_sshfp(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
{
	char *tmpkey;
        char *q, *r;
        char **canonsort;
        struct rr *rrp2 = NULL;

        uint16_t clen;
        int csort = 0;
	int i, rlen;

	
        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	
	canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
	if (canonsort == NULL) {
		dolog(LOG_INFO, "canonsort out of memory\n");
		return;
	}

	csort = 0;

	TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
		q = tmpkey;
		pack(q, rbt->zone, rbt->zonelen);
		q += rbt->zonelen;
		pack16(q, htons(DNS_TYPE_SSHFP));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(rrset->ttl));
		q += 4;
		pack16(q, htons(1 + 1 + ((struct sshfp *)rrp2->rdata)->fplen));
		q += 2;
		pack8(q, ((struct sshfp *)rrp2->rdata)->algorithm);
		q++;
		pack8(q, ((struct sshfp *)rrp2->rdata)->fptype);
		q++;
		pack(q, ((struct sshfp *)rrp2->rdata)->fingerprint, ((struct sshfp *)rrp2->rdata)->fplen);
		q += ((struct sshfp *)rrp2->rdata)->fplen;
		
		r = canonsort[csort] = malloc(68000);
		if (r == NULL) {
			dolog(LOG_INFO, "c1 out of memory\n");
			return;
		}
		
		clen = (plength(q, tmpkey));
		pack16(r, clen);
		r += 2;
		pack(r, tmpkey, clen);

		csort++;
	}

	r = canonical_sort(canonsort, csort, &rlen);
	if (r == NULL) {
		dolog(LOG_INFO, "canonical_sort failed\n");
		return;
	}

	delphinusdns_SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);

}

char *
canonical_sort(char **canonsort, int csort, int *rlen)
{
	int totallen = 0;
	int i;
	uint16_t len;
	char *p, *q, *rp = NULL;
	char *array, *r;

	
	array = calloc(csort, 68000);
	if (array == NULL)
		return NULL;

	r = array;

	for (i = 0; i < csort; i++) {
		p = canonsort[i];
		len = unpack16(p);	
		totallen += len;

		memcpy(r, p, len + 2);
		r += 68000;
	}
	

	qsort((void*)array, csort, 68000, cs_cmp);

	rp = malloc(totallen);
	if (rp == NULL) {
		return NULL;
	}

	q = &rp[0];
	r = array;

	for (i = 0; i < csort; i++) {
		len = unpack16(r);	
		r += 2;
		unpack(q, r, len);
		q += len;
		r += (68000 - 2);
	}

	free(array);

#if 0
	printf("dumping canonsort\n");
	for (i = 0; i < totallen; i++) {
		if (i && i % 16 == 0)
			printf("\n");
		printf("%02x, ", rp[i] & 0xff);
	}
	printf("\n");
#endif

	*rlen = totallen;
	return (rp);
}

static int
cs_cmp(const void *a, const void *b)
{
	uint16_t lena = unpack16((char *)a);
	uint16_t lenb = unpack16((char *)b);
	u_char *a2 = ((u_char *)a + 2);
	u_char *b2 = ((u_char *)b + 2);
	int i, mlen, ret;

	mlen = MIN(lena, lenb);

	/* skip the dnsname (no compression here) */
	for (i = 0; i < mlen; i++) {
		if (a2[i] != 0) {
			i += a2[i];
		} else {
			break;
		}
	}

	i++;	/* advance 1 to the ttl */
	i += 2;  /* type */
	i += 2;  /* class */
	i += 4;	 /* ttl */

	ret = memcmp(&a2[0], &b2[0], i);
	if (ret != 0)
		return (ret);

	i += 2;  /* rdlen */

	for (; i < mlen; i++) {
		if (a2[i] < b2[i])
			return -1;
		else if (a2[i] > b2[i])
			return 1;
	}

	/* if they are still equal the shorter one wins */
		
	if (lena < lenb)
		return -1;
	else if (lena > lenb)
		return 1;
	else
		return 0;
}

struct zonemd *
zonemd_hash_zonemd(struct rrset *rrset, struct rbtree *rbt)
{
	struct zonemd *zonemd;
        struct rr *rrp = NULL;

	rrp = TAILQ_FIRST(&rrset->rr_head);
	if (rrp == NULL) {
		dolog(LOG_INFO, "no ZONEMD records but have flags!\n");
		return NULL;
	}

	zonemd = malloc(sizeof(struct zonemd));	
	if (zonemd == NULL) {
		dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
		return NULL;
	}

	memcpy(zonemd, rrp->rdata, sizeof(struct zonemd));

	return (zonemd);
}

void
zonemd_hash_cds(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
{
	char *tmpkey;
        char *q, *r;
        char **canonsort;
        struct rr *rrp2 = NULL;

        uint16_t clen;
        int csort = 0;
	int i, rlen;

	
        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	
	canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
	if (canonsort == NULL) {
		dolog(LOG_INFO, "canonsort out of memory\n");
		return;
	}

	csort = 0;

	TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
		q = tmpkey;
		pack(q, rbt->zone, rbt->zonelen);
		q += rbt->zonelen;
		pack16(q, htons(DNS_TYPE_CDS));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(rrset->ttl));
		q += 4;
		pack16(q, htons(2 + 1 + 1 + ((struct cds *)rrp2->rdata)->digestlen));
		q += 2;
		pack16(q, htons(((struct cds *)rrp2->rdata)->key_tag));
		q += 2;
		pack8(q, ((struct cds *)rrp2->rdata)->algorithm);
		q++;
		pack8(q, ((struct cds *)rrp2->rdata)->digest_type);
		q++;
		pack(q, ((struct cds *)rrp2->rdata)->digest, ((struct cds *)rrp2->rdata)->digestlen);
		q += ((struct cds *)rrp2->rdata)->digestlen;
		
		r = canonsort[csort] = malloc(68000);
		if (r == NULL) {
			dolog(LOG_INFO, "c1 out of memory\n");
			return;
		}
		
		clen = (plength(q, tmpkey));
		pack16(r, clen);
		r += 2;
		pack(r, tmpkey, clen);

		csort++;
	}

	r = canonical_sort(canonsort, csort, &rlen);
	if (r == NULL) {
		dolog(LOG_INFO, "canonical_sort failed\n");
		return;
	}

	delphinusdns_SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);

}

void
zonemd_hash_ds(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
{
	char *tmpkey;
        char *q, *r;
        char **canonsort;
        struct rr *rrp2 = NULL;

        uint16_t clen;
        int csort = 0;
	int i, rlen;

	
        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	
	canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
	if (canonsort == NULL) {
		dolog(LOG_INFO, "canonsort out of memory\n");
		return;
	}

	csort = 0;

	TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
		q = tmpkey;
		pack(q, rbt->zone, rbt->zonelen);
		q += rbt->zonelen;
		pack16(q, htons(DNS_TYPE_DS));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(rrset->ttl));
		q += 4;
		pack16(q, htons(2 + 1 + 1 + ((struct ds *)rrp2->rdata)->digestlen));
		q += 2;
		pack16(q, htons(((struct ds *)rrp2->rdata)->key_tag));
		q += 2;
		pack8(q, ((struct ds *)rrp2->rdata)->algorithm);
		q++;
		pack8(q, ((struct ds *)rrp2->rdata)->digest_type);
		q++;
		pack(q, ((struct ds *)rrp2->rdata)->digest, ((struct ds *)rrp2->rdata)->digestlen);
		q += ((struct ds *)rrp2->rdata)->digestlen;
		
		r = canonsort[csort] = malloc(68000);
		if (r == NULL) {
			dolog(LOG_INFO, "c1 out of memory\n");
			return;
		}
		
		clen = (plength(q, tmpkey));
		pack16(r, clen);
		r += 2;
		pack(r, tmpkey, clen);

		csort++;
	}

	r = canonical_sort(canonsort, csort, &rlen);
	if (r == NULL) {
		dolog(LOG_INFO, "canonical_sort failed\n");
		return;
	}

	delphinusdns_SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);

}

void
zonemd_hash_dnskey(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
{
	char *tmpkey;
        char *q, *r;
        char **canonsort;
        struct rr *rrp2 = NULL;

        uint16_t clen;
        int csort = 0;
	int i, rlen;

	
        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	
	canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
	if (canonsort == NULL) {
		dolog(LOG_INFO, "canonsort out of memory\n");
		return;
	}

	csort = 0;

	TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
		q = tmpkey;
		pack(q, rbt->zone, rbt->zonelen);
		q += rbt->zonelen;
		pack16(q, htons(DNS_TYPE_DNSKEY));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(rrset->ttl));
		q += 4;
		pack16(q, htons(2 + 1 + 1 + ((struct dnskey *)rrp2->rdata)->publickey_len));
		q += 2;
		pack16(q, htons(((struct dnskey *)rrp2->rdata)->flags));
		q += 2;
		pack8(q, ((struct dnskey *)rrp2->rdata)->protocol);
		q++;
		pack8(q, ((struct dnskey *)rrp2->rdata)->algorithm);
		q++;
		pack(q, ((struct dnskey *)rrp2->rdata)->public_key, ((struct dnskey *)rrp2->rdata)->publickey_len);
		q += ((struct dnskey *)rrp2->rdata)->publickey_len;
		
		r = canonsort[csort] = malloc(68000);
		if (r == NULL) {
			dolog(LOG_INFO, "c1 out of memory\n");
			return;
		}
		
		clen = (plength(q, tmpkey));
		pack16(r, clen);
		r += 2;
		pack(r, tmpkey, clen);

		csort++;
	}

	r = canonical_sort(canonsort, csort, &rlen);
	if (r == NULL) {
		dolog(LOG_INFO, "canonical_sort failed\n");
		return;
	}

	delphinusdns_SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);

}

void
zonemd_hash_cdnskey(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
{
	char *tmpkey;
        char *q, *r;
        char **canonsort;
        struct rr *rrp2 = NULL;

        uint16_t clen;
        int csort = 0;
	int i, rlen;

	
        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	
	canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
	if (canonsort == NULL) {
		dolog(LOG_INFO, "canonsort out of memory\n");
		return;
	}

	csort = 0;

	TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
		q = tmpkey;
		pack(q, rbt->zone, rbt->zonelen);
		q += rbt->zonelen;
		pack16(q, htons(DNS_TYPE_CDNSKEY));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(rrset->ttl));
		q += 4;
		pack16(q, htons(2 + 1 + 1 + ((struct cdnskey *)rrp2->rdata)->publickey_len));
		q += 2;
		pack16(q, htons(((struct cdnskey *)rrp2->rdata)->flags));
		q += 2;
		pack8(q, ((struct cdnskey *)rrp2->rdata)->protocol);
		q++;
		pack8(q, ((struct cdnskey *)rrp2->rdata)->algorithm);
		q++;
		pack(q, ((struct cdnskey *)rrp2->rdata)->public_key, ((struct cdnskey *)rrp2->rdata)->publickey_len);
		q += ((struct cdnskey *)rrp2->rdata)->publickey_len;
		
		r = canonsort[csort] = malloc(68000);
		if (r == NULL) {
			dolog(LOG_INFO, "c1 out of memory\n");
			return;
		}
		
		clen = (plength(q, tmpkey));
		pack16(r, clen);
		r += 2;
		pack(r, tmpkey, clen);

		csort++;
	}

	r = canonical_sort(canonsort, csort, &rlen);
	if (r == NULL) {
		dolog(LOG_INFO, "canonical_sort failed\n");
		return;
	}

	delphinusdns_SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);

}

void
zonemd_hash_rrsig(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt, int skip_zonemd)
{
	char *tmpkey;
        char *q, *r;
        char **canonsort;
        struct rr *rrp2 = NULL;

        uint16_t clen;
        int csort = 0;
	int i, rlen;

	
        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	
	canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
	if (canonsort == NULL) {
		dolog(LOG_INFO, "canonsort out of memory\n");
		return;
	}

	csort = 0;

	TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
		if (skip_zonemd && 
			((struct rrsig *)rrp2->rdata)->type_covered == \
			DNS_TYPE_ZONEMD)
			continue;
	
		q = tmpkey;
		pack(q, rbt->zone, rbt->zonelen);
		q += rbt->zonelen;
		pack16(q, htons(DNS_TYPE_RRSIG));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(rrset->ttl));
		q += 4;
		pack16(q, htons(2 + 1 + 1 + 4 + 4 + 4 + 2 + ((struct rrsig *)rrp2->rdata)->signame_len) + ((struct rrsig *)rrp2->rdata)->signature_len);
		q += 2;
		pack16(q, htons(((struct rrsig *)rrp2->rdata)->type_covered));
		q += 2;
		pack8(q, ((struct rrsig *)rrp2->rdata)->algorithm);
		q++;
		pack8(q, ((struct rrsig *)rrp2->rdata)->labels);
		q++;
		pack32(q, htonl(((struct rrsig *)rrp2->rdata)->original_ttl));
		q += 4;
		pack32(q, htonl(((struct rrsig *)rrp2->rdata)->signature_expiration));
		q += 4;
		pack32(q, htonl(((struct rrsig *)rrp2->rdata)->signature_inception));
		q += 4;
		pack16(q, htons(((struct rrsig *)rrp2->rdata)->key_tag));
		q += 2;
		pack(q, ((struct rrsig *)rrp2->rdata)->signers_name, ((struct rrsig *)rrp2->rdata)->signame_len);
		q += ((struct rrsig *)rrp2->rdata)->signame_len;
		pack(q, ((struct rrsig *)rrp2->rdata)->signature, ((struct rrsig *)rrp2->rdata)->signature_len);
		q += ((struct rrsig *)rrp2->rdata)->signature_len;
		
		r = canonsort[csort] = malloc(68000);
		if (r == NULL) {
			dolog(LOG_INFO, "c1 out of memory\n");
			return;
		}
		
		clen = (plength(q, tmpkey));
		pack16(r, clen);
		r += 2;
		pack(r, tmpkey, clen);

		csort++;
	}

	r = canonical_sort(canonsort, csort, &rlen);
	if (r == NULL) {
		dolog(LOG_INFO, "canonical_sort failed\n");
		return;
	}

	delphinusdns_SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);

}

void
zonemd_hash_nsec3(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
{
	char *tmpkey;
        char *q, *r;
        char **canonsort;
        struct rr *rrp2 = NULL;

        uint16_t clen;
        int csort = 0;
	int i, rlen;

	
        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	
	canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
	if (canonsort == NULL) {
		dolog(LOG_INFO, "canonsort out of memory\n");
		return;
	}

	csort = 0;

	TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
		q = tmpkey;
		pack(q, rbt->zone, rbt->zonelen);
		q += rbt->zonelen;
		pack16(q, htons(DNS_TYPE_NSEC3));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(rrset->ttl));
		q += 4;
		pack16(q, htons(1 + 1 + 2 + 1 + 1 + ((struct nsec3 *)rrp2->rdata)->saltlen) + ((struct nsec3 *)rrp2->rdata)->nextlen + ((struct nsec3 *)rrp2->rdata)->bitmap_len);
		q += 2;
		pack8(q, ((struct nsec3 *)rrp2->rdata)->algorithm);
		q++;
		pack8(q, ((struct nsec3 *)rrp2->rdata)->flags);
		q++;
		pack16(q, htons(((struct nsec3 *)rrp2->rdata)->iterations));
		q += 2;
		pack8(q, ((struct nsec3 *)rrp2->rdata)->saltlen);
		q += 2;
		pack(q, ((struct nsec3 *)rrp2->rdata)->salt, ((struct nsec3 *)rrp2->rdata)->saltlen);
		q += ((struct nsec3 *)rrp2->rdata)->saltlen;
		pack8(q, ((struct nsec3 *)rrp2->rdata)->nextlen);
		q++;
		pack(q, ((struct nsec3 *)rrp2->rdata)->next, ((struct nsec3 *)rrp2->rdata)->nextlen);
		q += ((struct nsec3 *)rrp2->rdata)->nextlen;
		pack(q, ((struct nsec3 *)rrp2->rdata)->bitmap, ((struct nsec3 *)rrp2->rdata)->bitmap_len);
		q += ((struct nsec3 *)rrp2->rdata)->bitmap_len;
		
		r = canonsort[csort] = malloc(68000);
		if (r == NULL) {
			dolog(LOG_INFO, "c1 out of memory\n");
			return;
		}
		
		clen = (plength(q, tmpkey));
		pack16(r, clen);
		r += 2;
		pack(r, tmpkey, clen);

		csort++;
	}

	r = canonical_sort(canonsort, csort, &rlen);
	if (r == NULL) {
		dolog(LOG_INFO, "canonical_sort failed\n");
		return;
	}

	delphinusdns_SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);
}

void
zonemd_hash_nsec3param(DDD_SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
{
	char *tmpkey;
        char *q, *r;
        char **canonsort;
        struct rr *rrp2 = NULL;

        uint16_t clen;
        int csort = 0;
	int i, rlen;

	
        tmpkey = malloc(10 * 4096);
        if (tmpkey == NULL) {
                dolog(LOG_INFO, "tmpkey out of memory\n");
                return;
        }

	
	canonsort = (char **)calloc(MAX_RECORDS_IN_RRSET, sizeof(char *));
	if (canonsort == NULL) {
		dolog(LOG_INFO, "canonsort out of memory\n");
		return;
	}

	csort = 0;

	TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
		q = tmpkey;
		pack(q, rbt->zone, rbt->zonelen);
		q += rbt->zonelen;
		pack16(q, htons(DNS_TYPE_NSEC3PARAM));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(rrset->ttl));
		q += 4;
		pack16(q, htons(1 + 1 + 2 + 1 + ((struct nsec3 *)rrp2->rdata)->saltlen));
		q += 2;
		pack8(q, ((struct nsec3 *)rrp2->rdata)->algorithm);
		q++;
		pack8(q, ((struct nsec3 *)rrp2->rdata)->flags);
		q++;
		pack16(q, htons(((struct nsec3 *)rrp2->rdata)->iterations));
		q += 2;
		pack8(q, ((struct nsec3 *)rrp2->rdata)->saltlen);
		q += 2;
		pack(q, ((struct nsec3 *)rrp2->rdata)->salt, ((struct nsec3 *)rrp2->rdata)->saltlen);
		q += ((struct nsec3 *)rrp2->rdata)->saltlen;
		
		r = canonsort[csort] = malloc(68000);
		if (r == NULL) {
			dolog(LOG_INFO, "c1 out of memory\n");
			return;
		}
		
		clen = (plength(q, tmpkey));
		pack16(r, clen);
		r += 2;
		pack(r, tmpkey, clen);

		csort++;
	}

	r = canonical_sort(canonsort, csort, &rlen);
	if (r == NULL) {
		dolog(LOG_INFO, "canonical_sort failed\n");
		return;
	}

	delphinusdns_SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);
}


int
add_cookie(char *packet, int maxlen, int offset, DDD_BIGNUM *saved_cookie, u_char *cookieback, int cb_len)
{
	int i = 0, j = 0;
	uint16_t opt_codelen;
	char *cookie;
	char cookie_len;
	
	/* send a unique client cookie to server */
	if (saved_cookie == NULL) {

		if ((offset + 4 + 8) > maxlen)
			return -1;

		cookie_len = 8;
		cookie = malloc(cookie_len);
		if (cookie == NULL) {
			return -1;
		}
		arc4random_buf(cookie, cookie_len);

		opt_codelen = DNS_OPT_CODE_COOKIE;
		pack16(&packet[offset], htons(opt_codelen));
		offset += 2;
		
		opt_codelen = 8;
		pack16(&packet[offset], htons(opt_codelen));
		offset += 2;

		pack(&packet[offset], (char *)cookie, cookie_len);
		offset += cookie_len;
		

		for (i = 0; i < 8; i++) {
			snprintf(&cookieback[j], cb_len - j, "%02X", cookie[i] & 0xff);
			j += 2;
		}

		cookieback[j] = '\0';

		free(cookie);

		goto out;
	} else {
		cookie_len = delphinusdns_BN_num_bytes(saved_cookie);
		cookie = malloc(cookie_len);
		if (cookie == NULL) {
			return -1;
		}
	

		delphinusdns_BN_bn2bin(saved_cookie, cookie);

		if ((offset + 4 + cookie_len) > maxlen) {
			free(cookie);
			return -1;
		}

		opt_codelen = DNS_OPT_CODE_COOKIE;
		pack16(&packet[offset], htons(opt_codelen));
		offset += 2;
		
		opt_codelen = cookie_len;
		pack16(&packet[offset], htons(opt_codelen));
		offset += 2;

		pack(&packet[offset], (char *)cookie, cookie_len);
		offset += cookie_len;
		
		free(cookie);

		snprintf(cookieback, cb_len, "%s", delphinusdns_BN_bn2hex(saved_cookie));
	}

out:
	return (offset);
}

static int
param_cmp(const void *a, const void *b)
{
	char *ta = (char *)a;
	char *tb = (char *)b;
	uint16_t k1, k2;

	k1 = unpack16((char *)&ta[2]);
	k2 = unpack16((char *)&tb[2]);

	return (k1 < k2 ? -1 : k1 > k2);
}


int
param_human2tlv(char *input, char *output_sorted, int *len)
{
	char *p, *q, *o, *outp = NULL;
	char *output;
	char addrbuf[16];
	uint16_t keytype, qlen;
	uint16_t tmp16;
	int ilen = strlen(input);
	int i, j, numtokens = 0, last;
	int outcount = 0, outblock = 0;
	int maxlen = 0;
	int blocklen, sortlen = 0;

	TAILQ_HEAD(, tokenlist) tokenhead;
	SLIST_HEAD(, paramlist) paramhead;
	struct paramlist {
		SLIST_ENTRY(paramlist) entries;
		char *output;
		int len;
	} *n1, *n2, *np;

	struct tokenlist {
		TAILQ_ENTRY(tokenlist) tentries;
		char *token;
		int len;
	} *t1, *t2, *tp;
	

	SLIST_INIT(&paramhead);
	TAILQ_INIT(&tokenhead);

#if 0
	*len = strlen(input);
	memcpy(output, input, *len);
	return 0;
#endif

	output = (char *)calloc(1, 65535);
	if (output == NULL) {
		dolog(LOG_ERR, "%s calloc2: %s\n", __func__, strerror(errno));
		return -1;
	}

	for (p = input; (plength(p, input)) < ilen ; p = o) {
		q = strchr(p, '=');
		if (q == NULL) {
			dolog(LOG_INFO, "q == NULL\n");
			return -1;	
		}
		*q++ = '\0';

		o = strchr(q, ' ');
		if (o == NULL) {
			i = strlen(q);
			if (i == 0) {
				dolog(LOG_INFO, "i == 0\n");
				return -1;
			} else
				o = &q[i];
		} else
			*o++ = '\0';
		
		qlen = (uint16_t) strlen(q);

		if ((keytype = svcb_paramkey(p)) == 65535)
			return -1;

		/* if we're an alpn construct and contain a comma */
		if ((keytype == 1 || keytype == 2 || keytype > 6) && 
			strchr(q, ',') != NULL) {
			for (last = 0, j = 0; j < qlen; j++) {
				if (q[j] == ',' && j > 1 && 
					(q[j - 1] != '\\' ))  {

					t1 = calloc(1, sizeof(struct tokenlist));
					if (t1 == NULL) {
						dolog(LOG_ERR, "%s calloc %d: %s\n", __func__, 	
							__LINE__, strerror(errno));
						return -1;
					}

					t1->len = (j - last) + 1;
					if ((t1->token = calloc(1, t1->len)) == NULL) {
						dolog(LOG_ERR, "%s calloc %d: %s\n", __func__, 	
							__LINE__, strerror(errno));
						return -1;
					}
					strlcpy(t1->token, &q[last], t1->len);
					TAILQ_INSERT_TAIL(&tokenhead, t1, tentries);

					last = j + 1;
				} else if (q[j] == ',' && j > 2 && 
					(q[j - 1] == '\\' ))  {
					continue;  /* make it obvious */
				}
			}  /* for */

			t1 = calloc(1, sizeof(struct tokenlist));
			if (t1 == NULL) {
				dolog(LOG_ERR, "%s calloc %d: %s\n", __func__, 	
					__LINE__, strerror(errno));
				return -1;
			}

			t1->len = (j - last) + 1;
			if ((t1->token = calloc(1, t1->len)) == NULL) {
				dolog(LOG_ERR, "%s calloc %d: %s\n", __func__, 	
					__LINE__, strerror(errno));
				return -1;
			}
			strlcpy(t1->token, &q[last], t1->len);
			TAILQ_INSERT_TAIL(&tokenhead, t1, tentries);

			last = j + 1;
		} else if ((keytype == 0 || keytype == 3 || 
			keytype == 4 || keytype == 6) &&
			strchr(q, ',') != NULL) {

			/* if we're an ipv4hint or an ipv6hint */
			for (last = 0, j = 0; j < qlen; j++) {
				if (q[j] == ',') {
					t1 = calloc(1, sizeof(struct tokenlist));
					if (t1 == NULL) {
						dolog(LOG_ERR, "%s calloc %d: %s\n", __func__, 	
							__LINE__, strerror(errno));
						return -1;
					}

					t1->len = (j - last) + 1;
					if ((t1->token = calloc(1, t1->len)) == NULL) {
						dolog(LOG_ERR, "%s calloc %d: %s\n", __func__, 	
							__LINE__, strerror(errno));
						return -1;
					}
					strlcpy(t1->token, &q[last], t1->len);
					TAILQ_INSERT_TAIL(&tokenhead, t1, tentries);

					last = j + 1;
				} 
			}  /* for */

			t1 = calloc(1, sizeof(struct tokenlist));
			if (t1 == NULL) {
				dolog(LOG_ERR, "%s calloc %d: %s\n", __func__, 	
					__LINE__, strerror(errno));
				return -1;
			}

			t1->len = (j - last) + 1;
			if ((t1->token = calloc(1, t1->len)) == NULL) {
				dolog(LOG_ERR, "%s calloc %d: %s\n", __func__, 	
					__LINE__, strerror(errno));
				return -1;
			}
			strlcpy(t1->token, &q[last], t1->len);
			TAILQ_INSERT_TAIL(&tokenhead, t1, tentries);

			last = j + 1;
		} else {
			t1 = calloc(1, sizeof(struct tokenlist));
			if (t1 == NULL) {
				dolog(LOG_ERR, "%s calloc %d: %s\n", __func__, 	
					__LINE__, strerror(errno));
				return -1;
			}

			t1->len = qlen + 1;
			if ((t1->token = calloc(1, t1->len)) == NULL) {
				dolog(LOG_ERR, "%s calloc %d: %s\n", __func__, 	
					__LINE__, strerror(errno));
				return -1;
			}
			strlcpy(t1->token, q, t1->len);
			TAILQ_INSERT_TAIL(&tokenhead, t1, tentries);
		}

		/* reduce \\, \, and \210 */

		if ((keytype == 1 || keytype == 2 || keytype > 6)) {
			TAILQ_FOREACH(tp, &tokenhead, tentries) {
				char *a = tp->token;

				for (i = 0; i < tp->len; i++) {
					int decimal;

					if (a[i] == '\\') {
						if (a[i + 1] == '\\') {
							memmove(&a[i + 1], &a[i + 2], (tp->len - 1) - i);
							a[i] = 0x5c;
							i++;
							tp->len--;
						} else if (a[i + 1] == ',') {
							memmove(&a[i], &a[i + 1], (tp->len - 1) - i);		
							i++;
							tp->len--;
						} else {
							decimal = 0;
							decimal = (decimal * 10) + (a[i + 1] - '0');
							decimal = (decimal * 10) + (a[i + 2] - '0');
							decimal = (decimal * 10) + (a[i + 3] - '0');
							
							a[i] = decimal;
							
							memmove(&a[i + 1], &a[i + 4], (tp->len - 3) - i);
							tp->len -= 4;
							i += 4; /* XXX */
						}
					} /* if */
				} /* for */

			} /* TAILQ_FOREACH */
		} /* if keytype 1 and 2 and > 6 */

		/* count tokens */
		
		numtokens = 0;
		TAILQ_FOREACH(tp, &tokenhead, tentries) {
			numtokens++;
		}

		switch (keytype) {
		case 0:
			qlen = numtokens * 2;
			break;
		case 1:
			/* FALLTHROUGH */
		case 2:
			qlen = 0;
			TAILQ_FOREACH(tp, &tokenhead, tentries) {
				qlen += strlen(tp->token);
				qlen++;	/* alpn length */
			}
			break;
		case 3:
			qlen = numtokens * 2;
			break;
		case 4:		/* ipv4hint */
			qlen = numtokens * sizeof(in_addr_t);
			break;
		case 6:		/* ipv6hint */
			qlen = numtokens * sizeof(struct in6_addr);
			break;
		default:
			qlen = 0;
			TAILQ_FOREACH(tp, &tokenhead, tentries) {
				qlen += strlen(tp->token);
			}
			break;
		}

		outp = output;

		pack16(outp, qlen + 4);
		outp += 2;

		pack16(outp, htons(keytype));
		outp += 2;
		
		pack16(outp, htons(qlen));
		outp += 2;
		
		TAILQ_FOREACH(tp, &tokenhead, tentries) {
			uint8_t alen = 0;
			uint16_t mandatory;

			switch (keytype) {
			case 0:
				if ((mandatory = svcb_paramkey(tp->token)) == 65535)
					return -1;

				if ((mn = malloc(sizeof(struct mandatorynode))) == NULL) {
					dolog(LOG_ERR, "%s malloc %d: %s\n", __func__, __LINE__,
						strerror(errno));
					return -1;
				}

				mn->key = mandatory;
				
				RB_INSERT(mandatorytree, &mandatoryhead, mn);

				break;

			case 1:	/* alpn */
				alen = (uint8_t)strlen(tp->token);
				*outp = alen;
				outp += 1;

				pack(outp, tp->token, alen);
				outp += alen;
				break;
			case 2:	
				alen = (uint8_t)strlen(tp->token);
				*outp = alen;
				outp += 1;

		
				pack(outp, tp->token, alen);
				outp += alen;
				break;

			case 3:

				tmp16 = atoi(tp->token);
				pack16(outp, htons(tmp16));
				outp += 2;
				break;

			case 4:
				inet_pton(AF_INET, tp->token, &addrbuf);
				pack(outp, addrbuf, sizeof(in_addr_t));
				outp += sizeof(in_addr_t);
				break;

			case 6:
				inet_pton(AF_INET6, tp->token, &addrbuf);
				pack(outp, addrbuf, sizeof(struct in6_addr));
				outp += sizeof(struct in6_addr);
				break;

			default:

				pack(outp, tp->token, tp->len);
				outp += tp->len;
				break;
				
			}
		} /* TAILQ_FOREACH */

		if (keytype == 0) {
			RB_FOREACH_SAFE(mn, mandatorytree, &mandatoryhead, mn1) {
				pack16(outp, htons(mn->key));
				outp += 2;

				RB_REMOVE(mandatorytree, &mandatoryhead, mn);
			}
		}

		/* clean up the tokens */
		TAILQ_FOREACH_SAFE(tp, &tokenhead, tentries, t2) {
			TAILQ_REMOVE(&tokenhead, tp, tentries);
			free(tp->token);
			free(tp);
		}

		/* construct the to be sorted parameters */
		n1 = calloc(1, sizeof(struct paramlist));
		if (n1 == NULL) {
			dolog(LOG_ERR, "%s calloc %d: %s\n", __func__, __LINE__,
					strerror(errno));
			return -1;
		}

		n1->len = qlen + 6;
		n1->output = calloc(1, n1->len);
		if (n1->output == NULL) {
			dolog(LOG_ERR, "%s calloc %d: %s\n", __func__, __LINE__,
					strerror(errno));
			return -1;
		}
		memcpy(n1->output, output, n1->len);

		SLIST_INSERT_HEAD(&paramhead, n1, entries);
	} 

	/* we don't need output anymore, it will get reused */
	free(output);

	outcount = 0;
	SLIST_FOREACH(np, &paramhead, entries) {
		if (maxlen < np->len)
			maxlen = np->len;

		outcount++;
	}

	output = calloc(outcount, maxlen);
	if (output == NULL) {
		dolog(LOG_ERR, "%s calloc line %d: %s\n", __func__, __LINE__,
			strerror(errno));
		return -1;
	}
	
	SLIST_FOREACH_SAFE(np, &paramhead, entries, n2) {
		memcpy(&output[outblock], np->output, np->len);
		outblock += maxlen;
		
		SLIST_REMOVE(&paramhead, np, paramlist, entries);
		free(np->output);
		free(np);
	}

	/* quick sort the output list */
	qsort(output, outcount, maxlen, param_cmp);
		
	for (outblock = 0; outblock < (outcount * maxlen); outblock += maxlen) {
		blocklen = unpack16(&output[outblock]);
		memcpy(&output_sorted[sortlen], &output[outblock + 2], blocklen);
		sortlen += blocklen;

	}

	*len = sortlen;

#if 0
	printf("sorted list output\n");
	for (i = 0; i < *len; i++) {
		printf("%02X ", output_sorted[i] & 0xff);
	}
	printf("\n");
#endif

	return 0;
}

static char *
param_expand(char *input, int len, int bindfile)
{
	char *ret, *p;
	int i;
		
	ret = calloc(1, 65535);
	if (ret == NULL) {
		dolog(LOG_ERR, "%s calloc line %d: %s\n", __func__, __LINE__,
			strerror(errno));
		return NULL;
	}

	p = ret;

	for (i = 0; i < len; i++) {
		if (input[i] == ' ') {
			*p = '\\'; p++;
			if (! bindfile) { *p = '\\'; p++; }
			*p = '0'; p++;
			*p = '3'; p++;
			*p = '2'; p++;
		} else if (input[i] == 0x5c) {
			*p = '\\'; p++;
			*p = '\\'; p++;
			if (! bindfile) {
				*p = '\\'; p++;
				*p = '\\'; p++;
			}
		} else if (input[i] == ',') {
			*p = '\\'; p++;
			if (! bindfile) {
				*p = '\\'; p++;
			}
			*p = ','; p++;
		} else if (input[i] < 0x20 || input[i] > 0x7f) {
			*p = '\\'; p++;
			if (! bindfile) { *p = '\\'; p++; }
			snprintf(p, (65535 - (plength(p, ret))), "%03u", input[i] & 0xff);
			p += 3;
		} else {
			*p = input[i];
			p++;
		}
	}

	*p = '\0';

	return (ret);
}

char *
param_tlv2human(char *input, int len, int bindfile)
{
	char buf[64];
	char *ret, *b;
	int i, outlen = 0;
	uint16_t key, klen, mkey, port;
	uint8_t alpn;
	const int inet6size = 16;
	const int inetsize = 4;
	int pass = 0;
	int comma, save;

#if 0
	return (input);
#endif
	
	do {
		/* first pass */
		for (i = 0; i < len;) {
			key = unpack16(&input[i]);
			i += 2;
			klen = unpack16(&input[i]);
			i += 2;

			NTOHS(klen);

			switch (ntohs(key)) {
			case 0:
				if (pass) {
					strlcat(ret, "mandatory=", outlen);
				} else
					outlen += strlen("mandatory=");

				for (int j = 0; j < klen; j += 2) {
					mkey = unpack16(&input[i+j]);
					switch (ntohs(mkey)) {
					case 0:
						if (pass) {
							strlcat(ret, "mandatory", outlen);
						} else {
							outlen += strlen("mandatory");
						}
						break;
					case 1:
						if (pass) {
							strlcat(ret, "alpn", outlen);
						} else {
							outlen += strlen("alpn");		
						}
						break;
					case 2:
						if (pass) {
							strlcat(ret, "no-default-alpn", outlen);
						} else {
							outlen += strlen("no-default-alpn");
						}
						break;
					case 3:
						if (pass) {
							strlcat(ret, "port", outlen);
						} else {
							outlen += strlen("port");
						}
						break;
					case 4:
						if (pass) {
							strlcat(ret, "ipv4hint", outlen);
						} else {
							outlen += strlen("ipv4hint");
						}
						break;
					case 5:
						if (pass) {
							strlcat(ret, "ech", outlen);
						} else {
							outlen += strlen("ech");
						}
						break;
					case 6:
						if (pass) {
							strlcat(ret, "ipv6hint", outlen);
						} else {
							outlen += strlen("ipv6hint");
						}
						break;
					default:
						snprintf(buf, sizeof(buf), "key%u", ntohs(mkey));
						if (pass) {
							strlcat(ret, buf, outlen);
						} else {
							outlen += strlen(buf);
						}
						break;
					} /* switch */

					if (j + 2 < klen) {
						if (pass) {
							strlcat(ret, ",", outlen);
						} else {
							outlen++; /* comma seperator */
						}
					}
				} /* for */
				i += klen;
				break;
			case 1:
				if (pass) {
					strlcat(ret, "alpn=", outlen);
				} else {
					outlen += strlen("alpn=");
				}
				save = i;
				for (int j = 0; j < klen; j++) {
					alpn = (uint8_t)input[i];
					j += alpn + 1;
					if (pass) {
						b = param_expand(&input[i + 1], alpn, bindfile);
						if (b == NULL)
							return NULL;
						strlcat(ret, b, outlen);
						free(b);
					} else {
						b = param_expand(&input[i + 1], alpn, bindfile);
						if (b == NULL)
							return NULL;
						outlen += strlen(b);
						free(b);
					}

					if (j < (klen - 1)) {
						if (pass) {
							strlcat(ret, ",", outlen);
						} else {
							outlen++; /* comma seperator */
						}
					}

					i += alpn + 1;
				} /* for */
				i = save + klen;
				break;	
			case 2:

				if (pass) {
					strlcat(ret, "no-default-alpn=", outlen);
				} else {
					outlen += strlen(" no-default-alpn=");
				}
				save = i;
				for (int j = 0; j < klen; j++) {
					alpn = (uint8_t)input[i];
					j += alpn + 1;
					if (pass) {
						b = param_expand(&input[i + 1], alpn, bindfile);
						if (b == NULL)
							return NULL;
						strlcat(ret, b, outlen);
						free(b);
					} else {
						b = param_expand(&input[i + 1], alpn, bindfile);
						if (b == NULL)
							return NULL;
						outlen += strlen(b);
						free(b);
					}

					if (j < (klen - 1)) {
						if (pass) {
							strlcat(ret, ",", outlen);
						} else {
							outlen++; /* comma seperator */
						}	
					}
					i += alpn + 1;
				} /* for */
				i = save + klen;
				break;	
			case 3:
				if (pass) {
					strlcat(ret, "port=", outlen);
				} else {
					outlen += strlen("port=");
				}
				for (int x = 0; x < klen; x += 2) {
					port = unpack16(&input[i + x]);
					NTOHS(port);

					snprintf(buf, sizeof(buf), "%u", port);
					if (pass) {
						strlcat(ret, buf, outlen);
					} else {
						outlen += atoi(buf);
					}
		
					if (x + 2 < klen) {
						if (pass) {
							strlcat(ret, ",", outlen);
						} else {
							outlen++;	
						}
					}
				}
				i += klen;
				break;
			case 4:

				if (pass) {
					strlcat(ret, "ipv4hint=", outlen);
				} else {
					outlen += strlen("ipv4hint=");
				}
				comma = (klen / 4);
				if ((klen) >= inetsize) {
					int tlen = 0;

					comma--;
					for (int x = 0; x < klen; x += 4, comma--) {
						inet_ntop(AF_INET, &input[i + x], buf, sizeof(buf));	
						tlen = strlen(buf);
	
						if (pass) {
							strlcat(ret, buf, outlen);	

							if (comma) {
								strlcat(ret, ",", outlen);
							}
						} else {
							outlen += tlen;
							if (comma) {
								outlen++;
							}
						}
					}
				}
				i += klen;
				break;
			case 5:
				if (pass) {
					strlcat(ret, "ech=", outlen);
				} else {
					outlen += strlen("ech=");
				}

				break;
			case 6:
				if (pass) {
					strlcat(ret, "ipv6hint=", outlen);
				} else {
					outlen += strlen("ipv6hint=");
				}
				comma = (klen / 16);
				if ((klen) >= inet6size) {
					int tlen = 0;

					comma--;
					for (int x = 0; x < (klen); x += 16, comma--) {
						inet_ntop(AF_INET6, &input[i + x], buf, sizeof(buf));	
						tlen = strlen(buf);
	
						if (pass) {
							strlcat(ret, buf, outlen);	

							if (comma) {
								strlcat(ret, ",", outlen);
							}
						} else {
							outlen += tlen;
							if (comma) {
								outlen++;
							}
						}
					}
				}
				i += klen;
				break;
			default:
				snprintf(buf, sizeof(buf), "key%u=", ntohs(key));
				if (pass) {
					strlcat(ret, buf, outlen);
					b = param_expand(&input[i], klen, bindfile);
					if (b == NULL)
						return NULL;
					strlcat(ret, b, outlen);
					free(b);
				} else {
					outlen += strlen(buf);
					b = param_expand(&input[i], klen, bindfile);
					if (b == NULL)
						return NULL;
					outlen += strlen(b);
					free(b);
				}

				i += klen;

				break;	
			}

			if (pass) {
				strlcat(ret, " ", outlen);
			} else {
				outlen++;
			}

		} /* for */

		if (pass == 0) {
			ret = calloc(1, outlen + 1);
			if (ret == NULL)
				return (NULL);
		} else
			break;

		i = 0;
	} while (pass++ < 1);

	return (ret);
}

static uint16_t
svcb_paramkey(char *input)
{
	uint16_t ret = 65535;

	if (strcasecmp(input, "mandatory") == 0) {
		ret = 0;
	} else if (strcasecmp(input, "alpn") == 0) {
		ret = 1;
	} else if (strcasecmp(input, "no-default-alpn") == 0) {
		ret = 2;
	} else if (strcasecmp(input, "port") == 0) {
		ret = 3;
	} else if (strcasecmp(input, "ipv4hint") == 0) {
		ret = 4;
	} else if (strcasecmp(input, "ech") == 0) {
		ret = 5;
	} else if (strcasecmp(input, "ipv6hint") == 0) {
		ret = 6;
	} else if (strncasecmp(input, "key", 3) == 0) {
		char *p;

		p = input; p += 3;
		ret = atoi(p);
	} else
		ret = 65535;

	return (ret);
}

char *
ipseckey_type(struct ipseckey *ipseckey)
{
	static char ret[DNS_MAXNAME + 1];
	char *convertname;

	switch (ipseckey->gwtype) {
	case 0:
		ret[0] = '.'; ret[1] = '\0';
		break;
	case 1:
		inet_ntop(AF_INET, &ipseckey->gateway.ip4, ret, sizeof(ret));
		break;
	case 2:
		inet_ntop(AF_INET6, &ipseckey->gateway.ip6, ret, sizeof(ret));
		break;
	case 3:
		convertname = convert_name((char *)&ipseckey->gateway.dnsname,
					ipseckey->dnsnamelen);
		strlcpy(ret, convertname, sizeof(ret));
		break;
	}

	return (ret);
}

/*
 * INPUT_SANITIZE - syslogd does this sanitization, but in debug mode we want
 *			this sanitizer at least.
 */

char *
input_sanitize(char *fmt)
{
	char *buf;
	int len;

	len = strlen(fmt);
	if (len == 0)
		len = 1;
	len *= 5;

	buf = malloc(len);
	if (buf == NULL)
		return NULL;

	strnvis(buf, fmt, len, VIS_SAFE | VIS_OCTAL);
	buf[len - 1] = '\0';

	return (buf);
}

void
safe_fprintf(FILE *f, char *fmt, ...)
{
	char *buf, *sanitize;
	va_list ap;

	if (f == stdout) {
		buf = calloc(1, 65536);
		if (buf == NULL) {
			printf("calloc: %s\n", strerror(errno));
			return;
		}

		va_start(ap, fmt);
		vsnprintf(buf, 65536, fmt, ap);
		va_end(ap);

		sanitize = input_sanitize(buf);	
		if (sanitize == NULL) {
			printf("input_sanitize: %s\n", strerror(errno));
			free(buf);
			return;
		}
		
		printf("%s", sanitize);
		free(sanitize);
		free(buf);

		return;
	}

	va_start(ap, fmt);
	vfprintf(f, fmt, ap);
	va_end(ap);
}

/*
 * PLENMAX - nth is the nth element of an array starting at zeroth, only allow
 *		max size, if it's above that log the error...
 */

size_t
plenmax(void *nth, void *zeroth, size_t max)
{
	size_t len = (nth - zeroth);

	if (len > max) {
		dolog(LOG_ERR, "IMPORTANT: nth(%p) - zeroth(%p) is bigger than max (%u), did you switch their order accidentally?\n", nth, zeroth, max);
		abort();
	}

	return (len);
}	

size_t
plength(void *nth, void *zeroth)
{
	return (plenmax(nth, zeroth, 65536));	/* a sizeable DNS max? */
}


/*
 * NOWRAP_DEC - I proposed this for tcpdump in OpenBSD because of underwraps
 *		never go below 0 which wraps around on unsigned integers...
 */

u_int
nowrap_dec(u_int val, u_int dec)
{
	u_int ret = val;

	ret -= dec;
	if (ret > val)
		return 0;
	else 
		return (ret);
}

ddDB *
ddd_read_manna(ddDB *db, struct imsgbuf *ibuf, struct cfg *cfg)
{
	struct imsg imsg;
	struct iwantmanna iw;
	size_t n;

	/* grab the fd from imsg (so) */
	if (((n = imsg_read(ibuf)) == -1 && errno != EAGAIN) || n == 0) {
		dolog(LOG_INFO, "got error from TCP accept child, it likely died, exit\n");
		ddd_shutdown();
		exit(1);
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1) {
			break;
		}
		if (n == 0) {
			break;
		}

		switch(imsg.hdr.type) {
		case IMSG_IHAVEMANNA_MESSAGE:
#if DEBUG
			dolog(LOG_INFO, "asking for the zonefile \"%s\" via cortex\n", imsg.data);
#endif
			strlcpy(iw.zone, imsg.data, sizeof(iw.zone));
			iw.pid = getpid();

			imsg_compose(ibuf, IMSG_IWANTMANNA_MESSAGE,
				0, 0, -1, &iw, sizeof(iw));

			msgbuf_write(&ibuf->w);
			break;
	
		case IMSG_HEREISMANNA_MESSAGE:
			/* XXX no length checks? */
			memcpy(&iw, imsg.data, sizeof(iw));
			iwqueue_add(&iw, imsg.fd);
			imsg_free(&imsg);

			if (iwqueue_count() >= 64) {
				dolog(LOG_INFO, "over 64 zone updates in the queue, rebuilding database now\n");

				return (rebuild_db(cfg));
			}
				

			return NULL;

			break;
		default:
			dolog(LOG_INFO, "unknown imsg hdr type %d received, but we wanted MANNA!\n", imsg.hdr.type);
			break;
		}

		imsg_free(&imsg);
	}

	return (NULL);
}

void
iwqueue_add(struct iwantmanna *iw, int fd)
{
	int zonenamelen;
	char *zonename;

	zonename = dns_label(iw->zone, &zonenamelen);
	if (zonename == NULL) {
		close(fd);
		dolog(LOG_INFO, "dns_label in zonefile failed\n");
		return;
	}
		
	iwq = (struct iwqueue *)calloc(1, sizeof(struct iwqueue));
	if (iwq == NULL) {
		free(zonename);
		close(fd);
		dolog(LOG_INFO, "iwqueue: %s\n", strerror(errno));
		return;
	}

	iwq->fd = fd;
	memcpy(&iwq->zonename, zonename, zonenamelen);
	iwq->zonenamelen = zonenamelen;
	strlcpy(iwq->humanname, iw->zone, sizeof(iwq->humanname));
	iwq->time = time(NULL);
		
	TAILQ_INSERT_TAIL(&iwqhead, iwq, entries);

	free(zonename);
}

ddDB *
rebuild_db(struct cfg *cfg)
{
	ddDB *newdb = NULL;

	/* move to another function */
	newdb = dddbopen();
	if (newdb == NULL) {
		return NULL;
	}

	TAILQ_FOREACH_SAFE(iwq, &iwqhead, entries, iwq1) {

		delete_zone(iwq->zonename, iwq->zonenamelen);

		if (parse_file(newdb, NULL, PARSEFILE_FLAG_ZONEFD, iwq->fd) < 0) {
			dolog(LOG_INFO, "parsing the new zonefile \"%s\" failed\n", iwq->humanname);
			/* clean it up a little */

			close(iwq->fd);
			TAILQ_REMOVE(&iwqhead, iwq, entries);
			free(iwq);
			iwq = NULL;
			continue;
		}

		repopulate_zone(newdb, iwq->zonename, iwq->zonenamelen);
		close(iwq->fd);
	}

	(void)merge_db(cfg->db, newdb);

	TAILQ_FOREACH_SAFE(iwq, &iwqhead, entries, iwq1) {
		TAILQ_REMOVE(&iwqhead, iwq, entries);
		free(iwq);
	}

	return (newdb);
}

int
iwqueue_count(void)
{
	int count = 0;

	TAILQ_FOREACH(iwq0, &iwqhead, entries) {
		count++;
	}	

	return (count);
}

/*
 * ADVANCE_LABEL - advance a label in a DNSNAME, return NULL on error
 */

char *
advance_label(char *name, int *len)
{
	if (name == NULL)
		return NULL;

	if (*name == '\0')
		return (name);

	*len -= (*name + 1);

	if (*len < 0)
		return NULL;

	name = (name + (*name + 1));

	return (name);
}

/*
 * Copyright (c) 1988, 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)in_cksum.c	8.1 (Berkeley) 6/10/93
 */

/*
 * UDP_CKSUM - compute the ones complement sum of the ones complement of 16 bit 
 * 			  numbers
 */



/* 
 * UDP_CKSUM - compute the checksum with a pseudo header of the UDP packet
 * 				
 */

uint16_t
udp_cksum(uint16_t *addr, uint16_t len, struct ip *ip, struct udphdr *uh) 
{
	union {
		struct ph {
			in_addr_t src;
			in_addr_t dst;
			uint8_t pad;
			uint8_t proto;
			uint16_t len;
		} s __attribute__((packed));

		uint16_t i[6];
	} ph;

	int nleft = len - sizeof(struct udphdr); /* we pass the udp header */
	int sum = 0;
	uint16_t *w = &ph.i[0];
	uint16_t *u = (uint16_t *)uh;
	uint16_t answer;

	memset(&ph, 0, sizeof(ph));
	memcpy(&ph.s.src, &ip->ip_src.s_addr, sizeof(in_addr_t));
	memcpy(&ph.s.dst, &ip->ip_dst.s_addr, sizeof(in_addr_t));
	ph.s.pad = 0;
	ph.s.proto = ip->ip_p;
	ph.s.len = uh->uh_ulen;
	sum = w[0] + w[1] + w[2] + w[3] + w[4] + w[5] + u[0] + u[1] + u[2];
	w = addr;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
	if (nleft == 1) {
		sum += htons(*(u_char *)w << 8);
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

/* 
 * UDP_CKSUM6 - compute the checksum with a pseudo header of the UDP6 packet
 * 			RFC 8200 section 8.1	
 */

uint16_t
udp_cksum6(uint16_t *addr, uint16_t len, struct ip6_hdr *ip6, struct udphdr *uh) 
{
	union {
		struct ph {
			struct in6_addr src;
			struct in6_addr dst;
			uint32_t len;
			uint8_t pad[3];
			uint8_t nxt;
		} s __attribute__((packed));

		uint16_t i[20];
	} ph;

	int nleft = len - sizeof(struct udphdr); /* we pass the udp header */
	int sum;
	uint16_t *w = &ph.i[0];
	uint16_t *u = (uint16_t *)uh;
	uint16_t answer;

	memset(&ph, 0, sizeof(ph));
	memcpy(&ph.s.src, &ip6->ip6_src, sizeof(struct in6_addr));
	memcpy(&ph.s.dst, &ip6->ip6_dst, sizeof(struct in6_addr));
	ph.s.len = htonl(len);
	ph.s.nxt = ip6->ip6_nxt;

	sum = w[0] + w[1] + w[2] + w[3] + w[4] + w[5] + \
		w[6] + w[7] + w[8] + w[9] + w[10] + \
		w[11] + w[12] + w[13] + w[14] + w[15] + \
		w[16] + w[17] + w[18] + w[19] + u[0] + u[1] + u[2];

	w = addr;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
	if (nleft == 1) {
		sum += htons(*(u_char *)w << 8);
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

