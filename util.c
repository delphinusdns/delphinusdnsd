/*
 * Copyright (c) 2002-2021 Peter J. Philipp <pjp@delphinusdns.org>
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

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "ddd-dns.h"
#include "ddd-db.h" 
#include "ddd-config.h"

/* prototypes */

void 	pack(char *, char *, int);
void 	pack32(char *, u_int32_t);
void 	pack16(char *, u_int16_t);
void 	pack8(char *, u_int8_t);
uint32_t unpack32(char *);
uint16_t unpack16(char *);
void 	unpack(char *, char *, int);
int lower_dnsname(char *, int); 
int randomize_dnsname(char *, int);

int label_count(char *);
char * dns_label(char *, int *);
void ddd_shutdown(void);
int get_record_size(ddDB *, char *, int);
struct rbtree * 	get_soa(ddDB *, struct question *);
struct rbtree *		get_ns(ddDB *, struct rbtree *, int *);
struct rbtree * 	lookup_zone(ddDB *, struct question *, int *, int *, char *, int);
struct rbtree *		Lookup_zone(ddDB *, char *, u_int16_t, u_int16_t, int);
u_int16_t check_qtype(struct rbtree *, u_int16_t, int, int *);
struct question		*build_fake_question(char *, int, u_int16_t, char *, int);

char 			*get_dns_type(int, int);
int 			memcasecmp(u_char *, u_char *, int);
int 			compress_label(u_char *, u_int16_t, int);
struct question		*build_question(char *, int, int, char *);
int			free_question(struct question *);
struct rrtab 	*rrlookup(char *);
char * expand_compression(u_char *, u_char *, u_char *, u_char *, int *, int);
void log_diff(char *sha256, char *mac, int len);
int tsig_pseudoheader(char *, uint16_t, time_t, HMAC_CTX *);
char * 	bin2hex(char *, int);
u_int64_t timethuman(time_t);
char * 	bitmap2human(char *, int);
int lookup_axfr(FILE *, int, char *, struct soa *, u_int32_t, char *, char *, int *, int *, int *, struct soa_constraints *, uint32_t, int);
int dn_contains(char *name, int len, char *anchorname, int alen);
uint16_t udp_cksum(u_int16_t *, uint16_t, struct ip *, struct udphdr *);
uint16_t udp_cksum6(u_int16_t *, uint16_t, struct ip6_hdr *, struct udphdr *);

void zonemd_hash_a(SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_aaaa(SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_soa(SHA512_CTX *, struct rrset *, struct rbtree *, uint32_t *);
void zonemd_hash_ns(SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_cname(SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_ptr(SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_txt(SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_rp(SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_hinfo(SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_srv(SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_naptr(SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_caa(SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_mx(SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_tlsa(SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_sshfp(SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_ds(SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_dnskey(SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_rrsig(SHA512_CTX *, struct rrset *, struct rbtree *, int);
void zonemd_hash_nsec3(SHA512_CTX *, struct rrset *, struct rbtree *);
void zonemd_hash_nsec3param(SHA512_CTX *, struct rrset *, struct rbtree *);
struct zonemd * zonemd_hash_zonemd(struct rrset *, struct rbtree *);

char *canonical_sort(char **, int, int *);
static int cs_cmp(const void *, const void *);

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
extern struct rrset * find_rr(struct rbtree *rbt, u_int16_t rrtype);
extern int add_rr(struct rbtree *rbt, char *name, int len, u_int16_t rrtype, void *rdata);
extern int display_rr(struct rrset *rrset);
extern int 	check_ent(char *, int);
extern int     find_tsig_key(char *, int, char *, int);
extern int      mybase64_decode(char const *, u_char *, size_t);

extern int raxfr_a(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_tlsa(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_srv(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_naptr(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_aaaa(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_cname(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_zonemd(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_ns(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_ptr(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_mx(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_txt(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_dnskey(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_rrsig(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_nsec3param(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_nsec3(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_ds(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_rp(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_caa(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_hinfo(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern int raxfr_sshfp(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *);
extern u_int16_t raxfr_skip(FILE *, u_char *, u_char *);
extern int raxfr_soa(FILE *, u_char *, u_char *, u_char *, struct soa *, int, u_int32_t, u_int16_t, HMAC_CTX *, struct soa_constraints *);
extern int raxfr_peek(FILE *, u_char *, u_char *, u_char *, int *, int, u_int16_t *, u_int32_t, HMAC_CTX *, char *, int, int);
extern int raxfr_tsig(FILE *, u_char *, u_char *, u_char *, struct soa *, u_int16_t, HMAC_CTX *, char *, int);
extern char *convert_name(char *, int);


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
	{ NULL, 0}
};

static struct rrtab myrrtab[] =  { 
 { "a",         DNS_TYPE_A, 		DNS_TYPE_A } ,
 { "aaaa",      DNS_TYPE_AAAA,		DNS_TYPE_AAAA },
 { "caa",	DNS_TYPE_CAA,		DNS_TYPE_CAA },
 { "cname",     DNS_TYPE_CNAME, 	DNS_TYPE_CNAME },
 { "delegate",  DNS_TYPE_NS, 		DNS_TYPE_NS },
 { "dnskey", 	DNS_TYPE_DNSKEY, 	DNS_TYPE_DNSKEY },
 { "ds", 	DNS_TYPE_DS, 		DNS_TYPE_DS },
 { "hinfo",	DNS_TYPE_HINFO,		DNS_TYPE_HINFO },
 { "hint",      DNS_TYPE_HINT,		DNS_TYPE_NS }, 
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
	{ 0, 0, NULL }
};

/*
 * LABEL_COUNT - count the labels and return that number
 */

int 
label_count(char *name)
{
	int lc = 0;
	char *p;
	
	if (name == NULL) 
		return -1;

	p = name;
	while (*p != '\0') {
		lc++;
		p += (*p + 1);
	}

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
		strlcpy(p, labels[i], newlen - (p - dnslabel) + 1);
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
	if ((rbt = find_rrset(db, p, plen)) == NULL ||
		((ntohs(question->hdr->qtype) != DNS_TYPE_DS) && 
			(rbt->flags & RBT_GLUE)) ||
		((rbt->flags & RBT_DNSSEC) && (rrset = find_rr(rbt, DNS_TYPE_NSEC3)) != NULL)) {
		if (rbt == NULL) {
			splen = plen;
			sp = p;

			while ((rbt0 = find_rrset(db, sp, splen)) == NULL) {
				if (*sp == 0 && splen == 1)
					break;
				splen -= (*sp + 1);
				sp += (*sp + 1);
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
					plen -= (*p + 1);
					p += (*p + 1);
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
			plen -= (*p + 1);
			p = (p + (*p + 1));

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

			plen -= (*p + 1);
			p = (p + (*p + 1));
			continue;
		}
		
		rrset = find_rr(rbt, DNS_TYPE_SOA);
		if (rrset != NULL) {
			/* we'll take this one */
			return (rbt);	
		} else {
			plen -= (*p + 1);
			p = (p + (*p + 1));
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
			p += (*p + 1);
			len -= (*p + 1);
	
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
Lookup_zone(ddDB *db, char *name, u_int16_t namelen, u_int16_t type, int wildcard)
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

u_int16_t
check_qtype(struct rbtree *rbt, u_int16_t type, int nxdomain, int *error)
{
	u_int16_t returnval = -1;

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
		}

		if (nxdomain)
			*error = -2;
		else
			*error = -1;

		return 0;

	case DNS_TYPE_TLSA:
		if (find_rr(rbt, DNS_TYPE_TLSA) != NULL) {
			returnval = DNS_TYPE_TLSA;
			break;
		}

		*error = -1;
		return 0;

	case DNS_TYPE_CAA:
		if (find_rr(rbt, DNS_TYPE_CAA) != NULL) {
			returnval = DNS_TYPE_CAA;
			break;
		}

		*error = -1;
		return 0;

	case DNS_TYPE_RP:
		if (find_rr(rbt, DNS_TYPE_RP) != NULL) {
			returnval = DNS_TYPE_RP;
			break;
		}

		*error = -1;
		return 0;

	case DNS_TYPE_HINFO:
		if (find_rr(rbt, DNS_TYPE_HINFO) != NULL) {
			returnval = DNS_TYPE_HINFO;
			break;
		}

		*error = -1;
		return 0;

	case DNS_TYPE_SSHFP:
		if (find_rr(rbt, DNS_TYPE_SSHFP) != NULL) {
			returnval = DNS_TYPE_SSHFP;
			break;
		}

		*error = -1;
		return 0;

	case DNS_TYPE_SRV:	
		if (find_rr(rbt, DNS_TYPE_SRV) != NULL) {
			returnval = DNS_TYPE_SRV;
			break;
		}

		*error = -1;
		return 0;

	case DNS_TYPE_NAPTR:
		if (find_rr(rbt, DNS_TYPE_NAPTR) != NULL) {
				returnval = DNS_TYPE_NAPTR;
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
		}

		*error = -1;
		return 0;
	case DNS_TYPE_TXT:
		if (find_rr(rbt, DNS_TYPE_TXT) != NULL) {
			returnval = DNS_TYPE_TXT;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_RRSIG:
		if (find_rr(rbt, DNS_TYPE_RRSIG) != NULL) {
			returnval = DNS_TYPE_RRSIG;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_NSEC3PARAM:
		if (find_rr(rbt, DNS_TYPE_NSEC3PARAM) != NULL) {
			returnval = DNS_TYPE_NSEC3PARAM;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_NSEC3:
		if (find_rr(rbt, DNS_TYPE_NSEC3) != NULL) {
			returnval = DNS_TYPE_NSEC3;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_NSEC:
		if (find_rr(rbt, DNS_TYPE_NSEC) != NULL) {
			returnval = DNS_TYPE_NSEC;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_DS:
		if (find_rr(rbt, DNS_TYPE_DS) != NULL) {
			returnval = DNS_TYPE_DS;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_DNSKEY:
		if (find_rr(rbt, DNS_TYPE_DNSKEY) != NULL) {
			returnval = DNS_TYPE_DNSKEY;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_ZONEMD:
		if (find_rr(rbt, DNS_TYPE_ZONEMD) != NULL) {
			returnval = DNS_TYPE_ZONEMD;
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
build_fake_question(char *name, int namelen, u_int16_t type, char *tsigkey, int tsigkeylen)
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
build_question(char *buf, int len, int additional, char *mac)
{
	char pseudo_packet[4096];		/* for tsig */
	u_int rollback, i;
	u_int16_t qtype, qclass;
	u_int32_t ttl;
	u_int64_t timefudge;
	int elen = 0;

	char *end_name = NULL;
	char *pb = NULL;
	char *o;
	char expand[DNS_MAXNAME + 1];

	struct dns_tsigrr *tsigrr = NULL;
	struct dns_optrr *opt = NULL;
	struct question *q = NULL;
	struct dns_header *hdr = (struct dns_header *)buf;

	/* find the end of name */
	elen = 0;
	memset(&expand, 0, sizeof(expand));
	end_name = expand_compression((u_char *)&buf[sizeof(struct dns_header)], (u_char *)buf, (u_char *)&buf[len], (u_char *)&expand, &elen, sizeof(expand));
	if (end_name == NULL) {
		dolog(LOG_ERR, "expand_compression() failed, bad formatted question name\n");
		return NULL;
	}

	if ((end_name - buf) < elen) {
		dolog(LOG_ERR, "compression in question #1\n");
		return NULL;
	}

	i = (end_name - &buf[0]);

	
	/* check if there is space for qtype and qclass */
	if (len < ((end_name - &buf[0]) + (2 * sizeof(u_int16_t)))) {
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
	q->hdr->namelen = (end_name - &buf[sizeof(struct dns_header)]);
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

	i += (2 * sizeof(u_int16_t)); 	/* type,class*/

	/* in IXFR an additional SOA entry is tacked on, we want to skip this */
	do {
		u_int16_t val16;

		rollback = i;

		elen = 0;
		memset(&expand, 0, sizeof(expand));
		pb = expand_compression((u_char *)&buf[i], (u_char *)buf, (u_char *)&buf[len], (u_char *)&expand, &elen, sizeof(expand));
		if (pb == NULL) {
			i = rollback;
			break;
		}
		i = (pb - buf);

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
		additional--;
	} while (0);
	/* check for TSIG rr */
	do {
		u_int16_t val16, tsigerror, tsigotherlen;
		u_int16_t fudge;
		u_int32_t val32;
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
		i = (pb - buf);
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
		i = (pb - buf);
		pseudolen4 = i;

		memcpy(q->tsig.tsigalg, expand, elen);
		q->tsig.tsigalglen = elen;
			
		/* now check for MAC type, since it's given once again */
		if (elen == 11) {
			if (expand[0] != 9 ||
				memcasecmp(&expand[1], "hmac-sha1", 9) != 0) {
				break;
			}
		} else if (elen == 13) {
			if (expand[0] != 11 ||
				memcasecmp(&expand[1], "hmac-sha256", 11) != 0) {
				break;
			}
		} else if (elen == 26) {
			if (expand[0] != 8 ||
				memcasecmp(&expand[1], "hmac-md5", 8) != 0) {
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
		fudge = (u_int16_t)(timefudge & 0xffff);
		tsigtime = (u_int64_t)(timefudge >> 16);

		q->tsig.tsig_timefudge = tsigrr->timefudge;
		
		i += (8 + 2);		/* timefudge + macsize */

		if (ntohs(tsigrr->macsize) != DNS_HMAC_SHA256_SIZE) {
			q->tsig.tsigerrorcode = DNS_BADSIG; 
			break; 
		}

		i += ntohs(tsigrr->macsize);
	

		/* now get the MAC from packet with length rollback */
		NTOHS(hdr->additional);
		hdr->additional--;
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

		HMAC(EVP_sha256(), tsigkey, tsignamelen, (unsigned char *)pseudo_packet, 
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
		free(q);
		return NULL;
	}

	/* parse type and class from the question */

	o = (end_name);
	qtype = unpack16(o);
	o = (end_name + sizeof(uint16_t));
	qclass = unpack16(o);

	memcpy((char *)&q->hdr->qtype, (char *)&qtype, sizeof(u_int16_t));
	memcpy((char *)&q->hdr->qclass, (char *)&qclass, sizeof(u_int16_t));

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
	u_int16_t offset;

	/* expand name */
	while ((u_char)*p && p <= end) {
		/* test for compression */
		if ((*p & 0xc0) == 0xc0) {
			/* do not allow recursive compress pointers */
			if (! save) {
				save = p + 2;
			}
			offset = unpack16(p);
			/* offsets into the dns header are a nono */
			if ((ntohs(offset) & (~0xc000)) < sizeof(struct dns_header))
				return NULL;

			/* do not allow forwards jumping */
			if ((p - estart) <= (ntohs(offset) & (~0xc000))) {
				return NULL;
			}

			p = (estart + (ntohs(offset) & (~0xc000)));
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
tsig_pseudoheader(char *tsigkeyname, uint16_t fudge, time_t now, HMAC_CTX *ctx)
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

	HMAC_Update(ctx, pseudo_packet, ppoffset);

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

u_int64_t
timethuman(time_t timet)
{
	char timebuf[512];
	struct tm *tm;
	u_int64_t retbuf;

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
	u_int16_t bit;
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
lookup_axfr(FILE *f, int so, char *zonename, struct soa *mysoa, u_int32_t format, char *tsigkey, char *tsigpass, int *segment, int *answers, int *additionalcount, struct soa_constraints *constraints, uint32_t bytelimit, int ob)
{
	char query[512];
	char pseudo_packet[512];
	char shabuf[DNS_HMAC_SHA256_SIZE];
	char *reply;
	struct timeval tv, savetv;
	struct question *q;
	struct whole_header {
		u_int16_t len;
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
	u_int16_t rdlen, *plen;
	u_int16_t tcplen;
	
	HMAC_CTX *ctx;
	time_t now = 0;
	socklen_t sizetv;
	int sacount = 0;
	
	if (!(format & TCP_FORMAT))
		return -1;

	memset(&query, 0, sizeof(query));
	
	wh = (struct whole_header *)&query[0];
	
	wh->dh.id = htons(arc4random() & 0xffff);
	wh->dh.query = 0;
	wh->dh.question = htons(1);
	wh->dh.answer = 0;
	wh->dh.nsrr = 0;
	wh->dh.additional = htons(0);


	SET_DNS_QUERY(&wh->dh);
	SET_DNS_RECURSION(&wh->dh);
	HTONS(wh->dh.query);

	totallen = sizeof(struct whole_header);

	name = dns_label(zonename, &len);
	if (name == NULL) {
		return -1;
	}

	zonelen = len;
	
	p = (char *)&wh[1];	
	
	memcpy(p, name, len);
	totallen += len;
	p += len;

	pack16(p, htons(DNS_TYPE_AXFR));
	totallen += sizeof(u_int16_t);
	p += sizeof(u_int16_t);
	
	pack16(p, htons(DNS_CLASS_IN));
	totallen += sizeof(u_int16_t);
	p += sizeof(u_int16_t);

	/* we have a key, attach a TSIG payload */
	if (tsigkey) {

		if ((len = mybase64_decode(tsigpass, (u_char *)&pseudo_packet, sizeof(pseudo_packet))) < 0) {
			fprintf(stderr, "bad base64 password\n");
			return -1;
		}
		
		ctx = HMAC_CTX_new();
		HMAC_Init_ex(ctx, pseudo_packet, len, EVP_sha256(), NULL);
		HMAC_Update(ctx, &query[2], totallen - 2);

		now = time(NULL);
		if (tsig_pseudoheader(tsigkey, DEFAULT_TSIG_FUDGE, now, ctx) < 0) {
			fprintf(stderr, "tsig_pseudoheader failed\n");
			return -1;
		}

		HMAC_Final(ctx, shabuf, &len);

		if (len != DNS_HMAC_SHA256_SIZE) {
			fprintf(stderr, "not expected len != 32\n");
			return -1;
		}

		HMAC_CTX_free(ctx);

		keyname = dns_label(tsigkey, &len);
		if (keyname == NULL) {
			return -1;
		}

		memcpy(&query[totallen], keyname, len);
		totallen += len;
		
		p = &query[totallen];
		pack16(p, htons(DNS_TYPE_TSIG));
		totallen += 2;
		p += 2;

		pack16(p, htons(DNS_CLASS_ANY));
		totallen += 2;
		p += 2;

		pack32(p, htonl(0));
		totallen += 4;
		p += 4;

		keyname = dns_label("hmac-sha256", &len);
		if (keyname == NULL) {
			return -1;
		}

		/* rdlen */
		pack16(p, htons(len + 2 + 4 + 2 + 2 + DNS_HMAC_SHA256_SIZE + 2 + 2 + 2));
		totallen += 2;
		p += 2;

		/* algorithm name */
		memcpy(&query[totallen], keyname, len);
		totallen += len;
		p += len;

		/* time 1 */
		if (sizeof(time_t) == 4)		/* 32-bit time-t */
			pack16(p, 0);
		else
			pack16(p, htons((now >> 32) & 0xffff)); 
		totallen += 2;
		p += 2;

		/* time 2 */
		pack32(p, htonl(now & 0xffffffff));
		totallen += 4;
		p += 4;

		/* fudge */
		pack16(p, htons(DEFAULT_TSIG_FUDGE));
		totallen += 2;
		p += 2;
	
		/* hmac size */
		pack16(p, htons(sizeof(shabuf)));
		totallen += 2;
		p += 2;

		/* hmac */
		memcpy(&query[totallen], shabuf, sizeof(shabuf));
		totallen += sizeof(shabuf);
		p += sizeof(shabuf);

		/* original id */
		pack16(p, wh->dh.id);
		totallen += 2;
		p += 2;

		/* error */
		pack16(p, 0);
		totallen += 2;
		p += 2;
		
		/* other len */
		pack16(p, 0);
		totallen += 2;
		p += 2;

		wh->dh.additional = htons(1);
	}
	

	wh->len = htons(totallen - 2);

	if (send(so, query, totallen, 0) < 0) {
		perror("send");
		return -1;
	}

	/* catch reply, totallen is reused here */
	totallen = 0;

	reply = calloc(1, 0xffff + 2);
	if (reply == NULL) {
		perror("calloc");
		return -1;
	}

	if (tsigkey) {
		uint16_t maclen;
	
		if ((len = mybase64_decode(tsigpass, (u_char *)&pseudo_packet, sizeof(pseudo_packet))) < 0) {
			fprintf(stderr, "bad base64 password\n");
			return -1;
		}
		
		ctx = HMAC_CTX_new();
		HMAC_Init_ex(ctx, pseudo_packet, len, EVP_sha256(), NULL);
		maclen = htons(DNS_HMAC_SHA256_SIZE);
		HMAC_Update(ctx, (char *)&maclen, sizeof(maclen));
		HMAC_Update(ctx, shabuf, sizeof(shabuf));
	} else
		ctx = NULL;

	q = build_question((char *)&wh->dh, wh->len, wh->dh.additional, (tsigkey == NULL) ? NULL : shabuf);
	if (q == NULL) {
		fprintf(stderr, "failed to build_question\n");
		return -1;
	}

	for (;;) {
		sizetv = sizeof(struct timeval);
		if (getsockopt(so, SOL_SOCKET, SO_RCVTIMEO, &savetv, &sizetv) < 0) {	
			perror("getsockopt");
		}

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		if (setsockopt(so, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
			dolog(LOG_DEBUG, "setsockopt failed with sec 1, usec 0: %s\n", strerror(errno));
		}

		len = recv(so, reply, 2, MSG_PEEK | MSG_WAITALL);
		if (len <= 0)	
			break;

		plen = (u_int16_t *)reply;
		tcplen = ntohs(*plen) + 2;
		
		/* restore original timeout values */
		if (setsockopt(so, SOL_SOCKET, SO_RCVTIMEO, &savetv, sizeof(savetv)) < 0) {
			perror("setsockopt");
		}

		len = recv(so, reply, tcplen, MSG_WAITALL);
		if (len < 0) {
			perror("recv");
			return -1;
		}

		totallen += len;

		if (totallen >= bytelimit) {
			fprintf(stderr, "download exceeded byte limit\n");
			return -1;
		}

		rwh = (struct whole_header *)&reply[0];
		bytes_received += ntohs(rwh->len);

		end = &reply[len];
		len = rwh->len;

		if (rwh->dh.id != wh->dh.id) {
			fprintf(stderr, "DNS ID mismatch\n");
			return -1;
		}

		if (!(htons(rwh->dh.query) & DNS_REPLY)) {
			fprintf(stderr, "NOT a DNS reply\n");
			return -1;
		}
		
		if (ntohs(rwh->dh.answer) < 1) {	
			fprintf(stderr, "NO ANSWER provided\n");
			return -1;
		}

		segmentcount = ntohs(rwh->dh.answer);
		if (tsigkey) {
			segmentcount += ntohs(rwh->dh.additional);
			*additionalcount += ntohs(rwh->dh.additional);
#if 0
			printf("additional = %d\n", ntohs(rwh->dh.additional));
			// rwh->dh.additional = 0;
#endif
		} 
		*answers += segmentcount;

			
		if (memcmp(q->hdr->name, name, q->hdr->namelen) != 0) {
			fprintf(stderr, "question name not for what we asked\n");
			return -1;
		}

		if (q->hdr->qclass != htons(DNS_CLASS_IN) || q->hdr->qtype != htons(DNS_TYPE_AXFR)) {
			fprintf(stderr, "wrong class or type\n");
			return -1;
		}
		
		p = (char *)&rwh[1];		

		if (have_question) {
			p += q->hdr->namelen;
			p += sizeof(u_int16_t);	 	/* type */
			p += sizeof(u_int16_t);		/* class */
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
				rwh->dh.additional--;
			HTONS(rwh->dh.additional);
			HMAC_Update(ctx, estart, (p - estart));
			rwh->dh.additional = saveadd;
		}

		(*segment)++;

		for (count = 0; count < segmentcount; count++) {
			char mac[DNS_HMAC_SHA256_SIZE];

			if ((rrlen = raxfr_peek(f, p, estart, end, &rrtype, soacount, &rdlen, format, ctx, name, zonelen, 1)) < 0) {
				fprintf(stderr, "raxfr_peek() ERROR\n");
				return -1;
			}

			if (tsigkey && (rrtype == DNS_TYPE_TSIG)) {
				uint16_t maclen;

				/* do tsig checks here */
				if ((len = raxfr_tsig(f,p,estart,end,mysoa,rdlen,ctx, (char *)&mac, (sacount++ == 0) ? 1 : 0)) < 0) {
					fprintf(stderr, "error with TSIG record\n");
					return -1;
				}
		
				p = (estart + len);

				if ((len = mybase64_decode(tsigpass, (u_char *)&pseudo_packet, sizeof(pseudo_packet))) < 0) {
					fprintf(stderr, "bad base64 password\n");
					return -1;
				}

			 	if (HMAC_CTX_reset(ctx) != 1) {
					fprintf(stderr, "HMAC_CTX_reset failed!\n");
					return -1;
				}
				if (HMAC_Init_ex(ctx, pseudo_packet, len, EVP_sha256(), NULL) != 1) {
					fprintf(stderr, "HMAC_Init_ex failed!\n");
					return -1;
				}
				maclen = htons(DNS_HMAC_SHA256_SIZE);
				HMAC_Update(ctx, (char *)&maclen, sizeof(maclen));
				HMAC_Update(ctx, mac, sizeof(mac));

				if (soacount > 1)
					goto out;

				/*
				 * oldbehaviour did not account for another 
				 * header 
				 */

				if (! ob) {
					len = recv(so, reply, 2, MSG_PEEK | MSG_WAITALL);
					if (len <= 0) {
						fprintf(stderr, "mangled AXFR\n");
						return -1;
					}

					tcplen = ntohs(unpack16(reply));

					if (tcplen < sizeof(struct whole_header)) {
						fprintf(stderr, "parsing header after TSIG failed, boundary problem\n");
						return -1;
					}
						
					len = recv(so, reply, sizeof(struct whole_header), MSG_PEEK | MSG_WAITALL);
					if (len < 0) {
						perror("recv");
						return -1;
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
					fprintf(stderr, "raxfr_soa failed\n");
					return -1;
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
							fprintf(stderr, "error with rrtype %d\n", sr->rrtype);
							return -1;
						}
						p = (estart + len);
						break;
					}
				}

				if (sr->rrtype == 0) {
					if (rrtype != DNS_TYPE_TSIG) {
						fprintf(stderr, "unsupported RRTYPE %d\n", rrtype);
						return -1;
					} 
				} 
			}
		}
	}

	if ((len = recv(so, reply, 0xffff, 0)) > 0) {	
		fprintf(stderr, ";; WARN: received %d more bytes.\n", len);
	}

out:

	if (tsigkey) {
		HMAC_CTX_free(ctx);	
	}

#if 0
	if (f != NULL) {
		if ((format & ZONE_FORMAT))
			fprintf(f, "}\n");
	}
#endif

	free_question(q);

	return 0;

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
			memcasecmp(p, anchorname, alen) == 0) {
			return 1;
		}

		plen -= (*p + 1);
		p += (*p + 1);
	}

	return 0;
}

/* pack functions */

void
pack32(char *buf, u_int32_t value)
{
	pack(buf, (char *)&value, sizeof(uint32_t));
}	

void
pack16(char *buf, u_int16_t value)
{
	pack(buf, (char *)&value, sizeof(uint16_t));
}

void
pack8(char *buf, u_int8_t value)
{
	u_int8_t *p;

	p = (u_int8_t *)buf;
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

	memcpy(save, buf, len);

	q = &buf[0];
	for (p = q, offset = 0; offset <= len && *p != 0; offset += (*p + 1), p += (*p + 1)) {
		labellen = *p;
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
compress_label(u_char *buf, u_int16_t offset, int labellen)
{
	u_char *label[10000];
	u_char *end = &buf[offset];
	struct question {
		u_int16_t type;
		u_int16_t class;
	} __attribute__((packed));
	struct answer {
		u_int16_t type;
		u_int16_t class;
		u_int32_t ttl;
		u_int16_t rdlength;	 
	} __attribute__((packed));
	struct soa {
         	u_int32_t serial;
                u_int32_t refresh;
                u_int32_t retry;
                u_int32_t expire;
                u_int32_t minttl;
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

	if (((char *)end_name - (char *)buf) < elen) {
		dolog(LOG_ERR, "compression in question compress_label #1\n");
		return(0);
	}

	p = end_name;

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
		case DNS_TYPE_AAAA:
			p += 16;		/* sizeof 4 * 32 bit */
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
			p += (2 * sizeof(u_int16_t)); /* priority, weight */
			/* the port will be assumed in the fall through for
			   mx_priority..
			*/
			/* FALLTHROUGH */
		case DNS_TYPE_MX:
			p += sizeof(u_int16_t);	 /* mx_priority */
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
			p += (2 * sizeof(u_int16_t)); /* order and preference */
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
		case DNS_TYPE_NSEC3:
		case DNS_TYPE_NSEC3PARAM:
		case DNS_TYPE_RRSIG:
		case DNS_TYPE_CAA:
		case DNS_TYPE_HINFO:
		case DNS_TYPE_ZONEMD:
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

	for (;*p != 0;) {
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

		checklen -= *p;
		p += *p;
		checklen--;
		p++;
	}

	return (0);	 	/* no compression possible */

out:
	/* take off our compress length */
	offset -= checklen;
	/* write compressed label */
	pack16(&buf[offset], htons((compressmark - &buf[0]) | 0xc000));

	offset += sizeof(u_int16_t);	

	return (offset);
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
udp_cksum(u_int16_t *addr, uint16_t len, struct ip *ip, struct udphdr *uh) 
{
	union {
		struct ph {
			in_addr_t src;
			in_addr_t dst;
			u_int8_t pad;
			u_int8_t proto;
			u_int16_t len;
		} s __attribute__((packed));

		u_int16_t i[6];
	} ph;

	int nleft = len - sizeof(struct udphdr); /* we pass the udp header */
	int sum = 0;
	u_int16_t *w = &ph.i[0];
	u_int16_t *u = (u_int16_t *)uh;
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
udp_cksum6(u_int16_t *addr, uint16_t len, struct ip6_hdr *ip6, struct udphdr *uh) 
{
	union {
		struct ph {
			struct in6_addr src;
			struct in6_addr dst;
			u_int32_t len;
			u_int8_t pad[3];
			u_int8_t nxt;
		} s __attribute__((packed));

		u_int16_t i[20];
	} ph;

	int nleft = len - sizeof(struct udphdr); /* we pass the udp header */
	int sum;
	u_int16_t *w = &ph.i[0];
	u_int16_t *u = (u_int16_t *)uh;
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


void
zonemd_hash_a(SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
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

		clen = (q - tmpkey);
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

	SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);

	free(tmpkey);
}

void
zonemd_hash_aaaa(SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
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

		clen = (q - tmpkey);
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

	SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);
}

void
zonemd_hash_soa(SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt, uint32_t *serial)
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
	p += sizeof(u_int32_t);

	*serial = ((struct soa *)rrp->rdata)->serial;

	pack32(p, htonl(((struct soa *)rrp->rdata)->refresh));
	p += sizeof(u_int32_t);
	pack32(p, htonl(((struct soa *)rrp->rdata)->retry));
	p += sizeof(u_int32_t);

	pack32(p, htonl(((struct soa *)rrp->rdata)->expire));
	p += sizeof(u_int32_t);
	pack32(p, htonl(((struct soa *)rrp->rdata)->minttl));
	p += sizeof(u_int32_t);

	keylen = (p - tmpkey);

	SHA384_Update(ctx, tmpkey, keylen);

	free(tmpkey);
}
void
zonemd_hash_ns(SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
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

		clen = (q - tmpkey);
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

	SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);

}
void
zonemd_hash_cname(SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
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

	keylen = (p - tmpkey);     

	SHA384_Update(ctx, tmpkey, keylen);

	free(tmpkey);
}


void
zonemd_hash_ptr(SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
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
	
	keylen = (p - tmpkey);     

	SHA384_Update(ctx, tmpkey, keylen);

	free(tmpkey);

}
void
zonemd_hash_txt(SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
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
		clen = (q - tmpkey);
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

	SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);


}
void
zonemd_hash_rp(SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
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

		clen = (q - tmpkey);
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

	SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);


}


void
zonemd_hash_hinfo(SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
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
		
		clen = (q - tmpkey);
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

	SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);

	

}
void
zonemd_hash_srv(SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
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

		clen = (q - tmpkey);
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

	SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);
	

}


void
zonemd_hash_naptr(SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
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
		
		clen = (q - tmpkey);
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

	SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);
}


void
zonemd_hash_caa(SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
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

		clen = (q - tmpkey);
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

	SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);

}
void
zonemd_hash_mx(SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
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

		clen = (q - tmpkey);
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

	SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);
}


void
zonemd_hash_tlsa(SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
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
		
		clen = (q - tmpkey);
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

	SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);
}


void
zonemd_hash_sshfp(SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
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
		
		clen = (q - tmpkey);
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

	SHA384_Update(ctx, r, rlen);

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
zonemd_hash_ds(SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
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
		
		clen = (q - tmpkey);
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

	SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);

}

void
zonemd_hash_dnskey(SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
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
		
		clen = (q - tmpkey);
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

	SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);

}

void
zonemd_hash_rrsig(SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt, int skip_zonemd)
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
		
		clen = (q - tmpkey);
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

	SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);

}

void
zonemd_hash_nsec3(SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
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
		
		clen = (q - tmpkey);
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

	SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);
}

void
zonemd_hash_nsec3param(SHA512_CTX *ctx, struct rrset *rrset, struct rbtree *rbt)
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
		
		clen = (q - tmpkey);
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

	SHA384_Update(ctx, r, rlen);

	free (r);
	for (i = 0; i < csort; i++) {
		free(canonsort[i]);
	}

	free(canonsort);
	free(tmpkey);
}
