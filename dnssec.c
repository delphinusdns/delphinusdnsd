/*
 * Copyright (c) 2015-2024 Peter J. Philipp <pbug44@delphinusdns.org>
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
#include <sys/select.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>

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
#else /* not linux */
#include <sys/queue.h>
#include <sys/tree.h>
#ifdef __FreeBSD__
#include "imsg.h"
#else
#include <imsg.h>
#endif /* __FreeBSD__ */
#endif /* __linux__ */

#include "ddd-dns.h"
#include "ddd-db.h"
#include "ddd-crypto.h"


/* prototypes */

void init_dnssec(void);
int insert_apex(char *zonename, char *zone, int zonelen);
int insert_nsec3(char *zonename, char *domainname, char *dname, int dnamelen);
struct rbtree * nsec_match_closest(char *, int, struct rbtree *, ddDB *);
struct rbtree * nsec_match_closest_encloser(char *, int, struct rbtree *, ddDB *);
char * nsec3_next_closer(char *zonename, int zonelen, char *hashname);
char * nsec3_match(char *zonename, int zonelen, char *hashname);
struct rbtree * nsec3_match_qname(char *name, int namelen, struct rbtree *, ddDB *db);
struct rbtree * nsec3_match_closest(char *name, int namelen, struct rbtree *, ddDB *db);
struct rbtree * nsec3_wildcard_closest(char *name, int namelen, struct rbtree *, ddDB *db);
char * convert_name(char *name, int namelen);
int nsec_comp(const void *a, const void *b);
int nsec3_comp(const void *a, const void *b);
int count_dots(char *name);
char * next_closer_name(char *, int, char *, int, int *);
char * hash_name(char *name, int len, struct nsec3param *n3p);
char * base32hex_encode(u_char *input, int len);
int 	base32hex_decode(u_char *, u_char *);
void 	mysetbit(u_char *, int);
int finalize_nsec3(void);
struct rbtree * nsec3_closest_encloser(char *, int, struct rbtree *, ddDB *);
struct rbtree * nsec3_closest_encloser_wild(char *, int, struct rbtree *, ddDB *);
struct rbtree * nsec3_match_qname_wild(char *, int, struct rbtree *, ddDB *);
struct rbtree * closest_valid_name(char *, int, struct rbtree *, ddDB *);

/* externs */

extern int              get_record_size(ddDB *, char *, int);
extern char *           dns_label(char *, int *);
extern void             dolog(int, char *, ...);
extern int              checklabel(ddDB *, struct rbtree *, struct rbtree *, struct question *);
extern int              free_question(struct question *);
extern int		check_ent(char *, int);
extern int 		memcasecmp(u_char *, u_char *, int);

extern struct rbtree * 	find_rrset(ddDB *db, char *name, int len);
extern struct rbtree * 	find_rrsetwild(ddDB *db, char *name, int len);
extern struct rrset * 	find_rr(struct rbtree *rbt, uint16_t rrtype);
extern int 		add_rr(struct rbtree *rbt, char *name, int len, uint16_t rrtype, void *rdata);
extern size_t 		plength(void *, void *);
extern char *		advance_label(char *, int *);
extern struct zoneentry *      zone_findzone(struct rbtree *);

extern int debug;

SLIST_HEAD(listhead, dnssecentry) dnssechead;

struct nsec3entry {
	char domainname[DNS_MAXNAME + 1];
	char dname[DNS_MAXNAME];
	int dnamelen;
	TAILQ_ENTRY(nsec3entry) nsec3_entries;	
        RB_ENTRY(nsec3entry) nsec3_entry;
} *n3, *ns3p;


struct dnssecentry {
	char zonename[DNS_MAXNAME + 1];
	char zone[DNS_MAXNAME];
	int zonelen;
	SLIST_ENTRY(dnssecentry) dnssec_entry;
	TAILQ_HEAD(aa, nsec3entry) nsec3head;
	RB_HEAD(nsec3tree, nsec3entry) tree;
} *dn, *dnp;

int nsec3cmp(struct nsec3entry *, struct nsec3entry *);

RB_PROTOTYPE(nsec3tree, nsec3entry, nsec3_entry, nsec3cmp);
RB_GENERATE(nsec3tree, nsec3entry, nsec3_entry, nsec3cmp);


void
init_dnssec(void)
{
	SLIST_INIT(&dnssechead);
	return;
}

int
insert_apex(char *zonename, char *zone, int zonelen)
{
	dn = calloc(1, sizeof(struct dnssecentry));
	if (dn == NULL) {
		return -1;
	}

	strlcpy(dn->zonename, zonename, DNS_MAXNAME + 1);

	if (zonelen > DNS_MAXNAME) {
		free (dn);
		return -1;
	}

	memcpy(dn->zone, zone, zonelen);
	dn->zonelen = zonelen;

	TAILQ_INIT(&dn->nsec3head);
	RB_INIT(&dn->tree);

	SLIST_INSERT_HEAD(&dnssechead, dn, dnssec_entry);

	return (0);
}

int
insert_nsec3(char *zonename, char *domainname, char *dname, int dnamelen)
{

	SLIST_FOREACH(dnp, &dnssechead, dnssec_entry) {
		if (strcasecmp(dnp->zonename, zonename) == 0)
			break;
	}

	if (dnp == NULL)
		return -1;

	n3 = calloc(1, sizeof(struct nsec3entry));
	if (n3 == NULL)
		return -1;

	strlcpy(n3->domainname, domainname, DNS_MAXNAME + 1);
	
	if (dnamelen > DNS_MAXNAME) {
		free (n3);
		return -1;
	}

	memcpy(n3->dname, dname, dnamelen);	
	n3->dnamelen = dnamelen;

	RB_INSERT(nsec3tree, &dnp->tree, n3);
	
	return (0);
}




int
finalize_nsec3(void)
{
	/* this should sort the tree to a tailq'ed list */
	SLIST_FOREACH(dnp, &dnssechead, dnssec_entry) {
		RB_FOREACH(n3, nsec3tree, &dnp->tree) {
			TAILQ_INSERT_TAIL(&dnp->nsec3head, n3, nsec3_entries);
		}

		TAILQ_FOREACH(n3, &dnp->nsec3head, nsec3_entries) {
			if (debug)
				dolog(LOG_INFO, "%s ---> %s\n", dnp->zonename, n3->domainname);
		}
	}

	return (0);
}

int
nsec3cmp(struct nsec3entry *a, struct nsec3entry *b)
{
	return (strcmp((void *)a->domainname, (void *)b->domainname));
}

char * 
nsec3_next_closer(char *zonename, int zonelen, char *hashname)
{
	int hashlen;

	hashlen = strlen(hashname);

	SLIST_FOREACH(dnp, &dnssechead, dnssec_entry) {
		if (zonelen == dnp->zonelen && 
			(memcmp(dnp->zone, zonename, zonelen) == 0))
			break;
	}

	if (dnp == NULL)
		return NULL;

	/* we have found the zone, now find the next closer hash for nsec3 */
	TAILQ_FOREACH(n3, &dnp->nsec3head, nsec3_entries) {
		if (strncasecmp(hashname, n3->domainname, hashlen) <= 0) {
			break;
		} 
	}
	
	if (n3 == NULL) {
		/* returning NULL is not recommended here */
		ns3p = TAILQ_LAST(&dnp->nsec3head, aa);
		return (ns3p->domainname);
	}

#if DEBUG
	dolog(LOG_INFO, "resolved at %s\n", n3->domainname);
#endif

	if ((ns3p = TAILQ_PREV(n3, aa, nsec3_entries)) != NULL) {
		return (ns3p->domainname);
	} else {
		ns3p = TAILQ_LAST(&dnp->nsec3head, aa);
		return (ns3p->domainname);
	}

	/* NOTREACHED */
	return (NULL);
}

char * 
nsec3_match(char *zonename, int zonelen, char *hashname)
{
	int hashlen;

	hashlen = strlen(hashname);

	SLIST_FOREACH(dnp, &dnssechead, dnssec_entry) {
		if (zonelen == dnp->zonelen && 
			(memcmp(dnp->zone, zonename, zonelen) == 0))
			break;
	}

	if (dnp == NULL)
		return NULL;

	/* we have found the zone, now find the next closer hash for nsec3 */
	TAILQ_FOREACH(n3, &dnp->nsec3head, nsec3_entries) {
		if (strncasecmp(hashname, n3->domainname, hashlen) == 0) {
			break;
		} 
	}
	
	if (n3 == NULL) {
		return NULL;
	}

#ifdef DEBUG
	dolog(LOG_INFO, "resolved at %s\n", n3->domainname);
#endif

	return (n3->domainname);
}

/*
 * NSEC_MATCH_CLOSEST_ENCLOSER - find the closest encloser RR to 
 *					prove non-wildcard
 */

struct rbtree *
nsec_match_closest_encloser(char *name, int namelen, struct rbtree *rbt, ddDB *db)
{
	struct rbtree *rbt0, *rbt1;
	struct rrset *rp = NULL;
	struct rr *rrp = NULL;
	struct nsec *nsec;
	char *hn1, *adv_name;
	int adv_namelen;
	
	rbt0 = closest_valid_name(name, namelen, rbt, db);
	if (rbt0 == NULL)
		return NULL;

	adv_name = next_closer_name(name, namelen, rbt0->zone, rbt0->zonelen, &adv_namelen);
	if (adv_name == NULL)
		return NULL;

	hn1 = convert_name(adv_name, adv_namelen);
	if (hn1 == NULL)
		return NULL;


	/*
	 *  enumerate the NSEC chain in order to find the next closest 
	 *  encloser 
	 */

	for (rbt1 = rbt; rbt1 != NULL; rbt1 = rbt0) {
		rp = find_rr(rbt1, DNS_TYPE_NSEC);
		if (rp == NULL)
			goto out;

		if ((rrp = TAILQ_FIRST(&rp->rr_head)) == NULL)
			goto out;

		nsec = (struct nsec *)rrp->rdata;
		if (nsec == NULL)
			goto out;

		rbt0 = find_rrset(db, nsec->next, nsec->next_len);
		if (rbt0 == NULL)
			goto out;

#if 0
        	dots1 = count_dots(rbt1->humanname);
		dots2 = count_dots(rbt0->humanname);

		if ((dots1 < dots0 && strcmp(rbt1->humanname, hn1) < 0) &&
			(dots0 <= dots2 && 
			strcmp(hn1, rbt0->humanname) <= 0)) {
#endif



		if (strcmp(rbt1->humanname, hn1) < 0 &&
			strcmp(hn1, rbt0->humanname) <= 0) {
			free(hn1);
			return (rbt1);
		}

		/* we are where we started, apparently it can't be found */
		if (rbt0 == rbt)
			break;
	}

out:
	free(hn1);
	return NULL;
}

/*
 * NSEC_MATCH_CLOSEST - find the closest RR to prove non-wildcard
 *
 */

struct rbtree *
nsec_match_closest(char *name, int namelen, struct rbtree *rbt, ddDB *db)
{
	struct rbtree *rbt0;

	rbt0 = closest_valid_name(name, namelen, rbt, db);
	return (rbt0);
}

char *
convert_name(char *name, int namelen)
{
	char *ret;
	char *p, *p0;
	int plen;
	int i;

	if (namelen <= 0)
		return NULL;

	ret = calloc(namelen + 1, 1);
	if (ret == NULL) {
		return NULL;
	}

	/* short circuit root */
	if (namelen == 1 && name[0] == '\0') {
		ret[0] = '.';
		return (ret);
	}

	/* XXX why is the below here? */
	//memcpy(ret, name + 1, namelen - 1);
	
	p0 = ret;
	p = name;
	plen = namelen;

        while (plen >= 0 && *p != 0) {
		if (*p > DNS_MAXLABEL) {
			dolog(LOG_INFO, "compression in dns name\n");
			free (ret);
			return NULL;
		}
		for (i = 0; i < *p; i++) {
			*p0++ = p[i + 1];
		}
		*p0++ = '.';

		p = advance_label(p, &plen);
		if (p == NULL)
			return NULL;
	}

	return (ret);
}

/* canonical sort compare */

int
nsec_comp(const void *a, const void *b)
{
	struct domainnames {
		char name[DNS_MAXNAME + 1];
		char next[DNS_MAXNAME + 1];
	};
	struct domainnames *dn0, *dn1;
	int dots0, dots1;

	dn0 = (struct domainnames *)a;
	dn1 = (struct domainnames *)b;

	/* count the dots we need this for canonical compare */

	dots0 = count_dots(dn0->name);
	dots1 = count_dots(dn1->name);

	if (dots0 > dots1)
		return 1;
	else if (dots1 > dots0)
		return -1;
	
			
	/* we have a tie, strcmp them */

	return (strcmp(dn0->name, dn1->name));
}

/* much like nsec_comp */

int
nsec3_comp(const void *a, const void *b) 
{
	struct domainnames {
		char name[DNS_MAXNAME + 1];
		char next[DNS_MAXNAME + 1];
	};
	struct domainnames *dn0, *dn1;

	dn0 = (struct domainnames *)a;
	dn1 = (struct domainnames *)b;

	return (strcmp(dn0->name, dn1->name));
}

int
count_dots(char *name)
{
	int i;
	int ret = 0;


	for (i = 0; i < strlen(name); i++) {
		if (name[i] == '.')
			ret++;
	}

	return(ret);
}

/* 
 * NEXT_CLOSER_NAME - find the next closer name 
 */

char *
next_closer_name(char *qname, int qlen, char *closestname, int clen, int *rlen)
{
	static char save[DNS_MAXNAME];

	int plen;
	int qcount = 0;
	int ccount = 0;
	int discard;
	
	char *p;

	p = qname;
	plen = qlen;

	do {
		p = advance_label(p, &plen);
		if (p == NULL)
			return NULL;
		qcount++;
	} while (*p);

	p = closestname;
	plen = clen;

	do {
		p = advance_label(p, &plen);
		if (p == NULL)
			return NULL;
		ccount++;
	} while (*p);


	discard = qcount - (ccount + 1);	
	if (discard < 0)
		return NULL;

	p = qname;
	plen = qlen;
	
	while (*p && discard > 0) {
		p = advance_label(p, &plen);
		if (p == NULL)
			return NULL;
		discard--;
	}

	*rlen = plen;
	memcpy(save, p, plen);

	return ((char *)&save);
}

char *
hash_name(char *name, int len, struct nsec3param *n3p)
{
	SHA_CTX ctx;
	u_char md[20];
	int i;

	if (n3p->algorithm != 1) {
		dolog(LOG_INFO, "wrong algorithm: %d, expected 1\n", n3p->algorithm);
		return NULL;
	}

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, name, len);
	SHA1_Update(&ctx, n3p->salt, n3p->saltlen);
	SHA1_Final(md, &ctx);

	for (i = 0; i < n3p->iterations; i++) {
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, md, sizeof(md));
		SHA1_Update(&ctx, n3p->salt, n3p->saltlen);
		SHA1_Final(md, &ctx);
	}

	
	return(base32hex_encode(md, sizeof(md)));
}

void
mysetbit(u_char *input, int pos)
{
	int bit;
	int byte;

	byte = pos / 8;
	bit = pos % 8;
	
	switch (bit) {
	case 0:
		input[byte] |= 128;
		break;
	case 1:
		input[byte] |= 64;
		break;
	case 2:
		input[byte] |= 32;
		break;
	case 3:
		input[byte] |= 16;
		break;
	case 4:
		input[byte] |= 8;
		break;
	case 5:
		input[byte] |= 4;
		break;
	case 6:
		input[byte] |= 2;
		break;
	case 7:
		input[byte] |= 1;
		break;
	}

	return;
}

int
base32hex_decode(u_char *input, u_char *output)
{
	uint8_t tmp;
	char *character = "0123456789abcdefghijklmnopqrstuv=";
	char *start = character, *p = character;
	int i, j;
	int len;
	int bit = 0;

	len = (strlen((const char *)input) * 5) / 8;

	memset(output, 0, len);

	for (i = 0; i < strlen((const char*)input); i++) {
		if (input[i] == '=')
			continue;

		input[i] = tolower(input[i]);
		for (p = character; *p && *p != input[i]; p++);
		if (*p == '\0')
			return 0;
		
		tmp = (plength(p, start));
		tmp <<= 3;

		for (j = 0; j < 5; j++) {
			if (tmp & 128)
				mysetbit(output, bit);
			
			bit++;
			tmp <<= 1;
		}
	}
		
	return (len);
}



char *
base32hex_encode(u_char *input, int len)
{
	u_char *ui;
	uint64_t tb = 0;
	int i;
	u_char *p;
	static char ret[64];
	
	char *character = "0123456789abcdefghijklmnopqrstuv=";

	memset(&ret, 0, sizeof(ret));
	p = (u_char *)&ret[0];
	ui = input;

	for (i = 0; i < len; i += 5) {
		tb = (*ui & 0xff);	
		tb <<= 8;

		if (i < len) 
			ui++;
		else 
			*ui = 0;
	
		tb |= (*ui & 0xff);
		tb <<= 8;

		if (i < len) 
			ui++;
		else 
			*ui = 0;

		tb |= (*ui & 0xff);

		tb <<= 8;

		if (i < len) 
			ui++;
		else 
			*ui = 0;

		tb |= (*ui & 0xff);

		tb <<= 8;

		if (i < len) 
			ui++;
		else 
			*ui = 0;

		tb |= (*ui & 0xff);

		if (i < len) 
			ui++;
		else 
			*ui = 0;

		*(p + 7) = character[(tb & 0x1f)];
		tb >>= 5;
		*(p + 6) = character[(tb & 0x1f)];
		tb >>= 5;
		*(p + 5) = character[(tb & 0x1f)];
		tb >>= 5;
		*(p + 4) = character[(tb & 0x1f)];
		tb >>= 5;
		*(p + 3) = character[(tb & 0x1f)];
		tb >>= 5;
		*(p + 2) = character[(tb & 0x1f)];
		tb >>= 5;
		*(p + 1) = character[(tb & 0x1f)];
		tb >>= 5;
		*(p + 0) = character[(tb & 0x1f)];

		p += 8;
	}

	return (ret);
}

/*
 * NSEC3_MATCH_CLOSEST - find the closest matching encloser 
 *
 */

struct rbtree *
nsec3_match_closest(char *name, int namelen, struct rbtree *rbt, ddDB *db)
{
	char *backname;
	char *dname;
	int backnamelen;
	struct rbtree *rbt0;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;

	if ((rrset = find_rr(rbt, DNS_TYPE_NSEC3PARAM)) == NULL) {
		return NULL;
	}
	if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
		return NULL;
	}

	/* first off find  the next closer record */
	rbt0 = nsec3_closest_encloser(name, namelen, rbt, db);
	if (rbt0 == NULL) {
		return NULL;
	}

#if DEBUG
	dolog(LOG_INFO, "next closer = %s\n", rbt0->humanname);
#endif

#if 0
	hashname = hash_name(rbt0->zone, rbt0->zonelen, (struct nsec3param *)rrp->rdata);
	if (hashname == NULL) {
		dolog(LOG_INFO, "unable to get hashname\n");
		return NULL;
	}
#endif

#if DEBUG
	dolog(LOG_INFO, "hashname  = %s\n", rbt0->humanname);
#endif
	dname = nsec3_match(rbt->zone, rbt->zonelen, rbt0->humanname);
	
	if (dname == NULL) {
		return NULL;
	}
	
	/* found it, get it via db after converting it */	
	
#ifdef DEBUG
	dolog(LOG_INFO, "converting %s\n", dname);
#endif
	backname = dns_label(dname, &backnamelen);
	
	rbt0 = find_rrset(db, backname, backnamelen);
	if (rbt0 == NULL) {
		free (backname);
		return (NULL);
	}
	
	free (backname);

#ifdef DEBUG
	dolog(LOG_INFO, "returning %s\n", rbt0->humanname);
#endif
	return (rbt0);
}

/*
 * NSEC3_WILDCARD_CLOSEST - finds the right nsec3 domainname in a zone 
 * 
 */
struct rbtree *
nsec3_wildcard_closest(char *name, int namelen, struct rbtree *rbt, ddDB *db)
{
	struct rbtree *rbt0 = NULL;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;

	if ((rrset = find_rr(rbt, DNS_TYPE_NSEC3PARAM)) == NULL) {
		return NULL;
	}
	if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
		return NULL;
	}

	/* first off find  the next closer record */
	rbt0 = nsec3_closest_encloser_wild(name, namelen, rbt, db);
	if (rbt0 == NULL) {
		return NULL;
	}

#if DEBUG
	dolog(LOG_INFO, "returning %s\n", rbt0->humanname);
#endif
	return (rbt0);
}

/*
 * NSEC3_COVER_NEXT_CLOSER - finds the right nsec3 domainname in a zone 
 * 
 */
struct rbtree *
nsec3_cover_next_closer(char *name, int namelen, struct rbtree *rbt, ddDB *db)
{
	char *backname, *adv_name;
	char *dname;
	int backnamelen, adv_namelen;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	char *hashname;
	struct rbtree *rbt0;

	if ((rrset = find_rr(rbt, DNS_TYPE_NSEC3PARAM)) == NULL) {
		return NULL;
	}
	if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
		return NULL;
	}

	rbt0 = closest_valid_name(name, namelen, rbt, db);
	if (rbt0 == NULL)
		return NULL;

	adv_name = next_closer_name(name, namelen, rbt0->zone, rbt0->zonelen, &adv_namelen);
	if (adv_name != NULL)
		hashname = hash_name(adv_name, adv_namelen, (struct nsec3param *)rrp->rdata);
	else
		hashname = hash_name(name, namelen, (struct nsec3param *)rrp->rdata);

	/* hash name */
	if (hashname == NULL) {
		dolog(LOG_INFO, "unable to get hashname\n");
		return NULL;
	}


	/* free what we don't need */

	dname = nsec3_next_closer(rbt->zone, rbt->zonelen, hashname);
	if (dname == NULL) {
		return NULL;
	}

#ifdef DEBUG
	dolog(LOG_INFO, "converting %s\n", dname);
#endif

	backname = dns_label(dname, &backnamelen);
	
	if ((rbt0 = find_rrset(db, backname, backnamelen)) == NULL) {
		free (backname);
		return (NULL);
	}
	

	free (backname);

#ifdef DEBUG
	dolog(LOG_INFO, "returning %s\n", rbt0->humanname);
#endif

	return (rbt0);
}

/*
 * NSEC3_MATCH_QNAME - find the matching QNAME and return NSEC3
 *
 */

struct rbtree *
nsec3_match_qname(char *name, int namelen, struct rbtree *rbt, ddDB *db)
{
	char *hashname;
	char *backname;
	char *dname;
	int backnamelen;
	struct rbtree *rbt0 = NULL;
	struct rbtree *wrbt = NULL;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;


	if ((rrset = find_rr(rbt, DNS_TYPE_NSEC3PARAM)) == NULL) {
		return NULL;
	}
	if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
		return NULL;
	}

	if ((wrbt = find_rrsetwild(db, name, namelen)) == NULL)
		hashname = hash_name(name, namelen,  
					(struct nsec3param *)rrp->rdata);
	else
		hashname = hash_name(wrbt->zone, wrbt->zonelen, 
					(struct nsec3param *)rrp->rdata);
	if (hashname == NULL) {
		dolog(LOG_INFO, "unable to get hashname\n");
		return NULL;
	}

#if DEBUG
	dolog(LOG_INFO, "hashname  = %s\n", hashname);
#endif

	dname = nsec3_match(rbt->zone, rbt->zonelen, hashname);
	
	if (dname == NULL) {
		return NULL;
	}
	
	/* found it, get it via db after converting it */	
	
#if DEBUG
	dolog(LOG_INFO, "converting %s\n", dname);
#endif

	backname = dns_label(dname, &backnamelen);
	if (backname == NULL) {
		return NULL;
	}

	rbt0 = find_rrset(db, backname, backnamelen);
	if (rbt0 == NULL) {
		free (backname);
		return (NULL);
	}
	

	free (backname);

#ifdef DEBUG
	dolog(LOG_INFO, "returning %s\n", rbt0->humanname);
#endif

	return (rbt0);
}

char * 
nsec3_match_wild(char *zonename, int zonelen, char *hashname)
{
	int hashlen;

	hashlen = strlen(hashname);

	SLIST_FOREACH(dnp, &dnssechead, dnssec_entry) {
		if (zonelen == dnp->zonelen && 
			(memcmp(dnp->zone, zonename, zonelen) == 0))
			break;
	}

	if (dnp == NULL)
		return NULL;

	/* we have found the zone, now find the next closer hash for nsec3 */

	TAILQ_FOREACH(n3, &dnp->nsec3head, nsec3_entries) {
		if (strncasecmp(hashname, n3->domainname, hashlen) > 0) {
			continue;
		}  else
			break;
	}
	
	/* wraparound on first entry */
	if (TAILQ_FIRST(&dnp->nsec3head) == n3)
		n3 = TAILQ_LAST(&dnp->nsec3head, aa);
	else if (n3 == NULL) {
		n3 = TAILQ_LAST(&dnp->nsec3head, aa);
	} else
		n3 = TAILQ_PREV(n3, aa, nsec3_entries);

	if (n3 == NULL) {
		return (NULL);
	}

#ifdef DEBUG
	dolog(LOG_INFO, "resolved at %s\n", n3->domainname);
#endif

	return (n3->domainname);
}

/* 
 * NSEC3_CLOSEST_ENCLOSER - find the closest encloser record
 */

struct rbtree *
nsec3_closest_encloser(char *qname, int qnamelen, struct rbtree *rbt, ddDB *db)
{
	char nst[DNS_MAXNAME + 1];
	char *hashname, *name;
	int namelen;
	struct rbtree *rbt0 = NULL;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;

	int plen;
	
	char *p;

	p = qname;
	plen = qnamelen;

	/* advance one label */
	p = advance_label(p, &plen);
	if (p == NULL)
		return NULL;


	do {
		rbt0 = find_rrset(db, p, plen);
		if (rbt0 == NULL) {
			if (check_ent(p, plen)) {
				rbt0 = NULL;
				goto nsec3;
			}
			p = advance_label(p, &plen);
			if (p == NULL)
				return NULL;
			continue;
		}
		
		if ((rrset = find_rr(rbt0, DNS_TYPE_NSEC3)) != NULL) {
			p = advance_label(p, &plen);
			if (p == NULL)
				return NULL;
			continue;
		}

		goto nsec3;

	} while (*p);

	return NULL;

nsec3:

	if (rbt0 != NULL) {
		p = rbt0->zone;
		plen = rbt0->zonelen;
	}

	
	if ((rrset = find_rr(rbt, DNS_TYPE_NSEC3PARAM)) == NULL) {
		return (NULL);
	}

	if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL)  {
		return (NULL);
	}


	hashname = hash_name(p, plen, (struct nsec3param *)rrp->rdata);
	if (hashname == NULL)
		return (NULL);			

	snprintf(nst, sizeof(nst), "%s.%s", hashname, rbt->humanname);
	name = dns_label(nst, &namelen);
	if (name == NULL)
		return (NULL);

	return (find_rrset(db, name, namelen));
}

/* 
 * NSEC3_CLOSEST_ENCLOSER_WILD - find the closest encloser record for
 *					wildcards
 */

struct rbtree *
nsec3_closest_encloser_wild(char *qname, int qnamelen, struct rbtree *rbt, ddDB *db)
{
	char wildcard[DNS_MAXNAME + 1];
	char *hashname;
	int hashlen;
	struct rbtree *rbt0 = NULL;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct nsec3entry ns3;

	int plen;
	
	char *p;

	p = qname;
	plen = qnamelen;

	/* advance one label */
	p = advance_label(p, &plen);
	if (p == NULL)
		return NULL;


	do {
		rbt0 = find_rrset(db, p, plen);
		if (rbt0 == NULL) {
			if (check_ent(p, plen)) {
				rbt0 = NULL;
				goto nsec3;
			}
			p = advance_label(p, &plen);
			if (p == NULL)
				return NULL;

			continue;
		}
		
		if ((rrset = find_rr(rbt0, DNS_TYPE_NSEC3)) != NULL) {
			p = advance_label(p, &plen);
			if (p == NULL)
				return NULL;
			continue;
		}

		goto nsec3;

	} while (*p);

	return NULL;

nsec3:

	if (rbt0 != NULL) {
		snprintf(wildcard, sizeof(wildcard), "*.%s", rbt0->humanname);
		p = dns_label(wildcard, &plen);
		if (p == NULL)
			return NULL;

	} else {
		return NULL;
	}

	
	if ((rrset = find_rr(rbt, DNS_TYPE_NSEC3PARAM)) == NULL) {
		free(p);
		return (NULL);
	}

	if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL)  {
		free(p);
		return (NULL);
	}


	hashname = hash_name(p, plen, (struct nsec3param *)rrp->rdata);
	free(p);

	if (hashname == NULL)
		return (NULL);			

	hashlen = strlen(hashname);

	memset((char *)&ns3, 0, sizeof(ns3));
	strlcpy(ns3.domainname, hashname, sizeof(ns3.domainname));

	if ((n3 = RB_FIND(nsec3tree, &dnp->tree, &ns3)) == NULL) {
		TAILQ_FOREACH(n3, &dnp->nsec3head, nsec3_entries) {
			if (strncasecmp(hashname, n3->domainname, hashlen) <= 0) {
				break;
			}
		}
	}

	if (n3 == NULL) {
		/* returning NULL is not recommended here */
		ns3p = TAILQ_LAST(&dnp->nsec3head, aa);
		rbt0 = find_rrset(db, ns3p->dname, ns3p->dnamelen);
		if (rbt0 == NULL) {
			dolog(LOG_INFO, "TAILQ_LAST did not resolve\n");
		}
		return (rbt0);
	}

#if DEBUG
	dolog(LOG_INFO, "resolved wild at %s\n", n3->domainname);
#endif

	if ((ns3p = TAILQ_PREV(n3, aa, nsec3_entries)) != NULL) {
		rbt0 = find_rrset(db, ns3p->dname, ns3p->dnamelen);
		if (rbt0 == NULL) {
			dolog(LOG_INFO, "TAILQ_PREV did not resolve\n");
		}
		return (rbt0);
	} else {
		ns3p = TAILQ_LAST(&dnp->nsec3head, aa);
		rbt0 = find_rrset(db, ns3p->dname, ns3p->dnamelen);
		if (rbt0 == NULL) {
			dolog(LOG_INFO, "TAILQ_LAST did not resolve\n");
		}
		return (rbt0);
	}

	/* NOTREACHED */
	return (NULL);
}

/*
 * NSEC3_MATCH_QNAME_WILD - find the matching QNAME and return NSEC3
 *
 */

struct rbtree *
nsec3_match_qname_wild(char *name, int namelen, struct rbtree *rbt, ddDB *db)
{
	char *hashname;
	char *backname;
	char *dname;
	int backnamelen;
	struct rbtree *rbt0 = NULL;
	struct rbtree *wrbt = NULL;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;


	if ((rrset = find_rr(rbt, DNS_TYPE_NSEC3PARAM)) == NULL) {
		return NULL;
	}
	if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
		return NULL;
	}

	if ((wrbt = find_rrsetwild(db, name, namelen)) == NULL)
		return (NULL);


	hashname = hash_name(name, namelen, (struct nsec3param *)rrp->rdata);
	if (hashname == NULL) {
		dolog(LOG_INFO, "unable to get hashname\n");
		return NULL;
	}

#if DEBUG
	dolog(LOG_INFO, "hashname  = %s\n", hashname);
#endif

	dname = nsec3_match_wild(rbt->zone, rbt->zonelen, hashname);
	
	if (dname == NULL) {
		return NULL;
	}
	
	/* found it, get it via db after converting it */	
	
#if DEBUG
	dolog(LOG_INFO, "converting %s\n", dname);
#endif

	backname = dns_label(dname, &backnamelen);
	if (backname == NULL) {
		return NULL;
	}

	rbt0 = find_rrset(db, backname, backnamelen);
	if (rbt0 == NULL) {
		free (backname);
		return (NULL);
	}
	

	free (backname);

#ifdef DEBUG
	dolog(LOG_INFO, "returning %s\n", rbt0->humanname);
#endif

	return (rbt0);
}

/* 
 * CLOSEST_VALID_NAME - find the closest valid name
 */

struct rbtree *
closest_valid_name(char *qname, int qnamelen, struct rbtree *rbt, ddDB *db)
{
	struct rbtree *rbt0 = NULL;
	int plen = qnamelen;
	char *p = qname;

	while (plen > 0) {
		rbt0 = find_rrset(db, p, plen);
		if (rbt0 == NULL) {
			rbt0 = find_rrsetwild(db, p, plen);
			if (rbt0 != NULL)
				break;

			p = advance_label(p, &plen);
			if (p == NULL)
				return NULL;
			continue;
		}
		break;
	}

	return (rbt0);
}
