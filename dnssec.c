/*
 * Copyright (c) 2015-2018 Peter J. Philipp
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
 * $Id: dnssec.c,v 1.21 2019/02/15 15:11:34 pjp Exp $
 */

#include "ddd-include.h"
#include "ddd-dns.h"
#include "ddd-db.h"

#include <openssl/sha.h>

/* prototypes */

void init_dnssec(void);
int insert_apex(char *zonename, char *zone, int zonelen);
int insert_nsec3(char *zonename, char *domainname, char *dname, int dnamelen);
char * find_next_closer_nsec3(char *zonename, int zonelen, char *hashname);
char * find_match_nsec3(char *zonename, int zonelen, char *hashname);
char * find_match_nsec3_ent(char *zonename, int zonelen, char *hashname);
struct rbtree * find_nsec(char *name, int namelen, struct rbtree *rbt, ddDB *db);
struct rbtree * find_nsec3_match_qname(char *name, int namelen, struct rbtree *, ddDB *db);
struct rbtree * find_nsec3_match_closest(char *name, int namelen, struct rbtree *, ddDB *db);
struct rbtree * find_nsec3_wildcard_closest(char *name, int namelen, struct rbtree *, ddDB *db);
char * convert_name(char *name, int namelen);
int nsec_comp(const void *a, const void *b);
int nsec3_comp(const void *a, const void *b);
int count_dots(char *name);
struct rbtree * find_closest_encloser(ddDB *db, char *name, int namelen);
char * find_next_closer_name(char *, int, char *, int, int *);
char * hash_name(char *name, int len, struct nsec3param *n3p);
char * base32hex_encode(u_char *input, int len);
int 	base32hex_decode(u_char *, u_char *);
void 	mysetbit(u_char *, int);

extern int              get_record_size(ddDB *, char *, int);
extern char *           dns_label(char *, int *);
extern void             dolog(int, char *, ...);
extern int              checklabel(ddDB *, struct rbtree *, struct rbtree *, struct question *);
extern struct question  *build_fake_question(char *, int, u_int16_t);
extern int              free_question(struct question *);
extern int		check_ent(char *, int);
extern int 		memcasecmp(u_char *, u_char *, int);

extern struct rbtree * create_rr(ddDB *db, char *name, int len, int type, void *rdata);
extern struct rbtree * find_rrset(ddDB *db, char *name, int len);
extern struct rrset * find_rr(struct rbtree *rbt, u_int16_t rrtype);
extern int add_rr(struct rbtree *rbt, char *name, int len, u_int16_t rrtype, void *rdata);

SLIST_HEAD(listhead, dnssecentry) dnssechead;

static struct nsec3entry {
	char domainname[DNS_MAXNAME + 1];
	char dname[DNS_MAXNAME];
	int dnamelen;
	TAILQ_ENTRY(nsec3entry) nsec3_entries;	
} *n3, *ns3p;

static struct dnssecentry {
	char zonename[DNS_MAXNAME + 1];
	char zone[DNS_MAXNAME];
	int zonelen;
	SLIST_ENTRY(dnssecentry) dnssec_entry;
	TAILQ_HEAD(aa, nsec3entry) nsec3head;
} *dn, *dnp;


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


	/*
	 * sort the tailq here 
	 */

	if (TAILQ_EMPTY(&dn->nsec3head)) {
		TAILQ_INSERT_TAIL(&dn->nsec3head, n3, nsec3_entries);
	} else {
		ns3p = TAILQ_FIRST(&dn->nsec3head);
		if (strcmp(n3->domainname, ns3p->domainname) < 0) {
			TAILQ_INSERT_BEFORE(ns3p, n3, nsec3_entries);
		} else {
			while ((ns3p = TAILQ_NEXT(ns3p, nsec3_entries)) != NULL) {
				if (strcmp(n3->domainname, ns3p->domainname) < 0) {
					TAILQ_INSERT_BEFORE(ns3p, n3, nsec3_entries);
					break;
				}
			}
		}
		if (ns3p == NULL) {
			TAILQ_INSERT_TAIL(&dn->nsec3head, n3, nsec3_entries);
		}
	}


	return (0);
}

char * 
find_next_closer_nsec3(char *zonename, int zonelen, char *hashname)
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
find_match_nsec3_ent(char *zonename, int zonelen, char *hashname)
{
	int hashlen;
	int count;

	hashlen = strlen(hashname);

	SLIST_FOREACH(dnp, &dnssechead, dnssec_entry) {
		if (zonelen == dnp->zonelen && 
			(memcasecmp(dnp->zone, zonename, zonelen) == 0))
			break;
	}

	if (dnp == NULL)
		return NULL;

	/* we have found the zone, now find the next closer hash for nsec3 */

	count = 0;
	TAILQ_FOREACH(n3, &dnp->nsec3head, nsec3_entries) {
		if (strncasecmp(hashname, n3->domainname, hashlen) < 0) {
			if (count == 0) 
				n3 = TAILQ_LAST(&dnp->nsec3head, aa);
			else
				n3 = TAILQ_PREV(n3,  aa, nsec3_entries);
			break;
		} 
		count++;
	}
	
	if (n3 == NULL) {
		return NULL;
	}

#ifdef DEBUG
	dolog(LOG_INFO, "resolved at %s\n", n3->domainname);
#endif

	return (n3->domainname);
}

char * 
find_match_nsec3(char *zonename, int zonelen, char *hashname)
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


/* FIND_NSEC  */
/* finds the right nsec domainname in a zone */
struct rbtree *
find_nsec(char *name, int namelen, struct rbtree *rbt, ddDB *db)
{
	char *table, *tmp;
	char *nsecname;
	struct domainnames {
		char name[DNS_MAXNAME + 1];
		char next[DNS_MAXNAME + 1];
	} *dn;

	struct rbtree *rbt0;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	char *humanname;
	char tmpname[DNS_MAXNAME];
	int tmplen;
	char *backname;
	int backnamelen;
	int i, names = 100;
	int j;

	humanname = convert_name(name, namelen);

	if ((rrset = find_rr(rbt, DNS_TYPE_NSEC)) == NULL) {
		free (humanname);
		return (NULL);
	}
	
	rrp = TAILQ_FIRST(&rrset->rr_head);
	if (rrp == NULL) {
		free(humanname);
		return (NULL);
	}

	table = calloc(names, sizeof(struct domainnames));	
	if (table == NULL) {
		free (humanname);
		return (NULL);
	}

	dn = (struct domainnames *)table;
	strlcpy(dn->name, rbt->humanname, DNS_MAXNAME + 1);
	nsecname = convert_name(((struct nsec *)rrp->rdata)->next_domain_name, ((struct nsec *)rrp->rdata)->ndn_len);
	strlcpy(dn->next, nsecname, DNS_MAXNAME + 1);
	
	rbt0 = find_rrset(db, ((struct nsec *)rrp->rdata)->next_domain_name, ((struct nsec *)rrp->rdata)->ndn_len);
	if (rbt0 == NULL) {
		free (nsecname);
		free (humanname);
		free (table);
		return (NULL);
	}

	if ((rrset = find_rr(rbt0, DNS_TYPE_NSEC)) == NULL) {
		free (nsecname);
		free (humanname);
		free (table);
		free (rbt0);
		return (NULL);
	}

	rrp = TAILQ_FIRST(&rrset->rr_head);
	if (rrp == NULL) {
		free(humanname);
		return (NULL);
	}

	i = 1;
	while (strcasecmp(nsecname, rbt->humanname) != 0) {
		/* grow our table */
		if (i == names - 1) {
			names += 100;
	
			tmp = realloc(table, names * sizeof(struct domainnames));
			if (tmp == NULL) {
				free (nsecname);
				free (humanname);
				free (table);
				free (rbt0);
				return (NULL);
			}
			table = tmp;
		}

		dn = ((struct domainnames *)table) + i;
		
		free (nsecname);
		strlcpy(dn->name, rbt0->humanname, DNS_MAXNAME + 1);
		nsecname = convert_name(((struct nsec *)rrp->rdata)->next_domain_name, ((struct nsec *)rrp->rdata)->ndn_len);
		strlcpy(dn->next, nsecname, DNS_MAXNAME + 1);
		
		memcpy(tmpname, ((struct nsec *)rrp->rdata)->next_domain_name, ((struct nsec *)rrp->rdata)->ndn_len);
		tmplen = ((struct nsec *)rrp->rdata)->ndn_len;

		free (rbt0);

		rbt0 = find_rrset(db, tmpname, tmplen);
		if (rbt0 == NULL) {
			free (humanname);
			free (table);
			free (rbt0);
			return (NULL);
		}

		if ((rrset = find_rr(rbt0, DNS_TYPE_NSEC)) == NULL) {
			free (humanname);
			free (table);
			free (rbt0);
			return (NULL);
		}

		i++;
	}

	free (nsecname);
	dn = ((struct domainnames *)table) + i;
	strlcpy(dn->next, ".", DNS_MAXNAME + 1);
	strlcpy(dn->name, humanname, DNS_MAXNAME + 1);

	i++;

	/* now we sort the shebang */

	qsort(table, i, sizeof(struct domainnames), nsec_comp);
	
	for (j = 0; j < i; j++) {
		dn = ((struct domainnames *)table) + j;
		
#if DEBUG
		if (debug)
			printf("%s\n", dn->name);
#endif

		if (strcmp(dn->next, ".") == 0)
			break;
	}

	dn = ((struct domainnames *)table) + (j - 1);	
	
	/* found it, get it via db after converting it */	
	
	/* free what we don't need */
	free (humanname);
	free (rbt0);
	
	backname = dns_label(dn->name, &backnamelen);
	free (table);
	

	rbt0 = find_rrset(db, backname, backnamelen);
	if (rbt0 == NULL) {
		free (backname);
		free (rbt0);
		return (NULL);
	}
	
	free (backname);
	return (rbt0);
}

char *
convert_name(char *name, int namelen)
{
	char *ret;
	char *p, *p0;
	int plen;
	int i;

	if (namelen == 0)
		return NULL;

	ret = calloc(namelen + 1, 1);
	if (ret == NULL) {
		return NULL;
	}

	memcpy(ret, name + 1, namelen - 1);
	
	p0 = ret;
	p = name;
	plen = namelen;

        while (*p != 0) {
		if (*p > 63)
			break;
		for (i = 0; i < *p; i++) {
			*p0++ = p[i + 1];
		}
		*p0++ = '.';
        	plen -= (*p + 1);
                p = (p + (*p + 1));
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
 * FIND_NEXT_CLOSER - find the next closer name 
 */

char *
find_next_closer_name(char *qname, int qlen, char *closestname, int clen, int *rlen)
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
		plen -= (*p + 1);
		p = (p + (*p + 1));
		qcount++;
	} while (*p);

	p = closestname;
	plen = clen;

	do {
		plen -= (*p + 1);
		p = (p + (*p + 1));
		ccount++;
	} while (*p);


	discard = qcount - (ccount + 1);	
	if (discard < 0)
		return NULL;

	p = qname;
	plen = qlen;
	
	while (*p && discard > 0) {
		plen -= (*p + 1);
		p = (p + (*p + 1));
		discard--;
	}

	*rlen = plen;
	memcpy(save, p, plen);

	return ((char *)&save);
}

/* 
 * FIND_CLOSEST_ENCLOSER - find the closest encloser record
 */

struct rbtree *
find_closest_encloser(ddDB *db, char *name, int namelen)
{
	struct rbtree *rbt = NULL;
	struct rrset *rrset = NULL;

	int plen;
	
	char *p;

	p = name;
	plen = namelen;

	/* advance one label */
	plen -= (*p + 1);
	p = (p + (*p + 1));


	do {
		rbt = find_rrset(db, p, plen);
		if (rbt == NULL) {
			plen -= (*p + 1);
			p = (p + (*p + 1));
			continue;
		}
		
		if ((rrset = find_rr(rbt, DNS_TYPE_NSEC3)) != NULL) {
			plen -= (*p + 1);
			p = (p + (*p + 1));
			free (rbt);
			continue;
		}

		return (rbt);
	} while (*p);

	if (rbt)
		free (rbt);

	return NULL;
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
	u_int8_t tmp;
	u_char *character = "0123456789abcdefghijklmnopqrstuv=";
	u_char *start = character, *p = character;
	int i, j;
	int len;
	int bit = 0;

	len = (strlen(input) * 5) / 8;

	memset(output, 0, len);

	for (i = 0; i < strlen(input); i++) {
		if (input[i] == '=')
			continue;

		input[i] = tolower(input[i]);
		for (p = character; *p && *p != input[i]; p++);
		if (*p == '\0')
			return 0;
		
		tmp = (p - start);
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
	u_int64_t tb = 0;
	int i;
	u_char *p;
	static char ret[33];
	
	u_char *character = "0123456789abcdefghijklmnopqrstuv=";

	memset(&ret, 0, sizeof(ret));
	p = &ret[0];
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
 * FIND_NSEC3_MATCH_CLOSEST - find the closest matching encloser 
 *
 */

struct rbtree *
find_nsec3_match_closest(char *name, int namelen, struct rbtree *rbt, ddDB *db)
{
	char *hashname;
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
	rbt0 = find_closest_encloser(db, name, namelen);
	if (rbt0 == NULL) {
		return NULL;
	}

#if DEBUG
	dolog(LOG_INFO, "next closer = %s\n", rbt0->humanname);
#endif

	hashname = hash_name(rbt0->zone, rbt0->zonelen, (struct nsec3param *)rrp->rdata);
	if (hashname == NULL) {
		dolog(LOG_INFO, "unable to get hashname\n");
		free (rbt0);
		return NULL;
	}

	free (rbt0);
#if DEBUG
	dolog(LOG_INFO, "hashname  = %s\n", hashname);
#endif
	dname = find_match_nsec3(rbt->zone, rbt->zonelen, hashname);
	
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
 * FIND_NSEC3_WILDCARD_CLOSEST - finds the right nsec3 domainname in a zone 
 * 
 */
struct rbtree *
find_nsec3_wildcard_closest(char *name, int namelen, struct rbtree *rbt, ddDB *db)
{
	char *hashname;
	char *backname;
	char *dname;
	char wildcard[DNS_MAXNAME + 1];
	int backnamelen;
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
	rbt0 = find_closest_encloser(db, name, namelen);
	if (rbt0 == NULL) {
		return NULL;
	}

#if DEBUG
	dolog(LOG_INFO, "next closer = %s\n", rbt0->humanname);
#endif

	snprintf(wildcard, sizeof(wildcard), "*.%s", rbt0->humanname);
	backname = dns_label(wildcard, &backnamelen);

	hashname = hash_name(backname, backnamelen, (struct nsec3param *)rrp->rdata);
	if (hashname == NULL) {
		dolog(LOG_INFO, "unable to get hashname\n");
		free (rbt0);
		return NULL;
	}

#if DEBUG
	dolog(LOG_INFO, "hashname  = %s\n", hashname);
#endif
	
	dname = find_next_closer_nsec3(rbt->zone, rbt->zonelen, hashname);
	
	/* found it, get it via db after converting it */	
	
	/* free what we don't need */
	free (rbt0);
	
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
 * FIND_NSEC3_COVER_NEXT_CLOSER - finds the right nsec3 domainname in a zone 
 * 
 */
struct rbtree *
find_nsec3_cover_next_closer(char *name, int namelen, struct rbtree *rbt, ddDB *db)
{
	char *hashname;
	char *backname;
	char *dname;
	int backnamelen;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	char *ncn;
	int ncnlen;
	struct rbtree *rbt0;

	if ((rrset = find_rr(rbt, DNS_TYPE_NSEC3PARAM)) == NULL) {
		return NULL;
	}
	if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
		return NULL;
	}

	/* first off find  the next closer record */
	rbt0 = find_closest_encloser(db, name, namelen);
	if (rbt0 == NULL) {
		return NULL;
	}

	ncn = find_next_closer_name(name, namelen, rbt0->zone, rbt0->zonelen, &ncnlen);
	if (ncn == NULL) {
		free(rbt0);
		return NULL;
	}

	hashname = hash_name(ncn, ncnlen, (struct nsec3param *)rrp->rdata);
	if (hashname == NULL) {
		dolog(LOG_INFO, "unable to get hashname\n");
		free (rbt0);
		return NULL;
	}

#if DEBUG
	dolog(LOG_INFO, "hashname  = %s\n", hashname);
#endif
	
	/* free what we don't need */
	free (rbt0);

	dname = find_next_closer_nsec3(rbt->zone, rbt->zonelen, hashname);
	if (dname == NULL)
		return NULL;

	
#ifdef DEBUG
	dolog(LOG_INFO, "converting %s\n", dname);
#endif

	backname = dns_label(dname, &backnamelen);
	
	if ((rbt0 = find_rrset(db, backname, backnamelen)) == NULL) {
		free (backname);
		free (rbt0);
		return (NULL);
	}
	

	free (backname);

#ifdef DEBUG
	dolog(LOG_INFO, "returning %s\n", rbt0->humanname);
#endif

	return (rbt0);
}

/*
 * FIND_NSEC3_MATCH_QNAME - find the matching QNAME and return NSEC3
 *
 */

struct rbtree *
find_nsec3_match_qname(char *name, int namelen, struct rbtree *rbt, ddDB *db)
{
	char *hashname;
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

	hashname = hash_name(name, namelen,  (struct nsec3param *)rrp->rdata);
	if (hashname == NULL) {
		dolog(LOG_INFO, "unable to get hashname\n");
		return NULL;
	}

#if DEBUG
	dolog(LOG_INFO, "hashname  = %s\n", hashname);
#endif

	if (check_ent(name, namelen)) 
		dname = find_match_nsec3_ent(rbt->zone, rbt->zonelen, hashname);	
	else
		dname = find_match_nsec3(rbt->zone, rbt->zonelen, hashname);
	
	if (dname == NULL)
		return NULL;
	
	/* found it, get it via db after converting it */	
	
#if DEBUG
	dolog(LOG_INFO, "converting %s\n", dname);
#endif

	backname = dns_label(dname, &backnamelen);
	
	rbt0 = find_rrset(db, backname, backnamelen);
	if (rbt0 == NULL) {
		free (backname);
		free (rbt0);
		return (NULL);
	}
	

	free (backname);

#ifdef DEBUG
	dolog(LOG_INFO, "returning %s\n", rbt0->humanname);
#endif

	return (rbt0);
}
