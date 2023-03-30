/*
 * Copyright (c) 2015-2023 Peter J. Philipp <pbug44@delphinusdns.org>
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
int finalize_nsec3(void);
struct rbtree * find_closest_encloser_nsec3(char *, int, struct rbtree *, ddDB *);

extern int              get_record_size(ddDB *, char *, int);
extern char *           dns_label(char *, int *);
extern void             dolog(int, char *, ...);
extern int              checklabel(ddDB *, struct rbtree *, struct rbtree *, struct question *);
extern int              free_question(struct question *);
extern int		check_ent(char *, int);
extern int 		memcasecmp(u_char *, u_char *, int);

extern struct rbtree * find_rrset(ddDB *db, char *name, int len);
extern struct rbtree * find_rrsetwild(ddDB *db, char *name, int len);
extern struct rrset * find_rr(struct rbtree *rbt, uint16_t rrtype);
extern int add_rr(struct rbtree *rbt, char *name, int len, uint16_t rrtype, void *rdata);
extern size_t plength(void *, void *);

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

	RB_INSERT(nsec3tree, &dnp->tree, n3);
	
	return (0);
}




int
finalize_nsec3(void)
{
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

#if 0
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
#endif

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
		return (NULL);
	}

	rrp = TAILQ_FIRST(&rrset->rr_head);
	if (rrp == NULL) {
		free(nsecname);
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


		rbt0 = find_rrset(db, tmpname, tmplen);
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
		printf("%s\n", dn->name);
#endif

		if (strcmp(dn->next, ".") == 0)
			break;
	}

	dn = ((struct domainnames *)table) + (j - 1);	
	
	/* found it, get it via db after converting it */	
	
	/* free what we don't need */
	free (humanname);
	
	backname = dns_label(dn->name, &backnamelen);
	free (table);
	

	rbt0 = find_rrset(db, backname, backnamelen);
	if (rbt0 == NULL) {
		free (backname);
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
        	plen -= (*p + 1);
                p += (*p + 1);
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
			continue;
		}

		return (rbt);
	} while (*p);

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
		return NULL;
	}

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
	struct rbtree *rbt0 = NULL;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;

	char *hashname;
	char *backname;
	char *dname;
	char *p;
	char wildcard[DNS_MAXNAME + 1];

	int backnamelen;
	int ret;

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
	p = rbt0->humanname;
	ret = snprintf(wildcard, sizeof(wildcard), "*.%s", p);
	if (ret >= sizeof(wildcard)) {
		dolog(LOG_INFO, "result was truncated\n");
		return NULL;
	}

	backname = dns_label(wildcard, &backnamelen);

	hashname = hash_name(backname, backnamelen, (struct nsec3param *)rrp->rdata);
	if (hashname == NULL) {
		dolog(LOG_INFO, "unable to get hashname\n");
		return NULL;
	}

#if DEBUG
	dolog(LOG_INFO, "hashname  = %s\n", hashname);
#endif
	
	dname = find_next_closer_nsec3(rbt->zone, rbt->zonelen, hashname);
	if (dname == NULL)
		return NULL;
	
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
		return NULL;
	}

	hashname = hash_name(ncn, ncnlen, (struct nsec3param *)rrp->rdata);
	if (hashname == NULL) {
		dolog(LOG_INFO, "unable to get hashname\n");
		return NULL;
	}

#if DEBUG
	dolog(LOG_INFO, "hashname  = %s\n", hashname);
#endif
	
	/* free what we don't need */

	dname = find_next_closer_nsec3(rbt->zone, rbt->zonelen, hashname);
	if (dname == NULL)
		return NULL;

	
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

#if 0
	if (check_ent(name, namelen)) 
		dname = find_match_nsec3_ent(rbt->zone, rbt->zonelen, hashname);	
	else
#endif

	dname = find_match_nsec3(rbt->zone, rbt->zonelen, hashname);
	
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
find_match_nsec3_wild(char *zonename, int zonelen, char *hashname)
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
 * FIND_NSEC3_MATCH_QNAME_WILD - find the matching QNAME and return NSEC3
 *
 */

struct rbtree *
find_nsec3_match_qname_wild(char *name, int namelen, struct rbtree *rbt, ddDB *db)
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

	dname = find_match_nsec3_wild(rbt->zone, rbt->zonelen, hashname);
	
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
 * FIND_CLOSEST_ENCLOSER_NSEC3 - find the closest encloser record
 */

struct rbtree *
find_closest_encloser_nsec3(char *qname, int qnamelen, struct rbtree *rbt, ddDB *db)
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
	plen -= (*p + 1);
	p = (p + (*p + 1));


	do {
		rbt0 = find_rrset(db, p, plen);
		if (rbt0 == NULL) {
			if (check_ent(p, plen)) {
				rbt0 = NULL;
				goto nsec3;
			}
			plen -= (*p + 1);
			p = (p + (*p + 1));
			continue;
		}
		
		if ((rrset = find_rr(rbt0, DNS_TYPE_NSEC3)) != NULL) {
			plen -= (*p + 1);
			p = (p + (*p + 1));
			continue;
		}

		goto nsec3;

	} while (*p);

	return NULL;

nsec3:

	if (rbt0 != NULL) {
		p = rbt->zone;
		plen = rbt->zonelen;
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
