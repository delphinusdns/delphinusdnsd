/*
 * Copyright (c) 2015 Peter J. Philipp
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
#include "include.h"
#include "dns.h"
#include "db.h"

#include <openssl/sha.h>

/* prototypes */

void init_dnssec(void);
int insert_apex(char *zonename, char *zone, int zonelen);
int insert_nsec3(char *zonename, char *domainname, char *dname, int dnamelen);
struct domain * find_nsec(char *name, int namelen, struct domain *sd, DB *db);
struct domain * find_nsec3_match_qname(char *name, int namelen, struct domain *sd, DB *db);
struct domain * find_nsec3_match_closest(char *name, int namelen, struct domain *sd, DB *db);
struct domain * find_nsec3_wildcard_closest(char *name, int namelen, struct domain *sd, DB *db);
char * convert_name(char *name, int namelen);
int nsec_comp(const void *a, const void *b);
int nsec3_comp(const void *a, const void *b);
int count_dots(char *name);
struct domain * find_next_closer(DB *db, char *name, int namelen);
char * hash_name(char *name, int len, struct nsec3param *n3p);
char * base32hex_encode(u_char *input, int len);

extern int              get_record_size(DB *, char *, int);
extern char *           dns_label(char *, int *);
extern void             dolog(int, char *, ...);
extern int              checklabel(DB *, struct domain *, struct domain *, struct question *);
extern struct question  *build_fake_question(char *, int, u_int16_t);
extern int              free_question(struct question *);
extern void *           find_substruct(struct domain *, u_int16_t);


SLIST_HEAD(listhead, dnssecentry) dnssechead;

static struct dnssecentry {
	char zonename[DNS_MAXNAME + 1];
	char zone[DNS_MAXNAME];
	int zonelen;
	SLIST_ENTRY(dnssecentry) dnssec_entry;
	LIST_HEAD(, nsec3entry) nsec3head;
} *dn, *dnp;

static struct nsec3entry {
	char domainname[DNS_MAXNAME + 1];
	char dname[DNS_MAXNAME];
	int dnamelen;
	LIST_ENTRY(nsec3entry) nsec3_entries;	
} *n3, *ns3p;

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

	LIST_INIT(&dn->nsec3head);

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

	n3 = calloc(1, sizeof(dnp->nsec3head));
	if (n3 == NULL)
		return -1;

	strlcpy(n3->domainname, domainname, DNS_MAXNAME + 1);
	
	if (dnamelen > DNS_MAXNAME) {
		free (n3);
		return -1;
	}

	memcpy(n3->dname, dname, dnamelen);
	n3->dnamelen = dnamelen;

	LIST_FOREACH(ns3p, &dnp->nsec3head, nsec3_entries)
		if (LIST_NEXT(ns3p, nsec3_entries) == NULL)
			break;
	
	LIST_INSERT_AFTER(ns3p, n3, nsec3_entries);

	return (0);
}

/* FIND_NSEC  */
/* finds the right nsec domainname in a zone */
struct domain *
find_nsec(char *name, int namelen, struct domain *sd, DB *db)
{
	DBT key, data;
	char *table, *tmp;
	char *nsecname;
	struct domainnames {
		char name[DNS_MAXNAME + 1];
		char next[DNS_MAXNAME + 1];
	} *dn;

	struct domain *sd0;
	struct domain_nsec *sdnsec;
	char *humanname;
	char *backname;
	char tmpname[DNS_MAXNAME];
	int tmplen;
	int backnamelen;
	int rs, ret;
	int i, names = 100;
	int j;

	humanname = convert_name(name, namelen);

	if ((sdnsec = find_substruct(sd, INTERNAL_TYPE_NSEC)) == NULL) {
		free (humanname);
		return (NULL);
	}

	
	table = calloc(names, sizeof(struct domainnames));	
	if (table == NULL) {
		free (humanname);
		return (NULL);
	}

	dn = (struct domainnames *)table;
	strlcpy(dn->name, sd->zonename, DNS_MAXNAME + 1);
	nsecname = convert_name(sdnsec->nsec.next_domain_name, sdnsec->nsec.ndn_len);
	strlcpy(dn->next, nsecname, DNS_MAXNAME + 1);
	
	rs = get_record_size(db, sdnsec->nsec.next_domain_name, sdnsec->nsec.ndn_len);
	if (rs < 0) {
		free (nsecname);
		free (humanname);
		free (table);
		return (NULL);
	}

	if ((sd0 = calloc(1, rs)) == NULL) {
		free (nsecname);
		free (humanname);
		free (table);
		return (NULL);
	}

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));
	
	key.data = sdnsec->nsec.next_domain_name;
	key.size = sdnsec->nsec.ndn_len;

	data.data = NULL;
	data.size = rs;

	ret = db->get(db, NULL, &key, &data, 0);	
	if (ret != 0) {
		free (nsecname);
		free (humanname);
		free (table);
		free (sd0);
		return (NULL);
	}

	memcpy(sd0, data.data, data.size);

	if ((sdnsec = find_substruct(sd0, INTERNAL_TYPE_NSEC)) == NULL) {
		free (nsecname);
		free (humanname);
		free (table);
		free (sd0);
		return (NULL);
	}

	i = 1;
	while (strcasecmp(nsecname, sd->zonename) != 0) {
		/* grow our table */
		if (i == names - 1) {
			names += 100;
	
			tmp = realloc(table, names * sizeof(struct domainnames));
			if (tmp == NULL) {
				free (nsecname);
				free (humanname);
				free (table);
				free (sd0);
				return (NULL);
			}
			table = tmp;
		}

		dn = ((struct domainnames *)table) + i;
		
		free (nsecname);
		strlcpy(dn->name, sd0->zonename, DNS_MAXNAME + 1);
		nsecname = convert_name(sdnsec->nsec.next_domain_name, sdnsec->nsec.ndn_len);
		strlcpy(dn->next, nsecname, DNS_MAXNAME + 1);
		
		rs = get_record_size(db, sdnsec->nsec.next_domain_name, sdnsec->nsec.ndn_len);
		if (rs < 0) {
			free (table);
			return (NULL);
		}

		memcpy(tmpname, sdnsec->nsec.next_domain_name, sdnsec->nsec.ndn_len);
		tmplen = sdnsec->nsec.ndn_len;

		free (sd0);
		if ((sd0 = calloc(1, rs)) == NULL) {
			free (humanname);
			free (table);
			return (NULL);
		}

		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));
		
		key.data = tmpname;
		key.size = tmplen;

		data.data = NULL;
		data.size = rs;

		ret = db->get(db, NULL, &key, &data, 0);	
		if (ret != 0) {
			free (humanname);
			free (table);
			free (sd0);
			return (NULL);
		}

		memcpy(sd0, data.data, data.size);

		if ((sdnsec = find_substruct(sd0, INTERNAL_TYPE_NSEC)) == NULL) {
			free (humanname);
			free (table);
			free (sd0);
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
	free (sd0);
	
	backname = dns_label(dn->name, &backnamelen);
	free (table);
	
	rs = get_record_size(db, backname, backnamelen);
	if (rs < 0) {
		free (backname);
		return (NULL);
	}

	if ((sd0 = calloc(1, rs)) == NULL) {
		free (backname);
		return (NULL);
	}

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));
	
	key.data = backname;
	key.size = backnamelen;

	data.data = NULL;
	data.size = rs;

	ret = db->get(db, NULL, &key, &data, 0);	
	if (ret != 0) {
		free (backname);
		free (sd0);
		return (NULL);
	}
	

	memcpy(sd0, data.data, data.size);
	free (backname);

	return (sd0);
}

char *
convert_name(char *name, int namelen)
{
	char *ret;
	char *p, *p0;
	int plen;
	int i;

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
 * FIND_NEXT_CLOSER - find the next closest record
 */

struct domain *
find_next_closer(DB *db, char *name, int namelen)
{
	struct domain *sd = NULL;

	int plen;
	int ret = 0;
	int rs;
	
	DBT key, data;

	char *p;

	p = name;
	plen = namelen;

	do {
		rs = get_record_size(db, p, plen);
		if (rs < 0) {
			return NULL;
		}

		sd = calloc(rs, 1);
		if (sd == NULL) 
			return NULL;

		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));

		key.data = (char *)p;
		key.size = plen;

		data.data = NULL;
		data.size = rs;

		ret = db->get(db, NULL, &key, &data, 0);
		if (ret != 0) {
			plen -= (*p + 1);
			p = (p + (*p + 1));
			free (sd);
			continue;
		}
		
		if (data.size != rs) {
			dolog(LOG_INFO, "btree db is damaged, drop\n");
			free (sd);
			return (NULL);
		}

		memcpy((char *)sd, (char *)data.data, data.size);
		if (sd->flags & DOMAIN_HAVE_NSEC3) {
			plen -= (*p + 1);
			p = (p + (*p + 1));
			free (sd);
			continue;
		}

		return (sd);
	} while (*p);

	if (sd)
		free (sd);

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

	return (base32hex_encode(md, sizeof(md)));	
}

char *
base32hex_encode(u_char *input, int len)
{
	u_char *ui;
	u_int64_t tb = 0;
	int i;
	u_char *p;
	static char ret[32];
	
	u_char *character = "0123456789abcdefghijklmnopqrstuv=";

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

/* COUNT_NSEC3_IN_ZONE - counts how many nsec3 records there is */

int
count_nsec3_in_zone(DB *db, struct domain *sd, struct question *question)
{
	DBT key, data;
	DBC *cursor;
	struct domain *sd0;
	int rs, count = 0;

	if (db->cursor(db, NULL, &cursor, 0) != 0) {
		dolog(LOG_INFO, "cn3iz db->cursor: %s\n", strerror(errno));
		return -1;
	}	

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	if (cursor->c_get(cursor, &key, &data, DB_FIRST) != 0) {
		dolog(LOG_INFO, "cn3iz cursor->c_get: %s\n", strerror(errno));
		return -1;
	}

	do {
		rs = data.size;
		if ((sd0 = calloc(1, rs)) == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			return(-1);
		}

		memcpy((char *)sd0, (char *)data.data, data.size);

		if (checklabel(db, sd0, sd, question) == 1) {
			if (sd0->flags & DOMAIN_HAVE_NSEC3)
				count++;	
		}

		free (sd0);

		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));

	}  while (cursor->c_get(cursor, &key, &data, DB_NEXT) == 0);

	cursor->c_close(cursor);

	return (count);
}

/*
 * FIND_NSEC3_MATCH_CLOSEST - find the closest matching encloser 
 *
 */

struct domain *
find_nsec3_match_closest(char *name, int namelen, struct domain *sd, DB *db)
{
	struct domainnames {
		char name[DNS_MAXNAME + 1];
		char next[DNS_MAXNAME + 1];
	} *dn;

	DBC *cursor;
	DBT key, data;

	char *hashname;
	char *backname;
	char *table, *tmp;
	int backnamelen;
	int rs, ret;
	int i, j;
	int count, hashnamelen;
	struct domain *sd0, *sd1;
	struct domain_nsec3param *n3p;
	struct question *question;

	if ((n3p = find_substruct(sd, INTERNAL_TYPE_NSEC3PARAM)) == NULL) {
		return NULL;
	}

	/* first off find  the next closer record */
	sd0 = find_next_closer(db, name, namelen);
	if (sd0 == NULL) {
		return NULL;
	}

#if DEBUG
	dolog(LOG_INFO, "next closer = %s\n", sd0->zonename);
#endif

	hashname = hash_name(sd0->zone, sd0->zonelen, &n3p->nsec3param);
	if (hashname == NULL) {
		dolog(LOG_INFO, "unable to get hashname\n");
		free (sd0);
		return NULL;
	}

#if DEBUG
	dolog(LOG_INFO, "hashname  = %s\n", hashname);
#endif
	
	/* now go through our zone and find NSEC3 domains */
	/* first pass, count the NSEC3 list */	
	
	/* we need question for checklabel() */
	question = build_fake_question(sd->zone, sd->zonelen, 0);
	if (question == NULL) {
		dolog(LOG_INFO, "build_fake_question failed\n");
		free (sd0);
		return NULL;
	}

	count = count_nsec3_in_zone(db, sd, question);

	/* realloc names structure to fit the NSEC3 names */
	
	tmp = calloc(count, sizeof(struct domainnames));
	if (tmp == NULL) {
		dolog(LOG_INFO, "realloc: %s\n", strerror(errno));
		free_question(question);
		free (sd0);
		return NULL;	
	}
		
	table = tmp;
	dn = (struct domainnames *)tmp;

	/* second pass, fill NSEC3 list */

	if (db->cursor(db, NULL, &cursor, 0) != 0) {
		dolog(LOG_INFO, "find_nsec3 db->cursor: %s\n", strerror(errno));
		free_question(question);
		free (sd0);
		return NULL;
	}	

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	if (cursor->c_get(cursor, &key, &data, DB_FIRST) != 0) {
		dolog(LOG_INFO, "find_nsec3 cursor->c_get: %s\n", strerror(errno));
		free_question(question);
		free (sd0);
		return NULL;
	}

	i = 1;

	do {
		rs = data.size;
		if ((sd1 = calloc(1, rs)) == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			free_question(question);
			free (sd0);
			return NULL;
		}

		memcpy((char *)sd1, (char *)data.data, data.size);

		if (checklabel(db, sd1, sd, question) == 1) {
			if (sd1->flags & DOMAIN_HAVE_NSEC3) {
				strlcpy(dn->name, sd1->zonename, DNS_MAXNAME + 1);
				strlcpy(dn->next, "-", DNS_MAXNAME + 1);
				dn++;
			}
		}

		free (sd1);

		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));

	}  while (cursor->c_get(cursor, &key, &data, DB_NEXT) == 0);

	cursor->c_close(cursor);
	free_question(question);

	/* now we sort the shebang */
	qsort(table, count, sizeof(struct domainnames), nsec3_comp);

	hashnamelen = strlen(hashname);
	for (j = 0; j < count; j++) {
		dn = ((struct domainnames *)table) + j;
		
		if (strncasecmp(dn->name, hashname, hashnamelen) == 0)
			break;
	}

	if (j == count) {
		dolog(LOG_INFO, "did not find hashname %s in list\n", hashname);
		free (sd0);	
		return NULL;
	}
	
	/* found it, get it via db after converting it */	
	
	/* free what we don't need */
	free (sd0);
	
	dolog(LOG_INFO, "converting %s\n", dn->name);
	backname = dns_label(dn->name, &backnamelen);
	free (table);
	
	rs = get_record_size(db, backname, backnamelen);
	if (rs < 0) {
		free (backname);
		return (NULL);
	}

	if ((sd0 = calloc(1, rs)) == NULL) {
		free (backname);
		return (NULL);
	}

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));
	
	key.data = backname;
	key.size = backnamelen;

	data.data = NULL;
	data.size = rs;

	ret = db->get(db, NULL, &key, &data, 0);	
	if (ret != 0) {
		free (backname);
		free (sd0);
		return (NULL);
	}
	

	memcpy(sd0, data.data, data.size);
	free (backname);

	dolog(LOG_INFO, "returning %s\n", sd0->zonename);
	return (sd0);
}

/*
 * FIND_NSEC3_WILDCARD_CLOSEST - finds the right nsec3 domainname in a zone 
 * 
 */
struct domain *
find_nsec3_wildcard_closest(char *name, int namelen, struct domain *sd, DB *db)
{
	struct domainnames {
		char name[DNS_MAXNAME + 1];
		char next[DNS_MAXNAME + 1];
	} *dn;

	DBC *cursor;
	DBT key, data;

	char *hashname;
	char *backname;
	char *table, *tmp;
	char wildcard[DNS_MAXNAME + 1];
	int backnamelen;
	int rs, ret;
	int i, j;
	int count;
	int golast = 0;
	struct domain *sd0, *sd1;
	struct domain_nsec3param *n3p;
	struct question *question;

	if ((n3p = find_substruct(sd, INTERNAL_TYPE_NSEC3PARAM)) == NULL) {
		return NULL;
	}

	/* first off find  the next closer record */
	sd0 = find_next_closer(db, name, namelen);
	if (sd0 == NULL) {
		return NULL;
	}

#if DEBUG
	dolog(LOG_INFO, "next closer = %s\n", sd0->zonename);
#endif

	snprintf(wildcard, sizeof(wildcard), "*.%s", sd0->zonename);
	backname = dns_label(wildcard, &backnamelen);

	hashname = hash_name(backname, backnamelen, &n3p->nsec3param);
	if (hashname == NULL) {
		dolog(LOG_INFO, "unable to get hashname\n");
		free (sd0);
		return NULL;
	}

#if DEBUG
	dolog(LOG_INFO, "hashname  = %s\n", hashname);
#endif
	
	table = calloc(1, sizeof(struct domainnames));	
	if (table == NULL) {
		free (sd0);
		return (NULL);
	}

	dn = (struct domainnames *)table;
	strlcpy(dn->name, hashname, DNS_MAXNAME + 1);
	strlcpy(dn->next, ".", DNS_MAXNAME + 1);

	/* now go through our zone and find NSEC3 domains */
	/* first pass, count the NSEC3 list */	
	
	/* we need question for checklabel() */
	question = build_fake_question(sd->zone, sd->zonelen, 0);
	if (question == NULL) {
		dolog(LOG_INFO, "build_fake_question failed\n");
		free (sd0);
		return NULL;
	}

	count = count_nsec3_in_zone(db, sd, question);
	count++;	

	/* realloc names structure to fit the NSEC3 names */
	
	tmp = realloc(table, count * sizeof(struct domainnames));
	if (tmp == NULL) {
		dolog(LOG_INFO, "realloc: %s\n", strerror(errno));
		free_question(question);
		free (sd0);
		return NULL;	
	}
		
	table = tmp;
	dn = (struct domainnames *)tmp;
	dn++;

	/* second pass, fill NSEC3 list */

	if (db->cursor(db, NULL, &cursor, 0) != 0) {
		dolog(LOG_INFO, "find_nsec3 db->cursor: %s\n", strerror(errno));
		free_question(question);
		free (sd0);
		return NULL;
	}	

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	if (cursor->c_get(cursor, &key, &data, DB_FIRST) != 0) {
		dolog(LOG_INFO, "find_nsec3 cursor->c_get: %s\n", strerror(errno));
		free_question(question);
		free (sd0);
		return NULL;
	}

	i = 1;

	do {
		rs = data.size;
		if ((sd1 = calloc(1, rs)) == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			free_question(question);
			free (sd0);
			return NULL;
		}

		memcpy((char *)sd1, (char *)data.data, data.size);

		if (checklabel(db, sd1, sd, question) == 1) {
			if (sd1->flags & DOMAIN_HAVE_NSEC3) {
				strlcpy(dn->name, sd1->zonename, DNS_MAXNAME + 1);
				strlcpy(dn->next, "-", DNS_MAXNAME + 1);
				dn++;
			}
		}

		free (sd1);

		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));

	}  while (cursor->c_get(cursor, &key, &data, DB_NEXT) == 0);

	cursor->c_close(cursor);
	free_question(question);

	/* now we sort the shebang */
	qsort(table, count, sizeof(struct domainnames), nsec3_comp);

	dn = ((struct domainnames *)table); 
	if (strcmp(dn->next, ".") == 0)
		golast = 1;
	
	for (j = 0; j < count; j++) {
		dn = ((struct domainnames *)table) + j;
		
		if ((! golast) && (strcmp(dn->next, ".") == 0))
			break;
	}

	dn = ((struct domainnames *)table) + (j - 1);	
	
	/* found it, get it via db after converting it */	
	
	/* free what we don't need */
	free (sd0);
	
	dolog(LOG_INFO, "converting %s\n", dn->name);
	backname = dns_label(dn->name, &backnamelen);
	free (table);
	
	rs = get_record_size(db, backname, backnamelen);
	if (rs < 0) {
		free (backname);
		return (NULL);
	}

	if ((sd0 = calloc(1, rs)) == NULL) {
		free (backname);
		return (NULL);
	}

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));
	
	key.data = backname;
	key.size = backnamelen;

	data.data = NULL;
	data.size = rs;

	ret = db->get(db, NULL, &key, &data, 0);	
	if (ret != 0) {
		free (backname);
		free (sd0);
		return (NULL);
	}
	

	memcpy(sd0, data.data, data.size);
	free (backname);

	dolog(LOG_INFO, "returning %s\n", sd0->zonename);
	return (sd0);
}

/*
 * FIND_NSEC3_COVER_NEXT_CLOSER - finds the right nsec3 domainname in a zone 
 * 
 */
struct domain *
find_nsec3_cover_next_closer(char *name, int namelen, struct domain *sd, DB *db)
{
	struct domainnames {
		char name[DNS_MAXNAME + 1];
		char next[DNS_MAXNAME + 1];
	} *dn;

	DBC *cursor;
	DBT key, data;

	char *hashname;
	char *backname;
	char *table, *tmp;
	int backnamelen;
	int rs, ret;
	int i, j;
	int count;
	int golast = 0;
	struct domain *sd0, *sd1;
	struct domain_nsec3param *n3p;
	struct question *question;

	if ((n3p = find_substruct(sd, INTERNAL_TYPE_NSEC3PARAM)) == NULL) {
		return NULL;
	}

	/* first off find  the next closer record */
	sd0 = find_next_closer(db, name, namelen);
	if (sd0 == NULL) {
		return NULL;
	}

#if DEBUG
	dolog(LOG_INFO, "next closer = %s\n", sd0->zonename);
#endif

	hashname = hash_name(sd0->zone, sd0->zonelen, &n3p->nsec3param);
	if (hashname == NULL) {
		dolog(LOG_INFO, "unable to get hashname\n");
		free (sd0);
		return NULL;
	}

#if DEBUG
	dolog(LOG_INFO, "hashname  = %s\n", hashname);
#endif
	
	table = calloc(1, sizeof(struct domainnames));	
	if (table == NULL) {
		free (sd0);
		return (NULL);
	}

	dn = (struct domainnames *)table;
	strlcpy(dn->name, hashname, DNS_MAXNAME + 1);
	strlcpy(dn->next, ".", DNS_MAXNAME + 1);

	/* now go through our zone and find NSEC3 domains */
	/* first pass, count the NSEC3 list */	
	
	/* we need question for checklabel() */
	question = build_fake_question(sd->zone, sd->zonelen, 0);
	if (question == NULL) {
		dolog(LOG_INFO, "build_fake_question failed\n");
		free (sd0);
		return NULL;
	}

	count = count_nsec3_in_zone(db, sd, question);
	count++;	

	/* realloc names structure to fit the NSEC3 names */
	
	tmp = realloc(table, count * sizeof(struct domainnames));
	if (tmp == NULL) {
		dolog(LOG_INFO, "realloc: %s\n", strerror(errno));
		free_question(question);
		free (sd0);
		return NULL;	
	}
		
	table = tmp;
	dn = (struct domainnames *)tmp;
	dn++;

	/* second pass, fill NSEC3 list */

	if (db->cursor(db, NULL, &cursor, 0) != 0) {
		dolog(LOG_INFO, "find_nsec3 db->cursor: %s\n", strerror(errno));
		free_question(question);
		free (sd0);
		return NULL;
	}	

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	if (cursor->c_get(cursor, &key, &data, DB_FIRST) != 0) {
		dolog(LOG_INFO, "find_nsec3 cursor->c_get: %s\n", strerror(errno));
		free_question(question);
		free (sd0);
		return NULL;
	}

	i = 1;

	do {
		rs = data.size;
		if ((sd1 = calloc(1, rs)) == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			free_question(question);
			free (sd0);
			return NULL;
		}

		memcpy((char *)sd1, (char *)data.data, data.size);

		if (checklabel(db, sd1, sd, question) == 1) {
			if (sd1->flags & DOMAIN_HAVE_NSEC3) {
				strlcpy(dn->name, sd1->zonename, DNS_MAXNAME + 1);
				strlcpy(dn->next, "-", DNS_MAXNAME + 1);
				dn++;
			}
		}

		free (sd1);

		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));

	}  while (cursor->c_get(cursor, &key, &data, DB_NEXT) == 0);

	cursor->c_close(cursor);
	free_question(question);

	/* now we sort the shebang */
	qsort(table, count, sizeof(struct domainnames), nsec3_comp);

	dn = ((struct domainnames *)table); 
	if (strcmp(dn->next, ".") == 0)
		golast = 1;
	
	for (j = 0; j < count; j++) {
		dn = ((struct domainnames *)table) + j;
		
		if ((! golast) && (strcmp(dn->next, ".") == 0))
			break;
	}

	dn = ((struct domainnames *)table) + (j - 1);	
	
	/* found it, get it via db after converting it */	
	
	/* free what we don't need */
	free (sd0);
	
	dolog(LOG_INFO, "converting %s\n", dn->name);
	backname = dns_label(dn->name, &backnamelen);
	free (table);
	
	rs = get_record_size(db, backname, backnamelen);
	if (rs < 0) {
		free (backname);
		return (NULL);
	}

	if ((sd0 = calloc(1, rs)) == NULL) {
		free (backname);
		return (NULL);
	}

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));
	
	key.data = backname;
	key.size = backnamelen;

	data.data = NULL;
	data.size = rs;

	ret = db->get(db, NULL, &key, &data, 0);	
	if (ret != 0) {
		free (backname);
		free (sd0);
		return (NULL);
	}
	

	memcpy(sd0, data.data, data.size);
	free (backname);

	dolog(LOG_INFO, "returning %s\n", sd0->zonename);
	return (sd0);
}

/*
 * FIND_NSEC3_MATCH_QNAME - find the matching QNAME and return NSEC3
 *
 */

struct domain *
find_nsec3_match_qname(char *name, int namelen, struct domain *sd, DB *db)
{
	struct domainnames {
		char name[DNS_MAXNAME + 1];
		char next[DNS_MAXNAME + 1];
	} *dn;

	DBC *cursor;
	DBT key, data;

	char *hashname;
	char *backname;
	char *table, *tmp;
	int backnamelen;
	int rs, ret;
	int i, j;
	int count, hashnamelen;
	struct domain *sd0, *sd1;
	struct domain_nsec3param *n3p;
	struct question *question;

	if ((n3p = find_substruct(sd, INTERNAL_TYPE_NSEC3PARAM)) == NULL) {
		return NULL;
	}

	hashname = hash_name(name, namelen,  &n3p->nsec3param);
	if (hashname == NULL) {
		dolog(LOG_INFO, "unable to get hashname\n");
		return NULL;
	}

#if DEBUG
	dolog(LOG_INFO, "hashname  = %s\n", hashname);
#endif
	
	/* now go through our zone and find NSEC3 domains */
	/* first pass, count the NSEC3 list */	
	
	/* we need question for checklabel() */
	question = build_fake_question(sd->zone, sd->zonelen, 0);
	if (question == NULL) {
		dolog(LOG_INFO, "build_fake_question failed\n");
		return NULL;
	}

	count = count_nsec3_in_zone(db, sd, question);

	/* realloc names structure to fit the NSEC3 names */
	
	tmp = calloc(count, sizeof(struct domainnames));
	if (tmp == NULL) {
		dolog(LOG_INFO, "realloc: %s\n", strerror(errno));
		free_question(question);
		return NULL;	
	}
		
	table = tmp;
	dn = (struct domainnames *)tmp;

	/* second pass, fill NSEC3 list */

	if (db->cursor(db, NULL, &cursor, 0) != 0) {
		dolog(LOG_INFO, "find_nsec3 db->cursor: %s\n", strerror(errno));
		free_question(question);
		return NULL;
	}	

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	if (cursor->c_get(cursor, &key, &data, DB_FIRST) != 0) {
		dolog(LOG_INFO, "find_nsec3 cursor->c_get: %s\n", strerror(errno));
		free_question(question);
		return NULL;
	}

	i = 1;

	do {
		rs = data.size;
		if ((sd1 = calloc(1, rs)) == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			free_question(question);
			return NULL;
		}

		memcpy((char *)sd1, (char *)data.data, data.size);

		if (checklabel(db, sd1, sd, question) == 1) {
			if (sd1->flags & DOMAIN_HAVE_NSEC3) {
				strlcpy(dn->name, sd1->zonename, DNS_MAXNAME + 1);
				strlcpy(dn->next, "-", DNS_MAXNAME + 1);
				dn++;
			}
		}

		free (sd1);

		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));

	}  while (cursor->c_get(cursor, &key, &data, DB_NEXT) == 0);

	cursor->c_close(cursor);
	free_question(question);

	/* now we sort the shebang */
	qsort(table, count, sizeof(struct domainnames), nsec3_comp);

	hashnamelen = strlen(hashname);
	for (j = 0; j < count; j++) {
		dn = ((struct domainnames *)table) + j;
		
		if (strncasecmp(dn->name, hashname, hashnamelen) == 0)
			break;
	}

	if (j == count) {
		free(table);
		return NULL;
	}
		
	
	/* found it, get it via db after converting it */	
	
	dolog(LOG_INFO, "converting %s\n", dn->name);
	backname = dns_label(dn->name, &backnamelen);
	free (table);
	
	rs = get_record_size(db, backname, backnamelen);
	if (rs < 0) {
		free (backname);
		return (NULL);
	}

	if ((sd0 = calloc(1, rs)) == NULL) {
		free (backname);
		return (NULL);
	}

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));
	
	key.data = backname;
	key.size = backnamelen;

	data.data = NULL;
	data.size = rs;

	ret = db->get(db, NULL, &key, &data, 0);	
	if (ret != 0) {
		free (backname);
		free (sd0);
		return (NULL);
	}
	

	memcpy(sd0, data.data, data.size);
	free (backname);

	dolog(LOG_INFO, "returning %s\n", sd0->zonename);
	return (sd0);
}
