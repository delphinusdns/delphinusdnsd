/* 
 * Copyright (c) 2002-2016 Peter J. Philipp
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
#include "ddd-include.h"
#include "ddd-dns.h"
#include "ddd-db.h" 
#include "config.h"

/* prototypes */


char * dns_label(char *, int *);
void slave_shutdown(void);
int get_record_size(DB *, char *, int);
void * find_substruct(struct domain *, u_int16_t);

extern void 	dolog(int, char *, ...);

/* externs */

extern int debug;
extern int *ptr;

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
	char tname[DNS_MAXNAME + 1];	/* 255 bytes  + 1*/
	char *pt = &tname[0];


	if (name == NULL) 
		return NULL;

#if __linux__
	strncpy(tname, name, sizeof(tname));
	tname[sizeof(tname) - 1] = 0;
#else
	strlcpy(tname, name, sizeof(tname));
#endif

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

	*returnlen = newlen + 1;
	dnslabel[newlen] = '\0';	/* trailing NULL */

	for (i = 0, p = dnslabel; i < lc; i++) {
		len = strlen(labels[i]);
		*p++ = len;
#if __linux__
		/* XXX */
		strncpy(p, labels[i], newlen - (p - dnslabel) + 1);
		p[newlen - (p - dnslabel)] = 0;
#else
		strlcpy(p, labels[i], newlen - (p - dnslabel) + 1);
#endif
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

	if (debug)
		dolog(LOG_DEBUG, "converting name= %s\n", name);

	return dnslabel;
}
/*
 * slave_shutdown - a slave wishes to shutdown, enter its pid into the 
 *			shutdown shared memory and return.
 */

void
slave_shutdown(void)
{
	pid_t pid;

	pid = getpid();

	*ptr = pid;
}


/*
 * GET_RECORD_SIZE - get the record size of a record
 */

int 
get_record_size(DB *db, char *converted_name, int converted_namelen)
{
	struct domain *sdomain;
	DBT key, data;
	int ret;

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	key.data = (char *)converted_name;
	key.size = converted_namelen;

	data.data = NULL;
	data.size = sizeof(struct domain);

	if ((ret = db->get(db, NULL, &key, &data, 0)) == 0) {
		sdomain = (struct domain *)data.data;
		return (sdomain->len);
	} else {
		if (debug && ret != DB_NOTFOUND )
			dolog(LOG_INFO, "db->get: %s\n", strerror(errno));
	}

	return sizeof(struct domain);
}

/*
 * FIND_SUBSTRUCT - find the substruct of a record
 *
 */

void *
find_substruct(struct domain *ssd, u_int16_t type)
{
	struct domain_generic *sdg = NULL;
	void *ptr = NULL;
	void *vssd = (void *)ssd;

	switch (type) {
	case INTERNAL_TYPE_SOA:
		if (! (ssd->flags & DOMAIN_HAVE_SOA))
			return NULL;
		break;
	case INTERNAL_TYPE_A:
		if (! (ssd->flags & DOMAIN_HAVE_A))
			return NULL;
		break;
	case INTERNAL_TYPE_AAAA:
		if (! (ssd->flags & DOMAIN_HAVE_AAAA))
			return NULL;
		break;
	case INTERNAL_TYPE_MX:
		if (! (ssd->flags & DOMAIN_HAVE_MX))
			return NULL;
		break;
	case INTERNAL_TYPE_NS:
		if (! (ssd->flags & DOMAIN_HAVE_NS))
			return NULL;
		break;
	case INTERNAL_TYPE_CNAME:
		if (! (ssd->flags & DOMAIN_HAVE_CNAME))
			return NULL;
		break;
	case INTERNAL_TYPE_PTR:
		if (! (ssd->flags & DOMAIN_HAVE_PTR))
			return NULL;
		break;
	case INTERNAL_TYPE_TXT:
		if (! (ssd->flags & DOMAIN_HAVE_TXT))
			return NULL;
		break;
	case INTERNAL_TYPE_SPF:
		if (! (ssd->flags & DOMAIN_HAVE_SPF))
			return NULL;
		break;
	case INTERNAL_TYPE_SRV:
		if (! (ssd->flags & DOMAIN_HAVE_SRV))
			return NULL;
		break;
	case INTERNAL_TYPE_TLSA:
		if (! (ssd->flags & DOMAIN_HAVE_TLSA))
			return NULL;
		break;
	case INTERNAL_TYPE_SSHFP:
		if (! (ssd->flags & DOMAIN_HAVE_SSHFP))
			return NULL;
		break;
	case INTERNAL_TYPE_NAPTR:
		if (! (ssd->flags & DOMAIN_HAVE_NAPTR))
			return NULL;
		break;
	case INTERNAL_TYPE_DNSKEY:
		if (! (ssd->flags & DOMAIN_HAVE_DNSKEY))
			return NULL;
		break;
	case INTERNAL_TYPE_DS:
		if (! (ssd->flags & DOMAIN_HAVE_DS))
			return NULL;
		break;
	case INTERNAL_TYPE_NSEC3PARAM:
		if (! (ssd->flags & DOMAIN_HAVE_NSEC3PARAM))
			return NULL;
		break;
	case INTERNAL_TYPE_NSEC3:
		if (! (ssd->flags & DOMAIN_HAVE_NSEC3))
			return NULL;
		break;
	case INTERNAL_TYPE_NSEC:
		if (! (ssd->flags & DOMAIN_HAVE_NSEC))
			return NULL;
		break;
	case INTERNAL_TYPE_RRSIG:
		if (! (ssd->flags & DOMAIN_HAVE_RRSIG))
			return NULL;
		break;
	default:
		return NULL;
		break;
	}
	
	for (ptr = (void *)(vssd + sizeof(struct domain)); \
		ptr <= (void *)(vssd + ssd->len); \
		ptr += sdg->len) {
		sdg = (struct domain_generic *)ptr;
		if (type == sdg->type) {
			return (ptr);
		}
	}

	return NULL;
}
