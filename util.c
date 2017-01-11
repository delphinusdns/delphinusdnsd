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
#include "ddd-config.h"

/* prototypes */


int label_count(char *);
char * dns_label(char *, int *);
void slave_shutdown(void);
int get_record_size(DB *, char *, int);
void * find_substruct(struct domain *, u_int16_t);
struct domain * 	lookup_zone(DB *, struct question *, int *, int *, char *);
u_int16_t check_qtype(struct domain *, u_int16_t, int, int *);
struct question		*build_fake_question(char *, int, u_int16_t);

extern void 	dolog(int, char *, ...);
char 			*get_dns_type(int, int);
int 			memcasecmp(u_char *, u_char *, int);

/* externs */

extern int debug;
extern int *ptr;

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
	{ "SPF", DNS_TYPE_SPF },
	{ "SSHFP", DNS_TYPE_SSHFP },
	{ "NAPTR", DNS_TYPE_NAPTR },
	{ "RRSIG", DNS_TYPE_RRSIG },
	{ "DNSKEY", DNS_TYPE_DNSKEY },
	{ "NSEC", DNS_TYPE_NSEC },
	{ "DS", DNS_TYPE_DS },
	{ "NSEC3", DNS_TYPE_NSEC3 },
	{ "NSEC3PARAM", DNS_TYPE_NSEC3PARAM },
	{ "TLSA", DNS_TYPE_TLSA },
	{ NULL, 0}
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

	*returnlen = newlen + 1;
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


/*
 * LOOKUP_ZONE - look up a zone filling sd and returning RR TYPE, if error
 *		 occurs returns -1, and sets errno on what type of error.
 */


struct domain *
lookup_zone(DB *db, struct question *question, int *returnval, int *lzerrno, char *replystring)
{

	struct domain *sd = NULL;
	struct domain_ns *nsd;
	int plen, onemore = 0;
	int ret = 0;
	int error;
	int w = 0;
	int rs;

	char *p;
	
	DBT key, data;

	p = question->hdr->name;
	plen = question->hdr->namelen;
	onemore = 0;


	rs = get_record_size(db, p, plen);
	if (rs < 0) {
		*lzerrno = ERR_DROP;
		*returnval = -1;
		return (NULL);
	}
	if ((sd = (struct domain *)calloc(1, rs)) == NULL) {
		*lzerrno = ERR_DROP; /* only free on ERR_DROP */
		*returnval = -1;
		return (NULL);	
	}

	*returnval = 0;

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	key.data = (char *)p;
	key.size = plen;

	data.data = NULL;
	data.size = rs;

	ret = db->get(db, NULL, &key, &data, 0);
	if (ret != 0) {
nsec3:
		/*
		 * We have a condition where a record does not exist but we
		 * move toward the apex of the record, and there may be 
		 * something.  We return NXDOMAIN if there is an apex with 
		 * SOA if not then we return REFUSED 
		 */
		while (*p != 0) {
			plen -= (*p + 1);
			p = (p + (*p + 1));

			free(sd);
			rs = get_record_size(db, p, plen);
			if (rs < 0) {
				*lzerrno = ERR_DROP;
				*returnval = -1;
				return (NULL);
			}
			if ((sd = (struct domain *)calloc(1, rs)) == NULL) {
				*lzerrno = ERR_DROP; /* only free on ERR_DROP */
				*returnval = -1;
				return (NULL);	
			}

			memset(&key, 0, sizeof(key));
			memset(&data, 0, sizeof(data));

			key.data = (char *)p;
			key.size = plen;

			data.data = NULL;
			data.size = rs;

			ret = db->get(db, NULL, &key, &data, 0);
			if (ret == 0)
				memcpy((char *)sd, (char *)data.data, data.size);
			if (ret == 0 && (sd->flags & DOMAIN_HAVE_SOA)) {
				*lzerrno = ERR_NXDOMAIN;
				*returnval = -1;
				return (sd);
			}
		}
		*lzerrno = ERR_REFUSED;
		*returnval = -1;
		return (sd);
	}
	
	if (data.size != rs) {
		dolog(LOG_INFO, "btree db is damaged, drop\n");
		free(sd);
		sd = NULL;
		*lzerrno = ERR_DROP;	/* free on ERR_DROP */
		*returnval = -1;
		return (NULL);
	}

	memcpy((char *)sd, (char *)data.data, data.size);
	snprintf(replystring, DNS_MAXNAME, "%s", sd->zonename);


	if (sd->flags & DOMAIN_HAVE_NS) {
		nsd = (struct domain_ns *)find_substruct(sd, INTERNAL_TYPE_NS);
		if (w && nsd->ns_type == 0) {	
			*lzerrno = ERR_NXDOMAIN;
			*returnval = -1;
			return (sd);
		}

		/*
		 * we're of ns_type > 0, return an NS record
		 */

		if (nsd->ns_type > 0) {
			*returnval = DNS_TYPE_NS;
			*lzerrno = ERR_NOERROR;
			goto out;
		}
	} else if (sd->flags & DOMAIN_HAVE_NSEC3) {
		goto nsec3;
	}

	*returnval = check_qtype(sd, ntohs(question->hdr->qtype), 0, &error);
	if (*returnval == 0) {
		*lzerrno = ERR_NOERROR;
		*returnval = -1;
		return (sd);
	}

out:
	return(sd);
}

/*
 * CHECK_QTYPE - check the query type and return appropriately if we have 
 *		 such a record in our DB..
 *		 returns 0 on error, or the DNS TYPE from 1 through 65535
 * 		 when the return is 0 the error variable is set with the error
 *		 code (-1 or -2)
 */

u_int16_t
check_qtype(struct domain *sd, u_int16_t type, int nxdomain, int *error)
{
	u_int16_t returnval;

	switch (type) {

	case DNS_TYPE_ANY:
			returnval = DNS_TYPE_ANY;
			break;

	case DNS_TYPE_A:
		if ((sd->flags & DOMAIN_HAVE_A) == DOMAIN_HAVE_A)  {
			returnval = DNS_TYPE_A;
			break;
		} else if ((sd->flags & DOMAIN_HAVE_CNAME) == 						DOMAIN_HAVE_CNAME) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_AAAA:
		if ((sd->flags & DOMAIN_HAVE_AAAA) == DOMAIN_HAVE_AAAA)  {
			returnval = DNS_TYPE_AAAA;
			break;
		} else if ((sd->flags & DOMAIN_HAVE_CNAME) == 						DOMAIN_HAVE_CNAME) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_MX:
		if ((sd->flags & DOMAIN_HAVE_MX) == 
				DOMAIN_HAVE_MX)  {
			returnval = DNS_TYPE_MX;
			break;
		} else if ((sd->flags & DOMAIN_HAVE_CNAME) == 						DOMAIN_HAVE_CNAME) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_PTR:
		if ((sd->flags & DOMAIN_HAVE_PTR) == DOMAIN_HAVE_PTR)  {
			returnval = DNS_TYPE_PTR;
			break;
		} else if ((sd->flags & DOMAIN_HAVE_CNAME) == 						DOMAIN_HAVE_CNAME) {
			returnval = DNS_TYPE_CNAME;
			break;
		}

		*error = -1;
		return 0;

	case DNS_TYPE_SOA:
		if ((sd->flags & DOMAIN_HAVE_SOA) == DOMAIN_HAVE_SOA) {

			returnval = DNS_TYPE_SOA;
			break;
		}

		if (nxdomain)
			*error = -2;
		else
			*error = -1;

		return 0;

	case DNS_TYPE_TLSA:
		if ((sd->flags & DOMAIN_HAVE_TLSA) == DOMAIN_HAVE_TLSA) {
			returnval = DNS_TYPE_TLSA;
			break;
		}

		*error = -1;
		return 0;

	case DNS_TYPE_SSHFP:
		if ((sd->flags & DOMAIN_HAVE_SSHFP) == DOMAIN_HAVE_SSHFP) {
			returnval = DNS_TYPE_SSHFP;
			break;
		}

		*error = -1;
		return 0;

	case DNS_TYPE_SRV:	
		if ((sd->flags & DOMAIN_HAVE_SRV) == DOMAIN_HAVE_SRV) {
			returnval = DNS_TYPE_SRV;
			break;
		}

		*error = -1;
		return 0;

	case DNS_TYPE_NAPTR:
		if ((sd->flags & DOMAIN_HAVE_NAPTR) == DOMAIN_HAVE_NAPTR) {
				returnval = DNS_TYPE_NAPTR;
				break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_CNAME:
		if ((sd->flags & DOMAIN_HAVE_CNAME) == DOMAIN_HAVE_CNAME) {
				returnval = DNS_TYPE_CNAME;
				break;
		}

		*error = -1;
		return 0;

	case DNS_TYPE_NS:
		if ((sd->flags & DOMAIN_HAVE_NS) == DOMAIN_HAVE_NS) {
			returnval = DNS_TYPE_NS;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_TXT:
		if ((sd->flags & DOMAIN_HAVE_TXT) == DOMAIN_HAVE_TXT)  {
			returnval = DNS_TYPE_TXT;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_SPF:
		if ((sd->flags & DOMAIN_HAVE_SPF) == DOMAIN_HAVE_SPF)  {
			returnval = DNS_TYPE_SPF;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_RRSIG:
		if ((sd->flags & DOMAIN_HAVE_RRSIG) == DOMAIN_HAVE_RRSIG)  {
			returnval = DNS_TYPE_RRSIG;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_NSEC3PARAM:
		if ((sd->flags & DOMAIN_HAVE_NSEC3PARAM) == DOMAIN_HAVE_NSEC3PARAM)  {
			returnval = DNS_TYPE_NSEC3PARAM;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_NSEC3:
		if ((sd->flags & DOMAIN_HAVE_NSEC3) == DOMAIN_HAVE_NSEC3)  {
			returnval = DNS_TYPE_NSEC3;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_NSEC:
		if ((sd->flags & DOMAIN_HAVE_NSEC) == DOMAIN_HAVE_NSEC)  {
			returnval = DNS_TYPE_NSEC;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_DS:
		if ((sd->flags & DOMAIN_HAVE_DS) == DOMAIN_HAVE_DS)  {
			returnval = DNS_TYPE_DS;
			break;
		}

		*error = -1;
		return 0;
	case DNS_TYPE_DNSKEY:
		if ((sd->flags & DOMAIN_HAVE_DNSKEY) == DOMAIN_HAVE_DNSKEY)  {
			returnval = DNS_TYPE_DNSKEY;
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
build_fake_question(char *name, int namelen, u_int16_t type)
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
	q->converted_name = NULL;

	/* fill our name into the dns header struct */
	
	memcpy(q->hdr->name, name, q->hdr->namelen);
	
	q->hdr->qtype = type;
	q->hdr->qclass = htons(DNS_CLASS_IN);

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
