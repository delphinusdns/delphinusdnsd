/* 
 * Copyright (c) 2002-2018 Peter J. Philipp
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
 * $Id: util.c,v 1.40 2019/10/30 12:14:36 pjp Exp $
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
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

#include "ddd-dns.h"
#include "ddd-db.h" 
#include "ddd-config.h"

/* prototypes */

int label_count(char *);
char * dns_label(char *, int *);
void slave_shutdown(void);
int get_record_size(ddDB *, char *, int);
struct rbtree * 	lookup_zone(ddDB *, struct question *, int *, int *, char *);
u_int16_t check_qtype(struct rbtree *, u_int16_t, int, int *);
struct question		*build_fake_question(char *, int, u_int16_t, char *, int);

char 			*get_dns_type(int, int);
int 			memcasecmp(u_char *, u_char *, int);
struct question		*build_question(char *, int, int, char *);
int			free_question(struct question *);
struct rrtab 	*rrlookup(char *);
char * expand_compression(u_char *, u_char *, u_char *, u_char *, int *, int);
void log_diff(char *sha256, char *mac, int len);
int tsig_pseudoheader(char *, uint16_t, time_t, HMAC_CTX *);

/* externs */

extern int debug;
extern int *ptr;
extern int tsig;

extern void 	dolog(int, char *, ...);

extern struct rbtree * create_rr(ddDB *db, char *name, int len, int type, void *rdata);
extern struct rbtree * find_rrset(ddDB *db, char *name, int len);
extern struct rrset * find_rr(struct rbtree *rbt, u_int16_t rrtype);
extern int add_rr(struct rbtree *rbt, char *name, int len, u_int16_t rrtype, void *rdata);
extern int display_rr(struct rrset *rrset);
extern int 	check_ent(char *, int);
extern int     find_tsig_key(char *, int, char *, int);


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
	{ NULL, 0}
};

static struct rrtab myrrtab[] =  { 
 { "a",         DNS_TYPE_A, 		DNS_TYPE_A } ,
 { "aaaa",      DNS_TYPE_AAAA,		DNS_TYPE_AAAA },
 { "cname",     DNS_TYPE_CNAME, 	DNS_TYPE_CNAME },
 { "delegate",  DNS_TYPE_NS, 		DNS_TYPE_NS },
 { "dnskey", 	DNS_TYPE_DNSKEY, 	DNS_TYPE_DNSKEY },
 { "ds", 	DNS_TYPE_DS, 		DNS_TYPE_DS },
 { "hint",      DNS_TYPE_HINT,		DNS_TYPE_NS }, 
 { "mx",        DNS_TYPE_MX, 		DNS_TYPE_MX },
 { "naptr", 	DNS_TYPE_NAPTR,		DNS_TYPE_NAPTR },
 { "ns",        DNS_TYPE_NS,		DNS_TYPE_NS },
 { "nsec", 	DNS_TYPE_NSEC, 		DNS_TYPE_NSEC },
 { "nsec3", 	DNS_TYPE_NSEC3,		DNS_TYPE_NSEC3 },
 { "nsec3param", DNS_TYPE_NSEC3PARAM,	DNS_TYPE_NSEC3PARAM },
 { "ptr",       DNS_TYPE_PTR,		DNS_TYPE_PTR },
 { "rrsig", 	DNS_TYPE_RRSIG, 	DNS_TYPE_RRSIG },
 { "soa",       DNS_TYPE_SOA, 		DNS_TYPE_SOA },
 { "srv",       DNS_TYPE_SRV, 		DNS_TYPE_SRV },
 { "sshfp", 	DNS_TYPE_SSHFP,		DNS_TYPE_SSHFP },
 { "tlsa", 	DNS_TYPE_TLSA,		DNS_TYPE_TLSA },
 { "txt",       DNS_TYPE_TXT,		DNS_TYPE_TXT },
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
 * LOOKUP_ZONE - look up a zone filling rbtree and returning RR TYPE, if error
 *		 occurs returns -1, and sets errno on what type of error.
 */


struct rbtree *
lookup_zone(ddDB *db, struct question *question, int *returnval, int *lzerrno, char *replystring)
{

	struct rbtree *rbt = NULL;
	struct rrset *rrset = NULL, *rrset2 = NULL;
	int plen, error;

	char *p;
	
	p = question->hdr->name;
	plen = question->hdr->namelen;

	*returnval = 0;
	/* if the find_rrset fails, the find_rr will not get questioned */
	if ((rbt = find_rrset(db, p, plen)) == NULL ||
		(rbt->dnssec && (rrset = find_rr(rbt, DNS_TYPE_NSEC3)) != NULL)) {
		if (check_ent(p, plen) == 1) {
			*lzerrno = ERR_NODATA;
			*returnval = -1;

			/* stop leakage */
			if (rrset != NULL)
				free(rbt);

			return NULL;
		}
	
		if (rrset != NULL)
			free(rbt);

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
					*lzerrno = ERR_DELEGATE;
					*returnval = -1;
					return (rbt);
				}
	
				free(rbt);
			}
		}
		*lzerrno = ERR_REFUSED;
		*returnval = -1;
		return (NULL);
	}
	
	snprintf(replystring, DNS_MAXNAME, "%s", rbt->humanname);

	if ((rrset = find_rr(rbt, DNS_TYPE_NS)) != NULL &&
		(rrset2 = find_rr(rbt, DNS_TYPE_SOA)) == NULL) {
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
	q->converted_name = NULL;

	/* fill our name into the dns header struct */
	
	memcpy(q->hdr->name, name, q->hdr->namelen);
	
	q->hdr->qtype = type;
	q->hdr->qclass = htons(DNS_CLASS_IN);

	if (tsig) {
		char *alg;
		int alglen;

		if (tsigkeylen > sizeof(q->tsig.tsigkey)) {
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

			q->tsig.tsigmaclen = 32;
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
	u_int namelen = 0;
	u_int16_t *qtype, *qclass;
	u_int32_t ttl;
	u_int64_t timefudge;
	int num_label;

	char *p, *end_name = NULL;

	struct dns_tsigrr *tsigrr = NULL;
	struct dns_optrr *opt = NULL;
	struct question *q = NULL;
	struct dns_header *hdr = (struct dns_header *)buf;

	/* find the end of name */
	for (i = sizeof(struct dns_header); i < len; i++) {
		/* XXX */
		if (buf[i] == 0) {
			end_name = &buf[i];			
			break;
		}
	}

	/* 
	 * implies i >= len , because end_name still points to NULL and not
	 * &buf[i]
	 */

	if (end_name == NULL) {
		dolog(LOG_INFO, "query name is not null terminated\n");
		return NULL;
	}

	/* parse the size of the name */
	for (i = sizeof(struct dns_header), num_label = 0; i < len && &buf[i] < end_name;) {
		u_int labellen;

		++num_label;
		
		labellen = (u_int)buf[i];	

		/* 
		 * do some checks on the label, if it's 0 or over 63 it's
		 * illegal, also if it reaches beyond the entire name it's
		 * also illegal.
		 */
		if (labellen == 0) {
			dolog(LOG_INFO, "illegal label len (0)\n");
			return NULL;
		}
		if (labellen > DNS_MAXLABEL) {
			dolog(LOG_INFO, "illegal label len (> 63)\n");
			return NULL;
		}
		if (labellen > (end_name - &buf[i])) {
			dolog(LOG_INFO, "label len extends beyond name\n");
			return NULL;
		}

		i += (labellen + 1);
		namelen += labellen;
	}
	
	if (&buf[i] != end_name || i >= len) {
		dolog(LOG_INFO, "query name is maliciously malformed\n");
		return NULL;
	}

	if (i > DNS_MAXNAME) {
		dolog(LOG_INFO, "query name is too long (%u)\n", i);
		return NULL;
	}

	
	/* check if there is space for qtype and qclass */
	if (len < ((end_name - &buf[0]) + (2 * sizeof(u_int16_t)))) {
		dolog(LOG_INFO, "question rr is truncated\n");
		return NULL;
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
	q->hdr->namelen = (end_name - &buf[sizeof(struct dns_header)]) + 1;	/* XXX */
	q->hdr->name = (void *) calloc(1, q->hdr->namelen);
	if (q->hdr->name == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		free(q->hdr);
		free(q);
		return NULL;
	}
	q->converted_name = (void *)calloc(1, namelen + num_label + 2);
	if (q->converted_name == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));	
		free(q->hdr->name);
		free(q->hdr);
		free(q);
		return NULL;
	}

	p = q->converted_name;

	/* 
	 * parse the name again this time filling the labels 
	 * XXX this is expensive going over the buffer twice
	 */
	for (i = sizeof(struct dns_header); i < len && &buf[i] < end_name;) {
		u_int labelend;


		/* check for compression */
		if ((buf[i] & 0xc0) == 0xc0) {
			dolog(LOG_INFO, "question has compressed name, drop\n");
			free_question(q);
			return NULL;	/* XXX should say error */
		}

		labelend = (u_int)buf[i] + 1 + i; /* i = offset, plus contents of buf[i], + 1 */

		/* 
 		 * i is reused here to count every character, this is not 
		 * a bug!
		 */

		for (i++; i < labelend; i++) {
			int c0; 

			c0 = buf[i];
			*p++ = tolower(c0);
		}

		*p++ = '.';
	}

	/* XXX */
	if (&buf[sizeof(struct dns_header)] == end_name) 
		*p++ = '.';

	*p = '\0';
	i += (2 * sizeof(u_int16_t)) + 1;	/* trailing NUL and type,class*/

	/* in IXFR an additional SOA entry is tacked on, we want to skip this */
	do {
		u_int16_t *val16;
		u_int32_t *val32;
		char *pb = NULL;
		char expand[DNS_MAXNAME + 1];
		int elen;

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
		val16 = (u_int16_t *)&buf[i];
		if (ntohs(*val16) != DNS_TYPE_SOA) {
			i = rollback;
			break;
		}
		i += 2;
		/* class */
		val16 = (u_int16_t *)&buf[i];
		if (ntohs(*val16) != DNS_CLASS_IN) {
			i = rollback;
			break;
		}
		i += 2;
		/* ttl */
		val32 = (u_int32_t *)&buf[i];
		i += 4;
		val16 = (u_int16_t *)&buf[i];
		i += 2;

		if (i + ntohs(*val16) > len) {	/* rdlen of SOA */
			i = rollback;
			break;
		}

		i += ntohs(*val16);	
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

		i += 11 + ntohs(opt->rdlen);
		// i += sizeof(struct dns_optrr);
		additional--;
	} while (0);
	/* check for TSIG rr */
	do {
		u_int16_t *val16, *tsigerror, *tsigotherlen;
		u_int16_t fudge;
		u_int32_t *val32;
		int elen, tsignamelen;
		char *pb;
		char expand[DNS_MAXNAME + 1];
		char tsigkey[512];
		u_char sha256[32];
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
			dolog(LOG_INFO, "expand_compression() failed\n");
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
		val16 = (u_int16_t *)&buf[i];
		if (ntohs(*val16) != DNS_TYPE_TSIG) {
			i = rollback;
			break;
		}
		i += 2;
		pseudolen2 = i;

		q->tsig.have_tsig = 1;

		/* we don't have any tsig keys configured, no auth done */
		if (tsig == 0) {
			i = rollback;
			break;
		}

		q->tsig.tsigerrorcode = DNS_BADKEY;

		/* class */
		val16 = (u_int16_t *)&buf[i];
		if (ntohs(*val16) != DNS_CLASS_ANY) {
			i = rollback;
			break;
		}
		i += 2;
	
		/* ttl */
		val32 = (u_int32_t *)&buf[i];	
		if (ntohl(*val32) != 0) {
			i = rollback;
			break;
		}
		i += 4;	
			
		/* rdlen */
		val16 = (u_int16_t *)&buf[i];
		if (ntohs(*val16) != (len - (i + 2))) {
			i = rollback;
			break;
		}
		i += 2;
		pseudolen3 = i;

		/* the algorithm name is parsed here */
		elen = 0;
		memset(&expand, 0, sizeof(expand));
		pb = expand_compression((u_char *)&buf[i], (u_char *)buf, (u_char *)&buf[len], (u_char *)&expand, &elen, sizeof(expand));
		if (pb == NULL) {
			free_question(q);
			dolog(LOG_INFO, "expand_compression() failed 2\n");
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

		if (ntohs(tsigrr->macsize) != 32) {
			q->tsig.tsigerrorcode = DNS_BADSIG; 
			break; 
		}

		i += ntohs(tsigrr->macsize);
	

		/* now get the MAC from packet with length rollback */
		NTOHS(hdr->additional);
		hdr->additional--;
		HTONS(hdr->additional);

		/* origid */
		val16 = (u_int16_t *)&buf[i];
		i += 2;
		if (hdr->id != *val16)
			hdr->id = *val16;
		q->tsig.tsigorigid = *val16;

		/* error */
		tsigerror = (u_int16_t *)&buf[i];
		i += 2;

		/* other len */
		tsigotherlen = (u_int16_t *)&buf[i];
		i += 2;

		ppoffset = 0;

		/* check if we have a request mac, this means it's an answer */
		if (mac) {
			val16 = (u_int16_t *)&pseudo_packet[ppoffset];
			*val16 = htons(32);	 /* XXX magic number */
			ppoffset += 2;

			memcpy(&pseudo_packet[ppoffset], mac, 32);
			ppoffset += 32;
		}

		memcpy(&pseudo_packet[ppoffset], buf, pseudolen1);
		ppoffset += pseudolen1;
		memcpy((char *)&pseudo_packet[ppoffset], &buf[pseudolen2], 6); 
		ppoffset += 6;

		memcpy((char *)&pseudo_packet[ppoffset], &buf[pseudolen3], pseudolen4 - pseudolen3);
		ppoffset += (pseudolen4 - pseudolen3);

		memcpy((char *)&pseudo_packet[ppoffset], (char *)&tsigrr->timefudge, 8); 
		ppoffset += 8;

		val16 = (u_int16_t *)&pseudo_packet[ppoffset];
		*val16 = *tsigerror;
		ppoffset += 2;

		val16 = (u_int16_t *)&pseudo_packet[ppoffset];
		*val16 = *tsigotherlen;
		ppoffset += 2;

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
		q->tsig.tsigmaclen = 32;
		
		/* we're now authenticated */
		q->tsig.tsigerrorcode = 0;
		q->tsig.tsigverified = 1;
		
	} while (0);

	/* fill our name into the dns header struct */
		
	memcpy(q->hdr->name, &buf[sizeof(struct dns_header)], q->hdr->namelen);
	
	/* make it lower case */

	for (i = 0; i < q->hdr->namelen; i++) {
		int c0;

		c0 = q->hdr->name[i];
		if (isalpha(c0)) {
			q->hdr->name[i] = tolower(c0);
		}
	}

	/* parse type and class from the question */

	qtype = (u_int16_t *)(end_name + 1);
	qclass = (u_int16_t *)(end_name + sizeof(u_int16_t) + 1);		

	memcpy((char *)&q->hdr->qtype, (char *)qtype, sizeof(u_int16_t));
	memcpy((char *)&q->hdr->qclass, (char *)qclass, sizeof(u_int16_t));

	/* make note of whether recursion is desired */
	q->rd = ((ntohs(hdr->query) & DNS_RECURSE) == DNS_RECURSE);

	/* are we a notify packet? */
	if ((ntohs(*qtype) == DNS_TYPE_SOA) && (ntohs(*qclass) == DNS_CLASS_IN))
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
	u_int16_t *offset;

	/* expand name */
	while ((u_char)*p && p <= end) {
		/* test for compression */
		if ((*p & 0xc0) == 0xc0) {
			/* do not allow recursive compress pointers */
			if (! save) {
				save = p + 2;
			}
			offset = (u_int16_t *)p;
			/* do not allow forwards jumping */
			if ((p - estart) <= (ntohs(*offset) & (~0xc000))) {
				return NULL;
			}

			p = (estart + (ntohs(*offset) & (~0xc000)));
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
	for (i = 0; i < 32; i++) {
		snprintf(tbuf, sizeof(tbuf), "%02x", sha256[i] & 0xff);	
		strlcat(buf, tbuf, sizeof(buf));
	}

	strlcat(buf, "\n", sizeof(buf));

	dolog(LOG_INFO, "our HMAC = %s\n", buf);

	memset(&buf, 0, sizeof(buf));
	for (i = 0; i < 32; i++) {
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

	int ppoffset = 0I;
	int len;

	uint16_t *type;
	uint32_t *ttl;

	keyname = dns_label(tsigkeyname, &len);
	if (keyname == NULL) {
		return -1;
	}

	/* name of key */
	memcpy(&pseudo_packet, keyname, len);
	ppoffset += len;	

	free(keyname);

	/* class */
	type = (u_int16_t *) &pseudo_packet[ppoffset];
	*type = htons(DNS_CLASS_ANY);
	ppoffset += 2;

	/* TTL */
	ttl = (u_int32_t *) &pseudo_packet[ppoffset];
	*ttl = htonl(0);
	ppoffset += 4;
		
	keyname = dns_label("hmac-sha256", &len);
	if (keyname == NULL) {
		return -1;
	}
	
	/* alg name */	
	memcpy(&pseudo_packet[ppoffset], keyname, len);
	ppoffset += len;

	free(keyname);

	/* time 1 and 2 */
	now = time(NULL);
	type = (u_int16_t *)&pseudo_packet[ppoffset];	
	*type = htons((now >> 32) & 0xffff);
	ppoffset += 2;

	ttl = (u_int32_t *)&pseudo_packet[ppoffset];
	*ttl = htonl((now & 0xffffffff));
	ppoffset += 4;
	
	/* fudge */
	type = (u_int16_t *)&pseudo_packet[ppoffset];	
	*type = htons(fudge);
	ppoffset += 2;

	/* error */

	type = (u_int16_t *)&pseudo_packet[ppoffset];	
	*type = htons(0);
	ppoffset += 2;

	/* other len */
	
	type = (u_int16_t *)&pseudo_packet[ppoffset];	
	*type = htons(0);
	ppoffset += 2;

	HMAC_Update(ctx, pseudo_packet, ppoffset);

	return 0;
}
