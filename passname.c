/*
 * Copyright (c) 2021 Peter J. Philipp <pjp@delphinusdns.org>
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
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>

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
#endif /* __linux__ */



#include "ddd-dns.h"
#include "ddd-db.h"

int	insert_tsigpassname(char *);
struct pnentry * have_tsigpassname(char *name, int namelen);
int tsigpassname_contains(char *origname, int origlen, int *wildcard);
int pncmp(struct pnentry *, struct pnentry *);

extern void 		dolog(int, char *, ...);
extern char * dns_label(char *, int *);
extern void ddd_shutdown(void);

extern int debug, verbose;

struct pntree pnhead = RB_INITIALIZER(&pnhead);
RB_GENERATE(pntree, pnentry, pn_entry, pncmp);

int
insert_tsigpassname(char *name)
{
	struct pnentry *pnep;
	int len;
	char *tmp;
	char *p = name;

	if (name[0] == '*' && name[1] == '.')
		p = &name[2];

	if (strlen(p) > DNS_MAXNAME) {
		dolog(LOG_INFO, "domainname too long\n");
		return -1;
	}	

	pnep = malloc(sizeof(struct pnentry));
	if (pnep == NULL) {
		dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
		return -1;
	}

	tmp = dns_label(p, &len);
	pnep->namelen = len;
	memcpy(pnep->name, tmp, len);
	free(tmp);
	
	pnep->humanname = strdup(name);
	if (pnep->humanname == NULL) {
		dolog(LOG_INFO, "strdup failed\n");
		return -1;
	}

	RB_INSERT(pntree, &pnhead, pnep);
	return (0);
}

struct pnentry *
have_tsigpassname(char *name, int len)
{
	struct pnentry find, *res;

	memcpy(find.name, name, len);
	find.namelen = len;
	if ((res = RB_FIND(pntree, &pnhead, &find)) != NULL) {
		return (res);
	}

	return NULL;
}

int
tsigpassname_contains(char *origname, int origlen, int *wildcard)
{
	char *p = origname;
	int plen = origlen;
	struct pnentry *res;

	for (; *p; plen--, p++) {
		if ((res = have_tsigpassname(p, plen)) != NULL)
			break;
		plen -= *p;
		p += *p;
	}

	if (res == NULL)
		return 0;

	if (res->wildcard == 1)
		*wildcard = 1;
	else
		*wildcard = 0;

	return 1;
}

int
pncmp(struct pnentry *e1, struct pnentry *e2)
{
	if (e1->namelen == e2->namelen)
		return (memcmp(e1->name, e2->name, e1->namelen));
	else if (e1->namelen < e2->namelen)
		return -1;	
	else
		return 1;
}
