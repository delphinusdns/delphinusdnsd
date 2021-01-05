/*
 * Copyright (c) 2020 Peter J. Philipp
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

void	init_zone(void);
int	insert_zone(char *);
int have_zone(char *zonename, int zonelen);
void populate_zone(ddDB *db);
int zonecmp(struct zoneentry *, struct zoneentry *);
struct zoneentry * zone_findzone(struct rbtree *);

extern void 		dolog(int, char *, ...);
extern char * dns_label(char *, int *);
extern void ddd_shutdown(void);
extern int dn_contains(char *name, int len, char *anchorname, int alen);
extern uint32_t match_zonenumber(struct rbtree *, uint32_t);

extern int debug, verbose;
extern uint32_t zonenumber;

struct zonetree zonehead = RB_INITIALIZER(&zonehead);
RB_GENERATE(zonetree, zoneentry, zone_entry, zonecmp);

int
insert_zone(char *zonename)
{
	struct zoneentry *zep;
	int len;
	char *tmp;

	if (strlen(zonename) > DNS_MAXNAME) {
		dolog(LOG_INFO, "zonename too long\n");
		return -1;
	}	

	zep = malloc(sizeof(struct zoneentry));
	if (zep == NULL) {
		dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
		return -1;
	}

	tmp = dns_label(zonename, &len);
	zep->namelen = len;
	memcpy(zep->name, tmp, len);
	free(tmp);
	
	zep->humanname = strdup(zonename);
	if (zep->humanname == NULL) {
		dolog(LOG_INFO, "strdup failed\n");
		return -1;
	}
	zep->zonenumber = zonenumber;

	TAILQ_INIT(&zep->walkhead);

	RB_INSERT(zonetree, &zonehead, zep);
	return (0);
}

void
populate_zone(ddDB *db)
{
	struct node *walk;
	struct zoneentry find, *res;
	struct rbtree *rbt = NULL;
	char *p;
	int plen;
	uint32_t i;


	for (i = 0; i < zonenumber; i++) {
		RB_FOREACH(walk, domaintree, &db->head) {
			rbt = (struct rbtree *)walk->data;	
			if (rbt == NULL) {
				continue;
			}

			if (match_zonenumber(rbt, i) == 0)
				continue;

			res = NULL;
			for (plen = rbt->zonelen, p = rbt->zone; plen > 0; 
									p++, plen--) {
				memcpy(find.name, p, plen);
				find.namelen = plen;
				if (((res = RB_FIND(zonetree, &zonehead, &find)) != NULL) &&
					(i == res->zonenumber)) {
					break;
				}

				plen -= *p;
				p += *p;
			}

			if (res == NULL)
				continue;

			TAILQ_FOREACH(wep, &res->walkhead, walk_entry) {
				if (wep->rbt == rbt)
					break;
			}

			if (wep)
				continue;

			if ((wep = malloc(sizeof(struct walkentry))) == NULL) {
				dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
				ddd_shutdown();
				sleep(10);
				exit(1);
			}
				
			wep->rbt = rbt;
			TAILQ_INSERT_TAIL(&res->walkhead, wep, walk_entry);
		}
	}
}

int
have_zone(char *zonename, int zonelen)
{
	struct zoneentry find, *res;

	memcpy(find.name, zonename, zonelen);
	find.namelen = zonelen;
	if ((res = RB_FIND(zonetree, &zonehead, &find)) != NULL) {
		return 1;
	}

	return 0;
}

int
zonecmp(struct zoneentry *e1, struct zoneentry *e2)
{
	if (e1->namelen == e2->namelen)
		return (memcmp(e1->name, e2->name, e1->namelen));
	else if (e1->namelen < e2->namelen)
		return -1;	
	else
		return 1;
}

/*
 * ZONE_FINDZONE - find the closest zonenumber and return its zoneentry or NULL
 *
 */

struct zoneentry *
zone_findzone(struct rbtree *rbt)
{
	struct zoneentry find, *res;
	char *p;
	int plen;

	/* find the corresponding zone for the zone number */
	for (plen = rbt->zonelen, p = rbt->zone; plen > 0; p++, plen--) {
		memcpy(find.name, p, plen);
		find.namelen = plen;

		if ((res = RB_FIND(zonetree, &zonehead, &find)) != NULL) {
			return (res);
		}
		plen -= *p;
		p += *p;
	}

	return (NULL);
}
