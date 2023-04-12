/*
 * Copyright (c) 2020-2023 Peter J. Philipp <pbug44@delphinusdns.org>
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

void	init_zone(void);
int	insert_zone(char *);
int have_zone(char *zonename, int zonelen);
void populate_zone(ddDB *db);
void repopulate_zone(ddDB *db, char *zonename, int zonelen);
int zonecmp(struct zoneentry *, struct zoneentry *);
struct zoneentry * zone_findzone(struct rbtree *);
void delete_zone(char *name, int len);

extern void 		dolog(int, char *, ...);
extern char * dns_label(char *, int *);
extern void ddd_shutdown(void);
extern int dn_contains(char *name, int len, char *anchorname, int alen);
extern uint32_t match_zoneglue(struct rbtree *);

extern int debug, verbose;
extern uint32_t zonenumber;

struct zonetree zonehead = RB_INITIALIZER(&zonehead);
RB_GENERATE(zonetree, zoneentry, zone_entry, zonecmp);

struct walkentry *we1, *wep;


void
delete_zone(char *name, int len)
{
	struct zoneentry *res, find;

	memcpy(find.name, name, len);
	find.namelen = len;

	if ((res = RB_FIND(zonetree, &zonehead, &find)) == NULL) {
		return;
	}

	TAILQ_FOREACH_SAFE(wep, &res->walkhead, walk_entry, we1) {
		TAILQ_REMOVE(&res->walkhead, wep, walk_entry);
		free(wep);
	}
	RB_REMOVE(zonetree, &zonehead, res);
	free (res);

	return;
}

int
insert_zone(char *zonename)
{
	struct zoneentry *zep, *res, find;
	int len;
	char *tmp;

	if (strlen(zonename) > DNS_MAXNAME) {
		dolog(LOG_INFO, "zonename too long\n");
		return -1;
	}	

	tmp = dns_label(zonename, &len);
	if (tmp == NULL) {
		return -1;
	}

	memcpy(find.name, tmp, len);
	find.namelen = len;

	if ((res = RB_FIND(zonetree, &zonehead, &find)) != NULL) {
		return 0;
	}

	/* we didn't already find a zone entry, make a new one */

	zep = malloc(sizeof(struct zoneentry));
	if (zep == NULL) {
		dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
		return -1;
	}

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

	RB_FOREACH(walk, domaintree, &db->head) {
		rbt = (struct rbtree *)walk->data;	
		if (rbt == NULL) {
			continue;
		}

		res = NULL;
		for (plen = rbt->zonelen, p = rbt->zone; plen > 0; 
								p++, plen--) {
			memcpy(find.name, p, plen);
			find.namelen = plen;
			if ((res = RB_FIND(zonetree, &zonehead, &find)) != NULL) {
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
		/* wep->zonenumber = res->zonenumber; */
		TAILQ_INSERT_TAIL(&res->walkhead, wep, walk_entry);

		/* there is a parent zone that has another entry */
		if (match_zoneglue(rbt)) {
			res = NULL;

			plen -= *p;	/* advance to higher parent */
			p += *p;

			for (p++, plen--; plen > 0; p++, plen--) {
				memcpy(find.name, p, plen);
				find.namelen = plen;
				if ((res = RB_FIND(zonetree, &zonehead, &find)) != NULL) {
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

void
repopulate_zone(ddDB *db, char *zonename, int zonelen)
{
	struct node *walk;
	struct zoneentry find, *res;
	struct rbtree *rbt = NULL;
	char *p;
	int plen;

	RB_FOREACH(walk, domaintree, &db->head) {
		rbt = (struct rbtree *)walk->data;	
		if (rbt == NULL) {
			continue;
		}

		res = NULL;
		for (plen = rbt->zonelen, p = rbt->zone; plen > 0; 
								p++, plen--) {
			memcpy(find.name, p, plen);
			find.namelen = plen;
			if ((res = RB_FIND(zonetree, &zonehead, &find)) != NULL) {
				break;
			}

			plen -= *p;
			p += *p;
		}

		if (res == NULL)
			continue;

		if (! dn_contains(rbt->zone, rbt->zonelen, zonename, zonelen))
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
		/* wep->zonenumber = res->zonenumber; */
		TAILQ_INSERT_TAIL(&res->walkhead, wep, walk_entry);

		/* there is a parent zone that has another entry */
		if (match_zoneglue(rbt)) {
			res = NULL;

			plen -= *p;	/* advance to higher parent */
			p += *p;

			for (p++, plen--; plen > 0; p++, plen--) {
				memcpy(find.name, p, plen);
				find.namelen = plen;
				if ((res = RB_FIND(zonetree, &zonehead, &find)) != NULL) {
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
