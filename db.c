/*
 * Copyright (c) 2017-2021 Peter J. Philipp <pjp@delphinusdns.org>
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
#include <time.h>
#include <syslog.h>

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

struct rbtree * create_rr(ddDB *, char *, int, int, void *, uint32_t, uint16_t);
struct rbtree * find_rrset(ddDB *db, char *name, int len);
struct rrset * find_rr(struct rbtree *rbt, u_int16_t rrtype);
int add_rr(struct rbtree *rbt, char *name, int len, u_int16_t rrtype, void *rdata);
int display_rr(struct rrset *rrset);
int rotate_rr(struct rrset *rrset);
void flag_rr(struct rbtree *rbt, uint32_t flag);
int expire_rr(ddDB *, char *, int, u_int16_t, time_t);
int expire_db(ddDB *, int);
void remove_rbt(struct rbtree *);
uint32_t match_zoneglue(struct rbtree *rbt);

extern void      dolog(int, char *, ...);

extern uint32_t zonenumber;
extern char * convert_name(char *, int);
int domaincmp(struct node *e1, struct node *e2);



int
domaincmp(struct node *e1, struct node *e2)
{
	if (e1->len < e2->len)
		return -1;
	else if (e1->len > e2->len)
		return 1;
	else {
        	return (memcmp(e1->domainname, e2->domainname, e1->len));
	}
}


ddDB *
dddbopen(void)
{
	ddDB *db;

	db = calloc(1, sizeof(ddDB));
	if (db == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	db->put = dddbput;
	db->get = dddbget;
	db->close = dddbclose;
	db->offset = 0;

	RB_INIT(&db->head);
		
	return (db);
}

int
dddbput(ddDB *db, ddDBT *key, ddDBT *data)
{
	struct node find, *n, *res;

	strlcpy(find.domainname, key->data, sizeof(find.domainname));
	find.len = key->size;

	res = RB_FIND(domaintree, &db->head, &find);
	if (res == NULL) {
		/* does not exist, create it */
		n = calloc(sizeof(struct node), 1);
		if (n == NULL) {
			return -1;
		}
		n->len = key->size;
		memcpy(n->domainname, key->data, n->len);
		n->data = data->data;
		n->datalen = data->size;

		RB_INSERT(domaintree, &db->head, n);
	} else {
		if (res->datalen != data->size)
			return -1;

		if (res->data != data->data) {
			remove_rbt((struct rbtree *)res->data);
		}

		res->data = data->data;
		RB_REMOVE(domaintree, &db->head, res);
		RB_INSERT(domaintree, &db->head, res);
	}

	return 0;
}

int
dddbget(ddDB *db, ddDBT *key, ddDBT *data)
{
	struct node find, *res;
	
	memset(&find, 0, sizeof(struct node));
	strlcpy(find.domainname, key->data, sizeof(find.domainname));
	find.len = key->size;

	res = RB_FIND(domaintree, &db->head, &find);
	if (res == NULL) {
		return -1;
	}

	data->size = res->datalen;
	data->data = res->data;

	return 0;
}

int
dddbclose(ddDB *db)
{
	free (db);
	return 0;
}

struct rbtree *
create_rr(ddDB *db, char *name, int len, int type, void *rdata, uint32_t ttl, uint16_t rdlen)
{
	ddDBT key, data;
	struct rbtree *rbt = NULL;
	struct rrset *rrset = NULL;
	struct rr *myrr = NULL;
	char *humanname = NULL;

	rbt = find_rrset(db, name, len);
	if (rbt == NULL) {
		rbt = (struct rbtree *) calloc(1, sizeof(struct rbtree));
		if (! rbt) {
			perror("calloc");
			return NULL;
		}

		strlcpy(rbt->zone, name, sizeof(rbt->zone));
		rbt->zonelen = len;
		humanname = convert_name(name, len);
		strlcpy(rbt->humanname, humanname, sizeof(rbt->humanname));
		rbt->flags &= ~RBT_DNSSEC;	 /* by default not dnssec'ed */

		TAILQ_INIT(&rbt->rrset_head);

		/* rb insert too */
		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));

		key.data = (char *)name;
		key.size = len;

		data.data = (void *)rbt;
		data.size = sizeof(struct rbtree);

		db->put(db, &key, &data);
	}
	
	rrset = find_rr(rbt, type);
	if (rrset == NULL) {
		rrset = (struct rrset *)calloc(1, sizeof(struct rrset));
		if (! rrset){
			perror("calloc");
			return NULL;
		}

		rrset->rrtype = type;
		if (type != DNS_TYPE_RRSIG) 
			rrset->ttl = ttl;
		else
			rrset->ttl = 0;		/* fill in later */

		rrset->created = time(NULL);

		TAILQ_INIT(&rrset->rr_head);
		TAILQ_INSERT_TAIL(&rbt->rrset_head, rrset, entries);
	} else
		rrset->created = time(NULL);

	/* this sets up the RR */

	myrr = (struct rr *)calloc(1, sizeof(struct rr));
	if (! myrr) {
		perror("calloc");
		return NULL;
	}

	switch (type) {
	case DNS_TYPE_A:
		myrr->rdata = (struct a *)rdata;
		break;
	default:
		myrr->rdata = rdata;
		break;
	}
	myrr->changed = time(NULL);
	myrr->rdlen = rdlen;
	myrr->zonenumber = zonenumber - 1;          /* needed for glued ns */

	rrset->ttl = ttl;

	if (type == DNS_TYPE_RRSIG) {
		struct rrsig *rrsig = (struct rrsig *)rdata;
		rrsig->ttl = ttl;
		rrsig->created = time(NULL);
	}

	TAILQ_INSERT_TAIL(&rrset->rr_head, myrr, entries);

	return (rbt);
}

	
struct rbtree *
find_rrset(ddDB *db, char *name, int len)
{
	static ddDBT key, data;

	if (name == NULL || len == 0)
		return NULL;

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	key.data = (char *)name;
	key.size = len;

	if (db->get(db, &key, &data) != 0) {
		return (NULL);
	}

	return ((struct rbtree *)data.data);
}


int
add_rr(struct rbtree *rbt, char *name, int len, u_int16_t rrtype, void *rdata)
{
	struct rrset *rp0, *rp;
	struct rr *rt;

	TAILQ_FOREACH_SAFE(rp, &rbt->rrset_head, entries, rp0) {
		if (rrtype == rp->rrtype)
			break;
	}
	
	if (rp == NULL) {
		/* the rrset doesn't exist, create it */
		rp = (struct rrset *)calloc(1, sizeof(struct rrset));
		if (! rp) {
			perror("calloc");
			return -1;
		}

		rp->rrtype = rrtype;
		rp->ttl = 86400;
		TAILQ_INIT(&rp->rr_head);

		TAILQ_INSERT_TAIL(&rbt->rrset_head, rp, entries);
	}

	rt = calloc(1, sizeof(struct rr));
	if (rt == NULL) {
		perror("calloc");
		return -1;
	}

	rt->changed = time(NULL);
	rt->rdata = rdata;

	TAILQ_INSERT_HEAD(&rp->rr_head, rt, entries);

	return 0;
}

int
expire_rr(ddDB *db, char *name, int len, u_int16_t rrtype, time_t now)
{
	struct rbtree *rbt = NULL;
	struct rrset *rp;
	struct rr *rt1 = NULL, *rt2 = NULL;
	int count = 0;

	rbt = find_rrset(db, name, len);
	if (rbt == NULL) {
		return 0;	
	}

	rp = find_rr(rbt, rrtype);
	if (rp == NULL) {
		return 0;
	}

	/* expire these */
	if (rrtype != DNS_TYPE_RRSIG) {
		if (difftime(now, rp->created) >= (double)rp->ttl) {
			count = 0;

			TAILQ_FOREACH_SAFE(rt1, &rp->rr_head, entries, rt2) {
				TAILQ_REMOVE(&rp->rr_head, rt1, entries);
				free(rt1->rdata);
				free(rt1);
				count++;		
			}

			TAILQ_REMOVE(&rbt->rrset_head, rp, entries);
			free(rp);

			return (count);
		}
	} else {
		count = 0;
		TAILQ_FOREACH_SAFE(rt1, &rp->rr_head, entries, rt2) {
			struct rrsig *rrsig = (struct rrsig *)rt1->rdata;
			if (difftime(now, rrsig->created) >= (double)rrsig->ttl) {
				TAILQ_REMOVE(&rp->rr_head, rt1, entries);
				free(rt1->rdata);
				free(rt1);
				count++;
			}
		}
		
		if (TAILQ_EMPTY(&rp->rr_head)) {
			TAILQ_REMOVE(&rbt->rrset_head, rp, entries);
			free(rp);
		}

		return (count);
	}

	return 0;
}

int
expire_db(ddDB *db, int all)
{
	struct node *walk, *walk0;
	struct rbtree *rbt = NULL;
	struct rrset *rp, *rp0, *rp2;
	struct rr *rt1 = NULL, *rt2 = NULL;
	int totalcount = 0, count = 0;
	time_t now;

	if (all == 0)
		now = time(NULL);
	else
#if __OpenBSD__
		now = 4000000000;  /* Tue Oct  2 09:06:40 CEST 2096 hbdM */

#else
		now = 2147483647;
#endif
	
	RB_FOREACH_SAFE(walk, domaintree, &db->head, walk0) {
		rbt = (struct rbtree *)walk->data;
		if (rbt == NULL)
			continue;

		TAILQ_FOREACH_SAFE(rp, &rbt->rrset_head, entries, rp0) {
			rp2 = find_rr(rbt, rp->rrtype);
			if (rp2 == NULL) {
				return 0;
			}
			if (rp->rrtype != DNS_TYPE_RRSIG) {
				if (difftime(now, rp2->created) >= (double)rp2->ttl) {
					count = 0;

					TAILQ_FOREACH_SAFE(rt1, &rp2->rr_head, entries, rt2) {
						TAILQ_REMOVE(&rp2->rr_head, rt1, entries);
						free(rt1->rdata);
						free(rt1);
						count++;		
					}

					TAILQ_REMOVE(&rbt->rrset_head, rp2, entries);
					free(rp2);

					return (count);
				}
			} else {
				count = 0;
				TAILQ_FOREACH_SAFE(rt1, &rp2->rr_head, entries, rt2) {
					struct rrsig *rrsig = (struct rrsig *)rt1->rdata;
					if (difftime(now, rrsig->created) >= (double)rrsig->ttl) {
						TAILQ_REMOVE(&rp2->rr_head, rt1, entries);
						free(rt1->rdata);
						free(rt1);
						count++;
					}
				}
				
				if (TAILQ_EMPTY(&rp2->rr_head)) {
					TAILQ_REMOVE(&rbt->rrset_head, rp, entries);
					free(rp2);
				}
			}
			
			totalcount += count;
		}

		RB_REMOVE(domaintree, &db->head, walk);
		free(walk);
		free(rbt);
	}

	return (totalcount);
}

struct rrset *
find_rr(struct rbtree *rbt, u_int16_t rrtype)
{
	struct rrset *rp = NULL, *rp0 = NULL;

	if (TAILQ_EMPTY(&rbt->rrset_head))
		return NULL;

	TAILQ_FOREACH_SAFE(rp, &rbt->rrset_head, entries, rp0) {
		if (rrtype == rp->rrtype)
			break;
	}
	
	return (rp);
}

void 
flag_rr(struct rbtree *rbt, uint32_t flag)
{
	rbt->flags |= flag;
}

int
display_rr(struct rrset *rrset)
{
	struct rr *rrp, *rrp0;

	TAILQ_FOREACH_SAFE(rrp, &rrset->rr_head, entries, rrp0) {
#if __linux__
		printf("%ld:%u:%s\n", rrp->changed, rrset->ttl, (char *)rrp->rdata);
#else
		printf("%lld:%u:%s\n", rrp->changed, rrset->ttl, (char *)rrp->rdata);
#endif
	}

	return 0;
}

int
rotate_rr(struct rrset *rrset)
{
	struct rr *rrp;

	rrp = TAILQ_LAST(&rrset->rr_head, rrh);
	if (rrp == NULL)
		return -1;

	TAILQ_REMOVE(&rrset->rr_head, rrp, entries);
	TAILQ_INSERT_HEAD(&rrset->rr_head, rrp, entries);

	return 0;
}

void
remove_rbt(struct rbtree *rbt)
{
	struct rrset *rp = NULL, *rp0 = NULL, *rp2 = NULL;
	struct rr *rt1 = NULL, *rt2 = NULL;

	if (rbt == NULL)
		return;

	TAILQ_FOREACH_SAFE(rp, &rbt->rrset_head, entries, rp0) {
		rp2 = find_rr(rbt, rp->rrtype);
		if (rp2 == NULL) {
			TAILQ_REMOVE(&rbt->rrset_head, rp, entries);
			free(rp);

			continue;
		}
		if (rp->rrtype != DNS_TYPE_RRSIG) {
			TAILQ_FOREACH_SAFE(rt1, &rp2->rr_head, entries, rt2) {
				TAILQ_REMOVE(&rp2->rr_head, rt1, entries);
				free(rt1->rdata);
				free(rt1);
			}

			TAILQ_REMOVE(&rbt->rrset_head, rp, entries);
			free(rp);
		} else {
			TAILQ_FOREACH_SAFE(rt1, &rp2->rr_head, entries, rt2) {
				TAILQ_REMOVE(&rp2->rr_head, rt1, entries);
				free(rt1->rdata);
				free(rt1);
			}
			if (TAILQ_EMPTY(&rp->rr_head)) {
				TAILQ_REMOVE(&rbt->rrset_head, rp, entries);
				free(rp);
			}
		}
	}

	free(rbt);

	return;
}

/*
 * MATCH_ZONEGLUE - match if there is over 1 links to different zones inside
 *			this rbt, this means that there is glue information
 *			out there...
 */

uint32_t
match_zoneglue(struct rbtree *rbt)
{
	struct rrset *rrset = NULL;
	struct rr *rt1 = NULL;
	uint32_t lastzonenum = (uint32_t)-1;

	TAILQ_FOREACH(rrset, &rbt->rrset_head, entries) {
		if (rrset) {
			TAILQ_FOREACH(rt1, &rrset->rr_head, entries) {
				if (lastzonenum != (uint32_t)-1 && 	
					lastzonenum != rt1->zonenumber)
					return 1;
				lastzonenum = rt1->zonenumber;
			}
		}
	}

	return 0;
}
