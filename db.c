/* 
 * Copyright (c) 2017 Peter J. Philipp
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
 * $Id: db.c,v 1.15 2019/11/11 05:22:50 pjp Exp $
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

struct rbtree * create_rr(ddDB *db, char *name, int len, int type, void *rdata);
struct rbtree * find_rrset(ddDB *db, char *name, int len);
struct rrset * find_rr(struct rbtree *rbt, u_int16_t rrtype);
int add_rr(struct rbtree *rbt, char *name, int len, u_int16_t rrtype, void *rdata);
int display_rr(struct rrset *rrset);
int rotate_rr(struct rrset *rrset);
void flag_rr(struct rbtree *rbt);

extern void      dolog(int, char *, ...);

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
	char *map;

	strlcpy(find.domainname, key->data, sizeof(find.domainname));
	find.len = key->size;

	res = RB_FIND(domaintree, &db->head, &find);
	if (res == NULL) {
		/* does not exist, create it */
		
		map = calloc(1, data->size);
		if (map == NULL) {
			return -1;
		}

		n = calloc(sizeof(struct node), 1);
		if (n == NULL) {
			return -1;
		}
		memset(n, 0, sizeof(struct node));
		n->len = key->size;
		memcpy(n->domainname, key->data, n->len);
		n->data = map;
		n->datalen = data->size;
		memcpy(map, data->data, data->size);

		RB_INSERT(domaintree, &db->head, n);
	} else {
		if (res->datalen != data->size)
			return -1;

		memcpy(res->data, data->data, res->datalen);
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
	return 0;
}

struct rbtree *
create_rr(ddDB *db, char *name, int len, int type, void *rdata)
{
	struct rbtree *rbt = NULL;
	struct rrset *rrset = NULL;
	struct rr *myrr = NULL;
	ddDBT key, data;
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
	}
	
	rrset = find_rr(rbt, type);
	if (rrset == NULL) {
		rrset = (struct rrset *)calloc(1, sizeof(struct rrset));
		if (! rrset){
			perror("calloc");

			free(rbt);
			return NULL;
		}

		rrset->rrtype = type;
		TAILQ_INIT(&rrset->rr_head);

		TAILQ_INSERT_TAIL(&rbt->rrset_head, rrset, entries);
	}


	/* save this new rbtree (it changed) */

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	key.data = (char *)name;
	key.size = len;

	data.data = (void*)rbt;
	data.size = sizeof(struct rbtree);

	if (db->put(db, &key, &data) != 0) {
		return NULL;
	}

	/* this sets up the RR */

	myrr = (struct rr *)calloc(1, sizeof(struct rr));
	if (! myrr) {
		perror("calloc");
		return NULL;
	}

	myrr->ttl = 86400;
	myrr->rdata = rdata;
	myrr->changed = time(NULL);

	TAILQ_INSERT_TAIL(&rrset->rr_head, myrr, entries);

	return (rbt);
}

	
struct rbtree *
find_rrset(ddDB *db, char *name, int len)
{
	static struct rbtree *rb;
	ddDBT key, data;

	if (name == NULL || len == 0)
		return NULL;

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	key.data = (char *)name;
	key.size = len;

	if (db->get(db, &key, &data) != 0) {
		return (NULL);
	}

	if ((rb = calloc(1, sizeof(struct rbtree))) == NULL)
		return NULL;


	memcpy((char *)rb, (char *)data.data, sizeof(struct rbtree));

	return (rb);
}


int
add_rr(struct rbtree *rbt, char *name, int len, u_int16_t rrtype, void *rdata)
{
	struct rrset *rp0, *rp;
	struct rr *rt;

#ifdef __linux__
	TAILQ_FOREACH(rp, &rbt->rrset_head, entries) {
#else
	TAILQ_FOREACH_SAFE(rp, &rbt->rrset_head, entries, rp0) {
#endif
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
		TAILQ_INIT(&rp->rr_head);

		TAILQ_INSERT_TAIL(&rbt->rrset_head, rp, entries);
	}

	rt = calloc(1, sizeof(struct rr));
	if (rt == NULL) {
		perror("calloc");
		return -1;
	}

	rt->ttl = 86400;
	rt->changed = time(NULL);
	rt->rdata = rdata;

	TAILQ_INSERT_HEAD(&rp->rr_head, rt, entries);

	return 0;
}

struct rrset *
find_rr(struct rbtree *rbt, u_int16_t rrtype)
{
	struct rrset *rp = NULL, *rp0 = NULL;

#ifdef __linux__
	TAILQ_FOREACH(rp, &rbt->rrset_head, entries) {
#else
	TAILQ_FOREACH_SAFE(rp, &rbt->rrset_head, entries, rp0) {
#endif
		if (rrtype == rp->rrtype)
			break;
	}
	
	return (rp);
}

void 
flag_rr(struct rbtree *rbt)
{
	rbt->flags |= RBT_DNSSEC;
}

int
display_rr(struct rrset *rrset)
{
	struct rr *rrp, *rrp0;

#ifdef __linux__
	TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
#else
	TAILQ_FOREACH_SAFE(rrp, &rrset->rr_head, entries, rrp0) {
#endif
		printf("%lld:%u:%s\n", rrp->changed, rrp->ttl, (char *)rrp->rdata);
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
