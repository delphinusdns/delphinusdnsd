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


/*
 * this file is based on passlist.c
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

int		init_entlist(ddDB *);
int 		check_ent(char *, int);
static int 	ent_contains(char *, int, char *, int);

extern void 		dolog(int, char *, ...);
extern int 		memcasecmp(u_char *, u_char *, int);

extern int debug, verbose;

SLIST_HEAD(listhead, ententry) enthead;


static struct ententry {
	char *name;
	int len;
	SLIST_ENTRY(ententry) ent_entry;
} *ent2, *entp;

extern int domaincmp(struct node *e1, struct node *e2);


/*
 * INIT_ENTLIST - initialize the ent singly linked list
 */

int
init_entlist(ddDB *db)
{
	struct node *n, *nx;
	struct rbtree *rbt = NULL;

	SLIST_INIT(&enthead);

	RB_FOREACH_SAFE(n, domaintree, &db->head, nx) {
		rbt = (struct rbtree *)n->data;
		ent2 = malloc(sizeof(struct ententry));
		if (ent2 == NULL) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
			return -1;
		}	

		ent2->name = malloc(rbt->zonelen);
		if (ent2->name == NULL) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
			return -1;
		}
	

		memcpy(ent2->name, rbt->zone, rbt->zonelen);
		ent2->len = rbt->zonelen;

		SLIST_INSERT_HEAD(&enthead, ent2, ent_entry);
	} 
		

	return 0;
}

/*
 * Check if the provided name is an empty non-terminating (ENT) name, if so
 * return 1, else return 0
 */

int
check_ent(char *name, int len)
{
	/* walk the dns forest searching for a matching ENT */
	SLIST_FOREACH(entp, &enthead, ent_entry) {
		/* skip ent candidates that are too short */
		if (entp->len <= len)
			continue;	
		if (ent_contains(name, len, entp->name, entp->len)) {
			return (1);
		}
	}

	return (0);
}


static int
ent_contains(char *name, int len, char *entname, int entlen)
{
	char *p;
	int l;

	p = entname;
	l = entlen;
	while (*p) {
		l -= (*p + 1);
		p += (*p + 1);
		
		if (l != len)
			continue;

		if (memcasecmp((u_char *)name, (u_char *)p, l) == 0)
			goto exists; /* ? */
	}

	return 0;

exists:
	/*
	 * we take a second look, to make sure that we don't hit the
	 * base of an ENT...this was overlooked originally
	 */

	SLIST_FOREACH(ent2, &enthead, ent_entry) {
		if (ent2->len != l)
			continue;

		if (memcasecmp((u_char *)ent2->name, (u_char *)p, l) == 0)
			return 0;
	}

	return 1;
}
