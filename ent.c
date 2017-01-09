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
 * this file is based on whitelist.c
 */

#include "ddd-include.h"
#include "ddd-dns.h"
#include "ddd-db.h"

int		init_entlist(DB *);
int 		check_ent(char *, int);
static int 	ent_contains(char *, int, char *, int);

extern void 		dolog(int, char *, ...);
extern int 		memcasecmp(u_char *, u_char *, int);

extern int debug, verbose;

SLIST_HEAD(listhead, ententry) enthead;

static struct ententry {
	char *name;
	int len;
	u_int64_t flags;
	SLIST_ENTRY(ententry) ent_entry;
} *ent2, *entp;


static const char rcsid[] = "$Id: ent.c,v 1.1 2017/01/09 14:26:50 pjp Exp $";

/*
 * INIT_ENTLIST - initialize the ent singly linked list
 */

int
init_entlist(DB *db)
{
	DBT key, data;
	DBC *cursor;
	struct domain *sd = NULL;
	int curs;

	SLIST_INIT(&enthead);

	if (db->cursor(db, NULL, &cursor, 0) != 0) {
		dolog(LOG_INFO, "db->cursor: %s\n", strerror(errno));
		return -1;
	}

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	/* herd all ENT candidates into our ent-list */
	curs = cursor->c_get(cursor, &key, &data, DB_FIRST);
	do {
		
		if (curs != 0) {
			dolog(LOG_INFO, "cursor->c_get: %s\n", strerror(errno));
			return -1;
		}

		sd = (struct domain *)data.data;
		ent2 = malloc(sizeof(struct ententry));
		if (ent2 == NULL) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
			return -1;
		}	

		ent2->name = malloc(sd->zonelen);
		if (ent2->name == NULL) {
			dolog(LOG_INFO, "malloc: %s\n", strerror(errno));
			return -1;
		}
	

		memcpy(ent2->name, sd->zone, sd->zonelen);
		ent2->len = sd->zonelen;
		ent2->flags = sd->flags;	

		SLIST_INSERT_HEAD(&enthead, ent2, ent_entry);

		memset(&key, 0, sizeof(key));
		memset(&data, 0, sizeof(data));
		
	} while ((curs = cursor->c_get(cursor, &key, &data, DB_NEXT)) == 0);
		

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

		if (memcasecmp(name, p, l) == 0)
			return 1;
	}

	return 0;
}
