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

#include "ddd-include.h"
#include "ddd-dns.h"
#include "ddd-db.h"



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


RB_HEAD(domaintree, node) rbhead = RB_INITIALIZER(&rbhead);
RB_PROTOTYPE(domaintree, node, entry, domaincmp)
RB_GENERATE(domaintree, node, entry, domaincmp)



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
		
	return (db);
}

int
dddbput(ddDB *db, ddDBT *key, ddDBT *data)
{
	struct node find, *n, *res;
	char *map;

	if (data->size > SIZENODE) {
		errno = E2BIG;
		return -1;
	}

	strlcpy(find.domainname, key->data, sizeof(find.domainname));
	find.len = key->size;

	res = RB_FIND(domaintree, &rbhead, &find);
	if (res == NULL) {
		/* does not exist, create it */
		
		map = (char *)mmap(NULL, SIZENODE, PROT_READ|PROT_WRITE,MAP_ANON|MAP_SHARED,-1, 0);
		if (map == MAP_FAILED) {
			errno = EINVAL;
			return -1;
		}

		n = calloc(sizeof(struct node), 1);
		if (n == NULL) {
			errno = ENOMEM;
			return -1;
		}
		memset(n, 0, sizeof(struct node));
		n->len = key->size;
		memcpy(n->domainname, key->data, n->len);
		n->data = map;
		n->datalen = data->size;
		memcpy(map, data->data, data->size);

		RB_INSERT(domaintree, &rbhead, n);
	} else {
		res->datalen = data->size;
		memcpy(res->data, data->data, data->size);
	}

	return 0;
}

int
dddbget(ddDB *db, ddDBT *key, ddDBT *data)
{
	struct node find, *res;
	
	strlcpy(find.domainname, key->data, sizeof(find.domainname));
	find.len = key->size;

	res = RB_FIND(domaintree, &rbhead, &find);
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
