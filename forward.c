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

/* 
 * $Id: forward.c,v 1.3 2020/07/01 05:07:47 pjp Exp $
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <sys/select.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>

#include <unistd.h>
#include <imsg.h>

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

#include "ddd-dns.h"
#include "ddd-db.h"

void	init_forward(void);
int	insert_forward(struct sockaddr_storage *, uint16_t, char *);
void	forwardloop(ddDB *, struct cfg *, struct imsgbuf *);
void	forwardthis(int, struct forward *);

extern void 		dolog(int, char *, ...);

extern int debug, verbose;

SLIST_HEAD(, forwardentry) forwardhead;

static struct forwardentry {
	char name[INET6_ADDRSTRLEN];
	int family;
	struct sockaddr_storage host;
	uint16_t destport;
	char *tsigkey;
	SLIST_ENTRY(forwardentry) forward_entry;
} *fw2, *fwp;

SLIST_HEAD(, forwardqueue) fwqhead;

static struct forwardqueue {
	time_t time;
	struct sockaddr_storage host;
	uint16_t id;
	uint16_t port;
	struct sockaddr_storage oldhost;
	uint16_t oldid;
	uint16_t oldport;
	int so;
	SLIST_ENTRY(forwardqueue) entries;
} *fwq1, *fwq2, *fwqp;

/*
 * INIT_FORWARD - initialize the forward singly linked list
 */

void
init_forward(void)
{
	SLIST_INIT(&forwardhead);
	SLIST_INIT(&fwqhead);
	return;
}

/*
 * INSERT_FORWARD - insert into the forward slist
 */

int
insert_forward(struct sockaddr_storage *ip, uint16_t port, char *tsigkey)
{
	fw2 = calloc(1, sizeof(struct forwardentry));
	if (fw2 == NULL) {
		dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
		return 1;
	}

	switch (fw2->family = ip->ss_family) {
	case AF_INET:
		inet_ntop(AF_INET, (struct sockaddr_in *)ip, fw2->name, sizeof(fw2->name));
		break;
	case AF_INET6:
		inet_ntop(AF_INET6, (struct sockaddr_in6 *)ip, fw2->name, sizeof(fw2->name));
		break;
	}

	memcpy(&fw2->host, ip, sizeof(struct sockaddr_storage));
	fw2->destport = port;

	if (strcmp(tsigkey, "NOKEY") == 0)
		fw2->tsigkey = NULL;
	else {
		fw2->tsigkey = strdup(tsigkey);
		if (fw2->tsigkey == NULL) {
			dolog(LOG_INFO, "strdup: %s\n", strerror(errno));
			return 1;
		}
	}
			
	SLIST_INSERT_HEAD(&forwardhead, fw2, forward_entry);

	return (0);
}

void
forwardloop(ddDB *db, struct cfg *cfg, struct imsgbuf *ibuf)
{
	struct imsg imsg;
	int max, sel;
	ssize_t n, datalen;
	fd_set rset;

	for (;;) {
		FD_ZERO(&rset);	
		FD_SET(ibuf->fd, &rset);
		if (ibuf->fd > max)
			max = ibuf->fd;

		sel = select(max + 1, &rset, NULL, NULL, NULL);
		if (sel == -1) {	
			continue;
		}
		if (FD_ISSET(ibuf->fd, &rset)) {

			if ((n = imsg_read(ibuf)) < 0 && errno != EAGAIN) {
				dolog(LOG_ERR, "imsg read failure %s\n", strerror(errno));
				continue;
			}
			if (n == 0) {
				/* child died? */
				dolog(LOG_INFO, "sigpipe on child?  exiting.\n");
				exit(1);
			}

			for (;;) {
				if ((n = imsg_get(ibuf, &imsg)) < 0) {
					dolog(LOG_ERR, "imsg read error: %s\n", strerror(errno));
					break;
				} else {
					if (n == 0)
						break;

					datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
					if (datalen != sizeof(struct forward)) {
						imsg_free(&imsg);
						continue;
					}

					switch(imsg.hdr.type) {
					case IMSG_FORWARD_UDP:
						dolog(LOG_INFO, "received UDP message from mainloop\n");
						forwardthis(-1, imsg.data);	
						break;

					case IMSG_FORWARD_TCP:
						dolog(LOG_INFO, "received TCP message and descriptor\n");
						forwardthis(imsg.fd, imsg.data);
						break;
					}

					imsg_free(&imsg);
				}
			} /* for (;;) */
		} /* FD_ISSET... */
	}

	while (1)
		sleep(10);

	/* NOTREACHED */

}

void
forwardthis(int so, struct forward *forward)
{
	struct dns_header *dh = (struct dns_header *)forward->buf;
	time_t now;
	char *p;
	
	now = time(NULL);
	p = forward->buf;

	SLIST_FOREACH_SAFE(fwq1, &fwqhead, entries, fwq2) {
		if (difftime(now, fwq1->time) > 15) {
			SLIST_REMOVE(&fwqhead, fwq1, forwardqueue, entries);
			continue;
		}
	
		if (memcmp(&fwq1->oldhost, &forward->from, 
			sizeof(struct sockaddr_storage)) == 0 &&
			fwq1->oldport == forward->rport &&
			fwq1->oldid == dh->id) {
			/* found, break... */
			break;
		}
	}

	if (fwq1 == NULL) {
		/* create a new queue and send it */
		
	} else {
		/* resend this one */
		
		fwq1->time = now;
	}

	
}
