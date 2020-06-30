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
 * $Id: forward.c,v 1.2 2020/06/30 14:06:21 pjp Exp $
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
int	insert_forward(void);
void	forwardloop(ddDB *, struct cfg *, struct imsgbuf *);
void	forwardthis(int, struct forward *);

extern void 		dolog(int, char *, ...);

extern int debug, verbose;

SLIST_HEAD(, forwardentry) forwardhead;

static struct forwardentry {
	char name[INET6_ADDRSTRLEN];
	int family;
	struct sockaddr_storage hostmask;
	struct sockaddr_storage netmask;
	u_int8_t prefixlen;
	uint16_t destport;
	char *tsigkey;
	SLIST_ENTRY(forwardentry) forward_entry;
} *fw2, *fwp;


/*
 * INIT_FORWARD - initialize the forward singly linked list
 */

void
init_forward(void)
{
	SLIST_INIT(&forwardhead);
	return;
}

/*
 * INSERT_FORWARD - insert into the forward slist
 */

int
insert_forward(void)
{
	/* SLIST_INSERT_HEAD(&forwardhead, fw2, forward_entry); */

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



}
