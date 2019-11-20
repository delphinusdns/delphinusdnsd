/* 
 * Copyright (c) 2011-2018 Peter J. Philipp
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
 * $Id: log.c,v 1.7 2019/11/20 18:20:49 pjp Exp $
 */


#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

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

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "ddd-dns.h"
#include "ddd-db.h"

extern struct logging logging;
extern int debug;
extern int verbose;

void	dolog(int pri, char *fmt, ...);
void	receivelog(char *buf, int len);
int	remotelog(int fd, char *fmt, ...);
char	*input_sanitize(char *);


/*
 * INPUT_SANITIZE - syslogd does this sanitization, but in debug mode we want
 *			this sanitizer at least.
 */

char *
input_sanitize(char *fmt)
{
	char *buf;
	char *p, *q;
	char backslash = '\\';

	buf = malloc((4 * strlen(fmt)) + 1);
	if (buf == NULL)
		return NULL;

	q = buf;

	for (p = fmt; *p; p++) {
		if (*p == backslash) {
			*q++ = *p++;	
			if (*p == '\0')
				break;
			switch (*p) {
			case 'n':
			case 't':
			case 'r':
			case '\'':
			case '\\':
			case '"':
				*q++ = *p;
				break;
			default:
				*q++ = '\\';
				*q++ = *p;
				break;
			}
		} else {
			if (isprint(*p) || *p == '\n') {
				*q++ = *p;
			} else {
				*q++ = '\\';
				*q++ = 'x'; 
				snprintf(q, 3, "%02X", *p & 0xff);
				q += 2;
			}
		}
	}

	*q = '\0';

	return (buf);
}


/*
 * dolog() - is a wrapper to syslog and printf depending on debug flag
 *
 */

void 
dolog(int pri, char *fmt, ...)
{
	va_list ap;
	char *buf, *sanitize;

	va_start(ap, fmt);

	/*
	 * if the message is a debug message and verbose (-v) is set
	 *  then print it, otherwise 
	 */

	if (pri == LOG_DEBUG) {
		if (verbose && debug) {
			buf = malloc(1024);
			if (buf == NULL) {
				printf("-= failed to allocate memory for output buffer =-\n");
			} else {
				vsnprintf(buf, 1024, fmt, ap);
				sanitize = input_sanitize(buf);
				if (sanitize == NULL) {
					printf("-= failed to allocate memory for output buffer =-\n");
				} else {
					printf("%s", sanitize);
					free(sanitize);
				}
				free(buf); 
			}
		} else if (verbose)
			vsyslog(pri, fmt, ap);
	} else {
		if (debug) {
			buf = malloc(1024);
			if (buf == NULL) {
				printf("-= failed to allocate memory for output buffer =-\n");
			} else {
				vsnprintf(buf, 1024, fmt, ap);
				sanitize = input_sanitize(buf);
				if (sanitize == NULL) {
					printf("-= failed to allocate memory for output buffer =-\n");
				} else {
					printf("%s", sanitize);
					free(sanitize);
				}
				free(buf); 
			}
		} else 
			vsyslog(pri, fmt, ap);
	}	
	
	va_end(ap);

}

/*
 * remotelog() - is like syslog() only the first argument is a filedescriptor
 *		 instead of severity, it will send a packet to the loghost
 *		 signed.
 */

int
remotelog(int fd, char *fmt, ...)
{
	va_list ap;
	static char buf[1500];
	static char outbuf[1500];
	char sign[20];
	char *p;
	u_int rlen;
	static u_int64_t sequence = 0;


	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

#ifdef __NetBSD__
	snprintf(outbuf, sizeof(outbuf), "XXXXXXXXXXXXXXXXXXXX%lu %s %s", 
#else
	snprintf(outbuf, sizeof(outbuf), "XXXXXXXXXXXXXXXXXXXX%llu %s %s", 
#endif
			sequence++, logging.hostname, buf);

	p = &outbuf[20];

	
	HMAC(EVP_sha1(), logging.logpasswd, strlen(logging.logpasswd),
		(unsigned char *)p, strlen(p), (unsigned char *)&sign, 
		&rlen);

	memcpy(outbuf, sign, 20);

	return (send(fd, outbuf, strlen(outbuf), 0));
}


void
receivelog(char *buf, int len)
{
	static char inbuf[1500];
	char sign[20];
	char *p;
	int rlen;

	if (len < 21 || len > 1450)
		return;

	memcpy(&inbuf, buf, len);
	inbuf[len] = '\0';

	p = &inbuf[20];

	HMAC(EVP_sha1(), logging.logpasswd, strlen(logging.logpasswd),
		(unsigned char *)p, strlen(p), (unsigned char *)&sign, 
		(unsigned int *)&rlen);

	if (memcmp(inbuf, sign, 20) != 0) 
		return;

	/* skip sequence number */
	p = strchr(p, ' ');
	if (p == NULL)
		return;

	p++;

	syslog(LOG_INFO, "%s", p);

	return;
}
