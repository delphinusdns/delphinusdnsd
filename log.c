/*
 * Copyright (c) 2011-2021 Peter J. Philipp <pjp@delphinusdns.org>
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

extern int debug;
extern int verbose;

void	dolog(int pri, char *fmt, ...);
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
