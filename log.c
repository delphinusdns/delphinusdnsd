/* 
 * Copyright (c) 2011-2014 Peter J. Philipp
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

#include "include.h"
#include "dns.h"
#include "db.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

extern struct logging logging;
extern int debug;
extern int verbose;

void	dolog(int pri, char *fmt, ...);
void	receivelog(char *buf, int len);
int	remotelog(int fd, char *fmt, ...);


/*
 * dolog() - is a wrapper to syslog and printf depending on debug flag
 *
 */

void 
dolog(int pri, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	/*
	 * if the message is a debug message and verbose (-v) is set
	 *  then print it, otherwise 
	 */

	if (pri == LOG_DEBUG) {
		if (verbose && debug)
			vprintf(fmt, ap);
		else if (verbose)
			vsyslog(pri, fmt, ap);
	} else {
		if (debug)
			vprintf(fmt, ap);
		else 
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
