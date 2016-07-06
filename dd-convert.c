/* 
 * Copyright (c) 2016 Peter J. Philipp
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

int debug = 0;
int verbose = 0;

/* glue */
int insert_axfr(char *, char *);
int insert_region(char *, char *);
int insert_filter(char *, char *);
int insert_whitelist(char *, char *);
int insert_notifyslave(char *, char *);

int *ptr = NULL;
int notify = 0;
int whitelist = 0;
int bcount = 0;
char *bind_list[255];
char *interface_list[255];
int bflag = 0;
int ratelimit_packets_per_second = 0;
int ratelimit = 0;
u_int16_t port = 53;
int nflag = 0;
int iflag = 0;
int lflag = 0;
int icount = 0;
int vslen = 0;
char *versionstring = NULL;

int
main(int argc, char *argv[])
{
	int ch;

	char *zonefile = NULL;
	char *zonename = NULL;
	
	DB *db;


	while ((ch = getopt(argc, argv, "a:B:I:i:Kk:n:o:s:t:Zz:")) != -1) {
		switch (ch) {
		case 'a':
			/* algorithm */

			break;
	
		case 'B':
			/* bits */

			break;

		case 'I':
			/* NSEC3 iterations */

			break;

		case 'i':
			/* inputfile */

			break;

		case 'K':
			/* create KSK key */

			break;

		case 'k':
			/* use KSK key */

			break;

		case 'n':

			/* zone name */

			break;

		case 'o':
		
			/* output file */

			break;

		case 't':

			/* ttl of the zone */

			break;

		case 'Z':

			/* create ZSK */

			break;

		case 'z':
			/* use ZSK */

			break;

		}
	
	}

	if (zonefile == NULL && zonename == NULL) {
		fprintf(stderr, "must provide a zonefile and a zonename!\n");
		exit(1);
	}

	printf("zonefile is %s\n", zonefile);
		



}


int
insert_axfr(char *address, char *prefixlen)
{
	return -1;
}

int
insert_region(char *address, char *prefixlen)
{
	return -1;
}

int
insert_filter(char *address, char *prefixlen)
{
	return -1;
}

int
insert_whitelist(char *address, char *prefixlen)
{
	return -1;
}

int
insert_notifyslave(char *address, char *prefixlen)
{
	return -1;
}

