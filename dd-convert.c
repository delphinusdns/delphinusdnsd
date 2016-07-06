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

int debug = 0;		/* log.c usually logs to syslog at 0 */
int verbose = 0;

void	dolog(int pri, char *fmt, ...);


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
	int ret;

	key_t key;

	char *zonefile = NULL;
	char *zonename = NULL;
	
	DB *db;
	DB_ENV *dbenv;


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
			zonefile = optarg;

			break;

		case 'K':
			/* create KSK key */

			break;

		case 'k':
			/* use KSK key */

			break;

		case 'n':

			/* zone name */
			zonename = optarg;

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

	if (zonefile == NULL || zonename == NULL) {
		fprintf(stderr, "must provide a zonefile and a zonename!\n");
		exit(1);
	}

	printf("zonefile is %s\n", zonefile);

	/* open the database(s) */
	if ((ret = db_env_create(&dbenv, 0)) != 0) {
		fprintf(stderr, "db_env_create: %s\n", db_strerror(ret));
		exit(1);
	}

	key = ftok("/usr/local/sbin/dd-convert", 1);
	if (key == (key_t)-1) {
		perror("ftok");
		exit(1);
	}

	if ((ret = dbenv->set_shm_key(dbenv, key)) != 0) {
		fprintf(stderr, "dbenv->set_shm_key failed\n");
		exit(1);
	}

	if (mkdir("tmp/", 0700) < 0) {
		perror("mkdir");
	}

	if ((ret = dbenv->open(dbenv, "tmp", DB_CREATE | \
		DB_INIT_LOCK | DB_INIT_MPOOL | DB_SYSTEM_MEM, \
		S_IRUSR | S_IWUSR)) != 0) {
		fprintf(stderr, "dbenv->open: %s\n", db_strerror(ret));
		exit(1);
	}

	if (db_create((DB **)&db, (DB_ENV*)dbenv, 0) != 0) {
		perror("db_create");
		exit(1);
	}

	if (db->open(db, NULL, "ddc.db", NULL, DB_BTREE, DB_CREATE, 0600) != 0) {
		perror("db->open");
		exit(1);
	}

	/* now we start reading our configfile */
		
	
	if (parse_file(db, zonefile) < 0) {
		dolog(LOG_INFO, "parsing config file failed\n");
		exit(1);
	}

	


	exit(0);
}


int
insert_axfr(char *address, char *prefixlen)
{
	return 0;
}

int
insert_region(char *address, char *prefixlen)
{
	return 0;
}

int
insert_filter(char *address, char *prefixlen)
{
	return 0;
}

int
insert_whitelist(char *address, char *prefixlen)
{
	return 0;
}

int
insert_notifyslave(char *address, char *prefixlen)
{
	return 0;
}




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
		if (debug)
			vprintf(fmt, ap);
	} else {
			vprintf(fmt, ap);
	}	
	
	va_end(ap);

}
