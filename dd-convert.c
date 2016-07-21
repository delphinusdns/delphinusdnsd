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

#include <openssl/bn.h>
#include <openssl/rsa.h>

int debug = 0;
int verbose = 0;

void	dolog(int pri, char *fmt, ...);
int	add_dnskey(DB *, char *, char *);
char * 	parse_keyfile(int, uint32_t *, uint16_t *, uint8_t *, uint8_t *, char *);
char *	create_key(char *, int, int, int, int);
void 	dump_db(DB *);
char * alg_to_name(int);

#define ALGORITHM_RSASHA1	5		/* rfc 4034 , mandatory */
#define ALGORITHM_RSASHA256	8		/* rfc 5702 */
#define ALGORITHM_RSASHA512	10		/* rfc 5702 */

#define RSA_F5			0x100000001

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

/* externs */

extern int fill_dnskey(char *, char *, u_int32_t, u_int16_t, u_int8_t, u_int8_t, char *);
extern int      mybase64_encode(u_char const *, size_t, char *, size_t);
extern int      mybase64_decode(char const *, u_char *, size_t);

int
main(int argc, char *argv[])
{
	int ch;
	int ret, bits = 2048;
	int ttl = 86400;
	int create_zsk = 0;
	int create_ksk = 0;
	int algorithm = ALGORITHM_RSASHA256;

	key_t key;

	char *zonefile = NULL;
	char *zonename = NULL;
	
	char *ksk_key = NULL;
	char *zsk_key = NULL;
	
	DB *db;
	DB_ENV *dbenv;


	while ((ch = getopt(argc, argv, "a:B:I:i:Kk:n:o:s:t:Zz:")) != -1) {
		switch (ch) {
		case 'a':
			/* algorithm */

			break;
	
		case 'B':
			/* bits */

			bits = atoi(optarg);
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
			create_ksk = 1;

			break;

		case 'k':
			/* use KSK key */
			ksk_key = optarg;

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
			ttl = atoi(optarg);

			break;

		case 'Z':
			/* create ZSK */
			create_zsk = 1;
			break;

		case 'z':
			/* use ZSK */
			zsk_key = optarg;

			break;

		}
	
	}

	if (zonefile == NULL || zonename == NULL) {
		fprintf(stderr, "must provide a zonefile and a zonename!\n");
		exit(1);
	}

	if (create_ksk)
		ksk_key = create_key(zonename, ttl, 257, algorithm, bits);
	if (create_zsk)
		zsk_key = create_key(zonename, ttl, 256, algorithm, bits);

	if (ksk_key == NULL || zsk_key == NULL) {
		dolog(LOG_INFO, "must specify both a ksk and a zsk key! or -z -k\n");
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

	/* three passes to "sign" our zones */
	/* first pass, add dnskey records, on apex */

	if (zsk_key == NULL && ksk_key == NULL) {
		dolog(LOG_INFO, "no ksk or zsk keys specified\n");
		exit(1);
	}

	if (add_dnskey(db, zsk_key, ksk_key) < 0) {
		dolog(LOG_INFO, "add_dnskey failed\n");
		exit(1);
	}

	/* second pass calculate RRSIG's for every RR set */

	/* third pass construct NSEC3 records */	

	/* write new zone file */

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

	if (pri <= LOG_ERR) {
		vprintf(fmt, ap);
	}	
	
	va_end(ap);

}

int	
add_dnskey(DB *db, char *zsk_key, char *ksk_key)
{
	char key[4096];
	char buf[512];
	char *zone;
	int fd;
	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	/* first the zsk */
	snprintf(buf, sizeof(buf), "%s.key", zsk_key);
	if ((fd = open(buf, O_RDONLY, 0)) < 0) {
		dolog(LOG_INFO, "open %s: %s\n", buf, strerror(errno));
		return -1;
	}

	if ((zone = parse_keyfile(fd, &ttl, &flags, &protocol, &algorithm, (char *)&key)) == NULL) {
		dolog(LOG_INFO, "parse %s\n", buf);
		close (fd);
		return -1;
	}

	close(fd);
	
	if (fill_dnskey(zone, "dnskey", ttl, flags, protocol, algorithm, key) < 0) {
		return -1;
	}

	/* now the ksk */
	snprintf(buf, sizeof(buf), "%s.key", ksk_key);
	if ((fd = open(buf, O_RDONLY, 0)) < 0) {
		dolog(LOG_INFO, "open %s: %s\n", buf, strerror(errno));
		return -1;
	}

	if ((zone = parse_keyfile(fd, &ttl, &flags, &protocol, &algorithm, (char *)&key)) == NULL) {
		dolog(LOG_INFO, "parse %s\n", buf);
		close (fd);
		return -1;
	}

	close(fd);
	
	if (fill_dnskey(zone, "dnskey", ttl, flags, protocol, algorithm, key) < 0) {
		return -1;
	}

	dump_db(db);


	return 0;
}

char *
parse_keyfile(int fd, uint32_t *ttl, uint16_t *flags, uint8_t *protocol, uint8_t *algorithm, char *key)
{
	static char retbuf[256];
	char buf[8192];
	char *p, *q;
	FILE *f;

	if ((f = fdopen(fd, "r")) == NULL)
		return NULL;
	
	while (fgets(buf, sizeof(buf), f) != NULL) {
		if (buf[0] == ';')
			continue;
	}

	/* name */
	p = &buf[0];
	q = strchr(p, ' ');
	if (q == NULL) {
		return NULL;
	}
	
	*q++ = '\0';
	
	strlcpy(retbuf, p, sizeof(retbuf));
	/* ttl */
	p = q;
	
	q = strchr(p, ' ');
	if (q == NULL)
		return NULL;

	*q++ = '\0';
	*ttl = atoi(p);
	/* IN/DNSKEY/ flags */
	p = q;
	q = strchr(p, ' ');
	if (q == NULL)
		return NULL;
	q++;
	p = q;
	q = strchr(p, ' ');
	if (q == NULL)
		return NULL;
	q++;
	p = q;
	q = strchr(p, ' ');
	if (q == NULL) 
		return NULL;
	*q++ = '\0';
	*flags = atoi(p);
	/* protocol */
	p = q;
	q = strchr(p, ' ');
	if (q == NULL)
		return NULL;
	*q++ = '\0';
	*protocol = atoi(p);
	/* algorithm */
	p = q;
	q = strchr(p, ' ');
	if (q == NULL)
		return NULL;
	*q++ = '\0';
	*algorithm = atoi(p);
	/* key */
	p = q;

	q = key;
	while (*p) {
		if (*p == ' ' || *p == '\n' || *p == '\r') {
			p++;
			continue;
		}

		*q++ = *p++;
	}
	*q = '\0';
			
	return (&retbuf[0]);	
}

void
dump_db(DB *db)
{
	


}

char *	
create_key(char *zonename, int ttl, int flags, int algorithm, int bits)
{
	FILE *f;
        RSA *rsa;
        BIGNUM *e;
        BN_GENCB cb;
	char buf[512];
	char bin[4096];
	char b64[4096];
	int i, binlen, len;
	uint32_t pid;
	char *retval;
	char *p;
	time_t now;
	struct tm *tm;

	if ((rsa = RSA_new()) == NULL) {
		dolog(LOG_INFO, "RSA_new: %s\n", strerror(errno));
		return NULL;
	}

	if ((e = BN_new()) == NULL) {
		dolog(LOG_INFO, "BN_new: %s\n", strerror(errno));
		RSA_free(rsa);
		return NULL;
	}

	for (i = 0; i < 32; i++) {
		if (RSA_F4 & (1 << i)) {
			BN_set_bit(e, i);
		}
	}

	BN_GENCB_set_old(&cb, NULL, NULL);
	
	switch (algorithm) {
	case ALGORITHM_RSASHA1:
		break;
	case ALGORITHM_RSASHA256:
		break;
	case ALGORITHM_RSASHA512:
		break;
	default:
		dolog(LOG_INFO, "invalid key\n");
		return NULL;
	}

	if (RSA_generate_key_ex(rsa, bits, e, &cb) == 0) {
		dolog(LOG_INFO, "RSA_generate_key_ex: %s\n", strerror(errno));
		BN_free(e);
		RSA_free(rsa);
		return NULL;
	}


	pid = (arc4random() >> 16);
	
	snprintf(buf, sizeof(buf), "K%s%s+%03d+%d", zonename,
		(zonename[strlen(zonename) - 1] == '.') ? "" : ".",
		algorithm, pid);

	retval = strdup(buf);
	if (retval == NULL) {
		dolog(LOG_INFO, "strdup: %s\n", strerror(errno));
		RSA_free(rsa);
		BN_free(e);
		return NULL;
	}
		
	snprintf(buf, sizeof(buf), "%s.private", retval);

	f = fopen(buf, "w+");
	if (f == NULL) {
		dolog(LOG_INFO, "fopen: %s\n", strerror(errno));
		RSA_free(rsa);
		BN_free(e);
		return NULL;
	}

	fprintf(f, "Private-key-format: v1.3\n");
	fprintf(f, "Algorithm: %d (%s)\n", algorithm, alg_to_name(algorithm));
	/* modulus */
	binlen = BN_bn2bin(rsa->n, (char *)&bin);
	len = mybase64_encode(bin, binlen, b64, sizeof(b64));
	fprintf(f, "Modulus: %s\n", b64);
	/* public exponent */
	binlen = BN_bn2bin(rsa->e, (char *)&bin);
	len = mybase64_encode(bin, binlen, b64, sizeof(b64));
	fprintf(f, "PublicExponent: %s\n", b64);
	/* private exponent */
	binlen = BN_bn2bin(rsa->d, (char *)&bin);
	len = mybase64_encode(bin, binlen, b64, sizeof(b64));
	fprintf(f, "PrivateExponent: %s\n", b64);
	/* prime1 */
	binlen = BN_bn2bin(rsa->p, (char *)&bin);
	len = mybase64_encode(bin, binlen, b64, sizeof(b64));
	fprintf(f, "Prime1: %s\n", b64);
	/* prime2 */
	binlen = BN_bn2bin(rsa->q, (char *)&bin);
	len = mybase64_encode(bin, binlen, b64, sizeof(b64));
	fprintf(f, "Prime2: %s\n", b64);
	/* exponent1 */
	binlen = BN_bn2bin(rsa->dmp1, (char *)&bin);
	len = mybase64_encode(bin, binlen, b64, sizeof(b64));
	fprintf(f, "Exponent1: %s\n", b64);
	/* exponent2 */
	binlen = BN_bn2bin(rsa->dmq1, (char *)&bin);
	len = mybase64_encode(bin, binlen, b64, sizeof(b64));
	fprintf(f, "Exponent2: %s\n", b64);
	/* coefficient */
	binlen = BN_bn2bin(rsa->iqmp, (char *)&bin);
	len = mybase64_encode(bin, binlen, b64, sizeof(b64));
	fprintf(f, "Coefficient: %s\n", b64);

	now = time(NULL);
	tm = gmtime(&now);
	
	strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", tm);
	fprintf(f, "Created: %s\n", buf);
	fprintf(f, "Publish: %s\n", buf);
	fprintf(f, "Activate: %s\n", buf);
	
	fclose(f);
	BN_free(e);

	/* now for the .key */
	
	snprintf(buf, sizeof(buf), "%s.key", retval);

	f = fopen(buf, "w+");
	if (f == NULL) {
		dolog(LOG_INFO, "fopen: %s\n", strerror(errno));
		snprintf(buf, sizeof(buf), "%s.private", retval);
		unlink(buf);
		RSA_free(rsa);
		return NULL;
	}
	
	fprintf(f, "; This is a %s key, keyid %d, for %s%s\n", (flags == 257) ? "key-signing" : "zone-signing", pid, zonename, (zonename[strlen(zonename) - 1] == '.') ? "" : ".");

	strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", tm);
	strftime(bin, sizeof(bin), "%c", tm);
	fprintf(f, "; Created: %s (%s)\n", buf, bin);
	fprintf(f, "; Publish: %s (%s)\n", buf, bin);
	fprintf(f, "; Activate: %s (%s)\n", buf, bin);

	/* bogus */
	p = &bin[0];
	binlen = BN_bn2bin(rsa->e, (char *)&bin[1]);
	len = binlen;
	*p = len;
	len++;
	binlen = BN_bn2bin(rsa->n, (char *)&bin[len]);
	len += binlen;
	binlen = len;
	len = mybase64_encode(bin, binlen, b64, sizeof(b64));
	fprintf(f, "%s%s %d IN DNSKEY %d 3 %d %s\n", zonename, (zonename[strlen(zonename) - 1] == '.') ? "" : ".", ttl, flags, algorithm, b64);

	fclose(f);
	RSA_free(rsa);
	
	return (retval);
}

char *
alg_to_name(int algorithm)
{
	
	switch (algorithm) {
	case ALGORITHM_RSASHA1:
		return ("RSASHA");
		break;
	case ALGORITHM_RSASHA256:
		return ("RSASHA256");
		break;
	case ALGORITHM_RSASHA512:
		return ("RSASHA512");
		break;
	}

	return (NULL);
}
