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
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/sha.h>

int debug = 0;
int verbose = 0;

/* prototypes */
void	dolog(int pri, char *fmt, ...);
int	add_dnskey(DB *, char *, char *);
char * 	parse_keyfile(int, uint32_t *, uint16_t *, uint8_t *, uint8_t *, char *, int *);
char *	create_key(char *, int, int, int, int);
void 	dump_db(DB *);
char * alg_to_name(int);
int alg_to_rsa(int);
int 	calculate_rrsigs(DB *, char *, char *, char *, int);
u_int keytag(u_char *key, u_int keysize);
void pack(char *, char *, int);
void pack32(char *, u_int32_t);
void pack16(char *, u_int16_t);
void pack8(char *, u_int8_t);
RSA * read_private_key(char *, int, int);
u_int64_t timethuman(time_t);



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
extern int fill_rrsig(char *, char *, u_int32_t, char *, u_int8_t, u_int8_t, u_int32_t, u_int64_t, u_int64_t, u_int16_t, char *, char *);
extern int      mybase64_encode(u_char const *, size_t, char *, size_t);
extern int      mybase64_decode(char const *, u_char *, size_t);
extern struct domain *         lookup_zone(DB *, struct question *, int *, int *, char *);
extern struct question         *build_fake_question(char *, int, u_int16_t);
extern char * dns_label(char *, int *);
extern void * find_substruct(struct domain *, u_int16_t);
extern int label_count(char *);
extern char *get_dns_type(int, int);




int
main(int argc, char *argv[])
{
	int ch;
	int ret, bits = 2048;
	int ttl = 86400;
	int create_zsk = 0;
	int create_ksk = 0;
	int algorithm = ALGORITHM_RSASHA256;
	int expiry = 5184000;

	key_t key;

	char *zonefile = NULL;
	char *zonename = NULL;
	
	char *ksk_key = NULL;
	char *zsk_key = NULL;
	
	DB *db;
	DB_ENV *dbenv;


	while ((ch = getopt(argc, argv, "a:B:e:I:i:Kk:n:o:s:t:Zz:")) != -1) {
		switch (ch) {
		case 'a':
			/* algorithm */
			algorithm = atoi(optarg);
			break;
	
		case 'B':
			/* bits */

			bits = atoi(optarg);
			break;
		case 'e':
			/* expiry */
		
			expiry = atoi(optarg);
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

	if (calculate_rrsigs(db, zonename, zsk_key, ksk_key, expiry) < 0) {
		dolog(LOG_INFO, "calculate rrsigs failed\n");
		exit(1);
	}

	/* third pass construct NSEC3 records */	

	/* write new zone file */
	dump_db(db);

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

	if (pri <= LOG_INFO) {
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
	int keyid;

	/* first the zsk */
	snprintf(buf, sizeof(buf), "%s.key", zsk_key);
	if ((fd = open(buf, O_RDONLY, 0)) < 0) {
		dolog(LOG_INFO, "open %s: %s\n", buf, strerror(errno));
		return -1;
	}

	if ((zone = parse_keyfile(fd, &ttl, &flags, &protocol, &algorithm, (char *)&key, &keyid)) == NULL) {
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

	if ((zone = parse_keyfile(fd, &ttl, &flags, &protocol, &algorithm, (char *)&key, &keyid)) == NULL) {
		dolog(LOG_INFO, "parse %s\n", buf);
		close (fd);
		return -1;
	}

	close(fd);
	
	if (fill_dnskey(zone, "dnskey", ttl, flags, protocol, algorithm, key) < 0) {
		return -1;
	}



	return 0;
}

char *
parse_keyfile(int fd, uint32_t *ttl, uint16_t *flags, uint8_t *protocol, uint8_t *algorithm, char *key, int *keyid)
{
	static char retbuf[256];
	char buf[8192];
	char *p, *q;
	FILE *f;

	if ((f = fdopen(fd, "r")) == NULL)
		return NULL;
	
	while (fgets(buf, sizeof(buf), f) != NULL) {
		if (buf[0] == ';') {
			if ((p = strstr(buf, "keyid ")) != NULL) {
				p += 6;
				q = strchr(p, ' ');
				if (q == NULL) 
					return NULL;
				*q = '\0';
				*keyid = atoi(p);
			}

			continue;
		}
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
	int i, j, rs;

        DBT key, data;
        DBC *cursor;
	
	struct domain *sdomain;
	struct domain_rrsig *sdrr;
	struct domain_dnskey *sddk;
	struct rrsig *rss;
	
	char buf[4096];
	int len;
	
	if (db->cursor(db, NULL, &cursor, 0) != 0) {
		dolog(LOG_INFO, "db->cursor: %s\n", strerror(errno));
		exit(1);
	}

	memset(&key, 0, sizeof(key));   
	memset(&data, 0, sizeof(data));

	if (cursor->c_get(cursor, &key, &data, DB_FIRST) != 0) {
		dolog(LOG_INFO, "cursor->c_get: %s\n", strerror(errno));
		exit(1);
	}

	
	j = 0;
	do {
		
		rs = data.size;
		if ((sdomain = calloc(1, rs)) == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			exit(1);
		}

		memcpy((char *)sdomain, (char *)data.data, data.size);

		printf("name: %s\n", sdomain->zonename);

		if (sdomain->flags & DOMAIN_HAVE_DNSKEY) {
			printf(" has dnskey\n");
			if ((sddk = (struct domain_dnskey *)find_substruct(sdomain, INTERNAL_TYPE_DNSKEY)) == NULL) {
				dolog(LOG_INFO, "no dnskeys in zone!\n");
			}
			for (i = 0; i < sddk->dnskey_count; i++) {
				len = mybase64_encode(sddk->dnskey[i].public_key, sddk->dnskey[i].publickey_len, buf, sizeof(buf));
				buf[len] = '\0';
				printf("%s,dnskey,%d,%d,%d,%d,%s\n", 
					sdomain->zonename,
					sdomain->ttl[INTERNAL_TYPE_DNSKEY],
					sddk->dnskey[i].flags,
					sddk->dnskey[i].protocol,
					sddk->dnskey[i].algorithm,
					buf);
			}
		}
		if (sdomain->flags & DOMAIN_HAVE_RRSIG) {
			printf(" has rrsig\n");
			
                	if ((sdrr = (struct domain_rrsig *)find_substruct(sdomain, INTERNAL_TYPE_RRSIG)) == NULL) {
				dolog(LOG_INFO, "no rrsigs in zone!\n");
			}

			if (sdrr->rrsig_dnskey_count > 0) {
				rss = (struct rrsig *)&sdrr->rrsig_dnskey[0];
				
				len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
				buf[len] = '\0';
			}

			printf("%s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,%s\n", 
				sdomain->zonename,
				sdomain->ttl[INTERNAL_TYPE_RRSIG],
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				rss->original_ttl, 
				timethuman(rss->signature_expiration),
				timethuman(rss->signature_inception), 
				rss->key_tag,
				sdomain->zonename,
				buf);	
		
	
		}

		j++;
	} while (cursor->c_get(cursor, &key, &data, DB_NEXT) == 0);

	printf("%d records\n", j);
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
	char tmp[4096];
	int i, binlen, len;
	u_int32_t pid;
	char *retval;
	char *p;
	time_t now;
	struct tm *tm;
	mode_t savemask;
	int rlen;

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

	/* get the keytag, this is a bit of a hard process */
	p = (char *)&bin[0];
	pack16(p, htons(flags));
	p+=2;
	pack8(p, 3);	/* protocol always 3 */
	p++;
 	pack8(p, algorithm);
	p++;
	binlen = BN_bn2bin(rsa->e, (char *)tmp); 
	/* RFC 3110 */
	if (binlen < 256) {
		*p = binlen;
		p++;
	} else {
		*p = 0;
		p++;
		pack16(p, htons(binlen));
		p += 2;
	}
	
	pack(p, tmp, binlen);
	p += binlen;
	binlen = BN_bn2bin(rsa->n, (char *)tmp);
	pack(p, tmp, binlen);
	p += binlen;
	rlen = (p - &bin[0]);
	pid = keytag(bin, rlen);
	
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

	savemask = umask(077);

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

	umask(savemask);
	f = fopen(buf, "w+");
	if (f == NULL) {
		dolog(LOG_INFO, "fopen: %s\n", strerror(errno));
		snprintf(buf, sizeof(buf), "%s.private", retval);
		unlink(buf);
		RSA_free(rsa);
		return NULL;
	}
	
	fprintf(f, "; This is a %s key, keyid %u, for %s%s\n", (flags == 257) ? "key-signing" : "zone-signing", pid, zonename, (zonename[strlen(zonename) - 1] == '.') ? "" : ".");

	strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", tm);
	strftime(bin, sizeof(bin), "%c", tm);
	fprintf(f, "; Created: %s (%s)\n", buf, bin);
	fprintf(f, "; Publish: %s (%s)\n", buf, bin);
	fprintf(f, "; Activate: %s (%s)\n", buf, bin);

	/* RFC 3110, section 2 */
	p = &bin[0];
	binlen = BN_bn2bin(rsa->e, (char *)tmp);
	if (binlen < 256) {
		*p = binlen;
		p++;
	} else {
		*p = 0;
		p++;
		pack16(p, htons(binlen));
		p += 2;
	}
	pack(p, tmp, binlen);
	p += binlen;
	binlen = BN_bn2bin(rsa->n, (char *)tmp);
	pack(p, tmp, binlen);
	p += binlen; 
	binlen = (p - &bin[0]);
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

int
alg_to_rsa(int algorithm)
{
	
	switch (algorithm) {
	case ALGORITHM_RSASHA1:
		return (NID_sha1);
		break;
	case ALGORITHM_RSASHA256:
		return (NID_sha256);
		break;
	case ALGORITHM_RSASHA512:
		return (NID_sha512);
		break;
	}

	return (-1);
}

int
calculate_rrsigs(DB *db, char *zonename, char *zsk_key, char *ksk_key, int expiry)
{
	struct question *q;
	struct domain *sd;
	struct domain_dnskey *sddk;

	char tmp[4096];
	char signature[4096];
	char buf[512];
	char shabuf[64];
	
	SHA_CTX sha1;
	SHA256_CTX sha256;
	SHA512_CTX sha512;

	char *dnsname;
	char *p;
	char *key;
	char *zone;
	char replystring[512];

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen, i;
	int retval, lzerrno;
	int keyid;
	int fd, len;
	int keylen, siglen;
	int rsatype;
	int bufsize;
	int labels;

	RSA *rsa;
	time_t now;

	char timebuf[32];
	u_int64_t expiredon, signedon;
	struct tm *tm;
	u_int32_t expiredon2, signedon2;

	memset(&shabuf, 0, sizeof(shabuf));

	now = time(NULL);
	tm = gmtime(&now);
	strftime(timebuf, sizeof(timebuf), "%Y%m%d%H%M%S", tm);
	signedon = atoll(timebuf);
	now += expiry;
	tm = gmtime(&now);
	strftime(timebuf, sizeof(timebuf), "%Y%m%d%H%M%S", tm);
	expiredon = atoll(timebuf);

#if 0
	signedon = 20160821133855;
	expiredon = 20161020133855;
#endif

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "out of memory\n");
		return -1;
	}

	/* get the KSK */
	snprintf(buf, sizeof(buf), "%s.key", ksk_key);
	if ((fd = open(buf, O_RDONLY, 0)) < 0) {
		dolog(LOG_INFO, "open %s: %s\n", buf, strerror(errno));
		return -1;
	}

	if ((zone = parse_keyfile(fd, &ttl, &flags, &protocol, &algorithm, (char *)&tmp, &keyid)) == NULL) {
		dolog(LOG_INFO, "parse %s\n", buf);
		close (fd);
		return -1;
	}

	close(fd);

	/* check the keytag supplied */
	p = key;
	pack16(p, htons(flags));
	p += 2;
	pack8(p, protocol);
	p++;
	pack8(p, algorithm);
	p++;
	keylen = mybase64_decode(tmp, (char *)&signature, sizeof(signature));
	pack(p, signature, keylen);
	p += keylen;
	keylen = (p - key);
	if (keyid != keytag(key, keylen)) {
		dolog(LOG_ERR, "keytag does not match %d vs. %d\n", keyid, keytag(key, keylen));
		return -1;
	}
	
	labels = label_count(zonename);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	q = build_fake_question(dnsname, labellen, DNS_TYPE_DNSKEY);
	if (q == NULL) {
		return -1;
	}

	if ((sd = lookup_zone(db, q, &retval, &lzerrno, (char *)&replystring)) == NULL) {
		return -1;
	}

	if (sd->flags & DOMAIN_HAVE_DNSKEY) {
                if ((sddk = (struct domain_dnskey *)find_substruct(sd, INTERNAL_TYPE_DNSKEY)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in apex!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_DNSKEY));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_DNSKEY]));
	p += 4;
		
	snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
	strptime(timebuf, "%Y%m%d%H%M%S", tm);
	expiredon2 = timegm(tm);
	snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
	strptime(timebuf, "%Y%m%d%H%M%S", tm);
	signedon2 = timegm(tm);

	pack32(p, htonl(expiredon2));
	p += 4;
	pack32(p, htonl(signedon2));	
	p += 4;
	pack16(p, htons(keyid));
	p += 2;
	pack(p, dnsname, labellen);
	p += labellen;

	/* no signature here */	
	
	for (i = 0; i < sddk->dnskey_count; i++) {
		pack(p, dnsname, labellen);
		p += labellen;
		pack16(p, htons(DNS_TYPE_DNSKEY));
		p += 2;
		pack16(p, htons(DNS_CLASS_IN));
		p += 2;
		pack32(p, htonl(sd->ttl[INTERNAL_TYPE_DNSKEY]));
		p += 4;
		pack16(p, htons(2 + 1 + 1 + sddk->dnskey[i].publickey_len));
		p += 2;
		pack16(p, htons(sddk->dnskey[i].flags));
		p += 2;
		pack8(p, sddk->dnskey[i].protocol);
		p++;
		pack8(p, sddk->dnskey[i].algorithm);
		p++;
		pack(p, sddk->dnskey[i].public_key, sddk->dnskey[i].publickey_len);
		p += sddk->dnskey[i].publickey_len;
	}
	keylen = (p - key);	

#if 0
	fd = open("bindump.bin", O_WRONLY | O_CREAT | O_TRUNC, 0600);
	for (i = 0; i < keylen; i++) {
		write(fd, (char *)&key[i], 1);
	}
	close(fd);
	
#endif

	switch (algorithm) {
	case ALGORITHM_RSASHA1:
		SHA1_Init(&sha1);
		SHA1_Update(&sha1, key, keylen);
		SHA1_Final((u_char *)shabuf, &sha1);
		bufsize = 20;
		break;
	case ALGORITHM_RSASHA256:	
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, key, keylen);
		SHA256_Final((u_char *)shabuf, &sha256);
		bufsize = 32;

#if 0
		printf("keylen = %d\n", keylen);
		fd = open("bindump-sha256.bin", O_WRONLY | O_CREAT | O_TRUNC, 0600);
		for (i = 0; i < bufsize; i++) {
			write(fd, (char *)&shabuf[i], 1);
		}
		close(fd);
#endif

		break;
	case ALGORITHM_RSASHA512:
		SHA512_Init(&sha512);
		SHA512_Update(&sha512, &key, keylen);
		SHA512_Final((u_char *)shabuf, &sha512);
		bufsize = 64;
		break;
	default:
		return -1;
	}
		
	rsa = read_private_key(zonename, keyid, algorithm);
	if (rsa == NULL) {
		dolog(LOG_INFO, "reading private key failed\n");
		return -1;
	}
		
	rsatype = alg_to_rsa(algorithm);
	if (rsatype == -1) {
		dolog(LOG_INFO, "algorithm mismatch\n");
		return -1;
	}

	if (RSA_sign(rsatype, (u_char *)shabuf, bufsize, (u_char *)signature, &siglen, rsa) != 1) {
		dolog(LOG_INFO, "unable to sign with algorithm %d: %s\n", algorithm, ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(zonename, "RRSIG", ttl, "DNSKEY", algorithm, labels, sd->ttl[INTERNAL_TYPE_DNSKEY], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}

/* 
 * From RFC 4034, appendix b 
 */

u_int 
keytag(u_char *key, u_int keysize)
{
	u_long ac;
	int i;
	
	for (ac = 0, i = 0; i < keysize; ++i)
		ac += (i & 1) ? key[i] : key[i] << 8;
	ac += (ac >> 16) & 0xffff;
	
	return ac & 0xffff;
}


/* pack functions */

void
pack32(char *buf, u_int32_t value)
{
	u_int32_t *p;

	p = (u_int32_t *)buf;
	*p = value;
}	

void
pack16(char *buf, u_int16_t value)
{
	u_int16_t *p;

	p = (u_int16_t *)buf;
	*p = value;
}

void
pack8(char *buf, u_int8_t value)
{
	u_int8_t *p;

	p = (u_int8_t *)buf;
	*p = value;
}

void
pack(char *buf, char *input, int len)
{
	memcpy(buf, input, len);
}	


RSA *
read_private_key(char *zonename, int keyid, int algorithm)
{
	FILE *f;
	RSA *rsa;

	char buf[4096];
	char key[4096];
	char *p, *q;

	int keylen;

	rsa = RSA_new();
	if (rsa == NULL) {
		dolog(LOG_INFO, "RSA creation\n");
		return NULL;
	}

	snprintf(buf, sizeof(buf), "K%s%s+%03d+%d.private", zonename,
		(zonename[strlen(zonename) - 1] == '.') ? "" : ".",
		algorithm, keyid);

	f = fopen(buf, "r");
	if (f == NULL) {
		dolog(LOG_INFO, "fopen: %s\n", strerror(errno));
		return NULL;
	}
		
	while (fgets(buf, sizeof(buf), f) != NULL) {
		if ((p = strstr(buf, "Private-key-format: ")) != NULL) {
			p += 20;
			if (strncmp(p, "v1.3", 4) != 0) {
				dolog(LOG_INFO, "wrong private key version %s", p);
				return NULL;
			}	
		} else if ((p = strstr(buf, "Algorithm: ")) != NULL) {
			p += 11;

			q = strchr(p, ' ');
			if (q == NULL) {
				dolog(LOG_INFO, "bad parse of private key 1\n");
				return NULL;
			}
			*q = '\0';
	
			if (algorithm != atoi(p)) {
				dolog(LOG_INFO, "ZSK .key and .private file do not agree on algorithm %d\n", atoi(p));
				return NULL;
			}
		} else if ((p = strstr(buf, "Modulus: ")) != NULL) {
			p += 9;
	
			keylen = mybase64_decode(p, (char *)&key, sizeof(key));
			if ((rsa->n = BN_bin2bn(key, keylen, NULL)) == NULL)  {
				dolog(LOG_INFO, "BN_bin2bn failed\n");
				return NULL;
			}
		} else if ((p = strstr(buf, "PublicExponent: ")) != NULL) {
			p += 16;	

			keylen = mybase64_decode(p, (char *)&key, sizeof(key));
			if ((rsa->e = BN_bin2bn(key, keylen, NULL)) == NULL) {
				dolog(LOG_INFO, "BN_bin2bn failed\n");
				return NULL;
			}
		} else if ((p = strstr(buf, "PrivateExponent: ")) != NULL) {
			p += 17;

			keylen = mybase64_decode(p, (char *)&key, sizeof(key));
			if ((rsa->d = BN_bin2bn(key, keylen, NULL)) == NULL) {
				dolog(LOG_INFO, "BN_bin2bn failed\n");
				return NULL;
			}
		} else if ((p = strstr(buf, "Prime1: ")) != NULL) {
			p += 8;

			keylen = mybase64_decode(p, (char *)&key, sizeof(key));
			if ((rsa->p = BN_bin2bn(key, keylen, NULL)) == NULL) {
				dolog(LOG_INFO, "BN_bin2bn failed\n");
				return NULL;
			}
		} else if ((p = strstr(buf, "Prime2: ")) != NULL) {
			p += 8;

			keylen = mybase64_decode(p, (char *)&key, sizeof(key));
			if ((rsa->q = BN_bin2bn(key, keylen, NULL)) == NULL) {
				dolog(LOG_INFO, "BN_bin2bn failed\n");
				return NULL;
			}
		} else if ((p = strstr(buf, "Exponent1: ")) != NULL) {
			p += 11;

			keylen = mybase64_decode(p, (char *)&key, sizeof(key));
			if ((rsa->dmp1 = BN_bin2bn(key, keylen, NULL)) == NULL) {
				dolog(LOG_INFO, "BN_bin2bn failed\n");
				return NULL;
			}
		} else if ((p = strstr(buf, "Exponent2: ")) != NULL) {
			p += 11;

			keylen = mybase64_decode(p, (char *)&key, sizeof(key));
			if ((rsa->dmq1 = BN_bin2bn(key, keylen, NULL)) == NULL) {
				dolog(LOG_INFO, "BN_bin2bn failed\n");
				return NULL;
			}
		} else if ((p = strstr(buf, "Coefficient: ")) != NULL) {
			p += 13;

			keylen = mybase64_decode(p, (char *)&key, sizeof(key));
			if ((rsa->iqmp = BN_bin2bn(key, keylen, NULL)) == NULL) {
				dolog(LOG_INFO, "BN_bin2bn failed\n");
				return NULL;
			}
		}
	} /* fgets */

	fclose(f);
	return (rsa);
	
}

u_int64_t
timethuman(time_t timet)
{
	char timebuf[512];
	struct tm *tm;
	u_int64_t retbuf;

	tm = gmtime((time_t *)&timet);
	strftime(timebuf, sizeof(timebuf), "%Y%m%d%H%M%S", tm);
	retbuf = atoll(timebuf);

	return(retbuf);
}
