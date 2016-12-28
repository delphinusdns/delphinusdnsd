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
int 	construct_nsec3(DB *, char *, int, char *);
int 	calculate_rrsigs(DB *, char *, char *, char *, int);
int	sign_dnskey(DB *, char *, char *, char *, int, struct domain *);
int 	sign_a(DB *, char *, char *, int, struct domain *);
int 	sign_mx(DB *, char *, char *, int, struct domain *);
int 	sign_ns(DB *, char *, char *, int, struct domain *);
int 	sign_spf(DB *, char *, char *, int, struct domain *);
int 	sign_soa(DB *, char *, char *, int, struct domain *);
int	sign_txt(DB *, char *, char *, int, struct domain *);
int	sign_aaaa(DB *, char *, char *, int, struct domain *);
int	sign_nsec3param(DB *, char *, char *, int, struct domain *);
u_int keytag(u_char *key, u_int keysize);
void pack(char *, char *, int);
void pack32(char *, u_int32_t);
void pack16(char *, u_int16_t);
void pack8(char *, u_int8_t);
RSA * read_private_key(char *, int, int);
u_int64_t timethuman(time_t);
char * bitmap2human(char *, int);
char * bin2hex(char *, int);



#define ALGORITHM_RSASHA1	5		/* rfc 4034 , mandatory */
#define ALGORITHM_RSASHA256	8		/* rfc 5702 */
#define ALGORITHM_RSASHA512	10		/* rfc 5702 */

#define RSA_F5			0x100000001

#define PROVIDED_SIGNTIME			1
#define	SIGNEDON				20161129083129
#define EXPIREDON 				20170128083129

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
extern int fill_nsec3param(char *, char *, u_int32_t, u_int8_t, u_int8_t, u_int16_t, char *);
extern int fill_nsec3(char *, char *, u_int32_t, u_int8_t, u_int8_t, u_int16_t, char *, char *, char *);
extern char * convert_name(char *name, int namelen);

extern int      mybase64_encode(u_char const *, size_t, char *, size_t);
extern int      mybase64_decode(char const *, u_char *, size_t);
extern struct domain *         lookup_zone(DB *, struct question *, int *, int *, char *);
extern struct question         *build_fake_question(char *, int, u_int16_t);
extern char * dns_label(char *, int *);
extern void * find_substruct(struct domain *, u_int16_t);
extern int label_count(char *);
extern char *get_dns_type(int, int);
extern char * hash_name(char *, int, struct nsec3param *);
extern char * base32hex_encode(u_char *input, int len);



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
	int iterations = 10;

	key_t key;

	char *salt = "-";
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
			iterations = atoi(optarg);	
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

		case 's':
			/* salt */
			salt = optarg;
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

	/* second pass construct NSEC3 records */	

	if (construct_nsec3(db, zonename, iterations, salt) < 0) {
		dolog(LOG_INFO, "construct nsec3 failed\n");
		exit(1);
	}

	/* third  pass calculate RRSIG's for every RR set */

	if (calculate_rrsigs(db, zonename, zsk_key, ksk_key, expiry) < 0) {
		dolog(LOG_INFO, "calculate rrsigs failed\n");
		exit(1);
	}

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
	struct domain_nsec3 *sdn3;
	struct domain_nsec3param *sdn3param;
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
		if (sdomain->flags & DOMAIN_HAVE_NSEC3PARAM) {
			printf("has nsec3param\n");
			if ((sdn3param = (struct domain_nsec3param *)find_substruct(sdomain, INTERNAL_TYPE_NSEC3PARAM)) == NULL) {
				dolog(LOG_INFO, "no nsec3param in zone!\n");
			}
			
			printf("%s,nsec3param,%d,%d,%d,%d,\"%s\"\n",
				sdomain->zonename,
				sdomain->ttl[INTERNAL_TYPE_NSEC3PARAM],
				sdn3param->nsec3param.algorithm,
				sdn3param->nsec3param.flags,
				sdn3param->nsec3param.iterations,
				(sdn3param->nsec3param.saltlen == 0) ? "-" : bin2hex(sdn3param->nsec3param.salt, sdn3param->nsec3param.saltlen));
		}
		if (sdomain->flags & DOMAIN_HAVE_NSEC3) {
			printf("has nsec3\n");
			if ((sdn3 = (struct domain_nsec3 *)find_substruct(sdomain, INTERNAL_TYPE_NSEC3)) == NULL) {
				dolog(LOG_INFO, "no nsec3 in zone!\n");
			}
			
			printf("%s,nsec3,%d,%d,%d,%d,\"%s\",\"%s\",\"%s\"\n",
				sdomain->zonename,
				sdomain->ttl[INTERNAL_TYPE_NSEC3],
				sdn3->nsec3.algorithm,
				sdn3->nsec3.flags,
				sdn3->nsec3.iterations,
				(sdn3->nsec3.saltlen == 0) ? "-" : bin2hex(sdn3->nsec3.salt, sdn3->nsec3.saltlen),
				base32hex_encode(sdn3->nsec3.next, sdn3->nsec3.nextlen),
				bitmap2human(sdn3->nsec3.bitmap, sdn3->nsec3.bitmap_len));

		}
		if (sdomain->flags & DOMAIN_HAVE_RRSIG) {
			printf(" has rrsig\n");
			
                	if ((sdrr = (struct domain_rrsig *)find_substruct(sdomain, INTERNAL_TYPE_RRSIG)) == NULL) {
				dolog(LOG_INFO, "no rrsigs in zone!\n");
			}

			if ((sdomain->flags & DOMAIN_HAVE_DNSKEY) && sdrr->rrsig_dnskey_count > 0) {
				for (i = 0; i < sdrr->rrsig_dnskey_count; i++) {
					rss = (struct rrsig *)&sdrr->rrsig_dnskey[i];
					len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
					buf[len] = '\0';

					printf("%s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
						sdomain->zonename,
						sdomain->ttl[INTERNAL_TYPE_RRSIG],
						get_dns_type(rss->type_covered, 0), 
						rss->algorithm, rss->labels,
						rss->original_ttl, 
						timethuman(rss->signature_expiration),
						timethuman(rss->signature_inception), 
						rss->key_tag,
						convert_name(rss->signers_name, rss->signame_len),
						buf);	
				}
			}
			if (sdomain->flags & DOMAIN_HAVE_SOA) {
				rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_SOA];
				len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
				buf[len] = '\0';

				printf("%s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
					sdomain->zonename,
					sdomain->ttl[INTERNAL_TYPE_RRSIG],
					get_dns_type(rss->type_covered, 0), 
					rss->algorithm, rss->labels,
					rss->original_ttl, 
					timethuman(rss->signature_expiration),
					timethuman(rss->signature_inception), 
					rss->key_tag,
					convert_name(rss->signers_name, rss->signame_len),
					buf);	
			}

			if (sdomain->flags & DOMAIN_HAVE_TXT) {
				rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_TXT];
				len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
				buf[len] = '\0';

				printf("%s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
					sdomain->zonename,
					sdomain->ttl[INTERNAL_TYPE_RRSIG],
					get_dns_type(rss->type_covered, 0), 
					rss->algorithm, rss->labels,
					rss->original_ttl, 
					timethuman(rss->signature_expiration),
					timethuman(rss->signature_inception), 
					rss->key_tag,
					convert_name(rss->signers_name, rss->signame_len),
					buf);	
			}

			if (sdomain->flags & DOMAIN_HAVE_AAAA) {
				rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_AAAA];
				len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
				buf[len] = '\0';

				printf("%s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
					sdomain->zonename,
					sdomain->ttl[INTERNAL_TYPE_RRSIG],
					get_dns_type(rss->type_covered, 0), 
					rss->algorithm, rss->labels,
					rss->original_ttl, 
					timethuman(rss->signature_expiration),
					timethuman(rss->signature_inception), 
					rss->key_tag,
					convert_name(rss->signers_name, rss->signame_len),
					buf);	
			}

			if (sdomain->flags & DOMAIN_HAVE_NSEC3PARAM) {
				rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_NSEC3PARAM];
				len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
				buf[len] = '\0';

				printf("%s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
					sdomain->zonename,
					sdomain->ttl[INTERNAL_TYPE_RRSIG],
					get_dns_type(rss->type_covered, 0), 
					rss->algorithm, rss->labels,
					rss->original_ttl, 
					timethuman(rss->signature_expiration),
					timethuman(rss->signature_inception), 
					rss->key_tag,
					convert_name(rss->signers_name, rss->signame_len),
					buf);	
			}

			if (sdomain->flags & DOMAIN_HAVE_SPF) {
				rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_SPF];
				len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
				buf[len] = '\0';

				printf("%s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
					sdomain->zonename,
					sdomain->ttl[INTERNAL_TYPE_RRSIG],
					get_dns_type(rss->type_covered, 0), 
					rss->algorithm, rss->labels,
					rss->original_ttl, 
					timethuman(rss->signature_expiration),
					timethuman(rss->signature_inception), 
					rss->key_tag,
					convert_name(rss->signers_name, rss->signame_len),
					buf);	
			}



			if (sdomain->flags & DOMAIN_HAVE_NS) {
				rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_NS];
				len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
				buf[len] = '\0';

				printf("%s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
					sdomain->zonename,
					sdomain->ttl[INTERNAL_TYPE_RRSIG],
					get_dns_type(rss->type_covered, 0), 
					rss->algorithm, rss->labels,
					rss->original_ttl, 
					timethuman(rss->signature_expiration),
					timethuman(rss->signature_inception), 
					rss->key_tag,
					convert_name(rss->signers_name, rss->signame_len),
					buf);	
			}

			if (sdomain->flags & DOMAIN_HAVE_MX) {
				rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_MX];
				len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
				buf[len] = '\0';

				printf("%s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
					sdomain->zonename,
					sdomain->ttl[INTERNAL_TYPE_RRSIG],
					get_dns_type(rss->type_covered, 0), 
					rss->algorithm, rss->labels,
					rss->original_ttl, 
					timethuman(rss->signature_expiration),
					timethuman(rss->signature_inception), 
					rss->key_tag,
					convert_name(rss->signers_name, rss->signame_len),
					buf);	
			}

			if (sdomain->flags & DOMAIN_HAVE_A) {
				rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_A];
				len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
				buf[len] = '\0';

				printf("%s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
					sdomain->zonename,
					sdomain->ttl[INTERNAL_TYPE_RRSIG],
					get_dns_type(rss->type_covered, 0), 
					rss->algorithm, rss->labels,
					rss->original_ttl, 
					timethuman(rss->signature_expiration),
					timethuman(rss->signature_inception), 
					rss->key_tag,
					convert_name(rss->signers_name, rss->signame_len),
					buf);	
			}
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
        DBT key, data;
        DBC *cursor;
	
	struct domain *sd;
	int j, rs;

	/* set cursor on database */
	
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
		if ((sd = calloc(1, rs)) == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			exit(1);
		}

		memcpy((char *)sd, (char *)data.data, data.size);
		
		if (sd->flags & DOMAIN_HAVE_DNSKEY)
			if (sign_dnskey(db, zonename, zsk_key, ksk_key, expiry, sd) < 0)
				return -1;
		if (sd->flags & DOMAIN_HAVE_A)
			if (sign_a(db, zonename, zsk_key, expiry, sd) < 0)
				return -1;
		if (sd->flags & DOMAIN_HAVE_MX)
			if (sign_mx(db, zonename, zsk_key, expiry, sd) < 0)
				return -1;
		if (sd->flags & DOMAIN_HAVE_NS)
			if (sign_ns(db, zonename, zsk_key, expiry, sd) < 0)
				return -1;
		if (sd->flags & DOMAIN_HAVE_SOA)
			if (sign_soa(db, zonename, zsk_key, expiry, sd) < 0)
				return -1;
		if (sd->flags & DOMAIN_HAVE_TXT)
			if (sign_txt(db, zonename, zsk_key, expiry, sd) < 0)
				return -1;
		if (sd->flags & DOMAIN_HAVE_AAAA)
			if (sign_aaaa(db, zonename, zsk_key, expiry, sd) < 0)
				return -1;
		if (sd->flags & DOMAIN_HAVE_NSEC3PARAM)
			if (sign_nsec3param(db, zonename, zsk_key, expiry, sd) < 0)
				return -1;
		if (sd->flags & DOMAIN_HAVE_SPF)
			if (sign_spf(db, zonename, zsk_key, expiry, sd) < 0)
				return -1;

		j++;
	} while (cursor->c_get(cursor, &key, &data, DB_NEXT) == 0);
	
		
	return 0;
}

/*
 * create a RRSIG for an SOA record
 */

int
sign_soa(DB *db, char *zonename, char *zsk_key, int expiry, struct domain *sd)
{
	struct domain_soa *sdsoa;

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

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
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

#if PROVIDED_SIGNTIME
        signedon = SIGNEDON;
        expiredon = EXPIREDON;
#endif


	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "out of memory\n");
		return -1;
	}

	/* get the ZSK */
	snprintf(buf, sizeof(buf), "%s.key", zsk_key);
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
	
	labels = label_count(sd->zonename);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_SOA) {
                if ((sdsoa = (struct domain_soa *)find_substruct(sd, INTERNAL_TYPE_SOA)) == NULL) {
			dolog(LOG_INFO, "no SOA records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_SOA));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_SOA]));
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
	/* XXX this should probably be done on a canonical sorted records */
	
	pack(p, sd->zone, sd->zonelen);
	p += sd->zonelen;
	pack16(p, htons(DNS_TYPE_SOA));
	p += 2;
	pack16(p, htons(DNS_CLASS_IN));
	p += 2;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_SOA]));
	p += 4;
	pack16(p, htons(sdsoa->soa.nsserver_len + sdsoa->soa.rp_len + 4 + 4 + 4 + 4 + 4));
	p += 2;
	pack(p, sdsoa->soa.nsserver, sdsoa->soa.nsserver_len);
	p += sdsoa->soa.nsserver_len;
	pack(p, sdsoa->soa.responsible_person, sdsoa->soa.rp_len);
	p += sdsoa->soa.rp_len;
	pack32(p, htonl(sdsoa->soa.serial));
	p += 4;
	pack32(p, htonl(sdsoa->soa.refresh));
	p += 4;
	pack32(p, htonl(sdsoa->soa.retry));
	p += 4;
	pack32(p, htonl(sdsoa->soa.expire));
	p += 4;
	pack32(p, htonl(sdsoa->soa.minttl));
	p += 4;

	keylen = (p - key);	

#if 0
	{
		int i;
	fd = open("bindump.bin", O_WRONLY | O_CREAT | O_TRUNC, 0600);
	for (i = 0; i < keylen; i++) {
		write(fd, (char *)&key[i], 1);
	}
	close(fd);
	}
	
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

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_SOA], "SOA", algorithm, labels, sd->ttl[INTERNAL_TYPE_SOA], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}

/*
 * create a RRSIG for a TXT record
 */

int
sign_txt(DB *db, char *zonename, char *zsk_key, int expiry, struct domain *sd)
{
	struct domain_txt *sdtxt;

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

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
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

#if PROVIDED_SIGNTIME
        signedon = SIGNEDON;
        expiredon = EXPIREDON;
#endif


	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "out of memory\n");
		return -1;
	}

	/* get the ZSK */
	snprintf(buf, sizeof(buf), "%s.key", zsk_key);
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
	
	labels = label_count(sd->zonename);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_TXT) {
                if ((sdtxt = (struct domain_txt *)find_substruct(sd, INTERNAL_TYPE_TXT)) == NULL) {
			dolog(LOG_INFO, "no TXT records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_TXT));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_TXT]));
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
	/* XXX this should probably be done on a canonical sorted records */

	pack(p, sd->zone, sd->zonelen);
	p += sd->zonelen;
	pack16(p, htons(DNS_TYPE_TXT));
	p += 2;
	pack16(p, htons(DNS_CLASS_IN));
	p += 2;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_TXT]));
	p += 4;
	pack16(p, htons(sdtxt->txtlen + 1));
	p += 2;
	pack8(p, sdtxt->txtlen);
	p++;
	pack(p, sdtxt->txt, sdtxt->txtlen);
	p += sdtxt->txtlen;

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

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_TXT], "TXT", algorithm, labels, sd->ttl[INTERNAL_TYPE_TXT], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}

/*
 * create a RRSIG for an AAAA record
 */

int
sign_aaaa(DB *db, char *zonename, char *zsk_key, int expiry, struct domain *sd)
{
	struct domain_aaaa *sdaaaa;

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

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen, i;
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

#if PROVIDED_SIGNTIME
        signedon = SIGNEDON;
        expiredon = EXPIREDON;
#endif


	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "out of memory\n");
		return -1;
	}

	/* get the ZSK */
	snprintf(buf, sizeof(buf), "%s.key", zsk_key);
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
	
	labels = label_count(sd->zonename);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_AAAA) {
                if ((sdaaaa = (struct domain_aaaa *)find_substruct(sd, INTERNAL_TYPE_AAAA)) == NULL) {
			dolog(LOG_INFO, "no AAAA records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_AAAA));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_AAAA]));
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
	/* XXX this should probably be done on a canonical sorted records */
	
	for (i = 0; i < sdaaaa->aaaa_count; i++) {
		pack(p, sd->zone, sd->zonelen);
		p += sd->zonelen;
		pack16(p, htons(DNS_TYPE_AAAA));
		p += 2;
		pack16(p, htons(DNS_CLASS_IN));
		p += 2;
		pack32(p, htonl(sd->ttl[INTERNAL_TYPE_AAAA]));
		p += 4;
		pack16(p, htons(sizeof(struct in6_addr)));
		p += 2;
		pack(p, (char *)&sdaaaa->aaaa[i], sizeof(struct in6_addr));
		p += sizeof(struct in6_addr);
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

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_AAAA], "AAAA", algorithm, labels, sd->ttl[INTERNAL_TYPE_AAAA], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}


/*
 * create a RRSIG for an NSEC3PARAM record
 */

int
sign_nsec3param(DB *db, char *zonename, char *zsk_key, int expiry, struct domain *sd)
{
	struct domain_nsec3param *sdnsec3;

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

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
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

#if PROVIDED_SIGNTIME
        signedon = SIGNEDON;
        expiredon = EXPIREDON;
#endif


	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "out of memory\n");
		return -1;
	}

	/* get the ZSK */
	snprintf(buf, sizeof(buf), "%s.key", zsk_key);
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
	
	labels = label_count(sd->zonename);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_NSEC3PARAM) {
                if ((sdnsec3 = (struct domain_nsec3param *)find_substruct(sd, INTERNAL_TYPE_NSEC3PARAM)) == NULL) {
			dolog(LOG_INFO, "no NSEC3PARAM records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_NSEC3PARAM));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_NSEC3PARAM]));
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
	/* XXX this should probably be done on a canonical sorted records */
	
	pack(p, sd->zone, sd->zonelen);
	p += sd->zonelen;
	pack16(p, htons(DNS_TYPE_NSEC3PARAM));
	p += 2;
	pack16(p, htons(DNS_CLASS_IN));
	p += 2;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_NSEC3PARAM]));
	p += 4;
	if (sdnsec3->nsec3param.saltlen)
		pack16(p, htons(1 + 1 + 2 + sdnsec3->nsec3param.saltlen));
	else
		pack16(p, htons(1 + 1 + 2 + 1));
	p += 2;
	pack8(p, sdnsec3->nsec3param.algorithm);
	p++;
	pack8(p, sdnsec3->nsec3param.flags);
	p++;
	pack16(p, htons(sdnsec3->nsec3param.iterations));
	p += 2;
		
	if (sdnsec3->nsec3param.saltlen) {
		pack(p, sdnsec3->nsec3param.salt, sdnsec3->nsec3param.saltlen);
		p += sdnsec3->nsec3param.saltlen;
	} else {
		pack(p, sdnsec3->nsec3param.salt, 1);
		p++;
	}
	
	keylen = (p - key);	

#if 0
	{
		int i;
	fd = open("bindump.bin", O_WRONLY | O_CREAT | O_TRUNC, 0600);
	for (i = 0; i < keylen; i++) {
		write(fd, (char *)&key[i], 1);
	}
	close(fd);
	}
	
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

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_NSEC3PARAM], "NSEC3PARAM", algorithm, labels, sd->ttl[INTERNAL_TYPE_NSEC3PARAM], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}

/*
 * create a RRSIG for an SPF record
 */

int
sign_spf(DB *db, char *zonename, char *zsk_key, int expiry, struct domain *sd)
{
	struct domain_spf *sdspf;

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

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen;
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

#if PROVIDED_SIGNTIME
        signedon = SIGNEDON;
        expiredon = EXPIREDON;
#endif


	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "out of memory\n");
		return -1;
	}

	/* get the ZSK */
	snprintf(buf, sizeof(buf), "%s.key", zsk_key);
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
	
	labels = label_count(sd->zonename);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_SPF) {
                if ((sdspf= (struct domain_spf *)find_substruct(sd, INTERNAL_TYPE_SPF)) == NULL) {
			dolog(LOG_INFO, "no SPF records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_SPF));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_SPF]));
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
	/* XXX this should probably be done on a canonical sorted records */
	
	pack(p, sd->zone, sd->zonelen);
	p += sd->zonelen;
	pack16(p, htons(DNS_TYPE_SPF));
	p += 2;
	pack16(p, htons(DNS_CLASS_IN));
	p += 2;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_SPF]));
	p += 4;
	pack16(p, htons(1 + sdspf->spflen));
	p += 2;
	pack8(p, sdspf->spflen);
	p++;
	pack(p, sdspf->spf, sdspf->spflen);
	p += sdspf->spflen;

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

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_SPF], "SPF", algorithm, labels, sd->ttl[INTERNAL_TYPE_SPF], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}




/*
 * create a RRSIG for an NS record
 */

int
sign_ns(DB *db, char *zonename, char *zsk_key, int expiry, struct domain *sd)
{
	struct domain_ns *sdns;

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

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen, i;
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

#if PROVIDED_SIGNTIME
        signedon = SIGNEDON;
        expiredon = EXPIREDON;
#endif


	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "out of memory\n");
		return -1;
	}

	/* get the ZSK */
	snprintf(buf, sizeof(buf), "%s.key", zsk_key);
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
	
	labels = label_count(sd->zonename);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_NS) {
                if ((sdns = (struct domain_ns *)find_substruct(sd, INTERNAL_TYPE_NS)) == NULL) {
			dolog(LOG_INFO, "no NS records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_NS));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_NS]));
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
	/* XXX this should probably be done on a canonical sorted records */
	
	for (i = 0; i < sdns->ns_count; i++) {
		pack(p, sd->zone, sd->zonelen);
		p += sd->zonelen;
		pack16(p, htons(DNS_TYPE_NS));
		p += 2;
		pack16(p, htons(DNS_CLASS_IN));
		p += 2;
		pack32(p, htonl(sd->ttl[INTERNAL_TYPE_NS]));
		p += 4;
		pack16(p, htons(sdns->ns[i].nslen));
		p += 2;
		memcpy(p, sdns->ns[i].nsserver, sdns->ns[i].nslen);
		p += sdns->ns[i].nslen;
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

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_NS], "NS", algorithm, labels, sd->ttl[INTERNAL_TYPE_NS], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}

/*
 * create a RRSIG for an MX record
 */

int
sign_mx(DB *db, char *zonename, char *zsk_key, int expiry, struct domain *sd)
{
	struct domain_mx *sdmx;

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

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen, i;
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

#if PROVIDED_SIGNTIME
        signedon = SIGNEDON;
        expiredon = EXPIREDON;
#endif


	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "out of memory\n");
		return -1;
	}

	/* get the ZSK */
	snprintf(buf, sizeof(buf), "%s.key", zsk_key);
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
	
	labels = label_count(sd->zonename);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_MX) {
                if ((sdmx = (struct domain_mx *)find_substruct(sd, INTERNAL_TYPE_MX)) == NULL) {
			dolog(LOG_INFO, "no MX records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_MX));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_MX]));
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
	/* XXX this should probably be done on a canonical sorted records */
	
	for (i = 0; i < sdmx->mx_count; i++) {
		pack(p, sd->zone, sd->zonelen);
		p += sd->zonelen;
		pack16(p, htons(DNS_TYPE_MX));
		p += 2;
		pack16(p, htons(DNS_CLASS_IN));
		p += 2;
		pack32(p, htonl(sd->ttl[INTERNAL_TYPE_MX]));
		p += 4;
		pack16(p, htons(2 + sdmx->mx[i].exchangelen));
		p += 2;
		pack16(p, htons(sdmx->mx[i].preference));
		p += 2;
		memcpy(p, sdmx->mx[i].exchange, sdmx->mx[i].exchangelen);
		p += sdmx->mx[i].exchangelen;
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

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_MX], "MX", algorithm, labels, sd->ttl[INTERNAL_TYPE_MX], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}


/*
 * create a RRSIG for an A record
 */

int
sign_a(DB *db, char *zonename, char *zsk_key, int expiry, struct domain *sd)
{
	struct domain_a *sda;

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

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen, i;
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

#if PROVIDED_SIGNTIME
        signedon = SIGNEDON;
        expiredon = EXPIREDON;
#endif


	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "out of memory\n");
		return -1;
	}

	/* get the ZSK */
	snprintf(buf, sizeof(buf), "%s.key", zsk_key);
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
	
	labels = label_count(sd->zonename);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_A) {
                if ((sda = (struct domain_a *)find_substruct(sd, INTERNAL_TYPE_A)) == NULL) {
			dolog(LOG_INFO, "no A records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_A));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_A]));
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
	/* XXX this should probably be done on a canonical sorted records */
	
	for (i = 0; i < sda->a_count; i++) {
		pack(p, sd->zone, sd->zonelen);
		p += sd->zonelen;
		pack16(p, htons(DNS_TYPE_A));
		p += 2;
		pack16(p, htons(DNS_CLASS_IN));
		p += 2;
		pack32(p, htonl(sd->ttl[INTERNAL_TYPE_A]));
		p += 4;
		pack16(p, htons(sizeof(in_addr_t)));
		p += 2;
		pack32(p, sda->a[i]);
		p += 4;
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

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_A], "A", algorithm, labels, sd->ttl[INTERNAL_TYPE_A], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}

int
sign_dnskey(DB *db, char *zonename, char *zsk_key, char *ksk_key, int expiry, struct domain *sd)
{
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

	uint32_t ttl;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen, i;
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

#if PROVIDED_SIGNTIME
        signedon = SIGNEDON;
        expiredon = EXPIREDON;
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
	
	labels = label_count(sd->zonename);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

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

	if (fill_rrsig(sd->zonename, "RRSIG", ttl, "DNSKEY", algorithm, labels, sd->ttl[INTERNAL_TYPE_DNSKEY], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}

	/* now work out the ZSK */
	snprintf(buf, sizeof(buf), "%s.key", zsk_key);
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
	
	labels = label_count(sd->zonename);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

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

	if (fill_rrsig(sd->zonename, "RRSIG", ttl, "DNSKEY", algorithm, labels, sd->ttl[INTERNAL_TYPE_DNSKEY], expiredon, signedon, keyid, zonename, tmp) < 0) {
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

int
construct_nsec3(DB *db, char *zone, int iterations, char *salt)
{

        DBT key, data;
        DBC *cursor;
	
	struct domain *sd;
	struct question *q;
#if 0
	struct domain_rrsig *sdrr; 
	struct domain_dnskey *sddk;
	struct rrsig *rss;
	int len;
#endif
	struct nsec3param n3p;
	struct domain_nsec3param *sdn3p;
	
	char replystring[512];
	char buf[4096];
	char bitmap[4096];
	char *dnsname;
	char *hashname = NULL;

	int labellen;
	int retval, lzerrno;
	u_int32_t ttl = 0;

	int j, rs;

	TAILQ_HEAD(listhead, mynsec3) head;

	struct mynsec3 {
		char *hashname;
		char *bitmap;
		TAILQ_ENTRY(mynsec3) entries;
	} *n1, *n2, *np;
		
		
	TAILQ_INIT(&head);

	/* fill nsec3param */
	
	if (fill_nsec3param(zone, "nsec3param", 0, 1, 0, iterations, salt) < 0) {
		printf("fill_nsec3param failed\n");
		return -1;
	}

	dnsname = dns_label(zone, &labellen);
	if (dnsname == NULL)
		return -1;

	q = build_fake_question(dnsname, labellen, DNS_TYPE_NSEC3PARAM);
	if (q == NULL) {
		return -1;
	}

	if ((sd = lookup_zone(db, q, &retval, &lzerrno, (char *)&replystring)) == NULL) {
		return -1;
	}

	/* RFC 5155 page 3 */
	ttl = sd->ttl[INTERNAL_TYPE_SOA];

        if ((sdn3p = find_substruct(sd, INTERNAL_TYPE_NSEC3PARAM)) == NULL) {
                return -1;
        }

	n3p.algorithm = 1;	/* still in conformance with above */
	n3p.flags = 0;
	n3p.iterations = sdn3p->nsec3param.iterations;
	n3p.saltlen = sdn3p->nsec3param.saltlen;
	memcpy(&n3p.salt, sdn3p->nsec3param.salt, n3p.saltlen);

	/* set cursor on database */
	
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
		if ((sd = calloc(1, rs)) == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			exit(1);
		}

		memcpy((char *)sd, (char *)data.data, data.size);

		
		hashname = hash_name(sd->zone, sd->zonelen, &n3p);
		if (hashname == NULL) {
			dolog(LOG_INFO, "hash_name return NULL");
			return -1;
		}
		
		bitmap[0] = '\0';
		if (sd->flags & DOMAIN_HAVE_A)
			strlcat(bitmap, "A ", sizeof(bitmap));	
		if (sd->flags & DOMAIN_HAVE_NS)
			strlcat(bitmap, "NS ", sizeof(bitmap));	
		if (sd->flags & DOMAIN_HAVE_CNAME)
			strlcat(bitmap, "CNAME ", sizeof(bitmap));	
		if (sd->flags & DOMAIN_HAVE_SOA)
			strlcat(bitmap, "SOA ", sizeof(bitmap));	
		if (sd->flags & DOMAIN_HAVE_PTR)
			strlcat(bitmap, "PTR ", sizeof(bitmap));	
		if (sd->flags & DOMAIN_HAVE_MX)
			strlcat(bitmap, "MX ", sizeof(bitmap));	
		if (sd->flags & DOMAIN_HAVE_TXT)
			strlcat(bitmap, "TXT ", sizeof(bitmap));	
		if (sd->flags & DOMAIN_HAVE_AAAA)
			strlcat(bitmap, "AAAA ", sizeof(bitmap));	
		if (sd->flags & DOMAIN_HAVE_SRV)
			strlcat(bitmap, "SRV ", sizeof(bitmap));	
		if (sd->flags & DOMAIN_HAVE_NAPTR)
			strlcat(bitmap, "NAPTR ", sizeof(bitmap));	
		if (sd->flags & DOMAIN_HAVE_DS)
			strlcat(bitmap, "DS ", sizeof(bitmap));	
		if (sd->flags & DOMAIN_HAVE_SSHFP)
			strlcat(bitmap, "SSHFP ", sizeof(bitmap));	

		/* they all have RRSIG */
		strlcat(bitmap, "RRSIG ", sizeof(bitmap));	

		if (sd->flags & DOMAIN_HAVE_DNSKEY)
			strlcat(bitmap, "DNSKEY ", sizeof(bitmap));	

		if (sd->flags & DOMAIN_HAVE_NSEC3)
			strlcat(bitmap, "NSEC3 ", sizeof(bitmap));	

		if (sd->flags & DOMAIN_HAVE_NSEC3PARAM)
			strlcat(bitmap, "NSEC3PARAM ", sizeof(bitmap));	

		if (sd->flags & DOMAIN_HAVE_TLSA)
			strlcat(bitmap, "TLSA ", sizeof(bitmap));	

		if (sd->flags & DOMAIN_HAVE_SPF)
			strlcat(bitmap, "SPF ", sizeof(bitmap));	

#if 0
		printf("%s %s\n", buf, bitmap);
#endif

		n1 = malloc(sizeof(struct mynsec3));
		if (n1 == NULL) {
			dolog(LOG_INFO, "out of memory");
			return -1;
		}
		
		n1->hashname = strdup(hashname);
		n1->bitmap = strdup(bitmap);	
		if (n1->hashname == NULL || n1->bitmap == NULL) {
			dolog(LOG_INFO, "out of memory");
			return -1;
		}
	
		if (TAILQ_EMPTY(&head))
			TAILQ_INSERT_TAIL(&head, n1, entries);
		else {
			TAILQ_FOREACH(n2, &head, entries) {
				if (strcmp(n1->hashname, n2->hashname) < 0)
					break;
			}

			if (n2 != NULL) 
				TAILQ_INSERT_BEFORE(n2, n1, entries);
			else
				TAILQ_INSERT_TAIL(&head, n1, entries);
		}

	} while (cursor->c_get(cursor, &key, &data, DB_NEXT) == 0);

	TAILQ_FOREACH(n2, &head, entries) {
		np = TAILQ_NEXT(n2, entries);
		if (np == NULL)
			np = TAILQ_FIRST(&head);

#if 0
		printf("%s next: %s %s\n", n2->hashname, np->hashname, n2->bitmap);
#endif
		snprintf(buf, sizeof(buf), "%s.%s.", n2->hashname, zone);
		fill_nsec3(buf, "nsec3", ttl, n3p.algorithm, n3p.flags, n3p.iterations, salt, np->hashname, n2->bitmap);
	}

#if 0
	printf("%d records\n", j);
#endif
	
	return 0;
}

char *
bin2hex(char *bin, int len)
{
	static char hex[4096];
	char *p;
	int i;

	memset(&hex, 0, sizeof(hex));
	p = &hex[0];

	for (i = 0; i < len; i++) {
		snprintf(p, sizeof(hex), "%02x", bin[i] & 0xff);
		p += 2;
	}

	return ((char *)&hex);
}

char *
bitmap2human(char *bitmap, int len)
{
	static char human[4096];
	char expanded_bitmap[32];
	u_int16_t bit;
	int i, j, block, bitlen;
	int x;
	char *p;

	memset(&human, 0, sizeof(human));

	for (i = 0, p = bitmap; i < len;) {
		block = *p;
		p++;
		i++;
		memset(&expanded_bitmap, 0, sizeof(expanded_bitmap));
		bitlen = *p;
		p++;
		i++;
		memcpy(&expanded_bitmap, p, bitlen);
		p += bitlen;
		i += bitlen;
		for (j = 0; j < 32; j++) {
			if (expanded_bitmap[j] & 0x80) {
				x = 0;
				bit = (block * 255) + ((j * 8) + x);
				strlcat(human, get_dns_type(bit, 0), sizeof(human));
				strlcat(human, " ", sizeof(human));
			}
			if (expanded_bitmap[j] & 0x40) {
				x = 1;
				bit = (block * 255) + ((j * 8) + x);
				strlcat(human, get_dns_type(bit, 0), sizeof(human));
				strlcat(human, " ", sizeof(human));
			}
			if (expanded_bitmap[j] & 0x20) {
				x = 2;
				bit = (block * 255) + ((j * 8) + x);
				strlcat(human, get_dns_type(bit, 0), sizeof(human));
				strlcat(human, " ", sizeof(human));
			}
			if (expanded_bitmap[j] & 0x10) {
				x = 3;
				bit = (block * 255) + ((j * 8) + x);
				strlcat(human, get_dns_type(bit, 0), sizeof(human));
				strlcat(human, " ", sizeof(human));
			}
			if (expanded_bitmap[j] & 0x8) {
				x = 4;
				bit = (block * 255) + ((j * 8) + x);
				strlcat(human, get_dns_type(bit, 0), sizeof(human));
				strlcat(human, " ", sizeof(human));
			}
			if (expanded_bitmap[j] & 0x4) {
				x = 5;
				bit = (block * 255) + ((j * 8) + x);
				strlcat(human, get_dns_type(bit, 0), sizeof(human));
				strlcat(human, " ", sizeof(human));
			}
			if (expanded_bitmap[j] & 0x2) {
				x = 6;
				bit = (block * 255) + ((j * 8) + x);
				strlcat(human, get_dns_type(bit, 0), sizeof(human));
				strlcat(human, " ", sizeof(human));
			}
			if (expanded_bitmap[j] & 0x1) {
				x = 7;
				bit = (block * 255) + ((j * 8) + x);
				strlcat(human, get_dns_type(bit, 0), sizeof(human));
				strlcat(human, " ", sizeof(human));
			}

		}
	}
		
	if (human[strlen(human) - 1] == ' ')
		human[strlen(human) - 1] = '\0';

	return ((char *)&human);
}
