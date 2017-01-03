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
#include "ddd-config.h"

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
int 	dump_db(DB *, FILE *, char *);
char * 	alg_to_name(int);
int 	alg_to_rsa(int);
int 	construct_nsec3(DB *, char *, int, char *);
int 	calculate_rrsigs(DB *, char *, char *, char *, int);
int	sign_dnskey(DB *, char *, char *, char *, int, struct domain *);
int 	sign_a(DB *, char *, char *, int, struct domain *);
int 	sign_mx(DB *, char *, char *, int, struct domain *);
int 	sign_ns(DB *, char *, char *, int, struct domain *);
int 	sign_srv(DB *, char *, char *, int, struct domain *);
int 	sign_spf(DB *, char *, char *, int, struct domain *);
int 	sign_cname(DB *, char *, char *, int, struct domain *);
int 	sign_soa(DB *, char *, char *, int, struct domain *);
int	sign_txt(DB *, char *, char *, int, struct domain *);
int	sign_aaaa(DB *, char *, char *, int, struct domain *);
int	sign_ptr(DB *, char *, char *, int, struct domain *);
int	sign_nsec3(DB *, char *, char *, int, struct domain *);
int	sign_nsec3param(DB *, char *, char *, int, struct domain *);
int	sign_naptr(DB *, char *, char *, int, struct domain *);
int	sign_sshfp(DB *, char *, char *, int, struct domain *);
int	sign_tlsa(DB *, char *, char *, int, struct domain *);
int	sign_ds(DB *, char *, char *, int, struct domain *);
int 	create_ds(DB *, char *, char *);
u_int 	keytag(u_char *key, u_int keysize);
void 	pack(char *, char *, int);
void 	pack32(char *, u_int32_t);
void 	pack16(char *, u_int16_t);
void 	pack8(char *, u_int8_t);
RSA * 	read_private_key(char *, int, int);
u_int64_t timethuman(time_t);
char * 	bitmap2human(char *, int);
char * 	bin2hex(char *, int);
int 	print_sd(FILE *, struct domain *);
void	cleanup(DB *, char *);
void 	usage(void);


#define ALGORITHM_RSASHA1_NSEC3_SHA1 7 		/* rfc 5155 */
#define ALGORITHM_RSASHA256	8		/* rfc 5702 */
#define ALGORITHM_RSASHA512	10		/* rfc 5702 */

#define RSA_F5			0x100000001

#define PROVIDED_SIGNTIME			1
#define	SIGNEDON				20161230073133
#define EXPIREDON 				20170228073133


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
u_int64_t expiredon, signedon;

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
	FILE *of = stdout;
	struct stat sb;

	int ch;
	int ret, bits = 2048;
	int ttl = 3600;
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
	char *tmpdir;
	char tmppath[] = "./tmp.XXXXXXXXXX";
	
	DB *db;
	DB_ENV *dbenv;


	while ((ch = getopt(argc, argv, "a:B:e:hI:i:Kk:n:o:s:t:vZz:")) != -1) {
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

		case 'h':
			usage();
			exit(1);
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
			if (optarg[0] == '-')
				break;
 
			errno = 0;
			if (lstat(optarg, &sb) < 0 && errno != ENOENT) {
				perror("lstat");
				exit(1);
			}
			if (errno != ENOENT && ! S_ISREG(sb.st_mode)) {
				fprintf(stderr, "%s is not a file!\n", optarg);
				exit(1);
			}
			if ((of = fopen(optarg, "w")) == NULL) {
				perror("fopen");
				exit(1);
			}

			break;

		case 's':
			/* salt */
			salt = optarg;
			break;

		case 't':

			/* ttl of the zone */
			ttl = atoi(optarg);

			break;

		case 'v':
			/* version */

			printf("%s\n", DD_CONVERT_VERSION);
			exit(0);

		case 'Z':
			/* create ZSK */
			create_zsk = 1;
			break;

		case 'z':
			/* use ZSK */
			zsk_key = optarg;

			break;

		case '?':
		default:
			usage();
			exit(1);
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

#if DEBUG
	printf("zonefile is %s\n", zonefile);
#endif

	/* open the database(s) */
	if ((ret = db_env_create(&dbenv, 0)) != 0) {
		fprintf(stderr, "db_env_create: %s\n", db_strerror(ret));
		exit(1);
	}

	if ((tmpdir = mkdtemp(tmppath)) == NULL) {
		perror("mkdtemp");
		exit(1);
	}

	key = ftok(tmpdir, 1);
	if (key == (key_t)-1) {
		perror("ftok");
		exit(1);
	}

	if ((ret = dbenv->set_shm_key(dbenv, key)) != 0) {
		fprintf(stderr, "dbenv->set_shm_key failed\n");
		exit(1);
	}

	if ((ret = dbenv->open(dbenv, tmpdir, DB_CREATE | \
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

	/* calculate ds */
	if (create_ds(db, zonename, ksk_key) < 0) {
		dolog(LOG_INFO, "create_ds failed\n");
		exit(1);
	}

	/* write new zone file */
	if (dump_db(db, of, zonename) < 0)
		exit (1);


	/* clean up */
	cleanup(db, tmpdir);

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

int
dump_db(DB *db, FILE *of, char *zonename)
{
	int j, rs;

        DBT key, data;
        DBC *cursor;
	
	struct question *q;
	struct domain *sdomain;
	
	char replystring[512];
	char *dnsname;
	int labellen;
	int lzerrno, retval;

	fprintf(of, "; this file is automatically generated, do NOT edit\n");
	fprintf(of, "; it was generated by dd-convert.c\n");

	fprintf(of, "zone \"%s\" {\n", zonename);

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	q = build_fake_question(dnsname, labellen, DNS_TYPE_SOA);
	if (q == NULL) {
		return -1;
	}

	if ((sdomain = lookup_zone(db, q, &retval, &lzerrno, (char *)&replystring)) == NULL) {
		return -1;
	}

	if (print_sd(of, sdomain) < 0) {
		fprintf(stderr, "print_sd error\n");
		return -1;
	}
	
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

		if (strcmp(sdomain->zonename, zonename) == 0)
			continue;

		if (print_sd(of, sdomain) < 0) {
			fprintf(stderr, "print_sd error\n");
			return -1;
		}


		j++;
	} while (cursor->c_get(cursor, &key, &data, DB_NEXT) == 0);

	fprintf(of, "}\n");

#if DEBUG
	printf("%d records\n", j);
#endif
	return (0);
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
	struct stat sb;
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
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
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

	errno = 0;
	if (lstat(buf, &sb) < 0 && errno != ENOENT) {
		perror("lstat");
		exit(1);
	}
	
	if (errno != ENOENT && ! S_ISREG(sb.st_mode)) {
		dolog(LOG_INFO, "%s is not a file!\n", buf);
		RSA_free(rsa);
		BN_free(e);
		return NULL;
	}
	
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

	errno = 0;
	if (lstat(buf, &sb) < 0 && errno != ENOENT) {
		perror("lstat");
		exit(1);
	}
	
	if (errno != ENOENT && ! S_ISREG(sb.st_mode)) {
		dolog(LOG_INFO, "%s is not a file!\n", buf);
		RSA_free(rsa);
		BN_free(e);
		return NULL;
	}
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
	case ALGORITHM_RSASHA1_NSEC3_SHA1: 
		return ("RSASHA1_NSEC3_SHA1");
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
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
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

	time_t now;
	char timebuf[32];
	struct tm *tm;

	/* set expiredon and signedon */

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
			if (sign_dnskey(db, zonename, zsk_key, ksk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_dnskey error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_A)
			if (sign_a(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_a error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_MX)
			if (sign_mx(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_mx error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_NS)
			if (sign_ns(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_ns error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_SOA)
			if (sign_soa(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_soa error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_TXT)
			if (sign_txt(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_txt error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_AAAA)
			if (sign_aaaa(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_aaaa error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_NSEC3) 
			if (sign_nsec3(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_nsec3 error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_NSEC3PARAM)
			if (sign_nsec3param(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_nsec3param error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_SPF)
			if (sign_spf(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_spf error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_CNAME)
			if (sign_cname(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_cname error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_PTR)
			if (sign_ptr(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_ptr error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_NAPTR)
			if (sign_naptr(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_naptr error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_SRV)
			if (sign_srv(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_srv error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_SSHFP)
			if (sign_sshfp(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_sshfp error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_TLSA)
			if (sign_tlsa(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_tlsa error\n");
				return -1;
			}
		if (sd->flags & DOMAIN_HAVE_DS)
			if (sign_ds(db, zonename, zsk_key, expiry, sd) < 0) {
				fprintf(stderr, "sign_ds error\n");
				return -1;
			}

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

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;

	memset(&shabuf, 0, sizeof(shabuf));

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
	
	labels = label_count(sd->zone);
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
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	expiredon2 = timegm(&tm);
	snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	signedon2 = timegm(&tm);

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
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
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

	RSA_free(rsa);

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

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;

	memset(&shabuf, 0, sizeof(shabuf));

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
	
	labels = label_count(sd->zone);
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
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	expiredon2 = timegm(&tm);
	snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	signedon2 = timegm(&tm);

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
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
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

	RSA_free(rsa);

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
	char *p, *q;
	char *key, *tmpkey;
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

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;
	TAILQ_HEAD(listhead, canonical) head;

        struct canonical {
                char *data;
                int len;
                TAILQ_ENTRY(canonical) entries;
        } *c1, *c2, *cp;


        TAILQ_INIT(&head);
	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "key out of memory\n");
		return -1;
	}
	tmpkey = malloc(10 * 4096);
	if (tmpkey == NULL) {
		dolog(LOG_INFO, "tmpkey out of memory\n");
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
	
	labels = label_count(sd->zone);
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
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	expiredon2 = timegm(&tm);
	snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	signedon2 = timegm(&tm);

	pack32(p, htonl(expiredon2));
	p += 4;
	pack32(p, htonl(signedon2));	
	p += 4;
	pack16(p, htons(keyid));
	p += 2;
	pack(p, dnsname, labellen);
	p += labellen;

	/* no signature here */	
	
	for (i = 0; i < sdaaaa->aaaa_count; i++) {
		q = tmpkey;
		pack(q, sd->zone, sd->zonelen);
		q += sd->zonelen;
		pack16(q, htons(DNS_TYPE_AAAA));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(sd->ttl[INTERNAL_TYPE_AAAA]));
		q += 4;
		pack16(q, htons(sizeof(struct in6_addr)));
		q += 2;
		pack(q, (char *)&sdaaaa->aaaa[i], sizeof(struct in6_addr));
		q += sizeof(struct in6_addr);

	        c1 = malloc(sizeof(struct canonical));
                if (c1 == NULL) {
                        dolog(LOG_INFO, "c1 out of memory\n");
                        return -1;
                }

                c1->len = (q - tmpkey);
                c1->data = malloc(c1->len);
                if (c1->data == NULL) {
                        dolog(LOG_INFO, "c1->data out of memory\n");
                        return -1;
                }

                memcpy(c1->data, tmpkey, c1->len);

                if (TAILQ_EMPTY(&head))
                        TAILQ_INSERT_TAIL(&head, c1, entries);
                else {
                        TAILQ_FOREACH(c2, &head, entries) {
                                if (c1->len < c2->len)
                                        break;
                                else if (c2->len == c1->len &&
                                        memcmp(c1->data, c2->data, c1->len) < 0)
                                        break;
                        }

                        if (c2 != NULL)
                                TAILQ_INSERT_BEFORE(c2, c1, entries);
                        else
                                TAILQ_INSERT_TAIL(&head, c1, entries);
                }
	}

#ifdef __linux__
	TAILQ_FOREACH(c2, &head, entries) {
#else
	TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
#endif
                pack(p, c2->data, c2->len);
                p += c2->len;

                TAILQ_REMOVE(&head, c2, entries);
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
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
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

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_AAAA], "AAAA", algorithm, labels, sd->ttl[INTERNAL_TYPE_AAAA], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}

/*
 * create a RRSIG for an NSEC3 record
 */

int
sign_nsec3(DB *db, char *zonename, char *zsk_key, int expiry, struct domain *sd)
{
	struct domain_nsec3 *sdnsec3;

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

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;

	memset(&shabuf, 0, sizeof(shabuf));

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
	
	labels = label_count(sd->zone);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_NSEC3) {
                if ((sdnsec3 = (struct domain_nsec3 *)find_substruct(sd, INTERNAL_TYPE_NSEC3)) == NULL) {
			dolog(LOG_INFO, "no NSEC3 records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_NSEC3));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_NSEC3]));
	p += 4;
		
	snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	expiredon2 = timegm(&tm);
	snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	signedon2 = timegm(&tm);

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

	pack16(p, htons(DNS_TYPE_NSEC3));
	p += 2;
	pack16(p, htons(DNS_CLASS_IN));
	p += 2;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_NSEC3]));
	p += 4;
	pack16(p, htons(1 + 1 + 2 + 1 + sdnsec3->nsec3.saltlen + 1 + sdnsec3->nsec3.nextlen + sdnsec3->nsec3.bitmap_len));
	p += 2;
	pack8(p, sdnsec3->nsec3.algorithm);
	p++;
	pack8(p, sdnsec3->nsec3.flags);
	p++;
	pack16(p, htons(sdnsec3->nsec3.iterations));
	p += 2;
	
	pack8(p, sdnsec3->nsec3.saltlen);
	p++;
		
	if (sdnsec3->nsec3.saltlen) {
		pack(p, sdnsec3->nsec3.salt, sdnsec3->nsec3.saltlen);
		p += sdnsec3->nsec3.saltlen;
	} 
	
	pack8(p, sdnsec3->nsec3.nextlen);
	p++;
	pack(p, sdnsec3->nsec3.next, sdnsec3->nsec3.nextlen);
	p += sdnsec3->nsec3.nextlen;
	pack(p, sdnsec3->nsec3.bitmap, sdnsec3->nsec3.bitmap_len);
	p += sdnsec3->nsec3.bitmap_len;
	
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
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
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

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_NSEC3], "NSEC3", algorithm, labels, sd->ttl[INTERNAL_TYPE_NSEC3], expiredon, signedon, keyid, zonename, tmp) < 0) {
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

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;

	memset(&shabuf, 0, sizeof(shabuf));

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
	
	labels = label_count(sd->zone);
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
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	expiredon2 = timegm(&tm);
	snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	signedon2 = timegm(&tm);

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
	pack16(p, htons(1 + 1 + 2 + 1 + sdnsec3->nsec3param.saltlen));
	p += 2;
	pack8(p, sdnsec3->nsec3param.algorithm);
	p++;
	pack8(p, sdnsec3->nsec3param.flags);
	p++;
	pack16(p, htons(sdnsec3->nsec3param.iterations));
	p += 2;

	pack8(p, sdnsec3->nsec3param.saltlen);
	p++;
		
	if (sdnsec3->nsec3param.saltlen) {
		pack(p, sdnsec3->nsec3param.salt, sdnsec3->nsec3param.saltlen);
		p += sdnsec3->nsec3param.saltlen;
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
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
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

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", 0, "NSEC3PARAM", algorithm, labels, 0, expiredon, signedon, keyid, zonename, tmp) < 0) {
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

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;

	memset(&shabuf, 0, sizeof(shabuf));

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
	
	labels = label_count(sd->zone);
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
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	expiredon2 = timegm(&tm);
	snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	signedon2 = timegm(&tm);

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
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
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

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_SPF], "SPF", algorithm, labels, sd->ttl[INTERNAL_TYPE_SPF], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}


/*
 * create a RRSIG for a CNAME record
 */

int
sign_cname(DB *db, char *zonename, char *zsk_key, int expiry, struct domain *sd)
{
	struct domain_cname *sdc;

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

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;

	memset(&shabuf, 0, sizeof(shabuf));

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
	
	labels = label_count(sd->zone);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_CNAME) {
                if ((sdc = (struct domain_cname *)find_substruct(sd, INTERNAL_TYPE_CNAME)) == NULL) {
			dolog(LOG_INFO, "no CNAME records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_CNAME));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_CNAME]));
	p += 4;
		
	snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	expiredon2 = timegm(&tm);
	snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	signedon2 = timegm(&tm);

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
	pack16(p, htons(DNS_TYPE_CNAME));
	p += 2;
	pack16(p, htons(DNS_CLASS_IN));
	p += 2;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_CNAME]));
	p += 4;
	pack16(p, htons(sdc->cnamelen));
	p += 2;
	pack(p, sdc->cname, sdc->cnamelen);
	p += sdc->cnamelen;

	keylen = (p - key);	

#if 0
	fd = open("bindump.bin", O_WRONLY | O_CREAT | O_TRUNC, 0600);
	for (i = 0; i < keylen; i++) {
		write(fd, (char *)&key[i], 1);
	}
	close(fd);
	
#endif

	switch (algorithm) {
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
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

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_CNAME], "CNAME", algorithm, labels, sd->ttl[INTERNAL_TYPE_CNAME], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}

/*
 * create a RRSIG for an NS record
 */

int
sign_ptr(DB *db, char *zonename, char *zsk_key, int expiry, struct domain *sd)
{
	struct domain_ptr *sdptr;

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

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;

	memset(&shabuf, 0, sizeof(shabuf));

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
	
	labels = label_count(sd->zone);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_PTR) {
                if ((sdptr = (struct domain_ptr *)find_substruct(sd, INTERNAL_TYPE_PTR)) == NULL) {
			dolog(LOG_INFO, "no PTR records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_PTR));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_PTR]));
	p += 4;
		
	snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	expiredon2 = timegm(&tm);
	snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	signedon2 = timegm(&tm);

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
	pack16(p, htons(DNS_TYPE_PTR));
	p += 2;
	pack16(p, htons(DNS_CLASS_IN));
	p += 2;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_PTR]));
	p += 4;
	pack16(p, htons(sdptr->ptrlen));
	p += 2;
	pack(p, sdptr->ptr, sdptr->ptrlen);
	p += sdptr->ptrlen;

	keylen = (p - key);	

#if 0
	fd = open("bindump.bin", O_WRONLY | O_CREAT | O_TRUNC, 0600);
	for (i = 0; i < keylen; i++) {
		write(fd, (char *)&key[i], 1);
	}
	close(fd);
	
#endif

	switch (algorithm) {
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
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

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_PTR], "PTR", algorithm, labels, sd->ttl[INTERNAL_TYPE_PTR], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}

/*
 * create a RRSIG for a NAPTR record
 */

int
sign_naptr(DB *db, char *zonename, char *zsk_key, int expiry, struct domain *sd)
{
	struct domain_naptr *sdnaptr;

	char tmp[4096];
	char signature[4096];
	char buf[512];
	char shabuf[64];
	
	SHA_CTX sha1;
	SHA256_CTX sha256;
	SHA512_CTX sha512;

	char *dnsname;
	char *p, *q;
	char *key, *tmpkey;
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

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;
        TAILQ_HEAD(listhead, canonical) head;

        struct canonical {
                char *data;
                int len;
                TAILQ_ENTRY(canonical) entries;
        } *c1, *c2, *cp;


        TAILQ_INIT(&head);
	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "key out of memory\n");
		return -1;
	}
	tmpkey = malloc(10 * 4096);
	if (tmpkey == NULL) {
		dolog(LOG_INFO, "tmpkey out of memory\n");
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
	
	labels = label_count(sd->zone);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_NAPTR) {
                if ((sdnaptr = (struct domain_naptr *)find_substruct(sd, INTERNAL_TYPE_NAPTR)) == NULL) {
			dolog(LOG_INFO, "no NAPTR records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_NAPTR));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_NAPTR]));
	p += 4;
		
	snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	expiredon2 = timegm(&tm);
	snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	signedon2 = timegm(&tm);

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
	
	for (i = 0; i < sdnaptr->naptr_count; i++) {
		q = tmpkey;
		pack(q, sd->zone, sd->zonelen);
		q += sd->zonelen;
		pack16(q, htons(DNS_TYPE_NAPTR));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(sd->ttl[INTERNAL_TYPE_NAPTR]));
		q += 4;
		pack16(q, htons(2 + 2 + 1 + sdnaptr->naptr[i].flagslen + 1 + sdnaptr->naptr[i].serviceslen + 1 + sdnaptr->naptr[i].regexplen + sdnaptr->naptr[i].replacementlen));
		q += 2;
		pack16(q, htons(sdnaptr->naptr[i].order));
		q += 2;
		pack16(q, htons(sdnaptr->naptr[i].preference));
		q += 2;

		pack8(q, sdnaptr->naptr[i].flagslen);
		q++;
		pack(q, sdnaptr->naptr[i].flags, sdnaptr->naptr[i].flagslen);
		q += sdnaptr->naptr[i].flagslen;

		pack8(q, sdnaptr->naptr[i].serviceslen);
		q++;
		pack(q, sdnaptr->naptr[i].services, sdnaptr->naptr[i].serviceslen);
		q += sdnaptr->naptr[i].serviceslen;

		pack8(q, sdnaptr->naptr[i].regexplen);
		q++;
		pack(q, sdnaptr->naptr[i].regexp, sdnaptr->naptr[i].regexplen);
		q += sdnaptr->naptr[i].regexplen;

		pack(q, sdnaptr->naptr[i].replacement, sdnaptr->naptr[i].replacementlen);
		q += sdnaptr->naptr[i].replacementlen;

		c1 = malloc(sizeof(struct canonical));
                if (c1 == NULL) {
                        dolog(LOG_INFO, "c1 out of memory\n");
                        return -1;
                }

                c1->len = (q - tmpkey);
                c1->data = malloc(c1->len);
                if (c1->data == NULL) {
                        dolog(LOG_INFO, "c1->data out of memory\n");
                        return -1;
                }

                memcpy(c1->data, tmpkey, c1->len);

                if (TAILQ_EMPTY(&head))
                        TAILQ_INSERT_TAIL(&head, c1, entries);
                else {
                        TAILQ_FOREACH(c2, &head, entries) {
                                if (c1->len < c2->len)
                                        break;
                                else if (c2->len == c1->len &&
                                        memcmp(c1->data, c2->data, c1->len) < 0)
                                        break;
                        }

                        if (c2 != NULL)
                                TAILQ_INSERT_BEFORE(c2, c1, entries);
                        else
                                TAILQ_INSERT_TAIL(&head, c1, entries);
                }
	}

#ifdef __linux__
        TAILQ_FOREACH(c2, &head, entries) {
#else
        TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
#endif
                pack(p, c2->data, c2->len);
                p += c2->len;

                TAILQ_REMOVE(&head, c2, entries);
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
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
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

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_NAPTR], "NAPTR", algorithm, labels, sd->ttl[INTERNAL_TYPE_NAPTR], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}

/*
 * create a RRSIG for a SRV record
 */

int
sign_srv(DB *db, char *zonename, char *zsk_key, int expiry, struct domain *sd)
{
	struct domain_srv *sdsrv;

	char tmp[4096];
	char signature[4096];
	char buf[512];
	char shabuf[64];
	
	SHA_CTX sha1;
	SHA256_CTX sha256;
	SHA512_CTX sha512;

	char *dnsname;
	char *p, *q;
	char *key, *tmpkey;
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

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;
        TAILQ_HEAD(listhead, canonical) head;

        struct canonical {
                char *data;
                int len;
                TAILQ_ENTRY(canonical) entries;
        } *c1, *c2, *cp;


        TAILQ_INIT(&head);
	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "key out of memory\n");
		return -1;
	}
	tmpkey = malloc(10 * 4096);
	if (tmpkey == NULL) {
		dolog(LOG_INFO, "tmpkey out of memory\n");
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
	
	labels = label_count(sd->zone);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_SRV) {
                if ((sdsrv = (struct domain_srv *)find_substruct(sd, INTERNAL_TYPE_SRV)) == NULL) {
			dolog(LOG_INFO, "no SRV records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_SRV));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_SRV]));
	p += 4;
		
	snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	expiredon2 = timegm(&tm);
	snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	signedon2 = timegm(&tm);

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
	
	for (i = 0; i < sdsrv->srv_count; i++) {
		q = tmpkey;
		pack(q, sd->zone, sd->zonelen);
		q += sd->zonelen;
		pack16(q, htons(DNS_TYPE_SRV));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(sd->ttl[INTERNAL_TYPE_SRV]));
		q += 4;
		pack16(q, htons(2 + 2 + 2 + sdsrv->srv[i].targetlen));
		q += 2;
		pack16(q, htons(sdsrv->srv[i].priority));
		q += 2;
		pack16(q, htons(sdsrv->srv[i].weight));
		q += 2;
		pack16(q, htons(sdsrv->srv[i].port));
		q += 2;
		pack(q, sdsrv->srv[i].target, sdsrv->srv[i].targetlen);
		q += sdsrv->srv[i].targetlen;
		
		c1 = malloc(sizeof(struct canonical));
                if (c1 == NULL) {
                        dolog(LOG_INFO, "c1 out of memory\n");
                        return -1;
                }

                c1->len = (q - tmpkey);
                c1->data = malloc(c1->len);
                if (c1->data == NULL) {
                        dolog(LOG_INFO, "c1->data out of memory\n");
                        return -1;
                }

                memcpy(c1->data, tmpkey, c1->len);

                if (TAILQ_EMPTY(&head))
                        TAILQ_INSERT_TAIL(&head, c1, entries);
                else {
                        TAILQ_FOREACH(c2, &head, entries) {
                                if (c1->len < c2->len)
                                        break;
                                else if (c2->len == c1->len &&
                                        memcmp(c1->data, c2->data, c1->len) < 0)
                                        break;
                        }

                        if (c2 != NULL)
                                TAILQ_INSERT_BEFORE(c2, c1, entries);
                        else
                                TAILQ_INSERT_TAIL(&head, c1, entries);
                }

	}

#ifdef __linux__
        TAILQ_FOREACH(c2, &head, entries) {
#else
        TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
#endif
                pack(p, c2->data, c2->len);
                p += c2->len;

                TAILQ_REMOVE(&head, c2, entries);
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
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
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

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_SRV], "SRV", algorithm, labels, sd->ttl[INTERNAL_TYPE_SRV], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}


/*
 * create a RRSIG for an SSHFP record
 */

int
sign_sshfp(DB *db, char *zonename, char *zsk_key, int expiry, struct domain *sd)
{
	struct domain_sshfp *sdsshfp;

	char tmp[4096];
	char signature[4096];
	char buf[512];
	char shabuf[64];
	
	SHA_CTX sha1;
	SHA256_CTX sha256;
	SHA512_CTX sha512;

	char *dnsname;
	char *p, *q;
	char *key, *tmpkey;
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

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;
        TAILQ_HEAD(listhead, canonical) head;

        struct canonical {
                char *data;
                int len;
                TAILQ_ENTRY(canonical) entries;
        } *c1, *c2, *cp;


        TAILQ_INIT(&head);
	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "key out of memory\n");
		return -1;
	}
	tmpkey = malloc(10 * 4096);
	if (tmpkey == NULL) {
		dolog(LOG_INFO, "tmpkey out of memory\n");
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
	
	labels = label_count(sd->zone);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_SSHFP) {
                if ((sdsshfp = (struct domain_sshfp *)find_substruct(sd, INTERNAL_TYPE_SSHFP)) == NULL) {
			dolog(LOG_INFO, "no SSHFP records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_SSHFP));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_SSHFP]));
	p += 4;
		
	snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	expiredon2 = timegm(&tm);
	snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	signedon2 = timegm(&tm);

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
	
	for (i = 0; i < sdsshfp->sshfp_count; i++) {
		q = tmpkey;
		pack(q, sd->zone, sd->zonelen);
		q += sd->zonelen;
		pack16(q, htons(DNS_TYPE_SSHFP));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(sd->ttl[INTERNAL_TYPE_SSHFP]));
		q += 4;
		pack16(q, htons(1 + 1 + sdsshfp->sshfp[i].fplen));
		q += 2;
		pack8(q, sdsshfp->sshfp[i].algorithm);
		q++;
		pack8(q, sdsshfp->sshfp[i].fptype);
		q++;
		pack(q, sdsshfp->sshfp[i].fingerprint, sdsshfp->sshfp[i].fplen);
		q += sdsshfp->sshfp[i].fplen;

		c1 = malloc(sizeof(struct canonical));
                if (c1 == NULL) {
                        dolog(LOG_INFO, "c1 out of memory\n");
                        return -1;
                }

                c1->len = (q - tmpkey);
                c1->data = malloc(c1->len);
                if (c1->data == NULL) {
                        dolog(LOG_INFO, "c1->data out of memory\n");
                        return -1;
                }

                memcpy(c1->data, tmpkey, c1->len);

                if (TAILQ_EMPTY(&head))
                        TAILQ_INSERT_TAIL(&head, c1, entries);
                else {
                        TAILQ_FOREACH(c2, &head, entries) {
                                if (c1->len < c2->len)
                                        break;
                                else if (c2->len == c1->len &&
                                        memcmp(c1->data, c2->data, c1->len) < 0)
                                        break;
                        }

                        if (c2 != NULL)
                                TAILQ_INSERT_BEFORE(c2, c1, entries);
                        else
                                TAILQ_INSERT_TAIL(&head, c1, entries);
                }
	}

#ifdef __linux__
        TAILQ_FOREACH(c2, &head, entries) {
#else
        TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
#endif
                pack(p, c2->data, c2->len);
                p += c2->len;

                TAILQ_REMOVE(&head, c2, entries);
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
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
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

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_SSHFP], "SSHFP", algorithm, labels, sd->ttl[INTERNAL_TYPE_SSHFP], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}

/*
 * create a RRSIG for a TLSA record
 */

int
sign_tlsa(DB *db, char *zonename, char *zsk_key, int expiry, struct domain *sd)
{
	struct domain_tlsa *sdtlsa;

	char tmp[4096];
	char signature[4096];
	char buf[512];
	char shabuf[64];
	
	SHA_CTX sha1;
	SHA256_CTX sha256;
	SHA512_CTX sha512;

	char *dnsname;
	char *p, *q;
	char *key, *tmpkey;
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

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;
        TAILQ_HEAD(listhead, canonical) head;

        struct canonical {
                char *data;
                int len;
                TAILQ_ENTRY(canonical) entries;
        } *c1, *c2, *cp;


        TAILQ_INIT(&head);
	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "key out of memory\n");
		return -1;
	}
	tmpkey = malloc(10 * 4096);
	if (tmpkey == NULL) {
		dolog(LOG_INFO, "tmpkey out of memory\n");
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
	
	labels = label_count(sd->zone);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_TLSA) {
                if ((sdtlsa = (struct domain_tlsa *)find_substruct(sd, INTERNAL_TYPE_TLSA)) == NULL) {
			dolog(LOG_INFO, "no TLSA records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_TLSA));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_TLSA]));
	p += 4;
		
	snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	expiredon2 = timegm(&tm);
	snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	signedon2 = timegm(&tm);

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
	
	for (i = 0; i < sdtlsa->tlsa_count; i++) {
		q = tmpkey;
		pack(q, sd->zone, sd->zonelen);
		q += sd->zonelen;
		pack16(q, htons(DNS_TYPE_TLSA));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(sd->ttl[INTERNAL_TYPE_TLSA]));
		q += 4;
		pack16(q, htons(1 + 1 + 1 + sdtlsa->tlsa[i].datalen));
		q += 2;
		pack8(q, sdtlsa->tlsa[i].usage);
		q++;
		pack8(q, sdtlsa->tlsa[i].selector);
		q++;
		pack8(q, sdtlsa->tlsa[i].matchtype);
		q++;
		pack(q, sdtlsa->tlsa[i].data, sdtlsa->tlsa[i].datalen);
		q += sdtlsa->tlsa[i].datalen;

                c1 = malloc(sizeof(struct canonical));
                if (c1 == NULL) {
                        dolog(LOG_INFO, "c1 out of memory\n");
                        return -1;
                }

                c1->len = (q - tmpkey);
                c1->data = malloc(c1->len);
                if (c1->data == NULL) {
                        dolog(LOG_INFO, "c1->data out of memory\n");
                        return -1;
                }

                memcpy(c1->data, tmpkey, c1->len);

                if (TAILQ_EMPTY(&head))
                        TAILQ_INSERT_TAIL(&head, c1, entries);
                else {
                        TAILQ_FOREACH(c2, &head, entries) {
                                if (c1->len < c2->len)
                                        break;
                                else if (c2->len == c1->len &&
                                        memcmp(c1->data, c2->data, c1->len) < 0)
                                        break;
                        }

                        if (c2 != NULL)
                                TAILQ_INSERT_BEFORE(c2, c1, entries);
                        else
                                TAILQ_INSERT_TAIL(&head, c1, entries);
                }
	}

#ifdef __linux__
        TAILQ_FOREACH(c2, &head, entries) {
#else
        TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
#endif
                pack(p, c2->data, c2->len);
                p += c2->len;

                TAILQ_REMOVE(&head, c2, entries);
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
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
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

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_TLSA], "TLSA", algorithm, labels, sd->ttl[INTERNAL_TYPE_TLSA], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}

/*
 * create a RRSIG for an DS record
 */

int
sign_ds(DB *db, char *zonename, char *zsk_key, int expiry, struct domain *sd)
{
	struct domain_ds *sdds;

	char tmp[4096];
	char signature[4096];
	char buf[512];
	char shabuf[64];
	
	SHA_CTX sha1;
	SHA256_CTX sha256;
	SHA512_CTX sha512;

	char *dnsname;
	char *p, *q;
	char *key, *tmpkey;
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

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;
        TAILQ_HEAD(listhead, canonical) head;

        struct canonical {
                char *data;
                int len;
                TAILQ_ENTRY(canonical) entries;
        } *c1, *c2, *cp;


        TAILQ_INIT(&head);
	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "key out of memory\n");
		return -1;
	}
	tmpkey = malloc(10 * 4096);
	if (tmpkey == NULL) {
		dolog(LOG_INFO, "tmpkey out of memory\n");
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
	
	labels = label_count(sd->zone);
	if (labels < 0) {
		dolog(LOG_INFO, "label_count");
		return -1;
	}

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if (sd->flags & DOMAIN_HAVE_DS) {
                if ((sdds = (struct domain_ds *)find_substruct(sd, INTERNAL_TYPE_DS)) == NULL) {
			dolog(LOG_INFO, "no DS records but have flags!\n");
                        return -1;
		}
	}
	
	p = key;

	pack16(p, htons(DNS_TYPE_DS));
	p += 2;
	pack8(p, algorithm);
	p++;
	pack8(p, labels);
	p++;
	pack32(p, htonl(sd->ttl[INTERNAL_TYPE_DS]));
	p += 4;
		
	snprintf(timebuf, sizeof(timebuf), "%lld", expiredon);
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	expiredon2 = timegm(&tm);
	snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	signedon2 = timegm(&tm);

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
	
	for (i = 0; i < sdds->ds_count; i++) {
		q = tmpkey;
		pack(q, sd->zone, sd->zonelen);
		q += sd->zonelen;
		pack16(q, htons(DNS_TYPE_DS));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(sd->ttl[INTERNAL_TYPE_DS]));
		q += 4;
		pack16(q, htons(2 + 1 + 1 + sdds->ds[i].digestlen));
		q += 2;
		pack16(q, htons(sdds->ds[i].key_tag));
		q += 2;
		pack8(q, sdds->ds[i].algorithm);
		q++;
		pack8(q, sdds->ds[i].digest_type);
		q++;
		pack(q, sdds->ds[i].digest, sdds->ds[i].digestlen);
		q += sdds->ds[i].digestlen;

               c1 = malloc(sizeof(struct canonical));
                if (c1 == NULL) {
                        dolog(LOG_INFO, "c1 out of memory\n");
                        return -1;
                }

                c1->len = (q - tmpkey);
                c1->data = malloc(c1->len);
                if (c1->data == NULL) {
                        dolog(LOG_INFO, "c1->data out of memory\n");
                        return -1;
                }

                memcpy(c1->data, tmpkey, c1->len);

                if (TAILQ_EMPTY(&head))
                        TAILQ_INSERT_TAIL(&head, c1, entries);
                else {
                        TAILQ_FOREACH(c2, &head, entries) {
                                if (c1->len < c2->len)
                                        break;
                                else if (c2->len == c1->len &&
                                        memcmp(c1->data, c2->data, c1->len) < 0)
                                        break;
                        }

                        if (c2 != NULL)
                                TAILQ_INSERT_BEFORE(c2, c1, entries);
                        else
                                TAILQ_INSERT_TAIL(&head, c1, entries);
                }
	}

#ifdef __linux__
        TAILQ_FOREACH(c2, &head, entries) {
#else
        TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
#endif
                pack(p, c2->data, c2->len);
                p += c2->len;

                TAILQ_REMOVE(&head, c2, entries);
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
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
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

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_DS], "DS", algorithm, labels, sd->ttl[INTERNAL_TYPE_DS], expiredon, signedon, keyid, zonename, tmp) < 0) {
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
	char *p, *q;
	char *key, *tmpkey;
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

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;
        TAILQ_HEAD(listhead, canonical) head;

        struct canonical {
                char *data;
                int len;
                TAILQ_ENTRY(canonical) entries;
        } *c1, *c2, *cp;


        TAILQ_INIT(&head);
	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "key out of memory\n");
		return -1;
	}
	tmpkey = malloc(10 * 4096);
	if (tmpkey == NULL) {
		dolog(LOG_INFO, "tmpkey out of memory\n");
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
	
	labels = label_count(sd->zone);
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
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	expiredon2 = timegm(&tm);
	snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	signedon2 = timegm(&tm);

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
		q = tmpkey;
		pack(q, sd->zone, sd->zonelen);
		q += sd->zonelen;
		pack16(q, htons(DNS_TYPE_NS));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(sd->ttl[INTERNAL_TYPE_NS]));
		q += 4;
		pack16(q, htons(sdns->ns[i].nslen));
		q += 2;
		memcpy(q, sdns->ns[i].nsserver, sdns->ns[i].nslen);
		q += sdns->ns[i].nslen;

               c1 = malloc(sizeof(struct canonical));
                if (c1 == NULL) {
                        dolog(LOG_INFO, "c1 out of memory\n");
                        return -1;
                }

                c1->len = (q - tmpkey);
                c1->data = malloc(c1->len);
                if (c1->data == NULL) {
                        dolog(LOG_INFO, "c1->data out of memory\n");
                        return -1;
                }

                memcpy(c1->data, tmpkey, c1->len);

                if (TAILQ_EMPTY(&head))
                        TAILQ_INSERT_TAIL(&head, c1, entries);
                else {
                        TAILQ_FOREACH(c2, &head, entries) {
                                if (c1->len < c2->len)
                                        break;
                                else if (c2->len == c1->len &&
                                        memcmp(c1->data, c2->data, c1->len) < 0)
                                        break;
                        }

                        if (c2 != NULL)
                                TAILQ_INSERT_BEFORE(c2, c1, entries);
                        else
                                TAILQ_INSERT_TAIL(&head, c1, entries);
                }
	}

#ifdef __linux__
        TAILQ_FOREACH(c2, &head, entries) {
#else
        TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
#endif
                pack(p, c2->data, c2->len);
                p += c2->len;

                TAILQ_REMOVE(&head, c2, entries);
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
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
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

	RSA_free(rsa);

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
	char *p, *q;
	char *key, *tmpkey;
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

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;
        TAILQ_HEAD(listhead, canonical) head;

        struct canonical {
                char *data;
                int len;
                TAILQ_ENTRY(canonical) entries;
        } *c1, *c2, *cp;


        TAILQ_INIT(&head);
	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "key out of memory\n");
		return -1;
	}
	tmpkey = malloc(10 * 4096);
	if (tmpkey == NULL) {
		dolog(LOG_INFO, "tmpkey out of memory\n");
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
	
	labels = label_count(sd->zone);
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
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	expiredon2 = timegm(&tm);
	snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	signedon2 = timegm(&tm);

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
		q = tmpkey;
		pack(q, sd->zone, sd->zonelen);
		q += sd->zonelen;
		pack16(q, htons(DNS_TYPE_MX));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(sd->ttl[INTERNAL_TYPE_MX]));
		q += 4;
		pack16(q, htons(2 + sdmx->mx[i].exchangelen));
		q += 2;
		pack16(q, htons(sdmx->mx[i].preference));
		q += 2;
		memcpy(q, sdmx->mx[i].exchange, sdmx->mx[i].exchangelen);
		q += sdmx->mx[i].exchangelen;

                c1 = malloc(sizeof(struct canonical));
                if (c1 == NULL) {
                        dolog(LOG_INFO, "c1 out of memory\n");
                        return -1;
                }

                c1->len = (q - tmpkey);
                c1->data = malloc(c1->len);
                if (c1->data == NULL) {
                        dolog(LOG_INFO, "c1->data out of memory\n");
                        return -1;
                }

                memcpy(c1->data, tmpkey, c1->len);

                if (TAILQ_EMPTY(&head))
                        TAILQ_INSERT_TAIL(&head, c1, entries);
                else {
                        TAILQ_FOREACH(c2, &head, entries) {
                                if (c1->len < c2->len)
                                        break;
                                else if (c2->len == c1->len &&
                                        memcmp(c1->data, c2->data, c1->len) < 0)
                                        break;
                        }

                        if (c2 != NULL)
                                TAILQ_INSERT_BEFORE(c2, c1, entries);
                        else
                                TAILQ_INSERT_TAIL(&head, c1, entries);
                }
	}

#ifdef __linux__
        TAILQ_FOREACH(c2, &head, entries) {
#else
        TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
#endif
                pack(p, c2->data, c2->len);
                p += c2->len;

                TAILQ_REMOVE(&head, c2, entries);
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
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
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

	RSA_free(rsa);

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
	char *p, *q;
	char *key, *tmpkey;
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

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;
        TAILQ_HEAD(listhead, canonical) head;

        struct canonical {
                char *data;
                int len;
                TAILQ_ENTRY(canonical) entries;
        } *c1, *c2, *cp;


        TAILQ_INIT(&head);
	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "key out of memory\n");
		return -1;
	}
	tmpkey = malloc(10 * 4096);
	if (tmpkey == NULL) {
		dolog(LOG_INFO, "tmpkey out of memory\n");
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
	
	labels = label_count(sd->zone);
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
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	expiredon2 = timegm(&tm);
	snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	signedon2 = timegm(&tm);

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
		q = tmpkey;
		pack(q, sd->zone, sd->zonelen);
		q += sd->zonelen;
		pack16(q, htons(DNS_TYPE_A));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(sd->ttl[INTERNAL_TYPE_A]));
		q += 4;
		pack16(q, htons(sizeof(in_addr_t)));
		q += 2;
		pack32(q, sda->a[i]);
		q += 4;

                c1 = malloc(sizeof(struct canonical));
                if (c1 == NULL) {
                        dolog(LOG_INFO, "c1 out of memory\n");
                        return -1;
                }

                c1->len = (q - tmpkey);
                c1->data = malloc(c1->len);
                if (c1->data == NULL) {
                        dolog(LOG_INFO, "c1->data out of memory\n");
                        return -1;
                }

                memcpy(c1->data, tmpkey, c1->len);

                if (TAILQ_EMPTY(&head))
                        TAILQ_INSERT_TAIL(&head, c1, entries);
                else {
                        TAILQ_FOREACH(c2, &head, entries) {
                                if (c1->len < c2->len)
                                        break;
                                else if (c2->len == c1->len &&
                                        memcmp(c1->data, c2->data, c1->len) < 0)
                                        break;
                        }

                        if (c2 != NULL)
                                TAILQ_INSERT_BEFORE(c2, c1, entries);
                        else
                                TAILQ_INSERT_TAIL(&head, c1, entries);
                }
	}

#ifdef __linux__
        TAILQ_FOREACH(c2, &head, entries) {
#else
        TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
#endif
                pack(p, c2->data, c2->len);
                p += c2->len;

                TAILQ_REMOVE(&head, c2, entries);
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
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
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

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", sd->ttl[INTERNAL_TYPE_A], "A", algorithm, labels, sd->ttl[INTERNAL_TYPE_A], expiredon, signedon, keyid, zonename, tmp) < 0) {
		dolog(LOG_INFO, "fill_rrsig\n");
		return -1;
	}
	
	return 0;
}

int
create_ds(DB *db, char *zonename, char *ksk_key)
{
	FILE *f;

	struct domain *sd;
	struct domain_dnskey *sddk;
	struct stat sb;

	char *mytmp;
	char tmp[4096];
	char signature[4096];
	char buf[512];
	char shabuf[64];
	
	SHA_CTX sha1;
	SHA256_CTX sha256;

	char *dnsname;
	char *p;
	char *key;
	char *zone;

	uint32_t ttl = 3600;
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;

	int labellen, i;
	int keyid;
	int fd;
	int keylen;
	int bufsize;
	int labels;

	struct question *qp;
	int retval, lzerrno;
	char replystring[512];

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL) {
		dolog(LOG_INFO, "dnsname == NULL\n");
		return -1;
	}

	qp = build_fake_question(dnsname, labellen, DNS_TYPE_SOA);
	if (qp == NULL) {
		dolog(LOG_INFO, "qp == NULL\n");
		return -1;
	}

	if ((sd = lookup_zone(db, qp, &retval, &lzerrno, (char *)&replystring)) == NULL) {
		dolog(LOG_INFO, "sd == NULL\n");
		return -1;
	}

	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "key out of memory\n");
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
	
	labels = label_count(sd->zone);
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
	
	keylen = (p - key);	

	for (i = 0; i < sddk->dnskey_count; i++) {
		if (sddk->dnskey[i].flags == 257)
			break;
	}

	/* work out the digest */

	p = key;
	pack(p, sd->zone, sd->zonelen);
	p += sd->zonelen;
	pack16(p, htons(sddk->dnskey[i].flags));
	p += 2;
	pack8(p, sddk->dnskey[i].protocol);
	p++;
	pack8(p, sddk->dnskey[i].algorithm);
	p++;
	pack(p, sddk->dnskey[i].public_key, sddk->dnskey[i].publickey_len);
	p += sddk->dnskey[i].publickey_len;
	
	keylen = (p - key);

	SHA1_Init(&sha1);
	SHA1_Update(&sha1, key, keylen);
	SHA1_Final((u_char *)shabuf, &sha1);
	bufsize = 20;

	mytmp = bin2hex(shabuf, bufsize);
	if (mytmp == NULL) {
		dolog(LOG_INFO, "bin2hex shabuf\n");
		return -1;
	}
		
	for (p = mytmp; *p; p++) {
		*p = toupper(*p);
	}
	
	snprintf(buf, sizeof(buf), "dsset-%s", convert_name(sd->zone, sd->zonelen));

	errno = 0;
	if (lstat(buf, &sb) < 0 && errno != ENOENT) {
		perror("lstat");
		exit(1);
	}
	
	if (errno != ENOENT && ! S_ISREG(sb.st_mode)) {
		dolog(LOG_INFO, "%s is not a file!\n", buf);
		return -1;
	}

	f = fopen(buf, "w");
	if (f == NULL) {
		dolog(LOG_INFO, "fopen dsset\n");
		return -1;
	}

	fprintf(f, "%s\t\tIN DS %u %d 1 %s\n", convert_name(sd->zone, sd->zonelen), keyid, algorithm, mytmp);


	SHA256_Init(&sha256);
	SHA256_Update(&sha256, key, keylen);
	SHA256_Final((u_char *)shabuf, &sha256);
	bufsize = 32;

	mytmp = bin2hex(shabuf, bufsize);
	if (mytmp == NULL) {
		dolog(LOG_INFO, "bin2hex shabuf\n");
		return -1;
	}
	
	for (p = mytmp; *p; p++) {
		*p = toupper(*p);
	}

	fprintf(f, "%s\t\tIN DS %u %d 2 %s\n", convert_name(sd->zone, sd->zonelen), keyid, algorithm, mytmp);

	fclose(f);


	return 0;
}

/* 
 * From RFC 4034, appendix b 
 */

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
	char *p, *q;
	char *key, *tmpkey;
	char *zone;

	uint32_t ttl = 3600;
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

	char timebuf[32];
	struct tm tm;
	u_int32_t expiredon2, signedon2;

	TAILQ_HEAD(listhead, canonical) head;

	struct canonical {
		char *data;
		int len;
		TAILQ_ENTRY(canonical) entries;
	} *c1, *c2, *cp;
		
		
	TAILQ_INIT(&head);
	memset(&shabuf, 0, sizeof(shabuf));

	key = malloc(10 * 4096);
	if (key == NULL) {
		dolog(LOG_INFO, "key out of memory\n");
		return -1;
	}
	tmpkey = malloc(10 * 4096);
	if (tmpkey == NULL) {
		dolog(LOG_INFO, "tmpkey out of memory\n");
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
	
	labels = label_count(sd->zone);
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
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	expiredon2 = timegm(&tm);
	snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	signedon2 = timegm(&tm);

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
		q = tmpkey;
		pack(q, dnsname, labellen);
		q += labellen;
		pack16(q, htons(DNS_TYPE_DNSKEY));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(sd->ttl[INTERNAL_TYPE_DNSKEY]));
		q += 4;
		pack16(q, htons(2 + 1 + 1 + sddk->dnskey[i].publickey_len));
		q += 2;
		pack16(q, htons(sddk->dnskey[i].flags));
		q += 2;
		pack8(q, sddk->dnskey[i].protocol);
		q++;
		pack8(q, sddk->dnskey[i].algorithm);
		q++;
		pack(q, sddk->dnskey[i].public_key, sddk->dnskey[i].publickey_len);
		q += sddk->dnskey[i].publickey_len;


		c1 = malloc(sizeof(struct canonical));
		if (c1 == NULL) {
			dolog(LOG_INFO, "c1 out of memory\n");
			return -1;
		}

		c1->len = (q - tmpkey);
		c1->data = malloc(c1->len);
		if (c1->data == NULL) {
			dolog(LOG_INFO, "c1->data out of memory\n");
			return -1;
		}
	
		memcpy(c1->data, tmpkey, c1->len);

		if (TAILQ_EMPTY(&head))
			TAILQ_INSERT_TAIL(&head, c1, entries);
		else {
			TAILQ_FOREACH(c2, &head, entries) {
				if (c1->len < c2->len)
					break;
				else if (c2->len == c1->len && 
					memcmp(c1->data, c2->data, c1->len) < 0)
					break;
			}

			if (c2 != NULL) 
				TAILQ_INSERT_BEFORE(c2, c1, entries);
			else
				TAILQ_INSERT_TAIL(&head, c1, entries);
		}

	}

#ifdef __linux__
        TAILQ_FOREACH(c2, &head, entries) {
#else
        TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
#endif
		pack(p, c2->data, c2->len);
		p += c2->len;

		TAILQ_REMOVE(&head, c2, entries);
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
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
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

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", ttl, "DNSKEY", algorithm, labels, 		ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
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
	
	labels = label_count(sd->zone);
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
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	expiredon2 = timegm(&tm);
	snprintf(timebuf, sizeof(timebuf), "%lld", signedon);
	strptime(timebuf, "%Y%m%d%H%M%S", &tm);
	signedon2 = timegm(&tm);

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
		q = tmpkey;
		pack(q, dnsname, labellen);
		q += labellen;
		pack16(q, htons(DNS_TYPE_DNSKEY));
		q += 2;
		pack16(q, htons(DNS_CLASS_IN));
		q += 2;
		pack32(q, htonl(sd->ttl[INTERNAL_TYPE_DNSKEY]));
		q += 4;
		pack16(q, htons(2 + 1 + 1 + sddk->dnskey[i].publickey_len));
		q += 2;
		pack16(q, htons(sddk->dnskey[i].flags));
		q += 2;
		pack8(q, sddk->dnskey[i].protocol);
		q++;
		pack8(q, sddk->dnskey[i].algorithm);
		q++;
		pack(q, sddk->dnskey[i].public_key, sddk->dnskey[i].publickey_len);
		q += sddk->dnskey[i].publickey_len;

		c1 = malloc(sizeof(struct canonical));
                if (c1 == NULL) {
                        dolog(LOG_INFO, "c1 out of memory\n");
                        return -1;
                }

                c1->len = (q - tmpkey);
                c1->data = malloc(c1->len);
                if (c1->data == NULL) {
                        dolog(LOG_INFO, "c1->data out of memory\n");
                        return -1;
                }

                memcpy(c1->data, tmpkey, c1->len);

                if (TAILQ_EMPTY(&head))
                        TAILQ_INSERT_TAIL(&head, c1, entries);
                else {
                        TAILQ_FOREACH(c2, &head, entries) {
                                if (c1->len < c2->len)
                                        break;
                                else if (c2->len == c1->len &&
                                        memcmp(c1->data, c2->data, c1->len) < 0)
                                        break;
                        }

                        if (c2 != NULL)
                                TAILQ_INSERT_BEFORE(c2, c1, entries);
                        else
                                TAILQ_INSERT_TAIL(&head, c1, entries);
                }
	}

#ifdef __linux__
        TAILQ_FOREACH(c2, &head, entries) {
#else
        TAILQ_FOREACH_SAFE(c2, &head, entries, cp) {
#endif
                pack(p, c2->data, c2->len);
                p += c2->len;

                TAILQ_REMOVE(&head, c2, entries);
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
	case ALGORITHM_RSASHA1_NSEC3_SHA1:
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

	RSA_free(rsa);

	len = mybase64_encode(signature, siglen, tmp, sizeof(tmp));
	tmp[len] = '\0';

	if (fill_rrsig(sd->zonename, "RRSIG", ttl, "DNSKEY", algorithm, labels, 			ttl, expiredon, signedon, keyid, zonename, tmp) < 0) {
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

#if __linux__
	memset(buf, 0, sizeof(buf));
	memset(key, 0, sizeof(key));
#else
	explicit_bzero(buf, sizeof(buf));
	explicit_bzero(key, sizeof(key));
#endif

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

int
print_sd(FILE *of, struct domain *sdomain)
{
	int i, x, len;

	struct domain_soa *sdsoa;
	struct domain_ns *sdns;
	struct domain_mx *sdmx;
	struct domain_a *sda;
	struct domain_aaaa *sdaaaa;
	struct domain_cname *sdcname;
	struct domain_ptr *sdptr;
	struct domain_txt *sdtxt;
	struct domain_spf *sdspf;
	struct domain_naptr *sdnaptr;
	struct domain_srv *sdsrv;
	struct domain_rrsig *sdrr;
	struct domain_dnskey *sddk;
	struct domain_ds *sdds;
	struct domain_nsec3 *sdn3;
	struct domain_nsec3param *sdn3param;
	struct domain_sshfp *sdsshfp;
	struct domain_tlsa *sdtlsa;
	struct rrsig *rss;
	
	char buf[4096];

	if (sdomain->flags & DOMAIN_HAVE_SOA) {
		if ((sdsoa = (struct domain_soa *)find_substruct(sdomain, INTERNAL_TYPE_SOA)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		fprintf(of, "  %s,soa,%d,%s,%s,%d,%d,%d,%d,%d\n", 
			convert_name(sdomain->zone, sdomain->zonelen),
			sdomain->ttl[INTERNAL_TYPE_SOA],
			convert_name(sdsoa->soa.nsserver, sdsoa->soa.nsserver_len),
			convert_name(sdsoa->soa.responsible_person, sdsoa->soa.rp_len),
			sdsoa->soa.serial, sdsoa->soa.refresh, sdsoa->soa.retry, 
			sdsoa->soa.expire, sdsoa->soa.minttl);
	}
	if (sdomain->flags & DOMAIN_HAVE_NS) {
		if ((sdns = (struct domain_ns *)find_substruct(sdomain, INTERNAL_TYPE_NS)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sdns->ns_count; i++) {
			fprintf(of, "  %s,ns,%d,%s\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_NS],
				convert_name(sdns->ns[i].nsserver, sdns->ns[i].nslen));
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_MX) {
		if ((sdmx = (struct domain_mx *)find_substruct(sdomain, INTERNAL_TYPE_MX)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sdmx->mx_count; i++) {
			fprintf(of, "  %s,mx,%d,%d,%s\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_MX],
				sdmx->mx[i].preference,
				convert_name(sdmx->mx[i].exchange, sdmx->mx[i].exchangelen));
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_DS) {
		if ((sdds = (struct domain_ds *)find_substruct(sdomain, INTERNAL_TYPE_DS)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sdds->ds_count; i++) {
			fprintf(of, "  %s,ds,%d,%d,%d,%d,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_DS],
				sdds->ds[i].key_tag,
				sdds->ds[i].algorithm,
				sdds->ds[i].digest_type,
				bin2hex(sdds->ds[i].digest, sdds->ds[i].digestlen));
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_CNAME) {
		if ((sdcname = (struct domain_cname *)find_substruct(sdomain, INTERNAL_TYPE_CNAME)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		fprintf(of, "  %s,cname,%d,%s\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_CNAME],
				convert_name(sdcname->cname, sdcname->cnamelen));
	}
	if (sdomain->flags & DOMAIN_HAVE_SPF) {
		if ((sdspf = (struct domain_spf *)find_substruct(sdomain, INTERNAL_TYPE_SPF)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		fprintf(of, "  %s,spf,%d,\"", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_SPF]);
		for (i = 0; i < sdspf->spflen; i++) {
			fprintf(of, "%c", sdspf->spf[i]);
		}
		fprintf(of, "\"\n");
	}
	if (sdomain->flags & DOMAIN_HAVE_NAPTR) {
		if ((sdnaptr = (struct domain_naptr *)find_substruct(sdomain, INTERNAL_TYPE_NAPTR)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sdnaptr->naptr_count; i++) {
			fprintf(of, "  %s,naptr,%d,%d,%d,\"", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_NAPTR],
				sdnaptr->naptr[i].order,
				sdnaptr->naptr[i].preference);
			
			for (x = 0; x < sdnaptr->naptr[i].flagslen; x++) {
				fprintf(of, "%c", sdnaptr->naptr[i].flags[x]);
			}
			fprintf(of, "\",\"");
			for (x = 0; x < sdnaptr->naptr[i].serviceslen; x++) {
				fprintf(of, "%c", sdnaptr->naptr[i].services[x]);
			}
			fprintf(of, "\",\"");
			for (x = 0; x < sdnaptr->naptr[i].regexplen; x++) {
				fprintf(of, "%c", sdnaptr->naptr[i].regexp[x]);
			}
			fprintf(of, "\",%s\n", convert_name(sdnaptr->naptr[i].replacement, sdnaptr->naptr[i].replacementlen));
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_TXT) {
		if ((sdtxt = (struct domain_txt *)find_substruct(sdomain, INTERNAL_TYPE_TXT)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		fprintf(of, "  %s,txt,%d,\"", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_TXT]);
		for (i = 0; i < sdtxt->txtlen; i++) {
			fprintf(of, "%c", sdtxt->txt[i]);
		}
		fprintf(of, "\"\n");
	}
	if (sdomain->flags & DOMAIN_HAVE_PTR) {
		if ((sdptr = (struct domain_ptr *)find_substruct(sdomain, INTERNAL_TYPE_PTR)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		fprintf(of, "  %s,ptr,%d,%s\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_PTR],
				convert_name(sdptr->ptr, sdptr->ptrlen));
	}
	if (sdomain->flags & DOMAIN_HAVE_SRV) {
		if ((sdsrv = (struct domain_srv *)find_substruct(sdomain, INTERNAL_TYPE_SRV)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sdsrv->srv_count; i++) {
			fprintf(of, "  %s,srv,%d,%d,%d,%d,%s\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_SRV],
				sdsrv->srv[i].priority,
				sdsrv->srv[i].weight,
				sdsrv->srv[i].port,
				convert_name(sdsrv->srv[i].target,sdsrv->srv[i].targetlen));
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_TLSA) {
		if ((sdtlsa = (struct domain_tlsa *)find_substruct(sdomain, INTERNAL_TYPE_TLSA)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sdtlsa->tlsa_count; i++) {
			fprintf(of, "  %s,tlsa,%d,%d,%d,%d,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_TLSA],
				sdtlsa->tlsa[i].usage,
				sdtlsa->tlsa[i].selector,
				sdtlsa->tlsa[i].matchtype,
				bin2hex(sdtlsa->tlsa[i].data, sdtlsa->tlsa[i].datalen));
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_SSHFP) {
		if ((sdsshfp = (struct domain_sshfp *)find_substruct(sdomain, INTERNAL_TYPE_SSHFP)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sdsshfp->sshfp_count; i++) {
			fprintf(of, "  %s,sshfp,%d,%d,%d,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_SSHFP],
				sdsshfp->sshfp[i].algorithm,
				sdsshfp->sshfp[i].fptype,
				bin2hex(sdsshfp->sshfp[i].fingerprint, sdsshfp->sshfp[i].fplen));
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_A) {
		if ((sda = (struct domain_a *)find_substruct(sdomain, INTERNAL_TYPE_A)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sda->a_count; i++) {
			inet_ntop(AF_INET, &sda->a[i], buf, sizeof(buf));
			fprintf(of, "  %s,a,%d,%s\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_A],
				buf);
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_AAAA) {
		if ((sdaaaa = (struct domain_aaaa *)find_substruct(sdomain, INTERNAL_TYPE_AAAA)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sdaaaa->aaaa_count; i++) {
			inet_ntop(AF_INET6, &sdaaaa->aaaa[i], buf, sizeof(buf));
			fprintf(of, "  %s,aaaa,%d,%s\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_AAAA],
				buf);
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_DNSKEY) {
#if DEBUG
		printf(" has dnskey\n");
#endif
		if ((sddk = (struct domain_dnskey *)find_substruct(sdomain, INTERNAL_TYPE_DNSKEY)) == NULL) {
			dolog(LOG_INFO, "no dnskeys in zone!\n");
			return -1;
		}
		for (i = 0; i < sddk->dnskey_count; i++) {
			len = mybase64_encode(sddk->dnskey[i].public_key, sddk->dnskey[i].publickey_len, buf, sizeof(buf));
			buf[len] = '\0';
			fprintf(of, "  %s,dnskey,%d,%d,%d,%d,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				sdomain->ttl[INTERNAL_TYPE_DNSKEY],
				sddk->dnskey[i].flags,
				sddk->dnskey[i].protocol,
				sddk->dnskey[i].algorithm,
				buf);
		}
	}
	if (sdomain->flags & DOMAIN_HAVE_NSEC3PARAM) {
#if DEBUG
		printf("has nsec3param\n");
#endif
		if ((sdn3param = (struct domain_nsec3param *)find_substruct(sdomain, INTERNAL_TYPE_NSEC3PARAM)) == NULL) {
			dolog(LOG_INFO, "no nsec3param in zone!\n");
			return -1;
		}
		
		fprintf(of, "  %s,nsec3param,0,%d,%d,%d,\"%s\"\n",
			convert_name(sdomain->zone, sdomain->zonelen),
			sdn3param->nsec3param.algorithm,
			sdn3param->nsec3param.flags,
			sdn3param->nsec3param.iterations,
			(sdn3param->nsec3param.saltlen == 0) ? "-" : bin2hex(sdn3param->nsec3param.salt, sdn3param->nsec3param.saltlen));
	}
	if (sdomain->flags & DOMAIN_HAVE_NSEC3) {
#if DEBUG
		printf("has nsec3\n");
#endif
		if ((sdn3 = (struct domain_nsec3 *)find_substruct(sdomain, INTERNAL_TYPE_NSEC3)) == NULL) {
			dolog(LOG_INFO, "no nsec3 in zone!\n");
			return -1;
		}
		
		fprintf(of, "  %s,nsec3,%d,%d,%d,%d,\"%s\",\"%s\",\"%s\"\n",
			convert_name(sdomain->zone, sdomain->zonelen),
			sdomain->ttl[INTERNAL_TYPE_NSEC3],
			sdn3->nsec3.algorithm,
			sdn3->nsec3.flags,
			sdn3->nsec3.iterations,
			(sdn3->nsec3.saltlen == 0) ? "-" : bin2hex(sdn3->nsec3.salt, sdn3->nsec3.saltlen),
			base32hex_encode(sdn3->nsec3.next, sdn3->nsec3.nextlen),
			bitmap2human(sdn3->nsec3.bitmap, sdn3->nsec3.bitmap_len));

	}
	if (sdomain->flags & DOMAIN_HAVE_RRSIG) {
#if DEBUG
		printf(" has rrsig\n");
#endif
		
		if ((sdrr = (struct domain_rrsig *)find_substruct(sdomain, INTERNAL_TYPE_RRSIG)) == NULL) {
			dolog(LOG_INFO, "no rrsigs in zone!\n");
			return -1;
		}

		if ((sdomain->flags & DOMAIN_HAVE_DNSKEY) && sdrr->rrsig_dnskey_count > 0) {
			for (i = 0; i < sdrr->rrsig_dnskey_count; i++) {
				rss = (struct rrsig *)&sdrr->rrsig_dnskey[i];
				len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
				buf[len] = '\0';

				fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
					convert_name(sdomain->zone, sdomain->zonelen),
					sdomain->ttl[INTERNAL_TYPE_DNSKEY],
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

			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
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

		if (sdomain->flags & DOMAIN_HAVE_DS) {
			for (i = 0; i < sdrr->rrsig_ds_count; i++) {
				rss = (struct rrsig *)&sdrr->rrsig_ds[i];
				len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
				buf[len] = '\0';

				fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
					convert_name(sdomain->zone, sdomain->zonelen),
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



		if (sdomain->flags & DOMAIN_HAVE_TLSA) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_TLSA];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
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


		if (sdomain->flags & DOMAIN_HAVE_SSHFP) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_SSHFP];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
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

		if (sdomain->flags & DOMAIN_HAVE_SRV) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_SRV];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
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


		if (sdomain->flags & DOMAIN_HAVE_NAPTR) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_NAPTR];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
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

			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
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

			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
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

		if (sdomain->flags & DOMAIN_HAVE_NSEC3) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_NSEC3];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone,sdomain->zonelen),
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

			fprintf(of, "  %s,rrsig,0,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
				get_dns_type(rss->type_covered, 0), 
				rss->algorithm, rss->labels,
				0, /* original ttl */
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

			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
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


		if (sdomain->flags & DOMAIN_HAVE_CNAME) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_CNAME];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
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

		if (sdomain->flags & DOMAIN_HAVE_PTR) {
			rss = (struct rrsig *)&sdrr->rrsig[INTERNAL_TYPE_PTR];
			len = mybase64_encode(rss->signature, rss->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
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

			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
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

			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen),
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

			fprintf(of, "  %s,rrsig,%d,%s,%d,%d,%d,%llu,%llu,%d,%s,\"%s\"\n", 
				convert_name(sdomain->zone, sdomain->zonelen), 
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

	return 0;
}

void
usage(void)
{
	fprintf(stderr, "usage: dd-convert [-hKZ] [-a algorithm] [-B bits] [-e seconds] [-I iterations] [-i inputfile] [-k KSK] [-n zonename] [-o output] [-s salt] [-t ttl] [-z ZSK]\n");
	fprintf(stderr, "\t-h\t\tthis help usage.\n");
	fprintf(stderr, "\t-K\t\tcreate a new KSK key.\n");
	fprintf(stderr, "\t-Z\t\tcreate a new ZSK key.\n");
	fprintf(stderr, "\t-a algorithm	use algorithm (integer)\n");
	fprintf(stderr, "\t-B bits\t\tuse number of bits (integer)\n");
	fprintf(stderr, "\t-e seconds\texpiry in seconds\n");
	fprintf(stderr, "\t-I iteratiosn\tuse (integer) NSEC3 iterations\n");
	fprintf(stderr, "\t-i inputfile\tuse the inputfile of unsigned zone\n");
	fprintf(stderr, "\t-k KSK\t\tuse provided KSK key-signing keyname\n");
	fprintf(stderr, "\t-n zonename\trun for zonename zone\n");
	fprintf(stderr, "\t-o output\toutput to file, may be '-' for stdout\n");
	fprintf(stderr, "\t-s salt\t\tsalt for NSEC3 (in hexadecimal)\n");
	fprintf(stderr, "\t-t ttl\t\ttime-to-live for dnskey's\n");
	fprintf(stderr, "\t-z ZSK\t\tuse provided ZSK zone-signing keyname\n");	
	return;
}
	
void
cleanup(DB *db, char *tmpdir)
{
	DIR *dirp;
	struct dirent *dp;
	struct stat sb;
	
	db->close(db, 0);
	if (chdir(tmpdir) < 0) {
		return;
	}

	if ((dirp = opendir(".")) == NULL) {
		return;
	}

	while ((dp = readdir(dirp)) != NULL) {
		if (lstat(dp->d_name, &sb) < 0) {
			closedir(dirp);
			return;
		}
		if (S_ISREG(sb.st_mode)) {
			if (unlink(dp->d_name) < 0) {
				closedir(dirp);
				return;
			}
		}
	}
	(void)closedir(dirp);
	chdir("..");
	rmdir(tmpdir);

	return;
}
