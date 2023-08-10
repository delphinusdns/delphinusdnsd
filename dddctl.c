/*
 * Copyright (c) 2016-2023 Peter J. Philipp <pjp@delphinusdns.org>
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
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>

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
#include "ddd-config.h"

int wrap6to4region = 0xffff;
int debug = 0;
int verbose = 0;
int forward = 0;
int forwardtsig = 0;
int strictx20i = 1;
int forwardstrategy = STRATEGY_SPRAY;
int zonecount = 0;
int cache = 0;
int tsigpassname = 0;
char *versionstring = DD_VERSION;

extern int dnssec;
extern int bytes_received;

/* prototypes */

void	dolog(int pri, char *fmt, ...);
int	dump_db_bind(ddDB*, FILE *, char *);
int 	print_rbt_bind(FILE *, struct rbtree *);
int	usage(int argc, char *argv[]);
int	start(int argc, char *argv[]);
int	tsigf(int argc, char *argv[]);
int	restart(int argc, char *argv[]);
int	stop(int argc, char *argv[]);
int	coord(int argc, char *argv[]);
int	configtest(int argc, char *argv[]);
int	bindfile(int argc, char *argv[]);
int	sshfp(int argc, char *argv[]);
int	count_db(ddDB *);
int 	dumpcache(int argc, char *argv[]);
int 	versionf(int argc, char *argv[]);


/* glue */
int insert_axfr(char *, char *);
int insert_filter(char *, char *);
int insert_passlist(char *, char *);
int insert_notifyddd(char *, char *);
int insert_forward(struct sockaddr_storage *, uint16_t, char *);
int insert_zone(char *);
int insert_tsigpassname(char *, int);
void delete_zone(char *, int);
void repopulate_zone(ddDB *, char *, int);

int illdestination;
int *ptr = &illdestination;

int notify = 0;
int passlist = 0;
int bcount = 0;
char *bind_list[255];
char *interface_list[255];
int bflag = 0;
int ratelimit_packets_per_second = 0;
int ratelimit = 0;
int ratelimit_cidr = 0, ratelimit_cidr6 = 0;
extern uint16_t port;
int nflag = 0;
int iflag = 0;
int lflag = 0;
int icount = 0;
int vslen = 0;
uint64_t expiredon, signedon;

int tls = 0;
uint16_t tls_port = 853;
char *tls_certfile = NULL;
char *tls_keyfile = NULL;
char *tls_protocols = NULL;
char *tls_ciphers = NULL;

extern TAILQ_HEAD(, iwqueue) iwqhead;
extern struct iwqueue *iwq, *iwq0, *iwq1;


/* externs */

extern int	dig(int argc, char *argv[]);
extern int	signmain(int argc, char *argv[]);
extern int	zonemd(int argc, char *argv[]);
extern uint32_t unpack32(char *);
extern uint16_t unpack16(char *);
extern void 	unpack(char *, char *, int);

extern void 	pack(char *, char *, int);
extern void 	pack32(char *, uint32_t);
extern void 	pack16(char *, uint16_t);
extern void 	pack8(char *, uint8_t);
extern char * convert_name(char *name, int namelen);

extern int      mybase64_encode(u_char const *, size_t, char *, size_t);
extern int      mybase64_decode(char const *, u_char *, size_t);

extern char * 	bin2hex(char *, int);
extern uint64_t timethuman(time_t);
extern char * 	bitmap2human(char *, int);
extern char * dns_label(char *, int *);
extern struct rbtree *         Lookup_zone(ddDB *, char *, int, int, int);
extern struct question         *build_fake_question(char *, int, uint16_t, char *, int);
extern int                      memcasecmp(u_char *, u_char *, int);
extern struct rrset * find_rr(struct rbtree *rbt, uint16_t rrtype);
extern char * dns_label(char *, int *);
extern int label_count(char *);
extern char *get_dns_type(int, int);
extern char * hash_name(char *, int, struct nsec3param *);
extern char * base32hex_encode(u_char *input, int len);
extern char * param_tlv2human(char *, int, int);
extern char * ipseckey_type(struct ipseckey *);



struct _mycmdtab {
	char *var;
	int (*cmd)(int, char **);
} mycmdtab[] = {
	{ "bindfile", bindfile },
	{ "configtest", configtest },
	{ "coord", coord },
	{ "dumpcache", dumpcache },
	{ "help", usage },
	{ "query", dig },
	{ "restart", restart },
	{ "sign", signmain },
	{ "sshfp", sshfp },
	{ "start", start },
	{ "stop", stop },
	{ "tsig", tsigf },
	{ "version", versionf },
	{ "zonemd", zonemd },
	{ NULL, NULL }
};

int
main(int argc, char *argv[])
{
	struct _mycmdtab *pctab;

	if (argc == 1) {
		usage(argc, argv);
		exit(1);
	}
	
	for (pctab = &mycmdtab[0]; pctab->var; pctab++) {
		if (strcmp((char *)pctab->var, argv[1]) == 0) {
			argc--; argv++;
			dnssec = 1;
			exit(pctab->cmd(argc, argv));
		}
	}

	usage(argc, argv);
	exit(1);
}


void
repopulate_zone(ddDB *db, char *name, int len)
{
	return;
}

void 
delete_zone(char *name, int len)
{
	return;
}

int
insert_tsigpassname(char *name, int len)
{
	return 0;
}

int
insert_zone(char *zonename)
{
	return 0;
}

int
insert_axfr(char *address, char *prefixlen)
{
	return 0;
}

int
insert_filter(char *address, char *prefixlen)
{
	return 0;
}

int
insert_passlist(char *address, char *prefixlen)
{
	return 0;
}

int
insert_notifyddd(char *address, char *prefixlen)
{
	return 0;
}

int
insert_forward(struct sockaddr_storage *sso, uint16_t port, char *tsigkey)
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
usage(int argc, char *argv[])
{
	int retval = 0;

	if (argc == 2 && strcmp(argv[1], "sign") == 0) {
		fprintf(stderr, "usage: dddctl sign [-KXZ] [-a algorithm] [-B bits] [-e seconds] [-I iterations] [-i inputfile] [-k KSK] [-m mask] [-n zonename] [-o output] [-R keyword] [-S pid] [-s salt] [-t ttl] [-x serial] [-z ZSK]\n");
		fprintf(stderr, "\t-K\t\tcreate a new KSK key.\n");
		fprintf(stderr, "\t-M\t\tadd a ZONEMD RR before signing.\n");
		fprintf(stderr, "\t-X\t\tupdate the serial to YYYYMMDD01.\n");
		fprintf(stderr, "\t-Z\t\tcreate a new ZSK key.\n");
		fprintf(stderr, "\t-a algorithm	use algorithm (integer)\n");
		fprintf(stderr, "\t-B bits\t\tuse number of bits (integer)\n");
		fprintf(stderr, "\t-e seconds\texpiry in seconds\n");
		fprintf(stderr, "\t-I iterations\tuse (integer) NSEC3 iterations\n");
		fprintf(stderr, "\t-i inputfile\tuse the inputfile of unsigned zone\n");
		fprintf(stderr, "\t-k KSK\t\tuse provided KSK key-signing keyname\n");
		fprintf(stderr, "\t-m mask\t\trun the following masked functions\n");
		fprintf(stderr, "\t-N int\t\tuse NSEC version (default is 3).\n");
		fprintf(stderr, "\t-n zonename\trun for zonename zone\n");
		fprintf(stderr, "\t-o output\toutput to file, may be '-' for stdout\n");
		fprintf(stderr, "\t-R keyword\tSpecify key roll-over method (prep or double)\n");
		fprintf(stderr, "\t-S pid\t\tsign with this pid ('KSK' or 'ZSK' if used in\n\t\t\tconjunction with [-ZK])\n");
		fprintf(stderr, "\t-s salt\t\tsalt for NSEC3 (in hexadecimal)\n");
		fprintf(stderr, "\t-t ttl\t\ttime-to-live for dnskey's\n");
		fprintf(stderr, "\t-x serial\tupdate serial to argument\n");
		fprintf(stderr, "\t-z ZSK\t\tuse provided ZSK zone-signing keyname\n");	
		return 0;
	} else if (argc == 2 && strcmp(argv[1], "query") == 0) {
		fprintf(stderr, "usage: dddctl query [-DITZ] [-@ server] [-P port] [-p file] [-Q server]\n\t\t[-y keyname:password] name command\n");
		fprintf(stderr, "\t-@ server\t\tUse server ip.\n");
		fprintf(stderr, "\t-D\t\t\tUse DNSSEC (DO bit) lookup.\n");
		fprintf(stderr, "\t-I\t\t\tIndent output.\n");
		fprintf(stderr, "\t-T\t\t\tUse TCP.\n");
		fprintf(stderr, "\t-Z\t\t\tOutput as a zonefile.\n");
		fprintf(stderr, "\t-P port\t\t\tUse specified port.\n");
		fprintf(stderr, "\t-p file\t\t\tOutput to file.\n");
		fprintf(stderr, "\t-Q server\t\tSynonymous with -@\n");
		fprintf(stderr, "\t-y keyname:password\tTSIG keyname and password\n");
		
		return 0;
	} else if (argc == 2) {
		retval = 1;
	} else {
		fprintf(stderr, "usage: command [arg ...]\n");
		fprintf(stderr, "\tbindfile zonename zonefile\n");
		fprintf(stderr, "\tconfigtest [-cn] [configfile]\n");
		fprintf(stderr, "\tcoord [-c] [lat] [min] [sec] [N/S] [long] [min] [sec] [E/W]\n");
		fprintf(stderr, "\thelp [command]\n");
		fprintf(stderr, "\tquery [-DITZ] [-@ server] [-P port] [-p file] [-Q server]\n\t\t[-y keyname:password] name command\n");
		fprintf(stderr, "\trestart [-I ident] [-s socket]\n");
		fprintf(stderr, "\tsign [-KMXZ] [-a algorithm] [-B bits] [-e seconds]\n\t\t[-I iterations] [-i inputfile] [-k KSK] [-m mask]\n\t\t[-N int] [-n zonename] [-o output] [-R keyword] [-S pid]\n\t\t[-s salt] [-t ttl] [-x serial] [-z ZSK]\n");
		fprintf(stderr, "\tsshfp hostname [-k keyfile] [-t ttl]\n");
		fprintf(stderr, "\tstart [-f configfile] [-I ident] [-s socket]\n");
		fprintf(stderr, "\tstop [-I ident] [-s socket]\n");
		fprintf(stderr, "\ttsig\n");
		fprintf(stderr, "\tversion\n");
		fprintf(stderr, "\tzonemd [-c] [-n zonename] [-o outfile] file\n");
		retval = 0;
	}

	return (retval);
}

int	
start(int argc, char *argv[])
{
	struct stat sb;
	char buf[PATH_MAX];
	char sockpathbuf[PATH_MAX];
	char *path = NULL;
	char *socketpath = SOCKPATH;
	char *configfile = CONFFILE;
	char *ident = NULL;
	int ch, usesp = 0;

	while ((ch = getopt(argc, argv, "f:I:s:")) != -1) {
		switch (ch) {
		case 'f':
			configfile = optarg;
			break;
		case 'I':
			ident = optarg;
			break;
		case 's':
			socketpath = optarg;
			usesp = 1;
			break;
		default:
			usage(argc, argv);
			exit(1);
		}
	}

	if (ident != NULL && usesp) {
		fprintf(stderr, "cannot specify -I and -s together\n");
		exit(1);
	}

	if (ident != NULL) {
		snprintf(sockpathbuf, sizeof(sockpathbuf),
			"/var/run/delphinusdnsd-%s.sock", ident);

		socketpath = sockpathbuf;
	}

	if (lstat(socketpath, &sb) != -1) {
		fprintf(stderr, "%s exists, not clobbering\n", socketpath);
		exit(1);
	}
	

	if (geteuid() != 0) {
		fprintf(stderr, "must be root\n");
		exit(1);
	}

#if defined __OpenBSD__ || defined __FreeBSD__
	if (setresuid(0,0,0) < 0) {
		perror("setuid");
		exit(1);
	}
#else
        if (setgid(0) < 0) {
		perror("setgid");
                exit(1);
        }
        if (setuid(0) < 0) {
		perror("setuid");
                exit(1);
        }
#endif

	
	fprintf(stderr, "starting delphinusdnsd\n");

	path = realpath(configfile, buf);
	if (path == NULL) {
		perror("realpath");
		exit(1);
	}

	if (ident) {
		if (execl("/usr/local/sbin/delphinusdnsd", "delphinusdnsd", "-f", path, 
			"-I", ident, NULL) < 0) {
			perror("execl");
			exit(1);	
		}
	} else {
		if (execl("/usr/local/sbin/delphinusdnsd", "delphinusdnsd", "-f", path, 
			"-s", socketpath, NULL) < 0) {
			perror("execl");
			exit(1);	
		}
	}

	return 0;
}

int
tsigf(int argc, char *argv[])
{
	char buf[512];
	char b64buf[1024];
	int len;

	arc4random_buf(&buf, 32);
	len = mybase64_encode(buf, 32, b64buf, sizeof(b64buf));
	b64buf[len] = '\0';
	printf("%s\n", b64buf);

	return 0;
}

int
versionf(int argc, char *argv[])
{
	printf("%s\n", versionstring);
	return 0;
}

int
coord(int argc, char *argv[])
{
	int cartesian = 0;
	char *p, *latp;
	double latitude, longitude;
	double min, sec;
	double latmin, latsec;
	double longmin, longsec;
	double latresult, longresult;
	char latdir = 'N', longdir = 'E';
	char tmpbuf[128];
	char *Slat, *Slong;

	if (argc < 2) {
		usage(argc, argv);
		exit(1);
	}
		
	if (strcmp(argv[1], "-c") == 0) {
		cartesian = 1;
	}

	if (cartesian) {

		if (argc < 3) {
			usage(argc, argv);
			exit(1);
		}

		latp = argv[2];

		p = strchr(latp, ',');
		if (p == NULL) {
			fprintf(stderr, "there is a comma required between latitude and longitude\n");
			exit(1);
		}
		*p++ = '\0';
		
		latitude = atof(latp);
		longitude = atof(p);

		if (latitude < 0)
			latdir = 'S';

		if (longitude < 0)
			longdir = 'W';

		if (*latp == '-')
			latp++;

		Slat = strchr(latp, '.');
		if (Slat == NULL) {
			printf("%s 00 00 %c ", latp, latdir);	
			goto skip;
		}
		min = atof(Slat) * 60;
		*Slat = '\0';

		printf("%s ", latp);
		snprintf(tmpbuf, sizeof(tmpbuf), "%f", min);
		
		Slat = strchr(tmpbuf, '.');
		if (Slat == NULL) {
			printf("%s %s 00 %c ", latp, tmpbuf, latdir);
			goto skip;
		}
		sec = atof(Slat) * 60;
		*Slat = '\0';

		printf("%s %f %c ", tmpbuf, sec, latdir);

skip:
		if (*p == '-')
			p++;

		Slong = strchr(p, '.');
		if (Slong == NULL) {
			printf("%s 00 00 %c\n", p, longdir);	
			exit(0);
		}
		min = atof(Slong) * 60;
		*Slong = '\0';

		printf("%s ", p);
		snprintf(tmpbuf, sizeof(tmpbuf), "%f", min);
		
		Slong = strchr(tmpbuf, '.');
		if (Slong == NULL) {
			printf("%s %s 00 %c\n", p, tmpbuf, longdir);
			exit(0);
		}
		sec = atof(Slong) * 60;
		*Slong = '\0';

		printf("%s %f %c\n", tmpbuf, sec, longdir);
		exit(0);	
	}

	if (argc != 9) {
		usage(argc, argv);
		exit(1);
	}

	latitude = atof(argv[1]);
	latmin = atof(argv[2]) / 60;
	latsec = atof(argv[3]) / 3600;

	if (*argv[4] == 'S')
		latresult = -1 * (latitude + latmin + latsec);
	else
		latresult = (latitude + latmin + latsec);

	longitude = atof(argv[5]);
	longmin = atof(argv[6]) / 60;
	longsec = atof(argv[7]) / 3600;

	if (*argv[8] == 'W')
		longresult = -1 * (longitude + longmin + longsec);
	else
		longresult = (longitude + longmin + longsec);

	printf("%f,%f\n", latresult, longresult);
	exit(0);
}

int
command_socket(char *sockpath)
{
	int so;
	struct sockaddr_un sun;

	so = socket(AF_UNIX, SOCK_STREAM, 0);
	if (so < 0) {
		return -1;
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlcpy(sun.sun_path, sockpath, sizeof(sun.sun_path)) >= sizeof(sun.sun_path)) {
		close(so);
		return -1;
	}
#ifndef __linux__
	sun.sun_len = SUN_LEN(&sun);
#endif

	if (connect(so, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		close(so);
		return -1;
	}

	return (so);
}

int	
dumpcache(int argc, char *argv[])
{
	char buf[512], sockpathbuf[512];
	char *socketpath = SOCKPATH;
	char *ident = NULL;
	struct dddcomm *dc;
	int so, usesp = 0;
	int ch, len;

	while ((ch = getopt(argc, argv, "I:s:")) != -1) {
		switch (ch) {
		case 'I':
			ident = optarg;
			break;
		case 's':
			socketpath = optarg;
			usesp = 1;
			break;
		default:
			usage(argc, argv);
			exit(1);
		}
	}

	if (ident != NULL && usesp) {
		fprintf(stderr, "cannot specify -I and -s together\n");
		exit(1);
	} 

	if (ident != NULL) {
		snprintf(sockpathbuf, sizeof(sockpathbuf), 
			"/var/run/delphinusdnsd-%s.sock", ident);
		
		socketpath = sockpathbuf;
	}
	if (geteuid() != 0) {
		fprintf(stderr, "must be root\n");
		exit(1);
	}

	fprintf(stderr, "dumping cache\n");

	if ((so = command_socket(socketpath)) < 0) {
		perror(socketpath);
		exit(1);
	}		

	memset(&buf, 0, sizeof(buf));
	dc = (struct dddcomm *)&buf[0];
	dc->command = IMSG_DUMP_CACHE;
	if (send(so, buf, sizeof(struct dddcomm), 0) < 0) {
		perror("send");
		close(so);
		exit(1);
	}
	while ((len = recv(so, buf, sizeof(buf), 0)) != 0) {
		if (len < 0) {
			perror("recv");
			close(so);
			exit(1);
		}
		write (STDOUT_FILENO, buf, len);
	}
	close(so);

	printf("\n");
		
	return (0);
}

int	
restart(int argc, char *argv[])
{
	char buf[512], sockpathbuf[512];
	char *socketpath = SOCKPATH;
	char *ident = NULL;
	struct dddcomm *dc;
	int so, usesp = 0;
	int ch, len;

	while ((ch = getopt(argc, argv, "I:s:")) != -1) {
		switch (ch) {
		case 'I':
			ident = optarg;
			break;
		case 's':
			socketpath = optarg;
			usesp = 1;
			break;
		default:
			usage(argc, argv);
			exit(1);
		}
	}

	if (ident != NULL && usesp) {
		fprintf(stderr, "cannot specify -I and -s together\n");
		exit(1);
	} 

	if (ident != NULL) {
		snprintf(sockpathbuf, sizeof(sockpathbuf), 
			"/var/run/delphinusdnsd-%s.sock", ident);
		
		socketpath = sockpathbuf;
	}

	if (geteuid() != 0) {
		fprintf(stderr, "must be root\n");
		exit(1);
	}

	fprintf(stderr, "restarting delphinusdnsd\n");

	if ((so = command_socket(socketpath)) < 0) {
		perror(socketpath);
		exit(1);
	}		

	memset(&buf, 0, sizeof(buf));
	dc = (struct dddcomm *)&buf[0];
	dc->command = IMSG_RELOAD_MESSAGE;
	if (send(so, buf, sizeof(struct dddcomm), 0) < 0) {
		perror("send");
		close(so);
		exit(1);
	}
	if ((len = recv(so, buf, sizeof(struct dddcomm), 0)) < 0) {
		perror("recv");
		close(so);
		exit(1);
	}
	close(so);
		
	return (0);
}

int	
stop(int argc, char *argv[])
{
	char buf[PATH_MAX];
	char sockpathbuf[PATH_MAX];
	char *socketpath = SOCKPATH;
	char *ident = NULL;
	struct dddcomm *dc;
	int so, usesp = 0;
	int ch, len;

	while ((ch = getopt(argc, argv, "I:s:")) != -1) {
		switch (ch) {
		case 'I':
			ident = optarg;
			break;
		case 's':
			socketpath = optarg;
			usesp = 1;
			break;
		default:
			usage(argc, argv);
			exit(1);
		}
	}

	if (ident != NULL && usesp) {
		fprintf(stderr, "cannot specify -I and -s together\n");
		exit(1);
	} 

	if (ident != NULL) {
		snprintf(sockpathbuf, sizeof(sockpathbuf), 
			"/var/run/delphinusdnsd-%s.sock", ident);
		
		socketpath = sockpathbuf;
	}

	if (geteuid() != 0) {
		fprintf(stderr, "must be root\n");
		exit(1);
	}

	fprintf(stderr, "stopping delphinusdnsd\n");

	if ((so = command_socket(socketpath)) < 0) {
		perror(socketpath);
		exit(1);
	}		

	memset(&buf, 0, sizeof(buf));
	dc = (struct dddcomm *)&buf[0];
	dc->command = IMSG_SHUTDOWN_MESSAGE;
	if (send(so, buf, sizeof(struct dddcomm), 0) < 0) {
		perror("send");
		close(so);
		exit(1);
	}
	if ((len = recv(so, buf, sizeof(struct dddcomm), 0)) < 0) {
		perror("recv");
		close(so);
		exit(1);
	}
	close(so);
		
	return (0);
}

int	
configtest(int argc, char *argv[])
{
	ddDB *db;
	char *zonefile = CONFFILE;
	int ch, count = 0;
	uint32_t flags = 0;

	
	while ((ch = getopt(argc, argv, "cn")) != -1) {
		switch (ch) {
		case 'c':
			count = 1;
			break;
		case 'n':
			flags |= PARSEFILE_FLAG_NOSOCKET;
			flags |= PARSEFILE_FLAG_NOTSIGKEYS;
			break;
		default:
			fprintf(stderr, "usage: dddctl configtest [-c] [input]\n");
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc)
		zonefile = argv[0];




	/* open the database(s) */
	db = dddbopen();
	if (db == NULL) {
		dolog(LOG_INFO, "dddbopen() failed\n");
		return 1;
	}

	/* now we start reading our configfile */
		
	if (parse_file(db, zonefile, flags, -1) < 0) {
		dolog(LOG_INFO, "parsing config file failed\n");
		return 1;
	}

#if __OpenBSD__
	/* better late than never */
	if (pledge("stdio", NULL) < 0) {
		perror("pledge");
		exit(1);
	}
#endif

	if (count)
		count_db(db);

	dddbclose(db);
	
	printf("OK\n");
	
	return 0;
}

int	
sshfp(int argc, char *argv[])
{
	char buf[512];
	char *hostname = NULL;
	char *keyfile = NULL;
	FILE *po;
	char *p, *q;
	char *tmp;
	int len, ttl = 3600;
	int ch;

	if (argc < 2) {
		usage(argc, argv);
		exit(1);
	}

	hostname = argv[1];

	argv++;
	argc--;

	while ((ch = getopt(argc, argv, "f:k:t:")) != -1) {
		switch (ch) {
		case 'f':
			/* fallthrough */
		case 'k':
			keyfile = optarg;
			break;
		case 't':	
			ttl = atoi(optarg);
			break;

		}
	}

	if (keyfile)
		snprintf(buf, sizeof(buf), "/usr/bin/ssh-keygen -r %s -f %s", hostname, keyfile);
	else
		snprintf(buf, sizeof(buf), "/usr/bin/ssh-keygen -r %s", hostname);

	po = popen(buf, "r");
	if (po == NULL) {
		perror("popen");
		exit(1);
	}

	while (fgets(buf, sizeof(buf), po) != NULL) {
		len = strlen(buf);
		if (buf[len - 1] == '\n')
			len--;
		buf[len] = '\0';

		while ((p = strchr(buf, ' ')) != NULL) {
			*p = ',';
		}
	
		q = strrchr(buf, ',');
		if (q == NULL) {
			continue;
		}

		q++;
		if (*q == '\0') {
			continue;
		}

		tmp = strdup(q);
		if (tmp == NULL) {
			perror("strdup");
			exit(1);
		}
		*q = '\0';

		p = strchr(buf, ',');
		if (p == NULL) {
			continue;
		}
	
		q = strchr(p, ',');
		if (q == NULL) {
			continue;
		}

		q += 10;

		printf("  %s.,sshfp,%d,%s\"%s\"\n", hostname, ttl, q, tmp);
		free(tmp);
	}

	pclose(po);

	exit(0);	
}

int
dump_db_bind(ddDB *db, FILE *of, char *zonename)
{
	int j, rs;

        ddDBT key, data;
	
	struct node *n, *nx;
	struct rbtree *rbt = NULL, *rbt0 = NULL;
	
	
	char *dnsname;
	int labellen;

	fprintf(of, ";; This file was generated by dddctl.c of delphinusdnsd\n");

	dnsname = dns_label(zonename, &labellen);
	if (dnsname == NULL)
		return -1;

	if ((rbt = Lookup_zone(db, dnsname, labellen, DNS_TYPE_SOA, 0)) == NULL) {
		return -1;
	}

	if (print_rbt_bind(of, rbt) < 0) {
		fprintf(stderr, "print_rbt_bind error\n");
		return -1;
	}
	
	memset(&key, 0, sizeof(key));   
	memset(&data, 0, sizeof(data));

	j = 0;
	RB_FOREACH_SAFE(n, domaintree, &db->head, nx) {
		rs = n->datalen;
		if ((rbt0 = calloc(1, rs)) == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			exit(1);
		}

		memcpy((char *)rbt0, (char *)n->data, n->datalen);

		if (rbt->zonelen == rbt0->zonelen && 
			memcasecmp((u_char *)rbt->zone, (u_char *)rbt0->zone, rbt->zonelen) == 0) {
			continue;
		}

		if (print_rbt_bind(of, rbt0) < 0) {
			fprintf(stderr, "print_rbt_bind error\n");
			return -1;
		}


		j++;
	} 

#if DEBUG
	printf("%d records\n", j);
#endif

	return (0);
}

/*
 * dump the RR's in BIND format 
 */

int
print_rbt_bind(FILE *of, struct rbtree *rbt)
{
	int i, x, len;

	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct rr *rrp2 = NULL;

	char buf[4096];

	if ((rrset = find_rr(rbt, DNS_TYPE_SOA)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no soa in zone!\n");
			return -1;
		}
		fprintf(of, "%s %d IN SOA %s %s (\n\t\t\t\t%u\t; Serial\n\t\t\t\t%d\t; Refresh\n\t\t\t\t%d\t; Retry\n\t\t\t\t%d\t; Expire\n\t\t\t\t%d )\t; Minimum TTL\n\n", 
			convert_name(rbt->zone, rbt->zonelen),
			rrset->ttl, 
			convert_name(((struct soa *)rrp->rdata)->nsserver, ((struct soa *)rrp->rdata)->nsserver_len),
			convert_name(((struct soa *)rrp->rdata)->responsible_person, ((struct soa *)rrp->rdata)->rp_len),
			((struct soa *)rrp->rdata)->serial, 
			((struct soa *)rrp->rdata)->refresh, 
			((struct soa *)rrp->rdata)->retry, 
			((struct soa *)rrp->rdata)->expire, 
			((struct soa *)rrp->rdata)->minttl);
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_NS)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no soa in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "%s %d IN NS %s\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl, 
				convert_name(((struct ns *)rrp2->rdata)->nsserver, ((struct ns *)rrp2->rdata)->nslen));
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_MX)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no mx in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "%s %d IN MX %d %s\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl, 
				((struct smx *)rrp2->rdata)->preference, 
				convert_name(((struct smx *)rrp2->rdata)->exchange, ((struct smx *)rrp2->rdata)->exchangelen));
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_KX)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no kx in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "%s %d IN KX %d %s\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl, 
				((struct kx *)rrp2->rdata)->preference, 
				convert_name(((struct kx *)rrp2->rdata)->exchange, ((struct kx *)rrp2->rdata)->exchangelen));
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_IPSECKEY)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no ipseckey in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			len = mybase64_encode((const u_char *)((struct ipseckey *)rrp2->rdata)->key, ((struct ipseckey *)rrp2->rdata)->keylen, buf, sizeof(buf));
			buf[len] = '\0';
			fprintf(of, "%s %d IN IPSECKEY ( %d %d %d %s %s )\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl, 
				((struct ipseckey *)rrp2->rdata)->precedence,
				((struct ipseckey *)rrp2->rdata)->gwtype,
				((struct ipseckey *)rrp2->rdata)->alg,
				ipseckey_type((struct ipseckey *)rrp2->rdata),
				buf);
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_CDS)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no cds in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "%s %d IN CDS %d %d %d (%s)\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl, 
				((struct cds *)rrp2->rdata)->key_tag, 
				((struct cds *)rrp2->rdata)->algorithm, 
				((struct cds *)rrp2->rdata)->digest_type, 
				bin2hex(((struct cds *)rrp2->rdata)->digest, ((struct cds *)rrp2->rdata)->digestlen));
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_DS)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no ds in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "%s %d IN DS %d %d %d (%s)\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl, 
				((struct ds *)rrp2->rdata)->key_tag, 
				((struct ds *)rrp2->rdata)->algorithm, 
				((struct ds *)rrp2->rdata)->digest_type, 
				bin2hex(((struct ds *)rrp2->rdata)->digest, ((struct ds *)rrp2->rdata)->digestlen));
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_CNAME)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no soa in zone!\n");
			return -1;
		}
		fprintf(of, "%s %d IN CNAME %s\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl, 
				convert_name(((struct cname *)rrp->rdata)->cname, ((struct cname *)rrp->rdata)->cnamelen));
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_NAPTR)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no ds in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "%s %d IN NAPTR %d %d \"", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl, 
				((struct naptr *)rrp2->rdata)->order, 
				((struct naptr *)rrp2->rdata)->preference);
			
			for (x = 0; x < ((struct naptr *)rrp2->rdata)->flagslen; x++) {
				fprintf(of, "%c", ((struct naptr *)rrp2->rdata)->flags[x]);
			}
			fprintf(of, "\" \"");
			for (x = 0; x < ((struct naptr *)rrp2->rdata)->serviceslen; x++) {
				fprintf(of, "%c", ((struct naptr *)rrp2->rdata)->services[x]);
			}
			fprintf(of, "\" \"");
			for (x = 0; x < ((struct naptr *)rrp2->rdata)->regexplen; x++) {
				fprintf(of, "%c", ((struct naptr *)rrp2->rdata)->regexp[x]);
			}
			fprintf(of, "\" %s\n", (((struct naptr *)rrp2->rdata)->replacement[0] == '\0') ? "." : convert_name(((struct naptr *)rrp2->rdata)->replacement, ((struct naptr *)rrp2->rdata)->replacementlen));
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_CAA)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no caa in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "%s %d IN CAA %d ", 
					convert_name(rbt->zone, rbt->zonelen),
					rrset->ttl, 
					((struct caa *)rrp2->rdata)->flags);
					
			for (i = 0; i < ((struct caa *)rrp2->rdata)->taglen; i++) {
				fprintf(of, "%c", ((struct caa *)rrp2->rdata)->tag[i]);
			}
			fprintf(of, " \"");
			for (i = 0; i < ((struct caa *)rrp2->rdata)->valuelen; i++) {
				fprintf(of, "%c", ((struct caa *)rrp2->rdata)->value[i]);
			}
			fprintf(of, "\"\n");
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_HINFO)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no hinfo in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "%s %d IN HINFO \"", 
					convert_name(rbt->zone, rbt->zonelen),
					rrset->ttl);
					
			for (i = 0; i < ((struct hinfo *)rrp2->rdata)->cpulen; i++) {
				fprintf(of, "%c", ((struct hinfo *)rrp2->rdata)->cpu[i]);
			}
			fprintf(of, "\" \"");
			for (i = 0; i < ((struct hinfo *)rrp2->rdata)->oslen; i++) {
				fprintf(of, "%c", ((struct hinfo *)rrp2->rdata)->os[i]);
			}
			fprintf(of, "\"\n");
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_TXT)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no txt in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "%s %d IN TXT \"", 
					convert_name(rbt->zone, rbt->zonelen),
					rrset->ttl);
					
			for (i = 0; i < ((struct txt *)rrp2->rdata)->txtlen; i++) {
				if (i % 256 == 0) {
					if (i)
						printf("\" \"");

					continue;
				}

				fprintf(of, "%c", ((struct txt *)rrp2->rdata)->txt[i]);
			}
			fprintf(of, "\"\n");
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_HTTPS)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no txt in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "%s %d IN HTTPS %u %s %s", 
					convert_name(rbt->zone, rbt->zonelen),
					rrset->ttl,
					((struct https *)rrp2->rdata)->priority,
					convert_name(((struct https *)rrp2->rdata)->target,
					((struct https *)rrp2->rdata)->targetlen),
					(((struct svcb *)rrp2->rdata)->paramlen > 0) ? "( " : \
					"");
					
			fprintf(of, "%s", param_tlv2human(((struct https *)rrp2->rdata)->param, ((struct https *)rrp2->rdata)->paramlen, 1));

			fprintf(of, "%s\n", (((struct svcb *)rrp2->rdata)->paramlen > 0) \
					? " )" : "");
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_SVCB)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no txt in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "%s %d IN SVCB %u %s %s", 
					convert_name(rbt->zone, rbt->zonelen),
					rrset->ttl,
					((struct https *)rrp2->rdata)->priority,
					convert_name(((struct https *)rrp2->rdata)->target,
					((struct https *)rrp2->rdata)->targetlen),
					(((struct svcb *)rrp2->rdata)->paramlen > 0) ? "( " : \
					"");
					
			fprintf(of, "%s", param_tlv2human(((struct https *)rrp2->rdata)->param, ((struct https *)rrp2->rdata)->paramlen, 1));

			fprintf(of, "%s\n", (((struct svcb *)rrp2->rdata)->paramlen > 0) \
					? " )" : "");
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_PTR)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no ds in zone!\n");
			return -1;
		}
		fprintf(of, "%s %d IN PTR %s\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl,
				convert_name(((struct ptr *)rrp->rdata)->ptr, ((struct ptr *)rrp->rdata)->ptrlen));
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_SRV)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no srv in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "%s %d IN SRV %d %d %d %s\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl, 
				((struct srv *)rrp2->rdata)->priority, 
				((struct srv *)rrp2->rdata)->weight, 
				((struct srv *)rrp2->rdata)->port, 
				convert_name(((struct srv *)rrp2->rdata)->target,((struct srv *)rrp2->rdata)->targetlen));
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_LOC)) != NULL) {
		static u_int poweroften[10] = {1, 10, 100, 1000, 10000, 100000,
                                 1000000,10000000,100000000,1000000000};
		char latitude, longitude;
		uint32_t latsecfrac, latval, latsec, latmin, latdeg;
		uint32_t longsecfrac, longval, longsec, longmin, longdeg;
		int mantissa, exponent;
		uint32_t valsize, valhprec, valvprec;
		int32_t altval;
		int altmeters, altfrac, altsign;
		const int referencealt = 100000 * 100;
		char sizestr[64], hpstr[64], vpstr[64];


		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no loc in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			longval = (((struct loc *)rrp2->rdata)->longitude - (1<<31));
			if (longval < 0) {
				longitude = 'W';
				longval = -longval;
			} else
				longitude = 'E';

			latval = (((struct loc *)rrp2->rdata)->latitude - (1<<31));
			if (latval < 0) {
				latitude = 'S';
				latval = -latval;
			} else
				latitude = 'N';

			latsecfrac = latval % 1000;
			latval = latval / 1000;
			latsec = latval % 60;
			latval = latval / 60;
			latmin = latval % 60;
			latval = latval / 60;
			latdeg = latval;

			longsecfrac = longval % 1000;
			longval = longval / 1000;
			longsec = longval % 60;
			longval = longval / 60;
			longmin = longval % 60;
			longval = longval / 60;
			longdeg = longval;

			mantissa = (int)((((struct loc *)rrp2->rdata)->size >> 4) & 0x0f) % 10;
			exponent = (int)((((struct loc *)rrp2->rdata)->size >> 0) & 0x0f) % 10;

			valsize = mantissa * poweroften[exponent];

			mantissa = (int)((((struct loc *)rrp2->rdata)->horiz_pre >> 4) & 0x0f) % 10;
			exponent = (int)((((struct loc *)rrp2->rdata)->horiz_pre >> 0) & 0x0f) % 10;

			valhprec = mantissa * poweroften[exponent];

			mantissa = (int)((((struct loc *)rrp2->rdata)->vert_pre >> 4) & 0x0f) % 10;
			exponent = (int)((((struct loc *)rrp2->rdata)->vert_pre >> 0) & 0x0f) % 10;

			valvprec = mantissa * poweroften[exponent];

			if (((struct loc *)rrp2->rdata)->altitude < referencealt) {
				altval = referencealt - ((struct loc *)rrp2->rdata)->altitude; 
				altsign = -1;
			} else {
				altval = ((struct loc *)rrp2->rdata)->altitude - referencealt;
				altsign = 1;
			}

			altfrac = altval % 100;
			altmeters = (altval / 100) * altsign;

			snprintf(sizestr, sizeof(sizestr), "%d.%.2d", valsize / 100, valsize % 100);
			snprintf(hpstr, sizeof(hpstr), "%d.%.2d", valhprec / 100, valhprec % 100);
			snprintf(vpstr, sizeof(vpstr), "%d.%.2d", valvprec / 100, valvprec % 100);

			fprintf(of, "%s %d IN LOC ( %u %u %u.%.3u %c %u %u %u.%.3u %c %d.%.2dm %sm %sm %sm )\n",
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl,
				latdeg, latmin, latsec, latsecfrac, latitude,
				longdeg, longmin, longsec, longsecfrac, longitude,
				altmeters, altfrac,  sizestr, hpstr, vpstr);
	
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_TLSA)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no tlsa in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "%s %d IN TLSA %d %d %d (%s)\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl, 
				((struct tlsa *)rrp2->rdata)->usage, 
				((struct tlsa *)rrp2->rdata)->selector, 
				((struct tlsa *)rrp2->rdata)->matchtype, 
				bin2hex(((struct tlsa *)rrp2->rdata)->data, ((struct tlsa *)rrp2->rdata)->datalen));
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_ZONEMD)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no zonemd in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "%s %d IN ZONEMD %d %d %d ( %s )\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl, 
				((struct zonemd *)rrp2->rdata)->serial, 
				((struct zonemd *)rrp2->rdata)->scheme, 
				((struct zonemd *)rrp2->rdata)->algorithm, 
				bin2hex(((struct zonemd *)rrp2->rdata)->hash, ((struct zonemd *)rrp2->rdata)->hashlen));
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_SSHFP)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no sshfp in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			fprintf(of, "%s %d IN SSHFP %d %d (%s)\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl, 
				((struct sshfp *)rrp2->rdata)->algorithm, 
				((struct sshfp *)rrp2->rdata)->fptype, 
				bin2hex(((struct sshfp *)rrp2->rdata)->fingerprint, ((struct sshfp *)rrp2->rdata)->fplen));
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_A)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no a RR in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			inet_ntop(AF_INET, &((struct a *)rrp2->rdata)->a, buf, sizeof(buf));
			fprintf(of, "%s %d IN A %s\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl,
				buf);
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_EUI48)) != NULL) {
		uint8_t e[6];

		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no eui48 RR in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			memcpy(&e, &((struct eui48 *)rrp2->rdata)->eui48, sizeof(struct eui48));
			fprintf(of, "%s %d IN EUI48 %02x-%02x-%02x-%02x-%02x-%02x\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl,
				e[0], e[1], e[2], e[3], e[4], e[5]);
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_EUI64)) != NULL) {
		uint8_t e[8];

		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no eui64 RR in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			memcpy(&e, &((struct eui64 *)rrp2->rdata)->eui64, sizeof(struct eui64));
			fprintf(of, "%s %d IN EUI64 %02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl,
				e[0], e[1], e[2], e[3], e[4], e[5], e[6], e[7]);
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_AAAA)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no a RR in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			inet_ntop(AF_INET6, &((struct aaaa *)rrp2->rdata)->aaaa , buf, sizeof(buf));
			fprintf(of, "%s %d IN AAAA %s\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl,
				buf);
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_CDNSKEY)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no a RR in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			len = mybase64_encode((const u_char *)((struct cdnskey *)rrp2->rdata)->public_key, ((struct cdnskey *)rrp2->rdata)->publickey_len, buf, sizeof(buf));
			buf[len] = '\0';
			fprintf(of, "%s %d IN CDNSKEY %d %d %d (%s)\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl, 
				((struct cdnskey *)rrp2->rdata)->flags, 
				((struct cdnskey *)rrp2->rdata)->protocol,
				((struct cdnskey *)rrp2->rdata)->algorithm,
				buf);
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_DNSKEY)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no a RR in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			len = mybase64_encode((const u_char *)((struct dnskey *)rrp2->rdata)->public_key, ((struct dnskey *)rrp2->rdata)->publickey_len, buf, sizeof(buf));
			buf[len] = '\0';
			fprintf(of, "%s %d IN DNSKEY %d %d %d (%s)\n", 
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl, 
				((struct dnskey *)rrp2->rdata)->flags, 
				((struct dnskey *)rrp2->rdata)->protocol,
				((struct dnskey *)rrp2->rdata)->algorithm,
				buf);
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_RP)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no RP RR in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
		
			fprintf(of, "%s %d IN RP %s %s\n",
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl,
				convert_name(((struct rp *)rrp2->rdata)->mbox, ((struct rp *)rrp2->rdata)->mboxlen),
				convert_name(((struct rp *)rrp2->rdata)->txt, ((struct rp *)rrp2->rdata)->txtlen));
		}
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_NSEC3PARAM)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no NSEC3PARAM RR in zone!\n");
			return -1;
		}
		
		fprintf(of, "%s 0 IN NSEC3PARAM %d %d %d (%s)\n",
			convert_name(rbt->zone, rbt->zonelen),
			((struct nsec3param *)rrp->rdata)->algorithm,	
			((struct nsec3param *)rrp->rdata)->flags,	
			((struct nsec3param *)rrp->rdata)->iterations,	
			(((struct nsec3param *)rrp->rdata)->saltlen == 0) ? "-" : bin2hex(((struct nsec3param *)rrp->rdata)->salt, ((struct nsec3param *)rrp->rdata)->saltlen));
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_NSEC3)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no NSEC3PARAM RR in zone!\n");
			return -1;
		}
		
		fprintf(of, "%s %d IN NSEC3 %d %d %d %s %s %s\n",
			convert_name(rbt->zone, rbt->zonelen),
			rrset->ttl,
			((struct nsec3 *)rrp->rdata)->algorithm,
			((struct nsec3 *)rrp->rdata)->flags,
			((struct nsec3 *)rrp->rdata)->iterations,
			(((struct nsec3 *)rrp->rdata)->saltlen == 0) ? "-" : bin2hex(((struct nsec3 *)rrp->rdata)->salt, ((struct nsec3 *)rrp->rdata)->saltlen),
			base32hex_encode((u_char *)((struct nsec3 *)rrp->rdata)->next, ((struct nsec3 *)rrp->rdata)->nextlen),
			bitmap2human(((struct nsec3 *)rrp->rdata)->bitmap, ((struct nsec3 *)rrp->rdata)->bitmap_len));
	}
	if ((rrset = find_rr(rbt, DNS_TYPE_NSEC)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no nsec in zone!\n");
			return -1;
		}
		fprintf(of, "%s %d IN NSEC %s %s\n",
			convert_name(rbt->zone, rbt->zonelen),
			rrset->ttl,
			convert_name((u_char *)((struct nsec *)rrp->rdata)->next, ((struct nsec *)rrp->rdata)->next_len),
			bitmap2human(((struct nsec *)rrp->rdata)->bitmap, ((struct nsec *)rrp->rdata)->bitmap_len));

	}
	if ((rrset = find_rr(rbt, DNS_TYPE_RRSIG)) != NULL) {
		if ((rrp = TAILQ_FIRST(&rrset->rr_head)) == NULL) {
			dolog(LOG_INFO, "no a RR in zone!\n");
			return -1;
		}
		TAILQ_FOREACH(rrp2, &rrset->rr_head, entries) {
			len = mybase64_encode((u_char *)((struct rrsig *)rrp2->rdata)->signature, ((struct rrsig *)rrp2->rdata)->signature_len, buf, sizeof(buf));
			buf[len] = '\0';

#if defined __FreeBSD__ || defined __linux__
			fprintf(of, "%s %d IN RRSIG (%s %d %d %d %lu %lu %d %s %s)\n", 
#else
			fprintf(of, "%s %d IN RRSIG (%s %d %d %d %llu %llu %d %s %s)\n", 
#endif
				convert_name(rbt->zone, rbt->zonelen),
				rrset->ttl,
				get_dns_type(((struct rrsig *)rrp2->rdata)->type_covered, 0), 
				((struct rrsig *)rrp2->rdata)->algorithm,
				((struct rrsig *)rrp2->rdata)->labels,
				((struct rrsig *)rrp2->rdata)->original_ttl,
				timethuman(((struct rrsig *)rrp2->rdata)->signature_expiration),
				timethuman(((struct rrsig *)rrp2->rdata)->signature_inception), 
				((struct rrsig *)rrp2->rdata)->key_tag,
				convert_name(((struct rrsig *)rrp2->rdata)->signers_name, ((struct rrsig *)rrp2->rdata)->signame_len),
				buf);	
		}
	}

	return 0;
}


int	
bindfile(int argc, char *argv[])
{
	ddDB *db;
	char *zonefile;
	char *zonename;
	FILE *of = stdout;
	int len;
	uint32_t flags = PARSEFILE_FLAG_NOSOCKET;

	if (argc != 3) {
		usage(argc, argv);
		exit(1);
	}

	zonename = argv[1];
	zonefile = argv[2];

	len = strlen(zonename);
	if (zonename[len - 1] != '.') {
		len += 2;
		zonename = malloc(len);
		if (zonename == NULL) {
			perror("malloc");
			return 1;
		}

		strlcpy(zonename, argv[1], len);
		strlcat(zonename, ".", len);
	}
			

#if __OpenBSD__
	if (pledge("stdio rpath cpath", NULL) < 0) {
		perror("pledge");
		exit(1);
	}
#endif



	/* open the database(s) */
	db = dddbopen();
	if (db == NULL) {
		dolog(LOG_INFO, "dddbopen() failed\n");
		return 1;
	}

	/* now we start reading our configfile */
		
	if (parse_file(db, zonefile, flags, -1) < 0) {
		dolog(LOG_INFO, "parsing config file failed\n");
		return 1;
	}

	if (dump_db_bind(db, of, zonename) < 0) {
		dddbclose(db);
		return 1;
	}

	dddbclose(db);
	
	
	return 0;
}


int
count_db(ddDB *db)
{
	struct rbtree *rbt;
	struct rrset *rrset = NULL;
	struct rr *rrp = NULL;
	struct node *n, *nx;
	int count = 0;
	int rs;
	
	RB_FOREACH_SAFE(n, domaintree, &db->head, nx) {
		rs = n->datalen;
		if ((rbt = calloc(1, rs)) == NULL) {
			dolog(LOG_INFO, "calloc: %s\n", strerror(errno));
			exit(1);
		}


		memcpy((char *)rbt, (char *)n->data, n->datalen);


		TAILQ_FOREACH(rrset, &rbt->rrset_head, entries) {
			TAILQ_FOREACH(rrp, &rrset->rr_head, entries) {
					count++;
			}
		}
	}

	printf("Records = %d , ", count);

	return count;
}
