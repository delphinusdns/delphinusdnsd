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

