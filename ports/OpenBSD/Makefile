COMMENT =	simple authorative DNS server

V =		1.5.4
DISTNAME =	delphinusdnsd-${V}
PKGNAME =	${DISTNAME}
REVISION =	9

GH_ACCOUNT =	delphinusdns
GH_PROJECT =	delphinusdnsd
GH_COMMIT =	73462a603f5f49da80295fe708cf0c0a07e419c6

CATEGORIES =	net
HOMEPAGE =	https://delphinusdns.org/
MAINTAINER =	Ricardo Santos <risantos@pm.me>

# BSD
PERMIT_PACKAGE =    Yes
#uses pledge()

WANTLIB +=	c ssl crypto util
CFLAGS =	-Wall -g
LDFLAGS =	-Wall -g

CONFIGURE_STYLE =	simple
CONFIGURE_ARGS =	--user=_ddd \
			--location=/var/delphinusdnsd

NO_TEST =	Yes

post-install:
	${INSTALL_DATA_DIR} ${PREFIX}/share/examples/delphinusdnsd
	${INSTALL_DATA} ${WRKDIST}/examples/Master/{master1.conf,master2.conf} \
		${PREFIX}/share/examples/delphinusdnsd
	${INSTALL_DATA} ${WRKDIST}/examples/Replicant/{replicant1.conf,replicant2.conf} \
		${PREFIX}/share/examples/delphinusdnsd


.include <bsd.port.mk>
