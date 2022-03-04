COMMENT =	simple authorative DNS server

V =		1.6.0
DISTNAME =	delphinusdnsd-${V}
PKGNAME =	${DISTNAME}
CATEGORIES =	net

GH_ACCOUNT =	delphinusdns
GH_PROJECT =	delphinusdnsd
GH_COMMIT =	60a5e1a2bfc64b3192a98b00764cb875f5951853

HOMEPAGE =	https://delphinusdns.org/

MAINTAINER =	Ricardo Santos <risantos@pm.me>

# BSD
PERMIT_PACKAGE =    Yes
#uses pledge()

WANTLIB +=	c ssl crypto util
CFLAGS =	-Wall -g
LDFLAGS =	-Wall -g

CONFIGURE_STYLE =	simple

NO_TEST =	Yes

post-install:
	${INSTALL_DATA_DIR} ${PREFIX}/share/examples/delphinusdnsd
	${INSTALL_DATA} ${WRKDIST}/examples/Master/{master1.conf,master2.conf} \
		${PREFIX}/share/examples/delphinusdnsd
	${INSTALL_DATA} ${WRKDIST}/examples/Replicant/{replicant1.conf,replicant2.conf} \
		${PREFIX}/share/examples/delphinusdnsd

.include <bsd.port.mk>
