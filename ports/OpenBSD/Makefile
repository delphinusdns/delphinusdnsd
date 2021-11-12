COMMENT =           simple authorative DNS server
DISTNAME =          delphinusdnsd-${V}
V =		    1.5.4
PKGNAME =           ${DISTNAME}
CATEGORIES =        net

GH_ACCOUNT =        delphinusdns
GH_PROJECT =        delphinusdnsd
GH_TAGNAME =	    RELEASE_1_5_4

HOMEPAGE =          https://delphinusdns.org/
MAINTAINER =        Ricardo Santos <risantos@pm.me>

# BSD
PERMIT_PACKAGE =    Yes
#uses pledge()

WANTLIB +=          c ssl crypto util

CONFIGURE_STYLE =   simple

NO_TEST =           Yes

SEPARATE_BUILD =    Yes

post-install:
	${INSTALL_DATA_DIR} ${PREFIX}/share/examples/delphinusdnsd
	${INSTALL_DATA} ${WRKDIST}/examples/Master/*.conf \
		${PREFIX}/share/examples/delphinusdnsd

.include <bsd.port.mk>
