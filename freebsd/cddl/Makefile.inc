# $FreeBSD$

FREEBSD_SRC_DIR?=	/usr/src
OPENSOLARIS_USR_DISTDIR= ${FREEBSD_SRC_DIR}/cddl/contrib/opensolaris
OPENSOLARIS_SYS_DISTDIR= ${FREEBSD_SRC_DIR}/sys/cddl/contrib/opensolaris

IGNORE_PRAGMA=	YES

CFLAGS+=	-DNEED_SOLARIS_BOOLEAN

WARNS?=		6

# Do not lint the CDDL stuff. It is all externally maintained and
# lint output is wasteful noise here.

NO_LINT=
