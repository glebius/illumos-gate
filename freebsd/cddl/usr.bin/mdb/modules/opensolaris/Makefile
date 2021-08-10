# $FreeBSD$

MOD=	opensolaris
SRCS=	opensolaris.c nvpair.c

OSVERSION!=   awk '/^\#define[[:blank:]]__FreeBSD_version/ {print $$3}' < /usr/include/sys/param.h

.if ${OSVERSION} < 1400025
SRCS+=	avl.c
.endif

CWARNFLAGS.clang+= \
	-Wno-cast-align

CFLAGS+= -I${MDB_DIR}/common/modules/genunix

.include <bsd.lib.mk>

.PATH:	${MDB_DIR}/common/modules/genunix
