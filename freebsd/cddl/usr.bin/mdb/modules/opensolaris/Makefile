# $FreeBSD$

MOD=	opensolaris
SRCS=	opensolaris.c nvpair.c avl.c

CWARNFLAGS.clang+= \
	-Wno-cast-align

CFLAGS+= -I${MDB_DIR}/common/modules/genunix

.include <bsd.lib.mk>

.PATH:	${MDB_DIR}/common/modules/genunix
