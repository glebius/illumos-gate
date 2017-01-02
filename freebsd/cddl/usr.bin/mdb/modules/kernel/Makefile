# $FreeBSD$

MOD=	kernel
SRCS=	kernel.c kgrep.c vm.c

.include <bsd.lib.mk>

.PATH:	${MDB_DIR}/common/modules/genunix

CFLAGS+= -I${MDB_DIR}/common/modules/genunix
