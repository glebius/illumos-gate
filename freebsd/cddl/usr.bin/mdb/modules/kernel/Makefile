# $FreeBSD$

MOD=	kernel
SRCS=	findstack.c findstack_subr.c kernel.c kgrep.c net.c vm.c

.include <bsd.lib.mk>

.PATH:	${MDB_DIR}/common/modules/genunix

CFLAGS+= -I${.CURDIR} -I${MDB_DIR}/common/modules/genunix
