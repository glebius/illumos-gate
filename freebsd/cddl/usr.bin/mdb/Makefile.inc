# $FreeBSD$

.if ${MACHINE_ARCH} == "amd64"
CFLAGS+= -D__amd64
.endif

.include "../Makefile.inc"
