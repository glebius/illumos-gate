# $FreeBSD$

MDB_DIR=	${.CURDIR}/../../../../../usr/src/cmd/mdb

PROG=	mdb

CFLAGS+= -I${.CURDIR}/../../../../sys/cddl/compat/opensolaris \
	-I${FREEBSD_SRC_DIR}/sys/cddl/compat/opensolaris \
	-I${.CURDIR}/../../../../cddl/compat/opensolaris/include \
	-I${FREEBSD_SRC_DIR}/cddl/compat/opensolaris/include \
	-I${OPENSOLARIS_USR_DISTDIR}/lib/libctf/common \
	-I${OPENSOLARIS_SYS_DISTDIR}/uts/common

.if ${MACHINE_ARCH} == "amd64"
.PATH: ${MDB_DIR}/intel/amd64/mdb
.PATH: ${MDB_DIR}/intel/mdb

xSRCS+=	kvm_amd64dep.c \
	kvm_isadep.c \
	mdb_amd64util.c \
	proc_amd64dep.c

CFLAGS+= -I${MDB_DIR}/intel/mdb
CFLAGS+= -I${MDB_DIR}/intel/amd64/mdb
CFLAGS+= -I${MDB_DIR}/intel

# ???: CPPFLAGS+= -D_ELF64
.else
.error "Unsupported platform"
.endif

.PATH: ${MDB_DIR}/common/mdb

#	ffs.c \

SRCS += \
	mdb.c \
	mdb_addrvec.c \
	mdb_argvec.c \
	mdb_callb.c \
	mdb_cmdbuf.c \
	mdb_cmds.c \
	mdb_conf.c \
	mdb_context.c \
	mdb_create.c \
	mdb_ctf.c \
	mdb_ctf_open.c \
	mdb_debug.c \
	mdb_demangle.c \
	mdb_disasm.c \
	mdb_dump.c \
	mdb_err.c \
	mdb_evset.c \
	mdb_fdio.c \
	mdb_fmt.c \
	mdb_frame.c \
	mdb_gelf.c \
	mdb_help.c \
	mdb_io.c \
	mdb_kb_kvm.c \
	mdb_kproc.c \
	mdb_kvm.c \
	mdb_logio.c \
	mdb_list.c \
	mdb_macalias.c \
	mdb_main.c \
	mdb_memio.c \
	mdb_modapi.c \
	mdb_module.c \
	mdb_module_load.c \
	mdb_nm.c \
	mdb_nv.c \
	mdb_pipeio.c \
	mdb_print.c \
	mdb_proc.c \
	mdb_pservice.c \
	mdb_rawfile.c \
	mdb_set.c \
	mdb_shell.c \
	mdb_signal.c \
	mdb_stdlib.c \
	mdb_string.c \
	mdb_strio.c \
	mdb_tab.c \
	mdb_target.c \
	mdb_tdb.c \
	mdb_termio.c \
	mdb_typedef.c \
	mdb_umem.c \
	mdb_value.c \
	mdb_vcb.c \
	mdb_wcb.c \
	mdb_whatis.c

CFLAGS+= -D_MDB -I${MDB_DIR}/common

LIBADD=	curses kvm proc rtld_db ctf umem #disasm scf

# For 10.x
LDADD= -lcurses -lkvm -lproc -lrtld_db -lctf -lumem #-ldisasm -lscf

SRCS+=	mdb_lex.l \
	mdb_grammar.y

.PATH: ${.CURDIR}/../../../../cddl/compat/opensolaris/misc

SRCS+=	\
	fdwalk.c

# Convince mdb_types.h that FreeBSD always has uintptr_t defined.
CFLAGS+= -D_SYS_INT_TYPES_H

# Use 'aligned_alloc' from jemalloc for 'memalign'.
CFLAGS+= -Dmemalign=aligned_alloc

# Map FreeBSD termios ioctls to illumos names.
CFLAGS+= -DTCGETS=TIOCGETA -DTCSETSW=TIOCSETAW

# FreeBSD doesn't have an input mode like IUCLC
CFLAGS+= -DIUCLC=0

# Use ENOENT for ENODATA.
CFLAGS+= -DENODATA=ENOENT

.include <bsd.prog.mk>

CWARNFLAGS+= -Wno-cast-align \
	-Wno-incompatible-pointer-types \
	-Wno-incompatible-pointer-types-discards-qualifiers \
	-Wno-shadow \
	-Wno-sign-compare \
	-Wno-unused-parameter
