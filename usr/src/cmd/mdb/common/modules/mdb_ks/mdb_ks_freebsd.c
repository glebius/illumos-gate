/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Mdb kernel support module.  This module is loaded automatically when the
 * kvm target is initialized.  Any global functions declared here are exported
 * for the resolution of symbols in subsequently loaded modules.
 */

#include <mdb/mdb_target.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ctf.h>
#include <mdb/mdb_ks.h>

#include <sys/types.h>
#include <sys/msgbuf.h>

typedef struct {
	uintptr_t msg_ptr;
	u_int msg_magic;
	u_int msg_size;
	u_int msg_wseq;
	u_int msg_rseq;
	u_int msg_seqmod;
} mdb_msgbuf_t;

uintptr_t
mdb_list_first(const char *name)
{
	GElf_Sym sym;
	uintptr_t val;

	if (mdb_lookup_by_name(name, &sym) == -1) {
		mdb_warn("failed to lookup '%s'", name);
		return ((uintptr_t)-1);
	}

	if (mdb_vread(&val, sizeof(val), sym.st_value) == -1) {
		mdb_warn("failed to read '%s'", name);
		return ((uintptr_t)-1);
	}
	return (val);
}

uintptr_t
mdb_tailq_first(const char *name)
{
	GElf_Sym sym;
	uintptr_t val;

	if (mdb_lookup_by_name(name, &sym) == -1) {
		mdb_warn("failed to lookup '%s'", name);
		return ((uintptr_t)-1);
	}

	if (mdb_vread(&val, sizeof(val), sym.st_value) == -1) {
		mdb_warn("failed to read '%s'", name);
		return ((uintptr_t)-1);
	}
	return (val);
}

ssize_t
mdb_type_size(const char *name)
{
	mdb_ctf_id_t id;

	if (mdb_ctf_lookup_by_name(name, &id) != 0) {
		return (-1);
	}

	return (mdb_ctf_type_size(id));
}

static int
dmesg_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t msgbuf_addr;
	mdb_msgbuf_t buf;
	uint_t verbose = 0;
	int rseq, wseq;
	char c;

	mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, 1, &verbose,
	    NULL);

	if (mdb_readvar(&msgbuf_addr, "msgbufp") == -1) {
		mdb_warn("failed to read msgbufp");
		return (-1);
	}

	if (mdb_ctf_vread(&buf, "struct msgbuf", "mdb_msgbuf_t", msgbuf_addr,
	    0) == -1)
		return (-1);

	if (buf.msg_ptr == 0 || buf.msg_size == 0)
		return (0);

	wseq = MSGBUF_SEQ_TO_POS(&buf, buf.msg_wseq);

	if (verbose) {
		rseq = MSGBUF_SEQNORM(&buf, buf.msg_wseq - buf.msg_size);
	} else {
		mdb_printf("Unread portion of the message buffer:\n");
		rseq = MSGBUF_SEQ_TO_POS(&buf, buf.msg_rseq);
	}

	c = '\n';
	while (rseq != wseq) {
		mdb_vread(&c, sizeof(c), buf.msg_ptr + rseq);
		mdb_printf("%c", c);
		rseq = MSGBUF_SEQNORM(&buf, rseq + 1);
	}
	if (c != '\n')
		mdb_printf("\n");
	return (0);
}

static const mdb_dcmd_t dcmds[] = {
	{ "dmesg", "?[-v]", "print message buffer", dmesg_dcmd },
	{ NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds };

const mdb_modinfo_t *
_mdb_init(void)
{

	return (&modinfo);
}

void
_mdb_fini(void)
{
}
