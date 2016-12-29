/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ctf.h>

#include <sys/queue.h>

static uintptr_t linker_files_addr;
static size_t linker_file_t_size;

typedef struct {
	int	refs;
	TAILQ_ENTRY(linker_file) link;
	char	*filename;
	char	*pathname;
	int	id;
	char	*address;
	size_t	size;
	TAILQ_HEAD(, module) modules;
} mdb_linker_file_t;

#if 0
typedef struct {
	TAILQ_ENTRY(module) flink;
	int	refs;
	int	id;
	char	*name;
} mdb_module_t;
#endif

struct lf_walk_data {
	uintptr_t lfd_head;
	uint8_t lfd_lf[0];
};

static int
lf_walk_init(mdb_walk_state_t *wsp)
{
	struct lf_walk_data *lfd = mdb_alloc(
	    sizeof (struct lf_walk_data) + linker_file_t_size, UM_SLEEP);

	lfd->lfd_head = (wsp->walk_addr == 0 ? linker_files_addr : wsp->walk_addr);
	wsp->walk_data = lfd;
	wsp->walk_addr = 0;

	return (WALK_NEXT);
}

static int
lf_walk_step(mdb_walk_state_t *wsp)
{
	struct lf_walk_data *lfd = wsp->walk_data;
	mdb_linker_file_t lf;
	int	status;

	if (wsp->walk_addr == lfd->lfd_head)
		return (WALK_DONE);

	if (wsp->walk_addr == 0) {
		wsp->walk_addr = lfd->lfd_head;
		lfd->lfd_head = 0;
	}

	/* If this is the start of the list, read TAILQ_FIRST(). */
	if (wsp->walk_addr == linker_files_addr) {
		if (mdb_vread(&wsp->walk_addr, sizeof (wsp->walk_addr),
		    linker_files_addr) == -1) {
			mdb_warn("failed to read *linker_files\n");
			return (WALK_ERR);
		}
	}

	if (mdb_vread(lfd->lfd_lf, linker_file_t_size,
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read linker_file_t at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	if (mdb_ctf_convert(&lf, "struct linker_file", "mdb_linker_file_t",
	    lfd->lfd_lf, 0) == -1) {
		mdb_warn("failed to parse linker_file_t at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}
	
	status = wsp->walk_callback(wsp->walk_addr, lfd->lfd_lf,
	    wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)TAILQ_NEXT(&lf, link);

	return (status);
}

static void
lf_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct lf_walk_data) +
	    linker_file_t_size);
}

#if 0
static int
kldstat(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t addr;
	uint_t verbose = 0;

	mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, 1, &verbose,
	    NULL);

	if (mdb_vread(&addr, sizeof (addr), linker_files_addr) == -1) {
		mdb_warn("failed to read linker_file_t");
	}
}
#endif

static const mdb_dcmd_t dcmds[] = {
#if 0
	{ "kldstat", "?[-v]", "list kernel modules", kldstat },
	{ "modctl", NULL, "list modctl structures", modctls },
	{ "modhdrs", ":", "given modctl, dump module ehdr and shdrs", modhdrs },
	{ "modinfo", NULL, "list module information", modinfo },
	{ "ctfinfo", NULL, "list module CTF information", ctfinfo },
#endif
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "linker_files", "list of linker_file_t structures",
		lf_walk_init, lf_walk_step, lf_walk_fini },
	{ NULL }
};

static const mdb_modinfo_t kld_modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	GElf_Sym sym;
	mdb_ctf_id_t id;
	ssize_t size;

	if (mdb_lookup_by_name("linker_files", &sym) == -1) {
		mdb_warn("failed to lookup 'linker_files'");
		return (NULL);
	}

	linker_files_addr = (uintptr_t)sym.st_value;

	if (mdb_ctf_lookup_by_name("struct linker_file", &id) != 0) {
		mdb_warn("failed to lookup type 'struct linker_file'");
		return (NULL);
	}

	size = mdb_ctf_type_size(id);
	if (size <= 0) {
		mdb_warn("failed to lookup sizeof of 'struct linker_file'");
		return (NULL);
	}

	linker_file_t_size = size;

	return (&kld_modinfo);
}
