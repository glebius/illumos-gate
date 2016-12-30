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
#include <mdb/mdb_ks.h>

#include <sys/queue.h>

static ssize_t struct_linker_file_size;
static ssize_t struct_module_size;

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

typedef struct {
	TAILQ_ENTRY(module) link;
	TAILQ_ENTRY(module) flink;
	int	refs;
	int	id;
	char	*name;
} mdb_module_t;

static int
lf_walk_init(mdb_walk_state_t *wsp)
{

	if (struct_linker_file_size == 0)
		struct_linker_file_size = mdb_type_size("struct linker_file");
	if (struct_linker_file_size == -1) {
		mdb_warn("failed to lookup size of 'struct linker_file'");
		return (WALK_ERR);
	}
	if (wsp->walk_addr == 0) {
		wsp->walk_addr = mdb_tailq_first("linker_files");
		if (wsp->walk_addr == (uintptr_t)-1)
			return (WALK_ERR);
	}

	return (WALK_NEXT);
}

static int
lf_walk_step(mdb_walk_state_t *wsp)
{
	uint8_t tgtlf[struct_linker_file_size];
	mdb_linker_file_t lf;
	int	status;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_vread(tgtlf, sizeof (tgtlf), wsp->walk_addr) == -1) {
		mdb_warn("failed to read struct linker_file at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	if (mdb_ctf_convert(&lf, "struct linker_file", "mdb_linker_file_t",
	    tgtlf, 0) == -1) {
		mdb_warn("failed to parse struct linker_file at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, tgtlf, wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)TAILQ_NEXT(&lf, link);

	return (status);
}

static void
lf_walk_fini(mdb_walk_state_t *wsp)
{
}

static int
lfmod_walk_init(mdb_walk_state_t *wsp)
{
	mdb_linker_file_t lf;

	/*
	 * This walker requires the address of a linker_file as the
	 * starting address.
	 */
	if (wsp->walk_addr == 0)
		return (WALK_ERR);

	if (struct_module_size == 0)
		struct_module_size = mdb_type_size("struct module");
	if (struct_module_size == -1) {
		mdb_warn("failed to lookup size of 'struct module'");
		return (WALK_ERR);
	}

	/* Fetch the start of the list from the linker file. */
	if (mdb_ctf_vread(&lf, "struct linker_file", "mdb_linker_file_t",
	    wsp->walk_addr, 0) == -1) {
		mdb_warn("failed to read struct linker_file at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)TAILQ_FIRST(&lf.modules);

	return (WALK_NEXT);
}

static int
lfmod_walk_step(mdb_walk_state_t *wsp)
{
	uint8_t tgtmod[struct_module_size];
	mdb_module_t mod;
	int	status;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_vread(tgtmod, sizeof (tgtmod), wsp->walk_addr) == -1) {
		mdb_warn("failed to read module_t at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	if (mdb_ctf_convert(&mod, "struct module", "mdb_module_t", tgtmod,
	    0) == -1) {
		mdb_warn("failed to parse module_t at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, tgtmod, wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)TAILQ_NEXT(&mod, flink);

	return (status);
}

static void
lfmod_walk_fini(mdb_walk_state_t *wsp)
{
}

static int
lfmod_format(uintptr_t addr, const void *data, void *private)
{
	char name[MAXPATHLEN];
	mdb_module_t mod;

	if (mdb_ctf_convert(&mod, "struct module", "mdb_module_t", data,
	    0) == -1) {
		mdb_warn("failed to parse module_t at %#lr", addr);
		return (WALK_ERR);
	}

	if (mdb_readstr(name, sizeof (name), (uintptr_t)mod.name) == -1)
		strcpy(name, "???");

	mdb_printf("\t\t%d %s\n", mod.id, name);

	return (WALK_NEXT);
}

static int
kldstat_format(uintptr_t addr, const void *data, void *private)
{
	char name[MAXPATHLEN], pathname[MAXPATHLEN];
	int *verbosep;
	mdb_linker_file_t lf;

	verbosep = private;
	if (mdb_ctf_convert(&lf, "struct linker_file", "mdb_linker_file_t",
	    data, 0) == -1) {
		mdb_warn("failed to parse linker_file_t at %#lr",
		    addr);
		return (WALK_ERR);
	}

	if (mdb_readstr(name, sizeof (name), (uintptr_t)lf.filename) == -1)
		strcpy(name, "???");
	if (*verbosep == 0 || mdb_readstr(pathname, sizeof (pathname),
	    (uintptr_t)lf.pathname) == -1)
		strcpy(pathname, "???");

	mdb_printf("%2d %4d 0x%?p %-8lx %s", lf.id, lf.refs, lf.address,
	    (unsigned long)lf.size, name);
	if (*verbosep) {
		mdb_printf(" (%s)\n", pathname);
		mdb_printf("\tContains modules:\n");
		mdb_printf("\t\tId Name\n");
		mdb_pwalk("lf_modules", lfmod_format, NULL, addr);
	} else
		mdb_printf("\n");

	return (WALK_NEXT);
}

static int
kldstat(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t verbose = 0;

	mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, 1, &verbose,
	    NULL);

	if ((flags & DCMD_LOOPFIRST) || !(flags & DCMD_LOOP)) {
		mdb_printf("%<u>%2s %4s %-?s   %-8s %s%</u>\n",
		    "Id", "Refs", "Address", "Size", "Name");
	}

	if (flags & DCMD_ADDRSPEC) {
		uint8_t lf[struct_linker_file_size];

		(void) mdb_vread(lf, sizeof (lf), addr);
		return (kldstat_format(addr, lf, &verbose));
	}

	if (mdb_walk("linker_files", kldstat_format, &verbose) == -1)
		return (DCMD_ERR);

	return (DCMD_OK);
}

static const mdb_dcmd_t dcmds[] = {
	{ "kldstat", "?[-v]", "list kernel modules", kldstat },
#if 0
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
	{ "lf_modules", "list of module_t structures from a linker_file_t",
		lfmod_walk_init, lfmod_walk_step, lfmod_walk_fini },
	{ NULL }
};

static const mdb_modinfo_t kld_modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{

	return (&kld_modinfo);
}
