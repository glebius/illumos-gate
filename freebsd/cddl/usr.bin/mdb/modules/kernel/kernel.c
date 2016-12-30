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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2016 Joyent, Inc.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ctf.h>
#include <mdb/mdb_ks.h>

#include <sys/proc.h>

typedef struct {
	TAILQ_ENTRY(thread) td_plist;
	lwpid_t		td_tid;
	int		td_inhibitors;
	void		*td_wchan;
	const char	*td_wmesg;
} mdb_thread_t;

typedef struct {
	LIST_ENTRY(proc) p_list;
	TAILQ_HEAD(, thread) p_threads;
	enum {
		PRS_NEW = 0,
		PRS_NORMAL,
		PRS_ZOMBIE
	} p_state;
	pid_t		p_pid;
} mdb_proc_t;

static ssize_t struct_proc_size;

int
proc_walk_init(mdb_walk_state_t *wsp)
{

	if (struct_proc_size == 0)
		struct_proc_size = mdb_type_size("struct proc");
	if (struct_proc_size == -1) {
		mdb_warn("failed to lookup size of 'struct proc'");
		return (WALK_ERR);
	}
	
	if (wsp->walk_addr == 0) {
		wsp->walk_addr = mdb_list_first("allproc");
		if (wsp->walk_addr == (uintptr_t)-1)
			return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
proc_walk_step(mdb_walk_state_t *wsp)
{
	uint8_t tgtproc[struct_proc_size];
	mdb_proc_t p;
	int	status;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_vread(tgtproc, sizeof (tgtproc), wsp->walk_addr) == -1) {
		mdb_warn("failed to read struct proc at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	if (mdb_ctf_convert(&p, "struct proc", "mdb_proc_t", tgtproc, 0) ==
	    -1) {
		mdb_warn("failed to parse struct proc at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}
	
	status = wsp->walk_callback(wsp->walk_addr, tgtproc, wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)LIST_NEXT(&p, p_list);
	if (wsp->walk_addr == 0 && p.p_state != PRS_ZOMBIE) {
		wsp->walk_addr = mdb_tailq_first("zombproc");
		if (wsp->walk_addr == (uintptr_t)-1)
			wsp->walk_addr = 0;
	}

	return (status);
	
		
}

void
proc_walk_fini(mdb_walk_state_t *wsp)
{
}

static const mdb_dcmd_t dcmds[] = {
#if 0
	{ "ps", NULL, "list processes (and associated threads)", ps },
#endif
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "proc", "list of struct proc structures",
	  proc_walk_init, proc_walk_step, proc_walk_fini },
	{ NULL }
};

static const mdb_modinfo_t kernel_modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	
	return (&kernel_modinfo);
}
