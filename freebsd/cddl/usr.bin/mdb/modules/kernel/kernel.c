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
#include <regex.h>
#include <stdbool.h>

#include "kernel.h"
#include "kgrep.h"

typedef struct {
	TAILQ_ENTRY(thread) td_plist;
	lwpid_t		td_tid;
	int		td_flags;
	int		td_inhibitors;
	void		*td_wchan;
	const char	*td_wmesg;
	struct turnstile *td_blocked;
	const char	*td_lockname;
	char		td_name[MAXCOMLEN + 1];
	enum {
		TDS_INACTIVE = 0x0,
		TDS_INHIBITED,
		TDS_CAN_RUN,
		TDS_RUNQ,
		TDS_RUNNING
	} td_state;
	int		td_oncpu;
} mdb_thread_t;

typedef struct {
	LIST_ENTRY(proc) p_list;
	TAILQ_HEAD(, thread) p_threads;
	struct ucred	*p_ucred;
	struct pstats	*p_stats;
	int		p_flag;
	enum {
		PRS_NEW = 0,
		PRS_NORMAL,
		PRS_ZOMBIE
	} p_state;
	pid_t		p_pid;
	struct proc	*p_pptr;
	u_int		p_lock;
	char		p_comm[MAXCOMLEN + 1];
	struct pgrp	*p_pgrp;
} mdb_proc_t;

typedef struct {
	struct proc	*s_leader;
} mdb_session_t;

typedef struct {
	struct session	*pg_session;
	pid_t		pg_id;
} mdb_pgrp_t;

typedef struct {
	uid_t		cr_ruid;
	struct prison	*cr_prison;
} mdb_ucred_t;

typedef struct {
	struct timeval	p_start;
} mdb_pstats_t;

static ssize_t struct_proc_size;
static ssize_t struct_thread_size;
static uintptr_t prison0_addr;

static bool
jailed(mdb_ucred_t *cred)
{

	if (prison0_addr == 0) {
		GElf_Sym sym;

		if (mdb_lookup_by_name("prison0", &sym) == -1) {
			mdb_warn("failed to lookup 'prison0'");
			prison0_addr = (uintptr_t)-1;
			return (false);
		}
		prison0_addr = sym.st_value;
	}

	return ((uintptr_t)cred->cr_prison != prison0_addr);
}

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

static int
thread_walk_init(mdb_walk_state_t *wsp)
{
	mdb_proc_t p;

	/*
	 * This walker requires the address of a struct proc as the
	 * starting address.
	 */
	if (wsp->walk_addr == 0)
		return (WALK_ERR);

	if (struct_thread_size == 0)
		struct_thread_size = mdb_type_size("struct thread");
	if (struct_thread_size == -1) {
		mdb_warn("failed to lookup size of 'struct thread'");
		return (WALK_ERR);
	}

	/* Fetch the start of the list from the linker file. */
	if (mdb_ctf_vread(&p, "struct proc", "mdb_proc_t",
	    wsp->walk_addr, 0) == -1) {
		mdb_warn("failed to read struct proc at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)TAILQ_FIRST(&p.p_threads);

	return (WALK_NEXT);
}

static int
thread_walk_step(mdb_walk_state_t *wsp)
{
	uint8_t tgttd[struct_thread_size];
	mdb_thread_t td;
	int	status;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_vread(tgttd, sizeof (tgttd), wsp->walk_addr) == -1) {
		mdb_warn("failed to read struct thread at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	if (mdb_ctf_convert(&td, "struct thread", "mdb_thread_t", tgttd,
	    0) == -1) {
		mdb_warn("failed to parse struct thread at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, tgttd, wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)TAILQ_NEXT(&td, td_plist);

	return (status);
}

static void
thread_walk_fini(mdb_walk_state_t *wsp)
{
}

struct thread_states {
	int rflag;
	int sflag;
	int dflag;
	int lflag;
	int wflag;
};

static int
thread_state(uintptr_t addr, const void *data, void *private)
{
	struct thread_states *ts;
	mdb_thread_t td;

	ts = private;

	if (mdb_ctf_convert(&td, "struct thread", "mdb_thread_t", data, 0) ==
	    -1)
		return (WALK_ERR);
	
	if (td.td_state == TDS_RUNNING ||
	    td.td_state == TDS_RUNQ ||
	    td.td_state == TDS_CAN_RUN)
		ts->rflag++;
	if (TD_ON_LOCK(&td))
		ts->lflag++;
	if (TD_IS_SLEEPING(&td)) {
		if (!(td.td_flags & TDF_SINTR))
			ts->dflag++;
		else
			ts->sflag++;
	}
	if (TD_AWAITING_INTR(&td))
		ts->wflag++;

	return (WALK_NEXT);
}

static int
print_thread(uintptr_t addr, const void *data, void *private)
{
	char state[7], wmesg[9];
	void *wchan;
	const mdb_proc_t *p;
	mdb_thread_t td;

	p = private;
	if (mdb_ctf_convert(&td, "struct thread", "mdb_thread_t", data, 0) ==
	    -1)
		return (WALK_ERR);

	if (p->p_flag & P_HADTHREADS) {
		mdb_printf("%6d                  ", td.td_tid);
		switch (td.td_state) {
		case TDS_RUNNING:
			snprintf(state, sizeof(state), "Run");
			break;
		case TDS_RUNQ:
			snprintf(state, sizeof(state), "RunQ");
			break;
		case TDS_CAN_RUN:
			snprintf(state, sizeof(state), "CanRun");
			break;
		case TDS_INACTIVE:
			snprintf(state, sizeof(state), "Inactv");
			break;
		case TDS_INHIBITED:
			state[0] = '\0';
			if (TD_ON_LOCK(&td))
				strlcat(state, "L", sizeof(state));
			if (TD_IS_SLEEPING(&td)) {
				if (td.td_flags & TDF_SINTR)
					strlcat(state, "S", sizeof(state));
				else
					strlcat(state, "D", sizeof(state));
			}
			if (TD_IS_SWAPPED(&td))
				strlcat(state, "W", sizeof(state));
			if (TD_AWAITING_INTR(&td))
				strlcat(state, "I", sizeof(state));
			if (TD_IS_SUSPENDED(&td))
				strlcat(state, "s", sizeof(state));
			if (state[0] != '\0')
				break;
		default:
			snprintf(state, sizeof(state), "???");
		}			
		mdb_printf(" %-6s ", state);		
	}
	if (TD_ON_LOCK(&td)) {
		wmesg[0] = '*';
		if (mdb_readstr(wmesg + 1, sizeof (wmesg) - 1,
		    (uintptr_t)td.td_lockname) == -1)
			strcpy(wmesg, "");
		wchan = td.td_blocked;
	} else if (TD_ON_SLEEPQ(&td)) {
		if (mdb_readstr(wmesg, sizeof (wmesg),
		    (uintptr_t)td.td_wmesg) == -1)
			strcpy(wmesg, "");
		wchan = td.td_wchan;
	} else if (TD_IS_RUNNING(&td)) {
		snprintf(wmesg, sizeof(wmesg), "CPU %d", td.td_oncpu);
		wchan = NULL;
	} else {
		strcpy(wmesg, "");
		wchan = NULL;
	}
	mdb_printf("%-8s ", wmesg);
	if (wchan == NULL)
		mdb_printf("%?s    ", "");
	else
		mdb_printf("0x%p  ", wchan);
	if (p->p_flag & P_SYSTEM)
		mdb_printf("[");
	if (td.td_name[0] != '\0')
		mdb_printf("%s", td.td_name);
	else
		mdb_printf("%s", p->p_comm);
	if (p->p_flag & P_SYSTEM)
		mdb_printf("]");
	mdb_printf("\n");

	return (WALK_NEXT);
}

static void
print_proc(uintptr_t addr)
{
	mdb_proc_t p, pp;
	mdb_pgrp_t pg;
	mdb_session_t sess;
	mdb_ucred_t cred;
	char state[9];
	struct thread_states ts;
	
	if (mdb_ctf_vread(&p, "struct proc", "mdb_proc_t", addr, 0) == -1)
		return;
	if (p.p_ucred == NULL || mdb_ctf_vread(&cred, "struct ucred",
	    "mdb_ucred_t", (uintptr_t)p.p_ucred, 0) == -1)
		memset(&cred, 0, sizeof(cred));
	if (p.p_pgrp == NULL || mdb_ctf_vread(&pg, "struct pgrp", "mdb_pgrp_t",
	    (uintptr_t)p.p_pgrp, 0) == -1)
		memset(&pg, 0, sizeof(pg));
	if (pg.pg_session == NULL || mdb_ctf_vread(&sess, "struct session",
		"mdb_session_t", (uintptr_t)pg.pg_session, 0) == -1)
		memset(&sess, 0, sizeof(sess));
	if (p.p_pptr == NULL || mdb_ctf_vread(&pp, "struct proc", "mdb_proc_t",
	    (uintptr_t)p.p_pptr, 0) == -1)
		memset(&pp, 0, sizeof(pp));

	mdb_printf("%5d %5d %5d %5d ", p.p_pid, pp.p_pid, pg.pg_id,
	    cred.cr_ruid);

	/* Determine our primary process state. */
	switch (p.p_state) {
	case PRS_NORMAL:
		if (P_SHOULDSTOP(&p))
			state[0] = 'T';
		else {
			/*
			 * One of D, L, R, S, W.  For a multithreaded
			 * process we will use the state of the thread
			 * with the highest precedence.  The
			 * precendence order from high to low is R, L,
			 * D, S, W.  If no thread is in a sane state
			 * we use '?' for our primary state.
			 */
			memset(&ts, 0, sizeof(ts));
			mdb_pwalk("threads", thread_state, &ts, addr);
			if (ts.rflag)
				state[0] = 'R';
			else if (ts.lflag)
				state[0] = 'L';
			else if (ts.dflag)
				state[0] = 'D';
			else if (ts.sflag)
				state[0] = 'S';
			else if (ts.wflag)
				state[0] = 'W';
			else
				state[0] = '?';
			}
		break;
	case PRS_NEW:
		state[0] = 'N';
		break;
	case PRS_ZOMBIE:
		state[0] = 'Z';
		break;
	default:
		state[0] = 'U';
		break;
	}
	state[1] = '\0';

	/* Additional process state flags. */
	if (!(p.p_flag & P_INMEM))
		strlcat(state, "W", sizeof(state));
	if (p.p_flag & P_TRACED)
		strlcat(state, "X", sizeof(state));
	if (p.p_flag & P_WEXIT && p.p_state != PRS_ZOMBIE)
		strlcat(state, "E", sizeof(state));
	if (p.p_flag & P_PPWAIT)
		strlcat(state, "V", sizeof(state));
	if (p.p_flag & P_SYSTEM || p.p_lock > 0)
		strlcat(state, "L", sizeof(state));
	if ((uintptr_t)sess.s_leader == addr)
		strlcat(state, "s", sizeof(state));
	/* Cheated here and didn't compare pgid's. */
	if (p.p_flag & P_CONTROLT)
		strlcat(state, "+", sizeof(state));
	if (jailed(&cred))
		strlcat(state, "J", sizeof(state));
	mdb_printf(" %-6s ", state);
	if (p.p_flag & P_HADTHREADS) {
		mdb_printf("%-?s             ", "(threaded)");
		if (p.p_flag & P_SYSTEM)
			mdb_printf("[");
		mdb_printf("%s", p.p_comm);
		if (p.p_flag & P_SYSTEM)
			mdb_printf("]");
		mdb_printf("\n");
	}

	mdb_pwalk("threads", print_thread, &p, addr);
}

int
ps(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("proc", "ps", argc, argv) == -1) {
			mdb_warn("can't walk 'proc'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%<u>%5s %5s %5s %5s  %-6s %-8s %-?s    %s%</u>\n",
		    "pid", "ppid", "pgrp", "uid", "state", "wmesg", "wchan",
		    "cmd");

	print_proc(addr);

	return (DCMD_OK);
}

#define	PG_NEWEST	0x0001
#define	PG_OLDEST	0x0002
#define	PG_PIPE_OUT	0x0004
#define	PG_EXACT_MATCH	0x0008

typedef struct pgrep_data {
	uint_t pg_flags;
	uint_t pg_psflags;
	uintptr_t pg_xaddr;
	hrtime_t pg_xstart;
	const char *pg_pat;
#ifndef _KMDB
	regex_t pg_reg;
#endif
} pgrep_data_t;

/*ARGSUSED*/
static int
pgrep_cb(uintptr_t addr, const void *pdata, void *data)
{
	mdb_proc_t p;
	mdb_pstats_t pstats;
	pgrep_data_t *pgp = data;
#ifndef _KMDB
	regmatch_t pmatch;
#endif

	if (mdb_ctf_vread(&p, "struct proc", "mdb_proc_t", addr, 0) == -1)
		return (WALK_ERR);

	/*
	 * XXX: Should this also look at thread names?
	 */

	/*
	 * kmdb doesn't have access to the reg* functions, so we fall back
	 * to strstr/strcmp.
	 */
#ifdef _KMDB
	if ((pgp->pg_flags & PG_EXACT_MATCH) ?
	    (strcmp(p.p_comm, pgp->pg_pat) != 0) :
	    (strstr(p.p_comm, pgp->pg_pat) == NULL))
		return (WALK_NEXT);
#else
	if (regexec(&pgp->pg_reg, p.p_comm, 1, &pmatch, 0) != 0)
		return (WALK_NEXT);

	if ((pgp->pg_flags & PG_EXACT_MATCH) &&
	    (pmatch.rm_so != 0 || p.p_comm[pmatch.rm_eo] != '\0'))
		return (WALK_NEXT);
#endif

	if (pgp->pg_flags & (PG_NEWEST | PG_OLDEST)) {
		hrtime_t start;

		if (mdb_ctf_vread(&pstats, "struct pstats", "mdb_pstats_t",
		    (uintptr_t)p.p_stats, 0) == -1)
			start = 0;
		else
			start = (hrtime_t)pstats.p_start.tv_sec * MICROSEC +
			    pstats.p_start.tv_usec;

		if (pgp->pg_flags & PG_NEWEST) {
			if (pgp->pg_xaddr == 0 || start > pgp->pg_xstart) {
				pgp->pg_xaddr = addr;
				pgp->pg_xstart = start;
			}
		} else {
			if (pgp->pg_xaddr == 0 || start < pgp->pg_xstart) {
				pgp->pg_xaddr = addr;
				pgp->pg_xstart = start;
			}
		}

	} else if (pgp->pg_flags & PG_PIPE_OUT) {
		mdb_printf("%p\n", addr);

	} else {
		if (mdb_call_dcmd("ps", addr, pgp->pg_psflags, 0, NULL) != 0) {
			mdb_warn("can't invoke 'ps'");
			return (WALK_DONE);
		}
		pgp->pg_psflags &= ~DCMD_LOOPFIRST;
	}

	return (WALK_NEXT);
}

/*ARGSUSED*/
int
pgrep(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	pgrep_data_t pg;
	int i;
#ifndef _KMDB
	int err;
#endif

	if (flags & DCMD_ADDRSPEC)
		return (DCMD_USAGE);

	pg.pg_flags = 0;
	pg.pg_xaddr = 0;

	i = mdb_getopts(argc, argv,
	    'n', MDB_OPT_SETBITS, PG_NEWEST, &pg.pg_flags,
	    'o', MDB_OPT_SETBITS, PG_OLDEST, &pg.pg_flags,
	    'x', MDB_OPT_SETBITS, PG_EXACT_MATCH, &pg.pg_flags,
	    NULL);

	argc -= i;
	argv += i;

	if (argc != 1)
		return (DCMD_USAGE);

	/*
	 * -n and -o are mutually exclusive.
	 */
	if ((pg.pg_flags & PG_NEWEST) && (pg.pg_flags & PG_OLDEST))
		return (DCMD_USAGE);

	if (argv->a_type != MDB_TYPE_STRING)
		return (DCMD_USAGE);

	if (flags & DCMD_PIPE_OUT)
		pg.pg_flags |= PG_PIPE_OUT;

	pg.pg_pat = argv->a_un.a_str;
	if (DCMD_HDRSPEC(flags))
		pg.pg_psflags = DCMD_ADDRSPEC | DCMD_LOOP | DCMD_LOOPFIRST;
	else
		pg.pg_psflags = DCMD_ADDRSPEC | DCMD_LOOP;

#ifndef _KMDB
	if ((err = regcomp(&pg.pg_reg, pg.pg_pat, REG_EXTENDED)) != 0) {
		size_t nbytes;
		char *buf;

		nbytes = regerror(err, &pg.pg_reg, NULL, 0);
		buf = mdb_alloc(nbytes + 1, UM_SLEEP | UM_GC);
		(void) regerror(err, &pg.pg_reg, buf, nbytes);
		mdb_warn("%s\n", buf);

		return (DCMD_ERR);
	}
#endif

	if (mdb_walk("proc", pgrep_cb, &pg) != 0) {
		mdb_warn("can't walk 'proc'");
		return (DCMD_ERR);
	}

	if (pg.pg_xaddr != 0 && (pg.pg_flags & (PG_NEWEST | PG_OLDEST))) {
		if (pg.pg_flags & PG_PIPE_OUT) {
			mdb_printf("%p\n", pg.pg_xaddr);
		} else {
			if (mdb_call_dcmd("ps", pg.pg_xaddr, pg.pg_psflags,
			    0, NULL) != 0) {
				mdb_warn("can't invoke 'ps'");
				return (DCMD_ERR);
			}
		}
	}

	return (DCMD_OK);
}

typedef struct {
	kgrep_cb_func *kg_cb;
	void *kg_cbdata;
} kgrep_walk_data_t;

static int
kgrep_walk_vm_map_entry(uintptr_t addr, const void *data, void *private)
{
	kgrep_walk_data_t *kwd;
	mdb_vm_map_entry_t entry;
	mdb_vm_object_t obj;

	if (mdb_ctf_convert(&entry, "struct vm_map_entry", "mdb_vm_map_entry_t",
	    data, 0) == -1) {
		mdb_warn("failed to parse struct vm_map_entry at %#lr", addr);
		return (WALK_ERR);
	}

	if (entry.eflags & MAP_ENTRY_IS_SUB_MAP) {
		if (entry.object.sub_map == NULL)
			return (WALK_NEXT);
		return (mdb_pwalk("vm_map", kgrep_walk_vm_map_entry, private,
		    (uintptr_t)entry.object.sub_map));
	}

	if (!(entry.protection & VM_PROT_READ))
		return (WALK_NEXT);

	/*
	 * If the entry has an associated VM object, skip it if it
	 * could be mapping a device.
	 */
	if (entry.object.vm_object != NULL) {
		if (mdb_ctf_vread(&obj, "struct vm_object", "mdb_vm_object_t",
		    (uintptr_t)entry.object.vm_object, 0) == -1) {
			mdb_warn("failed to read struct vm_object at %#lr",
			    (uintptr_t)entry.object.vm_object);
			return (WALK_ERR);
		}

		switch (obj.type) {
		case OBJT_DEVICE:
		case OBJT_SG:
		case OBJT_MGTDEVICE:
			return (WALK_NEXT);
		}
	}

	kwd = private;
	return (kwd->kg_cb(entry.start, entry.end, kwd->kg_cbdata));
}

/*
 * Ideally this would scan all valid kernel memory.
 *
 * For now this scans the kernel_map.  This doesn't catch things that
 * are direct mapped (like small UMA allocations on amd64).
 */
int
kgrep_subr(kgrep_cb_func *cb, void *cbdata)
{
	uintptr_t kernel_map;
	kgrep_walk_data_t kwd;

	if (mdb_readvar(&kernel_map, "kernel_map") == -1) {
		mdb_warn("failed to read 'kernel_map'");
		return (DCMD_ERR);
	}

	kwd.kg_cb = cb;
	kwd.kg_cbdata = cbdata;
	if (mdb_pwalk("vm_map", kgrep_walk_vm_map_entry, &kwd, kernel_map) ==
	    -1) {
		mdb_warn("failed to walk kernel_map entries");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

size_t
kgrep_subr_pagesize(void)
{
	return (PAGE_SIZE);
}

static const mdb_dcmd_t dcmds[] = {
	/* from kernel.c */
	{ "ps", NULL, "list processes (and associated threads)", ps },
	{ "pgrep", "[-x] [-n | -o] pattern",
		"pattern match against all processes", pgrep },

	/* from kgrep.c + kernel.c */
	{ "kgrep", KGREP_USAGE, "search kernel as for a pointer", kgrep,
		kgrep_help },

	{ NULL }
};

static const mdb_walker_t walkers[] = {
	/* from kernel.c */
	{ "proc", "list of struct proc structures",
	  proc_walk_init, proc_walk_step, proc_walk_fini },
	{ "threads", "given a proc pointer, walk its threads",
	  thread_walk_init, thread_walk_step, thread_walk_fini },

	/* from vm.c */
	{ "vm_map", "given a vm_map, walk its vm_map entries",
	  vm_map_walk_init, vm_map_walk_step, vm_map_walk_fini },

	{ NULL }
};

static const mdb_modinfo_t kernel_modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	
	return (&kernel_modinfo);
}
