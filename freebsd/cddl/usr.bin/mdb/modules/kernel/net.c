/*-
 * Copyright (c) 2017 Netflix, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ctf.h>
#include <mdb/mdb_ks.h>

#include "kernel.h"

typedef struct {
	union {	/* next buffer in chain */
		struct mbuf		*m_next;
		SLIST_ENTRY(mbuf)	m_slist;
		STAILQ_ENTRY(mbuf)	m_stailq;
	};
} mdb_mbuf_t;

static ssize_t struct_mbuf_size;

int
mbuf_walk_init(mdb_walk_state_t *wsp)
{

	/*
	 * This walker requires the address of an mbuf as the starting
	 * address.
	 */
	if (wsp->walk_addr == 0)
		return (WALK_ERR);

	if (struct_mbuf_size == 0)
		struct_mbuf_size = mdb_type_size("struct mbuf");
	if (struct_mbuf_size == -1) {
		mdb_warn("failed to lookup size of 'struct mbuf'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
mbuf_walk_step(mdb_walk_state_t *wsp)
{
	uint8_t tgtmbuf[struct_mbuf_size];
	mdb_mbuf_t m;
	int	status;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_vread(tgtmbuf, sizeof (tgtmbuf), wsp->walk_addr) == -1) {
		mdb_warn("failed to read struct mbuf at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	if (mdb_ctf_convert(&m, "struct mbuf", "mdb_mbuf_t", tgtmbuf,
	    0) == -1) {
		mdb_warn("failed to parse struct mbuf at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, tgtmbuf, wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)m.m_next;

	return (status);
}

void
mbuf_walk_fini(mdb_walk_state_t *wsp)
{
}
