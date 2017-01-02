/*-
 * XXX: License.
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
