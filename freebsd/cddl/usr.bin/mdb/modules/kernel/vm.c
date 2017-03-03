/*-
 * XXX: License.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ctf.h>
#include <mdb/mdb_ks.h>

#include "kernel.h"

typedef struct {
	mdb_vm_map_entry_t header;
} mdb_vm_map_t;

typedef struct {
	struct pglist	pq_pl;
} mdb_vm_pagequeue_t;

typedef struct {
	union {
		TAILQ_ENTRY(vm_page) q;
		struct {
			SLIST_ENTRY(vm_page) ss;
			void *pv;
		} s;
		struct {
			u_long p;
			u_long v;
		} memguard;
	} plinks;
} mdb_vm_page_t;

typedef struct {
	LIST_ENTRY(uma_keg)	uk_link;
} mdb_uma_keg_t;

static ssize_t struct_vm_map_entry_size;
static ssize_t struct_vm_page_size;
static ssize_t struct_uma_keg_size;

int
vm_map_walk_init(mdb_walk_state_t *wsp)
{
	mdb_vm_map_t map;

	/*
	 * This walker requires the address of a vm_map as the
	 * starting address.
	 */
	if (wsp->walk_addr == 0)
		return (WALK_ERR);

	if (struct_vm_map_entry_size == 0)
		struct_vm_map_entry_size = mdb_type_size("struct vm_map_entry");
	if (struct_vm_map_entry_size == -1) {
		mdb_warn("failed to lookup size of 'struct vm_map_entry'");
		return (WALK_ERR);
	}

	if (mdb_ctf_vread(&map, "struct vm_map", "mdb_vm_map_t", wsp->walk_addr,
	    0) == -1) {
		mdb_warn("failed to read struct vm_map at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_data = (void *)wsp->walk_addr;
	wsp->walk_addr = (uintptr_t)map.header.next;

	return (WALK_NEXT);
}

int
vm_map_walk_step(mdb_walk_state_t *wsp)
{
	uint8_t tgtentry[struct_vm_map_entry_size];
	mdb_vm_map_entry_t entry;
	int	status;

	if (wsp->walk_addr == (uintptr_t)wsp->walk_data)
		return (WALK_DONE);

	if (mdb_vread(tgtentry, sizeof (tgtentry), wsp->walk_addr) == -1) {
		mdb_warn("failed to read struct vm_map_entry at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	if (mdb_ctf_convert(&entry, "struct vm_map_entry", "mdb_vm_map_entry_t",
	    tgtentry, 0) == -1) {
		mdb_warn("failed to parse struct vm_map_entry at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, tgtentry, wsp->walk_cbdata);

	
	wsp->walk_addr = (uintptr_t)entry.next;

	return (status);
}

void
vm_map_walk_fini(mdb_walk_state_t *wsp)
{
}

int
vm_pglist_walk_init(mdb_walk_state_t *wsp)
{
	mdb_vm_pagequeue_t pq;

	/*
	 * This walker requires the address of a VM page queue as the
	 * starting address.
	 */
	if (wsp->walk_addr == 0)
		return (WALK_ERR);

	if (struct_vm_page_size == 0)
		struct_vm_page_size = mdb_type_size("struct vm_page");
	if (struct_vm_page_size == -1) {
		mdb_warn("failed to lookup size of 'struct vm_page'");
		return (WALK_ERR);
	}

	if (mdb_ctf_vread(&pq, "struct vm_pagequeue", "mdb_vm_pagequeue_t",
	    wsp->walk_addr, 0) == -1) {
		mdb_warn("failed to read struct vm_pagequeue at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)TAILQ_FIRST(&pq.pq_pl);

	return (WALK_NEXT);
}

int
vm_pglist_walk_step(mdb_walk_state_t *wsp)
{
	uint8_t tgtpage[struct_vm_page_size];
	mdb_vm_page_t p;
	int	status;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_vread(tgtpage, sizeof (tgtpage), wsp->walk_addr) == -1) {
		mdb_warn("failed to read struct vm_page at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	if (mdb_ctf_convert(&p, "struct vm_page", "mdb_vm_page_t", tgtpage,
	    0) == -1) {
		mdb_warn("failed to parse struct vm_page at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, tgtpage, wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)TAILQ_NEXT(&p, plinks.q);

	return (status);
}

void
vm_pglist_walk_fini(mdb_walk_state_t *wsp)
{
}

int
uma_keg_walk_init(mdb_walk_state_t *wsp)
{

	if (struct_uma_keg_size == 0)
		struct_uma_keg_size = mdb_type_size("struct uma_keg");
	if (struct_uma_keg_size == -1) {
		mdb_warn("failed to lookup size of 'struct uma_keg'");
		return (WALK_ERR);
	}

	if (wsp->walk_addr == 0) {
		wsp->walk_addr = mdb_list_first("uma_kegs");
		if (wsp->walk_addr == (uintptr_t)-1)
			return (WALK_ERR);
	}
		
	return (WALK_NEXT);
}

int
uma_keg_walk_step(mdb_walk_state_t *wsp)
{
	uint8_t tgtkeg[struct_uma_keg_size];
	mdb_uma_keg_t keg;
	int	status;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_vread(tgtkeg, sizeof (tgtkeg), wsp->walk_addr) == -1) {
		mdb_warn("failed to read struct uma_keg at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	if (mdb_ctf_convert(&keg, "struct uma_keg", "mdb_uma_keg_t",
	    tgtkeg, 0) == -1) {
		mdb_warn("failed to parse struct uma_keg at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, tgtkeg, wsp->walk_cbdata);

	
	wsp->walk_addr = (uintptr_t)LIST_NEXT(&keg, uk_link);

	return (status);
}

void
uma_keg_walk_fini(mdb_walk_state_t *wsp)
{
}
