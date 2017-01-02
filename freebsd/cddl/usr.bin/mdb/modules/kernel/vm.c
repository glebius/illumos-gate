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

static ssize_t struct_vm_map_size;
static ssize_t struct_vm_map_entry_size;

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

	if (struct_vm_map_size == 0)
		struct_vm_map_size = mdb_type_size("struct vm_map");
	if (struct_vm_map_size == -1) {
		mdb_warn("failed to lookup size of 'struct vm_map'");
		return (WALK_ERR);
	}
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
