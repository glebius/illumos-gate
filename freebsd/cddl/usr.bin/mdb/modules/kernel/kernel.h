/*-
 * XXX: License.
 */

#ifndef _MDB_KERNEL_H_
#define _MDB_KERNEL_H_

/* XXX: Can't include <vm/vm.h> directly due to conflicts with boolean_t. */
typedef u_char vm_prot_t;	/* protection codes */

#define	VM_PROT_NONE		((vm_prot_t) 0x00)
#define	VM_PROT_READ		((vm_prot_t) 0x01)
#define	VM_PROT_WRITE		((vm_prot_t) 0x02)
#define	VM_PROT_EXECUTE		((vm_prot_t) 0x04)
#define	VM_PROT_COPY		((vm_prot_t) 0x08)	/* copy-on-read */

enum obj_type { OBJT_DEFAULT, OBJT_SWAP, OBJT_VNODE, OBJT_DEVICE, OBJT_PHYS,
		OBJT_DEAD, OBJT_SG, OBJT_MGTDEVICE };
typedef u_char objtype_t;

#define MAP_ENTRY_IS_SUB_MAP		0x0002

typedef struct {
	struct vm_map_entry *next;
	uintptr_t start;
	uintptr_t end;
	union {
		struct vm_object *vm_object;
		struct vm_map *sub_map;
	} object;
	unsigned int eflags;
	vm_prot_t protection;
} mdb_vm_map_entry_t;

typedef struct {
	objtype_t type;
} mdb_vm_object_t;

TAILQ_HEAD(pglist, vm_page);

extern int mbuf_walk_init(mdb_walk_state_t *);
extern int mbuf_walk_step(mdb_walk_state_t *);
extern void mbuf_walk_fini(mdb_walk_state_t *);
extern int vm_map_walk_init(mdb_walk_state_t *);
extern int vm_map_walk_step(mdb_walk_state_t *);
extern void vm_map_walk_fini(mdb_walk_state_t *);
extern int vm_pglist_walk_init(mdb_walk_state_t *);
extern int vm_pglist_walk_step(mdb_walk_state_t *);
extern void vm_pglist_walk_fini(mdb_walk_state_t *);

#endif  /* _MDB_KERNEL_H_ */
