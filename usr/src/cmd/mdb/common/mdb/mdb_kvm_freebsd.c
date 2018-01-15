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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 */

/*
 * Libkvm Kernel Target
 *
 * The libkvm kernel target provides access to both crash dumps and live
 * kernels through /dev/mem, using the facilities provided by
 * the libkvm library.  The target-specific data structures are shared
 * between this file (common code) and the ISA-dependent parts of the target,
 * and so they are defined in the mdb_kvm.h header.  The target processes an
 * "executable" (/dev/ksyms or the unix.X file) which contains a primary
 * .symtab and .dynsym, and then also iterates over the krtld module chain in
 * the kernel in order to obtain a list of loaded modules and per-module symbol
 * tables.  To improve startup performance, the per-module symbol tables are
 * instantiated on-the-fly whenever an address lookup falls within the text
 * section of a given module.  The target also relies on services from the
 * mdb_ks (kernel support) module, which contains pieces of the implementation
 * that must be compiled against the kernel implementation.
 */

#if 0
#include <sys/modctl.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#include <sys/utsname.h>
#include <sys/panic.h>
#include <sys/dumphdr.h>
#include <sys/dumpadm.h>
#endif

#if 0
#include <dlfcn.h>
#include <libctf.h>
#include <string.h>
#endif
#include <fcntl.h>
#if 0
#include <errno.h>
#endif
#include <limits.h>
#include <paths.h>

#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_io_impl.h>
#include <mdb/mdb_ctf.h>
#include <mdb/mdb_kvm_freebsd.h>
#include <mdb/mdb_module.h>
#include <mdb/mdb.h>

#if 0
#define	KT_RELOC_BUF(buf, obase, nbase) \
	((uintptr_t)(buf) - (uintptr_t)(obase) + (uintptr_t)(nbase))

#define	KT_BAD_BUF(buf, base, size) \
	((uintptr_t)(buf) < (uintptr_t)(base) || \
	((uintptr_t)(buf) >= (uintptr_t)(base) + (uintptr_t)(size)))
#endif

typedef struct kt_symarg {
	mdb_tgt_sym_f *sym_cb;		/* Caller's callback function */
	void *sym_data;			/* Callback function argument */
	uint_t sym_type;		/* Symbol type/binding filter */
	mdb_syminfo_t sym_info;		/* Symbol id and table id */
	const char *sym_obj;		/* Containing object */
} kt_symarg_t;

#if 0
typedef struct kt_maparg {
	mdb_tgt_t *map_target;		/* Target used for mapping iter */
	mdb_tgt_map_f *map_cb;		/* Caller's callback function */
	void *map_data;			/* Callback function argument */
} kt_maparg_t;
#endif

static const char KT_MODULE[] = "mdb_ks";
static const char KT_CTFPARENT[] = "kernel";

static const char *
sysroot_path(const char *path)
{
	static char buf[MAXPATHLEN];

	if (mdb_sysroot == NULL)
		return (path);
	(void) mdb_iob_snprintf(buf, MAXPATHLEN, "%s/%s", mdb_sysroot,
	    path);
	return (buf);
}

static void
kt_load_module(kt_data_t *kt, mdb_tgt_t *t, kt_module_t *km)
{
	mdb_io_t *fio;

	fio = mdb_fdio_create_path(NULL, km->km_pathname, O_RDONLY, 0);
	if (fio == NULL)
		return;

	/*
	 * Kernels are ET_EXEC.  Modules are ET_REL on platforms that
	 * use link_elf_obj.c like amd64, but ET_DYN on platforms that
	 * use link_elf.c like i386.  Easiest for now to not specify a
	 * desired type.
	 */
	km->km_file = mdb_gelf_create(fio, ET_NONE, GF_FILE);
	if (km->km_file == NULL) {
		mdb_io_destroy(fio);
		return;
	}

	/*
	 * Kernel modules (other than the base kernel) require symbol
	 * addresses to be manually relocated when using the symbol
	 * table from the module file.  We wouldn't need this if we
	 * used the in-kernel symbol table from the linker.
	 *
	 * TODO: What about ET_DYN?
	 */
	if (km->km_file->gf_ehdr.e_type == ET_REL) {
		/*
		 * Adjust the sh_offset of each section loaded by the
		 * kernel linker to map the address layout used by
		 * link_elf_obj.c.
		 */
		mdb_gelf_sect_t *gsp;
		size_t i;
		GElf_Shdr *shp;
		uintptr_t mapbase;
		int alignmask;

		mapbase = km->km_va;
		for (gsp = km->km_file->gf_sects, i = 0;
		     i < km->km_file->gf_shnum; i++, gsp++) {
			shp = &gsp->gs_shdr;
			if (shp->sh_size == 0)
				continue;
			switch (shp->sh_type) {
			case SHT_PROGBITS:
			case SHT_NOBITS:
#ifdef __amd64__
#ifdef SHT_X86_64_UNWIND
			case SHT_X86_64_UNWIND:
#endif
#endif
				if ((shdr[i].sh_flags & SHF_ALLOC) == 0)
					break;
				alignmask = shp->sh_addralign - 1;
				mapbase += alignmask;
				mapbase &= ~alignmask;
				shp->sh_offset = mapbase;
				mapbase += shp->sh_size;
				break;
			}
		}
	}

	km->km_symtab =
	    mdb_gelf_symtab_create_file(km->km_file, SHT_SYMTAB,
		MDB_TGT_SYMTAB);
}

static void
kt_load_modules(kt_data_t *kt, mdb_tgt_t *t)
{
	char name[NAME_MAX + 1];
	char pathname[PATH_MAX];
	uintptr_t addr, base, lf;
	size_t size;
	int kld_off_address, kld_off_filename, kld_off_pathname, kld_off_next;

	kt_module_t *km;

	if (mdb_tgt_readsym(t, MDB_TGT_AS_VIRT, &lf, sizeof (lf),
	    MDB_TGT_OBJ_EXEC, "linker_files") != sizeof (lf)) {
		warn("failed to read 'linker_files' pointer");
		return;
	}

	if (mdb_tgt_readsym(t, MDB_TGT_AS_VIRT, &kld_off_address,
	    sizeof (kld_off_address), MDB_TGT_OBJ_EXEC, "kld_off_address") !=
	    sizeof (kld_off_address) ||
	    mdb_tgt_readsym(t, MDB_TGT_AS_VIRT, &kld_off_filename,
	    sizeof (kld_off_filename), MDB_TGT_OBJ_EXEC, "kld_off_filename") !=
	    sizeof (kld_off_filename) ||
	    mdb_tgt_readsym(t, MDB_TGT_AS_VIRT, &kld_off_pathname,
	    sizeof (kld_off_pathname), MDB_TGT_OBJ_EXEC, "kld_off_pathname") !=
	    sizeof (kld_off_pathname) ||
	    mdb_tgt_readsym(t, MDB_TGT_AS_VIRT, &kld_off_next,
	    sizeof (kld_off_next), MDB_TGT_OBJ_EXEC, "kld_off_next") !=
	    sizeof (kld_off_next)) {
#if 0
		/*
		 * mdb doesn't support cross debugging, so fall back to
		 * static values and hope for the best.
		 */
		kld_off_address = offsetof(struct linker_file, address);
		kld_off_filename = offsetof(struct linker_file, filename);
		kld_off_pathname = offsetof(struct linker_file, pathname);
		kld_off_next = offsetof(struct linker_file, link.tqe_next);
#else
		warn("failed to read linker_file layout variables");
		return;
#endif
	}

	while (lf != 0) {
		if (mdb_tgt_vread(t, &addr, sizeof (addr),
		    lf + kld_off_filename) != sizeof (addr) ||
		    mdb_tgt_readstr(t, MDB_TGT_AS_VIRT, name, sizeof(name),
		    addr) == -1) {
			warn("failed to read module name at %p",
			    (void *)(lf + kld_off_filename));
			return;
		}

		mdb_dprintf(MDB_DBG_KMOD, "reading mod %s (%p)\n",
		    name, (void *)lf);

		if (mdb_nv_lookup(&kt->k_modules, name) != NULL) {
			warn("skipping duplicate module '%s'\n",
			    name);
			goto next_module;
		}

		if (mdb_tgt_vread(t, &addr, sizeof (addr),
		    lf + kld_off_pathname) != sizeof (addr) ||
		    mdb_tgt_readstr(t, MDB_TGT_AS_VIRT, pathname,
		    sizeof(pathname), addr) == -1) {
			warn("failed to read path for module '%s'\n",
			    name);
			return;
		}

		if (mdb_tgt_vread(t, &base, sizeof (base), lf +
		    kld_off_address) != sizeof(base)) {
			warn("failed to read base address for module '%s'\n",
			    name);
			return;
		}

		if (mdb_tgt_vread(t, &size, sizeof (size), lf +
		    kld_off_address + sizeof(base)) != sizeof(size)) {
			warn("failed to read size for module '%s'\n",
			    name);
			return;
		}

		km = mdb_zalloc(sizeof (kt_module_t), UM_SLEEP);
		km->km_name = strdup(name);
		km->km_pathname = strdup(sysroot_path(pathname));

		(void) mdb_nv_insert(&kt->k_modules, km->km_name, NULL,
		    (uintptr_t)km, MDB_NV_EXTNAME);

		km->km_va = base;
		km->km_size = size;

		/*
		 * Add the module to the end of the list of modules in load-
		 * dependency order.  This is needed to load the corresponding
		 * debugger modules in the same order for layering purposes.
		 */
		mdb_list_append(&kt->k_modlist, km);

		if (t->t_flags & MDB_TGT_F_PRELOAD) {
			mdb_iob_printf(mdb.m_out, " %s", name);
			mdb_iob_flush(mdb.m_out);
			kt_load_module(kt, t, km);
		}

	next_module:
		if (mdb_tgt_vread(t, &lf, sizeof (lf), lf +
		    kld_off_next) != sizeof(lf)) {
			warn("failed to read next module after '%s'\n",
			    name);
			return;
		}
	}
}

int
kt_setflags(mdb_tgt_t *t, int flags)
{
	int rwchg = (flags ^ t->t_flags) & MDB_TGT_F_RDWR;
	kt_data_t *kt = t->t_data;
	void *cookie;
	char errbuf[_POSIX2_LINE_MAX];
	int mode;

	if (!rwchg)
		return (0);

	mode = (flags & MDB_TGT_F_RDWR) ? O_RDWR : O_RDONLY;

	cookie = kvm_openfiles(kt->k_symfile, kt->k_kvmfile, NULL, mode,
	    errbuf);
	if (cookie == NULL) {
		/* We failed to re-open, so don't change t_flags */
		warn("failed to re-open target");
		return (-1);
	}

	/*
	 * We successfully reopened the target, so update k_cookie.  Also set
	 * the RDWR bit in t_flags to match those in flags.
	 */
	(void) kvm_close(kt->k_cookie);
	kt->k_cookie = cookie;

	t->t_flags = (t->t_flags & ~(MDB_TGT_F_RDWR)) |
	    (flags & (MDB_TGT_F_RDWR));

	return (0);
}

#if 0
/*
 * Determine which PIDs (if any) have their pages saved in the dump.  We
 * do this by looking for content flags in dump_flags in the header.  These
 * flags, which won't be set in older dumps, tell us whether a single process
 * has had its pages included in the dump.  If a single process has been
 * included, we need to get the PID for that process from the dump_pids
 * array in the dump.
 */
static int
kt_find_dump_contents(kt_data_t *kt)
{
	dumphdr_t *dh = kt->k_dumphdr;
	pid_t pid = -1;

	if (dh->dump_flags & DF_ALL)
		return (KT_DUMPCONTENT_ALL);

	if (dh->dump_flags & DF_CURPROC) {
		if ((pid = kt->k_dump_find_curproc()) == -1)
			return (KT_DUMPCONTENT_INVALID);
		else
			return (pid);
	} else {
		return (KT_DUMPCONTENT_KERNEL);
	}
}

static int
kt_dump_contains_proc(mdb_tgt_t *t, void *context)
{
	kt_data_t *kt = t->t_data;
	pid_t (*f_pid)(uintptr_t);
	pid_t reqpid;

	switch (kt->k_dumpcontent) {
	case KT_DUMPCONTENT_KERNEL:
		return (0);
	case KT_DUMPCONTENT_ALL:
		return (1);
	case KT_DUMPCONTENT_INVALID:
		goto procnotfound;
	default:
		f_pid = (pid_t (*)()) dlsym(RTLD_NEXT, "mdb_kproc_pid");
		if (f_pid == NULL)
			goto procnotfound;

		reqpid = f_pid((uintptr_t)context);
		if (reqpid == -1)
			goto procnotfound;

		return (kt->k_dumpcontent == reqpid);
	}

procnotfound:
	warn("unable to determine whether dump contains proc %p\n", context);
	return (1);
}
#endif

int
kt_setcontext(mdb_tgt_t *t, void *context)
{
#if 1
	if (context != NULL) {
		warn("kproc not yet supported");
		return (-1);
	}
	return (0);
#else
	if (context != NULL) {
		const char *argv[2];
		int argc = 0;
		mdb_tgt_t *ct;
		kt_data_t *kt = t->t_data;

		argv[argc++] = (const char *)context;
		argv[argc] = NULL;

		if (kt->k_dumphdr != NULL &&
		    !kt_dump_contains_proc(t, context)) {
			warn("dump does not contain pages for proc %p\n",
			    context);
			return (-1);
		}

		if ((ct = mdb_tgt_create(mdb_kproc_tgt_create,
		    t->t_flags, argc, argv)) == NULL)
			return (-1);

		mdb_printf("debugger context set to proc %p\n", context);
		mdb_tgt_activate(ct);
	} else
		mdb_printf("debugger context set to kernel\n");

	return (0);
#endif
}

static int
kt_stack(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	kt_data_t *kt = mdb.m_target->t_data;
	return (kt->k_dcmd_stack(addr, flags, argc, argv));
}

static int
kt_stackv(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	kt_data_t *kt = mdb.m_target->t_data;
	return (kt->k_dcmd_stackv(addr, flags, argc, argv));
}

static int
kt_stackr(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	kt_data_t *kt = mdb.m_target->t_data;
	return (kt->k_dcmd_stackr(addr, flags, argc, argv));
}

static int
kt_regs(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	kt_data_t *kt = mdb.m_target->t_data;

	if (argc != 0 || (flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	addr = (uintptr_t)kt->k_regs;

	return (kt->k_dcmd_regs(addr, flags, argc, argv));
}

#ifdef __x86
static int
kt_cpustack(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	kt_data_t *kt = mdb.m_target->t_data;
	return (kt->k_dcmd_cpustack(addr, flags, argc, argv));
}

static int
kt_cpuregs(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	kt_data_t *kt = mdb.m_target->t_data;
	return (kt->k_dcmd_cpuregs(addr, flags, argc, argv));
}
#endif /* __x86 */

/*ARGSUSED*/
static int
kt_status_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	kt_data_t *kt = mdb.m_target->t_data;
	struct utsname uts;

	bzero(&uts, sizeof (uts));
	(void) strcpy(uts.nodename, "unknown machine");
	(void) kt_uname(mdb.m_target, &uts);

#if 1
	if (mdb_prop_postmortem) {
		mdb_printf("debugging crash dump %s (%d-bit)\n",
		    kt->k_kvmfile, (int)(sizeof (void *) * NBBY));
	} else {
		mdb_printf("debugging live kernel %s (%d-bit)\n",
		    kt->k_symfile, (int)(sizeof (void *) * NBBY));
	}
#else
	if (mdb_prop_postmortem) {
		mdb_printf("debugging %scrash dump %s (%d-bit) from %s\n",
		    kt->k_xpv_domu ? "domain " : "", kt->k_kvmfile,
		    (int)(sizeof (void *) * NBBY), uts.nodename);
	} else {
		mdb_printf("debugging live kernel (%d-bit) on %s\n",
		    (int)(sizeof (void *) * NBBY), uts.nodename);
	}
#endif

	mdb_printf("operating system: %s %s (%s)\n",
	    uts.release, uts.version, uts.machine);

	if (kt->k_panicstr) {
		mdb_printf("panic message: %s\n", kt->k_panicstr);
	}

	return (DCMD_OK);
}

static const mdb_dcmd_t kt_dcmds[] = {
	{ "$c", "?[cnt]", "print stack backtrace", kt_stack },
	{ "$C", "?[cnt]", "print stack backtrace", kt_stackv },
	{ "$r", NULL, "print general-purpose registers", kt_regs },
	{ "$?", NULL, "print status and registers", kt_regs },
	{ "regs", NULL, "print general-purpose registers", kt_regs },
	{ "stack", "?[cnt]", "print stack backtrace", kt_stack },
	{ "stackregs", "?", "print stack backtrace and registers", kt_stackr },
#ifdef __x86
	{ "cpustack", "?[-v] [-c cpuid] [cnt]", "print stack backtrace for a "
	    "specific CPU", kt_cpustack },
	{ "cpuregs", "?[-c cpuid]", "print general-purpose registers for a "
	    "specific CPU", kt_cpuregs },
#endif
	{ "status", NULL, "print summary of current target", kt_status_dcmd },
	{ NULL }
};

static uintmax_t
reg_disc_get(const mdb_var_t *v)
{
	mdb_tgt_t *t = MDB_NV_COOKIE(v);
	kt_data_t *kt = t->t_data;
	mdb_tgt_reg_t r = 0;

	(void) mdb_tgt_getareg(t, kt->k_tid, mdb_nv_get_name(v), &r);
	return (r);
}

static kt_module_t *
kt_module_by_name(kt_data_t *kt, const char *name)
{
	kt_module_t *km;

	for (km = mdb_list_next(&kt->k_modlist); km; km = mdb_list_next(km)) {
		if (strcmp(name, km->km_name) == 0)
			return (km);
	}

	return (NULL);
}

void
kt_activate(mdb_tgt_t *t)
{
	static const mdb_nv_disc_t reg_disc = { NULL, reg_disc_get };
	kt_data_t *kt = t->t_data;
#if 0
	void *sym;
#endif

	int oflag;

	mdb_prop_postmortem = strcmp(kt->k_kvmfile, _PATH_MEM) != 0;
	mdb_prop_kernel = TRUE;
	mdb_prop_datamodel = MDB_TGT_MODEL_NATIVE;

	if (kt->k_activated == FALSE) {
#if 0
		struct utsname u1, u2;
		/*
		 * If we're examining a crash dump, root is /, and uname(2)
		 * does not match the utsname in the dump, issue a warning.
		 * Note that we are assuming that the modules and macros in
		 * /usr/lib are compiled against the kernel from uname -rv.
		 */
		if (mdb_prop_postmortem && strcmp(mdb.m_root, "/") == 0 &&
		    uname(&u1) >= 0 && kt_uname(t, &u2) >= 0 &&
		    (strcmp(u1.release, u2.release) ||
		    strcmp(u1.version, u2.version))) {
			mdb_warn("warning: dump is from %s %s %s; dcmds and "
			    "macros may not match kernel implementation\n",
			    u2.sysname, u2.release, u2.version);
		}
#endif

		if (mdb_module_load(KT_MODULE, MDB_MOD_GLOBAL) < 0) {
			warn("failed to load kernel support module -- "
			    "some modules may not load\n");
		}

#if 0
		if (mdb_prop_postmortem && kt->k_dumphdr != NULL) {
			sym = dlsym(RTLD_NEXT, "mdb_dump_print_content");
			if (sym != NULL)
				kt->k_dump_print_content = (void (*)())sym;

			sym = dlsym(RTLD_NEXT, "mdb_dump_find_curproc");
			if (sym != NULL)
				kt->k_dump_find_curproc = (int (*)())sym;

			kt->k_dumpcontent = kt_find_dump_contents(kt);
		}
#endif

		if (t->t_flags & MDB_TGT_F_PRELOAD) {
			oflag = mdb_iob_getflags(mdb.m_out) & MDB_IOB_PGENABLE;

			mdb_iob_clrflags(mdb.m_out, oflag);
			mdb_iob_puts(mdb.m_out, "Preloading module symbols: [");
			mdb_iob_flush(mdb.m_out);
		}

		if (!(t->t_flags & MDB_TGT_F_NOLOAD)) {
			kt_load_modules(kt, t);

			/*
			 * FreeBSD's kernel always includes its runtime
			 * linker, so force load the MDB kld module.
			 */
			(void) mdb_module_load("kld", MDB_MOD_SILENT);
		}


		if (t->t_flags & MDB_TGT_F_PRELOAD) {
			mdb_iob_puts(mdb.m_out, " ]\n");
			mdb_iob_setflags(mdb.m_out, oflag);
		}

		kt->k_activated = TRUE;
	}

	(void) mdb_tgt_register_dcmds(t, &kt_dcmds[0], MDB_MOD_FORCE);

	/* Export some of our registers as named variables */
	mdb_tgt_register_regvars(t, kt->k_rds, &reg_disc, MDB_NV_RDONLY);

	mdb_tgt_elf_export(kt->k_file);
}

void
kt_deactivate(mdb_tgt_t *t)
{
	kt_data_t *kt = t->t_data;

	const mdb_tgt_regdesc_t *rdp;
	const mdb_dcmd_t *dcp;

	for (rdp = kt->k_rds; rdp->rd_name != NULL; rdp++) {
		mdb_var_t *v;

		if (!(rdp->rd_flags & MDB_TGT_R_EXPORT))
			continue; /* Didn't export register as a variable */

		if ((v = mdb_nv_lookup(&mdb.m_nv, rdp->rd_name)) != NULL) {
			v->v_flags &= ~MDB_NV_PERSIST;
			mdb_nv_remove(&mdb.m_nv, v);
		}
	}

	for (dcp = &kt_dcmds[0]; dcp->dc_name != NULL; dcp++) {
		if (mdb_module_remove_dcmd(t->t_module, dcp->dc_name) == -1)
			warn("failed to remove dcmd %s", dcp->dc_name);
	}

	mdb_prop_postmortem = FALSE;
	mdb_prop_kernel = FALSE;
	mdb_prop_datamodel = MDB_TGT_MODEL_UNKNOWN;
}

/*ARGSUSED*/
const char *
kt_name(mdb_tgt_t *t)
{
	return ("kvm");
}

const char *
kt_platform(mdb_tgt_t *t)
{
	kt_data_t *kt = t->t_data;
	return (kt->k_platform);
}

static int
mdb_tgt_readsym_str(mdb_tgt_t *t, mdb_tgt_as_t as, void *buf, size_t nbytes,
    const char *obj, const char *name)
{
	GElf_Sym sym;

	if (mdb_tgt_lookup_by_name(t, obj, name, &sym, NULL) == 0)
		return (mdb_tgt_readstr(t, as, buf, nbytes, sym.st_value));

	return (-1);
}

int
kt_uname(mdb_tgt_t *t, struct utsname *utsp)
{

	if (mdb_tgt_readsym_str(t, MDB_TGT_AS_VIRT, utsp->sysname,
	    sizeof (utsp->sysname), MDB_TGT_OBJ_EXEC, "ostype") == -1)
		return (-1);
	/*
	 * XXX: Punt on hostname for now.  Would need to read from
	 * prison0.pr_hostname.
	 */
#ifdef notyet
	if (mdb_tgt_readsym_str(t, MDB_TGT_AS_VIRT, utsp->nodename,
	    sizeof (utsp->nodename), MDB_TGT_OBJ_EXEC, "prison0.pr_hostname") == -1)
		return (-1);
#endif
	if (mdb_tgt_readsym_str(t, MDB_TGT_AS_VIRT, utsp->release,
	    sizeof (utsp->release), MDB_TGT_OBJ_EXEC, "osrelease") == -1)
		return (-1);
	if (mdb_tgt_readsym_str(t, MDB_TGT_AS_VIRT, utsp->version,
	    sizeof (utsp->version), MDB_TGT_OBJ_EXEC, "version") == -1)
		return (-1);
	if (mdb_tgt_readsym_str(t, MDB_TGT_AS_VIRT, utsp->machine,
	    sizeof (utsp->machine), MDB_TGT_OBJ_EXEC, "machine") == -1)
		return (-1);
	return (sizeof(*utsp));
}

/*ARGSUSED*/
int
kt_dmodel(mdb_tgt_t *t)
{
	return (MDB_TGT_MODEL_NATIVE);
}

#if 0
ssize_t
kt_aread(mdb_tgt_t *t, mdb_tgt_as_t as, void *buf,
    size_t nbytes, mdb_tgt_addr_t addr)
{
	kt_data_t *kt = t->t_data;
	ssize_t rval;

	if ((rval = kt->k_kb_ops->kb_aread(kt->k_cookie, addr, buf,
	    nbytes, as)) == -1)
		return (set_errno(EMDB_NOMAP));

	return (rval);
}

ssize_t
kt_awrite(mdb_tgt_t *t, mdb_tgt_as_t as, const void *buf,
    size_t nbytes, mdb_tgt_addr_t addr)
{
	kt_data_t *kt = t->t_data;
	ssize_t rval;

	if ((rval = kt->k_kb_ops->kb_awrite(kt->k_cookie, addr, buf,
	    nbytes, as)) == -1)
		return (set_errno(EMDB_NOMAP));

	return (rval);
}
#endif

ssize_t
kt_vread(mdb_tgt_t *t, void *buf, size_t nbytes, uintptr_t addr)
{
	kt_data_t *kt = t->t_data;
	ssize_t rval;

	if ((rval = kvm_read(kt->k_cookie, addr, buf, nbytes)) == -1)
		return (set_errno(EMDB_NOMAP));

	return (rval);
}

ssize_t
kt_vwrite(mdb_tgt_t *t, const void *buf, size_t nbytes, uintptr_t addr)
{
	kt_data_t *kt = t->t_data;
	ssize_t rval;

	if ((rval = kvm_write(kt->k_cookie, addr, buf, nbytes)) == -1)
		return (set_errno(EMDB_NOMAP));

	return (rval);
}

ssize_t
kt_fread(mdb_tgt_t *t, void *buf, size_t nbytes, uintptr_t addr)
{
	return (kt_vread(t, buf, nbytes, addr));
}

ssize_t
kt_fwrite(mdb_tgt_t *t, const void *buf, size_t nbytes, uintptr_t addr)
{
	return (kt_vwrite(t, buf, nbytes, addr));
}

#if 0
ssize_t
kt_pread(mdb_tgt_t *t, void *buf, size_t nbytes, physaddr_t addr)
{
	kt_data_t *kt = t->t_data;
	ssize_t rval;

	if ((rval = kt->k_kb_ops->kb_pread(kt->k_cookie, addr, buf,
	    nbytes)) == -1)
		return (set_errno(EMDB_NOMAP));

	return (rval);
}

ssize_t
kt_pwrite(mdb_tgt_t *t, const void *buf, size_t nbytes, physaddr_t addr)
{
	kt_data_t *kt = t->t_data;
	ssize_t rval;

	if ((rval = kt->k_kb_ops->kb_pwrite(kt->k_cookie, addr, buf,
	    nbytes)) == -1)
		return (set_errno(EMDB_NOMAP));

	return (rval);
}

int
kt_vtop(mdb_tgt_t *t, mdb_tgt_as_t as, uintptr_t va, physaddr_t *pap)
{
	kt_data_t *kt = t->t_data;

	struct as *asp;
	physaddr_t pa;
	mdb_module_t *mod;
	mdb_var_t *v;
	int (*fptr)(uintptr_t, struct as *, physaddr_t *);

	switch ((uintptr_t)as) {
	case (uintptr_t)MDB_TGT_AS_PHYS:
	case (uintptr_t)MDB_TGT_AS_FILE:
	case (uintptr_t)MDB_TGT_AS_IO:
		return (set_errno(EINVAL));
	case (uintptr_t)MDB_TGT_AS_VIRT:
		asp = kt->k_as;
		break;
	default:
		asp = (struct as *)as;
	}

	if ((pa = kt->k_kb_ops->kb_vtop(kt->k_cookie, asp, va)) != -1ULL) {
		*pap = pa;
		return (0);
	}

	if ((v = mdb_nv_lookup(&mdb.m_modules, "unix")) != NULL &&
	    (mod = mdb_nv_get_cookie(v)) != NULL) {

		fptr = (int (*)(uintptr_t, struct as *, physaddr_t *))
		    dlsym(mod->mod_hdl, "platform_vtop");

		if ((fptr != NULL) && ((*fptr)(va, asp, pap) == 0))
			return (0);
	}

	return (set_errno(EMDB_NOMAP));
}
#endif

int
kt_lookup_by_name(mdb_tgt_t *t, const char *obj, const char *name,
    GElf_Sym *symp, mdb_syminfo_t *sip)
{
	kt_data_t *kt = t->t_data;
	kt_module_t *km, kmod;
	mdb_var_t *v;
	int n;

	/*
	 * To simplify the implementation, we create a fake module on the stack
	 * which is "prepended" to k_modlist and whose symtab is kt->k_symtab.
	 */
	kmod.km_symtab = kt->k_symtab;
	kmod.km_list.ml_next = mdb_list_next(&kt->k_modlist);

	switch ((uintptr_t)obj) {
	case (uintptr_t)MDB_TGT_OBJ_EXEC:
	case (uintptr_t)MDB_TGT_OBJ_RTLD:
		km = &kmod;
		n = 1;
		break;

	case (uintptr_t)MDB_TGT_OBJ_EVERY:
		km = &kmod;
		n = mdb_nv_size(&kt->k_modules) + 1;
		break;

	default:
		if ((v = mdb_nv_lookup(&kt->k_modules, obj)) == NULL)
			return (set_errno(EMDB_NOOBJ));

		km = mdb_nv_get_cookie(v);
		n = 1;

		if (km->km_symtab == NULL)
			kt_load_module(kt, t, km);
	}

	for (; n > 0; n--, km = mdb_list_next(km)) {
		if (mdb_gelf_symtab_lookup_by_name(km->km_symtab, name,
		    symp, &sip->sym_id) == 0) {
			sip->sym_table = MDB_TGT_SYMTAB;
			return (0);
		}
	}

	return (set_errno(EMDB_NOSYM));
}

int
kt_lookup_by_addr(mdb_tgt_t *t, uintptr_t addr, uint_t flags,
    char *buf, size_t nbytes, GElf_Sym *symp, mdb_syminfo_t *sip)
{
	kt_data_t *kt = t->t_data;
	kt_module_t kmods[3], *kmods_begin = &kmods[0], *kmods_end;
	const char *name;

	kt_module_t *km = &kmods[0];	/* Point km at first fake module */
	kt_module_t *sym_km = NULL;	/* Module associated with best sym */
	GElf_Sym sym;			/* Best symbol found so far if !exact */
	uint_t symid;			/* ID of best symbol found so far */

	/*
	 * To simplify the implementation, we create fake modules on the stack
	 * that are "prepended" to k_modlist and whose symtab is set to
	 * each of three special symbol tables, in order of precedence.
	 */
	km->km_va = 0;
	km->km_symtab = mdb.m_prsym;

	if (kt->k_symtab != NULL) {
		km->km_list.ml_next = (mdb_list_t *)(km + 1);
		km = mdb_list_next(km);
		km->km_va = 0;
		km->km_symtab = kt->k_symtab;
	}

	if (kt->k_dynsym != NULL) {
		km->km_list.ml_next = (mdb_list_t *)(km + 1);
		km = mdb_list_next(km);
		km->km_va = 0;
		km->km_symtab = kt->k_dynsym;
	}

	km->km_list.ml_next = mdb_list_next(&kt->k_modlist);
	kmods_end = km;

	/*
	 * Now iterate over the list of fake and real modules.  If the module
	 * has no symbol table and the address is in the module's range,
	 * instantiate the module's symbol table.  In exact mode, we can
	 * jump to 'found' immediately if we match.  Otherwise we continue
	 * looking and improve our choice if we find a closer symbol.
	 */
	for (km = &kmods[0]; km != NULL; km = mdb_list_next(km)) {
		if (km->km_symtab == NULL && addr >= km->km_va &&
		    addr < km->km_va + km->km_size)
			kt_load_module(kt, t, km);

		if (mdb_gelf_symtab_lookup_by_addr(km->km_symtab, addr,
		    flags, buf, nbytes, symp, &sip->sym_id) != 0 ||
		    symp->st_value == 0)
			continue;

		if (flags & MDB_TGT_SYM_EXACT) {
			sym_km = km;
			goto found;
		}

		if (sym_km == NULL || mdb_gelf_sym_closer(symp, &sym, addr)) {
			sym_km = km;
			sym = *symp;
			symid = sip->sym_id;
		}
	}

	if (sym_km == NULL)
		return (set_errno(EMDB_NOSYMADDR));

	*symp = sym; /* Copy our best symbol into the caller's symbol */
	sip->sym_id = symid;
found:
	/*
	 * Once we've found something, copy the final name into the caller's
	 * buffer and prefix it with the load object name if appropriate.
	 */
	if (sym_km != NULL) {
		name = mdb_gelf_sym_name(sym_km->km_symtab, symp);

		if (sym_km < kmods_begin || sym_km > kmods_end) {
			(void) mdb_snprintf(buf, nbytes, "%s`%s",
			    sym_km->km_name, name);
		} else if (nbytes > 0) {
			(void) strncpy(buf, name, nbytes);
			buf[nbytes - 1] = '\0';
		}

		if (sym_km->km_symtab == mdb.m_prsym)
			sip->sym_table = MDB_TGT_PRVSYM;
		else
			sip->sym_table = MDB_TGT_SYMTAB;
	} else {
		sip->sym_table = MDB_TGT_SYMTAB;
	}

	return (0);
}

static int
kt_symtab_func(void *data, const GElf_Sym *sym, const char *name, uint_t id)
{
	kt_symarg_t *argp = data;

	if (mdb_tgt_sym_match(sym, argp->sym_type)) {
		argp->sym_info.sym_id = id;

		return (argp->sym_cb(argp->sym_data, sym, name,
		    &argp->sym_info, argp->sym_obj));
	}

	return (0);
}

static void
kt_symtab_iter(mdb_gelf_symtab_t *gst, uint_t type, const char *obj,
    mdb_tgt_sym_f *cb, void *p)
{
	kt_symarg_t arg;

	arg.sym_cb = cb;
	arg.sym_data = p;
	arg.sym_type = type;
	arg.sym_info.sym_table = gst->gst_tabid;
	arg.sym_obj = obj;

	mdb_gelf_symtab_iter(gst, kt_symtab_func, &arg);
}

int
kt_symbol_iter(mdb_tgt_t *t, const char *obj, uint_t which, uint_t type,
    mdb_tgt_sym_f *cb, void *data)
{
	kt_data_t *kt = t->t_data;
	kt_module_t *km;

	mdb_gelf_symtab_t *symtab = NULL;
	mdb_var_t *v;

	switch ((uintptr_t)obj) {
	case (uintptr_t)MDB_TGT_OBJ_EXEC:
	case (uintptr_t)MDB_TGT_OBJ_RTLD:
		if (which == MDB_TGT_SYMTAB)
			symtab = kt->k_symtab;
		else
			symtab = kt->k_dynsym;
		break;

	case (uintptr_t)MDB_TGT_OBJ_EVERY:
		if (which == MDB_TGT_DYNSYM) {
			symtab = kt->k_dynsym;
			obj = MDB_TGT_OBJ_EXEC;
			break;
		}

		mdb_nv_rewind(&kt->k_modules);
		while ((v = mdb_nv_advance(&kt->k_modules)) != NULL) {
			km = mdb_nv_get_cookie(v);

			if (km->km_symtab == NULL)
				kt_load_module(kt, t, km);

			if (km->km_symtab != NULL)
				kt_symtab_iter(km->km_symtab, type,
				    km->km_name, cb, data);
		}
		break;

	default:
		v = mdb_nv_lookup(&kt->k_modules, obj);

		if (v == NULL)
			return (set_errno(EMDB_NOOBJ));

		km = mdb_nv_get_cookie(v);

		if (km->km_symtab == NULL)
			kt_load_module(kt, t, km);

		symtab = km->km_symtab;
	}

	if (symtab)
		kt_symtab_iter(symtab, type, obj, cb, data);

	return (0);
}

#if 0
static int
kt_mapping_walk(uintptr_t addr, const void *data, kt_maparg_t *marg)
{
	/*
	 * This is a bit sketchy but avoids problematic compilation of this
	 * target against the current VM implementation.  Now that we have
	 * vmem, we can make this less broken and more informative by changing
	 * this code to invoke the vmem walker in the near future.
	 */
	const struct kt_seg {
		caddr_t s_base;
		size_t s_size;
	} *segp = (const struct kt_seg *)data;

	mdb_map_t map;
	GElf_Sym sym;
	mdb_syminfo_t info;

	map.map_base = (uintptr_t)segp->s_base;
	map.map_size = segp->s_size;
	map.map_flags = MDB_TGT_MAP_R | MDB_TGT_MAP_W | MDB_TGT_MAP_X;

	if (kt_lookup_by_addr(marg->map_target, addr, MDB_TGT_SYM_EXACT,
	    map.map_name, MDB_TGT_MAPSZ, &sym, &info) == -1) {

		(void) mdb_iob_snprintf(map.map_name, MDB_TGT_MAPSZ,
		    "%lr", addr);
	}

	return (marg->map_cb(marg->map_data, &map, map.map_name));
}

int
kt_mapping_iter(mdb_tgt_t *t, mdb_tgt_map_f *func, void *private)
{
	kt_data_t *kt = t->t_data;
	kt_maparg_t m;

	m.map_target = t;
	m.map_cb = func;
	m.map_data = private;

	return (mdb_pwalk("seg", (mdb_walk_cb_t)kt_mapping_walk, &m,
	    (uintptr_t)kt->k_as));
}
#endif

static const mdb_map_t *
kt_module_to_map(kt_module_t *km, mdb_map_t *map)
{
	(void) strncpy(map->map_name, km->km_name, MDB_TGT_MAPSZ);
	map->map_name[MDB_TGT_MAPSZ - 1] = '\0';
	map->map_base = km->km_va;
	map->map_size = km->km_size;
	map->map_flags = MDB_TGT_MAP_R | MDB_TGT_MAP_W | MDB_TGT_MAP_X;

	return (map);
}

int
kt_object_iter(mdb_tgt_t *t, mdb_tgt_map_f *func, void *private)
{
	kt_data_t *kt = t->t_data;
	kt_module_t *km;
	mdb_map_t m;

	for (km = mdb_list_next(&kt->k_modlist); km; km = mdb_list_next(km)) {
		if (func(private, kt_module_to_map(km, &m), km->km_name) == -1)
			break;
	}

	return (0);
}

const mdb_map_t *
kt_addr_to_map(mdb_tgt_t *t, uintptr_t addr)
{
	kt_data_t *kt = t->t_data;
	kt_module_t *km;

	for (km = mdb_list_next(&kt->k_modlist); km; km = mdb_list_next(km)) {
		if (addr - km->km_va < km->km_size)
			return (kt_module_to_map(km, &kt->k_map));
	}

	(void) set_errno(EMDB_NOMAP);
	return (NULL);
}

const mdb_map_t *
kt_name_to_map(mdb_tgt_t *t, const char *name)
{
	kt_data_t *kt = t->t_data;
	kt_module_t *km;
	mdb_map_t m;

	/*
	 * If name is MDB_TGT_OBJ_EXEC, return the first module on the list,
	 * which will be unix since we keep k_modlist in load order.
	 */
	if (name == MDB_TGT_OBJ_EXEC || name == MDB_TGT_OBJ_RTLD)
		return (kt_module_to_map(mdb_list_next(&kt->k_modlist), &m));

	if ((km = kt_module_by_name(kt, name)) != NULL)
		return (kt_module_to_map(km, &m));

	(void) set_errno(EMDB_NOOBJ);
	return (NULL);
}

static ctf_file_t *
kt_load_ctfdata(mdb_tgt_t *t, kt_module_t *km)
{
	kt_data_t *kt = t->t_data;
	int err;

	if (km->km_ctfp != NULL)
		return (km->km_ctfp);

	if (km->km_symtab == NULL)
		kt_load_module(t->t_data, t, km);

	km->km_ctfp = mdb_ctf_open(km->km_pathname, &err);
	if (km->km_ctfp == NULL) {
		mdb_warn("failed to parse ctf data in %s: %s\n",
		    km->km_pathname, ctf_errmsg(err));
		return (NULL);
	}

	if (ctf_parent_name(km->km_ctfp) != NULL) {
		mdb_var_t *v;

		if ((v = mdb_nv_lookup(&kt->k_modules,
		    ctf_parent_name(km->km_ctfp))) == NULL) {
			warn("failed to load CTF data for %s - parent %s not "
			    "loaded\n", km->km_name,
			    ctf_parent_name(km->km_ctfp));
		}

		if (v != NULL) {
			kt_module_t *pm = mdb_nv_get_cookie(v);

			if (pm->km_ctfp == NULL)
				(void) kt_load_ctfdata(t, pm);

			if (pm->km_ctfp != NULL && ctf_import(km->km_ctfp,
			    pm->km_ctfp) == CTF_ERR) {
				warn("failed to import parent types into "
				    "%s: %s\n", km->km_name,
				    ctf_errmsg(ctf_errno(km->km_ctfp)));
			}
		}
	}

	return (km->km_ctfp);
}

ctf_file_t *
kt_addr_to_ctf(mdb_tgt_t *t, uintptr_t addr)
{
	kt_data_t *kt = t->t_data;
	kt_module_t *km;

	for (km = mdb_list_next(&kt->k_modlist); km; km = mdb_list_next(km)) {
		if (addr - km->km_va < km->km_size)
			return (kt_load_ctfdata(t, km));
	}

	(void) set_errno(EMDB_NOMAP);
	return (NULL);
}

ctf_file_t *
kt_name_to_ctf(mdb_tgt_t *t, const char *name)
{
	kt_data_t *kt = t->t_data;
	kt_module_t *km;

	if (name == MDB_TGT_OBJ_EXEC)
		name = KT_CTFPARENT;
	else if (name == MDB_TGT_OBJ_RTLD)
		name = KT_CTFPARENT;

	if ((km = kt_module_by_name(kt, name)) != NULL)
		return (kt_load_ctfdata(t, km));

	(void) set_errno(EMDB_NOOBJ);
	return (NULL);
}

/*ARGSUSED*/
int
kt_status(mdb_tgt_t *t, mdb_tgt_status_t *tsp)
{
	kt_data_t *kt = t->t_data;
	bzero(tsp, sizeof (mdb_tgt_status_t));
	tsp->st_state = strcmp(kt->k_kvmfile, _PATH_MEM) != 0 ?
	    MDB_TGT_DEAD : MDB_TGT_RUNNING;
	return (0);
}

#if 0
static ssize_t
kt_xd_dumphdr(mdb_tgt_t *t, void *buf, size_t nbytes)
{
	kt_data_t *kt = t->t_data;

	if (buf == NULL && nbytes == 0)
		return (sizeof (dumphdr_t));

	if (kt->k_dumphdr == NULL)
		return (set_errno(ENODATA));

	nbytes = MIN(nbytes, sizeof (dumphdr_t));
	bcopy(kt->k_dumphdr, buf, nbytes);

	return (nbytes);
}
#endif

void
kt_destroy(mdb_tgt_t *t)
{
	kt_data_t *kt = t->t_data;
	kt_module_t *km, *nkm;

	(void) mdb_module_unload(KT_MODULE, 0);

	if (kt->k_regs != NULL)
		mdb_free(kt->k_regs, kt->k_regsize);

	if (kt->k_symtab != NULL)
		mdb_gelf_symtab_destroy(kt->k_symtab);

	if (kt->k_dynsym != NULL)
		mdb_gelf_symtab_destroy(kt->k_dynsym);

	if (kt->k_panicstr != NULL)
		strfree(kt->k_panicstr);

	mdb_gelf_destroy(kt->k_file);

	(void) kvm_close(kt->k_cookie);

	for (km = mdb_list_next(&kt->k_modlist); km; km = nkm) {
		if (km->km_symtab)
			mdb_gelf_symtab_destroy(km->km_symtab);

		if (km->km_ctfp)
			ctf_close(km->km_ctfp);

		if (km->km_file)
			mdb_gelf_destroy(km->km_file);

		nkm = mdb_list_next(km);
		strfree(km->km_name);
		strfree(km->km_pathname);
		mdb_free(km, sizeof (kt_module_t));
	}

	mdb_nv_destroy(&kt->k_modules);

	strfree(kt->k_kvmfile);
	if (kt->k_symfile != NULL)
		strfree(kt->k_symfile);

	mdb_free(kt, sizeof (kt_data_t));
}

#if 0
static int
kt_data_stub(void)
{
	return (-1);
}
#endif

int
mdb_kvm_tgt_create(mdb_tgt_t *t, int argc, const char *argv[])
{
	kt_data_t *kt = mdb_zalloc(sizeof (kt_data_t), UM_SLEEP);
	int oflag = (t->t_flags & MDB_TGT_F_RDWR) ? O_RDWR : O_RDONLY;
	GElf_Sym sym;
#if 0
	pgcnt_t pmem;
#endif
	char errbuf[_POSIX2_LINE_MAX];
	lwpid_t dumptid;
	char panicstr[128];
	uintptr_t addr;

	if (argc == 2) {
		kt->k_symfile = strdup(argv[0]);
		kt->k_kvmfile = strdup(argv[1]);

		kt->k_cookie = kvm_openfiles(kt->k_symfile,
		    kt->k_kvmfile, NULL, oflag, errbuf);

		if (kt->k_cookie == NULL) {
			mdb_warn("failed to open vmcore: %s", errbuf);
			goto err;
		}
	} else {
		return (set_errno(EINVAL));
	}

	kt->k_fio = mdb_fdio_create_path(NULL, kt->k_symfile, O_RDONLY, 0);
	if (kt->k_fio == NULL)
		goto err;

	if ((kt->k_file = mdb_gelf_create(kt->k_fio,
	    ET_EXEC, GF_FILE)) == NULL) {
		mdb_io_destroy(kt->k_fio);
		goto err;
	}

	kt->k_symtab =
	    mdb_gelf_symtab_create_file(kt->k_file, SHT_SYMTAB, MDB_TGT_SYMTAB);

	kt->k_dynsym =
	    mdb_gelf_symtab_create_file(kt->k_file, SHT_DYNSYM, MDB_TGT_DYNSYM);

#if 0
	if (mdb_gelf_symtab_lookup_by_name(kt->k_symtab, "kas",
	    &sym, NULL) == -1) {
		warn("'kas' symbol is missing from kernel\n");
		goto err;
	}

	kt->k_as = (struct as *)(uintptr_t)sym.st_value;
#endif

	if (mdb_gelf_symtab_lookup_by_name(kt->k_symtab, "machine",
	    &sym, NULL) == -1) {
		warn("'machine' symbol is missing from kernel\n");
		goto err;
	}

	if (kvm_read(kt->k_cookie, sym.st_value,
	    kt->k_platform, MAXNAMELEN) <= 0) {
		warn("failed to read 'machine' string from kernel");
		goto err;
	}

#if 0
	if (mdb_gelf_symtab_lookup_by_name(kt->k_symtab, "utsname",
	    &sym, NULL) == -1) {
		warn("'utsname' symbol is missing from kernel\n");
		goto err;
	}

	if (kt->k_kb_ops->kb_kread(kt->k_cookie, sym.st_value, &uts,
	    sizeof (uts)) <= 0) {
		warn("failed to read 'utsname' struct from kernel");
		goto err;
	}

	kt->k_dump_print_content = (void (*)())kt_data_stub;
	kt->k_dump_find_curproc = kt_data_stub;

	/*
	 * We set k_ctfvalid based on the presence of the CTF vmem arena
	 * symbol.  The CTF members were added to the end of struct module at
	 * the same time, so this allows us to know whether we can use them.
	 */
	if (mdb_gelf_symtab_lookup_by_name(kt->k_symtab, "ctf_arena", &sym,
	    NULL) == 0 && !(mdb.m_flags & MDB_FL_NOCTF))
		kt->k_ctfvalid = 1;
#endif

	(void) mdb_nv_create(&kt->k_modules, UM_SLEEP);
	t->t_pshandle = kt->k_cookie;
	t->t_data = kt;

#ifdef __amd64__
	kt_amd64_init(t);
#else
#error	"unknown ISA"
#endif

	/*
	 * Read dumptid and panicstr from the crash dump.
	 */
	if (mdb_tgt_readsym(t, MDB_TGT_AS_VIRT, &dumptid, sizeof (dumptid),
	    MDB_TGT_OBJ_EXEC, "dumptid") == sizeof (dumptid))
		kt->k_tid = dumptid;
	if (mdb_tgt_readsym(t, MDB_TGT_AS_VIRT, &addr, sizeof (addr),
	    MDB_TGT_OBJ_EXEC, "panicstr") == sizeof (addr) && addr != 0) {
		if (mdb_tgt_readstr(t, MDB_TGT_AS_VIRT, panicstr,
		    sizeof(panicstr), addr) > 0)
			kt->k_panicstr = strdup(panicstr);
	}

	/*
	 * Pull initial register values from crash dump.
	 */
	if (kt->k_tid != 0 && mdb_gelf_symtab_lookup_by_name(kt->k_symtab,
	    "dumppcb", &sym, NULL) == 0)
		kt->k_load_pcb_regs(t, sym.st_value, kt->k_regs);

#if 0
	if ((mdb.m_flags & MDB_FL_ADB) && mdb_tgt_readsym(t, MDB_TGT_AS_VIRT,
	    &pmem, sizeof (pmem), MDB_TGT_OBJ_EXEC, "physmem") == sizeof (pmem))
		mdb_printf("physmem %lx\n", (ulong_t)pmem);
#endif

	return (0);

err:
	if (kt->k_panicstr != NULL)
		strfree(kt->k_panicstr);

	if (kt->k_symtab != NULL)
		mdb_gelf_symtab_destroy(kt->k_symtab);

	if (kt->k_dynsym != NULL)
		mdb_gelf_symtab_destroy(kt->k_dynsym);

	if (kt->k_file != NULL)
		mdb_gelf_destroy(kt->k_file);

	if (kt->k_cookie != NULL)
		(void) kvm_close(kt->k_cookie);

	mdb_free(kt, sizeof (kt_data_t));
	return (-1);
}

#if 0
int
mdb_kvm_is_dump(mdb_io_t *io)
{
	dumphdr_t h;

	(void) IOP_SEEK(io, (off64_t)0L, SEEK_SET);

	return (IOP_READ(io, &h, sizeof (dumphdr_t)) == sizeof (dumphdr_t) &&
	    h.dump_magic == DUMP_MAGIC);
}

int
mdb_kvm_is_compressed_dump(mdb_io_t *io)
{
	dumphdr_t h;

	(void) IOP_SEEK(io, (off64_t)0L, SEEK_SET);

	return (IOP_READ(io, &h, sizeof (dumphdr_t)) == sizeof (dumphdr_t) &&
	    h.dump_magic == DUMP_MAGIC &&
	    (h.dump_flags & DF_COMPRESSED) != 0);
}
#endif
