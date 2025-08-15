// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/mman.h>
#include <rz_drx.h>
#include "linux/linux_debug.h"
#include "procfs.h"
#include "linux/linux_coredump.h"
#include "drx.c" // x86 specific
#include "bt.c"

#ifdef __WALL
#define WAITPID_FLAGS __WALL
#else
#define WAITPID_FLAGS 0
#endif

#define PROC_NAME_SZ   1024
#define PROC_REGION_SZ 100
// PROC_REGION_SZ - 2 (used for `0x`). Due to how RZ_STR_DEF works this can't be
// computed.
#define PROC_REGION_LEFT_SZ 98
#define PROC_PERM_SZ        5
#define PROC_UNKSTR_SZ      128

#if WAIT_ON_ALL_CHILDREN
static int rz_debug_handle_signals(RzDebug *dbg) {
	RZ_LOG_WARN("signal handling is not supported on this platform\n");
	return 0;
}
#endif

static char *rz_debug_native_reg_profile(RzDebug *dbg) {
	if (dbg->bits & RZ_SYS_BITS_32) {
#if __x86_64__
#include "reg/linux-x64-32.h" // 32 binary on x86_64
#else
#include "reg/linux-x86.h"
#endif
	} else {
#include "reg/linux-x64.h"
	}
}

static bool rz_debug_native_step(RzDebug *dbg) {
	return linux_step(dbg);
}

static int rz_debug_native_attach(RzDebug *dbg, int pid) {
	return linux_attach(dbg, pid);
}

static int rz_debug_native_detach(RzDebug *dbg, int pid) {
	return rz_debug_ptrace(dbg, PTRACE_DETACH, pid, NULL, (rz_ptrace_data_t)(size_t)0);
}

static int rz_debug_native_select(RzDebug *dbg, int pid, int tid) {
	return linux_select(dbg, pid, tid);
}

static int rz_debug_native_continue_syscall(RzDebug *dbg, int pid, int num) {
	linux_set_options(dbg, pid);
	return rz_debug_ptrace(dbg, PTRACE_SYSCALL, pid, 0, 0);
}

static void interrupt_process(RzDebug *dbg) {
	rz_debug_kill(dbg, dbg->pid, dbg->tid, SIGINT);
	rz_cons_break_pop();
}

static int rz_debug_native_stop(RzDebug *dbg) {
	return linux_stop_threads(dbg, dbg->reason.tid);
}

static int rz_debug_native_continue(RzDebug *dbg, int pid, int tid, int sig) {
	int contsig = dbg->reason.signum;
	int ret = -1;

	if (sig != -1) {
		contsig = sig;
	}
	/* SIGINT handler for attached processes: dbg.consbreak (disabled by default) */
	if (dbg->consbreak) {
		rz_cons_break_push((RzConsBreak)interrupt_process, dbg);
	}

	if (dbg->continue_all_threads && dbg->n_threads && dbg->threads) {
		RzDebugPid *th;
		RzListIter *it;
		rz_list_foreach (dbg->threads, it, th) {
			ret = rz_debug_ptrace(dbg, PTRACE_CONT, th->pid, 0, 0);
			if (ret) {
				RZ_LOG_ERROR("(%d) is running or dead.\n", th->pid);
			}
		}
	} else {
		ret = rz_debug_ptrace(dbg, PTRACE_CONT, tid, NULL, (rz_ptrace_data_t)(size_t)contsig);
		if (ret) {
			rz_sys_perror("PTRACE_CONT");
		}
	}
	// return ret >= 0 ? tid : false;
	return tid;
}

static RzDebugInfo *rz_debug_native_info(RzDebug *dbg, const char *arg) {
	return linux_info(dbg, arg);
}

#ifdef WAIT_ON_ALL_CHILDREN
static RzDebugReasonType rz_debug_native_wait(RzDebug *dbg, int pid) {
	RzDebugReasonType reason = RZ_DEBUG_REASON_UNKNOWN;

	if (pid == -1) {
		RZ_LOG_ERROR("rz_debug_native_wait called with pid -1\n");
		return RZ_DEBUG_REASON_ERROR;
	}
	int status = -1;
	// XXX: this is blocking, ^C will be ignored
	int ret = waitpid(-1, &status, WAITPID_FLAGS);
	if (ret == -1) {
		rz_sys_perror("waitpid");
		return RZ_DEBUG_REASON_ERROR;
	}

	// eprintf ("rz_debug_native_wait: status=%d (0x%x) (return=%d)\n", status, status, ret);

	if (ret != pid) {
		reason = RZ_DEBUG_REASON_NEW_PID;
		rz_cons_printf("switching to pid %d\n", ret);
		rz_debug_select(dbg, ret, ret);
	}

	// TODO: switch status and handle reasons here
	// FIXME: Remove linux handling from this function?
#if defined(PT_GETEVENTMSG)
	reason = linux_ptrace_event(dbg, pid, status, true);
#endif

	/* propagate errors */
	if (reason == RZ_DEBUG_REASON_ERROR) {
		return reason;
	}

	/* we don't know what to do yet, let's try harder to figure it out. */
	if (reason == RZ_DEBUG_REASON_UNKNOWN) {
		if (WIFEXITED(status)) {
			rz_cons_printf("child exited with status %d\n", WEXITSTATUS(status));
			reason = RZ_DEBUG_REASON_DEAD;
		} else if (WIFSIGNALED(status)) {
			rz_cons_printf("child received signal %d\n", WTERMSIG(status));
			reason = RZ_DEBUG_REASON_SIGNAL;
		} else if (WIFSTOPPED(status)) {
			if (WSTOPSIG(status) != SIGTRAP &&
				WSTOPSIG(status) != SIGSTOP) {
				rz_cons_printf("Child stopped with signal %d\n", WSTOPSIG(status));
			}

			/* the ptrace documentation says GETSIGINFO is only necessary for
			 * differentiating the various stops.
			 *
			 * this might modify dbg->reason.signum
			 */
			if (rz_debug_handle_signals(dbg) != 0) {
				return RZ_DEBUG_REASON_ERROR;
			}
			reason = dbg->reason.type;
#ifdef WIFCONTINUED
		} else if (WIFCONTINUED(status)) {
			rz_cons_printf("child continued...\n");
			reason = RZ_DEBUG_REASON_NONE;
#endif
		} else if (status == 1) {
			/* XXX(jjd): does this actually happen? */
			rz_cons_printf("debugger is dead with status 1!\n");
			reason = RZ_DEBUG_REASON_DEAD;
		} else if (status == 0) {
			/* XXX(jjd): does this actually happen? */
			rz_cons_printf("debugger is dead with status 0\n");
			reason = RZ_DEBUG_REASON_DEAD;
		} else {
			if (ret != pid) {
				reason = RZ_DEBUG_REASON_NEW_PID;
			} else {
				/* ugh. still don't know :-/ */
				rz_cons_printf("returning from wait without knowing why...\n");
			}
		}
	}

	/* if we still don't know what to do, we have a problem... */
	if (reason == RZ_DEBUG_REASON_UNKNOWN) {
		rz_cons_printf("%s: no idea what happened...\n", __func__);
		reason = RZ_DEBUG_REASON_ERROR;
	}
	dbg->reason.tid = pid;
	dbg->reason.type = reason;
	return reason;
}
#else
static RzDebugReasonType rz_debug_native_wait(RzDebug *dbg, int pid) {
	RzDebugReasonType reason = RZ_DEBUG_REASON_UNKNOWN;
	if (pid == -1) {
		RZ_LOG_ERROR("rz_debug_native_wait called with pid -1\n");
		return RZ_DEBUG_REASON_ERROR;
	}

	reason = linux_dbg_wait(dbg, dbg->tid);
	dbg->reason.type = reason;
	return reason;
}
#endif

#undef MAXPID
#define MAXPID 99999

static RzList /*<RzDebugPid *>*/ *rz_debug_native_pids(RzDebug *dbg, int pid) {
	RzList *list = rz_list_new();
	if (!list) {
		return NULL;
	}
	return linux_pid_list(pid, list);
}

RZ_API RZ_OWN RzList /*<RzDebugPid *>*/ *rz_debug_native_threads(RzDebug *dbg, int pid) {
	RzList *list = rz_list_new();
	if (!list) {
		rz_cons_printf("No list?\n");
		return NULL;
	}
	return linux_thread_list(dbg, pid, list);
}

RZ_API ut64 rz_debug_get_tls(RZ_NONNULL RzDebug *dbg, int tid) {
	rz_return_val_if_fail(dbg, 0);
	return get_linux_tls_val(dbg, tid);
}

#define PRINT_FPU(fpregs) \
	rz_cons_printf("cwd = 0x%04x  ; control   ", (fpregs).cwd); \
	rz_cons_printf("swd = 0x%04x  ; status\n", (fpregs).swd); \
	rz_cons_printf("ftw = 0x%04x              ", (fpregs).ftw); \
	rz_cons_printf("fop = 0x%04x\n", (fpregs).fop); \
	rz_cons_printf("rip = 0x%016" PFMT64x "  ", (ut64)(fpregs).rip); \
	rz_cons_printf("rdp = 0x%016" PFMT64x "\n", (ut64)(fpregs).rdp); \
	rz_cons_printf("mxcsr = 0x%08x        ", (fpregs).mxcsr); \
	rz_cons_printf("mxcr_mask = 0x%08x\n", (fpregs).mxcr_mask)

#define PRINT_FPU_NOXMM(fpregs) \
	rz_cons_printf("cwd = 0x%04lx  ; control   ", (fpregs).cwd); \
	rz_cons_printf("swd = 0x%04lx  ; status\n", (fpregs).swd); \
	rz_cons_printf("twd = 0x%04lx              ", (fpregs).twd); \
	rz_cons_printf("fip = 0x%04lx          \n", (fpregs).fip); \
	rz_cons_printf("fcs = 0x%04lx              ", (fpregs).fcs); \
	rz_cons_printf("foo = 0x%04lx          \n", (fpregs).foo); \
	rz_cons_printf("fos = 0x%04lx              ", (fpregs).fos)

static void print_fpu(void *f) {
#if __x86_64__
	struct user_fpregs_struct fpregs = *(struct user_fpregs_struct *)f;
	rz_cons_printf("---- x86-64 ----\n");
	PRINT_FPU(fpregs);
	rz_cons_printf("size = 0x%08x\n", (ut32)sizeof(fpregs));
	for (int i = 0; i < 16; i++) {
		ut32 *a = (ut32 *)&fpregs.xmm_space;
		a = a + (i * 4);
		rz_cons_printf("xmm%d = %08x %08x %08x %08x   ", i, (int)a[0], (int)a[1],
			(int)a[2], (int)a[3]);
		if (i < 8) {
			ut64 *st_u64 = (ut64 *)&fpregs.st_space[i * 4];
			ut8 *st_u8 = (ut8 *)&fpregs.st_space[i * 4];
			long double *st_ld = (long double *)&fpregs.st_space[i * 4];
			rz_cons_printf("mm%d = 0x%016" PFMT64x " | st%d = ", i, *st_u64, i);
			// print as hex TBYTE - always little endian
			for (int j = 9; j >= 0; j--) {
				rz_cons_printf("%02x", st_u8[j]);
			}
			// Using %Lf and %Le even though we do not show the extra precision to avoid another cast
			// %f with (double)*st_ld would also work
			rz_cons_printf(" %Le %Lf\n", *st_ld, *st_ld);
		} else {
			rz_cons_printf("\n");
		}
	}
#elif __i386__
	struct user_fpregs_struct fpregs = *(struct user_fpregs_struct *)f;
	rz_cons_printf("---- x86-32-noxmm ----\n");
	PRINT_FPU_NOXMM(fpregs);
	for (int i = 0; i < 8; i++) {
		ut64 *b = (ut64 *)(&fpregs.st_space[i * 4]);
		double *d = (double *)b;
		ut32 *c = (ut32 *)&fpregs.st_space;
		float *f = (float *)&fpregs.st_space;
		c = c + (i * 4);
		f = f + (i * 4);
		rz_cons_printf("st%d = %0.3lg (0x%016" PFMT64x ") | %0.3f (0x%08x) | "
			       "%0.3f (0x%08x)\n",
			i, d[0], b[0], f[0], c[0], f[1], c[1]);
	}
#endif
}

static int rz_debug_native_reg_read(RzDebug *dbg, int type, ut8 *buf, int size) {
	if (size < 1) {
		return false;
	}
	bool showfpu = false;
	int pid = dbg->tid;
	int ret = 0;
	if (type < -1) {
		showfpu = true;
		type = -type;
	}
	switch (type) {
	case RZ_REG_TYPE_DRX: {
		int i;
		for (i = 0; i < 8; i++) { // DR0-DR7
			if (i == 4 || i == 5) {
				continue;
			}
			long ret = rz_debug_ptrace(dbg, PTRACE_PEEKUSER, pid,
				(void *)rz_offsetof(struct user, u_debugreg[i]), 0);
			if ((i + 1) * sizeof(ret) > size) {
				rz_cons_printf("linux_reg_get: Buffer too small %d\n", size);
				break;
			}
			memcpy(buf + (i * sizeof(ret)), &ret, sizeof(ret));
		}
		struct user a;
		return sizeof(a.u_debugreg);
	}
		return true;
		break;
	case RZ_REG_TYPE_FPU:
	case RZ_REG_TYPE_MMX:
	case RZ_REG_TYPE_XMM: {
		struct user_fpregs_struct fpregs;
		if (type == RZ_REG_TYPE_FPU) {
#if __x86_64__
			ret = rz_debug_ptrace(dbg, PTRACE_GETFPREGS, pid, NULL, &fpregs);
			if (ret != 0) {
				rz_sys_perror("PTRACE_GETFPREGS");
				return false;
			}
			if (showfpu) {
				print_fpu((void *)&fpregs);
			}
			size = RZ_MIN(sizeof(fpregs), size);
			memcpy(buf, &fpregs, size);
			return size;
#elif __i386__
			struct user_fpxregs_struct fpxregs;
			ret = rz_debug_ptrace(dbg, PTRACE_GETFPXREGS, pid, NULL, &fpxregs);
			if (ret == 0) {
				if (showfpu) {
					print_fpu((void *)&fpxregs);
				}
				size = RZ_MIN(sizeof(fpxregs), size);
				memcpy(buf, &fpxregs, size);
				return size;
			} else {
				ret = rz_debug_ptrace(dbg, PTRACE_GETFPREGS, pid, NULL, &fpregs);
				if (showfpu) {
					print_fpu((void *)&fpregs);
				}
				if (ret != 0) {
					rz_sys_perror("PTRACE_GETFPREGS");
					return false;
				}
				size = RZ_MIN(sizeof(fpregs), size);
				memcpy(buf, &fpregs, size);
				return size;
			}
#endif // __i386__
		}
	} break;
	case RZ_REG_TYPE_SEG:
	case RZ_REG_TYPE_FLG:
	case RZ_REG_TYPE_GPR: {
		RZ_DEBUG_REG_T regs;
		memset(&regs, 0, sizeof(regs));
		memset(buf, 0, size);
		/* linux -{arm/mips/riscv/x86/x86_64} */
		ret = rz_debug_ptrace(dbg, PTRACE_GETREGS, pid, NULL, &regs);
		/*
		 * if perror here says 'no such process' and the
		 * process exists still.. is because there's a missing call
		 * to 'wait'. and the process is not yet available to accept
		 * more ptrace queries.
		 */
		if (ret != 0) {
			rz_sys_perror("PTRACE_GETREGS");
			return false;
		}
		size = RZ_MIN(sizeof(regs), size);
		memcpy(buf, &regs, size);
		return size;
	} break;
	case RZ_REG_TYPE_YMM: {
#if HAVE_YMM && __x86_64__ && defined(PTRACE_GETREGSET)
		ut32 ymm_space[128]; // full ymm registers
		struct _xstate xstate;
		struct iovec iov;
		iov.iov_base = &xstate;
		iov.iov_len = sizeof(struct _xstate);
		ret = rz_debug_ptrace_get_x86_xstate(dbg, pid, &iov);
		if (ret == -1) {
			return false;
		}
		// stitch together xstate.fpstate._xmm and xstate.ymmh assuming LE
		int ri, rj;
		for (ri = 0; ri < 16; ri++) {
			for (rj = 0; rj < 4; rj++) {
				ymm_space[ri * 8 + rj] = xstate.fpstate._xmm[ri].element[rj];
			}
			for (rj = 0; rj < 4; rj++) {
				ymm_space[ri * 8 + (rj + 4)] = xstate.ymmh.ymmh_space[ri * 4 + rj];
			}
		}
		size = RZ_MIN(sizeof(ymm_space), size);
		memcpy(buf, &ymm_space, size);
		return size;
#endif
		return false;
	} break;
	}
	return false;
}

static int rz_debug_native_reg_write(RzDebug *dbg, int type, const ut8 *buf, int size) {
	int pid = dbg->tid;
	switch (type) {
	case RZ_REG_TYPE_DRX: {
		int i;
		long *val = (long *)buf;
		for (i = 0; i < 8; i++) { // DR0-DR7
			if (i == 4 || i == 5) {
				continue;
			}
			if (rz_debug_ptrace(dbg, PTRACE_POKEUSER, pid,
				    (void *)rz_offsetof(struct user, u_debugreg[i]), (rz_ptrace_data_t)val[i])) {
				rz_sys_perror("ptrace POKEUSER");
			}
		}
		return sizeof(RZ_DEBUG_REG_T);
	}
	case RZ_REG_TYPE_GPR: {
		int ret = rz_debug_ptrace(dbg, PTRACE_SETREGS, pid, 0, (void *)buf);
		if (ret == -1) {
			rz_sys_perror("reg_write");
			return false;
		}
		return true;
	}
	case RZ_REG_TYPE_FPU: {
		int ret = rz_debug_ptrace(dbg, PTRACE_SETFPREGS, pid, 0, (void *)buf);
		return (ret == 0);
	}
	default:
		RZ_LOG_ERROR("TODO: reg_write_non-gpr (%d)\n", type);
		return false;
	}
	return false;
}

static int io_perms_to_prot(int io_perms) {
	int prot_perms = PROT_NONE;

	if (io_perms & RZ_PERM_R) {
		prot_perms |= PROT_READ;
	}
	if (io_perms & RZ_PERM_W) {
		prot_perms |= PROT_WRITE;
	}
	if (io_perms & RZ_PERM_X) {
		prot_perms |= PROT_EXEC;
	}
	return prot_perms;
}

static int sys_thp_mode(void) {
	size_t i;
	const char *thp[] = {
		"/sys/kernel/mm/transparent_hugepage/enabled",
		"/sys/kernel/mm/redhat_transparent_hugepage/enabled",
	};
	int ret = 0;

	for (i = 0; i < RZ_ARRAY_SIZE(thp); i++) {
		char *val = rz_file_slurp(thp[i], NULL);
		if (val) {
			if (strstr(val, "[madvise]")) {
				ret = 1;
			} else if (strstr(val, "[always]")) {
				ret = 2;
			}
			free(val);
			break;
		}
	}

	return ret;
}

static int linux_map_thp(RzDebug *dbg, ut64 addr, int size) {
#if defined(MADV_HUGEPAGE)
	RzBuffer *buf = NULL;
	char code[1024];
	int ret = true;
	char *asm_list[] = {
		"x86", "x86.as",
		"x64", "x86.as",
		NULL
	};
	// In architectures where rizin is supported, arm and x86, it is 2MB
	const size_t thpsize = 1 << 21;

	if ((size % thpsize)) {
		rz_cons_printf("size not a power of huge pages size\n");
		return false;
	}
	// In always mode, is more into mmap syscall level
	// even though the address might not have the 'hg'
	// vmflags
	if (sys_thp_mode() != 1) {
		rz_cons_printf("transparent huge page mode is not in madvise mode\n");
		return false;
	}

	int num = rz_syscall_get_num(dbg->analysis->syscall, "madvise");

	snprintf(code, sizeof(code),
		"sc_madvise@syscall(%d);\n"
		"main@naked(0) { .rarg0 = sc_madvise(0x%08" PFMT64x ",%d, %d);break;\n"
		"}\n",
		num, addr, size, MADV_HUGEPAGE);
	rz_egg_reset(dbg->egg);
	rz_egg_setup(dbg->egg, dbg->arch, 8 * dbg->bits, 0, 0);
	rz_egg_load(dbg->egg, code, 0);
	if (!rz_egg_compile(dbg->egg)) {
		rz_cons_printf("Cannot compile.\n");
		goto err_linux_map_thp;
	}
	if (!rz_egg_assemble_asm(dbg->egg, asm_list)) {
		rz_cons_printf("rz_egg_assemble: invalid assembly\n");
		goto err_linux_map_thp;
	}
	buf = rz_egg_get_bin(dbg->egg);
	if (buf) {
		rz_reg_arena_push(dbg->reg);
		ut64 tmpsz;
		const ut8 *tmp = rz_buf_data(buf, &tmpsz);
		ret = rz_debug_execute(dbg, tmp, tmpsz, 1) == 0;
		rz_reg_arena_pop(dbg->reg);
	}
err_linux_map_thp:
	return ret;
#else
	return false;
#endif
}

static RzDebugMap *linux_map_alloc(RzDebug *dbg, ut64 addr, int size, bool thp) {
	RzBuffer *buf = NULL;
	RzDebugMap *map = NULL;
	char code[1024], *sc_name;
	int num;
	/* force to usage of x86.as, not yet working x86.nz */
	char *asm_list[] = {
		"x86", "x86.as",
		"x64", "x86.as",
		NULL
	};

	/* NOTE: Since kernel 2.4,  that  system  call  has  been  superseded  by
		 mmap2(2 and  nowadays  the  glibc  mmap()  wrapper  function invokes
		 mmap2(2)). If arch is x86_32 then usage mmap2() */
	if (!strcmp(dbg->arch, "x86") && dbg->bits == 4) {
		sc_name = "mmap2";
	} else {
		sc_name = "mmap";
	}
	num = rz_syscall_get_num(dbg->analysis->syscall, sc_name);
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif
	snprintf(code, sizeof(code),
		"sc_mmap@syscall(%d);\n"
		"main@naked(0) { .rarg0 = sc_mmap(0x%08" PFMT64x ",%d,%d,%d,%d,%d);break;\n"
		"}\n",
		num, addr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	rz_egg_reset(dbg->egg);
	rz_egg_setup(dbg->egg, dbg->arch, 8 * dbg->bits, 0, 0);
	rz_egg_load(dbg->egg, code, 0);
	if (!rz_egg_compile(dbg->egg)) {
		rz_cons_printf("Cannot compile.\n");
		goto err_linux_map_alloc;
	}
	if (!rz_egg_assemble_asm(dbg->egg, asm_list)) {
		rz_cons_printf("rz_egg_assemble: invalid assembly\n");
		goto err_linux_map_alloc;
	}
	buf = rz_egg_get_bin(dbg->egg);
	if (buf) {
		ut64 map_addr;

		rz_reg_arena_push(dbg->reg);
		ut64 tmpsz;
		const ut8 *tmp = rz_buf_data(buf, &tmpsz);
		map_addr = rz_debug_execute(dbg, tmp, tmpsz, 1);
		rz_reg_arena_pop(dbg->reg);
		if (map_addr != (ut64)-1) {
			if (thp) {
				if (!linux_map_thp(dbg, map_addr, size)) {
					// Not overly dramatic
					rz_cons_printf("map promotion to huge page failed\n");
				}
			}
			rz_debug_map_sync(dbg);
			map = rz_debug_map_get(dbg, map_addr);
		}
	}
err_linux_map_alloc:
	return map;
}

static int linux_map_dealloc(RzDebug *dbg, ut64 addr, int size) {
	RzBuffer *buf = NULL;
	char code[1024];
	int ret = 0;
	char *asm_list[] = {
		"x86", "x86.as",
		"x64", "x86.as",
		NULL
	};
	int num = rz_syscall_get_num(dbg->analysis->syscall, "munmap");

	snprintf(code, sizeof(code),
		"sc_munmap@syscall(%d);\n"
		"main@naked(0) { .rarg0 = sc_munmap(0x%08" PFMT64x ",%d);break;\n"
		"}\n",
		num, addr, size);
	rz_egg_reset(dbg->egg);
	rz_egg_setup(dbg->egg, dbg->arch, 8 * dbg->bits, 0, 0);
	rz_egg_load(dbg->egg, code, 0);
	if (!rz_egg_compile(dbg->egg)) {
		rz_cons_printf("Cannot compile.\n");
		goto err_linux_map_dealloc;
	}
	if (!rz_egg_assemble_asm(dbg->egg, asm_list)) {
		rz_cons_printf("rz_egg_assemble: invalid assembly\n");
		goto err_linux_map_dealloc;
	}
	buf = rz_egg_get_bin(dbg->egg);
	if (buf) {
		rz_reg_arena_push(dbg->reg);
		ut64 tmpsz;
		const ut8 *tmp = rz_buf_data(buf, &tmpsz);
		ret = rz_debug_execute(dbg, tmp, tmpsz, 1) == 0;
		rz_reg_arena_pop(dbg->reg);
	}
err_linux_map_dealloc:
	return ret;
}

static RzDebugMap *rz_debug_native_map_alloc(RzDebug *dbg, ut64 addr, int size, bool thp) {
	return linux_map_alloc(dbg, addr, size, thp);
}

static int rz_debug_native_map_dealloc(RzDebug *dbg, ut64 addr, int size) {
	return linux_map_dealloc(dbg, addr, size);
}

static void _map_free(RzDebugMap *map) {
	if (!map) {
		return;
	}
	free(map->name);
	free(map->file);
	free(map);
}

static RzList /*<RzDebugMap *>*/ *rz_debug_native_map_get(RzDebug *dbg) {
	RzList *list = NULL;
	RzDebugMap *map;
	int i, perm, unk = 0;
	char *pos_c;
	char path[1024], line[1024], name[PROC_NAME_SZ + 1];
	char region[PROC_REGION_SZ + 1], region2[PROC_REGION_SZ + 1], perms[PROC_PERM_SZ + 1];
	FILE *fd;
	if (dbg->pid == -1) {
		// eprintf ("rz_debug_native_map_get: No selected pid (-1)\n");
		return NULL;
	}
	/* prepend 0x prefix */
	region[0] = region2[0] = '0';
	region[1] = region2[1] = 'x';

	snprintf(path, sizeof(path), "/proc/%d/maps", dbg->pid);

	fd = rz_sys_fopen(path, "r");
	if (!fd) {
		char *errmsg = rz_str_newf("Cannot open '%s'", path);
		perror(errmsg);
		free(errmsg);
		return NULL;
	}

	list = rz_list_new();
	if (!list) {
		fclose(fd);
		return NULL;
	}
	list->free = (RzListFree)_map_free;
	while (!feof(fd)) {
		size_t line_len;
		bool map_is_shared = false;
		ut64 map_start, map_end;

		if (!fgets(line, sizeof(line), fd)) {
			break;
		}
		/* kill the newline if we got one */
		line_len = strlen(line);
		if (line[line_len - 1] == '\n') {
			line[line_len - 1] = '\0';
			line_len--;
		}
		/* maps files should not have empty lines */
		if (line_len == 0) {
			break;
		}

		ut64 offset = 0;
		// 7fc8124c4000-7fc81278d000 r--p 00000000 fc:00 17043921 /usr/lib/locale/locale-archive
		i = sscanf(line, "%" RZ_STR_DEF(PROC_REGION_LEFT_SZ) "s %" RZ_STR_DEF(PROC_PERM_SZ) "s %08" PFMT64x " %*s %*s %" RZ_STR_DEF(PROC_NAME_SZ) "[^\n]", &region[2], perms, &offset, name);
		if (i == 3) {
			name[0] = '\0';
		} else if (i != 4) {
			rz_cons_printf("%s: Unable to parse \"%s\"\n", __func__, path);
			rz_cons_printf("%s: problematic line: %s\n", __func__, line);
			rz_list_free(list);
			return NULL;
		}

		/* split the region in two */
		pos_c = strchr(&region[2], '-');
		if (!pos_c) { // should this be an error?
			continue;
		}
		strncpy(&region2[2], pos_c + 1, sizeof(region2) - 2 - 1);

		if (!*name) {
			snprintf(name, sizeof(name), "unk%d", unk++);
		}
		perm = 0;
		for (i = 0; i < 5 && perms[i]; i++) {
			switch (perms[i]) {
			case 'r': perm |= RZ_PERM_R; break;
			case 'w': perm |= RZ_PERM_W; break;
			case 'x': perm |= RZ_PERM_X; break;
			case 'p': map_is_shared = false; break;
			case 's': map_is_shared = true; break;
			}
		}

		map_start = rz_num_get(NULL, region);
		map_end = rz_num_get(NULL, region2);
		if (map_start == map_end || map_end == 0) {
			rz_cons_printf("%s: ignoring invalid map size: %s - %s\n", __func__, region, region2);
			continue;
		}
		map = rz_debug_map_new(name, map_start, map_end, perm, 0);
		if (!map) {
			break;
		}
		map->offset = offset;
		map->shared = map_is_shared;
		map->file = rz_str_dup(name);
		rz_list_append(list, map);
	}
	fclose(fd);
	return list;
}

static RzList /*<RzDebugMap *>*/ *rz_debug_native_modules_get(RzDebug *dbg) {
	char *lastname = NULL;
	RzDebugMap *map;
	RzListIter *iter, *iter2;
	RzList *list, *last;
	bool must_delete;
	if (!(list = rz_debug_native_map_get(dbg))) {
		return NULL;
	}
	if (!(last = rz_list_newf((RzListFree)rz_debug_map_free))) {
		rz_list_free(list);
		return NULL;
	}
	rz_list_foreach_safe (list, iter, iter2, map) {
		const char *file = map->file;
		if (!map->file) {
			file = map->file = rz_str_dup(map->name);
		}
		must_delete = true;
		if (file && *file == '/') {
			if (!lastname || strcmp(lastname, file)) {
				must_delete = false;
			}
		}
		if (must_delete) {
			rz_list_delete(list, iter);
		} else {
			rz_list_append(last, map);
			free(lastname);
			lastname = rz_str_dup(file);
		}
	}
	list->free = NULL;
	free(lastname);
	rz_list_free(list);
	return last;
}

static bool rz_debug_native_kill(RzDebug *dbg, int pid, int tid, int sig) {
	bool ret = false;
	if (pid == 0) {
		pid = dbg->pid;
	}
	if (sig == SIGKILL && dbg->threads) {
		rz_list_free(dbg->threads);
		dbg->threads = NULL;
	}
	if ((rz_sys_kill(pid, sig) != -1)) {
		ret = true;
	}
	if (errno == 1) {
		ret = -true; // EPERM
	}
	return ret;
}

static void sync_drx_regs(RzDebug *dbg, drxt *regs, size_t num_regs) {
	/* sanity check, we rely on this assumption */
	if (num_regs != NUM_DRX_REGISTERS) {
		RZ_LOG_ERROR("drx: Unsupported number of registers for get_debug_regs\n");
		return;
	}

	// sync drx regs
#define R dbg->reg
	regs[0] = rz_reg_getv(R, "dr0");
	regs[1] = rz_reg_getv(R, "dr1");
	regs[2] = rz_reg_getv(R, "dr2");
	regs[3] = rz_reg_getv(R, "dr3");
	/*
	RESERVED
	regs[4] = rz_reg_getv (R, "dr4");
	regs[5] = rz_reg_getv (R, "dr5");
*/
	regs[6] = rz_reg_getv(R, "dr6");
	regs[7] = rz_reg_getv(R, "dr7");
}

static void set_drx_regs(RzDebug *dbg, drxt *regs, size_t num_regs) {
	/* sanity check, we rely on this assumption */
	if (num_regs != NUM_DRX_REGISTERS) {
		RZ_LOG_ERROR("drx: Unsupported number of registers for get_debug_regs\n");
		return;
	}

#define R dbg->reg
	rz_reg_setv(R, "dr0", regs[0]);
	rz_reg_setv(R, "dr1", regs[1]);
	rz_reg_setv(R, "dr2", regs[2]);
	rz_reg_setv(R, "dr3", regs[3]);
	rz_reg_setv(R, "dr6", regs[6]);
	rz_reg_setv(R, "dr7", regs[7]);
}

static int rz_debug_native_drx(RzDebug *dbg, int n, ut64 addr, int sz, int rwx, int g, int api_type) {
	int retval = false;
	drxt regs[NUM_DRX_REGISTERS] = { 0 };
	// sync drx regs
	sync_drx_regs(dbg, regs, NUM_DRX_REGISTERS);

	switch (api_type) {
	case DRX_API_LIST:
		drx_list(regs);
		retval = false;
		break;
	case DRX_API_GET_BP:
		/* get the index of the breakpoint at addr */
		retval = drx_get_at(regs, addr);
		break;
	case DRX_API_REMOVE_BP:
		/* remove hardware breakpoint */
		drx_set(regs, n, addr, -1, 0, 0);
		retval = true;
		break;
	case DRX_API_SET_BP:
		/* set hardware breakpoint */
		drx_set(regs, n, addr, sz, rwx, g);
		retval = true;
		break;
	default:
		/* this should not happen, someone misused the API */
		RZ_LOG_ERROR("drx: Unsupported api type in rz_debug_native_drx\n");
		retval = false;
	}

	set_drx_regs(dbg, regs, NUM_DRX_REGISTERS);

	return retval;
}

static int rz_debug_native_bp(RzBreakpoint *bp, RzBreakpointItem *b, bool set) {
	if (b && b->hw) {
		return set
			? drx_add((RzDebug *)bp->user, bp, b)
			: drx_del((RzDebug *)bp->user, bp, b);
	}
	return false;
}

RzList /*<RzDebugDesc *>*/ *rz_debug_desc_native_list(int pid) {
	return linux_desc_list(pid);
}

static int rz_debug_native_map_protect(RzDebug *dbg, ut64 addr, int size, int perms) {
	RzBuffer *buf = NULL;
	char code[1024];
	int num;

	num = rz_syscall_get_num(dbg->analysis->syscall, "mprotect");
	snprintf(code, sizeof(code),
		"sc@syscall(%d);\n"
		"main@global(0) { sc(%p,%d,%d);\n"
		":int3\n"
		"}\n",
		num, (void *)(size_t)addr, size, io_perms_to_prot(perms));

	rz_egg_reset(dbg->egg);
	rz_egg_setup(dbg->egg, dbg->arch, 8 * dbg->bits, 0, 0);
	rz_egg_load(dbg->egg, code, 0);
	if (!rz_egg_compile(dbg->egg)) {
		rz_cons_printf("Cannot compile.\n");
		return false;
	}
	if (!rz_egg_assemble(dbg->egg)) {
		rz_cons_printf("rz_egg_assemble: invalid assembly\n");
		return false;
	}
	buf = rz_egg_get_bin(dbg->egg);
	if (buf) {
		rz_reg_arena_push(dbg->reg);
		ut64 tmpsz;
		const ut8 *tmp = rz_buf_data(buf, &tmpsz);
		rz_debug_execute(dbg, tmp, tmpsz, 1);
		rz_reg_arena_pop(dbg->reg);
		return true;
	}

	return false;
}

static int rz_debug_desc_native_open(const char *path) {
	return 0;
}

static bool rz_debug_gcore(RzDebug *dbg, char *path, RzBuffer *dest) {
	(void)path;
	return linux_generate_corefile(dbg, dest);
}

struct rz_debug_desc_plugin_t rz_debug_desc_plugin_native = {
	.open = rz_debug_desc_native_open,
	.list = rz_debug_desc_native_list,
};

static bool rz_debug_native_init(RzDebug *dbg, void **user) {
	dbg->cur->desc = rz_debug_desc_plugin_native;
	return true;
}

static void rz_debug_native_fini(RzDebug *dbg, void *user) {
	if (!user) {
		return;
	}
	free(user);
}

RzDebugPlugin rz_debug_plugin_native = {
	.name = "native",
	.license = "LGPL3",
#if __i386__
	.bits = RZ_SYS_BITS_32,
	.arch = "x86",
	.canstep = 1,
#elif __x86_64__
	.bits = RZ_SYS_BITS_32 | RZ_SYS_BITS_64,
	.arch = "x86",
	.canstep = 1, // XXX it's 1 on some platforms...
#endif
	.init = &rz_debug_native_init,
	.fini = &rz_debug_native_fini,
	.step = &rz_debug_native_step,
	.cont = &rz_debug_native_continue,
	.stop = &rz_debug_native_stop,
	.contsc = &rz_debug_native_continue_syscall,
	.attach = &rz_debug_native_attach,
	.detach = &rz_debug_native_detach,
	.select = &rz_debug_native_select,
	.pids = &rz_debug_native_pids,
	.threads = &rz_debug_native_threads,
	.wait = &rz_debug_native_wait,
	.kill = &rz_debug_native_kill,
	.frames = &rz_debug_native_frames, // rename to backtrace ?
	.reg_profile = rz_debug_native_reg_profile,
	.reg_read = rz_debug_native_reg_read,
	.info = rz_debug_native_info,
	.reg_write = (void *)&rz_debug_native_reg_write,
	.map_alloc = rz_debug_native_map_alloc,
	.map_dealloc = rz_debug_native_map_dealloc,
	.map_get = rz_debug_native_map_get,
	.modules_get = rz_debug_native_modules_get,
	.map_protect = rz_debug_native_map_protect,
	.breakpoint = rz_debug_native_bp,
	.drx = rz_debug_native_drx,
	.gcore = rz_debug_gcore,
};