/*
 * Copyright (c) 2002 Peter Edwards
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
 *
 * $FreeBSD$
 * $Id: pstack.c,v 1.3 2002/11/26 10:28:31 pmedwards Exp $
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/ptrace.h>

#include <dlfcn.h>
#include <elf.h>
#include <libgen.h>
#include <proc_service.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <thread_db.h>

#include "elfinfo.h"
#include "pstack.h"

#define LIBTHREAD_DB_SO "libthread_db.so"

static void	thread_db_startup(void);
static int	thread_db_probe(struct Process *proc);
static void	thread_db_free(struct Process *proc);
static void	thread_db_read_threads(struct Process *proc);

struct ps_prochandle {
	struct Process *proc;
};

struct thread_db_info {
	struct ps_prochandle proc_handle;
	td_thragent_t *thread_agent;
};
	
struct thread_ops thread_db_ops = {
	thread_db_startup,
	thread_db_probe,
	thread_db_read_threads,
	thread_db_free
};

/* Pointers to the libthread_db functions.  */

static td_err_e (*td_init_p) (void);

static td_err_e (*td_ta_new_p) (struct ps_prochandle *ps, td_thragent_t **ta);
static td_err_e (*td_ta_delete_p) (td_thragent_t *);
static td_err_e (*td_ta_thr_iter_p) (const td_thragent_t *ta,
				     td_thr_iter_f *callback,
				     void *cbdata_p, td_thr_state_e state,
				     int ti_pri, sigset_t *ti_sigmask_p,
				     unsigned int ti_user_flags);
static td_err_e (*td_thr_get_info_p) (const td_thrhandle_t *th,
				      td_thrinfo_t *infop);
static td_err_e (*td_thr_getgregs_p) (const td_thrhandle_t *th,
				      prgregset_t gregs);

static int thread_db_loaded;

static void
thread_db_startup(void)
{
	void *handle;
	td_err_e err;

	handle = dlopen(LIBTHREAD_DB_SO, RTLD_NOW);
	if (handle == NULL)
		return;

#define resolve(X)				\
	if (!(X##_p = dlsym(handle, #X)))	\
		return;

	resolve(td_init);
	resolve(td_ta_new);
	resolve(td_ta_delete);
	resolve(td_ta_thr_iter);
	resolve(td_thr_get_info);
	resolve(td_thr_getgregs);

	/* Initialize the library.  */
	err = td_init_p();
	if (err != TD_OK) {
		warnx("Cannot initialize libthread_db: %d", err);
		return;
	}
	thread_db_loaded = 1;
}

static int
thread_db_probe(struct Process *proc)
{
	struct ElfObject *obj;
	struct thread_db_info *info;
	td_err_e err;
	char *base;

	if (!thread_db_loaded)
		return (0);

	/* Explicitly ignore 4.x binaries. */
	for (obj = proc->objectList; obj != NULL; obj = obj->next) {
		base = basename(obj->fileName);
		if (base == NULL)
			continue;
		if (strcmp(base, "libc_r.so.4") == 0)
			return (0);
	}	
	
	info = malloc(sizeof(struct thread_db_info));
	info->proc_handle.proc = proc;
	err = td_ta_new_p(&info->proc_handle, &info->thread_agent);
	if (err == TD_OK) {
		proc->threadInfo = info;
		return (1);
	}
	free(info);
	return (0);
}

static int
find_new_threads_callback(const td_thrhandle_t *th_p, void *data)
{
	struct Process *proc;
	struct Thread *t;
	prgregset_t gregset;
	td_thrinfo_t ti;
	td_err_e err;

	err = td_thr_get_info_p(th_p, &ti);
	if (err != TD_OK) {
		warnx("Cannot get thread info: %d", err);
		return (0);
	}

	/* Ignore zombie */
	if (ti.ti_state == TD_THR_UNKNOWN || ti.ti_state == TD_THR_ZOMBIE)
		return (0);

	err = td_thr_getgregs_p(th_p, gregset);
	if (err != TD_OK) {
		warnx("Cannot fetch registers for thread %d: %d", ti.ti_tid,
		    err);
		return (0);
	}

	proc = data;
	t = procReadThread(proc, gregset[0].r_ebp, gregset[0].r_eip);
	if (t != NULL) {
		t->id = ti.ti_tid;
		if (ti.ti_state = TD_THR_RUN)
			t->running = 1;
	}
	return 0;
}

static void
thread_db_read_threads(struct Process *proc)
{
	struct thread_db_info *info;
	td_err_e err;

	/* Iterate over all user-space threads to discover new threads. */
	info = proc->threadInfo;
	err = td_ta_thr_iter_p(info->thread_agent, find_new_threads_callback,
	    proc, TD_THR_ANY_STATE, TD_THR_LOWEST_PRIORITY, TD_SIGNO_MASK,
	    TD_THR_ANY_USER_FLAGS);
	if (err != TD_OK)
		warnx("Cannot find new threads: %d", err);
}

static void
thread_db_free(struct Process *proc)
{
	struct thread_db_info *info;

	info = proc->threadInfo;
	td_ta_delete_p(info->thread_agent);
	free(proc->threadInfo);
	proc->threadInfo = NULL;
}

/* proc service functions */
void
ps_plog(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}

ps_err_e
ps_pglobal_lookup(struct ps_prochandle *ph, const char *objname,
    const char *name, psaddr_t *sym_addr)
{
	struct ElfObject *obj;
	const Elf_Sym *sym;

	obj = ph->proc->objectList;
	while (obj != NULL) {
		if (elfFindSymbolByName(obj, name, &sym) == 0) {
			*sym_addr = (void *)(uintptr_t)
			    (obj->baseAddr + sym->st_value);
			return (PS_OK);
		}
		obj = obj->next;
	}
	return (PS_NOSYM);
}

ps_err_e
ps_pread(struct ps_prochandle *ph, psaddr_t addr, void *buf, size_t len)
{

	if (procReadMem(ph->proc, buf, (uintptr_t)addr, len) != len)
		return (PS_ERR);
	return (PS_OK);
}

ps_err_e
ps_pwrite(struct ps_prochandle *ph, psaddr_t addr, const void *buf, size_t len)
{

	if (procWriteMem(ph->proc, buf, (uintptr_t)addr, len) != len)
		return (PS_ERR);
	return (PS_OK);
}

ps_err_e
ps_lgetregs(struct ps_prochandle *ph, lwpid_t lwpid, prgregset_t gregset)
{
	struct ElfObject *core;
	const prstatus_t *prstatus;
	const void *regs;
	int len;

	if (ph->proc->pid == -1) {
		core = ph->proc->coreImage;
		if (elfGetNote(core, "FreeBSD", NT_PRSTATUS,
		    (const void **)&prstatus, &len) == -1)
			return (PS_ERR);
		while (prstatus->pr_pid != lwpid) {
			if (elfGetNextNote(core, "FreeBSD", NT_PRSTATUS,
			    (const void **)&prstatus, &len) == -1)
				return (PS_ERR);
		}
		memcpy(gregset, &prstatus->pr_reg, sizeof(*gregset));
		return (PS_OK);
	}

	if (ptrace(PT_GETREGS, lwpid, (void *)gregset, 0) == -1)
		return (PS_ERR);
	return (PS_OK);
}

ps_err_e
ps_lsetregs(struct ps_prochandle *ph, lwpid_t lwpid, const prgregset_t gregset)
{

	warnx("%s called\n", __func__);
	return (PS_ERR);
}

ps_err_e
ps_lgetfpregs(struct ps_prochandle *ph, lwpid_t lwpid, prfpregset_t *fpregset)
{

	warnx("%s called\n", __func__);
	return (PS_ERR);
}

ps_err_e
ps_lsetfpregs(struct ps_prochandle *ph, lwpid_t lwpid,
               const prfpregset_t *fpregset)
{

	warnx("%s called\n", __func__);
	return (PS_ERR);
}

#ifdef PT_GETXMMREGS
ps_err_e
ps_lgetxmmregs(struct ps_prochandle *ph, lwpid_t lwpid, char *xmmregs)
{

	warnx("%s called\n", __func__);
	return (PS_ERR);
}

ps_err_e
ps_lsetxmmregs(struct ps_prochandle *ph, lwpid_t lwpid,
		const char *xmmregs)
{

	warnx("%s called\n", __func__);
	return (PS_ERR);
}
#endif

ps_err_e
ps_lstop(struct ps_prochandle *ph, lwpid_t lwpid)
{

	warnx("%s called\n", __func__);
	return (PS_ERR);
}

ps_err_e
ps_lcontinue(struct ps_prochandle *ph, lwpid_t lwpid)
{

	warnx("%s called\n", __func__);
	return (PS_ERR);
}

ps_err_e
ps_linfo(struct ps_prochandle *ph, lwpid_t lwpid, void *info)
{

	if (ph->proc->pid == -1) {
		/* XXX should verify lwpid and make a pseudo lwp info */
		memset(info, 0, sizeof(struct ptrace_lwpinfo));
		return (PS_OK);
	}

	if (ptrace(PT_LWPINFO, lwpid, info, sizeof(struct ptrace_lwpinfo)) == -1)
		return (PS_ERR);
	return (PS_OK);
}
