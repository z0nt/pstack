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
#include <sys/signal.h>
#include <sys/queue.h>
#include <sys/ucontext.h>

#include <assert.h>
#include <elf.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>

#include "elfinfo.h"
#include "pstack.h"

/*
 * XXX: extracted from src/lib/libc_r/uthread/pthread_private.h
 */
union ThreadContext {
	jmp_buf		jb;
	sigjmp_buf	sjb;
	ucontext_t	uc;
};

enum CtxType {
	CTX_JB_NOSIG, CTX_JB, CTX_SJB, CTX_UC
};

/* ... end pthread_private.h stuff */

struct LibcInfo {
	Elf_Addr	threadList;
	Elf_Addr	threadRun;
	int		hasContextType;
	int		offThreadNext;
	int		offThreadState;
	int		offThreadName;
	int		offThreadCtxType;
	int		offThreadCtx;
	int		offUniqueId;
};

static int	procGetLibcInfo(struct Process *proc, struct ElfObject *obj,
	    struct LibcInfo *lci);
static void	libcr_startup(void);
static int	libcr_probe(struct Process *proc);
static void	libcr_free(struct Process *proc);
static void	procReadLibcThreads(struct Process *proc);

struct thread_ops libc_r_ops = {
	libcr_startup,
	libcr_probe,
	procReadLibcThreads,
	libcr_free
};

/*
 * Try to find useful information from libc_r
 */
static int
procGetLibcInfo(struct Process *proc, struct ElfObject *obj,
    struct LibcInfo *lci)
{

	assert(lci->threadList == 0);
	if (procReadVar(proc, obj, "_thread_list", &lci->threadList) != 0)
		return (0);
	/* This appears to be libc_r: get the rest of the details we want */
	procReadVar(proc, obj, "_thread_run", &lci->threadRun);
	procReadVar(proc, obj, "_thread_state_offset", &lci->offThreadState);
	procReadVar(proc, obj, "_thread_name_offset", &lci->offThreadName);
	procReadVar(proc, obj, "_thread_next_offset", &lci->offThreadNext);
	procReadVar(proc, obj, "_thread_uniqueid_offset", &lci->offUniqueId);
	lci->hasContextType = procReadVar(proc, obj, "_thread_ctxtype_offset",
	    &lci->offThreadCtxType) != -1;
	if (gVerbose > 1 && lci->hasContextType == 0)
	    warnx("post 4.7 threads library");
	procReadVar(proc, obj, "_thread_ctx_offset", &lci->offThreadCtx);
	return (1);
}

static void
libcr_startup(void)
{
}

static int
libcr_probe(struct Process *proc)
{
	struct ElfObject *obj;
	struct LibcInfo *lci;

	lci = calloc(1, sizeof(struct LibcInfo));

	/* Check each object file to see if it is libc_r. */
	for (obj = proc->objectList; obj != NULL; obj = obj->next) {
		if (procGetLibcInfo(proc, obj, lci)) {
			proc->threadInfo = lci;
			return (1);
		}
	}
	free(lci);
	return (0);
}

/*
 * Grovel through libc_r's internals to find any threads.
 */
static void
procReadLibcThreads(struct Process *proc)
{
	struct Thread *t;
	Elf_Addr ip, bp, thrPtr, id;
	struct LibcInfo *libc = proc->threadInfo;
	union ThreadContext ctx;
	enum CtxType ctxType;

	for (thrPtr = libc->threadList; thrPtr; ) {
		/*
		 * We've already read the currently running thread from the
		 * machine registers: If we see that thread on the _thread_list,
		 * we ignore it.
		 */
		/*
		 * If the threads library has a concept of a "context
		 * type", (4.x, where x <= 7), we need to read it to
		 * decide how to unwind, otherwise, we default to using
		 * the jump buffer.
		 */
		if (libc->hasContextType) {
		    if (procReadMem(proc, &ctxType,
			thrPtr + libc->offThreadCtxType,
			sizeof(ctxType)) != sizeof(ctxType)) {
			    warnx("cannot read context type for "
				"thread %p", thrPtr);
			    goto next;
		    }
		} else {
			ctxType = CTX_JB;
		}
		if (procReadMem(proc, &ctx, thrPtr +
		    libc->offThreadCtx, sizeof(ctx)) != sizeof(ctx)) {
			warnx("cannot read context for thread %p",
			    thrPtr);
			goto next;
		}
		switch (ctxType) {
		case CTX_JB_NOSIG:
		case CTX_JB:
			ip = (Elf_Addr)ctx.jb[0]._jb[0];
			bp = (Elf_Addr)ctx.jb[0]._jb[3];
			break;
		case CTX_SJB:
			ip = (Elf_Addr)ctx.sjb[0]._sjb[0];
			bp = (Elf_Addr)ctx.sjb[0]._sjb[3];
			break;
		case CTX_UC:
			ip = (Elf_Addr)ctx.uc.uc_mcontext.mc_eip;
			bp = (Elf_Addr)ctx.uc.uc_mcontext.mc_ebp;
			break;
		default:
			/* Don't know enough about thread to trace */
			warnx("cannot get frame for thread %p", thrPtr);
			goto next;
		}
		if ((t = procReadThread(proc, bp, ip)) != NULL) {
			procReadMem(proc, &id, thrPtr + libc->offUniqueId,
			    sizeof(id));
			t->id = id;
			if (thrPtr == libc->threadRun)
				t->running = 1;
		}
next:
		if (procReadMem(proc, &thrPtr, thrPtr + libc->offThreadNext,
		    sizeof(thrPtr)) != sizeof thrPtr) {
			warnx("failed to read more threads");
			break;
		}
	}
}

static void
libcr_free(struct Process *proc)
{

	free(proc->threadInfo);
	proc->threadInfo = NULL;
}
