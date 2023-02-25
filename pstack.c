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

/*
 * pstack.c
 * Peter Edwards, January 2002.
 *
 * Given a process ID or core file, try to get a backtrace of every thread in
 * that process.
 * This program tries to deal with dynamically linked executables, and the
 * libraries they have loaded at the time of the snapshot, and the threads
 * in a process linked with FreeBSD's libc_r. In order to do this, it does
 * some pretty horrible grovelling around in the process's address space, and
 * makes some pretty heavy assumptions about the layout of libc_r, and, to a
 * lesser extent, the dynamic linker.
 *
 */

#include <sys/types.h>
#include <sys/procfs.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <elf.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "elfinfo.h"
#include "eh.h"
#include "pstack.h"

/*
 * Command-line flags
 */
static int gFrameArgs = 6;		/* number of arguments to print */
static int gMaxFrames = 1024;		/* max number of frames to read */
static int gDoTiming = 0;		/* Report time process was stopped */
static int gShowObjectNames = 0;	/* show names of objects for each IP */
static int gVerbose = 0;
int gThreadID = -1;			/* filter by thread, -1 - all */
static int gIterations = 1;

/* Amount of time process was suspended (if gDoTiming == 1) */
static struct timeval gSuspendTime;
static struct timeval gSuspendLoadedTime;


static struct thread_ops *thread_ops[] = {
	&thread_db_ops,
	NULL
};

static Elf_Addr	procFindRDebugAddr(struct Process *proc);

static int	procOpen(pid_t pid, const char *exeName,
			const char *coreFile, struct Process **procp);
static int	procFindObject(struct Process *proc, Elf_Addr addr,
			struct ElfObject **objp);
static int	procDumpStacks(FILE *file, struct Process *proc, int indent);
static void	procDumpThreadStacks(FILE *file, struct Process *proc,
		    struct Thread *thread, int indent);
static void	procAddElfObject(struct Process *proc, struct ElfObject *obj,
		    Elf_Addr base);
static void	procFree(struct Process *proc);
static void	procFreeThreads(struct Process *proc);
static void	procFreeObjects(struct Process *proc);
static void	procLoadSharedObjects(struct Process *proc);
static int	procGetRegs(struct Process *proc, struct reg *reg);
static int	procSetupMem(struct Process *proc, pid_t pid, const char *core);

static int	usage(void);

int
main(int argc, char **argv)
{
	const char *coreFile, *execFile = NULL;
	char *p;
	int err, i, c, snap = 64;
	struct Process *proc;
	pid_t pid;
	struct ElfObject *dumpObj;
	struct thread_ops **tdops;

	while ((c = getopt(argc, argv, "a:d:e:f:n:T:hoOs:tv")) != -1) {
		switch (c) {
		case 'a':
			gFrameArgs = atoi(optarg);
			break;
		case 'd':
			/* Undocumented option to dump image contents */
			if (elfLoadObject(optarg, &dumpObj) == 0) {
				elfDumpObject(stdout, dumpObj, snap, 0);
				return 0;
			} else {
				return -1;
			}
			break;
		case 'e':
			execFile = optarg;
			break;
		case 'f':
			gMaxFrames = strtol(optarg, &p, 0);
			if (gMaxFrames == 0 || *p != '\0')
				errx(EX_USAGE, "invalid stack frame count");
			break;
		case 'h':
			usage();
			return 0;
		case 'n':
			gIterations = MAX(1, atoi(optarg));
			break;
		case 'o':
			gShowObjectNames = 1;
			break;
		case 'O':
			gShowObjectNames = 2;
			break;
		case 's':
			snap = atoi(optarg);
			break;
		case 't':
			gDoTiming = 1;
			break;
		case 'T':
			gThreadID = atoi(optarg);
			break;
		case 'v':
			gVerbose++;
			gShowObjectNames++;
			break;
		default:
			return (usage());
		}
	}
	if (optind == argc)
		return (usage());
	tdops = thread_ops;
	while (*tdops) {
		(*tdops)->startup();
		tdops++;
	}
	for (int iteration = 0; iteration < gIterations; iteration++) {
		if (iteration > 0)
			usleep(200000);

		for (err = 0, i = optind; i < argc; i++) {
			pid = atoi(argv[i]);
			if (pid == 0 || (kill(pid, 0) == -1 && errno == ESRCH)) {
				/* Assume argv[i] is a core file */
				coreFile = argv[i];
				pid = -1;
			} else {
				/* Assume argv[i] is a pid */
				coreFile = 0;
			}

			if (procOpen(pid, execFile, coreFile, &proc) == 0) {
				procDumpStacks(stdout, proc, 0);
				procFree(proc);
				if (gDoTiming) {
					fprintf(stderr,
						"suspended for %zd.%06ld secs\n",
						gSuspendTime.tv_sec, gSuspendTime.tv_usec);
					fprintf(stderr,
						"loaded in %zd.%06ld secs\n",
						gSuspendLoadedTime.tv_sec, gSuspendLoadedTime.tv_usec);
				}
			} else {
				err = EX_OSERR;
			}
		}
	}

	return (err);
}

static int
usage(void)
{
	fprintf(stderr, "usage: pstack\n\t[-hoOt] [-e executable] "
	    "[-a arg count] [-f max frame count] pid|core ...\n"
	    "\tor\n"
	    "\t-d ELF-file\n");
	return (EX_USAGE);
}

/*
 * Create a description of a process. Attempt to get:
 *       A description of the executable object.
 *       A description of any loaded objects from the run-time linker.
 *       A stack trace for each thread we find, as well as the currently
 *       running thread.
 */
static int
procOpen(pid_t pid, const char *exeName, const char *coreFile,
	struct Process **procp)
{
	struct Thread *t;
	struct timeval start, loadedObjects, end;
	int i, status, rc;
	char tmpBuf[PATH_MAX];
	struct Process *proc;
	struct reg regs;
	struct thread_ops **tdops;

	proc = malloc(sizeof(*proc));
	proc->objectList = NULL;
	proc->threadList = NULL;
	proc->objectCount = 0;
	proc->coreImage = NULL;
	proc->pid = -1;
	proc->threadOps = NULL;
	/*
	 * Prepare Process data structure
	 */
	if (procSetupMem(proc, pid, coreFile) != 0) {
		procFree(proc);
		return (-1);
	}
	/*
	 * Fixup the executable name (if not specified, get from the core
	 * file, or from sysctl)
	 */
	if (!exeName) {
		if (proc->coreImage) {
			if (elfGetImageFromCore(proc->coreImage, &exeName) !=
			    0) {
				warnx("cannot find image name in core file");
				procFree(proc);
				return (-1);
			}
		} else {
			int name[4];
			size_t len;

			name[0] = CTL_KERN;
			name[1] = KERN_PROC;
			name[2] = KERN_PROC_PATHNAME;
			name[3] = proc->pid;

			len = sizeof(tmpBuf);
			if (sysctl(name, 4, &tmpBuf, &len, NULL, 0) == -1) {
				warn("sysctl: kern.proc.pathname: %d", proc->pid);
				procFree(proc);
				return (-1);
			}
			exeName = tmpBuf;
		}
	}
	/*
	 * read executable image
	 */
	if (elfLoadObject(exeName, &proc->execImage)) {
		procFree(proc);
		return (-1);
	}
	/* Work out the ABI for this executable */
	proc->abiPrefix = elfGetAbiPrefix(proc->execImage);
	/*
	 * If we got the executable name from sysctl, read the symlink for
	 * prettyness. (We do this _after_ the opening of the object, in case
	 * the file has moved before we needed to open it)
	 */
	if (exeName == tmpBuf && (i = readlink(proc->execImage->fileName,
	    tmpBuf, sizeof(tmpBuf) - 1)) != -1) {
		free(proc->execImage->fileName);
		tmpBuf[i] = 0;
		proc->execImage->fileName = strdup(tmpBuf);
	}
	procAddElfObject(proc, proc->execImage, 0);
	/*
	 * At this point, we need to suspend the subject process.
	 * While its suspended, we get the contents of its r_debug, the list
	 * of threads, and stack traces
	 * The less we do while the process is stopped, the better.
	 */
	if (pid != -1) {
		if (gDoTiming)
			gettimeofday(&start, 0);
		if (ptrace(PT_ATTACH, pid, 0, 0) != 0) {
			warn("failed to attach to process %d", pid);
			procFree(proc);
			return -1;
		}
		if (waitpid(pid, &status, 0) == -1)
			err(1, "failed in waitpid");
		if (!WIFSTOPPED(status))
			err(1, "cannot stop process %d", pid);
	}
	/* Attach any dynamically-linked libraries */
	procLoadSharedObjects(proc);
	if (gDoTiming)
		gettimeofday(&loadedObjects, 0);

	/* See if we have any threads. */
	tdops = thread_ops;
	while (*tdops != NULL) {
		if ((*tdops)->probe(proc)) {
			proc->threadOps = *tdops;
			break;
		}
		tdops++;
	}

	/*
	 * Read the machine registers for the current stack and
	 * instruction pointer
	 */
	procGetRegs(proc, &regs);
	/* Trace the active thread */
#ifdef __LP64__
	if ((t = procReadThread(proc, regs.r_rbp, regs.r_rip, regs.r_rsp)) != NULL) {
#else
	if ((t = procReadThread(proc, regs.r_ebp, regs.r_eip, regs.r_esp)) != NULL) {
#endif
		t->id = -1;
		t->running = 1;
	}

	/* If we know of more threads, trace those. */
	if (proc->threadOps)
		proc->threadOps->read_threads(proc);
	if (pid != -1) {
		/* Resume the process */
		if (ptrace(PT_DETACH, pid, (caddr_t)1, 0) != 0)
			warn("failed to detach from process %d", pid);
		if (gDoTiming) {
			gettimeofday(&end, 0);
			gSuspendTime.tv_sec = end.tv_sec - start.tv_sec;
			gSuspendTime.tv_usec = end.tv_usec - start.tv_usec;
			if (gSuspendTime.tv_usec < 0) {
				gSuspendTime.tv_sec -= 1;
				gSuspendTime.tv_usec += 1000000;
			}
			gSuspendLoadedTime.tv_sec = loadedObjects.tv_sec - start.tv_sec;
			gSuspendLoadedTime.tv_usec = loadedObjects.tv_usec - start.tv_usec;
			if (gSuspendLoadedTime.tv_usec < 0) {
				gSuspendLoadedTime.tv_sec -= 1;
				gSuspendLoadedTime.tv_usec += 1000000;
			}
		}
	}
	/* Success */
	*procp = proc;
	return (0);
}

/*
 * Write data to the target's address space.
 */
size_t
procWriteMem(struct Process *proc, const void *ptr, Elf_Addr remoteAddr,
    size_t size)
{
	struct ptrace_io_desc pio;

	if (proc->pid == -1)
		return (0);

	pio.piod_op = PIOD_WRITE_D;
	pio.piod_offs = (void *)remoteAddr;
	pio.piod_addr = (void *)ptr;
	pio.piod_len = size;
	if (ptrace(PT_IO, proc->pid, (caddr_t)&pio, 0) < 0)
		return (0);
	return (pio.piod_len);
}

/*
 * Read data from the target's address space.
 */
size_t
procReadMem(struct Process *proc, void *ptr, Elf_Addr remoteAddr, size_t size)
{
	struct ptrace_io_desc pio;
	int rc, err;
	size_t fragSize, readLen;
	const Elf_Phdr **hdr;
	const char *data;
	char *p;
	const struct ElfObject *core;
	struct PageCache *pcache = &proc->pageCache;

	readLen = 0;
	core = proc->coreImage;
	if (!core) {
		/*
		 * A simple LRU page cache, to avoid pread()ing pointer-sized
		 * amounts of data
		 */
		int pagesize = getpagesize(), luGeneration;
		struct MappedPage *page, *luPage = 0;
		Elf_Addr pageLoc;
		for (readLen = 0; size; readLen += fragSize) {
			luGeneration = INT_MAX;
			pageLoc = remoteAddr - remoteAddr % pagesize;
			for (page = pcache->pages + PAGECACHE_SIZE - 1;
			    page >= pcache->pages; page--) {
				if (page->address == pageLoc &&
				    page->data != NULL)
					break;
				if (page->lastAccess < luGeneration) {
					luPage = page;
					luGeneration = page->lastAccess;
				}
			}
			if (page < pcache->pages) {
				page = luPage;
				p = malloc(pagesize);
				/*
				 * Page not found: read entire page into
				 * least-recently used cache slot
				 */
				pio.piod_op = PIOD_READ_D;
				pio.piod_offs = (void *)pageLoc;
				pio.piod_addr = p;
				pio.piod_len = pagesize;
				errno = 0;
				err = ptrace(PT_IO, proc->pid, (caddr_t)&pio, 0);
				if (err < 0 || pio.piod_len != pagesize) {
					if (gVerbose)
						warnx("ptrace_read err(%d): %s for address 0x%lx",
						    err, strerror(errno), pageLoc);
					free(p);
					return (readLen);
				}
				if (page->data)
					free((void *)page->data);
				page->data = p;
				page->address = pageLoc;
			}
			page->lastAccess = ++pcache->accessGeneration;
			fragSize = MIN(size, pagesize - remoteAddr % pagesize);
			memcpy((char *)ptr + readLen,
			    page->data + remoteAddr % pagesize, fragSize);
			remoteAddr += fragSize;
			size -= fragSize;
		}
		return readLen;
	} else {
		/* Locate "remoteAddr" in the core file */
		while (size) {
			for (hdr = core->programHeaders; *hdr; hdr++) {
				if ((*hdr)->p_type == PT_LOAD &&
				    (*hdr)->p_vaddr <= remoteAddr &&
				    (*hdr)->p_vaddr + (*hdr)->p_memsz >
				    remoteAddr)
					break;
			}
			if (*hdr) {
				fragSize = MIN(
				    (*hdr)->p_vaddr + (*hdr)->p_memsz -
				    remoteAddr, size);
				data = core->fileData + (*hdr)->p_offset +
				    remoteAddr - (*hdr)->p_vaddr;
				memcpy((char *)ptr + readLen, data, fragSize);
				size -= fragSize;
				readLen += fragSize;
			} else {
				return readLen;
			}
		}
		return (readLen);
	}
}

/*
 * Given the current ip and bp registers, read each stack frame, and add a
 * thread structure to the "threadList" of the process.
 */
struct Thread *
procReadThread(struct Process *proc, Elf_Addr bp, Elf_Addr ip, Elf_Addr sp)
{
	int		err, frameCount, i, pos;
	int32_t		ip_offset, rel_ip;

	Elf_Addr	next_ip, next_bp, next_sp;

	struct eh_cfa_state	*rules;
	struct ElfObject	*objp;
	struct StackFrame	*frame;
	struct Thread		*thread;

	const int frameSize = sizeof(*frame) + sizeof(Elf_Word) * gFrameArgs;

	/* Initialize next registers by initial values, prepare for shifting */
	next_ip = ip;
	next_bp = bp;
	next_sp = sp;

	/* Check to see if we have already seen this thread. */
	for (thread = proc->threadList; thread != NULL; thread = thread->next) {
		frame = STAILQ_FIRST(&thread->stack);
		if (frame->ip == ip && frame->sp == sp)
			return (thread);
	}

	if(gVerbose > 0)
		fprintf( stderr,
		    "\n---- thread:\tip = 0x%016lx bp = 0x%016lx sp = 0x%016lx\n",
		    ip, bp, sp);

	/*
	 * There are 2 options:
	 * 	 - initial frame is frame pointer optimized (FPO)
	 * 	 - initial frame is with frame pointer, not optimized
	 *
	 * If FPO, then if there is EH in object file, we can find CFA and
	 * virtual BP.
	 * If there is no EH, assume no frame pointer optimization.
	 */
//	if (procFindObject(proc, ip, &objp) == 0) {
//		rules = malloc(sizeof(struct eh_cfa_state));
//		if(rules == NULL) {
//			abort();
//		}
//		memset(rules, 0, sizeof(struct eh_cfa_state));
//		rules->target_ip = ip - objp->baseAddr;
//		rules->eh_rel_ip = ehGetRelativeIP(ip, objp);
//
//		err = ehLookupFrame(objp->ehframeHeader, objp->fileData, rules);
//
//		if (err != 0) {
//			warnx("Can't read eh segments");
//			abort();
//		}
//
//		if (gVerbose > 1)
//			ehPrintRules(rules);
//
//		if (rules->cfareg == 7)
//		{
//			next_sp = sp + rules->cfaoffset;
//		}
//
//		next_ip = rules->reg[16]
//		// + (2 * rules->data_aligment)
//
//
//		free(rules);
//	} else {
//		/* TODO: ??? */
//		warnx("jitted code: ip = 0x%lx sp = 0x%lx bp = 0x%lx", ip, sp, bp);
//	}

	thread = malloc(sizeof(struct Thread));
	thread->running = 0;
	ip_offset = sizeof(Elf_Addr);
	STAILQ_INIT(&thread->stack);

	/*
	 * Iterate over frames
	 * Put a bound on the number of iterations.
	 */
	for (frameCount = 0; frameCount < gMaxFrames; frameCount++) {
		/*
		 * Allocate memory for new frame, fill it by registers and store this
		 * frame with args in the Thread
		 */
		frame = malloc(frameSize);
		if (frame == NULL) {
			//TODO: error handling
		}
		frame->ip = ip;
		frame->bp = bp;
		frame->sp = sp;
		frame->broken = 0;
		STAILQ_INSERT_TAIL(&thread->stack, frame, link);

		if(gVerbose > 1)
			warnx("frame#%d:\tip = 0x%016lx bp = 0x%016lx sp = 0x%016lx offset = 0x%d",
				frameCount, ip, bp, sp, ip_offset);

		/* XXX: it's broken. Attempt to fetch arguments */
		for (i = 0; i < gFrameArgs; i++)
			if (procReadMem(proc, &frame->args[i],
			    bp + sizeof(Elf_Word) * 2 + i * sizeof(Elf_Word),
			    sizeof(Elf_Word)) != sizeof(Elf_Word))
				break;
		frame->argCount = i;

		if (procFindObject(proc, ip, &objp) == 0) {
			/*
			 * Let's suppose FPO optimization. Try to find object
			 * of last known frame and look for eh_frame_hdr info.
			 */
			rules = malloc(sizeof(struct eh_cfa_state));
			if(rules == NULL) {
				abort();
			}
			memset(rules, 0, sizeof(struct eh_cfa_state));
			rules->target_ip = ip - objp->baseAddr;
			rules->eh_rel_ip = ehGetRelativeIP(ip, objp);

			if (gVerbose > 2)
				warnx("ehLookup:\tof = 0x%016x bp = 0x%016lx"
				    "\n\t\t(file %s at %p)"
				    "\n\t\t(EH eh_rel_ip: %d, ehframeHeader: %p)",
				    rules->target_ip, frame->bp,
				    objp->fileName, objp->fileData,
				    rules->eh_rel_ip, objp->ehframeHeader);

			err = ehLookupFrame(objp->ehframeHeader, objp->fileData, rules);

			if (err != 0) {
				if (gVerbose > 2)
					warnx("Can't read eh segments: %d", err);
				break;
			}

			if (gVerbose > 1)
				ehPrintRules(rules);

			if (rules->cfareg == 7)
			{
				/* SP register number is 7 */
				next_sp = sp + rules->cfaoffset;
				//XXX:
				if (frameCount == 0) {
					next_sp -= sizeof(Elf_Addr);
				}
				next_ip = next_sp + rules->reg[0x10];
			} else if (rules->cfareg == 6)
			{
				/* BP register number is 6 */
				next_bp = bp + rules->cfaoffset;
				next_ip = next_bp + rules->reg[0x10];
				if (rules->reg[6] != 0) {
					next_bp += rules->reg[6];
				}
			} else {
				/* if CFA register is neither SP nor BP, then raise error */
				warnx("CFA is not SP/BP offset:"
				    "0%x 0x%lx / 0x%x (%s)",
				    rules->cfareg, ip, rules->target_ip,
				    objp->fileName);
				abort();
			}

			if (rules->reg[6] != 0 &&
				procReadMem(proc, &next_bp, next_bp, sizeof(Elf_Addr)) != sizeof(Elf_Addr)) {
				frame->broken = '!';
				free(rules);
				break;
			}

			if (rules->reg[7] != 0 &&
				procReadMem(proc, &next_sp, next_sp, sizeof(Elf_Addr)) != sizeof(Elf_Addr)) {
				frame->broken = '!';
				free(rules);
				break;
			}

			free(rules);

			/* Fetch next RIP register value */
			if (procReadMem(proc, &next_ip, next_ip, sizeof(Elf_Addr)) != sizeof(Elf_Addr)) {
				frame->broken = '!';
				break;
			}
		} else {
			/*
			 * Fetch caller IP and BP registers assuming actual frame contains:
			 *  - caller ip is *[bp + word]
			 *  - caller bp is *[bp]
			 */
			if (gVerbose > 1)
				warnx("bad #%d:\tip = 0x%016lx bp = 0x%016lx"
				    " sp = 0x%016lx prev_ip = 0x%016lx",
				    frameCount + 1, ip, frame->ip,
				    frame->sp, frame->bp);

			if (procReadMem(proc, &next_ip, bp + ip_offset, sizeof(Elf_Addr)) != sizeof(Elf_Addr)) {
				frame->broken = '!';
				break;
			}

			if (procReadMem(proc, &next_bp, bp, sizeof(Elf_Addr)) != sizeof(Elf_Addr)) {
				frame->broken = '?';
				break;
			}
		}
//		} else {
//			if (procReadMem(proc, &next_ip, bp, sizeof(Elf_Addr)) != sizeof(Elf_Addr)) {
//				frame->broken = '!';
//				break;
//			}
//
//			bp += sizeof(ip);
//			sp += sizeof(ip);
//		}

		if (ip == 0) {
			frame->broken = '.';
			if(gVerbose > 1)
				procDumpThreadStacks(stdout, proc, thread, 4);
			break;
		}

		/*
		 * We need more love for this place. If previous frame
		 * is BP-supplied, so our SP is previous BP + 2 and CFA
		 * is previous BP + 2 + cfaoffset. :et's imagine that we're
		 * also BP-supplied, so our frame pointer is CFA-2, i.e.
		 * previous BP + cfaoffset. Return address is CFA + RA shift,
		 * i.e. our frame pointer + 2 + RA shift
		 */
		//next_bp = frame->bp + rules->cfaoffset;
		/* TODO: 0x10 is return address, take it from EH information */
		//ip_offset = rules->reg[0x10] - (2 * rules->data_aligment);

		frame->broken = 0;
		sp = next_sp;
		bp = next_bp;
		ip = next_ip;

		continue;
fpo_fail:
		if(rules != NULL)
			free(rules);

		if ((bp <= frame->bp) || ((bp - frame->bp) > 0x100000)){
			if (gVerbose > 1)
				frame->broken = '*';
			break;
		}

		ip_offset = sizeof(bp);
		next_sp = frame->bp + sizeof(ip);

		sp = next_sp;
		bp = next_bp;
		ip = next_ip;
	}
	thread->next = proc->threadList;
	proc->threadList = thread;
	return thread;
}

/*
 * Find the mapped object within which "addr" lies
 */
static int
procFindObject(struct Process *proc, Elf_Addr addr, struct ElfObject **objp)
{
	struct ElfObject *obj;
	const Elf_Phdr *phdr;
	Elf_Addr segAddr;
	int i;

	for (obj = proc->objectList; obj; obj = obj->next) {
		for (i = 0; i < obj->elfHeader->e_phnum; i++) {
			phdr = obj->programHeaders[i];
			segAddr = phdr->p_vaddr + obj->baseAddr;
			if (addr >= segAddr && addr < segAddr + phdr->p_memsz) {
				*objp = obj;
				return (0);
			}
		}
	}
	return (-1);
}

static void
procDumpThreadStacks(FILE *file, struct Process *proc, struct Thread *thread, int indent)
{
	struct StackFrame	*frame;
	struct ElfObject	*obj;
	const Elf_Sym		*sym;
	const char		*padding, *fileName, *symName, *p;
	int			 tmp;
	size_t			 size;
	char 			*buf, *tmpStr;

	if (gThreadID != -1 && gThreadID != thread->id)
		return;

	padding = pad(indent);
	size = 1024 * sizeof(char);

	fprintf(file, "%s----------------- thread %d ",
	    padding, thread->id);
	if (thread->running)
		printf("(running) ");
	fprintf(file, "-----------------\n");
	STAILQ_FOREACH(frame, &thread->stack, link) {
		symName = fileName = "????????";
		sym = NULL;
		obj = NULL;
		buf = NULL;
		if (procFindObject(proc, frame->ip, &obj) == 0) {
			fileName = obj->fileName;
			/* TODO: batch frames for same object */
			elfFindSymbolByAddress(obj,
			    frame->ip - obj->baseAddr, STT_FUNC, &sym,
			    &symName);

			if (symName != NULL && strlen(symName) > 2 &&
			    symName[0] == '_' && symName[1] == 'Z') {
				buf = malloc(size);
				buf = __cxa_demangle(symName, buf, &size, &tmp);
				if ( tmp != 0 ) {
					free(buf);
					buf = NULL;
				} else {
					symName = buf;
				}
			}
		}
		if (gVerbose > 1 && frame->broken != 0)
			fprintf(file, "%c", frame->broken);
		fprintf(file, "%s%#*zx ", padding - 1, 11, frame->ip);
		if (gVerbose) /* Show ebp for verbose */
		    fprintf(file, "0x%zx ", frame->bp);
		if (obj && gShowObjectNames) {
			fprintf(file, "in %s\t",
			    gShowObjectNames > 1 ||
			    !(p = strrchr(obj->fileName, '/')) ?
			    obj->fileName : p + 1);
		}
		fprintf(file, "%s", symName);
		if (buf != NULL) {
			free (buf);
			buf = NULL;
		}

		if (obj && sym != NULL)
			fprintf(file, " + %zx", frame->ip - obj->baseAddr -
			    sym->st_value);

#if 0
		fprintf(file, " (");
		if (frame->argCount) {
			for (tmp = 0; tmp < frame->argCount - 1; tmp++)
				fprintf(file, "%x, ", frame->args[tmp]);
			fprintf(file, "%x", frame->args[tmp]);
		}
		fprintf(file, ")");
#endif

		fprintf(file, "\n");
	}
	fprintf(file, "\n");
	return;
}

/*
 * Print a stack trace of each stack in the process
 */
static int
procDumpStacks(FILE *file, struct Process *proc, int indent)
{
	struct Thread	*thread;
	const char	*padding;

	padding = pad(indent);
	fprintf(file, "%s", padding);
	if (proc->coreImage)
		fprintf(file, "(core file \"%s\")", proc->coreImage->fileName);
	else
		fprintf(file, "%d", proc->pid);
	fprintf(file, ": %s\n", proc->execImage->fileName);
	for (thread = proc->threadList; thread; thread = thread->next)
		procDumpThreadStacks(file, proc, thread, indent);

	return (0);
}

/*
 * Add ELF object description into process.
 */
static void
procAddElfObject(struct Process *proc, struct ElfObject *obj, Elf_Addr base)
{
	obj->next = proc->objectList;
	if (base > 0)
		obj->baseAddr = base;

	proc->objectList = obj;
	proc->objectCount++;
	if (gVerbose)
		warnx("object loaded: %s @ 0x%lx", obj->fileName, obj->baseAddr);
}

/*
 * Read the value of the named symbol
 */
int
procReadVar(struct Process *proc, struct ElfObject *obj, const char *name,
		int *value)
{
	const Elf_Sym *sym;

	if (elfFindSymbolByName(obj, name, &sym) == 0 &&
	    procReadMem(proc, value, obj->baseAddr + sym->st_value,
	    sizeof(*value)) == sizeof(*value)) {
		return (0);
	}
	return (-1);
}

/*
 * Grovel through the rtld's internals to find any shared libraries.
 */
static void
procLoadSharedObjects(struct Process *proc)
{
	int loaded, maxpath;
	struct r_debug rDebug;
	struct link_map map;
	Elf_Addr mapAddr, lAddr, r_debug_addr;
	char prefixedPath[PATH_MAX + 1], *path;
	struct ElfObject *obj;

	if ((r_debug_addr = procFindRDebugAddr(proc)) == 0 ||
	    r_debug_addr == -1)
		return;
	if (procReadMem(proc, &rDebug, r_debug_addr, sizeof(rDebug))
	    != sizeof(rDebug))
		return;
	if (proc->abiPrefix) {
		path = prefixedPath + snprintf(prefixedPath,
		    sizeof prefixedPath, "%s", proc->abiPrefix);
		maxpath = PATH_MAX - strlen(proc->abiPrefix);
	} else {
		path = prefixedPath;
		maxpath = PATH_MAX;
	}
	for (mapAddr = (Elf_Addr)rDebug.r_map; mapAddr;
	    mapAddr = (Elf_Addr)map.l_next) {
		if (procReadMem(proc, &map, mapAddr, sizeof(map))
		    != sizeof (map)) {
			warnx("cannot read link_map @ %zu", mapAddr);
			break;
		}
		/* Read the path to the file */
		if (map.l_name == 0)
			continue;
		if (procReadMem(proc, path, (Elf_Addr)map.l_name, maxpath) <=
		    0)
			strcpy(path, "(object name unreadable)");
		/*
		 * Load the object into memory, but avoid loading the
		 * executable again.
		 * The executable is loaded at the start of memory, so any
		 * object with a load address lower than the executable's
		 * entry point is either broken, or is the executable.
		 */
		lAddr = (Elf_Addr)map.l_addr;
		if (lAddr <= proc->execImage->elfHeader->e_entry) {
			if (gVerbose > 1)
				// it's normal situation
				warnx("skipping \"%s\" as executable image: %lx %lx",
				    path, lAddr, proc->execImage->elfHeader->e_entry);
			continue;
		}
		if (proc->abiPrefix && access(prefixedPath, R_OK) == 0)
			loaded = !elfLoadObject(prefixedPath, &obj);
		else
			loaded = !elfLoadObject(path, &obj);
		if (!loaded)
			continue;
		procAddElfObject(proc, obj, lAddr);
	}
}

/*
 * Grab various bits of information from the run-time linker.
 */
static Elf_Addr
procFindRDebugAddr(struct Process *proc)
{
	struct ElfObject *obj;
	Elf_Dyn dyno;
	const Elf_Dyn *dynp;
	Elf_Addr dyn;

	obj = proc->execImage;
	/* Find DT_DEBUG in the process's dynamic section. */
	if (obj->dynamic) {
		for (dyn = 0; dyn < obj->dynamic->p_filesz;
		    dyn += sizeof(Elf_Dyn)) {
			dynp = (const Elf_Dyn *)(obj->fileData +
			    obj->dynamic->p_offset + dyn);
			if (dynp->d_tag == DT_DEBUG &&
			    procReadMem(proc, &dyno,
			    obj->dynamic->p_vaddr + dyn + obj->baseAddr, sizeof(dyno)) ==
			    sizeof (dyno))
				return(dyno.d_un.d_ptr);
		}
	}
	return (0);
}

/*
 * Read the registers, from the core, or from the process.
 */
static int
procGetRegs(struct Process *proc, struct reg *reg)
{
	const prstatus_t *prstatus;
	int len, rc;

	rc = -1;
	if (proc->pid != -1) {
		if (ptrace(PT_GETREGS, proc->pid, (void *)reg, 0) == 0)
			rc = 0;
	} else {
		/* Read from core file. */
		if (!elfGetNote(proc->coreImage, "FreeBSD", NT_PRSTATUS,
		    (const void **)&prstatus, &len)) {
			memcpy(reg, &prstatus->pr_reg, sizeof(*reg));
			rc = 0;
		}
	}
	return rc;
}

/*
 * Setup what we need to read from the process memory (or core file)
 */
static int
procSetupMem(struct Process *proc, pid_t pid, const char *core)
{
	int i;

	if (core) {
		if (!elfLoadObject(core, &proc->coreImage))
			return (0);
	} else if (pid != -1) {
		proc->pid = pid;
		for (i = 0; i < PAGECACHE_SIZE; i++) {
			proc->pageCache.pages[i].lastAccess = 0;
			proc->pageCache.pages[i].data = NULL;
		}
		proc->pageCache.accessGeneration = 0;
		return (0);
	} else {
		warn("no core file or process id!");
	}
	return (-1);
}

/*
 * Free any resources associated with a Process
 */
static void
procFree(struct Process *proc)
{
	size_t i;

	if (proc->threadOps)
		proc->threadOps->free(proc);
	procFreeObjects(proc);
	procFreeThreads(proc);
	if (proc->pid != -1) {
		for (i = 0; i < PAGECACHE_SIZE; i++)
			if (proc->pageCache.pages[i].data)
				free((char *)proc->pageCache.pages[i].data);
	}
	if (proc->coreImage)
		elfUnloadObject(proc->coreImage);
	free(proc);
}

/*
 * Release resources associated with the thread list
 */
static void
procFreeThreads(struct Process *proc)
{
	struct StackFrameList *stackFrameList;
	struct StackFrame *frame;
	struct Thread *thread, *nextThread;

	for (thread = proc->threadList; thread; thread = nextThread) {
		stackFrameList = &thread->stack;
		while (!STAILQ_EMPTY(stackFrameList)) {
			frame = STAILQ_FIRST(stackFrameList);
			STAILQ_REMOVE_HEAD(stackFrameList, link);
			free(frame);
		}
		nextThread = thread->next;
		free(thread);
	}
}

/*
 * Release the loaded ELF objects
 */
static void
procFreeObjects(struct Process *proc)
{
	struct ElfObject *obj, *nextObj;

	for (obj = proc->objectList; obj; obj = nextObj) {
		nextObj = obj->next;
		elfUnloadObject(obj);
	}
}
