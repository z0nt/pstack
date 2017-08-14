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
#include "pstack.h"

/*
 * Command-line flags
 */
static int gFrameArgs = 6;		/* number of arguments to print */
static int gMaxFrames = 1024;		/* max number of frames to read */
static int gDoTiming = 0;		/* Report time process was stopped */
static int gShowObjectNames = 0;	/* show names of objects for each IP */
static int gVerbose = 0;
int gThreadID = -1;		/* filter by thread, -1 - all */
static int gIterations = 1;

/* Amount of time process was suspended (if gDoTiming == 1) */
static struct timeval gSuspendTime;

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
static void	procAddElfObject(struct Process *proc,
			struct ElfObject *obj, Elf_Addr base);
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
			warn("Batch mode: %d",gIterations);
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
				if (gDoTiming)
					fprintf(stderr,
						"suspended for %zd.%06ld secs\n",
						gSuspendTime.tv_sec, gSuspendTime.tv_usec);
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
	struct timeval start, end;
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
	if ((t = procReadThread(proc, regs.r_rbp, regs.r_rip)) != NULL) {
#else
	if ((t = procReadThread(proc, regs.r_ebp, regs.r_eip)) != NULL) {
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
procReadThread(struct Process *proc, Elf_Addr bp, Elf_Addr ip)
{
	int frameCount, i;
	struct StackFrame *frame;
	const int frameSize = sizeof(*frame) + sizeof(Elf_Word) * gFrameArgs;
	struct Thread *thread;

	/* Check to see if we have already seen this thread. */
	for (thread = proc->threadList; thread != NULL; thread = thread->next) {
		frame = STAILQ_FIRST(&thread->stack);
		if (frame->ip == ip && frame->bp == bp)
			return (thread);
	}
	
	thread = malloc(sizeof(struct Thread));
	thread->running = 0;
	STAILQ_INIT(&thread->stack);
	/* Put a bound on the number of iterations. */
	for (frameCount = 0; frameCount < gMaxFrames; frameCount++) {
		frame = malloc(frameSize);
		/* Store this frame, and its args in the Thread */
		frame->ip = ip;
		frame->bp = bp;
		STAILQ_INSERT_TAIL(&thread->stack, frame, link);
		for (i = 0; i < gFrameArgs; i++)
			if (procReadMem(proc, &frame->args[i],
			    bp + sizeof(Elf_Word) * 2 + i * sizeof(Elf_Word),
			    sizeof(Elf_Word)) != sizeof(Elf_Word))
				break;
		frame->argCount = i;
		/* Read the next frame */
		if (procReadMem(proc, &ip, bp + sizeof(bp), sizeof(ip))
		    != sizeof(ip) || ip == 0 ||
		    procReadMem(proc, &bp, bp, sizeof(bp)) != sizeof(bp) ||
		    bp <= frame->bp)
			break;
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

/*
 * Print a stack trace of each stack in the process
 */
static int
procDumpStacks(FILE *file, struct Process *proc, int indent)
{
	struct StackFrame *frame;
	struct ElfObject *obj;
	int i;
	struct Thread *thread;
	const Elf_Sym *sym;
	const char *fileName, *symName, *p, *padding;

	padding = pad(indent);
	fprintf(file, "%s", padding);
	if (proc->coreImage)
		fprintf(file, "(core file \"%s\")", proc->coreImage->fileName);
	else
		fprintf(file, "%d", proc->pid);
	fprintf(file, ": %s\n", proc->execImage->fileName);
	for (thread = proc->threadList; thread; thread = thread->next) {
		fprintf(file, "%s----------------- thread %d ",
		    padding, thread->id);
		if (thread->running)
			printf("(running) ");
		fprintf(file, "-----------------\n");
		STAILQ_FOREACH(frame, &thread->stack, link) {
			symName = fileName = "????????";
			sym = NULL;
			obj = NULL;
			if (procFindObject(proc, frame->ip, &obj) == 0) {
				fileName = obj->fileName;
				elfFindSymbolByAddress(obj,
				    frame->ip - obj->baseAddr, STT_FUNC, &sym,
				    &symName);
			}
			fprintf(file, "%s%#*zx ", padding - 1, 11, frame->ip);
			if (gVerbose) /* Show ebp for verbose */
			    fprintf(file, "0x%zx ", frame->bp);
			fprintf(file, "%s (", symName);
			if (frame->argCount) {
				for (i = 0; i < frame->argCount - 1; i++)
					fprintf(file, "%x, ", frame->args[i]);
				fprintf(file, "%x", frame->args[i]);
			}
			fprintf(file, ")");
			if (obj && sym != NULL)
				printf(" + %zx", frame->ip - obj->baseAddr -
				    sym->st_value);
			if (obj && gShowObjectNames) {
				printf(" in %s",
				    gShowObjectNames > 1 ||
				    !(p = strrchr(obj->fileName, '/')) ?
				    obj->fileName : p + 1);
			}
			printf("\n");
		}
		fprintf(file, "\n");
	}
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
				warnx("skipping \"%s\" as executable image",
				    path);
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
