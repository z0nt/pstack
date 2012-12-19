/* $Yahoo: //depot/yahoo/ybsd_common/usr.local/pstack/pstack.h#1 $ */

#ifndef __PSTACK_H__
#define	__PSTACK_H__

struct StackFrame {
	STAILQ_ENTRY(StackFrame) link;
	Elf_Addr	ip;
	Elf_Addr	bp;
	int		argCount;
	Elf_Word	args[1];
};

STAILQ_HEAD(StackFrameList, StackFrame);

struct Thread {
	int			running;
	struct Thread		*next;
	struct StackFrameList	stack;
	int			id;
};

struct MappedPage {
	const char *data;
	Elf_Addr address; /* Valid only if data != NULL */
	int lastAccess;
};

#define PAGECACHE_SIZE 4

struct PageCache {
	struct MappedPage pages[PAGECACHE_SIZE];
	int 		accessGeneration;
};

struct thread_ops;

struct Process {
	pid_t		 pid;
	void		*threadInfo;
	int		 objectCount;
	struct ElfObject *objectList;
	struct ElfObject *execImage;
	struct ElfObject *coreImage;
	int		 threadCount;
	struct Thread	*threadList;
	const char	*abiPrefix;
	struct PageCache pageCache;
	struct thread_ops *threadOps;
};

struct thread_ops {
	void		(*startup)(void);
	int		(*probe)(struct Process *);
	void		(*read_threads)(struct Process *);
	void		(*free)(struct Process *);
};

extern struct thread_ops thread_db_ops;
extern int gVerbose;

size_t	procReadMem(struct Process *proc, void *ptr, Elf_Addr remoteAddr,
	    size_t size);
int	procReadVar(struct Process *proc, struct ElfObject *obj,
	    const char *name, int *value);
struct Thread *procReadThread(struct Process *proc, Elf_Addr bp,
	    Elf_Addr ip);
size_t	procWriteMem(struct Process *proc, const void *ptr, Elf_Addr remoteAddr,
	    size_t size);

#endif
