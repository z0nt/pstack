CFLAGS=	-O0
DEBUG_FLAGS=	-g

PROG=	pstack
SRCS=	elf.c pstack.c thread_db.c eh.c

LDADD=	-lelftc
# libthread_db.so calls back into gdb for the proc services.  Make all the
# global symbols visible.
LDFLAGS+= -Wl,-E

.include <bsd.prog.mk>
