# $Id: Makefile,v 1.2 2002/11/26 10:28:31 pmedwards Exp $
PROG=pstack
SRCS=pstack.c elf.c
VER!=uname -r | sed -e 's/\..*//'
.if ${VER} != "4"
SRCS+=thread_db.c
.endif
PREFIX ?= /usr/local
BINDIR ?= ${PREFIX}/bin
MANDIR = ${PREFIX}/man/man

# libthread_db.so calls back into gdb for the proc services.  Make all the
# global symbols visible.
LDFLAGS+= -Wl,-E

TARBALL_FILES = ChangeLog Makefile elf.c elfinfo.h pstack.1 pstack.c

VERSION ?= 1.3
TARBALL = pstack-${VERSION}.tar.gz
CLEANFILES += ${TARBALL}
${TARBALL}:
	mkdir pstack-${VERSION}
.for _file in ${TARBALL_FILES}
	ln ${.CURDIR}/${_file} pstack-${VERSION}/${_file}
.endfor
	tar fc - pstack-${VERSION} | gzip > ${.TARGET}
	md5 ${TARBALL} > ../port/sysutils/pstack/distinfo
	rm -rf pstack-${VERSION}

tarball: ${TARBALL}

.include <bsd.prog.mk>
