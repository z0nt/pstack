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
 * $Id: elf.c,v 1.1.1.1 2002/10/02 09:25:02 pmedwards Exp $
 */

/*
 * elf.c
 * Peter Edwards, January 2002.
 *
 * Implementation of utlities for accessing ELF images.
 */

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/procfs.h>
#include <sys/stat.h>

#include <elf.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "elfinfo.h"

static unsigned long	elf_hash(const unsigned char *name);

/*
 * Parse out an ELF file into an ElfObject structure.
 * XXX: We probably don't use all the information we parse, and can probably
 * pear this down a bit.
 */
int
elfLoadObject(const char *fileName, struct ElfObject **objp)
{
	int file, i;
	const unsigned char *p;
	struct ElfObject *obj;
	struct stat sb;
	const Elf_Ehdr *eHdr;
	const Elf_Shdr **sHdrs, *shdr;
	const Elf_Phdr **pHdrs;
	char *data;

	if ((file = open(fileName, O_RDONLY)) == -1) {
		warn("unable to open executable '%s'", fileName);
		return (-1);
	}
	if (fstat(file, &sb) == -1) {
		close(file);
		warn("unable to stat executable '%s'", fileName);
		return (-1);
	}
	data = mmap(0, sb.st_size, PROT_READ, MAP_SHARED, file, 0);
	close(file);
	if (data == MAP_FAILED) {
		warn("unable to map executable '%s'", fileName);
		return (-1);
	}
	obj = calloc(1, sizeof(*obj));
	obj->fileSize = sb.st_size;
	obj->fileData = data;
	obj->elfHeader = eHdr = (const Elf_Ehdr *)data;
	/* Validate the ELF header */
	if (!IS_ELF(*obj->elfHeader) ||
	    eHdr->e_ident[EI_CLASS] != ELF_TARG_CLASS ||
	    eHdr->e_ident[EI_VERSION] != EV_CURRENT) {
		warnx("not an ELF image");
		free(obj);
		munmap(data, sb.st_size);
		return (-1);
	}
	obj->programHeaders = pHdrs =
	    malloc(sizeof(Elf_Phdr *) * (eHdr->e_phnum + 1));
	for (p = data + eHdr->e_phoff, i = 0; i < eHdr->e_phnum; i++) {
		pHdrs[i] = (const Elf_Phdr *)p;
		switch (pHdrs[i]->p_type) {
		case PT_INTERP:
			obj->interpreterName = data + pHdrs[i]->p_offset;
			break;
		case PT_DYNAMIC:
			obj->dynamic = pHdrs[i];
			break;
		}
		p += eHdr->e_phentsize;
	}
	pHdrs[i] = 0;
	obj->sectionHeaders = sHdrs =
	    malloc(sizeof(Elf_Shdr *) * (eHdr->e_shnum + 1));
	for (p = data + eHdr->e_shoff, i = 0; i < eHdr->e_shnum; i++) {
		sHdrs[i] = (const Elf_Shdr *)p;
		p += eHdr->e_shentsize;
	}
	sHdrs[i] = 0;
	obj->sectionStrings = eHdr->e_shstrndx != SHN_UNDEF ?
	    data + sHdrs[eHdr->e_shstrndx]->sh_offset : 0;
	obj->fileName = strdup(fileName);
	*objp = obj;
	if (elfFindSectionByName(obj, ".stab", &shdr) != -1) {
		obj->stabs = (struct stab *)(obj->fileData + shdr->sh_offset);
		obj->stabCount = shdr->sh_size / sizeof (struct stab);
		if (shdr->sh_link)
			obj->stabStrings = obj->fileData +
			    sHdrs[shdr->sh_link]->sh_offset;
		else if (elfFindSectionByName(obj, ".stabstr", &shdr) != -1)
			obj->stabStrings = obj->fileData + shdr->sh_offset;
		else
			obj->stabStrings = 0;
	} else {
	    obj->stabs = 0;
	    obj->stabCount = 0;
	}
	return (0);
}

/*
 * Given an Elf object, find a particular section.
 */
int
elfFindSectionByName(struct ElfObject *obj, const char *name,
			const Elf_Shdr **shdrp)
{
	int i;

	for (i = 0; i < obj->elfHeader->e_shnum; i++)
		if (strcmp(obj->sectionHeaders[i]->sh_name +
		    obj->sectionStrings, name) == 0) {
			*shdrp = obj->sectionHeaders[i];
			return (0);
		}
	return (-1);
}

/*
 * Find the symbol that represents a particular address.
 * If we fail to find a symbol whose virtual range includes our target address
 * we will accept a symbol with the highest address less than or equal to our
 * target. This allows us to match the dynamic "stubs" in code.
 * A side-effect is a few false-positives: A stripped, dynamically linked,
 * executable will typically report functions as being "_init", because it is
 * the only symbol in the image, and it has no size.
 */
int
elfFindSymbolByAddress(struct ElfObject *obj, Elf_Addr addr,
			int type, const Elf_Sym **symp, const char **namep)
{
	const Elf_Shdr *symSection, **shdrs;
	const Elf_Sym *sym, *endSym;
	const char *symStrings;
	const char *sectionNames[] = { ".dynsym", ".symtab", 0 };
	int i, exact = 0;

	/* Try to find symbols in these sections */
	*symp = 0;
	shdrs = obj->sectionHeaders;
	for (i = 0; sectionNames[i] && !exact; i++) {
		if (elfFindSectionByName(obj, sectionNames[i],
		    &symSection) != 0)
			continue;
		/*
		 * Found the section in question: get the associated
		 * string section's data, and a pointer to the start
		 * and end of the table
		 */
		symStrings = obj->fileData +
		    shdrs[symSection->sh_link]->sh_offset;
		sym = (const Elf_Sym *)(obj->fileData +
		    symSection->sh_offset);
		endSym = (const Elf_Sym *)(obj->fileData +
		    symSection->sh_offset + symSection->sh_size);

		for (; sym < endSym; sym++) {
			if ((type == STT_NOTYPE ||
			    ELF_ST_TYPE(sym->st_info) == type) &&
			    sym->st_value <= addr &&
			    (shdrs[sym->st_shndx]->sh_flags & SHF_ALLOC)) {
				if (sym->st_size) {
					if (sym->st_size +
					    sym->st_value > addr) {
						*symp = sym;
						*namep = symStrings +
						    sym->st_name;
						exact = 1;
					}
				} else {
					if ((*symp) == 0 || (*symp)->st_value <
					    sym->st_value) {
						*symp = sym;
						*namep = symStrings +
						sym->st_name;
					}
				}
			}
		}
	}
	return (*symp ? 0 : -1);
}

int
elfLinearSymSearch(struct ElfObject *o, const Elf_Shdr *hdr,
			const char *name, const Elf_Sym **symp)
{
	const char *symStrings;
	const Elf_Sym *sym, *endSym;

	symStrings = o->fileData + o->sectionHeaders[hdr->sh_link]->sh_offset;

	sym = (const Elf_Sym *)(o->fileData + hdr->sh_offset); 
	endSym = sym = (const Elf_Sym *)(o->fileData + hdr->sh_offset + hdr->sh_size); 
	for (; sym < endSym; sym++)
		if (!strcmp(symStrings + sym->st_name, name)) {
			*symp = sym;
			return (0);
		}
	return (-1);
}

/*
 * Locate a symbol in an ELF image.
 */
int
elfFindSymbolByName(struct ElfObject *o, const char *name, const Elf_Sym **symp)
{
	const Elf_Shdr *hash, *syms;
	const char *symStrings;
	const Elf_Sym *sym;
	Elf_Word nbucket, nchain, i;
	const Elf_Word *buckets, *chains, *hashData;
	unsigned long hashv;

	/* First, search the hashed symbols in .dynsym.  */
	if (elfFindSectionByName(o, ".hash", &hash) == 0) {
		syms = o->sectionHeaders[hash->sh_link];
		hashData = (const Elf_Word *)(o->fileData + hash->sh_offset);
		sym = (const Elf_Sym *)(o->fileData + syms->sh_offset);
		symStrings = o->fileData +
		    o->sectionHeaders[syms->sh_link]->sh_offset;
		nbucket = hashData[0];
		nchain = hashData[1];
		buckets = hashData + 2;
		chains = buckets + nbucket;
		hashv = elf_hash(name) % nbucket;
		for (i = buckets[hashv]; i != STN_UNDEF; i = chains[i])
			if (strcmp(symStrings + sym[i].st_name, name) == 0) {
				*symp = sym + i;
				return (0);
			}
	} else if (elfFindSectionByName(o, ".dynsym", &syms) == 0) {
		/* No ".hash", but have ".dynsym": do linear search */
		if (elfLinearSymSearch(o, syms, name, symp) == 0)
			return (0);
	}
	/* Do a linear search of ".symtab" if present */
	if (elfFindSectionByName(o, ".symtab", &syms) == 0 &&
	    elfLinearSymSearch(o, syms, name, symp) == 0) {
		return (0);
	}
	return (-1);
}

/*
 * Get the data and length from a specific "note" in the ELF file
 */
int
elfGetNote(struct ElfObject *obj, const char *name,
		u_int32_t type, const void **datap, int *lenp)
{
	const Elf_Phdr **phdr;
	const Elf_Note *note;
	const char *noteName, *data, *s, *e;

	for (phdr = obj->programHeaders; *phdr; phdr++) {
		if ((*phdr)->p_type == PT_NOTE) {
			s = obj->fileData + (*phdr)->p_offset;
			e = s + (*phdr)->p_filesz;
			while (s < e) {
				note = (const Elf_Note *)s;
				s += sizeof(*note);
				noteName = s;
				s += roundup2(note->n_namesz, 4);
				data = s;
				s += roundup2(note->n_descsz, 4);
				if (strcmp(name, noteName) == 0 &&
				    (note->n_type == type || type == -1)) {
					*datap = data;
					*lenp = note->n_descsz;
					return (0);
				}
			}
		}
	}
	return (-1);
}

/*
 * Fetch the next "note" after the note whose data is pointed to by "datap".
 */
int
elfGetNextNote(struct ElfObject *obj, const char *name,
		u_int32_t type, const void **datap, int *lenp)
{
	const Elf_Phdr **phdr;
	const Elf_Note *note;
	const char *noteName, *data, *s, *e;
	int found;

	found = 0;
	for (phdr = obj->programHeaders; *phdr; phdr++) {
		if ((*phdr)->p_type == PT_NOTE) {
			s = obj->fileData + (*phdr)->p_offset;
			e = s + (*phdr)->p_filesz;
			while (s < e) {
				note = (const Elf_Note *)s;
				s += sizeof(*note);
				noteName = s;
				s += roundup2(note->n_namesz, 4);
				data = s;
				s += roundup2(note->n_descsz, 4);
				if (!found) {
					if (data == *datap)
						found = 1;
					continue;
				}
				if (strcmp(name, noteName) == 0 &&
				    (note->n_type == type || type == -1)) {
					*datap = data;
					*lenp = note->n_descsz;
					return (0);
				}
			}
		}
	}
	return (-1);
}

/*
 * Try to work out the name of the executable from a core file
 * XXX: This is not particularly useful, because the pathname appears to get
 * stripped.
 */
int
elfGetImageFromCore(struct ElfObject *obj, const char **name)
{
	const prpsinfo_t *psinfo;
	u_int32_t len;

	if (!elfGetNote(obj, "FreeBSD", NT_PRPSINFO,
	    (const void **)&psinfo, &len) &&
	    psinfo->pr_version == PRPSINFO_VERSION) {
		*name = psinfo->pr_fname;
		return (0);
	}
	return (-1);
}

/*
 * Attempt to find a prefix to an executable ABI's "emulation tree"
 */
const char *
elfGetAbiPrefix(struct ElfObject *obj)
{
	int i;
	static struct {
		int brand;
		const char *oldBrand;
		const char *interpreter;
		const char *prefix;
	} knownABIs[] = {
	    { ELFOSABI_FREEBSD, "FreeBSD", "/usr/libexec/ld-elf.so.1", 0},
	    { ELFOSABI_LINUX, "Linux", "/lib/ld-linux.so.1", "/compat/linux"},
	    { ELFOSABI_LINUX, "Linux", "/lib/ld-linux.so.2", "/compat/linux"},
	    { -1,0,0 }
	};

	/* Trust EI_OSABI, or the 3.x brand string first */
	for (i = 0; knownABIs[i].brand != -1; i++) {
		if (knownABIs[i].brand == obj->elfHeader->e_ident[EI_OSABI] ||
		    strcmp(knownABIs[i].oldBrand,
		    obj->elfHeader->e_ident + OLD_EI_BRAND) == 0)
			return knownABIs[i].prefix;
	}
	/* ... Then the interpreter */
	if (obj->interpreterName) {
	    for (i = 0; knownABIs[i].brand != -1; i++) {
		    if (strcmp(knownABIs[i].interpreter,
			obj->interpreterName) == 0)
			    return knownABIs[i].prefix;
	    }
	}
	/* No prefix */
	return 0;
}

/*
 * Free any resources assoiated with an ElfObject
 */
int
elfUnloadObject(struct ElfObject *obj)
{
	free(obj->fileName);
	free(obj->sectionHeaders);
	free(obj->programHeaders);
	munmap((void *)obj->fileData, obj->fileSize);
	free(obj);
	return (0);
}

/*
 * Culled from System V Application Binary Interface
 */
static unsigned long elf_hash(const unsigned char *name)
{
	unsigned long h = 0, g;

	while (*name != '\0') {
		h = (h << 4) + *name++;
		if ((g = h & 0xf0000000) != 0)
			h ^= g >> 24;
		h &= ~g;
	}
	return (h);
}

/*
 * Debug output of the contents of an ELF32 section
 */
void
elfDumpSection(FILE *f, struct ElfObject *obj, const Elf_Shdr *hdr,
		int snapSize, int indent)
{
	const Elf_Sym * sym, *esym;
	int i;
	const char *symStrings, *padding = pad(indent);
	static const char *sectionTypeNames[] = {
		"SHT_NULL",
		"SHT_PROGBITS",
		"SHT_SYMTAB",
		"SHT_STRTAB",
		"SHT_RELA",
		"SHT_HASH",
		"SHT_DYNAMIC",
		"SHT_NOTE",
		"SHT_NOBITS",
		"SHT_REL",
		"SHT_SHLIB",
		"SHT_DYNSYM",
	};

	fprintf(f, "%sname= %s\n"
	    "%stype= %d (%s)\n"
	    "%sflags= %xH (%s%s%s)\n"
	    "%saddress= %xH\n"
	    "%soffset= %d (%xH)\n"
	    "%ssize= %d (%xH)\n"
	    "%slink= %d (%xH)\n"
	    "%sinfo= %d (%xH)\n" ,
	    padding, obj->sectionStrings + hdr->sh_name,
	    padding, hdr->sh_type, hdr->sh_type <= SHT_DYNSYM ?
	    sectionTypeNames[hdr->sh_type] : "unknown",
	    padding,
	    hdr->sh_flags,
	    hdr->sh_flags & SHF_WRITE ? "write " : "",
	    hdr->sh_flags & SHF_ALLOC ? "alloc " : "",
	    hdr->sh_flags & SHF_EXECINSTR ? "instructions " : "",
	    padding, hdr->sh_addr,
	    padding, hdr->sh_offset, hdr->sh_offset,
	    padding, hdr->sh_size, hdr->sh_size,
	    padding, hdr->sh_link, hdr->sh_link,
	    padding, hdr->sh_info, hdr->sh_info);
	switch (hdr->sh_type) {
	case SHT_SYMTAB:
	case SHT_DYNSYM:
		symStrings = obj->fileData +
		    obj->sectionHeaders[hdr->sh_link]->sh_offset;
		sym = (const Elf_Sym *) (obj->fileData + hdr->sh_offset);
		esym = (const Elf_Sym *) ((char *)sym + hdr->sh_size);
		for (i = 0; sym < esym; i++, sym++) {
			printf("%ssymbol %d:\n", padding, i);
			elfDumpSymbol(f, sym, symStrings, indent + 4);
		}
		break;
	}
	fprintf(f,"%sstart of data:\n", padding);
	hexdump(f, indent, obj->fileData + hdr->sh_offset,
	    MIN(hdr->sh_size, snapSize));
}

/*
 * Debug output of an ELF32 program segment
 */
void
elfDumpProgramSegment(FILE *f, struct ElfObject *obj, const Elf_Phdr *hdr,
			int indent)
{
	const char *padding = pad(indent);
	static const char *segmentTypeNames[] = {
		"PT_NULL",
		"PT_LOAD",
		"PT_DYNAMIC",
		"PT_INTERP",
		"PT_NOTE",
		"PT_SHLIB",
		"PT_PHDR"
	};

	fprintf(f, "%stype = %xH (%s)\n"
	    "%soffset = %xH (%d)\n"
	    "%svirtual address = %xH (%d)\n"
	    "%sphysical address = %xH (%d)\n"
	    "%sfile size = %xH (%d)\n"
	    "%smemory size = %xH (%d)\n"
	    "%sflags = %xH (%s %s %s)\n"
	    "%salignment = %xH (%d)\n",
	    padding, hdr->p_type,
	    hdr->p_type <= PT_PHDR ? segmentTypeNames[hdr->p_type] : "unknown",
	    padding, hdr->p_offset, hdr->p_offset,
	    padding, hdr->p_vaddr, hdr->p_vaddr,
	    padding, hdr->p_paddr, hdr->p_paddr,
	    padding, hdr->p_filesz, hdr->p_filesz,
	    padding, hdr->p_memsz, hdr->p_memsz,
	    padding, hdr->p_flags,
	    hdr->p_flags & PF_R ? "PF_R" : "",
	    hdr->p_flags & PF_W ? "PF_W" : "",
	    hdr->p_flags & PF_X ? "PF_X" : "",
	    padding, hdr->p_align, hdr->p_align);
	fprintf(f, "%sstart of data:\n", padding);
	hexdump(f, indent, obj->fileData + hdr->p_offset,
	    MIN(hdr->p_filesz, 64));
}

/*
 * Debug output of an Elf symbol.
 */
void
elfDumpSymbol(FILE *f, const Elf_Sym * sym, const char *strings, int indent)
{
	static const char *bindingNames[] = {
	    "STB_LOCAL",
	    "STB_GLOBAL",
	    "STB_WEAK",
	    "unknown3",
	    "unknown4",
	    "unknown5",
	    "unknown6",
	    "unknown7",
	    "unknown8",
	    "unknown9",
	    "unknowna",
	    "unknownb",
	    "unknownc",
	    "STB_LOPROC",
	    "STB_LOPROC + 1",
	    "STB_HIPROC + 1",
	};
	static const char *typeNames[] = {
	    "STT_NOTYPE",
	    "STT_OBJECT",
	    "STT_FUNC",
	    "STT_SECTION",
	    "STT_FILE",
	    "STT_5",
	    "STT_6",
	    "STT_7",
	    "STT_8",
	    "STT_9",
	    "STT_A",
	    "STT_B",
	    "STT_C",
	    "STT_LOPROC",
	    "STT_LOPROC + 1",
	    "STT_HIPROC"
	};
	const char *padding = pad(indent);

	fprintf(f,
	    "%sname = %s\n"
	    "%svalue = %d (%xH)\n"
	    "%ssize = %d (%xH)\n"
	    "%sinfo = %d (%xH)\n"
	    "%sbinding = %s\n"
	    "%stype = %s\n"
	    "%sother = %d (%xH)\n"
	    "%sshndx = %d (%xH)\n",
	    padding, sym->st_name ? strings + sym->st_name : "(unnamed)",
	    padding, sym->st_value, sym->st_value,
	    padding, sym->st_size, sym->st_size,
	    padding, sym->st_info, sym->st_info,
	    pad(indent + 4), bindingNames[sym->st_info >> 4],
	    pad(indent + 4), typeNames[sym->st_info & 0xf],
	    padding, sym->st_other, sym->st_other,
	    padding, sym->st_shndx, sym->st_shndx);
}

/*
 * Debug output of an ELF32 dynamic item
 */

void
elfDumpDynamic(FILE *f, const Elf_Dyn *dyn, int indent)
{
	const char *padding = pad(indent);
	static const char *tagNames[] = {
	    "DT_NULL",
	    "DT_NEEDED",
	    "DT_PLTRELSZ",
	    "DT_PLTGOT",
	    "DT_HASH",
	    "DT_STRTAB",
	    "DT_SYMTAB",
	    "DT_RELA",
	    "DT_RELASZ",
	    "DT_RELAENT",
	    "DT_STRSZ",
	    "DT_SYMENT",
	    "DT_INIT",
	    "DT_FINI",
	    "DT_SONAME",
	    "DT_RPATH",
	    "DT_SYMBOLIC",
	    "DT_REL",
	    "DT_RELSZ",
	    "DT_RELENT",
	    "DT_PLTREL",
	    "DT_DEBUG",
	    "DT_TEXTREL",
	    "DT_JMPREL",
	    "DT_BIND_NOW"
	};

	fprintf(f, "%stag: %d (%s)\n", padding, dyn->d_tag,
	    dyn->d_tag >= 0 && dyn->d_tag <= DT_BIND_NOW ?
	    tagNames[dyn->d_tag] : "(unknown)");
	fprintf(f, "%sword/addr: %d (%x)\n",
	    padding, dyn->d_un.d_val, dyn->d_un.d_val);
}


/*
 * Debug output of an ELF32 object.
 */
void
elfDumpObject(FILE *f, struct ElfObject *obj, int snaplen, int indent)
{
	int brand, i;
	static const char *typeNames[] = {
		"ET_NONE",
		"ET_REL",
		"ET_EXEC",
		"ET_DYN",
		"ET_CORE"
	};
	static const char *abiNames[] = {
	    "SYSV/NONE",
	    "HP-UX",
	    "NetBSD",
	    "Linux",
	    "Hurd",
	    "86Open",
	    "Solaris",
	    "Monterey",
	    "Irix",
	    "FreeBSD",
	    "Tru64",
	    "Modesto",
	    "OpenBSD"
	};
	const Elf_Ehdr *ehdr = obj->elfHeader;
	const Elf_Dyn *dyn, *edyn;
	const char *padding = pad(indent);

	brand = ehdr->e_ident[EI_OSABI];
	fprintf(f, "%sType= %s\n", padding, typeNames[ehdr->e_type]);
	fprintf(f, "%sEntrypoint= %x\n", padding, ehdr->e_entry);
	fprintf(f, "%sExetype= %d (%s)\n", padding, brand,
		brand >= 0  && brand <= ELFOSABI_OPENBSD ?
		abiNames[brand] : "unknown");
	for (i = 1; i < obj->elfHeader->e_shnum; i++) {
		fprintf(f, "%ssection %d:\n", padding, i);
		elfDumpSection(f, obj, obj->sectionHeaders[i], snaplen,
		    indent + 4);
	}
	for (i = 0; i < obj->elfHeader->e_phnum; i++) {
		fprintf(f, "%ssegment %d:\n", padding, i);
		elfDumpProgramSegment(f, obj, obj->programHeaders[i],
		    indent + 4);
	}
	if (obj->dynamic) {
		dyn = (const Elf_Dyn *)
		    (obj->fileData + obj->dynamic->p_offset);
		edyn = (const Elf_Dyn *)
		    ((char *)dyn + obj->dynamic->p_filesz);
		while (dyn < edyn) {
			printf("%sdynamic entry\n", padding - 4);
			elfDumpDynamic(f, dyn, indent + 8);
			dyn++;
		}
	}
	if (obj->interpreterName)
		fprintf(f, "%sinterpreter %s\n", padding, obj->interpreterName);
}

/*
 * Helps for pretty-printing
 */
const char *
pad(int size)
{
	static const char padding[] =
		"                                        "
		"                                        ";

	if (size > 80)
		size = 80;
	return (padding + 80 - size);
}

void
hexdump(FILE *f, int indent, const char *p, int len)
{
	const unsigned char *cp = (const unsigned char *)p;
	char hex[16 * 3 + 1], *hp, ascii[16 + 1], *ap;
	int i, c;

	if (!len)
		return;
	while (len) {
		hp = hex;
		ap = ascii;
		for (i = 0; len && i < 16; i++) {
			c = *cp++;
			len--;
			hp += sprintf(hp, "%02x ", c);
			*ap++ = c < 127 && c >= 32 ? c : '.';
		}
		*ap = 0;
		fprintf(f, "%s%-48s |%-16s|\n", pad(indent), hex, ascii);
	}
}
