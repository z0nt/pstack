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
 * $Id: elfinfo.h,v 1.2 2002/11/25 12:56:34 pmedwards Exp $
 */

/*
 * elfinfo.h
 * Utility interface for accessing ELF images.
 */

#ifndef elfinfo_h_guard
#define elfinfo_h_guard

struct ElfObject {
	struct ElfObject *next;
	Elf_Addr	 baseAddr; /* For loaded objects */
	char		*fileName;
	size_t		 fileSize;
	const char	*fileData;
	const Elf_Ehdr	*elfHeader;
	const Elf_Phdr **programHeaders;
	const Elf_Shdr **sectionHeaders;
	const Elf_Phdr  *dynamic;
	const char	*sectionStrings;
	const char	*interpreterName;
	const struct stab *stabs;
	const char 	*stabStrings;
	int		 stabCount;
};

struct stab {
	unsigned long n_strx;
	unsigned char n_type;
	unsigned char n_other;
	unsigned short n_desc;
	unsigned long n_value;
};

enum StabType {
    N_UNDF = 0x0, 
    N_ABS = 0x2,
    N_ABS_EXT = 0x3, 
    N_TEXT = 0x4, 
    N_TEXT_EXT = 0x5, 
    N_DATA = 0x6, 
    N_DATA_EXT = 0x7, 
    N_BSS = 0x8, 
    N_BSS_EXT = 0x9, 
    N_FN_SEQ = 0x0c, 
    N_INDR = 0x0a, 
    N_COMM = 0x12, 
    N_SETA = 0x14,
    N_SETA_EXT = 0x15, 
    N_SETT = 0x16,
    N_SETT_EXT = 0x17, 
    N_SETD = 0x18,
    N_SETD_EXT = 0x19, 
    N_SETB = 0x1a, 
    N_SETB_EXT = 0x1b, 
    N_SETV = 0x1c,
    N_SETV_EXT = 0x1d, 
    N_WARNING = 0x1e, 
    N_FN = 0x1f, 
    N_GSYM = 0x20, 
    N_FNAME = 0x22, 
    N_FUN = 0x24, 
    N_STSYM = 0x26, 
    N_LCSYM = 0x28, 
    N_MAIN = 0x2a, 
    n_ROSYM = 0x2c, 
    N_PC = 0x30, 
    N_NSYMS = 0x32, 
    N_NOMAP = 0x34, 
    N_OBJ = 0x38, 
    N_OPT = 0x3c, 
    N_RSYM = 0x40, 
    N_M2C = 0x42, 
    N_SLINE = 0x44, 
    N_DSLINE = 0x46, 
    N_BSLINE = 0x48, 
    N_DEFD = 0x4a, 
    N_FLINE = 0x4c, 
    N_EHDECL = 0x50, 
    N_CATCH = 0x54, 
    N_SSYM = 0x60, 
    N_ENDM = 0x62, 
    N_SO = 0x64, 
    N_LSYM = 0x80, 
    N_BINCL = 0x82, 
    N_SOL = 0x84, 
    N_PSYM = 0xa0, 
    N_EINCL = 0xa2, 
    N_ENTRY = 0xa4, 
    N_LBRAC = 0xc0, 
    N_EXCL = 0xc2, 
    N_SCOPE = 0xc4, 
    N_RBRAC = 0xe0, 
    N_BCOMM = 0xe2, 
    N_ECOMM = 0xe4, 
    N_ECOML = 0xe8, 
    N_WITH = 0xea, 
    N_NBTEXT = 0xf0, 
    N_NBDATA = 0xf2, 
    N_NBBSS = 0xf4, 
    N_NBSTS = 0xf6, 
    N_NBLCS = 0xf8
};

int	elfFindSectionByName(struct ElfObject *obj,
			const char *name, const Elf_Shdr **sectionp);
int	elfFindSymbolByAddress(struct ElfObject *obj,
			Elf_Addr addr, int type,
			const Elf_Sym **symp, const char **namep);
int	elfLinearSymSearch(struct ElfObject *o,
			const Elf_Shdr *hdr,
			const char *name, const Elf_Sym **symp);
int	elfFindSymbolByName(struct ElfObject *o,
			const char *name, const Elf_Sym **symp);
int	elfLoadObject(const char *fileName, struct ElfObject **objp);
int	elfGetNote(struct ElfObject *obj, const char *name,
			u_int32_t type, const void **datap, int *lenp);
int	elfGetImageFromCore(struct ElfObject *obj, const char **name);
int	elfUnloadObject(struct ElfObject *obj);
const char *elfGetAbiPrefix(struct ElfObject *o);
void	elfDumpSymbol(FILE *f, const Elf_Sym *sym,
			const char *strings, int indent);
void	elfDumpDynamic(FILE *f, const Elf_Dyn *dyn, int indent);
void	elfDumpObject(FILE *f, struct ElfObject *obj, int snap, int indent);
void	elfDumpSection(FILE * f, struct ElfObject * obj,
			const Elf_Shdr * hdr, int snap, int indent);
void	elfDumpProgramSegment(FILE *f, struct ElfObject *obj,
			const Elf_Phdr *hdr, int indent);
void	hexdump(FILE *f, int indent, const char *p, int len);
const char *	pad(int size);

#endif /* Guard. */
