/*
 * eh.h
 *
 *  Created on: Jul 30, 2017
 *      Author: mizhka
 */

#ifndef EH_H_
#define EH_H_

#include <sys/_stdint.h>  // for uint32_t, int32_t, uint8_t, int64_t, uint64_t
#include <x86/elf.h>      // for Elf_Addr

#define	REGCNT	200

/* Logging levels */

enum {
        EH_PRINT_NONE = 0,
        EH_PRINT_RULES = 1,
        EH_PRINT_BYTECODE = 2,
        EH_PRINT_FDE = 4,
        EH_PRINT_ALL = 255
};

/* Structures */

struct ElfObject;

struct ehframehdr_item {
	int32_t		rel_ip;
	uint32_t	offset;
};


/*
 * This is combination of
 *   version (uint8)            structure version (=1)
 *   eh_frame_ptr_enc (uint8)   encoding of eh_frame_ptr
 *   fde_count_enc (uint8)      encoding of fde_count
 *   table_enc (uint8)          encoding of table entries
 */
#define	EH_FRAME_MAGIC	0x3b031b01

struct ehframehdr {
	uint32_t		magic;
	uint32_t		n_ptr; // pointer to eh_frame section
	uint32_t		n_fdecnt;
	struct ehframehdr_item	base;
};

struct eh_record_fde {
	int32_t		pc_begin;
	uint32_t	pc_range;
	uint8_t		augmentation_len;
};

struct eh_record_common {
	uint32_t	len;
	int32_t		cie_offset;
};

struct eh_record {
	struct eh_record_common		common;
	union {
		struct eh_record_fde	fde_specific;
	} fields;
};

struct eh_record_info {
	uint8_t		*base;
	uint8_t		*instr;
	uint32_t	 len;
	uint32_t	 instr_len;
};

struct eh_fde_info {
	struct eh_record_info	common;
	int32_t			pc_begin;
	uint32_t		pc_range;

};

struct eh_cie_info {
	struct eh_record_info	common;
	char*			augmentation;
	uint64_t		code_aligment;
	int64_t			data_aligment;
	uint8_t			register_ra;
};

struct eh_cfa_state {
	uint32_t	current_ip, target_ip;
	uint32_t	fde_offset;
	int32_t		eh_rel_ip;
	uint32_t	cfareg;
	uint32_t	cfaoffset;
	uint64_t	code_aligment;
	int64_t		data_aligment;
	int32_t		reg[REGCNT];
};


int	ehLookupFrame(const struct ehframehdr *ehframehdr, 
	    const char *dataAddress, struct eh_cfa_state *rules);
int32_t ehGetRelativeIP(Elf_Addr ip, struct ElfObject *obj);
void	ehPrintRules(struct eh_cfa_state *rules);

#endif /* EH_H_ */
