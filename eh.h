/*
 * eh.h
 *
 *  Created on: Jul 30, 2017
 *      Author: mizhka
 */

#ifndef EH_H_
#define EH_H_

struct ehframehdr_item {
	int32_t rel_ip;
	uint32_t offset;
};

struct ehframehdr {
	uint32_t n_enc;
	uint32_t n_ptr;
	uint32_t n_fdecnt;
	struct ehframehdr_item base;
};

struct eh_record_fde {
	int32_t		pc_begin;
	uint32_t	pc_range;
	uint8_t		augmentation_len;
} fde_specific;

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

#define	REGCNT		200

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

enum {
	EH_PRINT_RULES = 1,
	EH_PRINT_BYTECODE = 2,
	EH_PRINT_FDE = 4,
	EH_PRINT_ALL = 255
};

int	ehLookupFrame(const struct ehframehdr *ehframehdr, const char* dataAddress, struct eh_cfa_state	*rules);
int32_t ehGetRelativeIP(Elf_Addr ip, struct ElfObject *obj);
void	ehPrintRules(struct eh_cfa_state *rules);

#endif /* EH_H_ */
