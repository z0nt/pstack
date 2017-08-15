/*
 * Copyright (c) 2017 Michael Zhilin <mizhka@gmail.com>
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
 */

/*
 * This file provides API to parse .eh_frame and .eh_frame_hdr sections of
 * binaries to retrieve frames without frame pointer information.
 */
#include <sys/types.h>

#include "eh.h"
#include <dwarf.h>    // for DW_CFA_advance_loc, DW_CFA_advance_loc1, DW_CFA...
#include <err.h>      // for warnx
#include <stdio.h>    // for printf, NULL
#include <stdlib.h>   // for free, malloc
#include <string.h>   // for strcmp, strlen
#include "elfinfo.h"  // for ElfObject

/*
 * table - sorted table of FDEs
 * count - amount of FDEs in table
 * key   - key to search
 * ret   - found value
 */

static int	ehLogging = 0;

static int	ehFindFDE(const struct ehframehdr_item	*table, int count,
		    int32_t key, uint32_t *ret);

static uint64_t	_dwarf_decode_uleb128(uint8_t **dp);
static int64_t	_dwarf_decode_sleb128(uint8_t **dp);
static int	_dwarf_frame_convert_inst(uint8_t addr_size,
		    struct eh_record_info* info,
		    struct eh_cfa_state *rules,
		    uint32_t *count);
static uint64_t	_dwarf_decode_lsb(uint8_t **data, int bytes_to_read);

static int
ehFindFDE(const struct ehframehdr_item	*table, int count, int32_t key, uint32_t *ret)
{
	const int			 end = count - 1;
	int				 left, right, temp;

	//index of last item in table
	right = end;
	left = 0;

	// simple cases
	if ((end == 0) && (table[0].rel_ip <= key))
	{
		temp = 0;
		goto success;
	}

	if (end <= 0)
		return (-1);

	do {
		temp = (left + right) >> 1;

		// small region - check both
		if (right - left == 1) {
			if ((table[left].rel_ip <= key) && (table[right].rel_ip > key)) {
				temp = left;
				goto success;
			}

			if ((table[right].rel_ip <= key) && (right < end) && (table[right + 1].rel_ip > key)) {
				temp = right;
				goto success;
			}

			return (-1);
		}

		if (temp == left)
			temp = left + 1;
		else if (temp == right)
			temp = right - 1;



		// edge cases - success
		if (((temp == end) && (table[temp].rel_ip < key)) ||
		    ((temp == 0) && (table[1].rel_ip > key)))
		{
			goto success;
		}

		// edge cases - fail
		if ((temp == end) || (temp == 0))
			return (-1);

		// successful
		if (table[temp].rel_ip <= key) {
			if (table[temp + 1].rel_ip > key)
				goto success;
			left = temp;
		} else {
			right = temp;
		}
	} while(1);

success:
	if (ehLogging & EH_PRINT_FDE)
		printf("ehFindFDE cnt: %d, key: %d, index: %d, found_key:%d, value: %x\n",count, key, temp, table[temp].rel_ip, table[temp].offset);
	*ret = table[temp].offset;

	return (0);
}

int
ehLookupFrame(const struct ehframehdr *ehframehdr, const char* dataAddress,
    struct eh_cfa_state	*rules)
{
	const struct eh_record	*fde, *cie;
	struct eh_cie_info	*cie_info;
	struct eh_fde_info	*fde_info;
	uint32_t		 fde_offset, cnt;
	uint8_t			*tmp;
	int			 err;

	if (ehframehdr == NULL)
		return (-1);

	if (ehFindFDE(&(ehframehdr->base), ehframehdr->n_fdecnt,
	    rules->eh_rel_ip, &fde_offset) != 0)
		return (-1);

	cie_info = malloc(sizeof(struct eh_cie_info));
	fde_info = malloc(sizeof(struct eh_fde_info));

	if(cie_info == NULL || fde_info == NULL)
		goto clean;

	fde = ((void*)ehframehdr + fde_offset);
	cie = (void*) &(fde->common.cie_offset) - fde->common.cie_offset;

	// Unsupported very long FDE. Probably impossible case
	if (fde->common.len == 0xFFFFFFFF)
		goto clean;

	fde_info->common.base = ((void*)ehframehdr + fde_offset);
	fde_info->common.len = fde->common.len + sizeof(fde->common.len);
	fde_info->common.instr = ((void*)&(fde->fields.fde_specific.augmentation_len)) +
	    sizeof(fde->fields.fde_specific.augmentation_len) +
	    fde->fields.fde_specific.augmentation_len;
	    //fde_info->common.base +
	    //sizeof(struct eh_record_common) + sizeof(struct eh_record_fde) +
	    //fde->fields.fde_specific.augmentation_len;

	fde_info->common.instr_len = fde_info->common.len -
	    (fde_info->common.instr - fde_info->common.base);

	fde_info->pc_begin = (uint32_t)( (void*)&(fde->fields.fde_specific.pc_begin) -
	    (void*)dataAddress) + fde->fields.fde_specific.pc_begin;
	fde_info->pc_range = fde->fields.fde_specific.pc_range;

	cie_info->common.base = (uint8_t *)cie;
	cie_info->common.len = cie->common.len + sizeof(cie->common.len);
	// plus one byte on version
	cie_info->augmentation = (char *)cie_info->common.base +
	    sizeof(struct eh_record_common) + sizeof(uint8_t);

	//Unsupported case
	if(strcmp(cie_info->augmentation, "zR") != 0){
		warnx("cie_info: %s", cie_info->augmentation);
		goto clean;
	}
	tmp = (uint8_t*)cie_info->augmentation + strlen(cie_info->augmentation) + 1;
	cie_info->code_aligment = _dwarf_decode_uleb128(&tmp);
	cie_info->data_aligment = _dwarf_decode_sleb128(&tmp);
	cie_info->register_ra = *tmp++;
	cie_info->common.instr = tmp + *tmp + sizeof(uint8_t);
	cie_info->common.instr_len = cie_info->common.len -
	    (cie_info->common.instr - cie_info->common.base);

	if (ehLogging & EH_PRINT_FDE)
		printf("FDE(%p, %d): (0x%x-0x%x) CIE(%p, %d): ra = %x\n",
		    fde_info->common.base, fde_info->common.len, fde_info->pc_begin,
		    fde_info->pc_begin + fde_info->pc_range, cie_info->common.base,
		    cie_info->common.len, cie_info->register_ra);

	rules->current_ip = fde_info->pc_begin;
	rules->code_aligment = cie_info->code_aligment;
	rules->data_aligment = cie_info->data_aligment;
	rules->fde_offset = fde_offset;

	if(fde->fields.fde_specific.augmentation_len == 0) {
		err = _dwarf_frame_convert_inst(8, &(cie_info->common), rules, &cnt);
		if (ehLogging & EH_PRINT_FDE)
			printf("err: %d, cnt: %u\n", err, cnt);
		// hackish code: I dunno why, but FDE requires shift of IP and SP
		rules->current_ip++;
		rules->cfaoffset -= rules->data_aligment;
		err = _dwarf_frame_convert_inst(8, &(fde_info->common), rules, &cnt);
		if (ehLogging & EH_PRINT_FDE)
			printf("err: %d, cnt: %u\n", err, cnt);

		if ((ehLogging & EH_PRINT_RULES) != 0)
			ehPrintRules(rules);
	}

	return (0);
clean:
	if(cie_info != NULL)
		free(cie_info);
	if(fde_info != NULL)
		free(fde_info);

	return (-1);
}

void
ehPrintRules(struct eh_cfa_state *rules)
{

	if (rules == NULL)
		return;

	printf("	0x%x: code aligned on %lu, data aligned on %ld\n", rules->target_ip, rules->code_aligment, rules->data_aligment);
	printf("	CFA: reg<%d> off<%d>\n", rules->cfareg, rules->cfaoffset );
	for (int i = 0; i < REGCNT; i++)
		if(rules->reg[i] != 0)
			printf("	REG[%d]: off<%d>\n", i, rules->reg[i]);
}


int32_t
ehGetRelativeIP(Elf_Addr ip, struct ElfObject *obj)
{

	return (ip - obj->baseAddr - ((void*)obj->ehframeHeader - (void*)obj->fileData));
}

/*
 * Passing of DWARF bytecode
 * Taken from libdwarf to avoid full parsing of debug segments and adapted.
 */

typedef struct {
	uint8_t		 fp_base_op;
	uint8_t		 fp_extended_op;
	uint16_t	 fp_register;
	uint64_t	 fp_offset_or_block_len;
	//uint8_t		*fp_expr_block;
	uint64_t	 fp_instr_offset;
} Dwarf_Frame_Op3;

static int
_dwarf_frame_convert_inst(uint8_t addr_size,
    struct eh_record_info* info,
    struct eh_cfa_state	*rules,
    uint32_t *count)
{
	uint8_t 		*p, *pe;
	uint8_t 		 high2, low6;
	uint64_t 		 reg, reg2, uoff, soff, blen;

#define	PRINTF(x, ...)					\
	do {						\
		if (ehLogging & EH_PRINT_BYTECODE)	\
			printf(x, ## __VA_ARGS__ );	\
	} while (0);

	*count = 0;

	p = info->instr;
	pe = p + info->instr_len;

	while (p < pe && rules->current_ip <= rules->target_ip) {
		if (*p == DW_CFA_nop) {
			p++;
			PRINTF("	DW_CFA_nop\n");
			(*count)++;
			continue;
		}

		high2 = *p & 0xc0;
		low6 = *p & 0x3f;
		p++;

		if (high2 > 0) {
			switch (high2) {
			case DW_CFA_advance_loc:
//				SET_BASE_OP(high2);
//				SET_OFFSET(low6);
				rules->current_ip += low6 * rules->code_aligment;
				PRINTF("	DW_CFA_advance_loc offset<%x>\n",low6);
				break;
			case DW_CFA_offset:
//				SET_BASE_OP(high2);
//				SET_REGISTER(low6);
				uoff = _dwarf_decode_uleb128(&p);
//				SET_OFFSET(uoff);
				rules->reg[low6] = uoff * rules->data_aligment;
				PRINTF("	DW_CFA_offset reg<%x> offset<%lx>\n",low6, uoff);
				break;
			case DW_CFA_restore:
//				SET_BASE_OP(high2);
//				SET_REGISTER(low6);
				//rules->reg[low6] = 0;
				// TODO: how to mark unused/restored values? bitmask?
				warnx("UNIMPLEMENTED: DW_CFA_restore reg<%x>",low6);
				break;
			default:
				return (-1);
			}

			(*count)++;
			continue;
		}

//		SET_EXTENDED_OP(low6);
//
		switch (low6) {
		case DW_CFA_set_loc:
			uoff = _dwarf_decode_lsb(&p, addr_size);
//			SET_OFFSET(uoff);
			rules->current_ip = uoff;
			PRINTF("	DW_CFA_set_loc uoff<%lx>\n",uoff);
			break;
		case DW_CFA_advance_loc1:
			uoff = _dwarf_decode_lsb(&p, 1);
//			SET_OFFSET(uoff);
			rules->current_ip += uoff * rules->code_aligment;
			PRINTF("	DW_CFA_advance_loc1 uoff<%lx>\n",uoff);
			break;
		case DW_CFA_advance_loc2:
			uoff = _dwarf_decode_lsb(&p, 2);
//			SET_OFFSET(uoff);
			rules->current_ip += uoff * rules->code_aligment;
			PRINTF("	DW_CFA_advance_loc2 uoff<%lx>\n",uoff);
			break;
		case DW_CFA_advance_loc4:
			uoff = _dwarf_decode_lsb(&p, 4);
//			SET_OFFSET(uoff);
			rules->current_ip += uoff * rules->code_aligment;
			PRINTF("	DW_CFA_advance_loc4 uoff<%lx>\n",uoff);
			break;
		case DW_CFA_offset_extended:
			reg = _dwarf_decode_uleb128(&p);
			uoff = _dwarf_decode_uleb128(&p);
			rules->reg[reg] = uoff * rules->data_aligment;
			PRINTF("	DW_CFA_offset_extended reg<%lx> uoff<%lx>\n",reg, uoff);
			break;
		case DW_CFA_def_cfa:
			reg = _dwarf_decode_uleb128(&p);
			uoff = _dwarf_decode_uleb128(&p);
			rules->cfareg = reg;
			rules->cfaoffset = uoff;
			PRINTF("	DW_CFA_def_cfa reg<%lx> uoff<%lx>\n",reg, uoff);
			break;
		case DW_CFA_val_offset:
			reg = _dwarf_decode_uleb128(&p);
			uoff = _dwarf_decode_uleb128(&p);
//			SET_REGISTER(reg);
//			SET_OFFSET(uoff);
			rules->reg[reg] = uoff * rules->data_aligment; // TODO: mark VAL_OFFSET
			PRINTF("	DW_CFA_val_offset reg<%lx> uoff<%lx>\n",reg, uoff);
			break;
		case DW_CFA_restore_extended:
			reg = _dwarf_decode_uleb128(&p);
//			SET_REGISTER(reg);
			//add implementation
			warnx("	UNIMPLEMENTED: DW_CFA_restore_extended reg<%lx>",reg);
			break;
		case DW_CFA_undefined:
			reg = _dwarf_decode_uleb128(&p);
//			SET_REGISTER(reg);
			//add implementation
			warnx("	UNIMPLEMENTED: DW_CFA_undefined reg<%lx>",reg);
			break;
		case DW_CFA_same_value:
			reg = _dwarf_decode_uleb128(&p);
//			SET_REGISTER(reg);
			//add implementation
			warnx("	UNIMPLEMENTED: DW_CFA_same_value reg<%lx>",reg);
			break;
		case DW_CFA_def_cfa_register:
			reg = _dwarf_decode_uleb128(&p);
//			SET_REGISTER(reg);
			rules->cfareg = reg;
			PRINTF("	DW_CFA_def_cfa_register reg<%lx>\n",reg);
			break;
		case DW_CFA_register:
			reg = _dwarf_decode_uleb128(&p);
			reg2 = _dwarf_decode_uleb128(&p);
//			SET_REGISTER(reg);
//			SET_OFFSET(reg2);
			//add implementation
			warnx("UNIMPLEMENTED: DW_CFA_register reg<%lx> reg2<%lx>\n",reg, reg2);
			break;
		case DW_CFA_remember_state:
			warnx("UNIMPLEMENTED: DW_CFA_remember_state\n");
			break;
			//add implementation
		case DW_CFA_restore_state:
			warnx("UNIMPLEMENTED: DW_CFA_restore_state\n");
			break;
			//add implementation
		case DW_CFA_def_cfa_offset:
			uoff = _dwarf_decode_uleb128(&p);
//			SET_OFFSET(uoff);
			rules->cfaoffset = uoff;
			PRINTF("	DW_CFA_def_cfa_offset uoff<%lx>\n",uoff);
			break;
		case DW_CFA_def_cfa_expression:
			blen = _dwarf_decode_uleb128(&p);
//			SET_BLOCK_LEN(blen);
			//add implementation
			warnx("UNIMPLEMENTED: DW_CFA_def_cfa_expression blen<%lx>\n",blen);
			//SET_EXPR_BLOCK(p, blen);
			p += blen;
			break;
		case DW_CFA_expression:
		case DW_CFA_val_expression:
			reg = _dwarf_decode_uleb128(&p);
			blen = _dwarf_decode_uleb128(&p);
//			SET_REGISTER(reg);
//			SET_BLOCK_LEN(blen);
			//SET_EXPR_BLOCK(p, blen);
			//add implementation
			warnx("UNIMPLEMENTED: DW_CFA_expression/DW_CFA_val_expression reg<%lx> blen<%lx>\n",reg, blen);
			p += blen;
			break;
		case DW_CFA_offset_extended_sf:
			reg = _dwarf_decode_uleb128(&p);
			soff = _dwarf_decode_sleb128(&p);
			PRINTF("	DW_CFA_offset_extended_sf reg<%lx> soff<%lx>\n",reg, soff);
			rules->reg[reg] = soff * rules->data_aligment;
			break;
		case DW_CFA_def_cfa_sf:
			reg = _dwarf_decode_uleb128(&p);
			soff = _dwarf_decode_sleb128(&p);
			PRINTF("	DW_CFA_def_cfa_sf reg<%lx> soff<%lx>\n", reg, soff);
			rules->cfareg = reg;
			rules->cfaoffset = soff * rules->data_aligment;
			break;
		case DW_CFA_val_offset_sf:
			reg = _dwarf_decode_uleb128(&p);
			soff = _dwarf_decode_sleb128(&p);
			PRINTF("	DW_CFA_val_offset_sf reg<%lx> soff<%lx>\n", reg, soff);
			rules->reg[reg] = soff * rules->data_aligment; //TODO: mark VAL_OFFSET
			break;
		case DW_CFA_def_cfa_offset_sf:
			soff = _dwarf_decode_sleb128(&p);
//			SET_OFFSET(soff);
			rules->cfaoffset = soff * rules->data_aligment;
			PRINTF("	DW_CFA_def_cfa_offset_sf soff<%lx>\n",soff);
			break;
		default:
			return (-1);
		}

		(*count)++;
	}

	return (0);
}

static int64_t
_dwarf_decode_sleb128(uint8_t **dp)
{
	int64_t ret = 0;
	uint8_t b;
	int shift = 0;

	uint8_t *src = *dp;

	do {
		b = *src++;
		ret |= ((b & 0x7f) << shift);
		shift += 7;
	} while ((b & 0x80) != 0);

	if (shift < 64 && (b & 0x40) != 0)
		ret |= (-1 << shift);

	*dp = src;

	return (ret);
}

static uint64_t
_dwarf_decode_uleb128(uint8_t **dp)
{
	uint64_t ret = 0;
	uint8_t b;
	int shift = 0;

	uint8_t *src = *dp;

	do {
		b = *src++;
		ret |= ((b & 0x7f) << shift);
		shift += 7;
	} while ((b & 0x80) != 0);

	*dp = src;

	return (ret);
}

static uint64_t
_dwarf_decode_lsb(uint8_t **data, int bytes_to_read)
{
	uint64_t ret;
	uint8_t *src;

	src = *data;

	ret = 0;
	switch (bytes_to_read) {
	case 8:
		ret |= ((uint64_t) src[4]) << 32 | ((uint64_t) src[5]) << 40;
		ret |= ((uint64_t) src[6]) << 48 | ((uint64_t) src[7]) << 56;
		/* no break */
	case 4:
		ret |= ((uint64_t) src[2]) << 16 | ((uint64_t) src[3]) << 24;
		/* no break */
	case 2:
		ret |= ((uint64_t) src[1]) << 8;
		/* no break */
	case 1:
		ret |= src[0];
		break;
	default:
		return (0);
	}

	*data += bytes_to_read;

	return (ret);
}



