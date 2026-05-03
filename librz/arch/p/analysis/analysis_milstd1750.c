// SPDX-FileCopyrightText: 2026 godcodehunter
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_analysis.h>
#include <milstd1750/milstd1750_disas.h>

int rz_milstd1750_analysis_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask) {
	if (len < 2) {
		return -1;
	}

	int size = rz_milstd1750_op_size(data, len);
	if (size <= 0) {
		op->size = 2;
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		return -1;
	}

	op->addr = addr;
	op->size = size;
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;

	ut16 w1 = rz_read_be16(data);
	ut8 op8 = w1 >> 8;
	ut16 w2 = (size == 4) ? rz_read_be16(data + 2) : 0;

	// MIL-STD-1750A memory is word-addressed (1 unit = 16 bits) but rizin
	// uses byte addressing (bits=8), so all encoded addresses must be
	// multiplied by 2 to convert to byte addresses.
	st8 disp = (st8)(w1 & 0xFF);
	ut64 icr_target = addr + size + (st64)disp * 2;
	ut64 abs_target = (ut64)w2 * 2;

	switch (op8) {
	// Special
	case 0xFF:
		op->type = (w1 == 0xFFFF) ? RZ_ANALYSIS_OP_TYPE_TRAP : RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case 0x7F: // URS — unconditional return
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;

	// ICR conditional branches
	case 0x74: // BR (unconditional)
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = icr_target;
		break;
	case 0x75: // BEZ
	case 0x76: // BLT
	case 0x78: // BLE
	case 0x79: // BGT
	case 0x7A: // BNZ
	case 0x7B: // BGE
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = icr_target;
		op->fail = addr + size;
		break;

	// Memory-format jumps (4 bytes, absolute word-address target in w2)
	case 0x70: // JC
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = abs_target;
		op->fail = addr + size;
		break;
	case 0x71: // JCI (indirect)
		op->type = RZ_ANALYSIS_OP_TYPE_MCJMP;
		op->fail = addr + size;
		break;
	case 0x72: // JS — call
	case 0x7E: // SJS — call
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = abs_target;
		break;
	case 0x73: // SOJ — Subtract One and Jump
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = abs_target;
		op->fail = addr + size;
		break;
	case 0x77: // BEX — branch and exchange
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		break;
	case 0x4F: // BIF — branch on input flag
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->fail = addr + size;
		break;

	// IO
	case 0x48: // XIO
	case 0x49: // VIO
		op->type = RZ_ANALYSIS_OP_TYPE_IO;
		break;

	// Stack
	case 0x8F: // POPM
		op->type = RZ_ANALYSIS_OP_TYPE_POP;
		break;
	case 0x9F: // PSHM
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;

	// Move
	case 0x93: // MOV
	case 0xEC: // XBR
	case 0xED: // XWR
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;

	// Add
	case 0x10: // AB
	case 0xA0: // A
	case 0xA1: // AR
	case 0xA2: // AISP
	case 0xA3: // INCM
	case 0xA4: // ABS
	case 0xA6: // DA
	case 0xA7: // DAR
	case 0xA8: // FA
	case 0xA9: // FAR
	case 0xAA: // EFA
	case 0xAB: // EFAR
	case 0xAC: // FABS
	case 0xAD: // UAR
	case 0xAE: // UA
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;

	// Sub
	case 0x14: // SBB
	case 0xB0: // S
	case 0xB1: // SR
	case 0xB2: // SISP
	case 0xB3: // DECM
	case 0xB4: // NEG
	case 0xB5: // DNEG
	case 0xB6: // DS
	case 0xB7: // DSR
	case 0xB8: // FS
	case 0xB9: // FSR
	case 0xBA: // EFS
	case 0xBB: // EFSR
	case 0xBC: // FNEG
	case 0xBD: // USR
	case 0xBE: // US
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;

	// Mul
	case 0x18: // MB
	case 0xC0: // MS
	case 0xC1: // MSR
	case 0xC2: // MISP
	case 0xC3: // MISN
	case 0xC4: // M
	case 0xC5: // MR
	case 0xC6: // DM
	case 0xC7: // DMR
	case 0xC8: // FM
	case 0xC9: // FMR
	case 0xCA: // EFM
	case 0xCB: // EFMR
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;

	// Div
	case 0x1C: // DB
	case 0xD0: // DV
	case 0xD1: // DVR
	case 0xD2: // DISP
	case 0xD3: // DISN
	case 0xD4: // D
	case 0xD5: // DR
	case 0xD6: // DD
	case 0xD7: // DDR
	case 0xD8: // FD
	case 0xD9: // FDR
	case 0xDA: // EFD
	case 0xDB: // EFDR
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;

	// AND
	case 0x34: // ANDB
	case 0xE2: // AND
	case 0xE3: // ANDR
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;

	// OR
	case 0x30: // ORB
	case 0xE0: // OR
	case 0xE1: // ORR
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;

	// XOR
	case 0xE4: // XOR
	case 0xE5: // XORR
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;

	// NAND/N
	case 0xE6: // N
	case 0xE7: // NR
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		break;

	// Shifts left
	case 0x60: // SLL
	case 0x63: // SLC
	case 0x65: // DSLL
	case 0x68: // DSLC
	case 0x6A: // SLR
	case 0x6D: // DSLR
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;

	// Shifts right
	case 0x61: // SRL
	case 0x62: // SRA
	case 0x66: // DSRL
	case 0x67: // DSRA
	case 0x6B: // SAR
	case 0x6C: // SCR
	case 0x6E: // DSAR
	case 0x6F: // DSCR
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;

	// Compare
	case 0x38: // CB
	case 0xF0: // C
	case 0xF1: // CR
	case 0xF2: // CISP
	case 0xF3: // CISN
	case 0xF4: // CBL
	case 0xF6: // DC
	case 0xF7: // DCR
	case 0xF8: // FC
	case 0xF9: // FCR
	case 0xFA: // EFC
	case 0xFB: // EFCR
	case 0xFC: // UCR
	case 0xFD: // UC
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;

	// Loads
	case 0x00: // LB
	case 0x04: // DLB
	case 0x7C: // LSTI
	case 0x7D: // LST
	case 0x80: // L
	case 0x81: // LR
	case 0x82: // LISP
	case 0x83: // LISN
	case 0x84: // LI
	case 0x85: // LIM
	case 0x86: // DL
	case 0x87: // DLR
	case 0x88: // DLI
	case 0x89: // LM
	case 0x8A: // EFL
	case 0x8B: // LUB
	case 0x8C: // LLB
	case 0x8D: // LUBI
	case 0x8E: // LLBI
	case 0xDE: // LE
	case 0xDF: // DLE
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;

	// Stores
	case 0x08: // STB
	case 0x0C: // DSTB
	case 0x90: // ST
	case 0x91: // STC
	case 0x92: // STCI
	case 0x94: // STI
	case 0x95: // SFBS
	case 0x96: // DST
	case 0x97: // SRM
	case 0x98: // DSTI
	case 0x99: // STM
	case 0x9A: // EFST
	case 0x9B: // STUB
	case 0x9C: // STLB
	case 0x9D: // SUBI
	case 0x9E: // SLBI
	case 0xDC: // STE
	case 0xDD: // DSTE
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;

	// Bit set/reset/test
	case 0x50: // SB
	case 0x51: // SBR
	case 0x52: // SBI
	case 0x59: // TSB
	case 0x5A: // SVBR
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case 0x53: // RB
	case 0x54: // RBR
	case 0x55: // RBI
	case 0x5C: // RVBR
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case 0x56: // TB
	case 0x57: // TBR
	case 0x58: // TBI
	case 0x5E: // TVBR
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	}

	return op->size;
}

RzAnalysisPlugin rz_analysis_plugin_milstd1750 = {
	.name = "milstd1750",
	.desc = "MIL-STD 1750 ISA analysis plugin",
	.license = "MIT",
	.arch = "milstd1750",
	.bits = 16,
	.op = &rz_milstd1750_analysis_op,
	.esil = false
};
