// SPDX-FileCopyrightText: 2025 godcodehunter
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file Disassembler for the MIL-STD-1750A instruction set architecture.
 *
 * MIL-STD-1750A is a 16-bit military standard ISA originally developed by
 * the US Department of Defense for airborne embedded computers. It features
 * 16 general-purpose registers (R0-R15), 16-bit word-addressable memory,
 * and a mix of one-word (16-bit) and two-word (32-bit) instructions.
 *
 * References:
 * - MIL-STD-1750A Military Standard Sixteen-Bit Computer Instruction Set Architecture
 * - UT1750AR RadHard RISC Microprocessor data sheet
 * - https://github.com/okellogg/milstd1750tools/blob/master/as1750/as1750.c#L947
 * - https://github.com/EtchedPixels/sim1750a
 * - https://github.com/WarlockD/Mil-std-1750A-Emulator-C20/tree/master/instructions
 */

#include "milstd1750_disas.h"
#include <rz_types.h>

typedef char *(*WHandle)(ut16 w1);
typedef char *(*TwoWHandle)(ut32 w2);

typedef enum {
	OneWord = 1,
	TwoWord = 2,
} WSize;

typedef struct {
	ut16 opcode;
	const char *mnemonic;
	void *handler;
} MilStd1750LongInstruction;

typedef struct {
	ut16 opcode;
	const char *mnemonic;
} MilStd1750XioCommand;

static const MilStd1750XioCommand milstd1750_xio_commands[] = {
	{ 0x2000, "SMK" },
	{ 0x2001, "CLIR" },
	{ 0x2002, "ENBL" },
	{ 0x2003, "DSBL" },
	{ 0x2004, "RPI" },
	{ 0x2005, "SPI" },
	{ 0x200E, "WSW" },
	{ 0xA000, "RMK" },
	{ 0xA004, "RPIR" },
	{ 0xA00E, "RSW" },
	{ 0xA00F, "RCFR" },
	{ 0x2008, "OD" },
	{ 0x200A, "RNS" },
	{ 0x4000, "CO" },
	{ 0x4001, "CLC" },
	{ 0x4003, "MPEN" },
	{ 0x4004, "ESUR" },
	{ 0x4005, "DSUR" },
	{ 0x4006, "DMAE" },
	{ 0x4007, "DMAD" },
	{ 0x4008, "TAS" },
	{ 0x4009, "TAH" },
	{ 0x400A, "OTA" },
	{ 0x400B, "GO" },
	{ 0x400C, "TBS" },
	{ 0x400D, "TBH" },
	{ 0x400E, "OTB" },
	{ 0xA001, "RIC1" },
	{ 0xA002, "RIC2" },
	{ 0xA008, "RDOR" },
	{ 0xA009, "RDI" },
	{ 0xA00B, "TPIO" },
	{ 0xA00D, "RMFS" },
	{ 0xC000, "CI" },
	{ 0xC001, "RCS" },
	{ 0xC00A, "ITA" },
	{ 0xC00E, "ITB" },
};

static char *parse_xio_commands(ut16 cmd) {
	// Parse "PO"
	if ((cmd >> 12) == 0x0) {
		ut8 Y = (cmd >> 8) & 0x0F;
		ut8 X = cmd & 0xFF;

		return rz_str_newf("PO { %d, %d }", Y, X);
	}

	// Parse "PI"
	if ((cmd >> 12) == 0x8) {
		ut8 Y = (cmd >> 8) & 0x0F;
		ut8 X = cmd & 0xFF;

		return rz_str_newf("PI { %d, %d }", Y, X);
	}

	// Parse "LMP"
	if ((cmd >> 8) == 0x50) {
		ut8 X = cmd & 0xFF;

		return rz_str_newf("LMP { %d }", X);
	}

	// Parse "WIPR"
	if ((cmd >> 8) == 0x51) {
		ut8 X = (cmd & 0xFF) >> 4;
		ut8 Y = cmd & 0x0F;

		return rz_str_newf("WIPR { %d, %d }", X, Y);
	}

	// Parse "WOPR"
	if ((cmd >> 8) == 0x52) {
		ut8 X = (cmd & 0xFF) >> 4;
		ut8 Y = cmd & 0x0F;

		return rz_str_newf("WOPR { %d, %d }", X, Y);
	}

	// Parse "RMP"
	if ((cmd >> 8) == 0xD0) {
		ut8 X = cmd & 0xFF;

		return rz_str_newf("RMP { %d }", X);
	}

	// Parse "RIPR"
	if ((cmd >> 8) == 0xD1) {
		ut8 X = (cmd & 0xFF) >> 4;
		ut8 Y = cmd & 0x0F;

		return rz_str_newf("RIPR { %d, %d }", X, Y);
	}

	// Parse "ROPR"
	if ((cmd >> 8) == 0xD2) {
		ut8 X = (cmd & 0xFF) >> 4;
		ut8 Y = cmd & 0x0F;

		return rz_str_newf("ROPR { %d, %d }", X, Y);
	}

	for (size_t i = 0; i < RZ_ARRAY_SIZE(milstd1750_xio_commands); ++i) {
		if (milstd1750_xio_commands[i].opcode == cmd) {
			return rz_str_dup(milstd1750_xio_commands[i].mnemonic);
		}
	}

	return rz_str_newf("0x%04x", cmd);
}

// XIO: [8-bit op | 4-bit RA | 4-bit RX | 16-bit cmd]
static char *as_xio(ut32 full) {
	ut8 RA = (full >> 20) & 0xF;
	ut8 RX = (full >> 16) & 0xF;
	ut16 cmd = full & 0xFFFF;

	char *cmd_str = parse_xio_commands(cmd);
	if (!cmd_str) {
		return NULL;
	}

	char *result;
	if (RX != 0) {
		result = rz_str_newf("r%d, r%d, %s", RA, RX, cmd_str);
	} else {
		result = rz_str_newf("r%d, %s", RA, cmd_str);
	}
	free(cmd_str);
	return result;
}

// Long Direct: [8-bit op | 4-bit RA | 4-bit RX | 16-bit addr]
static char *as_mem(ut32 full) {
	ut8 RA = (full >> 20) & 0xF;
	ut8 RX = (full >> 16) & 0xF;
	ut16 ADDR = full & 0xFFFF;

	if (RX) {
		return rz_str_newf("r%d, 0x%04x, r%d", RA, ADDR, RX);
	}

	return rz_str_newf("r%d, 0x%04x", RA, ADDR);
}

// Immediate:  [8-bit op | 4-bit RA | 4-bit opex | 16-bit imm]
static char *as_im_ocx(ut32 full) {
	ut8 RA = (full >> 20) & 0xF;
	ut16 DATA = full & 0xFFFF;

	return rz_str_newf("r%d, 0x%04x", RA, DATA);
}

// Register-to-Register:  [8-bit op | 4-bit RA | 4-bit RB]
static char *as_r(ut16 full) {
	ut8 RA = (full >> 4) & 0xF;
	ut8 RB = full & 0xF;

	return rz_str_newf("r%d, r%d", RA, RB);
}

// Single Register:  [8-bit op | 4-bit RA | 0x0 ]
static char *as_sr(ut16 full) {
	ut8 RA = (full >> 4) & 0xF;

	return rz_str_newf("r%d", RA);
}

// Immediate 0-15: [8-bit op | 4-bit N imm | 4-bit RX | 16-bit addr]
static char *as_im_0_15(ut32 full) {
	ut8 N = (full >> 20) & 0xF;
	ut8 RX = (full >> 16) & 0xF;
	ut16 ADDR = full & 0xFFFF;

	return rz_str_newf("%d, 0x%04x, r%d", N, ADDR, RX);
}

// Immediate & Register: [8-bit op | 4-bit N imm | 4-bit RB]
static char *as_imm_r(ut16 full) {
	ut8 N = (full >> 4) & 0xF;
	ut8 RB = full & 0xF;

	return rz_str_newf("%d, r%d", N, RB);
}

// Base Rel Indexed: [6-bit op | 2-bit BR | 4-bit opex | 4-bit RX]
static char *as_bx(ut16 full) {
	ut8 BR = (full >> 8) & 0x3;
	ut8 RX = full & 0xF;

	BR += 12;

	return rz_str_newf("r%d, r%d", BR, RX);
}

// Base Relative: [6-bit op | 2-bit BR | 8-bit disp]
static char *as_b(ut16 full) {
	ut8 BR = (full >> 8) & 0x3;
	ut8 DISP = full & 0xFF;

	BR += 12;

	return rz_str_newf("r%d, %d", BR, DISP);
}

// Immediate Register: [8-bit op | 4-bit N-1 imm | 4-bit RB]
static char *as_r_imm(ut16 full) {
	ut8 RB = full & 0xF;
	ut8 N = (full >> 4) & 0xF;

	N++;

	return rz_str_newf("r%d, %d", RB, N);
}

// Immediate Short: [8-bit op | 4-bit RA | 4-bit (N-1) imm]
static char *as_is(ut16 full) {
	ut8 RA = (full >> 4) & 0xF;
	ut8 N = full & 0xF;

	N++;

	return rz_str_newf("r%d, %d", RA, N);
}

// Short None: [8-bit op | 0x00 ]
static char *as_none(ut16 full) {
	return rz_str_dup("");
}

// Direct Address: [8-bit op | 0x0 | 4-bit RX | 16-bit addr]
static char *as_addr(ut32 full) {
	ut8 RX = (full >> 16) & 0xF;
	ut16 ADDR = full & 0xFFFF;

	return rz_str_newf("0x%04x, r%d", ADDR, RX);
}

// Immediate 0-15: [8-bit op | 4-bit N-1 imm | 4-bit RX | 16-bit addr]
static char *as_im_1_16(ut32 full) {
	ut8 N = (full >> 20) & 0xF;
	ut8 RX = (full >> 16) & 0xF;
	ut16 ADDR = full & 0xFFFF;

	return rz_str_newf("%d, 0x%04x, r%d", N, ADDR, RX);
}

// Instruction Counter Relative: [8-bit op | 8-bit addr]
static char *as_icr(ut16 full) {
	ut8 ADDR = full & 0xFF;

	return rz_str_newf("0x%04x", ADDR);
}

// Special: [8-bit op | 8-bit special]
static char *as_s(ut16 full) {
	ut8 OC = full >> 8;

	switch (OC) {
	case 0x77: { // "BEX"
		ut8 N = full & 0xF;
		return rz_str_newf("%d", N);
	}
	case 0x4F: { // "BIF"
		ut8 OE = full & 0xFF;
		return rz_str_newf("0x%02x", OE);
	}
	default:
		rz_warn_if_reached();
		return rz_str_dup("invalid");
	}
}

// Jump on Condition: [8-bit op | 4-bit C | 4-bit RX | 16-bit addr]
static char *as_jump(ut32 full) {
	ut8 C = (full >> 20) & 0xF;
	ut8 RX = (full >> 16) & 0xF;
	ut16 ADDR = full & 0xFFFF;

	return rz_str_newf("0x%x, 0x%04x, r%d", C, ADDR, RX);
}

static WSize accepted_word_size(void *ptr) {
	void *tword_size_acceptor[] = {
		as_xio,
		as_mem,
		as_im_ocx,
		as_im_0_15,
		as_addr,
		as_im_1_16,
		as_jump,
	};
	// Exclusion, one word size:
	// - as_r
	// - as_sr
	// - as_imm_r
	// - as_bx
	// - as_b
	// - as_r_imm
	// - as_is
	// - as_none
	// - as_icr
	// - as_s

	for (size_t i = 0; i < RZ_ARRAY_SIZE(tword_size_acceptor); ++i) {
		if (tword_size_acceptor[i] == ptr) {
			return TwoWord;
		}
	}

	return OneWord;
}

/**
 * \note Some instructions are mentioned but not FULL defined:
 * BRX, CALL, CISP, CISM, CIM, CLC, CMP, CR, DMAD, DMAE,
 * DSUR, EFLX, FB, FBX, FL, FLX, GO, IMM, IMML, INR, ITA,
 * ITB, LBI, LMP, LRI, MOVC, MOVB, MPEN, MULS, OD, OTA,
 * OTB, OTR, POP, PUSH, SL, SM, SMK, SPI, STA, STR, STRI,
 * SUB, SUBB, SWAB, TA
 */
// clang-format off
static const MilStd1750LongInstruction milstd1750_inst_tab[] = {
	{ 0x4040, "ABX", as_bx, },
	{ 0x40E0, "ANDX", as_bx, },
	{ 0xA000, "A", as_mem, },
	{ 0xA400, "ABS", as_r, },
	{ 0x4A01, "AIM", as_im_ocx, },
	{ 0xA200, "AISP", as_is, },
	{ 0xE200, "AND", as_mem, },
	{ 0x3400, "ANDB", as_b, },
	{ 0x4A07, "ANDM", as_im_ocx, },
	{ 0xE300, "ANDR", as_r, },
	{ 0xA100, "AR", as_r, },
	{ 0x1000, "AB", as_b, },
	{ 0x7700, "BEX", as_s, },
	{ 0x7500, "BEZ", as_icr, },
	{ 0x7B00, "BGE", as_icr, },
	{ 0x7900, "BGT", as_icr, },
	{ 0x4F00, "BIF", as_s, },
	{ 0x7800, "BLE", as_icr, },
	{ 0x7600, "BLT", as_icr, },
	{ 0x7A00, "BNZ", as_icr, },
	{ 0xFFFF, "BPT", as_none, },
	{ 0x7400, "BR", as_icr, },
	{ 0xF000, "C", as_mem, },
	{ 0x3800, "CB", as_b, },
	{ 0xF400, "CBL", as_mem, },
	{ 0x40C0, "CBX", as_bx, },
	{ 0xF300, "CISN", as_is, },
	{ 0xD700, "DDR", as_r, },
	{ 0xD600, "DD", as_mem, },
	{ 0xD400, "D", as_mem, },
	{ 0xA600, "DA", as_mem, },
	{ 0xA500, "DABS", as_r, },
	{ 0xA700, "DAR", as_r, },
	{ 0x1C00, "DB", as_b, },
	{ 0xF600, "DC", as_mem, },
	{ 0xF700, "DCR", as_r, },
	{ 0xB300, "DECM", as_im_1_16, },
	{ 0x4A05, "DIM", as_im_ocx, },
	{ 0xD300, "DISN", as_is, },
	{ 0xD200, "DISP", as_is, },
	{ 0x8600, "DL", as_mem, },
	{ 0x0400, "DLB", as_b, },
	{ 0x4010, "DLBX", as_bx, },
	{ 0xDF00, "DLE", as_mem, },
	{ 0x8800, "DLI", as_mem, },
	{ 0x8700, "DLR", as_r, },
	{ 0xC600, "DM", as_mem, },
	{ 0xC700, "DMR", as_r, },
	{ 0xB500, "DNEG", as_r, },
	{ 0xD500, "DR", as_r, },
	{ 0xB600, "DS", as_mem, },
	{ 0x6E00, "DSAR", as_r, },
	{ 0x6F00, "DSCR", as_r, },
	{ 0x6500, "DSLL", as_r_imm, },
	{ 0x6800, "DSLC", as_r_imm, },
	{ 0x6D00, "DSLR", as_r, },
	{ 0x6700, "DSRA", as_r_imm, },
	{ 0x6600, "DSRL", as_r_imm, },
	{ 0xB700, "DSR", as_r, },
	{ 0x9600, "DST", as_mem, },
	{ 0x0C00, "DSTB", as_b, },
	{ 0x9800, "DSTI", as_mem, },
	{ 0xDD00, "DSTE", as_mem, },
	{ 0x4030, "DSTX", as_bx, },
	{ 0xD000, "DV", as_mem, },
	{ 0x4A06, "DVIM", as_im_ocx, },
	{ 0xD100, "DVR", as_r, },
	{ 0x4070, "DBX", as_bx, },
	{ 0xEB00, "EFLT", as_r, },
	{ 0xEA00, "EFIX", as_r, },
	{ 0xFA00, "EFC", as_mem, },
	{ 0xFB00, "EFCR", as_r, },
	{ 0xAA00, "EFA", as_mem, },
	{ 0xAB00, "EFAR", as_r, },
	{ 0xDA00, "EFD", as_mem, },
	{ 0xDB00, "EFDR", as_r, },
	{ 0x8A00, "EFL", as_mem, },
	{ 0xCA00, "EFM", as_mem, },
	{ 0xCB00, "EFMR", as_r, },
	{ 0xBA00, "EFS", as_mem, },
	{ 0xBB00, "EFSR", as_r, },
	{ 0x9A00, "EFST", as_mem, },
	{ 0xAC00, "FABS", as_r, },
	{ 0xA800, "FA", as_mem, },
	{ 0x2000, "FAB",as_b, },
	{ 0x4080, "FABX", as_bx, },
	{ 0xA900, "FAR", as_r, },
	{ 0xF800, "FC", as_mem, },
	{ 0x3C00, "FCB", as_b, },
	{ 0x40D0, "FCBX", as_bx, },
	{ 0xF900, "FCR", as_r, },
	{ 0xD800, "FD", as_mem, },
	{ 0x2C00, "FDB", as_b, },
	{ 0x40B0, "FDBX", as_bx, },
	{ 0xD900, "FDR", as_r, },
	{ 0xE800, "FIX", as_r, },
	{ 0xE900, "FLT", as_r, },
	{ 0xC800, "FM", as_mem, },
	{ 0x2800, "FMB", as_b, },
	{ 0x40A0, "FMBX", as_bx, },
	{ 0xC900, "FMR", as_r, },
	{ 0xBC00, "FNEG", as_r, },
	{ 0xB800, "FS", as_mem, },
	{ 0x2400, "FSB", as_b, },
	{ 0x4090, "FSBX", as_bx, },
	{ 0xB900, "FSR", as_r, },
	{ 0xA300, "INCM", as_im_1_16, },
	{ 0x7000, "JC", as_jump, },
	{ 0x7100, "JCI", as_jump, },
	{ 0x7200, "JS", as_mem, },
	{ 0x8300, "LISN", as_is, },
	{ 0x8000, "L", as_mem, },
	{ 0x0000, "LB", as_b, },
	{ 0x4000, "LBX", as_bx, },
	{ 0xDE00, "LE", as_mem, },
	{ 0x8400, "LI", as_mem, },
	{ 0x8500, "LIM", as_mem, },
	{ 0x8200, "LISP", as_is, },
	{ 0x8C00, "LLB", as_mem, },
	{ 0x8E00, "LLBI", as_mem, },
	{ 0x8900, "LM", as_im_0_15, },
	{ 0x8100, "LR", as_r, },
	{ 0x7C00, "LSTI", as_addr, },
	{ 0x7D00, "LST", as_addr, },
	{ 0x8B00, "LUB", as_mem, },
	{ 0x8D00, "LUBI", as_mem,},
	{ 0xC500, "MR", as_r, },
	{ 0xC400, "M", as_mem, },
	{ 0x1800, "MB", as_b, },
	{ 0x4060, "MBX", as_bx, },
	{ 0xC300, "MISN", as_is, },
	{ 0xC200, "MISP", as_is, },
	{ 0x4A03, "MIM", as_im_ocx, },
	{ 0x9300, "MOV", as_r, },
	{ 0xC000, "MS", as_mem, },
	{ 0x4A04, "MSIM", as_im_ocx, },
	{ 0xC100, "MSR", as_r, },
	{ 0xE600, "N", as_mem, },
	{ 0xB400, "NEG", as_r, },
	{ 0x4A0B, "NIM", as_im_ocx, },
	{ 0xFF00, "NOP", as_none, },
	{ 0xE700, "NR", as_r, },
	{ 0xE000, "OR", as_mem, },
	{ 0x3000, "ORB", as_b, },
	{ 0x40F0, "ORBX", as_bx, },
	{ 0x4A08, "ORIM", as_im_ocx, },
	{ 0xE100, "ORR", as_r, },
	{ 0x8F00, "POPM", as_r, },
	{ 0x9F00, "PSHM", as_r, },
	{ 0x5300, "RB", as_im_0_15, },
	{ 0x5500, "RBI", as_im_0_15, },
	{ 0x5400, "RBR", as_imm_r, },
	{ 0x5C00, "RVBR", as_r, },
	{ 0x9E00, "SLBI", as_mem, },
	{ 0x4050, "SBBX", as_bx, },
	{ 0x4020, "STBX", as_bx, },
	{ 0x6C00, "SCR", as_r, },
	{ 0x6B00, "SAR", as_r, },
	{ 0xB000, "S", as_mem, },
	{ 0x5000, "SB", as_im_0_15, },
	{ 0x1400, "SBB", as_b, },
	{ 0x5100, "SBR", as_imm_r, },
	{ 0x5200, "SBI", as_im_0_15, },
	{ 0x9500, "SFBS", as_r, },
	{ 0x4A02, "SIM", as_im_ocx, },
	{ 0xB200, "SISP", as_is, },
	{ 0x7E00, "SJS", as_mem, },
	{ 0x6300, "SLC", as_r_imm, },
	{ 0x6000, "SLL", as_r_imm, },
	{ 0x6A00, "SLR", as_r, },
	{ 0x7300, "SOJ", as_mem, },
	{ 0xB100, "SR", as_r, },
	{ 0x6200, "SRA", as_r_imm, },
	{ 0x9700, "SRM", as_mem, },
	{ 0x6100, "SRL", as_r_imm, },
	{ 0x9000, "ST", as_mem, },
	{ 0x9100, "STC", as_im_0_15, },
	{ 0x9200, "STCI", as_im_0_15, },
	{ 0x9400, "STI", as_mem, },
	{ 0x0800, "STB", as_b, },
	{ 0x9C00, "STLB", as_mem, },
	{ 0x9900, "STM", as_im_0_15, },
	{ 0x9B00, "STUB", as_mem, },
	{ 0x9D00, "SUBI", as_mem, },
	{ 0x5A00, "SVBR", as_r, },
	{ 0x5600, "TB", as_im_0_15, },
	{ 0xDC00, "STE", as_mem, },
	{ 0x5700, "TBR", as_imm_r, },
	{ 0x5E00, "TVBR", as_r, },
	{ 0x5800, "TBI", as_im_0_15, },
	{ 0x5900, "TSB", as_im_0_15, },
	{ 0xAE00, "UA", as_mem, },
	{ 0xAD00, "UAR", as_r, },
	{ 0xFD00, "UC", as_mem, },
	{ 0xF500, "UCIM", as_im_ocx, },
	{ 0xFC00, "UCR", as_r, },
	{ 0x7F00, "URS", as_sr, },
	{ 0xBE00, "US", as_mem, },
	{ 0xBD00, "USR", as_r, },
	{ 0x4900, "VIO", as_mem, },
	{ 0xEC00, "XBR", as_r, },
	{ 0x4800, "XIO", as_xio, },
	{ 0xE400, "XOR", as_mem, },
	{ 0x4A09, "XORM", as_im_ocx, },
	{ 0xE500, "XORR", as_r, },
	{ 0xED00, "XWR", as_r, },
};
// clang-format on

int rz_milstd1750_disasm(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	if (len < 2) {
		return -1;
	}

	ut16 w1 = rz_read_be16(buf);

	// Each handler implies a specific opcode mask based on instruction format:
	//   as_bx      → 0xFCF0  (6-bit op + 4-bit opex, BX format)
	//   as_b       → 0xFC00  (6-bit op, B format)
	//   as_im_ocx  → 0xFF0F  (8-bit op + 4-bit opex, IM format)
	//   others     → 0xFF00  (8-bit op)
	// No cross-format collisions because opcode ranges are disjoint.

	for (size_t i = 0; i < RZ_ARRAY_SIZE(milstd1750_inst_tab); ++i) {
		void *handler = milstd1750_inst_tab[i].handler;
		ut16 mask;
		if (handler == as_none) {
			mask = 0xFFFF;
		} else if (handler == as_bx) {
			mask = 0xFCF0;
		} else if (handler == as_b) {
			mask = 0xFC00;
		} else if (handler == as_im_ocx) {
			mask = 0xFF0F;
		} else {
			mask = 0xFF00;
		}

		if (milstd1750_inst_tab[i].opcode != (w1 & mask)) {
			continue;
		}

		char *result = NULL;

		WSize wsize = accepted_word_size(handler);
		switch (wsize) {
		case OneWord: {
			char *operands = ((WHandle)handler)(w1);
			result = rz_str_newf("%s(%s)", milstd1750_inst_tab[i].mnemonic, operands);
			free(operands);

			op->size = 2;
			break;
		}
		case TwoWord: {
			if (len < 4) {
				return -1;
			}
			ut16 w2 = rz_read_be16(buf + 2);
			ut32 full = ((ut32)w1 << 16) | w2;
			char *operands = ((TwoWHandle)handler)(full);
			result = rz_str_newf("%s(%s)", milstd1750_inst_tab[i].mnemonic, operands);
			free(operands);

			op->size = 4;
			break;
		}
		default:
			rz_warn_if_reached();
		}

		rz_strbuf_set(&op->buf_asm, result);
		free(result);
		return op->size;
	}

	rz_strbuf_set(&op->buf_asm, "invalid");
	return -1;
}