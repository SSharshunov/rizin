#include "mil1750_disas.h"
#include <rz_types.h>

typedef struct {
	ut8 opcode;
	const char *mnemonic;
	Mil1750Format format;
} Mil1750Opcode;

// Define the instruction formats
typedef enum {
	MIL1750_FMT_R, // Register-to-Register:  [8-bit op | 4-bit RA | 4-bit RB]
	MIL1750_FMT_ICR, // IC-Relative:           [8-bit op | 8-bit disp]
	MIL1750_FMT_B, // Base Relative:         [6-bit op | 2-bit BR | 8-bit disp]
	MIL1750_FMT_BX, // Base Rel Indexed:      [6-bit op | 2-bit BR | 4-bit opex | 4-bit RX]
	MIL1750_FMT_D, // Long Direct:           [8-bit op | 4-bit RA | 4-bit RX | 16-bit addr]
	MIL1750_FMT_DX, // Long Direct (no RX):   [8-bit op | 4-bit RA | 4-bit opex | 16-bit addr]
	MIL1750_FMT_IM, // Immediate:             [8-bit op | 4-bit RA | 4-bit opex | 16-bit imm]
	MIL1750_FMT_S, // Special:               [8-bit op | 8-bit opex]
	MIL1750_FMT_XIO, // XIO:                   [8-bit op | 4-bit RA | 4-bit RX | 16-bit cmd]
} Mil1750Format;

typedef struct {
	ut16 opcode;
	const char *mnemonic;
} Mil1750XioCommand;

static const Mil1750XioCommand mil1750_xio_commands[] = {
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
	{ 0x200E, "CO" },
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

		return rz_str_newf("XIO { %d, %d }", Y, X);
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

	for (size_t i = 0; i < RZ_ARRAY_SIZE(mil1750_xio_commands); ++i) {
		if (mil1750_xio_commands[i].opcode == cmd) {
			return rz_str_dup(mil1750_xio_commands[i].mnemonic);
		}
	}

	return "unknown";
}

// { "ABX",  0x4040, as_bx },
//  { "ANDX", 0x40E0, as_bx },
// { "DDR",  0xD700, as_r },
// { "DD",   0xD600, as_mem },
static const Mil1750Opcode mil1750_optab[] = {
	{ 0xA000, "A" },
	{ 0xA400, "ABS" },
	{ , "ADD" },
	{ , "ADDC" },
	{ , "ADDU" },
	{ 0x4A01, "AIM" },
	{ 0xA200, "AISP" },
	{ 0xE200, "AND" },
	{ 0x3400, "ANDB" },
	{ 0x4A07, "ANDM" },
	{ 0xE300, "ANDR" },
	{ 0xA100, "AR" },
	{ 0x1000, "AB" },
	{ 0xA000, "A" },
	{ 0x7700, "BEX" },
	{ 0x7500, "BEZ" },
	{ 0x7B00, "BGE" },
	{ 0x7900, "BGT" },
	{ 0x4F00, "BIF" },
	{ 0x7800, "BLE" },
	{ 0x7600, "BLT" },
	{ 0x7A00, "BNZ" },
	{ 0xFFFF, "BPT" },
	{ 0x7400, "BR" },
	{ , "BRX" },
	{ 0xF000, "C" },
	{ , "CALL" },
	{ 0x3800, "CB" },
	{ 0xF400, "CBL" },
	{ 0x40C0, "CBX" },
	{ 0xF300, "CISN" },
	{ , "CISP" },
	{ , "CISM" },
	{ , "CIM" },
	{ , "CLC" },
	{ , "CMP" },
	{ , "CR" },
	{ , "D" },
	{ 0xA600, "DA" },
	{ , "DABS" },
	{ 0xA700, "DAR" },
	{ , "DB" },
	{ 0xF600, "DC" },
	{ 0xF700, "DCR" },
	{ 0xB300, "DECM" },
	{ , "DIM" },
	{ , "DISN" },
	{ , "DISP" },
	{ 0x8600, "DL" },
	{ 0x0400, "DLB" },
	{ , "DLBX" },
	{ , "DLE" },
	{ , "DLI" },
	{ 0x8700, "DLR" },
	{ 0xC600, "DM" },
	{ , "DMAD" },
	{ , "DMAE" },
	{ 0xC700, "DMR" },
	{ , "DNEG" },
	{ , "DR" },
	{ 0xB600, "DS" },
	{ 0x6E00, "DSAR" },
	{ 0x6F00, "DSCR" },
	{ 0x6500, "DSLL" },
	{ 0x6800, "DSLC" },
	{ 0x6D00, "DSLR" },
	{ 0x6700, "DSRA" },
	{ 0x6600, "DSRL" },
	{ 0xB700, "DSR" },
	{ 0x9600, "DST" },
	{ 0x0C00, "DSTB" },
	{ , "DSTI" },
	{ , "DSTE" },
	{ , "DSTX" },
	{ , "DSUR" },
	{ , "DV" },
	{ , "DVIM" },
	{ , "DVR" },
	{ , "DBX" },
	{ , "EFIX" },
	{ , "EFC" },
	{ , "EFCR" },
	{ , "EFA" },
	{ , "EFAR" },
	{ , "EFD" },
	{ , "EFDR" },
	{ , "EFL" },
	{ , "EFLX" },
	{ , "EFM" },
	{ , "EFMR" },
	{ , "EFS" },
	{ , "EFSR" },
	{ , "EFST" },
	{ , "FA" },
	{ , "FAB" },
	{ , "FABX" },
	{ , "FAR" },
	{ , "FB" },
	{ , "FBX" },
	{ , "FC" },
	{ , "FCB" },
	{ , "FCBX" },
	{ , "FCR" },
	{ , "FD" },
	{ , "FDB" },
	{ , "FDBX" },
	{ , "FDR" },
	{ , "FIX" },
	{ , "FL" },
	{ , "FLT" },
	{ , "FLX" },
	{ , "FM" },
	{ , "FMB" },
	{ , "FMBX" },
	{ , "FMR" },
	{ , "FNEG" },
	{ , "FS" },
	{ , "FSB" },
	{ , "FSBX" },
	{ , "FSR" },
	{ , "GO" },
	{ , "IMM" },
	{ , "IMML" },
	{ , "INCM" },
	{ , "INR" },
	{ , "ITA" },
	{ , "ITB" },
	{ , "J" },
	{ , "JC" },
	{ , "JCI" },
	{ , "JEZ" },
	{ , "JGE" },
	{ , "JGT" },
	{ , "JLE" },
	{ , "JLT" },
	{ , "JNZ" },
	{ , "JS" },
	{ , "L" },
	{ , "LB" },
	{ , "LBI" },
	{ , "LBX" },
	{ , "LE" },
	{ , "LI" },
	{ , "LIM" },
	{ , "LISP" },
	{ , "LLB" },
	{ , "LLBI" },
	{ , "LM" },
	{ , "LMP" },
	{ , "LR" },
	{ , "LRI" },
	{ , "LSTI" },
	{ , "LST" },
	{ , "LUB" },
	{ , "LUBI" },
	{ , "M" },
	{ , "MB" },
	{ , "MBX" },
	{ , "MISN" },
	{ , "MISP" },
	{ , "MIM" },
	{ , "MOV" },
	{ , "MOVC" },
	{ , "MOVB" },
	{ , "MPEN" },
	{ , "MS" },
	{ , "MSIM" },
	{ , "MSR" },
	{ , "MULS" },
	{ , "N" },
	{ , "NEG" },
	{ , "NIM" },
	{ , "NOP" },
	{ , "NR" },
	{ , "OD" },
	{ , "OR" },
	{ , "ORB" },
	{ , "ORBX" },
	{ , "ORIM" },
	{ , "ORR" },
	{ , "OTA" },
	{ , "OTB" },
	{ , "OTR" },
	{ , "POP" },
	{ , "POPM" },
	{ , "PUSH" },
	{ , "PSHM" },
	{ , "RB" },
	{ , "RBI" },
	{ , "RBR" },
	{ , "RCS" },
	{ , "RCFR" },
	{ , "RDI" },
	{ , "RDOR" },
	{ , "RIC1" },
	{ , "RIC2" },
	{ , "RIPR" },
	{ , "RMFS" },
	{ , "RMK" },
	{ , "RMP" },
	{ , "RNS" },
	{ , "ROPR" },
	{ , "RPIR" },
	{ , "RPI" },
	{ , "RSW" },
	{ , "RVBR" },
	{ , "S" },
	{ , "SB" },
	{ , "SBB" },
	{ , "SBR" },
	{ , "SBI" },
	{ , "SFBS" },
	{ , "SIM" },
	{ , "SISP" },
	{ , "SJS" },
	{ , "SL" },
	{ , "SLC" },
	{ , "SLL" },
	{ , "SLR" },
	{ , "SM" },
	{ , "SMK" },
	{ , "SOJ" },
	{ , "SPI" },
	{ , "SR" },
	{ , "SRA" },
	{ , "SRM" },
	{ , "SRL" },
	{ , "ST" },
	{ , "STA" },
	{ , "STC" },
	{ , "STCI" },
	{ , "STI" },
	{ , "STB" },
	{ , "STLB" },
	{ , "STM" },
	{ , "STR" },
	{ , "STRI" },
	{ , "STUB" },
	{ , "SUB" },
	{ , "SUBB" },
	{ , "SUBI" },
	{ , "SVBR" },
	{ , "SWAB" },
	{ , "TA" },
	{ , "TAH" },
	{ , "TAS" },
	{ , "TB" },
	{ , "TBH" },
	{ , "TBR" },
	{ , "TBS" },
	{ , "TVBR" },
	{ , "TPIO" },
	{ , "TSB" },
	{ , "UA" },
	{ , "UAR" },
	{ , "UC" },
	{ , "UCIM" },
	{ , "UCR" },
	{ , "URS" },
	{ , "US" },
	{ , "USR" },
	{ , "VIO" },
	{ , "WIPR" },
	{ , "WOPR" },
	{ , "XBR" },
	{ , "XIO" },
	{ , "XOR" },
	{ , "XORM" },
	{ , "XORR" },
	{ , "XWR" },
};

format_to_handle

	int
	disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
}