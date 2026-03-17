#include "mil1750_disas.h"
#include <rz_types.h>

typedef char *(*WHandle)(ut16 w1);
typedef char *(*TwoWHandle)(ut32 w2);

typedef enum {
	OneWord = 1,
	TwoWord = 2,
} WSize;

typedef struct {
	ut8 opcode;
	const char *mnemonic;
	WSize w_size;
	void *handler;
} Mil1750LongInstruction;

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
	{ 0x5000, "LMP" },
	{ 0x5100, "WIPR" },
	{ 0x5200, "WOPR" },
	{ 0xD000, "RMP" },
	{ 0xD100, "RIPR" },
	{ 0xD200, "ROPR" },
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

	for (size_t i = 0; i < RZ_ARRAY_SIZE(mil1750_xio_commands); ++i) {
		if (mil1750_xio_commands[i].opcode == cmd) {
			return rz_str_dup(mil1750_xio_commands[i].mnemonic);
		}
	}

	return rz_str_newf("0x%04x", cmd);
}

// XIO: [8-bit op | 4-bit RA | 4-bit RX | 16-bit cmd]
static char *parse_xio(ut32 full) {
	ut8 RA = (full >> 20) & 0xF;
	ut8 RX = (full >> 16) & 0xF;
	ut16 cmd = full & 0xFFFF;

	char *cmd_str = parse_xio_commands(cmd);
	if (!cmd_str) {
		return NULL;
	}

	char *result;
	if (RX != 0) {
		result = rz_str_newf("xio r%d, r%d, %s", RA, RX, cmd_str);
	} else {
		result = rz_str_newf("xio r%d, %s", RA, cmd_str);
	}
	free(cmd_str);
	return result;
}

// { "ABX",  0x4040, as_bx },
// { "ANDX", 0x40E0, as_bx },
// { "DDR",  0xD700, as_r },
// { "DD",   0xD600, as_mem },
// { "TBI",  0x5800, as_im_0_15 },
// { "SLBI", 0x9E00, as_mem },
// { "STE",  0xDC00, as_xmem },
// { "STZ",  0x9100, as_addr },
// { "SBBX", 0x4050, as_bx },
static const Mil1750LongInstruction mil1750_inst_tab[] = {
	{ 0xA000, "A" },
	{ 0xA400, "ABS" },
	{, "ADD" },
	{, "ADDC" },
	{, "ADDU" },
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
	{, "BRX" },
	{ 0xF000, "C" },
	{, "CALL" },
	{ 0x3800, "CB" },
	{ 0xF400, "CBL" },
	{ 0x40C0, "CBX" },
	{ 0xF300, "CISN" },
	{, "CISP" },
	{, "CISM" },
	{, "CIM" },
	{, "CLC" },
	{, "CMP" },
	{, "CR" },
	{ 0xD400, "D" },
	{ 0xA600, "DA" },
	{ 0xA500, "DABS" },
	{ 0xA700, "DAR" },
	{ 0x1C00, "DB" },
	{ 0xF600, "DC" },
	{ 0xF700, "DCR" },
	{ 0xB300, "DECM" },
	{ 0x4A05, "DIM" },
	{ 0xD300, "DISN" },
	{ 0xD200, "DISP" },
	{ 0x8600, "DL" },
	{ 0x0400, "DLB" },
	{ 0x4010, "DLBX" },
	{ 0xDF00, "DLE" },
	{ 0x8800, "DLI" },
	{ 0x8700, "DLR" },
	{ 0xC600, "DM" },
	{, "DMAD" },
	{, "DMAE" },
	{ 0xC700, "DMR" },
	{ 0xB500, "DNEG" },
	{ 0xD500, "DR" },
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
	{ 0x9800, "DSTI" },
	{ 0xDD00, "DSTE" },
	{ 0x4030, "DSTX" },
	{, "DSUR" },
	{ 0xD000, "DV" },
	{ 0x4A06, "DVIM" },
	{ 0xD100, "DVR" },
	{ 0x4070, "DBX" },
	{, "EFIX" },
	{, "EFC" },
	{, "EFCR" },
	{, "EFA" },
	{, "EFAR" },
	{, "EFD" },
	{, "EFDR" },
	{, "EFL" },
	{, "EFLX" },
	{, "EFM" },
	{, "EFMR" },
	{, "EFS" },
	{, "EFSR" },
	{, "EFST" },
	{, "FA" },
	{, "FAB" },
	{, "FABX" },
	{, "FAR" },
	{, "FB" },
	{, "FBX" },
	{, "FC" },
	{, "FCB" },
	{, "FCBX" },
	{, "FCR" },
	{, "FD" },
	{, "FDB" },
	{, "FDBX" },
	{, "FDR" },
	{, "FIX" },
	{, "FL" },
	{, "FLT" },
	{, "FLX" },
	{, "FM" },
	{, "FMB" },
	{, "FMBX" },
	{, "FMR" },
	{, "FNEG" },
	{, "FS" },
	{, "FSB" },
	{, "FSBX" },
	{, "FSR" },
	{, "GO" },
	{, "IMM" },
	{, "IMML" },
	{, "INCM" },
	{, "INR" },
	{, "ITA" },
	{, "ITB" },
	{, "J" },
	{, "JC" },
	{, "JCI" },
	{, "JEZ" },
	{, "JGE" },
	{, "JGT" },
	{, "JLE" },
	{, "JLT" },
	{, "JNZ" },
	{, "JS" },
	{, "L" },
	{, "LB" },
	{, "LBI" },
	{, "LBX" },
	{, "LE" },
	{, "LI" },
	{, "LIM" },
	{, "LISP" },
	{, "LLB" },
	{, "LLBI" },
	{, "LM" },
	{, "LMP" },
	{, "LR" },
	{, "LRI" },
	{, "LSTI" },
	{, "LST" },
	{, "LUB" },
	{, "LUBI" },
	{, "M" },
	{, "MB" },
	{, "MBX" },
	{, "MISN" },
	{, "MISP" },
	{, "MIM" },
	{, "MOV" },
	{, "MOVC" },
	{, "MOVB" },
	{, "MPEN" },
	{, "MS" },
	{, "MSIM" },
	{, "MSR" },
	{, "MULS" },
	{, "N" },
	{, "NEG" },
	{, "NIM" },
	{, "NOP" },
	{, "NR" },
	{, "OD" },
	{, "OR" },
	{, "ORB" },
	{, "ORBX" },
	{, "ORIM" },
	{, "ORR" },
	{, "OTA" },
	{, "OTB" },
	{, "OTR" },
	{, "POP" },
	{, "POPM" },
	{, "PUSH" },
	{, "PSHM" },
	{, "RB" },
	{, "RBI" },
	{, "RBR" },
	{, "RCS" },
	{, "RCFR" },
	{, "RDI" },
	{, "RDOR" },
	{, "RIC1" },
	{, "RIC2" },
	{, "RIPR" },
	{, "RMFS" },
	{, "RMK" },
	{, "RMP" },
	{, "RNS" },
	{, "ROPR" },
	{, "RPIR" },
	{, "RPI" },
	{, "RSW" },
	{, "RVBR" },
	{, "S" },
	{, "SB" },
	{, "SBB" },
	{, "SBR" },
	{ 0x5200, "SBI" },
	{ 0x9500, "SFBS" },
	{, "SIM" },
	{, "SISP" },
	{, "SJS" },
	{, "SL" },
	{, "SLC" },
	{, "SLL" },
	{, "SLR" },
	{, "SM" },
	{, "SMK" },
	{, "SOJ" },
	{, "SPI" },
	{, "SR" },
	{, "SRA" },
	{ 0x9700, "SRM" },
	{, "SRL" },
	{, "ST" },
	{, "STA" },
	{, "STC" },
	{ 0x9200, "STCI" },
	{ 0x9400, "STI" },
	{, "STB" },
	{ 0x9C00, "STLB" },
	{ 0x9900, "STM" },
	{, "STR" },
	{, "STRI" },
	{ 0x9B00, "STUB" },
	{, "SUB" },
	{, "SUBB" },
	{ 0x9D00, "SUBI" },
	{, "SVBR" },
	{, "SWAB" },
	{, "TA" },
	{, "TAH" },
	{, "TAS" },
	{ 0x5600, "TB" },
	{, "TBH" },
	{ 0x5700, "TBR" },
	{, "TBS" },
	{ 0x5E00, "TVBR" },
	{, "TPIO" },
	{ 0x5900, "TSB" },
	{ 0xAE00, "UA" },
	{ 0xAD00, "UAR" },
	{ 0xFD00, "UC" },
	{ 0xF500, "UCIM" },
	{ 0xFC00, "UCR" },
	{ 0x7F00, "URS" },
	{ 0xBE00, "US" },
	{ 0xBD00, "USR" },
	{ 0x4900, "VIO" },
	{ 0xEC00, "XBR" },
	{ 0x4800, "XIO", TwoWord, parse_xio },
	{ 0xE400, "XOR" },
	{ 0x4A09, "XORM" },
	{ 0xE500, "XORR" },
	{ 0xED00, "XWR" },
};

int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	if (len < 2) {
		return -1;
	}

	ut16 w1 = rz_read_be16(buf);
	ut8 opcode = w1 >> 8;
	// TODO: six bit opcode

	for (size_t i = 0; i < RZ_ARRAY_SIZE(mil1750_inst_tab); ++i) {
		if (mil1750_inst_tab[i].opcode != opcode) {
			continue;
		}

		char *result = NULL;
		switch (mil1750_inst_tab[i].w_size) {
		case OneWord:
			char *operands = ((WHandle)mil1750_inst_tab[i].handler)(w1);
			result = rz_str_newf("%s %s", mil1750_inst_tab[i].mnemonic, operands);
			free(operand);

			op->size = 2;
			break;
		case TwoWord:
			if (len < 4) {
				return -1;
			}
			ut16 w2 = rz_read_be16(buf + 2);
			ut32 full = ((ut32)w1 << 16) | w2;
			char *operands = ((TwoWHandle)mil1750_inst_tab[i].handler)(full);
			result = rz_str_newf("%s %s", mil1750_inst_tab[i].mnemonic, operands);
			free(operand);

			op->size = 4;
			break;
		}

		rz_strbuf_set(&op->buf_asm, result);
		free(result);
		return op->size;
	}

	rz_strbuf_set(&op->buf_asm, "invalid");
	return -1;
}