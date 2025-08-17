// SPDX-FileCopyrightText: 2023 Jairus Martin <frmdstryr@protonmail.com>
// SPDX-FileCopyrightText: 2025 Alexandru Aioanei <alex03aioanei@gmail.com>
// SPDX-FileCopyrightText: 2025 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef _C166_DISAS_H
#define _C166_DISAS_H

#include <rz_types.h>
#include <rz_lib.h>

#define C166_INSTR_MAXLEN    16
#define C166_OPERANDS_MAXLEN 32

#define C166_BYTESIZE_2 2
#define C166_BYTESIZE_4 4

// clang-format off
#define SBUF_16 \
	(char[C166_INSTR_MAXLEN]) { 0 } /* CI linter gives an error */
#define SBUF_7 (char[7]) { 0 }
#define SBUF_9 (char[9]) { 0 }
// clang-format on

#define INSTR(...)    rz_snprintf(instr->instr, C166_INSTR_MAXLEN - 1, __VA_ARGS__);
#define OPERANDS(...) rz_snprintf(instr->operands, C166_OPERANDS_MAXLEN - 1, __VA_ARGS__);
#define PRINT_INSTR   INSTR("%s", c166_instr_name(instr->id))

#define print_hex_word(b, v) snprintf(b, 7, WORD_FMT, v) < 0 ? NULL : buf;

#define BYTE_FMT "0x%02x"
#define WORD_FMT "0x%04x"
#define FMT_BYTE ".byte 0x%02x"
#define FMT_WORD ".word 0x%02x%02x"
#define FMT0     "%s, [%s]"
#define FMT1     "%s, [%s+]"
#define FMT2     "[%s], %s"
#define FMT3     "[-%s], %s"
#define FMT4     "[%s], [%s]"
#define FMT5     "[%s+], [%s]"
#define FMT6     "[%s], [%s+]"
#define FMT7     "%s %s"
// #define FMT8     "%s, #%i"
#define FMT8  "%s, #0x%04x"
#define FMT9  "%s, %s"
#define FMT10 "%s, #%i"

// SFR
#define REG_CP   0xFE10 ///< CPU Context Pointer Register
#define REG_DPP0 0xFE00 ///< CPU Data Page Pointer 0 Register (4 bits)
#define REG_DPP1 (REG_DPP0 + 0x2) ///< CPU Data Page Pointer 1 Register (4 bits)
#define REG_DPP2 (REG_DPP0 + 0x4) ///< CPU Data Page Pointer 2 Register (4 bits)
#define REG_DPP3 (REG_DPP0 + 0x6) ///< CPU Data Page Pointer 3 Register (4 bits)

#define BASE_GPR_ADDR    0xFE10 ///< Base address for calculate GPR phisical address (also REG_CP)
#define BASE_SFR_ADDR    0xFE00 ///< Base address for calculate SFR phisical address (also REG_DPP0)
#define BASE_ESFR_ADDR   0xF000 ///< Base address for calculate ESFR phisical address
#define BASE_RAM_B_ADDR  0xFD00 ///< Base address for calculate RAM phisical address (bit)
#define BASE_SFR_B_ADDR  0xFF00 ///< Base address for calculate SFR phisical address (bit)
#define BASE_ESFR_B_ADDR 0xF100 ///< Base address for calculate ESFR phisical address (bit)

#define REG_R(n) (BASE_GPR_ADDR + (2 * n))

/**
 * C166 Register definitions
 * Defines all general-purpose and special registers for the C166 architecture
 */
// clang-format off
typedef enum {
	C166_R0,  C166_R1,  C166_R2,  C166_R3,
	C166_R4,  C166_R5,  C166_R6,  C166_R7,
	C166_R8,  C166_R9,  C166_R10, C166_R11,
	C166_R12, C166_R13, C166_R14, C166_R15,
	C166_RL0, C166_RH0, C166_RL1, C166_RH1,
	C166_RL2, C166_RH2, C166_RL3, C166_RH3,
	C166_RL4, C166_RH4, C166_RL5, C166_RH5,
	C166_RL6, C166_RH6, C166_RL7, C166_RH7,

	C166_IP,

	C166_SP,  C166_PSW, C166_CSP,
	C166_MDL, C166_MDH, C166_MDC,
	C166_STKOV, C166_STKUN,

	C166_CPUCON1, C166_CPUCON2,
	C166_VECSEG,  C166_SPSEG, C166_CP
} C166Register;

/*
	ADCIC, ADCON, ADDAT,
	ADDRSEL1, ADDRSEL2, ADDRSEL3, ADDRSEL4,
	ADEIC,
	BUSCON0, BUSCON1, BUSCON2, BUSCON3, BUSCON4,
	C1UMLM, // No 8-bit addr
	C1UGML, // No 8-bit addr
	C1LMLM, // No 8-bit addr
	C1LGML, // No 8-bit addr
	C1IR, // No 8-bit addr
	C1GMS, // No 8-bit addr
	C1BTR, // No 8-bit addr
	C1CSR, // No 8-bit addr
	CAPREL,
	CC0,  CC0IC,
	CC1,  CC1IC,
	CC2,  CC2IC,
	CC3,  CC3IC,
	CC4,  CC4IC,
	CC5,  CC5IC,
	CC6,  CC6IC,
	CC7,  CC7IC,
	CC8,  CC8IC,
	CC9,  CC9IC,
	CC10, CC10IC,
	CC11, CC11IC,
	CC12, CC12IC,
	CC13, CC13IC,
	CC14, CC14IC,
	CC15, CC15IC,
	CC16, CC17,
	CC18, CC19,
	CC20, CC21,
	CC22, CC23,
	CC24, CC25,
	CC26, CC27,
	CC28, CC29,
	CC30, CC31,

	CCM0, CCM1,
	CCM2, CCM3,
	CCM4, CCM5,
	CCM6, CCM7,
	// CP,
	CRIC,
	// CSP,
	DP2,  DP3,
	DP4,  DP6,
	DP7,  DP8,
	DPP0, DPP1,
	DPP2, DPP3,
	// MDC,
	// MDH,
	// MDL,
	ONES,
	P0L, P0H,
	P1L, P1H,
	P2,  P3,
	P4,  P5,
	P6,  P7,
	P8,
	PECC0, PECC1,
	PECC2, PECC3,
	PECC4, PECC5,
	PECC6, PECC7,
	// PSW,
	PW0, PW1,
	PW2, PW3,
	PWMCON0, PWMCON1,
	S0BG,
	S0CON,
	S0EIC,
	S0RBUF,
	S0RIC,
	S0TBUF,
	S0TIC,
	// SP,
	SSCCON,
	SSCEIC,
	SSCRIC,
	SSCTIC,
	// STKOV,
	// STKUN,
	SYSCON,
	T0,
	T01CON,
	T0IC,
	T0REL,
	T1, T1IC,  T1REL,
	T2, T2CON, T2IC,
	T3, T3CON, T3IC,
	T4, T4CON, T4IC,
	T5, T5CON, T5IC,
	T6, T6CON, T6IC,
	T78CON,
	TFR,
	WDT, WDTCON,
	ZEROS,

	ADDAT2,
	CC16IC,  CC17IC,
	CC18IC,  CC19IC,
	CC20IC,  CC21IC,
	CC22IC,  CC23IC,
	CC24IC,  CC25IC,
	CC26IC,  CC27IC,
	CC28IC,  CC29IC,
	CC30IC,  CC31IC,
	DP0L,    DP0H,
	DP1L,    DP1H,
	EXICON,
	ODP2,    ODP3,
	ODP6,    ODP7,
	ODP8,
	PICON,
	PP0, PP1, PP2, PP3,
	PT0, PT1, PT2, PT3,
	PWMIC,
	RP0H,
	S0TBIC,
	SSCBR,
	SSCRB,
	SSCTB,
	T7,
	T7IC,
	T7REL,
	T8,
	T8IC,
	T8REL,
	XP0IC, XP1IC, XP2IC, XP3IC,
*/
// clang-format on

/**
 * C166 Operation Types
 * Defines all instruction types supported by the C166 architecture
 */
typedef enum {
	C166_ADD_Rwn_Rwm = 0x00,
	C166_ADDB_Rbn_Rbm = 0x01,
	C166_ADD_reg_mem = 0x02,
	C166_ADDB_reg_mem = 0x03,
	C166_ADD_mem_reg = 0x04,
	C166_ADDB_mem_reg = 0x05,
	C166_ADD_reg_data16 = 0x06,
	C166_ADDB_reg_data8 = 0x07,
	C166_ADD_Rwn_x = 0x08,
	C166_ADDB_Rbn_x = 0x09,
	C166_BFLDL_bitoff_x = 0x0A,
	C166_MUL_Rwn_Rwm = 0x0B,
	C166_ROL_Rwn_Rwm = 0x0C,
	C166_JMPR_cc_UC_rel = 0x0D,
	C166_BCLR_bitoff0 = 0x0E,
	C166_BSET_bitoff0 = 0x0F,

	C166_ADDC_Rwn_Rwm = 0x10,
	C166_ADDCB_Rbn_Rbm = 0x11,
	C166_ADDC_reg_mem = 0x12,
	C166_ADDCB_reg_mem = 0x13,
	C166_ADDC_mem_reg = 0x14,
	C166_ADDCB_mem_reg = 0x15,
	C166_ADDC_reg_data16 = 0x16,
	C166_ADDCB_reg_data8 = 0x17,
	C166_ADDC_Rwn_x = 0x18,
	C166_ADDCB_Rbn_x = 0x19,
	C166_BFLDH_bitoff_x = 0x1A,
	C166_MULU_Rwn_Rwm = 0x1B,
	C166_ROL_Rwn_data4 = 0x1C,
	C166_JMPR_cc_NET_rel = 0x1D,
	C166_BCLR_bitoff1 = 0x1E,
	C166_BSET_bitoff1 = 0x1F,

	C166_SUB_Rwn_Rwm = 0x20,
	C166_SUBB_Rbn_Rbm = 0x21,
	C166_SUB_reg_mem = 0x22,
	C166_SUBB_reg_mem = 0x23,
	C166_SUB_mem_reg = 0x24,
	C166_SUBB_mem_reg = 0x25,
	C166_SUB_reg_data16 = 0x26,
	C166_SUBB_reg_data8 = 0x27,
	C166_SUB_Rwn_x = 0x28,
	C166_SUBB_Rbn_x = 0x29,
	C166_BCMP_bitaddr_bitaddr = 0x2A,
	C166_PRIOR_Rwn_Rwm = 0x2B,
	C166_ROR_Rwn_Rwm = 0x2C,
	C166_JMPR_cc_EQ_or_Z_rel = 0x2D,
	C166_BCLR_bitoff2 = 0x2E,
	C166_BSET_bitoff2 = 0x2F,

	C166_SUBC_Rwn_Rwm = 0x30,
	C166_SUBCB_Rbn_Rbm = 0x31,
	C166_SUBC_reg_mem = 0x32,
	C166_SUBCB_reg_mem = 0x33,
	C166_SUBC_mem_reg = 0x34,
	C166_SUBCB_mem_reg = 0x35,
	C166_SUBC_reg_data16 = 0x36,
	C166_SUBCB_reg_data8 = 0x37,
	C166_SUBC_Rwn_x = 0x38,
	C166_SUBCB_Rbn_x = 0x39,
	C166_BMOVN_bitaddr_bitaddr = 0x3A,
	// 0x3B,
	C166_ROR_Rwn_data4 = 0x3C,
	C166_JMPR_cc_NE_or_NZ_rel = 0x3D,
	C166_BCLR_bitoff3 = 0x3E,
	C166_BSET_bitoff3 = 0x3F,

	C166_CMP_Rwn_Rwm = 0x40,
	C166_CMPB_Rbn_Rbm = 0x41,
	C166_CMP_reg_mem = 0x42,
	C166_CMPB_reg_mem = 0x43,
	// 0x44,
	// 0x45,
	C166_CMP_reg_data16 = 0x46,
	C166_CMPB_reg_data8 = 0x47,
	C166_CMP_Rwn_x = 0x48,
	C166_CMPB_Rbn_x = 0x49,
	C166_BMOV_bitaddr_bitaddr = 0x4A,
	C166_DIV_Rwn = 0x4B,
	C166_SHL_Rwn_Rwm = 0x4C,
	C166_JMPR_cc_V_rel = 0x4D,
	C166_BCLR_bitoff4 = 0x4E,
	C166_BSET_bitoff4 = 0x4F,

	C166_XOR_Rwn_Rwm = 0x50,
	C166_XORB_Rbn_Rbm = 0x51,
	C166_XOR_reg_mem = 0x52,
	C166_XORB_reg_mem = 0x53,
	C166_XOR_mem_reg = 0x54,
	C166_XORB_mem_reg = 0x55,
	C166_XOR_reg_data16 = 0x56,
	C166_XORB_reg_data8 = 0x57,
	C166_XOR_Rwn_x = 0x58,
	C166_XORB_Rbn_x = 0x59,
	C166_BOR_bitaddr_bitaddr = 0x5A,
	C166_DIVU_Rwn = 0x5B,
	C166_SHL_Rwn_data4 = 0x5C,
	C166_JMPR_cc_NV_rel = 0x5D,
	C166_BCLR_bitoff5 = 0x5E,
	C166_BSET_bitoff5 = 0x5F,

	C166_AND_Rwn_Rwm = 0x60,
	C166_ANDB_Rbn_Rbm = 0x61,
	C166_AND_reg_mem = 0x62,
	C166_ANDB_reg_mem = 0x63,
	C166_AND_mem_reg = 0x64,
	C166_ANDB_mem_reg = 0x65,
	C166_AND_reg_data16 = 0x66,
	C166_ANDB_reg_data8 = 0x67,
	C166_AND_Rwn_x = 0x68,
	C166_ANDB_Rbn_x = 0x69,
	C166_BAND_bitaddr_bitaddr = 0x6A,
	C166_DIVL_Rwn = 0x6B,
	C166_SHR_Rwn_Rwm = 0x6C,
	C166_JMPR_cc_N_rel = 0x6D,
	C166_BCLR_bitoff6 = 0x6E,
	C166_BSET_bitoff6 = 0x6F,

	C166_OR_Rwn_Rwm = 0x70,
	C166_ORB_Rbn_Rbm = 0x71,
	C166_OR_reg_mem = 0x72,
	C166_ORB_reg_mem = 0x73,
	C166_OR_mem_reg = 0x74,
	C166_ORB_mem_reg = 0x75,
	C166_OR_reg_data16 = 0x76,
	C166_ORB_reg_data8 = 0x77,
	C166_OR_Rwn_x = 0x78,
	C166_ORB_Rbn_x = 0x79,
	C166_BXOR_bitaddr_bitaddr = 0x7A,
	C166_DIVLU_Rwn = 0x7B,
	C166_SHR_Rwn_data4 = 0x7C,
	C166_JMPR_cc_NN_rel = 0x7D,
	C166_BCLR_bitoff7 = 0x7E,
	C166_BSET_bitoff7 = 0x7F,

	C166_CMPI1_Rwn_data4 = 0x80,
	C166_NEG_Rwn = 0x81,
	C166_CMPI1_Rwn_mem = 0x82,
	// 0x83
	C166_MOV_oRwn_mem = 0x84,
	// 0x85
	C166_CMPI1_Rwn_data16 = 0x86,
	C166_IDLE = 0x87,
	C166_MOV_noRwm_Rwn = 0x88,
	C166_MOVB_noRwm_Rbn = 0x89,
	C166_JB_bitaddr_rel = 0x8A,
	// 0x8B
	C166_SBRK = 0x8C,
	C166_JMPR_cc_C_or_ULT_rel = 0x8D,
	C166_BCLR_bitoff8 = 0x8E,
	C166_BSET_bitoff8 = 0x8F,

	C166_CMPI2_Rwn_data4 = 0x90,
	C166_CPL_Rwn = 0x91,
	C166_CMPI2_Rwn_mem = 0x92,
	// 0x93
	C166_MOV_mem_oRwn = 0x94,
	// 0x95
	C166_CMPI2_Rwn_data16 = 0x96,
	C166_PWRDN = 0x97,
	C166_MOV_Rwn_oRwmp = 0x98,
	C166_MOVB_Rbn_oRwmp = 0x99,
	C166_JNB_bitaddr_rel = 0x9A,
	C166_TRAP_trap7 = 0x9B,
	C166_JMPI_cc_oRwn = 0x9C,
	C166_JMPR_cc_NC_or_NGE_rel = 0x9D,
	C166_BCLR_bitoff9 = 0x9E,
	C166_BSET_bitoff9 = 0x9F,

	C166_CMPD1_Rwn_data4 = 0xA0,
	C166_NEGB_Rbn = 0xA1,
	C166_CMPD1_Rwn_mem = 0xA2,
	// 0xA3
	C166_MOVB_oRwn_mem = 0xA4,
	C166_DISWDT = 0xA5,
	C166_CMPD1_Rwn_data16 = 0xA6,
	C166_SRVWDT = 0xA7,
	C166_MOV_Rwn_oRwm = 0xA8,
	C166_MOVB_Rbn_oRwm = 0xA9,
	C166_JBC_bitaddr_rel = 0xAA,
	C166_CALLI_cc_Rwn = 0xAB,
	C166_ASHR_Rwn_Rwm = 0xAC,
	C166_JMPR_cc_SGT_rel = 0xAD,
	C166_BCLR_bitoff10 = 0xAE,
	C166_BSET_bitoff10 = 0xAF,

	C166_CMPD2_Rwn_data4 = 0xB0,
	C166_CPLB_Rbn = 0xB1,
	C166_CMPD2_Rwn_mem = 0xB2,
	// 0xB3,
	C166_MOVB_mem_oRwn = 0xB4,
	C166_EINIT = 0xB5,
	C166_CMPD2_Rwn_data16 = 0xB6,
	C166_SRST = 0xB7,
	C166_MOV_oRwm_Rwn = 0xB8,
	C166_MOVB_oRwm_Rbn = 0xB9,
	C166_JNBS_bitaddr_rel = 0xBA,
	C166_CALLR_rel = 0xBB,
	C166_ASHR_Rwn_data4 = 0xBC,
	C166_JMPR_cc_SLE_rel = 0xBD,
	C166_BCLR_bitoff11 = 0xBE,
	C166_BSET_bitoff11 = 0xBF,

	C166_MOVBZ_Rwn_Rbm = 0xC0,
	// 0xC1
	C166_MOVBZ_reg_mem = 0xC2,
	// 0xC3
	C166_MOV_oRwm_data16_Rwn = 0xC4,
	C166_MOVBZ_mem_reg = 0xC5,
	C166_SCXT_reg_data16 = 0xC6,
	// 0xC7
	C166_MOV_oRwn_oRwm = 0xC8,
	C166_MOVB_oRwn_oRwm = 0xC9,
	C166_CALLA_cc_caddr = 0xCA,
	C166_RET = 0xCB,
	C166_NOP = 0xCC,
	C166_JMPR_cc_SLT_rel = 0xCD,
	C166_BCLR_bitoff12 = 0xCE,
	C166_BSET_bitoff12 = 0xCF,

	C166_MOVBS_Rwn_Rbm = 0xD0,
	C166_ATOMIC_or_EXTR_irang2 = 0xD1,
	C166_MOVBS_reg_mem = 0xD2,
	// 0xD3
	C166_MOV_Rwn_oRwm_data16 = 0xD4,
	C166_MOVBS_mem_reg = 0xD5,
	C166_SCXT_reg_mem = 0xD6,
	C166_EXTP_or_EXTS_pag10_or_seg8_irang2 = 0xD7,
	C166_MOV_oRwnp_oRwm = 0xD8,
	C166_MOVB_oRwnp_oRwm = 0xD9,
	C166_CALLS_seg_caddr = 0xDA,
	C166_RETS = 0xDB,
	C166_EXTP_or_EXTS_Rwm_irang2 = 0xDC,
	C166_JMPR_cc_SGE_rel = 0xDD,
	C166_BCLR_bitoff13 = 0xDE,
	C166_BSET_bitoff13 = 0xDF,

	C166_MOV_Rwn_data4 = 0xE0,
	C166_MOVB_Rbn_data4 = 0xE1,
	C166_PCALL_reg_caddr = 0xE2,
	// 0xE3
	C166_MOVB_oRwm_data16_Rbn = 0xE4,
	// 0xE5
	C166_MOV_reg_data16 = 0xE6,
	C166_MOVB_reg_data8 = 0xE7,
	C166_MOV_oRwn_oRwmp = 0xE8,
	C166_MOVB_oRwn_oRwmp = 0xE9,
	C166_JMPA_cc_caddr = 0xEA,
	C166_RETP_reg = 0xEB,
	C166_PUSH_reg = 0xEC,
	C166_JMPR_cc_UGT_rel = 0xED,
	C166_BCLR_bitoff14 = 0xEE,
	C166_BSET_bitoff14 = 0xEF,

	C166_MOV_Rwn_Rwm = 0xF0,
	C166_MOVB_Rbn_Rbm = 0xF1,
	C166_MOV_reg_mem = 0xF2,
	C166_MOVB_reg_mem = 0xF3,
	C166_MOVB_Rbn_oRwm_data16 = 0xF4,
	// 0xF5
	C166_MOV_mem_reg = 0xF6,
	C166_MOVB_mem_reg = 0xF7,
	// 0xF8
	// 0xF9
	C166_JMPS_seg_caddr = 0xFA,
	C166_RETI = 0xFB,
	C166_POP_reg = 0xFC,
	C166_JMPR_cc_ULE_rel = 0xFD,
	C166_BCLR_bitoff15 = 0xFE,
	C166_BSET_bitoff15 = 0xFF,
} c166_opcodes;

/*!
 * \brief C166 Branch Condition Codes
 *
 * Defines condition codes used for conditional branching instructions
 * Datasheet page 39
 * (*) Only usable with the JMPA and CALLA instructions
 */
// clang-format off
typedef enum {
	C166_CC_UC,     ///< [0D] Unconditional
	C166_CC_NET,    ///< [1D] Not Equal
	C166_CC_EQ,     ///< [2D] Equal
	// C166_CC_Z,   ///< [2D] Zero and Not End-of-Table
	C166_CC_NE,     ///< [3D] Not Equal
	// C166_CC_NZ,  ///< [3D] Not Zero
	C166_CC_V,      ///< [4D] Overflow
	C166_CC_NV,     ///< [5D] No Overflow
	C166_CC_N,      ///< [6D] Negative
	C166_CC_NN,     ///< [7D] Not Negative
	C166_CC_C,      ///< [8D] Carry
	// C166_CC_ULT, ///< [8D] Unsigned Less Than
	C166_CC_NC,     ///< [9D] No Carry
	// C166_CC_UGE, ///< [9D] Unsigned Greater Than or Equal
	C166_CC_SGT,    ///< [AD] Signed Greater Than
	C166_CC_SLE,    ///< [BD] Signed Less Than or Equal
	C166_CC_SLT,    ///< [CD] Signed Less Than /* Not described in datasheet */
	C166_CC_SGE,    ///< [DD] Signed Greater Than or Equal
	C166_CC_UGT,    ///< [ED] Unsigned Greater Than
	C166_CC_ULE,    ///< [FD] Unsigned Less Than or Equal

	// C166_CC_NUSR0,  ///< USR-bit 0 is cleared (*)
	// C166_CC_NUSR1,  ///< USR-bit 1 is cleared (*)
	// C166_CC_USR0,   ///< USR-bit 0 is set1)
	// C166_CC_USR1    ///< USR-bit 1 is set1)

} C166CondCode;

const char *c166_rw[] = {
	"r0", "r1", "r2", "r3",
	"r4", "r5", "r6", "r7",
	"r8", "r9", "r10", "r11",
	"r12", "r13", "r14", "r15",
};

const char *c166_rb[] = {
	"rl0", "rh0",
	"rl1", "rh1",
	"rl2", "rh2",
	"rl3", "rh3",
	"rl4", "rh4",
	"rl5", "rh5",
	"rl6", "rh6",
	"rl7", "rh7",
};

/**
 * Maps hexcodes to condition codes for JMPR instructions
 * Used to determine the condition code for conditional jump instructions
 */
// C166 condition code names
static const char *conds[] = {
	[C166_CC_UC]    = "cc_UC",      ///< Unconditional
	[C166_CC_V]     = "cc_V",       ///< Overflow
	[C166_CC_NV]    = "cc_NV",      ///< No Overflow
	[C166_CC_N]     = "cc_N",       ///< Negative
	[C166_CC_NN]    = "cc_NN",      ///< Not Negative
	[C166_CC_C]     = "cc_C/ULT",   ///< Carry
	[C166_CC_NC]    = "cc_NC/UGE",  ///< No Carry
	[C166_CC_EQ]    = "cc_Z/EQ",    ///< Equal
	[C166_CC_NE]    = "cc_NZ/NE",   ///< Not Equal
	[C166_CC_ULE]   = "cc_ULE",     ///< Unsigned Less Than or Equal
	[C166_CC_UGT]   = "cc_UGT",     ///< Unsigned Greater Than
	[C166_CC_SLE]   = "cc_SLE",     ///< Signed Less Than or Equal
	[C166_CC_SGE]   = "cc_SGE",     ///< Signed Greater Than or Equal
	[C166_CC_SGT]   = "cc_SGT",     ///< Signed Greater Than
	[C166_CC_NET]   = "cc_NET",     ///< Not Equal and Not End-of-Table

	[C166_CC_SLT]   = "cc_SLT",     ///< Signed Less Than

	// [C166_CC_NUSR0] = "cc_NUSR0",   ///< USR-bit 0 is cleared (*)
	// [C166_CC_NUSR1] = "cc_NUSR1",   ///< USR-bit 1 is cleared (*)
	// [C166_CC_USR0]  = "cc_USR0",    ///< USR-bit 0 is set1)
	// [C166_CC_USR1]  = "cc_USR1"     ///< USR-bit 1 is set1)
};
// clang-format on

typedef enum {
	C166_EXT_MODE_NONE,
	C166_EXT_MODE_PAGE,
	C166_EXT_MODE_SEG,
} C166ExtMode;

// clang-format off
typedef struct {
	bool esfr;  		///< Extended register sequence active
	C166ExtMode mode; 	///< Extended page/seq mode
	ut8 i; 				///< Number of unstructions remaining until state exits
	ut16 value; 		///< Value of ext
} C166ExtState;

typedef struct {
	ut32 last_addr; 	///< State of last addr dissassembled
	C166ExtState ext;
	RzPVector /*<RzAsmTokenPattern *>*/ *token_patterns;
} C166State;
// clang-format on

typedef struct {
	ut64 d;
	ut32 imm;
	union {
		ut32 disp;
		st32 sdisp;
	};
	c166_opcodes id;
	ut32 addr;
	ut8 byte_size : 4;
	unsigned type;
	char instr[C166_INSTR_MAXLEN];
	char operands[C166_OPERANDS_MAXLEN];
	C166ExtState ext;
} C166_Inst;

static inline ut32 extract(ut64 x, ut8 i, ut8 n) {
	return (x >> i) & ((1 << n) - 1);
}

static inline ut16 C166_word(const C166_Inst *i, unsigned index) {
	rz_warn_if_fail(index >= 1 && index <= 4);
	return extract(i->d, (index - 1) * 16, 16);
}

static inline ut16 get_opcode(const C166_Inst *i, unsigned l, unsigned r) {
	return extract(i->d, l, (r - l + 1));
}

static inline ut16 get_byte(const C166_Inst *i, ut8 index) {
	rz_warn_if_fail(index >= 0 && index <= 3);
	ut16 ret = 0;
	switch (index) {
	case 0:
		ret = get_opcode(i, 0, 8);
		break;
	case 1:
		ret = (C166_word(i, 1) & 0xFF00) >> 8;
		break;
	case 2:
		ret = C166_word(i, 2) & 0x00FF;
		break;
	case 3:
		ret = (C166_word(i, 2) & 0xFF00) >> 8;
		break;
	default: break;
	}
	return ret;
}

static inline ut16 get_operand(const C166_Inst *i, ut8 index) {
	rz_warn_if_fail(index >= 1 && index <= 3);
	return get_byte(i, index);
}

/**
 * Disassemble C166 instruction
 *
 * @param state Pointer to state structure
 * @param instr Pointer to instruction structure
 * @param bytes Buffer containing instruction bytes
 * @param len Length of buffer
 * @return Instruction byte size, 2 or 4 or -1 on error
 */
RZ_API st32 c166_decode_command(RZ_NONNULL C166State *state, RZ_NONNULL C166_Inst *instr, const ut8 *bytes, st32 len);
RZ_API bool check_unused_opcode(const ut8 opcode);
#endif /* _C166_DISAS_H */
