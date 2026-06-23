// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef C166_COMMON_H
#define C166_COMMON_H

#include <rz_types.h>
#include <rz_vector.h>
#include <rz_analysis.h>
#include <analysis_private.h>

#define C166_BYTESIZE_INVALID (-1)
#define C166_BYTESIZE_2 2
#define C166_BYTESIZE_4 4

#define H_NIB(x) (((x) & 0xF0) >> 4) ///< High nibble
#define L_NIB(x) ((x) & 0x0F) ///< Low nibble

// Core Special Function Registers (CSFR)
#define BASE_GPR_ADDR    0xFE10U ///< Base address for calculate GPR physical address (also REG_CP)
#define BASE_SFR_ADDR    0xFE00U ///< Base address for calculate SFR physical address (also REG_DPP0)
#define BASE_ESFR_ADDR   0xF000U ///< Base address for calculate ESFR physical address
#define BASE_RAM_B_ADDR  0xFD00U ///< Base address for calculate RAM physical address (bit)
#define BASE_SFR_B_ADDR  0xFF00U ///< Base address for calculate SFR physical address (bit)
#define BASE_ESFR_B_ADDR 0xF100U ///< Base address for calculate ESFR physical address (bit)

#define QX0   0xF000U ///< MAC Offset Register X0 (ESFRs)
#define QX1   0xF002U ///< MAC Offset Register X1 (ESFRs)
#define QR0   0xF004U ///< MAC Offset Register R0 (ESFRs)
#define QR1   0xF006U ///< MAC Offset Register R1 (ESFRs)
#define CPUID 0xF00CU ///< CPU Identification Register (ESFRs)

#define REG_PSW 0xFF10U ///< Processor Status Word

#define REG_DPP0    (BASE_SFR_ADDR + 0x00) ///< CPU Data Page Pointer 0 Register (10 bits)
#define REG_DPP1    (BASE_SFR_ADDR + 0x02) ///< CPU Data Page Pointer 1 Register (10 bits)
#define REG_DPP2    (BASE_SFR_ADDR + 0x04) ///< CPU Data Page Pointer 2 Register (10 bits)
#define REG_DPP3    (BASE_SFR_ADDR + 0x06) ///< CPU Data Page Pointer 3 Register (10 bits)
#define REG_CSP     (BASE_SFR_ADDR + 0x08) ///< Code Segment Pointer
#define REG_MDH     (BASE_SFR_ADDR + 0x0c) ///< Multiply Divide High Word
#define REG_MDL     (BASE_SFR_ADDR + 0x0e) ///< Multiply Divide Low Word
#define REG_CP      (BASE_SFR_ADDR + 0x10) ///< CPU Context Pointer Register
#define REG_SP      (BASE_SFR_ADDR + 0x12) ///< Stack Pointer Register
#define REG_STKOV   (BASE_SFR_ADDR + 0x14) ///< Stack Overflow Pointer
#define REG_STKUN   (BASE_SFR_ADDR + 0x16) ///< Stack Underflow Pointer
#define REG_CPUCON1 (BASE_SFR_ADDR + 0x18) ///< Core Control Register
#define REG_CPUCON2 (BASE_SFR_ADDR + 0x1A) ///< Core Control Register
#define REG_MAL     (BASE_SFR_ADDR + 0x5C) ///< MAC Accumulator – Low Word
#define REG_MAH     (BASE_SFR_ADDR + 0x5E) ///< MAC Accumulator – High Word

#define IDX0   0xFF08U ///< Address Pointer IDX0
#define IDX1   0xFF0AU ///< Address Pointer IDX1
#define SPSEG  0xFF0CU ///< Stack Pointer Segment Register
#define MDC    0xFF0EU ///< (Bit addressable) Multiply Divide Control Register
#define PSW    0xFF10U ///< (Bit addressable) Program Status Word
#define VECSEG 0xFF12U ///< (Bit addressable) Vector Table Segment Register
#define ZEROS  0xFF1CU ///< (Bit addressable) Constant Value 0s Register (read only)
#define ONES   0xFF1EU ///< (Bit addressable) Constant Value 1s Register (read only)
#define TFR    0xFFACU ///< (Bit addressable) Trap Flag Register
#define MRW    0xFFDAU ///< (Bit addressable) MAC Repeat Word
#define MCW    0xFFDCU ///< (Bit addressable) MAC Control Word
#define MSW    0xFFDEU ///< (Bit addressable) MAC Status Word

#define REG_ASC0_TIC 0xFF6CU ///< Serial Channel 0 Transmit Interrupt Control Register
#define REG_ASC0_RIC 0xFF6EU ///< Serial Channel 0 Receive Interrupt Control Register

#define baddr(base, reg) ((ut16)reg * 2 + base)
#define SFR_ADDR(reg) baddr(BASE_SFR_ADDR, reg)
#define ESFR_ADDR(reg) baddr(BASE_ESFR_ADDR, reg)

/*!
 * \brief C166 Branch Condition Codes
 *
 * Defines condition codes used for conditional branching instructions
 * Datasheet page 39
 * (*) Only usable with the JMPA and CALLA instructions
 */
// clang-format off
typedef enum {
	C166_CC_UC = 0x00,	///< CCNc = 0x00; [0D] Unconditional
	C166_CC_NET = 0x02,	///< CCNc = 0x01; [1D] Not equal AND not end of table
	// C166_CC_Z = 0x04,	///< CCNc = 0x02; [2D] Zero
	C166_CC_EQ = 0x04,	///< CCNc = 0x02; [2D] Equal
	// C166_CC_NZ = 0x06,	///< CCNc = 0x03; [3D] Not zero
	C166_CC_NE = 0x06,	///< CCNc = 0x03; [3D] Not equal
	C166_CC_V = 0x08,	///< CCNc = 0x04; [4D] Overflow
	C166_CC_NV = 0x0A,	///< CCNc = 0x05; [5D] No overflow
	C166_CC_N = 0x0C,	///< CCNc = 0x06; [6D] Negative
	C166_CC_NN = 0x0E,	///< CCNc = 0x07; [7D] Not negative
	C166_CC_C = 0x10,	///< CCNc = 0x08; [8D] Carry
	// C166_CC_ULT = 0x10,	///< CCNc = 0x08; [8D] Unsigned less than
	C166_CC_NC = 0x12,	///< CCNc = 0x09; [9D] No carry
	// C166_CC_UGE = 0x12,	///< CCNc = 0x09; [9D] Unsigned greater than or equal
	C166_CC_SGT = 0x14,	///< CCNc = 0x0A; [AD] Signed greater than
	C166_CC_SLE = 0x16,	///< CCNc = 0x0B; [BD] Signed less than or equal
	C166_CC_SLT = 0x18,	///< CCNc = 0x0C; [CD] Signed less than
	C166_CC_SGE = 0x1A,	///< CCNc = 0x0D; [DD] Signed greater than or equal
	C166_CC_UGT = 0x1C,	///< CCNc = 0x0E; [ED] Unsigned greater than
	C166_CC_ULE = 0x1E,	///< CCNc = 0x0F; [FD] Unsigned less than or equal

	C166_CC_NUSR0 = 0x01,     ///< USR-bit 0 is cleared (*)
	C166_CC_NUSR1 = 0x03,     ///< USR-bit 1 is cleared (*)
	C166_CC_USR0 = 0x05,      ///< USR-bit 0 is set 1
	C166_CC_USR1 = 0x07       ///< USR-bit 1 is set 1
} C166CondCode;

typedef enum {
	C166_EXT_MODE_NONE,
	C166_EXT_MODE_ATOMIC,
	C166_EXT_MODE_REG,
	C166_EXT_MODE_PAGE,
	C166_EXT_MODE_SEG,
} C166ExtMode;

// clang-format off
typedef struct {
	bool esfr;  		///< Extended register sequence active
	C166ExtMode mode; 	///< Extended page/seq mode
	ut8 i; 			///< Number of unstructions remaining until state exits
	ut16 value; 		///< Value of ext
} C166ExtState;

typedef struct {
	ut32 last_addr; 	///< State of last addr dissassembled
	C166ExtState ext;
	RzPVector /*<RzAsmTokenPattern *>*/ *token_patterns;
	bool inited;
} C166State;
// clang-format on

extern const char *const c166_rw[];
extern const char *const c166_rb[];
extern const char *const conds_names[];
extern const char *const c166_extx_names[];

const char *conds(ut8 cc);
const char *conds_extended(ut8 cc);
const char* c166_get_word_reg_name(const ut8 rb_index);
ut8 c166_get_byte_offset(const ut8 rb_index);

static inline bool IS_GPR(ut8 addr) {
	return addr >= 0xF0 && addr <= 0xFF;
}

static inline bool IS_RAM(ut8 addr) {
	return addr <= 0x7F;
}

static inline bool IS_rSFR(ut8 addr) {
	return addr <= 0xEF;
}

static inline bool IS_bSFR(ut8 addr) {
	return addr >= 0x80 && addr <= 0xEF;
}

#endif /* C166_COMMON_H */