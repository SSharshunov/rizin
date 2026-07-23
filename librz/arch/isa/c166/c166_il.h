// SPDX-FileCopyrightText: 2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZIL_ANALYSIS_C166_H
#define RZIL_ANALYSIS_C166_H

#include "analysis_private.h"
#include <rz_types.h>

// #define C166_ADDR_SIZE 24
#define C166_ADDR_SIZE 32 // should be 24 bits max, but we can ignore this

#define C166_SP_SIZE  16
#define C166_CSP_SIZE 16

#define C166_SP  "SP"
#define C166_CSP "CSP"

// #define C166_DUPLICATE_REG_OPERATIONS 1

#define SET_E2(x) \
	SETG("e", \
		ITE( \
			AND( \
				SLT(DUP(x), U16(0)), \
				EQ(DUP(x), NEG(DUP(x)))), \
			IL_TRUE, IL_FALSE))

#define SET_E3(x) \
	SETG("e", \
		INV(AND( \
			SLT(DUP(x), U16(0)), \
			EQ(DUP(x), NEG(DUP(x))))))
#define SET_E4(x)    SETG("e", MSB(DUP(x)))
#define SET_Ex(x, b) SETG("e", ITE(EQ(DUP(x), U16(1 << (b - 1))), IL_TRUE, IL_FALSE))
// #define SET_E(x) SETG("e", ITE(EQ(DUP(x), U16(1 << 15)), IL_TRUE, IL_FALSE))
#define SET_E(x)  SET_Ex(x, 16)
#define SET_E8(x) SET_Ex(x, 8)
#define SET_Z(x)  SETG("z", ITE(IS_ZERO(DUP(x)), IL_TRUE, IL_FALSE))
#define SET_N(x)  SETG("n", MSB(DUP(x)))
#define SET_C(x)  SETG("c", ITE(EQ(DUP(x), U16(0xFFFF)), IL_TRUE, IL_FALSE))
#define SET_C8(x) SETG("c", ITE(EQ(DUP(x), U8(0xFF)), IL_TRUE, IL_FALSE))
// #define SET_C8(x) SETG("c", ITE(EQ(UNSIGNED(8, DUP(x)), U8(0xFF)), IL_TRUE, IL_FALSE))

#define E_FALSE SETG("e", IL_FALSE)
#define E_TRUE  SETG("e", IL_TRUE)
#define V_FALSE SETG("v", IL_FALSE)
#define V_TRUE  SETG("v", IL_TRUE)
#define Z_FALSE SETG("z", IL_FALSE)
#define Z_TRUE  SETG("z", IL_TRUE)
#define C_FALSE SETG("c", IL_FALSE)
#define C_TRUE  SETG("c", IL_TRUE)
#define N_FALSE SETG("n", IL_FALSE)

#define IL_UN(l, x) rz_il_value_new_bitv(rz_bv_new_from_ut64(l, x))
#define IL_U8(x)    IL_UN(8, x)
#define IL_U16(x)   IL_UN(16, x)
#define IL_U32(x)   IL_UN(32, x)

// #define READ_RL(x) LOGAND(VARG(x), U16(0xFF))
#define READ_RL(x) LOGAND(x, U16(0xFF))
#define READ_RH(x) SHIFTR0(VARG(x), U16(8))

#define WRITE_RL2(r, v) \
	SEQ5( \
		SETL("r", VARG(r)), \
		SETL("rl", READ_RL(VARL("r"))), \
		SETL("rl", LOGAND(VARL("rl"), U16(0xFF))), /*SETG(r, LOGOR(VARL("r"), U16(0xFF00)))*/ \
		SETL("val", LOGAND(v, U16(0xFF))), \
		SETG(r, LOGOR(VARL("r"), VARL("val"))))
#define WRITE_RL(r, v) \
	SEQ4( \
		SETL("r", VARG(r)), \
		SETL("rh", LOGAND(VARL("r"), U16(0xFF00))), \
		SETL("val", READ_RL(v)), \
		SETG(r, LOGOR(VARL("rh"), VARL("val"))))

#define WRITE_RH(r, v) READ_RH(x)

#define SP_SET_VAL8  STORE(UNSIGNED(32, VARL("SP")), UNSIGNED(32, VARL("SP")))
#define SP_SET_VAL16 STORE(UNSIGNED(32, VARL("SP")), UNSIGNED(32, VARL("SP")))

#define SP_GET_VAL8  LOADW(8, UNSIGNED(32, VARL("SP")))
#define SP_GET_VAL16 LOADW(16, UNSIGNED(32, VARL("SP")))
#define SP_DEC       SUB(VARL("SP"), U16(2))
#define SP_INC       ADD(VARL("SP"), U16(2))

typedef RzILOpEffect *(*c166_il_op)(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op);

RZ_IPI bool rz_c166_il_opcode(RzAnalysis *analysis, RzAnalysisOp *op, ut64 pc, const ut8 *buf);
RZ_IPI RzAnalysisILConfig *rz_c166_il_config(RZ_NONNULL RzAnalysis *analysis);

#endif // RZIL_ANALYSIS_C166_H
