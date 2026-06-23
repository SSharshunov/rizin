// SPDX-FileCopyrightText: 2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZIL_ANALYSIS_C166_H
#define RZIL_ANALYSIS_C166_H

#include "analysis_private.h"
// #include <rz_core.h>
#include <rz_types.h>

#define C166_SP_SIZE   16
#define C166_CSP_SIZE  16

#define C166_SP      "SP"
#define C166_CSP      "CSP"

#define C166_DUPLICATE_REG_OPERATIONS 1



// #define R1V   VARG(R1)
// #define R2V   VARG(R2)

// #define C166_ADDR_SIZE 24
#define C166_ADDR_SIZE 32 // should be 24 bits max, but we can ignore this

// RZ_IPI bool rz_c166_il_opcode(RzAnalysis *analysis, RzAnalysisOp *op, ut64 pc, AVROp *aop, AVROp *next_op);
RZ_IPI bool rz_c166_il_opcode(RzAnalysis *analysis, RzAnalysisOp *op, ut64 pc, const ut8 *buf);
RZ_IPI RzAnalysisILConfig *rz_c166_il_config(RZ_NONNULL RzAnalysis *analysis);

#endif // RZIL_ANALYSIS_C166_H
