// SPDX-FileCopyrightText: 2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "c166/c166_il.h"
#include <rz_il/rz_il_opbuilder_begin.h>

/**
 * All registers available as global IL variables
 */
static const char *c166_global_registers[] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9",
	"r10", "r11", "r12", "r13", "r14", "r15", "CSP",
	NULL
};

typedef RzILOpEffect *(*c166_il_op)(ut64 pc, RzAnalysis *analysis, const ut8 *buf);

static RzILOpEffect *c166_il_unk(ut64 pc, RzAnalysis *analysis, const ut8 *buf) {
	return rz_il_op_new_nop();
}

/**
 *
 * IF (CPUCON1.SGTDIS = 0) THEN
 *	(CSP) ← op1
 * END IF
 * (IP) ← op2
 *
 */

/**
 *
 * IF (CPUCON1.SGTDIS = 0) THEN
 *	(CSP) ← op1
 * END IF
 * (IP) ← op2
 *
 */
static RzILOpEffect *c166_il_jmps_seg_caddr(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	const ut8 seg = buf[1];
	const ut16 caddr = rz_read_at_le16(buf, 2);
	const ut32 to_addr = (((ut32)seg) << 16) | caddr;

#ifdef C166_DUPLICATE_REG_OPERATIONS
	const ut8 SGTDIS = (ut8)rz_reg_getv(analysis->reg, "SGTDIS");
	if (SGTDIS == 0) {
		rz_reg_setv(analysis->reg, "CSP", seg);
	}
	// rz_reg_setv(analysis->reg, "IP", (((ut32)seg) << 16) | caddr);
#endif

	RzILOpEffect *set_CSP = SETG("CSP", ITE(INV(VARG("SGTDIS")), U8(seg), U8(0)));
	RzILOpBitVector *_loc = UN(C166_ADDR_SIZE, to_addr);
	return SEQ2(set_CSP, JMP(_loc));
}

static c166_il_op c166_ops[256] = {
	c166_il_add_rwn_rwm, // 0x00
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_add_reg_data16, //
	c166_il_unk, //c166_il_addb_reg_data8, //
	c166_il_add_rwn_x, // 0x08
	c166_il_addb_rbn_x, // 0x09
	c166_il_bfldl_bitoff_x, // 0x0A 10
	c166_il_unk, //
	c166_il_unk, //
	c166_il_jmpr_cc_uc_rel, //
	c166_il_bclr_bitoff0, //
	c166_il_bset_bitoff0, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, // 20
	c166_il_unk, //
	c166_il_unk, //c166_il_addc_reg_data16, //
	c166_il_unk, //
	c166_il_addc_rwn_x, //
	c166_il_unk, //
	c166_il_bfldh_bitoff_x, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //30
	c166_il_unk, //c166_il_bset_bitoff1, //
	c166_il_unk, //c166_il_sub_rwn_rwm, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //c166_il_sub_reg_data16, //
	c166_il_unk, //
	c166_il_sub_rwn_x, //40
	c166_il_unk, //c166_il_subb_rbn_x, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, // C166_ROR_Rwn_Rwm
	c166_il_jmpr_cc_eq_or_z_rel, //
	c166_il_unk, //c166_il_bclr_bitoff2, //
	c166_il_unk, //c166_il_bset_bitoff2, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //50
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //c166_il_bmovn_bitaddr_bitaddr, //
	c166_il_unk, //
	c166_il_unk, //60
	c166_il_jmpr_cc_ne_or_nz_rel, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //c166_il_cmp_rwn_rwm, //
	c166_il_cmpb_rbn_rbm, //
	c166_il_unk, //c166_il_cmp_reg_mem, //
	c166_il_unk, //c166_il_cmpb_reg_mem, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //c166_il_cmp_reg_data16, //70
	c166_il_cmpb_reg_data8, //
	c166_il_unk, //c166_il_cmp_rwn_x, //
	c166_il_cmpb_rbn_x, //
	c166_il_unk, //
	c166_il_unk, //c166_il_div_rwn, //
	c166_il_shl_rwn_rwm, //
	c166_il_unk, //
	c166_il_unk, //c166_il_bclr_bitoff4, //
	c166_il_unk, //c166_il_bset_bitoff4, //
	c166_il_unk, //80
	c166_il_xorb_rbn_rbm, //
	c166_il_xor_reg_mem, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //90
	c166_il_unk, //
	c166_il_shl_rwn_data4, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //100
	c166_il_unk, //
	c166_il_and_reg_data16, //
	c166_il_unk, //
	c166_il_and_rwn_x, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_divl_rwn, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //110
	c166_il_bset_bitoff6, //
	c166_il_or_rwn_rwm, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_or_reg_data16, //
	c166_il_unk, //
	c166_il_or_rwn_x, //120
	c166_il_orb_rbn_x, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_shr_rwn_data4, //
	c166_il_jmpr_cc_nn_rel, //
	c166_il_unk, //c166_il_bclr_bitoff7, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //130
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //c166_il_mov_norwm_rwn, //
	c166_il_unk, //
	c166_il_jb_bitaddr_rel, //
	c166_il_unk, //
	c166_il_unk, //140
	c166_il_jmpr_cc_c_or_ult_rel, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_cpl_rwn, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //150
	c166_il_unk, //
	c166_il_mov_rwn_orwmp, //
	c166_il_unk, //
	c166_il_jnb_bitaddr_rel, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //160
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_diswdt, // 0xA5
	c166_il_unk, //
	c166_il_unk, //
	c166_il_mov_rwn_orwm, //
	c166_il_movb_rbn_oRwm, //
	c166_il_jbc_bitaddr_rel, //170
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk,
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //180
	c166_il_einit, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_mov_orwm_rwn, //
	c166_il_movb_orwm_rbn, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //c166_il_bclr_bitoff11, //190
	c166_il_unk, //c166_il_bset_bitoff11, //
	c166_il_movbz_rwn_rbm, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //c166_il_mov_orwm_data16_rwn, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //200
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //c166_il_jmpr_cc_slt_rel, //
	c166_il_unk,c166_il_unk, //
	c166_il_unk, //c166_il_movbs_rwn_rbm, //
	c166_il_unk, //c166_il_atomic_or_extr_irang2, //
	c166_il_unk, //210
	c166_il_unk, //
	c166_il_mov_rwn_orwm_data16, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_extp_or_exts_pag10_or_seg8_irang2, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_calls_seg_caddr, //
	c166_il_rets, //
	c166_il_extp_or_exts_rwm_irang2, //220
	c166_il_unk, //c166_il_jmpr_cc_sge_rel, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_mov_rwn_data4, // 0xE0
	c166_il_movb_rbn_data4, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_movb_orwm_data16_rbn, //
	c166_il_unk, //
	c166_il_mov_reg_data16, //230
	c166_il_unk, //c166_il_movb_reg_data8, //
	c166_il_unk, //c166_il_mov_orwn_orwmp, //
	c166_il_unk, //
	c166_il_unk, //c166_il_jmpa_cc_caddr, //
	c166_il_unk, //
	c166_il_push_reg, //
	c166_il_unk, //c166_il_jmpr_cc_ugt_rel, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_mov_rwn_rwm, //240
	c166_il_movb_rbn_rbm, //
	c166_il_unk, //
	c166_il_unk, //c166_il_movb_reg_mem, //
	c166_il_movb_rbn_orwm_data16, //
	c166_il_unk, //
	c166_il_mov_mem_reg, // 0xF6
	c166_il_unk, //c166_il_movb_mem_reg, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_jmps_seg_caddr, ///< C166_JMPS_seg_caddr = 0xFA 250
	c166_il_unk, // 0xFB
	c166_il_unk, //c166_il_pop_reg, // 0xFC
	c166_il_unk, // 0xFD
	c166_il_unk, // 0xFE
	c166_il_unk // 0xFF
};

RZ_IPI bool rz_c166_il_opcode(RzAnalysis *analysis, RzAnalysisOp *op, ut64 pc, const ut8 *buf) {
	rz_return_val_if_fail(analysis && op, false);

	const c166_il_op create_op = c166_ops[op->id];
	op->il_op = create_op(pc, analysis, buf, op);
	return true;
}

RZ_IPI RzAnalysisILConfig *rz_c166_il_config(RZ_NONNULL RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);

	RzAnalysisILConfig *r = rz_analysis_il_config_new(32, analysis->big_endian, C166_ADDR_SIZE);
	r->reg_bindings = c166_global_registers;
	return r;
}
#include <rz_il/rz_il_opbuilder_end.h>