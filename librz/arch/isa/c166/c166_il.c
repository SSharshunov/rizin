// SPDX-FileCopyrightText: 2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "c166/c166_il.h"
#include "c166_common.h"

/**
 * All registers available as global IL variables
 */
static const char *c166_global_registers[] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9",
	"r10", "r11", "r12", "r13", "r14", "r15",
	"IP",
	"DPP0", "DPP1", "DPP2", "DPP3",
	"SP",
	// "STKUN", "STKOV", "",
	"CSP", "SGTDIS", //"CP",
	"e", "z", "v", "c", "n",
	"BUSCON0", "SYSCON",
	"PSW", "P8", //"FOCON", "P7",
	NULL
};

#include <rz_il/rz_il_opbuilder_begin.h>

static RzILOpBool *check_condition(const ut8 condition) {
	RzILOpBool *cond = NULL;
	switch (condition << 1) {
	case C166_CC_UC:
		cond = IL_TRUE;
		break;
	case C166_CC_EQ:
		cond = ITE(VARG("z"), IL_TRUE, IL_FALSE);
		break;
	case C166_CC_NE:
		cond = INV(VARG("z"));
		break;
	case C166_CC_N:
		cond = VARG("n");
		break;
	case C166_CC_NN:
		cond = INV(VARG("n"));
		break;
	case C166_CC_C:
		cond = VARG("c");
		break;
	case C166_CC_NC:
		cond = INV(VARG("c"));
		break;
	case C166_CC_NET:
	case C166_CC_V:
	case C166_CC_NV:
	case C166_CC_SGT:
	case C166_CC_SLE:
	case C166_CC_SLT:
	case C166_CC_SGE:
	case C166_CC_UGT:
	case C166_CC_ULE:
	default:
		rz_warn_if_reached();
	}
	return cond;
}

RzILOpEffect *bfld_flags_seq(RzILOpBitVector *result) {
	return SEQ5(E_FALSE, SET_Z(result), V_FALSE, C_FALSE, SET_N(result));
}

const char *c166_instr_name(ut8 instr);
static RzILOpEffect *c166_il_unk(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	const char *op_name = c166_instr_name(op->id);
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_unk %s\n", op->id, pc, IP, op_name);
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_lifted_nop(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	const char *op_name = c166_instr_name(op->id);
	RZ_LOG_DEBUG("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_lifted_nop %s\n", op->id, pc, IP, op_name);
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_add_rwn_rwm(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	const ut8 m = L_NIB(buf[1]);
	const ut8 n = H_NIB(buf[1]);
	const char* dst = c166_global_registers[n];
	const char* src = c166_global_registers[m];
	return SEQ8(
		SETL("val", VARG(src)),
		SETL("res", ADD(VARG(dst), VARL("val"))),
		SETG(dst, VARL("res")),
		SET_E(VARL("val")),
		SET_Z(VARL("res")),
		V_FALSE,
		SET_C(VARL("res")),
		SET_N(VARL("res"))
	);
}

static RzILOpEffect *c166_il_bclr_bitoff4(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_bclr_bitoff4\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_bset_bitoff4(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_bset_bitoff4\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_xorb_rbn_rbm(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	const ut8 n = H_NIB(buf[1]);
	const ut8 m = L_NIB(buf[1]);
	const char *src = c166_get_word_reg_name(m);
	const char *dst = c166_get_word_reg_name(n);
	return SEQN(5,
		SETL("op1", READ_RL(VARG(src))),
		SETL("op2", READ_RL(VARG(dst))),
		SETL("op2", LOGXOR(VARL("op1"), VARL("op2"))),
		WRITE_RL(dst, UNSIGNED(16, VARL("op2"))),
		SEQ5(SET_E(VARL("op2")), SET_Z(VARL("op2")), V_FALSE, C_FALSE, SET_N(VARL("op2")))
	);
}
static RzILOpEffect *c166_il_xor_reg_mem(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_xor_reg_mem\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}
static RzILOpEffect *c166_il_shl_rwn_data4(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_shl_rwn_data4\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_div_rwn(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_div_rwn\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_cmpb_rbn_rbm(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_cmpb_rbn_rbm\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}

/**
static RzILOpEffect *c166_il_cmp_reg_mem(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_cmp_reg_mem\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_cmpb_reg_mem(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_cmpb_reg_mem\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_cmp_reg_data16(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_cmp_reg_data16\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}
**/

static RzILOpEffect *c166_il_cmpb_reg_data8(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	const ut8 reg = buf[1];
	const ut16 data = rz_read_at_le16(buf, 2);
	const char *dst = c166_get_word_reg_name(L_NIB(reg));

	return SEQN(10,
		SETL("op1", UNSIGNED(8, READ_RL(VARG(dst)))),
		SETL("op2", U8(data & 0xFF)),
		SETL("res",
			ITE(
				ULT(VARL("op1"), VARL("op2")),
				SUB(UNSIGNED(16, VARL("op1")), UNSIGNED(16, VARL("op2"))),
				SUB(VARL("op1"), VARL("op2"))
			)
		),
		SETG("r14", UNSIGNED(16, VARL("op1"))),
		SETG("r15", UNSIGNED(16, VARL("res"))),
		SET_E8(VARL("op2")),
		SETG("z", ITE(EQ(VARL("op1"), VARL("op2")), IL_TRUE, IL_FALSE)),
		SETG("c", ITE(ULT(VARL("op1"), VARL("op2")), IL_TRUE, IL_FALSE)),
		SETG("v", ITE(EQ(VARL("res"), U8(0xFF)), IL_TRUE, IL_FALSE)),
		SET_N(VARL("res"))
	);
}

/**
static RzILOpEffect *c166_il_cmp_rwn_x(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_cmp_rwn_x\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}
**/

static RzILOpEffect *c166_il_cmpb_rbn_x(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_cmpb_rbn_x nop\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}

RzILOpEffect *mov_flags_seq(RzILOpBitVector *data) {
	RzILOpEffect *e = SET_E(data);
	RzILOpEffect *z = SET_Z(data);
	RzILOpEffect *n = SET_N(data);
	return SEQ3(e, z, n);
}

static RzILOpEffect *c166_il_mov_rwn_orwm(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	const C166State *state = (C166State *)analysis->plugin_data;
	if (!state) {
		RZ_LOG_FATAL("C166State was NULL.");
		return rz_il_op_new_nop();
	}
	const ut8 reg = buf[1];
	const char *src = c166_global_registers[L_NIB(reg)];
	const char *dst = c166_global_registers[H_NIB(reg)];

	if (state->ext.esfr && state->ext.mode == C166_EXT_MODE_REG) {
		const char *ext_reg_name = c166_global_registers[state->ext.value];
		return SEQN(7,
			SETL("seg", UNSIGNED(32, VARG(ext_reg_name))),
			SETL("seg", SHIFTL0(VARL("seg"), U16(16))),
			SETL("src_op", VARG(src)),
			SETL("addr", LOGOR(VARL("seg"), UNSIGNED(32, VARL("src_op")))),
			SETL("load", LOADW(16, VARL("addr"))),
			SETG(dst, UNSIGNED(16, VARL("load"))),
			SEQ3(SET_E(VARL("load")), SET_Z(VARL("load")), SET_N(VARL("load")))
		);
	}
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_mov_rwn_orwm unk\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}

/**
 * (count) ← 0
 * DO WHILE ((count) <8)
 *	IF op2[(count)] = 1
 *		(op1[(count)]) ← op3[(count)]
 *	ENDIF
 * (count) ← (count) + 1
 * END WHILE
 *
 */
static RzILOpEffect *c166_il_bfldl_bitoff_x(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	const ut8 bitoff = buf[1];
	const ut8 mask8 = buf[2]; // #mask8  ##
	const ut8 data8 = buf[3]; // #data8  @@
	if (IS_RAM(bitoff)) {
		const ut16 addr = BASE_RAM_B_ADDR + (2 * bitoff);
		RzILOpBitVector *load = LOAD(U16(addr));
		RzILOpEffect *bfld = STORE(U16(addr), load);
		return SEQ2(bfld_flags_seq(load), bfld);
	}
	if (IS_bSFR(bitoff)) {
		const C166State *state = (C166State *)analysis->plugin_data;
		if (!state) {
			RZ_LOG_FATAL("C166State was NULL.");
			return rz_il_op_new_nop();
		}
		const ut16 base_addr = state->ext.esfr ? BASE_ESFR_B_ADDR : BASE_SFR_B_ADDR;
		const ut16 addr = base_addr + (2 * (bitoff & 0x7F));
		const RzPlatformTarget *arch_target = rz_analysis_get_arch_target(analysis);
		const char *resolved = rz_platform_profile_resolve_mmio(arch_target->profile, addr);
		if (!resolved) {
			return rz_il_op_new_nop();
		}

		RzILOpBitVector *val = UNSIGNED(16, DUP(LOGAND(U8(data8), U8(mask8))));
		RzILOpPure *src = VARG(resolved);
		RzILOpBitVector *result = LOGOR(src, val);
		RzILOpEffect *bfld = SETG(resolved, result);
		return SEQ2(bfld_flags_seq(result), bfld);
	}

	return bfld_flags_seq(U16(buf[3]));
}
static RzILOpEffect *c166_il_bfldh_bitoff_x(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	const ut8 bitoff = buf[1];
	const ut8 mask8 = buf[3]; // #mask8  ##
	const ut8 data8 = buf[2]; // #data8  @@
	if (IS_GPR(bitoff)) {
		const RzILOpPure *dst = VARG(c166_rw[L_NIB(bitoff)]);
		(void)dst;
	}
	if (IS_bSFR(bitoff)) {
		const C166State *state = (C166State *)analysis->plugin_data;
		if (!state) {
			RZ_LOG_FATAL("C166State was NULL.");
			return rz_il_op_new_nop();
		}
		const ut16 base_addr = state->ext.esfr ? BASE_ESFR_B_ADDR : BASE_SFR_B_ADDR;
		const ut16 addr = base_addr + (2 * (bitoff & 0x7F));
		const RzPlatformTarget *arch_target = rz_analysis_get_arch_target(analysis);
		const char *resolved = rz_platform_profile_resolve_mmio(arch_target->profile, addr);
		if (!resolved) {
			return rz_il_op_new_nop();
		}

		RzILOpBitVector *mask = U16(~(mask8 << 8));
		RzILOpBitVector *tval = LOGAND(VARG(resolved), DUP(mask));
		RzILOpBitVector *tval2 = LOGAND(U16(data8 << 8), DUP(mask));
		RzILOpBitVector *result = LOGOR(tval, tval2);
		RzILOpEffect *bfld = SETG(resolved, result);
		return SEQ2(bfld_flags_seq(result), bfld);
	}
	return bfld_flags_seq(U16(buf[3]));
}

static RzILOpEffect *c166_il_movb_rbn_oRwm(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	const C166State *state = (C166State *)analysis->plugin_data;
	if (!state) {
		RZ_LOG_FATAL("C166State was NULL.");
		return rz_il_op_new_nop();
	}
	const ut8 n = H_NIB(buf[1]);
	const ut8 m = L_NIB(buf[1]);
	if (state->ext.esfr && state->ext.mode == C166_EXT_MODE_REG) {
		const char *ext_reg_name = c166_global_registers[state->ext.value];
		const char *src = c166_rw[m];
		const char *dst = c166_get_word_reg_name(n);
		const ut8 reg_offset = c166_get_byte_offset(n);
		return SEQN(8,
			SETL("seg", UNSIGNED(32, VARG(ext_reg_name))),
			SETL("seg", SHIFTL0(VARL("seg"), U16(16))),
			SETL("src_op", VARG(src)),
			SETL("addr", LOGOR(VARL("seg"), UNSIGNED(32, VARL("src_op")))),
			SETL("load", LOADW(16, VARL("addr"))),
			SETL("reg_offset", U8(reg_offset)),
			WRITE_RL(dst, UNSIGNED(16, VARL("load"))),
			SEQ3(SET_E(VARL("load")), SET_Z(VARL("load")), SET_N(VARL("src_op")))
		);
	}
	return rz_il_op_new_nop();
}
static RzILOpEffect *c166_il_jnb_bitaddr_rel(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	const ut8 qq = buf[1];
	const ut8 rr = buf[2];
	const ut8 op3 = buf[3];
	const ut8 q = H_NIB(op3);
	const char *reg = NULL;
	const ut32 addr = (ut32)pc + C166_BYTESIZE_4 + (2 * (st8)rr);
	if (IS_GPR(qq)) {
		reg = c166_rw[L_NIB(qq)];
		// printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_jnb_bitaddr_rel %s.%i, 0x%06x\n",
		// op->id, pc, IP, c166_rw[L_NIB(qq)], q, addr);
	}
	if (IS_bSFR(qq)) {
		const C166State *state = (C166State *)analysis->plugin_data;
		if (!state) {
			RZ_LOG_FATAL("C166State was NULL.");
			return rz_il_op_new_nop();
		}
		const ut16 base_addr = state->ext.esfr ? BASE_ESFR_B_ADDR : BASE_SFR_B_ADDR;
		const ut16 bitaddr = base_addr + (2 * (qq & 0x7F));
		printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_jnb_bitaddr_rel 0x%04x.%i, 0x%06x  new_IP: [0x%06x]\n",
		op->id, pc, IP, bitaddr, q, addr, addr);
	}
	RzILOpBitVector *mask = U16(1 << q);

	RzILOpBitVector *_iar = LOGAND(VARG(reg), mask);
	_iar = SHIFTR0(_iar, U16(q));

	RzILOpBool *cond = IS_ZERO(_iar);
	return BRANCH(DUP(cond), JMP(U32(addr)), NOP());
}

static RzILOpEffect *c166_il_and_reg_data16(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	const ut8 reg = buf[1];
	const ut16 data = rz_read_at_le16(buf, 2);
	const char* op1 = NULL;
	const C166State *state = (C166State *)analysis->plugin_data;
	if (!state) {
		RZ_LOG_FATAL("C166State was NULL.");
		return rz_il_op_new_nop();
	}
	if (IS_GPR(reg)) {
		// Short ‘reg’ addresses from F0 to FF always specify GPRs.
		op1 = c166_rw[L_NIB(reg)];
		RzILOpBitVector *val = LOGAND(VARG(op1), U16(data));
		return SEQ6(SET_E(val), SET_Z(val), V_FALSE, C_FALSE, SET_N(val), SETG(op1, val));
	}
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_jb_bitaddr_rel(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	const ut8 qq = buf[1];
	const ut8 rr = buf[2];
	const ut8 op3 = buf[3];
	const ut8 q = H_NIB(op3);
	const char *reg = NULL;
	const ut32 addr = pc + C166_BYTESIZE_4 + (2 * ((st8)rr));
	if (IS_GPR(qq)) {
		reg = c166_rw[L_NIB(qq)];
		// printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_jb_bitaddr_rel %s.%i, 0x%06x\n",
		// op->id, pc, IP, c166_rw[L_NIB(qq)], q, addr);
	}
	if (IS_RAM(qq)) {
		printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_jb_bitaddr_rel 0x%04x.%i, 0x%06x\n",
		op->id, pc, IP, BASE_RAM_B_ADDR + (2 * qq), q, addr);
	}
	if (IS_bSFR(qq)) {
		const C166State *state = (C166State *)analysis->plugin_data;
		if (!state) {
			RZ_LOG_FATAL("C166State was NULL.");
			return rz_il_op_new_nop();
		}
		const ut16 base_addr = state->ext.esfr ? BASE_ESFR_B_ADDR : BASE_SFR_B_ADDR;
		const ut16 bitaddr = base_addr + (2 * (qq & 0x7F));
		printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_jb_bitaddr_rel 0x%04x.%i, 0x%06x  new_IP: [0x%06x]\n",
		op->id, pc, IP, bitaddr, q, addr, addr);
	}
	RzILOpBitVector *mask = U16(1 << q);

	RzILOpBitVector *_iar = LOGAND(VARG(reg), mask);
	_iar = SHIFTR0(_iar, U16(q));

	RzILOpBool *cond = NON_ZERO(_iar);
	return BRANCH(DUP(cond), JMP(U32(addr)), NOP());
}

static RzILOpEffect *c166_il_or_reg_data16(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	const ut8 reg = buf[1];
	const ut16 data = rz_read_at_le16(buf, 2);
	const char* op1 = NULL;
	const C166State *state = (C166State *)analysis->plugin_data;
	if (!state) {
		RZ_LOG_FATAL("C166State was NULL.");
		return rz_il_op_new_nop();
	}
	if (IS_GPR(reg)) {
		// Short ‘reg’ addresses from F0 to FF always specify GPRs.
		op1 = c166_rw[L_NIB(reg)];
		RzILOpBitVector *val = LOGOR(VARG(op1), U16(data));
		return SEQ6(SET_E(U16(data)), SET_Z(val), V_FALSE, C_FALSE, SET_N(val), SETG(op1, val));
	}
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_or_rwn_x(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_or_rwn_x\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_orb_rbn_x(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_orb_rbn_x nop\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_bmovn_bitaddr_bitaddr(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_bmovn_bitaddr_bitaddr nop\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_cmp_rwn_rwm(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_cmp_rwn_rwm nop\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_addc_rwn_x(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	const ut8 reg = L_NIB(buf[1]);
	const char* src = c166_global_registers[H_NIB(buf[1])];
	RzILOpBitVector *val = NULL;
	RzILOpEffect *add = NULL;
	if ((reg & 0b1100) == 0b1100) {
		printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_addc_rwn_x r%i, [r%i+]\n",
			op->id, pc, IP, H_NIB(reg), reg & 0b1);
	} else if ((reg & 0b1000) == 0b1000) {
		printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_addc_rwn_x r%i, [r%i]\n",
			op->id, pc, IP, H_NIB(reg), reg & 0b11);
	} else {
		val = ADD(VARG(src), U16(L_NIB(reg)));
		add = SETG(src, val);
	}
	RzILOpEffect *e = SETG("e", ITE(EQ(VARG(src), S16(0x8000)), IL_TRUE, IL_FALSE));
	RzILOpEffect *z = SETG("z", ITE(IS_ZERO(DUP(val)), IL_TRUE, IL_FALSE));
	RzILOpEffect *v = SETG("v", IL_FALSE);
	RzILOpEffect *c = SETG("c", IL_FALSE);
	RzILOpEffect *n = SETG("n", MSB(DUP(val)));

	RzILOpEffect *add_flags_seq = SEQ5(e, z, v, c, n);
	return SEQ2(add, add_flags_seq);
}

static RzILOpEffect *c166_il_sub_rwn_x(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	const ut8 reg = L_NIB(buf[1]);
	const char* src = c166_global_registers[H_NIB(buf[1])];
	RzILOpBitVector *val = NULL;
	RzILOpEffect *sub = NULL;
	RzILOpEffect *e = NULL;
	RzILOpEffect *z = NULL;
	RzILOpEffect *n = NULL;
	RzILOpEffect *c = NULL;
	if ((reg & 0b1100) == 0b1100) {
		printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_sub_rwn_x r%i, [r%i+]\n",
			op->id, pc, IP, H_NIB(reg), reg & 0b1);
		e = SETG("e", ITE(EQ(U16(0), S16(0x8000)), IL_TRUE, IL_FALSE));
		z = SETG("z", ITE(IS_ZERO(DUP(val)), IL_TRUE, IL_FALSE));
		n = SET_N(val);
		c = SETG("c", IL_FALSE); // TODO ?????
	} else if ((reg & 0b1000) == 0b1000) {
		printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_sub_rwn_x r%i, [r%i]\n",
			op->id, pc, IP, H_NIB(reg), reg & 0b11);
		e = SETG("e", ITE(EQ(U16(0), S16(0x8000)), IL_TRUE, IL_FALSE));
		z = SETG("z", ITE(IS_ZERO(DUP(val)), IL_TRUE, IL_FALSE));
		n = SET_N(val);
		c = SETG("c", IL_FALSE); // TODO ?????
	} else {
		const ut8 data = L_NIB(reg) & 0x7; ///< n:0###
		// printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_sub_rwn_x r%i, #%x\n",
		// 	op->id, pc, IP, H_NIB(buf[1]), data);
		sub = SEQ3(
			SETL("val", VARG(src)),
			SETL("val", SUB(VARL("val"), U16(data))),
			SETG(src, VARL("val"))
		);
		e = SET_E(U16(data));
		z = SET_Z(VARL("val"));
		n = SET_N(VARL("val"));
		c = SET_C(VARL("val")); // TODO ?????
	}

	RzILOpEffect *v = SETG("v", IL_FALSE); // TODO ?????


	RzILOpEffect *sub_flags_seq = SEQ5(e, z, v, c, n);
	return SEQ2(sub, sub_flags_seq);
}

/**
static RzILOpEffect *c166_il_subb_rbn_x(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_subb_rbn_x\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_sub_reg_data16(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_sub_reg_data16\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}
**/

static RzILOpEffect *c166_il_movb_orwm_rbn(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	const C166State *state = (C166State *)analysis->plugin_data;
	if (!state) {
		RZ_LOG_FATAL("C166State was NULL.");
		return rz_il_op_new_nop();
	}
	const ut8 n = H_NIB(buf[1]);
	const ut8 m = L_NIB(buf[1]);
	const char *src = c166_get_word_reg_name(n);
	const ut8 reg_offset = c166_get_byte_offset(n);
	if (state->ext.esfr && state->ext.mode == C166_EXT_MODE_REG) {
		const char *dst = c166_rw[m];
		return SEQN(7,
			SETL("addr", UNSIGNED(32, VARG(dst))),
			SETL("val", VARG(src)),
			SETL("reg_offset", U8(reg_offset)),
			SETL("val",
				ITE(NON_ZERO(VARL("reg_offset")),
					SHIFTL0(VARL("val"), VARL("reg_offset")),
					VARL("val")
				)),
			STORE(VARL("addr"), UNSIGNED(8, VARL("val"))),
			SETL("src_op", U8(n)),
			SEQ3(SET_E(UNSIGNED(8, VARL("val"))), SET_Z(VARL("val")), SET_N(VARL("src_op")))
		);
	}
	const char *dst = c166_global_registers[m];
	return SEQN(7,
		SETL("addr", UNSIGNED(32, VARG(dst))),
		SETL("val", VARG(src)),
		SETL("reg_offset", U8(reg_offset)),
		SETL("val",
			ITE(NON_ZERO(VARL("reg_offset")),
				LOGAND(VARL("val"), U16(0xFF)),
				VARL("val")
			)),
		STORE(VARL("addr"), UNSIGNED(8, VARL("val"))),
		SETL("src_op", U8(n)),
		SEQ3(SET_E(UNSIGNED(8, VARL("val"))), SET_Z(VARL("val")), SET_N(VARL("src_op")))
	);
}

static RzILOpEffect *c166_il_movbz_rwn_rbm(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	// ut64 IP = rz_reg_getv(analysis->reg, "IP");
	const ut8 m = H_NIB(buf[1]);
	const ut8 n = L_NIB(buf[1]);

	const char *dst = c166_global_registers[n];
	const char *src = c166_get_word_reg_name(m);

	// printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_movbz_rwn_rbm %s %s\n", op->id, pc, IP, c166_rw[n], c166_rb[m]);
	return SEQN(3,
		SETL("val", READ_RL(VARG(src))),
		SETG(dst, VARL("val")),
		SEQ3(E_FALSE, SET_Z(VARL("val")), N_FALSE));
}

/**
static RzILOpEffect *c166_il_mov_orwm_data16_rwn(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_mov_orwm_data16_rwn\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_bclr_bitoff11(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_bclr_bitoff11\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_bset_bitoff11(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_bset_bitoff11\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}
**/

static RzILOpEffect *c166_il_mov_orwm_rwn(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_mov_orwm_rwn\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}
static RzILOpEffect *c166_il_cpl_rwn(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_cpl_rwn\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}
static RzILOpEffect *c166_il_shr_rwn_data4(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_shr_rwn_data4\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}

/**
static RzILOpEffect *c166_il_mov_norwm_rwn(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_mov_norwm_rwn\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}
**/

static RzILOpEffect *c166_il_and_rwn_x(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_and_rwn_x nop\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}
static RzILOpEffect *c166_il_divl_rwn(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_divl_rwn\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}
static RzILOpEffect *c166_il_shl_rwn_rwm(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_shl_rwn_rwm\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}
static RzILOpEffect *c166_il_bclr_bitoff0(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_bclr_bitoff0\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}
static RzILOpEffect *c166_il_bset_bitoff0(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_bset_bitoff0 nop\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}

/**
static RzILOpEffect *c166_il_addc_reg_data16(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_addc_reg_data16\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}
**/

static RzILOpEffect *c166_il_add_rwn_x(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	// 08 n:11ii
	const ut8 reg = L_NIB(buf[1]);
	const ut8 n = H_NIB(buf[1]);
	const char* dst = c166_global_registers[n];
	RzILOpBitVector *val = NULL;
	RzILOpEffect *add = NULL;
	RzILOpEffect *op1 = SETL("op1", VARG(dst));
	RzILOpEffect *e = NULL;
	if ((reg & 0b1100) == 0b1100) {
		printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_add_rwn_x r%i, [r%i+]\n",
			op->id, pc, IP, H_NIB(reg), reg & 0b1);
		e = SET_E(VARL("op1"));
	} else if ((reg & 0b1000) == 0b1000) {
		printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_add_rwn_x r%i, [r%i]\n",
			op->id, pc, IP, H_NIB(reg), reg & 0b11);
		e = SET_E(VARL("op1"));
	} else {
		val = ADD(VARL("op1"), U16(reg & 0x7));
		add = SETG(dst, val);
		e = SET_E(U16(reg & 0x7));
	}

	RzILOpEffect *add_flags_seq = SEQ5(e, SET_Z(val), V_FALSE, C_FALSE, SET_N(val));
	return SEQ3(op1, add, add_flags_seq);
}
static RzILOpEffect *c166_il_addb_rbn_x(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	// ut64 IP = rz_reg_getv(analysis->reg, "IP");
	// 08 n:11ii
	const ut8 reg = L_NIB(buf[1]);
	const ut8 n = H_NIB(buf[1]);
	const char *dst = c166_get_word_reg_name(n);
	RzILOpBitVector *val = NULL;
	RzILOpEffect *add = NULL;
	RzILOpEffect *op1 = SETL("op1", VARG(dst));
	RzILOpEffect *e = NULL;
	if ((reg & 0b1100) == 0b1100) {
		// printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_addb_rbn_x r%i, [r%i+]\n",
		// 	op->id, pc, IP, H_NIB(reg), reg & 0b1);
		e = SET_E(VARL("op1"));
	} else if ((reg & 0b1000) == 0b1000) {
		// printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_addb_rbn_x r%i, [r%i]\n",
		// 	op->id, pc, IP, H_NIB(reg), reg & 0b11);
		e = SET_E(VARL("op1"));
	} else {
		// printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_addb_rbn_x %s, #0x%04x\n",
		// 	op->id, pc, IP, c166_rb[n], reg & 0x7);
		val = ADD(READ_RL(VARL("op1")), U16(reg & 0x7));
		add = WRITE_RL(dst, val);
		e = SET_E(U16(reg & 0x7));
	}

	RzILOpEffect *add_flags_seq = SEQ5(e, SET_Z(val), V_FALSE, C_FALSE, SET_N(val));
	return SEQ3(op1, add, add_flags_seq);
}

static RzILOpEffect *c166_il_add_reg_data16(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	const ut8 reg = buf[1];
	const ut16 data = rz_read_at_le16(buf, 2);
	if (IS_GPR(reg)) {
		// Short ‘reg’ addresses from F0 to FF always specify GPRs.
		// return byte ? c166_rb[L_NIB(reg)] : c166_rw[L_NIB(reg)];
		// printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_add_reg_data16 %s, #0x%04x\n",
		// 	op->id, pc, IP, c166_rw[L_NIB(reg)], data);
		const char* dst = c166_global_registers[L_NIB(reg)];
		RzILOpBitVector *val = ADD(VARL("op1"), U16(data));
		return SEQ3(
			SETL("op1", VARG(dst)),
			SETG(dst, val),
			SEQ5(
				SET_E(U16(data)),
				SET_Z(val),
				V_FALSE,
				C_FALSE,
				SET_N(val)
			)
		);
	}
	const C166State *state = (C166State *)analysis->plugin_data;
	if (!state) {
		RZ_LOG_FATAL("C166State was NULL.");
		return rz_il_op_new_nop();
	}
	const ut16 addr = state->ext.esfr ? ESFR_ADDR(reg) : SFR_ADDR(reg);
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_add_reg_data16 0x%04x, #0x%04x\n",
		op->id, pc, IP, addr, data);
	return rz_il_op_new_nop();
}

/**
static RzILOpEffect *c166_il_addb_reg_data8(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_addb_reg_data8\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}
**/

/*
 * (IP) ← ((SP))
 * (SP) ← (SP) + 2
 * IF (CPUCON1.SGTDIS = 0) THEN
 *	(CSP) ← ((SP))
 * END IF
 * (SP) ← (SP) + 2
 */
static RzILOpEffect *c166_il_rets(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	return SEQN(6,
		SETL("SP", VARG("SP")),
		SETL("addr", SP_GET_VAL16),
		SETL("SP", SP_INC),
		BRANCH(INV(VARG("SGTDIS")),
			SETG("CSP", SP_GET_VAL8),
			NOP()
		),
		SETG("SP", SP_INC),
		JMP(UNSIGNED(32, VARL("addr")))
	);
}

/*
*	(IP) ← ((SP))
*	(SP) ← (SP) + 2
*	(tmp) ← ((SP))
*	(SP) ← (SP) + 2
*	(op1) ← (tmp)
*
 */
static RzILOpEffect *c166_il_retp(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	const ut8 reg = buf[1];
	if (IS_GPR(reg)) {
		// Short ‘reg’ addresses from F0 to FF always specify GPRs.
		printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_retp %s\n",
			op->id, pc, IP, c166_rw[L_NIB(reg)]);
		return rz_il_op_new_nop();
	}
	const C166State *state = (C166State *)analysis->plugin_data;
	if (!state) {
		RZ_LOG_FATAL("C166State was NULL.");
		return rz_il_op_new_nop();
	}
	const ut16 op1 = state->ext.esfr ? ESFR_ADDR(reg) : SFR_ADDR(reg);

	const RzPlatformTarget *arch_target = rz_analysis_get_arch_target(analysis);
	const char *resolved = rz_platform_profile_resolve_mmio(arch_target->profile, op1);
	if (!resolved) {
		printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_retp 0x%04x\n",
			op->id, pc, IP, op1);
		return SEQN(7,
			SETL("SP", VARG("SP")),
			SETL("ip", SP_GET_VAL16),
			SETL("SP", SP_INC),
			STOREW(U32(op1), SP_GET_VAL16),
			SETL("SP", SP_INC),
			SETG("SP", VARL("SP")),
			JMP(UNSIGNED(32, VARL("ip")))
		);
	}

	return SEQN(7,
		SETL("SP", VARG("SP")),
		SETL("ip", SP_GET_VAL16),
		SETL("SP", SP_INC),
		SETG(resolved, SP_GET_VAL16),
		SETL("SP", SP_INC),
		SETG("SP", VARL("SP")),
		JMP(UNSIGNED(32, VARL("ip")))
	);
}

/*
*	(IP) ← ((SP))
*	(SP) ← (SP) + 2
*	IF (CPUCON1.SGTDIS = 0) THEN
*		(CSP) ← ((SP))
*		(SP) ← (SP) + 2
*	END IF
*	(PSW) ← ((SP))
*	(SP) ← (SP) + 2
*
 */
static RzILOpEffect *c166_il_reti(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	return SEQN(8,
		SETL("SP", VARG("SP")),
		SETL("addr", SP_GET_VAL16),
		SETL("SP", SP_INC),
		BRANCH(INV(VARG("SGTDIS")),
			SEQ2(
				SETG("CSP", SP_GET_VAL8),
				SETL("SP", SP_INC)
			),
			NOP()
		),
		SETG("PSW", SP_GET_VAL16),
		SETL("SP", SP_INC),
		SETG("SP", VARL("SP")),
		JMP(UNSIGNED(32, VARL("addr")))
	);
}

/*
*	(IP) ← ((SP))
*	(SP) ← (SP) + 2
*
 */
static RzILOpEffect *c166_il_ret(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	return SEQN(4,
		SETL("SP", VARG("SP")),
		SETL("ip", SP_GET_VAL16),
		SETG("SP", SP_INC),
		JMP(UNSIGNED(32, VARL("ip")))
	);
}

/**
static RzILOpEffect *c166_il_extp_or_exts_rwm_irang2(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_jmpr_cc_sge_rel(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_jmpr_cc_sge_rel\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}
**/

static RzILOpEffect *c166_il_bset_bitoff6(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_bset_bitoff6\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_or_rwn_rwm(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	// ut64 IP = rz_reg_getv(analysis->reg, "IP");
	const ut8 reg = buf[1];
	const ut8 op1 = H_NIB(reg);
	const ut8 op2 = L_NIB(reg);
	const char *src = c166_global_registers[op2];
	const char *dst = c166_global_registers[op1];
	// printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_or_rwn_rwm r%i, r%i\n",
	// 	op->id, pc, IP, op1, op2);
	RzILOpPure *d = VARG(dst);
	RzILOpBitVector *res = LOGOR(d, VARG(src));
	RzILOpEffect *or = SETG(dst, res);

	RzILOpEffect *e = SETG("e", ITE(EQ(DUP(d), S16(1 << 15)), IL_TRUE, IL_FALSE));
	RzILOpEffect *z = SETG("z", ITE(IS_ZERO(U16(op2)), IL_TRUE, IL_FALSE));
	RzILOpEffect *v = SETG("v", IL_FALSE);
	RzILOpEffect *c = SETG("c", IL_FALSE);
	RzILOpEffect *n = SETG("n", MSB(DUP(res)));

	RzILOpEffect *or_flags_seq = SEQ5(e, z, v, c, n);
	return SEQ2(or_flags_seq, or);
}

static RzILOpEffect *c166_il_push_reg(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	const ut8 reg = buf[1];
	if (IS_GPR(reg)) {
		// Short ‘reg’ addresses from F0 to FF always specify GPRs.
		printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_push_reg %s\n",
			op->id, pc, IP, c166_rw[L_NIB(reg)]);
		return SEQ5(
			SETL("reg_val", VARG(c166_rw[L_NIB(reg)])),
			SETL("SP", VARG("SP")),
			SETL("SP", SP_DEC),
			SETL("addr", UNSIGNED(32, VARL("SP"))),
			STORE(VARL("addr"), VARL("reg_val"))
		);
	}
	const C166State *state = (C166State *)analysis->plugin_data;
	if (!state) {
		RZ_LOG_FATAL("C166State was NULL.");
		return rz_il_op_new_nop();
	}
	const ut16 addr = state->ext.esfr ? ESFR_ADDR(reg) : SFR_ADDR(reg);

	const RzPlatformTarget *arch_target = rz_analysis_get_arch_target(analysis);
	const char *resolved = rz_platform_profile_resolve_mmio(arch_target->profile, addr);
	if (!resolved) {

		printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_push_reg 0x%04x\n",
			op->id, pc, IP, addr);
		return rz_il_op_new_nop();
	}
	return SEQ6(
		SETL("reg_val", VARG(resolved)),
		SETL("SP", VARG("SP")),
		SETL("SP", SP_DEC),
		SETG("SP", VARL("SP")),
		SETL("addr", UNSIGNED(32, VARL("SP"))),
		STOREW(VARL("addr"), VARL("reg_val"))
	);
}

/**
static RzILOpEffect *c166_il_jmpr_cc_ugt_rel(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_jmpr_cc_ugt_rel\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}
**/

static RzILOpEffect *c166_il_movb_rbn_rbm(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_movb_rbn_rbm\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}

/**
static RzILOpEffect *c166_il_movb_reg_mem(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_movb_reg_mem\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_bset_bitoff1(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_bset_bitoff1\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_sub_rwn_rwm(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_sub_rwn_rwm\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}
**/

static RzILOpEffect *c166_il_movb_rbn_orwm_data16(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	const C166State *state = (C166State *)analysis->plugin_data;
	if (!state) {
		RZ_LOG_FATAL("C166State was NULL.");
		return rz_il_op_new_nop();
	}
	const ut16 mem = rz_read_at_le16(buf, 2);
	const ut8 n = H_NIB(buf[1]);
	const ut8 m = L_NIB(buf[1]);

	if (state->ext.mode == C166_EXT_MODE_PAGE) {
		const ut32 seg = ((ut32)(state->ext.value & 0xFF));
		const char *dst = c166_get_word_reg_name(n);
		return SEQ5(
			SETL("addr", U16((seg << 14) + mem)),
			SETL("addr", ADD(VARL("addr"), VARG(c166_rw[m]))),
			SETL("load", LOADW(8, UNSIGNED(32, VARL("addr")))),
			WRITE_RL(dst,  UNSIGNED(16, VARL("load"))),
			SEQ3(SET_E(VARL("load")), SET_Z(VARL("load")), SET_N(VARL("load"))) // ??
		);
	}
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_mov_mem_reg(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	const ut8 reg = buf[1];
	const ut16 mem = rz_read_at_le16(buf, 2);

	const C166State *state = (C166State *)analysis->plugin_data;
	if (!state) {
		RZ_LOG_FATAL("C166State was NULL.");
		return rz_il_op_new_nop();
	}
	if (state->ext.mode == C166_EXT_MODE_REG || state->ext.mode == C166_EXT_MODE_NONE) {
		const ut8 i = mem >> 14;
		const char *src = c166_global_registers[L_NIB(reg)];
		const ut16 DPP_addr = SFR_ADDR(i);
		RzILOpEffect *mov = STORE(U32(DPP_addr), UNSIGNED(8, VARG(src)));
		return SEQ2(mov_flags_seq(VARG(src)), mov);
	}
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_mov_mem_reg unk\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}

/**
static RzILOpEffect *c166_il_movb_mem_reg(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_movb_mem_reg\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}
**/

static RzILOpEffect *c166_il_movb_orwm_data16_rbn(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	const C166State *state = (C166State *)analysis->plugin_data;
	if (!state) {
		RZ_LOG_FATAL("C166State was NULL.");
		return rz_il_op_new_nop();
	}
	const ut16 mem = rz_read_at_le16(buf, 2);
	const ut8 n = H_NIB(buf[1]);
	const ut8 m = L_NIB(buf[1]);

	if (state->ext.mode == C166_EXT_MODE_PAGE) {
		const ut32 seg = (ut32)(state->ext.value & 0xFF);
		const char *dst = c166_get_word_reg_name(n);
		return SEQ3(
			SETL("addr", U16((seg << 14) + mem)),
			SETL("addr", ADD(VARL("addr"), VARG(c166_rw[m]))),
			STORE(UNSIGNED(32, VARL("addr")), UNSIGNED(8, READ_RL(VARG(dst))))
		);
	}
	return SEQ2(
		SETL("addr", UNSIGNED(32, ADD(VARG(c166_rw[m]), U16(mem)))),
		SETG(c166_rw[m], LOADW(16, VARL("addr")))
	);

}

static RzILOpEffect *c166_il_mov_rwn_rwm(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	const ut8 reg = buf[1];
	const char *dst = c166_global_registers[H_NIB(reg)];
	const char *src = c166_global_registers[L_NIB(reg)];
	RzILOpEffect *mov = SETG(dst, VARG(src));
	return SEQ2(mov_flags_seq(VARG(src)), mov);
}

static RzILOpEffect *c166_il_mov_rwn_orwmp(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	const C166State *state = (C166State *)analysis->plugin_data;
	if (!state) {
		RZ_LOG_FATAL("C166State was NULL.");
		return rz_il_op_new_nop();
	}
	// ut64 IP = rz_reg_getv(analysis->reg, "IP");
	const ut8 reg = buf[1];
	const char *src = c166_global_registers[L_NIB(reg)];
	const char *dst = c166_global_registers[H_NIB(reg)];
	// printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_mov_rwn_orwmp r%i, [r%i+] (esfr: %s)\n",
	// 	op->id, pc, IP, H_NIB(reg), L_NIB(reg),
	// 	state->ext.esfr ? "true" : "false");
	if (state->ext.esfr && state->ext.mode == C166_EXT_MODE_REG) {
		const char *ext_reg_name = c166_global_registers[state->ext.value];

		return SEQN(8,
			SETL("seg", UNSIGNED(32, VARG(ext_reg_name))),
			SETL("seg", SHIFTL0(VARL("seg"), U16(16))),
			SETL("src_op", VARG(src)),
			SETL("addr", LOGOR(VARL("seg"), UNSIGNED(32, VARL("src_op")))),
			SETL("load", LOADW(16, VARL("addr"))),
			SETG(dst, UNSIGNED(16, VARL("load"))),
			SETG(src, ADD(VARL("src_op"), U16(2))),
			SEQ3(SET_E(VARL("load")), SET_Z(VARL("load")), SET_N(VARL("load")))
		);
	}

	RzILOpBitVector *addr = UNSIGNED(32, VARG(src));
	RzILOpBitVector *load = LOAD(addr);
	RzILOpEffect *mov = SETG(dst, UNSIGNED(16, load));
	RzILOpBitVector *add = ADD(VARG(src), U16(2));
	RzILOpEffect *inc = SETG(src, add);
	return SEQ3(mov_flags_seq(VARG(c166_global_registers[L_NIB(reg)])), mov, inc);
}

static RzILOpEffect *c166_il_mov_rwn_data4(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	// ut64 IP = rz_reg_getv(analysis->reg, "IP");
	const ut8 reg = L_NIB(buf[1]);
	const ut8 data = H_NIB(buf[1]);
	// printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_mov_rwn_data4 r%i, #0x%02x\n",
	// 	op->id, pc, IP, reg, data);
	return SEQN(3,
		SETL("val", U8(data)),
		SETG(c166_global_registers[reg], U16(data)),
		SEQ3(SET_E(UNSIGNED(8, VARL("val"))), SET_Z(VARL("val")), SET_N(VARL("val")))
	);
}

static RzILOpEffect *c166_il_mov_reg_data16(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	const ut16 data = rz_read_at_le16(buf, 2);
	const ut8 reg = buf[1];

#ifdef C166_DUPLICATE_REG_OPERATIONS
	const ut8 SGTDIS = (ut8)rz_reg_getv(analysis->reg, "SGTDIS");
	if (SGTDIS == 0) {
		rz_reg_setv(analysis->reg, "CSP", seg);
	}
	// rz_reg_setv(analysis->reg, "IP", (((ut32)seg) << 16) | caddr);
	// rz_reg_setv(analysis->reg, c166_global_registers[L_NIB(reg)], (ut32)data);
#endif

	if (IS_GPR(reg)) {
#ifdef C166_DUPLICATE_REG_OPERATIONS
		rz_reg_setv(analysis->reg, c166_global_registers[L_NIB(reg)], (ut32)data);
#endif
		return SEQ2(
			mov_flags_seq(U16(data)),
			SETG(c166_global_registers[L_NIB(reg)], U16(data)));
	}
	const ut16 addr = SFR_ADDR(reg);

	const RzPlatformTarget *arch_target = rz_analysis_get_arch_target(analysis);
	const char *resolved = rz_platform_profile_resolve_mmio(arch_target->profile, addr);
	if (resolved) {
		switch (addr) {
		case 0xfe14: ///< "STKOV"
#ifdef C166_DUPLICATE_REG_OPERATIONS
			rz_reg_setv(analysis->reg, "r2", (ut32)data);
#endif
			return SEQ2(
				mov_flags_seq(U16(data)),
				SETG("r2", U16(data))
			);
		case 0xfe10: ///< "CP"
#ifdef C166_DUPLICATE_REG_OPERATIONS
			rz_reg_setv(analysis->reg, "r0", (ut32)data);
#endif
			return SEQ2(
				mov_flags_seq(U16(data)),
				SETG("r0", U16(data)));
		case 0xfe00: ///< "DPP0"
#ifdef C166_DUPLICATE_REG_OPERATIONS
			rz_reg_setv(analysis->reg, "DPP0", (ut32)data);
#endif
			return SEQ2(
				mov_flags_seq(U16(data)),
				SETG("DPP0", UN(10, data)));
		case 0xfe02: ///< "DPP1"
#ifdef C166_DUPLICATE_REG_OPERATIONS
			rz_reg_setv(analysis->reg, "DPP1", (ut32)data);
#endif
			return SEQ2(
				mov_flags_seq(U16(data)),
				SETG("DPP1", UN(10, data)));
		case 0xfe04: ///< "DPP2"
#ifdef C166_DUPLICATE_REG_OPERATIONS
			rz_reg_setv(analysis->reg, "DPP2", (ut32)data);
#endif
			return SEQ2(
				mov_flags_seq(U16(data)),
				SETG("DPP2", UN(10, data)));
		case 0xfe06: ///< "DPP3"
#ifdef C166_DUPLICATE_REG_OPERATIONS
			rz_reg_setv(analysis->reg, "DPP3", (ut32)data);
#endif
			return SEQ2(
				mov_flags_seq(U16(data)),
				SETG("DPP3", UN(10, data)));
		default:
			// printf("x `%s`\n", resolved);
			return SEQ2(mov_flags_seq(U16(data)), SETG(resolved, U16(data)));
		}
	}
	printf("--------------[0x%06lx] [%d] `%s`, 0x%04x\n",
		pc,
		L_NIB(reg),
		c166_global_registers[L_NIB(reg)],
		data);
	return mov_flags_seq(U16(data));
}

/**
static RzILOpEffect *c166_il_movb_reg_data8(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_movb_reg_data8\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_mov_orwn_orwmp(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_mov_orwn_orwmp\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_jmpa_cc_caddr(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_jmpa_cc_caddr\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}
**/

static RzILOpEffect *c166_il_movb_rbn_data4(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	const C166State *state = (C166State *)analysis->plugin_data;
	if (!state) {
		RZ_LOG_FATAL("C166State was NULL.");
		return rz_il_op_new_nop();
	}
	const ut8 data4 = H_NIB(buf[1]);
	const ut8 n = L_NIB(buf[1]);
	if (state->ext.esfr && state->ext.mode == C166_EXT_MODE_REG) {
		return rz_il_op_new_nop();
	}
	const char *dst = c166_get_word_reg_name(n);
	return SEQN(3,
		SETL("val", U16(data4)),
		WRITE_RL(dst, VARL("val")),
		SEQ3(SET_E(VARL("val")), SET_Z(VARL("val")), SET_N(VARL("val")))
	);
}

/**
static RzILOpEffect *c166_il_movbs_rwn_rbm(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_movbs_rwn_rbm\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_atomic_or_extr_irang2(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_atomic_or_extr_irang2\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}
**/

static RzILOpEffect *c166_il_mov_rwn_orwm_data16(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_mov_rwn_orwm_data16\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}
static RzILOpEffect *c166_il_extp_or_exts_pag10_or_seg8_irang2(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	// ut64 IP = rz_reg_getv(analysis->reg, "IP");
	// const C166State *state = (C166State *)analysis->plugin_data;
	// if (!state) {
	// 	RZ_LOG_FATAL("C166State was NULL.");
	// 	return rz_il_op_new_nop();
	// }
	// printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_extp_or_exts_pag10_or_seg8_irang2 #0x%04x, #%i\n",
	// 	op->id, pc, IP, state->ext.value, state->ext.i);
	return rz_il_op_new_nop();
}

/**
static RzILOpEffect *c166_il_pop_reg(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_pop_reg\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_atomic_or_extr_irang2(ut64 pc, RzAnalysis *analysis, const ut8 *buf) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL - [0x%06lx] IP: [0x%06lx] c166_il_atomic_or_extr_irang2\n", pc, IP);
	return rz_il_op_new_nop();
}
**/

static RzILOpEffect *c166_il_jbc_bitaddr_rel(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	// ut64 IP = rz_reg_getv(analysis->reg, "IP");
	const ut64 new_IP = op->addr + op->size + (2 * ((st8)buf[2]));
	const ut8 bitoff = buf[1];
	const ut8 bit_index = H_NIB(buf[3]);
	const char *reg = NULL;
	if (bitoff >= 0xF0) {
		reg = c166_rw[L_NIB(bitoff)];
	}
	// printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_jbc_bitaddr_rel new_IP: [0x%06lx] reg: %s\n",
	// 	op->id, pc, IP, new_IP, reg);

	RzILOpBitVector *mask = U16(1 << bit_index);

	RzILOpBitVector *_iar = LOGAND(VARG(reg), mask);
	_iar = SHIFTR0(_iar, U16(bit_index));

	RzILOpBool *cond = NON_ZERO(_iar);
	RzILOpEffect *clear_bit = BRANCH(DUP(cond), SETG(reg, SUB(VARG(reg), DUP(mask))), NOP());

	RzILOpEffect *e = SETG("e", IL_FALSE);
	RzILOpEffect *z = SETG("z", INV(DUP(cond)));
	RzILOpEffect *v = SETG("v", IL_FALSE);
	RzILOpEffect *c = SETG("c", IL_FALSE);
	RzILOpEffect *n = SETG("n", DUP(cond));
	return SEQ7(e, z, v, c, n, BRANCH(DUP(cond), JMP(U32(new_IP)), NOP()), clear_bit);
}

static RzILOpEffect *c166_il_jmpr_rel(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut8 condition = (buf[0] & 0xf0) >> 4;
	ut64 new_IP = op->addr + op->size + (2 * (st8)buf[1]);
	RzILOpBool *cond = check_condition(condition);
	return BRANCH(cond, JMP(U32(new_IP)), NOP());
}

/**
static RzILOpEffect *c166_il_bclr_bitoff2(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_bclr_bitoff2\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}

static RzILOpEffect *c166_il_bset_bitoff2(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	ut64 IP = rz_reg_getv(analysis->reg, "IP");
	printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_bset_bitoff2\n", op->id, pc, IP);
	return rz_il_op_new_nop();
}
**/

/**
 *
 * (SP) ← (SP) - 2
 * ((SP)) ← (CSP)
 * (SP) ← (SP) - 2
 * ((SP)) ← (IP)
 * IF (CPUCON1.SGTDIS = 0) THEN
 *	(CSP) ← op1
 * END IF
 * (IP) ← op2
 *
 */
static RzILOpEffect *c166_il_calls_seg_caddr(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	const ut8 seg = buf[1];
	const ut16 caddr = rz_read_at_le16(buf, 2);
	const ut32 to_addr = (((ut32)seg) << 16) | caddr;
	RzILOpBitVector *_loc = UN(C166_ADDR_SIZE, to_addr);
	return SEQ8(
		SETL("SP", SUB(VARG("SP"), U16(2))),
		SETL("CSP", VARG("CSP")),
		STORE(UNSIGNED(32, VARL("SP")), UNSIGNED(8, VARL("CSP"))),
		SETL("SP", SUB(VARL("SP"), U16(2))),
		STOREW(UNSIGNED(32, VARL("SP")), U16(pc + C166_BYTESIZE_4)),
		SETG("SP", VARL("SP")),
		SETG("CSP", ITE(INV(VARG("SGTDIS")), U8(seg), U8(0))),
		JMP(_loc)
	);
}

/**
 *
 * IF (op1) THEN
 *	(SP) ← (SP) - 2
 *	((SP)) ← (IP)
 *	(IP) ← op2
 * ELSE
 *	next instruction
 * END IF
 */
static RzILOpEffect *c166_il_calli_cc_rwn(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	const ut8 op1 = buf[1];
	const ut8 condition = H_NIB(op1);
	const ut32 seg = (ut32)pc & 0xFF0000;

	return SEQ3(
		SETL("addr", UNSIGNED(32, VARG(c166_global_registers[L_NIB(op1)]))),
		SETL("addr", LOGOR(U32(seg), VARL("addr"))),
		BRANCH(
			check_condition(condition),
			SEQ5(
				SETL("SP", VARG("SP")),
				SETL("SP", SP_DEC),
				SETG("SP", VARL("SP")),
				// STOREW(VARL("SP"), U16(pc + C166_BYTESIZE_4)),
				STOREW(UNSIGNED(32, VARL("SP")), U16(pc + C166_BYTESIZE_4)),
				JMP(VARL("addr"))
			),
			NOP()
		)
	);
	/**
	 SETL("reg_val", VARG(c166_rw[L_NIB(reg)])),
			SETL("SP", VARG("SP")),
			SETL("SP", SP_DEC),
			SETL("addr", UNSIGNED(32, VARL("SP"))),
			STORE(VARL("addr"), VARL("reg_val")),
			SETG("SP", VARL("SP"))
			*/

	// ITE(INV(VARG("SGTDIS")),
	// 			UNSIGNED(8, SP_GET_VAL8),
	// 			VARG("CSP")
	// 		)
	//
	// const ut16 caddr = rz_read_at_le16(buf, 2);
	// const ut32 to_addr = (((ut32)seg) << 16) | caddr;
	// RzILOpBitVector *_loc = UN(C166_ADDR_SIZE, to_addr);
	// return SEQ8(
	// 	SETL("SP", SP_DEC),
	// 	SETL("CSP", VARG("CSP")),
	// 	STORE(UNSIGNED(32, VARL("SP")), UNSIGNED(8, VARL("CSP"))),
	// 	SETL("SP", SP_DEC),
	// 	STOREW(UNSIGNED(32, VARL("SP")), U16(pc + C166_BYTESIZE_4)),
	// 	SETG("SP", VARL("SP")),
	// 	SETG("CSP", ITE(INV(VARG("SGTDIS")), U8(seg), U8(0))),
	// 	JMP(_loc)
	// );
	//
	// return SEQN(8,
	// 	SETL("SP", VARG("SP")),
	// 	SETL("addr", SP_GET_VAL16),
	// 	SETL("SP", SP_INC),
	// 	SETG("CSP",
	// 		ITE(INV(VARG("SGTDIS")),
	// 			UNSIGNED(8, SP_GET_VAL8),
	// 			VARG("CSP")
	// 		)
	// 	),
	// 	SETG("SP",
	// 		ITE(INV(VARG("SGTDIS")),
	// 			SP_INC,
	// 			VARG("SP")
	// 		)
	// 	),
	// 	SETG("PSW", SP_GET_VAL16),
	// 	SETL("SP", SP_INC),
	// 	JMP(UNSIGNED(32, VARL("addr")))
	// );
}

/**
 *
 * IF (CPUCON1.SGTDIS = 0) THEN
 *	(CSP) ← op1
 * END IF
 * (IP) ← op2
 *
 */
static RzILOpEffect *c166_il_jmps_seg_caddr(ut64 pc, RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op) {
	// ut64 IP = rz_reg_getv(analysis->reg, "IP");
	const ut8 seg = buf[1];
	const ut16 caddr = rz_read_at_le16(buf, 2);
	const ut32 to_addr = ((ut32)seg << 16) | caddr;
	// printf("IL[0x%02x] - [0x%06lx] IP: [0x%06lx] c166_il_jmps_seg_caddr\n", op->id, pc, IP);

#ifdef C166_DUPLICATE_REG_OPERATIONS
	const ut8 SGTDIS = (ut8)rz_reg_getv(analysis->reg, "SGTDIS");
	if (SGTDIS == 0) {
		rz_reg_setv(analysis->reg, "CSP", seg);
	}
	rz_reg_setv(analysis->reg, "IP", (((ut32)seg) << 16) | caddr);
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
	c166_il_jmpr_rel, //
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
	c166_il_jmpr_rel, //
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
	c166_il_jmpr_rel, //
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
	c166_il_bmovn_bitaddr_bitaddr, //
	c166_il_unk, //
	c166_il_unk, //60
	c166_il_jmpr_rel, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_cmp_rwn_rwm, //
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
	c166_il_div_rwn, //
	c166_il_shl_rwn_rwm, //
	c166_il_jmpr_rel, //
	c166_il_bclr_bitoff4, //
	c166_il_bset_bitoff4, //
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
	c166_il_jmpr_rel, //
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
	c166_il_jmpr_rel, //
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
	c166_il_jmpr_rel, //
	c166_il_unk, //c166_il_bclr_bitoff7, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //130
	c166_il_unk, //
	c166_il_unk, //
	c166_il_lifted_nop, //
	c166_il_unk, //
	c166_il_lifted_nop, //
	c166_il_unk, //c166_il_mov_norwm_rwn, //
	c166_il_unk, //
	c166_il_jb_bitaddr_rel, //
	c166_il_unk, //
	c166_il_lifted_nop, //140
	c166_il_jmpr_rel, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_cpl_rwn, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //150
	c166_il_lifted_nop, //
	c166_il_mov_rwn_orwmp, //
	c166_il_unk, //
	c166_il_jnb_bitaddr_rel, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_jmpr_rel, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //160
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_lifted_nop, // 0xA5
	c166_il_unk, //
	c166_il_lifted_nop, //
	c166_il_mov_rwn_orwm, //
	c166_il_movb_rbn_oRwm, //
	c166_il_jbc_bitaddr_rel, //170
	c166_il_calli_cc_rwn, //
	c166_il_unk, //
	c166_il_jmpr_rel,
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //180
	c166_il_lifted_nop, //
	c166_il_unk, //
	c166_il_lifted_nop, //
	c166_il_mov_orwm_rwn, //
	c166_il_movb_orwm_rbn, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_unk, //
	c166_il_jmpr_rel, //
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
	c166_il_ret, //
	c166_il_lifted_nop, //
	c166_il_jmpr_rel, //c166_il_jmpr_cc_slt_rel, //
	c166_il_unk,
	c166_il_unk, //
	c166_il_unk, //c166_il_movbs_rwn_rbm, //
	c166_il_extp_or_exts_pag10_or_seg8_irang2, //c166_il_atomic_or_extr_irang2, //
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
	c166_il_lifted_nop, // c166_il_extp_or_exts_rwm_irang2, //220
	c166_il_jmpr_rel, //c166_il_jmpr_cc_sge_rel, //
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
	c166_il_retp, //
	c166_il_push_reg, //
	c166_il_jmpr_rel, //c166_il_jmpr_cc_ugt_rel, //
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
	c166_il_reti, // 0xFB
	c166_il_unk, //c166_il_pop_reg, // 0xFC
	c166_il_jmpr_rel, // 0xFD
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
	r->init_state = rz_analysis_il_init_state_new();
	if (!r->init_state) {
		rz_analysis_il_config_free(r);
		return NULL;
	}
#define IL_UN(l, x) rz_il_value_new_bitv(rz_bv_new_from_ut64(l, x))
#define IL_U8(x) IL_UN(8, x)
#define IL_U16(x) IL_UN(16, x)
#define IL_U32(x) IL_UN(32, x)
	rz_analysis_il_init_state_set_var(r->init_state, "r0", IL_U16(0xFC00)); ///< CP
	rz_analysis_il_init_state_set_var(r->init_state, "r1", IL_U16(0xFC00)); /// < SP
	rz_analysis_il_init_state_set_var(r->init_state, "SP", IL_U16(0xFC00)); /// < SP
	rz_analysis_il_init_state_set_var(r->init_state, "r2", IL_U16(0xFA00)); ///< STKOV
	rz_analysis_il_init_state_set_var(r->init_state, "r3", IL_U16(0xFC00)); ///< STKUN
	rz_analysis_il_init_state_set_var(r->init_state, "DPP1", IL_UN(10, 0x0001));
	rz_analysis_il_init_state_set_var(r->init_state, "DPP2", IL_UN(10, 0x0002));
	rz_analysis_il_init_state_set_var(r->init_state, "DPP3", IL_UN(10, 0x0003));
	rz_analysis_il_init_state_set_var(r->init_state, "BUSCON0", IL_U16(0x0680)); ///< BUSCON0
	return r;
}
#include <rz_il/rz_il_opbuilder_end.h>