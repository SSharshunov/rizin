// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

#include <rz_types.h>
#include <rz_analysis.h>

#include <luac/lua_arch.h>

int rz_lua_analysis_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask) {
	if (!analysis->cpu) {
		RZ_LOG_ERROR("Cannot get lua version\n");
		return 0;
	}
	if (RZ_STR_EQ(analysis->cpu, "5.0")) {
		return lua50_analysis_op(analysis, op, addr, data, len);
	} else if (RZ_STR_EQ(analysis->cpu, "5.1")) {
		return lua51_analysis_op(analysis, op, addr, data, len);
	} else if (RZ_STR_EQ(analysis->cpu, "5.2")) {
		return lua52_analysis_op(analysis, op, addr, data, len);
	} else if (RZ_STR_EQ(analysis->cpu, "5.3")) {
		return lua53_analysis_op(analysis, op, addr, data, len);
	} else if (RZ_STR_EQ(analysis->cpu, "5.4")) {
		return lua54_analysis_op(analysis, op, addr, data, len, mask);
	} else if (RZ_STR_EQ(analysis->cpu, "5.5")) {
		return lua55_analysis_op(analysis, op, addr, data, len);
	} else {
		RZ_LOG_ERROR("Cannot find a suitable lua version to handle lua analysis\n");
		return 0;
	}
}

static char *get_reg_profile(RzAnalysis *analysis) {
	const char *p =
		// "=pc	pc\n"        // Program Counter
		// "=sp	sp\n"        // Stack Pointer
		"=A0	r0\n"
		"=A1	r1\n"
		"=A2	r2\n"
		"=A3	r3\n"
		"gpr	pc	.32	0	0\n"
		"gpr	sp	.32	4	0\n"
		"gpr	r0	.32	8	0\n"
		"gpr	r1	.32	12	0\n"
		"gpr	r2	.32	16	0\n"
		"gpr	r3	.32	20	0\n"
		"gpr	r4	.32	24	0\n"
		"gpr	r5	.32	28	0\n"
		"gpr	r6	.32	32	0\n"
		"gpr	r7	.32	36	0\n"
		"gpr	r8	.32	40	0\n"
		"gpr	r9	.32	44	0\n"
		"gpr	r10	.32	48	0\n"
		"gpr	r11	.32	52	0\n"
		"gpr	r12	.32	56	0\n"
		"gpr	r13	.32	60	0\n"
		"gpr	r14	.32	64	0\n"
		"gpr	r15	.32	68	0\n"
		"gpr	r16	.32	72	0\n"
		"gpr	r17	.32	76	0\n"
		"gpr	r18	.32	80	0\n"
		"gpr	r19	.32	84	0\n"
		"gpr	r20	.32	88	0\n"
		"gpr	r21	.32	92	0\n"
		"gpr	r22	.32	96	0\n"
		"gpr	r23	.32	100	0\n"
		"gpr	r24	.32	104	0\n"
		"gpr	r25	.32	108	0\n"
		"gpr	r26	.32	112	0\n"
		"gpr	r27	.32	116	0\n";
	return rz_str_dup(p);
}

static int archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		return 4;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return 4;
	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
		/* fall-thru */
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
		return -1;
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return false;
	default:
		return -1;
	}
}

RzAnalysisPlugin rz_analysis_plugin_luac = {
	.name = "luac",
	.desc = "Lua bytecode analysis plugin",
	.license = "LGPL3",
	.arch = "luac",
	.bits = 32,
	.get_reg_profile = &get_reg_profile,
	.op = &rz_lua_analysis_op,
	.archinfo = archinfo,
	.esil = false
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_luac,
	.version = RZ_VERSION
};
#endif