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
	RzStrBuf *sb = rz_strbuf_new("");

	rz_strbuf_append(sb, "=PC pc\n"); ///< Program Counter
	rz_strbuf_append(sb, "=SP sp\n"); ///< Stack Pointer
	rz_strbuf_append(sb, "gpr pc .32 0 0\n");
	rz_strbuf_append(sb, "gpr sp .32 4 0\n");
	rz_strbuf_append(sb, "=A0	r0\n");
	rz_strbuf_append(sb, "=A1	r1\n");
	rz_strbuf_append(sb, "=A2	r2\n");
	rz_strbuf_append(sb, "=A3	r3\n");

	///< Stack slots (Registers R0-R255)
	///< Use offset +8 (after pc and sp)
	for (int i = 0; i < 256; i++) {
		rz_strbuf_appendf(sb, "gpr r%d .32 %d 0\n", i, 8 + (i * 4));
	}

	///< Upvalues (U0-U127)
	///< Use offset after all R-regs: 8 + (256 * 4) = 1032
	for (int i = 0; i < 128; i++) {
		rz_strbuf_appendf(sb, "gpr u%d .32 %d 0\n", i, 1032 + (i * 4));
	}

	for (int i = 0; i < 128; i++) {
		rz_strbuf_appendf(sb, "gpr k%d .32 %d 0\n", i, 1544 + (i * 4));
	}

	return rz_strbuf_drain(sb);
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

static bool init(void **user) {
	AnalysisLuacContext *ctx = RZ_NEW0(AnalysisLuacContext);
	if (!ctx) {
		return false;
	}
	*user = ctx;
	return true;
}

static bool fini(void *user) {
	rz_return_val_if_fail(user, false);
	AnalysisLuacContext *ctx = (AnalysisLuacContext *)user;
	free(ctx);
	return true;
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
	.init = &init,
	.fini = &fini,
	.esil = false
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_luac,
	.version = RZ_VERSION
};
#endif