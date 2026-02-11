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
		return lua54_analysis_op(analysis, op, addr, data, len);
	} else if (RZ_STR_EQ(analysis->cpu, "5.5")) {
		return lua55_analysis_op(analysis, op, addr, data, len);
	} else {
		RZ_LOG_ERROR("Cannot find a suitable lua version to handle lua analysis\n");
		return 0;
	}
}

RzAnalysisPlugin rz_analysis_plugin_luac = {
	.name = "luac",
	.desc = "Lua bytecode analysis plugin",
	.license = "LGPL3",
	.arch = "luac",
	.bits = 8,
	.op = &rz_lua_analysis_op,
	.esil = false
};
