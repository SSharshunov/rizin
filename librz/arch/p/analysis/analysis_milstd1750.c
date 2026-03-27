// SPDX-FileCopyrightText: 2025 godcodehunter
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_analysis.h>

#include <milstd1750/milstd1750_analysis.h>

RzAnalysisPlugin rz_analysis_plugin_milstd1750 = {
	.name = "milstd1750",
	.desc = "milstd1750 analysis plugin",
	.license = "MIT",
	.arch = "milstd1750",
	.bits = 8,
	.op = &rz_milstd1750_analysis_op,
	.esil = false
};