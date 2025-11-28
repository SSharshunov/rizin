// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#include <luac/lua_arch.h>

int rz_luac_disasm(RzAsm *a, RzAsmOp *opstruct, const ut8 *buf, int len) {
	LuaOpNameList oplist = NULL;
	int r = 0;

	if (!a->cpu) {
		RZ_LOG_ERROR("disassembler: lua: no version info, specify it with `asm.cpu` option\n");
		return -1;
	}

	if (strcmp(a->cpu, "5.5") == 0) {
		oplist = get_lua55_opnames();
		r = lua55_disasm(opstruct, buf, len, oplist);
	} else if (strcmp(a->cpu, "5.4") == 0) {
		oplist = get_lua54_opnames();
		r = lua54_disasm(opstruct, buf, len, oplist);
	} else if (strcmp(a->cpu, "5.3") == 0) {
		oplist = get_lua53_opnames();
		r = lua53_disasm(opstruct, buf, len, oplist);
	} else if (strcmp(a->cpu, "5.2") == 0) {
		oplist = get_lua52_opnames();
		r = lua52_disasm(opstruct, buf, len, oplist);
	} else if (strcmp(a->cpu, "5.1") == 0) {
		oplist = get_lua51_opnames();
		r = lua51_disasm(opstruct, buf, len, oplist);
	} else if (strcmp(a->cpu, "5.0") == 0) {
		oplist = get_lua50_opnames();
		r = lua50_disasm(opstruct, buf, len, oplist);
	} else {
		RZ_LOG_ERROR("disassembler: lua: version %s is not supported\n", a->cpu);
		return -1;
	}

	free_lua_opnames(oplist);
	opstruct->size = r;
	return r;
}

int rz_luac_asm(RzAsm *a, RzAsmOp *opstruct, const char *str) {
	int str_len = strlen(str);
	ut32 instruction = 0;
	ut8 buffer[4];

	if (!a->cpu) {
		RZ_LOG_ERROR("assembler: lua: no version info, specify it with `asm.cpu` option\n");
		return -1;
	}

	if (strcmp(a->cpu, "5.0") == 0) {
		if (!lua50_assembly(str, str_len, &instruction)) {
			return -1;
		}
	} else if (strcmp(a->cpu, "5.1") == 0) {
		if (!lua51_assembly(str, str_len, &instruction)) {
			return -1;
		}
	} else if (strcmp(a->cpu, "5.2") == 0) {
		if (!lua52_assembly(str, str_len, &instruction)) {
			return -1;
		}
	} else if (strcmp(a->cpu, "5.3") == 0) {
		if (!lua53_assembly(str, str_len, &instruction)) {
			return -1;
		}
	} else if (strcmp(a->cpu, "5.4") == 0) {
		if (!lua54_assembly(str, str_len, &instruction)) {
			return -1;
		}
	} else if (strcmp(a->cpu, "5.5") == 0) {
		if (!lua55_assembly(str, str_len, &instruction)) {
			return -1;
		}
	} else {
		RZ_LOG_ERROR("assembler: lua: version %s is not supported\n", a->cpu);
		return -1;
	}

	lua_set_instruction(instruction, buffer);
	rz_strbuf_setbin(&opstruct->buf, (const ut8 *)&buffer, 4);
	return 4;
}

RzAsmPlugin rz_asm_plugin_luac = {
	.name = "luac",
	.arch = "luac",
	.license = "LGPL3",
	.bits = 8,
	.desc = "Lua bytecode (LUAC) disassembler",
	.disassemble = &rz_luac_disasm,
	.assemble = &rz_luac_asm,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = rz_asm_plugin_luac,
	.version = RZ_VERSION
};
#endif
