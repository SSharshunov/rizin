// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#include "lua_arch.h"
#include <luac/luac_common.h>

static LuacBinInfo *getLuacBinInfo(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis->binb.bin->binfiles, NULL);
	rz_return_val_if_fail(analysis->binb.bin->binfiles->length > 0, NULL);
	RzBinFile *bfile = (RzBinFile *)analysis->binb.bin->binfiles->head->val;
	rz_return_val_if_fail(bfile, NULL);
	rz_return_val_if_fail(bfile->o, NULL);
	RzBinObject *bo = (RzBinObject *)bfile->o;
	LuacBinInfo *obj = (LuacBinInfo *)bo->bin_obj;
	return obj;
}

ut64 get_k_vaddr(RzAnalysis *analysis, ut64 addr, int k_idx) {
	ut64 proto_base = addr & ~0xFFF;
	return proto_base + 0x800 + (k_idx * 16);
}

#define print_isk isk ? "k" : ""

LuaInstruction lua_build_instruction(const ut8 *buf) {
	LuaInstruction ret = 0;
	ret |= buf[3] << 24;
	ret |= buf[2] << 16;
	ret |= buf[1] << 8;
	ret |= buf[0];
	return ret;
}

void lua_set_instruction(const LuaInstruction instruction, ut8 *data) {
	data[3] = instruction >> 24;
	data[2] = instruction >> 16;
	data[1] = instruction >> 8;
	data[0] = instruction >> 0;
}

bool free_lua_opnames(LuaOpNameList list) {
	if (list != NULL) {
		RZ_FREE(list);
		return true;
	}
	return false;
}

/* formatted strings for asm_buf */
char *luaop_new_str_3arg(char *opname, const int a, const int b, const int c) {
	// return rz_str_newf("%s %d %d %d", opname, a, b, c);
	return rz_str_newf("%s %" PFMT32d " %" PFMT32d " %" PFMT32d, opname, a, b, c);
}

char *luaop_new_str_2arg(char *opname, const int a, const int b) {
	return rz_str_newf("%s %" PFMT32d " %" PFMT32d, opname, a, b);
}

char *luaop_new_str_1arg(char *opname, const int a) {
	return rz_str_newf("%s %" PFMT32d, opname, a);
}

/* For the k flag */
char *luaop_new_str_3arg_ex(char *opname, const int a, const int b, const int c, const int isk) {
	return rz_str_newf("%s %" PFMT32d " %" PFMT32d " %" PFMT32d " %s", opname, a, b, c, print_isk);
}

char *luaop_new_str_2arg_ex(char *opname, const int a, const int b, const int isk) {
	return rz_str_newf("%s %" PFMT32d " %" PFMT32d " %s", opname, a, b, print_isk);
}

char *luaop_new_str_2arg_ex_ki(char *opname, const int a, const int b, const int isk) {
	return rz_str_newf("%s %" PFMT32d " %" PFMT32d " %" PFMT32d, opname, a, b, isk);
}

char *luaop_new_str_2arg_ex_kc(char *opname, const int a, const int b, const int isk) {
	return rz_str_newf("%s %" PFMT32d " %" PFMT32d " %s", opname, a, b, print_isk);
}

char *luaop_new_str_1arg_ex(char *opname, const int a, const int isk) {
	return rz_str_newf("%s %" PFMT32d " %s", opname, a, print_isk);
}

int lua_load_next_arg_start(const char *raw_string, char *recv_buf) {
	if (!raw_string) {
		return 0;
	}

	const char *arg_start = NULL;
	const char *arg_end = NULL;
	int arg_len = 0;

	/* locate the start point */
	arg_start = rz_str_trim_head_ro(raw_string);
	if (strlen(arg_start) == 0) {
		return 0;
	}

	arg_end = strchr(arg_start, ' ');
	if (arg_end == NULL) {
		/* is last arg */
		arg_len = (int)strlen(arg_start);
	} else {
		arg_len = arg_end - arg_start;
	}

	/* Set NUL */
	memcpy(recv_buf, arg_start, arg_len);
	recv_buf[arg_len] = 0x00;

	/* Calculate offset */
	return arg_start - raw_string + arg_len;
}

bool lua_is_valid_num_value_string(const char *str) {
	if (!rz_is_valid_input_num_value(NULL, str)) {
		RZ_LOG_ERROR("assembler: lua: %s is not a valid number argument\n", str);
		return false;
	}
	return true;
}

int lua_convert_str_to_num(const char *str) {
	return (int)strtoll(str, NULL, 0);
}