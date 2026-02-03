// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2017 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#include "arch_51.h"

const ut8 luaP_opmodes51[LUA_NUM_OPCODES] = {
	/*       T  A    B       C     mode                opcode       */
	opmode(0, 1, OpArgR, OpArgN, iABC), /* OP_MOVE */
	opmode(0, 1, OpArgK, OpArgN, iABx), /* OP_LOADK */
	opmode(0, 1, OpArgU, OpArgU, iABC), /* OP_LOADBOOL */
	opmode(0, 1, OpArgR, OpArgN, iABC), /* OP_LOADNIL */
	opmode(0, 1, OpArgU, OpArgN, iABC), /* OP_GETUPVAL */
	opmode(0, 1, OpArgK, OpArgN, iABx), /* OP_GETGLOBAL */
	opmode(0, 1, OpArgR, OpArgK, iABC), /* OP_GETTABLE */
	opmode(0, 0, OpArgK, OpArgN, iABx), /* OP_SETGLOBAL */
	opmode(0, 0, OpArgU, OpArgN, iABC), /* OP_SETUPVAL */
	opmode(0, 0, OpArgK, OpArgK, iABC), /* OP_SETTABLE */
	opmode(0, 1, OpArgU, OpArgU, iABC), /* OP_NEWTABLE */
	opmode(0, 1, OpArgR, OpArgK, iABC), /* OP_SELF */
	opmode(0, 1, OpArgK, OpArgK, iABC), /* OP_ADD */
	opmode(0, 1, OpArgK, OpArgK, iABC), /* OP_SUB */
	opmode(0, 1, OpArgK, OpArgK, iABC), /* OP_MUL */
	opmode(0, 1, OpArgK, OpArgK, iABC), /* OP_DIV */
	opmode(0, 1, OpArgK, OpArgK, iABC), /* OP_MOD */
	opmode(0, 1, OpArgK, OpArgK, iABC), /* OP_POW */
	opmode(0, 1, OpArgR, OpArgN, iABC), /* OP_UNM */
	opmode(0, 1, OpArgR, OpArgN, iABC), /* OP_NOT */
	opmode(0, 1, OpArgR, OpArgN, iABC), /* OP_LEN */
	opmode(0, 1, OpArgR, OpArgR, iABC), /* OP_CONCAT */
	opmode(0, 0, OpArgR, OpArgN, iAsBx), /* OP_JMP */
	opmode(1, 0, OpArgK, OpArgK, iABC), /* OP_EQ */
	opmode(1, 0, OpArgK, OpArgK, iABC), /* OP_LT */
	opmode(1, 0, OpArgK, OpArgK, iABC), /* OP_LE */
	opmode(1, 1, OpArgR, OpArgU, iABC), /* OP_TEST */
	opmode(1, 1, OpArgR, OpArgU, iABC), /* OP_TESTSET */
	opmode(0, 1, OpArgU, OpArgU, iABC), /* OP_CALL */
	opmode(0, 1, OpArgU, OpArgU, iABC), /* OP_TAILCALL */
	opmode(0, 0, OpArgU, OpArgN, iABC), /* OP_RETURN */
	opmode(0, 1, OpArgR, OpArgN, iAsBx), /* OP_FORLOOP */
	opmode(0, 1, OpArgR, OpArgN, iAsBx), /* OP_FORPREP */
	opmode(1, 0, OpArgN, OpArgU, iABC), /* OP_TFORLOOP */
	opmode(0, 0, OpArgU, OpArgU, iABC), /* OP_SETLIST */
	opmode(0, 0, OpArgN, OpArgN, iABC), /* OP_CLOSE */
	opmode(0, 1, OpArgU, OpArgN, iABx), /* OP_CLOSURE */
	opmode(0, 1, OpArgU, OpArgN, iABC) /* OP_VARARG */
};

#define lua_strcase(case_str) if ( \
	((limit) <= sizeof(case_str) - 1) && \
	rz_str_ncasecmp((name), (case_str), sizeof(case_str) - 1) == 0)

LuaOpNameList get_lua51_opnames(void) {
	LuaOpNameList list = RZ_NEWS(char *, LUA_NUM_OPCODES + 1);
	if (list == NULL) {
		RZ_LOG_ERROR("Cannot allocate lua51 opcode list.\n");
		return NULL;
	}

	// Do not free the const string
	list[OP_MOVE] = "move";
	list[OP_LOADK] = "loadk";
	list[OP_LOADBOOL] = "loadbool";
	list[OP_LOADNIL] = "loadnil";
	list[OP_GETUPVAL] = "getupval";
	list[OP_GETGLOBAL] = "getglobal";
	list[OP_GETTABLE] = "gettable";
	list[OP_SETGLOBAL] = "setglobal";
	list[OP_SETUPVAL] = "setupval";
	list[OP_SETTABLE] = "settable";
	list[OP_NEWTABLE] = "newtable";
	list[OP_SELF] = "self";
	list[OP_ADD] = "add";
	list[OP_SUB] = "sub";
	list[OP_MUL] = "mul";
	list[OP_DIV] = "div";
	list[OP_MOD] = "mod";
	list[OP_POW] = "pow";
	list[OP_UNM] = "unm";
	list[OP_NOT] = "not";
	list[OP_LEN] = "len";
	list[OP_CONCAT] = "concat";
	list[OP_JMP] = "jmp";
	list[OP_EQ] = "eq";
	list[OP_LT] = "lt";
	list[OP_LE] = "le";
	list[OP_TEST] = "test";
	list[OP_TESTSET] = "testset";
	list[OP_CALL] = "call";
	list[OP_TAILCALL] = "tailcall";
	list[OP_RETURN] = "return";
	list[OP_FORLOOP] = "forloop";
	list[OP_FORPREP] = "forprep";
	list[OP_TFORLOOP] = "tforloop";
	list[OP_SETLIST] = "setlist";
	list[OP_CLOSE] = "close";
	list[OP_CLOSURE] = "closure";
	list[OP_VARARG] = "vararg";
	return list;
}

ut8 get_lua51_opcode_by_name(const char *name, int limit) {
	lua_strcase("move") return OP_MOVE;
	lua_strcase("loadk") return OP_LOADK;
	lua_strcase("loadbool") return OP_LOADBOOL;
	lua_strcase("loadnil") return OP_LOADNIL;
	lua_strcase("getupval") return OP_GETUPVAL;
	lua_strcase("getglobal") return OP_GETGLOBAL;
	lua_strcase("setglobal") return OP_SETGLOBAL;
	lua_strcase("gettable") return OP_GETTABLE;
	lua_strcase("setupval") return OP_SETUPVAL;
	lua_strcase("settable") return OP_SETTABLE;
	lua_strcase("newtable") return OP_NEWTABLE;
	lua_strcase("self") return OP_SELF;
	lua_strcase("add") return OP_ADD;
	lua_strcase("sub") return OP_SUB;
	lua_strcase("mul") return OP_MUL;
	lua_strcase("div") return OP_DIV;
	lua_strcase("mod") return OP_MOD;
	lua_strcase("pow") return OP_POW;
	lua_strcase("unm") return OP_UNM;
	lua_strcase("not") return OP_NOT;
	lua_strcase("len") return OP_LEN;
	lua_strcase("concat") return OP_CONCAT;
	lua_strcase("jmp") return OP_JMP;
	lua_strcase("eq") return OP_EQ;
	lua_strcase("lt") return OP_LT;
	lua_strcase("le") return OP_LE;
	lua_strcase("test") return OP_TEST;
	lua_strcase("testset") return OP_TESTSET;
	lua_strcase("call") return OP_CALL;
	lua_strcase("tailcall") return OP_TAILCALL;
	lua_strcase("return") return OP_RETURN;
	lua_strcase("forloop") return OP_FORLOOP;
	lua_strcase("forprep") return OP_FORPREP;
	lua_strcase("tforloop") return OP_TFORLOOP;
	lua_strcase("setlist") return OP_SETLIST;
	lua_strcase("close") return OP_CLOSE;
	lua_strcase("closure") return OP_CLOSURE;
	lua_strcase("vararg") return OP_VARARG;

	return OP_VARARG + 1; // invalid
}
