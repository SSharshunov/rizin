// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#include "arch_54.h"
#include "rz_core.h"
#include <rz_io_plugins.h>

#include <luac/luac_common.h>

char *read_string_from_vaddr(RzAnalysis *analysis, ut64 addr) {
	if (addr == UT64_MAX || addr == 0) return NULL;

	// 1. Сначала узнаем длину строки (или читаем буфер с запасом)
	// В Lua строки могут быть длинными, но для имен методов обычно хватает 256 байт
	ut8 buf[256];
	int res = analysis->iob.read_at(analysis->iob.io, addr, buf, sizeof(buf) - 1);

	if (res <= 0) return NULL;

	buf[res] = '\0'; // Гарантируем zero-termination

	// 2. Если это Lua TString, строка может начинаться со смещением (пропуск заголовка)
	// В Lua 5.4 заголовок TString обычно составляет 24-32 байта.
	// Если ваш RzBin замапил адрес сразу на начало текста, то читаем с 0.
	return rz_str_dup((const char *)buf);
}

RzRegItem *new_reg_item(RzAnalysis *analysis, const char *fmt, ut8 index) {
	char *r = rz_str_newf(fmt, index);
	RzRegItem *reg = rz_reg_get(analysis->reg, r, RZ_REG_TYPE_GPR);
	free(r);
	return reg;
}

int lua54_analysis_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask) {
	if (!op || len < 4) {
		return 0;
	}

	memset(op, 0, sizeof(RzAnalysisOp));
	LuaInstruction instruction = lua_build_instruction(data);

	op->size = 4;
	op->addr = addr;

	LuaOpCode54 opcode = GET_OPCODE54(instruction);

	if (opcode > OP_EXTRAARG) {
		op->family = RZ_ANALYSIS_OP_FAMILY_UNKNOWN;
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		op->nopcode = 1;
		op->cycles = 1;
		op->size = 2;
		op->eob = true;
		op->mnemonic = rz_str_dup("invalid");
		return op->size;
	}
	int a = GETARG_A4(instruction);
	int b = GETARG_B4(instruction);
	int c = GETARG_C4(instruction);
	int ax = GETARG_Ax4(instruction);
	int bx = GETARG_Bx4(instruction);
	int sb = GETARG_sB(instruction);
	int sc = GETARG_sC(instruction);
	int sbx = GETARG_sBx4(instruction);
	int sj = GETARG_sJ(instruction);
	int k = GETARG_k4(instruction);

	char *comment = NULL;
	char *mnemonic = NULL;

	switch (opcode) {
	case OP_MOVE: /*	A B	R[A] := R[B]					*/
	{
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->jump = addr + 4;

		op->dst = rz_analysis_value_new();
		if (op->dst) {
			op->dst->reg = new_reg_item(analysis, "r%d", a);
		}

		op->src[0] = rz_analysis_value_new();
		if (op->src[0]) {
			op->src[0]->reg = new_reg_item(analysis, "r%d", b);
		}

		mnemonic = rz_str_newf("move r%d, r%d", a, b);
		comment = rz_str_newf("r%d = r%d", a, b);
	} break;
	case OP_LOADK: /*	A Bx	R[A] := K[Bx]					*/
	{
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->jump = addr + 4;

		op->ptr = get_k_vaddr(analysis, addr, bx);

		op->dst = rz_analysis_value_new();
		if (op->dst) {
			op->dst->reg = new_reg_item(analysis, "r%d", a);
		}

		mnemonic = rz_str_newf("loadk r%d, k%d", a, bx);
		comment = rz_str_newf("r%d = constants[%d]", a, bx);
	} break;
	case OP_LOADI: /*	A sBx	R[A] := sBx					*/
	{
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->jump = addr + 4;

		op->dst = rz_analysis_value_new();
		if (op->dst) {
			op->dst->reg = new_reg_item(analysis, "r%d", a);
		}

		op->val = (ut64)sbx;
		op->src[0] = rz_analysis_value_new();
		if (op->src[0]) {
			op->src[0]->imm = (ut64)sbx;
		}

		mnemonic = rz_str_newf("loadi r%d, %d", a, sbx);
		comment = rz_str_newf("r%d = %d", a, sbx);
	} break;
	case OP_LOADF: /*	A sBx	R[A] := (lua_Number)sBx				*/
	case OP_LOADTRUE: /*	A	R[A] := true					*/
	case OP_LOADNIL: /*	A B	R[A], R[A+1], ..., R[A+B] := nil		*/
	case OP_LOADFALSE: /*	A	R[A] := false					*/
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case OP_LOADKX: /*	A	R[A] := K[extra arg]				*/
	{
		///< read EXTRAARG
		ut32 next_inst = *(ut32 *)(data + 4);
		int ax = GETARG_Ax4(next_inst);

		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->size = 8; ///< 2 instructions (4+4 bytes)

		op->ptr = get_k_vaddr(analysis, addr, ax);

		op->dst = rz_analysis_value_new();
		if (op->dst) {
			op->dst->reg = new_reg_item(analysis, "r%d", a);
		}
		mnemonic = rz_str_newf("loadkx r%d, k%d", a, ax);
		comment = rz_str_newf("r%d = constants[%d]", a, ax);
	} break;
	case OP_LFALSESKIP: /*A	R[A] := false; pc++				*/ {
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->jump = addr + 8;
		op->fail = UT64_MAX;
		op->val = 0;

		op->dst = rz_analysis_value_new();
		if (op->dst) {
			op->dst->reg = new_reg_item(analysis, "r%d", a);
		}

		mnemonic = rz_str_newf("lfalseskip r%d", a);
		comment = rz_str_newf("r%d = false, skip next", a);
	} break;
	case OP_GETUPVAL: /*	A B	R[A] := UpValue[B]				*/
	{
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->jump = addr + 4;

		op->dst = rz_analysis_value_new();
		op->dst->reg = new_reg_item(analysis, "r%d", a);

		op->src[0] = rz_analysis_value_new();
		op->src[0]->reg = new_reg_item(analysis, "uv%d", b);

		mnemonic = rz_str_newf("getupval r%d, uv%d", a, b);
		comment = rz_str_newf("r%d = upvalue[%d]", a, b);
	} break;
	case OP_GETI: /*	A B C	R[A] := R[B][C]					*/
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->src[0] = rz_analysis_value_new();
		op->src[0]->imm = (ut64)c;
		break;
	case OP_GETFIELD: /*	A B C	R[A] := R[B][K[C]:string]			*/
	{
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->jump = addr + 4;

		op->ptr = get_k_vaddr(analysis, addr, c);

		op->dst = rz_analysis_value_new();
		op->dst->reg = new_reg_item(analysis, "r%d", a);

		op->src[0] = rz_analysis_value_new();
		op->src[0]->reg = new_reg_item(analysis, "r%d", b);

		char *constant_name = get_const_string(analysis, addr, b);
		mnemonic = rz_str_newf("getfield r%d, r%d, k%d", a, b, c);
		comment = rz_str_newf("r%d = r%d['%s']", a, c, constant_name);
	} break;
	case OP_GETTABLE: /*	A B C	R[A] := R[B][R[C]]				*/
	{
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->jump = addr + 4;

		op->dst = rz_analysis_value_new();
		if (op->dst) {
			op->dst->reg = new_reg_item(analysis, "r%d", a);
		}

		op->src[0] = rz_analysis_value_new();
		if (op->src[0]) {
			op->src[0]->reg = new_reg_item(analysis, "r%d", b);
		}

		op->src[1] = rz_analysis_value_new();
		if (op->src[1]) {
			op->src[1]->reg = new_reg_item(analysis, "r%d", c);
		}

		mnemonic = rz_str_newf("gettable r%d, r%d, r%d", a, b, c);
		comment = rz_str_newf("r%d = r%d[r%d]", a, b, c);
	} break;
	case OP_SETTABLE: /*	A B C	R[A][R[B]] := RK(C)				*/
	{
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->jump = addr + 4;

		op->dst = rz_analysis_value_new();
		if (op->dst) {
			op->dst->reg = new_reg_item(analysis, "r%d", a);
		}

		op->src[0] = rz_analysis_value_new();
		if (op->src[0]) {
			op->src[0]->reg = new_reg_item(analysis, "r%d", c);
			if (c <= 0xFF) {
				op->src[0]->reg = new_reg_item(analysis, "r%d", c);
			} else {
				int k_idx = c & 0xFF;
				op->src[0]->imm = get_k_vaddr(analysis, addr, k_idx);
				op->src[0]->memref = 1;
			}
		}

		op->src[1] = rz_analysis_value_new();
		if (op->src[1]) {
			op->src[1]->reg = new_reg_item(analysis, "r%d", b);
		}
		mnemonic = rz_str_newf("settable r%d, r%d, %s%d", a, b, (c <= 0xff ? "r" : "k"), (c & 0xff));
		comment = rz_str_newf("r%d[r%d] = RK(%d)", a, b, c);
	} break;
	case OP_GETTABUP: /*	A B C	R[A] := UpValue[B][K[C]:string]			*/ {
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->jump = addr + 4;

		op->ptr = get_k_vaddr(analysis, addr, c);

		op->dst = rz_analysis_value_new();
		op->dst->reg = new_reg_item(analysis, "r%d", a);

		op->src[0] = rz_analysis_value_new();
		op->src[0]->reg = new_reg_item(analysis, "uv%d", b);

		mnemonic = rz_str_newf("gettabup r%d, uv%d, k%d", a, b, c);

		const char *scope = (b == 0) ? "_ENV" : rz_str_newf("upvalue[%d]", b);
		char *constant_name = get_const_string(analysis, addr, c);
		comment = rz_str_newf("r%d = %s['%s']", a, scope, (char*)constant_name);
	} break;
	case OP_SETTABUP: /*	A B C	UpValue[A][K[B]:string] := RK(C)		*/
	{
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->jump = addr + 4;

		op->ptr = get_k_vaddr(analysis, addr, b);

		op->dst = rz_analysis_value_new();
		op->dst->reg = new_reg_item(analysis, "r%d", a);

		op->src[0] = rz_analysis_value_new();
		if (op->src[0]) {
			op->src[0]->reg = new_reg_item(analysis, "r%d", c);
			if (c <= 0xFF) {
				op->src[0]->reg = new_reg_item(analysis, "r%d", c);
			} else {
				int k_idx = c & 0xFF;
				op->src[0]->imm = get_k_vaddr(analysis, addr, k_idx);
				op->src[0]->memref = 1;
			}
		}

		mnemonic = rz_str_newf("settabup uv%d, k%d, %s%d", a, b, (c <= 0xff ? "r" : "k"), (c & 0xff));
		const char *scope = (a == 0) ? "_ENV" : rz_str_newf("upvalue[%d]", a);
		char *constant_name = get_const_string(analysis, addr, b);
		comment = rz_str_newf("%s['%s'] = RK(%d)", scope, constant_name, c);
	} break;
	case OP_SETUPVAL: /*	A B	UpValue[B] := R[A]				*/
	{
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->jump = addr + 4;

		op->dst = rz_analysis_value_new();
		op->dst->reg = new_reg_item(analysis, "uv%d", b);

		op->src[0] = rz_analysis_value_new();
		op->src[0]->reg = new_reg_item(analysis, "r%d", a);

		mnemonic = rz_str_newf("setupval r%d, uv%d", a, b);
		comment = rz_str_newf("upvalue[%d] = r%d", b, a);
	} break;
	case OP_SETI: /*	A B C	R[A][B] := RK(C)				*/
	{
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->jump = addr + 4;

		op->dst = rz_analysis_value_new();
		op->dst->reg = new_reg_item(analysis, "r%d", a);

		op->src[0] = rz_analysis_value_new();
		if (op->src[0]) {
			op->src[0]->reg = new_reg_item(analysis, "r%d", c);
			if (c <= 0xFF) {
				op->src[0]->reg = new_reg_item(analysis, "r%d", c);
			} else {
				int k_idx = c & 0xFF;
				op->src[0]->imm = get_k_vaddr(analysis, addr, k_idx);
				op->src[0]->memref = 1;
			}
		}

		op->src[1] = rz_analysis_value_new();
		if (op->src[1]) {
			op->src[1]->imm = (ut64)b;
		}

		mnemonic = rz_str_newf("seti r%d, %d, %s%d", a, b, (c <= 0xff ? "r" : "k"), (c & 0xff));
		comment = rz_str_newf("r%d[%d] = RK(%d)", a, b, c);
	} break;
	case OP_SETFIELD: /*	A B C	R[A][K[B]:string] := RK(C)			*/ {
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->jump = addr + 4;

		op->ptr = get_k_vaddr(analysis, addr, b);
		op->dst = rz_analysis_value_new();
		op->dst->reg = new_reg_item(analysis, "r%d", a);
		op->src[0] = rz_analysis_value_new();
		if (c <= 0xff) {
			op->src[0]->reg = new_reg_item(analysis, "r%d", c);
		} else {
			op->src[0]->imm = (ut64)c;
		}

		char *constant_name = get_const_string(analysis, addr, b);

		mnemonic = rz_str_newf("setfield r%d, k%d, r%d", a, b, c);
		comment = rz_str_newf("table r%d['%s'] = r%d", a, constant_name, c);

		// 1. Читаем предыдущую инструкцию (адрес - 4)
		ut8 prev_buf[4];
		if (analysis->iob.read_at(analysis->iob.io, addr - 4, prev_buf, 4)) {
			ut32 prev_inst = rz_read_le32(prev_buf);
			int prev_opcode = prev_inst & 0x7f; // Маска опкода для Lua 5.4

			// 2. Проверяем, был ли это OP_CLOSURE (0x51)
			if (prev_opcode == OP_CLOSURE) {
				int bx = GETARG_Bx4(prev_inst);

				ut64 proto_base = (addr - 4) & ~0xFFF;
				ut64 child_vaddr = proto_base + ((bx + 1) * 0x1000);
				// ut64 child_vaddr = proto_base + ((bx + 1));

				// printf("child_vaddr: %08llx\n", proto_base);
				// printf("child_vaddr: 0x%llx\n", child_vaddr);

				// Устанавливаем новый красивый флаг
				char *flag_name = rz_str_newf("method.%s", constant_name);
				// printf("flag_name: %s\n", flag_name);
				// analysis->flb.set(analysis->flb.f, flag_name, child_vaddr, 1);

				// Добавление символа "на лету"
				if (analysis->binb.bin && analysis->binb.bin->cur && analysis->binb.bin->cur->o) {
					RzBinObject *obj = analysis->binb.bin->cur->o;
					bool exists = false;
					void **it;
					size_t size = 0;
					RzBinSection *section = NULL;

					rz_pvector_foreach (obj->sections, it) {
						section = (RzBinSection *)*it;
						if (section->vaddr == child_vaddr) {
							exists = true;
							size = section->size;

							break;
						}
					}

					exists = false;
					rz_pvector_foreach (obj->symbols, it) {
					     RzBinSymbol *s = (RzBinSymbol *)*it;
						if (s->vaddr == child_vaddr) {
							exists = true;
							break;
						}
					}
					if (!exists) {
						RzBinSymbol *msym = rz_bin_symbol_new(flag_name, section->paddr, child_vaddr);
						msym->type = RZ_BIN_TYPE_FUNC_STR;
						msym->bind = RZ_BIN_BIND_GLOBAL_STR;
						msym->size = section->size;
						// msym->paddr = section->paddr;
						rz_pvector_push(obj->symbols, msym);
						// rz_analysis_create_function(analysis, flag_name, child_vaddr, RZ_ANALYSIS_FCN_TYPE_FCN);

						// rz_bin_symbol_free(msym);
					}
					RzAnalysisFunction *fcn = rz_analysis_get_function_at(analysis, child_vaddr);
					if (!fcn) {
						// Создаем функцию.
						// Четвертый параметр часто - тип функции, используй RZ_ANALYSIS_FCN_TYPE_FCN
						analysis->flb.unset_off(analysis->flb.f, child_vaddr);
						fcn = rz_analysis_create_function(analysis, flag_name, child_vaddr, RZ_ANALYSIS_FCN_TYPE_FCN);

						if (fcn) {
							// ОЧЕНЬ ВАЖНО: задать размер.
							// Если размер 0 или 1, Rizin может "потерять" её при перерисовке графа.
							// fcn->size = 4; // Как минимум одна инструкция
						}
						if (!fcn) {
							eprintf("Failed to create function at 0x%08"PFMT64x"\n", child_vaddr);
						}
					}
					// else {
					// 	rz_bin_symbol_free(msym);
					// }
					// bool found = false;

					// RzAnalysisFunction *f = ht_sp_find(analysis->ht_name_fun, flag_name, &found);
					// if (f) {
					// 	printf("found %s\n", f->name);
					// }
					// if (found) {
					// 	rz_analysis_create_function(analysis, flag_name, child_vaddr, RZ_ANALYSIS_FCN_TYPE_FCN);
					// }
					// if (function_name_exists(analysis, fcn->name, fcn->addr)) {
					// 	RZ_LOG_WARN("Function name '%s' already exists\n", fcn->name);
					// 	return false;
					// }
					// size_t x = rz_pvector_find_index(obj->symbols, msym, compare_sym, /*void *user*/ NULL);
					// if (rz_pvector_contains(obj->symbols, msym)) {
					// 	rz_pvector_push(obj->symbols, msym);
					// }



					// Добавляем в список символов текущего объекта
					// rz_pvector_push(obj->symbols, msym);
					// rz_list_append(obj->symbols, msym);

					RzFlagItem *flag = analysis->flb.get_at(analysis->flb.f, child_vaddr, false);
					if (flag && flag->name) {
						// printf("flag: %s\n", flag->name);
						// Если флаг содержит мусор "str.ount...", чистим его
						// char *real_name = clean_lua_string(flag->name);
						//
						// char *new_flag = rz_str_newf("flg.%s", flag_name);
						// analysis->flb.set(analysis->flb.f, new_flag, child_vaddr, 1);
						analysis->flb.set(analysis->flb.f, flag_name, child_vaddr, size);

						// free(new_flag);
						// free(real_name);
					}
				}

				free(flag_name);
				// RzBinSymbol *sym = analysis->binb.get_symbol_at(analysis->binb.bin, vaddr);
				// if (sym && sym->name) {
				// 	// У тебя есть имя!
				// }
				// int closure_a = GETARG_A(prev_inst);
    //
				// // Проверяем, что CLOSURE загрузил функцию именно в тот регистр,
				// // который мы сейчас вызываем в CALL
				// if (closure_a == a) {
				// 	int bx = GETARG_Bx(prev_inst);
    //
				// 	// Теперь мы точно знаем адрес функции (Proto)
				// 	op->jump = get_proto_vaddr(analysis, bx);
				// 	op->type = RZ_ANALYSIS_OP_TYPE_CALL;
    //
				// 	rz_analysis_op_set_comment(op, rz_str_newf("Calling closure from Proto[%d]", bx));
				// }
			}
		}

		break;
	}
	case OP_NEWTABLE: /*	A B C k	R[A] := {}					*/ {
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD; // Создание/загрузка новой структуры
		op->jump = addr + 4;

		op->dst = rz_analysis_value_new();
		op->dst->reg = new_reg_item(analysis, "r%d", a);

		int array_size = (b > 0) ? (1 << (b - 1)) : 0;
		int hash_size = (c > 0) ? (1 << (c - 1)) : 0;

		op->val = array_size + hash_size;

		mnemonic = rz_str_newf("newtable r%d, %d, %d, %d", a, b, c, k);
		comment = rz_str_newf("r%d = {}; array: %d, hash: %d%s",
			a, array_size, hash_size, k ? " (extra)" : "");
	} break;
	case OP_SELF: /*	A B C	R[A+1] := R[B]; R[A] := R[B][RK(C):string]	*/
	{
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->jump = addr + 4;
		op->ptr = get_k_vaddr(analysis, addr, c);

		op->dst = rz_analysis_value_new();
		op->dst->reg = new_reg_item(analysis, "r%d", a);

		op->src[0] = rz_analysis_value_new();
		op->src[0]->reg = new_reg_item(analysis, "r%d", b);

		op->val = c;

		mnemonic = rz_str_newf("self r%d, r%d, k%d", a, b, c);
		char *constant_name = get_const_string(analysis, addr, c);
		comment = rz_str_newf("r%d=r%d (self), r%d=r%d['%s']", a + 1, b, a, b, constant_name);
	} break;
	case OP_ADDI: /*	A B sC	R[A] := R[B] + sC				*/
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;

		op->dst = rz_analysis_value_new();
		op->dst->reg = new_reg_item(analysis, "r%d", a);

		op->src[0] = rz_analysis_value_new();
		op->src[0]->reg = new_reg_item(analysis, "r%d", b);

		op->src[1] = rz_analysis_value_new();
		st32 immediate_val = sc;
		op->src[1]->imm = (ut64)(st64)immediate_val;

		break;
	case OP_ADDK: /*	A B C	R[A] := R[B] + K[C]				*/
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;

		op->dst = rz_analysis_value_new();
		op->dst->reg = new_reg_item(analysis, "r%d", a);
		op->src[0] = rz_analysis_value_new();
		op->src[0]->reg = new_reg_item(analysis, "r%d", b);

		op->ptr = (ut64)c;
		break;
	case OP_ADD: /*	A B C	R[A] := R[B] + R[C]				*/
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case OP_SUBK: /*	A B C	R[A] := R[B] - K[C]				*/
	case OP_SUB: /*	A B C	R[A] := R[B] - R[C]				*/
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case OP_MULK: /*	A B C	R[A] := R[B] * K[C]				*/
	case OP_MUL: /*	A B C	R[A] := R[B] * R[C]				*/
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case OP_MOD: /*	A B C	R[A] := R[B] % R[C]				*/
	case OP_MODK: /*	A B C	R[A] := R[B] % K[C]				*/
		op->type = RZ_ANALYSIS_OP_TYPE_MOD;
		break;
	case OP_POW: /*	A B C	R[A] := R[B] ^ R[C]				*/
	case OP_POWK: /*	A B C	R[A] := R[B] ^ K[C]				*/
		break;
	case OP_DIVK: /*	A B C	R[A] := R[B] / K[C]				*/
	case OP_IDIVK: /*	A B C	R[A] := R[B] // K[C]				*/
	case OP_DIV: /*	A B C	R[A] := R[B] / R[C]				*/
	case OP_IDIV: /*	A B C	R[A] := R[B] // R[C]				*/
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case OP_BANDK: /*	A B C	R[A] := R[B] & K[C]:integer			*/
	case OP_BAND: /*	A B C	R[A] := R[B] & R[C]				*/
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case OP_BOR: /*	A B C	R[A] := R[B] | R[C]				*/
	case OP_BORK: /*	A B C	R[A] := R[B] | K[C]:integer			*/
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case OP_BXOR: /*	A B C	R[A] := R[B] ~ R[C]				*/
	case OP_BXORK: /*	A B C	R[A] := R[B] ~ K[C]:integer			*/
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case OP_NOT: /*	A B	R[A] := not R[B]				*/
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		break;
	case OP_BNOT: /*	A B	R[A] := ~R[B]					*/
		op->type = RZ_ANALYSIS_OP_TYPE_CPL;
		break;
	case OP_SHRI: /*	A B sC	R[A] := R[B] >> sC				*/
	case OP_SHR: /*	A B C	R[A] := R[B] >> R[C]				*/
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case OP_SHLI: /*	A B sC	R[A] := sC << R[B]				*/
	case OP_SHL: /*	A B C	R[A] := R[B] << R[C]				*/
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case OP_MMBIN: /*	A B C	call C metamethod over R[A] and R[B]		*/
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;

		op->src[0] = rz_analysis_value_new();
		op->src[0]->reg = new_reg_item(analysis, "r%d", a);

		op->src[1] = rz_analysis_value_new();
		op->src[1]->reg = new_reg_item(analysis, "r%d", b);

		op->val = (ut64)c;
		op->fail = addr + 4;
		break;
	case OP_MMBINI: /*	A sB C k	call C metamethod over R[A] and sB	*/
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->src[0] = rz_analysis_value_new();
		op->src[0]->reg = new_reg_item(analysis, "r%d", a);

		op->src[1] = rz_analysis_value_new();
		op->src[1]->imm = (ut64)(st64)sb;

		op->val = (ut64)c;
		op->fail = addr + 4;
		break;
	case OP_MMBINK: /*	A B C k		call C metamethod over R[A] and K[B]	*/
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->ptr = (ut64)b;
		op->val = (ut64)c;
		op->fail = addr + 4;
		break;
	case OP_UNM: /*	A B	R[A] := -R[B]					*/
	case OP_LEN: /*	A B	R[A] := #R[B] (length operator)			*/
	case OP_CONCAT: /*	A B	R[A] := R[A].. ... ..R[A + B - 1]		*/
	case OP_CLOSE: /*	A	close all upvalues >= R[A]			*/
	case OP_TBC: /*	A	mark variable A "to be closed"			*/
		break;
	case OP_JMP: /*	sJ	pc += sJ					*/
	{
		ut64 target = addr + 4 + (sj * 4);

		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = target;
		op->fail = UT64_MAX;
		op->eob = true;

		mnemonic = rz_str_newf("jmp %d", sj);
		comment = rz_str_newf("jump to 0x%" PFMT64x, target);
	} break;
	case OP_EQ: /*	A B k	if ((R[A] == R[B]) ~= k) then pc++		*/
	case OP_LT: /*	A B k	if ((R[A] <  R[B]) ~= k) then pc++		*/
	case OP_LE: /*	A B k	if ((R[A] <= R[B]) ~= k) then pc++		*/ {
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = addr + 4;
		op->fail = addr + 8;

		if (opcode == OP_EQ) {
			op->cond = RZ_TYPE_COND_EQ;
		} else if (opcode == OP_LT) {
			op->cond = RZ_TYPE_COND_LT;
		} else {
			op->cond = RZ_TYPE_COND_LE;
		}

		op->src[0] = rz_analysis_value_new();
		op->src[0]->reg = new_reg_item(analysis, "r%d", a);
		op->src[1] = rz_analysis_value_new();
		op->src[1]->reg = new_reg_item(analysis, "r%d", b);

		mnemonic = rz_str_newf("eq r%d, r%d, %d", a, b, k);
	} break;
	case OP_EQK: /*	A B k	if ((R[A] == K[B]) ~= k) then pc++		*/
	case OP_EQI: /*	A sB k	if ((R[A] == sB) ~= k) then pc++		*/
		break;
	case OP_LTI: /*	A sB k	if ((R[A] < sB) ~= k) then pc++			*/
	case OP_LEI: /*	A sB k	if ((R[A] <= sB) ~= k) then pc++		*/
	case OP_GTI: /*	A sB k	if ((R[A] > sB) ~= k) then pc++			*/
	case OP_GEI: /*	A sB k	if ((R[A] >= sB) ~= k) then pc++		*/
	case OP_TEST: /*	A k	if (not R[A] == k) then pc++			*/
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + 8;
		op->fail = op->addr + 4;
		break;
	case OP_CALL: /*	A B C	R[A], ... ,R[A+C-2] := R[A](R[A+1], ... ,R[A+B-1]) */
		op->type = RZ_ANALYSIS_OP_TYPE_CALL; // or RZ_ANALYSIS_OP_TYPE_RCALL

		op->dst = rz_analysis_value_new();
		op->dst->reg = new_reg_item(analysis, "r%d", a);
		op->dst->type = RZ_ANALYSIS_VAL_REG;

		op->src[0] = rz_analysis_value_new();
		op->src[0]->reg = new_reg_item(analysis, "r%d", a);

		// op->ptr = c * 0x1000;
		op->ptr = c * 0x1000;
		// op->jump = op->ptr;
		// op->jump = addr + 4;
		// op->jump = op->ptr;
		op->jump = c * 0x1000;
		// op->jump = 0x1000;
		op->fail = addr + 4;
		// op->fail = UT64_MAX;
		// rz_analysis_xrefs_set(analysis, op->addr, op->ptr+0x1000, RZ_ANALYSIS_XREF_TYPE_CALL);

		int nparams = (b > 1) ? (b - 1) : (b == 0 ? -1 : 0);
		int nresults = (c > 1) ? (c - 1) : (c == 0 ? -1 : 0);

		op->val = (b > 0) ? (b - 1) : 0;

		op->stackop = RZ_ANALYSIS_STACK_SET;
		op->stackptr = (nresults != -1 ? nresults : 0) - (nparams != -1 ? nparams : 0);

		char *params_str = (b == 0) ? rz_str_dup("varargs") : rz_str_newf("%d", nparams);
		char *results_str = (c == 0) ? rz_str_dup("all") : rz_str_newf("%d", nresults);

		comment = rz_str_newf("%s in %s out", params_str, results_str);

		free(params_str);
		free(results_str);
		break;
	case OP_TESTSET: /*	A B k	if (not R[B] == k) then pc++ else R[A] := R[B]	*/
		op->type = RZ_ANALYSIS_OP_TYPE_CMOV;
		op->jump = op->addr + 8;
		op->fail = op->addr + 4;
		break;
	case OP_TAILCALL: /*	A B C k	return R[A](R[A+1], ... ,R[A+B-1])		*/
	{
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = 0;

		op->stackop = RZ_ANALYSIS_STACK_NULL;

		op->src[0] = rz_analysis_value_new();
		op->src[0]->reg = new_reg_item(analysis, "r%d", a);

		mnemonic = rz_str_newf("tailcall r%d, %d, %d", a, b, k);

		if (b > 0) {
			comment = rz_str_newf("return r%d(args: %d)", a, b - 1);
		} else {
			comment = rz_str_newf("return r%d(all varargs)", a);
		}
	} break;
	case OP_RETURN: /*	A B C k	return R[A], ... ,R[A+B-2]	(see note)	*/ {
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->eob = true;

		mnemonic = rz_str_newf("return r%d, %d, %d", a, b, k);
		if (b == 0) {
			comment = rz_str_dup("return all (top of stack)");
		} else {
			comment = rz_str_newf("%d out", b - 1);
		}
	} break;
	case OP_RETURN1: /*	A	return R[A]					*/
	{
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		// op->eob = true;

		op->src[0] = rz_analysis_value_new();
		op->src[0]->reg = new_reg_item(analysis, "r%d", a);

		mnemonic = rz_str_newf("return1 r%d", a);
		comment = rz_str_newf("return r%d", a);
	} break;
	case OP_RETURN0: /*		return						*/ {
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->eob = true;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -4;
		// op->jump = UT64_MAX;
		op->jump = UT64_MAX;

		mnemonic = rz_str_dup("return0");
		comment = rz_str_dup("empty return");
	} break;
	case OP_FORLOOP: /*	A Bx	update counters; if loop continues then pc-=Bx; */
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = op->addr + 4 - 4 * (GETARG_Bx4(instruction));
		op->fail = op->addr + 4;
		break;
	case OP_FORPREP: /*	A Bx	<check values and prepare counters>;
	      if not to run then pc+=Bx+1;			*/
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = op->addr + 4 + 4 * (bx + 1);
		op->fail = op->addr + 4;
		break;
	case OP_CLOSURE: /*	A Bx	R[A] := closure(KPROTO[Bx])			*/ {
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->datatype = RZ_ANALYSIS_DATATYPE_OBJECT;

		ut64 proto_base = addr & ~0xFFF;
		ut64 child_vaddr = proto_base + ((bx + 1) * 0x1000);

		op->ptr = child_vaddr;
		op->jump = child_vaddr;

		op->fail = UT64_MAX;

		op->dst = rz_analysis_value_new();
		op->dst->reg = new_reg_item(analysis, "r%d", a);

		mnemonic = rz_str_newf("closure r%d, p%d", a, bx);
		comment = rz_str_newf("instantiate proto%d at 0x%" PFMT64x, bx + 1, child_vaddr);
		// rz_analysis_xrefs_set(analysis, op->addr, op->ptr, RZ_ANALYSIS_XREF_TYPE_CALL);
		break;
	}
	case OP_TFORPREP: /*	A Bx	create upvalue for R[A + 3]; pc+=Bx		*/
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		st32 offset = bx;
		op->jump = addr + 4 + (offset * 4);
		op->val = (ut64)a;
		op->fail = -1;
		break;
	case OP_TFORCALL: /*	A C	R[A+4], ... ,R[A+3+C] := R[A](R[A+1], R[A+2]);	*/
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->val = (ut64)c;
		op->fail = addr + 4;

		op->dst = rz_analysis_value_new();
		op->dst->reg = new_reg_item(analysis, "r%d", a);
		break;
	case OP_TFORLOOP: /*	A Bx	if R[A+2] ~= nil then { R[A]=R[A+2]; pc -= Bx }	*/
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		offset = sbx;

		op->jump = op->addr + 4 + (offset * 4);
		op->fail = op->addr + 4;

		op->src[0] = rz_analysis_value_new();
		op->src[0]->reg = new_reg_item(analysis, "r%d", a);
		break;
	case OP_SETLIST: /*	A B C k	R[A][C+i] := R[A+i], 1 <= i <= B		*/
		break;
	case OP_VARARG: /*	A C	R[A], R[A+1], ..., R[A+C-2] = vararg		*/
	{
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;

		op->dst = rz_analysis_value_new();
		op->dst->reg = new_reg_item(analysis, "r%d", a);

		mnemonic = rz_str_newf("vararg r%d, %d", a, c);
		if (c == 0) {
			comment = rz_str_newf("r%d... = varargs (all)", a);
		} else {
			comment = rz_str_newf("r%d...r%d = varargs", a, a + c - 2);
		}
	} break;
	case OP_VARARGPREP: /*A	(adjust vararg parameters)			*/
	{
		// op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		mnemonic = rz_str_newf("varargprep %d", a);
		comment = rz_str_newf("prepare varargs, %d fixed args", a);
	} break;
	case OP_EXTRAARG: /*	Ax	extra (larger) argument for previous opcode	*/
	{
		// op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		op->val = ax;
		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = rz_str_newf("extraarg %d", ax);
		}

		comment = rz_str_dup("extension for previous opcode");
	} break;
	}
	if (mnemonic) {
		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = mnemonic;
		}
		RZ_FREE(mnemonic);
	}
	if (comment) {
		rz_meta_set(analysis, RZ_META_TYPE_COMMENT, addr, 4, comment);
		RZ_FREE(comment);
	}
	return op->size;
}
