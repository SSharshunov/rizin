// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#include "arch_54.h"
bool parse_args2(const char *s, int *args, int max_size) {
	int count = 0;
	bool k_flag = false;
	int i = 0;

	while (s[i] != '\0') {
		// 1. Если нашли цифру — собираем число целиком (хоть 2, хоть 255)
		if (s[i] >= '0' && s[i] <= '9') {
			int val = 0;
			while (s[i] >= '0' && s[i] <= '9') {
				val = val * 10 + (s[i] - '0');
				i++;
			}
			if (count < max_size) {
				args[count++] = val;
			}
			continue;
		}

		// 2. Если встретили 'k', проверяем не флаг ли это в конце строки
		if (s[i] == 'k') {
			int next = i + 1;
			while (s[next] == ' ' || s[next] == '\t' || s[next] == '\r' || s[next] == '\n') next++;

			if (s[next] == '\0') {
				k_flag = true;
			}
		}
		i++;
	}
	return k_flag;
}

static LuaInstruction encode_instruction(const ut8 opcode, const char *arg_start, ut16 flag, ut8 arg_num) {
	rz_return_val_if_fail((arg_num > 0) && (arg_num <= LUA_MAX_ARGS4), LUA_INVALID_INSNTRUCTION);
	LuaInstruction instruction = 0;
	int args[LUA_MAX_ARGS4];
	int cur_cnt = 0;

	const bool isK = parse_args2(arg_start, args, LUA_MAX_ARGS4);

	if (isK) {
		SETARG_k(instruction, 1);
	}

	SET_OPCODE54(instruction, opcode);
	if (has_param_flag(flag, PARAM_A)) {
		SETARG_A4(instruction, args[cur_cnt++]);
		if (cur_cnt >= arg_num) {
			return instruction;
		}
	}
	if (has_param_flag(flag, PARAM_B)) {
		SETARG_B4(instruction, args[cur_cnt++]);
		if (cur_cnt >= arg_num) {
			return instruction;
		}
	}
	if (has_param_flag(flag, PARAM_sB)) {
		SETARG_sB(instruction, args[cur_cnt++]);
		if (cur_cnt >= arg_num) {
			return instruction;
		}
	}
	if (has_param_flag(flag, PARAM_C)) {
		SETARG_C4(instruction, args[cur_cnt++]);
		if (cur_cnt >= arg_num) {
			return instruction;
		}
	}
	if (has_param_flag(flag, PARAM_sC)) {
		SETARG_sC(instruction, args[cur_cnt++]);
		if (cur_cnt >= arg_num) {
			return instruction;
		}
	}
	if (has_param_flag(flag, PARAM_Ax)) {
		SETARG_Ax4(instruction, args[cur_cnt++]);
		if (cur_cnt >= arg_num) {
			return instruction;
		}
	}
	if (has_param_flag(flag, PARAM_sBx)) {
		SETARG_sBx4(instruction, args[cur_cnt++]);
		if (cur_cnt >= arg_num) {
			return instruction;
		}
	}
	if (has_param_flag(flag, PARAM_Bx)) {
		SETARG_Bx4(instruction, args[cur_cnt++]);
		if (cur_cnt >= arg_num) {
			return instruction;
		}
	}
	if (has_param_flag(flag, PARAM_sJ)) {
		SETARG_sJ(instruction, args[cur_cnt++]);
		if (cur_cnt >= arg_num) {
			return instruction;
		}
	}
	rz_return_val_if_fail(cur_cnt == arg_num, LUA_INVALID_INSNTRUCTION);
	return instruction;
}

bool lua54_assembly(const char *input, st32 input_size, LuaInstruction *instruction_p) {
	rz_return_val_if_fail(input && input_size > 0, false);

	/* Find the opcode */
	const char *opcode_start = input; ///< point to the header
	const char *opcode_end = strchr(input, ' '); ///< point to the first white space
	if (opcode_end == NULL) {
		opcode_end = input + input_size;
	}

	const int opcode_len = opcode_end - opcode_start;
	const ut8 opcode = get_lua54_opcode_by_name(opcode_start, opcode_len);

	/* Find the arguments */
	const char *arg_start = rz_str_trim_head_ro(opcode_end);

	LuaInstruction instruction = 0x00;

	/* Encode opcode and args */
	switch (opcode) {
	case OP_GETI:
	case OP_MMBIN:
	case OP_GETTABUP:
	case OP_CALL:
	case OP_GETTABLE:
	case OP_ADD:
	case OP_SUB:
	case OP_MUL:
	case OP_POW:
	case OP_DIV:
	case OP_IDIV:
	case OP_BAND:
	case OP_BOR:
	case OP_SHL:
	case OP_SHR:
	case OP_ADDK:
	case OP_SUBK:
	case OP_MULK:
	case OP_MODK:
	case OP_POWK:
	case OP_DIVK:
	case OP_IDIVK:
	case OP_BANDK:
	case OP_BORK:
	case OP_BXORK:
	case OP_GETFIELD:
	// iABC k instruction
	case OP_TAILCALL:
	case OP_RETURN:
	case OP_SETTABUP:
	case OP_SETTABLE:
	case OP_SETI:
	case OP_SETFIELD:
	case OP_SELF:
	case OP_NEWTABLE:
	case OP_SETLIST:
	case OP_MMBINK:
		instruction = encode_instruction(opcode, arg_start, PARAM_A | PARAM_B | PARAM_C, 3);
		break;
	// AsBC k instruction
	case OP_MMBINI:
		instruction = encode_instruction(opcode, arg_start, PARAM_A | PARAM_sB | PARAM_C, 3);
		break;
	// ABsC
	case OP_ADDI:
	case OP_SHRI:
	case OP_SHLI:
		instruction = encode_instruction(opcode, arg_start, PARAM_A | PARAM_B | PARAM_sC, 3);
		break;
	// AB
	case OP_MOVE:
	case OP_UNM:
	case OP_BNOT:
	case OP_NOT:
	case OP_LEN:
	case OP_CONCAT:
	case OP_LOADNIL:
	case OP_GETUPVAL:
	case OP_SETUPVAL:
	// AB with k
	case OP_EQ:
	case OP_LT:
	case OP_LE:
	case OP_TESTSET:
	case OP_EQK:
		instruction = encode_instruction(opcode, arg_start, PARAM_A | PARAM_B, 2);
		break;
	// AsB with k
	case OP_EQI:
	case OP_LTI:
	case OP_LEI:
	case OP_GTI:
	case OP_GEI:
		instruction = encode_instruction(opcode, arg_start, PARAM_A | PARAM_sB, 2);
		break;
	// AC
	case OP_TFORCALL:
	case OP_VARARG:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_A | PARAM_C, 2);
		break;
	// A
	case OP_LOADKX:
	case OP_LOADFALSE:
	case OP_LFALSESKIP:
	case OP_LOADTRUE:
	case OP_CLOSE:
	case OP_TBC:
	case OP_RETURN1:
	case OP_VARARGPREP:
	// A with k
	case OP_TEST:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_A, 1);
		break;
	// no arg
	case OP_RETURN0:
		SET_OPCODE54(instruction, OP_RETURN0);
		break;
	// A Bx
	case OP_LOADK:
	case OP_FORLOOP:
	case OP_FORPREP:
	case OP_TFORLOOP:
	case OP_TFORPREP:
	case OP_CLOSURE:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_A | PARAM_Bx, 2);
		break;
	// A sBx
	case OP_LOADI:
	case OP_LOADF:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_A | PARAM_sBx, 2);
		break;
	// Ax
	case OP_EXTRAARG:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_Ax, 1);
		break;
	// isJ
	case OP_JMP:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_sJ, 1);
		break;
	default:
		return false;
	}

	if (instruction == -1) {
		return false;
	}

	*instruction_p = instruction;
	return true;
}
