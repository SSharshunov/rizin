// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2017 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#include "arch_51.h"

static LuaInstruction encode_instruction(ut8 opcode, const char *arg_start, ut16 flag, ut8 arg_num) {
	LuaInstruction instruction = 0;
	int args[3];
	char buffer[64]; // buffer for digits
	int cur_cnt = 0;
	int temp = 0;

	for (int i = 0; i < arg_num; ++i) {
		const int delta_offset = lua_load_next_arg_start(arg_start, buffer);
		if (delta_offset == 0) {
			return -1;
		}
		if (lua_is_valid_num_value_string(buffer)) {
			args[i] = lua_convert_str_to_num(buffer);
			arg_start += delta_offset;
		} else {
			return -1;
		}
	}

	if (opcode == OP_LOADK || opcode == OP_GETGLOBAL || opcode == OP_SETGLOBAL) {
		args[1] = MYK(args[1]);
	}

	if (!(opcode == OP_TFORLOOP || opcode == OP_CLOSE)) {
		args[1] = ISK(args[1]) ? (MYK(INDEXK(args[1]))) : args[1];
	}
	if (opcode == OP_GETTABLE ||
		opcode == OP_SETTABLE ||
		opcode == OP_NEWTABLE ||
		opcode == OP_SELF ||
		opcode == OP_ADD ||
		opcode == OP_SUB ||
		opcode == OP_MUL ||
		opcode == OP_DIV ||
		opcode == OP_MOD ||
		opcode == OP_POW ||
		opcode == OP_CONCAT ||
		opcode == OP_TFORLOOP ||
		opcode == OP_SETLIST ||
		opcode == OP_LT ||
		opcode == OP_LE ||
		opcode == OP_TEST ||
		opcode == OP_TESTSET ||
		opcode == OP_EQ ||
		opcode == OP_CALL ||
		opcode == OP_TAILCALL) {
		args[2] = ISK(args[2]) ? (MYK(INDEXK(args[2]))) : args[2];
	}

	SET_OPCODE51(instruction, opcode);
	if (has_param_flag(flag, PARAM_A)) {
		SETARG_A1(instruction, args[cur_cnt++]);
	}
	if (has_param_flag(flag, PARAM_B)) {
		temp = args[cur_cnt++];
		temp = temp < 0 ? 0xFF - temp : temp;
		SETARG_B1(instruction, temp);
	}
	if (has_param_flag(flag, PARAM_C)) {
		temp = args[cur_cnt++];
		temp = temp < 0 ? 0xFF - temp : temp;
		SETARG_C1(instruction, temp);
	}
	if (has_param_flag(flag, PARAM_sBx)) {
		SETARG_sBx1(instruction, args[cur_cnt++]);
	}
	if (has_param_flag(flag, PARAM_Bx)) {
		SETARG_Bx1(instruction, args[cur_cnt++]);
	}
	rz_return_val_if_fail(cur_cnt == arg_num, -1);

	return instruction;
}

bool lua51_assembly(const char *input, st32 input_size, LuaInstruction *instruction_p) {
	LuaInstruction instruction = 0x00;

	/* Find the opcode */
	const char *opcode_start = input; ///< point to the header
	const char *opcode_end = strchr(input, ' '); ///< point to the first white space
	if (opcode_end == NULL) {
		opcode_end = input + input_size;
	}

	const int opcode_len = opcode_end - opcode_start;
	const ut8 opcode = get_lua51_opcode_by_name(opcode_start, opcode_len);

	/* Find the arguments */
	const char *arg_start = rz_str_trim_head_ro(opcode_end);

	/* Encode opcode and args */
	switch (opcode) {
	case OP_MOVE:
	case OP_SETUPVAL:
	case OP_UNM:
	case OP_NOT:
	case OP_LEN:
	case OP_LOADNIL:
	case OP_RETURN:
	case OP_VARARG:
	case OP_GETUPVAL:
		instruction = encode_instruction(opcode, arg_start, PARAM_A | PARAM_B, 2);
		break;
	case OP_TEST:
		instruction = encode_instruction(opcode, arg_start, PARAM_A | PARAM_C, 2);
		break;
	case OP_LOADK:
	case OP_GETGLOBAL:
	case OP_SETGLOBAL:
	case OP_CLOSURE:
		instruction = encode_instruction(opcode, arg_start, PARAM_A | PARAM_Bx, 2);
		break;
	case OP_CONCAT:
	case OP_TESTSET:
	case OP_CALL:
	case OP_NEWTABLE:
	case OP_SETLIST:
	case OP_LOADBOOL:
	case OP_SELF:
	case OP_SETTABLE:
	case OP_ADD:
	case OP_SUB:
	case OP_MUL:
	case OP_MOD:
	case OP_POW:
	case OP_DIV:
	case OP_EQ:
	case OP_LT:
	case OP_LE:
		instruction = encode_instruction(opcode, arg_start,
			PARAM_A | PARAM_B | PARAM_C,
			3);
		break;
	case OP_JMP:
	case OP_FORLOOP:
	case OP_FORPREP:
	case OP_TFORLOOP:
		instruction = encode_instruction(opcode, arg_start, PARAM_A | PARAM_sBx, 2);
		break;
	default:
		rz_warn_if_reached();
		return false;
	}

	if (instruction == -1) {
		return false;
	}

	*instruction_p = instruction;
	return true;
}
