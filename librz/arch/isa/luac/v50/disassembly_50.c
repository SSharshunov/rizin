// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2017 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#include "arch_50.h"

int lua50_disasm(RzAsmOp *op, const ut8 *buf, int len, LuaOpNameList opnames) {
	if (len < 4) {
		RZ_LOG_DEBUG("Cannot disassemble lua52 opcode (truncated).\n");
		return 0;
	}
	ut32 instruction = rz_read_at_le32(buf, 0);
	LuaOpCode opcode = GET_OPCODE(instruction);

	/* Pre fetch some args */
	int a = GETARG_A(instruction);
	int b = GETARG_B(instruction);
	int c = GETARG_C(instruction);
	int bx = GETARG_Bx(instruction);
	int sbx = GETARG_sBx(instruction);

	// simplify test flag
	int is_special_B = b & 0x100;
	int is_special_C = c & 0x100;

	int special_c = 0xFF - c;
	int special_b = 0xFF - b;

	char *asm_string;

	switch (opcode) {
	case OP_CLOSE: /*     A       close all variables in the stack up to (>=) R(A)*/
		asm_string = luaop_new_str_1arg(opnames[opcode], a);
		break;
	case OP_JMP: /*       sBx     PC += sBx                                       */
		asm_string = luaop_new_str_1arg(opnames[opcode], sbx);
		break;
	case OP_SETUPVAL: /*  A B     UpValue[B] := R(A)                              */
	case OP_UNM: /*       A B     R(A) := -R(B)                                   */
	case OP_NOT: /*       A B     R(A) := not R(B)                                */
	case OP_LOADNIL: /*   A B     R(A) := ... := R(B) := nil                      */
	case OP_GETUPVAL: /*  A B     R(A) := UpValue[B]                              */
		asm_string = luaop_new_str_2arg(opnames[opcode], a, b);
		break;
	case OP_TFORLOOP: /*  A C     R(A+2), ... ,R(A+2+C) := R(A)(R(A+1), R(A+2));
			if R(A+2) ~= nil then pc++                      */
		asm_string = luaop_new_str_2arg(opnames[opcode], a, c);
		break;
	case OP_SETGLOBAL: /* A Bx    Gbl[Kst(Bx)] := R(A)                            */
	case OP_GETGLOBAL: /* A Bx    R(A) := Gbl[Kst(Bx)]                            */
	case OP_LOADK: /*     A Bx    R(A) := Kst(Bx)                                 */
		bx = ISK(b) ? (MYK(INDEXK(bx))) : bx;
		asm_string = luaop_new_str_2arg(opnames[opcode], a, bx);
		break;
	case OP_SETLIST: /*   A Bx    R(A)[Bx-Bx%FPF+i] := R(A+i), 1 <= i <= Bx%FPF+1 */
	case OP_SETLISTO: /*  A Bx                                                    */
	case OP_CLOSURE: /*   A Bx    R(A) := closure(KPROTO[Bx], R(A), ... ,R(A+n))  */
		asm_string = luaop_new_str_2arg(opnames[opcode], a, bx);
		break;
	case OP_RETURN: /*    A B     return R(A), ... ,R(A+B-2)      (see note)      */
	case OP_MOVE: /*      A B     R(A) := R(B)                                    */
	case OP_TEST: /*      A B C   if (R(B) <=> C) then R(A) := R(B) else pc++     */
	case OP_CONCAT: /*    A B C   R(A) := R(B).. ... ..R(C)                       */
	case OP_CALL: /*      A B C   R(A), ... ,R(A+C-2) := R(A)(R(A+1), ... ,R(A+B-1)) */
	case OP_NEWTABLE: /*  A B C   R(A) := {} (size = B,C)                         */
	case OP_LOADBOOL: /*  A B C   R(A) := (Bool)B; if (C) pc++                    */
	case OP_SELF: /*      A B C   R(A+1) := R(B); R(A) := R(B)[RK(C)]             */
	case OP_GETTABLE: /*  A B C   R(A) := R(B)[RK(C)]                             */
	case OP_TAILCALL: /*  A B C   return R(A)(R(A+1), ... ,R(A+B-1))              */
		asm_string = luaop_new_str_3arg(opnames[opcode], a, b, c);
		break;
	case OP_SETTABLE: /*  A B C   R(A)[RK(B)] := RK(C)                            */
	case OP_ADD: /*       A B C   R(A) := RK(B) + RK(C)                           */
	case OP_SUB: /*       A B C   R(A) := RK(B) - RK(C)                           */
	case OP_MUL: /*       A B C   R(A) := RK(B) * RK(C)                           */
	case OP_POW: /*       A B C   R(A) := RK(B) ^ RK(C)                           */
	case OP_DIV: /*       A B C   R(A) := RK(B) / RK(C)                           */
	case OP_EQ: /*        A B C   if ((RK(B) == RK(C)) ~= A) then pc++            */
	case OP_LT: /*        A B C   if ((RK(B) <  RK(C)) ~= A) then pc++            */
	case OP_LE: /*        A B C   if ((RK(B) <= RK(C)) ~= A) then pc++            */
		if (is_special_B) {
			if (is_special_C) {
				asm_string = luaop_new_str_3arg(
					opnames[opcode],
					a, special_b, special_c);
			} else {
				asm_string = luaop_new_str_3arg(
					opnames[opcode],
					a, special_b, c);
			}
		} else {
			if (is_special_C) {
				asm_string = luaop_new_str_3arg(
					opnames[opcode],
					a, b, special_c);
			} else {
				asm_string = luaop_new_str_3arg(
					opnames[opcode],
					a, b, c);
			}
		}
		break;
	case OP_FORLOOP: /*   A sBx   R(A)+=R(A+2); if R(A) <?= R(A+1) then PC+= sBx  */
	case OP_TFORPREP: /*  A sBx   if type(R(A)) == table then R(A+1):=R(A), R(A):=next;
			PC += sBx                                       */
		asm_string = luaop_new_str_2arg(opnames[opcode], a, sbx);
		break;
	default:
		asm_string = rz_str_dup("invalid");
		break;
	}

	rz_strbuf_append(&op->buf_asm, asm_string);
	op->size = 4;

	RZ_FREE(asm_string);
	return 4;
}
