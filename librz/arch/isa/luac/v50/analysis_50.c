// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2017 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#include "arch_50.h"

int lua50_anal_op(RzAnalysis *anal, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len) {
	if (!op) {
		return 0;
	}

	memset(op, 0, sizeof(RzAnalysisOp));
	const ut32 instruction = lua_build_instruction(data);

	op->addr = addr;
	op->size = 4;
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
	op->eob = false;

	if (GET_OPCODE50(instruction) > OP_CLOSURE) {
		return op->size;
	}

	switch (GET_OPCODE50(instruction)) {
	case OP_MOVE: /*      A B     R(A) := R(B)                                    */
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case OP_LOADK: /*     A Bx    R(A) := Kst(Bx)                                 */
	case OP_GETGLOBAL: /*   A Bx    R(A) := Gbl[Kst(Bx)]                                 */
	case OP_GETTABLE: /*	A B C   R(A) := R(B)[RK(C)]				*/
	case OP_SETTABLE: /*  A B C   R(A)[RK(B)] := RK(C)                            */
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case OP_LOADBOOL: /*  A B C   R(A) := (Bool)B; if (C) pc++                    */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->val = !!GETARG_B0(instruction);
		op->jump = op->addr + 8;
		op->fail = op->addr + 4;
		break;
	case OP_SETGLOBAL: /* A Bx    Gbl[Kst(Bx)] := R(A)                           */
	case OP_CLOSE: /*     A	close all variables in the stack up to (>=) R(A)     */
	case OP_LOADNIL: /*   A B     R(A), R(A+1), ..., R(A+B) := nil               */
		break;
	case OP_GETUPVAL: /*  A B     R(A) := UpValue[B]                              */
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case OP_SETUPVAL: /*  A B     UpValue[B] := R(A)                              */
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case OP_NEWTABLE: /*  A B C   R(A) := {} (size = B,C)                         */
		op->type = RZ_ANALYSIS_OP_TYPE_NEW;
		break;
	case OP_SELF: /*      A B C   R(A+1) := R(B); R(A) := R(B)[RK(C)]             */
		break;
	case OP_ADD: /*       A B C   R(A) := RK(B) + RK(C)                           */
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case OP_SUB: /*       A B C   R(A) := RK(B) - RK(C)                           */
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case OP_MUL: /*       A B C   R(A) := RK(B) * RK(C)                           */
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case OP_POW: /*       A B C   R(A) := RK(B) ^ RK(C)                           */
		break;
	case OP_DIV: /*       A B C   R(A) := RK(B) / RK(C)                           */
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case OP_UNM: /*       A B     R(A) := -R(B)                                   */
		break;
	case OP_NOT: /*       A B     R(A) := not R(B)                                */
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		break;
	case OP_CONCAT: /*    A B C   R(A) := R(B).. ... ..R(C)                       */
		break;
	case OP_JMP: /*       A sBx   pc+=sBx; if (A) close all upvalues >= R(A - 1)  */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)(4 * GETARG_sBx0(instruction));
		op->fail = op->addr + 4;
		break;
	case OP_EQ: /*        A B C   if ((RK(B) == RK(C)) ~= A) then pc++            */
	case OP_LT: /*        A B C   if ((RK(B) <  RK(C)) ~= A) then pc++            */
	case OP_LE: /*        A B C   if ((RK(B) <= RK(C)) ~= A) then pc++            */
	case OP_TEST: /*      A C     if not (R(A) <=> C) then pc++                   */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + 8;
		op->fail = op->addr + 4;
		break;
	case OP_CALL: /*      A B C   R(A), ... ,R(A+C-2) := R(A)(R(A+1), ... ,R(A+B-1)) */
		op->type = RZ_ANALYSIS_OP_TYPE_RCALL;
		break;
	case OP_TAILCALL: /*  A B C   return R(A)(R(A+1), ... ,R(A+B-1))              */
		op->type = RZ_ANALYSIS_OP_TYPE_RCALL;
		op->type2 = RZ_ANALYSIS_OP_TYPE_RET;
		op->eob = true;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -4;
		break;
	case OP_RETURN: /*    A B     return R(A), ... ,R(A+B-2)      (see note)      */
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->eob = true;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -4;
		break;
	case OP_FORLOOP: /*   A sBx   R(A)+=R(A+2); if R(A) <?= R(A+1) then { pc+=sBx; R(A+3)=R(A) }*/
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + 4 + 4 * (GETARG_sBx0(instruction));
		op->fail = op->addr + 4;
		break;
	case OP_TFORPREP: /*  A sBx   if type(R(A)) == table then R(A+1):=R(A), R(A):=next; PC += sBx */
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = op->addr + 4 + 4 * (GETARG_sBx0(instruction));
		op->fail = op->addr + 4;
		break;
	case OP_TFORLOOP: /*  A sBx   if R(A+1) ~= nil then { R(A)=R(A+1); pc += sBx }*/
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + 4 + 4 * (GETARG_sBx0(instruction));
		op->fail = op->addr + 4;
		break;
	case OP_SETLIST: /*   A B C   R(A)[(C-1)*FPF+i] := R(A+i), 1 <= i <= B        */
	case OP_SETLISTO: /*  A Bx                                                    */
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case OP_CLOSURE: /*   A Bx    R(A) := closure(KPROTO[Bx])                     */
		break;
	}
	return op->size;
}
