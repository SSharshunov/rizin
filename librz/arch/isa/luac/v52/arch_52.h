// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2017 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#ifndef BUILD_ARCH_52_H
#define BUILD_ARCH_52_H

#include <rz_types.h>
#include <rz_asm.h>
#include <stddef.h>
#include "../lua_arch.h"

/*===========================================================================
  We assume that instructions are unsigned numbers.
  All instructions have an opcode in the first 6 bits.
  Instructions can have the following fields:
	'A' : 8 bits
	'B' : 9 bits
	'C' : 9 bits
	'Ax' : 26 bits ('A', 'B', and 'C' together)
	'Bx' : 18 bits ('B' and 'C' together)
	'sBx' : signed Bx
  A signed argument is represented in excess K; that is, the number
  value is the unsigned value minus K. K is exactly the maximum value
  for that argument (so that -max is represented by 0, and +max is
  represented by 2*max), which is half the maximum for the corresponding
  unsigned argument.
===========================================================================*/

typedef enum {
	iABC,
	iABx,
	iAsBx,
	iAx
} LuaOpMode;

/* Offset of arguments in opcode */
#define SIZE_C  9
#define SIZE_B  9
#define SIZE_Bx (SIZE_C + SIZE_B)
#define SIZE_A  8
#define SIZE_Ax (SIZE_C + SIZE_B + SIZE_A)
#define SIZE_OP 6

#define POS_OP 0
#define POS_A  (POS_OP + SIZE_OP)
#define POS_C  (POS_A + SIZE_A)
#define POS_B  (POS_C + SIZE_C)
#define POS_Bx POS_C
#define POS_Ax POS_A
/*
** Macros to operate RK indices
*/

/* this bit 1 means constant (0 means register) */
#define BITRK (1 << (SIZE_B - 1))

/* test whether value is a constant */
#define ISK(x) ((x) & BITRK)

/* gets the index of the constant */
#define INDEXK(r) ((int)(r) & ~BITRK)

#define MAXINDEXRK (BITRK - 1)

/* code a constant index as a RK value */
#define RKASK(x) ((x) | BITRK)

/**
 * invalid register that fits in 8 bits
 **/
#define NO_REG MAXARG_A

/**
 * R(x) - register
 * Kst(x) - constant (in constant table)
 * RK(x) == if ISK(x) then Kst(INDEXK(x)) else R(x)
 */

/**
 * grep "ORDER OP" if you change these enums
 **/

typedef enum {
	/*----------------------------------------------------------------------
	name            args    description
	------------------------------------------------------------------------*/
	OP_MOVE, /*      A B     R(A) := R(B)                                    */
	OP_LOADK, /*     A Bx    R(A) := Kst(Bx)                                 */
	OP_LOADKX, /*    A       R(A) := Kst(extra arg)                          */
	OP_LOADBOOL, /*  A B C   R(A) := (Bool)B; if (C) pc++                    */
	OP_LOADNIL, /*   A B     R(A), R(A+1), ..., R(A+B) := nil                */
	OP_GETUPVAL, /*  A B     R(A) := UpValue[B]                              */

	OP_GETTABUP, /*  A B C   R(A) := UpValue[B][RK(C)]                       */
	OP_GETTABLE, /*  A B C   R(A) := R(B)[RK(C)]                             */

	OP_SETTABUP, /*  A B C   UpValue[A][RK(B)] := RK(C)                      */
	OP_SETUPVAL, /*  A B     UpValue[B] := R(A)                              */
	OP_SETTABLE, /*  A B C   R(A)[RK(B)] := RK(C)                            */

	OP_NEWTABLE, /*  A B C   R(A) := {} (size = B,C)                         */

	OP_SELF, /*      A B C   R(A+1) := R(B); R(A) := R(B)[RK(C)]             */

	OP_ADD, /*       A B C   R(A) := RK(B) + RK(C)                           */
	OP_SUB, /*       A B C   R(A) := RK(B) - RK(C)                           */
	OP_MUL, /*       A B C   R(A) := RK(B) * RK(C)                           */
	OP_DIV, /*       A B C   R(A) := RK(B) / RK(C)                           */
	OP_MOD, /*       A B C   R(A) := RK(B) % RK(C)                           */
	OP_POW, /*       A B C   R(A) := RK(B) ^ RK(C)                           */
	OP_UNM, /*       A B     R(A) := -R(B)                                   */
	OP_NOT, /*       A B     R(A) := not R(B)                                */
	OP_LEN, /*       A B     R(A) := length of R(B)                          */

	OP_CONCAT, /*    A B C   R(A) := R(B).. ... ..R(C)                       */

	OP_JMP, /*       A sBx   pc+=sBx; if (A) close all upvalues >= R(A - 1)  */
	OP_EQ, /*        A B C   if ((RK(B) == RK(C)) ~= A) then pc++            */
	OP_LT, /*        A B C   if ((RK(B) <  RK(C)) ~= A) then pc++            */
	OP_LE, /*        A B C   if ((RK(B) <= RK(C)) ~= A) then pc++            */

	OP_TEST, /*      A C     if not (R(A) <=> C) then pc++                   */
	OP_TESTSET, /*   A B C   if (R(B) <=> C) then R(A) := R(B) else pc++     */

	OP_CALL, /*      A B C   R(A), ... ,R(A+C-2) := R(A)(R(A+1), ... ,R(A+B-1)) */
	OP_TAILCALL, /*  A B C   return R(A)(R(A+1), ... ,R(A+B-1))              */
	OP_RETURN, /*    A B     return R(A), ... ,R(A+B-2)      (see note)      */

	OP_FORLOOP, /*   A sBx   R(A)+=R(A+2);
			if R(A) <?= R(A+1) then { pc+=sBx; R(A+3)=R(A) }*/
	OP_FORPREP, /*   A sBx   R(A)-=R(A+2); pc+=sBx                           */

	OP_TFORCALL, /*  A C     R(A+3), ... ,R(A+2+C) := R(A)(R(A+1), R(A+2));  */
	OP_TFORLOOP, /*  A sBx   if R(A+1) ~= nil then { R(A)=R(A+1); pc += sBx }*/

	OP_SETLIST, /*   A B C   R(A)[(C-1)*FPF+i] := R(A+i), 1 <= i <= B        */

	OP_CLOSURE, /*   A Bx    R(A) := closure(KPROTO[Bx])                     */

	OP_VARARG, /*    A B     R(A), R(A+1), ..., R(A+B-2) = vararg            */

	OP_EXTRAARG /*   Ax      extra (larger) argument for previous opcode     */
} LuaOpCode;

#define LUA_NUM_OPCODES ((int)(OP_EXTRAARG) + 1)

/*===========================================================================
  Notes:
  (*) In OP_CALL, if (B == 0) then B = top. If (C == 0), then `top' is
  set to last_result+1, so next open instruction (OP_CALL, OP_RETURN,
  OP_SETLIST) may use `top'.

  (*) In OP_VARARG, if (B == 0) then use actual number of varargs and
  set top (like in OP_CALL with C == 0).

  (*) In OP_RETURN, if (B == 0) then return up to `top'.

  (*) In OP_SETLIST, if (B == 0) then B = `top'; if (C == 0) then next
  'instruction' is EXTRAARG(real C).

  (*) In OP_LOADKX, the next 'instruction' is always EXTRAARG.

  (*) For comparisons, A specifies what condition the test should accept
  (true or false).

  (*) All `skips' (pc++) assume that next instruction is a jump.

===========================================================================*/

/*
** masks for instruction properties. The format is:
** bits 0-1: op mode
** bits 2-3: C arg mode
** bits 4-5: B arg mode
** bit 6: instruction set register A
** bit 7: operator is a test (next instruction must be a jump)
*/

enum OpArgMask {
	OpArgN, /* argument is not used */
	OpArgU, /* argument is used */
	OpArgR, /* argument is a register or a jump offset */
	OpArgK /* argument is a constant or register/constant */
};

extern const ut8 luaP_opmodes52[LUA_NUM_OPCODES];

#define opmode(t, a, b, c, m) (((t) << 7) | ((a) << 6) | ((b) << 4) | ((c) << 2) | (m))

#define getOpMode(m) (cast(LuaOpMode, luaP_opmodes52[m] & 3))
#define getBMode(m)  (cast(enum OpArgMask, (luaP_opmodes52[m] >> 4) & 3))
#define getCMode(m)  (cast(enum OpArgMask, (luaP_opmodes52[m] >> 2) & 3))
#define testAMode(m) (luaP_opmodes52[m] & (1 << 6))
#define testTMode(m) (luaP_opmodes52[m] & (1 << 7))

#define MYK(x) (-1 - (x))

#define MAX_INT INT_MAX /* maximum value of an int */

#define LUAI_BITSINT 32

/*
** limits for opcode arguments.
** we use (signed) int to manipulate most arguments,
** so they must fit in LUAI_BITSINT-1 bits (-1 for sign)
*/
#if SIZE_Bx < LUAI_BITSINT - 1
#define MAXARG_Bx  ((1 << SIZE_Bx) - 1)
#define MAXARG_sBx (MAXARG_Bx >> 1) /* 'sBx' is signed */
#else
#define MAXARG_Bx  MAX_INT
#define MAXARG_sBx MAX_INT
#endif

#if SIZE_Ax < LUAI_BITSINT - 1
#define MAXARG_Ax ((1 << SIZE_Ax) - 1)
#else
#define MAXARG_Ax MAX_INT
#endif

#define MAXARG_A ((1 << SIZE_A) - 1)
#define MAXARG_B ((1 << SIZE_B) - 1)
#define MAXARG_C ((1 << SIZE_C) - 1)

/* creates a mask with 'n' 1 bits at position 'p' */
#define MASK1(n, p) ((~((~0u) << (n))) << (p))

/* creates a mask with 'n' 0 bits at position 'p' */
#define MASK0(n, p) (~MASK1(n, p))

#define cast(x, y) ((x)(y))

#define GET_OPCODE(i)    (cast(LuaOpCode, ((i) >> POS_OP) & MASK1(SIZE_OP, 0)))
#define SET_OPCODE(i, o) ((i) = (((i) & MASK0(SIZE_OP, POS_OP)) | \
				  ((cast(ut32, o) << POS_OP) & MASK1(SIZE_OP, POS_OP))))

#define getarg(i, pos, size)    (cast(int, ((i) >> (pos)) & MASK1(size, 0)))
#define setarg(i, v, pos, size) ((i) = (((i) & MASK0(size, pos)) | \
					 ((cast(ut32, v) << (pos)) & MASK1(size, pos))))

#define GETARG_A(i)    getarg(i, POS_A, SIZE_A)
#define SETARG_A(i, v) setarg(i, v, POS_A, SIZE_A)

#define GETARG_B(i)    getarg(i, POS_B, SIZE_B)
#define SETARG_B(i, v) setarg(i, v, POS_B, SIZE_B)

#define GETARG_C(i)    getarg(i, POS_C, SIZE_C)
#define SETARG_C(i, v) setarg(i, v, POS_C, SIZE_C)

#define GETARG_Bx(i)    getarg(i, POS_Bx, SIZE_Bx)
#define SETARG_Bx(i, v) setarg(i, v, POS_Bx, SIZE_Bx)

#define GETARG_Ax(i)    getarg(i, POS_Ax, SIZE_Ax)
#define SETARG_Ax(i, v) setarg(i, v, POS_Ax, SIZE_Ax)

#define GETARG_sBx(i)    (GETARG_Bx(i) - MAXARG_sBx)
#define SETARG_sBx(i, b) SETARG_Bx((i), cast(unsigned int, (b) + MAXARG_sBx))

#define CREATE_ABC(o, a, b, c) ((cast(ut32, o) << POS_OP) | (cast(ut32, a) << POS_A) | (cast(ut32, b) << POS_B) | (cast(ut32, c) << POS_C))

#define CREATE_ABx(o, a, bc) ((cast(ut32, o) << POS_OP) | (cast(ut32, a) << POS_A) | (cast(ut32, bc) << POS_Bx))

#define CREATE_Ax(o, a) ((cast(ut32) << POS_OP) | (cast(ut32, a) << POS_Ax))

#endif // BUILD_ARCH_52_H
