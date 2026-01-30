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

/*
** type for virtual-machine instructions
** must be an unsigned with (at least) 4 bytes (see details in lopcodes.h)
*/
typedef unsigned long Instruction;

/*===========================================================================
  We assume that instructions are unsigned numbers.
  All instructions have an opcode in the first 6 bits.
  Instructions can have the following fields:
	'A' : 8 bits
	'B' : 9 bits
	'C' : 9 bits
	'Bx' : 18 bits ('B' and 'C' together)
	'sBx' : signed Bx
  A signed argument is represented in excess K; that is, the number
  value is the unsigned value minus K. K is exactly the maximum value
  for that argument (so that -max is represented by 0, and +max is
  represented by 2*max), which is half the maximum for the corresponding
  unsigned argument.
===========================================================================*/

/* basic instruction format */
typedef enum {
	iABC,
	iABx,
	iAsBx
} LuaOpMode;

/* parameter flags */
#define PARAM_A     1
#define PARAM_B     2
#define PARAM_C     4
#define PARAM_iAsBx 8

#define has_param_flag(flag, bit) ((flag) & (bit)) ? true : false

/* Offset of arguments in opcode */
#define SIZE_C  9
#define SIZE_B  9
#define SIZE_Bx (SIZE_C + SIZE_B)
#define SIZE_A  8

#define SIZE_OP 6

#define POS_C  SIZE_OP
#define POS_B  (POS_C + SIZE_C)
#define POS_Bx POS_C
#define POS_A  (POS_B + SIZE_B)

#define POS_OP 0

/*
** Macros to operate RK indices
*/

/* this bit 1 means constant (0 means register) */
#define BITRK (1 << (SIZE_B - 1))
/* test whether value is a constant */
#define ISK(x) ((x) & BITRK)
/* gets the index of the constant */
#define INDEXK(r)  ((int)(r) & ~BITRK)
#define MAXINDEXRK (BITRK - 1)
/* code a constant index as a RK value */
#define RKASK(x) ((x) | BITRK)

/*
** invalid register that fits in 8 bits
*/
#define NO_REG MAXARG_A

typedef enum {
	/*----------------------------------------------------------------------
		name            args    description
	------------------------------------------------------------------------*/
	OP_MOVE, /*      A B     R(A) := R(B)                                    */
	OP_LOADK, /*     A Bx    R(A) := Kst(Bx)                                 */
	OP_LOADBOOL, /*  A B C   R(A) := (Bool)B; if (C) PC++                    */
	OP_LOADNIL, /*   A B     R(A) := ... := R(B) := nil                      */
	OP_GETUPVAL, /*  A B     R(A) := UpValue[B]                              */

	OP_GETGLOBAL, /* A Bx    R(A) := Gbl[Kst(Bx)]                            */
	OP_GETTABLE, /*  A B C   R(A) := R(B)[RK(C)]                             */

	OP_SETGLOBAL, /* A Bx    Gbl[Kst(Bx)] := R(A)                            */
	OP_SETUPVAL, /*  A B     UpValue[B] := R(A)                              */
	OP_SETTABLE, /*  A B C   R(A)[RK(B)] := RK(C)                            */

	OP_NEWTABLE, /*  A B C   R(A) := {} (size = B,C)                         */

	OP_SELF, /*      A B C   R(A+1) := R(B); R(A) := R(B)[RK(C)]             */

	OP_ADD, /*       A B C   R(A) := RK(B) + RK(C)                           */
	OP_SUB, /*       A B C   R(A) := RK(B) - RK(C)                           */
	OP_MUL, /*       A B C   R(A) := RK(B) * RK(C)                           */
	OP_DIV, /*       A B C   R(A) := RK(B) / RK(C)                           */
	OP_POW, /*       A B C   R(A) := RK(B) ^ RK(C)                           */
	OP_UNM, /*       A B     R(A) := -R(B)                                   */
	OP_NOT, /*       A B     R(A) := not R(B)                                */

	OP_CONCAT, /*    A B C   R(A) := R(B).. ... ..R(C)                       */

	OP_JMP, /*       sBx     PC += sBx                                       */

	OP_EQ, /*        A B C   if ((RK(B) == RK(C)) ~= A) then pc++            */
	OP_LT, /*        A B C   if ((RK(B) <  RK(C)) ~= A) then pc++            */
	OP_LE, /*        A B C   if ((RK(B) <= RK(C)) ~= A) then pc++            */

	OP_TEST, /*      A B C   if (R(B) <=> C) then R(A) := R(B) else pc++     */

	OP_CALL, /*      A B C   R(A), ... ,R(A+C-2) := R(A)(R(A+1), ... ,R(A+B-1)) */
	OP_TAILCALL, /*  A B C   return R(A)(R(A+1), ... ,R(A+B-1))              */
	OP_RETURN, /*    A B     return R(A), ... ,R(A+B-2)      (see note)      */

	OP_FORLOOP, /*   A sBx   R(A)+=R(A+2); if R(A) <?= R(A+1) then PC+= sBx  */

	OP_TFORLOOP, /*  A C     R(A+2), ... ,R(A+2+C) := R(A)(R(A+1), R(A+2));
					if R(A+2) ~= nil then pc++ */
	OP_TFORPREP, /*  A sBx   if type(R(A)) == table then R(A+1):=R(A), R(A):=next;
				PC += sBx                                       */
	OP_SETLIST, /*   A Bx    R(A)[Bx-Bx%FPF+i] := R(A+i), 1 <= i <= Bx%FPF+1 */
	OP_SETLISTO, /*  A Bx                                                    */

	OP_CLOSE, /*     A       close all variables in the stack up to (>=) R(A)*/
	OP_CLOSURE, /*   A Bx    R(A) := closure(KPROTO[Bx], R(A), ... ,R(A+n))  */
} LuaOpCode;

#define LUA_NUM_OPCODES ((int)(OP_CLOSURE) + 1)

/*===========================================================================
  Notes:
  (1) In OP_CALL, if (B == 0) then B = top. C is the number of returns - 1,
      and can be 0: OP_CALL then sets `top' to last_result+1, so
      next open instruction (OP_CALL, OP_RETURN, OP_SETLIST) may use `top'.

  (2) In OP_RETURN, if (B == 0) then return up to `top'

  (3) For comparisons, B specifies what conditions the test should accept.

  (4) All `skips' (pc++) assume that next instruction is a jump
===========================================================================*/

/*
** masks for instruction properties
*/
enum OpModeMask {
	OpModeBreg = 2, /* B is a register */
	OpModeBrk, /* B is a register/constant */
	OpModeCrk, /* C is a register/constant */
	OpModesetA, /* instruction set register A */
	OpModeK, /* Bx is a constant */
	OpModeT /* operator is a test */
};

#define getOpMode(m)     (cast(enum OpMode, luaP_opmodes50[m] & 3))
#define testOpMode(m, b) (luaP_opmodes50[m] & (1 << (b)))

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

#define GETARG_sBx(i)    (GETARG_Bx(i) - MAXARG_sBx)
#define SETARG_sBx(i, b) SETARG_Bx((i), cast(unsigned int, (b) + MAXARG_sBx))

#define CREATE_ABC(o, a, b, c) ((cast(ut32, o) << POS_OP) | (cast(ut32, a) << POS_A) | (cast(ut32, b) << POS_B) | (cast(ut32, c) << POS_C))

#define CREATE_ABx(o, a, bc) ((cast(ut32, o) << POS_OP) | (cast(ut32, a) << POS_A) | (cast(ut32, bc) << POS_Bx))

#endif // BUILD_ARCH_52_H
