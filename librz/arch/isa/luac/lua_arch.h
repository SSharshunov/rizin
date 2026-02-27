// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#ifndef BUILD_LUA_ARCH_H
#define BUILD_LUA_ARCH_H

#include <rz_types.h>
#include <rz_asm.h>

#define LUA_INVALID_INSNTRUCTION -1
#define LUA_MAX_ARGS0            3
#define LUA_MAX_ARGS4            4

#define print_isk isk ? "k" : ""

#define load_args0 \
	for (int i = 0; i < arg_num; ++i) { \
		const int delta_offset = lua_load_next_arg_start(arg_start, buffer); \
		if (delta_offset == 0) { \
			return LUA_INVALID_INSNTRUCTION; \
		} \
		if (lua_is_valid_num_value_string(buffer)) { \
			args[i] = lua_convert_str_to_num(buffer); \
			arg_start += delta_offset; \
		} else { \
			return LUA_INVALID_INSNTRUCTION; \
		} \
	}

#define MAX_ARGS 10

#define load_args4 \
	for (int i = 0; i < arg_num; ++i) { \
		const int delta_offset = lua_load_next_arg_start(arg_start, buffer); \
		char *ptr = strchr(buffer, 'k'); \
		if (ptr != NULL) { \
			*ptr = '\0'; \
			args[i] = lua_convert_str_to_num(buffer); \
			args[i + 1] = 1; \
			arg_num++; \
			flag |= PARAM_k; \
			break; \
		} \
		args[i] = lua_convert_str_to_num(buffer); \
		arg_start += delta_offset; \
	}

/*
@@ LUAI_BITSINT defines the (minimum) number of bits in an 'int'.
*/
/* avoid undefined shifts */
#if ((INT_MAX >> 15) >> 15) >= 1
#define LUAI_BITSINT 32
#else
/* 'int' always must have at least 16 bits */
#define LUAI_BITSINT 16
#endif

/* parameter flags */
#define PARAM_A   1
#define PARAM_B   2
#define PARAM_C   4
#define PARAM_Ax  8
#define PARAM_Bx  16
#define PARAM_sBx 32
#define PARAM_sJ  64
#define PARAM_sC  128
#define PARAM_sB  256
#define PARAM_k   512

#define SIZE_A 8
#define POS_OP 0

#define SIZE_OP0 6
#define SIZE_OP4 7

#define SIZE_B0  9
#define SIZE_C0  9
#define SIZE_Bx0 (SIZE_C0 + SIZE_B0)

#define POS_C0  SIZE_OP0
#define POS_B0  (POS_C0 + SIZE_C0)
#define POS_Bx0 POS_C0

#define POS_B1 (POS_C1 + SIZE_C0)
#define POS_A0 (POS_B0 + SIZE_B0)
#define POS_A1 (POS_OP + SIZE_OP0)

#define POS_Ax1 POS_A1
#define POS_A4  (POS_OP + SIZE_OP4)
#define POS_Ax4 POS_A4

#define POS_C1 (POS_A1 + SIZE_A)

#define POS_Ax POS_A
#define POS_sJ POS_A

#define GETARG_C1(i) getarg(i, POS_C1, SIZE_C0)
#define GETARG_C0(i) getarg(i, POS_C0, SIZE_C0)

#define SIZE_Ax2 (SIZE_C0 + SIZE_B0 + SIZE_A)

#define SIZE_B4 8
#define SIZE_C4 8

#define SIZE_Bx4 (SIZE_C4 + SIZE_B4 + 1)
#define SIZE_Ax4 (SIZE_Bx4 + SIZE_A)
#define SIZE_sJ4 SIZE_Ax4

#define POS_k4  (POS_A4 + SIZE_A)
#define POS_C4  (POS_B4 + SIZE_B4)
#define POS_B4  (POS_k4 + 1)
#define POS_Bx4 POS_k4
#define POS_sJ4 POS_A4

#define SIZE_vC 10
#define SIZE_vB 6
#define POS_vB  (POS_k4 + 1)
#define POS_vC  (POS_vB + SIZE_vB)

/* type casts (a macro highlights casts in the code) */
#define cast(t, exp) ((t)(exp))

#define MYK(x) (-1 - (x))

/* creates a mask with 'n' 1 bits at position 'p' */
#define MASK1(n, p) ((~((~(LuaInstruction)0) << (n))) << (p))
/* creates a mask with 'n' 0 bits at position 'p' */
#define MASK0(n, p) (~MASK1(n, p))

/*
** limits for opcode arguments.
** we use (signed) int to manipulate most arguments,
** so they must fit in LUAI_BITSINT-1 bits (-1 for sign)
*/

/* 5.0-5.3 */
#if SIZE_Bx0 < LUAI_BITSINT - 1
#define MAXARG_Bx0 ((1 << SIZE_Bx0) - 1)
#define MAXARG_sBx (MAXARG_Bx0 >> 1) /* 'sBx' is signed */
#else
#define MAXARG_Bx0 INT_MAX
#define MAXARG_sBx INT_MAX
#endif

#define MAXARG_A0 ((1 << SIZE_A) - 1)
#define MAXARG_B0 ((1 << SIZE_B0) - 1)
#define MAXARG_C0 ((1 << SIZE_C0) - 1)

/* 5.1-5.3 */
/*
** Macros to operate RK indices
*/

/* this bit 1 means constant (0 means register) */
#define BITRK (1 << (SIZE_B0 - 1))

/* test whether value is a constant */
#define ISK(x) ((x) & BITRK)

/* gets the index of the constant */
#define INDEXK(r) ((int)(r) & ~BITRK)

#if !defined(MAXINDEXRK) /* (for debugging only) */
#define MAXINDEXRK (BITRK - 1)
#endif

/* code a constant index as a RK value */
#define RKASK(x) ((x) | BITRK)

/* 5.2-5.3 */
#if SIZE_Ax2 < LUAI_BITSINT - 1
#define MAXARG_Ax2 ((1 << SIZE_Ax2) - 1)
#else
#define MAXARG_Ax2 INT_MAX
#endif

#define GET_OPCODE50(i) (cast(LuaOpCode50, ((i) >> POS_OP) & MASK1(SIZE_OP0, 0)))
#define GET_OPCODE51(i) (cast(LuaOpCode51, ((i) >> POS_OP) & MASK1(SIZE_OP0, 0)))
#define GET_OPCODE52(i) (cast(LuaOpCode52, ((i) >> POS_OP) & MASK1(SIZE_OP0, 0)))
#define GET_OPCODE53(i) (cast(LuaOpCode53, ((i) >> POS_OP) & MASK1(SIZE_OP0, 0)))
#define GET_OPCODE54(i) (cast(LuaOpCode54, ((i) >> POS_OP) & MASK1(SIZE_OP4, 0)))
#define GET_OPCODE55(i) (cast(LuaOpCode55, ((i) >> POS_OP) & MASK1(SIZE_OP4, 0)))

#define SET_OPCODE50(i, o) \
	((i) = (((i) & MASK0(SIZE_OP0, POS_OP)) | cast(LuaInstruction, o)))
#define SET_OPCODE51(i, o) \
	((i) = (((i) & MASK0(SIZE_OP0, POS_OP)) | \
		 ((cast(LuaInstruction, o) << POS_OP) & MASK1(SIZE_OP0, POS_OP))))
#define SET_OPCODE52(i, o) \
	((i) = (((i) & MASK0(SIZE_OP0, POS_OP)) | \
		 ((cast(LuaInstruction, o) << POS_OP) & MASK1(SIZE_OP0, POS_OP))))
#define SET_OPCODE53(i, o) \
	((i) = (((i) & MASK0(SIZE_OP0, POS_OP)) | \
		 ((cast(LuaInstruction, o) << POS_OP) & MASK1(SIZE_OP0, POS_OP))))
#define SET_OPCODE54(i, o) \
	((i) = (((i) & MASK0(SIZE_OP4, POS_OP)) | \
		 ((cast(LuaInstruction, o) << POS_OP) & MASK1(SIZE_OP4, POS_OP))))
#define SET_OPCODE55(i, o) \
	((i) = (((i) & MASK0(SIZE_OP4, POS_OP)) | \
		 ((cast(LuaInstruction, o) << POS_OP) & MASK1(SIZE_OP4, POS_OP))))

#define getarg(i, pos, size) \
	(cast(int, ((i) >> (pos)) & MASK1(size, 0)))
#define setarg(i, v, pos, size) \
	((i) = (((i) & MASK0(size, pos)) | \
		 ((cast(LuaInstruction, v) << pos) & MASK1(size, pos))))

/* 5.0 */
#define GETARG_A0(i)    (cast(int, (i) >> POS_A0))
#define SETARG_A0(i, u) ( \
	(i) = (((i) & MASK0(SIZE_A, POS_A0)) | \
		((cast(LuaInstruction, u) << POS_A0) & MASK1(SIZE_A, POS_A0))))

/* 5.0-5.5 */
#define SETARG_B0(i, v) setarg(i, v, POS_B0, SIZE_B0)
#define SETARG_B1(i, v) setarg(i, v, POS_B1, SIZE_B0)
#define SETARG_B4(i, v) setarg(i, v, POS_B4, SIZE_B4)

#define SETARG_C0(i, v) setarg(i, v, POS_C0, SIZE_C0)
#define SETARG_C4(i, v) setarg(i, v, POS_C4, SIZE_C4)

#define SETARG_Bx0(i, v) setarg(i, v, POS_Bx0, SIZE_Bx0)
#define SETARG_Bx4(i, v) setarg(i, v, POS_Bx4, SIZE_Bx4)

/* 5.1 */
#define GETARG_B1(i) (cast(int, ((i) >> POS_B1) & MASK1(SIZE_B0, 0)))

/* 5.0-5.3 */
#define GETARG_B0(i)  getarg(i, POS_B0, SIZE_B0)
#define GETARG_Bx0(i) getarg(i, POS_Bx0, SIZE_Bx0)

#define SETARG_C1(i, v) setarg(i, v, POS_C1, SIZE_C0)

#define POS_Bx1          POS_C1
#define GETARG_Bx1(i)    getarg(i, POS_Bx1, SIZE_Bx0)
#define SETARG_Bx1(i, v) setarg(i, v, POS_Bx1, SIZE_Bx0)

#define GETARG_sBx1(i)    (GETARG_Bx1(i) - MAXARG_sBx)
#define SETARG_sBx1(i, b) SETARG_Bx1((i), cast(ut32, (b) + MAXARG_sBx))

#define GETARG_sBx0(i)    (GETARG_Bx0(i) - MAXARG_sBx)
#define SETARG_sBx0(i, b) SETARG_Bx0((i), cast(ut32, (b) + MAXARG_sBx))

/* 5.1-5.5 */
#define GETARG_A1(i)    getarg(i, POS_A1, SIZE_A)
#define GETARG_A4(i)    getarg(i, POS_A4, SIZE_A)
#define SETARG_A1(i, v) setarg(i, v, POS_A1, SIZE_A)
#define SETARG_A4(i, v) setarg(i, v, POS_A4, SIZE_A)

/* 5.2-5.3 */
#define GETARG_Ax2(i)    getarg(i, POS_Ax1, SIZE_Ax2)
#define SETARG_Ax2(i, v) setarg(i, v, POS_Ax1, SIZE_Ax2)

/* 5.4 */
/* Check whether type 'int' has at least 'b' bits ('b' < 32) */
#define L_INTHASBITS4(b) ((UINT_MAX >> ((b) - 1)) >= 1)
#if L_INTHASBITS4(SIZE_Bx4)
#define MAXARG_Bx5 ((1 << SIZE_Bx4) - 1)
#else
#define MAXARG_Bx INT_MAX
#endif

#if L_INTHASBITS4(SIZE_Ax4)
#define MAXARG_Ax ((1 << SIZE_Ax4) - 1)
#else
#define MAXARG_Ax INT_MAX
#endif

#if L_INTHASBITS4(SIZE_sJ4)
#define MAXARG_sJ ((1 << SIZE_sJ4) - 1)
#else
#define MAXARG_sJ INT_MAX
#endif

/* 5.5 */
/*
** Check whether type 'int' has at least 'b' + 1 bits.
** 'b' < 32; +1 for the sign bit.
*/
#define L_INTHASBITS5(b) ((UINT_MAX >> (b)) >= 1)
#if L_INTHASBITS5(SIZE_Bx4)
#define MAXARG_Bx ((1 << SIZE_Bx4) - 1)
#else
#define MAXARG_Bx INT_MAX
#endif

#if L_INTHASBITS5(SIZE_Ax4)
#define MAXARG_Ax ((1 << SIZE_Ax4) - 1)
#else
#define MAXARG_Ax INT_MAX
#endif

#if L_INTHASBITS5(SIZE_sJ4)
#define MAXARG_sJ ((1 << SIZE_sJ4) - 1)
#else
#define MAXARG_sJ INT_MAX
#endif

/* 5.4-5.5 */
#define OFFSET_sBx (MAXARG_Bx >> 1) /* 'sBx' is signed */
#define OFFSET_sJ  (MAXARG_sJ >> 1)

#define MAXARG_A  ((1 << SIZE_A) - 1)
#define MAXARG_B4 ((1 << SIZE_B4) - 1)
#define MAXARG_C4 ((1 << SIZE_C4) - 1)
#define OFFSET_sC (MAXARG_C4 >> 1)

#if !defined(MAXINDEXRK) /* (for debugging only) */
#define MAXINDEXRK MAXARG_B
#endif

/*
** Maximum size for the stack of a Lua function. It must fit in 8 bits.
** The highest valid register is one less than this value.
*/
#define MAX_FSTACK MAXARG_A

/*
** Invalid register (one more than last valid register).
*/
#define NO_REG MAX_FSTACK

#define int2sC(i) ((i) + OFFSET_sC)
#define sC2int(i) ((i) - OFFSET_sC)

#define SETARG_sC(i, v) SETARG_C4((i), int2sC(v))
#define SETARG_sB(i, v) SETARG_B4((i), int2sC(v))

#define CREATE_Ax4(o, a) \
	((cast(LuaInstruction, o) << POS_OP) | (cast(LuaInstruction, a) << POS_Ax))

#define GETARG_B4(i) getarg(i, POS_B4, SIZE_B4)

#define GETARG_sB(i) sC2int(GETARG_B4(i))
#define GETARG_C4(i) getarg(i, POS_C4, SIZE_C4)

#define GETARG_sC(i)  sC2int(GETARG_C4(i))
#define GETARG_Bx4(i) getarg(i, POS_Bx4, SIZE_Bx4)

#define cast_ut32(i)   cast(ut32, (i))
#define cast_st32(i)   cast(st32, (i))
#define GETARG_sBx4(i) getarg(i, POS_Bx4, SIZE_Bx4) - OFFSET_sBx

#define SETARG_sBx4(i, b) SETARG_Bx4((i), cast_ut32((b) + OFFSET_sBx))
#define GETARG_Ax4(i)     getarg(i, POS_Ax4, SIZE_Ax4)
#define SETARG_Ax4(i, v)  setarg(i, v, POS_Ax4, SIZE_Ax4)

#define GETARG_sJ(i) getarg(i, POS_sJ4, SIZE_sJ4) - OFFSET_sJ
#define SETARG_sJ(i, j) \
	setarg(i, cast_ut32((j) + OFFSET_sJ), POS_sJ4, SIZE_sJ4)

#define SETARG_k(i, v) setarg(i, v, POS_k4, 1)

#define GETARG_k4(i) getarg(i, POS_k4, 1)

#define has_param_flag(flag, bit) ((flag) & (bit)) ? true : false

#define lua_strcase(case_str) if ( \
	((limit) <= sizeof(case_str) - 1) && \
	rz_str_ncasecmp((name), (case_str), sizeof(case_str) - 1) == 0)

/**
 * type for virtual-machine instructions
 * must be an unsigned with (at least) 4 bytes (see details in lopcodes.h)
 */
/* Opcode Instruction Type */
typedef ut32 LuaInstruction;
/* Macros/Typedefs used in luac */
typedef double LUA_NUMBER;
typedef ut64 LUA_INTEGER;
typedef ut32 LUA_INT;

typedef struct analysis_luac_context_t {
	ut32 prev_inst; ///< Previous instruction
} AnalysisLuacContext;

/* opcode names */
typedef char **LuaOpNameList;

/* convert a 4-byte ut8 buffer into a lua instruction (ut32) */
LuaInstruction lua_build_instruction(const ut8 *buf);
void lua_set_instruction(LuaInstruction instruction, ut8 *data);
int lua_load_next_arg_start(const char *raw_string, char *recv_buf);
bool lua_is_valid_num_value_string(const char *str);
int lua_convert_str_to_num(const char *str);

/* formatted output strings */
char *luaop_new_str_3arg(char *opname, int a, int b, int c);
char *luaop_new_str_2arg(char *opname, int a, int b);
char *luaop_new_str_1arg(char *opname, int a);
char *luaop_new_str_3arg_ex(char *opname, int a, int b, int c, int isk);
char *luaop_new_str_2arg_ex(char *opname, int a, int b, int isk);
char *luaop_new_str_2arg_ex_ki(char *opname, int a, int b, int isk);
char *luaop_new_str_2arg_ex_kc(char *opname, int a, int b, int isk);
char *luaop_new_str_1arg_ex(char *opname, int a, int isk);
/* Free Opname List */
bool free_lua_opnames(LuaOpNameList list);

/* Lua 5.5 specified */
int lua55_disasm(RzAsmOp *op, const ut8 *buf, int len, LuaOpNameList oplist);
int lua55_analysis_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len);
bool lua55_assembly(const char *input, st32 input_size, LuaInstruction *instruction);
LuaOpNameList get_lua55_opnames(void);
ut8 get_lua55_opcode_by_name(const char *name, int len);

/* Lua 5.4 specified */
int lua54_disasm(RzAsmOp *op, const ut8 *buf, int len, LuaOpNameList oplist);
int lua54_analysis_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask);
bool lua54_assembly(const char *input, st32 input_size, LuaInstruction *instruction);
LuaOpNameList get_lua54_opnames(void);
ut8 get_lua54_opcode_by_name(const char *name, int len);

/* Lua 5.3 specified */
int lua53_disasm(RzAsmOp *op, const ut8 *buf, int len, LuaOpNameList oplist);
int lua53_analysis_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len);
bool lua53_assembly(const char *input, st32 input_size, LuaInstruction *instruction);
LuaOpNameList get_lua53_opnames(void);
ut8 get_lua53_opcode_by_name(const char *name, int len);

/* Lua 5.2 specified */
int lua52_disasm(RzAsmOp *op, const ut8 *buf, int len, LuaOpNameList oplist);
int lua52_analysis_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len);
bool lua52_assembly(const char *input, st32 input_size, LuaInstruction *instruction);
LuaOpNameList get_lua52_opnames(void);
ut8 get_lua52_opcode_by_name(const char *name, int len);

/* Lua 5.1 specified */
int lua51_disasm(RzAsmOp *op, const ut8 *buf, int len, LuaOpNameList oplist);
int lua51_analysis_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len);
bool lua51_assembly(const char *input, st32 input_size, LuaInstruction *instruction);
LuaOpNameList get_lua51_opnames(void);
ut8 get_lua51_opcode_by_name(const char *name, int len);

/* Lua 5.0 specified */
int lua50_disasm(RzAsmOp *op, const ut8 *buf, int len, LuaOpNameList oplist);
int lua50_analysis_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len);
bool lua50_assembly(const char *input, st32 input_size, LuaInstruction *instruction);
LuaOpNameList get_lua50_opnames(void);
ut8 get_lua50_opcode_by_name(const char *name, int len);

ut64 get_k_vaddr(RzAnalysis *analysis, ut64 addr, int k_idx);
char *get_const_string(RzAnalysis *analysis, ut64 addr, ut32 index);
#endif // BUILD_LUA_ARCH_H
