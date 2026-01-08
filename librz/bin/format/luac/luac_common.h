// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

// put common definition of luac

#ifndef BUILD_LUAC_COMMON_H
#define BUILD_LUAC_COMMON_H

#include <rz_bin.h>
#include <rz_lib.h>
#include <rz_list.h>

/* Macros for bin_luac.c */
/* Macros/Typedefs used in luac */
typedef double LUA_NUMBER;
typedef ut64 LUA_INTEGER;
typedef ut32 LUA_INT;

#define PF_VAHID 1 /* function has hidden vararg arguments */
#define PF_VATAB 2 /* function has vararg table */
#define PF_FIXED 4 /* prototype has parts in fixed memory */

/* a vararg function either has hidden args. or a vararg table */
#define isvararg(flag) (flag & (PF_VAHID | PF_VATAB))

/* Macro Functions */
/* type casts (a macro highlights casts in the code) */
#define luac_cast(t, exp) ((t)(exp))
#define luac_cast_num(i)  luac_cast(double, (i))
#define luac_cast_int(i)  luac_cast(int, (i))

/* Header Part */
// #define LUAC_52_FORMAT_OFFSET           0x05
// #define LUAC_52_LUAC_DATA_OFFSET        0x06
#define LUAC_52_INT_SIZE_OFFSET         0x07 // 0x0C
#define LUAC_52_SIZET_SIZE_OFFSET       0x09 // 0x0D
#define LUAC_52_INSTRUCTION_SIZE_OFFSET 0x08 // 0x0E
#define LUAC_52_INTEGER_SIZE_OFFSET     0x0F
#define LUAC_52_NUMBER_SIZE_OFFSET      0x0A // 0x10
#define LUAC_52_INTEGER_VALID_OFFSET    0x11 /* from 0x11 - 0x18 : 8 bytes */
#define LUAC_52_NUMBER_VALID_OFFSET     0x19 /* from 0x19 - 0x20 : 8 bytes */
#define LUAC_52_UPVALUES_NUMBER_OFFSET  0x21

/* Header Part */
// #define LUAC_53_FORMAT_OFFSET           0x05
// #define LUAC_53_LUAC_DATA_OFFSET        0x06
#define LUAC_53_INT_SIZE_OFFSET         0x0C
#define LUAC_53_SIZET_SIZE_OFFSET       0x0D
#define LUAC_53_INSTRUCTION_SIZE_OFFSET 0x0E
#define LUAC_53_INTEGER_SIZE_OFFSET     0x0F
#define LUAC_53_NUMBER_SIZE_OFFSET      0x10
#define LUAC_53_INTEGER_VALID_OFFSET    0x11 /* from 0x11 - 0x18 : 8 bytes */
#define LUAC_53_NUMBER_VALID_OFFSET     0x19 /* from 0x19 - 0x20 : 8 bytes */
#define LUAC_53_UPVALUES_NUMBER_OFFSET  0x21

/* luac 5.4 spec */
/* Header Information */
#define LUAC_FORMAT_OFFSET              0x05
#define LUAC_DATA_OFFSET                0x06
#define LUAC_54_INSTRUCTION_SIZE_OFFSET 0x0C
#define LUAC_54_INTEGER_SIZE_OFFSET     0x0D
#define LUAC_54_NUMBER_SIZE_OFFSET      0x0E
#define LUAC_54_INTEGER_VALID_OFFSET    0x0F
#define LUAC_54_NUMBER_VALID_OFFSET     0x17
#define LUAC_54_UPVALUES_NUMBER_OFFSET  0x1F

#define LUAC_54_SIGNATURE_SIZE        4
#define LUAC_54_VERSION_SIZE          1
#define LUAC_54_FORMAT_SIZE           1
#define LUAC_54_LUAC_DATA_SIZE        6
#define LUAC_54_INSTRUCTION_SIZE_SIZE 1
#define LUAC_54_INTEGER_SIZE_SIZE     1
#define LUAC_54_NUMBER_SIZE_SIZE      1
#define LUAC_54_INTEGER_VALID_SIZE    8
#define LUAC_54_NUMBER_VALID_SIZE     8
#define LUAC_54_UPVALUES_NUMBER_SIZE  1

#define LUAC_FORMAT            0 /* this is the official format */
#define LUAC_DATA              "\x19\x93\r\n\x1a\n"
#define LUAC_INT_VALIDATION    luac_cast_int(0x5678)
#define LUAC_NUMBER_VALIDATION luac_cast_num(370.5)

typedef ut32 LUA_INSTRUCTION;

/* Macros About Luac Format */
#define LUAC_MAGIC_OFFSET   0x00
#define LUAC_MAGIC_SIZE     4
#define LUAC_VERSION_OFFSET 0x04
#define LUAC_VERSION_SIZE   1

#define LUAC_MAGIC "\x1b\x4c\x75\x61" ///< "\033Lua"

/* Body */
#define LUAC_FILENAME_OFFSET(minor) (minor == 4) ? 0x20 : 0x22

/* Lua Constant Tag */
#define makevariant(t, v) ((t) | ((v) << 4))

#define LUA_TNIL     0
#define LUA_TBOOLEAN 1
#define LUA_TNUMBER  3
#define LUA_TSTRING  4

/* Macros of tag */
// conflict with 5.4
#define LUA_TNUMFLT (3 | (0 << 4)) /* float numbers */
#define LUA_TNUMINT (3 | (1 << 4)) /* integer numbers */

#define LUA_VNIL    makevariant(LUA_TNIL, 0)
#define LUA_VFALSE  makevariant(LUA_TBOOLEAN, 0)
#define LUA_VTRUE   makevariant(LUA_TBOOLEAN, 1)
#define LUA_VNUMINT makevariant(LUA_TNUMBER, 0) /* integer numbers */
#define LUA_VNUMFLT makevariant(LUA_TNUMBER, 1) /* float numbers */
#define LUA_VSHRSTR makevariant(LUA_TSTRING, 0) /* short strings */
#define LUA_VLNGSTR makevariant(LUA_TSTRING, 1) /* long strings */

/**
 *  \struct lua_proto_ex
 *  \brief Store valuable info when parsing. Treat luac file body as a main function.
 */
typedef struct lua_proto_ex {
	ut64 offset; ///< proto offset in bytes
	ut64 size; ///< current proto size

	ut8 *proto_name; ///<  current proto name
	int name_size; ///< size of proto name

	ut64 line_defined; ///< line number of function start
	ut64 lastline_defined; ///< line number of function end

	ut8 num_params; ///< number of parameters of this proto
	ut8 is_vararg; ///< is variable arg?
	ut8 max_stack_size; ///< max stack size

	/* Code of this proto */
	ut64 code_offset; ///< code section offset
	ut64 code_size; ///< code section size
	ut64 code_skipped; ///< opcode data offset to code_offset.

	/* store constant entries */
	RzList /*<LuaConstEntry *>*/ *const_entries; ///< A list to store constant entries
	ut64 const_offset; ///< const section offset
	ut64 const_size; ///< const section size

	/* store upvalue entries */
	RzList /*<LuaUpvalueEntry *>*/ *upvalue_entries; ///< A list to store upvalue entries
	ut64 upvalue_offset; ///< upvalue section offset
	ut64 upvalue_size; ///< upvalue section size

	/* store protos defined in this proto */
	RzList /*<LuaProto *>*/ *proto_entries; ///< A list to store sub proto entries
	ut64 inner_proto_offset; ///< sub proto section offset
	ut64 inner_proto_size; ///< sub proto section size

	/* store Debug info */
	ut64 debug_offset; ///< debug section offset
	ut64 debug_size; ///< debug section size
	RzList /*<LuaLineinfoEntry *>*/ *line_info_entries; ///< A list to store line info entries
	RzList /*<LuaAbsLineinfoEntry *>*/ *abs_line_info_entries; ///< A list to store absolutely line info entries
	RzList /*<LuaLocalVarEntry *>*/ *local_var_info_entries; ///< A list to store local var entries
	RzList /*<LuaLocalVarEntry *>*/ *dbg_upvalue_entries; ///< A list to store upvalue names

} LuaProtoHeavy;

typedef LuaProtoHeavy LuaProto;

/**
 * \struct lua_constant_entry
 * \brief Store constant type, data, and offset of this constant in luac file
 */
typedef struct lua_constant_entry {
	ut8 tag; ///< type of this constant, see LUA_V* macros in luac_common.h
	void *data; ///< can be Number/Integer/String
	int data_len; ///< len of data
	ut64 offset; ///< addr of this constant
} LuaConstEntry;

/**
 * \struct lua_upvalue_entry
 * \brief Store upvalue attributes
 */
typedef struct lua_upvalue_entry {
	/* attributes of upvalue */
	ut8 instack; ///< is in stack
	ut8 idx; ///< index
	ut8 kind; ///< kind
	ut64 offset; ///< offset of this upvalue
} LuaUpvalueEntry;

typedef struct LuaProto LuaProtoEntry;

/**
 * \struct lua_lineinfo_entry
 * \brief Store line info attributes
 */
typedef struct lua_lineinfo_entry {
	ut32 info_data;
	ut64 offset;
} LuaLineinfoEntry;

/**
 * \struct lua_abs_lineinfo_entry
 * \brief Store line info attributes
 */
typedef struct lua_abs_lineinfo_entry {
	int pc; ///< pc value of lua
	int line; ///< line number in source file
	ut64 offset;
} LuaAbsLineinfoEntry;

/**
 * \struct lua_local_var_entry
 * \brief Store local var names and other info
 */
typedef struct lua_local_var_entry {
	ut8 *varname; ///< name of this variable
	int varname_len; ///< length of name
	int start_pc; ///< first active position
	int end_pc; ///< first deactive position
	ut64 offset; ///< offset of this entry
} LuaLocalVarEntry;

/**
 * \struct lua_dbg_upvalue_entry
 * \brief Store upvalue's debug info
 */
typedef struct lua_dbg_upvalue_entry {
	ut8 *upvalue_name; ///< upvalue name
	int name_len; ///< length of name
	ut64 offset;
} LuaDbgUpvalueEntry;

/**
 * \struct lua_bin_info
 * \brief A context info structure for luac plugin.
 */
typedef struct luac_bin_info {
	st32 major; ///< major version
	st32 minor; ///< minor version
	LuaProto *proto;
	RzPVector /*<RzBinSection *>*/ *section_vec; ///< list of sections
	RzList /*<RzBinSymbol *>*/ *symbol_list; ///< list of symbols
	RzPVector /*<RzBinAddr *>*/ *entry_vec; ///< list of entries
	RzList /*<RzBinString *>*/ *string_list; ///< list of strings
	RzBinInfo *general_info; ///< general binary info from luac header
} LuacBinInfo;

/* ========================================================
 * Common Operation to Lua structures
 * Implemented in 'bin/format/luac/luac_common.c'
 * ======================================================== */
LuaDbgUpvalueEntry *lua_new_dbg_upvalue_entry();
LuaLocalVarEntry *lua_new_local_var_entry();
LuaAbsLineinfoEntry *lua_new_abs_lineinfo_entry();
LuaLineinfoEntry *lua_new_lineinfo_entry();
LuaUpvalueEntry *lua_new_upvalue_entry();
LuaConstEntry *lua_new_const_entry();
LuaProto *lua_new_proto_entry();

void lua_free_dbg_upvalue_entry(LuaDbgUpvalueEntry *);
void lua_free_local_var_entry(LuaLocalVarEntry *);
void lua_free_const_entry(LuaConstEntry *);
void lua_free_proto_entry(LuaProto *);

/* ========================================================
 * Common Operation to RzBinInfo
 * Implemented in 'bin/format/luac/luac_bin.c'
 * ======================================================== */
void luac_add_section(RzPVector /*<RzBinSection *>*/ *section_vec, char *name, ut64 offset, ut32 size, bool is_func);
void luac_add_symbol(RzList /*<RzBinSymbol *>*/ *symbol_list, char *name, ut64 offset, ut64 size, const char *type);
void luac_add_entry(RzPVector /*<RzBinAddr *>*/ *entry_vec, ut64 offset, int entry_type);
void luac_add_string(RzList /*<RzBinString *>*/ *string_list, char *string, ut64 offset, ut64 size);

LuacBinInfo *luac_build_info(LuaProto *proto);
void luac_build_info_free(LuacBinInfo *bin_info);
void _luac_build_info(LuaProto *proto, LuacBinInfo *info);

/* ========================================================
 * Export version specified Api to bin_luac.c
 * Implemented in bin/format/luac/v[version]/bin_[version]
 * ======================================================== */
RzBinInfo *lua_parse_header_54(RzBinFile *bf, st32 major, st32 minor);
LuaProto *lua_parse_body_54(RzBuffer *buffer, ut64 offset, ut64 data_size);

RzBinInfo *lua_parse_header_53(RzBinFile *bf, st32 major, st32 minor);
LuaProto *lua_parse_body_53(RzBuffer *buffer, ut64 offset, ut64 data_size);

RzBinInfo *lua_parse_header_52(RzBinFile *bf, st32 major, st32 minor);
LuaProto *lua_parse_body_52(RzBuffer *buffer, ut64 offset, ut64 data_size);

ut8 luac_hdrsize(ut8 minor);
// static
void lua_load_block(RzBuffer *buffer, void *dest, size_t size, ut64 offset, ut64 data_size);
// static
ut64 lua_load_integer(RzBuffer *buffer, ut64 offset);
// static
double lua_load_number(RzBuffer *buffer, ut64 offset);
// static ut32 lua_load_int(RzBuffer *buffer, ut64 offset);
// static ut64 lua_parse_name(LuaProto *proto, RzBuffer *buffer, ut64 offset, ut64 data_size, st32 minor);
LuaProto *lua_parse_body(RzBuffer *buffer, ut64 base_offset, ut64 data_size, st32 minor);
RzBinInfo *lua_parse_header(const RzBinFile *bf, st32 major, st32 minor);

#define lua_check_error_offset(offset) \
	if ((offset) == 0) { \
		return 0; \
	}
#define lua_check_error_offset_proto(offset, proto) \
	if ((offset) == 0) { \
		printf("lua_check_error_offset_proto offset: 0x%llx (line: %d)\n", offset, __LINE__); \
		lua_free_proto_entry((proto)); \
		return NULL; \
	}
#define lua_return_if_null(proto) \
	if ((proto) == NULL) { \
		return 0; \
	}

#endif // BUILD_LUAC_COMMON_H
