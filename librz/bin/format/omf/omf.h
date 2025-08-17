// SPDX-FileCopyrightText: 2015 ampotos <mercie_i@epitech.eu>
// SPDX-FileCopyrightText: 2015-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2025 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef OMF_H_
#define OMF_H_

#include <rz_util.h>
#include <rz_types.h>
#include <rz_bin.h>

#include "omf_specs.h"

#define BOOL_STR(x) x ? "true" : "false"

#define FINAL_TYPE                0x00
#define COMPONENT_LIST_DESCRIPTOR 0x20
#define POINTER_DESCRIPTOR        0x21
#define ARRAY_DESCRIPTOR          0x22
#define FUNCTION_DESCRIPTOR       0x23
#define STRUCT_UNION_DESCRIPTOR   0x24
#define BITFIELD_DESCRIPTOR       0x25

#define REP_BIT 0
// 0: BIT - the symbol is a bit symbol. The ’bpos’ field contains the
// position of the bit in the bitaddressable word. If V=1, then the
// Offset16 field specifies a register (0=R0, 1=R1, 15=R15).
#define REP_VAR 1
// 1: VAR - the symbol is a variable, whose type is specified with the
// type index.
#define REP_LAB 2
// 2: LAB - the symbol represents a label or procedure.
#define REP_REGBANK 3
// 3: REGBANK - the symbol represents the name of a register bank.
// ’Offset16’ is an address relative to segment zero.
#define REP_INTNO 4
// 4: INTNO - the symbol represents a symbolic interrupt
// number.’Offset16’ is the absolute interrupt number
#define REP_CONST 5
// 5: CONST - the symbol represents the numeric constant given by Offset16.
#define REP_REGVAR 6
// 6: REGVAR - the symbol represents a register variable. The register
// number is defined by the Offset16 field. The type of the variable given
// by TypeIndex decides the interpretation of the register number
// (WORD or BYTE register).
#define REP_AUTO 7
// 7: AUTO - the symbol represents a an automatic variable, which are
// located on the stack. Automatics are relative to R0 with an offset
// given by Offset16 [R0+Offset16]).

/*
	iTyp_0: Outputfile descriptor.
	Specifies path and name of the output file
	created by a translator or linker

	iTyp_1: Inputfile descriptor.
	Specifies path and name of the input file to the translator.

	iTyp_2: Includefile descriptor.
	If the Input file contains more than one include file,
	then each include file is listed with an iTyp_2 descriptor.

	iTyp_3: Commandfile descriptor;
	used when @file was given in the invocation line.

	iTyp_4: Object-Inputfile descriptor.
	Used to specify an object file as input for L166.

	iTyp_5: Commandline descriptor.
	Contains the invocation line to the translator
	including all invocation controls.
*/
#define ITYP_OUTPUTFILE       0x00
#define ITYP_INPUTFILE        0x01
#define ITYP_INCLUDEFILE      0x02
#define ITYP_COMMANDFILE      0x03
#define ITYP_OBJECT_INPUTFILE 0x04
#define ITYP_COMMANDLINE      0x05

#define IS_FINAL_TI(x) ((x >= 0x40) && (x <= 0x54))

typedef struct OMF_record_handler {
	OMF_record record;
	struct OMF_record_handler *next;
} OMF_record_handler;

typedef struct {
	ut32 nb_elem;
	void *elems;
} OMF_multi_datas;

typedef struct OMF_DATA {
	ut64 paddr; // offset in file
	ut64 size;
	ut32 offset;
	ut16 seg_idx;
	ut8 type;
	bool is_data;
	bool is_segment;
	struct OMF_DATA *next;
} OMF_data;

// sections return by the plugin are the addr of datas because sections are
// separate on non contiguous block on the omf file
typedef struct {
	ut32 index;
	ut32 name_idx;
	ut64 size;
	ut8 bits;
	ut64 vaddr;
	ut8 type;
	OMF_data *data;
} OMF_segment;

typedef struct {
	ut32 name_idx;
	ut64 size;
	ut8 bits;
	ut64 vaddr;
	ut8 type;
	OMF_data *data;
} OMF_pedata;

typedef struct {
	ut64 size;
	ut8 bits;
	ut64 vaddr;
	ut8 type;
	OMF_data *data;
} OMF_vecdata;

typedef struct {
	ut32 index;
	bool is_data;
	ut32 base;
	ut8 n; ///< n max 255, so name array len is 255
	char *name;
	char name2[255];
	ut64 size;
	ut16 seg_idx;
	ut32 offset;
	ut8 rec_type;
	ut16 ti;
	bool V;
	ut8 REP;
	ut8 REP8;
	ut8 bpos;
} OMF_symbol;

typedef struct {
	ut16 seg_idx;
	ut8 GroupIndex;
	ut8 SectionIndex;
	ut16 FrameNumber; // (optional)
	ut8 n; ///< n max 255, so name array len is 255
	char name[255];
	ut16 BlockOffset16;
	ut16 BlockLength16;

	bool PInfoProcedure;
	ut16 TI;
} OMF_blocks;

typedef struct {
	ut16 index;
	ut8 Type;
	bool X;
	bool H;
	ut8 bitpos;
	ut8 SecAtr;
	ut8 SegmentNumber8;
	ut32 offset;
	ut16 Seclen;
	bool isXSec;
} OMF_sections;

typedef struct {
	ut32 size;
	ut8 SegmentNumber8;
	bool isVector;
	ut8 data_type;
	ut32 offset;
	ut32 paddr;
	ut32 psize;
} OMF_pes;

typedef struct {
	ut16 index;
	char name[255];
} OMF_lnames;

typedef struct {
	ut16 index;
} OMF_deplsts;

typedef struct {
	ut16 fileIndex;
	ut16 LineNumber;
	ut64 address;
	ut8 n;
	char filename[255];
} OMF_linnums;

typedef struct {
	ut16 seg_idx;
	ut16 offset;
} OMF_ledatas;

typedef struct {
	ut16 index;
} OMF_regmsks;

typedef struct {
	ut16 index;
	bool nopurge;
	bool is_filename;
	ut8 n;
	char text[255];
} OMF_coments;

typedef struct {
	ut8 bits;
	ut8 modinfo;
	char **names;
	// ut32 nb_types;
	// OMF_typedata types[255];
	ut32 nb_name;
	OMF_segment **sections;
	ut32 nb_section;
	OMF_symbol **symbols;
	ut32 nb_symbol;
	OMF_record_handler *records;
} rz_bin_omf_obj;

typedef struct {
	ut16 index;
	// bool nopurge;
	// bool is_filename;
	ut8 n; ///< n max 255, so name array len is 255
	char name[255];
} OMF_debug_includes;

typedef struct {
	bool struct_union; ///< 1 = struct, 2 = union
	ut8 n;
	char tagname[255];
	ut32 size;
	ut16 member_ti;
} OMF_type_struct;

typedef struct {
	ut8 size;
	ut8 attrib;
	ut16 ti;
} OMF_type_pointer;

typedef struct {
	ut8 attrib; ///< 1 = Near-Function 2 = Far-Function
	ut16 rtype_ti;
	ut16 param_ti;
} OMF_type_function;

typedef struct {
	ut8 index;
	ut8 descr_type;
	void *data;
} OMF_typedata;

typedef struct {
	ut16 index;
	ut16 ti;
	ut32 offset;
	ut8 REP8;
	ut8 POS8;
	ut8 n; ///< n max 255, so name array len is 255
	char name[255];
} OMF_component;

typedef struct {
	ut16 index;
	ut16 count;
	OMF_component *comp;
} OMF_components;

typedef struct {
	ut16 index;
	bool is_data;
	ut16 size;
	char *label;
	void *user;
} OMF_types;

typedef struct {
	ut8 index;
	ut8 descr_type;
	// void *data;
	bool is_data;
	union {
		OMF_types final_types;
		OMF_components components;
		struct {
			ut8 size;
			ut8 attrib;
			ut16 ti;
		} pointer;
		struct {
			ut8 attrib; ///< 1 = Near-Function 2 = Far-Function
			ut16 rtype_ti;
			ut16 parmlist_ti;
		} function;
		struct {
			ut8 dims; ///< number of array dimensions
			ut8 attrib; ///< 1 = Huge-Array (0 ... 64K) 2 = Xhuge-Array (0 ... 16MByte)
			ut16 ti; ///< refers to the type which the array consist of
			ut32 dimsz; ///< the dimension size of each dimension
		} array;
		struct {
			bool is_struct; ///< 1 = struct, 2 = union
			ut8 n;
			char tagname[255];
			ut32 size;
			ut16 member_ti;
		} struct_union;

	} descriptor;
	char *label;
	void *rz_type;
} OMF_type;

typedef struct {
	ut16 TI16;
	ut32 OFFS32;
	ut8 REP8;
	ut8 POS8;
	ut8 n;
	char name[255];
} OMF_type_components;

typedef struct {
	ut16 NrOfComp16;
	OMF_type_components components[255];
} OMF_type_component_list;

typedef struct {
	ut16 index;
	// ut16 count;
	ut8 attrib;
	ut16 rtype;
	ut16 parmlist;
} OMF_functions;

typedef struct {
	ut8 bits;
	ut8 modinfo;
	ut32 nb_types;
	OMF_typedata types[255];
	OMF_vecdata **vecdata;
	ut32 nb_vecdata;

	RzTypeDB *typedb;
	HtUP /*<OMF_type *>*/ *ht_types;
	RzPVector /*<OMF_debug_includes *>*/ *includes_vec;
	RzPVector /*<OMF_ledatas *>*/ *ledatas_vec;
	RzPVector /*<OMF_lnames *>*/ *lnames_vec;
	RzPVector /*<OMF_deplsts *>*/ *deplsts_vec;
	RzPVector /*<OMF_linnums *>*/ *linnums_vec;
	RzPVector /*<OMF_regmsks *>*/ *regmsks_vec;
	RzPVector /*<OMF_coments *>*/ *coments_vec;
	RzPVector /*<OMF_sections *>*/ *sections_vec;
	RzPVector /*<OMF_symbol *>*/ *symbols_vec;
	RzPVector /*<OMF_blocks *>*/ *blocks_vec;
	RzPVector /*<OMF_pes *>*/ *pe_vec;
	RzVector /*<ut64>*/ *interrupts;
	ut32 nb_symbol;
} rz_bin_omf166_obj;

typedef struct {
	ut8 type;
	ut16 size;
	void *content;
	ut8 checksum;
} OMF166_modinfo;

// this value was chosen arbitrarily to made the loader work correctly
// if someone want to implement rellocation for omf he has to remove this
#define OMF_BASE_ADDR    0x1000
#define OMF166_BASE_ADDR 0x00
bool rz_bin_checksum_omf_ok(const ut8 *buf, ut64 buf_size);
rz_bin_omf_obj *rz_bin_internal_omf_load(const ut8 *buf, ut64 size);
void rz_bin_free_all_omf_obj(rz_bin_omf_obj *obj);
bool rz_bin_omf_get_entry(rz_bin_omf_obj *obj, RzBinAddr *addr);
int rz_bin_omf_get_bits(rz_bin_omf_obj *obj);
int rz_bin_omf_send_sections(RzPVector /*<RzBinSection *>*/ *vec, OMF_segment *section, rz_bin_omf_obj *obj);
ut64 rz_bin_omf_get_paddr_sym(rz_bin_omf_obj *obj, OMF_symbol *sym);
ut64 rz_bin_omf_get_vaddr_sym(rz_bin_omf_obj *obj, OMF_symbol *sym);

const ut32 get_perm_by_type(ut8 data_type);
const char *get_data_type(ut8 data_type);
RZ_API bool is_data_ti(rz_bin_omf166_obj *obj, ut16 ti_index);
RZ_API const char *name_of_ti(rz_bin_omf166_obj *obj, ut16 ti_index);
RZ_API bool is_final_type(rz_bin_omf166_obj *obj, ut16 ti_index);
RZ_API const char *name_of_rep8(ut8 rep8);
rz_bin_omf166_obj *rz_bin_internal_omf166_load(const ut8 *buf, ut64 size);
void rz_bin_free_all_omf166_obj(rz_bin_omf166_obj *obj);
bool rz_bin_omf166_get_entry(rz_bin_omf166_obj *obj, RzBinAddr *addr);
int rz_bin_omf166_send_sections(RzPVector /*<RzBinSection *>*/ *vec, OMF_segment *section, rz_bin_omf166_obj *obj);
ut64 rz_bin_omf166_get_paddr_sym(rz_bin_omf166_obj *obj, OMF_symbol *sym);
ut64 rz_bin_omf166_get_vaddr_sym(rz_bin_omf166_obj *obj, OMF_symbol *sym);
const char *rz_bin_omf166_get_module_information(rz_bin_omf166_obj *obj);
void free_lname(OMF_multi_datas *lname);
#endif
