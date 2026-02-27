// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#include "luac_common.h"

void luac_add_section(RzPVector /*<RzBinSection *>*/ *section_vec, char *name, ut64 poffset, ut64 voffset, ut32 size, bool is_func) {
	if (size == 0)
		return;
	RzBinSection *bin_sec = RZ_NEW0(RzBinSection);
	if (!bin_sec || !name) {
		free(bin_sec);
		return;
	}
	bin_sec->vaddr = voffset;
	bin_sec->paddr = poffset;
	bin_sec->size = size;
	bin_sec->vsize = size;
	bin_sec->is_data = is_func ? false : true;
	bin_sec->bits = 32;
	bin_sec->has_strings = false;
	bin_sec->arch = "luac";

	if (is_func) {
		bin_sec->perm = RZ_PERM_R | RZ_PERM_X;
	} else {
		bin_sec->perm = RZ_PERM_R;
	}

	if (!rz_pvector_push(section_vec, bin_sec)) {
		rz_bin_section_free(bin_sec);
	}
}

void luac_add_symbol(RzList /*<RzBinSymbol *>*/ *symbol_list, char *name, ut64 poffset, ut64 voffset, ut64 size, const char *type) {
	RzBinSymbol *bin_sym = RZ_NEW0(RzBinSymbol);
	if (!bin_sym) {
		return;
	}

	bin_sym->name = rz_str_dup(name);
	bin_sym->vaddr = voffset;
	bin_sym->paddr = poffset;
	bin_sym->size = size;
	bin_sym->type = type;
	bin_sym->bits = 32;

	rz_list_append(symbol_list, bin_sym);
}

void luac_add_entry(RzPVector /*<RzBinAddr *>*/ *entry_vec, ut64 offset, int entry_type) {
	RzBinAddr *entry = RZ_NEW0(RzBinAddr);
	if (!entry) {
		return;
	}

	entry->vaddr = offset;
	entry->paddr = offset;
	// entry->vaddr = 0;
	// entry->paddr = 0x31;
	entry->type = entry_type;

	rz_pvector_push(entry_vec, entry);
}

void luac_add_string(RzList /*<RzBinString *>*/ *string_list, char *string, ut64 poffset, ut64 voffset, ut64 size) {
	RzBinString *bin_string = RZ_NEW0(RzBinString);
	if (!bin_string) {
		return;
	}

	bin_string->paddr = poffset;
	bin_string->vaddr = voffset;
	bin_string->size = size + 1;
	bin_string->length = size;
	bin_string->string = rz_str_dup(string);
	bin_string->type = RZ_STRING_ENC_UTF8;

	rz_list_append(string_list, bin_string);
}

static void free_rz_section(RzBinSection *section) {
	if (!section) {
		return;
	}

	if (section->name) {
		RZ_FREE(section->name);
	}

	RZ_FREE(section);
}

static void free_rz_string(RzBinString *string) {
	if (!string) {
		return;
	}

	if (string->string) {
		RZ_FREE(string->string);
	}

	RZ_FREE(string);
}

static void free_rz_addr(RzBinAddr *addr) {
	if (!addr) {
		return;
	}
	RZ_FREE(addr);
}

void luac_build_info_free(LuacBinInfo *bin_info) {
	if (!bin_info) {
		return;
	}
	free(bin_info->header->src_file_name);
	free(bin_info->header);
	lua_free_proto_entry(bin_info->proto);
	bin_info->proto = NULL;
	rz_pvector_free(bin_info->protos_vec);
	rz_pvector_free(bin_info->entry_vec);
	rz_list_free(bin_info->symbol_list);
	// rz_pvector_free(bin_info->line_nums_vec);
	rz_pvector_free(bin_info->section_vec);
	rz_list_free(bin_info->string_list);
	free(bin_info);
}

static void free_line_nums(RzBinSourceLineSample *ln) {
	if (!ln) {
		return;
	}

	if (ln->file) {
		RZ_FREE(ln->file);
	}

	RZ_FREE(ln);
}

LuacBinInfo *luac_build_info(RZ_NONNULL LuaProto *proto) {
	if (!proto) {
		RZ_LOG_ERROR("Invalid luac file\n");
		return NULL;
	}

	LuacBinInfo *ret = RZ_NEW0(LuacBinInfo);
	rz_return_val_if_fail(ret, NULL);

	ret->protos_vec = rz_pvector_new((RzPVectorFree)NULL);
	ret->entry_vec = rz_pvector_new((RzPVectorFree)free_rz_addr);
	ret->symbol_list = rz_list_newf((RzListFree)rz_bin_symbol_free);
	ret->section_vec = rz_pvector_new((RzPVectorFree)free_rz_section);
	ret->line_nums_vec = rz_pvector_new((RzPVectorFree)free_line_nums);
	ret->string_list = rz_list_newf((RzListFree)free_rz_string);

	if (!(ret->entry_vec && ret->symbol_list && ret->section_vec && ret->string_list)) {
		rz_pvector_free(ret->entry_vec);
		rz_list_free(ret->symbol_list);
		rz_pvector_free(ret->section_vec);
		rz_pvector_free(ret->line_nums_vec);
		rz_list_free(ret->string_list);
	}

	_luac_build_info(proto, ret);

	// add entry of main
	ut64 main_entry_offset = 0x0 + PROTO_VBASE;
	luac_add_entry(ret->entry_vec, main_entry_offset, RZ_BIN_ENTRY_TYPE_PROGRAM);

	return ret;
}

static const char *get_tag_string(ut8 tag) {
	switch (tag) {
	case LUA_VNIL:
		return "CONST_NIL";
	case LUA_VTRUE:
	case LUA_VFALSE:
		return "CONST_BOOL";
	case LUA_VSHRSTR:
	case LUA_VLNGSTR:
		return "CONST_STRING";
	case LUA_VNUMFLT:
	case LUA_VNUMINT:
		return "CONST_NUM";
	default:
		return "CONST_UNKNOWN";
	}
}

/* Heap allocated string */
static char *get_constant_symbol_name(char *proto_name, LuaConstEntry *entry) {
	rz_return_val_if_fail(entry && proto_name, NULL);
	ut8 tag = entry->tag;
	char *ret;
	st64 integer_value;
	double float_value;

	switch (tag) {
	case LUA_VNIL:
		ret = rz_str_newf("%s_const_nil", proto_name);
		break;
	case LUA_VTRUE:
		ret = rz_str_newf("%s_const_true", proto_name);
		break;
	case LUA_VFALSE:
		ret = rz_str_newf("%s_const_false", proto_name);
		break;
	case LUA_VSHRSTR:
	case LUA_VLNGSTR:
		ret = rz_str_newf("%s_const_%s", proto_name, entry->data_len ? (char *)entry->data : "NULL");
		break;
	case LUA_VNUMFLT:
		rz_return_val_if_fail(entry->data, NULL);
		if (entry->data_len < sizeof(double)) {
			return NULL;
		}
		float_value = rz_read_le_double(entry->data);
		ret = rz_str_newf("%s_const_%f", proto_name, float_value);
		break;
	case LUA_VNUMINT:
		rz_return_val_if_fail(entry->data, NULL);
		if (entry->data_len < sizeof(st64)) {
			return NULL;
		}
		integer_value = (st64)rz_read_le64(entry->data);
		ret = rz_str_newf("%s_const_%lld", proto_name, integer_value);
		break;
	default:
		ret = rz_str_newf("%s_const_0x%llx", proto_name, entry->offset);
		break;
	}
	return ret;
}

/* Heap allocated string */
static char *simple_build_upvalue_symbol(char *proto_name, LuaUpvalueEntry *entry) {
	return rz_str_newf("%s_upvalue_0x%llx", proto_name, entry->offset);
}

static char *get_upvalue_symbol_name(char *proto_name, LuaUpvalueEntry *entry, char *debug_name) {
	rz_return_val_if_fail(proto_name || entry, NULL);
	if (debug_name == NULL) {
		return simple_build_upvalue_symbol(proto_name, entry);
	}

	return rz_str_newf("%s_upvalue_%s", proto_name, debug_name);
}

void _luac_build_info(LuaProto *proto, LuacBinInfo *info) {
	/* process proto header info */
	char *symbol_name = NULL;
	char *proto_name = NULL;
	char **upvalue_names = NULL;
	RzListIter *iter;
	int i = 0; // iter

	ut64 current_offset = 0;
	ut64 current_size = 0;
	char *section_name = NULL;

	// 1.2 set section name as function_name.code
	current_offset = proto->code_offset + proto->code_skipped;
	current_size = proto->code_size;
	proto_name = rz_str_newf("fcn.%08llx", current_offset);
	section_name = rz_str_newf("%s.code", proto_name);
	luac_add_section(info->section_vec, section_name, current_offset, PROTO_VADDRESS(proto->index), current_size, true);

	const char *p = proto->line_defined == 0 ? rz_str_dup("main") : rz_str_newf("proto%d", proto->index);
	RzBinSymbol *proto_sym = rz_bin_symbol_new(p, current_offset, PROTO_VADDRESS(proto->index));
	proto_sym->bind = RZ_BIN_BIND_GLOBAL_STR;
	proto_sym->type = RZ_BIN_TYPE_FUNC_STR;
	proto_sym->bits = 32;
	proto_sym->size = current_size;
	rz_list_append(info->symbol_list, proto_sym);
	RZ_FREE(p);
	RZ_FREE(section_name);

	// 1.3 set const section
	current_offset = proto->const_offset;
	current_size = proto->const_size;

	section_name = rz_str_newf("%s.const", proto_name);
	luac_add_section(info->section_vec, section_name, current_offset, PROTO_VADDRESS(proto->index) + CONST_OFFSET, current_size, false);
	RZ_FREE(section_name);

	LuaLineinfoEntry *line_info_entry;
	rz_list_foreach (proto->line_info_entries, iter, line_info_entry) {
		RzBinSourceLineSample *new_line_sample = RZ_NEW0(RzBinSourceLineSample);
		if (!new_line_sample) {
			return;
		}
		new_line_sample->address = line_info_entry->offset;
		new_line_sample->column = 0;
		new_line_sample->line = line_info_entry->info_data;
		new_line_sample->file = (const char *)proto->proto_name;
		rz_pvector_push(info->line_nums_vec, new_line_sample);
	}

	// 1.4 upvalue section
	// current_offset = proto->upvalue_offset;
	// current_size = proto->upvalue_size;
	// section_name = rz_str_newf("%s.upvalues", proto_name);
	// luac_add_section(info->section_vec, section_name, current_offset, current_size, false);
	// RZ_FREE(section_name);

	// 1.5 inner protos section
	// current_offset = proto->inner_proto_offset;
	// current_size = proto->inner_proto_size;
	// section_name = rz_str_newf("%s.protos", proto_name);
	// luac_add_section(info->section_vec, section_name, current_offset, current_size, false);
	// RZ_FREE(section_name);
	//
	// // 1.6 debug section
	// current_offset = proto->debug_offset;
	// current_size = proto->debug_size;
	// section_name = rz_str_newf("%s.debug", proto_name);
	// luac_add_section(info->section_vec, section_name, current_offset, current_size, false);
	// RZ_FREE(section_name);
	//
	// 2.1 parse local var info
	// LuaLocalVarEntry *local_var_entry;
	// rz_list_foreach (proto->local_var_info_entries, iter, local_var_entry) {
	// 	luac_add_string(
	// 		info->string_list,
	// 		(char *)local_var_entry->varname,
	// 		local_var_entry->offset,
	// 		local_var_entry->offset,
	// 		local_var_entry->varname_len);
	// }

	// 2.2 parse debug_upvalues
	/*
	size_t real_upvalue_cnt = RZ_MAX(rz_list_length(proto->upvalue_entries), rz_list_length(proto->dbg_upvalue_entries));
	if (real_upvalue_cnt > 0) {
		LuaDbgUpvalueEntry *debug_upv_entry;
		upvalue_names = RZ_NEWS0(char *, real_upvalue_cnt);
		if (!upvalue_names) {
			free(proto_name);
			return;
		}

		i = 0;
		rz_list_foreach (proto->dbg_upvalue_entries, iter, debug_upv_entry) {
			upvalue_names[i] = (char *)debug_upv_entry->upvalue_name;
			luac_add_string(
				info->string_list,
				upvalue_names[i],
				debug_upv_entry->offset,
				debug_upv_entry->name_len);
			i++;
		}
	}
	*/
	// 3.1 construct constant symbols
	LuaConstEntry *const_entry = NULL;
	void **it;
	rz_pvector_foreach (proto->const_entries, it) {
		const_entry = *it;
		RZ_FREE(proto_name);
		proto_name = rz_str_newf("data.%08llx", const_entry->voffset);
		symbol_name = get_constant_symbol_name(proto_name, const_entry);
		if (!symbol_name) {
			continue;
		}

		if (const_entry->tag == LUA_VLNGSTR || const_entry->tag == LUA_VSHRSTR) {
			luac_add_string(
				info->string_list,
				(char *)const_entry->data,
				const_entry->offset,
				const_entry->voffset,
				const_entry->data_len);
		}
		RZ_FREE(symbol_name);
		RZ_FREE(proto_name);
	}

	// 3.2 construct upvalue symbols
	/*
	LuaUpvalueEntry *upvalue_entry;
	i = 0;
	rz_list_foreach (proto->upvalue_entries, iter, upvalue_entry) {
		symbol_name = get_upvalue_symbol_name(proto_name, upvalue_entry, upvalue_names[i++]);
		luac_add_symbol(
			info->symbol_list,
			symbol_name,
			upvalue_entry->offset,
			3,
			"UPVALUE");
		RZ_FREE(symbol_name);
	}*/
	(void)i;
	(void)symbol_name;
	(void)get_upvalue_symbol_name;
	(void)get_constant_symbol_name;
	(void)get_tag_string;
	rz_pvector_push(info->protos_vec, proto);

	// 4. parse sub proto
	LuaProto *sub_proto;
	rz_list_foreach (proto->proto_entries, iter, sub_proto) {
		_luac_build_info(sub_proto, info);
	}

	free(upvalue_names);
	free(proto_name);
}
