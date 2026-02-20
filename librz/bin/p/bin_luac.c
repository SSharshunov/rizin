// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

#include <rz_bin.h>
#include <rz_lib.h>
#include "librz/bin/format/luac/luac_common.h"

#define GET_INTERNAL_BIN_INFO_OBJ(bf) ((LuacBinInfo *)(bf)->o->bin_obj)

static bool check_buffer(RzBuffer *buff) {
	if (rz_buf_size(buff) > LUAC_MAGIC_SIZE) {
		ut8 buf[LUAC_MAGIC_SIZE];
		rz_buf_read_at(buff, 0, buf, LUAC_MAGIC_SIZE);
		return !memcmp(buf, LUAC_MAGIC, LUAC_MAGIC_SIZE);
	}
	return false;
}

static int cmp_sections(const void *a, const void *b) {
	const RzBinSection *s_a, *s_b;
	s_a = a;
	s_b = b;
	return s_a->paddr - s_b->paddr;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	LuaHeaderInfo *header = RZ_NEW0(LuaHeaderInfo);
	const size_t header_size = parse_header(bf, header);
	if (header_size == 0) {
		RZ_LOG_ERROR("Invalid or truncated luac header\n");
		free(header);
		return false;
	}
	LuaProto *proto = lua_parse_body(buf, header, header_size, bf->size);
	if (!proto) {
		RZ_LOG_ERROR("Invalid luac proto\n");
		free(header);
		return false;
	}

	RzBinInfo *general_info = lua_parse_bin_info(bf, header);

	LuacBinInfo *bin_info_obj = luac_build_info(proto);
	if (!bin_info_obj) {
		lua_free_proto_entry(proto);
		rz_bin_info_free(general_info);
		free(bin_info_obj);
		return false;
	}
	bin_info_obj->header = header;
	bin_info_obj->general_info = general_info;
	bin_info_obj->proto = proto;

	rz_pvector_sort(bin_info_obj->section_vec, (RzPVectorComparator)cmp_sections, NULL);

	void **iter;
	RzBinSection *bin_sec;
	int i = 0;
	rz_pvector_foreach (bin_info_obj->section_vec, iter) {
		bin_sec = *iter;
		ut64 vaddr = i * 0x1000;
		char *proto_name = NULL;
		if (bin_sec->is_data) {
			proto_name = rz_str_newf("fcn.proto%d.const", i);
			vaddr = i * 0x1000 + 0x800;
			i++;
		} else {
			proto_name = rz_str_newf("fcn.proto%d.code", i);
		}
		bin_sec->vaddr = vaddr;
		bin_sec->name = rz_str_dup(proto_name);
		RZ_FREE(proto_name);
	}

	obj->bin_obj = bin_info_obj;
	return true;
}

static RzBinInfo *info(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	LuacBinInfo *bin_info_obj = GET_INTERNAL_BIN_INFO_OBJ(bf);
	rz_return_val_if_fail(bin_info_obj, NULL);
	return bin_info_obj->general_info;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	LuacBinInfo *bin_info_obj = GET_INTERNAL_BIN_INFO_OBJ(bf);
	rz_return_val_if_fail(bin_info_obj, NULL);
	return rz_pvector_clone(bin_info_obj->section_vec);
}

static RzPVector /*<RzBinMap *>*/ *maps(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}

	LuacBinInfo *obj = bf->o->bin_obj;

	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	if (!ret) {
		return NULL;
	}

	RzBinMap *map = NULL;
	RzPVector *v = obj->section_vec;
	void **it;
	int i = 0;
	rz_pvector_foreach (v, it) {
		RzBinSection *bin_sec = (RzBinSection *)*it;

		if (!(map = RZ_NEW0(RzBinMap))) {
			rz_pvector_free(ret);
			return NULL;
		}
		map->paddr = bin_sec->paddr;
		map->vaddr = bin_sec->vaddr;
		// printf("paddr: 0x%llx, vaddr: 0x%llx, bin_sec->paddr: 0x%llx, bin_sec->vaddr: 0x%llx\n", map->paddr, map->vaddr, bin_sec->paddr, bin_sec->vaddr);
		map->psize = map->vsize = bin_sec->size;
		map->perm = bin_sec->perm;
		map->name = rz_str_dup(bin_sec->name);
		rz_pvector_push(ret, map);
		i++;
	}
	return ret;
}

static RzPVector /*<RzBinSymbol *>*/ *symbols(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	LuacBinInfo *bin_info_obj = GET_INTERNAL_BIN_INFO_OBJ(bf);
	rz_return_val_if_fail(bin_info_obj, NULL);
	RzListIter *iter;
	RzBinSymbol *sym;
	RzPVector *vec = rz_pvector_new(NULL);
	rz_list_foreach (bin_info_obj->symbol_list, iter, sym) {
		rz_pvector_push(vec, sym);
	}
	return vec;
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	LuacBinInfo *bin_info_obj = GET_INTERNAL_BIN_INFO_OBJ(bf);
	rz_return_val_if_fail(bin_info_obj, NULL);
	return rz_pvector_clone(bin_info_obj->entry_vec);
}

static RzPVector /*<RzBinString *>*/ *strings(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	LuacBinInfo *bin_info_obj = GET_INTERNAL_BIN_INFO_OBJ(bf);
	rz_return_val_if_fail(bin_info_obj, NULL);
	rz_return_val_if_fail(bin_info_obj->string_list, NULL);

	RzPVector *pvec = rz_pvector_new((RzPVectorFree)rz_bin_string_free);
	if (!pvec || !rz_pvector_reserve(pvec, rz_list_length(bin_info_obj->string_list))) {
		rz_pvector_free(pvec);
		return NULL;
	}
	RzListIter *iter;
	RzBinString *bstr;
	rz_list_foreach (bin_info_obj->string_list, iter, bstr) {
		if (bstr) {
			rz_pvector_push(pvec, bstr);
		}
	}
	const RzListFree free_cb = bin_info_obj->string_list->free;
	bin_info_obj->string_list->free = NULL;
	rz_list_purge(bin_info_obj->string_list);
	bin_info_obj->string_list->free = free_cb;
	return pvec;
}

static void destroy(RzBinFile *bf) {
	LuacBinInfo *bin_info_obj = GET_INTERNAL_BIN_INFO_OBJ(bf);
	luac_build_info_free(bin_info_obj);
}

static RzStructuredData *get_structured_data_protos(RzStructuredData *parent, LuaProto *proto, st32 minor) {
	ut8 instruction_size = minor == 0 ? 8 : 4;
#ifdef RZ_DEBUG
	const char *pnd = proto->proto_name ? rz_str_dup((char *)proto->proto_name + 1) : rz_str_newf("fcn.%08llx", proto->offset);
	RZ_LOG_DEBUG("\n%s <%s:%" PFMT64d ",%" PFMT64d "> (%" PFMT64d " instructions at 0x%p)\n",
		proto->line_defined == 0 ? "main" : "function",
		pnd,
		proto->line_defined,
		proto->lastline_defined,
		proto->code_size / instruction_size,
		&proto);
	free((char *)pnd);

	RZ_LOG_DEBUG("%" PFMT32d "%s param%s, %" PFMT32d " slots, %" PFMT32d " upvalues, %" PFMT32d " locals, %" PFMT32d " constants, %" PFMT32d " functions\n",
		proto->num_params,
		isvararg(proto->is_vararg) ? "+" : "",
		proto->num_params > 1 ? "s" : "",
		proto->max_stack_size,
		proto->upvalue_entries->length,
		proto->local_var_info_entries->length,
		proto->const_entries->length,
		proto->proto_entries->length);
	RZ_LOG_DEBUG("constants (%" PFMT32d ")\n",
		proto->const_entries->length);
	RzListIter *it;
	LuaConstEntry *val;
	st32 i = 0;
	(void)i;
	rz_list_foreach (proto->const_entries, it, val) {
		if (!val) {
			continue;
		}
		if ((val->tag & 0x0F) == LUA_TSTRING) {
			RZ_LOG_DEBUG("%" PFMT32d "	%s\n", ++i, val->data ? (char *)val->data : "NULL");
		} else if (val->tag == LUA_VNUMINT) {
			RZ_LOG_DEBUG("%" PFMT32d "	%" PFMT64d "\n", ++i, *(st64 *)val->data);
		} else if (val->tag == LUA_VNUMFLT) {
			RZ_LOG_DEBUG("%" PFMT32d "	%f\n", ++i, *(double *)val->data);
		} else if ((val->tag & 0x0F) == LUA_TBOOLEAN) {
			RZ_LOG_DEBUG("%" PFMT32d "	%s\n", ++i, (bool)val->data == true ? "true" : "false");
		} else if ((val->tag & 0x0F) == LUA_TNIL) {
			RZ_LOG_DEBUG("%" PFMT32d "	%s\n", ++i, "NIL");
		} else {
			rz_warn_if_reached();
		}
	}
#endif

	const char *key = rz_str_newf("fcn.%08" PFMT64x, proto->offset);
	RzStructuredData *sd = rz_structured_data_map_add_map(parent, key);
	free((char *)key);
	if (!sd) {
		return NULL;
	}

	const char *pn = rz_str_newf(proto->line_defined ? "fcn.%08" PFMT64x : "main.%08" PFMT64x, proto->offset);
	rz_structured_data_map_add_string(sd, "proto_name", pn);
	free((char *)pn);

	rz_structured_data_map_add_unsigned(sd, "start_line", proto->line_defined, false);
	rz_structured_data_map_add_unsigned(sd, "last_line", proto->lastline_defined, false);
	rz_structured_data_map_add_unsigned(sd, "instructions", proto->code_size / instruction_size, false);

	rz_structured_data_map_add_unsigned(sd, "num_params", proto->num_params, false);
	rz_structured_data_map_add_unsigned(sd, "slots", proto->max_stack_size, false);
	rz_structured_data_map_add_unsigned(sd, "functions", proto->proto_entries->length, false);
	rz_structured_data_map_add_unsigned(sd, "locals", proto->local_var_info_entries->length, false);
	rz_structured_data_map_add_unsigned(sd, "upvalues", proto->upvalue_entries->length, false);
	if (!proto->const_entries)
		return sd;

	rz_structured_data_map_add_unsigned(sd, "constants_count", proto->const_entries->length, false);
	if (proto->const_entries->length > 0) {
		RzStructuredData *constants = rz_structured_data_map_add_array(sd, "constants");
		if (!constants) {
			return NULL;
		}

		RzListIter *it;
		LuaConstEntry *val;
		rz_list_foreach (proto->const_entries, it, val) {
			if (!val) {
				continue;
			}
			if ((val->tag & 0x0F) == LUA_TSTRING) {
				const char *cnst = rz_str_dup(val->data ? (char *)val->data : "NULL");
				rz_structured_data_array_add_string(constants, cnst);
				free((char *)cnst);
			} else if (val->tag == LUA_VNUMINT) {
				rz_structured_data_array_add_signed(constants, *(st64 *)val->data);
			} else if (val->tag == LUA_VNUMFLT) {
				rz_structured_data_array_add_double(constants, *(double *)val->data);
			} else if ((val->tag & 0x0F) == LUA_TBOOLEAN) {
				rz_structured_data_array_add_boolean(constants, (bool)val->data);
			} else if ((val->tag & 0x0F) == LUA_TNIL) {
				rz_structured_data_array_add_string(constants, "NIL");
			} else {
				rz_warn_if_reached();
			}
		}
	}
	return sd;
}

static RzStructuredData *luac_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->rbin && bf->o && bf->o->bin_obj, NULL);
	LuacBinInfo *obj = GET_INTERNAL_BIN_INFO_OBJ(bf);
	LuaHeaderInfo *header_info = (LuaHeaderInfo *)obj->header;

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *modinfo = rz_structured_data_map_add_map(info, "luac-info");
	if (!modinfo) {
		rz_structured_data_free(info);
		return NULL;
	}

	RzStructuredData *version = rz_structured_data_map_add_map(modinfo, "version");
	if (!version) {
		rz_structured_data_free(modinfo);
		rz_structured_data_free(info);
		return NULL;
	}
	rz_structured_data_map_add_signed(version, "major", header_info->major);
	rz_structured_data_map_add_signed(version, "minor", header_info->minor);

	const char *cmpl = rz_str_dup(obj->general_info->compiler);
	rz_structured_data_map_add_string(modinfo, "compiler", cmpl);
	free((char *)cmpl);

	if (obj->general_info->guid) {
		const char *sfn = rz_str_dup(obj->general_info->guid);
		rz_structured_data_map_add_string(modinfo, "source_file_name", sfn);
		free((char *)sfn);
	}

	rz_structured_data_map_add_unsigned(modinfo, "header_size", obj->proto->offset - 1, false);
	rz_structured_data_map_add_unsigned(modinfo, "body_size", obj->proto->size, false);
	rz_structured_data_map_add_unsigned(modinfo, "file_size", obj->proto->offset - 1 + obj->proto->size, false);

	RzStructuredData *protos = rz_structured_data_map_add_map(modinfo, "protos");
	if (!protos) {
		rz_structured_data_free(version);
		rz_structured_data_free(modinfo);
		rz_structured_data_free(info);
		return NULL;
	}

	RzStructuredData *psd = get_structured_data_protos(protos, obj->proto, obj->header->minor);
	if (!psd) {
		rz_structured_data_free(protos);
		rz_structured_data_free(version);
		rz_structured_data_free(modinfo);
		rz_structured_data_free(info);
	}
	return info;
}

RzBinPlugin rz_bin_plugin_luac = {
	.name = "luac",
	.desc = "Lua compiled binary",
	.license = "LGPL3",
	.author = "Heersin",
	.get_sdb = NULL,
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = NULL,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.info = &info,
	.bin_structure = &luac_structure,
	.strings = &strings,
	.maps = &maps,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_luac,
	.version = RZ_VERSION
};
#endif
