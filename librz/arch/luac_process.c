// SPDX-FileCopyrightText: 2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_analysis.h>
// #include <luac/lua_arch.h>
#include <bin/format/luac/luac_common.h>

static bool luac_integrate_function(void *user, const ut64 k, const void *value) {
	RZ_LOG_DEBUG("---->luac_integrate_function\n");
	return true;
}

/**
 * \brief Use parsed luac function info in the function analysis
 * \param analysis The analysis
 * \param flags The flags
 */
RZ_API void rz_analysis_luac_integrate_functions(RzAnalysis *analysis, RzFlag *flags) {
	rz_return_if_fail(analysis);
	ht_up_foreach(analysis->debug_info->function_by_addr, luac_integrate_function, analysis);
}

// static RzCallable *create_new_func(rz_bin_omf166_obj *omf_obj, OMF_type *omf_type, OMF_symbol *symbol) {
static RzCallable *create_new_function(LuacBinInfo *luac_obj, RzBinSymbol *symbol) {
	RzTypeDB *typedb = luac_obj->typedb;

	RzCallable *callable = rz_type_func_new(typedb, symbol->name, /*ret_type*/ NULL);
	rz_type_func_noreturn_add(typedb, symbol->name);

	// if (omf_type->descriptor.function.rtype_ti == 0x00 && omf_type->descriptor.function.parmlist_ti == 0x00)
	// 	return create_noretarg_func(typedb, symbol->name2);
	//
	// const char *ret_type_name = name_of_ti(omf_obj, omf_type->descriptor.function.rtype_ti);
	// RzType *ret_type = rz_type_identifier_of_base_type_str(typedb, ret_type_name);
	//
	// RzCallable *callable = rz_type_func_new(typedb, symbol->name2, ret_type);
	//
	// if (!strcmp(ret_type_name, "void") || (!ret_type)) {
	// 	rz_type_func_noreturn_add(typedb, symbol->name2);
	// }
	//
	// RZ_LOG_DEBUG("create_new_func: ti: 0x%02x, rtype_ti: 0x%02x [%s], parmlist_ti: 0x%02x [%s], symbol->name2: `%s` cal `%s`\n",
	// 	symbol->ti,
	// 	omf_type->descriptor.function.rtype_ti,
	// 	omf_type->descriptor.function.rtype_ti == 0x00 ? "0x00" : name_of_ti(omf_obj, omf_type->descriptor.function.rtype_ti),
	// 	omf_type->descriptor.function.parmlist_ti,
	// 	omf_type->descriptor.function.parmlist_ti == 0x00 ? "0x00" : name_of_ti(omf_obj, omf_type->descriptor.function.parmlist_ti),
	// 	symbol->name2,
	// 	callable->name);
	//
	// ut8 parmlist_ti = omf_type->descriptor.function.parmlist_ti;
	//
	// OMF_type *paramt = OMF_TYPE_TI(omf_obj, parmlist_ti);
	// rz_return_val_if_fail(paramt, NULL);
	//
	// ///< (parmlist_ti == 0x4A || parmlist_ti == 0x4d || parmlist_ti == 0x4e)
	// // parse parameter list
	// if ((paramt->descr_type == FINAL_TYPE) && (parmlist_ti != 0x4A)) {
	// 	RZ_LOG_DEBUG("paramt->descr_type == FINAL_TYPE\n");
	// 	RzType *carg_type = rz_type_identifier_of_base_type_str(
	// 		typedb,
	// 		name_of_ti(omf_obj, paramt->descriptor.final_types.index));
	//
	// 	RzCallableArg *cargs = rz_type_callable_arg_new(
	// 		typedb,
	// 		rz_str_dup(paramt->descriptor.final_types.label),
	// 		carg_type);
	// 	rz_type_callable_arg_add(callable, cargs);
	// }
	// if (paramt->descr_type == COMPONENT_LIST_DESCRIPTOR) {
	// 	RZ_LOG_DEBUG("paramt->descr_type == COMPONENT_LIST_DESCRIPTOR\n");
	// 	OMF_components *components = get_component_by_ti(omf_obj, parmlist_ti);
	// 	if (components) {
	// 		for (ut16 i = 0; i < components->count; i++) {
	// 			OMF_component *component = (OMF_component *)components->comp + i;
	// 			if (!component)
	// 				continue;
	// 			RZ_LOG_DEBUG("\tindex: 0x%04x, TI16: 0x%04x (%s), OFFS32: 0x%04x, REP8: 0x%02x, POS8: 0x%02x, n: %d (%s)\n",
	// 				components->index,
	// 				component->ti,
	// 				name_of_ti(omf_obj, component->ti),
	// 				component->offset, component->REP8,
	// 				component->POS8,
	// 				component->n,
	// 				component->name);
	//
	// 			RzType *carg_type = TYPE_TI(omf_obj, component->ti);
	// 			RzCallableArg *cargs = rz_type_callable_arg_new(typedb, component->name, carg_type);
	// 			rz_type_callable_arg_add(callable, cargs);
	// 		}
	// 	}
	// }
	rz_type_func_save(typedb, callable);
	return callable;
}

static int line_sample_cmp(const void *a, const void *b, void *user) {
	const RzBinSourceLineSample *sa = a;
	const RzBinSourceLineSample *sb = b;
	// first, sort by addr
	if (sa->address < sb->address) {
		return -1;
	}
	if (sa->address > sb->address) {
		return 1;
	}
	// then sort by line
	if (sa->line < sb->line) {
		return -1;
	}
	if (sa->line > sb->line) {
		return 1;
	}
	// and eventually by file because this is the most exponsive operation
	if (!strlen(sa->file) && !strlen(sb->file)) {
		return 0;
	}
	if (!strlen(sa->file)) {
		return -1;
	}
	if (!strlen(sb->file)) {
		return 1;
	}
	return strcmp(sa->file, sb->file);
}

RZ_API bool rz_core_bin_apply_luac_debug(RzCore *core, RzBinFile *binfile) {
	rz_return_val_if_fail(core && binfile, false);

	const char *arch = rz_config_get(core->config, "asm.arch");
	if (!strstr(arch, "luac")) {
		return false;
	}

	RzBinObject *binobj = rz_bin_cur_object(core->bin);
	RzBinInfo *info = binobj ? binobj->info : NULL;
	if (!info) {
		return false;
	}
	if (!info->rclass) {
		return false;
	}
	if (strcmp(info->rclass, "luac")) {
		return false;
	}
	// rz_bin_omf166_obj *omf_obj = (rz_bin_omf166_obj *)binfile->o->bin_obj;
	LuacBinInfo *luac_obj = (LuacBinInfo *)binfile->o->bin_obj;
	luac_obj->typedb = core->analysis->typedb;

	// rz_type_db_purge(core->analysis->typedb);
	// char *types_dir = rz_path_system(core->sys_path, RZ_SDB_TYPES);
	// if (!types_dir) {
	// 	return false;
	// }
	// rz_type_db_reload(core->analysis->typedb, types_dir);
	// free(types_dir);

	(void)create_new_function;

	rz_pvector_sort(luac_obj->line_nums_vec, line_sample_cmp, NULL);

	if (!binfile->o->lines) {
		RzPVector *ls = luac_obj->line_nums_vec;
		void **lit;
		ut16 index = 0;

		binfile->o->lines = RZ_NEW0(RzBinSourceLineInfo);
		size_t lc = rz_pvector_len(luac_obj->line_nums_vec);
		binfile->o->lines->samples_count = lc;
		binfile->o->lines->samples = RZ_NEWS0(RzBinSourceLineSample, lc);

		rz_pvector_foreach (ls, lit) {
			RzBinSourceLineSample *line_num = (RzBinSourceLineSample *)*lit;
			RzBinSourceLineSample *sample = &binfile->o->lines->samples[index];
			sample->address = line_num->address;
			sample->line = line_num->line;
			sample->column = 0;
			sample->file = rz_str_dup(line_num->file);
			index++;
		}
		rz_str_constpool_init(&binfile->o->lines->filename_pool);
	}
	return true;
}
