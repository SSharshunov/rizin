// SPDX-FileCopyrightText: 2015-2019 ampotos <mercie_i@epitech.eu>
// SPDX-FileCopyrightText: 2015-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2025 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include "omf/omf.h"

// Modified from one in analysis_riscv
// First arg is checked against all others
#define is_any_n(...) _is_any_n(__VA_ARGS__, NULL)
static bool _is_any_n(const char *str, size_t n, ...) {
	char *cur;
	va_list va;
	va_start(va, n);
	while (true) {
		cur = va_arg(va, char *);
		if (!cur) {
			break;
		}
		if (!strncmp(str, cur, n)) {
			va_end(va);
			return true;
		}
	}
	va_end(va);
	return false;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb) {
	ut64 size;
	const ut8 *buf = rz_buf_data(b, &size);
	rz_return_val_if_fail(buf, false);

	obj->bin_obj = rz_bin_internal_omf166_load(buf, size);
	rz_return_val_if_fail(obj->bin_obj, false);
	return true;
}

static void destroy(RzBinFile *bf) {
	rz_bin_free_all_omf_obj(bf->o->bin_obj);
	bf->o->bin_obj = NULL;
}

static bool check_buffer(RzBuffer *b) {
	ut8 ch;
	if (rz_buf_read_at(b, 0, &ch, 1) != 1) {
		return false;
	}
	if (ch != 0x70 && ch != 0x72) {
		return false;
	}

	ut16 rec_size;
	if (!rz_buf_read_le16_at(b, 1, &rec_size)) {
		return false;
	}

	// ut8 str_size;
	// (void)rz_buf_read_at(b, 3, &str_size, 1);
	ut64 length = rz_buf_size(b);
	if (length < rec_size + 3) {
		return false;
	}

	ut8 in[5];
	if (!rz_buf_read_at(b, 5, in, sizeof(in)) || !is_any_n((const char *)in, sizeof(in), "C166 ", "A166 ")) {
		return false;
	}
	ut64 size;
	const ut8 *buf = rz_buf_data(b, &size);
	if (buf == NULL) {
		// hackaround until we make this plugin not use RBuf.data
		ut8 buf[1024] = RZ_EMPTY;
		rz_buf_read_at(b, 0, buf, sizeof(buf));
		return rz_bin_checksum_omf_ok(buf, sizeof(buf));
	}
	rz_return_val_if_fail(buf, false);
	return rz_bin_checksum_omf_ok(buf, length);
}

static ut64 baddr(RzBinFile *bf) {
	return OMF166_BASE_ADDR;
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	RzPVector *ret;
	RzBinAddr *addr;

	if (!(ret = rz_pvector_new(free))) {
		return NULL;
	}
	if (!(addr = RZ_NEW0(RzBinAddr))) {
		rz_pvector_free(ret);
		return NULL;
	}
	if (!rz_bin_omf166_get_entry(bf->o->bin_obj, addr)) {
		RZ_FREE(addr);
	} else {
		rz_pvector_push(ret, addr);
	}
	return ret;
}

// static int append_section(RzPVector *vec, const char *name, ut32 vaddr, ut32 size, OMF_data *data) {
// 	RzBinSection *new;
// 	if (!(new = RZ_NEW0(RzBinSection))) {
// 		return false;
// 	}

// 	new->name = rz_str_dup(name);
// 	new->size = size;
// 	new->vsize = size;
// 	new->paddr = data->paddr;
// 	new->vaddr = vaddr;
// 	new->has_strings = true;
// 	new->is_data = data->is_data;
// 	new->is_segment = data->is_segment;
// 	// new->perm = data->perm;
// 	rz_pvector_push(vec, new);
// 	return true;
// }

static RzPVector /*<RzBinMap *>*/ *maps(RzBinFile *bf) {
	printf("==============maps\n");
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	if (!ret) {
		return NULL;
	}

	RzBinMap *map = RZ_NEW0(RzBinMap);
	if (!map) {
		rz_pvector_free(ret);
		return NULL;
	}

	ut32 ct_omf_pe = 0;
	rz_bin_omf_obj *obj = bf->o->bin_obj;

	while (ct_omf_pe < obj->nb_pedata) {
		OMF_pedata *pedata = obj->pedata[ct_omf_pe];
		OMF_data *data = (OMF_data *)pedata->data;

		if (!(map = RZ_NEW0(RzBinMap))) {
			rz_pvector_free(ret);
			return NULL;
		}

		map->paddr = data->paddr;
		map->vaddr = (data->seg_idx << 16) + data->offset;
		map->psize = pedata->size;
		map->vsize = pedata->size;
		map->perm = RZ_PERM_RW;
		map->name = rz_str_dup("CODE");
		rz_pvector_push(ret, map);

#ifdef X_DEBUG
		printf("ct_omf_pe: %04d pedata->name_idx: 0x%04x pedata->vaddr: 0x%08x `%s`\n", ct_omf_pe, pedata->name_idx, (data->seg_idx << 16) + data->offset, name);
#endif
		ct_omf_pe++;
		// (void)append_section;
		// append_section(ret, obj->names[],      0x00000, 0x00000, 0x0F000);
	}
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	RzPVector *ret;

	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}

	if (!(ret = rz_pvector_new(NULL))) {
		return NULL;
	}

	ut32 ct_omf_sect = 0;
	rz_bin_omf_obj *obj = bf->o->bin_obj;
	const char *name = NULL;
	while (ct_omf_sect < obj->nb_section) {
		OMF_segment *section = obj->sections[ct_omf_sect];
		if (section->name_idx < obj->nb_name) {
			name = obj->names[section->name_idx] ? obj->names[section->name_idx] : "NONE";
		} else {
			name = "no_name";
		}

		OMF_data *data = (OMF_data *)section->data;

		RzBinSection *new;
		if (!(new = RZ_NEW0(RzBinSection))) {
			return NULL;
		}

		ut32 perm = (section->type == 0x2) ? RZ_PERM_RX : RZ_PERM_R;
		new->name = rz_str_dup(name);
		new->size = section->size;
		new->vsize = section->size; // section->vaddr + data->offset + OMF166_BASE_ADDR; //section->sizepedata->vaddr + data->offset + OMF166_BASE_ADDR; // 0x10000;;
		new->paddr = data->paddr;
		new->vaddr = (data->seg_idx << 16) + data->offset; // section->vaddr;
		new->has_strings = true;
		new->is_data = data->is_data;
		new->is_segment = data->is_segment;
		new->perm = perm;
		rz_pvector_push(ret, new);

		printf("ct_omf_sect: %04d section->name_idx: 0x%04x section->vaddr: 0x%08llx `%s`\n",
			ct_omf_sect, section->name_idx, new->vaddr, name);
#ifdef X_DEBUG
#endif
		ct_omf_sect++;
		// append_section(ret, obj->names[],      0x00000, 0x00000, 0x0F000);
	}
	return ret;
}

// static void append_symbol(RzPVector *vec, int ct_sym, const char *name, ut32 addr) {
// 	RzBinSymbol *sym;
// 	if (!(sym = RZ_NEW0(RzBinSymbol))) {
// 		return;
// 	}
// 	sym->name = rz_str_dup(name);
// 	sym->forwarder = "NONE";
// 	sym->paddr = addr;
// 	sym->vaddr = addr;
// 	printf("sym_omf->name: `%s`, ct_sym: %d, sym->paddr: 0x%04x, sym->vaddr: 0x%04x\n",
// 		name,
// 		ct_sym,
// 		addr,
// 		addr);
// 	sym->ordinal = ct_sym;
// 	sym->size = 0;
// 	rz_pvector_push(vec, sym);
// 	return;
// }

static RzPVector /*<RzBinSymbol *>*/ *symbols(RzBinFile *bf) {
	RzPVector *ret;
	RzBinSymbol *sym;
	OMF_symbol *sym_omf;
	int ct_sym = 0;
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	if (!(ret = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free))) {
		return NULL;
	}

	while (ct_sym < ((rz_bin_omf_obj *)bf->o->bin_obj)->nb_symbol) {
		if (!(sym = RZ_NEW0(RzBinSymbol))) {
			return ret;
		}
		sym_omf = ((rz_bin_omf_obj *)bf->o->bin_obj)->symbols[ct_sym++];
		sym->name = rz_str_dup(sym_omf->name);
		sym->forwarder = "NONE";
		// sym->paddr = rz_bin_omf166_get_paddr_sym(bf->o->bin_obj, sym_omf);
		sym->paddr = sym_omf->offset;
		// sym->vaddr = rz_bin_omf166_get_vaddr_sym(bf->o->bin_obj, sym_omf);
		sym->vaddr = sym_omf->offset;
		sym->ordinal = ct_sym;
		sym->size = 0;
		rz_pvector_push(ret, sym);
	}
	// (void)append_symbol;
	return ret;
}

static RzBinInfo *info(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	rz_bin_omf_obj *obj = (rz_bin_omf_obj *)bf->o->bin_obj;
	rz_return_val_if_fail(obj->records, NULL);

	RzBinInfo *ret;
	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}

	RZ_LOG_INFO("OMF166_MODINF: 0x%02x\n", obj->modinfo);

	bool DOUBLE_USED = obj->modinfo >> 7; ///< The module contains double precision float operations. This bit is intended for the linker for automatic selection of libraries.
	bool FLOAT_USED = (obj->modinfo & 0x40) >> 6; ///< The module contains single precision float operations. This bit is intended for the linker for automatic selection of libraries.
	bool MOD167 = (obj->modinfo & 0x20) >> 5; ///< If bit is set, then the module is intended to be executed on an 80C167 CPU, otherwise the module is for a 80C166 CPU.
	ut8 MEMORY_MODEL = (obj->modinfo & 0x1C) >> 2; ///< The three bit model specifier gives the memory model choosen on translation:
						       ///< 1: Tiny
						       ///< 2: Small
						       ///< 3: Compact
						       ///< 4: Medium
						       ///< 5: Large
						       ///< 6: HCompact
						       ///< 7: HLarge
						       ///< 8: XLarge
	bool CASE = (obj->modinfo & 0x02) >> 1; ///< If bit is set, then names are to be considered case sensitive. This info is intended for the linker when combining object modules.
	bool SEGMENTED = (obj->modinfo & 0x01); ///< If bit is set, then the segmented cpu mode was choosen for the module.

	if (DOUBLE_USED)
		RZ_LOG_INFO("The module contains double precision float operations. This bit is intended for the linker for automatic selection of libraries.\n");
	if (FLOAT_USED)
		RZ_LOG_INFO("The module contains single precision float operations. This bit is intended for the linker for automatic selection of libraries.\n");
	if (MOD167)
		RZ_LOG_INFO("If bit is set, then the module is intended to be executed on an 80C167 CPU, otherwise the module is for a 80C166 CPU.\n");
	if (CASE)
		RZ_LOG_INFO("If bit is set, then names are to be considered case sensitive. This info is intended for the linker when combining object modules.\n");
	if (SEGMENTED)
		RZ_LOG_INFO("If bit is set, then the segmented cpu mode was choosen for the module.\n");

	switch (MEMORY_MODEL) {
	case 0x1: {
		ret->type = "Tiny: program 64K or less";
		break;
	}
	case 0x2: {
		ret->type = "Small: 'near' functions and data";
		break;
	}
	case 0x3: {
		ret->type = "Compact: 'far' data, 'near' funcs";
		break;
	}
	case 0x4: {
		ret->type = "Medium: 'near' data, 'far' funcs";
		break;
	}
	case 0x5: {
		ret->type = "Large: 'far' functions and data";
		break;
	}
	case 0x6: {
		ret->type = "HCompact: 'huge' data, 'near' funcs";
		break;
	}
	case 0x7: {
		ret->type = "HLarge: 'huge' data, 'far' funcs";
		break;
	}
	case 0x0: {
		ret->type = "XLarge: 'xhuge' data, 'far' funcs";
		break;
	}
	default:
		ret->type = "Unknown MEMORY_MODEL";
		RZ_LOG_ERROR("Unknown MEMORY_MODEL: 0x%02x.\n", MEMORY_MODEL);
		// rz_warn_if_reached();
		return NULL;
	}

	ret->file = rz_str_dup(bf->file);
	ret->bclass = rz_str_dup("OMF (Object Module Format)");
	ret->rclass = rz_str_dup("OMF166");

	ret->compiler = "keil";
	ret->os = rz_str_dup("c166");
	ret->machine = rz_str_dup("c166");
	ret->arch = rz_str_dup("c166");
	ret->big_endian = false;
	ret->has_va = true;
	ret->bits = 16; // rz_bin_omf_get_bits(bf->o->bin_obj);
	ret->dbg_info = 0;
	ret->has_nx = false;
	return ret;
}

static ut64 get_vaddr(RzBinFile *bf, ut64 baddr, ut64 paddr, ut64 vaddr) {
	return vaddr;
}

static RzPVector /*<RzBinString *>*/ *strings(RzBinFile *bf) {
	RzBinStringSearchOpt opt;
	rz_bin_string_search_opt_init(&opt);
	opt.mode = RZ_BIN_STRING_SEARCH_MODE_READ_ONLY_SECTIONS;
	opt.string_encoding = RZ_STRING_ENC_UTF8;
	return rz_bin_file_strings(bf, &opt);
}

RzBinPlugin rz_bin_plugin_omf166 = {
	.name = "omf166",
	.desc = "OMF166 (Object Module Format by Siemens)",
	.license = "LGPL3",
	.author = "SSharshunov",
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.entries = &entries,
	.maps = &maps,
	.sections = &sections,
	.symbols = &symbols,
	.info = &info,
	.strings = &strings,
	.get_vaddr = &get_vaddr,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_omf166,
	.version = RZ_VERSION
};
#endif
