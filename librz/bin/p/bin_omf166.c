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
	rz_bin_omf166_obj *omf_obj = (rz_bin_omf166_obj *)bf->o->bin_obj;
	if (bf->o->lines) {
		RzBinSourceLineInfo *lines = bf->o->lines;
		size_t sc = lines->samples_count;
		for (size_t i = 0; i < sc; i++) {
			RzBinSourceLineSample *sample = &lines->samples[i];
			RZ_FREE(sample->file);
		}
		RZ_FREE(lines->samples);
	}
	ht_up_free(omf_obj->ht_types);
	rz_bin_free_all_omf166_obj(omf_obj);
	RZ_FREE(omf_obj);
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
	addr->type = RZ_BIN_SPECIAL_SYMBOL_ENTRY;
	addr->vaddr = 0xC00000;
	rz_pvector_push(ret, addr);
	return ret;
}

static RzPVector /*<RzBinMap *>*/ *maps(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}

	rz_bin_omf166_obj *obj = bf->o->bin_obj;

	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	if (!ret) {
		return NULL;
	}

	RzBinMap *map = NULL;
	RzPVector *v = obj->pe_vec;
	void **it;
	rz_pvector_foreach (v, it) {
		OMF_pes *pe = (OMF_pes *)*it;

		if (!(map = RZ_NEW0(RzBinMap))) {
			rz_pvector_free(ret);
			return NULL;
		}
		map->paddr = pe->paddr;
		map->vaddr = (pe->SegmentNumber8 << 16) + pe->offset;
		map->psize = map->vsize = pe->size;
		map->perm = get_perm_by_type(pe->data_type);
		map->name = rz_str_dup(get_data_type(pe->data_type));
		rz_pvector_push(ret, map);
	}
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	RzPVector *ret;

	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}

	if (!(ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free))) {
		return NULL;
	}
	rz_bin_omf166_obj *obj = bf->o->bin_obj;

	RzPVector *v = obj->sections_vec;
	void **it;
	rz_pvector_foreach (v, it) {
		OMF_sections *section = (OMF_sections *)*it;

		RzBinSection *new = NULL;
		if (!(new = RZ_NEW0(RzBinSection))) {
			rz_pvector_free(ret);
			return NULL;
		}

		const char *name = NULL;
		OMF_lnames *lname = (OMF_lnames *)rz_pvector_at(obj->lnames_vec, section->index);
		name = RZ_STR_ISNOTEMPTY(lname->name) ? lname->name : "NONE";
		new->name = rz_str_dup(name);
		new->size = 64 * 1024;
		new->vsize = section->Seclen;
		new->vaddr = (section->SegmentNumber8 << 16) + section->offset;
		new->has_strings = false;
		new->is_data = (section->Type == 1);
		new->is_segment = 0;
		new->perm = get_perm_by_type(section->Type);
		rz_pvector_push(ret, new);
	}
	return ret;
}

static int offset_cmp(const void *a, const void *b, void *user) {
	const OMF_symbol *sa = a;
	const OMF_symbol *sb = b;
	// first, sort by addr
	if (sa->offset < sb->offset) {
		return -1;
	}
	if (sa->offset > sb->offset) {
		return 1;
	}
	return 0;
}

static RzPVector /*<RzBinSymbol *>*/ *symbols(RzBinFile *bf) {
	RzPVector *ret;
	RzBinSymbol *sym;

	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}

	rz_bin_omf166_obj *obj = bf->o->bin_obj;

	if (rz_pvector_len(obj->symbols_vec) < 1) {
		return NULL;
	}

	if (!(ret = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free))) {
		return NULL;
	}

	RzPVector *v = obj->symbols_vec;
	rz_pvector_sort(v, offset_cmp, NULL);
	void **it;
	rz_pvector_foreach (v, it) {
		OMF_symbol *p = (OMF_symbol *)*it;
		if (p->is_data)
			continue;
		if (!(sym = RZ_NEW0(RzBinSymbol))) {
			return ret;
		}
		// sym->name = (p->ti == 0x4B) ? rz_str_newf("label.%s", p->name2) : rz_str_dup(p->name2); ///< ?
		sym->name = rz_str_dup(p->name2); // ?
		sym->forwarder = "NONE"; // ?

		sym->paddr = p->offset; // ?
		sym->vaddr = p->base + p->offset;
		// sym->ordinal = ct_sym;
		sym->size = p->size;
		sym->is_imported = (p->ti == 0x004e);

		switch (p->rec_type) {
		case OMF166_GLBDEF:
			sym->bind = RZ_BIN_BIND_LOCAL_STR;
			sym->type = RZ_BIN_TYPE_FUNC_STR;
			break;
		case OMF166_LOCSYM:
		case OMF166_PUBDEF:
		default:
			sym->bind = RZ_BIN_BIND_UNKNOWN_STR;
			sym->type = RZ_BIN_TYPE_UNKNOWN_STR;
			break;
		}
		rz_pvector_push(ret, sym);
	}

	return ret;
}

static char *get_memory_model(ut8 modinfo) {
	ut8 MEMORY_MODEL = (modinfo & 0x1C) >> 2; ///< The three bit model specifier gives the memory model choosen on translation:
						  ///< 1: Tiny
						  ///< 2: Small
						  ///< 3: Compact
						  ///< 4: Medium
						  ///< 5: Large
						  ///< 6: HCompact
						  ///< 7: HLarge
						  ///< 8: XLarge
	switch (MEMORY_MODEL) {
	case 0x1: {
		return rz_str_dup("Tiny: program 64K or less");
		break;
	}
	case 0x2: {
		return rz_str_dup("Small: 'near' functions and data");
		break;
	}
	case 0x3: {
		return rz_str_dup("Compact: 'far' data, 'near' funcs");
		break;
	}
	case 0x4: {
		return rz_str_dup("Medium: 'near' data, 'far' funcs");
		break;
	}
	case 0x5: {
		return rz_str_dup("Large: 'far' functions and data");
		break;
	}
	case 0x6: {
		return rz_str_dup("HCompact: 'huge' data, 'near' funcs");
		break;
	}
	case 0x7: {
		return rz_str_dup("HLarge: 'huge' data, 'far' funcs");
		break;
	}
	case 0x0: {
		return rz_str_dup("XLarge: 'xhuge' data, 'far' funcs");
		break;
	}
	default:
		RZ_LOG_ERROR("Unknown MEMORY_MODEL: 0x%02x.\n", MEMORY_MODEL);
		return rz_str_dup("Unknown MEMORY_MODEL");
	}
}

static RzBinInfo *info(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	rz_bin_omf166_obj *obj = (rz_bin_omf166_obj *)bf->o->bin_obj;

	RzBinInfo *ret;
	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}

#ifdef RZ_BUILD_DEBUG
	RZ_LOG_DEBUG("OMF166_MODINF: 0x%02x\n", obj->modinfo);
	/*
	  7   6   5   4   3   2   1   0
	*********************************
	* D | F | x | m | m | m | C | M *
	*********************************
	  |   |   |               |   +----> [NON]SEGMENTED
	  |   |   |   \----+---/  +--------> [NO]CASE
	  |   |   |        +---------------> MEMORY MODEL
	  |   |   +------------------------> MOD167
	  |   +----------------------------> FLOAT-USED
	  +--------------------------------> DOUB
	*/
	bool DOUBLE_USED = obj->modinfo >> 7; ///< The module contains double precision float operations. This bit is intended for the linker for automatic selection of libraries.
	bool FLOAT_USED = (obj->modinfo & 0x40) >> 6; ///< The module contains single precision float operations. This bit is intended for the linker for automatic selection of libraries.
	bool MOD167 = (obj->modinfo & 0x20) >> 5; ///< If bit is set, then the module is intended to be executed on an 80C167 CPU, otherwise the module is for a 80C166 CPU.
	bool CASE = (obj->modinfo & 0x02) >> 1; ///< If bit is set, then names are to be considered case sensitive. This info is intended for the linker when combining object modules.
	bool SEGMENTED = (obj->modinfo & 0x01); ///< If bit is set, then the segmented cpu mode was choosen for the module.

	if (DOUBLE_USED)
		RZ_LOG_DEBUG("The module contains double precision float operations. This bit is intended for the linker for automatic selection of libraries.\n");
	if (FLOAT_USED)
		RZ_LOG_DEBUG("The module contains single precision float operations. This bit is intended for the linker for automatic selection of libraries.\n");
	if (MOD167)
		RZ_LOG_DEBUG("If bit is set, then the module is intended to be executed on an 80C167 CPU, otherwise the module is for a 80C166 CPU.\n");
	if (CASE)
		RZ_LOG_DEBUG("If bit is set, then names are to be considered case sensitive. This info is intended for the linker when combining object modules.\n");
	if (SEGMENTED)
		RZ_LOG_DEBUG("If bit is set, then the segmented cpu mode was choosen for the module.\n");
#endif

	ret->type = get_memory_model(obj->modinfo);
	ret->file = rz_str_dup(bf->file);
	ret->bclass = rz_str_dup("OMF (Object Module Format)");
	ret->rclass = rz_str_dup("OMF166");

	ret->compiler = rz_str_dup("keil");
	ret->os = rz_str_dup("c166");
	ret->machine = rz_str_dup("c166");
	ret->arch = rz_str_dup("c166");
	ret->big_endian = false;
	ret->has_va = true;
	ret->bits = 16;
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

static RzBinAddr *binsym(RzBinFile *bf, RzBinSpecialSymbol type) {
	RzBinAddr *ptr = NULL;

	switch (type) {
	case RZ_BIN_SPECIAL_SYMBOL_ENTRY:
		// entrypoint is always RESET vector (0xC00000)
		if (!(ptr = RZ_NEW0(RzBinAddr))) {
			RZ_FREE(ptr);
			return NULL;
		}
		ptr->type = RZ_BIN_SPECIAL_SYMBOL_ENTRY;
		ptr->vaddr = 0xC00000;
		return ptr;
	case RZ_BIN_SPECIAL_SYMBOL_MAIN:
		if (!(ptr = RZ_NEW0(RzBinAddr))) {
			return NULL;
		}
		if (!rz_bin_omf166_get_entry(bf->o->bin_obj, ptr)) {
			RZ_FREE(ptr);
			return NULL;
		}
		ptr->type = RZ_BIN_SPECIAL_SYMBOL_MAIN;
		return ptr;
	default:
		return NULL;
	}
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
	.binsym = &binsym,
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
