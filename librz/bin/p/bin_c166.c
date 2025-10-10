// SPDX-FileCopyrightText: 2023 Jairus Martin <frmdstryr@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_bin.h>

/**
 * \brief Check for some chars in array
 *
 * Modified from one in analysis_riscv
 * First arg is checked against all others
 * */
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

/**
 * \brief Check if file starts with a vector table
 * */
static bool is_c166_vector_table(RzBuffer *buf) {
	if (rz_buf_size(buf) < 64)
		return false;
	ut8 c = 0;
	ut8 i = 0;
	while (i < 64) {
		if (!rz_buf_read8_at(buf, i, &c) || c != 0xFA) {
			return false; // Not a jmp
		}
		i += 4;
	}
	return true;
}

// Look for p....C166 or p....A166
static bool is_c166_header(RzBuffer *buf) {
	if (rz_buf_size(buf) < 64)
		return false;
	ut8 c = 0;
	if (!rz_buf_read8_at(buf, 0, &c) || c != 'p')
		return false;
	ut8 in[5];
	if (!rz_buf_read_at(buf, 5, in, sizeof(in)) || !is_any_n((const char *)in, sizeof(in), "C166 ", "A166 ")) {
		return false;
	}

	return true;
}

static bool check_buffer(RzBuffer *buf) {
	(void)is_c166_vector_table;
	// if (is_c166_vector_table(buf))
	// 	return true;
	if (is_c166_header(buf))
		return true;
	return false;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	return check_buffer(buf);
}

static void destroy(RzBinFile *bf) {
	rz_buf_free(bf->o->bin_obj);
	bf->o->bin_obj = NULL;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	RzPVector *ret = NULL;

	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}

	if (!(ret = rz_pvector_new(NULL))) {
		return NULL;
	}

	RzBinSection *ptr = NULL;
	// RzBuffer *obj = bf->o->bin_obj;

	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}

	ptr->name = strdup("vectors");
	ptr->size = 0x1FF;
	ptr->vsize = ptr->size;
	ptr->paddr = 0;
	ptr->vaddr = 0;
	ptr->perm = RZ_PERM_R; // r--
	rz_pvector_push(ret, ptr);

	ut64 offset = 0;
	ut8 segment = 0;
	if (bf->size > 0) {
		while (offset < bf->size && segment < 255) {
			if (!(ptr = RZ_NEW0(RzBinSection))) {
				return ret;
			}

			ptr->name = rz_str_newf("seg_%d", segment);
			ptr->size = 0x10000;
			ptr->vsize = ptr->size;
			ptr->paddr = offset;
			ptr->vaddr = offset;
			ptr->perm = RZ_PERM_RWX;
			rz_pvector_push(ret, ptr);
			segment += 1;
			offset += 0x10000;
		}
	}

	return ret;
}

static RzBinInfo *info(RzBinFile *arch) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret)
		return NULL;

	if (!arch || !arch->buf) {
		free(ret);
		return NULL;
	}
	ret->file = strdup(arch->file);
	ret->type = strdup("ROM");
	ret->machine = strdup("Siemens/Infineon C166 family microcontroller");
	ret->os = strdup("c166");
	ret->arch = strdup("c166");
	ret->bits = 16;
	ret->rclass = "keil";

	return ret;
}

static RzPVector /*<RzBinString *>*/ *strings(RzBinFile *bf) {
	// we dont want to find strings in c166 bins because there are lot of false positives
	return rz_pvector_new((RzPVectorFree)rz_bin_string_free);
}

struct rz_bin_plugin_t rz_bin_plugin_c166 = {
	.name = "c166",
	.desc = "Siemens/Infineon C166 family microcontroller binary",
	.license = "LGPL3",
	.get_sdb = NULL,
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = NULL,
	.entries = NULL,
	.sections = &sections,
	.info = &info,
	.strings = &strings,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_c166,
	.version = RZ_VERSION
};
#endif
