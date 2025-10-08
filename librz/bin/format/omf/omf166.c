// SPDX-FileCopyrightText: 2015 ampotos <mercie_i@epitech.eu>
// SPDX-FileCopyrightText: 2015-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2025 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "omf.h"

int TI_INDEX = 0;
int SEC_INDEX = 0;
int PE_INDEX = 0;

#if RZ_BUILD_DEBUG
static const char *perm_names[] = {
	[0] = "RZ_PERM_UNKNOWN",
	[RZ_PERM_R] = "RZ_PERM_R",
	[RZ_PERM_W] = "RZ_PERM_W",
	[RZ_PERM_X] = "RZ_PERM_X",
	[RZ_PERM_RW] = "RZ_PERM_RW",
	[RZ_PERM_RX] = "RZ_PERM_RX",
	[RZ_PERM_RWX] = "RZ_PERM_RWX",
	[RZ_PERM_WX] = "RZ_PERM_WX",
};
#endif

ut64 rz_bin_omf166_get_abs_addr(ut8 SegmentNumber8, ut16 Offset) {
	ut64 offset = 0;
	offset = (SegmentNumber8 << 16) | Offset;
	return offset;
}

static bool is_valid_omf166_type(ut8 type) {
	int ct = 0;
	ut8 types[] = {
		OMF166_RTXDEF, OMF166_DEPLST, OMF166_REGMSK, OMF166_TYPNEW,
		OMF166_BLKEND, OMF166_THEADR, OMF166_LHEADR, OMF166_COMMENT,
		OMF166_MODEND, OMF166_LINNUM, OMF166_LNAMES, OMF166_LIBLOC,
		OMF166_LIBNAMES, OMF166_LIBDICT, OMF166_LIBHDR, OMF166_PHEADR,
		OMF166_PECDEF, OMF166_SSKDEF, OMF166_MODINF, OMF166_TSKDEF,
		OMF166_REGDEF, OMF166_SECDEF, OMF166_TYPDEF, OMF166_GRPDEF,
		OMF166_PUBDEF, OMF166_GLBDEF, OMF166_EXTDEF, OMF166_LOCSYM,
		OMF166_BLKDEF, OMF166_DEBSYM, OMF166_LEDATA, OMF166_PEDATA,
		OMF166_VECTAB, OMF166_FIXUPP, OMF166_TSKEND, OMF166_XSECDEF,
		OMF166_ERROR1, OMF166_ERROR2, OMF166_ERROR3, OMF166_ERROR4,
		OMF166_ERROR5, OMF166_ERROR6, OMF166_ERROR7, OMF166_ERROR8,
		OMF166_ERROR9, 0
	};
	for (; types[ct]; ct++) {
		if (type == types[ct]) {
			return true;
		}
	}
	RZ_LOG_ERROR("Invalid record type: 0x%02x\n", type);
	return false;
}

void print_bytes(const unsigned char *array, size_t length) {
    printf("[%ld] ", length);
	for (int i = 0; i < length; i++) {
        // Print each char as an unsigned hexadecimal byte
        printf("0x%02x ", (unsigned char)array[i]);
    }
    printf("\n");
}

bool rz_bin_checksum_omf166_ok(const ut8 *buf, ut64 buf_size) {
	ut16 size;
	ut8 checksum = 0;

	if (buf_size < 3) {
		RZ_LOG_ERROR("Invalid record (too short)\n");
		return false;
	}
	size = rz_read_le16(buf + 1);
	if (buf_size < size + 3) {
		RZ_LOG_ERROR("Invalid record (too short)\n");
		return false;
	}
	// Some compiler set checksum to 0
	if (!buf[size + 2]) {
		return true;
	}
	size += 3;
	for (; size; size--) {
		if (buf_size < size) {
			RZ_LOG_ERROR("Invalid record (too short)\n");
			return false;
		}
		checksum += buf[size - 1];
	}
	if (checksum) {
		RZ_LOG_ERROR("Invalid record checksum\n");
	}
	return !checksum ? true : false;
}

static ut16 omf166_get_idx(const ut8 *buf, int buf_size) {
	if (buf_size < 2) {
		return 0;
	}
	if (*buf & 0x80) {
		return (ut16)((*buf & 0x7f) * 0x100 + buf[1]);
	}
	return *buf;
}

static bool load_omf166_lnames(OMF_record *record, const ut8 *buf, ut64 buf_size, ut64 global_ct) {
	ut32 tmp_size = 0;
	ut32 ct_name = 0;
	OMF_multi_datas *ret = NULL;
	char **names;
	if (!record || !buf) {
		return false;
	}

	if (!(ret = RZ_NEW0(OMF_multi_datas))) {
		return false;
	}
	record->content = ret;

	while ((int)tmp_size < (int)(record->size - 1)) {
		int next;
		ret->nb_elem++;
		next = buf[3 + tmp_size] + 1;
		if (next < 1) {
			break;
		}
		tmp_size += next;
	}
	if (!(ret->elems = RZ_NEWS0(char *, ret->nb_elem + 1))) {
		RZ_FREE(ret);
		return false;
	}
	names = (char **)ret->elems;
	tmp_size = 0;
	while ((int)tmp_size < (int)(record->size - 1)) {
		if (ct_name >= ret->nb_elem) {
			RZ_LOG_ERROR("Invalid number of element (overflow)\n");
			break;
		}
		// sometimes there is a name with a null size so we just skip it
		char cb = buf[3 + tmp_size];
		if (cb < 1) {
			names[ct_name++] = NULL;
			tmp_size++;
			continue;
		}
		if (record->size + 3 < tmp_size + cb) {
			RZ_LOG_ERROR("Invalid Lnames record (bad size)\n");
			free(ret);
			return false;
		}
		if (!(names[ct_name] = RZ_NEWS0(char, cb + 1))) {
			free_lname(ret);
			return false;
		}
		if ((tmp_size + 4 + cb) < buf_size) {
			memcpy(names[ct_name], buf + 3 + tmp_size + 1, cb);
		}
#ifdef X_DEBUG
		printf("LNAMES ct_name: %03d, `%s`\n", ct_name, names[ct_name]);
#endif
		ct_name++;
		tmp_size += cb + 1; // buf[3 + tmp_size] + 1;

	}
#ifdef X_DEBUG
		printf("=========================> load_omf = LNAMES  =  [%05d] [0x%08llx] 0x%02x (%lld)\t", record->size, global_ct, record->type, buf_size);
		print_bytes(buf, record->size+3);
#endif
	return true;
}


static int load_omf166_symb(OMF_record *record, ut32 ct, const ut8 *buf, int buf_size, int bits, ut16 seg_idx) {
	ut32 nb_symb = 0;
	ut8 str_size = 0;
	OMF_symbol *symbol;
	// printf("+++++++++++++++++++++++++++++++++++++++++++++++++\n");
	ut32 lct = ct;

	while (nb_symb < ((OMF_multi_datas *)record->content)->nb_elem) {
		symbol = ((OMF_symbol *)((OMF_multi_datas *)record->content)->elems) + nb_symb;

		// printf("load_omf166_symb - nb_symb: %u, ct: %u, buf_size: %u, seg_idx: %u\n",
		// 	nb_symb, ct, buf_size, seg_idx);

		// if (record->size - 1 < ct - 2) {
		// 	RZ_LOG_ERROR("%d: Invalid Pubdef record (bad size)\n", __LINE__);
		// 	return false;
		// }

		str_size = buf[lct];
		// if (bits == 32) {
		// 	if (ct + 1 + str_size + 4 - 3 > record->size) {
		// 		RZ_LOG_ERROR("%d: Invalid Pubdef record (bad size)\n", __LINE__);
		// 		return false;
		// 	}
		// 	symbol->offset = rz_read_le32(buf + ct + 1 + str_size);
		// } else {
			// if (ct + 1 + str_size + 2 - 3 > record->size) {
			// 	RZ_LOG_ERROR("%d: Invalid Pubdef record (bad size)\n", __LINE__);
			// 	return false;
			// }
		// }

		symbol->seg_idx = seg_idx;

		if (!(symbol->name = RZ_NEWS0(char, str_size + 1))) {
			printf("======================!symbol->name\n");
			return false;
		}
		symbol->name[str_size] = 0;
		memcpy(symbol->name, buf + lct + 1, sizeof(char) * str_size);

		// symbol->offset = 0xC00000 + rz_read_le16(buf + lct + 1 + str_size);
		symbol->offset = (seg_idx << 16) + rz_read_le16(buf + lct + 1 + str_size);
		// printf("load_omf166_symb %s\n", symbol->name);
		printf("ct: %d, str_size: %d, symbol->offset: 0x%04x \n", lct, str_size, symbol->offset);
#ifdef X_DEBUG
#endif

		lct += 1 + str_size + (bits == 32 ? 4 : 2);
		if (lct >= buf_size) {
			printf("======================lct >= buf_size\n");
			return false;
		}
		// if (buf[lct] & 0x80) { // type index
		// 	lct += 2;
		// } else {
		// 	lct++;
		// }
		lct += 3;
		nb_symb++;
	}
#ifdef X_DEBUG
	printf("\n");
#endif
	return true;
}

static int load_omf166_global_sym_record(OMF_record *record, const ut8 *buf, int buf_size, ut64 global_ct) {

	const char *rec_name = NULL;
	if (record->type == OMF166_LOCSYM) rec_name = "LOCSYM";
	if (record->type == OMF166_PUBDEF) rec_name = "PUBDEF";
	if (record->type == OMF166_GLBDEF) rec_name = "GLBDEF";
	printf("\nload_omf = %s  =  [%05d] [0x%08llx] 0x%02x (%d)\n", rec_name, record->size, global_ct, record->type, buf_size);
#ifdef X_DEBUG

#endif
	OMF_multi_datas *ret = NULL;
	ut16 ct = 3;


	if (!(ret = RZ_NEW0(OMF_multi_datas))) {
		return false;
	}
#if 0
	ut16 seg_idx = rz_read_le32(buf + 5);;
	ut32 base = rz_read_le32(buf + ct);
#else
	ut16 seg_idx = omf166_get_idx(buf + 5, buf_size - 5);
	ut16 base = omf166_get_idx(buf + ct, buf_size - ct);
#endif
	ct += 4;
	while(record->size > ct) {
		// printf("=========================> load_omf = GLBDEF  = ct: %d, offset: [0x%08x]\n", ct, offset);
		int n = buf[ct];
		ct++;
		char name[255] = {0};
		rz_str_ncpy(name, (const char *)&buf[ct], n + 1);
		ct += n;
		ut16 Ofs16 = rz_read_le16(buf + ct);
		ct += 2;
		ut8 Rep8 = rz_read_le8(buf + ct);
		ct++;
		ut16 TI = rz_read_le16(buf + ct);
		ct += 2;

		ret->nb_elem++;
		printf("\t ct: %d, seg_idx: [0x%08x] base: [0x%08x] Ofs16:[0x%04x] Rep8:[0x%02x] TI:[0x%04x] (%d)`%s`\n",
			ct, seg_idx, base, Ofs16, Rep8, TI, n, name);
#ifdef X_DEBUG

#endif
	}

	record->content = ret;
	print_bytes(buf, record->size+3);
	printf("=== load_omf166_pubdef ret->nb_elem: %d\n", ret->nb_elem);
#ifdef X_DEBUG
#endif
		if (ret->nb_elem > 0) {
			if (!(ret->elems = RZ_NEWS0(OMF_symbol, ret->nb_elem))) {
				return false;
			}
		}
		if (!load_omf166_symb(record, 7, buf, buf_size, 16, seg_idx)) {
			return false;
		}
	return true;
}

static int load_omf_data(const ut8 *buf, int buf_size, OMF_record *record, ut64 global_ct) {
	ut16 seg_idx;
	ut32 offset;
	ut16 ct = 4;
	OMF_data *ret;

	if ((!(record->type & 1) && record->size < 4) || (record->size < 6)) {
		RZ_LOG_ERROR("Invalid Ledata record (bad size)\n");
		return false;
	}
	seg_idx = omf166_get_idx(buf + 3, buf_size - 3);
	if (seg_idx & 0xff00) {
		if ((!(record->type & 1) && record->size < 5) || (record->size < 7)) {
			RZ_LOG_ERROR("Invalid Ledata record (bad size)\n");
			return false;
		}
		ct++;
	}
	// if (record->type == OMF_LEDATA32) {
	// 	offset = rz_read_le32(buf + ct);
	// 	ct += 4;
	// } else {
		offset = rz_read_le16(buf + ct);
		ct += 2;
	// }
	if (!(ret = RZ_NEW0(OMF_data))) {
		return false;
	}
	record->content = ret;

	ret->size = record->size - 1 - (ct - 3);
	ret->paddr = global_ct + ct;
	ret->offset = offset;
	ret->seg_idx = seg_idx;
	ret->next = NULL;
	record->type = OMF166_LEDATA;

#ifdef X_DEBUG
	printf("=========================> load_omf = LEDATA  =  [%05d] [0x%08llx] 0x%02x (%d)\t", record->size, global_ct, record->type, buf_size);
	print_bytes(buf, record->size+3);
#endif

	return true;
}

static int load_omf_blkdef(const ut8 *buf, int buf_size, OMF_record *record, ut64 global_ct) {
	ut16 seg_idx = 0x00;
	// ut32 offset;
	ut16 ct = 3;
	OMF_data *ret;

	ut8 GroupIndex = 0x00;
 	ut8 SectionIndex = 0x00;
	// ut8 FrameNumber = 0x00;
	ut16 page_idx = 0x00;

	// if ((!(record->type & 1) && record->size < 4) || (record->size < 6)) {
	// 	RZ_LOG_ERROR("Invalid Ledata record (bad size)\n");
	// 	return false;
	// }
	// ct++;
	GroupIndex = omf166_get_idx(buf + ct, buf_size - ct); // ct = 3
	ct++;
	SectionIndex = omf166_get_idx(buf + ct, buf_size - ct); // ct = 4

	ct++;
	ut16 FrameNumber = rz_read_le16(buf + ct); // ct = 5
	// ut16 FrameNumber = omf166_get_idx(buf + ct, buf_size - ct);
	if (!GroupIndex && !SectionIndex) {
		ct += 2;
	}
	// ut8 FrameNumber = rz_read_le16(buf + 5);
	if ((FrameNumber & 0x8000) != 0) {
		page_idx = FrameNumber; (void)page_idx;
	} else {
		seg_idx = FrameNumber;
	}

	// ct++;

	char name[255*3] = {0};
	// const char *name = rz_strdup(buf[14]);
	ut8 n = buf[ct]; // ct = 7
	ct++;
	rz_str_ncpy(name, (const char *)&buf[ct], n + 1); // ct = 8

	// rz_str_ncpy(&name, &buf[ct++], n + 1 + 1); // ct = 8
	ct++;

	ct += n;
	ut16 BlockOffset16 = rz_read_le16(buf + ct); // ct = 5
	ct += 2;
	ut16 BlockLength16 = rz_read_le16(buf + ct); // ct = 5

	ct++;
	bool PInfoProcedure = (buf[ct] & 0x80);

	ct += 3;
	ut16 TI = rz_read_le16(buf + ct);
	// ut16 TI = omf166_get_idx(buf + ct, buf_size - ct);

// printf("\nload_omf = BLKDEF  =  [%05ld] [0x%08llx] 0x%02x (%d)\n",
// 		record->size, global_ct, record->type, buf_size);
#ifdef X_DEBUG
	printf("BLKDEF [0x%08llx], 0x%02x   0x%02x 0x%02x  GroupIndex: 0x%02x SectionIndex: 0x%02x FrameNumber: 0x%04x (%s), (%d) name: `%s` (%d) BlockOffset16: 0x%04x BlockLength16: 0x%04x (%d), %s, TI: 0x%04x\t",
		global_ct, buf[0], buf[1], buf[2], GroupIndex, SectionIndex,
		FrameNumber, ((FrameNumber & 0x8000) != 0) ? "PAGE Number" : "SEGMENT Number", n, name, record->size-7-n-1, BlockOffset16, BlockLength16, BlockLength16, PInfoProcedure ? "fP" : "nP", TI);
	print_bytes(buf+7+n+1, record->size-7+3-n-1);
	printf("\n");

#endif

#if RZ_BUILD_DEBUG
#endif

	if (!(ret = RZ_NEW0(OMF_data))) {
		return false;
	}
	record->content = ret;

	ret->size = record->size - 1 - (ct - 3);
	ret->paddr = global_ct + ct;
	ret->offset = BlockOffset16;
	ret->seg_idx = seg_idx;
	ret->next = NULL;
	record->type = OMF166_BLKDEF;
/*
	size_t length = rz_read_le16(buf + 1);

	ut8 BlockBase = buf[3];
	ut8 BlockInfo = buf[4];
	ut8 PInfo = buf[4];
	ut8 TI = buf[4];
	// ut8 Type = SecTyp >> 6; ///< 0:=BIT, 1:=DATA, 2:=CODE, 3:=CONST
	// ut8 X = (SecTyp & 0x20) >> 5; ///< is set if the section is of type ’xhuge’ (length 0 ... 16M).
	// ut8 H = (SecTyp & 0x10) >> 4; ///< is set if the section is of type ’huge’ (length 0 ... 64K).
	// ut8 bitpos = SecTyp & 0x0F ;

	0xB7 | RecLen | BlockBase | BlockInfo           | PInfo   | TI | ChkSum
	0xB7 | RecLen | BlockBase | FFFF FFFF FFFF FFFF | FF FFFF | TI | ChkSum
	BlockBase => GroupIndex | SectionIndex | FrameNumber
	BlockBase => GroupIndex | SectionIndex | FFFF FFFF
	BlockInfo => NAME | BlockOffset16 | BlockLength16
	BlockInfo => NAME | FFFFFFFF      | FFFFFFFF
	PInfo =>    |P|Z|Z|Z|Z|Z|Z|Z| Null16					FF FFFF

[30] 0x00 0x00 0xc0 0x00 0x0f 0x6d 0x65 0x61 0x73 0x75 0x72 0x65 0x5f 0x64 0x69 0x73 0x70 0x6c 0x61 0x79 0x8a 0x16 0x7c 0x00 0x80 0x00 0x00 0x80 0x8f 0x6a
[13] 0x00 0x00 0xc0 0x00 0x00 0x8c 0x16 0x76 0x00 0x00 0x00 0x00  0x64
[23] 0x00 0x00 0xc0 0x00 0x08 0x73 0x65 0x74 0x5f 0x74 0x69 0x6d 0x65 0x06 0x17 0xba 0x00 0x80 0x00 0x00 0x80 0x8d 0xac
[13] 0x00 0x00 0xc0 0x00 0x00 0x0c 0x17 0xb0 0x00 0x00 0x00 0x00  0xa9
[27] 0x00 0x00 0xc0 0x00 0x0c 0x73 0x65 0x74 0x5f 0x69 0x6e 0x74 0x65 0x72 0x76 0x61 0x6c 0xc0 0x17 0x1a 0x01 0x80 0x00 0x00 0x80 0x8d 0xd3
[13] 0x00 0x00 0xc0 0x00 0x00 0xc8 0x17 0x0c 0x01 0x00 0x00 0x00  0x90

 	ut8 GroupIndex = 0x00;
 	ut8 SectionIndex = 0x00;
	ut8 FrameNumber = 0x00;


	if ((FrameNumber & 0x8000) != 0) {
		PageNumber
	} else
		SegmentNumber

	ut16 NAME = 0;
	ut16 BlockOffset16 = 0;
	ut16 BlockLength16 = 0;

	ut16 PInfo = 0;
	ut16 TypeIndex = 0;
*/

	// ut8 Seclen = rz_read_le32(buf + 3);
	// (void)Seclen;
	// (void)seg_idx;
	// printf("\nload_omf = BLKDEF  =  [%05d] [0x%08llx] 0x%02x (%d)\n",
	// 	record->size, global_ct, record->type, buf_size);
	// print_bytes(buf, record->size+3);
	return true;
}

#define BOOL_STR(x) x ? "true" : "false"
static const char *get_data_type(ut8 data_type) {
	switch (data_type) {
		case 0: {
			return "BIT";
		}
		case 1: {
			return "DATA";
		}
		case 2: {
			return "CODE";
		}
		case 3: {
			return "CONST";
		}
		default: {
			rz_warn_if_reached();
			return NULL;
		}
	}
}
static int load_omf_pedata(const ut8 *buf, int buf_size, OMF_record *record, ut64 global_ct) {
	OMF_data *ret_data;
	OMF_pedata *ret_pedata;

	ut16 ct = 3;
	ut8 SegmentNumber8 = rz_read_le8(buf + ct);

	ct++;
	ut16 Offset = rz_read_le16(buf + ct);

	ct += 2;
	ut8 data_type = rz_read_le8(buf + ct);

	// ut16 abs_offset = rz_bin_omf166_get_abs_addr(SegmentNumber8, Offset);

	const char *dt = get_data_type(data_type);


	char data2[255*6] = {0};
	size_t data_length = 0;
	if (data_type == 1) {
		data_length = record->size - 5;
		if (data_length > 1){
			rz_str_ncpy(data2, (const char *)&buf[7], data_length);
		}
	}
	if (data_type == 2) {
		data_length = record->size - 5;
	}
	printf("load_omf = PEDATA  =  [%05d] [0x%08llx] 0x%02x (%7d) SegmentNumber8: %02x, Offset: 0x%04x, data_type: %s ||  `%s`  || dl: %ld\t",
		record->size, global_ct, record->type, buf_size,
		SegmentNumber8, Offset,
		dt, data2, data_length);
	printf("\n");
	/**
	 * 0xB9 | RecLen | ABS-Address | DatTyp | Data | Chks
	 * ABS-Address = SegmentNumber8 | OffsetLow8 | OffsetHigh8
	 * 0xc0  0x4c  0x1e     0x01    0x49   0x4e 0x56 0x41 0x4c 0x49 0x44 0x20 0x49 0x4e 0x54 0x45 0x52 0x56 0x41 0x4c 0x20 0x46 0x4f 0x52 0x4d 0x41 0x54 0x00 0x49 0x4e 0x56 0x41 0x4c 0x49 0x44 0x20 0x54 0x49 0x4d 0x45 0x20 0x46 0x4f 0x52 0x4d 0x41 0x54 0x00 0x25 0x62 0x64 0x3a 0x25 0x62 0x64 0x3a 0x25 0x62 0x64 0x00 0x25 0x62 0x64 0x3a 0x25 0x66 0x00 0x20 0x41 0x4e 0x25 0x64 0x3a 0x25 0x34 0x2e 0x32 0x66 0x56 0x00 0x0d 0x54 0x69 0x6d 0x65 0x3a 0x20 0x25 0x32 0x64 0x3a 0x25 0x30 0x32 0x64 0x3a 0x25 0x30 0x32 0x64 0x2e 0x25 0x30 0x33 0x64 0x20 0x20 0x50 0x32 0x3a 0x25 0x30 0x34 0x58 0x00 0x36
	 * DatTyp	0: BIT  1: DATA  2: CODE  3: CONST
	 *
	 *
	 */

	if (!(ret_pedata = RZ_NEW0(OMF_pedata))) {
		RZ_LOG_ERROR("!(ret_seg = RZ_NEW0(OMF_pedata))\n");
		return false;
	}
	record->content = ret_pedata;

	// rz_return_val_if_fail(ret = RZ_NEW0(OMF_data), false);
	if (!(ret_data = RZ_NEW0(OMF_data))) {
		RZ_LOG_ERROR("!(ret_data = RZ_NEW0(OMF_data))\n");
		return false;
	}

	ret_pedata->data = ret_data;

	ret_pedata->name_idx = PE_INDEX++;
	ret_pedata->size = record->size - 1 - (ct - 3); //Seclen;
	ret_pedata->bits = 16;

	ret_pedata->type = data_type;

	ret_data->size = record->size - 1 - (ct - 3);
	ret_data->paddr = global_ct + ct;
	ret_data->offset = Offset; // offset;
	ret_data->seg_idx = SegmentNumber8; // seg_idx;
	ret_data->next = NULL;
	record->type = OMF166_PEDATA;

#ifdef X_DEBUG
	print_bytes(buf, record->size+3);
	printf("\n");
#endif
#if RZ_BUILD_DEBUG
#endif
	return true;
}

static int load_omf_secdef(const ut8 *buf, int buf_size, OMF_record *record, ut64 global_ct) {
	// ut16 seg_idx = 0;
	ut32 offset = 0;
	ut32 offset2 = 0;
	ut16 ct = 3;
	OMF_data *ret_data;
	OMF_segment *ret_seg;

	// if ((!(record->type & 1) && record->size < 4) || (record->size < 6)) {
	// 	RZ_LOG_ERROR("Invalid section record (bad size)\n");
	// 	return false;
	// }
	ut8 SecTyp = rz_read_le8(buf + ct); // ct = 3
	ut8 Type = SecTyp >> 6; ///< 0:=BIT, 1:=DATA, 2:=CODE, 3:=CONST
	bool X = (SecTyp & 0x20) >> 5; ///< is set if the section is of type ’xhuge’ (length 0 ... 16M).
	bool H = (SecTyp & 0x10) >> 4; ///< is set if the section is of type ’huge’ (length 0 ... 64K).
	ut8 bitpos = SecTyp & 0x0F ;

	ct++;
	ut8 SecAtr = buf[ct]; // ct = 4

	ct++;
	ut8 SegmentNumber8 = rz_read_le8(buf + ct); // ct = 5

	ct++;
	// offset = rz_read_be16(buf + ct); // ct = 6
	// offset2 = rz_read_le16(buf + ct); // ct = 6

	ct++;
	offset = rz_read_be16(buf + ct); // ct = 7
	offset2 = rz_read_le16(buf + ct); // ct = 7

	ct += 2;
	ut16 Seclen = rz_read_le16(buf + ct); // ct = 8

	//   0xC5 |   RecLen   | SecTyp | SecAtr                         |   Seclen   |                | ChkSum
	// load_omf = SECDEF  = [12] [0xdc4] 0xb0 (120027) SecTyp = DATA,  Seclen [072] x: false, h: false, b: true	[15] 0xb0   0x0c 0x00   0x48  0x00 0x01 0x00 0x5b 0x02 0x01 0x00 0x32 0x11 0x01 0x59
/*
	[15] 0xb0   0x0c 0x00    0x80    0x00      0xc0 0x00   0x8a 0x16   0x50 0x02 0x1b 0x02 0x01      0xf4
	[15] 0xb0   0x0c 0x00    0x50    0x00      0xc0 0x00   0x4c 0x1e   0x6f 0x00 0x1c 0x04 0x01      0x3a
*/

	printf("load_omf: %s, seg_idx: 0x%02x, offset: 0x%04x {0x%04x}, [%02d] [%03lld] 0x%02x (%d) ",
		record->type == OMF166_XSECDEF ? "XSECDEF" : "SECDEF ",
		SegmentNumber8,
		offset,
		offset2,
		record->size, global_ct, record->type, buf_size);
	const char *dt = get_data_type(Type);
	printf("SecTyp = %s,   Seclen [%03d] x: %s, h: %s, b: 0x%x SecAtr: 0x%02x\t", dt, Seclen, BOOL_STR(X), BOOL_STR(H), bitpos, SecAtr);
	printf("\tsecdef: ");
	print_bytes(buf, record->size + 3);
	printf("\n");
#if RZ_BUILD_DEBUG
#endif
	// printf("\n");
	// 0x80 0x00 0xc0 0x00 0x1e 0x1a 0x08 0x00 0x33 0x02 0x01 0x8e
	// The ’bitpos’ field has the same meaning as defined in the Siemens OMF166 spec.

	if (!(ret_seg = RZ_NEW0(OMF_segment))) {
		RZ_LOG_ERROR("!(ret_seg = RZ_NEW0(OMF_segment))\n");
		return false;
	}
	record->content = ret_seg;

	// rz_return_val_if_fail(ret = RZ_NEW0(OMF_data), false);
	if (!(ret_data = RZ_NEW0(OMF_data))) {
		RZ_LOG_ERROR("!(ret_data = RZ_NEW0(OMF_data))\n");
		return false;
	}

	ret_seg->name_idx = SEC_INDEX++;
	ret_seg->size = Seclen;
	ret_seg->bits = 16;
	ret_seg->data = ret_data;
	// record->content->vaddr = 16;

	ut32 secsize = 1;
	if (H) secsize = 16*1024;
	if (X) secsize = 16*1024*1024;

	ut32 perm = (Type == 0x2) ? RZ_PERM_RX : RZ_PERM_R;

	ret_data->size = Seclen * secsize; // ???? record->size - 1 - (ct - 3);
	ret_data->paddr = global_ct + ct;
	ret_data->offset = offset;
	ret_data->seg_idx = SegmentNumber8;
	ret_data->perm = perm;
	ret_data->is_data = (Type == 0x1);
	ret_data->is_segment = true;
	ret_data->next = NULL;
	record->type = OMF166_SECDEF;

#if RZ_BUILD_DEBUG
#endif
	return true;
}

static int load_omf_vectab(const ut8 *buf, int buf_size, OMF_record *record, ut64 global_ct) {
	// 0xE9 | RecLen | ABS-Address | DatTyp | Data        | Chks
	// E9     09 00    C0 18 00      02       FA C0 78 00  02
	if (record->size < 9) {
		RZ_LOG_ERROR("Invalid VECTAB record (bad size)\n");
		return false;
	}
	ut16 ct = 3;
	OMF_data *ret;
	ut8 SegmentNumber8 = rz_read_le8(buf + ct); // ct = 3;
	ct++;
	ut16 Offset = rz_read_le16(buf + ct);  // ct = 4;
	ct += 2;
	ut8 DatTyp = rz_read_le8(buf + ct);  // ct = 6;
	ct++;
	ut32 Data = rz_read_be32(buf + ct);

	ut16 abs_offset = rz_bin_omf166_get_abs_addr(SegmentNumber8, Offset);

	printf("load_omf = VECTAB =  [%05d] [0x%08llx] 0x%02x (%d)\t", record->size, global_ct, record->type, buf_size);

	if (DatTyp == 0x0) {
		printf("DatTyp = BIT \t");
	} else if (DatTyp == 0x1) {
		printf("DatTyp = DATA\t");
	} else if (DatTyp == 0x2) {
		printf("DatTyp = CODE\t");
	} else if (DatTyp == 0x3) {
		printf("DatTyp = CONS\t");
	} else {
		printf("DatTyp = UNKNOWN(%d), DatTyp [0x%02x]\t", DatTyp, DatTyp);
	}
	printf("SegmentNumber8: 0x%02x, Offset: [0x%08x], Data: [0x%08x]\n", SegmentNumber8, abs_offset, Data);

	if (!(ret = RZ_NEW0(OMF_data))) {
		RZ_LOG_ERROR("!(ret = RZ_NEW0(OMF_data))\n");
		return false;
	}
	record->content = ret;
	ret->size = 0; // ???? record->size - 1 - (ct - 3);
	ret->paddr = global_ct + ct;
	ret->offset = Offset;
	ret->seg_idx = SegmentNumber8;
	// ret->perm = perm;
	// ret->is_data = (Type == 0x1);
	// ret->is_segment = true;
	ret->next = NULL;
	record->type = OMF166_VECTAB;
	return true;
}

static int load_omf_modinf(const ut8 *buf, int buf_size, OMF_record *record, ut64 global_ct) {
#if RZ_BUILD_DEBUG
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
	printf("0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n", buf[0], buf[1], buf[2], buf[3], buf[4]);

#endif
	ut16 seg_idx = 0;
	ut32 offset = 0;
	ut16 ct = 3;
	OMF_data *ret;

	printf("record->size: %d\n", record->size);
	if ((!(record->type & 1) && record->size != 2)) {
		RZ_LOG_ERROR("Invalid MODINF record (bad size)\n");
		return false;
	}

	if (!(ret = RZ_NEW0(OMF_data))) {
		return false;
	}
	record->content = ret;

	ret->size = record->size - 1;
	ret->paddr = global_ct + ct;
	ret->offset = offset;
	ret->seg_idx = seg_idx;
	ret->next = NULL;
	record->type = OMF166_MODINF;

	return true;
}

static const char *ti[] = {
	[0x40] = "untyped",
	[0x41] = "bit",
	[0x42] = "char",
	[0x43] = "unsigned char",
	[0x44] = "int",
	[0x45] = "unsigned int",
	[0x46] = "long",
	[0x47] = "unsigned long",
	[0x48] = "float (32-Bit IEEE)",
	[0x49] = "double (64-Bit IEEE)",
	[0x4A] = "void",
	[0x4B] = "label",
	[0x4C] = "< a166 BITWORD >",
	[0x4D] = "< a166 NEAR >",
	[0x4E] = "< a166 FAR >",
	[0x4F] = "< a166 DATA3 >",
	[0x50] = "< a166 DATA4 >",
	[0x51] = "< a166 DATA8 >",
	[0x52] = "< a166 DATA16 >",
	[0x53] = "< a166 INTNO >",
	[0x54] = "< a166 REGBANK >",
};

#define IS_TI(x) ((x >= 0x40) && (x <= 0x54))

static int load_omf_typnew(const ut8 *buf, int buf_size, OMF_record *record, ut64 global_ct) {
#if RZ_BUILD_DEBUG
	/*
		Value represented final type
		0x40 untyped
		0x41 bit
		0x42 char
		0x43 unsigned char
		0x44 int
		0x45 unsigned int
		0x46 long
		0x47 unsigned long
		0x48 float (32-Bit IEEE)
		0x49 double (64-Bit IEEE)
		0x4A void
		0x4B label
		0x4C < a166 BITWORD >
		0x4D < a166 NEAR >
		0x4E < a166 FAR >
		0x4F < a166 DATA3 >
		0x50 < a166 DATA4 >
		0x51 < a166 DATA8 >
		0x52 < a166 DATA16 >
		0x53 < a166 INTNO >
		0x54 < a166 REGBANK >
	*/
	/*
		F0   0F 00   24 01 06 00 00 00 83 00   05  63 6C 6F 63 6B            42
		F0   0E 00   24 01 10 00 00 00 84 00   04  6D 72 65 63               9E
		F0   12 00   24 01 04 00 00 00 86 00   08  69 6E 74 65 72 76 61 6C   E2
		F0   36 00   20 04 00 43 00 00 00 00 00 00 00 04 68 6F 75 72 43 00 01 00 00 00 00 00 03 6D 69 6E 43 00 02 00 00 00 00 00 03 73 65 63 45 00 04 00 00 00 00 00 04 6D 73 65 63 AE
	*/
#endif
	size_t length = rz_read_le16(buf + 1);
	printf("load_omf = TYPNEW [0x%02x] (0x%02llx) ", TI_INDEX | 0x80, global_ct); // %d , buf_size
	ut8 compound_type = buf[3];
	switch (compound_type) {
		case 0x20: {
			ut32 cct = 4;
			ut16 NrOfComp16 = rz_read_le16(buf + cct);
			cct += 2;
			printf("COMPONENT-LIST Descriptor NrOfComp16: %d\n", NrOfComp16);
			for (int i = 0; i < NrOfComp16; i++) {
				ut16 TI16 = rz_read_le16(buf + cct); cct = cct + 2;
				ut32 OFFS32 = rz_read_le16(buf + cct); cct = cct + 4;
				ut8 REP8 = rz_read_at_le8(buf, cct); cct++;
				ut8 POS8 = rz_read_at_le8(buf, cct); cct++;
				ut8 n = rz_read_at_le8(buf, cct); cct++;
				char name[255] = {0};
				// const char *name = rz_strdup(buf[14]);
				rz_str_ncpy(name, (const char *)&buf[cct], n + 1);
				cct += n;
				printf("\t TI16: 0x%04x (%s), OFFS32: 0x%04x, REP8: 0x%02x, POS8: 0x%02x, n: %d (%s)\n",
					TI16, IS_TI(TI16) ? ti[TI16] : NULL, OFFS32, REP8, POS8, n, name);
				// printf("\t(%s), OFFS32: 0x%04x, REP8: 0x%02x, POS8: 0x%02x, n: %d (%s)\n",
				// 	ti[TI16], OFFS32, REP8, POS8, n, name);
			}


			break;
		}
		case 0x21: {
			printf("POINTER Descriptor ");
			print_bytes(buf, length+3);
			printf("\n");
			break;
		}
		case 0x22: {
			printf("ARRAY Descriptor ");
			print_bytes(buf, length+3);
			printf("\n");
			break;
		}
		case 0x23: {
			// ut8 ATTRIB8
			///<  0x23 | ATTRIB8 | RTYPE-TI16 | PARMLIST-TI16
			///<  0x23 0x01 0x44 0x00 0x82 0x00 0x1f
			///<  0x23 0x01 0x4a 0x00 0x4a 0x00 0x51
			///<  0x23 0x01 0x44 0x00 0x4a 0x00 0x57
			ut32 cct = 4;
			ut8 ATTRIB8 = rz_read_at_le8(buf, cct); // cct = 4
			cct++;
			ut32 RTYPE_TI16 = rz_read_le16(buf + cct); // cct = 5
			cct += 2;
			ut32 PARMLIST_TI16 = rz_read_le16(buf + cct); // cct = 7
			/*ut8 n = rz_read_at_le8(buf, cct); // cct = 11
			char name[255] = {0};
			// const char *name = rz_strdup(buf[14]);
			rz_str_ncpy(&name, &buf[cct], n + 1);
			// cct = cct + n;*/
			printf("FUNCTION Descriptor `%s`, ret: %s, paramlist: 0x%04x\n",
				ATTRIB8 == 1 ? "NEAR" : "FAR",
				ti[RTYPE_TI16], PARMLIST_TI16);

			break;
		}
		case 0x24: {
			printf("STRUCT/UNION Descriptor ");
			// ATTRIB8 | SIZE32 | MEMBER-TI16 | tagname
			ut32 cct = 4;
			ut8 ATTRIB8 = rz_read_at_le8(buf, cct); // cct = 4
			cct++;
			ut32 SIZE32 = rz_read_le32(buf + cct); // cct = 5
			// // cct++;
			cct += 4;
			ut16 MEMBER_TI16 = rz_read_le16(buf + cct); // cct = 9
			cct += 2;
			ut8 n = rz_read_at_le8(buf, cct); // cct = 11

			cct++;
			char name[255] = {0};
			// const char *name = rz_strdup(buf[14]);
			rz_str_ncpy(name, (const char *)&buf[cct], n + 1);  // cct = 12
			// cct = cct + n;
			printf("STRUCT/UNION Descriptor `%s`, sizeof struct or union (%04d), MEMBER_TI16: 0x%04x ret: %s, name[%d]: `%s`\n",
				ATTRIB8 == 1 ? "struct" : "union",
				SIZE32,
				MEMBER_TI16,
				"x", //ti[MEMBER_TI16],
				n,
				name);
			break;
		}
		case 0x25: {
			printf("BITFIELD Descriptor ");
			print_bytes(buf, length+3);
			printf("\n");
			break;
		}
		default: {
			rz_warn_if_reached();
			break;
		}
	}
	TI_INDEX++;

	return true;
}

static int load_omf_content(OMF_record *record, const ut8 *buf, ut64 global_ct, ut64 buf_size) {

	// generic loader just copy data from buf to content
	if (!record->size) {
		RZ_LOG_ERROR("Invalid record (size to short)\n");
		return false;
	}

	if ((record->type > 0x60) && (record->type < 68)) return true;

	switch (record->type) {
		case OMF166_LNAMES: {
			return load_omf166_lnames(record, buf, buf_size, global_ct);
		}
		case OMF166_PUBDEF:
		case OMF166_LOCSYM:
		case OMF166_GLBDEF: {
			return load_omf166_global_sym_record(record, buf, buf_size, global_ct);
		}
		case OMF166_DEBSYM: {
			// printf("load_omf = DEBSYM  =  [%05ld] [0x%08llx] 0x%02x (%lld)\n", length, global_ct, record->type, buf_size);
			return true;
		}
		case OMF166_BLKDEF: {
			return load_omf_blkdef(buf, buf_size, record, global_ct);
		}
		case OMF166_PEDATA: {
			return load_omf_pedata(buf, buf_size, record, global_ct);
		}
		case OMF166_THEADR:
		case OMF166_LHEADR: {
			return true;
		}
		case OMF166_MODINF: {
			return load_omf_modinf(buf, buf_size, record, global_ct);
		}
		case OMF166_VECTAB: {
			return load_omf_vectab(buf, buf_size, record, global_ct);
		}
		case OMF166_MODEND:
		case OMF166_BLKEND:
		case OMF166_LINNUM:
		case OMF166_REGDEF:
		case OMF166_COMMENT:
		case OMF166_GRPDEF:
		case OMF166_DEPLST: {
			return true;
		}
		case OMF166_LEDATA: {
			printf("load_omf = LEDATA  =  [%05d] [0x%08llx] 0x%02x (%lld)\n", record->size, global_ct, record->type, buf_size);
			return load_omf_data(buf, buf_size, record, global_ct);
		}

		case OMF166_TYPNEW: {
			return load_omf_typnew(buf, buf_size, record, global_ct);
		}

		case OMF166_SECDEF:
		case OMF166_XSECDEF: {
			return load_omf_secdef(buf, buf_size, record, global_ct);
		}
		case OMF166_ERROR1:
		case OMF166_ERROR2:
		case OMF166_ERROR3:
		case OMF166_ERROR4:
		case OMF166_ERROR5: {
			return true;
		}
		default: {
			printf("load_omf = ??????? =  [%05d] [0x%08llx] 0x%02x (%lld)\n", record->size, global_ct, record->type, buf_size);
			rz_warn_if_reached();
			break;
		}
	}
	if (!(record->content = RZ_NEWS0(char, record->size))) {
		return false;
	}
	((char *)record->content)[record->size - 1] = 0;
	return true;
}

static OMF_record_handler *load_record_omf(const ut8 *buf, ut64 global_ct, ut64 buf_size) {
	OMF_record_handler *new = NULL;

	if (is_valid_omf166_type(*buf) && rz_bin_checksum_omf_ok(buf, buf_size)) {
		if (!(new = RZ_NEW0(OMF_record_handler))) {
			return NULL;
		}
		((OMF_record *)new)->type = *buf;
		((OMF_record *)new)->size = rz_read_le16(buf + 1);

		// at least a record have a type a size and a checksum
		if (((OMF_record *)new)->size > buf_size - 3 || buf_size < 4) {
			RZ_LOG_ERROR("Invalid record (too short)\n");
			RZ_FREE(new);
			return NULL;
		}

		if (!(load_omf_content((OMF_record *)new, buf, global_ct, buf_size))) {
			RZ_FREE(new);
			return NULL;
		}
		((OMF_record *)new)->checksum = buf[2 + ((OMF_record *)new)->size];
		new->next = NULL;
	}
	return new;
}

static int load_all_omf_records(rz_bin_omf_obj *obj, const ut8 *buf, ut64 size) {
	ut64 ct = 0;
	OMF_record_handler *new_rec = NULL;
	OMF_record_handler *tmp = NULL;

	while (ct < size) {
		if (!(new_rec = load_record_omf(buf + ct, ct, size - ct))) {
			return false;
		}

		// the order is important because some link are made by index
		if (!tmp) {
			obj->records = new_rec;
			tmp = obj->records;
		} else {
			tmp->next = new_rec;
			tmp = tmp->next;
		}
		ct += 3 + ((OMF_record *)tmp)->size;
	}
	return true;
}

static ut32 count_omf166_record_type(rz_bin_omf_obj *obj, ut8 type) {
	OMF_record_handler *tmp = obj->records;
	ut32 ct = 0;

	while (tmp) {
		if (((OMF_record *)tmp)->type == type) {
			ct++;
		}
		tmp = tmp->next;
	}
	return ct;
}

static ut32 count_omf166_multi_record_type(rz_bin_omf_obj *obj, ut8 type) {
	OMF_record_handler *tmp = obj->records;
	ut32 ct = 0;

	while (tmp) {
		if (((OMF_record *)tmp)->type == type) {
			ct += ((OMF_multi_datas *)((OMF_record *)tmp)->content)->nb_elem;
		}
		tmp = tmp->next;
	}
	return ct;
}

static OMF_record_handler *get_next_omf166_record_type(OMF_record_handler *tmp, ut8 type) {
	while (tmp) {
		if (((OMF_record *)tmp)->type == type) {
			return (tmp);
		}
		tmp = tmp->next;
	}
	return NULL;
}

static int cpy_omf_names(rz_bin_omf_obj *obj) {
	OMF_record_handler *tmp = obj->records;
	OMF_multi_datas *lname;
	int ct_obj = 0;
	int ct_rec;

	while ((tmp = get_next_omf166_record_type(tmp, OMF166_LNAMES))) {
		lname = (OMF_multi_datas *)((OMF_record *)tmp)->content;

		ct_rec = -1;
		while (++ct_rec < lname->nb_elem) {
			if (!((char **)lname->elems)[ct_rec]) {
				obj->names[ct_obj++] = NULL;
			} else if (!(obj->names[ct_obj++] = rz_str_dup(((char **)lname->elems)[ct_rec]))) {
				return false;
			}
#ifdef X_DEBUG
			printf("cpy_omf_names: (%04d) %s\n", ct_obj-1, obj->names[ct_obj-1]);
			// printf("cpy_omf_names: %s (%d)\n", obj->names[ct_obj-1], obj->sections[ct_obj]->name_idx);
#endif
		}
		tmp = tmp->next;
	}
	return true;
}

static void get_omf166_section_info(rz_bin_omf_obj *obj) {
	OMF_record_handler *tmp = obj->records;
	ut32 ct_obj = 0;

	while ((tmp = get_next_omf166_record_type(tmp, OMF166_SECDEF))) {
		obj->sections[ct_obj] = ((OMF_record *)tmp)->content;
		// ((OMF_record *)tmp)->content = NULL;

		ut32 xxx = (obj->sections[ct_obj]->name_idx - 0x0c70) / 15;
#ifdef X_DEBUG
		printf("get_omf166_section_info: 0x%04x {%d} = 0x%04x = %d = 0x%04x {%d} `%s`\n",
			obj->sections[ct_obj]->name_idx,
			obj->sections[ct_obj]->name_idx,
			xxx,
			// (obj->sections[ct_obj]->name_idx - 0x0c70) / 15, // + (ct_obj * 15),
			0x0c70 + (ct_obj * 15),
			ct_obj, ct_obj,
			obj->names[ct_obj]);
#endif
		if (!ct_obj) {
			obj->sections[ct_obj]->vaddr = 0;
		} else {
			obj->sections[ct_obj]->vaddr = obj->sections[ct_obj - 1]->vaddr +
				obj->sections[ct_obj - 1]->size;
		}
		// obj->sections[ct_obj]-> = obj->names[ct_obj++];
		ct_obj++;
		tmp = tmp->next;
	}
}

static int get_omf166_pedata_info(rz_bin_omf_obj *obj) {
	OMF_record_handler *tmp = obj->records;
	ut32 ct_obj = 0;

	while ((tmp = get_next_omf166_record_type(tmp, OMF166_PEDATA))) {
		rz_return_val_if_fail(((OMF_record *)tmp)->content, false);
		// OMF_pedata *pedata = (OMF_pedata *)((OMF_record *)tmp)->content;
		obj->pedata[ct_obj] = ((OMF_record *)tmp)->content;
		if (!ct_obj) {
			obj->pedata[ct_obj]->vaddr = 0;
		} else {
			obj->pedata[ct_obj]->vaddr = obj->pedata[ct_obj]->vaddr +
				obj->pedata[ct_obj]->size;
			// obj->pedata[ct_obj]->vaddr = obj->pedata[ct_obj - 1]->vaddr +
			// 	obj->pedata[ct_obj - 1]->size;
		}
		ct_obj++;
		tmp = tmp->next;
	}
	return true;
}

static int get_omf166_symbol_info(rz_bin_omf_obj *obj) {
	OMF_record_handler *tmp = obj->records;
	OMF_multi_datas *symbols;
	int ct_obj = 0;
	int ct_rec = 0;

	while ((tmp = get_next_omf166_record_type(tmp, OMF166_PUBDEF))) {
		symbols = (OMF_multi_datas *)((OMF_record *)tmp)->content;

		ct_rec = -1;
		while (++ct_rec < symbols->nb_elem) {
			if (!(obj->symbols[ct_obj] = RZ_NEW0(OMF_symbol))) {
				return false;
			}
			memcpy(obj->symbols[ct_obj], ((OMF_symbol *)symbols->elems) + ct_rec, sizeof(*(obj->symbols[ct_obj])));
			obj->symbols[ct_obj]->name = rz_str_dup(((OMF_symbol *)symbols->elems)[ct_rec].name);
			obj->symbols[ct_obj]->offset = ((OMF_symbol *)symbols->elems)[ct_rec].offset;
			obj->symbols[ct_obj]->seg_idx = ((OMF_symbol *)symbols->elems)[ct_rec].seg_idx;

			printf("get_omf166_symbol_info offset: [0x%08x] seg_idx: 0x%04x name: `%s`\n",
				obj->symbols[ct_obj]->offset, obj->symbols[ct_obj]->seg_idx, obj->symbols[ct_obj]->name);
			ct_obj++;
		}
		tmp = tmp->next;
	}
	return true;
}

static int get_omf166_data_info(rz_bin_omf_obj *obj) {
	OMF_record_handler *tmp = obj->records;
	// OMF_data *tmp_data;
	ut32 ct_obj = 0;
	while ((tmp = get_next_omf166_record_type(tmp, OMF166_SECDEF))) {
	// printf("get_next_omf166_record_type(tmp, OMF166_SECDEF) : `%s`\n", ((OMF_record *)tmp)->content ? "true" : "false");

	// while ((tmp = get_next_omf166_record_type(tmp, OMF166_LEDATA))) {
		// if (((OMF_data *)((OMF_record *)tmp)->content)->seg_idx - 1 >= obj->nb_section) {
		// 	RZ_LOG_ERROR("Invalid Ledata record (bad segment index)\n");
		// 	return false;
		// }
		// OMF_data *tmp_data3 = (OMF_data *)((OMF_record *)tmp)->content;
		rz_return_val_if_fail(((OMF_record *)tmp)->content, false);
		// tmp_data3 ? printf("tmp_data3\n") : printf("!tmp_data3\n");
		// printf("tmp_data3->seg_idx 0x%04x\n", tmp_data3->seg_idx);
		// printf("get_omf_data_info OMF166_LEDATA seg_idx: 0x%04x\n", ((OMF_data *)((OMF_record *)tmp)->content)->seg_idx);
		// ut32 xxx = (obj->sections[ct_obj]->name_idx - 0x0c70) / 15;
		OMF_segment *os = obj->sections[ct_obj];
		// os->data ? printf("os->data\n") : printf("!os->data\n");


		// OMF_segment *os = obj->sections[((OMF_data *)((OMF_record *)tmp)->content)->seg_idx - 1];
		rz_return_val_if_fail(os, false);
		/*if (os && (tmp_data = os->data)) {
			while (tmp_data->next) {
				tmp_data = tmp_data->next;
			}
			tmp_data->next = ((OMF_record *)tmp)->content;
		} else {
			obj->sections[((OMF_data *)((OMF_record *)tmp)->content)->seg_idx - 1]->data = ((OMF_record *)tmp)->content;
		}
		((OMF_record *)tmp)->content = NULL;*/
		OMF_segment *rec_seg = (OMF_segment *)((OMF_record *)tmp)->content;
		os->data = rec_seg->data;
		// os->data = ((OMF_record *)tmp)->content;
		// ut32 xxx = (obj->sections[ct_obj]->name_idx - 0x0c70) / 15;
		// printf("get_omf166_data_info: 0x%04x 0x%04x {} data->size: %10lld, \

#if RZ_BUILD_DEBUG
		printf("get_omf166_data_info: 0x%04x data->size: %10lld {0x%08llx}, data->paddr: 0x%08llx, data->vaddr: 0x%08llx, data->perm: %2d `%s` `%s`\n",
			obj->sections[ct_obj]->name_idx,
			os->data->size,
			os->data->size,
			os->data->paddr,
			os->vaddr,
			os->data->perm,
			perm_names[os->data->perm],
			obj->names[ct_obj]
		);
#endif
		// printf("data->perm: %s\n", perm_names[os->data->perm]);
		ct_obj++;
		tmp = tmp->next;
	}
	return true;
}

static int get_omf_infos(rz_bin_omf_obj *obj) {
	// get all name defined in lnames records
	obj->nb_name = count_omf166_multi_record_type(obj, OMF166_LNAMES);
	if (obj->nb_name > 0) {
		if (!(obj->names = RZ_NEWS0(char *, obj->nb_name))) {
			return false;
		}
		if (!cpy_omf_names(obj)) {
			return false;
		}
	}
	// get all sections (segdef record)
	obj->nb_section = count_omf166_record_type(obj, OMF166_SECDEF);
	RZ_LOG_WARN("========= obj->nb_section count: %d\n", obj->nb_section);
	// obj->nb_section = count_omf_record_type(obj, OMF_SEGDEF);
	if (obj->nb_section > 0) {
		if (!(obj->sections = RZ_NEWS0(OMF_segment *, obj->nb_section))) {
			return false;
		}
		get_omf166_section_info(obj);
	}
	obj->nb_pedata = count_omf166_record_type(obj, OMF166_PEDATA);
	RZ_LOG_WARN("========= obj->nb_pedata count: %d\n", obj->nb_pedata);
	// obj->nb_section = count_omf_record_type(obj, OMF_SEGDEF);
	if (obj->nb_pedata > 0) {
		if (!(obj->pedata = RZ_NEWS0(OMF_pedata *, obj->nb_pedata))) {
			return false;
		}
		get_omf166_pedata_info(obj);
	}
	// get all data (ledata record)
	get_omf166_data_info(obj);
	// get all symbols (pubdef + lpubdef)
	obj->nb_symbol = count_omf166_multi_record_type(obj, OMF166_PUBDEF);
#if 0
	obj->nb_symbol =+ count_omf166_multi_record_type(obj, OMF166_GLBDEF);
	obj->nb_symbol =+ count_omf166_multi_record_type(obj, OMF166_LOCSYM);
#endif

	RZ_LOG_WARN("========= obj->nb_symbol count: %d\n", obj->nb_symbol);
	if (obj->nb_symbol > 0) {
		if (!(obj->symbols = RZ_NEWS0(OMF_symbol *, obj->nb_symbol))) {
			return false;
		}
		if (!get_omf166_symbol_info(obj)) {
			return false;
		}
	}
	return true;
}

static void free_pubdef(OMF_multi_datas *datas) {
	if (!datas) {
		return;
	}
	RZ_FREE(datas->elems);
	RZ_FREE(datas);
}

static void free_all_omf_records(rz_bin_omf_obj *obj) {
	OMF_record_handler *tmp = NULL;
	OMF_record_handler *rec = obj->records;

	while (rec) {
		if (((OMF_record *)rec)->type == OMF166_LNAMES) {
			free_lname((OMF_multi_datas *)((OMF_record *)rec)->content);
		} else if (((OMF_record *)rec)->type == OMF166_PUBDEF) {
			free_pubdef((OMF_multi_datas *)((OMF_record *)rec)->content);
		} else {
			RZ_FREE(((OMF_record *)rec)->content);
		}
		tmp = rec->next;
		RZ_FREE(rec);
		rec = tmp;
	}
	obj->records = NULL;
}

static void free_all_omf_sections(rz_bin_omf_obj *obj) {
	ut32 ct = 0;
	OMF_data *data;

	while (ct < obj->nb_section) {
		while (obj->sections[ct]->data) {
			data = obj->sections[ct]->data->next;
			RZ_FREE(obj->sections[ct]->data);
			obj->sections[ct]->data = data;
		}
		RZ_FREE(obj->sections[ct]);
		ct++;
	}
	RZ_FREE(obj->sections);
}

static void free_all_omf_symbols(rz_bin_omf_obj *obj) {
	ut32 ct = 0;
	while (ct < obj->nb_symbol) {
		RZ_FREE(obj->symbols[ct]->name);
		RZ_FREE(obj->symbols[ct]);

		ct++;
	}
	RZ_FREE(obj->symbols);
}

static void free_all_omf_names(rz_bin_omf_obj *obj) {
	ut32 ct = 0;

	while (ct < obj->nb_name) {
		RZ_FREE(obj->names[ct]);
		ct++;
	}
	RZ_FREE(obj->names);
}

void rz_bin_free_all_omf166_obj(rz_bin_omf_obj *obj) {
	if (obj) {
		if (obj->records) {
			free_all_omf_records(obj);
		}
		if (obj->sections) {
			free_all_omf_sections(obj);
		}
		if (obj->symbols) {
			free_all_omf_symbols(obj);
		}
		if (obj->names) {
			free_all_omf_names(obj);
		}
		free(obj);
	}
}

rz_bin_omf_obj *rz_bin_internal_omf166_load(const ut8 *buf, ut64 size) {
	rz_bin_omf_obj *ret = NULL;

	if (!(ret = RZ_NEW0(rz_bin_omf_obj))) {
		return NULL;
	}
	if (!load_all_omf_records(ret, buf, size)) {
		rz_bin_free_all_omf166_obj(ret);
		return NULL;
	}

	OMF_record_handler *tmp = ret->records;
	while ((tmp = get_next_omf166_record_type(tmp, OMF166_MODINF))) {
		OMF_data *pt = ((OMF_data *)((OMF_record *)tmp)->content);
		if (!pt) {
			rz_bin_free_all_omf166_obj(ret);
			return NULL;
		}
		ret->modinfo = rz_read_at_le8(buf, pt->paddr);
		tmp = tmp->next;
	}

	if (!(get_omf_infos(ret))) {
		rz_bin_free_all_omf166_obj(ret);
		return NULL;
	}
	// free_all_omf_records(ret);
	return ret;
}

bool rz_bin_omf166_get_entry(rz_bin_omf_obj *obj, RzBinAddr *addr) {
	if (!obj) {
		return false;
	}

	ut32 ct_sym = 0;
	// OMF_data *data;
	ut32 offset = 0;

	// const char *start_symbol_name = "?C_STARTUP";
	const char *start_symbol_name = "main";
	printf("obj->nb_symbol %d\n", obj->nb_symbol);

	while (ct_sym < obj->nb_symbol) {
		printf("`%s` `%s` %d %d\n", start_symbol_name, obj->symbols[ct_sym]->name,
			strcmp(obj->symbols[ct_sym]->name, start_symbol_name),
			!strcmp(obj->symbols[ct_sym]->name, start_symbol_name));
		if (!strcmp(obj->symbols[ct_sym]->name, start_symbol_name)) {
		// if (!strcmp(obj->symbols[ct_sym]->name, "_start")) {
			// if (obj->symbols[ct_sym]->seg_idx - 1 > obj->nb_section) {
			if (obj->symbols[ct_sym]->seg_idx > obj->nb_section) {
				printf("Invalid segment index for symbol 0x%04x %s\n", obj->symbols[ct_sym]->seg_idx, start_symbol_name);
				return false;
			}
			addr->vaddr = 0x10;
			// addr->vaddr = obj->sections[obj->symbols[ct_sym]->seg_idx - 1]->vaddr + obj->symbols[ct_sym]->offset + OMF166_BASE_ADDR;
			// data = obj->sections[obj->symbols[ct_sym]->seg_idx - 1]->data;
			// while (data) {
			// 	offset += data->size;
			// 	if (obj->symbols[ct_sym]->offset < offset) {
			// 		addr->paddr = (obj->symbols[ct_sym]->offset - data->offset) + data->paddr;
					return true;
			// 	}
			// 	data = data->next;
			// }
		}
		ct_sym++;
	}
	return false;
}

const char *rz_bin_omf166_get_module_information(rz_bin_omf_obj *obj) {
	rz_return_val_if_fail(obj && obj->records, NULL);

	OMF_record_handler *tmp = obj->records;
	while ((tmp = get_next_omf166_record_type(tmp, OMF166_MODINF))) {
		OMF_data *pt = ((OMF_data *)((OMF_record *)tmp)->content);

		// 	bool DOUBLE_USED = byte >> 7; ///< The module contains double precision float operations. This bit is intended for the linker for automatic selection of libraries.
		// 	bool FLOAT_USED = (byte & 0x40) >> 6; ///< The module contains single precision float operations. This bit is intended for the linker for automatic selection of libraries.
		// 	bool MOD167 = (byte & 0x20) >> 5;   ///< If bit is set, then the module is intended to be executed on an 80C167 CPU, otherwise the module is for a 80C166 CPU.
		// 	bool MEMORY_MODEL = (byte & 0x1C) >> 2; ///< The three bit model specifier gives the memory model choosen on translation:
		// 											///< 1: Tiny
		// 											///< 2: Small
		// 											///< 3: Compact
		// 											///< 4: Medium
		// 											///< 5: Large
		// 	bool CASE = (byte & 0x02) >> 1; ///< If bit is set, then names are to be considered case sensitive. This info is intended for the linker when combining object modules.
		// 	bool SEGMENTED = (byte & 0x01); ///< If bit is set, then the segmented cpu mode was choosen for the module.

		((OMF_record *)tmp)->content = NULL;
		tmp = tmp->next;
	}
	return rz_str_dup("OMF166 (Non-Relocatable Object Module Format)");
}

ut64 rz_bin_omf166_get_paddr_sym(rz_bin_omf_obj *obj, OMF_symbol *sym) {
	printf("rz_bin_omf166_get_paddr_sym offset: [0x%08x] seg_idx: 0x%04x name: `%s`\n",
				sym->offset, sym->seg_idx, sym->name);
	ut64 offset = 0;
	if (!obj->sections) {
		return 0LL;
	}
	if (sym->seg_idx - 1 > obj->nb_section) {
		return 0LL;
	}
	int sidx = sym->seg_idx - 1;
	if (sidx >= obj->nb_section) {
		return 0LL;
	}
	OMF_data *data = obj->sections[sidx]->data;
	while (data) {
		offset += data->size;
		if (sym->offset < offset) {
			return sym->offset - data->offset + data->paddr;
		}
		data = data->next;
	}
	return 0;
}

ut64 rz_bin_omf166_get_vaddr_sym(rz_bin_omf_obj *obj, OMF_symbol *sym) {
	if (!obj->sections) {
		return 0LL;
	}
	// ut32 xxx = (sym->seg_idx - 0x0c70) / 15;
	// if (xxx >= obj->nb_section) {
	printf("rz_bin_omf166_get_vaddr_sym: sym->seg_idx: 0x%04x offset: 0x%08x `%s`\n", sym->seg_idx, sym->offset, sym->name);
	// if (sym->seg_idx >= obj->nb_section) {
	// 	RZ_LOG_ERROR("%d: Invalid segment index for symbol (0x%04x %d) `%s` \n", __LINE__, sym->seg_idx, sym->seg_idx, sym->name);
	// 	// RZ_LOG_ERROR("%d: Invalid segment index for symbol %s (0x%04x %d)(0x%04x %d)\n", __LINE__, sym->name, sym->seg_idx, sym->seg_idx, xxx, xxx);
	// 	return 0;
	// }
	// if (sym->seg_idx == 0) {
	// 	return 0;
	// }
	// return obj->sections[xxx]->vaddr + sym->offset + OMF166_BASE_ADDR;
	// return obj->sections[sym->seg_idx - 1]->vaddr + sym->offset + OMF166_BASE_ADDR;
	return sym->offset + OMF166_BASE_ADDR;
	// return obj->sections[sym->seg_idx]->vaddr + sym->offset;// + OMF166_BASE_ADDR;
	// ut16 abs_offset = rz_bin_omf166_get_abs_addr(SegmentNumber8, Offset);
}
