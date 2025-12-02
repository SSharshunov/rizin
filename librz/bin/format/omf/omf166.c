// SPDX-FileCopyrightText: 2015 ampotos <mercie_i@epitech.eu>
// SPDX-FileCopyrightText: 2015-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2025 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "omf.h"

int TI_INDEX = 0;
int SEC_INDEX = 0;

RZ_API bool is_data_ti(rz_bin_omf166_obj *obj, ut16 ti_index) {
	bool found = false;
	OMF_type *type = ht_up_find(obj->ht_types, ti_index, &found);
	rz_return_val_if_fail(found, NULL);
	return type->is_data;
}

RZ_API bool is_final_type(rz_bin_omf166_obj *obj, ut16 ti_index) {
	bool found = false;
	OMF_type *type = ht_up_find(obj->ht_types, ti_index, &found);
	rz_return_val_if_fail(found, false);
	return (type->descr_type == FINAL_TYPE) ? true : false;
}

RZ_API const char *name_of_ti(rz_bin_omf166_obj *obj, ut16 ti_index) {
	if (ti_index == 0x00)
		return "void";
	bool found = false;
	OMF_type *type = ht_up_find(obj->ht_types, ti_index, &found);
	rz_return_val_if_fail(found, NULL);
	switch (type->descr_type) {
	case FINAL_TYPE: {
		return type->label;
	}
	case COMPONENT_LIST_DESCRIPTOR: {
		return type->label ? type->label : "COMPONENT_LIST";
	}
	case POINTER_DESCRIPTOR: {
		if (type->descriptor.pointer.attrib == 1)
			return "POINTER: 1 = Data pointer (PAGE:OFFSET)";
		if (type->descriptor.pointer.attrib == 2)
			return "POINTER: 2 = Function pointer (SEG:OFFSET)";
		if (type->descriptor.pointer.attrib == 4)
			return "POINTER: 4 = Huge pointer (linear 32-Bit)";
		if (type->descriptor.pointer.attrib == 8)
			return "POINTER: 8 = Xhuge pointer (linear 32-Bit)";
		return "unknown pointer";
	}
	case ARRAY_DESCRIPTOR: {
		return type->label ? type->label : "ARRAY";
	}
	case FUNCTION_DESCRIPTOR: {
		return type->descriptor.function.attrib ? "Near-Function" : "Far-Function";
	}
	case STRUCT_UNION_DESCRIPTOR: {
		return type->descriptor.struct_union.tagname;
	}
	case BITFIELD_DESCRIPTOR: {
		return "BITFIELD";
	}
	default: {
		rz_warn_if_reached();
		return NULL;
	}
	}
	rz_warn_if_reached();
	return NULL;
}

RZ_API const char *name_of_rep8(ut8 rep8) {
	ut8 rep = (rep8 & 0x70) >> 4;
	switch (rep) {
	case REP_BIT: {
		return "BIT";
	}
	case REP_VAR: {
		return "VAR";
	}
	case REP_LAB: {
		return "LAB";
	}
	case REP_REGBANK: {
		return "REGBANK";
	}
	case REP_INTNO: {
		return "INTNO";
	}
	case REP_CONST: {
		return "CONST";
	}
	case REP_REGVAR: {
		return "REGVAR";
	}
	case REP_AUTO: {
		return "AUTO R0+offset";
	}
	default: {
		rz_warn_if_reached();
		return NULL;
	}
	}
	return NULL;
}

const char *name_of_iTyp(ut8 iTyp) {
	switch (iTyp) {
	case ITYP_OUTPUTFILE: {
		return "Outputfile";
	}
	case ITYP_INPUTFILE: {
		return "Inputfile";
	}
	case ITYP_INCLUDEFILE: {
		return "Includefile";
	}
	case ITYP_COMMANDFILE: {
		return "Commandfile";
	}
	case ITYP_OBJECT_INPUTFILE: {
		return "Object-Inputfile";
	}
	case ITYP_COMMANDLINE: {
		return "Commandline";
	}
	default: {
		rz_warn_if_reached();
		return "UNKNOWN";
	}
	}
	return NULL;
}

const char *get_data_type(ut8 data_type) {
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

const ut32 get_perm_by_type(ut8 data_type) {
	switch (data_type) {
	case 0: {
		return RZ_PERM_RW; ///< BIT
	}
	case 1: {
		return RZ_PERM_RW; ///< DATA
	}
	case 2: {
		return RZ_PERM_RWX; ///< CODE
	}
	case 3: {
		return RZ_PERM_R; ///< CONST
	}
	default: {
		rz_warn_if_reached();
		return RZ_PERM_R;
	}
	}
}

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
		OMF166_UNKNOWN0, OMF166_INCLUDES, OMF166_UNKNOWN2, OMF166_UNKNOWN3,
		OMF166_UNKNOWN4, OMF166_UNKNOWN5,
		0
	};
	for (; types[ct]; ct++) {
		if (type == types[ct]) {
			return true;
		}
	}
	RZ_LOG_ERROR("Invalid record type: 0x%02x\n", type);
	return false;
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
	ut16 ret = rz_read_le8(buf);
	if (ret & 0x80) {
		return (ut16)(ret & 0x7f) * 0x100 + rz_read_at_le8(buf, 1);
	}
	return ret;
}

static bool load_omf166_lnames(rz_bin_omf166_obj *obj, OMF_record *record, const ut8 *buf, ut64 buf_size, ut64 global_ct) {
	ut32 tmp_size = 0;
	ut32 ct_name = 0;

	OMF_lnames *lname = NULL;
	if (!record || !buf) {
		return false;
	}
	rz_return_val_if_fail(record->size > 3, false);

	while ((int)tmp_size < (int)(record->size - 1)) {
		int next;
		next = buf[3 + tmp_size] + 1;
		if (next < 1) {
			break;
		}
		tmp_size += next;
	}
	tmp_size = 0;
	while ((int)tmp_size < (int)(record->size - 1)) {
		// sometimes there is a name with a null size so we just skip it
		char cb = buf[3 + tmp_size];
#if 0
		/* TODO: check names counter */
		if (cb < 1) {
			names[ct_name++] = NULL;
			tmp_size++;
			continue;
		}
#endif
		if (record->size + 3 < tmp_size + cb) {
			RZ_LOG_ERROR("Invalid Lnames record (bad size)\n");
			return false;
		}
		if (!(lname = RZ_NEW0(OMF_lnames))) {
			return false;
		}
		if ((tmp_size + 4 + cb) < buf_size) {
			memcpy(lname->name, buf + 3 + tmp_size + 1, cb);
			lname->index = ct_name;
		}

		rz_pvector_push(obj->lnames_vec, lname);
		ct_name++;
		tmp_size += cb + 1; // buf[3 + tmp_size] + 1;
	}
	return true;
}

static int load_omf166_global_sym_record(rz_bin_omf166_obj *obj, OMF_record *record, const ut8 *buf, int buf_size, ut64 global_ct) {
	OMF_symbol *sym = NULL;
	ut16 ct = 3;
	ut32 base = 0;

	rz_return_val_if_fail(record->size > 3, false);

	if (record->type == OMF166_DEBSYM) {
		if ((buf[ct] == 0x02)) {
			ct++;
			base = rz_read_le8(buf + ct);
			ct++;
		} else {
			///< A DEBSYM record whose FRAMEINFO field is 0 is functionally
			///< equivalent to a LOCSYM record.
			ct++;
			base = rz_read_le32(buf + ct);
			ct += 4;
		}
	} else {
		base = rz_read_le32(buf + ct);
		ct += 4;
	}

	if (record->size <= ct) {
		RZ_LOG_ERROR("Invalid sym record (bad size)\n");
		return false;
	}

	while (record->size > ct) {
		if (!(sym = RZ_NEW0(OMF_symbol))) {
			return false;
		}
		sym->rec_type = record->type;
		sym->base = base;
		sym->n = rz_read_le8(buf + ct);

		ct++;
		rz_str_ncpy(sym->name2, (const char *)&buf[ct], sym->n + 1);

		ct += sym->n;
		sym->offset = rz_read_le16(buf + ct);

		ct += 2;
		sym->REP8 = rz_read_le8(buf + ct);
		sym->V = sym->REP8 >> 7;
		sym->REP = (sym->REP8 & 0x70) >> 4;
		sym->bpos = sym->REP8 & 0x0F;

		ct++;
		sym->ti = omf166_get_idx(buf + ct, buf_size - ct);
		ct += (buf[ct] & 0x80) ? 2 : 1;

		sym->is_data = is_data_ti(obj, sym->ti);
		ut8 rep = (sym->REP8 & 0x70) >> 4;
		if (rep == REP_BIT)
			sym->is_data = true;
		if (rep == REP_VAR)
			sym->is_data = true;
		if (rep == REP_REGBANK)
			sym->is_data = true;
		if (rep == REP_INTNO)
			sym->is_data = true;
		if (rep == REP_CONST)
			sym->is_data = true;
		if (rep == REP_REGVAR)
			sym->is_data = true;
		if (rep == REP_AUTO)
			sym->is_data = true;
		rz_pvector_push(obj->symbols_vec, sym);
	}
	return true;
}

static int load_omf_data(rz_bin_omf166_obj *obj, const ut8 *buf, int buf_size, OMF_record *record, ut64 global_ct) {
	OMF_ledatas *lep = NULL;
	ut16 ct = 4;

	if (!(lep = RZ_NEW0(OMF_ledatas))) {
		return false;
	}

	if ((!(record->type & 1) && record->size < 4) || (record->size < 6)) {
		RZ_LOG_ERROR("Invalid Ledata record (bad size)\n");
		return false;
	}
	lep->seg_idx = omf166_get_idx(buf + 3, buf_size - 3);
	if (lep->seg_idx & 0xff00) {
		if ((!(record->type & 1) && record->size < 5) || (record->size < 7)) {
			RZ_LOG_ERROR("Invalid Ledata record (bad size)\n");
			return false;
		}
		ct++;
	}

	lep->offset = rz_read_le16(buf + ct);
	ct += 2;

	rz_pvector_push(obj->ledatas_vec, lep);
	return true;
}

static int load_omf_blkdef(rz_bin_omf166_obj *obj, const ut8 *buf, int buf_size, OMF_record *record, ut64 global_ct) {
	OMF_blocks *block = NULL;
	if (!(block = RZ_NEW0(OMF_blocks))) {
		return false;
	}
	ut16 ct = 3;

	block->GroupIndex = omf166_get_idx(buf + ct, buf_size - ct); // ct = 3
	ct++;
	block->SectionIndex = omf166_get_idx(buf + ct, buf_size - ct); // ct = 4

	ct++;
	block->FrameNumber = rz_read_le16(buf + ct); // ct = 5
	if (!block->GroupIndex && !block->SectionIndex) {
		ct += 2;
	}

	block->n = buf[ct]; // ct = 7
	ct++;
	rz_str_ncpy(block->name, (const char *)&buf[ct], block->n + 1);

	ct += block->n;
	block->BlockOffset16 = rz_read_le16(buf + ct);
	ct += 2;
	block->BlockLength16 = rz_read_le16(buf + ct);
	ct += 2;

	block->PInfoProcedure = (buf[ct] & 0x80);

	ct += 3;
	block->TI = omf166_get_idx(buf + ct, buf_size - ct);

	if (block->n > 0)
		rz_pvector_push(obj->blocks_vec, block);
	else
		RZ_FREE(block);
	return true;
}

static int load_coment_data(rz_bin_omf166_obj *obj, const ut8 *buf, int buf_size, OMF_record *record, ut64 global_ct) {
	OMF_coments *coment = NULL;
	if (!(coment = RZ_NEW0(OMF_coments))) {
		return false;
	}
	ut16 ct = 3;
	ut8 ComTyp_b2 = rz_read_le8(buf + ct); // ct = 3

	ct++;
	ut8 ComTyp_b1 = rz_read_le8(buf + ct); // ct = 4
	coment->nopurge = (ComTyp_b1 & 0x80) >> 7;
	coment->is_filename = (ComTyp_b2 == 0x4b);

	ct++;
	coment->n = record->size + 3 - ct;
	rz_str_ncpy(coment->text,
		(const char *)&buf[ct], coment->n); // ct = 3

	rz_pvector_push(obj->coments_vec, coment);
	return true;
}

static int load_deplst_data(rz_bin_omf166_obj *obj, const ut8 *buf, int buf_size, OMF_record *record, ut64 global_ct) {
#if RZ_BUILD_DEBUG
	ut16 ct = 3;
	ut8 some_byte = rz_read_le8(buf + ct);
	(void)some_byte;
	ct++;
	ut8 info_n = rz_read_le8(buf + ct);
	ct++;
	char info[255] = RZ_EMPTY;
	rz_str_ncpy(info, (const char *)&buf[ct], info_n + 1);
	ct += info_n;
	while (ct < record->size) {
		///< iTyp | Mark8 | Time32 | Name(s)
		ut8 iTyp = rz_read_le8(buf + ct); ///< Specifies the type of the dependency descriptor
		ct++;
		ut8 Mark8 = rz_read_le8(buf + ct); ///< Byte, required to be zero.
		ct++;
		ut32 Time32 = rz_read_le32(buf + ct); ///< File creation date in Microsoft’s ’fstat()’ format.
		ct += 4;
		ut8 n = rz_read_le8(buf + ct);
		ct++;
		char pathname[255] = RZ_EMPTY; ///< Specifies the Pathname of one file. In case of iTyp 4, more than one pathname may be specified.
		rz_str_ncpy(pathname,
			(const char *)&buf[ct], n + 1);
		RZ_LOG_DEBUG("iTyp: [0x%02x] `%16s`, Mark8: 0x%02x, Time32: %d, n: %3d `%s`\n",
			iTyp, name_of_iTyp(iTyp), Mark8, Time32, n, pathname);
		ct += n;
	}
#endif
	return true;
}

static int load_linnum_data(rz_bin_omf166_obj *obj, const ut8 *buf, int buf_size, OMF_record *record, ut64 global_ct) {
	OMF_linnums *linnum = NULL;
	ut16 ct = 3;

	ut8 GroupIndex = omf166_get_idx(buf + ct, buf_size - ct); // ct = 3
	ct++;
	ut8 SectionIndex = omf166_get_idx(buf + ct, buf_size - ct); // ct = 4

	ct++;
	ut16 FrameNumber = rz_read_le16(buf + ct); // ct = 5
	if (!GroupIndex && !SectionIndex) {
		ct += 2;
	}

	while (ct < record->size) {
		if (!(linnum = RZ_NEW0(OMF_linnums))) {
			return false;
		}
		linnum->LineNumber = rz_read_le16(buf + ct); // start with ct = 5
		ct += 2;
		ut16 offset = rz_read_le16(buf + ct);
		ct += 2;
		linnum->address = (FrameNumber << 16) | offset;
		OMF_coments *coment = rz_pvector_tail(obj->coments_vec);
		if (!coment) {
			return false;
		}
		linnum->n = coment->n;
		rz_str_ncpy(linnum->filename, coment->text, coment->n);
		rz_pvector_push(obj->linnums_vec, linnum);
	}
	return true;
}

static int load_omf_pedata(rz_bin_omf166_obj *obj, const ut8 *buf, int buf_size, OMF_record *record, ut64 global_ct) {
	OMF_pes *pe = NULL;
	if (!(pe = RZ_NEW0(OMF_pes))) {
		return false;
	}

	ut16 ct = 3;
	pe->SegmentNumber8 = rz_read_le8(buf + ct);

	ct++;
	pe->offset = rz_read_le16(buf + ct);

	ct += 2;
	pe->data_type = rz_read_le8(buf + ct);
	ct++;

	pe->isVector = (record->type == OMF166_VECTAB);

	/**
	 * 0xB9 | RecLen | ABS-Address | DatTyp | Data | Chks
	 * ABS-Address = SegmentNumber8 | OffsetLow8 | OffsetHigh8
	 * 0xc0  0x4c  0x1e     0x01    0x49   0x4e 0x56 0x41 0x4c 0x49 0x44 0x20 0x49 0x4e 0x54 0x45 0x52 0x56 0x41 0x4c 0x20 0x46 0x4f 0x52 0x4d 0x41 0x54 0x00 0x49 0x4e 0x56 0x41 0x4c 0x49 0x44 0x20 0x54 0x49 0x4d 0x45 0x20 0x46 0x4f 0x52 0x4d 0x41 0x54 0x00 0x25 0x62 0x64 0x3a 0x25 0x62 0x64 0x3a 0x25 0x62 0x64 0x00 0x25 0x62 0x64 0x3a 0x25 0x66 0x00 0x20 0x41 0x4e 0x25 0x64 0x3a 0x25 0x34 0x2e 0x32 0x66 0x56 0x00 0x0d 0x54 0x69 0x6d 0x65 0x3a 0x20 0x25 0x32 0x64 0x3a 0x25 0x30 0x32 0x64 0x3a 0x25 0x30 0x32 0x64 0x2e 0x25 0x30 0x33 0x64 0x20 0x20 0x50 0x32 0x3a 0x25 0x30 0x34 0x58 0x00 0x36
	 * DatTyp	0: BIT  1: DATA  2: CODE  3: CONST
	 *
	 *
	 */
	pe->size = record->size - 1 - (ct - 3);
	pe->paddr = global_ct + ct;

	rz_pvector_push(obj->pe_vec, pe);
	return true;
}

static int load_omf_unk1(rz_bin_omf166_obj *obj, const ut8 *buf, int buf_size, OMF_record *record, ut64 global_ct) {
	/**
	 * 61    40 00    2C 03 9D 55 01 00
	 * 38    43 3A 5C 4B 65 69 6C 5F 76 35 5C 63 31 36 36 5C 45 78 61 6D 70 6C 65 73 5C 58 43 31 36 78 20 44 65 76 69 63 65 73 5C 4D 45 41 53 55 52 45 5C 47 65 74 6C 69 6E 65 2E 63
	 * C:\Keil_v5\c166\Examples\XC16x Devices\MEASURE\Getline.c
	 * CA
	 */
#if RZ_BUILD_DEBUG
	OMF_debug_includes *dip = NULL;
	if (!(dip = RZ_NEW0(OMF_debug_includes))) {
		return false;
	}

	dip->n = rz_read_at_le8(buf, 9);
	rz_str_ncpy(dip->name, (const char *)&buf[10], dip->n + 1); // cct = 12
	RZ_LOG_DEBUG("load_omf = INCLUDES  =  [%05d] [0x%08llx] 0x%02x (%10d)\t `%s`\n", record->size, global_ct, record->type, buf_size, dip->name);
	/*
		if (record->size > 11 + dip->n) {
			print_bytes(buf, record->size + 3);
		}
	*/
	rz_pvector_push(obj->includes_vec, dip);

#endif
	return true;
}

static int load_omf_unk2(rz_bin_omf166_obj *obj, const ut8 *buf, int buf_size, OMF_record *record, ut64 global_ct) {
#if RZ_BUILD_DEBUG
	char name[255] = RZ_EMPTY;
	ut8 n = rz_read_at_le8(buf, 7);
	rz_str_ncpy(name, (const char *)&buf[8], n + 1); // cct = 12
	RZ_LOG_DEBUG("load_omf = UNKNOWN2  =  [%05d] [0x%08llx] 0x%02x (%10d)\t 0x%02x 0x%02x 0x%02x 0x%02x  `%s`\n",
		record->size, global_ct,
		record->type, buf_size,
		buf[3], buf[4], buf[5], buf[6],
		name);
	/*
		if (record->size > 9 + n) {
			print_bytes(buf, record->size + 3);
			printf("\n");
		}
	*/
#endif
	return true;
}

static int load_omf_unk3(rz_bin_omf166_obj *obj, const ut8 *buf, int buf_size, OMF_record *record, ut64 global_ct) {
#if RZ_BUILD_DEBUG
	char name[255] = RZ_EMPTY;
	ut8 n = rz_read_at_le8(buf, 7);
	rz_str_ncpy(name, (const char *)&buf[8], n + 1); // cct = 12
	RZ_LOG_DEBUG("load_omf = UNKNOWN3  =  [%05d] [0x%08llx] 0x%02x (%10d)\t `%s`\n", record->size, global_ct, record->type, buf_size, name);
	RZ_LOG_DEBUG("%02x %02x %02x \n%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
		buf[0], buf[1], buf[2],
		buf[3], buf[4], buf[5], buf[6], buf[7],
		buf[8], buf[9], buf[10], buf[11], buf[12],
		buf[13], buf[14]);
#endif
	return true;
}

static int load_omf_unk4(rz_bin_omf166_obj *obj, const ut8 *buf, int buf_size, OMF_record *record, ut64 global_ct) {
#if RZ_BUILD_DEBUG
	RZ_LOG_DEBUG("load_omf = UNKNOWN4  =  [%05d] [0x%08llx] 0x%02x (%10d)\n", record->size, global_ct, record->type, buf_size);
	ut16 ct = 3;
	ut16 count = rz_read_le16(buf + ct);

	RZ_LOG_DEBUG("count: %2d [%02x %02x]\n%02x %02x\n",
		count, buf[ct], buf[ct + 1], buf[ct + 2], buf[ct + 3]);
	ct += 4;

	for (ut16 i = 0; i < count; i++) {
		ut8 b1 = rz_read_le8(buf + ct);
		ct++;
		ut8 b2 = rz_read_le8(buf + ct);
		ct++;
		ut8 b3 = rz_read_le8(buf + ct);
		ct++;
		ut8 b4 = rz_read_le8(buf + ct);
		ct++;
		ut16 line = rz_read_le16(buf + ct);
		ct += 2;

		RZ_LOG_DEBUG("%02x %02x %02x %02x  [line: %5d]   %02x %02x %s (0x%02x) %02x %02x %02x %02x %02x %02x %02x\n",
			b1, b2, b3, b4, line,
			buf[ct], buf[ct + 1],
			buf[ct + 2] ? "references" : "definition", buf[ct + 2],
			buf[ct + 3], buf[ct + 4], buf[ct + 5],
			buf[ct + 6], buf[ct + 7], buf[ct + 8], buf[ct + 9]);
		ct += 10;
	}
#endif
	return true;
}

static int load_omf_secdef(rz_bin_omf166_obj *obj, const ut8 *buf, int buf_size, OMF_record *record, ut64 global_ct) {
	ut16 ct = 3;

	OMF_sections *section = NULL;
	if (!(section = RZ_NEW0(OMF_sections))) {
		return false;
	}

	ut8 SecTyp = rz_read_le8(buf + ct); // ct = 3
	section->Type = SecTyp >> 6; ///< 0:=BIT, 1:=DATA, 2:=CODE, 3:=CONST
	section->X = (SecTyp & 0x20) >> 5; ///< is set if the section is of type ’xhuge’ (length 0 ... 16M).
	section->H = (SecTyp & 0x10) >> 4; ///< is set if the section is of type ’huge’ (length 0 ... 64K).
	section->bitpos = SecTyp & 0x0F;

	ct++;
	section->SecAtr = buf[ct]; // ct = 4

	ct++;
	section->SegmentNumber8 = rz_read_le8(buf + ct); // ct = 5

	ct += 2;
	section->offset = rz_read_be16(buf + ct); // ct = 7

	ct += 2;
	section->Seclen = record->type == OMF166_XSECDEF ? rz_read_le32(buf + ct) : rz_read_le16(buf + ct); // ct = 9
	section->isXSec = (record->type == OMF166_XSECDEF);
	/*
		0xC5 |   RecLen   | SecTyp | SecAtr                         |   Seclen   |                | ChkSum
		0xb0   0x0c 0x00    0x80    0x00      0xc0 0x00   0x8a 0x16   0x50 0x02 0x1b 0x02 0x01      0xf4
		0xb0   0x0c 0x00    0x50    0x00      0xc0 0x00   0x4c 0x1e   0x6f 0x00 0x1c 0x04 0x01      0x3a
	*/
	section->index = SEC_INDEX;

	/* ???
	ut32 secsize = 1;
	if (H)
		secsize = 16 * 1024;
	if (X)
		secsize = 16 * 1024 * 1024;
	*/

	rz_pvector_push(obj->sections_vec, section);
	SEC_INDEX++;
	return true;
}

static int load_omf_modinf(rz_bin_omf166_obj *obj, const ut8 *buf, int buf_size, OMF_record *record, ut64 global_ct) {
#if RZ_BUILD_DEBUG
	RZ_LOG_DEBUG("0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n", buf[0], buf[1], buf[2], buf[3], buf[4]);
#endif
	ut16 ct = 3;
	if ((!(record->type & 1) && record->size != 2)) {
		RZ_LOG_ERROR("Invalid MODINF record (bad size)\n");
		return false;
	}
	obj->modinfo = rz_read_le8(buf + ct);
	return true;
}

static int load_omf_typnew(rz_bin_omf166_obj *obj, const ut8 *buf, int buf_size, OMF_record *record, ut64 global_ct) {
	/*
		F0   0F 00   24 01 06 00 00 00 83 00   05  63 6C 6F 63 6B            42
		F0   0E 00   24 01 10 00 00 00 84 00   04  6D 72 65 63               9E
		F0   12 00   24 01 04 00 00 00 86 00   08  69 6E 74 65 72 76 61 6C   E2
		F0   36 00   20 04 00 43 00 00 00 00 00 00 00 04 68 6F 75 72 43 00 01 00 00 00 00 00 03 6D 69 6E 43 00 02 00 00 00 00 00 03 73 65 63 45 00 04 00 00 00 00 00 04 6D 73 65 63 AE
	*/

	rz_return_val_if_fail(obj->types, false);
	TI_INDEX = TI_INDEX | 0x80;

	OMF_type *newtype = NULL;
	if (!(newtype = RZ_NEW0(OMF_type))) {
		return false;
	}
	ut32 cct = 3;
	newtype->index = TI_INDEX;
	newtype->descr_type = rz_read_at_le8(buf, cct); // cct = 3
	obj->nb_types++;
	cct++; // cct = 4

	switch (newtype->descr_type) {
	case COMPONENT_LIST_DESCRIPTOR: {
		newtype->is_data = true;
		///< 0x20 | NrOfComp16 | Components [*]  { TI16 | OFFS32 | REP8 | POS8 | n,’name’ }
		newtype->label = "COMPONENT_LIST_DESCRIPTOR";
		newtype->descriptor.components.index = TI_INDEX;
		newtype->descriptor.components.count = rz_read_le16(buf + cct);
		newtype->descriptor.components.comp =
			RZ_NEWS0(OMF_component, newtype->descriptor.components.count);
		if (!newtype->descriptor.components.comp) {
			RZ_FREE(newtype);
			return false;
		}

		cct += 2; // cct = 6
		for (int i = 0; i < newtype->descriptor.components.count; i++) {
			OMF_component *component = newtype->descriptor.components.comp + i;
			component->index = TI_INDEX;
			component->ti = rz_read_le16(buf + cct);
			cct = cct + 2;
			component->offset = rz_read_le16(buf + cct);
			cct = cct + 4; // ?
			component->REP8 = rz_read_at_le8(buf, cct);
			cct++;
			component->POS8 = rz_read_at_le8(buf, cct);
			cct++;
			component->n = rz_read_at_le8(buf, cct);
			cct++;
			rz_str_ncpy(component->name, (const char *)&buf[cct], component->n + 1);
			cct += component->n;
		}
		break;
	}
	case POINTER_DESCRIPTOR: {
		newtype->label = "POINTER_DESCRIPTOR";
		newtype->descriptor.pointer.size = rz_read_at_le8(buf, cct); // cct = 4
		cct++; // cct = 5
		newtype->descriptor.pointer.attrib = rz_read_at_le8(buf, cct);
		cct++; // cct = 6
		///< RESERVED16
		cct += 2; // cct = 8
		newtype->descriptor.pointer.ti = rz_read_le8(buf + cct); ///< Specs bug
		// newtype->descriptor.pointer.ti = rz_read_le16(buf + cct); ///< Specs bug

#if RZ_BUILD_DEBUG
		char *attrib_str = NULL;
		if (newtype->descriptor.pointer.attrib == 0x01)
			attrib_str = "1 = Data pointer (PAGE:OFFSET)";
		if (newtype->descriptor.pointer.attrib == 0x02)
			attrib_str = "2 = Function pointer (SEG:OFFSET)";
		if (newtype->descriptor.pointer.attrib == 0x04)
			attrib_str = "4 = Huge pointer (linear 32-Bit)";
		if (newtype->descriptor.pointer.attrib == 0x05)
			attrib_str = "5 = UNKNOWN pointer";
		if (newtype->descriptor.pointer.attrib == 0x08)
			attrib_str = "8 = Xhuge pointer (linear 32-Bit)";

		// [1] = "1 = Data pointer (PAGE:OFFSET)",
		// [2] = "2 = Function pointer (SEG:OFFSET)";
		// [4] = "4 = Huge pointer (linear 32-Bit)";
		// [8] = "8 = Xhuge pointer (linear 32-Bit)";

		RZ_LOG_DEBUG("POINTER Descriptor size: 0x%02x; TI16: 0x%04x (%s), attrib_str: 0x%02x `%s`\n",
			newtype->descriptor.pointer.size,
			newtype->descriptor.pointer.ti,
			name_of_ti(obj, newtype->descriptor.pointer.ti),
			newtype->descriptor.pointer.attrib,
			attrib_str ? attrib_str : "NULL");
#endif
		break;
	}
	case ARRAY_DESCRIPTOR: {
		newtype->is_data = true;
		// 0x22 | DIMS8 | ATTRIB8 | TI16 | DIMSZ32 [*]
		cct = 4;
		newtype->descriptor.array.dims = rz_read_at_le8(buf, cct); // cct = 4
		cct++;
		newtype->descriptor.array.attrib = rz_read_at_le8(buf, cct); // cct = 5
		cct++;
		newtype->descriptor.array.ti = rz_read_at_le16(buf, cct); // cct = 6
		cct += 2;
		newtype->descriptor.array.dimsz = rz_read_at_le32(buf, cct); // cct = 8
		char array_length[255] = RZ_EMPTY;
		if (newtype->descriptor.array.dimsz != 0xFFFFFFFF) {
			rz_strf(array_length, "%d", newtype->descriptor.array.dimsz);
		}
		newtype->label = rz_str_newf("%s array[%s]",
			name_of_ti(obj, newtype->descriptor.array.ti),
			array_length);
#if RZ_BUILD_DEBUG
		RZ_LOG_DEBUG("ARRAY Descriptor dims: %d, ti: 0x%02x [%s], dimsz: %d, label: `%s`\t",
			newtype->descriptor.array.dims,
			newtype->descriptor.array.ti,
			name_of_ti(obj, newtype->descriptor.array.ti),
			newtype->descriptor.array.dimsz,
			newtype->label);
#endif
		break;
	}
	case FUNCTION_DESCRIPTOR: {
		///<  0x23 | ATTRIB8 | RTYPE-TI16 | PARMLIST-TI16
		///<  0x23 0x01 0x44 0x00 0x82 0x00 0x1f
		///<  0x23 0x01 0x4a 0x00 0x4a 0x00 0x51
		///<  0x23 0x01 0x44 0x00 0x4a 0x00 0x57

		cct = 4;
		newtype->descriptor.function.attrib = rz_read_at_le8(buf, cct); // cct = 4
		cct++;
		newtype->descriptor.function.rtype_ti = rz_read_le16(buf + cct); // cct = 5
		cct += 2;
		newtype->descriptor.function.parmlist_ti = rz_read_le16(buf + cct); // cct = 7
#if RZ_BUILD_DEBUG
		RZ_LOG_DEBUG("FUNCTION Descriptor `%s`, ret: %s, paramlist: (0x%04x) %s\n",
			newtype->descriptor.function.attrib == 1 ? "NEAR" : "FAR",
			name_of_ti(obj, newtype->descriptor.function.rtype_ti), // ti[function->rtype],
			newtype->descriptor.function.parmlist_ti,
			name_of_ti(obj, newtype->descriptor.function.parmlist_ti));
#endif
		newtype->label = rz_str_dup(newtype->descriptor.function.attrib ? "Near-Function" : "Far-Function");
		break;
	}
	case STRUCT_UNION_DESCRIPTOR: {
		newtype->label = "STRUCT_UNION_DESCRIPTOR";
		///< 0x24 | ATTRIB8 | SIZE32 | MEMBER-TI16 | tagname
		ut32 cct = 4;
		newtype->descriptor.struct_union.is_struct = (rz_read_at_le8(buf, cct) == 1); // cct = 4
		cct++;
		newtype->descriptor.struct_union.size = rz_read_le32(buf + cct); // cct = 5
		cct += 4;
		newtype->descriptor.struct_union.member_ti = rz_read_le16(buf + cct); // cct = 9
		cct += 2;
		newtype->descriptor.struct_union.n = rz_read_at_le8(buf, cct); // cct = 11

		cct++;
		rz_str_ncpy(
			newtype->descriptor.struct_union.tagname,
			(const char *)&buf[cct],
			newtype->descriptor.struct_union.n + 1); // cct = 12
#if RZ_BUILD_DEBUG
		RZ_LOG_DEBUG("STRUCT/UNION Descriptor `%s`, sizeof struct or union (%04d), MEMBER_TI16: 0x%04x ret: %s, name[%d]: `%s`\n",
			newtype->descriptor.struct_union.is_struct == 1 ? "struct" : "union",
			newtype->descriptor.struct_union.size,
			newtype->descriptor.struct_union.member_ti,
			name_of_ti(obj, newtype->descriptor.struct_union.member_ti), // "x", // ti[MEMBER_TI16],
			newtype->descriptor.struct_union.n,
			newtype->descriptor.struct_union.tagname);
#endif
		newtype->label = rz_str_dup(newtype->descriptor.struct_union.tagname);
		break;
	}
	case BITFIELD_DESCRIPTOR: {
		newtype->label = "BITFIELD_DESCRIPTOR";
		///< 0x25 | TI16 | OFFSET8 | WIDTH8
#if RZ_BUILD_DEBUG
		RZ_LOG_DEBUG("BITFIELD Descriptor \n");
#endif
		break;
	}
	default: {
		rz_warn_if_reached();
		break;
	}
	}

	ht_up_insert(obj->ht_types, TI_INDEX, newtype);
	TI_INDEX++;
	return true;
}

static int rz_bin_format_omf166_load_content(rz_bin_omf166_obj *obj, OMF_record *record, const ut8 *buf, ut64 global_ct, ut64 buf_size) {
	// generic loader just copy data from buf to content
	if (!record->size) {
		RZ_LOG_ERROR("Invalid record (size to short)\n");
		return false;
	}

	switch (record->type) {
	case OMF166_LNAMES: {
		return load_omf166_lnames(obj, record, buf, buf_size, global_ct);
	}
	case OMF166_GLBDEF:
	case OMF166_LOCSYM:
	case OMF166_PUBDEF:
	case OMF166_DEBSYM: {
		return load_omf166_global_sym_record(obj, record, buf, buf_size, global_ct);
	}
	case OMF166_BLKDEF: {
		return load_omf_blkdef(obj, buf, buf_size, record, global_ct);
	}
	case OMF166_VECTAB:
	case OMF166_PEDATA: {
		return load_omf_pedata(obj, buf, buf_size, record, global_ct);
	}
	case OMF166_LHEADR:
	case OMF166_THEADR: {
		char name[255] = RZ_EMPTY;
		ut8 n = rz_read_at_le8(buf, 3);
		rz_str_ncpy(name, (const char *)&buf[4], n + 1); // cct = 12
		RZ_LOG_DEBUG("load_omf = %s  =  [0x%08llx] (%05d) `%s`\n",
			record->type == OMF166_THEADR ? "THEADR" : "LHEADR",
			global_ct,
			record->size,
			name);
		return true;
	}
	case OMF166_MODINF: {
		return load_omf_modinf(obj, buf, buf_size, record, global_ct);
	}
	case OMF166_MODEND: {
		RZ_LOG_DEBUG("load_omf = MODEND  =  [%05d] [0x%08llx] 0x%02x (%lld)\n", record->size, global_ct, record->type, buf_size);
		return true;
	}
	case OMF166_BLKEND: {
		RZ_LOG_DEBUG("load_omf = BLKEND  =  [%05d] [0x%08llx] 0x%02x (%lld)\n", record->size, global_ct, record->type, buf_size);
		return true;
	}
	case OMF166_LINNUM: {
		return load_linnum_data(obj, buf, buf_size, record, global_ct);
	}
	case OMF166_REGDEF: {
		/*
			E3   0F 00   00 00 FC  07  49 4E 54 52 45 47 53                              FF FF 00    F1
			E3   18 00   00 20 FC  10  3F 43 5F 4D 41 49 4E 52 45 47 49 53 54 45 52 53   FF FF 00    1D
		*/
		RZ_LOG_DEBUG("load_omf = REGDEF  =  [%05d] [0x%08llx] 0x%02x (%lld)\n", record->size, global_ct, record->type, buf_size);
		return true;
	}
	case OMF166_COMMENT: {
		return load_coment_data(obj, buf, buf_size, record, global_ct);
	}
	case OMF166_GRPDEF: {
		RZ_LOG_DEBUG("load_omf = GRPDEF  =  [%05d] [0x%08llx] 0x%02x (%lld)\n", record->size, global_ct, record->type, buf_size);
		return true;
	}
	case OMF166_DEPLST: {
		return load_deplst_data(obj, buf, buf_size, record, global_ct);
	}
	case OMF166_LEDATA: {
		return load_omf_data(obj, buf, buf_size, record, global_ct);
	}

	case OMF166_TYPNEW: {
		return load_omf_typnew(obj, buf, buf_size, record, global_ct);
	}

	case OMF166_SECDEF:
	case OMF166_XSECDEF: {
		return load_omf_secdef(obj, buf, buf_size, record, global_ct);
	}
	case OMF166_UNKNOWN0: {
		/*
			60    5E 00    00 02 03 00 95 00 00 00 0C 00 00
			05  69 64 61 74 61 					= idata
			05  73 64 61 74 61 					= sdata
			05  62 64 61 74 61 					= bdata
			04  6E 65 61 72 						= near
			03  66 61 72 						= far
			0A  6E 65 61 72 20 63 6F 6E 73 74 	= near const
			09  66 61 72 20 63 6F 6E 73 74 		= far const
			04  68 75 67 65 						= huge
			0A  68 75 67 65 20 63 6F 6E 73 74 	= huge const
			05  78 68 75 67 65 					= xhuge
			0B  78 68 75 67 65 20 63 6F 6E 73 74 = xhuge const
			DB
		*/
		ut8 left = 14;
		while ((record->size - 1) > left) {
			char name[255] = RZ_EMPTY;
			ut8 n = rz_read_at_le8(buf, left);
			rz_str_ncpy(name, (const char *)&buf[++left], n + 1);
			left += n;
		}
		return true;
	}
	case OMF166_INCLUDES: {
		return load_omf_unk1(obj, buf, buf_size, record, global_ct);
	}
	case OMF166_UNKNOWN2: {
		return load_omf_unk2(obj, buf, buf_size, record, global_ct);
	}
	case OMF166_UNKNOWN3: { // ?????
		return load_omf_unk3(obj, buf, buf_size, record, global_ct);
	}
	case OMF166_UNKNOWN4: {
		return load_omf_unk4(obj, buf, buf_size, record, global_ct);
	}
	default: {
		RZ_LOG_DEBUG("load_omf: [%05d] [0x%08llx] 0x%02x (%lld)\t", record->size, global_ct, record->type, buf_size);
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

static OMF_record *rz_bin_format_omf166_load_record(rz_bin_omf166_obj *obj, const ut8 *buf, ut64 global_ct, ut64 buf_size) {
	if (!is_valid_omf166_type(*buf) && !rz_bin_checksum_omf_ok(buf, buf_size))
		return NULL;

	OMF_record *new = NULL;
	if (!(new = RZ_NEW0(OMF_record)))
		return NULL;

	new->type = *buf;
	new->size = rz_read_le16(buf + 1);

	// at least a record have a type a size and a checksum
	if (new->size > (buf_size - 3) || buf_size < 4) {
		RZ_LOG_ERROR("Invalid record (too short)\n");
		RZ_FREE(new);
		return NULL;
	}
	if (!(rz_bin_format_omf166_load_content(obj, new, buf, global_ct, buf_size))) {
		RZ_FREE(new);
		return NULL;
	}
	new->checksum = buf[2 + new->size];
	return new;
}

static int line_sample_cmp(const void *a, const void *b, void *user) {
	const OMF_linnums *sa = a;
	const OMF_linnums *sb = b;
	// first, sort by addr
	if (sa->address < sb->address) {
		return -1;
	}
	if (sa->address > sb->address) {
		return 1;
	}
	// then sort by line
	if (sa->LineNumber < sb->LineNumber) {
		return -1;
	}
	if (sa->LineNumber > sb->LineNumber) {
		return 1;
	}
	// and eventually by file because this is the most exponsive operation
	if (!strlen(sa->filename) && !strlen(sb->filename)) {
		return 0;
	}
	if (!strlen(sa->filename)) {
		return -1;
	}
	if (!strlen(sb->filename)) {
		return 1;
	}
	return strcmp(sa->filename, sb->filename);
}

static void omf166_linnums_free(void *it) {
	OMF_linnums *p = (OMF_linnums *)it;
	RZ_FREE(p);
}

static void *typnew_free(OMF_type *type) {
	rz_return_val_if_fail(type, NULL);
	if (type->descr_type == FINAL_TYPE) {
		RZ_FREE(type->label);
		RZ_FREE(type->descriptor.final_types.label);
	}
	if (type->descr_type == STRUCT_UNION_DESCRIPTOR) {
		RZ_FREE(type->label);
	}
	if (type->descr_type == FUNCTION_DESCRIPTOR) {
		RzCallable *cal = (RzCallable *)type->rz_type;
		RZ_FREE(type->label);
		RZ_FREE(cal->name);
		rz_type_free(cal->ret);
		rz_pvector_free(cal->args);
		RZ_FREE(cal);
	}
	if (type->descr_type == COMPONENT_LIST_DESCRIPTOR) {
		RZ_FREE(type->descriptor.components.comp);
	}
	RZ_FREE(type);
	return NULL;
}

static int rz_bin_format_omf166_init_internal_storage(rz_bin_omf166_obj *obj) {
	if (!(obj->ht_types = ht_up_new(NULL, (HtUPFreeValue)typnew_free))) {
		return false;
	};

	OMF_types final_types[] = {
		{ 0x40, true, 0, "untyped" },
		{ 0x41, true, 1, "bit" },
		{ 0x42, true, 8, "char" },
		{ 0x43, true, 8, "unsigned char" },
		{ 0x44, true, 32, "int" },
		{ 0x45, true, 32, "unsigned int" },
		{ 0x46, true, 32, "long" },
		{ 0x47, true, 32, "unsigned long" },
		{ 0x48, true, 32, "float" }, ///< (32-Bit IEEE)
		{ 0x49, true, 64, "double" }, ///< (64-Bit IEEE)
		{ 0x4A, false, 0, "void" },
		{ 0x4B, false, 0, "label" },
		{ 0x4C, true, 4, "<a166 BITWORD>" },
		{ 0x4D, false, 0, "<a166 NEAR>" },
		{ 0x4E, false, 0, "<a166 FAR>" },
		{ 0x4F, true, 3, "<a166 DATA3>" },
		{ 0x50, true, 4, "<a166 DATA4>" },
		{ 0x51, true, 8, "<a166 DATA8>" },
		{ 0x52, true, 16, "<a166 DATA16>" },
		{ 0x53, false, 0, "<a166 INTNO>" },
		{ 0x54, false, 0, "<a166 REGBANK>" }
	};

	for (ut8 i = 0; i < RZ_ARRAY_SIZE(final_types); i++) {
		OMF_type *newtype = NULL;
		if (!(newtype = RZ_NEW0(OMF_type))) {
			return false;
		}
		newtype->index = final_types[i].index;
		newtype->descr_type = FINAL_TYPE;
		newtype->is_data = final_types[i].is_data;
		newtype->label = rz_str_dup(final_types[i].label);
		newtype->descriptor.final_types.index = final_types[i].index;
		newtype->descriptor.final_types.is_data = final_types[i].is_data;
		newtype->descriptor.final_types.size = final_types[i].size;
		newtype->descriptor.final_types.label = rz_str_dup(final_types[i].label);
		rz_return_val_if_fail(
			ht_up_insert(obj->ht_types, final_types[i].index, newtype),
			false);
	}

#define new_pv_and_check(vec, destructor) \
	if (!(vec = rz_pvector_new((RzPVectorFree)destructor))) \
		return false;

	new_pv_and_check(obj->sections_vec, free);
	new_pv_and_check(obj->symbols_vec, free);
	new_pv_and_check(obj->blocks_vec, free);
	new_pv_and_check(obj->pe_vec, free);
	new_pv_and_check(obj->lnames_vec, free);
	new_pv_and_check(obj->deplsts_vec, free);
	new_pv_and_check(obj->linnums_vec, omf166_linnums_free);
	new_pv_and_check(obj->coments_vec, free);
	new_pv_and_check(obj->includes_vec, free);
	new_pv_and_check(obj->ledatas_vec, free);
	return true;
}

static int block_cmp(const void *a, const void *b, void *user) {
	const OMF_blocks *sa = a;
	const OMF_blocks *sb = b;
	// first, sort by addr
	if (sa->BlockOffset16 < sb->BlockOffset16) {
		return -1;
	}
	if (sa->BlockOffset16 > sb->BlockOffset16) {
		return 1;
	}
	return 0;
}

static int __find_symbol_by_paddr(const void *paddr, const void *sym, void *user) {
	OMF_symbol *p = (OMF_symbol *)sym;
	ut32 offset = p->base | p->offset;
	return (int)!(*(ut32 *)paddr == offset);
}

static int rz_bin_format_omf166_load_all_records(rz_bin_omf166_obj *obj, const ut8 *buf, ut64 size) {
	ut64 ct = 0;
	OMF_record *new_rec = NULL;
	rz_return_val_if_fail(obj, false);

	rz_bin_format_omf166_init_internal_storage(obj);

	while (ct < size) {
		if (!(new_rec = rz_bin_format_omf166_load_record(obj, buf + ct, ct, size - ct))) {
			return false;
		}
		ct += 3 + new_rec->size;
		free(new_rec);
	}

	size_t bc = rz_pvector_len(obj->blocks_vec);
	RZ_LOG_DEBUG("blocks count: %ld\n", bc);
	if (bc > 0) {
		RzPVector *v = obj->blocks_vec;
		rz_pvector_sort(v, block_cmp, NULL);
		void **it;
		rz_pvector_foreach (v, it) {
			OMF_blocks *block = (OMF_blocks *)*it;
			ut32 offset = (block->FrameNumber << 16) | block->BlockOffset16;
			void **iter = rz_pvector_find(obj->symbols_vec, &offset, __find_symbol_by_paddr, NULL);
			if (!iter) {
				RZ_LOG_DEBUG("new sym: `%s`\n", block->name);
				OMF_symbol *sym = RZ_NEW0(OMF_symbol);
				if (!sym) {
					break;
				}
				sym->index = block->FrameNumber; // ut32 index;
				sym->is_data = false;
				sym->base = block->FrameNumber << 16; // ut32 base;
				sym->n = block->n; // ut8 n; ///< n max 255, so name array len is 255

				rz_str_ncpy(sym->name2, (const char *)block->name, block->n + 1);
				sym->size = block->BlockLength16; // ut64 size;
				sym->seg_idx = block->FrameNumber; // ut16 seg_idx;
				sym->offset = offset & 0xFFFF; // ut32 offset;
				sym->ti = block->TI; // ut32 offset;
				sym->rec_type = OMF166_BLKDEF; // ut8 rec_type;
				rz_pvector_push(obj->symbols_vec, sym);
			} else {
				OMF_symbol *sym = (OMF_symbol *)*iter;
				sym->size = block->BlockLength16;
			}
		}
	}

#if RZ_BUILD_DEBUG
	size_t lc = rz_pvector_len(obj->lnames_vec);
	RZ_LOG_DEBUG("lnames count: %ld\n", lc);
	if (lc > 0) {
		RzPVector *v = obj->lnames_vec;
		void **it;
		rz_pvector_foreach (v, it) {
			OMF_lnames *lname = (OMF_lnames *)*it;
			RZ_LOG_DEBUG("LNAMES - index: %03d, name: `%s`\n", lname->index, lname->name);
		}
	}

	size_t sc = rz_pvector_len(obj->sections_vec);
	RZ_LOG_DEBUG("sections count: %ld\n", sc);
	if (sc > 0) {
		RzPVector *v = obj->sections_vec;
		void **it;
		rz_pvector_foreach (v, it) {
			OMF_sections *section = (OMF_sections *)*it;
			const char *dt = get_data_type(section->Type);
			RZ_LOG_DEBUG("sections - [%2d] %7s, seg_idx: 0x%02x, offset: 0x%04x SecTyp = %5s,   Seclen [%06d] x: %5s, h: %5s, b: 0x%x SecAtr: 0x%02x\n",
				section->index,
				section->isXSec ? "XSECDEF" : "SECDEF ",
				section->SegmentNumber8,
				section->offset,
				dt, section->Seclen,
				BOOL_STR(section->X),
				BOOL_STR(section->H),
				section->bitpos,
				section->SecAtr);
		}
	}
	size_t symlc = rz_pvector_len(obj->symbols_vec);
	RZ_LOG_DEBUG("sym count: %ld\n", symlc);
	if (symlc > 0) {
		RzPVector *v = obj->symbols_vec;
		void **it;
		rz_pvector_foreach (v, it) {
			OMF_symbol *symbol = (OMF_symbol *)*it;
			if (symbol->rec_type == OMF166_DEBSYM)
				RZ_LOG_DEBUG("debsym %s base: [0x%08x] Ofs16:[0x%04x] len:[%5lld] Rep8:[0x%02x] [%10s V%s bpos: %d] TI:[0x%04x] {%15s} (%d)`%s`\n",
					symbol->is_data ? "data" : "func",
					symbol->base,
					symbol->offset,
					symbol->size,
					symbol->REP8,
					name_of_rep8(symbol->REP8), symbol->V ? "-" : "+", symbol->bpos,
					symbol->ti,
					name_of_ti(obj, symbol->ti),
					symbol->n,
					symbol->name2);
		}
		rz_pvector_foreach (v, it) {
			OMF_symbol *symbol = (OMF_symbol *)*it;
			if (symbol->rec_type != OMF166_DEBSYM)
				RZ_LOG_DEBUG("0x%02x %s base: [0x%08x] Ofs16:[0x%04x] len:[%5lld] Rep8:[0x%02x] [%10s V%s bpos: %d] TI:[0x%04x] {%15s} (%d)`%s`\n",
					symbol->rec_type,
					symbol->is_data ? "data" : "func",
					symbol->base,
					symbol->offset,
					symbol->size,
					symbol->REP8,
					name_of_rep8(symbol->REP8), symbol->V ? "-" : "+", symbol->bpos,
					symbol->ti,
					name_of_ti(obj, symbol->ti),
					symbol->n,
					symbol->name2);
		}
	}
#endif
	size_t linc = rz_pvector_len(obj->linnums_vec);
	RZ_LOG_DEBUG("linnums count: %ld\n", linc);
	if (linc > 0) {
		RzPVector *v = obj->linnums_vec;
		rz_pvector_sort(v, line_sample_cmp, NULL);
#if RZ_BUILD_DEBUG
		void **it;
		rz_pvector_foreach (v, it) {
			OMF_linnums *linnums = (OMF_linnums *)*it;
			RZ_LOG_DEBUG("linnums fileIndex: %d, address: 0x%08llx, LineNumber: %4d, filename[%3d]: `%s`\n",
				linnums->fileIndex,
				linnums->address,
				linnums->LineNumber,
				linnums->n,
				linnums->filename);
		}
#endif
	}
#if RZ_BUILD_DEBUG
	size_t lec = rz_pvector_len(obj->ledatas_vec);
	RZ_LOG_DEBUG("ledata count: %ld\n", lec);
#endif
	return true;
}

#define PVEC_FREE(vec) \
	if (vec) \
		rz_pvector_free(vec);

void rz_bin_free_all_omf166_obj(rz_bin_omf166_obj *obj) {
	rz_return_if_fail(obj);
	PVEC_FREE(obj->sections_vec);
	PVEC_FREE(obj->symbols_vec);
	PVEC_FREE(obj->blocks_vec);
	PVEC_FREE(obj->pe_vec);
	PVEC_FREE(obj->lnames_vec);
	PVEC_FREE(obj->deplsts_vec);
	PVEC_FREE(obj->linnums_vec);
	PVEC_FREE(obj->coments_vec);
	PVEC_FREE(obj->includes_vec);
	PVEC_FREE(obj->ledatas_vec);
	return;
}

rz_bin_omf166_obj *rz_bin_internal_omf166_load(const ut8 *buf, ut64 size) {
	rz_bin_omf166_obj *ret = NULL;

	if (!(ret = RZ_NEW0(rz_bin_omf166_obj))) {
		return NULL;
	}
	if (!rz_bin_format_omf166_load_all_records(ret, buf, size)) {
		rz_bin_free_all_omf166_obj(ret);
		return NULL;
	}
	return ret;
}

bool rz_bin_omf166_get_entry(rz_bin_omf166_obj *obj, RzBinAddr *addr) {
	if (!obj) {
		return false;
	}

	const char *start_symbol_name = "main"; // Or may be "?C_STARTUP"

	if (!rz_pvector_len(obj->symbols_vec))
		return false;
	RzPVector *v = obj->symbols_vec;
	void **it;
	rz_pvector_foreach (v, it) {
		OMF_symbol *symbol = (OMF_symbol *)*it;
		if (!strcmp(symbol->name2, start_symbol_name)) {
			addr->vaddr = symbol->base + symbol->offset;
			return true;
		}
	}
	return false;
}
