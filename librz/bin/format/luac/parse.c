// SPDX-FileCopyrightText: 2017 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only


#include "librz/bin/format/luac/luac_common.h"

// static
void lua_load_block(RzBuffer *buffer, void *dest, size_t size, ut64 offset, ut64 data_size) {
	if (offset + size > data_size) {
		RZ_LOG_ERROR("Truncated load block at 0x%llx\n", offset);
		return;
	}
	rz_buf_read_at(buffer, offset, dest, size);
}

// static
ut64 lua_load_integer(RzBuffer *buffer, ut64 offset) {
	ut64 x = 0;
	rz_buf_read_le64_at(buffer, offset, &x);
	return x;
}

// static
double lua_load_number(RzBuffer *buffer, ut64 offset) {
	double x = 0;
	rz_buf_read_le64_at(buffer, offset, (ut64 *)&x);
	return x;
}

static ut32 lua_load_int(RzBuffer *buffer, ut64 offset) {
	ut32 x = 0;
	rz_buf_read_le32_at(buffer, offset, &x);
	return x;
}

// return an offset to skip string, return 1 if no string (0x80)
// TODO : clean type related issues
static ut64 lua_parse_szint(RzBuffer *buffer, int *size, ut64 offset, ut64 data_size) {
	int x = 0;
	int b = 0;
	int i = 0;
	ut32 limit = (~(ut32)0);
	limit >>= 7;

	// 1 byte at least
	if (offset + 1 > data_size) {
		RZ_LOG_ERROR("Truncated integer size at 0x%llx\n", offset);
		return 0;
	}

	do {
		ut8 tmp = 0;
		if (!rz_buf_read8_at(buffer, offset + i, &tmp)) {
			return 0;
		}
		b = tmp;
		i++;
		if (x >= limit) {
			RZ_LOG_ERROR("integer overflow while decoding integer size\n");
			return 0;
		}
		x = (x << 7) | (b & 0x7f);
	} while (((b & 0x80) == 0) && (i + offset < data_size));

	*size = x;
	return i;
}

static ut64 lua_parse_line_defined(LuaProto *proto, RzBuffer *buffer, ut64 offset, ut64 data_size, st32 minor) {
	ut64 size_offset = 0;
	int line_defined = 0;
	int last_line_defined = 0;

	if (minor == 2)
		size_offset = sizeof(LUA_INT);
	else if (minor == 3)
		size_offset = sizeof(LUA_INT) + sizeof(LUA_INT);
	else if (minor == 4) {
		size_offset = lua_parse_szint(buffer, &line_defined, offset, data_size);
		lua_check_error_offset(size_offset);
		const ut64 delta_offset = lua_parse_szint(buffer, &last_line_defined, offset + size_offset, data_size);
		lua_check_error_offset(delta_offset);
		size_offset += delta_offset;
	}

	if (minor != 4) {
		if (size_offset + offset > data_size) {
			return 0;
		}
		line_defined = lua_load_int(buffer, offset);
		offset += size_offset / 2;
		last_line_defined = lua_load_int(buffer, offset);
		offset += size_offset / 2;
	}

	/* Set Proto Member */
	proto->line_defined = line_defined;
	proto->lastline_defined = (ut64)last_line_defined;
	return (minor == 2) ? size_offset * 2 : size_offset;
}

static ut64 lua_parse_string(RzBuffer *buffer, ut8 **dest, int *str_len, ut64 offset, ut64 data_size, st32 minor) {
	ut64 size_offset = 0;
	int ret_buf_size = 0;
	int string_len = 0;
	ut8 *ret = 0x00;

	ut64 base_offset = 0;

	if (minor < 4) {
		ut8 tmp = 0;
		if (!rz_buf_read8_at(buffer, offset, &tmp)) {
			return 0;
		}
		ret_buf_size = (int)tmp;
		size_offset = (minor == 2) ? 4 : 1;

		base_offset = offset;
		// Long string
		if (ret_buf_size == 0xFF) {
			offset += size_offset;
			if (!rz_buf_read8_at(buffer, offset, &tmp)) {
				return 0;
			}
			ret_buf_size = (int)tmp;
			size_offset = 1;
		}
		offset += size_offset;
		if (minor == 2) {
			offset += 4; ///< 00 00 00 00 after char count (may be on x64)
		}
	} else {
		size_offset = lua_parse_szint(buffer, &ret_buf_size, offset, data_size);
		lua_check_error_offset(size_offset);
	}

	/* no string */
	if (ret_buf_size == 0) {
		ret = NULL;
		string_len = 0;
	} else {
		/* skip size byte */
		string_len = ret_buf_size - 1;
		ret = RZ_NEWS(ut8, ret_buf_size);
		if (ret == NULL) {
			string_len = 0;
		} else {
			if (minor > 3) {
				rz_buf_read_at(buffer, offset + size_offset, ret, string_len);
			} else {
				rz_buf_read_at(buffer, offset, ret, string_len);
			}
			ret[string_len] = 0x00;
		}
	}

	/* set to outside vars */
	if (dest && str_len) {
		*dest = ret;
		*str_len = string_len;
	} else {
		RZ_LOG_ERROR("Cannot store string\n");
	}
	if (minor == 2) {
		return offset + string_len + 1 - base_offset;
	}
	if (minor == 3) {
		return offset + string_len - base_offset;
	}
	if (minor == 4) {
		return size_offset + string_len;
	}
	return 0; // ???
}
// static
ut64 lua_parse_name(LuaProto *proto, RzBuffer *buffer, ut64 offset, ut64 data_size, st32 minor) {
	return lua_parse_string(buffer, &proto->proto_name, &proto->name_size, offset, data_size, minor);
}

static ut64 lua_parse_code(LuaProto *proto, RzBuffer *buffer, ut64 offset, ut64 data_size, st32 minor) {
	ut64 size_offset = 0;
	int code_size = 0;

	if (minor < 4) {
		size_offset = sizeof(LUA_INT);
		if (size_offset + offset > data_size) {
			return 0;
		}
		code_size = lua_load_int(buffer, offset);
	} else {
		size_offset = lua_parse_szint(buffer, &code_size, offset, data_size);
		lua_check_error_offset(size_offset);
	}
	ut64 total_size = code_size * 4 + size_offset;

	if (total_size + offset > data_size) {
		RZ_LOG_ERROR("Truncated Code at [0x%llx]\n", offset);
		return 0;
	}

	/* Set Proto Member */
	proto->code_size = code_size * 4;
	proto->code_skipped = size_offset;
	return total_size;
}

static ut64 lua_parse_const_entry(const LuaProto *proto, RzBuffer *buffer, ut64 offset, ut64 data_size, st32 minor) {
	ut8 *recv_data;
	int data_len;

	LuaConstEntry *current_entry = lua_new_const_entry();
	current_entry->offset = offset;
	ut64 base_offset = offset;
	ut64 delta_offset = 0;

	/* read TAG byte */
	if (offset + 1 > data_size) {
		return 0;
	}
	if (!rz_buf_read8_at(buffer, offset, &current_entry->tag)) {
		return 0;
	}
	offset += 1;

	ut8 tmp;

	/* read data */
	if (minor < 4) {
		// TODO : check tag Macro
		// RIGHT : 0x843
		switch (current_entry->tag) {
		case LUA_TNUMFLT:
			data_len = sizeof(LUA_NUMBER);
			recv_data = RZ_NEWS(ut8, data_len);
			lua_load_block(buffer, recv_data, data_len, offset, data_size);
			if (offset + data_len > data_size) {
				return 0;
			}
			delta_offset = data_len;
			current_entry->tag = LUA_VNUMFLT; // keep the same with 5.4 tag
			break;
		case LUA_TNUMINT:
			data_len = sizeof(LUA_INTEGER);
			recv_data = RZ_NEWS(ut8, data_len);
			lua_load_block(buffer, recv_data, data_len, offset, data_size);
			if (offset + data_len > data_size) {
				return 0;
			}
			delta_offset = data_len;
			current_entry->tag = LUA_VNUMINT; // keep the same with 5.4 tag
			break;
		case LUA_VSHRSTR:
		case LUA_VLNGSTR:
			delta_offset = lua_parse_string(buffer, &recv_data, &data_len, offset, data_size, minor);
			lua_check_error_offset(delta_offset);
			break;
			// BOOLEAN
		case LUA_TBOOLEAN:
			if (!rz_buf_read8_at(buffer, offset, &tmp)) {
				return 0;
			}

			current_entry->tag = tmp == 0 ? LUA_VFALSE : LUA_VTRUE;
			recv_data = NULL;
			data_len = 0;
			delta_offset = 1;
			break;
			// NIL
		case LUA_TNIL:
		default:
			recv_data = NULL;
			current_entry->tag = LUA_VNIL;
			data_len = 0;
			delta_offset = 0;
			break;
		}
	} else {
		// TODO : replace 8 with Macro
		switch (current_entry->tag) {
		case LUA_VNUMFLT:
		case LUA_VNUMINT:
			data_len = 8;
			recv_data = RZ_NEWS(ut8, data_len);
			lua_load_block(buffer, recv_data, data_len, offset, data_size);
			if (offset + data_len > data_size) {
				return 0;
			}
			delta_offset = data_len;
			break;
		case LUA_VSHRSTR:
		case LUA_VLNGSTR:
			delta_offset = lua_parse_string(buffer, &recv_data, &data_len, offset, data_size, minor);
			lua_check_error_offset(delta_offset);
			break;
		case LUA_VNIL:
		case LUA_VFALSE:
		case LUA_VTRUE:
		default:
			recv_data = NULL;
			data_len = 0;
			delta_offset = 0;
			break;
		}
	}


	offset += delta_offset;

	current_entry->data = recv_data;
	current_entry->data_len = data_len;

	/* add to list */
	rz_list_append(proto->const_entries, current_entry);

	return offset - base_offset;
}

static ut64 lua_parse_consts(LuaProto *proto, RzBuffer *buffer, ut64 offset, ut64 data_size, st32 minor) {
	int consts_cnt = 0;
	ut64 delta_offset = 0;

	ut64 base_offset = offset;

	/* parse number of constants */
	if (minor > 3) {
		delta_offset = lua_parse_szint(buffer, &consts_cnt, offset, data_size);
		lua_check_error_offset(delta_offset);
	} else {
		if (offset + sizeof(LUA_INT) > data_size) {
			return 0;
		}
		consts_cnt = lua_load_int(buffer, offset);
		delta_offset = sizeof(LUA_INT);
	}

	offset += delta_offset;
	for (int i = 0; i < consts_cnt; ++i) {
		// add an entry of constant
		delta_offset = lua_parse_const_entry(proto, buffer, offset, data_size, minor);
		lua_check_error_offset(delta_offset);
		offset += delta_offset;
	}
	if (minor == 3) {
		proto->const_size = offset - base_offset;
	} else {
		proto->const_size = offset - base_offset + 1;
	}

	return offset - base_offset;
}

static ut64 lua_parse_upvalue_entry(const LuaProto *proto, RzBuffer *buffer, ut64 offset, ut64 data_size, st32 minor) {

	ut64 base_offset = offset;
	LuaUpvalueEntry *current_entry = lua_new_upvalue_entry();
	current_entry->offset = base_offset;

	// no kind in lua 5.3
	const int some = (minor > 3) ? 3 : 2;

	if (offset + some > data_size) {
		return 0;
	}

	/* read instack/idx attr */
	if (!rz_buf_read8_at(buffer, offset + 0, &current_entry->instack)) {
		return 0;
	}

	if (!rz_buf_read8_at(buffer, offset + 1, &current_entry->idx)) {
		return 0;
	}

	if (minor > 2) {
		if (!rz_buf_read8_at(buffer, offset + 2, &current_entry->kind)) {
			return 0;
		}
	} else {
		current_entry->kind = 0;
	}

	offset += some;

	/* add to list */
	rz_list_append(proto->upvalue_entries, current_entry);

	return offset - base_offset;
}

static ut64 lua_parse_upvalues(LuaProto *proto, RzBuffer *buffer, ut64 offset, ut64 data_size, st32 minor) { // ?
	int upvalues_cnt = 0;
	ut64 delta_offset = 0;

	ut64 base_offset = offset;

	/* parse number of upvalues */
	if (minor > 3) {
		delta_offset = lua_parse_szint(buffer, &upvalues_cnt, offset, data_size);
		lua_check_error_offset(delta_offset);
	} else {
		delta_offset = sizeof(LUA_INT);
		if (delta_offset + offset > data_size) {
			return 0;
		}
		upvalues_cnt = lua_load_int(buffer, offset);
	}

	offset += delta_offset;

	for (int i = 0; i < upvalues_cnt; ++i) {
		delta_offset = lua_parse_upvalue_entry(proto, buffer, offset, data_size, minor);
		lua_check_error_offset(delta_offset);
		offset += delta_offset;
	}
	if (minor == 3) {
		proto->upvalue_size = offset - base_offset + 1;
	} else {
		proto->upvalue_size = offset - base_offset + 1;
	}

	if (minor == 2)
		proto->upvalue_size++;

	return offset - base_offset;
}

static ut64 lua_parse_debug(LuaProto *proto, RzBuffer *buffer, ut64 offset, ut64 data_size, st32 minor) {
	int entries_cnt;
	ut64 delta_offset = 0;
	ut64 base_offset = offset;

	/* parse line info */
	if (minor > 3) {
		delta_offset = lua_parse_szint(buffer, &entries_cnt, offset, data_size);
		lua_check_error_offset(delta_offset);
	} else {
		if (offset + sizeof(LUA_INT) > data_size) {
			printf("ERROR offset: 0x%llx (line: %d)\n", offset, __LINE__);
			return 0;
		}
		entries_cnt = lua_load_int(buffer, offset);
		delta_offset = sizeof(LUA_INT);
	}

	offset += delta_offset;
	for (int i = 0; i < entries_cnt; ++i) {
		LuaLineinfoEntry *info_entry = lua_new_lineinfo_entry();
		info_entry->offset = offset;
		if (minor > 3) {
			ut8 tmp;
			if (!rz_buf_read8_at(buffer, offset, &tmp)) {
				free(info_entry);
				return 0;
			}
			info_entry->info_data = tmp;
			offset += 1;
		} else {
			info_entry->info_data = lua_load_int(buffer, offset);
			offset += sizeof(int);
		}
		rz_list_append(proto->line_info_entries, info_entry);
	}

	if (minor > 3) {
		/* parse absline info */
		delta_offset = lua_parse_szint(buffer, &entries_cnt, offset, data_size);
		lua_check_error_offset(delta_offset);
		offset += delta_offset;
		for (int i = 0; i < entries_cnt; ++i) {
			LuaAbsLineinfoEntry *abs_info_entry = lua_new_abs_lineinfo_entry();
			abs_info_entry->offset = offset;

			delta_offset = lua_parse_szint(buffer, &abs_info_entry->pc, offset, data_size);
			lua_check_error_offset(delta_offset);
			offset += delta_offset;

			delta_offset = lua_parse_szint(buffer, &abs_info_entry->line, offset, data_size);
			lua_check_error_offset(delta_offset);
			offset += delta_offset;

			rz_list_append(proto->abs_line_info_entries, abs_info_entry);
		}
	}

	/* parse local vars */
	if (minor > 3) {
		delta_offset = lua_parse_szint(buffer, &entries_cnt, offset, data_size);
		lua_check_error_offset(delta_offset);
	} else {
		// delta_offset = lua_parse_szint(buffer, &entries_cnt, offset, data_size);
		// lua_check_error_offset(delta_offset);
#if 1
		if (offset + sizeof(LUA_INT) > data_size) {
			printf("ERROR offset: 0x%llx (line: %d)\n", offset, __LINE__);
			return 0;
		}
		entries_cnt = lua_load_int(buffer, offset);
		delta_offset = sizeof(LUA_INT);
#else
		if (offset + 1 > data_size) {
			printf("ERROR offset: 0x%llx (line: %d)\n", offset, __LINE__);
			return 0;
		}
		ut8 tmp;
		if (!rz_buf_read8_at(buffer, offset, &tmp)) {
			return 0;
		}
		entries_cnt = tmp;
		delta_offset = 1;
#endif
	}
	offset += delta_offset;
	for (int i = 0; i < entries_cnt; ++i) {
		LuaLocalVarEntry *var_entry = lua_new_local_var_entry();
		var_entry->offset = offset;

		/* string */
		delta_offset = lua_parse_string(
			buffer,
			&var_entry->varname, &var_entry->varname_len,
			offset, data_size, minor);
		lua_check_error_offset(delta_offset);
		offset += delta_offset;

		/* start pc -- int */
		if (minor > 3) {
			delta_offset = lua_parse_szint(buffer, &var_entry->start_pc, offset, data_size);
			lua_check_error_offset(delta_offset);
		} else {
			if (offset + sizeof(LUA_INT) + sizeof(LUA_INT) > data_size) {
			printf("ERROR offset: 0x%llx (line: %d)\n", offset, __LINE__);
				return 0;
			}
			var_entry->start_pc = lua_load_int(buffer, offset);
			delta_offset = sizeof(LUA_INT);
		}

		offset += delta_offset;

		/* end pc -- int */
		if (minor > 3) {
			delta_offset = lua_parse_szint(buffer, &var_entry->end_pc, offset, data_size);
			lua_check_error_offset(delta_offset);
		} else {
			var_entry->end_pc = lua_load_int(buffer, offset);
			delta_offset = sizeof(LUA_INT);
		}
		offset += delta_offset;

		rz_list_append(proto->local_var_info_entries, var_entry);
	}

	/* parse upvalue */
	if (minor > 3) {
		delta_offset = lua_parse_szint(buffer, &entries_cnt, offset, data_size);
		lua_check_error_offset(delta_offset);
	} else {
		if (offset + sizeof(LUA_INT) > data_size) {
			printf("ERROR offset: 0x%llx (line: %d)\n", offset, __LINE__);
			return 0;
		}
		entries_cnt = lua_load_int(buffer, offset);
		delta_offset = sizeof(LUA_INT);
	}
	offset += delta_offset;
	for (int i = 0; i < entries_cnt; ++i) {
		LuaDbgUpvalueEntry *dbg_upvalue_entry = lua_new_dbg_upvalue_entry();
		dbg_upvalue_entry->offset = offset;

		delta_offset = lua_parse_string(
			buffer,
			&dbg_upvalue_entry->upvalue_name,
			&dbg_upvalue_entry->name_len,
			offset, data_size, minor);
		lua_check_error_offset(delta_offset);
		offset += delta_offset;

		rz_list_append(proto->dbg_upvalue_entries, dbg_upvalue_entry);
	}

	proto->debug_size = offset - base_offset + 1;
	return offset - base_offset;
}

static ut64 lua_parse_protos(LuaProto *proto, RzBuffer *buffer, ut64 offset, ut64 data_size, st32 minor) {
	rz_return_val_if_fail(proto, 0);
	int proto_cnt = 0;
	ut64 delta_offset = 0;
	const ut64 base_offset = offset; // store origin offset

	if (minor > 3) {
		delta_offset = lua_parse_szint(buffer, &proto_cnt, offset, data_size); // skip size bytes
		lua_check_error_offset(delta_offset);
	} else {
		delta_offset = sizeof(LUA_INT);
		if (offset + delta_offset > data_size) {
			return 0;
		}
		proto_cnt = lua_load_int(buffer, offset);
	}

	offset += delta_offset;

	for (int i = 0; i < proto_cnt; ++i) {
		LuaProto *current_proto = lua_parse_body(buffer, offset, data_size, minor);
		lua_return_if_null(current_proto);
		rz_list_append(proto->proto_entries, current_proto);
		offset += current_proto->size - 1; // update offset
	}

	// return the delta between offset and base_offset
	return offset - base_offset;
}

LuaProto *lua_parse_body2(RzBuffer *buffer, ut64 base_offset, ut64 data_size, st32 minor) {

	LuaProto *ret_proto = lua_new_proto_entry();
	rz_return_val_if_fail(ret_proto, NULL);

	// start parsing
	ut64 offset = base_offset;

	// record offset of main proto
	ret_proto->offset = offset;

	// parse proto name
	ut64 delta_offset = lua_parse_name(ret_proto, buffer, offset, data_size, minor);
	lua_check_error_offset_proto(delta_offset, ret_proto);
	offset += delta_offset;

	/* parse line defined info */
	delta_offset = lua_parse_line_defined(ret_proto, buffer, offset, data_size, minor);
	lua_check_error_offset_proto(delta_offset, ret_proto);
	offset += delta_offset;

	/* parse num params max_stack_size */
	if (offset + 3 > data_size) {
		lua_free_proto_entry(ret_proto);
		return NULL;
	}
	if (!rz_buf_read8_at(buffer, offset + 0, &ret_proto->num_params) ||
		!rz_buf_read8_at(buffer, offset + 1, &ret_proto->is_vararg) ||
		!rz_buf_read8_at(buffer, offset + 2, &ret_proto->max_stack_size)) {
		lua_free_proto_entry(ret_proto);
		return NULL;
	}
	offset += 3;

	/* parse code */
	ret_proto->code_offset = offset;
	delta_offset = lua_parse_code(ret_proto, buffer, offset, data_size, minor);
	lua_check_error_offset_proto(delta_offset, ret_proto);
	offset += delta_offset;

	/* parse constants */
	ret_proto->const_offset = offset;
	delta_offset = lua_parse_consts(ret_proto, buffer, offset, data_size, minor);
	lua_check_error_offset_proto(delta_offset, ret_proto);
	offset += delta_offset;

	/* parse upvalues */
	ret_proto->upvalue_offset = offset;
	delta_offset = lua_parse_upvalues(ret_proto, buffer, offset, data_size, minor);
	lua_check_error_offset_proto(delta_offset, ret_proto);
	offset += delta_offset;

	/* parse inner protos */
	ret_proto->inner_proto_offset = offset;
	delta_offset = lua_parse_protos(ret_proto, buffer, offset, data_size, minor);
	lua_check_error_offset_proto(delta_offset, ret_proto);
	offset += delta_offset;

	/* specially handle recursive protos size */
	ret_proto->inner_proto_size = offset - ret_proto->inner_proto_offset;

	/* parse debug */
	ret_proto->debug_offset = offset;
	delta_offset = lua_parse_debug(ret_proto, buffer, offset, data_size, minor);
	// lua_check_error_offset_proto(delta_offset, ret_proto);
	offset += delta_offset;

	ret_proto->size = offset - base_offset + 1;

	return ret_proto;
}

LuaProto *lua_parse_body(RzBuffer *buffer, ut64 base_offset, ut64 data_size, st32 minor) {
	LuaProto *ret_proto = lua_new_proto_entry(); /* constructed proto for return */
	rz_return_val_if_fail(ret_proto, NULL);

	ut64 delta_offset = 0;

	// start parsing
	ut64 offset = base_offset; /* record offset */

	/* record offset of main proto */
	ret_proto->offset = offset;

	if ((minor > 2) && (minor != 5)) {
		/* parse proto name of main proto */
		delta_offset = lua_parse_name(ret_proto, buffer, offset, data_size, minor);
		lua_check_error_offset_proto(delta_offset, ret_proto);
		offset += delta_offset;
	}


	/* parse line defined info */
	delta_offset = lua_parse_line_defined(ret_proto, buffer, offset, data_size, minor);
	lua_check_error_offset_proto(delta_offset, ret_proto);
	offset += delta_offset;

	/* parse num params max_stack_size */
	if (offset + 3 > data_size) {
		lua_free_proto_entry(ret_proto);
		return NULL;
	}

	if (!rz_buf_read8_at(buffer, offset + 0, &ret_proto->num_params) ||
		!rz_buf_read8_at(buffer, offset + 1, &ret_proto->is_vararg) ||
		!rz_buf_read8_at(buffer, offset + 2, &ret_proto->max_stack_size)) {
		lua_free_proto_entry(ret_proto);
		return NULL;
	}
	offset += 3;

	/* parse code */
	ret_proto->code_offset = offset;
	delta_offset = lua_parse_code(ret_proto, buffer, offset, data_size, minor);
	lua_check_error_offset_proto(delta_offset, ret_proto);
	offset += delta_offset;

	/* parse constants */
	ret_proto->const_offset = offset;
	delta_offset = lua_parse_consts(ret_proto, buffer, offset, data_size, minor);
	lua_check_error_offset_proto(delta_offset, ret_proto);
	offset += delta_offset;

	if (minor == 2) {
		/* parse inner protos */
		ret_proto->inner_proto_offset = offset;
		delta_offset = lua_parse_protos(ret_proto, buffer, offset, data_size, minor);
		lua_check_error_offset_proto(delta_offset, ret_proto);
		offset += delta_offset;

		/* specially handle recursive protos size */
		ret_proto->inner_proto_size = offset - ret_proto->inner_proto_offset;
	}

	if (minor > 2) {
		/* parse upvalues */
		ret_proto->upvalue_offset = offset;
		delta_offset = lua_parse_upvalues(ret_proto, buffer, offset, data_size, minor);
		lua_check_error_offset_proto(delta_offset, ret_proto);
		offset += delta_offset;

		/* parse inner protos */
		ret_proto->inner_proto_offset = offset;
		delta_offset = lua_parse_protos(ret_proto, buffer, offset, data_size, minor);
		lua_check_error_offset_proto(delta_offset, ret_proto);
		offset += delta_offset;

		/* specially handle recursive protos size */
		ret_proto->inner_proto_size = offset - ret_proto->inner_proto_offset;
	}

	if (minor == 2) {
		/* parse upvalues */
		ret_proto->upvalue_offset = offset;
		delta_offset = lua_parse_upvalues(ret_proto, buffer, offset, data_size, minor);
		lua_check_error_offset_proto(delta_offset, ret_proto);
		offset += delta_offset;

		/* parse proto name of main proto */
		delta_offset = lua_parse_name(ret_proto, buffer, offset, data_size, minor);
		lua_check_error_offset_proto(delta_offset, ret_proto);
		offset += delta_offset;
	}
	/* parse debug */
	ret_proto->debug_offset = offset;
	delta_offset = lua_parse_debug(ret_proto, buffer, offset, data_size, minor);
	lua_check_error_offset_proto(delta_offset, ret_proto);
	offset += delta_offset;

	ret_proto->size = offset - base_offset + 1;

	return ret_proto;
}

typedef struct {
	ut8 int_size_offset;
	ut8 sizet_size_offset;
	ut8 instruction_size_offset;
	ut8 integer_size_offset;
	ut8 number_size_offset;
	ut8 integer_valid_offset;
	ut8 number_valid_offset;
} offsets_t;
offsets_t offsets[5] = {
	{
		.int_size_offset = 0,
		.sizet_size_offset = 0,
		.instruction_size_offset = 0,
		.integer_size_offset = 0,
		.number_size_offset = 0,
	}, {
		.int_size_offset = 0,
		.sizet_size_offset = 0,
		.instruction_size_offset = 0,
		.integer_size_offset = 0,
		.number_size_offset = 0,
	}, {
		.int_size_offset = LUAC_52_INT_SIZE_OFFSET,
		.sizet_size_offset = LUAC_52_SIZET_SIZE_OFFSET,
		.instruction_size_offset = LUAC_52_INSTRUCTION_SIZE_OFFSET,
		.integer_size_offset = LUAC_52_INTEGER_SIZE_OFFSET,
		.number_size_offset = LUAC_52_NUMBER_SIZE_OFFSET,
	}, {
		.int_size_offset = LUAC_53_INT_SIZE_OFFSET,
		.sizet_size_offset = LUAC_53_SIZET_SIZE_OFFSET,
		.instruction_size_offset = LUAC_53_INSTRUCTION_SIZE_OFFSET,
		.integer_size_offset = LUAC_53_INTEGER_SIZE_OFFSET,
		.number_size_offset = LUAC_53_NUMBER_SIZE_OFFSET,
		.integer_valid_offset = LUAC_53_INTEGER_VALID_OFFSET,
		.number_valid_offset = LUAC_53_NUMBER_VALID_OFFSET,
	}, {
		.int_size_offset = LUAC_54_INSTRUCTION_SIZE_OFFSET,
		.sizet_size_offset = LUAC_54_NUMBER_SIZE_OFFSET,
		.instruction_size_offset = LUAC_54_INSTRUCTION_SIZE_OFFSET,
		.integer_size_offset = LUAC_54_INTEGER_SIZE_OFFSET,
		.number_size_offset = LUAC_54_NUMBER_SIZE_OFFSET,
		.integer_valid_offset = LUAC_54_INTEGER_VALID_OFFSET,
		.number_valid_offset = LUAC_54_NUMBER_VALID_OFFSET,
	}
};

static inline st8 int_size_offset(st32 minor) {
	return offsets[minor].int_size_offset;
}

static inline st8 sizet_size_offset(st32 minor) {
	return offsets[minor].sizet_size_offset;
}

static inline st8 instruction_size_offset(st32 minor) {
	return offsets[minor].instruction_size_offset;
}

static inline st8 integer_size_offset(st32 minor) {
	return offsets[minor].integer_size_offset;
}

static inline st8 number_size_offset(st32 minor) {
	return offsets[minor].number_size_offset;
}

static inline st8 integer_valid_offset(st32 minor) {
	return offsets[minor].integer_valid_offset;
}

static inline st8 number_valid_offset(st32 minor) {
	return offsets[minor].number_valid_offset;
}

RzBinInfo *lua_parse_header(const RzBinFile *bf, st32 major, st32 minor) {
	// RzBinInfo *ret = NULL;

	st64 reat = bf->size;
	if (reat < luac_hdrsize(minor)) {
		RZ_LOG_ERROR("Truncated Header\n");
		return NULL;
	}
	RzBuffer *buffer = bf->buf;


	ut8 int_size = 0;
	ut8 sizet_size = 0;

	/* read header members from work buffer */
	ut8 luac_format = 0;
	if (!rz_buf_read8_at(buffer, LUAC_FORMAT_OFFSET, &luac_format)) {
		return NULL;
	}

	if (minor <= 4) {
		if (!rz_buf_read8_at(buffer, int_size_offset(minor), &int_size)) {
			return NULL;
		}
		if (!rz_buf_read8_at(buffer, sizet_size_offset(minor), &sizet_size)) {
			return NULL;
		}
	}

	ut8 instruction_size;
	if (!rz_buf_read8_at(buffer, instruction_size_offset(minor), &instruction_size)) {
		return NULL;
	}
	ut8 integer_size;
	if (!rz_buf_read8_at(buffer, integer_size_offset(minor), &integer_size)) {
		return NULL;
	}
	ut8 number_size;
	if (!rz_buf_read8_at(buffer, number_size_offset(minor), &number_size)) {
		return NULL;
	}
	// if (minor != 2) {
	// 	ut64 integer_valid = lua_load_integer(buffer, LUAC_53_INTEGER_VALID_OFFSET);
	// 	double number_valid = lua_load_number(buffer, LUAC_53_NUMBER_VALID_OFFSET);
	// }

	/* Common Ret */
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	rz_return_val_if_fail(ret, NULL);

	ret->file = rz_str_dup(bf->file);
	ret->type = rz_str_newf("Lua %c.%c compiled file", major + '0', minor + '0');
	ret->bclass = rz_str_dup("Lua compiled file");
	ret->rclass = rz_str_dup("luac");
	ret->arch = rz_str_dup("luac");
	ret->machine = rz_str_newf("Lua %c.%c VM", major + '0', minor + '0');
	ret->os = rz_str_newf("%c.%c", major + '0', minor + '0');
	ret->cpu = rz_str_newf("%c.%c", major + '0', minor + '0');
	ret->bits = 8;

	/* official format ? */
	if (luac_format != LUAC_FORMAT) {
		ret->compiler = rz_str_dup("Unofficial Lua Compiler");
		return ret;
	}
	ret->compiler = rz_str_dup("Official Lua Compiler");
	if (minor == 2)
		return ret;

	/* Check Size */
	// TODO : remove this check and process different compiler options
	if ((instruction_size != sizeof(LUA_INSTRUCTION)) ||
		(integer_size != sizeof(LUA_INTEGER)) ||
		(number_size != sizeof(LUA_NUMBER))) {
		RZ_LOG_ERROR("Size definition does not match with the expected size\n");
		return ret;
	}
	if (minor == 4) {
		if ((int_size != sizeof(LUA_INT)) ||
			(sizet_size != sizeof(size_t))) {
			RZ_LOG_ERROR("Size definition does not match with the expected size\n");
			return ret;
		}
	}

	/* Check endian */

	// if (minor != 2) {
		ut64 int_valid = lua_load_integer(buffer, integer_valid_offset(minor));
		double number_valid = lua_load_number(buffer, number_valid_offset(minor));
		if (int_valid != LUAC_INT_VALIDATION) {
			RZ_LOG_ERROR("Integer format does not match with the expected integer\n");
			return ret;
		} else if (number_valid != LUAC_NUMBER_VALIDATION) {
			RZ_LOG_ERROR("Number format does not match with the expected number\n");
			return ret;
		}
	// }

	/* parse source file name */
	char *src_file_name = NULL;
	int name_len;
	lua_parse_string(buffer, ((ut8 **)&(src_file_name)), &name_len, LUAC_FILENAME_OFFSET(minor), bf->size, minor);

	/* put source file info into GUID */
	ret->guid = rz_str_dup(src_file_name ? src_file_name : "stripped");
	free(src_file_name);

	return ret;
}
