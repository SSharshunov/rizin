// SPDX-FileCopyrightText: 2025 Alexandru Aioanei <alex03aioanei@gmail.com>
// SPDX-FileCopyrightText: 2025 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file asm_c166.c
 * \brief Assembly and disassembly plugin for C166 architecture
 *
 * Provides functionality for disassembling C166 machine code into assembly language
 * representation and assembling C166 assembly code into machine code.
 */

#include <stdio.h>
#include <string.h>
#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_asm.h>

#include "librz/arch/isa/c166/c166_disas.h"

RZ_API bool check_unused_opcode(const ut8 opcode) {
	switch (opcode) {
	case 0x3b:
	case 0x44:
	case 0x45:
	case 0x8B:
	case 0x95:
	case 0xC1:
	case 0xC7:
	case 0xE3:
	case 0xE5:
	case 0xF5:
	case 0xF8:
	case 0xF9:
		return true;
	default:
		break;
	}
	return false;
}

/**
 * \brief C166 disassembly function
 * \param a Pointer to RzAsm structure
 * \param op Pointer to RzAsmOp structure to be filled with disassembly data
 * \param buf Buffer containing instruction bytes
 * \param len Length of the buffer
 * \return Length of the disassembled instruction or 0 on failure
 *
 * Disassembles a single C166 instruction and populates the op->buf_asm with
 * human-readable assembly representation. Uses the c166_decode_command helper function
 * to perform the actual disassembly.
 */

static st32 disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, st32 len) {
	rz_return_val_if_fail(a && op && buf, -1);

	C166State *state = (C166State *)a->plugin_data;
	if (!state) {
		RZ_LOG_FATAL("C166State was NULL.\n");
	}

	C166_Inst inst = { 0 };
	inst.addr = (ut32)a->pc;
	if (check_unused_opcode(buf[0])) {
		rz_asm_op_setf_asm(op, FMT_BYTE, buf[0]);
		op->size = 1;
		return op->size;
	}
	st32 ret = c166_decode_command(state, &inst, buf, len);
	if (RZ_STR_EQ(inst.instr, "invalid")) {
		rz_asm_op_setf_asm(op, FMT_WORD, buf[0], buf[1]);
	} else {
		if (RZ_STR_ISNOTEMPTY(inst.operands)) {
			rz_asm_op_setf_asm(op, FMT7, inst.instr, inst.operands);
		} else {
			rz_asm_op_setf_asm(op, "%s", inst.instr);
		}
		op->size = ret;
	}
	// op->asm_toks = rz_asm_tokenize_asm_regex(&op->buf_asm, state->token_patterns);
	// op->asm_toks->op_type = op->op_type; // ???
	return op->size;
}

#define TOKEN(_type, _pat) \
	do { \
		RzAsmTokenPattern *pat = RZ_NEW0(RzAsmTokenPattern); \
		pat->type = RZ_ASM_TOKEN_##_type; \
		pat->pattern = rz_str_dup(_pat); \
		rz_pvector_push(pvec, pat); \
	} while (0)

static RZ_OWN RzPVector /*<RzAsmTokenPattern *>*/ *get_token_patterns() {
	RzPVector *pvec = rz_pvector_new(rz_asm_token_pattern_free);
	if (!pvec) {
		return NULL;
	}

	TOKEN(META, "(\\[|\\]|-)");
	// TOKEN(META, "(\\+[rc]?)");

	TOKEN(NUMBER, "(0x[[:digit:]abcdef]+)");

	TOKEN(REGISTER, "(r[0-9]{1,2}|DPP[0-3]|TFR|SP|PSW|MD[LHC]|r[hl][0-9]{1,2})");

	TOKEN(MNEMONIC, "^([a-zA-Z_]+)");

	TOKEN(SEPARATOR, "([[:blank:]]+)|([,.;#\\(\\)\\{\\}:])");

	TOKEN(NUMBER, "([[:digit:]]+)");

	return pvec;
}

static bool init(void **user) {

	C166State *state = RZ_NEW0(C166State);
	if (!state) {
		RZ_LOG_FATAL("Could not allocate memory for C166State!\n");
		return false;
	}
	// rz_return_val_if_fail(state, false);

	C166ExtState ext = {
		.esfr = false,
		.mode = C166_EXT_MODE_NONE,
		.i = 0,
		.value = 0
	};

	state->ext = ext;
	state->last_addr = 0;

	state->token_patterns = get_token_patterns();
	rz_asm_compile_token_patterns(state->token_patterns);

	*user = state; // user = RzAsm.plugin_data
	return true;
}

static bool fini(void *user) {
	rz_return_val_if_fail(user, false);
	C166State *state = (C166State *)user;
	rz_pvector_free(state->token_patterns);
	free(state);
	return true;
}

RzAsmPlugin rz_asm_plugin_c166 = {
	.name = "c166",
	.arch = "c166",
	.bits = 16,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.desc = "Siemens/Infineon C166 microcontroller disassembler",
	.license = "LGPL3",
	.disassemble = &disassemble,
	.init = &init,
	.fini = &fini,
	.cpus = "c166-generic"
};
