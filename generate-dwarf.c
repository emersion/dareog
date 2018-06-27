/*
 * Copyright (C) 2017 Josh Poimboeuf <jpoimboe@redhat.com>
 * Copyright (C) 2018 emersion
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#define _POSIX_C_SOURCE 200809L
#include <dwarf.h>
#include <dwarfw.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "asm/orc_types.h"
#include "dareog.h"

// Fallback for systems without this "read and write, mmaping if possible" cmd
#ifndef ELF_C_RDWR_MMAP
#define ELF_C_RDWR_MMAP ELF_C_RDWR
#endif

static Elf_Scn *find_section_by_name(Elf *elf, const char *section_name) {
	size_t sections_num;
	if (elf_getshdrnum(elf, &sections_num)) {
		return NULL;
	}

	size_t shstrndx;
	if (elf_getshdrstrndx(elf, &shstrndx)) {
		return NULL;
	}

	for (size_t i = 0; i < sections_num; ++i) {
		Elf_Scn *s = elf_getscn(elf, i);
		if (s == NULL) {
			return NULL;
		}

		GElf_Shdr sh;
		if (!gelf_getshdr(s, &sh)) {
			return NULL;
		}

		char *name = elf_strptr(elf, shstrndx, sh.sh_name);
		if (name == NULL) {
			return NULL;
		}

		if (strcmp(name, section_name) == 0) {
			return s;
		}
	}

	return NULL;
}

static Elf_Scn *create_section(Elf *elf, const char *name) {
	Elf_Scn *scn = elf_newscn(elf);
	if (scn == NULL) {
		fprintf(stderr, "elf_newscn() failed: %s\n", elf_errmsg(-1));
		return NULL;
	}

	GElf_Shdr shdr;
	if (!gelf_getshdr(scn, &shdr)) {
		fprintf(stderr, "gelf_getshdr() failed\n");
		return NULL;
	}

	// Add section name to .shstrtab
	Elf_Scn *shstrtab = find_section_by_name(elf, ".shstrtab");
	if (shstrtab == NULL) {
		fprintf(stderr, "can't find .shstrtab section\n");
		return NULL;
	}

	GElf_Shdr shstrtab_shdr;
	if (!gelf_getshdr(shstrtab, &shstrtab_shdr)) {
		fprintf(stderr, "gelf_getshdr(shstrtab) failed\n");
		return NULL;
	}

	Elf_Data *shstrtab_data = elf_newdata(shstrtab);
	if (shstrtab_data == NULL) {
		fprintf(stderr, "elf_newdata(shstrtab) failed\n");
		return NULL;
	}
	shstrtab_data->d_buf = strdup(name);
	shstrtab_data->d_size = strlen(name) + 1;
	shstrtab_data->d_align = 1;

	shdr.sh_name = shstrtab_shdr.sh_size;
	shstrtab_shdr.sh_size += shstrtab_data->d_size;

	if (!gelf_update_shdr(scn, &shdr)) {
		fprintf(stderr, "gelf_update_shdr() failed\n");
		return NULL;
	}

	if (!gelf_update_shdr(shstrtab, &shstrtab_shdr)) {
		fprintf(stderr, "gelf_update_shdr(shstrtab) failed\n");
		return NULL;
	}

	return scn;
}

static int find_section_symbol(Elf *elf, size_t index, GElf_Sym *sym) {
	Elf_Scn *symtab = find_section_by_name(elf, ".symtab");
	if (symtab == NULL) {
		fprintf(stderr, "can't find .symtab section\n");
		return -1;
	}

	Elf_Data *symtab_data = elf_getdata(symtab, NULL);
	if (symtab_data == NULL) {
		fprintf(stderr, "elf_getdata(symtab) failed\n");
		return -1;
	}

	GElf_Shdr symtab_shdr;
	if (!gelf_getshdr(symtab, &symtab_shdr)) {
		fprintf(stderr, "gelf_getshdr(symtab) failed\n");
		return -1;
	}

	int symbols_nr = symtab_shdr.sh_size / symtab_shdr.sh_entsize;
	for (int i = 0; i < symbols_nr; ++i) {
		if (!gelf_getsym(symtab_data, i, sym)) {
			fprintf(stderr, "gelf_getsym() failed\n");
			continue;
		}

		if (GELF_ST_TYPE(sym->st_info) == STT_SECTION &&
				index == sym->st_shndx) {
			return i;
		}
	}

	return -1;
}

static Elf_Scn *create_debug_frame_section(Elf *elf, const char *name,
		char *buf, size_t len) {
	Elf_Scn *scn = create_section(elf, name);
	if (scn == NULL) {
		return NULL;
	}

	Elf_Data *data = elf_newdata(scn);
	if (data == NULL) {
		fprintf(stderr, "elf_newdata() failed: %s\n", elf_errmsg(-1));
		return NULL;
	}
	data->d_align = 4;
	data->d_buf = buf;
	data->d_size = len;

	GElf_Shdr shdr;
	if (!gelf_getshdr(scn, &shdr)) {
		fprintf(stderr, "gelf_getshdr() failed\n");
		return NULL;
	}
	shdr.sh_size = len;
	shdr.sh_type = SHT_PROGBITS;
	shdr.sh_addralign = 1;
	shdr.sh_flags = SHF_ALLOC;
	if (!gelf_update_shdr(scn, &shdr)) {
		fprintf(stderr, "gelf_update_shdr() failed\n");
		return NULL;
	}

	return scn;
}

static Elf_Scn *create_rela_section(Elf *elf, const char *name, Elf_Scn *base,
		char *buf, size_t len) {
	Elf_Scn *scn = create_section(elf, name);
	if (scn == NULL) {
		fprintf(stderr, "can't create rela section\n");
		return NULL;
	}

	Elf_Data *data = elf_newdata(scn);
	if (!data) {
		fprintf(stderr, "elf_newdata() failed\n");
		return NULL;
	}

	data->d_buf = buf;
	data->d_size = len;
	data->d_align = 1;

	Elf_Scn *symtab = find_section_by_name(elf, ".symtab");
	if (symtab == NULL) {
		fprintf(stderr, "can't find .symtab section\n");
		return NULL;
	}

	GElf_Shdr shdr;
	if (!gelf_getshdr(scn, &shdr)) {
		fprintf(stderr, "gelf_getshdr() failed\n");
		return NULL;
	}
	shdr.sh_size = data->d_size;
	shdr.sh_type = SHT_RELA;
	shdr.sh_addralign = 8;
	shdr.sh_link = elf_ndxscn(symtab);
	shdr.sh_info = elf_ndxscn(base);
	shdr.sh_flags = SHF_INFO_LINK;
	if (!gelf_update_shdr(scn, &shdr)) {
		fprintf(stderr, "gelf_update_shdr() failed\n");
		return NULL;
	}

	return scn;
}


static unsigned int reg_number(unsigned int reg) {
	switch (reg) {
	case ORC_REG_BP:
		return 6;
	case ORC_REG_SP:
		return 7;
	case ORC_REG_R10:
		return 10;
	case ORC_REG_R13:
		return 13;
	default:
		return 0;
	}
}

static unsigned int indirect_reg_number(unsigned int reg) {
	switch (reg) {
	case ORC_REG_BP_INDIRECT:
		return reg_number(ORC_REG_BP);
	case ORC_REG_SP_INDIRECT:
		return reg_number(ORC_REG_SP);
	default:
		return reg_number(ORC_REG_UNDEFINED);
	}
}

static int write_fde_instruction(struct dwarfw_fde *fde,
		struct orc_entry *orc_entry, unsigned long long loc, FILE *f) {
	unsigned int reg;
	if (orc_entry->sp_reg == ORC_REG_UNDEFINED) {
		fprintf(stderr, "warning: dareog: undefined sp_reg at 0x%llx\n", loc);

		// write an undefined ra
		dwarfw_cie_write_undefined(fde->cie, 16, f);
	} else if ((reg = reg_number(orc_entry->sp_reg)) != 0) {
		dwarfw_cie_write_def_cfa(fde->cie, reg, orc_entry->sp_offset, f);

		// ra's offset is fixed at -8
		dwarfw_cie_write_offset(fde->cie, 16, -8, f);
	} else if ((reg = indirect_reg_number(orc_entry->sp_reg)) != 0) {
		char *expr_buf;
		size_t expr_len;
		FILE *expr_f = open_memstream(&expr_buf, &expr_len);
		if (expr_f == NULL) {
			fprintf(stderr, "open_memstream() failed\n");
			return -1;
		}
		dwarfw_op_write_bregx(reg, orc_entry->sp_offset, expr_f);
		dwarfw_op_write_deref(expr_f);
		fclose(expr_f);

		dwarfw_cie_write_def_cfa_expression(fde->cie, expr_buf, expr_len, f);
		free(expr_buf);
	} else {
		fprintf(stderr, "error: dareog: unsupported sp_reg %d at 0x%llx\n",
			orc_entry->sp_reg, loc);
		return -1;
	}

	if (orc_entry->bp_reg == ORC_REG_PREV_SP) {
		dwarfw_cie_write_offset(fde->cie, reg_number(ORC_REG_BP),
			orc_entry->bp_offset, f);
	} else if (orc_entry->bp_reg == ORC_REG_UNDEFINED) {
		dwarfw_cie_write_undefined(fde->cie, reg_number(ORC_REG_BP), f);
	} else if ((reg = reg_number(orc_entry->bp_reg)) != 0) {
		char *expr_buf;
		size_t expr_len;
		FILE *expr_f = open_memstream(&expr_buf, &expr_len);
		if (expr_f == NULL) {
			fprintf(stderr, "open_memstream() failed\n");
			return -1;
		}
		dwarfw_op_write_bregx(reg, orc_entry->bp_offset, expr_f);
		fclose(expr_f);

		dwarfw_cie_write_expression(fde->cie, reg_number(ORC_REG_BP),
			expr_buf, expr_len, f);
		free(expr_buf);
	} else if ((reg = indirect_reg_number(orc_entry->bp_reg)) != 0) {
		char *expr_buf;
		size_t expr_len;
		FILE *expr_f = open_memstream(&expr_buf, &expr_len);
		if (expr_f == NULL) {
			fprintf(stderr, "open_memstream() failed\n");
			return -1;
		}
		dwarfw_op_write_bregx(reg, orc_entry->bp_offset, expr_f);
		dwarfw_op_write_deref(expr_f);
		fclose(expr_f);

		dwarfw_cie_write_expression(fde->cie, reg_number(ORC_REG_BP),
			expr_buf, expr_len, f);
		free(expr_buf);
	} else {
		fprintf(stderr, "error: dareog: unsupported bp_reg %d at 0x%llx\n",
			orc_entry->bp_reg, loc);
		return -1;
	}

	return 0;
}

static int write_all_fde_instructions(struct dareog_state *state,
		struct dwarfw_fde *fde, ssize_t shndx, unsigned long long start_loc,
		unsigned long long stop_loc, FILE *f) {
	struct orc_entry *orc = state->orc;
	struct orc_entry *start_orc_entry = NULL;

	unsigned long long loc = start_loc, next_loc;
	int nr_entries = state->orc_size / sizeof(*orc);
	for (int i = 0; i < nr_entries; i++) {
		if (state->rela_orc_ip) {
			GElf_Rela rela;
			if (!gelf_getrela(state->rela_orc_ip, i, &rela)) {
				fprintf(stderr, "gelf_getrela() failed\n");
				return -1;
			}

			GElf_Sym sym;
			if (!gelf_getsym(state->symtab, GELF_R_SYM(rela.r_info), &sym)) {
				fprintf(stderr, "gelf_getsym() failed\n");
				return -1;
			}

			if (shndx >= 0 && sym.st_shndx != shndx) {
				continue;
			}

			next_loc = (unsigned long long)rela.r_addend;
		} else {
			// TODO: check shndx somehow
			next_loc = (unsigned long long)
				(state->orc_ip_addr + (i * sizeof(int)) + state->orc_ip[i]);
		}

		if (next_loc < start_loc) {
			start_orc_entry = &orc[i];
			continue;
		}
		if (next_loc >= stop_loc) {
			continue;
		}

		// TODO: do not emit last entry of a section when the section isn't the
		// last one
		if (i == nr_entries - 1 && orc[i].sp_reg == ORC_REG_UNDEFINED) {
			// Last entry has an undefined sp_reg
			continue;
		}

		if (start_orc_entry != NULL && next_loc > start_loc) {
			if (write_fde_instruction(fde, start_orc_entry, start_loc, f) != 0) {
				return -1;
			}
		}
		start_orc_entry = NULL;

		if (next_loc > 0) {
			dwarfw_cie_write_advance_loc(fde->cie, next_loc - loc, f);
		}
		loc = next_loc;

		if (write_fde_instruction(fde, &orc[i], loc, f) != 0) {
			return -1;
		}
	}

	return 0;
}

static int process_section(struct dareog_state *state, Elf_Scn *s, FILE *f,
		size_t *written, FILE *rela_f) {
	// TODO: support non-relocatable ELF files
	size_t shndx = elf_ndxscn(s);

	GElf_Sym text_sym;
	int text_sym_idx = find_section_symbol(state->elf, shndx, &text_sym);
	if (text_sym_idx < 0) {
		fprintf(stderr, "can't find .text section in symbol table\n");
		return 1;
	}

	struct dwarfw_cie cie = {
		.version = 1,
		.augmentation = "zR",
		.code_alignment = 1,
		.data_alignment = -8,
		.return_address_register = 16,
		.augmentation_data = {
			.pointer_encoding = DW_EH_PE_sdata4 | DW_EH_PE_pcrel,
		},
	};

	size_t n;
	if (!(n = dwarfw_cie_write(&cie, f))) {
		fprintf(stderr, "dwarfw_cie_write() failed\n");
		return -1;
	}
	*written += n;

	// Get function symbols for this section. We'll generate one FDE per
	// function.
	size_t func_syms_len = 0;
	GElf_Sym *func_syms =
		get_function_symbols(state->elf, shndx, &func_syms_len);
	if (func_syms == NULL) {
		// No symbols, generate only one FDE for the whole .text section
		func_syms_len = 1;
		func_syms = &text_sym;
	}

	for (size_t i = 0; i < func_syms_len; ++i) {
		GElf_Sym func_sym = func_syms[i];

		struct dwarfw_fde fde = {
			.cie = &cie,
			.initial_location = func_sym.st_value, // - text_sym.st_value
		};

		char *instr_buf;
		size_t instr_len;
		FILE *instr_f = open_memstream(&instr_buf, &instr_len);
		if (instr_f == NULL) {
			fprintf(stderr, "open_memstream() failed\n");
			return -1;
		}

		unsigned long long start_loc = func_sym.st_value;
		unsigned long long stop_loc = func_sym.st_value + func_sym.st_size;
		if (write_all_fde_instructions(state, &fde, shndx, start_loc, stop_loc,
				instr_f)) {
			fprintf(stderr, "write_all_fde_instructions() failed\n");
			return -1;
		}
		fclose(instr_f);

		if (instr_len == 0) {
			continue;
		}

		fde.address_range = func_sym.st_size;
		fde.instructions_length = instr_len;
		fde.instructions = instr_buf;
		fde.cie_pointer = *written;

		GElf_Rela initial_position_rela;
		if (!(n = dwarfw_fde_write(&fde, &initial_position_rela, f))) {
			fprintf(stderr, "dwarfw_fde_write() failed\n");
			return -1;
		}
		initial_position_rela.r_offset += *written;
		*written += n;
		free(instr_buf);

		// r_offset and r_addend have already been populated by dwarfw_fde_write
		initial_position_rela.r_info = GELF_R_INFO(text_sym_idx,
			ELF32_R_TYPE(initial_position_rela.r_info));

		if (!fwrite(&initial_position_rela, 1, sizeof(GElf_Rela), rela_f)) {
			fprintf(stderr, "can't write rela\n");
			return 1;
		}
	}

	if (func_syms != &text_sym) {
		free(func_syms);
	}

	return 0;
}

int dareog_generate_dwarf(int argc, char **argv) {
	if (argc != 2) {
		fprintf(stderr, "missing ELF object path\n");
		return -1;
	}

	elf_version(EV_CURRENT);

	char *objname = argv[1];
	int fd = open(objname, O_RDWR);
	if (fd == -1) {
		fprintf(stderr, "cannot open file\n");
		return -1;
	}

	Elf *elf = elf_begin(fd, ELF_C_RDWR_MMAP, NULL);
	if (!elf) {
		fprintf(stderr, "elf_begin() failed\n");
		return -1;
	}

	// Check the ELF object
	Elf_Kind ek = elf_kind(elf);
	if (ek != ELF_K_ELF) {
		fprintf(stderr, "not an ELF object\n");
		return 1;
	}

	size_t sections_num;
	if (elf_getshdrnum(elf, &sections_num)) {
		return 1;
	}

	size_t shstrtab_idx;
	if (elf_getshdrstrndx(elf, &shstrtab_idx)) {
		fprintf(stderr, "elf_getshdrstrndx() failed\n");
		return -1;
	}

	struct dareog_state state = { .elf = elf };
	for (size_t i = 0; i < sections_num; i++) {
		Elf_Scn *scn = elf_getscn(elf, i);
		if (!scn) {
			fprintf(stderr, "elf_getscn() failed\n");
			return -1;
		}

		GElf_Shdr sh;
		if (!gelf_getshdr(scn, &sh)) {
			fprintf(stderr, "gelf_getshdr() failed\n");
			return -1;
		}

		char *name = elf_strptr(elf, shstrtab_idx, sh.sh_name);
		if (!name) {
			fprintf(stderr, "elf_strptr\n");
			continue; // TODO
			return -1;
		}

		Elf_Data *data = elf_getdata(scn, NULL);
		if (!data) {
			fprintf(stderr, "elf_getdata() failed\n");
			return -1;
		}

		if (!strcmp(name, ".symtab")) {
			state.symtab = data;
		} else if (!strcmp(name, ".orc_unwind")) {
			state.orc = data->d_buf;
			state.orc_size = sh.sh_size;
		} else if (!strcmp(name, ".orc_unwind_ip")) {
			state.orc_ip = data->d_buf;
			state.orc_ip_addr = sh.sh_addr;
		} else if (!strcmp(name, ".rela.orc_unwind_ip")) {
			state.rela_orc_ip = data;
		}
	}

	if (!state.symtab || !state.orc || !state.orc_ip) {
		fprintf(stderr, "missing .symtab, .orc_unwind or .orc_unwind_ip section\n");
		return -1;
	}

	if (state.orc_size % sizeof(*state.orc) != 0) {
		fprintf(stderr, "bad .orc_unwind section size\n");
		return -1;
	}

	char *buf;
	size_t len;
	FILE *f = open_memstream(&buf, &len);
	if (f == NULL) {
		fprintf(stderr, "open_memstream() failed\n");
		return 1;
	}

	char *rela_buf;
	size_t rela_len;
	FILE *rela_f = open_memstream(&rela_buf, &rela_len);
	if (rela_f == NULL) {
		fprintf(stderr, "open_memstream() failed\n");
		return 1;
	}

	size_t written = 0;
	for (size_t i = 0; i < sections_num; ++i) {
		Elf_Scn *s = elf_getscn(elf, i);
		if (s == NULL) {
			return 1;
		}

		GElf_Shdr sh;
		if (!gelf_getshdr(s, &sh)) {
			return 1;
		}

		if ((sh.sh_flags & SHF_EXECINSTR) == 0) {
			continue;
		}

		if (process_section(&state, s, f, &written, rela_f)) {
			return 1;
		}
	}

	fclose(f);
	fclose(rela_f);

	// Create the .eh_frame section
	Elf_Scn *scn = create_debug_frame_section(elf, ".eh_frame", buf, len);
	if (scn == NULL) {
		fprintf(stderr, "create_debug_frame_section() failed\n");
		return 1;
	}

	// Create the .eh_frame.rela section
	Elf_Scn *rela = create_rela_section(elf, ".rela.eh_frame", scn,
		rela_buf, rela_len);
	if (rela == NULL) {
		fprintf(stderr, "create_rela_section() failed\n");
		return 1;
	}

	// Write the modified ELF object
	elf_flagelf(elf, ELF_C_SET, ELF_F_DIRTY);
	if (elf_update(elf, ELF_C_WRITE) < 0) {
		fprintf(stderr, "elf_update() failed: %s\n", elf_errmsg(-1));
		return 1;
	}

	free(buf);
	free(rela_buf);

	elf_end(elf);
	close(fd);

	return 0;
}
