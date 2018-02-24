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

		if (GELF_ST_TYPE(sym->st_info) == STT_SECTION && index == sym->st_shndx) {
			return i;
		}
	}

	return -1;
}

static Elf_Scn *create_rela_section(Elf *elf, const char *name, Elf_Scn *base,
		GElf_Rela *rela) {
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

	data->d_buf = rela;
	data->d_size = sizeof(GElf_Rela);
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

static int write_fde_instructions(Elf *elf, struct dwarfw_fde *fde,
		unsigned long long *begin_loc, unsigned long long *end_loc, FILE *f) {
	int *orc_ip = NULL, orc_size = 0;
	struct orc_entry *orc = NULL;
	char *name;
	Elf64_Addr orc_ip_addr = 0;
	size_t shstrtab_idx;
	Elf_Scn *scn;
	GElf_Shdr sh;
	GElf_Rela rela;
	GElf_Sym sym;
	Elf_Data *data, *symtab = NULL, *rela_orc_ip = NULL;
	unsigned long long loc = 0, next_loc;

	size_t nr_sections;
	if (elf_getshdrnum(elf, &nr_sections)) {
		fprintf(stderr, "elf_getshdrnum\n");
		return -1;
	}

	if (elf_getshdrstrndx(elf, &shstrtab_idx)) {
		fprintf(stderr, "elf_getshdrstrndx\n");
		return -1;
	}

	for (size_t i = 0; i < nr_sections; i++) {
		scn = elf_getscn(elf, i);
		if (!scn) {
			fprintf(stderr, "elf_getscn\n");
			return -1;
		}

		if (!gelf_getshdr(scn, &sh)) {
			fprintf(stderr, "gelf_getshdr\n");
			return -1;
		}

		name = elf_strptr(elf, shstrtab_idx, sh.sh_name);
		if (!name) {
			fprintf(stderr, "elf_strptr\n");
			return -1;
		}

		data = elf_getdata(scn, NULL);
		if (!data) {
			fprintf(stderr, "elf_getdata\n");
			return -1;
		}

		if (!strcmp(name, ".symtab")) {
			symtab = data;
		} else if (!strcmp(name, ".orc_unwind")) {
			orc = data->d_buf;
			orc_size = sh.sh_size;
		} else if (!strcmp(name, ".orc_unwind_ip")) {
			orc_ip = data->d_buf;
			orc_ip_addr = sh.sh_addr;
		} else if (!strcmp(name, ".rela.orc_unwind_ip")) {
			rela_orc_ip = data;
		}
	}

	if (!symtab || !orc || !orc_ip) {
		fprintf(stderr, "missing .symtab, .orc_unwind or .orc_unwind_ip section\n");
		return -1;
	}

	if (orc_size % sizeof(*orc) != 0) {
		fprintf(stderr, "bad .orc_unwind section size\n");
		return -1;
	}

	// ra's offset is fixed at -8
	dwarfw_cie_write_offset(fde->cie, 16, -8, f);

	int nr_entries = orc_size / sizeof(*orc);
	for (int i = 0; i < nr_entries; i++) {
		if (rela_orc_ip) {
			if (!gelf_getrela(rela_orc_ip, i, &rela)) {
				fprintf(stderr, "gelf_getrela\n");
				return -1;
			}

			if (!gelf_getsym(symtab, GELF_R_SYM(rela.r_info), &sym)) {
				fprintf(stderr, "gelf_getsym\n");
				return -1;
			}

			scn = elf_getscn(elf, sym.st_shndx);
			if (!scn) {
				fprintf(stderr, "elf_getscn\n");
				return -1;
			}

			if (!gelf_getshdr(scn, &sh)) {
				fprintf(stderr, "gelf_getshdr\n");
				return -1;
			}

			name = elf_strptr(elf, shstrtab_idx, sh.sh_name);
			if (!name || !*name) {
				fprintf(stderr, "elf_strptr\n");
				return -1;
			}

			next_loc = (unsigned long long)rela.r_addend;
		} else {
			next_loc = (unsigned long long)(orc_ip_addr + (i * sizeof(int)) + orc_ip[i]);
		}

		if (next_loc < *begin_loc) {
			*begin_loc = next_loc;
		}
		if (next_loc > *end_loc) {
			*end_loc = next_loc;
		}

		if (next_loc > 0) {
			dwarfw_cie_write_advance_loc(fde->cie, next_loc - loc, f);
		}
		loc = next_loc;

		if (orc[i].sp_reg != ORC_REG_UNDEFINED) {
			dwarfw_cie_write_def_cfa(fde->cie, reg_number(orc[i].sp_reg),
				orc[i].sp_offset, f);
		}

		if (orc[i].bp_reg == ORC_REG_PREV_SP) {
			dwarfw_cie_write_offset(fde->cie, reg_number(ORC_REG_BP),
				orc[i].bp_offset, f);
		} else if (orc[i].bp_reg == ORC_REG_UNDEFINED) {
			dwarfw_cie_write_undefined(fde->cie, reg_number(ORC_REG_BP), f);
		}
	}

	return 0;
}

int dareog_generate_dwarf(int argc, char **argv) {
	if (argc != 2) {
		fprintf(stderr, "Missing ELF object path\n");
		return -1;
	}

	elf_version(EV_CURRENT);

	char *objname = argv[1];
	int fd = open(objname, O_RDWR);
	if (fd == -1) {
		fprintf(stderr, "Cannot open file\n");
		return -1;
	}

	Elf *elf = elf_begin(fd, ELF_C_RDWR_MMAP, NULL);
	if (!elf) {
		fprintf(stderr, "elf_begin\n");
		return -1;
	}

	// Check the ELF object
	Elf_Kind ek = elf_kind(elf);
	if (ek != ELF_K_ELF) {
		fprintf(stderr, "Not an ELF object\n");
		return 1;
	}

	Elf_Scn *text = find_section_by_name(elf, ".text");
	if (text == NULL) {
		fprintf(stderr, "ELF object is missing a .text section\n");
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

	struct dwarfw_fde fde = {
		.cie = &cie,
		.initial_location = 0,
	};

	char *instr_buf;
	size_t instr_len;
	FILE *f = open_memstream(&instr_buf, &instr_len);
	if (f == NULL) {
		fprintf(stderr, "open_memstream\n");
		return -1;
	}
	unsigned long long begin_loc = ULLONG_MAX, end_loc = 0;
	if (write_fde_instructions(elf, &fde, &begin_loc, &end_loc, f)) {
		fprintf(stderr, "write_fde_instructions\n");
		return -1;
	}
	fclose(f);

	fde.address_range = end_loc - begin_loc;
	fde.instructions_length = instr_len;
	fde.instructions = instr_buf;

	size_t n, written = 0;

	// Write the .eh_frame section
	char *buf;
	size_t len;
	f = open_memstream(&buf, &len);
	if (f == NULL) {
		fprintf(stderr, "open_memstream\n");
		return -1;
	}

	if (!(n = dwarfw_cie_write(&cie, f))) {
		fprintf(stderr, "dwarfw_cie_write\n");
		return -1;
	}
	written += n;

	fde.cie_pointer = written;

	GElf_Rela initial_position_rela;
	if (!(n = dwarfw_fde_write(&fde, &initial_position_rela, f))) {
		fprintf(stderr, "dwarfw_fde_write\n");
		return -1;
	}
	initial_position_rela.r_offset += written;
	written += n;
	free(instr_buf);

	fclose(f);

	// Create the .eh_frame section
	Elf_Scn *scn = create_section(elf, ".eh_frame");
	if (scn == NULL) {
		return 1;
	}

	Elf_Data *data = elf_newdata(scn);
	if (data == NULL) {
		fprintf(stderr, "elf_newdata() failed: %s\n", elf_errmsg(-1));
		return 1;
	}
	data->d_align = 4;
	data->d_buf = buf;
	data->d_size = len;

	GElf_Shdr shdr;
	if (!gelf_getshdr(scn, &shdr)) {
		fprintf(stderr, "gelf_getshdr() failed\n");
		return 1;
	}
	shdr.sh_size = len;
	shdr.sh_type = SHT_PROGBITS;
	shdr.sh_addralign = 1;
	shdr.sh_flags = SHF_ALLOC;
	if (!gelf_update_shdr(scn, &shdr)) {
		fprintf(stderr, "gelf_update_shdr() failed\n");
		return 1;
	}

	// Create the .eh_frame.rela section
	GElf_Sym text_sym;
	int text_sym_idx = find_section_symbol(elf, elf_ndxscn(text), &text_sym);
	if (text_sym_idx < 0) {
		fprintf(stderr, "can't find .text section in symbol table\n");
		return 1;
	}
	// r_offset and r_addend have already been populated by dwarfw_fde_write
	initial_position_rela.r_info =
		GELF_R_INFO(text_sym_idx, ELF32_R_TYPE(initial_position_rela.r_info));
	Elf_Scn *rela = create_rela_section(elf, ".rela.eh_frame", scn,
		&initial_position_rela);
	if (rela == NULL) {
		return 1;
	}

	// Write the modified ELF object
	elf_flagelf(elf, ELF_C_SET, ELF_F_DIRTY);
	if (elf_update(elf, ELF_C_WRITE) < 0) {
		fprintf(stderr, "elf_update() failed: %s\n", elf_errmsg(-1));
		return 1;
	}

	free(buf);

	elf_end(elf);
	close(fd);

	return 0;
}
