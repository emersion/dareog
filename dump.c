#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "asm/orc_types.h"
#include "dareog.h"

static const char *reg_name(unsigned int reg) {
	switch (reg) {
	case ORC_REG_PREV_SP:
		return "prevsp";
	case ORC_REG_DX:
		return "dx";
	case ORC_REG_DI:
		return "di";
	case ORC_REG_BP:
		return "bp";
	case ORC_REG_SP:
		return "sp";
	case ORC_REG_R10:
		return "r10";
	case ORC_REG_R13:
		return "r13";
	case ORC_REG_BP_INDIRECT:
		return "bp(ind)";
	case ORC_REG_SP_INDIRECT:
		return "sp(ind)";
	default:
		return "?";
	}
}

static const char *orc_type_name(unsigned int type) {
	switch (type) {
	case ORC_TYPE_CALL:
		return "call";
	case ORC_TYPE_REGS:
		return "regs";
	case ORC_TYPE_REGS_IRET:
		return "iret";
	default:
		return "?";
	}
}

static void print_reg(unsigned int reg, int offset) {
	if (reg == ORC_REG_BP_INDIRECT) {
		printf("(bp%+d)", offset);
	} else if (reg == ORC_REG_SP_INDIRECT) {
		printf("(sp%+d)", offset);
	} else if (reg == ORC_REG_UNDEFINED) {
		printf("(und)");
	} else {
		printf("%s%+d", reg_name(reg), offset);
	}
}

int dareog_dump(int argc, char **argv) {
	if (argc != 2) {
		fprintf(stderr, "Missing ELF object path\n");
		return -1;
	}

	elf_version(EV_CURRENT);

	char *objname = argv[1];
	int fd = open(objname, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "Cannot open file\n");
		return -1;
	}

	Elf *elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (!elf) {
		fprintf(stderr, "elf_begin\n");
		return -1;
	}

	size_t nr_sections;
	if (elf_getshdrnum(elf, &nr_sections)) {
		fprintf(stderr, "elf_getshdrnum\n");
		return -1;
	}

	size_t shstrtab_idx;
	if (elf_getshdrstrndx(elf, &shstrtab_idx)) {
		fprintf(stderr, "elf_getshdrstrndx\n");
		return -1;
	}

	int *orc_ip = NULL, orc_size = 0;
	struct orc_entry *orc = NULL;
	Elf64_Addr orc_ip_addr = 0;
	Elf_Data *symtab = NULL, *rela_orc_ip = NULL;
	for (size_t i = 0; i < nr_sections; i++) {
		Elf_Scn *scn = elf_getscn(elf, i);
		if (!scn) {
			fprintf(stderr, "elf_getscn\n");
			return -1;
		}

		GElf_Shdr sh;
		if (!gelf_getshdr(scn, &sh)) {
			fprintf(stderr, "gelf_getshdr\n");
			return -1;
		}

		char *name = elf_strptr(elf, shstrtab_idx, sh.sh_name);
		if (!name) {
			fprintf(stderr, "elf_strptr\n");
			return -1;
		}

		Elf_Data *data = elf_getdata(scn, NULL);
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
		return 0;
	}

	if (orc_size % sizeof(*orc) != 0) {
		fprintf(stderr, "bad .orc_unwind section size (want %ld, have %d)\n", sizeof(*orc), orc_size);
		return -1;
	}

	size_t nr_entries = orc_size / sizeof(*orc);
	for (size_t i = 0; i < nr_entries; ++i) {
		if (rela_orc_ip) {
			GElf_Rela rela;
			if (!gelf_getrela(rela_orc_ip, i, &rela)) {
				fprintf(stderr, "gelf_getrela\n");
				return -1;
			}

			GElf_Sym sym;
			if (!gelf_getsym(symtab, GELF_R_SYM(rela.r_info), &sym)) {
				fprintf(stderr, "gelf_getsym\n");
				return -1;
			}

			Elf_Scn *scn = elf_getscn(elf, sym.st_shndx);
			if (!scn) {
				fprintf(stderr, "elf_getscn\n");
				return -1;
			}

			GElf_Shdr sh;
			if (!gelf_getshdr(scn, &sh)) {
				fprintf(stderr, "gelf_getshdr\n");
				return -1;
			}

			char *name = elf_strptr(elf, shstrtab_idx, sh.sh_name);
			if (!name || !*name) {
				fprintf(stderr, "elf_strptr\n");
				return -1;
			}

			printf("%s+%llx:", name, (unsigned long long)rela.r_addend);
		} else {
			printf("%llx:", (unsigned long long)(orc_ip_addr + (i * sizeof(int)) + orc_ip[i]));
		}

		printf(" sp:");
		print_reg(orc[i].sp_reg, orc[i].sp_offset);

		printf(" bp:");
		print_reg(orc[i].bp_reg, orc[i].bp_offset);

		printf(" type:%s\n", orc_type_name(orc[i].type));
	}

	elf_end(elf);
	close(fd);

	return 0;
}
