#ifndef DAREOG_H
#define DAREOG_H

#include <gelf.h>
#include <libelf.h>

struct dareog_state {
	Elf *elf;
	int *orc_ip, orc_size;
	struct orc_entry *orc;
	Elf64_Addr orc_ip_addr;
	Elf_Data *symtab, *rela_orc_ip;
};

int dareog_dump(int argc, char **argv);
int dareog_generate_dwarf(int argc, char **argv);

GElf_Sym *get_function_symbols(Elf *elf, size_t *len);

#endif
