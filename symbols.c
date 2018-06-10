#include <gelf.h>
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dareog.h"

int compare_symbols(const void *a, const void *b) {
	const GElf_Sym *sa = a, *sb = b;
	return sa->st_value - sb->st_value;
}

GElf_Sym *get_function_symbols(Elf *elf, size_t *len) {
	Elf_Scn *symtab = NULL;
	GElf_Shdr *symtab_shdr = NULL;
	Elf_Scn *scn = NULL;
	while (1) {
		scn = elf_nextscn(elf, scn);
		if (scn == NULL) {
			break;
		}

		GElf_Shdr shdr;
		gelf_getshdr(scn, &shdr);
		if (shdr.sh_type == SHT_SYMTAB) {
			symtab = scn;
			symtab_shdr = &shdr;
			break;
		}
	}
	if (symtab == NULL) {
		return NULL;
	}

	Elf_Data *data = elf_getdata(symtab, NULL);
	int count = symtab_shdr->sh_size / symtab_shdr->sh_entsize;
	GElf_Sym *symbols = malloc(count * sizeof(GElf_Sym));
	if (symbols == NULL) {
		return NULL;
	}

	size_t symbols_len = 0;
	for (int i = 0; i < count; ++i) {
		GElf_Sym sym;
		gelf_getsym(data, i, &sym);
		if (GELF_ST_TYPE(sym.st_info) != STT_FUNC || sym.st_size == 0) {
			continue;
		}
		memcpy(&symbols[symbols_len], &sym, sizeof(GElf_Sym));
		++symbols_len;
	}

	qsort(symbols, symbols_len, sizeof(GElf_Sym), compare_symbols);

	*len = symbols_len;
	return symbols;
}
