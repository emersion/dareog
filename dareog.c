#include <stdio.h>
#include <string.h>
#include "dareog.h"

static int usage() {
	fprintf(stderr, "usage: dareog dump <file>\n");
	fprintf(stderr, "usage: dareog generate-dwarf <file>\n");
	return 1;
}

int main(int argc, char **argv) {
	if (argc < 2) {
		return usage();
	}

	const char *command = argv[1];
	--argc;
	++argv;
	if (strcmp(command, "dump") == 0) {
		return dareog_dump(argc, argv);
	} else if (strcmp(command, "generate-dwarf") == 0) {
		return dareog_generate_dwarf(argc, argv);
	} else {
		return usage();
	}
}
