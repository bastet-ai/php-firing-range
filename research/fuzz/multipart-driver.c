/* Standalone driver for AFL++ (or batch seed runs): reads one input file
 * (argv[1] or stdin) and feeds it to the multipart harness entry points.
 * Links against the existing ASan/UBSan objects; UBSan stays in default
 * recover mode here (the libFuzzer build bakes -fno-sanitize-recover). */
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size);

int main(int argc, char **argv)
{
	if (LLVMFuzzerInitialize(&argc, &argv) != 0) return 2;

	unsigned char buf[1 << 20];
	size_t n = 0;

	if (argc > 1) {
		FILE *f = fopen(argv[1], "rb");
		if (!f) { perror("open"); return 3; }
		n = fread(buf, 1, sizeof(buf), f);
		fclose(f);
	} else {
		n = fread(buf, 1, sizeof(buf), stdin);
	}

	LLVMFuzzerTestOneInput(buf, n);
	printf("driver ok: %zu bytes\n", n);
	return 0;
}
