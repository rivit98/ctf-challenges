#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

__attribute__((constructor)) void init(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
}

int main() {
  const size_t page_size = getpagesize();
  char *rwx = mmap(NULL, page_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (rwx == MAP_FAILED) {
    perror("mmap");
    goto cleanup1;
  }

  FILE *fp = fopen("/dev/null","w");
  if (fp == NULL) {
    perror("fopen");
    goto cleanup2;
  }

  *rwx = 0xc3; // ret
  rwx -= 2;

  while (1) {
    char fmtstr[0x10] = {0};
    printf("Enter a format string: ");
    if (fgets(fmtstr, sizeof(fmtstr), stdin) == NULL) {
      perror("fgets");
      goto cleanup2;
    }
    fmtstr[strcspn(fmtstr, "\n")] = '\0';

    if (strlen(fmtstr) == 0) {
      break;
    }
    rwx += 2;
    fprintf(fp, fmtstr);
  }

  return ((int (*)())rwx)();

cleanup2:
  fclose(fp);

cleanup1:
  munmap(rwx, page_size);
  return 1;
}
