#include <fcntl.h>
#include <linux/seccomp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>

////////////////////////////////////////////////////////////////////////////

const size_t VAULT_SIZE = 0x1000;
#define MAX_WRITE_TYPES 5
#define HEAP_GUARD_SIZE 0x8

typedef struct vault {
  uint32_t vtable;
  uint32_t vtable_wide;
  uint32_t wide_data;

  uint8_t writes[MAX_WRITE_TYPES];
  uint8_t heap_guard_saved[HEAP_GUARD_SIZE];
  uint8_t *heap_guard;
} vault_t;

vault_t *vault;

void vault__lock(vault_t *v) {
  if (mprotect(v, VAULT_SIZE, PROT_READ) == -1) {
    _exit(EXIT_FAILURE);
  }
}

void vault__unlock(vault_t *v) {
  if (mprotect(v, VAULT_SIZE, PROT_WRITE) == -1) {
    _exit(EXIT_FAILURE);
  }
}

vault_t *vault__construct(void) {
  vault_t *v =
      mmap(NULL, VAULT_SIZE, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (v == MAP_FAILED) {
    exit(EXIT_FAILURE);
  }

  memset(v, 0, VAULT_SIZE);

  uint8_t writes[MAX_WRITE_TYPES] = {5, 4, 3, 2, 1};
  memcpy(v->writes, writes, MAX_WRITE_TYPES * sizeof(writes[0]));

  vault__lock(v);
  return v;
}

////////////////////////////////////////////////////////////////////////////

void _puts(char *x) {
  write(STDOUT_FILENO, x, strlen(x));
  write(STDOUT_FILENO, "\n", 1);
}

int _read(char *buf, size_t y) {
  int n = read(STDIN_FILENO, buf, y - 1);
  if (n <= 0) {
    _exit(EXIT_FAILURE);
  }
  buf[strcspn(buf, "\n")] = '\0';
  buf[n] = '\0';
  return n;
}

int getint(void) {
  char buf[0x10] = {};
  _read(buf, sizeof(buf));
  return atoi(buf);
}

int menu(void) {
  _puts("1. Write\n"
        "2. Rewind\n"
        "0. Exit\n"
        "> ");

  return getint();
}

void use_write(uint8_t index) {
  vault__unlock(vault);
  vault->writes[index] -= 1;
  vault__lock(vault);
}

uint8_t get_writes(uint8_t index) {
  vault__unlock(vault);
  uint8_t ret = vault->writes[index];
  vault__lock(vault);
  return ret;
}

int check_vtable(FILE *file) {
  int ret = 0;
  vault__unlock(vault);

  uint32_t cur_vtable = *(uint32_t *)((char *)file + 0x94);
  uint32_t cur_vtable_wide = *(uint32_t *)((char *)file + 0x12c);
  uint32_t wide_data = *(uint32_t *)((char *)file + 0x58);

  if (cur_vtable != vault->vtable || cur_vtable_wide != vault->vtable_wide ||
      wide_data != vault->wide_data) {
    ret = 1;
  }

  vault__lock(vault);
  return ret;
}

int check_heap_guard(void) {
  vault__unlock(vault);
  int ret = memcmp(vault->heap_guard, vault->heap_guard_saved,
                   sizeof(vault->heap_guard_saved));
  vault__lock(vault);
  return ret;
}

int do_write(void *p) {
  uint8_t index = 0;
  uint8_t offset = 0;
  char buf[0x10] = {};

  _puts("Index: ");
  index = getint();
  if (index >= MAX_WRITE_TYPES || index <= 0) {
    return 1;
  }

  if (get_writes(index) == 0) {
    return 1;
  }

  _puts("Offset: ");
  offset = getint();

  _puts("Data: ");
  _read(buf, sizeof(buf));
  if (strlen(buf) != index) {
    return 1;
  }

  memcpy(p + offset, buf, index);
  use_write(index);
  return 0;
}

int do_rewind(FILE *file) {
  uint8_t index = 0;

  if (get_writes(index) == 0) {
    return 1;
  }

  rewind(file);
  use_write(index);
  return 0;
}

static void install_seccomp(void) {
  static unsigned char filter[] = {
      32, 0, 0,   0, 0,  0, 0,  0, 21,  0,   6,   0, 11, 0, 0,  0, 21, 0,
      5,  0, 102, 1, 0,  0, 21, 0, 4,   0,   120, 0, 0,  0, 21, 0, 3,  0,
      2,  0, 0,   0, 21, 0, 2,  0, 190, 0,   0,   0, 21, 0, 1,  0, 26, 0,
      0,  0, 6,   0, 0,  0, 0,  0, 255, 127, 6,   0, 0,  0, 0,  0, 0,  0};

  struct prog {
    unsigned short len;
    unsigned char *filter;
  } rule = {.len = sizeof(filter) >> 3, .filter = filter};

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
    exit(EXIT_FAILURE);
  }
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &rule) < 0) {
    exit(EXIT_FAILURE);
  }
}

__attribute__((constructor)) void init(void) {
#define _IO_FLAGS2_NOCLOSE 32

  stdout->_flags2 |= _IO_FLAGS2_NOCLOSE;
  fclose(stdout);
  stderr->_flags2 |= _IO_FLAGS2_NOCLOSE;
  fclose(stderr);

  int fd = 0;
  if ((fd = creat("/tmp/tape", 0777)) < 0) {
    exit(EXIT_FAILURE);
  }
  close(fd);

  srand(time(NULL));

  vault = vault__construct();

  install_seccomp();
}

int main(int argc, char *argv[]) {
  FILE *file = fopen("/tmp/tape", "rm,ccs=UTF-8");
  if (file == NULL) {
    return EXIT_FAILURE;
  }

  vault__unlock(vault);

  vault->heap_guard = malloc(HEAP_GUARD_SIZE);
  memset(vault->heap_guard, 0, HEAP_GUARD_SIZE);
  int *heap_guard_ptr = (int *)vault->heap_guard;
  int *heap_guard_saved = (int *)vault->heap_guard_saved;
  for (int i = 0; i < HEAP_GUARD_SIZE / sizeof(*heap_guard_ptr); i++) {
    *(heap_guard_ptr + i) = rand();
    *(heap_guard_saved + i) = *(heap_guard_ptr + i);
  }

  vault->vtable = *(uint32_t *)((char *)file + 0x94);
  vault->vtable_wide = *(uint32_t *)((char *)file + 0x12c);
  vault->wide_data = *(uint32_t *)((char *)file + 0x58);

  vault__lock(vault);

  while (1) {
    if (check_vtable(file) != 0) {
      _exit(EXIT_FAILURE);
    }

    if (check_heap_guard() != 0) {
      _exit(EXIT_FAILURE);
    }

    switch (menu()) {
    case 1:
      if (do_write(file) != 0) {
        _exit(EXIT_FAILURE);
      }
      break;
    case 2:
      if (do_rewind(file) != 0) {
        _exit(EXIT_FAILURE);
      }
      break;
    default:
      _exit(EXIT_SUCCESS);
    }
  }

  _exit(EXIT_SUCCESS);
}
