#include "libc.h"

long syscall(long number, long arg1, long arg2, long arg3, long arg4, long arg5,
             long arg6) {
  long ret;
  asm volatile("movq %1, %%rax\n"
               "movq %2, %%rdi\n"
               "movq %3, %%rsi\n"
               "movq %4, %%rdx\n"
               "movq %5, %%r10\n"
               "movq %6, %%r8\n"
               "movq %7, %%r9\n"
               "syscall\n"
               : "=a"(ret)
               : "g"(number), "g"(arg1), "g"(arg2), "g"(arg3), "g"(arg4),
                 "g"(arg5), "g"(arg6)
               : "rdi", "rsi", "rdx", "r10", "r8", "r9", "rcx", "r11",
                 "memory");
  return ret;
}

void exit(int status) { syscall(60, status, 0, 0, 0, 0, 0); }

int write(int fd, const char *buf, size_t count) {
  return (int)syscall(1, fd, (long)buf, count, 0, 0, 0);
}

int read(int fd, char *buf, size_t count) {
  return (int)syscall(0, fd, (long)buf, count, 0, 0, 0);
}

void *mmap(void *addr, size_t len, int prot, int flags, int fd, long offset) {
  return (void *)syscall(9, (long)addr, len, prot, flags, fd, offset);
}

#define MALLOC_ALIGNMENT 0x10

void *malloc(memory_pool_t *state, size_t n) {
  state->alloc_ptr =
      (void *)0 +
      ((((unsigned long long)state->alloc_ptr) + MALLOC_ALIGNMENT - 1) &
       ~(MALLOC_ALIGNMENT - 1));

  void *ret = (void *)state->alloc_ptr;
  state->alloc_ptr += n;
  return ret;
}

void free(void *ptr) {}

size_t strlen(const char *s) {
  if (s == NULL)
    return 0; // Handle NULL input
  const char *p = s;
  while (*p)
    p++;
  return p - s;
}

char *strdup(memory_pool_t *state, const char *s) {
  size_t len = strlen(s);
  char *copy = (char *)malloc(state, len + 1);
  for (size_t i = 0; i < len; i++) {
    copy[i] = s[i];
  }
  copy[len] = '\0';
  return copy;
}

void print(const char *msg) { write(STDOUT_FILENO, msg, strlen(msg)); }

void rtrim(char *s) {
  if (!s || *s == '\0')
    return; // Handle NULL input and empty string

  char *end = s;
  while (*end)
    end++; // Move to the null terminator

  // Move back over trailing newlines
  while (end > s && *(end - 1) == '\n')
    end--;

  *end = '\0'; // Null-terminate after the last non-newline character
}

void *memset(void *dest, int val, size_t len) {
  unsigned char *ptr = (unsigned char *)dest;
  while (len-- > 0)
    *ptr++ = val;
  return dest;
}

char *itoa(uint64_t value, char *buffer) {
  char temp[20];
  char *p = temp;
  do {
    *p++ = (char)(value % 10) + '0';
    value /= 10;
  } while (value > 0);

  do {
    *buffer++ = *--p;
  } while (p != temp);

  return buffer;
}
