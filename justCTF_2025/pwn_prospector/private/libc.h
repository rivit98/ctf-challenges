#pragma once
#include <stdint.h>

#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0
#define STDOUT_FILENO 1
#define STDIN_FILENO 0
#define NULL ((void *)0)
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_ANONYMOUS 0x20
#define MAP_PRIVATE 0x02
#define MAP_GROWSDOWN	0x00100		/* Stack-like segment.  */

typedef uint64_t size_t;

typedef struct {
	void *alloc_ptr;
} memory_pool_t;

void *malloc (memory_pool_t* state, size_t n);

size_t strlen(const char *s);

char *strdup(memory_pool_t* state, const char *s);

void exit(int status);

int write(int fd, const char *buf, size_t count);

int read(int fd, char *buf, size_t count);

void *mmap(void *addr, size_t len, int prot, int flags, int fd, long offset);

void print(const char *msg);

void rtrim(char *s);

void *memset(void *s, int c, size_t n);

void free(void *ptr);

char *itoa(uint64_t value, char *buffer);
