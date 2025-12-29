#pragma once

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

typedef uint8_t   u8;
typedef int8_t    i8;
typedef uint16_t  u16;
typedef int16_t   i16;
typedef uint32_t  u32;
typedef int32_t   i32;
typedef uint64_t  u64;
typedef int64_t   i64;

#define LOG(f_, ...) printf(("[*] " f_), __VA_ARGS__)


#define FAIL(prefix_)       \
    do                      \
    {                       \
        perror(prefix_);    \
        exit(errno);        \
    } while (0)


#define CHECKED_CALL(func)      \
    do                          \
    {                           \
        if((func) < 0)          \
            FAIL(#func);        \
    } while (0)


#define IMPORT_BIN(sect, file, sym) asm (\
".section " #sect "\n"                  /* Change section */\
".balign 8\n"                           /* Word alignment */\
".global " #sym "\n"                    /* Export the object address */\
#sym ":\n"                              /* Define the object label */\
".incbin \"" file "\"\n"                /* Import the file */\
"sizeof_" #sym ": .quad . - " #sym "\n" /* Define the object size */\
".balign 8\n"                           /* Word alignment */\
".section \".text\"\n")                 /* Restore section */

/*
IMPORT_BIN(".rodata", "tar", tar_prog);
extern char tar_prog[];
extern int sizeof_tar_prog;
*/

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
