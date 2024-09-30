#define NULL ((void*)0)

typedef int size_t;
typedef char* va_list;

#define _INTSIZEOF(n) ((sizeof(n) + sizeof(int) - 1) & ~(sizeof(int) - 1))
#define va_start(ap, v) (ap = (va_list)&v + _INTSIZEOF(v))
#define va_end(ap) (ap = (va_list)0)

void vsprintf(char* buffer, const char* fmt, va_list argptr);
void printf(const char* fmt, ...);
int read(char* dest, size_t len);
unsigned int _rotl(const unsigned int value, int shift);
unsigned int _rotr(const unsigned int value, int shift);
void srand(unsigned seed);
int rand(void);


#include "constants.h"

int randSeed = 0;

// #define DEV

int vmMain()
{
    unsigned int i, r, c;
    char user_input[0x30];
    int correct;

    memset(user_input, 0, sizeof(user_input));
    srand(0x1337);

    printf("Input flag: \n");
    if (!read(user_input, sizeof(user_input))) {
        printf("Nope!\n");
        return 1;
    }

    for (i = 0; i < sizeof(expected) / sizeof(expected[0]); i++) {
        c = user_input[i];

        r = rand();

        c = c | (c << 16);
        c = _rotl(c, 5);

#ifdef DEV
        printf("expected[i]=%d\n", _rotr(r^c, i));
#endif
        expected[i] -= _rotr(r^c, i);
    }

#ifdef DEV
    for (i = 0; i < sizeof(expected) / sizeof(expected[0]); i++) {
        printf("%d, ", expected[i]);
    }
    printf("\n");
#endif

    correct = 1;
    for (i = 0; i < sizeof(expected) / sizeof(expected[0]); i++) {
        if (expected[i]) {
            correct = 0;
        }
    }

    if (correct) {
        printf("Correct!\n");
    } else {
        printf("Nope!\n");
    }

    return !correct;
}

unsigned int _rotl(unsigned int value, int shift)
{
    return (value << shift) | (value >> (sizeof(value) * 8 - shift));
}

unsigned int _rotr(unsigned int value, int shift)
{
    return (value >> shift) | (value << (sizeof(value) * 8 - shift));
}

void srand(unsigned seed)
{
    randSeed = seed;
}

int rand(void)
{
    randSeed = (69069 * randSeed + 1);
    return randSeed & 0x7fff;
}

#ifdef DEV
void printf(const char* fmt, ...)
{
    va_list argptr;
    char text[1024];

    va_start(argptr, fmt);
    vsprintf(text, fmt, argptr);
    va_end(argptr);

    trap_Printf(text);
}

void AddInt(char** buf_p, int val)
{
    char text[32];
    int digits;
    int signedVal;
    char* buf;

    digits = 0;
    signedVal = val;
    if (val < 0) {
        val = -val;
    }
    do {
        text[digits++] = '0' + val % 10;
        val /= 10;
    } while (val);

    if (signedVal < 0) {
        text[digits++] = '-';
    }

    buf = *buf_p;

    while (digits--) {
        *buf++ = text[digits];
    }

    *buf_p = buf;
}

void vsprintf(char* buf_p, const char* fmt, va_list argptr)
{
    int* arg;
    char ch;

    arg = (int*)argptr;

    while (1) {
        // run through the format string until we hit a '%' or '\0'
        for (ch = *fmt; (ch = *fmt) != '\0' && ch != '%'; fmt++) {
            *buf_p++ = ch;
        }
        if (ch == '\0') {
            goto done;
        }

        // skip over the '%'
        fmt++;

        ch = *fmt++;
        switch (ch) {
        case 'd':
            AddInt(&buf_p, *arg);
            arg++;
            break;
        case '%':
            *buf_p++ = ch;
            break;
        default:
            *buf_p++ = (char)*arg;
            arg++;
            break;
        }
    }

done:
    *buf_p = 0;
}
#else
void printf(const char* s, ...)
{
    trap_Printf(s);
}
#endif
