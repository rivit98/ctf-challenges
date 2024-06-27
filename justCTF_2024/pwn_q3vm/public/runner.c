#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#define MAX_BYTES 0x8000
char* prog = "/tmp/program.qvm";

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    printf("Payload len: ");

    char buf[0x10] = {0};
    if(fgets(buf, sizeof(buf), stdin) == NULL){
        puts("Failed to read data from stdin");
        return 1;
    }

    puts("Bytes: ");

    int bytes_num = atoi(buf);
    if(bytes_num > MAX_BYTES || bytes_num < 0){
        puts("Too much");
        return 2;
    }

    uint8_t* mem = calloc(bytes_num, sizeof(uint8_t));

    int _read = 0;
    while(_read < bytes_num){
        int ret = read(STDIN_FILENO, &mem[_read], MIN(0x100, bytes_num-_read));
        if(ret < 0) {
            puts("Failed to read");
            return 3;
        }

        if(ret == 0){
            break;
        }

        _read += ret;
    }

    FILE* f = fopen(prog, "wb");
    if(!f){
        puts("Failed to open program.qvm");
        return 4;
    }
    if(fwrite(mem, sizeof(uint8_t), bytes_num, f) != bytes_num) {
        puts("Failed to save program bytes");
        return 5;
    }
    fclose(f);
    free(mem);

    return 0;
}
