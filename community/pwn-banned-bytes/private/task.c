#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);        

    puts("Give me the bytes and I will run them");
    const uint8_t banned_bytes[] = {
        0xf, 0x5,         // syscall
        0x2f,             // '/' character
        0x49, 0x48, 0x89,  // some mov's, xor's
        0xe8, 0xff, 0x2d, 0x6c, 0xb2, 0x44, 0x50, 0x51, 0x97
    };
    puts("Banned bytes are: ");
    for(char b = 0; b < sizeof(banned_bytes); b++){
        printf("0x%02X ", banned_bytes[b]);
    }
    puts("");

    char code[64];
    read(STDIN_FILENO, code, 64);
    code[0x10] = 46;

    for(int i = 0; i < 64; i++){
        char c = code[i];
        for(char b = 0; b < sizeof(banned_bytes); b++){
            if(c == banned_bytes[b]){
                puts("Nope!");
                return 1;
            }
        }
    }

    (*(void(*)()) code)();
    
    return 0;
}
