#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]){
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    
    char buf[32];
    write(STDOUT_FILENO, "You have one job!\n", 19);
    read(STDIN_FILENO, buf, 0x100);
    __asm__("xor %rdx, %rdx");
    __asm__("xor %rdi, %rdi");
    __asm__("xor %rsi, %rsi");

    return 0;
}
