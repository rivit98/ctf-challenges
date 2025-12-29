#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);        

    puts("What do you want to run today?");

    char code[64];
    read(STDIN_FILENO, code, 64);
    (*(void(*)()) code)();
    
    return 0;
}
