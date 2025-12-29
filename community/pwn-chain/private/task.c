#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

char msg[] = "What is your favorite color? ";

void __attribute__ ((noinline)) ask(){
    puts(msg);

    char color[16];
    read(STDIN_FILENO, color, sizeof(color) * 16);

    if(strcmp(color, "yellow") == 0){
        puts("I also love yellow color");
    }else{
        puts("I don't like this color");
    }
}

int main(int argc, char *argv[]){
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    
    ask();
    
    return 0;
}
