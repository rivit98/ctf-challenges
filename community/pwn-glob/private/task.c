#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>


struct __attribute__((__packed__)) {
    char flag[32];
    char username[32];
    char *message;
} program_data;


void read_flag() {
    FILE *f = fopen("./flag.txt", "rt");
    if (f == NULL) {
        return;
    }

    fgets(program_data.flag, 32, f);      
    fclose(f);
}

int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);        

    read_flag();
    printf("Your name? ");
    
    program_data.message = program_data.username;
    read(STDIN_FILENO, program_data.username, 33);
    puts(program_data.message);
    
    return 0;
}
