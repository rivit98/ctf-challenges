#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

void print_flag(int p1, unsigned int p2){
    printf("You passed the following arguments:\n");
    printf("p1 = %d\n", p1);
    printf("p2 = 0x%X\n", p2);

    FILE *f = NULL;
    char flag[64];

    if(p1 == -1337){
        f = fopen("/flag.txt", "rt");
        if (f == NULL){
            puts("Could not open a flag file! Contact an admin.");
            return;
        }
    }

    if(p2 == 0xC0FFEE){
        fgets(flag, sizeof(flag), f);
        puts(flag);
    }

    if(f != NULL){
        fclose(f);
    }
}

void vuln(){
    puts("Do you want to say something?");
    char buf[32];
    read(STDIN_FILENO, buf, 64);

    print_flag(-1, 2);
}

int main(int argc, char *argv[]){
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    vuln();

    return 0;
}
