#include <stdlib.h>
#include <stdio.h>

void print_flag(){
    char flag[64];
    FILE *f = fopen("./flag.txt", "rt");
    if (f == NULL) {
        puts("No flag.txt found, contact an admin");
        return;
    }

    fgets(flag, 64, f); 
    fclose(f);
    puts(flag);
}

void vuln(){
    char buf[16];
    printf("First: ");
    gets(buf);
    printf(buf);
    printf("Second: ");
    gets(buf);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    vuln();

    return 0;
}
