#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void print_flag() {
    char flag[64];
    memset(flag, 0, sizeof(flag));
    FILE *f = fopen("./flag.txt", "rt");
    if (f == NULL) {
        puts("No flag.txt found, contact an admin");
        return;
    }

    fgets(flag, 64, f);
    fclose(f);
    puts(flag);
}

void vuln() {
    puts("What is the end of this story? ");
    char *src = malloc(16);
    char dest[8];

    memset(src, 0, sizeof(src));
    memset(dest, 0, sizeof(dest));
    gets(src);
    if(!strncmp(src, "admin", 5)){
        strncpy(dest, src, 9uLL);
        printf("Logged as %s! print_flag is here: %p\n", dest, print_flag);
        gets(dest);
    }

    free(src);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    vuln();

    return 0;
}
