#include <stdlib.h>
#include <stdio.h>

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    char flag[64], buffer[64];

    FILE *f = fopen("./flag.txt", "rt");
    if (f == NULL) {
        puts("No flag.txt found, contact an admin");
        return 1;
    }

    fgets(flag, 64, f);      
    fclose(f);

    printf("What is your favorite format tag? ");
    fgets(buffer, sizeof(buffer), stdin);
    printf(buffer);

    return 0;
}
