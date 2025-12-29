#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char *flag; 

void read_flag(){
    FILE *f = fopen("./flag.txt", "rt");
    if (f == NULL) {
        puts("No flag.txt found");
        return;
    }
    flag = malloc(0x64);
    fgets(flag, 0x64, f);      
    fclose(f);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    read_flag();

    char buffer[32];
    printf("Flag buffer: %p\n", flag);
    printf("Enter your format: ");
    fgets(buffer, sizeof(buffer), stdin);
    printf(buffer);

    free(flag);

    return 0;
}
