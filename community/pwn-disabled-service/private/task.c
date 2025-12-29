#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char PIN[] = "00";

void print_flag(){
    char flag[64]; 
    
    FILE *f = fopen("./flag.txt", "rt");
    if (f == NULL) {
        puts("No flag.txt found");
        return;
    }
    fgets(flag, 64, f);      
    fclose(f);
    puts(flag);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    char *pin_ptr = PIN;
    char buffer[64];
    printf("System temporarily disabled. Type 'q' to exit.\n> ");
    fgets(buffer, sizeof(buffer), stdin);
    printf(buffer);

    if(!strncmp(buffer, "q", 1)){
        puts("Bye!");
        return 1;
    }

    //TODO: enable it after maintenance 
    /*
    printf("Enter the PIN\n> ");
    fgets(PIN, sizeof(PIN), stdin);
    */

    if(!strcmp(pin_ptr, "51")){
        print_flag();
    }else{
        printf("%s is not a valid PIN\n", pin_ptr);
    }

    return 0;
}
