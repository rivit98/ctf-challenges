#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <stdint.h>

#define MAX_CHUNKS 6

struct User {
    char username[32];
    uint64_t access_level;
};

struct User user;

uint64_t read_num(){
    char input[32];
    memset(input, 0, sizeof(input));
    read(STDIN_FILENO, input, 0x1F);
    return strtoull(input, 0, 10);
}

void try_flag(){
    if(user.access_level != 0x1337){
        puts("Not so easy!");
        return;
    }

    FILE *f = fopen("./flag.txt", "rt");
    if (f == NULL){
        puts("Error reading flag");
        return;
    }

    char flag[64];
    fgets(flag, sizeof(flag), f);
    fclose(f);
    puts(flag);
}

void menu() {
    unsigned int idx = 0;
    char *chunks[MAX_CHUNKS];
    memset(chunks, 0, MAX_CHUNKS * sizeof(char *));

    printf("Username: ");
    memset(&user, 0, sizeof(struct User));
    read(STDIN_FILENO, user.username, sizeof(user.username));
    printf("Logged as %s", user.username);

    while(1){
        printf("\n1) malloc %u/%u\n", idx, MAX_CHUNKS);
        puts("2) free");
        puts("3) display flag");
        puts("4) quit");

        printf("> ");
        long c = read_num();

        switch (c)
        {
        case 1:
            if(idx >= MAX_CHUNKS){
                puts("Maximum requests reached");
                return;
            }

            printf("Size: ");
            uint64_t size = read_num();
            if(size > 120){
                puts("Max 120 bytes");
                break;
            }

            chunks[idx] = malloc(size);
            if(chunks[idx]){
                printf("Data: ");
                read(STDIN_FILENO, chunks[idx++], size);
            }else{
                puts("malloc failed");
            }
            break;
        
        case 2:
            printf("Index: ");
            uint64_t idx = read_num();
            if(idx >= MAX_CHUNKS){
                puts("Invalid chunk");
                break;
            }

            free(chunks[idx]);
            break;
        
        case 3:
            try_flag();
            break;
        
        case 4:
            return;
        
        default:
            puts("Invalid option");
            break;
        }
    }
}

int main(void){
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    menu();

	return 0;
}
