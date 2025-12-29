#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <stdint.h>

#define MAX_CHUNKS 6

uint64_t read_num(){
    char input[32];
    memset(input, 0, sizeof(input));
    read(STDIN_FILENO, input, 0x1F);
    return strtoull(input, 0, 10);
}

void menu() {
    unsigned int idx = 0;
    uint64_t index;
    char *chunks[MAX_CHUNKS];
    memset(chunks, 0, MAX_CHUNKS * sizeof(char *));

    while(1){
        printf("\n1) malloc %u/%u\n", idx, MAX_CHUNKS);
        puts("2) free");
        puts("3) edit");
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
            index = read_num();
            if(index >= MAX_CHUNKS){
                puts("Invalid chunk");
                break;
            }

            free(chunks[index]);
            break;
        
        case 3:
            printf("Index: ");
            index = read_num();
            if(index >= MAX_CHUNKS){
                puts("Invalid chunk");
                break;
            }

            if(chunks[index]){
                printf("Data: ");
                read(STDIN_FILENO, chunks[index], size);
            }else{
                puts("Empty index");
            }

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

    printf("puts @ %p\n", puts);

    menu();

	return 0;
}
