#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <stdint.h>
#include <unistd.h>

uint64_t read_num(){
    uint64_t n;
    int ret = scanf("%lu%*c", &n);
    if(ret != 1){
        puts("Invalid input");
        exit(1);
    }
    return n;
}

void menu() {
    unsigned int idx = 0;
    char *chunks[4] = {};

    while(1){
        printf("\nmalloc %u/%u\n", idx, 4);

        if(idx > 3){
            puts("Maximum requests reached");
            break;
        }else{
            printf("Size: ");
            uint64_t size = read_num();

            chunks[idx] = malloc(size);
            if(chunks[idx]){
                printf("Data: ");
                uint64_t chunk_size = *(((uint64_t *)chunks[idx]-1)); // get chunk size from chunk data
                read(STDIN_FILENO, chunks[idx++], chunk_size);
            }else{
                puts("malloc failed");
            }
        }
    }
}

int main(void){
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    printf("puts @ %p\n", puts);
    char *p = malloc(0x100);
    printf("heap @ %p\n\n", p-0x10);
    free(p);

    menu();

	return 0;
}
