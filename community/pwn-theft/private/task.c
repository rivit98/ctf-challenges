#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <stdint.h>

#define MAX_CHUNKS 3

typedef struct HiddenData {
    char *string;
    int secret_num;
} HiddenData;

typedef struct Data {
    char *metadata; //not used
    uint64_t str_len;
    char string[8];
} Data;

uint64_t read_num(){
    char input[32] = {};
    read(STDIN_FILENO, input, 0x1F);
    return strtoull(input, 0, 10);
}

void load_flag(HiddenData *secret_chunk){
    FILE *f = fopen("./flag.txt", "rt");
    if (f == NULL){
        puts("Error reading flag");
        return;
    }
    
    secret_chunk->string = malloc(32);
    fgets(secret_chunk->string, 32, f);
    secret_chunk->secret_num = strlen(secret_chunk->string);
    fclose(f);
}

void func() {
    HiddenData *tmp = malloc(sizeof(HiddenData));
    HiddenData *tmp2 = malloc(sizeof(HiddenData));
    HiddenData *secret_chunk = malloc(sizeof(HiddenData));
    free(tmp);
    free(tmp2);
    load_flag(secret_chunk);

    unsigned int idx = 0;
    uint64_t index;
    Data *chunks[MAX_CHUNKS];
    memset(chunks, 0, MAX_CHUNKS * sizeof(Data *));

    while(1){
        printf("\n1) malloc %u/%u\n", idx, MAX_CHUNKS);
        puts("2) show");
        puts("3) quit");

        printf("> ");
        long c = read_num();

        switch (c)
        {
        case 1:
            if(idx >= MAX_CHUNKS){
                puts("Maximum requests reached");
                return;
            }

            chunks[idx] = malloc(sizeof(Data));
            if(chunks[idx]){
                printf("Data: ");
                read(STDIN_FILENO, chunks[idx]->string, sizeof(Data));
                chunks[idx]->str_len = strlen(chunks[idx]->string);
                idx++;
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

            if(chunks[index]){
                printf("%s (%ld)\n", chunks[index]->string, chunks[index]->str_len);
                if(chunks[index]->metadata != NULL){
                    printf("Metadata: %s\n", chunks[index]->metadata);
                }
            }else{
                puts("Empty index");
            }

            break;

        case 3:
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

    func();

	return 0;
}
