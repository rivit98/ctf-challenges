#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/random.h>

uint64_t read_num(){
    char input[32];
    memset(input, 0, sizeof(input));
    read(STDIN_FILENO, input, 0x1F);
    return strtoull(input, 0, 10);
}

void load_flag(char *secret_chunk){
    char buf[0x32];
    FILE *f = fopen("./flag.txt", "rt");
    if (f == NULL){
        puts("Error reading flag");
        return;
    }
    
    fgets(buf, sizeof(buf), f);
    sprintf(secret_chunk, "Your flag is here: %s", buf);
    fclose(f);
}

uint32_t get_seed(){
    uint32_t random;
    getrandom(&random, sizeof(random), 0);
    return random;
}

void func() {
    srand(get_seed());

    int malloc_size = (rand() % 940) + 64;
    char *p = malloc(malloc_size);
    load_flag(p);
    free(p);
    malloc(0x20);

    while(1){
        printf("Size: ");
        uint64_t size = read_num();
        char *mem = malloc(size);
        for(int i = 0; i < 0x32+19; i++){
            printf("%c", mem[i]);
        }
        printf("\n");
    }
}

int main(void){
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    func();

	return 0;
}
