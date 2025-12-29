#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

#define DATA_LEN 65536

void gen_data(int seed){
    srand(seed);

    char *mem = mmap(NULL, DATA_LEN, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    if(mem == MAP_FAILED){
        perror("mmap");
        return;
    }
    memset(mem, 0, DATA_LEN);

    for(int i = 0; i < DATA_LEN; i++){
        mem[i] = rand() % 0xFF;
    }
    printf("Buffer at: %p\n", mem);
}

int main(int argc, char *argv[]){
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    int seed;
    printf("Specify the seed: ");
    scanf("%d", &seed);
    getchar(); //remove newline from the buffer

    gen_data(seed);

    char c[4];
    return read(STDIN_FILENO, c, 0x100);
}
