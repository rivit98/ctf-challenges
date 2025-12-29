#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <ctype.h>
#include <stdbool.h>

#ifdef CTFLEARN
#include "ctflearn.h"
#elif CTFGUIDE
#include "ctfguide.h"
#else
#error "specify compilation flag"
#endif

int main();
void destructor();

char input_buffer[0x100];
char fake_flag[] = {
    96, 92, 85, 64, 20, 67, 91, 65, 88, 80, 20, 86, 81, 20, 64, 91, 91, 20, 81, 85, 71, 77, 24, 20, 80, 91, 90, 19, 64, 20, 77, 91, 65, 20, 64, 92, 93, 90, 95, 11, 62, 0
}; // "That would be too easy, don't you think?\n"


uint32_t gen(uint32_t v){
    return (0xBA * v + 0xCC) % 0x123;
}

// void gen_correct(){
//     const uint8_t *flag = "ctfguide{p4tching_4nd_p4tching}";

//     for(int i = 0; i < strlen(flag); i++){
//         printf("%d, ", gen(flag[i]));
//     }
// }

char *rtrim(char *s){
    char* back = s + strlen(s);
    while(isspace(*--back));
    *(back+1) = '\0';
    return s;
}

bool check_flag(char *flag, size_t flag_len){
    alarm(1);

    char xor_key[] = {
        11, 57, 48, 48, 52, 39, 50, 38, 63, 57, 122, 49, 91, 127, 37, 62, 43, 52, 53, 60, 32, 42, 113, 122, 55, 81, 49, 118, 37, 100, 109, 63, 40, 115, 39, 53, 51, 61, 85, 96, 91, 0
    };

    for(int i = 0; i < flag_len; i++){
        if(flag[i] != fake_flag[i] ^ xor_key[i]){
            return false;
        }
    }
    return true;
}

bool check_flag2(char *flag, size_t flag_len){
    alarm(1);

    int good = 0;
    int correct_size = sizeof(correct_data) / sizeof(correct_data[0]);
    for(int i = 0; i < correct_size && i < strlen(flag); i++){
        // printf("%d vs %d (%c)\n", correct_data[i], gen(flag[i]), flag[i]);
        if(correct_data[i] == gen(flag[i])){
            good++;
        }
    }
    return good == correct_size && strlen(flag) == correct_size;
}

void print_bad(){
    char buf[] = {
        121, 88, 71, 82, 22, 61, 0
    }; // "Nope!\n"
    char *p = buf;
    while(*p != '\0'){
        *p++ ^= 0x37;
    }
    printf(buf);
}

void print_ok(){
    char buf[] = {
        4, 40, 53, 53, 34, 36, 51, 102, 77, 0
    }; // "Correct!\n"
    char *p = buf;
    while(*p != '\0'){
        *p++ ^= 0x47;
    }
    printf(buf);
}

// 2. patches main to exit early
void preinit(int argc, char **argv, char **envp) {
    // printf("%s\n", __FUNCTION__);
    char *main_addr = (char *)(main + 0x12); // after atexit call

    void *section_address = (void *) (((uint64_t)main_addr / 0x1000) * 0x1000);
    if(mprotect(section_address, 0x1000, PROT_WRITE | PROT_EXEC | PROT_READ) != 0){
        exit(1);
    }

    *main_addr = 0xc9;        // leave
    *(main_addr+1) = 0xc3;    // ret

    if(mprotect(section_address, 0x1000, PROT_EXEC | PROT_READ) != 0){
        exit(1);
    }
}

// 3. replace call to check_func in destructor with:
void init(int argc, char **argv, char **envp) {
    // printf("%s\n", __FUNCTION__);
    uint32_t *destructor_addr = (uint32_t *)((uint64_t)destructor + 0x1a + 1); // call <check_flag>

    void *section_address = (void *) (((uint64_t)destructor_addr / 0x1000) * 0x1000);
    if(mprotect(section_address, 0x1000, PROT_WRITE | PROT_EXEC | PROT_READ) != 0){
        exit(1);
    }

    // printf("%x %x\n", *destructor_addr, *destructor_addr + check_flag2 - check_flag);
    *destructor_addr += check_flag2 - check_flag;

    if(mprotect(section_address, 0x1000, PROT_EXEC | PROT_READ) != 0){
        exit(1);
    }
}

// 5.
void fini() {
    // printf("%s\n", __FUNCTION__);

    print_bad();
}

__attribute__((section(".init_array"))) typeof(init) *__init = init;
__attribute__((section(".preinit_array"))) typeof(preinit) *__preinit = preinit;
__attribute__((section(".fini_array"))) typeof(fini) *__fini = fini;


// 1. reads user input
void  __attribute__ ((constructor)) constructor() {
    alarm(20);
    // printf("%s\n", __FUNCTION__);

    char buf[] = {
        18, 57, 35, 50, 37, 119, 35, 63, 50, 119, 49, 59, 54, 48, 109, 119, 0
    }; // "Enter the flag: "
    char *p = buf;
    while(*p != '\0'){
        *p++ ^= 0x57;
    }
    write(STDOUT_FILENO, buf, strlen(buf));
    read(STDIN_FILENO, input_buffer, sizeof(input_buffer));
    rtrim(input_buffer);
}

void my_atexit() {
    // printf("%s\n", __FUNCTION__);
    char buf[0x100];
    snprintf(buf, sizeof(buf), "nothing here...");
    // gen_correct();
}

// 4. patch fini if flag is ok
void __attribute__ ((destructor)) destructor() {
    // printf("%s\n", __FUNCTION__);
    if(check_flag(input_buffer, strlen(input_buffer))) { // redirected to check_flag2 by `init`
        uint32_t *fini_addr = (uint32_t *)((uint64_t)fini + 0x9 + 1); // call <check_flag>

        void *section_address = (void *) (((uint64_t)fini_addr / 0x1000) * 0x1000);
        if(mprotect(section_address, 0x1000, PROT_WRITE | PROT_EXEC | PROT_READ) != 0){
            exit(1);
        }

        *fini_addr += print_ok - print_bad;

        if(mprotect(section_address, 0x1000, PROT_EXEC | PROT_READ) != 0){
            exit(1);
        }
    }
}

int main() {
    atexit(my_atexit);

    // leave
    // ret

    alarm(20);

    printf("Enter the flag: ");
    fflush(stdout);
    read(STDIN_FILENO, input_buffer, sizeof(input_buffer));

    char *p = input_buffer;
    while(*p != '\0'){
        *p++ ^= 0x34;
    }
    if(!memcmp(input_buffer, fake_flag, strlen(input_buffer))){
        printf("Correct!\n");
    }else{
        printf("Nope!\n");
    }
}
