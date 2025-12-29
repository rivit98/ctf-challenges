#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define ACCURACY 444

void *show_approximate_position() {
    char loc;
    int offset = rand() % ACCURACY - (ACCURACY / 2);
    void *ptr = &loc + offset;
    return ptr;
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    char buffer[0x1000];
    void (*location)(void);
    srand((unsigned) (uintptr_t) buffer);

    printf("Approximate position: %p\n", show_approximate_position());

    printf("What do you want to store? ");
    fgets(buffer, sizeof(buffer), stdin);

    printf("Where do you want to jump? ");
    scanf("%p", (void**) &location);
    location();

    return 0;
}
