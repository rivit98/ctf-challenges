#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void victory(void){
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

void func(void){
	char buf[128] = {0};

	printf("Address of victory: %p\n", &victory);
	printf("Address of buf: %p\n", buf);
	printf("Return address: %p\n", __builtin_return_address(0));

	fgets(buf, sizeof(buf), stdin);
	printf(buf);
	putchar('\n');

	printf("Return address: %p\n", __builtin_return_address(0));
}

int main(void){
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

	func();
	return 0;
}
