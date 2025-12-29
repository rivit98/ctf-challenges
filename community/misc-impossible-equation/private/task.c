#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

int main(){
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

	puts("X * 212103456793011 = 183057226632645");
	printf("X = ? ");

	uint64_t val;
	if(scanf("%lu", &val) != 1){
		return puts("Nope");
	}

	printf("result: %lu\n", val * 212103456793011ul);
	if(val * 212103456793011ul == 183057226632645ul){
    	system("cat ./flag.txt");
  	}else{
		puts("Nope");
	}
}

