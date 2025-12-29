#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/random.h>

int32_t cash = 3;
const uint32_t beerPrice = 10;
const int32_t flagPrice = 1333333337;

void buyBeer(){
	if(cash < beerPrice){
		puts("Not enough money");
	}else{
		cash -= beerPrice;
		puts("One fresh beer for you!");
	}
}

void buyFlag(){
	if(cash < flagPrice){
		puts("Not enough money");
		return;
	}
	cash -= flagPrice;

    FILE *f = fopen("./flag.txt", "rt");
    if (f == NULL){
        puts("Error reading flag, contact an admin");
        return;
    }

    char flag[64];
    fgets(flag, sizeof(flag), f);
    fclose(f);
	printf("Here it is: ");
    puts(flag);
}

void wallet(){
	printf("You have %d$\n", cash);
}

void work(){
	puts("Working...");
	sleep(1);
	puts("You earned 1$");
	cash += 1;
}

void bet(){
	if(cash < 5){
		puts("Not enough money");
		return;
	}

	int32_t toBet;
	printf("How much do you want to bet? ");
	scanf("%d", &toBet);

	if(toBet < 0){
		toBet = abs(toBet);
	}

	if(toBet > cash){
		puts("Not enough money");
		return;
	}
	cash -= toBet;

	int32_t selectedNumber;
	printf("Select number from 1 to 100: ");
	scanf("%d", &selectedNumber);

	puts("The lottery begins...");
	sleep(3);
	int32_t luckyNumber = rand() % 100 + 1;

	if(selectedNumber == luckyNumber){
		cash += toBet * 2;
		printf("You won %d$\n", toBet * 2);
	}else{
		printf("You lost %d$\n", toBet);
	}
}

void printMenu(){
	puts("-------");
	puts("1) show wallet");
	puts("2) go to work");
	puts("3) make a bet");
	puts("4) buy flag");
	puts("5) buy beer");
	puts("6) exit");
	printf("Select option: ");
}

uint32_t get_seed(){
	uint32_t random;
	getrandom(&random, sizeof(random), 0);
	return random;
}

int main(){
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    srand(get_seed());

	puts("What do you want to do?");

	int c;
	while(1){
		printMenu();
		scanf("%d", &c);

		switch (c)
		{
		case 1:
			wallet();
			break;
		
		case 2:
			work();
			break;
		
		case 3:
			bet();
			break;
		
		case 4:
			buyFlag();
			break;

		case 5:
			buyBeer();
			break;

		case 6:
			puts("Bye");
			return 0;
		
		default:
			puts("Invalid choice");
			break;
		}
	}
}
