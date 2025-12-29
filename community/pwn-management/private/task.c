#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define MAX_NAME_LEN 16
#define ARRAY_SIZE 10
char users[ARRAY_SIZE][MAX_NAME_LEN];

void create_users(){
    srand(time(NULL));
    const char *names[] = { 
        "Brigitte","Danilo","Valeri","Garfield","Arie","Nieves","Hershel","Cyril","Krista"
    };

    for(int i = 0; i < ARRAY_SIZE; i++){
        int random_idx = rand() % (sizeof(names) / sizeof(names[0]));
        strncpy(users[i], names[random_idx], MAX_NAME_LEN);
    }
    printf("There are %d users in the system\n", ARRAY_SIZE);
}

void print_users(){
    for(int i = 0; i < ARRAY_SIZE; i++){
       printf("%d. %s\n", i, users[i]);
    }
}

int get_choice() {
    int c;
    scanf("%d", &c);
    return c;
}

void change_user_nick(){
    char buf[MAX_NAME_LEN];
    printf("Select index: ");
    int i = get_choice();
    if(i >= ARRAY_SIZE){
        puts("Invalid choice");
        return;
    }

    printf("Provide new name: ");
    scanf("%s", buf);
    buf[strcspn(buf, "\n")] = 0;

    printf("User updated %s -> ", users[i]);
    memset(users[i], 0, MAX_NAME_LEN);
    strcpy(users[i], buf);
    puts(users[i]);
}

int menu(){
    int c;
    do {
        puts("----- MENU -----");
        puts("1. display all users");
        puts("2. change name of selected user");
        puts("3. todays date");
        puts("4. exit");
        printf("Your choice: ");
        c = get_choice();
    } while(c < 1 || c > 4);

    return c;
}

int main(int argc, char *argv[]){
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    
    puts("Logged as admin!");

    create_users();

    int c;
    while ((c = menu()) != 4){
        switch(c) {
            case 1: {
                print_users();
                break;
            }
            case 2: {
                change_user_nick();
                break;
            }
            case 3: {
                system("date");
                break;
            }
        }
    }

    puts("bye!");
    
    return 0;
}
