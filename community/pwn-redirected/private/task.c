#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void ask_user(){
    char buf[128];
    memset(buf, 0, sizeof(buf));
    system("echo Input your message: ");
    fgets(buf, sizeof(buf), stdin);
    printf(buf);
    puts("Thanks for sending the message!");
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    ask_user();

    return 0;
}
