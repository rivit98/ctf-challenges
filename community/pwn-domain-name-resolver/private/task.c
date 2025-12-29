#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(){
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

	char hostname[64];
	char buffer[256];

	printf("Enter the hostname to be resolved: ");
	fgets(hostname, 64, stdin);
	hostname[strcspn(hostname, "\r\n")] = 0;

	snprintf(buffer, sizeof(buffer)-1, "dig %s +short", hostname);
	system(buffer);
}
