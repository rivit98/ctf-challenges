#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_NAME_SIZE 32
#define MAX_PERSONS 10

int total = 0;
void *person[MAX_PERSONS];

void print_flag() {
    char buf[0x32];
    FILE *f = fopen("./flag.txt", "rt");
    if (f == NULL) {
        puts("Error reading flag");
        return;
    }

    fgets(buf, sizeof(buf), f);
    fclose(f);
    puts(buf);
}

struct Professor {
    char name[MAX_NAME_SIZE];
    int rate;
};

struct Student {
    char name[MAX_NAME_SIZE];
    void (*score_func)(struct Professor *, int);
};

void give_score(struct Professor *professor, int rate) {
    professor->rate = rate;
    printf("Scored %s - %d\n", professor->name, rate);
}

void *find_professor(char *name) {
    for (int i = 0; i < total; i++) {
        if (strncmp(((struct Professor *)person[i])->name, name, MAX_NAME_SIZE) == 0) {
            return person[i];
        }
    }
    puts("not found");
    exit(0);
}

void *find_student(char *name) {
    for (int i = 0; i < total; i++) {
        if (strncmp(((struct Student *)person[i])->name, name, MAX_NAME_SIZE) == 0) {
            return person[i];
        }
    }
    puts("not found");
    exit(0);
}

void get_line(char *buf) {
    int last = read(STDIN_FILENO, buf, MAX_NAME_SIZE - 1);
    buf[last - 1] = 0;
}

void func() {
    while (total < MAX_PERSONS - 1) {
        struct Student *student = (struct Student *)malloc(sizeof(struct Student));
        person[total++] = student;
        printf("Student name: ");
        get_line(student->name);

        struct Professor *professor = (struct Professor *)malloc(sizeof(struct Professor));
        person[total++] = professor;
        printf("Professor name: ");
        get_line(professor->name);
        student->score_func = &give_score;

        char nameStudent[MAX_NAME_SIZE];
        printf("Who will give the rate: ");
        get_line(nameStudent);
        student = (struct Student *)find_student(nameStudent);

        char nameProfessor[MAX_NAME_SIZE];
        printf("Who will receive the rate: ");
        get_line(nameProfessor);
        professor = (struct Professor *)find_professor(nameProfessor);

        puts(professor->name);
        unsigned int value;
        printf("Input the rate: ");
        scanf("%u", &value);
        printf("%u\n", value);

        student->score_func(professor, value);
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    func();

    return 0;
}
