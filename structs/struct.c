#include <stdio.h>

typedef struct _PERSON {

	int ID;
	int age;
	char name[];

} PERSON, *PPERSON;

int main() {
	PERSON person1 = { .ID = 1, .age = 28, .name = "Jack"};
	printf(person1.name);

	PPERSON person1Pointer = &person1;

	//person1Pointer->ID = 8765;
	printf("The structure's ID member is now : %d \n", person1Pointer->ID);
}