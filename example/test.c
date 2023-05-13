#include <stdio.h>
#include <stdlib.h>

struct mybuffer {   // size 30
    char *ptr;  // we need to overwrite this !!!
    char data[26];
};

struct vulobj {    // size 12
    char name[4];
    char *data;
    int len;
}


void *mybuffers[200];
void *vulobjs[200];


void add_buffer()
{
    int i = 0;
    for (; i < 200; i++) {
        if (mybuffers[i] == 0) {
            void *ptr = malloc(sizeof(struct mybuffer));
            mybuffers[i] = ptr;
            break;
        }
    }
    return;
}

void del_buffer(int i)
{
    if (mybuffers[i] != 0) {
        free(mybuffers[i]);
    }
    return;
}


void add_vulobj()
{
    int i = 0;
    for (; i < 200; i++) {
        if (vulobjs[i] == 0) {
            int x = get_int();
            
            char *data = (char*)malloc(x);
            void *ptr = malloc(sizeof(struct vulobj));
            ptr->data = data;
            prt->len = x;
            vulobjs[i] = ptr;
            break;
        }
    }
    return;
}

void del_vulobj(int i)
{
    if (vulobjs[i] != 0) {
        free(vulobjs[i]->data);
        free(vulobjs[i]);
    }
    return;
}

void edit_vulobj(int i)
{
    if (vulobjs[i] != 0) {
        read(0, vulobjs[i]->data, vulobjs[i]->len + 4);   // overflow 4 bytes
    }
    return;
}

void main(int argc, char const *argv[])
{
	int done = 0;
	int choiece = 0;

	while(!done):
		printf("Main Menu\n");
        printf("1. Add MyBuffer\n");
        printf("2. Del MyBuffer\n");
        printf("3. Add Vulobjects and length \n");
        printf("4. Del vulobjs\n");
        printf("5. Edit vulobjs\n");

        printf("Current Number of items in array = %d\n", array_size);
        fflush(stdout);
        choice = strtol(input, NULL, 10);
        int index = 0;
        switch (choice) {
        case 1:
            add_buffer();
            break;
        case 2:
            printf("input buffer index:\n");
            scanf("%d",$index);
            del_buffer(index);
            break;
        case 3:
            printf("input buffer size\n");
            add_vulobj();
            break;
        case 4:
            printf("input buffer index:\n");
            scanf("%d",$index);
            del_vulobj(index);
            break;

	return 0;
}