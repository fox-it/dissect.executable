// gcc hello_world.c -Wl,-Ttext-segment=0x1000000 [-static] -o hello_world.bin
#include <stdio.h>

int main() {
    setbuf(stdout, NULL);
    printf("Kusjes van SRT <3\n");
}
