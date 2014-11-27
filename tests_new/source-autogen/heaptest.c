#include <stdio.h>

int main() {
  char *a = malloc(0x100);
  char *b = malloc(0x100);
  memset(a, 0, 0x400);
  //read(0, a, 0x100);
  free(b);
}

