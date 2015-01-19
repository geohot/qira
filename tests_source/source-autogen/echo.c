#include <stdio.h>

int main() {
  char buf[0x100];
  printf("swag is king\n");
  fflush(stdout);
  fprintf(stderr, "error is king\n");
  fflush(stderr);
  while (1) {
    int a = read(0, buf, 0x100);
    if (a <= 0) break;
    write(1, buf, a);
  }
  return -1;
}

