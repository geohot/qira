#include <stdio.h>

int main(int argc, char *argv[]) {
  int a = atoi(argv[1])+27;
  printf("got %d\n", a);
  if (a == 37) {
    printf("WINNER\n");
  } else {
    printf("LOSER\n");
  }
}

