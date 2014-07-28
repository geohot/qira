#include <stdio.h>

int main(int argc, char *argv[]) {
  int a = atoi(argv[1]);
  a *= 0;
  if (a) {
    printf("WINNER\n");
  } else {
    printf("LOSER\n");
  }
}

