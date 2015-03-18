#include <stdio.h>

int stacked(int input) {
  int plus_2 = input + 2;
  int times_5 = input * 5;
  return plus_2 + times_5;
}

int main() {
  int i;
  for (i = 1; i < 4; i++) printf("%d %d\n", i, stacked(i));
}

