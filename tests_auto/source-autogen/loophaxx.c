#include <stdio.h>


int print(int i) {
  printf("%d\n", i);
}

int main() {
  int i;
  for (i = 0; i < 5; i++) {
    print(i);
  }
}

