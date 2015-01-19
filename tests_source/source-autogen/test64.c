#include <stdio.h>

int main() {
  volatile long a = 0xFFFFFFFFFFFFFFFF;
  a--;
  a *= 2;
  printf("%ld\n", a);
  return a;
}

