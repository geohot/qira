#include <stdio.h>
volatile int k = 0;

void swag() {
  k++;
}
  
int main(int argc, char *argv[]) {
  int i;
  int j = atoi(argv[1]);
  for (i = 0; i < j; i++) {
    swag();
  }
}

