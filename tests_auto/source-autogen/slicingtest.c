#include <stdio.h>
int main(int argc, char *argv[]) {
  int i = atoi(argv[1]);
  int j = atoi(argv[2]);
  int k = atoi(argv[3]);
  int l = i + j;
  int m = i + k;
  int n = j + k;
  printf("%d %d %d\n", l, m, n);
}

