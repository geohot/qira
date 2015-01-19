#include <stdio.h>

int main() {
  printf("FORK TEST\n");
  fflush(stdout);
  fork();
  printf("hi %d\n", getpid());
  /*if (fork() == 0) {
    printf("hello child\n");
  } else {
    printf("world parent\n");
  }*/
}

