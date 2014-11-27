#include <stdio.h>

int main() {
  register long esp __asm__("esp");
  printf("%8.8lx\n", esp);
}

