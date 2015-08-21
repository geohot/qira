#include <sys/mman.h>
#include <stdio.h>


int main() {
  int (*sc)();

  char *ptr = mmap(0, 0x1000, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);
  sc = ptr;

  ptr[0] = 0x31;
  ptr[1] = 0xc0;
  ptr[2] = 0x40;
  ptr[3] = 0xc3;
  printf("%d\n", sc());

  ptr[2] = 0xc3;
  printf("%d\n", sc());
}

