#include <stdio.h>
char buf[0x1000];

int main() {
  FILE *f = fopen("/proc/self/maps", "rb");
  buf[fread(buf, 1, 0x1000, f)] = '\0';
  fclose(f);
  printf("%s\n", buf);
  return 0;
}

