#include <stdio.h>
#include <stdlib.h>

#define NUMBUFS 10
char *bufs[NUMBUFS];

int main() {
  unsigned int bufnum, size, i;
  for (i = 0; i < NUMBUFS; i++) bufs[i] = NULL;
  printf("exploit me bro\n");
  while (1) {
    read(0, &bufnum, sizeof(bufnum));
    if (bufnum >= NUMBUFS) continue;
    read(0, &size, sizeof(size));
    if (size == 0) {
      if (bufs[bufnum] != NULL) free(bufs[bufnum]);
      bufs[bufnum] = NULL;
    } else {
      bufs[bufnum] = (char *)malloc(size);
      if (bufs[bufnum] != NULL) {
        int r = read(0, bufs[bufnum], size);
        if (r > 0) {
          bufs[bufnum][r] = '\0';
        }
      }
    }
  }
}

