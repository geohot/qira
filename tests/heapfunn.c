#include <stdio.h>
#include <stdlib.h>

#define NUMBUFS 10
char *bufs[NUMBUFS];

int main() {
  unsigned int bufnum, size, haxx, i;
  int ret;
  for (i = 0; i < NUMBUFS; i++) bufs[i] = NULL;
  printf("exploit me bro\n");
  fflush(stdout);
  while (1) {
    ret = read(0, &bufnum, sizeof(bufnum)); if (ret <= 0) break;
    if (bufnum >= NUMBUFS) continue;
    ret = read(0, &size, sizeof(size)); if (ret <= 0) break;
    ret = read(0, &haxx, sizeof(haxx)); if (ret <= 0) break;
    if (size == 0) {
      if (bufs[bufnum] != NULL) free(bufs[bufnum]);
      bufs[bufnum] = NULL;
    } else {
      bufs[bufnum] = (char *)malloc(size);
      if (bufs[bufnum] != NULL) {
        ret = read(0, bufs[bufnum], size); if (ret <= 0) break;
        if (haxx) {
          bufs[bufnum][size] = '\0';
        }
      }
    }
  }
}

