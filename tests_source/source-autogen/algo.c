int _start() {
  main();
  asm("movl $1,%%eax\n" \
      "xorl %%ebx,%%ebx\n" \
      "int $0x80" : );
}

int bubble_sort(int *dat, int len) {
  int ret = 0;
  int i, j;
  for (i = 0; i < len; i++) {
    for (j = i; j < len; j++) {
      if (dat[j] < dat[i]) {
        ret++;
        dat[i] ^= dat[j];
        dat[j] ^= dat[i];
        dat[i] ^= dat[j];
      }
    }
  }
  return ret;
}

int fib(int n) {
  if (n == 0 || n == 1) {
    return 1;
}
  return fib(n-1) + fib(n-2);
}

int recurse_countdown(int i) {
  if (i == 0) return 1;
  int ret = recurse_countdown(i-1);
  return ret+1;
}

int sum_of_1_through_10() {
  int i, j=0;
  for (i = 0; i < 10; i++) {
    j += i;
  }
  return i;
}

int control_flow(int a) {
  if (a) return 6;
  else return 4;
}

int nest2() {
  return 25;
}

int nest1() {
  return nest2();
}

int nest() {
  return nest1();
}

void memcpy(char *dest, char *src, int len) {
  int i;
  for (i=0;i<len;i++) i[dest] = i[src];
}

int main() {
  int ret = 0;
  int tmp[] = {345,43,22,2,3,6,78,7,7};

  ret += control_flow(1);
  ret += control_flow(0);
  ret += nest();
  ret += sum_of_1_through_10();
  ret += recurse_countdown(10);
  //ret += fib(4);
  //ret += bubble_sort(tmp, sizeof(tmp)/sizeof(int));
  return ret;
}

