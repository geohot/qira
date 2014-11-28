int test(int a) {
  a += 3;
  a *= 2;
  return a;
}

int main() {
  printf("hello world\n");
  int i;
  for (i = 0; i < 5; i++) {
    printf("%d\n", test(i));
  }
}

