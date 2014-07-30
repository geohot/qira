void swag();
void swag2();

int main() {
  int i;
  int j = 1;
  int k = 1;
  int l = 1;
  for (i = 1; i < 10; i++) {
    j *= i;
    k += 1;
    l += i;
  }
  swag();
  swag2();
  printf("%d %d %d\n", j, k, l);
}

