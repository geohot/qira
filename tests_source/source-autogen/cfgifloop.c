int main(int argc) {
  int i, j;
  for (i = 0; i < 6; i++) {
    if (argc==1) {
      for (j = 0; j < 6; j++) {
        printf("%d %d\n", i, j);
        if (j == 4) break;
      }
    } else {
      printf("cats %d\n", i);
    }
  }
}
