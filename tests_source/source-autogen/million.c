int main() {
  volatile int i;
  for (i = 0; i < 1000000; i++);
  return i;
}
