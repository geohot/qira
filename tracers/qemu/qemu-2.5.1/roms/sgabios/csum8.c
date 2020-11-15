/*
 * Copyright 2010 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * compute rom checksum byte
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>

#define MAX_SIZE 65536
unsigned char buf[MAX_SIZE];

int main(int argc, char **argv)
{
  ssize_t fsize;
  int i, sum, fd;
  unsigned char csum;

  if (argc < 2) {
    fprintf(stderr, "usage: %s filename\n", argv[0]);
    exit(1);
  }
  if ((fd = open(argv[1], O_RDWR)) < 0) {
    perror(argv[1]);
    exit(1);
  }
  if ((fsize = read(fd, buf, MAX_SIZE)) < 0) {
    perror(argv[1]);
    exit(1);
  }
  if (fsize >= MAX_SIZE && read(fd, &buf[MAX_SIZE - 1], 1) > 0) {
    fprintf(stderr, "FAIL: %s is larger than %d bytes\n", argv[1], MAX_SIZE);
    exit(1);
  }
  i = fsize - 2048 * (fsize / 2048);
  if (i != 2047) {
    fprintf(stderr, "FAIL: %s is %zd bytes, need 2K pad-1\n", argv[1], fsize);
    exit(1);
  }
  for (i = sum = 0; i < fsize; i++) {
    sum += buf[i];
  }
  sum &= 0xff;
  csum = -sum & 0xff;
  write(fd, &csum, 1);
  close(fd);
  fprintf(stderr, "%s: sum = 0x%02x, wrote byte 0x%02x\n", argv[1], sum, csum);
  return 0;
}
