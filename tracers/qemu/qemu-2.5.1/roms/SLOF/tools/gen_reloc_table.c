/******************************************************************************
 * Copyright (c) 2004, 2008 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>

static int reloc_64_cnt;

static int reloc_64[4096];

static void
output_int(FILE *output_file, int i)
{
  fputc((i>>24) & 0xff, output_file);
  fputc((i>>16) & 0xff, output_file);
  fputc((i>>8) & 0xff, output_file);
  fputc(i & 0xff, output_file);
}

static void
output_reloc_table(FILE * output_file, int reloc_cnt, int reloc[])
{
  int i;
  for (i=0; i < reloc_cnt; i++)
    {
#ifdef DEBUG
      printf ("reloc %x\n", reloc[i]);
#endif
      output_int (output_file, reloc[i]);
    }
  if ((reloc_cnt & 1) == 0)
    output_int (output_file, 0);
}

int
main(int argc, char *argv[])
{
  int cnt_a, cnt_b, offset = -1;
  unsigned char a, b;
  FILE *orig, *other, *output_file;

  if (argc != 4)
    {
      fprintf (stderr, "reloc_diff orig_file other_file output_file\n");
      exit(-1);
    }
    
  orig = fopen(argv[1], "rb");
  other = fopen(argv[2], "rb");
  output_file = fopen(argv[3], "wb");
  if(orig == NULL || other == NULL || output_file == NULL) {
    printf("Could not open file.\n");
    return -1;
  }

  while (1)
    {
      cnt_a = fread(&a, 1, 1, orig);
      cnt_b = fread(&b, 1, 1, other);
      offset ++;
      if (cnt_a != cnt_b)
	{
	  fprintf (stderr, "Files >%s< and >%s< have not the same length\n",argv[1],argv[2]);
	  exit(-1);
	}

      if (cnt_a == 0)
	break;
      
      if (a == b)	continue;

      if (a + 0x40 == b)
	{
	  reloc_64[reloc_64_cnt++] = offset;
	}
      else
	{
	  fprintf(stderr, "Unknown relocation");
	  fprintf(stderr, "Offset %x: %02x %02x\n", offset, a, b);
	  break;
	}
    }

  output_reloc_table(output_file, reloc_64_cnt, reloc_64);
  return 0;
}
