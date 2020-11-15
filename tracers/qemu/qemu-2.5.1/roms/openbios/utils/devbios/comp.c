/* Simple utility to compare 2 files.
 * Diff or cmp are not sufficient, when
 * comparing bioses :-)
 *
 * Copyright (c) 1998-2000 by Stefan Reinauer
 */


#include <stdio.h>

int main (int argc, char *argv[])
{
   FILE *eins,*zwei;
   int a,b,i=0,flag=0;

   if(argv[1]==NULL||argv[2]==NULL) {
	printf ("Usage: %s file1 file2\n  %s compares two files.\n",argv[0],argv[0]);
	return 0;
   }
   eins=fopen(argv[1],"r");
   zwei=fopen(argv[2],"r");

   if (eins==NULL) {
	printf ("File %s not found or unreadable.\n",argv[1]);
	return 0;
   }
   if (zwei==NULL) {
	printf ("File %s not found or unreadable.\n",argv[2]);
	fclose (eins);
	return 0;
   }

   while (!feof(eins)) {
	a=fgetc(eins);
	b=fgetc(zwei);
	if (flag==0 && (a==-1||b==-1) && (a!=-1||b!=-1)) {
		printf ("One file ended. Printing the rest of the other.\n");
		flag=1;
	}
	if(a!=b) printf ("0x%06x: 0x%02x -> 0x%02x\n",i,a,b);
	i++;
   }

   fclose(eins);
   fclose(zwei);
   return 0;
}
