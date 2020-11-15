\ tag: monochrome logo
\ 
\ simple monochrome logo
\ as described in IEEE 1275-1994
\ 
\ Copyright (C) 2003 Stefan Reinauer
\ 
\ See the file "COPYING" for further information about
\ the copyright and warranty status of this work.
\ 


\ FIXME : This is currently just a test file, it contains
\ a Pi symbol of size 64x64, not really nicely streched.

\ To use an XBM (X Bitmap), the bits in the bitmap array
\ have to be reversed, i.e. like this:
\ 
\ int main(void)
\ {
\ 	int i,j; unsigned char bit, bitnew;
\ 	for (i=0; i<512; i++) {
\ 		bit=openbios_bits[i]; bitnew=0;
\ 		for (j=0; j<8; j++)
\ 			if (bit & (1<<j)) bitnew |= (1<<(7-j));
\ 		 printf("%02x c, ", bitnew); if(i%8 == 7) printf("\n");
\ 	}
\ 	return 0;
\ }

here

00 c, 00 c, 00 c, 00 c, 00 c, 00 c, 00 c, 00 c, 
00 c, 00 c, 00 c, 00 c, 00 c, 00 c, 00 c, 00 c, 
07 c, ff c, ff c, ff c, ff c, ff c, ff c, e0 c, 
07 c, ff c, ff c, ff c, ff c, ff c, ff c, e0 c, 
07 c, ff c, ff c, ff c, ff c, ff c, ff c, e0 c, 
07 c, ff c, ff c, ff c, ff c, ff c, ff c, e0 c, 
7f c, ff c, ff c, ff c, ff c, ff c, ff c, e0 c, 
7f c, ff c, ff c, ff c, ff c, ff c, ff c, e0 c, 
7f c, ff c, ff c, ff c, ff c, ff c, ff c, e0 c, 
7f c, ff c, ff c, ff c, ff c, ff c, ff c, e0 c, 
7f c, df c, ff c, ff c, 7f c, ff c, ff c, 90 c, 
78 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
78 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
78 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
70 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 00 c, 00 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 01 c, 80 c, 
00 c, 03 c, fe c, 00 c, 07 c, f8 c, 01 c, e0 c, 
00 c, 03 c, fe c, 00 c, 07 c, f8 c, 01 c, e0 c, 
00 c, 03 c, fe c, 00 c, 07 c, fc c, 03 c, e0 c, 
00 c, 07 c, fe c, 00 c, 07 c, fc c, 07 c, e0 c, 
00 c, 3f c, fe c, 00 c, 07 c, ff c, ff c, e0 c, 
00 c, 3f c, fe c, 00 c, 07 c, ff c, ff c, e0 c, 
00 c, 3f c, fe c, 00 c, 07 c, ff c, ff c, e0 c, 
00 c, 3f c, fc c, 00 c, 07 c, ff c, ff c, c0 c, 
00 c, 3f c, f8 c, 00 c, 07 c, ff c, ff c, 80 c, 
00 c, 7f c, e0 c, 00 c, 0f c, ff c, fe c, 00 c, 
00 c, 3f c, e0 c, 00 c, 07 c, ff c, fe c, 00 c, 
00 c, 3f c, c0 c, 00 c, 07 c, ff c, fc c, 00 c, 
00 c, 00 c, 00 c, 00 c, 00 c, 00 c, 00 c, 00 c, 
00 c, 00 c, 00 c, 00 c, 00 c, 00 c, 00 c, 00 c, 
00 c, 00 c, 00 c, 00 c, 00 c, 00 c, 00 c, 00 c, 
00 c, 00 c, 00 c, 00 c, 00 c, 00 c, 00 c, 00 c, 
00 c, 00 c, 00 c, 00 c, 00 c, 00 c, 00 c, 00 c, 

value (romlogo-64x64)
