
 Standard C library for the SLOF firmware project
 ================================================

To use this library, link your target against the "libc.a" archive.

However, there are some prerequisites before you can use certain parts of the
library:

1) If you want to use malloc() and the like, you have to supply an implemen-
   tation of sbrk() in your own code. malloc() uses sbrk() to get new, free
   memory regions.
   
   Prototype:   void *sbrk(int incr);
   Description: sbrk() increments the available data space by incr bytes and
                returns a pointer to the start of the new area.
   
   See the man-page of sbrk for details about this function.

2) Before you can use the stdio output functions like printf(), puts() and the
   like, you have to provide a standard write() function in your code.
   printf() and the like use write() to print out the strings to the standard
   output.

   Prototype:   ssize_t write(int fd, const void *buf, size_t cnt);
   Description: Write cnt byte from the buffer buf to the stream associated
                with the file descriptor fd.

   The stdio functions will print their output to the stdout channel which is
   assigned with the file descriptor 1 by default. Note that the stdio
   functions will not use open() before calling write(), so if the stdout
   cannel needs to be opened first, you should do that in your start-up code
   before using the libc functions for the first time.
   
3) Before you can use the stdio input functions like scanf() and the
   like, you have to provide a standard read() function in your code.
   scanf() and the like use read() to get the characters from the standard
   input.

   Prototype:   ssize_t read(int fd, void *buf, size_t cnt);
   Description: Read cnt byte from the stream associated with the file
                descriptor fd and put them into the buffer buf.

   The stdio functions will get their input from the stdin channel which is
   assigned with the file descriptor 0 by default. Note that the stdio
   functions will not use open() before calling read(), so if the stdin
   cannel needs to be opened first, you should do that in your start-up code
   before using the libc functions for the first time.
   
