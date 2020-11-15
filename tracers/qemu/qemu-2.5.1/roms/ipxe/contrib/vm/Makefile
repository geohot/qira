all : serial-console.1

%.1 : %
	pod2man $< > $@

clean :
	rm -f serial-console.1
