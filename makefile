# Makefile for TCP project

all: myping Sniffer

myping: myping.c
	gcc -o myping myping.c

Sniffer: Sniffer.c
	gcc -o Sniffer Sniffer.c

clean:
	rm -f *.o myping Sniffer

runs:
	./myping

runc:
	./Sniffer

runs-strace:
	strace -f ./Sniffer

runc-strace:
	strace -f ./myping