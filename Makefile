CC = gcc
CFLAGS = -Wall -std=gnu99 -g

all: psnap psnapexec

psnap: report.o psnap.o
	$(CC) $(CFLAGS) report.o psnap.o -o psnap

psnapexec: report.o psnapexec.o
	$(CC) $(CFLAGS) report.o psnapexec.o -o psnapexec

psnap.o: psnap.c
	$(CC) $(CFLAGS) -c psnap.c

psnapexec.o: psnapexec.c
	$(CC) $(CFLAGS) -c psnapexec.c

report.o:
	$(CC) $(CFLAGS) -c report.c

clean:
	rm -f report.o psnap.o psnapexec.o psnap psnapexec
