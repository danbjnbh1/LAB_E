CC = gcc
CFLAGS = -m32 -Wall -g

all: myELF

myELF: myELF.c
	$(CC) $(CFLAGS) -o myELF myELF.c

clean:
	rm -f myELF out.ro

.PHONY: all clean
