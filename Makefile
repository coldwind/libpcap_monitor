CC = gcc
CFLAGS = -Wall -o2 -lpcap -o
install:main.c
	$(CC) $^ $(CFLAGS) monitor

.PHONY:clean
clean:
	@rm monitor
