#AUTHOR: Denis Dzibela xdzibe00
CC = g++

CFLAGS = -lpcap

.PHONY: compile clean pack

compile: main.cpp headers.h
	$(CC) $^ -o ipk-sniffer $(CFLAGS)

clean:
	-rm ipk-sniffer 2>/dev/null || true
	-rm main 2>/dev/null || true
	-rm xdzibe00.tar 2>/dev/null || true

pack: clean
	-tar -cf xdzibe00.tar Makefile README main.cpp headers.h protocols.h