#AUTHOR: Denis Dzibela xdzibe00
CC = g++

CFLAGS = -lpcap

.PHONY: compile clean pack

compile: main.cpp
	$(CC) $^ -o ipk-sniffer $(CFLAGS)

clean:
	-rm ipk-sniffer 2>/dev/null || true
	-rm main 2>/dev/null || true

pack: clean