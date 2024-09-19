CC = gcc
CFILES = $(shell find src/ -name "*.c")
CFLAGS = -pedantic -Iinclude/ -lcurl -lssl -lcrypto

all:
	$(CC) $(CFLAGS) $(CFILES) -o ci2p

install:
	mkdir -p /etc/ci2p/
	cp -r certs /etc/ci2p
