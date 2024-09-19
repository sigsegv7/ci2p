CC = gcc
CFILES = $(shell find src/ -name "*.c")
CFLAGS = -pedantic -Iinclude/ -lcurl -lssl -lcrypto -lzip

all:
	$(CC) $(CFLAGS) $(CFILES) -o ci2p

install:
	mkdir -p /var/run/ci2p/
	mkdir -p /var/run/ci2p/netdb/
	mkdir -p /etc/ci2p/
	cp -r certs /etc/ci2p
