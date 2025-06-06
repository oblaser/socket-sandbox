
# author        Oliver Blaser
# date          05.06.2025
# copyright     GPL-3.0 - Copyright (c) 2025 Oliver Blaser


CC = gcc
CC_BIN = gcc
LINK = gcc

CFLAGS_COMMON = -pedantic -Wall -Werror=format -Werror=overflow -Werror=return-type -Wdouble-promotion  -Werror=discarded-qualifiers -Werror=implicit -Werror=incompatible-pointer-types -Werror=int-conversion -Werror=pointer-sign

CFLAGS = -c $(CFLAGS_COMMON)
CFLAGS_BIN = $(CFLAGS_COMMON)
LFLAGS = 

OBJS = common.o socket-helper.o
EXES = server.bin client.bin

FILES_TO_CLEAN = $(OBJS) $(EXES)

BUILDDATE = $(shell date +"%Y-%m-%d-%H-%M")



all: $(EXES)

server.bin: $(OBJS) server.c
	$(CC_BIN) $(CFLAGS_BIN) $(LFLAGS) -o server.bin server.c $(OBJS)

client.bin: $(OBJS) client.c
	$(CC_BIN) $(CFLAGS_BIN) $(LFLAGS) -o client.bin client.c $(OBJS)

common.o: ../common.c ../common.h
	$(CC) $(CFLAGS) ../common.c

socket-helper.o: ../socket-helper.c ../socket-helper.h
	$(CC) $(CFLAGS) ../socket-helper.c

clean:
	rm $(FILES_TO_CLEAN)
