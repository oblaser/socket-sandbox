
# author        Oliver Blaser
# date          07.04.2025
# copyright     GPL-3.0 - Copyright (c) 2025 Oliver Blaser


CC = gcc
CC_BIN = gcc
LINK = gcc

CFLAGS_COMMON = -pedantic -Wall -Werror=return-type -Werror=format -Wdouble-promotion -Werror=implicit -Werror=int-conversion -Werror=discarded-qualifiers -Werror=incompatible-pointer-types

CFLAGS = -c $(CFLAGS_COMMON)
CFLAGS_BIN = $(CFLAGS_COMMON)
LFLAGS = 

OBJS = common.o
EXES = sniffer.bin

FILES_TO_CLEAN = $(OBJS) $(EXES)

BUILDDATE = $(shell date +"%Y-%m-%d-%H-%M")



all: $(EXES)

sniffer.bin: $(OBJS) sniffer.c
	$(CC_BIN) $(CFLAGS_BIN) $(LFLAGS) -o sniffer.bin sniffer.c $(OBJS)

common.o: ../common.c ../common.h
	$(CC) $(CFLAGS) ../common.c

clean:
	rm $(FILES_TO_CLEAN)
