
IDIR = ./include
SDIR = ./src
ODIR = ./obj

CC = gcc
CFLAGS = -I$(IDIR) -g -Wall -Wpedantic -pthread

_DEPS = dhcp.h sniffer.h spoofer.h

DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = main.o sniffer.o spoofer.o

OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

all: main

$(ODIR)/%.o: $(SDIR)/%.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

main: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean run

run: main
	./main

clean:
	rm -f $(ODIR)/*.o
	rm -f main
