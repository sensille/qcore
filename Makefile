CC      = gcc
LD      = ld
CFLAGS  = -Wall -Wextra -O2 -g -D_GNU_SOURCE -std=gnu11
TARGET  = qcore
SRCS    = main.c seize.c fd_harvest.c inject.c elf_dump.c
OBJS    = $(SRCS:.c=.o)

.PHONY: all clean

all: parasite.h $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

# Every C file depends on both headers so a parasite change rebuilds inject.o
%.o: %.c qcore.h parasite.h
	$(CC) $(CFLAGS) -c -o $@ $<

# ---------------------------------------------------------------------------
# Parasite shellcode pipeline
#   1. Assemble parasite.S to an ELF object
#   2. Link at virtual address 0, emit raw binary (position-independent)
#   3. Convert raw binary to a C header with xxd
# ---------------------------------------------------------------------------
parasite.o: parasite.S
	$(CC) -c -o $@ $<

parasite.bin: parasite.o
	$(LD) -Ttext=0 --oformat=binary -o $@ $<

parasite.h: parasite.bin
	xxd -i $< | sed 's/^unsigned char/static const unsigned char/' | sed 's/^unsigned int/static const unsigned int/' > $@

clean:
	rm -f $(OBJS) parasite.o parasite.bin parasite.h $(TARGET) core.* *.json
