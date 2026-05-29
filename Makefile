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
#   1. Assemble parasite.S to an ELF object.
#   2. Extract ONLY the .text section as a raw binary.
#      We use objcopy -j .text rather than ld --oformat=binary because
#      modern GCC adds .note.gnu.property (and possibly .comment) sections
#      to the object file.  ld --oformat=binary includes all allocated
#      sections; on distros where .note.gnu.property is placed at offset
#      4096+, the resulting binary exceeds our 4096-byte code page and
#      qcore refuses to load it.  objcopy -j .text extracts exactly the
#      shellcode bytes and nothing else.
#   3. Convert the raw binary to a C header with xxd.
# ---------------------------------------------------------------------------
parasite.o: parasite.S
	$(CC) -c -o $@ $<

parasite.bin: parasite.o
	objcopy -j .text -O binary $< $@

parasite.h: parasite.bin
	xxd -i $< | sed 's/^unsigned char/static const unsigned char/' | sed 's/^unsigned int/static const unsigned int/' > $@

clean:
	rm -f $(OBJS) parasite.o parasite.bin parasite.h $(TARGET) core.* *.json
