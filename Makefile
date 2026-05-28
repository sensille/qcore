CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -g -D_GNU_SOURCE
TARGET  = qcore
SRCS    = main.c seize.c fd_harvest.c cow_clone.c resume.c elf_dump.c
OBJS    = $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c qcore.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET) core.* *.json
