CC      = gcc
CFLAGS  = -Wall -Wextra -O0 -g -D_GNU_SOURCE
TARGETS = target_simple target_mt target_sockets target_registers

.PHONY: all clean

all: $(TARGETS)

target_simple:   target_simple.c
	$(CC) $(CFLAGS) -o $@ $<

target_mt:       target_mt.c
	$(CC) $(CFLAGS) -o $@ $< -lpthread

target_sockets:  target_sockets.c
	$(CC) $(CFLAGS) -o $@ $<

# -O0 is critical: prevents the compiler eliminating the volatile sentinel
# loads or reordering them relative to the inline asm pause syscall.
target_registers: target_registers.c
	$(CC) -O0 -g -D_GNU_SOURCE -o $@ $<

clean:
	rm -f $(TARGETS) *.o /tmp/qcore_test_*.sock
