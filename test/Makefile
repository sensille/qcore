CC      = gcc
CFLAGS  = -Wall -Wextra -O0 -g -D_GNU_SOURCE
TARGETS = target_simple target_mt target_sockets target_registers \
          target_epoll target_children target_callstack

.PHONY: all clean

all: $(TARGETS)

target_simple:   target_simple.c
	$(CC) $(CFLAGS) -o $@ $<

target_mt:       target_mt.c
	$(CC) $(CFLAGS) -o $@ $< -lpthread

target_sockets:  target_sockets.c
	$(CC) $(CFLAGS) -o $@ $<

target_registers: target_registers.c
	$(CC) -O0 -g -D_GNU_SOURCE -o $@ $<

target_epoll:    target_epoll.c
	$(CC) $(CFLAGS) -o $@ $<

target_children: target_children.c
	$(CC) $(CFLAGS) -o $@ $<

# Built as PIE (the modern distro default) ON PURPOSE: a PIE binary forces
# GDB to use the NT_FILE note in the core to compute the load bias before it
# can resolve ANY symbol.  Building -no-pie would mask NT_FILE bugs because
# GDB could resolve symbols from the executable's fixed addresses alone.
# Real-world binaries are PIE, so this is what must be tested.
target_callstack: target_callstack.c
	$(CC) -O0 -g -fno-omit-frame-pointer -fPIE -pie -D_GNU_SOURCE \
	      -o $@ $< -lpthread

clean:
	rm -f $(TARGETS) *.o /tmp/qcore_test_*.sock
