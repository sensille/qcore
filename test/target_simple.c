/*
 * Single-threaded test target.
 *
 * Embeds a unique marker string that the test suite can grep for inside the
 * core file to verify that heap/data memory was actually captured.
 */
#include <stdio.h>
#include <unistd.h>
#include <string.h>

/* Placed in BSS so it ends up in a PT_LOAD segment. */
static volatile char heap_marker[64];

int main(void)
{
    /* Marker must survive optimisation – write it at runtime. */
    memcpy((char *)heap_marker, "QCORE_MEMORY_MARKER_DEADBEEF1234", 33);

    printf("ready pid=%d\n", getpid());
    fflush(stdout);

    while (1) pause();   /* re-enter after -EINTR from ptrace detach */
}
