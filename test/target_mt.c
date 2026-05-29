/*
 * Multi-threaded test target.
 *
 * Spawns N_WORKERS pthreads that all block in pause(), then the main thread
 * blocks too.  The test suite expects at least N_WORKERS+1 NT_PRSTATUS notes
 * in the resulting core.
 */
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include "idle_loop.h"

#define N_WORKERS 7   /* +1 for main -> 8 total threads */

static void *worker(void *arg)
{
    (void)arg;
    qcore_idle_loop();
    return NULL;
}

int main(void)
{
    pthread_t t[N_WORKERS];
    for (int i = 0; i < N_WORKERS; i++)
        pthread_create(&t[i], NULL, worker, NULL);

    printf("ready pid=%d threads=%d\n", getpid(), N_WORKERS + 1);
    fflush(stdout);

    qcore_idle_loop();
}
