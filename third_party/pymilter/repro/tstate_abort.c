/* The gateway-ct abort, from pymilter 1.0.5's thread-state pattern alone (see ../AMX.md).
 *
 * pymilter keeps one PyThreadState per milter connection: made by _get_context() on the worker
 * that runs the connection's first callback, and deleted by milter_wrap_close() on whichever
 * worker runs close. libmilter's worker pool makes those two workers differ. Here worker A runs
 * connection 1's first callback, worker B closes it, then A reuses the freed block as small
 * buffers (libmilter's command buffers, say), starts connection 2, and makes a large request.
 *
 * Run it in the gateway image, which has a compiler and Python's headers:
 *   docker run --rm -v "$PWD/third_party/pymilter/repro:/w" --entrypoint sh amx-gateway-ct -c \
 *     'gcc -w -o /tmp/r /w/tstate_abort.c $(python3.13-config --includes) -L/usr/local/lib \
 *      -lpython3.13 -lpthread && for pad in 0 32768; do for p in "" 1; do \
 *      PAD=$pad PATCHED=$p LD_LIBRARY_PATH=/usr/local/lib \
 *      GLIBC_TUNABLES=glibc.malloc.tcache_count=0 /tmp/r; echo "pad=$pad patched=$p rc=$?"; \
 *      done; done'
 *
 * With PAD=32768 and no PATCHED it aborts (rc 134) with glibc's
 * "malloc_consolidate(): unaligned fastbin chunk detected". Python 3.13 clears bit 3 of the word
 * 32 bytes into the freed thread state (bind_gilstate_tstate), which is a free chunk's link. The
 * link is stored XORed with its address shifted right 12 bits, so its bit 3 is set when bit 15 of
 * the address is: PAD=0 corrupts nothing visible, and PAD=32768 moves the block to where it does.
 * That is this harness's layout; in a gateway, where the freed block lands and what reuses it
 * vary, which is why the abort was rare. With PATCHED=1 (each callback makes and deletes its own
 * thread state, as the vendored build does) it never aborts. GLIBC_TUNABLES turns off glibc's
 * per-thread cache so the small chunks go to the fastbins; with the cache on, the same write can
 * hit a cached chunk's link instead, and glibc reports "malloc(): unaligned tcache chunk
 * detected" (as the unpatched gateway did under stress).
 */
#include <Python.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

static PyInterpreterState *interp;
static PyThreadState *conn1;
static void *padding;

static void *a_first_callback(void *arg) {    /* _get_context() for a new connection */
    (void)arg;
    if (getenv("PAD")) padding = malloc(atoi(getenv("PAD")));  /* what came before it */
    conn1 = PyThreadState_New(interp);
    PyEval_AcquireThread(conn1);
    PyRun_SimpleString("pass");
    if (getenv("PATCHED") && *getenv("PATCHED")) {  /* patched _release_thread() */
        PyThreadState_Clear(conn1);
        PyEval_ReleaseThread(conn1);
        PyThreadState_Delete(conn1);
    } else {
        PyEval_ReleaseThread(conn1);                /* 1.0.5's _release_thread() */
    }
    return NULL;
}

static void *b_close(void *arg) {              /* milter_wrap_close() */
    (void)arg;
    PyThreadState *t = conn1;                   /* 1.0.5: the connection's thread state */
    if (getenv("PATCHED") && *getenv("PATCHED")) t = PyThreadState_New(interp);  /* patched */
    PyEval_AcquireThread(t);
    PyThreadState_Clear(t);
    PyEval_ReleaseThread(t);
    PyThreadState_Delete(t);
    return NULL;
}

static void *a_small_buffers(void *arg) {      /* the freed block, as small freed chunks */
    (void)arg;
    void *chunks[16];
    for (int i = 0; i < 16; i++) chunks[i] = malloc(24);
    for (int i = 0; i < 16; i++) free(chunks[i]);
    return NULL;
}

static void *a_next_connection(void *arg) {    /* _get_context() for the next connection */
    (void)arg;
    PyThreadState *conn2 = PyThreadState_New(interp);
    PyEval_AcquireThread(conn2);                 /* binds conn2 as A's PyGILState state */
    PyThreadState_Clear(conn2);
    PyEval_ReleaseThread(conn2);
    PyThreadState_Delete(conn2);
    return NULL;
}

static void *a_large_buffer(void *arg) {       /* a large request consolidates the fastbins */
    (void)arg;
    free(malloc(64 * 1024 - 64));
    return NULL;
}

/* A worker runs one step at a time and stays alive between steps, like a pool worker. */
typedef struct {
    pthread_mutex_t m;
    pthread_cond_t c;
    void *(*step)(void *);
    int done;
} worker_t;

#define STOP ((void *(*)(void *))1)

static void *worker(void *arg) {
    worker_t *w = arg;
    for (;;) {
        pthread_mutex_lock(&w->m);
        while (w->step == NULL) pthread_cond_wait(&w->c, &w->m);
        void *(*step)(void *) = w->step;
        pthread_mutex_unlock(&w->m);
        if (step == STOP) return NULL;
        step(NULL);
        pthread_mutex_lock(&w->m);
        w->step = NULL;
        w->done = 1;
        pthread_cond_broadcast(&w->c);
        pthread_mutex_unlock(&w->m);
    }
}

static void run(worker_t *w, void *(*step)(void *)) {
    pthread_mutex_lock(&w->m);
    w->step = step;
    w->done = 0;
    pthread_cond_broadcast(&w->c);
    if (step != STOP)
        while (!w->done) pthread_cond_wait(&w->c, &w->m);
    pthread_mutex_unlock(&w->m);
}

int main(void) {
    Py_Initialize();
    interp = PyThreadState_Get()->interp;
    PyThreadState *main_state = PyEval_SaveThread();  /* as milter.main() does */

    worker_t a = {PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, NULL, 0};
    worker_t b = {PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, NULL, 0};
    pthread_t ta, tb;
    pthread_create(&ta, NULL, worker, &a);
    pthread_create(&tb, NULL, worker, &b);
    run(&a, a_first_callback);
    run(&b, b_close);
    run(&a, a_small_buffers);
    run(&a, a_next_connection);
    run(&a, a_large_buffer);
    run(&a, STOP);
    run(&b, STOP);
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);

    PyEval_RestoreThread(main_state);
    free(padding);
    Py_Finalize();
    return 0;
}
