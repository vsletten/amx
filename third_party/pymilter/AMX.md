# pymilter 1.0.5, patched for libmilter's worker pool

This is pymilter 1.0.5 (GPL; see `COPYING`), the PyPI sdist that `uv.lock` used to pin
(`pymilter-1.0.5.tar.gz`, sha256 `2fac54d5b5ccca87786ad25eb0057a40bee6d5d3f71d7a6d5fe495ab6e460c3f`).
The sdist's tests, test data, and packaging extras are left out; the first commit that added
this directory has the files as shipped, and the later ones have the patch. `setup.py` says
`1.0.5+amx.1`; `pyproject.toml` here only tells uv to rebuild when the sources change.

## The patch (`miltermodule.c`)

pymilter keeps a Python thread state (`PyThreadState`) per libmilter connection: made on the
thread that runs the connection's first callback, re-attached for every later callback, and
deleted by `milter_wrap_close()`. That assumes libmilter's thread-per-connection model. Debian's
libmilter (8.18.1, and Ubuntu's) is built with `_FFR_WORKERS_POOL`: a connection waits in a
poll loop between commands, and whichever pool worker is free runs its next callback. So the
thread state runs on threads other than its own, and close deletes it on any of them.

Python binds a thread state to the PyGILState slot of an OS thread: 3.12 and later do it when
the thread state is made (if that thread's slot is empty) or first attached. Deleting it clears
the slot of the thread that deletes it, so deleting it on another thread leaves its own thread's
slot pointing at freed memory. Python 3.11 left that pointer too, but 3.12 made attaching write
through it: the next new thread state attached on that thread runs `bind_gilstate_tstate()`,
which clears a bit in the old one (`tcur->_status.bound_gilstate = 0`, 32 bytes into a freed
344-byte block).
- Usually that block is already another thread state. The write then clears that thread state's
  binding bit, so its own deletion skips the unbinding and leaves another slot dangling.
- When the block has been cut into small chunks, the write clears bit 3 of a free chunk's link,
  and glibc aborts later: `malloc_consolidate(): unaligned fastbin chunk detected` (gateway-ct,
  PLAN §8), `malloc(): unaligned tcache chunk detected`, or `free(): invalid pointer`.

The patch makes a thread state per callback instead, on the thread that runs the callback, and
deletes it there before returning to libmilter (`_acquire_thread`, `_release_thread`): the same
thing `PyGILState_Ensure`/`PyGILState_Release` do for a thread Python did not start. Callbacks
make it in `callback_interp`, which `milter.main()` sets and never clears: libmilter's workers
still run commands they have already read after `smfi_main()` returns. If a thread state
cannot be made in close, the context is unlinked from libmilter's and leaked.

What this changes for filter code: anything tied to a thread state lasts one callback, not one
connection. That covers `threading.local`, context variables, and the running asyncio loop.
`threading.current_thread()` is a new `Dummy-N` in each callback, so a log format with
`%(threadName)s` shows a new name per callback. amx's milter keeps its state on the
`Milter.Base` instance and uses none of these.

`tests/unit/test_milter_threads.py` drives a probe filter the way Stalwart does (many short
connections in parallel, plus a callback that raises and a connection closed before CONNECT). It
checks that every callback runs on its thread's own thread state, and that callbacks still run
after `milter.main()` returns. The first test fails with PyPI's 1.0.5.

`repro/tstate_abort.c` reduces the old pattern to two threads and gets glibc's abort from it, and
no abort from the new one; its header says how to run it in the gateway image.

## Dropping it

pymilter's master (checked 2026-09-26) still keeps a thread state per connection. If an upstream
release fixes this: remove `[tool.uv.sources]` and the ruff `extend-exclude` from the root
`pyproject.toml`, relock, delete the `COPY third_party` line from `deploy/gateway/Dockerfile`,
delete this directory, and drop its line from PLAN §5.1. The test above says whether the release
is fixed; keep it.
