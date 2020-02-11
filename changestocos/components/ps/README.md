# Building and testing

```
$ ./configure linux x86
$ make
```

Additional options include:

```
$ make tests
$ make clean
```

Testing:

```
$ ./configure linux x86
$ make tests
$ cd tests/
$ ./list.test
$ sudo ./slab.test
$ ...repeat with each *.test executable...
```

# Organization

- `ps_config.h` includes some configuration variables...edit this directly for your system.
- `Makefile.config` is an auto-generated file (with `configure`) includes two variables that control your OS and architecture.  These variables must exactly match a pair of directories in `plat/os/` and `plat/arch/`.
- `libps.a` is the output of the library compilation.  Including this in your `-L` path, and including this directory in `-I` will enable you to use the library.
- `README.md` and `TODO.md` ...take a wild guess ;-)
- `plat/` is the platform directory including both architecture-specific, and OS-specific functions.
- `tests/` the set of tests for each parsec abstraction.  A set of `*.test` executables are generated by this that can each be run as `root` (necessary to set thread affinity).

# FAQ

We presented the Parsec work at Eurosys, and a number of good questions arose.
I'll answer a few of those here, along with some questions from the program committee's reviews.

### Using `rdtsc` Properly

Q: There are complications with using `rdtsc`.
It is not a serializing instruction, so it can be reordered in the pipeline relative to memory operations.
Put another way, the accesses to the data-structure can be reordered *before* the time stamp counter (TSC) can be made visible to other cores in memory.

A: This is a great question, and originates from the fact that using `rdtsc` is surprisingly difficult to get right large because it is a *non-serializing* instruction.
Using the serializing variant (`rdtscp`) has a significant overhead (~80 vs 30 cycles).
We use a memory barrier to make sure that the memory value generated by `rdtsc` is visible to other cores *before* accessing the enclosed data-structure.
This has the effect of serializing with surrounding memory accesses.

It is certainly desirable to get rid of the memory barrier as flushing the store buffer can have significant overhead.
If we were to do so (using a previous technique that relies on the bounded size of the store buffer), then we'd have to add a conservative offset on the comparison between when memory is freed, and when tasks are accessing the parallel section.

### Avoiding `rdtsc`

Q: The `rdtsc` instruction is not free (roughly 30 cycles on our machine).
Is it possible to remove it in some way?

A: The benefit of `rdtsc` is that is provides local access to a global relation.
However, it *is* possible to use a global variable that is incremented periodically, and use that as our global time.
Each read-side section will read this global variable, thus will cause coherency traffic after it is updated.
However, these updates can be scheduled (i.e. modifying the period of time updates) to trade between the coherency overheads, and the rapid advancement of time.
The slower that time ticks by, the more difficult it is to distinguish between when memory is freed, and when parallel sections are being accessed.

In this case, the benefit of Parsec SMR stems from the fact that it tries to ascertain quiescence for when memory was freed.
Is any parallel section accessing that memory since before it was freed?
When memory is freed, it is queued.
When we attempt to quiesce, we try for the memory at the *head* of the queue (that was freed furthest in the past).
When we get a quiescence value, we can apply it to as many nodes of memory as possible.
This means that the operation is *wait-free* while still guaranteeing *progress* in deallocating memory.
Even if we can't reclaim memory *now*, as quiescence can't be achieved, we will be able to at a future point in time (assuming that all threads eventually clear their parallel sections).
Thus, even if we use a global variable to track time, there still is some benefit as we still get wait-free memory reclamation that is as scalable for quiescence as the `rdtsc` approach.

### Vs. Batch Frees

Q: Can't we just do a batch quiescence for many memory items, instead of a quiescence per memory free?
This would amortize the cost of the synchronization operation.

A: Yes.
In that case, we're manually attempting to compensate for the lack of scalability within the quiescence primitives.
The downsides of this approach are 1. that it is still using a primitive that spins determining quiescence, and 2. that the batch size is a key factor in the system that must be tuned.
In this context, Parsec SMR can be seen as a runtime that determines batch sizes automatically, and avoids inducing the latency spikes of spin-base quiescence (regardless how infrequent).