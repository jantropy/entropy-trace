"""entropytrace.adapters - project-specific glue, named as such.

The core pipeline (buildset.py, symbols.py, resolve.py, analysis/) is
backend-agnostic - it doesn't need to know anything about Coldcard or
Trust Wallet Core or any other specific project. What isn't generic is the
small amount of glue a particular project's build or runtime needs before
that pipeline can even see it: symlinking board directories before `make
-n` can resolve them, stubbing build-generated headers a real build would
normally produce first, or resolving a non-C runtime's own binding idiom
(a Python name, say) down to a C symbol the rest of the pipeline can just
keep walking from.

An adapter's job, precisely:
  - Prepare a project's tree so a generic buildset.py backend can run
    against it (board symlinks, that sort of thing).
  - Prepare a project's runtime scaffolding so preprocessing succeeds
    without a real build having actually run first.
  - Resolve a non-C binding idiom to a plain C symbol, then hand that back
    to the shared pipeline as if it were any other call.

What an adapter must never do:
  - Decide where a sink is - that's entirely analysis/sinks.py's job.
  - Decide how a chain walks forward, or terminate a walk early -
    analysis/slice.py owns the whole walk; an adapter only ever hands it
    one resolved symbol to continue from.
  - Classify a terminal, or influence what counts as one.
  - Touch policy in any way.
  - Silently change behaviour for a project that isn't using it - an
    adapter is opt-in machinery a caller reaches for by name, never
    something the pipeline reaches for on its own based on what it
    happens to spot in a tree.

No attempt is made here to build a generic binder across runtimes.
MicroPython's own module-registration idiom, CPython's PyMethodDef,
PyO3's bindings, cffi - none of these share enough shape to be worth
abstracting over. A future runtime gets its own adapter, written the same
plain way, not a "universal" interface bent to fit something it was never
built for.
"""
