# vectorNet

Userspace IPv4 and custom transport stack for macOS/Darwin on Apple Silicon.
Raw Ethernet integration will use buffered Berkeley Packet Filter devices. Phase 01
contains buildable interfaces and platform scaffolding only; it performs no packet I/O.

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_OSX_ARCHITECTURES=arm64
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Unit tests require no elevated privileges. Later raw-link and dummynet integration
scripts will isolate every privileged action under `scripts/` and restore host state.

See `AGENTS.md` for the phase gates, `HLD.md` for architecture, and `LLD.md` for
data structures and algorithms. Performance statements remain hypotheses until a
committed benchmark run supports them.
