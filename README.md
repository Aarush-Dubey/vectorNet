# vectorNet

Userspace IPv4 and custom transport stack for macOS/Darwin on Apple Silicon.
Raw Ethernet integration uses buffered Berkeley Packet Filter devices on the canonical
`feth0`/`feth1` pair. The implemented link and network layers cover BPF batch I/O,
Ethernet, ARP, IPv4 fragmentation, bounded reassembly, and the initialization-sized
packet pool, bounded owner-to-owner SPSC handoff, and the fixed transport wire
format through Phase 13.

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_OSX_ARCHITECTURES=arm64
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Unit tests require no elevated privileges. Later raw-link and dummynet integration
scripts will isolate every privileged action under `scripts/` and restore host state.

The Phase 10 sanitizer gate needs upstream libFuzzer. Xcode 26.6's Apple Clang package
does not include `libclang_rt.fuzzer_osx.a` on this host, so the script uses keg-only
Homebrew LLVM without replacing the normal Apple Clang toolchain:

```sh
brew install llvm
scripts/phase10_reassembly_fuzz.sh
```

See `AGENTS.md` for the phase gates, `HLD.md` for architecture, and `LLD.md` for
data structures and algorithms. Performance statements remain hypotheses until a
committed benchmark run supports them.
