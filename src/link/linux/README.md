# Linux link backend — historical reference only

Original design used `AF_PACKET`, `PACKET_MMAP`, and `TPACKET_V3`. macOS BPF now
owns maintained link-layer code. Nothing in this directory enters a CMake target,
and Linux builds are unsupported.

Do not add compatibility fixes here. Historical names remain only to document the
project's initial design intent.
