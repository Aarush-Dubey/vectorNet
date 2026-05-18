# Privileged scripts

No privileged script exists in Phase 01.

Future scripts that open BPF devices or alter `dnctl`/PF state must require explicit
`sudo`, scope rules narrowly, snapshot prior state, and restore it on success, failure,
or interruption. Unit tests must never call these scripts.
