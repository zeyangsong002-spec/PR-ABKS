# Version 1.0.0 — 2026-10-13

Initial source release prepared locally from the corrected 2026-10-12 version.

- Added MIT licensing, English and Chinese entry documentation, dependency
  provenance and installation instructions for a new Ubuntu/WSL environment.
- Added a checksum-pinned local PBC installer and an explicit parameter-sweep
  launcher with configuration and execution manifests.
- Documented the mapping to manuscript Figs. 4–11, timing statistics, parameter
  differences and unresolved historical configuration details.
- Validated in fresh Ubuntu 24.04.4 userspace, including self-tests, benchmarks
  and address/undefined-behavior checks.
- Cryptographic implementation and parameter bytes are unchanged from the
  corrected version, except for source header/licensing documentation.

This archive contains source and documentation only. It excludes historical
experiment data, old implementation backups, dependencies and build/IDE caches.
The previous implementation's Chinese correction history remains available in
`IMPLEMENTATION_NOTES.md`; the old backup directory is not part of this release.

The archive is prepared for public distribution but has not been uploaded by
this task. No repository URL, release DOI or publication DOI is invented here.
After public archiving, identify the exact released version and its persistent
link in the manuscript's code availability statement. The historical experiment
mapping limits must be resolved or accurately described before claiming exact
reproduction of the paper's figures.
