# Fresh-environment validation

Validation date: 2026-10-13. This is installation/functional validation, not a
performance measurement for the manuscript figures.

## Isolation and provenance

A fresh Ubuntu Base 24.04.4 amd64 root filesystem was downloaded from
https://cdimage.ubuntu.com/ubuntu-base/releases/24.04/release/ and verified against
the SHA256SUMS provided over HTTPS. It was run using chroot on the existing WSL
Linux kernel. Device access and DNS were supplied by the host; host libraries,
`/usr/local`, compiler installations and PBC were not mounted into the rootfs.
This tests a clean Linux userspace, not a new physical PC or a new WSL installation.

System dependencies were installed from Ubuntu package repositories in that
rootfs. The release was copied as source only. As an unprivileged user, the
documented installer downloaded the official PBC 0.5.14 archive, checked its
SHA-256 and compiled it into the project's local dependency directory.
`ldd` confirmed that the executable linked that newly built PBC, plus the rootfs's
GMP and libcrypto, with no unresolved library.

| Component | Validated version |
|---|---|
| Ubuntu userspace | 24.04.4 LTS, amd64 |
| GCC / G++ | 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1) |
| CMake | 3.28.3 |
| PBC | 0.5.14, independently downloaded and built |
| GMP development package | 2:6.3.0+dfsg-2ubuntu6.1 |
| OpenSSL development package | 3.0.13-0ubuntu3.16 |
| C++ language | C++17 |
| Release flags | -O3 -DNDEBUG -Wall -Wextra -Wpedantic -std=gnu++17 |

PBC archive SHA-256:
`772527404117587560080241cedaf441e5cac3269009cdde4c588a1dce4c23d2`.
Unchanged parameter file SHA-256:
`23427c7c855a78c2600dbc6477896d90eb0106aaf5743527e52e5f8667cdfa42`.

## Results

- Release configuration/build: passed.
- CTest correctness: 1/1 passed.
- Direct self-test: all 428 checks passed.
- Documented benchmark: each of three schemes completed 10 measured runs,
  following 1 warm-up, at N=10, U=10, ell=4, eta=3, m=1, p=1, K=Q=10.
- Boundary benchmark: each scheme completed 2 runs at N=3, U=ell=1,
  eta=1, m=p=0, K=Q=2, without warm-up.
- Debug build with address and undefined-behavior sanitizers: all 428 checks
  passed with no sanitizer report. The external PBC/GMP binaries were not themselves
  compiled with sanitizer instrumentation.

- Two-point sweep (N=2,3, U=2, ell=1, eta=2, m=p=1, K=Q=2,
  2 measured runs and no warm-up): passed, with matching manifest configurations.
- All four generated CSVs: 22 rows each, finite nonnegative statistics, and
  total_ms = runs * mean_ms within output-rounding tolerance.
- Launcher dry-run: created no output directory. Invalid tag dimensions and
  attempts to overwrite existing result files/directories were rejected; the
  existing result's checksum remained unchanged.

Benchmark outputs are generated validation artifacts, not the historical paper data.
No numerical performance claims are inferred from this validation.
