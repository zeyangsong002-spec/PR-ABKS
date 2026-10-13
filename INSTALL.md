# Installation on a fresh computer

## Supported route

Use Ubuntu x86-64, either natively or through WSL on Windows. The release is
validated in a fresh Ubuntu 24.04 userspace; the preceding implementation was
also tested on WSL Ubuntu 26.04. Native Windows/MSVC and macOS are not validated.
Do not build this release with the old Visual Studio solution.

Windows users without WSL can run `wsl --install -d Ubuntu-24.04` in an
administrator PowerShell and complete Ubuntu's first-start account setup
(restart Windows if requested). Existing WSL users can use their Ubuntu shell.
All remaining commands are Ubuntu-shell commands, not PowerShell commands.

Extract the source archive into a writable directory, preferably under the
Ubuntu home directory, then `cd` into the directory containing `CMakeLists.txt`.
Never copy a CMake build directory from another machine.

## System packages

```bash
sudo apt update
sudo apt install build-essential cmake libgmp-dev libssl-dev flex bison m4 curl ca-certificates python3
```

Python is needed only for `scripts/run_sweep.py`. No IDE is required.
Package installation needs administrator privileges; the following local PBC
installation and project build do not. System package versions follow Ubuntu
updates; tested versions are recorded in `docs/CLEAN_ENVIRONMENT.md`.

## PBC 0.5.14

```bash
bash scripts/install_pbc.sh
```

The script obtains the upstream PBC 0.5.14 archive over HTTPS, verifies SHA-256
`772527404117587560080241cedaf441e5cac3269009cdde4c588a1dce4c23d2`,
and builds it into `.deps/pbc-0.5.14`. It does not replace any system PBC library.
Do not substitute the current upstream latest version when reproducing this
environment. The script refuses to overwrite an existing prefix. After a failed
installation, inspect the error and choose a fresh absolute prefix as its first
argument, then use that prefix in the CMake command below.

## Configure, build and verify

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$PWD/.deps/pbc-0.5.14"
cmake --build build -j2
ctest --test-dir build --output-on-failure
./build/prabks --self-test
```

Expected: CTest reports 1/1 passed, and the direct test reports 428 checks passed.
CMake supplies a build-time library search path to the linked local PBC library.
If launching a copied executable produces a shared-library error, rebuild in
the current source directory; this release distributes source, not a relocatable
binary. `ldd build/prabks` should show the intended local PBC and no `not found`.

The default parameter-file path is bound at configuration time. After moving
the source, configure in a fresh build directory or pass
`--params /absolute/path/to/params/a.param` explicitly.

## Example benchmark

```bash
mkdir -p results
./build/prabks --benchmark --output results/example.csv \
  --users 10 --attrs 10 --policy 4 --eta 3 --tags 1 \
  --punctures 1 --keywords 10 --runs 10 --warmup 1
```

Expected: each scheme reports 10 validated runs and the CSV contains 22
algorithm rows plus a header. The filename must be new. `eta=1` requires
`tags=0`; otherwise validation fails. Use an existing output directory.

Optional independent memory/undefined-behavior check:

```bash
cmake -S . -B build-sanitize -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZERS=ON -DCMAKE_PREFIX_PATH="$PWD/.deps/pbc-0.5.14"
cmake --build build-sanitize -j2
./build-sanitize/prabks --self-test
```

For research timing, run on an otherwise idle machine, avoid simultaneous
benchmarks, and record CPU, OS, compiler, dependency versions and all options.
WSL/virtualization, CPU frequency and library builds can affect timings.
