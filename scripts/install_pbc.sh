#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
prefix=${1:-"$project_dir/.deps/pbc-0.5.14"}
case "$prefix" in /*) ;; *) echo 'Use an absolute installation prefix.' >&2; exit 2;; esac
for tool in curl tar make gcc flex bison m4 sha256sum; do
  command -v "$tool" >/dev/null || { echo "Missing dependency: $tool" >&2; exit 2; }
done
# A fresh build avoids silently reusing an incompatible installation.
test ! -e "$prefix" || { echo "Prefix already exists: $prefix" >&2; exit 2; }
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
cd "$work"
curl --fail --location --retry 3 https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz -o pbc-0.5.14.tar.gz
printf '%s  %s\n' 772527404117587560080241cedaf441e5cac3269009cdde4c588a1dce4c23d2 pbc-0.5.14.tar.gz | sha256sum --check
tar -xzf pbc-0.5.14.tar.gz
cd pbc-0.5.14
./configure --prefix="$prefix"
make -j2
make install
printf '\nPBC 0.5.14 installed in %s\n' "$prefix"
