# Third-party dependencies

The MIT license applies to the author-generated code and documentation in this
release. It does not relicense external libraries. No third-party library binary,
source archive or vendored header is included in the source release.

| Dependency | Role | License / source |
|---|---|---|
| PBC 0.5.14 | Pairing arithmetic | GNU LGPL; bundled COPYING is LGPL v3. https://crypto.stanford.edu/pbc/ |
| GMP | Integer arithmetic used by PBC | Dual LGPL v3 / GPL v2; consult the installed distribution. https://gmplib.org/ |
| OpenSSL 3 libcrypto | SHA-256 | Apache License 2.0. https://www.openssl.org/ |

Use the license files accompanying the exact dependency versions. The installer
downloads PBC separately and leaves it under the ignored `.deps/` directory.
Redistributing dependency binaries/sources requires observing their own notices
and obligations; this source-only archive does not include them.

Baseline algorithms are attributed to:

- *Puncturable Registered ABE for Vehicular Social Networks: Enhancing Security
  and Practicality* (PR-ABE; reference [29] in the checked manuscript).
- *Registered-Based Revocable Attribute-Based Encryption With Keyword Search
  for Secure Cloud Data Sharing* (RR-ABKS; reference [30]).

These are author implementations, not releases supplied or endorsed by the
baseline papers' authors. The RR-ABKS W-sign convention is explicitly described
in `docs/IMPLEMENTATION.md`.
