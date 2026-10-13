# Implementation conventions and boundaries

This release packages the corrected implementation from 2026-10-12. Packaging
changes do not alter cryptographic formulas. Full correction history is retained
in the Chinese `IMPLEMENTATION_NOTES.md`.

PR-ABE/PR-ABKS share PSetup, keygen, registration, encrypt, puncture and decryption.
RR-ABKS has its own setup, key validation, aggregation and ciphertext core; it
shares the identity-bound search implementation with PR-ABKS. General LSSS
reconstruction solves the finite-field linear system. Decryption has no access
to encryption randomness or known plaintext.

## Baseline convention

The RR-ABKS reference prints a positive W exponent while its printed ciphertext
and pairing-product decryption require the opposite sign to cancel the attribute
randomness. This implementation uses `W[j,i,w] = g^(-t_j*u_i,w)`, retaining the
printed C3/C4 and pairing-product form. This convention also appears in the
preceding local implementation. It is an explicit implementation convention,
not a claim of literal reproduction of every printed equation. PR-ABE's Tra and
OPR-ABE extension are not included in the six-algorithm baseline.

## Encodings

Messages are byte strings whose unsigned big-endian integer is strictly smaller
than the scalar order. Out-of-range messages are rejected, not reduced modulo
the order. Leading zero bytes are preserved. C1 concatenates message bytes and
fixed-width scalar s' encoding, XORed with a SHA-256 counter-expanded mask.
Recovery checks canonical scalar encoding and C7. This is a native-message
prototype, not an arbitrary-file encryption application.

Hashes use explicit binary lengths and domain separation. H1/H2 use SHA-256
followed by PBC field/group mapping. These practical instantiations are not a
replacement for random-oracle/security proofs. The existing IND-CKA proof task
is not resolved by this software release.

Ciphertext tag count m satisfies 0<=m<=eta-1. Duplicate ciphertext tags and
duplicate keywords are rejected; repeating a key puncture is idempotent.
Keywords use aggregate matching, not arbitrary subset matching. Identity leaves
are bound at registration; tree path products exclude the leaf identity node.

## Security/functionality scope

An index contains all eligible identities at creation time. Later revocation does
not modify an old index. Search receives only index and trapdoor. Updated keys
restrict their tag capability, but retained old keys remain usable. Tests include
this boundary; the application must ensure secure erasure when relying on it.
Element cleanup is not a secure-erasure guarantee. The prototype does not certify
attributes or provide a production service, wire format or deployment protocol.

Tests cover valid and invalid attributes, multiple LSSS policies, puncture
components, multiple updates, bounds, message encodings, identity binding, query
reordering/mismatches and revocation snapshots. Passing them checks functional
behavior; it is not a proof of IND-KU-CPA or IND-CKA security.
