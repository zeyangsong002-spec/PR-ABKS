# Manuscript–implementation experiment mapping

Checked against the manuscript revision dated 2026-10-11, *Puncturable registered
attribute-based keyword search for secure cloud data sharing*, Performance Analysis,
and the corrected source prepared 2026-10-12. This mapping describes correspondence,
not certification that historical plotted values were produced by this release.

## Figure mapping

All invocations use `--benchmark --output NEW.csv`. Each invocation evaluates all
three schemes and all supported algorithm phases. Select the appropriate CSV rows
after execution; do not compare the duration of the entire executable to a figure.

| Manuscript figure | CSV algorithm | Parameter to vary | Schemes plotted / qualification |
|---|---|---|---|
| 4(a), Setup vs attributes | `Setup` | `--attrs` (U) | All three; policy must remain <= U |
| 4(b), Setup vs users | `Setup` | `--users` (N) | All three |
| 5, KeyGen vs users | `KeyGen` | `--users` | All three; current timer sums N users |
| 6, Reg vs users | `Reg` | `--users` | All three; RR `IsValid` is separately reported |
| 7(a), Enc vs policy rows | `Enc` | `--policy` (ell) | All three; choose fixed U >= largest row count |
| 7(b), Enc vs keywords | `Enc` | `--keywords` | RR-ABKS and PR-ABKS; K and Q both change in this harness |
| 8, KeyUpt vs tag-related size | `KeyUpt` | See ambiguity below | PR-ABE and PR-ABKS |
| 9, TrapGen vs query keywords | `TrapGen` | `--keywords` | RR-ABKS and PR-ABKS |
| 10, Search vs query keywords | `Search` | `--keywords` | RR-ABKS and PR-ABKS; first matching identity |
| 11, Dec vs policy rows | `Dec` | `--policy` | All three; complete decryption, fixed puncture count |

The cost/communication tables contain analytical operation and element counts,
not serialized network measurements. This harness does not claim to measure
those tables' byte lengths. Functional comparison entries are not all benchmarking
capabilities (for example PR-ABE outsourcing is outside the implemented baseline).

## Historical settings versus release defaults

The manuscript states Windows 11, AMD Ryzen 7 7745HX (3.60 GHz), 16 GB RAM,
512-bit Type-A pairing, and **the total execution time of 10 independent runs**.
It gives initial N=10, U=10, Q=10, eta=1 and ell=4.

The release defaults are N=10, U=10, K=Q=10, ell=4, eta=3, m=1, p=1,
10 measured runs and 1 warm-up. These are demonstration defaults. To use the
manuscript's stated eta=1 under the corrected bound, set `--eta 1 --tags 0`.
Neither the historical puncture count nor historical warm-up count should be
inferred from the new defaults. The new validation environment is Linux userspace
under WSL, which is not a claim to reconstruct the original Windows software stack.

For figures described as sums of 10 runs, use `total_ms` with `--runs 10`.
Do not silently substitute `mean_ms`; it is a different statistic (total/10).
`sample_sd_ms` is the variability of individual measured runs, not the uncertainty
of their sum. Do not attach it to total-time curves as if the two had the same meaning.

The precise historical x-axis grids, fixed settings omitted from the manuscript,
and the point-by-point provenance of the plotted values are not encoded by this
release. No historical figure dataset or original plotting script is included.
Inspection of the supplied code directories did not locate an author plotting
script with a traceable mapping to those figures. Do not label a newly chosen
grid as the original experiment configuration.

### Fig. 8 and dimension terminology

`eta` is the coefficient-vector length; `m` (`--tags`) is the ciphertext tag count,
and `p` (`--punctures`) is the accumulated distinct puncture count. They are
different quantities, with 0 <= m <= eta-1. The manuscript refers to tag count
while discussing a cost involving eta. The historical axis interpretation remains
to be reconciled with its original configuration. For a **new** controlled study,
vary one of eta, m or p explicitly and hold the others fixed. KeyUpt measures the
sum of p sequential updates, not one update when p>1. In this implementation,
changing only ciphertext tags does not change the updated key-vector length.

## Re-running a clearly specified sweep

This example is a new two-point smoke sweep, **not a paper figure reproduction**:

```bash
python3 scripts/run_sweep.py --axis users --values 2 3 \
  --attrs 2 --policy 1 --eta 2 --tags 1 --punctures 1 \
  --keywords 2 --runs 2 --warmup 0 --output-dir results/users_smoke
```

Use `--dry-run` to inspect the commands without writing files. For a study, set
all fixed parameters and the desired grid explicitly. The script records commands,
parameter values, program/parameter hashes, exit status and per-configuration
logs. Outputs are new aggregate CSVs; no historical values are silently imported.
Before publication, also record CPU, OS, compiler/library versions and timing
conditions. The manifest is not a substitute for that environment description.

## Comparison boundaries that affect interpretation

- Search scans eligible identities in order; the benchmark succeeds at the first
  candidate. It does not implement an all-nonmatching performance scenario.
- The last identity is excluded when creating the index, so c=N-1. There is no
  separate CLI control for revocation fraction or independent K and Q sizes.
- PR-ABE and PR-ABKS share their puncturable core; PR-ABKS adds search operations.
- PR KeyGen times all N keys. Registration includes aggregate construction;
  RR validation is a distinct phase. Compare consistently with paper definitions.
- PR variants encrypt the bytes `PR-ABKS`; RR encrypts a random GT element.
  These are native construction inputs, not equal-length file-throughput workloads.
- Setup excludes pairing-file loading/initialization. Enc includes the full
  eligible-user index; Dec includes partial recovery and final recovery.
- Corrections to the old implementation change the executed operations. Do not
  splice old and corrected timing series or claim old plots are validated by the
  corrected program's successful self-tests.

The manuscript, figures and theoretical formulas were not edited for this release.
