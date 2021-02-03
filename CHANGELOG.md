# Sample changelog for maintainers

## Pending

### Breaking changes
- #4 Change groth16's logic to implement the `SNARK` trait.
- Minimum version on crates from `arkworks-rs/algebra` and `arkworks-rs/curves` is now `v0.2.0`

### Features
- #5 Add R1CS constraints for the groth16 verifier.
- #8 Add benchmarks for the prover
- #16 Add proof re-randomization

### Improvements
- #9 Improve memory consumption by manually dropping large vectors once they're no longer needed

### Bug fixes
- [c9bc5519](https://github.com/arkworks-rs/groth16/commit/885b9b569522f59a7eb428d1095f442ec9bc5519) Fix parallel feature flag
- #22 Compile with `panic='abort'` in release mode, for safety of the library across FFI boundaries.

## v0.1.0

_Initial release_