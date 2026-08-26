# Rust Dependency License Technical Review

Date: 2026-08-26

Scope: the 105 Rust packages resolved by the committed `crypto-spike/Cargo.lock` for the M0 crypto spike.

## Result

The generated `docs/RUST_DEPENDENCIES.md` inventory contains declared license metadata for every resolved package. A targeted repository scan found no declared GPL, AGPL, LGPL, SSPL, or MPL license expressions in that inventory.

Observed license families are permissive/notice-oriented expressions including MIT, Apache-2.0, BSD-3-Clause, BSD-1-Clause, Unlicense, Unicode-3.0, and Apache-2.0 WITH LLVM-exception combinations.

`vodozemac 0.10.0` declares Apache-2.0 in the resolved metadata.

## Boundary

This is a technical dependency-license screening, not legal advice and not the final application notice bundle. Before release, SecretMode still needs a third-party notices artifact/process that preserves the attribution and notice obligations of the shipped dependency set, including any relevant Android/Gradle dependencies introduced after M0.

Any future Cargo.lock change must regenerate and re-review `docs/RUST_DEPENDENCIES.md` before the M0/M1 security gate is considered unchanged.
