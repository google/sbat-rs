# fuzz-sbat

See the [Rust Fuzz Book] for the initial setup.

Run the fuzzer:
```
cargo +nightly fuzz run combo
```

Generate coverage:

```
rustup component add --toolchain nightly llvm-tools-preview

cargo +nightly fuzz coverage combo

cargo +nightly cov -- show target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/combo \
    --format=html \
    --instr-profile=fuzz/coverage/combo/coverage.profdata \
    > index.html
```

(Note that the coverage steps are slightly different from what the Fuzz
Book says to do, see <https://github.com/rust-fuzz/cargo-fuzz/issues/308>).

[Rust Fuzz Book]: https://rust-fuzz.github.io/book/cargo-fuzz/setup.html
