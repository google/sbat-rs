# fuzz-sbat

Initial setup:

```
rustup component add --toolchain nightly llvm-tools-preview
cargo install cargo-fuzz
cargo install grcov
```

Run the fuzzer for as long as you like:

```
cargo +nightly fuzz run combo
```

Generate coverage:

```
# Run this from the repository root.
make -C fuzz cov

# Output will be in `cov_report/index.html`.
```

See also the [Rust Fuzz Book].

[Rust Fuzz Book]: https://rust-fuzz.github.io/book/cargo-fuzz
