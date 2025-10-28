# BBS MACs vs. BBS Signatures: A Benchmark Comparison

[![Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org/)

A small Rust project to benchmark and compare the performance of BBS MACs (Message Authentication Codes) against BBS Signatures side-by-side.

> **Warning:** This project is for benchmarking and educational purposes only. It is **NOT INTENDED** for production use.

## Overview

This repository provides a simple, side-by-side performance comparison between BBS MACs and BBS Signatures. The goal is to observe the computational cost and speed of common operations for each scheme within the same environment.

## Usage

This project is built using Rust and managed with Cargo.

### Prerequisites

Ensure you have the Rust toolchain installed. You can install it from [rustup.rs](https://rustup.rs/).

### Running the Benchmarks

1.  **Clone the repository:**
    ```sh
    git clone [https://github.com/meyira/bbs-mac-vs-sig.git](https://github.com/meyira/bbs-mac-vs-sig.git)
    cd bbs-mac-vs-sig
    ```

2.  **Build the project:**
    ```sh
    cargo build --release
    ```

3.  **Run the executable:**
    The project is likely set up to run the benchmarks directly.
    ```sh
    cargo run --release
    ```

    If tests are included, you can run them using:
    ```sh
    cargo test --release
    ```

## Dependencies

All Rust dependencies are managed by `Cargo` and are listed in the `Cargo.toml` file.

## License

The license for this project has not been specified.
