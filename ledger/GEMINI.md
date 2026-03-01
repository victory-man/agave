# Gemini CLI Context: Solana Ledger (Agave Workspace)

## Project Overview
This directory contains the source code for the `solana-ledger` crate, which is a core component of the Agave (Solana) blockchain validator. Its primary responsibility is managing the persistent file-based ledger and handling the data packets (shreds) received from the network.

### Key Components
*   **Blockstore (`src/blockstore.rs`, `src/blockstore/`)**: A persistent file-based ledger powered by RocksDB. It handles iterative reads, append writes, random access reads, and parallel verification of the Proof of History ledger.
*   **Shreds (`src/shred.rs`, `src/shred/`)**: Data structures and methods for pulling and processing MTU-sized data frames from the network. It manages two types of shreds:
    *   *Data Shreds*: Contain the actual ledger entries and payload information.
    *   *Coding Shreds*: Provide redundancy using Reed-Solomon erasure coding to protect against dropped network packets.
*   **Leader Schedule (`src/leader_schedule*.rs`)**: Core logic for calculating, caching, and iterating through the validator leader schedule.
*   **Bank Forks (`src/bank_forks_utils.rs`)**: Utilities for managing and interacting with different forks of the blockchain state.

## Directory Structure
*   `src/`: Contains the primary Rust source code for the crate.
*   `benches/`: Contains performance benchmarks (e.g., `blockstore.rs`, `make_shreds_from_entries.rs`) using the `criterion` framework.
*   `tests/`: Contains integration tests for the blockstore and shreds.
*   `proptest-regressions/`: Stores regression files for property-based tests.

## Building and Testing
Since this is a standard Rust crate within a larger Cargo workspace, standard Cargo commands apply. You can run these commands directly within this directory:

*   **Build the crate:**
    ```bash
    cargo build
    ```
*   **Run tests:**
    ```bash
    cargo test
    ```
*   **Run benchmarks:**
    ```bash
    cargo bench
    ```

## Development Conventions
*   **Concurrency & Parallelism**: The codebase heavily leverages `rayon` for parallel verification and data processing, alongside `crossbeam-channel` and `tokio` for asynchronous and concurrent operations.
*   **Storage Engine**: `rocksdb` is used as the underlying storage engine, specifically configured to avoid vendor linker conflicts (e.g., explicitly disabling default features and enabling `lz4`).
*   **Testing Practices**: The project employs extensive testing, including inline unit tests `#[cfg(test)]`, integration tests, and property-based testing utilizing `proptest`.
*   **Feature Flags**: Development features such as `agave-unstable-api` and `frozen-abi` are used to manage API stability and binary interface compatibility across updates.
