# Contributing to DSPV

First off, thank you for considering contributing to the Dynamic Secure Portable Volume! We welcome contributions from everyone.

## How Can I Contribute?

### Reporting Bugs
* Ensure the bug was not already reported by searching on GitHub under Issues.
* If you're unable to find an open issue addressing the problem, open a new one. Be sure to include a title and clear description, as much relevant information as possible, and a code sample or an executable test case demonstrating the expected behavior that is not occurring.

### Suggesting Enhancements
* Open a new issue with a detailed description of the proposed feature.
* Explain *why* this enhancement would be useful to most users.

### Submitting Pull Requests
1. **Fork the repository** and create your branch from `main`.
2. **Clone** your fork locally.
3. **Branch** out: `git checkout -b my-feature-branch`.
4. **Develop** your feature or fix.
5. **Test** your code: Ensure all existing tests pass (`cargo test`) and write new tests for your specific additions, especially if they touch cryptography (`mod crypto`) or file I/O (`mod storage`).
6. **Lint** your code: Run `cargo fmt` and `cargo clippy` to ensure your code matches the project's style guidelines.
7. **Commit** your changes with clear, descriptive commit messages.
8. **Push** to your fork and **submit a pull request** to the `main` branch.

## Code Standards
* **Security First:** Any changes to the cryptographic implementation must be thoroughly documented and backed by tests verifying boundary conditions (e.g., bit-flipping attacks, extreme offsets).
* **Error Handling:** Use the custom structured Enums (e.g., `VaultError`, `ChunkIoError`) instead of generic IO errors to maintain clear logging and predictable failure states.
* **Memory Safety:** If you introduce new structures holding sensitive data (keys, plain-text buffers), ensure they implement the `Zeroize` and `ZeroizeOnDrop` traits.
