# Test corpus for tfhe-rs backward compatibility
This repo holds various messages from tfhe-rs that have been versioned and serialized.
The goal is to detect in tfhe-rs Ci when the version of a type should be upgraded because a breaking change has been added.

The messages are serialized using cbor and bincode because they both support large arrays and are vulnerable to different sets of breaking changes.

# Data generation
To re-generate the data, run the binary target for this project: `cargo run --release`. The prng is seeded using a fixed seed so the data should be identical.

# Adding a new tfhe-rs version
To add data for a new releaseed version of tfhe-rs, you should first add a dependency to this version in the `Cargo.toml` of this project. This dependency should only be activated with the `generate` feature to avoid conflicts in the testing phase.
You should then implement the `TfhersVersion` trait for this version. You may use the code in `data_0_6.rs` as an example.

# Using the data generated in tests
The data are stored using git-lfs, so first be sure to clone this project with lfs. To be able to parse the metadata and check that the loaded data are valid, your should add this crate as a dependency with the `load` feature activated.
