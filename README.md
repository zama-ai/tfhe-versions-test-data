# Test corpus for tfhe-rs backward compatibility
This repo holds various messages from tfhe-rs that have been versioned and serialized.
The goal is to detect in tfhe-rs Ci when the version of a type should be upgraded because a breaking change has been added.

The messages are serialized using cbor because it has the following features:
- The names of structure fields and enum variants are encoded. This allows stricter checks than something like bincode that only encodes their indexes.
- It supports arrays of up to 2^64 elements.
