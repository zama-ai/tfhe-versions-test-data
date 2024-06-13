use std::{
    borrow::Cow,
    fs::{self, File},
    path::{Path, PathBuf},
};

use bincode::Options;
use serde::Serialize;
use tfhe_versionable::Versionize;

use crate::{data_dir, dir_for_version, TestMetadata, TestParameterSet};

/// Valid parameter set that can be used in tfhe operations
pub const VALID_TEST_PARAMS: TestParameterSet = TestParameterSet {
    lwe_dimension: 761,
    glwe_dimension: 1,
    polynomial_size: 2048,
    lwe_noise_gaussian_stddev: 6.36835566258815e-06,
    glwe_noise_gaussian_stddev: 3.1529322391500584e-16,
    pbs_base_log: 23,
    pbs_level: 1,
    ks_base_log: 3,
    ks_level: 5,
    message_modulus: 4,
    carry_modulus: 4,
    max_noise_level: 5,
    log2_p_fail: -40.05,
    ciphertext_modulus: (u64::MAX as u128) + 1,
    encryption_key_choice: Cow::Borrowed("big"),
};

/// Invalid parameter set to test the limits
pub const INVALID_TEST_PARAMS: TestParameterSet = TestParameterSet {
    lwe_dimension: usize::MAX,
    glwe_dimension: usize::MAX,
    polynomial_size: usize::MAX,
    lwe_noise_gaussian_stddev: f64::MAX,
    glwe_noise_gaussian_stddev: f64::MAX,
    pbs_base_log: usize::MAX,
    pbs_level: usize::MAX,
    ks_base_log: usize::MAX,
    ks_level: usize::MAX,
    message_modulus: usize::MAX,
    carry_modulus: usize::MAX,
    max_noise_level: usize::MAX,
    log2_p_fail: f64::MAX,
    ciphertext_modulus: u128::MAX,
    encryption_key_choice: Cow::Borrowed("big"),
};

/// Stores the test data in `dir`, encoded in both cbor and bincode
pub fn store_versioned_test<Data: Versionize, P: AsRef<Path>>(
    msg: &Data,
    dir: P,
    test_filename: &str,
) {
    let versioned = msg.versionize();

    // Store in cbor
    let filename_cbor = format!("{}.cbor", test_filename);
    let mut cbor_file = File::create(dir.as_ref().join(filename_cbor)).unwrap();
    ciborium::ser::into_writer(&versioned, &mut cbor_file).unwrap();

    // Store in bincode
    let filename_bincode = format!("{}.bcode", test_filename);
    let mut bincode_file = File::create(dir.as_ref().join(filename_bincode)).unwrap();
    let options = bincode::DefaultOptions::new().with_fixint_encoding();
    options
        .serialize_into(&mut bincode_file, &versioned)
        .unwrap();
}

pub fn store_metadata<Meta: Serialize, P: AsRef<Path>>(value: &Meta, path: P) {
    let serialized = ron::to_string(value).unwrap();
    fs::write(path, serialized).unwrap();
}

pub trait TfhersVersion {
    type ShortintCiphertext: Versionize;
    type ShortintClientKey: Versionize;

    const VERSION_NUMBER: &'static str;

    fn data_dir() -> PathBuf {
        let base_data_dir = data_dir(env!("CARGO_MANIFEST_DIR"));
        dir_for_version(base_data_dir, Self::VERSION_NUMBER)
    }

    /// How to fix the prng seed for this version to make sure the generated testcases do not change every time we run the script
    fn seed_prng(seed: u128);

    /// Generates data for the "shortint" module for this version.
    /// This should create tfhe-rs shortint types, versionize them and store them into the version specific directory.
    /// The metadata for the generated tests should be returned in the same order that the tests will be run.
    fn gen_shortint_data() -> Vec<TestMetadata>;

    /// Generates data for the "high_level_api" module for this version.
    /// This should create tfhe-rs HL types, versionize them and store them into the version specific directory.
    /// The metadata for the generated tests should be returned in the same order that the tests will be run.
    fn gen_hl_data() -> Vec<TestMetadata>;
}
