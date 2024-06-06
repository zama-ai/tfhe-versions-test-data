use std::{
    borrow::Cow,
    fs,
    path::{Path, PathBuf},
};

use serde::Serialize;
use tfhe_versionable::Versionize;

use crate::{dir_for_version, TestMetadata, TestParameterSet};

pub const TEST_PARAMS: TestParameterSet = TestParameterSet {
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

pub fn store_versioned<Data: Versionize, P: AsRef<Path>>(msg: &Data, path: P) {
    let versioned = msg.versionize();
    let mut serialized = Vec::new();
    ciborium::ser::into_writer(&versioned, &mut serialized).unwrap();
    fs::write(path, &serialized).unwrap();
}

pub fn store_testcases<Meta: Serialize, P: AsRef<Path>>(value: &Meta, path: P) {
    let serialized = ron::to_string(value).unwrap();
    fs::write(path, &serialized).unwrap();
}

pub trait TfhersVersion {
    type ShortintCiphertext: Versionize;
    type ShortintClientKey: Versionize;

    const VERSION_NUMBER: &'static str;

    fn data_dir() -> PathBuf {
        dir_for_version(env!("CARGO_MANIFEST_DIR"), Self::VERSION_NUMBER)
    }

    /// How to fix the prng seed for this version to make sure the generated testcases do not change every time we run the script
    fn seed_prng(seed: u128);

    /// Generates data for the "shortint" module for this version.
    /// This should create tfhe-rs shortint types, versionize them and store them into the version specific directory.
    /// The metadata for the generated tests should be returned in the same order that the tests will be run.
    fn gen_shortint_data() -> Vec<TestMetadata>;
}
