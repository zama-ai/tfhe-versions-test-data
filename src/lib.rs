use core::f64;
use std::{borrow::Cow, fmt::Display};

use serde::{Deserialize, Serialize};

#[cfg(feature = "generate")]
pub mod data_0_6;
#[cfg(feature = "generate")]
pub mod generate;

#[cfg(feature = "load")]
pub mod load;

const DATA_DIR: &str = "data";

/// This struct re-defines tfhe-rs parameter sets but this allows to be independant
/// of changes made into the  ParameterSet of tfhe-rs. The idea here is to define a type
/// that is able to carry the information of the used parameters without using any tfhe-rs
/// types.
#[derive(Serialize, Deserialize, Debug)]
pub struct TestParameterSet {
    pub lwe_dimension: usize,
    pub glwe_dimension: usize,
    pub polynomial_size: usize,
    pub lwe_noise_gaussian_stddev: f64,
    pub glwe_noise_gaussian_stddev: f64,
    pub pbs_base_log: usize,
    pub pbs_level: usize,
    pub ks_base_log: usize,
    pub ks_level: usize,
    pub message_modulus: usize,
    pub ciphertext_modulus: u128,
    pub carry_modulus: usize,
    pub max_noise_level: usize,
    pub log2_p_fail: f64,
    pub encryption_key_choice: Cow<'static, str>,
}

pub struct TestFailure {
    target_type: String,
    test_filename: String,
    source_error: String,
}

impl Display for TestFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Test: {} in file {}: FAILED: {}",
            self.target_type, self.test_filename, self.source_error
        )
    }
}

pub struct TestSuccess {
    target_type: String,
    test_filename: String,
}

impl Display for TestSuccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Test: {} in file {}: SUCCESS",
            self.target_type, self.test_filename
        )
    }
}

pub trait Testcase {
    fn target_type(&self) -> String;
    fn test_filename(&self) -> String;

    fn success(&self) -> TestSuccess {
        TestSuccess {
            target_type: self.target_type(),
            test_filename: self.test_filename(),
        }
    }

    fn failure<E: Display>(&self, error: E) -> TestFailure {
        TestFailure {
            target_type: self.target_type(),
            test_filename: self.test_filename(),
            source_error: format!("{}", error),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ShortintClientKeyTest {
    pub key_filename: Cow<'static, str>,
    pub parameters: TestParameterSet,
}

impl Testcase for ShortintClientKeyTest {
    fn target_type(&self) -> String {
        "ShortintClientKey".to_string()
    }

    fn test_filename(&self) -> String {
        self.key_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ShortintCiphertextTest {
    pub key_filename: Cow<'static, str>,
    pub ct_filename: Cow<'static, str>,
    pub clear_value: u64,
}

impl Testcase for ShortintCiphertextTest {
    fn target_type(&self) -> String {
        "ShortintCiphertext".to_string()
    }

    fn test_filename(&self) -> String {
        self.ct_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum TestMetadata {
    ShortintCiphertext(ShortintCiphertextTest),
    ShortintClientKey(ShortintClientKeyTest),
}
