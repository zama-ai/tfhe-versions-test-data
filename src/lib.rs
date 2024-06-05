use core::f64;
use std::borrow::Cow;

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

#[derive(Serialize, Deserialize, Debug)]
pub struct ShortintClientKeyTest {
    pub key_filename: Cow<'static, str>,
    pub parameters: TestParameterSet,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ShortintCiphertextTest {
    pub key_filename: Cow<'static, str>,
    pub ct_filename: Cow<'static, str>,
    pub clear_value: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum TestMetadata {
    ShortintCiphertext(ShortintCiphertextTest),
    ShortintClientKey(ShortintClientKeyTest),
}
