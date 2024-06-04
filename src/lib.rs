use core::f64;
use std::{
    borrow::Cow,
    fs::{self, File},
    path::{Path, PathBuf},
    str::FromStr,
};

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use tfhe_versionable::Versionize;

pub mod data_0_6;

const DATA_DIR: &str = "data";

pub fn dir_for_version(version: &str) -> PathBuf {
    let mut path = PathBuf::from_str(env!("CARGO_MANIFEST_DIR")).unwrap();
    path.push(DATA_DIR);
    path.push(version.replace(".", "_"));

    path
}

pub fn dir_for_latest() -> PathBuf {
    let mut path = PathBuf::from_str(env!("CARGO_MANIFEST_DIR")).unwrap();
    path.push(DATA_DIR);
    path.push("latest");

    path
}

pub fn store_versioned<Data: Versionize, P: AsRef<Path>>(msg: &Data, path: P) {
    let versioned = msg.versionize();
    let mut serialized = Vec::new();
    ciborium::ser::into_writer(&versioned, &mut serialized).unwrap();
    fs::write(path, &serialized).unwrap();
}

pub fn load_versioned<Data: DeserializeOwned, P: AsRef<Path>>(path: P) -> Result<Data, ()> {
    let file = File::open(path).map_err(|_| ())?;
    ciborium::de::from_reader(file).map_err(|_| ())
}

pub fn store_metadata<Meta: Serialize, P: AsRef<Path>>(value: &Meta, path: P) {
    let serialized = ron::to_string(value).unwrap();
    fs::write(path, &serialized).unwrap();
}

pub fn load_metadata<P: AsRef<Path>>(path: P) -> Result<Vec<TestMetadata>, ()> {
    let serialized = fs::read_to_string(path).map_err(|_| ())?;
    ron::from_str(&serialized).map_err(|_| ())
}

/// This struct re-defines tfhe-rs parameter sets but this allows to be independant
/// of changes made into the  ParameterSet of tfhe-rs. The idea here is to define a type
/// that is able to carry the information of the used parameters without using any tfhe-rs
/// types.
#[derive(Serialize, Deserialize)]
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
    pub pfks_level: usize,
    pub pfks_base_log: usize,
    pub pfks_noise_gaussian_stddev: f64,
    pub cbs_level: usize,
    pub cbs_base_log: usize,
    pub message_modulus: usize,
    pub ciphertext_modulus: usize,
    pub carry_modulus: usize,
    pub max_noise_level: usize,
    pub log2_p_fail: f64,
    pub encryption_key_choice: Cow<'static, str>,
}

#[derive(Serialize, Deserialize)]
pub struct ShortintClientKeyTest {
    pub key_filename: Cow<'static, str>,
    pub parameters: TestParameterSet,
}

#[derive(Serialize, Deserialize)]
pub struct ShortintCiphertextTest {
    pub key_filename: Cow<'static, str>,
    pub ct_filename: Cow<'static, str>,
    pub clear_value: u64,
}

pub trait TfhersVersion {
    type ShortintCiphertext: Versionize;
    type ShortintClientKey: Versionize;

    const VERSION_NUMBER: &'static str;

    fn gen_shortint_client_key(meta: ShortintClientKeyTest) -> Self::ShortintClientKey;

    fn gen_shortint_ct(
        meta: ShortintCiphertextTest,
        key: &Self::ShortintClientKey,
    ) -> Self::ShortintCiphertext;
}

#[derive(Serialize, Deserialize)]
pub enum TestMetadata {
    ShortintCiphertext(ShortintCiphertextTest),
    ShortintClientKey(ShortintClientKeyTest),
}
