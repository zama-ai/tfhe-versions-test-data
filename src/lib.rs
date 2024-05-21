use std::{
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

pub(crate) fn store_versioned<Data: Versionize, P: AsRef<Path>>(msg: &Data, path: P) {
    let versioned = msg.versionize();
    let mut serialized = Vec::new();
    ciborium::ser::into_writer(&versioned, &mut serialized).unwrap();
    fs::write(path, &serialized).unwrap();
}

pub fn load_versioned<Data: DeserializeOwned, P: AsRef<Path>>(path: P) -> Result<Data, ()> {
    let file = File::open(path).map_err(|_| ())?;
    ciborium::de::from_reader(file).map_err(|_| ())
}

pub(crate) fn store_metadata<Meta: Serialize, P: AsRef<Path>>(value: &Meta, path: P) {
    let serialized = ron::to_string(value).unwrap();
    fs::write(path, &serialized).unwrap();
}

pub fn load_metadata<P: AsRef<Path>>(path: P) -> Result<Vec<TestMetadata>, ()> {
    let serialized = fs::read_to_string(path).map_err(|_| ())?;
    ron::from_str(&serialized).map_err(|_| ())
}

#[derive(Serialize, Deserialize)]
pub enum TestParameterSet {
    Message2Carry2KsPbs,
}

#[derive(Serialize, Deserialize)]
pub struct ShortintClientKeyTest {
    pub key_filename: String,
    pub parameters: TestParameterSet,
}

#[derive(Serialize, Deserialize)]
pub struct ShortintCiphertextTest {
    pub key_filename: String,
    pub ct_filename: String,
    pub clear_value: u64,
}

#[derive(Serialize, Deserialize)]
pub enum TestMetadata {
    ShortintCiphertext(ShortintCiphertextTest),
    ShortintClientKey(ShortintClientKeyTest),
}
