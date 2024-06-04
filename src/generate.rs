use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
};

use serde::Serialize;
use tfhe_versionable::Versionize;

use crate::{ShortintCiphertextTest, ShortintClientKeyTest, DATA_DIR};

pub fn dir_for_version(version: &str) -> PathBuf {
    let mut path = PathBuf::from_str(env!("CARGO_MANIFEST_DIR")).unwrap();
    path.push(DATA_DIR);
    path.push(version.replace(".", "_"));

    path
}

pub fn store_versioned<Data: Versionize, P: AsRef<Path>>(msg: &Data, path: P) {
    let versioned = msg.versionize();
    let mut serialized = Vec::new();
    ciborium::ser::into_writer(&versioned, &mut serialized).unwrap();
    fs::write(path, &serialized).unwrap();
}

pub fn store_metadata<Meta: Serialize, P: AsRef<Path>>(value: &Meta, path: P) {
    let serialized = ron::to_string(value).unwrap();
    fs::write(path, &serialized).unwrap();
}

pub trait TfhersVersion {
    type ShortintCiphertext: Versionize;
    type ShortintClientKey: Versionize;

    const VERSION_NUMBER: &'static str;

    fn seed_prng(seed: u128);

    fn gen_shortint_client_key(meta: ShortintClientKeyTest) -> Self::ShortintClientKey;

    fn gen_shortint_ct(
        meta: ShortintCiphertextTest,
        key: &Self::ShortintClientKey,
    ) -> Self::ShortintCiphertext;
}
