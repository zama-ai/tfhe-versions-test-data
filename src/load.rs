use std::{
    fs::{self, File},
    path::Path,
};

use serde::de::DeserializeOwned;

use crate::Testcase;

/// Loads auxiliary data that might be needed for a test (eg: a key to test a ciphertext)
pub fn load_versioned_auxiliary<Data: DeserializeOwned, P: AsRef<Path>>(
    path: P,
) -> Result<Data, String> {
    let file = File::open(path).map_err(|e| format!("{}", e))?;
    ciborium::de::from_reader(file).map_err(|e| format!("{}", e))
}

/// Loads the file that should be tested, serialized in cbor
pub fn load_versioned_test_cbor<Data: DeserializeOwned, P: AsRef<Path>>(
    dir: P,
    test_filename: &str,
) -> Result<Data, String> {
    let filename_cbor = format!("{}.cbor", test_filename);
    let file = File::open(dir.as_ref().join(filename_cbor)).map_err(|e| format!("{}", e))?;
    ciborium::de::from_reader(file).map_err(|e| format!("{}", e))
}

pub fn load_tests_metadata<P: AsRef<Path>>(path: P) -> Result<Vec<Testcase>, String> {
    let serialized = fs::read_to_string(path).map_err(|e| format!("{}", e))?;
    ron::from_str(&serialized).map_err(|e| format!("{}", e))
}
