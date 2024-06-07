use std::{
    fmt::Display,
    fs::{self, File},
    path::Path,
};

use bincode::{DefaultOptions, Options};
use serde::de::DeserializeOwned;

use crate::Testcase;

/// Loads auxiliary data that might be needed for a test (eg: a key to test a ciphertext)
pub fn load_versioned_auxiliary<Data: DeserializeOwned, P: AsRef<Path>>(
    path: P,
) -> Result<Data, String> {
    let file = File::open(path).map_err(|e| format!("{}", e))?;
    ciborium::de::from_reader(file).map_err(|e| format!("{}", e))
}

#[derive(Copy, Clone, Debug)]
pub enum DataFormat {
    Cbor,
    Bincode,
}

impl Display for DataFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl DataFormat {
    /// Loads the file that should be tested
    pub fn load_versioned_test<Data: DeserializeOwned, P: AsRef<Path>>(
        self,
        dir: P,
        test_filename: &str,
    ) -> Result<Data, String> {
        match self {
            Self::Cbor => {
                let filename_cbor = format!("{}.cbor", test_filename);
                let file =
                    File::open(dir.as_ref().join(filename_cbor)).map_err(|e| format!("{}", e))?;
                ciborium::de::from_reader(file).map_err(|e| format!("{}", e))
            }
            Self::Bincode => {
                let filename_bincode = format!("{}.bcode", test_filename);
                let file = File::open(dir.as_ref().join(filename_bincode))
                    .map_err(|e| format!("{}", e))?;
                let options = DefaultOptions::new().with_fixint_encoding();
                options.deserialize_from(file).map_err(|e| format!("{}", e))
            }
        }
    }
}

pub fn load_tests_metadata<P: AsRef<Path>>(path: P) -> Result<Vec<Testcase>, String> {
    let serialized = fs::read_to_string(path).map_err(|e| format!("{}", e))?;
    ron::from_str(&serialized).map_err(|e| format!("{}", e))
}
