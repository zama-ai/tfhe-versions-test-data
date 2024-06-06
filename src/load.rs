use std::{
    fs::{self, File},
    path::{Path, PathBuf},
};

use semver::{Version, VersionReq};
use serde::de::DeserializeOwned;

use crate::{TestMetadata, Testcase, DATA_DIR};

pub fn load_versioned<Data: DeserializeOwned, P: AsRef<Path>>(path: P) -> Result<Data, String> {
    let file = File::open(path).map_err(|e| format!("{}", e))?;
    ciborium::de::from_reader(file).map_err(|e| format!("{}", e))
}

pub fn load_metadata<P: AsRef<Path>>(path: P) -> Result<Vec<TestMetadata>, String> {
    let serialized = fs::read_to_string(path).map_err(|e| format!("{}", e))?;
    ron::from_str(&serialized).map_err(|e| format!("{}", e))
}
