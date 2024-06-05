use std::{
    fs::{self, File},
    path::{Path, PathBuf},
};

use serde::de::DeserializeOwned;

use crate::{TestMetadata, DATA_DIR};

pub fn dir_for_latest<P: AsRef<Path>>(base_dir: P) -> PathBuf {
    let mut path = base_dir.as_ref().to_path_buf();
    path.push(DATA_DIR);
    path.push("latest");

    path
}

pub fn load_versioned<Data: DeserializeOwned, P: AsRef<Path>>(path: P) -> Result<Data, String> {
    let file = File::open(path).map_err(|e| format!("{}", e))?;
    ciborium::de::from_reader(file).map_err(|e| format!("{}", e))
}

pub fn load_metadata<P: AsRef<Path>>(path: P) -> Result<Vec<TestMetadata>, String> {
    let serialized = fs::read_to_string(path).map_err(|e| format!("{}", e))?;
    ron::from_str(&serialized).map_err(|e| format!("{}", e))
}
