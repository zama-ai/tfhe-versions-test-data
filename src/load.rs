use std::{
    fs::{self, File},
    path::{Path, PathBuf},
    str::FromStr,
};

use serde::de::DeserializeOwned;
use tfhe::shortint::{
    parameters::{
        DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
        LweDimension, PolynomialSize, StandardDev,
    },
    CarryModulus, CiphertextModulus, ClassicPBSParameters, EncryptionKeyChoice, MaxNoiseLevel,
    MessageModulus, PBSParameters, ShortintParameterSet,
};

use crate::{TestMetadata, TestParameterSet, DATA_DIR};

pub fn dir_for_latest<P: AsRef<Path>>(base_dir: P) -> PathBuf {
    let mut path = base_dir.as_ref().to_path_buf();
    path.push(DATA_DIR);
    path.push("latest");

    path
}

pub fn load_versioned<Data: DeserializeOwned, P: AsRef<Path>>(path: P) -> Result<Data, ()> {
    let file = File::open(path).map_err(|_| ())?;
    ciborium::de::from_reader(file).map_err(|_| ())
}

pub fn load_metadata<P: AsRef<Path>>(path: P) -> Result<Vec<TestMetadata>, ()> {
    let serialized = fs::read_to_string(path).map_err(|_| ())?;
    ron::from_str(&serialized).map_err(|_| ())
}

impl From<TestParameterSet> for ShortintParameterSet {
    fn from(value: TestParameterSet) -> Self {
        Self::new_pbs_param_set(PBSParameters::PBS(ClassicPBSParameters {
            lwe_dimension: LweDimension(value.lwe_dimension),
            glwe_dimension: GlweDimension(value.glwe_dimension),
            polynomial_size: PolynomialSize(value.polynomial_size),
            lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
                value.lwe_noise_gaussian_stddev,
            )),
            glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
                value.glwe_noise_gaussian_stddev,
            )),
            pbs_base_log: DecompositionBaseLog(value.pbs_base_log),
            pbs_level: DecompositionLevelCount(value.pbs_level),
            ks_base_log: DecompositionBaseLog(value.ks_base_log),
            ks_level: DecompositionLevelCount(value.ks_level),
            message_modulus: MessageModulus(value.message_modulus),
            carry_modulus: CarryModulus(value.carry_modulus),
            max_noise_level: MaxNoiseLevel::new(value.max_noise_level),
            log2_p_fail: value.log2_p_fail,
            ciphertext_modulus: CiphertextModulus::try_new_power_of_2(
                value.log2_ciphertext_modulus,
            )
            .unwrap(),
            encryption_key_choice: {
                match &*value.encryption_key_choice {
                    "big" => EncryptionKeyChoice::Big,
                    "small" => EncryptionKeyChoice::Small,
                    _ => panic!("Invalid encryption key choice"),
                }
            },
        }))
    }
}
