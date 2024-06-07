use std::{borrow::Cow, fs::create_dir_all};

use tfhe_0_6::{
    core_crypto::commons::{
        generators::DeterministicSeeder,
        math::random::{ActivatedRandomGenerator, Seed},
    },
    shortint::{
        engine::ShortintEngine,
        parameters::{
            DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
            LweDimension, PolynomialSize, StandardDev,
        },
        CarryModulus, Ciphertext, CiphertextModulus, ClassicPBSParameters, ClientKey,
        EncryptionKeyChoice, MaxNoiseLevel, MessageModulus, PBSParameters, ShortintParameterSet,
    },
};

use crate::{
    generate::{store_versioned_test, TfhersVersion, TEST_PARAMS},
    ShortintCiphertextTest, ShortintClientKeyTest, TestMetadata, TestParameterSet,
};

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
            ciphertext_modulus: CiphertextModulus::try_new(value.ciphertext_modulus).unwrap(),
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

const SHORTINT_CLIENTKEY_TEST: ShortintClientKeyTest = ShortintClientKeyTest {
    test_filename: Cow::Borrowed("client_key"),
    parameters: TEST_PARAMS,
};
const SHORTINT_CT1_TEST: ShortintCiphertextTest = ShortintCiphertextTest {
    test_filename: Cow::Borrowed("ct1"),
    key_filename: Cow::Borrowed("client_key.cbor"),
    clear_value: 0,
};
const SHORTINT_CT2_TEST: ShortintCiphertextTest = ShortintCiphertextTest {
    test_filename: Cow::Borrowed("ct2"),
    key_filename: Cow::Borrowed("client_key.cbor"),
    clear_value: 3,
};

pub struct V0_6;

impl TfhersVersion for V0_6 {
    type ShortintCiphertext = Ciphertext;
    type ShortintClientKey = ClientKey;

    const VERSION_NUMBER: &'static str = "0.6";

    fn seed_prng(seed: u128) {
        let mut seeder = DeterministicSeeder::<ActivatedRandomGenerator>::new(Seed(seed));
        let engine = ShortintEngine::new_from_seeder(&mut seeder);

        ShortintEngine::with_thread_local_mut(|local_engine| {
            let _ = std::mem::replace(local_engine, engine);
        });
    }

    fn gen_shortint_data() -> Vec<TestMetadata> {
        let dir = Self::data_dir().join("shortint");
        create_dir_all(&dir).unwrap();

        // generate a client key
        let shortint_client_key = ClientKey::new(SHORTINT_CLIENTKEY_TEST.parameters);

        store_versioned_test(
            &shortint_client_key,
            &dir,
            &*SHORTINT_CLIENTKEY_TEST.test_filename,
        );

        // generate ciphertexts
        let ct1 = shortint_client_key.encrypt(SHORTINT_CT1_TEST.clear_value);
        let ct2 = shortint_client_key.encrypt(SHORTINT_CT2_TEST.clear_value);

        // Serialize them
        store_versioned_test(&ct1, &dir, &*SHORTINT_CT1_TEST.test_filename);
        store_versioned_test(&ct2, &dir, &*SHORTINT_CT2_TEST.test_filename);

        vec![
            TestMetadata::ShortintClientKey(SHORTINT_CLIENTKEY_TEST),
            TestMetadata::ShortintCiphertext(SHORTINT_CT1_TEST),
            TestMetadata::ShortintCiphertext(SHORTINT_CT2_TEST),
        ]
    }
}
