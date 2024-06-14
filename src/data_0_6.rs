use std::{borrow::Cow, fs::create_dir_all};

use tfhe_0_6::{
    boolean::engine::BooleanEngine,
    core_crypto::commons::{
        generators::DeterministicSeeder,
        math::random::{ActivatedRandomGenerator, Seed},
    },
    prelude::FheEncrypt,
    shortint::{
        self,
        engine::ShortintEngine,
        parameters::{
            DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
            LweDimension, PolynomialSize, StandardDev,
        },
        CarryModulus, CiphertextModulus, ClassicPBSParameters, EncryptionKeyChoice, MaxNoiseLevel,
        MessageModulus, PBSParameters,
    },
    CompressedFheUint8, FheUint8,
};

use crate::{
    generate::{store_versioned_test, TfhersVersion, VALID_TEST_PARAMS},
    HlCiphertextTest, HlClientKeyTest, ShortintCiphertextTest, ShortintClientKeyTest, TestMetadata,
    TestParameterSet, HL_MODULE_NAME, SHORTINT_MODULE_NAME,
};

impl From<TestParameterSet> for ClassicPBSParameters {
    fn from(value: TestParameterSet) -> Self {
        ClassicPBSParameters {
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
        }
    }
}

impl From<TestParameterSet> for PBSParameters {
    fn from(value: TestParameterSet) -> Self {
        let classic_pbs: ClassicPBSParameters = value.into();
        classic_pbs.into()
    }
}

const SHORTINT_CLIENTKEY_TEST: ShortintClientKeyTest = ShortintClientKeyTest {
    test_filename: Cow::Borrowed("client_key"),
    parameters: VALID_TEST_PARAMS,
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

const HL_CLIENTKEY_TEST: HlClientKeyTest = HlClientKeyTest {
    test_filename: Cow::Borrowed("client_key"),
    parameters: VALID_TEST_PARAMS,
};
const HL_CT1_TEST: HlCiphertextTest = HlCiphertextTest {
    test_filename: Cow::Borrowed("ct1"),
    key_filename: Cow::Borrowed("client_key.cbor"),
    compressed: false,
    clear_value: 0,
};
const HL_CT2_TEST: HlCiphertextTest = HlCiphertextTest {
    test_filename: Cow::Borrowed("ct2"),
    key_filename: Cow::Borrowed("client_key.cbor"),
    compressed: false,
    clear_value: 255,
};

const HL_COMPRESSED_CT1_TEST: HlCiphertextTest = HlCiphertextTest {
    test_filename: Cow::Borrowed("ct1_compressed"),
    key_filename: Cow::Borrowed("client_key.cbor"),
    compressed: true,
    clear_value: 0,
};
const HL_COMPRESSED_CT2_TEST: HlCiphertextTest = HlCiphertextTest {
    test_filename: Cow::Borrowed("ct2_compressed"),
    key_filename: Cow::Borrowed("client_key.cbor"),
    compressed: true,
    clear_value: 255,
};

pub struct V0_6;

impl TfhersVersion for V0_6 {
    const VERSION_NUMBER: &'static str = "0.6";

    fn seed_prng(seed: u128) {
        let mut seeder = DeterministicSeeder::<ActivatedRandomGenerator>::new(Seed(seed));
        let shortint_engine = ShortintEngine::new_from_seeder(&mut seeder);
        ShortintEngine::with_thread_local_mut(|local_engine| {
            let _ = std::mem::replace(local_engine, shortint_engine);
        });

        let boolean_engine = BooleanEngine::new_from_seeder(&mut seeder);
        BooleanEngine::replace_thread_local(boolean_engine);
    }

    fn gen_shortint_data() -> Vec<TestMetadata> {
        let dir = Self::data_dir().join(SHORTINT_MODULE_NAME);
        create_dir_all(&dir).unwrap();

        // generate a client key
        let shortint_client_key = shortint::ClientKey::new(SHORTINT_CLIENTKEY_TEST.parameters);

        store_versioned_test(
            &shortint_client_key,
            &dir,
            &SHORTINT_CLIENTKEY_TEST.test_filename,
        );

        // generate ciphertexts
        let ct1 = shortint_client_key.encrypt(SHORTINT_CT1_TEST.clear_value);
        let ct2 = shortint_client_key.encrypt(SHORTINT_CT2_TEST.clear_value);

        // Serialize them
        store_versioned_test(&ct1, &dir, &SHORTINT_CT1_TEST.test_filename);
        store_versioned_test(&ct2, &dir, &SHORTINT_CT2_TEST.test_filename);

        vec![
            TestMetadata::ShortintClientKey(SHORTINT_CLIENTKEY_TEST),
            TestMetadata::ShortintCiphertext(SHORTINT_CT1_TEST),
            TestMetadata::ShortintCiphertext(SHORTINT_CT2_TEST),
        ]
    }

    fn gen_hl_data() -> Vec<TestMetadata> {
        let dir = Self::data_dir().join(HL_MODULE_NAME);
        create_dir_all(&dir).unwrap();

        // generate a client key
        let config =
            tfhe_0_6::ConfigBuilder::with_custom_parameters(HL_CLIENTKEY_TEST.parameters, None)
                .build();
        let hl_client_key = tfhe_0_6::ClientKey::generate(config);

        store_versioned_test(&hl_client_key, &dir, &HL_CLIENTKEY_TEST.test_filename);

        // generate ciphertexts
        let ct1 = FheUint8::encrypt(HL_CT1_TEST.clear_value, &hl_client_key);
        let ct2 = FheUint8::encrypt(HL_CT2_TEST.clear_value, &hl_client_key);

        let compressed_ct1 =
            CompressedFheUint8::encrypt(HL_COMPRESSED_CT1_TEST.clear_value, &hl_client_key);
        let compressed_ct2 =
            CompressedFheUint8::encrypt(HL_COMPRESSED_CT2_TEST.clear_value, &hl_client_key);

        // Serialize them
        store_versioned_test(&ct1, &dir, &HL_CT1_TEST.test_filename);
        store_versioned_test(&ct2, &dir, &HL_CT2_TEST.test_filename);
        store_versioned_test(&compressed_ct1, &dir, &HL_COMPRESSED_CT1_TEST.test_filename);
        store_versioned_test(&compressed_ct2, &dir, &HL_COMPRESSED_CT2_TEST.test_filename);

        vec![
            TestMetadata::HlClientKey(HL_CLIENTKEY_TEST),
            TestMetadata::HlCiphertext(HL_CT1_TEST),
            TestMetadata::HlCiphertext(HL_CT2_TEST),
            TestMetadata::HlCiphertext(HL_COMPRESSED_CT1_TEST),
            TestMetadata::HlCiphertext(HL_COMPRESSED_CT2_TEST),
        ]
    }
}
