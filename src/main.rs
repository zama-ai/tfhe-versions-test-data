use std::{borrow::Cow, fs::create_dir_all, path::Path};

use tfhe_versions_test_data::{
    data_0_6::V0_6,
    generate::{dir_for_version, store_metadata, store_versioned, TfhersVersion},
    ShortintCiphertextTest, ShortintClientKeyTest, TestMetadata, TestParameterSet,
};

const TEST_PARAMS: TestParameterSet = TestParameterSet {
    lwe_dimension: 761,
    glwe_dimension: 1,
    polynomial_size: 2048,
    lwe_noise_gaussian_stddev: 6.36835566258815e-06,
    glwe_noise_gaussian_stddev: 3.1529322391500584e-16,
    pbs_base_log: 23,
    pbs_level: 1,
    ks_base_log: 3,
    ks_level: 5,
    message_modulus: 4,
    carry_modulus: 4,
    max_noise_level: 5,
    log2_p_fail: -40.05,
    log2_ciphertext_modulus: 64,
    encryption_key_choice: Cow::Borrowed("big"),
};

const PRNG_SEED: u128 = 0xdeadbeef;

const SHORTINT_CLIENTKEY_TEST: ShortintClientKeyTest = ShortintClientKeyTest {
    key_filename: Cow::Borrowed("client_key.cbor"),
    parameters: TEST_PARAMS,
};
const SHORTINT_CT1_TEST: ShortintCiphertextTest = ShortintCiphertextTest {
    key_filename: Cow::Borrowed("client_key.cbor"),
    ct_filename: Cow::Borrowed("ct1.cbor"),
    clear_value: 0,
};
const SHORTINT_CT2_TEST: ShortintCiphertextTest = ShortintCiphertextTest {
    key_filename: Cow::Borrowed("client_key.cbor"),
    ct_filename: Cow::Borrowed("ct2.cbor"),
    clear_value: 3,
};

fn gen_shortint_data<Vers: TfhersVersion>(dir: &Path) {
    create_dir_all(dir).unwrap();

    // generate a client key
    let shortint_client_key = Vers::gen_shortint_client_key(SHORTINT_CLIENTKEY_TEST);

    store_versioned(
        &shortint_client_key,
        dir.join(&*SHORTINT_CLIENTKEY_TEST.key_filename),
    );

    // generate ciphertexts
    let ct1 = Vers::gen_shortint_ct(SHORTINT_CT1_TEST, &shortint_client_key);
    let ct2 = Vers::gen_shortint_ct(SHORTINT_CT2_TEST, &shortint_client_key);

    // Serialize them
    store_versioned(&ct1, dir.join(&*SHORTINT_CT1_TEST.ct_filename));
    store_versioned(&ct2, dir.join(&*SHORTINT_CT2_TEST.ct_filename));

    let shortint_tests = vec![
        TestMetadata::ShortintClientKey(SHORTINT_CLIENTKEY_TEST),
        TestMetadata::ShortintCiphertext(SHORTINT_CT1_TEST),
        TestMetadata::ShortintCiphertext(SHORTINT_CT2_TEST),
    ];
    // store test metadata
    store_metadata(&shortint_tests, dir.join("shortint.ron"));
}

fn gen_all_data<Vers: TfhersVersion>() {
    Vers::seed_prng(PRNG_SEED);

    let dir = dir_for_version(Vers::VERSION_NUMBER);
    gen_shortint_data::<Vers>(&dir.join("shortint"))
}

fn main() {
    gen_all_data::<V0_6>();
}
