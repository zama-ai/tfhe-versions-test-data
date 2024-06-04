use std::{borrow::Cow, fs::create_dir_all, path::Path};

use tfhe_versions_test_data::{
    data_0_6::V0_6, dir_for_version, store_metadata, store_versioned, ShortintCiphertextTest,
    ShortintClientKeyTest, TestMetadata, TestParameterSet, TfhersVersion,
};

const TEST_PARAMS: TestParameterSet = TestParameterSet {
    lwe_dimension: 742,
    glwe_dimension: 1,
    polynomial_size: 2048,
    lwe_noise_gaussian_stddev: 0.000007069849454709433,
    glwe_noise_gaussian_stddev: 0.00000000000000029403601535432533,
    pbs_base_log: 23,
    pbs_level: 1,
    ks_base_log: 5,
    ks_level: 3,
    pfks_level: 1,
    pfks_base_log: 23,
    pfks_noise_gaussian_stddev: 0.00000000000000029403601535432533,
    cbs_level: 0,
    cbs_base_log: 0,
    message_modulus: 4,
    ciphertext_modulus: 64,
    carry_modulus: 4,
    max_noise_level: 5,
    log2_p_fail: -40.05,
    encryption_key_choice: Cow::Borrowed("big"),
};

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

    // generate ciphertexts
    let ct1 = Vers::gen_shortint_ct(SHORTINT_CT1_TEST, &shortint_client_key);
    let ct2 = Vers::gen_shortint_ct(SHORTINT_CT2_TEST, &shortint_client_key);

    store_versioned(&shortint_client_key, dir.join("client_key.cbor"));

    // Serialize them
    store_versioned(&ct1, dir.join("ct1.cbor"));
    store_versioned(&ct2, dir.join("ct2.cbor"));

    let shortint_tests = vec![TestMetadata::ShortintClientKey(SHORTINT_CLIENTKEY_TEST)];
    // store test metadata
    store_metadata(&shortint_tests, dir.join("shortint.ron"));
}

fn gen_all_data<Vers: TfhersVersion>() {
    let dir = dir_for_version(Vers::VERSION_NUMBER);
    gen_shortint_data::<Vers>(&dir.join("shortint"))
}

fn main() {
    gen_all_data::<V0_6>();
}
