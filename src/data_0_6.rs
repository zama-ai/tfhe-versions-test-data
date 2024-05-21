use std::{fs::create_dir_all, path::Path};

use tfhe_0_6::shortint::{gen_keys, parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS};

use crate::{
    store_metadata, store_versioned, ShortintCiphertextTest, ShortintClientKeyTest, TestMetadata,
    TestParameterSet,
};

pub fn gen_data(dir: &Path) {
    create_dir_all(dir).unwrap();

    // We generate a set of client/server key
    let (client_key, _server_key) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

    store_versioned(&client_key, dir.join("client_key.cbor"));

    let msg1 = 0;
    let msg2 = 3;

    // Create some init ciphertexts and another one which is the result of an homomoprhic op
    let ct1 = client_key.encrypt(msg1);
    let ct2 = client_key.encrypt(msg2);

    // Serialize them
    store_versioned(&ct1, dir.join("ct1.cbor"));
    store_versioned(&ct2, dir.join("ct2.cbor"));

    // store test metadata
    let tests = vec![
        TestMetadata::ShortintClientKey(ShortintClientKeyTest {
            key_filename: "client_key.cbor".to_string(),
            parameters: TestParameterSet::Message2Carry2KsPbs,
        }),
        TestMetadata::ShortintCiphertext(ShortintCiphertextTest {
            key_filename: "client_key.cbor".to_string(),
            ct_filename: "ct1.cbor".to_string(),
            clear_value: msg1,
        }),
        TestMetadata::ShortintCiphertext(ShortintCiphertextTest {
            key_filename: "client_key.cbor".to_string(),
            ct_filename: "ct2.cbor".to_string(),
            clear_value: msg2,
        }),
    ];

    store_metadata(&tests, dir.join("shortint.ron"));
}
