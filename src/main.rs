use tfhe_backward_compat_data::{
    data_0_6::V0_6,
    data_dir,
    generate::{store_metadata, TfhersVersion},
    Testcase,
};

const PRNG_SEED: u128 = 0xdeadbeef;

fn gen_all_data<Vers: TfhersVersion>() -> Vec<Testcase> {
    Vers::seed_prng(PRNG_SEED);

    let tests = Vers::gen_shortint_data();

    tests
        .iter()
        .map(|metadata| Testcase {
            tfhe_version_min: Vers::VERSION_NUMBER.to_string(),
            tfhe_module: "shortint".to_string(),
            metadata: metadata.clone(),
        })
        .collect()
}

fn main() {
    let root_dir = env!("CARGO_MANIFEST_DIR");
    let testcases = gen_all_data::<V0_6>(); // When we add more versions, extend the Vec with all the testcases

    let shortint_testcases: Vec<Testcase> = testcases
        .iter()
        .filter(|test| test.tfhe_module == "shortint")
        .map(|test| test.clone())
        .collect();

    store_metadata(&shortint_testcases, data_dir(root_dir).join("shortint.ron"))
}
