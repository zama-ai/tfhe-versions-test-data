use tfhe_versions_test_data::{data_0_6, dir_for_version};

fn main() {
    data_0_6::gen_data(&dir_for_version("0.6"));
}
