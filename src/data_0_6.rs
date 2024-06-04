use tfhe_0_6::{
    core_crypto::commons::{
        generators::DeterministicSeeder,
        math::random::{ActivatedRandomGenerator, Seed},
    },
    shortint::{
        engine::ShortintEngine,
        gen_keys,
        parameters::{
            DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
            LweDimension, PolynomialSize, StandardDev,
        },
        CarryModulus, Ciphertext, CiphertextModulus, ClassicPBSParameters, ClientKey,
        EncryptionKeyChoice, MaxNoiseLevel, MessageModulus, PBSParameters, ShortintParameterSet,
    },
};

use crate::{ShortintCiphertextTest, ShortintClientKeyTest, TestParameterSet, TfhersVersion};

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

    fn gen_shortint_client_key(meta: ShortintClientKeyTest) -> Self::ShortintClientKey {
        let (client_key, _server_key) = gen_keys(meta.parameters);
        client_key
    }

    fn gen_shortint_ct(
        meta: ShortintCiphertextTest,
        key: &Self::ShortintClientKey,
    ) -> Self::ShortintCiphertext {
        key.encrypt(meta.clear_value)
    }
}
