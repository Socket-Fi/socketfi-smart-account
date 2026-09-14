use crate::{
    account::Account,
    account_trait::AccountTrait,
    states::{clear_active_signers, read_passkey, read_rpid_hash, read_stellar_signer},
};
use socketfi_shared::{
    account_error::AccountError,
    bls::g1_group_gen_point,
    constants::DST,
    key_types::{BlsKeyWithPoP, EvmSignature, PasskeySignature},
};
use soroban_sdk::{
    contract, contractimpl,
    crypto::bls12_381::{Fr, G1Affine},
    testutils::Address as _,
    Address, Bytes, BytesN, Env, Vec, U256,
};

#[contract]
struct StorageHost;

#[contractimpl]
impl StorageHost {
    pub fn ping() {}
}

fn bls_proofs(env: &Env, challenge: &BytesN<32>) -> Vec<BlsKeyWithPoP> {
    // Deterministic test-only scalars 1 and 2, never production keys.
    let bls = env.crypto().bls12_381();
    let generator = -G1Affine::from_bytes(g1_group_gen_point(env));
    let message = bls.hash_to_g2(
        &challenge.clone().into(),
        &Bytes::from_slice(env, DST.as_bytes()),
    );
    let mut proofs = Vec::new(env);
    for scalar in [1, 2] {
        let scalar = Fr::from_u256(U256::from_u32(env, scalar));
        proofs.push_back(BlsKeyWithPoP {
            key: bls.g1_mul(&generator, &scalar).to_bytes(),
            sig: bls.g2_mul(&message, &scalar).to_bytes(),
        });
    }
    proofs
}

fn initialize(
    env: &Env,
    rpid_hash: Option<BytesN<32>>,
    passkey: Option<BytesN<65>>,
    passkey_sig: Option<PasskeySignature>,
    evm: bool,
    proofs: Vec<BlsKeyWithPoP>,
) -> Result<(), AccountError> {
    let stellar_address = Address::from_str(
        env,
        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
    );
    Account::__constructor(
        env.clone(),
        BytesN::from_array(env, &[7; 32]),
        passkey,
        passkey_sig,
        rpid_hash,
        if evm {
            None
        } else {
            Some(BytesN::from_array(env, &[0; 32]))
        },
        if evm { None } else { Some(stellar_address) },
        if evm {
            Some(BytesN::from_array(env, &[1; 20]))
        } else {
            None
        },
        if evm {
            Some(EvmSignature {
                signature: BytesN::from_array(env, &[0; 64]),
                recovery_id: 2,
            })
        } else {
            None
        },
        proofs,
        Vec::new(env),
        BytesN::from_array(env, &[9; 32]),
        Address::generate(env),
    )
}

#[test]
fn stellar_creation_stores_rpid_without_installing_passkey_and_preserves_it_on_clear() {
    let env = Env::default();
    let host = env.register(StorageHost, ());
    let hash = BytesN::from_array(&env, &[3; 32]);
    let proofs = bls_proofs(&env, &BytesN::from_array(&env, &[7; 32]));
    env.as_contract(&host, || {
        assert_eq!(
            initialize(&env, Some(hash.clone()), None, None, false, proofs),
            Ok(())
        );
        assert_eq!(read_rpid_hash(&env), Some(hash.clone()));
        assert!(read_passkey(&env).is_none());
        assert_eq!(
            read_stellar_signer(&env),
            Some(BytesN::from_array(&env, &[0; 32]))
        );
        clear_active_signers(&env);
        assert!(read_stellar_signer(&env).is_none());
        assert_eq!(read_rpid_hash(&env), Some(hash));
    });
}

#[test]
fn every_initial_signer_requires_rpid_configuration() {
    let env = Env::default();
    for evm in [false, true] {
        let host = env.register(StorageHost, ());
        env.as_contract(&host, || {
            assert_eq!(
                initialize(&env, None, None, None, evm, Vec::new(&env)),
                Err(AccountError::RpidNotFound)
            );
            assert!(read_rpid_hash(&env).is_none());
        });
    }
}

#[test]
fn rpid_only_does_not_bypass_evm_proof_validation() {
    let env = Env::default();
    let host = env.register(StorageHost, ());
    env.as_contract(&host, || {
        assert_eq!(
            initialize(
                &env,
                Some(BytesN::from_array(&env, &[3; 32])),
                None,
                None,
                true,
                Vec::new(&env)
            ),
            Err(AccountError::InvalidEvmRecoveryId)
        );
        assert!(read_rpid_hash(&env).is_none());
    });
}

#[test]
fn independent_rpid_does_not_allow_partial_passkey_configuration() {
    let env = Env::default();
    let host = env.register(StorageHost, ());
    env.as_contract(&host, || {
        assert_eq!(
            initialize(
                &env,
                Some(BytesN::from_array(&env, &[3; 32])),
                Some(BytesN::from_array(&env, &[0; 65])),
                None,
                false,
                Vec::new(&env)
            ),
            Err(AccountError::InvalidConfig)
        );
        assert!(read_rpid_hash(&env).is_none());
    });
}

// Public deterministic test keys (private scalar 1), never user material.
fn initialize_valid_owner(env: &Env, evm: bool, rpid: BytesN<32>) -> Result<(), AccountError> {
    let passkey_sig = PasskeySignature {
        signature: BytesN::from_array(env, &PSIG),
        client_data_json: Bytes::from_slice(env, CLIENT),
        authenticator_data: Bytes::from_slice(env, &AUTH),
    };
    let challenge = BytesN::from_array(env, &[7; 32]);
    Account::__constructor(
        env.clone(),
        challenge.clone(),
        if evm {
            None
        } else {
            Some(BytesN::from_array(env, &PUB))
        },
        if evm { None } else { Some(passkey_sig) },
        Some(rpid),
        None,
        None,
        if evm {
            Some(BytesN::from_array(env, &EADDR))
        } else {
            None
        },
        if evm {
            Some(EvmSignature {
                signature: BytesN::from_array(env, &ESIG),
                recovery_id: RECID,
            })
        } else {
            None
        },
        bls_proofs(env, &challenge),
        Vec::new(env),
        BytesN::from_array(env, &[9; 32]),
        Address::generate(env),
    )
}

#[test]
fn evm_creation_stores_rpid_without_installing_passkey() {
    let env = Env::default();
    let host = env.register(StorageHost, ());
    env.as_contract(&host, || {
        let hash = BytesN::from_array(&env, &[3; 32]);
        assert_eq!(initialize_valid_owner(&env, true, hash.clone()), Ok(()));
        assert_eq!(read_rpid_hash(&env), Some(hash));
        assert!(read_passkey(&env).is_none());
        assert_eq!(
            crate::states::read_evm_signer(&env),
            Some(BytesN::from_array(&env, &EADDR))
        );
    });
}

#[test]
fn existing_passkey_creation_still_verifies_and_stores_its_rpid() {
    let env = Env::default();
    let host = env.register(StorageHost, ());
    env.as_contract(&host, || {
        let hash = BytesN::from_array(&env, &[3; 32]);
        assert_eq!(initialize_valid_owner(&env, false, hash.clone()), Ok(()));
        assert_eq!(read_rpid_hash(&env), Some(hash));
        assert_eq!(read_passkey(&env), Some(BytesN::from_array(&env, &PUB)));
    });
}

#[test]
fn passkey_proof_for_another_rpid_is_still_rejected() {
    let env = Env::default();
    let host = env.register(StorageHost, ());
    env.as_contract(&host, || {
        assert_eq!(
            initialize_valid_owner(&env, false, BytesN::from_array(&env, &[4; 32])),
            Err(AccountError::InvalidRpIdHash)
        );
        assert!(read_passkey(&env).is_none());
        assert!(read_rpid_hash(&env).is_none());
    });
}

const PUB: [u8; 65] = [
    4, 107, 23, 209, 242, 225, 44, 66, 71, 248, 188, 230, 229, 99, 164, 64, 242, 119, 3, 125, 129,
    45, 235, 51, 160, 244, 161, 57, 69, 216, 152, 194, 150, 79, 227, 66, 226, 254, 26, 127, 155,
    142, 231, 235, 74, 124, 15, 158, 22, 43, 206, 51, 87, 107, 49, 94, 206, 203, 182, 64, 104, 55,
    191, 81, 245,
];

const PSIG: [u8; 64] = [
    128, 211, 57, 11, 153, 181, 23, 15, 1, 78, 250, 134, 238, 133, 206, 169, 227, 84, 96, 155, 203,
    179, 167, 72, 191, 215, 15, 88, 245, 43, 162, 112, 112, 172, 93, 117, 10, 32, 40, 72, 240, 209,
    233, 219, 91, 36, 117, 62, 147, 29, 78, 51, 209, 20, 180, 62, 33, 98, 64, 64, 139, 147, 132,
    245,
];

const AUTH: [u8; 37] = [
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    5, 0, 0, 0, 0,
];

const EADDR: [u8; 20] = [
    126, 95, 69, 82, 9, 26, 105, 18, 93, 93, 252, 183, 184, 194, 101, 144, 41, 57, 91, 223,
];

const ESIG: [u8; 64] = [
    121, 190, 102, 126, 249, 220, 187, 172, 85, 160, 98, 149, 206, 135, 11, 7, 2, 155, 252, 219,
    45, 206, 40, 217, 89, 242, 129, 91, 22, 248, 23, 152, 76, 183, 43, 128, 184, 223, 59, 161, 203,
    161, 38, 164, 193, 248, 225, 32, 6, 76, 207, 4, 164, 165, 176, 157, 124, 192, 145, 60, 234, 45,
    46, 63,
];

const CLIENT: &[u8] = br#"{"type":"webauthn.get","challenge":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","origin":"https://socket.fi"}"#;
const RECID: u32 = 0;
