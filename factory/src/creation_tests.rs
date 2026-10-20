use crate::{
    account_factory::{
        is_registered_account, read_creation_pop_challenge, write_creation_nonce_used,
        write_expected_network, write_registered_account, write_rpid_hash,
    },
    data::DataKey,
};
use socketfi_shared::account_error::AccountError;
use soroban_sdk::{
    contract, contractimpl,
    testutils::{storage::Temporary, Address as _, Ledger},
    Address, BytesN, Env, String, Symbol, Vec,
};

#[contract]
struct Host;
#[contractimpl]
impl Host {
    pub fn ping() {}
}

fn initialize_host(env: &Env, host: &Address, wasm_byte: u8) {
    env.as_contract(host, || {
        write_rpid_hash(env, &String::from_str(env, "socket.fi"));
        write_expected_network(env, &Symbol::new(env, "TESTNET")).unwrap();
        upgrade::init_account_wasm_hash(env, &BytesN::from_array(env, &[wasm_byte; 32])).unwrap();
    });
}

fn setup() -> (Env, Address) {
    let env = Env::default();
    env.ledger().set_sequence_number(1000);
    env.ledger().set_min_temp_entry_ttl(1);
    let host = env.register(Host, ());
    initialize_host(&env, &host, 9);
    (env, host)
}

fn challenge(
    env: &Env,
    nonce: &BytesN<32>,
    network: &Symbol,
    live_until_ledger: u32,
) -> Result<BytesN<32>, AccountError> {
    read_creation_pop_challenge(
        env,
        Some(BytesN::from_array(env, &[4; 65])),
        None,
        None,
        Vec::from_array(env, [BytesN::from_array(env, &[5; 96])]),
        nonce,
        network,
        Vec::new(env),
        live_until_ledger,
    )
}

#[test]
fn expiry_boundaries_network_binding_and_replay_retention() {
    let (env, host) = setup();
    let nonce = BytesN::from_array(&env, &[7; 32]);
    let network = Symbol::new(&env, "TESTNET");
    env.as_contract(&host, || {
        assert_eq!(
            challenge(&env, &nonce, &network, 999),
            Err(AccountError::CreationProofExpired)
        );
        assert!(challenge(&env, &nonce, &network, 1000).is_ok());
        assert!(challenge(&env, &nonce, &network, 1120).is_ok());
        assert_eq!(
            challenge(&env, &nonce, &network, 1121),
            Err(AccountError::InvalidCreationExpiry)
        );
        assert_eq!(
            challenge(&env, &nonce, &Symbol::new(&env, "OTHER"), 1120),
            Err(AccountError::InvalidNetwork)
        );
        assert_eq!(
            challenge(&env, &nonce, &Symbol::new(&env, "PUBLIC"), 1120),
            Err(AccountError::NetworkMismatch)
        );
        write_creation_nonce_used(&env, &nonce, 1120).unwrap();
        let key = DataKey::UsedCreationNonce(nonce.clone());
        assert_eq!(env.storage().temporary().get_ttl(&key), 120);
        assert!(!env.storage().persistent().has(&key));
        assert_eq!(
            challenge(&env, &nonce, &network, 1120),
            Err(AccountError::NonceAlreadyUsed)
        );
    });
    env.ledger().set_sequence_number(1120);
    env.as_contract(&host, || {
        assert_eq!(
            challenge(&env, &nonce, &network, 1120),
            Err(AccountError::NonceAlreadyUsed)
        );
    });
    env.ledger().set_sequence_number(1121);
    env.as_contract(&host, || {
        env.storage()
            .temporary()
            .remove(&DataKey::UsedCreationNonce(nonce.clone()));
        assert_eq!(
            challenge(&env, &nonce, &network, 1120),
            Err(AccountError::CreationProofExpired)
        );
    });
}

#[test]
fn challenge_binds_complete_creation_configuration() {
    let (env, host) = setup();
    let nonce = BytesN::from_array(&env, &[7; 32]);
    let network = Symbol::new(&env, "TESTNET");
    let original = env.as_contract(&host, || challenge(&env, &nonce, &network, 1120).unwrap());
    env.as_contract(&host, || {
        assert_ne!(original, challenge(&env, &nonce, &network, 1119).unwrap());
        assert_ne!(
            original,
            challenge(&env, &BytesN::from_array(&env, &[8; 32]), &network, 1120).unwrap()
        );
        let changed_passkey = read_creation_pop_challenge(
            &env,
            Some(BytesN::from_array(&env, &[6; 65])),
            None,
            None,
            Vec::from_array(&env, [BytesN::from_array(&env, &[5; 96])]),
            &nonce,
            &network,
            Vec::new(&env),
            1120,
        )
        .unwrap();
        assert_ne!(original, changed_passkey);
        let changed_bls = read_creation_pop_challenge(
            &env,
            Some(BytesN::from_array(&env, &[4; 65])),
            None,
            None,
            Vec::from_array(&env, [BytesN::from_array(&env, &[6; 96])]),
            &nonce,
            &network,
            Vec::new(&env),
            1120,
        )
        .unwrap();
        assert_ne!(original, changed_bls);
        let changed_guardians = read_creation_pop_challenge(
            &env,
            Some(BytesN::from_array(&env, &[4; 65])),
            None,
            None,
            Vec::from_array(&env, [BytesN::from_array(&env, &[5; 96])]),
            &nonce,
            &network,
            Vec::from_array(&env, [Address::generate(&env)]),
            1120,
        )
        .unwrap();
        assert_ne!(original, changed_guardians);
        write_rpid_hash(&env, &String::from_str(&env, "other.example"));
        assert_ne!(original, challenge(&env, &nonce, &network, 1120).unwrap());
    });
    let other = env.register(Host, ());
    initialize_host(&env, &other, 10);
    env.as_contract(&other, || {
        assert_ne!(original, challenge(&env, &nonce, &network, 1120).unwrap());
    });
    env.ledger().set_network_id([8; 32]);
    env.as_contract(&host, || {
        assert_ne!(original, challenge(&env, &nonce, &network, 1120).unwrap());
    });
}

#[test]
fn honors_legacy_tombstones_and_handles_u32_boundary() {
    let (env, host) = setup();
    let nonce = BytesN::from_array(&env, &[7; 32]);
    let network = Symbol::new(&env, "TESTNET");
    env.as_contract(&host, || {
        env.storage()
            .persistent()
            .set(&DataKey::UsedCreationNonce(nonce.clone()), &true);
        assert_eq!(
            challenge(&env, &nonce, &network, 1120),
            Err(AccountError::NonceAlreadyUsed)
        );
    });
    env.ledger().set_max_entry_ttl(10);
    env.ledger().set_sequence_number(u32::MAX - 10);
    assert_eq!(
        crate::account_factory::validate_creation_expiry(&env, u32::MAX - 1),
        Ok(())
    );
    assert_eq!(
        crate::account_factory::validate_creation_expiry(&env, 0),
        Err(AccountError::CreationProofExpired)
    );
}

#[test]
fn canonical_registry_is_keyed_and_does_not_accept_unwritten_accounts() {
    let (env, host) = setup();
    let registered = Address::generate(&env);
    let unknown = Address::generate(&env);
    env.as_contract(&host, || {
        assert!(!is_registered_account(&env, &registered));
        assert!(!is_registered_account(&env, &unknown));
        write_registered_account(&env, &registered);
        assert!(is_registered_account(&env, &registered));
        assert!(!is_registered_account(&env, &unknown));
    });
}
