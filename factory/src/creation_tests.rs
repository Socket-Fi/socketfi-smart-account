use crate::{
    account_factory::{read_creation_pop_challenge, write_creation_nonce_used, write_rpid_hash},
    data::DataKey,
};
use socketfi_shared::account_error::AccountError;
use soroban_sdk::{
    contract, contractimpl,
    testutils::{storage::Temporary, Ledger},
    Address, BytesN, Env, String, Symbol,
};

#[contract]
struct Host;
#[contractimpl]
impl Host {
    pub fn ping() {}
}

fn setup() -> (Env, Address) {
    let env = Env::default();
    env.ledger().set_sequence_number(1000);
    env.ledger().set_min_temp_entry_ttl(1);
    let host = env.register(Host, ());
    env.as_contract(&host, || {
        write_rpid_hash(&env, &String::from_str(&env, "socket.fi"))
    });
    (env, host)
}

#[test]
fn expiry_boundaries_and_replay_retention() {
    let (env, host) = setup();
    let nonce = BytesN::from_array(&env, &[7; 32]);
    let network = Symbol::new(&env, "TESTNET");
    env.as_contract(&host, || {
        assert_eq!(
            read_creation_pop_challenge(&env, &nonce, &network, 999),
            Err(AccountError::CreationProofExpired)
        );
        assert!(read_creation_pop_challenge(&env, &nonce, &network, 1000).is_ok());
        assert!(read_creation_pop_challenge(&env, &nonce, &network, 1120).is_ok());
        assert_eq!(
            read_creation_pop_challenge(&env, &nonce, &network, 1121),
            Err(AccountError::InvalidCreationExpiry)
        );
        assert_eq!(
            read_creation_pop_challenge(&env, &nonce, &Symbol::new(&env, "OTHER"), 1120),
            Err(AccountError::InvalidNetwork)
        );
        write_creation_nonce_used(&env, &nonce, 1120).unwrap();
        let key = DataKey::UsedCreationNonce(nonce.clone());
        assert_eq!(env.storage().temporary().get_ttl(&key), 120);
        assert!(!env.storage().persistent().has(&key));
        assert_eq!(
            read_creation_pop_challenge(&env, &nonce, &network, 1120),
            Err(AccountError::NonceAlreadyUsed)
        );
    });
    env.ledger().set_sequence_number(1120);
    env.as_contract(&host, || {
        assert_eq!(
            read_creation_pop_challenge(&env, &nonce, &network, 1120),
            Err(AccountError::NonceAlreadyUsed)
        );
    });
    env.ledger().set_sequence_number(1121);
    env.as_contract(&host, || {
        // Model eviction explicitly; old proof must fail even with no tombstone.
        env.storage()
            .temporary()
            .remove(&DataKey::UsedCreationNonce(nonce.clone()));
        assert_eq!(
            read_creation_pop_challenge(&env, &nonce, &network, 1120),
            Err(AccountError::CreationProofExpired)
        );
    });
}

#[test]
fn challenge_binds_expiry_factory_network_rpid_and_nonce() {
    let (env, host) = setup();
    let nonce = BytesN::from_array(&env, &[7; 32]);
    let network = Symbol::new(&env, "TESTNET");
    let original = env.as_contract(&host, || {
        read_creation_pop_challenge(&env, &nonce, &network, 1120).unwrap()
    });
    env.as_contract(&host, || {
        assert_ne!(
            original,
            read_creation_pop_challenge(&env, &nonce, &network, 1119).unwrap()
        );
        assert_ne!(
            original,
            read_creation_pop_challenge(&env, &BytesN::from_array(&env, &[8; 32]), &network, 1120)
                .unwrap()
        );
        assert_ne!(
            original,
            read_creation_pop_challenge(&env, &nonce, &Symbol::new(&env, "PUBLIC"), 1120).unwrap()
        );
        write_rpid_hash(&env, &String::from_str(&env, "other.example"));
        assert_ne!(
            original,
            read_creation_pop_challenge(&env, &nonce, &network, 1120).unwrap()
        );
        write_rpid_hash(&env, &String::from_str(&env, "socket.fi"));
    });
    let other = env.register(Host, ());
    env.as_contract(&other, || {
        write_rpid_hash(&env, &String::from_str(&env, "socket.fi"));
        assert_ne!(
            original,
            read_creation_pop_challenge(&env, &nonce, &network, 1120).unwrap()
        );
    });
    env.ledger().set_network_id([8; 32]);
    env.as_contract(&host, || {
        assert_ne!(
            original,
            read_creation_pop_challenge(&env, &nonce, &network, 1120).unwrap()
        )
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
            read_creation_pop_challenge(&env, &nonce, &network, 1120),
            Err(AccountError::NonceAlreadyUsed)
        );
    });
    // Validate arithmetic independently: no current+window overflow.
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
